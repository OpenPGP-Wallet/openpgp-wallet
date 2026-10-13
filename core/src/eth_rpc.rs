use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::OnceLock;

/// Call to simulate with `EthRpc::simulate_v1`.
pub struct SimCallRequest<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub value: u128,
    pub data: &'a [u8],
}

/// Result of a simulated call: success, and emitted events.
#[derive(Clone)]
pub struct SimulatedCall {
    pub success: bool,
    pub logs: Vec<SimulatedLog>,
}

/// Emitter of the native coin movements traced by `eth_simulateV1`
/// (`traceTransfers`, execution-apis specification).
pub const NATIVE_TRANSFER_EMITTER: [u8; 20] = [0xee; 20];

#[derive(Clone)]
pub struct SimulatedLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Minimal JSON-RPC client to talk to an Ethereum node (here: the Sepolia testnet).
pub struct EthRpc {
    endpoint: String,
    client: reqwest::blocking::Client,
}

// A `reqwest::Client` keeps a pool of keep-alive connections. Rebuilding it on every
// Tauri command (every `EthRpc::new`, so every click that touches the network) threw
// that pool away and paid for a full TCP + TLS handshake each time, adding
// noticeable network latency to every click. `Client` is designed to be shared and
// cloned (an internal `Arc`, cheap to clone): a single client built once per
// process, reused everywhere.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            // Without an explicit timeout, reqwest waits forever for a node that never
            // answers, blocking the whole app on that call.
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

impl EthRpc {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: shared_client().clone(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp: Value = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .with_context(|| format!("appel RPC {method} impossible"))?
            .json()
            .with_context(|| format!("réponse RPC {method} illisible"))?;

        if let Some(err) = resp.get("error") {
            return Err(anyhow!("erreur RPC {method} : {err}"));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("réponse RPC {method} sans champ 'result'"))
    }

    fn call_hex_u64(&self, method: &str, params: Value) -> Result<u64> {
        let result = self.call(method, params)?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse {method} non textuelle"))?;
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("réponse {method} non hexadécimale : {hex_str}"))
    }

    pub fn chain_id(&self) -> Result<u64> {
        self.call_hex_u64("eth_chainId", json!([]))
    }

    pub fn nonce(&self, address: &str) -> Result<u64> {
        self.call_hex_u64("eth_getTransactionCount", json!([address, "pending"]))
    }

    /// Gas actually consumed by running a call (`eth_estimateGas`, simulated by the
    /// node). Essential for a CONTRACT call: the intrinsic gas
    /// (`eth_tx::intrinsic_gas`) is only the minimum needed to SUBMIT a transaction,
    /// not to run it.
    pub fn estimate_gas(&self, from: &str, to: &str, value_wei: u128, data: &[u8]) -> Result<u64> {
        self.call_hex_u64(
            "eth_estimateGas",
            json!([{
                "from": from,
                "to": to,
                "value": format!("0x{value_wei:x}"),
                "data": format!("0x{}", hex::encode(data)),
            }]),
        )
    }

    /// Runs a call WITHOUT broadcasting anything (`eth_call`, "latest" state) and
    /// returns the bytes it produced. Used to read a contract (a token's decimals or
    /// symbol) and to detect, BEFORE signing, a dApp transaction that would fail (the
    /// node then returns an "execution reverted" error).
    pub fn call_contract(
        &self,
        from: &str,
        to: &str,
        value_wei: u128,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let result = self.call(
            "eth_call",
            json!([{
                "from": from,
                "to": to,
                "value": format!("0x{value_wei:x}"),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse eth_call non textuelle"))?;
        hex::decode(hex_str.trim_start_matches("0x"))
            .with_context(|| format!("réponse eth_call non hexadécimale : {hex_str}"))
    }

    /// Simulates calls ONE AFTER ANOTHER in the same block (`eth_simulateV1`, "latest"
    /// state, no nonce or fee check) and returns, for each one, its success and the
    /// events it emitted. Nothing is broadcast. Used to read what a transaction built
    /// by a third party would really do (recipient emitted by the contract, tokens
    /// leaving the user) before signing it, including a prior approval simulated just
    /// before in the same block.
    pub fn simulate_v1(&self, calls: &[SimCallRequest]) -> Result<Vec<SimulatedCall>> {
        self.simulate(calls, false)
    }

    /// Like `simulate_v1`, plus every movement of the network's coin as a `Transfer`
    /// event emitted by the `NATIVE_TRANSFER_EMITTER` address (`traceTransfers`):
    /// otherwise, what a contract sends in ETH, BNB... emits no event at all.
    pub fn simulate_v1_with_native_transfers(
        &self,
        calls: &[SimCallRequest],
    ) -> Result<Vec<SimulatedCall>> {
        self.simulate(calls, true)
    }

    fn simulate(
        &self,
        calls: &[SimCallRequest],
        trace_transfers: bool,
    ) -> Result<Vec<SimulatedCall>> {
        let calls_json: Vec<Value> = calls
            .iter()
            .map(|c| {
                json!({
                    "from": c.from,
                    "to": c.to,
                    "value": format!("0x{:x}", c.value),
                    "data": format!("0x{}", hex::encode(c.data)),
                })
            })
            .collect();
        let mut options =
            json!({ "blockStateCalls": [{ "calls": calls_json }], "validation": false });
        if trace_transfers {
            options["traceTransfers"] = json!(true);
        }
        let result = self.call("eth_simulateV1", json!([options, "latest"]))?;
        let simulated = result
            .get(0)
            .and_then(|block| block.get("calls"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("réponse eth_simulateV1 sans appels"))?;
        anyhow::ensure!(
            simulated.len() == calls.len(),
            "réponse eth_simulateV1 incomplète"
        );
        let hex_bytes = |v: &Value| -> Result<Vec<u8>> {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("réponse eth_simulateV1 non textuelle"))?;
            hex::decode(s.trim_start_matches("0x"))
                .context("réponse eth_simulateV1 non hexadécimale")
        };
        simulated
            .iter()
            .map(|call| {
                let logs = call
                    .get("logs")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(|log| {
                        let address: [u8; 20] = hex_bytes(&log["address"])?
                            .try_into()
                            .map_err(|_| anyhow!("adresse d'événement invalide"))?;
                        let topics = log["topics"]
                            .as_array()
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                            .iter()
                            .map(|t| {
                                hex_bytes(t)?
                                    .try_into()
                                    .map_err(|_| anyhow!("sujet d'événement invalide"))
                            })
                            .collect::<Result<Vec<[u8; 32]>>>()?;
                        Ok(SimulatedLog {
                            address,
                            topics,
                            data: hex_bytes(&log["data"])?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(SimulatedCall {
                    success: call.get("status").and_then(Value::as_str) == Some("0x1"),
                    logs,
                })
            })
            .collect()
    }

    /// Code deployed at `address` (empty for an ordinary address with no contract).
    pub fn code(&self, address: &str) -> Result<Vec<u8>> {
        let result = self.call("eth_getCode", json!([address, "latest"]))?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse eth_getCode non textuelle"))?;
        hex::decode(hex_str.trim_start_matches("0x"))
            .with_context(|| format!("réponse eth_getCode non hexadécimale : {hex_str}"))
    }

    pub fn gas_price(&self) -> Result<u128> {
        let result = self.call("eth_gasPrice", json!([]))?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse eth_gasPrice non textuelle"))?;
        u128::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("réponse eth_gasPrice non hexadécimale : {hex_str}"))
    }

    /// Balance in wei.
    pub fn balance(&self, address: &str) -> Result<u128> {
        let result = self.call("eth_getBalance", json!([address, "latest"]))?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse eth_getBalance non textuelle"))?;
        u128::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("réponse eth_getBalance non hexadécimale : {hex_str}"))
    }

    /// Transaction status: `Some(true)` mined and successful, `Some(false)` mined but
    /// reverted, `None` not mined yet.
    pub fn receipt_status(&self, tx_hash: &str) -> Result<Option<bool>> {
        let result = self.call("eth_getTransactionReceipt", json!([tx_hash]))?;
        if result.is_null() {
            return Ok(None);
        }
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("reçu de transaction sans statut"))?;
        Ok(Some(status == "0x1"))
    }

    /// Broadcasts an already signed transaction (raw RLP) and returns its hash
    /// (Keccak-256 of the signed transaction, computed here). Without a clear answer,
    /// it is "maybe sent" (see `wallet_flow::maybe_sent`); if the node already knows
    /// it, it is the same transaction, already sent.
    pub fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        use sha3::{Digest, Keccak256};
        let hash = format!("0x{}", hex::encode(Keccak256::digest(raw_tx)));
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [format!("0x{}", hex::encode(raw_tx))] });
        let response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .map_err(|e| {
                crate::wallet_flow::broadcast_failure(
                    e,
                    "appel RPC eth_sendRawTransaction impossible",
                    &hash,
                )
            })?;
        let resp: Value = response
            .json()
            .map_err(|_| crate::wallet_flow::maybe_sent(&hash))?;
        if let Some(err) = resp.get("error") {
            if err
                .to_string()
                .to_ascii_lowercase()
                .contains("already known")
            {
                return Ok(hash);
            }
            return Err(anyhow!("erreur RPC eth_sendRawTransaction : {err}"));
        }
        resp.get("result")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| crate::wallet_flow::maybe_sent(&hash))
    }
}
