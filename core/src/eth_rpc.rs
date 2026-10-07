use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::OnceLock;

/// Appel à simuler par `EthRpc::simulate_v1`.
pub struct SimCallRequest<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub value: u128,
    pub data: &'a [u8],
}

/// Résultat d'un appel simulé : succès et événements émis.
#[derive(Clone)]
pub struct SimulatedCall {
    pub success: bool,
    pub logs: Vec<SimulatedLog>,
}

/// Émetteur des mouvements de monnaie native tracés par `eth_simulateV1`
/// (`traceTransfers`, spécification execution-apis).
pub const NATIVE_TRANSFER_EMITTER: [u8; 20] = [0xee; 20];

#[derive(Clone)]
pub struct SimulatedLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Client JSON-RPC minimal pour parler à un nœud Ethereum (ici : Sepolia testnet).
pub struct EthRpc {
    endpoint: String,
    client: reqwest::blocking::Client,
}

// Un `reqwest::Client` maintient un pool de connexions keep-alive : le reconstruire
// à chaque appel de commande Tauri (chaque `EthRpc::new`, donc chaque clic qui
// touche le réseau) jetait ce pool et repayait une poignée de main TCP+TLS complète
// à chaque fois, ajoutant une latence réseau perceptible à chaque clic. `Client` est
// conçu pour être partagé/cloné (`Arc` en interne, clonage bon marché) : un seul
// client construit une fois par processus, réutilisé partout.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            // Sans timeout explicite, reqwest attend indéfiniment un nœud qui ne
            // répond jamais, bloquant l'app entière sur cet appel.
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

    /// Gas réellement consommé par l'exécution d'un appel (`eth_estimateGas`,
    /// simulation par le nœud) — indispensable pour un appel de CONTRAT : le
    /// gas intrinsèque (`eth_tx::intrinsic_gas`) n'est que le minimum pour
    /// SOUMETTRE une transaction, pas pour l'exécuter.
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

    /// Exécute un appel SANS rien diffuser (`eth_call`, état "latest") et
    /// renvoie les octets rendus — sert à lire un contrat (décimales/symbole
    /// d'un jeton) et à détecter AVANT signature une transaction de dApp qui
    /// échouerait (le nœud renvoie alors une erreur "execution reverted").
    pub fn call_contract(&self, from: &str, to: &str, value_wei: u128, data: &[u8]) -> Result<Vec<u8>> {
        let result = self.call(
            "eth_call",
            json!([{
                "from": from,
                "to": to,
                "value": format!("0x{value_wei:x}"),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )?;
        let hex_str = result.as_str().ok_or_else(|| anyhow!("réponse eth_call non textuelle"))?;
        hex::decode(hex_str.trim_start_matches("0x")).with_context(|| format!("réponse eth_call non hexadécimale : {hex_str}"))
    }

    /// Simule des appels À LA SUITE dans un même bloc (`eth_simulateV1`, état
    /// "latest", sans vérification de nonce ni de frais) et renvoie, pour
    /// chacun, son succès et les événements émis. Rien n'est diffusé. Sert à
    /// lire ce qu'une transaction construite par un tiers ferait réellement
    /// (destinataire émis par le contrat, jetons qui quittent l'utilisateur)
    /// avant de la signer — autorisation préalable comprise, simulée juste
    /// avant dans le même bloc.
    pub fn simulate_v1(&self, calls: &[SimCallRequest]) -> Result<Vec<SimulatedCall>> {
        self.simulate(calls, false)
    }

    /// Comme `simulate_v1`, avec en plus chaque mouvement de la monnaie du
    /// réseau sous forme d'événement `Transfer` émis par l'adresse
    /// `NATIVE_TRANSFER_EMITTER` (`traceTransfers`) : ce qu'un contrat envoie
    /// en ETH, BNB… n'émet sinon aucun événement.
    pub fn simulate_v1_with_native_transfers(&self, calls: &[SimCallRequest]) -> Result<Vec<SimulatedCall>> {
        self.simulate(calls, true)
    }

    fn simulate(&self, calls: &[SimCallRequest], trace_transfers: bool) -> Result<Vec<SimulatedCall>> {
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
        let mut options = json!({ "blockStateCalls": [{ "calls": calls_json }], "validation": false });
        if trace_transfers {
            options["traceTransfers"] = json!(true);
        }
        let result = self.call("eth_simulateV1", json!([options, "latest"]))?;
        let simulated = result
            .get(0)
            .and_then(|block| block.get("calls"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("réponse eth_simulateV1 sans appels"))?;
        anyhow::ensure!(simulated.len() == calls.len(), "réponse eth_simulateV1 incomplète");
        let hex_bytes = |v: &Value| -> Result<Vec<u8>> {
            let s = v.as_str().ok_or_else(|| anyhow!("réponse eth_simulateV1 non textuelle"))?;
            hex::decode(s.trim_start_matches("0x")).context("réponse eth_simulateV1 non hexadécimale")
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
                        let address: [u8; 20] = hex_bytes(&log["address"])?.try_into().map_err(|_| anyhow!("adresse d'événement invalide"))?;
                        let topics = log["topics"]
                            .as_array()
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                            .iter()
                            .map(|t| hex_bytes(t)?.try_into().map_err(|_| anyhow!("sujet d'événement invalide")))
                            .collect::<Result<Vec<[u8; 32]>>>()?;
                        Ok(SimulatedLog { address, topics, data: hex_bytes(&log["data"])? })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(SimulatedCall { success: call.get("status").and_then(Value::as_str) == Some("0x1"), logs })
            })
            .collect()
    }

    /// Code déployé à `address` (vide pour une adresse ordinaire, sans contrat).
    pub fn code(&self, address: &str) -> Result<Vec<u8>> {
        let result = self.call("eth_getCode", json!([address, "latest"]))?;
        let hex_str = result.as_str().ok_or_else(|| anyhow!("réponse eth_getCode non textuelle"))?;
        hex::decode(hex_str.trim_start_matches("0x")).with_context(|| format!("réponse eth_getCode non hexadécimale : {hex_str}"))
    }

    pub fn gas_price(&self) -> Result<u128> {
        let result = self.call("eth_gasPrice", json!([]))?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse eth_gasPrice non textuelle"))?;
        u128::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("réponse eth_gasPrice non hexadécimale : {hex_str}"))
    }

    /// Solde en wei.
    pub fn balance(&self, address: &str) -> Result<u128> {
        let result = self.call("eth_getBalance", json!([address, "latest"]))?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| anyhow!("réponse eth_getBalance non textuelle"))?;
        u128::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("réponse eth_getBalance non hexadécimale : {hex_str}"))
    }

    /// Statut d'une transaction : `Some(true)` minée et réussie, `Some(false)`
    /// minée mais annulée (revert), `None` pas encore minée.
    pub fn receipt_status(&self, tx_hash: &str) -> Result<Option<bool>> {
        let result = self.call("eth_getTransactionReceipt", json!([tx_hash]))?;
        if result.is_null() {
            return Ok(None);
        }
        let status = result.get("status").and_then(Value::as_str).ok_or_else(|| anyhow!("reçu de transaction sans statut"))?;
        Ok(Some(status == "0x1"))
    }

    /// Diffuse une transaction déjà signée (RLP brute) et renvoie son hash
    /// (Keccak-256 de la transaction signée, calculé ici). Sans réponse nette,
    /// « peut-être partie » (voir `wallet_flow::maybe_sent`) ; déjà connue du
    /// nœud : c'est la même, partie.
    pub fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        use sha3::{Digest, Keccak256};
        let hash = format!("0x{}", hex::encode(Keccak256::digest(raw_tx)));
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [format!("0x{}", hex::encode(raw_tx))] });
        let response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .map_err(|e| crate::wallet_flow::broadcast_failure(e, "appel RPC eth_sendRawTransaction impossible", &hash))?;
        let resp: Value = response.json().map_err(|_| crate::wallet_flow::maybe_sent(&hash))?;
        if let Some(err) = resp.get("error") {
            if err.to_string().to_ascii_lowercase().contains("already known") {
                return Ok(hash);
            }
            return Err(anyhow!("erreur RPC eth_sendRawTransaction : {err}"));
        }
        resp.get("result").and_then(Value::as_str).map(String::from).ok_or_else(|| crate::wallet_flow::maybe_sent(&hash))
    }
}
