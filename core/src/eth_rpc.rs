use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

/// Client JSON-RPC minimal pour parler à un nœud Ethereum (ici : Sepolia testnet).
pub struct EthRpc {
    endpoint: String,
    client: reqwest::blocking::Client,
}

impl EthRpc {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            // Sans timeout explicite, reqwest attend indéfiniment un nœud qui ne
            // répond jamais, bloquant l'app entière sur cet appel.
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("configuration du client HTTP valide"),
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

    /// Diffuse une transaction déjà signée (RLP brute) et renvoie son hash.
    pub fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let raw_hex = format!("0x{}", hex::encode(raw_tx));
        let result = self.call("eth_sendRawTransaction", json!([raw_hex]))?;
        result
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow!("réponse eth_sendRawTransaction non textuelle"))
    }
}
