use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::OnceLock;

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
