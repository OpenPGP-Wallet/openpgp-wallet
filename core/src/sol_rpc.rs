use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub struct SolRpc {
    endpoint: String,
    client: reqwest::blocking::Client,
}

// Voir eth_rpc::shared_client : un `reqwest::Client` reconstruit à chaque appel de
// commande jette son pool de connexions keep-alive et repaie une poignée de main
// TCP+TLS complète à chaque clic. Un seul client partagé, construit une fois.
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

impl SolRpc {
    /// `endpoint` : URL JSON-RPC du cluster ciblé (devnet ou mainnet-beta,
    /// voir wallet_flow::SOLANA_DEVNET / SOLANA_MAINNET).
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

    /// Solde en lamports (1 SOL = 1_000_000_000 lamports).
    pub fn balance_lamports(&self, pubkey_b58: &str) -> Result<u64> {
        let result = self.call("getBalance", json!([pubkey_b58]))?;
        result
            .get("value")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("réponse getBalance inattendue"))
    }

    pub fn latest_blockhash(&self) -> Result<[u8; 32]> {
        let result = self.call("getLatestBlockhash", json!([{"commitment": "finalized"}]))?;
        let blockhash_str = result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("réponse getLatestBlockhash inattendue"))?;
        let bytes = bs58::decode(blockhash_str)
            .into_vec()
            .context("blockhash base58 invalide")?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("blockhash de taille inattendue"))
    }

    /// Demande un airdrop devnet (peut échouer si le faucet intégré est rate-limité :
    /// dans ce cas, utiliser https://faucet.solana.com manuellement).
    pub fn request_airdrop(&self, pubkey_b58: &str, lamports: u64) -> Result<String> {
        let result = self.call("requestAirdrop", json!([pubkey_b58, lamports]))?;
        result
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow!("réponse requestAirdrop inattendue"))
    }

    pub fn send_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_tx);
        let result = self.call("sendTransaction", json!([b64, {"encoding": "base64"}]))?;
        result
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow!("réponse sendTransaction inattendue"))
    }

    /// Historique des signatures touchant `pubkey_b58`, du plus récent au plus
    /// ancien (ordre déjà garanti par `getSignaturesForAddress`). Le montant net de
    /// chaque transaction demande un second appel (`getTransaction`) : contrairement
    /// à Bitcoin où Esplora inclut déjà les vin/vout dans la même réponse, Solana ne
    /// donne l'historique des soldes que transaction par transaction.
    /// `true` si la transaction la plus récente touchant `pubkey_b58` n'a pas encore
    /// atteint la finalité (`confirmationStatus` autre que `"finalized"`) — fonds
    /// entrants ou sortants pas encore définitivement réglés. Un seul appel limité à
    /// la dernière signature, sans le second appel `getTransaction` que fait
    /// `signature_history` pour calculer un montant : appelé à chaque
    /// rafraîchissement automatique du solde (voir main.js::refreshBalance), il doit
    /// rester léger.
    pub fn has_unfinalized_tx(&self, pubkey_b58: &str) -> Result<bool> {
        let result = self.call("getSignaturesForAddress", json!([pubkey_b58, {"limit": 1}]))?;
        let entries = result.as_array().cloned().unwrap_or_default();
        Ok(entries
            .first()
            .and_then(|e| e.get("confirmationStatus"))
            .and_then(Value::as_str)
            .is_some_and(|status| status != "finalized"))
    }

    pub fn signature_history(&self, pubkey_b58: &str, limit: u32) -> Result<Vec<SolTx>> {
        let result = self.call("getSignaturesForAddress", json!([pubkey_b58, {"limit": limit}]))?;
        let entries = result.as_array().cloned().unwrap_or_default();

        Ok(entries
            .into_iter()
            .map(|entry| {
                let signature = entry.get("signature").and_then(Value::as_str).unwrap_or_default().to_string();
                let block_time = entry.get("blockTime").and_then(Value::as_i64);
                let confirmation_status = entry.get("confirmationStatus").and_then(Value::as_str).unwrap_or("");
                let failed = entry.get("err").map(|e| !e.is_null()).unwrap_or(false);
                // Erreur de récupération du détail volontairement avalée (`.ok().flatten()`) :
                // une transaction dont le montant n'a pas pu être déterminé (nœud qui a purgé
                // une signature ancienne, etc.) doit rester affichable sans montant plutôt que
                // de faire échouer tout l'historique.
                let net_lamports = self.net_lamports_for(&signature, pubkey_b58).ok().flatten();
                SolTx {
                    signature,
                    block_time,
                    confirmed: matches!(confirmation_status, "confirmed" | "finalized"),
                    failed,
                    net_lamports,
                }
            })
            .collect())
    }

    fn net_lamports_for(&self, signature: &str, pubkey_b58: &str) -> Result<Option<i128>> {
        let result = self.call(
            "getTransaction",
            json!([signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}]),
        )?;
        if result.is_null() {
            return Ok(None);
        }
        let account_keys = result.pointer("/transaction/message/accountKeys").and_then(Value::as_array);
        let pre_balances = result.pointer("/meta/preBalances").and_then(Value::as_array);
        let post_balances = result.pointer("/meta/postBalances").and_then(Value::as_array);
        let (Some(account_keys), Some(pre_balances), Some(post_balances)) = (account_keys, pre_balances, post_balances)
        else {
            return Ok(None);
        };
        let index = account_keys.iter().position(|k| k.as_str() == Some(pubkey_b58));
        Ok(index.and_then(|i| {
            let pre = pre_balances.get(i).and_then(Value::as_i64)?;
            let post = post_balances.get(i).and_then(Value::as_i64)?;
            Some((post - pre) as i128)
        }))
    }
}

pub struct SolTx {
    pub signature: String,
    pub block_time: Option<i64>,
    /// `confirmed`/`finalized` (voir `confirmationStatus`) ; `processed` (le niveau
    /// le moins sûr, pas encore répliqué) est traité comme non confirmé.
    pub confirmed: bool,
    pub failed: bool,
    /// Positif si reçu net, négatif si envoyé net, en lamports ; `None` si le détail
    /// n'a pas pu être récupéré.
    pub net_lamports: Option<i128>,
}
