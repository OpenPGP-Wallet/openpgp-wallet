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

    /// État brut (lamports, programme propriétaire, données) de plusieurs
    /// comptes à la fois — `None` pour un compte inexistant. Au plus 100 par
    /// appel (limite de `getMultipleAccounts`), découpé ici en lots.
    pub fn multiple_accounts(&self, pubkeys: &[String]) -> Result<Vec<Option<AccountState>>> {
        let mut states = Vec::with_capacity(pubkeys.len());
        for chunk in pubkeys.chunks(100) {
            let result = self.call("getMultipleAccounts", json!([chunk, {"encoding": "base64"}]))?;
            let values = result
                .get("value")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("réponse getMultipleAccounts inattendue"))?;
            anyhow::ensure!(values.len() == chunk.len(), "réponse getMultipleAccounts incomplète");
            for value in values {
                states.push(AccountState::from_rpc_value(value)?);
            }
        }
        Ok(states)
    }

    /// Comme `simulate_transaction`, mais renvoie aussi l'état de `addresses`
    /// APRÈS simulation (config `accounts` de `simulateTransaction`) — permet de
    /// vérifier ce qu'une transaction construite par un tiers ferait réellement
    /// aux comptes de l'utilisateur, au lieu de lui faire confiance (voir
    /// `api::verify_swap_effects`). La simulation est faite par CE nœud RPC, un
    /// tiers indépendant de celui qui a construit la transaction (Jupiter).
    pub fn simulate_with_account_states(&self, raw_tx: &[u8], addresses: &[String]) -> Result<SimulationOutcome> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_tx);
        let result = self.call(
            "simulateTransaction",
            json!([b64, {
                "encoding": "base64",
                "replaceRecentBlockhash": true,
                "sigVerify": false,
                "accounts": {"encoding": "base64", "addresses": addresses},
            }]),
        )?;
        let err = result.pointer("/value/err");
        if !(err.is_none() || err == Some(&Value::Null)) {
            let logs = result
                .pointer("/value/logs")
                .and_then(Value::as_array)
                .map(|entries| entries.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"))
                .unwrap_or_default();
            return Ok(SimulationOutcome::Failed { logs });
        }
        let accounts = result
            .pointer("/value/accounts")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("simulation sans état de comptes (champ 'accounts' absent)"))?;
        anyhow::ensure!(accounts.len() == addresses.len(), "simulation : nombre d'états de comptes inattendu");
        let post_states = accounts.iter().map(AccountState::from_rpc_value).collect::<Result<Vec<_>>>()?;
        Ok(SimulationOutcome::Succeeded { post_states })
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

    /// `true` si au moins une transaction a déjà touché `pubkey_b58` — distingue
    /// une adresse jamais utilisée d'une adresse vidée (les deux n'ont plus de
    /// compte on-chain). Une seule signature demandée, aucun détail.
    pub fn has_any_signature(&self, pubkey_b58: &str) -> Result<bool> {
        let result = self.call("getSignaturesForAddress", json!([pubkey_b58, {"limit": 1}]))?;
        let entries = result.as_array().ok_or_else(|| anyhow!("réponse getSignaturesForAddress inattendue"))?;
        Ok(!entries.is_empty())
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
                let details = self.transaction(&signature).ok().flatten();
                SolTx {
                    net_lamports: details.as_ref().and_then(|tx| net_lamports(tx, pubkey_b58)),
                    swap: details.as_ref().is_some_and(is_swap_transaction),
                    signature,
                    block_time,
                    confirmed: matches!(confirmation_status, "confirmed" | "finalized"),
                    failed,
                }
            })
            .collect())
    }

    /// Solde d'un compte de jeton SPL (Associated Token Account), en plus
    /// petite unité (ex: micro-USDC, 6 décimales). `None` si le compte
    /// n'existe pas encore (jamais reçu ce jeton) — `getTokenAccountBalance`
    /// renvoie une erreur JSON-RPC dans ce cas (pas un `value: null` comme
    /// `getAccountInfo`), détectée ici par le message plutôt qu'un code
    /// structuré, faute de mieux exposé par ce endpoint.
    pub fn token_account_balance(&self, ata_b58: &str) -> Result<Option<u64>> {
        match self.call("getTokenAccountBalance", json!([ata_b58])) {
            Ok(result) => {
                let amount_str = result
                    .pointer("/value/amount")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("réponse getTokenAccountBalance inattendue"))?;
                Ok(Some(amount_str.parse::<u64>().context("montant getTokenAccountBalance illisible")?))
            }
            Err(e) if e.to_string().to_lowercase().contains("could not find account") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `true` si un compte (ATA ou autre) existe déjà on-chain — sert à
    /// savoir si l'instruction CreateIdempotent va réellement créer un
    /// compte (et donc facturer le rent) avant d'afficher ce coût dans la
    /// boîte de dialogue de confirmation.
    pub fn account_exists(&self, pubkey_b58: &str) -> Result<bool> {
        let result = self.call("getAccountInfo", json!([pubkey_b58, {"encoding": "base64"}]))?;
        Ok(!result.get("value").map(Value::is_null).unwrap_or(true))
    }

    /// Minimum de lamports pour qu'un compte de `data_len` octets soit
    /// exempté de rent — interrogé en direct plutôt que codé en dur : ce
    /// paramètre réseau évolue avec le temps, un chiffre figé deviendrait
    /// silencieusement trop bas ou trop haut.
    pub fn minimum_rent_exempt_balance(&self, data_len: u64) -> Result<u64> {
        let result = self.call("getMinimumBalanceForRentExemption", json!([data_len]))?;
        result.as_u64().ok_or_else(|| anyhow!("réponse getMinimumBalanceForRentExemption inattendue"))
    }

    /// Détail d'une transaction (`getTransaction`) ; `None` si le nœud ne l'a
    /// plus (signature ancienne purgée).
    fn transaction(&self, signature: &str) -> Result<Option<Value>> {
        let result = self.call(
            "getTransaction",
            json!([signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}]),
        )?;
        Ok((!result.is_null()).then_some(result))
    }

    /// Même principe que `signature_history`, mais pour l'historique d'un jeton SPL
    /// (ex: USDC) : interroge les signatures touchant directement le compte de
    /// jetons associé (ATA), pas l'adresse "propriétaire" du wallet — c'est l'ATA,
    /// pas le compte système du propriétaire, qui reçoit/envoie effectivement le
    /// jeton. Le champ `net_lamports` du `SolTx` retourné contient en réalité un
    /// montant en plus petite unité du jeton (ex: micro-USDC), pas des lamports —
    /// réutilise la même structure plutôt que d'en dupliquer une identique.
    pub fn token_signature_history(&self, ata_b58: &str, limit: u32) -> Result<Vec<SolTx>> {
        let result = self.call("getSignaturesForAddress", json!([ata_b58, {"limit": limit}]))?;
        let entries = result.as_array().cloned().unwrap_or_default();

        Ok(entries
            .into_iter()
            .map(|entry| {
                let signature = entry.get("signature").and_then(Value::as_str).unwrap_or_default().to_string();
                let block_time = entry.get("blockTime").and_then(Value::as_i64);
                let confirmation_status = entry.get("confirmationStatus").and_then(Value::as_str).unwrap_or("");
                let failed = entry.get("err").map(|e| !e.is_null()).unwrap_or(false);
                let details = self.transaction(&signature).ok().flatten();
                SolTx {
                    net_lamports: details.as_ref().and_then(|tx| net_token_amount(tx, ata_b58)),
                    swap: details.as_ref().is_some_and(is_swap_transaction),
                    signature,
                    block_time,
                    confirmed: matches!(confirmation_status, "confirmed" | "finalized"),
                    failed,
                }
            })
            .collect())
    }

}

/// Variation du solde SOL de `pubkey_b58` dans une transaction (`getTransaction`).
fn net_lamports(tx: &Value, pubkey_b58: &str) -> Option<i128> {
    let account_keys = tx.pointer("/transaction/message/accountKeys")?.as_array()?;
    let index = account_keys.iter().position(|k| k.as_str() == Some(pubkey_b58))?;
    let pre = tx.pointer("/meta/preBalances")?.as_array()?.get(index)?.as_i64()?;
    let post = tx.pointer("/meta/postBalances")?.as_array()?.get(index)?.as_i64()?;
    Some((post - pre) as i128)
}

/// Équivalent de `net_lamports` pour un compte de jetons SPL : Solana ne
/// donne pas l'historique des soldes de jetons dans `preBalances`/`postBalances`
/// (réservés au solde natif SOL), mais dans `preTokenBalances`/`postTokenBalances`,
/// indexés par la position du compte dans `accountKeys` (même mécanisme
/// d'indexation). Absence dans `preTokenBalances` traitée comme un solde de 0
/// avant la transaction (cas d'un ATA tout juste créé par cette même
/// transaction, via CreateIdempotent).
fn net_token_amount(tx: &Value, ata_b58: &str) -> Option<i128> {
    let account_keys = tx.pointer("/transaction/message/accountKeys")?.as_array()?;
    let index = account_keys.iter().position(|k| k.as_str() == Some(ata_b58))?;
    let amount_at_index = |balances: &[Value]| -> Option<i128> {
        balances
            .iter()
            .find(|entry| entry.get("accountIndex").and_then(Value::as_u64) == Some(index as u64))
            .and_then(|entry| entry.pointer("/uiTokenAmount/amount"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<i128>().ok())
    };
    let pre_amount = tx.pointer("/meta/preTokenBalances").and_then(Value::as_array).and_then(|b| amount_at_index(b)).unwrap_or(0);
    amount_at_index(tx.pointer("/meta/postTokenBalances")?.as_array()?).map(|post| post - pre_amount)
}

/// Programme d'agrégation de swaps Jupiter (v6), celui qu'utilise l'app.
const JUPITER_PROGRAM: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

/// Swap : programme Jupiter appelé (toujours parmi les clés statiques du
/// message, un programme ne pouvant venir d'une table d'adresses), ou memo de
/// swap THORChain dans le journal du programme Memo
/// (`Program log: Memo (len N): "…"`).
fn is_swap_transaction(tx: &Value) -> bool {
    let jupiter = tx
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(JUPITER_PROGRAM)));
    let memo_swap = tx.pointer("/meta/logMessages").and_then(Value::as_array).is_some_and(|logs| {
        logs.iter().filter_map(Value::as_str).any(|line| {
            line.strip_prefix("Program log: Memo (len ")
                .and_then(|rest| rest.split_once("): \""))
                .and_then(|(_, memo)| memo.strip_suffix('"'))
                .is_some_and(crate::history::is_swap_memo)
        })
    });
    jupiter || memo_swap
}

/// Cherche le motif "Transfer: insufficient lamports X, need Y" dans un
/// journal de simulation (voir `SolRpc::simulate_transaction`) et, si
/// trouvé, construit un message clair avec le manque exact — beaucoup plus
/// lisible que le journal brut pour un montant/frais/rent qui ne peut pas
/// être prédit à l'avance de façon fiable (ex: coût exact d'une route de
/// swap Jupiter, qui varie d'un appel à l'autre).
pub fn insufficient_lamports_error(logs: &str) -> Option<anyhow::Error> {
    let line = logs.lines().find(|l| l.contains("insufficient lamports"))?;
    let numbers: Vec<u64> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();
    let (&available, &needed) = (numbers.first()?, numbers.get(1)?);
    let missing = needed.saturating_sub(available);
    Some(anyhow!(
        "SOL insuffisant pour cette opération : il manque environ {missing} lamports ({available} disponibles, {needed} requis à cette étape)"
    ))
}

/// État brut d'un compte Solana tel que renvoyé par le RPC (encodage base64).
#[derive(Clone, Debug, PartialEq)]
pub struct AccountState {
    pub lamports: u64,
    /// Programme propriétaire du compte (base58).
    pub owner: String,
    pub data: Vec<u8>,
}

impl AccountState {
    fn from_rpc_value(value: &Value) -> Result<Option<Self>> {
        if value.is_null() {
            return Ok(None);
        }
        let lamports = value.get("lamports").and_then(Value::as_u64).ok_or_else(|| anyhow!("compte sans lamports"))?;
        let owner = value.get("owner").and_then(Value::as_str).ok_or_else(|| anyhow!("compte sans propriétaire"))?.to_string();
        let data_b64 = value
            .get("data")
            .and_then(Value::as_array)
            .and_then(|d| d.first())
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("compte sans données base64"))?;
        let data = base64::engine::general_purpose::STANDARD.decode(data_b64).context("données de compte base64 invalides")?;
        Ok(Some(Self { lamports, owner, data }))
    }
}

pub enum SimulationOutcome {
    Failed { logs: String },
    Succeeded { post_states: Vec<Option<AccountState>> },
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
    /// Swap Jupiter ou THORChain (voir `is_swap_transaction`).
    pub swap: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ligne de journal réelle observée lors d'un échec de simulation de swap
    // Jupiter (rent/wrapping SOL<->wSOL sous-estimé) — vérifie que le motif
    // exact renvoyé par le validateur Solana est bien reconnu.
    #[test]
    fn insufficient_lamports_error_extracts_the_real_shortfall() {
        let logs = "Program log: Instruction: Route\nProgram 11111111111111111111111111111111 invoke [2]\nTransfer: insufficient lamports 6460932, need 13045440\nProgram 11111111111111111111111111111111 failed: custom program error: 0x1";
        let err = insufficient_lamports_error(logs).expect("motif reconnu");
        let message = err.to_string();
        assert!(message.contains("6460932"), "{message}");
        assert!(message.contains("13045440"), "{message}");
        assert!(message.contains("6584508"), "manque exact attendu : {message}");
    }

    #[test]
    fn insufficient_lamports_error_returns_none_without_the_pattern() {
        assert!(insufficient_lamports_error("Program log: Instruction: Route\nProgram ... success").is_none());
    }

    /// Formats de vraies transactions du réseau principal : swap Jupiter
    /// (programme parmi les clés statiques d'une transaction v0), dépôt de swap
    /// THORChain et paiement THORChain (lignes de journal du programme Memo
    /// recopiées telles quelles), virement ordinaire.
    #[test]
    fn swaps_are_detected_in_real_transaction_formats() {
        let tx = |keys: &[&str], logs: &[&str]| json!({"transaction": {"message": {"accountKeys": keys}}, "meta": {"logMessages": logs}});
        let jupiter = tx(&["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", JUPITER_PROGRAM], &["Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 invoke [1]"]);
        assert!(is_swap_transaction(&jupiter));
        let deposit = tx(
            &["11111111111111111111111111111111", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"],
            &[
                "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr invoke [1]",
                "Program log: Memo (len 53): \"=:BSC.USDT:0xd63678741D8e155e337c0Fe35cE143886fA04750\"",
            ],
        );
        assert!(is_swap_transaction(&deposit));
        let payout = tx(&[], &["Program log: Memo (len 68): \"OUT:69F129E7A9CC7D8C71D4A261C56EF2291275DF572A29F9218A535B743EAAEB15\""]);
        assert!(is_swap_transaction(&payout));
        let transfer = tx(&["11111111111111111111111111111111"], &["Program 11111111111111111111111111111111 invoke [1]", "Program log: Memo (len 5): \"merci\""]);
        assert!(!is_swap_transaction(&transfer));
        assert!(!is_swap_transaction(&json!({})));
    }

    /// Montants nets SOL et jeton, calculés sur le même détail de transaction.
    #[test]
    fn net_amounts_are_read_from_transaction_details() {
        let tx = json!({
            "transaction": {"message": {"accountKeys": ["Owner", "Ata", "Other"]}},
            "meta": {
                "preBalances": [1_000_000, 2_039_280, 5], "postBalances": [990_000, 2_039_280, 5],
                "preTokenBalances": [], "postTokenBalances": [{"accountIndex": 1, "uiTokenAmount": {"amount": "2500000"}}]
            }
        });
        assert_eq!(net_lamports(&tx, "Owner"), Some(-10_000));
        assert_eq!(net_lamports(&tx, "Absent"), None);
        assert_eq!(net_token_amount(&tx, "Ata"), Some(2_500_000), "compte de jetons créé par la transaction : solde avant = 0");
        assert_eq!(net_token_amount(&tx, "Other"), None);
    }
}
