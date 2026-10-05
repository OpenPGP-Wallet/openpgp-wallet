//! NEAR : compte implicite (64 caractères hexadécimaux, clé ed25519 dérivée
//! en m/44'/397'/p', comme les portefeuilles NEAR), solde, envoi de NEAR,
//! historique.
//!
//! Transactions sérialisées (Borsh) et signées ici, identiques octet pour
//! octet à la bibliothèque officielle (@near-js/transactions) dans les tests,
//! et vérifiées de bout en bout sur le réseau de test (test réel).
//!
//! Règles du réseau appliquées avant la boîte de confirmation :
//! - stockage : chaque compte garde de quoi payer ses octets (~0,00182 NEAR
//!   pour un compte implicite), jamais envoyable ;
//! - un destinataire implicite jamais utilisé est CRÉÉ par le virement, avec
//!   au moins son stockage ; un compte nommé (alice.near) doit exister ;
//! - adresses Ethereum (0x…, comptes « eth-implicites ») refusées : un envoi
//!   sur Ethereum se fait depuis la carte Ethereum ;
//! - frais : gaz du virement (coûts lus dans la configuration du protocole).
//!   Le réseau RETIENT d'abord le gaz d'exécution à son prix d'achat minimal
//!   (`min_gas_purchase_price`, 10 × le prix actuel en 2026) puis rend le
//!   surplus un bloc plus tard : cette retenue (+ 20 %) est le maximum
//!   affiché et vérifié, les frais réels (gaz × prix du moment) sont bien
//!   plus bas.

use crate::history;
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Réseau NEAR : nœuds JSON-RPC (dans l'ordre) et index des transactions.
pub struct Network {
    pub rpc: [&'static str; 2],
    pub tx_index: &'static str,
}

pub const MAINNET: Network = Network { rpc: ["https://rpc.mainnet.fastnear.com", "https://rpc.mainnet.near.org"], tx_index: "https://tx.main.fastnear.com" };
#[cfg(test)]
const TESTNET: Network = Network { rpc: ["https://rpc.testnet.fastnear.com", "https://rpc.testnet.near.org"], tx_index: "https://tx.test.fastnear.com" };

pub const DECIMALS: u8 = 24;
/// Taille du stockage d'un compte implicite neuf (compte + clé d'accès).
const IMPLICIT_ACCOUNT_BYTES: u128 = 182;
/// Plafond des frais d'un virement (0,01 NEAR ; ~0,00005 au repos).
const MAX_FEE_YOCTO: u128 = 10_000_000_000_000_000_000_000;

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("openpgp-wallet")
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Erreur renvoyée par le nœud (nom de la cause, message).
struct RpcError {
    name: String,
    detail: String,
}

/// Appel JSON-RPC : `Ok(Err(..))` pour une erreur DU NŒUD (compte inconnu,
/// transaction invalide…), `Err` si aucun nœud ne répond.
fn rpc(net: &Network, method: &str, params: Value) -> Result<std::result::Result<Value, RpcError>> {
    let mut last = anyhow!("nœud NEAR injoignable");
    for node in net.rpc {
        let attempt = (|| -> Result<Value> {
            let response = client().post(node).json(&json!({ "jsonrpc": "2.0", "id": "ow", "method": method, "params": params })).send().context("nœud NEAR injoignable")?;
            let status = response.status();
            // 400 : erreur du nœud, détaillée dans le corps JSON-RPC.
            ensure!(status.is_success() || status == reqwest::StatusCode::BAD_REQUEST, "nœud NEAR : réponse {status}");
            response.json().context("réponse du nœud NEAR illisible")
        })();
        match attempt {
            Ok(value) => return Ok(reply(&value)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Réponse JSON-RPC : le résultat, ou l'erreur DU NŒUD.
fn reply(value: &Value) -> std::result::Result<Value, RpcError> {
    if let Some(error) = value.get("error") {
        let name = error["cause"]["name"].as_str().or(error["name"].as_str()).unwrap_or("").to_string();
        let detail = [error["cause"]["info"].to_string(), error["data"].to_string()].into_iter().find(|d| d != "null" && d != "{}").unwrap_or_default();
        return Err(RpcError { name, detail });
    }
    // Réponse d'une requête « query » : erreur dans le résultat.
    if let Some(error) = value["result"]["error"].as_str() {
        return Err(RpcError { name: "QUERY_ERROR".into(), detail: error.to_string() });
    }
    Ok(value["result"].clone())
}

fn rpc_ok(net: &Network, method: &str, params: Value) -> Result<Value> {
    rpc(net, method, params)?.map_err(|e| anyhow!("nœud NEAR : {} {}", e.name, e.detail))
}

fn yocto(text: &str) -> Result<u128> {
    text.parse::<u128>().context("montant NEAR illisible")
}

/// Montant en NEAR, 5 décimales (« 12.50000 », arrondi inférieur) ; la
/// boîte de confirmation affiche le montant exact saisi.
pub fn format_near(yocto: u128) -> String {
    let whole = yocto / 10u128.pow(24);
    let fraction = (yocto % 10u128.pow(24)) / 10u128.pow(19);
    format!("{whole}.{fraction:05}")
}

/// Montant exact en NEAR (24 décimales, zéros finaux retirés).
pub fn format_near_exact(yocto: u128) -> String {
    let whole = yocto / 10u128.pow(24);
    let fraction = format!("{:024}", yocto % 10u128.pow(24));
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{whole}")
    } else {
        format!("{whole}.{fraction}")
    }
}

// --- Comptes -------------------------------------------------------------------------

/// Compte implicite d'une clé : sa clé publique en hexadécimal.
pub fn implicit_account(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn is_implicit(account: &str) -> bool {
    account.len() == 64 && account.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Identifiant de compte NEAR valide : implicite (64 hex) ou nommé
/// (« alice.near », règles du protocole). Adresses Ethereum refusées.
pub fn parse_account(text: &str) -> Result<String> {
    let text = text.trim();
    if text.len() == 42 && (text.starts_with("0x") || text.starts_with("0X")) && text[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("adresse Ethereum : pour envoyer sur Ethereum, utilisez la carte Ethereum (pas NEAR)");
    }
    ensure!(!text.bytes().any(|b| b.is_ascii_uppercase()), "adresse NEAR invalide (minuscules seulement)");
    ensure!((2..=64).contains(&text.len()), "adresse NEAR invalide");
    // Parties séparées par « . » ; dans une partie, « - » ou « _ » entre deux
    // caractères alphanumériques seulement.
    let valid = text.split('.').all(|part| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            && !part.starts_with(['-', '_'])
            && !part.ends_with(['-', '_'])
            && !part.as_bytes().windows(2).any(|w| matches!(w[0], b'-' | b'_') && matches!(w[1], b'-' | b'_'))
    });
    ensure!(valid, "adresse NEAR invalide");
    Ok(text.to_string())
}

// --- Transaction (Borsh) -------------------------------------------------------------------

/// Virement de NEAR, tel que signé.
pub struct Transfer {
    pub signer: String,
    pub public_key: [u8; 32],
    pub nonce: u64,
    pub receiver: String,
    pub block_hash: [u8; 32],
    pub deposit: u128,
}

fn borsh_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
}

impl Transfer {
    fn borsh(&self) -> Vec<u8> {
        let mut out = Vec::new();
        borsh_string(&mut out, &self.signer);
        out.push(0); // clé ed25519
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        borsh_string(&mut out, &self.receiver);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&1u32.to_le_bytes()); // une action
        out.push(3); // Transfer
        out.extend_from_slice(&self.deposit.to_le_bytes());
        out
    }

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.borsh()).into()
    }
}

pub struct Signed {
    pub bytes: Vec<u8>,
    /// Identifiant (base58 du condensé SHA-256 de la transaction).
    pub hash: String,
}

pub fn sign(tx: &Transfer, key: &SigningKey) -> Signed {
    let hash = tx.hash();
    let mut bytes = tx.borsh();
    bytes.push(0); // signature ed25519
    bytes.extend_from_slice(&key.sign(&hash).to_bytes());
    Signed { bytes, hash: bs58::encode(hash).into_string() }
}

// --- Compte et réseau ----------------------------------------------------------------------

struct AccountState {
    amount: u128,
    storage_usage: u128,
}

fn account_state(net: &Network, account: &str) -> Result<Option<AccountState>> {
    let account = parse_account(account)?;
    match rpc(net, "query", json!({ "request_type": "view_account", "finality": "final", "account_id": account }))? {
        Err(e) if e.name == "UNKNOWN_ACCOUNT" || e.detail.contains("does not exist") => Ok(None),
        Err(e) => bail!("nœud NEAR : {} {}", e.name, e.detail),
        Ok(value) => Ok(Some(AccountState {
            amount: yocto(value["amount"].as_str().context("solde NEAR illisible")?)?,
            storage_usage: value["storage_usage"].as_u64().map(u128::from).context("solde NEAR illisible")?,
        })),
    }
}

/// Coûts du protocole utiles à un virement.
struct Costs {
    storage_per_byte: u128,
    /// Gaz d'un virement vers un compte existant : (envoi, exécution).
    transfer_gas: (u128, u128),
    /// Gaz en plus quand le virement crée un compte implicite.
    create_gas: (u128, u128),
    gas_price: u128,
    /// Prix d'achat minimal du gaz d'exécution, retenu d'avance.
    purchase_price: u128,
}

fn costs(net: &Network) -> Result<Costs> {
    let config = rpc_ok(net, "EXPERIMENTAL_protocol_config", json!({ "finality": "final" }))?;
    let runtime = &config["runtime_config"];
    let fees = &runtime["transaction_costs"];
    let gas = |fee: &Value| -> Result<(u128, u128)> {
        let field = |name: &str| fee[name].as_u64().map(u128::from).context("configuration NEAR illisible");
        Ok((field("send_not_sir")?, field("execution")?))
    };
    let add = |a: (u128, u128), b: (u128, u128)| (a.0 + b.0, a.1 + b.1);
    let actions = &fees["action_creation_config"];
    let gas_price = rpc_ok(net, "gas_price", json!([null]))?;
    let price = |value: &Value| value.as_str().map(yocto).transpose()?.context("configuration NEAR illisible");
    Ok(Costs {
        storage_per_byte: price(&runtime["storage_amount_per_byte"])?,
        transfer_gas: add(gas(&fees["action_receipt_creation_config"])?, gas(&actions["transfer_cost"])?),
        create_gas: add(gas(&actions["create_account_cost"])?, gas(&actions["add_key_cost"]["full_access_cost"])?),
        gas_price: yocto(gas_price["gas_price"].as_str().context("prix du gaz NEAR illisible")?)?,
        purchase_price: price(&runtime["min_gas_purchase_price"]).unwrap_or(0),
    })
}

impl Costs {
    /// (frais réels attendus, maximum retenu) d'un virement.
    fn fee(&self, creates: bool) -> Result<(u128, u128)> {
        let (send, exec) = if creates { (self.transfer_gas.0 + self.create_gas.0, self.transfer_gas.1 + self.create_gas.1) } else { self.transfer_gas };
        let actual = (send + exec) * self.gas_price;
        let held = (send * self.gas_price + exec * self.gas_price.max(self.purchase_price)) * 12 / 10;
        ensure!(held <= MAX_FEE_YOCTO, "frais du réseau NEAR anormalement élevés ({} NEAR) — réessayez plus tard", format_near_exact(held));
        Ok((actual, held))
    }
}

/// Solde (yoctoNEAR) ; 0 pour un compte jamais utilisé.
pub fn balance(net: &Network, account: &str) -> Result<u128> {
    Ok(account_state(net, account)?.map_or(0, |a| a.amount))
}

/// Activité d'une adresse destinataire : (détient des NEAR, existe).
pub fn address_activity(net: &Network, account: &str) -> Result<(bool, bool)> {
    Ok(match account_state(net, account)? {
        Some(a) => (a.amount > 0, true),
        None => (false, false),
    })
}

/// Envoi préparé pour la boîte de confirmation.
#[derive(Clone, Copy, Debug)]
pub struct NearPlan {
    pub amount: u128,
    /// Maximum retenu pour les frais (le surplus revient en quelques secondes).
    pub fee: u128,
    /// Frais réels attendus (gaz × prix du moment).
    pub fee_actual: u128,
    /// NEAR réservés au stockage du compte de départ.
    pub reserved: u128,
    /// Destinataire implicite jamais utilisé : le virement le crée.
    pub creates: bool,
}

const NOT_ACTIVATED: &str = "compte NEAR pas encore activé : il doit d'abord recevoir des NEAR";

/// Contrôles du réseau (stockage, création, compte nommé existant) et frais.
pub fn plan(net: &Network, from: &str, to: &str, amount: u128) -> Result<NearPlan> {
    ensure!(amount > 0, "montant nul");
    let (from, to) = (parse_account(from)?, parse_account(to)?);
    ensure!(from != to, "envoi vers votre propre adresse NEAR");
    let sender = account_state(net, &from)?.context(NOT_ACTIVATED)?;
    let costs = costs(net)?;
    let destination = account_state(net, &to)?;
    let creates = destination.is_none();
    if creates {
        ensure!(is_implicit(&to), "ce compte NEAR n'existe pas : vérifiez l'adresse");
        let minimum = IMPLICIT_ACCOUNT_BYTES * costs.storage_per_byte;
        ensure!(amount >= minimum, "ce destinataire n'est pas encore activé : envoyez-lui au moins {} NEAR (stockage du compte)", format_near_exact(minimum));
    }
    let (fee_actual, fee) = costs.fee(creates)?;
    let reserved = sender.storage_usage * costs.storage_per_byte;
    let spendable = sender.amount.saturating_sub(reserved);
    ensure!(
        amount.checked_add(fee).is_some_and(|need| need <= spendable),
        "NEAR insuffisants : {} NEAR envoyables ({} NEAR restent réservés au stockage du compte), {} NEAR + {} NEAR de frais demandés",
        format_near_exact(spendable.saturating_sub(fee)),
        format_near_exact(reserved),
        format_near_exact(amount),
        format_near_exact(fee)
    );
    Ok(NearPlan { amount, fee, fee_actual, reserved, creates })
}

/// Plus grand montant envoyable (vers `to` s'il est connu : un compte à
/// créer coûte un peu plus de gaz).
pub fn max_amount(net: &Network, from: &str, to: Option<&str>) -> Result<u128> {
    let sender = account_state(net, from)?.context(NOT_ACTIVATED)?;
    let costs = costs(net)?;
    let creates = match to {
        Some(to) => account_state(net, to)?.is_none(),
        None => false,
    };
    let (_, fee) = costs.fee(creates)?;
    sender.amount.saturating_sub(sender.storage_usage * costs.storage_per_byte).checked_sub(fee).filter(|m| *m > 0).context("NEAR insuffisants pour couvrir les frais du réseau")
}

/// Construit, signe et diffuse l'envoi préparé ; renvoie son identifiant.
pub fn send(net: &Network, key: &SigningKey, to: &str, plan: &NearPlan) -> Result<String> {
    let signer = implicit_account(key);
    let public_key = key.verifying_key().to_bytes();
    // Nonce lu au dernier bloc (« optimistic ») : deux envois rapprochés ne
    // réutilisent pas un nonce déjà consommé (refus InvalidNonce).
    let access = rpc_ok(net, "query", json!({ "request_type": "view_access_key", "finality": "optimistic", "account_id": signer, "public_key": format!("ed25519:{}", bs58::encode(public_key).into_string()) }))?;
    let nonce = access["nonce"].as_u64().context("clé d'accès NEAR illisible")?;
    let block_hash: [u8; 32] = access["block_hash"].as_str().and_then(|h| bs58::decode(h).into_vec().ok()).and_then(|h| h.try_into().ok()).context("bloc NEAR illisible")?;
    let tx = Transfer { signer, public_key, nonce: nonce + 1, receiver: parse_account(to)?, block_hash, deposit: plan.amount };
    submit(net, &sign(&tx, key))
}

/// Diffuse (nœud suivant si l'un ne répond pas). Sans réponse nette d'aucun :
/// « peut-être partie » (voir `wallet_flow::maybe_sent`) ; et un refus
/// venu APRÈS un nœud resté sans réponse (nonce déjà utilisé…) peut venir de
/// CETTE transaction déjà reçue : « peut-être partie » aussi, jamais
/// « refusée ».
pub fn submit(net: &Network, signed: &Signed) -> Result<String> {
    let blob = base64::engine::general_purpose::STANDARD.encode(&signed.bytes);
    let body = json!({ "jsonrpc": "2.0", "id": "ow", "method": "send_tx", "params": { "signed_tx_base64": blob, "wait_until": "EXECUTED_OPTIMISTIC" } });
    let mut uncertain = false;
    let mut last = anyhow!("nœud NEAR injoignable");
    for node in net.rpc {
        let value: Value = match client().post(node).json(&body).send() {
            Ok(response) if response.status().is_success() || response.status() == reqwest::StatusCode::BAD_REQUEST => match response.json() {
                Ok(value) => value,
                Err(_) => {
                    uncertain = true;
                    continue;
                }
            },
            Ok(response) => {
                uncertain |= crate::wallet_flow::server_error_may_have_sent(response.status());
                last = anyhow!("nœud NEAR : réponse {}", response.status());
                continue;
            }
            Err(e) => {
                uncertain |= !crate::wallet_flow::nothing_sent(&e);
                last = anyhow::Error::new(e).context("nœud NEAR injoignable");
                continue;
            }
        };
        return submit_outcome(reply(&value), signed, uncertain);
    }
    Err(if uncertain { crate::wallet_flow::maybe_sent(&signed.hash) } else { last })
}

fn submit_outcome(outcome: std::result::Result<Value, RpcError>, signed: &Signed, uncertain: bool) -> Result<String> {
    match outcome {
        Ok(result) => {
            let status = &result["status"];
            if let Some(failure) = status.get("Failure") {
                bail!("transaction NEAR refusée : {}", compact(failure));
            }
            ensure!(status.get("SuccessValue").is_some() || status.get("SuccessReceiptId").is_some(), "transaction NEAR : état inattendu");
            ensure!(result["transaction"]["hash"].as_str() == Some(signed.hash.as_str()), "le nœud NEAR a renvoyé un autre identifiant de transaction");
            Ok(signed.hash.clone())
        }
        // Délai dépassé : la transaction peut encore être exécutée.
        Err(e) if e.name == "TIMEOUT_ERROR" => bail!("réseau NEAR lent : transaction {} envoyée mais pas encore confirmée — vérifiez l'historique avant de renvoyer", signed.hash),
        Err(_) if uncertain => Err(crate::wallet_flow::maybe_sent(&signed.hash)),
        Err(e) => bail!("transaction NEAR refusée : {} {}", e.name, e.detail),
    }
}

/// Erreur d'exécution en une ligne courte.
fn compact(value: &Value) -> String {
    let text = value.to_string();
    text.chars().filter(|c| !matches!(c, '{' | '}' | '"')).take(200).collect()
}

// --- Historique ----------------------------------------------------------------------------

/// Virements de NEAR de l'adresse (envoyés, reçus — y compris d'un contrat,
/// hors remboursements de gaz), les plus récents d'abord.
pub fn history(net: &Network, account: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    let account = parse_account(account)?;
    let list: Value = client().post(format!("{}/v0/account", net.tx_index)).json(&json!({ "account_id": account })).send().context("index NEAR injoignable")?.json().context("réponse de l'index NEAR illisible")?;
    let mut txs: Vec<(u64, String)> = list["account_txs"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|t| Some((t["tx_block_height"].as_u64()?, t["transaction_hash"].as_str()?.to_string())))
        .collect();
    txs.sort_by_key(|t| std::cmp::Reverse(t.0));
    txs.dedup_by(|a, b| a.1 == b.1);
    txs.truncate(limit.clamp(1, 50));
    let mut entries = Vec::new();
    for chunk in txs.chunks(20) {
        let hashes: Vec<&str> = chunk.iter().map(|t| t.1.as_str()).collect();
        let details: Value = client().post(format!("{}/v0/transactions", net.tx_index)).json(&json!({ "tx_hashes": hashes })).send().context("index NEAR injoignable")?.json().context("réponse de l'index NEAR illisible")?;
        for tx in details["transactions"].as_array().map(Vec::as_slice).unwrap_or_default() {
            if let Some(entry) = history_entry(tx, &account) {
                entries.push(entry);
            }
        }
    }
    entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp_unix));
    Ok(entries)
}

fn history_entry(tx: &Value, account: &str) -> Option<history::TxEntry> {
    let hash = tx["transaction"]["hash"].as_str().or(tx["execution_outcome"]["id"].as_str())?;
    let succeeded = |outcome: &Value| outcome["outcome"]["status"].get("SuccessValue").is_some() || outcome["outcome"]["status"].get("SuccessReceiptId").is_some();
    let (mut incoming, mut outgoing, mut burnt, mut failed) = (0u128, 0u128, 0u128, false);
    burnt += tx["execution_outcome"]["outcome"]["tokens_burnt"].as_str().and_then(|t| t.parse::<u128>().ok()).unwrap_or(0);
    for receipt in tx["receipts"].as_array().map(Vec::as_slice).unwrap_or_default() {
        burnt += receipt["execution_outcome"]["outcome"]["tokens_burnt"].as_str().and_then(|t| t.parse::<u128>().ok()).unwrap_or(0);
        let Some(actions) = receipt["receipt"]["receipt"]["Action"]["actions"].as_array() else { continue };
        let deposits: u128 = actions.iter().filter_map(|a| a["Transfer"]["deposit"].as_str()?.parse::<u128>().ok()).sum();
        if deposits == 0 {
            continue;
        }
        let (predecessor, receiver) = (receipt["receipt"]["predecessor_id"].as_str(), receipt["receipt"]["receiver_id"].as_str());
        let ok = succeeded(&receipt["execution_outcome"]);
        if receiver == Some(account) && predecessor != Some("system") && predecessor != Some(account) {
            if ok {
                incoming += deposits;
            }
        } else if predecessor == Some(account) && receiver != Some(account) {
            if ok {
                outgoing += deposits;
            } else {
                failed = true;
            }
        }
    }
    if incoming == 0 && outgoing == 0 && !failed {
        return None;
    }
    let signer = tx["transaction"]["signer_id"].as_str() == Some(account);
    let fee = if signer { burnt } else { 0 };
    let net = i128::try_from(incoming).ok()? - i128::try_from(outgoing).ok()? - i128::try_from(fee).ok()?;
    let timestamp = tx["execution_outcome"]["block_timestamp"].as_u64().map(|ns| (ns / 1_000_000_000) as i64);
    Some(history::TxEntry {
        id: hash.to_string(),
        timestamp_unix: timestamp,
        status: if failed { history::TxStatus::Failed } else { history::TxStatus::Confirmed },
        net_amount_minor: Some(net),
        fee_minor: 0,
        kind: if net > 0 { history::TxKind::Received } else { history::TxKind::Sent },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn key(index: u32) -> SigningKey {
        crate::derivation::derive_near_key(&hex::decode(SEED).unwrap(), index)
    }

    /// Vecteurs de near-seed-phrase (dérivation des portefeuilles NEAR) et
    /// de @near-js/transactions, indépendants de ce code.
    #[test]
    fn keys_and_transactions_match_the_official_libraries() {
        for (index, expected) in [(0, "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412"), (1, "3b93b03253b9715213ec314eb50ecc99d25602ccb5b059f91f51d24710d54326"), (7, "689ec7ca9d844e55d75d1fd43c2d3c5582a3b54722f89ffbb4cc3b8d28d46735")] {
            assert_eq!(implicit_account(&key(index)), expected, "index {index}");
        }
        assert_eq!(bs58::encode(key(0).verifying_key().to_bytes()).into_string(), "6j4b6zUaty6fD1awqcGCCU9JYGCWYUgdJhQrzfZhqE25");
        let block = |h: &str| -> [u8; 32] { bs58::decode(h).into_vec().unwrap().try_into().unwrap() };
        let t1 = Transfer { signer: implicit_account(&key(0)), public_key: key(0).verifying_key().to_bytes(), nonce: 12_345_678_901, receiver: implicit_account(&key(1)), block_hash: block("CW7viZzmpbwWcwJbDabJ8x9HczC8Czc1hPA8SQcSyyEi"), deposit: 1_500_000_000_000_000_000_000_000 };
        assert_eq!(hex::encode(t1.borsh()), "4000000035353130653262343463616536656238303765336530653435643537396464613035386332373461626362613135653563623834363336663564316565343132005510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412351cdcdf020000004000000033623933623033323533623937313532313365633331346562353065636339396432353630326363623562303539663931663531643234373130643534333236aae63b27cab273f393ddb567b10fc01c52198830e5bae1344dfca0485953966b0100000003000080716433b629a33d010000000000");
        let signed = sign(&t1, &key(0));
        assert_eq!(signed.hash, "49g8fGFVPAaAdRxPDqWkRB5ZRqNQj1cgQVJfFVKhXD6X");
        assert_eq!(hex::encode(&signed.bytes), "4000000035353130653262343463616536656238303765336530653435643537396464613035386332373461626362613135653563623834363336663564316565343132005510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412351cdcdf020000004000000033623933623033323533623937313532313365633331346562353065636339396432353630326363623562303539663931663531643234373130643534333236aae63b27cab273f393ddb567b10fc01c52198830e5bae1344dfca0485953966b0100000003000080716433b629a33d01000000000000913f9f2b22571ec49fb93086c5ee141243c8bc1b3efea0c4e27381977dde34f9e738197e8ca2ef1ae9c7676fb06ec18fcd599d3ffb8c539f64f4c9526397ec02");
        let t2 = Transfer { signer: implicit_account(&key(0)), public_key: key(0).verifying_key().to_bytes(), nonce: 7, receiver: "alice.near".into(), block_hash: block("DjsYX3zyMrmRukvkbKPeoJG7ZkyfV4yUX2R2ERga9gjG"), deposit: 1 };
        let signed = sign(&t2, &key(0));
        assert_eq!(signed.hash, "GdUiesG9aqedyx8Bexo69VzyQkBbKJjV474uRSHCxPjb");
        assert_eq!(hex::encode(&signed.bytes), "4000000035353130653262343463616536656238303765336530653435643537396464613035386332373461626362613135653563623834363336663564316565343132005510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee41207000000000000000a000000616c6963652e6e656172bd47c9667dcfe23a95c04c3ef05a47562c17332d85c4a803195e6dce6c06693f01000000030100000000000000000000000000000000d8044f3213e1918edb89f517b3479edf892d7dd871e2ba3202e17d46bb945ea31f75cd28406328eedd43e5357cabf94b582ffdb2434fb41afc60ad40fce4c60a");
    }

    #[test]
    fn account_ids_follow_the_protocol_rules() {
        for ok in ["alice.near", "a1", "relay.tg", "my-wallet_2.sub.near", "c108f2eee566da96a4f07dcf7faa5821435ee8a76a03f36d2104ba21749d0e9b"] {
            assert_eq!(parse_account(ok).unwrap(), ok);
        }
        for bad in ["a", "Alice.near", "alice..near", ".alice", "alice.", "-alice", "alice-", "al--ice", "al_-ice", "alice near", "aliçe.near", &"a".repeat(65)] {
            assert!(parse_account(bad).is_err(), "{bad}");
        }
        assert!(parse_account("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap_err().to_string().contains("carte Ethereum"));
        assert!(is_implicit("c108f2eee566da96a4f07dcf7faa5821435ee8a76a03f36d2104ba21749d0e9b") && !is_implicit("alice.near"));
    }

    #[test]
    fn amounts_are_formatted() {
        assert_eq!(format_near(1_500_000_000_000_000_000_000_000), "1.50000");
        assert_eq!(format_near_exact(1_820_000_000_000_000_000_000), "0.00182");
        assert_eq!(format_near_exact(2_000_000_000_000_000_000_000_000), "2");
        assert_eq!(format_near_exact(1), "0.000000000000000000000001");
    }

    /// Historique : virement reçu d'un contrat compté, remboursement de gaz
    /// (« system ») ignoré, frais du signataire déduits.
    #[test]
    fn history_entries_come_from_receipts() {
        let me = "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412";
        let receipt = |pred: &str, recv: &str, deposit: &str, ok: bool, burnt: &str| {
            json!({ "execution_outcome": { "outcome": { "tokens_burnt": burnt, "status": if ok { json!({ "SuccessValue": "" }) } else { json!({ "Failure": {} }) } } }, "receipt": { "predecessor_id": pred, "receiver_id": recv, "receipt": { "Action": { "actions": [{ "Transfer": { "deposit": deposit } }] } } } })
        };
        let incoming = json!({ "transaction": { "hash": "H1", "signer_id": "solver.near" }, "execution_outcome": { "block_timestamp": 1_791_144_173_672_955_600u64, "outcome": { "tokens_burnt": "100" } }, "receipts": [receipt("intents.near", me, "5000", true, "10"), receipt("system", me, "77", true, "0")] });
        let entry = history_entry(&incoming, me).unwrap();
        assert_eq!((entry.net_amount_minor, entry.kind == history::TxKind::Received, entry.timestamp_unix), (Some(5000), true, Some(1_791_144_173)));
        let outgoing = json!({ "transaction": { "hash": "H2", "signer_id": me }, "execution_outcome": { "block_timestamp": 1u64, "outcome": { "tokens_burnt": "100" } }, "receipts": [receipt(me, "alice.near", "3000", true, "20"), receipt("system", me, "50", true, "0")] });
        let entry = history_entry(&outgoing, me).unwrap();
        assert_eq!((entry.net_amount_minor, entry.kind == history::TxKind::Sent), (Some(-3120), true));
        let failed = json!({ "transaction": { "hash": "H3", "signer_id": me }, "execution_outcome": { "block_timestamp": 1u64, "outcome": { "tokens_burnt": "100" } }, "receipts": [receipt(me, "nobody.near", "3000", false, "20")] });
        let entry = history_entry(&failed, me).unwrap();
        assert!(matches!(entry.status, history::TxStatus::Failed) && entry.net_amount_minor == Some(-120));
        let unrelated = json!({ "transaction": { "hash": "H4", "signer_id": "x.near" }, "execution_outcome": { "block_timestamp": 1u64, "outcome": { "tokens_burnt": "1" } }, "receipts": [receipt("x.near", "y.near", "9", true, "0")] });
        assert!(history_entry(&unrelated, me).is_none());
    }

    /// Réel, réseau de test (compte créé gratuitement par le service de
    /// création de comptes) : virement qui CRÉE un compte implicite, puis
    /// renvoi depuis ce compte implicite, signés ici et exécutés ; signature
    /// altérée refusée ; compte nommé inexistant refusé avant signature.
    /// `cargo test -- --ignored real_near --nocapture`
    #[test]
    #[ignore]
    fn real_near_testnet_end_to_end() {
        let random_key = || {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            SigningKey::from_bytes(&seed)
        };
        // Compte nommé financé (10 NEAR de test), à la clé de « alice ».
        let alice = random_key();
        let alice_name = format!("ow{}.testnet", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        let created = client()
            .post("https://helper.testnet.near.org/account")
            .json(&json!({ "newAccountId": alice_name, "newAccountPublicKey": format!("ed25519:{}", bs58::encode(alice.verifying_key().to_bytes()).into_string()) }))
            .send()
            .unwrap();
        assert!(created.status().is_success(), "création du compte de test : {}", created.status());
        // Lectures en finalité « final » : quelques secondes de retard.
        let wait_for = |account: &str| {
            for _ in 0..15 {
                if account_state(&TESTNET, account).unwrap().is_some() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            panic!("compte {account} jamais visible");
        };
        wait_for(&alice_name);
        let bob = random_key();
        let bob_account = implicit_account(&bob);
        // Le compte de « alice » est nommé : envoi par sa clé, signataire = son nom.
        let send_from_named = |plan: &NearPlan, to: &str| -> Result<String> {
            let public_key = alice.verifying_key().to_bytes();
            let access = rpc_ok(&TESTNET, "query", json!({ "request_type": "view_access_key", "finality": "final", "account_id": alice_name, "public_key": format!("ed25519:{}", bs58::encode(public_key).into_string()) }))?;
            let block_hash: [u8; 32] = bs58::decode(access["block_hash"].as_str().unwrap()).into_vec()?.try_into().unwrap();
            let tx = Transfer { signer: alice_name.clone(), public_key, nonce: access["nonce"].as_u64().unwrap() + 1, receiver: to.to_string(), block_hash, deposit: plan.amount };
            submit(&TESTNET, &sign(&tx, &alice))
        };
        let tiny = plan(&TESTNET, &alice_name, &bob_account, 1_000_000_000_000_000_000_000).unwrap_err().to_string();
        assert!(tiny.contains("au moins 0.00182 NEAR"), "{tiny}");
        let first = plan(&TESTNET, &alice_name, &bob_account, 50_000_000_000_000_000_000_000).unwrap();
        assert!(first.creates, "{first:?}");
        println!("création : {} (frais max {} NEAR)", send_from_named(&first, &bob_account).unwrap(), format_near_exact(first.fee));
        wait_for(&bob_account);
        assert_eq!(balance(&TESTNET, &bob_account).unwrap(), 50_000_000_000_000_000_000_000);
        // Renvoi depuis le compte implicite (chemin de l'app).
        let back = plan(&TESTNET, &bob_account, &alice_name, 10_000_000_000_000_000_000_000).unwrap();
        assert!(!back.creates);
        let sent = send(&TESTNET, &bob, &alice_name, &back).unwrap();
        println!("renvoi : {sent} depuis {bob_account}");
        // Après le remboursement du surplus retenu : frais réels EXACTS.
        let expected = 40_000_000_000_000_000_000_000 - back.fee_actual;
        let mut left = 0;
        for _ in 0..20 {
            left = balance(&TESTNET, &bob_account).unwrap();
            if left == expected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        assert_eq!(left, expected, "frais réels {} NEAR attendus, retenue max {} NEAR", format_near_exact(back.fee_actual), format_near_exact(back.fee));
        // Signature altérée : refusée par le nœud.
        let access = rpc_ok(&TESTNET, "query", json!({ "request_type": "view_access_key", "finality": "final", "account_id": bob_account, "public_key": format!("ed25519:{}", bs58::encode(bob.verifying_key().to_bytes()).into_string()) })).unwrap();
        let tx = Transfer { signer: bob_account.clone(), public_key: bob.verifying_key().to_bytes(), nonce: access["nonce"].as_u64().unwrap() + 1, receiver: alice_name.clone(), block_hash: bs58::decode(access["block_hash"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap(), deposit: 1 };
        let mut signed = sign(&tx, &bob);
        let last = signed.bytes.len() - 1;
        signed.bytes[last] ^= 1;
        let error = submit(&TESTNET, &signed).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("InvalidSignature") || error.contains("INVALID_TRANSACTION"), "{error}");
        // Compte nommé inexistant : refusé avant toute signature.
        assert!(plan(&TESTNET, &bob_account, "personne-ici-123.testnet", 1).unwrap_err().to_string().contains("n'existe pas"));
        // Historique (l'index suit le réseau à quelques secondes).
        let mut found = Vec::new();
        for _ in 0..10 {
            found = history(&TESTNET, &bob_account, 10).unwrap();
            if found.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        assert!(found.iter().any(|e| e.kind == history::TxKind::Received && e.net_amount_minor == Some(50_000_000_000_000_000_000_000)), "historique : {}", found.len());
        assert!(found.iter().any(|e| e.id == sent && e.net_amount_minor.is_some_and(|n| n < -10_000_000_000_000_000_000_000)));
        // Réseau principal : lectures.
        let main = costs(&MAINNET).unwrap();
        println!("principal : gaz {} yocto, frais virement {} NEAR, création {} NEAR", main.gas_price, format_near_exact(main.fee(false).unwrap().0), format_near_exact(main.fee(true).unwrap().0));
        assert!(balance(&MAINNET, "relay.tg").unwrap() > 0);
    }
}
