//! Historique BNB Chain par NodeReal (fournisseur d'infrastructure de BNB
//! Chain, offre gratuite) : `nr_getAssetTransfers`, les virements d'une
//! adresse — BNB envoyés et reçus (y compris reçus d'un contrat : sortie
//! d'un échange, d'un pont), jetons BEP-20.
//!
//! Aucun service public sans clé ne fournit cet historique (constaté le
//! 07/10/2026 : ni Blockscout, ni Routescan, ni l'offre gratuite d'Etherscan ;
//! CoinGecko et CoinMarketCap n'ont pas d'historique par adresse). Clé lue À
//! LA COMPILATION (`NODEREAL_API_KEY` dans `partner-keys.env`, voir build.rs) ;
//! absente : historique indisponible, l'app renvoie vers BscScan. Lecture
//! seule, purement informatif ; seule l'adresse publique est envoyée.

use crate::blockscout::{EvmTx, TokenMove};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Clé d'API (offre gratuite), intégrée à la compilation.
pub const API_KEY: Option<&str> = option_env!("NODEREAL_API_KEY");
const ENDPOINT: &str = "https://bsc-mainnet.nodereal.io/v1/";
/// Virements demandés par sens et par appel.
const BATCH: usize = 50;
/// Écart minimal entre deux appels (offre gratuite partagée par tous les
/// utilisateurs de l'app : pas de rafale).
const SPACING: Duration = Duration::from_millis(150);
/// Contrat d'entrée de LI.FI sur BNB Chain (voir `lifi::diamond`) : un
/// envoi vers lui, ou des BNB reçus de lui, sont un échange.
const LIFI_DIAMOND: &str = "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae";

/// Historique BNB indisponible : clé absente de cette version de l'app.
pub const KEY_MISSING: &str = "historique BNB Chain indisponible dans cette version de l'app";
/// Quota ou débit de l'offre gratuite atteint.
pub const LIMITED: &str = "historique BNB Chain momentanément indisponible (limite du service atteinte) — réessayez plus tard";

pub fn available() -> bool {
    API_KEY.is_some()
}

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::blocking::Client::builder().timeout(Duration::from_secs(20)).build().expect("configuration du client HTTP valide"))
}

fn pace() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(wait) = last.map(|t| SPACING.saturating_sub(t.elapsed())) {
        std::thread::sleep(wait);
    }
    *last = Some(Instant::now());
}

/// Nombre d'une réponse : chaîne hexadécimale (« 0x1f »), décimale, ou nombre.
fn number(value: &Value) -> Option<u128> {
    match value {
        Value::Number(n) => n.as_u64().map(u128::from),
        Value::String(s) => match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some("") => Some(0),
            Some(hex) => u128::from_str_radix(hex, 16).ok(),
            None => s.parse().ok(),
        },
        _ => None,
    }
}

/// Un virement de la réponse, réduit à ce qui sert.
#[derive(Clone, Debug, PartialEq)]
struct Transfer {
    /// Identifiant du virement chez NodeReal (un même virement apparaît dans
    /// les deux sens s'il va de l'adresse vers elle-même).
    id: String,
    /// « external », « internal » ou « 20 ».
    category: String,
    block: u64,
    from: String,
    to: String,
    value: u128,
    hash: String,
    contract: Option<String>,
    timestamp: Option<i64>,
    /// Frais de la transaction (virement externe seulement), en wei.
    fee: u128,
    failed: bool,
}

fn transfer(value: &Value) -> Result<Transfer> {
    let text = |name: &str| value[name].as_str().map(str::to_lowercase);
    let block = number(&value["blockNum"]).context("réponse NodeReal : bloc absent")?;
    let gas_used = number(&value["gasUsed"]).unwrap_or(0);
    let gas_price = number(&value["gasPrice"]).unwrap_or(0);
    Ok(Transfer {
        id: match &value["id"] {
            Value::Null => format!("{}:{}", text("hash").unwrap_or_default(), value["logIndex"]),
            other => other.to_string(),
        },
        category: text("category").context("réponse NodeReal : catégorie absente")?,
        block: u64::try_from(block).context("réponse NodeReal : bloc hors limites")?,
        from: text("from").unwrap_or_default(),
        to: text("to").unwrap_or_default(),
        value: number(&value["value"]).unwrap_or(0),
        hash: text("hash").context("réponse NodeReal : transaction absente")?,
        contract: text("contractAddress").filter(|c| !c.is_empty()),
        timestamp: number(&value["blockTimeStamp"]).and_then(|t| i64::try_from(t).ok()),
        fee: gas_used.saturating_mul(gas_price),
        failed: number(&value["receiptsStatus"]) == Some(0),
    })
}

/// Un appel `nr_getAssetTransfers` : virements et clé de la page suivante.
fn call(params: Value) -> Result<(Vec<Transfer>, Option<String>)> {
    let key = API_KEY.ok_or_else(|| anyhow!(KEY_MISSING))?;
    pace();
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "nr_getAssetTransfers", "params": [params] });
    // La clé voyage dans l'URL : erreurs réseau reformulées SANS l'URL.
    let response = shared_client().post(format!("{ENDPOINT}{key}")).json(&body).send().map_err(|e| anyhow!("NodeReal injoignable : {}", e.without_url()))?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!(LIMITED);
    }
    let reply: Value = response.json().map_err(|e| anyhow!("réponse NodeReal illisible : {}", e.without_url()))?;
    parse_reply(&reply)
}

fn parse_reply(reply: &Value) -> Result<(Vec<Transfer>, Option<String>)> {
    if let Some(error) = reply.get("error") {
        let message = error["message"].as_str().unwrap_or_default();
        let lower = message.to_lowercase();
        if ["limit", "quota", "exceed", "too many"].iter().any(|word| lower.contains(word)) {
            bail!(LIMITED);
        }
        bail!("NodeReal a refusé la demande : {message}");
    }
    let result = &reply["result"];
    let transfers = result["transfers"].as_array().context("réponse NodeReal : virements absents")?.iter().map(transfer).collect::<Result<Vec<_>>>()?;
    let next = result["pageKey"].as_str().filter(|k| !k.is_empty()).map(String::from);
    Ok((transfers, next))
}

/// Un sens de lecture (envois ou réceptions) : virements lus d'avance, et
/// page suivante chez NodeReal.
#[derive(Clone, Debug, Default, PartialEq)]
struct Stream {
    buffer: Vec<Transfer>,
    next_key: Option<String>,
    done: bool,
}

/// Suite d'un historique : les deux sens, avec ce qui a été lu mais pas
/// encore rendu (plus ancien que la page rendue).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Cursor {
    sent: Stream,
    received: Stream,
}

impl Stream {
    /// Complète le tampon jusqu'à une page, si le sens n'est pas épuisé.
    fn fill(&mut self, mut params: Value, fetch: &mut impl FnMut(Value) -> Result<(Vec<Transfer>, Option<String>)>) -> Result<()> {
        if self.done || self.buffer.len() >= BATCH {
            return Ok(());
        }
        if let Some(key) = &self.next_key {
            params["pageKey"] = json!(key);
        }
        let (transfers, next) = fetch(params)?;
        self.done = next.is_none() || transfers.is_empty();
        self.next_key = next;
        self.buffer.extend(transfers);
        Ok(())
    }

    /// Plus ancien bloc lu d'un sens encore ouvert : en deçà, d'autres
    /// virements de ce sens peuvent encore venir.
    fn frontier(&self) -> Option<u64> {
        if self.done {
            None
        } else {
            self.buffer.iter().map(|t| t.block).min()
        }
    }
}

/// Page suivante, les deux sens fusionnés du plus récent au plus ancien :
/// seuls les virements plus récents que la frontière des deux sens sont
/// rendus (un virement plus ancien d'un sens peut encore manquer de l'autre),
/// le reste attend la page suivante.
fn next_page(
    address: &str,
    sent_params: Value,
    received_params: Value,
    cursor: Option<&Cursor>,
    fetch: &mut impl FnMut(Value) -> Result<(Vec<Transfer>, Option<String>)>,
) -> Result<(Vec<Transfer>, Option<Cursor>)> {
    let mut state = cursor.cloned().unwrap_or_default();
    state.sent.fill(json_with(sent_params, "fromAddress", address), fetch)?;
    state.received.fill(json_with(received_params, "toAddress", address), fetch)?;
    let frontier = state.sent.frontier().into_iter().chain(state.received.frontier()).max();
    let mut page: Vec<Transfer> = Vec::new();
    for stream in [&mut state.sent, &mut state.received] {
        let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut stream.buffer).into_iter().partition(|t| frontier.is_none_or(|f| t.block > f));
        page.extend(ready);
        stream.buffer = later;
    }
    // Toute une page dans un même bloc (cas extrême) : rendue telle quelle.
    if page.is_empty() {
        for stream in [&mut state.sent, &mut state.received] {
            page.extend(std::mem::take(&mut stream.buffer));
        }
    }
    // Un virement de l'adresse vers elle-même figure dans les deux sens.
    let mut seen = std::collections::HashSet::new();
    page.retain(|t| seen.insert(t.id.clone()));
    page.sort_by(|a, b| b.block.cmp(&a.block).then_with(|| a.hash.cmp(&b.hash)));
    let more = !(state.sent.done && state.received.done && state.sent.buffer.is_empty() && state.received.buffer.is_empty());
    Ok((page, more.then_some(state)))
}

fn json_with(mut params: Value, name: &str, address: &str) -> Value {
    params[name] = json!(address.to_lowercase());
    params
}

fn base_params(categories: &[&str]) -> Value {
    json!({ "category": categories, "order": "desc", "maxCount": format!("0x{BATCH:x}") })
}

/// Virements BNB de la page regroupés par transaction, du point de vue de
/// `address` : montant net (reçu moins envoyé, rien pour une transaction
/// échouée), frais si elle l'a émise.
fn transactions(page: &[Transfer], address: &str) -> Vec<EvmTx> {
    let address = address.to_lowercase();
    let mut txs: Vec<EvmTx> = Vec::new();
    for t in page {
        let index = match txs.iter().position(|tx| tx.hash == t.hash) {
            Some(index) => index,
            None => {
                txs.push(EvmTx { hash: t.hash.clone(), timestamp_unix: t.timestamp, failed: false, net_wei: 0, fee_wei: 0, swap: false });
                txs.len() - 1
            }
        };
        let tx = &mut txs[index];
        let value = i128::try_from(t.value).unwrap_or(i128::MAX);
        let external = t.category == "external";
        if external && t.failed {
            tx.failed = true;
        }
        if external && t.from == address {
            tx.fee_wei = i128::try_from(t.fee).unwrap_or(i128::MAX);
        }
        if !t.failed {
            if t.to == address {
                tx.net_wei += value;
            }
            if t.from == address {
                tx.net_wei -= value;
            }
        }
        tx.swap |= (external && t.from == address && t.to == LIFI_DIAMOND) || (t.to == address && t.from == LIFI_DIAMOND);
    }
    for tx in &mut txs {
        if tx.failed {
            tx.net_wei = 0;
        }
    }
    txs
}

/// Page d'historique BNB de `address` (transactions émises, BNB reçus, y
/// compris d'un contrat) et suite.
pub fn tx_history_page(address: &str, cursor: Option<&Cursor>) -> Result<(Vec<EvmTx>, Option<Cursor>)> {
    let (page, next) = next_page(address, base_params(&["external"]), base_params(&["external", "internal"]), cursor, &mut call)?;
    Ok((transactions(&page, address), next))
}

/// Page des virements du jeton BEP-20 `contract` pour `address`, regroupés
/// par transaction, et suite. Filtré par contrat chez NodeReal ET revérifié
/// ici : un faux jeton au même symbole n'y entre jamais.
pub fn token_history_page(address: &str, contract: &str, cursor: Option<&Cursor>) -> Result<(Vec<TokenMove>, Option<Cursor>)> {
    let contract = contract.to_lowercase();
    let mut params = base_params(&["20"]);
    params["contractAddresses"] = json!([contract]);
    let (page, next) = next_page(address, params.clone(), params, cursor, &mut call)?;
    token_moves(&page, address, &contract).map(|moves| (moves, next))
}

fn token_moves(page: &[Transfer], address: &str, contract: &str) -> Result<Vec<TokenMove>> {
    let address = address.to_lowercase();
    let mut moves: Vec<TokenMove> = Vec::new();
    for t in page {
        anyhow::ensure!(t.contract.as_deref() == Some(contract), "NodeReal a renvoyé un autre jeton que celui demandé");
        let value = i128::try_from(t.value).unwrap_or(i128::MAX);
        let delta = match (t.from == address, t.to == address) {
            (true, false) => -value,
            (false, true) => value,
            _ => 0,
        };
        match moves.iter_mut().find(|m| m.hash == t.hash) {
            Some(existing) => existing.net += delta,
            None => moves.push(TokenMove { hash: t.hash.clone(), timestamp_unix: t.timestamp, net: delta, swap: false }),
        }
    }
    Ok(moves)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0x59d78c44ac60f09369b544778358704b7b18e6ba";
    const OTHER: &str = "0x8894e0a0c962cb723c1976a4421c95949be2d4e3";

    /// Virement au format réel (champs relevés le 07/10/2026 sur une réponse
    /// de `nr_getAssetTransfers`).
    fn raw(id: u64, category: &str, block: u64, from: &str, to: &str, value: u128, hash: &str, status: u64) -> Value {
        json!({
            "id": id, "category": category, "blockNum": format!("0x{block:x}"), "from": from, "to": to,
            "value": format!("0x{value:x}"), "asset": "BNB", "hash": hash, "contractAddress": null,
            "blockTimeStamp": 1_791_368_243u64 + block, "gasPrice": "0x3b9aca00", "gasUsed": "0x5208", "receiptsStatus": status,
        })
    }

    fn parsed(values: Vec<Value>) -> Vec<Transfer> {
        values.iter().map(|v| transfer(v).unwrap()).collect()
    }

    /// Envoi (frais = gas × prix), réception, BNB reçus d'un contrat, envoi
    /// échoué (frais seuls), vers soi-même, échange LI.FI ; casse ignorée.
    #[test]
    fn transfers_become_transactions() {
        let page = parsed(vec![
            raw(1, "external", 100, &ME.to_uppercase().replacen("0X", "0x", 1), OTHER, 1_000, "0xa", 1),
            raw(2, "external", 99, OTHER, ME, 5_000, "0xb", 1),
            raw(3, "internal", 98, "0xcontract", ME, 700, "0xc", 1),
            raw(4, "external", 97, ME, OTHER, 9_999, "0xd", 0),
            raw(5, "external", 96, ME, ME, 42, "0xe", 1),
            raw(6, "external", 95, ME, LIFI_DIAMOND, 300, "0xf", 1),
        ]);
        let txs = transactions(&page, ME);
        let summary: Vec<_> = txs.iter().map(|t| (t.hash.as_str(), t.net_wei, t.fee_wei, t.failed, t.swap)).collect();
        let fee = 21_000 * 1_000_000_000;
        assert_eq!(
            summary,
            vec![
                ("0xa", -1_000, fee, false, false),
                ("0xb", 5_000, 0, false, false),
                ("0xc", 700, 0, false, false),
                ("0xd", 0, fee, true, false),
                ("0xe", 0, fee, false, false),
                ("0xf", -300, fee, false, true),
            ]
        );
        assert_eq!(txs[0].timestamp_unix, Some(1_791_368_343));
    }

    /// Fusion des deux sens : seuls les virements plus récents que la
    /// frontière sont rendus, le reste à la page suivante ; un virement vers
    /// soi-même (présent dans les deux sens) une seule fois ; fin quand les
    /// deux sens sont épuisés.
    #[test]
    fn both_directions_are_merged_by_block() {
        let mut calls = 0;
        let mut fetch = |params: Value| -> Result<(Vec<Transfer>, Option<String>)> {
            calls += 1;
            let sent = params.get("fromAddress").is_some();
            let second = params.get("pageKey").is_some();
            Ok(match (sent, second) {
                // Envois : blocs 100 et 90, puis 50.
                (true, false) => (parsed(vec![raw(1, "external", 100, ME, OTHER, 1, "0xa", 1), raw(2, "external", 90, ME, ME, 2, "0xs", 1)]), Some("k1".into())),
                (true, true) => (parsed(vec![raw(3, "external", 50, ME, OTHER, 3, "0xc", 1)]), None),
                // Réceptions : blocs 95, 90 (vers soi-même) et 40, puis rien.
                (false, _) => (
                    parsed(vec![raw(4, "external", 95, OTHER, ME, 4, "0xd", 1), raw(2, "external", 90, ME, ME, 2, "0xs", 1), raw(5, "external", 40, OTHER, ME, 5, "0xe", 1)]),
                    None,
                ),
            })
        };
        let (first, cursor) = next_page(ME, base_params(&["external"]), base_params(&["external"]), None, &mut fetch).unwrap();
        // Frontière : bloc 90 (envois encore ouverts) ; rendus : 100 et 95.
        assert_eq!(first.iter().map(|t| t.block).collect::<Vec<_>>(), vec![100, 95]);
        let cursor = cursor.expect("suite attendue");
        let (second, cursor) = next_page(ME, base_params(&["external"]), base_params(&["external"]), Some(&cursor), &mut fetch).unwrap();
        assert_eq!(second.iter().map(|t| (t.block, t.hash.as_str())).collect::<Vec<_>>(), vec![(90, "0xs"), (50, "0xc"), (40, "0xe")]);
        assert!(cursor.is_none(), "les deux sens sont épuisés");
        assert_eq!(calls, 3);
    }

    /// Jetons : regroupés par transaction, autre contrat refusé.
    #[test]
    fn token_moves_check_the_contract() {
        let token = "0x000ae314e2a2172a039b26378814c252734f556a";
        let mut a = raw(1, "20", 10, OTHER, ME, 500, "0x1", 1);
        a["contractAddress"] = json!(token);
        let mut b = raw(2, "20", 10, ME, OTHER, 200, "0x1", 1);
        b["contractAddress"] = json!(token);
        let moves = token_moves(&parsed(vec![a, b]), ME, token).unwrap();
        assert_eq!(moves.iter().map(|m| (m.hash.as_str(), m.net)).collect::<Vec<_>>(), vec![("0x1", 300)]);
        let mut fake = raw(3, "20", 9, OTHER, ME, 1, "0x2", 1);
        fake["contractAddress"] = json!("0x0000000000000000000000000000000000000bad");
        assert!(token_moves(&parsed(vec![fake]), ME, token).is_err());
    }

    #[test]
    fn replies_and_numbers_are_read() {
        assert_eq!(number(&json!("0x1f")), Some(31));
        assert_eq!(number(&json!("0x")), Some(0));
        assert_eq!(number(&json!("42")), Some(42));
        assert_eq!(number(&json!(7)), Some(7));
        let (transfers, next) = parse_reply(&json!({ "result": { "transfers": [raw(1, "external", 5, ME, OTHER, 1, "0xa", 1)], "pageKey": "abc" } })).unwrap();
        assert_eq!((transfers.len(), next.as_deref()), (1, Some("abc")));
        assert_eq!(parse_reply(&json!({ "result": { "transfers": [], "pageKey": null } })).unwrap().1, None);
        let limited = parse_reply(&json!({ "error": { "code": -32005, "message": "monthly CU limit exceeded" } })).unwrap_err();
        assert_eq!(limited.to_string(), LIMITED);
        assert!(parse_reply(&json!({ "error": { "code": -32601, "message": "method does not exist" } })).unwrap_err().to_string().contains("refusé"));
    }

    /// Réel (clé requise) : historique de l'adresse chaude de Binance, pages
    /// successives sans doublon et de plus en plus anciennes ; une adresse peu
    /// active lue au-delà de 100 000 blocs (la limite de plage de NodeReal ne
    /// s'applique pas sans bornes de blocs : historique complet).
    /// `cargo test -- --ignored real_nodereal --nocapture`
    #[test]
    #[ignore]
    fn real_nodereal() {
        assert!(available(), "NODEREAL_API_KEY absente de partner-keys.env");
        let (first, cursor) = tx_history_page(OTHER, None).unwrap();
        println!("{} transactions, suite : {}", first.len(), cursor.is_some());
        for tx in first.iter().take(3) {
            println!("{} {:?} net {} frais {}", &tx.hash[..12], tx.timestamp_unix, tx.net_wei, tx.fee_wei);
        }
        assert!(!first.is_empty() && cursor.is_some());
        let (second, _) = tx_history_page(OTHER, cursor.as_ref()).unwrap();
        assert!(second.iter().all(|t| !first.iter().any(|f| f.hash == t.hash)), "pages sans doublon");
        // Adresse peu active : remonter les pages jusqu'à dépasser 100 000 blocs.
        let quiet = "0x000000000000000000000000000000000000dead";
        let mut cursor = None;
        let mut oldest = i64::MAX;
        let newest = tx_history_page(quiet, None).unwrap().0.first().and_then(|t| t.timestamp_unix).unwrap_or(0);
        for _ in 0..8 {
            let (page, next) = tx_history_page(quiet, cursor.as_ref()).unwrap();
            oldest = oldest.min(page.iter().filter_map(|t| t.timestamp_unix).min().unwrap_or(oldest));
            cursor = next;
            if cursor.is_none() || newest - oldest > 2 * 24 * 3600 {
                break;
            }
        }
        println!("adresse peu active : remonté de {} h", (newest - oldest) / 3600);
        assert!(newest - oldest > 24 * 3600, "historique limité à la dernière plage de blocs");
    }
}
