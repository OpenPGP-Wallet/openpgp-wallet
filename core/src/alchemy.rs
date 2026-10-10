//! Historique de Base et de Polygon par Alchemy (offre gratuite) :
//! `alchemy_getAssetTransfers`, les virements d'une adresse — monnaie du
//! réseau envoyée et reçue (y compris reçue d'un contrat : sortie d'un
//! échange, d'un pont), jetons ERC-20.
//!
//! Aucun service sans clé ne fournit plus cet historique (constaté le
//! 10/10/2026) : base/polygon.blockscout.com sont derrière la vérification
//! anti-robots de Cloudflare et l'API officielle de Blockscout les réserve à
//! ses offres payantes ; Etherscan gratuit exclut Base. Clé lue À LA
//! COMPILATION (`ALCHEMY_API_KEY` dans `partner-keys.env`, voir build.rs) ;
//! absente : historique indisponible, l'app renvoie vers l'explorateur.
//! Lecture seule, purement informatif ; seule l'adresse publique est envoyée.
//!
//! Même forme de réponse que `nr_getAssetTransfers` de NodeReal (qui
//! reproduit cette méthode) : pagination dans les deux sens, regroupement par
//! transaction et filtrage des jetons sont ceux de `nodereal`. Mesuré le
//! 10/10/2026 : une transaction échouée n'y figure jamais (ni à l'envoi ni à
//! la réception, vérifié sur Base et Polygon) ; les frais n'y sont pas, ils
//! viennent des reçus (`gasUsed` × `effectiveGasPrice`, plus `l1Fee` sur Base).

use crate::blockscout::{EvmTx, TokenMove};
use crate::nodereal::{self, Cursor, Transfer};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Clé d'API (offre gratuite), intégrée à la compilation.
pub const API_KEY: Option<&str> = option_env!("ALCHEMY_API_KEY");
/// Virements demandés par sens et par appel.
const BATCH: usize = 50;
/// Écart minimal entre deux appels (offre gratuite partagée par tous les
/// utilisateurs de l'app : pas de rafale).
const SPACING: Duration = Duration::from_millis(250);
/// Historique indisponible : clé absente de cette version de l'app.
pub const KEY_MISSING: &str = "historique de ce réseau indisponible dans cette version de l'app";
/// Quota ou débit de l'offre gratuite atteint (même message que Blockscout).
pub const LIMITED: &str = crate::blockscout::BLOCKSCOUT_LIMITED;

/// Réseaux servis : ceux activés pour la clé de l'app, et que plus aucun
/// service sans clé ne couvre.
fn host(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        8_453 => Some("base-mainnet"),
        137 => Some("polygon-mainnet"),
        _ => None,
    }
}

pub fn available(chain_id: u64) -> bool {
    API_KEY.is_some() && host(chain_id).is_some()
}

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().expect("configuration du client HTTP valide"))
}

fn pace() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(wait) = last.map(|t| SPACING.saturating_sub(t.elapsed())) {
        std::thread::sleep(wait);
    }
    *last = Some(Instant::now());
}

/// Un appel JSON-RPC (ou un lot) au nœud Alchemy du réseau.
fn call(chain_id: u64, body: &Value) -> Result<Value> {
    let key = API_KEY.ok_or_else(|| anyhow!(KEY_MISSING))?;
    let host = host(chain_id).ok_or_else(|| anyhow!("historique Alchemy non prévu pour ce réseau"))?;
    pace();
    // La clé voyage dans l'URL : erreurs réseau reformulées SANS l'URL.
    let response = shared_client()
        .post(format!("https://{host}.g.alchemy.com/v2/{key}"))
        .json(body)
        .send()
        .map_err(|e| anyhow!("Alchemy injoignable : {}", e.without_url()))?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!(LIMITED);
    }
    let status = response.status();
    let reply: Value = response.json().map_err(|e| anyhow!("réponse Alchemy illisible : {}", e.without_url()))?;
    if !status.is_success() && reply.get("error").is_none() {
        bail!("Alchemy a répondu {status}");
    }
    Ok(reply)
}

/// Erreur d'une réponse JSON-RPC : limite de l'offre gratuite, ou refus.
fn check_error(reply: &Value) -> Result<()> {
    let Some(error) = reply.get("error") else { return Ok(()) };
    let message = error["message"].as_str().or_else(|| error.as_str()).unwrap_or_default();
    let lower = message.to_lowercase();
    if ["limit", "capacity", "exceed", "too many"].iter().any(|word| lower.contains(word)) {
        bail!(LIMITED);
    }
    bail!("Alchemy a refusé la demande : {message}");
}

/// Un virement de la réponse (champs relevés le 10/10/2026), au format commun
/// avec NodeReal. Montant brut : `rawContract.value` (`value` est arrondi, en
/// unités affichées). Frais : 0 ici, complétés par `add_fees`.
fn transfer(value: &Value) -> Result<Transfer> {
    let text = |v: &Value| v.as_str().map(str::to_lowercase);
    let block = nodereal::number(&value["blockNum"]).context("réponse Alchemy : bloc absent")?;
    let hash = text(&value["hash"]).context("réponse Alchemy : transaction absente")?;
    Ok(Transfer {
        id: text(&value["uniqueId"]).unwrap_or_else(|| format!("{hash}:{}", value["category"])),
        category: text(&value["category"]).context("réponse Alchemy : catégorie absente")?,
        block: u64::try_from(block).context("réponse Alchemy : bloc hors limites")?,
        from: text(&value["from"]).unwrap_or_default(),
        to: text(&value["to"]).unwrap_or_default(),
        value: nodereal::number(&value["rawContract"]["value"]).context("réponse Alchemy : montant absent")?,
        hash,
        contract: text(&value["rawContract"]["address"]).filter(|c| !c.is_empty()),
        timestamp: value["metadata"]["blockTimestamp"].as_str().and_then(crate::blockscout::parse_iso8601_utc),
        fee: 0,
        failed: false,
    })
}

fn parse_transfers(reply: &Value) -> Result<(Vec<Transfer>, Option<String>)> {
    check_error(reply)?;
    let result = &reply["result"];
    let transfers = result["transfers"].as_array().context("réponse Alchemy : virements absents")?.iter().map(transfer).collect::<Result<Vec<_>>>()?;
    let next = result["pageKey"].as_str().filter(|k| !k.is_empty()).map(String::from);
    Ok((transfers, next))
}

fn fetch(chain_id: u64, params: Value) -> Result<(Vec<Transfer>, Option<String>)> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "alchemy_getAssetTransfers", "params": [params] });
    parse_transfers(&call(chain_id, &body)?)
}

/// `with_zero` : garder les virements de montant nul — une transaction de
/// l'adresse sans monnaie envoyée (envoi de jeton, approbation, échange)
/// lui coûte quand même des frais (Alchemy les écarte par défaut).
fn params(categories: &[&str], with_zero: bool) -> Value {
    json!({ "category": categories, "order": "desc", "maxCount": format!("0x{BATCH:x}"), "withMetadata": true, "excludeZeroValue": !with_zero })
}

/// Frais d'un reçu de transaction : gaz × prix effectif, plus la part payée
/// à la couche 1 sur les réseaux OP Stack (Base : `l1Fee`).
fn receipt_fee(receipt: &Value) -> Option<u128> {
    let gas = nodereal::number(&receipt["gasUsed"])?;
    let price = nodereal::number(&receipt["effectiveGasPrice"])?;
    let l1 = nodereal::number(&receipt["l1Fee"]).unwrap_or(0);
    gas.checked_mul(price)?.checked_add(l1)
}

/// Complète les frais des transactions émises par `address` (virement
/// externe qui part d'elle) : reçus demandés en un seul lot.
fn add_fees(chain_id: u64, page: &mut [Transfer], address: &str) -> Result<()> {
    let address = address.to_lowercase();
    let mut hashes: Vec<String> = page.iter().filter(|t| t.category == "external" && t.from == address).map(|t| t.hash.clone()).collect();
    hashes.sort();
    hashes.dedup();
    if hashes.is_empty() {
        return Ok(());
    }
    let batch: Vec<Value> = hashes.iter().enumerate().map(|(i, hash)| json!({ "jsonrpc": "2.0", "id": i, "method": "eth_getTransactionReceipt", "params": [hash] })).collect();
    let reply = call(chain_id, &Value::Array(batch))?;
    check_error(&reply)?;
    let replies = reply.as_array().context("réponse Alchemy : lot de reçus illisible")?;
    let mut fees: HashMap<&str, (u128, bool)> = HashMap::new();
    for item in replies {
        check_error(item)?;
        let index = item["id"].as_u64().and_then(|i| usize::try_from(i).ok()).context("réponse Alchemy : reçu sans identifiant")?;
        let hash = hashes.get(index).context("réponse Alchemy : reçu inattendu")?;
        let receipt = &item["result"];
        anyhow::ensure!(receipt["transactionHash"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(hash)), "réponse Alchemy : reçu d'une autre transaction");
        let fee = receipt_fee(receipt).context("réponse Alchemy : frais absents du reçu")?;
        fees.insert(hash.as_str(), (fee, nodereal::number(&receipt["status"]) == Some(0)));
    }
    for t in page.iter_mut().filter(|t| t.category == "external" && t.from == address) {
        let (fee, failed) = fees.get(t.hash.as_str()).copied().context("réponse Alchemy : reçu manquant")?;
        t.fee = fee;
        t.failed = failed;
    }
    Ok(())
}

/// Page d'historique de la monnaie du réseau `chain_id` pour `address`
/// (transactions émises, monnaie reçue, y compris d'un contrat) et suite.
pub fn tx_history_page(chain_id: u64, address: &str, cursor: Option<&Cursor>) -> Result<(Vec<EvmTx>, Option<Cursor>)> {
    let (mut page, next) = nodereal::next_page(address, params(&["external"], true), params(&["external", "internal"], false), cursor, &mut |p| fetch(chain_id, p))?;
    add_fees(chain_id, &mut page, address)?;
    Ok((nodereal::transactions(&page, address), next))
}

/// Page des virements du jeton ERC-20 `contract` pour `address`, regroupés
/// par transaction, et suite. Filtré par contrat chez Alchemy ET revérifié
/// ici : un faux jeton au même symbole n'y entre jamais.
pub fn token_history_page(chain_id: u64, address: &str, contract: &str, cursor: Option<&Cursor>) -> Result<(Vec<TokenMove>, Option<Cursor>)> {
    let contract = contract.to_lowercase();
    let mut p = params(&["erc20"], false);
    p["contractAddresses"] = json!([contract]);
    let (page, next) = nodereal::next_page(address, p.clone(), p, cursor, &mut |p| fetch(chain_id, p))?;
    nodereal::token_moves(&page, address, &contract).map(|moves| (moves, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0xd8da6bf26964aF9D7eEd9e03E53415D37aA96045";

    /// Formats réels relevés le 10/10/2026 (Base : interne et externe ;
    /// Polygon : USDC).
    #[test]
    fn real_transfer_formats_are_read() {
        let internal = json!({ "blockNum": "0x2c0bafa", "uniqueId": "0xcf9f:internal:0", "hash": "0xCF9F", "from": "0xabc", "to": ME, "value": 1e-13, "asset": "ETH", "category": "internal",
            "rawContract": { "value": "0x0186a0", "address": null, "decimal": "0x12" }, "metadata": { "blockTimestamp": "2026-10-09T12:13:11.000Z" } });
        let t = transfer(&internal).unwrap();
        assert_eq!((t.value, t.category.as_str(), t.contract, t.hash.as_str(), t.to.as_str()), (100_000, "internal", None, "0xcf9f", ME.to_lowercase().as_str()));
        assert_eq!(t.timestamp, crate::blockscout::parse_iso8601_utc("2026-10-09T12:13:11Z"));
        // 20 735 jours après le 1/1/1970, plus 12 h 13 min 11 s.
        assert_eq!(t.timestamp, Some(20_735 * 86_400 + 43_991));
        let usdc = json!({ "blockNum": "0x57dad21", "uniqueId": "0x4845:log:1103", "hash": "0x4845", "from": ME, "to": "0xdef", "value": 0.5, "category": "erc20",
            "rawContract": { "value": "0x7a120", "address": "0x3C499c542cEF5E3811e1192ce70d8cC03d5c3359", "decimal": "0x6" }, "metadata": { "blockTimestamp": "2026-08-15T12:16:04.000Z" } });
        let t = transfer(&usdc).unwrap();
        assert_eq!((t.value, t.contract.as_deref()), (500_000, Some("0x3c499c542cef5e3811e1192ce70d8cc03d5c3359")));
        // Montant brut absent : refusé plutôt que compté nul.
        let mut broken = usdc.clone();
        broken["rawContract"]["value"] = Value::Null;
        assert!(transfer(&broken).is_err());
    }

    #[test]
    fn fees_include_the_l1_part() {
        let base = json!({ "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00", "l1Fee": "0x10" });
        assert_eq!(receipt_fee(&base), Some(21_000 * 1_000_000_000 + 16));
        let polygon = json!({ "gasUsed": "0x5208", "effectiveGasPrice": "0x6fc23ac00" });
        assert_eq!(receipt_fee(&polygon), Some(21_000 * 30_000_000_000));
        assert_eq!(receipt_fee(&json!({ "gasUsed": "0x5208" })), None);
    }

    #[test]
    fn limits_and_refusals_are_told_apart() {
        for limited in ["Monthly capacity limit exceeded.", "Your app has exceeded its compute units per second capacity."] {
            assert_eq!(check_error(&json!({ "error": { "code": 429, "message": limited } })).unwrap_err().to_string(), LIMITED);
        }
        let refused = check_error(&json!({ "error": { "code": 403, "message": "BASE_MAINNET is not enabled for this app." } })).unwrap_err();
        assert!(refused.to_string().contains("refusé"));
        assert!(check_error(&json!({ "result": [] })).is_ok());
    }

    #[test]
    fn only_networks_without_another_source() {
        assert_eq!(host(8_453), Some("base-mainnet"));
        assert_eq!(host(137), Some("polygon-mainnet"));
        assert_eq!(host(1), None);
        assert_eq!(host(42_161), None);
    }

    /// Service réel : chaque transaction émise d'une page, comparée au solde
    /// lu sur le nœud au bloc précédent et à son bloc — la variation doit
    /// être exactement le montant net moins les frais (frais L1 de Base
    /// compris) quand c'est la seule transaction de l'adresse dans ce bloc.
    /// `cargo test -- --ignored real_alchemy --nocapture`
    #[test]
    #[ignore]
    fn real_alchemy() {
        if API_KEY.is_none() {
            println!("ALCHEMY_API_KEY absente de partner-keys.env : rien à vérifier");
            return;
        }
        let balance_at = |chain: u64, address: &str, block: u64| -> i128 {
            let reply = call(chain, &json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, format!("0x{block:x}")] })).unwrap();
            i128::try_from(nodereal::number(&reply["result"]).unwrap()).unwrap()
        };
        // Polygon : vitalik.eth n'y envoie rien ; une adresse ordinaire qui
        // envoie (49 envois dans des blocs distincts, relevée le 10/10/2026).
        let networks = [(8_453, ME, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), (137, "0x1d296189638ec7509b58eea83c681cde6bf90871", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359")];
        for (chain, sender, usdc) in networks {
            let (txs, next) = tx_history_page(chain, sender, None).unwrap();
            println!("{chain} : {} transactions, suite {}", txs.len(), next.is_some());
            assert!(!txs.is_empty());
            if let Some(next) = next.as_ref() {
                let (second, _) = tx_history_page(chain, sender, Some(next)).unwrap();
                assert!(second.iter().all(|tx| !txs.iter().any(|t| t.hash == tx.hash)), "pages sans doublon");
            }
            // Vérification au wei sur les transactions isolées dans leur bloc
            // (blocs de toute la page lus en un lot de reçus).
            let batch: Vec<Value> = txs.iter().enumerate().map(|(i, t)| json!({ "jsonrpc": "2.0", "id": i, "method": "eth_getTransactionReceipt", "params": [t.hash] })).collect();
            let reply = call(chain, &Value::Array(batch)).unwrap();
            let mut blocks = vec![0u64; txs.len()];
            for item in reply.as_array().unwrap() {
                blocks[item["id"].as_u64().unwrap() as usize] = u64::try_from(nodereal::number(&item["result"]["blockNumber"]).unwrap()).unwrap();
            }
            let mut checked = 0;
            for (i, tx) in txs.iter().enumerate().filter(|(_, tx)| tx.fee_wei > 0).take(6) {
                let block = blocks[i];
                if blocks.iter().filter(|b| **b == block).count() != 1 {
                    continue;
                }
                let delta = balance_at(chain, sender, block) - balance_at(chain, sender, block - 1);
                println!("  {} : variation {delta}, net {} − frais {}", &tx.hash[..12], tx.net_wei, tx.fee_wei);
                assert_eq!(delta, tx.net_wei - tx.fee_wei, "{}", tx.hash);
                checked += 1;
            }
            println!("  {checked} transaction(s) vérifiée(s) au wei");
            assert!(checked > 0, "aucune transaction vérifiable");
            let (moves, _) = token_history_page(chain, ME, usdc, None).unwrap();
            println!("  USDC : {} mouvements", moves.len());
            assert!(!moves.is_empty());
        }
    }
}
