//! Base and Polygon history from Alchemy (free tier): `alchemy_getAssetTransfers`,
//! the transfers of an address: the network's native coin sent and received
//! (including coins received from a contract, such as swap or bridge outputs) and
//! ERC-20 tokens.
//!
//! No keyless service provides this history any more (as of 2026-10-10):
//! base/polygon.blockscout.com sit behind Cloudflare's bot check, Blockscout's
//! official API keeps them for paid plans, and the free Etherscan tier excludes
//! Base. The key is read AT BUILD TIME (`ALCHEMY_API_KEY` in `partner-keys.env`,
//! see build.rs); without it the history is unavailable and the app links to the
//! block explorer instead. Read-only and purely informational; only the public
//! address is sent.
//!
//! Same response shape as NodeReal's `nr_getAssetTransfers` (which mirrors this
//! method): pagination in both directions, grouping by transaction and token
//! filtering all come from `nodereal`. Measured on 2026-10-10: a failed transaction
//! never shows up (neither sent nor received, checked on Base and Polygon). Fees
//! are not included; they come from the receipts (`gasUsed` × `effectiveGasPrice`,
//! plus `l1Fee` on Base).

use crate::blockscout::{EvmTx, TokenMove};
use crate::nodereal::{self, Cursor, Transfer};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// API key (free tier), embedded at build time.
pub const API_KEY: Option<&str> = option_env!("ALCHEMY_API_KEY");
/// Transfers requested per direction and per call.
const BATCH: usize = 50;
/// Target throughput, in compute units (CU) per second. The free tier guarantees
/// 300, measured over a rolling 10 s window and shared by every user of the app
/// (plus 30 million per month). A plain 250 ms gap between calls went over it (120
/// CU per page of transfers, 1,000 for a batch of 50 receipts): Alchemy flagged it
/// by email on 2026-10-10.
const CU_PER_SECOND: u64 = 200;
const _: () = assert!(
    CU_PER_SECOND < 300,
    "sous le débit garanti de l'offre gratuite"
);
/// Costs taken from Alchemy's documentation (2026-10-10).
const TRANSFERS_CU: u64 = 120;
const RECEIPT_CU: u64 = 20;
/// Receipts per batch (at most 400 CU at once).
const RECEIPTS_PER_BATCH: usize = 20;
/// Waits before each retry after a rate-limit error (Alchemy recommends retrying).
const THROUGHPUT_RETRIES: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(3)];
/// Maximum number of receipts kept in memory (beyond that, the cache starts over).
const RECEIPT_CACHE_MAX: usize = 20_000;
/// History unavailable: this build of the app has no key.
pub const KEY_MISSING: &str = "historique de ce réseau indisponible dans cette version de l'app";
/// Free-tier quota or rate limit reached (same message as Blockscout).
pub const LIMITED: &str = crate::blockscout::BLOCKSCOUT_LIMITED;

/// Networks served: those enabled for the app's key, which no keyless service
/// covers any more.
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
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Time taken by a call costing `cost` CU at the target throughput.
fn spacing(cost: u64) -> Duration {
    Duration::from_millis(cost * 1000 / CU_PER_SECOND)
}

/// Waits until the target throughput allows a call costing `cost` CU (calls from
/// the whole app are queued, whatever the network).
fn pace(cost: u64) {
    static NEXT: Mutex<Option<Instant>> = Mutex::new(None);
    let mut next = NEXT.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    let start = next.map_or(now, |n| n.max(now));
    std::thread::sleep(start - now);
    *next = Some(start + spacing(cost));
}

/// What an Alchemy error means.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// Per-second rate exceeded: retry a little later.
    Throughput,
    /// Monthly quota used up, or some other limit.
    Limited,
    Other,
}

fn refusal(message: &str) -> Refusal {
    let lower = message.to_lowercase();
    if lower.contains("per second") || lower.contains("throughput") {
        Refusal::Throughput
    } else if ["limit", "capacity", "exceed", "too many"]
        .iter()
        .any(|word| lower.contains(word))
    {
        Refusal::Limited
    } else {
        Refusal::Other
    }
}

fn error_message(reply: &Value) -> Option<&str> {
    let error = reply.get("error")?;
    Some(
        error["message"]
            .as_str()
            .or_else(|| error.as_str())
            .unwrap_or_default(),
    )
}

/// A response (or batch of responses) reporting a rate-limit error.
fn throughput_exceeded(reply: &Value) -> bool {
    let exceeded = |r: &Value| error_message(r).is_some_and(|m| refusal(m) == Refusal::Throughput);
    exceeded(reply)
        || reply
            .as_array()
            .is_some_and(|items| items.iter().any(exceeded))
}

/// A JSON-RPC call (or batch) costing `cost` CU to the network's Alchemy node. If
/// the rate limit is hit: spaced-out retries, then `LIMITED`.
fn call(chain_id: u64, body: &Value, cost: u64) -> Result<Value> {
    let key = API_KEY.ok_or_else(|| anyhow!(KEY_MISSING))?;
    let host =
        host(chain_id).ok_or_else(|| anyhow!("historique Alchemy non prévu pour ce réseau"))?;
    for retry in THROUGHPUT_RETRIES.iter().map(Some).chain([None]) {
        pace(cost);
        // The key travels in the URL: network errors are reworded WITHOUT the URL.
        let response = shared_client()
            .post(format!("https://{host}.g.alchemy.com/v2/{key}"))
            .json(body)
            .send()
            .map_err(|e| anyhow!("Alchemy injoignable : {}", e.without_url()))?;
        let status = response.status();
        let text = response
            .text()
            .map_err(|e| anyhow!("réponse Alchemy illisible : {}", e.without_url()))?;
        let reply: Option<Value> = serde_json::from_str(&text).ok();
        let too_many = status == reqwest::StatusCode::TOO_MANY_REQUESTS;
        if reply.as_ref().is_some_and(throughput_exceeded)
            || (too_many && refusal(&text) != Refusal::Limited)
        {
            match retry {
                Some(wait) => {
                    std::thread::sleep(*wait);
                    continue;
                }
                None => bail!(LIMITED),
            }
        }
        if too_many {
            bail!(LIMITED);
        }
        let reply = reply.ok_or_else(|| anyhow!("réponse Alchemy illisible ({status})"))?;
        if !status.is_success() && reply.get("error").is_none() {
            bail!("Alchemy a répondu {status}");
        }
        return Ok(reply);
    }
    bail!(LIMITED)
}

/// Error from a JSON-RPC response: a free-tier limit, or a refusal.
fn check_error(reply: &Value) -> Result<()> {
    let Some(message) = error_message(reply) else {
        return Ok(());
    };
    match refusal(message) {
        Refusal::Throughput | Refusal::Limited => bail!(LIMITED),
        Refusal::Other => bail!("Alchemy a refusé la demande : {message}"),
    }
}

/// A transfer from the response (fields recorded on 2026-10-10), in the format
/// shared with NodeReal. Raw amount: `rawContract.value` (`value` is rounded, in
/// display units). Fee: 0 here, filled in by `add_fees`.
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
        value: nodereal::number(&value["rawContract"]["value"])
            .context("réponse Alchemy : montant absent")?,
        hash,
        contract: text(&value["rawContract"]["address"]).filter(|c| !c.is_empty()),
        timestamp: value["metadata"]["blockTimestamp"]
            .as_str()
            .and_then(crate::blockscout::parse_iso8601_utc),
        fee: 0,
        failed: false,
    })
}

fn parse_transfers(reply: &Value) -> Result<(Vec<Transfer>, Option<String>)> {
    check_error(reply)?;
    let result = &reply["result"];
    let transfers = result["transfers"]
        .as_array()
        .context("réponse Alchemy : virements absents")?
        .iter()
        .map(transfer)
        .collect::<Result<Vec<_>>>()?;
    let next = result["pageKey"]
        .as_str()
        .filter(|k| !k.is_empty())
        .map(String::from);
    Ok((transfers, next))
}

fn fetch(chain_id: u64, params: Value) -> Result<(Vec<Transfer>, Option<String>)> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "alchemy_getAssetTransfers", "params": [params] });
    parse_transfers(&call(chain_id, &body, TRANSFERS_CU)?)
}

/// `with_zero`: keep zero-value transfers. A transaction from the address that
/// sends no native coin (token transfer, approval, swap) still costs it fees
/// (Alchemy drops them by default).
fn params(categories: &[&str], with_zero: bool) -> Value {
    json!({ "category": categories, "order": "desc", "maxCount": format!("0x{BATCH:x}"), "withMetadata": true, "excludeZeroValue": !with_zero })
}

/// Fee from a transaction receipt: gas × effective price, plus the share paid to
/// layer 1 on OP Stack networks (Base: `l1Fee`).
fn receipt_fee(receipt: &Value) -> Option<u128> {
    let gas = nodereal::number(&receipt["gasUsed"])?;
    let price = nodereal::number(&receipt["effectiveGasPrice"])?;
    let l1 = nodereal::number(&receipt["l1Fee"]).unwrap_or(0);
    gas.checked_mul(price)?.checked_add(l1)
}

/// (network, transaction) → (fee, failed).
type ReceiptCache = HashMap<(u64, String), (u128, bool)>;

/// Fee and failure status of transactions already read, per network. A mined
/// transaction's receipt never changes, so it is not requested again during the
/// session (the chart is reread every 5 minutes, and the Activity tab when it is
/// reopened).
fn receipt_cache() -> &'static Mutex<ReceiptCache> {
    static CACHE: OnceLock<Mutex<ReceiptCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Receipts for `hashes` (JSON-RPC batch): the fee and failure status of each.
fn fetch_receipts(chain_id: u64, hashes: &[String]) -> Result<Vec<(u128, bool)>> {
    let batch: Vec<Value> = hashes.iter().enumerate().map(|(i, hash)| json!({ "jsonrpc": "2.0", "id": i, "method": "eth_getTransactionReceipt", "params": [hash] })).collect();
    let reply = call(
        chain_id,
        &Value::Array(batch),
        RECEIPT_CU * hashes.len() as u64,
    )?;
    check_error(&reply)?;
    let replies = reply
        .as_array()
        .context("réponse Alchemy : lot de reçus illisible")?;
    let mut found: Vec<Option<(u128, bool)>> = vec![None; hashes.len()];
    for item in replies {
        check_error(item)?;
        let index = item["id"]
            .as_u64()
            .and_then(|i| usize::try_from(i).ok())
            .context("réponse Alchemy : reçu sans identifiant")?;
        let hash = hashes
            .get(index)
            .context("réponse Alchemy : reçu inattendu")?;
        let receipt = &item["result"];
        anyhow::ensure!(
            receipt["transactionHash"]
                .as_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(hash)),
            "réponse Alchemy : reçu d'une autre transaction"
        );
        let fee = receipt_fee(receipt).context("réponse Alchemy : frais absents du reçu")?;
        found[index] = Some((fee, nodereal::number(&receipt["status"]) == Some(0)));
    }
    found
        .into_iter()
        .map(|r| r.context("réponse Alchemy : reçu manquant"))
        .collect()
}

/// Fills in the fees of transactions sent by `address` (external transfers leaving
/// it): receipts not yet known are requested in batches.
fn add_fees(chain_id: u64, page: &mut [Transfer], address: &str) -> Result<()> {
    let address = address.to_lowercase();
    let sent = |t: &Transfer| t.category == "external" && t.from == address;
    let mut missing: Vec<String> = {
        let cache = receipt_cache().lock().unwrap_or_else(|p| p.into_inner());
        page.iter()
            .filter(|t| sent(t) && !cache.contains_key(&(chain_id, t.hash.clone())))
            .map(|t| t.hash.clone())
            .collect()
    };
    missing.sort();
    missing.dedup();
    for chunk in missing.chunks(RECEIPTS_PER_BATCH) {
        let receipts = fetch_receipts(chain_id, chunk)?;
        let mut cache = receipt_cache().lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() > RECEIPT_CACHE_MAX {
            cache.clear();
        }
        cache.extend(
            chunk
                .iter()
                .cloned()
                .map(|hash| (chain_id, hash))
                .zip(receipts),
        );
    }
    let cache = receipt_cache().lock().unwrap_or_else(|p| p.into_inner());
    for t in page.iter_mut().filter(|t| sent(t)) {
        let (fee, failed) = cache
            .get(&(chain_id, t.hash.clone()))
            .copied()
            .context("réponse Alchemy : reçu manquant")?;
        t.fee = fee;
        t.failed = failed;
    }
    Ok(())
}

/// A page of native-coin history on network `chain_id` for `address` (transactions
/// sent, coins received, including from a contract), and the cursor for the next
/// one.
pub fn tx_history_page(
    chain_id: u64,
    address: &str,
    cursor: Option<&Cursor>,
) -> Result<(Vec<EvmTx>, Option<Cursor>)> {
    let (mut page, next) = nodereal::next_page(
        address,
        params(&["external"], true),
        params(&["external", "internal"], false),
        cursor,
        &mut |p| fetch(chain_id, p),
    )?;
    add_fees(chain_id, &mut page, address)?;
    Ok((nodereal::transactions(&page, address), next))
}

/// A page of transfers of the ERC-20 token `contract` for `address`, grouped by
/// transaction, and the cursor for the next one. Filtered by contract on Alchemy's
/// side AND checked again here: a fake token with the same symbol never gets in.
pub fn token_history_page(
    chain_id: u64,
    address: &str,
    contract: &str,
    cursor: Option<&Cursor>,
) -> Result<(Vec<TokenMove>, Option<Cursor>)> {
    let contract = contract.to_lowercase();
    let mut p = params(&["erc20"], false);
    p["contractAddresses"] = json!([contract]);
    let (page, next) =
        nodereal::next_page(address, p.clone(), p, cursor, &mut |p| fetch(chain_id, p))?;
    nodereal::token_moves(&page, address, &contract).map(|moves| (moves, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0xd8da6bf26964aF9D7eEd9e03E53415D37aA96045";

    /// Real formats recorded on 2026-10-10 (Base: internal and external; Polygon:
    /// USDC).
    #[test]
    fn real_transfer_formats_are_read() {
        let internal = json!({ "blockNum": "0x2c0bafa", "uniqueId": "0xcf9f:internal:0", "hash": "0xCF9F", "from": "0xabc", "to": ME, "value": 1e-13, "asset": "ETH", "category": "internal",
            "rawContract": { "value": "0x0186a0", "address": null, "decimal": "0x12" }, "metadata": { "blockTimestamp": "2026-10-09T12:13:11.000Z" } });
        let t = transfer(&internal).unwrap();
        assert_eq!(
            (
                t.value,
                t.category.as_str(),
                t.contract,
                t.hash.as_str(),
                t.to.as_str()
            ),
            (
                100_000,
                "internal",
                None,
                "0xcf9f",
                ME.to_lowercase().as_str()
            )
        );
        assert_eq!(
            t.timestamp,
            crate::blockscout::parse_iso8601_utc("2026-10-09T12:13:11Z")
        );
        // 20,735 days after 1970-01-01, plus 12 h 13 min 11 s.
        assert_eq!(t.timestamp, Some(20_735 * 86_400 + 43_991));
        let usdc = json!({ "blockNum": "0x57dad21", "uniqueId": "0x4845:log:1103", "hash": "0x4845", "from": ME, "to": "0xdef", "value": 0.5, "category": "erc20",
            "rawContract": { "value": "0x7a120", "address": "0x3C499c542cEF5E3811e1192ce70d8cC03d5c3359", "decimal": "0x6" }, "metadata": { "blockTimestamp": "2026-08-15T12:16:04.000Z" } });
        let t = transfer(&usdc).unwrap();
        assert_eq!(
            (t.value, t.contract.as_deref()),
            (500_000, Some("0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"))
        );
        // Missing raw amount: rejected rather than counted as zero.
        let mut broken = usdc.clone();
        broken["rawContract"]["value"] = Value::Null;
        assert!(transfer(&broken).is_err());
    }

    #[test]
    fn fees_include_the_l1_part() {
        let base =
            json!({ "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00", "l1Fee": "0x10" });
        assert_eq!(receipt_fee(&base), Some(21_000 * 1_000_000_000 + 16));
        let polygon = json!({ "gasUsed": "0x5208", "effectiveGasPrice": "0x6fc23ac00" });
        assert_eq!(receipt_fee(&polygon), Some(21_000 * 30_000_000_000));
        assert_eq!(receipt_fee(&json!({ "gasUsed": "0x5208" })), None);
    }

    /// Real Alchemy messages (documentation as of 2026-10-10).
    #[test]
    fn limits_and_refusals_are_told_apart() {
        let per_second = "Your app has exceeded its compute units per second capacity. If you have retries enabled, you can safely ignore this message.";
        assert_eq!(refusal(per_second), Refusal::Throughput);
        assert_eq!(
            refusal("Monthly capacity limit exceeded."),
            Refusal::Limited
        );
        assert_eq!(
            refusal("BASE_MAINNET is not enabled for this app."),
            Refusal::Other
        );
        let error = |message: &str| json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": 429, "message": message } });
        assert!(throughput_exceeded(&error(per_second)));
        assert!(
            throughput_exceeded(&json!([{ "id": 0, "result": {} }, error(per_second)])),
            "lot dont un élément est refusé"
        );
        assert!(!throughput_exceeded(&error(
            "Monthly capacity limit exceeded."
        )));
        assert!(!throughput_exceeded(&json!({ "result": [] })));
        for limited in ["Monthly capacity limit exceeded.", per_second] {
            assert_eq!(
                check_error(&error(limited)).unwrap_err().to_string(),
                LIMITED
            );
        }
        let refused = check_error(&json!({ "error": { "code": 403, "message": "BASE_MAINNET is not enabled for this app." } })).unwrap_err();
        assert!(refused.to_string().contains("refusé"));
        assert!(check_error(&json!({ "result": [] })).is_ok());
    }

    /// Below the free tier's 300 CU/s: one page of transfers every 0.6 s, one batch of
    /// 20 receipts every 2 s.
    #[test]
    fn calls_are_spaced_by_their_cost() {
        assert_eq!(spacing(TRANSFERS_CU), Duration::from_millis(600));
        assert_eq!(
            spacing(RECEIPT_CU * RECEIPTS_PER_BATCH as u64),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn only_networks_without_another_source() {
        assert_eq!(host(8_453), Some("base-mainnet"));
        assert_eq!(host(137), Some("polygon-mainnet"));
        assert_eq!(host(1), None);
        assert_eq!(host(42_161), None);
    }

    /// Live service: each transaction sent on a page is compared with the balance read
    /// from the node at the previous block and at its own block. The change must be
    /// exactly the net amount minus the fee (including Base's L1 fee) when it is the
    /// address's only transaction in that block.
    /// `cargo test -- --ignored real_alchemy --nocapture`
    #[test]
    #[ignore]
    fn real_alchemy() {
        if API_KEY.is_none() {
            println!("ALCHEMY_API_KEY absente de partner-keys.env : rien à vérifier");
            return;
        }
        let balance_at = |chain: u64, address: &str, block: u64| -> i128 {
            let reply = call(chain, &json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, format!("0x{block:x}")] }), 20).unwrap();
            i128::try_from(nodereal::number(&reply["result"]).unwrap()).unwrap()
        };
        // Polygon: vitalik.eth sends nothing there, so we use an ordinary address that
        // does (49 sends in separate blocks, recorded on 2026-10-10).
        let networks = [
            (8_453, ME, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            (
                137,
                "0x1d296189638ec7509b58eea83c681cde6bf90871",
                "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
            ),
        ];
        for (chain, sender, usdc) in networks {
            let (txs, next) = tx_history_page(chain, sender, None).unwrap();
            println!(
                "{chain} : {} transactions, suite {}",
                txs.len(),
                next.is_some()
            );
            assert!(!txs.is_empty());
            if let Some(next) = next.as_ref() {
                let (second, _) = tx_history_page(chain, sender, Some(next)).unwrap();
                assert!(
                    second
                        .iter()
                        .all(|tx| !txs.iter().any(|t| t.hash == tx.hash)),
                    "pages sans doublon"
                );
            }
            // Checked to the wei on the transactions that are alone in their block (the blocks
            // for the whole page are read in one batch of receipts).
            let batch: Vec<Value> = txs.iter().enumerate().map(|(i, t)| json!({ "jsonrpc": "2.0", "id": i, "method": "eth_getTransactionReceipt", "params": [t.hash] })).collect();
            let reply = call(chain, &Value::Array(batch), RECEIPT_CU * txs.len() as u64).unwrap();
            let mut blocks = vec![0u64; txs.len()];
            for item in reply.as_array().unwrap() {
                blocks[item["id"].as_u64().unwrap() as usize] =
                    u64::try_from(nodereal::number(&item["result"]["blockNumber"]).unwrap())
                        .unwrap();
            }
            let mut checked = 0;
            for (i, tx) in txs
                .iter()
                .enumerate()
                .filter(|(_, tx)| tx.fee_wei > 0)
                .take(6)
            {
                let block = blocks[i];
                if blocks.iter().filter(|b| **b == block).count() != 1 {
                    continue;
                }
                let delta = balance_at(chain, sender, block) - balance_at(chain, sender, block - 1);
                println!(
                    "  {} : variation {delta}, net {} − frais {}",
                    &tx.hash[..12],
                    tx.net_wei,
                    tx.fee_wei
                );
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
