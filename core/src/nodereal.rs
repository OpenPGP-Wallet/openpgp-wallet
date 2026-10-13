//! BNB Chain history through NodeReal (an infrastructure provider for BNB Chain,
//! free plan): `nr_getAssetTransfers`, an address's transfers: BNB sent and
//! received (including received from a contract: a swap output, a bridge), BEP-20
//! tokens.
//!
//! No public keyless service provides this history (observed on 2026-10-07: not
//! Blockscout, not Routescan, not Etherscan's free plan; CoinGecko and
//! CoinMarketCap have no per-address history). The key is read AT BUILD TIME
//! (`NODEREAL_API_KEY` in `partner-keys.env`, see build.rs); without it, the
//! history is unavailable and the app points to BscScan. Read-only, purely
//! informative; only the public address is sent.
//!
//! Reading both directions, grouping by transaction and filtering tokens also serve
//! `alchemy` (Base, Polygon): `nr_getAssetTransfers` mirrors
//! `alchemy_getAssetTransfers`.

use crate::blockscout::{EvmTx, TokenMove};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// API key (free plan), built in at compile time.
pub const API_KEY: Option<&str> = option_env!("NODEREAL_API_KEY");
const ENDPOINT: &str = "https://bsc-mainnet.nodereal.io/v1/";
/// Transfers requested per direction and per call.
const BATCH: usize = 50;
/// Minimum gap between two calls (a free plan shared by every user of the app: no
/// bursts).
const SPACING: Duration = Duration::from_millis(150);
/// LI.FI's entry contract on BNB Chain (see `lifi::diamond`): a send to it, or BNB
/// received from it, is a swap.
const LIFI_DIAMOND: &str = "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae";

/// BNB history unavailable: key missing from this version of the app.
pub const KEY_MISSING: &str = "historique BNB Chain indisponible dans cette version de l'app";
/// Free plan quota or rate reached.
pub const LIMITED: &str = "historique BNB Chain momentanément indisponible (limite du service atteinte) — réessayez plus tard";

pub fn available() -> bool {
    API_KEY.is_some()
}

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

fn pace() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(wait) = last.map(|t| SPACING.saturating_sub(t.elapsed())) {
        std::thread::sleep(wait);
    }
    *last = Some(Instant::now());
}

/// Number in a response: hex string ("0x1f"), decimal, or number.
pub(crate) fn number(value: &Value) -> Option<u128> {
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

/// A transfer from the response, reduced to what is needed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Transfer {
    /// The transfer's identifier at NodeReal (the same transfer appears in both
    /// directions if it goes from the address to itself).
    pub(crate) id: String,
    /// "external", "internal" or "20".
    pub(crate) category: String,
    pub(crate) block: u64,
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) value: u128,
    pub(crate) hash: String,
    pub(crate) contract: Option<String>,
    pub(crate) timestamp: Option<i64>,
    /// Transaction fee (external transfers only), in wei.
    pub(crate) fee: u128,
    pub(crate) failed: bool,
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

/// One `nr_getAssetTransfers` call: transfers and the key of the next page.
fn call(params: Value) -> Result<(Vec<Transfer>, Option<String>)> {
    let key = API_KEY.ok_or_else(|| anyhow!(KEY_MISSING))?;
    pace();
    let body =
        json!({ "jsonrpc": "2.0", "id": 1, "method": "nr_getAssetTransfers", "params": [params] });
    // The key travels in the URL: network errors are rephrased WITHOUT the URL.
    let response = shared_client()
        .post(format!("{ENDPOINT}{key}"))
        .json(&body)
        .send()
        .map_err(|e| anyhow!("NodeReal injoignable : {}", e.without_url()))?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!(LIMITED);
    }
    let reply: Value = response
        .json()
        .map_err(|e| anyhow!("réponse NodeReal illisible : {}", e.without_url()))?;
    parse_reply(&reply)
}

fn parse_reply(reply: &Value) -> Result<(Vec<Transfer>, Option<String>)> {
    if let Some(error) = reply.get("error") {
        let message = error["message"].as_str().unwrap_or_default();
        let lower = message.to_lowercase();
        if ["limit", "quota", "exceed", "too many"]
            .iter()
            .any(|word| lower.contains(word))
        {
            bail!(LIMITED);
        }
        bail!("NodeReal a refusé la demande : {message}");
    }
    let result = &reply["result"];
    let transfers = result["transfers"]
        .as_array()
        .context("réponse NodeReal : virements absents")?
        .iter()
        .map(transfer)
        .collect::<Result<Vec<_>>>()?;
    let next = result["pageKey"]
        .as_str()
        .filter(|k| !k.is_empty())
        .map(String::from);
    Ok((transfers, next))
}

/// One reading direction (sends or receipts): transfers read ahead, and the next
/// page at NodeReal.
#[derive(Clone, Debug, Default, PartialEq)]
struct Stream {
    buffer: Vec<Transfer>,
    next_key: Option<String>,
    done: bool,
}

/// Continuation of a history: both directions, with what was read but not returned
/// yet (older than the returned page).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Cursor {
    sent: Stream,
    received: Stream,
}

impl Stream {
    /// Fills the buffer up to a page, if the direction is not exhausted.
    fn fill(
        &mut self,
        mut params: Value,
        fetch: &mut impl FnMut(Value) -> Result<(Vec<Transfer>, Option<String>)>,
    ) -> Result<()> {
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

    /// Oldest block read in a direction that is still open: below it, more transfers in
    /// that direction may still come.
    fn frontier(&self) -> Option<u64> {
        if self.done {
            None
        } else {
            self.buffer.iter().map(|t| t.block).min()
        }
    }
}

/// Next page, both directions merged from newest to oldest: only transfers newer
/// than the frontier of both directions are returned (an older transfer in one
/// direction may still be missing from the other), and the rest waits for the next
/// page.
pub(crate) fn next_page(
    address: &str,
    sent_params: Value,
    received_params: Value,
    cursor: Option<&Cursor>,
    fetch: &mut impl FnMut(Value) -> Result<(Vec<Transfer>, Option<String>)>,
) -> Result<(Vec<Transfer>, Option<Cursor>)> {
    let mut state = cursor.cloned().unwrap_or_default();
    state
        .sent
        .fill(json_with(sent_params, "fromAddress", address), fetch)?;
    state
        .received
        .fill(json_with(received_params, "toAddress", address), fetch)?;
    let frontier = state
        .sent
        .frontier()
        .into_iter()
        .chain(state.received.frontier())
        .max();
    let mut page: Vec<Transfer> = Vec::new();
    for stream in [&mut state.sent, &mut state.received] {
        let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut stream.buffer)
            .into_iter()
            .partition(|t| frontier.is_none_or(|f| t.block > f));
        page.extend(ready);
        stream.buffer = later;
    }
    // A whole page in a single block (an extreme case): returned as is.
    if page.is_empty() {
        for stream in [&mut state.sent, &mut state.received] {
            page.extend(std::mem::take(&mut stream.buffer));
        }
    }
    // A transfer from the address to itself appears in both directions.
    let mut seen = std::collections::HashSet::new();
    page.retain(|t| seen.insert(t.id.clone()));
    page.sort_by(|a, b| b.block.cmp(&a.block).then_with(|| a.hash.cmp(&b.hash)));
    let more = !(state.sent.done
        && state.received.done
        && state.sent.buffer.is_empty()
        && state.received.buffer.is_empty());
    Ok((page, more.then_some(state)))
}

fn json_with(mut params: Value, name: &str, address: &str) -> Value {
    params[name] = json!(address.to_lowercase());
    params
}

fn base_params(categories: &[&str]) -> Value {
    json!({ "category": categories, "order": "desc", "maxCount": format!("0x{BATCH:x}") })
}

/// BNB transfers of the page grouped by transaction, from `address`'s point of
/// view: net amount (received minus sent, nothing for a failed transaction), and
/// the fee if it sent the transaction.
pub(crate) fn transactions(page: &[Transfer], address: &str) -> Vec<EvmTx> {
    let address = address.to_lowercase();
    let mut txs: Vec<EvmTx> = Vec::new();
    for t in page {
        let index = match txs.iter().position(|tx| tx.hash == t.hash) {
            Some(index) => index,
            None => {
                txs.push(EvmTx {
                    hash: t.hash.clone(),
                    timestamp_unix: t.timestamp,
                    failed: false,
                    net_wei: 0,
                    fee_wei: 0,
                    swap: false,
                });
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
        tx.swap |= (external && t.from == address && t.to == LIFI_DIAMOND)
            || (t.to == address && t.from == LIFI_DIAMOND);
    }
    for tx in &mut txs {
        if tx.failed {
            tx.net_wei = 0;
        }
    }
    txs
}

/// Page of `address`'s BNB history (transactions sent, BNB received, including from
/// a contract) and continuation.
pub fn tx_history_page(
    address: &str,
    cursor: Option<&Cursor>,
) -> Result<(Vec<EvmTx>, Option<Cursor>)> {
    let (page, next) = next_page(
        address,
        base_params(&["external"]),
        base_params(&["external", "internal"]),
        cursor,
        &mut call,
    )?;
    Ok((transactions(&page, address), next))
}

/// Page of the transfers of BEP-20 token `contract` for `address`, grouped by
/// transaction, and continuation. Filtered by contract at NodeReal AND checked
/// again here: a fake token with the same symbol never gets in.
pub fn token_history_page(
    address: &str,
    contract: &str,
    cursor: Option<&Cursor>,
) -> Result<(Vec<TokenMove>, Option<Cursor>)> {
    let contract = contract.to_lowercase();
    let mut params = base_params(&["20"]);
    params["contractAddresses"] = json!([contract]);
    let (page, next) = next_page(address, params.clone(), params, cursor, &mut call)?;
    token_moves(&page, address, &contract).map(|moves| (moves, next))
}

pub(crate) fn token_moves(
    page: &[Transfer],
    address: &str,
    contract: &str,
) -> Result<Vec<TokenMove>> {
    let address = address.to_lowercase();
    let mut moves: Vec<TokenMove> = Vec::new();
    for t in page {
        anyhow::ensure!(
            t.contract.as_deref() == Some(contract),
            "le service d'historique a renvoyé un autre jeton que celui demandé"
        );
        let value = i128::try_from(t.value).unwrap_or(i128::MAX);
        let delta = match (t.from == address, t.to == address) {
            (true, false) => -value,
            (false, true) => value,
            _ => 0,
        };
        match moves.iter_mut().find(|m| m.hash == t.hash) {
            Some(existing) => existing.net += delta,
            None => moves.push(TokenMove {
                hash: t.hash.clone(),
                timestamp_unix: t.timestamp,
                net: delta,
                swap: false,
            }),
        }
    }
    Ok(moves)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0x59d78c44ac60f09369b544778358704b7b18e6ba";
    const OTHER: &str = "0x8894e0a0c962cb723c1976a4421c95949be2d4e3";

    /// Transfer in the real format (fields captured on 2026-10-07 from an
    /// `nr_getAssetTransfers` response).
    #[allow(clippy::too_many_arguments)]
    fn raw(
        id: u64,
        category: &str,
        block: u64,
        from: &str,
        to: &str,
        value: u128,
        hash: &str,
        status: u64,
    ) -> Value {
        json!({
            "id": id, "category": category, "blockNum": format!("0x{block:x}"), "from": from, "to": to,
            "value": format!("0x{value:x}"), "asset": "BNB", "hash": hash, "contractAddress": null,
            "blockTimeStamp": 1_791_368_243u64 + block, "gasPrice": "0x3b9aca00", "gasUsed": "0x5208", "receiptsStatus": status,
        })
    }

    fn parsed(values: Vec<Value>) -> Vec<Transfer> {
        values.iter().map(|v| transfer(v).unwrap()).collect()
    }

    /// Send (fee = gas × price), receipt, BNB received from a contract, failed send
    /// (fee only), to self, LI.FI swap; case ignored.
    #[test]
    fn transfers_become_transactions() {
        let page = parsed(vec![
            raw(
                1,
                "external",
                100,
                &ME.to_uppercase().replacen("0X", "0x", 1),
                OTHER,
                1_000,
                "0xa",
                1,
            ),
            raw(2, "external", 99, OTHER, ME, 5_000, "0xb", 1),
            raw(3, "internal", 98, "0xcontract", ME, 700, "0xc", 1),
            raw(4, "external", 97, ME, OTHER, 9_999, "0xd", 0),
            raw(5, "external", 96, ME, ME, 42, "0xe", 1),
            raw(6, "external", 95, ME, LIFI_DIAMOND, 300, "0xf", 1),
        ]);
        let txs = transactions(&page, ME);
        let summary: Vec<_> = txs
            .iter()
            .map(|t| (t.hash.as_str(), t.net_wei, t.fee_wei, t.failed, t.swap))
            .collect();
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

    /// Merging both directions: only transfers newer than the frontier are returned,
    /// the rest goes to the next page; a transfer to self (present in both directions)
    /// appears only once; it ends when both directions are exhausted.
    #[test]
    fn both_directions_are_merged_by_block() {
        let mut calls = 0;
        let mut fetch = |params: Value| -> Result<(Vec<Transfer>, Option<String>)> {
            calls += 1;
            let sent = params.get("fromAddress").is_some();
            let second = params.get("pageKey").is_some();
            Ok(match (sent, second) {
                // Sends: blocks 100 and 90, then 50.
                (true, false) => (
                    parsed(vec![
                        raw(1, "external", 100, ME, OTHER, 1, "0xa", 1),
                        raw(2, "external", 90, ME, ME, 2, "0xs", 1),
                    ]),
                    Some("k1".into()),
                ),
                (true, true) => (
                    parsed(vec![raw(3, "external", 50, ME, OTHER, 3, "0xc", 1)]),
                    None,
                ),
                // Receipts: blocks 95, 90 (to self) and 40, then nothing.
                (false, _) => (
                    parsed(vec![
                        raw(4, "external", 95, OTHER, ME, 4, "0xd", 1),
                        raw(2, "external", 90, ME, ME, 2, "0xs", 1),
                        raw(5, "external", 40, OTHER, ME, 5, "0xe", 1),
                    ]),
                    None,
                ),
            })
        };
        let (first, cursor) = next_page(
            ME,
            base_params(&["external"]),
            base_params(&["external"]),
            None,
            &mut fetch,
        )
        .unwrap();
        // Frontier: block 90 (sends still open); returned: 100 and 95.
        assert_eq!(
            first.iter().map(|t| t.block).collect::<Vec<_>>(),
            vec![100, 95]
        );
        let cursor = cursor.expect("suite attendue");
        let (second, cursor) = next_page(
            ME,
            base_params(&["external"]),
            base_params(&["external"]),
            Some(&cursor),
            &mut fetch,
        )
        .unwrap();
        assert_eq!(
            second
                .iter()
                .map(|t| (t.block, t.hash.as_str()))
                .collect::<Vec<_>>(),
            vec![(90, "0xs"), (50, "0xc"), (40, "0xe")]
        );
        assert!(cursor.is_none(), "les deux sens sont épuisés");
        assert_eq!(calls, 3);
    }

    /// Tokens: grouped by transaction, another contract refused.
    #[test]
    fn token_moves_check_the_contract() {
        let token = "0x000ae314e2a2172a039b26378814c252734f556a";
        let mut a = raw(1, "20", 10, OTHER, ME, 500, "0x1", 1);
        a["contractAddress"] = json!(token);
        let mut b = raw(2, "20", 10, ME, OTHER, 200, "0x1", 1);
        b["contractAddress"] = json!(token);
        let moves = token_moves(&parsed(vec![a, b]), ME, token).unwrap();
        assert_eq!(
            moves
                .iter()
                .map(|m| (m.hash.as_str(), m.net))
                .collect::<Vec<_>>(),
            vec![("0x1", 300)]
        );
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
        assert_eq!(
            parse_reply(&json!({ "result": { "transfers": [], "pageKey": null } }))
                .unwrap()
                .1,
            None
        );
        let limited = parse_reply(
            &json!({ "error": { "code": -32005, "message": "monthly CU limit exceeded" } }),
        )
        .unwrap_err();
        assert_eq!(limited.to_string(), LIMITED);
        assert!(parse_reply(
            &json!({ "error": { "code": -32601, "message": "method does not exist" } })
        )
        .unwrap_err()
        .to_string()
        .contains("refusé"));
    }

    /// Real network (key required): net amounts compared with the transaction read from
    /// a public BNB Chain node (value, sender, recipient, fee).
    /// `cargo test -- --ignored real_nodereal_amounts --nocapture`
    #[test]
    #[ignore]
    fn real_nodereal_amounts() {
        let rpc = "https://bsc-dataseed.bnbchain.org";
        let node = |method: &str, hash: &str| -> Value {
            reqwest::blocking::Client::new()
                .post(rpc)
                .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": [hash] }))
                .send()
                .unwrap()
                .json::<Value>()
                .unwrap()["result"]
                .clone()
        };
        let (txs, _) = tx_history_page(OTHER, None).unwrap();
        let mut checked = 0;
        for tx in txs.iter().filter(|t| t.net_wei != 0 && !t.failed).take(12) {
            let chain = node("eth_getTransactionByHash", &tx.hash);
            let receipt = node("eth_getTransactionReceipt", &tx.hash);
            let value = number(&chain["value"]).unwrap() as i128;
            let from = chain["from"].as_str().unwrap().to_lowercase();
            let to = chain["to"].as_str().unwrap_or_default().to_lowercase();
            // Direct transfer (not from a contract): the net amount is the transaction's value.
            let expected = if from == OTHER {
                -value
            } else if to == OTHER {
                value
            } else {
                continue;
            };
            // Receipt not served (yet) by the public node: next transaction.
            let (Some(gas_used), Some(gas_price)) = (
                number(&receipt["gasUsed"]),
                number(&receipt["effectiveGasPrice"]),
            ) else {
                continue;
            };
            let fee = if from == OTHER {
                (gas_used * gas_price) as i128
            } else {
                0
            };
            println!(
                "{} net {} (nœud {expected}) frais {} (nœud {fee})",
                &tx.hash[..12],
                tx.net_wei,
                tx.fee_wei
            );
            assert_eq!((tx.net_wei, tx.fee_wei), (expected, fee), "{}", tx.hash);
            checked += 1;
        }
        assert!(checked > 0, "aucune transaction comparable dans la page");
    }

    /// Real diagnostic (key required): how far back pages go without block bounds
    /// (observed on 2026-10-07: beyond 210,000 blocks; the 100,000 limit only applies
    /// with bounds), and overly wide bounds refused.
    /// `cargo test -- --ignored real_nodereal_range --nocapture`
    #[test]
    #[ignore]
    fn real_nodereal_range() {
        let quiet = "0x000000000000000000000000000000000000dead";
        let mut params = base_params(&["external"]);
        params["toAddress"] = json!(quiet);
        let mut newest = None;
        for page in 0..10 {
            let (transfers, next) = call(params.clone()).unwrap();
            let (low, high) = (
                transfers.iter().map(|t| t.block).min(),
                transfers.iter().map(|t| t.block).max(),
            );
            newest = newest.or(high);
            println!(
                "page {page} : {} virements, blocs {low:?}..{high:?}, recul {:?} blocs, suite {}",
                transfers.len(),
                newest.zip(low).map(|(n, l)| n - l),
                next.is_some()
            );
            match next {
                Some(key) => params["pageKey"] = json!(key),
                None => break,
            }
        }
        let mut explicit = base_params(&["external"]);
        explicit["toAddress"] = json!(quiet);
        explicit["fromBlock"] = json!("0x0");
        explicit["toBlock"] = json!("latest");
        println!(
            "bornes 0..latest : {:?}",
            call(explicit).map(|(t, n)| (t.len(), n.is_some()))
        );
    }

    /// Real network (key required): history of Binance's hot address, successive pages
    /// without duplicates and getting older; a low-activity address read beyond 100,000
    /// blocks (NodeReal's range limit does not apply without block bounds: the full
    /// history).
    /// `cargo test -- --ignored real_nodereal --nocapture`
    #[test]
    #[ignore]
    fn real_nodereal() {
        assert!(available(), "NODEREAL_API_KEY absente de partner-keys.env");
        let (first, cursor) = tx_history_page(OTHER, None).unwrap();
        println!("{} transactions, suite : {}", first.len(), cursor.is_some());
        for tx in first.iter().take(3) {
            println!(
                "{} {:?} net {} frais {}",
                &tx.hash[..12],
                tx.timestamp_unix,
                tx.net_wei,
                tx.fee_wei
            );
        }
        assert!(!first.is_empty() && cursor.is_some());
        let (second, _) = tx_history_page(OTHER, cursor.as_ref()).unwrap();
        assert!(
            second
                .iter()
                .all(|t| !first.iter().any(|f| f.hash == t.hash)),
            "pages sans doublon"
        );
        // Low-activity address: walk back through the pages until past 100,000 blocks.
        let quiet = "0x000000000000000000000000000000000000dead";
        let mut cursor = None;
        let mut oldest = i64::MAX;
        let newest = tx_history_page(quiet, None)
            .unwrap()
            .0
            .first()
            .and_then(|t| t.timestamp_unix)
            .unwrap_or(0);
        for _ in 0..8 {
            let (page, next) = tx_history_page(quiet, cursor.as_ref()).unwrap();
            oldest = oldest.min(
                page.iter()
                    .filter_map(|t| t.timestamp_unix)
                    .min()
                    .unwrap_or(oldest),
            );
            cursor = next;
            if cursor.is_none() || newest - oldest > 20 * 3600 {
                break;
            }
        }
        // 100,000 blocks ≈ 11.7 h (0.42 s per block, measured on 2026-10-07).
        println!(
            "adresse peu active : remonté de {} h",
            (newest - oldest) / 3600
        );
        assert!(
            newest - oldest > 15 * 3600,
            "historique limité à la dernière plage de blocs"
        );
    }
}
