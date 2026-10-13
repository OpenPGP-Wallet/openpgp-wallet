//! Client for Routescan's Etherscan-compatible API (`api.routescan.io`), without a
//! key: history of an address's transactions and ERC-20 tokens on the networks that
//! no public Blockscout instance covers (Avalanche C-Chain). Same role and same
//! guarantees as `blockscout`: read-only, purely informative, no user data beyond
//! the address.
//!
//! Blockscout instances offer the same API (`/api`), faster than their v2 API for
//! token transfers, but limited without a key to 10 requests per long period
//! (observed: quota used up, reset 47 minutes later, on every instance at once),
//! which makes it unusable; the v2 API allows 180 (see `blockscout`).

use crate::blockscout::{is_swap_method, EvmTx, TokenMove};
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::sync::OnceLock;

const ROUTESCAN_URL: &str = "https://api.routescan.io/v2/network/mainnet/evm";
/// Transactions per page.
pub const PAGE_SIZE: u32 = 50;
/// These APIs refuse beyond 10,000 results (page × size).
const MAX_RESULTS: u32 = 10_000;

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

#[derive(Deserialize)]
struct Response {
    status: String,
    message: String,
    result: serde_json::Value,
}

/// `result` list of a response; an address with no result gives an empty list
/// (status "1", or "0" depending on the action); any other refusal is an error.
fn result_list<T: serde::de::DeserializeOwned>(body: &str) -> Result<Vec<T>> {
    let response: Response = serde_json::from_str(body).context("réponse Routescan illisible")?;
    if response.status != "1" {
        if response.result.as_array().is_some_and(Vec::is_empty) {
            return Ok(Vec::new());
        }
        let detail = response.result.as_str().unwrap_or(&response.message);
        bail!("Routescan a refusé la demande : {detail}");
    }
    serde_json::from_value(response.result).context("réponse Routescan illisible")
}

/// Call to the service.
fn get(chain_id: u64, query: &[(&str, &str)]) -> Result<String> {
    shared_client()
        .get(format!("{ROUTESCAN_URL}/{chain_id}/etherscan/api"))
        .query(query)
        .send()
        .and_then(|response| response.text())
        .map_err(|e| anyhow!("appel Routescan impossible : {}", e.without_url()))
}

/// Next page number, `None` after the last one (incomplete page or API limit).
fn next_page(page: u32, len: usize) -> Option<u32> {
    (len == PAGE_SIZE as usize && (page + 1) * PAGE_SIZE <= MAX_RESULTS).then_some(page + 1)
}

fn number(s: &str, what: &str) -> Result<i128> {
    s.parse::<i128>()
        .map_err(|_| anyhow!("{what} invalide dans la réponse de Routescan"))
}

/// Decoded function name ("swapExactETHForTokens(uint256 amountOutMin, ...)"): the
/// part before the parenthesis.
fn method_name(function_name: &str) -> &str {
    function_name.split('(').next().unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJson {
    hash: String,
    time_stamp: String,
    from: String,
    #[serde(default)]
    to: String,
    value: String,
    gas_used: String,
    gas_price: String,
    is_error: String,
    #[serde(default)]
    function_name: String,
}

/// Page `page` (starting at 1) of `address`'s history, newest to oldest, and the
/// next page number.
pub fn tx_history_page(
    chain_id: u64,
    address: &str,
    page: u32,
) -> Result<(Vec<EvmTx>, Option<u32>)> {
    let page_text = page.to_string();
    let size = PAGE_SIZE.to_string();
    let body = get(
        chain_id,
        &[
            ("module", "account"),
            ("action", "txlist"),
            ("address", address),
            ("page", &page_text),
            ("offset", &size),
            ("sort", "desc"),
        ],
    )?;
    let txs = parse_tx_list(&body, address)?;
    let next = next_page(page, txs.len());
    Ok((txs, next))
}

/// `txlist` response: net amount and fee from `address`'s point of view (same rules
/// as `BlockscoutClient::tx_history_page`).
fn parse_tx_list(body: &str, address: &str) -> Result<Vec<EvmTx>> {
    let address = address.to_lowercase();
    result_list::<TxJson>(body)?
        .into_iter()
        .map(|tx| {
            let value = number(&tx.value, "montant")?;
            let sender = tx.from.to_lowercase() == address;
            let receiver = tx.to.to_lowercase() == address;
            let failed = tx.is_error == "1";
            let net_wei = match (failed, sender, receiver) {
                (true, _, _) | (false, true, true) => 0,
                (false, true, false) => -value,
                (false, false, _) => value,
            };
            let fee_wei = if sender {
                number(&tx.gas_used, "gas")? * number(&tx.gas_price, "prix du gas")?
            } else {
                0
            };
            Ok(EvmTx {
                hash: tx.hash,
                timestamp_unix: tx.time_stamp.parse().ok(),
                failed,
                net_wei,
                fee_wei,
                swap: is_swap_method(method_name(&tx.function_name)),
            })
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenTxJson {
    hash: String,
    time_stamp: String,
    from: String,
    to: String,
    value: String,
    contract_address: String,
    #[serde(default)]
    function_name: String,
}

/// Page `page` of the transfers of ERC-20 token `contract` for `address` (50
/// transfers, newest to oldest), grouped by transaction, and the next page number.
/// Filtered by contract on the server side AND checked again here: a fake token
/// with the same symbol never gets in.
pub fn token_history_page(
    chain_id: u64,
    address: &str,
    contract: &str,
    page: u32,
) -> Result<(Vec<TokenMove>, Option<u32>)> {
    let page_text = page.to_string();
    let size = PAGE_SIZE.to_string();
    let body = get(
        chain_id,
        &[
            ("module", "account"),
            ("action", "tokentx"),
            ("contractaddress", contract),
            ("address", address),
            ("page", &page_text),
            ("offset", &size),
            ("sort", "desc"),
        ],
    )?;
    let transfers: Vec<TokenTxJson> = result_list(&body)?;
    let next = next_page(page, transfers.len());
    Ok((token_moves(transfers, address, contract)?, next))
}

/// Transfers of a page grouped by transaction (one transaction can contain several,
/// a swap for example), in page order.
fn token_moves(
    transfers: Vec<TokenTxJson>,
    address: &str,
    contract: &str,
) -> Result<Vec<TokenMove>> {
    let address = address.to_lowercase();
    let mut moves: Vec<TokenMove> = Vec::new();
    for transfer in transfers {
        anyhow::ensure!(
            transfer.contract_address.eq_ignore_ascii_case(contract),
            "Routescan a renvoyé un autre jeton que celui demandé"
        );
        let value = number(&transfer.value, "montant de jeton")?;
        let delta = match (
            transfer.from.to_lowercase() == address,
            transfer.to.to_lowercase() == address,
        ) {
            (true, false) => -value,
            (false, true) => value,
            _ => 0,
        };
        let swap = is_swap_method(method_name(&transfer.function_name));
        match moves
            .iter_mut()
            .find(|m| m.hash.eq_ignore_ascii_case(&transfer.hash))
        {
            Some(existing) => {
                existing.net += delta;
                existing.swap |= swap;
            }
            None => moves.push(TokenMove {
                timestamp_unix: transfer.time_stamp.parse().ok(),
                hash: transfer.hash,
                net: delta,
                swap,
            }),
        }
    }
    Ok(moves)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0x5d0b3cb43a0bfb7fafde0e3ccba8d6c0c5ec1e3f";

    /// Real `txlist` format (fields captured from Routescan, trimmed): received, sent
    /// (fee = gas used × price), failed (fee only), to self; an address with no
    /// transaction; a refusal from the service.
    #[test]
    fn tx_list_is_read_from_the_address_point_of_view() {
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[
              {{"hash":"0xa","timeStamp":"1738731709","from":"0xOTHER","to":"{ME}","value":"1000","gasUsed":"21000","gasPrice":"25000000000","isError":"0","functionName":""}},
              {{"hash":"0xb","timeStamp":"1738731700","from":"{ME}","to":"0xother","value":"400","gasUsed":"21000","gasPrice":"2","isError":"0","functionName":"swapExactAVAXForTokens(uint256 amountOutMin, address[] path)"}},
              {{"hash":"0xc","timeStamp":"1738731600","from":"{ME}","to":"0xother","value":"999","gasUsed":"30000","gasPrice":"3","isError":"1","functionName":""}},
              {{"hash":"0xd","timeStamp":"1738731500","from":"{}","to":"{ME}","value":"5","gasUsed":"21000","gasPrice":"1","isError":"0","functionName":""}}
            ]}}"#,
            ME.to_uppercase().replacen("0X", "0x", 1)
        );
        let txs = parse_tx_list(&body, ME).unwrap();
        let summary: Vec<_> = txs
            .iter()
            .map(|t| (t.hash.as_str(), t.net_wei, t.fee_wei, t.failed, t.swap))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("0xa", 1000, 0, false, false),
                ("0xb", -400, 42_000, false, true),
                ("0xc", 0, 90_000, true, false),
                ("0xd", 0, 21_000, false, false)
            ]
        );
        assert_eq!(txs[0].timestamp_unix, Some(1_738_731_709));
        assert!(parse_tx_list(
            r#"{"status":"0","message":"No transactions found","result":[]}"#,
            ME
        )
        .unwrap()
        .is_empty());
        let refused = parse_tx_list(
            r#"{"status":"0","message":"NOTOK","result":"Max rate limit reached"}"#,
            ME,
        )
        .err()
        .unwrap();
        assert!(refused.to_string().contains("Max rate limit reached"));
    }

    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    fn transfer(
        hash: &str,
        from: &str,
        to: &str,
        value: &str,
        contract: &str,
        function: &str,
    ) -> String {
        format!(
            r#"{{"blockNumber":"26079962","timeStamp":"1790646827","hash":"{hash}","from":"{from}","contractAddress":"{contract}","to":"{to}",
               "value":"{value}","tokenName":"USD Coin","tokenSymbol":"USDC","tokenDecimal":"6","functionName":"{function}"}}"#
        )
    }

    /// Real `tokentx` format (fields captured from Routescan and Blockscout): received,
    /// sent, a two-transfer swap grouped into one movement, to self; Blockscout's "no
    /// transfers"; another token in the response is rejected.
    #[test]
    fn token_transfers_are_grouped_by_transaction() {
        let other = "0xa916b82ff122591cc88aac0d64ce30a8e3e16081";
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[{},{},{},{},{}]}}"#,
            transfer(
                "0x01",
                other,
                ME,
                "420000",
                USDC,
                "transfer(address to, uint256 value)"
            ),
            transfer(
                "0x02",
                &ME.to_uppercase().replacen("0X", "0x", 1),
                other,
                "1000000",
                USDC,
                ""
            ),
            transfer(
                "0x03",
                ME,
                other,
                "500",
                USDC,
                "swapExactTokensForTokens(uint256 amountIn)"
            ),
            transfer(
                "0x03",
                other,
                ME,
                "200",
                USDC,
                "swapExactTokensForTokens(uint256 amountIn)"
            ),
            transfer("0x04", ME, ME, "7", USDC, ""),
        );
        let moves = token_moves(
            result_list(&body).unwrap(),
            ME,
            &USDC.to_uppercase().replacen("0X", "0x", 1),
        )
        .unwrap();
        let summary: Vec<_> = moves
            .iter()
            .map(|m| (m.hash.as_str(), m.net, m.swap))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("0x01", 420_000, false),
                ("0x02", -1_000_000, false),
                ("0x03", -300, true),
                ("0x04", 0, false)
            ]
        );
        assert_eq!(moves[0].timestamp_unix, Some(1_790_646_827));
        assert!(result_list::<TokenTxJson>(
            r#"{"message":"No token transfers found","result":[],"status":"0"}"#
        )
        .unwrap()
        .is_empty());

        let fake = format!(
            r#"{{"status":"1","message":"OK","result":[{}]}}"#,
            transfer(
                "0x05",
                other,
                ME,
                "1",
                "0x0000000000000000000000000000000000000bad",
                ""
            )
        );
        assert!(token_moves(result_list(&fake).unwrap(), ME, USDC).is_err());
    }

    #[test]
    fn pages_stop_when_incomplete_or_at_the_api_limit() {
        assert_eq!(next_page(1, 50), Some(2));
        assert_eq!(next_page(1, 49), None);
        assert_eq!(next_page(200, 50), None, "10 000 résultats au plus");
    }

    /// Real service: Avalanche history of a public address, then vitalik.eth's USDC
    /// transfers (Routescan serves Ethereum too: `tokentx` format checked on a very
    /// active address), all from the right contract, successive pages without
    /// duplicates.
    /// `cargo test -- --ignored real_routescan --nocapture`
    #[test]
    #[ignore]
    fn real_routescan() {
        let (txs, next) =
            tx_history_page(43114, "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3", 1).unwrap();
        println!("Avalanche : {} transactions, suivante {next:?}", txs.len());
        for tx in txs.iter().take(3) {
            println!(
                "{} {:?} net {} frais {}",
                &tx.hash[..12],
                tx.timestamp_unix,
                tx.net_wei,
                tx.fee_wei
            );
        }
        assert!(!txs.is_empty());
        assert!(
            txs.windows(2)
                .all(|w| w[0].timestamp_unix >= w[1].timestamp_unix),
            "du plus récent au plus ancien"
        );

        let vitalik = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let (first, next) = token_history_page(1, vitalik, USDC, 1).unwrap();
        println!(
            "USDC vitalik.eth : {} mouvements, suivante {next:?}",
            first.len()
        );
        for m in first.iter().take(3) {
            println!("{} {:?} {}", &m.hash[..12], m.timestamp_unix, m.net);
        }
        assert!(!first.is_empty());
        let (second, _) = token_history_page(1, vitalik, USDC, next.unwrap()).unwrap();
        assert!(
            second
                .iter()
                .all(|m| !first.iter().any(|f| f.hash == m.hash)),
            "pages sans doublon"
        );
    }
}
