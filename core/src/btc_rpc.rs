use crate::btc_tx::Utxo;
use anyhow::{anyhow, Context, Result};
use reqwest::blocking::{RequestBuilder, Response};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// See eth_rpc::shared_client: a `reqwest::Client` rebuilt on every command call
// throws away its pool of keep-alive connections and pays for a full TCP+TLS
// handshake on every click. One shared client, built once.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Blockstream's public Esplora API: no key required, and enough to query UTXOs and
/// broadcast a transaction. Mainnet and testnet are two separate deployments of the
/// same API, hence the `base_url` parameter of `EsploraClient::new` rather than a
/// single constant.
pub const ESPLORA_TESTNET_BASE: &str = "https://blockstream.info/testnet/api";
pub const ESPLORA_MAINNET_BASE: &str = "https://blockstream.info/api";

/// Servers tried in order: Blockstream, then mempool.space (same Esplora API).
/// Blockstream rate-limits requests per IP: 429 responses were seen on 2026-10-05,
/// which broke the Bitcoin balance and the portfolio chart. A server that is
/// overloaded (429), down (5xx) or unreachable hands over to the next one and stays
/// on the bench for `MIRROR_COOLDOWN`.
const MAINNET_MIRRORS: [&str; 2] = [ESPLORA_MAINNET_BASE, "https://mempool.space/api"];
const TESTNET_MIRRORS: [&str; 2] = [ESPLORA_TESTNET_BASE, "https://mempool.space/testnet/api"];
const MIRROR_COOLDOWN: Duration = Duration::from_secs(60);

/// Every server failed (overloaded, down or unreachable).
pub const BITCOIN_SERVERS_DOWN: &str = "serveurs Bitcoin indisponibles pour l'instant (trop de requêtes ou panne) — réessayez dans une minute";
/// Request refused by the server (invalid address…).
pub const BITCOIN_REQUEST_REFUSED: &str = "requête refusée par le serveur Bitcoin";

/// Benched servers, and until when.
fn cooling() -> std::sync::MutexGuard<'static, HashMap<&'static str, Instant>> {
    static COOLING: OnceLock<Mutex<HashMap<&'static str, Instant>>> = OnceLock::new();
    COOLING.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner())
}

pub struct EsploraClient {
    client: reqwest::blocking::Client,
    mirrors: Vec<&'static str>,
}

#[derive(Deserialize)]
struct UtxoJson {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Deserialize)]
struct UtxoStatus {
    confirmed: bool,
}

#[derive(Deserialize)]
struct AddressTxJson {
    txid: String,
    vin: Vec<VinJson>,
    vout: Vec<VoutJson>,
    status: AddressTxStatusJson,
}

#[derive(Deserialize)]
struct VinJson {
    prevout: Option<PrevoutJson>,
}

#[derive(Deserialize)]
struct PrevoutJson {
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize)]
struct VoutJson {
    scriptpubkey_address: Option<String>,
    value: u64,
    #[serde(default)]
    scriptpubkey: String,
}

#[derive(Deserialize)]
struct AddressTxStatusJson {
    confirmed: bool,
    block_time: Option<i64>,
}

#[derive(Deserialize)]
struct TxoStatsJson {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
    tx_count: u64,
}

#[derive(Deserialize)]
struct AddressStatsJson {
    chain_stats: TxoStatsJson,
    mempool_stats: TxoStatsJson,
}

/// See `EsploraClient::address_stats`.
pub struct AddressStats {
    /// Confirmed + mempool transactions involving the address.
    pub tx_count: u64,
    /// Confirmed + mempool balance, in satoshis.
    pub balance_sat: i128,
    /// Confirmed balance only, in satoshis.
    pub confirmed_sat: i128,
}

pub struct AddressTx {
    pub txid: String,
    pub confirmed: bool,
    pub block_time: Option<i64>,
    /// Positive if `address` received on net, negative if it sent on net, in satoshis.
    /// Computed from the vin/vout Esplora already provides (no extra call needed,
    /// unlike Solana where per-transaction details need a separate request).
    pub net_sat: i128,
    /// Text of the first OP_RETURN output (memo), if there is a readable one (e.g. a
    /// THORChain swap memo, see `history`).
    pub memo: Option<String>,
}

/// Data of an OP_RETURN script, as text: `OP_RETURN` followed by ONE push (direct
/// up to 75 bytes, `OP_PUSHDATA1` or `OP_PUSHDATA2`) covering the rest of the
/// script. `None` for any other script or for non-UTF-8 text.
fn op_return_text(script_hex: &str) -> Option<String> {
    let script = hex::decode(script_hex).ok()?;
    let (&opcode, rest) = script.strip_prefix(&[0x6a])?.split_first()?;
    let (len, data) = match opcode {
        1..=75 => (opcode as usize, rest),
        0x4c => (*rest.first()? as usize, &rest[1..]),
        0x4d => (u16::from_le_bytes([*rest.first()?, *rest.get(1)?]) as usize, &rest[2..]),
        _ => return None,
    };
    (data.len() == len).then(|| String::from_utf8(data.to_vec()).ok()).flatten()
}

impl EsploraClient {
    /// `base_url`: `ESPLORA_TESTNET_BASE` or `ESPLORA_MAINNET_BASE` (see
    /// `api::has_pending_btc`/`get_btc_balance`/`send_btc` for how it is chosen from
    /// the network the frontend asks for).
    pub fn new(base_url: &'static str) -> Self {
        let mirrors = match base_url {
            ESPLORA_MAINNET_BASE => MAINNET_MIRRORS.to_vec(),
            ESPLORA_TESTNET_BASE => TESTNET_MIRRORS.to_vec(),
            other => vec![other],
        };
        Self::with_mirrors(mirrors)
    }

    fn with_mirrors(mirrors: Vec<&'static str>) -> Self {
        Self { client: shared_client().clone(), mirrors }
    }

    /// Order to try: benched servers last (stable sort, so the preference order holds
    /// otherwise).
    fn ordered_mirrors(&self) -> Vec<&'static str> {
        let now = Instant::now();
        let cooling = cooling();
        let mut mirrors = self.mirrors.clone();
        mirrors.sort_by_key(|mirror| cooling.get(mirror).is_some_and(|until| *until > now));
        mirrors
    }

    /// Response from the first server that genuinely answers: on 429, 5xx or an
    /// unreachable server, move to the next one. Any other response (success, 400 for a
    /// refused transaction, 404…) is returned as is, without trying elsewhere.
    fn request(&self, path: &str, build: impl Fn(&str) -> RequestBuilder) -> Result<Response> {
        for mirror in self.ordered_mirrors() {
            match build(&format!("{mirror}{path}")).send() {
                Ok(response) if response.status() != StatusCode::TOO_MANY_REQUESTS && !response.status().is_server_error() => return Ok(response),
                _ => {
                    cooling().insert(mirror, Instant::now() + MIRROR_COOLDOWN);
                }
            }
        }
        Err(anyhow!(BITCOIN_SERVERS_DOWN))
    }

    /// JSON GET; `label` names the call in the error (without the address).
    fn get_json<T: DeserializeOwned>(&self, path: &str, label: &str) -> Result<T> {
        let response = self.request(path, |url| self.client.get(url))?;
        anyhow::ensure!(response.status().is_success(), BITCOIN_REQUEST_REFUSED);
        response.json().with_context(|| format!("réponse esplora {label} illisible"))
    }

    /// Confirmed UTXOs available for `address`.
    pub fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        let raw: Vec<UtxoJson> = self.get_json(&format!("/address/{address}/utxo"), "/utxo")?;

        raw.into_iter()
            .filter(|u| u.status.confirmed)
            .map(|u| {
                let bytes = hex::decode(&u.txid).context("txid invalide")?;
                let txid: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow!("txid de taille inattendue"))?;
                Ok(Utxo {
                    txid,
                    vout: u.vout,
                    value_sat: u.value,
                })
            })
            .collect()
    }

    /// `true` if at least one unconfirmed (mempool) transaction involves `address`:
    /// incoming or outgoing funds not mined yet. Uses the dedicated Esplora endpoint
    /// (`/txs/mempool`) rather than a filtered `address_history`. It is lighter, since
    /// it does not need to compute the amounts (vin/vout) of every transaction to
    /// answer a simple yes/no question, and it is called on every automatic balance
    /// refresh (see main.js::refreshBalance).
    pub fn has_mempool_tx(&self, address: &str) -> Result<bool> {
        let raw: Vec<serde_json::Value> = self.get_json(&format!("/address/{address}/txs/mempool"), "/txs/mempool")?;
        Ok(!raw.is_empty())
    }

    /// History of the transactions (confirmed or not) involving `address`, newest first
    /// (an order Esplora already guarantees).
    pub fn address_history(&self, address: &str) -> Result<Vec<AddressTx>> {
        self.address_history_after(address, None)
    }

    /// A page of history: without `after`, the first one (mempool, then 25 confirmed
    /// transactions); with it, the next 25 confirmed transactions older than `after`
    /// (`/txs/chain/:last_seen_txid`).
    pub fn address_history_after(&self, address: &str, after: Option<&str>) -> Result<Vec<AddressTx>> {
        let path = match after {
            None => format!("/address/{address}/txs"),
            Some(txid) => format!("/address/{address}/txs/chain/{txid}"),
        };
        self.transactions_at(&path, address)
    }

    /// Unconfirmed (mempool) transactions involving `address`.
    pub fn mempool_history(&self, address: &str) -> Result<Vec<AddressTx>> {
        self.transactions_at(&format!("/address/{address}/txs/mempool"), address)
    }

    fn transactions_at(&self, path: &str, address: &str) -> Result<Vec<AddressTx>> {
        let raw: Vec<AddressTxJson> = self.get_json(path, "/txs")?;

        Ok(raw
            .into_iter()
            .map(|tx| {
                let received: i128 = tx
                    .vout
                    .iter()
                    .filter(|o| o.scriptpubkey_address.as_deref() == Some(address))
                    .map(|o| o.value as i128)
                    .sum();
                let sent: i128 = tx
                    .vin
                    .iter()
                    .filter_map(|i| i.prevout.as_ref())
                    .filter(|p| p.scriptpubkey_address.as_deref() == Some(address))
                    .map(|p| p.value as i128)
                    .sum();
                AddressTx {
                    memo: tx.vout.iter().find_map(|o| op_return_text(&o.scriptpubkey)),
                    txid: tx.txid,
                    confirmed: tx.status.confirmed,
                    block_time: tx.status.block_time,
                    net_sat: received - sent,
                }
            })
            .collect())
    }

    /// Total number of transactions and balance (confirmed + mempool) of `address`, in
    /// a single call (`/address/{address}`) without the transaction details. Used to
    /// warn before sending to an address that has never been used or is empty (see
    /// `api::btc_recipient_activity`). The balance is computed as signed: mempool
    /// spends can exceed mempool receipts (they consume outputs that are already
    /// confirmed), as seen on real addresses.
    pub fn address_stats(&self, address: &str) -> Result<AddressStats> {
        let raw: AddressStatsJson = self.get_json(&format!("/address/{address}"), "/address")?;
        let balance = |s: &TxoStatsJson| i128::from(s.funded_txo_sum) - i128::from(s.spent_txo_sum);
        Ok(AddressStats {
            tx_count: raw.chain_stats.tx_count.saturating_add(raw.mempool_stats.tx_count),
            balance_sat: balance(&raw.chain_stats) + balance(&raw.mempool_stats),
            confirmed_sat: balance(&raw.chain_stats),
        })
    }

    /// Raw transaction `txid` (display order). The server is not trusted: the caller
    /// recomputes the txid of what it receives (see `ledger::btc`, which refuses any
    /// transaction that does not match the UTXO).
    pub fn raw_transaction(&self, txid: &[u8; 32]) -> Result<Vec<u8>> {
        let resp = self.request(&format!("/tx/{}/hex", hex::encode(txid)), |url| self.client.get(url))?;
        anyhow::ensure!(resp.status().is_success(), "transaction {} introuvable sur esplora", hex::encode(txid));
        hex::decode(resp.text().context("réponse esplora /tx/hex illisible")?.trim()).context("transaction brute esplora invalide")
    }

    /// Broadcasts a raw transaction (hex-encoded for the API) and returns its txid.
    /// Moves to the next server only if the first one is overloaded, down or
    /// unreachable (the same transaction broadcast twice is still a single spend); a
    /// transaction refused by one server is not retried elsewhere.
    ///
    /// The identifier is computed here (`btc_tx::txid`). If a server already knows it
    /// (broadcast by the previous one, which never answered), it is the same
    /// transaction, and it has been sent. If none gives a clear answer: "maybe sent"
    /// (see `wallet_flow::maybe_sent`), never "servers unavailable".
    pub fn broadcast(&self, raw_tx: &[u8]) -> Result<String> {
        let txid = crate::btc_tx::txid(raw_tx).context("transaction Bitcoin illisible")?;
        let hex_tx = hex::encode(raw_tx);
        let mut uncertain = false;
        for mirror in self.ordered_mirrors() {
            match self.client.post(format!("{mirror}/tx")).body(hex_tx.clone()).send() {
                Ok(resp) if resp.status().is_success() => return Ok(txid),
                Ok(resp) if resp.status() == StatusCode::TOO_MANY_REQUESTS || resp.status().is_server_error() => {
                    uncertain |= crate::wallet_flow::server_error_may_have_sent(resp.status());
                }
                Ok(resp) => {
                    let body = resp.text().unwrap_or_default();
                    if body.contains("already") {
                        return Ok(txid);
                    }
                    return Err(anyhow!("échec de diffusion de la transaction : {body}"));
                }
                Err(e) => uncertain |= !crate::wallet_flow::nothing_sent(&e),
            }
            cooling().insert(mirror, Instant::now() + MIRROR_COOLDOWN);
        }
        Err(if uncertain { crate::wallet_flow::maybe_sent(&txid) } else { anyhow!(BITCOIN_SERVERS_DOWN) })
    }

    /// Current fee rates (sat/vByte) per confirmation target (in blocks), sorted by
    /// increasing target, e.g. `[(2, 12.5), (6, 5.0), (144, 1.2)]`. Used to offer a
    /// fast/medium/slow choice before sending (see `api::estimate_btc_fees`). Fees on
    /// mainnet are set by the market (unlike testnet, where they are negligible): without
    /// a dynamic estimate, an underpaying real transaction could stay unconfirmed
    /// forever. Never below 1 sat/vByte: mempool.space advertises lower rates (0.28 on
    /// 2026-10-05), which nodes still configured at 1 sat/vByte (possibly the broadcast
    /// server, not necessarily the one giving the estimate) would not relay.
    pub fn fee_estimates(&self) -> Result<Vec<(u32, f64)>> {
        let raw: HashMap<String, f64> = self.get_json("/fee-estimates", "/fee-estimates")?;

        let mut estimates: Vec<(u32, f64)> = raw
            .into_iter()
            .filter_map(|(target, rate)| target.parse::<u32>().ok().map(|t| (t, rate.max(1.0))))
            .collect();
        estimates.sort_by_key(|(target, _)| *target);
        Ok(estimates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Small local HTTP server: answers every request with `status` and `body`, and
    /// counts the requests received.
    fn local_server(status: &'static str, body: &'static str) -> (&'static str, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url: &'static str = Box::leak(format!("http://{}", listener.local_addr().unwrap()).into_boxed_str());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (url, hits)
    }

    /// Overloaded server (429): the next one answers, and the overloaded one goes last
    /// for later calls.
    #[test]
    fn a_rate_limited_server_hands_over_to_the_next_one() {
        let (busy, busy_hits) = local_server("429 Too Many Requests", "Too Many Requests");
        let (spare, spare_hits) = local_server("200 OK", r#"{"1":12.5,"6":0.3}"#);
        let client = EsploraClient::with_mirrors(vec![busy, spare]);
        assert_eq!(client.fee_estimates().unwrap(), vec![(1, 12.5), (6, 1.0)], "tarif plancher 1 sat/vByte");
        assert_eq!(client.fee_estimates().unwrap().len(), 2);
        assert_eq!(busy_hits.load(Ordering::SeqCst), 1, "en retrait après son 429");
        assert_eq!(spare_hits.load(Ordering::SeqCst), 2);
    }

    /// Refused request (400): no retry elsewhere (a transaction refused by one node is
    /// refused by the others).
    #[test]
    fn a_refusal_is_not_retried_elsewhere() {
        let (refusing, _) = local_server("400 Bad Request", "sendrawtransaction RPC error: bad-txns-inputs-missingorspent");
        let (spare, spare_hits) = local_server("200 OK", "ok");
        let client = EsploraClient::with_mirrors(vec![refusing, spare]);
        let err = client.broadcast(&[0u8; 10]).unwrap_err().to_string();
        assert!(err.contains("bad-txns-inputs-missingorspent"), "{err}");
        assert_eq!(client.address_stats("bc1qtest").err().unwrap().to_string(), BITCOIN_REQUEST_REFUSED);
        assert_eq!(spare_hits.load(Ordering::SeqCst), 0);
    }

    /// Transaction already known to a server (broadcast by a previous one that never
    /// answered): the same transaction, sent, never "failed".
    #[test]
    fn an_already_known_transaction_counts_as_sent() {
        let (busy, _) = local_server("429 Too Many Requests", "");
        let (knowing, _) = local_server("400 Bad Request", "sendrawtransaction RPC error: txn-already-known");
        let client = EsploraClient::with_mirrors(vec![busy, knowing]);
        let raw = hex::decode(REAL_SEGWIT_TX).unwrap();
        assert_eq!(client.broadcast(&raw).unwrap(), REAL_SEGWIT_TXID);
    }

    /// A real segwit transaction (block from 2026-10-05): txid recomputed here.
    const REAL_SEGWIT_TX: &str = "02000000000101ad487afc8681dc27cf310967360e2d08cda3c36ac3ee1f5b6b6750b700fcf43a0100000000fdffffff022412f1050000000016001445e8767745422b4292d96eee4ce6fcb2a3dc81b80095ba0a00000000160014574583706299b84078391eed9e0efb20806c9bbe024730440220473bbb58550feedbbd591af5b4f73239be4df78a7fbe040d790087c11adb9d69022044b091f732aafdc612f528a7688d07e439ee1238ba729aca432f930e65fb4cdf0121039054a6a7a07ed2a76c055103d56dc987917b40d53cf7059cf8797145f6d50bc255cd0e00";
    const REAL_SEGWIT_TXID: &str = "bbf97468027dd29541cd04fa23dcda6fb8b21a618000e5d70f94195ca8fb8c2d";

    #[test]
    fn txid_of_a_real_segwit_transaction() {
        assert_eq!(crate::btc_tx::txid(&hex::decode(REAL_SEGWIT_TX).unwrap()).as_deref(), Some(REAL_SEGWIT_TXID));
        assert_eq!(crate::btc_tx::txid(&[0, 0, 0, 0, 0, 1, 5]), None, "sérialisation tronquée");
    }

    /// All overloaded or unreachable: a clear message, not "unreadable".
    #[test]
    fn all_servers_down_gives_a_clear_message() {
        let (busy, _) = local_server("503 Service Unavailable", "");
        let client = EsploraClient::with_mirrors(vec![busy, "http://127.0.0.1:9"]);
        assert_eq!(client.utxos("bc1qtest").err().unwrap().to_string(), BITCOIN_SERVERS_DOWN);
    }

    /// Live: mempool.space on its own returns the same answers as Blockstream (balance,
    /// history, UTXOs, fees, raw transaction).
    /// `cargo test -- --ignored real_mempool_space_mirror --nocapture`
    #[test]
    #[ignore]
    fn real_mempool_space_mirror() {
        let client = EsploraClient::with_mirrors(vec![MAINNET_MIRRORS[1]]);
        let address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
        let stats = client.address_stats(address).unwrap();
        assert!(stats.tx_count > 0);
        let history = client.address_history(address).unwrap();
        assert!(!history.is_empty());
        let older = client.address_history_after(address, Some(&history.last().unwrap().txid)).unwrap();
        assert!(older.iter().all(|tx| tx.confirmed));
        // UTXOs of an ordinary address (first recipient of a transaction in the latest
        // block): mempool.space refuses the list beyond 500 UTXOs (400 "Too many unspent
        // transaction outputs"), which is the case for `address`.
        let tip = reqwest::blocking::get(format!("{}/blocks/tip/hash", MAINNET_MIRRORS[1])).unwrap().text().unwrap();
        let block: serde_json::Value = reqwest::blocking::get(format!("{}/block/{tip}/txs", MAINNET_MIRRORS[1])).unwrap().json().unwrap();
        let ordinary = block[1]["vout"][0]["scriptpubkey_address"].as_str().unwrap().to_string();
        let utxos = client.utxos(&ordinary).unwrap();
        assert!(client.utxos(address).is_err(), "plus de 500 UTXO : refusé");
        let fees = client.fee_estimates().unwrap();
        assert!(fees.iter().all(|(_, rate)| *rate >= 1.0));
        let txid: [u8; 32] = hex::decode(&history.last().unwrap().txid).unwrap().try_into().unwrap();
        assert!(!client.raw_transaction(&txid).unwrap().is_empty());
        let testnet = EsploraClient::with_mirrors(vec![TESTNET_MIRRORS[1]]);
        assert!(testnet.fee_estimates().is_ok());
        println!("{} tx, {} dans la 1re page, {} plus anciennes, {} UTXO, frais {:?}", stats.tx_count, history.len(), older.len(), utxos.len(), &fees[..3.min(fees.len())]);
    }

    /// OP_RETURN scripts from real THORChain transactions on mainnet (read from
    /// Esplora): direct push (e8bf29df…), `OP_PUSHDATA1` (990fb6f4…), outbound payment
    /// "OUT:" (909686b5…).
    #[test]
    fn op_return_memos_of_real_transactions_are_read() {
        assert_eq!(
            op_return_text("6a423d3a783a72444466356e47696d3352514e4475536150626d79727848714448676f796e6876563a3435363632313837373830302f302f303a2d5f2f74313a302f3730").as_deref(),
            Some("=:x:rDDf5nGim3RQNDuSaPbmyrxHqDHgoynhvV:456621877800/0/0:-_/t1:0/70")
        );
        assert_eq!(
            op_return_text("6a4c503d3a4554482e555344433a3078643139303266363632613239326362393634614231334546354661344630343541633235386138323a32343438333135303430302f302f303a2d5f2f74313a302f3730").as_deref(),
            Some("=:ETH.USDC:0xd1902f662a292cb964aB13EF5Fa4F045Ac258a82:24483150400/0/0:-_/t1:0/70")
        );
        assert_eq!(
            op_return_text("6a444f55543a32363430324233373338463143463934423431454630423739343645463141423734464239354145463045374137443345423945443636433833443236313636").as_deref(),
            Some("OUT:26402B3738F1CF94B41EF0B7946EF1AB74FB95AEF0E7A7D3EB9ED66C83D26166")
        );
        // Not an OP_RETURN, inconsistent length, non-UTF-8 text, empty script.
        for bad in ["0014751e76e8199196d454941c45d1b3a323f1433bd6", "6a05616263", "6a02ffff", "", "zz"] {
            assert_eq!(op_return_text(bad), None, "{bad}");
        }
    }
}
