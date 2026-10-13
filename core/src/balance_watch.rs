//! Live watch of the displayed balances: as soon as a send or a receipt changes an
//! address's amount, the app is notified and reads the balance again, without
//! waiting for the periodic refresh.
//! - Solana (SOL, USDC): WebSocket `accountSubscribe` subscription with the same
//!   public node as the reads, "confirmed" level (about 1 s after the transaction):
//!   the node pushes every change to the account (the address, or its USDC token
//!   account).
//! - Ethereum: balance read again every 6 s (a block every 12 s; public nodes do
//!   not expose an address's pending transactions).
//! - Bitcoin: address statistics (confirmed + mempool) read again every 10 s, so a
//!   broadcast transaction shows up before it confirms.
//! - Registry tokens (`tokens.rs`): ERC-20 read again every 12 s (one Ethereum
//!   block; several displayed tokens must not saturate the public nodes), Solana
//!   tokens pushed like USDC (associated token account).
//! - Dogecoin: address totals (confirmed + pending) read again every 10 s, so a
//!   send or a receipt shows up before the next block (about 1 min).
//! - Transparent Zcash: balance read again every 20 s (a block every 75 s;
//!   lightwalletd only counts mined transactions).
//! - Tron: balance read again every 10 s (a block every 3 s).
//!
//! Nothing new is sent to anyone: the same public addresses, to the same providers
//! as the balance reads. The watch stops when the `BalanceWatch` is dropped (lock,
//! profile or network change).

use crate::tokens::{self, TokenKind};
use crate::{api, btc_rpc, external_wallets, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

/// An address to watch; `id` is handed back as is on every change.
pub struct Target {
    pub id: String,
    /// "evm_mainnet", "evm_sepolia", "btc_mainnet", "btc_testnet", "sol_mainnet",
    /// "sol_devnet" or "usdc_solana".
    pub network: String,
    pub address: String,
    /// Registry token (`tokens.rs`) held at `address` on `network`; `None`: the
    /// network's coin.
    pub token: Option<String>,
}

/// Called with the `id` of an address whose balance changed (or may have changed
/// during a connection outage).
pub type Notify = Arc<dyn Fn(&str) + Send + Sync>;

/// Watch in progress; stopped when dropped.
pub struct BalanceWatch {
    stop: Arc<AtomicBool>,
}

impl Drop for BalanceWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

const MAX_TARGETS: usize = 64;
const EVM_INTERVAL: Duration = Duration::from_secs(6);
const BTC_INTERVAL: Duration = Duration::from_secs(10);
const TOKEN_INTERVAL: Duration = Duration::from_secs(12);
const DOGE_INTERVAL: Duration = Duration::from_secs(10);
const ZEC_INTERVAL: Duration = Duration::from_secs(20);
const TRON_INTERVAL: Duration = Duration::from_secs(10);
const XRP_INTERVAL: Duration = Duration::from_secs(8);
const XLM_INTERVAL: Duration = Duration::from_secs(10);
const NEAR_INTERVAL: Duration = Duration::from_secs(8);
const ADA_INTERVAL: Duration = Duration::from_secs(20);
const STX_INTERVAL: Duration = Duration::from_secs(12);
/// Bittensor: a block every 12 s.
const TAO_INTERVAL: Duration = Duration::from_secs(12);
const HEARTBEAT: Duration = Duration::from_secs(30);
const MAX_BACKOFF_SECS: u64 = 60;

enum Polled {
    Evm(&'static wallet_flow::EvmNetwork, String),
    Btc(&'static wallet_flow::BtcNetwork, String),
    /// ERC-20 token: network, contract, holder.
    Erc20(&'static wallet_flow::EvmNetwork, &'static str, String),
    Doge(String),
    Zec(String),
    Tron(String),
    /// TRC-20 token: contract, holder.
    Trc20(&'static str, String),
    Xrp(String),
    Xlm(String),
    Near(String),
    Ada(String),
    Stx(String),
    Tao(String),
}

impl Polled {
    fn interval(&self) -> Duration {
        match self {
            Polled::Evm(..) => EVM_INTERVAL,
            Polled::Btc(..) => BTC_INTERVAL,
            Polled::Erc20(..) => TOKEN_INTERVAL,
            Polled::Doge(..) => DOGE_INTERVAL,
            Polled::Zec(..) => ZEC_INTERVAL,
            Polled::Tron(..) | Polled::Trc20(..) => TRON_INTERVAL,
            Polled::Xrp(..) => XRP_INTERVAL,
            Polled::Xlm(..) => XLM_INTERVAL,
            Polled::Near(..) => NEAR_INTERVAL,
            Polled::Ada(..) => ADA_INTERVAL,
            Polled::Stx(..) => STX_INTERVAL,
            Polled::Tao(..) => TAO_INTERVAL,
        }
    }
}

/// Starts watching `targets` (addresses checked first).
pub fn start(targets: Vec<Target>, notify: Notify) -> Result<BalanceWatch> {
    ensure!(targets.len() <= MAX_TARGETS, "trop d'adresses à surveiller");
    let stop = Arc::new(AtomicBool::new(false));
    // Solana accounts per node (one WebSocket connection each): (id, account).
    let mut solana: HashMap<&'static str, Vec<(String, String)>> = HashMap::new();
    let mut polled: Vec<(String, Polled)> = Vec::new();
    for target in targets {
        let address = target.address.trim().to_string();
        external_wallets::validate_address(&target.network, &address)?;
        if let Some(token) = &target.token {
            let (_, deployment) = tokens::find(token, &target.network)
                .ok_or_else(|| anyhow!("jeton non pris en charge sur ce réseau : {token}"))?;
            match deployment.kind {
                TokenKind::Erc20 { contract } => {
                    let net = wallet_flow::evm_network(&target.network)
                        .ok_or_else(|| anyhow!("réseau inconnu : {}", target.network))?;
                    polled.push((target.id, Polled::Erc20(net, contract, address)));
                }
                TokenKind::Trc20 { contract } => {
                    polled.push((target.id, Polled::Trc20(contract, address)))
                }
                TokenKind::Spl { .. } | TokenKind::Spl2022 { .. } => {
                    ensure!(
                        target.network == "sol_mainnet",
                        "jeton Solana hors du réseau principal : {token}"
                    );
                    // Associated account of the right program (Token-2022 for xStocks).
                    let account = api::registered_token_account(&address, token)?;
                    solana
                        .entry(wallet_flow::SOLANA_MAINNET.rpc)
                        .or_default()
                        .push((target.id, account));
                }
            }
            continue;
        }
        match target.network.as_str() {
            "sol_mainnet" => solana
                .entry(wallet_flow::SOLANA_MAINNET.rpc)
                .or_default()
                .push((target.id, address)),
            "sol_devnet" => solana
                .entry(wallet_flow::SOLANA_DEVNET.rpc)
                .or_default()
                .push((target.id, address)),
            "usdc_solana" => {
                let token_account = api::usdc_token_account(&address)?;
                solana
                    .entry(wallet_flow::SOLANA_MAINNET.rpc)
                    .or_default()
                    .push((target.id, token_account));
            }
            "btc_mainnet" => {
                polled.push((target.id, Polled::Btc(&wallet_flow::BTC_MAINNET, address)))
            }
            "btc_testnet" => {
                polled.push((target.id, Polled::Btc(&wallet_flow::BTC_TESTNET, address)))
            }
            "doge_mainnet" => polled.push((target.id, Polled::Doge(address))),
            "zec_mainnet" => polled.push((target.id, Polled::Zec(address))),
            "tron_mainnet" => polled.push((target.id, Polled::Tron(address))),
            "xrp_mainnet" => polled.push((target.id, Polled::Xrp(address))),
            "xlm_mainnet" => polled.push((target.id, Polled::Xlm(address))),
            "near_mainnet" => polled.push((target.id, Polled::Near(address))),
            "ada_mainnet" => polled.push((target.id, Polled::Ada(address))),
            "stx_mainnet" => polled.push((target.id, Polled::Stx(address))),
            "tao_mainnet" => polled.push((target.id, Polled::Tao(address))),
            other => match wallet_flow::evm_network(other) {
                // Every EVM network (Ethereum, L2s, BNB Chain...): balance read again.
                Some(net) => polled.push((target.id, Polled::Evm(net, address))),
                None => bail!("réseau inconnu : {other}"),
            },
        }
    }
    for (rpc, accounts) in solana {
        let (stop, notify) = (stop.clone(), notify.clone());
        std::thread::spawn(move || watch_solana(rpc, &accounts, &stop, &notify));
    }
    if !polled.is_empty() {
        let (stop, notify) = (stop.clone(), notify.clone());
        std::thread::spawn(move || poll(&polled, &stop, &notify));
    }
    Ok(BalanceWatch { stop })
}

/// Waits `duration` in small slices so it can stop quickly. `false` if stopped.
fn pause(duration: Duration, stop: &AtomicBool) -> bool {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200).min(end - Instant::now()));
    }
    !stop.load(Ordering::Relaxed)
}

/// WebSocket address of a Solana node (same host as its HTTPS address).
fn ws_url(rpc: &str) -> Result<String> {
    rpc.strip_prefix("https://")
        .map(|rest| format!("wss://{rest}"))
        .ok_or_else(|| anyhow!("nœud Solana sans HTTPS : {rpc}"))
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

fn connect(url: &str) -> Result<Socket> {
    let host = url
        .strip_prefix("wss://")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| anyhow!("adresse WebSocket invalide"))?;
    let address = (host, 443)
        .to_socket_addrs()
        .context("nœud injoignable (DNS)")?
        .next()
        .ok_or_else(|| anyhow!("nœud injoignable (DNS)"))?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .context("nœud injoignable")?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let (mut socket, _) = tungstenite::client_tls(url, tcp)
        .map_err(|e| anyhow!("connexion WebSocket impossible : {e}"))?;
    // Short read: the thread also has to see the stop and send the heartbeat.
    match socket.get_mut() {
        MaybeTlsStream::NativeTls(tls) => tls
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(500)))?,
        MaybeTlsStream::Plain(tcp) => tcp.set_read_timeout(Some(Duration::from_millis(500)))?,
        _ => {}
    }
    Ok(socket)
}

/// What a message from the Solana node says.
#[derive(Debug, PartialEq)]
enum SolanaMessage {
    /// Subscription `request` confirmed under number `subscription`.
    Subscribed {
        request: u64,
        subscription: u64,
    },
    /// Change to the account followed by subscription `subscription`.
    Changed {
        subscription: u64,
    },
    /// Request refused (node limit, invalid account...).
    Refused,
    Other,
}

fn parse_solana_message(text: &str) -> SolanaMessage {
    let Ok(message) = serde_json::from_str::<Value>(text) else {
        return SolanaMessage::Other;
    };
    if message.get("method").and_then(Value::as_str) == Some("accountNotification") {
        return match message
            .pointer("/params/subscription")
            .and_then(Value::as_u64)
        {
            Some(subscription) => SolanaMessage::Changed { subscription },
            None => SolanaMessage::Other,
        };
    }
    match (
        message.get("id").and_then(Value::as_u64),
        message.get("result").and_then(Value::as_u64),
        message.get("error"),
    ) {
        (Some(request), Some(subscription), None) => SolanaMessage::Subscribed {
            request,
            subscription,
        },
        (Some(_), _, Some(_)) => SolanaMessage::Refused,
        _ => SolanaMessage::Other,
    }
}

/// One connection per node, one subscription per account; reconnects with a growing
/// delay. After an outage a change may have been missed, so each address is flagged
/// once to be read again.
fn watch_solana(rpc: &str, accounts: &[(String, String)], stop: &AtomicBool, notify: &Notify) {
    let Ok(url) = ws_url(rpc) else { return };
    let mut backoff = 1;
    let mut reconnecting = false;
    while !stop.load(Ordering::Relaxed) {
        let mut socket = match connect(&url) {
            Ok(socket) => socket,
            Err(_) => {
                if !pause(Duration::from_secs(backoff), stop) {
                    return;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF_SECS);
                continue;
            }
        };
        let subscribed = accounts.iter().enumerate().all(|(request, (_, account))| {
            let subscribe = json!({
                "jsonrpc": "2.0",
                "id": request,
                "method": "accountSubscribe",
                "params": [account, {"encoding": "base64", "commitment": "confirmed"}],
            });
            socket.send(Message::text(subscribe.to_string())).is_ok()
        });
        if reconnecting {
            accounts.iter().for_each(|(id, _)| notify(id));
        }
        reconnecting = true;
        let mut subscriptions: HashMap<u64, usize> = HashMap::new();
        let mut last_ping = Instant::now();
        let mut broken = !subscribed;
        while !broken {
            if stop.load(Ordering::Relaxed) {
                let _ = socket.close(None);
                return;
            }
            match socket.read() {
                Ok(Message::Text(text)) => match parse_solana_message(text.as_str()) {
                    SolanaMessage::Subscribed {
                        request,
                        subscription,
                    } => {
                        if (request as usize) < accounts.len() {
                            subscriptions.insert(subscription, request as usize);
                            backoff = 1;
                        }
                    }
                    SolanaMessage::Changed { subscription } => {
                        if let Some(&index) = subscriptions.get(&subscription) {
                            notify(&accounts[index].0);
                        }
                    }
                    SolanaMessage::Refused => broken = true,
                    SolanaMessage::Other => {}
                },
                Ok(Message::Close(_)) => broken = true,
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => broken = true,
            }
            if last_ping.elapsed() >= HEARTBEAT {
                broken |= socket.send(Message::Ping(Vec::new().into())).is_err();
                last_ping = Instant::now();
            }
        }
        if !pause(Duration::from_secs(backoff), stop) {
            return;
        }
        backoff = (backoff * 2).min(MAX_BACKOFF_SECS);
    }
}

/// Compared read of an address that is read periodically (EVM, Bitcoin, ERC-20
/// tokens, Dogecoin, transparent Zcash).
fn read(polled: &Polled) -> Result<String> {
    Ok(match polled {
        Polled::Evm(network, address) => api::get_evm_balance(address, network)?.to_string(),
        Polled::Btc(network, address) => {
            let stats = btc_rpc::EsploraClient::new(network.esplora_base).address_stats(address)?;
            format!("{}:{}", stats.tx_count, stats.balance_sat)
        }
        Polled::Erc20(network, contract, address) => {
            api::get_erc20_balance(network, contract, address)?.to_string()
        }
        Polled::Doge(address) => crate::doge::watch_reading(address)?,
        Polled::Zec(address) => crate::zcash::balance(address)?.to_string(),
        Polled::Tron(address) => crate::tron::balance(address)?.to_string(),
        Polled::Trc20(contract, address) => {
            crate::tron::trc20_balance(address, contract)?.to_string()
        }
        Polled::Xrp(address) => crate::xrp::balance(&crate::xrp::MAINNET, address)?.to_string(),
        Polled::Xlm(address) => {
            crate::stellar::balance(&crate::stellar::MAINNET, address)?.to_string()
        }
        Polled::Near(address) => crate::near::balance(&crate::near::MAINNET, address)?.to_string(),
        Polled::Ada(address) => crate::cardano::balance(address)?.to_string(),
        Polled::Stx(address) => {
            crate::stacks::balance(&crate::stacks::MAINNET, address)?.to_string()
        }
        Polled::Tao(address) => crate::bittensor::balance(address)?.to_string(),
    })
}

/// Reads each address at its own pace and reports any change from the previous read
/// (the first one serves as the reference). A failed read is simply retried on the
/// next round.
fn poll(targets: &[(String, Polled)], stop: &AtomicBool, notify: &Notify) {
    let mut last: Vec<Option<String>> = vec![None; targets.len()];
    let mut due: Vec<Instant> = vec![Instant::now(); targets.len()];
    loop {
        for (index, (id, polled)) in targets.iter().enumerate() {
            if Instant::now() < due[index] {
                continue;
            }
            due[index] = Instant::now() + polled.interval();
            let Ok(reading) = read(polled) else { continue };
            if last[index]
                .as_ref()
                .is_some_and(|previous| *previous != reading)
            {
                notify(id);
            }
            last[index] = Some(reading);
        }
        if !pause(Duration::from_millis(250), stop) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn solana_messages_are_understood() {
        assert_eq!(
            parse_solana_message(r#"{"jsonrpc":"2.0","result":23784,"id":1}"#),
            SolanaMessage::Subscribed {
                request: 1,
                subscription: 23784
            }
        );
        assert_eq!(
            parse_solana_message(
                r#"{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":5199307},"value":{"lamports":33594}},"subscription":23784}}"#
            ),
            SolanaMessage::Changed {
                subscription: 23784
            }
        );
        assert_eq!(
            parse_solana_message(
                r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param"},"id":0}"#
            ),
            SolanaMessage::Refused
        );
        assert_eq!(parse_solana_message("pas du JSON"), SolanaMessage::Other);
        assert_eq!(
            ws_url("https://api.mainnet-beta.solana.com").unwrap(),
            "wss://api.mainnet-beta.solana.com"
        );
        assert!(ws_url("http://localhost:8899").is_err());
    }

    #[test]
    fn targets_are_checked_before_anything_starts() {
        let notify: Notify = Arc::new(|_| {});
        let target = |network: &str, address: &str| Target {
            id: "x".into(),
            network: network.into(),
            address: address.into(),
            token: None,
        };
        assert!(start(
            vec![target("sol_mainnet", "pas une adresse")],
            notify.clone()
        )
        .is_err());
        assert!(start(vec![target("dogecoin", "D123")], notify.clone()).is_err());
        assert!(
            start(vec![target("doge_mainnet", "D123")], notify.clone()).is_err(),
            "adresse Dogecoin invalide"
        );
        assert!(
            start(
                vec![target(
                    "zec_mainnet",
                    "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3"
                )],
                notify.clone()
            )
            .is_err(),
            "adresse EVM sur Zcash"
        );
        // Unknown token, or not on this network: refused before anything starts.
        let token = |network: &str, address: &str, id: &str| Target {
            id: "x".into(),
            network: network.into(),
            address: address.into(),
            token: Some(id.into()),
        };
        let evm = "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3";
        assert!(start(
            vec![token("evm_mainnet", evm, "pas-un-jeton")],
            notify.clone()
        )
        .is_err());
        assert!(
            start(vec![token("sol_mainnet", evm, "usdt")], notify.clone()).is_err(),
            "adresse EVM sur Solana"
        );
        assert!(start(vec![token("evm_mainnet", evm, "usdt")], notify.clone()).is_ok());
        let many = (0..=MAX_TARGETS)
            .map(|_| target("evm_mainnet", "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3"))
            .collect();
        assert!(start(many, notify).is_err());
    }

    /// REAL nodes, very active addresses: each network must report a change within 5 minutes
    /// (Dogecoin: blocks are sometimes several minutes apart, and an address does not change in every
    /// block). Solana: the network clock's account (changes every slot, about 400 ms, so it is never
    /// idle, unlike a wallet); with `WATCH_SOL_ADDRESS` (an active wallet), the reported change must
    /// also show up in its separately read balance.
    /// `cargo test -- --ignored live_balance_changes_are_reported --nocapture`
    #[test]
    #[ignore]
    fn live_balance_changes_are_reported() {
        let seen: Arc<Mutex<Vec<(String, Instant)>>> = Arc::default();
        let recorder = seen.clone();
        let notify: Notify = Arc::new(move |id| {
            recorder
                .lock()
                .unwrap()
                .push((id.to_string(), Instant::now()))
        });
        let wallet = std::env::var("WATCH_SOL_ADDRESS").ok();
        let sol = wallet
            .clone()
            .unwrap_or_else(|| "SysvarC1ock11111111111111111111111111111111".to_string());
        let sol = sol.as_str();
        let target = |id: &str, network: &str, address: &str| Target {
            id: id.into(),
            network: network.into(),
            address: address.into(),
            token: None,
        };
        let before = api::get_sol_balance(sol, &wallet_flow::SOLANA_MAINNET).unwrap();
        let started = Instant::now();
        let watch = start(
            vec![
                target("sol", "sol_mainnet", sol),
                target(
                    "eth",
                    "evm_mainnet",
                    "0x28C6c06298d514Db089934071355E5743bf21d60",
                ),
                target(
                    "btc",
                    "btc_mainnet",
                    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
                ),
                // ERC-20 token: USDT of the same exchange wallet.
                Target {
                    token: Some("usdt".into()),
                    ..target(
                        "usdt",
                        "evm_mainnet",
                        "0x28C6c06298d514Db089934071355E5743bf21d60",
                    )
                },
                // Dogecoin: the most active address over 4 recent blocks (captured on 2026-10-04).
                target("doge", "doge_mainnet", "D6Dz1pzn2AcwSfz1Sat6Re54pghrFxcRa8"),
            ],
            notify,
        )
        .unwrap();
        while started.elapsed() < Duration::from_secs(300) {
            let ids: Vec<String> = seen
                .lock()
                .unwrap()
                .iter()
                .map(|(id, _)| id.clone())
                .collect();
            if ["sol", "eth", "btc", "usdt", "doge"]
                .iter()
                .all(|id| ids.iter().any(|seen| seen == id))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        drop(watch);
        for (id, at) in seen.lock().unwrap().iter().take(12) {
            println!("{id} après {:?}", at.duration_since(started));
        }
        let ids: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| id.clone())
            .collect();
        for id in ["sol", "eth", "btc", "usdt", "doge"] {
            assert!(
                ids.iter().any(|seen| seen == id),
                "aucun changement signalé pour {id}"
            );
        }
        let after = api::get_sol_balance(sol, &wallet_flow::SOLANA_MAINNET).unwrap();
        println!("SOL : {before} -> {after} lamports");
        if wallet.is_some() {
            assert_ne!(
                before, after,
                "un changement signalé doit se voir dans le solde"
            );
        }
    }
}
