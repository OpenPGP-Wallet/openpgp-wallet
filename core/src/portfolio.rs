//! Dollar value of a set of addresses (the wallet profile, external wallets) over
//! time, rebuilt from chain data: the current balance, then each history transaction
//! going backwards (the actual balance change, fees included), multiplied by the
//! asset's price at each point in time (see `price_history`). Purely informational,
//! read-only.
//!
//! Each address's history is read page by page, as far back as the period requires
//! ("all": back to the first transaction), within a per-address limit. Before the
//! oldest transaction read for an address whose history was not read to the end, its
//! balance is unknown: the chart then starts at that point (`since`) instead of
//! inventing a value.
//!
//! Network with no usable history source (BNB Chain without a NodeReal key): the
//! current balance is counted over the whole period, and the crypto is flagged
//! (`constant`) so the UI can say so.

use crate::history::{self, EvmCursor, TxEntry, TxStatus};
use crate::price_history::{self, Asset, ChartRange, PriceSeries};
use crate::tokens::{self, TokenKind};
use crate::{api, external_wallets, wallet_flow};
use anyhow::{anyhow, ensure, Result};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// An address, its network (app identifiers: "evm_mainnet", "base_mainnet",
/// "btc_mainnet", "sol_mainnet"…; "usdc_solana", the legacy external wallet
/// identifier = USDC on Solana) and, for a token, its identifier in the registry
/// (`tokens`). Test networks are accepted but ignored, since their funds have no
/// value.
pub struct Holding {
    pub network: String,
    pub address: String,
    pub token: Option<String>,
}

pub struct PortfolioHistory {
    /// (time, dollar value), in chronological order; the last point is the present.
    pub points: Vec<(i64, f64)>,
    /// Start of the exact data, when an address's history is truncated within the
    /// requested period.
    pub since: Option<i64>,
    /// Incomplete data encountered (unknown transaction amount, or a negative rebuilt
    /// balance: a movement missing from the history, such as an internal Ethereum
    /// contract transfer): the chart is only indicative.
    pub approximate: bool,
    /// History still being read: ask again for the rest.
    pub loading: bool,
    /// Transactions read so far, across all addresses.
    pub transactions_read: usize,
    /// Cryptos held on a network with no history, counted at their current balance over
    /// the whole period (symbols, deduplicated).
    pub constant: Vec<String>,
    /// Cryptos for which an address could not be read at all (service overloaded or
    /// down): left out of the chart, read again on the next call (symbols,
    /// deduplicated).
    pub unavailable: Vec<String>,
}

/// Maximum transactions read per address: 20 Blockscout pages, 40 Esplora pages.
const EVM_MAX: usize = 1000;
const BTC_MAX: usize = 1000;
/// Dogecoin transactions read for the chart (each block's time requested once from
/// the service, then cached).
const DOGE_MAX: usize = 100;
/// TRX transfers read for the chart (one TronGrid page).
const TRON_MAX: usize = 50;
const XRP_MAX: usize = 50;
const XLM_MAX: usize = 50;
const NEAR_MAX: usize = 25;
const ADA_MAX: usize = 25;
const STX_MAX: usize = 50;
/// TAO transfers read for the chart (one Taostats page).
const TAO_MAX: usize = 100;
/// Confirmed transactions per Esplora page.
const BTC_PAGE: usize = 25;
/// Each Solana transaction needs a detail request, which the public node limits to
/// 35 per 10 s (see `sol_rpc`): 300 ≈ 1 min 30 at worst, much less afterwards
/// (details of finalized transactions are cached).
const SOL_MAX: usize = 300;
/// A short first page (≈ 10 s of reading) so that a chart appears quickly, then
/// longer pages.
const SOL_FIRST_PAGE: u32 = 10;
const SOL_PAGE: u32 = 25;
const MAX_HOLDINGS: usize = 60;
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Maximum wait for one call before returning a partial chart.
const WAIT: Duration = Duration::from_secs(6);
/// Period shown for "all" when no transaction is known.
const DEFAULT_ALL_SPAN: i64 = 365 * 86_400;

/// Continuation of a history: a cursor specific to each source.
#[derive(Clone)]
enum Cursor {
    Evm(EvmCursor),
    /// Last confirmed txid seen.
    Btc(String),
    /// Last signature seen.
    Sol(String),
}

struct Page {
    entries: Vec<TxEntry>,
    next: Option<Cursor>,
}

#[derive(Clone)]
struct HoldingData {
    asset: Asset,
    decimals: i32,
    symbol: &'static str,
    /// No history source: the current balance is counted over the whole period.
    constant: bool,
    /// Current balance, in the smallest unit.
    balance: i128,
    /// (time, balance change), newest to oldest.
    changes: Vec<(i64, i128)>,
    /// Oldest transaction read.
    oldest: Option<i64>,
    /// Continuation of the history; `None` once it has been read to the end.
    next: Option<Cursor>,
    /// Transactions read.
    read: usize,
    approximate: bool,
}

impl HoldingData {
    fn absorb(&mut self, page: Page, now: i64) {
        self.read += page.entries.len();
        // Empty page: end of the history, even if the source gives a cursor.
        self.next = if page.entries.is_empty() { None } else { page.next };
        for entry in &page.entries {
            if let Some(t) = entry.timestamp_unix {
                self.oldest = Some(self.oldest.map_or(t, |o| o.min(t)));
            }
            match entry.balance_change() {
                // Pending: no timestamp yet, counted at the present time.
                Some(change) => self.changes.push((entry.timestamp_unix.unwrap_or(now), change)),
                None => self.approximate = true,
            }
        }
        self.changes.sort_by_key(|change| std::cmp::Reverse(change.0));
    }

    /// Enough history: read to the end, back to `until`, or the limit reached.
    fn covers(&self, until: Option<i64>, max_read: usize) -> bool {
        self.next.is_none() || self.read >= max_read || matches!((until, self.oldest), (Some(u), Some(o)) if o <= u)
    }

    /// Start of the exact data if the history was not read to the end.
    fn known_since(&self) -> Option<i64> {
        self.next.as_ref().and(self.oldest)
    }
}

/// What needs reading for a holding.
#[derive(Clone, Copy)]
struct Spec {
    asset: Asset,
    decimals: i32,
    /// Maximum transactions read.
    max_read: usize,
    symbol: &'static str,
    source: Source,
}

#[derive(Clone, Copy)]
enum Source {
    Btc,
    Sol,
    /// SPL token (mint): history of its associated token account.
    Spl([u8; 32]),
    /// An EVM network's native coin.
    Evm(&'static wallet_flow::EvmNetwork),
    /// ERC-20 token (contract address).
    Erc20(&'static wallet_flow::EvmNetwork, &'static str),
    /// Transparent Zcash: current balance, counted as constant over the period.
    Zec,
    /// Monero: balance and full history from the local state (see `monero`).
    Xmr,
    /// Shielded Zcash: balance and history from the local database (see
    /// `zcash_shielded`).
    ZecShielded,
    /// Dogecoin: recent history, in one page (see `DOGE_MAX`).
    Doge,
    /// Tron: recent TRX transfers, in one page (see `TRON_MAX`).
    Tron,
    /// TRC-20 token (contract): recent transfers, in one page.
    Trc20(&'static str),
    /// XRP Ledger: recent payments, in one page (see `XRP_MAX`).
    Xrp,
    /// Stellar: recent payments, in one page (see `XLM_MAX`).
    Xlm,
    /// NEAR: recent transfers, in one page (see `NEAR_MAX`).
    Near,
    /// Cardano: recent transactions, in one page (see `ADA_MAX`).
    Ada,
    /// Stacks: recent movements, in one page (see `STX_MAX`).
    Stx,
    /// Bittensor: recent transfers, in one page (see `TAO_MAX`); balance only when this
    /// build has no Taostats key.
    Tao,
}

impl Spec {
    /// History read from NodeReal or Alchemy (shared free tiers, see `nodereal` and
    /// `alchemy`).
    fn uses_shared_quota(&self) -> bool {
        matches!(self.source, Source::Evm(net) | Source::Erc20(net, _) if matches!(net.history, Some(wallet_flow::EvmHistory::NodeReal | wallet_flow::EvmHistory::Alchemy)))
    }

    /// A history source exists for this holding (see `EvmNetwork::history`).
    fn has_history(&self) -> bool {
        match self.source {
            Source::Evm(net) | Source::Erc20(net, _) => history::evm_history_available(net),
            Source::Btc | Source::Sol | Source::Spl(_) | Source::Xmr | Source::ZecShielded | Source::Doge | Source::Tron | Source::Trc20(_) | Source::Xrp | Source::Xlm | Source::Near | Source::Ada | Source::Stx => true,
            Source::Tao => crate::bittensor::history_available(),
            Source::Zec => false,
        }
    }
}

/// Holding of `token` (or of the network's native coin) on `network`; `Ok(None)`:
/// no value (test network, or a crypto with no price source).
fn spec(network: &str, token: Option<&str>) -> Result<Option<Spec>> {
    let (network, token) = if network == "usdc_solana" { ("sol_mainnet", Some("usdc")) } else { (network, token) };
    if let Some(token_id) = token {
        let (token, deployment) = tokens::find(token_id, network).ok_or_else(|| anyhow!("jeton non pris en charge sur ce réseau : {token_id}"))?;
        let Some(asset) = price_history::price_asset(&token.symbol.to_ascii_uppercase()) else { return Ok(None) };
        let (source, max_read) = match deployment.kind {
            TokenKind::Spl { .. } => (Source::Spl(api::registered_spl_mint(token_id)?), SOL_MAX),
            // Tokenized shares: no price history, left out of the chart (their current value
            // is still counted on the dashboard).
            TokenKind::Spl2022 { .. } => return Ok(None),
            TokenKind::Erc20 { contract } => {
                let net = wallet_flow::evm_network(network).ok_or_else(|| anyhow!("réseau inconnu : {network}"))?;
                (Source::Erc20(net, contract), EVM_MAX)
            }
            TokenKind::Trc20 { contract } => (Source::Trc20(contract), TRON_MAX),
        };
        return Ok(Some(Spec { asset, decimals: i32::from(deployment.decimals), max_read, symbol: token.symbol, source }));
    }
    Ok(Some(match network {
        "btc_mainnet" => Spec { asset: Asset::Btc, decimals: 8, max_read: BTC_MAX, symbol: "BTC", source: Source::Btc },
        "sol_mainnet" => Spec { asset: Asset::Sol, decimals: 9, max_read: SOL_MAX, symbol: "SOL", source: Source::Sol },
        "zec_mainnet" => Spec { asset: Asset::Pair("ZECUSDT"), decimals: 8, max_read: BTC_MAX, symbol: "ZEC", source: Source::Zec },
        "zec_shielded" => Spec { asset: Asset::Pair("ZECUSDT"), decimals: 8, max_read: usize::MAX, symbol: "ZEC", source: Source::ZecShielded },
        "xmr_mainnet" => Spec { asset: Asset::Kraken("XMRUSD"), decimals: 12, max_read: usize::MAX, symbol: "XMR", source: Source::Xmr },
        "doge_mainnet" => Spec { asset: Asset::Pair("DOGEUSDT"), decimals: 8, max_read: DOGE_MAX, symbol: "DOGE", source: Source::Doge },
        "tron_mainnet" => Spec { asset: Asset::Pair("TRXUSDT"), decimals: 6, max_read: TRON_MAX, symbol: "TRX", source: Source::Tron },
        "xrp_mainnet" => Spec { asset: Asset::Pair("XRPUSDT"), decimals: 6, max_read: XRP_MAX, symbol: "XRP", source: Source::Xrp },
        "xlm_mainnet" => Spec { asset: Asset::Pair("XLMUSDT"), decimals: 7, max_read: XLM_MAX, symbol: "XLM", source: Source::Xlm },
        "near_mainnet" => Spec { asset: Asset::Pair("NEARUSDT"), decimals: 24, max_read: NEAR_MAX, symbol: "NEAR", source: Source::Near },
        "ada_mainnet" => Spec { asset: Asset::Pair("ADAUSDT"), decimals: 6, max_read: ADA_MAX, symbol: "ADA", source: Source::Ada },
        "stx_mainnet" => Spec { asset: Asset::Pair("STXUSDT"), decimals: 6, max_read: STX_MAX, symbol: "STX", source: Source::Stx },
        "tao_mainnet" => Spec { asset: Asset::Pair("TAOUSDT"), decimals: 9, max_read: TAO_MAX, symbol: "TAO", source: Source::Tao },
        other => match wallet_flow::evm_network(other) {
            // Network added by the user: no price (its symbol says nothing about its value),
            // left out of the chart.
            Some(net) if net.mainnet && !net.custom => {
                let Some(asset) = price_history::price_asset(net.native_symbol) else { return Ok(None) };
                Spec { asset, decimals: 18, max_read: EVM_MAX, symbol: net.native_symbol, source: Source::Evm(net) }
            }
            _ => return Ok(None),
        },
    }))
}

fn fetch_balance(spec: &Spec, address: &str) -> Result<i128> {
    let solana = &wallet_flow::SOLANA_MAINNET;
    Ok(match spec.source {
        Source::Evm(net) => api::get_evm_balance(address, net)? as i128,
        Source::Erc20(net, contract) => api::get_erc20_balance(net, contract, address)? as i128,
        // Same as the card: confirmed minus pending sends, WITHOUT unconfirmed receipts
        // (which their sender can cancel, see `api::BtcBalanceView`); those are also
        // removed from the history (`fetch_page`).
        Source::Btc => api::get_btc_balance_view(address, &wallet_flow::BTC_MAINNET)?.settled_sat.into(),
        // Staked SOL included (native staking): it still belongs to the user. If it cannot
        // be read: balance only, rather than no chart at all.
        Source::Sol => {
            let staked = crate::sol_stake::staked_lamports(&crate::sol_rpc::SolRpc::new(solana.rpc), address).unwrap_or(0);
            i128::from(api::get_sol_balance(address, solana)?) + i128::from(staked)
        }
        Source::Zec => api::get_zec_balance(address)?.into(),
        Source::Xmr => crate::monero::balance_of_address(address)?.into(),
        Source::ZecShielded => crate::zcash_shielded::balance_of_address(address)?.into(),
        Source::Doge => api::get_doge_balance(address)?.into(),
        Source::Tron => api::get_trx_balance(address)?.into(),
        Source::Xrp => api::get_xrp_balance(address)?.into(),
        Source::Xlm => api::get_xlm_balance(address)?.into(),
        Source::Near => i128::try_from(api::get_near_balance(address)?).map_err(|_| anyhow!("solde hors limites"))?,
        Source::Ada => api::get_ada_balance(address)?.into(),
        Source::Stx => api::get_stx_balance(address)?.into(),
        Source::Tao => crate::bittensor::balance(address)?.into(),
        Source::Trc20(contract) => i128::try_from(crate::tron::trc20_balance(address, contract)?).map_err(|_| anyhow!("solde hors limites"))?,
        Source::Spl(mint) => api::get_spl_balance(address, &mint, solana)?.into(),
    })
}

/// A page of history: the first without `cursor`, the next one otherwise.
fn fetch_page(spec: &Spec, address: &str, cursor: Option<&Cursor>) -> Result<Page> {
    let solana = &wallet_flow::SOLANA_MAINNET;
    let evm_cursor = match cursor {
        Some(Cursor::Evm(evm)) => Some(evm),
        _ => None,
    };
    match spec.source {
        Source::Evm(net) => {
            let (entries, next) = history::evm_history_page(net.chain_id, address, evm_cursor)?;
            Ok(Page { entries, next: next.map(Cursor::Evm) })
        }
        Source::Erc20(net, contract) => {
            let (entries, next) = history::erc20_history_page(net.chain_id, address, contract, evm_cursor)?;
            Ok(Page { entries, next: next.map(Cursor::Evm) })
        }
        Source::Btc => {
            let after = match cursor {
                Some(Cursor::Btc(txid)) => Some(txid.as_str()),
                _ => None,
            };
            let mut entries = history::btc_history_after(&wallet_flow::BTC_MAINNET, address, after)?;
            let confirmed: Vec<&TxEntry> = entries.iter().filter(|e| matches!(e.status, TxStatus::Confirmed)).collect();
            // Incomplete page of confirmed transactions: end of the history.
            let next = if confirmed.len() >= BTC_PAGE { confirmed.last().map(|e| Cursor::Btc(e.id.clone())) } else { None };
            // Unconfirmed receipts: excluded from the balance (`fetch_balance`), so excluded from the
            // history.
            entries.retain(|e| !(matches!(e.status, TxStatus::Pending) && e.net_amount_minor.is_some_and(|net| net > 0)));
            Ok(Page { entries, next })
        }
        Source::Sol | Source::Spl(_) => {
            let before = match cursor {
                Some(Cursor::Sol(signature)) => Some(signature.as_str()),
                _ => None,
            };
            let size = if before.is_some() { SOL_PAGE } else { SOL_FIRST_PAGE };
            let mut entries = match spec.source {
                Source::Spl(mint) => history::spl_history_before(solana.rpc, &api::spl_token_account(address, &mint)?, size, before)?,
                _ => history::sol_history_before(solana.rpc, address, size, before)?,
            };
            // Native staking: SOL moves from one of the user's accounts to another, both
            // counted (`fetch_balance`); only the fee (0.000005 SOL) changes the total, and it
            // is ignored.
            for entry in entries.iter_mut().filter(|e| e.kind == history::TxKind::Stake) {
                entry.net_amount_minor = Some(0);
            }
            let next = if entries.len() >= size as usize { entries.last().map(|e| Cursor::Sol(e.id.clone())) } else { None };
            Ok(Page { entries, next })
        }
        // Balance counted as constant (`has_history`): never read page by page.
        Source::Zec => Ok(Page { entries: Vec::new(), next: None }),
        // The whole history is local: a single page.
        Source::Xmr => Ok(Page { entries: crate::monero::history_of_address(address)?, next: None }),
        Source::ZecShielded => Ok(Page { entries: crate::zcash_shielded::history_of_address(address)?, next: None }),
        // One page: the `DOGE_MAX` most recent transactions.
        Source::Doge => Ok(Page { entries: crate::doge::history(address, DOGE_MAX)?, next: None }),
        Source::Tron => Ok(Page { entries: crate::tron::history(address, TRON_MAX)?, next: None }),
        Source::Trc20(contract) => Ok(Page { entries: crate::tron::trc20_history(address, contract, TRON_MAX)?, next: None }),
        Source::Xrp => Ok(Page { entries: crate::xrp::history(&crate::xrp::MAINNET, address, XRP_MAX)?, next: None }),
        Source::Xlm => Ok(Page { entries: crate::stellar::history(&crate::stellar::MAINNET, address, XLM_MAX)?, next: None }),
        Source::Near => Ok(Page { entries: crate::near::history(&crate::near::MAINNET, address, NEAR_MAX)?, next: None }),
        Source::Ada => Ok(Page { entries: crate::cardano::history(address, ADA_MAX)?, next: None }),
        Source::Stx => Ok(Page { entries: crate::stacks::history(&crate::stacks::MAINNET, address, STX_MAX)?, next: None }),
        Source::Tao => Ok(Page { entries: crate::bittensor::history(address, TAO_MAX)?, next: None }),
    }
}

/// Balance, then the first page of history (except on a network with no history:
/// balance only, counted over the whole period).
fn fetch_first(spec: &Spec, address: &str) -> Result<HoldingData> {
    let mut data = HoldingData {
        asset: spec.asset,
        decimals: spec.decimals,
        symbol: spec.symbol,
        constant: !spec.has_history(),
        balance: 0,
        changes: Vec::new(),
        oldest: None,
        next: None,
        read: 0,
        approximate: false,
    };
    if data.constant {
        data.balance = fetch_balance(spec, address)?;
        return Ok(data);
    }
    let (balance, first) = std::thread::scope(|scope| {
        let balance = scope.spawn(|| fetch_balance(spec, address));
        let first = fetch_page(spec, address, None);
        (balance.join().expect("le fil du solde ne doit pas paniquer"), first)
    });
    data.balance = balance?;
    match first {
        Ok(page) => data.absorb(page, price_history::unix_now()),
        // NodeReal or Alchemy temporarily unavailable (free-tier limit reached…), or
        // Blockscout history unavailable (public site behind the bot check with no
        // official API key, which is the case for Arbitrum, Base and Polygon since
        // 2026-10-10, or daily credits used up): the balance is counted as constant rather
        // than failing the whole chart, and the UI says so (`constant`) if there is a
        // balance.
        Err(_) if spec.uses_shared_quota() => data.constant = true,
        Err(e) if crate::blockscout::unavailable(&e) => data.constant = true,
        Err(e) => return Err(e),
    }
    Ok(data)
}

/// Network, address and optional token.
type Key = (String, String, Option<String>);

/// Reading an address: the latest published data, the read in progress.
#[derive(Default)]
struct Slot {
    /// Data, and when its balance was read.
    data: Option<(Instant, Arc<HoldingData>)>,
    /// Depth wanted by the read in progress (`None`: the whole history).
    target: Option<i64>,
    running: bool,
    /// Failure of the last read, when it could not read anything.
    error: Option<String>,
}

type Slots = (Mutex<HashMap<Key, Slot>>, Condvar);

fn slots() -> &'static Slots {
    static SLOTS: OnceLock<Slots> = OnceLock::new();
    SLOTS.get_or_init(Default::default)
}

fn lock_slots() -> MutexGuard<'static, HashMap<Key, Slot>> {
    slots().0.lock().unwrap_or_else(|p| p.into_inner())
}

/// The deeper of two limits (`None`: the whole history).
fn deepest(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    Some(a?.min(b?))
}

/// Requests the history of `key` back to `until`: nothing to do if the cached data
/// (5 minutes) covers it; otherwise a background read starts, or the one in
/// progress goes deeper. Asynchronous: the public Solana node only allows about one
/// transaction detail per second, so a long history takes minutes the first time.
fn request(key: &Key, spec: Spec, until: Option<i64>) {
    let max_read = spec.max_read;
    let mut map = lock_slots();
    let slot = map.entry(key.clone()).or_default();
    let fresh = slot.data.as_ref().filter(|(fetched, _)| fetched.elapsed() < CACHE_TTL).map(|(fetched, data)| (*fetched, data.clone()));
    if fresh.as_ref().is_some_and(|(_, data)| data.covers(until, max_read)) {
        return;
    }
    if slot.running {
        slot.target = deepest(slot.target, until);
        return;
    }
    // Continue from fresh data; otherwise a full reread (balance included), published
    // only at the end when a chart is already shown, so as not to shorten it in the
    // meantime.
    let base = fresh.map(|(fetched, data)| (fetched, HoldingData::clone(&data)));
    let publish_each_page = base.is_some() || slot.data.is_none();
    slot.target = until;
    slot.running = true;
    slot.error = None;
    drop(map);
    let key = key.clone();
    std::thread::spawn(move || {
        let address = key.1.clone();
        load(&key, max_read, base, publish_each_page, || fetch_first(&spec, &address), |cursor| fetch_page(&spec, &address, Some(cursor)));
    });
}

/// Background read of `key`: balance and first page (unless continuing from
/// `base`), then older pages down to the wanted depth, rechecked on every page, so
/// a deeper request that arrives in the meantime extends the read. A failed older
/// page stops the descent (the chart then starts at the oldest transaction read)
/// instead of failing everything; it will be requested again later.
fn load(
    key: &Key,
    max_read: usize,
    base: Option<(Instant, HoldingData)>,
    publish_each_page: bool,
    first: impl FnOnce() -> Result<HoldingData>,
    next: impl Fn(&Cursor) -> Result<Page>,
) {
    let publish = |fetched: Instant, data: &HoldingData| {
        if let Some(slot) = lock_slots().get_mut(key) {
            slot.data = Some((fetched, Arc::new(data.clone())));
        }
        slots().1.notify_all();
    };
    let (fetched, mut data) = match base {
        Some(base) => base,
        None => match first() {
            Ok(data) => (Instant::now(), data),
            Err(e) => {
                if let Some(slot) = lock_slots().get_mut(key) {
                    slot.running = false;
                    slot.error = Some(e.to_string());
                }
                slots().1.notify_all();
                return;
            }
        },
    };
    if publish_each_page {
        publish(fetched, &data);
    }
    let now = price_history::unix_now();
    let mut stopped = false;
    loop {
        let cursor = {
            let mut map = lock_slots();
            let Some(slot) = map.get_mut(key) else { return };
            match data.next.clone() {
                Some(cursor) if !stopped && !data.covers(slot.target, max_read) => cursor,
                _ => {
                    slot.data = Some((fetched, Arc::new(data)));
                    slot.running = false;
                    drop(map);
                    slots().1.notify_all();
                    return;
                }
            }
        };
        match next(&cursor) {
            Ok(page) => {
                data.absorb(page, now);
                if publish_each_page {
                    publish(fetched, &data);
                }
            }
            Err(_) => stopped = true,
        }
    }
}

/// Sampled times: multiples of `step` from `start`, then `now`.
fn sample_times(start: i64, now: i64, step: i64) -> Vec<i64> {
    let mut t = start.div_euclid(step) * step;
    if t < start {
        t += step;
    }
    let mut times = Vec::new();
    while t < now {
        times.push(t);
        t += step;
    }
    times.push(now);
    times
}

/// Total value at each point in time: rebuilt balance (current balance minus later
/// changes) × price at that time. A point with no known price for a held asset is
/// skipped. Also reports whether a rebuilt balance went negative (incomplete
/// history).
fn values_over_time(holdings: &[&HoldingData], times: &[i64], price: impl Fn(Asset, i64) -> Option<f64>) -> (Vec<(i64, f64)>, bool) {
    let mut negative = false;
    let mut points = Vec::with_capacity(times.len());
    'times: for &t in times {
        let mut total = 0.0;
        for holding in holdings {
            let later: i128 = holding.changes.iter().take_while(|(ts, _)| *ts > t).map(|(_, change)| change).sum();
            let mut balance = holding.balance - later;
            if balance < 0 {
                negative = true;
                balance = 0;
            }
            if balance == 0 {
                continue;
            }
            let Some(usd) = price(holding.asset, t) else { continue 'times };
            total += balance as f64 / 10f64.powi(holding.decimals) * usd;
        }
        points.push((t, total));
    }
    (points, negative)
}

/// Start of the chart: `range_start` for a fixed period; for "all", the first known
/// transaction (one year if there is none); later if an address's history is
/// truncated (`since`).
fn chart_start(data: &[&HoldingData], range_start: Option<i64>, now: i64) -> (i64, Option<i64>) {
    let since = data.iter().filter_map(|d| d.known_since()).max().filter(|s| range_start.is_none_or(|start| *s > start));
    let first_change = data.iter().filter_map(|d| d.changes.last().map(|c| c.0)).min();
    let start = since.or(range_start).unwrap_or_else(|| first_change.unwrap_or(now - DEFAULT_ALL_SPAN));
    (start, since)
}

/// State of the requested addresses: published data; addresses with neither data
/// nor a failure yet (`missing`); cryptos whose address failed without returning
/// anything (`unavailable`, deduplicated), and the first of those errors.
struct Gathered {
    data: Vec<Arc<HoldingData>>,
    missing: bool,
    unavailable: Vec<String>,
    first_error: Option<String>,
}

fn gather(keys: &[(Key, Spec)], map: &HashMap<Key, Slot>) -> Gathered {
    let mut gathered = Gathered { data: Vec::with_capacity(keys.len()), missing: false, unavailable: Vec::new(), first_error: None };
    for (key, spec) in keys {
        let slot = map.get(key);
        match slot.and_then(|slot| slot.data.as_ref()) {
            Some((_, holding)) => gathered.data.push(holding.clone()),
            None => match slot.and_then(|slot| slot.error.clone()) {
                Some(error) => {
                    if !gathered.unavailable.iter().any(|s| s == spec.symbol) {
                        gathered.unavailable.push(spec.symbol.to_string());
                    }
                    gathered.first_error.get_or_insert(error);
                }
                None => gathered.missing = true,
            },
        }
    }
    gathered
}

/// Value of `holdings` over the period `range`. Waits at most `WAIT` for the needed
/// histories to be read; after that, the chart is computed from what has already
/// been read (`loading`) and reading continues in the background, so a new call
/// returns the rest. As long as an address has not returned anything yet, there are
/// no points (a chart without it would be wrong). A failing address is left out and
/// flagged (`unavailable`): a single overloaded service no longer takes down the
/// whole chart (Esplora returning 429, 2026-10-05).
pub fn portfolio_history(holdings: &[Holding], range: ChartRange) -> Result<PortfolioHistory> {
    ensure!(holdings.len() <= MAX_HOLDINGS, "trop d'adresses pour un graphique");
    for h in holdings {
        external_wallets::validate_address(&h.network, &h.address)?;
    }
    let now = price_history::unix_now();
    let range_start = range.span().map(|span| now - span);
    let mut keys: Vec<(Key, Spec)> = Vec::new();
    for h in holdings {
        if let Some(spec) = spec(&h.network, h.token.as_deref())? {
            keys.push(((h.network.clone(), h.address.trim().to_string(), h.token.clone()), spec));
        }
    }
    for (key, spec) in &keys {
        request(key, *spec, range_start);
    }

    let deadline = Instant::now() + WAIT;
    let mut map = lock_slots();
    while keys.iter().any(|(key, _)| map.get(key).is_some_and(|slot| slot.running)) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        map = slots().1.wait_timeout(map, left).unwrap_or_else(|p| p.into_inner()).0;
    }
    let loading = keys.iter().any(|(key, _)| map.get(key).is_some_and(|slot| slot.running));
    let Gathered { data, missing, unavailable, first_error } = gather(&keys, &map);
    drop(map);
    // No readable address: the error itself.
    if let (true, false, Some(error)) = (data.is_empty(), missing, first_error) {
        return Err(anyhow!(error));
    }
    let transactions_read = data.iter().map(|d| d.read).sum();
    if missing {
        return Ok(PortfolioHistory { points: Vec::new(), since: None, approximate: false, loading: true, transactions_read, constant: Vec::new(), unavailable });
    }
    let mut constant: Vec<String> = Vec::new();
    for d in data.iter().filter(|d| d.constant && d.balance > 0) {
        if !constant.iter().any(|s| s == d.symbol) {
            constant.push(d.symbol.to_string());
        }
    }

    let mut assets: Vec<Asset> = Vec::new();
    for d in &data {
        if !assets.contains(&d.asset) {
            assets.push(d.asset);
        }
    }
    let series: HashMap<Asset, Arc<PriceSeries>> = std::thread::scope(|scope| {
        let handles: Vec<_> = assets.iter().map(|&a| (a, scope.spawn(move || price_history::series(a)))).collect();
        handles.into_iter().map(|(a, h)| h.join().expect("le fil des prix ne doit pas paniquer").map(|s| (a, s))).collect::<Result<_>>()
    })?;

    let refs: Vec<&HoldingData> = data.iter().map(Arc::as_ref).collect();
    let (start, since) = chart_start(&refs, range_start, now);
    let step = if range == ChartRange::All { price_history::step_for_span(now - start) } else { range.step() };
    let times = sample_times(start, now, step);
    let (points, negative) = values_over_time(&refs, &times, |asset, t| series.get(&asset).and_then(|s| s.usd_at(Some(t))));
    Ok(PortfolioHistory { points, since, approximate: negative || data.iter().any(|d| d.approximate), loading, transactions_read, constant, unavailable })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holding_data(asset: Asset, decimals: i32, balance: i128, changes: &[(i64, i128)]) -> HoldingData {
        HoldingData { asset, decimals, symbol: "X", constant: false, balance, changes: changes.to_vec(), oldest: changes.last().map(|c| c.0), next: None, read: changes.len(), approximate: false }
    }

    /// A failing address (Esplora overloaded) is left out and flagged, and the others
    /// make up the chart; if it is the only one failing: the error.
    #[test]
    fn a_failing_address_is_left_out_and_reported() {
        let btc = spec("btc_mainnet", None).unwrap().unwrap();
        let eth = spec("evm_mainnet", None).unwrap().unwrap();
        let key = |network: &str| (network.to_string(), "adresse".to_string(), None);
        let failed = Slot { error: Some("serveurs Bitcoin indisponibles".into()), ..Default::default() };
        let read = Slot { data: Some((Instant::now(), Arc::new(holding_data(Asset::Eth, 18, 1, &[])))), ..Default::default() };
        let map: HashMap<Key, Slot> = [(key("btc_mainnet"), failed), (key("evm_mainnet"), read)].into_iter().collect();
        let both = gather(&[(key("btc_mainnet"), btc), (key("evm_mainnet"), eth)], &map);
        assert_eq!((both.data.len(), both.missing, both.unavailable), (1, false, vec!["BTC".to_string()]));
        let alone = gather(&[(key("btc_mainnet"), btc)], &map);
        assert!(alone.data.is_empty() && !alone.missing);
        assert_eq!(alone.first_error.as_deref(), Some("serveurs Bitcoin indisponibles"));
        // Address not read yet (neither data nor failure): pending.
        assert!(gather(&[(key("sol_mainnet"), eth)], &map).missing);
    }

    #[test]
    fn samples_are_aligned_and_end_now() {
        assert_eq!(sample_times(100, 350, 100), vec![100, 200, 300, 350]);
        assert_eq!(sample_times(150, 350, 100), vec![200, 300, 350]);
        assert_eq!(sample_times(150, 160, 100), vec![160]);
    }

    /// Balance rebuilt backwards: 2 BTC today, 1.5 received at t=300, 0.5 sent (fee
    /// included) at t=200 -> 1 BTC before t=200, 0.5 between 200 and 300...; varying
    /// price; two assets added up.
    #[test]
    fn value_is_rebuilt_backwards_from_the_current_balance() {
        let btc = holding_data(Asset::Btc, 8, 200_000_000, &[(300, 150_000_000), (200, -50_000_000)]);
        let usdc = holding_data(Asset::Usdc, 6, 10_000_000, &[]);
        let price = |asset, t: i64| Some(if asset == Asset::Btc { 1000.0 + t as f64 } else { 1.0 });
        let (points, negative) = values_over_time(&[&btc, &usdc], &[100, 250, 400], price);
        assert!(!negative);
        assert_eq!(points, vec![(100, 1.0 * 1100.0 + 10.0), (250, 0.5 * 1250.0 + 10.0), (400, 2.0 * 1400.0 + 10.0)]);
    }

    /// A movement missing from the history: negative rebuilt balance, clamped to 0 and
    /// flagged; a point with no price for a held asset: skipped.
    #[test]
    fn incomplete_histories_are_flagged_and_unknown_prices_skipped() {
        let eth = holding_data(Asset::Eth, 18, 1_000_000_000_000_000_000, &[(200, 3_000_000_000_000_000_000)]);
        let (points, negative) = values_over_time(&[&eth], &[100, 300], |_, _| Some(2000.0));
        assert!(negative);
        assert_eq!(points, vec![(100, 0.0), (300, 2000.0)]);
        let (points, _) = values_over_time(&[&eth], &[100, 300], |_, t| (t > 200).then_some(2000.0));
        assert_eq!(points, vec![(100, 0.0), (300, 2000.0)], "solde nul à t=100 : aucun prix nécessaire");
        let (points, _) = values_over_time(&[&holding_data(Asset::Eth, 18, 1, &[])], &[100, 300], |_, t| (t > 200).then_some(2000.0));
        assert_eq!(points.len(), 1, "point sans prix omis");
    }

    fn entry(id: &str, timestamp: Option<i64>, net: Option<i128>) -> TxEntry {
        TxEntry {
            id: id.into(),
            timestamp_unix: timestamp,
            status: if timestamp.is_some() { TxStatus::Confirmed } else { TxStatus::Pending },
            net_amount_minor: net,
            fee_minor: 0,
            kind: history::TxKind::Other,
        }
    }

    /// Pages absorbed in order: changes sorted newest to oldest, a pending transaction
    /// counted now, an unknown amount flagged; the history "covers" a period when it
    /// goes back far enough, has been read to the end, or the limit is reached; an
    /// empty page = the end, even with a cursor.
    #[test]
    fn pages_are_absorbed_until_the_period_is_covered() {
        let mut data = holding_data(Asset::Sol, 9, 100, &[]);
        data.absorb(Page { entries: vec![entry("p", None, Some(5)), entry("a", Some(900), Some(10))], next: Some(Cursor::Sol("a".into())) }, 1000);
        assert_eq!(data.changes, vec![(1000, 5), (900, 10)]);
        assert_eq!((data.oldest, data.read, data.known_since()), (Some(900), 2, Some(900)));
        assert!(!data.covers(Some(500), 10), "pas assez loin");
        assert!(data.covers(Some(950), 10), "assez loin");
        assert!(!data.covers(None, 10), "« tout » : pas encore au bout");
        assert!(data.covers(None, 2), "limite de lecture atteinte");

        data.absorb(Page { entries: vec![entry("b", Some(400), None), entry("c", Some(300), Some(-7))], next: Some(Cursor::Sol("c".into())) }, 1000);
        assert_eq!(data.changes, vec![(1000, 5), (900, 10), (300, -7)]);
        assert!(data.approximate, "montant inconnu");
        assert!(data.covers(Some(500), 10));

        data.absorb(Page { entries: vec![], next: Some(Cursor::Sol("c".into())) }, 1000);
        assert!(data.next.is_none() && data.covers(None, 10), "page vide : fin de l'historique");
        assert_eq!(data.known_since(), None, "lu jusqu'au bout : rien d'inventé ni de tronqué");
    }

    /// Background read: each page published as it comes; a deeper request arriving
    /// during the read extends it; end of read flagged; a failure on the first page
    /// kept for the caller; a failure on an older page stops the read and the data is
    /// kept.
    #[test]
    fn background_reads_follow_the_deepest_request() {
        let key: Key = ("test".into(), "adresse-a".into(), None);
        lock_slots().insert(key.clone(), Slot { target: Some(850), running: true, ..Default::default() });
        let first = || {
            let mut data = holding_data(Asset::Sol, 9, 100, &[]);
            data.absorb(Page { entries: vec![entry("a", Some(900), Some(10))], next: Some(Cursor::Sol("a".into())) }, 1000);
            Ok(data)
        };
        let calls = std::cell::Cell::new(0);
        let next = |cursor: &Cursor| {
            calls.set(calls.get() + 1);
            let published = lock_slots().get(&key).and_then(|s| s.data.as_ref().map(|(_, d)| d.read));
            assert_eq!(published, Some(calls.get()), "page précédente publiée avant la suivante");
            let Cursor::Sol(before) = cursor else { unreachable!() };
            if before == "a" {
                // During the read: ask for the whole history.
                request(&key, Spec { asset: Asset::Sol, decimals: 9, max_read: 100, symbol: "SOL", source: Source::Sol }, None);
                return Ok(Page { entries: vec![entry("b", Some(800), Some(5))], next: Some(Cursor::Sol("b".into())) });
            }
            Ok(Page { entries: vec![entry("c", Some(700), Some(1))], next: None })
        };
        load(&key, 100, None, true, first, next);
        assert_eq!(calls.get(), 2, "prolongée jusqu'au bout après la demande « tout »");
        let map = lock_slots();
        let slot = map.get(&key).unwrap();
        assert!(!slot.running);
        let data = &slot.data.as_ref().unwrap().1;
        assert_eq!((data.read, data.oldest, data.known_since()), (3, Some(700), None));
        drop(map);

        let failing: Key = ("test".into(), "adresse-b".into(), None);
        lock_slots().insert(failing.clone(), Slot { running: true, ..Default::default() });
        load(&failing, 100, None, true, || Err(anyhow!("nœud injoignable")), |_| unreachable!());
        let map = lock_slots();
        let slot = map.get(&failing).unwrap();
        assert_eq!((slot.running, slot.error.as_deref(), slot.data.is_none()), (false, Some("nœud injoignable"), true));
        drop(map);

        let partial: Key = ("test".into(), "adresse-c".into(), None);
        lock_slots().insert(partial.clone(), Slot { target: None, running: true, ..Default::default() });
        load(&partial, 100, None, true, first, |_| Err(anyhow!("page refusée")));
        let map = lock_slots();
        let slot = map.get(&partial).unwrap();
        assert!(!slot.running && slot.error.is_none());
        assert_eq!(slot.data.as_ref().unwrap().1.known_since(), Some(900), "tronqué à la dernière page lue");
    }

    /// Start of the chart: a fixed period, or the first transaction for "all", pushed
    /// back to the start of the exact data if a history is truncated; with no
    /// transaction at all, one year.
    #[test]
    fn chart_starts_at_the_first_known_data() {
        let a = holding_data(Asset::Btc, 8, 1, &[(800, 1), (300, 2)]);
        let b = holding_data(Asset::Eth, 18, 1, &[(500, 1)]);
        assert_eq!(chart_start(&[&a, &b], Some(100), 1000), (100, None));
        assert_eq!(chart_start(&[&a, &b], None, 1000), (300, None), "tout : première transaction");
        let mut truncated = holding_data(Asset::Sol, 9, 1, &[(600, 1)]);
        truncated.next = Some(Cursor::Sol("x".into()));
        assert_eq!(chart_start(&[&a, &truncated], None, 1000), (600, Some(600)));
        assert_eq!(chart_start(&[&a, &truncated], Some(700), 1000), (700, None), "tronqué avant la période : sans effet");
        let quiet = holding_data(Asset::Sol, 9, 1, &[]);
        assert_eq!(chart_start(&[&quiet], None, 1000 + DEFAULT_ALL_SPAN), (1000, None));
    }

    /// REAL holdings on the new sources: Avalanche (Routescan), an ERC-20 token
    /// (Blockscout), an SPL token, and BNB Chain without history (constant balance,
    /// flagged). Final value = Σ current balance × current price.
    /// `cargo test -- --ignored real_portfolio_history_covers_new_sources --nocapture`
    #[test]
    #[ignore]
    fn real_portfolio_history_covers_new_sources() {
        let binance = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let holding = |network: &str, address: &str, token: Option<&str>| Holding { network: network.into(), address: address.into(), token: token.map(Into::into) };
        let holdings = [
            holding("avax_mainnet", binance, None),
            holding("bsc_mainnet", binance, None),
            holding("evm_mainnet", binance, Some("usdt")),
            holding("sol_mainnet", "3iUShJYbFX6it5ArcR31Pm6SqqowccAe5NwQrfaG1yvG", Some("usdc")),
        ];
        let history = loop {
            let history = portfolio_history(&holdings, ChartRange::Week).unwrap();
            println!("{} transactions lues, en cours {}", history.transactions_read, history.loading);
            if !history.loading {
                break history;
            }
        };
        println!("{} points, depuis {:?}, approximatif {}, constants {:?}", history.points.len(), history.since, history.approximate, history.constant);
        let mut expected = 0.0;
        for h in &holdings {
            let spec = spec(&h.network, h.token.as_deref()).unwrap().unwrap();
            let balance = fetch_balance(&spec, &h.address).unwrap();
            let price = price_history::series(spec.asset).unwrap().usd_at(None).unwrap();
            println!("{} {} : {balance} × {price} $ (historique : {})", h.network, spec.symbol, spec.has_history());
            expected += balance as f64 / 10f64.powi(spec.decimals) * price;
        }
        let (_, last) = *history.points.last().unwrap();
        println!("valeur actuelle : {last:.2} $, attendu {expected:.2} $");
        assert!((last - expected).abs() <= expected * 0.01 + 0.01, "{last} vs {expected}");
        assert!(!spec("bsc_mainnet", None).unwrap().unwrap().has_history());
        assert!(spec("avax_mainnet", None).unwrap().unwrap().has_history());
        assert!(spec("evm_sepolia", None).unwrap().is_none(), "réseau de test : sans valeur");
    }

    /// REAL addresses (mainnet): the rebuilt final value equals current balance ×
    /// current price; the chart is consistent over 30 days.
    /// `cargo test -- --ignored real_portfolio_history_is_consistent --nocapture`
    #[test]
    #[ignore]
    fn real_portfolio_history_is_consistent() {
        let holdings = [
            Holding { network: "btc_mainnet".into(), address: "bc1qwqap30shafhtfd0k5hda4xep6xypgm6fyvphnw".into(), token: None },
            Holding { network: "evm_mainnet".into(), address: "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3".into(), token: None },
            Holding { network: "sol_mainnet".into(), address: "3iUShJYbFX6it5ArcR31Pm6SqqowccAe5NwQrfaG1yvG".into(), token: None },
            Holding { network: "btc_testnet".into(), address: "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk".into(), token: None },
        ];
        // Repeated calls while the read continues in the background, like the app does.
        let complete = |range| loop {
            let history = portfolio_history(&holdings, range).unwrap();
            println!("{range:?} : {} transactions lues, en cours {}", history.transactions_read, history.loading);
            if !history.loading {
                break history;
            }
        };
        let started = Instant::now();
        let history = complete(ChartRange::Month);
        println!("{} points en {:?}, depuis {:?}, approximatif {}", history.points.len(), started.elapsed(), history.since, history.approximate);
        for (t, v) in history.points.iter().step_by(30) {
            println!("{t} : {v:.2} $");
        }
        let (_, last) = *history.points.last().unwrap();
        let btc = api::get_btc_balance_view(&holdings[0].address, &wallet_flow::BTC_MAINNET).unwrap().settled_sat as f64 / 1e8;
        let eth = api::get_evm_balance(&holdings[1].address, &wallet_flow::ETHEREUM_MAINNET).unwrap() as f64 / 1e18;
        let sol = api::get_sol_balance(&holdings[2].address, &wallet_flow::SOLANA_MAINNET).unwrap() as f64 / 1e9;
        let price = |a| price_history::series(a).unwrap().usd_at(None).unwrap();
        let expected = btc * price(Asset::Btc) + eth * price(Asset::Eth) + sol * price(Asset::Sol);
        println!("valeur actuelle : {last:.2} $, attendu {expected:.2} $");
        assert!((last - expected).abs() <= expected * 0.01 + 0.01, "{last} vs {expected}");

        let deeper = Instant::now();
        let all = complete(ChartRange::All);
        println!("tout : {} points en {:?}, depuis {:?}, approximatif {}", all.points.len(), deeper.elapsed(), all.since, all.approximate);
        assert!(all.points.first().unwrap().0 <= history.points.first().unwrap().0, "« tout » remonte au moins aussi loin");
        assert!((all.points.last().unwrap().1 - last).abs() <= last * 0.01 + 0.01, "même valeur actuelle");
        let again = Instant::now();
        assert!(!portfolio_history(&holdings, ChartRange::Month).unwrap().loading);
        assert!(again.elapsed() < Duration::from_secs(2), "changement de période servi par le cache");
    }

    /// Explorers behind a bot check (Arbitrum and Base on Blockscout, seen on
    /// 2026-10-10): balance counted as constant, no more "temporarily unreadable"
    /// address on every chart. Still valid once the block is lifted (no address
    /// unavailable).
    /// `cargo test -- --ignored blocked_explorers_do_not_break_the_curve --nocapture`
    #[test]
    #[ignore]
    fn blocked_explorers_do_not_break_the_curve() {
        let address = "0x9458AF2B720Ecf1bB18f525d864A28Af5c818cfA";
        let holdings: Vec<Holding> = ["evm_mainnet", "arbitrum_mainnet", "base_mainnet"]
            .into_iter()
            .flat_map(|network| [None, Some("usdc".to_string())].map(|token| Holding { network: network.into(), address: address.into(), token }))
            .collect();
        let mut history = portfolio_history(&holdings, ChartRange::Week).unwrap();
        for _ in 0..10 {
            if !history.loading {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
            history = portfolio_history(&holdings, ChartRange::Week).unwrap();
        }
        println!("{} points, indisponibles {:?}, constants {:?}", history.points.len(), history.unavailable, history.constant);
        assert!(history.unavailable.is_empty(), "adresses illisibles : {:?}", history.unavailable);
        assert!(!history.points.is_empty());
    }
}

