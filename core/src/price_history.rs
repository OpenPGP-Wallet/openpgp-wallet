//! Historical prices in dollars, used to show the value of a transaction AT THE
//! TIME it happened. Purely informational: plays no part in building or signing a
//! transaction.
//!
//! Source: Binance's public market data API (`data-api.binance.vision`, keyless),
//! hourly candles (≈ the last 41 days) and daily candles (since the asset was
//! listed: August 2017 for BTC and ETH), USDT pairs (≈ $1). For a crypto Binance
//! does not list (VVV): Kraken's public OHLC API (keyless, in dollars), at most 720
//! candles per interval (≈ 2 years of daily candles: all of VVV's history, listed
//! since February 2025). For xStocks tokenized shares (listed neither on Binance
//! nor in Kraken's public API): Jupiter's charts (`datapi.jup.ag`, the ones its
//! website uses, keyless, undocumented), priced per DISPLAYED unit. Measured on
//! 2026-10-10: the latest AAPLx close = Jupiter's price per displayed unit, full
//! daily history since listing (June 2025), 25 quick calls accepted. Fallback:
//! GeckoTerminal (the most liquid Solana pool, same unit), limited to about 6 calls
//! in quick succession (measured). CoinGecko, already used for the current price,
//! was ruled out here: its free tier refused the 3rd consecutive call during
//! testing, and the history needs several.
//!
//! Privacy: requests ask for complete SERIES, identical for everyone, never the
//! price at the exact time of a transaction, which would reveal to the provider
//! (together with the IP address) when the user's transactions happened, and
//! therefore the transactions themselves. The value of each transaction is computed
//! here, locally.

use anyhow::{anyhow, ensure, Context, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const KLINES_URL: &str = "https://data-api.binance.vision/api/v3/klines";
const KRAKEN_OHLC_URL: &str = "https://api.kraken.com/0/public/OHLC";
const GECKO_TERMINAL_URL: &str = "https://api.geckoterminal.com/api/v2/networks/solana";
const JUPITER_CHARTS_URL: &str = "https://datapi.jup.ag/v2/charts";
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
/// Beyond this, the series are reread (the latest hourly candle moves on).
const CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Asset {
    Btc,
    Eth,
    Sol,
    Usdc,
    /// Exchange rate: dollars per euro (EUR/USDT pair, listed since 2020-01-03), used
    /// to show amounts in euros at each date's rate.
    Eur,
    /// Any other crypto: Binance USDT pair (allowlist, see `price_asset`).
    Pair(&'static str),
    /// A crypto Binance does not list: Kraken dollar pair.
    Kraken(&'static str),
    /// xStocks tokenized share (Solana mint from the registry): Jupiter's charts, with
    /// GeckoTerminal as a fallback.
    Solana(&'static str),
    /// A dollar stablecoin with no market pair (USDT, the quote currency of Binance
    /// pairs; USDG): $1, for the value of a balance or a transaction. No chart.
    Usd,
}

/// Price series for one of the app's cryptos, by its symbol (`None`: no price
/// source). Tokenized shares: by their uppercase symbol ("TSLAX").
pub fn price_asset(symbol: &str) -> Option<Asset> {
    listed_asset(symbol).or_else(|| xstock_asset(symbol))
}

/// The registry's tokenized share whose (uppercase) symbol is `symbol`.
fn xstock_asset(symbol: &str) -> Option<Asset> {
    crate::tokens::TOKENS
        .iter()
        .filter(|t| t.symbol.to_ascii_uppercase() == symbol)
        .flat_map(|t| t.deployments)
        .find_map(|d| match d.kind {
            crate::tokens::TokenKind::Spl2022 { mint } => Some(Asset::Solana(mint)),
            _ => None,
        })
}

fn listed_asset(symbol: &str) -> Option<Asset> {
    Some(match symbol {
        "BTC" => Asset::Btc,
        "ETH" => Asset::Eth,
        "SOL" => Asset::Sol,
        "USDC" => Asset::Usdc,
        "EUR" => Asset::Eur,
        "BNB" => Asset::Pair("BNBUSDT"),
        "AVAX" => Asset::Pair("AVAXUSDT"),
        "POL" => Asset::Pair("POLUSDT"),
        "ZEC" => Asset::Pair("ZECUSDT"),
        "DOGE" => Asset::Pair("DOGEUSDT"),
        "TRX" => Asset::Pair("TRXUSDT"),
        "XRP" => Asset::Pair("XRPUSDT"),
        "XLM" => Asset::Pair("XLMUSDT"),
        "NEAR" => Asset::Pair("NEARUSDT"),
        "ADA" => Asset::Pair("ADAUSDT"),
        "STX" => Asset::Pair("STXUSDT"),
        "TAO" => Asset::Pair("TAOUSDT"),
        "LINK" => Asset::Pair("LINKUSDT"),
        "DAI" => Asset::Pair("DAIUSDT"),
        "USDE" => Asset::Pair("USDEUSDT"),
        "UNI" => Asset::Pair("UNIUSDT"),
        "XAUT" => Asset::Pair("XAUTUSDT"),
        "ONDO" => Asset::Pair("ONDOUSDT"),
        "QNT" => Asset::Pair("QNTUSDT"),
        "FET" => Asset::Pair("FETUSDT"),
        "GNO" => Asset::Pair("GNOUSDT"),
        "ARB" => Asset::Pair("ARBUSDT"),
        "ASTER" => Asset::Pair("ASTERUSDT"),
        "RENDER" => Asset::Pair("RENDERUSDT"),
        "VVV" => Asset::Kraken("VVVUSD"),
        "JITOSOL" => Asset::Kraken("JITOSOLUSD"),
        // stETH: listed neither on Binance nor on Kraken; it tracks ETH 1:1 to within a
        // few tenths of a percent (redeemable through Lido), so we use the ETH chart.
        "STETH" => Asset::Eth,
        // Monero: delisted from Binance in 2024, whose API still returns a frozen price
        // ($118.70 on 2026-10-03, versus $553 on Kraken).
        "XMR" => Asset::Kraken("XMRUSD"),
        "USDT" | "USDG" => Asset::Usd,
        // EURC tracks the euro: its chart is EUR/USDT's.
        "EURC" => Asset::Eur,
        _ => return None,
    })
}

impl Asset {
    /// Binance pair (`None`: another source, or none).
    fn binance_symbol(self) -> Option<&'static str> {
        Some(match self {
            Asset::Btc => "BTCUSDT",
            Asset::Eth => "ETHUSDT",
            Asset::Sol => "SOLUSDT",
            Asset::Usdc => "USDCUSDT",
            Asset::Eur => "EURUSDT",
            Asset::Pair(pair) => pair,
            Asset::Kraken(_) | Asset::Solana(_) | Asset::Usd => return None,
        })
    }

    /// Counted at $1 wherever its series has no price (see `PriceSeries::stable`).
    fn is_stable(self) -> bool {
        matches!(self, Asset::Usdc | Asset::Usd)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Candle {
    /// Start of the candle, in Unix seconds.
    open_time: i64,
    open: f64,
    close: f64,
}

/// An asset's hourly and daily candles, sorted by date.
#[derive(Debug)]
pub struct PriceSeries {
    hourly: Vec<Candle>,
    daily: Vec<Candle>,
    /// Stablecoin (USDC): $1 wherever the series has no price. Binance removed the
    /// USDC/USDT pair from 2022-09-26 to 2023-03-11 (seen on the API); without this,
    /// any portfolio value containing USDC vanished from the chart over that period.
    stable: bool,
}

impl PriceSeries {
    /// Price in dollars at time `timestamp` (Unix seconds): the hourly candle if the
    /// time is covered, otherwise the daily one, interpolated between open and close.
    /// `None` (pending transaction): the latest price. Returns `None` if the time is
    /// before every known candle.
    pub fn usd_at(&self, timestamp: Option<i64>) -> Option<f64> {
        let Some(t) = timestamp else {
            return self
                .hourly
                .last()
                .or(self.daily.last())
                .map(|c| c.close)
                .or(self.stable.then_some(1.0));
        };
        price_in(&self.hourly, HOUR, t)
            .or_else(|| price_in(&self.daily, DAY, t))
            .or(self.stable.then_some(1.0))
    }
}

/// Price at time `t` within candles of duration `span`: linear interpolation
/// between the open and close of the candle containing `t`; after the last candle
/// (clock running ahead), its close.
fn price_in(candles: &[Candle], span: i64, t: i64) -> Option<f64> {
    let first = candles.first()?;
    if t < first.open_time {
        return None;
    }
    let index = candles.partition_point(|c| c.open_time <= t) - 1;
    let candle = candles[index];
    let elapsed = t - candle.open_time;
    if elapsed >= span {
        // A gap in the series, or a time after the last candle.
        return (index + 1 == candles.len()).then_some(candle.close);
    }
    Some(candle.open + (candle.close - candle.open) * elapsed as f64 / span as f64)
}

/// Binance `klines` response: `[[open_ms, "open", "high", "low", "close", ...],
/// ...]`. Any inconsistent series (non-increasing dates, non-positive prices) is
/// refused rather than showing a wrong value.
fn parse_klines(body: &str) -> Result<Vec<Candle>> {
    let rows: Vec<Vec<serde_json::Value>> =
        serde_json::from_str(body).context("réponse de prix illisible")?;
    let mut candles = Vec::with_capacity(rows.len());
    for row in rows {
        let open_ms = row
            .first()
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
        let price = |i: usize| -> Result<f64> {
            let value: f64 = row
                .get(i)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
            ensure!(
                value.is_finite() && value > 0.0,
                "prix invalide dans la série"
            );
            Ok(value)
        };
        candles.push(Candle {
            open_time: open_ms.div_euclid(1000),
            open: price(1)?,
            close: price(4)?,
        });
    }
    ensure!(
        candles.windows(2).all(|w| w[0].open_time < w[1].open_time),
        "série de prix non ordonnée"
    );
    Ok(candles)
}

/// Kraken OHLC response: `{"error": [], "result": {"<pair>": [[open_s, "open",
/// "high", "low", "close", "vwap", "volume", count], ...], "last": n}}`. Same
/// refusals as `parse_klines`.
fn parse_kraken_ohlc(body: &str) -> Result<Vec<Candle>> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("réponse de prix illisible")?;
    if let Some(errors) = value.get("error").and_then(serde_json::Value::as_array) {
        ensure!(
            errors.is_empty(),
            "le service de prix a refusé la demande : {}",
            serde_json::Value::Array(errors.clone())
        );
    }
    let rows = value
        .get("result")
        .and_then(serde_json::Value::as_object)
        .and_then(|result| result.iter().find(|(key, _)| *key != "last"))
        .and_then(|(_, rows)| rows.as_array())
        .ok_or_else(|| anyhow!("réponse de prix illisible"))?;
    let mut candles = Vec::with_capacity(rows.len());
    for row in rows {
        let open_time = row
            .get(0)
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
        let price = |i: usize| -> Result<f64> {
            let value: f64 = row
                .get(i)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
            ensure!(
                value.is_finite() && value > 0.0,
                "prix invalide dans la série"
            );
            Ok(value)
        };
        candles.push(Candle {
            open_time,
            open: price(1)?,
            close: price(4)?,
        });
    }
    ensure!(
        candles.windows(2).all(|w| w[0].open_time < w[1].open_time),
        "série de prix non ordonnée"
    );
    Ok(candles)
}

/// GeckoTerminal OHLCV response: `{"data": {"attributes": {"ohlcv_list": [[open_s,
/// open, high, low, close, volume], ...]}}}`, newest first, put back in order. Same
/// refusals as `parse_klines`.
fn parse_gecko_ohlcv(body: &str) -> Result<Vec<Candle>> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("réponse de prix illisible")?;
    let rows = value
        .pointer("/data/attributes/ohlcv_list")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("réponse de prix illisible"))?;
    let mut candles = Vec::with_capacity(rows.len());
    for row in rows {
        let open_time = row
            .get(0)
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
        let price = |i: usize| -> Result<f64> {
            let value = row
                .get(i)
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
            ensure!(
                value.is_finite() && value > 0.0,
                "prix invalide dans la série"
            );
            Ok(value)
        };
        candles.push(Candle {
            open_time,
            open: price(1)?,
            close: price(4)?,
        });
    }
    candles.reverse();
    ensure!(
        candles.windows(2).all(|w| w[0].open_time < w[1].open_time),
        "série de prix non ordonnée"
    );
    Ok(candles)
}

/// Jupiter chart response: `{"candles": [{"time": s, "open": o, "close": c, ...},
/// ...]}`, oldest to newest. Same refusals as `parse_klines`.
fn parse_jupiter_chart(body: &str) -> Result<Vec<Candle>> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("réponse de prix illisible")?;
    let rows = value
        .get("candles")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("réponse de prix illisible"))?;
    let mut candles = Vec::with_capacity(rows.len());
    for row in rows {
        let open_time = row
            .get("time")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
        let price = |field: &str| -> Result<f64> {
            let value = row
                .get(field)
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
            ensure!(
                value.is_finite() && value > 0.0,
                "prix invalide dans la série"
            );
            Ok(value)
        };
        candles.push(Candle {
            open_time,
            open: price("open")?,
            close: price("close")?,
        });
    }
    ensure!(!candles.is_empty(), "aucun prix pour cette action");
    ensure!(
        candles.windows(2).all(|w| w[0].open_time < w[1].open_time),
        "série de prix non ordonnée"
    );
    Ok(candles)
}

/// Jupiter candles for the share `mint` (the last `limit`, at most 1000).
fn fetch_jupiter_chart(mint: &str, interval: &str, limit: usize) -> Result<Vec<Candle>> {
    let interval = match interval {
        "15m" => "15_MINUTE",
        "1h" => "1_HOUR",
        "4h" => "4_HOUR",
        "1d" => "1_DAY",
        other => anyhow::bail!("intervalle non pris en charge : {other}"),
    };
    let now_ms = unix_now().saturating_mul(1000);
    let response = shared_client()
        .get(format!("{JUPITER_CHARTS_URL}/{mint}"))
        .query(&[
            ("interval", interval.to_string()),
            ("to", now_ms.to_string()),
            ("candles", limit.min(1000).to_string()),
            ("type", "price".to_string()),
            ("quote", "usd".to_string()),
        ])
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(
        response.status().is_success(),
        "le service de prix a répondu {}",
        response.status()
    );
    parse_jupiter_chart(&response.text().context("réponse de prix illisible")?)
}

/// Candles for a tokenized share: Jupiter, otherwise GeckoTerminal.
fn fetch_xstock(
    mint: &str,
    interval: &str,
    limit: usize,
    start: Option<i64>,
) -> Result<Vec<Candle>> {
    match fetch_jupiter_chart(mint, interval, limit) {
        Ok(candles) => Ok(match start {
            Some(start) => candles
                .into_iter()
                .filter(|c| c.open_time >= start)
                .collect(),
            None => candles,
        }),
        Err(_) => fetch_gecko(mint, interval, limit, start),
    }
}

/// The most liquid pool where the share `mint` is the base token (the price read is
/// for it), chosen once per session.
fn gecko_pool(mint: &str) -> Result<String> {
    static POOLS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let pools = POOLS.get_or_init(Default::default);
    if let Some(pool) = pools.lock().unwrap_or_else(|p| p.into_inner()).get(mint) {
        return Ok(pool.clone());
    }
    let response = shared_client()
        .get(format!("{GECKO_TERMINAL_URL}/tokens/{mint}/pools"))
        .header("accept", "application/json")
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(
        response.status().is_success(),
        "le service de prix a répondu {}",
        response.status()
    );
    let body: serde_json::Value = response.json().context("réponse de prix illisible")?;
    let base = format!("solana_{mint}");
    let pool = body["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| {
            p.pointer("/relationships/base_token/data/id")
                .and_then(serde_json::Value::as_str)
                == Some(base.as_str())
        })
        .max_by(|a, b| {
            let liquidity = |p: &serde_json::Value| {
                p.pointer("/attributes/reserve_in_usd")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0)
            };
            liquidity(a).total_cmp(&liquidity(b))
        })
        .and_then(|p| {
            p.pointer("/attributes/address")
                .and_then(serde_json::Value::as_str)
        })
        .ok_or_else(|| anyhow!("aucun marché trouvé pour cette action"))?
        .to_string();
    pools
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(mint.to_string(), pool.clone());
    Ok(pool)
}

/// GeckoTerminal candles for the share `mint`, same parameters as `fetch_klines`
/// (the last `limit`, at most 1000; `start`: the ones after it, among those).
fn fetch_gecko(
    mint: &str,
    interval: &str,
    limit: usize,
    start: Option<i64>,
) -> Result<Vec<Candle>> {
    let (timeframe, aggregate) = match interval {
        "15m" => ("minute", 15),
        "1h" => ("hour", 1),
        "4h" => ("hour", 4),
        "1d" => ("day", 1),
        other => anyhow::bail!("intervalle non pris en charge : {other}"),
    };
    let response = shared_client()
        .get(format!(
            "{GECKO_TERMINAL_URL}/pools/{}/ohlcv/{timeframe}",
            gecko_pool(mint)?
        ))
        .header("accept", "application/json")
        .query(&[
            ("aggregate", aggregate.to_string()),
            ("limit", limit.min(1000).to_string()),
            ("currency", "usd".to_string()),
            ("token", "base".to_string()),
        ])
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(
        response.status().is_success(),
        "le service de prix a répondu {}",
        response.status()
    );
    let candles = parse_gecko_ohlcv(&response.text().context("réponse de prix illisible")?)?;
    Ok(match start {
        Some(start) => candles
            .into_iter()
            .filter(|c| c.open_time >= start)
            .collect(),
        None => candles,
    })
}

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// `interval` candles for `asset`: the last `limit`, or the first `limit` from
/// `start` (Unix seconds). At most 1000 per request.
fn fetch_klines(
    asset: Asset,
    interval: &str,
    limit: usize,
    start: Option<i64>,
) -> Result<Vec<Candle>> {
    let symbol = match asset {
        Asset::Kraken(pair) => return fetch_kraken(pair, interval, limit, start),
        Asset::Solana(mint) => return fetch_xstock(mint, interval, limit, start),
        Asset::Usd => anyhow::bail!("pas de série de prix pour un dollar stable"),
        other => other.binance_symbol().expect("paire Binance"),
    };
    let mut query = vec![
        ("symbol", symbol.to_string()),
        ("interval", interval.to_string()),
        ("limit", limit.to_string()),
    ];
    if let Some(start) = start {
        query.push(("startTime", (start * 1000).to_string()));
    }
    let response = shared_client()
        .get(KLINES_URL)
        .query(&query)
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(
        response.status().is_success(),
        "le service de prix a répondu {}",
        response.status()
    );
    parse_klines(&response.text().context("réponse de prix illisible")?)
}

/// Kraken candles for `pair`, same parameters as `fetch_klines`: Kraken always
/// returns its last 720 candles (or fewer); the last `limit` are kept, or the first
/// `limit` from `start`.
fn fetch_kraken(
    pair: &str,
    interval: &str,
    limit: usize,
    start: Option<i64>,
) -> Result<Vec<Candle>> {
    let minutes = match interval {
        "15m" => 15,
        "1h" => 60,
        "4h" => 240,
        "1d" => 1440,
        other => anyhow::bail!("intervalle non pris en charge : {other}"),
    };
    let response = shared_client()
        .get(KRAKEN_OHLC_URL)
        .query(&[
            ("pair", pair.to_string()),
            ("interval", minutes.to_string()),
        ])
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(
        response.status().is_success(),
        "le service de prix a répondu {}",
        response.status()
    );
    let candles = parse_kraken_ohlc(&response.text().context("réponse de prix illisible")?)?;
    Ok(match start {
        Some(start) => candles
            .into_iter()
            .filter(|c| c.open_time >= start)
            .take(limit)
            .collect(),
        None => candles[candles.len().saturating_sub(limit)..].to_vec(),
    })
}

/// Every daily candle since `asset` was listed: pages of 1000 from the origin (≈ 4
/// requests for Bitcoin).
fn fetch_daily_history(asset: Asset) -> Result<Vec<Candle>> {
    const PAGE: usize = 1000;
    // Tokenized shares: listed since June 2025, fewer than 1000 days.
    if let Asset::Solana(mint) = asset {
        return fetch_xstock(mint, "1d", PAGE, None);
    }
    let mut candles: Vec<Candle> = Vec::new();
    loop {
        let start = candles.last().map_or(0, |c| c.open_time + DAY);
        let page = fetch_klines(asset, "1d", PAGE, Some(start))?;
        let full = page.len() == PAGE;
        candles.extend(page);
        // 30 pages: over 80 years of candles, a guard against an endless loop.
        if !full || candles.len() >= 30 * PAGE {
            break;
        }
    }
    ensure!(
        candles.windows(2).all(|w| w[0].open_time < w[1].open_time),
        "série de prix non ordonnée"
    );
    Ok(candles)
}

/// Price series for `asset` (10-minute cache; hourly and daily read in parallel on
/// the first call). A failure is not cached: retried on the next call.
pub fn series(asset: Asset) -> Result<Arc<PriceSeries>> {
    /// Series per asset, with the time they were read.
    type Cache = Mutex<HashMap<Asset, (Instant, Arc<PriceSeries>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if asset == Asset::Usd {
        return Ok(Arc::new(PriceSeries {
            hourly: Vec::new(),
            daily: Vec::new(),
            stable: true,
        }));
    }
    if let Some((fetched, series)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&asset) {
        if fetched.elapsed() < CACHE_TTL {
            return Ok(series.clone());
        }
    }
    let (hourly, daily) = std::thread::scope(|scope| {
        let hourly = scope.spawn(|| fetch_klines(asset, "1h", 1000, None));
        let daily = scope.spawn(|| fetch_daily_history(asset));
        (
            hourly
                .join()
                .expect("le fil des prix horaires ne doit pas paniquer"),
            daily
                .join()
                .expect("le fil des prix journaliers ne doit pas paniquer"),
        )
    });
    let series = Arc::new(PriceSeries {
        hourly: hourly?,
        daily: daily?,
        stable: asset.is_stable(),
    });
    cache
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(asset, (Instant::now(), series.clone()));
    Ok(series)
}

/// A chart's period.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ChartRange {
    Day,
    Week,
    Month,
    Year,
    /// All available history.
    All,
}

impl ChartRange {
    /// "1d", "7d", "30d", "1y", "all".
    pub fn parse(range: &str) -> Option<Self> {
        Some(match range {
            "1d" => ChartRange::Day,
            "7d" => ChartRange::Week,
            "30d" => ChartRange::Month,
            "1y" => ChartRange::Year,
            "all" => ChartRange::All,
            _ => return None,
        })
    }

    /// Duration covered, in seconds; `None` for the whole history.
    pub fn span(self) -> Option<i64> {
        match self {
            ChartRange::Day => Some(DAY),
            ChartRange::Week => Some(7 * DAY),
            ChartRange::Month => Some(30 * DAY),
            ChartRange::Year => Some(365 * DAY),
            ChartRange::All => None,
        }
    }

    /// Step between two points (candles, or samples of a portfolio value); for a
    /// portfolio's whole history, see `step_for_span`.
    pub fn step(self) -> i64 {
        match self {
            ChartRange::Day => 15 * 60,
            ChartRange::Week => HOUR,
            ChartRange::Month => 4 * HOUR,
            ChartRange::Year | ChartRange::All => DAY,
        }
    }

    /// Binance interval matching `step`.
    fn interval(self) -> &'static str {
        match self {
            ChartRange::Day => "15m",
            ChartRange::Week => "1h",
            ChartRange::Month => "4h",
            ChartRange::Year | ChartRange::All => "1d",
        }
    }
}

/// Sampling step for an arbitrary duration (the "all" period): the finest of the
/// other periods' steps that gives at most 800 points, one day beyond that.
pub fn step_for_span(span: i64) -> i64 {
    [15 * 60, HOUR, 4 * HOUR]
        .into_iter()
        .find(|step| span / step <= 800)
        .unwrap_or(DAY)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Points of a chart: the open price of each candle, then the latest price (current
/// close) at the present time.
fn chart_points(candles: &[Candle], now: i64) -> Vec<(i64, f64)> {
    let mut points: Vec<(i64, f64)> = candles.iter().map(|c| (c.open_time, c.open)).collect();
    if let Some(last) = candles.last() {
        points.push((now.max(last.open_time), last.close));
    }
    points
}

/// Price chart of `asset` over the period (a series identical for everyone, see the
/// header); "all": daily candles since listing. Cache: 2 minutes for 24 h, 10
/// minutes otherwise.
pub fn chart(asset: Asset, range: ChartRange) -> Result<Arc<Vec<(i64, f64)>>> {
    ensure!(asset != Asset::Usd, "pas de courbe pour un dollar stable");
    if range == ChartRange::All {
        return Ok(Arc::new(chart_points(&series(asset)?.daily, unix_now())));
    }
    type ChartCache = Mutex<HashMap<(Asset, ChartRange), (Instant, Arc<Vec<(i64, f64)>>)>>;
    static CACHE: OnceLock<ChartCache> = OnceLock::new();
    let ttl = if range == ChartRange::Day {
        Duration::from_secs(120)
    } else {
        CACHE_TTL
    };
    let cache = CACHE.get_or_init(Default::default);
    if let Some((fetched, points)) = cache
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&(asset, range))
    {
        if fetched.elapsed() < ttl {
            return Ok(points.clone());
        }
    }
    let limit = (range.span().unwrap_or(DAY) / range.step()) as usize;
    let points = Arc::new(chart_points(
        &fetch_klines(asset, range.interval(), limit, None)?,
        unix_now(),
    ));
    cache
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert((asset, range), (Instant::now(), points.clone()));
    Ok(points)
}

/// Absolute dollar value of a signed amount in the smallest unit (`decimals`
/// decimals), at the price at the given time.
pub fn usd_value(
    series: &PriceSeries,
    amount_minor: i128,
    decimals: i32,
    timestamp: Option<i64>,
) -> Option<f64> {
    let price = series.usd_at(timestamp)?;
    Some(amount_minor.unsigned_abs() as f64 / 10f64.powi(decimals) * price)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candle(open_time: i64, open: f64, close: f64) -> Candle {
        Candle {
            open_time,
            open,
            close,
        }
    }

    /// Interpolation within the candle containing the time; hourly before daily; before
    /// the series: nothing; after: last close; pending: latest price.
    #[test]
    fn price_is_read_from_the_candle_containing_the_instant() {
        let series = PriceSeries {
            hourly: vec![
                candle(10 * DAY, 100.0, 110.0),
                candle(10 * DAY + HOUR, 110.0, 90.0),
            ],
            daily: vec![
                candle(8 * DAY, 50.0, 60.0),
                candle(9 * DAY, 60.0, 100.0),
                candle(10 * DAY, 100.0, 90.0),
            ],
            stable: false,
        };
        assert_eq!(series.usd_at(Some(10 * DAY)), Some(100.0));
        assert_eq!(series.usd_at(Some(10 * DAY + HOUR / 2)), Some(105.0));
        assert_eq!(series.usd_at(Some(10 * DAY + HOUR + HOUR / 4)), Some(105.0));
        assert_eq!(
            series.usd_at(Some(9 * DAY + DAY / 4)),
            Some(70.0),
            "avant les bougies horaires : journalier"
        );
        assert_eq!(series.usd_at(Some(7 * DAY)), None, "avant toute donnée");
        assert_eq!(
            series.usd_at(Some(10 * DAY + 5 * HOUR)),
            Some(90.0),
            "après la dernière bougie : dernière clôture"
        );
        assert_eq!(series.usd_at(None), Some(90.0), "en attente : dernier prix");
        let amount = usd_value(&series, -150_000_000, 8, Some(10 * DAY)).unwrap();
        assert!((amount - 150.0).abs() < 1e-9, "valeur absolue : {amount}");
    }

    /// A gap in the series does not produce an invented price, except for a stablecoin,
    /// counted at $1.
    #[test]
    fn gaps_in_a_series_give_no_price() {
        let candles = [candle(0, 1.0, 2.0), candle(3 * HOUR, 3.0, 4.0)];
        assert_eq!(price_in(&candles, HOUR, HOUR + 1), None);
        assert_eq!(price_in(&candles, HOUR, 3 * HOUR), Some(3.0));
        let usdc = |stable| PriceSeries {
            hourly: vec![],
            daily: vec![candle(0, 0.99, 1.0), candle(10 * DAY, 1.0, 1.01)],
            stable,
        };
        assert_eq!(
            usdc(true).usd_at(Some(DAY / 2)),
            Some(0.995),
            "prix réel quand il existe"
        );
        assert_eq!(usdc(true).usd_at(Some(5 * DAY)), Some(1.0), "trou : 1 $");
        assert_eq!(usdc(false).usd_at(Some(5 * DAY)), None);
    }

    /// "All": the finest step possible under 800 points, one day beyond that.
    #[test]
    fn all_history_range_is_parsed_and_sampled() {
        assert_eq!(ChartRange::parse("all"), Some(ChartRange::All));
        assert_eq!(ChartRange::All.span(), None);
        assert_eq!(
            ChartRange::parse("1y").and_then(ChartRange::span),
            Some(365 * DAY)
        );
        assert_eq!(ChartRange::parse("5y"), None);
        assert_eq!(step_for_span(2 * DAY), 15 * 60);
        assert_eq!(step_for_span(21 * DAY), HOUR);
        assert_eq!(step_for_span(120 * DAY), 4 * HOUR);
        assert_eq!(step_for_span(3000 * DAY), DAY);
    }

    /// Real Binance format; inconsistent series refused.
    #[test]
    fn klines_are_parsed_and_checked() {
        let body = r#"[[1758844800000,"84100.00000000","84500.1","83900.0","84163.05000000","1.0",1758848399999,"0",1,"0","0","0"],
                       [1758848400000,"84163.05","84200","84000","84000.5","1.0",1758851999999,"0",1,"0","0","0"]]"#;
        let candles = parse_klines(body).unwrap();
        assert_eq!(
            candles,
            vec![
                candle(1_758_844_800, 84_100.0, 84_163.05),
                candle(1_758_848_400, 84_163.05, 84_000.5)
            ]
        );
        assert!(
            parse_klines(r#"[[2000,"1","1","1","1"],[1000,"1","1","1","1"]]"#).is_err(),
            "dates non croissantes"
        );
        assert!(
            parse_klines(r#"[[1000,"1","1","1","-3"]]"#).is_err(),
            "prix négatif"
        );
        assert!(
            parse_klines(r#"[[1000,"1"]]"#).is_err(),
            "bougie incomplète"
        );
        assert!(parse_klines(r#"{"code":-1121,"msg":"Invalid symbol."}"#).is_err());
    }

    /// Real Kraken format (response recorded from the API, truncated); service errors
    /// and inconsistent series refused.
    #[test]
    fn jupiter_chart_is_parsed_and_checked() {
        // Real excerpt (AAPLx, 2026-10-10): oldest to newest.
        let body = r#"{"candles":[{"time":1791622800,"open":335.5460055405212,"high":336.2,"low":335.2,"close":335.52725591416214,"volume":17859.1},{"time":1791626400,"open":335.52725591416214,"high":336.2,"low":335.2,"close":335.5189133638771,"volume":150.2}]}"#;
        assert_eq!(
            parse_jupiter_chart(body).unwrap(),
            vec![
                candle(1_791_622_800, 335.5460055405212, 335.52725591416214),
                candle(1_791_626_400, 335.52725591416214, 335.5189133638771)
            ]
        );
        assert!(parse_jupiter_chart(r#"{"candles":[]}"#).is_err(), "vide");
        assert!(parse_jupiter_chart(r#"{"error":"not found"}"#).is_err());
        assert!(
            parse_jupiter_chart(
                r#"{"candles":[{"time":2,"open":1,"close":1},{"time":1,"open":1,"close":1}]}"#
            )
            .is_err(),
            "désordre"
        );
        assert!(
            parse_jupiter_chart(r#"{"candles":[{"time":1,"open":1,"close":-1}]}"#).is_err(),
            "prix négatif"
        );
    }

    #[test]
    fn gecko_ohlcv_is_parsed_and_checked() {
        // Real excerpt (AAPLx/USDC, 2026-10-10): newest first.
        let body = r#"{"data":{"attributes":{"ohlcv_list":[[1791590400,340.3661461621266,340.3661461621266,334.9319465990773,335.70110571415927,30710.65],[1791504000,338.644787845157,345.02710016742776,328.74819935392355,340.3661461621266,161181.43]]}}}"#;
        assert_eq!(
            parse_gecko_ohlcv(body).unwrap(),
            vec![
                candle(1_791_504_000, 338.644787845157, 340.3661461621266),
                candle(1_791_590_400, 340.3661461621266, 335.70110571415927)
            ]
        );
        assert!(parse_gecko_ohlcv(r#"{"errors":[{"status":"429"}]}"#).is_err());
        assert!(
            parse_gecko_ohlcv(r#"{"data":{"attributes":{"ohlcv_list":[[1,1,1,1,0,1]]}}}"#).is_err(),
            "prix nul"
        );
        assert!(
            parse_gecko_ohlcv(
                r#"{"data":{"attributes":{"ohlcv_list":[[1,1,1,1,1,1],[2,1,1,1,1,1]]}}}"#
            )
            .is_err(),
            "désordre"
        );
        assert_eq!(
            price_asset("TSLAX"),
            Some(Asset::Solana("XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB"))
        );
        assert_eq!(
            price_asset("BRK.BX"),
            Some(Asset::Solana("Xs6B6zawENwAbWVi7w92rjazLuAr5Az59qgWKcNb45x"))
        );
        assert_eq!(price_asset("BTC"), Some(Asset::Btc));
        assert_eq!(price_asset("TSLA"), None);
    }

    /// Real charts for a tokenized share (GeckoTerminal): each period gives an ordered
    /// series, with a latest price close to Jupiter's price per displayed unit.
    /// `cargo test -- --ignored real_xstock_charts --nocapture`
    #[test]
    #[ignore]
    fn real_xstock_charts() {
        let asset = price_asset("AAPLX").unwrap();
        let Asset::Solana(mint) = asset else {
            panic!("action attendue")
        };
        let jupiter = crate::price_rpc::jupiter_stock_prices(&[mint]).unwrap()[0].usd;
        for range in [
            ChartRange::Day,
            ChartRange::Week,
            ChartRange::Month,
            ChartRange::Year,
            ChartRange::All,
        ] {
            let points = chart(asset, range).unwrap();
            let last = points.last().unwrap().1;
            println!(
                "{range:?} : {} points, dernier {last:.2} $ (Jupiter {jupiter:.2} $)",
                points.len()
            );
            assert!(
                points.len() >= 2 && points.windows(2).all(|w| w[0].0 < w[1].0),
                "{range:?}"
            );
            assert!(
                (last / jupiter - 1.0).abs() < 0.03,
                "{range:?} : {last} contre {jupiter}"
            );
            std::thread::sleep(std::time::Duration::from_millis(2500));
        }
        assert!(
            series(asset)
                .unwrap()
                .usd_at(Some(unix_now() - 3 * DAY))
                .is_some(),
            "prix d'il y a 3 jours"
        );
    }

    #[test]
    fn kraken_ohlc_is_parsed_and_checked() {
        let body = r#"{"error":[],"result":{"VVVUSD":[[1740614400,"4.214","4.244","3.992","4.000","4.165","4296.32432",35],
                       [1740700800,"3.894","4.079","3.664","4.068","3.899","5838.94705",66]],"last":1790726400}}"#;
        assert_eq!(
            parse_kraken_ohlc(body).unwrap(),
            vec![
                candle(1_740_614_400, 4.214, 4.0),
                candle(1_740_700_800, 3.894, 4.068)
            ]
        );
        assert!(parse_kraken_ohlc(r#"{"error":["EQuery:Unknown asset pair"]}"#).is_err());
        assert!(parse_kraken_ohlc(
            r#"{"error":[],"result":{"X":[[2,"1","1","1","1"],[1,"1","1","1","1"]],"last":0}}"#
        )
        .is_err());
        assert!(
            parse_kraken_ohlc(r#"{"error":[],"result":{"X":[[1,"1","1","1","0"]],"last":0}}"#)
                .is_err()
        );
    }

    /// Dollar stablecoin with no pair: $1 at all times, no request, no chart.
    #[test]
    fn stable_dollar_is_worth_one_dollar() {
        let usd = series(Asset::Usd).unwrap();
        assert_eq!(
            (usd.usd_at(Some(0)), usd.usd_at(None)),
            (Some(1.0), Some(1.0))
        );
        assert_eq!(price_asset("USDT"), Some(Asset::Usd));
        assert!(chart(Asset::Usd, ChartRange::Month).is_err());
    }

    /// Real Kraken (VVV): daily since listing (2025-02-27), recent hourly, charts for
    /// each period, price consistent with CoinGecko.
    /// `cargo test -- --ignored real_kraken_series --nocapture`
    #[test]
    #[ignore]
    fn real_kraken_series() {
        let vvv = price_asset("VVV").unwrap();
        let s = series(vvv).unwrap();
        assert_eq!(
            s.daily[0].open_time, 1_740_614_400,
            "première bougie = cotation"
        );
        assert!(unix_now() - s.daily.last().unwrap().open_time < DAY);
        assert!(s.hourly.len() >= 700 && unix_now() - s.hourly.last().unwrap().open_time < HOUR);
        for range in [
            ChartRange::Day,
            ChartRange::Week,
            ChartRange::Month,
            ChartRange::Year,
            ChartRange::All,
        ] {
            let points = chart(vvv, range).unwrap();
            let expected = (range.span().unwrap_or(DAY) / range.step()) as usize;
            println!(
                "{range:?} : {} points, de {} à {}",
                points.len(),
                points[0].0,
                points.last().unwrap().0
            );
            if range != ChartRange::All {
                assert_eq!(points.len(), expected + 1, "{range:?}");
            }
        }
        let gecko = crate::price_rpc::PriceRpc::new().get_market_data().unwrap();
        let reference = gecko
            .iter()
            .find(|c| c.id == "venice-token")
            .unwrap()
            .price_usd;
        let now = s.usd_at(None).unwrap();
        println!("VVV : {now} $ (CoinGecko {reference} $)");
        assert!((now / reference - 1.0).abs() < 0.05);
    }

    /// Live service: the 4 assets, hourly series (~41 days) and daily series (since
    /// listing, with no gaps or duplicates between pages, up to today), prices
    /// consistent with CoinGecko's current price (another source) to within a few %;
    /// USDC ≈ $1.
    #[test]
    #[ignore]
    fn real_price_series_match_an_independent_source() {
        let current = crate::price_rpc::PriceRpc::new().get_prices().unwrap();
        let listed = [
            (Asset::Btc, 1_502_928_000),
            (Asset::Eth, 1_502_928_000),
            (Asset::Sol, 1_597_104_000),
            (Asset::Usdc, 1_544_832_000),
        ];
        for (asset, reference) in [
            (Asset::Btc, current.btc_usd),
            (Asset::Eth, current.eth_usd),
            (Asset::Sol, current.sol_usd),
            (Asset::Usdc, 1.0),
        ] {
            let s = series(asset).unwrap();
            assert_eq!(s.hourly.len(), 1000);
            let first_day = listed.iter().find(|(a, _)| *a == asset).unwrap().1;
            assert_eq!(
                s.daily[0].open_time, first_day,
                "{asset:?} : première bougie = cotation"
            );
            assert!(
                unix_now() - s.daily.last().unwrap().open_time < DAY,
                "{asset:?} : jusqu'à aujourd'hui"
            );
            let gaps: Vec<_> = s
                .daily
                .windows(2)
                .filter(|w| w[1].open_time - w[0].open_time != DAY)
                .map(|w| (w[0].open_time, w[1].open_time))
                .collect();
            let expected_gaps = if asset == Asset::Usdc {
                vec![(1_664_150_400, 1_678_492_800)]
            } else {
                vec![]
            };
            assert_eq!(gaps, expected_gaps, "{asset:?} : bougies consécutives");
            let chart = chart(asset, ChartRange::All).unwrap();
            assert_eq!(chart.len(), s.daily.len() + 1);
            let now = s.usd_at(None).unwrap();
            println!("{asset:?} : {now} $ (CoinGecko {reference} $), horaire depuis {}, journalier depuis {}", s.hourly[0].open_time, s.daily[0].open_time);
            assert!(
                (now / reference - 1.0).abs() < 0.03,
                "{asset:?} {now} vs {reference}"
            );
        }
    }
}
