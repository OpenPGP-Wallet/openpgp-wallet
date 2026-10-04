//! Prix historiques en dollars, pour afficher la valeur d'une transaction AU
//! MOMENT où elle a eu lieu. Purement informatif : ne joue aucun rôle dans la
//! construction ou la signature d'une transaction.
//!
//! Source : l'API publique de données de marché de Binance
//! (`data-api.binance.vision`, sans clé), bougies horaires (≈ 41 derniers
//! jours) et journalières (depuis la cotation de l'actif : août 2017 pour
//! BTC et ETH), paires en USDT (≈ 1 $).
//! Crypto absente de Binance (VVV) : l'API publique OHLC de Kraken (sans clé,
//! en dollars), 720 bougies au plus par intervalle (≈ 2 ans en journalier :
//! tout l'historique de VVV, coté depuis février 2025).
//! CoinGecko, déjà utilisé pour le prix courant, a été écarté ici : sa limite
//! gratuite a refusé le 3ᵉ appel consécutif lors des essais, alors qu'il en
//! faut plusieurs pour l'historique.
//!
//! Confidentialité : les requêtes demandent des SÉRIES complètes, identiques
//! pour tout le monde — jamais le prix à l'heure précise d'une transaction,
//! qui révélerait au fournisseur (avec l'adresse IP) les instants des
//! transactions de l'utilisateur, et donc les transactions elles-mêmes. La
//! valeur de chaque transaction est calculée ici, localement.

use anyhow::{anyhow, ensure, Context, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const KLINES_URL: &str = "https://data-api.binance.vision/api/v3/klines";
const KRAKEN_OHLC_URL: &str = "https://api.kraken.com/0/public/OHLC";
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
/// Au-delà, les séries sont relues (la dernière bougie horaire avance).
const CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Asset {
    Btc,
    Eth,
    Sol,
    Usdc,
    /// Taux de change : dollars pour 1 euro (paire EUR/USDT, cotée depuis le
    /// 03/01/2020), pour afficher les montants en euros au taux de chaque date.
    Eur,
    /// Autre crypto : paire USDT de Binance (liste blanche, voir `price_asset`).
    Pair(&'static str),
    /// Crypto absente de Binance : paire en dollars de Kraken.
    Kraken(&'static str),
    /// Dollar stable sans paire de marché (USDT, monnaie de cotation des paires
    /// Binance ; USDG) : 1 $, pour la valeur d'un solde ou d'une transaction.
    /// Pas de courbe.
    Usd,
}

/// Série de prix d'une crypto de l'app, par son symbole (`None` : aucune
/// source de prix).
pub fn price_asset(symbol: &str) -> Option<Asset> {
    Some(match symbol {
        "BTC" => Asset::Btc,
        "ETH" => Asset::Eth,
        "SOL" => Asset::Sol,
        "USDC" => Asset::Usdc,
        "EUR" => Asset::Eur,
        "BNB" => Asset::Pair("BNBUSDT"),
        "AVAX" => Asset::Pair("AVAXUSDT"),
        "POL" => Asset::Pair("POLUSDT"),
        "HYPE" => Asset::Pair("HYPEUSDT"),
        "ZEC" => Asset::Pair("ZECUSDT"),
        "DOGE" => Asset::Pair("DOGEUSDT"),
        "TRX" => Asset::Pair("TRXUSDT"),
        "XRP" => Asset::Pair("XRPUSDT"),
        "XLM" => Asset::Pair("XLMUSDT"),
        "NEAR" => Asset::Pair("NEARUSDT"),
        "LINK" => Asset::Pair("LINKUSDT"),
        "DAI" => Asset::Pair("DAIUSDT"),
        "USDE" => Asset::Pair("USDEUSDT"),
        "UNI" => Asset::Pair("UNIUSDT"),
        "XAUT" => Asset::Pair("XAUTUSDT"),
        "ONDO" => Asset::Pair("ONDOUSDT"),
        "FET" => Asset::Pair("FETUSDT"),
        "GNO" => Asset::Pair("GNOUSDT"),
        "ARB" => Asset::Pair("ARBUSDT"),
        "ASTER" => Asset::Pair("ASTERUSDT"),
        "RENDER" => Asset::Pair("RENDERUSDT"),
        "VVV" => Asset::Kraken("VVVUSD"),
        // Monero : retiré de Binance en 2024, dont l'API renvoie encore un
        // cours figé (118,70 $ le 03/10/2026, contre 553 $ chez Kraken).
        "XMR" => Asset::Kraken("XMRUSD"),
        "USDT" | "USDG" => Asset::Usd,
        // EURC suit l'euro : sa courbe est celle d'EUR/USDT.
        "EURC" => Asset::Eur,
        _ => return None,
    })
}

impl Asset {
    /// Paire Binance (`None` : autre source, ou aucune).
    fn binance_symbol(self) -> Option<&'static str> {
        Some(match self {
            Asset::Btc => "BTCUSDT",
            Asset::Eth => "ETHUSDT",
            Asset::Sol => "SOLUSDT",
            Asset::Usdc => "USDCUSDT",
            Asset::Eur => "EURUSDT",
            Asset::Pair(pair) => pair,
            Asset::Kraken(_) | Asset::Usd => return None,
        })
    }

    /// Compté à 1 $ là où sa série n'a pas de prix (voir `PriceSeries::stable`).
    fn is_stable(self) -> bool {
        matches!(self, Asset::Usdc | Asset::Usd)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Candle {
    /// Début de la bougie, en secondes Unix.
    open_time: i64,
    open: f64,
    close: f64,
}

/// Bougies horaires et journalières d'un actif, triées par date.
#[derive(Debug)]
pub struct PriceSeries {
    hourly: Vec<Candle>,
    daily: Vec<Candle>,
    /// Stablecoin (USDC) : 1 $ là où la série n'a pas de prix. Binance a
    /// retiré la paire USDC/USDT du 26/09/2022 au 11/03/2023 (constaté sur
    /// l'API) ; sans cela, toute valeur de portefeuille contenant de l'USDC
    /// disparaissait de la courbe sur cette période.
    stable: bool,
}

impl PriceSeries {
    /// Prix en dollars à l'instant `timestamp` (secondes Unix) : bougie
    /// horaire si l'instant est couvert, sinon journalière, interpolé entre
    /// ouverture et clôture. `None` (transaction en attente) : dernier prix.
    /// `None` en retour si l'instant précède toutes les bougies connues.
    pub fn usd_at(&self, timestamp: Option<i64>) -> Option<f64> {
        let Some(t) = timestamp else {
            return self.hourly.last().or(self.daily.last()).map(|c| c.close).or(self.stable.then_some(1.0));
        };
        price_in(&self.hourly, HOUR, t).or_else(|| price_in(&self.daily, DAY, t)).or(self.stable.then_some(1.0))
    }
}

/// Prix à l'instant `t` dans des bougies de durée `span` : interpolation
/// linéaire entre l'ouverture et la clôture de la bougie qui contient `t` ;
/// après la dernière bougie (horloge en avance), sa clôture.
fn price_in(candles: &[Candle], span: i64, t: i64) -> Option<f64> {
    let first = candles.first()?;
    if t < first.open_time {
        return None;
    }
    let index = candles.partition_point(|c| c.open_time <= t) - 1;
    let candle = candles[index];
    let elapsed = t - candle.open_time;
    if elapsed >= span {
        // Trou dans la série ou instant postérieur à la dernière bougie.
        return (index + 1 == candles.len()).then_some(candle.close);
    }
    Some(candle.open + (candle.close - candle.open) * elapsed as f64 / span as f64)
}

/// Réponse `klines` de Binance : `[[ouverture_ms, "open", "high", "low",
/// "close", ...], ...]`. Refus de toute série incohérente (dates non
/// croissantes, prix non positifs) plutôt que d'afficher une valeur fausse.
fn parse_klines(body: &str) -> Result<Vec<Candle>> {
    let rows: Vec<Vec<serde_json::Value>> = serde_json::from_str(body).context("réponse de prix illisible")?;
    let mut candles = Vec::with_capacity(rows.len());
    for row in rows {
        let open_ms = row.first().and_then(serde_json::Value::as_i64).ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
        let price = |i: usize| -> Result<f64> {
            let value: f64 = row
                .get(i)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
            ensure!(value.is_finite() && value > 0.0, "prix invalide dans la série");
            Ok(value)
        };
        candles.push(Candle { open_time: open_ms.div_euclid(1000), open: price(1)?, close: price(4)? });
    }
    ensure!(candles.windows(2).all(|w| w[0].open_time < w[1].open_time), "série de prix non ordonnée");
    Ok(candles)
}

/// Réponse OHLC de Kraken : `{"error": [], "result": {"<paire>": [[ouverture_s,
/// "open", "high", "low", "close", "vwap", "volume", nombre], ...], "last": n}}`.
/// Mêmes refus que `parse_klines`.
fn parse_kraken_ohlc(body: &str) -> Result<Vec<Candle>> {
    let value: serde_json::Value = serde_json::from_str(body).context("réponse de prix illisible")?;
    if let Some(errors) = value.get("error").and_then(serde_json::Value::as_array) {
        ensure!(errors.is_empty(), "le service de prix a refusé la demande : {}", serde_json::Value::Array(errors.clone()));
    }
    let rows = value
        .get("result")
        .and_then(serde_json::Value::as_object)
        .and_then(|result| result.iter().find(|(key, _)| *key != "last"))
        .and_then(|(_, rows)| rows.as_array())
        .ok_or_else(|| anyhow!("réponse de prix illisible"))?;
    let mut candles = Vec::with_capacity(rows.len());
    for row in rows {
        let open_time = row.get(0).and_then(serde_json::Value::as_i64).ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
        let price = |i: usize| -> Result<f64> {
            let value: f64 = row
                .get(i)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow!("bougie de prix mal formée"))?;
            ensure!(value.is_finite() && value > 0.0, "prix invalide dans la série");
            Ok(value)
        };
        candles.push(Candle { open_time, open: price(1)?, close: price(4)? });
    }
    ensure!(candles.windows(2).all(|w| w[0].open_time < w[1].open_time), "série de prix non ordonnée");
    Ok(candles)
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

/// Bougies `interval` de `asset` : les `limit` dernières, ou les `limit`
/// premières à partir de `start` (secondes Unix). Au plus 1000 par requête.
fn fetch_klines(asset: Asset, interval: &str, limit: usize, start: Option<i64>) -> Result<Vec<Candle>> {
    let symbol = match asset {
        Asset::Kraken(pair) => return fetch_kraken(pair, interval, limit, start),
        Asset::Usd => anyhow::bail!("pas de série de prix pour un dollar stable"),
        other => other.binance_symbol().expect("paire Binance"),
    };
    let mut query = vec![("symbol", symbol.to_string()), ("interval", interval.to_string()), ("limit", limit.to_string())];
    if let Some(start) = start {
        query.push(("startTime", (start * 1000).to_string()));
    }
    let response = shared_client()
        .get(KLINES_URL)
        .query(&query)
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(response.status().is_success(), "le service de prix a répondu {}", response.status());
    parse_klines(&response.text().context("réponse de prix illisible")?)
}

/// Bougies Kraken de `pair`, mêmes paramètres que `fetch_klines` : Kraken
/// donne toujours ses 720 dernières bougies (ou moins) ; les `limit`
/// dernières sont gardées, ou les `limit` premières à partir de `start`.
fn fetch_kraken(pair: &str, interval: &str, limit: usize, start: Option<i64>) -> Result<Vec<Candle>> {
    let minutes = match interval {
        "15m" => 15,
        "1h" => 60,
        "4h" => 240,
        "1d" => 1440,
        other => anyhow::bail!("intervalle non pris en charge : {other}"),
    };
    let response = shared_client()
        .get(KRAKEN_OHLC_URL)
        .query(&[("pair", pair.to_string()), ("interval", minutes.to_string())])
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(response.status().is_success(), "le service de prix a répondu {}", response.status());
    let candles = parse_kraken_ohlc(&response.text().context("réponse de prix illisible")?)?;
    Ok(match start {
        Some(start) => candles.into_iter().filter(|c| c.open_time >= start).take(limit).collect(),
        None => candles[candles.len().saturating_sub(limit)..].to_vec(),
    })
}

/// Toutes les bougies journalières depuis la cotation de `asset` : pages de
/// 1000 à partir de l'origine (≈ 4 requêtes pour Bitcoin).
fn fetch_daily_history(asset: Asset) -> Result<Vec<Candle>> {
    const PAGE: usize = 1000;
    let mut candles: Vec<Candle> = Vec::new();
    loop {
        let start = candles.last().map_or(0, |c| c.open_time + DAY);
        let page = fetch_klines(asset, "1d", PAGE, Some(start))?;
        let full = page.len() == PAGE;
        candles.extend(page);
        // 30 pages : plus de 80 ans de bougies, garde-fou contre une boucle sans fin.
        if !full || candles.len() >= 30 * PAGE {
            break;
        }
    }
    ensure!(candles.windows(2).all(|w| w[0].open_time < w[1].open_time), "série de prix non ordonnée");
    Ok(candles)
}

/// Séries de prix de `asset` (cache de 10 minutes ; horaire et journalier lus
/// en parallèle au premier appel). Un échec n'est pas mis en cache : réessayé
/// au suivant.
pub fn series(asset: Asset) -> Result<Arc<PriceSeries>> {
    /// Séries par actif, avec l'instant où elles ont été lues.
    type Cache = Mutex<HashMap<Asset, (Instant, Arc<PriceSeries>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if asset == Asset::Usd {
        return Ok(Arc::new(PriceSeries { hourly: Vec::new(), daily: Vec::new(), stable: true }));
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
            hourly.join().expect("le fil des prix horaires ne doit pas paniquer"),
            daily.join().expect("le fil des prix journaliers ne doit pas paniquer"),
        )
    });
    let series = Arc::new(PriceSeries { hourly: hourly?, daily: daily?, stable: asset.is_stable() });
    cache.lock().unwrap_or_else(|p| p.into_inner()).insert(asset, (Instant::now(), series.clone()));
    Ok(series)
}

/// Période d'un graphique.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ChartRange {
    Day,
    Week,
    Month,
    Year,
    /// Tout l'historique disponible.
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

    /// Durée couverte, en secondes ; `None` pour tout l'historique.
    pub fn span(self) -> Option<i64> {
        match self {
            ChartRange::Day => Some(DAY),
            ChartRange::Week => Some(7 * DAY),
            ChartRange::Month => Some(30 * DAY),
            ChartRange::Year => Some(365 * DAY),
            ChartRange::All => None,
        }
    }

    /// Pas entre deux points (bougies, ou échantillons d'une valeur de
    /// portefeuille) ; pour tout l'historique d'un portefeuille, voir
    /// `step_for_span`.
    pub fn step(self) -> i64 {
        match self {
            ChartRange::Day => 15 * 60,
            ChartRange::Week => HOUR,
            ChartRange::Month => 4 * HOUR,
            ChartRange::Year | ChartRange::All => DAY,
        }
    }

    /// Intervalle Binance correspondant à `step`.
    fn interval(self) -> &'static str {
        match self {
            ChartRange::Day => "15m",
            ChartRange::Week => "1h",
            ChartRange::Month => "4h",
            ChartRange::Year | ChartRange::All => "1d",
        }
    }
}

/// Pas d'échantillonnage d'une durée quelconque (période « tout ») : le plus
/// fin des pas des autres périodes qui donne au plus 800 points, un jour au-delà.
pub fn step_for_span(span: i64) -> i64 {
    [15 * 60, HOUR, 4 * HOUR].into_iter().find(|step| span / step <= 800).unwrap_or(DAY)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Points d'une courbe : prix d'ouverture de chaque bougie, puis le dernier
/// prix (clôture courante) à l'instant présent.
fn chart_points(candles: &[Candle], now: i64) -> Vec<(i64, f64)> {
    let mut points: Vec<(i64, f64)> = candles.iter().map(|c| (c.open_time, c.open)).collect();
    if let Some(last) = candles.last() {
        points.push((now.max(last.open_time), last.close));
    }
    points
}

/// Courbe de prix de `asset` sur la période (série identique pour tout le
/// monde, voir l'en-tête) ; « tout » : les bougies journalières depuis la
/// cotation. Cache : 2 minutes sur 24 h, 10 minutes sinon.
pub fn chart(asset: Asset, range: ChartRange) -> Result<Arc<Vec<(i64, f64)>>> {
    ensure!(asset != Asset::Usd, "pas de courbe pour un dollar stable");
    if range == ChartRange::All {
        return Ok(Arc::new(chart_points(&series(asset)?.daily, unix_now())));
    }
    type ChartCache = Mutex<HashMap<(Asset, ChartRange), (Instant, Arc<Vec<(i64, f64)>>)>>;
    static CACHE: OnceLock<ChartCache> = OnceLock::new();
    let ttl = if range == ChartRange::Day { Duration::from_secs(120) } else { CACHE_TTL };
    let cache = CACHE.get_or_init(Default::default);
    if let Some((fetched, points)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&(asset, range)) {
        if fetched.elapsed() < ttl {
            return Ok(points.clone());
        }
    }
    let limit = (range.span().unwrap_or(DAY) / range.step()) as usize;
    let points = Arc::new(chart_points(&fetch_klines(asset, range.interval(), limit, None)?, unix_now()));
    cache.lock().unwrap_or_else(|p| p.into_inner()).insert((asset, range), (Instant::now(), points.clone()));
    Ok(points)
}

/// Valeur absolue en dollars d'un montant signé en plus petite unité
/// (`decimals` décimales), au prix de l'instant donné.
pub fn usd_value(series: &PriceSeries, amount_minor: i128, decimals: i32, timestamp: Option<i64>) -> Option<f64> {
    let price = series.usd_at(timestamp)?;
    Some(amount_minor.unsigned_abs() as f64 / 10f64.powi(decimals) * price)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candle(open_time: i64, open: f64, close: f64) -> Candle {
        Candle { open_time, open, close }
    }

    /// Interpolation dans la bougie qui contient l'instant ; horaire avant
    /// journalier ; avant la série : rien ; après : dernière clôture ; en
    /// attente : dernier prix.
    #[test]
    fn price_is_read_from_the_candle_containing_the_instant() {
        let series = PriceSeries {
            hourly: vec![candle(10 * DAY, 100.0, 110.0), candle(10 * DAY + HOUR, 110.0, 90.0)],
            daily: vec![candle(8 * DAY, 50.0, 60.0), candle(9 * DAY, 60.0, 100.0), candle(10 * DAY, 100.0, 90.0)],
            stable: false,
        };
        assert_eq!(series.usd_at(Some(10 * DAY)), Some(100.0));
        assert_eq!(series.usd_at(Some(10 * DAY + HOUR / 2)), Some(105.0));
        assert_eq!(series.usd_at(Some(10 * DAY + HOUR + HOUR / 4)), Some(105.0));
        assert_eq!(series.usd_at(Some(9 * DAY + DAY / 4)), Some(70.0), "avant les bougies horaires : journalier");
        assert_eq!(series.usd_at(Some(7 * DAY)), None, "avant toute donnée");
        assert_eq!(series.usd_at(Some(10 * DAY + 5 * HOUR)), Some(90.0), "après la dernière bougie : dernière clôture");
        assert_eq!(series.usd_at(None), Some(90.0), "en attente : dernier prix");
        let amount = usd_value(&series, -150_000_000, 8, Some(10 * DAY)).unwrap();
        assert!((amount - 150.0).abs() < 1e-9, "valeur absolue : {amount}");
    }

    /// Un trou dans la série ne donne pas un prix inventé — sauf pour un
    /// stablecoin, compté à 1 $.
    #[test]
    fn gaps_in_a_series_give_no_price() {
        let candles = [candle(0, 1.0, 2.0), candle(3 * HOUR, 3.0, 4.0)];
        assert_eq!(price_in(&candles, HOUR, HOUR + 1), None);
        assert_eq!(price_in(&candles, HOUR, 3 * HOUR), Some(3.0));
        let usdc = |stable| PriceSeries { hourly: vec![], daily: vec![candle(0, 0.99, 1.0), candle(10 * DAY, 1.0, 1.01)], stable };
        assert_eq!(usdc(true).usd_at(Some(DAY / 2)), Some(0.995), "prix réel quand il existe");
        assert_eq!(usdc(true).usd_at(Some(5 * DAY)), Some(1.0), "trou : 1 $");
        assert_eq!(usdc(false).usd_at(Some(5 * DAY)), None);
    }

    /// « Tout » : pas le plus fin possible sous 800 points, un jour au-delà.
    #[test]
    fn all_history_range_is_parsed_and_sampled() {
        assert_eq!(ChartRange::parse("all"), Some(ChartRange::All));
        assert_eq!(ChartRange::All.span(), None);
        assert_eq!(ChartRange::parse("1y").and_then(ChartRange::span), Some(365 * DAY));
        assert_eq!(ChartRange::parse("5y"), None);
        assert_eq!(step_for_span(2 * DAY), 15 * 60);
        assert_eq!(step_for_span(21 * DAY), HOUR);
        assert_eq!(step_for_span(120 * DAY), 4 * HOUR);
        assert_eq!(step_for_span(3000 * DAY), DAY);
    }

    /// Format réel de Binance ; séries incohérentes refusées.
    #[test]
    fn klines_are_parsed_and_checked() {
        let body = r#"[[1758844800000,"84100.00000000","84500.1","83900.0","84163.05000000","1.0",1758848399999,"0",1,"0","0","0"],
                       [1758848400000,"84163.05","84200","84000","84000.5","1.0",1758851999999,"0",1,"0","0","0"]]"#;
        let candles = parse_klines(body).unwrap();
        assert_eq!(candles, vec![candle(1_758_844_800, 84_100.0, 84_163.05), candle(1_758_848_400, 84_163.05, 84_000.5)]);
        assert!(parse_klines(r#"[[2000,"1","1","1","1"],[1000,"1","1","1","1"]]"#).is_err(), "dates non croissantes");
        assert!(parse_klines(r#"[[1000,"1","1","1","-3"]]"#).is_err(), "prix négatif");
        assert!(parse_klines(r#"[[1000,"1"]]"#).is_err(), "bougie incomplète");
        assert!(parse_klines(r#"{"code":-1121,"msg":"Invalid symbol."}"#).is_err());
    }

    /// Format réel de Kraken (réponse relevée sur l'API, tronquée) ; erreur
    /// du service et séries incohérentes refusées.
    #[test]
    fn kraken_ohlc_is_parsed_and_checked() {
        let body = r#"{"error":[],"result":{"VVVUSD":[[1740614400,"4.214","4.244","3.992","4.000","4.165","4296.32432",35],
                       [1740700800,"3.894","4.079","3.664","4.068","3.899","5838.94705",66]],"last":1790726400}}"#;
        assert_eq!(parse_kraken_ohlc(body).unwrap(), vec![candle(1_740_614_400, 4.214, 4.0), candle(1_740_700_800, 3.894, 4.068)]);
        assert!(parse_kraken_ohlc(r#"{"error":["EQuery:Unknown asset pair"]}"#).is_err());
        assert!(parse_kraken_ohlc(r#"{"error":[],"result":{"X":[[2,"1","1","1","1"],[1,"1","1","1","1"]],"last":0}}"#).is_err());
        assert!(parse_kraken_ohlc(r#"{"error":[],"result":{"X":[[1,"1","1","1","0"]],"last":0}}"#).is_err());
    }

    /// Dollar stable sans paire : 1 $ à tout instant, aucune requête, pas de courbe.
    #[test]
    fn stable_dollar_is_worth_one_dollar() {
        let usd = series(Asset::Usd).unwrap();
        assert_eq!((usd.usd_at(Some(0)), usd.usd_at(None)), (Some(1.0), Some(1.0)));
        assert_eq!(price_asset("USDT"), Some(Asset::Usd));
        assert!(chart(Asset::Usd, ChartRange::Month).is_err());
    }

    /// Kraken réel (VVV) : journalier depuis la cotation (27/02/2025), horaire
    /// récent, courbes de chaque période, prix cohérent avec CoinGecko.
    /// `cargo test -- --ignored real_kraken_series --nocapture`
    #[test]
    #[ignore]
    fn real_kraken_series() {
        let vvv = price_asset("VVV").unwrap();
        let s = series(vvv).unwrap();
        assert_eq!(s.daily[0].open_time, 1_740_614_400, "première bougie = cotation");
        assert!(unix_now() - s.daily.last().unwrap().open_time < DAY);
        assert!(s.hourly.len() >= 700 && unix_now() - s.hourly.last().unwrap().open_time < HOUR);
        for range in [ChartRange::Day, ChartRange::Week, ChartRange::Month, ChartRange::Year, ChartRange::All] {
            let points = chart(vvv, range).unwrap();
            let expected = (range.span().unwrap_or(DAY) / range.step()) as usize;
            println!("{range:?} : {} points, de {} à {}", points.len(), points[0].0, points.last().unwrap().0);
            if range != ChartRange::All {
                assert_eq!(points.len(), expected + 1, "{range:?}");
            }
        }
        let gecko = crate::price_rpc::PriceRpc::new().get_market_data().unwrap();
        let reference = gecko.iter().find(|c| c.id == "venice-token").unwrap().price_usd;
        let now = s.usd_at(None).unwrap();
        println!("VVV : {now} $ (CoinGecko {reference} $)");
        assert!((now / reference - 1.0).abs() < 0.05);
    }

    /// Service réel : les 4 actifs, séries horaires (~41 j) et journalières
    /// (depuis la cotation, sans trou ni doublon entre les pages, jusqu'à
    /// aujourd'hui), prix cohérents avec le prix courant de CoinGecko (autre
    /// source) à quelques % près ; USDC ≈ 1 $.
    #[test]
    #[ignore]
    fn real_price_series_match_an_independent_source() {
        let current = crate::price_rpc::PriceRpc::new().get_prices().unwrap();
        let listed = [(Asset::Btc, 1_502_928_000), (Asset::Eth, 1_502_928_000), (Asset::Sol, 1_597_104_000), (Asset::Usdc, 1_544_832_000)];
        for (asset, reference) in [(Asset::Btc, current.btc_usd), (Asset::Eth, current.eth_usd), (Asset::Sol, current.sol_usd), (Asset::Usdc, 1.0)] {
            let s = series(asset).unwrap();
            assert_eq!(s.hourly.len(), 1000);
            let first_day = listed.iter().find(|(a, _)| *a == asset).unwrap().1;
            assert_eq!(s.daily[0].open_time, first_day, "{asset:?} : première bougie = cotation");
            assert!(unix_now() - s.daily.last().unwrap().open_time < DAY, "{asset:?} : jusqu'à aujourd'hui");
            let gaps: Vec<_> = s.daily.windows(2).filter(|w| w[1].open_time - w[0].open_time != DAY).map(|w| (w[0].open_time, w[1].open_time)).collect();
            let expected_gaps = if asset == Asset::Usdc { vec![(1_664_150_400, 1_678_492_800)] } else { vec![] };
            assert_eq!(gaps, expected_gaps, "{asset:?} : bougies consécutives");
            let chart = chart(asset, ChartRange::All).unwrap();
            assert_eq!(chart.len(), s.daily.len() + 1);
            let now = s.usd_at(None).unwrap();
            println!("{asset:?} : {now} $ (CoinGecko {reference} $), horaire depuis {}, journalier depuis {}", s.hourly[0].open_time, s.daily[0].open_time);
            assert!((now / reference - 1.0).abs() < 0.03, "{asset:?} {now} vs {reference}");
        }
    }
}
