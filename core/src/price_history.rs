//! Prix historiques en dollars, pour afficher la valeur d'une transaction AU
//! MOMENT où elle a eu lieu. Purement informatif : ne joue aucun rôle dans la
//! construction ou la signature d'une transaction.
//!
//! Source : l'API publique de données de marché de Binance
//! (`data-api.binance.vision`, sans clé), bougies horaires (≈ 41 derniers
//! jours) et journalières (≈ 2 ans et demi), paires en USDT (≈ 1 $).
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
}

impl Asset {
    fn symbol(self) -> &'static str {
        match self {
            Asset::Btc => "BTCUSDT",
            Asset::Eth => "ETHUSDT",
            Asset::Sol => "SOLUSDT",
            Asset::Usdc => "USDCUSDT",
        }
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
}

impl PriceSeries {
    /// Prix en dollars à l'instant `timestamp` (secondes Unix) : bougie
    /// horaire si l'instant est couvert, sinon journalière, interpolé entre
    /// ouverture et clôture. `None` (transaction en attente) : dernier prix.
    /// `None` en retour si l'instant précède toutes les bougies connues.
    pub fn usd_at(&self, timestamp: Option<i64>) -> Option<f64> {
        let Some(t) = timestamp else {
            return self.hourly.last().or(self.daily.last()).map(|c| c.close);
        };
        price_in(&self.hourly, HOUR, t).or_else(|| price_in(&self.daily, DAY, t))
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

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

fn fetch_klines(asset: Asset, interval: &str, limit: &str) -> Result<Vec<Candle>> {
    let response = shared_client()
        .get(KLINES_URL)
        .query(&[("symbol", asset.symbol()), ("interval", interval), ("limit", limit)])
        .send()
        .context("appel du service de prix impossible")?;
    ensure!(response.status().is_success(), "le service de prix a répondu {}", response.status());
    parse_klines(&response.text().context("réponse de prix illisible")?)
}

/// Séries de prix de `asset` (cache de 10 minutes, deux requêtes en parallèle
/// au premier appel). Un échec n'est pas mis en cache : réessayé au suivant.
pub fn series(asset: Asset) -> Result<Arc<PriceSeries>> {
    /// Séries par actif, avec l'instant où elles ont été lues.
    type Cache = Mutex<HashMap<Asset, (Instant, Arc<PriceSeries>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some((fetched, series)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&asset) {
        if fetched.elapsed() < CACHE_TTL {
            return Ok(series.clone());
        }
    }
    let (hourly, daily) = std::thread::scope(|scope| {
        let hourly = scope.spawn(|| fetch_klines(asset, "1h", "1000"));
        let daily = scope.spawn(|| fetch_klines(asset, "1d", "1000"));
        (
            hourly.join().expect("le fil des prix horaires ne doit pas paniquer"),
            daily.join().expect("le fil des prix journaliers ne doit pas paniquer"),
        )
    });
    let series = Arc::new(PriceSeries { hourly: hourly?, daily: daily? });
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
}

impl ChartRange {
    /// "1d", "7d", "30d", "1y".
    pub fn parse(range: &str) -> Option<Self> {
        Some(match range {
            "1d" => ChartRange::Day,
            "7d" => ChartRange::Week,
            "30d" => ChartRange::Month,
            "1y" => ChartRange::Year,
            _ => return None,
        })
    }

    /// Durée couverte, en secondes.
    pub fn span(self) -> i64 {
        match self {
            ChartRange::Day => DAY,
            ChartRange::Week => 7 * DAY,
            ChartRange::Month => 30 * DAY,
            ChartRange::Year => 365 * DAY,
        }
    }

    /// Pas entre deux points (bougies, ou échantillons d'une valeur de portefeuille).
    pub fn step(self) -> i64 {
        match self {
            ChartRange::Day => 15 * 60,
            ChartRange::Week => HOUR,
            ChartRange::Month => 4 * HOUR,
            ChartRange::Year => DAY,
        }
    }

    /// Intervalle Binance correspondant à `step`.
    fn interval(self) -> &'static str {
        match self {
            ChartRange::Day => "15m",
            ChartRange::Week => "1h",
            ChartRange::Month => "4h",
            ChartRange::Year => "1d",
        }
    }
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
/// monde, voir l'en-tête). Cache : 2 minutes sur 24 h, 10 minutes sinon.
pub fn chart(asset: Asset, range: ChartRange) -> Result<Arc<Vec<(i64, f64)>>> {
    type ChartCache = Mutex<HashMap<(Asset, ChartRange), (Instant, Arc<Vec<(i64, f64)>>)>>;
    static CACHE: OnceLock<ChartCache> = OnceLock::new();
    let ttl = if range == ChartRange::Day { Duration::from_secs(120) } else { CACHE_TTL };
    let cache = CACHE.get_or_init(Default::default);
    if let Some((fetched, points)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&(asset, range)) {
        if fetched.elapsed() < ttl {
            return Ok(points.clone());
        }
    }
    let limit = (range.span() / range.step()).to_string();
    let points = Arc::new(chart_points(&fetch_klines(asset, range.interval(), &limit)?, unix_now()));
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

    /// Un trou dans la série ne donne pas un prix inventé.
    #[test]
    fn gaps_in_a_series_give_no_price() {
        let candles = [candle(0, 1.0, 2.0), candle(3 * HOUR, 3.0, 4.0)];
        assert_eq!(price_in(&candles, HOUR, HOUR + 1), None);
        assert_eq!(price_in(&candles, HOUR, 3 * HOUR), Some(3.0));
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

    /// Service réel : les 4 actifs, séries horaires (~41 j) et journalières
    /// (~2,7 ans), prix cohérents avec le prix courant de CoinGecko (autre
    /// source) à quelques % près ; USDC ≈ 1 $.
    #[test]
    #[ignore]
    fn real_price_series_match_an_independent_source() {
        let current = crate::price_rpc::PriceRpc::new().get_prices().unwrap();
        for (asset, reference) in [(Asset::Btc, current.btc_usd), (Asset::Eth, current.eth_usd), (Asset::Sol, current.sol_usd), (Asset::Usdc, 1.0)] {
            let s = series(asset).unwrap();
            assert_eq!(s.hourly.len(), 1000);
            assert_eq!(s.daily.len(), 1000);
            let now = s.usd_at(None).unwrap();
            println!("{asset:?} : {now} $ (CoinGecko {reference} $), horaire depuis {}, journalier depuis {}", s.hourly[0].open_time, s.daily[0].open_time);
            assert!((now / reference - 1.0).abs() < 0.03, "{asset:?} {now} vs {reference}");
        }
    }
}
