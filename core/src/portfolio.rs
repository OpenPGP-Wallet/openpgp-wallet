//! Valeur en dollars d'un ensemble d'adresses (profil du portefeuille, wallets
//! externes) au fil du temps, reconstruite à partir des données de la chaîne :
//! solde actuel, puis à rebours chaque transaction de l'historique (variation
//! réelle du solde, frais compris), multiplié par le prix de l'actif à chaque
//! instant (voir `price_history`). Purement informatif, lecture seule.
//!
//! Limite assumée : l'historique lu est borné (dernières transactions de
//! chaque adresse). Avant la plus ancienne transaction lue d'une adresse dont
//! l'historique est tronqué, son solde est inconnu : la courbe commence alors
//! à cet instant (`since`) au lieu d'inventer une valeur.

use crate::price_history::{self, Asset, ChartRange, PriceSeries};
use crate::{api, btc_rpc, external_wallets, history, wallet_flow};
use anyhow::{ensure, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Une adresse et son réseau (identifiants de l'app : "evm_mainnet",
/// "btc_mainnet", "sol_mainnet", "usdc_solana" ; les réseaux de test sont
/// acceptés mais ignorés, leurs fonds n'ayant pas de valeur).
pub struct Holding {
    pub network: String,
    pub address: String,
}

pub struct PortfolioHistory {
    /// (instant, valeur en dollars), dans l'ordre chronologique ; le dernier
    /// point est l'instant présent.
    pub points: Vec<(i64, f64)>,
    /// Début des données exactes, quand l'historique d'une adresse est
    /// tronqué à l'intérieur de la période demandée.
    pub since: Option<i64>,
    /// Données incomplètes rencontrées (montant d'une transaction inconnu, ou
    /// solde reconstruit négatif : mouvement absent de l'historique, comme un
    /// transfert interne de contrat Ethereum) : courbe seulement indicative.
    pub approximate: bool,
}

/// Une page Blockscout.
const EVM_LIMIT: usize = 50;
/// Une page Esplora de transactions confirmées.
const BTC_PAGE: usize = 25;
/// Chaque transaction Solana demande une requête de détail.
const SOL_LIMIT: u32 = 30;
const MAX_HOLDINGS: usize = 60;
const CACHE_TTL: Duration = Duration::from_secs(300);

struct HoldingData {
    asset: Asset,
    decimals: i32,
    /// Solde actuel, en plus petite unité.
    balance: i128,
    /// (instant, variation du solde), du plus récent au plus ancien.
    changes: Vec<(i64, i128)>,
    /// Plus ancienne transaction lue, si l'historique est tronqué.
    known_since: Option<i64>,
    approximate: bool,
}

/// Solde et variations d'une adresse ; `None` pour un réseau sans valeur.
fn fetch_holding(network: &str, address: &str) -> Result<Option<HoldingData>> {
    let solana = &wallet_flow::SOLANA_MAINNET;
    let (asset, decimals, balance, entries, truncated) = match network {
        "evm_mainnet" => {
            let entries = history::evm_history(wallet_flow::ETHEREUM_MAINNET.chain_id, address, EVM_LIMIT)?;
            let truncated = entries.len() >= EVM_LIMIT;
            let balance = api::get_evm_balance(address, &wallet_flow::ETHEREUM_MAINNET)? as i128;
            (Asset::Eth, 18, balance, entries, truncated)
        }
        "btc_mainnet" => {
            let entries = history::btc_history(&wallet_flow::BTC_MAINNET, address)?;
            let truncated = entries.iter().filter(|e| e.timestamp_unix.is_some()).count() >= BTC_PAGE;
            // Confirmé + mempool, comme l'historique.
            let balance = btc_rpc::EsploraClient::new(wallet_flow::BTC_MAINNET.esplora_base).address_stats(address)?.balance_sat;
            (Asset::Btc, 8, balance, entries, truncated)
        }
        "sol_mainnet" => {
            let entries = history::sol_history(solana.rpc, address, SOL_LIMIT)?;
            let truncated = entries.len() >= SOL_LIMIT as usize;
            (Asset::Sol, 9, api::get_sol_balance(address, solana)?.into(), entries, truncated)
        }
        "usdc_solana" => {
            let entries = api::get_usdc_tx_history(address, solana, SOL_LIMIT)?;
            let truncated = entries.len() >= SOL_LIMIT as usize;
            (Asset::Usdc, 6, api::get_usdc_balance(address, solana)?.into(), entries, truncated)
        }
        _ => return Ok(None),
    };
    let now = price_history::unix_now();
    let mut approximate = false;
    let mut changes = Vec::with_capacity(entries.len());
    for entry in &entries {
        match entry.balance_change() {
            // En attente : pas encore d'horodatage, compté à l'instant présent.
            Some(change) => changes.push((entry.timestamp_unix.unwrap_or(now), change)),
            None => approximate = true,
        }
    }
    changes.sort_by_key(|change| std::cmp::Reverse(change.0));
    let known_since = if truncated { entries.iter().filter_map(|e| e.timestamp_unix).min() } else { None };
    Ok(Some(HoldingData { asset, decimals, balance, changes, known_since, approximate }))
}

/// `fetch_holding` avec un cache de 5 minutes (changer de période ne relit rien).
fn holding(network: &str, address: &str) -> Result<Option<Arc<HoldingData>>> {
    type Cache = Mutex<HashMap<(String, String), (Instant, Option<Arc<HoldingData>>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (network.to_string(), address.to_string());
    if let Some((fetched, data)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        if fetched.elapsed() < CACHE_TTL {
            return Ok(data.clone());
        }
    }
    let data = fetch_holding(network, address)?.map(Arc::new);
    cache.lock().unwrap_or_else(|p| p.into_inner()).insert(key, (Instant::now(), data.clone()));
    Ok(data)
}

/// Instants échantillonnés : multiples de `step` depuis `start`, puis `now`.
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

/// Valeur totale à chaque instant : solde reconstruit (solde actuel moins les
/// variations postérieures) × prix de l'instant. Un point sans prix connu
/// pour un actif détenu est omis. Renvoie aussi si un solde reconstruit est
/// devenu négatif (historique incomplet).
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

/// Valeur de `holdings` sur la période `range`.
pub fn portfolio_history(holdings: &[Holding], range: ChartRange) -> Result<PortfolioHistory> {
    ensure!(holdings.len() <= MAX_HOLDINGS, "trop d'adresses pour un graphique");
    for h in holdings {
        external_wallets::validate_address(&h.network, &h.address)?;
    }
    let fetched: Vec<Option<Arc<HoldingData>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = holdings.iter().map(|h| scope.spawn(move || holding(&h.network, h.address.trim()))).collect();
        handles.into_iter().map(|h| h.join().expect("le fil d'une adresse ne doit pas paniquer")).collect::<Result<_>>()
    })?;
    let data: Vec<Arc<HoldingData>> = fetched.into_iter().flatten().collect();

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

    let now = price_history::unix_now();
    let range_start = now - range.span();
    let since = data.iter().filter_map(|d| d.known_since).max().filter(|s| *s > range_start);
    let times = sample_times(since.unwrap_or(range_start), now, range.step());
    let refs: Vec<&HoldingData> = data.iter().map(Arc::as_ref).collect();
    let (points, negative) = values_over_time(&refs, &times, |asset, t| series.get(&asset).and_then(|s| s.usd_at(Some(t))));
    Ok(PortfolioHistory { points, since, approximate: negative || data.iter().any(|d| d.approximate) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holding_data(asset: Asset, decimals: i32, balance: i128, changes: &[(i64, i128)]) -> HoldingData {
        HoldingData { asset, decimals, balance, changes: changes.to_vec(), known_since: None, approximate: false }
    }

    #[test]
    fn samples_are_aligned_and_end_now() {
        assert_eq!(sample_times(100, 350, 100), vec![100, 200, 300, 350]);
        assert_eq!(sample_times(150, 350, 100), vec![200, 300, 350]);
        assert_eq!(sample_times(150, 160, 100), vec![160]);
    }

    /// Solde reconstruit à rebours : 2 BTC aujourd'hui, reçu 1,5 à t=300,
    /// envoyé 0,5 (frais compris) à t=200 -> 1 BTC avant t=200, 0,5 entre 200
    /// et 300... ; prix variable ; deux actifs additionnés.
    #[test]
    fn value_is_rebuilt_backwards_from_the_current_balance() {
        let btc = holding_data(Asset::Btc, 8, 200_000_000, &[(300, 150_000_000), (200, -50_000_000)]);
        let usdc = holding_data(Asset::Usdc, 6, 10_000_000, &[]);
        let price = |asset, t: i64| Some(if asset == Asset::Btc { 1000.0 + t as f64 } else { 1.0 });
        let (points, negative) = values_over_time(&[&btc, &usdc], &[100, 250, 400], price);
        assert!(!negative);
        assert_eq!(points, vec![(100, 1.0 * 1100.0 + 10.0), (250, 0.5 * 1250.0 + 10.0), (400, 2.0 * 1400.0 + 10.0)]);
    }

    /// Mouvement absent de l'historique : solde reconstruit négatif, ramené à
    /// 0 et signalé ; point sans prix pour un actif détenu : omis.
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

    /// Adresses RÉELLES (réseau principal) : la valeur finale reconstruite
    /// égale solde actuel × prix actuel ; courbe cohérente sur 30 jours.
    /// `cargo test -- --ignored real_portfolio_history_is_consistent --nocapture`
    #[test]
    #[ignore]
    fn real_portfolio_history_is_consistent() {
        let holdings = [
            Holding { network: "btc_mainnet".into(), address: "bc1qwqap30shafhtfd0k5hda4xep6xypgm6fyvphnw".into() },
            Holding { network: "evm_mainnet".into(), address: "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3".into() },
            Holding { network: "sol_mainnet".into(), address: "3iUShJYbFX6it5ArcR31Pm6SqqowccAe5NwQrfaG1yvG".into() },
            Holding { network: "btc_testnet".into(), address: "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk".into() },
        ];
        let started = Instant::now();
        let history = portfolio_history(&holdings, ChartRange::Month).unwrap();
        println!("{} points en {:?}, depuis {:?}, approximatif {}", history.points.len(), started.elapsed(), history.since, history.approximate);
        for (t, v) in history.points.iter().step_by(30) {
            println!("{t} : {v:.2} $");
        }
        let (_, last) = *history.points.last().unwrap();
        let btc = btc_rpc::EsploraClient::new(wallet_flow::BTC_MAINNET.esplora_base).address_stats(&holdings[0].address).unwrap().balance_sat as f64 / 1e8;
        let eth = api::get_evm_balance(&holdings[1].address, &wallet_flow::ETHEREUM_MAINNET).unwrap() as f64 / 1e18;
        let sol = api::get_sol_balance(&holdings[2].address, &wallet_flow::SOLANA_MAINNET).unwrap() as f64 / 1e9;
        let price = |a| price_history::series(a).unwrap().usd_at(None).unwrap();
        let expected = btc * price(Asset::Btc) + eth * price(Asset::Eth) + sol * price(Asset::Sol);
        println!("valeur actuelle : {last:.2} $, attendu {expected:.2} $");
        assert!((last - expected).abs() <= expected * 0.01 + 0.01, "{last} vs {expected}");
        let again = Instant::now();
        portfolio_history(&holdings, ChartRange::Year).unwrap();
        assert!(again.elapsed() < Duration::from_secs(2), "changement de période servi par le cache");
    }
}
