//! Valeur en dollars d'un ensemble d'adresses (profil du portefeuille, wallets
//! externes) au fil du temps, reconstruite à partir des données de la chaîne :
//! solde actuel, puis à rebours chaque transaction de l'historique (variation
//! réelle du solde, frais compris), multiplié par le prix de l'actif à chaque
//! instant (voir `price_history`). Purement informatif, lecture seule.
//!
//! L'historique de chaque adresse est lu page par page, aussi loin que la
//! période l'exige (« tout » : jusqu'à la première transaction), dans une
//! limite par adresse. Avant la plus ancienne transaction lue d'une adresse
//! dont l'historique n'a pas été lu jusqu'au bout, son solde est inconnu : la
//! courbe commence alors à cet instant (`since`) au lieu d'inventer une valeur.
//!
//! Réseau sans source publique d'historique (BNB Chain, HyperEVM) : le solde
//! actuel est compté sur toute la période, et la crypto est signalée
//! (`constant`) pour que l'interface le dise.

use crate::history::{self, EvmCursor, TxEntry, TxStatus};
use crate::price_history::{self, Asset, ChartRange, PriceSeries};
use crate::tokens::{self, TokenKind};
use crate::{api, external_wallets, wallet_flow};
use anyhow::{anyhow, ensure, Result};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// Une adresse, son réseau (identifiants de l'app : "evm_mainnet",
/// "base_mainnet", "btc_mainnet", "sol_mainnet"… ; "usdc_solana", ancien
/// identifiant des wallets externes = USDC sur Solana) et, pour un jeton,
/// son identifiant dans le registre (`tokens`). Les réseaux de test sont
/// acceptés mais ignorés, leurs fonds n'ayant pas de valeur.
pub struct Holding {
    pub network: String,
    pub address: String,
    pub token: Option<String>,
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
    /// Historique encore en cours de lecture : redemander pour la suite.
    pub loading: bool,
    /// Transactions lues jusqu'ici, toutes adresses confondues.
    pub transactions_read: usize,
    /// Cryptos détenues sur un réseau sans historique, comptées à leur solde
    /// actuel sur toute la période (symboles, sans doublon).
    pub constant: Vec<String>,
}

/// Transactions lues au plus par adresse : 20 pages Blockscout, 40 pages
/// Esplora.
const EVM_MAX: usize = 1000;
const BTC_MAX: usize = 1000;
/// Transactions Dogecoin lues pour la courbe (heure de chaque bloc demandée
/// une fois au service, puis gardée).
const DOGE_MAX: usize = 100;
/// Virements de TRX lus pour la courbe (une page TronGrid).
const TRON_MAX: usize = 50;
const XRP_MAX: usize = 50;
const XLM_MAX: usize = 50;
/// Transactions confirmées par page Esplora.
const BTC_PAGE: usize = 25;
/// Chaque transaction Solana demande une requête de détail, que le nœud
/// public limite à 35 par 10 s (voir `sol_rpc`) : 300 ≈ 1 min 30 au pire,
/// beaucoup moins ensuite (détails des transactions finalisées gardés).
const SOL_MAX: usize = 300;
/// Première page courte (≈ 10 s de lecture) pour qu'une courbe apparaisse
/// vite, puis des pages plus longues.
const SOL_FIRST_PAGE: u32 = 10;
const SOL_PAGE: u32 = 25;
const MAX_HOLDINGS: usize = 60;
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Attente maximale d'un appel avant de rendre une courbe partielle.
const WAIT: Duration = Duration::from_secs(6);
/// Période affichée pour « tout » quand aucune transaction n'est connue.
const DEFAULT_ALL_SPAN: i64 = 365 * 86_400;

/// Suite d'un historique : curseur propre à chaque source.
#[derive(Clone)]
enum Cursor {
    Evm(EvmCursor),
    /// Dernier txid confirmé vu.
    Btc(String),
    /// Dernière signature vue.
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
    /// Aucune source d'historique : solde actuel compté sur toute la période.
    constant: bool,
    /// Solde actuel, en plus petite unité.
    balance: i128,
    /// (instant, variation du solde), du plus récent au plus ancien.
    changes: Vec<(i64, i128)>,
    /// Plus ancienne transaction lue.
    oldest: Option<i64>,
    /// Suite de l'historique ; `None` quand il a été lu jusqu'au bout.
    next: Option<Cursor>,
    /// Transactions lues.
    read: usize,
    approximate: bool,
}

impl HoldingData {
    fn absorb(&mut self, page: Page, now: i64) {
        self.read += page.entries.len();
        // Page vide : fin de l'historique, même si la source donne un curseur.
        self.next = if page.entries.is_empty() { None } else { page.next };
        for entry in &page.entries {
            if let Some(t) = entry.timestamp_unix {
                self.oldest = Some(self.oldest.map_or(t, |o| o.min(t)));
            }
            match entry.balance_change() {
                // En attente : pas encore d'horodatage, compté à l'instant présent.
                Some(change) => self.changes.push((entry.timestamp_unix.unwrap_or(now), change)),
                None => self.approximate = true,
            }
        }
        self.changes.sort_by_key(|change| std::cmp::Reverse(change.0));
    }

    /// Historique suffisant : lu jusqu'au bout, jusqu'à `until`, ou limite atteinte.
    fn covers(&self, until: Option<i64>, max_read: usize) -> bool {
        self.next.is_none() || self.read >= max_read || matches!((until, self.oldest), (Some(u), Some(o)) if o <= u)
    }

    /// Début des données exactes si l'historique n'a pas été lu jusqu'au bout.
    fn known_since(&self) -> Option<i64> {
        self.next.as_ref().and(self.oldest)
    }
}

/// Ce qu'il faut lire pour un avoir.
#[derive(Clone, Copy)]
struct Spec {
    asset: Asset,
    decimals: i32,
    /// Transactions lues au plus.
    max_read: usize,
    symbol: &'static str,
    source: Source,
}

#[derive(Clone, Copy)]
enum Source {
    Btc,
    Sol,
    /// Jeton SPL (mint) : historique de son compte de jetons associé.
    Spl([u8; 32]),
    /// Monnaie d'un réseau EVM.
    Evm(&'static wallet_flow::EvmNetwork),
    /// Jeton ERC-20 (adresse du contrat).
    Erc20(&'static wallet_flow::EvmNetwork, &'static str),
    /// Zcash transparent : solde actuel, compté constant sur la période.
    Zec,
    /// Monero : solde et historique complet de l'état local (voir `monero`).
    Xmr,
    /// Zcash protégé : solde et historique de la base locale (voir
    /// `zcash_shielded`).
    ZecShielded,
    /// Dogecoin : historique récent, en une page (voir `DOGE_MAX`).
    Doge,
    /// Tron : virements de TRX récents, en une page (voir `TRON_MAX`).
    Tron,
    /// Jeton TRC-20 (contrat) : transferts récents, en une page.
    Trc20(&'static str),
    /// XRP Ledger : paiements récents, en une page (voir `XRP_MAX`).
    Xrp,
    /// Stellar : paiements récents, en une page (voir `XLM_MAX`).
    Xlm,
}

impl Spec {
    /// Historique lu chez Etherscan, avec la clé de l'utilisateur.
    fn uses_etherscan(&self) -> bool {
        matches!(self.source, Source::Evm(net) | Source::Erc20(net, _) if matches!(net.history, Some(wallet_flow::EvmHistory::Etherscan)))
    }

    /// Une source d'historique existe pour cet avoir (voir `EvmNetwork::history`).
    fn has_history(&self) -> bool {
        match self.source {
            Source::Evm(net) | Source::Erc20(net, _) => history::evm_history_available(net),
            Source::Btc | Source::Sol | Source::Spl(_) | Source::Xmr | Source::ZecShielded | Source::Doge | Source::Tron | Source::Trc20(_) | Source::Xrp | Source::Xlm => true,
            Source::Zec => false,
        }
    }
}

/// Avoir de `token` (ou de la monnaie du réseau) sur `network` ; `Ok(None)` :
/// sans valeur (réseau de test, ou crypto sans source de prix).
fn spec(network: &str, token: Option<&str>) -> Result<Option<Spec>> {
    let (network, token) = if network == "usdc_solana" { ("sol_mainnet", Some("usdc")) } else { (network, token) };
    if let Some(token_id) = token {
        let (token, deployment) = tokens::find(token_id, network).ok_or_else(|| anyhow!("jeton non pris en charge sur ce réseau : {token_id}"))?;
        let Some(asset) = price_history::price_asset(&token.symbol.to_ascii_uppercase()) else { return Ok(None) };
        let (source, max_read) = match deployment.kind {
            TokenKind::Spl { .. } => (Source::Spl(api::registered_spl_mint(token_id)?), SOL_MAX),
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
        other => match wallet_flow::evm_network(other) {
            Some(net) if net.mainnet => {
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
        // Comme la carte : confirmé moins les envois en attente, SANS les
        // réceptions non confirmées (annulables par leur émetteur, voir
        // `api::BtcBalanceView`) — retirées aussi de l'historique (`fetch_page`).
        Source::Btc => api::get_btc_balance_view(address, &wallet_flow::BTC_MAINNET)?.settled_sat.into(),
        Source::Sol => api::get_sol_balance(address, solana)?.into(),
        Source::Zec => api::get_zec_balance(address)?.into(),
        Source::Xmr => crate::monero::balance_of_address(address)?.into(),
        Source::ZecShielded => crate::zcash_shielded::balance_of_address(address)?.into(),
        Source::Doge => api::get_doge_balance(address)?.into(),
        Source::Tron => api::get_trx_balance(address)?.into(),
        Source::Xrp => api::get_xrp_balance(address)?.into(),
        Source::Xlm => api::get_xlm_balance(address)?.into(),
        Source::Trc20(contract) => i128::try_from(crate::tron::trc20_balance(address, contract)?).map_err(|_| anyhow!("solde hors limites"))?,
        Source::Spl(mint) => api::get_spl_balance(address, &mint, solana)?.into(),
    })
}

/// Une page d'historique : la première sans `cursor`, sinon la suivante.
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
            // Page de confirmées incomplète : fin de l'historique.
            let next = if confirmed.len() >= BTC_PAGE { confirmed.last().map(|e| Cursor::Btc(e.id.clone())) } else { None };
            // Réceptions non confirmées : hors du solde (`fetch_balance`), donc hors de l'historique.
            entries.retain(|e| !(matches!(e.status, TxStatus::Pending) && e.net_amount_minor.is_some_and(|net| net > 0)));
            Ok(Page { entries, next })
        }
        Source::Sol | Source::Spl(_) => {
            let before = match cursor {
                Some(Cursor::Sol(signature)) => Some(signature.as_str()),
                _ => None,
            };
            let size = if before.is_some() { SOL_PAGE } else { SOL_FIRST_PAGE };
            let entries = match spec.source {
                Source::Spl(mint) => history::spl_history_before(solana.rpc, &api::spl_token_account(address, &mint)?, size, before)?,
                _ => history::sol_history_before(solana.rpc, address, size, before)?,
            };
            let next = if entries.len() >= size as usize { entries.last().map(|e| Cursor::Sol(e.id.clone())) } else { None };
            Ok(Page { entries, next })
        }
        // Solde compté constant (`has_history`) : jamais lu page par page.
        Source::Zec => Ok(Page { entries: Vec::new(), next: None }),
        // Tout l'historique est local : une seule page.
        Source::Xmr => Ok(Page { entries: crate::monero::history_of_address(address)?, next: None }),
        Source::ZecShielded => Ok(Page { entries: crate::zcash_shielded::history_of_address(address)?, next: None }),
        // Une page : les `DOGE_MAX` transactions les plus récentes.
        Source::Doge => Ok(Page { entries: crate::doge::history(address, DOGE_MAX)?, next: None }),
        Source::Tron => Ok(Page { entries: crate::tron::history(address, TRON_MAX)?, next: None }),
        Source::Trc20(contract) => Ok(Page { entries: crate::tron::trc20_history(address, contract, TRON_MAX)?, next: None }),
        Source::Xrp => Ok(Page { entries: crate::xrp::history(address, XRP_MAX)?, next: None }),
        Source::Xlm => Ok(Page { entries: crate::stellar::history(&crate::stellar::MAINNET, address, XLM_MAX)?, next: None }),
    }
}

/// Solde, puis première page d'historique (sauf réseau sans historique :
/// solde seul, compté sur toute la période).
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
        // Clé Etherscan refusée pour ce réseau (offre gratuite sur BNB Chain,
        // clé révoquée…) : solde compté constant plutôt qu'une courbe entière
        // en échec — l'interface le dit (`constant`).
        Err(_) if spec.uses_etherscan() => data.constant = true,
        Err(e) => return Err(e),
    }
    Ok(data)
}

/// Réseau, adresse et jeton éventuel.
type Key = (String, String, Option<String>);

/// Lecture d'une adresse : dernières données publiées, lecture en cours.
#[derive(Default)]
struct Slot {
    /// Données, et instant où leur solde a été lu.
    data: Option<(Instant, Arc<HoldingData>)>,
    /// Profondeur voulue par la lecture en cours (`None` : tout l'historique).
    target: Option<i64>,
    running: bool,
    /// Échec de la dernière lecture, quand elle n'a rien pu lire.
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

/// La plus profonde de deux limites (`None` : tout l'historique).
fn deepest(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    Some(a?.min(b?))
}

/// Demande l'historique de `key` jusqu'à `until` : rien à faire si les
/// données en cache (5 minutes) le couvrent ; sinon une lecture en
/// arrière-plan démarre, ou celle en cours est approfondie. Asynchrone : le
/// nœud Solana public n'accorde qu'environ un détail de transaction par
/// seconde, un long historique demande des minutes la première fois.
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
    // Suite des données fraîches ; sinon relecture complète (solde compris),
    // publiée à la fin seulement quand une courbe est déjà affichée, pour ne
    // pas la raccourcir entre-temps.
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

/// Lecture en arrière-plan de `key` : solde et première page (sauf suite de
/// `base`), puis pages plus anciennes jusqu'à la profondeur voulue, relue à
/// chaque page — une demande plus profonde arrivée entre-temps prolonge la
/// lecture. Une page ancienne en échec arrête la remontée (la courbe
/// commence alors à la plus ancienne transaction lue) au lieu de tout faire
/// échouer ; elle sera redemandée plus tard.
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

/// Début de la courbe : `range_start` pour une période fixe ; pour « tout »,
/// la première transaction connue (à défaut, un an) ; plus tard si
/// l'historique d'une adresse est tronqué (`since`).
fn chart_start(data: &[&HoldingData], range_start: Option<i64>, now: i64) -> (i64, Option<i64>) {
    let since = data.iter().filter_map(|d| d.known_since()).max().filter(|s| range_start.is_none_or(|start| *s > start));
    let first_change = data.iter().filter_map(|d| d.changes.last().map(|c| c.0)).min();
    let start = since.or(range_start).unwrap_or_else(|| first_change.unwrap_or(now - DEFAULT_ALL_SPAN));
    (start, since)
}

/// Valeur de `holdings` sur la période `range`. Attend au plus `WAIT` que
/// les historiques nécessaires soient lus ; au-delà, la courbe est calculée
/// avec ce qui l'est déjà (`loading`) et la lecture continue en arrière-plan
/// — un nouvel appel donne la suite. Tant qu'une adresse n'a encore rien
/// donné, aucun point (une courbe sans elle serait fausse).
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
    let mut data = Vec::with_capacity(keys.len());
    let mut missing = false;
    for (key, _) in &keys {
        let slot = map.get(key);
        match slot.and_then(|slot| slot.data.as_ref()) {
            Some((_, holding)) => data.push(holding.clone()),
            None => match slot.and_then(|slot| slot.error.clone()) {
                Some(error) => return Err(anyhow!(error)),
                None => missing = true,
            },
        }
    }
    drop(map);
    let transactions_read = data.iter().map(|d| d.read).sum();
    if missing {
        return Ok(PortfolioHistory { points: Vec::new(), since: None, approximate: false, loading: true, transactions_read, constant: Vec::new() });
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
    Ok(PortfolioHistory { points, since, approximate: negative || data.iter().any(|d| d.approximate), loading, transactions_read, constant })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holding_data(asset: Asset, decimals: i32, balance: i128, changes: &[(i64, i128)]) -> HoldingData {
        HoldingData { asset, decimals, symbol: "X", constant: false, balance, changes: changes.to_vec(), oldest: changes.last().map(|c| c.0), next: None, read: changes.len(), approximate: false }
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

    /// Pages absorbées dans l'ordre : variations triées du plus récent au plus
    /// ancien, transaction en attente comptée maintenant, montant inconnu
    /// signalé ; l'historique « couvre » une période quand il remonte assez
    /// loin, qu'il est lu jusqu'au bout ou que la limite est atteinte ; page
    /// vide = fin, même avec un curseur.
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

    /// Lecture en arrière-plan : chaque page publiée au fur et à mesure ; une
    /// demande plus profonde arrivée pendant la lecture la prolonge ; fin de
    /// lecture signalée ; échec de la première page conservé pour l'appelant,
    /// échec d'une page ancienne : lecture arrêtée, données gardées.
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
                // Pendant la lecture : on demande tout l'historique.
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

    /// Début de la courbe : période fixe, ou première transaction pour
    /// « tout », repoussé au début des données exactes si un historique est
    /// tronqué ; sans aucune transaction, un an.
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

    /// Avoirs RÉELS sur les nouvelles sources : Avalanche (Routescan), jeton
    /// ERC-20 (Blockscout), jeton SPL, et BNB Chain sans historique (solde
    /// constant, signalé). Valeur finale = Σ solde actuel × prix actuel.
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

    /// Adresses RÉELLES (réseau principal) : la valeur finale reconstruite
    /// égale solde actuel × prix actuel ; courbe cohérente sur 30 jours.
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
        // Appels répétés tant que la lecture continue en arrière-plan, comme l'app.
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
}
