//! Client pour l'API publique Blockscout (v2), utilisé uniquement pour lister
//! l'historique de transactions EVM d'une adresse : contrairement à Bitcoin
//! (Esplora expose `/address/:address/txs`) et Solana (`getSignaturesForAddress`
//! est une méthode JSON-RPC standard), aucun nœud EVM public n'expose "la liste des
//! transactions d'une adresse" — cette information n'existe que via un indexeur
//! externe. Les instances publiques Blockscout (contrairement à Etherscan) ne
//! demandent aucune clé API, ce qui les rend cohérentes avec Bitcoin/Solana : zéro
//! configuration requise de la part de l'utilisateur.
//!
//! Depuis octobre 2026, les sites publics d'Arbitrum, de Base et de Polygon
//! sont derrière la vérification anti-robots de Cloudflare (403, constaté le
//! 10/10/2026 ; Ethereum et Sepolia répondent encore). Un réseau dont le site
//! refuse passe par l'API officielle de Blockscout (`api.blockscout.com`, mêmes
//! routes v2), avec la clé gratuite de l'app : 100 000 crédits par jour et 5
//! requêtes par seconde, partagés par tous ses utilisateurs (20 crédits par
//! page de transactions, 30 par page de virements de jeton). Mesuré le
//! 10/10/2026 : Arbitrum et Ethereum servis avec la clé gratuite ; Base et
//! Polygon refusés (402 « Featured chain … requires one of the following
//! plans: Builder, Business, Pro »).

use anyhow::{anyhow, bail, Context, Result};
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Clé de l'API officielle (offre gratuite), intégrée À LA COMPILATION
/// (`BLOCKSCOUT_API_KEY` dans `partner-keys.env`, voir build.rs) ; absente :
/// historique des réseaux bloqués indisponible (`BLOCKSCOUT_BLOCKED`).
pub const API_KEY: Option<&str> = option_env!("BLOCKSCOUT_API_KEY");
const PRO_API: &str = "https://api.blockscout.com";
/// Écart minimal entre deux appels à l'API officielle (5 requêtes par
/// seconde pour tous les utilisateurs : pas de rafale).
const PRO_SPACING: Duration = Duration::from_millis(250);
/// Plus longue attente acceptée avant une seconde tentative (limite de débit).
const PRO_MAX_RETRY_WAIT: Duration = Duration::from_secs(2);

fn pace() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(wait) = last.map(|t| PRO_SPACING.saturating_sub(t.elapsed())) {
        std::thread::sleep(wait);
    }
    *last = Some(Instant::now());
}

/// Sites publics vus bloqués pendant cette session : leurs appels suivants
/// vont directement à l'API officielle (pas une requête perdue à chaque fois).
fn blocked_sites() -> &'static Mutex<HashSet<&'static str>> {
    static SITES: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    SITES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Réseaux que l'API officielle refuse à la clé de l'app (offre payante
/// exigée, clé invalide) : plus redemandés pendant cette session.
fn refused_chains() -> &'static Mutex<HashSet<u64>> {
    static CHAINS: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    CHAINS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Ce que dit une réponse de l'API officielle, selon son statut.
#[derive(Debug, PartialEq)]
enum ProReply {
    Ok,
    /// Débit dépassé : une seconde tentative après cette attente.
    RetryAfter(Duration),
    /// Crédits du jour épuisés, ou débit dépassé pour longtemps.
    Limited,
    /// Clé absente, invalide ou révoquée.
    Refused,
    Other(StatusCode),
}

/// `credits_left` et `reset_ms` : en-têtes `x-credits-remaining` et
/// `x-ratelimit-reset` (millisecondes), s'ils sont là.
fn pro_reply(status: StatusCode, credits_left: Option<i64>, reset_ms: Option<i64>) -> ProReply {
    match status {
        s if s.is_success() => ProReply::Ok,
        StatusCode::TOO_MANY_REQUESTS => match (credits_left, reset_ms) {
            (Some(credits), _) if credits <= 0 => ProReply::Limited,
            (_, Some(ms)) if (0..=PRO_MAX_RETRY_WAIT.as_millis() as i64).contains(&ms) => ProReply::RetryAfter(Duration::from_millis(ms as u64)),
            _ => ProReply::Limited,
        },
        StatusCode::UNAUTHORIZED | StatusCode::PAYMENT_REQUIRED | StatusCode::FORBIDDEN => ProReply::Refused,
        s => ProReply::Other(s),
    }
}

fn header_number(response: &reqwest::blocking::Response, name: &str) -> Option<i64> {
    response.headers().get(name)?.to_str().ok()?.trim().parse().ok()
}

/// Page de vérification anti-robots de Cloudflare (403 en HTML) au lieu de JSON.
fn is_challenge(response: &reqwest::blocking::Response) -> bool {
    let html = response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/html"));
    html && response.status() == StatusCode::FORBIDDEN
}

/// Historique indisponible du côté de l'explorateur (site bloqué sans clé,
/// clé refusée, limite du jour atteinte) plutôt qu'une panne de l'app : la
/// courbe du portefeuille compte alors le solde constant.
pub fn unavailable(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text == BLOCKSCOUT_BLOCKED || text == BLOCKSCOUT_LIMITED
}

// Voir eth_rpc::shared_client : un `reqwest::Client` reconstruit à chaque appel de
// commande jette son pool de connexions keep-alive et repaie une poignée de main
// TCP+TLS complète à chaque clic. Un seul client partagé, construit une fois.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

pub struct BlockscoutClient {
    client: reqwest::blocking::Client,
    base_url: &'static str,
    /// Réseau, pour l'API officielle (`api.blockscout.com/<réseau>/…`).
    chain_id: u64,
}

#[derive(Deserialize)]
struct TxListResponse {
    items: Vec<TxJson>,
    /// Curseur de la page suivante (`null` sur la dernière).
    #[serde(default)]
    next_page_params: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Paramètres de requête de la page suivante d'un historique, tels que
/// Blockscout les donne (`next_page_params`).
pub type PageParams = Vec<(String, String)>;

#[derive(Deserialize)]
struct TxJson {
    hash: String,
    timestamp: Option<String>,
    #[serde(default)]
    status: Option<String>,
    value: String,
    from: AddressRef,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    fee: Option<FeeJson>,
}

#[derive(Deserialize)]
struct FeeJson {
    value: Option<String>,
}

#[derive(Deserialize)]
struct AddressRef {
    hash: String,
}

pub struct EvmTx {
    pub hash: String,
    pub timestamp_unix: Option<i64>,
    /// `true` si la transaction a été minée mais a échoué à l'exécution (revert).
    pub failed: bool,
    /// Positif si l'adresse interrogée a reçu net, négatif si elle a envoyé net,
    /// en wei, frais non compris ; 0 pour une transaction échouée (le montant
    /// n'est alors pas transféré, seuls les frais sont payés).
    pub net_wei: i128,
    /// Frais payés par l'adresse interrogée (transaction qu'elle a émise), en wei.
    pub fee_wei: i128,
    /// Appel d'une fonction de swap (voir is_swap_method).
    pub swap: bool,
}

impl BlockscoutClient {
    /// `base_url` : `https://eth.blockscout.com` (mainnet) ou
    /// `https://eth-sepolia.blockscout.com` (Sepolia) — voir `history::evm_history`.
    pub fn new(base_url: &'static str, chain_id: u64) -> Self {
        Self {
            client: shared_client().clone(),
            base_url,
            chain_id,
        }
    }

    pub fn tx_history(&self, address: &str, limit: usize) -> Result<Vec<EvmTx>> {
        let (mut txs, _) = self.tx_history_page(address, None)?;
        txs.truncate(limit);
        Ok(txs)
    }

    /// Réponse JSON de `path` (`/api/v2/…`) : le site public d'abord ; s'il
    /// renvoie la page de vérification anti-robots de Cloudflare (403 « Just a
    /// moment… », quel que soit l'en-tête), l'API officielle avec la clé de
    /// l'app — sans clé, `BLOCKSCOUT_BLOCKED`, plutôt qu'une réponse
    /// « illisible » sans cause.
    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str, query: &[(String, String)]) -> Result<T> {
        let blocked = blocked_sites().lock().unwrap_or_else(|p| p.into_inner()).contains(self.base_url);
        if !blocked {
            let response = self.client.get(format!("{}{path}", self.base_url)).query(query).send().context("appel Blockscout impossible")?;
            if !is_challenge(&response) {
                return response.json().context("réponse Blockscout illisible");
            }
            blocked_sites().lock().unwrap_or_else(|p| p.into_inner()).insert(self.base_url);
        }
        let key = API_KEY.ok_or_else(|| anyhow!(BLOCKSCOUT_BLOCKED))?;
        anyhow::ensure!(!refused_chains().lock().unwrap_or_else(|p| p.into_inner()).contains(&self.chain_id), BLOCKSCOUT_BLOCKED);
        self.pro_json(key, path, query)
    }

    /// Réponse JSON de l'API officielle. La clé voyage dans l'en-tête
    /// `authorization`, jamais dans l'URL (que les erreurs réseau citent).
    fn pro_json<T: serde::de::DeserializeOwned>(&self, key: &str, path: &str, query: &[(String, String)]) -> Result<T> {
        let url = format!("{PRO_API}/{}{path}", self.chain_id);
        for attempt in 0..2 {
            pace();
            let response = self.client.get(&url).query(query).bearer_auth(key).send().context("appel Blockscout impossible")?;
            match pro_reply(response.status(), header_number(&response, "x-credits-remaining"), header_number(&response, "x-ratelimit-reset")) {
                ProReply::Ok => return response.json().context("réponse Blockscout illisible"),
                ProReply::RetryAfter(wait) if attempt == 0 => std::thread::sleep(wait),
                ProReply::RetryAfter(_) | ProReply::Limited => bail!(BLOCKSCOUT_LIMITED),
                ProReply::Refused => {
                    refused_chains().lock().unwrap_or_else(|p| p.into_inner()).insert(self.chain_id);
                    bail!(BLOCKSCOUT_BLOCKED)
                }
                ProReply::Other(status) => bail!("Blockscout a répondu {status}"),
            }
        }
        bail!(BLOCKSCOUT_LIMITED)
    }

    /// Une page d'historique (50 transactions, de la plus récente à la plus
    /// ancienne) et le curseur de la suivante, `None` après la dernière.
    pub fn tx_history_page(&self, address: &str, page: Option<&PageParams>) -> Result<(Vec<EvmTx>, Option<PageParams>)> {
        let path = format!("/api/v2/addresses/{address}/transactions");
        let resp: TxListResponse = self.get_json(&path, page.map(Vec::as_slice).unwrap_or_default())?;

        let next = resp.next_page_params.map(page_params);
        let address_lower = address.to_lowercase();
        let txs = resp
            .items
            .into_iter()
            .map(|tx| {
                let value: i128 = tx.value.parse().context("montant de transaction Blockscout invalide")?;
                let sender = tx.from.hash.to_lowercase() == address_lower;
                let failed = tx.status.as_deref() == Some("error");
                let net_wei = match (failed, sender) {
                    (true, _) => 0,
                    (false, true) => -value,
                    (false, false) => value,
                };
                let fee_wei = match (sender, tx.fee.as_ref().and_then(|f| f.value.as_deref())) {
                    (true, Some(fee)) => fee.parse().context("frais de transaction Blockscout invalides")?,
                    _ => 0,
                };
                Ok(EvmTx {
                    hash: tx.hash,
                    timestamp_unix: tx.timestamp.as_deref().and_then(parse_iso8601_utc),
                    failed,
                    net_wei,
                    fee_wei,
                    swap: tx.method.as_deref().is_some_and(is_swap_method),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((txs, next))
    }

    /// Une page des mouvements du jeton ERC-20 `contract` pour `address` (50
    /// virements, du plus récent au plus ancien), regroupés par transaction,
    /// et le curseur de la suivante. Filtré par contrat côté serveur ET
    /// revérifié ici : un faux jeton au même symbole n'y entre jamais.
    /// Mesuré : 0,45 s pour une adresse ordinaire, 21 s pour une adresse très
    /// active (vitalik.eth) — d'où le long délai d'attente du client.
    pub fn token_transfers_page(&self, address: &str, contract: &str, page: Option<&PageParams>) -> Result<(Vec<TokenMove>, Option<PageParams>)> {
        let path = format!("/api/v2/addresses/{address}/token-transfers");
        let mut query: PageParams = vec![("type".into(), "ERC-20".into()), ("token".into(), contract.into())];
        if let Some(page) = page {
            query.extend(page.iter().filter(|(key, _)| key != "type" && key != "token").cloned());
        }
        let resp: TokenTransferListResponse = self.get_json(&path, &query)?;
        let moves = token_moves(resp.items, address, contract)?;
        Ok((moves, resp.next_page_params.map(page_params)))
    }
}

/// L'explorateur refuse les requêtes automatiques (page de vérification
/// anti-robots) : historique de ce réseau indisponible tant qu'il le fait.
pub const BLOCKSCOUT_BLOCKED: &str = "l'explorateur de ce réseau refuse pour l'instant les requêtes automatiques : historique indisponible";

/// Crédits du jour de l'API officielle épuisés (ou débit dépassé).
pub const BLOCKSCOUT_LIMITED: &str = "historique de ce réseau momentanément indisponible (limite du service atteinte) — réessayez plus tard";

/// Mouvement net d'un jeton pour l'adresse interrogée dans une transaction
/// (Blockscout ou Routescan).
pub struct TokenMove {
    pub hash: String,
    pub timestamp_unix: Option<i64>,
    /// En plus petite unité du jeton : positif reçu, négatif envoyé, 0 vers
    /// soi-même.
    pub net: i128,
    pub swap: bool,
}

#[derive(Deserialize)]
struct TokenTransferListResponse {
    items: Vec<TokenTransferJson>,
    #[serde(default)]
    next_page_params: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct TokenTransferJson {
    #[serde(alias = "tx_hash")]
    transaction_hash: String,
    timestamp: Option<String>,
    from: AddressRef,
    to: AddressRef,
    total: TokenTotalJson,
    token: TokenRef,
    #[serde(default)]
    method: Option<String>,
}

#[derive(Deserialize)]
struct TokenTotalJson {
    value: Option<String>,
}

#[derive(Deserialize)]
struct TokenRef {
    #[serde(alias = "address")]
    address_hash: String,
}

/// Virements d'une page regroupés par transaction (une transaction peut en
/// contenir plusieurs, un échange par exemple), dans l'ordre de la page.
fn token_moves(items: Vec<TokenTransferJson>, address: &str, contract: &str) -> Result<Vec<TokenMove>> {
    let address = address.to_lowercase();
    let mut moves: Vec<TokenMove> = Vec::new();
    for item in items {
        anyhow::ensure!(item.token.address_hash.eq_ignore_ascii_case(contract), "Blockscout a renvoyé un autre jeton que celui demandé");
        let value: i128 = item
            .total
            .value
            .as_deref()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("montant de virement de jeton Blockscout invalide"))?;
        let delta = match (item.from.hash.to_lowercase() == address, item.to.hash.to_lowercase() == address) {
            (true, false) => -value,
            (false, true) => value,
            _ => 0,
        };
        let swap = item.method.as_deref().is_some_and(is_swap_method);
        match moves.iter_mut().find(|m| m.hash.eq_ignore_ascii_case(&item.transaction_hash)) {
            Some(existing) => {
                existing.net += delta;
                existing.swap |= swap;
            }
            None => moves.push(TokenMove {
                timestamp_unix: item.timestamp.as_deref().and_then(parse_iso8601_utc),
                hash: item.transaction_hash,
                net: delta,
                swap,
            }),
        }
    }
    Ok(moves)
}

/// Curseur `next_page_params` de Blockscout en paramètres de requête.
fn page_params(params: serde_json::Map<String, serde_json::Value>) -> PageParams {
    params
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            (key, value)
        })
        .collect()
}

/// Convertit un horodatage ISO 8601 UTC tel que renvoyé par Blockscout (ex:
/// "2024-01-01T12:00:00.000000Z") en secondes Unix. Le format est fixe (toujours
/// UTC, toujours cette forme), donc un calcul manuel du nombre de jours depuis
/// l'epoch suffit et évite d'ajouter un crate de dates (`chrono`) pour cet unique
/// besoin de parsing.
/// Méthode (nom décodé par Blockscout) d'un swap : dépôt sur le routeur
/// THORChain (depositWithExpiry, celui qu'utilise l'app), ou toute fonction
/// dont le nom contient swap (routeurs d'échange décentralisés).
pub(crate) fn is_swap_method(method: &str) -> bool {
    method == "depositWithExpiry" || method.to_ascii_lowercase().contains("swap")
}

pub(crate) fn parse_iso8601_utc(s: &str) -> Option<i64> {
    let date_part = s.get(0..10)?;
    let time_part = s.get(11..19)?;
    let mut date = date_part.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    let mut time = time_part.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next()?.parse().ok()?;

    Some(civil_to_days(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Nombre de jours écoulés depuis 1970-01-01 pour une date civile donnée
/// (algorithme "civil_to_days" d'Howard Hinnant, valide sur tout le calendrier
/// grégorien) : https://howardhinnant.github.io/date_algorithms.html
fn civil_to_days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iso8601_utc_matches_known_unix_timestamps() {
        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00.000000Z"), Some(0));
        // 2024-01-01T00:00:00Z, vérifié indépendamment (ex: `date -u -d ... +%s`).
        assert_eq!(parse_iso8601_utc("2024-01-01T00:00:00.000000Z"), Some(1_704_067_200));
    }

    /// Méthodes lues sur de vraies transactions (Blockscout) : dépôt THORChain
    /// (0xfce530aa…), paiement THORChain vu du coffre (transferOut, pas un swap
    /// de l'utilisateur), virement de jeton.
    /// Statuts de l'API officielle (documentation du 10/10/2026 : 402 sans
    /// clé, 429 au-delà du débit ou des crédits du jour).
    #[test]
    fn pro_api_replies_are_understood() {
        assert_eq!(pro_reply(StatusCode::OK, Some(99_980), None), ProReply::Ok);
        assert_eq!(pro_reply(StatusCode::TOO_MANY_REQUESTS, Some(5_000), Some(400)), ProReply::RetryAfter(Duration::from_millis(400)));
        assert_eq!(pro_reply(StatusCode::TOO_MANY_REQUESTS, None, Some(2_000)), ProReply::RetryAfter(Duration::from_secs(2)));
        // Crédits épuisés : attendre ne sert à rien avant minuit UTC.
        assert_eq!(pro_reply(StatusCode::TOO_MANY_REQUESTS, Some(0), Some(300)), ProReply::Limited);
        assert_eq!(pro_reply(StatusCode::TOO_MANY_REQUESTS, Some(10), Some(60_000)), ProReply::Limited);
        assert_eq!(pro_reply(StatusCode::TOO_MANY_REQUESTS, None, None), ProReply::Limited);
        assert_eq!(pro_reply(StatusCode::TOO_MANY_REQUESTS, None, Some(-1)), ProReply::Limited);
        for refused in [StatusCode::UNAUTHORIZED, StatusCode::PAYMENT_REQUIRED, StatusCode::FORBIDDEN] {
            assert_eq!(pro_reply(refused, None, None), ProReply::Refused);
        }
        assert_eq!(pro_reply(StatusCode::BAD_GATEWAY, None, None), ProReply::Other(StatusCode::BAD_GATEWAY));
        assert!(unavailable(&anyhow!(BLOCKSCOUT_BLOCKED)) && unavailable(&anyhow!(BLOCKSCOUT_LIMITED)));
        assert!(!unavailable(&anyhow!("appel Blockscout impossible")));
    }

    /// Service réel : Arbitrum (site public bloqué depuis le 10/10/2026) par
    /// l'API officielle avec la clé de l'app — transactions et virements
    /// USDC, pages successives sans doublon ; Base et Polygon (offre payante
    /// exigée) : `BLOCKSCOUT_BLOCKED`, puis plus redemandés.
    /// `cargo test -- --ignored real_blocked_networks_through_pro_api --nocapture`
    #[test]
    #[ignore]
    fn real_blocked_networks_through_pro_api() {
        if API_KEY.is_none() {
            println!("BLOCKSCOUT_API_KEY absente de partner-keys.env : rien à vérifier");
            return;
        }
        for (site, chain) in [("https://base.blockscout.com", 8_453), ("https://polygon.blockscout.com", 137)] {
            let error = BlockscoutClient::new(site, chain).tx_history_page(ME, None).err().expect("offre payante exigée");
            assert_eq!(error.to_string(), BLOCKSCOUT_BLOCKED, "{site}");
            assert!(refused_chains().lock().unwrap().contains(&chain), "{site} : plus redemandé");
            println!("{site} : refusé à l'offre gratuite");
        }
        for (site, chain, usdc) in [("https://arbitrum.blockscout.com", 42_161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831")] {
            let client = BlockscoutClient::new(site, chain);
            let (txs, next) = client.tx_history_page(ME, None).unwrap();
            println!("{site} : {} transactions, suivante {}", txs.len(), next.is_some());
            assert!(!txs.is_empty() && txs.iter().all(|tx| tx.hash.starts_with("0x") && tx.timestamp_unix.is_some()));
            let (second, _) = client.tx_history_page(ME, next.as_ref()).unwrap();
            assert!(second.iter().all(|tx| !txs.iter().any(|t| t.hash == tx.hash)), "pages sans doublon");
            let (moves, _) = client.token_transfers_page(ME, usdc, None).unwrap();
            println!("  USDC : {} mouvements", moves.len());
            println!("  site public bloqué : {}", blocked_sites().lock().unwrap().contains(site));
        }
    }

    #[test]
    fn swap_methods_are_recognised() {
        for swap in ["depositWithExpiry", "swapExactETHForTokens", "swapETHForExactTokens", "multiSwap"] {
            assert!(is_swap_method(swap), "{swap}");
        }
        for other in ["transfer", "approve", "transferOut", "deposit", "execute"] {
            assert!(!is_swap_method(other), "{other}");
        }
    }

    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const ME: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

    fn transfer(hash: &str, from: &str, to: &str, value: &str, token: &str, method: &str) -> String {
        format!(
            r#"{{"transaction_hash":"{hash}","timestamp":"2026-07-19T00:32:23.000000Z","from":{{"hash":"{from}"}},"to":{{"hash":"{to}"}},
               "total":{{"decimals":"6","value":"{value}"}},"token":{{"address_hash":"{token}","symbol":"USDC"}},"method":"{method}","type":"token_transfer"}}"#
        )
    }

    /// Format réel de `token-transfers` (champs relevés sur eth.blockscout.com) :
    /// reçu, envoyé, échange à deux virements regroupés en un mouvement, vers
    /// soi-même ; un autre jeton dans la réponse est refusé.
    #[test]
    fn token_transfers_are_grouped_by_transaction() {
        let other = "0xA916B82Ff122591cC88AaC0D64cE30A8e3e16081";
        let body = format!(
            r#"{{"items":[{},{},{},{},{}],"next_page_params":{{"index":696,"token":"{USDC}","block_number":24433087}}}}"#,
            transfer("0x01", other, ME, "420000", USDC, "0xa9059cbb"),
            transfer("0x02", &ME.to_lowercase(), other, "1000000", USDC, "transfer"),
            transfer("0x03", ME, other, "500", USDC, "swapExactTokensForTokens"),
            transfer("0x03", other, ME, "200", USDC, "swapExactTokensForTokens"),
            transfer("0x04", ME, ME, "7", USDC, "transfer"),
        );
        let resp: TokenTransferListResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(page_params(resp.next_page_params.clone().unwrap()).len(), 3);
        let moves = token_moves(resp.items, ME, &USDC.to_lowercase()).unwrap();
        let summary: Vec<_> = moves.iter().map(|m| (m.hash.as_str(), m.net, m.swap)).collect();
        assert_eq!(summary, vec![("0x01", 420_000, false), ("0x02", -1_000_000, false), ("0x03", -300, true), ("0x04", 0, false)]);
        assert_eq!(moves[0].timestamp_unix, Some(1_784_421_143));

        let fake = format!(r#"{{"items":[{}]}}"#, transfer("0x05", other, ME, "1", "0x0000000000000000000000000000000000000bad", "transfer"));
        let resp: TokenTransferListResponse = serde_json::from_str(&fake).unwrap();
        assert!(token_moves(resp.items, ME, USDC).is_err());
    }

    /// Service réel : virements USDC d'une adresse ordinaire puis d'une
    /// adresse très active (vitalik.eth, ≈ 21 s), tous du bon contrat, pages
    /// successives sans doublon.
    /// `cargo test -- --ignored real_token_transfers --nocapture`
    #[test]
    #[ignore]
    fn real_token_transfers() {
        let client = BlockscoutClient::new("https://eth.blockscout.com", 1);
        for address in ["0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3", ME] {
            let started = std::time::Instant::now();
            let (first, next) = client.token_transfers_page(address, USDC, None).unwrap();
            println!("{address} : {} mouvements en {:?}, suivante {}", first.len(), started.elapsed(), next.is_some());
            for m in first.iter().take(3) {
                println!("  {} {:?} {}", &m.hash[..12], m.timestamp_unix, m.net);
            }
            if let Some(next) = next {
                let (second, _) = client.token_transfers_page(address, USDC, Some(&next)).unwrap();
                assert!(second.iter().all(|m| !first.iter().any(|f| f.hash == m.hash)), "pages sans doublon");
            }
        }
    }
}
