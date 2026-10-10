//! Client pour l'API publique Blockscout (v2), utilisé uniquement pour lister
//! l'historique de transactions EVM d'une adresse : contrairement à Bitcoin
//! (Esplora expose `/address/:address/txs`) et Solana (`getSignaturesForAddress`
//! est une méthode JSON-RPC standard), aucun nœud EVM public n'expose "la liste des
//! transactions d'une adresse" — cette information n'existe que via un indexeur
//! externe. Les instances publiques Blockscout (contrairement à Etherscan) ne
//! demandent aucune clé API, ce qui les rend cohérentes avec Bitcoin/Solana : zéro
//! configuration requise de la part de l'utilisateur.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::sync::OnceLock;

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
    pub fn new(base_url: &'static str) -> Self {
        Self {
            client: shared_client().clone(),
            base_url,
        }
    }

    pub fn tx_history(&self, address: &str, limit: usize) -> Result<Vec<EvmTx>> {
        let (mut txs, _) = self.tx_history_page(address, None)?;
        txs.truncate(limit);
        Ok(txs)
    }

    /// Réponse JSON de `url` ; page de vérification anti-robots (constaté le
    /// 10/10/2026 sur arbitrum.blockscout.com et base.blockscout.com : 403 et
    /// page « Just a moment… » de Cloudflare, quel que soit l'en-tête) :
    /// `BLOCKSCOUT_BLOCKED`, plutôt qu'une réponse « illisible » sans cause.
    fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str, query: &[(String, String)]) -> Result<T> {
        let response = self.client.get(url).query(query).send().context("appel Blockscout impossible")?;
        let html = response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/html"));
        anyhow::ensure!(!(html && response.status() == reqwest::StatusCode::FORBIDDEN), BLOCKSCOUT_BLOCKED);
        response.json().context("réponse Blockscout illisible")
    }

    /// Une page d'historique (50 transactions, de la plus récente à la plus
    /// ancienne) et le curseur de la suivante, `None` après la dernière.
    pub fn tx_history_page(&self, address: &str, page: Option<&PageParams>) -> Result<(Vec<EvmTx>, Option<PageParams>)> {
        let url = format!("{}/api/v2/addresses/{address}/transactions", self.base_url);
        let resp: TxListResponse = self.get_json(&url, page.map(Vec::as_slice).unwrap_or_default())?;

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
        let url = format!("{}/api/v2/addresses/{address}/token-transfers", self.base_url);
        let mut query: PageParams = vec![("type".into(), "ERC-20".into()), ("token".into(), contract.into())];
        if let Some(page) = page {
            query.extend(page.iter().filter(|(key, _)| key != "type" && key != "token").cloned());
        }
        let resp: TokenTransferListResponse = self.get_json(&url, &query)?;
        let moves = token_moves(resp.items, address, contract)?;
        Ok((moves, resp.next_page_params.map(page_params)))
    }
}

/// L'explorateur refuse les requêtes automatiques (page de vérification
/// anti-robots) : historique de ce réseau indisponible tant qu'il le fait.
pub const BLOCKSCOUT_BLOCKED: &str = "l'explorateur de ce réseau refuse pour l'instant les requêtes automatiques : historique indisponible";

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
        let client = BlockscoutClient::new("https://eth.blockscout.com");
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
