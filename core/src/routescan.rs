//! Client de l'API compatible Etherscan de Routescan (`api.routescan.io`),
//! sans clé : historique des transactions et des jetons ERC-20 d'une adresse
//! sur les réseaux qu'aucune instance Blockscout publique ne couvre
//! (Avalanche C-Chain). Même rôle et mêmes garanties que `blockscout` :
//! lecture seule, purement informatif, aucune donnée de l'utilisateur au-delà
//! de l'adresse.
//!
//! Les instances Blockscout offrent la même API (`/api`), plus rapide que leur
//! API v2 pour les virements de jetons, mais limitée sans clé à 10 requêtes
//! par longue période (constaté : quota épuisé, remis à zéro 47 minutes plus
//! tard, sur toutes les instances à la fois) — inutilisable ; l'API v2 en
//! accorde 180 (voir `blockscout`).
//!
//! Même format chez Etherscan (API v2, par identifiant de chaîne), avec la
//! clé de l'utilisateur (`etherscan_key`) : HyperEVM et BNB Chain, qu'aucun
//! service sans clé ne couvre (voir `Api::Etherscan`).

use crate::blockscout::{is_swap_method, EvmTx, TokenMove};
use crate::etherscan_key;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const ROUTESCAN_URL: &str = "https://api.routescan.io/v2/network/mainnet/evm";
const ETHERSCAN_URL: &str = "https://api.etherscan.io/v2/api";
/// Écart minimal entre deux appels à Etherscan : 5 par seconde au plus avec
/// l'offre gratuite (au-delà, refus « Max calls per sec rate limit reached »).
const ETHERSCAN_SPACING: Duration = Duration::from_millis(220);

/// Historique de ce réseau sans clé Etherscan enregistrée.
pub const ETHERSCAN_KEY_MISSING: &str = "historique de ce réseau : ajoutez votre clé Etherscan gratuite dans Paramètres";
/// Clé enregistrée refusée par Etherscan (réponse réelle : « Invalid API Key (#err2) »).
pub const ETHERSCAN_KEY_REFUSED: &str = "Etherscan refuse la clé enregistrée (invalide ou révoquée) — vérifiez-la dans Paramètres";

/// Service compatible Etherscan interrogé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    /// Routescan, sans clé (Avalanche).
    Routescan,
    /// Etherscan, avec la clé de l'utilisateur (HyperEVM avec l'offre
    /// gratuite, BNB Chain avec une offre payante).
    Etherscan,
}

impl Api {
    fn name(self) -> &'static str {
        match self {
            Api::Routescan => "Routescan",
            Api::Etherscan => "Etherscan",
        }
    }
}

/// Réseau couvert par l'offre GRATUITE d'Etherscan ? Pas BNB Chain (56) —
/// liste officielle relevée le 03/10/2026 sur docs.etherscan.io/supported-chains,
/// confirmée par la réponse réelle d'Etherscan (voir `is_paid_plan_refusal`).
pub fn etherscan_free_tier_covers(chain_id: u64) -> bool {
    chain_id != 56
}

/// Refus d'Etherscan pour un réseau que l'offre gratuite ne couvre pas
/// (réponse réelle sur BNB Chain : « Free API access is not supported for
/// this chain. Please upgrade your api plan… »).
pub fn is_paid_plan_refusal(error: &str) -> bool {
    error.contains("Free API access is not supported")
}
/// Transactions par page.
pub const PAGE_SIZE: u32 = 50;
/// Ces API refusent au-delà de 10 000 résultats (page × taille).
const MAX_RESULTS: u32 = 10_000;

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

#[derive(Deserialize)]
struct Response {
    status: String,
    message: String,
    result: serde_json::Value,
}

/// Liste `result` d'une réponse ; adresse sans résultat : liste vide (statut
/// "1", ou "0" selon l'action) ; autre refus : erreur.
fn result_list<T: serde::de::DeserializeOwned>(api: Api, body: &str) -> Result<Vec<T>> {
    let name = api.name();
    let response: Response = serde_json::from_str(body).with_context(|| format!("réponse {name} illisible"))?;
    if response.status != "1" {
        if response.result.as_array().is_some_and(Vec::is_empty) {
            return Ok(Vec::new());
        }
        let detail = response.result.as_str().unwrap_or(&response.message);
        if api == Api::Etherscan && detail.contains("Invalid API Key") {
            bail!(ETHERSCAN_KEY_REFUSED);
        }
        bail!("{name} a refusé la demande : {detail}");
    }
    serde_json::from_value(response.result).with_context(|| format!("réponse {name} illisible"))
}

/// Attend que l'appel précédent à Etherscan date d'au moins `ETHERSCAN_SPACING`.
fn pace_etherscan() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(wait) = last.map(|t| ETHERSCAN_SPACING.saturating_sub(t.elapsed())) {
        std::thread::sleep(wait);
    }
    *last = Some(Instant::now());
}

/// Appel au service. Chez Etherscan, la clé voyage dans l'URL : les erreurs
/// réseau sont reformulées SANS l'URL (`without_url`), pour qu'elle ne finisse
/// jamais dans un message affiché ou journalisé.
fn get(api: Api, chain_id: u64, query: &[(&str, &str)]) -> Result<String> {
    let name = api.name();
    let request = match api {
        Api::Routescan => shared_client().get(format!("{ROUTESCAN_URL}/{chain_id}/etherscan/api")),
        Api::Etherscan => {
            let key = etherscan_key::current().ok_or_else(|| anyhow!(ETHERSCAN_KEY_MISSING))?;
            pace_etherscan();
            shared_client().get(ETHERSCAN_URL).query(&[("chainid", chain_id.to_string()), ("apikey", key)])
        }
    };
    request
        .query(query)
        .send()
        .and_then(|response| response.text())
        .map_err(|e| anyhow!("appel {name} impossible : {}", e.without_url()))
}

/// Numéro de la page suivante, `None` après la dernière (page incomplète ou
/// limite de l'API).
fn next_page(page: u32, len: usize) -> Option<u32> {
    (len == PAGE_SIZE as usize && (page + 1) * PAGE_SIZE <= MAX_RESULTS).then_some(page + 1)
}

fn number(s: &str, what: &str) -> Result<i128> {
    s.parse::<i128>().map_err(|_| anyhow!("{what} invalide dans la réponse de Routescan"))
}

/// Nom de fonction décodé (« swapExactETHForTokens(uint256 amountOutMin, …) ») :
/// la partie avant la parenthèse.
fn method_name(function_name: &str) -> &str {
    function_name.split('(').next().unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJson {
    hash: String,
    time_stamp: String,
    from: String,
    #[serde(default)]
    to: String,
    value: String,
    gas_used: String,
    gas_price: String,
    is_error: String,
    #[serde(default)]
    function_name: String,
}

/// Page `page` (à partir de 1) de l'historique de `address`, de la plus
/// récente à la plus ancienne, et le numéro de la suivante.
pub fn tx_history_page(api: Api, chain_id: u64, address: &str, page: u32) -> Result<(Vec<EvmTx>, Option<u32>)> {
    let page_text = page.to_string();
    let size = PAGE_SIZE.to_string();
    let body = get(
        api,
        chain_id,
        &[("module", "account"), ("action", "txlist"), ("address", address), ("page", &page_text), ("offset", &size), ("sort", "desc")],
    )?;
    let txs = parse_tx_list(api, &body, address)?;
    let next = next_page(page, txs.len());
    Ok((txs, next))
}

/// Réponse `txlist` : montant net et frais du point de vue de `address`
/// (mêmes règles que `BlockscoutClient::tx_history_page`).
fn parse_tx_list(api: Api, body: &str, address: &str) -> Result<Vec<EvmTx>> {
    let address = address.to_lowercase();
    result_list::<TxJson>(api, body)?
        .into_iter()
        .map(|tx| {
            let value = number(&tx.value, "montant")?;
            let sender = tx.from.to_lowercase() == address;
            let receiver = tx.to.to_lowercase() == address;
            let failed = tx.is_error == "1";
            let net_wei = match (failed, sender, receiver) {
                (true, _, _) | (false, true, true) => 0,
                (false, true, false) => -value,
                (false, false, _) => value,
            };
            let fee_wei = if sender { number(&tx.gas_used, "gas")? * number(&tx.gas_price, "prix du gas")? } else { 0 };
            Ok(EvmTx {
                hash: tx.hash,
                timestamp_unix: tx.time_stamp.parse().ok(),
                failed,
                net_wei,
                fee_wei,
                swap: is_swap_method(method_name(&tx.function_name)),
            })
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenTxJson {
    hash: String,
    time_stamp: String,
    from: String,
    to: String,
    value: String,
    contract_address: String,
    #[serde(default)]
    function_name: String,
}

/// Page `page` des virements du jeton ERC-20 `contract` pour `address` (50
/// virements, du plus récent au plus ancien), regroupés par transaction, et
/// le numéro de la suivante. Filtré par contrat côté serveur ET revérifié
/// ici : un faux jeton au même symbole n'y entre jamais.
pub fn token_history_page(api: Api, chain_id: u64, address: &str, contract: &str, page: u32) -> Result<(Vec<TokenMove>, Option<u32>)> {
    let page_text = page.to_string();
    let size = PAGE_SIZE.to_string();
    let body = get(
        api,
        chain_id,
        &[
            ("module", "account"),
            ("action", "tokentx"),
            ("contractaddress", contract),
            ("address", address),
            ("page", &page_text),
            ("offset", &size),
            ("sort", "desc"),
        ],
    )?;
    let transfers: Vec<TokenTxJson> = result_list(api, &body)?;
    let next = next_page(page, transfers.len());
    Ok((token_moves(api, transfers, address, contract)?, next))
}

/// Virements d'une page regroupés par transaction (une transaction peut en
/// contenir plusieurs, un échange par exemple), dans l'ordre de la page.
fn token_moves(api: Api, transfers: Vec<TokenTxJson>, address: &str, contract: &str) -> Result<Vec<TokenMove>> {
    let address = address.to_lowercase();
    let mut moves: Vec<TokenMove> = Vec::new();
    for transfer in transfers {
        anyhow::ensure!(transfer.contract_address.eq_ignore_ascii_case(contract), "{} a renvoyé un autre jeton que celui demandé", api.name());
        let value = number(&transfer.value, "montant de jeton")?;
        let delta = match (transfer.from.to_lowercase() == address, transfer.to.to_lowercase() == address) {
            (true, false) => -value,
            (false, true) => value,
            _ => 0,
        };
        let swap = is_swap_method(method_name(&transfer.function_name));
        match moves.iter_mut().find(|m| m.hash.eq_ignore_ascii_case(&transfer.hash)) {
            Some(existing) => {
                existing.net += delta;
                existing.swap |= swap;
            }
            None => moves.push(TokenMove { timestamp_unix: transfer.time_stamp.parse().ok(), hash: transfer.hash, net: delta, swap }),
        }
    }
    Ok(moves)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0x5d0b3cb43a0bfb7fafde0e3ccba8d6c0c5ec1e3f";

    /// Format réel de `txlist` (champs relevés sur Routescan, réduits) : reçu,
    /// envoyé (frais = gas utilisé × prix), échoué (frais seuls), vers
    /// soi-même ; adresse sans transaction ; refus du service.
    #[test]
    fn tx_list_is_read_from_the_address_point_of_view() {
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[
              {{"hash":"0xa","timeStamp":"1738731709","from":"0xOTHER","to":"{ME}","value":"1000","gasUsed":"21000","gasPrice":"25000000000","isError":"0","functionName":""}},
              {{"hash":"0xb","timeStamp":"1738731700","from":"{ME}","to":"0xother","value":"400","gasUsed":"21000","gasPrice":"2","isError":"0","functionName":"swapExactAVAXForTokens(uint256 amountOutMin, address[] path)"}},
              {{"hash":"0xc","timeStamp":"1738731600","from":"{ME}","to":"0xother","value":"999","gasUsed":"30000","gasPrice":"3","isError":"1","functionName":""}},
              {{"hash":"0xd","timeStamp":"1738731500","from":"{}","to":"{ME}","value":"5","gasUsed":"21000","gasPrice":"1","isError":"0","functionName":""}}
            ]}}"#,
            ME.to_uppercase().replacen("0X", "0x", 1)
        );
        let txs = parse_tx_list(Api::Routescan, &body, ME).unwrap();
        let summary: Vec<_> = txs.iter().map(|t| (t.hash.as_str(), t.net_wei, t.fee_wei, t.failed, t.swap)).collect();
        assert_eq!(
            summary,
            vec![("0xa", 1000, 0, false, false), ("0xb", -400, 42_000, false, true), ("0xc", 0, 90_000, true, false), ("0xd", 0, 21_000, false, false)]
        );
        assert_eq!(txs[0].timestamp_unix, Some(1_738_731_709));
        assert!(parse_tx_list(Api::Routescan, r#"{"status":"0","message":"No transactions found","result":[]}"#, ME).unwrap().is_empty());
        let refused = parse_tx_list(Api::Routescan, r#"{"status":"0","message":"NOTOK","result":"Max rate limit reached"}"#, ME).err().unwrap();
        assert!(refused.to_string().contains("Max rate limit reached"));
    }

    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    fn transfer(hash: &str, from: &str, to: &str, value: &str, contract: &str, function: &str) -> String {
        format!(
            r#"{{"blockNumber":"26079962","timeStamp":"1790646827","hash":"{hash}","from":"{from}","contractAddress":"{contract}","to":"{to}",
               "value":"{value}","tokenName":"USD Coin","tokenSymbol":"USDC","tokenDecimal":"6","functionName":"{function}"}}"#
        )
    }

    /// Format réel de `tokentx` (champs relevés sur Routescan et Blockscout) :
    /// reçu, envoyé, échange à deux virements regroupés en un mouvement, vers
    /// soi-même ; « aucun virement » de Blockscout ; un autre jeton dans la
    /// réponse est refusé.
    #[test]
    fn token_transfers_are_grouped_by_transaction() {
        let other = "0xa916b82ff122591cc88aac0d64ce30a8e3e16081";
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[{},{},{},{},{}]}}"#,
            transfer("0x01", other, ME, "420000", USDC, "transfer(address to, uint256 value)"),
            transfer("0x02", &ME.to_uppercase().replacen("0X", "0x", 1), other, "1000000", USDC, ""),
            transfer("0x03", ME, other, "500", USDC, "swapExactTokensForTokens(uint256 amountIn)"),
            transfer("0x03", other, ME, "200", USDC, "swapExactTokensForTokens(uint256 amountIn)"),
            transfer("0x04", ME, ME, "7", USDC, ""),
        );
        let moves = token_moves(Api::Routescan, result_list(Api::Routescan, &body).unwrap(), ME, &USDC.to_uppercase().replacen("0X", "0x", 1)).unwrap();
        let summary: Vec<_> = moves.iter().map(|m| (m.hash.as_str(), m.net, m.swap)).collect();
        assert_eq!(summary, vec![("0x01", 420_000, false), ("0x02", -1_000_000, false), ("0x03", -300, true), ("0x04", 0, false)]);
        assert_eq!(moves[0].timestamp_unix, Some(1_790_646_827));
        assert!(result_list::<TokenTxJson>(Api::Routescan, r#"{"message":"No token transfers found","result":[],"status":"0"}"#).unwrap().is_empty());

        let fake = format!(r#"{{"status":"1","message":"OK","result":[{}]}}"#, transfer("0x05", other, ME, "1", "0x0000000000000000000000000000000000000bad", ""));
        assert!(token_moves(Api::Routescan, result_list(Api::Routescan, &fake).unwrap(), ME, USDC).is_err());
    }

    /// Etherscan : sans clé, message clair sans appel ; refus réel de l'offre
    /// gratuite sur BNB Chain reconnu ; refus nommé d'après le service.
    #[test]
    fn etherscan_needs_a_key_and_names_its_refusals() {
        if etherscan_key::current().is_none() {
            assert_eq!(get(Api::Etherscan, 999, &[]).unwrap_err().to_string(), ETHERSCAN_KEY_MISSING);
        }
        let paid = r#"{"status":"0","message":"NOTOK","result":"Free API access is not supported for this chain. Please upgrade your api plan for full chain coverage. https://etherscan.io/apis"}"#;
        let error = parse_tx_list(Api::Etherscan, paid, ME).err().expect("refus attendu").to_string();
        assert!(error.starts_with("Etherscan a refusé la demande") && is_paid_plan_refusal(&error), "{error}");
        assert!(!is_paid_plan_refusal("Etherscan a refusé la demande : Max calls per sec rate limit reached (5/sec)"));
        let invalid = r#"{"status":"0","message":"NOTOK","result":"Invalid API Key (#err2)"}"#;
        assert_eq!(parse_tx_list(Api::Etherscan, invalid, ME).err().expect("refus attendu").to_string(), ETHERSCAN_KEY_REFUSED);
    }

    #[test]
    fn pages_stop_when_incomplete_or_at_the_api_limit() {
        assert_eq!(next_page(1, 50), Some(2));
        assert_eq!(next_page(1, 49), None);
        assert_eq!(next_page(200, 50), None, "10 000 résultats au plus");
    }

    /// Service réel : historique Avalanche d'une adresse publique, puis
    /// virements USDC de vitalik.eth (Routescan sert aussi Ethereum : format
    /// `tokentx` vérifié sur une adresse très active), tous du bon contrat,
    /// pages successives sans doublon.
    /// `cargo test -- --ignored real_routescan --nocapture`
    #[test]
    #[ignore]
    fn real_routescan() {
        let (txs, next) = tx_history_page(Api::Routescan, 43114, "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3", 1).unwrap();
        println!("Avalanche : {} transactions, suivante {next:?}", txs.len());
        for tx in txs.iter().take(3) {
            println!("{} {:?} net {} frais {}", &tx.hash[..12], tx.timestamp_unix, tx.net_wei, tx.fee_wei);
        }
        assert!(!txs.is_empty());
        assert!(txs.windows(2).all(|w| w[0].timestamp_unix >= w[1].timestamp_unix), "du plus récent au plus ancien");

        let vitalik = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let (first, next) = token_history_page(Api::Routescan, 1, vitalik, USDC, 1).unwrap();
        println!("USDC vitalik.eth : {} mouvements, suivante {next:?}", first.len());
        for m in first.iter().take(3) {
            println!("{} {:?} {}", &m.hash[..12], m.timestamp_unix, m.net);
        }
        assert!(!first.is_empty());
        let (second, _) = token_history_page(Api::Routescan, 1, vitalik, USDC, next.unwrap()).unwrap();
        assert!(second.iter().all(|m| !first.iter().any(|f| f.hash == m.hash)), "pages sans doublon");
    }
}
