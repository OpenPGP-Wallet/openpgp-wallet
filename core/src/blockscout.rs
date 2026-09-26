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
            .timeout(std::time::Duration::from_secs(20))
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
}

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
        let url = format!("{}/api/v2/addresses/{address}/transactions", self.base_url);
        let resp: TxListResponse = self
            .client
            .get(&url)
            .send()
            .context("appel Blockscout impossible")?
            .json()
            .context("réponse Blockscout illisible")?;

        let address_lower = address.to_lowercase();
        resp.items
            .into_iter()
            .take(limit)
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
            .collect()
    }
}

/// Convertit un horodatage ISO 8601 UTC tel que renvoyé par Blockscout (ex:
/// "2024-01-01T12:00:00.000000Z") en secondes Unix. Le format est fixe (toujours
/// UTC, toujours cette forme), donc un calcul manuel du nombre de jours depuis
/// l'epoch suffit et évite d'ajouter un crate de dates (`chrono`) pour cet unique
/// besoin de parsing.
/// Méthode (nom décodé par Blockscout) d'un swap : dépôt sur le routeur
/// THORChain (depositWithExpiry, celui qu'utilise l'app), ou toute fonction
/// dont le nom contient swap (routeurs d'échange décentralisés).
fn is_swap_method(method: &str) -> bool {
    method == "depositWithExpiry" || method.to_ascii_lowercase().contains("swap")
}

fn parse_iso8601_utc(s: &str) -> Option<i64> {
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
}
