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
    /// en wei.
    pub net_wei: i128,
}

impl BlockscoutClient {
    /// `base_url` : `https://eth.blockscout.com` (mainnet) ou
    /// `https://eth-sepolia.blockscout.com` (Sepolia) — voir `history::evm_history`.
    pub fn new(base_url: &'static str) -> Self {
        Self {
            // Sans timeout explicite, reqwest attend indéfiniment un service qui ne
            // répond jamais, bloquant l'app entière sur cet appel.
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .expect("configuration du client HTTP valide"),
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
                let net_wei = if tx.from.hash.to_lowercase() == address_lower { -value } else { value };
                Ok(EvmTx {
                    hash: tx.hash,
                    timestamp_unix: tx.timestamp.as_deref().and_then(parse_iso8601_utc),
                    failed: tx.status.as_deref() == Some("error"),
                    net_wei,
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
}
