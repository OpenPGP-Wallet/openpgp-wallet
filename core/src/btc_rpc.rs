use crate::btc_tx::Utxo;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::sync::OnceLock;

// Voir eth_rpc::shared_client : un `reqwest::Client` reconstruit à chaque appel de
// commande jette son pool de connexions keep-alive et repaie une poignée de main
// TCP+TLS complète à chaque clic. Un seul client partagé, construit une fois.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// API Esplora publique de Blockstream : pas de clé requise, suffisant pour
/// interroger les UTXOs et diffuser une transaction dans ce PoC. Mainnet et
/// testnet sont deux déploiements distincts de la même API, d'où le champ
/// `base_url` plutôt qu'une constante unique.
pub const ESPLORA_TESTNET_BASE: &str = "https://blockstream.info/testnet/api";
pub const ESPLORA_MAINNET_BASE: &str = "https://blockstream.info/api";

pub struct EsploraClient {
    client: reqwest::blocking::Client,
    base_url: &'static str,
}

#[derive(Deserialize)]
struct UtxoJson {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Deserialize)]
struct UtxoStatus {
    confirmed: bool,
}

#[derive(Deserialize)]
struct AddressTxJson {
    txid: String,
    vin: Vec<VinJson>,
    vout: Vec<VoutJson>,
    status: AddressTxStatusJson,
}

#[derive(Deserialize)]
struct VinJson {
    prevout: Option<PrevoutJson>,
}

#[derive(Deserialize)]
struct PrevoutJson {
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize)]
struct VoutJson {
    scriptpubkey_address: Option<String>,
    value: u64,
    #[serde(default)]
    scriptpubkey: String,
}

#[derive(Deserialize)]
struct AddressTxStatusJson {
    confirmed: bool,
    block_time: Option<i64>,
}

#[derive(Deserialize)]
struct TxoStatsJson {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
    tx_count: u64,
}

#[derive(Deserialize)]
struct AddressStatsJson {
    chain_stats: TxoStatsJson,
    mempool_stats: TxoStatsJson,
}

/// Voir `EsploraClient::address_stats`.
pub struct AddressStats {
    /// Transactions confirmées + en mempool touchant l'adresse.
    pub tx_count: u64,
    /// Solde confirmé + mempool, en satoshis.
    pub balance_sat: i128,
}

pub struct AddressTx {
    pub txid: String,
    pub confirmed: bool,
    pub block_time: Option<i64>,
    /// Positif si `address` a reçu net, négatif si elle a envoyé net, en satoshis —
    /// calculé à partir des vin/vout déjà fournis par Esplora (pas d'appel
    /// supplémentaire nécessaire, contrairement à Solana où le détail par
    /// transaction demande une requête séparée).
    pub net_sat: i128,
    /// Texte de la première sortie OP_RETURN (memo), s'il y en a une lisible
    /// (ex : memo d'un swap THORChain, voir `history`).
    pub memo: Option<String>,
}

/// Données d'un script OP_RETURN, en texte : `OP_RETURN` suivi d'UNE poussée
/// (directe jusqu'à 75 octets, `OP_PUSHDATA1` ou `OP_PUSHDATA2`) couvrant le
/// reste du script. `None` pour tout autre script ou un texte non UTF-8.
fn op_return_text(script_hex: &str) -> Option<String> {
    let script = hex::decode(script_hex).ok()?;
    let (&opcode, rest) = script.strip_prefix(&[0x6a])?.split_first()?;
    let (len, data) = match opcode {
        1..=75 => (opcode as usize, rest),
        0x4c => (*rest.first()? as usize, &rest[1..]),
        0x4d => (u16::from_le_bytes([*rest.first()?, *rest.get(1)?]) as usize, &rest[2..]),
        _ => return None,
    };
    (data.len() == len).then(|| String::from_utf8(data.to_vec()).ok()).flatten()
}

impl EsploraClient {
    /// `base_url` : `ESPLORA_TESTNET_BASE` ou `ESPLORA_MAINNET_BASE` (voir
    /// `api::has_pending_btc`/`get_btc_balance`/`send_btc` pour le choix selon le
    /// réseau demandé par le frontend).
    pub fn new(base_url: &'static str) -> Self {
        Self {
            client: shared_client().clone(),
            base_url,
        }
    }

    /// UTXOs confirmés disponibles pour `address`.
    pub fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        let url = format!("{}/address/{address}/utxo", self.base_url);
        let raw: Vec<UtxoJson> = self
            .client
            .get(&url)
            .send()
            .context("appel esplora /utxo impossible")?
            .json()
            .context("réponse esplora /utxo illisible")?;

        raw.into_iter()
            .filter(|u| u.status.confirmed)
            .map(|u| {
                let bytes = hex::decode(&u.txid).context("txid invalide")?;
                let txid: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow!("txid de taille inattendue"))?;
                Ok(Utxo {
                    txid,
                    vout: u.vout,
                    value_sat: u.value,
                })
            })
            .collect()
    }

    /// `true` si au moins une transaction non confirmée (mempool) touche `address` —
    /// fonds entrants ou sortants pas encore minés. Utilise l'endpoint Esplora dédié
    /// (`/txs/mempool`) plutôt que `address_history` filtré : plus léger, puisqu'il
    /// n'a pas besoin de calculer les montants (vin/vout) de chaque transaction pour
    /// répondre à une simple question oui/non, appelée à chaque rafraîchissement
    /// automatique du solde (voir main.js::refreshBalance).
    pub fn has_mempool_tx(&self, address: &str) -> Result<bool> {
        let url = format!("{}/address/{address}/txs/mempool", self.base_url);
        let raw: Vec<serde_json::Value> = self
            .client
            .get(&url)
            .send()
            .context("appel esplora /txs/mempool impossible")?
            .json()
            .context("réponse esplora /txs/mempool illisible")?;
        Ok(!raw.is_empty())
    }

    /// Historique des transactions (confirmées ou non) touchant `address`, du plus
    /// récent au plus ancien (ordre déjà garanti par Esplora).
    pub fn address_history(&self, address: &str) -> Result<Vec<AddressTx>> {
        let url = format!("{}/address/{address}/txs", self.base_url);
        let raw: Vec<AddressTxJson> = self
            .client
            .get(&url)
            .send()
            .context("appel esplora /txs impossible")?
            .json()
            .context("réponse esplora /txs illisible")?;

        Ok(raw
            .into_iter()
            .map(|tx| {
                let received: i128 = tx
                    .vout
                    .iter()
                    .filter(|o| o.scriptpubkey_address.as_deref() == Some(address))
                    .map(|o| o.value as i128)
                    .sum();
                let sent: i128 = tx
                    .vin
                    .iter()
                    .filter_map(|i| i.prevout.as_ref())
                    .filter(|p| p.scriptpubkey_address.as_deref() == Some(address))
                    .map(|p| p.value as i128)
                    .sum();
                AddressTx {
                    memo: tx.vout.iter().find_map(|o| op_return_text(&o.scriptpubkey)),
                    txid: tx.txid,
                    confirmed: tx.status.confirmed,
                    block_time: tx.status.block_time,
                    net_sat: received - sent,
                }
            })
            .collect())
    }

    /// Nombre total de transactions et solde (confirmé + mempool) de `address` —
    /// un seul appel (`/address/{address}`), sans le détail des transactions.
    /// Sert à prévenir avant un envoi vers une adresse jamais utilisée ou vide
    /// (voir `api::btc_recipient_activity`). Solde calculé en signé : les
    /// dépenses en mempool peuvent dépasser les réceptions en mempool (elles
    /// consomment des sorties déjà confirmées) — constaté sur de vraies adresses.
    pub fn address_stats(&self, address: &str) -> Result<AddressStats> {
        let url = format!("{}/address/{address}", self.base_url);
        let raw: AddressStatsJson = self
            .client
            .get(&url)
            .send()
            .context("appel esplora /address impossible")?
            .json()
            .context("réponse esplora /address illisible")?;
        let balance = |s: &TxoStatsJson| i128::from(s.funded_txo_sum) - i128::from(s.spent_txo_sum);
        Ok(AddressStats {
            tx_count: raw.chain_stats.tx_count.saturating_add(raw.mempool_stats.tx_count),
            balance_sat: balance(&raw.chain_stats) + balance(&raw.mempool_stats),
        })
    }

    /// Transaction brute `txid` (ordre affiché). Aucune confiance accordée au
    /// serveur : l'appelant recalcule le txid de ce qu'il reçoit (voir
    /// `ledger::btc`, qui refuse toute transaction ne correspondant pas à l'UTXO).
    pub fn raw_transaction(&self, txid: &[u8; 32]) -> Result<Vec<u8>> {
        let url = format!("{}/tx/{}/hex", self.base_url, hex::encode(txid));
        let resp = self.client.get(&url).send().context("appel esplora /tx/hex impossible")?;
        anyhow::ensure!(resp.status().is_success(), "transaction {} introuvable sur esplora", hex::encode(txid));
        hex::decode(resp.text().context("réponse esplora /tx/hex illisible")?.trim()).context("transaction brute esplora invalide")
    }

    /// Diffuse une transaction brute (hex-encodée pour l'API) et renvoie son txid.
    pub fn broadcast(&self, raw_tx: &[u8]) -> Result<String> {
        let url = format!("{}/tx", self.base_url);
        let hex_tx = hex::encode(raw_tx);
        let resp = self
            .client
            .post(&url)
            .body(hex_tx)
            .send()
            .context("appel esplora /tx impossible")?;

        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("échec de diffusion de la transaction : {body}"));
        }
        Ok(resp.text().context("réponse esplora /tx illisible")?.trim().to_string())
    }

    /// Tarifs de frais actuels (sat/vByte) par objectif de confirmation (en blocs),
    /// triés par objectif croissant — ex: `[(2, 12.5), (6, 5.0), (144, 1.2)]`. Sert à
    /// proposer un choix rapide/moyen/lent avant l'envoi (voir `api::estimate_btc_fees`).
    /// Frais dictés par le marché sur mainnet (contrairement au testnet, où ils sont
    /// dérisoires) : sans estimation dynamique, une transaction réelle sous-payée
    /// resterait non confirmée indéfiniment.
    pub fn fee_estimates(&self) -> Result<Vec<(u32, f64)>> {
        let url = format!("{}/fee-estimates", self.base_url);
        let raw: std::collections::HashMap<String, f64> = self
            .client
            .get(&url)
            .send()
            .context("appel esplora /fee-estimates impossible")?
            .json()
            .context("réponse esplora /fee-estimates illisible")?;

        let mut estimates: Vec<(u32, f64)> = raw
            .into_iter()
            .filter_map(|(target, rate)| target.parse::<u32>().ok().map(|t| (t, rate)))
            .collect();
        estimates.sort_by_key(|(target, _)| *target);
        Ok(estimates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripts OP_RETURN de vraies transactions THORChain du réseau principal
    /// (lues sur Esplora) : poussée directe (e8bf29df…), `OP_PUSHDATA1`
    /// (990fb6f4…), paiement sortant « OUT: » (909686b5…).
    #[test]
    fn op_return_memos_of_real_transactions_are_read() {
        assert_eq!(
            op_return_text("6a423d3a783a72444466356e47696d3352514e4475536150626d79727848714448676f796e6876563a3435363632313837373830302f302f303a2d5f2f74313a302f3730").as_deref(),
            Some("=:x:rDDf5nGim3RQNDuSaPbmyrxHqDHgoynhvV:456621877800/0/0:-_/t1:0/70")
        );
        assert_eq!(
            op_return_text("6a4c503d3a4554482e555344433a3078643139303266363632613239326362393634614231334546354661344630343541633235386138323a32343438333135303430302f302f303a2d5f2f74313a302f3730").as_deref(),
            Some("=:ETH.USDC:0xd1902f662a292cb964aB13EF5Fa4F045Ac258a82:24483150400/0/0:-_/t1:0/70")
        );
        assert_eq!(
            op_return_text("6a444f55543a32363430324233373338463143463934423431454630423739343645463141423734464239354145463045374137443345423945443636433833443236313636").as_deref(),
            Some("OUT:26402B3738F1CF94B41EF0B7946EF1AB74FB95AEF0E7A7D3EB9ED66C83D26166")
        );
        // Pas un OP_RETURN, longueur incohérente, texte non UTF-8, script vide.
        for bad in ["0014751e76e8199196d454941c45d1b3a323f1433bd6", "6a05616263", "6a02ffff", "", "zz"] {
            assert_eq!(op_return_text(bad), None, "{bad}");
        }
    }
}
