//! Historique de transactions unifié pour les 3 réseaux : chaque source a un
//! format et des garanties différentes (Esplora pour Bitcoin donne déjà les
//! montants dans la même réponse, `getSignaturesForAddress` pour Solana ne donne
//! que des signatures, Blockscout pour Ethereum est le seul indexeur disponible
//! faute de méthode RPC standard) ; ce module les ramène à une seule représentation
//! pour l'UI. Purement informatif : ne joue aucun rôle dans la construction ou la
//! signature d'une transaction, et ne lit ni ne dérive jamais de clé privée.

use crate::{blockscout::BlockscoutClient, btc_rpc::EsploraClient, sol_rpc::SolRpc, wallet_flow};
use anyhow::Result;

pub enum TxStatus {
    Confirmed,
    Pending,
    Failed,
}

pub struct TxEntry {
    /// Identifiant à afficher et à utiliser dans le lien vers l'explorateur (txid
    /// Bitcoin, signature Solana, hash Ethereum).
    pub id: String,
    pub timestamp_unix: Option<i64>,
    pub status: TxStatus,
    /// Signé, dans l'unité mineure du réseau (satoshis / lamports / wei) :
    /// positif si l'adresse interrogée a reçu net, négatif si elle a envoyé net.
    /// `None` quand le montant n'a pas pu être déterminé (voir
    /// `sol_rpc::SolTx::net_lamports`) — l'entrée reste affichable sans montant.
    pub net_amount_minor: Option<i128>,
}

pub fn btc_history(network: &wallet_flow::BtcNetwork, address: &str) -> Result<Vec<TxEntry>> {
    let txs = EsploraClient::new(network.esplora_base).address_history(address)?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntry {
            id: tx.txid,
            timestamp_unix: tx.block_time,
            status: if tx.confirmed { TxStatus::Confirmed } else { TxStatus::Pending },
            net_amount_minor: Some(tx.net_sat),
        })
        .collect())
}

pub fn sol_history(rpc_url: &str, pubkey_b58: &str, limit: u32) -> Result<Vec<TxEntry>> {
    let txs = SolRpc::new(rpc_url).signature_history(pubkey_b58, limit)?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntry {
            id: tx.signature,
            timestamp_unix: tx.block_time,
            status: if tx.failed {
                TxStatus::Failed
            } else if tx.confirmed {
                TxStatus::Confirmed
            } else {
                TxStatus::Pending
            },
            net_amount_minor: tx.net_lamports,
        })
        .collect())
}

/// Historique d'un jeton SPL (USDC) : `ata_b58` est le compte de jetons associé
/// (ATA) du propriétaire, pas son adresse Solana "propriétaire" — voir
/// `sol_spl::find_associated_token_address` côté appelant (api.rs) pour le
/// dériver. `net_amount_minor` est alors en plus petite unité du jeton
/// (micro-USDC), pas en lamports.
pub fn usdc_history(rpc_url: &str, ata_b58: &str, limit: u32) -> Result<Vec<TxEntry>> {
    let txs = SolRpc::new(rpc_url).token_signature_history(ata_b58, limit)?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntry {
            id: tx.signature,
            timestamp_unix: tx.block_time,
            status: if tx.failed {
                TxStatus::Failed
            } else if tx.confirmed {
                TxStatus::Confirmed
            } else {
                TxStatus::Pending
            },
            net_amount_minor: tx.net_lamports,
        })
        .collect())
}

/// `chain_id` : 1 pour Ethereum mainnet, 11155111 pour Sepolia (voir
/// wallet_flow::ETHEREUM_MAINNET / SEPOLIA) — détermine quelle instance publique
/// Blockscout interroger.
pub fn evm_history(chain_id: u64, address: &str, limit: usize) -> Result<Vec<TxEntry>> {
    let base_url = match chain_id {
        1 => "https://eth.blockscout.com",
        11155111 => "https://eth-sepolia.blockscout.com",
        other => anyhow::bail!("historique EVM non pris en charge pour chain_id={other}"),
    };
    let txs = BlockscoutClient::new(base_url).tx_history(address, limit)?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntry {
            id: tx.hash,
            timestamp_unix: tx.timestamp_unix,
            status: if tx.failed { TxStatus::Failed } else { TxStatus::Confirmed },
            net_amount_minor: Some(tx.net_wei),
        })
        .collect())
}
