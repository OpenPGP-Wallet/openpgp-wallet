//! Historique de transactions unifié pour les 3 réseaux : chaque source a un
//! format et des garanties différentes (Esplora pour Bitcoin donne déjà les
//! montants dans la même réponse, `getSignaturesForAddress` pour Solana ne donne
//! que des signatures, Blockscout pour Ethereum est le seul indexeur disponible
//! faute de méthode RPC standard) ; ce module les ramène à une seule représentation
//! pour l'UI. Purement informatif : ne joue aucun rôle dans la construction ou la
//! signature d'une transaction, et ne lit ni ne dérive jamais de clé privée.

use crate::blockscout::{BlockscoutClient, EvmTx, PageParams};
use crate::sol_rpc::{SolRpc, SolTx};
use crate::wallet_flow::EvmHistory;
use crate::{btc_rpc::EsploraClient, routescan, wallet_flow};
use anyhow::{anyhow, Result};

pub enum TxStatus {
    Confirmed,
    Pending,
    Failed,
}

/// Nature d'une transaction pour l'adresse interrogée.
#[derive(Debug, PartialEq, Eq)]
pub enum TxKind {
    Received,
    Sent,
    /// Échange (Jupiter, THORChain…), dans un sens ou dans l'autre : le signe
    /// du montant dit si l'actif est parti ou arrivé.
    Swap,
    /// Staking natif Solana (mise, arrêt, retrait) : le signe du montant dit
    /// si les SOL sont partis vers un compte de mise ou en sont revenus.
    Stake,
    /// Aucun montant de l'actif du réseau déplacé (autorisation ou virement de
    /// jeton, appel de contrat, opération payée par un tiers…), ou montant
    /// inconnu — ni envoi ni réception de cet actif.
    Other,
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
    /// Frais payés en plus de `net_amount_minor` (Ethereum : le montant net ne
    /// les inclut pas) ; 0 quand ils y sont déjà (Bitcoin, Solana).
    pub fee_minor: i128,
    pub kind: TxKind,
}

impl TxEntry {
    /// Variation réelle du solde (montant net moins frais), si connue.
    pub fn balance_change(&self) -> Option<i128> {
        self.net_amount_minor.map(|net| net - self.fee_minor)
    }
}

/// Envoi ou réception d'après le signe du montant, sauf swap détecté.
/// Montant nul : « Autre » — constaté sur de vrais historiques (autorisation
/// ERC-20, virement de jeton, opération Solana payée par un tiers), qu'un
/// libellé « Envoyé » aurait présentés à tort comme des envois.
fn classify(net_amount_minor: Option<i128>, swap: bool) -> TxKind {
    match (swap, net_amount_minor) {
        (true, _) => TxKind::Swap,
        (false, Some(net)) if net > 0 => TxKind::Received,
        (false, Some(net)) if net < 0 => TxKind::Sent,
        (false, _) => TxKind::Other,
    }
}

/// Memo d'un swap THORChain (ou Maya, même format) : `SWAP:`, ses alias `=:`
/// et `s:`, et côté réception le paiement `OUT:` ou le remboursement
/// `REFUND:` d'un swap. Formats vérifiés sur de vraies transactions.
pub(crate) fn is_swap_memo(memo: &str) -> bool {
    let memo = memo.trim_start();
    let prefix = memo.split_once(':').map(|(p, _)| p.to_ascii_lowercase());
    matches!(prefix.as_deref(), Some("=" | "s" | "swap" | "out" | "refund"))
}

/// Historique Zcash transparent (voir `zcash::history`).
pub fn zec_history(address: &str) -> Result<Vec<TxEntry>> {
    let crate::zcash::Recipient::P2pkh(hash160) = crate::zcash::parse_recipient(address)? else {
        anyhow::bail!("adresse Zcash du portefeuille attendue (t1…)")
    };
    Ok(crate::zcash::history(address, &hash160)?
        .into_iter()
        .map(|tx| TxEntry {
            kind: classify(Some(tx.net_zat), false),
            id: tx.txid,
            timestamp_unix: tx.time,
            status: if tx.height > 0 { TxStatus::Confirmed } else { TxStatus::Pending },
            net_amount_minor: Some(tx.net_zat),
            fee_minor: 0,
        })
        .collect())
}

pub fn btc_history(network: &wallet_flow::BtcNetwork, address: &str) -> Result<Vec<TxEntry>> {
    btc_history_after(network, address, None)
}

/// Page d'historique Bitcoin : sans `after`, mempool puis 25 transactions
/// confirmées ; avec, les 25 confirmées plus anciennes que le txid `after`.
pub fn btc_history_after(network: &wallet_flow::BtcNetwork, address: &str, after: Option<&str>) -> Result<Vec<TxEntry>> {
    let txs = EsploraClient::new(network.esplora_base).address_history_after(address, after)?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntry {
            kind: classify(Some(tx.net_sat), tx.memo.as_deref().is_some_and(is_swap_memo)),
            id: tx.txid,
            timestamp_unix: tx.block_time,
            status: if tx.confirmed { TxStatus::Confirmed } else { TxStatus::Pending },
            net_amount_minor: Some(tx.net_sat),
            fee_minor: 0,
        })
        .collect())
}

fn sol_entries(txs: Vec<SolTx>) -> Vec<TxEntry> {
    txs.into_iter()
        .map(|tx| TxEntry {
            kind: if tx.stake && !tx.swap { TxKind::Stake } else { classify(tx.net_lamports, tx.swap) },
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
            fee_minor: 0,
        })
        .collect()
}

pub fn sol_history(rpc_url: &str, pubkey_b58: &str, limit: u32) -> Result<Vec<TxEntry>> {
    sol_history_before(rpc_url, pubkey_b58, limit, None)
}

/// Page d'historique Solana : `limit` signatures plus anciennes que `before`.
pub fn sol_history_before(rpc_url: &str, pubkey_b58: &str, limit: u32, before: Option<&str>) -> Result<Vec<TxEntry>> {
    Ok(sol_entries(SolRpc::new(rpc_url).signature_history_before(pubkey_b58, limit, before)?))
}

/// Historique d'un jeton SPL : `ata_b58` est le compte de jetons associé (ATA)
/// du propriétaire pour ce jeton, pas son adresse Solana "propriétaire" — voir
/// `sol_spl::find_associated_token_address` côté appelant (api.rs) pour le
/// dériver. `net_amount_minor` est alors en plus petite unité du jeton, pas
/// en lamports.
pub fn spl_history(rpc_url: &str, ata_b58: &str, limit: u32) -> Result<Vec<TxEntry>> {
    spl_history_before(rpc_url, ata_b58, limit, None)
}

/// Page d'historique d'un jeton SPL : `limit` signatures plus anciennes que `before`.
pub fn spl_history_before(rpc_url: &str, ata_b58: &str, limit: u32, before: Option<&str>) -> Result<Vec<TxEntry>> {
    Ok(sol_entries(SolRpc::new(rpc_url).token_signature_history_before(ata_b58, limit, before)?))
}

/// Suite d'un historique EVM, propre à la source du réseau.
#[derive(Clone, Debug)]
pub enum EvmCursor {
    Blockscout(PageParams),
    /// Numéro de la page suivante (Routescan).
    Page(u32),
}

/// Historique lisible sur `net` : une source existe, et pour Etherscan une
/// clé est enregistrée (voir `etherscan_key`).
pub fn evm_history_available(net: &wallet_flow::EvmNetwork) -> bool {
    match net.history {
        None => false,
        Some(EvmHistory::Etherscan) => crate::etherscan_key::current().is_some(),
        Some(_) => true,
    }
}

/// Source d'historique du réseau EVM `chain_id` (voir `EvmNetwork::history`).
fn evm_source(chain_id: u64) -> Result<EvmHistory> {
    wallet_flow::EVM_NETWORKS
        .iter()
        .find(|n| n.chain_id == chain_id)
        .and_then(|n| n.history)
        .ok_or_else(|| anyhow!("historique pas encore disponible sur ce réseau"))
}

/// `chain_id` : identifiant du réseau EVM (voir `wallet_flow::EVM_NETWORKS`),
/// qui détermine la source interrogée.
pub fn evm_history(chain_id: u64, address: &str, limit: usize) -> Result<Vec<TxEntry>> {
    let (mut entries, _) = evm_history_page(chain_id, address, None)?;
    entries.truncate(limit);
    Ok(entries)
}

/// Page d'historique EVM (50 transactions) et curseur de la suivante, `None`
/// après la dernière.
pub fn evm_history_page(chain_id: u64, address: &str, cursor: Option<&EvmCursor>) -> Result<(Vec<TxEntry>, Option<EvmCursor>)> {
    let (txs, next) = match evm_source(chain_id)? {
        EvmHistory::Blockscout(base_url) => {
            let page = match cursor {
                Some(EvmCursor::Blockscout(params)) => Some(params),
                _ => None,
            };
            let (txs, next) = BlockscoutClient::new(base_url).tx_history_page(address, page)?;
            (txs, next.map(EvmCursor::Blockscout))
        }
        source @ (EvmHistory::Routescan | EvmHistory::Etherscan) => {
            let (txs, next) = routescan::tx_history_page(etherscan_api(source), chain_id, address, page_number(cursor))?;
            (txs, next.map(EvmCursor::Page))
        }
    };
    Ok((txs.into_iter().map(evm_entry).collect(), next))
}

fn evm_entry(tx: EvmTx) -> TxEntry {
    TxEntry {
        kind: classify(Some(tx.net_wei), tx.swap),
        id: tx.hash,
        timestamp_unix: tx.timestamp_unix,
        status: if tx.failed { TxStatus::Failed } else { TxStatus::Confirmed },
        net_amount_minor: Some(tx.net_wei),
        fee_minor: tx.fee_wei,
    }
}

/// Page d'historique du jeton ERC-20 `contract` pour `address` sur le réseau
/// `chain_id` (montants en plus petite unité du jeton, aucun frais : ils
/// sont payés dans la monnaie du réseau), via la source du réseau.
pub fn erc20_history_page(chain_id: u64, address: &str, contract: &str, cursor: Option<&EvmCursor>) -> Result<(Vec<TxEntry>, Option<EvmCursor>)> {
    let (moves, next) = match evm_source(chain_id)? {
        EvmHistory::Blockscout(base_url) => {
            let page = match cursor {
                Some(EvmCursor::Blockscout(params)) => Some(params),
                _ => None,
            };
            let (moves, next) = BlockscoutClient::new(base_url).token_transfers_page(address, contract, page)?;
            (moves, next.map(EvmCursor::Blockscout))
        }
        source @ (EvmHistory::Routescan | EvmHistory::Etherscan) => {
            let (moves, next) = routescan::token_history_page(etherscan_api(source), chain_id, address, contract, page_number(cursor))?;
            (moves, next.map(EvmCursor::Page))
        }
    };
    let entries = moves
        .into_iter()
        .map(|m| TxEntry {
            kind: classify(Some(m.net), m.swap),
            id: m.hash,
            timestamp_unix: m.timestamp_unix,
            // Un virement de jeton n'existe que dans une transaction réussie.
            status: TxStatus::Confirmed,
            net_amount_minor: Some(m.net),
            fee_minor: 0,
        })
        .collect();
    Ok((entries, next))
}

/// Service compatible Etherscan d'une source d'historique.
fn etherscan_api(source: EvmHistory) -> routescan::Api {
    match source {
        EvmHistory::Etherscan => routescan::Api::Etherscan,
        _ => routescan::Api::Routescan,
    }
}

/// Page demandée par `cursor` (la première sans curseur).
fn page_number(cursor: Option<&EvmCursor>) -> u32 {
    match cursor {
        Some(EvmCursor::Page(page)) => *page,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memos de vraies transactions THORChain (Bitcoin, Solana) : dépôts de
    /// swap et paiements ; d'autres memos ne sont pas des swaps.
    #[test]
    fn thorchain_swap_memos_are_recognised() {
        for memo in [
            "=:x:rDDf5nGim3RQNDuSaPbmyrxHqDHgoynhvV:456621877800/0/0:-_/t1:0/70",
            "=:ETH.USDC:0xd1902f662a292cb964aB13EF5Fa4F045Ac258a82:24483150400/0/0:-_/t1:0/70",
            "=:BSC.USDT:0xd63678741D8e155e337c0Fe35cE143886fA04750",
            "OUT:26402B3738F1CF94B41EF0B7946EF1AB74FB95AEF0E7A7D3EB9ED66C83D26166",
            "SWAP:ETH.ETH:0xabc",
            "s:BTC.BTC:bc1q",
            "REFUND:ABCDEF",
        ] {
            assert!(is_swap_memo(memo), "{memo}");
        }
        for memo in ["+:BTC.BTC", "hello", "", "outil:rien", "=", "ADD:BTC.BTC"] {
            assert!(!is_swap_memo(memo), "{memo}");
        }
    }

    /// Historiques RÉELS d'adresses repérées dans l'index public de THORChain
    /// (Midgard) : chaque transaction connue comme swap doit être classée
    /// « Swap » (dépôt ou paiement), sur les trois réseaux.
    /// `cargo test -- --ignored real_histories_classify_known_thorchain_swaps --nocapture`
    #[test]
    #[ignore]
    fn real_histories_classify_known_thorchain_swaps() {
        let show = |label: &str, entries: &[TxEntry]| {
            println!("--- {label}");
            for e in entries.iter().take(8) {
                println!("{:?} {:?} {}", e.kind, e.net_amount_minor, &e.id[..16]);
            }
        };
        fn find<'a>(entries: &'a [TxEntry], id: &str) -> Option<&'a TxKind> {
            entries.iter().find(|e| e.id.eq_ignore_ascii_case(id)).map(|e| &e.kind)
        }

        let btc = btc_history(&wallet_flow::BTC_MAINNET, "bc1qwqap30shafhtfd0k5hda4xep6xypgm6fyvphnw").unwrap();
        show("BTC destinataire d'un paiement THORChain", &btc);
        assert_eq!(find(&btc, "909686b5b485c49ab270ea0b86d6c981129b6b67ac4ce5c333a722fa2fb6796c"), Some(&TxKind::Swap));

        let eth = evm_history(1, "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3", 50).unwrap();
        show("ETH déposant THORChain", &eth);
        assert_eq!(find(&eth, "0xfce530aa6e05ccc95df9e6bd3f660966d48233458a3a1fa4e089c080a62c5387"), Some(&TxKind::Swap));

        let sol = sol_history(wallet_flow::SOLANA_MAINNET.rpc, "3iUShJYbFX6it5ArcR31Pm6SqqowccAe5NwQrfaG1yvG", 25).unwrap();
        show("SOL destinataire d'un paiement THORChain", &sol);
        assert_eq!(find(&sol, "4HuniHVGia6nAXvdMXVWdwvcBg9z5ehjjvha9MYrq1K121btuuaCUV9XzK8qHmPs28inzFEanrZ2BUQh2is55vb8"), Some(&TxKind::Swap));
    }

    #[test]
    fn kind_follows_the_amount_unless_it_is_a_swap() {
        assert_eq!(classify(Some(5), false), TxKind::Received);
        assert_eq!(classify(Some(-5), false), TxKind::Sent);
        assert_eq!(classify(Some(0), false), TxKind::Other, "aucun montant de l'actif déplacé");
        assert_eq!(classify(Some(-5), true), TxKind::Swap);
        assert_eq!(classify(Some(5), true), TxKind::Swap);
        assert_eq!(classify(None, false), TxKind::Other);
        assert_eq!(classify(None, true), TxKind::Swap);
    }
}
