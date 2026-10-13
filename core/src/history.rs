//! Unified transaction history across networks. Each source has a different format
//! and different guarantees (Esplora for Bitcoin already gives the amounts in the
//! same response, Solana's `getSignaturesForAddress` only gives signatures,
//! Blockscout for Ethereum is the only indexer available since there is no standard
//! RPC method); this module brings them down to a single representation for the UI.
//! Purely informative: plays no part in building or signing a transaction, and
//! never reads or derives a private key.

use crate::blockscout::{BlockscoutClient, EvmTx, PageParams};
use crate::sol_rpc::{SolRpc, SolTx};
use crate::wallet_flow::EvmHistory;
use crate::{btc_rpc::EsploraClient, nodereal, routescan, wallet_flow};
use anyhow::{anyhow, Result};

pub enum TxStatus {
    Confirmed,
    Pending,
    Failed,
}

/// Kind of a transaction for the queried address.
#[derive(Debug, PartialEq, Eq)]
pub enum TxKind {
    Received,
    Sent,
    /// Swap (Jupiter, THORChain...), in either direction: the sign of the amount says
    /// whether the asset left or arrived.
    Swap,
    /// Native Solana staking (stake, deactivate, withdraw): the sign of the amount says
    /// whether the SOL went to a stake account or came back from one.
    Stake,
    /// No amount of the network's asset moved (token approval or transfer, contract
    /// call, an operation paid by someone else...), or an unknown amount: neither a
    /// send nor a receipt of that asset.
    Other,
}

pub struct TxEntry {
    /// Identifier to display and to use in the explorer link (Bitcoin txid, Solana
    /// signature, Ethereum hash).
    pub id: String,
    pub timestamp_unix: Option<i64>,
    pub status: TxStatus,
    /// Signed, in the network's minor unit (satoshis / lamports / wei): positive if the
    /// queried address received net, negative if it sent net. `None` when the amount
    /// could not be determined (see `sol_rpc::SolTx::net_lamports`): the entry can
    /// still be shown without an amount.
    pub net_amount_minor: Option<i128>,
    /// Fee paid on top of `net_amount_minor` (Ethereum: the net amount does not include
    /// it); 0 when it is already included (Bitcoin, Solana).
    pub fee_minor: i128,
    pub kind: TxKind,
}

impl TxEntry {
    /// Actual balance change (net amount minus fee), if known.
    pub fn balance_change(&self) -> Option<i128> {
        self.net_amount_minor.map(|net| net - self.fee_minor)
    }
}

/// Send or receipt from the sign of the amount, unless a swap was detected. A zero
/// amount is "Other": seen in real histories (ERC-20 approval, token transfer, a
/// Solana operation paid by someone else), which a "Sent" label would have wrongly
/// presented as sends.
fn classify(net_amount_minor: Option<i128>, swap: bool) -> TxKind {
    match (swap, net_amount_minor) {
        (true, _) => TxKind::Swap,
        (false, Some(net)) if net > 0 => TxKind::Received,
        (false, Some(net)) if net < 0 => TxKind::Sent,
        (false, _) => TxKind::Other,
    }
}

/// THORChain (or Maya, same format) swap memo: `SWAP:`, its aliases `=:` and `s:`,
/// and on the receiving side a swap's `OUT:` payment or `REFUND:`. Formats checked
/// on real transactions.
pub(crate) fn is_swap_memo(memo: &str) -> bool {
    let memo = memo.trim_start();
    let prefix = memo.split_once(':').map(|(p, _)| p.to_ascii_lowercase());
    matches!(
        prefix.as_deref(),
        Some("=" | "s" | "swap" | "out" | "refund")
    )
}

/// Transparent Zcash history (see `zcash::history`).
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
            status: if tx.height > 0 {
                TxStatus::Confirmed
            } else {
                TxStatus::Pending
            },
            net_amount_minor: Some(tx.net_zat),
            fee_minor: 0,
        })
        .collect())
}

pub fn btc_history(network: &wallet_flow::BtcNetwork, address: &str) -> Result<Vec<TxEntry>> {
    btc_history_after(network, address, None)
}

/// Page of Bitcoin history: without `after`, the mempool then 25 confirmed
/// transactions; with it, the 25 confirmed transactions older than txid `after`.
pub fn btc_history_after(
    network: &wallet_flow::BtcNetwork,
    address: &str,
    after: Option<&str>,
) -> Result<Vec<TxEntry>> {
    let txs = EsploraClient::new(network.esplora_base).address_history_after(address, after)?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntry {
            kind: classify(
                Some(tx.net_sat),
                tx.memo.as_deref().is_some_and(is_swap_memo),
            ),
            id: tx.txid,
            timestamp_unix: tx.block_time,
            status: if tx.confirmed {
                TxStatus::Confirmed
            } else {
                TxStatus::Pending
            },
            net_amount_minor: Some(tx.net_sat),
            fee_minor: 0,
        })
        .collect())
}

fn sol_entries(txs: Vec<SolTx>) -> Vec<TxEntry> {
    txs.into_iter()
        .map(|tx| TxEntry {
            kind: if tx.stake && !tx.swap {
                TxKind::Stake
            } else {
                classify(tx.net_lamports, tx.swap)
            },
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

/// Page of Solana history: `limit` signatures older than `before`.
pub fn sol_history_before(
    rpc_url: &str,
    pubkey_b58: &str,
    limit: u32,
    before: Option<&str>,
) -> Result<Vec<TxEntry>> {
    Ok(sol_entries(
        SolRpc::new(rpc_url).signature_history_before(pubkey_b58, limit, before)?,
    ))
}

/// History of an SPL token: `ata_b58` is the owner's associated token account (ATA)
/// for that token, not their "owner" Solana address; see
/// `sol_spl::find_associated_token_address` on the caller's side (api.rs) to derive
/// it. `net_amount_minor` is then in the token's smallest unit, not in lamports.
pub fn spl_history(rpc_url: &str, ata_b58: &str, limit: u32) -> Result<Vec<TxEntry>> {
    spl_history_before(rpc_url, ata_b58, limit, None)
}

/// Page of an SPL token's history: `limit` signatures older than `before`.
pub fn spl_history_before(
    rpc_url: &str,
    ata_b58: &str,
    limit: u32,
    before: Option<&str>,
) -> Result<Vec<TxEntry>> {
    Ok(sol_entries(
        SolRpc::new(rpc_url).token_signature_history_before(ata_b58, limit, before)?,
    ))
}

/// Continuation of an EVM history, specific to the network's source.
#[derive(Clone, Debug)]
pub enum EvmCursor {
    Blockscout(PageParams),
    /// Next page number (Routescan).
    Page(u32),
    /// NodeReal continuation (BNB Chain): both directions, and what is left to return.
    NodeReal(nodereal::Cursor),
    /// Alchemy continuation (Base, Polygon), same shape as NodeReal's.
    Alchemy(nodereal::Cursor),
}

/// History readable on `net`: a source exists, and for NodeReal the key is built
/// into this version of the app.
pub fn evm_history_available(net: &wallet_flow::EvmNetwork) -> bool {
    match net.history {
        None => false,
        Some(EvmHistory::NodeReal) => nodereal::available(),
        Some(EvmHistory::Alchemy) => crate::alchemy::available(net.chain_id),
        Some(_) => true,
    }
}

/// History source of EVM network `chain_id` (see `EvmNetwork::history`).
fn evm_source(chain_id: u64) -> Result<EvmHistory> {
    wallet_flow::EVM_NETWORKS
        .iter()
        .find(|n| n.chain_id == chain_id)
        .and_then(|n| n.history)
        .ok_or_else(|| anyhow!("historique pas encore disponible sur ce réseau"))
}

/// `chain_id`: EVM network identifier (see `wallet_flow::EVM_NETWORKS`), which
/// decides the source queried.
pub fn evm_history(chain_id: u64, address: &str, limit: usize) -> Result<Vec<TxEntry>> {
    let (mut entries, _) = evm_history_page(chain_id, address, None)?;
    entries.truncate(limit);
    Ok(entries)
}

/// Page of EVM history (50 transactions) and the cursor of the next one, `None`
/// after the last.
pub fn evm_history_page(
    chain_id: u64,
    address: &str,
    cursor: Option<&EvmCursor>,
) -> Result<(Vec<TxEntry>, Option<EvmCursor>)> {
    let (txs, next) = match evm_source(chain_id)? {
        EvmHistory::Blockscout(base_url) => {
            let page = match cursor {
                Some(EvmCursor::Blockscout(params)) => Some(params),
                _ => None,
            };
            let (txs, next) =
                BlockscoutClient::new(base_url, chain_id).tx_history_page(address, page)?;
            (txs, next.map(EvmCursor::Blockscout))
        }
        EvmHistory::Routescan => {
            let (txs, next) = routescan::tx_history_page(chain_id, address, page_number(cursor))?;
            (txs, next.map(EvmCursor::Page))
        }
        EvmHistory::NodeReal => {
            let (txs, next) = nodereal::tx_history_page(address, nodereal_cursor(cursor))?;
            (txs, next.map(EvmCursor::NodeReal))
        }
        EvmHistory::Alchemy => {
            let (txs, next) =
                crate::alchemy::tx_history_page(chain_id, address, alchemy_cursor(cursor))?;
            (txs, next.map(EvmCursor::Alchemy))
        }
    };
    Ok((txs.into_iter().map(evm_entry).collect(), next))
}

fn evm_entry(tx: EvmTx) -> TxEntry {
    TxEntry {
        kind: classify(Some(tx.net_wei), tx.swap),
        id: tx.hash,
        timestamp_unix: tx.timestamp_unix,
        status: if tx.failed {
            TxStatus::Failed
        } else {
            TxStatus::Confirmed
        },
        net_amount_minor: Some(tx.net_wei),
        fee_minor: tx.fee_wei,
    }
}

/// Page of the history of ERC-20 token `contract` for `address` on network
/// `chain_id` (amounts in the token's smallest unit, no fee: it is paid in the
/// network's coin), through the network's source.
pub fn erc20_history_page(
    chain_id: u64,
    address: &str,
    contract: &str,
    cursor: Option<&EvmCursor>,
) -> Result<(Vec<TxEntry>, Option<EvmCursor>)> {
    let (moves, next) = match evm_source(chain_id)? {
        EvmHistory::Blockscout(base_url) => {
            let page = match cursor {
                Some(EvmCursor::Blockscout(params)) => Some(params),
                _ => None,
            };
            let (moves, next) = BlockscoutClient::new(base_url, chain_id)
                .token_transfers_page(address, contract, page)?;
            (moves, next.map(EvmCursor::Blockscout))
        }
        EvmHistory::Routescan => {
            let (moves, next) =
                routescan::token_history_page(chain_id, address, contract, page_number(cursor))?;
            (moves, next.map(EvmCursor::Page))
        }
        EvmHistory::NodeReal => {
            let (moves, next) =
                nodereal::token_history_page(address, contract, nodereal_cursor(cursor))?;
            (moves, next.map(EvmCursor::NodeReal))
        }
        EvmHistory::Alchemy => {
            let (moves, next) = crate::alchemy::token_history_page(
                chain_id,
                address,
                contract,
                alchemy_cursor(cursor),
            )?;
            (moves, next.map(EvmCursor::Alchemy))
        }
    };
    let entries = moves
        .into_iter()
        .map(|m| TxEntry {
            kind: classify(Some(m.net), m.swap),
            id: m.hash,
            timestamp_unix: m.timestamp_unix,
            // A token transfer only exists in a successful transaction.
            status: TxStatus::Confirmed,
            net_amount_minor: Some(m.net),
            fee_minor: 0,
        })
        .collect();
    Ok((entries, next))
}

/// Alchemy continuation requested by `cursor` (the first page without one).
fn alchemy_cursor(cursor: Option<&EvmCursor>) -> Option<&nodereal::Cursor> {
    match cursor {
        Some(EvmCursor::Alchemy(next)) => Some(next),
        _ => None,
    }
}

/// NodeReal continuation requested by `cursor` (the first page without one).
fn nodereal_cursor(cursor: Option<&EvmCursor>) -> Option<&nodereal::Cursor> {
    match cursor {
        Some(EvmCursor::NodeReal(next)) => Some(next),
        _ => None,
    }
}

/// Page requested by `cursor` (the first one without a cursor).
fn page_number(cursor: Option<&EvmCursor>) -> u32 {
    match cursor {
        Some(EvmCursor::Page(page)) => *page,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memos from real THORChain transactions (Bitcoin, Solana): swap deposits and
    /// payments; other memos are not swaps.
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

    /// REAL histories of addresses found in THORChain's public index (Midgard): every
    /// transaction known to be a swap must be classified "Swap" (deposit or payment), on
    /// all three networks.
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
            entries
                .iter()
                .find(|e| e.id.eq_ignore_ascii_case(id))
                .map(|e| &e.kind)
        }

        // The address is still receiving: the known transaction moves back page after page
        // (observed on 2026-10-07), so a few pages are walked through.
        let mut btc = btc_history(
            &wallet_flow::BTC_MAINNET,
            "bc1qwqap30shafhtfd0k5hda4xep6xypgm6fyvphnw",
        )
        .unwrap();
        for _ in 0..6 {
            if find(
                &btc,
                "909686b5b485c49ab270ea0b86d6c981129b6b67ac4ce5c333a722fa2fb6796c",
            )
            .is_some()
            {
                break;
            }
            let Some(last) = btc.last().map(|e| e.id.clone()) else {
                break;
            };
            btc.extend(
                btc_history_after(
                    &wallet_flow::BTC_MAINNET,
                    "bc1qwqap30shafhtfd0k5hda4xep6xypgm6fyvphnw",
                    Some(&last),
                )
                .unwrap(),
            );
        }
        show("BTC destinataire d'un paiement THORChain", &btc);
        assert_eq!(
            find(
                &btc,
                "909686b5b485c49ab270ea0b86d6c981129b6b67ac4ce5c333a722fa2fb6796c"
            ),
            Some(&TxKind::Swap)
        );

        let eth = evm_history(1, "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3", 50).unwrap();
        show("ETH déposant THORChain", &eth);
        assert_eq!(
            find(
                &eth,
                "0xfce530aa6e05ccc95df9e6bd3f660966d48233458a3a1fa4e089c080a62c5387"
            ),
            Some(&TxKind::Swap)
        );

        let sol = sol_history(
            wallet_flow::SOLANA_MAINNET.rpc,
            "3iUShJYbFX6it5ArcR31Pm6SqqowccAe5NwQrfaG1yvG",
            25,
        )
        .unwrap();
        show("SOL destinataire d'un paiement THORChain", &sol);
        assert_eq!(find(&sol, "4HuniHVGia6nAXvdMXVWdwvcBg9z5ehjjvha9MYrq1K121btuuaCUV9XzK8qHmPs28inzFEanrZ2BUQh2is55vb8"), Some(&TxKind::Swap));
    }

    #[test]
    fn kind_follows_the_amount_unless_it_is_a_swap() {
        assert_eq!(classify(Some(5), false), TxKind::Received);
        assert_eq!(classify(Some(-5), false), TxKind::Sent);
        assert_eq!(
            classify(Some(0), false),
            TxKind::Other,
            "aucun montant de l'actif déplacé"
        );
        assert_eq!(classify(Some(-5), true), TxKind::Swap);
        assert_eq!(classify(Some(5), true), TxKind::Swap);
        assert_eq!(classify(None, false), TxKind::Other);
        assert_eq!(classify(None, true), TxKind::Swap);
    }
}
