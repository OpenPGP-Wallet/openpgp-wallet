//! Read-only external wallets: track the balance of addresses that do NOT belong to
//! this wallet (friends', other accounts...) by simply pasting their public
//! address. No private key and no secret is ever involved here, only public
//! addresses and labels, the same sensitivity as `messaging::Recipient` (the
//! recipient book). The balance itself comes from the existing `get_balance` Tauri
//! command (the same read-only RPC calls as for the wallet's profiles): nothing new
//! to build on the network side.

use crate::{derivation, wallet_flow};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const EXTERNAL_WALLETS_FILE: &str = "external_wallets.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct ExternalWallet {
    pub id: u32,
    pub label: String,
    /// One of the network identifiers already used elsewhere in the app:
    /// "evm_mainnet"/"evm_sepolia"/"btc_mainnet"/"btc_testnet"/"sol_mainnet"/"sol_devnet".
    pub network: String,
    pub address: String,
    /// `None`: ungrouped wallet, shown separately.
    pub group_id: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExternalWalletGroup {
    pub id: u32,
    pub name: String,
}

#[derive(Serialize, Deserialize, Default)]
struct ExternalWalletsData {
    wallets: Vec<ExternalWallet>,
    groups: Vec<ExternalWalletGroup>,
}

fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(EXTERNAL_WALLETS_FILE)
}

fn load(data_dir: &Path) -> ExternalWalletsData {
    std::fs::read_to_string(path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(data_dir: &Path, data: &ExternalWalletsData) -> Result<()> {
    let content =
        serde_json::to_string_pretty(data).context("sérialisation des wallets externes")?;
    std::fs::write(path(data_dir), content).context("écriture des wallets externes")
}

/// Validates the address format for the given network before saving it: better to
/// fail right away with a clear message than to discover an invalid address later
/// through the generic failure of an RPC call. Reuses exactly the same parsers as
/// the rest of the app (no new address validation logic).
pub(crate) fn validate_address(network: &str, address: &str) -> Result<()> {
    match network {
        // Every EVM network (Ethereum, L2s, BNB Chain...): same address format.
        n if wallet_flow::evm_network(n).is_some() => {
            wallet_flow::parse_evm_address(address)?;
        }
        // Any standard address type (1..., 3..., bc1q..., bc1p...): the ones the app can
        // pay.
        "btc_mainnet" => {
            derivation::btc_mainnet_recipient_script(address)?;
        }
        "btc_testnet" => {
            derivation::btc_testnet_recipient_script(address)?;
        }
        // "usdc_solana": same address format as "sol_*" (the address is always the
        // owner's; the USDC token account that actually holds the funds is an invisible
        // detail derived on the Rust side, see sol_spl.rs). Mainnet only, as for this
        // app's own wallet (no devnet USDC mint verified with confidence).
        "sol_mainnet" | "sol_devnet" | "usdc_solana" => {
            let bytes = bs58::decode(address.trim())
                .into_vec()
                .context("adresse Solana invalide (base58 attendu)")?;
            anyhow::ensure!(bytes.len() == 32, "une adresse Solana fait 32 octets");
        }
        // Transparent Zcash (t1, t3, tex1); shielded addresses rejected. Without this
        // branch, the portfolio chart (which validates every holding) failed as soon as
        // the Zcash card was shown.
        "zec_mainnet" => {
            crate::zcash::parse_recipient(address)?;
        }
        // Monero (mainnet address): same reason, for the Monero card.
        "xmr_mainnet" => {
            crate::monero::parse_recipient(address)?;
        }
        // Dogecoin (D..., or P2SH).
        "doge_mainnet" => {
            crate::doge::parse_recipient(address)?;
        }
        // Tron (T...).
        "tron_mainnet" => {
            crate::tron::parse_address(address)?;
        }
        // XRP Ledger (r...).
        "xrp_mainnet" => {
            crate::xrp::parse_address(address)?;
        }
        // Stellar (G...).
        "xlm_mainnet" => {
            crate::stellar::parse_address(address)?;
        }
        // NEAR (implicit or named account).
        "near_mainnet" => {
            crate::near::parse_account(address)?;
        }
        // Cardano (addr1...).
        "ada_mainnet" => {
            crate::cardano::parse_address(address)?;
        }
        // Stacks (SP...).
        "stx_mainnet" => {
            crate::stacks::parse_address(&crate::stacks::MAINNET, address)?;
        }
        // Bittensor (5..., SS58 format 42).
        "tao_mainnet" => {
            crate::bittensor::parse_address(address)?;
        }
        // Shielded Zcash (the u1 address of the "Shielded Zcash" card).
        "zec_shielded" => {
            crate::zcash_shielded::parse_shielded_address(address)?;
        }
        other => anyhow::bail!("réseau inconnu : {other}"),
    }
    Ok(())
}

/// Wallets tracked on the app's networks; those of a removed network (HyperEVM, on
/// 2026-10-07) stay in the file without being shown.
pub fn list_wallets(data_dir: &Path) -> Vec<ExternalWallet> {
    load(data_dir)
        .wallets
        .into_iter()
        .filter(|w| validate_address(&w.network, &w.address).is_ok())
        .collect()
}

pub fn list_groups(data_dir: &Path) -> Vec<ExternalWalletGroup> {
    load(data_dir).groups
}

pub fn add_wallet(
    data_dir: &Path,
    label: &str,
    network: &str,
    address: &str,
    group_id: Option<u32>,
) -> Result<ExternalWallet> {
    validate_address(network, address)?;
    let mut data = load(data_dir);
    if let Some(gid) = group_id {
        anyhow::ensure!(
            data.groups.iter().any(|g| g.id == gid),
            "groupe introuvable (id {gid})"
        );
    }
    let next_id = data.wallets.iter().map(|w| w.id).max().map_or(0, |m| m + 1);
    let wallet = ExternalWallet {
        id: next_id,
        label: label.trim().to_string(),
        network: network.to_string(),
        address: address.trim().to_string(),
        group_id,
    };
    data.wallets.push(wallet.clone());
    save(data_dir, &data)?;
    Ok(wallet)
}

pub fn remove_wallet(data_dir: &Path, id: u32) -> Result<()> {
    let mut data = load(data_dir);
    let before = data.wallets.len();
    data.wallets.retain(|w| w.id != id);
    anyhow::ensure!(
        data.wallets.len() < before,
        "wallet externe introuvable (id {id})"
    );
    save(data_dir, &data)
}

/// Moves a wallet to another group (or out of any group with `group_id: None`).
/// Only affects the grouping, never the address or the label.
pub fn set_wallet_group(data_dir: &Path, id: u32, group_id: Option<u32>) -> Result<()> {
    let mut data = load(data_dir);
    if let Some(gid) = group_id {
        anyhow::ensure!(
            data.groups.iter().any(|g| g.id == gid),
            "groupe introuvable (id {gid})"
        );
    }
    let wallet = data
        .wallets
        .iter_mut()
        .find(|w| w.id == id)
        .ok_or_else(|| anyhow::anyhow!("wallet externe introuvable (id {id})"))?;
    wallet.group_id = group_id;
    save(data_dir, &data)
}

pub fn create_group(data_dir: &Path, name: &str) -> Result<ExternalWalletGroup> {
    let mut data = load(data_dir);
    let next_id = data.groups.iter().map(|g| g.id).max().map_or(0, |m| m + 1);
    let group = ExternalWalletGroup {
        id: next_id,
        name: name.trim().to_string(),
    };
    data.groups.push(group.clone());
    save(data_dir, &data)?;
    Ok(group)
}

pub fn rename_group(data_dir: &Path, id: u32, name: &str) -> Result<()> {
    let mut data = load(data_dir);
    let group = data
        .groups
        .iter_mut()
        .find(|g| g.id == id)
        .ok_or_else(|| anyhow::anyhow!("groupe introuvable (id {id})"))?;
    group.name = name.trim().to_string();
    save(data_dir, &data)
}

/// Deletes the group; its wallets are NOT deleted, they simply become ungrouped.
/// Consistent with the rest of the app, which always prefers a reversible state
/// with no data loss over a cascading deletion (see profile archiving).
pub fn delete_group(data_dir: &Path, id: u32) -> Result<()> {
    let mut data = load(data_dir);
    let before = data.groups.len();
    data.groups.retain(|g| g.id != id);
    anyhow::ensure!(data.groups.len() < before, "groupe introuvable (id {id})");
    for wallet in data.wallets.iter_mut() {
        if wallet.group_id == Some(id) {
            wallet.group_id = None;
        }
    }
    save(data_dir, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_external_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID_EVM_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
    const VALID_SOL_ADDRESS: &str = "11111111111111111111111111111111";

    /// Transparent Zcash address (the Zcash card's) accepted, an address from another
    /// network rejected.
    #[test]
    fn validates_zcash_transparent_addresses() {
        let t1 = crate::zcash::p2pkh_address(&[7u8; 20]);
        assert!(validate_address("zec_mainnet", &t1).is_ok(), "{t1}");
        assert!(validate_address("zec_mainnet", VALID_EVM_ADDRESS).is_err());
        assert!(validate_address("zec_mainnet", "t1pasuneadresse").is_err());
        assert!(validate_address("doge_mainnet", "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L").is_ok());
        assert!(validate_address("doge_mainnet", &t1).is_err());
        let xmr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        assert!(validate_address("xmr_mainnet", xmr).is_ok());
        assert!(validate_address("xmr_mainnet", &t1).is_err());
        assert!(validate_address("zec_mainnet", xmr).is_err());
    }

    #[test]
    fn add_wallet_accepts_usdc_solana_network_with_a_valid_solana_address() {
        let dir = temp_dir("usdc_solana");
        let wallet = add_wallet(&dir, "Ami USDC", "usdc_solana", VALID_SOL_ADDRESS, None)
            .expect("ajout valide");
        assert_eq!(wallet.network, "usdc_solana");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_wallet_rejects_an_invalid_address_for_the_given_network() {
        let dir = temp_dir("invalid_address");
        assert!(add_wallet(&dir, "Ami", "evm_mainnet", "pas une adresse", None).is_err());
        assert!(list_wallets(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_wallet_then_list_round_trips() {
        let dir = temp_dir("roundtrip");
        let wallet =
            add_wallet(&dir, "Ami", "evm_mainnet", VALID_EVM_ADDRESS, None).expect("ajout valide");
        let listed = list_wallets(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, wallet.id);
        assert_eq!(listed[0].address, VALID_EVM_ADDRESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_wallet_rejects_an_unknown_group_id() {
        let dir = temp_dir("unknown_group");
        assert!(add_wallet(&dir, "Ami", "sol_mainnet", VALID_SOL_ADDRESS, Some(42)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleting_a_group_ungroups_its_wallets_instead_of_deleting_them() {
        let dir = temp_dir("delete_group");
        let group = create_group(&dir, "Famille").expect("création du groupe");
        let wallet = add_wallet(
            &dir,
            "Ami",
            "sol_mainnet",
            VALID_SOL_ADDRESS,
            Some(group.id),
        )
        .expect("ajout dans le groupe");

        delete_group(&dir, group.id).expect("suppression du groupe");

        let wallets = list_wallets(&dir);
        assert_eq!(wallets.len(), 1, "le wallet ne doit pas être supprimé");
        assert_eq!(wallets[0].id, wallet.id);
        assert_eq!(
            wallets[0].group_id, None,
            "le wallet doit redevenir non groupé"
        );
        assert!(list_groups(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_wallet_removes_only_the_targeted_wallet() {
        let dir = temp_dir("remove_wallet");
        let a = add_wallet(&dir, "A", "evm_mainnet", VALID_EVM_ADDRESS, None).unwrap();
        let b = add_wallet(&dir, "B", "sol_mainnet", VALID_SOL_ADDRESS, None).unwrap();

        remove_wallet(&dir, a.id).expect("suppression de A");

        let remaining = list_wallets(&dir);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, b.id);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
