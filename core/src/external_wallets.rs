//! Wallets externes en lecture seule : suivre le solde d'adresses qui
//! n'appartiennent PAS à ce portefeuille (celles d'amis, d'autres comptes...) en
//! collant juste leur adresse publique. Aucune clé privée, aucun secret n'est
//! jamais impliqué ici — seulement des adresses publiques et des labels, au même
//! niveau de sensibilité que `messaging::Recipient` (carnet de destinataires).
//! Le solde lui-même est récupéré via la commande Tauri `get_balance` déjà
//! existante (mêmes appels RPC en lecture seule que pour les profils du wallet),
//! rien de nouveau à construire côté réseau.

use crate::{derivation, wallet_flow};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const EXTERNAL_WALLETS_FILE: &str = "external_wallets.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct ExternalWallet {
    pub id: u32,
    pub label: String,
    /// Un des identifiants réseau déjà utilisés ailleurs dans l'app :
    /// "evm_mainnet"/"evm_sepolia"/"btc_mainnet"/"btc_testnet"/"sol_mainnet"/"sol_devnet".
    pub network: String,
    pub address: String,
    /// `None` : wallet non groupé, affiché à part.
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
    let content = serde_json::to_string_pretty(data).context("sérialisation des wallets externes")?;
    std::fs::write(path(data_dir), content).context("écriture des wallets externes")
}

/// Valide le format de l'adresse pour le réseau donné avant de l'enregistrer —
/// mieux vaut échouer tout de suite avec un message clair que de découvrir une
/// adresse invalide plus tard via l'échec générique d'un appel RPC. Réutilise
/// exactement les mêmes parseurs que le reste de l'app (aucune nouvelle logique
/// de validation d'adresse).
pub(crate) fn validate_address(network: &str, address: &str) -> Result<()> {
    match network {
        // Tous les réseaux EVM (Ethereum, L2, BNB Chain…) : même format d'adresse.
        n if wallet_flow::evm_network(n).is_some() => {
            wallet_flow::parse_evm_address(address)?;
        }
        "btc_mainnet" => {
            derivation::parse_btc_mainnet_address(address)?;
        }
        "btc_testnet" => {
            derivation::parse_btc_testnet_address(address)?;
        }
        // "usdc_solana" : même format d'adresse que "sol_*" (l'adresse est
        // toujours celle du propriétaire — le compte de jetons USDC qui la
        // détient réellement est un détail invisible, dérivé côté Rust, voir
        // sol_spl.rs). Mainnet uniquement, comme pour le wallet propre à cette
        // app (pas de mint USDC devnet vérifié avec confiance).
        "sol_mainnet" | "sol_devnet" | "usdc_solana" => {
            let bytes = bs58::decode(address.trim())
                .into_vec()
                .context("adresse Solana invalide (base58 attendu)")?;
            anyhow::ensure!(bytes.len() == 32, "une adresse Solana fait 32 octets");
        }
        // Zcash transparent (t1, t3, tex1) ; adresses protégées refusées. Sans
        // cette branche, la courbe du portefeuille (qui valide chaque avoir)
        // échouait dès que la carte Zcash était affichée.
        "zec_mainnet" => {
            crate::zcash::parse_recipient(address)?;
        }
        // Monero (adresse du réseau principal) : même raison, pour la carte
        // Monero.
        "xmr_mainnet" => {
            crate::monero::parse_recipient(address)?;
        }
        // Dogecoin (D…, ou P2SH).
        "doge_mainnet" => {
            crate::doge::parse_recipient(address)?;
        }
        // Tron (T…).
        "tron_mainnet" => {
            crate::tron::parse_address(address)?;
        }
        // XRP Ledger (r…).
        "xrp_mainnet" => {
            crate::xrp::parse_address(address)?;
        }
        // Stellar (G…).
        "xlm_mainnet" => {
            crate::stellar::parse_address(address)?;
        }
        // NEAR (compte implicite ou nommé).
        "near_mainnet" => {
            crate::near::parse_account(address)?;
        }
        // Cardano (addr1…).
        "ada_mainnet" => {
            crate::cardano::parse_address(address)?;
        }
        // Stacks (SP…).
        "stx_mainnet" => {
            crate::stacks::parse_address(&crate::stacks::MAINNET, address)?;
        }
        // Bittensor (5…, SS58 format 42).
        "tao_mainnet" => {
            crate::bittensor::parse_address(address)?;
        }
        // Zcash protégé (adresse u1 de la carte « Zcash protégé »).
        "zec_shielded" => {
            crate::zcash_shielded::parse_shielded_address(address)?;
        }
        other => anyhow::bail!("réseau inconnu : {other}"),
    }
    Ok(())
}

/// Wallets suivis sur les réseaux de l'app ; ceux d'un réseau retiré
/// (HyperEVM, le 07/10/2026) restent dans le fichier sans être affichés.
pub fn list_wallets(data_dir: &Path) -> Vec<ExternalWallet> {
    load(data_dir).wallets.into_iter().filter(|w| validate_address(&w.network, &w.address).is_ok()).collect()
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
        anyhow::ensure!(data.groups.iter().any(|g| g.id == gid), "groupe introuvable (id {gid})");
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
    anyhow::ensure!(data.wallets.len() < before, "wallet externe introuvable (id {id})");
    save(data_dir, &data)
}

/// Déplace un wallet vers un autre groupe (ou le sort de tout groupe avec
/// `group_id: None`) — n'affecte que le classement, jamais l'adresse ni le label.
pub fn set_wallet_group(data_dir: &Path, id: u32, group_id: Option<u32>) -> Result<()> {
    let mut data = load(data_dir);
    if let Some(gid) = group_id {
        anyhow::ensure!(data.groups.iter().any(|g| g.id == gid), "groupe introuvable (id {gid})");
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
    let group = ExternalWalletGroup { id: next_id, name: name.trim().to_string() };
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

/// Supprime le groupe ; ses wallets ne sont PAS supprimés, ils redeviennent
/// simplement non groupés — cohérent avec le reste de l'app, qui préfère
/// toujours un état réversible/sans perte de données à une suppression en
/// cascade (voir l'archivage de profil).
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
        let dir = std::env::temp_dir().join(format!("pgp_wallet_external_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID_EVM_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
    const VALID_SOL_ADDRESS: &str = "11111111111111111111111111111111";

    /// Adresse Zcash transparente (celle de la carte Zcash) acceptée, adresse
    /// d'un autre réseau refusée.
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
        let wallet = add_wallet(&dir, "Ami USDC", "usdc_solana", VALID_SOL_ADDRESS, None).expect("ajout valide");
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
        let wallet = add_wallet(&dir, "Ami", "evm_mainnet", VALID_EVM_ADDRESS, None).expect("ajout valide");
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
        let wallet = add_wallet(&dir, "Ami", "sol_mainnet", VALID_SOL_ADDRESS, Some(group.id)).expect("ajout dans le groupe");

        delete_group(&dir, group.id).expect("suppression du groupe");

        let wallets = list_wallets(&dir);
        assert_eq!(wallets.len(), 1, "le wallet ne doit pas être supprimé");
        assert_eq!(wallets[0].id, wallet.id);
        assert_eq!(wallets[0].group_id, None, "le wallet doit redevenir non groupé");
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
