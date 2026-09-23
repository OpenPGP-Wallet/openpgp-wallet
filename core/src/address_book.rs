//! Carnet d'adresses : associer un label à une adresse pour la retrouver
//! facilement au moment d'envoyer des fonds, sans avoir à la recoller à la
//! main à chaque fois. Distinct de `external_wallets` (qui sert à suivre un
//! solde en lecture seule) : ici aucun solde n'est jamais interrogé, il ne
//! s'agit que d'un label + réseau + adresse, réutilise cependant la même
//! validation d'adresse par réseau (`external_wallets::validate_address`)
//! pour ne pas dupliquer cette logique.

use crate::external_wallets::validate_address;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const ADDRESS_BOOK_FILE: &str = "address_book.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct AddressBookEntry {
    pub id: u32,
    pub label: String,
    /// Même jeu d'identifiants réseau que `external_wallets::ExternalWallet`.
    pub network: String,
    pub address: String,
}

#[derive(Serialize, Deserialize, Default)]
struct AddressBookData {
    entries: Vec<AddressBookEntry>,
}

fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(ADDRESS_BOOK_FILE)
}

fn load(data_dir: &Path) -> AddressBookData {
    std::fs::read_to_string(path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(data_dir: &Path, data: &AddressBookData) -> Result<()> {
    let content = serde_json::to_string_pretty(data).context("sérialisation du carnet d'adresses")?;
    std::fs::write(path(data_dir), content).context("écriture du carnet d'adresses")
}

pub fn list_entries(data_dir: &Path) -> Vec<AddressBookEntry> {
    load(data_dir).entries
}

pub fn add_entry(data_dir: &Path, label: &str, network: &str, address: &str) -> Result<AddressBookEntry> {
    validate_address(network, address)?;
    let mut data = load(data_dir);
    let next_id = data.entries.iter().map(|e| e.id).max().map_or(0, |m| m + 1);
    let entry = AddressBookEntry {
        id: next_id,
        label: label.trim().to_string(),
        network: network.to_string(),
        address: address.trim().to_string(),
    };
    data.entries.push(entry.clone());
    save(data_dir, &data)?;
    Ok(entry)
}

pub fn remove_entry(data_dir: &Path, id: u32) -> Result<()> {
    let mut data = load(data_dir);
    let before = data.entries.len();
    data.entries.retain(|e| e.id != id);
    anyhow::ensure!(data.entries.len() < before, "entrée du carnet d'adresses introuvable (id {id})");
    save(data_dir, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_address_book_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID_EVM_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
    const VALID_SOL_ADDRESS: &str = "11111111111111111111111111111111";

    #[test]
    fn add_entry_then_list_round_trips() {
        let dir = temp_dir("roundtrip");
        let entry = add_entry(&dir, "Alice", "evm_mainnet", VALID_EVM_ADDRESS).expect("ajout valide");
        let listed = list_entries(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, entry.id);
        assert_eq!(listed[0].label, "Alice");
        assert_eq!(listed[0].address, VALID_EVM_ADDRESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_entry_rejects_an_invalid_address_for_the_given_network() {
        let dir = temp_dir("invalid_address");
        assert!(add_entry(&dir, "Alice", "evm_mainnet", "pas une adresse").is_err());
        assert!(list_entries(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_entry_accepts_usdc_solana_network() {
        let dir = temp_dir("usdc_solana");
        let entry = add_entry(&dir, "Bob", "usdc_solana", VALID_SOL_ADDRESS).expect("ajout valide");
        assert_eq!(entry.network, "usdc_solana");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_entry_removes_only_the_targeted_entry() {
        let dir = temp_dir("remove_entry");
        let a = add_entry(&dir, "A", "evm_mainnet", VALID_EVM_ADDRESS).unwrap();
        let b = add_entry(&dir, "B", "sol_mainnet", VALID_SOL_ADDRESS).unwrap();

        remove_entry(&dir, a.id).expect("suppression de A");

        let remaining = list_entries(&dir);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, b.id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_entry_rejects_an_unknown_id() {
        let dir = temp_dir("remove_unknown");
        assert!(remove_entry(&dir, 42).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
