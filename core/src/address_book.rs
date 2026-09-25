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

/// Partie "visible" d'une adresse, sans le préfixe fixe commun à TOUTES les
/// adresses de son format (sinon toutes les adresses Bitcoin, qui commencent
/// par `bc1q`, se "ressembleraient"), en minuscules pour la comparaison.
fn distinctive_part(address: &str) -> String {
    let lower = address.trim().to_ascii_lowercase();
    for prefix in ["0x", "bc1q", "bc1p", "tb1q", "tb1p"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    lower
}

fn same_address(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim(), b.trim());
    // Hex EVM et bech32 : insensibles à la casse ; base58 (Solana) : sensible.
    if a.starts_with("0x") || a.starts_with("bc1") || a.starts_with("tb1") {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Entrée du carnet dont l'adresse RESSEMBLE à `address` sans lui être
/// identique : mêmes 4 premiers ET 4 derniers caractères distinctifs, milieu
/// différent — trouvé lors de l'audit "failles connues des hot wallets"
/// (empoisonnement d'adresse, "address poisoning" : un attaquant génère une
/// adresse qui imite début et fin de celle d'un contact habituel, pour qu'elle
/// soit copiée par erreur ; c'est précisément ce que l'œil vérifie d'une
/// adresse). `None` si l'adresse est exactement celle d'un contact, ou ne
/// ressemble à aucun.
pub fn lookalike_entry<'a>(entries: &'a [AddressBookEntry], address: &str) -> Option<&'a AddressBookEntry> {
    const EDGE: usize = 4;
    // `.get()` plutôt qu'un découpage direct : l'adresse est saisie par
    // l'utilisateur, un caractère non-ASCII (é, emoji collé par erreur) ferait
    // tomber un découpage direct au milieu d'un caractère — panique, donc
    // arrêt de l'app (`panic = "abort"`). Une telle saisie n'est de toute façon
    // pas une adresse valide : aucun avertissement de ressemblance à émettre.
    let edges = |s: &str| -> Option<(String, String)> {
        let s = distinctive_part(s);
        if s.len() < 2 * EDGE {
            return None;
        }
        Some((s.get(..EDGE)?.to_string(), s.get(s.len() - EDGE..)?.to_string()))
    };
    let target = edges(address)?;
    if entries.iter().any(|e| same_address(&e.address, address)) {
        return None;
    }
    entries.iter().find(|entry| edges(&entry.address).as_ref() == Some(&target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str, address: &str) -> AddressBookEntry {
        AddressBookEntry { id: 0, label: label.into(), network: "evm_mainnet".into(), address: address.into() }
    }

    #[test]
    fn lookalike_entry_flags_a_poisoned_address_but_not_the_real_one() {
        let book = vec![
            entry("Alice", "0x7a2F5c1e8B9d0e3f4A6b7C8d9E0f1A2b3C4d9e1F"),
            entry("Bob BTC", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
        ];
        // Même début (7a2f) et même fin (9e1f), milieu différent : empoisonnée.
        let poisoned = "0x7A2F000000000000000000000000000000009E1F";
        assert_eq!(lookalike_entry(&book, poisoned).map(|e| e.label.as_str()), Some("Alice"));
        // La vraie adresse (casse différente, hex insensible à la casse) : aucun avertissement.
        assert!(lookalike_entry(&book, "0x7a2f5c1e8b9d0e3f4a6b7c8d9e0f1a2b3c4d9e1f").is_none());
        // Adresse Bitcoin sans rapport : le préfixe commun "bc1q" ne doit pas suffire.
        assert!(lookalike_entry(&book, "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz").is_none());
        // Adresse Bitcoin imitant début et fin de celle de Bob : signalée.
        assert_eq!(
            lookalike_entry(&book, "bc1qxy2k000000000000000000000000000000x0wlh").map(|e| e.label.as_str()),
            Some("Bob BTC")
        );
        // Saisie non-ASCII : jamais de panique (arrêt de l'app), simplement aucun avertissement.
        assert!(lookalike_entry(&book, "0x7a2é00000000000000000000000000000009e1f").is_none());
        assert!(lookalike_entry(&book, "🔥🔥🔥🔥🔥🔥🔥🔥🔥").is_none());
    }

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
