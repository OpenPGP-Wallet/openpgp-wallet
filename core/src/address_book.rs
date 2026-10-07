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

/// Contacts des réseaux de l'app ; ceux d'un réseau retiré (HyperEVM, le
/// 07/10/2026) restent dans le fichier mais ne sont plus proposés : une
/// adresse de dépôt valable sur un réseau ne l'est pas forcément sur un autre.
pub fn list_entries(data_dir: &Path) -> Vec<AddressBookEntry> {
    load(data_dir).entries.into_iter().filter(|e| NETWORKS.contains(&e.network.as_str())).collect()
}

/// Réseaux proposables pour une adresse (carnet, wallets externes), dans
/// l'ordre de proposition : réseaux principaux d'abord, de test à la fin.
const NETWORKS: [&str; 23] = [
    "evm_mainnet",
    "base_mainnet",
    "arbitrum_mainnet",
    "bsc_mainnet",
    "avax_mainnet",
    "polygon_mainnet",
    "btc_mainnet",
    "sol_mainnet",
    "usdc_solana",
    "zec_mainnet",
    "zec_shielded",
    "xmr_mainnet",
    "doge_mainnet",
    "tron_mainnet",
    "xrp_mainnet",
    "xlm_mainnet",
    "near_mainnet",
    "ada_mainnet",
    "stx_mainnet",
    "tao_mainnet",
    "evm_sepolia",
    "btc_testnet",
    "sol_devnet",
];

/// Réseaux où `address` est valide (mêmes parseurs que l'envoi) : le menu
/// « Réseau » ne propose que ceux-là, et l'ajout refuse les autres. NEAR à
/// part : sa syntaxe de compte nommé (minuscules, chiffres, « . », « - »,
/// « _ ») accepte presque n'importe quel mot — une adresse Bitcoin bech32,
/// ou mal recopiée (« bc1qpasuneadresse », constaté). Proposé seulement pour
/// une forme propre à NEAR (compte implicite, ou nom à point comme
/// « alice.near »), et si aucun autre réseau ne la reconnaît.
pub fn networks_for(address: &str) -> Vec<&'static str> {
    let address = address.trim();
    if address.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<&'static str> = NETWORKS.iter().copied().filter(|n| *n != "near_mainnet" && validate_address(n, address).is_ok()).collect();
    let implicit = address.len() == 64 && address.bytes().all(|b| b.is_ascii_hexdigit());
    if found.is_empty() && (implicit || address.contains('.')) && validate_address("near_mainnet", address).is_ok() {
        found.push("near_mainnet");
    }
    found
}

pub fn add_entry(data_dir: &Path, label: &str, network: &str, address: &str) -> Result<AddressBookEntry> {
    validate_address(network, address)?;
    anyhow::ensure!(networks_for(address).contains(&network), "cette adresse n'est pas une adresse de ce réseau");
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

    /// Le réseau suit l'adresse : une adresse Solana ne peut pas être
    /// enregistrée comme adresse Ethereum, ni une adresse Bitcoin comme
    /// compte NEAR.
    #[test]
    fn networks_follow_the_address() {
        let evm = networks_for("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        assert_eq!(evm.first(), Some(&"evm_mainnet"));
        assert_eq!(evm.last(), Some(&"evm_sepolia"));
        assert!(evm.iter().all(|n| crate::wallet_flow::evm_network(n).is_some()), "{evm:?}");
        assert_eq!(evm.len(), crate::wallet_flow::EVM_NETWORKS.len());
        assert_eq!(networks_for("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"), vec!["btc_mainnet"]);
        assert_eq!(networks_for("So11111111111111111111111111111111111111112"), vec!["sol_mainnet", "usdc_solana", "sol_devnet"]);
        assert_eq!(networks_for("alice.near"), vec!["near_mainnet"]);
        assert_eq!(networks_for(&"ab".repeat(32)), vec!["near_mainnet"]);
        assert!(networks_for("pas une adresse !").is_empty());
        // Adresse Bitcoin mal recopiée : pas un « compte NEAR » pour autant.
        assert!(networks_for("bc1qpasuneadresse").is_empty());
        assert!(networks_for("  ").is_empty());

        let dir = std::env::temp_dir().join(format!("pgp_wallet_book_networks_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(add_entry(&dir, "x", "evm_mainnet", "So11111111111111111111111111111111111111112").is_err());
        let err = add_entry(&dir, "x", "near_mainnet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").err().unwrap().to_string();
        assert_eq!(err, "cette adresse n'est pas une adresse de ce réseau");
        assert!(add_entry(&dir, "x", "btc_mainnet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
