//! Address book: attach a label to an address so it is easy to find when sending
//! funds, without pasting it by hand every time. Separate from `external_wallets`
//! (which tracks a balance, read-only): no balance is ever queried here, it is just
//! a label + network + address, though it reuses the same per-network address
//! validation (`external_wallets::validate_address`) rather than duplicating that
//! logic.

use crate::external_wallets::validate_address;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const ADDRESS_BOOK_FILE: &str = "address_book.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct AddressBookEntry {
    pub id: u32,
    pub label: String,
    /// Same set of network identifiers as `external_wallets::ExternalWallet`.
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
    let content =
        serde_json::to_string_pretty(data).context("sérialisation du carnet d'adresses")?;
    std::fs::write(path(data_dir), content).context("écriture du carnet d'adresses")
}

/// Contacts on the app's networks; those on a removed network (HyperEVM, on
/// 2026-10-07) stay in the file but are no longer offered: a deposit address valid
/// on one network is not necessarily valid on another.
pub fn list_entries(data_dir: &Path) -> Vec<AddressBookEntry> {
    load(data_dir)
        .entries
        .into_iter()
        .filter(|e| NETWORKS.contains(&e.network.as_str()))
        .collect()
}

/// Networks that can be offered for an address (address book, external wallets), in
/// the order they are offered: mainnets first, testnets last.
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

/// Networks on which `address` is valid (the same parsers as sending): the
/// "Network" menu only offers those, and adding refuses the others. NEAR is the
/// exception: its named-account syntax (lower case, digits, ".", "-", "_") accepts
/// almost any word, including a bech32 Bitcoin address, or a miscopied one
/// ("bc1qpasuneadresse", seen in practice). It is only offered for a NEAR-specific
/// shape (implicit account, or a dotted name such as "alice.near"), and when no
/// other network recognizes the address.
pub fn networks_for(address: &str) -> Vec<&'static str> {
    let address = address.trim();
    if address.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<&'static str> = NETWORKS
        .iter()
        .copied()
        .filter(|n| *n != "near_mainnet" && validate_address(n, address).is_ok())
        .collect();
    let implicit = address.len() == 64 && address.bytes().all(|b| b.is_ascii_hexdigit());
    if found.is_empty()
        && (implicit || address.contains('.'))
        && validate_address("near_mainnet", address).is_ok()
    {
        found.push("near_mainnet");
    }
    found
}

pub fn add_entry(
    data_dir: &Path,
    label: &str,
    network: &str,
    address: &str,
) -> Result<AddressBookEntry> {
    validate_address(network, address)?;
    anyhow::ensure!(
        networks_for(address).contains(&network),
        "cette adresse n'est pas une adresse de ce réseau"
    );
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
    anyhow::ensure!(
        data.entries.len() < before,
        "entrée du carnet d'adresses introuvable (id {id})"
    );
    save(data_dir, &data)
}

/// "Visible" part of an address, without the fixed prefix shared by ALL addresses
/// of its format (otherwise every Bitcoin address, starting with `bc1q`, would
/// "look alike"), lower-cased for comparison.
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
    // EVM hex and bech32: case-insensitive; base58 (Solana): case-sensitive.
    if a.starts_with("0x") || a.starts_with("bc1") || a.starts_with("tb1") {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Address book entry whose address LOOKS LIKE `address` without being identical:
/// same first 4 AND last 4 distinctive characters, a different middle. Found during
/// the "known hot wallet flaws" audit (address poisoning: an attacker generates an
/// address that mimics the start and end of a usual contact's, so that it gets
/// copied by mistake; those are exactly the parts the eye checks). `None` if the
/// address is exactly a contact's, or looks like none of them.
pub fn lookalike_entry<'a>(
    entries: &'a [AddressBookEntry],
    address: &str,
) -> Option<&'a AddressBookEntry> {
    const EDGE: usize = 4;
    // `.get()` rather than direct slicing: the address is typed by the user, and a
    // non-ASCII character (é, an emoji pasted by mistake) would make direct slicing
    // land in the middle of a character and panic. Such input is not a valid address
    // anyway: no look-alike warning to raise.
    let edges = |s: &str| -> Option<(String, String)> {
        let s = distinctive_part(s);
        if s.len() < 2 * EDGE {
            return None;
        }
        Some((
            s.get(..EDGE)?.to_string(),
            s.get(s.len() - EDGE..)?.to_string(),
        ))
    };
    let target = edges(address)?;
    if entries.iter().any(|e| same_address(&e.address, address)) {
        return None;
    }
    entries
        .iter()
        .find(|entry| edges(&entry.address).as_ref() == Some(&target))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The network follows the address: a Solana address cannot be saved as an Ethereum
    /// address, nor a Bitcoin address as a NEAR account.
    #[test]
    fn networks_follow_the_address() {
        let evm = networks_for("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        assert_eq!(evm.first(), Some(&"evm_mainnet"));
        assert_eq!(evm.last(), Some(&"evm_sepolia"));
        assert!(
            evm.iter()
                .all(|n| crate::wallet_flow::evm_network(n).is_some()),
            "{evm:?}"
        );
        assert_eq!(evm.len(), crate::wallet_flow::EVM_NETWORKS.len());
        assert_eq!(
            networks_for("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
            vec!["btc_mainnet"]
        );
        assert_eq!(
            networks_for("So11111111111111111111111111111111111111112"),
            vec!["sol_mainnet", "usdc_solana", "sol_devnet"]
        );
        assert_eq!(networks_for("alice.near"), vec!["near_mainnet"]);
        assert_eq!(networks_for(&"ab".repeat(32)), vec!["near_mainnet"]);
        assert!(networks_for("pas une adresse !").is_empty());
        // A miscopied Bitcoin address is not a "NEAR account" either.
        assert!(networks_for("bc1qpasuneadresse").is_empty());
        assert!(networks_for("  ").is_empty());

        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_book_networks_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(add_entry(
            &dir,
            "x",
            "evm_mainnet",
            "So11111111111111111111111111111111111111112"
        )
        .is_err());
        let err = add_entry(
            &dir,
            "x",
            "near_mainnet",
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(err, "cette adresse n'est pas une adresse de ce réseau");
        assert!(add_entry(
            &dir,
            "x",
            "btc_mainnet",
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        )
        .is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn entry(label: &str, address: &str) -> AddressBookEntry {
        AddressBookEntry {
            id: 0,
            label: label.into(),
            network: "evm_mainnet".into(),
            address: address.into(),
        }
    }

    #[test]
    fn lookalike_entry_flags_a_poisoned_address_but_not_the_real_one() {
        let book = vec![
            entry("Alice", "0x7a2F5c1e8B9d0e3f4A6b7C8d9E0f1A2b3C4d9e1F"),
            entry("Bob BTC", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
        ];
        // Same start (7a2f) and same end (9e1f), different middle: poisoned.
        let poisoned = "0x7A2F000000000000000000000000000000009E1F";
        assert_eq!(
            lookalike_entry(&book, poisoned).map(|e| e.label.as_str()),
            Some("Alice")
        );
        // The real address (different case, hex is case-insensitive): no warning.
        assert!(lookalike_entry(&book, "0x7a2f5c1e8b9d0e3f4a6b7c8d9e0f1a2b3c4d9e1f").is_none());
        // Unrelated Bitcoin address: the shared "bc1q" prefix must not be enough.
        assert!(lookalike_entry(&book, "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz").is_none());
        // Bitcoin address mimicking the start and end of Bob's: flagged.
        assert_eq!(
            lookalike_entry(&book, "bc1qxy2k000000000000000000000000000000x0wlh")
                .map(|e| e.label.as_str()),
            Some("Bob BTC")
        );
        // Non-ASCII input: never a panic, simply no warning.
        assert!(lookalike_entry(&book, "0x7a2é00000000000000000000000000000009e1f").is_none());
        assert!(lookalike_entry(&book, "🔥🔥🔥🔥🔥🔥🔥🔥🔥").is_none());
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_address_book_{name}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID_EVM_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
    const VALID_SOL_ADDRESS: &str = "11111111111111111111111111111111";

    #[test]
    fn add_entry_then_list_round_trips() {
        let dir = temp_dir("roundtrip");
        let entry =
            add_entry(&dir, "Alice", "evm_mainnet", VALID_EVM_ADDRESS).expect("ajout valide");
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
