//! Local log of the addresses THIS wallet has already sent funds to. It is used to
//! warn, in the native confirmation dialog, that a send is going to an address
//! never paid before (the moment when a miscopied, poisoned or swapped address
//! costs the most). Explicitly requested by the user.
//!
//! Local rather than rebuilt from the blockchain: the on-chain history of a Solana
//! address takes one request per transaction, and no public EVM node exposes an
//! address's transactions (see `history::evm_history`). Accepted consequence: the
//! log only knows the sends made since the version that introduced it, so the first
//! send to a usual recipient after the update is flagged as new, once (the safe
//! direction: never the other way round).
//!
//! Written ONLY by the Rust backend, after a successful broadcast (see
//! `app/src-tauri`): a compromised frontend cannot make an address look "already
//! paid" without actually sending it funds, which takes the native confirmation
//! dialog and the password. No secret here, only public addresses (same sensitivity
//! as the address book).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

/// Read-modify-write of the log: two simultaneous sends (commands running in
/// parallel, a hardware send during a software send) would each have rewritten the
/// log without the other's entry.
static JOURNAL_MUTEX: Mutex<()> = Mutex::new(());

const SENT_RECIPIENTS_FILE: &str = "sent_recipients.json";

#[derive(Serialize, Deserialize, Default)]
struct Journal {
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Entry {
    /// The app's network identifier ("evm_mainnet", "btc_mainnet", "sol_mainnet"...):
    /// the same EVM address on Sepolia and on mainnet stays two distinct recipients.
    network: String,
    address: String,
}

fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(SENT_RECIPIENTS_FILE)
}

/// Missing or unreadable file = empty log: every address is then flagged as new,
/// never the other way round.
fn load(data_dir: &Path) -> Journal {
    std::fs::read_to_string(path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Comparison form: EVM hex and Bitcoin bech32 are case-insensitive (same address),
/// Solana base58 IS case-sensitive (a different address).
fn normalize(address: &str) -> String {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("0x") || lower.starts_with("bc1") || lower.starts_with("tb1") {
        lower
    } else {
        trimmed.to_string()
    }
}

/// `true` if this wallet has already sent funds to `address` on `network`. All the
/// addresses already paid, across every network (no duplicates), to spot an almost
/// identical address (`recipient_check`).
pub fn addresses(data_dir: &Path) -> Vec<String> {
    let mut list: Vec<String> = load(data_dir).entries.into_iter().map(|e| e.address).collect();
    list.sort();
    list.dedup();
    list
}

pub fn has_sent_to(data_dir: &Path, network: &str, address: &str) -> bool {
    let address = normalize(address);
    load(data_dir).entries.iter().any(|e| e.network == network && e.address == address)
}

/// Call this after a SUCCESSFUL broadcast only. No effect if the address is already
/// known.
pub fn record_sent(data_dir: &Path, network: &str, address: &str) -> Result<()> {
    let _serialize = JOURNAL_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let entry = Entry { network: network.to_string(), address: normalize(address) };
    let mut journal = load(data_dir);
    if journal.entries.contains(&entry) {
        return Ok(());
    }
    journal.entries.push(entry);
    let content = serde_json::to_string_pretty(&journal).context("sérialisation du journal des destinataires")?;
    // Temporary file, then rename: a power cut during the write does not leave a
    // truncated log.
    let tmp = path(data_dir).with_extension("json.tmp");
    std::fs::write(&tmp, content).context("écriture du journal des destinataires")?;
    std::fs::rename(&tmp, path(data_dir)).context("écriture du journal des destinataires")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_sent_recipients_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn records_and_recognizes_recipients_per_network() {
        let dir = temp_dir("per_network");
        let evm = "0xAbCdEf0123456789abcdef0123456789ABCDEF01";
        assert!(!has_sent_to(&dir, "evm_mainnet", evm), "journal vide : tout est nouveau");

        record_sent(&dir, "evm_mainnet", evm).unwrap();
        assert!(has_sent_to(&dir, "evm_mainnet", evm));
        assert!(has_sent_to(&dir, "evm_mainnet", &evm.to_lowercase()), "hex EVM : insensible à la casse");
        assert!(!has_sent_to(&dir, "evm_sepolia", evm), "autre réseau = autre destinataire");
        assert!(!has_sent_to(&dir, "evm_mainnet", "0xabcdef0123456789abcdef0123456789abcdef02"), "autre adresse");

        let sol = "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F";
        record_sent(&dir, "sol_mainnet", sol).unwrap();
        assert!(has_sent_to(&dir, "sol_mainnet", sol));
        assert!(!has_sent_to(&dir, "sol_mainnet", &sol.to_lowercase()), "base58 : la casse change l'adresse");

        let btc = "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz";
        record_sent(&dir, "btc_mainnet", &btc.to_uppercase()).unwrap();
        assert!(has_sent_to(&dir, "btc_mainnet", btc), "bech32 : insensible à la casse");

        // Idempotent: no duplicate.
        record_sent(&dir, "evm_mainnet", evm).unwrap();
        assert_eq!(load(&dir).entries.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupted_journal_treats_every_address_as_new() {
        let dir = temp_dir("corrupted");
        std::fs::write(path(&dir), "{ pas du json").unwrap();
        assert!(!has_sent_to(&dir, "btc_mainnet", "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
