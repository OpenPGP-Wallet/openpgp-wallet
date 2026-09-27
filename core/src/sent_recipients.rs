//! Journal local des adresses auxquelles CE portefeuille a déjà envoyé des
//! fonds — sert à prévenir, dans la boîte de confirmation native, qu'un envoi
//! part vers une adresse jamais payée auparavant (le moment où une adresse
//! mal recopiée, empoisonnée ou substituée coûte le plus cher). Demandé
//! explicitement par l'utilisateur.
//!
//! Local plutôt que reconstruit depuis la blockchain : l'historique on-chain
//! d'une adresse Solana demande une requête par transaction, et aucun nœud
//! EVM public n'expose les transactions d'une adresse (voir
//! `history::evm_history`). Conséquence assumée : le journal ne connaît que les
//! envois faits depuis la version qui l'a introduit — le premier envoi vers un
//! destinataire habituel après la mise à jour est signalé comme nouveau, une
//! seule fois (sens sûr : jamais l'inverse).
//!
//! Écrit UNIQUEMENT par le backend Rust, après une diffusion réussie (voir
//! `app/src-tauri`) : un frontend compromis ne peut pas faire passer une
//! adresse pour "déjà payée" sans réellement lui envoyer des fonds, ce qui
//! exige la boîte de confirmation native et le mot de passe. Aucun secret
//! ici, seulement des adresses publiques (même niveau de sensibilité que le
//! carnet d'adresses).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

/// Lecture-modification-écriture du journal : deux envois simultanés (commandes
/// exécutées en parallèle, envoi matériel pendant un envoi logiciel) auraient
/// chacun réécrit le journal sans l'entrée de l'autre.
static JOURNAL_MUTEX: Mutex<()> = Mutex::new(());

const SENT_RECIPIENTS_FILE: &str = "sent_recipients.json";

#[derive(Serialize, Deserialize, Default)]
struct Journal {
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Entry {
    /// Identifiant réseau de l'app ("evm_mainnet", "btc_mainnet", "sol_mainnet"...)
    /// — une même adresse EVM sur Sepolia et sur mainnet reste deux destinataires
    /// distincts.
    network: String,
    address: String,
}

fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(SENT_RECIPIENTS_FILE)
}

/// Fichier absent ou illisible = journal vide : toutes les adresses sont alors
/// signalées comme nouvelles, jamais l'inverse.
fn load(data_dir: &Path) -> Journal {
    std::fs::read_to_string(path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Forme de comparaison : hex EVM et bech32 Bitcoin sont insensibles à la
/// casse (même adresse), base58 Solana y est SENSIBLE (autre adresse).
fn normalize(address: &str) -> String {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("0x") || lower.starts_with("bc1") || lower.starts_with("tb1") {
        lower
    } else {
        trimmed.to_string()
    }
}

/// `true` si ce portefeuille a déjà envoyé des fonds à `address` sur `network`.
pub fn has_sent_to(data_dir: &Path, network: &str, address: &str) -> bool {
    let address = normalize(address);
    load(data_dir).entries.iter().any(|e| e.network == network && e.address == address)
}

/// À appeler après une diffusion RÉUSSIE uniquement. Sans effet si l'adresse
/// est déjà connue.
pub fn record_sent(data_dir: &Path, network: &str, address: &str) -> Result<()> {
    let _serialize = JOURNAL_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let entry = Entry { network: network.to_string(), address: normalize(address) };
    let mut journal = load(data_dir);
    if journal.entries.contains(&entry) {
        return Ok(());
    }
    journal.entries.push(entry);
    let content = serde_json::to_string_pretty(&journal).context("sérialisation du journal des destinataires")?;
    // Fichier temporaire puis renommage : une coupure pendant l'écriture ne laisse
    // pas un journal tronqué.
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

        // Idempotent : pas de doublon.
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
