//! Spike manuel — PAS un test automatisé, aucune vérification biométrique réelle
//! n'est automatisable. À lancer soi-même sur une machine avec Windows Hello
//! configuré, pour valider empiriquement `windows_hello.rs` avant de lui faire
//! confiance dans `api.rs`/`lib.rs` (voir le plan : "Étape 0 — Spike Windows
//! Hello/TPM, à valider AVANT tout le reste").
//!
//! Usage (`cargo run --bin tpm_hello_spike -- <commande>`, depuis `core/`) :
//!   enroll   : crée une clé TPM, scelle un secret de test, le déchiffre tout de
//!              suite dans le même processus — un prompt Windows Hello doit
//!              apparaître à la création ET/OU au déchiffrement. Écrit l'état
//!              (nom de clé + blob scellé) dans tpm_hello_spike_state.json.
//!   reopen   : relit l'état écrit par `enroll` et retente SEULEMENT le
//!              déchiffrement, depuis CE lancement (processus séparé) — doit
//!              re-déclencher le prompt, jamais réussir silencieusement :
//!              c'est toute la justification du choix face à DPAPI.
//!   cancel   : mêmes étapes que `reopen`, mais avec l'instruction d'ANNULER le
//!              prompt manuellement — doit échouer proprement (pas de secret
//!              renvoyé), jamais réussir.
//!   cleanup  : supprime la clé TPM et l'état local.
//!
//! Critères de succès à cocher avant de continuer l'implémentation :
//! (a) un vrai prompt Windows Hello apparaît de façon fiable au déchiffrement ;
//! (b) annuler le prompt échoue proprement (voir `cancel`) plutôt que de
//!     réussir silencieusement ;
//! (c) `reopen` (autre lancement du processus) est SOUMIS AU MÊME prompt, pas
//!     silencieusement autorisé ;
//! (d) le comportement reste stable après un redémarrage de la machine.

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use pgp_wallet_poc::windows_hello;
#[cfg(windows)]
use serde::{Deserialize, Serialize};

#[cfg(windows)]
const STATE_FILE: &str = "tpm_hello_spike_state.json";
#[cfg(windows)]
const TEST_SECRET: &[u8] = b"ceci est un secret de test de 32o!!";

#[cfg(windows)]
#[derive(Serialize, Deserialize)]
struct SpikeState {
    key_name: String,
    sealed_blob_hex: String,
}

#[cfg(windows)]
fn save_state(key_name: &str, sealed_blob: &[u8]) -> Result<()> {
    let state = SpikeState { key_name: key_name.to_string(), sealed_blob_hex: hex::encode(sealed_blob) };
    std::fs::write(STATE_FILE, serde_json::to_string_pretty(&state)?).context("écriture de l'état du spike")
}

#[cfg(windows)]
fn load_state() -> Result<SpikeState> {
    let content = std::fs::read_to_string(STATE_FILE)
        .context("lecture de l'état du spike (as-tu lancé `enroll` avant ?)")?;
    serde_json::from_str(&content).context("état du spike corrompu")
}

#[cfg(not(windows))]
fn main() {
    println!("Ce spike est spécifique à Windows (Windows Hello/TPM via NCrypt) — rien à faire sur cet OS.");
}

#[cfg(windows)]
fn main() -> Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "enroll".to_string());
    println!("=== Spike Windows Hello / TPM — commande : {command} ===\n");

    match command.as_str() {
        "enroll" => {
            println!("Vérification de la disponibilité de Windows Hello (heuristique d'affichage) : {}",
                windows_hello::is_available());
            println!("Création d'une clé TPM + scellement du secret de test...");
            let (key_name, sealed_blob) = windows_hello::enroll(TEST_SECRET)?;
            println!("Clé créée : {key_name}");
            println!("Blob scellé : {} octets", sealed_blob.len());
            save_state(&key_name, &sealed_blob)?;

            println!("\nTentative de déchiffrement IMMÉDIATE, même processus.");
            println!(">>> Un prompt Windows Hello devrait apparaître maintenant — répondez-y normalement. <<<");
            let recovered = windows_hello::unlock(&key_name, &sealed_blob)?;
            if recovered.as_slice() == TEST_SECRET {
                println!("OK : secret récupéré identique à l'original.");
            } else {
                println!("PROBLÈME : secret récupéré DIFFÉRENT de l'original — ne pas continuer l'implémentation.");
            }
            println!("\nRelance maintenant `cargo run --bin tpm_hello_spike -- reopen` \
                (idéalement depuis un second terminal, pour un vrai second processus).");
        }
        "reopen" => {
            let state = load_state()?;
            let sealed_blob = hex::decode(&state.sealed_blob_hex).context("blob scellé illisible")?;
            println!("Ré-ouverture de la clé {} depuis CE processus (pid {}).", state.key_name, std::process::id());
            println!(">>> Un prompt Windows Hello devrait apparaître — répondez-y normalement. <<<");
            let recovered = windows_hello::unlock(&state.key_name, &sealed_blob)?;
            if recovered.as_slice() == TEST_SECRET {
                println!("OK : la barrière tient depuis un autre processus, et le secret est correct.");
            } else {
                println!("PROBLÈME : secret récupéré différent de l'original.");
            }
        }
        "cancel" => {
            let state = load_state()?;
            let sealed_blob = hex::decode(&state.sealed_blob_hex).context("blob scellé illisible")?;
            println!(">>> ANNULE le prompt Windows Hello qui va apparaître (Échap ou bouton Annuler). <<<");
            match windows_hello::unlock(&state.key_name, &sealed_blob) {
                Ok(_) => println!("PROBLÈME : le déchiffrement a réussi malgré l'annulation — ne pas continuer."),
                Err(e) => println!("OK : échec propre après annulation, comme attendu ({e})."),
            }
        }
        "cleanup" => {
            let state = load_state()?;
            windows_hello::remove(&state.key_name)?;
            let _ = std::fs::remove_file(STATE_FILE);
            println!("Clé TPM {} supprimée, état local nettoyé.", state.key_name);
        }
        other => {
            println!("Commande inconnue : {other} (attendu : enroll, reopen, cancel, cleanup)");
        }
    }

    Ok(())
}
