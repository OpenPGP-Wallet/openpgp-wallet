//! Manual spike, NOT an automated test: no real biometric check can be automated.
//! Run it yourself on a machine with Windows Hello set up, to validate
//! `windows_hello.rs` empirically before trusting it in `api.rs`/`lib.rs` (from the
//! plan: "Step 0: Windows Hello/TPM spike, to validate BEFORE anything else").
//!
//! Usage (`cargo run --example tpm_hello_spike -- <command>`, from `core/`):
//! - `enroll`: creates a TPM key, seals a test secret and decrypts it right away in
//!   the same process. A Windows Hello prompt must appear at creation AND/OR at
//!   decryption. Writes the state (key name + sealed blob) to
//!   tpm_hello_spike_state.json.
//! - `reopen`: reads the state written by `enroll` and retries ONLY the decryption,
//!   from THIS run (a separate process). It must trigger the prompt again and never
//!   succeed silently: that is the whole reason for choosing this over DPAPI.
//! - `cancel`: same steps as `reopen`, but you CANCEL the prompt by hand. It must
//!   fail cleanly (no secret returned), never succeed.
//! - `cleanup`: deletes the TPM key and the local state.
//!
//! Success criteria to tick before going on with the implementation:
//! - (a) a real Windows Hello prompt reliably appears at decryption;
//! - (b) cancelling the prompt fails cleanly (see `cancel`) instead of succeeding
//!   silently;
//! - (c) `reopen` (another run of the process) is SUBJECT TO THE SAME prompt, not
//!   silently allowed;
//! - (d) the behavior stays stable after rebooting the machine.

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use openpgp_wallet_core::windows_hello;
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
