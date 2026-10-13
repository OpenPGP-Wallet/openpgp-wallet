//! Manual spike, NOT an automated test: `cargo test` deliberately uses a fake
//! in-memory vault for `secure_storage` (see `api.rs::active_key_store`, same
//! pattern as `tpm_hello_spike.rs` for Windows Hello), so nothing ever checks the
//! REAL OS vault automatically. Run it yourself to confirm empirically that the
//! Windows Credential Manager (or Keychain / Secret Service on macOS / Linux)
//! really works on this machine before trusting `secure_storage::OsKeyStore` in
//! production.
//!
//! Usage (`cargo run --example keyring_spike -- <command>`, from `core/`):
//! - `write`: writes a test secret to the OS vault under a fixed spike name (never
//!   the name a real wallet uses).
//! - `read`: reads that secret back from another run of the process; it must return
//!   exactly the same value.
//! - `cleanup`: deletes the test entry from the OS vault.
//! - `full-cycle`: exercises the REAL production path (`api::create_wallet` ->
//!   `unlock_wallet` -> `reset_wallet`) in a throwaway temporary `data_dir`, and
//!   checks at each step that the private key really lives in the OS vault (never
//!   in a file), that unlocking reads it back correctly, and that the reset really
//!   deletes the vault entry. Only this mode actually touches `api.rs`; the 3
//!   previous ones only test `secure_storage` on its own.
//! - `legacy-fallback`: checks that a wallet whose private key is still a plain
//!   file (created before this change) can still be unlocked through the file
//!   fallback.

use anyhow::{Context, Result};
use openpgp_wallet_core::secure_storage::{entry_username, KeyStore, OsKeyStore};

const SPIKE_USERNAME: &str = "keyring_spike_test_entry";
const TEST_SECRET: &str = "ceci est un secret de test du spike keyring";

fn main() -> Result<()> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "write".to_string());
    println!("=== Spike coffre OS (keyring) — commande : {command} ===\n");

    let store = OsKeyStore;
    match command.as_str() {
        "write" => {
            store
                .write(SPIKE_USERNAME, TEST_SECRET)
                .context("écriture dans le coffre OS")?;
            println!("OK : secret écrit dans le coffre OS sous \"{SPIKE_USERNAME}\".");
            println!("Relance maintenant `cargo run --bin keyring_spike -- read` (idéalement depuis un second lancement du processus).");
        }
        "read" => {
            let secret = store
                .read(SPIKE_USERNAME)
                .context("lecture depuis le coffre OS")?
                .context("aucune entrée de spike (as-tu lancé `write` avant ?)")?;
            if secret.as_str() == TEST_SECRET {
                println!("OK : secret relu identique à l'original.");
            } else {
                println!("PROBLÈME : secret relu DIFFÉRENT de l'original — ne pas faire confiance à ce module.");
            }
        }
        "cleanup" => {
            store
                .remove(SPIKE_USERNAME)
                .context("suppression dans le coffre OS")?;
            println!("Entrée de test supprimée du coffre OS.");
        }
        "full-cycle" => {
            let data_dir = std::env::temp_dir()
                .join(format!("keyring_spike_full_cycle_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&data_dir);
            let username = entry_username(&data_dir);
            println!("data_dir de test : {}", data_dir.display());
            println!("nom d'entrée coffre OS attendu : {username}\n");

            println!("1. create_wallet...");
            openpgp_wallet_core::api::create_wallet(
                &data_dir,
                "un mot de passe de test bien assez long",
            )
            .context("create_wallet")?;
            let privkey_file_exists = data_dir.join("device_privkey.asc").exists();
            // `Ok(None)` means absent: `.is_ok()` alone would wrongly answer "present".
            let in_os_store = matches!(store.read(&username), Ok(Some(_)));
            println!(
                "   fichier device_privkey.asc présent : {privkey_file_exists} (attendu : false)\n   \
                 entrée présente dans le coffre OS : {in_os_store} (attendu : true)"
            );
            if privkey_file_exists || !in_os_store {
                println!("PROBLÈME : la clé privée n'a pas été déplacée vers le coffre OS comme attendu.");
            }

            println!("2. unlock_wallet (doit relire la clé privée depuis le coffre OS)...");
            match openpgp_wallet_core::api::unlock_wallet(
                &data_dir,
                "un mot de passe de test bien assez long",
            ) {
                Ok(profiles) => println!("   OK : {} profil(s) déverrouillé(s).", profiles.len()),
                Err(e) => println!("PROBLÈME : déverrouillage échoué ({e})."),
            }

            println!("3. reset_wallet (doit supprimer l'entrée du coffre OS)...");
            openpgp_wallet_core::api::reset_wallet(&data_dir).context("reset_wallet")?;
            let still_in_os_store = matches!(store.read(&username), Ok(Some(_)));
            println!("   entrée encore présente dans le coffre OS après reset : {still_in_os_store} (attendu : false)");
            if still_in_os_store {
                println!(
                    "PROBLÈME : reset_wallet a laissé une entrée orpheline dans le coffre OS."
                );
                let _ = store.remove(&username);
            }

            let _ = std::fs::remove_dir_all(&data_dir);
            println!("\nTerminé.");
        }
        "legacy-fallback" => {
            // Simulates a wallet created BEFORE this change (private key in a plain file,
            // never in the OS vault): checks that the read fallback still works, which is
            // essential so an existing wallet is never locked out of its funds.
            let data_dir =
                std::env::temp_dir().join(format!("keyring_spike_legacy_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&data_dir);
            let username = entry_username(&data_dir);

            println!("1. create_wallet (crée normalement via le coffre OS)...");
            openpgp_wallet_core::api::create_wallet(
                &data_dir,
                "un mot de passe de test bien assez long",
            )
            .context("create_wallet")?;

            println!(
                "2. simulation d'un ancien wallet : déplacement manuel coffre OS -> fichier..."
            );
            let secret = store
                .read(&username)
                .context("lecture du secret à migrer manuellement")?
                .context("clé absente du coffre OS juste après create_wallet")?;
            std::fs::write(data_dir.join("device_privkey.asc"), secret.as_bytes())?;
            store
                .remove(&username)
                .context("suppression de l'entrée coffre OS (simulation)")?;
            println!(
                "   fichier device_privkey.asc présent : {} (attendu : true)",
                data_dir.join("device_privkey.asc").exists()
            );
            println!(
                "   entrée coffre OS présente : {} (attendu : false)",
                matches!(store.read(&username), Ok(Some(_)))
            );

            println!("3. unlock_wallet (doit réussir via le repli fichier)...");
            match openpgp_wallet_core::api::unlock_wallet(&data_dir, "un mot de passe de test bien assez long") {
                Ok(profiles) => println!("   OK : {} profil(s) déverrouillé(s) via le fichier legacy.", profiles.len()),
                Err(e) => println!("PROBLÈME : le repli fichier ne fonctionne pas ({e}) — un wallet existant serait verrouillé."),
            }

            println!("4. reset_wallet (doit supprimer le fichier)...");
            openpgp_wallet_core::api::reset_wallet(&data_dir).context("reset_wallet")?;
            println!(
                "   fichier encore présent après reset : {} (attendu : false)",
                data_dir.join("device_privkey.asc").exists()
            );

            let _ = std::fs::remove_dir_all(&data_dir);
            println!("\nTerminé.");
        }
        other => {
            println!("Commande inconnue : {other} (attendu : write, read, cleanup)");
        }
    }

    Ok(())
}
