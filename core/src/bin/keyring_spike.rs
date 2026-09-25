//! Spike manuel — PAS un test automatisé : `cargo test` utilise volontairement
//! un faux coffre en mémoire pour `secure_storage` (voir
//! `api.rs::active_key_store`, même motif que `tpm_hello_spike.rs` pour
//! Windows Hello), donc rien ne vérifie jamais le VRAI coffre OS
//! automatiquement. À lancer soi-même pour valider empiriquement que le
//! Gestionnaire d'identification Windows (ou Trousseau/Secret Service sur
//! macOS/Linux) fonctionne réellement sur cette machine, avant de faire
//! confiance à `secure_storage::OsKeyStore` en production.
//!
//! Usage (`cargo run --bin keyring_spike -- <commande>`, depuis `core/`) :
//!   write      : écrit un secret de test dans le coffre OS sous un nom fixe
//!                de spike (jamais le nom utilisé par un vrai wallet).
//!   read       : relit ce secret depuis un autre lancement du processus —
//!                doit renvoyer exactement la même valeur.
//!   cleanup    : supprime l'entrée de test du coffre OS.
//!   full-cycle : exerce le VRAI chemin de production (`api::create_wallet`
//!                -> `unlock_wallet` -> `reset_wallet`) dans un `data_dir`
//!                temporaire jetable, et vérifie à chaque étape que la clé
//!                privée vit bien dans le coffre OS (jamais dans un fichier),
//!                que le déverrouillage la relit correctement, et que la
//!                réinitialisation supprime bien l'entrée du coffre OS.
//!                Seul ce mode touche vraiment `api.rs` ; les 3 précédents ne
//!                testent que `secure_storage` isolément.
//!   legacy-fallback : vérifie qu'un wallet dont la clé privée est encore un
//!                simple fichier (créé avant ce changement) reste bien
//!                déverrouillable via le repli fichier.

use anyhow::{Context, Result};
use pgp_wallet_poc::secure_storage::{entry_username, KeyStore, OsKeyStore};

const SPIKE_USERNAME: &str = "keyring_spike_test_entry";
const TEST_SECRET: &str = "ceci est un secret de test du spike keyring";

fn main() -> Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "write".to_string());
    println!("=== Spike coffre OS (keyring) — commande : {command} ===\n");

    let store = OsKeyStore;
    match command.as_str() {
        "write" => {
            store.write(SPIKE_USERNAME, TEST_SECRET).context("écriture dans le coffre OS")?;
            println!("OK : secret écrit dans le coffre OS sous \"{SPIKE_USERNAME}\".");
            println!("Relance maintenant `cargo run --bin keyring_spike -- read` (idéalement depuis un second lancement du processus).");
        }
        "read" => {
            let secret = store.read(SPIKE_USERNAME).context("lecture depuis le coffre OS")?;
            if secret.as_str() == TEST_SECRET {
                println!("OK : secret relu identique à l'original.");
            } else {
                println!("PROBLÈME : secret relu DIFFÉRENT de l'original — ne pas faire confiance à ce module.");
            }
        }
        "cleanup" => {
            store.remove(SPIKE_USERNAME).context("suppression dans le coffre OS")?;
            println!("Entrée de test supprimée du coffre OS.");
        }
        "full-cycle" => {
            let data_dir = std::env::temp_dir().join(format!("keyring_spike_full_cycle_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&data_dir);
            let username = entry_username(&data_dir);
            println!("data_dir de test : {}", data_dir.display());
            println!("nom d'entrée coffre OS attendu : {username}\n");

            println!("1. create_wallet...");
            pgp_wallet_poc::api::create_wallet(&data_dir, "un mot de passe de test bien assez long").context("create_wallet")?;
            let privkey_file_exists = data_dir.join("device_privkey.asc").exists();
            let in_os_store = store.read(&username).is_ok();
            println!(
                "   fichier device_privkey.asc présent : {privkey_file_exists} (attendu : false)\n   \
                 entrée présente dans le coffre OS : {in_os_store} (attendu : true)"
            );
            if privkey_file_exists || !in_os_store {
                println!("PROBLÈME : la clé privée n'a pas été déplacée vers le coffre OS comme attendu.");
            }

            println!("2. unlock_wallet (doit relire la clé privée depuis le coffre OS)...");
            match pgp_wallet_poc::api::unlock_wallet(&data_dir, "un mot de passe de test bien assez long") {
                Ok(profiles) => println!("   OK : {} profil(s) déverrouillé(s).", profiles.len()),
                Err(e) => println!("PROBLÈME : déverrouillage échoué ({e})."),
            }

            println!("3. reset_wallet (doit supprimer l'entrée du coffre OS)...");
            pgp_wallet_poc::api::reset_wallet(&data_dir).context("reset_wallet")?;
            let still_in_os_store = store.read(&username).is_ok();
            println!("   entrée encore présente dans le coffre OS après reset : {still_in_os_store} (attendu : false)");
            if still_in_os_store {
                println!("PROBLÈME : reset_wallet a laissé une entrée orpheline dans le coffre OS.");
                let _ = store.remove(&username);
            }

            let _ = std::fs::remove_dir_all(&data_dir);
            println!("\nTerminé.");
        }
        "legacy-fallback" => {
            // Simule un wallet créé AVANT ce changement (clé privée en simple
            // fichier, jamais dans le coffre OS) : vérifie que le repli lecture
            // fonctionne toujours, condition indispensable pour ne jamais
            // verrouiller un wallet existant hors de ses fonds.
            let data_dir = std::env::temp_dir().join(format!("keyring_spike_legacy_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&data_dir);
            let username = entry_username(&data_dir);

            println!("1. create_wallet (crée normalement via le coffre OS)...");
            pgp_wallet_poc::api::create_wallet(&data_dir, "un mot de passe de test bien assez long").context("create_wallet")?;

            println!("2. simulation d'un ancien wallet : déplacement manuel coffre OS -> fichier...");
            let secret = store.read(&username).context("lecture du secret à migrer manuellement")?;
            std::fs::write(data_dir.join("device_privkey.asc"), secret.as_bytes())?;
            store.remove(&username).context("suppression de l'entrée coffre OS (simulation)")?;
            println!("   fichier device_privkey.asc présent : {} (attendu : true)", data_dir.join("device_privkey.asc").exists());
            println!("   entrée coffre OS présente : {} (attendu : false)", store.read(&username).is_ok());

            println!("3. unlock_wallet (doit réussir via le repli fichier)...");
            match pgp_wallet_poc::api::unlock_wallet(&data_dir, "un mot de passe de test bien assez long") {
                Ok(profiles) => println!("   OK : {} profil(s) déverrouillé(s) via le fichier legacy.", profiles.len()),
                Err(e) => println!("PROBLÈME : le repli fichier ne fonctionne pas ({e}) — un wallet existant serait verrouillé."),
            }

            println!("4. reset_wallet (doit supprimer le fichier)...");
            pgp_wallet_poc::api::reset_wallet(&data_dir).context("reset_wallet")?;
            println!("   fichier encore présent après reset : {} (attendu : false)", data_dir.join("device_privkey.asc").exists());

            let _ = std::fs::remove_dir_all(&data_dir);
            println!("\nTerminé.");
        }
        other => {
            println!("Commande inconnue : {other} (attendu : write, read, cleanup)");
        }
    }

    Ok(())
}
