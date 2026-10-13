//! Génère les 3 paires de clés PGP de test attendues par main.rs (une par "backup" :
//! user, backup_a, backup_b), chacune avec sa propre passphrase. À lancer une seule
//! fois avant `cargo run` (le binaire principal), tant qu'on n'a pas de vraies clés.
//!
//! Les clés vont dans keys/ (déjà ignoré par .gitignore, jamais commit).

use anyhow::{Context, Result};
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;
use std::io::{self, Write};
use zeroize::Zeroizing;

const IDENTITIES: [&str; 3] = ["user", "backup_a", "backup_b"];

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> Result<()> {
    println!("=== Génération des 3 clés PGP de test (user, backup_a, backup_b) ===\n");
    std::fs::create_dir_all("keys")?;

    for name in IDENTITIES {
        let passphrase = Zeroizing::new(prompt(&format!("Passphrase pour la clé '{name}' : "))?);

        let (cert, _revocation) = CertBuilder::new()
            .add_userid(format!("{name} <{name}@wallet-poc.invalid>"))
            .add_transport_encryption_subkey()
            .set_password(Some(Password::from(passphrase.as_str())))
            .generate()
            .with_context(|| format!("génération de la clé '{name}' impossible"))?;

        let mut pubkey_bytes = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut pubkey_bytes, armor::Kind::PublicKey)?;
            cert.serialize(&mut writer)?;
            writer.finalize()?;
        }
        std::fs::write(format!("keys/{name}_pubkey.asc"), &pubkey_bytes)?;

        let mut privkey_bytes = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut privkey_bytes, armor::Kind::SecretKey)?;
            cert.as_tsk().serialize(&mut writer)?;
            writer.finalize()?;
        }
        std::fs::write(format!("keys/{name}_privkey.asc"), &privkey_bytes)?;

        println!("  -> keys/{name}_pubkey.asc + keys/{name}_privkey.asc\n");
    }

    println!("Terminé. Tu peux maintenant lancer `cargo run` (main.rs).");
    Ok(())
}
