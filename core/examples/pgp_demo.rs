//! Standalone demo: generates a test PGP key pair (with Sequoia, no GnuPG install
//! needed), encrypts a dummy share with the public key, then decrypts it with the
//! private key and passphrase. It validated encrypt_share/decrypt_share before they
//! were wired into the full flow (the shamir_pgp_cli example, with real Shamir
//! shares).
//!
//! The generated keys go to keys/ (ignored by git, never committed).

use anyhow::{Context, Result};
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::serialize::Serialize;
use openpgp_wallet_core::pgp_engine;
use sequoia_openpgp as openpgp;
use std::io::{self, Write};
use zeroize::Zeroizing;

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> Result<()> {
    println!("=== Démo PGP (chiffrement/déchiffrement d'une part) — clé de test générée à la volée ===\n");

    let passphrase = Zeroizing::new(prompt(
        "Choisis une passphrase pour la clé de test générée : ",
    )?);

    println!("\nGénération d'une paire de clés PGP de test...");
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("Clé de test PoC <test@example.invalid>")
        .add_transport_encryption_subkey()
        .set_password(Some(Password::from(passphrase.as_str())))
        .generate()
        .context("génération de la clé PGP de test impossible")?;

    std::fs::create_dir_all("keys")?;

    let mut pubkey_bytes = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut pubkey_bytes, armor::Kind::PublicKey)?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("keys/test_pubkey.asc", &pubkey_bytes)?;

    let mut privkey_bytes = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut privkey_bytes, armor::Kind::SecretKey)?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("keys/test_privkey.asc", &privkey_bytes)?;
    println!(
        "Clés écrites dans keys/test_pubkey.asc et keys/test_privkey.asc (ignorées par git).\n"
    );

    let share = b"ceci-est-une-fausse-part-shamir-pour-le-test".to_vec();
    println!(
        "Part factice à chiffrer : {}",
        String::from_utf8_lossy(&share)
    );

    let encrypted = pgp_engine::encrypt_share(&share, "keys/test_pubkey.asc")?;
    println!("Chiffrée avec succès ({} octets).", encrypted.len());

    let decrypted = pgp_engine::decrypt_share(&encrypted, "keys/test_privkey.asc", &passphrase)?;

    if decrypted == share {
        println!("\nDéchiffrement réussi : le contenu correspond exactement à l'original.");
    } else {
        println!("\nPROBLÈME : le contenu déchiffré ne correspond pas à l'original.");
    }

    Ok(())
}
