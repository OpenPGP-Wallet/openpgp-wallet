//! Test rapide et manuel : chiffre un message texte simple ("bonjour" par défaut)
//! avec une clé PGP existante (keys/test_pubkey.asc, générée par pgp_demo), affiche
//! le bloc PGP armored obtenu, puis le déchiffre pour vérifier le round-trip.
//! Sert juste à voir concrètement que encrypt_share/decrypt_share produisent du
//! vrai PGP standard (lisible par n'importe quel client GPG), pas un format maison.

use anyhow::{Context, Result};
use openpgp::parse::Parse;
use openpgp::Message as OpenpgpMessage;
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
    println!("=== Test manuel PGP : chiffrement/déchiffrement d'un message texte ===\n");

    let text = "bonjour";
    println!("Message en clair : \"{text}\"\n");

    let encrypted = pgp_engine::encrypt_share(text.as_bytes(), "keys/test_pubkey.asc")
        .context("chiffrement impossible (as-tu lancé `cargo run --bin pgp_demo` au moins une fois ?)")?;

    println!("--- Résultat chiffré (PGP armored, format standard OpenPGP) ---");
    println!("{}", String::from_utf8_lossy(&encrypted));

    // Vérification que c'est bien un message PGP structurellement valide
    // (pas juste du texte qui ressemble à du PGP).
    OpenpgpMessage::from_bytes(&encrypted).context("le résultat n'est pas un message PGP valide")?;
    println!("(structure PGP valide confirmée : c'est un vrai message OpenPGP, pas juste du texte formaté)\n");

    let passphrase = Zeroizing::new(prompt("Passphrase de la clé de test (celle donnée à `pgp_demo`) : ")?);
    let decrypted = pgp_engine::decrypt_share(&encrypted, "keys/test_privkey.asc", &passphrase)?;
    let decrypted_text = String::from_utf8(decrypted).context("le contenu déchiffré n'est pas du texte UTF-8")?;

    println!("\nMessage déchiffré : \"{decrypted_text}\"");
    if decrypted_text == text {
        println!("Ça correspond exactement à l'original : le chiffrement/déchiffrement PGP fonctionne.");
    } else {
        println!("PROBLÈME : le message déchiffré ne correspond pas à l'original.");
    }

    Ok(())
}
