//! Interactive demo: splits the master entropy into shares (Shamir, 2-of-3
//! threshold) and checks the reconstruction, WITHOUT PGP. Encrypting each share is
//! a separate layer on top (see pgp_engine::encrypt_share and decrypt_share).
//!
//! WARNING: this prints the entropy and the shares in the clear, for teaching
//! purposes only, to check the mechanism. The product itself must never display or
//! log these values.

use anyhow::{anyhow, Context, Result};
use openpgp_wallet_core::{entropy, shamir};
use std::io::{self, Write};
use zeroize::Zeroizing;

const THRESHOLD: u8 = 2;
const TOTAL_SHARES: u8 = 3;

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> Result<()> {
    println!(
        "=== Démo Shamir's Secret Sharing (sans PGP) — seuil {THRESHOLD}-sur-{TOTAL_SHARES} ===\n"
    );

    let master_entropy = Zeroizing::new(entropy::generate_master_entropy());
    println!(
        "Entropie maître générée ({} octets) : {}",
        master_entropy.len(),
        hex::encode(&master_entropy)
    );
    println!("(affichée uniquement pour cette démo — le produit final ne l'affiche jamais)\n");

    let shares = shamir::split_secret(&master_entropy, THRESHOLD, TOTAL_SHARES)?;
    println!("{TOTAL_SHARES} parts générées :");
    for (i, share) in shares.iter().enumerate() {
        println!("  Part {} : {}", i + 1, hex::encode(share));
    }
    println!();

    println!("Test 1/2 : reconstruction avec 1 seule part (doit échouer, seuil = {THRESHOLD})...");
    match shamir::reconstruct_secret(THRESHOLD, &[shares[0].as_slice()]) {
        Ok(_) => println!("  -> INATTENDU : la reconstruction a réussi avec 1 seule part !\n"),
        Err(e) => println!("  -> Échec attendu : {e}\n"),
    }

    println!("Test 2/2 : choisis 2 parts parmi les {TOTAL_SHARES} pour reconstruire l'entropie.");
    let choice = prompt("Numéros des 2 parts séparés par un espace (ex: 1 3) : ")?;
    let indices: Vec<usize> = choice
        .split_whitespace()
        .map(|s| s.parse::<usize>().map(|n: usize| n.wrapping_sub(1)))
        .collect::<std::result::Result<_, _>>()
        .context("entrée invalide, attendu deux nombres entre 1 et 3")?;

    if indices.len() != 2 || indices.iter().any(|&i| i >= shares.len()) {
        return Err(anyhow!(
            "il faut exactement 2 numéros valides entre 1 et {TOTAL_SHARES}"
        ));
    }

    let subset: Vec<&[u8]> = indices.iter().map(|&i| shares[i].as_slice()).collect();
    let recovered = Zeroizing::new(shamir::reconstruct_secret(THRESHOLD, &subset)?);

    if *recovered == *master_entropy {
        println!(
            "\nReconstruction réussie : l'entropie récupérée correspond exactement à l'originale."
        );
    } else {
        println!("\nPROBLÈME : l'entropie récupérée NE correspond PAS à l'originale.");
    }

    Ok(())
}
