use anyhow::{anyhow, Context, Result};
use openpgp_wallet_core::{derivation, entropy, memory_guard, pgp_engine, shamir, wallet_flow};
use std::io::{self, Write};
use zeroize::Zeroizing;

const THRESHOLD: u8 = 2;
const TOTAL_SHARES: u8 = 3;
const IDENTITIES: [&str; TOTAL_SHARES as usize] = ["user", "backup_a", "backup_b"];

/// Explicit confirmation gate before any operation on a mainnet (real funds,
/// irreversible). Refuses by default: the exact phrase has to be typed.
fn confirm_mainnet_transfer() -> Result<()> {
    println!("\n/!\\ RÉSEAU MAINNET — CECI VA DÉPENSER DE VRAIS FONDS, IRRÉVERSIBLE. /!\\");
    println!("Ce PoC n'a jamais été audité par un tiers indépendant.");
    let confirm = prompt("Tape exactement 'OUI VRAIS FONDS' pour continuer : ")?;
    if confirm != "OUI VRAIS FONDS" {
        return Err(anyhow!("confirmation non reçue, opération annulée"));
    }
    Ok(())
}

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> Result<()> {
    println!("=== OpenPGP Wallet PoC — entropie maître fragmentée (Shamir 2-sur-3) ===\n");

    // 1. Generate the master entropy (256 bits)
    let master_entropy = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&master_entropy);
    println!("Entropie générée ({} octets).", master_entropy.len());

    // 2. Split it into 3 shares, any 2 of which rebuild it
    let shares = shamir::split_secret(&master_entropy, THRESHOLD, TOTAL_SHARES)?;
    println!(
        "{} parts générées (seuil de reconstruction : {}).",
        shares.len(),
        THRESHOLD
    );

    // 3. Encrypt each share with a separate PGP key (run `cargo run --example
    //    generate_test_keys` first if keys/ is empty)
    std::fs::create_dir_all("vault")?;
    for (i, share) in shares.iter().enumerate() {
        let pubkey_path = format!("keys/{}_pubkey.asc", IDENTITIES[i]);
        let encrypted = pgp_engine::encrypt_share(share, &pubkey_path)?;
        std::fs::write(format!("vault/share_{}.asc", i + 1), &encrypted)?;
        println!(
            "Part {} chiffrée -> vault/share_{}.asc ({})",
            i + 1,
            i + 1,
            IDENTITIES[i]
        );
    }

    // 4. `master_entropy` is wiped automatically at the end of `main` (the `Zeroizing`
    //    drop), even if an earlier step fails with `?`: more robust than a manual
    //    `memory_guard::wipe` that would be skipped in that case.
    println!("Entropie en clair : ne sera plus utilisée directement à partir d'ici.\n");

    // 5. Restore demo: 2 decrypted shares are enough to rebuild the master key, which is
    //    never shown in the clear from here on (only derived addresses are, see step 6).
    println!("--- Restauration (démonstration) ---");
    println!(
        "Choisis 2 des 3 backups à utiliser : 1={}, 2={}, 3={}",
        IDENTITIES[0], IDENTITIES[1], IDENTITIES[2]
    );
    let choice = prompt("Numéros séparés par un espace (ex: 1 3) : ")?;
    let indices: Vec<usize> = choice
        .split_whitespace()
        .map(|s| s.parse::<usize>().map(|n: usize| n.wrapping_sub(1)))
        .collect::<std::result::Result<_, _>>()
        .context("entrée invalide, attendu deux nombres entre 1 et 3")?;

    if indices.len() != 2 || indices.iter().any(|&i| i >= TOTAL_SHARES as usize) {
        return Err(anyhow!(
            "il faut exactement 2 numéros valides entre 1 et {TOTAL_SHARES}"
        ));
    }

    const MAX_ATTEMPTS: u32 = 3;

    // Each decrypted share is as sensitive as a partial master key (any 2 of 3 rebuild
    // everything): same `Zeroizing` treatment.
    let mut decrypted_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for &i in &indices {
        let name = IDENTITIES[i];
        let encrypted = std::fs::read(format!("vault/share_{}.asc", i + 1))
            .with_context(|| format!("lecture de vault/share_{}.asc", i + 1))?;

        let mut decrypted = None;
        for attempt in 1..=MAX_ATTEMPTS {
            let passphrase = Zeroizing::new(prompt(&format!(
                "Passphrase pour '{name}' (essai {attempt}/{MAX_ATTEMPTS}) : "
            ))?);
            match pgp_engine::decrypt_share(&encrypted, &format!("keys/{name}_privkey.asc"), &passphrase) {
                Ok(d) => {
                    decrypted = Some(d);
                    break;
                }
                Err(e) => {
                    println!("  -> Échec ({e}).");
                    if attempt < MAX_ATTEMPTS {
                        println!("     Réessaie.\n");
                    }
                }
            }
        }

        let decrypted = decrypted.ok_or_else(|| {
            anyhow!("échec du déchiffrement de la part '{name}' après {MAX_ATTEMPTS} tentatives")
        })?;
        decrypted_shares.push(Zeroizing::new(decrypted));
        println!("  -> part '{name}' déchiffrée.");
    }

    let share_refs: Vec<&[u8]> = decrypted_shares.iter().map(|s| s.as_slice()).collect();
    let recovered = Zeroizing::new(shamir::reconstruct_secret(THRESHOLD, &share_refs)?);
    let _recovered_lock = memory_guard::lock(&recovered);
    println!("Clé maîtresse reconstruite (jamais affichée en clair).\n");

    // 6. Derive addresses from the rebuilt key: proof that the restore works, without
    //    ever exposing the secret itself.
    let (_evm_key, evm_address) = derivation::derive_evm_key(&recovered, 0)?;
    let (_btc_key, btc_hash160) = derivation::derive_btc_testnet_key(&recovered, 0)?;
    let sol_key = derivation::derive_solana_key(&recovered, 0);

    println!("Adresse EVM dérivée         : {}", derivation::format_address(&evm_address));
    println!(
        "Adresse BTC testnet dérivée : {}",
        derivation::format_btc_testnet_address(&btc_hash160)?
    );
    println!(
        "Adresse Solana dérivée      : {}",
        bs58::encode(sol_key.verifying_key().to_bytes()).into_string()
    );
    println!("\nRestauration réussie : le wallet complet a été reconstruit à partir de 2 parts sur 3.\n");

    // 7. The restored wallet is usable: offer a real testnet/devnet transfer with the
    //    rebuilt key (never shown), to prove it is a working wallet and not just an
    //    address check.
    let do_transfer = prompt("Faire un vrai virement test avec ce wallet restauré ? [o/N] : ")?;
    if matches!(do_transfer.to_lowercase().as_str(), "o" | "oui" | "y" | "yes") {
        let network = prompt(
            "Quel réseau ? (1=EVM Sepolia testnet, 2=Bitcoin testnet, 3=Solana devnet,\n\
             4=Ethereum MAINNET - fonds réels, 5=Solana MAINNET - fonds réels) : ",
        )?;
        let result = match network.trim() {
            "1" => wallet_flow::run_evm_wallet(&recovered, &wallet_flow::SEPOLIA),
            "2" => wallet_flow::run_btc_wallet(&recovered),
            "3" => wallet_flow::run_sol_wallet(&recovered, &wallet_flow::SOLANA_DEVNET),
            "4" => confirm_mainnet_transfer()
                .and_then(|_| wallet_flow::run_evm_wallet(&recovered, &wallet_flow::ETHEREUM_MAINNET)),
            "5" => confirm_mainnet_transfer()
                .and_then(|_| wallet_flow::run_sol_wallet(&recovered, &wallet_flow::SOLANA_MAINNET)),
            other => Err(anyhow!("choix invalide : '{other}' (attendu 1 à 5)")),
        };
        // `recovered` is wiped automatically at the end of `main` (the `Zeroizing` drop).
        result?;
    }

    Ok(())
}
