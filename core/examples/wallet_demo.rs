//! Démo autonome : dérive une adresse EVM depuis une entropie maître fraîche
//! (SANS passer par Shamir/PGP) et effectue un vrai virement sur le testnet
//! Sepolia. Sert uniquement à valider la brique "wallet" (dérivation BIP32,
//! signature ECDSA, RLP, JSON-RPC) indépendamment de la brique "sauvegarde
//! chiffrée" du reste du projet (voir wallet_flow::run_evm_transfer, aussi
//! utilisé après restauration Shamir+PGP dans main.rs).
//!
//! ATTENTION : la clé privée générée ici n'est protégée par rien (pas de
//! Shamir, pas de PGP). Elle n'existe que le temps de l'exécution et n'est
//! utilisable que sur testnet. Ne jamais réutiliser cette approche pour de
//! vrais fonds.

use anyhow::{Context, Result};
use openpgp_wallet_core::{entropy, memory_guard, wallet_flow, wallet_flow::SEPOLIA};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    println!("=== Démo wallet EVM (sans Shamir/PGP) — testnet Sepolia uniquement ===\n");

    // Entropie fraîche. Par défaut ce projet ne passe jamais par une phrase de
    // récupération : l'entropie sert directement de seed BIP32.
    // On propose ici, uniquement pour cette démo, de la voir sous forme BIP39
    // (12 mots) à but pédagogique/comparatif.
    let entropy_buf = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&entropy_buf);

    let answer = wallet_flow::prompt("Générer une seed phrase BIP39 (12 mots) pour cette démo ? [o/N] : ")?;
    let want_mnemonic = matches!(answer.to_lowercase().as_str(), "o" | "oui" | "y" | "yes");

    let derivation_seed: Zeroizing<Vec<u8>> = Zeroizing::new(if want_mnemonic {
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy_buf)
            .context("génération de la phrase BIP39 impossible")?;
        println!("\n/!\\ Phrase de récupération BIP39 ({} mots) — DÉMO PÉDAGOGIQUE UNIQUEMENT.", mnemonic.word_count());
        println!("    Le produit final n'affichera jamais ça : ne réutilise pas");
        println!("    une phrase générée ainsi pour de vrais fonds, ne la stocke pas en clair.");
        println!("    {mnemonic}\n");
        mnemonic.to_seed("").to_vec()
    } else {
        entropy_buf.to_vec()
    });
    let _derivation_lock = memory_guard::lock(&derivation_seed);

    wallet_flow::run_evm_wallet(&derivation_seed, &SEPOLIA)
}
