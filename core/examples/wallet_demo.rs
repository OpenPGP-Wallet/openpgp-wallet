//! Standalone demo: derives an EVM address from fresh master entropy (WITHOUT going
//! through Shamir or PGP) and makes a real transfer on the Sepolia testnet. Its
//! only purpose is to validate the "wallet" building block (BIP32 derivation, ECDSA
//! signing, RLP, JSON-RPC) independently of the project's "encrypted backup" block
//! (see wallet_flow::run_evm_transfer, also used after a Shamir + PGP restore in
//! the shamir_pgp_cli example).
//!
//! WARNING: the private key generated here is not protected at all (no Shamir, no
//! PGP). It only lives for the duration of the run and is only usable on testnet.
//! Never reuse this approach for real funds.

use anyhow::{Context, Result};
use openpgp_wallet_core::{entropy, memory_guard, wallet_flow, wallet_flow::SEPOLIA};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    println!("=== Démo wallet EVM (sans Shamir/PGP) — testnet Sepolia uniquement ===\n");

    // Fresh entropy. This project never goes through a recovery phrase: the entropy is
    // used directly as the BIP32 seed. For this demo only, it can be shown in BIP39
    // form (12 words), for teaching and comparison.
    let entropy_buf = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&entropy_buf);

    let answer =
        wallet_flow::prompt("Générer une seed phrase BIP39 (12 mots) pour cette démo ? [o/N] : ")?;
    let want_mnemonic = matches!(answer.to_lowercase().as_str(), "o" | "oui" | "y" | "yes");

    let derivation_seed: Zeroizing<Vec<u8>> = Zeroizing::new(if want_mnemonic {
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy_buf)
            .context("génération de la phrase BIP39 impossible")?;
        println!(
            "\n/!\\ Phrase de récupération BIP39 ({} mots) — DÉMO PÉDAGOGIQUE UNIQUEMENT.",
            mnemonic.word_count()
        );
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
