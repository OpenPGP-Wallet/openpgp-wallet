//! Démo autonome : dérive une adresse Bitcoin testnet (P2WPKH) depuis une entropie
//! maître fraîche (SANS Shamir/PGP) et effectue un vrai virement sur le testnet
//! Bitcoin (voir wallet_flow::run_btc_transfer, aussi utilisé après restauration
//! Shamir+PGP dans main.rs).
//!
//! ATTENTION : comme wallet_demo (EVM), la clé privée n'est protégée par rien.
//! Testnet uniquement, jamais de vrais fonds.

use anyhow::Result;
use openpgp_wallet_core::{entropy, memory_guard, wallet_flow};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    println!("=== Démo wallet Bitcoin (sans Shamir/PGP) — testnet uniquement ===\n");

    let entropy_buf = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&entropy_buf);
    wallet_flow::run_btc_wallet(&entropy_buf)
}
