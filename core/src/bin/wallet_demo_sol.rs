//! Démo autonome : dérive une adresse Solana (ed25519, SLIP-0010) depuis une entropie
//! maître fraîche (SANS Shamir/PGP) et effectue un vrai virement sur le devnet Solana
//! (voir wallet_flow::run_sol_transfer, aussi utilisé après restauration Shamir+PGP
//! dans main.rs).
//!
//! ATTENTION : comme les autres démos, la clé privée n'est protégée par rien.
//! Devnet uniquement, jamais de vrais fonds.

use anyhow::Result;
use pgp_wallet_poc::{entropy, memory_guard, wallet_flow};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    println!("=== Démo wallet Solana (sans Shamir/PGP) — devnet uniquement ===\n");

    let entropy_buf = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&entropy_buf);
    wallet_flow::run_sol_wallet(&entropy_buf, &wallet_flow::SOLANA_DEVNET)
}
