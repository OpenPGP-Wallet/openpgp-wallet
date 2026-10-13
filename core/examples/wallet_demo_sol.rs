//! Standalone demo: derives a Solana address (ed25519, SLIP-0010) from fresh master
//! entropy (WITHOUT Shamir or PGP) and makes a real transfer on Solana devnet (see
//! wallet_flow::run_sol_transfer, also used after a Shamir + PGP restore in the
//! shamir_pgp_cli example).
//!
//! WARNING: as in the other demos, the private key is not protected at all. Devnet
//! only, never real funds.

use anyhow::Result;
use openpgp_wallet_core::{entropy, memory_guard, wallet_flow};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    println!("=== Démo wallet Solana (sans Shamir/PGP) — devnet uniquement ===\n");

    let entropy_buf = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&entropy_buf);
    wallet_flow::run_sol_wallet(&entropy_buf, &wallet_flow::SOLANA_DEVNET)
}
