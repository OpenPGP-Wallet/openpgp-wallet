//! Standalone demo: derives a Bitcoin testnet (P2WPKH) address from fresh master
//! entropy (WITHOUT Shamir or PGP) and makes a real transfer on Bitcoin testnet
//! (see wallet_flow::run_btc_transfer, also used after a Shamir + PGP restore in
//! the shamir_pgp_cli example).
//!
//! WARNING: as in wallet_demo (EVM), the private key is not protected at all.
//! Testnet only, never real funds.

use anyhow::Result;
use openpgp_wallet_core::{entropy, memory_guard, wallet_flow};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    println!("=== Démo wallet Bitcoin (sans Shamir/PGP) — testnet uniquement ===\n");

    let entropy_buf = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&entropy_buf);
    wallet_flow::run_btc_wallet(&entropy_buf)
}
