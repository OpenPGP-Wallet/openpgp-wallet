//! Creation date of this device's wallet: syncing the private coins (Monero,
//! shielded Zcash) starts shortly before it instead of at the app's fixed birthday.
//! Otherwise their first sync would grow longer over time (one day of chain is
//! about 2 min for Monero).
//!
//! Only known for a wallet CREATED here (fresh entropy: no funds can be older).
//! After a restore it is unknown, since the funds may predate it, so the fixed
//! birthday is used. "Rescan from the beginning" (Settings) forgets it too.
//!
//! The first block is estimated from the current chain height and the time elapsed
//! since creation, both measured with the same clock (a clock that is merely offset
//! does not skew the difference), minus a 3-day margin; never before the fixed
//! birthday.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const FILE: &str = "wallet_created.json";
const MARGIN_SECS: u64 = 3 * 24 * 3600;

#[derive(Serialize, Deserialize)]
struct Created {
    unix: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Wallet created on this device just now.
pub fn record_created(data_dir: &Path) -> Result<()> {
    std::fs::write(data_dir.join(FILE), serde_json::to_vec(&Created { unix: now() })?).context("date de création du portefeuille : enregistrement impossible")
}

/// Date forgotten (restore, reset, full rescan).
pub fn forget(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(FILE));
}

fn created_unix(data_dir: &Path) -> Option<u64> {
    let bytes = std::fs::read(data_dir.join(FILE)).ok()?;
    serde_json::from_slice::<Created>(&bytes).ok().map(|c| c.unix)
}

/// First block to scan on a chain whose tip is `tip` (`block_secs` seconds per
/// block): shortly before the wallet was created, never before `fixed` (the app's
/// fixed birthday), never after `tip`.
pub fn start_height(data_dir: &Path, tip: u64, block_secs: u64, fixed: u64) -> u64 {
    start_height_at(created_unix(data_dir), now(), tip, block_secs, fixed)
}

fn start_height_at(created: Option<u64>, now: u64, tip: u64, block_secs: u64, fixed: u64) -> u64 {
    let Some(created) = created else { return fixed };
    let elapsed = now.saturating_sub(created).saturating_add(MARGIN_SECS);
    tip.saturating_sub(elapsed / block_secs.max(1)).max(fixed).min(tip.max(fixed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_is_shortly_before_creation_and_never_before_the_fixed_birthday() {
        let (tip, fixed) = (3_900_000u64, 3_776_000u64);
        // Restore (date unknown): fixed birthday.
        assert_eq!(start_height_at(None, 1_000_000, tip, 120, fixed), fixed);
        // Created 10 days ago: 10 + 3 days of Monero blocks back.
        let now = 2_000_000_000;
        assert_eq!(start_height_at(Some(now - 10 * 86_400), now, tip, 120, fixed), tip - 13 * 720);
        // Created a very long time ago: never before the fixed birthday.
        assert_eq!(start_height_at(Some(0), now, tip, 120, fixed), fixed);
        // Clock moved back since creation: margin only (3 days).
        assert_eq!(start_height_at(Some(now + 86_400), now, tip, 120, fixed), tip - 3 * 720);
        // Chain still below the fixed birthday (lagging node): never past the last known block... and never before the
        // birthday.
        assert_eq!(start_height_at(Some(now), now, fixed - 5, 120, fixed), fixed);
    }

    #[test]
    fn creation_is_recorded_and_forgotten() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_birthday_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(start_height(&dir, 3_900_000, 120, 3_776_000), 3_776_000);
        record_created(&dir).unwrap();
        assert_eq!(start_height(&dir, 3_900_000, 120, 3_776_000), 3_900_000 - 3 * 720);
        forget(&dir);
        assert_eq!(start_height(&dir, 3_900_000, 120, 3_776_000), 3_776_000);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
