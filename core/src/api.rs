//! Non-interactive API of the crypto worker, designed to be called from a graphical
//! interface (Tauri) rather than a terminal: no function here reads stdin or prints
//! to stdout; everything goes through parameters and return values.
//! `wallet_flow.rs` remains the interactive CLI version (prompts) for the
//! command-line demos; this module reuses the same building blocks (derivation,
//! shamir, pgp_engine, eth/btc/sol_tx/rpc) without ever printing or reading a
//! secret.
//!
//! The model:
//! - One "local vault" per device: the complete master entropy, encrypted with a
//!   PGP key dedicated to THIS device, unlocked with a single password, for
//!   everyday hot-wallet use.
//! - A 2-of-3 Shamir "backup kit", generated once at creation, only used to restore
//!   the wallet on a NEW device if this one is lost; never used for everyday
//!   unlocking.

use crate::{
    bittensor, btc_rpc, cardano, cow, dapp_requests, derivation, doge, entropy, eth_rpc, eth_tx,
    evm_sign, history, jupiter_rpc, lifi, memory_guard, monero, moonpay_trade, native_deposit,
    near, pgp_engine, secure_storage, shamir, sol_rpc, sol_spl, sol_stake, sol_tx, stacks, stellar,
    thorchain_rpc, tokens, tron, wallet_birthday, wallet_flow, xrp, zcash, zcash_shielded,
};
use anyhow::{Context, Result};
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DEVICE_PUBKEY_FILE: &str = "device_pubkey.asc";
const DEVICE_PRIVKEY_FILE: &str = "device_privkey.asc";
const DEVICE_VAULT_FILE: &str = "device_vault.asc";
const BACKUP_IDENTITIES: [&str; 3] = ["backup_a", "backup_b", "backup_c"];

// Biometric unlock (Windows Hello/TPM, see windows_hello.rs and
// enroll_biometric_unlock below): a SECOND PGP identity, alongside "device"
// (password, unchanged), whose private key is protected by a hardware-sealed
// random secret rather than a human password. The vault (`DEVICE_VAULT_FILE`) is
// then encrypted for both identities at once (see
// `pgp_engine::encrypt_share_multi`): either private key decrypts it on its own.
const DEVICE_BIOMETRIC_PUBKEY_FILE: &str = "device_biometric_pubkey.asc";
const DEVICE_BIOMETRIC_PRIVKEY_FILE: &str = "device_biometric_privkey.asc";
const DEVICE_BIOMETRIC_SEALED_SECRET_FILE: &str = "device_biometric_sealed_secret.bin";
const DEVICE_BIOMETRIC_KEY_META_FILE: &str = "device_biometric_key_meta.json";

const UNLOCK_ATTEMPTS_FILE: &str = "unlock_attempts.json";
/// Number of consecutive failures tolerated before a delay starts applying.
const MAX_FREE_ATTEMPTS: u32 = 5;
/// Base delay (seconds), doubled with each additional failure beyond
/// `MAX_FREE_ATTEMPTS`, capped at `MAX_LOCKOUT_SECS`.
const BASE_LOCKOUT_SECS: u64 = 5;
const MAX_LOCKOUT_SECS: u64 = 300;

/// Unlock failure counter, persisted next to the vault. Without it, nothing stopped
/// a script able to call `unlock_wallet`/`send_*` in a loop (devtools, compromised
/// dependency) from trying passwords forever, as fast as the CPU allows. The
/// 12-character minimum enforced at creation only protects against manual guessing,
/// not against a script.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct UnlockAttempts {
    consecutive_failures: u32,
    last_failure_unix: u64,
}

fn unlock_attempts_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(UNLOCK_ATTEMPTS_FILE)
}

fn read_unlock_attempts(data_dir: &Path) -> UnlockAttempts {
    std::fs::read_to_string(unlock_attempts_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_unlock_attempts(data_dir: &Path, attempts: &UnlockAttempts) {
    if let Ok(s) = serde_json::to_string(attempts) {
        let _ = std::fs::write(unlock_attempts_path(data_dir), s);
    }
}

fn required_lockout_secs(consecutive_failures: u32) -> u64 {
    if consecutive_failures < MAX_FREE_ATTEMPTS {
        return 0;
    }
    let extra = (consecutive_failures - MAX_FREE_ATTEMPTS).min(6); // avoids an absurdly large shift
    BASE_LOCKOUT_SECS
        .saturating_mul(1u64 << extra)
        .min(MAX_LOCKOUT_SECS)
}

/// To call before any attempt to decrypt the vault with a password supplied by the
/// caller. Returns an error if the device is currently "on hold" after too many
/// recent failures.
fn enforce_unlock_lockout(data_dir: &Path) -> Result<()> {
    let attempts = read_unlock_attempts(data_dir);
    let delay = required_lockout_secs(attempts.consecutive_failures);
    if delay == 0 {
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let elapsed = now.saturating_sub(attempts.last_failure_unix);
    anyhow::ensure!(
        elapsed >= delay,
        "trop de tentatives incorrectes récentes ; réessayez dans {} seconde(s)",
        delay - elapsed
    );
    Ok(())
}

fn record_unlock_failure(data_dir: &Path) {
    let mut attempts = read_unlock_attempts(data_dir);
    attempts.consecutive_failures = attempts.consecutive_failures.saturating_add(1);
    attempts.last_failure_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    write_unlock_attempts(data_dir, &attempts);
}

fn reset_unlock_attempts(data_dir: &Path) {
    let _ = std::fs::remove_file(unlock_attempts_path(data_dir));
}

// A SEPARATE failure counter for the biometric path (never shared with
// `UNLOCK_ATTEMPTS_FILE`/the password): a Windows Hello prompt that lingers, fails
// or gets spammed must never put password unlock on hold, and vice versa. A
// near-verbatim copy of the logic above (`required_lockout_secs` is a pure
// function over a counter, reused as is), duplicated rather than parameterized so
// there is no risk of changing, even indirectly, the already-audited password
// path.
const BIOMETRIC_UNLOCK_ATTEMPTS_FILE: &str = "unlock_attempts_biometric.json";

fn biometric_unlock_attempts_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(BIOMETRIC_UNLOCK_ATTEMPTS_FILE)
}

fn read_biometric_unlock_attempts(data_dir: &Path) -> UnlockAttempts {
    std::fs::read_to_string(biometric_unlock_attempts_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_biometric_unlock_attempts(data_dir: &Path, attempts: &UnlockAttempts) {
    if let Ok(s) = serde_json::to_string(attempts) {
        let _ = std::fs::write(biometric_unlock_attempts_path(data_dir), s);
    }
}

fn enforce_biometric_unlock_lockout(data_dir: &Path) -> Result<()> {
    let attempts = read_biometric_unlock_attempts(data_dir);
    let delay = required_lockout_secs(attempts.consecutive_failures);
    if delay == 0 {
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let elapsed = now.saturating_sub(attempts.last_failure_unix);
    anyhow::ensure!(
        elapsed >= delay,
        "trop de tentatives biométriques incorrectes récentes ; réessayez dans {} seconde(s)",
        delay - elapsed
    );
    Ok(())
}

fn record_biometric_unlock_failure(data_dir: &Path) {
    let mut attempts = read_biometric_unlock_attempts(data_dir);
    attempts.consecutive_failures = attempts.consecutive_failures.saturating_add(1);
    attempts.last_failure_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    write_biometric_unlock_attempts(data_dir, &attempts);
}

fn reset_biometric_unlock_attempts(data_dir: &Path) {
    let _ = std::fs::remove_file(biometric_unlock_attempts_path(data_dir));
}

pub struct Addresses {
    pub evm: String,
    pub btc_testnet: String,
    /// Distinct from `btc_testnet` for the same profile (different derivation path and
    /// bech32 prefix, see `derivation.rs`), unlike `evm`/`solana`, which are used
    /// unchanged on every variant of their network.
    pub btc_mainnet: String,
    pub solana: String,
    /// Transparent Zcash address (t1…), path m/44'/133'/0'/0/{index}.
    pub zcash: String,
    /// Dogecoin address (D…), path m/44'/3'/0'/0/{index}.
    pub doge: String,
    /// Tron address (T…), path m/44'/195'/0'/0/{index}.
    pub tron: String,
    /// XRP address (r…), path m/44'/144'/0'/0/{index}.
    pub xrp: String,
    /// Stellar address (G…), SEP-0005 path m/44'/148'/{index}'.
    pub stellar: String,
    /// NEAR implicit account (64 hex), path m/44'/397'/{index}'.
    pub near: String,
    /// Cardano base address (addr1…), CIP-1852 m/1852'/1815'/{index}'.
    pub cardano: String,
    /// Stacks address (SP…), path m/44'/5757'/0'/0/{index}.
    pub stacks: String,
    /// Bittensor address (5…, SS58 format 42), sr25519 key: the root of the entropy for
    /// profile 0, hard path "//n" beyond that (see `bittensor`).
    pub bittensor: String,
    /// THORChain address (thor1…), path m/44'/931'/0'/0/{index}: the one for the
    /// developer's main profile is the app's affiliate address.
    pub thor: String,
    /// Shielded Zcash address (u1…, Orchard receiver only) of ZIP-32 account no.
    /// {index}.
    pub zcash_shielded: String,
    /// Viewing keys of the shielded account (never sent to the UI): account creation
    /// and sync without the seed.
    pub zcash_shielded_keys: zcash_shielded::ProfileKeys,
    /// Primary Monero address (4…), the Ledger Monero app's scheme
    /// (m/44'/128'/{index}'/0/0, see `monero`).
    pub monero: String,
    /// Monero view keys (never sent to the UI): sync and send preparation without the
    /// seed.
    pub monero_keys: monero::ViewKeys,
}

const PROFILES_FILE: &str = "profiles.json";
const DEFAULT_PROFILE_LABEL: &str = "Principal";

/// A "profile" is just a labeled HD derivation index (BIP32/SLIP-10): the security
/// layer (2-of-3 Shamir + PGP) protects a single master entropy, as before.
/// `derive_evm_key`/`derive_btc_testnet_key`/`derive_solana_key` have accepted an
/// index from the start (see `core/src/derivation.rs`), so several addresses per
/// network need no change to the security model, only to stop always deriving index
/// 0. The `profiles.json` file (labels + indexes) holds nothing sensitive: without
/// it, the same addresses can still be derived from the seed, and only the labels
/// the user chose would be lost.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    pub index: u32,
    pub label: String,
    /// An archived profile no longer appears in the main selector or in the addresses
    /// derived by `unlock_wallet`, but stays in `profiles.json` and can be unarchived
    /// at any time (see `archive_profile`/`unarchive_profile`). This is the "soft",
    /// reversible removal, with no password: unlike `delete_profile`, nothing is lost
    /// irreversibly. `#[serde(default)]` keeps compatibility with a `profiles.json`
    /// written before this field existed.
    #[serde(default)]
    pub archived: bool,
}

pub struct ProfileAddresses {
    pub profile: Profile,
    /// `None` when the profile was created without a password (see `create_profile`):
    /// deriving an address means decrypting the seed again, which is never cached.
    /// Without a password, only the label/index is saved, and the address will appear
    /// at the next `unlock_wallet` (which derives every known profile while it already
    /// has the seed at hand).
    pub addresses: Option<Addresses>,
}

fn profiles_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PROFILES_FILE)
}

/// Backward compatibility: a vault created before profiles existed has no
/// `profiles.json`, so it is assumed to have a single default profile at index 0
/// (the one used everywhere until then), so no access is lost.
fn load_profiles(data_dir: &Path) -> Vec<Profile> {
    std::fs::read_to_string(profiles_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<Profile>>(&s).ok())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            vec![Profile {
                index: 0,
                label: DEFAULT_PROFILE_LABEL.to_string(),
                archived: false,
            }]
        })
}

fn save_profiles(data_dir: &Path, profiles: &[Profile]) -> Result<()> {
    let content = serde_json::to_string_pretty(profiles).context("sérialisation des profils")?;
    std::fs::write(profiles_path(data_dir), content).context("écriture des profils")
}

/// A Shamir backup share, encrypted with its own throwaway PGP identity. To be
/// exported by the user (files + passphrase) off the device.
pub struct BackupShare {
    pub label: String,
    pub passphrase: String,
    pub encrypted_share: Vec<u8>,
    pub privkey_armored: Vec<u8>,
}

pub struct CreateWalletResult {
    pub addresses: Addresses,
    pub backups: Vec<BackupShare>,
}

fn generate_pgp_identity(label: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let (cert, _revocation) = CertBuilder::new()
        // Same user ID domain as the keys created by earlier versions.
        .add_userid(format!("{label} <{label}@pgp-wallet-poc.local>"))
        .add_transport_encryption_subkey()
        .set_password(Some(Password::from(passphrase)))
        .generate()
        .with_context(|| format!("génération de la clé PGP '{label}' impossible"))?;

    let mut pubkey_armored = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey)?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }

    let mut privkey_armored = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut privkey_armored, armor::Kind::SecretKey)?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }

    Ok((pubkey_armored, privkey_armored))
}

/// Passphrase generated automatically for a backup (never typed by the user, just
/// shown once so it can be saved offline).
fn random_passphrase() -> String {
    // The raw entropy buffer is wiped as soon as the hex has been extracted from it
    // (`Zeroizing`); this was the only case outside `generate_master_entropy` in the
    // whole project that did not do it yet. The returned hex `String`, on the other
    // hand, is deliberately shown to the user (the passphrase of a backup share, to be
    // written down): there is nothing to gain by protecting it, since it ends up in the
    // clear in the UI anyway.
    let bytes = Zeroizing::new(entropy::generate_master_entropy());
    hex::encode(&bytes[..16])
}

fn derive_addresses(seed: &[u8], index: u32) -> Result<Addresses> {
    let (_evm_key, evm_address) = derivation::derive_evm_key(seed, index)?;
    let (_btc_testnet_key, btc_testnet_hash160) = derivation::derive_btc_testnet_key(seed, index)?;
    let (_btc_mainnet_key, btc_mainnet_hash160) = derivation::derive_btc_mainnet_key(seed, index)?;
    let sol_key = derivation::derive_solana_key(seed, index);
    let (_zec_key, zec_hash160) = derivation::derive_zec_key(seed, index)?;
    let (_doge_key, doge_hash160) = derivation::derive_doge_key(seed, index)?;
    let (_tron_key, tron_address) = derivation::derive_tron_key(seed, index)?;
    let (_xrp_key, xrp_account) = derivation::derive_xrp_key(seed, index)?;
    let stellar_key = derivation::derive_stellar_key(seed, index);
    let near_key = derivation::derive_near_key(seed, index);
    let (_thor_key, thor_hash160) = derivation::derive_thor_key(seed, index)?;
    let shielded_keys = zcash_shielded::profile_keys(seed, index)?;
    let monero_keys = monero::view_keys(seed, index)?;
    Ok(Addresses {
        monero: monero_keys.address()?,
        monero_keys,
        zcash_shielded: zcash_shielded::address(&shielded_keys.1)?,
        zcash_shielded_keys: shielded_keys,
        thor: derivation::format_thor_address(&thor_hash160)?,
        zcash: zcash::p2pkh_address(&zec_hash160),
        doge: doge::p2pkh_address(&doge_hash160),
        tron: tron::encode_address(&tron_address),
        xrp: xrp::encode_address(&xrp_account),
        stellar: stellar::encode_address(&stellar_key.verifying_key().to_bytes()),
        near: near::implicit_account(&near_key),
        cardano: cardano::address_of(seed, index),
        stacks: stacks::address_of(
            &stacks::MAINNET,
            &derivation::derive_stacks_key(seed, index)?,
        ),
        bittensor: bittensor::address(&bittensor::keypair(seed, index)?.public.to_bytes()),
        evm: derivation::format_address(&evm_address),
        btc_testnet: derivation::format_btc_testnet_address(&btc_testnet_hash160)?,
        btc_mainnet: derivation::format_btc_mainnet_address(&btc_mainnet_hash160)?,
        solana: bs58::encode(sol_key.verifying_key().to_bytes()).into_string(),
    })
}

/// List of this device's ACTIVE profiles (labels + derivation indexes), without ever
/// touching the vault or the password: just a file read. Does not include archived
/// profiles (see `archive_profile`): they appear neither in the main selector nor in
/// the addresses derived by `unlock_wallet`.
pub fn list_profiles(data_dir: &Path) -> Vec<Profile> {
    load_profiles(data_dir)
        .into_iter()
        .filter(|p| !p.archived)
        .collect()
}

/// List of archived profiles (see `archive_profile`): set aside without being
/// deleted, recoverable at any time through `unarchive_profile`.
pub fn list_archived_profiles(data_dir: &Path) -> Vec<Profile> {
    load_profiles(data_dir)
        .into_iter()
        .filter(|p| p.archived)
        .collect()
}

/// "Soft", reversible removal: the profile disappears from the main selector and
/// from the addresses derived at each unlock, but stays in `profiles.json` and can
/// be brought back at any time through `unarchive_profile`, with no password.
/// Nothing is irreversible, so nothing here calls for a heavy confirmation (unlike
/// `delete_profile`).
pub fn archive_profile(data_dir: &Path, index: u32) -> Result<()> {
    let mut profiles = load_profiles(data_dir);
    anyhow::ensure!(
        profiles.iter().filter(|p| !p.archived).count() > 1,
        "impossible d'archiver le dernier profil actif restant"
    );
    let profile = profiles
        .iter_mut()
        .find(|p| p.index == index && !p.archived)
        .ok_or_else(|| anyhow::anyhow!("profil actif introuvable (index {index})"))?;
    profile.archived = true;
    save_profiles(data_dir, &profiles)
}

/// Undoes an archive (see `archive_profile`): the profile becomes active again and
/// reappears in the main selector and in the derived addresses at the next unlock.
pub fn unarchive_profile(data_dir: &Path, index: u32) -> Result<()> {
    let mut profiles = load_profiles(data_dir);
    let profile = profiles
        .iter_mut()
        .find(|p| p.index == index && p.archived)
        .ok_or_else(|| anyhow::anyhow!("profil archivé introuvable (index {index})"))?;
    profile.archived = false;
    save_profiles(data_dir, &profiles)
}

/// Checks the device password (vault decrypted, then wiped straight away). Done
/// BEFORE opening a confirmation window, so the user is never asked to confirm for
/// nothing.
pub fn check_device_password(data_dir: &Path, device_password: &str) -> Result<()> {
    let _ = unlock_seed(data_dir, device_password)?;
    Ok(())
}

/// Name of a profile (active or archived), read from the profiles file.
pub fn profile_label(data_dir: &Path, index: u32) -> Option<String> {
    load_profiles(data_dir)
        .into_iter()
        .find(|p| p.index == index)
        .map(|p| p.label)
}

/// Removes a profile from the list (label + index).
///
/// Requires the device password (checked through `unlock_seed`, the seed discarded
/// straight away without being used): not because the removal itself touches the
/// seed, but as a proper confirmation before an action whose practical consequence
/// can be serious (see below), and to benefit from the same anti-brute-force lock as
/// the other sensitive actions.
///
/// To be clear about it: cryptographically, the address can still be derived from the
/// same seed at the same index (nothing is destroyed "in theory"). But this app offers
/// **no way to recreate a profile at a specific index**: `create_profile` always picks
/// the next free index, never one that was used and then removed. In practice, for a
/// user of this app (not a developer able to re-derive the index by hand), removing a
/// profile that has already received funds means losing access to them from this
/// interface for good. Hence the password: this is not a mere convenience operation on
/// a list of labels.
///
/// At least one active profile always remains: without a default vault to show, the
/// user would have no visible address after unlocking.
pub fn delete_profile(data_dir: &Path, device_password: &str, index: u32) -> Result<()> {
    // Seed discarded without being used: we only want to check the password.
    // `Zeroizing` wipes it automatically at the end of this expression, no manual call
    // needed (see earlier audit rounds on this).
    let _ = unlock_seed(data_dir, device_password)?;

    let mut profiles = load_profiles(data_dir);
    let before = profiles.len();
    profiles.retain(|p| p.index != index);
    anyhow::ensure!(
        profiles.len() < before,
        "profil introuvable (index {index})"
    );
    // Checked AFTER the removal, on ACTIVE profiles only: otherwise, removing the last
    // active profile could have gone through as long as an archived profile was still
    // lying around in the file (a total count > 1 was enough), leaving the dashboard
    // with no address to show after unlocking.
    anyhow::ensure!(
        profiles.iter().any(|p| !p.archived),
        "impossible de supprimer le dernier profil actif restant"
    );
    save_profiles(data_dir, &profiles)
}

/// Splits `secret` into a new 2-of-3 Shamir kit (3 new throwaway PGP identities, 3 new
/// random passphrases, never reused from one call to the next), each encrypting one
/// share. Shared by `create_wallet` (initial kit) and `regenerate_backup_kit`
/// (recreating a kit if the user lost their files). Having several valid Shamir kits
/// for the same secret at once is not a problem (they are just different splits of the
/// same secret), so an old kit that was not revoked stays valid: not a security issue,
/// just a harmless duplicate if the user generates several.
fn generate_backup_kit(data_dir: &Path, secret: &[u8]) -> Result<Vec<BackupShare>> {
    let shares: Vec<Zeroizing<Vec<u8>>> = shamir::split_secret(secret, 2, 3)?
        .into_iter()
        .map(Zeroizing::new)
        .collect();
    let kit_id = hex::encode(&Zeroizing::new(entropy::generate_master_entropy())[..8]);
    let mark = kit_mark_name(&kit_id, &kit_check(secret));
    let mut backups = Vec::with_capacity(3);
    for (i, share) in shares.iter().enumerate() {
        let label = BACKUP_IDENTITIES[i].to_string();
        let passphrase = random_passphrase();
        let (pubkey_armored, privkey_armored) = generate_pgp_identity(&label, &passphrase)?;
        let encrypted_share = encrypt_with_armored_pubkey(
            share,
            &data_dir.join(format!("tmp_{label}_pub.asc")),
            &pubkey_armored,
            Some(&mark),
        )?;
        backups.push(BackupShare {
            label,
            passphrase,
            encrypted_share,
            privkey_armored,
        });
    }
    Ok(backups)
}

/// Regenerates a brand-new 2-of-3 Shamir backup kit (3 new PGP identities, 3 new
/// passphrases) from the current master entropy, without touching the local vault or
/// the device password. Useful if the user lost one or more of their original backup
/// files: until this existed, the only way to get a backup kit again was to recreate
/// everything through `reset_wallet` + `create_wallet`, which also changes the master
/// entropy (and therefore the addresses).
pub fn regenerate_backup_kit(data_dir: &Path, device_password: &str) -> Result<Vec<BackupShare>> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    generate_backup_kit(data_dir, &seed)
}

/// THORChain (RUNE) address derived from the same master entropy, fixed index 0
/// (never a "profile" in the sense of the other networks: a single address, not one
/// per profile). Only used to receive swap affiliate fees (see thorchain_rpc.rs)
/// and to register the affiliate name (see `native_deposit`); purely informational
/// here.
pub fn get_thor_fee_address(data_dir: &Path, device_password: &str) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (_key, hash160) = derivation::derive_thor_key(&seed, 0)?;
    derivation::format_thor_address(&hash160)
}

/// An arbitrary but generous cap (no real use comes anywhere near it). Without it,
/// the passwordless path of `create_profile` requires NO authentication at all, and a
/// script able to invoke the Tauri command directly could grow `profiles.json`
/// without limit. The concrete consequence: `unlock_wallet` derives the addresses of
/// EVERY known profile on each unlock (see its docs), so tens of thousands of bogus
/// profiles would slow down (or, at the extreme, noticeably stall) the real owner's
/// legitimate unlock.
const MAX_PROFILES: usize = 50;

/// Adds a new profile (a new derivation index, never reused).
///
/// The password is optional: supplying it derives and returns the new profile's
/// address straight away (decrypting the seed again, which is never cached; the same
/// principle as sending funds, see `unlock_seed`); leaving it out only saves the
/// label/index without touching the vault or asking for the password. In that second
/// case, `addresses` is `None`: the address will appear on its own at the next
/// `unlock_wallet`, which derives every known profile while it already has the seed
/// at hand.
pub fn create_profile(
    data_dir: &Path,
    device_password: Option<&str>,
    label: &str,
) -> Result<ProfileAddresses> {
    let mut profiles = load_profiles(data_dir);
    anyhow::ensure!(
        profiles.len() < MAX_PROFILES,
        "nombre maximal de profils atteint ({MAX_PROFILES}) sur cet appareil"
    );
    let next_index = profiles.iter().map(|p| p.index).max().map_or(0, |m| m + 1);
    let profile = Profile {
        index: next_index,
        label: label.to_string(),
        archived: false,
    };

    let addresses = match device_password {
        Some(password) => {
            let seed = unlock_seed(data_dir, password)?;
            let _seed_lock = memory_guard::lock(&seed);
            Some(derive_addresses(&seed, profile.index)?)
        }
        None => None,
    };

    profiles.push(profile.clone());
    save_profiles(data_dir, &profiles)?;

    Ok(ProfileAddresses { profile, addresses })
}

/// Guarantees the temporary file is deleted even if the operation panics (`Drop`
/// runs during unwinding). Without this guard, a panic between writing and the
/// manual deletion would leave the file on disk, which is especially sensitive for
/// `decrypt_with_armored_privkey` (the file then holds a private key in the clear,
/// albeit itself protected by PGP).
struct TempFileGuard<'a>(&'a Path);

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// Encrypt_share requires a file path for the public key: a small temporary file,
/// written then read immediately, with no secret in it (public key only).
fn encrypt_with_armored_pubkey(
    data: &[u8],
    tmp_path: &Path,
    pubkey_armored: &[u8],
    name: Option<&str>,
) -> Result<Vec<u8>> {
    std::fs::write(tmp_path, pubkey_armored)?;
    let _guard = TempFileGuard(tmp_path);
    pgp_engine::encrypt_share_named(data, &tmp_path.to_string_lossy(), name)
}

/// Identifier of a backup kit: a fingerprint of its ENCRYPTED shares (nothing about
/// the wallet can be derived from it). The same value for all 3 shares of a kit;
/// used to refuse two shares of the same kit on the same USB drive.
pub fn backup_kit_id(backups: &[BackupShare]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for backup in backups {
        hasher.update((backup.encrypted_share.len() as u64).to_be_bytes());
        hasher.update(&backup.encrypted_share);
    }
    hex::encode(&hasher.finalize()[..12])
}

/// Kit mark (kits created since 2026-10-09), carried ENCRYPTED by each share (the
/// literal packet name, see `pgp_engine::encrypt_share_named`):
/// `pgpwallet-kit-v1:<kit identifier>:<wallet fingerprint>`, 16 hex characters
/// each. Two shares from different kits yield a WRONG secret without any error
/// (Shamir checks nothing, measured): the mark gets them refused, and the
/// fingerprint verifies the rebuilt secret. Earlier versions of the app ignore this
/// name and restore these kits as before; older kits (without a mark) can still be
/// restored, without proof.
const KIT_MARK_PREFIX: &str = "pgpwallet-kit-v1:";
pub const KITS_DIFFERENT: &str = "ces deux parts viennent de deux kits de sauvegarde différents : utilisez deux parts d'un même kit";
pub const KIT_CHECK_FAILED: &str = "ces deux parts ne redonnent pas le portefeuille de leur kit : essayez avec une autre part de ce kit";

#[derive(Debug, PartialEq)]
struct KitMark {
    kit: String,
    check: String,
}

/// Wallet fingerprint in the mark: 8 bytes of a domain-separated SHA-256 of the
/// secret; nothing about the secret can be derived from it.
fn kit_check(secret: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"OpenPGP Wallet: empreinte de kit v1\0");
    hasher.update(secret);
    hex::encode(&hasher.finalize()[..8])
}

fn kit_mark_name(kit: &str, check: &str) -> String {
    format!("{KIT_MARK_PREFIX}{kit}:{check}")
}

/// Mark read from a share's name; any other name (or none): `None`.
fn parse_kit_mark(name: Option<&[u8]>) -> Option<KitMark> {
    let rest = std::str::from_utf8(name?)
        .ok()?
        .strip_prefix(KIT_MARK_PREFIX)?;
    let (kit, check) = rest.split_once(':')?;
    let hex16 = |s: &str| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
    (hex16(kit) && hex16(check)).then(|| KitMark {
        kit: kit.to_string(),
        check: check.to_string(),
    })
}

/// Checks that a backup share decrypts with its private key and password (after
/// being written to a USB drive and reread from it); the decrypted share is wiped
/// from memory straight away.
pub fn verify_backup_share(
    data_dir: &Path,
    encrypted: &[u8],
    privkey_armored: &[u8],
    passphrase: &str,
) -> Result<()> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::fs::create_dir_all(data_dir)?;
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = data_dir.join(format!("tmp_verify_backup_{}_{n}.asc", std::process::id()));
    let share = Zeroizing::new(decrypt_with_armored_privkey(
        encrypted,
        &tmp,
        privkey_armored,
        passphrase,
    )?);
    anyhow::ensure!(!share.is_empty(), "part de sauvegarde vide");
    Ok(())
}

fn decrypt_with_armored_privkey(
    data: &[u8],
    tmp_path: &Path,
    privkey_armored: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>> {
    decrypt_with_armored_privkey_named(data, tmp_path, privkey_armored, passphrase)
        .map(|(share, _)| share)
}

/// `decrypt_with_armored_privkey` with the name carried by the share (kit mark).
fn decrypt_with_armored_privkey_named(
    data: &[u8],
    tmp_path: &Path,
    privkey_armored: &[u8],
    passphrase: &str,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    std::fs::write(tmp_path, privkey_armored)?;
    let _guard = TempFileGuard(tmp_path);
    pgp_engine::decrypt_share_named(data, &tmp_path.to_string_lossy(), passphrase)
}

// --- Storing the "device" private key (OS vault rather than a plain file) ------
//
// See `secure_storage.rs` for the "why" (real OS access control, not just a file
// path to guess) and the isolation by `data_dir`. Only concerns
// `device_privkey.asc` (password unlock): the "device_biometric" private key stays
// in a file, since its secret is already hardware-sealed by the TPM (see
// windows_hello.rs) and a second protection mechanism would add little.

/// Selects the active vault: the real OS vault in production, a fake in-memory
/// vault shared between tests under `#[cfg(test)]`. Same pattern as
/// `SecretSealer`/`WindowsHelloSealer` for biometric unlock, for the same reason:
/// `cargo test` must never touch the real Credential Manager/Keychain of the
/// machine running it, nor depend on an OS vault actually being configured on a CI
/// machine.
#[cfg(not(test))]
fn active_key_store() -> &'static dyn secure_storage::KeyStore {
    static STORE: secure_storage::OsKeyStore = secure_storage::OsKeyStore;
    &STORE
}

#[cfg(test)]
fn active_key_store() -> &'static dyn secure_storage::KeyStore {
    static STORE: std::sync::OnceLock<secure_storage::InMemoryKeyStore> =
        std::sync::OnceLock::new();
    STORE.get_or_init(secure_storage::InMemoryKeyStore::default)
}

/// Writes a new "device" private key: tries the OS vault first and falls back to a
/// regular file ONLY if it is unavailable (wallet creation/restore is never blocked
/// because of it). Deletes any existing file when the OS vault succeeds: only one
/// copy of the secret must exist at a time, never both side by side.
fn write_device_privkey(data_dir: &Path, armored: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(armored)
        .context("clé privée générée non-UTF8 (bug de génération PGP)")?;
    let username = secure_storage::entry_username(data_dir);
    match active_key_store().write(&username, text) {
        Ok(()) => {
            let _ = std::fs::remove_file(data_dir.join(DEVICE_PRIVKEY_FILE));
            Ok(())
        }
        Err(_) => std::fs::write(data_dir.join(DEVICE_PRIVKEY_FILE), armored)
            .context("écriture de la clé privée de l'appareil (coffre OS indisponible)"),
    }
}

/// Gives temporary access to the "device" private key as a FILE PATH, since
/// `pgp_engine::decrypt_share` (a constraint inherited from
/// `sequoia-openpgp::Cert::from_file`) only accepts a path, never bytes in memory.
/// Reads the OS vault FIRST, then falls back to the legacy file only if needed
/// (compatibility with wallets created before this change, or an OS vault that is
/// temporarily unavailable). When the source is the OS vault, the secret is briefly
/// materialized in a single-use temporary file, deleted even on panic/error
/// (`TempFileGuard`, the same mechanism already used for the Shamir backup keys):
/// an on-disk exposure window lasting a single call, instead of the permanent
/// exposure at a fixed, predictable path before this change.
fn with_device_privkey_path<T>(data_dir: &Path, f: impl FnOnce(&str) -> Result<T>) -> Result<T> {
    with_device_privkey_path_in(data_dir, active_key_store(), f)
}

/// Error meaning "the private key could not even be reached" (OS vault down AND no
/// fallback file, or a temporary file that could not be written), never a wrong
/// password. Found in self-review round 20: `unlock_seed` counted ANY error from
/// `with_device_privkey_path` as a failed password attempt, even though its own
/// docs say the lock "only counts wrong passwords". Since the move to the OS vault,
/// a simple transient problem with it would therefore have penalized a legitimate
/// user who typed the RIGHT password (with a growing delay of up to 5 minutes). A
/// marker type rather than a text comparison (unlike `is_user_cancellation`, which
/// is constrained by a Windows error code formatted by a third-party crate): here
/// we control both ends.
#[derive(Debug)]
struct KeyMaterialUnavailable(String);

impl std::fmt::Display for KeyMaterialUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyMaterialUnavailable {}

fn is_key_material_unavailable(err: &anyhow::Error) -> bool {
    err.downcast_ref::<KeyMaterialUnavailable>().is_some()
}

fn with_device_privkey_path_in<T>(
    data_dir: &Path,
    store: &dyn secure_storage::KeyStore,
    f: impl FnOnce(&str) -> Result<T>,
) -> Result<T> {
    let username = secure_storage::entry_username(data_dir);
    let from_store = store.read(&username);
    if let Ok(Some(secret)) = &from_store {
        let unique = format!(
            "{:?}-{}",
            std::thread::current().id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let tmp_path = data_dir.join(format!("tmp_device_privkey_{unique}.asc"));
        std::fs::write(&tmp_path, secret.as_bytes()).map_err(|e| {
            anyhow::Error::new(KeyMaterialUnavailable(format!(
                "matérialisation temporaire de la clé privée de l'appareil impossible : {e}"
            )))
        })?;
        let _guard = TempFileGuard(&tmp_path);
        return f(&tmp_path.to_string_lossy());
    }
    // `Ok(None)` (a wallet whose key still lives in a file) AND `Err` (OS vault down)
    // both try the file: an OS vault failure must never block a wallet whose key is
    // precisely in a file (e.g. the vault was unavailable at creation time, see
    // `write_device_privkey`).
    let path = data_dir.join(DEVICE_PRIVKEY_FILE);
    if !path.exists() {
        let detail = match &from_store {
            Err(e) => format!(" (coffre OS : {e:#})"),
            _ => String::new(),
        };
        return Err(anyhow::Error::new(KeyMaterialUnavailable(format!(
            "clé privée de l'appareil introuvable (ni coffre OS, ni fichier){detail}"
        ))));
    }
    f(&path.to_string_lossy())
}

/// A wallet created before the move to the OS vault (2026-09-25): its "device"
/// private key had stayed in a file, and nothing moved it (seen on a real wallet).
/// Called after a SUCCESSFUL unlock (the file is then known to be good): the key is
/// written to the OS vault, read back and compared, and only then is the file
/// deleted. One copy at a time: if the file cannot be deleted, the vault entry is
/// removed and the migration will be retried at the next unlock. No effect if the
/// key is already in the vault or if the vault is unavailable; a failure always
/// leaves the wallet in its previous state.
fn migrate_device_privkey_to_store(data_dir: &Path, store: &dyn secure_storage::KeyStore) {
    let username = secure_storage::entry_username(data_dir);
    if !matches!(store.read(&username), Ok(None)) {
        return;
    }
    let path = data_dir.join(DEVICE_PRIVKEY_FILE);
    let Ok(bytes) = std::fs::read(&path).map(Zeroizing::new) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return;
    };
    if store.write(&username, text).is_err() {
        return;
    }
    match store.read(&username) {
        Ok(Some(stored)) if stored.as_str() == text => {
            if std::fs::remove_file(&path).is_err() {
                let _ = store.remove(&username);
            }
        }
        _ => {
            let _ = store.remove(&username);
        }
    }
}

/// Deletes the "device" private key wherever it lives (OS vault and/or file: at
/// most one of the two in practice, see `write_device_privkey`, but both are
/// checked so an orphaned copy is never left behind). Best-effort on the OS vault
/// (its absence is normal if the wallet has always lived in a file); an error if
/// the file exists but cannot be deleted (permissions, lock), the same behavior as
/// `reset_wallet` for the vault's other files.
fn remove_device_privkey(data_dir: &Path) -> Result<()> {
    let username = secure_storage::entry_username(data_dir);
    let _ = active_key_store().remove(&username);
    let path = data_dir.join(DEVICE_PRIVKEY_FILE);
    if path.exists() {
        std::fs::remove_file(&path)
            .context("suppression du fichier de clé privée de l'appareil impossible")?;
    }
    Ok(())
}

/// Minimum length of a new device password, in characters.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// Fragments that make a password guessable whatever its length.
const COMMON_PASSWORD_PATTERNS: [&str; 8] = [
    "password",
    "motdepasse",
    "azerty",
    "qwerty",
    "123456",
    "00000000",
    "letmein",
    "admin",
];

/// The rule for a new device password (wallet creation, restore). It lived only in
/// the interface until v2.13, which the threat model treats as untrusted: a
/// compromised frontend could create or restore a vault under "a", and the vault
/// file, the target of an offline theft (THREAT_MODEL §5.1), would then fall to a
/// dictionary attack despite the maximum S2K cost. Same heuristic as the
/// interface's strength hint (`estimatePasswordStrength` in `app/src/main.js`), so
/// both always agree: at least 12 characters, no common pattern, and some variety
/// (16 characters or more, mixed case, digits, symbols: at least 3 of the 5 points).
pub fn check_new_password(password: &str) -> Result<()> {
    anyhow::ensure!(
        password.chars().count() >= MIN_PASSWORD_CHARS,
        "mot de passe trop court : au moins 12 caractères"
    );
    let lower = password.to_lowercase();
    let common = COMMON_PASSWORD_PATTERNS.iter().any(|p| lower.contains(p));
    let score = [
        true, // the minimum length, checked above
        password.chars().count() >= 16,
        password.chars().any(|c| c.is_ascii_lowercase())
            && password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|&&point| point)
    .count();
    anyhow::ensure!(
        !common && score > 2,
        "mot de passe trop faible ou trop prévisible : mélangez lettres, chiffres et symboles"
    );
    Ok(())
}

/// Creates a new wallet in `data_dir`: local vault (device password) + 2-of-3 Shamir
/// backup kit (3 shares, each with its own automatically generated passphrase). Never
/// logs or returns the entropy itself.
pub fn create_wallet(data_dir: &Path, device_password: &str) -> Result<CreateWalletResult> {
    check_new_password(device_password)?;
    // Without this guard, calling `create_wallet` a second time on a device that already
    // has a vault would silently overwrite `device_vault.asc`/`device_privkey.asc` with a
    // completely different master entropy. No caller checked this invariant on the Rust
    // side; only the frontend did (by showing the onboarding screen only when
    // `wallet_exists` returns false). A script able to invoke the Tauri command directly
    // (devtools, compromised dependency) could have triggered that replacement without
    // confirmation. The right way to "start over" goes explicitly through `reset_wallet`
    // first.
    anyhow::ensure!(
        !device_vault_exists(data_dir),
        "un coffre existe déjà sur cet appareil ; réinitialisez-le d'abord (reset_wallet) si vous voulez repartir de zéro"
    );
    std::fs::create_dir_all(data_dir)?;

    let master_entropy = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&master_entropy);
    let default_profile = Profile {
        index: 0,
        label: DEFAULT_PROFILE_LABEL.to_string(),
        archived: false,
    };
    let addresses = derive_addresses(&master_entropy, default_profile.index)?;
    save_profiles(data_dir, std::slice::from_ref(&default_profile))?;
    // Fresh entropy: no funds can be older than now, so the private cryptos sync from
    // shortly before now (see `wallet_birthday`).
    wallet_birthday::record_created(data_dir)?;

    // 1. The device's local vault.
    let (device_pub, device_priv) = generate_pgp_identity("device", device_password)?;
    // Found during an independent audit (not just `cargo test`): unlike the entropy,
    // the seed and the passwords, the PGP private key freshly generated here was never
    // wiped after use. The same gap that was fixed for other buffers in self-review
    // round 2, which had simply stayed unnoticed because `generate_pgp_identity` is
    // more recent.
    let device_priv = Zeroizing::new(device_priv);
    std::fs::write(data_dir.join(DEVICE_PUBKEY_FILE), &device_pub)?;
    write_device_privkey(data_dir, &device_priv)?;
    let vault = encrypt_with_armored_pubkey(
        &master_entropy,
        &data_dir.join("tmp_device_pub.asc"),
        &device_pub,
        None,
    )?;
    std::fs::write(data_dir.join(DEVICE_VAULT_FILE), &vault)?;
    // A leftover failure counter (e.g. a file left behind by a `reset_wallet` that
    // partly failed, or manual file tampering) must never make a freshly created vault
    // start out "on hold".
    reset_unlock_attempts(data_dir);

    // 2. 2-of-3 Shamir backup kit (independent of the local vault). Each share is
    //    wrapped in `Zeroizing` inside `generate_backup_kit`: 2 of them are enough to
    //    rebuild the master key, so they are just as sensitive and must be wiped the
    //    same way.
    let backups = generate_backup_kit(data_dir, &master_entropy)?;

    // `master_entropy` is wiped automatically at the end of the function (the
    // `Zeroizing` Drop), including on an early return through `?` above, unlike a
    // manual `memory_guard::wipe` at the end of the function, which would be skipped
    // if an earlier operation failed.
    Ok(CreateWalletResult { addresses, backups })
}

/// Unlocks the local vault with the device password and returns the public
/// addresses of ALL known profiles (never the private key or the entropy). The seed
/// is never cached between calls (see `unlock_seed`), so deriving every profile
/// while it is already in memory here avoids asking for the password again just to
/// switch the profile shown on the dashboard.
pub fn unlock_wallet(data_dir: &Path, device_password: &str) -> Result<Vec<ProfileAddresses>> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    forget_other_shielded_wallets(data_dir, &seed);
    // Active profiles only: an archived profile (see `archive_profile`) must not
    // appear anywhere until it has been explicitly unarchived.
    list_profiles(data_dir)
        .into_iter()
        .map(|profile| {
            let addresses = derive_addresses(&seed, profile.index)?;
            update_monero_key_images(data_dir, &seed, profile.index);
            Ok(ProfileAddresses {
                profile,
                addresses: Some(addresses),
            })
        })
        .collect()
}

/// Shielded Zcash accounts of another wallet (same device) are removed before
/// anything is displayed; a failure is retried at the next unlock.
fn forget_other_shielded_wallets(data_dir: &Path, seed: &[u8]) {
    if let Err(e) = zcash_shielded::forget_other_wallets(data_dir, seed) {
        eprintln!("Zcash protégé : {e:#}");
    }
}

/// Monero key images for outputs received since the last pass (detecting spends
/// made elsewhere, see `monero`), while the seed is in memory. A failure does not
/// block the unlock: it is redone at the next one or at the next send.
fn update_monero_key_images(data_dir: &Path, seed: &[u8], profile: u32) {
    if let Err(e) = monero::update_key_images(data_dir, seed, profile) {
        eprintln!("Monero : key images non calculées ({e:#})");
    }
}

/// Decrypts two shares and rebuilds the secret, writing nothing but temporary
/// files. Marked shares (see `KIT_MARK_PREFIX`): refused if they come from two
/// different kits, and the rebuilt secret must give back the kit's fingerprint →
/// `true`. Unmarked shares (older kits): rebuilt with no possible proof → `false`
/// (the user then checks the recovered address). A marked share with an unmarked
/// one: two different kits, refused.
fn recover_backup_secret(
    data_dir: &Path,
    backup_1: (&[u8], &[u8], &str),
    backup_2: (&[u8], &[u8], &str),
) -> Result<(Zeroizing<Vec<u8>>, bool)> {
    std::fs::create_dir_all(data_dir)?;
    // Each decrypted share is as sensitive as a partial master key (2 of 3 are enough
    // to rebuild everything): same `Zeroizing` treatment.
    let mut decrypted_shares: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(2);
    let mut marks = Vec::with_capacity(2);
    for (i, (encrypted, privkey_armored, passphrase)) in [backup_1, backup_2].iter().enumerate() {
        let tmp_path = data_dir.join(format!("tmp_restore_{i}.asc"));
        let (decrypted, name) =
            decrypt_with_armored_privkey_named(encrypted, &tmp_path, privkey_armored, passphrase)
                .with_context(|| {
                format!(
                    "échec du déchiffrement de la part de sauvegarde n°{}",
                    i + 1
                )
            })?;
        decrypted_shares.push(Zeroizing::new(decrypted));
        marks.push(parse_kit_mark(name.as_deref()));
    }
    let verified = match (&marks[0], &marks[1]) {
        (Some(a), Some(b)) => {
            anyhow::ensure!(a.kit == b.kit, KITS_DIFFERENT);
            true
        }
        (None, None) => false,
        _ => anyhow::bail!(KITS_DIFFERENT),
    };
    let share_refs: Vec<&[u8]> = decrypted_shares.iter().map(|s| s.as_slice()).collect();
    let recovered = Zeroizing::new(shamir::reconstruct_secret(2, &share_refs)?);
    if verified {
        let check = kit_check(&recovered);
        anyhow::ensure!(
            marks.iter().flatten().all(|mark| mark.check == check),
            KIT_CHECK_FAILED
        );
    }
    Ok((recovered, verified))
}

/// Check of two shares BEFORE a restore, writing nothing.
pub struct RestoreCheck {
    /// Addresses the restore will give back (main profile), to show the user before
    /// they confirm.
    pub addresses: Addresses,
    /// Marked kit: the shares belong together and give back the kit's wallet
    /// (fingerprint verified). `false`: a kit from before marks existed.
    pub verified: bool,
}

/// Check of two shares before a restore: shares that do not belong together are
/// refused (`KITS_DIFFERENT`, `KIT_CHECK_FAILED`), and the recovered addresses are
/// returned.
pub fn check_restore(
    data_dir: &Path,
    backup_1: (&[u8], &[u8], &str),
    backup_2: (&[u8], &[u8], &str),
) -> Result<RestoreCheck> {
    let (recovered, verified) = recover_backup_secret(data_dir, backup_1, backup_2)?;
    let _recovered_lock = memory_guard::lock(&recovered);
    Ok(RestoreCheck {
        addresses: derive_addresses(&recovered, 0)?,
        verified,
    })
}

/// Restores a wallet from 2 backup shares (any 2 of the 3) and recreates a local
/// vault on THIS device with a new password. To use when the original device is
/// lost.
pub fn restore_wallet(
    data_dir: &Path,
    new_device_password: &str,
    backup_1: (&[u8], &[u8], &str),
    backup_2: (&[u8], &[u8], &str),
) -> Result<Addresses> {
    restore_wallet_with(
        data_dir,
        new_device_password,
        backup_1,
        backup_2,
        &WindowsHelloSealer,
    )
}

/// `sealer` is injectable for tests, for the same reason as `reset_wallet_with`:
/// found in the same audit, the same class of bug existed here. `restore_wallet`
/// replaces the device's "device" identity (unlike `create_wallet`, it does not
/// even require that no vault exists; see its own docs, this is the "original
/// device lost" scenario) WITHOUT ever invalidating an existing biometric
/// enrollment, which refers to the OLD "device" identity. The new
/// `device_vault.asc` is only encrypted for the new identity, never for the old
/// "device_biometric" one, so a biometric unlock after restoring would fail
/// cleanly, but would still show as enabled (`biometric_unlock_enrolled` only
/// checks that the files exist) and would leave the old device's TPM key orphaned
/// forever.
fn restore_wallet_with(
    data_dir: &Path,
    new_device_password: &str,
    backup_1: (&[u8], &[u8], &str),
    backup_2: (&[u8], &[u8], &str),
    sealer: &dyn SecretSealer,
) -> Result<Addresses> {
    check_new_password(new_device_password)?;
    // Shares that do not belong together: refused BEFORE touching the device's state
    // (see `recover_backup_secret`).
    let (recovered, _verified) = recover_backup_secret(data_dir, backup_1, backup_2)?;
    let _recovered_lock = memory_guard::lock(&recovered);
    let default_profile = Profile {
        index: 0,
        label: DEFAULT_PROFILE_LABEL.to_string(),
        archived: false,
    };
    let addresses = derive_addresses(&recovered, default_profile.index)?;
    // The old wallet's state is wiped BEFORE writing the new vault: on failure, the
    // old one stays intact (see `remove_seed_bound_state`).
    remove_seed_bound_state(data_dir)?;
    // Any profile label created beyond the default on the old device is lost (it is
    // not part of the Shamir backup, which only protects the entropy). No consequence
    // for the funds: the same addresses can still be derived at the same indexes from
    // the recovered seed if the user recreates them with the same indexes.
    save_profiles(data_dir, std::slice::from_ref(&default_profile))?;

    let (device_pub, device_priv) = generate_pgp_identity("device", new_device_password)?;
    let device_priv = Zeroizing::new(device_priv); // see the equivalent comment in create_wallet
    std::fs::write(data_dir.join(DEVICE_PUBKEY_FILE), &device_pub)?;
    write_device_privkey(data_dir, &device_priv)?;
    let vault = encrypt_with_armored_pubkey(
        &recovered,
        &data_dir.join("tmp_device_pub.asc"),
        &device_pub,
        None,
    )?;
    std::fs::write(data_dir.join(DEVICE_VAULT_FILE), &vault)?;

    // Any biometric enrollment referred to the OLD "device" identity: it can never be
    // valid again once `device_vault.asc` has been replaced above (see this function's
    // docs). Best-effort, like the equivalent cleanup in
    // `disable_biometric_unlock_with`.
    try_remove_existing_biometric_enrollment(data_dir, sealer);
    for file in [
        DEVICE_BIOMETRIC_PUBKEY_FILE,
        DEVICE_BIOMETRIC_PRIVKEY_FILE,
        DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
        DEVICE_BIOMETRIC_KEY_META_FILE,
    ] {
        let _ = std::fs::remove_file(data_dir.join(file));
    }

    // Proving possession of 2 backup shares is a far stronger proof of identity than a
    // password; any anti-brute-force lock built up on the old password (before the
    // restore) has no reason to apply to the new vault, which was just created with a
    // different password.
    reset_unlock_attempts(data_dir);

    // `recovered` is wiped automatically at the end of the function (the `Zeroizing`
    // Drop), even on an early return from one of the `?` lines above.
    Ok(addresses)
}

/// Local state tied to a seed (shielded Zcash database, Monero state), deleted when
/// this device's wallet changes. Also the recipients already paid: otherwise the
/// "new address" warning would disappear for a different wallet (at worst, a few
/// extra warnings if the same wallet comes back).
///
/// Background syncs are stopped first (see `seed_state`). A file that cannot be
/// deleted is an error: the reset or restore stops BEFORE touching the vault,
/// instead of leaving the old wallet's data to the next one. (A file still open is
/// in any case set aside at the next unlock:
/// `zcash_shielded::forget_other_wallets`, Monero profile binding.)
fn remove_seed_bound_state(data_dir: &Path) -> Result<()> {
    crate::seed_state::wipe(|| {
        zcash_shielded::forget_known();
        monero::forget_known();
        for file in [
            "zcash_shielded.sqlite",
            "zcash_shielded.sqlite-journal",
            "zcash_shielded.sqlite-wal",
            "zcash_shielded.sqlite-shm",
            "monero_wallet.json",
            "sent_recipients.json",
        ] {
            remove_with_retry(&data_dir.join(file)).map_err(|_| {
                anyhow::anyhow!("effacement de {file} impossible : le fichier est encore ouvert (autre programme ?) — rien n'a été supprimé, fermez l'app puis recommencez")
            })?;
        }
        wallet_birthday::forget(data_dir);
        Ok(())
    })
}

/// Deletes `path` (absent: already done), retrying for 3 s: a brief read (balance
/// display) may hold it open for a moment, and Windows then refuses to delete an
/// open file.
fn remove_with_retry(path: &Path) -> std::io::Result<()> {
    let mut attempts = 0;
    loop {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if attempts >= 30 => return Err(e),
            Err(_) => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

pub fn device_vault_exists(data_dir: &Path) -> bool {
    data_dir.join(DEVICE_VAULT_FILE).exists()
}

/// Reads the device's public key (certificate) for display/sharing: used by the
/// "encrypt a message" section (others can add it as a recipient to write to you)
/// and by the app's "Certificate" tab.
pub fn read_device_pubkey_armored(data_dir: &Path) -> Result<String> {
    std::fs::read_to_string(data_dir.join(DEVICE_PUBKEY_FILE))
        .context("lecture de la clé publique de l'appareil")
}

/// Decrypts an arbitrary PGP message (the app's "Message" section) received by this
/// device, with the local vault's private key. Unlike the wallet's vault, the
/// content decrypted here is arbitrary text meant to be read, not a secret to
/// protect again, so no `memory_guard::wipe` is needed.
///
/// Goes through `unlock_seed` (seed discarded without being used, same pattern as
/// `delete_profile`) only to benefit from its anti-brute-force lock: the private
/// key decrypted here is protected by exactly the same password as the wallet's
/// vault, so calling it directly without that barrier would have opened a second
/// door, with unlimited attempts, for guessing THAT password, making the lock
/// already in place on `unlock_wallet`/`send_*` useless.
///
/// The key that decrypts these messages is ALSO the one that decrypts the vault:
/// the contents of `device_vault.asc`, pasted here as a "message", would give back
/// the master entropy. Until audit round 22, the only protection was that 32 random
/// bytes almost never form valid UTF-8 text: a probability, not a guarantee. It is
/// now refused explicitly.
pub fn decrypt_incoming_message(
    data_dir: &Path,
    device_password: &str,
    ciphertext: &str,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let plaintext = Zeroizing::new(with_device_privkey_path(data_dir, |privkey_path| {
        pgp_engine::decrypt_share(ciphertext.as_bytes(), privkey_path, device_password)
    })?);
    anyhow::ensure!(
        plaintext.as_slice() != seed.as_slice(),
        "ce « message » est le coffre du portefeuille lui-même — déchiffrement refusé"
    );
    String::from_utf8(plaintext.to_vec())
        .context("le message déchiffré n'est pas du texte UTF-8 valide")
}

/// Deletes this device's local vault (useful to test onboarding again, or for a real
/// "reset this device"). Touches nothing else: if the user did export their 3 backup
/// shares at creation, the wallet can still be recovered through `restore_wallet`. No
/// error if the vault did not exist.
pub fn reset_wallet(data_dir: &Path) -> Result<()> {
    reset_wallet_with(data_dir, &WindowsHelloSealer)
}

/// Found during an independent audit (not a failing test): until then, this
/// function only touched `device_pubkey.asc`/`device_vault.asc` and the "device"
/// private key, never the biometric enrollment. In practice, resetting a device
/// with Windows Hello enabled left an orphaned key in the TPM forever (exactly the
/// risk already documented by `disable_biometric_unlock`, just never applied here),
/// plus the 4 obsolete `device_biometric_*` files on disk, which would then have
/// made `biometric_unlock_enrolled` believe that a SECOND wallet created later on
/// the same device had biometrics enabled, even though the new vault was never
/// encrypted for that identity (the unlock would still fail cleanly, but the
/// displayed state would be wrong). `sealer` is injectable for tests, same pattern
/// as `enroll_biometric_unlock`/`disable_biometric_unlock`: it must never trigger a
/// real Windows Hello prompt during `cargo test`.
fn reset_wallet_with(data_dir: &Path, sealer: &dyn SecretSealer) -> Result<()> {
    // First: on failure, the wallet stays intact.
    remove_seed_bound_state(data_dir)?;
    try_remove_existing_biometric_enrollment(data_dir, sealer);
    for file in [
        DEVICE_PUBKEY_FILE,
        DEVICE_VAULT_FILE,
        DEVICE_BIOMETRIC_PUBKEY_FILE,
        DEVICE_BIOMETRIC_PRIVKEY_FILE,
        DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
        DEVICE_BIOMETRIC_KEY_META_FILE,
    ] {
        let path = data_dir.join(file);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("suppression de {file} impossible"))?;
        }
    }
    remove_device_privkey(data_dir)?;
    // Best-effort: a new vault must start with a clean failure counter.
    reset_unlock_attempts(data_dir);
    Ok(())
}

/// Serializes the whole read-attempt-write cycle of the failure counter within the
/// process. Without it, the on-disk counter (read, then modified, then written back
/// in 3 separate steps in `unlock_seed`) is open to a race: a script invoking
/// `unlock_wallet`/`send_*` several times IN PARALLEL would see every call read the
/// same counter before any had time to increment it, then each would write back its
/// own value over the others'. N passwords tried at once would count as a single
/// failure, defeating the anti-brute-force lock. This protects against a script
/// looping from THIS instance of the app; a second instance of the program running
/// in parallel is not covered by an in-memory mutex, but that is a far more
/// constrained scenario than a simple `Promise.all` loop in the frontend.
static UNLOCK_MUTEX: Mutex<()> = Mutex::new(());

/// Returns the unlocked seed wrapped in `Zeroizing`: it is wiped automatically when
/// dropped, including when the caller returns early through `?` after getting it
/// (unlike a manual `memory_guard::wipe`, which would be skipped in that case).
fn unlock_seed(data_dir: &Path, device_password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let _serialize = UNLOCK_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // The lock only counts wrong passwords, not a missing vault (otherwise querying a
    // device with no wallet would build up an artificial counter).
    let vault =
        std::fs::read(data_dir.join(DEVICE_VAULT_FILE)).context("coffre local introuvable")?;
    enforce_unlock_lockout(data_dir)?;
    let result = with_device_privkey_path(data_dir, |privkey_path| {
        pgp_engine::decrypt_share(&vault, privkey_path, device_password)
    });
    match result {
        Ok(seed) => {
            reset_unlock_attempts(data_dir);
            migrate_device_privkey_to_store(data_dir, active_key_store());
            Ok(Zeroizing::new(seed))
        }
        Err(e) => {
            // Only a real decryption failure (wrong password) counts: an unreachable private
            // key is not a password attempt, see `KeyMaterialUnavailable`.
            if !is_key_material_unavailable(&e) {
                record_unlock_failure(data_dir);
            }
            Err(e)
        }
    }
}

// --- Biometric unlock (Windows Hello/TPM) ----------------------------------
//
// A path IN ADDITION to the password, never a replacement: see the comment on the
// `DEVICE_BIOMETRIC_*` constants above, and `windows_hello.rs` for why the TPM was
// chosen over DPAPI.

/// Abstraction over "seal/recover a secret through a local biometric check". It
/// lets the whole orchestration (enable/disable/unlock, files, anti-brute-force
/// lock) be tested with a fake in-memory sealer, without real Windows Hello
/// hardware. In production, always `WindowsHelloSealer`.
pub(crate) trait SecretSealer {
    fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)>;
    fn unlock(&self, key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn remove(&self, key_name: &str) -> Result<()>;
}

/// `true` if `err` is a deliberate cancellation of the Windows Hello prompt by the
/// user (NTE_USER_CANCELLED, Windows code `0x800704c7`): a deliberate choice ("I'd
/// rather type my password"), never an attempt to guess the secret. Biometrics are
/// structurally not "guessable" through this function; they are entirely gated by
/// the TPM/OS. Without this distinction, a user clicking "Cancel" several times
/// (change of mind, flaky sensor) would trigger the same anti-brute-force lock
/// meant for a real attack, punishing legitimate use. The numeric code (unlike the
/// message text, which depends on the Windows language) is stable and independent
/// of the system language, as checked empirically during the spike
/// (`tpm_hello_spike.rs`, `cancel` command).
fn is_user_cancellation(err: &anyhow::Error) -> bool {
    err.to_string().to_lowercase().contains("0x800704c7")
}

#[cfg(windows)]
struct WindowsHelloSealer;

#[cfg(windows)]
impl SecretSealer for WindowsHelloSealer {
    fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
        crate::windows_hello::enroll(secret)
    }
    fn unlock(&self, key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crate::windows_hello::unlock(key_name, sealed_blob)
    }
    fn remove(&self, key_name: &str) -> Result<()> {
        crate::windows_hello::remove(key_name)
    }
}

#[cfg(not(windows))]
struct WindowsHelloSealer;

#[cfg(not(windows))]
impl SecretSealer for WindowsHelloSealer {
    fn enroll(&self, _secret: &[u8]) -> Result<(String, Vec<u8>)> {
        Err(anyhow::anyhow!(
            "le déverrouillage biométrique n'est disponible que sous Windows"
        ))
    }
    fn unlock(&self, _key_name: &str, _sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(anyhow::anyhow!(
            "le déverrouillage biométrique n'est disponible que sous Windows"
        ))
    }
    fn remove(&self, _key_name: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "le déverrouillage biométrique n'est disponible que sous Windows"
        ))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BiometricKeyMeta {
    key_name: String,
    created_unix: u64,
}

fn read_biometric_meta(data_dir: &Path) -> Result<BiometricKeyMeta> {
    let content = std::fs::read_to_string(data_dir.join(DEVICE_BIOMETRIC_KEY_META_FILE))
        .context("déverrouillage biométrique non activé sur cet appareil")?;
    serde_json::from_str(&content).context("métadonnées de la clé biométrique corrompues")
}

/// `true` if biometric unlock is enabled on this device.
pub fn biometric_unlock_enrolled(data_dir: &Path) -> bool {
    data_dir.join(DEVICE_BIOMETRIC_SEALED_SECRET_FILE).exists()
}

fn try_remove_existing_biometric_enrollment(data_dir: &Path, sealer: &dyn SecretSealer) {
    if let Ok(meta) = read_biometric_meta(data_dir) {
        let _ = sealer.remove(&meta.key_name);
    }
}

/// Enables biometric unlock IN ADDITION to the existing password, never instead of
/// it: re-encrypts `device_vault.asc` for TWO recipients (the existing "device"
/// identity, unchanged, + a new "device_biometric" identity whose passphrase is a
/// random 256-bit secret sealed by the TPM, see `windows_hello::enroll`). Requires
/// the device's current password (same anti-brute-force lock as the other sensitive
/// actions, through `unlock_seed`): enabling this second path is a security action,
/// not just a convenience.
///
/// Re-enrolling when an enrollment already exists replaces it cleanly (the old TPM
/// key is deleted best-effort) rather than requiring a prior
/// `disable_biometric_unlock`, which helps when the user reconfigures their Windows
/// Hello fingerprint/face.
pub fn enroll_biometric_unlock(data_dir: &Path, device_password: &str) -> Result<()> {
    enroll_biometric_unlock_with(data_dir, device_password, &WindowsHelloSealer)
}

fn enroll_biometric_unlock_with(
    data_dir: &Path,
    device_password: &str,
    sealer: &dyn SecretSealer,
) -> Result<()> {
    let master_entropy = unlock_seed(data_dir, device_password)?;
    let _entropy_lock = memory_guard::lock(&master_entropy);

    try_remove_existing_biometric_enrollment(data_dir, sealer);

    let secret = Zeroizing::new(entropy::generate_master_entropy());
    let biometric_passphrase = Zeroizing::new(hex::encode(&secret[..]));
    let (bio_pub, bio_priv) = generate_pgp_identity("device_biometric", &biometric_passphrase)?;
    let bio_priv = Zeroizing::new(bio_priv); // see the equivalent comment in create_wallet

    let (key_name, sealed_blob) = sealer.enroll(&secret)?;

    // From here on, the TPM key really exists (see `windows_hello::enroll`). If a
    // later step fails, this function never writes the metadata file
    // (`DEVICE_BIOMETRIC_KEY_META_FILE`) that would let it be found later: without
    // this explicit cleanup, it would stay orphaned in the TPM forever, invisible to
    // `try_remove_existing_biometric_enrollment` on a future attempt.
    let result = finish_enroll(
        data_dir,
        device_password,
        &master_entropy,
        &bio_pub,
        &bio_priv,
        &key_name,
        &sealed_blob,
    );
    if result.is_err() {
        let _ = sealer.remove(&key_name);
    }
    result
}

fn finish_enroll(
    data_dir: &Path,
    device_password: &str,
    master_entropy: &[u8],
    bio_pub: &[u8],
    bio_priv: &[u8],
    key_name: &str,
    sealed_blob: &[u8],
) -> Result<()> {
    let device_pub = std::fs::read(data_dir.join(DEVICE_PUBKEY_FILE))
        .context("lecture de la clé publique de l'appareil")?;
    let new_vault = pgp_engine::encrypt_share_multi(master_entropy, &[&device_pub, bio_pub])?;

    // Write-verify-rename: the existing password must be able to decrypt the NEW vault
    // before the old one is ever overwritten. Otherwise, a malformed new vault would
    // break the only unlock path that existed before this call.
    let tmp_vault_path = data_dir.join("tmp_device_vault_new.asc");
    std::fs::write(&tmp_vault_path, &new_vault)?;
    let _guard = TempFileGuard(&tmp_vault_path);
    with_device_privkey_path(data_dir, |privkey_path| pgp_engine::decrypt_share(&new_vault, privkey_path, device_password))
        .context("vérification post-ré-chiffrement du coffre : le mot de passe existant ne fonctionne plus, activation annulée")?;

    std::fs::write(data_dir.join(DEVICE_BIOMETRIC_PUBKEY_FILE), bio_pub)?;
    std::fs::write(data_dir.join(DEVICE_BIOMETRIC_PRIVKEY_FILE), bio_priv)?;
    std::fs::write(
        data_dir.join(DEVICE_BIOMETRIC_SEALED_SECRET_FILE),
        sealed_blob,
    )?;
    let created_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let meta = BiometricKeyMeta {
        key_name: key_name.to_string(),
        created_unix,
    };
    std::fs::write(
        data_dir.join(DEVICE_BIOMETRIC_KEY_META_FILE),
        serde_json::to_string(&meta)?,
    )?;
    std::fs::rename(&tmp_vault_path, data_dir.join(DEVICE_VAULT_FILE))?; // last step, atomic
    reset_biometric_unlock_attempts(data_dir);
    Ok(())
}

/// Disables biometric unlock: goes back to a vault protected by the password alone
/// (as before it was ever enabled), deletes the TPM key (best-effort) and the
/// biometric files. Requires the device password, never the biometrics themselves,
/// to disable it.
pub fn disable_biometric_unlock(data_dir: &Path, device_password: &str) -> Result<()> {
    disable_biometric_unlock_with(data_dir, device_password, &WindowsHelloSealer)
}

fn disable_biometric_unlock_with(
    data_dir: &Path,
    device_password: &str,
    sealer: &dyn SecretSealer,
) -> Result<()> {
    let master_entropy = unlock_seed(data_dir, device_password)?;
    let _entropy_lock = memory_guard::lock(&master_entropy);

    let device_pub = std::fs::read(data_dir.join(DEVICE_PUBKEY_FILE))
        .context("lecture de la clé publique de l'appareil")?;
    let tmp_pub_path = data_dir.join("tmp_device_pub_disable.asc");
    let new_vault = encrypt_with_armored_pubkey(&master_entropy, &tmp_pub_path, &device_pub, None)?;

    let tmp_vault_path = data_dir.join("tmp_device_vault_disable.asc");
    std::fs::write(&tmp_vault_path, &new_vault)?;
    let _guard = TempFileGuard(&tmp_vault_path);
    with_device_privkey_path(data_dir, |privkey_path| pgp_engine::decrypt_share(&new_vault, privkey_path, device_password))
        .context("vérification post-ré-chiffrement du coffre : le mot de passe existant ne fonctionne plus, désactivation annulée")?;
    std::fs::rename(&tmp_vault_path, data_dir.join(DEVICE_VAULT_FILE))?;

    if let Ok(meta) = read_biometric_meta(data_dir) {
        let _ = sealer.remove(&meta.key_name);
    }
    for file in [
        DEVICE_BIOMETRIC_PUBKEY_FILE,
        DEVICE_BIOMETRIC_PRIVKEY_FILE,
        DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
        DEVICE_BIOMETRIC_KEY_META_FILE,
    ] {
        let _ = std::fs::remove_file(data_dir.join(file));
    }
    reset_biometric_unlock_attempts(data_dir);
    Ok(())
}

/// Serializes the read-attempt-write cycle of the biometric failure counter, for
/// the same reason as `UNLOCK_MUTEX` for the password; an entirely separate mutex
/// so one never waits on the other.
static BIOMETRIC_UNLOCK_MUTEX: Mutex<()> = Mutex::new(());

fn unlock_seed_biometric(data_dir: &Path, sealer: &dyn SecretSealer) -> Result<Zeroizing<Vec<u8>>> {
    let _serialize = BIOMETRIC_UNLOCK_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let vault =
        std::fs::read(data_dir.join(DEVICE_VAULT_FILE)).context("coffre local introuvable")?;
    enforce_biometric_unlock_lockout(data_dir)?;
    let meta = read_biometric_meta(data_dir)?;
    let sealed_blob = std::fs::read(data_dir.join(DEVICE_BIOMETRIC_SEALED_SECRET_FILE))
        .context("secret biométrique scellé introuvable")?;

    let secret = match sealer.unlock(&meta.key_name, &sealed_blob) {
        Ok(s) => s,
        Err(e) => {
            // A deliberate cancellation of the prompt (see `is_user_cancellation`) never
            // counts toward the anti-brute-force lock; only a real verification failure
            // (corrupt blob, missing TPM key, etc.) does.
            if !is_user_cancellation(&e) {
                record_biometric_unlock_failure(data_dir);
            }
            return Err(e);
        }
    };
    let passphrase = Zeroizing::new(hex::encode(&secret[..]));
    let privkey_path = data_dir.join(DEVICE_BIOMETRIC_PRIVKEY_FILE);
    match pgp_engine::decrypt_share(&vault, &privkey_path.to_string_lossy(), &passphrase) {
        Ok(seed) => {
            reset_biometric_unlock_attempts(data_dir);
            Ok(Zeroizing::new(seed))
        }
        Err(e) => {
            record_biometric_unlock_failure(data_dir);
            Err(e)
        }
    }
}

/// Unlocks the vault through biometrics (Windows Hello/TPM) rather than the
/// password: a path parallel to `unlock_wallet`, never mixed with its
/// anti-brute-force lock or its mutex. Returns the same addresses, for every active
/// profile.
pub fn unlock_wallet_biometric(data_dir: &Path) -> Result<Vec<ProfileAddresses>> {
    unlock_wallet_biometric_with(data_dir, &WindowsHelloSealer)
}

fn unlock_wallet_biometric_with(
    data_dir: &Path,
    sealer: &dyn SecretSealer,
) -> Result<Vec<ProfileAddresses>> {
    let seed = unlock_seed_biometric(data_dir, sealer)?;
    let _seed_lock = memory_guard::lock(&seed);
    forget_other_shielded_wallets(data_dir, &seed);
    list_profiles(data_dir)
        .into_iter()
        .map(|profile| {
            let addresses = derive_addresses(&seed, profile.index)?;
            update_monero_key_images(data_dir, &seed, profile.index);
            Ok(ProfileAddresses {
                profile,
                addresses: Some(addresses),
            })
        })
        .collect()
}

pub fn get_evm_balance(address: &str, network: &wallet_flow::EvmNetwork) -> Result<u128> {
    eth_rpc::EthRpc::new(network.rpc).balance(address)
}

pub fn get_btc_balance(address: &str, network: &wallet_flow::BtcNetwork) -> Result<u64> {
    let utxos = btc_rpc::EsploraClient::new(network.esplora_base).utxos(address)?;
    Ok(utxos.iter().map(|u| u.value_sat).sum())
}

/// Balance of the Bitcoin card.
pub struct BtcBalanceView {
    /// Confirmed, minus what is leaving in pending transactions: a send shows up as
    /// soon as it is broadcast (it can only go out).
    pub settled_sat: u64,
    /// Unconfirmed receipts, shown SEPARATELY and not counted: a pending receipt can
    /// still be cancelled by its sender (double spend, RBF replacement), the classic
    /// "payment received" scam that vanishes. Found in audit round 23: the card was
    /// counting them.
    pub incoming_pending_sat: u64,
}

/// A pending transaction classified by its net change for the address: negative =
/// send (change returned deducted), positive = receipt.
pub fn get_btc_balance_view(
    address: &str,
    network: &wallet_flow::BtcNetwork,
) -> Result<BtcBalanceView> {
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let (stats, mempool) = std::thread::scope(|scope| {
        let stats = scope.spawn(|| esplora.address_stats(address));
        let mempool = esplora.mempool_history(address);
        (
            stats
                .join()
                .expect("le fil des statistiques ne doit pas paniquer"),
            mempool,
        )
    });
    let (stats, mempool) = (stats?, mempool?);
    Ok(btc_balance_view(
        stats.confirmed_sat,
        mempool.iter().map(|tx| tx.net_sat),
    ))
}

fn btc_balance_view(
    confirmed_sat: i128,
    pending_nets: impl Iterator<Item = i128>,
) -> BtcBalanceView {
    let (mut settled, mut incoming) = (confirmed_sat, 0i128);
    for net in pending_nets {
        if net < 0 {
            settled += net;
        } else {
            incoming += net;
        }
    }
    let to_u64 = |v: i128| u64::try_from(v.max(0)).unwrap_or(u64::MAX);
    BtcBalanceView {
        settled_sat: to_u64(settled),
        incoming_pending_sat: to_u64(incoming),
    }
}

pub fn get_sol_balance(address: &str, network: &wallet_flow::SolNetwork) -> Result<u64> {
    sol_rpc::SolRpc::new(network.rpc).balance_lamports(address)
}

/// USDC balance of `owner_address` (mainnet only, see sol_spl.rs), in the smallest
/// unit (6 decimals); 0 if the Associated Token Account does not exist yet (no USDC
/// ever received), not an error.
pub fn get_usdc_balance(owner_address: &str, network: &wallet_flow::SolNetwork) -> Result<u64> {
    get_spl_balance(owner_address, &sol_spl::usdc_mint_mainnet(), network)
}

/// Balance of an SPL token `mint` held by `owner_address` (associated token
/// account; absent: 0).
pub fn get_spl_balance(
    owner_address: &str,
    mint: &[u8; 32],
    network: &wallet_flow::SolNetwork,
) -> Result<u64> {
    let owner_bytes = bs58::decode(owner_address.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let owner: [u8; 32] = owner_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = sol_spl::find_associated_token_address(&owner, mint);
    let ata_b58 = bs58::encode(ata).into_string();
    Ok(sol_rpc::SolRpc::new(network.rpc)
        .token_account_balance(&ata_b58)?
        .unwrap_or(0))
}

/// History of a registry SPL token for `owner_address`: derives its associated
/// token account (ATA), then delegates to `history::spl_history` (see its docs: the
/// ATA, not the "owner" address, is what actually receives/sends the token). If the
/// ATA does not exist yet (token never received), `getSignaturesForAddress` simply
/// returns an empty list, without an error.
pub fn get_spl_tx_history(
    owner_address: &str,
    mint: &[u8; 32],
    network: &wallet_flow::SolNetwork,
    limit: u32,
) -> Result<Vec<history::TxEntry>> {
    history::spl_history(network.rpc, &spl_token_account(owner_address, mint)?, limit)
}

/// Associated USDC token account (ATA, base58) of the Solana address
/// `owner_address`.
pub fn usdc_token_account(owner_address: &str) -> Result<String> {
    spl_token_account(owner_address, &sol_spl::usdc_mint_mainnet())
}

/// Associated token account (ATA, base58) of the Solana address `owner_address` for
/// the token `mint`.
pub fn spl_token_account(owner_address: &str, mint: &[u8; 32]) -> Result<String> {
    let owner_bytes = bs58::decode(owner_address.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let owner: [u8; 32] = owner_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = sol_spl::find_associated_token_address(&owner, mint);
    Ok(bs58::encode(ata).into_string())
}

/// `Some(rent lamports)` if the USDC Associated Token Account of `to_address` does
/// not exist yet (creating it in `send_usdc` will charge this amount on top of the
/// usual network fee), `None` if it already exists. Read-only, meant to be called
/// BEFORE confirmation so a hidden cost is never revealed after the fact (see
/// `describe_possible_ata_rent` in the Tauri app, which formats this figure for the
/// dialog).
pub fn usdc_ata_rent_lamports_if_missing(
    to_address: &str,
    network: &wallet_flow::SolNetwork,
) -> Result<Option<u64>> {
    spl_ata_rent_lamports_if_missing(to_address, &sol_spl::usdc_mint_mainnet(), network)
}

/// Rent for the recipient's `mint` token account if it does not exist yet (created
/// and paid for by the sender); `None` if it exists.
pub fn spl_ata_rent_lamports_if_missing(
    to_address: &str,
    mint: &[u8; 32],
    network: &wallet_flow::SolNetwork,
) -> Result<Option<u64>> {
    let to_bytes = bs58::decode(to_address.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let to_owner: [u8; 32] = to_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let dest_ata = sol_spl::find_associated_token_address(&to_owner, mint);
    let dest_ata_b58 = bs58::encode(dest_ata).into_string();
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    if rpc.account_exists(&dest_ata_b58)? {
        return Ok(None);
    }
    Ok(Some(rpc.minimum_rent_exempt_balance(165)?))
}

/// `true` if a transaction involving `address` has not reached finality yet
/// (Bitcoin mempool, or a latest Solana signature not yet "finalized"); used to
/// show "transaction detected, pending" in the UI before the balance moves. No
/// equivalent for Ethereum: unlike Esplora and `getSignaturesForAddress` (a
/// standard JSON-RPC method), no public EVM node exposes the pending transactions
/// of a given address (the same limit as for the history, see
/// `history::evm_history`).
pub fn has_pending_btc(address: &str, network: &wallet_flow::BtcNetwork) -> Result<bool> {
    btc_rpc::EsploraClient::new(network.esplora_base).has_mempool_tx(address)
}

pub fn has_pending_sol(address: &str, network: &wallet_flow::SolNetwork) -> Result<bool> {
    sol_rpc::SolRpc::new(network.rpc).has_unfinalized_tx(address)
}

/// Fee rate cap for a Bitcoin swap (fees chosen automatically, see
/// `send_swap_btc`), far above usual rates; only extreme, brief spikes have
/// exceeded it.
pub const BTC_SWAP_MAX_FEE_RATE_SAT_VB: u32 = 300;
/// Gas for a simple ETH transfer to an ordinary address.
pub const EVM_TRANSFER_GAS_LIMIT: u64 = 21_000;
/// Gas cap for a deposit on the THORChain router: measured at 45,632 for real
/// (`eth_estimateGas`, test
/// `thorchain_router_deposit_gas_vs_intrinsic_on_the_real_network`), so more than
/// 3x headroom; also used as the bound shown as the maximum fee BEFORE
/// confirmation.
pub const EVM_SWAP_MAX_GAS_LIMIT: u64 = 150_000;

/// Gas price shown in the confirmation dialog, THEN used as is for signing (never
/// reread after confirmation): "sign what you see", applied to fees. Refused above
/// the safety cap on mainnet.
pub fn evm_gas_price_for_confirmation(network: &wallet_flow::EvmNetwork) -> Result<u128> {
    let gas_price = eth_rpc::EthRpc::new(network.rpc).gas_price()?;
    check_evm_gas_price(network, gas_price)?;
    Ok(gas_price)
}

fn check_evm_gas_price(network: &wallet_flow::EvmNetwork, gas_price: u128) -> Result<()> {
    // Each network's own cap (`EvmNetwork::max_gas_price_wei`); none on a test
    // network.
    if let Some(cap) = network.max_gas_price_wei {
        anyhow::ensure!(
            gas_price <= cap,
            "prix du gas annoncé par le nœud anormalement élevé ({} gwei, plafond de sécurité {} gwei) — envoi refusé",
            gas_price / 1_000_000_000,
            cap / 1_000_000_000
        );
    }
    Ok(())
}

/// Cap on a gas limit ESTIMATED by the node (Arbitrum, where the cost of posting to
/// Ethereum is counted in gas): above it, refused rather than trusting the node. A
/// transfer there usually uses less than 1 million.
pub const EVM_MAX_ESTIMATED_GAS: u64 = 5_000_000;
/// Fee oracle of OP Stack networks (same address on all of them: Base…).
const OP_GAS_PRICE_ORACLE: &str = "0x420000000000000000000000000000000000000F";

/// Fees for an EVM send, shown in the confirmation dialog THEN used as is for
/// signing ("sign what you see"); never reread afterwards.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EvmFee {
    pub gas_price: u128,
    pub gas_limit: u64,
    /// OP Stack networks (Base): Ethereum posting fees, charged on top of gas by the
    /// network itself (estimate with a margin); 0 elsewhere. Included in the balance
    /// check.
    pub l1_fee: u128,
}

impl EvmFee {
    /// Maximum fee: gas × price (a hard bound: never more than the limit) + estimated
    /// posting fees.
    pub fn max_total(&self) -> Result<u128> {
        self.gas_price
            .checked_mul(u128::from(self.gas_limit))
            .and_then(|gas| gas.checked_add(self.l1_fee))
            .context("frais de gas dépassant la capacité représentable")
    }
}

/// Fees for a native transfer of `value` wei (`data`: a contract call, empty for a
/// plain transfer) from `from`: the node's gas price (capped), a fixed or estimated
/// gas limit (+20%, bounded), and OP Stack posting fees where applicable (+25%).
pub fn evm_fee_for_confirmation(
    network: &wallet_flow::EvmNetwork,
    from: &[u8; 20],
    to: &[u8; 20],
    value: u128,
    data: &[u8],
) -> Result<EvmFee> {
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let gas_price = rpc.gas_price()?;
    check_evm_gas_price(network, gas_price)?;
    let gas_limit = match (network.transfer_gas, data.is_empty()) {
        (Some(fixed), true) => fixed,
        _ => {
            // Estimate refused for lack of funds: a clear message rather than the node's raw
            // error, which depends on its software ("insufficient funds" on Arbitrum, "EVM
            // error: OutOfFunds" on OP Mainnet, seen with a zero balance).
            let estimated = rpc
                .estimate_gas(
                    &derivation::format_address(from),
                    &derivation::format_address(to),
                    value,
                    data,
                )
                .map_err(|e| {
                    let text = format!("{e:#}");
                    if text.contains("insufficient funds") || text.contains("OutOfFunds") {
                        anyhow::anyhow!("fonds insuffisants pour ce montant et les frais du réseau")
                    } else {
                        e
                    }
                })?;
            let with_margin = estimated
                .saturating_add(estimated / 5)
                .max(eth_tx::intrinsic_gas(data));
            anyhow::ensure!(
                with_margin <= EVM_MAX_ESTIMATED_GAS,
                "gas estimé anormalement élevé ({with_margin}, maximum {EVM_MAX_ESTIMATED_GAS}) — envoi refusé"
            );
            with_margin
        }
    };
    let l1_fee = evm_l1_fee(network, to, value, data, gas_price, gas_limit)?;
    Ok(EvmFee {
        gas_price,
        gas_limit,
        l1_fee,
    })
}

/// Ethereum posting fee for a transaction on an OP Stack network (Base), 25% margin
/// included; 0 on other networks. Also used for transactions requested by a dApp
/// (`dapp_requests`).
pub fn evm_l1_fee(
    network: &wallet_flow::EvmNetwork,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    gas_price: u128,
    gas_limit: u64,
) -> Result<u128> {
    if !network.op_stack_l1_fee {
        return Ok(0);
    }
    let draft = eth_tx::EthTx {
        nonce: 0,
        gas_price,
        gas_limit,
        to: *to,
        value,
        chain_id: network.chain_id,
        data: data.to_vec(),
    };
    let fee = op_stack_l1_fee(&eth_rpc::EthRpc::new(network.rpc), &draft.unsigned_rlp())?;
    Ok(fee.saturating_add(fee / 4))
}

/// Enough balance for an EVM transfer (amount + maximum fee shown), checked BEFORE
/// the confirmation dialog. It used to be checked only afterwards: the user
/// confirmed a send that was refused right after, with a message in wei. Amounts in
/// the network's unit (ETH, BNB…).
pub fn ensure_evm_transfer_funds(
    network: &wallet_flow::EvmNetwork,
    from: &str,
    amount: &str,
    fee: EvmFee,
) -> Result<()> {
    let value = wallet_flow::parse_eth_to_wei(amount)?;
    let gas = fee.max_total()?;
    let needed = value
        .checked_add(gas)
        .context("montant + frais dépasse la capacité représentable")?;
    let balance = get_evm_balance(from, network)?;
    let unit = |wei: u128| {
        format!(
            "{} {}",
            tokens::format_amount(wei, 18),
            network.native_symbol
        )
    };
    anyhow::ensure!(
        needed <= balance,
        "fonds insuffisants : {} disponibles, {} + {} de frais requis",
        unit(balance),
        unit(value),
        unit(gas)
    );
    Ok(())
}

/// Enough funds to sell `amount` of `from_coin` through Jupiter, checked BEFORE the
/// confirmation dialog (seen on 2026-10-10: without funds, the dialog opened and
/// the refusal only came afterwards). SOL: the amount alone; the exact fee and rent
/// reserve is still checked by `send_jupiter_swap`.
pub fn ensure_jupiter_funds(from_coin: &str, owner: &str, amount: &str) -> Result<()> {
    if from_coin != "sol" {
        return ensure_token_funds(from_coin, "sol_mainnet", owner, amount);
    }
    let wanted = tokens::parse_amount(amount, 9)?;
    let balance = u128::from(get_sol_balance(owner, &wallet_flow::SOLANA_MAINNET)?);
    anyhow::ensure!(
        wanted <= balance,
        "fonds insuffisants : {} SOL disponibles, {} SOL requis",
        tokens::format_amount(balance, 9),
        tokens::format_amount(wanted, 9)
    );
    Ok(())
}

/// Enough token balance for a transfer (registry `tokens.rs`, USDC included),
/// checked before the confirmation dialog.
pub fn ensure_token_funds(token_id: &str, network: &str, owner: &str, amount: &str) -> Result<()> {
    let (balance, decimals) = if token_id == "usdc" && network == "sol_mainnet" {
        (
            u128::from(get_spl_balance(
                owner,
                &sol_spl::usdc_mint_mainnet(),
                &wallet_flow::SOLANA_MAINNET,
            )?),
            6,
        )
    } else {
        get_token_balance(token_id, network, owner)?
    };
    let wanted = tokens::parse_amount(amount, decimals)?;
    let symbol = tokens::find(token_id, network)
        .map_or_else(|| token_id.to_uppercase(), |(t, _)| t.symbol.to_string());
    anyhow::ensure!(
        wanted <= balance,
        "fonds insuffisants : {} {symbol} disponibles, {} {symbol} requis",
        tokens::format_amount(balance, decimals),
        tokens::format_amount(wanted, decimals)
    );
    Ok(())
}

/// Enough native coin for the gas of an ERC-20 token transfer, checked before the
/// confirmation dialog.
pub fn ensure_evm_gas_funds(
    network: &wallet_flow::EvmNetwork,
    from: &str,
    fee: EvmFee,
) -> Result<()> {
    let gas = fee.max_total()?;
    let balance = get_evm_balance(from, network)?;
    let unit = |wei: u128| {
        format!(
            "{} {}",
            tokens::format_amount(wei, 18),
            network.native_symbol
        )
    };
    anyhow::ensure!(
        gas <= balance,
        "fonds insuffisants : {} disponibles, {} de frais de gas requis",
        unit(balance),
        unit(gas)
    );
    Ok(())
}

/// The same check for a SOL transfer (amount + base fee), before the confirmation
/// dialog.
pub fn ensure_sol_transfer_funds(
    network: &wallet_flow::SolNetwork,
    from: &str,
    amount: &str,
) -> Result<()> {
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let lamports = wallet_flow::parse_sol_to_lamports(amount)?;
    let needed = lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    let balance = get_sol_balance(from, network)?;
    let unit = |l: u64| format!("{} SOL", tokens::format_amount(u128::from(l), 9));
    anyhow::ensure!(
        needed <= balance,
        "fonds insuffisants : {} disponibles, {} + {} de frais requis",
        unit(balance),
        unit(lamports),
        unit(SOL_FEE_LAMPORTS)
    );
    Ok(())
}

// --- Maximum amount that can be sent ("Max" button)
// ---------------------------------
//
// Balance minus the network fees, with the same fee rules as the send itself:
// recomputed when the confirmation dialog opens, so the amount shown (and signed)
// stays exact if the fees have moved.

/// Estimated fee for a maximum EVM transfer: gas for a zero transfer to `to` (the
/// amount does not change the gas of a native transfer; an estimate with the whole
/// balance would fail for lack of anything to pay the gas with).
pub fn evm_max_fee(
    network: &wallet_flow::EvmNetwork,
    from: Option<&str>,
    to: &str,
) -> Result<EvmFee> {
    evm_transfer_fee_for_confirmation(network, from, to, "0")
}

/// EVM native coin: balance minus gas × price, minus the Ethereum posting fees (OP
/// Stack) increased by a quarter, since they are charged at the block and may rise
/// a little by then; the tiny remainder stays.
pub fn evm_max_native(
    network: &wallet_flow::EvmNetwork,
    from: &str,
    fee: EvmFee,
) -> Result<String> {
    let margin = fee.l1_fee / 4;
    let reserved = fee
        .max_total()?
        .checked_add(margin)
        .context("frais de gas dépassant la capacité représentable")?;
    let balance = get_evm_balance(from, network)?;
    let max = balance
        .checked_sub(reserved)
        .filter(|max| *max > 0)
        .with_context(|| {
            format!(
                "{} insuffisants pour couvrir les frais du réseau ({} {})",
                network.native_symbol,
                tokens::format_amount(reserved, 18),
                network.native_symbol
            )
        })?;
    Ok(tokens::format_amount(max, 18))
}

/// SOL: balance minus the fee for one signature (an account emptied to zero is
/// allowed).
pub fn sol_max(network: &wallet_flow::SolNetwork, from: &str) -> Result<String> {
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let max = get_sol_balance(from, network)?
        .checked_sub(SOL_FEE_LAMPORTS)
        .filter(|max| *max > 0)
        .context("SOL insuffisants pour couvrir les frais du réseau")?;
    Ok(tokens::format_amount(u128::from(max), 9))
}

/// Bitcoin: all the outputs (as in `send_btc`) cover the amount and the chosen fee;
/// checked before the confirmation dialog.
pub fn ensure_btc_transfer_funds(
    network: &wallet_flow::BtcNetwork,
    address: &str,
    amount: &str,
    fee_sat: u64,
) -> Result<()> {
    let total: u64 = btc_rpc::EsploraClient::new(network.esplora_base)
        .utxos(address)?
        .iter()
        .map(|u| u.value_sat)
        .sum();
    btc_change(total, wallet_flow::parse_btc_to_sat(amount)?, fee_sat).map(|_| ())
}

/// Bitcoin: all the outputs (as in `send_btc`) minus the chosen fee.
pub fn btc_max(network: &wallet_flow::BtcNetwork, address: &str, fee_sat: u64) -> Result<String> {
    let total: u64 = btc_rpc::EsploraClient::new(network.esplora_base)
        .utxos(address)?
        .iter()
        .map(|u| u.value_sat)
        .sum();
    let max = total
        .checked_sub(fee_sat)
        .filter(|max| *max > 1_000)
        .context("BTC insuffisants pour couvrir les frais choisis")?;
    Ok(tokens::format_amount(u128::from(max), 8))
}

/// Token (registry, Solana USDC included): the whole token balance, since the fees
/// are paid in the network's native coin.
pub fn token_max(token_id: &str, network: &str, owner: &str) -> Result<String> {
    let (balance, decimals) = if token_id == "usdc" && network == "sol_mainnet" {
        (
            u128::from(get_spl_balance(
                owner,
                &sol_spl::usdc_mint_mainnet(),
                &wallet_flow::SOLANA_MAINNET,
            )?),
            6,
        )
    } else {
        get_token_balance(token_id, network, owner)?
    };
    anyhow::ensure!(balance > 0, "aucun jeton à envoyer");
    Ok(tokens::format_amount(balance, decimals))
}

/// Transparent Zcash: the best choice of outputs, ZIP-317 fee deducted.
pub fn zec_max(from: &str) -> Result<String> {
    Ok(zcash::format_zec(zcash::max_amount(&zcash::utxos(from)?)?))
}

/// Dogecoin: the best choice of confirmed outputs, current fee deducted.
pub fn doge_max(from: &str) -> Result<String> {
    let doge::Recipient::P2pkh(own) = doge::parse_recipient(from)? else {
        anyhow::bail!("adresse Dogecoin du profil invalide")
    };
    Ok(doge::format_doge(doge::max_send(&own)?))
}

/// Shielded Zcash: the amount of the library's "send everything" proposal (to `to`,
/// or to our own address for an estimate).
pub fn zec_shielded_max(data_dir: &Path, profile_index: u32, to: &str) -> Result<String> {
    Ok(zcash::format_zec(zcash_shielded::max_amount(
        data_dir,
        profile_index,
        to,
    )?))
}

/// Fees for a native transfer of `amount` (text, 18 decimals) to `to`: see
/// `evm_fee_for_confirmation`. `from`: the sending address, only needed where the gas
/// limit is estimated (Arbitrum).
pub fn evm_transfer_fee_for_confirmation(
    network: &wallet_flow::EvmNetwork,
    from: Option<&str>,
    to: &str,
    amount: &str,
) -> Result<EvmFee> {
    let to = wallet_flow::parse_evm_address(to)?;
    let value = wallet_flow::parse_eth_to_wei(amount)?;
    let from = match (from, network.transfer_gas) {
        (Some(address), _) => wallet_flow::parse_evm_address(address)?,
        // Fixed gas limit: the sending address plays no part.
        (None, Some(_)) => [0u8; 20],
        (None, None) => anyhow::bail!("adresse d'envoi inconnue : déverrouillez le portefeuille"),
    };
    evm_fee_for_confirmation(network, &from, &to, value, &[])
}

/// Ethereum posting fee for a transaction (unsigned encoding) on an OP Stack
/// network: `getL1Fee(bytes)` on the network's oracle.
fn op_stack_l1_fee(rpc: &eth_rpc::EthRpc, unsigned_tx: &[u8]) -> Result<u128> {
    // Selector of getL1Fee(bytes), then the `bytes` argument in ABI form: offset
    // (0x20), length, data padded to a multiple of 32 bytes.
    let mut calldata = vec![0x49, 0x94, 0x8e, 0x0e];
    let mut word = [0u8; 32];
    word[31] = 0x20;
    calldata.extend_from_slice(&word);
    let mut length = [0u8; 32];
    length[24..].copy_from_slice(&(unsigned_tx.len() as u64).to_be_bytes());
    calldata.extend_from_slice(&length);
    calldata.extend_from_slice(unsigned_tx);
    let padded = 4 + (calldata.len() - 4).div_ceil(32) * 32;
    calldata.resize(padded, 0);
    let answer = rpc.call_contract(
        &derivation::format_address(&[0u8; 20]),
        OP_GAS_PRICE_ORACLE,
        0,
        &calldata,
    )?;
    anyhow::ensure!(
        answer.len() == 32,
        "réponse de l'oracle de frais inattendue"
    );
    anyhow::ensure!(
        answer[..16].iter().all(|&b| b == 0),
        "frais de publication annoncés anormalement élevés"
    );
    Ok(u128::from_be_bytes(
        answer[16..].try_into().expect("16 octets"),
    ))
}

/// Unlocks the vault (password required: this is the authentication barrier before
/// any spending), signs and broadcasts an EVM transfer. `gas_price`: the one SHOWN in
/// the confirmation dialog (see `evm_gas_price_for_confirmation`), used as is, never
/// a price reread from the node afterwards.
pub fn send_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    to: &str,
    amount_eth: &str,
    fee: EvmFee,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, fee.gas_price)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let tx = prepare_evm_transfer(network, &address, to, amount_eth, fee)?;
    let raw_tx = tx.sign(&signing_key)?;
    eth_rpc::EthRpc::new(network.rpc).send_raw_transaction(&raw_tx)
}

/// An EVM transfer ready to sign from `address` (software or hardware wallet, see
/// `hardware::send_evm`): nonce, network and balance read from the node, network
/// checked, balance enough for amount + maximum fee.
pub(crate) fn prepare_evm_transfer(
    network: &wallet_flow::EvmNetwork,
    address: &[u8; 20],
    to: &str,
    amount_eth: &str,
    fee: EvmFee,
) -> Result<eth_tx::EthTx> {
    check_evm_gas_price(network, fee.gas_price)?;
    anyhow::ensure!(
        fee.gas_limit >= eth_tx::intrinsic_gas(&[]),
        "limite de gas trop basse pour un virement"
    );
    let to_bytes = wallet_flow::parse_evm_address(to)?;
    let value = wallet_flow::parse_eth_to_wei(amount_eth)?;

    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let address_str = derivation::format_address(address);
    // The 3 calls below are independent RPC reads (none depends on another's result):
    // running them in parallel rather than one after the other cuts the perceived
    // latency of an ETH send to ~1 network round trip.
    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce_handle = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id_handle = scope.spawn(|| rpc.chain_id());
        let balance_handle = scope.spawn(|| rpc.balance(&address_str));
        (
            nonce_handle
                .join()
                .expect("le thread nonce ne doit pas paniquer"),
            chain_id_handle
                .join()
                .expect("le thread chain_id ne doit pas paniquer"),
            balance_handle
                .join()
                .expect("le thread balance ne doit pas paniquer"),
        )
    });
    let nonce = nonce?;
    let chain_id = chain_id?;
    let balance = balance?;
    // A node answering for a different network than the one chosen would get us to
    // sign a transaction replayable elsewhere (EIP-155 binds the signature to the
    // chain_id).
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );

    // Unlike Bitcoin (UTXOs, checked in `send_btc`), nothing here checked that the
    // balance covers amount + gas fees before signing and broadcasting. Without this
    // check, the error only surfaces through the RPC node's rejection after signing,
    // which hides the real cause from the user ("insufficient funds") behind a generic
    // RPC error message.
    let gas_cost = fee.max_total()?;
    let total_needed = value
        .checked_add(gas_cost)
        .context("montant + frais de gas dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
    );

    Ok(eth_tx::EthTx {
        nonce,
        gas_price: fee.gas_price,
        gas_limit: fee.gas_limit,
        to: to_bytes,
        value,
        chain_id,
        data: Vec::new(),
    })
}

/// Unlocks the vault, signs and broadcasts an Ethereum -> THORChain swap. Unlike a
/// normal send, the transaction is NOT a plain transfer to `quote.inbound_address`
/// but a call to the "THORChain Router" contract (`quote.router`; never
/// `inbound_address` directly on an EVM chain, see `thorchain_rpc::SwapQuote`):
/// `depositWithExpiry` with `asset` = the zero address (native coin) and `amount` =
/// the amount sent (`msg.value`, required by the newer router on Avalanche and
/// Base). `expiration`: Unix timestamp + a wide margin (1h), as THORChain
/// documents, so a call left pending for a long time does not execute at a stale
/// rate. `gas_price`: the one SHOWN in the confirmation dialog (see
/// `evm_gas_price_for_confirmation`), used as is.
pub fn send_swap_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    quote: &thorchain_rpc::SwapQuote,
    amount_eth: &str,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let router = quote
        .router
        .as_deref()
        .context("devis THORChain sans adresse de routeur (attendu pour un swap EVM)")?;
    let router_bytes = wallet_flow::parse_evm_address(router)?;
    let vault_bytes = wallet_flow::parse_evm_address(&quote.inbound_address)?;
    // Native ETH = the zero address on the contract side (NOT the "0xEeee...Eeee"
    // convention used by other protocols), checked by reading the deployed router's
    // real verified source code through Sourcify: `if(asset == address(0))`, see
    // `deposit()` in the THORChain_Router contract.
    let native_asset_bytes = [0u8; 20];

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let value = wallet_flow::parse_eth_to_wei(amount_eth)?;

    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let address_str = derivation::format_address(&address);
    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce_handle = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id_handle = scope.spawn(|| rpc.chain_id());
        let balance_handle = scope.spawn(|| rpc.balance(&address_str));
        (
            nonce_handle
                .join()
                .expect("le thread nonce ne doit pas paniquer"),
            chain_id_handle
                .join()
                .expect("le thread chain_id ne doit pas paniquer"),
            balance_handle
                .join()
                .expect("le thread balance ne doit pas paniquer"),
        )
    });
    let nonce = nonce?;
    let chain_id = chain_id?;
    let balance = balance?;
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );

    let expiration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("horloge système invalide")?
        .as_secs()
        + 3600;

    // `amount` = the amount sent: the newer router (Avalanche, Base) refuses a native
    // deposit where it differs from `msg.value` ("TC:eth amount mismatch", seen for
    // real); the older one (Ethereum) ignores it.
    let calldata = eth_tx::thorchain_deposit_calldata(
        &vault_bytes,
        &native_asset_bytes,
        value,
        &quote.memo,
        expiration,
    );
    // The gas ACTUALLY needed to execute the contract (+20%), not the intrinsic gas.
    // Found in the same audit: the previous version used `intrinsic_gas` (23,844
    // measured) as the limit, whereas a real deposit on the router uses 45,632
    // (`eth_estimateGas` on mainnet): EVERY ETH swap would have run out of gas and
    // failed on-chain, burning the fees without ever swapping anything. Bounded by
    // `EVM_SWAP_MAX_GAS_LIMIT`, the maximum shown in the confirmation dialog.
    let estimated = rpc.estimate_gas(&address_str, router, value, &calldata)?;
    let gas_limit = estimated
        .saturating_mul(12)
        .div_ceil(10)
        .max(eth_tx::intrinsic_gas(&calldata));
    let (_, deposit_cap) = swap_gas_caps(network);
    anyhow::ensure!(
        gas_limit <= deposit_cap,
        "gas estimé anormalement élevé pour un dépôt THORChain ({gas_limit}, maximum {deposit_cap}) — swap refusé"
    );

    // Base (OP Stack): Ethereum posting fees on top of gas.
    let l1_fee = evm_l1_fee(
        network,
        &router_bytes,
        value,
        &calldata,
        gas_price,
        gas_limit,
    )?;
    let gas_cost = gas_price
        .checked_mul(u128::from(gas_limit))
        .and_then(|gas| gas.checked_add(l1_fee))
        .context("gas_price * gas_limit dépasse la capacité représentable")?;
    let total_needed = value
        .checked_add(gas_cost)
        .context("montant + frais de gas dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
    );

    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit,
        to: router_bytes,
        value,
        chain_id,
        data: calldata,
    };
    let raw_tx = tx.sign(&signing_key)?;
    rpc.send_raw_transaction(&raw_tx)
}

/// Gas cap for an ERC-20 approval (`approve`): usually 46,000 to 60,000.
pub const EVM_APPROVE_MAX_GAS_LIMIT: u64 = 100_000;

/// Gas caps (approval, deposit) for a swap on `network`. Where the gas limit also
/// counts posting to Ethereum (Arbitrum, `transfer_gas` = `None`), it rises with
/// Ethereum's gas price: the same wide cap as for a transfer
/// (`EVM_MAX_ESTIMATED_GAS`), otherwise legitimate swaps would be refused when
/// Ethereum is busy.
pub fn swap_gas_caps(network: &wallet_flow::EvmNetwork) -> (u64, u64) {
    match network.transfer_gas {
        None => (EVM_MAX_ESTIMATED_GAS, EVM_MAX_ESTIMATED_GAS),
        Some(_) => (EVM_APPROVE_MAX_GAS_LIMIT, EVM_SWAP_MAX_GAS_LIMIT),
    }
}
/// Maximum wait for an approval to be confirmed before the deposit.
const APPROVE_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// THORChain swap from an ERC-20 token (USDC, USDT, DAI, VVV…): the router pulls
/// the token itself, which first requires an approval (`approve`) for the EXACT
/// amount of the swap (never unlimited), then `depositWithExpiry(vault, token,
/// amount, memo, expiration)`. Both transactions are built here (no call supplied
/// by a third party), at the gas price shown in the confirmation dialog. An
/// approval that is already sufficient is not requested again; a non-zero but
/// insufficient approval is first reset to 0 (required by USDT). The approval must
/// be mined before the deposit (otherwise the deposit's estimate fails): a bounded
/// wait; beyond it, the swap can be restarted, and the approval stays in place.
#[allow(clippy::too_many_arguments)]
pub fn send_swap_erc20(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    from: &thorchain_rpc::ThorAsset,
    quote: &thorchain_rpc::SwapQuote,
    amount: &str,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let contract = from.contract.context("jeton ERC-20 attendu")?;
    let contract_bytes = wallet_flow::parse_evm_address(contract)?;
    let router = quote
        .router
        .as_deref()
        .context("devis THORChain sans adresse de routeur (attendu pour un swap EVM)")?;
    let router_bytes = wallet_flow::parse_evm_address(router)?;
    let vault_bytes = wallet_flow::parse_evm_address(&quote.inbound_address)?;
    let units = tokens::parse_amount(amount, from.decimals as u8)?;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    let rpc = eth_rpc::EthRpc::new(network.rpc);

    let (nonce, chain_id, balance, token_balance, allowance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let token_balance = scope.spawn(|| get_erc20_balance(network, contract, &address_str));
        let allowance =
            scope.spawn(|| get_erc20_allowance(network, contract, &address, &router_bytes));
        let join = "un fil de lecture ne doit pas paniquer";
        (
            nonce.join().expect(join),
            chain_id.join().expect(join),
            balance.join().expect(join),
            token_balance.join().expect(join),
            allowance.join().expect(join),
        )
    });
    let (mut nonce, chain_id, balance, token_balance, allowance) =
        (nonce?, chain_id?, balance?, token_balance?, allowance?);
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );
    anyhow::ensure!(
        units <= token_balance,
        "{} insuffisants : {} disponibles, {} demandés",
        from.symbol,
        tokens::format_amount(token_balance, from.decimals as u8),
        tokens::format_amount(units, from.decimals as u8)
    );

    let approvals = approval_amounts(allowance, units);
    // Native coin for ALL the transactions, at worst: approvals and deposit at their
    // gas cap (+ L1 fees on Base).
    let (_, deposit_cap) = swap_gas_caps(network);
    let deposit_draft = eth_tx::thorchain_deposit_calldata(
        &vault_bytes,
        &contract_bytes,
        units,
        &quote.memo,
        u64::MAX,
    );
    let deposit_fee = gas_price
        .checked_mul(u128::from(deposit_cap))
        .and_then(|g| {
            g.checked_add(
                evm_l1_fee(
                    network,
                    &router_bytes,
                    0,
                    &deposit_draft,
                    gas_price,
                    deposit_cap,
                )
                .ok()?,
            )
        })
        .context("frais de gas dépassant la capacité représentable")?;
    ensure_fees_covered(
        network,
        &contract_bytes,
        &router_bytes,
        &approvals,
        gas_price,
        deposit_fee,
        balance,
    )?;
    nonce = send_approvals(
        &rpc,
        network,
        &signing_key,
        &address_str,
        chain_id,
        nonce,
        &contract_bytes,
        &router_bytes,
        &approvals,
        gas_price,
    )?;

    let expiration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("horloge système invalide")?
        .as_secs()
        + 3600;
    let calldata = eth_tx::thorchain_deposit_calldata(
        &vault_bytes,
        &contract_bytes,
        units,
        &quote.memo,
        expiration,
    );
    let estimated = rpc.estimate_gas(&address_str, router, 0, &calldata)?;
    let gas_limit = estimated
        .saturating_mul(12)
        .div_ceil(10)
        .max(eth_tx::intrinsic_gas(&calldata));
    anyhow::ensure!(
        gas_limit <= deposit_cap,
        "gas estimé anormalement élevé pour un dépôt THORChain ({gas_limit}, maximum {deposit_cap}) — swap refusé"
    );
    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit,
        to: router_bytes,
        value: 0,
        chain_id,
        data: calldata,
    };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

/// Approvals to send so a contract can pull exactly `units`: none if the current
/// approval is enough; otherwise the exact amount (never unlimited), preceded by a
/// reset to 0 if a partial approval exists (required by USDT).
fn approval_amounts(allowance: u128, units: u128) -> Vec<u128> {
    match allowance {
        a if a >= units => vec![],
        0 => vec![units],
        _ => vec![0, units],
    }
}

/// Checks that the native coin covers, at worst, the approvals at their gas cap (+
/// L1 fees on Base) plus `other_fees`.
fn ensure_fees_covered(
    network: &wallet_flow::EvmNetwork,
    contract: &[u8; 20],
    spender: &[u8; 20],
    approvals: &[u128],
    gas_price: u128,
    other_fees: u128,
    balance: u128,
) -> Result<()> {
    let (approve_cap, _) = swap_gas_caps(network);
    let mut worst_case = other_fees;
    for amount in approvals {
        let data = erc20_approve_data(spender, *amount);
        let approve_fee = gas_price
            .checked_mul(u128::from(approve_cap))
            .and_then(|g| {
                g.checked_add(evm_l1_fee(network, contract, 0, &data, gas_price, approve_cap).ok()?)
            })
            .context("frais de gas dépassant la capacité représentable")?;
        worst_case = worst_case
            .checked_add(approve_fee)
            .context("frais de gas dépassant la capacité représentable")?;
    }
    anyhow::ensure!(
        worst_case <= balance,
        "{} insuffisant pour les frais du réseau : {} disponibles, jusqu'à {} nécessaires",
        network.native_symbol,
        tokens::format_amount(balance, 18),
        tokens::format_amount(worst_case, 18)
    );
    Ok(())
}

/// Sends the approvals one by one, waiting for each to be mined and successful
/// before the next; returns the next nonce.
#[allow(clippy::too_many_arguments)]
fn send_approvals(
    rpc: &eth_rpc::EthRpc,
    network: &wallet_flow::EvmNetwork,
    signing_key: &k256::ecdsa::SigningKey,
    owner: &str,
    chain_id: u64,
    mut nonce: u64,
    contract: &[u8; 20],
    spender: &[u8; 20],
    approvals: &[u128],
    gas_price: u128,
) -> Result<u64> {
    let (approve_cap, _) = swap_gas_caps(network);
    let contract_str = derivation::format_address(contract);
    for amount in approvals {
        let data = erc20_approve_data(spender, *amount);
        let estimated = rpc.estimate_gas(owner, &contract_str, 0, &data)?;
        let gas_limit = estimated
            .saturating_mul(12)
            .div_ceil(10)
            .max(eth_tx::intrinsic_gas(&data));
        anyhow::ensure!(
            gas_limit <= approve_cap,
            "gas estimé anormalement élevé pour l'autorisation ({gas_limit}, maximum {approve_cap}) — échange refusé"
        );
        let tx = eth_tx::EthTx {
            nonce,
            gas_price,
            gas_limit,
            to: *contract,
            value: 0,
            chain_id,
            data,
        };
        let hash = rpc.send_raw_transaction(&tx.sign(signing_key)?)?;
        wait_for_success(rpc, &hash)?;
        nonce += 1;
    }
    Ok(nonce)
}

/// Maximum fee for a THORChain swap from an EVM network, shown BEFORE confirmation
/// with the gas price that will be signed: the deposit at its gas cap (+ L1 fees on
/// Base) and, for a token, the prior approval(s) (two when a partial approval must
/// be reset to 0).
pub struct EvmSwapFees {
    pub deposit: EvmFee,
    pub approve: EvmFee,
    /// Approvals to send before the deposit (0 for a native coin, or if the approval
    /// already granted is enough).
    pub approvals: usize,
}

impl EvmSwapFees {
    pub fn max_total(&self) -> Result<u128> {
        let approvals = self
            .approve
            .max_total()?
            .checked_mul(self.approvals as u128)
            .context("frais dépassant la capacité représentable")?;
        self.deposit
            .max_total()?
            .checked_add(approvals)
            .context("frais dépassant la capacité représentable")
    }
}

pub fn evm_swap_fees(
    network: &wallet_flow::EvmNetwork,
    from: &thorchain_rpc::ThorAsset,
    quote: &thorchain_rpc::SwapQuote,
    amount: &str,
    gas_price: u128,
    owner: Option<&str>,
) -> Result<EvmSwapFees> {
    let router = wallet_flow::parse_evm_address(
        quote
            .router
            .as_deref()
            .context("devis THORChain sans adresse de routeur")?,
    )?;
    let vault = wallet_flow::parse_evm_address(&quote.inbound_address)?;
    let units = tokens::parse_amount(amount, from.decimals as u8)?;
    let (asset, value) = match from.contract {
        Some(contract) => (wallet_flow::parse_evm_address(contract)?, 0),
        None => ([0u8; 20], units),
    };
    let draft = eth_tx::thorchain_deposit_calldata(&vault, &asset, units, &quote.memo, u64::MAX);
    let (approve_cap, deposit_cap) = swap_gas_caps(network);
    let deposit = EvmFee {
        gas_price,
        gas_limit: deposit_cap,
        l1_fee: evm_l1_fee(network, &router, value, &draft, gas_price, deposit_cap)?,
    };
    let approve_data = erc20_approve_data(&router, units);
    let approve = EvmFee {
        gas_price,
        gas_limit: approve_cap,
        l1_fee: evm_l1_fee(network, &asset, 0, &approve_data, gas_price, approve_cap)?,
    };
    let approvals = match (from.contract, owner) {
        (None, _) => 0,
        (Some(contract), Some(owner)) => approval_amounts(
            get_erc20_allowance(
                network,
                contract,
                &wallet_flow::parse_evm_address(owner)?,
                &router,
            )?,
            units,
        )
        .len(),
        (Some(_), None) => 1,
    };
    Ok(EvmSwapFees {
        deposit,
        approve,
        approvals,
    })
}

/// Waits for a transaction to be mined and SUCCESSFUL (an approval before a
/// deposit), for at most `APPROVE_WAIT`.
fn wait_for_success(rpc: &eth_rpc::EthRpc, hash: &str) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        match rpc.receipt_status(hash) {
            Ok(Some(true)) => return Ok(()),
            Ok(Some(false)) => anyhow::bail!("l'autorisation du jeton a échoué on-chain ({hash}) — échange interrompu, rien d'autre n'a été envoyé"),
            _ if started.elapsed() > APPROVE_WAIT => anyhow::bail!(
                "autorisation envoyée ({hash}) mais pas encore confirmée par le réseau — relancez l'échange dans un instant (l'autorisation restera acquise)"
            ),
            _ => std::thread::sleep(std::time::Duration::from_secs(3)),
        }
    }
}

// --- CoW Protocol swap (same EVM network) ------------------------------------

/// CoW tokens (sold, bought) for a pair designated by the UI.
pub fn cow_tokens(
    network: &str,
    from_coin: &str,
    to_coin: &str,
) -> Result<(cow::CowToken, cow::CowToken)> {
    let sell = cow::token(from_coin, network)
        .with_context(|| format!("{from_coin} n'est pas échangeable via CoW sur ce réseau"))?;
    let buy = cow::token(to_coin, network)
        .with_context(|| format!("{to_coin} n'est pas échangeable via CoW sur ce réseau"))?;
    Ok((sell, buy))
}

/// Canonical form of the amount sold (the token's decimals), shown AND signed.
pub fn canonical_cow_amount(sell: &cow::CowToken, amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, sell.decimals)?,
        sell.decimals,
    ))
}

/// CoW quote for selling `amount` of `sell` for `buy`, on behalf of `owner` (seller
/// AND recipient). Refused as long as the partner fee address is not set (see
/// `cow::PARTNER_FEE_RECIPIENT`).
pub fn get_cow_quote(
    network: &wallet_flow::EvmNetwork,
    sell: &cow::CowToken,
    buy: &cow::CowToken,
    amount: &str,
    owner: &str,
    partner_fee_bps: u32,
) -> Result<cow::CowOrder> {
    let recipient = cow::PARTNER_FEE_RECIPIENT.context("échange via CoW pas encore activé")?;
    wallet_flow::parse_evm_address(owner)?;
    cow::quote(
        network.id,
        sell,
        buy,
        tokens::parse_amount(amount, sell.decimals)?,
        owner,
        recipient,
        partner_fee_bps,
    )
}

/// Approvals to send to CoW's VaultRelayer before the order, and the maximum fee
/// for each (shown before confirmation, at the signed gas price).
pub fn cow_approval_fees(
    network: &wallet_flow::EvmNetwork,
    order: &cow::CowOrder,
    gas_price: u128,
) -> Result<(EvmFee, usize)> {
    let relayer = wallet_flow::parse_evm_address(cow::VAULT_RELAYER)?;
    let contract = wallet_flow::parse_evm_address(&order.sell_token)?;
    let owner = wallet_flow::parse_evm_address(&order.receiver)?;
    let (approve_cap, _) = swap_gas_caps(network);
    let data = erc20_approve_data(&relayer, order.sell_amount);
    let fee = EvmFee {
        gas_price,
        gas_limit: approve_cap,
        l1_fee: evm_l1_fee(network, &contract, 0, &data, gas_price, approve_cap)?,
    };
    let approvals = approval_amounts(
        get_erc20_allowance(network, &order.sell_token, &owner, &relayer)?,
        order.sell_amount,
    )
    .len();
    Ok((fee, approvals))
}

/// Minimum validity margin at signing time: an order that expires almost
/// immediately would have no chance of being executed.
const COW_MIN_REMAINING_VALIDITY_SECS: u64 = 120;

/// CoW swap: approval(s) to the VaultRelayer for the exact amount if needed (same
/// rules as `send_swap_erc20`), then signing of the order SHOWN in the confirmation
/// dialog (`order`), with no new quote: if the market drops below the signed
/// minimum, the order expires at no cost. The order must be in the name of the
/// signing profile (recipient = seller). No swap transaction: CoW's network fees
/// are taken from the token sold and already counted in the order. Returns the
/// order identifier.
pub fn send_cow_swap(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    sell: &cow::CowToken,
    order: &cow::CowOrder,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    anyhow::ensure!(
        order.network == network.id && order.sell_token == sell.address && !sell.native,
        "ordre CoW incohérent — échange refusé"
    );
    let contract_bytes = wallet_flow::parse_evm_address(&sell.address)?;
    let relayer = wallet_flow::parse_evm_address(cow::VAULT_RELAYER)?;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(
        address_str.eq_ignore_ascii_case(&order.receiver),
        "l'ordre CoW n'est pas au nom de ce profil — échange refusé"
    );
    let rpc = eth_rpc::EthRpc::new(network.rpc);

    let (nonce, chain_id, balance, token_balance, allowance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let token_balance = scope.spawn(|| get_erc20_balance(network, &sell.address, &address_str));
        let allowance =
            scope.spawn(|| get_erc20_allowance(network, &sell.address, &address, &relayer));
        let join = "un fil de lecture ne doit pas paniquer";
        (
            nonce.join().expect(join),
            chain_id.join().expect(join),
            balance.join().expect(join),
            token_balance.join().expect(join),
            allowance.join().expect(join),
        )
    });
    let (nonce, chain_id, balance, token_balance, allowance) =
        (nonce?, chain_id?, balance?, token_balance?, allowance?);
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );
    anyhow::ensure!(
        order.sell_amount <= token_balance,
        "{} insuffisants : {} disponibles, {} demandés",
        sell.symbol,
        tokens::format_amount(token_balance, sell.decimals),
        tokens::format_amount(order.sell_amount, sell.decimals)
    );

    let approvals = approval_amounts(allowance, order.sell_amount);
    ensure_fees_covered(
        network,
        &contract_bytes,
        &relayer,
        &approvals,
        gas_price,
        0,
        balance,
    )?;
    send_approvals(
        &rpc,
        network,
        &signing_key,
        &address_str,
        chain_id,
        nonce,
        &contract_bytes,
        &relayer,
        &approvals,
        gas_price,
    )?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("horloge système invalide")?
        .as_secs();
    anyhow::ensure!(
        u64::from(order.valid_to) >= now + COW_MIN_REMAINING_VALIDITY_SECS,
        "le devis CoW a expiré pendant l'autorisation — relancez l'échange (l'autorisation reste acquise)"
    );
    let digest = cow::digest(order, chain_id)?;
    let signature = evm_sign::sign_digest(&signing_key, &digest)?;
    cow::submit(order, &digest, &signature, &address_str)
}

/// Maximum fee for the EthFlow transaction (`createOrder`), shown before
/// confirmation at the signed gas price (+ posting fees on Base).
pub fn cow_eth_flow_fee(
    network: &wallet_flow::EvmNetwork,
    order: &cow::CowOrder,
    gas_price: u128,
) -> Result<EvmFee> {
    let contract = wallet_flow::parse_evm_address(cow::ETH_FLOW)?;
    let data = cow::eth_flow_calldata(order)?;
    let (_, cap) = swap_gas_caps(network);
    Ok(EvmFee {
        gas_price,
        gas_limit: cap,
        l1_fee: evm_l1_fee(network, &contract, order.sell_amount, &data, gas_price, cap)?,
    })
}

/// Selling the network's native coin through CoW's EthFlow contract: the
/// `createOrder` transaction (built here, at the gas price shown) hands it the
/// amount of the order SHOWN (`order`), in the name of the signing profile. Before
/// sending, the appData is uploaded to CoW: the on-chain order only carries its
/// hash, and that document is what declares the partner fee. If not executed, the
/// order expires and CoW refunds. Returns (transaction, order identifier).
pub fn send_cow_eth_flow(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    order: &cow::CowOrder,
    gas_price: u128,
    profile_index: u32,
) -> Result<(String, String)> {
    check_evm_gas_price(network, gas_price)?;
    anyhow::ensure!(
        order.network == network.id
            && order.eth_flow_quote_id.is_some()
            && cow::wrapped_native(network.id) == Some(order.sell_token.as_str()),
        "ordre CoW incohérent — échange refusé"
    );
    let contract = wallet_flow::parse_evm_address(cow::ETH_FLOW)?;
    let data = cow::eth_flow_calldata(order)?;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(
        address_str.eq_ignore_ascii_case(&order.receiver),
        "l'ordre CoW n'est pas au nom de ce profil — échange refusé"
    );
    let rpc = eth_rpc::EthRpc::new(network.rpc);

    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let join = "un fil de lecture ne doit pas paniquer";
        (
            nonce.join().expect(join),
            chain_id.join().expect(join),
            balance.join().expect(join),
        )
    });
    let (nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );

    // Amount + worst-case fees (gas cap) covered BEFORE the estimate, which would
    // otherwise fail with a raw node error.
    let worst_case = cow_eth_flow_fee(network, order, gas_price)?
        .max_total()?
        .checked_add(order.sell_amount)
        .context("montant + frais dépassant la capacité représentable")?;
    anyhow::ensure!(
        worst_case <= balance,
        "fonds insuffisants : {} {sym} disponibles, jusqu'à {} {sym} nécessaires (montant + frais du réseau)",
        tokens::format_amount(balance, 18),
        tokens::format_amount(worst_case, 18),
        sym = network.native_symbol
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("horloge système invalide")?
        .as_secs();
    anyhow::ensure!(
        u64::from(order.valid_to) >= now + COW_MIN_REMAINING_VALIDITY_SECS,
        "le devis CoW a expiré — relancez l'échange"
    );

    let estimated = rpc.estimate_gas(&address_str, cow::ETH_FLOW, order.sell_amount, &data)?;
    let gas_limit = estimated
        .saturating_mul(12)
        .div_ceil(10)
        .max(eth_tx::intrinsic_gas(&data));
    let (_, cap) = swap_gas_caps(network);
    anyhow::ensure!(gas_limit <= cap, "gas estimé anormalement élevé pour l'ordre EthFlow ({gas_limit}, maximum {cap}) — échange refusé");

    let uid = cow::eth_flow_uid(order, chain_id)?;
    cow::upload_app_data(order)?;
    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit,
        to: contract,
        value: order.sell_amount,
        chain_id,
        data,
    };
    let hash = rpc.send_raw_transaction(&tx.sign(&signing_key)?)?;
    Ok((hash, uid))
}

// --- LI.FI swap (between two ecosystems) ----------------------------------------

/// Bridges that keep the recipient off-chain when the destination is not an EVM
/// network (recorded on 2026-10-02: the contract's event only carries a marker):
/// excluded upfront from an EVM network, otherwise every quote would fail
/// verification. To an EVM network, the recipient is in `BridgeData`, so they stay
/// allowed.
const LIFI_HIDDEN_RECEIVER_BRIDGES: [&str; 1] = ["relaydepository"];
/// Gas cap for a LI.FI call (a bridge with a prior swap: ~550,000 measured in
/// simulation on Ethereum).
const LIFI_MAX_GAS: u64 = 1_000_000;
/// Solana fee budget for a LI.FI send (fees, priority, rent for a bridge order
/// account): 0.01 SOL.
pub const LIFI_SOL_FEE_BUDGET_LAMPORTS: u64 = 10_000_000;

/// LI.FI tokens (sent, received) for a pair designated by the UI.
pub fn lifi_tokens(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
) -> Result<(lifi::LifiToken, lifi::LifiToken)> {
    let from = lifi::token(from_coin, from_network).context("crypto non échangeable via LI.FI")?;
    let to = lifi::token(to_coin, to_network).context("crypto non échangeable via LI.FI")?;
    Ok((from, to))
}

/// Canonical form of the amount sent (the token's decimals), shown AND signed.
pub fn canonical_lifi_amount(from: &lifi::LifiToken, amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, from.decimals)?,
        from.decimals,
    ))
}

fn lifi_initial_deny(from_network: &str, to_network: &str) -> Vec<String> {
    if lifi::diamond(from_network).is_some() && lifi::diamond(to_network).is_none() {
        LIFI_HIDDEN_RECEIVER_BRIDGES
            .iter()
            .map(|b| b.to_string())
            .collect()
    } else {
        Vec::new()
    }
}

/// LI.FI quote for the preview (without verifying the transaction, which happens at
/// confirmation): the same bridges excluded as for the send.
#[allow(clippy::too_many_arguments)]
pub fn get_lifi_quote(
    from_network: &'static str,
    from: &lifi::LifiToken,
    to_network: &'static str,
    to: &lifi::LifiToken,
    amount: &str,
    from_address: &str,
    to_address: &str,
) -> Result<lifi::LifiQuote> {
    lifi::Receiver::parse(to_network, to_address)?;
    let units = tokens::parse_amount(amount, from.decimals)?;
    lifi::quote(
        from_network,
        from,
        to_network,
        to,
        units,
        from_address,
        to_address,
        &lifi_initial_deny(from_network, to_network),
        None,
    )
}

/// Verifies the transaction of a LI.FI quote before signing (see
/// `core/src/lifi.rs`). `Some(true)`: recipient verified; `Some(false)`: effects
/// verified but the recipient is handled off-chain by the bridge (Solana source,
/// stated in the confirmation dialog); `None`: a bridge that hides the recipient
/// from an EVM network, to be excluded.
fn verify_lifi_quote(quote: &lifi::LifiQuote, receiver: &lifi::Receiver) -> Result<Option<bool>> {
    match &quote.tx {
        lifi::LifiTx::Evm { to, data, value } => {
            let network =
                wallet_flow::evm_network(quote.from_network).context("réseau EVM inconnu")?;
            let sell_token = if quote.from.native {
                None
            } else {
                Some(wallet_flow::parse_evm_address(&quote.from.address)?)
            };
            let expected = lifi::Expected {
                user: wallet_flow::parse_evm_address(&quote.from_address)?,
                sell_token,
                amount: quote.from_amount,
                diamond: *to,
                destination_chain: quote.to.chain,
                receiver,
                integrator: lifi::INTEGRATOR,
            };
            if !lifi::simulates(quote.from_network) {
                lifi::verify_static(data, &expected)?;
                return Ok(Some(true));
            }
            let diamond = derivation::format_address(to);
            let approve = sell_token.map(|_| erc20_approve_data(to, quote.from_amount));
            let mut calls = Vec::new();
            if let Some(approve) = &approve {
                calls.push(eth_rpc::SimCallRequest {
                    from: &quote.from_address,
                    to: &quote.from.address,
                    value: 0,
                    data: approve,
                });
            }
            calls.push(eth_rpc::SimCallRequest {
                from: &quote.from_address,
                to: &diamond,
                value: *value,
                data,
            });
            let simulated = eth_rpc::EthRpc::new(network.rpc).simulate_v1(&calls)?;
            Ok(match lifi::verify_simulation(&simulated, &expected)? {
                lifi::Verification::Verified => Some(true),
                lifi::Verification::ReceiverHidden { .. } => None,
            })
        }
        lifi::LifiTx::Solana { raw } => {
            let owner: [u8; 32] = bs58::decode(&quote.from_address)
                .into_vec()
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("adresse Solana invalide")?;
            let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
            check_swap_effects(&rpc, raw, &lifi_solana_limits(owner, quote)?)?;
            Ok(Some(false))
        }
        // Deposit verified by `lifi_btc_deposit` (outputs reread from Esplora): before the
        // confirmation dialog, which shows its fees, then again just before signing
        // (`send_lifi_btc`); not here, so the same data is not reread twice at each step.
        lifi::LifiTx::Bitcoin { .. } => Ok(Some(false)),
    }
}

/// Bitcoin deposit from a LI.FI quote, verified against the address's confirmed
/// outputs, reread HERE (see `lifi::verify_btc_deposit`), with a network fee rate
/// of at most twice Esplora's "next block" rate (at least 20 sat/vB, at most
/// `BTC_SWAP_MAX_FEE_RATE_SAT_VB`): LI.FI sets these fees, and the app bounds them.
pub fn lifi_btc_deposit(quote: &lifi::LifiQuote) -> Result<lifi::BtcDeposit> {
    let lifi::LifiTx::Bitcoin {
        psbt,
        deposit_script,
        ..
    } = &quote.tx
    else {
        anyhow::bail!("devis LI.FI non Bitcoin")
    };
    let network = &wallet_flow::BTC_MAINNET;
    let own_script =
        crate::btc_tx::p2wpkh_script_pubkey(&(network.parse_address)(&quote.from_address)?);
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let (utxos, estimates) = std::thread::scope(|scope| {
        let utxos = scope.spawn(|| esplora.utxos(&quote.from_address));
        let estimates = esplora.fee_estimates();
        (
            utxos.join().expect("le thread UTXOs ne doit pas paniquer"),
            estimates,
        )
    });
    let max_fee_rate = (fee_rate_for_target(&estimates?, 1) * 2.0)
        .ceil()
        .clamp(20.0, f64::from(BTC_SWAP_MAX_FEE_RATE_SAT_VB)) as u64;
    let amount = u64::try_from(quote.from_amount).context("montant hors limites")?;
    lifi::verify_btc_deposit(
        psbt,
        deposit_script,
        &own_script,
        &utxos?,
        amount,
        max_fee_rate,
    )
}

/// LI.FI send from Bitcoin: the deposit is checked again just before signing
/// (outputs reread, network fee at most `max_network_fee`, the cap shown), the
/// transaction re-serialized and signed by the app in the profile's name, and
/// broadcast through Esplora. Returns the transaction identifier.
pub fn send_lifi_btc(
    data_dir: &Path,
    device_password: &str,
    quote: &lifi::LifiQuote,
    max_network_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let network = &wallet_flow::BTC_MAINNET;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, hash160) = (network.derive_key)(&seed, profile_index)?;
    anyhow::ensure!(
        (network.format_address)(&hash160)? == quote.from_address,
        "la transaction LI.FI n'est pas au nom de ce profil — échange refusé"
    );
    let deposit = lifi_btc_deposit(quote)?;
    anyhow::ensure!(
        deposit.network_fee <= max_network_fee,
        "les frais réseau Bitcoin de la transaction LI.FI ont augmenté depuis la confirmation — relancez l'échange"
    );
    let raw = deposit.tx.sign(&signing_key, &hash160)?;
    btc_rpc::EsploraClient::new(network.esplora_base).broadcast(&raw)
}

/// Bounds of a LI.FI send from Solana: the token sold leaves for at most the
/// amount, lamports for at most the amount (SOL) + the fee budget, and nothing is
/// expected back on Solana.
fn lifi_solana_limits(owner: [u8; 32], quote: &lifi::LifiQuote) -> Result<SwapEffectLimits> {
    let amount = u64::try_from(quote.from_amount).context("montant hors limites")?;
    let (sold_lamports, input_token) = if quote.from.native {
        (amount, None)
    } else {
        let mint: [u8; 32] = bs58::decode(&quote.from.address)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("mint invalide")?;
        (0, Some((mint, amount)))
    };
    Ok(SwapEffectLimits {
        user: owner,
        max_lamport_loss: sold_lamports
            .checked_add(LIFI_SOL_FEE_BUDGET_LAMPORTS)
            .context("montant hors limites")?,
        input_token,
        min_output: MinOutput::Nothing,
    })
}

/// A LI.FI quote whose transaction passed verification: a new quote without the
/// offending bridge while the recipient is hidden (at most
/// `lifi::MAX_ROUTE_ATTEMPTS` times). Returns the quote and whether the recipient
/// was verified.
#[allow(clippy::too_many_arguments)]
pub fn lifi_verified_quote(
    from_network: &'static str,
    from: &lifi::LifiToken,
    to_network: &'static str,
    to: &lifi::LifiToken,
    amount: &str,
    from_address: &str,
    to_address: &str,
) -> Result<(lifi::LifiQuote, bool)> {
    let receiver = lifi::Receiver::parse(to_network, to_address)?;
    let units = tokens::parse_amount(amount, from.decimals)?;
    ensure_lifi_balance(from_network, from, units, from_address)?;
    let mut deny = lifi_initial_deny(from_network, to_network);
    for _ in 0..lifi::MAX_ROUTE_ATTEMPTS {
        let quote = lifi::quote(
            from_network,
            from,
            to_network,
            to,
            units,
            from_address,
            to_address,
            &deny,
            None,
        )?;
        match verify_lifi_quote(&quote, &receiver)? {
            Some(verified) => return Ok((quote, verified)),
            None => deny.push(quote.tool.clone()),
        }
    }
    anyhow::bail!(
        "aucune route LI.FI dont le destinataire soit vérifiable (ponts écartés : {})",
        deny.join(", ")
    )
}

/// Enough balance for the send, checked before the simulation (which would
/// otherwise fail with a misleading message).
fn ensure_lifi_balance(
    from_network: &str,
    from: &lifi::LifiToken,
    units: u128,
    from_address: &str,
) -> Result<()> {
    let available = if from_network == "btc_mainnet" {
        // Confirmed outputs only: the only ones the deposit can spend.
        let utxos = btc_rpc::EsploraClient::new(wallet_flow::BTC_MAINNET.esplora_base)
            .utxos(from_address)?;
        utxos.iter().map(|u| u128::from(u.value_sat)).sum()
    } else if let Some(network) = wallet_flow::evm_network(from_network) {
        if from.native {
            eth_rpc::EthRpc::new(network.rpc).balance(from_address)?
        } else {
            get_erc20_balance(network, &from.address, from_address)?
        }
    } else {
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        if from.native {
            u128::from(rpc.balance_lamports(from_address)?)
        } else {
            let owner: [u8; 32] = bs58::decode(from_address)
                .into_vec()
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("adresse Solana invalide")?;
            let mint: [u8; 32] = bs58::decode(&from.address)
                .into_vec()
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("mint invalide")?;
            let ata =
                bs58::encode(sol_spl::find_associated_token_address(&owner, &mint)).into_string();
            u128::from(rpc.token_account_balance(&ata)?.unwrap_or(0))
        }
    };
    anyhow::ensure!(
        units <= available,
        "{} insuffisants : {} disponibles, {} demandés",
        from.symbol,
        tokens::format_amount(available, from.decimals),
        tokens::format_amount(units, from.decimals)
    );
    Ok(())
}

/// Quote requested AGAIN after confirmation (the native dialog stays open for an
/// arbitrary time, and a bridge's transaction expires quickly) on the SAME bridge,
/// refused if it no longer matches what was shown: same recipient, a minimum of at
/// least 99% of the one shown, the same level of verification.
pub fn refresh_lifi_quote_matching(
    shown: &lifi::LifiQuote,
    shown_verified: bool,
) -> Result<lifi::LifiQuote> {
    let receiver = lifi::Receiver::parse(shown.to_network, &shown.to_address)?;
    let quote = lifi::quote(
        shown.from_network,
        &shown.from,
        shown.to_network,
        &shown.to,
        shown.from_amount,
        &shown.from_address,
        &shown.to_address,
        &[],
        Some(&shown.tool),
    )?;
    anyhow::ensure!(
        quote.tool == shown.tool,
        "LI.FI propose maintenant un autre pont que celui affiché — relancez l'échange"
    );
    if let (
        lifi::LifiTx::Bitcoin {
            deposit: shown_deposit,
            ..
        },
        lifi::LifiTx::Bitcoin { deposit, .. },
    ) = (&shown.tx, &quote.tx)
    {
        anyhow::ensure!(
            deposit == shown_deposit,
            "l'adresse de dépôt du pont a changé pendant la confirmation — relancez l'échange"
        );
    }
    anyhow::ensure!(
        quote.to_amount_min.saturating_mul(100) >= shown.to_amount_min.saturating_mul(99),
        "le minimum annoncé par LI.FI a baissé de plus de 1 % depuis l'affichage — relancez l'échange"
    );
    anyhow::ensure!(
        verify_lifi_quote(&quote, &receiver)? == Some(shown_verified),
        "la nouvelle transaction LI.FI ne passe plus la même vérification — relancez l'échange"
    );
    Ok(quote)
}

/// Maximum fee for a LI.FI send from an EVM network, shown before confirmation: the
/// call at its gas cap (+ L1 fees on Base) and the approvals to the LI.FI contract
/// if needed.
pub fn lifi_evm_fees(
    network: &wallet_flow::EvmNetwork,
    quote: &lifi::LifiQuote,
    gas_price: u128,
) -> Result<(EvmFee, EvmFee, usize)> {
    let lifi::LifiTx::Evm { to, data, value } = &quote.tx else {
        anyhow::bail!("devis LI.FI non EVM")
    };
    let cap = lifi_gas_cap(network);
    let call = EvmFee {
        gas_price,
        gas_limit: cap,
        l1_fee: evm_l1_fee(network, to, *value, data, gas_price, cap)?,
    };
    let (approve_cap, _) = swap_gas_caps(network);
    let (approve, approvals) = if quote.from.native {
        (
            EvmFee {
                gas_price,
                gas_limit: 0,
                l1_fee: 0,
            },
            0,
        )
    } else {
        let contract = wallet_flow::parse_evm_address(&quote.from.address)?;
        let approve_data = erc20_approve_data(to, quote.from_amount);
        let fee = EvmFee {
            gas_price,
            gas_limit: approve_cap,
            l1_fee: evm_l1_fee(network, &contract, 0, &approve_data, gas_price, approve_cap)?,
        };
        let owner = wallet_flow::parse_evm_address(&quote.from_address)?;
        (
            fee,
            approval_amounts(
                get_erc20_allowance(network, &quote.from.address, &owner, to)?,
                quote.from_amount,
            )
            .len(),
        )
    };
    Ok((call, approve, approvals))
}

fn lifi_gas_cap(network: &wallet_flow::EvmNetwork) -> u64 {
    // Arbitrum: the gas limit also counts posting to Ethereum.
    if network.transfer_gas.is_none() {
        EVM_MAX_ESTIMATED_GAS
    } else {
        LIFI_MAX_GAS
    }
}

/// LI.FI send from an EVM network: the transaction SHOWN and verified (`quote`), in
/// the name of the signing profile, at the gas price shown; an approval for the
/// exact amount to the LI.FI contract if needed (same rules as the other swaps).
/// Returns the transaction hash.
pub fn send_lifi_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    quote: &lifi::LifiQuote,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let lifi::LifiTx::Evm { to, data, value } = &quote.tx else {
        anyhow::bail!("devis LI.FI non EVM")
    };
    anyhow::ensure!(
        quote.from_network == network.id
            && lifi::diamond(network.id)
                .map(wallet_flow::parse_evm_address)
                .transpose()?
                == Some(*to),
        "transaction LI.FI incohérente — échange refusé"
    );
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(
        address_str.eq_ignore_ascii_case(&quote.from_address),
        "la transaction LI.FI n'est pas au nom de ce profil — échange refusé"
    );
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let diamond = derivation::format_address(to);

    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let join = "un fil de lecture ne doit pas paniquer";
        (
            nonce.join().expect(join),
            chain_id.join().expect(join),
            balance.join().expect(join),
        )
    });
    let (mut nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );

    let cap = lifi_gas_cap(network);
    let call_fee = gas_price
        .checked_mul(u128::from(cap))
        .and_then(|g| g.checked_add(evm_l1_fee(network, to, *value, data, gas_price, cap).ok()?))
        .and_then(|f| f.checked_add(*value))
        .context("montant + frais dépassant la capacité représentable")?;
    if quote.from.native {
        ensure_fees_covered(network, to, to, &[], gas_price, call_fee, balance)?;
    } else {
        let contract = wallet_flow::parse_evm_address(&quote.from.address)?;
        let token_balance = get_erc20_balance(network, &quote.from.address, &address_str)?;
        anyhow::ensure!(
            quote.from_amount <= token_balance,
            "{} insuffisants : {} disponibles, {} demandés",
            quote.from.symbol,
            tokens::format_amount(token_balance, quote.from.decimals),
            tokens::format_amount(quote.from_amount, quote.from.decimals)
        );
        let approvals = approval_amounts(
            get_erc20_allowance(network, &quote.from.address, &address, to)?,
            quote.from_amount,
        );
        ensure_fees_covered(
            network, &contract, to, &approvals, gas_price, call_fee, balance,
        )?;
        nonce = send_approvals(
            &rpc,
            network,
            &signing_key,
            &address_str,
            chain_id,
            nonce,
            &contract,
            to,
            &approvals,
            gas_price,
        )?;
    }

    let estimated = rpc.estimate_gas(&address_str, &diamond, *value, data)?;
    let gas_limit = estimated
        .saturating_mul(12)
        .div_ceil(10)
        .max(eth_tx::intrinsic_gas(data));
    anyhow::ensure!(gas_limit <= cap, "gas estimé anormalement élevé pour l'échange LI.FI ({gas_limit}, maximum {cap}) — échange refusé");
    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit,
        to: *to,
        value: *value,
        chain_id,
        data: data.clone(),
    };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

/// LI.FI send from Solana: effects checked again by simulation just before signing
/// (the token sold leaves for at most the amount, nothing else leaves the user
/// beyond the fee budget, no authority handed over), then the transaction SHOWN is
/// signed in the profile's name.
pub fn send_lifi_solana(
    data_dir: &Path,
    device_password: &str,
    quote: &lifi::LifiQuote,
    profile_index: u32,
) -> Result<String> {
    let lifi::LifiTx::Solana { raw } = &quote.tx else {
        anyhow::bail!("devis LI.FI non Solana")
    };
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    anyhow::ensure!(
        bs58::encode(owner).into_string() == quote.from_address,
        "la transaction LI.FI n'est pas au nom de ce profil — échange refusé"
    );
    let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
    check_swap_effects(&rpc, raw, &lifi_solana_limits(owner, quote)?)?;
    // A fresh blockhash from our node (see `jupiter_rpc::with_recent_blockhash`).
    let raw = jupiter_rpc::with_recent_blockhash(raw, &rpc.latest_blockhash()?)?;
    let signed = jupiter_rpc::sign_swap_transaction(&raw, &signing_key, &owner)?;
    rpc.send_transaction(&signed)
}

// --- Monero ----------------------------------------------------------------------

/// Syncs the Monero accounts up to the tip of the chain (called in the background
/// after unlocking). `generation`: read before the keys (see `seed_state`),
/// otherwise the pass is discarded.
pub fn sync_xmr(data_dir: &Path, keys: &[monero::ViewKeys], generation: u64) -> Result<()> {
    monero::sync(data_dir, keys, generation)
}

pub fn xmr_balance(data_dir: &Path, profile_index: u32) -> Result<monero::Balance> {
    monero::balance(data_dir, profile_index)
}

pub fn xmr_history(data_dir: &Path, profile_index: u32) -> Result<Vec<history::TxEntry>> {
    monero::history(data_dir, profile_index)
}

pub fn xmr_has_received(data_dir: &Path) -> bool {
    monero::has_received(data_dir)
}

pub fn has_pending_xmr(data_dir: &Path, profile_index: u32) -> Result<bool> {
    monero::has_pending(data_dir, profile_index)
}

pub fn canonical_xmr_amount(amount: &str) -> Result<String> {
    Ok(monero::format_xmr(monero::parse_xmr(amount)?))
}

/// A send prepared for the confirmation dialog: recipient verified (never
/// ourselves), outputs chosen, decoys drawn, fee computed; exactly what `send_xmr`
/// will sign.
pub fn xmr_send_plan(
    data_dir: &Path,
    keys: &monero::ViewKeys,
    to: &str,
    amount: &str,
) -> Result<monero::SendPlan> {
    monero::prepare_send(data_dir, keys, to, monero::parse_xmr(amount)?)
}

/// Sends the whole spendable Monero balance, fee deducted (`to` absent: amount
/// estimate for the "Max" button).
pub fn xmr_send_plan_max(
    data_dir: &Path,
    keys: &monero::ViewKeys,
    to: Option<&str>,
) -> Result<monero::SendPlan> {
    monero::prepare_send_max(data_dir, keys, to)
}

/// Signs the prepared (and confirmed) send with the spend key drawn from the seed,
/// broadcasts it and returns the transaction identifier.
pub fn send_xmr(data_dir: &Path, device_password: &str, plan: monero::SendPlan) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    monero::sign_and_send(data_dir, &seed, plan)
}

/// "Rescan from the beginning" (Settings): Monero and shielded Zcash reread from
/// the app's fixed birthday, for funds older than the wallet's creation on this
/// device (a wallet imported some other way).
pub fn rescan_private_funds(data_dir: &Path) -> Result<()> {
    wallet_birthday::forget(data_dir);
    monero::rescan_from_birthday(data_dir)?;
    zcash_shielded::request_rescan(data_dir)
}

/// Monero node chosen in Settings (`None`: the default public nodes).
pub fn xmr_node(data_dir: &Path) -> Option<String> {
    monero::custom_node(data_dir)
}

pub fn set_xmr_node(
    data_dir: &Path,
    url: &str,
    confirm: impl FnOnce(&str) -> bool,
) -> Result<Option<String>> {
    monero::set_custom_node(data_dir, url, confirm)
}

// --- Shielded Zcash (Orchard and Ironwood)
// ------------------------------------------

/// Creates any missing shielded accounts, then syncs up to the tip of the chain
/// (called in the background after unlocking). Same `generation` rule as
/// `sync_xmr`.
pub fn sync_zec_shielded(
    data_dir: &Path,
    keys: &[zcash_shielded::ProfileKeys],
    generation: u64,
) -> Result<()> {
    let Some(_pass) = crate::seed_state::pass(generation) else {
        return Ok(());
    };
    zcash_shielded::ensure_accounts(data_dir, keys)?;
    zcash_shielded::sync(data_dir)
}

pub fn zec_shielded_balance(
    data_dir: &Path,
    profile_index: u32,
) -> Result<zcash_shielded::ShieldedBalance> {
    zcash_shielded::balance(data_dir, profile_index)
}

pub fn zec_shielded_history(data_dir: &Path, profile_index: u32) -> Result<Vec<history::TxEntry>> {
    zcash_shielded::history(data_dir, profile_index)
}

/// Shields the ZEC on the profile's t1 address: summary confirmed through
/// `confirm`, then the seed is unlocked (password), signed, broadcast. `Ok(None)`:
/// confirmation declined.
pub fn shield_zec(
    data_dir: &Path,
    device_password: &str,
    profile_index: u32,
    t1: &str,
    confirm: impl FnOnce(&zcash_shielded::SpendSummary) -> bool,
) -> Result<Option<String>> {
    zcash_shielded::shield(data_dir, profile_index, t1, confirm, || {
        unlock_seed(data_dir, device_password)
    })
}

/// Sends from the profile's shielded funds (amount in ZEC, 8 decimals).
pub fn send_zec_shielded(
    data_dir: &Path,
    device_password: &str,
    profile_index: u32,
    to: &str,
    amount: &str,
    confirm: impl FnOnce(&zcash_shielded::SpendSummary) -> bool,
) -> Result<Option<String>> {
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    zcash_shielded::send(data_dir, profile_index, to, units, confirm, || {
        unlock_seed(data_dir, device_password)
    })
}

/// Sends all spendable shielded funds, fee deducted.
pub fn send_zec_shielded_max(
    data_dir: &Path,
    device_password: &str,
    profile_index: u32,
    to: &str,
    confirm: impl FnOnce(&zcash_shielded::SpendSummary) -> bool,
) -> Result<Option<String>> {
    zcash_shielded::send_max(data_dir, profile_index, to, confirm, || {
        unlock_seed(data_dir, device_password)
    })
}

// --- Zcash (transparent addresses) ---------------------------------------------

pub fn get_zec_balance(address: &str) -> Result<u64> {
    zcash::balance(address)
}

/// State of a Zcash recipient address, for the dialog's warnings.
pub fn zec_recipient_activity(to: &str) -> Result<RecipientActivity> {
    let address = zcash::transparent_address(&zcash::parse_recipient(to)?);
    Ok(match zcash::address_activity(&address)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in ZEC (8 decimals), shown AND signed.
pub fn canonical_zec_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(tokens::parse_amount(amount, 8)?, 8))
}

/// A send prepared for the confirmation dialog: recipient verified (t1, t3, tex1;
/// never ourselves), outputs chosen, ZIP-317 fee and change returned.
pub fn zec_send_plan(from_address: &str, to: &str, amount: &str) -> Result<zcash::SendPlan> {
    let recipient = zcash::parse_recipient(to)?;
    anyhow::ensure!(
        recipient != zcash::parse_recipient(from_address)?,
        "envoi vers votre propre adresse Zcash"
    );
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    zcash::plan_send(zcash::utxos(from_address)?, units)
}

/// Zcash send: outputs reread, fee never higher than the one shown (`shown_fee`),
/// consensus branch checked with the server, transaction built and signed here,
/// then broadcast.
pub fn send_zec(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let recipient = zcash::parse_recipient(to)?;
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_zec_key(&seed, profile_index)?;
    anyhow::ensure!(
        recipient != zcash::Recipient::P2pkh(hash160),
        "envoi vers votre propre adresse Zcash"
    );
    let from = zcash::p2pkh_address(&hash160);
    let plan = zcash::plan_send(zcash::utxos(&from)?, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Zcash ont augmenté depuis la confirmation ({} au lieu de {} ZEC) — relancez l'envoi",
        zcash::format_zec(plan.fee),
        zcash::format_zec(shown_fee)
    );
    let chain = zcash::chain_info()?;
    // Height announced by the server: never trusted to leave room for one more block.
    let target = chain
        .height
        .checked_add(1)
        .context("hauteur de chaîne Zcash hors limites")?;
    let branch = zcash::branch_for(target, chain.branch_id)?;
    let signed = zcash::build_signed(&plan, &key, &hash160, &recipient, target, branch)?;
    zcash::broadcast(&signed.raw, &signed.txid)
}

/// Deposit for a swap from Zcash (Maya), prepared for the confirmation dialog: fee
/// computed for an 80-byte memo, the longest possible. The quote reread after
/// confirmation may carry a memo one byte longer or shorter, never fees beyond
/// those shown.
pub fn zec_swap_plan(
    from_address: &str,
    quote: &thorchain_rpc::SwapQuote,
    amount: &str,
) -> Result<zcash::SendPlan> {
    let vault = zec_vault(quote)?;
    anyhow::ensure!(
        vault != zcash::parse_recipient(from_address)?,
        "adresse de dépôt Maya égale à votre propre adresse — échange refusé"
    );
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    zcash::plan_deposit(zcash::utxos(from_address)?, units, &[0; 80])
}

/// The quote's Zcash vault: a transparent address (Maya announces no other kind,
/// see the notes in its quotes).
fn zec_vault(quote: &thorchain_rpc::SwapQuote) -> Result<zcash::Recipient> {
    anyhow::ensure!(
        quote.memo.len() <= 80,
        "memo Maya trop long pour une sortie OP_RETURN ({} octets)",
        quote.memo.len()
    );
    zcash::parse_recipient(&quote.inbound_address).context("adresse de dépôt Maya invalide")
}

/// Sends a swap from Zcash: a transparent transfer to the quote's vault, with the
/// memo in an OP_RETURN output (vault, change, memo: the order Maya requires),
/// ZIP-317 fee never beyond the one shown (`shown_fee`), consensus branch checked
/// with the server.
pub fn send_swap_zec(
    data_dir: &Path,
    device_password: &str,
    quote: &thorchain_rpc::SwapQuote,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let vault = zec_vault(quote)?;
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_zec_key(&seed, profile_index)?;
    anyhow::ensure!(
        vault != zcash::Recipient::P2pkh(hash160),
        "adresse de dépôt Maya égale à votre propre adresse — échange refusé"
    );
    let from = zcash::p2pkh_address(&hash160);
    let plan = zcash::plan_deposit(zcash::utxos(&from)?, units, quote.memo.as_bytes())?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Zcash ont augmenté depuis la confirmation ({} au lieu de {} ZEC) — relancez l'échange",
        zcash::format_zec(plan.fee),
        zcash::format_zec(shown_fee)
    );
    let chain = zcash::chain_info()?;
    // Height announced by the server: never trusted to leave room for one more block.
    let target = chain
        .height
        .checked_add(1)
        .context("hauteur de chaîne Zcash hors limites")?;
    let branch = zcash::branch_for(target, chain.branch_id)?;
    let signed = zcash::build_signed(&plan, &key, &hash160, &vault, target, branch)?;
    zcash::broadcast(&signed.raw, &signed.txid)
}

// --- Tron (TRX) ----------------------------------------------------------------------

pub fn get_trx_balance(address: &str) -> Result<u64> {
    tron::balance(address)
}

/// State of a Tron recipient address, for the dialog's warnings.
pub fn trx_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match tron::address_activity(to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in TRX (6 decimals), shown AND signed.
pub fn canonical_trx_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, tron::DECIMALS)?,
        tron::DECIMALS,
    ))
}

fn trx_units(amount: &str) -> Result<u64> {
    u64::try_from(tokens::parse_amount(amount, tron::DECIMALS)?).context("montant hors limites")
}

/// A send prepared for the confirmation dialog: recipient verified (never
/// ourselves), maximum fee (bandwidth, activating an account that does not exist),
/// enough balance.
pub fn trx_send_plan(from_address: &str, to: &str, amount: &str) -> Result<tron::TrxPlan> {
    tron::plan_trx(from_address, to, trx_units(amount)?)
}

/// TRX send: fee never higher than the one shown (`shown_fee`), transaction built
/// and signed here, then broadcast.
pub fn send_trx(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let recipient = tron::parse_address(to)?;
    let units = trx_units(amount)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, address) = derivation::derive_tron_key(&seed, profile_index)?;
    let plan = tron::plan_trx(&tron::encode_address(&address), to, units)?;
    anyhow::ensure!(
        plan.fee_max <= shown_fee,
        "les frais Tron ont augmenté depuis la confirmation ({} au lieu de {} TRX) — relancez l'envoi",
        tron::format_trx(plan.fee_max),
        tron::format_trx(shown_fee)
    );
    tron::send_trx(&key, &recipient, units)
}

/// Transfer of a registry TRC-20 token, prepared for the dialog: energy simulated,
/// maximum fee, token and TRX balances checked.
pub fn trc20_send_plan(
    token_id: &str,
    from_address: &str,
    to: &str,
    amount: &str,
) -> Result<(tron::Trc20Plan, &'static str)> {
    let (_, deployment) = registered_token(token_id, "tron_mainnet")?;
    let tokens::TokenKind::Trc20 { contract } = deployment.kind else {
        anyhow::bail!("jeton TRC-20 attendu")
    };
    let units = tokens::parse_amount(amount, deployment.decimals)?;
    ensure_token_funds(token_id, "tron_mainnet", from_address, amount)?;
    Ok((
        tron::plan_trc20(from_address, contract, to, units)?,
        contract,
    ))
}

/// TRC-20 token send: fee never higher than the one shown (`shown_fee`),
/// transaction signed here with the recomputed `fee_limit`.
pub fn send_trc20(
    data_dir: &Path,
    device_password: &str,
    token_id: &str,
    to: &str,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let (_, deployment) = registered_token(token_id, "tron_mainnet")?;
    let tokens::TokenKind::Trc20 { contract } = deployment.kind else {
        anyhow::bail!("jeton TRC-20 attendu")
    };
    let recipient = tron::parse_address(to)?;
    let units = tokens::parse_amount(amount, deployment.decimals)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, address) = derivation::derive_tron_key(&seed, profile_index)?;
    let plan = tron::plan_trc20(&tron::encode_address(&address), contract, to, units)?;
    anyhow::ensure!(
        plan.fee_max <= shown_fee,
        "les frais Tron ont augmenté depuis la confirmation ({} au lieu de {} TRX) — relancez l'envoi",
        tron::format_trx(plan.fee_max),
        tron::format_trx(shown_fee)
    );
    tron::send_trc20(
        &key,
        &tron::parse_address(contract)?,
        &recipient,
        units,
        plan.fee_limit,
    )
}

/// "Max" button: balance minus the maximum fee (to `to` if known).
pub fn trx_max(from: &str, to: Option<&str>) -> Result<String> {
    Ok(tron::format_trx(tron::max_trx(from, to)?))
}

// --- XRP Ledger ------------------------------------------------------------------------

pub fn get_xrp_balance(address: &str) -> Result<u64> {
    xrp::balance(&xrp::MAINNET, address)
}

/// State of an XRP recipient address, for the dialog's warnings.
pub fn xrp_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match xrp::address_activity(&xrp::MAINNET, to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in XRP (6 decimals), shown AND signed.
pub fn canonical_xrp_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, xrp::DECIMALS)?,
        xrp::DECIMALS,
    ))
}

fn xrp_units(amount: &str) -> Result<u64> {
    u64::try_from(tokens::parse_amount(amount, xrp::DECIMALS)?).context("montant hors limites")
}

/// Destination tag entered (empty = none): a 32-bit integer.
pub fn parse_destination_tag(tag: Option<&str>) -> Result<Option<u32>> {
    match tag.map(str::trim).filter(|t| !t.is_empty()) {
        None => Ok(None),
        Some(t) => t.parse::<u32>().map(Some).map_err(|_| {
            anyhow::anyhow!("tag de destination invalide (nombre entier de 0 à 4294967295)")
        }),
    }
}

/// A send prepared for the confirmation dialog: network reserve, activation of a
/// new recipient, required tag, fee.
pub fn xrp_send_plan(
    from_address: &str,
    to: &str,
    amount: &str,
    destination_tag: Option<u32>,
) -> Result<xrp::XrpPlan> {
    xrp::plan_xrp(
        &xrp::MAINNET,
        from_address,
        to,
        xrp_units(amount)?,
        destination_tag,
    )
}

/// XRP send: checks redone, signed with the fee rechecked just now (never higher
/// than the one shown, `shown_fee`), then broadcast.
pub fn send_xrp(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    destination_tag: Option<u32>,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let recipient = xrp::parse_address(to)?;
    let units = xrp_units(amount)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, account) = derivation::derive_xrp_key(&seed, profile_index)?;
    let plan = xrp::plan_xrp(
        &xrp::MAINNET,
        &xrp::encode_address(&account),
        to,
        units,
        destination_tag,
    )?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais XRP ont augmenté depuis la confirmation ({} au lieu de {} XRP) — relancez l'envoi",
        xrp::format_xrp(plan.fee),
        xrp::format_xrp(shown_fee)
    );
    xrp::send_xrp(
        &xrp::MAINNET,
        &key,
        &recipient,
        units,
        plan.fee,
        destination_tag,
    )
}

/// "Max" button: balance minus the reserve and the fee.
pub fn xrp_max(from: &str) -> Result<String> {
    Ok(xrp::format_xrp(xrp::max_xrp(&xrp::MAINNET, from)?))
}

// --- Stellar (XLM) -------------------------------------------------------------------

pub fn get_xlm_balance(address: &str) -> Result<i64> {
    stellar::balance(&stellar::MAINNET, address)
}

/// State of a Stellar recipient address, for the dialog's warnings.
pub fn xlm_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match stellar::address_activity(&stellar::MAINNET, to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in XLM (7 decimals), shown AND signed.
pub fn canonical_xlm_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, stellar::DECIMALS)?,
        stellar::DECIMALS,
    ))
}

fn xlm_units(amount: &str) -> Result<i64> {
    i64::try_from(tokens::parse_amount(amount, stellar::DECIMALS)?).context("montant hors limites")
}

/// Memo entered (empty = none): a numeric ID or short ASCII text.
pub fn parse_stellar_memo(memo: Option<&str>) -> Result<stellar::Memo> {
    stellar::parse_memo(memo)
}

/// A send prepared for the confirmation dialog: network reserve, creation of a new
/// recipient, required memo, fee.
pub fn xlm_send_plan(
    from_address: &str,
    to: &str,
    amount: &str,
    memo: &stellar::Memo,
) -> Result<stellar::XlmPlan> {
    stellar::plan(
        &stellar::MAINNET,
        from_address,
        to,
        xlm_units(amount)?,
        memo,
    )
}

/// XLM send: checks redone, signed with the fee bid rechecked just now (never
/// higher than the one shown, `shown_fee`), then broadcast.
pub fn send_xlm(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    memo: stellar::Memo,
    shown_fee: u32,
    profile_index: u32,
) -> Result<String> {
    let recipient = stellar::parse_address(to)?;
    let units = xlm_units(amount)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let key = derivation::derive_stellar_key(&seed, profile_index);
    let plan = stellar::plan(
        &stellar::MAINNET,
        &stellar::encode_address(&key.verifying_key().to_bytes()),
        to,
        units,
        &memo,
    )?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Stellar ont augmenté depuis la confirmation ({} au lieu de {} XLM) — relancez l'envoi",
        stellar::format_xlm(i64::from(plan.fee)),
        stellar::format_xlm(i64::from(shown_fee))
    );
    stellar::send(&stellar::MAINNET, &key, &recipient, &plan, memo)
}

/// "Max" button: balance minus the reserve and the fee.
pub fn xlm_max(from: &str) -> Result<String> {
    Ok(stellar::format_xlm(stellar::max_amount(
        &stellar::MAINNET,
        from,
    )?))
}

// --- NEAR ----------------------------------------------------------------------------

pub fn get_near_balance(account: &str) -> Result<u128> {
    near::balance(&near::MAINNET, account)
}

/// State of a NEAR recipient account, for the dialog's warnings.
pub fn near_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match near::address_activity(&near::MAINNET, to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in NEAR (at most 24 decimals), shown AND signed.
pub fn canonical_near_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, near::DECIMALS)?,
        near::DECIMALS,
    ))
}

/// A send prepared for the confirmation dialog: account storage, creation of a new
/// implicit account, existing named account, fee.
pub fn near_send_plan(from_account: &str, to: &str, amount: &str) -> Result<near::NearPlan> {
    near::plan(
        &near::MAINNET,
        from_account,
        to,
        tokens::parse_amount(amount, near::DECIMALS)?,
    )
}

/// NEAR send: checks redone, fee never higher than the maximum shown (`shown_fee`),
/// transfer signed here, then broadcast.
pub fn send_near(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    shown_fee: u128,
    profile_index: u32,
) -> Result<String> {
    let units = tokens::parse_amount(amount, near::DECIMALS)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let key = derivation::derive_near_key(&seed, profile_index);
    let plan = near::plan(&near::MAINNET, &near::implicit_account(&key), to, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais NEAR ont augmenté depuis la confirmation ({} au lieu de {} NEAR) — relancez l'envoi",
        near::format_near_exact(plan.fee),
        near::format_near_exact(shown_fee)
    );
    near::send(&near::MAINNET, &key, to, &plan)
}

/// "Max" button: balance minus storage and fees (to `to` if known).
pub fn near_max(from: &str, to: Option<&str>) -> Result<String> {
    Ok(near::format_near_exact(near::max_amount(
        &near::MAINNET,
        from,
        to,
    )?))
}

// --- Cardano (ADA) -------------------------------------------------------------------

pub fn get_ada_balance(address: &str) -> Result<u64> {
    cardano::balance(address)
}

/// State of a Cardano recipient address, for the dialog's warnings.
pub fn ada_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match cardano::address_activity(to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in ADA (6 decimals), shown AND signed.
pub fn canonical_ada_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, cardano::DECIMALS)?,
        cardano::DECIMALS,
    ))
}

fn ada_units(amount: &str) -> Result<u64> {
    u64::try_from(tokens::parse_amount(amount, cardano::DECIMALS)?).context("montant hors limites")
}

/// A send prepared for the confirmation dialog: outputs chosen (ADA only), exact
/// fee, change returned, output minimum.
pub fn ada_send_plan(from_address: &str, to: &str, amount: &str) -> Result<cardano::AdaPlan> {
    cardano::plan(from_address, to, ada_units(amount)?)
}

/// Cardano staking operation ("Stake" on the Cardano card).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdaStakeAction {
    Delegate,
    Withdraw,
    Undelegate,
}

/// Operation prepared from the profile's public address (confirmation dialog):
/// exactly what will be signed.
pub fn ada_stake_plan(
    address: &str,
    account: &cardano::StakeAccount,
    action: AdaStakeAction,
    pool: Option<&str>,
) -> Result<cardano::StakePlan> {
    match action {
        AdaStakeAction::Delegate => {
            cardano::plan_delegate(address, account, pool.context("pool Cardano non choisi")?)
        }
        AdaStakeAction::Withdraw => cardano::plan_withdraw(address, account),
        AdaStakeAction::Undelegate => cardano::plan_undelegate(address, account),
    }
}

/// Signs and broadcasts the confirmed operation: prepared again HERE, it must be
/// the one shown (same certificates, same withdrawal, fee at most the one shown),
/// otherwise refused.
pub fn send_ada_stake(
    data_dir: &Path,
    device_password: &str,
    action: AdaStakeAction,
    pool: Option<&str>,
    shown: &cardano::StakePlan,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (payment, stake) = cardano::account_keys(&seed, profile_index);
    let from = cardano::base_address(&payment.public(), &stake.public());
    let plan = ada_stake_plan(&from, &cardano::stake_account(&from)?, action, pool)?;
    anyhow::ensure!(
        plan.certs == shown.certs && plan.withdrawal == shown.withdrawal && plan.fee <= shown.fee,
        "l'état de votre délégation Cardano a changé depuis la confirmation — relancez l'opération"
    );
    cardano::send_stake(&payment, &stake, &from, &plan)
}

/// ADA send: preparation redone, fee never higher than the one shown (`shown_fee`),
/// transaction signed here, then broadcast.
pub fn send_ada(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let units = ada_units(amount)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (payment, stake) = cardano::account_keys(&seed, profile_index);
    let from = cardano::base_address(&payment.public(), &stake.public());
    drop(stake);
    let plan = cardano::plan(&from, to, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Cardano ont augmenté depuis la confirmation ({} au lieu de {} ADA) — relancez l'envoi",
        cardano::format_ada(plan.fee),
        cardano::format_ada(shown_fee)
    );
    cardano::send(&payment, &from, to, &plan)
}

// --- Native Solana staking ---------------------------------------------------------

fn sol_mainnet_rpc() -> sol_rpc::SolRpc {
    sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc)
}

pub fn sol_stake_overview(owner: &str) -> Result<sol_stake::Overview> {
    sol_stake::overview(&sol_mainnet_rpc(), owner)
}

pub fn sol_validators() -> Result<Vec<sol_stake::Validator>> {
    sol_stake::validators(&sol_mainnet_rpc())
}

/// Natively staked SOL (lamports): the SOL card's line and the total value.
pub fn sol_staked_lamports(owner: &str) -> Result<u64> {
    sol_stake::staked_lamports(&sol_mainnet_rpc(), owner)
}

/// "Max" of the native staking window, in SOL.
pub fn sol_stake_max(owner: &str) -> Result<String> {
    Ok(sol_rpc::format_lamports(sol_stake::max_delegation(
        &sol_mainnet_rpc(),
        owner,
    )?))
}

/// Operation prepared and simulated from the profile's public address (confirmation
/// dialog). Stake: `amount` (SOL) and `target` = vote account; deactivate or
/// withdraw: `target` = stake account.
pub fn sol_stake_plan(
    owner: &str,
    action: sol_stake::Action,
    amount: Option<&str>,
    target: &str,
) -> Result<sol_stake::Plan> {
    let rpc = sol_mainnet_rpc();
    match action {
        sol_stake::Action::Delegate => {
            let lamports =
                wallet_flow::parse_sol_to_lamports(amount.context("montant à staker absent")?)?;
            sol_stake::plan_delegate(&rpc, owner, lamports, target)
        }
        sol_stake::Action::Deactivate => sol_stake::plan_deactivate(&rpc, owner, target),
        sol_stake::Action::Withdraw => sol_stake::plan_withdraw(&rpc, owner, target),
    }
}

/// Signs and broadcasts the confirmed operation: prepared and simulated again HERE,
/// it must be exactly the one shown, otherwise refused.
pub fn send_sol_stake(
    data_dir: &Path,
    device_password: &str,
    action: sol_stake::Action,
    amount: Option<&str>,
    target: &str,
    shown: &sol_stake::Plan,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let plan = sol_stake_plan(&bs58::encode(owner).into_string(), action, amount, target)?;
    anyhow::ensure!(
        plan == *shown,
        "l'état de votre staking Solana a changé depuis la confirmation — relancez l'opération"
    );
    let rpc = sol_mainnet_rpc();
    let message = sol_stake::message(&plan, &owner, &rpc.latest_blockhash()?)?;
    let raw_tx = sol_tx::assemble_transaction(
        &ed25519_dalek::Signer::sign(&signing_key, &message).to_bytes(),
        &message,
    );
    rpc.send_transaction(&raw_tx)
}

// --- MoonPay Trade (see core/src/moonpay_trade.rs) -------------------------------------

/// MoonPay Trade pair designated by the UI (the app's networks).
pub fn moonpay_assets(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
) -> Result<(moonpay_trade::Asset, moonpay_trade::Asset)> {
    let from = moonpay_trade::asset(from_coin, from_network)
        .context("crypto non échangeable via MoonPay Trade")?;
    let to = moonpay_trade::asset(to_coin, to_network)
        .context("crypto non échangeable via MoonPay Trade")?;
    Ok((from, to))
}

/// MoonPay Trade quote (shape verified, see `moonpay_trade::parse_action`) for an
/// amount entered.
pub fn moonpay_quote(
    from: &moonpay_trade::Asset,
    to: &moonpay_trade::Asset,
    amount: &str,
    sender: &str,
    recipient: &str,
) -> Result<moonpay_trade::Quote> {
    let units = tokens::parse_amount(amount, from.decimals)?;
    moonpay_trade::quote(from, to, units, sender, recipient)
}

/// Simulates the swap through the router (same EVM network) from `sender`: an
/// approval for the exact amount if needed, then the call; checks that only the
/// token sold leaves, for the exact amount, and that the token bought lands on
/// `sender`'s address, at least the guaranteed minimum. Returns what would arrive.
pub fn verify_moonpay_router(
    from: &moonpay_trade::Asset,
    to: &moonpay_trade::Asset,
    quote: &moonpay_trade::Quote,
    sender: &str,
) -> Result<u128> {
    let moonpay_trade::TradeTx::Router {
        router,
        data,
        value,
    } = &quote.tx
    else {
        anyhow::bail!("devis MoonPay Trade sans routeur")
    };
    anyhow::ensure!(
        from.network == to.network,
        "échange MoonPay Trade par le routeur : même réseau seulement"
    );
    let network = wallet_flow::evm_network(from.network).context("réseau EVM inconnu")?;
    let user = wallet_flow::parse_evm_address(sender)?;
    let token = |asset: &moonpay_trade::Asset| {
        if asset.native {
            Ok(None)
        } else {
            wallet_flow::parse_evm_address(asset.token).map(Some)
        }
    };
    let expected = moonpay_trade::Expected {
        user,
        sell_token: token(from)?,
        amount: quote.amount,
        buy_token: token(to)?,
        min_out: quote.min_out,
        router: *router,
    };
    let router_text = derivation::format_address(router);
    let approvals = match expected.sell_token {
        Some(_) => approval_amounts(
            get_erc20_allowance(network, from.token, &user, router)?,
            quote.amount,
        ),
        None => Vec::new(),
    };
    let approve_data: Vec<Vec<u8>> = approvals
        .iter()
        .map(|amount| erc20_approve_data(router, *amount))
        .collect();
    let mut calls: Vec<eth_rpc::SimCallRequest> = approve_data
        .iter()
        .map(|data| eth_rpc::SimCallRequest {
            from: sender,
            to: from.token,
            value: 0,
            data,
        })
        .collect();
    calls.push(eth_rpc::SimCallRequest {
        from: sender,
        to: &router_text,
        value: *value,
        data,
    });
    let simulated = eth_rpc::EthRpc::new(network.rpc).simulate_v1_with_native_transfers(&calls)?;
    moonpay_trade::verify_router(&simulated, &expected)
}

/// Gas cap for a MoonPay Trade swap through the router (~325,000 measured in
/// simulation on Ethereum on 2026-10-07, ETH → USDC); Arbitrum: the limit also
/// counts posting to Ethereum.
fn moonpay_gas_cap(network: &wallet_flow::EvmNetwork) -> u64 {
    if network.transfer_gas.is_none() {
        EVM_MAX_ESTIMATED_GAS
    } else {
        700_000
    }
}

/// Maximum fee for a MoonPay Trade swap through the router, shown before
/// confirmation: the call at its gas cap (+ L1 fees on Base) and the approvals to
/// the router if needed.
pub fn moonpay_router_fees(
    from: &moonpay_trade::Asset,
    quote: &moonpay_trade::Quote,
    sender: &str,
    gas_price: u128,
) -> Result<(EvmFee, EvmFee, usize)> {
    let moonpay_trade::TradeTx::Router {
        router,
        data,
        value,
    } = &quote.tx
    else {
        anyhow::bail!("devis MoonPay Trade sans routeur")
    };
    let network = wallet_flow::evm_network(from.network).context("réseau EVM inconnu")?;
    let cap = moonpay_gas_cap(network);
    let call = EvmFee {
        gas_price,
        gas_limit: cap,
        l1_fee: evm_l1_fee(network, router, *value, data, gas_price, cap)?,
    };
    if from.native {
        return Ok((
            call,
            EvmFee {
                gas_price,
                gas_limit: 0,
                l1_fee: 0,
            },
            0,
        ));
    }
    let (approve_cap, _) = swap_gas_caps(network);
    let contract = wallet_flow::parse_evm_address(from.token)?;
    let approve = EvmFee {
        gas_price,
        gas_limit: approve_cap,
        l1_fee: evm_l1_fee(
            network,
            &contract,
            0,
            &erc20_approve_data(router, quote.amount),
            gas_price,
            approve_cap,
        )?,
    };
    let approvals = approval_amounts(
        get_erc20_allowance(
            network,
            from.token,
            &wallet_flow::parse_evm_address(sender)?,
            router,
        )?,
        quote.amount,
    )
    .len();
    Ok((call, approve, approvals))
}

/// MoonPay Trade swap through the router: the transaction SHOWN, checked again by
/// simulation just before signing (at least the minimum shown on the profile's
/// address), in the name of the signing profile, at the gas price shown; an
/// approval for the exact amount to the router if needed. Returns the hash.
#[allow(clippy::too_many_arguments)]
pub fn send_moonpay_router(
    data_dir: &Path,
    device_password: &str,
    from: &moonpay_trade::Asset,
    to: &moonpay_trade::Asset,
    quote: &moonpay_trade::Quote,
    sender: &str,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    let moonpay_trade::TradeTx::Router {
        router,
        data,
        value,
    } = &quote.tx
    else {
        anyhow::bail!("devis MoonPay Trade sans routeur")
    };
    let network = wallet_flow::evm_network(from.network).context("réseau EVM inconnu")?;
    anyhow::ensure!(
        moonpay_trade::router(network.id)
            .map(wallet_flow::parse_evm_address)
            .transpose()?
            == Some(*router),
        "transaction MoonPay Trade incohérente — échange refusé"
    );
    check_evm_gas_price(network, gas_price)?;
    verify_moonpay_router(from, to, quote, sender)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(
        address_str.eq_ignore_ascii_case(sender),
        "l'échange MoonPay Trade n'est pas au nom de ce profil — échange refusé"
    );
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let join = "un fil de lecture ne doit pas paniquer";
        (
            nonce.join().expect(join),
            chain_id.join().expect(join),
            balance.join().expect(join),
        )
    });
    let (mut nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );
    let cap = moonpay_gas_cap(network);
    let call_fee = gas_price
        .checked_mul(u128::from(cap))
        .and_then(|g| {
            g.checked_add(evm_l1_fee(network, router, *value, data, gas_price, cap).ok()?)
        })
        .and_then(|f| f.checked_add(*value))
        .context("montant + frais dépassant la capacité représentable")?;
    if from.native {
        ensure_fees_covered(network, router, router, &[], gas_price, call_fee, balance)?;
    } else {
        let contract = wallet_flow::parse_evm_address(from.token)?;
        let token_balance = get_erc20_balance(network, from.token, &address_str)?;
        anyhow::ensure!(
            quote.amount <= token_balance,
            "{} insuffisants : {} disponibles, {} demandés",
            from.symbol,
            tokens::format_amount(token_balance, from.decimals),
            tokens::format_amount(quote.amount, from.decimals)
        );
        let approvals = approval_amounts(
            get_erc20_allowance(network, from.token, &address, router)?,
            quote.amount,
        );
        ensure_fees_covered(
            network, &contract, router, &approvals, gas_price, call_fee, balance,
        )?;
        nonce = send_approvals(
            &rpc,
            network,
            &signing_key,
            &address_str,
            chain_id,
            nonce,
            &contract,
            router,
            &approvals,
            gas_price,
        )?;
    }
    let router_text = derivation::format_address(router);
    let estimated = rpc.estimate_gas(&address_str, &router_text, *value, data)?;
    let gas_limit = estimated
        .saturating_mul(12)
        .div_ceil(10)
        .max(eth_tx::intrinsic_gas(data));
    anyhow::ensure!(gas_limit <= cap, "gas estimé anormalement élevé pour l'échange MoonPay Trade ({gas_limit}, maximum {cap}) — échange refusé");
    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit,
        to: *router,
        value: *value,
        chain_id,
        data: data.clone(),
    };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

// --- Stacks (STX) -------------------------------------------------------------------

pub fn get_stx_balance(address: &str) -> Result<u64> {
    stacks::balance(&stacks::MAINNET, address)
}

/// State of a Stacks recipient address, for the dialog's warnings.
pub fn stx_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match stacks::address_activity(&stacks::MAINNET, to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in STX (6 decimals), shown AND signed.
pub fn canonical_stx_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, stacks::DECIMALS)?,
        stacks::DECIMALS,
    ))
}

fn stx_units(amount: &str) -> Result<u64> {
    u64::try_from(tokens::parse_amount(amount, stacks::DECIMALS)?).context("montant hors limites")
}

/// Stacks memo entered (at most 34 ASCII characters; empty = none).
pub fn parse_stacks_memo(memo: Option<&str>) -> Result<String> {
    stacks::parse_memo(memo)
}

/// A send prepared for the confirmation dialog: available balance, fee.
pub fn stx_send_plan(from_address: &str, to: &str, amount: &str) -> Result<stacks::StxPlan> {
    stacks::plan(&stacks::MAINNET, from_address, to, stx_units(amount)?)
}

/// STX send: preparation redone, fee never higher than the one shown (`shown_fee`),
/// transfer signed here, then broadcast.
pub fn send_stx(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    memo: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let units = stx_units(amount)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let key = derivation::derive_stacks_key(&seed, profile_index)?;
    let plan = stacks::plan(
        &stacks::MAINNET,
        &stacks::address_of(&stacks::MAINNET, &key),
        to,
        units,
    )?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Stacks ont augmenté depuis la confirmation ({} au lieu de {} STX) — relancez l'envoi",
        stacks::format_stx(plan.fee),
        stacks::format_stx(shown_fee)
    );
    stacks::send(&stacks::MAINNET, &key, to, &plan, memo)
}

/// "Max" button: available balance minus the fee.
pub fn stx_max(from: &str) -> Result<String> {
    Ok(stacks::format_stx(stacks::max_amount(
        &stacks::MAINNET,
        from,
    )?))
}

// --- Bittensor (TAO) ----------------------------------------------------------------

pub fn get_tao_balance(address: &str) -> Result<u64> {
    bittensor::balance(address)
}

/// State of a Bittensor recipient address, for the dialog's warnings.
pub fn tao_recipient_activity(to: &str) -> Result<RecipientActivity> {
    Ok(match bittensor::address_activity(to)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in TAO (9 decimals), shown AND signed.
pub fn canonical_tao_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, bittensor::DECIMALS)?,
        bittensor::DECIMALS,
    ))
}

fn tao_units(amount: &str) -> Result<u64> {
    u64::try_from(tokens::parse_amount(amount, bittensor::DECIMALS)?)
        .context("montant hors limites")
}

/// A send prepared for the confirmation dialog: fee, reserves checked.
pub fn tao_send_plan(from_address: &str, to: &str, amount: &str) -> Result<bittensor::TaoPlan> {
    bittensor::plan(from_address, to, tao_units(amount)?)
}

/// TAO send: preparation redone, fee at most the one shown give or take 10% (it
/// follows network load, very slightly), transfer signed here, validated by the
/// node, then broadcast.
pub fn send_tao(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let units = tao_units(amount)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let pair = bittensor::keypair(&seed, profile_index)?;
    let plan = bittensor::plan(&bittensor::address(&pair.public.to_bytes()), to, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee.saturating_add(shown_fee / 10),
        "les frais Bittensor ont augmenté depuis la confirmation ({} au lieu de {} TAO) — relancez l'envoi",
        bittensor::format_tao(plan.fee),
        bittensor::format_tao(shown_fee)
    );
    bittensor::send(&pair, &plan)
}

/// "Max" button: available balance minus the fee and the account's reserve.
pub fn tao_max(from: &str, to: Option<&str>) -> Result<String> {
    Ok(tokens::format_amount(
        u128::from(bittensor::max_amount(from, to)?),
        bittensor::DECIMALS,
    ))
}

/// "Max" button: all spendable ADA, fee deducted (to `to` if known).
pub fn ada_max(from: &str, to: Option<&str>) -> Result<String> {
    Ok(cardano::format_ada(match to {
        Some(to) => cardano::plan_max(from, to)?.amount,
        None => cardano::max_amount(from)?,
    }))
}

// --- Dogecoin -----------------------------------------------------------------------

pub fn get_doge_balance(address: &str) -> Result<u64> {
    doge::balance(address)
}

pub fn has_pending_doge(address: &str) -> Result<bool> {
    doge::has_pending(address)
}

/// State of a Dogecoin recipient address, for the dialog's warnings.
pub fn doge_recipient_activity(to: &str) -> Result<RecipientActivity> {
    doge::parse_recipient(to)?;
    Ok(match doge::address_activity(to.trim())? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Canonical form of an amount in DOGE (8 decimals), shown AND signed.
pub fn canonical_doge_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, doge::DECIMALS)?,
        doge::DECIMALS,
    ))
}

/// A send prepared for the confirmation dialog: recipient verified (never
/// ourselves), outputs chosen then verified against their source transactions, fee
/// at the current rate, change returned.
pub fn doge_send_plan(from_address: &str, to: &str, amount: &str) -> Result<doge::SendPlan> {
    let own = match doge::parse_recipient(from_address)? {
        doge::Recipient::P2pkh(hash) => hash,
        doge::Recipient::P2sh(_) => anyhow::bail!("adresse Dogecoin du profil invalide"),
    };
    let recipient = doge::parse_recipient(to)?;
    anyhow::ensure!(
        recipient != doge::Recipient::P2pkh(own),
        "envoi vers votre propre adresse Dogecoin"
    );
    let units = u64::try_from(tokens::parse_amount(amount, doge::DECIMALS)?)
        .context("montant hors limites")?;
    doge::plan(&own, units)
}

/// Dogecoin send: outputs reread and checked again, fee never higher than the one
/// shown (`shown_fee`), transaction built and signed here, then broadcast.
pub fn send_doge(
    data_dir: &Path,
    device_password: &str,
    to: &str,
    amount: &str,
    shown_fee: u64,
    profile_index: u32,
) -> Result<String> {
    let recipient = doge::parse_recipient(to)?;
    let units = u64::try_from(tokens::parse_amount(amount, doge::DECIMALS)?)
        .context("montant hors limites")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_doge_key(&seed, profile_index)?;
    anyhow::ensure!(
        recipient != doge::Recipient::P2pkh(hash160),
        "envoi vers votre propre adresse Dogecoin"
    );
    let plan = doge::plan(&hash160, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Dogecoin ont augmenté depuis la confirmation ({} au lieu de {} DOGE) — relancez l'envoi",
        doge::format_doge(plan.fee),
        doge::format_doge(shown_fee)
    );
    let signed = doge::build_signed(&plan, &key, &hash160, &recipient)?;
    doge::broadcast(&signed)
}

pub struct BtcFeeEstimate {
    pub fast_sat: u64,
    pub medium_sat: u64,
    pub slow_sat: u64,
}

/// The closest confirmation target (in blocks) available in `estimates` (sorted by
/// increasing target, see `btc_rpc::EsploraClient::fee_estimates`), preferring a
/// target <= `target` (never a rate more expensive than planned); failing that, the
/// closest target above. `1.0` sat/vByte (the network's standard minimum relay fee)
/// is the safety net if the API returns nothing.
fn fee_rate_for_target(estimates: &[(u32, f64)], target: u32) -> f64 {
    estimates
        .iter()
        .filter(|(t, _)| *t <= target)
        .max_by_key(|(t, _)| *t)
        .or_else(|| estimates.first())
        .map(|(_, rate)| *rate)
        .unwrap_or(1.0)
}

/// Start of the refusal message for a Bitcoin amount below the dust threshold
/// (translated by the app).
pub const BTC_DUST_PREFIX: &str = "montant trop petit pour le réseau Bitcoin : au moins ";

/// Output script of a Bitcoin send's recipient (any standard type, see
/// `derivation::btc_recipient_script`), with an amount above the dust threshold for
/// that output type; otherwise nodes refuse the transaction.
pub fn btc_recipient(
    network: &wallet_flow::BtcNetwork,
    to: &str,
    amount_sat: u64,
) -> Result<Vec<u8>> {
    let script = (network.recipient_script)(to)?;
    let dust = crate::btc_tx::dust_threshold(&script);
    anyhow::ensure!(
        amount_sat >= dust,
        "{BTC_DUST_PREFIX}{} BTC vers cette adresse",
        tokens::format_amount(u128::from(dust), 8)
    );
    Ok(script)
}

/// `btc_recipient` for an amount entered (in BTC): checks for the preview and for
/// deposits, before the confirmation dialog.
pub fn check_btc_recipient(
    network: &wallet_flow::BtcNetwork,
    to: &str,
    amount_btc: &str,
) -> Result<()> {
    btc_recipient(network, to, wallet_flow::parse_btc_to_sat(amount_btc)?).map(|_| ())
}

/// Change of a Bitcoin send consuming `total_sat`: sufficient funds required; 0
/// below the dust threshold (the remainder then goes to the fee).
pub(crate) fn btc_change(total_sat: u64, amount_sat: u64, fee_sat: u64) -> Result<u64> {
    const DUST_THRESHOLD_SAT: u64 = 1_000;
    // `checked_add` rather than `+`: `amount_sat` comes from the amount the user
    // typed, potentially close to u64::MAX (see parse_btc_to_sat). An overflow here
    // would wrap around silently in release builds and could let an invalid amount
    // pass as "sufficient".
    let total_needed = amount_sat
        .checked_add(fee_sat)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= total_sat,
        "fonds insuffisants : {total_sat} sat confirmés disponibles, {amount_sat} sat + {fee_sat} sat de frais requis"
    );
    let remaining = total_sat - total_needed;
    Ok(if remaining > DUST_THRESHOLD_SAT {
        remaining
    } else {
        0
    })
}

/// Estimates the fast/medium/slow fees (~1/~3/~6 blocks, i.e. about 10 minutes, 30
/// minutes and 1 hour; a full-day target is of no practical use to anyone) for a
/// transfer from `address`, in sats, to choose before `send_btc`. The number of
/// inputs depends on the UTXOs actually available on this address (all consumed,
/// see `send_btc`); the number of outputs is assumed to be 2 (recipient + change),
/// the most common case. If the real transaction ends up with only one output, the
/// fee paid will be very slightly higher than needed (a few sats), never
/// insufficient.
pub fn estimate_btc_fees(
    address: &str,
    network: &wallet_flow::BtcNetwork,
) -> Result<BtcFeeEstimate> {
    estimate_btc_fees_for(&[address], network)
}

/// `estimate_btc_fees` for a send consuming the UTXOs of several addresses (Ledger
/// account: receive and change, see `hardware::send_btc`).
pub(crate) fn estimate_btc_fees_for(
    addresses: &[&str],
    network: &wallet_flow::BtcNetwork,
) -> Result<BtcFeeEstimate> {
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    // The addresses' UTXOs and the network fee estimates are independent HTTP calls
    // (none depends on another's result): running them in parallel rather than one
    // after the other roughly halves the perceived latency when the Bitcoin send
    // window opens.
    let (utxos, estimates) = std::thread::scope(|scope| {
        let utxo_handles: Vec<_> = addresses
            .iter()
            .map(|a| scope.spawn(|| esplora.utxos(a)))
            .collect();
        let estimates_handle = scope.spawn(|| esplora.fee_estimates());
        (
            utxo_handles
                .into_iter()
                .map(|h| h.join().expect("le thread UTXOs ne doit pas paniquer"))
                .collect::<Result<Vec<_>>>(),
            estimates_handle
                .join()
                .expect("le thread frais ne doit pas paniquer"),
        )
    });
    let num_inputs = utxos?.iter().map(Vec::len).sum::<usize>().max(1);
    let vsize = crate::btc_tx::estimate_send_vsize(num_inputs) as f64;
    let estimates = estimates?;

    let sat_for_target =
        |target: u32| (fee_rate_for_target(&estimates, target) * vsize).ceil() as u64;
    Ok(BtcFeeEstimate {
        fast_sat: sat_for_target(1),
        medium_sat: sat_for_target(3),
        slow_sat: sat_for_target(6),
    })
}

/// Unlocks the vault, signs and broadcasts a Bitcoin transfer (mainnet or testnet
/// depending on `network`). `fee_sat` is chosen by the caller (see
/// `estimate_btc_fees`: fast/medium/slow) rather than fixed here: real fees are set
/// by the market on mainnet, unlike testnet where they are negligible, and a single
/// constant would have left a real transaction underpaid and unconfirmed forever.
pub fn send_btc(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::BtcNetwork,
    to: &str,
    amount_btc: &str,
    fee_sat: u64,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, hash160) = (network.derive_key)(&seed, profile_index)?;

    let address = (network.format_address)(&hash160)?;
    let amount_sat = wallet_flow::parse_btc_to_sat(amount_btc)?;
    let to_script = btc_recipient(network, to, amount_sat)?;

    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let utxos = esplora.utxos(&address)?;
    let total_sat: u64 = utxos.iter().map(|u| u.value_sat).sum();
    let change_sat = btc_change(total_sat, amount_sat, fee_sat)?;

    let tx = crate::btc_tx::BtcTx {
        inputs: utxos,
        to_script,
        value_sat: amount_sat,
        change_hash160: hash160,
        change_sat,
        op_return_data: None,
    };
    let raw_tx = tx.sign(&signing_key, &hash160)?;
    esplora.broadcast(&raw_tx)
}

/// Unlocks the vault, signs and broadcasts a Bitcoin -> THORChain swap: the same
/// mechanics as `send_btc`, but the send goes to the quote's `inbound_address` (not
/// an address typed by the user) and carries the swap memo in an OP_RETURN output.
/// Unlike `send_btc`, the fee is not chosen by the caller (no fast/medium/slow
/// selector in the swap window, which already has plenty of steps): the "medium"
/// target is used automatically, consistent with the rest of the swap flow
/// (Jupiter/THORChain also choose their own network fees without user input).
pub fn send_swap_btc(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::BtcNetwork,
    quote: &thorchain_rpc::SwapQuote,
    amount_btc: &str,
    profile_index: u32,
) -> Result<String> {
    anyhow::ensure!(
        quote.memo.len() <= 80,
        "memo THORChain trop long pour une sortie OP_RETURN standard ({} octets)",
        quote.memo.len()
    );

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, hash160) = (network.derive_key)(&seed, profile_index)?;

    let address = (network.format_address)(&hash160)?;
    let to_hash160 = (network.parse_address)(&quote.inbound_address)?;
    let amount_sat = wallet_flow::parse_btc_to_sat(amount_btc)?;

    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let (utxos, estimates) = std::thread::scope(|scope| {
        let utxos_handle = scope.spawn(|| esplora.utxos(&address));
        let estimates_handle = scope.spawn(|| esplora.fee_estimates());
        (
            utxos_handle
                .join()
                .expect("le thread UTXOs ne doit pas paniquer"),
            estimates_handle
                .join()
                .expect("le thread d'estimation de frais ne doit pas paniquer"),
        )
    });
    let utxos = utxos?;
    let estimates = estimates?;
    let total_sat: u64 = utxos.iter().map(|u| u.value_sat).sum();

    // Vault + change (P2WPKH), plus the OP_RETURN output at its real size (66 bytes
    // for a 55-byte memo, versus 31 for a P2WPKH output).
    let vsize = (crate::btc_tx::estimate_p2wpkh_vsize(utxos.len(), 2)
        + crate::btc_tx::op_return_output_size(quote.memo.len())) as f64;
    // Never below the rate recommended by the protocol (`recommended_gas_rate`): an
    // underpaying deposit may take a while to be picked up.
    let fee_rate =
        fee_rate_for_target(&estimates, 3).max(quote.recommended_gas_rate.unwrap_or(0) as f64);
    // Rate read from Esplora without user input (unlike `send_btc`, where the user
    // picks a tier shown in sats): capped so a compromised server cannot inflate the
    // fees at will, the same idea as the EVM gas price cap
    // (`EvmNetwork::max_gas_price_wei`). The cap is shown in the swap's confirmation
    // dialog.
    anyhow::ensure!(
        fee_rate.is_finite() && fee_rate <= BTC_SWAP_MAX_FEE_RATE_SAT_VB as f64,
        "tarif de frais Bitcoin anormalement élevé ({fee_rate:.1} sat/vB, plafond {BTC_SWAP_MAX_FEE_RATE_SAT_VB}) — swap refusé"
    );
    let fee_sat = (fee_rate * vsize).ceil() as u64;

    const DUST_THRESHOLD_SAT: u64 = 1_000;
    let total_needed = amount_sat
        .checked_add(fee_sat)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= total_sat,
        "fonds insuffisants : {total_sat} sat confirmés disponibles, {amount_sat} sat + {fee_sat} sat de frais requis"
    );
    let remaining = total_sat - total_needed;
    let change_sat = if remaining > DUST_THRESHOLD_SAT {
        remaining
    } else {
        0
    };

    let tx = crate::btc_tx::BtcTx {
        inputs: utxos,
        to_script: crate::btc_tx::p2wpkh_script_pubkey(&to_hash160),
        value_sat: amount_sat,
        change_hash160: hash160,
        change_sat,
        op_return_data: Some(quote.memo.as_bytes().to_vec()),
    };
    let raw_tx = tx.sign(&signing_key, &hash160)?;
    esplora.broadcast(&raw_tx)
}

/// Checks that a Solana address really is a WALLET before sending funds to it.
/// Found during the "known hot wallet weaknesses" audit (the "sending to an address
/// type where funds are lost" class, a classic Solana trap that Phantom/Solflare
/// warn about). There was no check at all: pasting a TOKEN ACCOUNT address by
/// mistake (the one explorers often show) instead of the wallet's created a USDC
/// account owned by... that token account, which nobody can ever sign for, so the
/// funds were lost for good. To call BEFORE confirmation (see the Tauri app), and
/// again just before signing (defense in depth).
pub fn check_solana_recipient(to: &str, network: &wallet_flow::SolNetwork) -> Result<()> {
    let pubkey: [u8; 32] = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let state = sol_rpc::SolRpc::new(network.rpc)
        .multiple_accounts(&[bs58::encode(pubkey).into_string()])?
        .into_iter()
        .next()
        .flatten();
    classify_solana_recipient(&pubkey, state.as_ref())
}

fn classify_solana_recipient(
    pubkey: &[u8; 32],
    state: Option<&sol_rpc::AccountState>,
) -> Result<()> {
    match state {
        // A wallet (or a multisig vault, also owned by the system program).
        Some(s) if s.owner == SYSTEM_PROGRAM_ID => Ok(()),
        Some(s) if s.owner == TOKEN_PROGRAM_ID || s.owner == TOKEN_2022_PROGRAM_ID => anyhow::bail!(
            "cette adresse est un compte de jetons (ou un mint), pas un portefeuille : les fonds y seraient perdus. Demandez l'adresse du PORTEFEUILLE du destinataire."
        ),
        Some(_) => anyhow::bail!("cette adresse appartient à un programme, pas à un portefeuille — envoi refusé (fonds probablement irrécupérables)"),
        None if sol_spl::is_on_curve(pubkey) => Ok(()), // new wallet, never used
        None => anyhow::bail!(
            "cette adresse n'a aucune clé privée (dérivée d'un programme) et n'a jamais été utilisée — les fonds y seraient très probablement perdus"
        ),
    }
}

// --- State of a recipient address on the blockchain ------------------------
//
// Requested explicitly by the user: warn, in the native confirmation dialog, that
// a recipient address has never been used (a miscopied address, or one freshly
// generated by a scammer) or that it is empty. Read-only, BEFORE confirmation; a
// network failure does not prevent the send (the app then shows "could not be
// checked" rather than a reassuring silence).

/// See the block above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientActivity {
    /// No trace on the blockchain: an address that has never been used (EVM: no
    /// transaction sent and no ETH, since an EVM node does not expose RECEIVED
    /// transactions, see `history::evm_history`).
    Unused,
    /// Already used, but currently holds no funds.
    Empty,
    /// Holds funds.
    Funded,
}

fn classify_evm_activity(nonce: u64, balance_wei: u128) -> RecipientActivity {
    if balance_wei > 0 {
        RecipientActivity::Funded
    } else if nonce == 0 {
        RecipientActivity::Unused
    } else {
        RecipientActivity::Empty
    }
}

fn classify_btc_activity(stats: &btc_rpc::AddressStats) -> RecipientActivity {
    if stats.balance_sat > 0 {
        RecipientActivity::Funded
    } else if stats.tx_count == 0 {
        RecipientActivity::Unused
    } else {
        RecipientActivity::Empty
    }
}

/// `lamports`: `None` if the account does not exist on-chain (never used OR
/// emptied: Solana deletes an account at 0 lamports), hence `has_history` to tell
/// the two apart.
fn classify_sol_activity(lamports: Option<u64>, has_history: bool) -> RecipientActivity {
    match lamports {
        Some(l) if l > 0 => RecipientActivity::Funded,
        _ if has_history => RecipientActivity::Empty,
        _ => RecipientActivity::Unused,
    }
}

/// Refuses a malformed EVM address (or one with a wrong EIP-55 checksum) BEFORE the
/// confirmation dialog; until now it was only rejected after confirmation, at
/// signing time.
pub fn validate_evm_recipient(to: &str) -> Result<()> {
    wallet_flow::parse_evm_address(to).map(|_| ())
}

/// Same principle as `validate_evm_recipient`, for Bitcoin.
pub fn validate_btc_recipient(to: &str, network: &wallet_flow::BtcNetwork) -> Result<()> {
    (network.recipient_script)(to).map(|_| ())
}

pub fn evm_recipient_activity(
    to: &str,
    network: &wallet_flow::EvmNetwork,
) -> Result<RecipientActivity> {
    let address = derivation::format_address(&wallet_flow::parse_evm_address(to)?);
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let (nonce, balance) = std::thread::scope(|scope| {
        let nonce_handle = scope.spawn(|| rpc.nonce(&address));
        let balance_handle = scope.spawn(|| rpc.balance(&address));
        (
            nonce_handle
                .join()
                .expect("le thread nonce ne doit pas paniquer"),
            balance_handle
                .join()
                .expect("le thread balance ne doit pas paniquer"),
        )
    });
    Ok(classify_evm_activity(nonce?, balance?))
}

pub fn btc_recipient_activity(
    to: &str,
    network: &wallet_flow::BtcNetwork,
) -> Result<RecipientActivity> {
    // Format validated first: the address is inserted into the URL path. Lowercase for
    // a bech32 address only (case-insensitive): a 1…/3… (base58) address in lowercase
    // would be a different address.
    (network.recipient_script)(to)?;
    let to = to.trim();
    let bech32 = to
        .get(..3)
        .is_some_and(|p| p.eq_ignore_ascii_case("bc1") || p.eq_ignore_ascii_case("tb1"));
    let stats = btc_rpc::EsploraClient::new(network.esplora_base).address_stats(&if bech32 {
        to.to_ascii_lowercase()
    } else {
        to.to_string()
    })?;
    Ok(classify_btc_activity(&stats))
}

/// For a USDC send too: it is the recipient WALLET that is assessed (a missing USDC
/// account is already flagged separately, with its cost).
pub fn sol_recipient_activity(
    to: &str,
    network: &wallet_flow::SolNetwork,
) -> Result<RecipientActivity> {
    let pubkey: [u8; 32] = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let address = bs58::encode(pubkey).into_string();
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let lamports = rpc
        .multiple_accounts(std::slice::from_ref(&address))?
        .into_iter()
        .next()
        .flatten()
        .map(|s| s.lamports);
    let has_history = if lamports.is_some_and(|l| l > 0) {
        true
    } else {
        rpc.has_any_signature(&address)?
    };
    Ok(classify_sol_activity(lamports, has_history))
}

/// USDC send: a wallet can hold USDC without any SOL (its main account is then
/// purged, and only its USDC account exists), so calling it "empty" would be wrong.
/// Holds USDC => `Funded`; an existing USDC account, even empty, proves the address
/// has been used => at least `Empty`.
pub fn usdc_recipient_activity(
    to: &str,
    network: &wallet_flow::SolNetwork,
) -> Result<RecipientActivity> {
    let owner: [u8; 32] = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = bs58::encode(sol_spl::find_associated_token_address(
        &owner,
        &sol_spl::usdc_mint_mainnet(),
    ))
    .into_string();
    let usdc_balance = sol_rpc::SolRpc::new(network.rpc).token_account_balance(&ata)?;
    if usdc_balance.is_some_and(|b| b > 0) {
        return Ok(RecipientActivity::Funded);
    }
    Ok(match (sol_recipient_activity(to, network)?, usdc_balance) {
        (RecipientActivity::Unused, Some(_)) => RecipientActivity::Empty,
        (wallet, _) => wallet,
    })
}

/// Unlocks the vault, signs and broadcasts a Solana transfer.
pub fn send_sol(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    to: &str,
    amount_sol: &str,
    profile_index: u32,
) -> Result<String> {
    check_solana_recipient(to, network)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let message = prepare_sol_transfer(
        network,
        &signing_key.verifying_key().to_bytes(),
        to,
        amount_sol,
    )?;
    let raw_tx = sol_tx::assemble_transaction(
        &ed25519_dalek::Signer::sign(&signing_key, &message).to_bytes(),
        &message,
    );
    sol_rpc::SolRpc::new(network.rpc).send_transaction(&raw_tx)
}

/// Message for a SOL transfer ready to sign from `from_pubkey` (software or
/// hardware wallet, see `hardware::send_sol`): enough balance for amount + fee,
/// latest blockhash.
pub(crate) fn prepare_sol_transfer(
    network: &wallet_flow::SolNetwork,
    from_pubkey: &[u8; 32],
    to: &str,
    amount_sol: &str,
) -> Result<Vec<u8>> {
    let to_bytes = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let to_pubkey: [u8; 32] = to_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let lamports = wallet_flow::parse_sol_to_lamports(amount_sol)?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let from_address = bs58::encode(from_pubkey).into_string();
    // The balance and the latest blockhash are two independent RPC reads: running them
    // in parallel rather than one after the other cuts the perceived latency of a SOL
    // send by about half.
    let (balance, recent_blockhash) = std::thread::scope(|scope| {
        let balance_handle = scope.spawn(|| rpc.balance_lamports(&from_address));
        let blockhash_handle = scope.spawn(|| rpc.latest_blockhash());
        (
            balance_handle
                .join()
                .expect("le thread balance ne doit pas paniquer"),
            blockhash_handle
                .join()
                .expect("le thread blockhash ne doit pas paniquer"),
        )
    });
    let balance = balance?;
    let recent_blockhash = recent_blockhash?;

    // The same check as on the CLI side (`wallet_flow::send_sol`), missing here until
    // now: without it, an amount + fee above the balance was only detected when the RPC
    // node rejected it after signing, instead of a clear "insufficient funds" message.
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let total_needed = lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} lamports disponibles, {lamports} lamports + {SOL_FEE_LAMPORTS} lamports de frais requis"
    );

    Ok(sol_tx::build_message(
        from_pubkey,
        &[sol_tx::transfer_instruction(
            from_pubkey,
            &to_pubkey,
            lamports,
        )],
        &recent_blockhash,
    ))
}

fn parse_swap_amount_for_coin(coin: &str, amount: &str) -> Result<u128> {
    match coin {
        "sol" => wallet_flow::parse_sol_to_lamports(amount).map(u128::from),
        "btc" => wallet_flow::parse_btc_to_sat(amount).map(u128::from),
        "evm" => wallet_flow::parse_eth_to_wei(amount),
        "usdc" => wallet_flow::parse_usdc_to_micros(amount).map(u128::from),
        other => anyhow::bail!("actif non pris en charge pour le swap : {other}"),
    }
}

/// Amount to SHOW in a native confirmation dialog, rebuilt from the exact value
/// that will be signed (smallest unit) rather than copied from the input. Found in
/// audit round 22: the parsing functions tolerate forms the eye misreads (`"0.+5"`
/// = 0.05 BTC, leading or trailing line breaks removed by `trim`), so the text
/// shown could differ from what actually goes out. `coin`: "evm", "btc", "sol" or
/// "usdc". The result re-parses to exactly the same value: the caller uses it for
/// display AND for signing.
pub fn canonical_amount(coin: &str, amount: &str) -> Result<String> {
    let decimals: usize = match coin {
        "evm" => 18,
        "btc" => 8,
        "sol" => 9,
        "usdc" => 6,
        other => anyhow::bail!("actif non pris en charge pour le swap : {other}"),
    };
    let minor = parse_swap_amount_for_coin(coin, amount)?;
    let unit = 10u128.pow(decimals as u32);
    let (whole, frac) = (minor / unit, minor % unit);
    if frac == 0 {
        return Ok(whole.to_string());
    }
    let frac = format!("{frac:0decimals$}");
    Ok(format!("{whole}.{}", frac.trim_end_matches('0')))
}

/// Solana mint (32 bytes) of a crypto swapped through Jupiter: native SOL (wSOL),
/// or a registry SPL token (USDC, USDT, EURC, RENDER…, see tokens.rs); never a mint
/// supplied by the UI.
fn jupiter_mint_bytes_for_coin(coin: &str) -> Result<[u8; 32]> {
    match coin {
        "sol" => bs58::decode(jupiter_rpc::SOL_MINT)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("mint SOL mal formé (bug de compilation)"),
        token => registered_solana_token(token)
            .map(|t| t.mint)
            .context("crypto non échangeable via Jupiter"),
    }
}

fn jupiter_mint_for_coin(coin: &str) -> Result<String> {
    Ok(bs58::encode(jupiter_mint_bytes_for_coin(coin)?).into_string())
}

/// Decimals of a crypto swapped through Jupiter (SOL: 9; token: registry).
pub fn jupiter_decimals(coin: &str) -> Result<u8> {
    if coin == "sol" {
        return Ok(9);
    }
    Ok(registered_token(coin, "sol_mainnet")?.1.decimals)
}

/// Display symbol of a crypto swapped through Jupiter.
pub fn jupiter_symbol(coin: &str) -> Result<&'static str> {
    if coin == "sol" {
        return Ok("SOL");
    }
    Ok(registered_token(coin, "sol_mainnet")?.0.symbol)
}

/// Amount (text) → smallest unit of the crypto sold through Jupiter (xStocks: RAW
/// unit, see `jupiter_raw_amount`).
fn jupiter_amount(coin: &str, amount: &str) -> Result<u64> {
    let shown: u64 = tokens::parse_amount(amount, jupiter_decimals(coin)?)?
        .try_into()
        .context("montant trop grand")?;
    jupiter_raw_amount(coin, shown)
}

/// Amount of a Jupiter swap in its canonical form (shown AND signed, see
/// `canonical_amount`).
pub fn canonical_jupiter_amount(coin: &str, amount: &str) -> Result<String> {
    let decimals = jupiter_decimals(coin)?;
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, decimals)?,
        decimals,
    ))
}

/// Gets a Jupiter quote (read-only, no secrets involved): the expected output
/// amount, in the destination asset's smallest unit. `amount` in the SOURCE asset's
/// human unit, as everywhere else in this API.
pub fn get_jupiter_quote(
    from_coin: &str,
    to_coin: &str,
    amount: &str,
    slippage_bps: u32,
) -> Result<JupiterQuoteInfo> {
    let input_mint = jupiter_mint_for_coin(from_coin)?;
    let output_mint = jupiter_mint_for_coin(to_coin)?;
    let amount_native = jupiter_amount(from_coin, amount)?;
    let fee_mint = jupiter_fee_mint(
        &sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc),
        &input_mint,
        &output_mint,
    )?;
    let fee_bps = jupiter_fee_bps(from_coin, to_coin);
    let quote = jupiter_rpc::quote_with_fee(
        &input_mint,
        &output_mint,
        amount_native,
        slippage_bps,
        fee_mint,
        fee_bps,
    )?;
    // Output shown (and passed back to `send_jupiter_swap`) in display units.
    Ok(JupiterQuoteInfo {
        out_amount: jupiter_shown_out(to_coin, quote.out_amount)?,
        fee_mint,
        fee_bps,
    })
}

/// Jupiter affiliate fee for the pair: the liquid staking rate
/// (`swap_routes::staking_fee_bps`), otherwise `jupiter_rpc::AFFILIATE_FEE_BPS`.
pub fn jupiter_fee_bps(from_coin: &str, to_coin: &str) -> u32 {
    crate::swap_routes::staking_fee_bps((from_coin, "sol_mainnet"), (to_coin, "sol_mainnet"))
        .unwrap_or(jupiter_rpc::AFFILIATE_FEE_BPS)
}

/// Jupiter quote as shown: expected output, and the token for the affiliate fee
/// (`None`: fee-free swap).
pub struct JupiterQuoteInfo {
    pub out_amount: u64,
    pub fee_mint: Option<[u8; 32]>,
    /// Rate applied if `fee_mint` exists (basis points).
    pub fee_bps: u32,
}

/// Token for a Jupiter swap's affiliate fee: the first candidate
/// (`jupiter_rpc::fee_mint_candidates`) for which the affiliate's fee account
/// EXISTS; `None` otherwise. The swap then goes ahead without a fee rather than
/// making the user pay to create the developer's fee account, or failing (Jupiter
/// refuses a missing account).
fn jupiter_fee_mint(
    rpc: &sol_rpc::SolRpc,
    input_mint: &str,
    output_mint: &str,
) -> Result<Option<[u8; 32]>> {
    // xStocks (Token-2022), measured by simulation on 2026-10-09: when buying, a fee
    // taken on the token SOLD makes the Jupiter route fail (error 6014,
    // IncorrectTokenProgramID); taken on the xStock received (Token-2022 fee account),
    // it goes through. To an xStock: fee on it only (without an affiliate xStock fee
    // account: fee-free swap). From an xStock: fee on the token received (USDC…),
    // never on the xStock sold.
    let candidates = jupiter_rpc::fee_mint_candidates(input_mint, output_mint);
    let is_2022 =
        |mint: &[u8; 32]| jupiter_rpc::fee_token_program(mint) == sol_spl::token_2022_program_id();
    let output_2022 = bs58::decode(output_mint)
        .into_vec()
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .is_some_and(|m| is_2022(&m));
    let candidates: Vec<[u8; 32]> = if output_2022 {
        candidates
            .into_iter()
            .take(1)
            .filter(|m| is_2022(m))
            .collect()
    } else {
        candidates.into_iter().filter(|m| !is_2022(m)).collect()
    };
    for mint in candidates {
        if rpc.account_exists(&bs58::encode(jupiter_rpc::fee_account(&mint)?).into_string())? {
            return Ok(Some(mint));
        }
    }
    Ok(None)
}

/// SOL reserve for a Jupiter swap, checked before building the transaction: fees (a
/// generous floor, since there is no exact value before building), a temporary wSOL
/// account when selling SOL, and the destination token account if it has to be
/// created.
fn jupiter_sol_reserve(
    rpc: &sol_rpc::SolRpc,
    owner: &[u8; 32],
    from_coin: &str,
    to_coin: &str,
) -> Result<u64> {
    const SOL_FEE_RESERVE_LAMPORTS: u64 = 50_000;
    let mut reserve = SOL_FEE_RESERVE_LAMPORTS;
    // Swapping from native SOL first wraps it into the SPL token "wSOL", which
    // requires funding a temporary token account at the rent-exemption minimum, ON TOP
    // of the swap amount itself (recovered when that same account is closed at the end
    // of the transaction, but needed a moment earlier in the same transaction).
    // Queried live rather than hard-coded (a network parameter that changes), the same
    // principle as for the USDC ATA (see send_usdc); a fixed floor would badly
    // underestimate this real need.
    if from_coin == "sol" {
        reserve = reserve
            .checked_add(rpc.minimum_rent_exempt_balance(165)?)
            .context("réserve de frais dépasse la capacité représentable")?;
    }
    // The destination token account may also need to be created (Jupiter then includes
    // it in the transaction, see CreateIdempotent for the ATA): the same rent cost if
    // the account does not exist yet.
    if to_coin != "sol" {
        let output = registered_solana_token(to_coin)?;
        let dest_ata =
            sol_spl::find_associated_token_address_for(owner, &output.mint, &output.program);
        let dest_ata_b58 = bs58::encode(dest_ata).into_string();
        if !rpc.account_exists(&dest_ata_b58)? {
            reserve = reserve
                .checked_add(rpc.minimum_rent_exempt_balance(output.account_size())?)
                .context("réserve de frais dépasse la capacité représentable")?;
        }
    }
    Ok(reserve)
}

/// "Max" unavailable for this swap.
pub const SWAP_MAX_UNAVAILABLE: &str =
    "« Max » indisponible pour cet échange — saisissez le montant";

/// "Max" in the "Convert" window, from `owner` (the profile's address on
/// `from_network`). Token: its whole balance, since fees are paid in the network's
/// native coin. Native coin: the balance minus the most that the swap through
/// `protocol` will cost, using the same caps as its own funds check (contract gas,
/// Bitcoin memo output, Solana accounts to fund), with a margin in case the gas
/// price or the Bitcoin fee rate rises before the quote. That check, done before
/// any signing, is the one that counts.
pub fn swap_max(
    protocol: &str,
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    owner: &str,
) -> Result<String> {
    let token = tokens::find(from_coin, from_network).is_some()
        || (from_coin == "usdc" && from_network == "sol_mainnet");
    if token {
        return token_max(from_coin, from_network, owner);
    }
    if let Some(net) = wallet_flow::evm_network(from_network) {
        let transfer = evm_max_fee(net, Some(owner), owner)?;
        let gas_limit = match protocol {
            "lifi" => lifi_gas_cap(net),
            "swapkit" => transfer.gas_limit,
            _ => swap_gas_caps(net).1,
        };
        let gas_price = transfer.gas_price.saturating_add(transfer.gas_price / 4);
        return evm_max_native(
            net,
            owner,
            EvmFee {
                gas_price,
                gas_limit,
                l1_fee: transfer.l1_fee.saturating_mul(4),
            },
        );
    }
    match (from_network, protocol) {
        ("sol_mainnet", "jupiter" | "lifi") => {
            let net = &wallet_flow::SOLANA_MAINNET;
            let reserve = if protocol == "jupiter" {
                let owner_bytes: [u8; 32] = bs58::decode(owner)
                    .into_vec()
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .context("adresse Solana invalide")?;
                jupiter_sol_reserve(&sol_rpc::SolRpc::new(net.rpc), &owner_bytes, "sol", to_coin)?
                    .saturating_add(jupiter_rpc::PRIORITY_FEE_MAX_LAMPORTS)
            } else {
                LIFI_SOL_FEE_BUDGET_LAMPORTS
            };
            let max = get_sol_balance(owner, net)?
                .checked_sub(reserve)
                .filter(|max| *max > 0)
                .context("SOL insuffisants pour couvrir les frais de l'échange")?;
            Ok(tokens::format_amount(u128::from(max), 9))
        }
        ("sol_mainnet", _) => sol_max(&wallet_flow::SOLANA_MAINNET, owner),
        ("btc_mainnet", "swapkit") => {
            let net = &wallet_flow::BTC_MAINNET;
            btc_max(net, owner, estimate_btc_fees(owner, net)?.medium_sat)
        }
        ("btc_mainnet", _) => {
            // Like `send_swap_btc`: two outputs and the longest memo, 3-block rate (half again
            // as margin: reread at quote time, and at least the rate THORChain recommends).
            let esplora = btc_rpc::EsploraClient::new(wallet_flow::BTC_MAINNET.esplora_base);
            let (utxos, estimates) = (esplora.utxos(owner)?, esplora.fee_estimates()?);
            let vsize = (crate::btc_tx::estimate_p2wpkh_vsize(utxos.len(), 2)
                + crate::btc_tx::op_return_output_size(80)) as f64;
            let rate =
                (fee_rate_for_target(&estimates, 3) * 1.5).min(BTC_SWAP_MAX_FEE_RATE_SAT_VB as f64);
            let fee_sat = (rate * vsize).ceil() as u64;
            let total: u64 = utxos.iter().map(|u| u.value_sat).sum();
            let max = total
                .checked_sub(fee_sat)
                .filter(|max| *max > 1_000)
                .context("BTC insuffisants pour couvrir les frais de l'échange")?;
            Ok(tokens::format_amount(u128::from(max), 8))
        }
        // Maya deposit: a memo of at most 80 bytes (like `zec_swap_plan`), which may cost
        // one more ZIP-317 action (audit round 31).
        ("zec_mainnet", "swapkit") => zec_max(owner),
        ("zec_mainnet", _) => Ok(zcash::format_zec(zcash::max_amount_with_memo(
            &zcash::utxos(owner)?,
            Some(80),
        )?)),
        // Plain deposits (SwapKit).
        ("doge_mainnet", "swapkit") => doge_max(owner),
        ("tron_mainnet", "swapkit") => trx_max(owner, None),
        ("xrp_mainnet", "swapkit") => xrp_max(owner),
        ("ada_mainnet", "swapkit") => ada_max(owner, None),
        ("near_mainnet", "swapkit") => near_max(owner, None),
        _ => anyhow::bail!(SWAP_MAX_UNAVAILABLE),
    }
}

/// Sends a swap through Jupiter (within Solana, unlike cross-chain swaps through
/// THORChain); see jupiter_rpc.rs for the full context, notably why the transaction
/// itself is not rebuilt by hand here (only verified, then signed).
#[allow(clippy::too_many_arguments)]
pub fn send_jupiter_swap(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    from_coin: &str,
    to_coin: &str,
    amount: &str,
    slippage_bps: u32,
    shown_out_amount: u64,
    fee_mint: Option<[u8; 32]>,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let owner_address = bs58::encode(owner).into_string();

    let input_mint = jupiter_mint_for_coin(from_coin)?;
    let output_mint = jupiter_mint_for_coin(to_coin)?;
    let mut amount_native = jupiter_amount(from_coin, amount)?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let sol_balance = rpc.balance_lamports(&owner_address)?;
    let reserve = jupiter_sol_reserve(&rpc, &owner, from_coin, to_coin)?;

    // Swapping from native SOL first wraps it into the SPL token "wSOL", which
    // requires funding a temporary token account at the rent-exemption minimum, ON TOP
    // of the swap amount itself (recovered when that same account is closed at the end
    // of the transaction, but needed a moment earlier in the same transaction).
    // Queried live rather than hard-coded (a network parameter that changes), the same
    // principle as for the USDC ATA (see send_usdc); a fixed floor would badly
    // underestimate this real need.
    if from_coin == "sol" {
        let total_needed = amount_native
            .checked_add(reserve)
            .context("montant + frais dépasse la capacité représentable")?;
        anyhow::ensure!(
            total_needed <= sol_balance,
            "fonds insuffisants : {sol_balance} lamports disponibles, {amount_native} lamports + ~{reserve} lamports de frais/rent requis"
        );
    } else {
        anyhow::ensure!(
            reserve <= sol_balance,
            "SOL insuffisant pour les frais/rent : {sol_balance} lamports disponibles, ~{reserve} lamports requis"
        );
        // A source other than native SOL (USDC): the token balance itself is never covered
        // by the SOL balance check above, which only covers fees/rent, so it is checked
        // separately here.
        let input = registered_solana_token(from_coin)?;
        let source_ata =
            sol_spl::find_associated_token_address_for(&owner, &input.mint, &input.program);
        let source_ata_b58 = bs58::encode(source_ata).into_string();
        let source_balance = rpc.token_account_balance(&source_ata_b58)?.unwrap_or(0);
        // xStocks, the whole displayed balance: the whole raw balance, with nothing left
        // over.
        if input.scaled {
            let shown = tokens::parse_amount(amount, input.decimals)?;
            let multiplier = scaled_mint_config(&rpc, input.mint_b58, false)?.effective(unix_now());
            amount_native = scaled_raw_amount(shown, multiplier, source_balance)?;
        }
        anyhow::ensure!(
            amount_native <= source_balance,
            "fonds insuffisants : {source_balance} unité(s) disponibles, {amount_native} unité(s) requises"
        );
    }

    // The same fee decision as the one SHOWN in the confirmation (`fee_mint`). Output
    // shown in display units (xStocks): the floor is checked in raw units.
    let min_out_shown =
        shown_out_amount.saturating_mul(u64::from(10_000 - slippage_bps.min(10_000))) / 10_000;
    let min_out = match registered_solana_token(to_coin) {
        Ok(output) if output.scaled => scaled_mint_config(&rpc, output.mint_b58, true)?
            .effective(unix_now())
            .to_raw(u128::from(min_out_shown))?,
        _ => min_out_shown,
    };
    let limits = swap_effect_limits(owner, from_coin, amount_native, to_coin, min_out)?;
    // Price moved between the quote and the simulation: one fresh quote, once only.
    // Nothing is signed before a successful simulation.
    let mut retried = false;
    let raw_tx = loop {
        let quote = jupiter_rpc::quote_with_fee(
            &input_mint,
            &output_mint,
            amount_native,
            slippage_bps,
            fee_mint,
            jupiter_fee_bps(from_coin, to_coin),
        )?;
        let raw_tx = jupiter_rpc::build_swap_transaction(&quote, &owner_address)?;
        match check_swap_effects(&rpc, &raw_tx, &limits) {
            Ok(()) => break raw_tx,
            Err(e) if !retried && e.to_string() == SWAP_PRICE_MOVED => retried = true,
            Err(e) => return Err(e),
        }
    };

    // Simulation of the FULLY BUILT transaction, with a check of its real effects on
    // the user's accounts (see `check_swap_effects`), BEFORE signing it. Found in
    // audit round 22: the previous version signed first, then sent the SIGNED
    // transaction to the RPC node for simulation, so a malicious transaction later
    // rejected by the check had already left the app, signed and broadcastable by
    // anyone who saw it go by. The simulation verifies no signatures (`sigVerify:
    // false`): the unsigned message is enough, and that exact message is what gets
    // signed right after.

    // A fresh blockhash from our node (see `jupiter_rpc::with_recent_blockhash`).
    let raw_tx = jupiter_rpc::with_recent_blockhash(&raw_tx, &rpc.latest_blockhash()?)?;
    let signed_tx = jupiter_rpc::sign_swap_transaction(&raw_tx, &signing_key, &owner)?;
    rpc.send_transaction(&signed_tx)
}

// --- Checking the effects of a transaction built by a third party -------------
//
// Found during the "known hot wallet weaknesses" audit (the "blind signing of a
// transaction built by a third party" class): for a Jupiter swap, the ONLY check
// before signing was on the fee payer. A compromised Jupiter API could return a
// transaction with the right fee payer BUT also a transfer of all the SOL to
// itself, an `Approve` (a delegate able to drain the USDC later), a `SetAuthority`
// (theft of the USDC account itself) or an `Assign` of the main account, and all
// of it would have been signed. Now: simulation by the RPC node (a party
// INDEPENDENT of Jupiter) returning the accounts' state AFTER execution, compared
// with the state before.

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub(crate) const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub(crate) const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: &str = "AddressLookupTab1e1111111111111111111111111";
/// Size of an address lookup table's header before the list of keys (discriminator
/// 4 + deactivation_slot 8 + last_extended_slot 8 + start_index 1 + authority
/// Option<Pubkey> 33 + padding 2).
const LOOKUP_TABLE_META_SIZE: usize = 56;
/// Maximum network fee budget (base fee + priority) tolerated beyond the amount
/// swapped: 0.005 SOL. Real cost measured on real simulated mainnet swaps (test
/// `jupiter_swap_effects_pass_on_real_mainnet_swaps`): between ~25,000 and ~490,000
/// lamports depending on the route and congestion, and priority fees are capped at
/// 1,000,000 lamports on Jupiter's side (see
/// `jupiter_rpc::build_swap_transaction`). This budget therefore cannot be reached
/// legitimately, and it bounds what a malicious transaction could divert as
/// fees/tips.
const JUPITER_SWAP_FEE_BUDGET_LAMPORTS: u64 = 5_000_000;

/// What the user agreed to lose in the swap, and nothing more.
struct SwapEffectLimits {
    user: [u8; 32],
    /// Maximum loss in lamports, across ALL the user's accounts (main + token accounts,
    /// rent included): SOL amount sold + fee budget. Creating a token account for the
    /// user or wrapping/unwrapping SOL moves lamports between THEIR accounts without
    /// losing any, hence this total rather than an account-by-account check.
    max_lamport_loss: u64,
    /// Token sold (other than native SOL) and the maximum quantity that may leave.
    input_token: Option<([u8; 32], u64)>,
    /// What the user must receive AT LEAST. Found in the same audit: without this
    /// floor, bounding LOSSES was not enough, since a malicious transaction could take
    /// the SOL sold (an "authorized" loss) and return nothing (a route through a pool
    /// controlled by the attacker).
    min_output: MinOutput,
}

enum MinOutput {
    /// Native SOL: checked through the user's total lamports.
    Lamports(u64),
    /// SPL token (mint, minimum quantity).
    Token([u8; 32], u64),
    /// Nothing arrives on Solana: a swap to another network (LI.FI), where only losses
    /// are bounded.
    Nothing,
}

fn swap_effect_limits(
    owner: [u8; 32],
    from_coin: &str,
    amount_native: u64,
    to_coin: &str,
    min_out: u64,
) -> Result<SwapEffectLimits> {
    let sold_lamports = if from_coin == "sol" { amount_native } else { 0 };
    let input_token = if from_coin == "sol" {
        None
    } else {
        Some((jupiter_mint_bytes_for_coin(from_coin)?, amount_native))
    };
    let min_output = if to_coin == "sol" {
        MinOutput::Lamports(min_out)
    } else {
        MinOutput::Token(jupiter_mint_bytes_for_coin(to_coin)?, min_out)
    };
    Ok(SwapEffectLimits {
        user: owner,
        max_lamport_loss: sold_lamports
            .checked_add(JUPITER_SWAP_FEE_BUDGET_LAMPORTS)
            .context("montant + budget de frais dépasse la capacité représentable")?,
        input_token,
        min_output,
    })
}

/// View of an SPL token account (Token or Token-2022 program). The same base layout
/// for both: mint 0..32, owner 32..64, amount 64..72, delegate COption 72..108,
/// close authority COption 129..165.
struct TokenAccountView {
    mint: [u8; 32],
    owner: [u8; 32],
    amount: u64,
    delegate: [u8; 36],
    close_authority: [u8; 36],
}

fn parse_token_account(state: &sol_rpc::AccountState) -> Option<TokenAccountView> {
    if state.owner != TOKEN_PROGRAM_ID && state.owner != TOKEN_2022_PROGRAM_ID {
        return None;
    }
    // Token account: exactly 165 bytes, or more with Token-2022 extensions, in which
    // case byte 165 is 2 (AccountType::Account; a Token-2022 mint with extensions also
    // exceeds 165 bytes but has 1).
    let data = &state.data;
    if !(data.len() == 165 || (data.len() > 165 && data[165] == 2)) {
        return None;
    }
    Some(TokenAccountView {
        mint: data[0..32].try_into().ok()?,
        owner: data[32..64].try_into().ok()?,
        amount: u64::from_le_bytes(data[64..72].try_into().ok()?),
        delegate: data[72..108].try_into().ok()?,
        close_authority: data[129..165].try_into().ok()?,
    })
}

/// Balance sheet of a simulated transaction on the user's accounts: lamports (main
/// account + rent of their token accounts, wSOL included) and tokens per mint
/// (excluding wSOL, already counted in lamports), before and after.
pub(crate) struct UserEffects {
    pub lamports_pre: u128,
    pub lamports_post: u128,
    pub tokens_pre: std::collections::HashMap<[u8; 32], u128>,
    pub tokens_post: std::collections::HashMap<[u8; 32], u128>,
}

/// Effects of a transaction on `user`'s accounts, from the state of their writable
/// accounts before (`pre`) and after simulation (`post`), aligned with `addresses`,
/// with the STRUCTURAL REFUSALS that do not depend on what the transaction is
/// supposed to do (Assign, delegate, owner change, account handed over,
/// non-standard account). Shared by the Jupiter swap (`verify_swap_effects`, which
/// also bounds losses and gains) and WalletConnect dApp transactions (which SHOW
/// this balance sheet). Pure function: testable against every type of attack
/// without a network.
pub(crate) fn user_effects(
    addresses: &[String],
    pre: &[Option<sol_rpc::AccountState>],
    post: &[Option<sol_rpc::AccountState>],
    user: &[u8; 32],
) -> Result<UserEffects> {
    anyhow::ensure!(
        addresses.len() == pre.len() && pre.len() == post.len(),
        "états de comptes désalignés"
    );
    let user_b58 = bs58::encode(user).into_string();
    let native_mint: [u8; 32] = bs58::decode(jupiter_rpc::SOL_MINT)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("mint SOL mal formé (bug de compilation)")?;

    let mut lamports_pre: u128 = 0;
    let mut lamports_post: u128 = 0;
    let mut tokens_pre: std::collections::HashMap<[u8; 32], u128> =
        std::collections::HashMap::new();
    let mut tokens_post: std::collections::HashMap<[u8; 32], u128> =
        std::collections::HashMap::new();
    let mut main_seen = false;

    // An account at 0 lamports no longer exists (purged at the end of the
    // transaction): the simulation returns a CLOSED account as "0 lamports, system
    // program, 0 bytes", NOT as `null`. Seen on a real mainnet swap (a wSOL account
    // closed by Jupiter's unwrapping), which wrongly triggered the "SetAuthority"
    // refusal. Normalized to "absent" here, on both sides.
    let live = |s: &Option<sol_rpc::AccountState>| s.clone().filter(|s| s.lamports > 0);
    let pre: Vec<_> = pre.iter().map(live).collect();
    let post: Vec<_> = post.iter().map(live).collect();

    for i in 0..addresses.len() {
        if addresses[i] == user_b58 {
            main_seen = true;
            lamports_pre += pre[i].as_ref().map_or(0, |s| u128::from(s.lamports));
            if let Some(p) = &post[i] {
                anyhow::ensure!(
                    p.owner == SYSTEM_PROGRAM_ID,
                    "la transaction changerait le programme propriétaire de votre compte principal (Assign) — refus de signer"
                );
                anyhow::ensure!(p.data.is_empty(), "la transaction allouerait des données sur votre compte principal — refus de signer");
                lamports_post += u128::from(p.lamports);
            }
            continue;
        }

        let pre_token = pre[i].as_ref().and_then(parse_token_account);
        let post_token = post[i].as_ref().and_then(parse_token_account);
        let pre_is_user = pre_token.as_ref().is_some_and(|t| t.owner == *user);
        let post_is_user = post_token.as_ref().is_some_and(|t| t.owner == *user);

        if let (true, Some(before)) = (pre_is_user, &pre_token) {
            lamports_pre += pre[i].as_ref().map_or(0, |s| u128::from(s.lamports));
            if before.mint != native_mint {
                *tokens_pre.entry(before.mint).or_default() += u128::from(before.amount);
            }
            match (&post[i], &post_token) {
                // Closed account: its value must reappear elsewhere with the user, which the
                // global lamports check verifies.
                (None, _) => {}
                (Some(p), Some(after)) if after.owner == *user => {
                    anyhow::ensure!(after.mint == before.mint, "un de vos comptes de jetons changerait de jeton — refus de signer");
                    anyhow::ensure!(
                        after.delegate == before.delegate,
                        "la transaction ajouterait un délégué sur un de vos comptes de jetons (Approve : droit de le vider plus tard) — refus de signer"
                    );
                    anyhow::ensure!(
                        after.close_authority == before.close_authority,
                        "la transaction changerait l'autorité de fermeture d'un de vos comptes de jetons — refus de signer"
                    );
                    lamports_post += u128::from(p.lamports);
                    if after.mint != native_mint {
                        *tokens_post.entry(after.mint).or_default() += u128::from(after.amount);
                    }
                }
                _ => anyhow::bail!(
                    "la transaction transférerait la propriété d'un de vos comptes de jetons (SetAuthority) — refus de signer"
                ),
            }
        } else if let (true, Some(after), Some(p)) = (post_is_user, &post_token, &post[i]) {
            // An account that becomes the user's: only the "created by this transaction" case
            // (e.g. the destination ATA) is legitimate. An EXISTING account handed to the user
            // could carry a trap (a delegate already set, funds deposited later and then
            // drained).
            anyhow::ensure!(
                pre[i].is_none(),
                "la transaction vous céderait un compte de jetons existant — refus de signer"
            );
            // And only at that token's STANDARD address (associated account). Found in audit
            // round 22: since the user signs the transaction, a compromised API could create a
            // token account at an arbitrary address (CreateAccountWithSeed with the user as
            // the base) and deliver the swap output there. Nothing stolen, but funds the app
            // never shows or spends (it only reads the associated account): for the user, a
            // swap that "returned nothing".
            //
            // Program of the created account (Token, or Token-2022 for xStocks): it is part of
            // the associated account's address.
            let program = if p.owner == TOKEN_2022_PROGRAM_ID {
                sol_spl::token_2022_program_id()
            } else {
                sol_spl::token_program_id()
            };
            let canonical = bs58::encode(sol_spl::find_associated_token_address_for(
                user,
                &after.mint,
                &program,
            ))
            .into_string();
            anyhow::ensure!(
                addresses[i] == canonical,
                "la transaction livrerait vos jetons sur un compte non standard, invisible dans l'app — refus de signer"
            );
            let none = [0u8; 36];
            anyhow::ensure!(
                after.delegate[..4] == none[..4] && after.close_authority[..4] == none[..4],
                "un compte de jetons créé pour vous aurait déjà un délégué ou une autorité de fermeture — refus de signer"
            );
            lamports_post += u128::from(p.lamports);
            if after.mint != native_mint {
                *tokens_post.entry(after.mint).or_default() += u128::from(after.amount);
            }
        }
    }

    anyhow::ensure!(
        main_seen,
        "votre compte principal n'apparaît pas dans la transaction (payeur de frais attendu)"
    );
    Ok(UserEffects {
        lamports_pre,
        lamports_post,
        tokens_pre,
        tokens_post,
    })
}

/// Checks the effects of a Jupiter swap: the structural refusals of `user_effects`,
/// then a loss bounded to the amount sold + the fee budget, and a minimum output.
fn verify_swap_effects(
    addresses: &[String],
    pre: &[Option<sol_rpc::AccountState>],
    post: &[Option<sol_rpc::AccountState>],
    limits: &SwapEffectLimits,
) -> Result<()> {
    let UserEffects {
        lamports_pre,
        lamports_post,
        tokens_pre,
        tokens_post,
    } = user_effects(addresses, pre, post, &limits.user)?;
    anyhow::ensure!(
        lamports_post + u128::from(limits.max_lamport_loss) >= lamports_pre,
        "la transaction vous coûterait {} lamports, au-delà du montant échangé + frais autorisés ({} lamports) — refus de signer",
        lamports_pre.saturating_sub(lamports_post),
        limits.max_lamport_loss
    );
    match limits.min_output {
        MinOutput::Lamports(min) => anyhow::ensure!(
            // Network fees are paid in SOL: they can reduce the net gain by at most the fee
            // budget.
            lamports_post + u128::from(JUPITER_SWAP_FEE_BUDGET_LAMPORTS) >= lamports_pre + u128::from(min),
            "la transaction vous rendrait moins de SOL que le minimum annoncé ({min} lamports) — refus de signer"
        ),
        MinOutput::Token(mint, min) => {
            let before = tokens_pre.get(&mint).copied().unwrap_or(0);
            let after = tokens_post.get(&mint).copied().unwrap_or(0);
            anyhow::ensure!(
                after >= before + u128::from(min),
                "la transaction vous rendrait {} unité(s) de jeton, moins que le minimum annoncé ({min}) — refus de signer",
                after.saturating_sub(before)
            );
        }
        MinOutput::Nothing => {}
    }
    for (mint, before) in &tokens_pre {
        let allowed = match limits.input_token {
            Some((input_mint, max)) if &input_mint == mint => u128::from(max),
            _ => 0,
        };
        let after = tokens_post.get(mint).copied().unwrap_or(0);
        anyhow::ensure!(
            after + allowed >= *before,
            "la transaction ferait sortir {} unité(s) du jeton {} au-delà de ce qui a été confirmé — refus de signer",
            before.saturating_sub(after),
            bs58::encode(mint).into_string()
        );
    }
    Ok(())
}

/// Simulation refused by Jupiter for price slippage (6001,
/// `SlippageToleranceExceeded`): the price moved between the quote and the
/// simulation. Nothing has been signed; a fresh quote may succeed.
const SWAP_PRICE_MOVED: &str = "le prix a bougé pendant la préparation de l'échange (au-delà du glissement toléré) — rien n'a été envoyé, relancez l'échange";

fn is_jupiter_slippage(err: &serde_json::Value, logs: &str) -> bool {
    err.to_string().contains("\"Custom\":6001")
        && logs.contains(
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 failed: custom program error: 0x1771",
        )
}

/// Resolves a transaction's writable accounts (static keys + lookup tables read
/// ON-CHAIN, never supplied by Jupiter), fetches their state before, simulates with
/// their state after, then calls `verify_swap_effects`.
fn check_swap_effects(rpc: &sol_rpc::SolRpc, tx: &[u8], limits: &SwapEffectLimits) -> Result<()> {
    let addresses = resolve_writable_addresses(rpc, tx)?;
    let pre = rpc.multiple_accounts(&addresses)?;
    match rpc.simulate_with_account_states(tx, &addresses)? {
        sol_rpc::SimulationOutcome::Failed { err, logs } if is_jupiter_slippage(&err, &logs) => {
            Err(anyhow::anyhow!(SWAP_PRICE_MOVED))
        }
        sol_rpc::SimulationOutcome::Failed { err, logs } => Err(rpc
            .explain_simulation_failure(&err, &logs)
            .unwrap_or_else(|| {
                anyhow::anyhow!("échec de simulation de l'échange ({err}) :\n{logs}")
            })),
        sol_rpc::SimulationOutcome::Succeeded { post_states } => {
            verify_swap_effects(&addresses, &pre, &post_states, limits)
        }
    }
}

pub(crate) fn resolve_writable_addresses(rpc: &sol_rpc::SolRpc, tx: &[u8]) -> Result<Vec<String>> {
    let message = jupiter_rpc::transaction_message(tx)?;
    let writable = jupiter_rpc::message_writable_accounts(message)?;
    anyhow::ensure!(
        !writable.advances_durable_nonce,
        "la transaction utilise un nonce durable (valide indéfiniment, rejouable plus tard à un autre cours) — refus de signer"
    );
    let mut addresses: Vec<String> = writable
        .static_keys
        .iter()
        .map(|k| bs58::encode(k).into_string())
        .collect();

    if !writable.lookups.is_empty() {
        let tables: Vec<String> = writable
            .lookups
            .iter()
            .map(|(t, _)| bs58::encode(t).into_string())
            .collect();
        let table_states = rpc.multiple_accounts(&tables)?;
        for ((table, indexes), state) in writable.lookups.iter().zip(table_states) {
            let table_b58 = bs58::encode(table).into_string();
            let state = state.with_context(|| {
                format!("table de correspondance {table_b58} introuvable on-chain")
            })?;
            anyhow::ensure!(
                state.owner == ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                "le compte {table_b58} n'est pas une table de correspondance d'adresses — refus de signer"
            );
            for &index in indexes {
                let start = LOOKUP_TABLE_META_SIZE + 32 * index as usize;
                let key = state
                    .data
                    .get(start..start + 32)
                    .with_context(|| format!("index {index} hors de la table {table_b58}"))?;
                addresses.push(bs58::encode(key).into_string());
            }
        }
    }
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

/// Gets a THORChain swap quote (read-only, no secrets involved); see
/// `thorchain_rpc` for the full context. `amount` in the SOURCE asset's main unit
/// (e.g. "0.5" for 0.5 SOL), as everywhere else in this API. `destination`: the
/// user's address on the DESTINATION chain (never the developer's;
/// `thorchain_rpc::AFFILIATE_ADDRESS` is added automatically by
/// `thorchain_rpc::quote_swap`).
pub fn get_swap_quote(
    protocol: &thorchain_rpc::CrossChain,
    from: &thorchain_rpc::ThorAsset,
    to: &thorchain_rpc::ThorAsset,
    amount: &str,
    destination: &str,
) -> Result<thorchain_rpc::SwapQuote> {
    anyhow::ensure!(
        !std::ptr::eq(from, to),
        "échange d'une crypto vers elle-même"
    );
    protocol.quote_swap(
        from.asset,
        to.asset,
        swap_amount_1e8(from, amount)?,
        destination,
    )
}

fn swap_amount_1e8(from: &thorchain_rpc::ThorAsset, amount: &str) -> Result<u64> {
    let amount_native = tokens::parse_amount(amount, from.decimals as u8)?;
    thorchain_rpc::to_thorchain_amount(amount_native, from.decimals)
}

/// Asset of one of the app's cryptos (`coin`) on `network` for `protocol`
/// (THORChain or Maya).
pub fn cross_chain_asset(
    protocol: &thorchain_rpc::CrossChain,
    coin: &str,
    network: &str,
) -> Result<&'static thorchain_rpc::ThorAsset> {
    protocol.asset(coin, network).ok_or_else(|| {
        anyhow::anyhow!(
            "échange {} non disponible pour cette crypto sur ce réseau",
            protocol.name
        )
    })
}

/// Amount of a swap in its canonical form (shown AND signed, see
/// `canonical_amount`), using the source asset's decimals.
pub fn canonical_swap_amount(from: &thorchain_rpc::ThorAsset, amount: &str) -> Result<String> {
    let decimals = from.decimals as u8;
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, decimals)?,
        decimals,
    ))
}

/// Requests a quote again JUST BEFORE sending (never a stale vault, see the docs of
/// `thorchain_rpc::SwapQuote`) while guaranteeing that what goes out is what was
/// SHOWN in the confirmation dialog (`shown`): same vault address, same router, and
/// a minimum output of at least 99% of the expected output shown; otherwise refused
/// (the user restarts and sees the new values). This resolves the tension left by
/// self-review round 18 between "always a fresh quote" and "sign what you see":
/// rereading the quote after confirmation could pay a vault/router that was never
/// shown, or deliver less than the announced output if the rate had moved in the
/// meantime.
pub fn refresh_swap_quote_matching(
    protocol: &thorchain_rpc::CrossChain,
    from: &thorchain_rpc::ThorAsset,
    to: &thorchain_rpc::ThorAsset,
    amount: &str,
    destination: &str,
    shown: &thorchain_rpc::SwapQuote,
) -> Result<thorchain_rpc::SwapQuote> {
    // Same affiliate as the quote shown (fees announced in the dialog).
    let fresh = protocol.quote_swap_as(
        from.asset,
        to.asset,
        swap_amount_1e8(from, amount)?,
        destination,
        shown.affiliate.as_deref(),
    )?;
    ensure_quote_matches_shown(protocol, &fresh, shown, to.asset, destination)?;
    Ok(fresh)
}

fn ensure_quote_matches_shown(
    protocol: &thorchain_rpc::CrossChain,
    fresh: &thorchain_rpc::SwapQuote,
    shown: &thorchain_rpc::SwapQuote,
    to_asset: &str,
    destination: &str,
) -> Result<()> {
    anyhow::ensure!(
        fresh.inbound_address == shown.inbound_address && fresh.router == shown.router,
        "l'adresse de dépôt {} a changé pendant la confirmation — relancez l'échange pour voir la nouvelle",
        protocol.name
    );
    protocol
        .verify_memo(&fresh.memo, shown.affiliate.as_deref(), to_asset, destination, shown.expected_amount_out)
        .context("le cours a bougé pendant la confirmation (sortie minimale sous 99 % du montant affiché) — relancez l'échange")
}

// --- Affiliate name (THORName / MAYAName) -------------------------------------
//
// Reserved for the developer's wallet: the one whose THOR address (key
// m/44'/931'/0'/0/0, same hash160 on Maya) IS the app's affiliate address.
// Registration through a native deposit signed here (see `native_deposit`).

/// A name's protocol: native network and swap protocol.
pub fn affiliate_name_chains(
    chain: &str,
) -> Result<(
    &'static native_deposit::NativeChain,
    &'static thorchain_rpc::CrossChain,
)> {
    match chain {
        "thorchain" => Ok((&native_deposit::THORCHAIN, &thorchain_rpc::THORCHAIN)),
        "maya" => Ok((&native_deposit::MAYA, &thorchain_rpc::MAYA)),
        other => anyhow::bail!("réseau de nom inconnu : {other}"),
    }
}

/// Affiliate name on a protocol, as seen from the app.
#[derive(Clone, Debug, PartialEq)]
pub enum NameState {
    /// Free (or expired): registration possible.
    Free,
    /// Registered by the affiliate address; years remaining; alias correct.
    Ours {
        years_left: f64,
        points_to_affiliate: bool,
    },
    /// Registered by someone else.
    Taken,
}

pub struct NameStatus {
    pub name: &'static str,
    pub state: NameState,
    /// Affiliate address on this network (pays for the registration, receives the
    /// fees).
    pub address: &'static str,
    pub balance: u128,
    pub decimals: u32,
    /// Proposed deposit amount: registration (one year included) + one year, or one
    /// more year if the name is already ours.
    pub deposit: u128,
    pub network_fee: u128,
}

/// Registration (one year included) and one extra year, from the protocol's
/// constants (taken from real registrations: 10 RUNE or 10 CACAO, then ~1.05 per
/// year).
fn name_costs(native: &native_deposit::NativeChain) -> Result<(u128, u128)> {
    let register = native_deposit::constant(native, "TNSRegisterFee")?;
    let per_block = native_deposit::constant(native, "TNSFeePerBlock")?;
    Ok((
        u128::from(register),
        u128::from(per_block) * u128::from(thorchain_rpc::NAME_BLOCKS_PER_YEAR),
    ))
}

fn name_state(protocol: &thorchain_rpc::CrossChain, name: &str) -> Result<NameState> {
    Ok(match protocol.name_record(name)? {
        None => NameState::Free,
        Some(record) if record.expired() => NameState::Free,
        Some(record) if record.owner == protocol.affiliate_address => NameState::Ours {
            years_left: (record.expire_height - record.current_height) as f64
                / thorchain_rpc::NAME_BLOCKS_PER_YEAR as f64,
            points_to_affiliate: record.points_to_affiliate,
        },
        Some(_) => NameState::Taken,
    })
}

/// Deposit to make for state `state` (`None`: name taken by someone else).
fn name_deposit(state: &NameState, register: u128, year: u128) -> Option<u128> {
    match state {
        NameState::Free => Some(register + year),
        NameState::Ours { .. } => Some(year),
        NameState::Taken => None,
    }
}

/// State of the affiliate name on `chain` ("thorchain", "maya"): read-only, public
/// data.
pub fn affiliate_name_status(chain: &str) -> Result<NameStatus> {
    let (native, protocol) = affiliate_name_chains(chain)?;
    let name = protocol
        .affiliate_name
        .context("aucun nom d'affiliation prévu sur ce réseau")?;
    let state = name_state(protocol, name)?;
    let (register, year) = name_costs(native)?;
    Ok(NameStatus {
        name,
        deposit: name_deposit(&state, register, year).unwrap_or(0),
        state,
        address: protocol.affiliate_address,
        balance: native_deposit::balance(native, protocol.affiliate_address)?,
        decimals: native.decimals,
        network_fee: native_deposit::network_fee(native)?,
    })
}

/// Registers (or extends by a year) the affiliate name on `chain`, signed by the
/// main profile's THOR key; refused if it is not the app's affiliate address.
/// `shown_deposit`: the amount shown in the confirmation dialog, never exceeded.
/// Returns the transaction identifier.
pub fn register_affiliate_name(
    data_dir: &Path,
    device_password: &str,
    chain: &str,
    shown_deposit: u128,
) -> Result<String> {
    let (native, protocol) = affiliate_name_chains(chain)?;
    let name = protocol
        .affiliate_name
        .context("aucun nom d'affiliation prévu sur ce réseau")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_thor_key(&seed, 0)?;
    let address = bech32::encode(
        native.hrp,
        bech32::ToBase32::to_base32(&hash160),
        bech32::Variant::Bech32,
    )
    .context("encodage bech32 impossible")?;
    anyhow::ensure!(
        address == protocol.affiliate_address,
        "ce portefeuille n'est pas celui qui reçoit les frais d'affiliation de l'app — inscription réservée à ce dernier"
    );
    let (register, year) = name_costs(native)?;
    let state = name_state(protocol, name)?;
    let deposit = name_deposit(&state, register, year).with_context(|| {
        format!(
            "le nom « {name} » appartient déjà à quelqu'un d'autre sur {}",
            native.name
        )
    })?;
    anyhow::ensure!(
        deposit <= shown_deposit,
        "le coût du nom a changé depuis la confirmation — relancez l'inscription"
    );
    let fee = native_deposit::network_fee(native)?;
    let balance = native_deposit::balance(native, &address)?;
    anyhow::ensure!(
        balance >= deposit + fee,
        "solde insuffisant sur l'adresse d'affiliation {} : {} disponibles, {} nécessaires (dépôt + frais réseau)",
        native.name,
        tokens::format_amount(balance, native.decimals as u8),
        tokens::format_amount(deposit + fee, native.decimals as u8)
    );
    let (account_number, sequence) = native_deposit::account(native, &address)?
        .context("adresse d'affiliation jamais approvisionnée sur ce réseau")?;
    // Native chain alias pointing to the affiliate address; owner: the signer (that
    // same address).
    let memo = format!("~:{name}:{}:{address}", protocol.native_chain());
    let tx =
        native_deposit::signed_deposit(native, &key, deposit, &memo, account_number, sequence)?;
    native_deposit::broadcast(native, &tx)
}

/// Sends a THORChain swap from Solana: builds a SOL transfer to the quote's vault
/// address, plus a Memo instruction (SPL Memo Program) carrying the THORChain memo,
/// in the SAME transaction, so THORChain links the two atomically. `quote` must
/// have been obtained just before this call (the vault address is never cached, see
/// the docs of `thorchain_rpc::SwapQuote`).
pub fn send_swap_sol(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    quote: &thorchain_rpc::SwapQuote,
    amount_sol: &str,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let amount_lamports = wallet_flow::parse_sol_to_lamports(amount_sol)?;

    let vault_bytes = bs58::decode(quote.inbound_address.trim())
        .into_vec()
        .context("adresse de vault THORChain invalide (base58 attendu)")?;
    let vault: [u8; 32] = vault_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let owner_address = bs58::encode(owner).into_string();
    let (balance, recent_blockhash) = std::thread::scope(|scope| {
        let balance_handle = scope.spawn(|| rpc.balance_lamports(&owner_address));
        let blockhash_handle = scope.spawn(|| rpc.latest_blockhash());
        (
            balance_handle
                .join()
                .expect("le thread balance ne doit pas paniquer"),
            blockhash_handle
                .join()
                .expect("le thread blockhash ne doit pas paniquer"),
        )
    });
    let balance = balance?;
    let recent_blockhash = recent_blockhash?;

    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let total_needed = amount_lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} lamports disponibles, {amount_lamports} lamports + {SOL_FEE_LAMPORTS} lamports de frais requis"
    );

    let transfer_ix = sol_tx::transfer_instruction(&owner, &vault, amount_lamports);
    let memo_ix = sol_tx::Instruction {
        program_id: sol_tx::memo_program_id(),
        accounts: vec![],
        data: quote.memo.as_bytes().to_vec(),
    };
    let raw_tx = sol_tx::build_and_sign_transaction(
        &signing_key,
        &owner,
        &[transfer_ix, memo_ix],
        &recent_blockhash,
    );
    rpc.send_transaction(&raw_tx)
}

/// Unlocks the vault, signs and broadcasts a USDC transfer (mainnet only, see
/// sol_spl.rs). This is an SPL token, not native SOL: two instructions in a single
/// transaction (create the recipient's Associated Token Account if needed, then
/// transfer), see sol_spl.rs. Checks the USDC balance AND the SOL balance (fees +
/// any rent) BEFORE signing or broadcasting anything, the same "fail early and
/// clearly" principle as send_sol/send_btc/send_evm.
pub fn send_usdc(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    to: &str,
    amount_usdc: &str,
    profile_index: u32,
) -> Result<String> {
    let amount = wallet_flow::parse_usdc_to_micros(amount_usdc)?;
    send_spl(
        data_dir,
        device_password,
        network,
        &sol_spl::usdc_mint_mainnet(),
        sol_spl::USDC_DECIMALS,
        "USDC",
        to,
        amount,
        profile_index,
    )
}

/// Transfer of an SPL token `mint` (`amount` in units, `decimals` of the mint); see
/// `send_usdc`: the recipient's token account is created if needed, and the token
/// and SOL balances (fees + rent) are checked before signing.
#[allow(clippy::too_many_arguments)]
pub fn send_spl(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    mint: &[u8; 32],
    decimals: u8,
    symbol: &str,
    to: &str,
    amount: u64,
    profile_index: u32,
) -> Result<String> {
    check_solana_recipient(to, network)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();

    let to_bytes = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let to_owner: [u8; 32] = to_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let mint = *mint;
    let source_ata = sol_spl::find_associated_token_address(&owner, &mint);
    let dest_ata = sol_spl::find_associated_token_address(&to_owner, &mint);
    let source_ata_b58 = bs58::encode(source_ata).into_string();
    let dest_ata_b58 = bs58::encode(dest_ata).into_string();
    let owner_b58 = bs58::encode(owner).into_string();

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    // 4 independent RPC reads in parallel (same pattern as send_sol/send_evm): SOL
    // balance (fees), USDC balance (source ATA), recent blockhash, and whether the
    // recipient's ATA exists (to know whether creating it will charge rent).
    let (sol_balance, usdc_balance, recent_blockhash, dest_ata_exists) =
        std::thread::scope(|scope| {
            let sol_handle = scope.spawn(|| rpc.balance_lamports(&owner_b58));
            let usdc_handle = scope.spawn(|| rpc.token_account_balance(&source_ata_b58));
            let blockhash_handle = scope.spawn(|| rpc.latest_blockhash());
            let dest_handle = scope.spawn(|| rpc.account_exists(&dest_ata_b58));
            (
                sol_handle
                    .join()
                    .expect("le thread solde SOL ne doit pas paniquer"),
                usdc_handle
                    .join()
                    .expect("le thread solde USDC ne doit pas paniquer"),
                blockhash_handle
                    .join()
                    .expect("le thread blockhash ne doit pas paniquer"),
                dest_handle
                    .join()
                    .expect("le thread existence ATA ne doit pas paniquer"),
            )
        });
    let sol_balance = sol_balance?;
    let recent_blockhash = recent_blockhash?;
    let dest_ata_exists = dest_ata_exists?;

    // Missing source ATA == USDC balance necessarily zero (no USDC ever received):
    // fail clearly rather than build a transaction that would fail on-chain anyway.
    let usdc_balance = usdc_balance?.ok_or_else(|| {
        anyhow::anyhow!("aucun compte {symbol} trouvé pour cette adresse (solde 0)")
    })?;
    anyhow::ensure!(
        amount <= usdc_balance,
        "fonds {symbol} insuffisants : {usdc_balance} disponibles (unité 10^-{decimals} {symbol}), {amount} requis"
    );

    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let rent_lamports = if dest_ata_exists {
        0
    } else {
        // Standard size of an SPL Token account (165 bytes), checked against the real
        // network; see sol_spl.rs. Queried live rather than hard-coded: the rent amount is
        // a network parameter that changes.
        rpc.minimum_rent_exempt_balance(165)?
    };
    let total_sol_needed = SOL_FEE_LAMPORTS
        .checked_add(rent_lamports)
        .context("frais + rent dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_sol_needed <= sol_balance,
        "SOL insuffisant pour les frais{} : {sol_balance} lamports disponibles, {total_sol_needed} lamports requis",
        if dest_ata_exists { String::new() } else { " + création du compte de jetons du destinataire".to_string() }
    );

    let create_ata_ix =
        sol_spl::create_ata_idempotent_instruction(&owner, &to_owner, &mint, &dest_ata);
    let transfer_ix = sol_spl::transfer_checked_instruction(
        &source_ata,
        &mint,
        &dest_ata,
        &owner,
        amount,
        decimals,
    );
    let raw_tx = sol_tx::build_and_sign_transaction(
        &signing_key,
        &owner,
        &[create_ata_ix, transfer_ix],
        &recent_blockhash,
    );
    rpc.send_transaction(&raw_tx)
}

// --- Registry tokens (see tokens.rs) -------------------------------------------
//
// The UI only provides the token identifier and the network: contract, mint and
// decimals ALWAYS come from the registry.

fn abi_word_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn abi_word_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Calldata for an ERC-20 `transfer(to, amount)` call.
pub fn erc20_transfer_data(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&abi_word_address(to));
    data.extend_from_slice(&abi_word_u128(amount));
    data
}

/// Calldata for an ERC-20 `approve(spender, amount)` call.
pub fn erc20_approve_data(spender: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = vec![0x09, 0x5e, 0xa7, 0xb3];
    data.extend_from_slice(&abi_word_address(spender));
    data.extend_from_slice(&abi_word_u128(amount));
    data
}

/// Amount `spender` can still pull from `owner`: `allowance(owner, spender)`.
pub fn get_erc20_allowance(
    network: &wallet_flow::EvmNetwork,
    contract: &str,
    owner: &[u8; 20],
    spender: &[u8; 20],
) -> Result<u128> {
    let mut data = vec![0xdd, 0x62, 0xed, 0x3e];
    data.extend_from_slice(&abi_word_address(owner));
    data.extend_from_slice(&abi_word_address(spender));
    let answer = eth_rpc::EthRpc::new(network.rpc).call_contract(
        &derivation::format_address(owner),
        contract,
        0,
        &data,
    )?;
    anyhow::ensure!(answer.len() == 32, "réponse du contrat de jeton inattendue");
    // An "unlimited" approval (2^256 − 1) granted elsewhere: capped at u128::MAX.
    if answer[..16].iter().any(|&b| b != 0) {
        return Ok(u128::MAX);
    }
    Ok(u128::from_be_bytes(
        answer[16..].try_into().expect("16 octets"),
    ))
}

/// ERC-20 balance of `owner` (token units): `balanceOf(owner)`.
pub fn get_erc20_balance(
    network: &wallet_flow::EvmNetwork,
    contract: &str,
    owner: &str,
) -> Result<u128> {
    let owner_bytes = wallet_flow::parse_evm_address(owner)?;
    let mut data = vec![0x70, 0xa0, 0x82, 0x31];
    data.extend_from_slice(&abi_word_address(&owner_bytes));
    let answer = eth_rpc::EthRpc::new(network.rpc).call_contract(owner, contract, 0, &data)?;
    anyhow::ensure!(answer.len() == 32, "réponse du contrat de jeton inattendue");
    anyhow::ensure!(
        answer[..16].iter().all(|&b| b == 0),
        "solde de jeton hors limites"
    );
    Ok(u128::from_be_bytes(
        answer[16..].try_into().expect("16 octets"),
    ))
}

fn registered_token(
    token_id: &str,
    network: &str,
) -> Result<(&'static tokens::Token, &'static tokens::Deployment)> {
    tokens::find(token_id, network)
        .ok_or_else(|| anyhow::anyhow!("jeton non pris en charge sur ce réseau"))
}

fn token_evm_network(network: &str) -> Result<&'static wallet_flow::EvmNetwork> {
    wallet_flow::evm_network(network)
        .ok_or_else(|| anyhow::anyhow!("réseau EVM inconnu : {network}"))
}

/// Balance of a registry token on `network`: (units, decimals).
pub fn get_token_balance(token_id: &str, network: &str, owner: &str) -> Result<(u128, u8)> {
    let (_, deployment) = registered_token(token_id, network)?;
    let units = match deployment.kind {
        tokens::TokenKind::Erc20 { contract } => {
            get_erc20_balance(token_evm_network(network)?, contract, owner)?
        }
        tokens::TokenKind::Spl { mint } => {
            let mint = sol_spl_mint(mint)?;
            u128::from(get_spl_balance(owner, &mint, &wallet_flow::SOLANA_MAINNET)?)
        }
        tokens::TokenKind::Spl2022 { mint } => scaled_token_balance(owner, mint)?,
        tokens::TokenKind::Trc20 { contract } => tron::trc20_balance(owner, contract)?,
    };
    Ok((units, deployment.decimals))
}

/// Mint (32 bytes) of a registry SPL token.
pub fn registered_spl_mint(token_id: &str) -> Result<[u8; 32]> {
    let (_, deployment) = registered_token(token_id, "sol_mainnet")?;
    let tokens::TokenKind::Spl { mint } = deployment.kind else {
        anyhow::bail!("jeton SPL attendu")
    };
    sol_spl_mint(mint)
}

fn sol_spl_mint(mint: &str) -> Result<[u8; 32]> {
    bs58::decode(mint)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("mint invalide"))
}

/// Canonical amount of a token (the form shown AND signed).
pub fn canonical_token_amount(token_id: &str, network: &str, amount: &str) -> Result<String> {
    let (_, deployment) = registered_token(token_id, network)?;
    Ok(tokens::format_amount(
        tokens::parse_amount(amount, deployment.decimals)?,
        deployment.decimals,
    ))
}

/// Fees for an ERC-20 transfer, shown in the confirmation dialog and then signed as
/// is (the call's gas estimated by the node, see `evm_fee_for_confirmation`). A
/// transfer TO a token contract is refused (funds lost forever).
pub fn erc20_fee_for_confirmation(
    token_id: &str,
    network: &str,
    from: &str,
    to: &str,
    amount: &str,
) -> Result<EvmFee> {
    let (_, deployment) = registered_token(token_id, network)?;
    let tokens::TokenKind::Erc20 { contract } = deployment.kind else {
        anyhow::bail!("jeton ERC-20 attendu")
    };
    anyhow::ensure!(
        !tokens::is_known_contract(to),
        "destinataire refusé : c'est le contrat d'un jeton, les fonds y seraient perdus à jamais"
    );
    let units = tokens::parse_amount(amount, deployment.decimals)?;
    let data = erc20_transfer_data(&wallet_flow::parse_evm_address(to)?, units);
    evm_fee_for_confirmation(
        token_evm_network(network)?,
        &wallet_flow::parse_evm_address(from)?,
        &wallet_flow::parse_evm_address(contract)?,
        0,
        &data,
    )
    .map_err(|e| {
        // Call refused by the contract during the estimate: the common case is an
        // insufficient token balance. A classic refusal ("revert") or an old contract that
        // stops on an invalid opcode (USDT, seen with a zero balance).
        let message = format!("{e:#}");
        if message.contains("revert") || message.contains("invalid opcode") {
            anyhow::anyhow!(
                "solde de jeton insuffisant, ou transfert refusé par le contrat du jeton"
            )
        } else {
            e
        }
    })
}

/// Unlocks the vault, signs and broadcasts an ERC-20 transfer of a registry token.
/// `fee`: the one shown in the confirmation dialog, used as is. Checks before
/// signing: the node's network, the token balance, the native balance for fees.
#[allow(clippy::too_many_arguments)]
pub fn send_erc20(
    data_dir: &Path,
    device_password: &str,
    token_id: &str,
    network: &str,
    to: &str,
    amount: &str,
    fee: EvmFee,
    profile_index: u32,
) -> Result<String> {
    let (token, deployment) = registered_token(token_id, network)?;
    let tokens::TokenKind::Erc20 { contract } = deployment.kind else {
        anyhow::bail!("jeton ERC-20 attendu")
    };
    let net = token_evm_network(network)?;
    check_evm_gas_price(net, fee.gas_price)?;
    anyhow::ensure!(
        !tokens::is_known_contract(to),
        "destinataire refusé : c'est le contrat d'un jeton, les fonds y seraient perdus à jamais"
    );
    let to_bytes = wallet_flow::parse_evm_address(to)?;
    let contract_bytes = wallet_flow::parse_evm_address(contract)?;
    let units = tokens::parse_amount(amount, deployment.decimals)?;
    let data = erc20_transfer_data(&to_bytes, units);
    anyhow::ensure!(
        fee.gas_limit >= eth_tx::intrinsic_gas(&data),
        "limite de gas trop basse pour ce transfert"
    );

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    let rpc = eth_rpc::EthRpc::new(net.rpc);
    let (nonce, chain_id, native, token_balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let native = scope.spawn(|| rpc.balance(&address_str));
        let token_balance = scope.spawn(|| get_erc20_balance(net, contract, &address_str));
        (
            nonce.join().expect("le thread nonce ne doit pas paniquer"),
            chain_id
                .join()
                .expect("le thread chain_id ne doit pas paniquer"),
            native.join().expect("le thread solde ne doit pas paniquer"),
            token_balance
                .join()
                .expect("le thread solde de jeton ne doit pas paniquer"),
        )
    });
    let (nonce, chain_id, native, token_balance) = (nonce?, chain_id?, native?, token_balance?);
    anyhow::ensure!(
        chain_id == net.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        net.chain_id
    );
    anyhow::ensure!(
        units <= token_balance,
        "fonds {} insuffisants : {} disponibles, {} requis",
        token.symbol,
        tokens::format_amount(token_balance, deployment.decimals),
        tokens::format_amount(units, deployment.decimals)
    );
    let gas_cost = fee.max_total()?;
    anyhow::ensure!(
        gas_cost <= native,
        "{} insuffisant pour les frais : {} wei disponibles, {gas_cost} wei requis",
        net.native_symbol,
        native
    );
    let tx = eth_tx::EthTx {
        nonce,
        gas_price: fee.gas_price,
        gas_limit: fee.gas_limit,
        to: contract_bytes,
        value: 0,
        chain_id,
        data,
    };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

/// Transfer of a registry Solana token (classic program, or Token-2022 for xStocks:
/// see `send_scaled_token`).
pub fn send_registered_spl(
    data_dir: &Path,
    device_password: &str,
    token_id: &str,
    to: &str,
    amount: &str,
    profile_index: u32,
) -> Result<String> {
    let (token, deployment) = registered_token(token_id, "sol_mainnet")?;
    match deployment.kind {
        tokens::TokenKind::Spl { mint } => {
            let units = u64::try_from(tokens::parse_amount(amount, deployment.decimals)?)
                .context("montant trop grand")?;
            send_spl(
                data_dir,
                device_password,
                &wallet_flow::SOLANA_MAINNET,
                &sol_spl_mint(mint)?,
                deployment.decimals,
                token.symbol,
                to,
                units,
                profile_index,
            )
        }
        tokens::TokenKind::Spl2022 { mint } => send_scaled_token(
            data_dir,
            device_password,
            token.symbol,
            mint,
            deployment.decimals,
            to,
            amount,
            profile_index,
        ),
        _ => anyhow::bail!("jeton SPL attendu"),
    }
}

// --- xStocks tokenized shares (Token-2022, display multiplier) -----------------
//
// See `tokens::TokenKind::Spl2022`. Measured on 2026-10-09: the node applies the
// current multiplier to the balance (getTokenAccountBalance), NOT to the balances
// of past transactions; Jupiter's prices are per displayed unit (usdPrice), while
// its quotes and transfers are in raw units. The app counts in displayed units
// everywhere and converts at signing time.

/// Display multiplier as an exact decimal: value = `num` / 10^`scale`. Read as the
/// node writes it ("1", "1.0211807004882871"), with no floating-point arithmetic on
/// an amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiMultiplier {
    num: u128,
    scale: u32,
}

impl UiMultiplier {
    pub const ONE: Self = Self { num: 1, scale: 0 };

    /// At most 18 decimals, between 0.01 and 100: beyond that, refused rather than
    /// giving a wrong amount.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
        anyhow::ensure!(
            !whole.is_empty()
                && whole.len() <= 3
                && whole.bytes().all(|b| b.is_ascii_digit())
                && frac.len() <= 18
                && frac.bytes().all(|b| b.is_ascii_digit()),
            "coefficient d'affichage illisible : {text}"
        );
        let scale = frac.len() as u32;
        let num: u128 = format!("{whole}{frac}")
            .parse()
            .context("coefficient d'affichage illisible")?;
        let unit = 10u128.pow(scale);
        anyhow::ensure!(
            num > 0 && num >= unit / 100 && num <= unit * 100,
            "coefficient d'affichage hors limites : {text}"
        );
        Ok(Self { num, scale })
    }

    fn unit(self) -> u128 {
        10u128.pow(self.scale)
    }

    /// Raw units → displayed units, truncated (like the node). No overflow for any u64
    /// amount.
    pub fn to_ui(self, raw: u64) -> u128 {
        let (raw, unit) = (u128::from(raw), self.unit());
        raw / unit * self.num + raw % unit * self.num / unit
    }

    /// Displayed units → raw units, rounded down: never more than the amount requested.
    pub fn to_raw(self, ui: u128) -> Result<u64> {
        let raw = ui.checked_mul(self.unit()).context("montant trop grand")? / self.num;
        u64::try_from(raw).context("montant trop grand")
    }
}

/// What the app reads from an xStocks mint.
#[derive(Clone, Debug, PartialEq)]
struct ScaledMintConfig {
    current: UiMultiplier,
    next: UiMultiplier,
    /// Time (Unix) at which `next` takes effect.
    next_at: i64,
    paused: bool,
    transfer_hook: Option<String>,
}

impl ScaledMintConfig {
    /// Multiplier in force at `now`: the new one from its effective time (observed:
    /// Jupiter's raw/displayed price ratio is the new multiplier once its time has
    /// passed).
    fn effective(&self, now: i64) -> UiMultiplier {
        if now >= self.next_at {
            self.next
        } else {
            self.current
        }
    }
}

pub const XSTOCK_PAUSED: &str =
    "transferts de ce jeton suspendus par son émetteur : réessayez plus tard";
pub const XSTOCK_TRANSFER_HOOK: &str = "l'émetteur de ce jeton a ajouté une règle de transfert que l'app ne gère pas encore : envoi refusé, rien n'a été dépensé";
pub const XSTOCK_MULTIPLIER_SWITCH: &str = "le coefficient de ce jeton change en ce moment (dividende ou division d'action) : réessayez dans quelques minutes";

/// `info` fields of a mint read as `jsonParsed` → the useful configuration.
fn parse_scaled_mint(info: &serde_json::Value) -> Result<ScaledMintConfig> {
    let extension = |name: &str| {
        info["extensions"]
            .as_array()
            .and_then(|list| list.iter().find(|e| e["extension"] == name))
            .map(|e| &e["state"])
    };
    let scaled =
        extension("scaledUiAmountConfig").context("coefficient d'affichage absent du mint")?;
    let current = UiMultiplier::parse(
        scaled["multiplier"]
            .as_str()
            .context("coefficient d'affichage illisible")?,
    )?;
    let next = UiMultiplier::parse(
        scaled["newMultiplier"]
            .as_str()
            .context("coefficient d'affichage illisible")?,
    )?;
    Ok(ScaledMintConfig {
        current,
        next,
        next_at: scaled["newMultiplierEffectiveTimestamp"]
            .as_i64()
            .unwrap_or(0),
        paused: extension("pausableConfig")
            .and_then(|p| p["paused"].as_bool())
            .unwrap_or(false),
        transfer_hook: extension("transferHook")
            .and_then(|h| h["programId"].as_str())
            .map(str::to_string),
    })
}

/// Can this token move at `now`? Refused if the issuer has paused transfers, if a
/// transfer hook is active (a plain transfer would fail), or within 5 minutes of a
/// multiplier change (amount converted with one, executed with the other).
fn check_scaled_transfer(config: &ScaledMintConfig, now: i64) -> Result<()> {
    anyhow::ensure!(!config.paused, XSTOCK_PAUSED);
    anyhow::ensure!(config.transfer_hook.is_none(), XSTOCK_TRANSFER_HOOK);
    anyhow::ensure!(
        config.next == config.current || (now - config.next_at).abs() >= 300,
        XSTOCK_MULTIPLIER_SWITCH
    );
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Configuration of the xStocks mint `mint`; kept for 10 minutes for balances and
/// history (the multiplier changes a few times a year, and its time is known in
/// advance), reread (`fresh`) before any movement.
fn scaled_mint_config(rpc: &sol_rpc::SolRpc, mint: &str, fresh: bool) -> Result<ScaledMintConfig> {
    type Cache = std::collections::HashMap<String, (std::time::Instant, ScaledMintConfig)>;
    static CACHE: std::sync::OnceLock<Mutex<Cache>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Cache::new()));
    if !fresh {
        if let Some((read, config)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(mint) {
            if read.elapsed() < std::time::Duration::from_secs(600) {
                return Ok(config.clone());
            }
        }
    }
    let result = rpc.call(
        "getAccountInfo",
        serde_json::json!([mint, {"encoding": "jsonParsed"}]),
    )?;
    let value = &result["value"];
    anyhow::ensure!(
        value["owner"] == TOKEN_2022_PROGRAM_ID,
        "mint du jeton inattendu sur le réseau"
    );
    let config = parse_scaled_mint(&value["data"]["parsed"]["info"])?;
    cache.lock().unwrap_or_else(|p| p.into_inner()).insert(
        mint.to_string(),
        (std::time::Instant::now(), config.clone()),
    );
    Ok(config)
}

/// A registry Solana token (classic program or Token-2022).
pub struct SolanaToken {
    pub mint: [u8; 32],
    pub mint_b58: &'static str,
    /// Token program (part of the associated account's address).
    pub program: [u8; 32],
    pub decimals: u8,
    pub symbol: &'static str,
    /// Display multiplier (xStocks).
    pub scaled: bool,
}

impl SolanaToken {
    /// Size of a token account for this token (rent for creating it).
    pub fn account_size(&self) -> u64 {
        if self.scaled {
            tokens::XSTOCK_ACCOUNT_SIZE
        } else {
            165
        }
    }
}

pub fn registered_solana_token(token_id: &str) -> Result<SolanaToken> {
    let (token, deployment) = registered_token(token_id, "sol_mainnet")?;
    let (mint, program, scaled) = match deployment.kind {
        tokens::TokenKind::Spl { mint } => (mint, sol_spl::token_program_id(), false),
        tokens::TokenKind::Spl2022 { mint } => (mint, sol_spl::token_2022_program_id(), true),
        _ => anyhow::bail!("jeton SPL attendu"),
    };
    Ok(SolanaToken {
        mint: sol_spl_mint(mint)?,
        mint_b58: mint,
        program,
        decimals: deployment.decimals,
        symbol: token.symbol,
        scaled,
    })
}

fn solana_owner(address: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(address.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))
}

/// Associated token account (base58) of `owner_address` for the registry token
/// `token_id`, under the right program.
pub fn registered_token_account(owner_address: &str, token_id: &str) -> Result<String> {
    let token = registered_solana_token(token_id)?;
    Ok(bs58::encode(sol_spl::find_associated_token_address_for(
        &solana_owner(owner_address)?,
        &token.mint,
        &token.program,
    ))
    .into_string())
}

/// Rent for the recipient's `token_id` token account if it does not exist yet
/// (created and paid for by the sender); `None` if it exists.
pub fn token_account_rent_if_missing(
    token_id: &str,
    to_address: &str,
    network: &wallet_flow::SolNetwork,
) -> Result<Option<u64>> {
    let token = registered_solana_token(token_id)?;
    let account = bs58::encode(sol_spl::find_associated_token_address_for(
        &solana_owner(to_address)?,
        &token.mint,
        &token.program,
    ))
    .into_string();
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    if rpc.account_exists(&account)? {
        return Ok(None);
    }
    Ok(Some(rpc.minimum_rent_exempt_balance(token.account_size())?))
}

/// xStocks balance of `owner`, in displayed units (multiplier only read if there is
/// a balance).
fn scaled_token_balance(owner: &str, mint: &'static str) -> Result<u128> {
    let account = sol_spl::find_associated_token_address_for(
        &solana_owner(owner)?,
        &sol_spl_mint(mint)?,
        &sol_spl::token_2022_program_id(),
    );
    let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
    let raw = rpc
        .token_account_balance(&bs58::encode(account).into_string())?
        .unwrap_or(0);
    if raw == 0 {
        return Ok(0);
    }
    Ok(scaled_mint_config(&rpc, mint, false)?
        .effective(unix_now())
        .to_ui(raw))
}

/// xStocks balances of `owner` in ONE request (all their Token-2022 accounts), in
/// displayed units: only associated accounts count (the ones the app spends from).
/// Tokens with no balance: absent.
pub fn stock_balances(owner: &str) -> Result<Vec<(&'static str, u128)>> {
    let owner_bytes = solana_owner(owner)?;
    let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
    let result = rpc.call(
        "getTokenAccountsByOwner",
        serde_json::json!([owner.trim(), {"programId": TOKEN_2022_PROGRAM_ID}, {"encoding": "jsonParsed", "commitment": "confirmed"}]),
    )?;
    let accounts = result["value"].as_array().cloned().unwrap_or_default();
    let mut balances = Vec::new();
    for token in tokens::TOKENS.iter().filter(|t| tokens::is_spl2022(t.id)) {
        let solana = registered_solana_token(token.id)?;
        let ata = bs58::encode(sol_spl::find_associated_token_address_for(
            &owner_bytes,
            &solana.mint,
            &solana.program,
        ))
        .into_string();
        let raw = accounts
            .iter()
            .find(|a| {
                a["pubkey"] == ata.as_str()
                    && a["account"]["data"]["parsed"]["info"]["mint"] == solana.mint_b58
            })
            .and_then(|a| a["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"].as_str())
            .and_then(|amount| amount.parse::<u64>().ok())
            .unwrap_or(0);
        if raw > 0 {
            balances.push((
                token.id,
                scaled_mint_config(&rpc, solana.mint_b58, false)?
                    .effective(unix_now())
                    .to_ui(raw),
            ));
        }
    }
    Ok(balances)
}

/// Signed amount in raw units → displayed units.
fn scale_signed(amount: i128, multiplier: UiMultiplier) -> i128 {
    let shown = multiplier.to_ui(u64::try_from(amount.unsigned_abs()).unwrap_or(u64::MAX)) as i128;
    if amount < 0 {
        -shown
    } else {
        shown
    }
}

/// History of a registry Solana token (associated account under the right program).
/// xStocks: amounts in displayed units at the CURRENT multiplier (past transaction
/// balances are raw), consistent with the displayed balance.
pub fn get_registered_spl_tx_history(
    token_id: &str,
    owner_address: &str,
    network: &wallet_flow::SolNetwork,
    limit: u32,
) -> Result<Vec<history::TxEntry>> {
    let token = registered_solana_token(token_id)?;
    let account = registered_token_account(owner_address, token_id)?;
    let mut entries = history::spl_history(network.rpc, &account, limit)?;
    if token.scaled && entries.iter().any(|e| e.net_amount_minor.is_some()) {
        let multiplier =
            scaled_mint_config(&sol_rpc::SolRpc::new(network.rpc), token.mint_b58, false)?
                .effective(unix_now());
        for entry in &mut entries {
            entry.net_amount_minor = entry
                .net_amount_minor
                .map(|amount| scale_signed(amount, multiplier));
        }
    }
    Ok(entries)
}

/// Amount of an xStocks movement: displayed units `shown` → raw. The whole balance
/// (`shown` equal to the displayed balance): the whole raw balance, with nothing
/// left over.
fn scaled_raw_amount(shown: u128, multiplier: UiMultiplier, raw_balance: u64) -> Result<u64> {
    if shown == multiplier.to_ui(raw_balance) {
        return Ok(raw_balance);
    }
    let raw = multiplier.to_raw(shown)?;
    anyhow::ensure!(raw > 0, "montant trop petit pour ce jeton");
    Ok(raw)
}

/// Transfer of an xStock: associated account under the Token-2022 program (created
/// for the recipient if needed, rent announced in the confirmation), amount entered
/// in displayed units converted at the current multiplier, mint reread just before
/// (pause, transfer hook, multiplier change).
#[allow(clippy::too_many_arguments)]
fn send_scaled_token(
    data_dir: &Path,
    device_password: &str,
    symbol: &str,
    mint: &'static str,
    decimals: u8,
    to: &str,
    amount: &str,
    profile_index: u32,
) -> Result<String> {
    let network = &wallet_flow::SOLANA_MAINNET;
    check_solana_recipient(to, network)?;
    let shown = tokens::parse_amount(amount, decimals)?;
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let config = scaled_mint_config(&rpc, mint, true)?;
    let now = unix_now();
    check_scaled_transfer(&config, now)?;
    let multiplier = config.effective(now);

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let to_owner = solana_owner(to)?;
    let (mint_bytes, program) = (sol_spl_mint(mint)?, sol_spl::token_2022_program_id());
    let source = sol_spl::find_associated_token_address_for(&owner, &mint_bytes, &program);
    let dest = sol_spl::find_associated_token_address_for(&to_owner, &mint_bytes, &program);
    let (source_b58, dest_b58, owner_b58) = (
        bs58::encode(source).into_string(),
        bs58::encode(dest).into_string(),
        bs58::encode(owner).into_string(),
    );

    let (sol_balance, raw_balance, blockhash, dest_exists) = std::thread::scope(|scope| {
        let sol = scope.spawn(|| rpc.balance_lamports(&owner_b58));
        let token = scope.spawn(|| rpc.token_account_balance(&source_b58));
        let blockhash = scope.spawn(|| rpc.latest_blockhash());
        let dest = scope.spawn(|| rpc.account_exists(&dest_b58));
        (
            sol.join()
                .expect("le thread solde SOL ne doit pas paniquer"),
            token
                .join()
                .expect("le thread solde du jeton ne doit pas paniquer"),
            blockhash
                .join()
                .expect("le thread blockhash ne doit pas paniquer"),
            dest.join()
                .expect("le thread compte destinataire ne doit pas paniquer"),
        )
    });
    let (sol_balance, blockhash, dest_exists) = (sol_balance?, blockhash?, dest_exists?);
    let raw_balance = raw_balance?.ok_or_else(|| {
        anyhow::anyhow!("aucun compte {symbol} trouvé pour cette adresse (solde 0)")
    })?;
    let raw = scaled_raw_amount(shown, multiplier, raw_balance)?;
    anyhow::ensure!(
        raw <= raw_balance,
        "fonds {symbol} insuffisants : {} disponibles, {} requis",
        tokens::format_amount(multiplier.to_ui(raw_balance), decimals),
        tokens::format_amount(shown, decimals)
    );
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let rent = if dest_exists {
        0
    } else {
        rpc.minimum_rent_exempt_balance(tokens::XSTOCK_ACCOUNT_SIZE)?
    };
    let needed = SOL_FEE_LAMPORTS
        .checked_add(rent)
        .context("frais + rent dépasse la capacité représentable")?;
    anyhow::ensure!(
        needed <= sol_balance,
        "SOL insuffisant pour les frais{} : {sol_balance} lamports disponibles, {needed} lamports requis",
        if dest_exists { String::new() } else { " + création du compte de jetons du destinataire".to_string() }
    );
    let create = sol_spl::create_ata_idempotent_instruction_for(
        &owner,
        &to_owner,
        &mint_bytes,
        &dest,
        &program,
    );
    let transfer = sol_spl::transfer_checked_instruction_for(
        &source,
        &mint_bytes,
        &dest,
        &owner,
        raw,
        decimals,
        &program,
    );
    let raw_tx =
        sol_tx::build_and_sign_transaction(&signing_key, &owner, &[create, transfer], &blockhash);
    rpc.send_transaction(&raw_tx)
}

/// Raw units of a Jupiter swap amount: xStocks converted at the current multiplier
/// (mint reread), other tokens unchanged.
fn jupiter_raw_amount(coin: &str, shown: u64) -> Result<u64> {
    if coin == "sol" {
        return Ok(shown);
    }
    let token = registered_solana_token(coin)?;
    if !token.scaled {
        return Ok(shown);
    }
    let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
    let config = scaled_mint_config(&rpc, token.mint_b58, true)?;
    let now = unix_now();
    check_scaled_transfer(&config, now)?;
    config.effective(now).to_raw(u128::from(shown))
}

/// Output of a Jupiter quote (raw) in displayed units.
fn jupiter_shown_out(coin: &str, raw: u64) -> Result<u64> {
    if coin == "sol" || !registered_solana_token(coin)?.scaled {
        return Ok(raw);
    }
    let token = registered_solana_token(coin)?;
    let multiplier = scaled_mint_config(
        &sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc),
        token.mint_b58,
        false,
    )?
    .effective(unix_now());
    u64::try_from(multiplier.to_ui(raw)).context("montant trop grand")
}

// --- Signatures requested by dApps (WalletConnect) ---------------------------

/// Signs a dApp request that has ALREADY been prepared (see
/// `dapp_requests::prepare`: validation, dry run or simulation, decoding) and
/// confirmed in the native dialog; nothing is reread or recomputed here from the
/// dApp. The password is required for every signature, as for any send of funds.
/// `account`: the session's addresses; the derived key must match one of them
/// (defense in depth: a session bound to another profile cannot sign anything).
/// Returns the JSON result the dApp expects.
pub fn sign_dapp_request(
    data_dir: &Path,
    device_password: &str,
    profile_index: u32,
    account: &dapp_requests::Account,
    prepared: &dapp_requests::Prepared,
) -> Result<serde_json::Value> {
    use dapp_requests::Prepared;
    use ed25519_dalek::Signer;
    use serde_json::json;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let evm_key = || -> Result<k256::ecdsa::SigningKey> {
        let (key, address) = derivation::derive_evm_key(&seed, profile_index)?;
        anyhow::ensure!(
            derivation::format_address(&address).eq_ignore_ascii_case(&account.evm),
            "le compte de la session ne correspond pas au profil — signature refusée"
        );
        Ok(key)
    };
    let solana_key = || -> Result<ed25519_dalek::SigningKey> {
        let key = derivation::derive_solana_key(&seed, profile_index);
        anyhow::ensure!(
            bs58::encode(key.verifying_key().to_bytes()).into_string() == account.solana,
            "le compte de la session ne correspond pas au profil — signature refusée"
        );
        Ok(key)
    };

    match prepared {
        Prepared::EvmPersonalSign { message, .. } => {
            let signature = crate::evm_sign::sign_digest(
                &evm_key()?,
                &crate::evm_sign::personal_message_hash(message),
            )?;
            Ok(json!(format!("0x{}", hex::encode(signature))))
        }
        Prepared::EvmTypedData { digest, .. } => {
            let signature = crate::evm_sign::sign_digest(&evm_key()?, digest)?;
            Ok(json!(format!("0x{}", hex::encode(signature))))
        }
        Prepared::EvmTransaction {
            network,
            to,
            value,
            data,
            gas_limit,
            gas_price,
            l1_fee,
            ..
        } => {
            check_evm_gas_price(network, *gas_price)?;
            let signing_key = evm_key()?;
            let rpc = eth_rpc::EthRpc::new(network.rpc);
            let (nonce, chain_id, balance) = std::thread::scope(|scope| {
                let nonce_handle = scope.spawn(|| rpc.nonce(&account.evm));
                let chain_id_handle = scope.spawn(|| rpc.chain_id());
                let balance_handle = scope.spawn(|| rpc.balance(&account.evm));
                (
                    nonce_handle
                        .join()
                        .expect("le thread nonce ne doit pas paniquer"),
                    chain_id_handle
                        .join()
                        .expect("le thread chain_id ne doit pas paniquer"),
                    balance_handle
                        .join()
                        .expect("le thread balance ne doit pas paniquer"),
                )
            });
            let (nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
            anyhow::ensure!(
                chain_id == network.chain_id,
                "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
                network.chain_id
            );
            let gas_cost = gas_price
                .checked_mul(u128::from(*gas_limit))
                .and_then(|gas| gas.checked_add(*l1_fee))
                .context("gas_price * gas_limit dépasse la capacité représentable")?;
            let total_needed = value
                .checked_add(gas_cost)
                .context("montant + frais de gas dépasse la capacité représentable")?;
            anyhow::ensure!(
                total_needed <= balance,
                "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
            );
            let tx = eth_tx::EthTx {
                nonce,
                gas_price: *gas_price,
                gas_limit: *gas_limit,
                to: *to,
                value: *value,
                chain_id,
                data: data.clone(),
            };
            Ok(json!(rpc.send_raw_transaction(&tx.sign(&signing_key)?)?))
        }
        Prepared::SolanaMessage { message, .. } => {
            let signature = solana_key()?.sign(message);
            Ok(json!({"signature": bs58::encode(signature.to_bytes()).into_string()}))
        }
        Prepared::SolanaTransaction {
            network, tx, send, ..
        } => {
            let key = solana_key()?;
            let signed =
                jupiter_rpc::sign_swap_transaction(tx, &key, &key.verifying_key().to_bytes())?;
            let signature = bs58::encode(&signed[1..65]).into_string();
            if *send {
                Ok(
                    json!({"signature": sol_rpc::SolRpc::new(network.rpc).send_transaction(&signed)?}),
                )
            } else {
                use base64::Engine;
                Ok(
                    json!({"signature": signature, "transaction": base64::engine::general_purpose::STANDARD.encode(&signed)}),
                )
            }
        }
    }
}

#[cfg(test)]
#[path = "swap_matrix.rs"]
mod swap_matrix;

#[cfg(test)]
mod tests {
    use super::*;

    /// Bitcoin recipient of every standard type: accepted from its dust threshold,
    /// refused below it with the minimum in BTC; a testnet address refused on mainnet.
    #[test]
    fn bitcoin_recipients_of_every_type_need_an_amount_above_their_dust() {
        let net = &wallet_flow::BTC_MAINNET;
        for (address, dust) in [
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 546u64),
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 540),
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 294),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                330,
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                330,
            ),
        ] {
            assert_eq!(
                btc_recipient(net, address, dust).unwrap(),
                (net.recipient_script)(address).unwrap(),
                "{address}"
            );
            let refused = btc_recipient(net, address, dust - 1)
                .unwrap_err()
                .to_string();
            assert_eq!(
                refused,
                format!(
                    "{BTC_DUST_PREFIX}{} BTC vers cette adresse",
                    tokens::format_amount(u128::from(dust), 8)
                ),
                "{address}"
            );
            assert!(validate_btc_recipient(address, net).is_ok(), "{address}");
        }
        assert!(btc_recipient(net, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 10_000).is_err());
        assert!(btc_recipient(
            &wallet_flow::BTC_TESTNET,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            10_000
        )
        .is_ok());
    }

    /// Jupiter slippage (6001) recognized; other failures left as they are.
    #[test]
    fn jupiter_slippage_is_recognized() {
        let logs = "Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 consumed 56922 of 1372519 compute units\nProgram JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 failed: custom program error: 0x1771";
        assert!(is_jupiter_slippage(
            &serde_json::json!({ "InstructionError": [6, { "Custom": 6001 }] }),
            logs
        ));
        assert!(!is_jupiter_slippage(
            &serde_json::json!({ "InstructionError": [6, { "Custom": 6025 }] }),
            logs
        ));
        assert!(!is_jupiter_slippage(
            &serde_json::json!({ "InstructionError": [2, { "Custom": 6001 }] }),
            "Program Other failed: custom program error: 0x1771"
        ));
    }

    /// Live (read-only): "Max" on funded public addresses, below the balance by the
    /// network fee difference only.
    /// `cargo test -- --ignored real_max_amounts --nocapture`
    #[test]
    #[ignore]
    fn real_max_amounts_on_funded_addresses() {
        let parse = |s: &str, d: u8| tokens::parse_amount(s, d).unwrap();
        // Dogecoin: an address with 1,000+ outputs (600-input cap).
        let doge = doge_max("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L").unwrap();
        let doge_balance = doge::balance("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L").unwrap();
        println!("DOGE : max {doge} sur {}", doge::format_doge(doge_balance));
        assert!(parse(&doge, 8) < u128::from(doge_balance));
        // Ethereum: gas for a transfer deducted (mainnet: no L1 fee).
        let evm = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let net = wallet_flow::evm_network("evm_mainnet").unwrap();
        let fee = evm_max_fee(net, Some(evm), evm).unwrap();
        let max = parse(&evm_max_native(net, evm, fee).unwrap(), 18);
        let balance = get_evm_balance(evm, net).unwrap();
        println!(
            "ETH : max {} sur {}, frais {}",
            tokens::format_amount(max, 18),
            tokens::format_amount(balance, 18),
            tokens::format_amount(fee.max_total().unwrap(), 18)
        );
        assert_eq!(
            balance - max,
            fee.max_total().unwrap(),
            "solde stable entre les deux lectures attendu"
        );
        // Token: the whole balance.
        let usdt = token_max(
            "usdt",
            "evm_mainnet",
            "0x28C6c06298d514Db089934071355E5743bf21d60",
        )
        .unwrap();
        println!("USDT : max {usdt}");
        // Solana: one signature's fee.
        let sol_account = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let sol = parse(
            &sol_max(&wallet_flow::SOLANA_MAINNET, sol_account).unwrap(),
            9,
        );
        assert_eq!(
            u128::from(get_sol_balance(sol_account, &wallet_flow::SOLANA_MAINNET).unwrap()) - sol,
            5_000
        );
        println!("SOL : max {}", tokens::format_amount(sol, 9));
    }

    /// Live (read-only): a swap's "Max", below the balance by the provider's own
    /// reserve (contract gas, Solana accounts, Bitcoin memo output), the whole balance
    /// for a token.
    /// `cargo test -- --ignored real_swap_max --nocapture`
    #[test]
    #[ignore]
    fn real_swap_max_on_funded_addresses() {
        let parse = |s: &str, d: u8| tokens::parse_amount(s, d).unwrap();
        let evm = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let net = wallet_flow::evm_network("evm_mainnet").unwrap();
        let balance = get_evm_balance(evm, net).unwrap();
        let gas_price = evm_max_fee(net, Some(evm), evm).unwrap().gas_price;
        for (protocol, gas_limit) in [
            ("thorchain", EVM_SWAP_MAX_GAS_LIMIT),
            ("cow", EVM_SWAP_MAX_GAS_LIMIT),
            ("lifi", LIFI_MAX_GAS),
            ("swapkit", EVM_TRANSFER_GAS_LIMIT),
        ] {
            let max = parse(
                &swap_max(protocol, "evm", "evm_mainnet", "btc", evm).unwrap(),
                18,
            );
            let kept = balance - max;
            println!(
                "ETH via {protocol} : max {}, gardé {}",
                tokens::format_amount(max, 18),
                tokens::format_amount(kept, 18)
            );
            // Gas at the provider's cap, price increased by a quarter (the price, reread on
            // each call, can move from one block to the next: 5%).
            let expected = (gas_price + gas_price / 4) * u128::from(gas_limit);
            assert!(
                kept.abs_diff(expected) <= expected / 20,
                "{protocol} : gardé {kept}, attendu {expected}"
            );
        }
        let whale = "0x28C6c06298d514Db089934071355E5743bf21d60";
        assert_eq!(
            swap_max("cow", "usdt", "evm_mainnet", "evm", whale).unwrap(),
            token_max("usdt", "evm_mainnet", whale).unwrap(),
            "jeton : tout le solde"
        );

        let sol = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let sol_balance = u128::from(get_sol_balance(sol, &wallet_flow::SOLANA_MAINNET).unwrap());
        let jupiter = sol_balance
            - parse(
                &swap_max("jupiter", "sol", "sol_mainnet", "usdc", sol).unwrap(),
                9,
            );
        println!(
            "SOL via Jupiter : gardé {}",
            tokens::format_amount(jupiter, 9)
        );
        // Fees (50,000) + priority at the cap + wSOL account (+ USDC account to create); a
        // token account's deposit read live (down from 2,039,280 lamports: 1,488,440 on
        // 2026-10-05).
        let rent = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc)
            .minimum_rent_exempt_balance(165)
            .unwrap();
        assert!(
            jupiter >= u128::from(50_000 + jupiter_rpc::PRIORITY_FEE_MAX_LAMPORTS + rent),
            "{jupiter}"
        );
        assert_eq!(
            sol_balance
                - parse(
                    &swap_max("lifi", "sol", "sol_mainnet", "usdc", sol).unwrap(),
                    9
                ),
            u128::from(LIFI_SOL_FEE_BUDGET_LAMPORTS)
        );
        assert_eq!(
            sol_balance
                - parse(
                    &swap_max("swapkit", "sol", "sol_mainnet", "usdc", sol).unwrap(),
                    9
                ),
            5_000
        );

        // Bitcoin: an ordinary address from the latest block (few outputs).
        let tip = reqwest::blocking::get("https://mempool.space/api/blocks/tip/hash")
            .unwrap()
            .text()
            .unwrap();
        let block: serde_json::Value =
            reqwest::blocking::get(format!("https://mempool.space/api/block/{tip}/txs"))
                .unwrap()
                .json()
                .unwrap();
        let btc = block
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
            .filter_map(|tx| tx["vout"][0]["scriptpubkey_address"].as_str())
            .find(|a| a.starts_with("bc1q"))
            .unwrap()
            .to_string();
        let total: u64 = btc_rpc::EsploraClient::new(wallet_flow::BTC_MAINNET.esplora_base)
            .utxos(&btc)
            .unwrap()
            .iter()
            .map(|u| u.value_sat)
            .sum();
        match swap_max("thorchain", "btc", "btc_mainnet", "evm", &btc) {
            Ok(max) => {
                let kept = u128::from(total) - parse(&max, 8);
                println!("BTC via THORChain ({btc}) : gardé {kept} sat sur {total}");
                assert!(kept > 0 && kept < 20_000, "{kept}");
            }
            Err(e) => println!("BTC ({btc}, {total} sat) : {e}"),
        }
        assert_eq!(
            swap_max("thorchain", "xlm", "xlm_mainnet", "evm", "G")
                .unwrap_err()
                .to_string(),
            SWAP_MAX_UNAVAILABLE
        );
    }

    /// Audit round 23: a pending send (negative net change, change returned deducted)
    /// counts straight away; an unconfirmed receipt is shown separately, NEVER in the
    /// balance (it can still be cancelled).
    #[test]
    fn unconfirmed_receptions_are_never_counted_in_the_btc_balance() {
        let view = btc_balance_view(100_000, [-30_000, 5_000].into_iter());
        assert_eq!(
            (view.settled_sat, view.incoming_pending_sat),
            (70_000, 5_000)
        );
        let view = btc_balance_view(0, [2_500_000].into_iter());
        assert_eq!(
            (view.settled_sat, view.incoming_pending_sat),
            (0, 2_500_000),
            "rien de confirmé : 0, réception à part"
        );
        let view = btc_balance_view(10_000, [-20_000].into_iter());
        assert_eq!(view.settled_sat, 0, "jamais négatif");
    }

    /// End-to-end check against the real mainnet RPC (read-only, no risk): the same
    /// public wallet used to validate `find_associated_token_address` (see sol_spl.rs),
    /// with a known non-zero balance when this test was written. Ignored by default
    /// (depends on the network, not run by the normal suite); run it explicitly with:
    /// `cargo test -- --ignored get_usdc_balance_matches_the_real_network`
    #[test]
    #[ignore]
    fn get_usdc_balance_matches_the_real_network() {
        let network = wallet_flow::SOLANA_MAINNET;
        let balance = get_usdc_balance("E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk", &network)
            .expect("appel réseau réel");
        assert!(
            balance > 0,
            "ce portefeuille public détient de l'USDC au moment de l'écriture du test"
        );
    }

    #[test]
    fn fee_rate_for_target_prefers_the_closest_target_at_or_below_the_requested_one() {
        let estimates = [(2, 20.0), (6, 8.0), (144, 1.5)];
        // Exact target present.
        assert_eq!(fee_rate_for_target(&estimates, 6), 8.0);
        // Target missing between two known values: the closest one BELOW (cheaper than
        // planned never happens before confirmation, so we must never underestimate by
        // picking a faster target than hoped for).
        assert_eq!(fee_rate_for_target(&estimates, 10), 8.0);
        // A target faster than anything known: the fastest available.
        assert_eq!(fee_rate_for_target(&estimates, 1), 20.0);
    }

    #[test]
    fn fee_rate_for_target_falls_back_to_1_sat_per_vbyte_when_no_estimates_are_available() {
        assert_eq!(fee_rate_for_target(&[], 6), 1.0);
    }

    /// The password rule holds in core, whatever the interface checked: 11 characters
    /// refused, 12 accepted, a common pattern or a single kind of character refused.
    #[test]
    fn new_password_rule_is_enforced_in_core() {
        assert!(check_new_password("Abcdefgh1!x").is_err()); // 11 characters
        assert!(check_new_password("Abcdefgh1!xy").is_ok()); // 12
        assert!(check_new_password("abcdefghijkl").is_err()); // one kind only
        assert!(check_new_password("Password123!").is_err()); // common pattern
        assert!(check_new_password("Azerty-2026-maison").is_err());
        assert!(check_new_password("un mot de passe de test bien assez long").is_ok());
        // Counted in characters, not bytes: 11 accented letters + "1" are 12.
        assert!(check_new_password("éàèùçÉÀÈÙÇê1").is_ok());
        assert!(check_new_password("éàèùçÉÀÈÙÇ1").is_err());
    }

    /// A trivial password is refused before anything is written: no vault is created,
    /// and a restore leaves the device as it was.
    #[test]
    fn create_and_restore_refuse_a_weak_password_before_writing() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_weak_password_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(create_wallet(&dir, "a").is_err());
        assert!(!device_vault_exists(&dir));
        assert!(!dir.exists());

        let created = create_wallet(&dir, "un mot de passe de test bien assez long").unwrap();
        let vault = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        let [b1, b2, _] = &created.backups[..] else {
            panic!("3 parts attendues")
        };
        let refused = restore_wallet_with(
            &dir,
            "motdepasse",
            (&b1.encrypted_share, &b1.privkey_armored, &b1.passphrase),
            (&b2.encrypted_share, &b2.privkey_armored, &b2.passphrase),
            &FakeSealer { fail_enroll: false },
        );
        assert!(refused
            .err()
            .is_some_and(|e| e.to_string().contains("trop court")));
        assert_eq!(std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap(), vault);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_profile_removes_label_but_refuses_to_remove_the_last_one() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_delete_profile_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        create_profile(&dir, None, "Épargne").expect("création d'un second profil");
        assert_eq!(list_profiles(&dir).len(), 2);

        assert!(
            delete_profile(&dir, "mauvais mot de passe", 1).is_err(),
            "un mauvais mot de passe doit refuser la suppression"
        );
        assert_eq!(
            list_profiles(&dir).len(),
            2,
            "rien ne doit être supprimé sur un mauvais mot de passe"
        );

        delete_profile(&dir, password, 1).expect("suppression du second profil");
        let remaining = list_profiles(&dir);
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].index, 0,
            "le profil par défaut doit être celui qui reste"
        );

        assert!(
            delete_profile(&dir, password, 0).is_err(),
            "supprimer le dernier profil restant doit être refusé"
        );
        assert_eq!(
            list_profiles(&dir).len(),
            1,
            "le profil restant ne doit pas avoir été supprimé"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_and_unarchive_profile_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_archive_profile_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        create_profile(&dir, None, "Épargne").expect("création d'un second profil");

        // Archived: disappears from the active list, appears in the archives.
        archive_profile(&dir, 1).expect("archivage du second profil");
        assert_eq!(
            list_profiles(&dir).len(),
            1,
            "le profil archivé ne doit plus être actif"
        );
        let archived = list_archived_profiles(&dir);
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].index, 1);

        // A full unlock must derive active profiles only.
        let unlocked = unlock_wallet(&dir, password).expect("déverrouillage");
        assert_eq!(
            unlocked.len(),
            1,
            "un profil archivé ne doit pas être dérivé au déverrouillage"
        );

        // Unarchived: active again, gone from the archives.
        unarchive_profile(&dir, 1).expect("désarchivage");
        assert_eq!(
            list_profiles(&dir).len(),
            2,
            "le profil désarchivé doit redevenir actif"
        );
        assert!(list_archived_profiles(&dir).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_profile_refuses_to_archive_the_last_active_profile() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_archive_last_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        assert!(
            archive_profile(&dir, 0).is_err(),
            "archiver le seul profil actif doit être refusé"
        );
        assert_eq!(list_profiles(&dir).len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Guard against the side effect discovered while adding archiving: without it,
    /// `delete_profile` only checked that the TOTAL number of profiles (active +
    /// archived) was > 1, so removing the last active profile could have gone through
    /// as long as an archived profile was lying around, leaving the dashboard with no
    /// address to show after unlocking.
    #[test]
    fn delete_profile_refuses_to_remove_the_last_active_profile_even_with_an_archived_one_present()
    {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_delete_last_active_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        create_profile(&dir, None, "Épargne").expect("création d'un second profil");
        archive_profile(&dir, 1).expect("archivage du second profil");

        // 2 profiles in total (1 active + 1 archived), but only one active: removing the
        // last active profile must be refused.
        assert!(
            delete_profile(&dir, password, 0).is_err(),
            "supprimer le seul profil actif restant doit être refusé même si un profil archivé existe"
        );
        assert_eq!(
            list_profiles(&dir).len(),
            1,
            "le profil actif ne doit pas avoir été supprimé"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_profiles_defaults_to_a_single_principal_profile_when_no_file_exists() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_profiles_default_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let profiles = list_profiles(&dir);
        assert_eq!(
            profiles.len(),
            1,
            "un coffre pré-existant sans profiles.json doit avoir un seul profil implicite"
        );
        assert_eq!(profiles[0].index, 0);
        assert_eq!(profiles[0].label, DEFAULT_PROFILE_LABEL);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_wallet_end_to_end_supports_adding_a_second_profile() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_profiles_create_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";

        create_wallet(&dir, password).expect("création du wallet");
        let initial = list_profiles(&dir);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].index, 0);

        let second =
            create_profile(&dir, Some(password), "Épargne").expect("création d'un second profil");
        assert_eq!(
            second.profile.index, 1,
            "le second profil doit prendre l'index suivant, jamais réutiliser 0"
        );
        assert_eq!(second.profile.label, "Épargne");
        // A different profile must deterministically derive a different address (same
        // seed, different index); otherwise "several profiles" would be pointless.
        let second_evm = second
            .addresses
            .expect("mot de passe fourni : l'adresse doit être dérivée tout de suite")
            .evm;
        assert_ne!(second_evm, initial_addresses_for(&dir, password).evm);

        let all = list_profiles(&dir);
        assert_eq!(
            all.len(),
            2,
            "le nouveau profil doit être persisté à côté du premier"
        );

        // A full unlock must return the addresses of BOTH profiles in a single call (see
        // the docs of `unlock_wallet`), without asking for the password again.
        let unlocked = unlock_wallet(&dir, password).expect("déverrouillage");
        assert_eq!(unlocked.len(), 2);
        assert!(unlocked.iter().all(|p| p.addresses.is_some()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regenerating a kit must neither change the addresses (same seed, same profiles)
    /// nor require a different vault: only new throwaway PGP identities/passphrases are
    /// produced on each call.
    #[test]
    fn regenerate_backup_kit_produces_a_fresh_valid_kit_without_touching_addresses() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_regen_backup_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";

        let created = create_wallet(&dir, password).expect("création du wallet");
        let addresses_before = unlock_wallet(&dir, password).unwrap();

        let kit1 = regenerate_backup_kit(&dir, password).expect("première régénération");
        let kit2 = regenerate_backup_kit(&dir, password).expect("seconde régénération");
        assert_eq!(kit1.len(), 3);
        assert_eq!(kit2.len(), 3);
        // Two separate regenerations must produce different PGP identities (fresh
        // passphrases each time), not the same pair reused.
        assert_ne!(kit1[0].passphrase, kit2[0].passphrase);

        // The new kit must be a real, working Shamir split of THE SAME master entropy as
        // the one protected by the vault: 2 of its 3 shares must recover the same
        // addresses as before the regeneration.
        let share1 = decrypt_with_armored_privkey(
            &kit1[0].encrypted_share,
            &dir.join("tmp_test_decrypt_0.asc"),
            &kit1[0].privkey_armored,
            &kit1[0].passphrase,
        )
        .unwrap();
        let share2 = decrypt_with_armored_privkey(
            &kit1[1].encrypted_share,
            &dir.join("tmp_test_decrypt_1.asc"),
            &kit1[1].privkey_armored,
            &kit1[1].passphrase,
        )
        .unwrap();
        let recovered =
            shamir::reconstruct_secret(2, &[share1.as_slice(), share2.as_slice()]).unwrap();
        let recovered_addresses = derive_addresses(&recovered, 0).unwrap();
        assert_eq!(
            recovered_addresses.evm,
            addresses_before[0].addresses.as_ref().unwrap().evm
        );

        assert_eq!(
            created.addresses.evm,
            addresses_before[0].addresses.as_ref().unwrap().evm
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_profile_without_password_registers_label_but_defers_the_address() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_profiles_no_password_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        let profile = create_profile(&dir, None, "Sans mdp").expect("création sans mot de passe");
        assert_eq!(profile.profile.index, 1);
        assert!(
            profile.addresses.is_none(),
            "sans mot de passe, l'adresse ne doit pas être dérivée tout de suite"
        );

        // The address must still appear at the next full unlock, since the profile (label
        // + index) was persisted.
        let unlocked = unlock_wallet(&dir, password).expect("déverrouillage");
        let deferred = unlocked
            .iter()
            .find(|p| p.profile.index == 1)
            .expect("le profil doit être persisté");
        assert!(
            deferred.addresses.is_some(),
            "l'adresse doit être dérivable au prochain déverrouillage"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Guard against unauthenticated, unbounded growth of `profiles.json`: the
    /// passwordless path of `create_profile` requires no authentication, so without a
    /// cap a script could create any number of profiles, slowing down `unlock_wallet`
    /// (which derives every known profile on each unlock) for the real owner.
    #[test]
    fn create_profile_without_password_is_capped() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_profiles_cap_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        // The default profile already counts as 1: (MAX_PROFILES - 1) more creations must
        // succeed, and the next one must fail.
        for i in 0..(MAX_PROFILES - 1) {
            create_profile(&dir, None, &format!("Profil {i}"))
                .expect("sous le plafond, la création doit réussir");
        }
        assert_eq!(list_profiles(&dir).len(), MAX_PROFILES);
        assert!(
            create_profile(&dir, None, "Un de trop").is_err(),
            "au-delà du plafond, la création doit être refusée"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn initial_addresses_for(dir: &Path, password: &str) -> Addresses {
        unlock_wallet(dir, password)
            .unwrap()
            .into_iter()
            .find(|p| p.profile.index == 0)
            .unwrap()
            .addresses
            .unwrap()
    }

    #[test]
    fn no_lockout_below_free_attempts_threshold() {
        for n in 0..MAX_FREE_ATTEMPTS {
            assert_eq!(
                required_lockout_secs(n),
                0,
                "{n} échecs ne devrait pas encore déclencher de délai"
            );
        }
    }

    #[test]
    fn lockout_grows_and_caps() {
        let first = required_lockout_secs(MAX_FREE_ATTEMPTS);
        assert_eq!(first, BASE_LOCKOUT_SECS);
        let second = required_lockout_secs(MAX_FREE_ATTEMPTS + 1);
        assert!(
            second > first,
            "le délai doit croître avec les échecs supplémentaires"
        );
        // Even with a huge number of failures, the delay must never exceed the cap (and
        // above all must not overflow arithmetically on `1u64 << extra`).
        let capped = required_lockout_secs(u32::MAX);
        assert_eq!(capped, MAX_LOCKOUT_SECS);
    }

    #[test]
    fn unlock_attempts_roundtrip_via_disk() {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_lockout_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        assert!(
            enforce_unlock_lockout(&dir).is_ok(),
            "aucun échec enregistré : pas de verrou"
        );

        for _ in 0..MAX_FREE_ATTEMPTS {
            record_unlock_failure(&dir);
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "après {MAX_FREE_ATTEMPTS} échecs, une nouvelle tentative doit être bloquée"
        );

        reset_unlock_attempts(&dir);
        assert!(
            enforce_unlock_lockout(&dir).is_ok(),
            "reset_unlock_attempts doit lever le verrou"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Guard against the regression found during an audit: `decrypt_incoming_message`
    /// called `pgp_engine::decrypt_share` directly with the device password, without going
    /// through `unlock_seed`, so a wrong password there never fed the failure counter.
    /// That offered a second door for guessing the password with no attempt limit at all
    /// (whereas `unlock_wallet`/`send_*`/`delete_profile`/`regenerate_backup_kit` are all
    /// subject to it). This test would fail if that back door came back.
    #[test]
    fn decrypt_incoming_message_is_covered_by_the_same_lockout_as_unlock_wallet() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_decrypt_lockout_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        for _ in 0..MAX_FREE_ATTEMPTS {
            assert!(decrypt_incoming_message(&dir, "mauvais mot de passe", "peu importe").is_err());
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "les échecs de decrypt_incoming_message doivent déclencher le même verrou que unlock_wallet"
        );
        // Since the lock is shared, even the RIGHT password stays blocked while it is active.
        assert!(unlock_wallet(&dir, password).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Guard against the race we already hit (non-atomic read-modify-write of the
    /// on-disk counter): without `UNLOCK_MUTEX` serializing access, concurrent threads
    /// would lose updates and the final counter would be lower than the real number of
    /// failures.
    #[test]
    fn concurrent_failures_are_not_lost_under_the_mutex() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_lockout_race_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        reset_unlock_attempts(&dir);

        const THREADS: usize = 20;
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    let _serialize = UNLOCK_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
                    record_unlock_failure(&dir);
                });
            }
        });

        let attempts = read_unlock_attempts(&dir);
        assert_eq!(
            attempts.consecutive_failures, THREADS as u32,
            "chaque échec concurrent doit être compté, aucun ne doit être perdu"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Guard against a bug introduced by the fix itself: without the
    /// `reset_unlock_attempts` added to `create_wallet`, a leftover failure counter
    /// (e.g. a file left by an interrupted `reset_wallet`) could have made a freshly
    /// created vault start out "on hold", blocking the user's very first legitimate
    /// unlock.
    #[test]
    fn create_wallet_clears_stale_lockout_state() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_create_lockout_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        for _ in 0..(MAX_FREE_ATTEMPTS + 2) {
            record_unlock_failure(&dir);
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "précondition : le verrou doit être actif avant la création du coffre"
        );

        create_wallet(&dir, "un mot de passe de test bien assez long")
            .expect("la création doit réussir malgré le fichier de verrou résiduel");

        assert!(
            enforce_unlock_lockout(&dir).is_ok(),
            "un coffre tout juste créé ne doit jamais hériter d'un verrou résiduel"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Biometric unlock --------------------------------------------------
    //
    // `FakeSealer` does NO real sealing (the "sealed" blob is the secret in the
    // clear): what is tested here is the orchestration in api.rs (files, re-encrypting
    // the vault, anti-brute-force lock), not the NCrypt/TPM cryptography itself; see
    // `windows_hello.rs` and the manual spike for that part, which cannot be
    // automated.
    struct FakeSealer {
        fail_enroll: bool,
    }

    impl SecretSealer for FakeSealer {
        fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
            if self.fail_enroll {
                return Err(anyhow::anyhow!(
                    "échec simulé du scelleur (TPM indisponible)"
                ));
            }
            Ok(("fake-tpm-key".to_string(), secret.to_vec()))
        }
        fn unlock(&self, _key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(sealed_blob.to_vec()))
        }
        fn remove(&self, _key_name: &str) -> Result<()> {
            Ok(())
        }
    }

    /// A sealer whose enrollment succeeds but whose `remove` records every call
    /// (through `Cell`, so `&self` is enough): used to check that a "TPM" key is
    /// cleaned up if a step AFTER enrollment fails.
    struct TrackingSealer {
        removed: std::cell::Cell<bool>,
    }

    impl SecretSealer for TrackingSealer {
        fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
            Ok(("fake-tpm-key".to_string(), secret.to_vec()))
        }
        fn unlock(&self, _key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(sealed_blob.to_vec()))
        }
        fn remove(&self, _key_name: &str) -> Result<()> {
            self.removed.set(true);
            Ok(())
        }
    }

    /// Simulates the user cancelling the Windows Hello prompt (code NTE_USER_CANCELLED,
    /// see `is_user_cancellation`).
    struct CancellingSealer;

    impl SecretSealer for CancellingSealer {
        fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
            Ok(("fake-tpm-key".to_string(), secret.to_vec()))
        }
        fn unlock(&self, _key_name: &str, _sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Err(anyhow::anyhow!("vérification Windows Hello refusée, annulée ou échouée : L'opération a été annulée par l'utilisateur. (code 0x800704c7)"))
        }
        fn remove(&self, _key_name: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn enroll_biometric_unlock_cleans_up_the_sealer_key_if_a_later_step_fails() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_bio_cleanup_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        // Breaks reading the device's public key (deleted) to force a failure AFTER the
        // sealer has already "created" its key, the only moment a cleanup is needed (see
        // enroll_biometric_unlock_with).
        std::fs::remove_file(dir.join(DEVICE_PUBKEY_FILE)).unwrap();

        let sealer = TrackingSealer {
            removed: std::cell::Cell::new(false),
        };
        assert!(enroll_biometric_unlock_with(&dir, password, &sealer).is_err());
        assert!(
            sealer.removed.get(),
            "la clé du scelleur doit être nettoyée après un échec post-enrôlement"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Direct guard against the bug found during an independent audit: `reset_wallet`
    /// only touched the "device" (password) files, never the biometric enrollment,
    /// leaving an orphaned key in the TPM (here, in the test sealer) forever, plus 4
    /// obsolete `device_biometric_*` files on disk.
    #[test]
    fn reset_wallet_also_cleans_up_the_biometric_enrollment() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_reset_bio_cleanup_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");
        assert!(
            biometric_unlock_enrolled(&dir),
            "la biométrie doit être active avant le test"
        );

        let sealer = TrackingSealer {
            removed: std::cell::Cell::new(false),
        };
        reset_wallet_with(&dir, &sealer).expect("réinitialisation du wallet");

        assert!(sealer.removed.get(), "la clé TPM doit être supprimée par reset_wallet, pas seulement par disable_biometric_unlock");
        assert!(
            !biometric_unlock_enrolled(&dir),
            "aucune trace d'enrôlement biométrique ne doit survivre à une réinitialisation"
        );
        for file in [
            DEVICE_BIOMETRIC_PUBKEY_FILE,
            DEVICE_BIOMETRIC_PRIVKEY_FILE,
            DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
            DEVICE_BIOMETRIC_KEY_META_FILE,
        ] {
            assert!(
                !dir.join(file).exists(),
                "{file} ne doit pas survivre à reset_wallet"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Shielded Zcash database still open (as during a sync): Windows refuses to delete
    /// it. Seen on 2026-10-07: the failure was ignored and the old wallet's database
    /// stayed. The reset now stops BEFORE touching the vault, then succeeds once the
    /// database is closed.
    #[cfg(windows)]
    #[test]
    fn reset_stops_before_the_vault_when_state_stays_open() {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_open_state_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        create_wallet(&dir, "un mot de passe de test bien assez long").expect("création du wallet");
        let db = rusqlite::Connection::open(dir.join("zcash_shielded.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);")
            .unwrap();
        let err = reset_wallet_with(&dir, &FakeSealer { fail_enroll: false })
            .expect_err("base ouverte : refus attendu");
        assert!(err.to_string().contains("zcash_shielded.sqlite"), "{err}");
        assert!(device_vault_exists(&dir), "coffre supprimé malgré l'échec");
        drop(db);
        reset_wallet_with(&dir, &FakeSealer { fail_enroll: false })
            .expect("base refermée : réinitialisation");
        assert!(!dir.join("zcash_shielded.sqlite").exists() && !device_vault_exists(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// State tied to a seed (shielded Zcash, Monero, paid recipients) survives neither
    /// a reset nor a restore.
    #[test]
    fn wallet_change_removes_seed_bound_state() {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_seed_state_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files = [
            "zcash_shielded.sqlite",
            "monero_wallet.json",
            "sent_recipients.json",
        ];
        let plant = || {
            files
                .iter()
                .for_each(|f| std::fs::write(dir.join(f), b"ancien").unwrap())
        };
        create_wallet(&dir, "un mot de passe de test bien assez long").expect("création du wallet");
        plant();
        reset_wallet_with(&dir, &FakeSealer { fail_enroll: false }).expect("réinitialisation");
        assert!(
            files.iter().all(|f| !dir.join(f).exists()),
            "réinitialisation"
        );
        plant();
        remove_seed_bound_state(&dir).expect("restauration (même nettoyage)");
        assert!(
            files.iter().all(|f| !dir.join(f).exists()),
            "restauration (même nettoyage)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Solana recipient address type ---------------------------------------

    #[test]
    fn solana_recipient_must_be_a_wallet() {
        let on_curve = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let off_curve =
            sol_spl::find_associated_token_address(&on_curve, &sol_spl::usdc_mint_mainnet());
        assert!(
            !sol_spl::is_on_curve(&off_curve),
            "une ATA est hors-courbe par construction"
        );

        let state = |owner: &str| sol_rpc::AccountState {
            lamports: 1,
            owner: owner.to_string(),
            data: vec![],
        };
        classify_solana_recipient(&on_curve, Some(&state(SYSTEM_PROGRAM_ID)))
            .expect("portefeuille existant");
        classify_solana_recipient(&off_curve, Some(&state(SYSTEM_PROGRAM_ID)))
            .expect("coffre multisig (PDA détenue par le système)");
        classify_solana_recipient(&on_curve, None).expect("portefeuille neuf");

        let err =
            classify_solana_recipient(&off_curve, Some(&state(TOKEN_PROGRAM_ID))).unwrap_err();
        assert!(err.to_string().contains("compte de jetons"), "{err}");
        assert!(
            classify_solana_recipient(&off_curve, Some(&state(TOKEN_2022_PROGRAM_ID))).is_err()
        );
        assert!(classify_solana_recipient(
            &on_curve,
            Some(&state("BPFLoaderUpgradeab1e11111111111111111111111"))
        )
        .is_err());
        let err = classify_solana_recipient(&off_curve, None).unwrap_err();
        assert!(err.to_string().contains("aucune clé privée"), "{err}");
    }

    /// Real mainnet addresses: a wallet, ITS USDC account (the typical mistake of a user
    /// copying the address from an explorer), the USDC mint and the Jupiter program.
    /// `cargo test -- --ignored solana_recipient_check_on_real`
    #[test]
    #[ignore]
    fn solana_recipient_check_on_real_mainnet_addresses() {
        let net = &wallet_flow::SOLANA_MAINNET;
        check_solana_recipient("5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9", net)
            .expect("vrai portefeuille accepté");
        for (label, address) in [
            (
                "compte USDC de ce portefeuille",
                "FzbcyEZ9m8xjtergWgWDq7mfPoHEbboBF791B6cTpzbq",
            ),
            ("mint USDC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            (
                "programme Jupiter",
                "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            ),
        ] {
            let err = check_solana_recipient(address, net).expect_err(label);
            println!("{label} refusé : {err}");
        }
    }

    // --- Fees and quotes: "sign what you see" ---------------------------------

    #[test]
    fn evm_gas_price_is_capped_on_mainnet_only() {
        let cap = wallet_flow::ETHEREUM_MAINNET
            .max_gas_price_wei
            .expect("plafond sur mainnet");
        assert!(check_evm_gas_price(&wallet_flow::ETHEREUM_MAINNET, cap).is_ok());
        let err = check_evm_gas_price(&wallet_flow::ETHEREUM_MAINNET, 100_000 * 1_000_000_000)
            .unwrap_err();
        assert!(err.to_string().contains("anormalement élevé"), "{err}");
        assert!(
            check_evm_gas_price(&wallet_flow::SEPOLIA, 100_000 * 1_000_000_000).is_ok(),
            "pas de plafond sur testnet"
        );
    }

    fn shown_quote(memo_limit: u64) -> thorchain_rpc::SwapQuote {
        thorchain_rpc::SwapQuote {
            inbound_address: "bc1qvaultvaultvaultvaultvaultvaultvault00".into(),
            router: None,
            memo: format!(
                "=:b:bc1qdest:{memo_limit}:{}:80",
                thorchain_rpc::AFFILIATE_ADDRESS
            ),
            expected_amount_out: 1_000_000,
            total_fees: None,
            recommended_gas_rate: None,
            affiliate: Some(thorchain_rpc::AFFILIATE_ADDRESS.to_string()),
        }
    }

    /// Cost of a name depending on its state: free = registration + one year, ours =
    /// one more year, taken = nothing.
    #[test]
    fn name_deposit_follows_the_state() {
        assert_eq!(
            name_deposit(&NameState::Free, 1_000_000_000, 105_120_000),
            Some(1_105_120_000)
        );
        assert_eq!(
            name_deposit(
                &NameState::Ours {
                    years_left: 0.5,
                    points_to_affiliate: true
                },
                1_000_000_000,
                105_120_000
            ),
            Some(105_120_000)
        );
        assert_eq!(
            name_deposit(&NameState::Taken, 1_000_000_000, 105_120_000),
            None
        );
    }

    #[test]
    fn refreshed_quote_must_match_what_was_shown() {
        let shown = shown_quote(990_000);
        ensure_quote_matches_shown(
            &thorchain_rpc::THORCHAIN,
            &shown_quote(990_000),
            &shown,
            "BTC.BTC",
            "bc1qdest",
        )
        .expect("identique");

        let mut churned = shown_quote(990_000);
        churned.inbound_address = "bc1qautrevaultautrevaultautrevault00000".into();
        assert!(
            ensure_quote_matches_shown(
                &thorchain_rpc::THORCHAIN,
                &churned,
                &shown,
                "BTC.BTC",
                "bc1qdest"
            )
            .is_err(),
            "vault changé"
        );

        let mut rerouted = shown_quote(990_000);
        rerouted.router = Some("0xAutreRouteur".into());
        assert!(
            ensure_quote_matches_shown(
                &thorchain_rpc::THORCHAIN,
                &rerouted,
                &shown,
                "BTC.BTC",
                "bc1qdest"
            )
            .is_err(),
            "routeur changé"
        );

        // Rate dropped to 950,000: the new minimum output (99% of 950,000) is below 99% of
        // what was SHOWN (1,000,000), so refused.
        let price_dropped = shown_quote(940_500);
        let err = ensure_quote_matches_shown(
            &thorchain_rpc::THORCHAIN,
            &price_dropped,
            &shown,
            "BTC.BTC",
            "bc1qdest",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cours a bougé"), "{err:#}");

        // From Zcash (Maya, no affiliate): a 4-field memo reread the same way.
        let mut zec_shown = shown_quote(990_000);
        zec_shown.memo = "=:b:bc1qdest:990000".into();
        zec_shown.affiliate = None;
        let zec_fresh = |memo: &str| thorchain_rpc::SwapQuote {
            memo: memo.into(),
            ..shown_quote(0)
        };
        ensure_quote_matches_shown(
            &thorchain_rpc::MAYA,
            &zec_fresh("=:b:bc1qdest:990000"),
            &zec_shown,
            "BTC.BTC",
            "bc1qdest",
        )
        .expect("identique");
        assert!(ensure_quote_matches_shown(
            &thorchain_rpc::MAYA,
            &zec_fresh("=:b:bc1qautre:990000"),
            &zec_shown,
            "BTC.BTC",
            "bc1qdest"
        )
        .is_err());
        assert!(ensure_quote_matches_shown(
            &thorchain_rpc::MAYA,
            &zec_fresh("=:b:bc1qdest:990000:maya1x:50"),
            &zec_shown,
            "BTC.BTC",
            "bc1qdest"
        )
        .is_err());
    }

    // --- verify_swap_effects: one attack per case -------------------------

    const USER: [u8; 32] = [1u8; 32];
    const ATTACKER: [u8; 32] = [9u8; 32];
    const USDC_MINT_T: [u8; 32] = [2u8; 32];
    const OTHER_MINT: [u8; 32] = [3u8; 32];
    const ATA_RENT: u64 = 2_039_280;
    const SOL: u64 = 1_000_000_000;

    fn native_mint_bytes() -> [u8; 32] {
        bs58::decode(jupiter_rpc::SOL_MINT)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn token_data(
        mint: [u8; 32],
        owner: [u8; 32],
        amount: u64,
        delegate: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(&mint);
        d[32..64].copy_from_slice(&owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        if let Some(delegate) = delegate {
            d[72..76].copy_from_slice(&1u32.to_le_bytes());
            d[76..108].copy_from_slice(&delegate);
        }
        d[108] = 1; // initialized
        d
    }

    fn sys(lamports: u64) -> Option<sol_rpc::AccountState> {
        Some(sol_rpc::AccountState {
            lamports,
            owner: SYSTEM_PROGRAM_ID.to_string(),
            data: vec![],
        })
    }

    fn tok(lamports: u64, data: Vec<u8>) -> Option<sol_rpc::AccountState> {
        Some(sol_rpc::AccountState {
            lamports,
            owner: TOKEN_PROGRAM_ID.to_string(),
            data,
        })
    }

    fn addrs(n: usize) -> Vec<String> {
        let mut v = vec![bs58::encode(USER).into_string()];
        for i in 1..n {
            v.push(format!("compte{i}"));
        }
        v
    }

    fn sol_to_usdc_limits(amount: u64) -> SwapEffectLimits {
        SwapEffectLimits {
            user: USER,
            max_lamport_loss: amount + JUPITER_SWAP_FEE_BUDGET_LAMPORTS,
            input_token: None,
            min_output: MinOutput::Token(USDC_MINT_T, 0),
        }
    }

    /// [main account, associated account (standard address) of `mint`].
    fn addrs_with_ata(mint: [u8; 32]) -> Vec<String> {
        vec![
            bs58::encode(USER).into_string(),
            bs58::encode(sol_spl::find_associated_token_address(&USER, &mint)).into_string(),
        ]
    }

    #[test]
    fn swap_effects_accept_a_legit_sol_to_usdc_swap_including_ata_creation() {
        let pre = vec![sys(10 * SOL), None];
        let post = vec![
            sys(10 * SOL - SOL - ATA_RENT - 10_000),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 150_000_000, None)),
        ];
        verify_swap_effects(
            &addrs_with_ata(USDC_MINT_T),
            &pre,
            &post,
            &sol_to_usdc_limits(SOL),
        )
        .expect("swap légitime + création de l'ATA");
    }

    /// Audit round 22: output delivered to a token account created at a NON-standard
    /// address (invisible in the app) must be refused, even if the amount is right;
    /// only the address differs from the legitimate case above.
    #[test]
    fn swap_effects_reject_output_delivered_to_a_non_standard_token_account() {
        let pre = vec![sys(10 * SOL), None];
        let post = vec![
            sys(10 * SOL - SOL - ATA_RENT - 10_000),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 150_000_000, None)),
        ];
        let err =
            verify_swap_effects(&addrs(2), &pre, &post, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("non standard"), "{err}");
    }

    #[test]
    fn swap_effects_reject_a_sol_drain() {
        let pre = vec![sys(10 * SOL)];
        let post = vec![sys(SOL / 2)];
        let err =
            verify_swap_effects(&addrs(1), &pre, &post, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("coûterait"), "{err}");
    }

    #[test]
    fn swap_effects_reject_approve_set_authority_and_assign() {
        let existing = || tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, None));
        let approve = vec![
            sys(10 * SOL - SOL),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, Some(ATTACKER))),
        ];
        let err = verify_swap_effects(
            &addrs(2),
            &[sys(10 * SOL), existing()],
            &approve,
            &sol_to_usdc_limits(SOL),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Approve"), "{err}");

        let set_authority = vec![
            sys(10 * SOL - SOL),
            tok(ATA_RENT, token_data(USDC_MINT_T, ATTACKER, 100, None)),
        ];
        let err = verify_swap_effects(
            &addrs(2),
            &[sys(10 * SOL), existing()],
            &set_authority,
            &sol_to_usdc_limits(SOL),
        )
        .unwrap_err();
        assert!(err.to_string().contains("SetAuthority"), "{err}");

        let assign = vec![Some(sol_rpc::AccountState {
            lamports: 9 * SOL,
            owner: "ProgrammeAttaquant".into(),
            data: vec![],
        })];
        let err = verify_swap_effects(
            &addrs(1),
            &[sys(10 * SOL)],
            &assign,
            &sol_to_usdc_limits(SOL),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Assign"), "{err}");
    }

    #[test]
    fn swap_effects_bound_the_input_token_and_protect_every_other_token() {
        let limits = SwapEffectLimits {
            user: USER,
            max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS,
            input_token: Some((USDC_MINT_T, 10)),
            min_output: MinOutput::Lamports(0),
        };
        let pre = vec![
            sys(SOL),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, None)),
            tok(ATA_RENT, token_data(OTHER_MINT, USER, 1000, None)),
        ];
        let legit = vec![
            sys(SOL + SOL / 2),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 90, None)),
            pre[2].clone(),
        ];
        verify_swap_effects(&addrs(3), &pre, &legit, &limits).expect("USDC -> SOL légitime");

        let overspend = vec![
            legit[0].clone(),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 50, None)),
            pre[2].clone(),
        ];
        assert!(
            verify_swap_effects(&addrs(3), &pre, &overspend, &limits).is_err(),
            "plus d'USDC que confirmé"
        );

        let other_drained = vec![
            legit[0].clone(),
            legit[1].clone(),
            tok(ATA_RENT, token_data(OTHER_MINT, USER, 0, None)),
        ];
        assert!(
            verify_swap_effects(&addrs(3), &pre, &other_drained, &limits).is_err(),
            "autre jeton vidé"
        );
    }

    #[test]
    fn swap_effects_track_wsol_value_and_reject_trapped_accounts() {
        let wsol = native_mint_bytes();
        let pre = vec![
            sys(5 * SOL),
            tok(ATA_RENT + SOL, token_data(wsol, USER, SOL, None)),
        ];
        let limits = SwapEffectLimits {
            user: USER,
            max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS,
            input_token: None,
            min_output: MinOutput::Lamports(0),
        };
        // wSOL account closed, value returned to the user: legitimate.
        let returned = vec![sys(5 * SOL + SOL + ATA_RENT - 10_000), None];
        verify_swap_effects(&addrs(2), &pre, &returned, &limits)
            .expect("désenveloppement légitime");
        // wSOL account closed, value gone elsewhere: refused.
        let stolen = vec![sys(5 * SOL - 10_000), None];
        assert!(
            verify_swap_effects(&addrs(2), &pre, &stolen, &limits).is_err(),
            "wSOL détourné"
        );

        // An EXISTING account handed to the user, or one created with a delegate: refused.
        let foreign = tok(ATA_RENT, token_data(USDC_MINT_T, ATTACKER, 0, None));
        let given = vec![
            sys(5 * SOL - 10_000),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 0, None)),
        ];
        assert!(
            verify_swap_effects(&addrs(2), &[sys(5 * SOL), foreign], &given, &limits).is_err(),
            "compte cédé"
        );
        let trapped = vec![
            sys(5 * SOL - ATA_RENT - 10_000),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 0, Some(ATTACKER))),
        ];
        // At the standard address: it really is the delegate that must cause the refusal.
        let err = verify_swap_effects(
            &addrs_with_ata(USDC_MINT_T),
            &[sys(5 * SOL), None],
            &trapped,
            &limits,
        )
        .unwrap_err();
        assert!(err.to_string().contains("délégué"), "créé piégé : {err}");
    }

    /// "Take the SOL and return nothing": the loss stays within what is authorized (the
    /// amount sold), so only the output floor catches it.
    #[test]
    fn swap_effects_reject_taking_the_input_and_returning_nothing_or_too_little() {
        let mut limits = sol_to_usdc_limits(SOL);
        limits.min_output = MinOutput::Token(USDC_MINT_T, 149_000_000);
        let existing_ata = tok(ATA_RENT, token_data(USDC_MINT_T, USER, 0, None));
        let nothing = vec![sys(9 * SOL - 10_000), existing_ata.clone()];
        let err = verify_swap_effects(
            &addrs(2),
            &[sys(10 * SOL), existing_ata.clone()],
            &nothing,
            &limits,
        )
        .unwrap_err();
        assert!(err.to_string().contains("moins que le minimum"), "{err}");
        let enough = vec![
            sys(9 * SOL - 10_000),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 150_000_000, None)),
        ];
        verify_swap_effects(&addrs(2), &[sys(10 * SOL), existing_ata], &enough, &limits)
            .expect("sortie suffisante");

        // USDC -> SOL: the SOL received, fees deducted, must reach the minimum.
        let usdc_to_sol = SwapEffectLimits {
            user: USER,
            max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS,
            input_token: Some((USDC_MINT_T, 10)),
            min_output: MinOutput::Lamports(SOL / 2),
        };
        let pre = vec![
            sys(SOL),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, None)),
        ];
        let too_little = vec![
            sys(SOL + SOL / 10),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 90, None)),
        ];
        assert!(
            verify_swap_effects(&addrs(2), &pre, &too_little, &usdc_to_sol).is_err(),
            "SOL reçu insuffisant"
        );
        let fine = vec![
            sys(SOL + SOL / 2),
            tok(ATA_RENT, token_data(USDC_MINT_T, USER, 90, None)),
        ];
        verify_swap_effects(&addrs(2), &pre, &fine, &usdc_to_sol).expect("SOL reçu suffisant");
    }

    /// A real case reproduced (SOL -> USDC swap on mainnet): the user's wSOL account,
    /// closed by Jupiter's unwrapping, comes back from the simulation as "0 lamports,
    /// system program", not `null`.
    #[test]
    fn swap_effects_treat_a_zero_lamport_system_account_as_closed() {
        let wsol = native_mint_bytes();
        let pre = vec![
            sys(5 * SOL),
            tok(ATA_RENT + SOL, token_data(wsol, USER, SOL, None)),
        ];
        let post = vec![sys(5 * SOL + SOL + ATA_RENT - 10_000), sys(0)];
        let limits = SwapEffectLimits {
            user: USER,
            max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS,
            input_token: None,
            min_output: MinOutput::Lamports(0),
        };
        verify_swap_effects(&addrs(2), &pre, &post, &limits)
            .expect("compte fermé rapporté à 0 lamport");
    }

    #[test]
    fn swap_effects_require_the_user_main_account() {
        let addresses = vec!["pas_l_utilisateur".to_string()];
        assert!(verify_swap_effects(
            &addresses,
            &[sys(SOL)],
            &[sys(SOL)],
            &sol_to_usdc_limits(SOL)
        )
        .is_err());
    }

    /// EVM networks: unique identifiers and chains, a gas price cap on every real-funds
    /// network, OP Stack posting fees only where they exist.
    #[test]
    fn evm_networks_are_consistent() {
        let networks = wallet_flow::EVM_NETWORKS;
        for (i, a) in networks.iter().enumerate() {
            for b in &networks[i + 1..] {
                assert_ne!(a.id, b.id);
                assert_ne!(a.chain_id, b.chain_id);
            }
            assert_eq!(
                wallet_flow::evm_network(a.id).map(|n| n.chain_id),
                Some(a.chain_id)
            );
            assert_eq!(
                a.mainnet,
                a.max_gas_price_wei.is_some(),
                "{} : plafond sur fonds réels uniquement",
                a.id
            );
            assert!(
                a.rpc.starts_with("https://") && a.explorer_tx_prefix.starts_with("https://"),
                "{}",
                a.id
            );
        }
        assert!(wallet_flow::evm_network("inconnu").is_none());
        let op_stack: Vec<&str> = networks
            .iter()
            .filter(|n| n.op_stack_l1_fee)
            .map(|n| n.id)
            .collect();
        assert_eq!(
            op_stack,
            ["base_mainnet"],
            "frais L1 OP Stack : Base seulement"
        );
        let fee = EvmFee {
            gas_price: 2,
            gas_limit: 21_000,
            l1_fee: 5,
        };
        assert_eq!(fee.max_total().unwrap(), 42_005);
        assert!(EvmFee {
            gas_price: u128::MAX,
            gas_limit: 2,
            l1_fee: 0
        }
        .max_total()
        .is_err());
    }

    /// Fees read on EVERY real EVM network for a transfer: price under the cap, fixed
    /// limit (21,000) or estimated (Arbitrum), posting fees on Base. Read-only.
    /// `cargo test -- --ignored evm_fees_are_read_on_every --nocapture`
    #[test]
    #[ignore]
    fn evm_fees_are_read_on_every_real_network() {
        let from = "0x28C6c06298d514Db089934071355E5743bf21d60"; // public hot wallet (read-only)
        let to = "0x000000000000000000000000000000000000dEaD";
        for net in wallet_flow::EVM_NETWORKS.iter().filter(|n| n.mainnet) {
            let fee = evm_transfer_fee_for_confirmation(net, Some(from), to, "0")
                .unwrap_or_else(|e| panic!("{} : {e:#}", net.id));
            println!(
                "{:>18} : {:.4} gwei, gas {}, L1 {} wei, total {} wei",
                net.id,
                fee.gas_price as f64 / 1e9,
                fee.gas_limit,
                fee.l1_fee,
                fee.max_total().unwrap()
            );
            assert!(fee.gas_price > 0, "{}", net.id);
            assert!(fee.gas_limit >= 21_000, "{}", net.id);
            assert_eq!(fee.l1_fee > 0, net.op_stack_l1_fee, "{} : frais L1", net.id);
        }
    }

    /// Every contract in the token registry, reread on ITS blockchain: symbol and
    /// decimals of the ERC-20 contract; SPL Token program and decimals of the Solana
    /// mint. Then a real balance read through the app's code path (USDT of a known
    /// public wallet). Read-only.
    /// `cargo test -- --ignored token_contracts_match --nocapture`
    #[test]
    #[ignore]
    fn token_contracts_match_the_real_networks() {
        fn abi_string(answer: &[u8]) -> String {
            if answer.len() == 32 {
                return String::from_utf8_lossy(answer)
                    .trim_end_matches('\0')
                    .to_string();
            }
            let len = u128::from_be_bytes(answer[48..64].try_into().unwrap()) as usize;
            String::from_utf8_lossy(&answer[64..64 + len]).into_owned()
        }
        let caller = "0x000000000000000000000000000000000000dEaD";
        let mut mints = Vec::new();
        for token in tokens::TOKENS {
            for d in token.deployments {
                match d.kind {
                    tokens::TokenKind::Erc20 { contract } => {
                        let rpc =
                            eth_rpc::EthRpc::new(wallet_flow::evm_network(d.network).unwrap().rpc);
                        let symbol = abi_string(
                            &rpc.call_contract(caller, contract, 0, &[0x95, 0xd8, 0x9b, 0x41])
                                .unwrap(),
                        );
                        let decimals = rpc
                            .call_contract(caller, contract, 0, &[0x31, 0x3c, 0xe5, 0x67])
                            .unwrap();
                        println!(
                            "{:>7} {:>17} « {symbol} » {}",
                            token.symbol, d.network, decimals[31]
                        );
                        assert!(
                            symbol.eq_ignore_ascii_case(token.symbol),
                            "{} sur {} : symbole « {symbol} »",
                            token.id,
                            d.network
                        );
                        assert_eq!(decimals[31], d.decimals, "{} sur {}", token.id, d.network);
                    }
                    tokens::TokenKind::Spl { mint } => mints.push((token, d, mint.to_string())),
                    // Checked separately, metadata included: tokens::xstocks_match_the_real_mints.
                    tokens::TokenKind::Spl2022 { .. } => {}
                    tokens::TokenKind::Trc20 { contract } => {
                        let decimals = tron::trc20_decimals(contract).unwrap();
                        println!(
                            "{:>7} {:>17} TRC-20 {} décimales",
                            token.symbol, d.network, decimals
                        );
                        assert_eq!(decimals, d.decimals, "{} sur {}", token.id, d.network);
                    }
                }
            }
        }
        let addresses: Vec<String> = mints.iter().map(|(_, _, mint)| mint.clone()).collect();
        let states = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc)
            .multiple_accounts(&addresses)
            .unwrap();
        for ((token, d, mint), state) in mints.iter().zip(states) {
            let state = state.unwrap_or_else(|| panic!("mint {mint} introuvable"));
            println!(
                "{:>7} {:>17} {} décimales {}",
                token.symbol, d.network, state.owner, state.data[44]
            );
            assert_eq!(
                state.owner, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "{} : programme SPL Token attendu",
                token.id
            );
            assert_eq!(
                state.data[44], d.decimals,
                "{} : décimales du mint",
                token.id
            );
        }
        let (usdt, decimals) = get_token_balance(
            "usdt",
            "evm_mainnet",
            "0x28C6c06298d514Db089934071355E5743bf21d60",
        )
        .unwrap();
        assert_eq!(decimals, 6);
        assert!(usdt > 0, "portefeuille public avec de l'USDT");
    }

    /// ERC-20 `transfer` calldata: selector, recipient and amount as 32-byte words.
    #[test]
    fn erc20_transfer_data_is_abi_encoded() {
        let to = [0x11u8; 20];
        let data = erc20_transfer_data(&to, 1_000_000);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &to);
        assert_eq!(
            u128::from_be_bytes(data[52..68].try_into().unwrap()),
            1_000_000
        );
        assert!(data[36..52].iter().all(|&b| b == 0));
    }

    /// `approve(spender, amount)`: selector 0x095ea7b3, address then amount.
    #[test]
    fn erc20_approve_data_is_abi_encoded() {
        let spender = [0x22u8; 20];
        let data = erc20_approve_data(&spender, 7);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(&data[16..36], &spender);
        assert_eq!(data[67], 7);
        assert!(data[36..67].iter().all(|&b| b == 0));
    }

    /// REAL networks, without spending anything: the THORChain router on BNB Chain and Avalanche
    /// accepts our native deposit (gas estimate from a public wallet holding those coins), and
    /// the fees for a swap from a Base token count the approval and the posting to Ethereum.
    /// `cargo test -- --ignored thorchain_new_networks_accept_our_deposits --nocapture`
    #[test]
    #[ignore]
    fn thorchain_new_networks_accept_our_deposits() {
        let holder = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let btc = thorchain_rpc::asset("btc", "btc_mainnet").unwrap();
        // Holders of the native coin (estimate only, nothing is signed): a public wallet,
        // or the WETH contract, which holds the deposited ETH.
        for (coin, network, amount, from_addr) in [
            (
                "evm",
                "evm_mainnet",
                "0.01",
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            ),
            (
                "evm",
                "base_mainnet",
                "0.01",
                "0x4200000000000000000000000000000000000006",
            ),
            ("bnb", "bsc_mainnet", "0.05", holder),
            ("avax", "avax_mainnet", "1", holder),
        ] {
            let from = thorchain_rpc::asset(coin, network).unwrap();
            let net = wallet_flow::evm_network(network).unwrap();
            let quote = get_swap_quote(
                &thorchain_rpc::THORCHAIN,
                from,
                btc,
                amount,
                "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz",
            )
            .unwrap();
            let router = quote.router.clone().unwrap();
            let vault = wallet_flow::parse_evm_address(&quote.inbound_address).unwrap();
            let expiration = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600;
            let value = wallet_flow::parse_eth_to_wei(amount).unwrap();
            let calldata = eth_tx::thorchain_deposit_calldata(
                &vault,
                &[0u8; 20],
                value,
                &quote.memo,
                expiration,
            );
            let gas = eth_rpc::EthRpc::new(net.rpc)
                .estimate_gas(from_addr, &router, value, &calldata)
                .unwrap_or_else(|e| panic!("{network} : {e:#}"));
            println!(
                "{network} : dépôt {amount} {} vers BTC, routeur {router}, gas estimé {gas}",
                from.symbol
            );
            assert!(gas < EVM_SWAP_MAX_GAS_LIMIT);
        }
        // Maya, Arbitrum: the same `depositWithExpiry` router, accepted with the amount
        // sent.
        let arb_eth = thorchain_rpc::MAYA
            .asset("evm", "arbitrum_mainnet")
            .unwrap();
        let maya_btc = thorchain_rpc::MAYA.asset("btc", "btc_mainnet").unwrap();
        let quote = get_swap_quote(
            &thorchain_rpc::MAYA,
            arb_eth,
            maya_btc,
            "0.01",
            "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz",
        )
        .unwrap();
        let router = quote.router.clone().unwrap();
        let vault = wallet_flow::parse_evm_address(&quote.inbound_address).unwrap();
        let value = wallet_flow::parse_eth_to_wei("0.01").unwrap();
        let expiration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let calldata =
            eth_tx::thorchain_deposit_calldata(&vault, &[0u8; 20], value, &quote.memo, expiration);
        let arbitrum = wallet_flow::evm_network("arbitrum_mainnet").unwrap();
        let gas = eth_rpc::EthRpc::new(arbitrum.rpc)
            .estimate_gas(
                "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
                &router,
                value,
                &calldata,
            )
            .unwrap();
        println!(
            "Maya arbitrum_mainnet : dépôt 0.01 ETH vers BTC, routeur {router}, gas estimé {gas}"
        );

        let usdc_base = thorchain_rpc::asset("usdc", "base_mainnet").unwrap();
        let eth = thorchain_rpc::asset("evm", "evm_mainnet").unwrap();
        let quote =
            get_swap_quote(&thorchain_rpc::THORCHAIN, usdc_base, eth, "100", holder).unwrap();
        let base = wallet_flow::evm_network("base_mainnet").unwrap();
        let gas_price = evm_gas_price_for_confirmation(base).unwrap();
        let fees = evm_swap_fees(base, usdc_base, &quote, "100", gas_price, Some(holder)).unwrap();
        println!(
            "USDC Base -> ETH : {} autorisation(s), frais max {} wei (L1 dépôt {} wei)",
            fees.approvals,
            fees.max_total().unwrap(),
            fees.deposit.l1_fee
        );
        assert!(
            fees.deposit.l1_fee > 0,
            "Base : frais de publication sur Ethereum"
        );
        assert!(
            fees.approvals >= 1,
            "aucune autorisation accordée au routeur par ce portefeuille"
        );
    }

    /// Checks against the real network how much gas a `depositWithExpiry` on the THORChain
    /// router REALLY costs (an `eth_estimateGas` simulation from a funded public address,
    /// read-only), compared with the intrinsic gas.
    /// `cargo test -- --ignored thorchain_router_deposit_gas --nocapture`
    #[test]
    #[ignore]
    fn thorchain_router_deposit_gas_vs_intrinsic_on_the_real_network() {
        let from = "0x28C6c06298d514Db089934071355E5743bf21d60"; // public hot wallet (read-only)
        let quote = thorchain_rpc::quote_swap(
            "ETH.ETH",
            "BTC.BTC",
            1_000_000,
            "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz",
        )
        .unwrap();
        let router = quote.router.clone().unwrap();
        let vault = wallet_flow::parse_evm_address(&quote.inbound_address).unwrap();
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let calldata =
            eth_tx::thorchain_deposit_calldata(&vault, &[0u8; 20], 0, &quote.memo, expiration);
        let value = 10_000_000_000_000_000u128; // 0.01 ETH
        let rpc = eth_rpc::EthRpc::new(wallet_flow::ETHEREUM_MAINNET.rpc);
        let estimated = rpc
            .estimate_gas(from, &router, value, &calldata)
            .expect("estimation réelle");
        let intrinsic = eth_tx::intrinsic_gas(&calldata);
        println!("gas intrinsèque = {intrinsic}, gas réellement nécessaire (eth_estimateGas) = {estimated}");
    }

    /// Calibration AND a guard against false rejections: real Jupiter swaps built for a
    /// heavily funded public mainnet address (a Binance hot wallet, read-only: simulation
    /// without a signature), run through the REAL production code path
    /// (`check_swap_effects`). Prints the real loss measured beyond the amount, to size the
    /// fee budget. An isolated failure is possible without a bug: this hot wallet receives
    /// and sends SOL continuously, so its balance can move between the "before" read and the
    /// simulation (seen once, 3/3 on rerun). For a personal wallet, only an incoming
    /// transfer could slip in between; it would inflate the gain, and an attacker would have
    /// to pay for what they steal: nothing exploitable.
    /// `cargo test -- --ignored jupiter_swap_effects_pass_on_real_mainnet_swaps --nocapture`
    #[test]
    #[ignore]
    fn jupiter_swap_effects_pass_on_real_mainnet_swaps() {
        let owner_b58 = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
        let owner: [u8; 32] = bs58::decode(owner_b58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        for (from, to, amount) in [
            ("sol", "usdc", 100_000_000u64),
            ("usdc", "sol", 10_000_000u64),
            ("sol", "usdt", 100_000_000),
            ("sol", "eurc", 100_000_000),
            ("sol", "render", 100_000_000),
            ("usdc", "render", 10_000_000),
            // Tokenized shares (Token-2022, 179-byte destination account).
            ("usdc", "aaplx", 10_000_000),
            ("sol", "tslax", 100_000_000),
        ] {
            let (input, output) = (
                jupiter_mint_for_coin(from).unwrap(),
                jupiter_mint_for_coin(to).unwrap(),
            );
            let fee_mint = jupiter_fee_mint(&rpc, &input, &output).unwrap();
            println!(
                "{from}->{to} : frais d'affiliation {}",
                if fee_mint.is_some() {
                    "prélevés"
                } else {
                    "absents (aucun compte de frais)"
                }
            );
            let q = jupiter_rpc::quote(&input, &output, amount, 50, fee_mint).unwrap();
            let tx = jupiter_rpc::build_swap_transaction(&q, owner_b58).unwrap();
            let addresses = resolve_writable_addresses(&rpc, &tx).unwrap();
            let pre = rpc.multiple_accounts(&addresses).unwrap();
            let post_states = match rpc.simulate_with_account_states(&tx, &addresses).unwrap() {
                sol_rpc::SimulationOutcome::Succeeded { post_states } => post_states,
                sol_rpc::SimulationOutcome::Failed { err, logs } => {
                    panic!("simulation réelle en échec pour {from}->{to} ({err}) :\n{logs}")
                }
            };
            let user_lamports = |states: &[Option<sol_rpc::AccountState>]| -> i128 {
                addresses
                    .iter()
                    .zip(states)
                    .filter_map(|(a, s)| s.as_ref().map(|s| (a, s)))
                    .filter(|(a, s)| {
                        **a == owner_b58 || parse_token_account(s).is_some_and(|t| t.owner == owner)
                    })
                    .map(|(_, s)| i128::from(s.lamports))
                    .sum()
            };
            let loss = user_lamports(&pre) - user_lamports(&post_states);
            let sold = if from == "sol" { i128::from(amount) } else { 0 };
            println!("{from}->{to} : {} comptes inscriptibles, perte lamports réelle au-delà du montant = {}", addresses.len(), loss - sold);
            let min_out = q.out_amount * 9_950 / 10_000; // "displayed" output - 0.5% slippage
            let limits = swap_effect_limits(owner, from, amount, to, min_out).unwrap();
            if let Err(e) = verify_swap_effects(&addresses, &pre, &post_states, &limits) {
                for ((a, before), after) in addresses.iter().zip(&pre).zip(&post_states) {
                    let describe = |s: &Option<sol_rpc::AccountState>| match s {
                        None => "absent".to_string(),
                        Some(s) => format!(
                            "{} lamports, programme {}, {} octets, jeton de l'utilisateur : {}",
                            s.lamports,
                            s.owner,
                            s.data.len(),
                            parse_token_account(s).is_some_and(|t| t.owner == owner)
                        ),
                    };
                    println!(
                        "  {a}\n    avant : {}\n    après : {}",
                        describe(before),
                        describe(after)
                    );
                }
                panic!("faux rejet {from}->{to} : {e:#}");
            }
        }
    }

    /// Exact display multiplier: read as the node writes it, converted without floating
    /// point. Real vector (2026-10-09): an MCDx account with 22,906,601,081 raw units,
    /// multiplier 1.0211807004882871 → the node shows 233.91778937 (truncated). Back to
    /// raw, rounded down; the whole displayed balance → the whole raw balance, with
    /// nothing left over.
    #[test]
    fn scaled_amounts_are_exact() {
        let one = UiMultiplier::parse("1").unwrap();
        assert_eq!((one.to_ui(123), one.to_raw(123).unwrap()), (123, 123));
        let mcd = UiMultiplier::parse("1.0211807004882871").unwrap();
        assert_eq!(mcd.to_ui(22_906_601_081), 23_391_778_937, "comme le nœud");
        assert_eq!(
            mcd.to_raw(23_391_778_937).unwrap(),
            22_906_601_080,
            "arrondi vers le bas"
        );
        assert_eq!(
            scaled_raw_amount(23_391_778_937, mcd, 22_906_601_081).unwrap(),
            22_906_601_081,
            "tout le solde"
        );
        assert_eq!(
            scaled_raw_amount(100_000_000, mcd, 22_906_601_081).unwrap(),
            97_925_861,
            "1 action affichée"
        );
        assert!(
            scaled_raw_amount(1, UiMultiplier::parse("1.5").unwrap(), 10).is_err(),
            "trop petit pour une unité brute"
        );
        for amount in [1u128, 7, 99_999, 123_456_789, 10_000_000_000_000] {
            assert!(
                mcd.to_ui(mcd.to_raw(amount).unwrap()) <= amount,
                "jamais plus que demandé : {amount}"
            );
        }
        assert!(
            UiMultiplier::parse("99.999999999999999999")
                .unwrap()
                .to_ui(u64::MAX)
                > u128::from(u64::MAX),
            "sans dépassement"
        );
        for bad in [
            "",
            " ",
            "abc",
            "1e5",
            "-1",
            "+1",
            "0",
            "0.0",
            "1000",
            "0.001",
            "1.0000000000000000001",
            "1,5",
            "1.2.3",
        ] {
            assert!(UiMultiplier::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            scale_signed(-200, UiMultiplier::parse("1.5").unwrap()),
            -300
        );
        assert_eq!(scale_signed(0, mcd), 0);
    }

    /// Configuration read from a real mint (AAPLx, `getAccountInfo` jsonParsed on
    /// 2026-10-09): multiplier in force depending on the time, a movement refused if
    /// transfers are paused, if a transfer hook is active, or around a multiplier
    /// change.
    #[test]
    fn scaled_mint_config_is_read_from_a_real_mint() {
        let info = serde_json::json!({"decimals": 8, "extensions": [
            {"extension": "permanentDelegate", "state": {"delegate": "5aMNNLQJwAEeoemTEMkv5NVjqKwvvefRYCQ5Z67HFvEq"}},
            {"extension": "scaledUiAmountConfig", "state": {"authority": "S7vYFFWH6BjJyEsdrPQpqpYTqLTrPRK6KW3VwsJuRaS", "multiplier": "1.0026642075893797", "newMultiplier": "1.0032690125398187", "newMultiplierEffectiveTimestamp": 1786149000}},
            {"extension": "pausableConfig", "state": {"authority": "JDq14BWvqCRFNu1krb12bcRpbGtJZ1FLEakMw6FdxJNs", "paused": false}},
            {"extension": "transferHook", "state": {"authority": "5aMNNLQJwAEeoemTEMkv5NVjqKwvvefRYCQ5Z67HFvEq", "programId": null}}
        ]});
        let config = parse_scaled_mint(&info).unwrap();
        assert_eq!(
            config.effective(1_786_148_999),
            UiMultiplier::parse("1.0026642075893797").unwrap()
        );
        assert_eq!(
            config.effective(1_786_149_000),
            UiMultiplier::parse("1.0032690125398187").unwrap()
        );
        assert!(check_scaled_transfer(&config, 1_791_500_000).is_ok());
        assert_eq!(
            check_scaled_transfer(&config, 1_786_149_120)
                .unwrap_err()
                .to_string(),
            XSTOCK_MULTIPLIER_SWITCH
        );
        assert_eq!(
            check_scaled_transfer(&config, 1_786_148_800)
                .unwrap_err()
                .to_string(),
            XSTOCK_MULTIPLIER_SWITCH
        );
        let paused = ScaledMintConfig {
            paused: true,
            ..config.clone()
        };
        assert_eq!(
            check_scaled_transfer(&paused, 1_791_500_000)
                .unwrap_err()
                .to_string(),
            XSTOCK_PAUSED
        );
        let hooked = ScaledMintConfig {
            transfer_hook: Some("Hook111".into()),
            ..config.clone()
        };
        assert_eq!(
            check_scaled_transfer(&hooked, 1_791_500_000)
                .unwrap_err()
                .to_string(),
            XSTOCK_TRANSFER_HOOK
        );
        let steady = ScaledMintConfig {
            next: config.current,
            ..config
        };
        assert!(
            check_scaled_transfer(&steady, 1_786_149_000).is_ok(),
            "pas de changement réel : pas de fenêtre"
        );
        assert!(
            parse_scaled_mint(&serde_json::json!({"extensions": []})).is_err(),
            "sans coefficient : refus"
        );
        // Registry tokens: program and account size.
        let tsla = registered_solana_token("tslax").unwrap();
        assert!(
            tsla.scaled
                && tsla.program == sol_spl::token_2022_program_id()
                && tsla.account_size() == 179
                && tsla.decimals == 8
        );
        let usdc = registered_solana_token("usdc").unwrap();
        assert!(
            !usdc.scaled
                && usdc.program == sol_spl::token_program_id()
                && usdc.account_size() == 165
        );
        assert!(
            registered_spl_mint("tslax").is_err(),
            "les chemins du programme classique refusent un xStock"
        );
    }

    /// Real xStocks accounts whose address is their owner's associated account, taken
    /// from the mint's recent transactions.
    fn real_xstock_holders(rpc: &sol_rpc::SolRpc, token_id: &str) -> Vec<(String, String)> {
        let token = registered_solana_token(token_id).unwrap();
        let signatures = rpc
            .call(
                "getSignaturesForAddress",
                serde_json::json!([token.mint_b58, {"limit": 12}]),
            )
            .unwrap();
        let mut holders = Vec::new();
        for entry in signatures.as_array().unwrap() {
            std::thread::sleep(std::time::Duration::from_millis(400));
            let Ok(tx) = rpc.call("getTransaction", serde_json::json!([entry["signature"], {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 1}])) else { continue };
            for balance in tx["meta"]["postTokenBalances"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let (Some(owner), Some(index)) =
                    (balance["owner"].as_str(), balance["accountIndex"].as_u64())
                else {
                    continue;
                };
                let account = tx["transaction"]["message"]["accountKeys"][index as usize]["pubkey"]
                    .as_str()
                    .unwrap_or_default();
                if balance["mint"] == token.mint_b58
                    && registered_token_account(owner, token_id).ok().as_deref() == Some(account)
                    && !holders.iter().any(|(o, _): &(String, String)| o == owner)
                {
                    holders.push((owner.to_string(), account.to_string()));
                }
            }
        }
        holders
    }

    /// xStocks balances read by the app = balances shown by the node (multiplier ≠ 1:
    /// MCDx), on real accounts.
    #[test]
    #[ignore]
    fn xstock_balances_match_the_node() {
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        let holders = real_xstock_holders(&rpc, "mcdx");
        assert!(!holders.is_empty(), "aucun détenteur trouvé");
        let mut compared = 0;
        for (owner, account) in holders.iter().take(4) {
            let node = rpc
                .call("getTokenAccountBalance", serde_json::json!([account]))
                .unwrap();
            let shown = tokens::parse_amount(node["value"]["uiAmountString"].as_str().unwrap(), 8)
                .unwrap_or(0);
            let (units, decimals) = get_token_balance("mcdx", "sol_mainnet", owner).unwrap();
            println!(
                "{owner} : nœud {shown}, app {units} (brut {})",
                node["value"]["amount"]
            );
            assert_eq!((units, decimals), (shown, 8), "{owner}");
            compared += 1;
        }
        assert!(compared > 0);
        // Batched read (one request): the same balances.
        for (owner, _) in holders.iter().take(2) {
            let grouped = stock_balances(owner).unwrap();
            let single = get_token_balance("mcdx", "sol_mainnet", owner).unwrap().0;
            assert_eq!(
                grouped
                    .iter()
                    .find(|(id, _)| *id == "mcdx")
                    .map(|(_, units)| *units)
                    .unwrap_or(0),
                single,
                "{owner}"
            );
        }
    }

    /// xStocks transfer built by the app, simulated on the real network from a real
    /// holder (signature not verified by the simulation) to a new recipient: creation
    /// of the Token-2022 associated account then TransferChecked accepted, account
    /// created with `XSTOCK_ACCOUNT_SIZE` bytes holding exactly the raw amount sent.
    #[test]
    #[ignore]
    fn xstock_transfer_simulates_on_mainnet() {
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        let token = registered_solana_token("mcdx").unwrap();
        let holders = real_xstock_holders(&rpc, "mcdx");
        let recipient = derivation::derive_solana_key(&[9u8; 64], 0)
            .verifying_key()
            .to_bytes();
        let dest =
            sol_spl::find_associated_token_address_for(&recipient, &token.mint, &token.program);
        let dest_b58 = bs58::encode(dest).into_string();
        for (owner, account) in holders {
            let owner_bytes = solana_owner(&owner).unwrap();
            let balance = rpc.token_account_balance(&account).unwrap().unwrap_or(0);
            if balance < 1_000 || rpc.balance_lamports(&owner).unwrap_or(0) < 10_000_000 {
                continue;
            }
            let source = sol_spl::find_associated_token_address_for(
                &owner_bytes,
                &token.mint,
                &token.program,
            );
            let create = sol_spl::create_ata_idempotent_instruction_for(
                &owner_bytes,
                &recipient,
                &token.mint,
                &dest,
                &token.program,
            );
            let transfer = sol_spl::transfer_checked_instruction_for(
                &source,
                &token.mint,
                &dest,
                &owner_bytes,
                1_000,
                token.decimals,
                &token.program,
            );
            let dummy = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let tx = sol_tx::build_and_sign_transaction(
                &dummy,
                &owner_bytes,
                &[create, transfer],
                &rpc.latest_blockhash().unwrap(),
            );
            match rpc
                .simulate_with_account_states(&tx, std::slice::from_ref(&dest_b58))
                .unwrap()
            {
                sol_rpc::SimulationOutcome::Succeeded { post_states } => {
                    let created = post_states[0]
                        .as_ref()
                        .expect("compte du destinataire créé");
                    assert_eq!(created.owner, TOKEN_2022_PROGRAM_ID);
                    assert_eq!(
                        created.data.len() as u64,
                        tokens::XSTOCK_ACCOUNT_SIZE,
                        "taille du compte créé"
                    );
                    let view = parse_token_account(created).expect("compte de jetons");
                    assert_eq!(
                        (view.mint, view.owner, view.amount),
                        (token.mint, recipient, 1_000)
                    );
                    println!(
                        "simulation réussie depuis {owner} : compte de {} octets créé",
                        created.data.len()
                    );
                    return;
                }
                sol_rpc::SimulationOutcome::Failed { err, logs } => {
                    panic!("simulation en échec depuis {owner} ({err}) :\n{logs}")
                }
            }
        }
        panic!("aucun détenteur avec assez de jetons et de SOL");
    }

    /// Jupiter quote to an xStock (multiplier ≠ 1: AAPLx): output shown in displayed
    /// units, consistent with the price per displayed unit (100 USDC ≈ 100 / price,
    /// minus fees and impact).
    #[test]
    #[ignore]
    fn jupiter_quotes_xstocks_in_shown_units() {
        let quote = get_jupiter_quote("usdc", "aaplx", "100", 50).unwrap();
        let token = registered_solana_token("aaplx").unwrap();
        let price = crate::price_rpc::jupiter_stock_prices(&[token.mint_b58]).unwrap()[0].usd;
        let shown = quote.out_amount as f64 / 1e8;
        let value = shown * price;
        println!(
            "100 USDC → {shown} AAPLx affichés (cours {price} $) = {value} $, frais {:?}",
            quote.fee_mint.map(|m| bs58::encode(m).into_string())
        );
        assert!(
            (96.0..=100.5).contains(&value),
            "valeur {value} $ pour 100 USDC"
        );
        // When buying: fee on the xStock received (the affiliate's Token-2022 fee account)
        // or none, never on the USDC sold (route refused).
        assert!(
            quote.fee_mint.is_none() || quote.fee_mint == Some(token.mint),
            "frais à l'achat : {:?}",
            quote.fee_mint
        );
        // When selling: fee on the USDC received.
        let sale = get_jupiter_quote("aaplx", "usdc", "0.1", 50).unwrap();
        assert_eq!(
            sale.fee_mint,
            Some(sol_spl::usdc_mint_mainnet()),
            "frais de vente en USDC"
        );
    }

    #[test]
    fn recipient_activity_distinguishes_unused_empty_and_funded() {
        use RecipientActivity::*;
        assert_eq!(classify_evm_activity(0, 0), Unused);
        assert_eq!(classify_evm_activity(5, 0), Empty);
        assert_eq!(
            classify_evm_activity(0, 1),
            Funded,
            "reçu de l'ETH sans jamais en envoyer"
        );
        assert_eq!(classify_evm_activity(7, 10), Funded);

        let btc = |tx_count, balance_sat| btc_rpc::AddressStats {
            tx_count,
            balance_sat,
            confirmed_sat: balance_sat,
        };
        assert_eq!(classify_btc_activity(&btc(0, 0)), Unused);
        assert_eq!(classify_btc_activity(&btc(2, 0)), Empty);
        assert_eq!(
            classify_btc_activity(&btc(1, 1_000)),
            Funded,
            "réception en mempool comprise"
        );

        assert_eq!(classify_sol_activity(None, false), Unused);
        assert_eq!(
            classify_sol_activity(None, true),
            Empty,
            "compte vidé puis purgé par Solana"
        );
        assert_eq!(classify_sol_activity(Some(0), true), Empty);
        assert_eq!(classify_sol_activity(Some(890_880), true), Funded);
    }

    /// Check of the three states on real mainnet addresses (read-only), for each network;
    /// "new" addresses drawn at random on each run (never used, by construction). The "empty"
    /// Bitcoin address was found live (2 transactions, zero balance): if someone ever sends
    /// dust to it, it will become "Funded" (manual test).
    /// `cargo test -- --ignored recipient_activity_matches_real_mainnet_addresses --nocapture`
    #[test]
    #[ignore]
    fn recipient_activity_matches_real_mainnet_addresses() {
        use RecipientActivity::*;
        let random: [u8; 32] = entropy::generate_master_entropy()[..32].try_into().unwrap();

        let fresh_evm = derivation::format_address(&random[..20].try_into().unwrap());
        assert_eq!(
            evm_recipient_activity(&fresh_evm, &wallet_flow::ETHEREUM_MAINNET).unwrap(),
            Unused
        );
        assert_eq!(
            evm_recipient_activity(
                "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                &wallet_flow::ETHEREUM_MAINNET
            )
            .unwrap(),
            Funded
        );

        let fresh_btc =
            derivation::format_btc_mainnet_address(&random[..20].try_into().unwrap()).unwrap();
        assert_eq!(
            btc_recipient_activity(&fresh_btc, &wallet_flow::BTC_MAINNET).unwrap(),
            Unused
        );
        assert_eq!(
            btc_recipient_activity(
                "bc1q2zq2dkxrkrqn7dlqdgp4xda65mzfae8437he6z",
                &wallet_flow::BTC_MAINNET
            )
            .unwrap(),
            Empty
        );
        assert_eq!(
            btc_recipient_activity(
                "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
                &wallet_flow::BTC_MAINNET
            )
            .unwrap(),
            Funded
        );

        let fresh_sol = bs58::encode(
            ed25519_dalek::SigningKey::from_bytes(&random)
                .verifying_key()
                .to_bytes(),
        )
        .into_string();
        assert_eq!(
            sol_recipient_activity(&fresh_sol, &wallet_flow::SOLANA_MAINNET).unwrap(),
            Unused
        );
        assert_eq!(
            sol_recipient_activity(
                "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9",
                &wallet_flow::SOLANA_MAINNET
            )
            .unwrap(),
            Funded
        );
        // The (closed) wSOL account of the public wallet E645Tck…: it has a history, but
        // no on-chain account any more; the "emptied then purged" case specific to Solana.
        assert_eq!(
            sol_recipient_activity(
                "DvW59wVbiXr2zCbQNxUnLGS544XoQjpy7YBUC38HtcJ2",
                &wallet_flow::SOLANA_MAINNET
            )
            .unwrap(),
            Empty
        );
        // USDC: a public wallet holding USDC (see
        // `get_usdc_balance_matches_the_real_network`), and a new address.
        assert_eq!(
            usdc_recipient_activity(
                "E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk",
                &wallet_flow::SOLANA_MAINNET
            )
            .unwrap(),
            Funded
        );
        assert_eq!(
            usdc_recipient_activity(&fresh_sol, &wallet_flow::SOLANA_MAINNET).unwrap(),
            Unused
        );
        println!("neuves testées : {fresh_evm} / {fresh_btc} / {fresh_sol}");
    }

    /// dApp signatures on a real test wallet: the address RECOVERED from each EVM
    /// signature must be the profile's, the Solana signature must verify against its
    /// public key, and a session bound to another account must not be able to sign
    /// anything.
    #[test]
    fn dapp_signatures_recover_to_the_session_account() {
        use dapp_requests::{Account, Prepared};
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_dapp_sign_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        let created = create_wallet(&dir, password).unwrap();
        let account = Account {
            evm: created.addresses.evm.clone(),
            solana: created.addresses.solana.clone(),
        };

        let recover = |digest: [u8; 32], sig: &str| -> String {
            let bytes = hex::decode(sig.trim_start_matches("0x")).unwrap();
            let signature = k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap();
            let recid = k256::ecdsa::RecoveryId::from_byte(bytes[64] - 27).unwrap();
            let key = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature, recid)
                .unwrap();
            let point = key.to_encoded_point(false);
            let hash = crate::evm_sign::keccak(&point.as_bytes()[1..]);
            derivation::format_address(&hash[12..].try_into().unwrap())
        };

        let personal = dapp_requests::prepare(
            "personal_sign",
            &serde_json::json!(["0x48656c6c6f", account.evm]),
            dapp_requests::EVM_MAINNET,
            &account,
        )
        .unwrap();
        let sig = sign_dapp_request(&dir, password, 0, &account, &personal).unwrap();
        assert_eq!(
            recover(
                crate::evm_sign::personal_message_hash(b"Hello"),
                sig.as_str().unwrap()
            ),
            account.evm
        );

        let message = bs58::encode("Connexion").into_string();
        let sol = dapp_requests::prepare(
            "solana_signMessage",
            &serde_json::json!({"message": message, "pubkey": account.solana}),
            dapp_requests::SOLANA_MAINNET,
            &account,
        )
        .unwrap();
        let sig = sign_dapp_request(&dir, password, 0, &account, &sol).unwrap();
        let sig: [u8; 64] = bs58::decode(sig["signature"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let pubkey: [u8; 32] = bs58::decode(&account.solana)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
            .unwrap()
            .verify_strict(b"Connexion", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("signature Solana valide");

        // Session bound to another account (or profile): refused before any signing.
        let other = Account {
            evm: "0x5555555555555555555555555555555555555555".to_string(),
            solana: account.solana.clone(),
        };
        assert!(sign_dapp_request(&dir, password, 0, &other, &personal).is_err());
        assert!(matches!(personal, Prepared::EvmPersonalSign { .. }));
        // Wrong password: refused (and counted toward the lock, as everywhere).
        assert!(sign_dapp_request(&dir, "mauvais mot de passe", 0, &account, &personal).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Audit round 22: what the confirmation dialog shows must be the value actually
    /// signed, never a misleading form of the input.
    #[test]
    fn canonical_amount_shows_exactly_what_will_be_signed() {
        // Forms the parser accepts but the eye misreads.
        assert_eq!(canonical_amount("btc", "0.+5").unwrap(), "0.05");
        assert_eq!(canonical_amount("btc", "\n\n\n2.5\n").unwrap(), "2.5");
        assert_eq!(canonical_amount("sol", "+1").unwrap(), "1");
        // Normal forms, trailing zeros removed, full precision kept.
        assert_eq!(canonical_amount("evm", "0.010").unwrap(), "0.01");
        assert_eq!(
            canonical_amount("evm", "1.000000000000000001").unwrap(),
            "1.000000000000000001"
        );
        assert_eq!(canonical_amount("usdc", ".5").unwrap(), "0.5");
        assert_eq!(canonical_amount("sol", "3").unwrap(), "3");
        // Round trip: the displayed value re-parses to EXACTLY the same value.
        for (coin, raw) in [
            ("btc", "0.+5"),
            ("evm", "12.3456789"),
            ("sol", "0.000000001"),
            ("usdc", "1000000.123456"),
        ] {
            let shown = canonical_amount(coin, raw).unwrap();
            assert_eq!(
                parse_swap_amount_for_coin(coin, &shown).unwrap(),
                parse_swap_amount_for_coin(coin, raw).unwrap(),
                "{coin} {raw}"
            );
        }
        assert!(canonical_amount("btc", "1 000").is_err());
        assert!(canonical_amount("doge", "1").is_err());
    }

    /// Audit round 22: the vault itself, armored and pasted into "decrypt a message"
    /// (same device key), must be refused explicitly, not just by the luck of the UTF-8
    /// check. A real message goes through.
    #[test]
    fn decrypt_incoming_message_refuses_the_wallet_vault_itself() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_vault_as_message_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        let vault = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        let mut armored = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut armored, armor::Kind::Message).unwrap();
            std::io::Write::write_all(&mut writer, &vault).unwrap();
            writer.finalize().unwrap();
        }
        let err = decrypt_incoming_message(&dir, password, std::str::from_utf8(&armored).unwrap())
            .unwrap_err();
        assert!(
            err.to_string().contains("coffre du portefeuille"),
            "{err:#}"
        );

        let pubkey = read_device_pubkey_armored(&dir).unwrap();
        let message = crate::messaging::encrypt_message(&[pubkey], "bonjour").unwrap();
        assert_eq!(
            decrypt_incoming_message(&dir, password, &message).unwrap(),
            "bonjour"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path the previous test never exercised (the Binance hot wallet already has its USDC account): a SOL -> USDC
    /// swap for a wallet that does NOT have a USDC account yet, which the Jupiter transaction must therefore CREATE.
    /// This is the "account that becomes the user's" branch of `verify_swap_effects`. Public mainnet validator
    /// identities (SOL for voting fees, never any USDC in practice): the first one with no USDC account and enough
    /// SOL is used. Read-only, nothing is signed (transaction simulated without a signature, as in production).
    /// `cargo test -- --ignored jupiter_swap_effects_pass_when_the_destination_token_account_is_created --nocapture`
    #[test]
    #[ignore]
    fn jupiter_swap_effects_pass_when_the_destination_token_account_is_created() {
        const CANDIDATES: [&str; 15] = [
            "Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk",
            "HEL1USMZKAL2odpNBj2oCjffnFGaYwmbGmyewGv1e2TU",
            "DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy",
            "JUPiTERrZqgf1jUyR7dSkhMx4Kn2qJyekWsg3LT1h4b",
            "E1r4Psq84tHfQ6aPTvvDka4U3u8zPVD7gEUrH25RdxHL",
            "C8Bey3LKVJHVqN6xPTeW8WJfUgFQAeGNBpT4Rp99JP1k",
            "CAo1dCGYrB6NhHh5xb1cGjUiu86iyCfMTENxgHumSve4",
            "EvnRmnMrd69kFdbLMxWkTn1icZ7DCceRhvmb2SJXqDo4",
            "9eGrDohdNTAo61DRHyfMuqKWXqYnA3i254Wiszxe8FoY",
            "Awes4Tr6TX8JDzEhCZY2QVNimT6iD1zWHzf1vNyGvpLM",
            "JD549HsbJHeEKKUrKgg4Fj2iyv2RGjsV7NTZjZUrHybB",
            "9jxgosAfHgHzwnxsHw4RAZYaLVokMbnYtmiZBreynGFP",
            "5pPRHniefFjkiaArbGX3Y8NUysJmQ9tMZg3FrFGwHzSm",
            "5Cchr1XGEg7dbBXByV5NY2ad8jfxAM7HA3x8D56rq9Ux",
            "GnC339vkyXRm1jRX69dt9mapPPu2LbzXfSDoxc91qta6",
        ];
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        let amount = 50_000_000u64; // 0.05 SOL
        let owner_b58 = CANDIDATES
            .iter()
            .find(|c| {
                let owner: [u8; 32] = bs58::decode(c).into_vec().unwrap().try_into().unwrap();
                let ata = bs58::encode(sol_spl::find_associated_token_address(
                    &owner,
                    &sol_spl::usdc_mint_mainnet(),
                ))
                .into_string();
                !rpc.account_exists(&ata).unwrap() && rpc.balance_lamports(c).unwrap() > 10 * amount
            })
            .expect("au moins une identité de validateur sans compte USDC");
        println!("portefeuille utilisé (sans compte USDC) : {owner_b58}");
        let owner: [u8; 32] = bs58::decode(owner_b58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();

        let q = jupiter_rpc::quote(
            jupiter_rpc::SOL_MINT,
            &jupiter_mint_for_coin("usdc").unwrap(),
            amount,
            50,
            None,
        )
        .unwrap();
        let tx = jupiter_rpc::build_swap_transaction(&q, owner_b58).unwrap();
        let limits =
            swap_effect_limits(owner, "sol", amount, "usdc", q.out_amount * 9_950 / 10_000)
                .unwrap();
        check_swap_effects(&rpc, &tx, &limits)
            .expect("un vrai swap qui crée le compte USDC de destination ne doit pas être rejeté");

        // The test only proves something if the "creation" branch was actually taken: the
        // user's USDC account absent before, present after.
        let addresses = resolve_writable_addresses(&rpc, &tx).unwrap();
        let pre = rpc.multiple_accounts(&addresses).unwrap();
        let sol_rpc::SimulationOutcome::Succeeded { post_states } =
            rpc.simulate_with_account_states(&tx, &addresses).unwrap()
        else {
            panic!("simulation en échec");
        };
        let created: Vec<&String> = addresses
            .iter()
            .zip(pre.iter().zip(&post_states))
            .filter(|(_, (before, after))| {
                before.is_none()
                    && after
                        .as_ref()
                        .and_then(parse_token_account)
                        .is_some_and(|t| t.owner == owner && t.mint == sol_spl::usdc_mint_mainnet())
            })
            .map(|(a, _)| a)
            .collect();
        println!("comptes USDC créés pour l'utilisateur : {created:?}");
        assert_eq!(
            created.len(),
            1,
            "la transaction doit créer exactement un compte USDC pour l'utilisateur"
        );
    }

    /// Guard from audit round 20: an unreachable private key (here, removed from the
    /// vault with no fallback file) must NEVER count as a failed password attempt; even
    /// with the RIGHT password repeated well past the threshold, the lock must not kick
    /// in.
    #[test]
    fn unreachable_key_material_does_not_count_toward_the_password_lockout() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_key_unreachable_lockout_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        active_key_store()
            .remove(&secure_storage::entry_username(&dir))
            .unwrap();
        assert!(
            !dir.join(DEVICE_PRIVKEY_FILE).exists(),
            "aucun fichier de repli pour ce test"
        );

        for _ in 0..(MAX_FREE_ATTEMPTS + 3) {
            let Err(err) = unlock_wallet(&dir, password) else {
                panic!("la clé est injoignable, le déverrouillage ne peut pas réussir");
            };
            assert!(
                is_key_material_unavailable(&err),
                "erreur inattendue : {err:#}"
            );
        }
        assert!(
            enforce_unlock_lockout(&dir).is_ok(),
            "une clé injoignable ne doit jamais déclencher le verrou anti-brute-force"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wallet from before the OS vault (key in a file, nothing in the vault): the
    /// first successful unlock moves the key into the vault and deletes the file; the
    /// wallet then unlocks from the vault. A wrong password moves nothing.
    #[test]
    fn legacy_file_key_moves_into_the_os_store_after_a_successful_unlock() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_key_migration_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let username = secure_storage::entry_username(&dir);
        // Simulates a wallet created before the OS vault: key put back in a file.
        let key = active_key_store()
            .read(&username)
            .unwrap()
            .expect("clé dans le coffre après création");
        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), key.as_bytes()).unwrap();
        active_key_store().remove(&username).unwrap();

        assert!(unlock_wallet(&dir, "pas le bon mot de passe du tout").is_err());
        assert!(
            dir.join(DEVICE_PRIVKEY_FILE).exists(),
            "mauvais mot de passe : rien ne bouge"
        );
        assert!(active_key_store().read(&username).unwrap().is_none());

        unlock_wallet(&dir, password).expect("déverrouillage depuis le fichier");
        assert!(
            !dir.join(DEVICE_PRIVKEY_FILE).exists(),
            "fichier supprimé après migration"
        );
        assert_eq!(
            active_key_store()
                .read(&username)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some(key.as_str())
        );
        unlock_wallet(&dir, password).expect("déverrouillage depuis le coffre");

        active_key_store().remove(&username).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Vault down: the key stays in its file, intact.
    #[test]
    fn failed_migration_leaves_the_file_key_untouched() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_key_migration_failure_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(DEVICE_PRIVKEY_FILE),
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        )
        .unwrap();
        migrate_device_privkey_to_store(&dir, &FailingKeyStore);
        assert_eq!(
            std::fs::read(dir.join(DEVICE_PRIVKEY_FILE)).unwrap(),
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The real Windows Credential Manager, in a temporary folder (an entry specific to
    /// that folder, never a real wallet's): migration of a real wallet key (real size),
    /// readback, then cleanup.
    /// `cargo test -- --ignored real_os_store_migration --nocapture`
    #[test]
    #[ignore]
    fn real_os_store_migration() {
        use secure_storage::KeyStore;
        let store = secure_storage::OsKeyStore;
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_real_store_migration_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let username = secure_storage::entry_username(&dir);
        let key = active_key_store()
            .read(&username)
            .unwrap()
            .expect("clé générée");
        println!("clé de {} octets", key.len());
        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), key.as_bytes()).unwrap();
        assert!(
            store.read(&username).unwrap().is_none(),
            "aucune entrée réelle au départ"
        );

        migrate_device_privkey_to_store(&dir, &store);
        let stored = store.read(&username).unwrap();
        let migrated = !dir.join(DEVICE_PRIVKEY_FILE).exists()
            && stored.as_deref().map(String::as_str) == Some(key.as_str());
        store.remove(&username).unwrap();
        active_key_store().remove(&username).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            migrated,
            "clé dans le vrai coffre, identique, fichier supprimé"
        );
    }

    /// An OS vault that fails on every read (not "absent": a real error), to check that
    /// the file fallback is still used in that case.
    struct FailingKeyStore;

    impl secure_storage::KeyStore for FailingKeyStore {
        fn write(&self, _username: &str, _secret: &str) -> Result<()> {
            Err(anyhow::anyhow!("coffre OS simulé en panne"))
        }
        fn read(&self, _username: &str) -> Result<Option<Zeroizing<String>>> {
            Err(anyhow::anyhow!("coffre OS simulé en panne"))
        }
        fn remove(&self, _username: &str) -> Result<()> {
            Err(anyhow::anyhow!("coffre OS simulé en panne"))
        }
    }

    #[test]
    fn a_failing_os_keystore_still_falls_back_to_the_key_file_and_otherwise_reports_key_unavailable(
    ) {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_failing_keystore_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let err = with_device_privkey_path_in(&dir, &FailingKeyStore, |_| Ok(()))
            .expect_err("ni coffre ni fichier");
        assert!(
            is_key_material_unavailable(&err),
            "doit être marquée comme clé injoignable : {err:#}"
        );
        assert!(
            format!("{err:#}").contains("coffre OS simulé en panne"),
            "la cause réelle doit rester visible : {err:#}"
        );

        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), b"contenu factice").unwrap();
        let used = with_device_privkey_path_in(&dir, &FailingKeyStore, |p| Ok(p.to_string()))
            .expect("repli fichier");
        assert!(
            used.ends_with(DEVICE_PRIVKEY_FILE),
            "une panne du coffre OS ne doit pas bloquer une clé stockée en fichier"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same bug as `reset_wallet_also_cleans_up_the_biometric_enrollment`, found in
    /// the same audit: `restore_wallet` replaces the "device" identity without ever
    /// invalidating a biometric enrollment that referred to the OLD identity (see the
    /// docs of `restore_wallet_with`).
    #[test]
    fn restore_wallet_also_cleans_up_a_stale_biometric_enrollment_from_the_old_device_identity() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_restore_bio_cleanup_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        let created = create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");
        assert!(
            biometric_unlock_enrolled(&dir),
            "la biométrie doit être active avant le test"
        );

        let b1 = &created.backups[0];
        let b2 = &created.backups[1];
        let sealer = TrackingSealer {
            removed: std::cell::Cell::new(false),
        };
        restore_wallet_with(
            &dir,
            "un nouveau mot de passe bien assez long aussi",
            (&b1.encrypted_share, &b1.privkey_armored, &b1.passphrase),
            (&b2.encrypted_share, &b2.privkey_armored, &b2.passphrase),
            &sealer,
        )
        .expect("restauration du wallet");

        assert!(
            sealer.removed.get(),
            "la clé TPM de l'ancien appareil doit être supprimée par restore_wallet"
        );
        assert!(
            !biometric_unlock_enrolled(&dir),
            "aucune trace d'un enrôlement biométrique périmé ne doit survivre à une restauration"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Public addresses for every network, in the order of `Addresses`.
    fn all_public_addresses(a: &Addresses) -> Vec<(&'static str, String)> {
        vec![
            ("evm", a.evm.clone()),
            ("btc_testnet", a.btc_testnet.clone()),
            ("btc_mainnet", a.btc_mainnet.clone()),
            ("solana", a.solana.clone()),
            ("zcash", a.zcash.clone()),
            ("doge", a.doge.clone()),
            ("tron", a.tron.clone()),
            ("xrp", a.xrp.clone()),
            ("stellar", a.stellar.clone()),
            ("near", a.near.clone()),
            ("cardano", a.cardano.clone()),
            ("stacks", a.stacks.clone()),
            ("bittensor", a.bittensor.clone()),
            ("thor", a.thor.clone()),
            ("zcash_shielded", a.zcash_shielded.clone()),
            ("monero", a.monero.clone()),
        ]
    }

    /// Generates `testdata/backup_kit_v2.json`, a FROZEN kit in the current format
    /// (marked shares) for `frozen_backup_kits_still_restore`. `backup_kit_v1.json`
    /// (unmarked shares) was frozen by this same generator before marks existed. Only
    /// rerun it to freeze a NEW format, into a NEW file: an existing file is never
    /// regenerated.
    /// `cargo test --lib export_frozen_backup_kit -- --ignored`
    #[test]
    #[ignore]
    fn export_frozen_backup_kit() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_export_frozen_kit_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/backup_kit_v2.json");
        assert!(
            !std::path::Path::new(path).exists(),
            "kit figé déjà présent : il ne se régénère jamais"
        );
        let secret: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let backups = generate_backup_kit(&dir, &secret).unwrap();
        let addresses = derive_addresses(&secret, 0).unwrap();
        let kit = serde_json::json!({
            "note": "Kit de sauvegarde FACTICE (secret public), figé le 2026-10-09 au format v2 (parts marquées) : toute version de l'app doit le restaurer. Ne jamais envoyer de fonds à ces adresses ; ne jamais régénérer ce fichier.",
            "secret_hex": hex::encode(&secret),
            "addresses": all_public_addresses(&addresses).into_iter().map(|(k, v)| (k.to_string(), serde_json::Value::String(v))).collect::<serde_json::Map<String, serde_json::Value>>(),
            "parts": backups.iter().map(|b| serde_json::json!({
                "label": b.label,
                "passphrase": b.passphrase,
                "encrypted_share_hex": hex::encode(&b.encrypted_share),
                "privkey_armored": String::from_utf8(b.privkey_armored.clone()).unwrap(),
            })).collect::<Vec<_>>(),
        });
        std::fs::write(path, serde_json::to_string_pretty(&kit).unwrap() + "\n").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A share of the frozen kit: (encrypted share, armored private key, password).
    type FrozenPart = (Vec<u8>, Vec<u8>, String);

    /// Frozen kit `testdata/backup_kit_v{version}.json` and its shares.
    fn frozen_backup_kit(version: u8) -> (serde_json::Value, Vec<FrozenPart>) {
        let path = format!(
            "{}/testdata/backup_kit_v{version}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("kit figé {path} : {e}"));
        let kit: serde_json::Value = serde_json::from_str(&text).unwrap();
        let parts = kit["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    hex::decode(p["encrypted_share_hex"].as_str().unwrap()).unwrap(),
                    p["privkey_armored"].as_str().unwrap().as_bytes().to_vec(),
                    p["passphrase"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        (kit, parts)
    }

    /// GUARANTEE: a backup kit made by one version of the app restores with every later
    /// version. Frozen dummy kits (`testdata/backup_kit_v1.json` unmarked, `v2`
    /// marked): each pair of shares (1+2, 1+3, 2+3) goes through the check and then the
    /// real restore, and gives back the same secret and the same addresses on every
    /// network. A failure after an update (OpenPGP library, Shamir, derivation) would
    /// mean that real backups would no longer give back the funds: fix the code, NEVER
    /// these files.
    #[test]
    fn frozen_backup_kits_still_restore() {
        for version in [1u8, 2] {
            frozen_backup_kit_restores(version);
        }
    }

    fn frozen_backup_kit_restores(version: u8) {
        let (kit, parts) = frozen_backup_kit(version);
        assert_eq!(parts.len(), 3);
        let secret = hex::decode(kit["secret_hex"].as_str().unwrap()).unwrap();
        for (a, b) in [(0usize, 1usize), (0, 2), (1, 2)] {
            let dir = std::env::temp_dir().join(format!(
                "pgp_wallet_frozen_kit_v{version}_{a}{b}_{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let (pa, pb) = (&parts[a], &parts[b]);
            let decrypted: Vec<Zeroizing<Vec<u8>>> = [pa, pb]
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    Zeroizing::new(
                        decrypt_with_armored_privkey(
                            &p.0,
                            &dir.join(format!("tmp_frozen_{i}.asc")),
                            &p.1,
                            &p.2,
                        )
                        .unwrap(),
                    )
                })
                .collect();
            let refs: Vec<&[u8]> = decrypted.iter().map(|s| s.as_slice()).collect();
            assert_eq!(
                *shamir::reconstruct_secret(2, &refs).unwrap(),
                secret,
                "v{version}, parts {} + {}",
                a + 1,
                b + 1
            );
            let check = check_restore(&dir, (&pa.0, &pa.1, &pa.2), (&pb.0, &pb.1, &pb.2)).unwrap();
            assert_eq!(
                check.verified,
                version >= 2,
                "v{version} : parts vérifiées par leur marque"
            );
            assert_eq!(
                all_public_addresses(&check.addresses),
                all_public_addresses(&derive_addresses(&secret, 0).unwrap())
            );
            let addresses = restore_wallet_with(
                &dir,
                "un nouveau mot de passe bien assez long",
                (&pa.0, &pa.1, &pa.2),
                (&pb.0, &pb.1, &pb.2),
                &FakeSealer { fail_enroll: false },
            )
            .unwrap_or_else(|e| {
                panic!(
                    "restauration v{version} des parts {} + {} : {e:#}",
                    a + 1,
                    b + 1
                )
            });
            for (network, address) in all_public_addresses(&addresses) {
                assert_eq!(
                    kit["addresses"][network].as_str(),
                    Some(address.as_str()),
                    "v{version} {network}, parts {} + {}",
                    a + 1,
                    b + 1
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Shares that do not belong together, refused BEFORE any change to the device: two
    /// kits of the same wallet (wrong rebuilt secret without the mark), a marked share
    /// with an unmarked one, and a share whose mark names another wallet (fingerprint).
    /// Without the refusal, the restore would have installed an empty wallet.
    #[test]
    fn mismatched_backup_shares_are_refused_before_anything_changes() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_mismatched_shares_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let secret: Vec<u8> = (0..32u8).map(|i| i ^ 0x5a).collect();
        let kit_a = generate_backup_kit(&dir, &secret).unwrap();
        let kit_b = generate_backup_kit(&dir, &secret).unwrap();
        let part = |b: &BackupShare| {
            (
                b.encrypted_share.clone(),
                b.privkey_armored.clone(),
                b.passphrase.clone(),
            )
        };
        let as_ref = |p: &FrozenPart| (p.0.clone(), p.1.clone(), p.2.clone());
        let attempt = |x: &FrozenPart, y: &FrozenPart| {
            let device = dir.join("appareil");
            let _ = std::fs::remove_dir_all(&device);
            let checked =
                check_restore(&device, (&x.0, &x.1, &x.2), (&y.0, &y.1, &y.2)).map(|c| c.verified);
            let restored = restore_wallet_with(
                &device,
                "un nouveau mot de passe bien assez long",
                (&x.0, &x.1, &x.2),
                (&y.0, &y.1, &y.2),
                &FakeSealer { fail_enroll: false },
            );
            if restored.is_err() {
                assert!(
                    !device.join(DEVICE_VAULT_FILE).exists(),
                    "aucun coffre écrit après un refus"
                );
            }
            (checked.map_err(|e| e.to_string()), restored.is_ok())
        };
        // Same kit: verified.
        assert_eq!(
            attempt(&part(&kit_a[0]), &part(&kit_a[2])),
            (Ok(true), true)
        );
        // Two kits of the same wallet.
        assert_eq!(
            attempt(&part(&kit_a[0]), &part(&kit_b[1])),
            (Err(KITS_DIFFERENT.to_string()), false)
        );
        // A marked share + an unmarked share (older kit).
        let (_, old) = frozen_backup_kit(1);
        assert_eq!(
            attempt(&part(&kit_a[0]), &as_ref(&old[1])),
            (Err(KITS_DIFFERENT.to_string()), false)
        );
        // Another wallet's mark: shares of a secret S2 carrying the mark (same kit
        // identifier) of `secret`'s wallet.
        let other: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(3)).collect();
        let shares = shamir::split_secret(&other, 2, 3).unwrap();
        let mark = kit_mark_name("00112233aabbccdd", &kit_check(&secret));
        let forged: Vec<FrozenPart> = shares
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, share)| {
                let passphrase = random_passphrase();
                let (public, private) =
                    generate_pgp_identity(&format!("forge{i}"), &passphrase).unwrap();
                let encrypted = encrypt_with_armored_pubkey(
                    share,
                    &dir.join("tmp_forge_pub.asc"),
                    &public,
                    Some(&mark),
                )
                .unwrap();
                (encrypted, private, passphrase)
            })
            .collect();
        assert_eq!(
            attempt(&forged[0], &forged[1]),
            (Err(KIT_CHECK_FAILED.to_string()), false)
        );
        // Unreadable mark (other software, other format): treated as unmarked.
        assert_eq!(parse_kit_mark(Some(b"photo.jpg")), None);
        assert_eq!(parse_kit_mark(Some(b"pgpwallet-kit-v1:0011:22")), None);
        assert_eq!(parse_kit_mark(None), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// New kits stay readable by earlier versions of the app: their restore reads the
    /// share with `decrypt_share` (content only) and passes it to Shamir, which is
    /// exactly what this test does, and it must give back the secret.
    #[test]
    fn new_kits_stay_restorable_by_earlier_versions() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_new_kit_old_reader_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (kit, parts) = frozen_backup_kit(2);
        let secret = hex::decode(kit["secret_hex"].as_str().unwrap()).unwrap();
        let old_reader = |p: &FrozenPart, i: usize| {
            let path = dir.join(format!("old_reader_{i}.asc"));
            std::fs::write(&path, &p.1).unwrap();
            Zeroizing::new(pgp_engine::decrypt_share(&p.0, &path.to_string_lossy(), &p.2).unwrap())
        };
        let shares = [old_reader(&parts[0], 0), old_reader(&parts[2], 2)];
        let refs: Vec<&[u8]> = shares.iter().map(|s| s.as_slice()).collect();
        assert_eq!(*shamir::reconstruct_secret(2, &refs).unwrap(), secret);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn biometric_unlock_cancellation_does_not_count_toward_the_lockout() {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_bio_cancel_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        for _ in 0..(MAX_FREE_ATTEMPTS + 3) {
            assert!(unlock_wallet_biometric_with(&dir, &CancellingSealer).is_err());
        }
        assert!(
            enforce_biometric_unlock_lockout(&dir).is_ok(),
            "annuler le prompt plusieurs fois ne doit jamais déclencher le verrou anti-brute-force"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_adds_a_second_recipient_without_breaking_the_existing_password() {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_enroll_bio_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let before = initial_addresses_for(&dir, password);

        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        let after = unlock_wallet(&dir, password)
            .expect("le mot de passe doit toujours déverrouiller le coffre");
        let after_addresses = after
            .into_iter()
            .find(|p| p.profile.index == 0)
            .unwrap()
            .addresses
            .unwrap();
        assert_eq!(
            before.evm, after_addresses.evm,
            "les adresses ne doivent pas changer après activation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_then_unlock_wallet_biometric_returns_the_same_addresses_as_password_unlock(
    ) {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_bio_unlock_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        assert!(biometric_unlock_enrolled(&dir));

        let via_password = initial_addresses_for(&dir, password);
        let via_biometric = unlock_wallet_biometric_with(&dir, &FakeSealer { fail_enroll: false })
            .expect("déverrouillage biométrique")
            .into_iter()
            .find(|p| p.profile.index == 0)
            .unwrap()
            .addresses
            .unwrap();
        assert_eq!(via_password.evm, via_biometric.evm);
        assert_eq!(via_password.solana, via_biometric.solana);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The central guard for this whole feature: the password's anti-brute-force lock
    /// (counter, delay) must behave EXACTLY as it did before biometrics existed,
    /// whether they are enabled or not.
    #[test]
    fn wrong_device_password_lockout_is_unaffected_by_biometric_enrollment() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_bio_lockout_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        for _ in 0..MAX_FREE_ATTEMPTS {
            assert!(unlock_wallet(&dir, "mauvais mot de passe").is_err());
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "le verrou mot de passe doit se déclencher normalement, biométrie activée ou non"
        );
        // The biometric counter, on the other hand, must not have moved: these are
        // password attempts, never counted on the other path.
        assert!(enforce_biometric_unlock_lockout(&dir).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disable_biometric_unlock_returns_the_vault_to_single_recipient_and_removes_the_four_files() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_bio_disable_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");
        assert!(biometric_unlock_enrolled(&dir));

        disable_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("désactivation de la biométrie");

        assert!(!biometric_unlock_enrolled(&dir));
        for file in [
            DEVICE_BIOMETRIC_PUBKEY_FILE,
            DEVICE_BIOMETRIC_PRIVKEY_FILE,
            DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
            DEVICE_BIOMETRIC_KEY_META_FILE,
        ] {
            assert!(
                !dir.join(file).exists(),
                "{file} devrait avoir été supprimé"
            );
        }
        assert!(
            unlock_wallet(&dir, password).is_ok(),
            "le mot de passe doit toujours fonctionner après désactivation"
        );
        assert!(
            unlock_wallet_biometric_with(&dir, &FakeSealer { fail_enroll: false }).is_err(),
            "la biométrie ne doit plus fonctionner après désactivation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_twice_replaces_the_previous_enrollment_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_bio_reenroll_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("premier enrôlement");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false }).expect(
            "second enrôlement (ré-enrôlement) doit réussir sans exiger de désactivation préalable",
        );

        assert!(unlock_wallet(&dir, password).is_ok());
        assert!(unlock_wallet_biometric_with(&dir, &FakeSealer { fail_enroll: false }).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_rejects_a_wrong_device_password_and_leaves_the_vault_untouched() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_bio_wrongpass_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let vault_before = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();

        assert!(enroll_biometric_unlock_with(
            &dir,
            "mauvais mot de passe",
            &FakeSealer { fail_enroll: false }
        )
        .is_err());

        let vault_after = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        assert_eq!(
            vault_before, vault_after,
            "un mauvais mot de passe ne doit jamais toucher au coffre"
        );
        assert!(!biometric_unlock_enrolled(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// If the sealer (real TPM) fails at enrollment time, the vault must stay strictly
    /// identical to before (write-verify-rename pattern, see
    /// `enroll_biometric_unlock_with`).
    #[test]
    fn enroll_biometric_unlock_leaves_the_vault_untouched_when_the_sealer_fails() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_bio_sealer_fail_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let vault_before = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();

        assert!(
            enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: true })
                .is_err()
        );

        let vault_after = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        assert_eq!(
            vault_before, vault_after,
            "un échec du scelleur ne doit jamais toucher au coffre"
        );
        assert!(!biometric_unlock_enrolled(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
