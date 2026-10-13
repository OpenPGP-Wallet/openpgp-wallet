//! Abstraction over storing the device's PGP private key: prefers the OS's native
//! vault (Windows Credential Manager / macOS Keychain / Linux Secret Service,
//! `keyring` crate) to a plain `.asc` file, which means real access control by the
//! operating system (tied to the user session) rather than just a file path to
//! guess. See `api.rs` for the orchestration (file fallback if the OS vault is
//! unavailable, never blocking wallet creation or unlocking because of it, and
//! compatibility with vaults created before this change).
//!
//! The OS vault entry is identified by a hash of the absolute path of `data_dir`,
//! never a fixed name: several wallets on the same machine (a real one plus test
//! data, for example) must have completely isolated vault entries, exactly as they
//! already have separate files.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Frozen: existing wallets keep their vault entries under this service name in
/// the OS credential store. Renaming it would lock their owners out.
const SERVICE: &str = "pgp-wallet-poc";

/// Stable, unique identifier per `data_dir`, never the path in the clear (no need
/// to expose it as is in the OS vault, and some paths contain characters that some
/// backends dislike). `pub` (not `pub(crate)`) for the same reason as `OsKeyStore`:
/// usable from `examples/keyring_spike.rs`.
pub fn entry_username(data_dir: &Path) -> String {
    let hash = Sha256::digest(data_dir.to_string_lossy().as_bytes());
    format!("device_privkey_{}", hex::encode(&hash[..16]))
}

/// Injectable abstraction for tests, the same pattern as
/// `SecretSealer`/`WindowsHelloSealer` for biometric unlock (see `api.rs`): tests
/// use an in-memory vault instead of the real OS vault, so they never pollute the
/// real Credential Manager or Keychain of the machine running `cargo test`, and
/// never depend on an OS vault actually being set up on a CI machine.
pub trait KeyStore: Sync {
    fn write(&self, username: &str, secret: &str) -> Result<()>;
    /// `Ok(None)` = no entry (the normal case for a wallet whose key still lives in a
    /// file); `Err` = a REAL failure of the OS vault. The previous version mixed the
    /// two (every failure treated as "absent"), which hid the real cause of a problem;
    /// found in the 20th self-review round.
    ///
    /// `Zeroizing<String>` (never a bare `String`): the content is a PGP private key in
    /// the clear (2nd self-review round).
    fn read(&self, username: &str) -> Result<Option<Zeroizing<String>>>;
    fn remove(&self, username: &str) -> Result<()>;
}

/// `pub` (not `pub(crate)`) only so it stays usable from
/// `examples/keyring_spike.rs`, a separate program that depends on this crate like
/// an external dependency; same reason `windows_hello::enroll`/`unlock`/`remove`
/// are `pub` for `tpm_hello_spike.rs`.
pub struct OsKeyStore;

impl KeyStore for OsKeyStore {
    // `set_secret`/`get_secret` (raw bytes), never `set_password`/`get_password`
    // (text): found empirically (`keyring_spike full-cycle`) that `keyring`'s Windows
    // backend converts a password to UTF-16 BEFORE writing it (for interoperability
    // with the native Windows APIs, which expect UTF-16 passwords), which DOUBLES the
    // byte size of ASCII text such as our armored PGP key. A 1,337-byte key (measured
    // on a real vault of this project) thus went over Windows Credential Manager's
    // real limit (2,560 bytes) once converted (2,674 bytes), while 1,337 RAW bytes fit
    // comfortably within that same limit. `set_secret` writes the bytes as they are on
    // every platform (Windows AND the trait's default used by macOS/Linux): more
    // consistent AND more compact.
    fn write(&self, username: &str, secret: &str) -> Result<()> {
        keyring::Entry::new(SERVICE, username)
            .and_then(|e| e.set_secret(secret.as_bytes()))
            .context("écriture dans le coffre natif de l'OS")
    }

    fn read(&self, username: &str) -> Result<Option<Zeroizing<String>>> {
        let entry = keyring::Entry::new(SERVICE, username)
            .context("ouverture de l'entrée du coffre natif de l'OS")?;
        match entry.get_secret() {
            // `secret` (raw bytes) consumed directly by `from_utf8`, never cloned: only one
            // buffer exists at any time, the one that ends up wrapped in the returned
            // `Zeroizing`.
            Ok(secret) => String::from_utf8(secret)
                .map(|s| Some(Zeroizing::new(s)))
                .context("contenu du coffre OS non-UTF8 (corruption ?)"),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context("lecture depuis le coffre natif de l'OS")),
        }
    }

    fn remove(&self, username: &str) -> Result<()> {
        keyring::Entry::new(SERVICE, username)
            .and_then(|e| e.delete_credential())
            .context("suppression dans le coffre natif de l'OS")
    }
}

/// Fake in-memory vault for tests (see the trait's doc): never used in production.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct InMemoryKeyStore(std::sync::Mutex<std::collections::HashMap<String, String>>);

#[cfg(test)]
impl KeyStore for InMemoryKeyStore {
    fn write(&self, username: &str, secret: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(username.to_string(), secret.to_string());
        Ok(())
    }

    fn read(&self, username: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(username)
            .cloned()
            .map(Zeroizing::new))
    }

    fn remove(&self, username: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(username);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_username_is_deterministic_and_differs_per_data_dir() {
        let a = entry_username(Path::new("/tmp/wallet_a"));
        let b = entry_username(Path::new("/tmp/wallet_a"));
        let c = entry_username(Path::new("/tmp/wallet_b"));
        assert_eq!(
            a, b,
            "même data_dir -> même identifiant, sinon un wallet existant deviendrait illisible"
        );
        assert_ne!(
            c, a,
            "des data_dir différents ne doivent jamais partager la même entrée de coffre OS"
        );
    }

    #[test]
    fn in_memory_key_store_round_trips_and_isolates_by_username() {
        let store = InMemoryKeyStore::default();
        store.write("alice", "secret-a").unwrap();
        store.write("bob", "secret-b").unwrap();
        assert_eq!(store.read("alice").unwrap().unwrap().as_str(), "secret-a");
        assert_eq!(store.read("bob").unwrap().unwrap().as_str(), "secret-b");
        store.remove("alice").unwrap();
        assert!(
            store.read("alice").unwrap().is_none(),
            "une entrée supprimée doit être absente, pas une erreur"
        );
        assert_eq!(
            store.read("bob").unwrap().unwrap().as_str(),
            "secret-b",
            "supprimer une entrée ne doit pas affecter les autres"
        );
    }
}
