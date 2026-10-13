//! Seals a random secret in a key persisted in the TPM ("Microsoft Platform Crypto
//! Provider", through NCrypt), with a UI policy that makes Windows itself require a
//! Windows Hello check (fingerprint, face or PIN) before any decryption. It is the
//! TPM that refuses the operation, in hardware, without a fresh check, never this
//! application code "asking nicely" before acting. Deliberately chosen over a DPAPI
//! wrapper: DPAPI decrypts for any process running in the same Windows session,
//! without ever going through Windows Hello again.
//!
//! The secret sealed here serves as the passphrase of a dedicated PGP identity
//! ("device_biometric", see api.rs): this module knows nothing about the wallet,
//! the vault or PGP, only "seal a secret" / "get it back after verification".
//!
//! The prompt's behavior (really triggered, clean failure on cancel, barrier held
//! from another process, survives a reboot) must be validated by hand with
//! `core/examples/tpm_hello_spike.rs` on a real machine with Windows Hello set up,
//! before trusting this module.

use anyhow::{Context, Result};
use windows::core::{Error as WinError, HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY, NCRYPT_UI_PROTECT_KEY_FLAG,
};
use zeroize::Zeroizing;

const RSA_KEY_BITS: u32 = 2048;
/// Prefix of the TPM key names this project creates, followed by a random name (see
/// `enroll`), never a fixed name: two successive enrollments (or an enrollment
/// after `reset_wallet`) must never collide with an orphaned TPM key from a
/// previous cycle, since NCrypt does not scope these persisted keys to the app's
/// data directory.
///
/// Frozen, like the vault service name: existing Windows Hello keys are found by
/// this prefix.
const KEY_NAME_PREFIX: &str = "pgp-wallet-poc-biometric-";

fn oaep_hash_algorithm() -> PCWSTR {
    windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALGORITHM
}

fn to_anyhow(context: &str, err: WinError) -> anyhow::Error {
    anyhow::anyhow!("{context} : {err} (code {:#010x})", err.code().0 as u32)
}

/// DISPLAY heuristic only: tells whether Windows Hello seems set up, so the enable
/// button is only offered when it has a chance of working. `enroll`/`unlock` stay
/// fail-closed regardless of this function: a wrong answer here can never weaken
/// security, only degrade the experience (offering a button that will fail, or the
/// reverse).
pub fn is_available() -> bool {
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };
    let Ok(operation) = UserConsentVerifier::CheckAvailabilityAsync() else {
        return false;
    };
    match operation.get() {
        Ok(availability) => availability == UserConsentVerifierAvailability::Available,
        Err(_) => false,
    }
}

struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> Result<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) }.map_err(
            |e| {
                to_anyhow(
                    "ouverture du fournisseur TPM (Microsoft Platform Crypto Provider)",
                    e,
                )
            },
        )?;
        Ok(Self(handle))
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0 .0)) };
    }
}

struct KeyHandle(NCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0 .0)) };
    }
}

/// Creates a new RSA key pair persisted in the TPM, with a UI policy that forces
/// Windows Hello before any future use of the private key, then seals `secret` with
/// the freshly created public key (RSA-OAEP/SHA-256). Returns the key identifier
/// (keep it, it is needed for `unlock`/`remove`) and the sealed blob (opaque, keep
/// it too; useless without the matching TPM key).
pub fn enroll(secret: &[u8]) -> Result<(String, Vec<u8>)> {
    let provider = Provider::open()?;
    let key_name = format!(
        "{KEY_NAME_PREFIX}{}",
        hex::encode(crate::entropy::generate_master_entropy())
    );
    let key_name_wide = HSTRING::from(&key_name);

    // `NCryptCreatePersistedKey` only really persists the key at `NCryptFinalizeKey`
    // (before that, a failure here leaves nothing in the TPM and needs no cleanup).
    // Once `NCryptFinalizeKey` has succeeded, however, the key really exists in the
    // TPM's store. If a later step (sealing the secret) then fails, this function
    // returns an error WITHOUT ever giving `key_name` back to the caller, who
    // therefore can never clean it up later (no metadata file is written for a key
    // whose enrollment failed): it would stay orphaned in the TPM forever. `finalized`
    // tells the two cases apart so the best-effort deletion only runs if the key was
    // really created.
    let mut finalized = false;
    let result = enroll_inner(&provider, &key_name_wide, secret, &mut finalized);
    if result.is_err() && finalized {
        // Best effort: if this cleanup fails too, the original error (already in `result`)
        // is still what reaches the caller. The real enrollment failure must not be hidden
        // behind a cleanup failure.
        let _: Result<()> = (|| {
            let mut handle = NCRYPT_KEY_HANDLE::default();
            unsafe {
                NCryptOpenKey(
                    provider.0,
                    &mut handle,
                    &key_name_wide,
                    CERT_KEY_SPEC(0),
                    NCRYPT_FLAGS(0),
                )
            }
            .map_err(|e| {
                to_anyhow(
                    "ré-ouverture de la clé TPM à nettoyer après échec d'enrôlement",
                    e,
                )
            })?;
            unsafe { NCryptDeleteKey(handle, 0) }
                .map_err(|e| to_anyhow("nettoyage de la clé TPM après échec d'enrôlement", e))
        })();
    }
    result.map(|sealed| (key_name, sealed))
}

fn enroll_inner(
    provider: &Provider,
    key_name_wide: &HSTRING,
    secret: &[u8],
    finalized: &mut bool,
) -> Result<Vec<u8>> {
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut key_handle,
            BCRYPT_RSA_ALGORITHM,
            key_name_wide,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| to_anyhow("création de la clé TPM persistée", e))?;
    let key = KeyHandle(key_handle);

    let length_bytes = RSA_KEY_BITS.to_le_bytes();
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0 .0),
            NCRYPT_LENGTH_PROPERTY,
            &length_bytes,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| to_anyhow("réglage de la taille de clé TPM", e))?;

    // `NCRYPT_UI_PROTECT_KEY_FLAG`: THIS setting is what the TPM provider itself
    // enforces on every future use of the private key (see `unlock`). It is not an
    // application-side checkbox but a policy imposed by the key provider / TPM itself.
    let title = HSTRING::from("OpenPGP Wallet");
    let friendly_name = HSTRING::from("Déverrouillage biométrique du coffre");
    let description = HSTRING::from("Confirmez votre identité pour déverrouiller ce portefeuille.");
    let ui_policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
        pszCreationTitle: PCWSTR(title.as_ptr()),
        pszFriendlyName: PCWSTR(friendly_name.as_ptr()),
        pszDescription: PCWSTR(description.as_ptr()),
    };
    let ui_policy_bytes = unsafe {
        std::slice::from_raw_parts(
            (&ui_policy as *const NCRYPT_UI_POLICY) as *const u8,
            std::mem::size_of::<NCRYPT_UI_POLICY>(),
        )
    };
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0 .0),
            NCRYPT_UI_POLICY_PROPERTY,
            ui_policy_bytes,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| to_anyhow("réglage de la politique Windows Hello sur la clé TPM", e))?;

    unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }
        .map_err(|e| to_anyhow("finalisation de la clé TPM", e))?;
    *finalized = true; // the key now really exists in the TPM

    let padding_algo = oaep_hash_algorithm();
    let padding_info = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: padding_algo,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let padding_info_ptr =
        &padding_info as *const BCRYPT_OAEP_PADDING_INFO as *const std::ffi::c_void;

    let mut needed: u32 = 0;
    unsafe {
        NCryptEncrypt(
            key.0,
            Some(secret),
            Some(padding_info_ptr),
            None,
            &mut needed,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0),
        )
    }
    .map_err(|e| to_anyhow("calcul de la taille du blob scellé", e))?;

    let mut sealed = vec![0u8; needed as usize];
    let mut written: u32 = 0;
    unsafe {
        NCryptEncrypt(
            key.0,
            Some(secret),
            Some(padding_info_ptr),
            Some(&mut sealed),
            &mut written,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0),
        )
    }
    .map_err(|e| to_anyhow("scellement du secret dans le TPM", e))?;
    sealed.truncate(written as usize);

    Ok(sealed)
}

/// Reopens the persisted TPM key `key_name` and decrypts `sealed_blob`. THIS call
/// triggers and blocks on the Windows Hello prompt, enforced by the key provider
/// (see `enroll`), never by this application code. Fails if the check is cancelled
/// or fails, if the key no longer exists (Windows Hello reset, TPM cleared) or if
/// the blob is corrupted.
pub fn unlock(key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let provider = Provider::open()?;
    let key_name_wide = HSTRING::from(key_name);

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.0,
            &mut key_handle,
            &key_name_wide,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| {
        to_anyhow(
            "ouverture de la clé TPM (déverrouillage biométrique désactivé ou clé absente ?)",
            e,
        )
    })?;
    let key = KeyHandle(key_handle);

    let padding_algo = oaep_hash_algorithm();
    let padding_info = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: padding_algo,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let padding_info_ptr =
        &padding_info as *const BCRYPT_OAEP_PADDING_INFO as *const std::ffi::c_void;

    let mut needed: u32 = 0;
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(sealed_blob),
            Some(padding_info_ptr),
            None,
            &mut needed,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0),
        )
    }
    .map_err(|e| to_anyhow("calcul de la taille du secret déchiffré", e))?;

    let mut secret = Zeroizing::new(vec![0u8; needed as usize]);
    let mut written: u32 = 0;
    // This call triggers the Windows Hello prompt (UI policy set at enrollment); it
    // blocks until the user answers or the OS timeout expires.
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(sealed_blob),
            Some(padding_info_ptr),
            Some(&mut secret),
            &mut written,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0),
        )
    }
    .map_err(|e| to_anyhow("vérification Windows Hello refusée, annulée ou échouée", e))?;
    secret.truncate(written as usize);

    Ok(secret)
}

/// Permanently deletes the persisted TPM key. Without this call, turning off
/// biometric unlock in the app would leave an orphaned key in the TPM store of the
/// user's Windows profile.
pub fn remove(key_name: &str) -> Result<()> {
    let provider = Provider::open()?;
    let key_name_wide = HSTRING::from(key_name);

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.0,
            &mut key_handle,
            &key_name_wide,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .context("ouverture de la clé TPM à supprimer")
    .map_err(|_| anyhow::anyhow!("clé TPM déjà absente, rien à supprimer"))?;
    unsafe { NCryptDeleteKey(key_handle, 0) }.map_err(|e| to_anyhow("suppression de la clé TPM", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The display function must never panic, whatever the state of Windows Hello on
    /// the machine running the tests (often not set up on a CI or dev machine). That is
    /// all that can be checked without real biometric hardware.
    #[test]
    fn is_available_never_panics() {
        let _ = is_available();
    }
}
