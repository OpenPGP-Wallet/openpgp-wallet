//! Scelle un secret aléatoire dans une clé persistée dans le TPM (fournisseur
//! "Microsoft Platform Crypto Provider", via NCrypt), avec une politique UI qui
//! force Windows lui-même à exiger une vérification Windows Hello (empreinte,
//! visage ou code confidentiel) avant tout déchiffrement — c'est le TPM qui
//! refuse matériellement l'opération sans vérification fraîche, jamais ce code
//! applicatif qui "demande gentiment" avant d'agir. Choix délibérément préféré à
//! une façade DPAPI : DPAPI déchiffre pour n'importe quel processus tournant sous
//! la même session Windows, sans jamais repasser par Windows Hello — voir la
//! discussion dans ETAPES.md ("Idées d'amélioration identifiées").
//!
//! Le secret scellé ici sert de passphrase à une identité PGP dédiée
//! ("device_biometric", voir api.rs) : ce module ne connaît rien du wallet, du
//! coffre ni de PGP, seulement "sceller un secret" / "le récupérer après
//! vérification".
//!
//! Comportement du prompt (déclenchement réel, échec propre sur annulation,
//! barrière tenue depuis un autre processus, survie après redémarrage) à
//! valider manuellement via `core/src/bin/tpm_hello_spike.rs` sur une machine
//! réelle avec Windows Hello configuré, avant toute confiance dans ce module.

use anyhow::{Context, Result};
use windows::core::{Error as WinError, HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM,
    CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY,
    NCRYPT_UI_PROTECT_KEY_FLAG,
};
use zeroize::Zeroizing;

const RSA_KEY_BITS: u32 = 2048;
/// Préfixe des noms de clé TPM créées par ce projet — un nom aléatoire suit
/// (voir `enroll`), jamais un nom fixe : deux enrôlements successifs (ou un
/// enrôlement après `reset_wallet`) ne doivent jamais entrer en collision avec
/// une clé TPM orpheline d'un cycle précédent, puisque NCrypt ne scope pas ces
/// clés persistées au répertoire de données de l'app.
///
/// Frozen, like the vault service name: existing Windows Hello keys are found
/// by this prefix.
const KEY_NAME_PREFIX: &str = "pgp-wallet-poc-biometric-";

fn oaep_hash_algorithm() -> PCWSTR {
    windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALGORITHM
}

fn to_anyhow(context: &str, err: WinError) -> anyhow::Error {
    anyhow::anyhow!("{context} : {err} (code {:#010x})", err.code().0 as u32)
}

/// Heuristique d'AFFICHAGE uniquement : indique si Windows Hello semble
/// configuré, pour ne proposer le bouton d'activation que quand ça a une chance
/// de fonctionner. `enroll`/`unlock` restent fail-closed indépendamment de cette
/// fonction — une réponse erronée ici ne peut jamais affaiblir la sécurité,
/// seulement dégrader l'expérience (proposer un bouton qui échouera, ou
/// l'inverse).
pub fn is_available() -> bool {
    use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};
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
        unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
            .map_err(|e| to_anyhow("ouverture du fournisseur TPM (Microsoft Platform Crypto Provider)", e))?;
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

/// Crée une nouvelle paire de clés RSA persistée dans le TPM, avec une politique
/// UI qui force Windows Hello avant tout usage futur de la clé privée, puis
/// scelle `secret` avec sa clé publique fraîchement créée (RSA-OAEP/SHA-256).
/// Renvoie l'identifiant de la clé (à conserver, nécessaire pour `unlock`/
/// `remove`) et le blob scellé (opaque, à conserver aussi — sans intérêt sans la
/// clé TPM correspondante).
pub fn enroll(secret: &[u8]) -> Result<(String, Vec<u8>)> {
    let provider = Provider::open()?;
    let key_name = format!("{KEY_NAME_PREFIX}{}", hex::encode(crate::entropy::generate_master_entropy()));
    let key_name_wide = HSTRING::from(&key_name);

    // `NCryptCreatePersistedKey` ne persiste réellement la clé qu'au moment de
    // `NCryptFinalizeKey` (avant ça, un échec ici ne laisse rien dans le TPM,
    // pas besoin de nettoyage). En revanche, une fois `NCryptFinalizeKey`
    // réussi, la clé existe vraiment dans le magasin du TPM — si une étape
    // suivante (scellement du secret) échoue ensuite, cette fonction retourne
    // une erreur SANS jamais renvoyer `key_name` à l'appelant, qui ne peut donc
    // jamais la nettoyer plus tard (aucun fichier de métadonnées n'est écrit
    // pour une clé dont l'enrôlement a échoué) : elle resterait orpheline dans
    // le TPM indéfiniment. `finalized` distingue les deux cas pour ne
    // déclencher la suppression best-effort que si la clé a vraiment été créée.
    let mut finalized = false;
    let result = enroll_inner(&provider, &key_name_wide, secret, &mut finalized);
    if result.is_err() && finalized {
        // Best-effort : si ce nettoyage échoue aussi, l'erreur d'origine (déjà
        // dans `result`) reste ce qui est remonté à l'appelant — pas question
        // de masquer l'échec réel de l'enrôlement par un échec de nettoyage.
        let _: Result<()> = (|| {
            let mut handle = NCRYPT_KEY_HANDLE::default();
            unsafe { NCryptOpenKey(provider.0, &mut handle, &key_name_wide, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) }
                .map_err(|e| to_anyhow("ré-ouverture de la clé TPM à nettoyer après échec d'enrôlement", e))?;
            unsafe { NCryptDeleteKey(handle, 0) }.map_err(|e| to_anyhow("nettoyage de la clé TPM après échec d'enrôlement", e))
        })();
    }
    result.map(|sealed| (key_name, sealed))
}

fn enroll_inner(provider: &Provider, key_name_wide: &HSTRING, secret: &[u8], finalized: &mut bool) -> Result<Vec<u8>> {
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
    unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.0 .0), NCRYPT_LENGTH_PROPERTY, &length_bytes, NCRYPT_FLAGS(0)) }
        .map_err(|e| to_anyhow("réglage de la taille de clé TPM", e))?;

    // `NCRYPT_UI_PROTECT_KEY_FLAG` : c'est CE réglage que le fournisseur TPM
    // applique lui-même à chaque usage futur de la clé privée (voir `unlock`) —
    // pas une case à cocher côté application, une politique imposée par le
    // fournisseur de clé/TPM lui-même.
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
    unsafe { NCryptSetProperty(NCRYPT_HANDLE(key.0 .0), NCRYPT_UI_POLICY_PROPERTY, ui_policy_bytes, NCRYPT_FLAGS(0)) }
        .map_err(|e| to_anyhow("réglage de la politique Windows Hello sur la clé TPM", e))?;

    unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }.map_err(|e| to_anyhow("finalisation de la clé TPM", e))?;
    *finalized = true; // la clé existe désormais vraiment dans le TPM

    let padding_algo = oaep_hash_algorithm();
    let padding_info = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: padding_algo,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let padding_info_ptr = &padding_info as *const BCRYPT_OAEP_PADDING_INFO as *const std::ffi::c_void;

    let mut needed: u32 = 0;
    unsafe {
        NCryptEncrypt(
            key.0,
            Some(secret),
            Some(padding_info_ptr),
            None,
            &mut needed,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0 as u32),
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
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0 as u32),
        )
    }
    .map_err(|e| to_anyhow("scellement du secret dans le TPM", e))?;
    sealed.truncate(written as usize);

    Ok(sealed)
}

/// Rouvre la clé TPM persistée `key_name` et déchiffre `sealed_blob` — c'est CET
/// appel qui déclenche et bloque sur le prompt Windows Hello, imposé par le
/// fournisseur de clé (voir `enroll`), jamais par ce code applicatif. Échoue si
/// la vérification est annulée ou échoue, si la clé n'existe plus (Windows Hello
/// réinitialisé, TPM effacé) ou si le blob est corrompu.
pub fn unlock(key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let provider = Provider::open()?;
    let key_name_wide = HSTRING::from(key_name);

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe { NCryptOpenKey(provider.0, &mut key_handle, &key_name_wide, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) }
        .map_err(|e| to_anyhow("ouverture de la clé TPM (déverrouillage biométrique désactivé ou clé absente ?)", e))?;
    let key = KeyHandle(key_handle);

    let padding_algo = oaep_hash_algorithm();
    let padding_info = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: padding_algo,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let padding_info_ptr = &padding_info as *const BCRYPT_OAEP_PADDING_INFO as *const std::ffi::c_void;

    let mut needed: u32 = 0;
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(sealed_blob),
            Some(padding_info_ptr),
            None,
            &mut needed,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0 as u32),
        )
    }
    .map_err(|e| to_anyhow("calcul de la taille du secret déchiffré", e))?;

    let mut secret = Zeroizing::new(vec![0u8; needed as usize]);
    let mut written: u32 = 0;
    // C'est cet appel qui déclenche le prompt Windows Hello (politique UI posée
    // à l'enrôlement) ; il bloque jusqu'à la réponse de l'utilisateur ou
    // l'expiration du délai imposé par l'OS.
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(sealed_blob),
            Some(padding_info_ptr),
            Some(&mut secret),
            &mut written,
            NCRYPT_FLAGS(NCRYPT_PAD_OAEP_FLAG.0 as u32),
        )
    }
    .map_err(|e| to_anyhow("vérification Windows Hello refusée, annulée ou échouée", e))?;
    secret.truncate(written as usize);

    Ok(secret)
}

/// Supprime définitivement la clé TPM persistée — sans cet appel, désactiver le
/// déverrouillage biométrique côté app laisserait une clé orpheline dans le
/// magasin TPM du profil Windows de l'utilisateur.
pub fn remove(key_name: &str) -> Result<()> {
    let provider = Provider::open()?;
    let key_name_wide = HSTRING::from(key_name);

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe { NCryptOpenKey(provider.0, &mut key_handle, &key_name_wide, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)) }
        .context("ouverture de la clé TPM à supprimer")
        .map_err(|_| anyhow::anyhow!("clé TPM déjà absente, rien à supprimer"))?;
    unsafe { NCryptDeleteKey(key_handle, 0) }.map_err(|e| to_anyhow("suppression de la clé TPM", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La fonction d'affichage ne doit jamais paniquer, quel que soit l'état de
    /// Windows Hello sur la machine qui lance les tests (souvent non configuré
    /// sur une machine de CI/dev) — c'est tout ce qu'on peut vérifier sans
    /// matériel biométrique réel.
    #[test]
    fn is_available_never_panics() {
        let _ = is_available();
    }
}
