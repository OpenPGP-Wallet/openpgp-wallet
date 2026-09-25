//! Abstraction sur le stockage de la clé privée PGP de l'appareil : privilégie
//! le coffre natif de l'OS (Windows Credential Manager / macOS Keychain /
//! Linux Secret Service, crate `keyring`) à un simple fichier `.asc` — un vrai
//! contrôle d'accès du système d'exploitation (lié à la session utilisateur),
//! pas seulement un chemin de fichier à deviner. Voir `api.rs` pour
//! l'orchestration (repli sur fichier si le coffre OS est indisponible,
//! jamais de blocage de la création/du déverrouillage du wallet à cause de
//! ça, et compatibilité avec les coffres créés avant ce changement).
//!
//! L'entrée du coffre OS est identifiée par un hash du chemin absolu de
//! `data_dir`, jamais un nom fixe : plusieurs wallets sur la même machine
//! (un vrai + des données de test, par exemple) doivent avoir des entrées de
//! coffre OS complètement isolées, exactement comme ils ont déjà des
//! fichiers séparés aujourd'hui.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

const SERVICE: &str = "pgp-wallet-poc";

/// Identifiant stable et unique par `data_dir`, jamais le chemin en clair
/// (inutile de l'exposer tel quel dans le coffre OS, et certains chemins
/// contiendraient des caractères que certains backends n'aiment pas). `pub`
/// (pas `pub(crate)`) pour la même raison que `OsKeyStore` : utilisable
/// depuis `src/bin/keyring_spike.rs`.
pub fn entry_username(data_dir: &Path) -> String {
    let hash = Sha256::digest(data_dir.to_string_lossy().as_bytes());
    format!("device_privkey_{}", hex::encode(&hash[..16]))
}

/// Abstraction injectable pour les tests — même motif que `SecretSealer`/
/// `WindowsHelloSealer` déjà en place pour le déverrouillage biométrique
/// (voir `api.rs`) : les tests utilisent un coffre en mémoire plutôt que le
/// vrai coffre OS, pour ne jamais polluer le Gestionnaire d'identification/
/// Trousseau réel de la machine qui exécute `cargo test`, et pour ne pas
/// dépendre d'un coffre OS réellement configuré sur une machine de CI.
pub trait KeyStore: Sync {
    fn write(&self, username: &str, secret: &str) -> Result<()>;
    /// `Zeroizing<String>` (jamais un `String` nu) : le contenu est une clé
    /// privée PGP en clair — trouvé lors d'un audit indépendant (pas
    /// seulement `cargo test`) que la version initiale de ce trait renvoyait
    /// un `String` ordinaire, jamais effacé de la mémoire après usage,
    /// contrairement à tous les autres buffers de clé privée/entropie de ce
    /// projet (`Zeroizing` partout ailleurs, voir le 2ᵉ passage d'auto-revue
    /// dans ETAPES.md).
    fn read(&self, username: &str) -> Result<Zeroizing<String>>;
    fn remove(&self, username: &str) -> Result<()>;
}

/// `pub` (pas `pub(crate)`) uniquement pour rester utilisable depuis
/// `src/bin/keyring_spike.rs`, un binaire séparé qui dépend de cette crate
/// comme une dépendance externe — même raison que `windows_hello::enroll`/
/// `unlock`/`remove` sont `pub` pour `tpm_hello_spike.rs`.
pub struct OsKeyStore;

impl KeyStore for OsKeyStore {
    // `set_secret`/`get_secret` (octets bruts), jamais `set_password`/
    // `get_password` (texte) : trouvé empiriquement (`keyring_spike --
    // full-cycle`) que le backend Windows de `keyring` convertit un mot de
    // passe en UTF-16 AVANT de l'écrire (pour l'interopérabilité avec les
    // API Windows natives, qui attendent des mots de passe en UTF-16) — ce
    // qui DOUBLE la taille en octets d'un texte ASCII comme notre clé PGP
    // armorée. Une clé de 1337 octets (mesurée sur un coffre réel de ce
    // projet) dépassait ainsi la limite réelle de Windows Credential Manager
    // (2560 octets) une fois convertie (2674 octets), alors que 1337 octets
    // BRUTS tiennent confortablement dans cette même limite. `set_secret`
    // écrit les octets tels quels sur toutes les plateformes (Windows ET la
    // valeur par défaut du trait utilisée par macOS/Linux), donc plus
    // cohérent ET plus compact.
    fn write(&self, username: &str, secret: &str) -> Result<()> {
        keyring::Entry::new(SERVICE, username)
            .and_then(|e| e.set_secret(secret.as_bytes()))
            .context("écriture dans le coffre natif de l'OS")
    }

    fn read(&self, username: &str) -> Result<Zeroizing<String>> {
        let secret = keyring::Entry::new(SERVICE, username)
            .and_then(|e| e.get_secret())
            .context("lecture depuis le coffre natif de l'OS")?;
        // `secret` (octets bruts) directement consommé par `from_utf8`, jamais
        // cloné : un seul buffer existe à tout moment, celui qui finit
        // enveloppé dans le `Zeroizing` renvoyé.
        String::from_utf8(secret).map(Zeroizing::new).context("contenu du coffre OS non-UTF8 (corruption ?)")
    }

    fn remove(&self, username: &str) -> Result<()> {
        keyring::Entry::new(SERVICE, username)
            .and_then(|e| e.delete_credential())
            .context("suppression dans le coffre natif de l'OS")
    }
}

/// Faux coffre en mémoire pour les tests (voir la doc du trait) — jamais
/// utilisé en production.
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

    fn read(&self, username: &str) -> Result<Zeroizing<String>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(username)
            .cloned()
            .map(Zeroizing::new)
            .ok_or_else(|| anyhow::anyhow!("clé absente du coffre en mémoire (test)"))
    }

    fn remove(&self, username: &str) -> Result<()> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(username);
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
        assert_eq!(a, b, "même data_dir -> même identifiant, sinon un wallet existant deviendrait illisible");
        assert_ne!(c, a, "des data_dir différents ne doivent jamais partager la même entrée de coffre OS");
    }

    #[test]
    fn in_memory_key_store_round_trips_and_isolates_by_username() {
        let store = InMemoryKeyStore::default();
        store.write("alice", "secret-a").unwrap();
        store.write("bob", "secret-b").unwrap();
        assert_eq!(store.read("alice").unwrap().as_str(), "secret-a");
        assert_eq!(store.read("bob").unwrap().as_str(), "secret-b");
        store.remove("alice").unwrap();
        assert!(store.read("alice").is_err(), "une entrée supprimée ne doit plus être lisible");
        assert_eq!(store.read("bob").unwrap().as_str(), "secret-b", "supprimer une entrée ne doit pas affecter les autres");
    }
}
