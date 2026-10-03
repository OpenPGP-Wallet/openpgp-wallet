//! Clé d'API Etherscan de l'utilisateur (gratuite, créée sur etherscan.io),
//! saisie dans Paramètres et gardée sur cet appareil : elle ouvre
//! l'historique des réseaux qu'aucun indexeur public sans clé ne couvre —
//! HyperEVM avec l'offre gratuite ; BNB Chain avec une offre Etherscan
//! payante seulement (relevé le 03/10/2026 : « Free API access is not
//! supported for this chain »).
//!
//! Ce n'est pas un secret du portefeuille : elle ne donne accès qu'à des
//! données publiques, et Etherscan n'y associe que les adresses publiques
//! interrogées. Jamais embarquée dans l'app (chaque utilisateur la sienne),
//! jamais renvoyée en entier à l'interface (`masked`), jamais recopiée dans
//! un message d'erreur (voir `routescan::get`).

use anyhow::{ensure, Context, Result};
use std::path::Path;
use std::sync::RwLock;

const KEY_FILE: &str = "etherscan_key.txt";

static KEY: RwLock<Option<String>> = RwLock::new(None);

/// Clé enregistrée, si l'utilisateur en a saisi une.
pub fn current() -> Option<String> {
    KEY.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Forme affichable de la clé enregistrée : 4 premiers et 4 derniers caractères.
pub fn masked() -> Option<String> {
    current().map(|key| mask(&key))
}

fn mask(key: &str) -> String {
    format!("{}…{}", &key[..4], &key[key.len() - 4..])
}

/// Clé au format d'Etherscan (34 majuscules et chiffres ; 30 à 40 admis) :
/// une autre saisie (adresse 0x…, phrase, lien) est refusée.
fn normalize(key: &str) -> Result<String> {
    let key = key.trim();
    ensure!(
        (30..=40).contains(&key.len()) && key.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
        "clé Etherscan invalide : 34 lettres majuscules et chiffres attendus (à copier depuis etherscan.io/myapikey)"
    );
    Ok(key.to_string())
}

/// Relit la clé enregistrée sur l'appareil (au démarrage de l'app).
pub fn load(data_dir: &Path) -> Result<()> {
    let key = match std::fs::read_to_string(data_dir.join(KEY_FILE)) {
        Ok(text) => Some(normalize(&text)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("clé Etherscan illisible"),
    };
    *KEY.write().unwrap_or_else(|p| p.into_inner()) = key;
    Ok(())
}

/// Enregistre la clé sur l'appareil (écriture atomique), ou la supprime si
/// `key` est vide. Renvoie sa forme masquée.
pub fn save(data_dir: &Path, key: &str) -> Result<Option<String>> {
    let path = data_dir.join(KEY_FILE);
    let key = if key.trim().is_empty() { None } else { Some(normalize(key)?) };
    match &key {
        Some(key) => {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, key).context("enregistrement de la clé Etherscan impossible")?;
            std::fs::rename(&tmp, &path).context("enregistrement de la clé Etherscan impossible")?;
        }
        None => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e).context("suppression de la clé Etherscan impossible"),
            _ => {}
        },
    }
    let shown = key.as_deref().map(mask);
    *KEY.write().unwrap_or_else(|p| p.into_inner()) = key;
    Ok(shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_validated_masked_saved_and_removed() {
        assert!(normalize("0x59D78c44ac60F09369b544778358704B7b18E6ba").is_err(), "adresse");
        assert!(normalize("https://etherscan.io/myapikey").is_err(), "lien");
        assert!(normalize("court").is_err());
        let key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678";
        assert_eq!(normalize(&format!("  {key}\n")).unwrap(), key);
        assert_eq!(mask(key), "ABCD…5678");

        let dir = std::env::temp_dir().join(format!("etherscan-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(save(&dir, key).unwrap().as_deref(), Some("ABCD…5678"));
        *KEY.write().unwrap() = None;
        load(&dir).unwrap();
        assert_eq!(current().as_deref(), Some(key), "relue au démarrage");
        assert!(save(&dir, "pas une clé !").is_err());
        assert_eq!(current().as_deref(), Some(key), "saisie refusée : clé inchangée");
        assert_eq!(save(&dir, "").unwrap(), None);
        assert!(current().is_none() && !dir.join(KEY_FILE).exists(), "supprimée");
        load(&dir).unwrap();
        assert!(current().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
