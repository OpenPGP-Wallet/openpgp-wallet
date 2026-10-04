//! Date de création du portefeuille de cet appareil : les synchronisations des
//! cryptos privées (Monero, Zcash protégé) commencent peu avant elle, au lieu
//! de la naissance fixe de l'app — sinon leur première synchronisation
//! s'allongerait avec le temps (une journée de chaîne ≈ 2 min pour Monero).
//!
//! Connue seulement pour un portefeuille CRÉÉ ici (entropie neuve : aucun fonds
//! ne peut être plus ancien). Après une restauration, inconnue — les fonds
//! peuvent dater d'avant — : naissance fixe. « Réanalyser depuis le début »
//! (Paramètres) l'oublie aussi.
//!
//! Le premier bloc est estimé à partir de la hauteur actuelle de la chaîne et
//! du temps écoulé depuis la création, mesurés avec la même horloge (une
//! horloge simplement décalée ne fausse pas l'écart), moins une marge de
//! 3 jours ; jamais avant la naissance fixe.

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

/// Portefeuille créé sur cet appareil à l'instant.
pub fn record_created(data_dir: &Path) -> Result<()> {
    std::fs::write(data_dir.join(FILE), serde_json::to_vec(&Created { unix: now() })?).context("date de création du portefeuille : enregistrement impossible")
}

/// Date oubliée (restauration, réinitialisation, réanalyse complète).
pub fn forget(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(FILE));
}

fn created_unix(data_dir: &Path) -> Option<u64> {
    let bytes = std::fs::read(data_dir.join(FILE)).ok()?;
    serde_json::from_slice::<Created>(&bytes).ok().map(|c| c.unix)
}

/// Premier bloc à analyser sur une chaîne dont le dernier bloc est `tip`
/// (`block_secs` secondes par bloc) : peu avant la création du portefeuille,
/// jamais avant `fixed` (la naissance fixe de l'app), jamais après `tip`.
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
        // Restauration (date inconnue) : naissance fixe.
        assert_eq!(start_height_at(None, 1_000_000, tip, 120, fixed), fixed);
        // Créé il y a 10 jours : 10 + 3 jours de blocs Monero en arrière.
        let now = 2_000_000_000;
        assert_eq!(start_height_at(Some(now - 10 * 86_400), now, tip, 120, fixed), tip - 13 * 720);
        // Créé il y a très longtemps : jamais avant la naissance fixe.
        assert_eq!(start_height_at(Some(0), now, tip, 120, fixed), fixed);
        // Horloge revenue en arrière depuis la création : marge seule (3 jours).
        assert_eq!(start_height_at(Some(now + 86_400), now, tip, 120, fixed), tip - 3 * 720);
        // Chaîne encore sous la naissance fixe (nœud en retard) : jamais au-delà du dernier bloc connu… ni avant la naissance.
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
