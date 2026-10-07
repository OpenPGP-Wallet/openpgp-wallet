//! État local lié à la graine (base Zcash protégée, état Monero, destinataires
//! payés) : coordination entre les synchronisations de fond et son effacement
//! (réinitialisation, restauration).
//!
//! Constaté le 07/10/2026 sur l'app de test : la synchronisation Zcash protégée
//! garde sa base SQLite ouverte pendant toute une passe, Windows refuse alors de
//! l'effacer, et l'échec était ignoré — la base de l'ancien portefeuille
//! survivait à la réinitialisation. Une passe Monero en cours, elle, aurait
//! réécrit son état (clés de l'ancien portefeuille) après l'effacement.
//!
//! Une passe tient `pass` pendant qu'elle lit ou écrit cet état et interroge
//! `cancelled` entre deux étapes ; `wipe` demande l'arrêt des passes, attend
//! leur fin, puis efface. La génération écarte une passe dont les clés ont été
//! lues avant un effacement.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{RwLock, RwLockReadGuard};

static LOCK: RwLock<()> = RwLock::new(());
static WIPING: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Génération de l'état : à lire AVANT les clés d'une passe.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// Autorisation de passe ; `None` : effacement en cours, ou survenu depuis
/// `generation` (clés de l'ancien portefeuille).
pub fn pass(generation: u64) -> Option<RwLockReadGuard<'static, ()>> {
    let guard = LOCK.read().unwrap_or_else(|p| p.into_inner());
    (!cancelled() && GENERATION.load(Ordering::SeqCst) == generation).then_some(guard)
}

/// Effacement demandé : la passe en cours s'arrête au plus tôt.
pub fn cancelled() -> bool {
    WIPING.load(Ordering::SeqCst)
}

/// Arrête les passes, attend leur fin, puis exécute `erase`.
pub fn wipe<T>(erase: impl FnOnce() -> T) -> T {
    WIPING.store(true, Ordering::SeqCst);
    let result = {
        let _guard = LOCK.write().unwrap_or_else(|p| p.into_inner());
        GENERATION.fetch_add(1, Ordering::SeqCst);
        erase()
    };
    WIPING.store(false, Ordering::SeqCst);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// L'effacement attend la passe en cours, qui voit la demande d'arrêt ;
    /// une passe dont les clés datent d'avant est ensuite refusée.
    #[test]
    fn wipe_waits_for_the_running_pass() {
        // D'autres tests réinitialisent en parallèle : la passe prend la
        // génération du moment, essais répétés.
        let (ready, started_pass) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (used, pass_guard) = loop {
                let current = generation();
                if let Some(guard) = pass(current) {
                    break (current, guard);
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            ready.send(used).unwrap();
            let started = Instant::now();
            while !cancelled() {
                assert!(started.elapsed() < Duration::from_secs(5), "demande d'arrêt jamais vue");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(100));
            drop(pass_guard);
            Instant::now()
        });
        let used = started_pass.recv().unwrap();
        let erased_at = wipe(Instant::now);
        let pass_ended = worker.join().unwrap();
        assert!(erased_at >= pass_ended, "effacé pendant la passe");
        assert!(pass(used).is_none(), "clés d'avant l'effacement acceptées");
    }
}
