//! Local state tied to the seed (shielded Zcash database, Monero state, paid
//! recipients): coordination between background syncs and erasing that state
//! (reset, restore).
//!
//! Observed on 2026-10-07 in the test app: the shielded Zcash sync keeps its SQLite
//! database open for a whole pass, Windows then refuses to delete it, and the
//! failure was ignored, so the previous wallet's database survived the reset. A
//! Monero pass in progress would, for its part, have rewritten its state (with the
//! previous wallet's keys) after the erase.
//!
//! A pass holds `pass` while it reads or writes this state and checks `cancelled`
//! between steps; `wipe` asks the passes to stop, waits for them to finish, then
//! erases. The generation rules out a pass whose keys were read before an erase.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard};

static LOCK: RwLock<()> = RwLock::new(());
/// Erases requested and not yet finished: a counter, not a flag. The first of two
/// simultaneous erases to finish must not lift the other's stop request (seen on
/// 2026-10-07: the running pass no longer stopped, and the second erase waited for
/// it until the end).
static WIPING: AtomicUsize = AtomicUsize::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// State generation: read it BEFORE a pass's keys.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// Permission to run a pass; `None`: an erase is in progress, or happened since
/// `generation` (keys of the previous wallet).
pub fn pass(generation: u64) -> Option<RwLockReadGuard<'static, ()>> {
    let guard = LOCK.read().unwrap_or_else(|p| p.into_inner());
    (!cancelled() && GENERATION.load(Ordering::SeqCst) == generation).then_some(guard)
}

/// Erase requested: the running pass stops as soon as possible.
pub fn cancelled() -> bool {
    WIPING.load(Ordering::SeqCst) > 0
}

/// Stops the passes, waits for them to finish, then runs `erase`.
pub fn wipe<T>(erase: impl FnOnce() -> T) -> T {
    // Request lifted at the end, even if `erase` panics.
    struct Request;
    impl Drop for Request {
        fn drop(&mut self) {
            WIPING.fetch_sub(1, Ordering::SeqCst);
        }
    }
    WIPING.fetch_add(1, Ordering::SeqCst);
    let _request = Request;
    let _guard = LOCK.write().unwrap_or_else(|p| p.into_inner());
    GENERATION.fetch_add(1, Ordering::SeqCst);
    erase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The erase waits for the running pass, which sees the stop request; a pass whose
    /// keys predate it is then refused.
    #[test]
    fn wipe_waits_for_the_running_pass() {
        // Other tests reset in parallel: the pass takes the current generation, with
        // retries.
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
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "demande d'arrêt jamais vue"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(100));
            // Time noted BEFORE releasing the lock: the erase can start right after.
            let ended = Instant::now();
            drop(pass_guard);
            ended
        });
        let used = started_pass.recv().unwrap();
        let erased_at = wipe(Instant::now);
        let pass_ended = worker.join().unwrap();
        assert!(erased_at >= pass_ended, "effacé pendant la passe");
        assert!(pass(used).is_none(), "clés d'avant l'effacement acceptées");
    }
}
