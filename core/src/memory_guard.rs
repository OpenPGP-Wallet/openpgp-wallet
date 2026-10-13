use zeroize::Zeroize;

/// Explicitly wipes a sensitive buffer in memory (overwrites it with zeros in a way
/// the compiler cannot optimize away).
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Locks the memory pages of a sensitive buffer against swapping to disk (`mlock`
/// on Unix, `VirtualLock` on Windows, through the `region` crate). Returns a guard
/// that unlocks automatically when dropped: keep it alive (do not `drop` it or let
/// it go out of scope) as long as the buffer holds a secret, then call [`wipe`]
/// before or while the buffer is freed.
///
/// WARNING: the locked buffer must not be reallocated (`resize`, `push` beyond its
/// capacity, `clone`...) while the guard is active: the locked address would become
/// stale and the new buffer would no longer be protected. Use it on a buffer that
/// already has its final size.
///
/// Best effort: if locking fails (system limit, permissions, which can happen in a
/// container or with a low `ulimit -l`), a warning is printed and the caller
/// carries on. `zeroize` remains the main wiping guarantee; `lock` is only an extra
/// defensive layer.
#[must_use = "le verrouillage se termine dès que le guard est abandonné"]
pub fn lock(buf: &[u8]) -> Option<region::LockGuard> {
    if buf.is_empty() {
        return None;
    }
    match region::lock(buf.as_ptr(), buf.len()) {
        Ok(guard) => Some(guard),
        Err(e) => {
            eprintln!("avertissement : verrouillage mémoire (mlock) impossible : {e}");
            None
        }
    }
}
