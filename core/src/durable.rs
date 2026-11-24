//! Files that must survive a crash or a power cut: the vault and the FROST seat.
//!
//! A file written then renamed over the old one is atomic for the file system, but its
//! content may still be in the system's cache when the new name is recorded. A power
//! cut at that moment can leave the new name on an empty or zero-filled file, with the
//! old file already gone. The content is therefore flushed to the disk first, so that
//! either the old file or the new one is found, whole.

use std::io::Write;
use std::path::Path;

/// Writes `content` to `path` and waits for the disk to hold it.
pub fn write_synced(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(content)?;
    file.sync_all()
}

/// Replaces `path` with `content`: written and flushed under `temporary` (in the same
/// folder), then renamed over `path`. On failure, `path` is untouched and the temporary
/// file is removed.
pub fn replace(path: &Path, temporary: &Path, content: &[u8]) -> std::io::Result<()> {
    let written = write_synced(temporary, content).and_then(|()| std::fs::rename(temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_durable_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_file_is_replaced_whole_and_no_temporary_file_is_left() {
        let dir = folder("replace");
        let path = dir.join("seat");
        let temporary = dir.join("seat.tmp");
        replace(&path, &temporary, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        replace(&path, &temporary, b"second, longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second, longer");
        assert!(!temporary.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The temporary file cannot be created (its folder does not exist): the file in
    /// place is left as it was.
    #[test]
    fn a_failed_write_leaves_the_file_in_place() {
        let dir = folder("failed");
        let path = dir.join("seat");
        std::fs::write(&path, b"kept").unwrap();
        let temporary = dir.join("missing").join("seat.tmp");
        assert!(replace(&path, &temporary, b"lost").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"kept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
