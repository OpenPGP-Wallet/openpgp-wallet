//! Bodies of HTTP answers, read up to a limit.
//!
//! `response.json()` and `response.text()` read whatever the server sends: a node or an
//! indexer that answers with gigabytes, by fault or on purpose, would fill the memory
//! until the app stops. An answer has a known order of size, so its body is read up to a
//! limit and refused beyond it. Found in audit round 34; Tezos is the first network to
//! use it.

use std::io::Read;

/// Reads `body` to its end, at most `max` bytes. A longer body is an error, and nothing
/// beyond the limit is kept in memory.
pub fn read(body: impl Read, max: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    body.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "réponse trop volumineuse",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_is_read_up_to_the_limit_and_refused_beyond() {
        assert_eq!(read(&b"abcd"[..], 4).unwrap(), b"abcd");
        assert_eq!(read(&b""[..], 0).unwrap(), b"");
        assert!(read(&b"abcde"[..], 4).is_err());
        // A body that never ends is refused once the limit is passed, not read forever.
        assert!(read(std::io::repeat(7), 1024).is_err());
    }
}
