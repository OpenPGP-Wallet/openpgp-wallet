use anyhow::{anyhow, Result};
use blahaj::{Share, Sharks};

/// Splits `secret` into `total_shares` shares, any `threshold` of which rebuild it
/// (Shamir's scheme).
pub fn split_secret(secret: &[u8], threshold: u8, total_shares: u8) -> Result<Vec<Vec<u8>>> {
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Vec<u8>> = dealer
        .take(total_shares as usize)
        .map(|s| Vec::from(&s))
        .collect();
    Ok(shares)
}

/// Rebuilds the secret from at least `threshold` decrypted shares. Takes `&[u8]`
/// rather than `Vec<u8>` so the caller can pass shares wrapped in `Zeroizing` (2
/// shares are enough to rebuild the secret, so they are as sensitive as the secret
/// itself) without cloning their contents into an unprotected intermediate buffer.
pub fn reconstruct_secret(threshold: u8, raw_shares: &[&[u8]]) -> Result<Vec<u8>> {
    let sharks = Sharks(threshold);
    let shares: std::result::Result<Vec<Share>, _> =
        raw_shares.iter().map(|s| Share::try_from(*s)).collect();
    let shares = shares.map_err(|_| anyhow!("format de part invalide"))?;
    sharks
        .recover(&shares)
        .map_err(|_| anyhow!("échec de la reconstruction (parts insuffisantes ou corrompues)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reconstruct_roundtrip() {
        let secret = b"01234567890123456789012345678901".to_vec(); // 32 bytes
        let shares = split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 of the 3 shares must be enough, whichever they are
        let subset: Vec<&[u8]> = vec![shares[0].as_slice(), shares[2].as_slice()];
        let recovered = reconstruct_secret(2, &subset).unwrap();
        assert_eq!(recovered, secret);
    }
}
