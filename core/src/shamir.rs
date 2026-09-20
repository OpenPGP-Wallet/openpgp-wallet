use anyhow::{anyhow, Result};
use blahaj::{Share, Sharks};

/// Découpe `secret` en `total_shares` parts, dont `threshold` suffisent
/// à le reconstruire (schéma de Shamir).
pub fn split_secret(secret: &[u8], threshold: u8, total_shares: u8) -> Result<Vec<Vec<u8>>> {
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Vec<u8>> = dealer.take(total_shares as usize).map(|s| Vec::from(&s)).collect();
    Ok(shares)
}

/// Reconstitue le secret à partir d'au moins `threshold` parts déchiffrées.
/// Prend des `&[u8]` plutôt que des `Vec<u8>` pour permettre à l'appelant de passer
/// des parts enveloppées dans `Zeroizing` (2 parts suffisant à reconstruire le
/// secret, elles sont aussi sensibles que lui) sans avoir à en cloner le contenu
/// dans un buffer intermédiaire non protégé.
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
        let secret = b"01234567890123456789012345678901".to_vec(); // 32 octets
        let shares = split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // 2 parts sur 3 doivent suffire, peu importe lesquelles
        let subset: Vec<&[u8]> = vec![shares[0].as_slice(), shares[2].as_slice()];
        let recovered = reconstruct_secret(2, &subset).unwrap();
        assert_eq!(recovered, secret);
    }
}
