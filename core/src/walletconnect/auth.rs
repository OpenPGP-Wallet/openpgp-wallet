//! Authentification auprès du relais WalletConnect : un JWT signé en Ed25519
//! par une clé propre à ce client (sans rapport avec les clés du portefeuille),
//! reproduit d'après `relay-auth` (dépôt `walletconnect-utils`, lu directement) :
//! en-tête `{"alg":"EdDSA","typ":"JWT"}`, charge `{"iss","sub","aud","iat","exp"}`
//! dans CET ordre, `iss` = `did:key:z` + base58btc(0xED 0x01 + clé publique),
//! `sub` = 32 octets aléatoires en hexadécimal, `aud` = URL du relais, durée 1 jour,
//! le tout en base64url sans remplissage, signature Ed25519 de `en-tête.charge`.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

/// Préfixe multicodec d'une clé publique Ed25519 ("K36" en base58btc).
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];
pub const JWT_TTL_SECS: u64 = 86_400;

/// Identifiant DID de la clé du client (`iss` du JWT).
pub fn did_key(public: &[u8; 32]) -> String {
    let mut bytes = MULTICODEC_ED25519.to_vec();
    bytes.extend_from_slice(public);
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// JWT d'authentification. `client_seed` : graine Ed25519 de ce client
/// (persistée, voir `store`) ; `sub` : identifiant aléatoire de la connexion.
/// Les trois valeurs interpolées ci-dessous (DID base58, hexadécimal, URL fixe
/// du relais) ne contiennent jamais de caractère à échapper en JSON.
pub fn sign_jwt(client_seed: &[u8; 32], sub: &str, aud: &str, iat: u64) -> String {
    let key = SigningKey::from_bytes(client_seed);
    let iss = did_key(&key.verifying_key().to_bytes());
    let header = b64url(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let exp = iat + JWT_TTL_SECS;
    let payload = b64url(format!(r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","iat":{iat},"exp":{exp}}}"#).as_bytes());
    let data = format!("{header}.{payload}");
    let signature = key.sign(data.as_bytes());
    format!("{data}.{}", b64url(&signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteur produit par `@walletconnect/relay-auth` (`generateKeyPair(seed)`,
    /// `signJWT(sub, aud, 86400, keyPair, iat)`), vérifié valide par son propre
    /// `verifyJWT` : Ed25519 étant déterministe, le JWT doit être identique au
    /// caractère près.
    #[test]
    fn relay_jwt_matches_the_official_relay_auth_library() {
        let seed = [0x33; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(did_key(&public), "did:key:z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5");
        let jwt = sign_jwt(&seed, &"44".repeat(32), "wss://relay.walletconnect.org", 1_700_000_000);
        assert_eq!(
            jwt,
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtnNDlOdFFSMkx5WVJEQ1FGSzR3MVZWSHFoeXBaU1NSbzdIc3l1TjdTVjd2NSIsInN1YiI6IjQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0Lm9yZyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.RsKOvPuk8f3cwqBtptVmgvh9sdKdw0tDrrW5-gQJ7M-Wi4m32ovRn5CWLJ3vmZ2Di6ZqcIFCLC_7VUWim821AQ"
        );
    }
}
