//! Authentication with the WalletConnect relay: a JWT signed with Ed25519 by a key
//! specific to this client (unrelated to the wallet's keys), reproduced from
//! `relay-auth` (in the `walletconnect-utils` repository, read directly): header
//! `{"alg":"EdDSA","typ":"JWT"}`, payload `{"iss","sub","aud","iat","exp"}` in THAT
//! order, `iss` = `did:key:z` + base58btc(0xED 0x01 + public key), `sub` = 32 random
//! bytes in hex, `aud` = relay URL, valid for 1 day, all in unpadded base64url, with
//! an Ed25519 signature of `header.payload`.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

/// Multicodec prefix of an Ed25519 public key ("K36" in base58btc).
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];
pub const JWT_TTL_SECS: u64 = 86_400;

/// DID of the client key (the JWT's `iss`).
pub fn did_key(public: &[u8; 32]) -> String {
    let mut bytes = MULTICODEC_ED25519.to_vec();
    bytes.extend_from_slice(public);
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Authentication JWT. `client_seed`: this client's Ed25519 seed (persisted, see
/// `store`); `sub`: random connection identifier. The three values interpolated
/// below (base58 DID, hex, fixed relay URL) never contain a character that needs
/// escaping in JSON.
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

    /// Vector produced by `@walletconnect/relay-auth` (`generateKeyPair(seed)`,
    /// `signJWT(sub, aud, 86400, keyPair, iat)`) and accepted by its own `verifyJWT`:
    /// since Ed25519 is deterministic, the JWT must match character for character.
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
