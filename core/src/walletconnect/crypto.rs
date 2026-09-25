//! Primitives cryptographiques du protocole WalletConnect v2, reproduites
//! d'après le code de référence du SDK officiel (`packages/utils/src/crypto.ts`
//! du monorepo WalletConnect, lu directement) :
//! - échange X25519, puis clé symétrique = HKDF-SHA256(secret partagé, sans
//!   sel, sans info, 32 octets) ;
//! - "topic" (canal du relais) = SHA-256 de la clé symétrique, en hexadécimal ;
//! - enveloppe = base64 (avec remplissage) de `type (1 octet) | [clé publique
//!   de l'émetteur (32), type 1 seulement] | nonce (12) | ChaCha20-Poly1305(message)`,
//!   sans données authentifiées additionnelles.
//!
//! Chaque fonction est vérifiée octet par octet contre des vecteurs produits par
//! les bibliothèques mêmes du SDK officiel (voir les tests).

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const TYPE_0: u8 = 0;
const TYPE_1: u8 = 1;
const IV_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
/// Étiquette d'authentification Poly1305.
const TAG_LENGTH: usize = 16;

/// Paire de clés X25519 (clé privée effacée de la mémoire à la destruction).
pub struct KeyPair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow!("génération d'aléa impossible : {e}"))?;
    Ok(buf)
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_private(random_bytes::<32>()?))
    }

    /// Clampage RFC 7748 appliqué par `mul_base_clamped` — identique à
    /// `x25519.getPublicKey` de la bibliothèque de référence.
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Self { private: Zeroizing::new(private), public }
    }
}

/// Clé symétrique d'une session, dérivée de notre clé privée et de la clé
/// publique du pair. Refuse un secret partagé nul : clé publique du pair de
/// petit ordre (point dégénéré), qui donnerait une clé connue de tous.
pub fn derive_sym_key(own_private: &[u8; 32], peer_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = Zeroizing::new(MontgomeryPoint(*peer_public).mul_clamped(*own_private).to_bytes());
    anyhow::ensure!(shared.iter().any(|&b| b != 0), "clé publique du pair invalide (point de petit ordre)");
    let mut sym_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared.as_slice())
        .expand(&[], sym_key.as_mut_slice())
        .map_err(|_| anyhow!("dérivation HKDF impossible"))?;
    Ok(sym_key)
}

/// Topic (canal de publication du relais) associé à une clé, en hexadécimal.
pub fn topic_for_key(key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(key))
}

fn cipher(sym_key: &[u8; 32]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(sym_key).map_err(|_| anyhow!("clé ChaCha20-Poly1305 invalide"))
}

fn seal(sym_key: &[u8; 32], iv: &[u8; IV_LENGTH], plaintext: &str) -> Result<Vec<u8>> {
    cipher(sym_key)?
        .encrypt(&Nonce::from(*iv), plaintext.as_bytes())
        .map_err(|_| anyhow!("chiffrement ChaCha20-Poly1305 impossible"))
}

/// Enveloppe de type 0 (le cas général : clé symétrique déjà partagée), nonce
/// aléatoire. `encrypt_type0_with_iv` n'existe que pour les vecteurs de test.
pub fn encrypt_type0(sym_key: &[u8; 32], plaintext: &str) -> Result<String> {
    encrypt_type0_with_iv(sym_key, &random_bytes::<IV_LENGTH>()?, plaintext)
}

fn encrypt_type0_with_iv(sym_key: &[u8; 32], iv: &[u8; IV_LENGTH], plaintext: &str) -> Result<String> {
    let mut out = vec![TYPE_0];
    out.extend_from_slice(iv);
    out.extend_from_slice(&seal(sym_key, iv, plaintext)?);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Enveloppe déchiffrée : texte clair, et clé publique de l'émetteur pour une
/// enveloppe de type 1 (utilisée par le protocole quand la clé symétrique
/// n'est pas encore connue du destinataire).
pub struct Opened {
    pub plaintext: String,
    pub sender_public: Option<[u8; 32]>,
}

/// Déchiffre une enveloppe de type 0 ou 1 avec `sym_key`. Toute enveloppe
/// tronquée, d'un autre type, altérée (étiquette Poly1305 fausse) ou dont le
/// contenu n'est pas de l'UTF-8 est refusée — jamais de panique sur une donnée
/// venue du réseau.
pub fn decrypt(sym_key: &[u8; 32], encoded: &str) -> Result<Opened> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("enveloppe WalletConnect : base64 invalide")?;
    let (&kind, rest) = bytes.split_first().ok_or_else(|| anyhow!("enveloppe WalletConnect vide"))?;
    let (sender_public, rest) = match kind {
        TYPE_0 => (None, rest),
        TYPE_1 => {
            anyhow::ensure!(rest.len() >= KEY_LENGTH, "enveloppe WalletConnect tronquée");
            let (key, rest) = rest.split_at(KEY_LENGTH);
            (Some(<[u8; 32]>::try_from(key).expect("longueur vérifiée")), rest)
        }
        other => anyhow::bail!("type d'enveloppe WalletConnect non pris en charge : {other}"),
    };
    anyhow::ensure!(rest.len() >= IV_LENGTH + TAG_LENGTH, "enveloppe WalletConnect tronquée");
    let (iv, sealed) = rest.split_at(IV_LENGTH);
    let iv: [u8; IV_LENGTH] = iv.try_into().expect("longueur vérifiée");
    let plaintext = cipher(sym_key)?
        .decrypt(&Nonce::from(iv), sealed)
        .map_err(|_| anyhow!("enveloppe WalletConnect indéchiffrable (mauvaise clé ou message altéré)"))?;
    Ok(Opened {
        plaintext: String::from_utf8(plaintext).context("message WalletConnect non UTF-8")?,
        sender_public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// Vecteurs produits par les bibliothèques du SDK officiel (@noble/curves,
    /// @noble/hashes, @noble/ciphers), avec le code exact de
    /// `utils/src/crypto.ts` (`deriveSymKey`, `hashKey`, `serialize`).
    #[test]
    fn key_agreement_and_topic_match_the_official_sdk() {
        let a = KeyPair::from_private([0xaa; 32]);
        let b = KeyPair::from_private([0xbb; 32]);
        assert_eq!(hex::encode(a.public), "14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070");
        assert_eq!(hex::encode(b.public), "6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b");
        let sym = derive_sym_key(&a.private, &b.public).unwrap();
        assert_eq!(hex::encode(*sym), "4c8ef98d347067c5ec8db6833c8d2ff633650c21b72fb864caee11f70f6e8916");
        assert_eq!(*derive_sym_key(&b.private, &a.public).unwrap(), *sym, "les deux côtés obtiennent la même clé");
        assert_eq!(topic_for_key(&sym), "3ffcb98d9e16876dc79de08095d125359d1139e209f408c48c027e5f8776d599");
    }

    #[test]
    fn envelopes_match_the_official_sdk_and_round_trip() {
        let key = [0x11; 32];
        let iv = [0x22; 12];
        let msg = r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#;
        let type0 = "ACIiIiIiIiIiIiIiIv5XvHofqpxb/wiCk5VwugwFx2OqdeLw2lwwSpXd+851cAvVG4vfLrb197owuHVrkAfsJbITpiOzF9nL2gx7iEVqlyhlFCnroVPliql3XA==";
        assert_eq!(encrypt_type0_with_iv(&key, &iv, msg).unwrap(), type0);
        let opened = decrypt(&key, type0).unwrap();
        assert_eq!(opened.plaintext, msg);
        assert!(opened.sender_public.is_none());

        // Type 1 : produit par le SDK (clé publique de l'émetteur en clair).
        let type1 = "ARTKnk04e8zzV0bgQH2qrMayik+ERe9aUViJTbmD4kBwIiIiIiIiIiIiIiIi/le8eh+qnFv/CIKTlXC6DAXHY6p14vDaXDBKld37znVwC9Ubi98utvX3ujC4dWuQB+wlshOmI7MX2cvaDHuIRWqXKGUUKeuhU+WKqXdc";
        let opened = decrypt(&key, type1).unwrap();
        assert_eq!(opened.plaintext, msg);
        assert_eq!(opened.sender_public, Some(h32("14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070")));

        // Nonce aléatoire : deux chiffrements du même message diffèrent, et se déchiffrent.
        let (x, y) = (encrypt_type0(&key, msg).unwrap(), encrypt_type0(&key, msg).unwrap());
        assert_ne!(x, y);
        assert_eq!(decrypt(&key, &x).unwrap().plaintext, msg);
    }

    #[test]
    fn tampered_truncated_or_foreign_envelopes_are_refused_without_panic() {
        let key = [0x11; 32];
        let good = encrypt_type0(&key, "bonjour").unwrap();
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(&good).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert!(decrypt(&key, &tampered).is_err(), "étiquette altérée");
        assert!(decrypt(&[0x12; 32], &good).is_err(), "mauvaise clé");
        for garbage in ["", "AA==", "AQ==", "Ag==", "pas du base64 !"] {
            assert!(decrypt(&key, garbage).is_err(), "{garbage}");
        }
    }

    /// Clé publique de petit ordre (ici le point nul) : le secret partagé serait
    /// nul, donc connu de tous — refusé.
    #[test]
    fn low_order_peer_keys_are_refused() {
        let a = KeyPair::from_private([0xaa; 32]);
        assert!(derive_sym_key(&a.private, &[0u8; 32]).is_err());
    }
}
