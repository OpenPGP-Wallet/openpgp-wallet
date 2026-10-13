use anyhow::{anyhow, Context, Result};
use openpgp::cert::Cert;
use openpgp::crypto::{KeyPair, Password, SessionKey};
use openpgp::parse::stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper};
use openpgp::parse::{PacketParser, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{KeyHandle, Packet};
use sequoia_openpgp as openpgp;
use std::io::{Read, Write};
use std::time::SystemTime;

/// The moment at which OUR own keys are evaluated (backup shares, device vault,
/// Windows Hello): the computer's time, but never before the key was created.
/// Evaluated at the current time alone, a key "not created yet" for a clock running
/// behind (motherboard battery, an offline PC set wrong) could no longer be used,
/// neither to restore nor to unlock, until the clock was fixed, even when it was
/// only one minute behind (measured). These keys are created without an expiry and
/// are never revoked, so nothing the date protects is lost. Other people's keys
/// (`messaging.rs`) are still evaluated at the computer's time (their expiry
/// matters).
fn own_key_time(cert: &Cert) -> SystemTime {
    let now = SystemTime::now();
    let newest = cert
        .clone()
        .into_packets()
        .filter_map(|packet| match packet {
            Packet::PublicKey(k) => Some(k.creation_time()),
            Packet::PublicSubkey(k) => Some(k.creation_time()),
            Packet::SecretKey(k) => Some(k.creation_time()),
            Packet::SecretSubkey(k) => Some(k.creation_time()),
            Packet::Signature(sig) => sig.signature_creation_time(),
            _ => None,
        })
        .max();
    newest.map_or(now, |newest| newest.max(now))
}

/// Encrypts a share (bytes) for the holder of the given PGP public key.
pub fn encrypt_share(share: &[u8], pubkey_path: &str) -> Result<Vec<u8>> {
    encrypt_share_named(share, pubkey_path, None)
}

/// `encrypt_share` with a name carried by the literal packet: metadata encrypted
/// and protected together with the share (same integrity check), which
/// `decrypt_share` ignores. Versions of the app that do not know it decrypt the
/// share exactly as before. Used for the kit mark (`api::generate_backup_kit`).
pub fn encrypt_share_named(share: &[u8], pubkey_path: &str, name: Option<&str>) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let cert = Cert::from_file(pubkey_path)
        .with_context(|| format!("lecture de la clé publique {pubkey_path}"))?;

    let recipients = cert
        .keys()
        .with_policy(&policy, Some(own_key_time(&cert)))
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .context("initialisation du chiffreur PGP")?;
        let mut literal = LiteralWriter::new(message);
        if let Some(name) = name {
            literal = literal.filename(name).context("nom de la part trop long")?;
        }
        let mut writer = literal.build().context("initialisation de l'écriture littérale")?;
        writer.write_all(share)?;
        writer.finalize()?;
    }
    Ok(sink)
}

/// Encrypts a share (bytes) for SEVERAL PGP recipients at once (a single session key,
/// an independent PKESK per certificate). Same principle as
/// `messaging::encrypt_message`, but on raw, unarmored bytes (the device vault stays
/// binary) and from certificates already in memory rather than a file path. Any of the
/// recipients can decrypt the result independently with their own private key, without
/// knowing the others. Fails closed if even ONE of the given certificates has no valid
/// encryption subkey, rather than silently encrypting for fewer recipients than
/// requested: the same guard, for the same reason, as `messaging::encrypt_message`
/// (see its regression test
/// `encrypt_message_fails_closed_when_one_recipient_has_no_usable_encryption_subkey`).
pub fn encrypt_share_multi(share: &[u8], pubkeys_armored: &[&[u8]]) -> Result<Vec<u8>> {
    if pubkeys_armored.is_empty() {
        return Err(anyhow!("au moins un destinataire est requis"));
    }

    let policy = StandardPolicy::new();
    let certs = pubkeys_armored
        .iter()
        .map(|k| Cert::from_bytes(k).context("clé publique PGP invalide"))
        .collect::<Result<Vec<_>>>()?;

    let mut recipients = Vec::new();
    for cert in &certs {
        let cert_recipients: Vec<_> = cert
            .keys()
            .with_policy(&policy, Some(own_key_time(cert)))
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();
        if cert_recipients.is_empty() {
            return Err(anyhow!(
                "un des certificats fournis n'a aucune sous-clé de chiffrement valide (expirée ou révoquée)"
            ));
        }
        recipients.extend(cert_recipients);
    }

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .context("initialisation du chiffreur PGP")?;
        let mut writer = LiteralWriter::new(message)
            .build()
            .context("initialisation de l'écriture littérale")?;
        writer.write_all(share)?;
        writer.finalize()?;
    }
    Ok(sink)
}

/// Decryption helper for Sequoia's streaming API: provides the private key, already
/// unlocked with its passphrase, to open the PGP session packet, and notes the
/// literal packet's name along the way.
struct DecryptionKeyHelper {
    keypair: KeyPair,
    literal_name: Option<Vec<u8>>,
}

impl VerificationHelper for DecryptionKeyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new()) // no signature to verify: shares are encrypted, not signed
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }

    fn inspect(&mut self, pp: &PacketParser) -> openpgp::Result<()> {
        if let Packet::Literal(literal) = &pp.packet {
            self.literal_name = literal.filename().filter(|name| !name.is_empty()).map(<[u8]>::to_vec);
        }
        Ok(())
    }
}

impl DecryptionHelper for DecryptionKeyHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            if pkesk
                .decrypt(&mut self.keypair, sym_algo)
                .map(|(algo, session_key)| decrypt(algo, &session_key))
                .unwrap_or(false)
            {
                return Ok(None);
            }
        }
        Err(anyhow!("aucune part PKESK n'a pu être déchiffrée avec cette clé"))
    }
}

/// Decrypts a share previously encrypted by `encrypt_share`, unlocking the matching
/// private key with a passphrase entered directly (no gpg-agent or hardware key
/// involved).
pub fn decrypt_share(encrypted: &[u8], privkey_path: &str, passphrase: &str) -> Result<Vec<u8>> {
    decrypt_share_named(encrypted, privkey_path, passphrase).map(|(share, _)| share)
}

/// `decrypt_share`, plus the name carried by the literal packet (`None`: an unnamed
/// share, see `encrypt_share_named`). Only returned once the whole message is
/// decrypted and its integrity verified: as trustworthy as the share.
pub fn decrypt_share_named(encrypted: &[u8], privkey_path: &str, passphrase: &str) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let cert = Cert::from_file(privkey_path)
        .with_context(|| format!("lecture de la clé privée {privkey_path}"))?;
    decrypt_with_cert_at(encrypted, &cert, privkey_path, passphrase, own_key_time(&cert))
}

/// `decrypt_share_named` with the key already read, evaluated (key and message) at
/// `time`. Kept separate so the tests can judge a share several decades ahead.
fn decrypt_with_cert_at(encrypted: &[u8], cert: &Cert, privkey_path: &str, passphrase: &str, time: SystemTime) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let policy = StandardPolicy::new();
    let password = Password::from(passphrase);

    // First usable encryption subkey.
    let key_amalgamation = cert
        .keys()
        .with_policy(&policy, Some(time))
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .secret()
        .next()
        .ok_or_else(|| anyhow!("aucune clé de déchiffrement trouvée dans {privkey_path}"))?;
    let key = key_amalgamation.key().clone();
    let key = if key.secret().is_encrypted() {
        key.decrypt_secret(&password)
            .context("passphrase incorrecte ou clé privée corrompue")?
    } else {
        key
    };
    let keypair = key.into_keypair().context("clé privée inutilisable pour le déchiffrement")?;

    let helper = DecryptionKeyHelper { keypair, literal_name: None };
    let mut decryptor = DecryptorBuilder::from_bytes(encrypted)
        .context("lecture du message PGP chiffré")?
        .with_policy(&policy, Some(time), helper)
        .context("échec du déchiffrement (mauvaise clé ou message corrompu)")?;

    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .context("lecture du contenu déchiffré")?;
    let name = decryptor.into_helper().literal_name;
    Ok((plaintext, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::armor;
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;

    /// End-to-end test of the PGP engine (key generation, encryption, decryption):
    /// exercises the real configured crypto backend (`crypto-cng` on Windows), not just
    /// the application logic around it. Also a safety net for a future backend change.
    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let dir = std::env::temp_dir().join(format!("pgp_engine_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pubkey_path = dir.join("test_pubkey.asc");
        let privkey_path = dir.join("test_privkey.asc");

        let passphrase = "correct horse battery staple test only";
        let (cert, _revocation) = CertBuilder::new()
            .add_userid("Test <test@example.invalid>")
            .add_transport_encryption_subkey()
            .set_password(Some(Password::from(passphrase)))
            .generate()
            .expect("génération de la clé de test");

        let mut pubkey_armored = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey).unwrap();
            cert.serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        std::fs::write(&pubkey_path, &pubkey_armored).unwrap();

        let mut privkey_armored = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut privkey_armored, armor::Kind::SecretKey).unwrap();
            cert.as_tsk().serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        std::fs::write(&privkey_path, &privkey_armored).unwrap();

        let plaintext = b"round-trip crypto backend test";
        let encrypted = encrypt_share(plaintext, &pubkey_path.to_string_lossy()).expect("chiffrement");
        let decrypted =
            decrypt_share(&encrypted, &privkey_path.to_string_lossy(), passphrase).expect("déchiffrement");
        assert_eq!(decrypted, plaintext);

        // A wrong password must fail cleanly, not return garbage.
        assert!(decrypt_share(&encrypted, &privkey_path.to_string_lossy(), "mauvais mot de passe").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn generate_test_identity(passphrase: &str) -> (Vec<u8>, Vec<u8>) {
        generate_test_identity_created(passphrase, std::time::SystemTime::now())
    }

    /// Identity generated as in the app (`api::generate_pgp_identity`:
    /// `CertBuilder::new`, no validity period), dated `creation`.
    fn generate_test_identity_created(passphrase: &str, creation: std::time::SystemTime) -> (Vec<u8>, Vec<u8>) {
        let (cert, _revocation) = CertBuilder::new()
            .set_creation_time(creation)
            .add_userid("Test <test@example.invalid>")
            .add_transport_encryption_subkey()
            .set_password(Some(Password::from(passphrase)))
            .generate()
            .expect("génération de la clé de test");

        let mut pubkey_armored = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey).unwrap();
            cert.serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        let mut privkey_armored = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut privkey_armored, armor::Kind::SecretKey).unwrap();
            cert.as_tsk().serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        (pubkey_armored, privkey_armored)
    }

    /// Core guarantee of biometric unlock: a vault encrypted for two recipients must be
    /// decryptable independently by either one, each with its own passphrase, without
    /// one needing to know or use the other's key.
    #[test]
    fn encrypt_share_multi_lets_either_recipient_decrypt_independently() {
        let dir = std::env::temp_dir().join(format!("pgp_engine_multi_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (pub_a, priv_a) = generate_test_identity("passphrase du destinataire A");
        let (pub_b, priv_b) = generate_test_identity("passphrase du destinataire B, bien différente");

        let priv_a_path = dir.join("a_privkey.asc");
        let priv_b_path = dir.join("b_privkey.asc");
        std::fs::write(&priv_a_path, &priv_a).unwrap();
        std::fs::write(&priv_b_path, &priv_b).unwrap();

        let plaintext = b"secret partage entre deux identites independantes";
        let encrypted = encrypt_share_multi(plaintext, &[&pub_a, &pub_b]).expect("chiffrement multi-destinataires");

        let decrypted_by_a = decrypt_share(&encrypted, &priv_a_path.to_string_lossy(), "passphrase du destinataire A")
            .expect("déchiffrement par A");
        assert_eq!(decrypted_by_a, plaintext);

        let decrypted_by_b = decrypt_share(
            &encrypted,
            &priv_b_path.to_string_lossy(),
            "passphrase du destinataire B, bien différente",
        )
        .expect("déchiffrement par B");
        assert_eq!(decrypted_by_b, plaintext);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: without this check, a certificate without a usable encryption subkey
    /// would silently contribute 0 recipients instead of failing the whole operation
    /// (see the same flaw fixed in `messaging::encrypt_message`).
    #[test]
    fn encrypt_share_multi_fails_closed_when_one_recipient_has_no_usable_encryption_subkey() {
        let (pub_a, _priv_a) = generate_test_identity("passphrase du destinataire A");
        // A certificate with no encryption subkey at all (only a signing key): no
        // `for_transport_encryption()` available.
        let (cert_no_enc, _) = CertBuilder::new()
            .add_userid("Sans chiffrement <no-enc@example.invalid>")
            .generate()
            .expect("génération de la clé sans sous-clé de chiffrement");
        let mut pub_no_enc = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut pub_no_enc, armor::Kind::PublicKey).unwrap();
            cert_no_enc.serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }

        let result = encrypt_share_multi(b"peu importe", &[&pub_a, &pub_no_enc]);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_share_multi_requires_at_least_one_recipient() {
        assert!(encrypt_share_multi(b"peu importe", &[]).is_err());
    }

    /// Our keys do not depend on the computer's clock: a clock one minute, one hour or
    /// two years behind the key's creation (a restore on a PC set wrong), or a key 26
    /// years old, and encryption and decryption still work (before: "no decryption key
    /// found" as soon as the clock was one minute behind).
    #[test]
    fn own_keys_work_whatever_the_computer_clock_says() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let dir = std::env::temp_dir().join(format!("pgp_engine_clock_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let year = Duration::from_secs(31_557_600);
        let now = SystemTime::now();
        let cases = [("1 minute", now + Duration::from_secs(60)), ("1 heure", now + Duration::from_secs(3600)), ("2 ans", now + year * 2), ("an 2000", UNIX_EPOCH + year * 30)];
        for (name, creation) in cases {
            let passphrase = "passphrase de test, horloge décalée";
            let (public, private) = generate_test_identity_created(passphrase, creation);
            let (pub_path, priv_path) = (dir.join("clock_pub.asc"), dir.join("clock_priv.asc"));
            std::fs::write(&pub_path, &public).unwrap();
            std::fs::write(&priv_path, &private).unwrap();
            let encrypted = encrypt_share(b"part de test", &pub_path.to_string_lossy()).unwrap_or_else(|e| panic!("{name} : chiffrement {e:#}"));
            let decrypted = decrypt_share(&encrypted, &priv_path.to_string_lossy(), passphrase).unwrap_or_else(|e| panic!("{name} : déchiffrement {e:#}"));
            assert_eq!(decrypted, b"part de test", "{name}");
            let multi = encrypt_share_multi(b"coffre de test", &[&public]).unwrap_or_else(|e| panic!("{name} : chiffrement multiple {e:#}"));
            assert_eq!(decrypt_share(&multi, &priv_path.to_string_lossy(), passphrase).unwrap(), b"coffre de test", "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Name of the share (kit mark): returned by `decrypt_share_named` together with
    /// the share, ignored by `decrypt_share` (which is what older versions of the app
    /// do: the decrypted share is exactly the same); an unnamed share gives `None`. A
    /// share with a single changed byte returns neither share nor name.
    #[test]
    fn share_name_is_carried_encrypted_and_ignored_by_plain_decryption() {
        let dir = std::env::temp_dir().join(format!("pgp_engine_named_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let passphrase = "passphrase de test, part nommée";
        let (public, private) = generate_test_identity(passphrase);
        let (pub_path, priv_path) = (dir.join("named_pub.asc"), dir.join("named_priv.asc"));
        std::fs::write(&pub_path, &public).unwrap();
        std::fs::write(&priv_path, &private).unwrap();
        let (pub_path, priv_path) = (pub_path.to_string_lossy().into_owned(), priv_path.to_string_lossy().into_owned());
        let named = encrypt_share_named(b"part de test", &pub_path, Some("pgpwallet-kit-v1:0011223344556677:8899aabbccddeeff")).unwrap();
        let (share, name) = decrypt_share_named(&named, &priv_path, passphrase).unwrap();
        assert_eq!(share, b"part de test");
        assert_eq!(name.as_deref(), Some(b"pgpwallet-kit-v1:0011223344556677:8899aabbccddeeff".as_slice()));
        assert_eq!(decrypt_share(&named, &priv_path, passphrase).unwrap(), b"part de test", "lecture comme avant");
        let plain = encrypt_share(b"part de test", &pub_path).unwrap();
        assert_eq!(decrypt_share_named(&plain, &priv_path, passphrase).unwrap(), (b"part de test".to_vec(), None));
        for i in (0..named.len()).step_by(7) {
            let mut bad = named.clone();
            bad[i] ^= 0x10;
            if let Ok((share, name)) = decrypt_share_named(&bad, &priv_path, passphrase) {
                assert_eq!(share, b"part de test", "octet {i} : part altérée rendue");
                assert_eq!(name.as_deref(), Some(b"pgpwallet-kit-v1:0011223344556677:8899aabbccddeeff".as_slice()), "octet {i} : nom altéré rendu");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A share encrypted today still decrypts in 2040, 2070 and 2100 with this version
    /// of the library: no dated rule in Sequoia's policy (algorithms refused after a
    /// given date) will make it unusable over time.
    #[test]
    fn todays_shares_still_decrypt_decades_later() {
        use std::time::{Duration, UNIX_EPOCH};
        let dir = std::env::temp_dir().join(format!("pgp_engine_decades_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let passphrase = "passphrase de test, dans plusieurs décennies";
        let (public, private) = generate_test_identity(passphrase);
        let (pub_path, priv_path) = (dir.join("decades_pub.asc"), dir.join("decades_priv.asc"));
        std::fs::write(&pub_path, &public).unwrap();
        std::fs::write(&priv_path, &private).unwrap();
        let encrypted = encrypt_share(b"part de test", &pub_path.to_string_lossy()).unwrap();
        let cert = Cert::from_bytes(&private).unwrap();
        for year in [2040u64, 2070, 2100] {
            let time = UNIX_EPOCH + Duration::from_secs((year - 1970) * 31_557_600);
            let (decrypted, _) = decrypt_with_cert_at(&encrypted, &cert, "clé de test", passphrase, time).unwrap_or_else(|e| panic!("{year} : {e:#}"));
            assert_eq!(decrypted, b"part de test", "{year}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
