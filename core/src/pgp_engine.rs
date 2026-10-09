use anyhow::{anyhow, Context, Result};
use openpgp::cert::Cert;
use openpgp::crypto::{KeyPair, Password, SessionKey};
use openpgp::parse::stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{KeyHandle, Packet};
use sequoia_openpgp as openpgp;
use std::io::{Read, Write};
use std::time::SystemTime;

/// Instant auquel évaluer NOS propres clés (parts de sauvegarde, coffre de
/// l'appareil, Windows Hello) : l'heure de l'ordinateur, mais jamais avant la
/// création de la clé. Évaluée à l'heure seule, une clé « pas encore créée »
/// pour une horloge en retard (pile de la carte mère, PC hors ligne mal
/// réglé) n'était plus utilisable : ni restauration, ni déverrouillage, tant
/// que l'horloge n'était pas corrigée — même d'une minute (mesuré). Ces clés
/// sont créées sans expiration et ne sont jamais révoquées : rien de ce que la
/// date protège n'est perdu. Les clés d'autres personnes (`messaging.rs`)
/// restent évaluées à l'heure de l'ordinateur (leur expiration compte).
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

/// Chiffre une part (bytes) pour le détenteur de la clé publique PGP donnée.
pub fn encrypt_share(share: &[u8], pubkey_path: &str) -> Result<Vec<u8>> {
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
        let mut writer = LiteralWriter::new(message)
            .build()
            .context("initialisation de l'écriture littérale")?;
        writer.write_all(share)?;
        writer.finalize()?;
    }
    Ok(sink)
}

/// Chiffre une part (bytes) pour PLUSIEURS destinataires PGP à la fois (une seule
/// clé de session, un PKESK indépendant par certificat) — même principe que
/// `messaging::encrypt_message`, mais sur des octets bruts non armurés (le coffre
/// de l'appareil reste binaire) et à partir de certificats déjà en mémoire plutôt
/// que d'un chemin de fichier. N'importe lequel des destinataires peut déchiffrer
/// indépendamment le résultat avec sa propre clé privée, sans connaître les
/// autres. Échoue (fail-closed) si UN SEUL des certificats fournis n'a aucune
/// sous-clé de chiffrement valide, plutôt que de chiffrer silencieusement pour
/// moins de destinataires que demandé — même garde-fou, pour la même raison, que
/// `messaging::encrypt_message` (voir son test de régression
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

/// Aide de déchiffrement pour l'API stream de sequoia : fournit la clé privée
/// déjà déverrouillée (par passphrase) pour ouvrir le paquet de session PGP.
struct DecryptionKeyHelper {
    keypair: KeyPair,
}

impl VerificationHelper for DecryptionKeyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new()) // pas de vérification de signature pour ce PoC
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
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

/// Déchiffre une part précédemment chiffrée par `encrypt_share`, en déverrouillant
/// la clé privée correspondante avec une passphrase saisie directement (pas de
/// gpg-agent ni de YubiKey dans ce PoC).
pub fn decrypt_share(encrypted: &[u8], privkey_path: &str, passphrase: &str) -> Result<Vec<u8>> {
    let cert = Cert::from_file(privkey_path)
        .with_context(|| format!("lecture de la clé privée {privkey_path}"))?;
    decrypt_with_cert_at(encrypted, &cert, privkey_path, passphrase, own_key_time(&cert))
}

/// `decrypt_share` avec la clé déjà lue, évaluée (clé et message) à `time` —
/// séparé pour que les tests puissent juger une part dans plusieurs décennies.
fn decrypt_with_cert_at(encrypted: &[u8], cert: &Cert, privkey_path: &str, passphrase: &str, time: SystemTime) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let password = Password::from(passphrase);

    // Première sous-clé de chiffrement utilisable.
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

    let helper = DecryptionKeyHelper { keypair };
    let mut decryptor = DecryptorBuilder::from_bytes(encrypted)
        .context("lecture du message PGP chiffré")?
        .with_policy(&policy, Some(time), helper)
        .context("échec du déchiffrement (mauvaise clé ou message corrompu)")?;

    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .context("lecture du contenu déchiffré")?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::armor;
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;

    /// Test de bout en bout du moteur PGP (génération de clé, chiffrement,
    /// déchiffrement) — exerce le vrai backend crypto configuré (`crypto-cng` sur
    /// Windows), pas seulement la logique applicative autour. Sert aussi de
    /// garde-fou lors d'un futur changement de backend.
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

        // Un mauvais mot de passe doit échouer proprement, pas renvoyer n'importe quoi.
        assert!(decrypt_share(&encrypted, &privkey_path.to_string_lossy(), "mauvais mot de passe").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn generate_test_identity(passphrase: &str) -> (Vec<u8>, Vec<u8>) {
        generate_test_identity_created(passphrase, std::time::SystemTime::now())
    }

    /// Identité générée comme dans l'app (`api::generate_pgp_identity` :
    /// `CertBuilder::new`, sans durée de validité), datée de `creation`.
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

    /// Garantie centrale du déverrouillage biométrique : un coffre chiffré pour
    /// deux destinataires doit être déchiffrable indépendamment par l'un OU
    /// l'autre, chacun avec sa propre passphrase, sans que l'un ait besoin de
    /// connaître ou d'utiliser la clé de l'autre.
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

    /// Régression : sans cette vérification, un certificat sans sous-clé de
    /// chiffrement utilisable contribuerait silencieusement 0 destinataire au
    /// lieu de faire échouer l'opération entière (voir la même faille corrigée
    /// dans `messaging::encrypt_message`).
    #[test]
    fn encrypt_share_multi_fails_closed_when_one_recipient_has_no_usable_encryption_subkey() {
        let (pub_a, _priv_a) = generate_test_identity("passphrase du destinataire A");
        // Un certificat sans sous-clé de chiffrement du tout (seulement une clé de
        // signature) : aucun `for_transport_encryption()` disponible.
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

    /// Nos clés ne dépendent pas de l'horloge de l'ordinateur : horloge en
    /// retard d'une minute, d'une heure ou de deux ans sur la création de la
    /// clé (restauration sur un PC mal réglé), ou clé vieille de 26 ans →
    /// chiffrement et déchiffrement fonctionnent (avant : « aucune clé de
    /// déchiffrement trouvée » dès une minute de retard).
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

    /// Une part chiffrée aujourd'hui se déchiffre encore en 2040, 2070 et
    /// 2100 avec cette version de la bibliothèque : aucune règle datée de la
    /// politique de sequoia (algorithmes refusés après une date) ne la rendra
    /// inutilisable avec le temps.
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
            let decrypted = decrypt_with_cert_at(&encrypted, &cert, "clé de test", passphrase, time).unwrap_or_else(|e| panic!("{year} : {e:#}"));
            assert_eq!(decrypted, b"part de test", "{year}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
