use anyhow::{anyhow, Context, Result};
use openpgp::cert::Cert;
use openpgp::crypto::{KeyPair, Password, SessionKey};
use openpgp::parse::stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;
use openpgp::KeyHandle;
use sequoia_openpgp as openpgp;
use std::io::{Read, Write};

/// Chiffre une part (bytes) pour le détenteur de la clé publique PGP donnée.
pub fn encrypt_share(share: &[u8], pubkey_path: &str) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let cert = Cert::from_file(pubkey_path)
        .with_context(|| format!("lecture de la clé publique {pubkey_path}"))?;

    let recipients = cert
        .keys()
        .with_policy(&policy, None)
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
        Err(anyhow!("aucune part PKESK n'a pu être déchiffrée avec cette clé").into())
    }
}

/// Déchiffre une part précédemment chiffrée par `encrypt_share`, en déverrouillant
/// la clé privée correspondante avec une passphrase saisie directement (pas de
/// gpg-agent ni de YubiKey dans ce PoC).
pub fn decrypt_share(encrypted: &[u8], privkey_path: &str, passphrase: &str) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let cert = Cert::from_file(privkey_path)
        .with_context(|| format!("lecture de la clé privée {privkey_path}"))?;

    let password = Password::from(passphrase);

    let mut keypair = None;
    for key_amalgamation in cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .secret()
    {
        let key = key_amalgamation.key().clone();
        let key = if key.secret().is_encrypted() {
            key.decrypt_secret(&password)
                .context("passphrase incorrecte ou clé privée corrompue")?
        } else {
            key
        };
        keypair = Some(key.into_keypair().context("clé privée inutilisable pour le déchiffrement")?);
        break;
    }

    let keypair = keypair.ok_or_else(|| anyhow!("aucune clé de déchiffrement trouvée dans {privkey_path}"))?;

    let helper = DecryptionKeyHelper { keypair };
    let mut decryptor = DecryptorBuilder::from_bytes(encrypted)
        .context("lecture du message PGP chiffré")?
        .with_policy(&policy, None, helper)
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
}
