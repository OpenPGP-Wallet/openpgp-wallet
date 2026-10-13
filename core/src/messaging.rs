//! Classic OpenPGP text message encryption, a nod to the project's origins: PGP was
//! first designed to encrypt messages between people, before being put to work here
//! protecting a seed. No wallet secret is involved: messages are encrypted to any
//! public key (not necessarily an identity tied to the wallet), one way, without
//! ever touching the master entropy or the derivation private keys.

use anyhow::{Context, Result};
use openpgp::armor;
use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message as PgpMessage};
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

const RECIPIENTS_FILE: &str = "recipients.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct Recipient {
    pub label: String,
    pub pubkey_armored: String,
}

fn load_recipients(data_dir: &Path) -> Result<Vec<Recipient>> {
    let path = data_dir.join(RECIPIENTS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path).context("lecture du carnet de destinataires")?;
    serde_json::from_str(&content).context("carnet de destinataires corrompu")
}

fn save_recipients(data_dir: &Path, recipients: &[Recipient]) -> Result<()> {
    let path = data_dir.join(RECIPIENTS_FILE);
    let content = serde_json::to_string_pretty(recipients)
        .context("sérialisation du carnet de destinataires")?;
    std::fs::write(path, content).context("écriture du carnet de destinataires")
}

/// Checks that the given text really is a usable PGP public key before adding it to
/// the book (replaces the existing entry if the label is already taken).
pub fn add_recipient(data_dir: &Path, label: &str, pubkey_armored: &str) -> Result<()> {
    Cert::from_bytes(pubkey_armored.as_bytes()).context("clé publique PGP invalide")?;

    let mut recipients = load_recipients(data_dir)?;
    recipients.retain(|r| r.label != label);
    recipients.push(Recipient {
        label: label.to_string(),
        pubkey_armored: pubkey_armored.to_string(),
    });
    save_recipients(data_dir, &recipients)
}

pub fn list_recipients(data_dir: &Path) -> Result<Vec<Recipient>> {
    load_recipients(data_dir)
}

/// `Some((old_fingerprint, new_fingerprint))` if `label` already matches a saved
/// recipient whose public key differs from `new_pubkey_armored`. Used to warn the
/// user before `add_recipient` silently replaces a key already in the book (see its
/// doc: "replaces the existing entry if the label is already taken"). Without this
/// warning, someone able to convince the user to "re-add" a contact with a different
/// key (social engineering, or a book tampered with locally and then "repaired"
/// through the UI) would swap the trusted key with no sign of it, which is exactly
/// what the fingerprint shown in the book is meant to catch. `None` for a new
/// contact, or when the key is strictly identical.
pub fn recipient_key_change(
    data_dir: &Path,
    label: &str,
    new_pubkey_armored: &str,
) -> Result<Option<(String, String)>> {
    let recipients = load_recipients(data_dir)?;
    let Some(existing) = recipients.iter().find(|r| r.label == label) else {
        return Ok(None);
    };
    if existing.pubkey_armored == new_pubkey_armored {
        return Ok(None);
    }
    let old_fingerprint = cert_info(&existing.pubkey_armored)
        .map(|c| c.fingerprint)
        .unwrap_or_else(|_| "invalide".to_string());
    let new_fingerprint = cert_info(new_pubkey_armored)
        .map(|c| c.fingerprint)
        .unwrap_or_else(|_| "invalide".to_string());
    Ok(Some((old_fingerprint, new_fingerprint)))
}

pub fn remove_recipient(data_dir: &Path, label: &str) -> Result<()> {
    let mut recipients = load_recipients(data_dir)?;
    recipients.retain(|r| r.label != label);
    save_recipients(data_dir, &recipients)
}

/// Encrypts a text message to one or more PGP public keys; the result is
/// ASCII-armored, ready to copy, paste or send over any channel. Each listed
/// recipient can decrypt the same message independently (PGP encrypts the session
/// key once per recipient), without any of them seeing the others' private keys or
/// being able to decrypt on someone else's behalf.
pub fn encrypt_message(pubkeys_armored: &[String], message: &str) -> Result<String> {
    if pubkeys_armored.is_empty() {
        return Err(anyhow::anyhow!("au moins un destinataire est requis"));
    }

    let policy = StandardPolicy::new();
    let certs = pubkeys_armored
        .iter()
        .map(|k| Cert::from_bytes(k.as_bytes()).context("clé publique PGP invalide"))
        .collect::<Result<Vec<_>>>()?;

    // A naive `flat_map` here would silently contribute 0 recipients for a certificate
    // without a valid encryption subkey (expired, revoked): the message would still go
    // out, encrypted for the others, with no sign that an intended recipient was left
    // out. So each certificate is checked individually, and the whole operation fails
    // rather than silently sending to fewer recipients than requested.
    let mut recipients = Vec::new();
    for (cert, pubkey_armored) in certs.iter().zip(pubkeys_armored) {
        let cert_recipients: Vec<_> = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();
        if cert_recipients.is_empty() {
            let name = cert_info(pubkey_armored)
                .map(|info| info.user_id)
                .unwrap_or_else(|_| "destinataire inconnu".to_string());
            return Err(anyhow::anyhow!(
                "\"{name}\" n'a aucune sous-clé de chiffrement valide (expirée ou révoquée) — message non envoyé"
            ));
        }
        recipients.extend(cert_recipients);
    }

    let mut sink = Vec::new();
    {
        let mut armor_writer = armor::Writer::new(&mut sink, armor::Kind::Message)
            .context("initialisation de l'armure PGP")?;
        {
            let pgp_message = PgpMessage::new(&mut armor_writer);
            let pgp_message = Encryptor::for_recipients(pgp_message, recipients)
                .build()
                .context("initialisation du chiffreur PGP")?;
            let mut lw = LiteralWriter::new(pgp_message)
                .build()
                .context("initialisation de l'écriture littérale")?;
            lw.write_all(message.as_bytes())?;
            lw.finalize()?;
        }
        armor_writer
            .finalize()
            .context("finalisation de l'armure PGP")?;
    }
    String::from_utf8(sink).context("résultat PGP non-UTF8 (inattendu)")
}

pub struct CertInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub user_id: String,
    pub pubkey_armored: String,
}

/// Readable information about an OpenPGP certificate (the official term for "public
/// key + identities + signatures"): no private data, fit for display.
pub fn cert_info(pubkey_armored: &str) -> Result<CertInfo> {
    let cert = Cert::from_bytes(pubkey_armored.as_bytes()).context("certificat invalide")?;

    let user_id = cert
        .userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).to_string())
        .unwrap_or_else(|| "(sans identité)".to_string());

    Ok(CertInfo {
        fingerprint: cert.fingerprint().to_string(),
        key_id: cert.keyid().to_string(),
        user_id,
        pubkey_armored: pubkey_armored.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::prelude::*;

    fn test_pubkey_armored(userid: &str) -> String {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid(userid)
            .add_transport_encryption_subkey()
            .generate()
            .expect("génération de la clé de test");
        let mut pubkey_armored = Vec::new();
        {
            use openpgp::serialize::Serialize;
            let mut writer =
                armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey).unwrap();
            cert.serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        String::from_utf8(pubkey_armored).unwrap()
    }

    #[test]
    fn recipient_key_change_returns_none_for_a_new_label() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_recipient_change_new_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = test_pubkey_armored("Alice <alice@example.invalid>");
        assert!(recipient_key_change(&dir, "Alice", &key).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recipient_key_change_returns_none_when_the_key_is_unchanged() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_recipient_change_same_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = test_pubkey_armored("Alice <alice@example.invalid>");
        add_recipient(&dir, "Alice", &key).expect("ajout initial");
        assert!(recipient_key_change(&dir, "Alice", &key).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Guard against the regression found during an audit: `add_recipient` silently
    /// replaces the key of an already saved contact when given an identical label,
    /// which is exactly the kind of swap the fingerprint shown in the book is meant to
    /// catch.
    #[test]
    fn recipient_key_change_detects_a_different_key_for_the_same_label() {
        let dir = std::env::temp_dir().join(format!(
            "pgp_wallet_recipient_change_diff_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_key = test_pubkey_armored("Alice <alice@example.invalid>");
        add_recipient(&dir, "Alice", &original_key).expect("ajout initial");

        let attacker_key = test_pubkey_armored("Alice <alice@example.invalid>");
        let change = recipient_key_change(&dir, "Alice", &attacker_key).unwrap();
        assert!(
            change.is_some(),
            "un changement de clé pour le même label doit être détecté"
        );
        let (old_fp, new_fp) = change.unwrap();
        assert_ne!(old_fp, new_fp);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Certificate without an encryption subkey (only a signing key): simulates a
    /// contact whose key never had, or no longer has, a subkey usable for encryption
    /// (expired or revoked, in practice).
    fn test_pubkey_armored_without_encryption_subkey(userid: &str) -> String {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid(userid)
            .generate()
            .expect("génération de la clé de test");
        let mut pubkey_armored = Vec::new();
        {
            use openpgp::serialize::Serialize;
            let mut writer =
                armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey).unwrap();
            cert.serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        String::from_utf8(pubkey_armored).unwrap()
    }

    #[test]
    fn encrypt_message_requires_at_least_one_recipient() {
        assert!(encrypt_message(&[], "salut").is_err());
    }

    #[test]
    fn encrypt_message_succeeds_for_several_valid_recipients() {
        let alice = test_pubkey_armored("Alice <alice@example.invalid>");
        let bob = test_pubkey_armored("Bob <bob@example.invalid>");
        let armored = encrypt_message(&[alice, bob], "salut à vous deux")
            .expect("chiffrement multi-destinataires");
        assert!(armored.contains("BEGIN PGP MESSAGE"));
    }

    /// Guard against a regression found during an audit: before this fix, a recipient
    /// without a valid encryption subkey was silently excluded (0 recipients added for
    /// their certificate), and the message still went out to the others without any
    /// error. The user believed they had encrypted for everyone, while one of the
    /// intended recipients could never actually decrypt the message.
    #[test]
    fn encrypt_message_fails_closed_when_one_recipient_has_no_usable_encryption_subkey() {
        let alice = test_pubkey_armored("Alice <alice@example.invalid>");
        let bob_broken = test_pubkey_armored_without_encryption_subkey("Bob <bob@example.invalid>");
        let result = encrypt_message(&[alice, bob_broken], "salut à vous deux");
        assert!(
            result.is_err(),
            "un destinataire sans sous-clé de chiffrement valide doit faire échouer tout l'envoi, pas seulement l'exclure silencieusement"
        );
    }
}
