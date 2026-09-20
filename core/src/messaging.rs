//! Chiffrement de messages texte OpenPGP classique — un clin d'œil à l'origine
//! du projet : PGP a d'abord été conçu pour chiffrer des messages entre personnes,
//! avant d'être détourné ici pour protéger une seed. Aucun secret du wallet n'est
//! impliqué : on chiffre pour une clé publique quelconque (pas forcément une
//! identité liée au wallet), à sens unique, sans jamais toucher à l'entropie
//! maître ni aux clés privées de dérivation.

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
    let content = serde_json::to_string_pretty(recipients).context("sérialisation du carnet de destinataires")?;
    std::fs::write(path, content).context("écriture du carnet de destinataires")
}

/// Valide que le texte fourni est bien une clé publique PGP exploitable avant de
/// l'ajouter au carnet (remplace l'entrée existante si le label est déjà pris).
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

/// `Some((ancienne_empreinte, nouvelle_empreinte))` si `label` correspond déjà à un
/// destinataire enregistré dont la clé publique diffère de `new_pubkey_armored` —
/// sert à avertir l'utilisateur avant qu'`add_recipient` ne remplace silencieusement
/// une clé déjà en carnet (voir sa doc : "remplace l'entrée existante si le label
/// est déjà pris"). Sans cet avertissement, quelqu'un capable de convaincre
/// l'utilisateur de "réajouter" un contact avec une clé différente (ingénierie
/// sociale, ou un carnet localement altéré puis "réparé" via l'UI) substituerait la
/// clé de confiance sans qu'aucun signe ne l'indique — exactement ce que
/// l'empreinte affichée dans le carnet est censée permettre de détecter.
/// `None` si c'est un nouveau contact, ou si la clé est strictement identique.
pub fn recipient_key_change(data_dir: &Path, label: &str, new_pubkey_armored: &str) -> Result<Option<(String, String)>> {
    let recipients = load_recipients(data_dir)?;
    let Some(existing) = recipients.iter().find(|r| r.label == label) else {
        return Ok(None);
    };
    if existing.pubkey_armored == new_pubkey_armored {
        return Ok(None);
    }
    let old_fingerprint = cert_info(&existing.pubkey_armored).map(|c| c.fingerprint).unwrap_or_else(|_| "invalide".to_string());
    let new_fingerprint = cert_info(new_pubkey_armored).map(|c| c.fingerprint).unwrap_or_else(|_| "invalide".to_string());
    Ok(Some((old_fingerprint, new_fingerprint)))
}

pub fn remove_recipient(data_dir: &Path, label: &str) -> Result<()> {
    let mut recipients = load_recipients(data_dir)?;
    recipients.retain(|r| r.label != label);
    save_recipients(data_dir, &recipients)
}

/// Chiffre un message texte pour une ou plusieurs clés publiques PGP ; résultat en
/// ASCII-armor, prêt à copier/coller ou envoyer par n'importe quel canal. Chaque
/// destinataire listé peut déchiffrer indépendamment le même message (PGP chiffre
/// la clé de session une fois par destinataire), sans qu'aucun ne voie les autres
/// clés privées ni ne puisse déchiffrer pour le compte d'un autre.
pub fn encrypt_message(pubkeys_armored: &[String], message: &str) -> Result<String> {
    if pubkeys_armored.is_empty() {
        return Err(anyhow::anyhow!("au moins un destinataire est requis"));
    }

    let policy = StandardPolicy::new();
    let certs = pubkeys_armored
        .iter()
        .map(|k| Cert::from_bytes(k.as_bytes()).context("clé publique PGP invalide"))
        .collect::<Result<Vec<_>>>()?;

    // Un `flat_map` naïf ici contribuerait silencieusement 0 destinataire pour un
    // certificat sans sous-clé de chiffrement valide (expirée, révoquée) : le
    // message partirait quand même, chiffré pour les autres, sans qu'aucun signe
    // n'indique qu'un destinataire prévu a été exclu. On vérifie donc chaque
    // certificat individuellement et on échoue pour tout le monde plutôt que
    // d'envoyer silencieusement à moins de destinataires que demandé.
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
        let mut armor_writer =
            armor::Writer::new(&mut sink, armor::Kind::Message).context("initialisation de l'armure PGP")?;
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
        armor_writer.finalize().context("finalisation de l'armure PGP")?;
    }
    String::from_utf8(sink).context("résultat PGP non-UTF8 (inattendu)")
}

pub struct CertInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub user_id: String,
    pub pubkey_armored: String,
}

/// Infos lisibles sur un certificat OpenPGP (terme officiel pour "clé publique
/// + identités + signatures") — aucune donnée privée, adapté à l'affichage.
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
            let mut writer = armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey).unwrap();
            cert.serialize(&mut writer).unwrap();
            writer.finalize().unwrap();
        }
        String::from_utf8(pubkey_armored).unwrap()
    }

    #[test]
    fn recipient_key_change_returns_none_for_a_new_label() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_recipient_change_new_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = test_pubkey_armored("Alice <alice@example.invalid>");
        assert!(recipient_key_change(&dir, "Alice", &key).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recipient_key_change_returns_none_when_the_key_is_unchanged() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_recipient_change_same_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = test_pubkey_armored("Alice <alice@example.invalid>");
        add_recipient(&dir, "Alice", &key).expect("ajout initial");
        assert!(recipient_key_change(&dir, "Alice", &key).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou contre la régression trouvée lors d'un audit : `add_recipient`
    /// remplace silencieusement la clé d'un contact déjà enregistré si on lui
    /// soumet un nouveau label identique — exactement le genre de substitution que
    /// l'empreinte affichée dans le carnet est censée permettre de détecter.
    #[test]
    fn recipient_key_change_detects_a_different_key_for_the_same_label() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_recipient_change_diff_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_key = test_pubkey_armored("Alice <alice@example.invalid>");
        add_recipient(&dir, "Alice", &original_key).expect("ajout initial");

        let attacker_key = test_pubkey_armored("Alice <alice@example.invalid>");
        let change = recipient_key_change(&dir, "Alice", &attacker_key).unwrap();
        assert!(change.is_some(), "un changement de clé pour le même label doit être détecté");
        let (old_fp, new_fp) = change.unwrap();
        assert_ne!(old_fp, new_fp);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Certificat sans sous-clé de chiffrement (seulement une clé de signature) —
    /// simule un contact dont la clé n'a jamais eu, ou n'a plus, de sous-clé
    /// utilisable pour du chiffrement (expirée/révoquée en pratique).
    fn test_pubkey_armored_without_encryption_subkey(userid: &str) -> String {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid(userid)
            .generate()
            .expect("génération de la clé de test");
        let mut pubkey_armored = Vec::new();
        {
            use openpgp::serialize::Serialize;
            let mut writer = armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey).unwrap();
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
        let armored = encrypt_message(&[alice, bob], "salut à vous deux").expect("chiffrement multi-destinataires");
        assert!(armored.contains("BEGIN PGP MESSAGE"));
    }

    /// Garde-fou contre une régression trouvée lors d'un audit : avant ce correctif,
    /// un destinataire sans sous-clé de chiffrement valide était silencieusement
    /// exclu (0 destinataire ajouté pour son certificat), le message partait quand
    /// même pour les autres sans aucune erreur — l'utilisateur croyait avoir chiffré
    /// pour tout le monde alors qu'un des destinataires prévus n'avait en réalité
    /// jamais pu déchiffrer le message.
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
