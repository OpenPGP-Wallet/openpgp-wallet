//! Sauvegarde du kit de récupération sur clé USB (ETAPES.md, « Phase 3 :
//! appareil de backup ») : brancher une clé suffit, l'app la détecte et y écrit
//! des parts COMPLÈTES (fichier de part, clé privée, mot de passe) — rien à
//! noter. Deux usages, choisis par l'utilisateur :
//! - une part par clé (`write_share`) : une clé seule ne sert à rien (2 parts
//!   sur 3 sont nécessaires) ; d'où le refus d'y écrire une deuxième part du
//!   même kit ;
//! - tout le kit sur une clé (`write_kit`) : cette clé suffit alors À ELLE
//!   SEULE à tout récupérer, sans mot de passe — l'app le fait confirmer, et le
//!   fichier LISEZ-MOI le rappelle à qui trouve la clé.
//!
//! Disposition : `PGP-Wallet-Sauvegarde/part-N/` (part.asc, cle-privee.asc,
//! mot-de-passe.txt, sauvegarde.json) et un LISEZ-MOI à la racine du dossier.
//! Écriture vérifiée : relue et comparée, puis chaque part est réellement
//! déchiffrée avec la clé et le mot de passe écrits (voir
//! `api::verify_backup_share`), avant de dire à l'utilisateur que c'est fait.
//! Seules les clés USB détectées par le système sont acceptées comme
//! destination ou source (jamais un chemin choisi par l'interface).

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Dossier créé à la racine de la clé.
pub const BACKUP_DIR: &str = "PGP-Wallet-Sauvegarde";
const SHARE_FILE: &str = "part.asc";
const KEY_FILE: &str = "cle-privee.asc";
const PASSWORD_FILE: &str = "mot-de-passe.txt";
const INFO_FILE: &str = "sauvegarde.json";
const README_FILE: &str = "LISEZ-MOI.txt";
/// Fichiers d'une part : quelques Ko ; au-delà, ce n'est pas une sauvegarde.
const MAX_FILE_BYTES: u64 = 1 << 20;
const MIN_FREE_BYTES: u64 = 256 * 1024;
const FORMAT_VERSION: u32 = 1;

/// Part présente sur une clé : kit (identifiant aléatoire, ne révèle rien du
/// portefeuille) et numéro de part.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ShareInfo {
    pub kit: String,
    pub part: u8,
}

#[derive(Serialize, Deserialize)]
struct InfoFile {
    format: u32,
    kit: String,
    part: u8,
}

/// Clé USB détectée.
#[derive(Debug)]
pub struct RemovableDrive {
    /// Racine, `E:\`.
    pub root: PathBuf,
    pub label: String,
    pub free_bytes: u64,
    /// Parts de sauvegarde déjà présentes.
    pub shares: Vec<ShareInfo>,
}

/// Contenu d'une part de sauvegarde.
pub struct ShareFiles {
    pub encrypted_share: Vec<u8>,
    pub privkey_armored: Vec<u8>,
    pub passphrase: Zeroizing<String>,
}

/// Clés USB branchées (lecteurs amovibles avec un support inséré).
#[cfg(windows)]
pub fn removable_drives() -> Vec<RemovableDrive> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW};
    /// `DRIVE_REMOVABLE` : clé USB, carte mémoire (un disque dur externe USB
    /// se déclare « fixe » et n'est pas proposé).
    const DRIVE_REMOVABLE: u32 = 2;
    let mask = unsafe { GetLogicalDrives() };
    let mut drives = Vec::new();
    for index in 0..26u8 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let root = format!("{}:\\", char::from(b'A' + index));
        let root_w = HSTRING::from(root.as_str());
        if unsafe { GetDriveTypeW(&root_w) } != DRIVE_REMOVABLE {
            continue;
        }
        // Lecteur sans support (lecteur de cartes vide) : ignoré.
        let mut name = [0u16; 261];
        if unsafe { GetVolumeInformationW(&root_w, Some(&mut name), None, None, None, None) }.is_err() {
            continue;
        }
        let label = String::from_utf16_lossy(&name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())]);
        let mut free: u64 = 0;
        let _ = unsafe { GetDiskFreeSpaceExW(&root_w, Some(&mut free), None, None) };
        let root = PathBuf::from(root);
        let shares = shares_on(&root);
        drives.push(RemovableDrive { root, label, free_bytes: free, shares });
    }
    drives
}

/// Détection des clés USB : Windows seulement pour l'instant.
#[cfg(not(windows))]
pub fn removable_drives() -> Vec<RemovableDrive> {
    Vec::new()
}

fn part_dir(root: &Path, part: u8) -> PathBuf {
    root.join(BACKUP_DIR).join(format!("part-{part}"))
}

/// Parts reconnues sur la clé `root` (format connu, dossier cohérent).
fn shares_on(root: &Path) -> Vec<ShareInfo> {
    (1..=3u8)
        .filter_map(|part| {
            let path = part_dir(root, part).join(INFO_FILE);
            if std::fs::metadata(&path).ok()?.len() > MAX_FILE_BYTES {
                return None;
            }
            let info: InfoFile = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
            (info.format == FORMAT_VERSION && info.part == part).then_some(ShareInfo { kit: info.kit, part })
        })
        .collect()
}

/// La clé USB de racine `root`, si elle est bien branchée et amovible : seule
/// destination ou source acceptée (l'interface ne choisit pas un chemin).
fn detected_drive(root: &str) -> Result<RemovableDrive> {
    removable_drives()
        .into_iter()
        .find(|d| d.root.to_string_lossy().eq_ignore_ascii_case(root.trim()))
        .ok_or_else(|| anyhow!("clé USB introuvable : branchez-la puis réessayez"))
}

/// Écrit `content` dans `path` : fichier temporaire, écriture forcée sur le
/// support, renommage, puis relecture comparée. En cas d'échec, le fichier
/// temporaire (qui peut contenir le mot de passe d'une part) est supprimé.
fn write_verified(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context("écriture sur la clé USB impossible"));
    }
    let back = std::fs::read(path).context("relecture de la clé USB impossible")?;
    ensure!(back == content, "la relecture de la clé USB ne correspond pas à ce qui a été écrit : clé défectueuse ?");
    Ok(())
}

/// LISEZ-MOI selon les parts de ce kit présentes sur la clé.
fn readme(parts: &[u8]) -> String {
    let list = parts.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
    if parts.len() >= 2 {
        format!(
            "SAUVEGARDE PGP WALLET — PARTS {list} SUR 3\r\n\
             \r\n\
             ATTENTION : cette clé contient PLUSIEURS parts du kit de récupération d'un\r\n\
             portefeuille PGP Wallet. Elle suffit À ELLE SEULE à récupérer tout le\r\n\
             portefeuille et ses fonds, sans aucun mot de passe. Rangez-la en lieu sûr\r\n\
             (coffre), jamais avec l'ordinateur.\r\n\
             \r\n\
             Restaurer : installez PGP Wallet, choisissez « J'ai déjà un portefeuille »\r\n\
             (ou « Restaurer depuis une sauvegarde »), puis branchez cette clé.\r\n\
             Ne modifiez ni ne renommez les fichiers de ce dossier.\r\n\
             \r\n\
             PGP WALLET BACKUP — SHARES {list} OF 3\r\n\
             \r\n\
             WARNING: this drive holds SEVERAL shares of a PGP Wallet recovery kit. On its\r\n\
             own it is enough to recover the whole wallet and its funds, with no password.\r\n\
             Keep it somewhere safe, never with the computer. To restore: install PGP\r\n\
             Wallet, choose \"I already have a wallet\", then plug in this drive.\r\n"
        )
    } else {
        format!(
            "SAUVEGARDE PGP WALLET — PART N°{list} SUR 3\r\n\
             \r\n\
             Cette clé contient UNE part du kit de récupération d'un portefeuille PGP Wallet.\r\n\
             Une part seule ne permet rien. DEUX parts réunies donnent un accès COMPLET au\r\n\
             portefeuille et à ses fonds : gardez chaque clé à un endroit différent, jamais\r\n\
             avec l'ordinateur ni avec une autre part.\r\n\
             \r\n\
             Restaurer : installez PGP Wallet, choisissez « J'ai déjà un portefeuille »\r\n\
             (ou « Restaurer depuis une sauvegarde »), puis branchez deux clés de sauvegarde.\r\n\
             Ne modifiez ni ne renommez les fichiers de ce dossier.\r\n\
             \r\n\
             PGP WALLET BACKUP — SHARE {list} OF 3\r\n\
             \r\n\
             This drive holds ONE share of a PGP Wallet recovery kit. One share alone is\r\n\
             useless; TWO shares together give FULL access to the wallet and its funds: keep\r\n\
             each drive in a different place, never with the computer or another share.\r\n\
             To restore: install PGP Wallet, choose \"I already have a wallet\", then plug in\r\n\
             two backup drives. Do not edit or rename the files in this folder.\r\n"
        )
    }
}

fn check_kit_id(kit: &str) -> Result<()> {
    ensure!(!kit.is_empty() && kit.len() <= 64 && kit.bytes().all(|b| b.is_ascii_hexdigit()), "identifiant de kit invalide");
    Ok(())
}

/// Refus commun : une part d'une AUTRE sauvegarde sur la clé (ne jamais en
/// écraser une sans que l'utilisateur l'ait décidé lui-même).
fn refuse_other_kits(drive: &RemovableDrive, kit: &str) -> Result<()> {
    if drive.shares.iter().any(|s| s.kit != kit) {
        bail!(
            "cette clé USB contient déjà une part d'une autre sauvegarde (ancienne, ou d'un autre portefeuille) : utilisez une clé vide, ou supprimez vous-même son dossier PGP-Wallet-Sauvegarde si vous n'en avez plus besoin"
        );
    }
    ensure!(drive.free_bytes >= MIN_FREE_BYTES, "espace insuffisant sur la clé USB");
    Ok(())
}

/// Écrit une part dans son dossier, puis le LISEZ-MOI.
fn write_part(drive: &RemovableDrive, kit: &str, part: u8, files: &ShareFiles) -> Result<()> {
    let dir = part_dir(&drive.root, part);
    std::fs::create_dir_all(&dir).context("écriture sur la clé USB impossible")?;
    write_verified(&dir.join(SHARE_FILE), &files.encrypted_share)?;
    write_verified(&dir.join(KEY_FILE), &files.privkey_armored)?;
    write_verified(&dir.join(PASSWORD_FILE), files.passphrase.as_bytes())?;
    let info = serde_json::to_vec_pretty(&InfoFile { format: FORMAT_VERSION, kit: kit.to_string(), part }).context("écriture sur la clé USB impossible")?;
    write_verified(&dir.join(INFO_FILE), &info)
}

/// Retire une part de la clé (ses seuls fichiers, puis son dossier s'il est
/// vide) : une part écrite mais invérifiable ne doit pas passer pour une
/// sauvegarde valable.
fn remove_part(root: &Path, part: u8) {
    let dir = part_dir(root, part);
    for name in [SHARE_FILE, KEY_FILE, PASSWORD_FILE, INFO_FILE] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = std::fs::remove_dir(&dir);
}

/// Relit chaque part écrite depuis la clé et la fait vérifier par `verify`
/// (déchiffrement réel), puis réécrit le LISEZ-MOI d'après les parts présentes.
/// Une part qui échoue à la vérification est retirée de la clé.
fn verify_parts(root: &str, kit: &str, parts: &[u8], verify: &impl Fn(&ShareFiles) -> Result<()>) -> Result<RemovableDrive> {
    let drive = detected_drive(root)?;
    for &part in parts {
        let checked = read_part(&drive.root, part).and_then(|(info, files)| {
            ensure!(info == (ShareInfo { kit: kit.to_string(), part }), "la relecture de la clé USB ne correspond pas à ce qui a été écrit");
            verify(&files).context("la part écrite sur la clé USB ne se déchiffre pas : sauvegarde inutilisable")
        });
        if let Err(e) = checked {
            remove_part(&drive.root, part);
            return Err(e);
        }
    }
    let drive = detected_drive(root)?;
    let present: Vec<u8> = drive.shares.iter().filter(|s| s.kit == kit).map(|s| s.part).collect();
    write_verified(&drive.root.join(BACKUP_DIR).join(README_FILE), readme(&present).as_bytes())?;
    Ok(drive)
}

/// Une part par clé : écrit la part `part` du kit `kit` sur la clé `root`,
/// puis la vérifie (relue depuis la clé). Refus : clé non détectée, clé
/// contenant déjà une AUTRE part de ce kit (deux parts sur une clé = accès
/// complet — pour cela, `write_kit`, choix explicite), ou une part d'une autre
/// sauvegarde.
pub fn write_share(root: &str, kit: &str, part: u8, files: &ShareFiles, verify: impl Fn(&ShareFiles) -> Result<()>) -> Result<RemovableDrive> {
    ensure!((1..=3).contains(&part), "numéro de part invalide");
    check_kit_id(kit)?;
    let drive = detected_drive(root)?;
    if let Some(other) = drive.shares.iter().find(|s| s.kit == kit && s.part != part) {
        bail!(
            "cette clé USB contient déjà la part n°{} de ce kit : deux parts sur une même clé suffiraient à tout récupérer — utilisez une autre clé",
            other.part
        );
    }
    refuse_other_kits(&drive, kit)?;
    write_part(&drive, kit, part, files)?;
    verify_parts(root, kit, &[part], &verify)
}

/// Tout le kit sur une clé (choix explicite de l'utilisateur, confirmé avant
/// l'appel) : écrit chaque part `(numéro, contenu)` puis les vérifie toutes.
/// Refus : clé non détectée, ou part d'une autre sauvegarde présente.
pub fn write_kit(root: &str, kit: &str, parts: &[(u8, ShareFiles)], verify: impl Fn(&ShareFiles) -> Result<()>) -> Result<RemovableDrive> {
    check_kit_id(kit)?;
    ensure!(!parts.is_empty() && parts.iter().all(|(p, _)| (1..=3).contains(p)), "numéro de part invalide");
    let drive = detected_drive(root)?;
    refuse_other_kits(&drive, kit)?;
    for (part, files) in parts {
        write_part(&drive, kit, *part, files)?;
    }
    let numbers: Vec<u8> = parts.iter().map(|(p, _)| *p).collect();
    verify_parts(root, kit, &numbers, &verify)
}

/// Lit la part `part` présente sur la clé USB `root`.
pub fn read_share(root: &str, part: u8) -> Result<(ShareInfo, ShareFiles)> {
    let drive = detected_drive(root)?;
    read_part(&drive.root, part)
}

/// Lit la part `part` rangée sous `root` (déjà vérifiée comme clé USB).
fn read_part(root: &Path, part: u8) -> Result<(ShareInfo, ShareFiles)> {
    let info = shares_on(root)
        .into_iter()
        .find(|s| s.part == part)
        .ok_or_else(|| anyhow!("aucune sauvegarde PGP Wallet sur cette clé USB"))?;
    let dir = part_dir(root, part);
    let read = |name: &str| -> Result<Vec<u8>> {
        let path = dir.join(name);
        let size = std::fs::metadata(&path).with_context(|| format!("sauvegarde incomplète sur la clé USB ({name} absent)"))?.len();
        ensure!(size <= MAX_FILE_BYTES, "fichier de sauvegarde anormalement gros sur la clé USB ({name})");
        std::fs::read(&path).context("lecture de la clé USB impossible")
    };
    let passphrase = String::from_utf8(read(PASSWORD_FILE)?).map_err(|_| anyhow!("mot de passe de la part illisible sur la clé USB"))?;
    let files = ShareFiles {
        encrypted_share: read(SHARE_FILE)?,
        privkey_armored: read(KEY_FILE)?,
        passphrase: Zeroizing::new(passphrase.trim_end_matches(['\r', '\n']).to_string()),
    };
    Ok((info, files))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parts reconnues : format connu et numéro cohérent avec le dossier ;
    /// illisible, d'un autre format ou mal rangée → ignorée.
    #[test]
    fn shares_are_recognized_only_when_well_formed() {
        let root = std::env::temp_dir().join(format!("usb_backup_info_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for part in 1..=3 {
            std::fs::create_dir_all(part_dir(&root, part)).unwrap();
        }
        assert!(shares_on(&root).is_empty(), "aucun fichier");
        let write = |part: u8, body: &str| std::fs::write(part_dir(&root, part).join(INFO_FILE), body).unwrap();
        write(1, r#"{"format":1,"kit":"ab12","part":1}"#);
        write(3, r#"{"format":1,"kit":"ab12","part":3}"#);
        assert_eq!(shares_on(&root), vec![ShareInfo { kit: "ab12".into(), part: 1 }, ShareInfo { kit: "ab12".into(), part: 3 }]);
        write(2, r#"{"format":1,"kit":"ab12","part":3}"#);
        write(3, r#"{"format":9,"kit":"ab12","part":3}"#);
        assert_eq!(shares_on(&root), vec![ShareInfo { kit: "ab12".into(), part: 1 }], "part mal rangée et autre format ignorées");
        write(1, "pas du json");
        assert!(shares_on(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// LISEZ-MOI : une part seule ne permet rien ; plusieurs parts sur la même
    /// clé = accès complet, et le fichier le dit.
    #[test]
    fn readme_warns_when_one_drive_holds_several_shares() {
        assert!(readme(&[2]).contains("UNE part") && readme(&[2]).contains("PART N°2"));
        assert!(readme(&[1, 2, 3]).contains("À ELLE SEULE") && readme(&[1, 2, 3]).contains("PARTS 1, 2, 3"));
    }

    /// Aller-retour réel : un vrai kit écrit sous un dossier temporaire (à la
    /// place de la clé), relu à l'identique, et chaque part relue se déchiffre
    /// avec la clé et le mot de passe relus ; aucun fichier temporaire ne reste.
    #[test]
    fn written_parts_read_back_identical_and_decrypt() {
        let base = std::env::temp_dir().join(format!("usb_backup_roundtrip_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let data = base.join("data");
        let drive = RemovableDrive { root: base.join("cle"), label: String::new(), free_bytes: u64::MAX, shares: Vec::new() };
        let created = crate::api::create_wallet(&data, "un mot de passe de test bien assez long").expect("création du wallet");
        let kit = crate::api::backup_kit_id(&created.backups);
        for (i, backup) in created.backups.iter().enumerate() {
            let files = ShareFiles {
                encrypted_share: backup.encrypted_share.clone(),
                privkey_armored: backup.privkey_armored.clone(),
                passphrase: Zeroizing::new(backup.passphrase.clone()),
            };
            write_part(&drive, &kit, i as u8 + 1, &files).expect("écriture de la part");
        }
        let expected: Vec<ShareInfo> = (1..=3).map(|part| ShareInfo { kit: kit.clone(), part }).collect();
        assert_eq!(shares_on(&drive.root), expected);
        for (i, backup) in created.backups.iter().enumerate() {
            let (info, files) = read_part(&drive.root, i as u8 + 1).expect("relecture");
            assert_eq!(info.part, i as u8 + 1);
            assert_eq!(files.encrypted_share, backup.encrypted_share);
            assert_eq!(files.privkey_armored, backup.privkey_armored);
            assert_eq!(files.passphrase.as_str(), backup.passphrase);
            crate::api::verify_backup_share(&data, &files.encrypted_share, &files.privkey_armored, &files.passphrase).expect("déchiffrement");
        }
        // Mauvais mot de passe : la vérification échoue (c'est elle qui fait
        // retirer une part invérifiable de la clé).
        let (_, files) = read_part(&drive.root, 1).unwrap();
        assert!(crate::api::verify_backup_share(&data, &files.encrypted_share, &files.privkey_armored, "faux").is_err());
        let leftovers = std::fs::read_dir(part_dir(&drive.root, 1)).unwrap().filter_map(|e| e.ok()).filter(|e| e.path().extension().is_some_and(|x| x == "tmp")).count();
        assert_eq!(leftovers, 0, "fichier temporaire laissé sur la clé");
        remove_part(&drive.root, 2);
        assert_eq!(shares_on(&drive.root).len(), 2, "part retirée");
        assert!(!part_dir(&drive.root, 2).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Une destination qui n'est pas une clé USB détectée est refusée (le disque
    /// système, un dossier quelconque), et les paramètres invalides aussi.
    #[test]
    fn only_detected_usb_drives_are_accepted() {
        let files = || ShareFiles { encrypted_share: vec![1], privkey_armored: vec![2], passphrase: Zeroizing::new("x".into()) };
        let ok = |_: &ShareFiles| Ok(());
        assert!(write_share("C:\\", "ab12", 1, &files(), ok).is_err(), "disque système");
        assert!(write_share(&std::env::temp_dir().to_string_lossy(), "ab12", 1, &files(), ok).is_err());
        assert!(write_share("C:\\", "ab12", 4, &files(), ok).is_err(), "part invalide");
        assert!(write_share("C:\\", "../x", 1, &files(), ok).is_err(), "kit invalide");
        assert!(write_kit("C:\\", "ab12", &[(1, files()), (2, files())], ok).is_err(), "disque système");
        assert!(write_kit("C:\\", "ab12", &[(7, files())], ok).is_err(), "part invalide");
        assert!(read_share("C:\\", 1).is_err());
    }
}
