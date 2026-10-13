//! Backing up the recovery kit to a USB drive: plugging in a drive is enough, the
//! app detects it and writes COMPLETE shares to it (share file, private key,
//! password), so there is nothing to write down. Two uses, chosen by the user:
//! - one share per drive (`write_share`): a single drive is useless on its own (2
//!   shares out of 3 are needed), hence the refusal to write a second share of the
//!   same kit to it;
//! - the whole kit on one drive (`write_kit`): that drive is then enough ON ITS OWN
//!   to recover everything, with no password. The app asks for confirmation, and
//!   the LISEZ-MOI (README) file warns whoever finds the drive.
//!
//! One drive can hold backups of SEVERAL wallets, each in its own folder, named by
//! the user ("Perso", "Pro"…): `PGP-Wallet-Sauvegarde/<name>-<kit>/part-N/`
//! (part.asc, cle-privee.asc, mot-de-passe.txt, sauvegarde.json), with a LISEZ-MOI
//! per folder and one at the root. Drives written earlier
//! (`PGP-Wallet-Sauvegarde/part-N/`, unnamed) are still read, and a share there is
//! rewritten in the same place. These on-drive names are frozen: existing drives
//! must keep working.
//!
//! Verified writes: reread and compared, then each share is actually decrypted with
//! the key and password written (see `api::verify_backup_share`) before telling the
//! user it is done. Only USB drives detected by the system are accepted as a
//! destination or source (never a path chosen by the UI).

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Folder created at the root of the drive.
pub const BACKUP_DIR: &str = "PGP-Wallet-Sauvegarde";
const SHARE_FILE: &str = "part.asc";
const KEY_FILE: &str = "cle-privee.asc";
const PASSWORD_FILE: &str = "mot-de-passe.txt";
const INFO_FILE: &str = "sauvegarde.json";
const README_FILE: &str = "LISEZ-MOI.txt";
/// A share's files: a few KB; anything bigger is not a backup.
const MAX_FILE_BYTES: u64 = 1 << 20;
const MIN_FREE_BYTES: u64 = 256 * 1024;
/// 2: backup name (1: unnamed, legacy layout).
const FORMAT_VERSION: u32 = 2;
/// Maximum number of backup folders read on a drive.
const MAX_FOLDERS: usize = 32;
pub const NAME_INVALID: &str = "nom de la sauvegarde : 1 à 30 caractères (lettres, chiffres, espaces, - _)";

/// A share found on a drive: kit (random identifier, reveals nothing about the
/// wallet), share number and backup name (empty: written before names existed).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ShareInfo {
    pub kit: String,
    pub part: u8,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
struct InfoFile {
    format: u32,
    kit: String,
    part: u8,
    #[serde(default)]
    name: String,
}

/// Check of a share on the drive ("Check my backup drives"): reread and decrypted,
/// nothing is written or restored.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ShareCheck {
    /// Empty for an unrecognized share.
    pub kit: String,
    pub part: u8,
    /// Backup name; for an unrecognized share, the name of its folder.
    pub name: String,
    /// `None`: intact. Otherwise `PROBLEM_UNREADABLE`, `PROBLEM_DECRYPT` or
    /// `PROBLEM_UNRECOGNIZED`.
    pub problem: Option<&'static str>,
}

/// The share's file is missing, abnormally large or unreadable.
pub const PROBLEM_UNREADABLE: &str = "unreadable";
/// The share no longer decrypts with its key and password.
pub const PROBLEM_DECRYPT: &str = "decrypt";
/// Damaged `sauvegarde.json`: restore-from-drive no longer sees the share (its
/// files may still be usable through restore-from-files).
pub const PROBLEM_UNRECOGNIZED: &str = "unrecognized";

/// A detected USB drive.
#[derive(Debug)]
pub struct RemovableDrive {
    /// Root, `E:\`.
    pub root: PathBuf,
    pub label: String,
    pub free_bytes: u64,
    /// Backup shares already present.
    pub shares: Vec<ShareInfo>,
}

/// Content of a backup share.
pub struct ShareFiles {
    pub encrypted_share: Vec<u8>,
    pub privkey_armored: Vec<u8>,
    pub passphrase: Zeroizing<String>,
}

/// Plugged-in USB drives (removable drives with media inserted).
#[cfg(windows)]
pub fn removable_drives() -> Vec<RemovableDrive> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW};
    use windows::Win32::System::Diagnostics::Debug::{SetThreadErrorMode, SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX, THREAD_ERROR_MODE};
    /// `DRIVE_REMOVABLE`: USB stick, memory card (an external USB hard drive reports
    /// itself as "fixed" and is not offered).
    const DRIVE_REMOVABLE: u32 = 2;
    /// Restores the thread's previous error mode at the end of detection.
    struct ErrorModeGuard(THREAD_ERROR_MODE);
    impl Drop for ErrorModeGuard {
        fn drop(&mut self) {
            let _ = unsafe { SetThreadErrorMode(self.0, None) };
        }
    }
    // Drive with no media (empty card reader): without this mode, Windows may show its
    // "No disk in the drive" dialog on every detection, i.e. every 1.5 s while the USB
    // window is open. Applies to the current thread only, restored at the end.
    let mut previous = THREAD_ERROR_MODE(0);
    let _guard = unsafe { SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, Some(&mut previous)) }
        .ok()
        .map(|()| ErrorModeGuard(previous));
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
        // Drive with no media (empty card reader): ignored.
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

/// USB drive detection: Windows only for now.
#[cfg(not(windows))]
pub fn removable_drives() -> Vec<RemovableDrive> {
    Vec::new()
}

/// A share found on the drive, with the folder that contains its `part-N` folders.
struct Located {
    info: ShareInfo,
    kit_dir: PathBuf,
}

fn part_dir(kit_dir: &Path, part: u8) -> PathBuf {
    kit_dir.join(format!("part-{part}"))
}

/// Shares recognized on the drive `root`: the legacy layout (`part-N` directly
/// under the backup folder) and one folder per named backup. Known format, number
/// consistent with the folder, valid kit identifier; a given (kit, share) pair is
/// kept only once.
fn located_shares(root: &Path) -> Vec<Located> {
    let mut found: Vec<Located> = Vec::new();
    for kit_dir in kit_dirs(root) {
        for part in 1..=3u8 {
            let Some(info) = read_info(&kit_dir, part) else { continue };
            if !found.iter().any(|l| l.info.kit == info.kit && l.info.part == part) {
                found.push(Located { info, kit_dir: kit_dir.clone() });
            }
        }
    }
    found
}

/// Folders containing `part-N` folders: the backup folder itself (legacy layout),
/// then one per named backup.
fn kit_dirs(root: &Path) -> Vec<PathBuf> {
    let base = root.join(BACKUP_DIR);
    let mut kit_dirs = vec![base.clone()];
    if let Ok(entries) = std::fs::read_dir(&base) {
        let mut named: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()) && !matches!(e.file_name().to_str(), Some("part-1" | "part-2" | "part-3")))
            .map(|e| e.path())
            .collect();
        named.sort();
        named.truncate(MAX_FOLDERS);
        kit_dirs.extend(named);
    }
    kit_dirs
}

/// `sauvegarde.json` of share `part` in `kit_dir`, if well-formed: known format,
/// number consistent with the folder, valid kit identifier.
fn read_info(kit_dir: &Path, part: u8) -> Option<ShareInfo> {
    let path = part_dir(kit_dir, part).join(INFO_FILE);
    let info = std::fs::metadata(&path)
        .ok()
        .filter(|m| m.len() <= MAX_FILE_BYTES)
        .and_then(|_| std::fs::read(&path).ok())
        .and_then(|bytes| serde_json::from_slice::<InfoFile>(&bytes).ok())?;
    let well_formed = matches!(info.format, 1 | 2) && info.part == part && check_kit_id(&info.kit).is_ok();
    let name = if info.format == 1 { String::new() } else { normalize_name(&info.name).unwrap_or_default() };
    well_formed.then_some(ShareInfo { kit: info.kit, part, name })
}

/// Checks every share on the drive `root` (reread, then decrypted by `verify`)
/// without writing anything. Worth doing from time to time, since a USB drive can
/// degrade over the years. Also reports share folders whose `sauvegarde.json` is
/// damaged, which restore-from-drive no longer sees.
pub fn check_drive(root: &str, verify: impl Fn(&ShareFiles) -> Result<()>) -> Result<Vec<ShareCheck>> {
    let drive = detected_drive(root)?;
    Ok(check_drive_at(&drive.root, &verify))
}

fn check_drive_at(root: &Path, verify: &impl Fn(&ShareFiles) -> Result<()>) -> Vec<ShareCheck> {
    let mut checks: Vec<ShareCheck> = located_shares(root)
        .iter()
        .map(|located| ShareCheck {
            kit: located.info.kit.clone(),
            part: located.info.part,
            name: located.info.name.clone(),
            problem: match read_located(located) {
                Err(_) => Some(PROBLEM_UNREADABLE),
                Ok(files) => verify(&files).err().map(|_| PROBLEM_DECRYPT),
            },
        })
        .collect();
    let base = root.join(BACKUP_DIR);
    for kit_dir in kit_dirs(root) {
        for part in 1..=3u8 {
            let dir = part_dir(&kit_dir, part);
            let has_files = std::fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_some());
            if has_files && read_info(&kit_dir, part).is_none() {
                let name = if kit_dir == base { String::new() } else { kit_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default() };
                checks.push(ShareCheck { kit: String::new(), part, name, problem: Some(PROBLEM_UNRECOGNIZED) });
            }
        }
    }
    checks
}

fn shares_on(root: &Path) -> Vec<ShareInfo> {
    located_shares(root).into_iter().map(|l| l.info).collect()
}

/// Accepted backup name: 1 to 30 characters, letters (accented ones included),
/// digits, spaces, "-" and "_"; nothing that causes trouble in a folder name on the
/// drive.
pub fn normalize_name(name: &str) -> Result<String> {
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!((1..=30).contains(&name.chars().count()) && name.chars().all(|c| c.is_alphanumeric() || " -_".contains(c)), NAME_INVALID);
    Ok(name)
}

/// Folder of a named backup: the name (spaces as "-") followed by the start of the
/// kit identifier, so two backups with the same name never get mixed up.
fn kit_folder(name: &str, kit: &str, full_id: bool) -> String {
    let base: String = name.chars().map(|c| if c == ' ' { '-' } else { c }).collect();
    format!("{base}-{}", if full_id { kit } else { &kit[..kit.len().min(6)] })
}

/// The USB drive with root `root`, if it is actually plugged in and removable: the
/// only destination or source accepted (the UI does not choose a path).
fn detected_drive(root: &str) -> Result<RemovableDrive> {
    removable_drives()
        .into_iter()
        .find(|d| d.root.to_string_lossy().eq_ignore_ascii_case(root.trim()))
        .ok_or_else(|| anyhow!("clé USB introuvable : branchez-la puis réessayez"))
}

/// Writes `content` to `path`: temporary file, write flushed to the media, rename,
/// then reread and compare. On failure, the temporary file (which may contain a
/// share's password) is deleted.
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

/// LISEZ-MOI for a backup, based on its shares present on the drive.
fn readme(name: &str, parts: &[u8]) -> String {
    let list = parts.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
    let title = if name.is_empty() { String::new() } else { format!(" « {name} »") };
    let title_en = if name.is_empty() { String::new() } else { format!(" \"{name}\"") };
    if parts.len() >= 2 {
        format!(
            "SAUVEGARDE OPENPGP WALLET{title} — PARTS {list} SUR 3\r\n\
             \r\n\
             ATTENTION : cette clé contient PLUSIEURS parts du kit de récupération d'un\r\n\
             portefeuille OpenPGP Wallet. Elle suffit À ELLE SEULE à récupérer tout le\r\n\
             portefeuille et ses fonds, sans aucun mot de passe. Rangez-la en lieu sûr\r\n\
             (coffre), jamais avec l'ordinateur.\r\n\
             \r\n\
             Restaurer : installez OpenPGP Wallet, choisissez « J'ai déjà un portefeuille »\r\n\
             (ou « Restaurer depuis une sauvegarde »), puis branchez cette clé.\r\n\
             Ne modifiez ni ne renommez les fichiers de ce dossier.\r\n\
             \r\n\
             OPENPGP WALLET BACKUP{title_en} — SHARES {list} OF 3\r\n\
             \r\n\
             WARNING: this drive holds SEVERAL shares of an OpenPGP Wallet recovery kit.\r\n\
             On its own it is enough to recover the whole wallet and its funds, with no\r\n\
             password. Keep it somewhere safe, never with the computer. To restore: install\r\n\
             OpenPGP Wallet, choose \"I already have a wallet\", then plug in this drive.\r\n"
        )
    } else {
        format!(
            "SAUVEGARDE OPENPGP WALLET{title} — PART N°{list} SUR 3\r\n\
             \r\n\
             Cette clé contient UNE part du kit de récupération d'un portefeuille\r\n\
             OpenPGP Wallet. Une part seule ne permet rien. DEUX parts réunies donnent un\r\n\
             accès COMPLET au portefeuille et à ses fonds : gardez chaque clé à un endroit\r\n\
             différent, jamais avec l'ordinateur ni avec une autre part.\r\n\
             \r\n\
             Restaurer : installez OpenPGP Wallet, choisissez « J'ai déjà un portefeuille »\r\n\
             (ou « Restaurer depuis une sauvegarde »), puis branchez deux clés de sauvegarde.\r\n\
             Ne modifiez ni ne renommez les fichiers de ce dossier.\r\n\
             \r\n\
             OPENPGP WALLET BACKUP{title_en} — SHARE {list} OF 3\r\n\
             \r\n\
             This drive holds ONE share of an OpenPGP Wallet recovery kit. One share alone\r\n\
             is useless; TWO shares together give FULL access to the wallet and its funds:\r\n\
             keep each drive in a different place, never with the computer or another\r\n\
             share. To restore: install OpenPGP Wallet, choose \"I already have a wallet\",\r\n\
             then plug in two backup drives. Do not edit or rename the files in this folder.\r\n"
        )
    }
}

/// LISEZ-MOI at the root when the drive holds named backups.
const ROOT_README: &str = "SAUVEGARDES OPENPGP WALLET\r\n\
\r\n\
Chaque dossier contient des parts du kit de récupération d'un portefeuille\r\n\
OpenPGP Wallet, sous le nom choisi à l'enregistrement. Le LISEZ-MOI de chaque\r\n\
dossier dit combien de parts de ce portefeuille cette clé contient. Une part\r\n\
seule ne permet rien ; deux parts d'un même portefeuille y donnent un accès\r\n\
complet. Ne modifiez ni ne renommez les fichiers et dossiers.\r\n\
\r\n\
OPENPGP WALLET BACKUPS\r\n\
\r\n\
Each folder holds shares of an OpenPGP Wallet recovery kit, under the name chosen\r\n\
when saving. The LISEZ-MOI file of each folder says how many shares of that\r\n\
wallet this drive holds. One share alone is useless; two shares of the same\r\n\
wallet give full access to it. Do not edit or rename the files or folders.\r\n";

fn check_kit_id(kit: &str) -> Result<()> {
    ensure!(!kit.is_empty() && kit.len() <= 64 && kit.bytes().all(|b| b.is_ascii_hexdigit()), "identifiant de kit invalide");
    Ok(())
}

/// Folder to write the kit's shares into: the one it already occupies on the drive
/// (legacy layout included, with its name), otherwise a new named folder. Never a
/// folder that is already filled (same name and same start of identifier as another
/// backup: the full identifier tells them apart).
fn kit_destination(root: &Path, located: &[Located], kit: &str, name: &str) -> Result<(PathBuf, String)> {
    if let Some(existing) = located.iter().find(|l| l.info.kit == kit) {
        return Ok((existing.kit_dir.clone(), existing.info.name.clone()));
    }
    let name = normalize_name(name)?;
    let dir = [false, true]
        .into_iter()
        .map(|full_id| root.join(BACKUP_DIR).join(kit_folder(&name, kit, full_id)))
        .find(|dir| std::fs::read_dir(dir).map_or(true, |mut entries| entries.next().is_none()))
        .ok_or_else(|| anyhow!("un dossier de sauvegarde de ce nom existe déjà sur la clé USB : choisissez un autre nom"))?;
    Ok((dir, name))
}

/// Writes a share into its kit's folder.
fn write_part(kit_dir: &Path, kit: &str, name: &str, part: u8, files: &ShareFiles) -> Result<()> {
    let dir = part_dir(kit_dir, part);
    std::fs::create_dir_all(&dir).context("écriture sur la clé USB impossible")?;
    write_verified(&dir.join(SHARE_FILE), &files.encrypted_share)?;
    write_verified(&dir.join(KEY_FILE), &files.privkey_armored)?;
    write_verified(&dir.join(PASSWORD_FILE), files.passphrase.as_bytes())?;
    let format = if name.is_empty() { 1 } else { FORMAT_VERSION };
    let info = serde_json::to_vec_pretty(&InfoFile { format, kit: kit.to_string(), part, name: name.to_string() }).context("écriture sur la clé USB impossible")?;
    write_verified(&dir.join(INFO_FILE), &info)
}

/// Removes a share from the drive (only its files, then its folder if empty): a
/// share that was written but cannot be verified must not pass for a valid backup.
fn remove_part(kit_dir: &Path, part: u8) {
    let dir = part_dir(kit_dir, part);
    for name in [SHARE_FILE, KEY_FILE, PASSWORD_FILE, INFO_FILE] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = std::fs::remove_dir(&dir);
}

/// Removes from the drive shares that were written but not verified (interrupted
/// write, failed verification): nothing unverifiable is left behind, password
/// included. The folder of a named backup that has no shares left disappears;
/// otherwise the LISEZ-MOI files follow the remaining shares.
fn discard_parts(root: &Path, kit_dir: &Path, kit: &str, parts: &[u8]) {
    for &part in parts {
        remove_part(kit_dir, part);
    }
    let left = located_shares(root).iter().any(|l| l.info.kit == kit);
    if kit_dir != root.join(BACKUP_DIR) && !left {
        let _ = std::fs::remove_file(kit_dir.join(README_FILE));
        let _ = std::fs::remove_dir(kit_dir);
    }
    let _ = write_readmes(root, kit);
}

/// Rereads each written share from the drive and has `verify` check it (real
/// decryption), then rewrites the LISEZ-MOI files from the shares present. At the
/// first failure, that share and those not yet verified are removed from the drive
/// (shares already verified remain valid).
fn verify_parts_at(root: &Path, kit_dir: &Path, kit: &str, parts: &[u8], verify: &impl Fn(&ShareFiles) -> Result<()>) -> Result<()> {
    for (index, &part) in parts.iter().enumerate() {
        let located = located_shares(root).into_iter().find(|l| l.info.kit == kit && l.info.part == part);
        let checked = located
            .ok_or_else(|| anyhow!("la relecture de la clé USB ne correspond pas à ce qui a été écrit"))
            .and_then(|located| read_located(&located))
            .and_then(|files| verify(&files).context("la part écrite sur la clé USB ne se déchiffre pas : sauvegarde inutilisable"));
        if let Err(e) = checked {
            discard_parts(root, kit_dir, kit, &parts[index..]);
            return Err(e);
        }
    }
    write_readmes(root, kit)
}

/// Writes the shares into the kit's folder, then verifies them. If the write is
/// interrupted, the shares already written in this call are removed.
fn write_and_verify(root: &Path, kit_dir: &Path, kit: &str, name: &str, parts: &[(u8, &ShareFiles)], verify: &impl Fn(&ShareFiles) -> Result<()>) -> Result<()> {
    let numbers: Vec<u8> = parts.iter().map(|(p, _)| *p).collect();
    for (index, (part, files)) in parts.iter().enumerate() {
        if let Err(e) = write_part(kit_dir, kit, name, *part, files) {
            discard_parts(root, kit_dir, kit, &numbers[..=index]);
            return Err(e);
        }
    }
    verify_parts_at(root, kit_dir, kit, &numbers, verify)
}

/// LISEZ-MOI for the folder of kit `kit` and for the root. At the root: the one for
/// the legacy layout (unnamed shares stored there), preceded by the general text as
/// soon as the drive holds named backups.
fn write_readmes(root: &Path, kit: &str) -> Result<()> {
    let base = root.join(BACKUP_DIR);
    let located = located_shares(root);
    let mine: Vec<&Located> = located.iter().filter(|l| l.info.kit == kit).collect();
    if let Some(first) = mine.first().filter(|l| l.kit_dir != base) {
        let present: Vec<u8> = mine.iter().map(|l| l.info.part).collect();
        write_verified(&first.kit_dir.join(README_FILE), readme(&first.info.name, &present).as_bytes())?;
    }
    let legacy: Vec<u8> = located.iter().filter(|l| l.kit_dir == base).map(|l| l.info.part).collect();
    let named = located.iter().any(|l| l.kit_dir != base);
    let content = match (named, legacy.is_empty()) {
        (true, true) => ROOT_README.to_string(),
        (true, false) => format!("{ROOT_README}\r\n----------------------------------------\r\n\r\n{}", readme("", &legacy)),
        (false, false) => readme("", &legacy),
        (false, true) => return Ok(()),
    };
    write_verified(&base.join(README_FILE), content.as_bytes())
}

/// `write_share` on a root folder already recognized as a USB drive.
fn write_share_at(root: &Path, free_bytes: u64, kit: &str, name: &str, part: u8, files: &ShareFiles, verify: &impl Fn(&ShareFiles) -> Result<()>) -> Result<()> {
    let located = located_shares(root);
    if let Some(other) = located.iter().find(|l| l.info.kit == kit && l.info.part != part) {
        bail!(
            "cette clé USB contient déjà la part n°{} de ce kit : deux parts sur une même clé suffiraient à tout récupérer — utilisez une autre clé",
            other.info.part
        );
    }
    ensure!(free_bytes >= MIN_FREE_BYTES, "espace insuffisant sur la clé USB");
    let (kit_dir, name) = kit_destination(root, &located, kit, name)?;
    write_and_verify(root, &kit_dir, kit, &name, &[(part, files)], verify)
}

/// `write_kit` on a root folder already recognized as a USB drive.
fn write_kit_at(root: &Path, free_bytes: u64, kit: &str, name: &str, parts: &[(u8, ShareFiles)], verify: &impl Fn(&ShareFiles) -> Result<()>) -> Result<()> {
    ensure!(free_bytes >= MIN_FREE_BYTES, "espace insuffisant sur la clé USB");
    let (kit_dir, name) = kit_destination(root, &located_shares(root), kit, name)?;
    let parts: Vec<(u8, &ShareFiles)> = parts.iter().map(|(p, f)| (*p, f)).collect();
    write_and_verify(root, &kit_dir, kit, &name, &parts, verify)
}

/// One share per drive: writes share `part` of kit `kit` to the drive `root`, in
/// the folder of backup `name` (the one this kit already occupies, if any), then
/// verifies it (reread from the drive). Other wallets' backups on the drive are
/// left alone. Refused: drive not detected, or drive already holding ANOTHER share
/// of this kit (two shares on one drive = full access; that is what `write_kit` is
/// for, as an explicit choice).
pub fn write_share(root: &str, kit: &str, name: &str, part: u8, files: &ShareFiles, verify: impl Fn(&ShareFiles) -> Result<()>) -> Result<RemovableDrive> {
    ensure!((1..=3).contains(&part), "numéro de part invalide");
    check_kit_id(kit)?;
    let drive = detected_drive(root)?;
    write_share_at(&drive.root, drive.free_bytes, kit, name, part, files, &verify)?;
    detected_drive(root)
}

/// The whole kit on one drive (the user's explicit choice, confirmed before the
/// call): writes each share `(number, content)`, then verifies them all. Refused:
/// drive not detected.
pub fn write_kit(root: &str, kit: &str, name: &str, parts: &[(u8, ShareFiles)], verify: impl Fn(&ShareFiles) -> Result<()>) -> Result<RemovableDrive> {
    check_kit_id(kit)?;
    ensure!(!parts.is_empty() && parts.iter().all(|(p, _)| (1..=3).contains(p)), "numéro de part invalide");
    let drive = detected_drive(root)?;
    write_kit_at(&drive.root, drive.free_bytes, kit, name, parts, &verify)?;
    detected_drive(root)
}

/// Reads share `part` of kit `kit` from the USB drive `root`.
pub fn read_share(root: &str, kit: &str, part: u8) -> Result<(ShareInfo, ShareFiles)> {
    let drive = detected_drive(root)?;
    read_share_at(&drive.root, kit, part)
}

fn read_share_at(root: &Path, kit: &str, part: u8) -> Result<(ShareInfo, ShareFiles)> {
    let located = located_shares(root)
        .into_iter()
        .find(|l| l.info.kit == kit && l.info.part == part)
        .ok_or_else(|| anyhow!("aucune sauvegarde OpenPGP Wallet sur cette clé USB"))?;
    let files = read_located(&located)?;
    Ok((located.info, files))
}

fn read_located(located: &Located) -> Result<ShareFiles> {
    let dir = part_dir(&located.kit_dir, located.info.part);
    let read = |name: &str| -> Result<Vec<u8>> {
        let path = dir.join(name);
        let size = std::fs::metadata(&path).with_context(|| format!("sauvegarde incomplète sur la clé USB ({name} absent)"))?.len();
        ensure!(size <= MAX_FILE_BYTES, "fichier de sauvegarde anormalement gros sur la clé USB ({name})");
        std::fs::read(&path).context("lecture de la clé USB impossible")
    };
    let passphrase = String::from_utf8(read(PASSWORD_FILE)?).map_err(|_| anyhow!("mot de passe de la part illisible sur la clé USB"))?;
    Ok(ShareFiles {
        encrypted_share: read(SHARE_FILE)?,
        privkey_armored: read(KEY_FILE)?,
        passphrase: Zeroizing::new(passphrase.trim_end_matches(['\r', '\n']).to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("usb_backup_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn info(kit: &str, part: u8, name: &str) -> ShareInfo {
        ShareInfo { kit: kit.into(), part, name: name.into() }
    }

    /// Recognized shares: known format and number consistent with the folder;
    /// unreadable, in another format or misplaced → ignored. Legacy layout (unnamed)
    /// and named folders read together.
    #[test]
    fn shares_are_recognized_only_when_well_formed() {
        let root = temp_root("info");
        let legacy = root.join(BACKUP_DIR);
        for part in 1..=3 {
            std::fs::create_dir_all(part_dir(&legacy, part)).unwrap();
        }
        assert!(shares_on(&root).is_empty(), "aucun fichier");
        let write = |dir: &Path, part: u8, body: &str| {
            std::fs::create_dir_all(part_dir(dir, part)).unwrap();
            std::fs::write(part_dir(dir, part).join(INFO_FILE), body).unwrap();
        };
        write(&legacy, 1, r#"{"format":1,"kit":"ab12","part":1}"#);
        write(&legacy, 3, r#"{"format":1,"kit":"ab12","part":3}"#);
        assert_eq!(shares_on(&root), vec![info("ab12", 1, ""), info("ab12", 3, "")]);
        let pro = legacy.join("Pro-cd34ef");
        write(&pro, 2, r#"{"format":2,"kit":"cd34ef","part":2,"name":"Pro"}"#);
        assert_eq!(shares_on(&root), vec![info("ab12", 1, ""), info("ab12", 3, ""), info("cd34ef", 2, "Pro")]);
        write(&legacy, 2, r#"{"format":1,"kit":"ab12","part":3}"#);
        write(&legacy, 3, r#"{"format":9,"kit":"ab12","part":3}"#);
        write(&pro, 1, r#"{"format":2,"kit":"../x","part":1,"name":"Pro"}"#);
        assert_eq!(shares_on(&root), vec![info("ab12", 1, ""), info("cd34ef", 2, "Pro")], "part mal rangée, autre format, kit invalide ignorés");
        write(&legacy, 1, "pas du json");
        assert_eq!(shares_on(&root), vec![info("cd34ef", 2, "Pro")]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn backup_names_are_checked() {
        assert_eq!(normalize_name("  Mon   portefeuille ").unwrap(), "Mon portefeuille");
        assert_eq!(normalize_name("Épargne_2026-bis").unwrap(), "Épargne_2026-bis");
        for bad in ["", "   ", "../x", "a/b", "nom:avec", "x".repeat(31).as_str(), "point."] {
            assert!(normalize_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(kit_folder("Mon portefeuille", "0123456789ab", false), "Mon-portefeuille-012345");
    }

    /// LISEZ-MOI: a single share allows nothing; several shares on the same drive =
    /// full access, and the file says so, with the backup's name.
    #[test]
    fn readme_warns_when_one_drive_holds_several_shares() {
        assert!(readme("", &[2]).contains("UNE part") && readme("", &[2]).contains("PART N°2"));
        assert!(readme("", &[1, 2, 3]).contains("À ELLE SEULE") && readme("", &[1, 2, 3]).contains("PARTS 1, 2, 3"));
        assert!(readme("Pro", &[1]).contains("SAUVEGARDE OPENPGP WALLET « Pro » — PART N°1"));
    }

    fn files_of(backup: &crate::api::BackupShare) -> ShareFiles {
        ShareFiles {
            encrypted_share: backup.encrypted_share.clone(),
            privkey_armored: backup.privkey_armored.clone(),
            passphrase: Zeroizing::new(backup.passphrase.clone()),
        }
    }

    /// Real round trip: a real kit written under a temporary folder (in place of the
    /// drive), reread identically, and each reread share decrypts with the reread key
    /// and password; no temporary file is left behind.
    #[test]
    fn written_parts_read_back_identical_and_decrypt() {
        let base = temp_root("roundtrip");
        let data = base.join("data");
        let root = base.join("cle");
        let created = crate::api::create_wallet(&data, "un mot de passe de test bien assez long").expect("création du wallet");
        let kit = crate::api::backup_kit_id(&created.backups);
        let verify = |files: &ShareFiles| crate::api::verify_backup_share(&data, &files.encrypted_share, &files.privkey_armored, &files.passphrase);
        let parts: Vec<(u8, ShareFiles)> = created.backups.iter().enumerate().map(|(i, b)| (i as u8 + 1, files_of(b))).collect();
        write_kit_at(&root, u64::MAX, &kit, "Coffre", &parts, &verify).expect("écriture du kit");
        let expected: Vec<ShareInfo> = (1..=3).map(|part| info(&kit, part, "Coffre")).collect();
        assert_eq!(shares_on(&root), expected);
        let kit_dir = root.join(BACKUP_DIR).join(kit_folder("Coffre", &kit, false));
        assert!(kit_dir.join(README_FILE).exists() && root.join(BACKUP_DIR).join(README_FILE).exists());
        for (i, backup) in created.backups.iter().enumerate() {
            let (read_info, files) = read_share_at(&root, &kit, i as u8 + 1).expect("relecture");
            assert_eq!(read_info, info(&kit, i as u8 + 1, "Coffre"));
            assert_eq!(files.encrypted_share, backup.encrypted_share);
            assert_eq!(files.privkey_armored, backup.privkey_armored);
            assert_eq!(files.passphrase.as_str(), backup.passphrase);
            verify(&files).expect("déchiffrement");
        }
        // Wrong password: verification fails (that is what gets an unverifiable share
        // removed from the drive).
        let (_, files) = read_share_at(&root, &kit, 1).unwrap();
        assert!(crate::api::verify_backup_share(&data, &files.encrypted_share, &files.privkey_armored, "faux").is_err());
        let leftovers = std::fs::read_dir(part_dir(&kit_dir, 1)).unwrap().filter_map(|e| e.ok()).filter(|e| e.path().extension().is_some_and(|x| x == "tmp")).count();
        assert_eq!(leftovers, 0, "fichier temporaire laissé sur la clé");
        remove_part(&kit_dir, 2);
        assert_eq!(shares_on(&root).len(), 2, "part retirée");
        assert!(!part_dir(&kit_dir, 2).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Several wallets on one drive: each in its own named folder, one share of each;
    /// never two shares of the same wallet (except "everything on one drive"); a
    /// rewritten share stays in its kit's folder (original name kept), legacy layout
    /// included; an unverifiable share is removed without touching the others.
    #[test]
    fn several_wallets_share_one_drive() {
        let base = temp_root("several");
        let root = base.join("cle");
        let created_a = crate::api::create_wallet(&base.join("a"), "un mot de passe de test bien assez long").unwrap();
        let created_b = crate::api::create_wallet(&base.join("b"), "un autre mot de passe de test assez long").unwrap();
        let (kit_a, kit_b) = (crate::api::backup_kit_id(&created_a.backups), crate::api::backup_kit_id(&created_b.backups));
        let ok = |_: &ShareFiles| Ok(());
        write_share_at(&root, u64::MAX, &kit_a, "Perso", 1, &files_of(&created_a.backups[0]), &ok).unwrap();
        write_share_at(&root, u64::MAX, &kit_b, "Pro", 2, &files_of(&created_b.backups[1]), &ok).unwrap();
        assert_eq!(shares_on(&root), vec![info(&kit_a, 1, "Perso"), info(&kit_b, 2, "Pro")]);
        let err = write_share_at(&root, u64::MAX, &kit_a, "Perso", 2, &files_of(&created_a.backups[1]), &ok).unwrap_err().to_string();
        assert!(err.contains("part n°1 de ce kit"), "{err}");
        // Rewriting share 1 under another name: same folder, original name.
        write_share_at(&root, u64::MAX, &kit_a, "Autre nom", 1, &files_of(&created_a.backups[0]), &ok).unwrap();
        assert_eq!(shares_on(&root), vec![info(&kit_a, 1, "Perso"), info(&kit_b, 2, "Pro")]);
        // Unverifiable share: removed, the other wallet intact.
        let refuse = |_: &ShareFiles| -> Result<()> { bail!("ne se déchiffre pas") };
        assert!(write_share_at(&root, u64::MAX, &kit_a, "Perso", 1, &files_of(&created_a.backups[0]), &refuse).is_err());
        assert_eq!(shares_on(&root), vec![info(&kit_b, 2, "Pro")]);
        // Legacy layout: a rewritten share stays there, unnamed.
        let old = base.join("ancienne");
        let legacy = old.join(BACKUP_DIR);
        write_part(&legacy, &kit_a, "", 3, &files_of(&created_a.backups[2])).unwrap();
        write_share_at(&old, u64::MAX, &kit_a, "Perso", 3, &files_of(&created_a.backups[2]), &ok).unwrap();
        assert_eq!(shares_on(&old), vec![info(&kit_a, 3, "")]);
        assert!(part_dir(&legacy, 3).join(INFO_FILE).exists());
        // Then a named backup next to it: the root LISEZ-MOI keeps the description of the
        // legacy share, after the general text.
        write_share_at(&old, u64::MAX, &kit_b, "Pro", 1, &files_of(&created_b.backups[0]), &ok).unwrap();
        assert_eq!(shares_on(&old), vec![info(&kit_a, 3, ""), info(&kit_b, 1, "Pro")]);
        let root_readme = std::fs::read_to_string(legacy.join(README_FILE)).unwrap();
        assert!(root_readme.starts_with("SAUVEGARDES OPENPGP WALLET") && root_readme.contains("PART N°3 SUR 3"), "{root_readme}");
        let pro_readme = std::fs::read_to_string(legacy.join(kit_folder("Pro", &kit_b, false)).join(README_FILE)).unwrap();
        assert!(pro_readme.contains("« Pro » — PART N°1"), "{pro_readme}");
        // A folder with the same name already present (same start of identifier): never
        // reused, the full identifier tells them apart.
        let clash = base.join("collision");
        let taken = clash.join(BACKUP_DIR).join(kit_folder("Perso", &kit_a, false));
        std::fs::create_dir_all(&taken).unwrap();
        std::fs::write(taken.join("autre.txt"), "à garder").unwrap();
        write_share_at(&clash, u64::MAX, &kit_a, "Perso", 1, &files_of(&created_a.backups[0]), &ok).unwrap();
        assert!(clash.join(BACKUP_DIR).join(kit_folder("Perso", &kit_a, true)).join("part-1").join(INFO_FILE).exists());
        assert_eq!(std::fs::read_dir(&taken).unwrap().count(), 1, "dossier existant intact");
        // A backup named "part" is not confused with the legacy layout.
        write_share_at(&clash, u64::MAX, &kit_b, "part", 2, &files_of(&created_b.backups[1]), &ok).unwrap();
        assert!(shares_on(&clash).contains(&info(&kit_b, 2, "part")));
        // Invalid name or full drive: refused before anything is written.
        assert!(write_share_at(&base.join("vide"), u64::MAX, &kit_a, "../x", 1, &files_of(&created_a.backups[0]), &ok).is_err());
        assert!(write_share_at(&base.join("pleine"), 1024, &kit_a, "Perso", 1, &files_of(&created_a.backups[0]), &ok).is_err());
        assert!(!base.join("vide").join(BACKUP_DIR).exists() && !base.join("pleine").join(BACKUP_DIR).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Nothing unverifiable stays on the drive: verification fails on share 2 → shares
    /// 2 and 3 removed, share 1 (verified) kept and the LISEZ-MOI updated; interrupted
    /// write → the call's shares removed, and the folder of a backup with no shares
    /// disappears; the other wallet intact.
    #[test]
    fn failed_writes_leave_nothing_unverified() {
        let base = temp_root("failed");
        let root = base.join("cle");
        let created = crate::api::create_wallet(&base.join("a"), "un mot de passe de test bien assez long").unwrap();
        let other = crate::api::create_wallet(&base.join("b"), "un autre mot de passe de test assez long").unwrap();
        let (kit, kit_other) = (crate::api::backup_kit_id(&created.backups), crate::api::backup_kit_id(&other.backups));
        write_share_at(&root, u64::MAX, &kit_other, "Pro", 1, &files_of(&other.backups[0]), &|_: &ShareFiles| Ok(())).unwrap();
        let parts: Vec<(u8, ShareFiles)> = created.backups.iter().enumerate().map(|(i, b)| (i as u8 + 1, files_of(b))).collect();
        let second = created.backups[1].encrypted_share.clone();
        let fails_on_2 = |files: &ShareFiles| if files.encrypted_share == second { bail!("ne se déchiffre pas") } else { Ok(()) };
        assert!(write_kit_at(&root, u64::MAX, &kit, "Coffre", &parts, &fails_on_2).is_err());
        assert_eq!(shares_on(&root), vec![info(&kit, 1, "Coffre"), info(&kit_other, 1, "Pro")]);
        let kit_dir = root.join(BACKUP_DIR).join(kit_folder("Coffre", &kit, false));
        assert!(!part_dir(&kit_dir, 2).exists() && !part_dir(&kit_dir, 3).exists());
        let text = std::fs::read_to_string(kit_dir.join(README_FILE)).unwrap();
        assert!(text.contains("PART N°1 SUR 3"), "{text}");
        // Interrupted write: "part-2" is a file, so the folder cannot be created; the
        // rewritten share 1 (not verified) is removed too.
        std::fs::write(part_dir(&kit_dir, 2), "obstacle").unwrap();
        assert!(write_kit_at(&root, u64::MAX, &kit, "Coffre", &parts, &|_: &ShareFiles| Ok(())).is_err());
        assert_eq!(shares_on(&root), vec![info(&kit_other, 1, "Pro")]);
        assert!(!part_dir(&kit_dir, 1).join(PASSWORD_FILE).exists() && !kit_dir.join(README_FILE).exists());
        std::fs::remove_file(part_dir(&kit_dir, 2)).unwrap();
        // Everything fails from the first share: the named folder disappears.
        assert!(write_kit_at(&root, u64::MAX, &kit, "Coffre", &parts, &|_: &ShareFiles| -> Result<()> { bail!("non") }).is_err());
        assert!(!kit_dir.exists(), "dossier de sauvegarde vide retiré");
        assert_eq!(shares_on(&root), vec![info(&kit_other, 1, "Pro")]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Drives written by previous versions: the original layout
    /// (`PGP-Wallet-Sauvegarde/part-N/`, format 1, unnamed) and the named layout
    /// (format 2), written here with LITERAL paths and content (not with the current
    /// writing code), from the frozen kit (`testdata/backup_kit_v1.json`): recognized,
    /// reread identically, and one share from each layout restores the wallet to the
    /// same addresses. A failure would mean that drives people already made could no
    /// longer be read.
    #[test]
    fn drives_written_by_earlier_versions_still_restore() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/backup_kit_v1.json")).unwrap();
        let kit_json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let backups: Vec<crate::api::BackupShare> = kit_json["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| crate::api::BackupShare {
                label: p["label"].as_str().unwrap().into(),
                passphrase: p["passphrase"].as_str().unwrap().into(),
                encrypted_share: hex::decode(p["encrypted_share_hex"].as_str().unwrap()).unwrap(),
                privkey_armored: p["privkey_armored"].as_str().unwrap().as_bytes().to_vec(),
            })
            .collect();
        let kit = crate::api::backup_kit_id(&backups);
        let base = temp_root("earlier");
        let write_part_literally = |dir: PathBuf, backup: &crate::api::BackupShare, info: String| {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("part.asc"), &backup.encrypted_share).unwrap();
            std::fs::write(dir.join("cle-privee.asc"), &backup.privkey_armored).unwrap();
            std::fs::write(dir.join("mot-de-passe.txt"), &backup.passphrase).unwrap();
            std::fs::write(dir.join("sauvegarde.json"), info).unwrap();
        };
        let v1 = base.join("v1");
        for (i, backup) in backups.iter().enumerate().take(2) {
            let part = i + 1;
            write_part_literally(v1.join(format!("PGP-Wallet-Sauvegarde/part-{part}")), backup, format!("{{\n  \"format\": 1,\n  \"kit\": \"{kit}\",\n  \"part\": {part}\n}}"));
        }
        let v2 = base.join("v2");
        write_part_literally(
            v2.join(format!("PGP-Wallet-Sauvegarde/Coffre-familial-{}/part-3", &kit[..6])),
            &backups[2],
            format!("{{\n  \"format\": 2,\n  \"kit\": \"{kit}\",\n  \"part\": 3,\n  \"name\": \"Coffre familial\"\n}}"),
        );
        assert_eq!(shares_on(&v1), vec![info(&kit, 1, ""), info(&kit, 2, "")]);
        assert_eq!(shares_on(&v2), vec![info(&kit, 3, "Coffre familial")]);
        let (_, first) = read_share_at(&v1, &kit, 1).unwrap();
        let (_, third) = read_share_at(&v2, &kit, 3).unwrap();
        for (files, backup) in [(&first, &backups[0]), (&third, &backups[2])] {
            assert_eq!(files.encrypted_share, backup.encrypted_share);
            assert_eq!(files.privkey_armored, backup.privkey_armored);
            assert_eq!(files.passphrase.as_str(), backup.passphrase);
        }
        let restored = crate::api::restore_wallet(
            &base.join("appareil"),
            "un nouveau mot de passe bien assez long",
            (&first.encrypted_share, &first.privkey_armored, &first.passphrase),
            (&third.encrypted_share, &third.privkey_armored, &third.passphrase),
        )
        .expect("restauration depuis une clé v1 et une clé v2");
        assert_eq!(Some(restored.evm.as_str()), kit_json["addresses"]["evm"].as_str());
        assert_eq!(Some(restored.btc_mainnet.as_str()), kit_json["addresses"]["btc_mainnet"].as_str());
        assert_eq!(Some(restored.solana.as_str()), kit_json["addresses"]["solana"].as_str());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Checking a drive: intact shares recognized; a share that no longer decrypts, a
    /// missing file, a damaged `sauvegarde.json` (share invisible to
    /// restore-from-drive): each one reported, nothing written.
    #[test]
    fn drive_check_reports_damaged_shares_without_writing() {
        let base = temp_root("check");
        let data = base.join("data");
        let root = base.join("cle");
        let created = crate::api::create_wallet(&data, "un mot de passe de test bien assez long").unwrap();
        let kit = crate::api::backup_kit_id(&created.backups);
        let verify = |files: &ShareFiles| crate::api::verify_backup_share(&data, &files.encrypted_share, &files.privkey_armored, &files.passphrase);
        let parts: Vec<(u8, ShareFiles)> = created.backups.iter().enumerate().map(|(i, b)| (i as u8 + 1, files_of(b))).collect();
        write_kit_at(&root, u64::MAX, &kit, "Coffre", &parts, &verify).unwrap();
        let ok = |part| ShareCheck { kit: kit.clone(), part, name: "Coffre".into(), problem: None };
        assert_eq!(check_drive_at(&root, &verify), vec![ok(1), ok(2), ok(3)]);
        let kit_dir = root.join(BACKUP_DIR).join(kit_folder("Coffre", &kit, false));
        let snapshot = |root: &Path| {
            let mut all: Vec<(PathBuf, Vec<u8>)> = Vec::new();
            for dir in kit_dirs(root) {
                for part in 1..=3 {
                    for entry in std::fs::read_dir(part_dir(&dir, part)).into_iter().flatten().flatten() {
                        all.push((entry.path(), std::fs::read(entry.path()).unwrap_or_default()));
                    }
                }
            }
            all.sort();
            all
        };
        // Share 2: one byte of the encrypted content changed.
        let share_path = part_dir(&kit_dir, 2).join(SHARE_FILE);
        let mut share = std::fs::read(&share_path).unwrap();
        let at = share.len() - 5;
        share[at] ^= 0x10;
        std::fs::write(&share_path, share).unwrap();
        // Share 3: private key gone; share 1: damaged sauvegarde.json.
        std::fs::remove_file(part_dir(&kit_dir, 3).join(KEY_FILE)).unwrap();
        std::fs::write(part_dir(&kit_dir, 1).join(INFO_FILE), "{\"format\": 2, \"kit\": \"ab").unwrap();
        let before = snapshot(&root);
        let checks = check_drive_at(&root, &verify);
        assert_eq!(snapshot(&root), before, "la vérification n'écrit rien");
        assert_eq!(
            checks,
            vec![
                ShareCheck { problem: Some(PROBLEM_DECRYPT), ..ok(2) },
                ShareCheck { problem: Some(PROBLEM_UNREADABLE), ..ok(3) },
                ShareCheck { kit: String::new(), part: 1, name: kit_folder("Coffre", &kit, false), problem: Some(PROBLEM_UNRECOGNIZED) },
            ]
        );
        // Drive with no backup: nothing to report.
        assert!(check_drive_at(&base.join("vide"), &verify).is_empty());
        assert!(check_drive("C:\\", verify).is_err(), "disque système refusé");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A destination that is not a detected USB drive is refused (the system disk, an
    /// arbitrary folder), and so are invalid parameters.
    #[test]
    fn only_detected_usb_drives_are_accepted() {
        let files = || ShareFiles { encrypted_share: vec![1], privkey_armored: vec![2], passphrase: Zeroizing::new("x".into()) };
        let ok = |_: &ShareFiles| Ok(());
        assert!(write_share("C:\\", "ab12", "Perso", 1, &files(), ok).is_err(), "disque système");
        assert!(write_share(&std::env::temp_dir().to_string_lossy(), "ab12", "Perso", 1, &files(), ok).is_err());
        assert!(write_share("C:\\", "ab12", "Perso", 4, &files(), ok).is_err(), "part invalide");
        assert!(write_share("C:\\", "../x", "Perso", 1, &files(), ok).is_err(), "kit invalide");
        assert!(write_kit("C:\\", "ab12", "Perso", &[(1, files()), (2, files())], ok).is_err(), "disque système");
        assert!(write_kit("C:\\", "ab12", "Perso", &[(7, files())], ok).is_err(), "part invalide");
        assert!(read_share("C:\\", "ab12", 1).is_err());
    }
}
