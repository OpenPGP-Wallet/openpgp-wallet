//! API non-interactive du "worker" crypto, pensée pour être appelée depuis une
//! interface graphique (Tauri) plutôt qu'un terminal : aucune fonction ici ne lit
//! stdin ni n'imprime sur stdout, tout passe par des paramètres et des valeurs de
//! retour. `wallet_flow.rs` reste la version CLI interactive (prompts) pour les
//! démos en ligne de commande ; ce module réutilise les mêmes briques (derivation,
//! shamir, pgp_engine, eth/btc/sol_tx/rpc) sans jamais imprimer ni lire de secret.
//!
//! Modèle retenu :
//! - Un "coffre local" par appareil : l'entropie maître complète, chiffrée par une
//!   clé PGP dédiée à CET appareil, déverrouillée par un seul mot de passe — usage
//!   quotidien façon hot wallet.
//! - Un "kit de sauvegarde" Shamir 2-sur-3, généré une seule fois à la création,
//!   qui ne sert qu'à restaurer le wallet sur un NOUVEL appareil si celui-ci est
//!   perdu — jamais utilisé pour le déverrouillage quotidien.

use crate::{btc_rpc, derivation, entropy, eth_rpc, eth_tx, memory_guard, pgp_engine, shamir, sol_rpc, sol_tx, wallet_flow};
use anyhow::{Context, Result};
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DEVICE_PUBKEY_FILE: &str = "device_pubkey.asc";
const DEVICE_PRIVKEY_FILE: &str = "device_privkey.asc";
const DEVICE_VAULT_FILE: &str = "device_vault.asc";
const BACKUP_IDENTITIES: [&str; 3] = ["backup_a", "backup_b", "backup_c"];

const UNLOCK_ATTEMPTS_FILE: &str = "unlock_attempts.json";
/// Nombre d'échecs consécutifs tolérés avant qu'un délai commence à s'appliquer.
const MAX_FREE_ATTEMPTS: u32 = 5;
/// Délai de base (secondes), doublé à chaque échec supplémentaire au-delà de
/// `MAX_FREE_ATTEMPTS`, plafonné à `MAX_LOCKOUT_SECS`.
const BASE_LOCKOUT_SECS: u64 = 5;
const MAX_LOCKOUT_SECS: u64 = 300;

/// Compteur d'échecs de déverrouillage, persisté à côté du coffre : sans lui, rien
/// n'empêchait un script capable d'appeler `unlock_wallet`/`send_*` en boucle
/// (devtools, dépendance compromise) d'essayer des mots de passe indéfiniment et
/// aussi vite que le CPU le permet — la complexité minimale de 12 caractères imposée
/// à la création ne protège que contre un essai manuel, pas contre un script.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct UnlockAttempts {
    consecutive_failures: u32,
    last_failure_unix: u64,
}

fn unlock_attempts_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(UNLOCK_ATTEMPTS_FILE)
}

fn read_unlock_attempts(data_dir: &Path) -> UnlockAttempts {
    std::fs::read_to_string(unlock_attempts_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_unlock_attempts(data_dir: &Path, attempts: &UnlockAttempts) {
    if let Ok(s) = serde_json::to_string(attempts) {
        let _ = std::fs::write(unlock_attempts_path(data_dir), s);
    }
}

fn required_lockout_secs(consecutive_failures: u32) -> u64 {
    if consecutive_failures < MAX_FREE_ATTEMPTS {
        return 0;
    }
    let extra = (consecutive_failures - MAX_FREE_ATTEMPTS).min(6); // évite un décalage démesuré
    BASE_LOCKOUT_SECS.saturating_mul(1u64 << extra).min(MAX_LOCKOUT_SECS)
}

/// À appeler avant toute tentative de déchiffrement du coffre avec un mot de passe
/// fourni par l'appelant. Renvoie une erreur si l'appareil est actuellement "en
/// attente" suite à trop d'échecs récents.
fn enforce_unlock_lockout(data_dir: &Path) -> Result<()> {
    let attempts = read_unlock_attempts(data_dir);
    let delay = required_lockout_secs(attempts.consecutive_failures);
    if delay == 0 {
        return Ok(());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let elapsed = now.saturating_sub(attempts.last_failure_unix);
    anyhow::ensure!(
        elapsed >= delay,
        "trop de tentatives incorrectes récentes ; réessayez dans {} seconde(s)",
        delay - elapsed
    );
    Ok(())
}

fn record_unlock_failure(data_dir: &Path) {
    let mut attempts = read_unlock_attempts(data_dir);
    attempts.consecutive_failures = attempts.consecutive_failures.saturating_add(1);
    attempts.last_failure_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    write_unlock_attempts(data_dir, &attempts);
}

fn reset_unlock_attempts(data_dir: &Path) {
    let _ = std::fs::remove_file(unlock_attempts_path(data_dir));
}

pub struct Addresses {
    pub evm: String,
    pub btc_testnet: String,
    /// Distincte de `btc_testnet` pour le même profil (chemin de dérivation et
    /// préfixe bech32 différents, voir `derivation.rs`) — contrairement à `evm`/
    /// `solana`, qui servent inchangées sur toutes les variantes de leur réseau.
    pub btc_mainnet: String,
    pub solana: String,
}

const PROFILES_FILE: &str = "profiles.json";
const DEFAULT_PROFILE_LABEL: &str = "Principal";

/// Un "profil" n'est qu'un index de dérivation HD (BIP32/SLIP-10) étiqueté : la
/// sécurité (Shamir 2-sur-3 + PGP) protège une seule entropie maître, comme avant.
/// `derive_evm_key`/`derive_btc_testnet_key`/`derive_solana_key` acceptent déjà un
/// index depuis le début (voir `core/src/derivation.rs`) — plusieurs adresses par
/// réseau ne demandent donc aucun changement du modèle de sécurité, seulement de
/// n'plus toujours dériver l'index 0. Le fichier `profiles.json` (labels + index)
/// n'a rien de sensible : sans lui, les mêmes adresses restent dérivables à partir
/// de la seed, seuls les libellés choisis par l'utilisateur seraient perdus.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    pub index: u32,
    pub label: String,
    /// Un profil archivé n'apparaît plus dans le sélecteur principal ni dans les
    /// adresses dérivées par `unlock_wallet`, mais reste dans `profiles.json` et
    /// peut être désarchivé à tout moment (voir `archive_profile`/`unarchive_profile`)
    /// — c'est la suppression "légère", réversible, sans mot de passe : contrairement
    /// à `delete_profile`, rien n'est perdu de façon irréversible. `#[serde(default)]`
    /// pour rester compatible avec un `profiles.json` écrit avant l'ajout de ce champ.
    #[serde(default)]
    pub archived: bool,
}

pub struct ProfileAddresses {
    pub profile: Profile,
    /// `None` quand le profil a été créé sans mot de passe (voir `create_profile`) :
    /// dériver une adresse suppose de redéchiffrer la seed, jamais mise en cache —
    /// sans mot de passe, on enregistre juste le label/index, et l'adresse
    /// apparaîtra au prochain `unlock_wallet` (qui dérive tous les profils connus
    /// pendant qu'il a déjà la seed en main).
    pub addresses: Option<Addresses>,
}

fn profiles_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PROFILES_FILE)
}

/// Compatibilité ascendante : un coffre créé avant l'introduction des profils n'a
/// pas de `profiles.json` — on lui suppose alors un unique profil par défaut à
/// l'index 0 (celui déjà utilisé partout jusqu'ici), pour ne perdre l'accès à rien.
fn load_profiles(data_dir: &Path) -> Vec<Profile> {
    std::fs::read_to_string(profiles_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<Profile>>(&s).ok())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            vec![Profile {
                index: 0,
                label: DEFAULT_PROFILE_LABEL.to_string(),
                archived: false,
            }]
        })
}

fn save_profiles(data_dir: &Path, profiles: &[Profile]) -> Result<()> {
    let content = serde_json::to_string_pretty(profiles).context("sérialisation des profils")?;
    std::fs::write(profiles_path(data_dir), content).context("écriture des profils")
}

/// Une part de sauvegarde Shamir, chiffrée par sa propre identité PGP jetable.
/// À exporter par l'utilisateur (fichiers + passphrase) hors de l'appareil.
pub struct BackupShare {
    pub label: String,
    pub passphrase: String,
    pub encrypted_share: Vec<u8>,
    pub privkey_armored: Vec<u8>,
}

pub struct CreateWalletResult {
    pub addresses: Addresses,
    pub backups: Vec<BackupShare>,
}

fn generate_pgp_identity(label: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(format!("{label} <{label}@pgp-wallet-poc.local>"))
        .add_transport_encryption_subkey()
        .set_password(Some(Password::from(passphrase)))
        .generate()
        .with_context(|| format!("génération de la clé PGP '{label}' impossible"))?;

    let mut pubkey_armored = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut pubkey_armored, armor::Kind::PublicKey)?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }

    let mut privkey_armored = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut privkey_armored, armor::Kind::SecretKey)?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }

    Ok((pubkey_armored, privkey_armored))
}

/// Passphrase générée automatiquement pour un backup (jamais tapée par l'utilisateur,
/// juste affichée une fois pour être sauvegardée hors ligne).
fn random_passphrase() -> String {
    let bytes = entropy::generate_master_entropy();
    hex::encode(&bytes[..16])
}

fn derive_addresses(seed: &[u8], index: u32) -> Result<Addresses> {
    let (_evm_key, evm_address) = derivation::derive_evm_key(seed, index)?;
    let (_btc_testnet_key, btc_testnet_hash160) = derivation::derive_btc_testnet_key(seed, index)?;
    let (_btc_mainnet_key, btc_mainnet_hash160) = derivation::derive_btc_mainnet_key(seed, index)?;
    let sol_key = derivation::derive_solana_key(seed, index);
    Ok(Addresses {
        evm: derivation::format_address(&evm_address),
        btc_testnet: derivation::format_btc_testnet_address(&btc_testnet_hash160)?,
        btc_mainnet: derivation::format_btc_mainnet_address(&btc_mainnet_hash160)?,
        solana: bs58::encode(sol_key.verifying_key().to_bytes()).into_string(),
    })
}

/// Liste des profils ACTIFS de cet appareil (labels + index de dérivation), sans
/// jamais toucher au coffre ni au mot de passe : purement de la lecture de fichier.
/// N'inclut pas les profils archivés (voir `archive_profile`) : ils n'apparaissent
/// ni dans le sélecteur principal ni dans les adresses dérivées par `unlock_wallet`.
pub fn list_profiles(data_dir: &Path) -> Vec<Profile> {
    load_profiles(data_dir).into_iter().filter(|p| !p.archived).collect()
}

/// Liste des profils archivés (voir `archive_profile`) : mis de côté sans être
/// supprimés, récupérables à tout moment via `unarchive_profile`.
pub fn list_archived_profiles(data_dir: &Path) -> Vec<Profile> {
    load_profiles(data_dir).into_iter().filter(|p| p.archived).collect()
}

/// Suppression "légère" et réversible : le profil disparaît du sélecteur principal
/// et des adresses dérivées à chaque déverrouillage, mais reste dans
/// `profiles.json` et peut être remis en service à tout moment via
/// `unarchive_profile`, sans mot de passe — rien n'est irréversible, donc rien
/// n'exige de confirmation lourde ici (contrairement à `delete_profile`).
pub fn archive_profile(data_dir: &Path, index: u32) -> Result<()> {
    let mut profiles = load_profiles(data_dir);
    anyhow::ensure!(
        profiles.iter().filter(|p| !p.archived).count() > 1,
        "impossible d'archiver le dernier profil actif restant"
    );
    let profile = profiles
        .iter_mut()
        .find(|p| p.index == index && !p.archived)
        .ok_or_else(|| anyhow::anyhow!("profil actif introuvable (index {index})"))?;
    profile.archived = true;
    save_profiles(data_dir, &profiles)
}

/// Annule un archivage (voir `archive_profile`) : le profil redevient actif,
/// réapparaît dans le sélecteur principal et dans les adresses dérivées au
/// prochain déverrouillage.
pub fn unarchive_profile(data_dir: &Path, index: u32) -> Result<()> {
    let mut profiles = load_profiles(data_dir);
    let profile = profiles
        .iter_mut()
        .find(|p| p.index == index && p.archived)
        .ok_or_else(|| anyhow::anyhow!("profil archivé introuvable (index {index})"))?;
    profile.archived = false;
    save_profiles(data_dir, &profiles)
}

/// Retire un profil de la liste (label + index).
///
/// Exige le mot de passe de l'appareil (vérifié via `unlock_seed`, seed aussitôt
/// rejetée sans être utilisée) : pas parce que la suppression elle-même touche à la
/// seed, mais comme confirmation à part entière avant une action dont la
/// conséquence pratique peut être sérieuse (voir ci-dessous), et pour profiter au
/// passage du même verrou anti-brute-force que les autres actions sensibles.
///
/// Important, à ne pas enjoliver : cryptographiquement, l'adresse reste dérivable
/// depuis la même seed au même index (rien n'est détruit "en théorie"). Mais cette
/// application n'offre **aucun moyen de recréer un profil à un index précis** —
/// `create_profile` choisit toujours le prochain index libre, jamais un index déjà
/// utilisé puis supprimé. Concrètement, pour l'utilisateur de cette app (pas un
/// développeur capable de re-dériver l'index à la main), supprimer un profil qui a
/// déjà reçu des fonds revient à en perdre l'accès de façon définitive depuis cette
/// interface. D'où l'exigence du mot de passe : ce n'est pas une simple opération
/// de confort sur une liste de labels.
///
/// Toujours au moins un profil restant : sans coffre par défaut affichable,
/// l'utilisateur n'aurait plus aucune adresse visible après un déverrouillage.
pub fn delete_profile(data_dir: &Path, device_password: &str, index: u32) -> Result<()> {
    // Seed jetée sans être utilisée : on ne veut que vérifier le mot de passe.
    // `Zeroizing` l'efface automatiquement à la fin de cette expression, pas besoin
    // d'appel manuel (voir les rounds d'audit précédents sur ce sujet).
    let _ = unlock_seed(data_dir, device_password)?;

    let mut profiles = load_profiles(data_dir);
    let before = profiles.len();
    profiles.retain(|p| p.index != index);
    anyhow::ensure!(profiles.len() < before, "profil introuvable (index {index})");
    // Vérifié APRÈS la suppression, sur les profils ACTIFS uniquement : sans ça,
    // supprimer le seul profil actif restant aurait pu passer tant qu'un profil
    // archivé traînait encore dans le fichier (le compte total > 1 suffisait), en
    // laissant le tableau de bord sans aucune adresse à afficher après déverrouillage.
    anyhow::ensure!(
        profiles.iter().any(|p| !p.archived),
        "impossible de supprimer le dernier profil actif restant"
    );
    save_profiles(data_dir, &profiles)
}

/// Découpe `secret` en un nouveau kit Shamir 2-sur-3 (3 nouvelles identités PGP
/// jetables, 3 nouvelles passphrases aléatoires — jamais réutilisées d'un appel à
/// l'autre) chiffrant chacune une part. Partagé entre `create_wallet` (kit initial)
/// et `regenerate_backup_kit` (recréer un kit si l'utilisateur a perdu ses fichiers) :
/// avoir plusieurs kits Shamir valides simultanément pour le même secret ne pose
/// aucun problème (ce sont juste des découpages différents du même secret), donc un
/// ancien kit non révoqué reste valable — ce n'est pas un souci de sécurité, juste
/// un doublon inoffensif si l'utilisateur en génère plusieurs.
fn generate_backup_kit(data_dir: &Path, secret: &[u8]) -> Result<Vec<BackupShare>> {
    let shares: Vec<Zeroizing<Vec<u8>>> = shamir::split_secret(secret, 2, 3)?
        .into_iter()
        .map(Zeroizing::new)
        .collect();
    let mut backups = Vec::with_capacity(3);
    for (i, share) in shares.iter().enumerate() {
        let label = BACKUP_IDENTITIES[i].to_string();
        let passphrase = random_passphrase();
        let (pubkey_armored, privkey_armored) = generate_pgp_identity(&label, &passphrase)?;
        let encrypted_share =
            encrypt_with_armored_pubkey(share, &data_dir.join(format!("tmp_{label}_pub.asc")), &pubkey_armored)?;
        backups.push(BackupShare {
            label,
            passphrase,
            encrypted_share,
            privkey_armored,
        });
    }
    Ok(backups)
}

/// Régénère un kit de sauvegarde Shamir 2-sur-3 tout neuf (3 nouvelles identités PGP,
/// 3 nouvelles passphrases) à partir de l'entropie maître actuelle, sans toucher au
/// coffre local ni au mot de passe de l'appareil. Utile si l'utilisateur a perdu un
/// ou plusieurs de ses fichiers de sauvegarde d'origine : jusqu'ici, la seule façon
/// de revoir un kit de sauvegarde était de tout recréer via `reset_wallet` +
/// `create_wallet`, ce qui change aussi l'entropie maître (donc les adresses).
pub fn regenerate_backup_kit(data_dir: &Path, device_password: &str) -> Result<Vec<BackupShare>> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    generate_backup_kit(data_dir, &seed)
}

/// Ajoute un nouveau profil (nouvel index de dérivation, jamais réutilisé).
///
/// Le mot de passe est optionnel : le fournir dérive et renvoie tout de suite
/// l'adresse du nouveau profil (redéchiffre la seed, jamais mise en cache — même
/// principe que pour un envoi de fonds, voir `unlock_seed`) ; l'omettre se contente
/// d'enregistrer le label/index sans toucher au coffre ni demander le mot de passe.
/// Dans ce second cas, `addresses` vaut `None` : l'adresse apparaîtra d'elle-même au
/// prochain `unlock_wallet`, qui dérive tous les profils connus pendant qu'il a déjà
/// la seed en main pour cet appel.
/// Plafond arbitraire mais généreux (aucun usage réel n'en approche) : sans lui, le
/// chemin sans mot de passe de `create_profile` ne demande AUCUNE authentification —
/// un script capable d'invoquer directement la commande Tauri pourrait sinon faire
/// grossir `profiles.json` sans limite. Conséquence concrète : `unlock_wallet` dérive
/// les adresses de TOUS les profils connus à chaque déverrouillage (voir sa doc) ;
/// des dizaines de milliers de profils bidons ralentiraient (voire, à l'extrême,
/// bloqueraient perceptiblement) le déverrouillage légitime du vrai propriétaire.
const MAX_PROFILES: usize = 50;

pub fn create_profile(data_dir: &Path, device_password: Option<&str>, label: &str) -> Result<ProfileAddresses> {
    let mut profiles = load_profiles(data_dir);
    anyhow::ensure!(
        profiles.len() < MAX_PROFILES,
        "nombre maximal de profils atteint ({MAX_PROFILES}) sur cet appareil"
    );
    let next_index = profiles.iter().map(|p| p.index).max().map_or(0, |m| m + 1);
    let profile = Profile {
        index: next_index,
        label: label.to_string(),
        archived: false,
    };

    let addresses = match device_password {
        Some(password) => {
            let seed = unlock_seed(data_dir, password)?;
            let _seed_lock = memory_guard::lock(&seed);
            Some(derive_addresses(&seed, profile.index)?)
        }
        None => None,
    };

    profiles.push(profile.clone());
    save_profiles(data_dir, &profiles)?;

    Ok(ProfileAddresses { profile, addresses })
}

/// Garantit la suppression du fichier temporaire même si l'opération panique
/// (le `Drop` s'exécute pendant le unwinding) — sans ce guard, un panic entre
/// l'écriture et la suppression manuelle laisserait le fichier sur le disque,
/// ce qui est particulièrement sensible pour `decrypt_with_armored_privkey`
/// (le fichier contient alors une clé privée en clair, quoique protégée par
/// PGP elle-même).
struct TempFileGuard<'a>(&'a Path);

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// Encrypt_share exige un chemin de fichier pour la clé publique : petit fichier
/// temporaire écrit puis lu immédiatement, aucun secret dedans (clé publique only).
fn encrypt_with_armored_pubkey(data: &[u8], tmp_path: &Path, pubkey_armored: &[u8]) -> Result<Vec<u8>> {
    std::fs::write(tmp_path, pubkey_armored)?;
    let _guard = TempFileGuard(tmp_path);
    pgp_engine::encrypt_share(data, &tmp_path.to_string_lossy())
}

fn decrypt_with_armored_privkey(data: &[u8], tmp_path: &Path, privkey_armored: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    std::fs::write(tmp_path, privkey_armored)?;
    let _guard = TempFileGuard(tmp_path);
    pgp_engine::decrypt_share(data, &tmp_path.to_string_lossy(), passphrase)
}

/// Crée un nouveau wallet dans `data_dir` : coffre local (mot de passe de l'appareil)
/// + kit de sauvegarde Shamir 2-sur-3 (3 parts, chacune avec sa propre passphrase
/// générée automatiquement). Ne journalise et ne retourne jamais l'entropie elle-même.
pub fn create_wallet(data_dir: &Path, device_password: &str) -> Result<CreateWalletResult> {
    // Sans ce garde-fou, appeler `create_wallet` une seconde fois sur un appareil qui
    // a déjà un coffre écraserait silencieusement `device_vault.asc`/`device_privkey.asc`
    // avec une entropie maître totalement différente — aucune fonction appelante ne
    // vérifiait cette invariant côté Rust, seul le frontend s'en chargeait (en
    // n'affichant l'écran d'onboarding que si `wallet_exists` renvoie faux). Un script
    // capable d'invoquer directement la commande Tauri (devtools, dépendance
    // compromise) aurait pu déclencher ce remplacement sans confirmation. La bonne
    // façon de "repartir de zéro" passe explicitement par `reset_wallet` d'abord.
    anyhow::ensure!(
        !device_vault_exists(data_dir),
        "un coffre existe déjà sur cet appareil ; réinitialisez-le d'abord (reset_wallet) si vous voulez repartir de zéro"
    );
    std::fs::create_dir_all(data_dir)?;

    let master_entropy = Zeroizing::new(entropy::generate_master_entropy());
    let _entropy_lock = memory_guard::lock(&master_entropy);
    let default_profile = Profile {
        index: 0,
        label: DEFAULT_PROFILE_LABEL.to_string(),
        archived: false,
    };
    let addresses = derive_addresses(&master_entropy, default_profile.index)?;
    save_profiles(data_dir, std::slice::from_ref(&default_profile))?;

    // 1. Coffre local de l'appareil.
    let (device_pub, device_priv) = generate_pgp_identity("device", device_password)?;
    std::fs::write(data_dir.join(DEVICE_PUBKEY_FILE), &device_pub)?;
    std::fs::write(data_dir.join(DEVICE_PRIVKEY_FILE), &device_priv)?;
    let vault = encrypt_with_armored_pubkey(&master_entropy, &data_dir.join("tmp_device_pub.asc"), &device_pub)?;
    std::fs::write(data_dir.join(DEVICE_VAULT_FILE), &vault)?;
    // Un compteur d'échecs résiduel (ex: fichier laissé par un `reset_wallet` qui
    // aurait échoué en partie, ou une manipulation manuelle des fichiers) ne doit
    // jamais faire naître un coffre tout juste créé déjà "en attente".
    reset_unlock_attempts(data_dir);

    // 2. Kit de sauvegarde Shamir 2-sur-3 (indépendant du coffre local). Chaque part
    //    est enveloppée dans `Zeroizing` à l'intérieur de `generate_backup_kit` : 2
    //    d'entre elles suffisent à reconstruire la clé maîtresse, donc aussi
    //    sensibles qu'elle et à effacer de la même façon.
    let backups = generate_backup_kit(data_dir, &master_entropy)?;

    // `master_entropy` est effacée automatiquement à la fin de la fonction (Drop de
    // `Zeroizing`), y compris sur un retour anticipé via `?` ci-dessus — contrairement
    // à un `memory_guard::wipe` manuel en fin de fonction, qui serait sauté si une
    // opération précédente échoue.
    Ok(CreateWalletResult { addresses, backups })
}

/// Déverrouille le coffre local avec le mot de passe de l'appareil et retourne les
/// adresses publiques de TOUS les profils connus (jamais la clé privée ni
/// l'entropie) : la seed n'est jamais mise en cache entre deux appels (voir
/// `unlock_seed`), donc dériver tous les profils pendant qu'elle est déjà en
/// mémoire ici évite d'avoir à redemander le mot de passe juste pour changer de
/// profil affiché dans le tableau de bord.
pub fn unlock_wallet(data_dir: &Path, device_password: &str) -> Result<Vec<ProfileAddresses>> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    // Seuls les profils actifs : un profil archivé (voir `archive_profile`) ne doit
    // plus apparaître nulle part tant qu'il n'a pas été explicitement désarchivé.
    list_profiles(data_dir)
        .into_iter()
        .map(|profile| {
            let addresses = derive_addresses(&seed, profile.index)?;
            Ok(ProfileAddresses { profile, addresses: Some(addresses) })
        })
        .collect()
}

/// Restaure un wallet à partir de 2 parts de sauvegarde (peu importe lesquelles
/// parmi les 3) et recrée un coffre local sur CET appareil avec un nouveau mot de
/// passe. À utiliser quand l'appareil d'origine est perdu.
pub fn restore_wallet(
    data_dir: &Path,
    new_device_password: &str,
    backup_1: (&[u8], &[u8], &str),
    backup_2: (&[u8], &[u8], &str),
) -> Result<Addresses> {
    std::fs::create_dir_all(data_dir)?;

    // Chaque part déchiffrée est aussi sensible qu'une clé maîtresse partielle
    // (2 sur 3 suffisent à tout reconstruire) : même traitement `Zeroizing`.
    let mut decrypted_shares: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(2);
    for (i, (encrypted, privkey_armored, passphrase)) in [backup_1, backup_2].iter().enumerate() {
        let tmp_path = data_dir.join(format!("tmp_restore_{i}.asc"));
        let decrypted = decrypt_with_armored_privkey(encrypted, &tmp_path, privkey_armored, passphrase)
            .with_context(|| format!("échec du déchiffrement de la part de sauvegarde n°{}", i + 1))?;
        decrypted_shares.push(Zeroizing::new(decrypted));
    }

    let share_refs: Vec<&[u8]> = decrypted_shares.iter().map(|s| s.as_slice()).collect();
    let recovered = Zeroizing::new(shamir::reconstruct_secret(2, &share_refs)?);
    let _recovered_lock = memory_guard::lock(&recovered);
    let default_profile = Profile {
        index: 0,
        label: DEFAULT_PROFILE_LABEL.to_string(),
        archived: false,
    };
    let addresses = derive_addresses(&recovered, default_profile.index)?;
    // Toute étiquette de profil créée en plus du défaut sur l'ancien appareil est
    // perdue (elle n'est pas incluse dans la sauvegarde Shamir, qui ne protège que
    // l'entropie) : sans conséquence sur les fonds, les mêmes adresses restent
    // dérivables aux mêmes index depuis la seed retrouvée si l'utilisateur les
    // recrée avec les mêmes index.
    save_profiles(data_dir, std::slice::from_ref(&default_profile))?;

    let (device_pub, device_priv) = generate_pgp_identity("device", new_device_password)?;
    std::fs::write(data_dir.join(DEVICE_PUBKEY_FILE), &device_pub)?;
    std::fs::write(data_dir.join(DEVICE_PRIVKEY_FILE), &device_priv)?;
    let vault = encrypt_with_armored_pubkey(&recovered, &data_dir.join("tmp_device_pub.asc"), &device_pub)?;
    std::fs::write(data_dir.join(DEVICE_VAULT_FILE), &vault)?;
    // Prouver la possession de 2 parts de sauvegarde est une preuve d'identité bien
    // plus forte qu'un mot de passe ; un éventuel verrou anti-brute-force accumulé
    // sur l'ancien mot de passe (avant restauration) n'a plus de raison de s'appliquer
    // au nouveau coffre qui vient d'être créé avec un mot de passe différent.
    reset_unlock_attempts(data_dir);

    // `recovered` est effacée automatiquement à la fin de la fonction (Drop de
    // `Zeroizing`), même en cas de retour anticipé sur une des lignes `?` ci-dessus.
    Ok(addresses)
}

pub fn device_vault_exists(data_dir: &Path) -> bool {
    data_dir.join(DEVICE_VAULT_FILE).exists()
}

/// Lit la clé publique (certificat) de l'appareil, pour affichage/partage — utile
/// pour la section "chiffrer un message" (les autres peuvent l'ajouter comme
/// destinataire pour t'écrire) et l'onglet "Certificat" de l'app.
pub fn read_device_pubkey_armored(data_dir: &Path) -> Result<String> {
    std::fs::read_to_string(data_dir.join(DEVICE_PUBKEY_FILE)).context("lecture de la clé publique de l'appareil")
}

/// Déchiffre un message PGP arbitraire (section "Message" de l'app) reçu par cet
/// appareil, avec la clé privée du coffre local. Contrairement au coffre du
/// wallet, le contenu déchiffré ici est un texte quelconque destiné à être lu,
/// pas un secret à re-protéger — pas de `memory_guard::wipe` nécessaire.
///
/// Passe par `unlock_seed` (seed jetée sans être utilisée, même motif que
/// `delete_profile`) uniquement pour bénéficier de son verrou anti-brute-force :
/// la clé privée déchiffrée ici est protégée par exactement le même mot de passe
/// que le coffre du wallet, donc l'appeler directement sans cette barrière aurait
/// offert une deuxième porte, non limitée en tentatives, pour deviner CE mot de
/// passe — rendant inutile le verrou déjà en place sur `unlock_wallet`/`send_*`.
pub fn decrypt_incoming_message(data_dir: &Path, device_password: &str, ciphertext: &str) -> Result<String> {
    let _ = unlock_seed(data_dir, device_password)?;
    let privkey_path = data_dir.join(DEVICE_PRIVKEY_FILE);
    let plaintext = pgp_engine::decrypt_share(ciphertext.as_bytes(), &privkey_path.to_string_lossy(), device_password)?;
    String::from_utf8(plaintext).context("le message déchiffré n'est pas du texte UTF-8 valide")
}

/// Supprime le coffre local de cet appareil (utile pour retester l'onboarding, ou
/// pour un vrai "réinitialiser cet appareil"). Ne touche à rien d'autre : si
/// l'utilisateur a bien exporté ses 3 parts de sauvegarde à la création, le wallet
/// reste récupérable via `restore_wallet`. Aucune erreur si le coffre n'existait déjà pas.
pub fn reset_wallet(data_dir: &Path) -> Result<()> {
    for file in [DEVICE_PUBKEY_FILE, DEVICE_PRIVKEY_FILE, DEVICE_VAULT_FILE] {
        let path = data_dir.join(file);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("suppression de {file} impossible"))?;
        }
    }
    // Best-effort : un nouveau coffre doit repartir avec un compteur d'échecs vierge.
    reset_unlock_attempts(data_dir);
    Ok(())
}

/// Retourne la seed déverrouillée enveloppée dans `Zeroizing` : elle sera effacée
/// automatiquement à sa destruction, y compris si l'appelant retourne tôt via `?`
/// après l'avoir obtenue (contrairement à un `memory_guard::wipe` manuel, qui
/// serait sauté dans ce cas).
/// Sérialise tout le cycle lecture-tentative-écriture du compteur d'échecs par
/// processus. Sans lui, le compteur sur disque (lu, puis modifié, puis réécrit en
/// 3 étapes séparées dans `unlock_seed`) est vulnérable à une course : un script
/// invoquant `unlock_wallet`/`send_*` plusieurs fois EN PARALLÈLE verrait chaque
/// appel lire le même compteur avant qu'aucun n'ait eu le temps de l'incrémenter,
/// puis chacun réécrirait sa propre valeur en écrasant celle des autres — N mots de
/// passe testés simultanément ne compteraient alors que comme un seul échec,
/// vidant le verrou anti-brute-force de son effet. Protège contre un script qui
/// boucle depuis CETTE instance de l'app ; une seconde instance du programme lancée
/// en parallèle n'est pas couverte par un mutex en mémoire, mais c'est un scénario
/// bien plus contraint qu'une simple boucle `Promise.all` côté frontend.
static UNLOCK_MUTEX: Mutex<()> = Mutex::new(());

fn unlock_seed(data_dir: &Path, device_password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let _serialize = UNLOCK_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // Le verrou ne compte que les mauvais mots de passe, pas l'absence de coffre
    // (sinon interroger un appareil sans wallet créerait un compteur artificiel).
    let vault = std::fs::read(data_dir.join(DEVICE_VAULT_FILE)).context("coffre local introuvable")?;
    enforce_unlock_lockout(data_dir)?;
    let privkey_path = data_dir.join(DEVICE_PRIVKEY_FILE);
    match pgp_engine::decrypt_share(&vault, &privkey_path.to_string_lossy(), device_password) {
        Ok(seed) => {
            reset_unlock_attempts(data_dir);
            Ok(Zeroizing::new(seed))
        }
        Err(e) => {
            record_unlock_failure(data_dir);
            Err(e)
        }
    }
}

pub fn get_evm_balance(address: &str, network: &wallet_flow::EvmNetwork) -> Result<u128> {
    eth_rpc::EthRpc::new(network.rpc).balance(address)
}

pub fn get_btc_balance(address: &str, network: &wallet_flow::BtcNetwork) -> Result<u64> {
    let utxos = btc_rpc::EsploraClient::new(network.esplora_base).utxos(address)?;
    Ok(utxos.iter().map(|u| u.value_sat).sum())
}

pub fn get_sol_balance(address: &str, network: &wallet_flow::SolNetwork) -> Result<u64> {
    sol_rpc::SolRpc::new(network.rpc).balance_lamports(address)
}

/// `true` si une transaction touchant `address` n'a pas encore atteint sa finalité
/// (mempool Bitcoin, ou dernière signature Solana pas encore "finalized") — sert à
/// signaler "transaction détectée, en attente" côté UI avant que le solde ne bouge.
/// Aucun équivalent pour Ethereum : contrairement à Esplora et à
/// `getSignaturesForAddress` (une méthode JSON-RPC standard), aucun nœud EVM public
/// n'expose les transactions en attente pour une adresse donnée (même limite que
/// pour l'historique, voir `history::evm_history`).
pub fn has_pending_btc(address: &str, network: &wallet_flow::BtcNetwork) -> Result<bool> {
    btc_rpc::EsploraClient::new(network.esplora_base).has_mempool_tx(address)
}

pub fn has_pending_sol(address: &str, network: &wallet_flow::SolNetwork) -> Result<bool> {
    sol_rpc::SolRpc::new(network.rpc).has_unfinalized_tx(address)
}

/// Déverrouille le coffre (mot de passe requis : c'est la barrière d'authentification
/// avant toute dépense), signe et diffuse un virement EVM.
pub fn send_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    to: &str,
    amount_eth: &str,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;

    let to_bytes = wallet_flow::parse_evm_address(to)?;
    let value = wallet_flow::parse_eth_to_wei(amount_eth)?;

    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let address_str = derivation::format_address(&address);
    let nonce = rpc.nonce(&address_str)?;
    let gas_price = rpc.gas_price()?;
    let chain_id = rpc.chain_id()?;

    // Contrairement à Bitcoin (UTXO, vérifié dans `send_btc`), rien ne vérifiait ici
    // que le solde couvre montant + frais de gas avant de signer et diffuser : sans
    // ce contrôle, l'erreur ne remonte que via le rejet du nœud RPC après signature,
    // ce qui masque la vraie cause côté utilisateur ("fonds insuffisants") derrière un
    // message d'erreur RPC générique.
    const GAS_LIMIT: u128 = 21_000;
    let gas_cost = gas_price
        .checked_mul(GAS_LIMIT)
        .context("gas_price * gas_limit dépasse la capacité représentable")?;
    let total_needed = value
        .checked_add(gas_cost)
        .context("montant + frais de gas dépasse la capacité représentable")?;
    let balance = rpc.balance(&address_str)?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
    );

    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit: 21_000,
        to: to_bytes,
        value,
        chain_id,
    };
    let raw_tx = tx.sign(&signing_key)?;
    rpc.send_raw_transaction(&raw_tx)
}

pub struct BtcFeeEstimate {
    pub fast_sat: u64,
    pub medium_sat: u64,
    pub slow_sat: u64,
}

/// Cible de confirmation (en blocs) la plus proche disponible dans `estimates`
/// (triés par cible croissante, voir `btc_rpc::EsploraClient::fee_estimates`),
/// préférée à une cible <= `target` (jamais un tarif plus cher que prévu) ; à
/// défaut, la cible la plus proche au-dessus. `1.0` sat/vByte (le minimum de relais
/// standard du réseau) sert de filet de sécurité si l'API ne renvoie rien.
fn fee_rate_for_target(estimates: &[(u32, f64)], target: u32) -> f64 {
    estimates
        .iter()
        .filter(|(t, _)| *t <= target)
        .max_by_key(|(t, _)| *t)
        .or_else(|| estimates.first())
        .map(|(_, rate)| *rate)
        .unwrap_or(1.0)
}

/// Estime les frais rapide/moyen/lent (~1/~3/~6 blocs, soit environ 10 minutes,
/// 30 minutes et 1 heure — une cible d'un jour entier n'a d'intérêt pratique pour
/// personne) pour un virement depuis `address`, en sats — à choisir avant
/// `send_btc`. Le nombre d'entrées dépend des UTXOs réellement disponibles sur
/// cette adresse (tous consommés, voir `send_btc`) ; le nombre de sorties est
/// supposé à 2 (destinataire + monnaie), le cas le plus fréquent — si la
/// transaction réelle n'a finalement qu'une sortie, les frais payés seront très
/// légèrement supérieurs à nécessaire (quelques sats), jamais insuffisants.
pub fn estimate_btc_fees(address: &str, network: &wallet_flow::BtcNetwork) -> Result<BtcFeeEstimate> {
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let num_inputs = esplora.utxos(address)?.len().max(1);
    let vsize = crate::btc_tx::estimate_p2wpkh_vsize(num_inputs, 2) as f64;
    let estimates = esplora.fee_estimates()?;

    let sat_for_target = |target: u32| (fee_rate_for_target(&estimates, target) * vsize).ceil() as u64;
    Ok(BtcFeeEstimate {
        fast_sat: sat_for_target(1),
        medium_sat: sat_for_target(3),
        slow_sat: sat_for_target(6),
    })
}

/// Déverrouille le coffre, signe et diffuse un virement Bitcoin (mainnet ou
/// testnet selon `network`). `fee_sat` est choisi par l'appelant (voir
/// `estimate_btc_fees` : rapide/moyen/lent) plutôt que fixé ici — les frais réels
/// sont dictés par le marché sur mainnet, contrairement au testnet où ils sont
/// dérisoires ; une constante unique aurait laissé une vraie transaction
/// sous-payée et non confirmée indéfiniment.
pub fn send_btc(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::BtcNetwork,
    to: &str,
    amount_btc: &str,
    fee_sat: u64,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, hash160) = (network.derive_key)(&seed, profile_index)?;

    let address = (network.format_address)(&hash160)?;
    let to_hash160 = (network.parse_address)(to)?;
    let amount_sat = wallet_flow::parse_btc_to_sat(amount_btc)?;

    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let utxos = esplora.utxos(&address)?;
    let total_sat: u64 = utxos.iter().map(|u| u.value_sat).sum();

    const DUST_THRESHOLD_SAT: u64 = 1_000;
    // `checked_add` plutôt que `+` : `amount_sat` vient du montant tapé par
    // l'utilisateur, potentiellement proche de u64::MAX (voir parse_btc_to_sat) —
    // un dépassement ici s'enroulerait silencieusement en release et pourrait
    // faire passer un montant invalide comme "suffisant".
    let total_needed = amount_sat
        .checked_add(fee_sat)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= total_sat,
        "fonds insuffisants : {total_sat} sat disponibles, {amount_sat} sat + {fee_sat} sat de frais requis"
    );
    let remaining = total_sat - total_needed;
    let change_sat = if remaining > DUST_THRESHOLD_SAT { remaining } else { 0 };

    let tx = crate::btc_tx::BtcTx {
        inputs: utxos,
        to_hash160,
        value_sat: amount_sat,
        change_hash160: hash160,
        change_sat,
    };
    let raw_tx = tx.sign(&signing_key, &hash160)?;
    esplora.broadcast(&raw_tx)
}

/// Déverrouille le coffre, signe et diffuse un virement Solana.
pub fn send_sol(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    to: &str,
    amount_sol: &str,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);

    let from_pubkey = signing_key.verifying_key().to_bytes();
    let to_bytes = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let to_pubkey: [u8; 32] = to_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let lamports = wallet_flow::parse_sol_to_lamports(amount_sol)?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);

    // Même contrôle que côté CLI (`wallet_flow::send_sol`), absent ici jusqu'à présent :
    // sans lui, un montant + frais supérieur au solde n'était détecté qu'au rejet par
    // le nœud RPC après signature, au lieu d'un message clair "fonds insuffisants".
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let from_address = bs58::encode(from_pubkey).into_string();
    let balance = rpc.balance_lamports(&from_address)?;
    let total_needed = lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} lamports disponibles, {lamports} lamports + {SOL_FEE_LAMPORTS} lamports de frais requis"
    );

    let recent_blockhash = rpc.latest_blockhash()?;
    let raw_tx = sol_tx::build_transfer_transaction(&signing_key, &from_pubkey, &to_pubkey, lamports, &recent_blockhash);
    rpc.send_transaction(&raw_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_rate_for_target_prefers_the_closest_target_at_or_below_the_requested_one() {
        let estimates = [(2, 20.0), (6, 8.0), (144, 1.5)];
        // Cible exacte présente.
        assert_eq!(fee_rate_for_target(&estimates, 6), 8.0);
        // Cible absente entre deux valeurs connues : la plus proche EN DESSOUS (moins
        // cher que prévu n'arrive jamais avant confirmation, donc on ne doit jamais
        // sous-estimer en choisissant une cible plus rapide qu'espéré).
        assert_eq!(fee_rate_for_target(&estimates, 10), 8.0);
        // Cible plus rapide que tout ce qui est connu : la plus rapide disponible.
        assert_eq!(fee_rate_for_target(&estimates, 1), 20.0);
    }

    #[test]
    fn fee_rate_for_target_falls_back_to_1_sat_per_vbyte_when_no_estimates_are_available() {
        assert_eq!(fee_rate_for_target(&[], 6), 1.0);
    }

    #[test]
    fn delete_profile_removes_label_but_refuses_to_remove_the_last_one() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_delete_profile_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        create_profile(&dir, None, "Épargne").expect("création d'un second profil");
        assert_eq!(list_profiles(&dir).len(), 2);

        assert!(
            delete_profile(&dir, "mauvais mot de passe", 1).is_err(),
            "un mauvais mot de passe doit refuser la suppression"
        );
        assert_eq!(list_profiles(&dir).len(), 2, "rien ne doit être supprimé sur un mauvais mot de passe");

        delete_profile(&dir, password, 1).expect("suppression du second profil");
        let remaining = list_profiles(&dir);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].index, 0, "le profil par défaut doit être celui qui reste");

        assert!(
            delete_profile(&dir, password, 0).is_err(),
            "supprimer le dernier profil restant doit être refusé"
        );
        assert_eq!(list_profiles(&dir).len(), 1, "le profil restant ne doit pas avoir été supprimé");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_and_unarchive_profile_round_trips() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_archive_profile_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        create_profile(&dir, None, "Épargne").expect("création d'un second profil");

        // Archivé : disparaît de la liste active, apparaît dans les archives.
        archive_profile(&dir, 1).expect("archivage du second profil");
        assert_eq!(list_profiles(&dir).len(), 1, "le profil archivé ne doit plus être actif");
        let archived = list_archived_profiles(&dir);
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].index, 1);

        // Le déverrouillage complet ne doit dériver que les profils actifs.
        let unlocked = unlock_wallet(&dir, password).expect("déverrouillage");
        assert_eq!(unlocked.len(), 1, "un profil archivé ne doit pas être dérivé au déverrouillage");

        // Désarchivé : redevient actif, disparaît des archives.
        unarchive_profile(&dir, 1).expect("désarchivage");
        assert_eq!(list_profiles(&dir).len(), 2, "le profil désarchivé doit redevenir actif");
        assert!(list_archived_profiles(&dir).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_profile_refuses_to_archive_the_last_active_profile() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_archive_last_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        assert!(
            archive_profile(&dir, 0).is_err(),
            "archiver le seul profil actif doit être refusé"
        );
        assert_eq!(list_profiles(&dir).len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou contre l'effet de bord découvert en ajoutant l'archivage : sans lui,
    /// `delete_profile` ne vérifiait que le compte TOTAL de profils (actifs +
    /// archivés) > 1, donc supprimer le seul profil actif restant aurait pu passer
    /// tant qu'un profil archivé traînait — laissant le tableau de bord sans aucune
    /// adresse à afficher après déverrouillage.
    #[test]
    fn delete_profile_refuses_to_remove_the_last_active_profile_even_with_an_archived_one_present() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_delete_last_active_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        create_profile(&dir, None, "Épargne").expect("création d'un second profil");
        archive_profile(&dir, 1).expect("archivage du second profil");

        // 2 profils au total (1 actif + 1 archivé), mais un seul actif : la
        // suppression du profil actif restant doit être refusée.
        assert!(
            delete_profile(&dir, password, 0).is_err(),
            "supprimer le seul profil actif restant doit être refusé même si un profil archivé existe"
        );
        assert_eq!(list_profiles(&dir).len(), 1, "le profil actif ne doit pas avoir été supprimé");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_profiles_defaults_to_a_single_principal_profile_when_no_file_exists() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_profiles_default_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let profiles = list_profiles(&dir);
        assert_eq!(profiles.len(), 1, "un coffre pré-existant sans profiles.json doit avoir un seul profil implicite");
        assert_eq!(profiles[0].index, 0);
        assert_eq!(profiles[0].label, DEFAULT_PROFILE_LABEL);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_wallet_end_to_end_supports_adding_a_second_profile() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_profiles_create_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";

        create_wallet(&dir, password).expect("création du wallet");
        let initial = list_profiles(&dir);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].index, 0);

        let second = create_profile(&dir, Some(password), "Épargne").expect("création d'un second profil");
        assert_eq!(second.profile.index, 1, "le second profil doit prendre l'index suivant, jamais réutiliser 0");
        assert_eq!(second.profile.label, "Épargne");
        // Un profil différent doit déterministiquement dériver une adresse différente
        // (même seed, index différent) — sinon "plusieurs profils" ne servirait à rien.
        let second_evm = second.addresses.expect("mot de passe fourni : l'adresse doit être dérivée tout de suite").evm;
        assert_ne!(second_evm, initial_addresses_for(&dir, password).evm);

        let all = list_profiles(&dir);
        assert_eq!(all.len(), 2, "le nouveau profil doit être persisté à côté du premier");

        // Un déverrouillage complet doit renvoyer les adresses des DEUX profils en un
        // seul appel (voir doc de `unlock_wallet`), sans redemander le mot de passe.
        let unlocked = unlock_wallet(&dir, password).expect("déverrouillage");
        assert_eq!(unlocked.len(), 2);
        assert!(unlocked.iter().all(|p| p.addresses.is_some()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Régénérer un kit ne doit ni changer les adresses (même seed, même profils),
    /// ni exiger un coffre différent : seules de nouvelles identités PGP/passphrases
    /// jetables sont produites à chaque appel.
    #[test]
    fn regenerate_backup_kit_produces_a_fresh_valid_kit_without_touching_addresses() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_regen_backup_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";

        let created = create_wallet(&dir, password).expect("création du wallet");
        let addresses_before = unlock_wallet(&dir, password).unwrap();

        let kit1 = regenerate_backup_kit(&dir, password).expect("première régénération");
        let kit2 = regenerate_backup_kit(&dir, password).expect("seconde régénération");
        assert_eq!(kit1.len(), 3);
        assert_eq!(kit2.len(), 3);
        // Deux régénérations distinctes doivent produire des identités PGP différentes
        // (passphrases fraîches à chaque fois), pas la même paire réutilisée.
        assert_ne!(kit1[0].passphrase, kit2[0].passphrase);

        // Le nouveau kit doit être un vrai découpage Shamir fonctionnel de LA MÊME
        // entropie maître que celle protégée par le coffre : 2 de ses 3 parts
        // doivent permettre de retrouver les mêmes adresses qu'avant régénération.
        let share1 = decrypt_with_armored_privkey(
            &kit1[0].encrypted_share,
            &dir.join("tmp_test_decrypt_0.asc"),
            &kit1[0].privkey_armored,
            &kit1[0].passphrase,
        )
        .unwrap();
        let share2 = decrypt_with_armored_privkey(
            &kit1[1].encrypted_share,
            &dir.join("tmp_test_decrypt_1.asc"),
            &kit1[1].privkey_armored,
            &kit1[1].passphrase,
        )
        .unwrap();
        let recovered = shamir::reconstruct_secret(2, &[share1.as_slice(), share2.as_slice()]).unwrap();
        let recovered_addresses = derive_addresses(&recovered, 0).unwrap();
        assert_eq!(recovered_addresses.evm, addresses_before[0].addresses.as_ref().unwrap().evm);

        assert_eq!(created.addresses.evm, addresses_before[0].addresses.as_ref().unwrap().evm);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_profile_without_password_registers_label_but_defers_the_address() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_profiles_no_password_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        let profile = create_profile(&dir, None, "Sans mdp").expect("création sans mot de passe");
        assert_eq!(profile.profile.index, 1);
        assert!(profile.addresses.is_none(), "sans mot de passe, l'adresse ne doit pas être dérivée tout de suite");

        // L'adresse doit malgré tout apparaître dès le prochain déverrouillage complet,
        // puisque le profil (label + index) a bien été persisté.
        let unlocked = unlock_wallet(&dir, password).expect("déverrouillage");
        let deferred = unlocked.iter().find(|p| p.profile.index == 1).expect("le profil doit être persisté");
        assert!(deferred.addresses.is_some(), "l'adresse doit être dérivable au prochain déverrouillage");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou contre une croissance non authentifiée et non bornée de
    /// `profiles.json` : le chemin sans mot de passe de `create_profile` ne demande
    /// aucune authentification, donc sans plafond un script pourrait en créer un
    /// nombre arbitraire, ralentissant `unlock_wallet` (qui dérive tous les profils
    /// connus à chaque déverrouillage) pour le vrai propriétaire.
    #[test]
    fn create_profile_without_password_is_capped() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_profiles_cap_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        // Le profil par défaut compte déjà pour 1 : (MAX_PROFILES - 1) créations
        // supplémentaires doivent réussir, la suivante doit échouer.
        for i in 0..(MAX_PROFILES - 1) {
            create_profile(&dir, None, &format!("Profil {i}")).expect("sous le plafond, la création doit réussir");
        }
        assert_eq!(list_profiles(&dir).len(), MAX_PROFILES);
        assert!(
            create_profile(&dir, None, "Un de trop").is_err(),
            "au-delà du plafond, la création doit être refusée"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn initial_addresses_for(dir: &Path, password: &str) -> Addresses {
        unlock_wallet(dir, password)
            .unwrap()
            .into_iter()
            .find(|p| p.profile.index == 0)
            .unwrap()
            .addresses
            .unwrap()
    }

    #[test]
    fn no_lockout_below_free_attempts_threshold() {
        for n in 0..MAX_FREE_ATTEMPTS {
            assert_eq!(required_lockout_secs(n), 0, "{n} échecs ne devrait pas encore déclencher de délai");
        }
    }

    #[test]
    fn lockout_grows_and_caps() {
        let first = required_lockout_secs(MAX_FREE_ATTEMPTS);
        assert_eq!(first, BASE_LOCKOUT_SECS);
        let second = required_lockout_secs(MAX_FREE_ATTEMPTS + 1);
        assert!(second > first, "le délai doit croître avec les échecs supplémentaires");
        // Même avec un nombre d'échecs énorme, le délai ne doit jamais dépasser le plafond
        // (et ne doit surtout pas déborder arithmétiquement sur `1u64 << extra`).
        let capped = required_lockout_secs(u32::MAX);
        assert_eq!(capped, MAX_LOCKOUT_SECS);
    }

    #[test]
    fn unlock_attempts_roundtrip_via_disk() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_lockout_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        assert!(enforce_unlock_lockout(&dir).is_ok(), "aucun échec enregistré : pas de verrou");

        for _ in 0..MAX_FREE_ATTEMPTS {
            record_unlock_failure(&dir);
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "après {MAX_FREE_ATTEMPTS} échecs, une nouvelle tentative doit être bloquée"
        );

        reset_unlock_attempts(&dir);
        assert!(enforce_unlock_lockout(&dir).is_ok(), "reset_unlock_attempts doit lever le verrou");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou contre la régression trouvée lors d'un audit : `decrypt_incoming_message`
    /// appelait directement `pgp_engine::decrypt_share` avec le mot de passe de
    /// l'appareil, sans passer par `unlock_seed` — un mot de passe incorrect n'y
    /// alimentait donc jamais le compteur d'échecs, offrant une deuxième porte pour
    /// deviner ce mot de passe sans la moindre limite de tentatives (alors que
    /// `unlock_wallet`/`send_*`/`delete_profile`/`regenerate_backup_kit` y sont tous
    /// soumis). Ce test échouerait si cette porte dérobée revenait.
    #[test]
    fn decrypt_incoming_message_is_covered_by_the_same_lockout_as_unlock_wallet() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_decrypt_lockout_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        for _ in 0..MAX_FREE_ATTEMPTS {
            assert!(decrypt_incoming_message(&dir, "mauvais mot de passe", "peu importe").is_err());
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "les échecs de decrypt_incoming_message doivent déclencher le même verrou que unlock_wallet"
        );
        // Le verrou étant partagé, même le BON mot de passe reste bloqué tant qu'il est actif.
        assert!(unlock_wallet(&dir, password).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou contre le bug de course déjà rencontré (lecture-modification-écriture
    /// non atomique du compteur sur disque) : sans `UNLOCK_MUTEX` sérialisant l'accès,
    /// des threads concurrents perdraient des mises à jour et le compteur final serait
    /// inférieur au nombre réel d'échecs.
    #[test]
    fn concurrent_failures_are_not_lost_under_the_mutex() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_lockout_race_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        reset_unlock_attempts(&dir);

        const THREADS: usize = 20;
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    let _serialize = UNLOCK_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
                    record_unlock_failure(&dir);
                });
            }
        });

        let attempts = read_unlock_attempts(&dir);
        assert_eq!(
            attempts.consecutive_failures, THREADS as u32,
            "chaque échec concurrent doit être compté, aucun ne doit être perdu"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou contre un bug introduit par le correctif lui-même : sans le
    /// `reset_unlock_attempts` ajouté dans `create_wallet`, un compteur d'échecs
    /// résiduel (ex: fichier laissé par un `reset_wallet` interrompu) aurait pu
    /// faire naître un coffre tout juste créé déjà "en attente", bloquant le tout
    /// premier déverrouillage légitime de l'utilisateur.
    #[test]
    fn create_wallet_clears_stale_lockout_state() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_create_lockout_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        for _ in 0..(MAX_FREE_ATTEMPTS + 2) {
            record_unlock_failure(&dir);
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "précondition : le verrou doit être actif avant la création du coffre"
        );

        create_wallet(&dir, "un mot de passe de test bien assez long")
            .expect("la création doit réussir malgré le fichier de verrou résiduel");

        assert!(
            enforce_unlock_lockout(&dir).is_ok(),
            "un coffre tout juste créé ne doit jamais hériter d'un verrou résiduel"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
