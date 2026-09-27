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

use crate::{
    btc_rpc, dapp_requests, derivation, entropy, eth_rpc, eth_tx, history, jupiter_rpc, memory_guard, pgp_engine, secure_storage, shamir,
    sol_rpc, sol_spl, sol_tx, thorchain_rpc, wallet_flow,
};
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

// Déverrouillage biométrique (Windows Hello/TPM, voir windows_hello.rs et
// enroll_biometric_unlock ci-dessous) : une SECONDE identité PGP, en plus de
// "device" (mot de passe, inchangée), dont la clé privée est protégée par un
// secret aléatoire scellé matériellement plutôt qu'un mot de passe humain. Le
// coffre (`DEVICE_VAULT_FILE`) est alors chiffré pour les deux identités à la
// fois (voir `pgp_engine::encrypt_share_multi`) — n'importe laquelle des deux
// clés privées le déchiffre indépendamment.
const DEVICE_BIOMETRIC_PUBKEY_FILE: &str = "device_biometric_pubkey.asc";
const DEVICE_BIOMETRIC_PRIVKEY_FILE: &str = "device_biometric_privkey.asc";
const DEVICE_BIOMETRIC_SEALED_SECRET_FILE: &str = "device_biometric_sealed_secret.bin";
const DEVICE_BIOMETRIC_KEY_META_FILE: &str = "device_biometric_key_meta.json";

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

// Compteur d'échecs SÉPARÉ pour le chemin biométrique (jamais partagé avec
// `UNLOCK_ATTEMPTS_FILE`/le mot de passe) : un prompt Windows Hello qui traîne,
// échoue ou est spammé ne doit jamais mettre en attente le déverrouillage par
// mot de passe, et inversement. Copie quasi verbatim de la logique ci-dessus
// (`required_lockout_secs` est une fonction pure sur un compteur, réutilisée
// telle quelle) — dupliquée plutôt que paramétrée pour ne surtout pas risquer de
// modifier, même indirectement, le chemin mot de passe déjà audité.
const BIOMETRIC_UNLOCK_ATTEMPTS_FILE: &str = "unlock_attempts_biometric.json";

fn biometric_unlock_attempts_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(BIOMETRIC_UNLOCK_ATTEMPTS_FILE)
}

fn read_biometric_unlock_attempts(data_dir: &Path) -> UnlockAttempts {
    std::fs::read_to_string(biometric_unlock_attempts_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_biometric_unlock_attempts(data_dir: &Path, attempts: &UnlockAttempts) {
    if let Ok(s) = serde_json::to_string(attempts) {
        let _ = std::fs::write(biometric_unlock_attempts_path(data_dir), s);
    }
}

fn enforce_biometric_unlock_lockout(data_dir: &Path) -> Result<()> {
    let attempts = read_biometric_unlock_attempts(data_dir);
    let delay = required_lockout_secs(attempts.consecutive_failures);
    if delay == 0 {
        return Ok(());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let elapsed = now.saturating_sub(attempts.last_failure_unix);
    anyhow::ensure!(
        elapsed >= delay,
        "trop de tentatives biométriques incorrectes récentes ; réessayez dans {} seconde(s)",
        delay - elapsed
    );
    Ok(())
}

fn record_biometric_unlock_failure(data_dir: &Path) {
    let mut attempts = read_biometric_unlock_attempts(data_dir);
    attempts.consecutive_failures = attempts.consecutive_failures.saturating_add(1);
    attempts.last_failure_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    write_biometric_unlock_attempts(data_dir, &attempts);
}

fn reset_biometric_unlock_attempts(data_dir: &Path) {
    let _ = std::fs::remove_file(biometric_unlock_attempts_path(data_dir));
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
    // Le buffer d'entropie brut est effacé dès que le hex en est extrait (`Zeroizing`) —
    // seul le cas de `generate_master_entropy` dans tout le projet qui ne le faisait pas
    // encore. La `String` hex retournée, elle, est délibérément affichée à l'utilisateur
    // (passphrase d'une part de sauvegarde à noter) : rien à gagner à la protéger, elle
    // finit de toute façon rendue en clair côté interface.
    let bytes = Zeroizing::new(entropy::generate_master_entropy());
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

/// Adresse THORChain (RUNE) dérivée de la même entropie maître, index 0 fixe
/// (jamais un "profil" au sens des autres réseaux — une seule adresse, pas une
/// par profil). Sert UNIQUEMENT à recevoir les frais d'affiliation des swaps
/// (voir thorchain_rpc.rs) : purement informatif ici, aucune fonctionnalité
/// d'envoi/solde RUNE dans cette v1.
pub fn get_thor_fee_address(data_dir: &Path, device_password: &str) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (_key, hash160) = derivation::derive_thor_key(&seed, 0)?;
    derivation::format_thor_address(&hash160)
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

// --- Stockage de la clé privée "device" (coffre OS plutôt qu'un simple fichier) --
// Voir `secure_storage.rs` pour le "pourquoi" (contrôle d'accès OS réel, pas
// seulement un chemin de fichier à deviner) et l'isolation par `data_dir`.
// Ne concerne QUE `device_privkey.asc` (déverrouillage par mot de passe) : la
// clé privée "device_biometric" reste en fichier, son secret est déjà scellé
// matériellement par le TPM (voir windows_hello.rs), le gain marginal d'un
// second mécanisme de protection serait minime.

/// Sélectionne le coffre actif : le vrai coffre OS en production, un faux
/// coffre en mémoire partagé entre tests en `#[cfg(test)]` — même motif que
/// `SecretSealer`/`WindowsHelloSealer` pour le déverrouillage biométrique,
/// justifié ici pour la même raison : `cargo test` ne doit jamais toucher le
/// vrai Gestionnaire d'identification/Trousseau de la machine qui l'exécute,
/// ni dépendre d'un coffre OS réellement configuré sur une machine de CI.
#[cfg(not(test))]
fn active_key_store() -> &'static dyn secure_storage::KeyStore {
    static STORE: secure_storage::OsKeyStore = secure_storage::OsKeyStore;
    &STORE
}

#[cfg(test)]
fn active_key_store() -> &'static dyn secure_storage::KeyStore {
    static STORE: std::sync::OnceLock<secure_storage::InMemoryKeyStore> = std::sync::OnceLock::new();
    STORE.get_or_init(secure_storage::InMemoryKeyStore::default)
}

/// Écrit une nouvelle clé privée "device" : essaie le coffre OS en premier,
/// ne retombe sur un fichier classique QUE s'il est indisponible (jamais de
/// blocage de la création/restauration du wallet à cause de ça). Supprime un
/// éventuel fichier existant en cas de succès du coffre OS : une seule copie
/// du secret doit exister à la fois, jamais les deux en parallèle.
fn write_device_privkey(data_dir: &Path, armored: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(armored).context("clé privée générée non-UTF8 (bug de génération PGP)")?;
    let username = secure_storage::entry_username(data_dir);
    match active_key_store().write(&username, text) {
        Ok(()) => {
            let _ = std::fs::remove_file(data_dir.join(DEVICE_PRIVKEY_FILE));
            Ok(())
        }
        Err(_) => std::fs::write(data_dir.join(DEVICE_PRIVKEY_FILE), armored)
            .context("écriture de la clé privée de l'appareil (coffre OS indisponible)"),
    }
}

/// Donne un accès temporaire, sous forme de CHEMIN DE FICHIER, à la clé
/// privée "device" — `pgp_engine::decrypt_share` (biais hérité de
/// `sequoia-openpgp::Cert::from_file`) n'accepte qu'un chemin, jamais des
/// octets en mémoire directement. Lit D'ABORD le coffre OS puis, seulement à
/// défaut, l'ancien fichier (compatibilité avec les wallets créés avant ce
/// changement, ou coffre OS momentanément indisponible). Quand la source est
/// le coffre OS, le secret est brièvement matérialisé dans un fichier
/// temporaire à usage unique, supprimé même en cas de panique/erreur
/// (`TempFileGuard`, même mécanisme déjà utilisé pour les clés de sauvegarde
/// Shamir) : une fenêtre d'exposition sur disque de la durée d'un seul appel,
/// contre une exposition permanente à un chemin fixe et prévisible avant ce
/// changement.
fn with_device_privkey_path<T>(data_dir: &Path, f: impl FnOnce(&str) -> Result<T>) -> Result<T> {
    with_device_privkey_path_in(data_dir, active_key_store(), f)
}

/// Erreur "la clé privée n'a même pas pu être atteinte" (coffre OS en panne ET
/// aucun fichier de repli, ou fichier temporaire impossible à écrire) —
/// jamais un mauvais mot de passe. Trouvé lors du 20ᵉ passage d'auto-revue :
/// `unlock_seed` comptait TOUTE erreur de `with_device_privkey_path` comme une
/// tentative de mot de passe ratée, alors que sa propre doc dit que le verrou
/// "ne compte que les mauvais mots de passe". Depuis la migration vers le
/// coffre OS, un simple souci transitoire de celui-ci aurait donc pénalisé un
/// utilisateur légitime ayant tapé le BON mot de passe (délai croissant
/// jusqu'à 5 minutes). Type marqueur plutôt qu'une comparaison de texte
/// (contrairement à `is_user_cancellation`, contraint par un code d'erreur
/// Windows formaté par une crate tierce) : ici on contrôle les deux bouts.
#[derive(Debug)]
struct KeyMaterialUnavailable(String);

impl std::fmt::Display for KeyMaterialUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyMaterialUnavailable {}

fn is_key_material_unavailable(err: &anyhow::Error) -> bool {
    err.downcast_ref::<KeyMaterialUnavailable>().is_some()
}

fn with_device_privkey_path_in<T>(
    data_dir: &Path,
    store: &dyn secure_storage::KeyStore,
    f: impl FnOnce(&str) -> Result<T>,
) -> Result<T> {
    let username = secure_storage::entry_username(data_dir);
    let from_store = store.read(&username);
    if let Ok(Some(secret)) = &from_store {
        let unique = format!("{:?}-{}", std::thread::current().id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos());
        let tmp_path = data_dir.join(format!("tmp_device_privkey_{unique}.asc"));
        std::fs::write(&tmp_path, secret.as_bytes()).map_err(|e| {
            anyhow::Error::new(KeyMaterialUnavailable(format!("matérialisation temporaire de la clé privée de l'appareil impossible : {e}")))
        })?;
        let _guard = TempFileGuard(&tmp_path);
        return f(&tmp_path.to_string_lossy());
    }
    // `Ok(None)` (wallet dont la clé vit encore en fichier) ET `Err` (coffre OS
    // en panne) tentent tous deux le fichier : une panne du coffre OS ne doit
    // jamais bloquer un wallet dont la clé est justement en fichier (ex :
    // coffre indisponible au moment de la création, voir `write_device_privkey`).
    let path = data_dir.join(DEVICE_PRIVKEY_FILE);
    if !path.exists() {
        let detail = match &from_store {
            Err(e) => format!(" (coffre OS : {e:#})"),
            _ => String::new(),
        };
        return Err(anyhow::Error::new(KeyMaterialUnavailable(format!(
            "clé privée de l'appareil introuvable (ni coffre OS, ni fichier){detail}"
        ))));
    }
    f(&path.to_string_lossy())
}

/// Supprime la clé privée "device", où qu'elle vive (coffre OS et/ou fichier
/// — au plus l'un des deux en pratique, voir `write_device_privkey`, mais
/// vérifie les deux pour ne jamais laisser une copie orpheline). Best-effort
/// sur le coffre OS (absence normale si le wallet a toujours vécu en
/// fichier) ; erreur si le fichier existe mais ne peut pas être supprimé
/// (permissions, verrouillage) — comportement identique à `reset_wallet`
/// pour les autres fichiers du coffre.
fn remove_device_privkey(data_dir: &Path) -> Result<()> {
    let username = secure_storage::entry_username(data_dir);
    let _ = active_key_store().remove(&username);
    let path = data_dir.join(DEVICE_PRIVKEY_FILE);
    if path.exists() {
        std::fs::remove_file(&path).context("suppression du fichier de clé privée de l'appareil impossible")?;
    }
    Ok(())
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
    // Trouvé lors d'un audit indépendant (pas seulement `cargo test`) : contrairement
    // à l'entropie/la seed/les mots de passe, la clé privée PGP fraîchement générée
    // ici n'était jamais effacée après usage — même écart que celui corrigé pour
    // d'autres buffers lors du 2ᵉ passage d'auto-revue (voir ETAPES.md), juste
    // resté invisible jusqu'ici parce que `generate_pgp_identity` est plus récente.
    let device_priv = Zeroizing::new(device_priv);
    std::fs::write(data_dir.join(DEVICE_PUBKEY_FILE), &device_pub)?;
    write_device_privkey(data_dir, &device_priv)?;
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
    restore_wallet_with(data_dir, new_device_password, backup_1, backup_2, &WindowsHelloSealer)
}

/// `sealer` injectable pour les tests, même raison que `reset_wallet_with` :
/// trouvé dans le même audit, la même classe de bug existait ici. `restore_
/// wallet` remplace l'identité "device" de l'appareil (contrairement à
/// `create_wallet`, il n'exige même pas l'absence d'un coffre existant — voir
/// sa propre doc, c'est le scénario "appareil d'origine perdu") SANS jamais
/// invalider un enrôlement biométrique préexistant, qui référence l'ANCIENNE
/// identité "device" : `device_vault.asc` (nouveau) n'est chiffré que pour la
/// nouvelle identité, jamais pour l'ancienne "device_biometric", donc un
/// déverrouillage biométrique après restauration échouerait proprement, mais
/// resterait affiché comme activé (`biometric_unlock_enrolled` ne vérifie que
/// l'existence des fichiers) et laisserait la clé TPM de l'ancien appareil
/// orpheline indéfiniment.
fn restore_wallet_with(
    data_dir: &Path,
    new_device_password: &str,
    backup_1: (&[u8], &[u8], &str),
    backup_2: (&[u8], &[u8], &str),
    sealer: &dyn SecretSealer,
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
    let device_priv = Zeroizing::new(device_priv); // voir le commentaire équivalent dans create_wallet
    std::fs::write(data_dir.join(DEVICE_PUBKEY_FILE), &device_pub)?;
    write_device_privkey(data_dir, &device_priv)?;
    let vault = encrypt_with_armored_pubkey(&recovered, &data_dir.join("tmp_device_pub.asc"), &device_pub)?;
    std::fs::write(data_dir.join(DEVICE_VAULT_FILE), &vault)?;

    // Un enrôlement biométrique éventuel référençait l'ANCIENNE identité
    // "device" : plus jamais valide une fois `device_vault.asc` remplacé
    // ci-dessus (voir la doc de cette fonction) — best-effort, comme le
    // nettoyage équivalent dans `disable_biometric_unlock_with`.
    try_remove_existing_biometric_enrollment(data_dir, sealer);
    for file in [
        DEVICE_BIOMETRIC_PUBKEY_FILE,
        DEVICE_BIOMETRIC_PRIVKEY_FILE,
        DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
        DEVICE_BIOMETRIC_KEY_META_FILE,
    ] {
        let _ = std::fs::remove_file(data_dir.join(file));
    }

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
///
/// La clé qui déchiffre ces messages est AUSSI celle qui déchiffre le coffre :
/// le contenu de `device_vault.asc`, collé ici comme un "message", donnerait
/// l'entropie maître. Seule protection jusqu'au 22ᵉ passage : 32 octets
/// aléatoires ne forment presque jamais du texte UTF-8 valide — une
/// probabilité, pas une garantie. Désormais refusé explicitement.
pub fn decrypt_incoming_message(data_dir: &Path, device_password: &str, ciphertext: &str) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let plaintext = Zeroizing::new(with_device_privkey_path(data_dir, |privkey_path| {
        pgp_engine::decrypt_share(ciphertext.as_bytes(), privkey_path, device_password)
    })?);
    anyhow::ensure!(
        plaintext.as_slice() != seed.as_slice(),
        "ce « message » est le coffre du portefeuille lui-même — déchiffrement refusé"
    );
    String::from_utf8(plaintext.to_vec()).context("le message déchiffré n'est pas du texte UTF-8 valide")
}

/// Supprime le coffre local de cet appareil (utile pour retester l'onboarding, ou
/// pour un vrai "réinitialiser cet appareil"). Ne touche à rien d'autre : si
/// l'utilisateur a bien exporté ses 3 parts de sauvegarde à la création, le wallet
/// reste récupérable via `restore_wallet`. Aucune erreur si le coffre n'existait déjà pas.
pub fn reset_wallet(data_dir: &Path) -> Result<()> {
    reset_wallet_with(data_dir, &WindowsHelloSealer)
}

/// Trouvé lors d'un audit indépendant (pas un test qui a échoué) : cette
/// fonction ne touchait jusqu'ici QUE `device_pubkey.asc`/`device_vault.asc`
/// et la clé privée "device" — jamais l'enrôlement biométrique. Concrètement,
/// réinitialiser un appareil sur lequel Windows Hello était activé laissait
/// une clé orpheline dans le TPM indéfiniment (exactement le risque déjà
/// documenté par `disable_biometric_unlock`, juste jamais appliqué ici), plus
/// les 4 fichiers `device_biometric_*` obsolètes sur disque — qui auraient
/// ensuite fait croire à `biometric_unlock_enrolled` qu'un DEUXIÈME wallet
/// créé sur ce même appareil après coup a la biométrie active, alors que ce
/// nouveau coffre n'a jamais été chiffré pour cette identité (l'échec
/// resterait propre au déverrouillage, mais l'état affiché serait faux).
/// `sealer` injectable pour les tests, même motif que `enroll_biometric_
/// unlock`/`disable_biometric_unlock` : ne doit jamais déclencher un vrai
/// prompt Windows Hello pendant `cargo test`.
fn reset_wallet_with(data_dir: &Path, sealer: &dyn SecretSealer) -> Result<()> {
    try_remove_existing_biometric_enrollment(data_dir, sealer);
    for file in [
        DEVICE_PUBKEY_FILE,
        DEVICE_VAULT_FILE,
        DEVICE_BIOMETRIC_PUBKEY_FILE,
        DEVICE_BIOMETRIC_PRIVKEY_FILE,
        DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
        DEVICE_BIOMETRIC_KEY_META_FILE,
    ] {
        let path = data_dir.join(file);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("suppression de {file} impossible"))?;
        }
    }
    remove_device_privkey(data_dir)?;
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
    let result = with_device_privkey_path(data_dir, |privkey_path| pgp_engine::decrypt_share(&vault, privkey_path, device_password));
    match result {
        Ok(seed) => {
            reset_unlock_attempts(data_dir);
            Ok(Zeroizing::new(seed))
        }
        Err(e) => {
            // Seul un vrai échec de déchiffrement (mauvais mot de passe) compte :
            // une clé privée injoignable n'est pas une tentative de mot de passe,
            // voir `KeyMaterialUnavailable`.
            if !is_key_material_unavailable(&e) {
                record_unlock_failure(data_dir);
            }
            Err(e)
        }
    }
}

// --- Déverrouillage biométrique (Windows Hello/TPM) ------------------------
// Chemin ADDITIONNEL au mot de passe, jamais un remplacement : voir le
// commentaire sur les constantes `DEVICE_BIOMETRIC_*` plus haut, et
// `windows_hello.rs` pour le "pourquoi" du choix TPM plutôt que DPAPI.

/// Abstraction sur "sceller/récupérer un secret via une vérification
/// biométrique locale" — permet de tester toute l'orchestration
/// (activation/désactivation/déverrouillage, fichiers, verrou anti-brute-force)
/// avec un faux scelleur en mémoire, sans matériel Windows Hello réel. En
/// production, toujours `WindowsHelloSealer`.
pub(crate) trait SecretSealer {
    fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)>;
    fn unlock(&self, key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn remove(&self, key_name: &str) -> Result<()>;
}

/// `true` si `err` correspond à une annulation volontaire du prompt Windows
/// Hello par l'utilisateur (NTE_USER_CANCELLED, code Windows `0x800704c7`) —
/// un choix délibéré ("je préfère taper mon mot de passe"), jamais une
/// tentative de deviner le secret : la biométrie n'est structurellement pas
/// "devinable" par cette fonction, elle est intégralement gated par le
/// TPM/l'OS. Sans cette distinction, un utilisateur qui clique "Annuler"
/// plusieurs fois (changement d'avis, capteur capricieux) déclencherait le
/// même verrou anti-brute-force que prévu pour une vraie attaque, punissant
/// un usage légitime. Le code numérique (contrairement au texte du message,
/// dépendant de la langue de Windows) est stable, indépendant de la langue du
/// système — vérifié empiriquement lors du spike (`tpm_hello_spike.rs`,
/// commande `cancel`).
fn is_user_cancellation(err: &anyhow::Error) -> bool {
    err.to_string().to_lowercase().contains("0x800704c7")
}

#[cfg(windows)]
struct WindowsHelloSealer;

#[cfg(windows)]
impl SecretSealer for WindowsHelloSealer {
    fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
        crate::windows_hello::enroll(secret)
    }
    fn unlock(&self, key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crate::windows_hello::unlock(key_name, sealed_blob)
    }
    fn remove(&self, key_name: &str) -> Result<()> {
        crate::windows_hello::remove(key_name)
    }
}

#[cfg(not(windows))]
struct WindowsHelloSealer;

#[cfg(not(windows))]
impl SecretSealer for WindowsHelloSealer {
    fn enroll(&self, _secret: &[u8]) -> Result<(String, Vec<u8>)> {
        Err(anyhow::anyhow!("le déverrouillage biométrique n'est disponible que sous Windows"))
    }
    fn unlock(&self, _key_name: &str, _sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(anyhow::anyhow!("le déverrouillage biométrique n'est disponible que sous Windows"))
    }
    fn remove(&self, _key_name: &str) -> Result<()> {
        Err(anyhow::anyhow!("le déverrouillage biométrique n'est disponible que sous Windows"))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BiometricKeyMeta {
    key_name: String,
    created_unix: u64,
}

fn read_biometric_meta(data_dir: &Path) -> Result<BiometricKeyMeta> {
    let content = std::fs::read_to_string(data_dir.join(DEVICE_BIOMETRIC_KEY_META_FILE))
        .context("déverrouillage biométrique non activé sur cet appareil")?;
    serde_json::from_str(&content).context("métadonnées de la clé biométrique corrompues")
}

/// `true` si le déverrouillage biométrique est activé sur cet appareil.
pub fn biometric_unlock_enrolled(data_dir: &Path) -> bool {
    data_dir.join(DEVICE_BIOMETRIC_SEALED_SECRET_FILE).exists()
}

fn try_remove_existing_biometric_enrollment(data_dir: &Path, sealer: &dyn SecretSealer) {
    if let Ok(meta) = read_biometric_meta(data_dir) {
        let _ = sealer.remove(&meta.key_name);
    }
}

/// Active le déverrouillage biométrique EN PLUS du mot de passe existant,
/// jamais à sa place : ré-chiffre `device_vault.asc` pour DEUX destinataires
/// (l'identité "device" existante, inchangée, + une nouvelle identité
/// "device_biometric" dont la passphrase est un secret aléatoire de 256 bits
/// scellé par le TPM, voir `windows_hello::enroll`). Exige le mot de passe
/// actuel de l'appareil (même verrou anti-brute-force que les autres actions
/// sensibles, via `unlock_seed`) : activer ce second chemin est une action de
/// sécurité, pas un simple confort.
///
/// Ré-enrôler alors qu'un enrôlement existe déjà le remplace proprement
/// (l'ancienne clé TPM est supprimée en best-effort) plutôt que d'exiger un
/// `disable_biometric_unlock` préalable — utile si l'utilisateur reconfigure
/// son empreinte/visage Windows Hello.
pub fn enroll_biometric_unlock(data_dir: &Path, device_password: &str) -> Result<()> {
    enroll_biometric_unlock_with(data_dir, device_password, &WindowsHelloSealer)
}

fn enroll_biometric_unlock_with(data_dir: &Path, device_password: &str, sealer: &dyn SecretSealer) -> Result<()> {
    let master_entropy = unlock_seed(data_dir, device_password)?;
    let _entropy_lock = memory_guard::lock(&master_entropy);

    try_remove_existing_biometric_enrollment(data_dir, sealer);

    let secret = Zeroizing::new(entropy::generate_master_entropy());
    let biometric_passphrase = Zeroizing::new(hex::encode(&secret[..]));
    let (bio_pub, bio_priv) = generate_pgp_identity("device_biometric", &biometric_passphrase)?;
    let bio_priv = Zeroizing::new(bio_priv); // voir le commentaire équivalent dans create_wallet

    let (key_name, sealed_blob) = sealer.enroll(&secret)?;

    // À partir d'ici, la clé TPM existe réellement (voir `windows_hello::enroll`).
    // Si une étape suivante échoue, cette fonction n'écrit jamais le fichier de
    // métadonnées (`DEVICE_BIOMETRIC_KEY_META_FILE`) qui permettrait de la
    // retrouver plus tard : sans ce nettoyage explicite, elle resterait
    // orpheline dans le TPM indéfiniment, invisible pour
    // `try_remove_existing_biometric_enrollment` lors d'un futur essai.
    let result = finish_enroll(data_dir, device_password, &master_entropy, &bio_pub, &bio_priv, &key_name, &sealed_blob);
    if result.is_err() {
        let _ = sealer.remove(&key_name);
    }
    result
}

fn finish_enroll(
    data_dir: &Path,
    device_password: &str,
    master_entropy: &[u8],
    bio_pub: &[u8],
    bio_priv: &[u8],
    key_name: &str,
    sealed_blob: &[u8],
) -> Result<()> {
    let device_pub = std::fs::read(data_dir.join(DEVICE_PUBKEY_FILE)).context("lecture de la clé publique de l'appareil")?;
    let new_vault = pgp_engine::encrypt_share_multi(master_entropy, &[&device_pub, bio_pub])?;

    // Écrit-vérifie-renomme : le mot de passe existant doit pouvoir déchiffrer
    // le NOUVEAU coffre avant que l'ancien ne soit jamais écrasé — sans ça, un
    // nouveau coffre mal formé casserait le seul chemin de déverrouillage qui
    // existait avant cet appel.
    let tmp_vault_path = data_dir.join("tmp_device_vault_new.asc");
    std::fs::write(&tmp_vault_path, &new_vault)?;
    let _guard = TempFileGuard(&tmp_vault_path);
    with_device_privkey_path(data_dir, |privkey_path| pgp_engine::decrypt_share(&new_vault, privkey_path, device_password))
        .context("vérification post-ré-chiffrement du coffre : le mot de passe existant ne fonctionne plus, activation annulée")?;

    std::fs::write(data_dir.join(DEVICE_BIOMETRIC_PUBKEY_FILE), bio_pub)?;
    std::fs::write(data_dir.join(DEVICE_BIOMETRIC_PRIVKEY_FILE), bio_priv)?;
    std::fs::write(data_dir.join(DEVICE_BIOMETRIC_SEALED_SECRET_FILE), sealed_blob)?;
    let created_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = BiometricKeyMeta { key_name: key_name.to_string(), created_unix };
    std::fs::write(data_dir.join(DEVICE_BIOMETRIC_KEY_META_FILE), serde_json::to_string(&meta)?)?;
    std::fs::rename(&tmp_vault_path, data_dir.join(DEVICE_VAULT_FILE))?; // dernière étape, atomique
    reset_biometric_unlock_attempts(data_dir);
    Ok(())
}

/// Désactive le déverrouillage biométrique : revient à un coffre protégé par le
/// seul mot de passe (comme avant toute activation), supprime la clé TPM
/// (best-effort) et les fichiers biométriques. Exige le mot de passe de
/// l'appareil — jamais la biométrie elle-même pour se désactiver.
pub fn disable_biometric_unlock(data_dir: &Path, device_password: &str) -> Result<()> {
    disable_biometric_unlock_with(data_dir, device_password, &WindowsHelloSealer)
}

fn disable_biometric_unlock_with(data_dir: &Path, device_password: &str, sealer: &dyn SecretSealer) -> Result<()> {
    let master_entropy = unlock_seed(data_dir, device_password)?;
    let _entropy_lock = memory_guard::lock(&master_entropy);

    let device_pub = std::fs::read(data_dir.join(DEVICE_PUBKEY_FILE)).context("lecture de la clé publique de l'appareil")?;
    let tmp_pub_path = data_dir.join("tmp_device_pub_disable.asc");
    let new_vault = encrypt_with_armored_pubkey(&master_entropy, &tmp_pub_path, &device_pub)?;

    let tmp_vault_path = data_dir.join("tmp_device_vault_disable.asc");
    std::fs::write(&tmp_vault_path, &new_vault)?;
    let _guard = TempFileGuard(&tmp_vault_path);
    with_device_privkey_path(data_dir, |privkey_path| pgp_engine::decrypt_share(&new_vault, privkey_path, device_password))
        .context("vérification post-ré-chiffrement du coffre : le mot de passe existant ne fonctionne plus, désactivation annulée")?;
    std::fs::rename(&tmp_vault_path, data_dir.join(DEVICE_VAULT_FILE))?;

    if let Ok(meta) = read_biometric_meta(data_dir) {
        let _ = sealer.remove(&meta.key_name);
    }
    for file in [
        DEVICE_BIOMETRIC_PUBKEY_FILE,
        DEVICE_BIOMETRIC_PRIVKEY_FILE,
        DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
        DEVICE_BIOMETRIC_KEY_META_FILE,
    ] {
        let _ = std::fs::remove_file(data_dir.join(file));
    }
    reset_biometric_unlock_attempts(data_dir);
    Ok(())
}

/// Sérialise le cycle lecture-tentative-écriture du compteur d'échecs
/// biométrique — même raison que `UNLOCK_MUTEX` pour le mot de passe, mutex
/// entièrement séparé pour ne jamais faire attendre l'un sur l'autre.
static BIOMETRIC_UNLOCK_MUTEX: Mutex<()> = Mutex::new(());

fn unlock_seed_biometric(data_dir: &Path, sealer: &dyn SecretSealer) -> Result<Zeroizing<Vec<u8>>> {
    let _serialize = BIOMETRIC_UNLOCK_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let vault = std::fs::read(data_dir.join(DEVICE_VAULT_FILE)).context("coffre local introuvable")?;
    enforce_biometric_unlock_lockout(data_dir)?;
    let meta = read_biometric_meta(data_dir)?;
    let sealed_blob = std::fs::read(data_dir.join(DEVICE_BIOMETRIC_SEALED_SECRET_FILE))
        .context("secret biométrique scellé introuvable")?;

    let secret = match sealer.unlock(&meta.key_name, &sealed_blob) {
        Ok(s) => s,
        Err(e) => {
            // Une annulation volontaire du prompt (voir `is_user_cancellation`)
            // ne compte jamais dans le verrou anti-brute-force — seul un
            // véritable échec de vérification (blob corrompu, clé TPM absente,
            // etc.) y contribue.
            if !is_user_cancellation(&e) {
                record_biometric_unlock_failure(data_dir);
            }
            return Err(e);
        }
    };
    let passphrase = Zeroizing::new(hex::encode(&secret[..]));
    let privkey_path = data_dir.join(DEVICE_BIOMETRIC_PRIVKEY_FILE);
    match pgp_engine::decrypt_share(&vault, &privkey_path.to_string_lossy(), &passphrase) {
        Ok(seed) => {
            reset_biometric_unlock_attempts(data_dir);
            Ok(Zeroizing::new(seed))
        }
        Err(e) => {
            record_biometric_unlock_failure(data_dir);
            Err(e)
        }
    }
}

/// Déverrouille le coffre via la biométrie (Windows Hello/TPM) plutôt que le mot
/// de passe — chemin parallèle à `unlock_wallet`, jamais mêlé à son verrou
/// anti-brute-force ni à son mutex. Renvoie les mêmes adresses, pour tous les
/// profils actifs.
pub fn unlock_wallet_biometric(data_dir: &Path) -> Result<Vec<ProfileAddresses>> {
    unlock_wallet_biometric_with(data_dir, &WindowsHelloSealer)
}

fn unlock_wallet_biometric_with(data_dir: &Path, sealer: &dyn SecretSealer) -> Result<Vec<ProfileAddresses>> {
    let seed = unlock_seed_biometric(data_dir, sealer)?;
    let _seed_lock = memory_guard::lock(&seed);
    list_profiles(data_dir)
        .into_iter()
        .map(|profile| {
            let addresses = derive_addresses(&seed, profile.index)?;
            Ok(ProfileAddresses { profile, addresses: Some(addresses) })
        })
        .collect()
}

pub fn get_evm_balance(address: &str, network: &wallet_flow::EvmNetwork) -> Result<u128> {
    eth_rpc::EthRpc::new(network.rpc).balance(address)
}

pub fn get_btc_balance(address: &str, network: &wallet_flow::BtcNetwork) -> Result<u64> {
    let utxos = btc_rpc::EsploraClient::new(network.esplora_base).utxos(address)?;
    Ok(utxos.iter().map(|u| u.value_sat).sum())
}

/// Solde de la carte Bitcoin.
pub struct BtcBalanceView {
    /// Confirmé, moins ce qui part dans des transactions en attente : un envoi
    /// se voit dès sa diffusion (il ne peut que partir).
    pub settled_sat: u64,
    /// Réceptions non confirmées, montrées À PART et non comptées : une
    /// réception en attente peut encore être annulée par son émetteur (double
    /// dépense, remplacement RBF) — l'arnaque classique du « paiement reçu »
    /// qui disparaît. Trouvé au 23ᵉ passage : la carte les comptait.
    pub incoming_pending_sat: u64,
}

/// Transaction en attente classée d'après sa variation nette pour l'adresse :
/// négative = envoi (monnaie rendue déduite), positive = réception.
pub fn get_btc_balance_view(address: &str, network: &wallet_flow::BtcNetwork) -> Result<BtcBalanceView> {
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let (stats, mempool) = std::thread::scope(|scope| {
        let stats = scope.spawn(|| esplora.address_stats(address));
        let mempool = esplora.mempool_history(address);
        (stats.join().expect("le fil des statistiques ne doit pas paniquer"), mempool)
    });
    let (stats, mempool) = (stats?, mempool?);
    Ok(btc_balance_view(stats.confirmed_sat, mempool.iter().map(|tx| tx.net_sat)))
}

fn btc_balance_view(confirmed_sat: i128, pending_nets: impl Iterator<Item = i128>) -> BtcBalanceView {
    let (mut settled, mut incoming) = (confirmed_sat, 0i128);
    for net in pending_nets {
        if net < 0 {
            settled += net;
        } else {
            incoming += net;
        }
    }
    let to_u64 = |v: i128| u64::try_from(v.max(0)).unwrap_or(u64::MAX);
    BtcBalanceView { settled_sat: to_u64(settled), incoming_pending_sat: to_u64(incoming) }
}

pub fn get_sol_balance(address: &str, network: &wallet_flow::SolNetwork) -> Result<u64> {
    sol_rpc::SolRpc::new(network.rpc).balance_lamports(address)
}

/// Solde USDC de `owner_address` (mainnet uniquement, voir sol_spl.rs), en
/// plus petite unité (6 décimales) — 0 si l'Associated Token Account n'existe
/// pas encore (jamais reçu d'USDC), pas une erreur.
pub fn get_usdc_balance(owner_address: &str, network: &wallet_flow::SolNetwork) -> Result<u64> {
    let owner_bytes = bs58::decode(owner_address.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let owner: [u8; 32] = owner_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = sol_spl::find_associated_token_address(&owner, &sol_spl::usdc_mint_mainnet());
    let ata_b58 = bs58::encode(ata).into_string();
    Ok(sol_rpc::SolRpc::new(network.rpc).token_account_balance(&ata_b58)?.unwrap_or(0))
}

/// Historique des transactions USDC de `owner_address` : dérive son ATA puis
/// délègue à `history::usdc_history` (voir sa doc — l'ATA, pas l'adresse
/// "propriétaire", est ce qui reçoit/envoie effectivement le jeton). Si l'ATA
/// n'existe pas encore (jamais reçu d'USDC), `getSignaturesForAddress` renvoie
/// simplement une liste vide, sans erreur.
pub fn get_usdc_tx_history(owner_address: &str, network: &wallet_flow::SolNetwork, limit: u32) -> Result<Vec<history::TxEntry>> {
    history::usdc_history(network.rpc, &usdc_token_account(owner_address)?, limit)
}

/// Compte de jetons USDC associé (ATA, base58) de l'adresse Solana `owner_address`.
pub fn usdc_token_account(owner_address: &str) -> Result<String> {
    let owner_bytes = bs58::decode(owner_address.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let owner: [u8; 32] = owner_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = sol_spl::find_associated_token_address(&owner, &sol_spl::usdc_mint_mainnet());
    Ok(bs58::encode(ata).into_string())
}

/// `Some(lamports de rent)` si l'Associated Token Account USDC de `to_address`
/// n'existe pas encore (sa création par `send_usdc` facturera ce montant en
/// plus des frais réseau habituels), `None` si elle existe déjà — lecture
/// seule, pensée pour être appelée AVANT confirmation afin de ne jamais
/// présenter un coût caché après coup (voir `describe_possible_ata_rent` côté
/// app-tauri, qui met ce chiffre en forme pour la boîte de dialogue).
pub fn usdc_ata_rent_lamports_if_missing(to_address: &str, network: &wallet_flow::SolNetwork) -> Result<Option<u64>> {
    let to_bytes = bs58::decode(to_address.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let to_owner: [u8; 32] = to_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let dest_ata = sol_spl::find_associated_token_address(&to_owner, &sol_spl::usdc_mint_mainnet());
    let dest_ata_b58 = bs58::encode(dest_ata).into_string();
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    if rpc.account_exists(&dest_ata_b58)? {
        return Ok(None);
    }
    Ok(Some(rpc.minimum_rent_exempt_balance(165)?))
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

/// Plafond de sécurité du prix du gas sur Ethereum MAINNET (200 gwei) — trouvé
/// lors de l'audit "failles connues des hot wallets" (manipulation des frais
/// par un nœud RPC) : le prix du gas était lu auprès du nœud APRÈS la
/// confirmation, jamais affiché, jamais plafonné. Un nœud compromis annonçant
/// 100 000 gwei aurait fait payer 2,1 ETH de frais pour un simple virement,
/// le seul contrôle étant que le solde les couvre. 200 gwei laisse une marge
/// énorme sur les prix réels de mainnet ; au-delà, l'envoi est refusé plutôt
/// que de faire confiance au nœud. Pas de plafond sur les testnets (fonds sans
/// valeur, prix du gas parfois erratiques).
const MAINNET_MAX_GAS_PRICE_WEI: u128 = 200_000_000_000;
/// Plafond du tarif de frais d'un swap Bitcoin (frais choisis automatiquement,
/// voir `send_swap_btc`) — largement au-dessus des tarifs usuels, seuls des
/// pics extrêmes et brefs l'ont dépassé.
pub const BTC_SWAP_MAX_FEE_RATE_SAT_VB: u32 = 300;
/// Gas d'un virement ETH simple vers une adresse ordinaire.
pub const EVM_TRANSFER_GAS_LIMIT: u64 = 21_000;
/// Plafond du gas d'un dépôt sur le routeur THORChain : mesuré à 45 632 en
/// réel (`eth_estimateGas`, test `thorchain_router_deposit_gas_vs_intrinsic_on_
/// the_real_network`) — plus de 3x de marge, sert aussi de borne à afficher
/// comme frais maximum AVANT confirmation.
pub const EVM_SWAP_MAX_GAS_LIMIT: u64 = 150_000;

/// Prix du gas à afficher dans la boîte de confirmation PUIS à utiliser tel
/// quel pour signer (jamais relu après la confirmation) — "on signe ce qu'on
/// voit", appliqué aux frais. Refusé au-delà du plafond de sécurité sur mainnet.
pub fn evm_gas_price_for_confirmation(network: &wallet_flow::EvmNetwork) -> Result<u128> {
    let gas_price = eth_rpc::EthRpc::new(network.rpc).gas_price()?;
    check_evm_gas_price(network, gas_price)?;
    Ok(gas_price)
}

fn check_evm_gas_price(network: &wallet_flow::EvmNetwork, gas_price: u128) -> Result<()> {
    if network.chain_id == wallet_flow::ETHEREUM_MAINNET.chain_id {
        anyhow::ensure!(
            gas_price <= MAINNET_MAX_GAS_PRICE_WEI,
            "prix du gas annoncé par le nœud anormalement élevé ({} gwei, plafond de sécurité {} gwei) — envoi refusé",
            gas_price / 1_000_000_000,
            MAINNET_MAX_GAS_PRICE_WEI / 1_000_000_000
        );
    }
    Ok(())
}

/// Déverrouille le coffre (mot de passe requis : c'est la barrière d'authentification
/// avant toute dépense), signe et diffuse un virement EVM. `gas_price` : celui
/// AFFICHÉ dans la boîte de confirmation (voir `evm_gas_price_for_confirmation`),
/// utilisé tel quel — jamais un prix relu auprès du nœud après coup.
pub fn send_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    to: &str,
    amount_eth: &str,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let tx = prepare_evm_transfer(network, &address, to, amount_eth, gas_price)?;
    let raw_tx = tx.sign(&signing_key)?;
    eth_rpc::EthRpc::new(network.rpc).send_raw_transaction(&raw_tx)
}

/// Virement EVM prêt à signer depuis `address` (portefeuille logiciel ou
/// matériel, voir `hardware::send_evm`) : nonce, réseau et solde lus auprès
/// du nœud, réseau vérifié, solde suffisant pour montant + frais maximum.
pub(crate) fn prepare_evm_transfer(
    network: &wallet_flow::EvmNetwork,
    address: &[u8; 20],
    to: &str,
    amount_eth: &str,
    gas_price: u128,
) -> Result<eth_tx::EthTx> {
    check_evm_gas_price(network, gas_price)?;
    let to_bytes = wallet_flow::parse_evm_address(to)?;
    let value = wallet_flow::parse_eth_to_wei(amount_eth)?;

    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let address_str = derivation::format_address(address);
    // Les 3 appels ci-dessous sont des lectures RPC indépendantes (aucune ne dépend
    // du résultat d'une autre) : les lancer en parallèle plutôt que l'une après
    // l'autre réduit la latence perçue d'un envoi ETH à ~1x un aller-retour réseau.
    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce_handle = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id_handle = scope.spawn(|| rpc.chain_id());
        let balance_handle = scope.spawn(|| rpc.balance(&address_str));
        (
            nonce_handle.join().expect("le thread nonce ne doit pas paniquer"),
            chain_id_handle.join().expect("le thread chain_id ne doit pas paniquer"),
            balance_handle.join().expect("le thread balance ne doit pas paniquer"),
        )
    });
    let nonce = nonce?;
    let chain_id = chain_id?;
    let balance = balance?;
    // Un nœud qui répondrait un autre réseau que celui choisi ferait signer une
    // transaction rejouable ailleurs (EIP-155 lie la signature au chain_id).
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );

    // Contrairement à Bitcoin (UTXO, vérifié dans `send_btc`), rien ne vérifiait ici
    // que le solde couvre montant + frais de gas avant de signer et diffuser : sans
    // ce contrôle, l'erreur ne remonte que via le rejet du nœud RPC après signature,
    // ce qui masque la vraie cause côté utilisateur ("fonds insuffisants") derrière un
    // message d'erreur RPC générique.
    let gas_cost = gas_price
        .checked_mul(u128::from(EVM_TRANSFER_GAS_LIMIT))
        .context("gas_price * gas_limit dépasse la capacité représentable")?;
    let total_needed = value
        .checked_add(gas_cost)
        .context("montant + frais de gas dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
    );

    Ok(eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit: EVM_TRANSFER_GAS_LIMIT,
        to: to_bytes,
        value,
        chain_id,
        data: Vec::new(),
    })
}

/// Déverrouille le coffre, signe et diffuse un swap Ethereum -> THORChain :
/// contrairement à un envoi normal, la transaction n'est PAS un simple
/// transfert vers `quote.inbound_address`, mais un appel au contrat
/// "THORChain Router" (`quote.router` — jamais `inbound_address` directement
/// sur une chaîne EVM, voir `thorchain_rpc::SwapQuote`) : `depositWithExpiry`
/// avec `asset` = adresse nulle (ETH natif) et `amount` ignoré côté contrat
/// (c'est `msg.value`, donc `value`, qui compte réellement). `expiration` :
/// horodatage Unix + marge large (1h), comme documenté par THORChain pour
/// éviter qu'un appel resté longtemps en attente ne s'exécute à un cours
/// périmé. `gas_price` : celui AFFICHÉ dans la boîte de confirmation (voir
/// `evm_gas_price_for_confirmation`), utilisé tel quel.
pub fn send_swap_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    quote: &thorchain_rpc::SwapQuote,
    amount_eth: &str,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let router = quote
        .router
        .as_deref()
        .context("devis THORChain sans adresse de routeur (attendu pour un swap EVM)")?;
    let router_bytes = wallet_flow::parse_evm_address(router)?;
    let vault_bytes = wallet_flow::parse_evm_address(&quote.inbound_address)?;
    // ETH natif = adresse nulle côté contrat (PAS la convention "0xEeee...Eeee"
    // utilisée par d'autres protocoles — vérifié en lisant le vrai code source
    // vérifié du routeur déployé, via Sourcify : `if(asset == address(0))`,
    // voir `deposit()` dans le contrat THORChain_Router). `amount` est alors
    // ignoré par le contrat (c'est `msg.value`, donc `value` plus bas, qui
    // compte réellement).
    let native_asset_bytes = [0u8; 20];

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let value = wallet_flow::parse_eth_to_wei(amount_eth)?;

    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let address_str = derivation::format_address(&address);
    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce_handle = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id_handle = scope.spawn(|| rpc.chain_id());
        let balance_handle = scope.spawn(|| rpc.balance(&address_str));
        (
            nonce_handle.join().expect("le thread nonce ne doit pas paniquer"),
            chain_id_handle.join().expect("le thread chain_id ne doit pas paniquer"),
            balance_handle.join().expect("le thread balance ne doit pas paniquer"),
        )
    });
    let nonce = nonce?;
    let chain_id = chain_id?;
    let balance = balance?;
    anyhow::ensure!(
        chain_id == network.chain_id,
        "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
        network.chain_id
    );

    let expiration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("horloge système invalide")?
        .as_secs()
        + 3600;

    let calldata = eth_tx::thorchain_deposit_calldata(&vault_bytes, &native_asset_bytes, 0, &quote.memo, expiration);
    // Gas RÉELLEMENT nécessaire à l'exécution du contrat (+20 %), pas le gas
    // intrinsèque — trouvé lors du même audit : la version précédente prenait
    // `intrinsic_gas` (23 844 mesuré) comme limite, alors qu'un dépôt réel sur
    // le routeur en consomme 45 632 (`eth_estimateGas` sur mainnet) : CHAQUE
    // swap ETH aurait manqué de gas et échoué on-chain, en brûlant les frais,
    // sans jamais rien échanger. Borné par `EVM_SWAP_MAX_GAS_LIMIT`, le
    // maximum affiché dans la boîte de confirmation.
    let estimated = rpc.estimate_gas(&address_str, router, value, &calldata)?;
    let gas_limit = estimated
        .saturating_mul(12)
        .div_ceil(10)
        .max(eth_tx::intrinsic_gas(&calldata));
    anyhow::ensure!(
        gas_limit <= EVM_SWAP_MAX_GAS_LIMIT,
        "gas estimé anormalement élevé pour un dépôt THORChain ({gas_limit}, maximum {EVM_SWAP_MAX_GAS_LIMIT}) — swap refusé"
    );

    let gas_cost = gas_price
        .checked_mul(u128::from(gas_limit))
        .context("gas_price * gas_limit dépasse la capacité représentable")?;
    let total_needed = value
        .checked_add(gas_cost)
        .context("montant + frais de gas dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
    );

    let tx = eth_tx::EthTx {
        nonce,
        gas_price,
        gas_limit,
        to: router_bytes,
        value,
        chain_id,
        data: calldata,
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

/// Monnaie d'un envoi Bitcoin qui consomme `total_sat` : fonds suffisants
/// exigés ; 0 sous le seuil de poussière (le reliquat part alors en frais).
pub(crate) fn btc_change(total_sat: u64, amount_sat: u64, fee_sat: u64) -> Result<u64> {
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
        "fonds insuffisants : {total_sat} sat confirmés disponibles, {amount_sat} sat + {fee_sat} sat de frais requis"
    );
    let remaining = total_sat - total_needed;
    Ok(if remaining > DUST_THRESHOLD_SAT { remaining } else { 0 })
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
    estimate_btc_fees_for(&[address], network)
}

/// `estimate_btc_fees` pour un envoi qui consomme les UTXOs de plusieurs
/// adresses (compte Ledger : réception et monnaie, voir `hardware::send_btc`).
pub(crate) fn estimate_btc_fees_for(addresses: &[&str], network: &wallet_flow::BtcNetwork) -> Result<BtcFeeEstimate> {
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    // Les UTXOs des adresses et les estimations de frais du réseau sont des appels
    // HTTP indépendants (aucun ne dépend du résultat d'un autre) : les lancer en
    // parallèle plutôt que l'un après l'autre coupe environ de moitié la latence
    // perçue à l'ouverture de la modale d'envoi Bitcoin.
    let (utxos, estimates) = std::thread::scope(|scope| {
        let utxo_handles: Vec<_> = addresses.iter().map(|a| scope.spawn(|| esplora.utxos(a))).collect();
        let estimates_handle = scope.spawn(|| esplora.fee_estimates());
        (
            utxo_handles
                .into_iter()
                .map(|h| h.join().expect("le thread UTXOs ne doit pas paniquer"))
                .collect::<Result<Vec<_>>>(),
            estimates_handle.join().expect("le thread frais ne doit pas paniquer"),
        )
    });
    let num_inputs = utxos?.iter().map(Vec::len).sum::<usize>().max(1);
    let vsize = crate::btc_tx::estimate_p2wpkh_vsize(num_inputs, 2) as f64;
    let estimates = estimates?;

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
    let change_sat = btc_change(total_sat, amount_sat, fee_sat)?;

    let tx = crate::btc_tx::BtcTx {
        inputs: utxos,
        to_hash160,
        value_sat: amount_sat,
        change_hash160: hash160,
        change_sat,
        op_return_data: None,
    };
    let raw_tx = tx.sign(&signing_key, &hash160)?;
    esplora.broadcast(&raw_tx)
}

/// Déverrouille le coffre, signe et diffuse un swap Bitcoin -> THORChain :
/// même mécanique que `send_btc`, mais l'envoi part vers l'`inbound_address`
/// du devis (pas l'adresse tapée par l'utilisateur) et porte le memo du swap
/// dans une sortie OP_RETURN. Contrairement à `send_btc`, les frais ne sont
/// pas choisis par l'appelant (pas de sélecteur rapide/moyen/lent dans la
/// modale de swap, déjà chargée d'étapes) : la cible "moyenne" est utilisée
/// automatiquement, cohérente avec le reste du flux de swap (Jupiter/THORChain
/// choisissent aussi leurs propres frais réseau sans intervention).
pub fn send_swap_btc(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::BtcNetwork,
    quote: &thorchain_rpc::SwapQuote,
    amount_btc: &str,
    profile_index: u32,
) -> Result<String> {
    anyhow::ensure!(
        quote.memo.as_bytes().len() <= 80,
        "memo THORChain trop long pour une sortie OP_RETURN standard ({} octets)",
        quote.memo.as_bytes().len()
    );

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, hash160) = (network.derive_key)(&seed, profile_index)?;

    let address = (network.format_address)(&hash160)?;
    let to_hash160 = (network.parse_address)(&quote.inbound_address)?;
    let amount_sat = wallet_flow::parse_btc_to_sat(amount_btc)?;

    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let (utxos, estimates) = std::thread::scope(|scope| {
        let utxos_handle = scope.spawn(|| esplora.utxos(&address));
        let estimates_handle = scope.spawn(|| esplora.fee_estimates());
        (
            utxos_handle.join().expect("le thread UTXOs ne doit pas paniquer"),
            estimates_handle.join().expect("le thread d'estimation de frais ne doit pas paniquer"),
        )
    });
    let utxos = utxos?;
    let estimates = estimates?;
    let total_sat: u64 = utxos.iter().map(|u| u.value_sat).sum();

    // Poids approximatif d'une sortie OP_RETURN (script <= 80 octets) : 8
    // (valeur) + 1 (longueur script) + jusqu'à 82 (OP_RETURN + pushdata +
    // données) => ~91 octets, contre ~31 pour une sortie P2WPKH classique.
    // `estimate_p2wpkh_vsize` sous-estimerait donc légèrement les frais réels
    // ici ; la marge (~60 vbytes) reste négligeable face à la volatilité des
    // frais réseau eux-mêmes.
    let vsize = crate::btc_tx::estimate_p2wpkh_vsize(utxos.len(), 2) as f64;
    let fee_rate = fee_rate_for_target(&estimates, 3);
    // Tarif lu auprès d'Esplora sans intervention de l'utilisateur (contrairement
    // à `send_btc`, où il choisit un palier affiché en sats) : plafonné pour qu'un
    // serveur compromis ne puisse pas gonfler les frais à volonté — même famille
    // que le plafond du prix du gas EVM (`MAINNET_MAX_GAS_PRICE_WEI`). Plafond
    // affiché dans la boîte de confirmation du swap.
    anyhow::ensure!(
        fee_rate.is_finite() && fee_rate <= BTC_SWAP_MAX_FEE_RATE_SAT_VB as f64,
        "tarif de frais Bitcoin anormalement élevé ({fee_rate:.1} sat/vB, plafond {BTC_SWAP_MAX_FEE_RATE_SAT_VB}) — swap refusé"
    );
    let fee_sat = (fee_rate * vsize).ceil() as u64;

    const DUST_THRESHOLD_SAT: u64 = 1_000;
    let total_needed = amount_sat
        .checked_add(fee_sat)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= total_sat,
        "fonds insuffisants : {total_sat} sat confirmés disponibles, {amount_sat} sat + {fee_sat} sat de frais requis"
    );
    let remaining = total_sat - total_needed;
    let change_sat = if remaining > DUST_THRESHOLD_SAT { remaining } else { 0 };

    let tx = crate::btc_tx::BtcTx {
        inputs: utxos,
        to_hash160,
        value_sat: amount_sat,
        change_hash160: hash160,
        change_sat,
        op_return_data: Some(quote.memo.as_bytes().to_vec()),
    };
    let raw_tx = tx.sign(&signing_key, &hash160)?;
    esplora.broadcast(&raw_tx)
}

/// Déverrouille le coffre, signe et diffuse un virement Solana.
/// Vérifie qu'une adresse Solana est bien un PORTEFEUILLE avant d'y envoyer
/// des fonds — trouvé lors de l'audit "failles connues des hot wallets"
/// (classe "envoi vers un type d'adresse où les fonds sont perdus", piège
/// classique de Solana contre lequel Phantom/Solflare avertissent). Aucune
/// vérification n'existait : coller par erreur l'adresse d'un COMPTE DE
/// JETONS (celle que montrent souvent les explorateurs) au lieu de celle du
/// portefeuille faisait créer un compte USDC détenu par... ce compte de
/// jetons, que personne ne pourra jamais signer — fonds définitivement perdus.
/// À appeler AVANT la confirmation (voir app-tauri), et de nouveau juste avant
/// de signer (défense en profondeur).
pub fn check_solana_recipient(to: &str, network: &wallet_flow::SolNetwork) -> Result<()> {
    let pubkey: [u8; 32] = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let state = sol_rpc::SolRpc::new(network.rpc)
        .multiple_accounts(&[bs58::encode(pubkey).into_string()])?
        .into_iter()
        .next()
        .flatten();
    classify_solana_recipient(&pubkey, state.as_ref())
}

fn classify_solana_recipient(pubkey: &[u8; 32], state: Option<&sol_rpc::AccountState>) -> Result<()> {
    match state {
        // Portefeuille (ou coffre multisig, lui aussi détenu par le programme système).
        Some(s) if s.owner == SYSTEM_PROGRAM_ID => Ok(()),
        Some(s) if s.owner == TOKEN_PROGRAM_ID || s.owner == TOKEN_2022_PROGRAM_ID => anyhow::bail!(
            "cette adresse est un compte de jetons (ou un mint), pas un portefeuille : les fonds y seraient perdus. Demandez l'adresse du PORTEFEUILLE du destinataire."
        ),
        Some(_) => anyhow::bail!("cette adresse appartient à un programme, pas à un portefeuille — envoi refusé (fonds probablement irrécupérables)"),
        None if sol_spl::is_on_curve(pubkey) => Ok(()), // portefeuille neuf, jamais utilisé
        None => anyhow::bail!(
            "cette adresse n'a aucune clé privée (dérivée d'un programme) et n'a jamais été utilisée — les fonds y seraient très probablement perdus"
        ),
    }
}

// --- État d'une adresse destinataire sur la blockchain ----------------------
// Demandé explicitement par l'utilisateur : prévenir, dans la boîte de
// confirmation native, qu'une adresse destinataire n'a jamais servi (adresse
// mal recopiée, ou fraîchement générée par un escroc) ou qu'elle est vide.
// Lecture seule, AVANT la confirmation ; un échec réseau n'empêche pas l'envoi
// (l'app affiche alors "impossible à vérifier" plutôt qu'un silence rassurant).

/// Voir le bloc ci-dessus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientActivity {
    /// Aucune trace sur la blockchain : adresse jamais utilisée (EVM : aucune
    /// transaction envoyée et aucun ETH — un nœud EVM n'expose pas les
    /// transactions REÇUES, voir `history::evm_history`).
    Unused,
    /// Déjà utilisée, mais ne détient aucun fonds actuellement.
    Empty,
    /// Détient des fonds.
    Funded,
}

fn classify_evm_activity(nonce: u64, balance_wei: u128) -> RecipientActivity {
    if balance_wei > 0 {
        RecipientActivity::Funded
    } else if nonce == 0 {
        RecipientActivity::Unused
    } else {
        RecipientActivity::Empty
    }
}

fn classify_btc_activity(stats: &btc_rpc::AddressStats) -> RecipientActivity {
    if stats.balance_sat > 0 {
        RecipientActivity::Funded
    } else if stats.tx_count == 0 {
        RecipientActivity::Unused
    } else {
        RecipientActivity::Empty
    }
}

/// `lamports` : `None` si le compte n'existe pas on-chain (jamais utilisé OU
/// vidé : Solana supprime un compte à 0 lamport), d'où `has_history` pour
/// distinguer les deux.
fn classify_sol_activity(lamports: Option<u64>, has_history: bool) -> RecipientActivity {
    match lamports {
        Some(l) if l > 0 => RecipientActivity::Funded,
        _ if has_history => RecipientActivity::Empty,
        _ => RecipientActivity::Unused,
    }
}

/// Refuse AVANT la boîte de confirmation une adresse EVM mal formée (ou au
/// checksum EIP-55 faux) — elle n'était jusqu'ici rejetée qu'après la
/// confirmation, au moment de signer.
pub fn validate_evm_recipient(to: &str) -> Result<()> {
    wallet_flow::parse_evm_address(to).map(|_| ())
}

/// Même principe que `validate_evm_recipient`, pour Bitcoin.
pub fn validate_btc_recipient(to: &str, network: &wallet_flow::BtcNetwork) -> Result<()> {
    (network.parse_address)(to).map(|_| ())
}

pub fn evm_recipient_activity(to: &str, network: &wallet_flow::EvmNetwork) -> Result<RecipientActivity> {
    let address = derivation::format_address(&wallet_flow::parse_evm_address(to)?);
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let (nonce, balance) = std::thread::scope(|scope| {
        let nonce_handle = scope.spawn(|| rpc.nonce(&address));
        let balance_handle = scope.spawn(|| rpc.balance(&address));
        (
            nonce_handle.join().expect("le thread nonce ne doit pas paniquer"),
            balance_handle.join().expect("le thread balance ne doit pas paniquer"),
        )
    });
    Ok(classify_evm_activity(nonce?, balance?))
}

pub fn btc_recipient_activity(to: &str, network: &wallet_flow::BtcNetwork) -> Result<RecipientActivity> {
    // Format validé d'abord : l'adresse est insérée dans le chemin de l'URL.
    (network.parse_address)(to)?;
    let stats = btc_rpc::EsploraClient::new(network.esplora_base).address_stats(&to.trim().to_ascii_lowercase())?;
    Ok(classify_btc_activity(&stats))
}

/// Pour un envoi USDC aussi : c'est le PORTEFEUILLE destinataire qui est
/// évalué (l'absence de compte USDC est déjà signalée à part, avec son coût).
pub fn sol_recipient_activity(to: &str, network: &wallet_flow::SolNetwork) -> Result<RecipientActivity> {
    let pubkey: [u8; 32] = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let address = bs58::encode(pubkey).into_string();
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let lamports = rpc.multiple_accounts(std::slice::from_ref(&address))?.into_iter().next().flatten().map(|s| s.lamports);
    let has_history = if lamports.is_some_and(|l| l > 0) { true } else { rpc.has_any_signature(&address)? };
    Ok(classify_sol_activity(lamports, has_history))
}

/// Envoi USDC : un portefeuille peut détenir de l'USDC sans aucun SOL (son
/// compte principal est alors purgé, seul son compte USDC existe) — le dire
/// "vide" serait faux. Détient de l'USDC => `Funded` ; un compte USDC existant
/// même vide prouve que l'adresse a servi => au moins `Empty`.
pub fn usdc_recipient_activity(to: &str, network: &wallet_flow::SolNetwork) -> Result<RecipientActivity> {
    let owner: [u8; 32] = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = bs58::encode(sol_spl::find_associated_token_address(&owner, &sol_spl::usdc_mint_mainnet())).into_string();
    let usdc_balance = sol_rpc::SolRpc::new(network.rpc).token_account_balance(&ata)?;
    if usdc_balance.is_some_and(|b| b > 0) {
        return Ok(RecipientActivity::Funded);
    }
    Ok(match (sol_recipient_activity(to, network)?, usdc_balance) {
        (RecipientActivity::Unused, Some(_)) => RecipientActivity::Empty,
        (wallet, _) => wallet,
    })
}

pub fn send_sol(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    to: &str,
    amount_sol: &str,
    profile_index: u32,
) -> Result<String> {
    check_solana_recipient(to, network)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let message = prepare_sol_transfer(network, &signing_key.verifying_key().to_bytes(), to, amount_sol)?;
    let raw_tx = sol_tx::assemble_transaction(&ed25519_dalek::Signer::sign(&signing_key, &message).to_bytes(), &message);
    sol_rpc::SolRpc::new(network.rpc).send_transaction(&raw_tx)
}

/// Message d'un virement SOL prêt à signer depuis `from_pubkey` (portefeuille
/// logiciel ou matériel, voir `hardware::send_sol`) : solde suffisant pour
/// montant + frais, dernier blockhash.
pub(crate) fn prepare_sol_transfer(network: &wallet_flow::SolNetwork, from_pubkey: &[u8; 32], to: &str, amount_sol: &str) -> Result<Vec<u8>> {
    let to_bytes = bs58::decode(to.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let to_pubkey: [u8; 32] = to_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let lamports = wallet_flow::parse_sol_to_lamports(amount_sol)?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let from_address = bs58::encode(from_pubkey).into_string();
    // Le solde et le dernier blockhash sont deux lectures RPC indépendantes : les
    // lancer en parallèle plutôt que l'une après l'autre réduit la latence perçue
    // d'un envoi SOL d'environ moitié.
    let (balance, recent_blockhash) = std::thread::scope(|scope| {
        let balance_handle = scope.spawn(|| rpc.balance_lamports(&from_address));
        let blockhash_handle = scope.spawn(|| rpc.latest_blockhash());
        (
            balance_handle.join().expect("le thread balance ne doit pas paniquer"),
            blockhash_handle.join().expect("le thread blockhash ne doit pas paniquer"),
        )
    });
    let balance = balance?;
    let recent_blockhash = recent_blockhash?;

    // Même contrôle que côté CLI (`wallet_flow::send_sol`), absent ici jusqu'à présent :
    // sans lui, un montant + frais supérieur au solde n'était détecté qu'au rejet par
    // le nœud RPC après signature, au lieu d'un message clair "fonds insuffisants".
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let total_needed = lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} lamports disponibles, {lamports} lamports + {SOL_FEE_LAMPORTS} lamports de frais requis"
    );

    Ok(sol_tx::build_message(from_pubkey, &[sol_tx::transfer_instruction(from_pubkey, &to_pubkey, lamports)], &recent_blockhash))
}

/// Traduit un identifiant de coin interne à l'app ("evm"/"btc"/"sol", les
/// mêmes que `data-coin` côté frontend) en code d'actif natif THORChain +
/// décimales natives de la chaîne. USDC volontairement absent : la notation
/// THORChain pour un jeton non natif inclut son adresse de contrat/mint, pas
/// seulement un ticker — chantier séparé (voir le plan swap), pas cette v1.
fn thorchain_asset_for_coin(coin: &str) -> Result<(&'static str, u32)> {
    match coin {
        "sol" => Ok(("SOL.SOL", 9)),
        "btc" => Ok(("BTC.BTC", 8)),
        "evm" => Ok(("ETH.ETH", 18)),
        other => anyhow::bail!("actif non pris en charge pour le swap : {other}"),
    }
}

fn parse_swap_amount_for_coin(coin: &str, amount: &str) -> Result<u128> {
    match coin {
        "sol" => wallet_flow::parse_sol_to_lamports(amount).map(u128::from),
        "btc" => wallet_flow::parse_btc_to_sat(amount).map(u128::from),
        "evm" => wallet_flow::parse_eth_to_wei(amount),
        "usdc" => wallet_flow::parse_usdc_to_micros(amount).map(u128::from),
        other => anyhow::bail!("actif non pris en charge pour le swap : {other}"),
    }
}

/// Montant à AFFICHER dans une boîte de confirmation native, reconstruit
/// depuis la valeur exacte qui sera signée (plus petite unité) plutôt que
/// recopié depuis la saisie — trouvé lors du 22ᵉ passage : les fonctions de
/// parsing tolèrent des formes que l'œil lit mal (`"0.+5"` = 0,05 BTC, des
/// retours à la ligne en tête ou en fin, retirés par `trim`), si bien que le
/// texte affiché pouvait différer de ce qui part réellement. `coin` : "evm",
/// "btc", "sol" ou "usdc". Le résultat se re-parse en exactement la même
/// valeur : l'appelant l'utilise pour l'affichage ET pour la signature.
pub fn canonical_amount(coin: &str, amount: &str) -> Result<String> {
    let decimals: usize = match coin {
        "evm" => 18,
        "btc" => 8,
        "sol" => 9,
        "usdc" => 6,
        other => anyhow::bail!("actif non pris en charge pour le swap : {other}"),
    };
    let minor = parse_swap_amount_for_coin(coin, amount)?;
    let unit = 10u128.pow(decimals as u32);
    let (whole, frac) = (minor / unit, minor % unit);
    if frac == 0 {
        return Ok(whole.to_string());
    }
    let frac = format!("{frac:0decimals$}");
    Ok(format!("{whole}.{}", frac.trim_end_matches('0')))
}

/// Mint Solana (32 octets) pour un identifiant de coin interne — seuls
/// "sol"/"usdc" ont un sens ici (swap Jupiter, même chaîne uniquement, voir
/// jupiter_rpc.rs).
fn jupiter_mint_bytes_for_coin(coin: &str) -> Result<[u8; 32]> {
    match coin {
        "sol" => bs58::decode(jupiter_rpc::SOL_MINT)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("mint SOL mal formé (bug de compilation)"),
        "usdc" => Ok(sol_spl::usdc_mint_mainnet()),
        other => anyhow::bail!("actif non pris en charge pour le swap Jupiter : {other}"),
    }
}

fn jupiter_mint_for_coin(coin: &str) -> Result<String> {
    Ok(bs58::encode(jupiter_mint_bytes_for_coin(coin)?).into_string())
}

/// Obtient un devis Jupiter (lecture seule, aucun secret impliqué) — montant
/// de sortie attendu, dans la plus petite unité de l'actif de destination.
/// `amount` dans l'unité humaine de l'actif SOURCE, comme partout ailleurs
/// dans cette API.
pub fn get_jupiter_quote(from_coin: &str, to_coin: &str, amount: &str, slippage_bps: u32) -> Result<u64> {
    let input_mint = jupiter_mint_for_coin(from_coin)?;
    let output_mint = jupiter_mint_for_coin(to_coin)?;
    let amount_native = parse_swap_amount_for_coin(from_coin, amount)?;
    let amount_native: u64 = amount_native.try_into().context("montant trop grand")?;
    Ok(jupiter_rpc::quote(&input_mint, &output_mint, amount_native, slippage_bps)?.out_amount)
}

/// Envoie un swap SOL <-> USDC via Jupiter (même chaîne, contrairement au
/// swap cross-chain via THORChain) — voir jupiter_rpc.rs pour le contexte
/// complet, notamment pourquoi la transaction elle-même n'est pas
/// reconstruite à la main ici (seulement vérifiée puis signée).
pub fn send_jupiter_swap(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    from_coin: &str,
    to_coin: &str,
    amount: &str,
    slippage_bps: u32,
    shown_out_amount: u64,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let owner_address = bs58::encode(owner).into_string();

    let input_mint = jupiter_mint_for_coin(from_coin)?;
    let output_mint = jupiter_mint_for_coin(to_coin)?;
    let amount_native: u64 = parse_swap_amount_for_coin(from_coin, amount)?
        .try_into()
        .context("montant trop grand")?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let sol_balance = rpc.balance_lamports(&owner_address)?;

    // Réserve conservatrice pour les frais réseau/priorité de calcul : pas de
    // valeur exacte disponible avant construction de la transaction, ce
    // plancher reste volontairement généreux plutôt que précis.
    const SOL_FEE_RESERVE_LAMPORTS: u64 = 50_000;
    let mut reserve = SOL_FEE_RESERVE_LAMPORTS;

    // Swapper depuis du SOL natif l'enveloppe d'abord en jeton SPL "wSOL" —
    // exige de financer un compte de jetons temporaire au minimum
    // d'exemption de rent, EN PLUS du montant du swap lui-même (récupéré à la
    // clôture de ce même compte en fin de transaction, mais nécessaire un
    // instant plus tôt dans la même transaction). Interrogé en direct plutôt
    // que codé en dur (paramètre réseau qui évolue), même principe que pour
    // l'ATA USDC (voir send_usdc) — un plancher fixe sous-estimerait
    // largement ce besoin réel.
    if from_coin == "sol" {
        reserve = reserve
            .checked_add(rpc.minimum_rent_exempt_balance(165)?)
            .context("réserve de frais dépasse la capacité représentable")?;
    }
    // Le compte de jetons de destination peut aussi devoir être créé (Jupiter
    // l'inclut alors dans la transaction, voir CreateIdempotent côté ATA) :
    // même coût de rent si le compte n'existe pas encore.
    if to_coin != "sol" {
        let output_mint = jupiter_mint_bytes_for_coin(to_coin)?;
        let dest_ata = sol_spl::find_associated_token_address(&owner, &output_mint);
        let dest_ata_b58 = bs58::encode(dest_ata).into_string();
        if !rpc.account_exists(&dest_ata_b58)? {
            reserve = reserve
                .checked_add(rpc.minimum_rent_exempt_balance(165)?)
                .context("réserve de frais dépasse la capacité représentable")?;
        }
    }

    if from_coin == "sol" {
        let total_needed = amount_native.checked_add(reserve).context("montant + frais dépasse la capacité représentable")?;
        anyhow::ensure!(
            total_needed <= sol_balance,
            "fonds insuffisants : {sol_balance} lamports disponibles, {amount_native} lamports + ~{reserve} lamports de frais/rent requis"
        );
    } else {
        anyhow::ensure!(
            reserve <= sol_balance,
            "SOL insuffisant pour les frais/rent : {sol_balance} lamports disponibles, ~{reserve} lamports requis"
        );
        // Source autre que SOL natif (USDC) : le solde de jetons lui-même
        // n'est jamais couvert par la vérification de solde SOL ci-dessus,
        // qui ne porte que sur les frais/rent — vérifié séparément ici.
        let input_mint_bytes = jupiter_mint_bytes_for_coin(from_coin)?;
        let source_ata = sol_spl::find_associated_token_address(&owner, &input_mint_bytes);
        let source_ata_b58 = bs58::encode(source_ata).into_string();
        let source_balance = rpc.token_account_balance(&source_ata_b58)?.unwrap_or(0);
        anyhow::ensure!(
            amount_native <= source_balance,
            "fonds insuffisants : {source_balance} unité(s) disponibles, {amount_native} unité(s) requises"
        );
    }

    let quote = jupiter_rpc::quote(&input_mint, &output_mint, amount_native, slippage_bps)?;
    let raw_tx = jupiter_rpc::build_swap_transaction(&quote, &owner_address)?;

    // Simulation de la transaction ENTIÈREMENT CONSTRUITE, avec vérification de
    // ses effets réels sur les comptes de l'utilisateur (voir
    // `check_swap_effects`) — AVANT de la signer. Trouvé lors du 22ᵉ passage :
    // la version précédente signait d'abord, puis envoyait la transaction
    // SIGNÉE au nœud RPC pour la simulation — une transaction malveillante
    // rejetée ensuite par la vérification avait donc déjà quitté l'app,
    // signée et diffusable par quiconque la voyait passer. La simulation ne
    // vérifie aucune signature (`sigVerify: false`) : le message non signé
    // suffit, et c'est exactement ce message qui est signé juste après.
    let min_out = shown_out_amount.saturating_mul(u64::from(10_000 - slippage_bps.min(10_000))) / 10_000;
    check_swap_effects(&rpc, &raw_tx, &swap_effect_limits(owner, from_coin, amount_native, to_coin, min_out)?)?;

    let signed_tx = jupiter_rpc::sign_swap_transaction(&raw_tx, &signing_key, &owner)?;
    rpc.send_transaction(&signed_tx)
}

// --- Vérification des effets d'une transaction construite par un tiers -------
// Trouvé lors de l'audit "failles connues des hot wallets" (classe "signature
// aveugle d'une transaction construite par un tiers") : pour un swap Jupiter,
// la SEULE vérification avant signature portait sur le payeur de frais. Une
// API Jupiter compromise pouvait renvoyer une transaction avec le bon payeur
// de frais MAIS aussi un transfert de tout le SOL vers elle, un `Approve`
// (délégué qui pourra vider l'USDC plus tard), un `SetAuthority` (vol du
// compte USDC lui-même) ou un `Assign` du compte principal — tout aurait
// été signé. Désormais : simulation par le nœud RPC (tiers INDÉPENDANT de
// Jupiter) avec l'état des comptes APRÈS exécution, comparé à l'état avant.

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub(crate) const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub(crate) const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: &str = "AddressLookupTab1e1111111111111111111111111";
/// Taille de l'en-tête d'une table de correspondance d'adresses avant la liste
/// de clés (discriminant 4 + deactivation_slot 8 + last_extended_slot 8 +
/// start_index 1 + authority Option<Pubkey> 33 + padding 2).
const LOOKUP_TABLE_META_SIZE: usize = 56;
/// Budget maximal de frais réseau (frais de base + priorité) toléré au-delà
/// du montant échangé : 0,005 SOL. Coût réel mesuré sur de vrais swaps
/// mainnet simulés (test `jupiter_swap_effects_pass_on_real_mainnet_swaps`) :
/// entre ~25 000 et ~490 000 lamports selon la route et la congestion, et les
/// frais de priorité sont plafonnés à 1 000 000 lamports côté Jupiter (voir
/// `jupiter_rpc::build_swap_transaction`) — ce budget ne peut donc pas être
/// atteint légitimement, et borne ce qu'une transaction malveillante pourrait
/// détourner en frais/pourboires.
const JUPITER_SWAP_FEE_BUDGET_LAMPORTS: u64 = 5_000_000;

/// Ce que l'utilisateur a accepté de perdre dans le swap, et rien de plus.
struct SwapEffectLimits {
    user: [u8; 32],
    /// Perte maximale en lamports, TOUS comptes de l'utilisateur confondus
    /// (principal + comptes de jetons, rent incluse) : montant de SOL vendu +
    /// budget de frais. Créer un compte de jetons pour l'utilisateur ou
    /// envelopper/désenvelopper du SOL déplace des lamports entre SES comptes
    /// sans en perdre, d'où ce total plutôt qu'un contrôle compte par compte.
    max_lamport_loss: u64,
    /// Jeton vendu (hors SOL natif) et quantité maximale qui peut en sortir.
    input_token: Option<([u8; 32], u64)>,
    /// Ce que l'utilisateur doit AU MOINS recevoir — trouvé lors du même audit :
    /// sans ce plancher, borner les PERTES ne suffisait pas, une transaction
    /// malveillante pouvait prendre le SOL vendu (perte "autorisée") et ne rien
    /// rendre (route via un pool contrôlé par l'attaquant).
    min_output: MinOutput,
}

enum MinOutput {
    /// SOL natif : vérifié via le total des lamports de l'utilisateur.
    Lamports(u64),
    /// Jeton SPL (mint, quantité minimale).
    Token([u8; 32], u64),
}

fn swap_effect_limits(owner: [u8; 32], from_coin: &str, amount_native: u64, to_coin: &str, min_out: u64) -> Result<SwapEffectLimits> {
    let sold_lamports = if from_coin == "sol" { amount_native } else { 0 };
    let input_token = if from_coin == "sol" { None } else { Some((jupiter_mint_bytes_for_coin(from_coin)?, amount_native)) };
    let min_output = if to_coin == "sol" {
        MinOutput::Lamports(min_out)
    } else {
        MinOutput::Token(jupiter_mint_bytes_for_coin(to_coin)?, min_out)
    };
    Ok(SwapEffectLimits {
        user: owner,
        max_lamport_loss: sold_lamports
            .checked_add(JUPITER_SWAP_FEE_BUDGET_LAMPORTS)
            .context("montant + budget de frais dépasse la capacité représentable")?,
        input_token,
        min_output,
    })
}

/// Vue sur un compte de jetons SPL (programme Token ou Token-2022). Disposition
/// de base identique pour les deux : mint 0..32, propriétaire 32..64, montant
/// 64..72, délégué COption 72..108, autorité de fermeture COption 129..165.
struct TokenAccountView {
    mint: [u8; 32],
    owner: [u8; 32],
    amount: u64,
    delegate: [u8; 36],
    close_authority: [u8; 36],
}

fn parse_token_account(state: &sol_rpc::AccountState) -> Option<TokenAccountView> {
    if state.owner != TOKEN_PROGRAM_ID && state.owner != TOKEN_2022_PROGRAM_ID {
        return None;
    }
    // Compte de jetons : exactement 165 octets, ou plus avec extensions
    // Token-2022 — auquel cas l'octet 165 vaut 2 (AccountType::Account ; un
    // mint Token-2022 avec extensions dépasse aussi 165 octets mais vaut 1).
    let data = &state.data;
    if !(data.len() == 165 || (data.len() > 165 && data[165] == 2)) {
        return None;
    }
    Some(TokenAccountView {
        mint: data[0..32].try_into().ok()?,
        owner: data[32..64].try_into().ok()?,
        amount: u64::from_le_bytes(data[64..72].try_into().ok()?),
        delegate: data[72..108].try_into().ok()?,
        close_authority: data[129..165].try_into().ok()?,
    })
}

/// Bilan d'une transaction simulée sur les comptes de l'utilisateur : lamports
/// (compte principal + rent de ses comptes de jetons, wSOL compris) et jetons
/// par mint (hors wSOL, déjà compté en lamports), avant et après.
pub(crate) struct UserEffects {
    pub lamports_pre: u128,
    pub lamports_post: u128,
    pub tokens_pre: std::collections::HashMap<[u8; 32], u128>,
    pub tokens_post: std::collections::HashMap<[u8; 32], u128>,
}

/// Effets d'une transaction sur les comptes de `user`, à partir de l'état de
/// ses comptes inscriptibles avant (`pre`) et après simulation (`post`),
/// alignés sur `addresses` — avec les REFUS STRUCTURELS qui ne dépendent pas
/// de ce que la transaction est censée faire (Assign, délégué, changement de
/// propriétaire, compte cédé, compte non standard). Partagé par le swap
/// Jupiter (`verify_swap_effects`, qui borne en plus pertes et gains) et les
/// transactions de dApps WalletConnect (qui AFFICHENT ce bilan). Fonction
/// pure : testable contre chaque type d'attaque sans réseau.
pub(crate) fn user_effects(
    addresses: &[String],
    pre: &[Option<sol_rpc::AccountState>],
    post: &[Option<sol_rpc::AccountState>],
    user: &[u8; 32],
) -> Result<UserEffects> {
    anyhow::ensure!(addresses.len() == pre.len() && pre.len() == post.len(), "états de comptes désalignés");
    let user_b58 = bs58::encode(user).into_string();
    let native_mint: [u8; 32] = bs58::decode(jupiter_rpc::SOL_MINT)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("mint SOL mal formé (bug de compilation)")?;

    let mut lamports_pre: u128 = 0;
    let mut lamports_post: u128 = 0;
    let mut tokens_pre: std::collections::HashMap<[u8; 32], u128> = std::collections::HashMap::new();
    let mut tokens_post: std::collections::HashMap<[u8; 32], u128> = std::collections::HashMap::new();
    let mut main_seen = false;

    // Un compte à 0 lamport n'existe plus (purgé en fin de transaction) : la
    // simulation renvoie un compte FERMÉ comme "0 lamport, programme système,
    // 0 octet", PAS comme `null` — constaté sur un vrai swap mainnet (compte
    // wSOL fermé par le désenveloppement de Jupiter), qui déclenchait à tort
    // le refus "SetAuthority". Normalisé ici en "absent", des deux côtés.
    let live = |s: &Option<sol_rpc::AccountState>| s.clone().filter(|s| s.lamports > 0);
    let pre: Vec<_> = pre.iter().map(live).collect();
    let post: Vec<_> = post.iter().map(live).collect();

    for i in 0..addresses.len() {
        if addresses[i] == user_b58 {
            main_seen = true;
            lamports_pre += pre[i].as_ref().map_or(0, |s| u128::from(s.lamports));
            if let Some(p) = &post[i] {
                anyhow::ensure!(
                    p.owner == SYSTEM_PROGRAM_ID,
                    "la transaction changerait le programme propriétaire de votre compte principal (Assign) — refus de signer"
                );
                anyhow::ensure!(p.data.is_empty(), "la transaction allouerait des données sur votre compte principal — refus de signer");
                lamports_post += u128::from(p.lamports);
            }
            continue;
        }

        let pre_token = pre[i].as_ref().and_then(parse_token_account);
        let post_token = post[i].as_ref().and_then(parse_token_account);
        let pre_is_user = pre_token.as_ref().is_some_and(|t| t.owner == *user);
        let post_is_user = post_token.as_ref().is_some_and(|t| t.owner == *user);

        if let (true, Some(before)) = (pre_is_user, &pre_token) {
            lamports_pre += pre[i].as_ref().map_or(0, |s| u128::from(s.lamports));
            if before.mint != native_mint {
                *tokens_pre.entry(before.mint).or_default() += u128::from(before.amount);
            }
            match (&post[i], &post_token) {
                // Compte fermé : sa valeur doit réapparaître ailleurs chez
                // l'utilisateur, ce que le contrôle global des lamports vérifie.
                (None, _) => {}
                (Some(p), Some(after)) if after.owner == *user => {
                    anyhow::ensure!(after.mint == before.mint, "un de vos comptes de jetons changerait de jeton — refus de signer");
                    anyhow::ensure!(
                        after.delegate == before.delegate,
                        "la transaction ajouterait un délégué sur un de vos comptes de jetons (Approve : droit de le vider plus tard) — refus de signer"
                    );
                    anyhow::ensure!(
                        after.close_authority == before.close_authority,
                        "la transaction changerait l'autorité de fermeture d'un de vos comptes de jetons — refus de signer"
                    );
                    lamports_post += u128::from(p.lamports);
                    if after.mint != native_mint {
                        *tokens_post.entry(after.mint).or_default() += u128::from(after.amount);
                    }
                }
                _ => anyhow::bail!(
                    "la transaction transférerait la propriété d'un de vos comptes de jetons (SetAuthority) — refus de signer"
                ),
            }
        } else if let (true, Some(after), Some(p)) = (post_is_user, &post_token, &post[i]) {
            // Compte qui devient celui de l'utilisateur : seul le cas "créé par
            // cette transaction" (ex : ATA de destination) est légitime — un
            // compte EXISTANT remis à l'utilisateur pourrait porter un piège
            // (délégué déjà fixé, fonds déposés plus tard puis siphonnés).
            anyhow::ensure!(pre[i].is_none(), "la transaction vous céderait un compte de jetons existant — refus de signer");
            // Et seulement à l'adresse STANDARD (compte associé) de ce jeton —
            // trouvé lors du 22ᵉ passage : l'utilisateur signant la transaction,
            // une API compromise pouvait créer un compte de jetons à une adresse
            // arbitraire (CreateAccountWithSeed avec l'utilisateur comme base)
            // et y livrer la sortie du swap. Rien de volé, mais des fonds que
            // l'app n'affiche ni ne dépense jamais (elle ne lit que le compte
            // associé) : pour l'utilisateur, un swap qui n'a "rien rendu".
            let canonical = bs58::encode(sol_spl::find_associated_token_address(user, &after.mint)).into_string();
            anyhow::ensure!(
                addresses[i] == canonical,
                "la transaction livrerait vos jetons sur un compte non standard, invisible dans l'app — refus de signer"
            );
            let none = [0u8; 36];
            anyhow::ensure!(
                after.delegate[..4] == none[..4] && after.close_authority[..4] == none[..4],
                "un compte de jetons créé pour vous aurait déjà un délégué ou une autorité de fermeture — refus de signer"
            );
            lamports_post += u128::from(p.lamports);
            if after.mint != native_mint {
                *tokens_post.entry(after.mint).or_default() += u128::from(after.amount);
            }
        }
    }

    anyhow::ensure!(main_seen, "votre compte principal n'apparaît pas dans la transaction (payeur de frais attendu)");
    Ok(UserEffects { lamports_pre, lamports_post, tokens_pre, tokens_post })
}

/// Vérifie les effets d'un swap Jupiter : refus structurels de `user_effects`,
/// puis perte bornée au montant vendu + budget de frais, et sortie minimale.
fn verify_swap_effects(
    addresses: &[String],
    pre: &[Option<sol_rpc::AccountState>],
    post: &[Option<sol_rpc::AccountState>],
    limits: &SwapEffectLimits,
) -> Result<()> {
    let UserEffects { lamports_pre, lamports_post, tokens_pre, tokens_post } = user_effects(addresses, pre, post, &limits.user)?;
    anyhow::ensure!(
        lamports_post + u128::from(limits.max_lamport_loss) >= lamports_pre,
        "la transaction vous coûterait {} lamports, au-delà du montant échangé + frais autorisés ({} lamports) — refus de signer",
        lamports_pre.saturating_sub(lamports_post),
        limits.max_lamport_loss
    );
    match limits.min_output {
        MinOutput::Lamports(min) => anyhow::ensure!(
            // Les frais réseau se paient en SOL : ils peuvent réduire le gain
            // net d'au plus le budget de frais.
            lamports_post + u128::from(JUPITER_SWAP_FEE_BUDGET_LAMPORTS) >= lamports_pre + u128::from(min),
            "la transaction vous rendrait moins de SOL que le minimum annoncé ({min} lamports) — refus de signer"
        ),
        MinOutput::Token(mint, min) => {
            let before = tokens_pre.get(&mint).copied().unwrap_or(0);
            let after = tokens_post.get(&mint).copied().unwrap_or(0);
            anyhow::ensure!(
                after >= before + u128::from(min),
                "la transaction vous rendrait {} unité(s) de jeton, moins que le minimum annoncé ({min}) — refus de signer",
                after.saturating_sub(before)
            );
        }
    }
    for (mint, before) in &tokens_pre {
        let allowed = match limits.input_token {
            Some((input_mint, max)) if &input_mint == mint => u128::from(max),
            _ => 0,
        };
        let after = tokens_post.get(mint).copied().unwrap_or(0);
        anyhow::ensure!(
            after + allowed >= *before,
            "la transaction ferait sortir {} unité(s) du jeton {} au-delà de ce qui a été confirmé — refus de signer",
            before.saturating_sub(after),
            bs58::encode(mint).into_string()
        );
    }
    Ok(())
}

/// Résout les comptes inscriptibles d'une transaction (clés statiques + tables
/// de correspondance lues ON-CHAIN, jamais fournies par Jupiter), récupère leur
/// état avant, simule avec leur état après, puis appelle `verify_swap_effects`.
fn check_swap_effects(rpc: &sol_rpc::SolRpc, tx: &[u8], limits: &SwapEffectLimits) -> Result<()> {
    let addresses = resolve_writable_addresses(rpc, tx)?;
    let pre = rpc.multiple_accounts(&addresses)?;
    match rpc.simulate_with_account_states(tx, &addresses)? {
        sol_rpc::SimulationOutcome::Failed { logs } => Err(
            sol_rpc::insufficient_lamports_error(&logs).unwrap_or_else(|| anyhow::anyhow!("échec de simulation du swap Jupiter :\n{logs}")),
        ),
        sol_rpc::SimulationOutcome::Succeeded { post_states } => verify_swap_effects(&addresses, &pre, &post_states, limits),
    }
}

pub(crate) fn resolve_writable_addresses(rpc: &sol_rpc::SolRpc, tx: &[u8]) -> Result<Vec<String>> {
    let message = jupiter_rpc::transaction_message(tx)?;
    let writable = jupiter_rpc::message_writable_accounts(message)?;
    anyhow::ensure!(
        !writable.advances_durable_nonce,
        "la transaction utilise un nonce durable (valide indéfiniment, rejouable plus tard à un autre cours) — refus de signer"
    );
    let mut addresses: Vec<String> = writable.static_keys.iter().map(|k| bs58::encode(k).into_string()).collect();

    if !writable.lookups.is_empty() {
        let tables: Vec<String> = writable.lookups.iter().map(|(t, _)| bs58::encode(t).into_string()).collect();
        let table_states = rpc.multiple_accounts(&tables)?;
        for ((table, indexes), state) in writable.lookups.iter().zip(table_states) {
            let table_b58 = bs58::encode(table).into_string();
            let state = state.with_context(|| format!("table de correspondance {table_b58} introuvable on-chain"))?;
            anyhow::ensure!(
                state.owner == ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                "le compte {table_b58} n'est pas une table de correspondance d'adresses — refus de signer"
            );
            for &index in indexes {
                let start = LOOKUP_TABLE_META_SIZE + 32 * index as usize;
                let key = state
                    .data
                    .get(start..start + 32)
                    .with_context(|| format!("index {index} hors de la table {table_b58}"))?;
                addresses.push(bs58::encode(key).into_string());
            }
        }
    }
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

/// Obtient un devis de swap THORChain (lecture seule, aucun secret impliqué) —
/// voir `thorchain_rpc` pour le contexte complet. `amount` dans l'unité
/// principale de l'actif SOURCE (ex: "0.5" pour 0,5 SOL), comme partout
/// ailleurs dans cette API. `destination` : l'adresse de l'utilisateur sur la
/// chaîne DESTINATION (jamais celle du développeur — voir
/// `thorchain_rpc::AFFILIATE_ADDRESS`, déjà injectée automatiquement par
/// `thorchain_rpc::quote_swap`).
pub fn get_swap_quote(from_coin: &str, to_coin: &str, amount: &str, destination: &str) -> Result<thorchain_rpc::SwapQuote> {
    let (from_asset, from_decimals) = thorchain_asset_for_coin(from_coin)?;
    let (to_asset, _to_decimals) = thorchain_asset_for_coin(to_coin)?;
    let amount_native = parse_swap_amount_for_coin(from_coin, amount)?;
    let amount_thorchain = thorchain_rpc::to_thorchain_amount(amount_native, from_decimals)?;
    thorchain_rpc::quote_swap(from_asset, to_asset, amount_thorchain, destination)
}

/// Re-demande un devis JUSTE AVANT l'envoi (jamais de vault périmé, voir la doc
/// de `thorchain_rpc::SwapQuote`) tout en garantissant que ce qui part est ce
/// qui a été AFFICHÉ dans la boîte de confirmation (`shown`) : même adresse de
/// vault, même routeur, et une sortie minimale d'au moins 99 % de la sortie
/// attendue affichée — sinon refus (l'utilisateur relance et voit les nouvelles
/// valeurs). Résout la tension laissée par le 18ᵉ passage d'auto-revue entre
/// "devis toujours frais" et "on signe ce qu'on voit" : relire le devis après la
/// confirmation pouvait faire payer un vault/routeur jamais affiché, ou livrer
/// moins que la sortie annoncée si le cours avait bougé entre-temps.
pub fn refresh_swap_quote_matching(
    from_coin: &str,
    to_coin: &str,
    amount: &str,
    destination: &str,
    shown: &thorchain_rpc::SwapQuote,
) -> Result<thorchain_rpc::SwapQuote> {
    let fresh = get_swap_quote(from_coin, to_coin, amount, destination)?;
    let (to_asset, _) = thorchain_asset_for_coin(to_coin)?;
    ensure_quote_matches_shown(&fresh, shown, to_asset, destination)?;
    Ok(fresh)
}

fn ensure_quote_matches_shown(
    fresh: &thorchain_rpc::SwapQuote,
    shown: &thorchain_rpc::SwapQuote,
    to_asset: &str,
    destination: &str,
) -> Result<()> {
    anyhow::ensure!(
        fresh.inbound_address == shown.inbound_address && fresh.router == shown.router,
        "l'adresse de dépôt THORChain a changé pendant la confirmation — relancez l'échange pour voir la nouvelle"
    );
    thorchain_rpc::verify_swap_memo(&fresh.memo, to_asset, destination, shown.expected_amount_out)
        .context("le cours a bougé pendant la confirmation (sortie minimale sous 99 % du montant affiché) — relancez l'échange")
}

/// Envoie un swap THORChain depuis Solana : construit un transfert SOL vers
/// l'adresse de vault du devis, plus une instruction Memo (SPL Memo Program)
/// portant le memo THORChain — dans la MÊME transaction, pour que THORChain
/// associe les deux de façon atomique. `quote` doit avoir été obtenu juste
/// avant cet appel (l'adresse de vault n'est jamais mise en cache, voir la
/// doc de `thorchain_rpc::SwapQuote`).
pub fn send_swap_sol(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    quote: &thorchain_rpc::SwapQuote,
    amount_sol: &str,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let amount_lamports = wallet_flow::parse_sol_to_lamports(amount_sol)?;

    let vault_bytes = bs58::decode(quote.inbound_address.trim())
        .into_vec()
        .context("adresse de vault THORChain invalide (base58 attendu)")?;
    let vault: [u8; 32] = vault_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let owner_address = bs58::encode(owner).into_string();
    let (balance, recent_blockhash) = std::thread::scope(|scope| {
        let balance_handle = scope.spawn(|| rpc.balance_lamports(&owner_address));
        let blockhash_handle = scope.spawn(|| rpc.latest_blockhash());
        (
            balance_handle.join().expect("le thread balance ne doit pas paniquer"),
            blockhash_handle.join().expect("le thread blockhash ne doit pas paniquer"),
        )
    });
    let balance = balance?;
    let recent_blockhash = recent_blockhash?;

    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let total_needed = amount_lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} lamports disponibles, {amount_lamports} lamports + {SOL_FEE_LAMPORTS} lamports de frais requis"
    );

    let transfer_ix = sol_tx::transfer_instruction(&owner, &vault, amount_lamports);
    let memo_ix = sol_tx::Instruction {
        program_id: sol_tx::memo_program_id(),
        accounts: vec![],
        data: quote.memo.as_bytes().to_vec(),
    };
    let raw_tx = sol_tx::build_and_sign_transaction(&signing_key, &owner, &[transfer_ix, memo_ix], &recent_blockhash);
    rpc.send_transaction(&raw_tx)
}

/// Déverrouille le coffre, signe et diffuse un virement USDC (mainnet
/// uniquement, voir sol_spl.rs) — un jeton SPL, pas du SOL natif : deux
/// instructions dans une seule transaction (créer l'Associated Token Account
/// du destinataire si besoin, puis transférer), voir sol_spl.rs. Vérifie le
/// solde USDC ET le solde SOL (frais + rent éventuel) AVANT de signer ou
/// diffuser quoi que ce soit — même principe "échec précoce et clair" que
/// send_sol/send_btc/send_evm.
pub fn send_usdc(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    to: &str,
    amount_usdc: &str,
    profile_index: u32,
) -> Result<String> {
    check_solana_recipient(to, network)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();

    let to_bytes = bs58::decode(to.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let to_owner: [u8; 32] = to_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let amount = wallet_flow::parse_usdc_to_micros(amount_usdc)?;

    let mint = sol_spl::usdc_mint_mainnet();
    let source_ata = sol_spl::find_associated_token_address(&owner, &mint);
    let dest_ata = sol_spl::find_associated_token_address(&to_owner, &mint);
    let source_ata_b58 = bs58::encode(source_ata).into_string();
    let dest_ata_b58 = bs58::encode(dest_ata).into_string();
    let owner_b58 = bs58::encode(owner).into_string();

    let rpc = sol_rpc::SolRpc::new(network.rpc);
    // 4 lectures RPC indépendantes en parallèle (même motif que send_sol/send_evm) :
    // solde SOL (frais), solde USDC (ATA source), blockhash récent, et existence de
    // l'ATA destinataire (pour savoir si sa création va facturer du rent).
    let (sol_balance, usdc_balance, recent_blockhash, dest_ata_exists) = std::thread::scope(|scope| {
        let sol_handle = scope.spawn(|| rpc.balance_lamports(&owner_b58));
        let usdc_handle = scope.spawn(|| rpc.token_account_balance(&source_ata_b58));
        let blockhash_handle = scope.spawn(|| rpc.latest_blockhash());
        let dest_handle = scope.spawn(|| rpc.account_exists(&dest_ata_b58));
        (
            sol_handle.join().expect("le thread solde SOL ne doit pas paniquer"),
            usdc_handle.join().expect("le thread solde USDC ne doit pas paniquer"),
            blockhash_handle.join().expect("le thread blockhash ne doit pas paniquer"),
            dest_handle.join().expect("le thread existence ATA ne doit pas paniquer"),
        )
    });
    let sol_balance = sol_balance?;
    let recent_blockhash = recent_blockhash?;
    let dest_ata_exists = dest_ata_exists?;

    // ATA source absente == solde USDC forcément nul (jamais reçu d'USDC) :
    // échouer clairement plutôt que de construire une transaction qui
    // échouerait de toute façon on-chain.
    let usdc_balance = usdc_balance?.ok_or_else(|| anyhow::anyhow!("aucun compte USDC trouvé pour cette adresse (solde 0)"))?;
    anyhow::ensure!(
        amount <= usdc_balance,
        "fonds USDC insuffisants : {usdc_balance} disponibles (unité 10^-6 USDC), {amount} requis"
    );

    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let rent_lamports = if dest_ata_exists {
        0
    } else {
        // Taille standard d'un compte SPL Token (165 octets), vérifiée contre
        // le réseau réel — voir sol_spl.rs. Interrogé en direct plutôt que
        // codé en dur : le montant de rent est un paramètre réseau qui évolue.
        rpc.minimum_rent_exempt_balance(165)?
    };
    let total_sol_needed = SOL_FEE_LAMPORTS
        .checked_add(rent_lamports)
        .context("frais + rent dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_sol_needed <= sol_balance,
        "SOL insuffisant pour les frais{} : {sol_balance} lamports disponibles, {total_sol_needed} lamports requis",
        if dest_ata_exists { String::new() } else { " + création du compte de jetons du destinataire".to_string() }
    );

    let create_ata_ix = sol_spl::create_ata_idempotent_instruction(&owner, &to_owner, &mint, &dest_ata);
    let transfer_ix = sol_spl::transfer_checked_instruction(&source_ata, &mint, &dest_ata, &owner, amount, sol_spl::USDC_DECIMALS);
    let raw_tx = sol_tx::build_and_sign_transaction(&signing_key, &owner, &[create_ata_ix, transfer_ix], &recent_blockhash);
    rpc.send_transaction(&raw_tx)
}

// --- Signatures demandées par des dApps (WalletConnect) ---------------------

/// Signe une demande de dApp DÉJÀ préparée (voir `dapp_requests::prepare` :
/// validation, exécution à blanc ou simulation, décodage) et confirmée dans la
/// boîte native — rien n'est relu ni recalculé ici à partir de la dApp. Mot
/// de passe exigé à chaque signature, comme pour tout envoi de fonds. `account`
/// : les adresses de la session ; la clé dérivée doit y correspondre (défense
/// en profondeur : une session liée à un autre profil ne peut rien signer).
/// Renvoie le résultat JSON attendu par la dApp.
pub fn sign_dapp_request(
    data_dir: &Path,
    device_password: &str,
    profile_index: u32,
    account: &dapp_requests::Account,
    prepared: &dapp_requests::Prepared,
) -> Result<serde_json::Value> {
    use dapp_requests::Prepared;
    use ed25519_dalek::Signer;
    use serde_json::json;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let evm_key = || -> Result<k256::ecdsa::SigningKey> {
        let (key, address) = derivation::derive_evm_key(&seed, profile_index)?;
        anyhow::ensure!(
            derivation::format_address(&address).eq_ignore_ascii_case(&account.evm),
            "le compte de la session ne correspond pas au profil — signature refusée"
        );
        Ok(key)
    };
    let solana_key = || -> Result<ed25519_dalek::SigningKey> {
        let key = derivation::derive_solana_key(&seed, profile_index);
        anyhow::ensure!(
            bs58::encode(key.verifying_key().to_bytes()).into_string() == account.solana,
            "le compte de la session ne correspond pas au profil — signature refusée"
        );
        Ok(key)
    };

    match prepared {
        Prepared::EvmPersonalSign { message, .. } => {
            let signature = crate::evm_sign::sign_digest(&evm_key()?, &crate::evm_sign::personal_message_hash(message))?;
            Ok(json!(format!("0x{}", hex::encode(signature))))
        }
        Prepared::EvmTypedData { digest, .. } => {
            let signature = crate::evm_sign::sign_digest(&evm_key()?, digest)?;
            Ok(json!(format!("0x{}", hex::encode(signature))))
        }
        Prepared::EvmTransaction { network, to, value, data, gas_limit, gas_price, .. } => {
            check_evm_gas_price(network, *gas_price)?;
            let signing_key = evm_key()?;
            let rpc = eth_rpc::EthRpc::new(network.rpc);
            let (nonce, chain_id, balance) = std::thread::scope(|scope| {
                let nonce_handle = scope.spawn(|| rpc.nonce(&account.evm));
                let chain_id_handle = scope.spawn(|| rpc.chain_id());
                let balance_handle = scope.spawn(|| rpc.balance(&account.evm));
                (
                    nonce_handle.join().expect("le thread nonce ne doit pas paniquer"),
                    chain_id_handle.join().expect("le thread chain_id ne doit pas paniquer"),
                    balance_handle.join().expect("le thread balance ne doit pas paniquer"),
                )
            });
            let (nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
            anyhow::ensure!(
                chain_id == network.chain_id,
                "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé",
                network.chain_id
            );
            let gas_cost = gas_price
                .checked_mul(u128::from(*gas_limit))
                .context("gas_price * gas_limit dépasse la capacité représentable")?;
            let total_needed = value.checked_add(gas_cost).context("montant + frais de gas dépasse la capacité représentable")?;
            anyhow::ensure!(
                total_needed <= balance,
                "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
            );
            let tx = eth_tx::EthTx { nonce, gas_price: *gas_price, gas_limit: *gas_limit, to: *to, value: *value, chain_id, data: data.clone() };
            Ok(json!(rpc.send_raw_transaction(&tx.sign(&signing_key)?)?))
        }
        Prepared::SolanaMessage { message, .. } => {
            let signature = solana_key()?.sign(message);
            Ok(json!({"signature": bs58::encode(signature.to_bytes()).into_string()}))
        }
        Prepared::SolanaTransaction { network, tx, send, .. } => {
            let key = solana_key()?;
            let signed = jupiter_rpc::sign_swap_transaction(tx, &key, &key.verifying_key().to_bytes())?;
            let signature = bs58::encode(&signed[1..65]).into_string();
            if *send {
                Ok(json!({"signature": sol_rpc::SolRpc::new(network.rpc).send_transaction(&signed)?}))
            } else {
                use base64::Engine;
                Ok(json!({"signature": signature, "transaction": base64::engine::general_purpose::STANDARD.encode(&signed)}))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 23ᵉ passage : un envoi en attente (variation nette négative, monnaie
    /// rendue déduite) compte tout de suite ; une réception non confirmée est
    /// montrée à part, JAMAIS dans le solde (elle peut encore être annulée).
    #[test]
    fn unconfirmed_receptions_are_never_counted_in_the_btc_balance() {
        let view = btc_balance_view(100_000, [-30_000, 5_000].into_iter());
        assert_eq!((view.settled_sat, view.incoming_pending_sat), (70_000, 5_000));
        let view = btc_balance_view(0, [2_500_000].into_iter());
        assert_eq!((view.settled_sat, view.incoming_pending_sat), (0, 2_500_000), "rien de confirmé : 0, réception à part");
        let view = btc_balance_view(10_000, [-20_000].into_iter());
        assert_eq!(view.settled_sat, 0, "jamais négatif");
    }

    /// Vérification de bout en bout contre le RPC mainnet réel (lecture seule,
    /// aucun risque) : même portefeuille public utilisé pour valider
    /// `find_associated_token_address` (voir sol_spl.rs) — solde connu non
    /// nul au moment de l'écriture de ce test. Ignoré par défaut (dépend du
    /// réseau, pas exécuté par la suite normale) : lancer explicitement avec
    /// `cargo test -- --ignored get_usdc_balance_matches_the_real_network`.
    #[test]
    #[ignore]
    fn get_usdc_balance_matches_the_real_network() {
        let network = wallet_flow::SOLANA_MAINNET;
        let balance = get_usdc_balance("E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk", &network)
            .expect("appel réseau réel");
        assert!(balance > 0, "ce portefeuille public détient de l'USDC au moment de l'écriture du test");
    }

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

    // --- Déverrouillage biométrique ----------------------------------------
    // `FakeSealer` ne fait AUCUN vrai scellement (le blob "scellé" est le secret
    // en clair) : la propriété testée ici est l'orchestration côté api.rs
    // (fichiers, ré-chiffrement du coffre, verrou anti-brute-force), pas la
    // cryptographie NCrypt/TPM elle-même — voir `windows_hello.rs` et le spike
    // manuel pour cette partie-là, non automatisable.
    struct FakeSealer {
        fail_enroll: bool,
    }

    impl SecretSealer for FakeSealer {
        fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
            if self.fail_enroll {
                return Err(anyhow::anyhow!("échec simulé du scelleur (TPM indisponible)"));
            }
            Ok(("fake-tpm-key".to_string(), secret.to_vec()))
        }
        fn unlock(&self, _key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(sealed_blob.to_vec()))
        }
        fn remove(&self, _key_name: &str) -> Result<()> {
            Ok(())
        }
    }

    /// Scelleur dont l'enrôlement réussit mais dont `remove` enregistre chaque
    /// appel (via `Cell`, `&self` suffit) — sert à vérifier qu'une clé
    /// "TPM" est bien nettoyée si une étape APRÈS l'enrôlement échoue.
    struct TrackingSealer {
        removed: std::cell::Cell<bool>,
    }

    impl SecretSealer for TrackingSealer {
        fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
            Ok(("fake-tpm-key".to_string(), secret.to_vec()))
        }
        fn unlock(&self, _key_name: &str, sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(sealed_blob.to_vec()))
        }
        fn remove(&self, _key_name: &str) -> Result<()> {
            self.removed.set(true);
            Ok(())
        }
    }

    /// Simule une annulation du prompt Windows Hello par l'utilisateur (code
    /// NTE_USER_CANCELLED, voir `is_user_cancellation`).
    struct CancellingSealer;

    impl SecretSealer for CancellingSealer {
        fn enroll(&self, secret: &[u8]) -> Result<(String, Vec<u8>)> {
            Ok(("fake-tpm-key".to_string(), secret.to_vec()))
        }
        fn unlock(&self, _key_name: &str, _sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Err(anyhow::anyhow!("vérification Windows Hello refusée, annulée ou échouée : L'opération a été annulée par l'utilisateur. (code 0x800704c7)"))
        }
        fn remove(&self, _key_name: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn enroll_biometric_unlock_cleans_up_the_sealer_key_if_a_later_step_fails() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_cleanup_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        // Corrompt la lecture de la clé publique de l'appareil (supprimée) pour
        // forcer un échec APRÈS que le scelleur ait déjà "créé" sa clé — le seul
        // moment où un nettoyage est nécessaire (voir enroll_biometric_unlock_with).
        std::fs::remove_file(dir.join(DEVICE_PUBKEY_FILE)).unwrap();

        let sealer = TrackingSealer { removed: std::cell::Cell::new(false) };
        assert!(enroll_biometric_unlock_with(&dir, password, &sealer).is_err());
        assert!(sealer.removed.get(), "la clé du scelleur doit être nettoyée après un échec post-enrôlement");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou direct contre le bug trouvé lors d'un audit indépendant :
    /// `reset_wallet` ne touchait jusqu'ici que les fichiers "device"
    /// (mot de passe), jamais l'enrôlement biométrique — laissant une clé
    /// orpheline dans le TPM (ici, dans le scelleur de test) indéfiniment,
    /// plus 4 fichiers `device_biometric_*` obsolètes sur disque.
    #[test]
    fn reset_wallet_also_cleans_up_the_biometric_enrollment() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_reset_bio_cleanup_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false }).expect("activation de la biométrie");
        assert!(biometric_unlock_enrolled(&dir), "la biométrie doit être active avant le test");

        let sealer = TrackingSealer { removed: std::cell::Cell::new(false) };
        reset_wallet_with(&dir, &sealer).expect("réinitialisation du wallet");

        assert!(sealer.removed.get(), "la clé TPM doit être supprimée par reset_wallet, pas seulement par disable_biometric_unlock");
        assert!(!biometric_unlock_enrolled(&dir), "aucune trace d'enrôlement biométrique ne doit survivre à une réinitialisation");
        for file in [
            DEVICE_BIOMETRIC_PUBKEY_FILE,
            DEVICE_BIOMETRIC_PRIVKEY_FILE,
            DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
            DEVICE_BIOMETRIC_KEY_META_FILE,
        ] {
            assert!(!dir.join(file).exists(), "{file} ne doit pas survivre à reset_wallet");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Type d'adresse du destinataire Solana -------------------------------

    #[test]
    fn solana_recipient_must_be_a_wallet() {
        let on_curve = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        let off_curve = sol_spl::find_associated_token_address(&on_curve, &sol_spl::usdc_mint_mainnet());
        assert!(!sol_spl::is_on_curve(&off_curve), "une ATA est hors-courbe par construction");

        let state = |owner: &str| sol_rpc::AccountState { lamports: 1, owner: owner.to_string(), data: vec![] };
        classify_solana_recipient(&on_curve, Some(&state(SYSTEM_PROGRAM_ID))).expect("portefeuille existant");
        classify_solana_recipient(&off_curve, Some(&state(SYSTEM_PROGRAM_ID))).expect("coffre multisig (PDA détenue par le système)");
        classify_solana_recipient(&on_curve, None).expect("portefeuille neuf");

        let err = classify_solana_recipient(&off_curve, Some(&state(TOKEN_PROGRAM_ID))).unwrap_err();
        assert!(err.to_string().contains("compte de jetons"), "{err}");
        assert!(classify_solana_recipient(&off_curve, Some(&state(TOKEN_2022_PROGRAM_ID))).is_err());
        assert!(classify_solana_recipient(&on_curve, Some(&state("BPFLoaderUpgradeab1e11111111111111111111111"))).is_err());
        let err = classify_solana_recipient(&off_curve, None).unwrap_err();
        assert!(err.to_string().contains("aucune clé privée"), "{err}");
    }

    /// Vraies adresses mainnet : un portefeuille, SON compte USDC (l'erreur type
    /// d'un utilisateur qui copie l'adresse depuis un explorateur), le mint
    /// USDC et le programme Jupiter. `cargo test -- --ignored solana_recipient_check_on_real`
    #[test]
    #[ignore]
    fn solana_recipient_check_on_real_mainnet_addresses() {
        let net = &wallet_flow::SOLANA_MAINNET;
        check_solana_recipient("5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9", net).expect("vrai portefeuille accepté");
        for (label, address) in [
            ("compte USDC de ce portefeuille", "FzbcyEZ9m8xjtergWgWDq7mfPoHEbboBF791B6cTpzbq"),
            ("mint USDC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            ("programme Jupiter", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),
        ] {
            let err = check_solana_recipient(address, net).expect_err(label);
            println!("{label} refusé : {err}");
        }
    }

    // --- Frais et devis : "on signe ce qu'on voit" ---------------------------

    #[test]
    fn evm_gas_price_is_capped_on_mainnet_only() {
        let cap = MAINNET_MAX_GAS_PRICE_WEI;
        assert!(check_evm_gas_price(&wallet_flow::ETHEREUM_MAINNET, cap).is_ok());
        let err = check_evm_gas_price(&wallet_flow::ETHEREUM_MAINNET, 100_000 * 1_000_000_000).unwrap_err();
        assert!(err.to_string().contains("anormalement élevé"), "{err}");
        assert!(check_evm_gas_price(&wallet_flow::SEPOLIA, 100_000 * 1_000_000_000).is_ok(), "pas de plafond sur testnet");
    }

    fn shown_quote(memo_limit: u64) -> thorchain_rpc::SwapQuote {
        thorchain_rpc::SwapQuote {
            inbound_address: "bc1qvaultvaultvaultvaultvaultvaultvault00".into(),
            router: None,
            memo: format!("=:b:bc1qdest:{memo_limit}:{}:80", thorchain_rpc::AFFILIATE_ADDRESS),
            expected_amount_out: 1_000_000,
            total_fees: None,
        }
    }

    #[test]
    fn refreshed_quote_must_match_what_was_shown() {
        let shown = shown_quote(990_000);
        ensure_quote_matches_shown(&shown_quote(990_000), &shown, "BTC.BTC", "bc1qdest").expect("identique");

        let mut churned = shown_quote(990_000);
        churned.inbound_address = "bc1qautrevaultautrevaultautrevault00000".into();
        assert!(ensure_quote_matches_shown(&churned, &shown, "BTC.BTC", "bc1qdest").is_err(), "vault changé");

        let mut rerouted = shown_quote(990_000);
        rerouted.router = Some("0xAutreRouteur".into());
        assert!(ensure_quote_matches_shown(&rerouted, &shown, "BTC.BTC", "bc1qdest").is_err(), "routeur changé");

        // Cours tombé à 950 000 : la nouvelle sortie minimale (99 % de 950 000)
        // est sous 99 % de ce qui a été AFFICHÉ (1 000 000) — refusé.
        let price_dropped = shown_quote(940_500);
        let err = ensure_quote_matches_shown(&price_dropped, &shown, "BTC.BTC", "bc1qdest").unwrap_err();
        assert!(format!("{err:#}").contains("cours a bougé"), "{err:#}");
    }

    // --- verify_swap_effects : une attaque par cas -------------------------

    const USER: [u8; 32] = [1u8; 32];
    const ATTACKER: [u8; 32] = [9u8; 32];
    const USDC_MINT_T: [u8; 32] = [2u8; 32];
    const OTHER_MINT: [u8; 32] = [3u8; 32];
    const ATA_RENT: u64 = 2_039_280;
    const SOL: u64 = 1_000_000_000;

    fn native_mint_bytes() -> [u8; 32] {
        bs58::decode(jupiter_rpc::SOL_MINT).into_vec().unwrap().try_into().unwrap()
    }

    fn token_data(mint: [u8; 32], owner: [u8; 32], amount: u64, delegate: Option<[u8; 32]>) -> Vec<u8> {
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(&mint);
        d[32..64].copy_from_slice(&owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        if let Some(delegate) = delegate {
            d[72..76].copy_from_slice(&1u32.to_le_bytes());
            d[76..108].copy_from_slice(&delegate);
        }
        d[108] = 1; // initialisé
        d
    }

    fn sys(lamports: u64) -> Option<sol_rpc::AccountState> {
        Some(sol_rpc::AccountState { lamports, owner: SYSTEM_PROGRAM_ID.to_string(), data: vec![] })
    }

    fn tok(lamports: u64, data: Vec<u8>) -> Option<sol_rpc::AccountState> {
        Some(sol_rpc::AccountState { lamports, owner: TOKEN_PROGRAM_ID.to_string(), data })
    }

    fn addrs(n: usize) -> Vec<String> {
        let mut v = vec![bs58::encode(USER).into_string()];
        for i in 1..n {
            v.push(format!("compte{i}"));
        }
        v
    }

    fn sol_to_usdc_limits(amount: u64) -> SwapEffectLimits {
        SwapEffectLimits { user: USER, max_lamport_loss: amount + JUPITER_SWAP_FEE_BUDGET_LAMPORTS, input_token: None, min_output: MinOutput::Token(USDC_MINT_T, 0) }
    }

    /// [compte principal, compte associé (adresse standard) de `mint`].
    fn addrs_with_ata(mint: [u8; 32]) -> Vec<String> {
        vec![bs58::encode(USER).into_string(), bs58::encode(sol_spl::find_associated_token_address(&USER, &mint)).into_string()]
    }

    #[test]
    fn swap_effects_accept_a_legit_sol_to_usdc_swap_including_ata_creation() {
        let pre = vec![sys(10 * SOL), None];
        let post = vec![sys(10 * SOL - SOL - ATA_RENT - 10_000), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 150_000_000, None))];
        verify_swap_effects(&addrs_with_ata(USDC_MINT_T), &pre, &post, &sol_to_usdc_limits(SOL)).expect("swap légitime + création de l'ATA");
    }

    /// 22ᵉ passage : la sortie livrée sur un compte de jetons créé à une adresse
    /// NON standard (invisible dans l'app) doit être refusée, même si le montant
    /// est bon — seule l'adresse change par rapport au cas légitime ci-dessus.
    #[test]
    fn swap_effects_reject_output_delivered_to_a_non_standard_token_account() {
        let pre = vec![sys(10 * SOL), None];
        let post = vec![sys(10 * SOL - SOL - ATA_RENT - 10_000), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 150_000_000, None))];
        let err = verify_swap_effects(&addrs(2), &pre, &post, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("non standard"), "{err}");
    }

    #[test]
    fn swap_effects_reject_a_sol_drain() {
        let pre = vec![sys(10 * SOL)];
        let post = vec![sys(SOL / 2)];
        let err = verify_swap_effects(&addrs(1), &pre, &post, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("coûterait"), "{err}");
    }

    #[test]
    fn swap_effects_reject_approve_set_authority_and_assign() {
        let existing = || tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, None));
        let approve = vec![sys(10 * SOL - SOL), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, Some(ATTACKER)))];
        let err = verify_swap_effects(&addrs(2), &[sys(10 * SOL), existing()], &approve, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("Approve"), "{err}");

        let set_authority = vec![sys(10 * SOL - SOL), tok(ATA_RENT, token_data(USDC_MINT_T, ATTACKER, 100, None))];
        let err = verify_swap_effects(&addrs(2), &[sys(10 * SOL), existing()], &set_authority, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("SetAuthority"), "{err}");

        let assign = vec![Some(sol_rpc::AccountState { lamports: 9 * SOL, owner: "ProgrammeAttaquant".into(), data: vec![] })];
        let err = verify_swap_effects(&addrs(1), &[sys(10 * SOL)], &assign, &sol_to_usdc_limits(SOL)).unwrap_err();
        assert!(err.to_string().contains("Assign"), "{err}");
    }

    #[test]
    fn swap_effects_bound_the_input_token_and_protect_every_other_token() {
        let limits = SwapEffectLimits { user: USER, max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS, input_token: Some((USDC_MINT_T, 10)), min_output: MinOutput::Lamports(0) };
        let pre = vec![sys(SOL), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, None)), tok(ATA_RENT, token_data(OTHER_MINT, USER, 1000, None))];
        let legit = vec![sys(SOL + SOL / 2), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 90, None)), pre[2].clone()];
        verify_swap_effects(&addrs(3), &pre, &legit, &limits).expect("USDC -> SOL légitime");

        let overspend = vec![legit[0].clone(), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 50, None)), pre[2].clone()];
        assert!(verify_swap_effects(&addrs(3), &pre, &overspend, &limits).is_err(), "plus d'USDC que confirmé");

        let other_drained = vec![legit[0].clone(), legit[1].clone(), tok(ATA_RENT, token_data(OTHER_MINT, USER, 0, None))];
        assert!(verify_swap_effects(&addrs(3), &pre, &other_drained, &limits).is_err(), "autre jeton vidé");
    }

    #[test]
    fn swap_effects_track_wsol_value_and_reject_trapped_accounts() {
        let wsol = native_mint_bytes();
        let pre = vec![sys(5 * SOL), tok(ATA_RENT + SOL, token_data(wsol, USER, SOL, None))];
        let limits = SwapEffectLimits { user: USER, max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS, input_token: None, min_output: MinOutput::Lamports(0) };
        // Compte wSOL fermé, valeur rendue à l'utilisateur : légitime.
        let returned = vec![sys(5 * SOL + SOL + ATA_RENT - 10_000), None];
        verify_swap_effects(&addrs(2), &pre, &returned, &limits).expect("désenveloppement légitime");
        // Compte wSOL fermé, valeur partie ailleurs : refusé.
        let stolen = vec![sys(5 * SOL - 10_000), None];
        assert!(verify_swap_effects(&addrs(2), &pre, &stolen, &limits).is_err(), "wSOL détourné");

        // Compte EXISTANT cédé à l'utilisateur, ou créé avec un délégué : refusé.
        let foreign = tok(ATA_RENT, token_data(USDC_MINT_T, ATTACKER, 0, None));
        let given = vec![sys(5 * SOL - 10_000), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 0, None))];
        assert!(verify_swap_effects(&addrs(2), &[sys(5 * SOL), foreign], &given, &limits).is_err(), "compte cédé");
        let trapped = vec![sys(5 * SOL - ATA_RENT - 10_000), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 0, Some(ATTACKER)))];
        // À l'adresse standard : c'est bien le délégué qui doit faire refuser.
        let err = verify_swap_effects(&addrs_with_ata(USDC_MINT_T), &[sys(5 * SOL), None], &trapped, &limits).unwrap_err();
        assert!(err.to_string().contains("délégué"), "créé piégé : {err}");
    }

    /// "Prendre le SOL et ne rien rendre" : la perte reste dans ce qui est
    /// autorisé (le montant vendu), seul le plancher de sortie l'attrape.
    #[test]
    fn swap_effects_reject_taking_the_input_and_returning_nothing_or_too_little() {
        let mut limits = sol_to_usdc_limits(SOL);
        limits.min_output = MinOutput::Token(USDC_MINT_T, 149_000_000);
        let existing_ata = tok(ATA_RENT, token_data(USDC_MINT_T, USER, 0, None));
        let nothing = vec![sys(9 * SOL - 10_000), existing_ata.clone()];
        let err = verify_swap_effects(&addrs(2), &[sys(10 * SOL), existing_ata.clone()], &nothing, &limits).unwrap_err();
        assert!(err.to_string().contains("moins que le minimum"), "{err}");
        let enough = vec![sys(9 * SOL - 10_000), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 150_000_000, None))];
        verify_swap_effects(&addrs(2), &[sys(10 * SOL), existing_ata], &enough, &limits).expect("sortie suffisante");

        // USDC -> SOL : le SOL reçu, frais déduits, doit atteindre le minimum.
        let usdc_to_sol = SwapEffectLimits {
            user: USER,
            max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS,
            input_token: Some((USDC_MINT_T, 10)),
            min_output: MinOutput::Lamports(SOL / 2),
        };
        let pre = vec![sys(SOL), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 100, None))];
        let too_little = vec![sys(SOL + SOL / 10), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 90, None))];
        assert!(verify_swap_effects(&addrs(2), &pre, &too_little, &usdc_to_sol).is_err(), "SOL reçu insuffisant");
        let fine = vec![sys(SOL + SOL / 2), tok(ATA_RENT, token_data(USDC_MINT_T, USER, 90, None))];
        verify_swap_effects(&addrs(2), &pre, &fine, &usdc_to_sol).expect("SOL reçu suffisant");
    }

    /// Cas réel reproduit (swap SOL -> USDC mainnet) : le compte wSOL de
    /// l'utilisateur, fermé par le désenveloppement de Jupiter, revient de la
    /// simulation comme "0 lamport, programme système", pas `null`.
    #[test]
    fn swap_effects_treat_a_zero_lamport_system_account_as_closed() {
        let wsol = native_mint_bytes();
        let pre = vec![sys(5 * SOL), tok(ATA_RENT + SOL, token_data(wsol, USER, SOL, None))];
        let post = vec![sys(5 * SOL + SOL + ATA_RENT - 10_000), sys(0)];
        let limits = SwapEffectLimits { user: USER, max_lamport_loss: JUPITER_SWAP_FEE_BUDGET_LAMPORTS, input_token: None, min_output: MinOutput::Lamports(0) };
        verify_swap_effects(&addrs(2), &pre, &post, &limits).expect("compte fermé rapporté à 0 lamport");
    }

    #[test]
    fn swap_effects_require_the_user_main_account() {
        let addresses = vec!["pas_l_utilisateur".to_string()];
        assert!(verify_swap_effects(&addresses, &[sys(SOL)], &[sys(SOL)], &sol_to_usdc_limits(SOL)).is_err());
    }

    /// Vérifie contre le réseau réel combien de gas coûte VRAIMENT un
    /// `depositWithExpiry` sur le routeur THORChain (simulation `eth_estimateGas`
    /// depuis une adresse publique approvisionnée, lecture seule), comparé au
    /// gas intrinsèque. `cargo test -- --ignored thorchain_router_deposit_gas --nocapture`
    #[test]
    #[ignore]
    fn thorchain_router_deposit_gas_vs_intrinsic_on_the_real_network() {
        let from = "0x28C6c06298d514Db089934071355E5743bf21d60"; // hot wallet public (lecture seule)
        let quote = thorchain_rpc::quote_swap("ETH.ETH", "BTC.BTC", 1_000_000, "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz").unwrap();
        let router = quote.router.clone().unwrap();
        let vault = wallet_flow::parse_evm_address(&quote.inbound_address).unwrap();
        let expiration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
        let calldata = eth_tx::thorchain_deposit_calldata(&vault, &[0u8; 20], 0, &quote.memo, expiration);
        let value = 10_000_000_000_000_000u128; // 0,01 ETH
        let rpc = eth_rpc::EthRpc::new(wallet_flow::ETHEREUM_MAINNET.rpc);
        let estimated = rpc.estimate_gas(from, &router, value, &calldata).expect("estimation réelle");
        let intrinsic = eth_tx::intrinsic_gas(&calldata);
        println!("gas intrinsèque = {intrinsic}, gas réellement nécessaire (eth_estimateGas) = {estimated}");
    }

    /// Calibration ET garde-fou contre les faux rejets : vrais swaps Jupiter
    /// construits pour une adresse publique mainnet très approvisionnée (hot
    /// wallet Binance, lecture seule — simulation sans signature), passés dans
    /// le VRAI chemin de production (`check_swap_effects`). Affiche la perte
    /// réelle mesurée au-delà du montant, pour dimensionner le budget de frais.
    /// Échec isolé possible sans bug : ce hot wallet reçoit et envoie du SOL en
    /// continu, son solde peut bouger entre la lecture "avant" et la simulation
    /// (observé une fois, 3/3 au relancement). Pour un portefeuille personnel,
    /// seule une réception pourrait s'intercaler — elle gonflerait le gain, et
    /// un attaquant devrait payer ce qu'il vole : rien d'exploitable.
    /// `cargo test -- --ignored jupiter_swap_effects_pass_on_real_mainnet_swaps --nocapture`
    #[test]
    #[ignore]
    fn jupiter_swap_effects_pass_on_real_mainnet_swaps() {
        let owner_b58 = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
        let owner: [u8; 32] = bs58::decode(owner_b58).into_vec().unwrap().try_into().unwrap();
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        for (from, to, amount) in [("sol", "usdc", 100_000_000u64), ("usdc", "sol", 10_000_000u64)] {
            let q = jupiter_rpc::quote(&jupiter_mint_for_coin(from).unwrap(), &jupiter_mint_for_coin(to).unwrap(), amount, 50).unwrap();
            let tx = jupiter_rpc::build_swap_transaction(&q, owner_b58).unwrap();
            let addresses = resolve_writable_addresses(&rpc, &tx).unwrap();
            let pre = rpc.multiple_accounts(&addresses).unwrap();
            let post_states = match rpc.simulate_with_account_states(&tx, &addresses).unwrap() {
                sol_rpc::SimulationOutcome::Succeeded { post_states } => post_states,
                sol_rpc::SimulationOutcome::Failed { logs } => panic!("simulation réelle en échec pour {from}->{to} :\n{logs}"),
            };
            let user_lamports = |states: &[Option<sol_rpc::AccountState>]| -> i128 {
                addresses
                    .iter()
                    .zip(states)
                    .filter_map(|(a, s)| s.as_ref().map(|s| (a, s)))
                    .filter(|(a, s)| **a == owner_b58 || parse_token_account(s).is_some_and(|t| t.owner == owner))
                    .map(|(_, s)| i128::from(s.lamports))
                    .sum()
            };
            let loss = user_lamports(&pre) - user_lamports(&post_states);
            let sold = if from == "sol" { i128::from(amount) } else { 0 };
            println!("{from}->{to} : {} comptes inscriptibles, perte lamports réelle au-delà du montant = {}", addresses.len(), loss - sold);
            let min_out = q.out_amount * 9_950 / 10_000; // sortie "affichée" - 0,5 % de glissement
            let limits = swap_effect_limits(owner, from, amount, to, min_out).unwrap();
            if let Err(e) = verify_swap_effects(&addresses, &pre, &post_states, &limits) {
                for ((a, before), after) in addresses.iter().zip(&pre).zip(&post_states) {
                    let describe = |s: &Option<sol_rpc::AccountState>| match s {
                        None => "absent".to_string(),
                        Some(s) => format!(
                            "{} lamports, programme {}, {} octets, jeton de l'utilisateur : {}",
                            s.lamports,
                            s.owner,
                            s.data.len(),
                            parse_token_account(s).is_some_and(|t| t.owner == owner)
                        ),
                    };
                    println!("  {a}\n    avant : {}\n    après : {}", describe(before), describe(after));
                }
                panic!("faux rejet {from}->{to} : {e:#}");
            }
        }
    }

    #[test]
    fn recipient_activity_distinguishes_unused_empty_and_funded() {
        use RecipientActivity::*;
        assert_eq!(classify_evm_activity(0, 0), Unused);
        assert_eq!(classify_evm_activity(5, 0), Empty);
        assert_eq!(classify_evm_activity(0, 1), Funded, "reçu de l'ETH sans jamais en envoyer");
        assert_eq!(classify_evm_activity(7, 10), Funded);

        let btc = |tx_count, balance_sat| btc_rpc::AddressStats { tx_count, balance_sat, confirmed_sat: balance_sat };
        assert_eq!(classify_btc_activity(&btc(0, 0)), Unused);
        assert_eq!(classify_btc_activity(&btc(2, 0)), Empty);
        assert_eq!(classify_btc_activity(&btc(1, 1_000)), Funded, "réception en mempool comprise");

        assert_eq!(classify_sol_activity(None, false), Unused);
        assert_eq!(classify_sol_activity(None, true), Empty, "compte vidé puis purgé par Solana");
        assert_eq!(classify_sol_activity(Some(0), true), Empty);
        assert_eq!(classify_sol_activity(Some(890_880), true), Funded);
    }

    /// Vérification sur de vraies adresses mainnet (lecture seule) des trois
    /// états, pour chaque réseau — adresses "neuves" tirées au hasard à chaque
    /// exécution (jamais utilisées, par construction). L'adresse Bitcoin "vide"
    /// a été trouvée en direct (2 transactions, solde nul) : si quelqu'un y
    /// envoie un jour de la poussière, elle passera "Funded" (test manuel).
    /// `cargo test -- --ignored recipient_activity_matches_real_mainnet_addresses --nocapture`
    #[test]
    #[ignore]
    fn recipient_activity_matches_real_mainnet_addresses() {
        use RecipientActivity::*;
        let random: [u8; 32] = entropy::generate_master_entropy()[..32].try_into().unwrap();

        let fresh_evm = derivation::format_address(&random[..20].try_into().unwrap());
        assert_eq!(evm_recipient_activity(&fresh_evm, &wallet_flow::ETHEREUM_MAINNET).unwrap(), Unused);
        assert_eq!(evm_recipient_activity("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", &wallet_flow::ETHEREUM_MAINNET).unwrap(), Funded);

        let fresh_btc = derivation::format_btc_mainnet_address(&random[..20].try_into().unwrap()).unwrap();
        assert_eq!(btc_recipient_activity(&fresh_btc, &wallet_flow::BTC_MAINNET).unwrap(), Unused);
        assert_eq!(btc_recipient_activity("bc1q2zq2dkxrkrqn7dlqdgp4xda65mzfae8437he6z", &wallet_flow::BTC_MAINNET).unwrap(), Empty);
        assert_eq!(btc_recipient_activity("bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", &wallet_flow::BTC_MAINNET).unwrap(), Funded);

        let fresh_sol = bs58::encode(ed25519_dalek::SigningKey::from_bytes(&random).verifying_key().to_bytes()).into_string();
        assert_eq!(sol_recipient_activity(&fresh_sol, &wallet_flow::SOLANA_MAINNET).unwrap(), Unused);
        assert_eq!(sol_recipient_activity("5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9", &wallet_flow::SOLANA_MAINNET).unwrap(), Funded);
        // Compte wSOL (fermé) du portefeuille public E645Tck… : historique, mais
        // plus de compte on-chain — le cas "vidé puis purgé" propre à Solana.
        assert_eq!(sol_recipient_activity("DvW59wVbiXr2zCbQNxUnLGS544XoQjpy7YBUC38HtcJ2", &wallet_flow::SOLANA_MAINNET).unwrap(), Empty);
        // USDC : portefeuille public qui détient de l'USDC (voir
        // `get_usdc_balance_matches_the_real_network`), et adresse neuve.
        assert_eq!(usdc_recipient_activity("E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk", &wallet_flow::SOLANA_MAINNET).unwrap(), Funded);
        assert_eq!(usdc_recipient_activity(&fresh_sol, &wallet_flow::SOLANA_MAINNET).unwrap(), Unused);
        println!("neuves testées : {fresh_evm} / {fresh_btc} / {fresh_sol}");
    }

    /// Signatures de dApps sur un vrai wallet de test : l'adresse RECOUVRÉE
    /// depuis chaque signature EVM doit être celle du profil, la signature
    /// Solana doit vérifier contre sa clé publique, et une session liée à un
    /// autre compte ne doit rien pouvoir signer.
    #[test]
    fn dapp_signatures_recover_to_the_session_account() {
        use dapp_requests::{Account, Prepared};
        let dir = std::env::temp_dir().join(format!("pgp_wallet_dapp_sign_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        let created = create_wallet(&dir, password).unwrap();
        let account = Account { evm: created.addresses.evm.clone(), solana: created.addresses.solana.clone() };

        let recover = |digest: [u8; 32], sig: &str| -> String {
            let bytes = hex::decode(sig.trim_start_matches("0x")).unwrap();
            let signature = k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap();
            let recid = k256::ecdsa::RecoveryId::from_byte(bytes[64] - 27).unwrap();
            let key = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature, recid).unwrap();
            let point = key.to_encoded_point(false);
            let hash = crate::evm_sign::keccak(&point.as_bytes()[1..]);
            derivation::format_address(&hash[12..].try_into().unwrap())
        };

        let personal = dapp_requests::prepare("personal_sign", &serde_json::json!(["0x48656c6c6f", account.evm]), dapp_requests::EVM_MAINNET, &account).unwrap();
        let sig = sign_dapp_request(&dir, password, 0, &account, &personal).unwrap();
        assert_eq!(recover(crate::evm_sign::personal_message_hash(b"Hello"), sig.as_str().unwrap()), account.evm);

        let message = bs58::encode("Connexion").into_string();
        let sol = dapp_requests::prepare("solana_signMessage", &serde_json::json!({"message": message, "pubkey": account.solana}), dapp_requests::SOLANA_MAINNET, &account).unwrap();
        let sig = sign_dapp_request(&dir, password, 0, &account, &sol).unwrap();
        let sig: [u8; 64] = bs58::decode(sig["signature"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap();
        let pubkey: [u8; 32] = bs58::decode(&account.solana).into_vec().unwrap().try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
            .unwrap()
            .verify_strict(b"Connexion", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("signature Solana valide");

        // Session liée à un autre compte (ou profil) : refus avant toute signature.
        let other = Account { evm: "0x5555555555555555555555555555555555555555".to_string(), solana: account.solana.clone() };
        assert!(sign_dapp_request(&dir, password, 0, &other, &personal).is_err());
        assert!(matches!(personal, Prepared::EvmPersonalSign { .. }));
        // Mauvais mot de passe : refus (et compté dans le verrou, comme partout).
        assert!(sign_dapp_request(&dir, "mauvais mot de passe", 0, &account, &personal).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 22ᵉ passage : ce qu'affiche la boîte de confirmation doit être la valeur
    /// réellement signée, jamais une forme trompeuse de la saisie.
    #[test]
    fn canonical_amount_shows_exactly_what_will_be_signed() {
        // Formes acceptées par le parsing mais trompeuses à l'œil.
        assert_eq!(canonical_amount("btc", "0.+5").unwrap(), "0.05");
        assert_eq!(canonical_amount("btc", "\n\n\n2.5\n").unwrap(), "2.5");
        assert_eq!(canonical_amount("sol", "+1").unwrap(), "1");
        // Formes normales, zéros de fin retirés, précision complète conservée.
        assert_eq!(canonical_amount("evm", "0.010").unwrap(), "0.01");
        assert_eq!(canonical_amount("evm", "1.000000000000000001").unwrap(), "1.000000000000000001");
        assert_eq!(canonical_amount("usdc", ".5").unwrap(), "0.5");
        assert_eq!(canonical_amount("sol", "3").unwrap(), "3");
        // Aller-retour : l'affiché se re-parse en EXACTEMENT la même valeur.
        for (coin, raw) in [("btc", "0.+5"), ("evm", "12.3456789"), ("sol", "0.000000001"), ("usdc", "1000000.123456")] {
            let shown = canonical_amount(coin, raw).unwrap();
            assert_eq!(parse_swap_amount_for_coin(coin, &shown).unwrap(), parse_swap_amount_for_coin(coin, raw).unwrap(), "{coin} {raw}");
        }
        assert!(canonical_amount("btc", "1 000").is_err());
        assert!(canonical_amount("doge", "1").is_err());
    }

    /// 22ᵉ passage : le coffre lui-même, armuré et collé dans "déchiffrer un
    /// message" (même clé de l'appareil), doit être refusé explicitement — pas
    /// seulement par le hasard du contrôle UTF-8. Un vrai message, lui, passe.
    #[test]
    fn decrypt_incoming_message_refuses_the_wallet_vault_itself() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_vault_as_message_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        let vault = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        let mut armored = Vec::new();
        {
            let mut writer = armor::Writer::new(&mut armored, armor::Kind::Message).unwrap();
            std::io::Write::write_all(&mut writer, &vault).unwrap();
            writer.finalize().unwrap();
        }
        let err = decrypt_incoming_message(&dir, password, std::str::from_utf8(&armored).unwrap()).unwrap_err();
        assert!(err.to_string().contains("coffre du portefeuille"), "{err:#}");

        let pubkey = read_device_pubkey_armored(&dir).unwrap();
        let message = crate::messaging::encrypt_message(&[pubkey], "bonjour").unwrap();
        assert_eq!(decrypt_incoming_message(&dir, password, &message).unwrap(), "bonjour");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Chemin jamais exercé par le test précédent (le hot wallet Binance a déjà
    /// son compte USDC) : un swap SOL -> USDC pour un portefeuille qui n'a PAS
    /// encore de compte USDC, que la transaction Jupiter doit donc CRÉER — c'est
    /// la branche "compte qui devient celui de l'utilisateur" de
    /// `verify_swap_effects`. Identités de validateurs mainnet publiques (SOL
    /// pour les frais de vote, jamais d'USDC en pratique) : la première sans
    /// compte USDC et avec assez de SOL est utilisée. Lecture seule, rien n'est
    /// signé (transaction simulée sans signature, comme en production).
    /// `cargo test -- --ignored jupiter_swap_effects_pass_when_the_destination_token_account_is_created --nocapture`
    #[test]
    #[ignore]
    fn jupiter_swap_effects_pass_when_the_destination_token_account_is_created() {
        const CANDIDATES: [&str; 15] = [
            "Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk",
            "HEL1USMZKAL2odpNBj2oCjffnFGaYwmbGmyewGv1e2TU",
            "DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy",
            "JUPiTERrZqgf1jUyR7dSkhMx4Kn2qJyekWsg3LT1h4b",
            "E1r4Psq84tHfQ6aPTvvDka4U3u8zPVD7gEUrH25RdxHL",
            "C8Bey3LKVJHVqN6xPTeW8WJfUgFQAeGNBpT4Rp99JP1k",
            "CAo1dCGYrB6NhHh5xb1cGjUiu86iyCfMTENxgHumSve4",
            "EvnRmnMrd69kFdbLMxWkTn1icZ7DCceRhvmb2SJXqDo4",
            "9eGrDohdNTAo61DRHyfMuqKWXqYnA3i254Wiszxe8FoY",
            "Awes4Tr6TX8JDzEhCZY2QVNimT6iD1zWHzf1vNyGvpLM",
            "JD549HsbJHeEKKUrKgg4Fj2iyv2RGjsV7NTZjZUrHybB",
            "9jxgosAfHgHzwnxsHw4RAZYaLVokMbnYtmiZBreynGFP",
            "5pPRHniefFjkiaArbGX3Y8NUysJmQ9tMZg3FrFGwHzSm",
            "5Cchr1XGEg7dbBXByV5NY2ad8jfxAM7HA3x8D56rq9Ux",
            "GnC339vkyXRm1jRX69dt9mapPPu2LbzXfSDoxc91qta6",
        ];
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        let amount = 50_000_000u64; // 0,05 SOL
        let owner_b58 = CANDIDATES
            .iter()
            .find(|c| {
                let owner: [u8; 32] = bs58::decode(c).into_vec().unwrap().try_into().unwrap();
                let ata = bs58::encode(sol_spl::find_associated_token_address(&owner, &sol_spl::usdc_mint_mainnet())).into_string();
                !rpc.account_exists(&ata).unwrap() && rpc.balance_lamports(c).unwrap() > 10 * amount
            })
            .expect("au moins une identité de validateur sans compte USDC");
        println!("portefeuille utilisé (sans compte USDC) : {owner_b58}");
        let owner: [u8; 32] = bs58::decode(owner_b58).into_vec().unwrap().try_into().unwrap();

        let q = jupiter_rpc::quote(jupiter_rpc::SOL_MINT, &jupiter_mint_for_coin("usdc").unwrap(), amount, 50).unwrap();
        let tx = jupiter_rpc::build_swap_transaction(&q, owner_b58).unwrap();
        let limits = swap_effect_limits(owner, "sol", amount, "usdc", q.out_amount * 9_950 / 10_000).unwrap();
        check_swap_effects(&rpc, &tx, &limits).expect("un vrai swap qui crée le compte USDC de destination ne doit pas être rejeté");

        // Le test ne prouve quelque chose que si la branche "création" a bien
        // été traversée : compte USDC de l'utilisateur absent avant, présent après.
        let addresses = resolve_writable_addresses(&rpc, &tx).unwrap();
        let pre = rpc.multiple_accounts(&addresses).unwrap();
        let sol_rpc::SimulationOutcome::Succeeded { post_states } = rpc.simulate_with_account_states(&tx, &addresses).unwrap() else {
            panic!("simulation en échec");
        };
        let created: Vec<&String> = addresses
            .iter()
            .zip(pre.iter().zip(&post_states))
            .filter(|(_, (before, after))| {
                before.is_none()
                    && after
                        .as_ref()
                        .and_then(parse_token_account)
                        .is_some_and(|t| t.owner == owner && t.mint == sol_spl::usdc_mint_mainnet())
            })
            .map(|(a, _)| a)
            .collect();
        println!("comptes USDC créés pour l'utilisateur : {created:?}");
        assert_eq!(created.len(), 1, "la transaction doit créer exactement un compte USDC pour l'utilisateur");
    }

    /// Garde-fou du 20ᵉ passage : une clé privée injoignable (ici, retirée du
    /// coffre sans fichier de repli) ne doit JAMAIS compter comme une tentative
    /// de mot de passe ratée — même avec le BON mot de passe répété bien
    /// au-delà du seuil, le verrou ne doit pas s'enclencher.
    #[test]
    fn unreachable_key_material_does_not_count_toward_the_password_lockout() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_key_unreachable_lockout_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        active_key_store().remove(&secure_storage::entry_username(&dir)).unwrap();
        assert!(!dir.join(DEVICE_PRIVKEY_FILE).exists(), "aucun fichier de repli pour ce test");

        for _ in 0..(MAX_FREE_ATTEMPTS + 3) {
            let Err(err) = unlock_wallet(&dir, password) else {
                panic!("la clé est injoignable, le déverrouillage ne peut pas réussir");
            };
            assert!(is_key_material_unavailable(&err), "erreur inattendue : {err:#}");
        }
        assert!(
            enforce_unlock_lockout(&dir).is_ok(),
            "une clé injoignable ne doit jamais déclencher le verrou anti-brute-force"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Coffre OS qui tombe en panne à chaque lecture (pas "absent" : une vraie
    /// erreur) — pour vérifier que le repli fichier reste utilisé dans ce cas.
    struct FailingKeyStore;

    impl secure_storage::KeyStore for FailingKeyStore {
        fn write(&self, _username: &str, _secret: &str) -> Result<()> {
            Err(anyhow::anyhow!("coffre OS simulé en panne"))
        }
        fn read(&self, _username: &str) -> Result<Option<Zeroizing<String>>> {
            Err(anyhow::anyhow!("coffre OS simulé en panne"))
        }
        fn remove(&self, _username: &str) -> Result<()> {
            Err(anyhow::anyhow!("coffre OS simulé en panne"))
        }
    }

    #[test]
    fn a_failing_os_keystore_still_falls_back_to_the_key_file_and_otherwise_reports_key_unavailable() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_failing_keystore_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let err = with_device_privkey_path_in(&dir, &FailingKeyStore, |_| Ok(())).expect_err("ni coffre ni fichier");
        assert!(is_key_material_unavailable(&err), "doit être marquée comme clé injoignable : {err:#}");
        assert!(format!("{err:#}").contains("coffre OS simulé en panne"), "la cause réelle doit rester visible : {err:#}");

        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), b"contenu factice").unwrap();
        let used = with_device_privkey_path_in(&dir, &FailingKeyStore, |p| Ok(p.to_string())).expect("repli fichier");
        assert!(used.ends_with(DEVICE_PRIVKEY_FILE), "une panne du coffre OS ne doit pas bloquer une clé stockée en fichier");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Même bug que `reset_wallet_also_cleans_up_the_biometric_enrollment`,
    /// trouvé dans le même audit : `restore_wallet` remplace l'identité
    /// "device" sans jamais invalider un enrôlement biométrique qui
    /// référençait l'ANCIENNE identité (voir la doc de `restore_wallet_with`).
    #[test]
    fn restore_wallet_also_cleans_up_a_stale_biometric_enrollment_from_the_old_device_identity() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_restore_bio_cleanup_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        let created = create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false }).expect("activation de la biométrie");
        assert!(biometric_unlock_enrolled(&dir), "la biométrie doit être active avant le test");

        let b1 = &created.backups[0];
        let b2 = &created.backups[1];
        let sealer = TrackingSealer { removed: std::cell::Cell::new(false) };
        restore_wallet_with(
            &dir,
            "un nouveau mot de passe bien assez long aussi",
            (&b1.encrypted_share, &b1.privkey_armored, &b1.passphrase),
            (&b2.encrypted_share, &b2.privkey_armored, &b2.passphrase),
            &sealer,
        )
        .expect("restauration du wallet");

        assert!(sealer.removed.get(), "la clé TPM de l'ancien appareil doit être supprimée par restore_wallet");
        assert!(
            !biometric_unlock_enrolled(&dir),
            "aucune trace d'un enrôlement biométrique périmé ne doit survivre à une restauration"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn biometric_unlock_cancellation_does_not_count_toward_the_lockout() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_cancel_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false }).expect("activation de la biométrie");

        for _ in 0..(MAX_FREE_ATTEMPTS + 3) {
            assert!(unlock_wallet_biometric_with(&dir, &CancellingSealer).is_err());
        }
        assert!(
            enforce_biometric_unlock_lockout(&dir).is_ok(),
            "annuler le prompt plusieurs fois ne doit jamais déclencher le verrou anti-brute-force"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_adds_a_second_recipient_without_breaking_the_existing_password() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_enroll_bio_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let before = initial_addresses_for(&dir, password);

        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        let after = unlock_wallet(&dir, password).expect("le mot de passe doit toujours déverrouiller le coffre");
        let after_addresses = after.into_iter().find(|p| p.profile.index == 0).unwrap().addresses.unwrap();
        assert_eq!(before.evm, after_addresses.evm, "les adresses ne doivent pas changer après activation");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_then_unlock_wallet_biometric_returns_the_same_addresses_as_password_unlock() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_unlock_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        assert!(biometric_unlock_enrolled(&dir));

        let via_password = initial_addresses_for(&dir, password);
        let via_biometric = unlock_wallet_biometric_with(&dir, &FakeSealer { fail_enroll: false })
            .expect("déverrouillage biométrique")
            .into_iter()
            .find(|p| p.profile.index == 0)
            .unwrap()
            .addresses
            .unwrap();
        assert_eq!(via_password.evm, via_biometric.evm);
        assert_eq!(via_password.solana, via_biometric.solana);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Garde-fou central de toute cette fonctionnalité : le verrou anti-brute-force
    /// du mot de passe (compteur, délai) doit se comporter EXACTEMENT comme avant
    /// l'existence de la biométrie, avec ou sans elle activée.
    #[test]
    fn wrong_device_password_lockout_is_unaffected_by_biometric_enrollment() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_lockout_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");

        for _ in 0..MAX_FREE_ATTEMPTS {
            assert!(unlock_wallet(&dir, "mauvais mot de passe").is_err());
        }
        assert!(
            enforce_unlock_lockout(&dir).is_err(),
            "le verrou mot de passe doit se déclencher normalement, biométrie activée ou non"
        );
        // Le compteur biométrique, lui, ne doit pas avoir bougé : ce sont des
        // tentatives par mot de passe, jamais comptées sur l'autre chemin.
        assert!(enforce_biometric_unlock_lockout(&dir).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disable_biometric_unlock_returns_the_vault_to_single_recipient_and_removes_the_four_files() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_disable_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("activation de la biométrie");
        assert!(biometric_unlock_enrolled(&dir));

        disable_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("désactivation de la biométrie");

        assert!(!biometric_unlock_enrolled(&dir));
        for file in [
            DEVICE_BIOMETRIC_PUBKEY_FILE,
            DEVICE_BIOMETRIC_PRIVKEY_FILE,
            DEVICE_BIOMETRIC_SEALED_SECRET_FILE,
            DEVICE_BIOMETRIC_KEY_META_FILE,
        ] {
            assert!(!dir.join(file).exists(), "{file} devrait avoir été supprimé");
        }
        assert!(unlock_wallet(&dir, password).is_ok(), "le mot de passe doit toujours fonctionner après désactivation");
        assert!(
            unlock_wallet_biometric_with(&dir, &FakeSealer { fail_enroll: false }).is_err(),
            "la biométrie ne doit plus fonctionner après désactivation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_twice_replaces_the_previous_enrollment_cleanly() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_reenroll_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");

        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false }).expect("premier enrôlement");
        enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: false })
            .expect("second enrôlement (ré-enrôlement) doit réussir sans exiger de désactivation préalable");

        assert!(unlock_wallet(&dir, password).is_ok());
        assert!(unlock_wallet_biometric_with(&dir, &FakeSealer { fail_enroll: false }).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_biometric_unlock_rejects_a_wrong_device_password_and_leaves_the_vault_untouched() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_wrongpass_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let vault_before = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();

        assert!(enroll_biometric_unlock_with(&dir, "mauvais mot de passe", &FakeSealer { fail_enroll: false }).is_err());

        let vault_after = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        assert_eq!(vault_before, vault_after, "un mauvais mot de passe ne doit jamais toucher au coffre");
        assert!(!biometric_unlock_enrolled(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Si le scelleur (TPM réel) échoue au moment de l'enrôlement, le coffre doit
    /// rester strictement identique à avant — motif écrire-vérifier-renommer
    /// (voir `enroll_biometric_unlock_with`).
    #[test]
    fn enroll_biometric_unlock_leaves_the_vault_untouched_when_the_sealer_fails() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_bio_sealer_fail_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let vault_before = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();

        assert!(enroll_biometric_unlock_with(&dir, password, &FakeSealer { fail_enroll: true }).is_err());

        let vault_after = std::fs::read(dir.join(DEVICE_VAULT_FILE)).unwrap();
        assert_eq!(vault_before, vault_after, "un échec du scelleur ne doit jamais toucher au coffre");
        assert!(!biometric_unlock_enrolled(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
