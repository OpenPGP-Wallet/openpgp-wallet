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
    btc_rpc, cow, dapp_requests, derivation, doge, lifi, monero, native_deposit, wallet_birthday, zcash, zcash_shielded, entropy, eth_rpc, eth_tx, history, jupiter_rpc, memory_guard, pgp_engine, secure_storage, shamir,
    evm_sign, sol_rpc, sol_spl, sol_tx, thorchain_rpc, tokens, wallet_flow,
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
    /// Adresse Zcash transparente (t1…), chemin m/44'/133'/0'/0/{index}.
    pub zcash: String,
    /// Adresse Dogecoin (D…), chemin m/44'/3'/0'/0/{index}.
    pub doge: String,
    /// Adresse THORChain (thor1…), chemin m/44'/931'/0'/0/{index} : celle du
    /// profil principal du développeur est l'adresse d'affiliation de l'app.
    pub thor: String,
    /// Adresse Zcash protégée (u1…, récepteur Orchard seul) du compte ZIP-32
    /// n°{index}.
    pub zcash_shielded: String,
    /// Clés de visualisation du compte protégé (jamais envoyées à
    /// l'interface) : création du compte et synchronisation sans la seed.
    pub zcash_shielded_keys: zcash_shielded::ProfileKeys,
    /// Adresse Monero principale (4…), schéma de l'app Monero de Ledger
    /// (m/44'/128'/{index}'/0/0, voir `monero`).
    pub monero: String,
    /// Clés de visualisation Monero (jamais envoyées à l'interface) :
    /// synchronisation et préparation des envois sans la seed.
    pub monero_keys: monero::ViewKeys,
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
    let (_zec_key, zec_hash160) = derivation::derive_zec_key(seed, index)?;
    let (_doge_key, doge_hash160) = derivation::derive_doge_key(seed, index)?;
    let (_thor_key, thor_hash160) = derivation::derive_thor_key(seed, index)?;
    let shielded_keys = zcash_shielded::profile_keys(seed, index)?;
    let monero_keys = monero::view_keys(seed, index)?;
    Ok(Addresses {
        monero: monero_keys.address()?,
        monero_keys,
        zcash_shielded: zcash_shielded::address(&shielded_keys.1)?,
        zcash_shielded_keys: shielded_keys,
        thor: derivation::format_thor_address(&thor_hash160)?,
        zcash: zcash::p2pkh_address(&zec_hash160),
        doge: doge::p2pkh_address(&doge_hash160),
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

/// Identifiant d'un kit de sauvegarde : empreinte de ses parts CHIFFRÉES (rien
/// du portefeuille ne s'en déduit). Même valeur pour les 3 parts d'un kit ;
/// sert à refuser deux parts d'un même kit sur une même clé USB.
pub fn backup_kit_id(backups: &[BackupShare]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for backup in backups {
        hasher.update((backup.encrypted_share.len() as u64).to_be_bytes());
        hasher.update(&backup.encrypted_share);
    }
    hex::encode(&hasher.finalize()[..12])
}

/// Vérifie qu'une part de sauvegarde se déchiffre avec sa clé privée et son mot
/// de passe (après son écriture sur une clé USB, relue depuis la clé) ; la part
/// déchiffrée est effacée de la mémoire aussitôt.
pub fn verify_backup_share(data_dir: &Path, encrypted: &[u8], privkey_armored: &[u8], passphrase: &str) -> Result<()> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::fs::create_dir_all(data_dir)?;
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = data_dir.join(format!("tmp_verify_backup_{}_{n}.asc", std::process::id()));
    let share = Zeroizing::new(decrypt_with_armored_privkey(encrypted, &tmp, privkey_armored, passphrase)?);
    anyhow::ensure!(!share.is_empty(), "part de sauvegarde vide");
    Ok(())
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

/// Wallet créé avant le passage au coffre OS (25/09/2026) : sa clé privée
/// "device" était restée en fichier, rien ne la déplaçait (constaté sur un
/// vrai wallet). Appelé après un déverrouillage RÉUSSI (le fichier est alors
/// connu bon) : la clé est écrite dans le coffre OS, relue et comparée, et
/// seulement alors le fichier est supprimé. Une seule copie à la fois : si le
/// fichier ne peut pas être supprimé, l'entrée du coffre est retirée et la
/// migration sera retentée au prochain déverrouillage. Sans effet si la clé
/// est déjà dans le coffre ou si celui-ci est indisponible ; un échec laisse
/// toujours le wallet dans son état précédent.
fn migrate_device_privkey_to_store(data_dir: &Path, store: &dyn secure_storage::KeyStore) {
    let username = secure_storage::entry_username(data_dir);
    if !matches!(store.read(&username), Ok(None)) {
        return;
    }
    let path = data_dir.join(DEVICE_PRIVKEY_FILE);
    let Ok(bytes) = std::fs::read(&path).map(Zeroizing::new) else { return };
    let Ok(text) = std::str::from_utf8(&bytes) else { return };
    if store.write(&username, text).is_err() {
        return;
    }
    match store.read(&username) {
        Ok(Some(stored)) if stored.as_str() == text => {
            if std::fs::remove_file(&path).is_err() {
                let _ = store.remove(&username);
            }
        }
        _ => {
            let _ = store.remove(&username);
        }
    }
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
    // Entropie neuve : aucun fonds ne peut être plus ancien — synchronisations
    // des cryptos privées depuis peu avant maintenant (voir `wallet_birthday`).
    wallet_birthday::record_created(data_dir)?;

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
    forget_other_shielded_wallets(data_dir, &seed);
    // Seuls les profils actifs : un profil archivé (voir `archive_profile`) ne doit
    // plus apparaître nulle part tant qu'il n'a pas été explicitement désarchivé.
    list_profiles(data_dir)
        .into_iter()
        .map(|profile| {
            let addresses = derive_addresses(&seed, profile.index)?;
            update_monero_key_images(data_dir, &seed, profile.index);
            Ok(ProfileAddresses { profile, addresses: Some(addresses) })
        })
        .collect()
}

/// Comptes Zcash protégés d'un autre portefeuille (même appareil) écartés
/// avant tout affichage ; un échec est retenté au déverrouillage suivant.
fn forget_other_shielded_wallets(data_dir: &Path, seed: &[u8]) {
    if let Err(e) = zcash_shielded::forget_other_wallets(data_dir, seed) {
        eprintln!("Zcash protégé : {e:#}");
    }
}

/// Key images Monero des sorties reçues depuis le dernier passage (détection
/// des dépenses faites ailleurs, voir `monero`), tant que la seed est en
/// mémoire. Un échec ne bloque pas le déverrouillage : refait au suivant ou
/// au prochain envoi.
fn update_monero_key_images(data_dir: &Path, seed: &[u8], profile: u32) {
    if let Err(e) = monero::update_key_images(data_dir, seed, profile) {
        eprintln!("Monero : key images non calculées ({e:#})");
    }
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
    remove_seed_bound_state(data_dir);

    // Prouver la possession de 2 parts de sauvegarde est une preuve d'identité bien
    // plus forte qu'un mot de passe ; un éventuel verrou anti-brute-force accumulé
    // sur l'ancien mot de passe (avant restauration) n'a plus de raison de s'appliquer
    // au nouveau coffre qui vient d'être créé avec un mot de passe différent.
    reset_unlock_attempts(data_dir);

    // `recovered` est effacée automatiquement à la fin de la fonction (Drop de
    // `Zeroizing`), même en cas de retour anticipé sur une des lignes `?` ci-dessus.
    Ok(addresses)
}

/// État local propre à une seed (base Zcash protégée, état Monero) :
/// supprimé quand le portefeuille de cet appareil change — best-effort, un
/// fichier encore ouvert est de toute façon écarté au déverrouillage suivant
/// (`zcash_shielded::forget_other_wallets`, lien des profils Monero). Aussi
/// les destinataires déjà payés : sinon l'alerte « nouvelle adresse »
/// disparaîtrait pour un autre portefeuille (au pire, quelques alertes de plus
/// si c'est le même qui revient).
fn remove_seed_bound_state(data_dir: &Path) {
    wallet_birthday::forget(data_dir);
    for file in ["zcash_shielded.sqlite", "zcash_shielded.sqlite-wal", "zcash_shielded.sqlite-shm", "monero_wallet.json", "sent_recipients.json"] {
        let _ = std::fs::remove_file(data_dir.join(file));
    }
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
    remove_seed_bound_state(data_dir);
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
            migrate_device_privkey_to_store(data_dir, active_key_store());
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
    forget_other_shielded_wallets(data_dir, &seed);
    list_profiles(data_dir)
        .into_iter()
        .map(|profile| {
            let addresses = derive_addresses(&seed, profile.index)?;
            update_monero_key_images(data_dir, &seed, profile.index);
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
    get_spl_balance(owner_address, &sol_spl::usdc_mint_mainnet(), network)
}

/// Solde d'un jeton SPL `mint` de `owner_address` (compte de jetons associé ;
/// absent : 0).
pub fn get_spl_balance(owner_address: &str, mint: &[u8; 32], network: &wallet_flow::SolNetwork) -> Result<u64> {
    let owner_bytes = bs58::decode(owner_address.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let owner: [u8; 32] = owner_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = sol_spl::find_associated_token_address(&owner, mint);
    let ata_b58 = bs58::encode(ata).into_string();
    Ok(sol_rpc::SolRpc::new(network.rpc).token_account_balance(&ata_b58)?.unwrap_or(0))
}

/// Historique d'un jeton SPL du registre pour `owner_address` : dérive son
/// compte de jetons associé (ATA) puis délègue à `history::spl_history` (voir
/// sa doc — l'ATA, pas l'adresse "propriétaire", est ce qui reçoit/envoie
/// effectivement le jeton). Si l'ATA n'existe pas encore (jeton jamais reçu),
/// `getSignaturesForAddress` renvoie simplement une liste vide, sans erreur.
pub fn get_spl_tx_history(owner_address: &str, mint: &[u8; 32], network: &wallet_flow::SolNetwork, limit: u32) -> Result<Vec<history::TxEntry>> {
    history::spl_history(network.rpc, &spl_token_account(owner_address, mint)?, limit)
}

/// Compte de jetons USDC associé (ATA, base58) de l'adresse Solana `owner_address`.
pub fn usdc_token_account(owner_address: &str) -> Result<String> {
    spl_token_account(owner_address, &sol_spl::usdc_mint_mainnet())
}

/// Compte de jetons associé (ATA, base58) de l'adresse Solana `owner_address`
/// pour le jeton `mint`.
pub fn spl_token_account(owner_address: &str, mint: &[u8; 32]) -> Result<String> {
    let owner_bytes = bs58::decode(owner_address.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let owner: [u8; 32] = owner_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let ata = sol_spl::find_associated_token_address(&owner, mint);
    Ok(bs58::encode(ata).into_string())
}

/// `Some(lamports de rent)` si l'Associated Token Account USDC de `to_address`
/// n'existe pas encore (sa création par `send_usdc` facturera ce montant en
/// plus des frais réseau habituels), `None` si elle existe déjà — lecture
/// seule, pensée pour être appelée AVANT confirmation afin de ne jamais
/// présenter un coût caché après coup (voir `describe_possible_ata_rent` côté
/// app-tauri, qui met ce chiffre en forme pour la boîte de dialogue).
pub fn usdc_ata_rent_lamports_if_missing(to_address: &str, network: &wallet_flow::SolNetwork) -> Result<Option<u64>> {
    spl_ata_rent_lamports_if_missing(to_address, &sol_spl::usdc_mint_mainnet(), network)
}

/// Rent du compte de jetons `mint` du destinataire s'il n'existe pas encore
/// (créé et payé par l'expéditeur) ; `None` s'il existe.
pub fn spl_ata_rent_lamports_if_missing(to_address: &str, mint: &[u8; 32], network: &wallet_flow::SolNetwork) -> Result<Option<u64>> {
    let to_bytes = bs58::decode(to_address.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let to_owner: [u8; 32] = to_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let dest_ata = sol_spl::find_associated_token_address(&to_owner, mint);
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
    // Plafond propre à chaque réseau (`EvmNetwork::max_gas_price_wei`) ; aucun
    // sur un réseau de test.
    if let Some(cap) = network.max_gas_price_wei {
        anyhow::ensure!(
            gas_price <= cap,
            "prix du gas annoncé par le nœud anormalement élevé ({} gwei, plafond de sécurité {} gwei) — envoi refusé",
            gas_price / 1_000_000_000,
            cap / 1_000_000_000
        );
    }
    Ok(())
}

/// Plafond d'une limite de gas ESTIMÉE par le nœud (Arbitrum, où le coût de
/// publication sur Ethereum est compté en gas) : au-delà, refus plutôt que de
/// lui faire confiance. Un virement y consomme d'ordinaire moins de 1 million.
pub const EVM_MAX_ESTIMATED_GAS: u64 = 5_000_000;
/// Oracle des frais des réseaux OP Stack (même adresse sur tous : Base…).
const OP_GAS_PRICE_ORACLE: &str = "0x420000000000000000000000000000000000000F";

/// Frais d'un envoi EVM, montrés dans la boîte de confirmation PUIS utilisés
/// tels quels pour signer ("on signe ce qu'on voit") — jamais relus après.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EvmFee {
    pub gas_price: u128,
    pub gas_limit: u64,
    /// Réseaux OP Stack (Base) : frais de publication sur Ethereum, facturés
    /// en plus du gas par le réseau lui-même (estimation avec marge) ; 0
    /// ailleurs. Compris dans le contrôle du solde.
    pub l1_fee: u128,
}

impl EvmFee {
    /// Frais maximum : gas × prix (borne réelle : jamais plus que la limite)
    /// + frais de publication estimés.
    pub fn max_total(&self) -> Result<u128> {
        self.gas_price
            .checked_mul(u128::from(self.gas_limit))
            .and_then(|gas| gas.checked_add(self.l1_fee))
            .context("frais de gas dépassant la capacité représentable")
    }
}

/// Frais d'un virement natif de `value` wei (`data` : appel de contrat, vide
/// pour un simple virement) depuis `from` : prix du gas du nœud (plafonné),
/// limite de gas fixe ou estimée (+20 %, bornée), frais de publication OP
/// Stack le cas échéant (+25 %).
pub fn evm_fee_for_confirmation(network: &wallet_flow::EvmNetwork, from: &[u8; 20], to: &[u8; 20], value: u128, data: &[u8]) -> Result<EvmFee> {
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let gas_price = rpc.gas_price()?;
    check_evm_gas_price(network, gas_price)?;
    let gas_limit = match (network.transfer_gas, data.is_empty()) {
        (Some(fixed), true) => fixed,
        _ => {
            // Estimation refusée faute de fonds : message clair plutôt que l'erreur
            // brute du nœud (constaté sur Arbitrum avec un solde nul).
            let estimated = rpc.estimate_gas(&derivation::format_address(from), &derivation::format_address(to), value, data).map_err(|e| {
                if format!("{e:#}").contains("insufficient funds") {
                    anyhow::anyhow!("fonds insuffisants pour ce montant et les frais du réseau")
                } else {
                    e
                }
            })?;
            let with_margin = estimated.saturating_add(estimated / 5).max(eth_tx::intrinsic_gas(data));
            anyhow::ensure!(
                with_margin <= EVM_MAX_ESTIMATED_GAS,
                "gas estimé anormalement élevé ({with_margin}, maximum {EVM_MAX_ESTIMATED_GAS}) — envoi refusé"
            );
            with_margin
        }
    };
    let l1_fee = evm_l1_fee(network, to, value, data, gas_price, gas_limit)?;
    Ok(EvmFee { gas_price, gas_limit, l1_fee })
}

/// Frais de publication sur Ethereum d'une transaction sur un réseau OP Stack
/// (Base), marge de 25 % comprise ; 0 sur les autres réseaux. Aussi utilisé
/// pour les transactions demandées par une dApp (`dapp_requests`).
pub fn evm_l1_fee(network: &wallet_flow::EvmNetwork, to: &[u8; 20], value: u128, data: &[u8], gas_price: u128, gas_limit: u64) -> Result<u128> {
    if !network.op_stack_l1_fee {
        return Ok(0);
    }
    let draft = eth_tx::EthTx { nonce: 0, gas_price, gas_limit, to: *to, value, chain_id: network.chain_id, data: data.to_vec() };
    let fee = op_stack_l1_fee(&eth_rpc::EthRpc::new(network.rpc), &draft.unsigned_rlp())?;
    Ok(fee.saturating_add(fee / 4))
}

/// Frais d'un virement natif de `amount` (texte, 18 décimales) vers `to` : voir
/// `evm_fee_for_confirmation`. `from` : adresse d'envoi, nécessaire seulement
/// là où la limite de gas est estimée (Arbitrum).
/// Solde suffisant pour un virement EVM (montant + frais maximum affichés),
/// vérifié AVANT la boîte de confirmation — jusqu'ici seulement après :
/// l'utilisateur confirmait un envoi refusé juste ensuite, avec un message en
/// wei. Montants dans l'unité du réseau (ETH, BNB…).
pub fn ensure_evm_transfer_funds(network: &wallet_flow::EvmNetwork, from: &str, amount: &str, fee: EvmFee) -> Result<()> {
    let value = wallet_flow::parse_eth_to_wei(amount)?;
    let gas = fee.max_total()?;
    let needed = value.checked_add(gas).context("montant + frais dépasse la capacité représentable")?;
    let balance = get_evm_balance(from, network)?;
    let unit = |wei: u128| format!("{} {}", tokens::format_amount(wei, 18), network.native_symbol);
    anyhow::ensure!(needed <= balance, "fonds insuffisants : {} disponibles, {} + {} de frais requis", unit(balance), unit(value), unit(gas));
    Ok(())
}

/// Solde de jeton suffisant pour un virement (registre `tokens.rs`, USDC
/// compris), vérifié avant la boîte de confirmation.
pub fn ensure_token_funds(token_id: &str, network: &str, owner: &str, amount: &str) -> Result<()> {
    let (balance, decimals) = if token_id == "usdc" && network == "sol_mainnet" {
        (u128::from(get_spl_balance(owner, &sol_spl::usdc_mint_mainnet(), &wallet_flow::SOLANA_MAINNET)?), 6)
    } else {
        get_token_balance(token_id, network, owner)?
    };
    let wanted = tokens::parse_amount(amount, decimals)?;
    let symbol = tokens::find(token_id, network).map_or_else(|| token_id.to_uppercase(), |(t, _)| t.symbol.to_string());
    anyhow::ensure!(
        wanted <= balance,
        "fonds insuffisants : {} {symbol} disponibles, {} {symbol} requis",
        tokens::format_amount(balance, decimals),
        tokens::format_amount(wanted, decimals)
    );
    Ok(())
}

/// Monnaie du réseau suffisante pour le gas d'un virement de jeton ERC-20,
/// vérifiée avant la boîte de confirmation.
pub fn ensure_evm_gas_funds(network: &wallet_flow::EvmNetwork, from: &str, fee: EvmFee) -> Result<()> {
    let gas = fee.max_total()?;
    let balance = get_evm_balance(from, network)?;
    let unit = |wei: u128| format!("{} {}", tokens::format_amount(wei, 18), network.native_symbol);
    anyhow::ensure!(gas <= balance, "fonds insuffisants : {} disponibles, {} de frais de gas requis", unit(balance), unit(gas));
    Ok(())
}

/// Même vérification pour un virement SOL (montant + frais de base), avant la
/// boîte de confirmation.
pub fn ensure_sol_transfer_funds(network: &wallet_flow::SolNetwork, from: &str, amount: &str) -> Result<()> {
    const SOL_FEE_LAMPORTS: u64 = 5_000;
    let lamports = wallet_flow::parse_sol_to_lamports(amount)?;
    let needed = lamports.checked_add(SOL_FEE_LAMPORTS).context("montant + frais dépasse la capacité représentable")?;
    let balance = get_sol_balance(from, network)?;
    let unit = |l: u64| format!("{} SOL", tokens::format_amount(u128::from(l), 9));
    anyhow::ensure!(needed <= balance, "fonds insuffisants : {} disponibles, {} + {} de frais requis", unit(balance), unit(lamports), unit(SOL_FEE_LAMPORTS));
    Ok(())
}

pub fn evm_transfer_fee_for_confirmation(network: &wallet_flow::EvmNetwork, from: Option<&str>, to: &str, amount: &str) -> Result<EvmFee> {
    let to = wallet_flow::parse_evm_address(to)?;
    let value = wallet_flow::parse_eth_to_wei(amount)?;
    let from = match (from, network.transfer_gas) {
        (Some(address), _) => wallet_flow::parse_evm_address(address)?,
        // Limite de gas fixe : l'adresse d'envoi n'intervient pas.
        (None, Some(_)) => [0u8; 20],
        (None, None) => anyhow::bail!("adresse d'envoi inconnue : déverrouillez le portefeuille"),
    };
    evm_fee_for_confirmation(network, &from, &to, value, &[])
}

/// Frais de publication sur Ethereum d'une transaction (encodage non signé)
/// sur un réseau OP Stack : `getL1Fee(bytes)` de l'oracle du réseau.
fn op_stack_l1_fee(rpc: &eth_rpc::EthRpc, unsigned_tx: &[u8]) -> Result<u128> {
    // Sélecteur de getL1Fee(bytes), puis l'argument `bytes` en ABI : position
    // (0x20), longueur, données complétées à un multiple de 32 octets.
    let mut calldata = vec![0x49, 0x94, 0x8e, 0x0e];
    let mut word = [0u8; 32];
    word[31] = 0x20;
    calldata.extend_from_slice(&word);
    let mut length = [0u8; 32];
    length[24..].copy_from_slice(&(unsigned_tx.len() as u64).to_be_bytes());
    calldata.extend_from_slice(&length);
    calldata.extend_from_slice(unsigned_tx);
    let padded = 4 + (calldata.len() - 4).div_ceil(32) * 32;
    calldata.resize(padded, 0);
    let answer = rpc.call_contract(&derivation::format_address(&[0u8; 20]), OP_GAS_PRICE_ORACLE, 0, &calldata)?;
    anyhow::ensure!(answer.len() == 32, "réponse de l'oracle de frais inattendue");
    anyhow::ensure!(answer[..16].iter().all(|&b| b == 0), "frais de publication annoncés anormalement élevés");
    Ok(u128::from_be_bytes(answer[16..].try_into().expect("16 octets")))
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
    fee: EvmFee,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, fee.gas_price)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let tx = prepare_evm_transfer(network, &address, to, amount_eth, fee)?;
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
    fee: EvmFee,
) -> Result<eth_tx::EthTx> {
    check_evm_gas_price(network, fee.gas_price)?;
    anyhow::ensure!(fee.gas_limit >= eth_tx::intrinsic_gas(&[]), "limite de gas trop basse pour un virement");
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
    let gas_cost = fee.max_total()?;
    let total_needed = value
        .checked_add(gas_cost)
        .context("montant + frais de gas dépasse la capacité représentable")?;
    anyhow::ensure!(
        total_needed <= balance,
        "fonds insuffisants : {balance} wei disponibles, {value} wei + {gas_cost} wei de frais de gas requis"
    );

    Ok(eth_tx::EthTx {
        nonce,
        gas_price: fee.gas_price,
        gas_limit: fee.gas_limit,
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
/// avec `asset` = adresse nulle (monnaie native) et `amount` = le montant envoyé
/// (`msg.value`, exigé par le routeur récent d'Avalanche et Base). `expiration` :
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
    // voir `deposit()` dans le contrat THORChain_Router).
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

    // `amount` = le montant envoyé : le routeur récent (Avalanche, Base) refuse
    // un dépôt natif où il diffère de `msg.value` (« TC:eth amount mismatch »,
    // constaté en réel) ; l'ancien (Ethereum) l'ignore.
    let calldata = eth_tx::thorchain_deposit_calldata(&vault_bytes, &native_asset_bytes, value, &quote.memo, expiration);
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
    let (_, deposit_cap) = swap_gas_caps(network);
    anyhow::ensure!(
        gas_limit <= deposit_cap,
        "gas estimé anormalement élevé pour un dépôt THORChain ({gas_limit}, maximum {deposit_cap}) — swap refusé"
    );

    // Base (OP Stack) : frais de publication sur Ethereum en plus du gas.
    let l1_fee = evm_l1_fee(network, &router_bytes, value, &calldata, gas_price, gas_limit)?;
    let gas_cost = gas_price
        .checked_mul(u128::from(gas_limit))
        .and_then(|gas| gas.checked_add(l1_fee))
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

/// Plafond du gas d'une autorisation ERC-20 (`approve`) : d'ordinaire
/// 46 000 à 60 000.
pub const EVM_APPROVE_MAX_GAS_LIMIT: u64 = 100_000;

/// Plafonds de gas (autorisation, dépôt) d'un échange sur `network`. Là où
/// la limite de gas compte aussi la publication sur Ethereum (Arbitrum,
/// `transfer_gas` = `None`), elle monte avec le prix du gas d'Ethereum : même
/// plafond large que pour un virement (`EVM_MAX_ESTIMATED_GAS`), sinon des
/// échanges légitimes seraient refusés quand Ethereum est chargé.
pub fn swap_gas_caps(network: &wallet_flow::EvmNetwork) -> (u64, u64) {
    match network.transfer_gas {
        None => (EVM_MAX_ESTIMATED_GAS, EVM_MAX_ESTIMATED_GAS),
        Some(_) => (EVM_APPROVE_MAX_GAS_LIMIT, EVM_SWAP_MAX_GAS_LIMIT),
    }
}
/// Attente maximale de la confirmation d'une autorisation avant le dépôt.
const APPROVE_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// Échange THORChain depuis un jeton ERC-20 (USDC, USDT, DAI, VVV…) : le
/// routeur prélève lui-même le jeton, ce qui demande d'abord une autorisation
/// (`approve`) au MONTANT EXACT de l'échange — jamais illimitée —, puis
/// `depositWithExpiry(vault, jeton, montant, memo, expiration)`. Les deux
/// transactions sont construites ici (aucun appel fourni par un tiers), au
/// prix du gas affiché dans la boîte de confirmation. Une autorisation déjà
/// suffisante n'est pas redemandée ; une autorisation non nulle mais
/// insuffisante est d'abord remise à 0 (exigé par USDT). L'autorisation doit
/// être minée avant le dépôt (sinon l'estimation du dépôt échoue) : attente
/// bornée ; au-delà, l'échange peut être relancé, l'autorisation restant
/// acquise.
#[allow(clippy::too_many_arguments)]
pub fn send_swap_erc20(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    from: &thorchain_rpc::ThorAsset,
    quote: &thorchain_rpc::SwapQuote,
    amount: &str,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let contract = from.contract.context("jeton ERC-20 attendu")?;
    let contract_bytes = wallet_flow::parse_evm_address(contract)?;
    let router = quote.router.as_deref().context("devis THORChain sans adresse de routeur (attendu pour un swap EVM)")?;
    let router_bytes = wallet_flow::parse_evm_address(router)?;
    let vault_bytes = wallet_flow::parse_evm_address(&quote.inbound_address)?;
    let units = tokens::parse_amount(amount, from.decimals as u8)?;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    let rpc = eth_rpc::EthRpc::new(network.rpc);

    let (nonce, chain_id, balance, token_balance, allowance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let token_balance = scope.spawn(|| get_erc20_balance(network, contract, &address_str));
        let allowance = scope.spawn(|| get_erc20_allowance(network, contract, &address, &router_bytes));
        let join = "un fil de lecture ne doit pas paniquer";
        (nonce.join().expect(join), chain_id.join().expect(join), balance.join().expect(join), token_balance.join().expect(join), allowance.join().expect(join))
    });
    let (mut nonce, chain_id, balance, token_balance, allowance) = (nonce?, chain_id?, balance?, token_balance?, allowance?);
    anyhow::ensure!(chain_id == network.chain_id, "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé", network.chain_id);
    anyhow::ensure!(
        units <= token_balance,
        "{} insuffisants : {} disponibles, {} demandés",
        from.symbol,
        tokens::format_amount(token_balance, from.decimals as u8),
        tokens::format_amount(units, from.decimals as u8)
    );

    let approvals = approval_amounts(allowance, units);
    // Monnaie du réseau pour TOUTES les transactions, au pire : autorisations
    // et dépôt à leur plafond de gas (+ frais L1 sur Base).
    let (_, deposit_cap) = swap_gas_caps(network);
    let deposit_draft = eth_tx::thorchain_deposit_calldata(&vault_bytes, &contract_bytes, units, &quote.memo, u64::MAX);
    let deposit_fee = gas_price
        .checked_mul(u128::from(deposit_cap))
        .and_then(|g| g.checked_add(evm_l1_fee(network, &router_bytes, 0, &deposit_draft, gas_price, deposit_cap).ok()?))
        .context("frais de gas dépassant la capacité représentable")?;
    ensure_fees_covered(network, &contract_bytes, &router_bytes, &approvals, gas_price, deposit_fee, balance)?;
    nonce = send_approvals(&rpc, network, &signing_key, &address_str, chain_id, nonce, &contract_bytes, &router_bytes, &approvals, gas_price)?;

    let expiration = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).context("horloge système invalide")?.as_secs() + 3600;
    let calldata = eth_tx::thorchain_deposit_calldata(&vault_bytes, &contract_bytes, units, &quote.memo, expiration);
    let estimated = rpc.estimate_gas(&address_str, router, 0, &calldata)?;
    let gas_limit = estimated.saturating_mul(12).div_ceil(10).max(eth_tx::intrinsic_gas(&calldata));
    anyhow::ensure!(
        gas_limit <= deposit_cap,
        "gas estimé anormalement élevé pour un dépôt THORChain ({gas_limit}, maximum {deposit_cap}) — swap refusé"
    );
    let tx = eth_tx::EthTx { nonce, gas_price, gas_limit, to: router_bytes, value: 0, chain_id, data: calldata };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

/// Autorisations à envoyer pour qu'un contrat puisse prélever exactement
/// `units` : aucune si l'autorisation actuelle suffit ; sinon le montant exact
/// — jamais illimité —, précédé d'une remise à 0 si une autorisation partielle
/// existe (exigé par USDT).
fn approval_amounts(allowance: u128, units: u128) -> Vec<u128> {
    match allowance {
        a if a >= units => vec![],
        0 => vec![units],
        _ => vec![0, units],
    }
}

/// Vérifie que la monnaie du réseau couvre, au pire, les autorisations à
/// leur plafond de gas (+ frais L1 sur Base) plus `other_fees`.
fn ensure_fees_covered(
    network: &wallet_flow::EvmNetwork,
    contract: &[u8; 20],
    spender: &[u8; 20],
    approvals: &[u128],
    gas_price: u128,
    other_fees: u128,
    balance: u128,
) -> Result<()> {
    let (approve_cap, _) = swap_gas_caps(network);
    let mut worst_case = other_fees;
    for amount in approvals {
        let data = erc20_approve_data(spender, *amount);
        let approve_fee = gas_price
            .checked_mul(u128::from(approve_cap))
            .and_then(|g| g.checked_add(evm_l1_fee(network, contract, 0, &data, gas_price, approve_cap).ok()?))
            .context("frais de gas dépassant la capacité représentable")?;
        worst_case = worst_case.checked_add(approve_fee).context("frais de gas dépassant la capacité représentable")?;
    }
    anyhow::ensure!(
        worst_case <= balance,
        "{} insuffisant pour les frais du réseau : {} disponibles, jusqu'à {} nécessaires",
        network.native_symbol,
        tokens::format_amount(balance, 18),
        tokens::format_amount(worst_case, 18)
    );
    Ok(())
}

/// Envoie les autorisations une à une, chacune attendue minée et réussie
/// avant la suivante ; renvoie le nonce suivant.
#[allow(clippy::too_many_arguments)]
fn send_approvals(
    rpc: &eth_rpc::EthRpc,
    network: &wallet_flow::EvmNetwork,
    signing_key: &k256::ecdsa::SigningKey,
    owner: &str,
    chain_id: u64,
    mut nonce: u64,
    contract: &[u8; 20],
    spender: &[u8; 20],
    approvals: &[u128],
    gas_price: u128,
) -> Result<u64> {
    let (approve_cap, _) = swap_gas_caps(network);
    let contract_str = derivation::format_address(contract);
    for amount in approvals {
        let data = erc20_approve_data(spender, *amount);
        let estimated = rpc.estimate_gas(owner, &contract_str, 0, &data)?;
        let gas_limit = estimated.saturating_mul(12).div_ceil(10).max(eth_tx::intrinsic_gas(&data));
        anyhow::ensure!(
            gas_limit <= approve_cap,
            "gas estimé anormalement élevé pour l'autorisation ({gas_limit}, maximum {approve_cap}) — échange refusé"
        );
        let tx = eth_tx::EthTx { nonce, gas_price, gas_limit, to: *contract, value: 0, chain_id, data };
        let hash = rpc.send_raw_transaction(&tx.sign(signing_key)?)?;
        wait_for_success(rpc, &hash)?;
        nonce += 1;
    }
    Ok(nonce)
}

/// Frais maximum d'un échange THORChain depuis un réseau EVM, montrés AVANT
/// la confirmation avec le prix du gas qui sera signé : dépôt au plafond de
/// gas (+ frais L1 sur Base) et, pour un jeton, la ou les autorisations
/// préalables (deux quand une autorisation partielle doit être remise à 0).
pub struct EvmSwapFees {
    pub deposit: EvmFee,
    pub approve: EvmFee,
    /// Autorisations à envoyer avant le dépôt (0 pour une monnaie native, ou
    /// si l'autorisation déjà accordée suffit).
    pub approvals: usize,
}

impl EvmSwapFees {
    pub fn max_total(&self) -> Result<u128> {
        let approvals = self.approve.max_total()?.checked_mul(self.approvals as u128).context("frais dépassant la capacité représentable")?;
        self.deposit.max_total()?.checked_add(approvals).context("frais dépassant la capacité représentable")
    }
}

pub fn evm_swap_fees(
    network: &wallet_flow::EvmNetwork,
    from: &thorchain_rpc::ThorAsset,
    quote: &thorchain_rpc::SwapQuote,
    amount: &str,
    gas_price: u128,
    owner: Option<&str>,
) -> Result<EvmSwapFees> {
    let router = wallet_flow::parse_evm_address(quote.router.as_deref().context("devis THORChain sans adresse de routeur")?)?;
    let vault = wallet_flow::parse_evm_address(&quote.inbound_address)?;
    let units = tokens::parse_amount(amount, from.decimals as u8)?;
    let (asset, value) = match from.contract {
        Some(contract) => (wallet_flow::parse_evm_address(contract)?, 0),
        None => ([0u8; 20], units),
    };
    let draft = eth_tx::thorchain_deposit_calldata(&vault, &asset, units, &quote.memo, u64::MAX);
    let (approve_cap, deposit_cap) = swap_gas_caps(network);
    let deposit = EvmFee { gas_price, gas_limit: deposit_cap, l1_fee: evm_l1_fee(network, &router, value, &draft, gas_price, deposit_cap)? };
    let approve_data = erc20_approve_data(&router, units);
    let approve = EvmFee {
        gas_price,
        gas_limit: approve_cap,
        l1_fee: evm_l1_fee(network, &asset, 0, &approve_data, gas_price, approve_cap)?,
    };
    let approvals = match (from.contract, owner) {
        (None, _) => 0,
        (Some(contract), Some(owner)) => approval_amounts(get_erc20_allowance(network, contract, &wallet_flow::parse_evm_address(owner)?, &router)?, units).len(),
        (Some(_), None) => 1,
    };
    Ok(EvmSwapFees { deposit, approve, approvals })
}

/// Attend qu'une transaction soit minée et RÉUSSIE (autorisation avant un
/// dépôt), au plus `APPROVE_WAIT`.
fn wait_for_success(rpc: &eth_rpc::EthRpc, hash: &str) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        match rpc.receipt_status(hash) {
            Ok(Some(true)) => return Ok(()),
            Ok(Some(false)) => anyhow::bail!("l'autorisation du jeton a échoué on-chain ({hash}) — échange interrompu, rien d'autre n'a été envoyé"),
            _ if started.elapsed() > APPROVE_WAIT => anyhow::bail!(
                "autorisation envoyée ({hash}) mais pas encore confirmée par le réseau — relancez l'échange dans un instant (l'autorisation restera acquise)"
            ),
            _ => std::thread::sleep(std::time::Duration::from_secs(3)),
        }
    }
}

// --- Échange CoW Protocol (même réseau EVM) ----------------------------------

/// Jetons CoW (vendu, acheté) d'une paire désignée par l'interface.
pub fn cow_tokens(network: &str, from_coin: &str, to_coin: &str) -> Result<(cow::CowToken, cow::CowToken)> {
    let sell = cow::token(from_coin, network).with_context(|| format!("{from_coin} n'est pas échangeable via CoW sur ce réseau"))?;
    let buy = cow::token(to_coin, network).with_context(|| format!("{to_coin} n'est pas échangeable via CoW sur ce réseau"))?;
    Ok((sell, buy))
}

/// Forme canonique du montant vendu (décimales du jeton), affichée ET signée.
pub fn canonical_cow_amount(sell: &cow::CowToken, amount: &str) -> Result<String> {
    Ok(tokens::format_amount(tokens::parse_amount(amount, sell.decimals)?, sell.decimals))
}

/// Devis CoW pour vendre `amount` de `sell` contre `buy`, au profit de
/// `owner` (vendeur ET destinataire). Refusé tant que l'adresse des frais
/// partenaire n'est pas renseignée (voir `cow::PARTNER_FEE_RECIPIENT`).
pub fn get_cow_quote(network: &wallet_flow::EvmNetwork, sell: &cow::CowToken, buy: &cow::CowToken, amount: &str, owner: &str) -> Result<cow::CowOrder> {
    let recipient = cow::PARTNER_FEE_RECIPIENT.context("échange via CoW pas encore activé")?;
    wallet_flow::parse_evm_address(owner)?;
    cow::quote(network.id, sell, buy, tokens::parse_amount(amount, sell.decimals)?, owner, recipient)
}

/// Autorisations à envoyer au VaultRelayer de CoW avant l'ordre, et frais
/// maximum de chacune (montrés avant la confirmation, au prix du gas signé).
pub fn cow_approval_fees(network: &wallet_flow::EvmNetwork, order: &cow::CowOrder, gas_price: u128) -> Result<(EvmFee, usize)> {
    let relayer = wallet_flow::parse_evm_address(cow::VAULT_RELAYER)?;
    let contract = wallet_flow::parse_evm_address(&order.sell_token)?;
    let owner = wallet_flow::parse_evm_address(&order.receiver)?;
    let (approve_cap, _) = swap_gas_caps(network);
    let data = erc20_approve_data(&relayer, order.sell_amount);
    let fee = EvmFee { gas_price, gas_limit: approve_cap, l1_fee: evm_l1_fee(network, &contract, 0, &data, gas_price, approve_cap)? };
    let approvals = approval_amounts(get_erc20_allowance(network, &order.sell_token, &owner, &relayer)?, order.sell_amount).len();
    Ok((fee, approvals))
}

/// Marge minimale de validité au moment de signer : un ordre qui expire
/// presque aussitôt n'aurait aucune chance d'être exécuté.
const COW_MIN_REMAINING_VALIDITY_SECS: u64 = 120;

/// Échange CoW : autorisation(s) au VaultRelayer au montant exact si
/// nécessaire (mêmes règles que `send_swap_erc20`), puis signature de l'ordre
/// AFFICHÉ dans la boîte de confirmation (`order`), sans nouveau devis : si le
/// marché passe sous le minimum signé, l'ordre expire sans rien coûter. L'ordre
/// doit être au nom du profil qui signe (destinataire = vendeur). Aucune
/// transaction d'échange : les frais réseau de CoW sont pris sur le jeton
/// vendu, déjà comptés dans l'ordre. Renvoie l'identifiant de l'ordre.
pub fn send_cow_swap(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    sell: &cow::CowToken,
    order: &cow::CowOrder,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    anyhow::ensure!(order.network == network.id && order.sell_token == sell.address && !sell.native, "ordre CoW incohérent — échange refusé");
    let contract_bytes = wallet_flow::parse_evm_address(&sell.address)?;
    let relayer = wallet_flow::parse_evm_address(cow::VAULT_RELAYER)?;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(address_str.eq_ignore_ascii_case(&order.receiver), "l'ordre CoW n'est pas au nom de ce profil — échange refusé");
    let rpc = eth_rpc::EthRpc::new(network.rpc);

    let (nonce, chain_id, balance, token_balance, allowance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let token_balance = scope.spawn(|| get_erc20_balance(network, &sell.address, &address_str));
        let allowance = scope.spawn(|| get_erc20_allowance(network, &sell.address, &address, &relayer));
        let join = "un fil de lecture ne doit pas paniquer";
        (nonce.join().expect(join), chain_id.join().expect(join), balance.join().expect(join), token_balance.join().expect(join), allowance.join().expect(join))
    });
    let (nonce, chain_id, balance, token_balance, allowance) = (nonce?, chain_id?, balance?, token_balance?, allowance?);
    anyhow::ensure!(chain_id == network.chain_id, "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé", network.chain_id);
    anyhow::ensure!(
        order.sell_amount <= token_balance,
        "{} insuffisants : {} disponibles, {} demandés",
        sell.symbol,
        tokens::format_amount(token_balance, sell.decimals),
        tokens::format_amount(order.sell_amount, sell.decimals)
    );

    let approvals = approval_amounts(allowance, order.sell_amount);
    ensure_fees_covered(network, &contract_bytes, &relayer, &approvals, gas_price, 0, balance)?;
    send_approvals(&rpc, network, &signing_key, &address_str, chain_id, nonce, &contract_bytes, &relayer, &approvals, gas_price)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).context("horloge système invalide")?.as_secs();
    anyhow::ensure!(
        u64::from(order.valid_to) >= now + COW_MIN_REMAINING_VALIDITY_SECS,
        "le devis CoW a expiré pendant l'autorisation — relancez l'échange (l'autorisation reste acquise)"
    );
    let digest = cow::digest(order, chain_id)?;
    let signature = evm_sign::sign_digest(&signing_key, &digest)?;
    cow::submit(order, &digest, &signature, &address_str)
}

/// Frais maximum de la transaction EthFlow (`createOrder`), montrés avant la
/// confirmation au prix du gas signé (+ frais de publication sur Base).
pub fn cow_eth_flow_fee(network: &wallet_flow::EvmNetwork, order: &cow::CowOrder, gas_price: u128) -> Result<EvmFee> {
    let contract = wallet_flow::parse_evm_address(cow::ETH_FLOW)?;
    let data = cow::eth_flow_calldata(order)?;
    let (_, cap) = swap_gas_caps(network);
    Ok(EvmFee { gas_price, gas_limit: cap, l1_fee: evm_l1_fee(network, &contract, order.sell_amount, &data, gas_price, cap)? })
}

/// Vente de la monnaie du réseau via le contrat EthFlow de CoW : la
/// transaction `createOrder` — construite ici, au prix du gas affiché — lui
/// confie le montant de l'ordre AFFICHÉ (`order`), au nom du profil qui
/// signe. Avant l'envoi, l'appData est déposée chez CoW : l'ordre on-chain
/// n'en porte que l'empreinte, et c'est elle qui déclare les frais partenaire.
/// Non exécuté, l'ordre expire et CoW rembourse. Renvoie (transaction,
/// identifiant de l'ordre).
pub fn send_cow_eth_flow(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    order: &cow::CowOrder,
    gas_price: u128,
    profile_index: u32,
) -> Result<(String, String)> {
    check_evm_gas_price(network, gas_price)?;
    anyhow::ensure!(
        order.network == network.id && order.eth_flow_quote_id.is_some() && cow::wrapped_native(network.id) == Some(order.sell_token.as_str()),
        "ordre CoW incohérent — échange refusé"
    );
    let contract = wallet_flow::parse_evm_address(cow::ETH_FLOW)?;
    let data = cow::eth_flow_calldata(order)?;

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(address_str.eq_ignore_ascii_case(&order.receiver), "l'ordre CoW n'est pas au nom de ce profil — échange refusé");
    let rpc = eth_rpc::EthRpc::new(network.rpc);

    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let join = "un fil de lecture ne doit pas paniquer";
        (nonce.join().expect(join), chain_id.join().expect(join), balance.join().expect(join))
    });
    let (nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
    anyhow::ensure!(chain_id == network.chain_id, "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé", network.chain_id);

    // Montant + frais au pire (plafond de gas) couverts AVANT l'estimation, qui
    // échouerait sinon avec une erreur brute du nœud.
    let worst_case = cow_eth_flow_fee(network, order, gas_price)?
        .max_total()?
        .checked_add(order.sell_amount)
        .context("montant + frais dépassant la capacité représentable")?;
    anyhow::ensure!(
        worst_case <= balance,
        "fonds insuffisants : {} {sym} disponibles, jusqu'à {} {sym} nécessaires (montant + frais du réseau)",
        tokens::format_amount(balance, 18),
        tokens::format_amount(worst_case, 18),
        sym = network.native_symbol
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH).context("horloge système invalide")?.as_secs();
    anyhow::ensure!(u64::from(order.valid_to) >= now + COW_MIN_REMAINING_VALIDITY_SECS, "le devis CoW a expiré — relancez l'échange");

    let estimated = rpc.estimate_gas(&address_str, cow::ETH_FLOW, order.sell_amount, &data)?;
    let gas_limit = estimated.saturating_mul(12).div_ceil(10).max(eth_tx::intrinsic_gas(&data));
    let (_, cap) = swap_gas_caps(network);
    anyhow::ensure!(gas_limit <= cap, "gas estimé anormalement élevé pour l'ordre EthFlow ({gas_limit}, maximum {cap}) — échange refusé");

    let uid = cow::eth_flow_uid(order, chain_id)?;
    cow::upload_app_data(order)?;
    let tx = eth_tx::EthTx { nonce, gas_price, gas_limit, to: contract, value: order.sell_amount, chain_id, data };
    let hash = rpc.send_raw_transaction(&tx.sign(&signing_key)?)?;
    Ok((hash, uid))
}

// --- Échange LI.FI (entre deux écosystèmes) ------------------------------------

/// Ponts qui gardent le destinataire hors chaîne quand l'arrivée n'est pas sur
/// un réseau EVM (relevé le 02/10/2026 : l'événement du contrat ne porte
/// qu'un marqueur) : écartés d'emblée depuis un réseau EVM, sinon chaque devis
/// serait refusé à la vérification. Vers un réseau EVM, le destinataire est
/// dans `BridgeData` : ils restent permis.
const LIFI_HIDDEN_RECEIVER_BRIDGES: [&str; 1] = ["relaydepository"];
/// Plafond du gas d'un appel LI.FI (pont avec échange préalable : ~550 000
/// mesurés en simulation sur Ethereum).
const LIFI_MAX_GAS: u64 = 1_000_000;
/// Budget de frais Solana d'un envoi LI.FI (frais, priorité, rent d'un compte
/// d'ordre du pont) : 0,01 SOL.
pub const LIFI_SOL_FEE_BUDGET_LAMPORTS: u64 = 10_000_000;

/// Jetons LI.FI (envoyé, reçu) d'une paire désignée par l'interface.
pub fn lifi_tokens(from_coin: &str, from_network: &str, to_coin: &str, to_network: &str) -> Result<(lifi::LifiToken, lifi::LifiToken)> {
    let from = lifi::token(from_coin, from_network).context("crypto non échangeable via LI.FI")?;
    let to = lifi::token(to_coin, to_network).context("crypto non échangeable via LI.FI")?;
    Ok((from, to))
}

/// Forme canonique du montant envoyé (décimales du jeton), affichée ET signée.
pub fn canonical_lifi_amount(from: &lifi::LifiToken, amount: &str) -> Result<String> {
    Ok(tokens::format_amount(tokens::parse_amount(amount, from.decimals)?, from.decimals))
}

fn lifi_initial_deny(from_network: &str, to_network: &str) -> Vec<String> {
    if lifi::diamond(from_network).is_some() && lifi::diamond(to_network).is_none() {
        LIFI_HIDDEN_RECEIVER_BRIDGES.iter().map(|b| b.to_string()).collect()
    } else {
        Vec::new()
    }
}

/// Devis LI.FI pour l'aperçu (sans vérification de la transaction, faite à
/// la confirmation) : mêmes ponts écartés que pour l'envoi.
#[allow(clippy::too_many_arguments)]
pub fn get_lifi_quote(
    from_network: &'static str,
    from: &lifi::LifiToken,
    to_network: &'static str,
    to: &lifi::LifiToken,
    amount: &str,
    from_address: &str,
    to_address: &str,
) -> Result<lifi::LifiQuote> {
    lifi::Receiver::parse(to_network, to_address)?;
    let units = tokens::parse_amount(amount, from.decimals)?;
    lifi::quote(from_network, from, to_network, to, units, from_address, to_address, &lifi_initial_deny(from_network, to_network), None)
}

/// Vérifie la transaction d'un devis LI.FI avant signature (voir
/// `core/src/lifi.rs`). `Some(true)` : destinataire vérifié ; `Some(false)` :
/// effets vérifiés mais destinataire géré hors chaîne par le pont (source
/// Solana, dit dans la boîte de confirmation) ; `None` : pont qui cache le
/// destinataire depuis un réseau EVM, à écarter.
fn verify_lifi_quote(quote: &lifi::LifiQuote, receiver: &lifi::Receiver) -> Result<Option<bool>> {
    match &quote.tx {
        lifi::LifiTx::Evm { to, data, value } => {
            let network = wallet_flow::evm_network(quote.from_network).context("réseau EVM inconnu")?;
            let sell_token = if quote.from.native { None } else { Some(wallet_flow::parse_evm_address(&quote.from.address)?) };
            let expected = lifi::Expected {
                user: wallet_flow::parse_evm_address(&quote.from_address)?,
                sell_token,
                amount: quote.from_amount,
                diamond: *to,
                destination_chain: quote.to.chain,
                receiver,
                integrator: lifi::INTEGRATOR,
            };
            if !lifi::simulates(quote.from_network) {
                lifi::verify_static(data, &expected)?;
                return Ok(Some(true));
            }
            let diamond = derivation::format_address(to);
            let approve = sell_token.map(|_| erc20_approve_data(to, quote.from_amount));
            let mut calls = Vec::new();
            if let Some(approve) = &approve {
                calls.push(eth_rpc::SimCallRequest { from: &quote.from_address, to: &quote.from.address, value: 0, data: approve });
            }
            calls.push(eth_rpc::SimCallRequest { from: &quote.from_address, to: &diamond, value: *value, data });
            let simulated = eth_rpc::EthRpc::new(network.rpc).simulate_v1(&calls)?;
            Ok(match lifi::verify_simulation(&simulated, &expected)? {
                lifi::Verification::Verified => Some(true),
                lifi::Verification::ReceiverHidden { .. } => None,
            })
        }
        lifi::LifiTx::Solana { raw } => {
            let owner: [u8; 32] = bs58::decode(&quote.from_address).into_vec().ok().and_then(|v| v.try_into().ok()).context("adresse Solana invalide")?;
            let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
            check_swap_effects(&rpc, raw, &lifi_solana_limits(owner, quote)?)?;
            Ok(Some(false))
        }
        // Dépôt vérifié par `lifi_btc_deposit` (sorties relues sur Esplora) :
        // avant la boîte de confirmation, qui en montre les frais, puis de
        // nouveau juste avant la signature (`send_lifi_btc`) — pas ici, pour
        // ne pas relire deux fois les mêmes données à chaque étape.
        lifi::LifiTx::Bitcoin { .. } => Ok(Some(false)),
    }
}

/// Dépôt Bitcoin d'un devis LI.FI vérifié contre les sorties confirmées de
/// l'adresse, relues ICI (voir `lifi::verify_btc_deposit`), avec un tarif
/// de frais réseau au plus double du tarif « prochain bloc » d'Esplora (20
/// sat/vB au moins, `BTC_SWAP_MAX_FEE_RATE_SAT_VB` au plus) : c'est LI.FI
/// qui fixe ces frais, l'app les borne.
pub fn lifi_btc_deposit(quote: &lifi::LifiQuote) -> Result<lifi::BtcDeposit> {
    let lifi::LifiTx::Bitcoin { psbt, deposit_script, .. } = &quote.tx else { anyhow::bail!("devis LI.FI non Bitcoin") };
    let network = &wallet_flow::BTC_MAINNET;
    let own_script = crate::btc_tx::p2wpkh_script_pubkey(&(network.parse_address)(&quote.from_address)?);
    let esplora = btc_rpc::EsploraClient::new(network.esplora_base);
    let (utxos, estimates) = std::thread::scope(|scope| {
        let utxos = scope.spawn(|| esplora.utxos(&quote.from_address));
        let estimates = esplora.fee_estimates();
        (utxos.join().expect("le thread UTXOs ne doit pas paniquer"), estimates)
    });
    let max_fee_rate = (fee_rate_for_target(&estimates?, 1) * 2.0).ceil().clamp(20.0, f64::from(BTC_SWAP_MAX_FEE_RATE_SAT_VB)) as u64;
    let amount = u64::try_from(quote.from_amount).context("montant hors limites")?;
    lifi::verify_btc_deposit(psbt, deposit_script, &own_script, &utxos?, amount, max_fee_rate)
}

/// Envoi LI.FI depuis Bitcoin : dépôt revérifié juste avant la signature
/// (sorties relues, frais réseau au plus `max_network_fee`, le plafond
/// affiché), transaction re-sérialisée et signée par l'app au nom du profil,
/// diffusée via Esplora. Renvoie l'identifiant de la transaction.
pub fn send_lifi_btc(data_dir: &Path, device_password: &str, quote: &lifi::LifiQuote, max_network_fee: u64, profile_index: u32) -> Result<String> {
    let network = &wallet_flow::BTC_MAINNET;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, hash160) = (network.derive_key)(&seed, profile_index)?;
    anyhow::ensure!((network.format_address)(&hash160)? == quote.from_address, "la transaction LI.FI n'est pas au nom de ce profil — échange refusé");
    let deposit = lifi_btc_deposit(quote)?;
    anyhow::ensure!(
        deposit.network_fee <= max_network_fee,
        "les frais réseau Bitcoin de la transaction LI.FI ont augmenté depuis la confirmation — relancez l'échange"
    );
    let raw = deposit.tx.sign(&signing_key, &hash160)?;
    btc_rpc::EsploraClient::new(network.esplora_base).broadcast(&raw)
}

/// Bornes d'un envoi LI.FI depuis Solana : le jeton vendu sort au plus du
/// montant, les lamports au plus du montant (SOL) + budget de frais, rien
/// n'est attendu en retour sur Solana.
fn lifi_solana_limits(owner: [u8; 32], quote: &lifi::LifiQuote) -> Result<SwapEffectLimits> {
    let amount = u64::try_from(quote.from_amount).context("montant hors limites")?;
    let (sold_lamports, input_token) = if quote.from.native {
        (amount, None)
    } else {
        let mint: [u8; 32] = bs58::decode(&quote.from.address).into_vec().ok().and_then(|v| v.try_into().ok()).context("mint invalide")?;
        (0, Some((mint, amount)))
    };
    Ok(SwapEffectLimits {
        user: owner,
        max_lamport_loss: sold_lamports.checked_add(LIFI_SOL_FEE_BUDGET_LAMPORTS).context("montant hors limites")?,
        input_token,
        min_output: MinOutput::Nothing,
    })
}

/// Devis LI.FI dont la transaction a passé la vérification : nouveau devis
/// sans le pont fautif tant que le destinataire est caché (au plus
/// `lifi::MAX_ROUTE_ATTEMPTS` fois). Renvoie le devis et si le destinataire a
/// été vérifié.
#[allow(clippy::too_many_arguments)]
pub fn lifi_verified_quote(
    from_network: &'static str,
    from: &lifi::LifiToken,
    to_network: &'static str,
    to: &lifi::LifiToken,
    amount: &str,
    from_address: &str,
    to_address: &str,
) -> Result<(lifi::LifiQuote, bool)> {
    let receiver = lifi::Receiver::parse(to_network, to_address)?;
    let units = tokens::parse_amount(amount, from.decimals)?;
    ensure_lifi_balance(from_network, from, units, from_address)?;
    let mut deny = lifi_initial_deny(from_network, to_network);
    for _ in 0..lifi::MAX_ROUTE_ATTEMPTS {
        let quote = lifi::quote(from_network, from, to_network, to, units, from_address, to_address, &deny, None)?;
        match verify_lifi_quote(&quote, &receiver)? {
            Some(verified) => return Ok((quote, verified)),
            None => deny.push(quote.tool.clone()),
        }
    }
    anyhow::bail!("aucune route LI.FI dont le destinataire soit vérifiable (ponts écartés : {})", deny.join(", "))
}

/// Solde suffisant pour l'envoi, vérifié avant la simulation (qui échouerait
/// sinon avec un message trompeur).
fn ensure_lifi_balance(from_network: &str, from: &lifi::LifiToken, units: u128, from_address: &str) -> Result<()> {
    let available = if from_network == "btc_mainnet" {
        // Sorties confirmées seulement : les seules que le dépôt peut dépenser.
        let utxos = btc_rpc::EsploraClient::new(wallet_flow::BTC_MAINNET.esplora_base).utxos(from_address)?;
        utxos.iter().map(|u| u128::from(u.value_sat)).sum()
    } else if let Some(network) = wallet_flow::evm_network(from_network) {
        if from.native {
            eth_rpc::EthRpc::new(network.rpc).balance(from_address)?
        } else {
            get_erc20_balance(network, &from.address, from_address)?
        }
    } else {
        let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
        if from.native {
            u128::from(rpc.balance_lamports(from_address)?)
        } else {
            let owner: [u8; 32] = bs58::decode(from_address).into_vec().ok().and_then(|v| v.try_into().ok()).context("adresse Solana invalide")?;
            let mint: [u8; 32] = bs58::decode(&from.address).into_vec().ok().and_then(|v| v.try_into().ok()).context("mint invalide")?;
            let ata = bs58::encode(sol_spl::find_associated_token_address(&owner, &mint)).into_string();
            u128::from(rpc.token_account_balance(&ata)?.unwrap_or(0))
        }
    };
    anyhow::ensure!(
        units <= available,
        "{} insuffisants : {} disponibles, {} demandés",
        from.symbol,
        tokens::format_amount(available, from.decimals),
        tokens::format_amount(units, from.decimals)
    );
    Ok(())
}

/// Devis RE-demandé après la confirmation (la boîte native reste ouverte un
/// temps arbitraire, la transaction d'un pont expire vite) sur le MÊME pont,
/// refusé s'il ne correspond plus à ce qui a été affiché : même destinataire,
/// minimum d'au moins 99 % de celui affiché, même niveau de vérification.
pub fn refresh_lifi_quote_matching(shown: &lifi::LifiQuote, shown_verified: bool) -> Result<lifi::LifiQuote> {
    let receiver = lifi::Receiver::parse(shown.to_network, &shown.to_address)?;
    let quote = lifi::quote(
        shown.from_network,
        &shown.from,
        shown.to_network,
        &shown.to,
        shown.from_amount,
        &shown.from_address,
        &shown.to_address,
        &[],
        Some(&shown.tool),
    )?;
    anyhow::ensure!(quote.tool == shown.tool, "LI.FI propose maintenant un autre pont que celui affiché — relancez l'échange");
    if let (lifi::LifiTx::Bitcoin { deposit: shown_deposit, .. }, lifi::LifiTx::Bitcoin { deposit, .. }) = (&shown.tx, &quote.tx) {
        anyhow::ensure!(deposit == shown_deposit, "l'adresse de dépôt du pont a changé pendant la confirmation — relancez l'échange");
    }
    anyhow::ensure!(
        quote.to_amount_min.saturating_mul(100) >= shown.to_amount_min.saturating_mul(99),
        "le minimum annoncé par LI.FI a baissé de plus de 1 % depuis l'affichage — relancez l'échange"
    );
    anyhow::ensure!(
        verify_lifi_quote(&quote, &receiver)? == Some(shown_verified),
        "la nouvelle transaction LI.FI ne passe plus la même vérification — relancez l'échange"
    );
    Ok(quote)
}

/// Frais maximum d'un envoi LI.FI depuis un réseau EVM, montrés avant la
/// confirmation : l'appel au plafond de gas (+ frais L1 sur Base) et les
/// autorisations au contrat LI.FI s'il en faut.
pub fn lifi_evm_fees(network: &wallet_flow::EvmNetwork, quote: &lifi::LifiQuote, gas_price: u128) -> Result<(EvmFee, EvmFee, usize)> {
    let lifi::LifiTx::Evm { to, data, value } = &quote.tx else { anyhow::bail!("devis LI.FI non EVM") };
    let cap = lifi_gas_cap(network);
    let call = EvmFee { gas_price, gas_limit: cap, l1_fee: evm_l1_fee(network, to, *value, data, gas_price, cap)? };
    let (approve_cap, _) = swap_gas_caps(network);
    let (approve, approvals) = if quote.from.native {
        (EvmFee { gas_price, gas_limit: 0, l1_fee: 0 }, 0)
    } else {
        let contract = wallet_flow::parse_evm_address(&quote.from.address)?;
        let approve_data = erc20_approve_data(to, quote.from_amount);
        let fee = EvmFee { gas_price, gas_limit: approve_cap, l1_fee: evm_l1_fee(network, &contract, 0, &approve_data, gas_price, approve_cap)? };
        let owner = wallet_flow::parse_evm_address(&quote.from_address)?;
        (fee, approval_amounts(get_erc20_allowance(network, &quote.from.address, &owner, to)?, quote.from_amount).len())
    };
    Ok((call, approve, approvals))
}

fn lifi_gas_cap(network: &wallet_flow::EvmNetwork) -> u64 {
    // Arbitrum : la limite de gas compte aussi la publication sur Ethereum.
    if network.transfer_gas.is_none() {
        EVM_MAX_ESTIMATED_GAS
    } else {
        LIFI_MAX_GAS
    }
}

/// Envoi LI.FI depuis un réseau EVM : la transaction AFFICHÉE et vérifiée
/// (`quote`), au nom du profil qui signe, au prix du gas affiché ;
/// autorisation au montant exact au contrat LI.FI si nécessaire (mêmes règles
/// que les autres échanges). Renvoie le hash de la transaction.
pub fn send_lifi_evm(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::EvmNetwork,
    quote: &lifi::LifiQuote,
    gas_price: u128,
    profile_index: u32,
) -> Result<String> {
    check_evm_gas_price(network, gas_price)?;
    let lifi::LifiTx::Evm { to, data, value } = &quote.tx else { anyhow::bail!("devis LI.FI non EVM") };
    anyhow::ensure!(quote.from_network == network.id && lifi::diamond(network.id).map(wallet_flow::parse_evm_address).transpose()? == Some(*to), "transaction LI.FI incohérente — échange refusé");
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    anyhow::ensure!(address_str.eq_ignore_ascii_case(&quote.from_address), "la transaction LI.FI n'est pas au nom de ce profil — échange refusé");
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    let diamond = derivation::format_address(to);

    let (nonce, chain_id, balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let balance = scope.spawn(|| rpc.balance(&address_str));
        let join = "un fil de lecture ne doit pas paniquer";
        (nonce.join().expect(join), chain_id.join().expect(join), balance.join().expect(join))
    });
    let (mut nonce, chain_id, balance) = (nonce?, chain_id?, balance?);
    anyhow::ensure!(chain_id == network.chain_id, "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé", network.chain_id);

    let cap = lifi_gas_cap(network);
    let call_fee = gas_price
        .checked_mul(u128::from(cap))
        .and_then(|g| g.checked_add(evm_l1_fee(network, to, *value, data, gas_price, cap).ok()?))
        .and_then(|f| f.checked_add(*value))
        .context("montant + frais dépassant la capacité représentable")?;
    if quote.from.native {
        ensure_fees_covered(network, to, to, &[], gas_price, call_fee, balance)?;
    } else {
        let contract = wallet_flow::parse_evm_address(&quote.from.address)?;
        let token_balance = get_erc20_balance(network, &quote.from.address, &address_str)?;
        anyhow::ensure!(
            quote.from_amount <= token_balance,
            "{} insuffisants : {} disponibles, {} demandés",
            quote.from.symbol,
            tokens::format_amount(token_balance, quote.from.decimals),
            tokens::format_amount(quote.from_amount, quote.from.decimals)
        );
        let approvals = approval_amounts(get_erc20_allowance(network, &quote.from.address, &address, to)?, quote.from_amount);
        ensure_fees_covered(network, &contract, to, &approvals, gas_price, call_fee, balance)?;
        nonce = send_approvals(&rpc, network, &signing_key, &address_str, chain_id, nonce, &contract, to, &approvals, gas_price)?;
    }

    let estimated = rpc.estimate_gas(&address_str, &diamond, *value, data)?;
    let gas_limit = estimated.saturating_mul(12).div_ceil(10).max(eth_tx::intrinsic_gas(data));
    anyhow::ensure!(gas_limit <= cap, "gas estimé anormalement élevé pour l'échange LI.FI ({gas_limit}, maximum {cap}) — échange refusé");
    let tx = eth_tx::EthTx { nonce, gas_price, gas_limit, to: *to, value: *value, chain_id, data: data.clone() };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

/// Envoi LI.FI depuis Solana : effets revérifiés par simulation juste avant
/// la signature (le jeton vendu sort au plus du montant, rien d'autre ne
/// quitte l'utilisateur au-delà du budget de frais, aucune autorité cédée),
/// puis signature de la transaction AFFICHÉE au nom du profil.
pub fn send_lifi_solana(data_dir: &Path, device_password: &str, quote: &lifi::LifiQuote, profile_index: u32) -> Result<String> {
    let lifi::LifiTx::Solana { raw } = &quote.tx else { anyhow::bail!("devis LI.FI non Solana") };
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    anyhow::ensure!(bs58::encode(owner).into_string() == quote.from_address, "la transaction LI.FI n'est pas au nom de ce profil — échange refusé");
    let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
    check_swap_effects(&rpc, raw, &lifi_solana_limits(owner, quote)?)?;
    // Blockhash frais de notre nœud (voir `jupiter_rpc::with_recent_blockhash`).
    let raw = jupiter_rpc::with_recent_blockhash(raw, &rpc.latest_blockhash()?)?;
    let signed = jupiter_rpc::sign_swap_transaction(&raw, &signing_key, &owner)?;
    rpc.send_transaction(&signed)
}

// --- Monero ----------------------------------------------------------------------

/// Synchronise les comptes Monero jusqu'au bout de la chaîne (appelé en
/// arrière-plan après le déverrouillage).
pub fn sync_xmr(data_dir: &Path, keys: &[monero::ViewKeys]) -> Result<()> {
    monero::sync(data_dir, keys)
}

pub fn xmr_balance(data_dir: &Path, profile_index: u32) -> Result<monero::Balance> {
    monero::balance(data_dir, profile_index)
}

pub fn xmr_history(data_dir: &Path, profile_index: u32) -> Result<Vec<history::TxEntry>> {
    monero::history(data_dir, profile_index)
}

pub fn xmr_has_received(data_dir: &Path) -> bool {
    monero::has_received(data_dir)
}

pub fn has_pending_xmr(data_dir: &Path, profile_index: u32) -> Result<bool> {
    monero::has_pending(data_dir, profile_index)
}

pub fn canonical_xmr_amount(amount: &str) -> Result<String> {
    Ok(monero::format_xmr(monero::parse_xmr(amount)?))
}

/// Envoi préparé pour la boîte de confirmation : destinataire vérifié
/// (jamais soi-même), sorties choisies, leurres tirés, frais calculés —
/// exactement ce que `send_xmr` signera.
pub fn xmr_send_plan(data_dir: &Path, keys: &monero::ViewKeys, to: &str, amount: &str) -> Result<monero::SendPlan> {
    monero::prepare_send(data_dir, keys, to, monero::parse_xmr(amount)?)
}

/// Signe l'envoi préparé (et confirmé) avec la clé de dépense tirée de la
/// seed, le diffuse et renvoie l'identifiant de la transaction.
pub fn send_xmr(data_dir: &Path, device_password: &str, plan: monero::SendPlan) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    monero::sign_and_send(data_dir, &seed, plan)
}

/// « Réanalyser depuis le début » (Paramètres) : Monero et Zcash protégé relus
/// depuis la naissance fixe de l'app — pour des fonds plus anciens que la
/// création du portefeuille sur cet appareil (portefeuille importé autrement).
pub fn rescan_private_funds(data_dir: &Path) -> Result<()> {
    wallet_birthday::forget(data_dir);
    monero::rescan_from_birthday(data_dir)?;
    zcash_shielded::request_rescan(data_dir)
}

/// Nœud Monero choisi dans Paramètres (`None` : nœuds publics par défaut).
pub fn xmr_node(data_dir: &Path) -> Option<String> {
    monero::custom_node(data_dir)
}

pub fn set_xmr_node(data_dir: &Path, url: &str) -> Result<Option<String>> {
    monero::set_custom_node(data_dir, url)
}

// --- Zcash protégé (Orchard) ------------------------------------------------------

/// Crée les comptes protégés manquants puis synchronise jusqu'au bout de la
/// chaîne (appelé en arrière-plan après le déverrouillage).
pub fn sync_zec_shielded(data_dir: &Path, keys: &[zcash_shielded::ProfileKeys]) -> Result<()> {
    zcash_shielded::ensure_accounts(data_dir, keys)?;
    zcash_shielded::sync(data_dir)
}

pub fn zec_shielded_balance(data_dir: &Path, profile_index: u32) -> Result<zcash_shielded::ShieldedBalance> {
    zcash_shielded::balance(data_dir, profile_index)
}

pub fn zec_shielded_history(data_dir: &Path, profile_index: u32) -> Result<Vec<history::TxEntry>> {
    zcash_shielded::history(data_dir, profile_index)
}

/// Protège les ZEC de l'adresse t1 du profil : résumé confirmé par
/// `confirm`, puis seed déverrouillée (mot de passe), signature, diffusion.
/// `Ok(None)` : confirmation refusée.
pub fn shield_zec(data_dir: &Path, device_password: &str, profile_index: u32, t1: &str, confirm: impl FnOnce(&zcash_shielded::SpendSummary) -> bool) -> Result<Option<String>> {
    zcash_shielded::shield(data_dir, profile_index, t1, confirm, || unlock_seed(data_dir, device_password))
}

/// Envoie depuis les fonds protégés du profil (montant en ZEC, 8 décimales).
pub fn send_zec_shielded(
    data_dir: &Path,
    device_password: &str,
    profile_index: u32,
    to: &str,
    amount: &str,
    confirm: impl FnOnce(&zcash_shielded::SpendSummary) -> bool,
) -> Result<Option<String>> {
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    zcash_shielded::send(data_dir, profile_index, to, units, confirm, || unlock_seed(data_dir, device_password))
}

// --- Zcash (adresses transparentes) ---------------------------------------------

pub fn get_zec_balance(address: &str) -> Result<u64> {
    zcash::balance(address)
}

/// État d'une adresse Zcash destinataire, pour les avertissements de la boîte.
pub fn zec_recipient_activity(to: &str) -> Result<RecipientActivity> {
    let address = zcash::transparent_address(&zcash::parse_recipient(to)?);
    Ok(match zcash::address_activity(&address)? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Forme canonique d'un montant en ZEC (8 décimales), affichée ET signée.
pub fn canonical_zec_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(tokens::parse_amount(amount, 8)?, 8))
}

/// Envoi préparé pour la boîte de confirmation : destinataire vérifié (t1,
/// t3, tex1 ; jamais soi-même), sorties choisies, frais ZIP-317 et monnaie
/// rendue.
pub fn zec_send_plan(from_address: &str, to: &str, amount: &str) -> Result<zcash::SendPlan> {
    let recipient = zcash::parse_recipient(to)?;
    anyhow::ensure!(recipient != zcash::parse_recipient(from_address)?, "envoi vers votre propre adresse Zcash");
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    zcash::plan_send(zcash::utxos(from_address)?, units)
}

/// Envoi Zcash : sorties relues, frais jamais supérieurs à ceux affichés
/// (`shown_fee`), branche de consensus vérifiée auprès du serveur,
/// transaction construite et signée ici, puis diffusée.
pub fn send_zec(data_dir: &Path, device_password: &str, to: &str, amount: &str, shown_fee: u64, profile_index: u32) -> Result<String> {
    let recipient = zcash::parse_recipient(to)?;
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_zec_key(&seed, profile_index)?;
    anyhow::ensure!(recipient != zcash::Recipient::P2pkh(hash160), "envoi vers votre propre adresse Zcash");
    let from = zcash::p2pkh_address(&hash160);
    let plan = zcash::plan_send(zcash::utxos(&from)?, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Zcash ont augmenté depuis la confirmation ({} au lieu de {} ZEC) — relancez l'envoi",
        zcash::format_zec(plan.fee),
        zcash::format_zec(shown_fee)
    );
    let chain = zcash::chain_info()?;
    let target = chain.height + 1;
    let branch = zcash::branch_for(target, chain.branch_id)?;
    let signed = zcash::build_signed(&plan, &key, &hash160, &recipient, target, branch)?;
    zcash::broadcast(&signed.raw, &signed.txid)
}

/// Dépôt d'un échange depuis Zcash (Maya), préparé pour la boîte de
/// confirmation : frais calculés pour un memo de 80 octets, le plus long
/// possible — le devis relu après la confirmation peut porter un memo d'un
/// octet de plus ou de moins, jamais des frais au-delà de ceux affichés.
pub fn zec_swap_plan(from_address: &str, quote: &thorchain_rpc::SwapQuote, amount: &str) -> Result<zcash::SendPlan> {
    let vault = zec_vault(quote)?;
    anyhow::ensure!(vault != zcash::parse_recipient(from_address)?, "adresse de dépôt Maya égale à votre propre adresse — échange refusé");
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    zcash::plan_deposit(zcash::utxos(from_address)?, units, &[0; 80])
}

/// Coffre Zcash du devis : une adresse transparente (Maya n'en annonce pas
/// d'autre, voir les notes de ses devis).
fn zec_vault(quote: &thorchain_rpc::SwapQuote) -> Result<zcash::Recipient> {
    anyhow::ensure!(
        quote.memo.len() <= 80,
        "memo Maya trop long pour une sortie OP_RETURN ({} octets)",
        quote.memo.len()
    );
    zcash::parse_recipient(&quote.inbound_address).context("adresse de dépôt Maya invalide")
}

/// Envoie un échange depuis Zcash : virement transparent vers le coffre du
/// devis, avec le memo en sortie OP_RETURN (coffre, monnaie, memo — l'ordre
/// demandé par Maya), frais ZIP-317 jamais au-delà de ceux affichés
/// (`shown_fee`), branche de consensus vérifiée auprès du serveur.
pub fn send_swap_zec(data_dir: &Path, device_password: &str, quote: &thorchain_rpc::SwapQuote, amount: &str, shown_fee: u64, profile_index: u32) -> Result<String> {
    let vault = zec_vault(quote)?;
    let units = u64::try_from(tokens::parse_amount(amount, 8)?).context("montant hors limites")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_zec_key(&seed, profile_index)?;
    anyhow::ensure!(vault != zcash::Recipient::P2pkh(hash160), "adresse de dépôt Maya égale à votre propre adresse — échange refusé");
    let from = zcash::p2pkh_address(&hash160);
    let plan = zcash::plan_deposit(zcash::utxos(&from)?, units, quote.memo.as_bytes())?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Zcash ont augmenté depuis la confirmation ({} au lieu de {} ZEC) — relancez l'échange",
        zcash::format_zec(plan.fee),
        zcash::format_zec(shown_fee)
    );
    let chain = zcash::chain_info()?;
    let target = chain.height + 1;
    let branch = zcash::branch_for(target, chain.branch_id)?;
    let signed = zcash::build_signed(&plan, &key, &hash160, &vault, target, branch)?;
    zcash::broadcast(&signed.raw, &signed.txid)
}

// --- Dogecoin -----------------------------------------------------------------------

pub fn get_doge_balance(address: &str) -> Result<u64> {
    doge::balance(address)
}

pub fn has_pending_doge(address: &str) -> Result<bool> {
    doge::has_pending(address)
}

/// État d'une adresse Dogecoin destinataire, pour les avertissements de la boîte.
pub fn doge_recipient_activity(to: &str) -> Result<RecipientActivity> {
    doge::parse_recipient(to)?;
    Ok(match doge::address_activity(to.trim())? {
        (true, _) => RecipientActivity::Funded,
        (false, true) => RecipientActivity::Empty,
        (false, false) => RecipientActivity::Unused,
    })
}

/// Forme canonique d'un montant en DOGE (8 décimales), affichée ET signée.
pub fn canonical_doge_amount(amount: &str) -> Result<String> {
    Ok(tokens::format_amount(tokens::parse_amount(amount, doge::DECIMALS)?, doge::DECIMALS))
}

/// Envoi préparé pour la boîte de confirmation : destinataire vérifié (jamais
/// soi-même), sorties choisies puis vérifiées sur leurs transactions
/// d'origine, frais au taux du moment, monnaie rendue.
pub fn doge_send_plan(from_address: &str, to: &str, amount: &str) -> Result<doge::SendPlan> {
    let own = match doge::parse_recipient(from_address)? {
        doge::Recipient::P2pkh(hash) => hash,
        doge::Recipient::P2sh(_) => anyhow::bail!("adresse Dogecoin du profil invalide"),
    };
    let recipient = doge::parse_recipient(to)?;
    anyhow::ensure!(recipient != doge::Recipient::P2pkh(own), "envoi vers votre propre adresse Dogecoin");
    let units = u64::try_from(tokens::parse_amount(amount, doge::DECIMALS)?).context("montant hors limites")?;
    doge::plan(&own, units)
}

/// Envoi Dogecoin : sorties relues et revérifiées, frais jamais supérieurs à
/// ceux affichés (`shown_fee`), transaction construite et signée ici, puis
/// diffusée.
pub fn send_doge(data_dir: &Path, device_password: &str, to: &str, amount: &str, shown_fee: u64, profile_index: u32) -> Result<String> {
    let recipient = doge::parse_recipient(to)?;
    let units = u64::try_from(tokens::parse_amount(amount, doge::DECIMALS)?).context("montant hors limites")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_doge_key(&seed, profile_index)?;
    anyhow::ensure!(recipient != doge::Recipient::P2pkh(hash160), "envoi vers votre propre adresse Dogecoin");
    let plan = doge::plan(&hash160, units)?;
    anyhow::ensure!(
        plan.fee <= shown_fee,
        "les frais Dogecoin ont augmenté depuis la confirmation ({} au lieu de {} DOGE) — relancez l'envoi",
        doge::format_doge(plan.fee),
        doge::format_doge(shown_fee)
    );
    let signed = doge::build_signed(&plan, &key, &hash160, &recipient)?;
    doge::broadcast(&signed)
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
        quote.memo.len() <= 80,
        "memo THORChain trop long pour une sortie OP_RETURN standard ({} octets)",
        quote.memo.len()
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

    // Coffre + monnaie (P2WPKH), plus la sortie OP_RETURN à sa taille réelle
    // (66 octets pour un memo de 55, contre 31 pour une sortie P2WPKH).
    let vsize = (crate::btc_tx::estimate_p2wpkh_vsize(utxos.len(), 2) + crate::btc_tx::op_return_output_size(quote.memo.len())) as f64;
    // Jamais sous le tarif conseillé par le protocole (`recommended_gas_rate`) :
    // un dépôt moins payé peut tarder à être pris en compte.
    let fee_rate = fee_rate_for_target(&estimates, 3).max(quote.recommended_gas_rate.unwrap_or(0) as f64);
    // Tarif lu auprès d'Esplora sans intervention de l'utilisateur (contrairement
    // à `send_btc`, où il choisit un palier affiché en sats) : plafonné pour qu'un
    // serveur compromis ne puisse pas gonfler les frais à volonté — même famille
    // que le plafond du prix du gas EVM (`EvmNetwork::max_gas_price_wei`). Plafond
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

/// Mint Solana (32 octets) d'une crypto échangée via Jupiter : SOL natif
/// (wSOL), ou jeton SPL du registre (USDC, USDT, EURC, RENDER…, voir
/// tokens.rs) — jamais un mint fourni par l'interface.
fn jupiter_mint_bytes_for_coin(coin: &str) -> Result<[u8; 32]> {
    match coin {
        "sol" => bs58::decode(jupiter_rpc::SOL_MINT)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("mint SOL mal formé (bug de compilation)"),
        token => registered_spl_mint(token).context("crypto non échangeable via Jupiter"),
    }
}

fn jupiter_mint_for_coin(coin: &str) -> Result<String> {
    Ok(bs58::encode(jupiter_mint_bytes_for_coin(coin)?).into_string())
}

/// Décimales d'une crypto échangée via Jupiter (SOL : 9 ; jeton : registre).
pub fn jupiter_decimals(coin: &str) -> Result<u8> {
    if coin == "sol" {
        return Ok(9);
    }
    Ok(registered_token(coin, "sol_mainnet")?.1.decimals)
}

/// Symbole affiché d'une crypto échangée via Jupiter.
pub fn jupiter_symbol(coin: &str) -> Result<&'static str> {
    if coin == "sol" {
        return Ok("SOL");
    }
    Ok(registered_token(coin, "sol_mainnet")?.0.symbol)
}

/// Montant (texte) → plus petite unité de la crypto vendue via Jupiter.
fn jupiter_amount(coin: &str, amount: &str) -> Result<u64> {
    tokens::parse_amount(amount, jupiter_decimals(coin)?)?.try_into().context("montant trop grand")
}

/// Montant d'un échange Jupiter sous sa forme canonique (affichée ET signée,
/// voir `canonical_amount`).
pub fn canonical_jupiter_amount(coin: &str, amount: &str) -> Result<String> {
    let decimals = jupiter_decimals(coin)?;
    Ok(tokens::format_amount(tokens::parse_amount(amount, decimals)?, decimals))
}

/// Obtient un devis Jupiter (lecture seule, aucun secret impliqué) — montant
/// de sortie attendu, dans la plus petite unité de l'actif de destination.
/// `amount` dans l'unité humaine de l'actif SOURCE, comme partout ailleurs
/// dans cette API.
pub fn get_jupiter_quote(from_coin: &str, to_coin: &str, amount: &str, slippage_bps: u32) -> Result<JupiterQuoteInfo> {
    let input_mint = jupiter_mint_for_coin(from_coin)?;
    let output_mint = jupiter_mint_for_coin(to_coin)?;
    let amount_native = jupiter_amount(from_coin, amount)?;
    let fee_mint = jupiter_fee_mint(&sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc), &input_mint, &output_mint)?;
    let quote = jupiter_rpc::quote(&input_mint, &output_mint, amount_native, slippage_bps, fee_mint)?;
    Ok(JupiterQuoteInfo { out_amount: quote.out_amount, fee_mint })
}

/// Devis Jupiter tel qu'affiché : sortie attendue, et jeton des frais
/// d'affiliation (`None` : échange sans frais).
pub struct JupiterQuoteInfo {
    pub out_amount: u64,
    pub fee_mint: Option<[u8; 32]>,
}

/// Jeton des frais d'affiliation d'un échange Jupiter : le premier des
/// candidats (`jupiter_rpc::fee_mint_candidates`) dont le compte de frais de
/// l'affilié EXISTE ; `None` sinon — l'échange se fait alors sans frais
/// plutôt que de faire payer à l'utilisateur la création du compte de frais
/// du développeur, ou d'échouer (Jupiter refuse un compte absent).
fn jupiter_fee_mint(rpc: &sol_rpc::SolRpc, input_mint: &str, output_mint: &str) -> Result<Option<[u8; 32]>> {
    for mint in jupiter_rpc::fee_mint_candidates(input_mint, output_mint) {
        if rpc.account_exists(&bs58::encode(jupiter_rpc::fee_account(&mint)?).into_string())? {
            return Ok(Some(mint));
        }
    }
    Ok(None)
}

/// Envoie un swap SOL <-> USDC via Jupiter (même chaîne, contrairement au
/// swap cross-chain via THORChain) — voir jupiter_rpc.rs pour le contexte
/// complet, notamment pourquoi la transaction elle-même n'est pas
/// reconstruite à la main ici (seulement vérifiée puis signée).
#[allow(clippy::too_many_arguments)]
pub fn send_jupiter_swap(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    from_coin: &str,
    to_coin: &str,
    amount: &str,
    slippage_bps: u32,
    shown_out_amount: u64,
    fee_mint: Option<[u8; 32]>,
    profile_index: u32,
) -> Result<String> {
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();
    let owner_address = bs58::encode(owner).into_string();

    let input_mint = jupiter_mint_for_coin(from_coin)?;
    let output_mint = jupiter_mint_for_coin(to_coin)?;
    let amount_native = jupiter_amount(from_coin, amount)?;

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

    // Même décision de frais que celle AFFICHÉE dans la confirmation (`fee_mint`).
    let quote = jupiter_rpc::quote(&input_mint, &output_mint, amount_native, slippage_bps, fee_mint)?;
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

    // Blockhash frais de notre nœud (voir `jupiter_rpc::with_recent_blockhash`).
    let raw_tx = jupiter_rpc::with_recent_blockhash(&raw_tx, &rpc.latest_blockhash()?)?;
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
    /// Rien n'arrive sur Solana : échange vers un autre réseau (LI.FI), où
    /// seules les pertes sont bornées.
    Nothing,
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
        MinOutput::Nothing => {}
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
        sol_rpc::SimulationOutcome::Failed { err, logs } => {
            Err(rpc.explain_simulation_failure(&err, &logs).unwrap_or_else(|| anyhow::anyhow!("échec de simulation de l'échange ({err}) :\n{logs}")))
        }
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
pub fn get_swap_quote(
    protocol: &thorchain_rpc::CrossChain,
    from: &thorchain_rpc::ThorAsset,
    to: &thorchain_rpc::ThorAsset,
    amount: &str,
    destination: &str,
) -> Result<thorchain_rpc::SwapQuote> {
    anyhow::ensure!(!std::ptr::eq(from, to), "échange d'une crypto vers elle-même");
    protocol.quote_swap(from.asset, to.asset, swap_amount_1e8(from, amount)?, destination)
}

fn swap_amount_1e8(from: &thorchain_rpc::ThorAsset, amount: &str) -> Result<u64> {
    let amount_native = tokens::parse_amount(amount, from.decimals as u8)?;
    thorchain_rpc::to_thorchain_amount(amount_native, from.decimals)
}

/// Actif d'une crypto de l'app (`coin`) sur `network` pour `protocol`
/// (THORChain ou Maya).
pub fn cross_chain_asset(protocol: &thorchain_rpc::CrossChain, coin: &str, network: &str) -> Result<&'static thorchain_rpc::ThorAsset> {
    protocol
        .asset(coin, network)
        .ok_or_else(|| anyhow::anyhow!("échange {} non disponible pour cette crypto sur ce réseau", protocol.name))
}

/// Montant d'un échange sous sa forme canonique (affichée ET signée, voir
/// `canonical_amount`), selon les décimales de l'actif source.
pub fn canonical_swap_amount(from: &thorchain_rpc::ThorAsset, amount: &str) -> Result<String> {
    let decimals = from.decimals as u8;
    Ok(tokens::format_amount(tokens::parse_amount(amount, decimals)?, decimals))
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
    protocol: &thorchain_rpc::CrossChain,
    from: &thorchain_rpc::ThorAsset,
    to: &thorchain_rpc::ThorAsset,
    amount: &str,
    destination: &str,
    shown: &thorchain_rpc::SwapQuote,
) -> Result<thorchain_rpc::SwapQuote> {
    // Même affilié que le devis affiché (frais annoncés dans la boîte).
    let fresh = protocol.quote_swap_as(from.asset, to.asset, swap_amount_1e8(from, amount)?, destination, shown.affiliate.as_deref())?;
    ensure_quote_matches_shown(protocol, &fresh, shown, to.asset, destination)?;
    Ok(fresh)
}

fn ensure_quote_matches_shown(
    protocol: &thorchain_rpc::CrossChain,
    fresh: &thorchain_rpc::SwapQuote,
    shown: &thorchain_rpc::SwapQuote,
    to_asset: &str,
    destination: &str,
) -> Result<()> {
    anyhow::ensure!(
        fresh.inbound_address == shown.inbound_address && fresh.router == shown.router,
        "l'adresse de dépôt {} a changé pendant la confirmation — relancez l'échange pour voir la nouvelle",
        protocol.name
    );
    protocol
        .verify_memo(&fresh.memo, shown.affiliate.as_deref(), to_asset, destination, shown.expected_amount_out)
        .context("le cours a bougé pendant la confirmation (sortie minimale sous 99 % du montant affiché) — relancez l'échange")
}

// --- Nom d'affiliation (THORName / MAYAName) -----------------------------------
// Réservé au portefeuille du développeur : celui dont l'adresse THOR (clé
// m/44'/931'/0'/0/0, même hash160 sur Maya) EST l'adresse d'affiliation de
// l'app. Inscription par un dépôt natif signé ici (voir `native_deposit`).

/// Protocole d'un nom : réseau natif et protocole d'échange.
pub fn affiliate_name_chains(chain: &str) -> Result<(&'static native_deposit::NativeChain, &'static thorchain_rpc::CrossChain)> {
    match chain {
        "thorchain" => Ok((&native_deposit::THORCHAIN, &thorchain_rpc::THORCHAIN)),
        "maya" => Ok((&native_deposit::MAYA, &thorchain_rpc::MAYA)),
        other => anyhow::bail!("réseau de nom inconnu : {other}"),
    }
}

/// Nom d'affiliation sur un protocole, vu depuis l'app.
#[derive(Clone, Debug, PartialEq)]
pub enum NameState {
    /// Libre (ou expiré) : inscription possible.
    Free,
    /// Inscrit par l'adresse d'affiliation ; années restantes ; alias correct.
    Ours { years_left: f64, points_to_affiliate: bool },
    /// Inscrit par quelqu'un d'autre.
    Taken,
}

pub struct NameStatus {
    pub name: &'static str,
    pub state: NameState,
    /// Adresse d'affiliation sur ce réseau (paie l'inscription, reçoit les frais).
    pub address: &'static str,
    pub balance: u128,
    pub decimals: u32,
    /// Montant du dépôt proposé : inscription (un an inclus) + un an, ou un
    /// an de plus si le nom est déjà à nous.
    pub deposit: u128,
    pub network_fee: u128,
}

/// Inscription (un an inclus) et un an de plus, d'après les constantes du
/// protocole (relevées sur de vraies inscriptions : 10 RUNE ou 10 CACAO, puis
/// ~1,05 par an).
fn name_costs(native: &native_deposit::NativeChain) -> Result<(u128, u128)> {
    let register = native_deposit::constant(native, "TNSRegisterFee")?;
    let per_block = native_deposit::constant(native, "TNSFeePerBlock")?;
    Ok((u128::from(register), u128::from(per_block) * u128::from(thorchain_rpc::NAME_BLOCKS_PER_YEAR)))
}

fn name_state(protocol: &thorchain_rpc::CrossChain, name: &str) -> Result<NameState> {
    Ok(match protocol.name_record(name)? {
        None => NameState::Free,
        Some(record) if record.expired() => NameState::Free,
        Some(record) if record.owner == protocol.affiliate_address => NameState::Ours {
            years_left: (record.expire_height - record.current_height) as f64 / thorchain_rpc::NAME_BLOCKS_PER_YEAR as f64,
            points_to_affiliate: record.points_to_affiliate,
        },
        Some(_) => NameState::Taken,
    })
}

/// Dépôt à faire pour l'état `state` (`None` : nom pris par un autre).
fn name_deposit(state: &NameState, register: u128, year: u128) -> Option<u128> {
    match state {
        NameState::Free => Some(register + year),
        NameState::Ours { .. } => Some(year),
        NameState::Taken => None,
    }
}

/// État du nom d'affiliation sur `chain` (« thorchain », « maya ») : lecture
/// seule, données publiques.
pub fn affiliate_name_status(chain: &str) -> Result<NameStatus> {
    let (native, protocol) = affiliate_name_chains(chain)?;
    let name = protocol.affiliate_name.context("aucun nom d'affiliation prévu sur ce réseau")?;
    let state = name_state(protocol, name)?;
    let (register, year) = name_costs(native)?;
    Ok(NameStatus {
        name,
        deposit: name_deposit(&state, register, year).unwrap_or(0),
        state,
        address: protocol.affiliate_address,
        balance: native_deposit::balance(native, protocol.affiliate_address)?,
        decimals: native.decimals,
        network_fee: native_deposit::network_fee(native)?,
    })
}

/// Inscrit (ou prolonge d'un an) le nom d'affiliation sur `chain`, signé par
/// la clé THOR du profil principal — refusé si elle n'est pas l'adresse
/// d'affiliation de l'app. `shown_deposit` : montant affiché dans la boîte
/// de confirmation, jamais dépassé. Renvoie l'identifiant de la transaction.
pub fn register_affiliate_name(data_dir: &Path, device_password: &str, chain: &str, shown_deposit: u128) -> Result<String> {
    let (native, protocol) = affiliate_name_chains(chain)?;
    let name = protocol.affiliate_name.context("aucun nom d'affiliation prévu sur ce réseau")?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (key, hash160) = derivation::derive_thor_key(&seed, 0)?;
    let address = bech32::encode(native.hrp, bech32::ToBase32::to_base32(&hash160), bech32::Variant::Bech32).context("encodage bech32 impossible")?;
    anyhow::ensure!(
        address == protocol.affiliate_address,
        "ce portefeuille n'est pas celui qui reçoit les frais d'affiliation de l'app — inscription réservée à ce dernier"
    );
    let (register, year) = name_costs(native)?;
    let state = name_state(protocol, name)?;
    let deposit = name_deposit(&state, register, year).with_context(|| format!("le nom « {name} » appartient déjà à quelqu'un d'autre sur {}", native.name))?;
    anyhow::ensure!(deposit <= shown_deposit, "le coût du nom a changé depuis la confirmation — relancez l'inscription");
    let fee = native_deposit::network_fee(native)?;
    let balance = native_deposit::balance(native, &address)?;
    anyhow::ensure!(
        balance >= deposit + fee,
        "solde insuffisant sur l'adresse d'affiliation {} : {} disponibles, {} nécessaires (dépôt + frais réseau)",
        native.name,
        tokens::format_amount(balance, native.decimals as u8),
        tokens::format_amount(deposit + fee, native.decimals as u8)
    );
    let (account_number, sequence) = native_deposit::account(native, &address)?.context("adresse d'affiliation jamais approvisionnée sur ce réseau")?;
    // Alias de la chaîne native vers l'adresse d'affiliation ; propriétaire :
    // le signataire (cette même adresse).
    let memo = format!("~:{name}:{}:{address}", protocol.native_chain());
    let tx = native_deposit::signed_deposit(native, &key, deposit, &memo, account_number, sequence)?;
    native_deposit::broadcast(native, &tx)
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
    let amount = wallet_flow::parse_usdc_to_micros(amount_usdc)?;
    send_spl(data_dir, device_password, network, &sol_spl::usdc_mint_mainnet(), sol_spl::USDC_DECIMALS, "USDC", to, amount, profile_index)
}

/// Virement d'un jeton SPL `mint` (`amount` en unités, `decimals` du mint) —
/// voir `send_usdc` : compte de jetons du destinataire créé si besoin, soldes
/// du jeton et SOL (frais + rent) vérifiés avant de signer.
#[allow(clippy::too_many_arguments)]
pub fn send_spl(
    data_dir: &Path,
    device_password: &str,
    network: &wallet_flow::SolNetwork,
    mint: &[u8; 32],
    decimals: u8,
    symbol: &str,
    to: &str,
    amount: u64,
    profile_index: u32,
) -> Result<String> {
    check_solana_recipient(to, network)?;
    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let signing_key = derivation::derive_solana_key(&seed, profile_index);
    let owner = signing_key.verifying_key().to_bytes();

    let to_bytes = bs58::decode(to.trim()).into_vec().context("adresse Solana invalide (base58 attendu)")?;
    let to_owner: [u8; 32] = to_bytes.try_into().map_err(|_| anyhow::anyhow!("une adresse Solana fait 32 octets"))?;
    let mint = *mint;
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
    let usdc_balance = usdc_balance?.ok_or_else(|| anyhow::anyhow!("aucun compte {symbol} trouvé pour cette adresse (solde 0)"))?;
    anyhow::ensure!(
        amount <= usdc_balance,
        "fonds {symbol} insuffisants : {usdc_balance} disponibles (unité 10^-{decimals} {symbol}), {amount} requis"
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
    let transfer_ix = sol_spl::transfer_checked_instruction(&source_ata, &mint, &dest_ata, &owner, amount, decimals);
    let raw_tx = sol_tx::build_and_sign_transaction(&signing_key, &owner, &[create_ata_ix, transfer_ix], &recent_blockhash);
    rpc.send_transaction(&raw_tx)
}

// --- Jetons du registre (voir tokens.rs) ---------------------------------------
// L'interface ne donne que l'identifiant du jeton et le réseau : contrat, mint
// et décimales viennent TOUJOURS du registre.

fn abi_word_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn abi_word_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Données d'un appel ERC-20 `transfer(to, amount)`.
pub fn erc20_transfer_data(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&abi_word_address(to));
    data.extend_from_slice(&abi_word_u128(amount));
    data
}

/// Données d'un appel ERC-20 `approve(spender, amount)`.
pub fn erc20_approve_data(spender: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = vec![0x09, 0x5e, 0xa7, 0xb3];
    data.extend_from_slice(&abi_word_address(spender));
    data.extend_from_slice(&abi_word_u128(amount));
    data
}

/// Montant que `spender` peut encore prélever sur `owner` : `allowance(owner, spender)`.
pub fn get_erc20_allowance(network: &wallet_flow::EvmNetwork, contract: &str, owner: &[u8; 20], spender: &[u8; 20]) -> Result<u128> {
    let mut data = vec![0xdd, 0x62, 0xed, 0x3e];
    data.extend_from_slice(&abi_word_address(owner));
    data.extend_from_slice(&abi_word_address(spender));
    let answer = eth_rpc::EthRpc::new(network.rpc).call_contract(&derivation::format_address(owner), contract, 0, &data)?;
    anyhow::ensure!(answer.len() == 32, "réponse du contrat de jeton inattendue");
    // Autorisation « illimitée » (2^256 − 1) donnée ailleurs : bornée à u128::MAX.
    if answer[..16].iter().any(|&b| b != 0) {
        return Ok(u128::MAX);
    }
    Ok(u128::from_be_bytes(answer[16..].try_into().expect("16 octets")))
}

/// Solde ERC-20 de `owner` (unités du jeton) : `balanceOf(owner)`.
pub fn get_erc20_balance(network: &wallet_flow::EvmNetwork, contract: &str, owner: &str) -> Result<u128> {
    let owner_bytes = wallet_flow::parse_evm_address(owner)?;
    let mut data = vec![0x70, 0xa0, 0x82, 0x31];
    data.extend_from_slice(&abi_word_address(&owner_bytes));
    let answer = eth_rpc::EthRpc::new(network.rpc).call_contract(owner, contract, 0, &data)?;
    anyhow::ensure!(answer.len() == 32, "réponse du contrat de jeton inattendue");
    anyhow::ensure!(answer[..16].iter().all(|&b| b == 0), "solde de jeton hors limites");
    Ok(u128::from_be_bytes(answer[16..].try_into().expect("16 octets")))
}

fn registered_token(token_id: &str, network: &str) -> Result<(&'static tokens::Token, &'static tokens::Deployment)> {
    tokens::find(token_id, network).ok_or_else(|| anyhow::anyhow!("jeton non pris en charge sur ce réseau"))
}

fn token_evm_network(network: &str) -> Result<&'static wallet_flow::EvmNetwork> {
    wallet_flow::evm_network(network).ok_or_else(|| anyhow::anyhow!("réseau EVM inconnu : {network}"))
}

/// Solde d'un jeton du registre sur `network` : (unités, décimales).
pub fn get_token_balance(token_id: &str, network: &str, owner: &str) -> Result<(u128, u8)> {
    let (_, deployment) = registered_token(token_id, network)?;
    let units = match deployment.kind {
        tokens::TokenKind::Erc20 { contract } => get_erc20_balance(token_evm_network(network)?, contract, owner)?,
        tokens::TokenKind::Spl { mint } => {
            let mint = sol_spl_mint(mint)?;
            u128::from(get_spl_balance(owner, &mint, &wallet_flow::SOLANA_MAINNET)?)
        }
    };
    Ok((units, deployment.decimals))
}

/// Mint (32 octets) d'un jeton SPL du registre.
pub fn registered_spl_mint(token_id: &str) -> Result<[u8; 32]> {
    let (_, deployment) = registered_token(token_id, "sol_mainnet")?;
    let tokens::TokenKind::Spl { mint } = deployment.kind else { anyhow::bail!("jeton SPL attendu") };
    sol_spl_mint(mint)
}

fn sol_spl_mint(mint: &str) -> Result<[u8; 32]> {
    bs58::decode(mint).into_vec().ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow::anyhow!("mint invalide"))
}

/// Montant canonique d'un jeton (forme affichée ET signée).
pub fn canonical_token_amount(token_id: &str, network: &str, amount: &str) -> Result<String> {
    let (_, deployment) = registered_token(token_id, network)?;
    Ok(tokens::format_amount(tokens::parse_amount(amount, deployment.decimals)?, deployment.decimals))
}

/// Frais d'un virement ERC-20, montrés dans la boîte de confirmation puis
/// signés tels quels (gas de l'appel estimé par le nœud, voir
/// `evm_fee_for_confirmation`). Refus d'un virement VERS un contrat de jeton
/// (fonds perdus à jamais).
pub fn erc20_fee_for_confirmation(token_id: &str, network: &str, from: &str, to: &str, amount: &str) -> Result<EvmFee> {
    let (_, deployment) = registered_token(token_id, network)?;
    let tokens::TokenKind::Erc20 { contract } = deployment.kind else { anyhow::bail!("jeton ERC-20 attendu") };
    anyhow::ensure!(!tokens::is_known_contract(to), "destinataire refusé : c'est le contrat d'un jeton, les fonds y seraient perdus à jamais");
    let units = tokens::parse_amount(amount, deployment.decimals)?;
    let data = erc20_transfer_data(&wallet_flow::parse_evm_address(to)?, units);
    evm_fee_for_confirmation(token_evm_network(network)?, &wallet_flow::parse_evm_address(from)?, &wallet_flow::parse_evm_address(contract)?, 0, &data).map_err(|e| {
        // Appel refusé par le contrat lors de l'estimation : le cas courant est
        // un solde de jeton insuffisant.
        // Refus classique (« revert ») ou ancien contrat qui s'arrête sur un
        // opcode invalide (USDT, constaté avec un solde nul).
        let message = format!("{e:#}");
        if message.contains("revert") || message.contains("invalid opcode") {
            anyhow::anyhow!("solde de jeton insuffisant, ou transfert refusé par le contrat du jeton")
        } else {
            e
        }
    })
}

/// Déverrouille le coffre, signe et diffuse un virement ERC-20 du registre.
/// `fee` : celui affiché dans la boîte de confirmation, utilisé tel quel.
/// Vérifie avant de signer : réseau du nœud, solde du jeton, solde natif pour
/// les frais.
#[allow(clippy::too_many_arguments)]
pub fn send_erc20(
    data_dir: &Path,
    device_password: &str,
    token_id: &str,
    network: &str,
    to: &str,
    amount: &str,
    fee: EvmFee,
    profile_index: u32,
) -> Result<String> {
    let (token, deployment) = registered_token(token_id, network)?;
    let tokens::TokenKind::Erc20 { contract } = deployment.kind else { anyhow::bail!("jeton ERC-20 attendu") };
    let net = token_evm_network(network)?;
    check_evm_gas_price(net, fee.gas_price)?;
    anyhow::ensure!(!tokens::is_known_contract(to), "destinataire refusé : c'est le contrat d'un jeton, les fonds y seraient perdus à jamais");
    let to_bytes = wallet_flow::parse_evm_address(to)?;
    let contract_bytes = wallet_flow::parse_evm_address(contract)?;
    let units = tokens::parse_amount(amount, deployment.decimals)?;
    let data = erc20_transfer_data(&to_bytes, units);
    anyhow::ensure!(fee.gas_limit >= eth_tx::intrinsic_gas(&data), "limite de gas trop basse pour ce transfert");

    let seed = unlock_seed(data_dir, device_password)?;
    let _seed_lock = memory_guard::lock(&seed);
    let (signing_key, address) = derivation::derive_evm_key(&seed, profile_index)?;
    let address_str = derivation::format_address(&address);
    let rpc = eth_rpc::EthRpc::new(net.rpc);
    let (nonce, chain_id, native, token_balance) = std::thread::scope(|scope| {
        let nonce = scope.spawn(|| rpc.nonce(&address_str));
        let chain_id = scope.spawn(|| rpc.chain_id());
        let native = scope.spawn(|| rpc.balance(&address_str));
        let token_balance = scope.spawn(|| get_erc20_balance(net, contract, &address_str));
        (
            nonce.join().expect("le thread nonce ne doit pas paniquer"),
            chain_id.join().expect("le thread chain_id ne doit pas paniquer"),
            native.join().expect("le thread solde ne doit pas paniquer"),
            token_balance.join().expect("le thread solde de jeton ne doit pas paniquer"),
        )
    });
    let (nonce, chain_id, native, token_balance) = (nonce?, chain_id?, native?, token_balance?);
    anyhow::ensure!(chain_id == net.chain_id, "le nœud RPC répond pour le réseau {chain_id}, pas {} — envoi refusé", net.chain_id);
    anyhow::ensure!(
        units <= token_balance,
        "fonds {} insuffisants : {} disponibles, {} requis",
        token.symbol,
        tokens::format_amount(token_balance, deployment.decimals),
        tokens::format_amount(units, deployment.decimals)
    );
    let gas_cost = fee.max_total()?;
    anyhow::ensure!(
        gas_cost <= native,
        "{} insuffisant pour les frais : {} wei disponibles, {gas_cost} wei requis",
        net.native_symbol,
        native
    );
    let tx = eth_tx::EthTx { nonce, gas_price: fee.gas_price, gas_limit: fee.gas_limit, to: contract_bytes, value: 0, chain_id, data };
    rpc.send_raw_transaction(&tx.sign(&signing_key)?)
}

/// Virement d'un jeton SPL du registre (Solana).
pub fn send_registered_spl(data_dir: &Path, device_password: &str, token_id: &str, to: &str, amount: &str, profile_index: u32) -> Result<String> {
    let (token, deployment) = registered_token(token_id, "sol_mainnet")?;
    let tokens::TokenKind::Spl { mint } = deployment.kind else { anyhow::bail!("jeton SPL attendu") };
    let units = u64::try_from(tokens::parse_amount(amount, deployment.decimals)?).context("montant trop grand")?;
    send_spl(data_dir, device_password, &wallet_flow::SOLANA_MAINNET, &sol_spl_mint(mint)?, deployment.decimals, token.symbol, to, units, profile_index)
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
        Prepared::EvmTransaction { network, to, value, data, gas_limit, gas_price, l1_fee, .. } => {
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
                .and_then(|gas| gas.checked_add(*l1_fee))
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
#[path = "swap_matrix.rs"]
mod swap_matrix;

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

    /// L'état propre à une seed (Zcash protégé, Monero, destinataires payés)
    /// ne survit ni à une réinitialisation ni à une restauration.
    #[test]
    fn wallet_change_removes_seed_bound_state() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_seed_state_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files = ["zcash_shielded.sqlite", "monero_wallet.json", "sent_recipients.json"];
        let plant = || files.iter().for_each(|f| std::fs::write(dir.join(f), b"ancien").unwrap());
        create_wallet(&dir, "un mot de passe de test bien assez long").expect("création du wallet");
        plant();
        reset_wallet_with(&dir, &FakeSealer { fail_enroll: false }).expect("réinitialisation");
        assert!(files.iter().all(|f| !dir.join(f).exists()), "réinitialisation");
        plant();
        remove_seed_bound_state(&dir);
        assert!(files.iter().all(|f| !dir.join(f).exists()), "restauration (même nettoyage)");
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
        let cap = wallet_flow::ETHEREUM_MAINNET.max_gas_price_wei.expect("plafond sur mainnet");
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
            recommended_gas_rate: None,
            affiliate: Some(thorchain_rpc::AFFILIATE_ADDRESS.to_string()),
        }
    }

    /// Coût d'un nom selon son état : libre = inscription + un an, à nous = un
    /// an de plus, pris = rien.
    #[test]
    fn name_deposit_follows_the_state() {
        assert_eq!(name_deposit(&NameState::Free, 1_000_000_000, 105_120_000), Some(1_105_120_000));
        assert_eq!(name_deposit(&NameState::Ours { years_left: 0.5, points_to_affiliate: true }, 1_000_000_000, 105_120_000), Some(105_120_000));
        assert_eq!(name_deposit(&NameState::Taken, 1_000_000_000, 105_120_000), None);
    }

    #[test]
    fn refreshed_quote_must_match_what_was_shown() {
        let shown = shown_quote(990_000);
        ensure_quote_matches_shown(&thorchain_rpc::THORCHAIN, &shown_quote(990_000), &shown, "BTC.BTC", "bc1qdest").expect("identique");

        let mut churned = shown_quote(990_000);
        churned.inbound_address = "bc1qautrevaultautrevaultautrevault00000".into();
        assert!(ensure_quote_matches_shown(&thorchain_rpc::THORCHAIN, &churned, &shown, "BTC.BTC", "bc1qdest").is_err(), "vault changé");

        let mut rerouted = shown_quote(990_000);
        rerouted.router = Some("0xAutreRouteur".into());
        assert!(ensure_quote_matches_shown(&thorchain_rpc::THORCHAIN, &rerouted, &shown, "BTC.BTC", "bc1qdest").is_err(), "routeur changé");

        // Cours tombé à 950 000 : la nouvelle sortie minimale (99 % de 950 000)
        // est sous 99 % de ce qui a été AFFICHÉ (1 000 000) — refusé.
        let price_dropped = shown_quote(940_500);
        let err = ensure_quote_matches_shown(&thorchain_rpc::THORCHAIN, &price_dropped, &shown, "BTC.BTC", "bc1qdest").unwrap_err();
        assert!(format!("{err:#}").contains("cours a bougé"), "{err:#}");

        // Depuis Zcash (Maya, sans affilié) : memo à 4 champs relu de même.
        let mut zec_shown = shown_quote(990_000);
        zec_shown.memo = "=:b:bc1qdest:990000".into();
        zec_shown.affiliate = None;
        let zec_fresh = |memo: &str| thorchain_rpc::SwapQuote { memo: memo.into(), ..shown_quote(0) };
        ensure_quote_matches_shown(&thorchain_rpc::MAYA, &zec_fresh("=:b:bc1qdest:990000"), &zec_shown, "BTC.BTC", "bc1qdest").expect("identique");
        assert!(ensure_quote_matches_shown(&thorchain_rpc::MAYA, &zec_fresh("=:b:bc1qautre:990000"), &zec_shown, "BTC.BTC", "bc1qdest").is_err());
        assert!(ensure_quote_matches_shown(&thorchain_rpc::MAYA, &zec_fresh("=:b:bc1qdest:990000:maya1x:50"), &zec_shown, "BTC.BTC", "bc1qdest").is_err());
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
    /// Réseaux EVM : identifiants et chaînes uniques, plafond de prix du gas sur
    /// chaque réseau à fonds réels, frais de publication OP Stack seulement là
    /// où ils existent.
    #[test]
    fn evm_networks_are_consistent() {
        let networks = wallet_flow::EVM_NETWORKS;
        for (i, a) in networks.iter().enumerate() {
            for b in &networks[i + 1..] {
                assert_ne!(a.id, b.id);
                assert_ne!(a.chain_id, b.chain_id);
            }
            assert_eq!(wallet_flow::evm_network(a.id).map(|n| n.chain_id), Some(a.chain_id));
            assert_eq!(a.mainnet, a.max_gas_price_wei.is_some(), "{} : plafond sur fonds réels uniquement", a.id);
            assert!(a.rpc.starts_with("https://") && a.explorer_tx_prefix.starts_with("https://"), "{}", a.id);
        }
        assert!(wallet_flow::evm_network("inconnu").is_none());
        let op_stack: Vec<&str> = networks.iter().filter(|n| n.op_stack_l1_fee).map(|n| n.id).collect();
        assert_eq!(op_stack, ["base_mainnet"], "frais L1 OP Stack : Base seulement");
        let fee = EvmFee { gas_price: 2, gas_limit: 21_000, l1_fee: 5 };
        assert_eq!(fee.max_total().unwrap(), 42_005);
        assert!(EvmFee { gas_price: u128::MAX, gas_limit: 2, l1_fee: 0 }.max_total().is_err());
    }

    /// Frais lus sur CHAQUE réseau EVM réel pour un virement : prix sous le
    /// plafond, limite fixe (21 000) ou estimée (Arbitrum), frais de
    /// publication sur Base. Lecture seule.
    /// `cargo test -- --ignored evm_fees_are_read_on_every --nocapture`
    #[test]
    #[ignore]
    fn evm_fees_are_read_on_every_real_network() {
        let from = "0x28C6c06298d514Db089934071355E5743bf21d60"; // hot wallet public (lecture seule)
        let to = "0x000000000000000000000000000000000000dEaD";
        for net in wallet_flow::EVM_NETWORKS.iter().filter(|n| n.mainnet) {
            let fee = evm_transfer_fee_for_confirmation(net, Some(from), to, "0").unwrap_or_else(|e| panic!("{} : {e:#}", net.id));
            println!("{:>18} : {:.4} gwei, gas {}, L1 {} wei, total {} wei", net.id, fee.gas_price as f64 / 1e9, fee.gas_limit, fee.l1_fee, fee.max_total().unwrap());
            assert!(fee.gas_price > 0, "{}", net.id);
            assert!(fee.gas_limit >= 21_000, "{}", net.id);
            assert_eq!(fee.l1_fee > 0, net.op_stack_l1_fee, "{} : frais L1", net.id);
        }
    }

    /// Chaque contrat du registre des jetons, relu sur SA blockchain : symbole et
    /// décimales du contrat ERC-20 ; programme SPL Token et décimales du mint
    /// Solana. Puis un solde réel lu par le chemin de l'app (USDT d'un
    /// portefeuille public connu). Lecture seule.
    /// `cargo test -- --ignored token_contracts_match --nocapture`
    #[test]
    #[ignore]
    fn token_contracts_match_the_real_networks() {
        fn abi_string(answer: &[u8]) -> String {
            if answer.len() == 32 {
                return String::from_utf8_lossy(answer).trim_end_matches('\0').to_string();
            }
            let len = u128::from_be_bytes(answer[48..64].try_into().unwrap()) as usize;
            String::from_utf8_lossy(&answer[64..64 + len]).into_owned()
        }
        let caller = "0x000000000000000000000000000000000000dEaD";
        let mut mints = Vec::new();
        for token in tokens::TOKENS {
            for d in token.deployments {
                match d.kind {
                    tokens::TokenKind::Erc20 { contract } => {
                        let rpc = eth_rpc::EthRpc::new(wallet_flow::evm_network(d.network).unwrap().rpc);
                        let symbol = abi_string(&rpc.call_contract(caller, contract, 0, &[0x95, 0xd8, 0x9b, 0x41]).unwrap());
                        let decimals = rpc.call_contract(caller, contract, 0, &[0x31, 0x3c, 0xe5, 0x67]).unwrap();
                        println!("{:>7} {:>17} « {symbol} » {}", token.symbol, d.network, decimals[31]);
                        assert!(symbol.eq_ignore_ascii_case(token.symbol), "{} sur {} : symbole « {symbol} »", token.id, d.network);
                        assert_eq!(decimals[31], d.decimals, "{} sur {}", token.id, d.network);
                    }
                    tokens::TokenKind::Spl { mint } => mints.push((token, d, mint.to_string())),
                }
            }
        }
        let addresses: Vec<String> = mints.iter().map(|(_, _, mint)| mint.clone()).collect();
        let states = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc).multiple_accounts(&addresses).unwrap();
        for ((token, d, mint), state) in mints.iter().zip(states) {
            let state = state.unwrap_or_else(|| panic!("mint {mint} introuvable"));
            println!("{:>7} {:>17} {} décimales {}", token.symbol, d.network, state.owner, state.data[44]);
            assert_eq!(state.owner, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "{} : programme SPL Token attendu", token.id);
            assert_eq!(state.data[44], d.decimals, "{} : décimales du mint", token.id);
        }
        let (usdt, decimals) = get_token_balance("usdt", "evm_mainnet", "0x28C6c06298d514Db089934071355E5743bf21d60").unwrap();
        assert_eq!(decimals, 6);
        assert!(usdt > 0, "portefeuille public avec de l'USDT");
    }

    /// Données d'un `transfer` ERC-20 : sélecteur, destinataire et montant en
    /// mots de 32 octets.
    #[test]
    fn erc20_transfer_data_is_abi_encoded() {
        let to = [0x11u8; 20];
        let data = erc20_transfer_data(&to, 1_000_000);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &to);
        assert_eq!(u128::from_be_bytes(data[52..68].try_into().unwrap()), 1_000_000);
        assert!(data[36..52].iter().all(|&b| b == 0));
    }

    /// `approve(spender, amount)` : sélecteur 0x095ea7b3, adresse puis montant.
    #[test]
    fn erc20_approve_data_is_abi_encoded() {
        let spender = [0x22u8; 20];
        let data = erc20_approve_data(&spender, 7);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(&data[16..36], &spender);
        assert_eq!(data[67], 7);
        assert!(data[36..67].iter().all(|&b| b == 0));
    }

    /// Réseaux RÉELS, sans rien dépenser : le routeur THORChain de BNB Chain et
    /// d'Avalanche accepte notre dépôt natif (estimation du gas depuis un
    /// portefeuille public qui détient ces monnaies), et les frais d'un échange
    /// depuis un jeton de Base comptent l'autorisation et la publication sur
    /// Ethereum. `cargo test -- --ignored thorchain_new_networks_accept_our_deposits --nocapture`
    #[test]
    #[ignore]
    fn thorchain_new_networks_accept_our_deposits() {
        let holder = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let btc = thorchain_rpc::asset("btc", "btc_mainnet").unwrap();
        // Détenteurs de la monnaie native (estimation seulement, rien n'est
        // signé) : portefeuille public, ou contrat WETH qui détient l'ETH déposé.
        for (coin, network, amount, from_addr) in [
            ("evm", "evm_mainnet", "0.01", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            ("evm", "base_mainnet", "0.01", "0x4200000000000000000000000000000000000006"),
            ("bnb", "bsc_mainnet", "0.05", holder),
            ("avax", "avax_mainnet", "1", holder),
        ] {
            let from = thorchain_rpc::asset(coin, network).unwrap();
            let net = wallet_flow::evm_network(network).unwrap();
            let quote = get_swap_quote(&thorchain_rpc::THORCHAIN, from, btc, amount, "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz").unwrap();
            let router = quote.router.clone().unwrap();
            let vault = wallet_flow::parse_evm_address(&quote.inbound_address).unwrap();
            let expiration = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600;
            let value = wallet_flow::parse_eth_to_wei(amount).unwrap();
            let calldata = eth_tx::thorchain_deposit_calldata(&vault, &[0u8; 20], value, &quote.memo, expiration);
            let gas = eth_rpc::EthRpc::new(net.rpc).estimate_gas(from_addr, &router, value, &calldata).unwrap_or_else(|e| panic!("{network} : {e:#}"));
            println!("{network} : dépôt {amount} {} vers BTC, routeur {router}, gas estimé {gas}", from.symbol);
            assert!(gas < EVM_SWAP_MAX_GAS_LIMIT);
        }
        // Maya, Arbitrum : même routeur `depositWithExpiry`, accepté avec le montant envoyé.
        let arb_eth = thorchain_rpc::MAYA.asset("evm", "arbitrum_mainnet").unwrap();
        let maya_btc = thorchain_rpc::MAYA.asset("btc", "btc_mainnet").unwrap();
        let quote = get_swap_quote(&thorchain_rpc::MAYA, arb_eth, maya_btc, "0.01", "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz").unwrap();
        let router = quote.router.clone().unwrap();
        let vault = wallet_flow::parse_evm_address(&quote.inbound_address).unwrap();
        let value = wallet_flow::parse_eth_to_wei("0.01").unwrap();
        let expiration = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600;
        let calldata = eth_tx::thorchain_deposit_calldata(&vault, &[0u8; 20], value, &quote.memo, expiration);
        let arbitrum = wallet_flow::evm_network("arbitrum_mainnet").unwrap();
        let gas = eth_rpc::EthRpc::new(arbitrum.rpc).estimate_gas("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", &router, value, &calldata).unwrap();
        println!("Maya arbitrum_mainnet : dépôt 0.01 ETH vers BTC, routeur {router}, gas estimé {gas}");

        let usdc_base = thorchain_rpc::asset("usdc", "base_mainnet").unwrap();
        let eth = thorchain_rpc::asset("evm", "evm_mainnet").unwrap();
        let quote = get_swap_quote(&thorchain_rpc::THORCHAIN, usdc_base, eth, "100", holder).unwrap();
        let base = wallet_flow::evm_network("base_mainnet").unwrap();
        let gas_price = evm_gas_price_for_confirmation(base).unwrap();
        let fees = evm_swap_fees(base, usdc_base, &quote, "100", gas_price, Some(holder)).unwrap();
        println!("USDC Base -> ETH : {} autorisation(s), frais max {} wei (L1 dépôt {} wei)", fees.approvals, fees.max_total().unwrap(), fees.deposit.l1_fee);
        assert!(fees.deposit.l1_fee > 0, "Base : frais de publication sur Ethereum");
        assert!(fees.approvals >= 1, "aucune autorisation accordée au routeur par ce portefeuille");
    }

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
        for (from, to, amount) in [
            ("sol", "usdc", 100_000_000u64),
            ("usdc", "sol", 10_000_000u64),
            ("sol", "usdt", 100_000_000),
            ("sol", "eurc", 100_000_000),
            ("sol", "render", 100_000_000),
            ("usdc", "render", 10_000_000),
        ] {
            let (input, output) = (jupiter_mint_for_coin(from).unwrap(), jupiter_mint_for_coin(to).unwrap());
            let fee_mint = jupiter_fee_mint(&rpc, &input, &output).unwrap();
            println!("{from}->{to} : frais d'affiliation {}", if fee_mint.is_some() { "prélevés" } else { "absents (aucun compte de frais)" });
            let q = jupiter_rpc::quote(&input, &output, amount, 50, fee_mint).unwrap();
            let tx = jupiter_rpc::build_swap_transaction(&q, owner_b58).unwrap();
            let addresses = resolve_writable_addresses(&rpc, &tx).unwrap();
            let pre = rpc.multiple_accounts(&addresses).unwrap();
            let post_states = match rpc.simulate_with_account_states(&tx, &addresses).unwrap() {
                sol_rpc::SimulationOutcome::Succeeded { post_states } => post_states,
                sol_rpc::SimulationOutcome::Failed { err, logs } => panic!("simulation réelle en échec pour {from}->{to} ({err}) :\n{logs}"),
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

        let q = jupiter_rpc::quote(jupiter_rpc::SOL_MINT, &jupiter_mint_for_coin("usdc").unwrap(), amount, 50, None).unwrap();
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

    /// Wallet d'avant le coffre OS (clé en fichier, rien dans le coffre) : le
    /// premier déverrouillage réussi déplace la clé dans le coffre et supprime
    /// le fichier ; le wallet se déverrouille ensuite depuis le coffre. Un
    /// mauvais mot de passe ne déplace rien.
    #[test]
    fn legacy_file_key_moves_into_the_os_store_after_a_successful_unlock() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_key_migration_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let username = secure_storage::entry_username(&dir);
        // Simule un wallet créé avant le coffre OS : clé remise en fichier.
        let key = active_key_store().read(&username).unwrap().expect("clé dans le coffre après création");
        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), key.as_bytes()).unwrap();
        active_key_store().remove(&username).unwrap();

        assert!(unlock_wallet(&dir, "pas le bon mot de passe du tout").is_err());
        assert!(dir.join(DEVICE_PRIVKEY_FILE).exists(), "mauvais mot de passe : rien ne bouge");
        assert!(active_key_store().read(&username).unwrap().is_none());

        unlock_wallet(&dir, password).expect("déverrouillage depuis le fichier");
        assert!(!dir.join(DEVICE_PRIVKEY_FILE).exists(), "fichier supprimé après migration");
        assert_eq!(active_key_store().read(&username).unwrap().as_deref().map(String::as_str), Some(key.as_str()));
        unlock_wallet(&dir, password).expect("déverrouillage depuis le coffre");

        active_key_store().remove(&username).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Coffre en panne : la clé reste dans son fichier, intacte.
    #[test]
    fn failed_migration_leaves_the_file_key_untouched() {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_key_migration_failure_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), b"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap();
        migrate_device_privkey_to_store(&dir, &FailingKeyStore);
        assert_eq!(std::fs::read(dir.join(DEVICE_PRIVKEY_FILE)).unwrap(), b"-----BEGIN PGP PRIVATE KEY BLOCK-----");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Vrai Gestionnaire d'identification Windows, dans un dossier temporaire
    /// (entrée propre à ce dossier, jamais celle d'un vrai wallet) : migration
    /// d'une clé de wallet réelle (taille réelle), relecture, puis nettoyage.
    /// `cargo test -- --ignored real_os_store_migration --nocapture`
    #[test]
    #[ignore]
    fn real_os_store_migration() {
        use secure_storage::KeyStore;
        let store = secure_storage::OsKeyStore;
        let dir = std::env::temp_dir().join(format!("pgp_wallet_real_store_migration_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = "un mot de passe de test bien assez long";
        create_wallet(&dir, password).expect("création du wallet");
        let username = secure_storage::entry_username(&dir);
        let key = active_key_store().read(&username).unwrap().expect("clé générée");
        println!("clé de {} octets", key.len());
        std::fs::write(dir.join(DEVICE_PRIVKEY_FILE), key.as_bytes()).unwrap();
        assert!(store.read(&username).unwrap().is_none(), "aucune entrée réelle au départ");

        migrate_device_privkey_to_store(&dir, &store);
        let stored = store.read(&username).unwrap();
        let migrated = !dir.join(DEVICE_PRIVKEY_FILE).exists() && stored.as_deref().map(String::as_str) == Some(key.as_str());
        store.remove(&username).unwrap();
        active_key_store().remove(&username).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(migrated, "clé dans le vrai coffre, identique, fichier supprimé");
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
