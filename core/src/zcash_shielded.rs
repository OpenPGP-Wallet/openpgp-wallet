//! Zcash protégé (Orchard) : adresse unifiée u1… (récepteur Orchard seul),
//! réception, solde, puis protection des ZEC transparents et envoi.
//!
//! Pile officielle des portefeuilles légers (celle de Zashi) :
//! - `zcash_client_sqlite` : base de portefeuille locale (notes, arbres de
//!   commitments). Elle ne contient que des clés de VISUALISATION (UFVK) : la
//!   clé de dépense est dérivée de la seed (mot de passe) au moment de signer.
//!   Fuite de cette base = historique protégé visible, jamais de fonds perdus.
//! - `zcash_client_backend::sync` : synchronisation par les serveurs
//!   lightwalletd déjà utilisés pour le transparent (blocs compacts, déchiffrement
//!   par essai), sans rien envoyer d'autre que des demandes de blocs.
//!
//! Compte protégé n°p = compte ZIP-32 n°p de la seed (profil n°p). L'adresse
//! t1 existante du profil (m/44'/133'/0'/0/p) y est importée pour pouvoir la
//! protéger. Naissance commune à tous les comptes (`BIRTHDAY_HEIGHT`) : aucune
//! adresse protégée de l'app n'existait avant, donc rien ne peut être manqué, et
//! une restauration sur un autre appareil retrouve tout sans rescanner la chaîne.

use crate::{derivation, zcash};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::path::Path;
use std::sync::Mutex;
use zcash_client_backend::data_api::chain::{error as chain_error, BlockCache, BlockSource};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{Account as _, AccountBirthday, AccountPurpose, WalletRead, WalletWrite, Zip32Derivation};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{BlockHeight, MainNetwork};

/// Hauteur de naissance de tous les comptes protégés : juste avant la
/// première version de l'app qui affiche une adresse u1 (chaîne à 3 505 105
/// le 03/10/2026).
pub const BIRTHDAY_HEIGHT: u32 = 3_504_000;
const WALLET_FILE: &str = "zcash_shielded.sqlite";
/// Blocs téléchargés puis analysés par lot.
const SYNC_BATCH: u32 = 1_000;

type Db = WalletDb<rusqlite::Connection, MainNetwork, SystemClock, rand_core::OsRng>;

fn open(data_dir: &Path) -> Result<Db> {
    let mut db = WalletDb::for_path(data_dir.join(WALLET_FILE), MainNetwork, SystemClock, rand_core::OsRng).context("base Zcash protégée illisible")?;
    init_wallet_db(&mut db, None).map_err(|e| anyhow!("base Zcash protégée : migration impossible ({e})"))?;
    Ok(db)
}

fn account_index(profile: u32) -> Result<zip32::AccountId> {
    zip32::AccountId::try_from(profile).map_err(|_| anyhow!("profil hors des comptes Zcash possibles"))
}

/// Clé de visualisation du compte protégé du profil (calcul local, à partir
/// de la seed).
pub fn viewing_key(seed: &[u8], profile: u32) -> Result<UnifiedFullViewingKey> {
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, seed, account_index(profile)?).map_err(|e| anyhow!("clé Zcash protégée : {e:?}"))?;
    Ok(usk.to_unified_full_viewing_key())
}

/// Adresse protégée du profil : adresse unifiée au seul récepteur Orchard.
pub fn address(ufvk: &UnifiedFullViewingKey) -> Result<String> {
    let (address, _) = ufvk.default_address(UnifiedAddressRequest::ORCHARD).map_err(|e| anyhow!("adresse Zcash protégée : {e:?}"))?;
    Ok(address.encode(&MainNetwork))
}

/// Compte protégé du profil dans la base, s'il existe.
fn find_account(db: &Db, profile: u32) -> Result<Option<AccountUuid>> {
    let wanted = account_index(profile)?;
    for id in db.get_account_ids()? {
        if let Some(account) = db.get_account(id)? {
            // Compte importé par sa clé de visualisation (`AccountSource::Imported`)
            // ou dérivé : même métadonnée de dérivation ZIP-32.
            if account.source().key_derivation().is_some_and(|d| d.account_index() == wanted) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

// --- lightwalletd ---------------------------------------------------------------

/// Connexion sans délai par requête (un lot de blocs compacts peut dépasser
/// les 30 s du client transparent), serveurs essayés dans l'ordre.
async fn client() -> Result<CompactTxStreamerClient<tonic::transport::Channel>> {
    let mut last = anyhow!("aucun serveur Zcash configuré");
    for server in zcash::SERVERS {
        let tls = tonic::transport::ClientTlsConfig::new().with_webpki_roots();
        let endpoint = tonic::transport::Channel::from_static(server).tls_config(tls)?.connect_timeout(std::time::Duration::from_secs(10));
        match endpoint.connect().await {
            Ok(channel) => return Ok(CompactTxStreamerClient::new(channel)),
            Err(e) => last = anyhow!("serveur Zcash {server} injoignable : {e}"),
        }
    }
    Err(last)
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().context("démarrage du client Zcash impossible")
}

/// Naissance des comptes : état des arbres de commitments juste avant
/// `BIRTHDAY_HEIGHT`.
async fn birthday(client: &mut CompactTxStreamerClient<tonic::transport::Channel>) -> Result<AccountBirthday> {
    let state = client
        .get_tree_state(BlockId { height: u64::from(BIRTHDAY_HEIGHT - 1), hash: vec![] })
        .await
        .map_err(|e| anyhow!("état de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner();
    AccountBirthday::from_treestate(state, None).map_err(|_| anyhow!("état de la chaîne Zcash invalide"))
}

/// Clés d'un profil pour `ensure_accounts`, dérivées de la seed : clé de
/// visualisation, clé publique de l'adresse t1, empreinte de la seed.
pub type ProfileKeys = (u32, UnifiedFullViewingKey, [u8; 33], zip32::fingerprint::SeedFingerprint);

pub fn profile_keys(seed: &[u8], profile: u32) -> Result<ProfileKeys> {
    let ufvk = viewing_key(seed, profile)?;
    let (t1_key, _) = derivation::derive_zec_key(seed, profile)?;
    let pubkey: [u8; 33] = t1_key.verifying_key().to_encoded_point(true).as_bytes().try_into().context("clé publique Zcash invalide")?;
    let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(seed).context("seed trop courte pour Zcash")?;
    Ok((profile, ufvk, pubkey, seed_fp))
}

/// Crée (une fois) le compte protégé de chaque profil — appelé après le
/// déverrouillage, sans la seed (clés déjà dérivées).
pub fn ensure_accounts(data_dir: &Path, profiles: &[ProfileKeys]) -> Result<()> {
    let mut db = open(data_dir)?;
    let mut missing = Vec::new();
    for keys in profiles {
        if find_account(&db, keys.0)?.is_none() {
            missing.push(keys);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let birthday = runtime()?.block_on(async { birthday(&mut client().await?).await })?;
    for (profile, ufvk, t1_pubkey, seed_fp) in missing {
        let purpose = AccountPurpose::Spending { derivation: Some(Zip32Derivation::new(*seed_fp, account_index(*profile)?)) };
        let account = db
            .import_account_ufvk(&format!("Profil {profile}"), ufvk, &birthday, purpose, Some("openpgp-wallet"))
            .map_err(|e| anyhow!("compte Zcash protégé : création impossible ({e})"))?;
        // Profil principal : son adresse t1 est déjà la première adresse
        // transparente du compte 0 ; les autres sont importées.
        if *profile != 0 {
            let pubkey = secp256k1::PublicKey::from_slice(t1_pubkey).context("clé publique Zcash invalide")?;
            db.import_standalone_transparent_pubkey(account.id(), pubkey).map_err(|e| anyhow!("adresse t1 : import impossible ({e})"))?;
        }
    }
    Ok(())
}

/// Synchronise tous les comptes protégés jusqu'au bout de la chaîne.
pub fn sync(data_dir: &Path) -> Result<()> {
    let mut db = open(data_dir)?;
    if db.get_account_ids()?.is_empty() {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = client().await?;
        let cache = MemoryCache::default();
        zcash_client_backend::sync::run(&mut client, &MainNetwork, &cache, &mut db, SYNC_BATCH).await.map_err(|e| anyhow!("synchronisation Zcash protégée : {e}"))
    })
}

/// Solde du compte protégé du profil (zatoshis).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ShieldedBalance {
    /// Dépensable maintenant (notes Orchard confirmées).
    pub spendable: u64,
    /// Reçu mais pas encore dépensable (confirmations en attente).
    pub pending: u64,
    /// Hauteur jusqu'où la chaîne a été analysée (`None` : pas encore).
    pub scanned_height: Option<u32>,
    pub chain_height: Option<u32>,
}

pub fn balance(data_dir: &Path, profile: u32) -> Result<ShieldedBalance> {
    let db = open(data_dir)?;
    let Some(account) = find_account(&db, profile)? else { return Ok(ShieldedBalance::default()) };
    let Some(summary) = db.get_wallet_summary(ConfirmationsPolicy::default())? else { return Ok(ShieldedBalance::default()) };
    let Some(balances) = summary.account_balances().get(&account) else { return Ok(ShieldedBalance::default()) };
    let orchard = balances.orchard_balance();
    let spendable = u64::from(orchard.spendable_value());
    let total = u64::from(orchard.total());
    Ok(ShieldedBalance {
        spendable,
        pending: total.saturating_sub(spendable),
        scanned_height: Some(u32::from(summary.fully_scanned_height())),
        chain_height: Some(u32::from(summary.chain_tip_height())),
    })
}

// --- Cache de blocs en mémoire (le temps d'une synchronisation) -------------------

#[derive(Debug)]
pub struct CacheError(String);

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cache de blocs : {}", self.0)
    }
}

impl std::error::Error for CacheError {}

#[derive(Default)]
struct MemoryCache {
    blocks: Mutex<Vec<CompactBlock>>,
}

fn height_of(block: &CompactBlock) -> BlockHeight {
    BlockHeight::from_u32(block.height as u32)
}

fn poisoned() -> CacheError {
    CacheError("verrou empoisonné".into())
}

impl BlockSource for MemoryCache {
    type Error = CacheError;

    fn with_blocks<F, WalletErrT>(&self, from_height: Option<BlockHeight>, limit: Option<usize>, mut with_block: F) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>,
    {
        let mut blocks: Vec<CompactBlock> = {
            let cached = self.blocks.lock().map_err(|_| chain_error::Error::BlockSource(poisoned()))?;
            cached.iter().filter(|b| from_height.is_none_or(|h| height_of(b) >= h)).cloned().collect()
        };
        blocks.sort_by_key(|b| b.height);
        for block in blocks.into_iter().take(limit.unwrap_or(usize::MAX)) {
            with_block(block)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemoryCache {
    fn get_tip_height(&self, range: Option<&ScanRange>) -> Result<Option<BlockHeight>, Self::Error> {
        let cached = self.blocks.lock().map_err(|_| poisoned())?;
        Ok(cached.iter().map(height_of).filter(|h| range.is_none_or(|r| r.block_range().contains(h))).max())
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let cached = self.blocks.lock().map_err(|_| poisoned())?;
        let mut blocks: Vec<CompactBlock> = cached.iter().filter(|b| range.block_range().contains(&height_of(b))).cloned().collect();
        blocks.sort_by_key(|b| b.height);
        Ok(blocks)
    }

    async fn insert(&self, mut compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        self.blocks.lock().map_err(|_| poisoned())?.append(&mut compact_blocks);
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        self.blocks.lock().map_err(|_| poisoned())?.retain(|b| !range.block_range().contains(&height_of(b)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 64] = [5u8; 64];

    /// Adresse u1 au seul récepteur Orchard, propre à chaque profil, relue
    /// par la bibliothèque d'adresses officielle.
    #[test]
    fn orchard_only_unified_addresses_per_profile() {
        let a0 = address(&viewing_key(&SEED, 0).unwrap()).unwrap();
        let a1 = address(&viewing_key(&SEED, 1).unwrap()).unwrap();
        assert!(a0.starts_with("u1") && a1.starts_with("u1") && a0 != a1);
        assert_eq!(a0, address(&viewing_key(&SEED, 0).unwrap()).unwrap(), "déterministe");
        let parsed = zcash_address::ZcashAddress::try_from_encoded(&a0).unwrap();
        assert!(parsed.can_receive_as(zcash_protocol::PoolType::ORCHARD));
        assert!(!parsed.can_receive_as(zcash_protocol::PoolType::SAPLING) && !parsed.can_receive_as(zcash_protocol::PoolType::TRANSPARENT));
    }

    /// Réseau réel (lecture seule) : comptes créés à la naissance commune,
    /// synchronisés jusqu'au bout de la chaîne, solde nul, puis relus sans
    /// nouvelle création.
    /// `cargo test --lib real_shielded_sync -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_shielded_sync() {
        let dir = std::env::temp_dir().join(format!("zec-shielded-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [profile_keys(&SEED, 0).unwrap(), profile_keys(&SEED, 1).unwrap()];
        ensure_accounts(&dir, &keys).unwrap();
        ensure_accounts(&dir, &keys).unwrap();
        let start = std::time::Instant::now();
        sync(&dir).unwrap();
        let b = balance(&dir, 1).unwrap();
        println!("synchronisé en {:?} : {b:?}", start.elapsed());
        assert_eq!((b.spendable, b.pending), (0, 0));
        assert!(b.scanned_height.unwrap() + 5 >= b.chain_height.unwrap() && b.chain_height.unwrap() > BIRTHDAY_HEIGHT);
        assert_eq!(open(&dir).unwrap().get_account_ids().unwrap().len(), 2, "un compte par profil, une seule fois");
        std::fs::remove_dir_all(&dir).ok();
    }
}
