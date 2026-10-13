//! Shielded Zcash (Orchard and Ironwood pools): unified address u1… (Orchard
//! receiver only, which Ironwood shares), receiving, balance, then shielding
//! transparent ZEC and sending.
//!
//! The official light wallet stack (the one Zashi uses):
//! - `zcash_client_sqlite`: local wallet database (notes, commitment trees). It
//!   only holds VIEWING keys (UFVK): the spending key is derived from the seed
//!   (password) at signing time. A leak of this database exposes the shielded
//!   history, never the funds.
//! - `zcash_client_backend::sync`: sync through the lightwalletd servers already
//!   used for transparent funds (compact blocks, trial decryption), sending nothing
//!   but block requests.
//!
//! Shielded account no. p = ZIP-32 account no. p of the seed (profile no. p). The
//! profile's existing t1 address (m/44'/133'/0'/0/p) is imported into it so it can
//! be shielded. Every account shares the same birthday (`BIRTHDAY_HEIGHT`): no
//! shielded address from the app existed before it, so nothing can be missed, and a
//! restore on another device finds everything without rescanning the chain.

use crate::{derivation, history, wallet_birthday, zcash};
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

/// Birthday height of every shielded account: just before the first app version
/// that shows a u1 address (the chain was at 3,505,105 on 2026-10-03).
pub const BIRTHDAY_HEIGHT: u32 = 3_504_000;
const WALLET_FILE: &str = "zcash_shielded.sqlite";
/// Rescan from the fixed birthday requested (handled by the next sync, which holds
/// the database).
const RESCAN_FILE: &str = "zcash_shielded_rescan";
/// Blocks downloaded, then scanned, per batch.
const SYNC_BATCH: u32 = 1_000;

type Db = WalletDb<rusqlite::Connection, MainNetwork, SystemClock, rand_core::OsRng>;

fn open(data_dir: &Path) -> Result<Db> {
    let mut db = WalletDb::for_path(data_dir.join(WALLET_FILE), MainNetwork, SystemClock, rand_core::OsRng).context("base Zcash protégée illisible")?;
    init_wallet_db(&mut db, None).map_err(|e| anyhow!("base Zcash protégée : migration impossible ({e})"))?;
    Ok(db)
}

/// Database for a plain read (balance, history, maximum amount): `None` if it does
/// not exist; it is never created here. Seen on 2026-10-07: a balance requested
/// right after the database was erased (reset) recreated it immediately, empty but
/// under the next wallet's name.
fn open_existing(data_dir: &Path) -> Result<Option<Db>> {
    if !data_dir.join(WALLET_FILE).exists() {
        return Ok(None);
    }
    open(data_dir).map(Some)
}

/// Forgets the remembered addresses (state wipe, see `seed_state`).
pub(crate) fn forget_known() {
    *KNOWN.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

fn account_index(profile: u32) -> Result<zip32::AccountId> {
    zip32::AccountId::try_from(profile).map_err(|_| anyhow!("profil hors des comptes Zcash possibles"))
}

/// Viewing key of the profile's shielded account (computed locally from the seed).
pub fn viewing_key(seed: &[u8], profile: u32) -> Result<UnifiedFullViewingKey> {
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, seed, account_index(profile)?).map_err(|e| anyhow!("clé Zcash protégée : {e:?}"))?;
    Ok(usk.to_unified_full_viewing_key())
}

/// The profile's shielded address: a unified address with only an Orchard receiver.
pub fn address(ufvk: &UnifiedFullViewingKey) -> Result<String> {
    let (address, _) = ufvk.default_address(UnifiedAddressRequest::ORCHARD).map_err(|e| anyhow!("adresse Zcash protégée : {e:?}"))?;
    Ok(address.encode(&MainNetwork))
}

/// The profile's shielded account in the database, if it exists.
fn find_account(db: &Db, profile: u32) -> Result<Option<AccountUuid>> {
    let wanted = account_index(profile)?;
    for id in db.get_account_ids()? {
        if let Some(account) = db.get_account(id)? {
            // Account imported from its viewing key (`AccountSource::Imported`) or derived:
            // same ZIP-32 derivation metadata.
            if account.source().key_derivation().is_some_and(|d| d.account_index() == wanted) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

// --- lightwalletd --------------------------------------------------------------

/// Connection without a per-request timeout (a batch of compact blocks can take
/// longer than the transparent client's 30 s), servers tried in order. `future` is
/// dropped as soon as a state wipe is requested (see `seed_state`): `None`. The
/// database opened around it closes straight away.
async fn unless_wiped<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<Option<T>> {
    let wiped = async {
        while !crate::seed_state::cancelled() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    tokio::select! {
        result = future => result.map(Some),
        () = wiped => Ok(None),
    }
}

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

/// Account birthday: the state of the commitment trees just before the first block
/// to scan, shortly before the wallet was created when that is known (see
/// `wallet_birthday`, ~75 s per block), otherwise `BIRTHDAY_HEIGHT`.
async fn birthday(data_dir: &Path, client: &mut CompactTxStreamerClient<tonic::transport::Channel>) -> Result<AccountBirthday> {
    let tip = client
        .get_latest_block(zcash_client_backend::proto::service::ChainSpec {})
        .await
        .map_err(|e| anyhow!("hauteur de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner()
        .height;
    let start = wallet_birthday::start_height(data_dir, tip, 75, u64::from(BIRTHDAY_HEIGHT));
    let state = client
        .get_tree_state(BlockId { height: start - 1, hash: vec![] })
        .await
        .map_err(|e| anyhow!("état de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner();
    AccountBirthday::from_treestate(state, None).map_err(|_| anyhow!("état de la chaîne Zcash invalide"))
}

/// A profile's keys for `ensure_accounts`, derived from the seed: viewing key,
/// public key of the t1 address, seed fingerprint.
pub type ProfileKeys = (u32, UnifiedFullViewingKey, [u8; 33], zip32::fingerprint::SeedFingerprint);

pub fn profile_keys(seed: &[u8], profile: u32) -> Result<ProfileKeys> {
    let ufvk = viewing_key(seed, profile)?;
    let (t1_key, _) = derivation::derive_zec_key(seed, profile)?;
    let pubkey: [u8; 33] = t1_key.verifying_key().to_encoded_point(true).as_bytes().try_into().context("clé publique Zcash invalide")?;
    let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(seed).context("seed trop courte pour Zcash")?;
    Ok((profile, ufvk, pubkey, seed_fp))
}

/// Creates (once) each profile's shielded account. Called after unlocking, without
/// the seed (keys already derived).
pub fn ensure_accounts(data_dir: &Path, profiles: &[ProfileKeys]) -> Result<()> {
    let addresses = profiles.iter().map(|keys| Ok((address(&keys.1)?, keys.0))).collect::<Result<_>>()?;
    *KNOWN.lock().unwrap_or_else(|p| p.into_inner()) = Some((data_dir.to_path_buf(), addresses));
    let mut db = open(data_dir)?;
    // "Rescan from the beginning": accounts deleted, then recreated below from the
    // fixed birthday (creation date forgotten).
    let rescan = data_dir.join(RESCAN_FILE);
    if rescan.exists() {
        for id in db.get_account_ids()? {
            db.delete_account(id).map_err(|e| anyhow!("réanalyse Zcash protégée : suppression impossible ({e})"))?;
        }
        std::fs::remove_file(&rescan).context("réanalyse Zcash protégée : demande illisible")?;
    }
    let mut missing = Vec::new();
    for keys in profiles {
        if find_account(&db, keys.0)?.is_none() {
            missing.push(keys);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let Some(birthday) = runtime()?.block_on(unless_wiped(async { birthday(data_dir, &mut client().await?).await }))? else { return Ok(()) };
    for (profile, ufvk, t1_pubkey, seed_fp) in missing {
        let purpose = AccountPurpose::Spending { derivation: Some(Zip32Derivation::new(*seed_fp, account_index(*profile)?)) };
        let account = db
            .import_account_ufvk(&format!("Profil {profile}"), ufvk, &birthday, purpose, Some("openpgp-wallet"))
            .map_err(|e| anyhow!("compte Zcash protégé : création impossible ({e})"))?;
        // Main profile: its t1 address is already the first transparent address of account
        // 0; the others are imported.
        if *profile != 0 {
            let pubkey = secp256k1::PublicKey::from_slice(t1_pubkey).context("clé publique Zcash invalide")?;
            db.import_standalone_transparent_pubkey(account.id(), pubkey).map_err(|e| anyhow!("adresse t1 : import impossible ({e})"))?;
        }
    }
    Ok(())
}

/// Removes from the database the accounts of ANOTHER wallet (another seed: a reset,
/// then a new wallet or a restore on this device), so their balance and history are
/// never shown for this one (accounts are found by their number alone, see
/// `find_account`). Called on unlock, before anything is displayed.
pub fn forget_other_wallets(data_dir: &Path, seed: &[u8]) -> Result<()> {
    if !data_dir.join(WALLET_FILE).exists() {
        return Ok(());
    }
    let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(seed).context("seed trop courte pour Zcash")?;
    let mut db = open(data_dir)?;
    for id in db.get_account_ids()? {
        let Some(account) = db.get_account(id)? else { continue };
        if !account.source().key_derivation().is_some_and(|d| d.seed_fingerprint() == &fingerprint) {
            db.delete_account(id).map_err(|e| anyhow!("compte Zcash protégé d'un autre portefeuille : suppression impossible ({e})"))?;
        }
    }
    Ok(())
}

/// Requests a full rescan (Settings): at the next sync, accounts are recreated from
/// the fixed birthday.
pub fn request_rescan(data_dir: &Path) -> Result<()> {
    std::fs::write(data_dir.join(RESCAN_FILE), b"1").context("réanalyse Zcash protégée : demande impossible")
}

/// Syncs every shielded account up to the tip of the chain.
pub fn sync(data_dir: &Path) -> Result<()> {
    let mut db = open(data_dir)?;
    if db.get_account_ids()?.is_empty() {
        return Ok(());
    }
    // Reset or restore requested: this pass is abandoned (see `unless_wiped`).
    runtime()?
        .block_on(unless_wiped(async {
            let mut client = client().await?;
            let cache = MemoryCache::default();
            zcash_client_backend::sync::run(&mut client, &MainNetwork, &cache, &mut db, SYNC_BATCH).await.map_err(|e| anyhow!("synchronisation Zcash protégée : {e}"))
        }))
        .map(|_| ())
}

/// Balance of the profile's shielded account (zatoshis).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ShieldedBalance {
    /// Spendable now (confirmed Orchard and Ironwood notes).
    pub spendable: u64,
    /// Received but not spendable yet (confirmations pending).
    pub pending: u64,
    /// Height up to which the chain has been scanned (`None`: not yet).
    pub scanned_height: Option<u32>,
    pub chain_height: Option<u32>,
}

pub fn balance(data_dir: &Path, profile: u32) -> Result<ShieldedBalance> {
    let Some(db) = open_existing(data_dir)? else { return Ok(ShieldedBalance::default()) };
    let Some(account) = find_account(&db, profile)? else { return Ok(ShieldedBalance::default()) };
    let Some(summary) = db.get_wallet_summary(ConfirmationsPolicy::default())? else { return Ok(ShieldedBalance::default()) };
    let Some(balances) = summary.account_balances().get(&account) else { return Ok(ShieldedBalance::default()) };
    // Since NU6.3 (block 3,428,143) the Orchard pool is sealed and every new shielded
    // note lands in Ironwood. Both pools are counted so that nothing the wallet holds
    // is ever left off the balance.
    let pools = [balances.orchard_balance(), balances.ironwood_balance()];
    let spendable: u64 = pools.iter().map(|b| u64::from(b.spendable_value())).sum();
    let total: u64 = pools.iter().map(|b| u64::from(b.total())).sum();
    Ok(ShieldedBalance {
        spendable,
        pending: total.saturating_sub(spendable),
        scanned_height: Some(u32::from(summary.fully_scanned_height())),
        chain_height: Some(u32::from(summary.chain_tip_height())),
    })
}

// --- History ("Shielded Zcash" card) ----------------------------------------------

/// Database folder and known shielded addresses (u1 address → profile), recorded by
/// `ensure_accounts`: the portfolio chart reads balance and history by address
/// (`balance_of_address`, `history_of_address`).
static KNOWN: Mutex<Option<(std::path::PathBuf, std::collections::BTreeMap<String, u32>)>> = Mutex::new(None);

/// A shielded address from the app (mainnet u1…, Orchard receiver).
pub fn parse_shielded_address(address: &str) -> Result<()> {
    anyhow::ensure!(address.trim().starts_with("u1"), "adresse Zcash protégée invalide (u1… attendue)");
    let parsed = check_recipient(address)?;
    anyhow::ensure!(parsed.can_receive_as(PoolType::ORCHARD), "adresse Zcash protégée invalide (u1… attendue)");
    Ok(())
}

/// Transactions of the profile's shielded account, newest first: the change in
/// shielded funds only (notes received minus notes spent). A shielding shows up as
/// received here and as sent on the transparent card; a send includes its fee. Read
/// from the local database, no network calls.
pub fn history(data_dir: &Path, profile: u32) -> Result<Vec<history::TxEntry>> {
    let Some(db) = open_existing(data_dir)? else { return Ok(Vec::new()) };
    let Some(account) = find_account(&db, profile)? else { return Ok(Vec::new()) };
    let conn = rusqlite::Connection::open_with_flags(data_dir.join(WALLET_FILE), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .context("base Zcash protégée illisible")?;
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts WHERE uuid = ?1", [account.expose_uuid().as_bytes().to_vec()], |row| row.get(0))
        .context("compte Zcash protégé introuvable")?;
    shielded_history(&conn, account_id)
}

/// Net shielded value per transaction, across the Orchard and Ironwood pools
/// (Ironwood holds every note received since NU6.3).
fn shielded_history(conn: &rusqlite::Connection, account_id: i64) -> Result<Vec<history::TxEntry>> {
    let tip: Option<u32> = conn.query_row("SELECT MAX(height) FROM blocks", [], |row| row.get(0)).context("base Zcash protégée illisible")?;
    let mut statement = conn
        .prepare(
            "WITH deltas AS (
                 SELECT rn.transaction_id AS tx, rn.value AS value
                 FROM orchard_received_notes rn WHERE rn.account_id = ?1
                 UNION ALL
                 SELECT s.transaction_id AS tx, -rn.value AS value
                 FROM orchard_received_note_spends s
                 JOIN orchard_received_notes rn ON rn.id = s.orchard_received_note_id
                 WHERE rn.account_id = ?1
                 UNION ALL
                 SELECT rn.transaction_id AS tx, rn.value AS value
                 FROM ironwood_received_notes rn WHERE rn.account_id = ?1
                 UNION ALL
                 SELECT s.transaction_id AS tx, -rn.value AS value
                 FROM ironwood_received_note_spends s
                 JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
                 WHERE rn.account_id = ?1
             )
             SELECT t.txid, t.mined_height, b.time, t.expiry_height, SUM(d.value)
             FROM deltas d
             JOIN transactions t ON t.id_tx = d.tx
             LEFT JOIN blocks b ON b.height = t.mined_height
             GROUP BY d.tx
             ORDER BY t.mined_height IS NULL DESC, t.mined_height DESC",
        )
        .context("base Zcash protégée illisible")?;
    let rows = statement
        .query_map([account_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<u32>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<u32>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .context("base Zcash protégée illisible")?;
    let mut entries = Vec::new();
    for row in rows {
        let (txid, mined, time, expiry, net) = row.context("base Zcash protégée illisible")?;
        let txid: [u8; 32] = txid.try_into().map_err(|_| anyhow!("identifiant de transaction Zcash invalide"))?;
        let expired = mined.is_none() && matches!((expiry, tip), (Some(e), Some(t)) if e > 0 && e <= t);
        entries.push(history::TxEntry {
            id: zcash_protocol::TxId::from_bytes(txid).to_string(),
            timestamp_unix: time,
            status: match (mined, expired) {
                (Some(_), _) => history::TxStatus::Confirmed,
                (None, false) => history::TxStatus::Pending,
                (None, true) => history::TxStatus::Failed,
            },
            net_amount_minor: Some(i128::from(net)),
            fee_minor: 0,
            kind: match net {
                n if n > 0 => history::TxKind::Received,
                n if n < 0 => history::TxKind::Sent,
                _ => history::TxKind::Other,
            },
        });
    }
    Ok(entries)
}

fn known_profile(address: &str) -> Result<(std::path::PathBuf, u32)> {
    let known = KNOWN.lock().unwrap_or_else(|p| p.into_inner());
    let (dir, addresses) = known.as_ref().ok_or_else(|| anyhow!("fonds protégés pas encore prêts (synchronisation en cours)"))?;
    let profile = addresses.get(address.trim()).ok_or_else(|| anyhow!("adresse Zcash protégée inconnue de ce portefeuille"))?;
    Ok((dir.clone(), *profile))
}

/// Shielded funds of the address (spendable and pending): portfolio chart.
pub fn balance_of_address(address: &str) -> Result<u64> {
    let (dir, profile) = known_profile(address)?;
    let b = balance(&dir, profile)?;
    Ok(b.spendable.saturating_add(b.pending))
}

pub fn history_of_address(address: &str) -> Result<Vec<history::TxEntry>> {
    let (dir, profile) = known_profile(address)?;
    history(&dir, profile)
}

// --- Spending: shielding transparent ZEC, sending shielded funds
// -------------------
//
// As elsewhere in the app, the transaction is first PROPOSED (inputs, ZIP-317 fee,
// change, without any spending key), its summary is confirmed in a native dialog,
// then THAT proposal is signed with the key derived from the seed (password) and
// broadcast through lightwalletd.

use zcash_client_backend::data_api::wallet::input_selection::{GreedyInputSelector, LockedInputPolicy, SpendPolicy};
use zcash_client_backend::data_api::wallet::{create_proposed_transactions, propose_send_max_transfer, propose_shielding, propose_transfer, SpendingKeys};
use zcash_client_backend::data_api::MaxSpendMode;
use zcash_client_backend::data_api::CoinbaseFilter;
use zcash_client_backend::fees::{zip317::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool};

/// No Sapling prover: the app never spends or creates a Sapling note (recipients
/// are transparent or have an Orchard receiver, change goes to Ironwood, all
/// checked before the proposal). A Sapling spend would fail while preparing the
/// circuit; a Sapling output would carry an empty proof that the network would
/// refuse, so funds are never at stake.
struct NoSapling;

impl sapling_crypto::prover::SpendProver for NoSapling {
    type Proof = ();

    fn prepare_circuit(
        _: sapling_crypto::ProofGenerationKey,
        _: sapling_crypto::Diversifier,
        _: sapling_crypto::Rseed,
        _: sapling_crypto::value::NoteValue,
        _: jubjub::Fr,
        _: sapling_crypto::value::ValueCommitTrapdoor,
        _: bls12_381::Scalar,
        _: sapling_crypto::MerklePath,
    ) -> Option<sapling_crypto::circuit::Spend> {
        None
    }

    fn create_proof<R: rand_core::RngCore>(&self, _: sapling_crypto::circuit::Spend, _: &mut R) -> Self::Proof {}

    fn encode_proof(_: Self::Proof) -> sapling_crypto::bundle::GrothProofBytes {
        // Size of a Groth16 proof (48 + 96 + 48 bytes).
        [0; 192]
    }
}

impl sapling_crypto::prover::OutputProver for NoSapling {
    type Proof = ();

    fn prepare_circuit(
        _: &sapling_crypto::keys::EphemeralSecretKey,
        _: sapling_crypto::PaymentAddress,
        _: jubjub::Fr,
        _: sapling_crypto::value::NoteValue,
        _: sapling_crypto::value::ValueCommitTrapdoor,
    ) -> sapling_crypto::circuit::Output {
        sapling_crypto::circuit::Output { value_commitment_opening: None, payment_address: None, commitment_randomness: None, esk: None }
    }

    fn create_proof<R: rand_core::RngCore>(&self, _: sapling_crypto::circuit::Output, _: &mut R) -> Self::Proof {}

    fn encode_proof(_: Self::Proof) -> sapling_crypto::bundle::GrothProofBytes {
        // Size of a Groth16 proof (48 + 96 + 48 bytes).
        [0; 192]
    }
}

/// Summary of a spend, shown in the confirmation dialog.
#[derive(Clone, Debug, PartialEq)]
pub struct SpendSummary {
    /// Amount that reaches the recipient (or gets shielded), in zatoshis.
    pub amount: u64,
    /// ZIP-317 fee.
    pub fee: u64,
    /// Recipient (the profile's shielded address for a shielding).
    pub recipient: String,
}

/// Change, and shielded transparent funds, go to Ironwood: the Orchard pool has
/// been sealed since NU6.3 and refuses new value. (The library would already
/// redirect an Orchard fallback there; this states it outright.)
fn change_strategy() -> SingleOutputChangeStrategy<StandardFeeRule, Db> {
    SingleOutputChangeStrategy::new(StandardFeeRule::Zip317, None, ShieldedPool::Ironwood, DustOutputPolicy::default())
}

/// The profile's spending keys: unified key of the ZIP-32 account, and the key of
/// the imported t1 address (profiles other than the main one).
fn spending_keys(seed: &[u8], profile: u32) -> Result<SpendingKeys> {
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, seed, account_index(profile)?).map_err(|e| anyhow!("clé Zcash protégée : {e:?}"))?;
    let mut standalone = std::collections::HashMap::new();
    if profile != 0 {
        let (key, hash160) = derivation::derive_zec_key(seed, profile)?;
        let secret = secp256k1::SecretKey::from_slice(&key.to_bytes()).context("clé Zcash invalide")?;
        standalone.insert(zcash_transparent::address::TransparentAddress::PublicKeyHash(hash160), vec![secret]);
    }
    Ok(SpendingKeys::new(usk, standalone))
}

/// Signs the proposal and broadcasts its transactions; returns the last identifier.
fn create_and_broadcast<N: std::fmt::Display>(db: &mut Db, proposal: &Proposal<StandardFeeRule, N>, keys: &SpendingKeys) -> Result<String> {
    // Input selection and change error types: specific to the proposal, never produced
    // while building.
    let txids = create_proposed_transactions::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(db, &MainNetwork, &NoSapling, &NoSapling, keys, OvkPolicy::Sender, proposal, None)
        .map_err(|e| anyhow!("transaction Zcash protégée : construction impossible ({e})"))?;
    let mut last = String::new();
    for txid in txids {
        let tx = db.get_transaction(txid)?.context("transaction Zcash protégée introuvable après sa construction")?;
        let mut raw = Vec::new();
        tx.write(&mut raw).context("sérialisation de la transaction Zcash impossible")?;
        last = zcash::broadcast(&raw, &txid.to_string())?;
    }
    Ok(last)
}

/// Insufficient funds, in plain words: library messages recorded live
/// ("Insufficient balance (have 0, need 1010000 including fee)", "Insufficient
/// funds: required 10000 zatoshis, but only 0 zatoshis were available").
fn insufficient(message: &str) -> Option<anyhow::Error> {
    let number_after = |marker: &str| -> Option<u64> {
        let rest = &message[message.find(marker)? + marker.len()..];
        rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    };
    let (have, need) = match (number_after("have "), number_after("need ")) {
        (Some(have), Some(need)) => (have, need),
        _ => (number_after("but only ")?, number_after("required ")?),
    };
    Some(anyhow!("ZEC insuffisants : {} disponibles, {} nécessaires (frais compris)", zcash::format_zec(have), zcash::format_zec(need)))
}

fn proposal_fee<N>(proposal: &Proposal<StandardFeeRule, N>) -> u64 {
    proposal.steps().iter().map(|step| u64::from(step.balance().fee_required())).sum()
}

/// Shields the ZEC on the profile's t1 address `t1` (to its shielded address):
/// proposes, has the summary confirmed (`confirm`), then signs with the seed
/// (`seed`) and broadcasts. `Ok(None)`: confirmation declined.
pub fn shield(
    data_dir: &Path,
    profile: u32,
    t1: &str,
    confirm: impl FnOnce(&SpendSummary) -> bool,
    seed: impl FnOnce() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Option<String>> {
    let mut db = open(data_dir)?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let from = match zcash::parse_recipient(t1)? {
        zcash::Recipient::P2pkh(hash) => zcash_transparent::address::TransparentAddress::PublicKeyHash(hash),
        zcash::Recipient::P2sh(_) => anyhow::bail!("adresse t1 du profil attendue"),
    };
    let proposal = propose_shielding::<_, _, _, _, std::convert::Infallible>(
        &mut db,
        &MainNetwork,
        &GreedyInputSelector::new(),
        &change_strategy(),
        Zatoshis::const_from_u64(10_000),
        &[from],
        account,
        ConfirmationsPolicy::default(),
        CoinbaseFilter::AllTransparentOutputs,
        None,
    )
    .map_err(|e| insufficient(&e.to_string()).unwrap_or_else(|| anyhow!("rien à protéger pour l'instant ({e})")))?;
    let fee = proposal_fee(&proposal);
    let inputs: u64 = proposal.steps().iter().flat_map(|s| s.transparent_inputs()).map(|i| u64::from(i.txout().value())).sum();
    let ufvk = db.get_account(account)?.and_then(|a| a.ufvk().cloned()).context("compte Zcash protégé sans clé de visualisation")?;
    let summary = SpendSummary { amount: inputs.saturating_sub(fee), fee, recipient: address(&ufvk)? };
    if !confirm(&summary) {
        return Ok(None);
    }
    let seed = seed()?;
    create_and_broadcast(&mut db, &proposal, &spending_keys(&seed, profile)?).map(Some)
}

/// Can the recipient receive without Sapling (transparent, or a unified address
/// with an Orchard receiver)?
pub fn check_recipient(address: &str) -> Result<zcash_address::ZcashAddress> {
    let parsed = zcash_address::ZcashAddress::try_from_encoded(address.trim()).map_err(|_| anyhow!("adresse Zcash invalide"))?;
    anyhow::ensure!(parsed.can_receive_as(PoolType::ORCHARD) || parsed.can_receive_as(PoolType::TRANSPARENT), "adresse Zcash Sapling seule (zs…) pas prise en charge — demandez une adresse u1… ou t1…");
    let mainnet = ["u1", "t1", "t3", "tex1"].iter().any(|prefix| address.trim().starts_with(prefix));
    anyhow::ensure!(mainnet, "adresse Zcash d'un autre réseau (test) — refusée");
    Ok(parsed)
}

/// Sends `amount` zatoshis from the profile's shielded funds to `to`: same steps as
/// `shield`.
pub fn send(
    data_dir: &Path,
    profile: u32,
    to: &str,
    amount: u64,
    confirm: impl FnOnce(&SpendSummary) -> bool,
    seed: impl FnOnce() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Option<String>> {
    let recipient = check_recipient(to)?;
    let mut db = open(data_dir)?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let value = Zatoshis::from_u64(amount).map_err(|_| anyhow!("montant hors limites"))?;
    let request = TransactionRequest::new(vec![Payment::without_memo(recipient, value)]).map_err(|e| anyhow!("demande de paiement invalide ({e:?})"))?;
    let proposal = propose_transfer::<_, _, _, _, std::convert::Infallible>(
        &mut db,
        &MainNetwork,
        account,
        &GreedyInputSelector::new(),
        &change_strategy(),
        request,
        ConfirmationsPolicy::default(),
        &SpendPolicy::default(),
        None,
        None,
    )
    .map_err(|e| insufficient(&e.to_string()).unwrap_or_else(|| anyhow!("envoi Zcash protégé impossible ({e})")))?;
    let summary = SpendSummary { amount, fee: proposal_fee(&proposal), recipient: to.trim().to_string() };
    if !confirm(&summary) {
        return Ok(None);
    }
    let seed = seed()?;
    create_and_broadcast(&mut db, &proposal, &spending_keys(&seed, profile)?).map(Some)
}

/// Proposal to send ALL spendable shielded funds (fee deducted through the
/// library's input selection, the only part that knows it) and the amount it sends.
fn max_proposal(db: &mut Db, account: AccountUuid, recipient: zcash_address::ZcashAddress) -> Result<(Proposal<StandardFeeRule, zcash_client_sqlite::ReceivedNoteId>, u64)> {
    let proposal = propose_send_max_transfer::<_, _, _, std::convert::Infallible>(
        db,
        &MainNetwork,
        account,
        // Ironwood holds every note received since NU6.3; Orchard notes, if any, may still
        // leave their sealed pool through the turnstile.
        &[ShieldedPool::Orchard, ShieldedPool::Ironwood],
        &StandardFeeRule::Zip317,
        recipient,
        None,
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::default(),
        &LockedInputPolicy::Exclude,
        None,
    )
    .map_err(|e| insufficient(&e.to_string()).unwrap_or_else(|| anyhow!("envoi Zcash protégé impossible ({e})")))?;
    let amount = proposal
        .steps()
        .first()
        .transaction_request()
        .total()
        .ok()
        .flatten()
        .map(u64::from)
        .filter(|amount| *amount > 0)
        .context("ZEC protégés insuffisants pour couvrir les frais du réseau")?;
    Ok((proposal, amount))
}

/// Maximum amount that can be sent from the profile's shielded funds (to `to`, or
/// to its own address for an estimate: same shielded fees).
pub fn max_amount(data_dir: &Path, profile: u32, to: &str) -> Result<u64> {
    let recipient = check_recipient(to)?;
    let mut db = open_existing(data_dir)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    Ok(max_proposal(&mut db, account, recipient)?.1)
}

/// Sends ALL the profile's spendable shielded funds to `to`, fee deducted: same
/// steps as `send`.
pub fn send_max(
    data_dir: &Path,
    profile: u32,
    to: &str,
    confirm: impl FnOnce(&SpendSummary) -> bool,
    seed: impl FnOnce() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Option<String>> {
    let recipient = check_recipient(to)?;
    let mut db = open(data_dir)?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let (proposal, amount) = max_proposal(&mut db, account, recipient)?;
    let summary = SpendSummary { amount, fee: proposal_fee(&proposal), recipient: to.trim().to_string() };
    if !confirm(&summary) {
        return Ok(None);
    }
    let seed = seed()?;
    create_and_broadcast(&mut db, &proposal, &spending_keys(&seed, profile)?).map(Some)
}

// --- In-memory block cache (for the duration of one sync) ------------------------

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
    use zcash_address::ToAddress as _;

    const SEED: [u8; 64] = [5u8; 64];

    /// Reads without a database (wallet reset): empty, and the database is not
    /// recreated.
    #[test]
    fn reads_never_create_the_database() {
        let dir = std::env::temp_dir().join(format!("zec-shielded-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(balance(&dir, 0).unwrap(), ShieldedBalance::default());
        assert!(history(&dir, 0).unwrap().is_empty());
        assert!(max_amount(&dir, 0, &address(&viewing_key(&SEED, 0).unwrap()).unwrap()).is_err());
        assert!(!dir.join(WALLET_FILE).exists(), "base recréée par une lecture");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// History query run against a database created by the library (real schema: tables
    /// and columns checked); empty with no transactions.
    #[test]
    fn history_query_matches_the_wallet_schema() {
        let dir = std::env::temp_dir().join(format!("zec-shielded-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        drop(open(&dir).unwrap());
        let conn = rusqlite::Connection::open(dir.join(WALLET_FILE)).unwrap();
        assert!(shielded_history(&conn, 1).unwrap().is_empty());
        assert!(history(&dir, 0).unwrap().is_empty(), "profil sans compte : historique vide");
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Since NU6.3 every shielded note lands in Ironwood: a note received, then spent
    /// with change, must show up in the history with the right net amounts. Rows are
    /// written straight into the library's real schema (foreign keys off: no account or
    /// block rows are needed for the query).
    #[test]
    fn history_counts_ironwood_notes() {
        let dir = std::env::temp_dir().join(format!("zec-shielded-ironwood-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        drop(open(&dir).unwrap());
        let conn = rusqlite::Connection::open(dir.join(WALLET_FILE)).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             INSERT INTO transactions (id_tx, txid, mined_height, min_observed_height) VALUES
                 (1, x'0000000000000000000000000000000000000000000000000000000000000001', 3500000, 3500000),
                 (2, x'0000000000000000000000000000000000000000000000000000000000000002', 3500010, 3500010);
             INSERT INTO ironwood_received_notes
                 (id, transaction_id, action_index, account_id, diversifier, value, rho, rseed, is_change, note_version) VALUES
                 (1, 1, 0, 1, x'00', 150000, x'00', x'00', 0, 0),
                 (2, 2, 0, 1, x'00', 90000, x'00', x'00', 1, 0);
             INSERT INTO ironwood_received_note_spends (ironwood_received_note_id, transaction_id) VALUES (1, 2);",
        )
        .unwrap();
        let entries = shielded_history(&conn, 1).unwrap();
        assert_eq!(entries.len(), 2);
        // Most recent first: the spend (50,000 sent + 10,000 fee), then the receipt.
        assert_eq!(entries[0].kind, history::TxKind::Sent);
        assert_eq!(entries[0].net_amount_minor, Some(-60_000));
        assert_eq!(entries[1].kind, history::TxKind::Received);
        assert_eq!(entries[1].net_amount_minor, Some(150_000));
        assert!(entries.iter().all(|e| matches!(e.status, history::TxStatus::Confirmed)));
        assert!(shielded_history(&conn, 2).unwrap().is_empty(), "another account sees nothing");
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Accounts of another wallet (another seed, same device) are removed on unlock;
    /// those of the current wallet are kept. Offline: a made-up account birthday (no
    /// lightwalletd call).
    #[test]
    fn accounts_of_another_wallet_are_forgotten() {
        use zcash_client_backend::data_api::chain::ChainState;
        let dir = std::env::temp_dir().join(format!("zec-shielded-forget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let birthday = AccountBirthday::from_parts(ChainState::empty(BlockHeight::from_u32(BIRTHDAY_HEIGHT - 1), zcash_primitives::block::BlockHash([0; 32])), None);
        let import = |seed: &[u8]| {
            let mut db = open(&dir).unwrap();
            let (profile, ufvk, _, fp) = profile_keys(seed, 0).unwrap();
            let purpose = AccountPurpose::Spending { derivation: Some(Zip32Derivation::new(fp, account_index(profile).unwrap())) };
            db.import_account_ufvk("test", &ufvk, &birthday, purpose, None).unwrap();
        };
        import(&SEED);
        forget_other_wallets(&dir, &SEED).unwrap();
        assert!(find_account(&open(&dir).unwrap(), 0).unwrap().is_some(), "compte du portefeuille courant gardé");
        let other = [8u8; 64];
        forget_other_wallets(&dir, &other).unwrap();
        assert!(find_account(&open(&dir).unwrap(), 0).unwrap().is_none(), "compte d'un autre portefeuille supprimé");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live: a wallet created just now → account birthday ~3 days before the latest
    /// block (instead of BIRTHDAY_HEIGHT); a restore → the fixed birthday.
    /// `cargo test -- --ignored real_birthday --nocapture`
    #[test]
    #[ignore]
    fn real_birthday_follows_wallet_creation() {
        let dir = std::env::temp_dir().join(format!("zec-birthday-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fixed = runtime().unwrap().block_on(async { birthday(&dir, &mut client().await.unwrap()).await }).unwrap();
        assert_eq!(u32::from(fixed.height()), BIRTHDAY_HEIGHT);
        wallet_birthday::record_created(&dir).unwrap();
        let fresh = runtime().unwrap().block_on(async { birthday(&dir, &mut client().await.unwrap()).await }).unwrap();
        let tip = runtime().unwrap().block_on(async {
            client().await.unwrap().get_latest_block(zcash_client_backend::proto::service::ChainSpec {}).await.unwrap().into_inner().height
        });
        println!("dernier bloc {tip} ; naissance fixe {} ; portefeuille neuf {}", u32::from(fixed.height()), u32::from(fresh.height()));
        // 3 days of margin at ~75 s per block, never before the fixed birthday.
        let expected = (tip - 3 * 86_400 / 75).max(u64::from(BIRTHDAY_HEIGHT));
        assert!(u64::from(u32::from(fresh.height())).abs_diff(expected) <= 2, "attendu ~{expected}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shielded_addresses_only() {
        let ufvk = viewing_key(&SEED, 0).unwrap();
        assert!(parse_shielded_address(&address(&ufvk).unwrap()).is_ok());
        assert!(parse_shielded_address("t1Vtnn4Lq8w1tQ8fJg1GsB4s9XzK6QnC2Zo").is_err());
        assert!(parse_shielded_address("u1pasuneadresse").is_err());
    }

    /// A u1 address with only an Orchard receiver, unique to each profile, reread by
    /// the official address library.
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

    /// Recipients: t1 and Orchard u1 accepted; Sapling-only refused.
    #[test]
    fn recipients_without_sapling() {
        let u1 = address(&viewing_key(&SEED, 0).unwrap()).unwrap();
        assert!(check_recipient(&u1).is_ok());
        assert!(check_recipient("t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE").is_ok());
        // A well-formed Sapling-only address (official encoding, valid checksum).
        let sapling = zcash_address::ZcashAddress::from_sapling(zcash_protocol::consensus::NetworkType::Main, [7u8; 43]).encode();
        assert!(sapling.starts_with("zs1"));
        assert!(check_recipient(&sapling).unwrap_err().to_string().contains("Sapling"), "Sapling seule");
        let testnet = zcash_address::ZcashAddress::from_transparent_p2pkh(zcash_protocol::consensus::NetworkType::Test, [7u8; 20]).encode();
        assert!(check_recipient(&testnet).is_err(), "réseau de test");
        assert!(check_recipient("pas une adresse").is_err());
    }

    /// Insufficient funds: the library's real messages, in plain words.
    #[test]
    fn insufficient_funds_in_plain_words() {
        let send = insufficient("Insufficient balance (have 0, need 1010000 including fee)").unwrap().to_string();
        assert_eq!(send, "ZEC insuffisants : 0.00000000 disponibles, 0.01010000 nécessaires (frais compris)");
        let shield = insufficient("Change output generation failed: Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were available.").unwrap().to_string();
        assert_eq!(shield, "ZEC insuffisants : 0.00000000 disponibles, 0.00010000 nécessaires (frais compris)");
        assert!(insufficient("autre erreur").is_none());
    }

    /// Real network (read-only): accounts created at the shared birthday, synced up to
    /// the tip of the chain, zero balance, then reread without being created again.
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
