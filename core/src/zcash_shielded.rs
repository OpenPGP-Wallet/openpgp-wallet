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

/// Hauteur de naissance de tous les comptes protégés : juste avant la
/// première version de l'app qui affiche une adresse u1 (chaîne à 3 505 105
/// le 03/10/2026).
pub const BIRTHDAY_HEIGHT: u32 = 3_504_000;
const WALLET_FILE: &str = "zcash_shielded.sqlite";
/// Réanalyse depuis la naissance fixe demandée (traitée par la
/// synchronisation suivante, qui tient la base).
const RESCAN_FILE: &str = "zcash_shielded_rescan";
/// Blocs téléchargés puis analysés par lot.
const SYNC_BATCH: u32 = 1_000;

type Db = WalletDb<rusqlite::Connection, MainNetwork, SystemClock, rand_core::OsRng>;

fn open(data_dir: &Path) -> Result<Db> {
    let mut db = WalletDb::for_path(data_dir.join(WALLET_FILE), MainNetwork, SystemClock, rand_core::OsRng).context("base Zcash protégée illisible")?;
    init_wallet_db(&mut db, None).map_err(|e| anyhow!("base Zcash protégée : migration impossible ({e})"))?;
    Ok(db)
}

/// Base pour une simple lecture (solde, historique, montant maximal) : `None`
/// si elle n'existe pas — jamais créée ici. Constaté le 07/10/2026 : un solde
/// demandé juste après l'effacement de la base (réinitialisation) la
/// recréait aussitôt, vide mais au nom du portefeuille suivant.
fn open_existing(data_dir: &Path) -> Result<Option<Db>> {
    if !data_dir.join(WALLET_FILE).exists() {
        return Ok(None);
    }
    open(data_dir).map(Some)
}

/// Oublie les adresses mémorisées (effacement de l'état, voir `seed_state`).
pub(crate) fn forget_known() {
    *KNOWN.lock().unwrap_or_else(|p| p.into_inner()) = None;
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
/// `future` abandonné dès qu'un effacement de l'état est demandé (voir
/// `seed_state`) : `None`. La base ouverte autour se referme aussitôt.
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

/// Naissance des comptes : état des arbres de commitments juste avant le
/// premier bloc à analyser — peu avant la création du portefeuille quand elle
/// est connue (voir `wallet_birthday`, ~75 s par bloc), sinon
/// `BIRTHDAY_HEIGHT`.
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
    let addresses = profiles.iter().map(|keys| Ok((address(&keys.1)?, keys.0))).collect::<Result<_>>()?;
    *KNOWN.lock().unwrap_or_else(|p| p.into_inner()) = Some((data_dir.to_path_buf(), addresses));
    let mut db = open(data_dir)?;
    // « Réanalyser depuis le début » : comptes supprimés puis recréés
    // ci-dessous depuis la naissance fixe (date de création oubliée).
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
        // Profil principal : son adresse t1 est déjà la première adresse
        // transparente du compte 0 ; les autres sont importées.
        if *profile != 0 {
            let pubkey = secp256k1::PublicKey::from_slice(t1_pubkey).context("clé publique Zcash invalide")?;
            db.import_standalone_transparent_pubkey(account.id(), pubkey).map_err(|e| anyhow!("adresse t1 : import impossible ({e})"))?;
        }
    }
    Ok(())
}

/// Supprime de la base les comptes d'un AUTRE portefeuille (autre seed :
/// réinitialisation puis création ou restauration sur cet appareil) — jamais
/// leur solde ni leur historique montrés pour celui-ci (les comptes sont
/// retrouvés par leur seul numéro, voir `find_account`). Appelé au
/// déverrouillage, avant tout affichage.
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

/// Demande une réanalyse complète (Paramètres) : à la prochaine
/// synchronisation, comptes recréés depuis la naissance fixe.
pub fn request_rescan(data_dir: &Path) -> Result<()> {
    std::fs::write(data_dir.join(RESCAN_FILE), b"1").context("réanalyse Zcash protégée : demande impossible")
}

/// Synchronise tous les comptes protégés jusqu'au bout de la chaîne.
pub fn sync(data_dir: &Path) -> Result<()> {
    let mut db = open(data_dir)?;
    if db.get_account_ids()?.is_empty() {
        return Ok(());
    }
    // Réinitialisation ou restauration demandée : passe abandonnée (voir
    // `unless_wiped`).
    runtime()?
        .block_on(unless_wiped(async {
            let mut client = client().await?;
            let cache = MemoryCache::default();
            zcash_client_backend::sync::run(&mut client, &MainNetwork, &cache, &mut db, SYNC_BATCH).await.map_err(|e| anyhow!("synchronisation Zcash protégée : {e}"))
        }))
        .map(|_| ())
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
    let Some(db) = open_existing(data_dir)? else { return Ok(ShieldedBalance::default()) };
    let Some(account) = find_account(&db, profile)? else { return Ok(ShieldedBalance::default()) };
    let Some(summary) = db.get_wallet_summary(ConfirmationsPolicy::default())? else { return Ok(ShieldedBalance::default()) };
    let Some(balances) = summary.account_balances().get(&account) else { return Ok(ShieldedBalance::default()) };
    // Since NU6.3 (block 3,428,143) the Orchard pool is sealed and every new
    // shielded note lands in Ironwood. Both pools are counted so that nothing
    // the wallet holds is ever left off the balance.
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

// --- Historique (carte « Zcash protégé ») ------------------------------------------

/// Dossier de la base et adresses protégées connues (adresse u1 → profil),
/// notés par `ensure_accounts` : la courbe du portefeuille lit solde et
/// historique par adresse (`balance_of_address`, `history_of_address`).
static KNOWN: Mutex<Option<(std::path::PathBuf, std::collections::BTreeMap<String, u32>)>> = Mutex::new(None);

/// Adresse protégée de l'app (u1… du réseau principal, récepteur Orchard).
pub fn parse_shielded_address(address: &str) -> Result<()> {
    anyhow::ensure!(address.trim().starts_with("u1"), "adresse Zcash protégée invalide (u1… attendue)");
    let parsed = check_recipient(address)?;
    anyhow::ensure!(parsed.can_receive_as(PoolType::ORCHARD), "adresse Zcash protégée invalide (u1… attendue)");
    Ok(())
}

/// Transactions du compte protégé du profil, la plus récente d'abord :
/// variation des seuls fonds Orchard (notes reçues moins notes dépensées) —
/// une protection apparaît reçue ici et envoyée sur la carte transparente ;
/// un envoi compte ses frais. Lu dans la base locale, aucun appel réseau.
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

/// Fonds protégés de l'adresse (dépensables et en attente) : courbe du
/// portefeuille.
pub fn balance_of_address(address: &str) -> Result<u64> {
    let (dir, profile) = known_profile(address)?;
    let b = balance(&dir, profile)?;
    Ok(b.spendable.saturating_add(b.pending))
}

pub fn history_of_address(address: &str) -> Result<Vec<history::TxEntry>> {
    let (dir, profile) = known_profile(address)?;
    history(&dir, profile)
}

// --- Dépenses : protéger les ZEC transparents, envoyer depuis Orchard -------------
// Comme ailleurs dans l'app : la transaction est d'abord PROPOSÉE (entrées,
// frais ZIP-317, monnaie, sans aucune clé de dépense), son résumé est
// confirmé dans une boîte native, puis CETTE proposition est signée avec la
// clé dérivée de la seed (mot de passe) et diffusée par lightwalletd.

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

/// Prouveur Sapling absent : l'app ne dépense ni ne crée jamais de note
/// Sapling (Orchard seul : destinataires transparents ou Orchard, monnaie vers
/// Orchard, vérifiés avant la proposition). Une dépense Sapling échouerait à la
/// préparation du circuit ; une sortie Sapling donnerait une preuve vide que
/// le réseau refuserait — jamais de fonds engagés.
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
        // Taille d'une preuve Groth16 (48 + 96 + 48 octets).
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
        // Taille d'une preuve Groth16 (48 + 96 + 48 octets).
        [0; 192]
    }
}

/// Résumé d'une dépense, montré dans la boîte de confirmation.
#[derive(Clone, Debug, PartialEq)]
pub struct SpendSummary {
    /// Montant qui arrive au destinataire (ou protégé), en zatoshis.
    pub amount: u64,
    /// Frais ZIP-317.
    pub fee: u64,
    /// Destinataire (adresse protégée du profil pour une protection).
    pub recipient: String,
}

/// Change, and shielded transparent funds, go to Ironwood: the Orchard pool
/// has been sealed since NU6.3 and refuses new value. (The library would
/// already redirect an Orchard fallback there; this states it outright.)
fn change_strategy() -> SingleOutputChangeStrategy<StandardFeeRule, Db> {
    SingleOutputChangeStrategy::new(StandardFeeRule::Zip317, None, ShieldedPool::Ironwood, DustOutputPolicy::default())
}

/// Clés de dépense du profil : clé unifiée du compte ZIP-32, et clé de
/// l'adresse t1 importée (profils autres que le principal).
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

/// Signe la proposition et diffuse ses transactions ; renvoie le dernier
/// identifiant.
fn create_and_broadcast<N: std::fmt::Display>(db: &mut Db, proposal: &Proposal<StandardFeeRule, N>, keys: &SpendingKeys) -> Result<String> {
    // Types d'erreur de sélection et de monnaie : propres à la proposition,
    // jamais produits par la construction.
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

/// Fonds insuffisants, en clair : messages de la bibliothèque relevés en
/// réel (« Insufficient balance (have 0, need 1010000 including fee) »,
/// « Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were
/// available »).
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

/// Protège les ZEC de l'adresse t1 `t1` du profil (vers son adresse
/// Orchard) : propose, fait confirmer le résumé (`confirm`), puis signe avec
/// la seed (`seed`) et diffuse. `Ok(None)` : confirmation refusée.
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

/// Le destinataire peut-il recevoir sans Sapling (transparent, ou adresse
/// unifiée avec un récepteur Orchard) ?
pub fn check_recipient(address: &str) -> Result<zcash_address::ZcashAddress> {
    let parsed = zcash_address::ZcashAddress::try_from_encoded(address.trim()).map_err(|_| anyhow!("adresse Zcash invalide"))?;
    anyhow::ensure!(parsed.can_receive_as(PoolType::ORCHARD) || parsed.can_receive_as(PoolType::TRANSPARENT), "adresse Zcash Sapling seule (zs…) pas prise en charge — demandez une adresse u1… ou t1…");
    let mainnet = ["u1", "t1", "t3", "tex1"].iter().any(|prefix| address.trim().starts_with(prefix));
    anyhow::ensure!(mainnet, "adresse Zcash d'un autre réseau (test) — refusée");
    Ok(parsed)
}

/// Envoie `amount` zatoshis depuis les fonds protégés du profil vers `to` :
/// mêmes étapes que `shield`.
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

/// Proposition d'envoi de TOUS les fonds protégés dépensables (frais déduits par
/// la sélection des entrées de la bibliothèque, seule à les connaître) et le
/// montant qu'elle envoie.
fn max_proposal(db: &mut Db, account: AccountUuid, recipient: zcash_address::ZcashAddress) -> Result<(Proposal<StandardFeeRule, zcash_client_sqlite::ReceivedNoteId>, u64)> {
    let proposal = propose_send_max_transfer::<_, _, _, std::convert::Infallible>(
        db,
        &MainNetwork,
        account,
        // Ironwood holds every note received since NU6.3; Orchard notes, if
        // any, may still leave their sealed pool through the turnstile.
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

/// Montant maximal envoyable depuis les fonds protégés du profil (vers `to`,
/// ou vers sa propre adresse pour une estimation : mêmes frais Orchard).
pub fn max_amount(data_dir: &Path, profile: u32, to: &str) -> Result<u64> {
    let recipient = check_recipient(to)?;
    let mut db = open_existing(data_dir)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    Ok(max_proposal(&mut db, account, recipient)?.1)
}

/// Envoie TOUS les fonds protégés dépensables du profil vers `to`, frais
/// déduits : mêmes étapes que `send`.
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
    use zcash_address::ToAddress as _;

    const SEED: [u8; 64] = [5u8; 64];

    /// Lectures sans base (portefeuille réinitialisé) : vides, et la base
    /// n'est pas recréée.
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

    /// Requête d'historique exécutée sur une base créée par la bibliothèque
    /// (schéma réel : tables et colonnes vérifiées) ; vide sans transaction.
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

    /// Since NU6.3 every shielded note lands in Ironwood: a note received,
    /// then spent with change, must show up in the history with the right net
    /// amounts. Rows are written straight into the library's real schema
    /// (foreign keys off: no account or block rows are needed for the query).
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

    /// Comptes d'un autre portefeuille (autre seed, même appareil) supprimés
    /// au déverrouillage ; ceux du portefeuille courant gardés. Hors ligne :
    /// naissance de compte fabriquée (aucun appel lightwalletd).
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

    /// Réel : portefeuille créé à l'instant → naissance des comptes ~3 jours
    /// avant le dernier bloc (au lieu de BIRTHDAY_HEIGHT) ; restauration →
    /// naissance fixe. `cargo test -- --ignored real_birthday --nocapture`
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
        // 3 jours de marge à ~75 s par bloc, jamais avant la naissance fixe.
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

    /// Destinataires : t1 et u1 Orchard acceptés ; Sapling seule refusée.
    #[test]
    fn recipients_without_sapling() {
        let u1 = address(&viewing_key(&SEED, 0).unwrap()).unwrap();
        assert!(check_recipient(&u1).is_ok());
        assert!(check_recipient("t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE").is_ok());
        // Adresse Sapling seule bien formée (encodage officiel, somme de contrôle valide).
        let sapling = zcash_address::ZcashAddress::from_sapling(zcash_protocol::consensus::NetworkType::Main, [7u8; 43]).encode();
        assert!(sapling.starts_with("zs1"));
        assert!(check_recipient(&sapling).unwrap_err().to_string().contains("Sapling"), "Sapling seule");
        let testnet = zcash_address::ZcashAddress::from_transparent_p2pkh(zcash_protocol::consensus::NetworkType::Test, [7u8; 20]).encode();
        assert!(check_recipient(&testnet).is_err(), "réseau de test");
        assert!(check_recipient("pas une adresse").is_err());
    }

    /// Fonds insuffisants : messages réels de la bibliothèque, en clair.
    #[test]
    fn insufficient_funds_in_plain_words() {
        let send = insufficient("Insufficient balance (have 0, need 1010000 including fee)").unwrap().to_string();
        assert_eq!(send, "ZEC insuffisants : 0.00000000 disponibles, 0.01010000 nécessaires (frais compris)");
        let shield = insufficient("Change output generation failed: Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were available.").unwrap().to_string();
        assert_eq!(shield, "ZEC insuffisants : 0.00000000 disponibles, 0.00010000 nécessaires (frais compris)");
        assert!(insufficient("autre erreur").is_none());
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
