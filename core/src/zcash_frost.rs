//! FROST 2-of-3 shielded Zcash account (ZCG grant #490, Milestone 1).
//!
//! The desktop app is member 1, the coordinator; a co-signer (a phone, or the
//! frost-zec test co-signer) holds member 2 and creates member 3, the backup.
//! Any two members sign. The protocol (pairing, key generation, signing
//! session and the co-signer's checks) is frost-zec's, specified in its
//! docs/spec.md; this module plugs it into the app's Zcash stack.
//!
//! - One account per network (Mainnet and Testnet), each in its own wallet
//!   database, imported from the group's viewing key as a view-only account:
//!   sync, balance and history work as for the app's own shielded account.
//! - The public part (viewing key, address, birthday) is stored in clear so the
//!   card shows without unlocking. The seat (share, `sk`, pairing keys) is
//!   encrypted with XChaCha20-Poly1305 under a key derived from the wallet's
//!   seed: it is protected like everything else, and `sk` is never under
//!   public-key encryption (zcash/zips#1432, Storage and transmission).
//! - A send is proposed, turned into a PCZT, signed with the co-signer over QR
//!   codes, then proved, extracted and broadcast here.

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frost_zec::channel::{Initiator, Pairing, PendingPairing};
use frost_zec::cosigning::{CoordinatorSession, Member, Reply};
use frost_zec::setup::{self as frost_setup, CoordinatorSetup, Done, Group, Round1, Round2};
use frost_zec::wire::{self, kind, Message, WireError};
use frost_zec::{check, keys, signing};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use zcash_client_backend::data_api::wallet::input_selection::{
    GreedyInputSelector, LockedInputPolicy, SpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, extract_and_store_transaction_from_pczt, propose_send_max_transfer,
    propose_transfer, ConfirmationsPolicy,
};
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, MaxSpendMode, WalletRead, WalletWrite,
};
use zcash_client_backend::fees::{
    zip317::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule,
};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec,
};
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::builder::BundlePadding;
use zcash_protocol::consensus::{Network, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;
use zeroize::{Zeroize, Zeroizing};

use crate::zcash_shielded::{ShieldedBalance, SpendSummary};

/// The two networks a FROST account can live on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Net {
    Main,
    Test,
}

impl Net {
    pub fn parse(name: &str) -> Result<Net> {
        match name {
            "main" | "mainnet" => Ok(Net::Main),
            "test" | "testnet" => Ok(Net::Test),
            _ => bail!("réseau Zcash inconnu : {name}"),
        }
    }

    fn params(self) -> Network {
        match self {
            Net::Main => Network::MainNetwork,
            Net::Test => Network::TestNetwork,
        }
    }

    fn network_type(self) -> NetworkType {
        match self {
            Net::Main => NetworkType::Main,
            Net::Test => NetworkType::Test,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Net::Main => "main",
            Net::Test => "test",
        }
    }

    fn servers(self) -> &'static [&'static str] {
        match self {
            Net::Main => &crate::zcash::SERVERS,
            Net::Test => &["https://testnet.zec.rocks:443"],
        }
    }

    fn file(self, data_dir: &Path, extension: &str) -> PathBuf {
        self.slot_file(data_dir, Slot::Current, extension)
    }

    fn slot_file(self, data_dir: &Path, slot: Slot, extension: &str) -> PathBuf {
        let suffix = match slot {
            Slot::Current => "",
            Slot::Old => "_old",
        };
        data_dir.join(format!("zcash_frost_{}{suffix}.{extension}", self.tag()))
    }
}

/// Which of a network's FROST accounts: the one the wallet uses, or the old
/// one a recovery sweeps to it (frost-zec spec § 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// The account the wallet uses.
    Current,
    /// An account recovered after a lost wallet, kept only until it is swept.
    Old,
}

type Db = WalletDb<rusqlite::Connection, Network, SystemClock, UnwrapErr<SysRng>>;

fn open(data_dir: &Path, net: Net) -> Result<Db> {
    open_slot(data_dir, net, Slot::Current)
}

fn open_slot(data_dir: &Path, net: Net, slot: Slot) -> Result<Db> {
    let mut db = WalletDb::for_path(
        net.slot_file(data_dir, slot, "sqlite"),
        net.params(),
        SystemClock,
        UnwrapErr(SysRng),
    )
    .context("base du compte FROST illisible")?;
    init_wallet_db(&mut db, None)
        .map_err(|e| anyhow!("base du compte FROST : migration impossible ({e})"))?;
    Ok(db)
}

fn the_account(db: &Db) -> Result<AccountUuid> {
    db.get_account_ids()?
        .first()
        .copied()
        .context("compte FROST pas encore prêt")
}

// --- Public part and encrypted seat ------------------------------------------------

/// What the card shows, stored in clear.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FrostAccount {
    pub network: Net,
    pub ufvk: String,
    pub address: String,
    pub birthday: u32,
    /// Whether the co-signer acknowledged the end of the setup (frost-zec spec
    /// § 4.1). The wallet has the account once it holds the co-signer's keys,
    /// but the co-signer only computes its own share and the backup's from the
    /// last message: if that message never reaches it, the account can never
    /// sign, and funds sent to it are lost. Until confirmed, the account is
    /// neither shown for receiving nor spent from. Accounts from before this
    /// field were all finished by hand, hence true when it is absent.
    #[serde(default = "confirmed_when_absent")]
    pub confirmed: bool,
}

fn confirmed_when_absent() -> bool {
    true
}

/// Shown when the address of an account the co-signer may not have finished is
/// asked for a send.
pub const NOT_CONFIRMED: &str =
    "création du compte FROST pas terminée : il manque le dernier message du co-signataire";

/// Shown when the co-signer acknowledges another group than this device's.
pub const DIFFERENT_GROUP: &str = "le co-signataire a terminé la création avec un autre groupe que ce portefeuille : n'utilisez pas ce compte, retirez-le et recommencez la création";

/// Shown for a message from a co-signer that speaks draft v0.1 of the protocol.
pub const OLD_COSIGNER: &str = "ce message vient d'un co-signataire d'une version précédente : mettez à jour le co-signataire (frost-zec)";

/// Records that the co-signer acknowledged the end of the setup (see
/// [`FrostAccount::confirmed`]). Written to a temporary file then renamed, so
/// the account file is never left half-written.
fn confirm(data_dir: &Path, net: Net) -> Result<FrostAccount> {
    let mut account = account(data_dir, net)?.context("aucun compte FROST sur ce réseau")?;
    account.confirmed = true;
    let path = net.file(data_dir, "json");
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(&account)?)
        .context("compte FROST : écriture impossible")?;
    std::fs::rename(&temporary, &path).context("compte FROST : écriture impossible")?;
    Ok(account)
}

/// The FROST account on `net`, if one was set up.
pub fn account(data_dir: &Path, net: Net) -> Result<Option<FrostAccount>> {
    account_slot(data_dir, net, Slot::Current)
}

/// The old account on `net` that a recovery is sweeping, if any.
pub fn old_account(data_dir: &Path, net: Net) -> Result<Option<FrostAccount>> {
    account_slot(data_dir, net, Slot::Old)
}

fn account_slot(data_dir: &Path, net: Net, slot: Slot) -> Result<Option<FrostAccount>> {
    match std::fs::read(net.slot_file(data_dir, slot, "json")) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("compte FROST illisible")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("compte FROST illisible"),
    }
}

/// Where removed accounts go, inside the data directory.
pub const REMOVED_DIR: &str = "zcash_frost_removed";

/// Takes the FROST account on `net` out of the app, so that a new one can be
/// set up on that network. Nothing is deleted: the account's files move to
/// `zcash_frost_removed/<network>-<seconds>/`, the seat still encrypted as
/// before, and moving them back gives the account, and any funds left on it,
/// back to this wallet. Returns that folder.
///
/// The database moves first, since an open one (a sync running) is what can
/// refuse to move, and the account file last: if a move fails, the account is
/// still listed, and removing it again moves what is left.
pub fn remove(data_dir: &Path, net: Net) -> Result<PathBuf> {
    remove_slot(data_dir, net, Slot::Current)
}

/// Sets the old account of a recovery aside, once it is swept, as [`remove`]
/// does: nothing is deleted.
pub fn remove_old(data_dir: &Path, net: Net) -> Result<PathBuf> {
    remove_slot(data_dir, net, Slot::Old)
}

fn remove_slot(data_dir: &Path, net: Net, slot: Slot) -> Result<PathBuf> {
    if account_slot(data_dir, net, slot)?.is_none() {
        bail!("aucun compte FROST sur ce réseau");
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let folder = data_dir.join(REMOVED_DIR).join(format!(
        "{}{}-{seconds}",
        net.tag(),
        if slot == Slot::Old { "-old" } else { "" }
    ));
    std::fs::create_dir_all(&folder).context("compte FROST : mise de côté impossible")?;
    for extension in ["sqlite", "sqlite-wal", "sqlite-shm", "seat", "json"] {
        let from = net.slot_file(data_dir, slot, extension);
        let to = folder.join(from.file_name().context("nom de fichier")?);
        match std::fs::rename(&from, &to) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e)
                    .context("compte FROST : mise de côté impossible, réessayez dans un instant");
            }
            _ => {}
        }
    }
    Ok(folder)
}

/// Member 1's secrets. Encrypted on disk, wiped from memory when dropped.
#[derive(Serialize, Deserialize)]
struct Seat {
    pairing: String,
    key_package: String,
    public_key_package: String,
    sk: String,
}

impl Drop for Seat {
    fn drop(&mut self) {
        self.pairing.zeroize();
        self.key_package.zeroize();
        self.sk.zeroize();
    }
}

const SEAT_VERSION: u8 = 1;
const SEAT_AAD: &[u8] = b"OpenPGP Wallet FROST seat v1";

fn seat_key(seed: &[u8], net: Net) -> Zeroizing<[u8; 32]> {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"OPGPWalletFrSeat")
        .to_state()
        .update(seed)
        .update(net.tag().as_bytes())
        .finalize();
    Zeroizing::new(digest.as_bytes().try_into().expect("32-byte hash"))
}

/// The associated data of a seat: its network, and whether it is an old
/// account's, so that neither file can stand in for another.
fn seat_aad(net: Net, slot: Slot) -> Vec<u8> {
    let mut aad: Vec<u8> = [SEAT_AAD, net.tag().as_bytes()].concat();
    if slot == Slot::Old {
        aad.extend_from_slice(b"-old");
    }
    aad
}

#[cfg(test)]
fn save_seat(data_dir: &Path, net: Net, seed: &[u8], seat: &Seat) -> Result<()> {
    save_seat_slot(data_dir, net, Slot::Current, seed, seat)
}

fn save_seat_slot(data_dir: &Path, net: Net, slot: Slot, seed: &[u8], seat: &Seat) -> Result<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(seat)?);
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("aléa indisponible : {e}"))?;
    let key = seat_key(seed, net);
    let aad = seat_aad(net, slot);
    let ciphertext = XChaCha20Poly1305::new(&(*key).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("chiffrement du siège FROST impossible"))?;
    let mut file = vec![SEAT_VERSION];
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);
    let path = net.slot_file(data_dir, slot, "seat");
    let temporary = path.with_extension("seat.tmp");
    std::fs::write(&temporary, file).context("siège FROST : écriture impossible")?;
    std::fs::rename(&temporary, &path).context("siège FROST : écriture impossible")?;
    Ok(())
}

/// Member 1, ready to sign, with the pairing to the co-signer.
fn load_seat(data_dir: &Path, net: Net, seed: &[u8]) -> Result<(Pairing, Member)> {
    load_seat_slot(data_dir, net, Slot::Current, seed)
}

fn load_seat_slot(data_dir: &Path, net: Net, slot: Slot, seed: &[u8]) -> Result<(Pairing, Member)> {
    let file =
        std::fs::read(net.slot_file(data_dir, slot, "seat")).context("siège FROST introuvable")?;
    if file.len() < 25 || file[0] != SEAT_VERSION {
        bail!("siège FROST illisible");
    }
    let nonce: [u8; 24] = file[1..25].try_into().expect("24 bytes");
    let key = seat_key(seed, net);
    let aad = seat_aad(net, slot);
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(&(*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &file[25..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow!("siège FROST : déchiffrement impossible (autre portefeuille ?)")
            })?,
    );
    let seat: Seat = serde_json::from_slice(&plaintext).context("siège FROST illisible")?;
    let pairing = Pairing::from_bytes(&Zeroizing::new(hex::decode(&seat.pairing)?))
        .map_err(|e| anyhow!("{e}"))?;
    let public_key_package = frost_zec::redpallas::keys::PublicKeyPackage::deserialize(
        &hex::decode(&seat.public_key_package)?,
    )
    .map_err(|e| anyhow!("siège FROST : {e}"))?;
    let key_package = frost_zec::redpallas::keys::KeyPackage::deserialize(&Zeroizing::new(
        hex::decode(&seat.key_package)?,
    ))
    .map_err(|e| anyhow!("siège FROST : {e}"))?;
    let sk_bytes = Zeroizing::new(hex::decode(&seat.sk)?);
    let sk: Zeroizing<[u8; 32]> = Zeroizing::new(
        sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("siège FROST : sk invalide"))?,
    );
    let ak = signing::group_ak(&public_key_package).map_err(|e| anyhow!("{e}"))?;
    let fvk = keys::derive(&sk, &ak).map_err(|e| anyhow!("{e}"))?.fvk;
    Ok((
        pairing,
        Member {
            key_package,
            public_key_package,
            fvk,
            network: net.network_type(),
        },
    ))
}

// --- lightwalletd -----------------------------------------------------------------

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("démarrage du client Zcash impossible")
}

async fn client(net: Net) -> Result<CompactTxStreamerClient<tonic::transport::Channel>> {
    let mut last = anyhow!("aucun serveur Zcash configuré");
    for server in net.servers() {
        let tls = tonic::transport::ClientTlsConfig::new().with_webpki_roots();
        let endpoint = tonic::transport::Channel::from_static(server)
            .tls_config(tls)?
            .connect_timeout(std::time::Duration::from_secs(10));
        match endpoint.connect().await {
            Ok(channel) => return Ok(CompactTxStreamerClient::new(channel)),
            Err(e) => last = anyhow!("serveur Zcash {server} injoignable : {e}"),
        }
    }
    Err(last)
}

/// The account birthday for a new FROST account on `net`: the tree state just
/// before the current tip (the group's address did not exist before, so nothing
/// earlier can belong to it). Fetched before the last setup step consumes
/// anything, with a few retries, so that a network error can simply be retried.
pub fn chain_birthday(net: Net) -> Result<AccountBirthday> {
    let mut last = anyhow!("serveur Zcash injoignable");
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        match runtime()?.block_on(async { birthday_now(&mut client(net).await?).await }) {
            Ok(birthday) => return Ok(birthday),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn birthday_now(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
) -> Result<AccountBirthday> {
    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(|e| anyhow!("hauteur de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner()
        .height;
    let state = client
        .get_tree_state(BlockId {
            height: tip.saturating_sub(1),
            hash: vec![],
        })
        .await
        .map_err(|e| anyhow!("état de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner();
    AccountBirthday::from_treestate(state, None)
        .map_err(|_| anyhow!("état de la chaîne Zcash invalide"))
}

/// Syncs the FROST account on `net` up to the tip (nothing if there is none).
pub fn sync(data_dir: &Path, net: Net) -> Result<()> {
    sync_slot(data_dir, net, Slot::Current)
}

/// Syncs the old account a recovery sweeps on `net` (nothing if there is none).
pub fn sync_old(data_dir: &Path, net: Net) -> Result<()> {
    sync_slot(data_dir, net, Slot::Old)
}

fn sync_slot(data_dir: &Path, net: Net, slot: Slot) -> Result<()> {
    if account_slot(data_dir, net, slot)?.is_none() {
        return Ok(());
    }
    let mut db = open_slot(data_dir, net, slot)?;
    runtime()?.block_on(async {
        let mut client = client(net).await?;
        let cache = crate::zcash_shielded::MemoryCache::default();
        let params = net.params();
        let pass = zcash_client_backend::sync::run(&mut client, &params, &cache, &mut db, 1_000);
        tokio::time::timeout(std::time::Duration::from_secs(300), pass)
            .await
            .map_err(|_| anyhow!("serveur Zcash trop lent : nouvel essai au prochain passage"))?
            .map_err(|e| anyhow!("synchronisation du compte FROST : {e}"))
    })
}

/// Balance of the FROST account on `net`.
pub fn balance(data_dir: &Path, net: Net) -> Result<ShieldedBalance> {
    balance_slot(data_dir, net, Slot::Current)
}

/// Balance of the old account a recovery sweeps on `net`.
pub fn balance_old(data_dir: &Path, net: Net) -> Result<ShieldedBalance> {
    balance_slot(data_dir, net, Slot::Old)
}

fn balance_slot(data_dir: &Path, net: Net, slot: Slot) -> Result<ShieldedBalance> {
    if account_slot(data_dir, net, slot)?.is_none() {
        return Ok(ShieldedBalance::default());
    }
    let db = open_slot(data_dir, net, slot)?;
    let account = the_account(&db)?;
    let Some(summary) = db.get_wallet_summary(ConfirmationsPolicy::default())? else {
        return Ok(ShieldedBalance::default());
    };
    let Some(balances) = summary.account_balances().get(&account) else {
        return Ok(ShieldedBalance::default());
    };
    let pools = [balances.orchard_balance(), balances.ironwood_balance()];
    let spendable: u64 = pools.iter().map(|b| u64::from(b.spendable_value())).sum();
    let total: u64 = pools.iter().map(|b| u64::from(b.total())).sum();
    Ok(ShieldedBalance {
        spendable,
        pending: total.saturating_sub(spendable),
        scanned_height: Some(u32::from(summary.fully_scanned_height())),
        chain_height: Some(u32::from(summary.chain_tip_height())),
        progress: None,
    })
}

// --- Setup: pairing and key generation, as the coordinator -------------------------

/// Where the coordinator is in the setup. Each step returns the QR payload to
/// show next.
pub enum SetupStep {
    /// pair-init is on screen; scan the co-signer's pair-response.
    AwaitingResponse { net: Net, initiator: Box<Initiator> },
    /// pair-confirm and round 1 are on screen; the user compares the code.
    AwaitingCode {
        net: Net,
        pending: PendingPairing,
        setup: CoordinatorSetup,
    },
    /// The code matched; scan the co-signer's keys.
    AwaitingKeys {
        net: Net,
        pairing: Pairing,
        setup: CoordinatorSetup,
    },
    /// The account is stored, unconfirmed, and the last message is on screen;
    /// scan the co-signer's acknowledgement. `digest` is this device's digest
    /// of the group, which the co-signer's must equal.
    AwaitingDone {
        net: Net,
        pairing: Pairing,
        digest: [u8; 32],
    },
}

impl SetupStep {
    pub fn net(&self) -> Net {
        match self {
            SetupStep::AwaitingResponse { net, .. }
            | SetupStep::AwaitingCode { net, .. }
            | SetupStep::AwaitingKeys { net, .. }
            | SetupStep::AwaitingDone { net, .. } => *net,
        }
    }
}

/// Starts the setup on `net`: the pair-init payload to show.
pub fn setup_start(data_dir: &Path, net: Net) -> Result<(SetupStep, Vec<u8>)> {
    if account(data_dir, net)?.is_some() {
        bail!("un compte FROST existe déjà sur ce réseau");
    }
    let (initiator, init) = Initiator::start(&mut UnwrapErr(SysRng));
    Ok((
        SetupStep::AwaitingResponse {
            net,
            initiator: Box::new(initiator),
        },
        wire::encode_payload(&[Message::pair_init(&init)]),
    ))
}

/// Takes the scanned pair-response; returns the payload to show (pair-confirm
/// with this device's round 1) and the code the user compares.
pub fn setup_response(step: SetupStep, payload: &[u8]) -> Result<(SetupStep, Vec<u8>, String)> {
    let SetupStep::AwaitingResponse { net, initiator } = step else {
        bail!("étape de configuration inattendue");
    };
    let messages = wire::decode_payload(payload)?;
    let response = messages.first().context("QR vide")?.to_pair_response()?;
    let (pending, confirm) = initiator.finish(&response)?;
    let (setup, round1) =
        CoordinatorSetup::start(net.network_type()).map_err(|e| anyhow!("{e}"))?;
    let shown = wire::encode_payload(&[
        Message::pair_confirm(&confirm),
        Message::seal_public(
            &pending,
            kind::DKG_ROUND1,
            b"dkg",
            &round1.to_bytes(),
            &mut UnwrapErr(SysRng),
        )?,
    ]);
    let code = pending.code();
    Ok((
        SetupStep::AwaitingCode {
            net,
            pending,
            setup,
        },
        shown,
        code,
    ))
}

/// The user confirmed that both devices show the same code.
pub fn setup_code_confirmed(step: SetupStep) -> Result<SetupStep> {
    let SetupStep::AwaitingCode {
        net,
        pending,
        setup,
    } = step
    else {
        bail!("étape de configuration inattendue");
    };
    Ok(SetupStep::AwaitingKeys {
        net,
        pairing: pending.confirm(),
        setup,
    })
}

/// Asks the user to compare the pairing code (`ask` shows it in a native
/// window and returns the answer), then confirms the step whose code was shown.
/// The step leaves `slot` before the question: while the window is open, a
/// compromised frontend could put another pairing, with an attacker's
/// co-signer, in the slot, and confirming whatever the slot holds afterwards
/// would pair the wallet with it. Returns false if the user refused.
pub fn confirm_code(
    slot: &Mutex<Option<SetupStep>>,
    ask: impl FnOnce(&str) -> bool,
) -> Result<bool> {
    let step = {
        let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(*guard, Some(SetupStep::AwaitingCode { .. })) {
            bail!("Aucune configuration en cours.");
        }
        guard.take().context("Aucune configuration en cours.")?
    };
    let code = match &step {
        SetupStep::AwaitingCode { pending, .. } => pending.code(),
        _ => bail!("étape de configuration inattendue"),
    };
    if !ask(&code) {
        return Ok(false);
    }
    let confirmed = setup_code_confirmed(step)?;
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(confirmed);
    Ok(true)
}

/// Takes the co-signer's keys; stores the account, unconfirmed, and returns
/// the last payload to show with the next step, which waits for the
/// co-signer's acknowledgement. `seed` encrypts the seat; `birthday` comes
/// from [`chain_birthday`].
pub fn setup_finish(
    data_dir: &Path,
    step: SetupStep,
    payload: &[u8],
    seed: &[u8],
    birthday: &AccountBirthday,
    recovery: Option<(&RecoveryInput, &AccountBirthday)>,
) -> Result<(Vec<u8>, SetupStep)> {
    let SetupStep::AwaitingKeys {
        net,
        pairing,
        setup,
    } = step
    else {
        bail!("étape de configuration inattendue");
    };
    // Checked again here: another setup may have finished since this one began.
    if account(data_dir, net)?.is_some() {
        bail!("un compte FROST existe déjà sur ce réseau");
    }
    let messages = wire::decode_payload(payload)?;
    // In a recovery, the co-signer's keys come after its description of the
    // old account, which member 3 must match before anything else is done.
    let restored = match recovery {
        Some((input, _)) => {
            if old_account(data_dir, net)?.is_some() {
                bail!(OLD_EXISTS);
            }
            if messages.len() != 3 {
                bail!("QR inattendu : la description de l'ancien compte et les clés du co-signataire étaient attendues");
            }
            let (_, info) = open_one_message(&messages[0], &pairing, kind::GROUP_INFO)?;
            let info =
                frost_zec::recovery::GroupInfo::from_bytes(&info).map_err(|e| anyhow!("{e}"))?;
            let restored = frost_zec::recovery::restore_member(
                &input.backup,
                &info,
                input.kit_ufvk.as_deref(),
            )
            .map_err(|e| anyhow!("sauvegarde du membre 3 : {e}"))?;
            if restored.member.network != net.network_type() {
                bail!("l'ancien compte est sur un autre réseau que celui choisi");
            }
            Some(restored)
        }
        None => {
            if messages.len() != 2 {
                bail!("QR inattendu : les clés du co-signataire étaient attendues");
            }
            None
        }
    };
    let keys_at = messages.len() - 2;
    let (_, theirs1) = messages[keys_at].open(&pairing, kind::DKG_ROUND1)?;
    let (_, theirs2) = messages[keys_at + 1].open(&pairing, kind::DKG_ROUND2)?;
    let (round2, group) = setup
        .finish(
            &Round1::from_bytes(&theirs1).map_err(|e| anyhow!("{e}"))?,
            &Round2::from_bytes(&theirs2).map_err(|e| anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow!("{e}"))?;
    let shown = wire::encode_payload(&[Message::seal(
        &pairing,
        kind::DKG_ROUND2,
        b"dkg",
        &round2.to_bytes(),
        &mut UnwrapErr(SysRng),
    )?]);
    let digest = group.digest().map_err(|e| anyhow!("{e}"))?;
    store(
        data_dir,
        net,
        Slot::Current,
        &pairing,
        &group,
        seed,
        birthday,
        false,
    )?;
    if let (Some(restored), Some((_, old_birthday))) = (restored, recovery) {
        // The old account answers through the new pairing; its member is
        // member 3, restored, encrypted under the seed like any seat.
        store(
            data_dir,
            net,
            Slot::Old,
            &pairing,
            &restored,
            seed,
            old_birthday,
            true,
        )?;
    }
    Ok((
        shown,
        SetupStep::AwaitingDone {
            net,
            pairing,
            digest,
        },
    ))
}

/// Opens one sealed message as `expected`, in the user's words when it is
/// another message (see [`open_one`]).
fn open_one_message(
    message: &Message,
    pairing: &Pairing,
    expected: u8,
) -> Result<(Vec<u8>, Vec<u8>)> {
    match message.open(pairing, expected) {
        Ok((session, plaintext)) => Ok((session, plaintext.to_vec())),
        Err(WireError::UnexpectedKind(48..=50)) => bail!(OLD_COSIGNER),
        Err(WireError::UnexpectedKind(_)) => {
            bail!(
                "ce n'est pas le message attendu du co-signataire : récupérez son dernier message"
            )
        }
        Err(e) => Err(e.into()),
    }
}

/// Opens the one sealed message of `payload` as `expected`, in the user's
/// words when it is another message (an older co-signer's, or the wrong one
/// pasted). Returns the session it is bound to and its plaintext.
fn open_one(pairing: &Pairing, payload: &[u8], expected: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let messages = wire::decode_payload(payload)?;
    let message = messages.first().context("QR vide")?;
    match message.open(pairing, expected) {
        Ok((session, plaintext)) => Ok((session, plaintext.to_vec())),
        Err(WireError::UnexpectedKind(48..=50)) => bail!(OLD_COSIGNER),
        Err(WireError::UnexpectedKind(_)) => {
            bail!(
                "ce n'est pas le message attendu du co-signataire : récupérez son dernier message"
            )
        }
        Err(e) => Err(e.into()),
    }
}

/// Takes the co-signer's acknowledgement (frost-zec spec § 4.1): once its
/// digest of the group equals this device's, the account is confirmed and its
/// address can be shown. The step is only read, so a wrong paste can be
/// followed by the right one.
pub fn setup_done(data_dir: &Path, step: &SetupStep, payload: &[u8]) -> Result<FrostAccount> {
    let SetupStep::AwaitingDone {
        net,
        pairing,
        digest,
    } = step
    else {
        bail!("étape de configuration inattendue");
    };
    let (_, bytes) = open_one(pairing, payload, kind::DKG_DONE)?;
    let done = Done::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?;
    if done.digest != *digest {
        bail!(DIFFERENT_GROUP);
    }
    confirm(data_dir, *net)
}

/// The co-signer's acknowledgement for an account left unconfirmed, after the
/// app was closed during the setup (the co-signer shows it again with
/// `frost-zec qr done`). `seed` unlocks the seat, from which the digest is
/// computed again.
pub fn setup_done_later(
    data_dir: &Path,
    net: Net,
    seed: &[u8],
    payload: &[u8],
) -> Result<FrostAccount> {
    let account = account(data_dir, net)?.context("aucun compte FROST sur ce réseau")?;
    if account.confirmed {
        return Ok(account);
    }
    let (pairing, member) = load_seat(data_dir, net, seed)?;
    // The viewing key comes from the encrypted seat; the account file is
    // public, and must agree with it.
    let ufvk = keys::ufvk(&member.fvk, member.network).map_err(|e| anyhow!("{e}"))?;
    if ufvk != account.ufvk {
        bail!("compte FROST incohérent : le fichier du compte ne correspond pas à son siège");
    }
    let (_, bytes) = open_one(&pairing, payload, kind::DKG_DONE)?;
    let done = Done::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?;
    frost_setup::check_done(&member, &ufvk, &done).map_err(|_| anyhow!(DIFFERENT_GROUP))?;
    confirm(data_dir, net)
}

#[allow(clippy::too_many_arguments)]
fn store(
    data_dir: &Path,
    net: Net,
    slot: Slot,
    pairing: &Pairing,
    group: &Group,
    seed: &[u8],
    birthday: &AccountBirthday,
    confirmed: bool,
) -> Result<FrostAccount> {
    let ufvk = UnifiedFullViewingKey::decode(&net.params(), &group.ufvk)
        .map_err(|e| anyhow!("clé de visualisation du groupe illisible : {e}"))?;
    // The account file is written last, so an account already in the database
    // was left there by a setup that failed before the end: nobody was shown
    // its address. The database only holds scan data; start from an empty one,
    // or the account picked later would be that one.
    if !open_slot(data_dir, net, slot)?
        .get_account_ids()?
        .is_empty()
    {
        for extension in ["sqlite", "sqlite-wal", "sqlite-shm"] {
            match std::fs::remove_file(net.slot_file(data_dir, slot, extension)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).context("base du compte FROST : nettoyage impossible");
                }
                _ => {}
            }
        }
    }
    let mut db = open_slot(data_dir, net, slot)?;
    db.import_account_ufvk(
        "FROST 2-of-3",
        &ufvk,
        birthday,
        AccountPurpose::ViewOnly,
        None,
    )
    .map_err(|e| anyhow!("compte FROST : import impossible ({e})"))?;
    save_seat_slot(
        data_dir,
        net,
        slot,
        seed,
        &Seat {
            pairing: hex::encode(pairing.to_bytes()),
            key_package: hex::encode(Zeroizing::new(
                group
                    .member
                    .key_package
                    .serialize()
                    .map_err(|e| anyhow!("{e}"))?,
            )),
            public_key_package: hex::encode(
                group
                    .member
                    .public_key_package
                    .serialize()
                    .map_err(|e| anyhow!("{e}"))?,
            ),
            sk: hex::encode(group.sk),
        },
    )?;
    let account = FrostAccount {
        network: net,
        ufvk: group.ufvk.clone(),
        address: group.address.clone(),
        birthday: u32::from(birthday.height()),
        // A new account waits for the co-signer's acknowledgement; an old
        // one being recovered existed already.
        confirmed,
    };
    std::fs::write(
        net.slot_file(data_dir, slot, "json"),
        serde_json::to_vec_pretty(&account)?,
    )
    .context("compte FROST : écriture impossible")?;
    Ok(account)
}

// --- Recovery: the wallet as a new coordinator (frost-zec spec § 7.2) --------------

/// Shown when a recovery would replace an old account still to sweep.
pub const OLD_EXISTS: &str =
    "un ancien compte à vider existe déjà sur ce réseau : videz-le et retirez-le d'abord";

/// Member 3's backup, read and checked before a recovery pairs with the
/// co-signer. Secret: wiped when dropped.
pub struct RecoveryInput {
    backup: Zeroizing<String>,
    kit_ufvk: Option<String>,
    birthday: Option<u32>,
}

impl std::fmt::Debug for RecoveryInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryInput")
            .field("backup", &"<redacted>")
            .field("kit_ufvk", &self.kit_ufvk.is_some())
            .field("birthday", &self.birthday)
            .finish()
    }
}

impl RecoveryInput {
    /// The old account's viewing key, when the backup file holds it.
    pub fn kit_ufvk(&self) -> Option<&str> {
        self.kit_ufvk.as_deref()
    }
}

/// The largest backup file a recovery reads.
pub const BACKUP_FILE_MAX: usize = 16 * 1024;

/// Reads member 3's backup: a backup file (frost-zec profile 1, binary or its
/// `zkfrost-file-1:` text) under its passphrase, or a bare member backup
/// string. The file is decrypted and checked here, so a wrong passphrase is
/// said before any pairing.
pub fn recovery_input(bytes: &[u8], passphrase: &str) -> Result<RecoveryInput> {
    if bytes.len() > BACKUP_FILE_MAX {
        bail!("fichier anormalement gros pour une sauvegarde du membre 3");
    }
    let text = std::str::from_utf8(bytes).ok().map(str::trim);
    if let Some(text) = text.filter(|t| t.starts_with("zkfrost1")) {
        frost_zec::backup::Backup::decode(text)
            .map_err(|e| anyhow!("sauvegarde du membre 3 : {e}"))?;
        return Ok(RecoveryInput {
            backup: Zeroizing::new(text.to_string()),
            kit_ufvk: None,
            birthday: None,
        });
    }
    let file = match text.filter(|t| t.starts_with(frost_zec::profiles::TEXT_PREFIX)) {
        Some(text) => frost_zec::profiles::from_text(text).map_err(|e| anyhow!("{e}"))?,
        None => bytes.to_vec(),
    };
    frost_zec::profiles::file_cost(&file).map_err(|e| anyhow!("sauvegarde du membre 3 : {e}"))?;
    if passphrase.is_empty() {
        bail!("entrez la phrase de passe du fichier de sauvegarde");
    }
    let contents = frost_zec::profiles::decrypt(&file, passphrase).map_err(|e| {
        if e.to_string().contains("wrong passphrase") {
            anyhow!("phrase de passe incorrecte, ou fichier de sauvegarde abîmé")
        } else {
            anyhow!("sauvegarde du membre 3 : {e}")
        }
    })?;
    Ok(RecoveryInput {
        backup: contents.backup.clone(),
        kit_ufvk: Some(contents.ufvk.clone()),
        birthday: contents.birthday,
    })
}

/// The old account's birthday for its scan: the backup's when it holds one,
/// otherwise Ironwood's activation, before which no FROST account existed.
/// Fetched before the setup's last step consumes anything.
pub fn recovery_birthday(net: Net, input: &RecoveryInput) -> Result<AccountBirthday> {
    let activation = net
        .params()
        .activation_height(NetworkUpgrade::Nu7)
        .map(u32::from)
        .context("hauteur d'activation d'Ironwood inconnue")?;
    let height = input.birthday.unwrap_or(activation).max(activation);
    runtime()?.block_on(async {
        let mut client = client(net).await?;
        let state = client
            .get_tree_state(BlockId {
                height: u64::from(height.saturating_sub(1)),
                hash: vec![],
            })
            .await
            .map_err(|e| anyhow!("état de la chaîne Zcash illisible : {}", e.message()))?
            .into_inner();
        AccountBirthday::from_treestate(state, None)
            .map_err(|_| anyhow!("état de la chaîne Zcash invalide"))
    })
}

/// Shown when the old account has nothing spendable yet: a sync in progress,
/// or funds still short of their confirmations.
pub const SWEEP_NOT_SPENDABLE: &str = "rien à transférer pour l'instant : les fonds de l'ancien compte ne sont pas encore dépensables (synchronisation en cours ou confirmations manquantes), réessayez dans un instant";

/// Whether an account is scanned up to the chain tip it knows and holds
/// nothing, spendable or pending. Before its first sync it is not "empty".
fn is_empty_and_synced(balance: &ShieldedBalance) -> bool {
    let synced = matches!(
        (balance.scanned_height, balance.chain_height),
        (Some(scanned), Some(tip)) if scanned >= tip
    );
    synced && balance.spendable == 0 && balance.pending == 0
}

/// Shown when the old account, synced to the chain tip, holds nothing.
pub const OLD_EMPTY: &str =
    "l'ancien compte est vide : rien à transférer, vous pouvez le retirer du portefeuille";

/// Shown when a sweep is asked for without an old account.
pub const NO_OLD_ACCOUNT: &str = "aucun ancien compte à vider sur ce réseau";

/// The sweep of a recovery: every spendable note of the old account, less the
/// fee, to the new account's address. Signed like any send, by the restored
/// member 3 and the co-signer.
pub fn sweep_prepare(data_dir: &Path, net: Net) -> Result<PreparedSend> {
    let current = account(data_dir, net)?.context("aucun compte FROST sur ce réseau")?;
    if !current.confirmed {
        bail!(NOT_CONFIRMED);
    }
    old_account(data_dir, net)?.context(NO_OLD_ACCOUNT)?;
    if is_empty_and_synced(&balance_old(data_dir, net)?) {
        bail!(OLD_EMPTY);
    }
    let recipient = zcash_address::ZcashAddress::try_from_encoded(&current.address)
        .map_err(|_| anyhow!("adresse du nouveau compte illisible"))?;
    let memo = MemoBytes::from_bytes(b"FROST recovery").expect("a short memo");
    let mut db = open_slot(data_dir, net, Slot::Old)?;
    let account = the_account(&db)?;
    let proposal = propose_send_max_transfer::<_, _, _, std::convert::Infallible>(
        &mut db,
        &net.params(),
        account,
        &[ShieldedPool::Ironwood],
        &StandardFeeRule::Zip317,
        recipient,
        Some(memo),
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::default(),
        &LockedInputPolicy::Exclude,
        None,
    )
    .map_err(|e| {
        let detail = e.to_string();
        if detail.contains("Must scan blocks first") {
            anyhow!("{NOT_SYNCED}")
        } else if detail.contains("Insufficient balance") {
            anyhow!("{SWEEP_NOT_SPENDABLE}")
        } else {
            anyhow!("transfert de l'ancien compte impossible ({detail})")
        }
    })?;
    let fee = proposal_fee(&proposal);
    let amount: u64 = proposal
        .steps()
        .iter()
        .flat_map(|step| step.transaction_request().payments().values())
        .filter_map(|payment| payment.amount())
        .map(u64::from)
        .sum();
    let pczt = create_pczt_from_proposal::<
        _,
        _,
        std::convert::Infallible,
        _,
        std::convert::Infallible,
        _,
    >(
        &mut db,
        &net.params(),
        &SystemClock,
        &mut UnwrapErr(SysRng),
        account,
        OvkPolicy::Sender,
        &proposal,
        None,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| anyhow!("PCZT impossible ({e})"))?;
    Ok(PreparedSend {
        net,
        slot: Slot::Old,
        pczt: pczt.serialize().map_err(|e| anyhow!("PCZT : {e:?}"))?,
        summary: SpendSummary {
            amount,
            fee,
            recipient: current.address,
        },
    })
}

// --- Sending ------------------------------------------------------------------------

/// Shown when a send is tried before the account was ever synced.
pub const NOT_SYNCED: &str = "compte FROST pas encore synchronisé : synchronisez-le d'abord";

/// A send waiting for the co-signer: the PCZT and what the user confirmed.
pub struct PreparedSend {
    pub net: Net,
    /// The account it spends from: the current one, or an old one swept.
    pub slot: Slot,
    pub pczt: Vec<u8>,
    pub summary: SpendSummary,
}

fn change_strategy() -> SingleOutputChangeStrategy<StandardFeeRule, Db> {
    SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    )
}

fn proposal_fee<N>(proposal: &Proposal<StandardFeeRule, N>) -> u64 {
    proposal
        .steps()
        .iter()
        .map(|step| u64::from(step.balance().fee_required()))
        .sum()
}

/// A recipient the co-signer would refuse: it signs only transactions whose
/// every part it decodes, which here means Ironwood alone, so the payment must
/// go to a unified address with an Orchard receiver (Ironwood notes are paid to
/// Orchard receivers).
pub const RECIPIENT_TRANSPARENT: &str =
    "adresse transparente : le co-signataire n'accepte que les adresses protégées unifiées";
pub const RECIPIENT_SAPLING: &str =
    "adresse Sapling : le co-signataire n'accepte que les adresses protégées unifiées";
pub const RECIPIENT_NO_ORCHARD: &str =
    "adresse unifiée sans récepteur Orchard : le co-signataire ne pourrait pas la payer";

/// Checks a recipient before anything is built: a valid address, on `net`,
/// that a FROST account can pay. Shown live under the field as it is typed,
/// and checked again here before every send.
pub fn check_recipient(net: Net, to: &str) -> Result<()> {
    let to = to.trim();
    zcash_address::ZcashAddress::try_from_encoded(to)
        .map_err(|_| anyhow!("adresse Zcash invalide"))?;
    match zcash_keys::address::Address::decode(&net.params(), to) {
        None => bail!("cette adresse est sur un autre réseau Zcash"),
        Some(zcash_keys::address::Address::Unified(address)) if address.has_orchard() => Ok(()),
        Some(zcash_keys::address::Address::Unified(_)) => bail!(RECIPIENT_NO_ORCHARD),
        Some(
            zcash_keys::address::Address::Transparent(_) | zcash_keys::address::Address::Tex(_),
        ) => bail!(RECIPIENT_TRANSPARENT),
        Some(_) => bail!(RECIPIENT_SAPLING),
    }
}

/// Proposes a payment from the FROST account and turns it into a PCZT.
pub fn send_prepare(
    data_dir: &Path,
    net: Net,
    to: &str,
    amount: u64,
    memo: Option<&str>,
) -> Result<PreparedSend> {
    if !account(data_dir, net)?
        .context("aucun compte FROST sur ce réseau")?
        .confirmed
    {
        bail!(NOT_CONFIRMED);
    }
    check_recipient(net, to)?;
    let recipient = zcash_address::ZcashAddress::try_from_encoded(to.trim())
        .map_err(|_| anyhow!("adresse Zcash invalide"))?;
    let memo = memo
        .filter(|text| !text.is_empty())
        .map(|text| {
            MemoBytes::from_bytes(text.as_bytes())
                .map_err(|_| anyhow!("mémo trop long (512 octets au plus)"))
        })
        .transpose()?;
    let value = Zatoshis::from_u64(amount).map_err(|_| anyhow!("montant hors limites"))?;
    let payment = Payment::new(recipient, Some(value), memo, None, None, vec![])
        .map_err(|e| anyhow!("paiement invalide ({e:?})"))?;
    let request = TransactionRequest::new(vec![payment])
        .map_err(|e| anyhow!("demande de paiement invalide ({e:?})"))?;
    let mut db = open(data_dir, net)?;
    let account = the_account(&db)?;
    let proposal = propose_transfer::<_, _, _, _, std::convert::Infallible>(
        &mut db,
        &net.params(),
        account,
        &GreedyInputSelector::new(),
        &change_strategy(),
        request,
        ConfirmationsPolicy::default(),
        &SpendPolicy::default(),
        None,
        None,
    )
    .map_err(|e| {
        let detail = e.to_string();
        if detail.contains("Must scan blocks first") {
            anyhow!("{NOT_SYNCED}")
        } else {
            anyhow!("envoi FROST impossible ({detail})")
        }
    })?;
    let fee = proposal_fee(&proposal);
    // Payments use the group's outgoing viewing key, which the co-signer needs
    // to read them back (frost-zec docs/spec.md § 6).
    let pczt = create_pczt_from_proposal::<
        _,
        _,
        std::convert::Infallible,
        _,
        std::convert::Infallible,
        _,
    >(
        &mut db,
        &net.params(),
        &SystemClock,
        &mut UnwrapErr(SysRng),
        account,
        OvkPolicy::Sender,
        &proposal,
        None,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| anyhow!("PCZT impossible ({e})"))?;
    Ok(PreparedSend {
        net,
        slot: Slot::Current,
        pczt: pczt.serialize().map_err(|e| anyhow!("PCZT : {e:?}"))?,
        summary: SpendSummary {
            amount,
            fee,
            recipient: to.trim().to_string(),
        },
    })
}

/// A signing session waiting for the co-signer's reply.
pub struct PendingSignature {
    net: Net,
    slot: Slot,
    pairing: Pairing,
    session: CoordinatorSession,
}

/// Opens a signing session for a confirmed send: returns the request payload
/// to show and the coordinator's own check of the PCZT. `seed` unlocks the
/// seat. Every call draws fresh nonces, so each request is a new session.
pub fn send_request(
    data_dir: &Path,
    prepared: &PreparedSend,
    seed: &[u8],
) -> Result<(PendingSignature, Vec<u8>, check::Report)> {
    let (pairing, member) = load_seat_slot(data_dir, prepared.net, prepared.slot, seed)?;
    let (session, request, report) =
        CoordinatorSession::request(&member, &prepared.pczt, &mut UnwrapErr(SysRng))
            .map_err(|e| anyhow!("{e}"))?;
    let shown = wire::encode_payload(&[Message::seal(
        &pairing,
        kind::SIGN_REQUEST,
        &request.session,
        &request.to_bytes().map_err(|e| anyhow!("{e}"))?,
        &mut UnwrapErr(SysRng),
    )?]);
    Ok((
        PendingSignature {
            net: prepared.net,
            slot: prepared.slot,
            pairing,
            session,
        },
        shown,
        report,
    ))
}

/// Reads the co-signer's reply to this session without using it: a wrong
/// paste, or a reply to an earlier request, leaves the session as it was.
pub fn read_reply(pending: &PendingSignature, payload: &[u8]) -> Result<Reply> {
    let (bound, bytes) = open_one(&pending.pairing, payload, kind::SIGN_REPLY)?;
    let reply = Reply::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?;
    let session = pending.session.session();
    if bound != session || reply.session() != session {
        bail!("cette réponse du co-signataire est celle d'une autre demande de signature");
    }
    Ok(reply)
}

/// Takes the co-signer's reply (from [`read_reply`]): signs this member's
/// part, aggregates, proves, stores and broadcasts. Consumes the session and
/// its nonces, whatever happens. Returns the transaction id.
pub fn send_finish(data_dir: &Path, pending: PendingSignature, reply: &Reply) -> Result<String> {
    let signed = pending.session.finish(reply).map_err(|e| anyhow!("{e}"))?;
    let proved = prove(signed)?;
    let mut db = open_slot(data_dir, pending.net, pending.slot)?;
    let txid = extract_and_store_transaction_from_pczt::<_, ()>(
        &mut db,
        &SystemClock,
        &mut UnwrapErr(SysRng),
        proved,
        None,
        None,
    )
    .map_err(|e| anyhow!("transaction FROST : extraction impossible ({e:?})"))?;
    let tx = db
        .get_transaction(txid)?
        .context("transaction FROST introuvable après sa construction")?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .context("sérialisation de la transaction impossible")?;
    broadcast(pending.net, raw)?;
    Ok(txid.to_string())
}

/// Orchard-protocol proofs for the Ironwood bundle, with the circuit of the
/// PCZT's consensus branch.
fn prove(pczt: pczt::Pczt) -> Result<pczt::Pczt> {
    let branch =
        zcash_protocol::consensus::BranchId::try_from(*pczt.global().consensus_branch_id())
            .map_err(|_| anyhow!("PCZT : branche de consensus inconnue"))?;
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_ironwood_proof() || prover.requires_orchard_proof() {
        let version =
            zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
                branch,
                orchard::ValuePool::Orchard,
            )
            .context("PCZT : branche sans Orchard")?;
        let key = orchard::circuit::ProvingKey::build(version.circuit_version());
        if prover.requires_orchard_proof() {
            prover = prover
                .create_orchard_proof(UnwrapErr(SysRng), &key)
                .map_err(|e| anyhow!("preuve Orchard impossible ({e:?})"))?;
        }
        if prover.requires_ironwood_proof() {
            prover = prover
                .create_ironwood_proof(UnwrapErr(SysRng), &key)
                .map_err(|e| anyhow!("preuve Ironwood impossible ({e:?})"))?;
        }
    }
    Ok(prover.finish())
}

fn broadcast(net: Net, raw: Vec<u8>) -> Result<()> {
    runtime()?.block_on(async {
        let mut client = client(net).await?;
        let response = client
            .send_transaction(zcash_client_backend::proto::service::RawTransaction {
                data: raw,
                height: 0,
            })
            .await
            .map_err(|e| anyhow!("diffusion impossible : {}", e.message()))?
            .into_inner();
        if response.error_code != 0 {
            bail!(
                "transaction refusée par le serveur : {}",
                response.error_message
            );
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unified_addresses_with_an_orchard_receiver_can_be_paid() {
        use zcash_address::ToAddress;
        // A testnet FROST group's address (frost-zec keygen): unified, Orchard.
        let unified = "utest14z46743rm6rdlnev2za09q5vftu7gn5phg9nfk9yjxgmgtmrfc8w0r8gp328tl63pdaee4th50h6qjjkqxnaf63m0dap4a2ytu2kaess";
        assert!(check_recipient(Net::Test, unified).is_ok());
        assert!(check_recipient(Net::Test, &format!("  {unified}\n")).is_ok());
        assert_eq!(
            check_recipient(Net::Main, unified).unwrap_err().to_string(),
            "cette adresse est sur un autre réseau Zcash"
        );
        let transparent =
            zcash_address::ZcashAddress::from_transparent_p2pkh(NetworkType::Test, [7; 20])
                .encode();
        assert_eq!(
            check_recipient(Net::Test, &transparent)
                .unwrap_err()
                .to_string(),
            RECIPIENT_TRANSPARENT
        );
        let tex = zcash_address::ZcashAddress::from_tex(NetworkType::Test, [7; 20]).encode();
        assert_eq!(
            check_recipient(Net::Test, &tex).unwrap_err().to_string(),
            RECIPIENT_TRANSPARENT
        );
        assert_eq!(
            check_recipient(Net::Test, "utest1notanaddress")
                .unwrap_err()
                .to_string(),
            "adresse Zcash invalide"
        );
    }

    #[test]
    fn an_account_is_spent_from_only_once_its_address_is_confirmed() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-confirm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // An account from before the field: finished by hand, so confirmed.
        std::fs::write(
            Net::Test.file(&dir, "json"),
            br#"{"network":"test","ufvk":"uviewtest1-x","address":"utest1-x","birthday":1}"#,
        )
        .unwrap();
        assert!(account(&dir, Net::Test).unwrap().unwrap().confirmed);

        // A new account starts unconfirmed: no send, whatever it is asked.
        let fresh = FrostAccount {
            network: Net::Main,
            ufvk: "uview1-y".into(),
            address: "u1-y".into(),
            birthday: 2,
            confirmed: false,
        };
        std::fs::write(
            Net::Main.file(&dir, "json"),
            serde_json::to_vec(&fresh).unwrap(),
        )
        .unwrap();
        let refused = send_prepare(&dir, Net::Main, "u1-anything", 1_000, None)
            .err()
            .unwrap();
        assert_eq!(refused.to_string(), NOT_CONFIRMED);

        let confirmed = confirm(&dir, Net::Main).unwrap();
        assert!(confirmed.confirmed);
        assert_eq!(
            account(&dir, Net::Main).unwrap(),
            Some(FrostAccount {
                confirmed: true,
                ..fresh
            })
        );
        assert!(!Net::Main.file(&dir, "json.tmp").exists());
        // Past the check, the send now fails on the address instead.
        let after = send_prepare(&dir, Net::Main, "u1-anything", 1_000, None)
            .err()
            .unwrap();
        assert_ne!(after.to_string(), NOT_CONFIRMED);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_removed_account_is_set_aside_not_deleted() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-remove-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let main = FrostAccount {
            network: Net::Main,
            ufvk: "uview1-main".into(),
            address: "u1-main".into(),
            birthday: 3_500_000,
            confirmed: true,
        };
        let test = FrostAccount {
            network: Net::Test,
            ..main.clone()
        };
        std::fs::write(
            Net::Main.file(&dir, "json"),
            serde_json::to_vec(&main).unwrap(),
        )
        .unwrap();
        std::fs::write(Net::Main.file(&dir, "seat"), b"sealed seat").unwrap();
        std::fs::write(Net::Main.file(&dir, "sqlite"), b"scan data").unwrap();
        std::fs::write(
            Net::Test.file(&dir, "json"),
            serde_json::to_vec(&test).unwrap(),
        )
        .unwrap();

        let folder = remove(&dir, Net::Main).unwrap();

        assert!(account(&dir, Net::Main).unwrap().is_none());
        assert_eq!(account(&dir, Net::Test).unwrap(), Some(test));
        for (name, bytes) in [
            ("zcash_frost_main.seat", &b"sealed seat"[..]),
            ("zcash_frost_main.sqlite", &b"scan data"[..]),
        ] {
            assert_eq!(std::fs::read(folder.join(name)).unwrap(), bytes);
            assert!(!dir.join(name).exists());
        }
        let kept: FrostAccount =
            serde_json::from_slice(&std::fs::read(folder.join("zcash_frost_main.json")).unwrap())
                .unwrap();
        assert_eq!(kept, main);
        assert!(remove(&dir, Net::Main).is_err(), "nothing left to remove");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_seat_round_trips_only_with_its_seed_and_network() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-seat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (key_packages, public_key_package) = frost_zec::dkg::run(3, 2).unwrap();
        let key_package = key_packages.into_values().next().unwrap();
        let sk = [7u8; 32];
        let pairing_bytes = {
            let mut rng = UnwrapErr(SysRng);
            let (i, init) = Initiator::start(&mut rng);
            let (r, response) = frost_zec::channel::Responder::respond(&init, &mut rng).unwrap();
            let (pending, confirm) = i.finish(&response).unwrap();
            drop(r.finish(&confirm).unwrap());
            pending.confirm().to_bytes()
        };
        let seat = Seat {
            pairing: hex::encode(&pairing_bytes),
            key_package: hex::encode(key_package.serialize().unwrap()),
            public_key_package: hex::encode(public_key_package.serialize().unwrap()),
            sk: hex::encode(sk),
        };
        let seed = [1u8; 64];
        save_seat(&dir, Net::Test, &seed, &seat).unwrap();
        let (pairing, member) = load_seat(&dir, Net::Test, &seed).unwrap();
        assert_eq!(pairing.to_bytes(), pairing_bytes);
        assert_eq!(member.network, NetworkType::Test);
        // Another seed, or the file moved to the other network, cannot open it.
        assert!(load_seat(&dir, Net::Test, &[2u8; 64]).is_err());
        std::fs::rename(Net::Test.file(&dir, "seat"), Net::Main.file(&dir, "seat")).unwrap();
        assert!(load_seat(&dir, Net::Main, &seed).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A setup up to the code comparison, against a co-signer's pair-response.
    fn awaiting_code(dir: &Path) -> SetupStep {
        let (step, shown) = setup_start(dir, Net::Test).unwrap();
        let init = wire::decode_payload(&shown).unwrap()[0]
            .to_pair_init()
            .unwrap();
        let (_, response) =
            frost_zec::channel::Responder::respond(&init, &mut UnwrapErr(SysRng)).unwrap();
        let payload = wire::encode_payload(&[Message::pair_response(&response)]);
        setup_response(step, &payload).unwrap().0
    }

    fn pairing_id(step: &SetupStep) -> [u8; 16] {
        match step {
            SetupStep::AwaitingCode { pending, .. } => pending.id(),
            SetupStep::AwaitingKeys { pairing, .. } | SetupStep::AwaitingDone { pairing, .. } => {
                pairing.id()
            }
            SetupStep::AwaitingResponse { .. } => panic!("no pairing yet"),
        }
    }

    #[test]
    fn the_pairing_confirmed_is_the_one_whose_code_was_shown() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-code-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let shown = awaiting_code(&dir);
        let shown_id = pairing_id(&shown);
        let slot = Mutex::new(Some(shown));
        // While the native window is open, a compromised frontend puts another
        // pairing in the slot; the user confirms the code they were shown.
        let confirmed = confirm_code(&slot, |_code| {
            *slot.lock().unwrap() = Some(awaiting_code(&dir));
            true
        })
        .unwrap();
        assert!(confirmed);
        let step = slot.lock().unwrap().take().unwrap();
        assert!(matches!(step, SetupStep::AwaitingKeys { .. }));
        assert_eq!(pairing_id(&step), shown_id);

        // Refused: nothing is confirmed. No setup waiting: an error.
        let slot = Mutex::new(Some(awaiting_code(&dir)));
        assert!(!confirm_code(&slot, |_| false).unwrap());
        assert!(slot.lock().unwrap().is_none());
        assert!(confirm_code(&slot, |_| true).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The co-signer's side of a whole setup, played by frost-zec's own code
    /// against this module, up to the stored account waiting for dkg-done.
    struct Cosigner {
        pairing: Pairing,
        group: Group,
    }

    fn setup_until_done(dir: &Path) -> (SetupStep, Cosigner) {
        setup_with(dir, None).unwrap()
    }

    fn test_birthday(height: u32) -> AccountBirthday {
        use zcash_client_backend::data_api::chain::ChainState;
        AccountBirthday::from_parts(
            ChainState::empty(
                zcash_protocol::consensus::BlockHeight::from_u32(height - 1),
                zcash_primitives::block::BlockHash([0; 32]),
            ),
            None,
        )
    }

    /// A setup to the stored account waiting for dkg-done; with `recovery`,
    /// the co-signer first describes the old group (`info`) and the wallet
    /// restores member 3 from `input`.
    fn setup_with(
        dir: &Path,
        recovery: Option<(&RecoveryInput, frost_zec::recovery::GroupInfo)>,
    ) -> Result<(SetupStep, Cosigner)> {
        use frost_zec::setup::CosignerSetup;
        let mut rng = UnwrapErr(SysRng);
        let (step, shown) = setup_start(dir, Net::Test).unwrap();
        let init = wire::decode_payload(&shown).unwrap()[0]
            .to_pair_init()
            .unwrap();
        let (responder, response) =
            frost_zec::channel::Responder::respond(&init, &mut rng).unwrap();
        let (step, shown, _) = setup_response(
            step,
            &wire::encode_payload(&[Message::pair_response(&response)]),
        )
        .unwrap();
        let step = setup_code_confirmed(step).unwrap();
        let messages = wire::decode_payload(&shown).unwrap();
        let pairing = responder
            .finish(&messages[0].to_pair_confirm().unwrap())
            .unwrap()
            .confirm();
        let (_, theirs1) = messages[1].open(&pairing, kind::DKG_ROUND1).unwrap();
        let (cosigner_setup, round1, round2) =
            CosignerSetup::respond(NetworkType::Test, &Round1::from_bytes(&theirs1).unwrap())
                .unwrap();
        let mut sealed = Vec::new();
        if let Some((_, info)) = &recovery {
            sealed.push(
                Message::seal(
                    &pairing,
                    kind::GROUP_INFO,
                    b"dkg",
                    &info.to_bytes().unwrap(),
                    &mut rng,
                )
                .unwrap(),
            );
        }
        sealed.extend([
            Message::seal(
                &pairing,
                kind::DKG_ROUND1,
                b"dkg",
                &round1.to_bytes(),
                &mut rng,
            )
            .unwrap(),
            Message::seal(
                &pairing,
                kind::DKG_ROUND2,
                b"dkg",
                &round2.to_bytes(),
                &mut rng,
            )
            .unwrap(),
        ]);
        let keys = wire::encode_payload(&sealed);
        let birthday = test_birthday(4_600_001);
        let old_birthday = test_birthday(4_465_026);
        let (last, step) = setup_finish(
            dir,
            step,
            &keys,
            &[3u8; 64],
            &birthday,
            recovery.as_ref().map(|(input, _)| (*input, &old_birthday)),
        )?;
        let (_, theirs2) = wire::decode_payload(&last).unwrap()[0]
            .open(&pairing, kind::DKG_ROUND2)
            .unwrap();
        let (group, backup) = cosigner_setup
            .finish(&Round2::from_bytes(&theirs2).unwrap())
            .unwrap();
        frost_setup::check_backup(&backup.backup_string().unwrap(), &group).unwrap();
        Ok((step, Cosigner { pairing, group }))
    }

    /// An old group, from frost-zec's own key generation: its co-signer's
    /// member 2 and member 3.
    fn old_group() -> (Group, Group) {
        use frost_zec::setup::{CoordinatorSetup, CosignerSetup};
        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let (cosigner, s1, s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        let (c2, _) = coordinator.finish(&s1, &s2).unwrap();
        cosigner.finish(&c2).unwrap()
    }

    #[test]
    fn a_lost_wallet_is_recovered_from_member_3() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-recover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (two, three) = old_group();
        let passphrase = "one two three four five six seven eight nine ten eleven twelve";
        let file = frost_zec::profiles::encrypt(
            &frost_zec::profiles::Contents {
                backup: Zeroizing::new(three.backup_string().unwrap()),
                ufvk: two.ufvk.clone(),
                birthday: Some(4_500_000),
                label: None,
            },
            passphrase,
        )
        .unwrap();
        assert!(recovery_input(&file, "wrong")
            .unwrap_err()
            .to_string()
            .contains("phrase de passe"));
        let input = recovery_input(&file, passphrase).unwrap();
        assert_eq!(input.kit_ufvk(), Some(two.ufvk.as_str()));
        // The text form and the bare string are read too.
        recovery_input(frost_zec::profiles::to_text(&file).as_bytes(), passphrase).unwrap();
        recovery_input(three.backup_string().unwrap().as_bytes(), "").unwrap();

        let info = frost_zec::recovery::GroupInfo::new(&two.member, &two.ufvk);
        let (step, cosigner) = setup_with(&dir, Some((&input, info))).unwrap();
        // The old account is stored, member 3 restored in its seat.
        let old = old_account(&dir, Net::Test).unwrap().unwrap();
        assert_eq!(old.address, two.address);
        assert!(old.confirmed);
        let (_, member) = load_seat_slot(&dir, Net::Test, Slot::Old, &[3u8; 64]).unwrap();
        assert_eq!(member.id(), three.member.id());
        assert_eq!(member.fvk, two.member.fvk);
        // The current seat cannot be read as the old one, nor the reverse.
        std::fs::copy(
            Net::Test.slot_file(&dir, Slot::Old, "seat"),
            dir.join("old.seat"),
        )
        .unwrap();
        std::fs::copy(
            Net::Test.slot_file(&dir, Slot::Current, "seat"),
            Net::Test.slot_file(&dir, Slot::Old, "seat"),
        )
        .unwrap();
        assert!(load_seat_slot(&dir, Net::Test, Slot::Old, &[3u8; 64]).is_err());
        // The new account, confirmed by the acknowledgement as any setup.
        let confirmed =
            setup_done(&dir, &step, &acknowledgement(&cosigner, &cosigner.group)).unwrap();
        assert!(confirmed.confirmed);
        assert_ne!(confirmed.address, old.address);
        // A second recovery waits until the old account is swept and removed.
        assert!(remove_old(&dir, Net::Test).is_ok());
        assert!(old_account(&dir, Net::Test).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_account_is_empty_only_once_synced() {
        let balance = |spendable, pending, scanned, tip| ShieldedBalance {
            spendable,
            pending,
            scanned_height: scanned,
            chain_height: tip,
            progress: None,
        };
        assert!(is_empty_and_synced(&balance(0, 0, Some(100), Some(100))));
        // Not synced yet: its funds may still be found.
        assert!(!is_empty_and_synced(&balance(0, 0, None, None)));
        assert!(!is_empty_and_synced(&balance(0, 0, Some(90), Some(100))));
        // Funds still to confirm, or spendable: not empty.
        assert!(!is_empty_and_synced(&balance(0, 1, Some(100), Some(100))));
        assert!(!is_empty_and_synced(&balance(1, 0, Some(100), Some(100))));
    }

    #[test]
    fn a_cosigner_describing_another_group_is_refused() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-lying-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (two, three) = old_group();
        let (other, _) = old_group();
        let file = frost_zec::profiles::encrypt(
            &frost_zec::profiles::Contents {
                backup: Zeroizing::new(three.backup_string().unwrap()),
                ufvk: two.ufvk.clone(),
                birthday: None,
                label: None,
            },
            "a passphrase",
        )
        .unwrap();
        let input = recovery_input(&file, "a passphrase").unwrap();
        let lying = frost_zec::recovery::GroupInfo::new(&other.member, &other.ufvk);
        let refused = setup_with(&dir, Some((&input, lying)))
            .err()
            .unwrap()
            .to_string();
        assert!(refused.contains("membre 3"), "{refused}");
        assert!(
            account(&dir, Net::Test).unwrap().is_none(),
            "nothing stored"
        );
        assert!(old_account(&dir, Net::Test).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn acknowledgement(cosigner: &Cosigner, group: &Group) -> Vec<u8> {
        wire::encode_payload(&[Message::seal(
            &cosigner.pairing,
            kind::DKG_DONE,
            b"dkg",
            &group.done().unwrap().to_bytes(),
            &mut UnwrapErr(SysRng),
        )
        .unwrap()])
    }

    #[test]
    fn a_setup_ends_only_with_the_cosigners_acknowledgement() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-done-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (step, cosigner) = setup_until_done(&dir);
        // Stored, but no address to fund and no send before the acknowledgement.
        assert!(!account(&dir, Net::Test).unwrap().unwrap().confirmed);

        // Another group's acknowledgement, under this pairing, is refused, and
        // the setup still waits.
        let other = {
            let other_dir = dir.join("other");
            std::fs::create_dir_all(&other_dir).unwrap();
            setup_until_done(&other_dir).1.group
        };
        let refused = setup_done(&dir, &step, &acknowledgement(&cosigner, &other))
            .unwrap_err()
            .to_string();
        assert_eq!(refused, DIFFERENT_GROUP);
        // A message of another kind is refused in the user's words.
        let wrong = wire::encode_payload(&[Message::seal(
            &cosigner.pairing,
            kind::SIGN_REPLY,
            b"dkg",
            b"x",
            &mut UnwrapErr(SysRng),
        )
        .unwrap()]);
        assert!(setup_done(&dir, &step, &wrong)
            .unwrap_err()
            .to_string()
            .contains("pas le message attendu"));
        assert!(!account(&dir, Net::Test).unwrap().unwrap().confirmed);

        // The co-signer's own acknowledgement confirms the account.
        let confirmed =
            setup_done(&dir, &step, &acknowledgement(&cosigner, &cosigner.group)).unwrap();
        assert!(confirmed.confirmed);
        assert_eq!(confirmed.address, cosigner.group.address);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unfinished_setup_is_finished_later_from_the_seat() {
        let dir = std::env::temp_dir().join(format!("zcash-frost-later-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The app closed before the acknowledgement came: the step is gone.
        let (_, cosigner) = setup_until_done(&dir);
        let payload = acknowledgement(&cosigner, &cosigner.group);
        // Another seed cannot open the seat.
        assert!(setup_done_later(&dir, Net::Test, &[4u8; 64], &payload).is_err());
        let account = setup_done_later(&dir, Net::Test, &[3u8; 64], &payload).unwrap();
        assert!(account.confirmed);
        assert_eq!(account.address, cosigner.group.address);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
