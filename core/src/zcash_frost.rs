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
use frost_zec::cosigning::{Commitments, CoordinatorSession, Member, Reply};
use frost_zec::setup::{CoordinatorSetup, Group, Round1, Round2};
use frost_zec::wire::{self, kind, Message};
use frost_zec::{check, keys, signing};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use zcash_client_backend::data_api::wallet::input_selection::{GreedyInputSelector, SpendPolicy};
use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, extract_and_store_transaction_from_pczt, propose_transfer,
    ConfirmationsPolicy,
};
use zcash_client_backend::data_api::{AccountBirthday, AccountPurpose, WalletRead, WalletWrite};
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
use zcash_protocol::consensus::{Network, NetworkType};
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
        data_dir.join(format!("zcash_frost_{}.{extension}", self.tag()))
    }
}

type Db = WalletDb<rusqlite::Connection, Network, SystemClock, UnwrapErr<SysRng>>;

fn open(data_dir: &Path, net: Net) -> Result<Db> {
    let mut db = WalletDb::for_path(
        net.file(data_dir, "sqlite"),
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
    /// Whether the user confirmed that the co-signer shows this address. The
    /// wallet has the account once it holds the co-signer's keys, but the
    /// co-signer only computes its own share and the backup's from the last
    /// message: if that message never reaches it, the account can never sign,
    /// and funds sent to it are lost. Until confirmed, the account is neither
    /// shown for receiving nor spent from. Accounts from before this field
    /// were all finished by hand, hence true when it is absent.
    #[serde(default = "confirmed_when_absent")]
    pub confirmed: bool,
}

fn confirmed_when_absent() -> bool {
    true
}

/// Shown when the address of an account the co-signer may not have finished is
/// asked for a send.
pub const NOT_CONFIRMED: &str =
    "création du compte FROST pas confirmée : vérifiez que le co-signataire affiche son adresse";

/// Records that the co-signer shows the account's address (see
/// [`FrostAccount::confirmed`]). Written to a temporary file then renamed, so
/// the account file is never left half-written.
pub fn confirm(data_dir: &Path, net: Net) -> Result<FrostAccount> {
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
    match std::fs::read(net.file(data_dir, "json")) {
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
    if account(data_dir, net)?.is_none() {
        bail!("aucun compte FROST sur ce réseau");
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let folder = data_dir
        .join(REMOVED_DIR)
        .join(format!("{}-{seconds}", net.tag()));
    std::fs::create_dir_all(&folder).context("compte FROST : mise de côté impossible")?;
    for extension in ["sqlite", "sqlite-wal", "sqlite-shm", "seat", "json"] {
        let from = net.file(data_dir, extension);
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

fn save_seat(data_dir: &Path, net: Net, seed: &[u8], seat: &Seat) -> Result<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(seat)?);
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("aléa indisponible : {e}"))?;
    let key = seat_key(seed, net);
    let mut aad = SEAT_AAD.to_vec();
    aad.extend_from_slice(net.tag().as_bytes());
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
    let path = net.file(data_dir, "seat");
    let temporary = path.with_extension("seat.tmp");
    std::fs::write(&temporary, file).context("siège FROST : écriture impossible")?;
    std::fs::rename(&temporary, &path).context("siège FROST : écriture impossible")?;
    Ok(())
}

/// Member 1, ready to sign, with the pairing to the co-signer.
fn load_seat(data_dir: &Path, net: Net, seed: &[u8]) -> Result<(Pairing, Member)> {
    let file = std::fs::read(net.file(data_dir, "seat")).context("siège FROST introuvable")?;
    if file.len() < 25 || file[0] != SEAT_VERSION {
        bail!("siège FROST illisible");
    }
    let nonce: [u8; 24] = file[1..25].try_into().expect("24 bytes");
    let key = seat_key(seed, net);
    let mut aad = SEAT_AAD.to_vec();
    aad.extend_from_slice(net.tag().as_bytes());
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
    if account(data_dir, net)?.is_none() {
        return Ok(());
    }
    let mut db = open(data_dir, net)?;
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
    if account(data_dir, net)?.is_none() {
        return Ok(ShieldedBalance::default());
    }
    let db = open(data_dir, net)?;
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
}

impl SetupStep {
    pub fn net(&self) -> Net {
        match self {
            SetupStep::AwaitingResponse { net, .. }
            | SetupStep::AwaitingCode { net, .. }
            | SetupStep::AwaitingKeys { net, .. } => *net,
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

/// Takes the co-signer's keys; returns the last payload to show, and the
/// account once stored. `seed` encrypts the seat; `birthday` comes from
/// [`chain_birthday`].
pub fn setup_finish(
    data_dir: &Path,
    step: SetupStep,
    payload: &[u8],
    seed: &[u8],
    birthday: &AccountBirthday,
) -> Result<(Vec<u8>, FrostAccount)> {
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
    if messages.len() != 2 {
        bail!("QR inattendu : les clés du co-signataire étaient attendues");
    }
    let (_, theirs1) = messages[0].open(&pairing, kind::DKG_ROUND1)?;
    let (_, theirs2) = messages[1].open(&pairing, kind::DKG_ROUND2)?;
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
    let account = store(data_dir, net, &pairing, &group, seed, birthday)?;
    Ok((shown, account))
}

fn store(
    data_dir: &Path,
    net: Net,
    pairing: &Pairing,
    group: &Group,
    seed: &[u8],
    birthday: &AccountBirthday,
) -> Result<FrostAccount> {
    let ufvk = UnifiedFullViewingKey::decode(&net.params(), &group.ufvk)
        .map_err(|e| anyhow!("clé de visualisation du groupe illisible : {e}"))?;
    // The account file is written last, so an account already in the database
    // was left there by a setup that failed before the end: nobody was shown
    // its address. The database only holds scan data; start from an empty one,
    // or the account picked later would be that one.
    if !open(data_dir, net)?.get_account_ids()?.is_empty() {
        for extension in ["sqlite", "sqlite-wal", "sqlite-shm"] {
            match std::fs::remove_file(net.file(data_dir, extension)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).context("base du compte FROST : nettoyage impossible");
                }
                _ => {}
            }
        }
    }
    let mut db = open(data_dir, net)?;
    db.import_account_ufvk(
        "FROST 2-of-3",
        &ufvk,
        birthday,
        AccountPurpose::ViewOnly,
        None,
    )
    .map_err(|e| anyhow!("compte FROST : import impossible ({e})"))?;
    save_seat(
        data_dir,
        net,
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
        // The co-signer has not seen the last message yet.
        confirmed: false,
    };
    std::fs::write(
        net.file(data_dir, "json"),
        serde_json::to_vec_pretty(&account)?,
    )
    .context("compte FROST : écriture impossible")?;
    Ok(account)
}

// --- Sending ------------------------------------------------------------------------

/// Shown when a send is tried before the account was ever synced.
pub const NOT_SYNCED: &str = "compte FROST pas encore synchronisé : synchronisez-le d'abord";

/// A send waiting for the co-signer: the PCZT and what the user confirmed.
pub struct PreparedSend {
    pub net: Net,
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
    pairing: Pairing,
    session: CoordinatorSession,
}

/// Takes the co-signer's commitments; returns the request payload to show and
/// the coordinator's own check of the PCZT. `seed` unlocks the seat.
pub fn send_request(
    data_dir: &Path,
    prepared: &PreparedSend,
    commitments: &[u8],
    seed: &[u8],
) -> Result<(PendingSignature, Vec<u8>, check::Report)> {
    let (pairing, member) = load_seat(data_dir, prepared.net, seed)?;
    let messages = wire::decode_payload(commitments)?;
    let (bound, bytes) = messages
        .first()
        .context("QR vide")?
        .open(&pairing, kind::SIGN_COMMITMENTS)?;
    let opening = Commitments::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?;
    if bound != opening.session {
        bail!("QR incohérent : deux sessions différentes");
    }
    let (session, request, report) = CoordinatorSession::request(&member, &prepared.pczt, &opening)
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
            pairing,
            session,
        },
        shown,
        report,
    ))
}

/// Takes the co-signer's reply: aggregates, proves, stores and broadcasts.
/// Returns the transaction id.
pub fn send_finish(data_dir: &Path, pending: PendingSignature, reply: &[u8]) -> Result<String> {
    let messages = wire::decode_payload(reply)?;
    let (_, bytes) = messages
        .first()
        .context("QR vide")?
        .open(&pending.pairing, kind::SIGN_REPLY)?;
    let reply = Reply::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?;
    let signed = pending.session.finish(&reply).map_err(|e| anyhow!("{e}"))?;
    let proved = prove(signed)?;
    let mut db = open(data_dir, pending.net)?;
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
            SetupStep::AwaitingKeys { pairing, .. } => pairing.id(),
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
}
