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
use zcash_client_backend::data_api::wallet::input_selection::{GreedyInputSelector, SpendPolicy};
use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, extract_and_store_transaction_from_pczt, propose_transfer,
    ConfirmationsPolicy,
};
use zcash_client_backend::data_api::{AccountBirthday, AccountPurpose, WalletRead, WalletWrite};
use zcash_client_backend::fees::{zip317::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec};
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::builder::BundlePadding;
use zcash_protocol::consensus::{Network, NetworkType};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;
use zeroize::Zeroizing;

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
    let mut db = WalletDb::for_path(net.file(data_dir, "sqlite"), net.params(), SystemClock, UnwrapErr(SysRng))
        .context("base du compte FROST illisible")?;
    init_wallet_db(&mut db, None).map_err(|e| anyhow!("base du compte FROST : migration impossible ({e})"))?;
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
}

/// The FROST account on `net`, if one was set up.
pub fn account(data_dir: &Path, net: Net) -> Result<Option<FrostAccount>> {
    match std::fs::read(net.file(data_dir, "json")) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).context("compte FROST illisible")?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("compte FROST illisible"),
    }
}

/// Member 1's secrets. Encrypted on disk.
#[derive(Serialize, Deserialize)]
struct Seat {
    pairing: String,
    key_package: String,
    public_key_package: String,
    sk: String,
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
        .encrypt(&XNonce::from(nonce), Payload { msg: &plaintext, aad: &aad })
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
            .decrypt(&XNonce::from(nonce), Payload { msg: &file[25..], aad: &aad })
            .map_err(|_| anyhow!("siège FROST : déchiffrement impossible (autre portefeuille ?)"))?,
    );
    let seat: Seat = serde_json::from_slice(&plaintext).context("siège FROST illisible")?;
    let pairing = Pairing::from_bytes(&hex::decode(&seat.pairing)?).map_err(|e| anyhow!("{e}"))?;
    let public_key_package = frost_zec::redpallas::keys::PublicKeyPackage::deserialize(&hex::decode(&seat.public_key_package)?)
        .map_err(|e| anyhow!("siège FROST : {e}"))?;
    let key_package = frost_zec::redpallas::keys::KeyPackage::deserialize(&hex::decode(&seat.key_package)?)
        .map_err(|e| anyhow!("siège FROST : {e}"))?;
    let sk: Zeroizing<[u8; 32]> = Zeroizing::new(
        hex::decode(&seat.sk)?.try_into().map_err(|_| anyhow!("siège FROST : sk invalide"))?,
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

/// The tree state just before the current tip: the group's address did not
/// exist before, so nothing earlier can belong to it.
async fn birthday_now(client: &mut CompactTxStreamerClient<tonic::transport::Channel>) -> Result<AccountBirthday> {
    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(|e| anyhow!("hauteur de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner()
        .height;
    let state = client
        .get_tree_state(BlockId { height: tip.saturating_sub(1), hash: vec![] })
        .await
        .map_err(|e| anyhow!("état de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner();
    AccountBirthday::from_treestate(state, None).map_err(|_| anyhow!("état de la chaîne Zcash invalide"))
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
    AwaitingResponse { net: Net, initiator: Initiator },
    /// pair-confirm and round 1 are on screen; the user compares the code.
    AwaitingCode { net: Net, pending: PendingPairing, setup: CoordinatorSetup },
    /// The code matched; scan the co-signer's keys.
    AwaitingKeys { net: Net, pairing: Pairing, setup: CoordinatorSetup },
}

/// Starts the setup on `net`: the pair-init payload to show.
pub fn setup_start(data_dir: &Path, net: Net) -> Result<(SetupStep, Vec<u8>)> {
    if account(data_dir, net)?.is_some() {
        bail!("un compte FROST existe déjà sur ce réseau");
    }
    let (initiator, init) = Initiator::start(&mut UnwrapErr(SysRng));
    Ok((
        SetupStep::AwaitingResponse { net, initiator },
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
    let (setup, round1) = CoordinatorSetup::start(net.network_type()).map_err(|e| anyhow!("{e}"))?;
    let shown = wire::encode_payload(&[
        Message::pair_confirm(&confirm),
        Message::seal_public(&pending, kind::DKG_ROUND1, b"dkg", &round1.to_bytes(), &mut UnwrapErr(SysRng))?,
    ]);
    let code = pending.code();
    Ok((SetupStep::AwaitingCode { net, pending, setup }, shown, code))
}

/// The user confirmed that both devices show the same code.
pub fn setup_code_confirmed(step: SetupStep) -> Result<SetupStep> {
    let SetupStep::AwaitingCode { net, pending, setup } = step else {
        bail!("étape de configuration inattendue");
    };
    Ok(SetupStep::AwaitingKeys { net, pairing: pending.confirm(), setup })
}

/// Takes the co-signer's keys; returns the last payload to show, and the
/// account once stored. `seed` encrypts the seat.
pub fn setup_finish(
    data_dir: &Path,
    step: SetupStep,
    payload: &[u8],
    seed: &[u8],
) -> Result<(Vec<u8>, FrostAccount)> {
    let SetupStep::AwaitingKeys { net, pairing, setup } = step else {
        bail!("étape de configuration inattendue");
    };
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
    let account = store(data_dir, net, &pairing, &group, seed)?;
    Ok((shown, account))
}

fn store(data_dir: &Path, net: Net, pairing: &Pairing, group: &Group, seed: &[u8]) -> Result<FrostAccount> {
    let ufvk = UnifiedFullViewingKey::decode(&net.params(), &group.ufvk)
        .map_err(|e| anyhow!("clé de visualisation du groupe illisible : {e}"))?;
    let birthday = runtime()?.block_on(async { birthday_now(&mut client(net).await?).await })?;
    let mut db = open(data_dir, net)?;
    db.import_account_ufvk("FROST 2-of-3", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
        .map_err(|e| anyhow!("compte FROST : import impossible ({e})"))?;
    save_seat(
        data_dir,
        net,
        seed,
        &Seat {
            pairing: hex::encode(pairing.to_bytes()),
            key_package: hex::encode(group.member.key_package.serialize().map_err(|e| anyhow!("{e}"))?),
            public_key_package: hex::encode(group.member.public_key_package.serialize().map_err(|e| anyhow!("{e}"))?),
            sk: hex::encode(group.sk),
        },
    )?;
    let account = FrostAccount {
        network: net,
        ufvk: group.ufvk.clone(),
        address: group.address.clone(),
        birthday: u32::from(birthday.height()),
    };
    std::fs::write(net.file(data_dir, "json"), serde_json::to_vec_pretty(&account)?)
        .context("compte FROST : écriture impossible")?;
    Ok(account)
}

// --- Sending ------------------------------------------------------------------------

/// A send waiting for the co-signer: the PCZT and what the user confirmed.
pub struct PreparedSend {
    pub net: Net,
    pub pczt: Vec<u8>,
    pub summary: SpendSummary,
}

fn change_strategy() -> SingleOutputChangeStrategy<StandardFeeRule, Db> {
    SingleOutputChangeStrategy::new(StandardFeeRule::Zip317, None, ShieldedPool::Ironwood, DustOutputPolicy::default())
}

fn proposal_fee<N>(proposal: &Proposal<StandardFeeRule, N>) -> u64 {
    proposal
        .steps()
        .iter()
        .map(|step| u64::from(step.balance().fee_required()))
        .sum()
}

/// Proposes a payment from the FROST account and turns it into a PCZT.
pub fn send_prepare(data_dir: &Path, net: Net, to: &str, amount: u64, memo: Option<&str>) -> Result<PreparedSend> {
    let recipient = zcash_address::ZcashAddress::try_from_encoded(to.trim())
        .map_err(|_| anyhow!("adresse Zcash invalide"))?;
    if zcash_keys::address::Address::decode(&net.params(), to.trim()).is_none() {
        bail!("cette adresse est sur un autre réseau Zcash");
    }
    let memo = memo
        .filter(|text| !text.is_empty())
        .map(|text| MemoBytes::from_bytes(text.as_bytes()).map_err(|_| anyhow!("mémo trop long (512 octets au plus)")))
        .transpose()?;
    let value = Zatoshis::from_u64(amount).map_err(|_| anyhow!("montant hors limites"))?;
    let payment = Payment::new(recipient, Some(value), memo, None, None, vec![])
        .map_err(|e| anyhow!("paiement invalide ({e:?})"))?;
    let request = TransactionRequest::new(vec![payment]).map_err(|e| anyhow!("demande de paiement invalide ({e:?})"))?;
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
    .map_err(|e| anyhow!("envoi FROST impossible ({e})"))?;
    let fee = proposal_fee(&proposal);
    // Payments use the group's outgoing viewing key, which the co-signer needs
    // to read them back (frost-zec docs/spec.md § 6).
    let pczt = create_pczt_from_proposal::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
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
        summary: SpendSummary { amount, fee, recipient: to.trim().to_string() },
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
    let (bound, bytes) = messages.first().context("QR vide")?.open(&pairing, kind::SIGN_COMMITMENTS)?;
    let opening = Commitments::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?;
    if bound != opening.session {
        bail!("QR incohérent : deux sessions différentes");
    }
    let (session, request, report) =
        CoordinatorSession::request(&member, &prepared.pczt, &opening).map_err(|e| anyhow!("{e}"))?;
    let shown = wire::encode_payload(&[Message::seal(
        &pairing,
        kind::SIGN_REQUEST,
        &request.session,
        &request.to_bytes().map_err(|e| anyhow!("{e}"))?,
        &mut UnwrapErr(SysRng),
    )?]);
    Ok((PendingSignature { net: prepared.net, pairing, session }, shown, report))
}

/// Takes the co-signer's reply: aggregates, proves, stores and broadcasts.
/// Returns the transaction id.
pub fn send_finish(data_dir: &Path, pending: PendingSignature, reply: &[u8]) -> Result<String> {
    let messages = wire::decode_payload(reply)?;
    let (_, bytes) = messages.first().context("QR vide")?.open(&pending.pairing, kind::SIGN_REPLY)?;
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
    tx.write(&mut raw).context("sérialisation de la transaction impossible")?;
    broadcast(pending.net, raw)?;
    Ok(txid.to_string())
}

/// Orchard-protocol proofs for the Ironwood bundle, with the circuit of the
/// PCZT's consensus branch.
fn prove(pczt: pczt::Pczt) -> Result<pczt::Pczt> {
    let branch = zcash_protocol::consensus::BranchId::try_from(*pczt.global().consensus_branch_id())
        .map_err(|_| anyhow!("PCZT : branche de consensus inconnue"))?;
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_ironwood_proof() || prover.requires_orchard_proof() {
        let version = zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
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
            .send_transaction(zcash_client_backend::proto::service::RawTransaction { data: raw, height: 0 })
            .await
            .map_err(|e| anyhow!("diffusion impossible : {}", e.message()))?
            .into_inner();
        if response.error_code != 0 {
            bail!("transaction refusée par le serveur : {}", response.error_message);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
