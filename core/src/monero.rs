//! Monero: primary address 4…, receiving, balance, history and sending.
//!
//! Libraries: `monero-wallet` (monero-oxide, derived from monero-serai, audited)
//! for scanning blocks with the VIEW key, decoy selection and CLSAG + Bulletproofs+
//! signing; `monero-simple-request-rpc` to talk to a Monero node.
//!
//! Keys: the Ledger Monero app's scheme. BIP32 key m/44'/128'/p'/0/0 from the seed,
//! spend key = reduced keccak256(key), view key = reduced keccak256(spend key).
//! Checked against the vectors from the Ledger app's tests: the same BIP39 seed
//! gives the same Monero wallet.
//!
//! Node: public by default (`DEFAULT_NODES`, tried in order), or the user's own
//! (Settings). The app downloads ALL blocks (pruned) and scans them locally, so the
//! node does not learn which outputs are ours while syncing. It does see the IP
//! address and the transactions we ask it to broadcast, and it provides the output
//! index and the decoys: a malicious node can show funds that do not exist or
//! weaken a send's privacy (a limit of any light wallet); decoy selection refuses a
//! node that lies about the output being spent.
//!
//! Local state (`monero_wallet.json`): received outputs, key images, sends. The
//! spend key is never stored: key images (spend detection) are computed whenever
//! the seed is available (unlock, send), and the blocks scanned without them since
//! an output was received are then reread. A leak of this file exposes the Monero
//! history, never the funds.

use crate::{derivation, history, tokens, wallet_birthday};
use anyhow::{anyhow, bail, ensure, Context, Result};
use monero_simple_request_rpc::prelude::MoneroDaemon;
use monero_simple_request_rpc::SimpleRequestTransport;
use monero_wallet::address::{AddressError, AddressType, MoneroAddress, Network};
use monero_wallet::ed25519::{CompressedPoint, Point, Scalar};
use monero_wallet::interface::prelude::*;
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SendError, SignableTransaction};
use monero_wallet::transaction::Input;
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair, WalletOutput, DEFAULT_LOCK_WINDOW};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroizing;

type Daemon = MoneroDaemon<SimpleRequestTransport>;

/// Account birthday: no Monero address from the app existed before it (recorded on
/// 2026-10-03: height 3,776,115), so nothing can be missed.
pub const BIRTHDAY_HEIGHT: usize = 3_776_000;

/// Public nodes (restricted RPC, HTTPS; recorded on 2026-10-03, all at the same
/// height and hash): Cake Wallet's and Stack Wallet's, then two community nodes.
pub const DEFAULT_NODES: [&str; 4] = [
    "https://xmr-node.cakewallet.com:18081",
    "https://monero.stackwallet.com:18081",
    "https://node.sethforprivacy.com:443",
    "https://xmr.cryptostorm.is:18081",
];

const STATE_FILE: &str = "monero_wallet.json";
const NODE_FILE: &str = "monero_node.txt";
/// Ring size enforced by consensus since hard fork 15.
const RING_LEN: u8 = 16;
/// Network upgrade whose rules the library knows (CLSAG + Bulletproofs+): any other
/// block version makes the send fail.
const KNOWN_HARDFORK: u8 = 16;
/// Blocks requested per call (`get_blocks.bin`, pruned).
const BATCH: usize = 100;
/// Latest blocks kept to detect a chain reorganization.
const RECENT_BLOCKS: usize = 30;
/// Fee cap per unit of weight (piconeros): 20,000 on 2026-10-03 at low priority
/// (wallet2's default), 320,000 at high priority; above that, the node is
/// suspicious and the send is refused.
const MAX_FEE_PER_WEIGHT: u64 = 400_000;
/// A send never mined after this delay (a transaction's lifetime in the nodes'
/// mempool): its outputs become available again.
const PENDING_EXPIRY_SECS: u64 = 3 * 24 * 3600;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
pub const DECIMALS: u32 = 12;

/// One read-modify-write of the state at a time (background sync and sends).
static STATE_LOCK: Mutex<()> = Mutex::new(());

/// State folder and known profiles (address → profile), recorded at the start of
/// each sync: the portfolio chart reads balance and history by address
/// (`balance_of_address`, `history_of_address`).
static KNOWN: Mutex<Option<(std::path::PathBuf, BTreeMap<String, u32>)>> = Mutex::new(None);

// --- Keys and address ------------------------------------------------------------

/// A profile's view keys (kept in memory on unlock, never sent to the UI): the
/// public spend key and the private view key, enough to find received outputs but
/// not to spend them.
#[derive(Clone)]
pub struct ViewKeys {
    pub profile: u32,
    spend_public: [u8; 32],
    view_private: Zeroizing<[u8; 32]>,
}

impl ViewKeys {
    fn pair(&self) -> Result<ViewPair> {
        let spend = CompressedPoint::from(self.spend_public)
            .decompress()
            .ok_or_else(|| anyhow!("clé publique Monero invalide"))?;
        let view = Scalar::read(&mut self.view_private.as_slice())
            .context("clé de visualisation Monero invalide")?;
        ViewPair::new(spend, Zeroizing::new(view))
            .map_err(|e| anyhow!("clés Monero invalides ({e})"))
    }

    /// The profile's primary address (4…).
    pub fn address(&self) -> Result<String> {
        Ok(self.pair()?.legacy_address(Network::Mainnet).to_string())
    }
}

fn dalek(bytes: &[u8; 32]) -> curve25519_dalek::Scalar {
    curve25519_dalek::Scalar::from_bytes_mod_order(*bytes)
}

/// The profile's private spend key (Ledger scheme, see the header).
fn spend_key(seed: &[u8], profile: u32) -> Result<Zeroizing<Scalar>> {
    let base = derivation::derive_monero_base_key(seed, profile)?;
    Ok(Zeroizing::new(Scalar::hash(&base[..])))
}

pub fn view_keys(seed: &[u8], profile: u32) -> Result<ViewKeys> {
    Ok(keys_from_spend(profile, &*spend_key(seed, profile)?))
}

fn keys_from_spend(profile: u32, spend: &Scalar) -> ViewKeys {
    let spend_bytes = Zeroizing::new(<[u8; 32]>::from(*spend));
    let view = Scalar::hash(&spend_bytes[..]);
    let spend_public = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &dalek(&spend_bytes))
        .compress()
        .to_bytes();
    ViewKeys {
        profile,
        spend_public,
        view_private: Zeroizing::new(<[u8; 32]>::from(view)),
    }
}

/// Key image of an output: (spend key + output offset) × Hp(output key), published
/// by the transaction that spends it.
fn key_image(spend: &Scalar, output_key: Point, key_offset: Scalar) -> [u8; 32] {
    let spend_bytes = Zeroizing::new(<[u8; 32]>::from(*spend));
    let secret = Zeroizing::new(dalek(&spend_bytes) + dalek(&<[u8; 32]>::from(key_offset)));
    key_image_for(&secret, output_key)
}

fn key_image_for(secret: &curve25519_dalek::Scalar, output_key: Point) -> [u8; 32] {
    let hp = Point::biased_hash(output_key.compress().to_bytes()).into();
    (secret * hp).compress().to_bytes()
}

/// Recipient: a mainnet Monero address (standard 4…, subaddress 8…, integrated);
/// test networks and non-standard formats refused.
pub fn parse_recipient(address: &str) -> Result<MoneroAddress> {
    let address =
        MoneroAddress::from_str(Network::Mainnet, address.trim()).map_err(|e| match e {
            AddressError::DifferentNetwork { .. } => {
                anyhow!("adresse Monero d'un réseau de test (stagenet/testnet) : refusée")
            }
            _ => anyhow!("adresse Monero invalide"),
        })?;
    ensure!(
        !matches!(address.kind(), AddressType::Featured { .. }),
        "format d'adresse Monero non standard : refusé"
    );
    Ok(address)
}

// --- Amounts ---------------------------------------------------------------------

pub fn format_xmr(piconero: u64) -> String {
    tokens::format_amount(u128::from(piconero), DECIMALS as u8)
}

pub fn parse_xmr(amount: &str) -> Result<u64> {
    u64::try_from(tokens::parse_amount(amount, DECIMALS as u8)?).context("montant hors limites")
}

// --- Local state -----------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct State {
    /// The node's latest known block (last sync).
    #[serde(default)]
    tip: usize,
    /// Latest scanned blocks (number, hash), oldest to newest.
    #[serde(default)]
    recent: Vec<(usize, String)>,
    #[serde(default)]
    profiles: BTreeMap<u32, ProfileState>,
}

#[derive(Serialize, Deserialize)]
struct ProfileState {
    /// Public spend key (hex) of the stored outputs: a state written for ANOTHER wallet
    /// (a reset, then a new wallet or a restore on this device) is forgotten instead of
    /// being mixed in (see `bind_profile`). `None`: state from before this field
    /// existed.
    #[serde(default)]
    spend_public: Option<String>,
    /// Next block to scan for this profile.
    next_block: usize,
    #[serde(default)]
    outputs: Vec<Received>,
    #[serde(default)]
    sends: Vec<Sent>,
}

impl ProfileState {
    fn new(spend_public: &[u8; 32], start: usize) -> Self {
        Self {
            spend_public: Some(hex::encode(spend_public)),
            next_block: start,
            outputs: Vec::new(),
            sends: Vec::new(),
        }
    }
}

/// The profile's state, bound to ITS keys: created if missing (scan from `start`),
/// replaced if it was written for another wallet, marked if it predates the
/// binding.
fn bind_profile(state: &mut State, profile: u32, spend_public: &[u8; 32], start: usize) {
    let expected = hex::encode(spend_public);
    match state.profiles.get_mut(&profile) {
        Some(p) if p.spend_public.as_deref() == Some(expected.as_str()) => {}
        Some(p) if p.spend_public.is_none() => p.spend_public = Some(expected),
        _ => {
            state
                .profiles
                .insert(profile, ProfileState::new(spend_public, start));
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Received {
    /// Full output (`monero-wallet` format, hex): enough to spend it with the spend
    /// key.
    output: String,
    tx: String,
    /// The output's public key (hex): an output already seen is never counted twice
    /// (rereading, or the "burning bug": only the first one is spendable).
    key: String,
    block: usize,
    time: u64,
    amount: u64,
    #[serde(default)]
    key_image: Option<String>,
    #[serde(default)]
    spent: Option<Spend>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct Spend {
    tx: String,
    /// `None`: send broadcast, not mined yet.
    block: Option<usize>,
    time: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Sent {
    tx: String,
    to: String,
    amount: u64,
    fee: u64,
    change: u64,
    time: u64,
    #[serde(default)]
    block: Option<usize>,
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    STATE_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn load(data_dir: &Path) -> Result<State> {
    match std::fs::read(data_dir.join(STATE_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("état Monero illisible"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e).context("état Monero illisible"),
    }
}

fn save(data_dir: &Path, state: &State) -> Result<()> {
    let path = data_dir.join(STATE_FILE);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(state)?)
        .context("enregistrement de l'état Monero impossible")?;
    std::fs::rename(&tmp, &path).context("enregistrement de l'état Monero impossible")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pending spend that is too old: never mined, output available again.
fn spend_expired(spend: &Spend, now: u64) -> bool {
    spend.block.is_none() && now.saturating_sub(spend.time) > PENDING_EXPIRY_SECS
}

fn decode_output(hex_output: &str) -> Result<WalletOutput> {
    let bytes = hex::decode(hex_output).context("sortie Monero illisible")?;
    WalletOutput::read(&mut bytes.as_slice()).context("sortie Monero illisible")
}

// --- Node ------------------------------------------------------------------------

/// Node chosen by the user in Settings, if any.
pub fn custom_node(data_dir: &Path) -> Option<String> {
    std::fs::read_to_string(data_dir.join(NODE_FILE))
        .ok()
        .and_then(|text| normalize_node(&text).ok())
}

/// Saves the user's node (empty: back to the public nodes).
pub fn set_custom_node(data_dir: &Path, url: &str) -> Result<Option<String>> {
    let path = data_dir.join(NODE_FILE);
    if url.trim().is_empty() {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).context("suppression du nœud Monero impossible")
            }
            _ => return Ok(None),
        }
    }
    let url = normalize_node(url)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &url).context("enregistrement du nœud Monero impossible")?;
    std::fs::rename(&tmp, &path).context("enregistrement du nœud Monero impossible")?;
    Ok(Some(url))
}

/// Accepted node address: `https://host[:port]`, or `http://` for a local or LAN
/// node only (in the clear over the Internet, a middleman could show fake blocks).
/// No path or credentials.
fn normalize_node(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("adresse de nœud invalide : https://hôte:port attendu"))?;
    ensure!(
        !rest.is_empty() && !rest.contains(['/', '?', '#', '@', ' ']),
        "adresse de nœud invalide : https://hôte:port attendu, sans chemin"
    );
    let host = match rest.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => rest.split(':').next().unwrap_or_default(),
    };
    ensure!(!host.is_empty(), "adresse de nœud invalide : hôte manquant");
    match scheme.to_ascii_lowercase().as_str() {
        "https" => {}
        "http" => ensure!(
            is_local_host(host),
            "nœud distant : https:// obligatoire (http:// seulement pour un nœud local)"
        ),
        _ => bail!("adresse de nœud invalide : https://hôte:port attendu"),
    }
    Ok(format!("{}://{rest}", scheme.to_ascii_lowercase()))
}

fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback(),
        Err(_) => false,
    }
}

fn nodes(data_dir: &Path) -> Vec<String> {
    match custom_node(data_dir) {
        Some(url) => vec![url],
        None => DEFAULT_NODES.iter().map(|u| u.to_string()).collect(),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("démarrage du client Monero impossible")
}

/// The first node that answers, with the height of the latest block.
async fn connect(data_dir: &Path) -> Result<(Daemon, usize)> {
    let mut errors = Vec::new();
    for url in nodes(data_dir) {
        let attempt = async {
            let rpc =
                SimpleRequestTransport::with_custom_timeout(url.clone(), REQUEST_TIMEOUT).await?;
            let tip = rpc.latest_block_number().await?;
            Ok::<_, InterfaceError>((rpc, tip))
        };
        match attempt.await {
            Ok(found) => return Ok(found),
            Err(e) => errors.push(format!("{} : {e}", host_of(&url))),
        }
    }
    bail!("aucun nœud Monero joignable ({})", errors.join(" ; "))
}

fn host_of(url: &str) -> &str {
    url.split_once("://").map_or(url, |(_, rest)| rest)
}

fn node_err(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("nœud Monero : {e}")
}

// --- Sync ------------------------------------------------------------------------

/// Forgets the remembered addresses (state wipe, see `seed_state`).
pub(crate) fn forget_known() {
    *KNOWN.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// Scans blocks up to the tip of the chain for every profile (called in the
/// background after unlocking). The state is saved after each batch, so an
/// interruption only loses the current batch. `generation` (see `seed_state`): the
/// state is only read and written under its authorization, never during network
/// calls; a reset only waits for one batch in memory, and the pass stops without
/// writing anything back.
pub fn sync(data_dir: &Path, keys: &[ViewKeys], generation: u64) -> Result<()> {
    if keys.is_empty() || crate::seed_state::pass(generation).is_none() {
        return Ok(());
    }
    let mut scanners = keys
        .iter()
        .map(|k| Ok((k.profile, Scanner::new(k.pair()?))))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let addresses = keys
        .iter()
        .map(|k| Ok((k.address()?, k.profile)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    *KNOWN.lock().unwrap_or_else(|p| p.into_inner()) = Some((data_dir.to_path_buf(), addresses));
    runtime()?.block_on(async {
        let (rpc, _) = connect(data_dir).await?;
        loop {
            // Reset or restore requested: nothing is written back (see `seed_state`).
            if crate::seed_state::cancelled() {
                return Ok(());
            }
            let tip = rpc.latest_block_number().await.map_err(node_err)?;
            // Lock released during network calls: a send never waits for a batch to finish.
            let (start, recent) = {
                let Some(_pass) = crate::seed_state::pass(generation) else {
                    return Ok(());
                };
                let _guard = lock();
                let state = load(data_dir)?;
                (scan_start(&state, keys), state.recent.clone())
            };
            let fork = find_fork(&rpc, &recent).await?;
            let blocks = if fork.is_none() && start <= tip {
                ProvidesScannableBlocks::contiguous_scannable_blocks(
                    &rpc,
                    start..=tip.min(start + BATCH - 1),
                )
                .await
                .map_err(node_err)?
            } else {
                Vec::new()
            };

            let Some(_pass) = crate::seed_state::pass(generation) else {
                return Ok(());
            };
            let _guard = lock();
            let mut state = load(data_dir)?;
            // New profile: scan from shortly before the wallet was created (fixed birthday if
            // unknown); never beyond the known chain (wrong clock). (A different name from
            // `start`, the first block of THIS batch: mixing them up made the loop spin
            // without doing anything.)
            let new_profile_start =
                wallet_birthday::start_height(data_dir, tip as u64, 120, BIRTHDAY_HEIGHT as u64)
                    as usize;
            for k in keys {
                bind_profile(&mut state, k.profile, &k.spend_public, new_profile_start);
                if let Some(p) = state.profiles.get_mut(&k.profile) {
                    if p.next_block > tip + 1 {
                        p.next_block = new_profile_start;
                    }
                }
            }
            state.tip = tip;
            expire_pending(&mut state, now());
            if let Some(fork) = fork {
                rollback(&mut state, fork);
                save(data_dir, &state)?;
                continue;
            }
            // State changed during the read (key images computed: blocks to reread): start
            // over with it.
            if scan_start(&state, keys) != start || state.recent != recent {
                save(data_dir, &state)?;
                continue;
            }
            if start > tip {
                return save(data_dir, &state);
            }
            // Chain reorganized between the check and the read: the next pass goes back to the
            // common point.
            if let (Some((number, hash)), Some(first)) = (state.recent.last(), blocks.first()) {
                if number + 1 == start && hex::encode(first.block.header.previous) != *hash {
                    state.recent.pop();
                    save(data_dir, &state)?;
                    continue;
                }
            }
            for block in blocks {
                // Wipe requested: stop between two blocks, nothing written back.
                if crate::seed_state::cancelled() {
                    return Ok(());
                }
                process_block(&mut state, &mut scanners, block)?;
            }
            save(data_dir, &state)?;
        }
    })
}

/// Next block to scan: the furthest behind across profiles.
fn scan_start(state: &State, keys: &[ViewKeys]) -> usize {
    keys.iter()
        .map(|k| {
            state
                .profiles
                .get(&k.profile)
                .map_or(BIRTHDAY_HEIGHT, |p| p.next_block)
        })
        .min()
        .unwrap_or(BIRTHDAY_HEIGHT)
}

/// Compares the latest scanned blocks with the node's: `Some(last common block)` if
/// the chain was reorganized.
async fn find_fork(rpc: &Daemon, recent: &[(usize, String)]) -> Result<Option<usize>> {
    let Some(&(last, _)) = recent.last() else {
        return Ok(None);
    };
    for (number, hash) in recent.iter().rev() {
        let node_hash = ProvidesBlockchain::block_hash(rpc, *number)
            .await
            .map_err(node_err)?;
        if hex::encode(node_hash) == *hash {
            return Ok((*number != last).then_some(*number));
        }
    }
    // Deeper than the blocks kept (never seen on Monero): go back to the oldest.
    Ok(Some(recent[0].0.saturating_sub(1)))
}

/// Forgets the blocks after `fork`: received outputs removed, spends set back to
/// pending, profiles to reread from `fork + 1`.
fn rollback(state: &mut State, fork: usize) {
    state.recent.retain(|(number, _)| *number <= fork);
    for profile in state.profiles.values_mut() {
        profile.outputs.retain(|o| o.block <= fork);
        for output in &mut profile.outputs {
            if let Some(spend) = &mut output.spent {
                if spend.block.is_some_and(|b| b > fork) {
                    spend.block = None;
                }
            }
        }
        for sent in &mut profile.sends {
            if sent.block.is_some_and(|b| b > fork) {
                sent.block = None;
            }
        }
        profile.next_block = profile.next_block.min(fork + 1);
    }
}

fn expire_pending(state: &mut State, now: u64) {
    for profile in state.profiles.values_mut() {
        for output in &mut profile.outputs {
            if output.spent.as_ref().is_some_and(|s| spend_expired(s, now)) {
                output.spent = None;
            }
        }
    }
}

fn process_block(
    state: &mut State,
    scanners: &mut BTreeMap<u32, Scanner>,
    block: ScannableBlock,
) -> Result<()> {
    let number = block.block.number();
    let time = block.block.header.timestamp;
    let hash = hex::encode(block.block.hash());

    // Spends: key images of the inputs, compared with those of our outputs.
    let ours: HashSet<String> = state
        .profiles
        .values()
        .flat_map(|p| p.outputs.iter().filter_map(|o| o.key_image.clone()))
        .collect();
    if !ours.is_empty() {
        for (tx_hash, tx) in block.block.transactions.iter().zip(&block.transactions) {
            for input in &tx.prefix().inputs {
                if let Input::ToKey { key_image, .. } = input {
                    let image = hex::encode(key_image.to_bytes());
                    if ours.contains(&image) {
                        mark_spent(state, &image, &hex::encode(tx_hash), Some(number), time);
                    }
                }
            }
        }
    }

    for (profile, scanner) in scanners.iter_mut() {
        let state_profile = state
            .profiles
            .get_mut(profile)
            .ok_or_else(|| anyhow!("profil Monero inconnu"))?;
        if state_profile.next_block > number {
            continue;
        }
        let found = scanner
            .scan(block.clone())
            .map_err(|e| anyhow!("bloc Monero {number} illisible ({e})"))?
            .not_additionally_locked();
        for output in found {
            let key = hex::encode(output.key().compress().to_bytes());
            if state_profile.outputs.iter().any(|o| o.key == key) {
                continue;
            }
            state_profile.outputs.push(Received {
                output: hex::encode(output.serialize()),
                tx: hex::encode(output.transaction()),
                key,
                block: number,
                time,
                amount: output.commitment().amount,
                key_image: None,
                spent: None,
            });
        }
        state_profile.next_block = number + 1;
    }

    // Reread blocks (key images computed afterwards): already stored.
    if state.recent.last().is_none_or(|(last, _)| number > *last) {
        state.recent.push((number, hash));
        let excess = state.recent.len().saturating_sub(RECENT_BLOCKS);
        state.recent.drain(..excess);
    }
    Ok(())
}

/// Output with key image `image` spent by `tx` (mined in `block`, or pending).
fn mark_spent(state: &mut State, image: &str, tx: &str, block: Option<usize>, time: u64) {
    for profile in state.profiles.values_mut() {
        for output in profile
            .outputs
            .iter_mut()
            .filter(|o| o.key_image.as_deref() == Some(image))
        {
            output.spent = Some(Spend {
                tx: tx.to_string(),
                block,
                time,
            });
        }
        if block.is_some() {
            for sent in profile.sends.iter_mut().filter(|s| s.tx == tx) {
                sent.block = block;
            }
        }
    }
}

/// Computes the key images of outputs that do not have one yet (seed available:
/// unlock or send) and has the blocks scanned without them since their receipt
/// reread, to find any spend there.
pub fn update_key_images(data_dir: &Path, seed: &[u8], profile: u32) -> Result<()> {
    let _guard = lock();
    let mut state = load(data_dir)?;
    if !state.profiles.contains_key(&profile) {
        return Ok(());
    }
    // Unlock: another wallet's state is forgotten before anything is displayed.
    let spend = spend_key(seed, profile)?;
    let spend_public = keys_from_spend(profile, &spend).spend_public;
    let before = state
        .profiles
        .get(&profile)
        .and_then(|p| p.spend_public.clone());
    // Another wallet (restore): fixed birthday, since the funds may be old.
    bind_profile(&mut state, profile, &spend_public, BIRTHDAY_HEIGHT);
    let Some(state_profile) = state.profiles.get_mut(&profile) else {
        return Ok(());
    };
    if state_profile.outputs.iter().all(|o| o.key_image.is_some()) {
        if state_profile.spend_public != before {
            save(data_dir, &state)?;
        }
        return Ok(());
    }
    let mut rescan_from = state_profile.next_block;
    for output in state_profile
        .outputs
        .iter_mut()
        .filter(|o| o.key_image.is_none())
    {
        let decoded = decode_output(&output.output)?;
        output.key_image = Some(hex::encode(key_image(
            &spend,
            decoded.key(),
            decoded.key_offset(),
        )));
        rescan_from = rescan_from.min(output.block + 1);
    }
    state_profile.next_block = rescan_from;
    save(data_dir, &state)
}

// --- Balance and history ---------------------------------------------------------

pub struct Balance {
    /// Spendable now (10 confirmations).
    pub unlocked: u64,
    /// Received but not spendable yet, plus the change expected from pending sends.
    pub locked: u64,
    /// Chain fully scanned for this profile.
    pub synced: bool,
}

fn unlocked_at(output: &Received, tip: usize) -> bool {
    tip + 1 >= output.block + DEFAULT_LOCK_WINDOW
}

fn available(output: &Received, now: u64) -> bool {
    output.spent.as_ref().is_none_or(|s| spend_expired(s, now))
}

pub fn balance(data_dir: &Path, profile: u32) -> Result<Balance> {
    let state = load(data_dir)?;
    let Some(p) = state.profiles.get(&profile) else {
        return Ok(Balance {
            unlocked: 0,
            locked: 0,
            synced: false,
        });
    };
    let now = now();
    let (mut unlocked, mut locked) = (0u64, 0u64);
    for output in p.outputs.iter().filter(|o| available(o, now)) {
        if unlocked_at(output, state.tip) {
            unlocked = unlocked.saturating_add(output.amount);
        } else {
            locked = locked.saturating_add(output.amount);
        }
    }
    for sent in p
        .sends
        .iter()
        .filter(|s| s.block.is_none() && now.saturating_sub(s.time) <= PENDING_EXPIRY_SECS)
    {
        locked = locked.saturating_add(sent.change);
    }
    Ok(Balance {
        unlocked,
        locked,
        synced: state.tip > 0 && p.next_block > state.tip,
    })
}

/// The profile's transactions, newest first: net amount (received minus spent,
/// including the fee for a send).
pub fn history(data_dir: &Path, profile: u32) -> Result<Vec<history::TxEntry>> {
    let state = load(data_dir)?;
    let Some(p) = state.profiles.get(&profile) else {
        return Ok(Vec::new());
    };
    let now = now();
    // tx → (net, block, time, abandoned)
    let mut txs: BTreeMap<String, (i128, Option<usize>, u64, bool)> = BTreeMap::new();
    for output in &p.outputs {
        let entry =
            txs.entry(output.tx.clone())
                .or_insert((0, Some(output.block), output.time, false));
        entry.0 += i128::from(output.amount);
        if let Some(spend) = &output.spent {
            let entry = txs.entry(spend.tx.clone()).or_insert((
                0,
                spend.block,
                spend.time,
                spend_expired(spend, now),
            ));
            entry.0 -= i128::from(output.amount);
        }
    }
    let mut entries: Vec<_> = txs
        .into_iter()
        .map(|(id, (net, block, time, abandoned))| history::TxEntry {
            id,
            timestamp_unix: i64::try_from(time).ok(),
            status: match (block, abandoned) {
                (Some(_), _) => history::TxStatus::Confirmed,
                (None, false) => history::TxStatus::Pending,
                (None, true) => history::TxStatus::Failed,
            },
            net_amount_minor: Some(net),
            fee_minor: 0,
            kind: match net {
                n if n > 0 => history::TxKind::Received,
                n if n < 0 => history::TxKind::Sent,
                _ => history::TxKind::Other,
            },
        })
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp_unix));
    Ok(entries)
}

fn known_profile(address: &str) -> Result<(std::path::PathBuf, u32)> {
    let known = KNOWN.lock().unwrap_or_else(|p| p.into_inner());
    let (dir, addresses) = known
        .as_ref()
        .ok_or_else(|| anyhow!("Monero : synchronisation pas encore lancée"))?;
    let profile = addresses
        .get(address)
        .ok_or_else(|| anyhow!("adresse Monero inconnue de ce portefeuille"))?;
    Ok((dir.clone(), *profile))
}

/// Sum of the address's unspent outputs (without the change expected from pending
/// sends, which is not in the history either): portfolio chart.
pub fn balance_of_address(address: &str) -> Result<u64> {
    let (dir, profile) = known_profile(address)?;
    let state = load(&dir)?;
    let now = now();
    Ok(state.profiles.get(&profile).map_or(0, |p| {
        p.outputs
            .iter()
            .filter(|o| available(o, now))
            .map(|o| o.amount)
            .sum()
    }))
}

/// Full history of the address (local state): portfolio chart.
pub fn history_of_address(address: &str) -> Result<Vec<history::TxEntry>> {
    let (dir, profile) = known_profile(address)?;
    history(&dir, profile)
}

/// Outputs have already been received (by at least one profile): sync continues
/// even with the Monero card hidden (spends to track).
pub fn has_received(data_dir: &Path) -> bool {
    load(data_dir).is_ok_and(|state| state.profiles.values().any(|p| !p.outputs.is_empty()))
}

/// "Rescan from the beginning": every profile reread from the fixed birthday
/// (outputs already known are kept, never counted twice).
pub fn rescan_from_birthday(data_dir: &Path) -> Result<()> {
    let _guard = lock();
    let mut state = load(data_dir)?;
    for p in state.profiles.values_mut() {
        p.next_block = BIRTHDAY_HEIGHT;
    }
    save(data_dir, &state)
}

/// A send broadcast but not mined yet (the card refreshes more often).
pub fn has_pending(data_dir: &Path, profile: u32) -> Result<bool> {
    let state = load(data_dir)?;
    let now = now();
    Ok(state.profiles.get(&profile).is_some_and(|p| {
        p.sends
            .iter()
            .any(|s| s.block.is_none() && now.saturating_sub(s.time) <= PENDING_EXPIRY_SECS)
    }))
}

// --- Sending ---------------------------------------------------------------------

/// A send prepared for the confirmation dialog: outputs chosen, decoys drawn, fee
/// computed; exactly what will be signed.
pub struct SendPlan {
    pub profile: u32,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    tx: SignableTransaction,
}

/// The profile's spendable outputs (largest first), their total and the amount
/// still locked; refused until the sync is up to date.
fn spendable(data_dir: &Path, keys: &ViewKeys) -> Result<(Vec<Received>, u64, u64)> {
    let (outputs, synced, locked) = {
        let state = load(data_dir)?;
        let p = state.profiles.get(&keys.profile).ok_or_else(|| {
            anyhow!("Monero : synchronisation pas encore faite, réessayez dans un instant")
        })?;
        let now = now();
        let mut outputs: Vec<Received> = p
            .outputs
            .iter()
            .filter(|o| available(o, now) && unlocked_at(o, state.tip))
            .cloned()
            .collect();
        outputs.sort_by_key(|o| std::cmp::Reverse(o.amount));
        let locked: u64 = p
            .outputs
            .iter()
            .filter(|o| available(o, now) && !unlocked_at(o, state.tip))
            .map(|o| o.amount)
            .sum();
        (outputs, state.tip > 0 && p.next_block > state.tip, locked)
    };
    ensure!(
        synced,
        "Monero : synchronisation en cours, réessayez dans un instant"
    );
    let total: u64 = outputs.iter().map(|o| o.amount).sum();
    Ok((outputs, total, locked))
}

/// Verified recipient: a mainnet address, never our own.
fn checked_recipient(keys: &ViewKeys, to: &str) -> Result<MoneroAddress> {
    let recipient = parse_recipient(to)?;
    let pair = keys.pair()?;
    ensure!(
        recipient.spend() != pair.spend() || recipient.view() != pair.view(),
        "envoi vers votre propre adresse Monero"
    );
    Ok(recipient)
}

/// Prepares a send of the WHOLE spendable balance, fee deducted, to `to` (`None`: a
/// random address, just to find out the amount, since the fee only depends on the
/// number of inputs and outputs). Every output is spent; zero change.
pub fn prepare_send_max(data_dir: &Path, keys: &ViewKeys, to: Option<&str>) -> Result<SendPlan> {
    let recipient = match to {
        Some(to) => checked_recipient(keys, to)?,
        None => {
            let mut random = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(random.as_mut());
            parse_recipient(&keys_from_spend(keys.profile, &Scalar::hash(&random[..])).address()?)?
        }
    };
    let pair = keys.pair()?;
    let (outputs, total, locked) = spendable(data_dir, keys)?;
    ensure!(total > 0, "{}", insufficient(1, total, locked));
    runtime()?.block_on(async {
        let (rpc, tip) = connect(data_dir).await?;
        let header = ProvidesBlockchain::block_by_number(&rpc, tip)
            .await
            .map_err(node_err)?
            .header;
        ensure!(
            header.hardfork_version == KNOWN_HARDFORK,
            "réseau Monero mis à niveau (version {}) : mettez l'app à jour avant d'envoyer",
            header.hardfork_version
        );
        let fee_rate = rpc
            .fee_rate(FeePriority::Unimportant, MAX_FEE_PER_WEIGHT)
            .await
            .map_err(node_err)?;
        let mut inputs = Vec::new();
        for output in &outputs {
            inputs.push(
                OutputWithDecoys::new(
                    &mut OsRng,
                    &rpc,
                    RING_LEN,
                    tip,
                    decode_output(&output.output)?,
                )
                .await
                .map_err(node_err)?,
            );
        }
        let build = |amount: u64| {
            let mut outgoing_view_key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(outgoing_view_key.as_mut());
            SignableTransaction::new(
                RctType::ClsagBulletproofPlus,
                outgoing_view_key,
                inputs.clone(),
                vec![(recipient, amount)],
                Change::new(pair.clone(), None),
                Vec::new(),
                fee_rate,
            )
        };
        // Fee for this transaction shape (all the inputs, two outputs), then the amount
        // that leaves exactly that.
        let fee = match build(1) {
            Ok(tx) => tx.necessary_fee(),
            Err(SendError::NotEnoughFunds { necessary_fee, .. }) => {
                bail!(
                    "XMR insuffisants pour les frais ({} XMR)",
                    format_xmr(necessary_fee.unwrap_or(0))
                )
            }
            Err(e) => bail!("envoi Monero impossible ({e})"),
        };
        let amount = total
            .checked_sub(fee)
            .filter(|a| *a > 0)
            .ok_or_else(|| anyhow!("XMR insuffisants pour les frais ({} XMR)", format_xmr(fee)))?;
        let tx = build(amount).map_err(|e| anyhow!("envoi Monero impossible ({e})"))?;
        ensure!(tx.necessary_fee() == fee, "frais Monero incohérents");
        Ok(SendPlan {
            profile: keys.profile,
            to: recipient.to_string(),
            amount,
            fee,
            change: 0,
            tx,
        })
    })
}

/// Prepares a send of `amount` piconeros to `to` from the profile of `keys`
/// (without the spend key: nothing is signed here).
pub fn prepare_send(data_dir: &Path, keys: &ViewKeys, to: &str, amount: u64) -> Result<SendPlan> {
    let recipient = checked_recipient(keys, to)?;
    let pair = keys.pair()?;
    ensure!(amount > 0, "montant nul");
    let (outputs, total, locked) = spendable(data_dir, keys)?;
    ensure!(amount <= total, "{}", insufficient(amount, total, locked));

    runtime()?.block_on(async {
        let (rpc, tip) = connect(data_dir).await?;
        let header = ProvidesBlockchain::block_by_number(&rpc, tip)
            .await
            .map_err(node_err)?
            .header;
        ensure!(
            header.hardfork_version == KNOWN_HARDFORK,
            "réseau Monero mis à niveau (version {}) : mettez l'app à jour avant d'envoyer",
            header.hardfork_version
        );
        let fee_rate = rpc
            .fee_rate(FeePriority::Unimportant, MAX_FEE_PER_WEIGHT)
            .await
            .map_err(node_err)?;

        let mut inputs = Vec::new();
        let mut selected = 0u64;
        for output in &outputs {
            inputs.push(
                OutputWithDecoys::new(
                    &mut OsRng,
                    &rpc,
                    RING_LEN,
                    tip,
                    decode_output(&output.output)?,
                )
                .await
                .map_err(node_err)?,
            );
            selected += output.amount;
            if selected <= amount {
                continue;
            }
            let mut outgoing_view_key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(outgoing_view_key.as_mut());
            match SignableTransaction::new(
                RctType::ClsagBulletproofPlus,
                outgoing_view_key,
                inputs.clone(),
                vec![(recipient, amount)],
                Change::new(pair.clone(), None),
                Vec::new(),
                fee_rate,
            ) {
                Ok(tx) => {
                    let fee = tx.necessary_fee();
                    let change = selected
                        .checked_sub(amount + fee)
                        .ok_or_else(|| anyhow!("frais Monero incohérents"))?;
                    return Ok(SendPlan {
                        profile: keys.profile,
                        to: recipient.to_string(),
                        amount,
                        fee,
                        change,
                        tx,
                    });
                }
                Err(SendError::NotEnoughFunds { necessary_fee, .. }) => {
                    if selected == total {
                        let fee = necessary_fee.unwrap_or(0);
                        bail!(
                            "XMR insuffisants pour les frais ({} XMR) : maximum envoyable {} XMR",
                            format_xmr(fee),
                            format_xmr(total.saturating_sub(fee))
                        );
                    }
                }
                Err(e) => bail!("envoi Monero impossible ({e})"),
            }
        }
        bail!("{}", insufficient(amount, total, locked))
    })
}

fn insufficient(amount: u64, unlocked: u64, locked: u64) -> String {
    let mut message = format!(
        "XMR insuffisants : {} demandés, {} disponibles",
        format_xmr(amount),
        format_xmr(unlocked)
    );
    if locked > 0 {
        message.push_str(&format!(
            " ({} encore bloqués : 10 confirmations, ≈ 20 min)",
            format_xmr(locked)
        ));
    }
    message
}

/// Signs exactly the prepared (and confirmed) send with the spend key drawn from
/// `seed`, broadcasts it, then marks its outputs as spent.
pub fn sign_and_send(data_dir: &Path, seed: &[u8], plan: SendPlan) -> Result<String> {
    update_key_images(data_dir, seed, plan.profile)?;
    let spend = spend_key(seed, plan.profile)?;
    let SendPlan {
        profile: _,
        to,
        amount,
        fee,
        change,
        tx,
    } = plan;
    let tx = tx
        .sign(&mut OsRng, &spend)
        .map_err(|e| anyhow!("signature Monero impossible ({e})"))?;
    drop(spend);
    let tx_hash = hex::encode(tx.hash());
    let images: Vec<String> = tx
        .prefix()
        .inputs
        .iter()
        .filter_map(|input| match input {
            Input::ToKey { key_image, .. } => Some(hex::encode(key_image.to_bytes())),
            Input::Gen(_) => None,
        })
        .collect();

    let record = Sent {
        tx: tx_hash.clone(),
        to,
        amount,
        fee,
        change,
        time: now(),
        block: None,
    };
    let published = runtime()?.block_on(async {
        let (rpc, _) = connect(data_dir).await?;
        Ok::<_, anyhow::Error>(rpc.publish_transaction(&tx).await)
    })?;
    match published {
        Ok(()) => {}
        Err(PublishTransactionError::TransactionRejected(reason)) => {
            bail!("transaction refusée par le nœud Monero : {reason}")
        }
        // Timed out or connection lost after sending: the transaction may have gone out.
        // Its outputs are marked pending (never spent twice); if it is never mined, they
        // become available again after `PENDING_EXPIRY_SECS`.
        Err(PublishTransactionError::InterfaceError(e)) => {
            record_send(data_dir, &record, &images)?;
            bail!("diffusion Monero incertaine ({e}) : vérifiez l'historique dans quelques minutes avant de renvoyer")
        }
    }
    record_send(data_dir, &record, &images)?;
    Ok(tx_hash)
}

fn record_send(data_dir: &Path, sent: &Sent, images: &[String]) -> Result<()> {
    let _guard = lock();
    let mut state = load(data_dir)?;
    for image in images {
        mark_spent(&mut state, image, &sent.tx, None, sent.time);
    }
    if let Some(p) = state.profiles.values_mut().find(|p| {
        p.outputs
            .iter()
            .any(|o| o.spent.as_ref().is_some_and(|s| s.tx == sent.tx))
    }) {
        p.sends.push(sent.clone());
    }
    save(data_dir, &state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP39 seed of "abandon ×11 about" (no passphrase), the one used in the Ledger
    /// Monero app's tests (`tests/conftest.py`).
    const ABANDON_SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn seed() -> Vec<u8> {
        hex::decode(ABANDON_SEED).unwrap()
    }

    #[test]
    fn keys_match_the_ledger_monero_app() {
        // Vectors from LedgerHQ/app-monero's `tests/test_crypto.py`.
        let spend = spend_key(&seed(), 0).unwrap();
        assert_eq!(
            hex::encode(<[u8; 32]>::from(*spend)),
            "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109"
        );
        let keys = view_keys(&seed(), 0).unwrap();
        assert_eq!(
            hex::encode(*keys.view_private),
            "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201"
        );
        assert_eq!(
            hex::encode(keys.spend_public),
            "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d"
        );
        let pair = keys.pair().unwrap();
        assert_eq!(
            hex::encode(pair.view().compress().to_bytes()),
            "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"
        );
        assert_eq!(
            pair.legacy_address(Network::Stagenet).to_string(),
            "5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE"
        );
        let address = keys.address().unwrap();
        assert!(address.starts_with('4') && address.len() == 95, "{address}");
        assert_eq!(parse_recipient(&address).unwrap().to_string(), address);
    }

    #[test]
    fn profiles_have_distinct_wallets() {
        let a = view_keys(&seed(), 0).unwrap().address().unwrap();
        let b = view_keys(&seed(), 1).unwrap().address().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn key_images_match_the_monero_vectors() {
        // `generate_key_image <public key> <private key> <key image>` from
        // tests/crypto/tests.txt (monero-project/monero).
        for (public, secret, expected) in [
            (
                "e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0",
                "981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f",
                "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887",
            ),
            (
                "8661153f5f856b46f83e9e225777656cd95584ab16396fa03749ec64e957283b",
                "156d7f2e20899371404b87d612c3587ffe9fba294bafbbc99bb1695e3275230e",
                "03ec63d7f1b722f551840b2725c76620fa457c805cbbf2ee941a6bf4cfb6d06c",
            ),
        ] {
            let public: [u8; 32] = hex::decode(public).unwrap().try_into().unwrap();
            let public = CompressedPoint::from(public).decompress().unwrap();
            let secret = Scalar::read(&mut hex::decode(secret).unwrap().as_slice()).unwrap();
            let zero = Scalar::read(&mut [0u8; 32].as_slice()).unwrap();
            // Output path: spend key + offset (zero here).
            assert_eq!(hex::encode(key_image(&secret, public, zero)), expected);
        }
    }

    #[test]
    fn recipients() {
        let keys = view_keys(&seed(), 0).unwrap();
        let pair = keys.pair().unwrap();
        let sub = pair
            .subaddress(
                Network::Mainnet,
                monero_wallet::address::SubaddressIndex::new(0, 1).unwrap(),
            )
            .to_string();
        assert!(sub.starts_with('8'));
        assert!(parse_recipient(&sub).is_ok());
        let integrated = pair
            .legacy_integrated_address(Network::Mainnet, [7; 8])
            .to_string();
        assert!(parse_recipient(&integrated).is_ok());
        let stagenet = pair.legacy_address(Network::Stagenet).to_string();
        assert!(parse_recipient(&stagenet)
            .unwrap_err()
            .to_string()
            .contains("réseau de test"));
        assert!(parse_recipient("4pasuneadresse").is_err());
        assert!(parse_recipient("0x0000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_xmr("1").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_xmr("0.000000000001").unwrap(), 1);
        assert!(parse_xmr("0.0000000000001").is_err());
        assert_eq!(format_xmr(1_500_000_000_000), "1.5");
    }

    #[test]
    fn node_addresses() {
        assert_eq!(
            normalize_node(" https://node.example.org:18089/ ").unwrap(),
            "https://node.example.org:18089"
        );
        assert_eq!(
            normalize_node("http://127.0.0.1:18081").unwrap(),
            "http://127.0.0.1:18081"
        );
        assert_eq!(
            normalize_node("http://192.168.1.20:18081").unwrap(),
            "http://192.168.1.20:18081"
        );
        assert!(
            normalize_node("http://node.example.org:18081").is_err(),
            "http distant refusé"
        );
        assert!(normalize_node("https://user:pass@node.example.org").is_err());
        assert!(normalize_node("https://node.example.org/json_rpc").is_err());
        assert!(normalize_node("ftp://node.example.org").is_err());
        assert!(normalize_node("node.example.org").is_err());
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_monero_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn received(tx: &str, block: usize, amount: u64, spent: Option<Spend>) -> Received {
        Received {
            output: String::new(),
            tx: tx.into(),
            key: format!("k{tx}"),
            block,
            time: 1,
            amount,
            key_image: Some(format!("i{tx}")),
            spent,
        }
    }

    /// A state written for another wallet is replaced, never mixed in; our own is kept;
    /// a state from before the binding is adopted.
    #[test]
    fn profile_state_is_bound_to_its_wallet() {
        let mine = view_keys(&seed(), 0).unwrap().spend_public;
        let other = view_keys(&[9u8; 64], 0).unwrap().spend_public;
        let mut state = State::default();
        bind_profile(&mut state, 0, &other, BIRTHDAY_HEIGHT);
        state
            .profiles
            .get_mut(&0)
            .unwrap()
            .outputs
            .push(received("old", 10, 99, None));
        bind_profile(&mut state, 0, &other, BIRTHDAY_HEIGHT);
        assert_eq!(
            state.profiles[&0].outputs.len(),
            1,
            "même portefeuille : gardé"
        );
        bind_profile(&mut state, 0, &mine, BIRTHDAY_HEIGHT + 500);
        assert!(
            state.profiles[&0].outputs.is_empty(),
            "autre portefeuille : oublié"
        );
        assert_eq!(
            state.profiles[&0].next_block,
            BIRTHDAY_HEIGHT + 500,
            "nouvel état : analyse depuis le début demandé"
        );
        state.profiles.get_mut(&0).unwrap().spend_public = None;
        state
            .profiles
            .get_mut(&0)
            .unwrap()
            .outputs
            .push(received("legacy", 10, 5, None));
        bind_profile(&mut state, 0, &mine, BIRTHDAY_HEIGHT);
        assert_eq!(
            state.profiles[&0].outputs.len(),
            1,
            "état d'avant le lien : adopté"
        );
        assert_eq!(
            state.profiles[&0].spend_public.as_deref(),
            Some(hex::encode(mine).as_str())
        );
    }

    #[test]
    fn reorg_rolls_back_outputs_and_spends() {
        let mut state = State {
            tip: 120,
            recent: (100..=120).map(|n| (n, format!("h{n}"))).collect(),
            profiles: BTreeMap::new(),
        };
        let spent_late = Spend {
            tx: "s".into(),
            block: Some(115),
            time: 2,
        };
        state.profiles.insert(
            0,
            ProfileState {
                spend_public: None,
                next_block: 121,
                outputs: vec![
                    received("a", 90, 5, Some(spent_late)),
                    received("b", 112, 7, None),
                ],
                sends: vec![Sent {
                    tx: "s".into(),
                    to: String::new(),
                    amount: 1,
                    fee: 1,
                    change: 3,
                    time: 2,
                    block: Some(115),
                }],
            },
        );
        rollback(&mut state, 110);
        let p = &state.profiles[&0];
        assert_eq!(p.next_block, 111);
        assert_eq!(p.outputs.len(), 1, "sortie du bloc 112 oubliée");
        assert_eq!(
            p.outputs[0].spent.as_ref().unwrap().block,
            None,
            "dépense repassée en attente"
        );
        assert_eq!(p.sends[0].block, None);
        assert_eq!(state.recent.last().unwrap().0, 110);
    }

    #[test]
    fn balance_counts_locks_and_pending_sends() {
        let dir = temp_dir("balance");
        let t = now();
        let mut state = State {
            tip: 200,
            recent: Vec::new(),
            profiles: BTreeMap::new(),
        };
        state.profiles.insert(
            0,
            ProfileState {
                spend_public: None,
                next_block: 201,
                outputs: vec![
                    received("old", 150, 10, None),
                    received("new", 195, 4, None),
                    received(
                        "gone",
                        100,
                        50,
                        Some(Spend {
                            tx: "s".into(),
                            block: None,
                            time: t,
                        }),
                    ),
                    received(
                        "stale",
                        100,
                        2,
                        Some(Spend {
                            tx: "x".into(),
                            block: None,
                            time: t - PENDING_EXPIRY_SECS - 10,
                        }),
                    ),
                ],
                sends: vec![Sent {
                    tx: "s".into(),
                    to: String::new(),
                    amount: 30,
                    fee: 1,
                    change: 19,
                    time: t,
                    block: None,
                }],
            },
        );
        save(&dir, &state).unwrap();
        let b = balance(&dir, 0).unwrap();
        assert_eq!(b.unlocked, 12, "10 + 2 (dépense jamais minée expirée)");
        assert_eq!(b.locked, 4 + 19, "reçu récent + monnaie attendue");
        assert!(b.synced);
        let h = history(&dir, 0).unwrap();
        let send = h.iter().find(|e| e.id == "s").unwrap();
        assert_eq!(send.net_amount_minor, Some(-50));
        assert!(matches!(send.status, history::TxStatus::Pending));
        assert!(matches!(
            h.iter().find(|e| e.id == "x").unwrap().status,
            history::TxStatus::Failed
        ));
        assert!(has_pending(&dir, 0).unwrap());
    }

    /// Live: sync from the birthday with the public nodes.
    /// `cargo test -p openpgp-wallet-core monero::tests::real_sync -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_sync() {
        let dir = temp_dir("sync");
        let keys = view_keys(&seed(), 0).unwrap();
        let started = std::time::Instant::now();
        sync(
            &dir,
            std::slice::from_ref(&keys),
            crate::seed_state::generation(),
        )
        .unwrap();
        let state = load(&dir).unwrap();
        println!(
            "{} blocs en {:?}, hauteur {}",
            state.tip + 1 - BIRTHDAY_HEIGHT,
            started.elapsed(),
            state.tip
        );
        assert!(balance(&dir, 0).unwrap().synced);
        // Second pass: nothing to reread.
        let again = std::time::Instant::now();
        sync(
            &dir,
            std::slice::from_ref(&keys),
            crate::seed_state::generation(),
        )
        .unwrap();
        println!("seconde passe {:?}", again.elapsed());
        let error = prepare_send(&dir, &keys, &keys.address().unwrap(), 1)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("propre adresse"), "{error}");
        let other = view_keys(&seed(), 1).unwrap().address().unwrap();
        let error = prepare_send(&dir, &keys, &other, 1)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("XMR insuffisants"), "{error}");
    }
}
