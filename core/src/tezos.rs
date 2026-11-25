//! Tezos (XTZ): tz1… address (Ed25519 key m/44'/1729'/p'/0', the path Temple, Kukai,
//! Umami and Ledger's Tezos app use), balance, sending tez, history.
//!
//! Operations are forged (binary encoding) and signed here: Ed25519 over the
//! BLAKE2b-256 hash of 0x03 ‖ forged bytes. Before signing, the node forges the same
//! operation from its JSON form and must return the same bytes: an encoding change in a
//! future protocol refuses the send instead of signing bytes the node would read
//! differently. Before broadcasting, the node "preapplies" the signed operation
//! (signature, counter, fees, execution) without relaying it.
//!
//! Checked against Taquito's derivation vectors (the key the mainnet shows for that
//! address), Trust Wallet Core's address and signature vectors and bytes forged by a
//! mainnet node; the signature is checked by a mainnet node's preapply, and the whole
//! send end to end on Shadownet, the long-running test network.
//!
//! Before the confirmation dialog: spendable balance, baker fee, tez burned when the
//! payment creates the recipient's account, the one-time publication of the account's
//! public key (reveal), and contract addresses (KT1…) refused.

use crate::history;
use anyhow::{anyhow, bail, ensure, Context, Result};
use blake2b_simd::Params;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Tezos network: public RPC nodes (in order: when one does not answer, the next one
/// is used), TzKT indexer, chain ID.
pub struct Network {
    pub rpc: &'static [&'static str],
    pub tzkt: &'static str,
    chain_id: &'static str,
}

pub const MAINNET: Network = Network {
    rpc: &[
        "https://rpc.tzbeta.net",
        "https://rpc.tzkt.io/mainnet",
        "https://mainnet.smartpy.io",
    ],
    tzkt: "https://api.tzkt.io",
    chain_id: "NetXdQprcVkpaWU",
};
#[cfg(test)]
const SHADOWNET: Network = Network {
    rpc: &["https://rpc.shadownet.teztnets.com"],
    tzkt: "https://api.shadownet.tzkt.io",
    chain_id: "NetXsqzbfFenSTS",
};

/// The node one send uses for every step (preparation, simulation, forging, preapply,
/// injection), its chain checked: see `node`.
#[derive(Clone, Copy)]
struct Node {
    url: &'static str,
    chain_id: &'static str,
}

pub const DECIMALS: u8 = 6;
/// Minimal fee of the nodes' mempool (Octez defaults): 100 mutez, plus 1 mutez per byte
/// and 0.1 mutez per gas unit.
const MINIMAL_FEE: u64 = 100;
/// Shell header (branch) and signature, counted in full in each operation's fee.
const HEADER_AND_SIGNATURE: u64 = 32 + 64;
/// Gas added to the simulated consumption, as Taquito does.
const GAS_MARGIN: u64 = 100;
/// The baker fee and the burn are each refused above 0.1 XTZ.
const MAX_FEE: u64 = 100_000;
const MAX_BURN: u64 = 100_000;

// Base58Check prefixes.
const TZ1: [u8; 3] = [6, 161, 159];
const TZ2: [u8; 3] = [6, 161, 161];
const TZ3: [u8; 3] = [6, 161, 164];
const TZ4: [u8; 3] = [6, 161, 166];
const KT1: [u8; 3] = [2, 90, 121];
const EDPK: [u8; 4] = [13, 15, 37, 217];
const EDSIG: [u8; 5] = [9, 245, 205, 134, 18];
const BLOCK_HASH: [u8; 2] = [1, 52];
const OPERATION_HASH: [u8; 2] = [5, 116];

/// Implicit account prefixes and the curve tag each one is forged with.
const IMPLICIT: [([u8; 3], u8); 4] = [(TZ1, 0), (TZ2, 1), (TZ3, 2), (TZ4, 3)];

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("openpgp-wallet")
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// The largest body read from a node or from TzKT. Their answers here are a few hundred
/// kilobytes at most (a page of history): beyond this limit it is not an answer.
const MAX_BODY: u64 = 4 * 1024 * 1024;

/// The JSON body of an answer, read up to [`MAX_BODY`].
fn body_json(response: reqwest::blocking::Response) -> Result<Value> {
    let bytes =
        crate::http_limit::read(response, MAX_BODY).context("réponse du nœud Tezos illisible")?;
    serde_json::from_slice(&bytes).context("réponse du nœud Tezos illisible")
}

/// The body of an answer as text, read up to [`MAX_BODY`]; empty when it cannot be read,
/// which every caller treats as an unreadable answer.
fn body_text(response: reqwest::blocking::Response) -> String {
    crate::http_limit::read(response, MAX_BODY)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

/// GET; `Ok(None)` when the server does not have the key: a 404, or the node's storage
/// error for a key its context lacks (`full_balance` of an account that never received
/// tez answers that, HTTP 500, where `balance` answers "0": seen on PsUshuai).
fn get_opt(base: &str, path: &str) -> Result<Option<Value>> {
    let response = client()
        .get(format!("{base}{path}"))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .context("nœud Tezos injoignable")?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        let body: Value = body_json(response).unwrap_or(Value::Null);
        if missing_key(&body) {
            return Ok(None);
        }
        bail!("nœud Tezos : réponse {status}");
    }
    ensure!(status.is_success(), "nœud Tezos : réponse {status}");
    Ok(Some(body_json(response)?))
}

/// A node's answer made only of storage errors on a missing key.
fn missing_key(body: &Value) -> bool {
    body.as_array().is_some_and(|errors| {
        !errors.is_empty()
            && errors.iter().all(|e| {
                e["id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(".context.storage_error"))
                    && e["missing_key"].is_array()
            })
    })
}

fn get(base: &str, path: &str) -> Result<Value> {
    get_opt(base, path)?.context("réponse du nœud Tezos illisible")
}

/// GET from the first node that answers (reads shown, not used to sign).
fn read_opt(net: &Network, path: &str) -> Result<Option<Value>> {
    let mut last = anyhow!("nœud Tezos injoignable");
    for node in net.rpc {
        match get_opt(node, path) {
            Ok(answer) => return Ok(answer),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Node for a send: the first one that answers for the network's chain.
fn node(net: &Network) -> Result<Node> {
    let mut last = anyhow!("nœud Tezos injoignable");
    let mut other_chain = false;
    for &url in net.rpc {
        match get(url, "/chains/main/chain_id") {
            Ok(chain) if chain.as_str() == Some(net.chain_id) => {
                return Ok(Node {
                    url,
                    chain_id: net.chain_id,
                })
            }
            Ok(_) => other_chain = true,
            Err(e) => last = e,
        }
    }
    if other_chain {
        bail!("le nœud Tezos répond pour une autre chaîne — envoi refusé");
    }
    Err(last)
}

/// POST to the send's node: (success, body).
fn post(node: Node, path: &str, body: &Value) -> Result<(bool, String)> {
    let response = client()
        .post(format!("{}{path}", node.url))
        .json(body)
        .send()
        .context("nœud Tezos injoignable")?;
    let ok = response.status().is_success();
    Ok((ok, body_text(response)))
}

fn mutez(value: &Value) -> Result<u64> {
    value
        .as_str()
        .and_then(|v| v.parse().ok())
        .or(value.as_u64())
        .context("montant Tezos illisible")
}

/// Amount in XTZ, 6 decimals ("12.500000").
pub fn format_xtz(mutez: u64) -> String {
    format!("{}.{:06}", mutez / 1_000_000, mutez % 1_000_000)
}

fn blake2b<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut state = Params::new().hash_length(N).to_state();
    for part in parts {
        state.update(part);
    }
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("longueur de condensé demandée")
}

fn b58check(prefix: &[u8], data: &[u8]) -> String {
    let mut payload = [prefix, data].concat();
    let check = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&check[..4]);
    bs58::encode(payload).into_string()
}

/// Data of a Base58Check string with this prefix and this length (checksum verified).
fn b58check_decode(text: &str, prefix: &[u8], len: usize) -> Option<Vec<u8>> {
    let bytes = bs58::decode(text).into_vec().ok()?;
    let (body, check) = bytes.split_at_checked(bytes.len().checked_sub(4)?)?;
    if Sha256::digest(Sha256::digest(body))[..4] != *check {
        return None;
    }
    let data = body.strip_prefix(prefix)?;
    (data.len() == len).then(|| data.to_vec())
}

// --- Addresses and keys ---------------------------------------------------------

/// Implicit account (tz1, tz2, tz3 or tz4): curve tag and key hash, as forged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Implicit {
    tag: u8,
    hash: [u8; 20],
}

impl Implicit {
    fn text(self) -> String {
        let prefix = IMPLICIT
            .iter()
            .find(|(_, tag)| *tag == self.tag)
            .map(|(prefix, _)| prefix)
            .expect("étiquette d'adresse connue");
        b58check(prefix, &self.hash)
    }

    /// `public_key_hash`: curve tag, then the 20-byte hash.
    fn forge(self, out: &mut Vec<u8>) {
        out.push(self.tag);
        out.extend_from_slice(&self.hash);
    }
}

/// Recipient address: an implicit account (tz1, tz2, tz3, tz4). Contract addresses
/// (KT1…) are refused: tez sent there could stay locked.
pub fn parse_address(text: &str) -> Result<Implicit> {
    let text = text.trim();
    if b58check_decode(text, &KT1, 20).is_some() {
        bail!(
            "adresse de contrat Tezos (KT1…) : envoi refusé, les fonds pourraient y rester bloqués"
        );
    }
    for (prefix, tag) in IMPLICIT {
        if let Some(hash) = b58check_decode(text, &prefix, 20) {
            let hash = hash.try_into().expect("20 octets vérifiés");
            return Ok(Implicit { tag, hash });
        }
    }
    if ["tz1", "tz2", "tz3", "tz4", "KT1"]
        .iter()
        .any(|p| text.starts_with(p))
    {
        bail!("adresse Tezos non reconnue : un caractère semble mal recopié");
    }
    bail!("adresse Tezos invalide (tz1…, tz2…, tz3… ou tz4… attendue)")
}

fn implicit_of(public_key: &[u8; 32]) -> Implicit {
    Implicit {
        tag: 0,
        hash: blake2b::<20>(&[public_key]),
    }
}

/// tz1 address of a key.
pub fn address_of(key: &SigningKey) -> String {
    implicit_of(&key.verifying_key().to_bytes()).text()
}

/// Public key as wallets write it (edpk…). Known without the password, it lets a send
/// be prepared before the confirmation dialog, reveal included.
pub fn public_key_text(key: &SigningKey) -> String {
    b58check(&EDPK, &key.verifying_key().to_bytes())
}

pub fn parse_public_key(text: &str) -> Result<[u8; 32]> {
    b58check_decode(text.trim(), &EDPK, 32)
        .and_then(|key| key.try_into().ok())
        .context("clé publique Tezos invalide")
}

/// tz1 address of a public key written edpk….
pub fn address_of_public_key(text: &str) -> Result<String> {
    Ok(implicit_of(&parse_public_key(text)?).text())
}

// --- Operations -----------------------------------------------------------------

/// Zarith natural number: 7 bits per byte, least significant first.
fn zarith(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Manager operation of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Content {
    /// Publishes the account's public key; required once, before its first send.
    Reveal {
        fee: u64,
        counter: u64,
        gas_limit: u64,
        storage_limit: u64,
        public_key: [u8; 32],
    },
    /// Tez transfer to an implicit account, without parameters.
    Transaction {
        fee: u64,
        counter: u64,
        gas_limit: u64,
        storage_limit: u64,
        amount: u64,
        destination: Implicit,
    },
}

impl Content {
    fn limits(&mut self) -> (&mut u64, &mut u64, &mut u64) {
        match self {
            Content::Reveal {
                fee,
                gas_limit,
                storage_limit,
                ..
            }
            | Content::Transaction {
                fee,
                gas_limit,
                storage_limit,
                ..
            } => (fee, gas_limit, storage_limit),
        }
    }

    fn fee(&self) -> u64 {
        match self {
            Content::Reveal { fee, .. } | Content::Transaction { fee, .. } => *fee,
        }
    }

    fn forge(&self, source: Implicit, out: &mut Vec<u8>) {
        match self {
            Content::Reveal {
                fee,
                counter,
                gas_limit,
                storage_limit,
                public_key,
            } => {
                out.push(107);
                source.forge(out);
                for n in [*fee, *counter, *gas_limit, *storage_limit] {
                    zarith(n, out);
                }
                out.push(0x00); // Ed25519 key
                out.extend_from_slice(public_key);
                out.push(0x00); // no proof (BLS keys only)
            }
            Content::Transaction {
                fee,
                counter,
                gas_limit,
                storage_limit,
                amount,
                destination,
            } => {
                out.push(108);
                source.forge(out);
                for n in [*fee, *counter, *gas_limit, *storage_limit, *amount] {
                    zarith(n, out);
                }
                out.push(0x00); // implicit account
                destination.forge(out);
                out.push(0x00); // no parameters
            }
        }
    }

    fn json(&self, source: &str) -> Value {
        match self {
            Content::Reveal {
                fee,
                counter,
                gas_limit,
                storage_limit,
                public_key,
            } => json!({
                "kind": "reveal",
                "source": source,
                "fee": fee.to_string(),
                "counter": counter.to_string(),
                "gas_limit": gas_limit.to_string(),
                "storage_limit": storage_limit.to_string(),
                "public_key": b58check(&EDPK, public_key),
            }),
            Content::Transaction {
                fee,
                counter,
                gas_limit,
                storage_limit,
                amount,
                destination,
            } => json!({
                "kind": "transaction",
                "source": source,
                "fee": fee.to_string(),
                "counter": counter.to_string(),
                "gas_limit": gas_limit.to_string(),
                "storage_limit": storage_limit.to_string(),
                "amount": amount.to_string(),
                "destination": destination.text(),
            }),
        }
    }
}

/// An unsigned operation: branch (block hash), source and contents.
#[derive(Clone, Debug)]
struct Operation {
    branch: [u8; 32],
    source: Implicit,
    contents: Vec<Content>,
}

impl Operation {
    fn forge(&self) -> Vec<u8> {
        let mut out = self.branch.to_vec();
        for content in &self.contents {
            content.forge(self.source, &mut out);
        }
        out
    }

    fn branch_text(&self) -> String {
        b58check(&BLOCK_HASH, &self.branch)
    }

    fn contents_json(&self) -> Vec<Value> {
        let source = self.source.text();
        self.contents.iter().map(|c| c.json(&source)).collect()
    }
}

/// Signature of forged bytes: Ed25519 over BLAKE2b-256(0x03 ‖ bytes).
fn sign_forged(key: &SigningKey, forged: &[u8]) -> [u8; 64] {
    key.sign(&blake2b::<32>(&[&[0x03], forged])).to_bytes()
}

/// Operation hash (o…) of the signed bytes.
fn operation_hash(signed: &[u8]) -> String {
    b58check(&OPERATION_HASH, &blake2b::<32>(&[signed]))
}

// --- Node -----------------------------------------------------------------------

/// Error identifiers of a node's answer (JSON list of errors), without the protocol
/// prefix ("proto.025-PsUshuai.").
fn error_ids(errors: &Value) -> Vec<String> {
    errors
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e["id"].as_str())
        .map(|id| match id.split_once('.') {
            Some(("proto", rest)) => rest.split_once('.').map_or(rest, |(_, r)| r).to_string(),
            _ => id.to_string(),
        })
        .collect()
}

/// Refusal of a send while another one of the account has not been included yet.
const PENDING_SEND: &str =
    "un autre envoi Tezos de ce compte est en cours — attendez sa confirmation puis relancez";

/// The node's mempool already holds an operation of this account: its answer to an
/// injection while a first send is pending. The identifier is a bare "failure" and the
/// reason is only in the message (seen on Shadownet, Octez 25); the identifiers of
/// older versions are recognized too.
fn mempool_conflict(errors: &Value) -> bool {
    errors
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .any(|e| {
            e["id"]
                .as_str()
                .is_some_and(|id| id.contains("manager_restriction") || id.contains("conflict"))
                || e["msg"]
                    .as_str()
                    .is_some_and(|msg| msg.contains("conflicting operation"))
        })
}

/// A node's refusal in plain words.
fn refusal(ids: &[String]) -> String {
    let has = |part: &str| ids.iter().any(|id| id.contains(part));
    if has("balance_too_low") || has("cannot_pay_storage_fee") || has("subtraction_underflow") {
        "XTZ insuffisants pour ce virement et ses frais".to_string()
    } else if has("signature") {
        "signature Tezos refusée par le nœud".to_string()
    } else if has("counter") {
        PENDING_SEND.to_string()
    } else {
        let id: String = ids
            .last()
            .map(String::as_str)
            .unwrap_or("?")
            .chars()
            .take(120)
            .collect();
        format!("opération Tezos refusée par le nœud : {id}")
    }
}

/// Statuses of an applied (or simulated) operation: `Ok` only if the node answered for
/// each of the `expected` contents and applied every one. An answer of another shape
/// (nothing, an empty list) is no approval.
fn ensure_applied(contents: &Value, expected: usize) -> Result<()> {
    let contents = contents.as_array().map(Vec::as_slice).unwrap_or_default();
    ensure!(
        contents.len() == expected,
        "nœud Tezos : réponse inattendue"
    );
    for content in contents {
        let result = &content["metadata"]["operation_result"];
        if result["status"].as_str() != Some("applied") {
            let mut ids = error_ids(&result["errors"]);
            if ids.is_empty() {
                ids.push(result["status"].as_str().unwrap_or("?").to_string());
            }
            bail!("{}", refusal(&ids));
        }
    }
    Ok(())
}

/// Response to a POST: JSON, or the node's refusal.
fn post_json(node: Node, path: &str, body: &Value) -> Result<Value> {
    let (ok, text) = post(node, path, body)?;
    let value: Option<Value> = serde_json::from_str(&text).ok();
    if !ok {
        let ids = value.as_ref().map(error_ids).unwrap_or_default();
        ensure!(!ids.is_empty(), "nœud Tezos : réponse inattendue");
        bail!("{}", refusal(&ids));
    }
    value.context("réponse du nœud Tezos illisible")
}

/// Head of the chain: branch (head~2, safe from a reorganization), next protocol.
fn head(node: Node) -> Result<([u8; 32], String)> {
    let hash = get(node.url, "/chains/main/blocks/head~2/hash")?;
    let branch = hash
        .as_str()
        .and_then(|h| b58check_decode(h, &BLOCK_HASH, 32))
        .and_then(|b| b.try_into().ok())
        .context("bloc Tezos illisible")?;
    let protocol = get(node.url, "/chains/main/blocks/head/protocols")?["next_protocol"]
        .as_str()
        .context("protocole Tezos illisible")?
        .to_string();
    Ok((branch, protocol))
}

fn contract_path(address: &str) -> String {
    format!("/chains/main/blocks/head/context/contracts/{address}")
}

/// Balance the account can spend (excluding staked tez).
fn spendable(node: Node, address: &str) -> Result<u64> {
    match get_opt(node.url, &format!("{}/balance", contract_path(address)))? {
        Some(value) => mutez(&value),
        None => Ok(0),
    }
}

/// Full balance (staked tez included); 0 for an account that never received tez.
pub fn balance(net: &Network, address: &str) -> Result<u64> {
    let address = parse_address(address)?.text();
    match read_opt(net, &format!("{}/full_balance", contract_path(&address)))? {
        Some(value) => mutez(&value),
        None => Ok(0),
    }
}

/// Activity of a recipient address: (holds tez, has been used before).
pub fn address_activity(net: &Network, address: &str) -> Result<(bool, bool)> {
    let address = parse_address(address)?.text();
    let account = get(net.tzkt, &format!("/v1/accounts/{address}"))?;
    if account["type"].as_str() == Some("empty") {
        return Ok((false, false));
    }
    let held = account["balance"].as_u64().unwrap_or(0) > 0;
    Ok((held, true))
}

/// Protocol constants this module needs: (cost per byte of storage, size of a new
/// account, gas per operation, storage per operation).
fn constants(node: Node) -> Result<(u64, u64, u64, u64)> {
    let c = get(node.url, "/chains/main/blocks/head/context/constants")?;
    let read =
        |name: &str| mutez(&c[name]).with_context(|| format!("constante Tezos {name} illisible"));
    Ok((
        read("cost_per_byte")?,
        read("origination_size")?,
        read("hard_gas_limit_per_operation")?,
        read("hard_storage_limit_per_operation")?,
    ))
}

/// Results of a simulation, one per content.
fn simulate(node: Node, op: &Operation) -> Result<Vec<Value>> {
    let operation = json!({
        "branch": op.branch_text(),
        "contents": op.contents_json(),
        // The simulation does not check the signature.
        "signature": b58check(&EDSIG, &[0; 64]),
    });
    let response = post_json(
        node,
        "/chains/main/blocks/head/helpers/scripts/simulate_operation",
        &json!({ "operation": operation, "chain_id": node.chain_id }),
    )?;
    ensure_applied(&response["contents"], op.contents.len())?;
    response["contents"]
        .as_array()
        .cloned()
        .context("simulation Tezos illisible")
}

/// What a simulated content needs: (gas limit, storage limit, whether it creates the
/// recipient's account). A transfer between implicit accounts stores nothing: only the
/// creation of the recipient's account is paid for, at the protocol's fixed size. An
/// answer that says otherwise is refused, not turned into limits to sign.
fn simulated_limits(
    result: &Value,
    transfer: bool,
    origination_size: u64,
) -> Result<(u64, u64, bool)> {
    let milligas = mutez(&result["consumed_milligas"]).context("simulation Tezos illisible")?;
    let allocates = result["allocated_destination_contract"].as_bool() == Some(true);
    let stored = match result.get("paid_storage_size_diff") {
        Some(diff) => mutez(diff).context("simulation Tezos illisible")?,
        None => 0,
    };
    ensure!(
        stored == 0 && (transfer || !allocates),
        "simulation Tezos illisible"
    );
    Ok((
        milligas.div_ceil(1000) + GAS_MARGIN,
        if allocates { origination_size } else { 0 },
        allocates,
    ))
}

/// Send prepared for the confirmation dialog.
#[derive(Clone, Copy, Debug)]
pub struct XtzPlan {
    pub amount: u64,
    /// Baker fees of the whole operation (reveal included).
    pub fee: u64,
    /// Tez burned for the storage the payment creates (a new recipient account).
    pub burn: u64,
    /// The account's public key is published with this send (its first one).
    pub reveal: bool,
    /// The payment creates the recipient's account (never used yet).
    pub creates: bool,
}

impl XtzPlan {
    /// What the send costs on top of the amount.
    pub fn cost(&self) -> u64 {
        self.fee.saturating_add(self.burn)
    }
}

struct Prepared {
    op: Operation,
    protocol: String,
    plan: XtzPlan,
}

/// Builds the operation: counter, reveal if needed, gas and storage from a simulation,
/// fees by the mempool rule. `destination = None`: a transfer to the account itself,
/// only to size the "Max" button.
fn prepare(
    node: Node,
    public_key: &[u8; 32],
    destination: Option<Implicit>,
    amount: u64,
    fee_amount: u64,
) -> Result<Prepared> {
    ensure!(amount > 0, "montant nul");
    let source = implicit_of(public_key);
    let source_text = source.text();
    if let Some(destination) = destination {
        ensure!(
            destination != source,
            "envoi vers votre propre adresse Tezos"
        );
    }
    let spendable = spendable(node, &source_text)?;
    ensure!(
        amount <= spendable,
        "XTZ insuffisants : {} XTZ disponibles, {} XTZ demandés",
        format_xtz(spendable),
        format_xtz(amount)
    );
    let (branch, protocol) = head(node)?;
    let counter = get_opt(
        node.url,
        &format!("{}/counter", contract_path(&source_text)),
    )?
    .map(|c| mutez(&c))
    .transpose()?
    .context("compte Tezos vide : il doit d'abord recevoir des XTZ")?;
    let revealed = !get(
        node.url,
        &format!("{}/manager_key", contract_path(&source_text)),
    )?
    .is_null();
    let (cost_per_byte, origination_size, hard_gas, hard_storage) = constants(node)?;

    // The counters come from the node: an absurd one is an unreadable answer, never an
    // overflow.
    let first_counter = counter
        .checked_add(1)
        .context("réponse du nœud Tezos illisible")?;
    let transfer_counter = first_counter
        .checked_add(u64::from(!revealed))
        .context("réponse du nœud Tezos illisible")?;
    let mut contents = Vec::new();
    if !revealed {
        contents.push(Content::Reveal {
            fee: 0,
            counter: first_counter,
            gas_limit: 0,
            storage_limit: 0,
            public_key: *public_key,
        });
    }
    contents.push(Content::Transaction {
        fee: 0,
        counter: transfer_counter,
        gas_limit: 0,
        storage_limit: hard_storage,
        amount,
        destination: destination.unwrap_or(source),
    });
    let per_op_gas = hard_gas / contents.len() as u64;
    for content in &mut contents {
        *content.limits().1 = per_op_gas;
    }
    let mut op = Operation {
        branch,
        source,
        contents,
    };

    // Gas and storage: what the simulation consumed.
    let results = simulate(node, &op)?;
    let (mut burn, mut creates) = (0, false);
    for (content, result) in op.contents.iter_mut().zip(&results) {
        let transfer = matches!(content, Content::Transaction { .. });
        let (gas, storage, allocates) = simulated_limits(
            &result["metadata"]["operation_result"],
            transfer,
            origination_size,
        )?;
        let (_, gas_limit, storage_limit) = content.limits();
        *gas_limit = gas;
        *storage_limit = storage;
        if transfer {
            // The constants come from the node too: a product that does not fit is
            // above any cap.
            burn = storage.saturating_mul(cost_per_byte);
            creates = allocates;
        }
    }

    // Fees by the mempool rule, with a 10% margin; the fee changes the size, so twice.
    // `fee_amount` sizes the amount field ("Max": the largest amount that can be sent).
    let mut sizing = op.clone();
    if let Some(Content::Transaction { amount, .. }) = sizing.contents.last_mut() {
        *amount = fee_amount.max(*amount);
    }
    for _ in 0..3 {
        for i in 0..sizing.contents.len() {
            let mut bytes = Vec::new();
            sizing.contents[i].forge(source, &mut bytes);
            let gas = *sizing.contents[i].limits().1;
            let fee = MINIMAL_FEE + bytes.len() as u64 + HEADER_AND_SIGNATURE + gas.div_ceil(10);
            *sizing.contents[i].limits().0 = fee + fee.div_ceil(10);
        }
    }
    for (content, sized) in op.contents.iter_mut().zip(&sizing.contents) {
        *content.limits().0 = sized.fee();
    }
    let fee: u64 = op.contents.iter().map(Content::fee).sum();
    ensure!(
        fee <= MAX_FEE,
        "frais du réseau Tezos anormalement élevés ({} XTZ) — réessayez plus tard",
        format_xtz(fee)
    );
    ensure!(
        burn <= MAX_BURN,
        "stockage Tezos anormalement cher ({} XTZ) — envoi refusé",
        format_xtz(burn)
    );
    Ok(Prepared {
        op,
        protocol,
        plan: XtzPlan {
            amount,
            fee,
            burn,
            reveal: !revealed,
            creates,
        },
    })
}

/// Checks the balance covers the amount and the plan's costs.
fn ensure_funds(node: Node, address: &str, plan: &XtzPlan) -> Result<()> {
    let spendable = spendable(node, address)?;
    ensure!(
        plan.amount
            .checked_add(plan.cost())
            .is_some_and(|need| need <= spendable),
        "XTZ insuffisants : {} XTZ disponibles, {} XTZ + {} XTZ de frais demandés",
        format_xtz(spendable),
        format_xtz(plan.amount),
        format_xtz(plan.cost())
    );
    Ok(())
}

/// Send prepared for the confirmation dialog, from the account's public key (edpk…).
pub fn plan(net: &Network, from_public_key: &str, to: &str, amount: u64) -> Result<XtzPlan> {
    let public_key = parse_public_key(from_public_key)?;
    let destination = parse_address(to)?;
    let node = node(net)?;
    let prepared = prepare(node, &public_key, Some(destination), amount, amount)?;
    ensure_funds(node, &implicit_of(&public_key).text(), &prepared.plan)?;
    Ok(prepared.plan)
}

/// Largest amount that can be sent: spendable balance minus the fees (and the burn,
/// when `to` is a new account).
pub fn max_amount(net: &Network, from_public_key: &str, to: Option<&str>) -> Result<u64> {
    let public_key = parse_public_key(from_public_key)?;
    let destination = to.map(parse_address).transpose()?;
    let node = node(net)?;
    let spendable = spendable(node, &implicit_of(&public_key).text())?;
    ensure!(spendable > 0, "aucun XTZ envoyable sur cette adresse");
    let prepared = prepare(node, &public_key, destination, 1, spendable)?;
    spendable
        .checked_sub(prepared.plan.cost())
        .filter(|m| *m > 0)
        .context("XTZ insuffisants pour couvrir les frais du réseau")
}

/// Builds, checks, signs and broadcasts a send; the fees and burn never exceed
/// `shown_cost` (what the dialog showed). Returns the operation hash.
pub fn send(
    net: &Network,
    key: &SigningKey,
    to: &str,
    amount: u64,
    shown_cost: u64,
) -> Result<String> {
    let public_key = key.verifying_key().to_bytes();
    let node = node(net)?;
    let prepared = prepare(node, &public_key, Some(parse_address(to)?), amount, amount)?;
    ensure!(
        prepared.plan.cost() <= shown_cost,
        "les frais Tezos ont augmenté depuis la confirmation ({} au lieu de {} XTZ) — relancez l'envoi",
        format_xtz(prepared.plan.cost()),
        format_xtz(shown_cost)
    );
    ensure_funds(node, &address_of(key), &prepared.plan)?;
    let forged = prepared.op.forge();
    ensure_node_forges_the_same(node, &prepared.op, &forged)?;
    let signature = sign_forged(key, &forged);
    preapply(node, &prepared, &signature)?;
    inject(node, &[forged, signature.to_vec()].concat())
}

/// The node forges the operation's JSON into the same bytes as this module: otherwise
/// the encoding changed with a protocol, and nothing is signed.
fn ensure_node_forges_the_same(node: Node, op: &Operation, forged: &[u8]) -> Result<()> {
    let bytes = post_json(
        node,
        "/chains/main/blocks/head/helpers/forge/operations",
        &json!({ "branch": op.branch_text(), "contents": op.contents_json() }),
    )?;
    ensure!(
        bytes.as_str() == Some(hex::encode(forged).as_str()),
        "encodage Tezos différent de celui du nœud (nouveau protocole ?) — envoi refusé, mettez l'app à jour"
    );
    Ok(())
}

/// The node applies the signed operation in a test block, without relaying it.
fn preapply(node: Node, prepared: &Prepared, signature: &[u8; 64]) -> Result<()> {
    let response = post_json(
        node,
        "/chains/main/blocks/head/helpers/preapply/operations",
        &json!([{
            "protocol": prepared.protocol,
            "branch": prepared.op.branch_text(),
            "contents": prepared.op.contents_json(),
            "signature": b58check(&EDSIG, signature),
        }]),
    )?;
    ensure_applied(&response[0]["contents"], prepared.op.contents.len())
}

/// Broadcasts signed bytes; returns their hash.
fn inject(node: Node, signed: &[u8]) -> Result<String> {
    let hash = operation_hash(signed);
    let response = client()
        .post(format!("{}/injection/operation?chain=main", node.url))
        .json(&hex::encode(signed))
        .send()
        .map_err(|e| crate::wallet_flow::broadcast_failure(e, "nœud Tezos injoignable", &hash))?;
    let status = response.status();
    let text = body_text(response);
    if status.is_success() {
        // Accepted: an answer other than our hash must not make it look refused, since
        // sending again would pay twice.
        if text.trim().trim_matches('"') != hash {
            return Err(crate::wallet_flow::maybe_sent(&hash));
        }
        return Ok(hash);
    }
    // The node's own refusal is a JSON list of errors: nothing went out. Anything else
    // (gateway, timeout page): maybe sent.
    let errors = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    if mempool_conflict(&errors) {
        bail!(PENDING_SEND);
    }
    let ids = error_ids(&errors);
    if !ids.is_empty() {
        bail!("{}", refusal(&ids));
    }
    if crate::wallet_flow::server_error_may_have_sent(status) {
        return Err(crate::wallet_flow::maybe_sent(&hash));
    }
    bail!("opération Tezos refusée (réponse {status})")
}

// --- History --------------------------------------------------------------------

/// Tez transfers of the address (TzKT), newest first: received amounts, and sent
/// amounts with their fees and burn on top (`fee_minor`, as for Ethereum).
pub fn history(net: &Network, address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    let address = parse_address(address)?.text();
    let list = get(
        net.tzkt,
        &format!(
            "/v1/accounts/{address}/operations?type=transaction&limit={}",
            limit.clamp(1, 100)
        ),
    )?;
    Ok(history_entries(&list, &address))
}

/// Entries of TzKT's transaction list for `address` (see `history`).
fn history_entries(list: &Value, address: &str) -> Vec<history::TxEntry> {
    let mut entries = Vec::new();
    for item in list.as_array().map(Vec::as_slice).unwrap_or_default() {
        let Some(id) = item["hash"]
            .as_str()
            .filter(|h| b58check_decode(h, &OPERATION_HASH, 32).is_some())
        else {
            continue;
        };
        let applied = item["status"].as_str() == Some("applied");
        let amount = i128::from(item["amount"].as_u64().unwrap_or(0));
        let sent = item["sender"]["address"].as_str() == Some(address);
        let received = item["target"]["address"].as_str() == Some(address);
        let fees: i128 = ["bakerFee", "storageFee", "allocationFee"]
            .iter()
            .map(|f| i128::from(item[*f].as_u64().unwrap_or(0)))
            .sum();
        let (net_amount, fee) = match (sent, received) {
            (true, true) => (0, fees),
            (true, false) => (if applied { -amount } else { 0 }, fees),
            (false, true) => (if applied { amount } else { 0 }, 0),
            (false, false) => continue,
        };
        if net_amount == 0 && fee == 0 {
            continue;
        }
        entries.push(history::TxEntry {
            id: id.to_string(),
            timestamp_unix: item["timestamp"]
                .as_str()
                .and_then(crate::blockscout::parse_iso8601_utc),
            status: if applied {
                history::TxStatus::Confirmed
            } else {
                history::TxStatus::Failed
            },
            net_amount_minor: Some(net_amount),
            fee_minor: fee,
            // No tez moved (a token transfer, a call to a contract, a failed send, a
            // payment to oneself): "Other", as for the other networks, not "Sent".
            kind: match net_amount {
                n if n > 0 => history::TxKind::Received,
                n if n < 0 => history::TxKind::Sent,
                _ => history::TxKind::Other,
            },
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP39 seed of "abandon abandon … about" (empty passphrase).
    const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn key(index: u32) -> SigningKey {
        crate::derivation::derive_tezos_key(&hex::decode(SEED).unwrap(), index)
    }

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// Taquito's vectors (packages/taquito-signer/test/fixtures/mnemonic-keys.json):
    /// "defaults" (m/44'/1729'/0'/0') and "account one" (m/44'/1729'/1'/0'). The mainnet
    /// shows the first key for that address too (revealed account).
    #[test]
    fn keys_match_taquito() {
        for (index, address, public_key) in [
            (
                0,
                "tz1VQA4RP4fLjEEMW2FR4pE9kAg5abb5h5GL",
                "edpku4US3ZykcZifjzSGFCmFr3zRgCKndE82estE4irj4d5oqDNDvf",
            ),
            (
                1,
                "tz1gvekQVEwFFdxT2KrcY6kZgFK1qMN3mmWF",
                "edpku4J2bq38SAaNrP6kLV34ZzTBWu9FwLmmeFaXV3XzozUckyEvb6",
            ),
        ] {
            assert_eq!(address_of(&key(index)), address);
            assert_eq!(public_key_text(&key(index)), public_key);
            assert_eq!(address_of_public_key(public_key).unwrap(), address);
        }
    }

    /// Trust Wallet Core's address vectors (tests/chains/Tezos/AddressTests.cpp).
    #[test]
    fn addresses_match_trust_wallet_core() {
        for (address, forged) in [
            (
                "tz1eZwq8b5cvE2bPKokatLkVMzkxz24z3Don",
                "0000cfa4aae60f5d9389752d41e320da224d43287fe2",
            ),
            (
                "tz2Rh3NYeLxrqTuvaZJmaMiVMqCajeXMWtYo",
                "0001be99dd914e38388ec80432818b517759e3524f16",
            ),
            (
                "tz3RDC3Jdn4j15J7bBHZd29EUee9gVB1CxD9",
                "0002358cbffa97149631cfb999fa47f0035fb1ea8636",
            ),
        ] {
            let parsed = parse_address(address).unwrap();
            let mut bytes = vec![0x00];
            parsed.forge(&mut bytes);
            assert_eq!(hex::encode(bytes), forged, "{address}");
            assert_eq!(parsed.text(), address);
        }
        assert_eq!(
            implicit_of(&unhex(
                "fe157cc8011727936c592f856c9071d39cf4acdadfa6d76435e4619c9dc56f63"
            ))
            .text(),
            "tz1cG2jx3W4bZFeVGBjsTxUAG8tdpTXtE8PT"
        );
        for valid in [
            "tz1Yju7jmmsaUiG9qQLoYv35v5pHgnWoLWbt",
            "tz2PdGc7U5tiyqPgTSgqCDct94qd6ovQwP6u",
            "tz3VEZ4k6a4Wx42iyev6i2aVAptTRLEAivNN",
        ] {
            assert!(parse_address(valid).is_ok(), "{valid}");
        }
        // A tz4 (BLS) address is an account like the others.
        let tz4 = b58check(&TZ4, &[7; 20]);
        assert!(tz4.starts_with("tz4"));
        assert_eq!(parse_address(&tz4).unwrap().tag, 3);
        let error = |a: &str| parse_address(a).unwrap_err().to_string();
        assert!(error("KT1XnTn74bUtxHfDtBmm2bGZAQfhPbvKWR8o").contains("contrat"));
        assert!(error("tz1eZwq8b5cvE2bPKokatLkVMzkxz24z3AAAA").contains("mal recopié"));
        assert!(error("NmH7tmeJUmHcncBDvpr7aJNEBk7rp5zYsB1qt").contains("invalide"));
        assert!(
            error("tz1eZwq8b5cvE2bPKokatLkVMzkxz24z3Don\0garbage").contains("invalide")
                || error("tz1eZwq8b5cvE2bPKokatLkVMzkxz24z3Don\0garbage").contains("mal recopié")
        );
        assert!(
            parse_public_key("edpku4US3ZykcZifjzSGFCmFr3zRgCKndE82estE4irj4d5oqDNDvX").is_err()
        );
    }

    #[test]
    fn zarith_numbers() {
        for (n, expected) in [
            (0, "00"),
            (1, "01"),
            (127, "7f"),
            (128, "8001"),
            (171, "ab01"),
            (257, "8102"),
            (1234, "d209"),
            (1_000_000, "c0843d"),
        ] {
            let mut out = Vec::new();
            zarith(n, &mut out);
            assert_eq!(hex::encode(out), expected, "{n}");
        }
    }

    /// A reveal and a transfer forged by a mainnet node (protocol PsUshuai, Octez 25.2,
    /// /helpers/forge/operations) for this JSON: the same bytes here.
    #[test]
    fn operations_match_a_mainnet_node() {
        let public_key =
            parse_public_key("edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav").unwrap();
        let source = implicit_of(&public_key);
        assert_eq!(source.text(), "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx");
        let branch = b58check_decode(
            "BMX6K5JRwcd6z8Pi5hzgLcx37huisECHqsxekg7Uc2KwZSez77N",
            &BLOCK_HASH,
            32,
        )
        .unwrap();
        let op = Operation {
            branch: branch.try_into().unwrap(),
            source,
            contents: vec![
                Content::Reveal {
                    fee: 1234,
                    counter: 5,
                    gas_limit: 171,
                    storage_limit: 0,
                    public_key,
                },
                Content::Transaction {
                    fee: 405,
                    counter: 6,
                    gas_limit: 1527,
                    storage_limit: 257,
                    amount: 1_000_000,
                    destination: source,
                },
            ],
        };
        assert_eq!(
            hex::encode(op.forge()),
            "edfbda7e46d73162afa8fc3e0172b8136f377edc980a79cf7911b917ef65f58a6b0002298c03ed7d454a101eb7022bc95f7e5f41ac78d20905ab0100004798d2cc98473d7e250c898885718afd2e4efbcb1a1595ab9730761ed830de0f006c0002298c03ed7d454a101eb7022bc95f7e5f41ac78950306f70b8102c0843d000002298c03ed7d454a101eb7022bc95f7e5f41ac7800"
        );
        assert_eq!(
            op.contents_json()[0]["public_key"],
            "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav"
        );
        assert_eq!(
            op.contents_json()[1]["destination"],
            "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
        );
        assert_eq!(
            op.branch_text(),
            "BMX6K5JRwcd6z8Pi5hzgLcx37huisECHqsxekg7Uc2KwZSez77N"
        );
    }

    /// Trust Wallet Core's "BlindSign" vector (tests/chains/Tezos/TWAnySignerTests.cpp):
    /// the same signature of the same bytes with the same key.
    #[test]
    fn signature_matches_trust_wallet_core() {
        let key = SigningKey::from_bytes(&unhex(
            "3caf5afaed067890cd850efd1555df351aa482badb4a541c29261f1acf261bf5",
        ));
        let bytes = hex::decode(include_str!("../testdata/tezos_blind_sign.hex").trim()).unwrap();
        assert_eq!(
            hex::encode(sign_forged(&key, &bytes)),
            "e10077fc3068aaaf1c7779e1dc2c396b3b40d73ddda04648bf4b16ac2e747c89b461771488e80da3aa30fc18c90de99fd358bfb76683f3c3ec250b1ee09b6d07"
        );
        let hash = operation_hash(&[bytes, vec![0; 64]].concat());
        assert!(hash.starts_with('o') && hash.len() == 51, "{hash}");
    }

    #[test]
    fn node_errors_are_explained() {
        let errors =
            json!([{ "kind": "temporary", "id": "proto.025-PsUshuai.contract.balance_too_low" }]);
        assert_eq!(error_ids(&errors), vec!["contract.balance_too_low"]);
        assert!(refusal(&error_ids(&errors)).contains("insuffisants"));
        let signature =
            json!([{ "id": "proto.025-PsUshuai.validate.operation.invalid_signature" }]);
        assert!(refusal(&error_ids(&signature)).contains("signature"));
        assert!(refusal(&["something.else".to_string()]).ends_with("something.else"));
        assert_eq!(format_xtz(64_250), "0.064250");
    }

    /// An approval is an answer for every content, each applied. Nothing, an empty
    /// list or a list of another length is none: a preapply answering `{}` used to
    /// pass (audit round 34).
    #[test]
    fn an_answer_that_does_not_cover_the_operation_is_no_approval() {
        let applied = json!({ "metadata": { "operation_result": { "status": "applied" } } });
        assert!(ensure_applied(&json!([applied]), 1).is_ok());
        assert!(ensure_applied(&json!([applied, applied]), 2).is_ok());
        for (answer, expected) in [
            (Value::Null, 1),
            (json!({}), 1),
            (json!([]), 1),
            (json!([applied]), 2),
            (json!([applied, applied]), 1),
        ] {
            let error = ensure_applied(&answer, expected).unwrap_err().to_string();
            assert_eq!(error, "nœud Tezos : réponse inattendue", "{answer}");
        }
        let failed = json!({ "metadata": { "operation_result": {
            "status": "failed",
            "errors": [{ "id": "proto.025-PsUshuai.contract.balance_too_low" }],
        } } });
        let error = ensure_applied(&json!([applied, failed]), 2).unwrap_err();
        assert!(error.to_string().contains("insuffisants"), "{error}");
        // No status at all is not "applied".
        assert!(ensure_applied(&json!([{ "metadata": {} }]), 1).is_err());
    }

    /// A second send while the first one waits in the mempool: the answer a Shadownet
    /// node gave to the injection (HTTP 500; nothing went out, and the first send was
    /// included alone). It reads as "another send is pending", not as a bare "failure".
    #[test]
    fn a_send_while_another_one_is_pending_says_so() {
        let answer = json!([
            { "kind": "permanent", "id": "async_injection_failed" },
            {
                "kind": "temporary",
                "id": "failure",
                "msg": "Error while validating injected operation opKxMS7YJLYPBDaNTiHSAgnZ9PjYFxSGP6xnKsbwbtd9PLkvig6:
Error:
  The operation opKxMS7YJLYPBDaNTiHSAgnZ9PjYFxSGP6xnKsbwbtd9PLkvig6 cannot be added because the mempool already contains a conflicting operation. To replace the latter, this particular operation would need a total fee of at least 557 mutez.
",
            },
        ]);
        assert!(mempool_conflict(&answer));
        assert!(mempool_conflict(&json!([
            { "id": "proto.025-PsUshuai.validate.operation.manager_restriction" }
        ])));
        for other in [
            Value::Null,
            json!([]),
            json!([{ "id": "proto.025-PsUshuai.contract.balance_too_low" }]),
            json!([{ "id": "failure", "msg": "timeout" }]),
        ] {
            assert!(!mempool_conflict(&other), "{other}");
        }
        // A used counter (the first send was included meanwhile) says the same.
        assert_eq!(
            refusal(&["contract.counter_in_the_past".to_string()]),
            PENDING_SEND
        );
    }

    /// Limits read from a simulation, with the two answers a Shadownet node gave (an
    /// existing recipient, then a new one). What a plain transfer cannot produce is
    /// refused: no gas figure, storage paid for, an account created by a reveal.
    #[test]
    fn simulation_results_are_read_strictly() {
        let existing = json!({ "status": "applied", "consumed_milligas": "2168821" });
        assert_eq!(
            simulated_limits(&existing, true, 257).unwrap(),
            (2269, 0, false)
        );
        let new = json!({
            "status": "applied",
            "consumed_milligas": "2168821",
            "allocated_destination_contract": true,
        });
        assert_eq!(
            simulated_limits(&new, true, 257).unwrap(),
            (2269, 257, true)
        );
        assert!(simulated_limits(&new, false, 257).is_err());
        for odd in [
            json!({ "status": "applied" }),
            json!({ "consumed_milligas": "abc" }),
            json!({ "consumed_milligas": "1000", "paid_storage_size_diff": "5" }),
            json!({ "consumed_milligas": "1000", "paid_storage_size_diff": "x" }),
            json!({
                "consumed_milligas": "1000",
                "paid_storage_size_diff": "18446744073709551615",
                "allocated_destination_contract": true,
            }),
        ] {
            let error = simulated_limits(&odd, true, 257).unwrap_err().to_string();
            assert_eq!(error, "simulation Tezos illisible", "{odd}");
        }
        let zero = json!({ "consumed_milligas": "1000", "paid_storage_size_diff": "0" });
        assert_eq!(simulated_limits(&zero, true, 257).unwrap(), (101, 0, false));
        // The largest gas a node can state still gives a limit: the fee cap refuses it.
        let huge = json!({ "consumed_milligas": "18446744073709551615" });
        assert!(simulated_limits(&huge, true, 257).is_ok());
    }

    /// History lines from TzKT items (fields as TzKT returns them): tez received, tez
    /// sent with fees and burn apart, and "Other" when no tez moved (a token transfer
    /// to a KT1, a failed send, a payment to oneself), fees still counted.
    #[test]
    fn history_lines_follow_the_tez_that_moved() {
        let me = "tz1hwbDzkk2uWTUNDtRHd66RN3sWYPmvnReB";
        let other = "tz1iEFa4VJx8mjeianYjxUd3Xze3Rp7PrCYt";
        let item = |hash: &str, status: &str, from: &str, to: &str, amount: u64, fees: [u64; 3]| {
            json!({
                "hash": hash,
                "status": status,
                "timestamp": "2026-11-24T17:20:02Z",
                "sender": { "address": from },
                "target": { "address": to },
                "amount": amount,
                "bakerFee": fees[0],
                "storageFee": fees[1],
                "allocationFee": fees[2],
            })
        };
        let list = json!([
            item(
                "oosqjKCHVcSm2gZVQN4ziuBKbWeFvKszeQqjeSLpECRhLf4sFT6",
                "applied",
                other,
                me,
                10_000_000,
                [400, 0, 0]
            ),
            item(
                "ooHrXCtuAGW7v2GC78Mb1hoK88VFsvobcGBWbA6tVPoMwbidJb6",
                "applied",
                me,
                other,
                2_000_000,
                [523, 0, 64_250]
            ),
            item(
                "ooD9P8dfXJDAThS3fNnMn9T3DpigSGQN7UZSDksjkC6e63eMu8H",
                "applied",
                me,
                "KT1VaEsVNiBoA56eToEK6n6BcPgh1tdx9eXi",
                0,
                [633, 0, 0]
            ),
            item(
                "opDHFoxKnBxAP6CjeoQzgJ5ZkiMaJpATQxhECYvufejczRcdWZY",
                "failed",
                me,
                other,
                5_000_000,
                [500, 0, 0]
            ),
            item(
                "oojBgndDEuJo8UsZfiq63iRuWWnH4SbRGcQMyW86H5f4qvuPJu7",
                "applied",
                me,
                me,
                3_000_000,
                [300, 0, 0]
            ),
            // Not applied on the receiving side: nothing came in, nothing to show.
            item(
                "oonsN5UPoawXidfX31oKZ1bjuUWyJNHhBUueXSzYYr3CGoeyC5N",
                "backtracked",
                other,
                me,
                1_000_000,
                [400, 0, 0]
            ),
            // Not an operation hash.
            item("not-a-hash", "applied", other, me, 1, [0, 0, 0]),
        ]);
        let lines: Vec<_> = history_entries(&list, me)
            .into_iter()
            .map(|e| {
                let status = match e.status {
                    history::TxStatus::Confirmed => "confirmed",
                    history::TxStatus::Failed => "failed",
                    _ => "other",
                };
                (
                    e.net_amount_minor,
                    e.fee_minor,
                    e.kind,
                    status,
                    e.timestamp_unix.is_some(),
                )
            })
            .collect();
        use history::TxKind::*;
        assert_eq!(
            lines,
            [
                (Some(10_000_000), 0, Received, "confirmed", true),
                (Some(-2_000_000), 64_773, Sent, "confirmed", true),
                (Some(0), 633, Other, "confirmed", true),
                (Some(0), 500, Other, "failed", true),
                (Some(0), 300, Other, "confirmed", true),
            ]
        );
    }

    /// `full_balance` of an account outside the context (never funded, or emptied): the
    /// node's exact answer (HTTP 500, PsUshuai) reads as "no such key"; any other error
    /// stays an error.
    #[test]
    fn a_missing_account_reads_as_absent() {
        let missing = json!([{
            "kind": "permanent",
            "id": "proto.025-PsUshuai.context.storage_error",
            "missing_key": ["contracts", "index", "0000e8f0b20d442bfeed18f1981768e34c1a3a75e875", "balance"],
            "function": "get"
        }]);
        assert!(missing_key(&missing));
        for other in [
            json!([]),
            json!(null),
            json!("Internal Server Error"),
            json!([{ "kind": "temporary", "id": "proto.025-PsUshuai.gas_exhausted.operation" }]),
            json!([{ "kind": "permanent", "id": "proto.025-PsUshuai.context.storage_error" }]),
            json!([
                missing[0].clone(),
                { "kind": "temporary", "id": "failure", "msg": "timeout" }
            ]),
        ] {
            assert!(!missing_key(&other), "{other}");
        }
    }

    /// Mainnet, nothing broadcast: the test account above (index 0, public key known
    /// to everyone) signs a 1-mutez transfer to itself with no fee; the node forges the
    /// same bytes and its preapply accepts the signature; a tampered signature is
    /// refused. `cargo test -- --ignored real_tezos_mainnet --nocapture`
    #[test]
    #[ignore]
    fn real_tezos_mainnet_preapply_checks_the_signature() {
        let key = key(0);
        let public_key = key.verifying_key().to_bytes();
        let source = implicit_of(&public_key);
        let chosen = node(&MAINNET).unwrap();
        let (branch, protocol) = head(chosen).unwrap();
        let counter = mutez(
            &get(
                chosen.url,
                &format!("{}/counter", contract_path(&source.text())),
            )
            .unwrap(),
        )
        .unwrap();
        let mut op = Operation {
            branch,
            source,
            contents: vec![Content::Transaction {
                fee: 0,
                counter: counter + 1,
                gas_limit: 10_000,
                storage_limit: 0,
                amount: 1,
                destination: source,
            }],
        };
        let results = simulate(chosen, &op).unwrap();
        let milligas =
            mutez(&results[0]["metadata"]["operation_result"]["consumed_milligas"]).unwrap();
        *op.contents[0].limits().1 = milligas.div_ceil(1000) + GAS_MARGIN;
        let forged = op.forge();
        ensure_node_forges_the_same(chosen, &op, &forged).unwrap();
        let prepared = Prepared {
            op,
            protocol,
            plan: XtzPlan {
                amount: 1,
                fee: 0,
                burn: 0,
                reveal: false,
                creates: false,
            },
        };
        let signature = sign_forged(&key, &forged);
        preapply(chosen, &prepared, &signature).unwrap();
        println!("préapplication acceptée, gaz {}", milligas.div_ceil(1000));
        let mut tampered = signature;
        tampered[10] ^= 1;
        let error = preapply(chosen, &prepared, &tampered)
            .unwrap_err()
            .to_string();
        println!("signature altérée : {error}");
        assert!(error.contains("signature"), "{error}");
        // Reads: balance, history, activity.
        println!(
            "solde {} XTZ",
            format_xtz(balance(&MAINNET, &source.text()).unwrap())
        );
        assert!(address_activity(&MAINNET, &source.text()).unwrap().1);
        println!(
            "{} entrées d'historique",
            history(&MAINNET, &source.text(), 10).unwrap().len()
        );
        // An address that never received tez: `full_balance` answers a storage error
        // there, shown as 0 (every node of the list).
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let fresh = address_of(&SigningKey::from_bytes(&secret));
        for url in MAINNET.rpc {
            let one = Network {
                rpc: std::slice::from_ref(url),
                ..MAINNET
            };
            assert_eq!(balance(&one, &fresh).unwrap(), 0, "{url}");
            assert_eq!(node(&one).unwrap().url, *url);
        }
        // A node that does not answer hands over to the next one.
        let dead_first = Network {
            rpc: &["https://127.0.0.1:9", "https://rpc.tzbeta.net"],
            ..MAINNET
        };
        assert_eq!(node(&dead_first).unwrap().url, "https://rpc.tzbeta.net");
        assert_eq!(
            balance(&dead_first, &source.text()).unwrap(),
            balance(&MAINNET, &source.text()).unwrap()
        );
    }

    /// Shadownet, real sends: the key in the file named by `TEZOS_SHADOWNET_KEY`
    /// (64 hex digits, created if missing; fund its address from
    /// https://faucet.shadownet.teztnets.com) pays a new account, which creates it
    /// (burn) and reveals the key if it is the first send; the new account pays part
    /// back (its own reveal). `cargo test -- --ignored real_tezos_shadownet --nocapture`
    #[test]
    #[ignore]
    fn real_tezos_shadownet_end_to_end() {
        let path = std::env::var("TEZOS_SHADOWNET_KEY").expect("TEZOS_SHADOWNET_KEY");
        let key = match std::fs::read_to_string(&path) {
            Ok(text) => SigningKey::from_bytes(&unhex(text.trim())),
            Err(_) => {
                let mut secret = [0u8; 32];
                getrandom::getrandom(&mut secret).unwrap();
                std::fs::write(&path, hex::encode(secret)).unwrap();
                SigningKey::from_bytes(&secret)
            }
        };
        let from = address_of(&key);
        println!("compte : {from}");
        let shadow = node(&SHADOWNET).unwrap();
        let funds = spendable(shadow, &from).unwrap();
        assert!(
            funds >= 3_000_000,
            "à financer : {from} ({} XTZ)",
            format_xtz(funds)
        );
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let bob = SigningKey::from_bytes(&secret);
        let bob_address = address_of(&bob);
        let first = plan(&SHADOWNET, &public_key_text(&key), &bob_address, 2_000_000).unwrap();
        println!("plan : {first:?}");
        assert!(first.creates && first.burn > 0);
        let hash = send(&SHADOWNET, &key, &bob_address, 2_000_000, first.cost()).unwrap();
        println!("virement : {hash}");
        let wait = |address: &str, at_least: u64| {
            for _ in 0..40 {
                if spendable(shadow, address).unwrap() >= at_least {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            panic!("{address} jamais crédité");
        };
        wait(&bob_address, 2_000_000);
        // Back from the new account: its reveal, and the Max button.
        let back = max_amount(&SHADOWNET, &public_key_text(&bob), Some(&from)).unwrap();
        let second = plan(&SHADOWNET, &public_key_text(&bob), &from, back).unwrap();
        assert!(second.reveal && !second.creates, "{second:?}");
        let hash = send(&SHADOWNET, &bob, &from, back, second.cost()).unwrap();
        println!(
            "retour (Max, {} XTZ, révélation) : {hash}",
            format_xtz(back)
        );
        for _ in 0..40 {
            if spendable(shadow, &bob_address).unwrap() == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
        assert_eq!(
            spendable(shadow, &bob_address).unwrap(),
            0,
            "Max vide le compte"
        );
        // Emptied, the account leaves the context: the full balance still reads 0.
        assert_eq!(balance(&SHADOWNET, &bob_address).unwrap(), 0);
        std::thread::sleep(std::time::Duration::from_secs(10));
        let entries = history(&SHADOWNET, &bob_address, 10).unwrap();
        println!("{} entrées d'historique", entries.len());
        assert!(entries
            .iter()
            .any(|e| e.net_amount_minor == Some(2_000_000)));
    }
}
