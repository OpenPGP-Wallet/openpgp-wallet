//! Ledger Bitcoin app (`app-bitcoin-new`, protocol of versions ≥ 2.1;
//! specifications `doc/bitcoin.md`, `doc/merkle.md`, `doc/wallet.md`, reference
//! client `ledger_bitcoin`, read directly).
//!
//! The device does not receive the transaction in one piece: the first command only
//! sends COMMITMENTS (Merkle roots, SHA-256 hashes) to the partially signed
//! transaction (PSBT v2, BIP 370) and to the wallet; the device then asks, piece by
//! piece, for the data it needs ("client" commands: preimage, Merkle proof...) and
//! checks each piece against those commitments. This module plays the client's
//! role.
//!
//! Wallet used: the native SegWit "default" wallet (BIP 84, `wpkh(@0/**)`, keys
//! m/84'/c'/n'/{0,1}/i), which the device recognizes without prior registration.
//! Change goes to an address on the 1/i path, which the device checks itself before
//! hiding it.
//!
//! Everything the device returns is checked again here: addresses recomputed from
//! the extended public key, and every signature checked against the BIP 143 digest
//! of the transaction that WE will broadcast.

use super::{send_raw, Transport, HARDENED};
use crate::btc_tx::{dsha256, p2wpkh_script_pubkey, push_varint};
use anyhow::{anyhow, bail, ensure, Context, Result};
use bip32::{ChildNumber, ExtendedKey, Prefix, XPub};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};

const CLA: u8 = 0xe1;
const CLA_FRAMEWORK: u8 = 0xf8;
const INS_GET_EXTENDED_PUBKEY: u8 = 0x00;
const INS_GET_WALLET_ADDRESS: u8 = 0x03;
const INS_SIGN_PSBT: u8 = 0x04;
const INS_GET_MASTER_FINGERPRINT: u8 = 0x05;
const INS_CONTINUE: u8 = 0x01;
/// P2 = protocol version (1 since app 2.1.0).
const PROTOCOL_VERSION: u8 = 1;
const SW_INTERRUPTED_EXECUTION: u16 = 0xe000;
/// Cap on the number of round trips for one command: protects against a device that
/// never finishes (a real signature takes a few hundred to a few thousand).
const MAX_ROUNDS: u32 = 200_000;

/// Transaction version and input sequence (final, no RBF), written into the PSBT
/// and reused identically for the local BIP 143 digest.
const TX_VERSION: u32 = 2;
const SEQUENCE: u32 = 0xffff_ffff;
const SIGHASH_ALL: u8 = 0x01;

/// Status words specific to the Bitcoin app, then generic meanings.
fn check(sw: u16) -> Result<()> {
    match sw {
        0x9000 => Ok(()),
        0x6985 => Err(anyhow!("opération refusée sur le Ledger (0x6985)")),
        0x6a80 => Err(anyhow!("transaction refusée par l'application Bitcoin du Ledger : données incohérentes (0x6a80)")),
        0xb007 => Err(anyhow!("l'application Bitcoin du Ledger a interrompu l'opération (état inattendu, 0xb007)")),
        0xb008 => Err(anyhow!("l'application Bitcoin du Ledger a refusé le portefeuille (signature ou HMAC invalide, 0xb008)")),
        other => Err(super::status_error(other)),
    }
}

// --- Bounded byte reading ----------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.data.len()).ok_or_else(|| anyhow!("données tronquées"))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("longueur vérifiée"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Variable-length integer in Bitcoin format ("CompactSize").
    fn varint(&mut self) -> Result<u64> {
        Ok(match self.u8()? {
            0xfd => u16::from_le_bytes(self.array()?) as u64,
            0xfe => u32::from_le_bytes(self.array()?) as u64,
            0xff => u64::from_le_bytes(self.array()?),
            n => n as u64,
        })
    }

    fn length(&mut self) -> Result<usize> {
        usize::try_from(self.varint()?).map_err(|_| anyhow!("longueur invalide"))
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        self.pos = self.data.len();
        rest
    }

    fn finish(&self) -> Result<()> {
        ensure!(self.pos == self.data.len(), "données inattendues en fin de message");
        Ok(())
    }
}

fn varint(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    push_varint(&mut out, n as u64);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn hash160(pubkey: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(pubkey)).into()
}

// --- Merkle trees (`doc/merkle.md`, a variant of RFC 6962) --------------------

/// Leaf: SHA-256(0x00 || element).
fn element_hash(element: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(element);
    hasher.finalize().into()
}

/// Internal node: SHA-256(0x01 || left || right).
fn combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Size of the left subtree of a tree with `n` ≥ 2 leaves: the largest power of 2
/// strictly below `n`.
fn left_size(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Root; 32 zero bytes for an empty tree.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0; 32],
        1 => leaves[0],
        n => {
            let k = left_size(n);
            combine(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Proof of membership for leaf `index`: the successive siblings, from the leaf up
/// to the root.
fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = left_size(leaves.len());
    let (mut proof, sibling) = if index < k {
        (merkle_proof(&leaves[..k], index), merkle_root(&leaves[k..]))
    } else {
        (merkle_proof(&leaves[k..], index - k), merkle_root(&leaves[..k]))
    };
    proof.push(sibling);
    proof
}

/// Key -> value map of a PSBT (key = type || key data), sorted by key as the
/// commitment requires.
type Map = BTreeMap<Vec<u8>, Vec<u8>>;

/// Commitment of a map: number of entries, root of the keys, root of the values.
fn map_commitment(map: &Map) -> Vec<u8> {
    let mut out = varint(map.len());
    out.extend(merkle_root(&map.keys().map(|k| element_hash(k)).collect::<Vec<_>>()));
    out.extend(merkle_root(&map.values().map(|v| element_hash(v)).collect::<Vec<_>>()));
    out
}

// --- "Client" commands ----------------------------------------------------------

/// Answers the device's requests during an interactive command, using only the data
/// committed at the start (formats from `client_command.py`).
#[derive(Default)]
struct Client {
    preimages: HashMap<[u8; 32], Vec<u8>>,
    trees: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Rest of a response too long for one APDU (GET_MORE_ELEMENTS).
    queue: VecDeque<Vec<u8>>,
    /// Results sent by the device (YIELD): the signatures.
    yielded: Vec<Vec<u8>>,
}

impl Client {
    fn add_preimage(&mut self, data: &[u8]) {
        self.preimages.insert(sha256(data), data.to_vec());
    }

    /// A list committed by a Merkle tree: the tree, and each revealable leaf (preimage
    /// 0x00 || element).
    fn add_list<T: AsRef<[u8]>>(&mut self, elements: &[T]) {
        let mut leaves = Vec::with_capacity(elements.len());
        for element in elements {
            let mut preimage = vec![0x00];
            preimage.extend_from_slice(element.as_ref());
            self.add_preimage(&preimage);
            leaves.push(element_hash(element.as_ref()));
        }
        self.trees.insert(merkle_root(&leaves), leaves);
    }

    fn add_map(&mut self, map: &Map) {
        self.add_list(&map.keys().collect::<Vec<_>>());
        self.add_list(&map.values().collect::<Vec<_>>());
    }

    fn execute(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        let (&code, body) = request.split_first().ok_or_else(|| anyhow!("demande vide du Ledger"))?;
        let mut r = Reader::new(body);
        match code {
            // YIELD: one result; empty response.
            0x10 => {
                self.yielded.push(body.to_vec());
                Ok(Vec::new())
            }
            // GET_PREIMAGE: total length, then the largest possible prefix; the rest goes byte
            // by byte into the queue.
            0x40 => {
                ensure!(r.u8()? == 0, "demande de préimage non prise en charge");
                let hash: [u8; 32] = r.array()?;
                r.finish()?;
                let preimage = self.preimages.get(&hash).ok_or_else(|| anyhow!("le Ledger demande une donnée qui ne lui a pas été engagée"))?;
                let mut out = varint(preimage.len());
                let size = (255 - out.len() - 1).min(preimage.len());
                out.push(size as u8);
                out.extend_from_slice(&preimage[..size]);
                self.queue.extend(preimage[size..].iter().map(|b| vec![*b]));
                Ok(out)
            }
            // GET_MERKLE_LEAF_PROOF: leaf, proof length, then as many elements as fit (6); the
            // rest goes into the queue.
            0x41 => {
                let root: [u8; 32] = r.array()?;
                let size = r.length()?;
                let index = r.length()?;
                r.finish()?;
                let leaves = self.trees.get(&root).ok_or_else(|| anyhow!("le Ledger demande un arbre de Merkle inconnu"))?;
                ensure!(index < size && leaves.len() == size, "demande de preuve de Merkle incohérente");
                ensure!(self.queue.is_empty(), "demande de preuve de Merkle avant la fin de la précédente");
                let proof = merkle_proof(leaves, index);
                let n = proof.len().min((255 - 32 - 1 - 1) / 32);
                let mut out = leaves[index].to_vec();
                out.push(proof.len() as u8);
                out.push(n as u8);
                proof[..n].iter().for_each(|h| out.extend_from_slice(h));
                self.queue.extend(proof[n..].iter().map(|h| h.to_vec()));
                Ok(out)
            }
            // GET_MERKLE_LEAF_INDEX: found (0/1), then index.
            0x42 => {
                let root: [u8; 32] = r.array()?;
                let leaf: [u8; 32] = r.array()?;
                r.finish()?;
                let leaves = self.trees.get(&root).ok_or_else(|| anyhow!("le Ledger demande un arbre de Merkle inconnu"))?;
                let (found, index) = leaves.iter().position(|l| *l == leaf).map_or((0u8, 0), |i| (1, i));
                let mut out = vec![found];
                out.extend(varint(index));
                Ok(out)
            }
            // GET_MORE_ELEMENTS: elements of the same size, at most 253 bytes.
            0xa0 => {
                r.finish()?;
                let size = self.queue.front().map(Vec::len).ok_or_else(|| anyhow!("le Ledger demande la suite d'une réponse terminée"))?;
                ensure!(self.queue.iter().all(|e| e.len() == size), "file de réponse incohérente");
                let mut data = Vec::new();
                let mut n = 0u8;
                while !self.queue.is_empty() && data.len() + size <= 253 {
                    data.extend(self.queue.pop_front().expect("file non vide"));
                    n += 1;
                }
                let mut out = vec![n, size as u8];
                out.extend(data);
                Ok(out)
            }
            other => bail!("commande inattendue du Ledger (0x{other:02x})"),
        }
    }
}

/// Sends a command and answers each interruption (0xE000) with CONTINUE until the
/// final response.
fn request(transport: &mut dyn Transport, ins: u8, data: &[u8], client: &mut Client) -> Result<Vec<u8>> {
    let (mut response, mut sw) = send_raw(transport, CLA, ins, 0, PROTOCOL_VERSION, data)?;
    let mut rounds = 0;
    while sw == SW_INTERRUPTED_EXECUTION {
        rounds += 1;
        ensure!(rounds <= MAX_ROUNDS, "échange avec le Ledger anormalement long : abandon");
        let reply = client.execute(&response)?;
        (response, sw) = send_raw(transport, CLA_FRAMEWORK, INS_CONTINUE, 0, PROTOCOL_VERSION, &reply)?;
    }
    check(sw)?;
    Ok(response)
}

// --- Wallet policy (`doc/wallet.md`, version 2) --------------------------------

struct WalletPolicy {
    name: String,
    template: String,
    keys: Vec<String>,
}

impl WalletPolicy {
    /// version | name | length and SHA-256 of the descriptor template | number of keys
    /// | Merkle root of the keys.
    fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0x02, self.name.len() as u8];
        out.extend_from_slice(self.name.as_bytes());
        out.extend(varint(self.template.len()));
        out.extend(sha256(self.template.as_bytes()));
        out.extend(varint(self.keys.len()));
        out.extend(merkle_root(&self.keys.iter().map(|k| element_hash(k.as_bytes())).collect::<Vec<_>>()));
        out
    }

    fn id(&self) -> [u8; 32] {
        sha256(&self.serialize())
    }

    /// Client that knows the policy (required by every command that uses it).
    fn client(&self) -> Client {
        let mut client = Client::default();
        client.add_list(&self.keys.iter().map(String::as_bytes).collect::<Vec<_>>());
        client.add_preimage(&self.serialize());
        client.add_preimage(self.template.as_bytes());
        client
    }
}

// --- Account --------------------------------------------------------------------

/// A Ledger's native SegWit (BIP 84) Bitcoin account: everything needed to compute
/// its addresses and build its transactions without the device. No secret data
/// (extended public key and master fingerprint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub testnet: bool,
    pub account: u32,
    pub fingerprint: [u8; 4],
    pub xpub: String,
}

impl Account {
    fn path(testnet: bool, account: u32) -> [u32; 3] {
        [84 | HARDENED, testnet as u32 | HARDENED, account | HARDENED]
    }

    /// Reads the master fingerprint and the extended public key of account
    /// m/84'/c'/`account`' (standard path: no confirmation asked). The open app must
    /// match the network (Bitcoin / Bitcoin Test).
    pub fn load(transport: &mut dyn Transport, testnet: bool, account: u32) -> Result<Self> {
        ensure!(account < HARDENED, "numéro de compte invalide");
        let fingerprint = request(transport, INS_GET_MASTER_FINGERPRINT, &[], &mut Client::default())?
            .try_into()
            .map_err(|_| anyhow!("empreinte maîtresse du Ledger mal formée"))?;
        let path = Self::path(testnet, account);
        let mut data = vec![0u8, path.len() as u8];
        path.iter().for_each(|i| data.extend(i.to_be_bytes()));
        let xpub = String::from_utf8(request(transport, INS_GET_EXTENDED_PUBKEY, &data, &mut Client::default())?)
            .context("clé publique étendue du Ledger mal formée")?;
        let loaded = Self { testnet, account, fingerprint, xpub };
        loaded.parsed_xpub()?;
        Ok(loaded)
    }

    /// Validated extended key: public, right network, at account level.
    fn parsed_xpub(&self) -> Result<XPub> {
        let key: ExtendedKey = self.xpub.parse().map_err(|_| anyhow!("clé publique étendue du Ledger illisible"))?;
        let expected = if self.testnet { Prefix::TPUB } else { Prefix::XPUB };
        ensure!(
            key.prefix == expected,
            "le Ledger n'est pas sur le bon réseau : ouvrez l'application « {} »",
            if self.testnet { "Bitcoin Test" } else { "Bitcoin" }
        );
        ensure!(
            key.attrs.depth == 3 && key.attrs.child_number == ChildNumber::new(self.account, true)?,
            "clé publique étendue du Ledger inattendue (niveau de dérivation)"
        );
        XPub::try_from(key).map_err(|_| anyhow!("clé publique étendue du Ledger invalide"))
    }

    fn policy(&self) -> WalletPolicy {
        let origin = format!("[{}/84'/{}'/{}']{}", hex::encode(self.fingerprint), self.testnet as u32, self.account, self.xpub);
        WalletPolicy { name: String::new(), template: "wpkh(@0/**)".into(), keys: vec![origin] }
    }

    /// Compressed public key of m/84'/c'/n'/`change`/`index`, derived locally from the
    /// extended key.
    pub fn public_key(&self, change: u32, index: u32) -> Result<[u8; 33]> {
        ensure!(change <= 1 && index < HARDENED, "chemin d'adresse invalide");
        let child = self
            .parsed_xpub()?
            .derive_child(ChildNumber::new(change, false)?)?
            .derive_child(ChildNumber::new(index, false)?)?;
        Ok(child.to_bytes())
    }

    pub fn hash160(&self, change: u32, index: u32) -> Result<[u8; 20]> {
        Ok(hash160(&self.public_key(change, index)?))
    }

    pub fn address(&self, change: u32, index: u32) -> Result<String> {
        let hash = self.hash160(change, index)?;
        if self.testnet {
            crate::derivation::format_btc_testnet_address(&hash)
        } else {
            crate::derivation::format_btc_mainnet_address(&hash)
        }
    }

    /// Value of a PSBT BIP 32 derivation field: master fingerprint, then each index in
    /// little-endian.
    fn derivation(&self, change: u32, index: u32) -> Vec<u8> {
        let mut out = self.fingerprint.to_vec();
        for step in Self::path(self.testnet, self.account).into_iter().chain([change, index]) {
            out.extend(step.to_le_bytes());
        }
        out
    }
}

/// Address computed BY THE DEVICE (`display`: shown on its screen and confirmed by
/// the user), compared with the one derived locally.
pub fn wallet_address(transport: &mut dyn Transport, account: &Account, change: u32, index: u32, display: bool) -> Result<String> {
    let expected = account.address(change, index)?;
    let policy = account.policy();
    let mut data = vec![display as u8];
    data.extend(policy.id());
    data.extend([0u8; 32]); // default wallet: no HMAC
    data.push(change as u8);
    data.extend(index.to_be_bytes());
    let address = String::from_utf8(request(transport, INS_GET_WALLET_ADDRESS, &data, &mut policy.client())?)
        .context("adresse du Ledger mal formée")?;
    ensure!(address == expected, "l'adresse calculée par le Ledger ne correspond pas à celle du compte");
    Ok(address)
}

// --- Transactions -------------------------------------------------------------

/// A parsed previous transaction (the one that created a UTXO). Shared with the
/// Trezor code, which also asks for its version, inputs and locktime.
pub(crate) struct PrevTx {
    pub(crate) txid: [u8; 32],
    /// Serialization without witnesses (the one the txid covers).
    pub(crate) stripped: Vec<u8>,
    pub(crate) version: u32,
    pub(crate) inputs: Vec<PrevTxIn>,
    pub(crate) outputs: Vec<(u64, Vec<u8>)>,
    pub(crate) locktime: u32,
}

pub(crate) struct PrevTxIn {
    /// Spent txid, in serialization order.
    pub(crate) prevout: [u8; 32],
    pub(crate) vout: u32,
    pub(crate) script_sig: Vec<u8>,
    pub(crate) sequence: u32,
}

/// Parses a raw transaction, with or without witnesses (BIP 144 format).
pub(crate) fn parse_transaction(raw: &[u8]) -> Result<PrevTx> {
    let mut r = Reader::new(raw);
    let version = r.take(4)?;
    let segwit = raw.get(4..6) == Some(&[0x00, 0x01][..]);
    if segwit {
        r.take(2)?;
    }
    let body_start = r.pos;
    let input_count = r.varint()?;
    ensure!(input_count > 0, "transaction sans entrée");
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let prevout: [u8; 32] = r.array()?;
        let vout = u32::from_le_bytes(r.array()?);
        let script = r.length()?;
        let script_sig = r.take(script)?.to_vec();
        let sequence = u32::from_le_bytes(r.array()?);
        inputs.push(PrevTxIn { prevout, vout, script_sig, sequence });
    }
    let mut outputs = Vec::new();
    for _ in 0..r.varint()? {
        let value = u64::from_le_bytes(r.array()?);
        let script = r.length()?;
        outputs.push((value, r.take(script)?.to_vec()));
    }
    let body_end = r.pos;
    if segwit {
        for _ in 0..input_count {
            for _ in 0..r.varint()? {
                let item = r.length()?;
                r.take(item)?;
            }
        }
    }
    let locktime = r.take(4)?;
    r.finish().context("transaction précédente mal formée")?;
    let mut stripped = version.to_vec();
    stripped.extend_from_slice(&raw[body_start..body_end]);
    stripped.extend_from_slice(locktime);
    let mut txid = dsha256(&stripped);
    txid.reverse();
    Ok(PrevTx {
        txid,
        stripped,
        version: u32::from_le_bytes(version.try_into().expect("4 octets")),
        inputs,
        outputs,
        locktime: u32::from_le_bytes(locktime.try_into().expect("4 octets")),
    })
}

pub(crate) struct TxIn {
    /// Txid in serialization order (the reverse of display order).
    pub(crate) prevout: [u8; 32],
    pub(crate) vout: u32,
    pub(crate) sequence: u32,
}

pub(crate) struct TxOut {
    pub(crate) value: u64,
    pub(crate) script: Vec<u8>,
}

pub(crate) struct UnsignedTx {
    pub(crate) version: u32,
    pub(crate) inputs: Vec<TxIn>,
    pub(crate) outputs: Vec<TxOut>,
    pub(crate) locktime: u32,
}

impl UnsignedTx {
    fn outputs_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for o in &self.outputs {
            out.extend(o.value.to_le_bytes());
            out.extend(varint(o.script.len()));
            out.extend_from_slice(&o.script);
        }
        out
    }

    /// BIP 143 digest (SIGHASH_ALL) of input `index`, which spends a P2WPKH output
    /// `hash160` worth `value`.
    pub(crate) fn sighash(&self, index: usize, hash160: &[u8; 20], value: u64) -> [u8; 32] {
        let prevouts: Vec<u8> = self.inputs.iter().flat_map(|i| [&i.prevout[..], &i.vout.to_le_bytes()].concat()).collect();
        let sequences: Vec<u8> = self.inputs.iter().flat_map(|i| i.sequence.to_le_bytes()).collect();
        let input = &self.inputs[index];
        let mut preimage = self.version.to_le_bytes().to_vec();
        preimage.extend(dsha256(&prevouts));
        preimage.extend(dsha256(&sequences));
        preimage.extend_from_slice(&input.prevout);
        preimage.extend(input.vout.to_le_bytes());
        preimage.extend([0x19, 0x76, 0xa9, 0x14]); // equivalent P2PKH scriptCode
        preimage.extend_from_slice(hash160);
        preimage.extend([0x88, 0xac]);
        preimage.extend(value.to_le_bytes());
        preimage.extend(input.sequence.to_le_bytes());
        preimage.extend(dsha256(&self.outputs_body()));
        preimage.extend(self.locktime.to_le_bytes());
        preimage.extend((SIGHASH_ALL as u32).to_le_bytes());
        dsha256(&preimage)
    }

    /// Final transaction: each P2WPKH input has (signature, public key) as its witness.
    pub(crate) fn serialize_signed(&self, witnesses: &[(Vec<u8>, [u8; 33])]) -> Vec<u8> {
        let mut out = self.version.to_le_bytes().to_vec();
        out.extend([0x00, 0x01]); // SegWit marker and flag
        out.extend(varint(self.inputs.len()));
        for i in &self.inputs {
            out.extend_from_slice(&i.prevout);
            out.extend(i.vout.to_le_bytes());
            out.push(0x00); // empty scriptSig
            out.extend(i.sequence.to_le_bytes());
        }
        out.extend(varint(self.outputs.len()));
        out.extend(self.outputs_body());
        for (signature, pubkey) in witnesses {
            out.push(2);
            out.extend(varint(signature.len()));
            out.extend_from_slice(signature);
            out.extend(varint(pubkey.len()));
            out.extend_from_slice(pubkey);
        }
        out.extend(self.locktime.to_le_bytes());
        out
    }
}

/// UTXO to spend, on the account's address m/84'/c'/n'/`change`/`index`, with the
/// raw transaction that created it (the device recomputes its txid to make sure of
/// the amount actually spent).
pub struct Input {
    /// Txid in the order block explorers display.
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
    pub prev_tx: Vec<u8>,
    pub change: u32,
    pub index: u32,
}

/// Output: `change_index` = Some(i) for change, sent to m/84'/c'/n'/1/i (the device
/// recognizes it, checks it and does not display it).
pub struct Output {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
    pub change_index: Option<u32>,
}

/// PSBT v2 ready to be committed to the device.
struct Psbt {
    global: Map,
    inputs: Vec<Map>,
    outputs: Vec<Map>,
}

/// Builds the PSBT after checking locally each input (txid of the previous
/// transaction, amount and script of the spent output) and each change output.
fn build_psbt(account: &Account, inputs: &[Input], outputs: &[Output]) -> Result<Psbt> {
    ensure!(!inputs.is_empty() && !outputs.is_empty(), "transaction vide");
    let mut input_maps = Vec::new();
    for input in inputs {
        let pubkey = account.public_key(input.change, input.index)?;
        let script = p2wpkh_script_pubkey(&hash160(&pubkey));
        let prev = parse_transaction(&input.prev_tx)?;
        ensure!(prev.txid == input.txid, "la transaction précédente fournie ne correspond pas à l'UTXO {}", hex::encode(input.txid));
        let spent = prev.outputs.get(input.vout as usize);
        ensure!(
            spent == Some(&(input.value_sat, script.clone())),
            "l'UTXO {}:{} n'a pas le montant ou l'adresse attendus",
            hex::encode(input.txid),
            input.vout
        );
        let mut witness_utxo = input.value_sat.to_le_bytes().to_vec();
        witness_utxo.extend(varint(script.len()));
        witness_utxo.extend(&script);
        let mut prevout = input.txid;
        prevout.reverse();
        let mut map = Map::new();
        map.insert(vec![0x00], prev.stripped); // PSBT_IN_NON_WITNESS_UTXO
        map.insert(vec![0x01], witness_utxo); // PSBT_IN_WITNESS_UTXO
        map.insert([&[0x06][..], &pubkey].concat(), account.derivation(input.change, input.index)); // PSBT_IN_BIP32_DERIVATION
        map.insert(vec![0x0e], prevout.to_vec()); // PSBT_IN_PREVIOUS_TXID
        map.insert(vec![0x0f], input.vout.to_le_bytes().to_vec()); // PSBT_IN_OUTPUT_INDEX
        map.insert(vec![0x10], SEQUENCE.to_le_bytes().to_vec()); // PSBT_IN_SEQUENCE
        input_maps.push(map);
    }
    let mut output_maps = Vec::new();
    for output in outputs {
        let mut map = Map::new();
        map.insert(vec![0x03], output.value_sat.to_le_bytes().to_vec()); // PSBT_OUT_AMOUNT
        map.insert(vec![0x04], output.script_pubkey.clone()); // PSBT_OUT_SCRIPT
        if let Some(index) = output.change_index {
            let pubkey = account.public_key(1, index)?;
            ensure!(output.script_pubkey == p2wpkh_script_pubkey(&hash160(&pubkey)), "sortie de monnaie incohérente avec le compte");
            map.insert([&[0x02][..], &pubkey].concat(), account.derivation(1, index)); // PSBT_OUT_BIP32_DERIVATION
        }
        output_maps.push(map);
    }
    let mut global = Map::new();
    global.insert(vec![0x02], TX_VERSION.to_le_bytes().to_vec()); // PSBT_GLOBAL_TX_VERSION
    global.insert(vec![0x04], varint(inputs.len())); // PSBT_GLOBAL_INPUT_COUNT
    global.insert(vec![0x05], varint(outputs.len())); // PSBT_GLOBAL_OUTPUT_COUNT
    global.insert(vec![0xfb], 2u32.to_le_bytes().to_vec()); // PSBT_GLOBAL_VERSION
    Ok(Psbt { global, inputs: input_maps, outputs: output_maps })
}

impl Psbt {
    /// SIGN_PSBT data, and a client able to reveal everything it commits to.
    fn sign_request(&self, policy: &WalletPolicy) -> (Vec<u8>, Client) {
        let mut client = policy.client();
        client.add_map(&self.global);
        self.inputs.iter().chain(&self.outputs).for_each(|m| client.add_map(m));
        let input_commitments: Vec<Vec<u8>> = self.inputs.iter().map(map_commitment).collect();
        let output_commitments: Vec<Vec<u8>> = self.outputs.iter().map(map_commitment).collect();
        client.add_list(&input_commitments);
        client.add_list(&output_commitments);

        let mut data = map_commitment(&self.global);
        data.extend(varint(self.inputs.len()));
        data.extend(merkle_root(&input_commitments.iter().map(|c| element_hash(c)).collect::<Vec<_>>()));
        data.extend(varint(self.outputs.len()));
        data.extend(merkle_root(&output_commitments.iter().map(|c| element_hash(c)).collect::<Vec<_>>()));
        data.extend(policy.id());
        data.extend([0u8; 32]); // default wallet: no HMAC
        (data, client)
    }
}

/// Has the device sign the transaction (it displays recipients, amounts and fees
/// and waits for physical confirmation), checks each signature against the BIP 143
/// digest computed here, then returns the final transaction, ready to broadcast.
pub fn sign_transaction(transport: &mut dyn Transport, account: &Account, inputs: &[Input], outputs: &[Output]) -> Result<Vec<u8>> {
    let psbt = build_psbt(account, inputs, outputs)?;
    let (data, mut client) = psbt.sign_request(&account.policy());
    request(transport, INS_SIGN_PSBT, &data, &mut client)?;

    let unsigned = UnsignedTx {
        version: TX_VERSION,
        inputs: inputs
            .iter()
            .map(|i| {
                let mut prevout = i.txid;
                prevout.reverse();
                TxIn { prevout, vout: i.vout, sequence: SEQUENCE }
            })
            .collect(),
        outputs: outputs.iter().map(|o| TxOut { value: o.value_sat, script: o.script_pubkey.clone() }).collect(),
        locktime: 0,
    };
    let mut witnesses: Vec<Option<(Vec<u8>, [u8; 33])>> = vec![None; inputs.len()];
    for yielded in &client.yielded {
        let mut r = Reader::new(yielded);
        let index = usize::try_from(r.varint()?).ok().filter(|i| *i < inputs.len()).ok_or_else(|| anyhow!("signature du Ledger pour une entrée inexistante"))?;
        let key_len = r.u8()? as usize;
        let key = r.take(key_len)?;
        let (&sighash_type, der) = r.rest().split_last().ok_or_else(|| anyhow!("signature du Ledger vide"))?;
        let pubkey = account.public_key(inputs[index].change, inputs[index].index)?;
        ensure!(key == pubkey, "le Ledger a signé l'entrée {index} avec une autre clé que celle attendue");
        ensure!(sighash_type == SIGHASH_ALL, "type de signature inattendu du Ledger");
        let signature = Signature::from_der(der).map_err(|_| anyhow!("signature du Ledger mal formée"))?;
        ensure!(signature.normalize_s().is_none(), "signature du Ledger non canonique");
        let digest = unsigned.sighash(index, &hash160(&pubkey), inputs[index].value_sat);
        VerifyingKey::from_sec1_bytes(&pubkey)
            .map_err(|_| anyhow!("clé publique invalide"))?
            .verify_prehash(&digest, &signature)
            .map_err(|_| anyhow!("la signature du Ledger ne correspond pas à la transaction attendue — transaction non diffusée"))?;
        ensure!(witnesses[index].is_none(), "le Ledger a signé deux fois l'entrée {index}");
        let mut encoded = signature.to_der().as_bytes().to_vec();
        encoded.push(SIGHASH_ALL);
        witnesses[index] = Some((encoded, pubkey));
    }
    let witnesses: Vec<_> = witnesses.into_iter().collect::<Option<_>>().ok_or_else(|| anyhow!("le Ledger n'a pas signé toutes les entrées"))?;
    Ok(unsigned.serialize_signed(&witnesses))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// Trees produced by the OFFICIAL Python client (`ledger_bitcoin.merkle`) over the
    /// leaves b"a", b"bb", b"ccc"...: roots for 0 to 7 leaves and every proof of the
    /// 7-leaf tree.
    #[test]
    fn merkle_trees_match_the_official_client() {
        let leaves: Vec<[u8; 32]> = (0..7u8).map(|i| element_hash(&vec![0x61 + i; i as usize + 1])).collect();
        let roots = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c",
            "3ea3f8423cf12b1398d6e9b468114e368fceab86b53bcc57adb29a1564c0226d",
            "f6ee8bcc9daa22bc0d5355fb7d3f2c429fc43da07838f4288caa193373c95e56",
            "875d0247a07593eb3dc3d556a5abc4b0d465663fde4cb4ee27ca15eae903b85e",
            "f0e1bc9cc820b504db2e25550f4acb8bd79aaba930efcc4893d73388519661bc",
            "28e5466149cfdd309fccdb9397a696e92f7a66117b6aaaa9b0f179f271eb1026",
            "611a0b944ff0ebb337c5e8ae061b6f0afe9b3a12bb749fb9eff01b4d086308c3",
        ];
        for (n, root) in roots.iter().enumerate() {
            assert_eq!(hex::encode(merkle_root(&leaves[..n])), *root, "{n} feuilles");
        }
        let proofs: [&[&str]; 7] = [
            &["69372b398d6cc28945af8d2474c0b7661b6ab4587d2eb59364e914adf655fcee", "45d79ce10358829795103c11d9f17fba97813ca87ea14da5a083a080aaf7641b", "d63f8efb10919b65b11957b0fcda1c52214f4648c6ba908e0c332d9a4c8a1ac5"],
            &["022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c", "45d79ce10358829795103c11d9f17fba97813ca87ea14da5a083a080aaf7641b", "d63f8efb10919b65b11957b0fcda1c52214f4648c6ba908e0c332d9a4c8a1ac5"],
            &["d11edf2b22a5e116c89e7242dbfce68bfa304f2e9b9533b5a8ba24a9db30fe28", "3ea3f8423cf12b1398d6e9b468114e368fceab86b53bcc57adb29a1564c0226d", "d63f8efb10919b65b11957b0fcda1c52214f4648c6ba908e0c332d9a4c8a1ac5"],
            &["e0aa59c39192da9adcbda848d2c9aa11e5b249315ded98449ae3fc5ed361a238", "3ea3f8423cf12b1398d6e9b468114e368fceab86b53bcc57adb29a1564c0226d", "d63f8efb10919b65b11957b0fcda1c52214f4648c6ba908e0c332d9a4c8a1ac5"],
            &["19914622eb795189cb43623a5cb0bf14d40eff2218d534e249073a0c2bde2057", "79859a2c8e969d8da8b788bda6f3f745e1e5042ed2d90dcdb8479b2f4b2dd233", "875d0247a07593eb3dc3d556a5abc4b0d465663fde4cb4ee27ca15eae903b85e"],
            &["a44f62f1d5e749e2e342d7c0ed9fbefb4115eaf6429f09559ae131e6252089b0", "79859a2c8e969d8da8b788bda6f3f745e1e5042ed2d90dcdb8479b2f4b2dd233", "875d0247a07593eb3dc3d556a5abc4b0d465663fde4cb4ee27ca15eae903b85e"],
            &["e15f86c8079b2136975993c575f68ee17b362012ab2730c674b8b51fde056346", "875d0247a07593eb3dc3d556a5abc4b0d465663fde4cb4ee27ca15eae903b85e"],
        ];
        for (i, expected) in proofs.iter().enumerate() {
            let proof: Vec<String> = merkle_proof(&leaves, i).iter().map(hex::encode).collect();
            assert_eq!(proof, *expected, "preuve de la feuille {i}");
        }
    }

    /// Map commitment and wallet policy: values from the official Python client
    /// (`get_merkleized_map_commitment`, `WalletPolicy`).
    #[test]
    fn map_commitment_and_wallet_policy_match_the_official_client() {
        let map: Map = [(vec![0x04], vec![0x01]), (vec![0x02], h("02000000")), (vec![0x05], vec![0x02]), (vec![0xfb], h("02000000"))].into();
        assert_eq!(
            hex::encode(map_commitment(&map)),
            "042848ffbdeddc791430d3c6fe8b0c68f63321b850a0784af7f1763a1f53dd31c99efc681771b266014fead174cbd618862f8c1b4d702af3a8859acdf4364d773d"
        );
        let policy = WalletPolicy {
            name: String::new(),
            template: "wpkh(@0/**)".into(),
            keys: vec!["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".into()],
        };
        assert_eq!(
            hex::encode(policy.serialize()),
            "02000bc8974a0d8bdd29024b2ddb7a7fe8df1d9801b270f4e6c1e7e1011ae39e7c9b000144006386daf887e322e999231f37ba1dcc1863357a4bc21a78a623d7d2863f02"
        );
        assert_eq!(hex::encode(policy.id()), "74e9dad05d709eb46f8cce7378ebafb45a75c7e83e0d2a63e02f492c8adc7293");
    }

    /// Answers to the device's commands identical, byte for byte, to those of the
    /// official Python client (`ClientCommandInterpreter`): long preimage split up,
    /// long proof split up, index found / not found, YIELD.
    #[test]
    fn client_commands_match_the_official_client() {
        let mut client = Client::default();
        let preimage: Vec<u8> = (0..300u32).map(|i| (i % 256) as u8).collect();
        client.add_preimage(&preimage);
        let elements: Vec<Vec<u8>> = (0..100u8).map(|i| vec![i; 3]).collect();
        client.add_list(&elements);
        let leaves: Vec<[u8; 32]> = elements.iter().map(|e| element_hash(e)).collect();
        let root = merkle_root(&leaves);
        assert_eq!(hex::encode(root), "26fa48b478e0df5ce2466a488bf4a5486aa014028bed7ed7182b6a8c8635dd2e");

        let response = client.execute(&[&[0x40, 0x00][..], &sha256(&preimage)].concat()).unwrap();
        assert_eq!(hex::encode(&response[..4]), "fd2c01fb");
        assert_eq!(&response[4..], &preimage[..251]);
        let more = client.execute(&[0xa0]).unwrap();
        assert_eq!(hex::encode(more), "3101fbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b");

        let proof = client.execute(&[&[0x41][..], &root, &varint(100), &varint(77)].concat()).unwrap();
        assert_eq!(
            hex::encode(proof),
            "4ecf48a12ef7c4d68c02e570c7f478373d458dc198c2fcd037d2ab5916acad3d07069b36ff39baa5e1773bd42143cdbb2a4504fc443acde6b41aaf8df57a18248476be728fce08ac293fc9a66c9c8285865c67e87bb1cd2515abed5515d1ec73a760973c472093a8ea1ec3a76670d32c4226ddfc2d3599a05e49694bcff0df075a7a7007871d8378b9e5ee233eaeef51bb2f54dd4d84c6ccf2f6ef1f51fe01511433ea27f1f8287857a7cb6ca2148e51f584cd80d13f03f0273f56525258026a040183f74989f99696a23556a23fd79aa13ef3d731086823cc46ff8feb9f726f24c8"
        );
        assert_eq!(hex::encode(client.execute(&[0xa0]).unwrap()), "0120d231ea05660e24948372ec42cd56caec593db648b123cf618bf521d8a5a15239");

        assert_eq!(hex::encode(client.execute(&[&[0x42][..], &root, &leaves[42]].concat()).unwrap()), "012a");
        assert_eq!(hex::encode(client.execute(&[&[0x42][..], &root, &[0x11; 32]].concat()).unwrap()), "0000");
        assert_eq!(hex::encode(client.execute(&[&[0x40, 0x00][..], &leaves[5]].concat()).unwrap()), "040400050505");
        assert!(client.execute(&[0x10, 0xaa, 0xbb]).unwrap().is_empty());
        assert_eq!(client.yielded, vec![vec![0xaa, 0xbb]]);

        // Invalid requests: refused, never an invented answer.
        assert!(client.execute(&[&[0x40, 0x00][..], &[0x22; 32]].concat()).is_err(), "préimage inconnue");
        assert!(client.execute(&[&[0x41][..], &[0x33; 32], &varint(1), &varint(0)].concat()).is_err(), "arbre inconnu");
        assert!(client.execute(&[&[0x41][..], &root, &varint(100), &varint(100)].concat()).is_err(), "indice hors de l'arbre");
        assert!(client.execute(&[&[0x41][..], &root, &varint(99), &varint(1)].concat()).is_err(), "taille d'arbre fausse");
        assert!(client.execute(&[0xa0]).is_err(), "file vide");
        assert!(client.execute(&[0x77]).is_err(), "commande inconnue");
        assert!(client.execute(&[]).is_err());
    }

    /// BIP 143's official "Native P2WPKH" example: digest of the second input (6 BTC,
    /// SIGHASH_ALL).
    #[test]
    fn bip143_sighash_matches_the_official_example() {
        let tx = UnsignedTx {
            version: 1,
            inputs: vec![
                TxIn { prevout: h("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f").try_into().unwrap(), vout: 0, sequence: 0xffff_ffee },
                TxIn { prevout: h("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a").try_into().unwrap(), vout: 1, sequence: 0xffff_ffff },
            ],
            outputs: vec![
                TxOut { value: 112_340_000, script: h("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac") },
                TxOut { value: 223_450_000, script: h("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac") },
            ],
            locktime: 17,
        };
        let pubkey = h("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        assert_eq!(hex::encode(hash160(&pubkey)), "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1");
        assert_eq!(hex::encode(tx.sighash(1, &hash160(&pubkey), 600_000_000)), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
    }

    /// Txid of a real mainnet SegWit transaction (block 860000, as served by Esplora):
    /// witnesses stripped correctly, outputs read.
    #[test]
    fn previous_transactions_are_parsed_like_the_network_does() {
        let raw = h("02000000000101513f69bcd4338d8909cc43a2dc816cbe93b68b271eda3b0b9cbab216292b65a40100000000fdffffff02f05c0300000000001600148df02028a1ea803d3d8303cb7292af093289fed4a4de0e000000000016001432a6e6570e9ca071b44655d0aa032219e0a7cb5d0247304402207216fccd85bfcb893e57b96cd6b46bb66c7be2c60f3e3b138a3503c22240654c022064e6978af86db210d6ec901b590187b4543986c9b9ea6b73b4f8f96be56e2c7701210254732a97053baf09a3d7e1362fb9d57ccadc8e6927f863ee05bf8f6211fad5eb041f0d00");
        let tx = parse_transaction(&raw).unwrap();
        assert_eq!(hex::encode(tx.txid), "e11ed377b312fb737278cd55e1b2d03c38ef0c634493afa158dfa393756840ea");
        assert_eq!(tx.outputs, vec![(220_400, h("00148df02028a1ea803d3d8303cb7292af093289fed4")), (974_500, h("001432a6e6570e9ca071b44655d0aa032219e0a7cb5d"))]);
        // Without witnesses, the serialization is unchanged.
        assert_eq!(parse_transaction(&tx.stripped).unwrap().stripped, tx.stripped);
        for bad in [&raw[..raw.len() - 1], &[&raw[..], &[0]].concat()[..], &raw[..10]] {
            assert!(parse_transaction(bad).is_err());
        }
    }

    /// Account m/84'/1'/0' computed locally from the test seed.
    fn local_test_account() -> (Account, bip32::XPrv) {
        let seed = bip39::Mnemonic::parse(super::super::speculos::TEST_MNEMONIC).unwrap().to_seed("");
        let root = bip32::XPrv::new(seed).unwrap();
        let mut account = root.clone();
        for step in Account::path(true, 0) {
            account = account.derive_child(ChildNumber::from(step)).unwrap();
        }
        let local = Account { testnet: true, account: 0, fingerprint: root.public_key().fingerprint(), xpub: account.public_key().to_string(Prefix::TPUB) };
        (local, account)
    }

    /// Previous transaction (non-witness format) crediting the given addresses.
    fn funding_transaction(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut tx = 2u32.to_le_bytes().to_vec();
        tx.push(1);
        tx.extend([0x42; 32]);
        tx.extend(3u32.to_le_bytes());
        tx.push(0);
        tx.extend(SEQUENCE.to_le_bytes());
        tx.extend(varint(outputs.len()));
        for (value, script) in outputs {
            tx.extend(value.to_le_bytes());
            tx.extend(varint(script.len()));
            tx.extend(script);
        }
        tx.extend(0u32.to_le_bytes());
        tx
    }

    /// Test transaction: UTXOs on 0/0 (50,000 sat) and 1/3 (30,000 sat), 60,000 sat to
    /// a third party, 18,000 sat of change on 1/4.
    fn test_transaction(account: &Account) -> (Vec<Input>, Vec<Output>) {
        let script = |change, index| p2wpkh_script_pubkey(&account.hash160(change, index).unwrap());
        let prev = funding_transaction(&[(50_000, script(0, 0)), (30_000, script(1, 3))]);
        let txid = parse_transaction(&prev).unwrap().txid;
        let inputs = vec![
            Input { txid, vout: 0, value_sat: 50_000, prev_tx: prev.clone(), change: 0, index: 0 },
            Input { txid, vout: 1, value_sat: 30_000, prev_tx: prev, change: 1, index: 3 },
        ];
        let outputs = vec![
            Output { value_sat: 60_000, script_pubkey: p2wpkh_script_pubkey(&[0x55; 20]), change_index: None },
            Output { value_sat: 18_000, script_pubkey: script(1, 4), change_index: Some(4) },
        ];
        (inputs, outputs)
    }

    /// BIP 174 serialization ("psbt\xff", maps separated by 0x00), for the official
    /// Python client.
    fn serialize_psbt(psbt: &Psbt) -> Vec<u8> {
        let mut out = b"psbt\xff".to_vec();
        for map in std::iter::once(&psbt.global).chain(&psbt.inputs).chain(&psbt.outputs) {
            for (key, value) in map {
                out.extend(varint(key.len()));
                out.extend(key);
                out.extend(varint(value.len()));
                out.extend(value);
            }
            out.push(0x00);
        }
        out
    }

    /// SIGN_PSBT data identical to what the official Python client computes
    /// (`NewClient.sign_psbt`: parsing our PSBT, commitments for each map, roots of the
    /// inputs and outputs, policy). The SHA-256 hash of our PSBT also pins its exact
    /// content.
    #[test]
    fn sign_psbt_request_matches_the_official_client() {
        let (account, _) = local_test_account();
        let (inputs, outputs) = test_transaction(&account);
        let psbt = build_psbt(&account, &inputs, &outputs).unwrap();
        let (data, _) = psbt.sign_request(&account.policy());
        assert_eq!(hex::encode(sha256(&serialize_psbt(&psbt))), "a691552df40a406c5698434613e574e4f84a78a6fc3b3e60b56cabf541506377");
        assert_eq!(
            hex::encode(data),
            "042848ffbdeddc791430d3c6fe8b0c68f63321b850a0784af7f1763a1f53dd31c9c0ede25601048078c572ba946f8d0038d322ca9fff00a6160f5cc70b8b233267\
             026bd1b210043cc98ed73d867aafd62e5295ebff04f67f41074416a7eafaaff406\
             02d6cd5a5de46784624a8d96ba3b74d6284b7d5ffea5573a837d6630f0b975b781\
             74e9dad05d709eb46f8cce7378ebafb45a75c7e83e0d2a63e02f492c8adc7293\
             0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    /// Local checks refuse an inconsistent input or change output BEFORE any exchange
    /// with the device.
    #[test]
    fn inconsistent_inputs_and_change_are_refused_before_signing() {
        let (account, _) = local_test_account();
        let (inputs, outputs) = test_transaction(&account);
        let mut wrong_value = test_transaction(&account).0;
        wrong_value[0].value_sat += 1;
        assert!(build_psbt(&account, &wrong_value, &outputs).is_err(), "montant différent de l'UTXO");
        let mut wrong_key = test_transaction(&account).0;
        wrong_key[1].index = 4;
        assert!(build_psbt(&account, &wrong_key, &outputs).is_err(), "UTXO d'une autre adresse");
        let mut wrong_txid = test_transaction(&account).0;
        wrong_txid[0].txid[0] ^= 1;
        assert!(build_psbt(&account, &wrong_txid, &outputs).is_err(), "transaction précédente d'un autre UTXO");
        let mut wrong_change = test_transaction(&account).1;
        wrong_change[1].change_index = Some(5);
        assert!(build_psbt(&account, &inputs, &wrong_change).is_err(), "monnaie vers une autre adresse que celle annoncée");
        assert!(build_psbt(&account, &[], &outputs).is_err());
        assert!(build_psbt(&account, &inputs, &[]).is_err());
    }

    /// The OFFICIAL Bitcoin app ("Bitcoin Test" 2.5.1) in Speculos, public test seed:
    /// - master fingerprint and extended key m/84'/1'/0' identical to OUR derivation; addresses computed by
    ///   the device = ours;
    /// - address shown on screen for verification;
    /// - a real transaction (2 inputs on 0/0 and 1/3, one recipient, change on 1/4) signed after on-screen
    ///   review (amount, recipient, fee; change not shown), signatures checked against OUR digest;
    /// - refusal -> clear error.
    ///
    /// Speculos must run `bitcoin-nanosp.elf`.
    /// `cargo test -- --ignored ledger_btc_against_the_official_app_in_speculos --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn ledger_btc_against_the_official_app_in_speculos() {
        use super::super::{speculos, TcpTransport};
        let mut t = TcpTransport::connect(speculos::APDU).unwrap();
        speculos::back_to_home();
        let (local, account_key) = local_test_account();
        let device = Account::load(&mut t, true, 0).unwrap();
        assert_eq!(device, local, "compte du Ledger = notre dérivation");
        println!("compte : [{}] {}", hex::encode(device.fingerprint), device.xpub);
        assert!(Account::load(&mut t, false, 0).is_err(), "application testnet : compte mainnet refusé");

        for (change, index) in [(0, 0), (1, 3), (0, 17)] {
            let address = wallet_address(&mut t, &device, change, index, false).unwrap();
            let key = account_key.derive_child(ChildNumber::new(change, false).unwrap()).unwrap().derive_child(ChildNumber::new(index, false).unwrap()).unwrap();
            let ours = crate::derivation::format_btc_testnet_address(&hash160(&key.public_key().to_bytes())).unwrap();
            assert_eq!(address, ours, "{change}/{index}");
        }

        let receive = device.address(0, 0).unwrap();
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Confirm", "Approve"]));
        assert_eq!(wallet_address(&mut t, &device, 0, 0, true).unwrap(), receive);
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans adresse : {screens}");
        assert!(screens.replace(' ', "").contains(&receive[..20]), "adresse affichée");
        speculos::back_to_home();

        // 2,000 sat fee.
        let (inputs, outputs) = test_transaction(&device);
        let recipient_address = crate::derivation::format_btc_testnet_address(&[0x55; 20]).unwrap();
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign transaction", "Accept and send", "Approve"]));
        let signed = sign_transaction(&mut t, &device, &inputs, &outputs).unwrap();
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans transaction : {screens}");
        let compact = screens.replace(' ', "");
        assert!(compact.contains("0.0006"), "montant affiché");
        assert!(compact.contains(&recipient_address[..20]), "destinataire affiché");
        assert!(compact.contains("0.00002"), "frais affichés");
        assert!(!compact.contains("0.00018"), "la monnaie n'est pas présentée comme un envoi");
        println!("transaction signée : {}", hex::encode(&signed));
        let parsed = parse_transaction(&signed).unwrap();
        assert_eq!(parsed.outputs, outputs.iter().map(|o| (o.value_sat, o.script_pubkey.clone())).collect::<Vec<_>>());
        speculos::back_to_home();

        // A recipient of each other standard type (P2PKH m…, P2SH 2…, P2WSH, Taproot
        // tb1p…): address shown by the device, transaction signed with that output script.
        for to_script in [
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ] {
            let to_script = hex::decode(to_script).unwrap();
            let address = crate::derivation::btc_script_address(&to_script, true).unwrap();
            let mut outputs = test_transaction(&device).1;
            outputs[0].script_pubkey = to_script.clone();
            let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign transaction", "Accept and send", "Approve"]));
            let signed = sign_transaction(&mut t, &device, &inputs, &outputs).unwrap();
            let screens = approver.join().unwrap().join(" | ");
            println!("{address} : {screens}");
            assert!(screens.replace(' ', "").contains(&address[..16]), "{address} affichée");
            assert_eq!(parse_transaction(&signed).unwrap().outputs[0], (60_000, to_script));
            speculos::back_to_home();
        }

        let rejecter = std::thread::spawn(|| speculos::review_and_accept(&["Reject"]));
        let err = sign_transaction(&mut t, &device, &inputs, &outputs).unwrap_err();
        rejecter.join().unwrap();
        assert!(err.to_string().contains("refusée"), "{err}");
        speculos::back_to_home();
    }

    struct Status(u16);
    impl Transport for Status {
        fn exchange(&mut self, _apdu: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.to_be_bytes().to_vec())
        }
    }

    #[test]
    fn bitcoin_specific_status_words() {
        let refused = request(&mut Status(0x6985), INS_SIGN_PSBT, &[], &mut Client::default()).unwrap_err();
        assert!(refused.to_string().contains("refusée"), "{refused}");
        let incorrect = request(&mut Status(0x6a80), INS_SIGN_PSBT, &[], &mut Client::default()).unwrap_err();
        assert!(incorrect.to_string().contains("données incohérentes"), "{incorrect}");
    }
}
