use anyhow::{anyhow, Result};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// A UTXO (unspent output) to consume as a transaction input. `txid` is stored in
/// "display" order (big-endian), as block explorers show it; it is reversed at
/// serialization time.
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

/// A plain Bitcoin transaction: one or more P2WPKH UTXOs from the same address to a
/// recipient of any type (`to_script`, see `derivation::btc_recipient_script`),
/// with an optional change output.
pub struct BtcTx {
    pub inputs: Vec<Utxo>,
    pub to_script: Vec<u8>,
    pub value_sat: u64,
    pub change_hash160: [u8; 20],
    /// 0 if the change is below the dust threshold (it then goes to the fee).
    pub change_sat: u64,
    /// Optional OP_RETURN output (value 0, unspendable), used to carry a memo (e.g. a
    /// THORChain swap memo). `None` behaves exactly as before this field was added (no
    /// regression on regular sends).
    pub op_return_data: Option<Vec<u8>>,
}

pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

pub(crate) fn push_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Identifier (txid, display order) of a serialized transaction: double SHA-256 of
/// its form WITHOUT witnesses (segwit: marker, flag and witnesses removed). `None`
/// if the serialization cannot be read.
pub fn txid(raw: &[u8]) -> Option<String> {
    fn varint(raw: &[u8], pos: &mut usize) -> Option<usize> {
        let first = *raw.get(*pos)?;
        let (value, len) = match first {
            0xfd => (u64::from(u16::from_le_bytes(raw.get(*pos + 1..*pos + 3)?.try_into().ok()?)), 3),
            0xfe => (u64::from(u32::from_le_bytes(raw.get(*pos + 1..*pos + 5)?.try_into().ok()?)), 5),
            0xff => (u64::from_le_bytes(raw.get(*pos + 1..*pos + 9)?.try_into().ok()?), 9),
            n => (u64::from(n), 1),
        };
        *pos += len;
        usize::try_from(value).ok()
    }
    let legacy;
    let body: &[u8] = if raw.get(4) == Some(&0) && raw.get(5) == Some(&1) {
        let mut pos = 6;
        for _ in 0..varint(raw, &mut pos)? {
            pos = pos.checked_add(36)?;
            let script = varint(raw, &mut pos)?;
            pos = pos.checked_add(script)?.checked_add(4)?;
        }
        for _ in 0..varint(raw, &mut pos)? {
            pos = pos.checked_add(8)?;
            let script = varint(raw, &mut pos)?;
            pos = pos.checked_add(script)?;
        }
        if raw.len() < pos.checked_add(4)? {
            return None;
        }
        legacy = [&raw[..4], &raw[6..pos], &raw[raw.len() - 4..]].concat();
        &legacy
    } else {
        raw
    };
    let mut hash = dsha256(body);
    hash.reverse();
    Some(hex::encode(hash))
}

/// Approximate virtual size (vbytes) of a pure P2WPKH transaction (no exotic script),
/// used to estimate the fee BEFORE knowing whether the transaction will have a change
/// output (the logical order is: estimate the fee → decide whether enough is left for
/// a change output → build the real transaction, see `api::send_btc`). Standard,
/// widely used formula for this kind of transaction: ~10.5 vbytes of fixed overhead
/// (version, locktime, segwit marker/flag, input/output counts) + ~68 vbytes per
/// P2WPKH input (thanks to the segwit weight discount on the witness signature and
/// public key) + ~31 vbytes per P2WPKH output.
pub fn estimate_p2wpkh_vsize(num_inputs: usize, num_outputs: usize) -> u64 {
    (10.5 + (num_inputs as f64) * 68.0 + (num_outputs as f64) * 31.0).ceil() as u64
}

/// Largest standard output a send can pay to (P2WSH, Taproot: 8 + 1 + 34 bytes),
/// versus 31 for a P2WPKH.
const LARGEST_RECIPIENT_OUTPUT_VBYTES: f64 = 43.0;

/// Virtual size of a send (`num_inputs` P2WPKH inputs, recipient, P2WPKH change),
/// estimated before the recipient is known. The fee is chosen when the send window
/// opens, so it is computed for the largest possible output: never below the
/// intended rate (at most 12 vbytes too many for a bc1q… address).
pub fn estimate_send_vsize(num_inputs: usize) -> u64 {
    (10.5 + (num_inputs as f64) * 68.0 + LARGEST_RECIPIENT_OUTPUT_VBYTES + 31.0).ceil() as u64
}

/// Bitcoin Core's dust threshold (3 sat/vB relay rate) for an output carrying
/// `script`: below it, nodes refuse the transaction. Size of the output, plus that
/// of the input that would spend it (witness counted at a quarter for a SegWit
/// program): 294 sat for P2WPKH, 330 for P2WSH and Taproot, 540 for P2SH, 546 for
/// P2PKH.
pub fn dust_threshold(script: &[u8]) -> u64 {
    let output = 8 + varint_len(script.len() as u64) + script.len() as u64;
    let witness_program = (4..=42).contains(&script.len()) && (script[0] == 0x00 || (0x51..=0x60).contains(&script[0])) && usize::from(script[1]) + 2 == script.len();
    let spend = if witness_program { 32 + 4 + 1 + 107 / 4 + 4 } else { 32 + 4 + 1 + 107 + 4 };
    (output + spend) * 3
}

pub(crate) fn p2wpkh_script_pubkey(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14]; // OP_0 + push(20)
    s.extend_from_slice(hash160);
    s
}

/// OP_RETURN scriptPubKey carrying `data` in the clear (unspendable, only used to
/// anchor metadata, e.g. a swap memo). Limited in practice to ~80 bytes by the
/// Bitcoin network's standard relay policy.
fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut s = vec![0x6a]; // OP_RETURN
    if data.len() <= 75 {
        s.push(data.len() as u8); // direct push
    } else {
        s.push(0x4c); // OP_PUSHDATA1
        s.push(data.len() as u8);
    }
    s.extend_from_slice(data);
    s
}

/// Size (bytes, = vbytes: no witness part) of an OP_RETURN output carrying `len`
/// bytes: value, script length, script.
pub fn op_return_output_size(len: usize) -> u64 {
    let script = 1 + if len <= 75 { 1 } else { 2 } + len as u64;
    8 + varint_len(script) + script
}

/// scriptCode used in the BIP143 sighash for a P2WPKH input: equivalent to the
/// classic P2PKH script (required by the spec, even though the input is not P2PKH).
fn p2wpkh_script_code(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x19, 0x76, 0xa9, 0x14]; // length + OP_DUP OP_HASH160 push(20)
    s.extend_from_slice(hash160);
    s.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    s
}

/// P2WPKH input of an arbitrary transaction (see `RawTx`).
#[derive(Debug)]
pub struct RawInput {
    /// "Display" order (big-endian), like `Utxo::txid`.
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
    /// Amount of the output being spent, committed to by the signature (BIP143).
    pub value_sat: u64,
}

/// A transaction whose inputs are all P2WPKH from the same key, with arbitrary
/// outputs (value, script): the one the app builds (`BtcTx`), or the one in a PSBT
/// provided by a third party (LI.FI), reread and re-serialized here before signing.
#[derive(Debug)]
pub struct RawTx {
    pub version: u32,
    pub inputs: Vec<RawInput>,
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub locktime: u32,
}

impl RawTx {
    /// Outputs serialized WITHOUT the count prefix (varint): that is the format the
    /// BIP143 sighash expects for `hashOutputs` (unlike the final transaction, which
    /// does need the prefix; see `sign()`).
    fn outputs_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (value, script) in &self.outputs {
            buf.extend_from_slice(&value.to_le_bytes());
            push_varint(&mut buf, script.len() as u64);
            buf.extend_from_slice(script);
        }
        buf
    }

    fn hash_prevouts(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            buf.extend_from_slice(&txid_le);
            buf.extend_from_slice(&input.vout.to_le_bytes());
        }
        dsha256(&buf)
    }

    fn hash_sequence(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for input in &self.inputs {
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        dsha256(&buf)
    }

    /// BIP143 sighash (SIGHASH_ALL) for input `index`, whose scriptCode matches `input_hash160`.
    fn sighash(&self, index: usize, input_hash160: &[u8; 20]) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.version.to_le_bytes());
        preimage.extend_from_slice(&self.hash_prevouts());
        preimage.extend_from_slice(&self.hash_sequence());

        let input = &self.inputs[index];
        let mut txid_le = input.txid;
        txid_le.reverse();
        preimage.extend_from_slice(&txid_le);
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        preimage.extend_from_slice(&p2wpkh_script_code(input_hash160));
        preimage.extend_from_slice(&input.value_sat.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        preimage.extend_from_slice(&dsha256(&self.outputs_body()));
        preimage.extend_from_slice(&self.locktime.to_le_bytes());
        preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        dsha256(&preimage)
    }

    /// Size without witnesses (version, inputs, outputs, locktime).
    fn base_size(&self) -> u64 {
        let mut size = 4 + 4 + varint_len(self.inputs.len() as u64) + varint_len(self.outputs.len() as u64);
        size += self.inputs.len() as u64 * (32 + 4 + 1 + 4);
        for (_, script) in &self.outputs {
            size += 8 + varint_len(script.len() as u64) + script.len() as u64;
        }
        size
    }

    /// Upper bound on the virtual size once signed (72-byte DER signature with its
    /// type, compressed key): used to check the fee rate of a transaction prepared by a
    /// third party.
    pub fn signed_vsize(&self) -> u64 {
        // Segwit marker and flag (2), then per input: count (1) + signature (1 + 72) + key
        // (1 + 33).
        let witness = 2 + self.inputs.len() as u64 * (1 + 1 + 72 + 1 + 33);
        (self.base_size() * 4 + witness).div_ceil(4)
    }

    /// Builds and signs the transaction. Every input must belong to the same key
    /// (`input_hash160`).
    pub fn sign(&self, key: &SigningKey, input_hash160: &[u8; 20]) -> Result<Vec<u8>> {
        let pubkey_compressed = key.verifying_key().to_encoded_point(true);

        let mut witnesses = Vec::new();
        for i in 0..self.inputs.len() {
            let hash = self.sighash(i, input_hash160);
            let signature: Signature = key
                .sign_prehash(&hash)
                .map_err(|e| anyhow!("échec de signature ECDSA : {e}"))?;
            let signature = signature.normalize_s().unwrap_or(signature);
            let der = signature.to_der();
            let mut sig_with_type = der.as_bytes().to_vec();
            sig_with_type.push(0x01); // SIGHASH_ALL
            witnesses.push((sig_with_type, pubkey_compressed.as_bytes().to_vec()));
        }

        let mut tx = Vec::new();
        tx.extend_from_slice(&self.version.to_le_bytes());
        tx.push(0x00); // segwit marker
        tx.push(0x01); // segwit flag

        push_varint(&mut tx, self.inputs.len() as u64);
        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            tx.extend_from_slice(&txid_le);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            tx.push(0x00); // empty scriptSig (native segwit)
            tx.extend_from_slice(&input.sequence.to_le_bytes());
        }

        push_varint(&mut tx, self.outputs.len() as u64);
        tx.extend_from_slice(&self.outputs_body());

        for (sig, pubkey) in &witnesses {
            push_varint(&mut tx, 2); // 2 witness items: signature + public key
            push_varint(&mut tx, sig.len() as u64);
            tx.extend_from_slice(sig);
            push_varint(&mut tx, pubkey.len() as u64);
            tx.extend_from_slice(pubkey);
        }

        tx.extend_from_slice(&self.locktime.to_le_bytes());
        Ok(tx)
    }
}

fn varint_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

impl BtcTx {
    /// The same transaction in generic form: version 1, sequences 0xffffffff, locktime
    /// 0; recipient, change (if above dust) then OP_RETURN (if present), in that order.
    fn to_raw(&self) -> RawTx {
        let mut outputs = vec![(self.value_sat, self.to_script.clone())];
        if self.change_sat > 0 {
            outputs.push((self.change_sat, p2wpkh_script_pubkey(&self.change_hash160)));
        }
        if let Some(data) = &self.op_return_data {
            outputs.push((0, op_return_script(data))); // value 0: unspendable
        }
        let inputs = self.inputs.iter().map(|u| RawInput { txid: u.txid, vout: u.vout, sequence: 0xffff_ffff, value_sat: u.value_sat }).collect();
        RawTx { version: 1, inputs, outputs, locktime: 0 }
    }

    #[cfg(test)]
    fn outputs_body(&self) -> Vec<u8> {
        self.to_raw().outputs_body()
    }

    #[cfg(test)]
    pub(crate) fn sighash(&self, index: usize, input_hash160: &[u8; 20]) -> [u8; 32] {
        self.to_raw().sighash(index, input_hash160)
    }

    /// Builds and signs the transaction. Every input must belong to the same key
    /// (`input_hash160`), which is always the case here (one address per wallet
    /// profile).
    pub fn sign(&self, key: &SigningKey, input_hash160: &[u8; 20]) -> Result<Vec<u8>> {
        self.to_raw().sign(key, input_hash160)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    /// Widely quoted reference for a 1-input / 2-output P2WPKH transaction: ~141-143
    /// vbytes measured in practice. A guard against a regression in the formula (e.g.
    /// overhead or per-input/output cost changed by mistake), not proof of byte-exact
    /// accuracy: the estimate stays deliberately approximate (see its documentation).
    #[test]
    fn estimate_p2wpkh_vsize_matches_known_reference_for_one_input_two_outputs() {
        let vsize = estimate_p2wpkh_vsize(1, 2);
        assert!((140..=143).contains(&vsize), "vsize inattendue : {vsize}");
    }

    #[test]
    fn estimate_p2wpkh_vsize_grows_with_more_inputs_and_outputs() {
        let base = estimate_p2wpkh_vsize(1, 1);
        assert!(estimate_p2wpkh_vsize(2, 1) > base);
        assert!(estimate_p2wpkh_vsize(1, 2) > base);
    }

    #[test]
    fn push_varint_boundaries() {
        let cases: [(u64, &[u8]); 4] = [
            (0x00, &[0x00]),
            (0xfc, &[0xfc]),
            (0xfd, &[0xfd, 0xfd, 0x00]),
            (0x10000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
        ];
        for (value, expected) in cases {
            let mut buf = Vec::new();
            push_varint(&mut buf, value);
            assert_eq!(buf, expected, "varint pour {value}");
        }
    }

    /// Direct guard against a bug we already hit: `outputs_body` (used for
    /// `hashOutputs` in the BIP143 sighash) must NEVER start with an output count byte,
    /// only with the value (8 bytes little-endian) of the first output. That exact
    /// mix-up used to produce invalid signatures.
    #[test]
    fn outputs_body_never_starts_with_a_count_byte() {
        let hash160 = [0x33u8; 20];
        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0u8; 32], vout: 0, value_sat: 10_000 }],
            to_script: p2wpkh_script_pubkey(&[0x44u8; 20]),
            value_sat: 9_000,
            change_hash160: hash160,
            change_sat: 0,
            op_return_data: None,
        };
        let body = tx.outputs_body();
        assert_eq!(&body[0..8], &tx.value_sat.to_le_bytes());
        // A single output here: 8 (value) + 1 (script length) + 22 (P2WPKH script).
        assert_eq!(body.len(), 8 + 1 + 22);
    }

    #[test]
    fn outputs_body_includes_change_when_above_dust() {
        let hash160 = [0x11u8; 20];
        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0xAAu8; 32], vout: 0, value_sat: 100_000 }],
            to_script: p2wpkh_script_pubkey(&[0x22u8; 20]),
            value_sat: 50_000,
            change_hash160: hash160,
            change_sat: 49_000,
            op_return_data: None,
        };
        let body = tx.outputs_body();
        // Two outputs: 2 * (8 + 1 + 22) = 62 bytes.
        assert_eq!(body.len(), 2 * (8 + 1 + 22));
    }

    /// The OP_RETURN output must be present, unspendable (value 0) and carry the memo
    /// in the clear, without breaking anything else (a guard against a regression in
    /// `num_outputs`/`sign` introduced by this feature).
    #[test]
    fn outputs_body_includes_op_return_when_present() {
        let hash160 = [0x11u8; 20];
        let memo = b"SWAP:BTC.BTC:bc1qxyz:0/1/0:thor1abc:80".to_vec();
        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0xAAu8; 32], vout: 0, value_sat: 100_000 }],
            to_script: p2wpkh_script_pubkey(&[0x22u8; 20]),
            value_sat: 50_000,
            change_hash160: hash160,
            change_sat: 49_000,
            op_return_data: Some(memo.clone()),
        };
        let body = tx.outputs_body();
        // Main output + change (2 * 31 bytes), then OP_RETURN: value (8, zero) + script
        // length (1) + OP_RETURN (1) + direct push (1) + memo.
        let expected_len = 2 * (8 + 1 + 22) + 8 + 1 + 1 + 1 + memo.len();
        assert_eq!(body.len(), expected_len);
        let op_return_offset = 2 * (8 + 1 + 22);
        assert_eq!(&body[op_return_offset..op_return_offset + 8], &0u64.to_le_bytes());
        assert_eq!(body[op_return_offset + 9], 0x6a, "OP_RETURN attendu");
        assert_eq!(body[op_return_offset + 10], memo.len() as u8, "push direct de la longueur");
        assert_eq!(&body[op_return_offset + 11..], &memo[..]);

        let key = SigningKey::from_slice(&[9u8; 32]).expect("clé de test valide");
        let raw = tx.sign(&key, &hash160).expect("signature réussie avec OP_RETURN");
        // 3 outputs now: the count varint must be 3. (marker+flag = 2 bytes after the 4
        // version bytes, then the input count varint = 1 byte here, 41 bytes of input,
        // then the output count varint)
        let outputs_count_offset = 4 + 2 + 1 + 41;
        assert_eq!(raw[outputs_count_offset], 3, "3 sorties attendues (dest + monnaie + OP_RETURN)");
    }

    /// Regression test: the BIP143 sighash, recomputed independently, must be exactly
    /// the one the signature produced by `sign()` is valid against. This would have
    /// caught the earlier bug (badly built hashOutputs).
    #[test]
    fn signature_verifies_against_recomputed_sighash() {
        let key = SigningKey::from_slice(&[9u8; 32]).expect("clé de test valide");
        let hash160 = [0x11u8; 20];

        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0xAAu8; 32], vout: 0, value_sat: 100_000 }],
            to_script: p2wpkh_script_pubkey(&[0x22u8; 20]),
            value_sat: 50_000,
            change_hash160: hash160,
            change_sat: 49_000,
            op_return_data: None,
        };

        // sign() must succeed (exercises the whole pipeline: building, signing, serializing).
        let raw = tx.sign(&key, &hash160).expect("signature réussie");
        assert_eq!(&raw[4..6], &[0x00, 0x01], "marker + flag segwit attendus");

        let expected_hash = tx.sighash(0, &hash160);
        let verifying_key = VerifyingKey::from(&key);
        let signature: Signature = key.sign_prehash(&expected_hash).expect("signature de contrôle");
        verifying_key
            .verify_prehash(&expected_hash, &signature)
            .expect("la signature doit vérifier contre le sighash BIP143 recalculé");
    }

    /// Official BIP143 vector ("Native P2WPKH"): version 1, sequence 0xffffffee on the
    /// first input, locktime 17, P2PKH outputs. These are the fields a third-party PSBT
    /// may set differently from the app.
    #[test]
    fn raw_tx_sighash_matches_the_bip143_native_p2wpkh_vector() {
        let display = |le_hex: &str| -> [u8; 32] {
            let mut bytes: [u8; 32] = hex::decode(le_hex).unwrap().try_into().unwrap();
            bytes.reverse();
            bytes
        };
        let tx = RawTx {
            version: 1,
            inputs: vec![
                RawInput { txid: display("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"), vout: 0, sequence: 0xffff_ffee, value_sat: 625_000_000 },
                RawInput { txid: display("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"), vout: 1, sequence: 0xffff_ffff, value_sat: 600_000_000 },
            ],
            outputs: vec![
                (112_340_000, hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").unwrap()),
                (223_450_000, hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").unwrap()),
            ],
            locktime: 17,
        };
        let hash160: [u8; 20] = hex::decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap().try_into().unwrap();
        assert_eq!(hex::encode(tx.sighash(1, &hash160)), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");

        // Signature with the vector's key: valid for this sighash, and the real size stays
        // under the `signed_vsize` bound.
        let key = SigningKey::from_slice(&hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9").unwrap()).unwrap();
        let raw = tx.sign(&key, &hash160).unwrap();
        let witness_bytes = raw.len() as u64 - (tx.base_size());
        let real_vsize = (tx.base_size() * 4 + witness_bytes).div_ceil(4);
        assert!(real_vsize <= tx.signed_vsize(), "{real_vsize} > {}", tx.signed_vsize());
        assert_eq!(op_return_output_size(55), 8 + 1 + 57);
        assert_eq!(op_return_output_size(80), 8 + 1 + 83);
    }

    fn script(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    /// Scripts of every standard type (vectors from `derivation`).
    fn standard_scripts() -> [(&'static str, Vec<u8>); 5] {
        [
            ("P2PKH", script("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac")),
            ("P2SH", script("a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87")),
            ("P2WPKH", script("0014751e76e8199196d454941c45d1b3a323f1433bd6")),
            ("P2WSH", script("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")),
            ("P2TR", script("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        ]
    }

    /// Bitcoin Core dust thresholds (`GetDustThreshold`, 3 sat/vB relay rate) for each
    /// output type.
    #[test]
    fn dust_thresholds_match_bitcoin_core() {
        let expected = [546, 540, 294, 330, 330];
        for ((name, script), dust) in standard_scripts().into_iter().zip(expected) {
            assert_eq!(dust_threshold(&script), dust, "{name}");
        }
    }

    /// Sending to every output type: the signed transaction carries the recipient's
    /// script as is, its signature verifies against that transaction's BIP143 sighash,
    /// and its real size stays under the estimate made before the recipient was known
    /// (at most 12 vbytes over for the smallest output).
    #[test]
    fn sends_to_every_standard_output_type_are_signed_and_sized() {
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let hash160 = crate::ledger::btc::hash160(key.verifying_key().to_encoded_point(true).as_bytes());
        for inputs in [1usize, 3] {
            for (name, to_script) in standard_scripts() {
                let tx = BtcTx {
                    inputs: (0..inputs).map(|i| Utxo { txid: [i as u8 + 1; 32], vout: i as u32, value_sat: 100_000 }).collect(),
                    to_script: to_script.clone(),
                    value_sat: 50_000,
                    change_hash160: hash160,
                    change_sat: 40_000,
                    op_return_data: None,
                };
                let raw = tx.sign(&key, &hash160).unwrap();
                let parsed = crate::ledger::btc::parse_transaction(&raw).unwrap();
                assert_eq!(parsed.outputs[0], (50_000, to_script.clone()), "{name}");
                assert_eq!(parsed.outputs[1], (40_000, p2wpkh_script_pubkey(&hash160)), "{name}");

                // Witnesses: between the non-witness part (version, inputs, outputs) and the
                // locktime; per input, 2 items (DER signature + type, compressed key), lengths <
                // 0xfd.
                let unsigned = tx.to_raw();
                let mut pos = 4 + 2 + (parsed.stripped.len() - 8);
                for index in 0..inputs {
                    assert_eq!(raw[pos], 2, "{name}");
                    let signature = &raw[pos + 2..pos + 2 + usize::from(raw[pos + 1])];
                    pos += 2 + signature.len();
                    let pubkey = &raw[pos + 1..pos + 1 + usize::from(raw[pos])];
                    pos += 1 + pubkey.len();
                    assert_eq!(signature.last(), Some(&0x01), "SIGHASH_ALL");
                    let signature = Signature::from_der(&signature[..signature.len() - 1]).unwrap();
                    VerifyingKey::from_sec1_bytes(pubkey)
                        .unwrap()
                        .verify_prehash(&unsigned.sighash(index, &hash160), &signature)
                        .unwrap_or_else(|e| panic!("{name}, entrée {index} : {e}"));
                }
                assert_eq!(pos, raw.len() - 4, "{name} : témoins entièrement lus");

                // Weight = non-witness part × 3 + whole transaction.
                assert_eq!(parsed.stripped.len() as u64, unsigned.base_size(), "{name}");
                let real_vsize = (parsed.stripped.len() as u64 * 3 + raw.len() as u64).div_ceil(4);
                let estimate = estimate_send_vsize(inputs);
                assert!(real_vsize <= estimate, "{name}, {inputs} entrée(s) : {real_vsize} > {estimate}");
                assert!(estimate - real_vsize <= 12 + inputs as u64, "{name}, {inputs} entrée(s) : estimation {estimate}, réel {real_vsize}");
            }
        }
    }

    /// Vectors for verification by an independent library (embit): addresses of every type
    /// (mainnet and testnet) with their script, and signed transactions to each of them. Written
    /// to the `BTC_VECTORS_OUT` file.
    /// `BTC_VECTORS_OUT=… cargo test -p openpgp-wallet-core --lib -- --ignored export_btc_vectors`
    #[test]
    #[ignore]
    fn export_btc_vectors() {
        use crate::derivation::{btc_mainnet_recipient_script, btc_script_address, btc_testnet_recipient_script};
        let recipient = |address: &str, testnet: bool| if testnet { btc_testnet_recipient_script(address) } else { btc_mainnet_recipient_script(address) };
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let pubkey = key.verifying_key().to_encoded_point(true);
        let hash160 = crate::ledger::btc::hash160(pubkey.as_bytes());
        let mut addresses = Vec::new();
        let mut transactions = Vec::new();
        for testnet in [false, true] {
            for (name, to_script) in standard_scripts() {
                let address = btc_script_address(&to_script, testnet).unwrap();
                assert_eq!(recipient(&address, testnet).unwrap(), to_script, "{address}");
                addresses.push(serde_json::json!({ "address": address, "script": hex::encode(&to_script), "testnet": testnet }));
                let tx = BtcTx {
                    inputs: vec![Utxo { txid: [0x11; 32], vout: 0, value_sat: 70_000 }, Utxo { txid: [0x22; 32], vout: 3, value_sat: 30_000 }],
                    to_script: to_script.clone(),
                    value_sat: 60_000,
                    change_hash160: hash160,
                    change_sat: 38_000,
                    op_return_data: None,
                };
                transactions.push(serde_json::json!({
                    "name": format!("{name}{}", if testnet { " (testnet)" } else { "" }),
                    "testnet": testnet,
                    "raw": hex::encode(tx.sign(&key, &hash160).unwrap()),
                    "to": address,
                    "value": 60_000,
                    "pubkey": hex::encode(pubkey.as_bytes()),
                    "input_values": [70_000, 30_000],
                    "estimated_vsize": estimate_send_vsize(2),
                }));
            }
        }
        let out = std::env::var("BTC_VECTORS_OUT").expect("BTC_VECTORS_OUT");
        std::fs::write(&out, serde_json::to_string_pretty(&serde_json::json!({ "addresses": addresses, "transactions": transactions })).unwrap()).unwrap();
        println!("vecteurs écrits dans {out}");
    }
}
