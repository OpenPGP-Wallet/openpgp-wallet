use anyhow::{anyhow, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

/// A plain "legacy" (non-EIP-1559) Ethereum transaction: an ETH transfer, or a
/// contract call when `data` is set.
pub struct EthTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub chain_id: u64,
    /// Contract call data. Empty for a plain transfer. Non-empty for a THORChain swap
    /// (`thorchain_deposit_calldata`): `gas_limit` must then come from a real estimate
    /// of the execution (`EthRpc::estimate_gas`), never from `intrinsic_gas` alone,
    /// which is only the minimum needed to SUBMIT the transaction (measured: 23,844
    /// versus 45,632 actually consumed by a deposit on the THORChain router).
    pub data: Vec<u8>,
}

/// Encodes an integer as "minimal big-endian" RLP (leading zeros removed, 0 -> empty
/// string), as Ethereum transaction integer fields require.
fn trim_be(bytes: &[u8]) -> Vec<u8> {
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(i) => bytes[i..].to_vec(),
        None => Vec::new(),
    }
}

impl EthTx {
    fn encode(&self, v: Option<(u64, &[u8], &[u8])>) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.begin_list(9);
        s.append(&trim_be(&self.nonce.to_be_bytes()));
        s.append(&trim_be(&self.gas_price.to_be_bytes()));
        s.append(&trim_be(&self.gas_limit.to_be_bytes()));
        s.append(&self.to.as_slice());
        s.append(&trim_be(&self.value.to_be_bytes()));
        s.append(&self.data);

        match v {
            None => {
                // EIP-155 tuple on the unsigned tx: (chain_id, 0, 0)
                s.append(&trim_be(&self.chain_id.to_be_bytes()));
                s.append(&Vec::<u8>::new());
                s.append(&Vec::<u8>::new());
            }
            Some((v, r, sig_s)) => {
                s.append(&trim_be(&v.to_be_bytes()));
                s.append(&r);
                s.append(&sig_s);
            }
        }
        s.out().to_vec()
    }

    /// UNSIGNED RLP encoding (EIP-155 tuple `chain_id, 0, 0` at the end): what a
    /// hardware wallet signs (see `ledger::eth`).
    pub fn unsigned_rlp(&self) -> Vec<u8> {
        self.encode(None)
    }

    /// Final transaction from a signature produced elsewhere (hardware device): full
    /// EIP-155 `v`, `r`/`s` on 32 bytes.
    pub fn encode_with_signature(&self, v: u64, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        self.encode(Some((v, trim_be(r).as_slice(), trim_be(s).as_slice())))
    }

    fn hash_unsigned(&self) -> [u8; 32] {
        let unsigned = self.encode(None);
        let digest = Keccak256::digest(&unsigned);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Signs the transaction with the derived private key and returns the RLP-encoded
    /// transaction, ready to send with `eth_sendRawTransaction`.
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        let hash = self.hash_unsigned();

        let (signature, recid): (Signature, RecoveryId) = key
            .sign_prehash(&hash)
            .map_err(|e| anyhow!("échec de signature ECDSA : {e}"))?;

        let r = signature.r().to_bytes();
        let s_val = signature.s().to_bytes();
        let v = self.chain_id * 2 + 35 + u64::from(recid.to_byte());

        Ok(self.encode(Some((v, trim_be(&r).as_slice(), trim_be(&s_val).as_slice()))))
    }
}

/// Actual intrinsic gas of a transaction (the post-EIP-2028 rule, in force since
/// Istanbul): 21,000 base + 16 per non-zero calldata byte + 4 per zero byte. A
/// plain transfer (empty `data`) gives exactly 21,000. This is only a FLOOR (the
/// minimum to submit the transaction): for a contract call, execution consumes much
/// more; see `EthTx::data`.
pub fn intrinsic_gas(data: &[u8]) -> u64 {
    const BASE: u64 = 21_000;
    let (zero, nonzero) = data.iter().fold((0u64, 0u64), |(zero, nonzero), &b| {
        if b == 0 { (zero + 1, nonzero) } else { (zero, nonzero + 1) }
    });
    BASE + zero * 4 + nonzero * 16
}

fn pad_left_32(bytes: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    buf
}

/// Encodes the `depositWithExpiry(address vault, address asset, uint256 amount,
/// string memo, uint256 expiration)` call of the "THORChain Router" contract, as a
/// THORChain swap from an EVM chain requires (see `thorchain_rpc` for context:
/// `vault` = `SwapQuote::inbound_address`, and the call must target
/// `SwapQuote::router`, never `inbound_address` directly). The selector
/// (`0x44bc937b`) was checked live against the public 4byte.directory database,
/// never worked out by eye. Follows the standard Solidity ABI encoding: the first 3
/// static parameters are encoded in place, `memo` (the only dynamic type) is
/// replaced in the head by an offset to the tail, and `expiration` stays static
/// after that offset. See the test
/// `thorchain_deposit_calldata_matches_a_hand_computed_reference` for a
/// byte-for-byte check against the spec.
pub fn thorchain_deposit_calldata(vault: &[u8; 20], asset: &[u8; 20], amount: u128, memo: &str, expiration: u64) -> Vec<u8> {
    const SELECTOR: [u8; 4] = [0x44, 0xbc, 0x93, 0x7b];
    const HEAD_SLOTS: u128 = 5; // vault, asset, amount, offset(memo), expiration

    let memo_bytes = memo.as_bytes();
    let mut data = Vec::with_capacity(4 + 32 * 5 + 32 + memo_bytes.len().div_ceil(32) * 32);
    data.extend_from_slice(&SELECTOR);

    data.extend_from_slice(&pad_left_32(vault));
    data.extend_from_slice(&pad_left_32(asset));
    data.extend_from_slice(&pad_left_32(&amount.to_be_bytes()));
    data.extend_from_slice(&pad_left_32(&(HEAD_SLOTS * 32).to_be_bytes())); // memo offset
    data.extend_from_slice(&pad_left_32(&(expiration as u128).to_be_bytes()));

    data.extend_from_slice(&pad_left_32(&(memo_bytes.len() as u128).to_be_bytes()));
    data.extend_from_slice(memo_bytes);
    let padding = (32 - memo_bytes.len() % 32) % 32;
    data.extend(std::iter::repeat(0u8).take(padding));

    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    #[test]
    fn trim_be_removes_leading_zeros() {
        assert_eq!(trim_be(&[0, 0, 1, 2]), vec![1, 2]);
        assert_eq!(trim_be(&[0, 0, 0, 0]), Vec::<u8>::new());
        assert_eq!(trim_be(&[5, 6]), vec![5, 6]);
        assert_eq!(trim_be(&[1]), vec![1]);
    }

    /// Ethereum requires a "low-S" signature since Homestead (EIP-2): a "high-S"
    /// signature is rejected by the network AND allows a second valid signature for the
    /// same message (malleability, `s' = n - s`). `sign()` never calls `normalize_s()`
    /// explicitly (unlike `btc_tx.rs::sign()`, which does), so this test checks
    /// empirically, over a large number of distinct hashes, that
    /// `k256::ecdsa::SigningKey::sign_prehash` always produces a normalized signature
    /// on its own, rather than assuming it.
    #[test]
    fn signatures_are_always_low_s_without_explicit_normalization() {
        let key = SigningKey::from_slice(&[3u8; 32]).expect("clé de test valide");
        for i in 0..2000u32 {
            let hash = Keccak256::digest(i.to_be_bytes());
            let (signature, _recid): (Signature, RecoveryId) =
                key.sign_prehash(&hash).expect("signature réussie");
            assert!(
                signature.normalize_s().is_none(),
                "signature high-S produite pour i={i} : normalize_s() n'aurait jamais dû être nécessaire"
            );
        }
    }

    /// Regression test: signs a transaction, decodes it again from RLP and checks that
    /// the signature (r, s) matches the recomputed unsigned hash with the corresponding
    /// public key. It would have caught the kind of bug already met on the Bitcoin side
    /// (a badly built hashOutputs) had it existed here.
    #[test]
    fn signed_tx_round_trips_and_signature_verifies() {
        let key = SigningKey::from_slice(&[7u8; 32]).expect("clé de test valide");
        let tx = EthTx {
            nonce: 3,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: [0xABu8; 20],
            value: 1_000_000_000_000_000_000, // 1 ETH
            chain_id: 11155111,                // Sepolia
            data: Vec::new(),
        };

        let raw = tx.sign(&key).expect("signature réussie");
        let rlp = rlp::Rlp::new(&raw);
        assert_eq!(rlp.item_count().unwrap(), 9);

        let nonce: u64 = rlp.val_at(0).unwrap();
        assert_eq!(nonce, tx.nonce);
        let to: Vec<u8> = rlp.val_at(3).unwrap();
        assert_eq!(to, tx.to.to_vec());
        let value_bytes: Vec<u8> = rlp.val_at(4).unwrap();
        assert_eq!(value_bytes, trim_be(&tx.value.to_be_bytes()));

        let sig_v: u64 = rlp.val_at(6).unwrap();
        let sig_r: Vec<u8> = rlp.val_at(7).unwrap();
        let sig_s: Vec<u8> = rlp.val_at(8).unwrap();

        // v = chain_id*2 + 35 + recid; recid can only be 0 or 1.
        let expected_base = tx.chain_id * 2 + 35;
        assert!(sig_v == expected_base || sig_v == expected_base + 1);

        let mut r_padded = [0u8; 32];
        r_padded[32 - sig_r.len()..].copy_from_slice(&sig_r);
        let mut s_padded = [0u8; 32];
        s_padded[32 - sig_s.len()..].copy_from_slice(&sig_s);
        let signature = Signature::from_scalars(r_padded, s_padded).expect("signature reconstructible");

        let verifying_key = VerifyingKey::from(&key);
        let hash = tx.hash_unsigned();
        verifying_key
            .verify_prehash(&hash, &signature)
            .expect("la signature doit vérifier contre la clé publique et le hash non-signé");
    }

    #[test]
    fn intrinsic_gas_matches_the_base_cost_for_an_empty_payload() {
        // A plain transfer (empty data) must give exactly 21,000: no regression on the
        // existing send path, which hard-coded that value before this addition.
        assert_eq!(intrinsic_gas(&[]), 21_000);
    }

    #[test]
    fn intrinsic_gas_counts_zero_and_nonzero_bytes_at_their_real_eip2028_cost() {
        let data = [0x00, 0x00, 0xFF, 0x01]; // 2 zero bytes, 2 non-zero
        assert_eq!(intrinsic_gas(&data), 21_000 + 2 * 4 + 2 * 16);
    }

    /// Checks the `thorchain_deposit_calldata` encoding byte for byte against the
    /// Solidity ABI spec, worked out by hand here (not just "it compiles"): selector, 3
    /// static fields in place, offset to the memo (the only dynamic type), then the
    /// memo's length + content + padding in the tail. The `0x44bc937b` selector was
    /// checked live against 4byte.directory before going into the code (never worked
    /// out by eye).
    #[test]
    fn thorchain_deposit_calldata_matches_a_hand_computed_reference() {
        let vault = [0x11u8; 20];
        let asset = [0x22u8; 20];
        let amount: u128 = 1000;
        let memo = "AB";
        let expiration: u64 = 5;

        let calldata = thorchain_deposit_calldata(&vault, &asset, amount, memo, expiration);

        // 4 (selector) + 5*32 (head) + 32 (memo length) + 32 (memo padded to 32) = 228.
        assert_eq!(calldata.len(), 228);

        assert_eq!(&calldata[0..4], &[0x44, 0xbc, 0x93, 0x7b]);

        // vault: 12 zero bytes, then the address (20 bytes), right-aligned.
        assert_eq!(&calldata[4..16], &[0u8; 12]);
        assert_eq!(&calldata[16..36], &vault);

        // asset: same layout.
        assert_eq!(&calldata[36..48], &[0u8; 12]);
        assert_eq!(&calldata[48..68], &asset);

        // amount: big-endian uint256, value 1000 in the last bytes.
        assert_eq!(&calldata[68..98], &[0u8; 30]);
        assert_eq!(&calldata[98..100], &[0x03, 0xe8]); // 1000

        // memo offset: 5 head slots * 32 = 160 = 0xa0.
        assert_eq!(&calldata[100..131], &[0u8; 31]);
        assert_eq!(calldata[131], 0xa0);

        // expiration: big-endian uint256, value 5.
        assert_eq!(&calldata[132..163], &[0u8; 31]);
        assert_eq!(calldata[163], 5);

        // memo length ("AB" = 2 bytes), then content and padding.
        assert_eq!(&calldata[164..195], &[0u8; 31]);
        assert_eq!(calldata[195], 2);
        assert_eq!(&calldata[196..198], b"AB");
        assert_eq!(&calldata[198..228], &[0u8; 30], "padding du memo jusqu'à 32 octets");
    }
}
