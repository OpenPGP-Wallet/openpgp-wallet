//! Robustness tests (from the "before public trust" checklist): a multi-input
//! Bitcoin transaction checked signature by signature, amounts at the limits
//! (u64/u128), and deterministic fuzzing of amount and address parsing: random
//! inputs (never a panic, never wrongly accepted) and valid addresses with a single
//! character altered (rejected by their checksum).
//!
//! Home-made pseudo-random generator with a fixed seed: every failure replays
//! identically, with no extra test dependency.

use crate::btc_tx::{BtcTx, Utxo};
use crate::{derivation, monero, tokens, zcash, zcash_shielded};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// xorshift64*: good enough to generate varied test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn read_varint(raw: &[u8], at: &mut usize) -> u64 {
    let first = raw[*at];
    *at += 1;
    let width = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        n => return u64::from(n),
    };
    let mut value = 0u64;
    for i in 0..width {
        value |= u64::from(raw[*at + i]) << (8 * i);
    }
    *at += width;
    value
}

/// Transaction with 5 inputs: read back byte by byte, each witness carries a valid
/// DER signature (low-S) against the BIP143 sighash of ITS input, with the
/// address's public key; consistent amounts (outputs < inputs).
#[test]
fn multi_input_bitcoin_transaction_signs_every_input() {
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let verifying = VerifyingKey::from(&key);
    let pubkey = verifying.to_encoded_point(true);
    let hash160 = {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};
        let digest: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey.as_bytes())).into();
        digest
    };
    let values = [10_000u64, 250_000, 1, 99_999_999, 546];
    let inputs: Vec<Utxo> = values
        .iter()
        .enumerate()
        .map(|(i, v)| Utxo {
            txid: [i as u8 + 1; 32],
            vout: i as u32 * 3,
            value_sat: *v,
        })
        .collect();
    let total: u64 = values.iter().sum();
    let tx = BtcTx {
        inputs,
        to_script: crate::btc_tx::p2wpkh_script_pubkey(&[0x42; 20]),
        value_sat: 100_000_000,
        change_hash160: hash160,
        change_sat: total - 100_000_000 - 2_000,
        op_return_data: None,
    };
    let raw = tx.sign(&key, &hash160).unwrap();

    let mut at = 6; // version + segwit marker/flag
    assert_eq!(&raw[4..6], &[0x00, 0x01]);
    let n_inputs = read_varint(&raw, &mut at);
    assert_eq!(n_inputs, 5);
    for i in 0..5 {
        let txid: [u8; 32] = raw[at..at + 32].try_into().unwrap();
        let mut expected = [i as u8 + 1; 32];
        expected.reverse();
        assert_eq!(txid, expected, "txid de l'entrée {i} (ordre inversé)");
        assert_eq!(
            u32::from_le_bytes(raw[at + 32..at + 36].try_into().unwrap()),
            i as u32 * 3
        );
        assert_eq!(raw[at + 36], 0, "scriptSig vide (segwit)");
        at += 41;
    }
    let n_outputs = read_varint(&raw, &mut at);
    let mut sent = 0u64;
    for _ in 0..n_outputs {
        sent += u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        at += 8;
        let script_len = read_varint(&raw, &mut at) as usize;
        at += script_len;
    }
    assert!(sent < total, "sorties {sent} >= entrées {total}");
    assert_eq!(total - sent, 2_000, "frais exacts");
    let mut sighashes = std::collections::HashSet::new();
    for i in 0..5 {
        assert_eq!(read_varint(&raw, &mut at), 2, "témoin à deux éléments");
        let sig_len = read_varint(&raw, &mut at) as usize;
        let sig = &raw[at..at + sig_len];
        at += sig_len;
        assert_eq!(*sig.last().unwrap(), 0x01, "SIGHASH_ALL");
        let pk_len = read_varint(&raw, &mut at) as usize;
        assert_eq!(&raw[at..at + pk_len], pubkey.as_bytes());
        at += pk_len;
        let signature = Signature::from_der(&sig[..sig.len() - 1]).unwrap();
        assert!(signature.normalize_s().is_none(), "signature low-S");
        let sighash = tx.sighash(i, &hash160);
        assert!(sighashes.insert(sighash), "sighash distinct par entrée");
        verifying
            .verify_prehash(&sighash, &signature)
            .unwrap_or_else(|_| panic!("signature de l'entrée {i} invalide"));
    }
    assert_eq!(raw.len(), at + 4, "locktime en fin de transaction");
}

/// Amounts: exact u128 and u64 bounds (ZEC, XMR), then 20,000 random inputs. No
/// panic, and every accepted amount reads back identically.
#[test]
fn amounts_at_the_limits_and_under_fuzzing() {
    let max = u128::MAX.to_string();
    assert_eq!(tokens::parse_amount(&max, 0).unwrap(), u128::MAX);
    assert!(
        tokens::parse_amount("340282366920938463463374607431768211456", 0).is_err(),
        "u128::MAX + 1"
    );
    assert_eq!(
        tokens::parse_amount("3.40282366920938463463374607431768211455", 38).unwrap(),
        u128::MAX
    );
    assert!(
        tokens::parse_amount("1", 39).is_err(),
        "10^39 ne tient pas dans u128"
    );
    assert!(
        tokens::parse_amount("0", 18).is_err() && tokens::parse_amount("0.000", 18).is_err(),
        "montant nul refusé"
    );
    // XMR (12 decimals, u64 of piconeros) and ZEC (8 decimals, u64 of zatoshis).
    assert_eq!(
        monero::parse_xmr("18446744.073709551615").unwrap(),
        u64::MAX
    );
    assert!(monero::parse_xmr("18446744.073709551616").is_err());
    let zat = |s: &str| {
        tokens::parse_amount(s, 8)
            .ok()
            .and_then(|u| u64::try_from(u).ok())
    };
    assert_eq!(zat("184467440737.09551615"), Some(u64::MAX));
    assert_eq!(zat("184467440737.09551616"), None);

    let alphabet = [
        '0', '1', '5', '9', '.', '.', '-', '+', 'e', 'E', ' ', ',', '_', 'x', '٣', '١', '\u{200b}',
        '½',
    ];
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let (mut accepted, mut refused) = (0, 0);
    for round in 0..40_000 {
        // Half noise (mixed characters), half well-formed numbers: digits, at most one
        // dot, sometimes more decimals than allowed or surrounding spaces.
        let input: String = if round % 2 == 0 {
            let len = rng.below(24);
            (0..len).map(|_| *rng.pick(&alphabet)).collect()
        } else {
            let digits = |rng: &mut Rng, n: usize| {
                (0..n)
                    .map(|_| char::from(b'0' + rng.below(10) as u8))
                    .collect::<String>()
            };
            let n = rng.below(22);
            let whole = digits(&mut rng, n);
            let fraction = if rng.below(3) == 0 {
                String::new()
            } else {
                {
                    let n = rng.below(28);
                    format!(".{}", digits(&mut rng, n))
                }
            };
            let pad = if rng.below(5) == 0 { " " } else { "" };
            format!("{pad}{whole}{fraction}{pad}")
        };
        let decimals = rng.below(25) as u8;
        let Ok(units) = tokens::parse_amount(&input, decimals) else {
            refused += 1;
            continue;
        };
        accepted += 1;
        {
            assert!(units > 0);
            assert!(
                input
                    .trim()
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'.'),
                "accepté à tort : {input:?}"
            );
            let shown = tokens::format_amount(units, decimals);
            assert_eq!(
                tokens::parse_amount(&shown, decimals).unwrap(),
                units,
                "aller-retour {input:?} -> {shown}"
            );
            // Truncated displayed balance: never above the real balance.
            let cut = rng.below(usize::from(decimals) + 1) as u8;
            let balance = tokens::format_balance(units, decimals, cut);
            if let Ok(back) = tokens::parse_amount(&balance, decimals) {
                assert!(back <= units, "{balance} > {shown}");
            }
        }
    }
    println!("montants : {accepted} acceptés, {refused} refusés");
    assert!(
        accepted > 5_000 && refused > 5_000,
        "fuzzing trop peu varié ({accepted}/{refused})"
    );
}

/// One character of a valid address replaced by another from the same alphabet:
/// always rejected (bech32/bech32m, base58check, Monero base58 with a keccak
/// checksum); and random strings never make the parsers panic.
#[test]
fn addresses_reject_single_character_typos_and_survive_fuzzing() {
    let btc = derivation::format_btc_mainnet_address(&[0x5a; 20]).unwrap();
    let zec_t1 = zcash::p2pkh_address(&[0x33; 20]);
    let seed = [3u8; 64];
    let xmr = monero::view_keys(&seed, 0).unwrap().address().unwrap();
    let u1 = zcash_shielded::address(&zcash_shielded::viewing_key(&seed, 0).unwrap()).unwrap();
    assert!(derivation::parse_btc_mainnet_address(&btc).is_ok());
    assert!(zcash::parse_recipient(&zec_t1).is_ok());
    assert!(monero::parse_recipient(&xmr).is_ok());
    assert!(zcash_shielded::parse_shielded_address(&u1).is_ok());

    const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut rng = Rng(0x0dd_ba11_c0ff_ee42);
    let mutate = |rng: &mut Rng, address: &str, prefix: usize, alphabet: &str| -> Option<String> {
        let chars: Vec<char> = address.chars().collect();
        let at = prefix + rng.below(chars.len() - prefix);
        let replacement = alphabet.chars().nth(rng.below(alphabet.len()))?;
        if replacement == chars[at] {
            return None;
        }
        let mut out = chars;
        out[at] = replacement;
        Some(out.into_iter().collect())
    };
    let mut checked = 0;
    for _ in 0..400 {
        if let Some(bad) = mutate(&mut rng, &btc, 4, BECH32) {
            assert!(
                derivation::parse_btc_mainnet_address(&bad).is_err(),
                "BTC altérée acceptée : {bad}"
            );
            checked += 1;
        }
        if let Some(bad) = mutate(&mut rng, &zec_t1, 2, BASE58) {
            assert!(
                zcash::parse_recipient(&bad).is_err(),
                "t1 altérée acceptée : {bad}"
            );
            checked += 1;
        }
        if let Some(bad) = mutate(&mut rng, &xmr, 1, BASE58) {
            assert!(
                monero::parse_recipient(&bad).is_err(),
                "XMR altérée acceptée : {bad}"
            );
            checked += 1;
        }
        if let Some(bad) = mutate(&mut rng, &u1, 3, BECH32) {
            assert!(
                zcash_shielded::parse_shielded_address(&bad).is_err(),
                "u1 altérée acceptée : {bad}"
            );
            checked += 1;
        }
    }
    assert!(checked > 1_400, "{checked} altérations seulement");

    let alphabet: Vec<char> = format!("{BASE58}{BECH32}0OIl:/?.-_ \u{00e9}\u{1F600}")
        .chars()
        .collect();
    for _ in 0..5_000 {
        let len = rng.below(120);
        let input: String = (0..len).map(|_| *rng.pick(&alphabet)).collect();
        let _ = derivation::parse_btc_mainnet_address(&input);
        let _ = derivation::parse_btc_testnet_address(&input);
        let _ = zcash::parse_recipient(&input);
        let _ = zcash_shielded::check_recipient(&input);
        let _ = monero::parse_recipient(&input);
        let _ = crate::external_wallets::validate_address("evm_mainnet", &input);
        let _ = crate::external_wallets::validate_address("sol_mainnet", &input);
    }
}
