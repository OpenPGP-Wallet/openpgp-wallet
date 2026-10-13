//! Stacks (STX): SP... address (secp256k1 key m/44'/5757'/0'/0/p, as in Leather and
//! Xverse), balance, sending STX with a memo, history.
//!
//! Transactions are serialized and signed here (Stacks format: SHA-512/256 digest
//! of the "cleared" transaction, then of its pre-signer), identical byte for byte
//! to @stacks/transactions (Hiro's official library) in the tests, and checked end
//! to end on the testnet (free funds from Hiro's faucet, a real test).
//!
//! Before the confirmation dialog: available balance (excluding STX locked by
//! "stacking"), fee, and contract addresses (SP....name) rejected; the memo
//! (required by exchanges) is always shown.

use crate::{btc_tx, history};
use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha512_256};
use std::sync::OnceLock;

/// Stacks network: Hiro API, version bytes for transactions and addresses.
pub struct Network {
    pub api: &'static str,
    tx_version: u8,
    chain_id: u32,
    /// Accepted address versions: (single signature, multisignature).
    address_versions: (u8, u8),
}

pub const MAINNET: Network = Network { api: "https://api.hiro.so", tx_version: 0x00, chain_id: 0x0000_0001, address_versions: (22, 20) };
#[cfg(test)]
const TESTNET: Network = Network { api: "https://api.testnet.hiro.so", tx_version: 0x80, chain_id: 0x8000_0000, address_versions: (26, 21) };

pub const DECIMALS: u8 = 6;
/// Fee: at least 0.003 STX, at most 0.1 STX.
const MIN_FEE: u64 = 3_000;
const MAX_FEE: u64 = 100_000;
const MEMO_LEN: usize = 34;

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

fn get(net: &Network, path: &str) -> Result<Value> {
    let response = client().get(format!("{}{path}", net.api)).send().context("service Stacks injoignable")?;
    let status = response.status();
    ensure!(status.is_success(), "service Stacks : réponse {status}");
    response.json().context("réponse du service Stacks illisible")
}

fn micro(value: &Value) -> Result<u64> {
    value.as_str().and_then(|v| v.parse().ok()).or(value.as_u64()).context("montant Stacks illisible")
}

/// Amount in STX, 6 decimals ("12.500000").
pub fn format_stx(micro: u64) -> String {
    format!("{}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    Ripemd160::digest(sha2::Sha256::digest(data)).into()
}

fn sha512_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

// --- Addresses (c32check) --------------------------------------------------------

const C32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// c32 encoding: the number in base 32 (without leading zeros), then one "0" per
/// leading zero byte.
fn c32_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new(); // base 32, least significant first
    for &byte in data {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            let value = (u32::from(*d) << 8) + carry;
            *d = (value % 32) as u8;
            carry = value / 32;
        }
        while carry > 0 {
            digits.push((carry % 32) as u8);
            carry /= 32;
        }
    }
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut out: String = std::iter::repeat_n('0', zeros).collect();
    out.extend(digits.iter().rev().map(|&d| C32[d as usize] as char));
    out
}

fn c32_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new(); // least significant first
    for c in text.bytes() {
        let mut carry = C32.iter().position(|&x| x == c)? as u32;
        for b in bytes.iter_mut() {
            let value = (u32::from(*b) << 5) + carry;
            *b = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|&c| c == b'0').count();
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

pub fn encode_address(version: u8, hash160: &[u8; 20]) -> String {
    let mut body = hash160.to_vec();
    body.extend_from_slice(&btc_tx::dsha256(&[&[version][..], hash160].concat())[..4]);
    format!("S{}{}", C32[version as usize] as char, c32_encode(&body))
}

/// Standard address (SP.../SM...) of the network: (version, hash160). Contract
/// addresses (SP....name) are rejected.
pub fn parse_address(net: &Network, text: &str) -> Result<(u8, [u8; 20])> {
    let text = text.trim();
    ensure!(!text.contains('.'), "adresse de contrat Stacks : envoi refusé (adresse de portefeuille SP… attendue)");
    // c32 (Crockford) normalization: upper case, O → 0, I and L → 1.
    let normalized: String = text.to_ascii_uppercase().chars().map(|c| match c {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    }).collect();
    ensure!(normalized.len() >= 5 && normalized.starts_with('S'), "adresse Stacks invalide");
    let version = C32.iter().position(|&c| c == normalized.as_bytes()[1]).context("adresse Stacks invalide")? as u8;
    let data = c32_decode(&normalized[2..]).filter(|d| d.len() == 24).context("adresse Stacks invalide")?;
    let hash: [u8; 20] = data[..20].try_into().expect("20");
    ensure!(btc_tx::dsha256(&[&[version][..], &hash].concat())[..4] == data[20..], "adresse Stacks invalide (somme de contrôle)");
    ensure!(encode_address(version, &hash) == normalized, "adresse Stacks invalide");
    let (single, multi) = net.address_versions;
    ensure!(version == single || version == multi, "adresse Stacks d'un autre réseau — refusée");
    Ok((version, hash))
}

pub fn address_of(net: &Network, key: &SigningKey) -> String {
    encode_address(net.address_versions.0, &hash160(key.verifying_key().to_encoded_point(true).as_bytes()))
}

// --- Memo -----------------------------------------------------------------------

/// Memo (34 bytes, printable ASCII); empty = none.
pub fn parse_memo(text: Option<&str>) -> Result<String> {
    let text = text.map(str::trim).unwrap_or("");
    ensure!(text.len() <= MEMO_LEN, "mémo Stacks trop long (34 caractères au plus)");
    ensure!(text.bytes().all(|b| (0x20..=0x7e).contains(&b)), "mémo Stacks invalide (lettres, chiffres et ponctuation ASCII seulement)");
    Ok(text.to_string())
}

// --- Transaction ----------------------------------------------------------------

pub struct Transfer {
    pub signer: [u8; 20],
    pub nonce: u64,
    pub fee: u64,
    pub recipient: (u8, [u8; 20]),
    pub amount: u64,
    pub memo: String,
}

impl Transfer {
    fn serialize(&self, net: &Network, signature: &[u8; 65], nonce: u64, fee: u64) -> Vec<u8> {
        let mut out = vec![net.tx_version];
        out.extend_from_slice(&net.chain_id.to_be_bytes());
        // Standard authorization, single signature (P2PKH), compressed key.
        out.extend_from_slice(&[0x04, 0x00]);
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&fee.to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(signature);
        // Any anchor mode, post-conditions: deny, none.
        out.extend_from_slice(&[0x03, 0x02, 0, 0, 0, 0]);
        // STX transfer to a standard principal.
        out.extend_from_slice(&[0x00, 0x05, self.recipient.0]);
        out.extend_from_slice(&self.recipient.1);
        out.extend_from_slice(&self.amount.to_be_bytes());
        let mut memo = [0u8; MEMO_LEN];
        memo[..self.memo.len()].copy_from_slice(self.memo.as_bytes());
        out.extend_from_slice(&memo);
        out
    }

    /// Signed digest: SHA-512/256(ID of the cleared transaction ‖ authorization type ‖
    /// fee ‖ nonce).
    fn presign_hash(&self, net: &Network) -> [u8; 32] {
        let initial = sha512_256(&[&self.serialize(net, &[0; 65], 0, 0)]);
        sha512_256(&[&initial, &[0x04], &self.fee.to_be_bytes(), &self.nonce.to_be_bytes()])
    }
}

pub struct Signed {
    pub bytes: Vec<u8>,
    pub txid: String,
}

pub fn sign(tx: &Transfer, key: &SigningKey, net: &Network) -> Result<Signed> {
    let (signature, recovery) = key.sign_prehash_recoverable(&tx.presign_hash(net)).map_err(|e| anyhow!("signature Stacks impossible ({e})"))?;
    // Low S (required by the network): the recovery parity follows.
    let (signature, recovery) = match signature.normalize_s() {
        Some(low) => (low, k256::ecdsa::RecoveryId::from_byte(recovery.to_byte() ^ 1).context("signature Stacks impossible")?),
        None => (signature, recovery),
    };
    let mut vrs = [0u8; 65];
    vrs[0] = recovery.to_byte();
    vrs[1..].copy_from_slice(&signature.to_bytes());
    let bytes = tx.serialize(net, &vrs, tx.nonce, tx.fee);
    let txid = hex::encode(sha512_256(&[&bytes]));
    Ok(Signed { bytes, txid })
}

// --- Account and network --------------------------------------------------------

/// (available balance excluding locked STX, total balance).
fn balances(net: &Network, address: &str) -> Result<(u64, u64)> {
    let value = get(net, &format!("/extended/v1/address/{}/stx", address.trim()))?;
    let total = micro(&value["balance"])?;
    let locked = micro(&value["locked"]).unwrap_or(0);
    Ok((total.saturating_sub(locked), total))
}

pub fn balance(net: &Network, address: &str) -> Result<u64> {
    parse_address(net, address)?;
    Ok(balances(net, address)?.1)
}

/// Activity of a recipient address: (holds STX, has been used before).
pub fn address_activity(net: &Network, address: &str) -> Result<(bool, bool)> {
    parse_address(net, address)?;
    let txs = get(net, &format!("/extended/v2/addresses/{}/transactions?limit=1", address.trim()))?;
    let used = txs["total"].as_u64().unwrap_or(0) > 0;
    Ok((balances(net, address)?.1 > 0, used))
}

fn fee(net: &Network, size: usize) -> Result<u64> {
    let rate = get(net, "/v2/fees/transfer")?.as_u64().context("frais Stacks illisibles")?;
    let fee = (rate * size as u64 * 2).max(MIN_FEE);
    ensure!(fee <= MAX_FEE, "frais du réseau Stacks anormalement élevés ({} STX) — réessayez plus tard", format_stx(fee));
    Ok(fee)
}

/// Send prepared for the confirmation dialog.
#[derive(Clone, Copy, Debug)]
pub struct StxPlan {
    pub amount: u64,
    pub fee: u64,
}

/// Size of a signed transfer (fixed: the memo is padded to 34 bytes).
const TRANSFER_SIZE: usize = 180;

pub fn plan(net: &Network, from: &str, to: &str, amount: u64) -> Result<StxPlan> {
    ensure!(amount > 0, "montant nul");
    ensure!(parse_address(net, from)? != parse_address(net, to)?, "envoi vers votre propre adresse Stacks");
    let fee = fee(net, TRANSFER_SIZE)?;
    let (spendable, total) = balances(net, from)?;
    ensure!(
        amount.checked_add(fee).is_some_and(|need| need <= spendable),
        "STX insuffisants : {} STX disponibles{}, {} STX + {} STX de frais demandés",
        format_stx(spendable),
        if total > spendable { format!(" ({} STX bloqués par le stacking)", format_stx(total - spendable)) } else { String::new() },
        format_stx(amount),
        format_stx(fee)
    );
    Ok(StxPlan { amount, fee })
}

/// Largest amount that can be sent: available balance minus the fee.
pub fn max_amount(net: &Network, from: &str) -> Result<u64> {
    parse_address(net, from)?;
    let fee = fee(net, TRANSFER_SIZE)?;
    balances(net, from)?.0.checked_sub(fee).filter(|m| *m > 0).context("STX insuffisants pour couvrir les frais du réseau")
}

/// Builds, signs and broadcasts the prepared send; returns its ID.
pub fn send(net: &Network, key: &SigningKey, to: &str, plan: &StxPlan, memo: &str) -> Result<String> {
    let from = address_of(net, key);
    // Next nonce, pending transactions included.
    let nonce = get(net, &format!("/extended/v1/address/{from}/nonces"))?["possible_next_nonce"].as_u64().context("nonce Stacks illisible")?;
    let tx = Transfer { signer: hash160(key.verifying_key().to_encoded_point(true).as_bytes()), nonce, fee: plan.fee, recipient: parse_address(net, to)?, amount: plan.amount, memo: parse_memo(Some(memo))? };
    submit(net, &sign(&tx, key, net)?)
}

pub fn submit(net: &Network, signed: &Signed) -> Result<String> {
    let response = client()
        .post(format!("{}/v2/transactions", net.api))
        .header("content-type", "application/octet-stream")
        .body(signed.bytes.clone())
        .send()
        .map_err(|e| crate::wallet_flow::broadcast_failure(e, "service Stacks injoignable", &signed.txid))?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    // Gateway error: maybe sent (see `wallet_flow::maybe_sent`).
    if crate::wallet_flow::server_error_may_have_sent(status) {
        return Err(crate::wallet_flow::maybe_sent(&signed.txid));
    }
    if status.is_success() {
        let returned = text.trim().trim_matches('"').trim_start_matches("0x").to_ascii_lowercase();
        // Transaction accepted: an ID other than ours must not make it look refused, since
        // sending again would pay twice (32nd review round).
        if returned != signed.txid {
            return Err(crate::wallet_flow::maybe_sent(&signed.txid));
        }
        return Ok(signed.txid.clone());
    }
    let reason = serde_json::from_str::<Value>(&text).ok().and_then(|v| v["reason"].as_str().map(str::to_string)).unwrap_or(text);
    let reason: String = reason.chars().filter(|c| !matches!(c, '{' | '}' | '"')).take(200).collect();
    bail!("transaction Stacks refusée : {reason}")
}

// --- History --------------------------------------------------------------------

/// STX movements of the address (received − sent, fee included), newest first.
pub fn history(net: &Network, address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(net, address)?;
    let list = get(net, &format!("/extended/v2/addresses/{}/transactions?limit={}", address.trim(), limit.clamp(1, 50)))?;
    let mut entries = Vec::new();
    for item in list["results"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let tx = &item["tx"];
        let Some(id) = tx["tx_id"].as_str().map(|t| t.trim_start_matches("0x")).filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())) else { continue };
        let net_amount = i128::from(micro(&item["stx_received"]).unwrap_or(0)) - i128::from(micro(&item["stx_sent"]).unwrap_or(0));
        if net_amount == 0 {
            continue;
        }
        let status = match tx["tx_status"].as_str() {
            Some("success") => history::TxStatus::Confirmed,
            Some("pending") => history::TxStatus::Pending,
            _ => history::TxStatus::Failed,
        };
        entries.push(history::TxEntry {
            id: id.to_string(),
            timestamp_unix: tx["block_time"].as_i64(),
            status,
            net_amount_minor: Some(net_amount),
            fee_minor: 0,
            kind: if net_amount > 0 { history::TxKind::Received } else { history::TxKind::Sent },
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn key(index: u32) -> SigningKey {
        crate::derivation::derive_stacks_key(&hex::decode(SEED).unwrap(), index).unwrap()
    }

    /// Vectors from @stacks/transactions + bip32, independent of this code.
    #[test]
    fn addresses_match_the_official_library() {
        for (index, main, test) in [(0, "SPC5KHM41H6WHAST7MWWDD807YSPRQKJ69FSH54J", "STC5KHM41H6WHAST7MWWDD807YSPRQKJ68T330BQ"), (1, "SP3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMD2N3MGH", "ST3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMEXRWMFR"), (7, "SP23HR2AW1CHQY48VVN0JE2NEC5MG87NMW53N328M", "ST23HR2AW1CHQY48VVN0JE2NEC5MG87NMW7JRDAE8")] {
            assert_eq!(address_of(&MAINNET, &key(index)), main);
            assert_eq!(address_of(&TESTNET, &key(index)), test);
            assert_eq!(parse_address(&MAINNET, main).unwrap().0, 22);
            assert!(parse_address(&MAINNET, test).unwrap_err().to_string().contains("autre réseau"));
        }
        // Lower case and Crockford look-alikes accepted (c32 normalization).
        assert!(parse_address(&MAINNET, "sp3xhes5990fydv5bhbzcjrfyfd2z4x3fmd2n3mgh").is_ok());
        assert!(parse_address(&MAINNET, "SP3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMD2N3MGJ").unwrap_err().to_string().contains("somme de contrôle"));
        assert!(parse_address(&MAINNET, "SP3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMD2N3MGH.my-contract").unwrap_err().to_string().contains("contrat"));
        assert!(parse_address(&MAINNET, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_err());
        // Leading zero bytes: leading "0" in c32, exact round trip.
        assert_eq!(c32_decode(&c32_encode(&[0, 0, 1, 2, 255])).unwrap(), vec![0, 0, 1, 2, 255]);
    }

    #[test]
    fn memos_are_parsed_strictly() {
        assert_eq!(parse_memo(None).unwrap(), "");
        assert_eq!(parse_memo(Some(" 104857 ")).unwrap(), "104857");
        assert!(parse_memo(Some(&"a".repeat(35))).is_err());
        assert!(parse_memo(Some("abc\u{202e}")).is_err());
    }

    /// Transfers identical byte for byte to @stacks/transactions (with and without a
    /// memo, mainnet and testnet).
    #[test]
    fn transfers_match_the_official_library() {
        let signer = hash160(key(0).verifying_key().to_encoded_point(true).as_bytes());
        for (net, memo, nonce, recipient, expected, txid) in [
            (&MAINNET, "104857", 7, "SP3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMD2N3MGH", "000000000104001859c6840c4dc8ab3a3d39c6b5003fb36c5e72320000000000000007000000000000087000016446c0e2d4bb8e2c0ca2b22f968a1def52c36cdde42372c835b217c46820ea133c815e4dcfef1c752f032b5de16840b1a2e502049a9e9a6fabf0e0cf9875b7d3030200000000000516fb1764a9481fe6ecab8afec961fe7b45f2746fa3000000000016e36031303438353700000000000000000000000000000000000000000000000000000000", "e92daaca9ecbb391ad31b3cb9605cc500d25bfa2cb9cdbf6943664377b1bc1b1"),
            (&MAINNET, "", 0, "SP3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMD2N3MGH", "000000000104001859c6840c4dc8ab3a3d39c6b5003fb36c5e72320000000000000000000000000000087000002e4ee334ec0c7d7864a83d45a750047fc8a41182d26211de1032fca63a6011c51b57d3e25a54d1386eea2507ffcd1f264ee119f7e1c2afddbb3c7c3899e22cbe030200000000000516fb1764a9481fe6ecab8afec961fe7b45f2746fa3000000000016e36000000000000000000000000000000000000000000000000000000000000000000000", "7d297c8d55c36d53406c9bb52b10c1bf14431c5c7e358a9c27d1adc436e19ce0"),
            (&TESTNET, "hello", 3, "ST3XHES5990FYDV5BHBZCJRFYFD2Z4X3FMEXRWMFR", "808000000004001859c6840c4dc8ab3a3d39c6b5003fb36c5e723200000000000000030000000000000870000129f5f309a655b783dae417774bd055a9bdb7cbd1717ae26142cabdda2c05c6db692ea1862ea7c6d57146ee0a6ef670fdaff7b9f4456facc99675b4294d342f3803020000000000051afb1764a9481fe6ecab8afec961fe7b45f2746fa3000000000016e36068656c6c6f0000000000000000000000000000000000000000000000000000000000", "bcc61c40ab1cf230f3b3bc61eab348f8075ecc2c0f974d40aa139c146c710e43"),
        ] {
            let tx = Transfer { signer, nonce, fee: 2160, recipient: parse_address(net, recipient).unwrap(), amount: 1_500_000, memo: memo.into() };
            let signed = sign(&tx, &key(0), net).unwrap();
            assert_eq!(hex::encode(&signed.bytes), expected, "mémo « {memo} »");
            assert_eq!(signed.txid, txid);
            assert_eq!(signed.bytes.len(), TRANSFER_SIZE);
        }
    }

    /// Real network, testnet (Hiro's free faucet): a transfer signed here with a memo,
    /// accepted and executed; a tampered signature rejected. Mainnet reads.
    /// `cargo test -- --ignored real_stacks --nocapture`
    #[test]
    #[ignore]
    fn real_stacks_testnet_end_to_end() {
        let random_key = || {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            SigningKey::from_slice(&seed).unwrap()
        };
        let alice = random_key();
        let alice_address = address_of(&TESTNET, &alice);
        let funded = client().post(format!("{}/extended/v1/faucets/stx?address={alice_address}", TESTNET.api)).send().unwrap().text().unwrap();
        println!("robinet : {}", &funded[..funded.len().min(120)]);
        let wait_balance = |address: &str, at_least: u64| -> u64 {
            for _ in 0..60 {
                let (spendable, _) = balances(&TESTNET, address).unwrap();
                if spendable >= at_least {
                    return spendable;
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            panic!("solde de {address} jamais arrivé");
        };
        wait_balance(&alice_address, 2_000_000);
        let bob = random_key();
        let bob_address = address_of(&TESTNET, &bob);
        let plan = plan(&TESTNET, &alice_address, &bob_address, 1_500_000).unwrap();
        let txid = send(&TESTNET, &alice, &bob_address, &plan, "hello").unwrap();
        println!("virement : {txid} (frais {} STX)", format_stx(plan.fee));
        assert_eq!(wait_balance(&bob_address, 1_500_000), 1_500_000);
        let tx = get(&TESTNET, &format!("/extended/v1/tx/0x{txid}")).unwrap();
        assert_eq!(tx["token_transfer"]["memo"].as_str().map(|m| m.starts_with("0x68656c6c6f00")), Some(true), "{}", tx["token_transfer"]);
        assert_eq!(tx["tx_status"].as_str(), Some("success"));
        // Tampered signature: rejected.
        let mut signed = sign(&Transfer { signer: hash160(alice.verifying_key().to_encoded_point(true).as_bytes()), nonce: 1, fee: plan.fee, recipient: parse_address(&TESTNET, &bob_address).unwrap(), amount: 1, memo: String::new() }, &alice, &TESTNET).unwrap();
        signed.bytes[60] ^= 1;
        let error = submit(&TESTNET, &signed).unwrap_err().to_string();
        println!("{error}");
        assert!(error.to_lowercase().contains("signature") || error.contains("SignatureValidation"), "{error}");
        // History and mainnet.
        assert!(history(&TESTNET, &bob_address, 10).unwrap().iter().any(|e| e.net_amount_minor == Some(1_500_000)));
        println!("principal : frais {} STX", format_stx(fee(&MAINNET, TRANSFER_SIZE).unwrap()));
    }
}
