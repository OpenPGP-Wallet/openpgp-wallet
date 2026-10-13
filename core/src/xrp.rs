//! XRP Ledger: r... address (BIP44 m/44'/144'/0'/0/p, secp256k1 key), balance,
//! sending XRP, history.
//!
//! Transactions are serialized and signed here (the XRP Ledger's canonical binary
//! format, SHA-512Half digest with the "STX\0" prefix, low-S DER signature),
//! checked against Ripple's official libraries (ripple-binary-codec,
//! ripple-address-codec) in the tests.
//!
//! Network rules applied before the confirmation dialog:
//! - reserve: 1 XRP (+ 0.2 per owned entry) stays locked on the account, never
//!   sendable (read on 2026-10-04, `server_state`);
//! - a recipient that was never activated must receive at least the base reserve,
//!   otherwise the network refuses the payment;
//! - a recipient that REQUIRES a destination tag (exchanges, `lsfRequireDestTag`
//!   flag) receives nothing without a tag;
//! - a "deposit-authorized only" recipient (`lsfDepositAuth`) that has not
//!   authorized the sender would make the payment fail with the fee lost: refused
//!   beforehand;
//! - fee: the network's (`fee`), capped.

use crate::{btc_tx, history};
use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::sync::OnceLock;

/// XRP network: public nodes (JSON-RPC), in order.
pub struct Network {
    nodes: &'static [&'static str],
}

pub const MAINNET: Network = Network {
    nodes: &[
        "https://xrplcluster.com",
        "https://s1.ripple.com:51234",
        "https://s2.ripple.com:51234",
    ],
};
#[cfg(test)]
const TESTNET: Network = Network {
    nodes: &["https://s.altnet.rippletest.net:51234"],
};
pub const DECIMALS: u8 = 6;
/// Cap on the accepted fee (0.001 XRP; 0.00001 when the network is quiet).
const MAX_FEE_DROPS: u64 = 1_000;
/// Validity of a transaction: 20 ledgers (about 1 min) after the last validated
/// one.
const LEDGER_MARGIN: u32 = 20;
/// Node errors that say nothing about the account or the transaction.
const TRANSIENT_ERRORS: [&str; 6] = [
    "tooBusy",
    "slowDown",
    "noNetwork",
    "noCurrent",
    "noClosed",
    "amendmentBlocked",
];
/// "Destination tag required" account flag.
const LSF_REQUIRE_DEST_TAG: u64 = 0x0002_0000;
/// "Deposit-authorized only" account flag (DepositAuth).
const LSF_DEPOSIT_AUTH: u64 = 0x0100_0000;

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

fn rpc(net: &Network, method: &str, params: Value) -> Result<Value> {
    let mut last = anyhow!("nœud XRP injoignable");
    for &node in net.nodes {
        let attempt = (|| -> Result<Value> {
            let response = client()
                .post(node)
                .json(&json!({ "method": method, "params": [params] }))
                .send()
                .context("nœud XRP injoignable")?;
            let status = response.status();
            ensure!(status.is_success(), "nœud XRP : réponse {status}");
            let value: Value = response.json().context("réponse du nœud XRP illisible")?;
            let result = value["result"].clone();
            // Node overloaded or not up to date: try the next one.
            if let Some(error) = result["error"]
                .as_str()
                .filter(|e| TRANSIENT_ERRORS.contains(e))
            {
                bail!("nœud XRP : réponse {error}");
            }
            Ok(result)
        })();
        match attempt {
            Ok(result) => return Ok(result),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Amount in XRP, 6 decimals ("12.500000").
pub fn format_xrp(drops: u64) -> String {
    format!("{}.{:06}", drops / 1_000_000, drops % 1_000_000)
}

// --- Addresses ------------------------------------------------------------------

pub type AccountId = [u8; 20];

/// Account ID of a key: RIPEMD-160(SHA-256(compressed public key)).
pub fn account_id(key: &SigningKey) -> AccountId {
    use ripemd::Ripemd160;
    Ripemd160::digest(Sha256::digest(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    ))
    .into()
}

pub fn encode_address(account: &AccountId) -> String {
    let mut data = vec![0u8];
    data.extend_from_slice(account);
    let check = btc_tx::dsha256(&data);
    data.extend_from_slice(&check[..4]);
    bs58::encode(data)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

/// Classic r... address, checksum checked. "X" addresses (with an embedded tag) are
/// refused with instructions.
pub fn parse_address(text: &str) -> Result<AccountId> {
    let text = text.trim();
    ensure!(!text.starts_with('X'), "adresse XRP « X » non prise en charge : demandez l'adresse classique r… et le tag de destination");
    let data = bs58::decode(text)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .map_err(|_| anyhow!("adresse XRP invalide"))?;
    ensure!(data.len() == 25, "adresse XRP invalide");
    let (body, check) = data.split_at(21);
    ensure!(
        btc_tx::dsha256(body)[..4] == *check,
        "adresse XRP invalide (somme de contrôle)"
    );
    ensure!(body[0] == 0, "adresse XRP invalide");
    body[1..]
        .try_into()
        .map_err(|_| anyhow!("adresse XRP invalide"))
}

// --- Canonical serialization (Payment) ------------------------------------------

fn field_id(out: &mut Vec<u8>, type_code: u8, field_code: u8) {
    match (type_code < 16, field_code < 16) {
        (true, true) => out.push((type_code << 4) | field_code),
        (true, false) => out.extend_from_slice(&[type_code << 4, field_code]),
        (false, true) => out.extend_from_slice(&[field_code, type_code]),
        (false, false) => out.extend_from_slice(&[0, type_code, field_code]),
    }
}

fn vl(out: &mut Vec<u8>, bytes: &[u8]) {
    // Lengths used here: always < 193 (one byte).
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn native_amount(drops: u64) -> [u8; 8] {
    (0x4000_0000_0000_0000u64 | drops).to_be_bytes()
}

/// XRP payment to serialize.
#[derive(Clone, Debug)]
pub struct Payment {
    pub account: AccountId,
    pub destination: AccountId,
    pub amount: u64,
    pub fee: u64,
    pub sequence: u32,
    pub destination_tag: Option<u32>,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: [u8; 33],
}

impl Payment {
    /// Fields sorted by (type, field); signature included if given.
    fn serialize(&self, signature: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        field_id(&mut out, 1, 2); // TransactionType
        out.extend_from_slice(&0u16.to_be_bytes()); // Payment
        field_id(&mut out, 2, 2); // Flags
        out.extend_from_slice(&0u32.to_be_bytes());
        field_id(&mut out, 2, 4); // Sequence
        out.extend_from_slice(&self.sequence.to_be_bytes());
        if let Some(tag) = self.destination_tag {
            field_id(&mut out, 2, 14); // DestinationTag
            out.extend_from_slice(&tag.to_be_bytes());
        }
        field_id(&mut out, 2, 27); // LastLedgerSequence
        out.extend_from_slice(&self.last_ledger_sequence.to_be_bytes());
        field_id(&mut out, 6, 1); // Amount
        out.extend_from_slice(&native_amount(self.amount));
        field_id(&mut out, 6, 8); // Fee
        out.extend_from_slice(&native_amount(self.fee));
        field_id(&mut out, 7, 3); // SigningPubKey
        vl(&mut out, &self.signing_pub_key);
        if let Some(signature) = signature {
            field_id(&mut out, 7, 4); // TxnSignature
            vl(&mut out, signature);
        }
        field_id(&mut out, 8, 1); // Account
        vl(&mut out, &self.account);
        field_id(&mut out, 8, 3); // Destination
        vl(&mut out, &self.destination);
        out
    }

    /// Signed digest: SHA-512Half("STX\0" ‖ transaction without signature).
    fn signing_hash(&self) -> [u8; 32] {
        sha512_half(&[b"STX\0".as_slice(), &self.serialize(None)].concat())
    }
}

fn sha512_half(data: &[u8]) -> [u8; 32] {
    let full = Sha512::digest(data);
    full[..32].try_into().expect("32 octets")
}

pub struct Signed {
    pub blob: Vec<u8>,
    /// Identifier: SHA-512Half("TXN\0" ‖ signed transaction), in upper case.
    pub hash: String,
}

pub fn sign(payment: &Payment, key: &SigningKey) -> Result<Signed> {
    let signature: Signature = key
        .sign_prehash(&payment.signing_hash())
        .map_err(|e| anyhow!("signature XRP impossible ({e})"))?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let der = signature.to_der();
    let blob = payment.serialize(Some(der.as_bytes()));
    let hash = hex::encode_upper(sha512_half(&[b"TXN\0".as_slice(), &blob].concat()));
    Ok(Signed { blob, hash })
}

// --- Account and network --------------------------------------------------------

/// State of an account: `None` if it is not activated yet.
struct AccountState {
    balance: u64,
    sequence: u32,
    owner_count: u64,
    flags: u64,
}

fn account_state(net: &Network, address: &str) -> Result<Option<AccountState>> {
    parse_address(address)?;
    let result = rpc(
        net,
        "account_info",
        json!({ "account": address.trim(), "ledger_index": "validated" }),
    )?;
    if result["error"].as_str() == Some("actNotFound") {
        return Ok(None);
    }
    let data = &result["account_data"];
    ensure!(
        result["status"].as_str() == Some("success") && data.is_object(),
        "réponse du nœud XRP illisible"
    );
    Ok(Some(AccountState {
        balance: data["Balance"]
            .as_str()
            .and_then(|b| b.parse().ok())
            .context("solde XRP illisible")?,
        sequence: data["Sequence"]
            .as_u64()
            .and_then(|s| u32::try_from(s).ok())
            .context("séquence XRP illisible")?,
        owner_count: data["OwnerCount"].as_u64().unwrap_or(0),
        flags: data["Flags"].as_u64().unwrap_or(0),
    }))
}

struct LedgerState {
    base_reserve: u64,
    owner_reserve: u64,
    validated_ledger: u32,
}

fn ledger_state(net: &Network) -> Result<LedgerState> {
    let state = rpc(net, "server_state", json!({}))?;
    let ledger = &state["state"]["validated_ledger"];
    Ok(LedgerState {
        base_reserve: ledger["reserve_base"]
            .as_u64()
            .context("réserve XRP illisible")?,
        owner_reserve: ledger["reserve_inc"]
            .as_u64()
            .context("réserve XRP illisible")?,
        validated_ledger: ledger["seq"]
            .as_u64()
            .and_then(|s| u32::try_from(s).ok())
            .context("registre XRP illisible")?,
    })
}

/// Current fee (drops), capped.
fn current_fee(net: &Network) -> Result<u64> {
    let result = rpc(net, "fee", json!({}))?;
    let fee = result["drops"]["open_ledger_fee"]
        .as_str()
        .and_then(|f| f.parse::<u64>().ok())
        .context("frais XRP illisibles")?
        .max(10);
    ensure!(
        fee <= MAX_FEE_DROPS,
        "frais du réseau XRP anormalement élevés ({} XRP) — réessayez plus tard",
        format_xrp(fee)
    );
    Ok(fee)
}

/// Total balance (drops), reserve included; 0 for an account that is not activated.
pub fn balance(net: &Network, address: &str) -> Result<u64> {
    Ok(account_state(net, address)?.map_or(0, |a| a.balance))
}

/// Activity of a recipient address: (holds XRP, has been used before).
pub fn address_activity(net: &Network, address: &str) -> Result<(bool, bool)> {
    Ok(match account_state(net, address)? {
        Some(a) => (a.balance > 0, true),
        None => (false, false),
    })
}

/// Send prepared for the confirmation dialog.
#[derive(Clone, Copy, Debug)]
pub struct XrpPlan {
    pub amount: u64,
    pub fee: u64,
    /// XRP locked by the reserve on the source account.
    pub reserve: u64,
    /// Recipient never activated (the payment activates it).
    pub activates: bool,
}

/// Network checks (reserve, activation, required tag) and fee.
pub fn plan_xrp(
    net: &Network,
    from: &str,
    to: &str,
    amount: u64,
    destination_tag: Option<u32>,
) -> Result<XrpPlan> {
    ensure!(amount > 0, "montant nul");
    ensure!(
        parse_address(from)? != parse_address(to)?,
        "envoi vers votre propre adresse XRP"
    );
    let ledger = ledger_state(net)?;
    let sender = account_state(net, from)?
        .context("compte XRP pas encore activé : il doit d'abord recevoir au moins 1 XRP")?;
    let reserve = ledger.base_reserve + ledger.owner_reserve * sender.owner_count;
    let fee = current_fee(net)?;
    let spendable = sender.balance.saturating_sub(reserve);
    ensure!(
        amount.checked_add(fee).is_some_and(|need| need <= spendable),
        "XRP insuffisants : {} XRP envoyables ({} XRP restent bloqués par la réserve du réseau), {} XRP + {} XRP de frais demandés",
        format_xrp(spendable.saturating_sub(fee)),
        format_xrp(reserve),
        format_xrp(amount),
        format_xrp(fee)
    );
    let destination = account_state(net, to)?;
    if destination.is_none() {
        ensure!(
            amount >= ledger.base_reserve,
            "ce destinataire n'est pas encore activé : envoyez-lui au moins {} XRP (réserve du réseau)",
            format_xrp(ledger.base_reserve)
        );
    }
    if let Some(d) = &destination {
        ensure!(
            destination_tag.is_some() || d.flags & LSF_REQUIRE_DEST_TAG == 0,
            "ce destinataire exige un tag de destination (plateforme d'échange) : renseignez-le"
        );
        if d.flags & LSF_DEPOSIT_AUTH != 0 {
            let result = rpc(
                net,
                "deposit_authorized",
                json!({ "source_account": from.trim(), "destination_account": to.trim(), "ledger_index": "validated" }),
            )?;
            ensure!(
                result["deposit_authorized"].as_bool() == Some(true),
                "ce destinataire n'accepte que les paiements qu'il a autorisés, et pas le vôtre"
            );
        }
    }
    Ok(XrpPlan {
        amount,
        fee,
        reserve,
        activates: destination.is_none(),
    })
}

/// Largest amount that can be sent: balance minus reserve and fee.
pub fn max_xrp(net: &Network, from: &str) -> Result<u64> {
    let ledger = ledger_state(net)?;
    let sender = account_state(net, from)?
        .context("compte XRP pas encore activé : il doit d'abord recevoir au moins 1 XRP")?;
    let reserve = ledger.base_reserve + ledger.owner_reserve * sender.owner_count;
    sender
        .balance
        .saturating_sub(reserve)
        .checked_sub(current_fee(net)?)
        .filter(|m| *m > 0)
        .context("XRP insuffisants : tout le solde est bloqué par la réserve du réseau")
}

/// Builds, signs and broadcasts a payment; returns its ID.
pub fn send_xrp(
    net: &Network,
    key: &SigningKey,
    to: &AccountId,
    amount: u64,
    fee: u64,
    destination_tag: Option<u32>,
) -> Result<String> {
    ensure!(
        fee <= MAX_FEE_DROPS,
        "frais du réseau XRP anormalement élevés — envoi refusé"
    );
    let account = account_id(key);
    let state =
        account_state(net, &encode_address(&account))?.context("compte XRP pas encore activé")?;
    let ledger = ledger_state(net)?;
    let payment = Payment {
        account,
        destination: *to,
        amount,
        fee,
        sequence: state.sequence,
        destination_tag,
        last_ledger_sequence: ledger.validated_ledger + LEDGER_MARGIN,
        signing_pub_key: key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow!("clé XRP invalide"))?,
    };
    let signed = sign(&payment, key)?;
    submit(net, &signed)
}

/// Broadcasts (moving to the next node if one does not answer). Without a clear
/// answer from any of them, it is "maybe sent" (see `wallet_flow::maybe_sent`);
/// already received (`tefALREADY`, or a sequence consumed by THIS transaction): the
/// same transaction, already sent. Never "refused": sending again would take the
/// next sequence and pay twice.
pub fn submit(net: &Network, signed: &Signed) -> Result<String> {
    let body =
        json!({ "method": "submit", "params": [{ "tx_blob": hex::encode_upper(&signed.blob) }] });
    let mut uncertain = false;
    let mut last = anyhow!("nœud XRP injoignable");
    for &node in net.nodes {
        let result = match client().post(node).json(&body).send() {
            Ok(response) if response.status().is_success() => match response.json::<Value>() {
                Ok(value) => value["result"].clone(),
                Err(_) => {
                    uncertain = true;
                    continue;
                }
            },
            Ok(response) => {
                uncertain |= crate::wallet_flow::server_error_may_have_sent(response.status());
                last = anyhow!("nœud XRP : réponse {}", response.status());
                continue;
            }
            Err(e) => {
                uncertain |= !crate::wallet_flow::nothing_sent(&e);
                last = anyhow::Error::new(e).context("nœud XRP injoignable");
                continue;
            }
        };
        // Node overloaded or not up to date: try the next one.
        if let Some(error) = result["error"]
            .as_str()
            .filter(|e| TRANSIENT_ERRORS.contains(e))
        {
            last = anyhow!("nœud XRP : réponse {error}");
            continue;
        }
        let known = || {
            rpc(net, "tx", json!({ "transaction": signed.hash })).is_ok_and(|tx| {
                tx["hash"]
                    .as_str()
                    .is_some_and(|h| h.eq_ignore_ascii_case(&signed.hash))
            })
        };
        return submit_outcome(&result, &signed.hash, known);
    }
    Err(if uncertain {
        crate::wallet_flow::maybe_sent(&signed.hash)
    } else {
        last
    })
}

fn submit_outcome(result: &Value, hash: &str, known: impl FnOnce() -> bool) -> Result<String> {
    let engine = result["engine_result"].as_str().unwrap_or("");
    // Accepted (or queued) by the network, or already received.
    if engine == "tesSUCCESS"
        || engine == "terQUEUED"
        || engine == "tefALREADY"
        || (engine == "tefPAST_SEQ" && known())
    {
        return Ok(hash.to_string());
    }
    // ter... (except a missing source account): not applied yet, but it can be in the
    // next ledgers (before `LastLedgerSequence`), so "maybe sent", never "refused":
    // sending again would pay twice (33rd review round).
    if engine.starts_with("ter") && engine != "terNO_ACCOUNT" {
        return Err(crate::wallet_flow::maybe_sent(hash));
    }
    let signed_hash = hash;
    let message = [
        "engine_result_message",
        "error_exception",
        "error_message",
        "error",
    ]
    .iter()
    .find_map(|k| result[*k].as_str())
    .unwrap_or("erreur inconnue");
    let detail = [engine, message]
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    // tec...: the payment fails, but the transaction goes into the ledger and its fee
    // is charged (the checks before the dialog prevent this).
    if engine.starts_with("tec") {
        bail!("transaction XRP refusée : {detail} — frais du réseau prélevés (identifiant {signed_hash})");
    }
    bail!("transaction XRP refusée : {detail}")
}

// --- History --------------------------------------------------------------------

/// XRP payments of the address, newest first.
pub fn history(net: &Network, address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(address)?;
    let result = rpc(
        net,
        "account_tx",
        json!({ "account": address.trim(), "limit": limit.clamp(1, 50), "ledger_index_min": -1, "ledger_index_max": -1 }),
    )?;
    if result["error"].as_str() == Some("actNotFound") {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in result["transactions"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let tx = &item["tx"];
        if tx["TransactionType"].as_str() != Some("Payment") {
            continue;
        }
        let Some(hash) = tx["hash"]
            .as_str()
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        else {
            continue;
        };
        // Amount actually delivered, in XRP only (tokens ignored).
        let Some(delivered) = item["meta"]["delivered_amount"]
            .as_str()
            .and_then(|d| d.parse::<i128>().ok())
        else {
            continue;
        };
        let fee = tx["Fee"]
            .as_str()
            .and_then(|f| f.parse::<i128>().ok())
            .unwrap_or(0);
        let outgoing = tx["Account"].as_str() == Some(address.trim());
        // A third party's payment that only passes through the account: ignored.
        if !outgoing && tx["Destination"].as_str() != Some(address.trim()) {
            continue;
        }
        let net = if outgoing {
            -(delivered + fee)
        } else {
            delivered
        };
        let success = item["meta"]["TransactionResult"].as_str() == Some("tesSUCCESS");
        // Ledger date: seconds since January 1, 2000 (UTC).
        let timestamp_unix = tx["date"].as_i64().map(|d| d + 946_684_800);
        entries.push(history::TxEntry {
            id: hash.to_string(),
            timestamp_unix,
            status: if success {
                history::TxStatus::Confirmed
            } else {
                history::TxStatus::Failed
            },
            net_amount_minor: Some(net),
            fee_minor: 0,
            kind: if outgoing {
                history::TxKind::Sent
            } else {
                history::TxKind::Received
            },
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Already received (`tefALREADY`, or a sequence taken by THIS transaction): the
    /// same one, already sent; a sequence taken by another one: refused.
    #[test]
    fn an_already_received_payment_counts_as_sent() {
        let outcome = |engine: &str, known: bool| {
            submit_outcome(&json!({ "engine_result": engine }), "AB", || known)
        };
        assert!(outcome("tesSUCCESS", false).is_ok());
        assert!(outcome("tefALREADY", false).is_ok());
        assert!(outcome("tefPAST_SEQ", true).is_ok());
        assert!(outcome("tefPAST_SEQ", false)
            .unwrap_err()
            .to_string()
            .starts_with("transaction XRP refusée"));
        assert!(outcome("tecUNFUNDED_PAYMENT", false)
            .unwrap_err()
            .to_string()
            .contains("frais du réseau prélevés (identifiant AB)"));
        // Not applied yet (ter...): maybe sent; missing source account: refused.
        for engine in ["terPRE_SEQ", "terRETRY", "terINSUF_FEE_B"] {
            assert!(
                outcome(engine, false)
                    .unwrap_err()
                    .to_string()
                    .contains("peut-être partie"),
                "{engine}"
            );
        }
        assert!(outcome("terNO_ACCOUNT", false)
            .unwrap_err()
            .to_string()
            .starts_with("transaction XRP refusée"));
    }

    const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    /// Vectors computed with bip32 + ripple-address-codec / ripple-binary-codec
    /// (Ripple's official libraries), independent of this code.
    #[test]
    fn addresses_and_serialization_match_the_official_libraries() {
        let seed = hex::decode(SEED).unwrap();
        for (index, expected) in [
            (0, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"),
            (1, "r3AgF9mMBFtaLhKcg96weMhbbEFLZ3mx17"),
            (7, "rny6pTkxmEcJhTJoUKVK3Xri1QGjjuAXFu"),
        ] {
            let (key, account) = crate::derivation::derive_xrp_key(&seed, index).unwrap();
            assert_eq!(account, account_id(&key));
            assert_eq!(encode_address(&account), expected, "index {index}");
            assert_eq!(parse_address(expected).unwrap(), account);
        }
        assert!(
            parse_address("rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v4").is_err(),
            "somme de contrôle"
        );
        assert!(
            parse_address("XVLhHMPHU98es4dbozjVtdWzVrDjtV5fdx1mHp98tDMoQXb")
                .unwrap_err()
                .to_string()
                .contains("« X »")
        );
        let (key, account) = crate::derivation::derive_xrp_key(&seed, 0).unwrap();
        let payment = Payment {
            account,
            destination: parse_address("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap(),
            amount: 1_500_000,
            fee: 12,
            sequence: 7,
            destination_tag: Some(12345),
            last_ledger_sequence: 107_433_100,
            signing_pub_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        assert_eq!(
            hex::encode_upper([b"STX\0".as_slice(), &payment.serialize(None)].concat()),
            "53545800120000220000000024000000072E00003039201B06674C8C61400000000016E36068400000000000000C7321031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE8114AFF3C2E33458B30714CA16FFEE19952DD35C17C88314F667B0CA50CC7709A220B0561B85E53A48461FA8"
        );
        assert_eq!(
            hex::encode(payment.signing_hash()),
            "4d82007370e98e47d4b1fd2a60d740d6b1b62287cd2b0cdb6b79885bde48c0da"
        );
        let dummy = hex::decode("3045022100AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899022011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();
        let blob = payment.serialize(Some(&dummy));
        assert_eq!(
            hex::encode_upper(&blob),
            "120000220000000024000000072E00003039201B06674C8C61400000000016E36068400000000000000C7321031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE74473045022100AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899022011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEEFF8114AFF3C2E33458B30714CA16FFEE19952DD35C17C88314F667B0CA50CC7709A220B0561B85E53A48461FA8"
        );
        assert_eq!(
            hex::encode_upper(sha512_half(&[b"TXN\0".as_slice(), &blob].concat())),
            "8DFC2DEFA82649C9CBAF5205F88C4F971AFFCA477398CA1CD1C2601270BBECF7"
        );
    }

    #[test]
    fn signatures_are_low_s_and_verify() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let seed = hex::decode(SEED).unwrap();
        let (key, account) = crate::derivation::derive_xrp_key(&seed, 0).unwrap();
        let payment = Payment {
            account,
            destination: [7; 20],
            amount: 1,
            fee: 10,
            sequence: 1,
            destination_tag: None,
            last_ledger_sequence: 1,
            signing_pub_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let signed = sign(&payment, &key).unwrap();
        // TxnSignature: field 0x74, length, DER.
        let at = signed
            .blob
            .windows(2)
            .position(|w| w[0] == 0x74 && (70..=72).contains(&w[1]))
            .unwrap();
        let der = &signed.blob[at + 2..at + 2 + signed.blob[at + 1] as usize];
        let signature = Signature::from_der(der).unwrap();
        assert!(signature.normalize_s().is_none(), "low-S");
        key.verifying_key()
            .verify_prehash(&payment.signing_hash(), &signature)
            .unwrap();
        assert_eq!(signed.hash.len(), 64);
    }

    /// Real network: reads (balance, reserve, fee, history), network rules (required
    /// tag, activation) and a payment signed from an account that was never activated,
    /// refused for the ACCOUNT (terNO_ACCOUNT) after the node's signature check.
    /// `cargo test -- --ignored real_xrp --nocapture`
    #[test]
    #[ignore]
    fn real_xrp_reads_and_signature() {
        let rich = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh";
        println!("solde {} XRP", format_xrp(balance(&MAINNET, rich).unwrap()));
        let net = ledger_state(&MAINNET).unwrap();
        println!(
            "réserve {} + {} XRP, registre {}, frais {} drops",
            format_xrp(net.base_reserve),
            format_xrp(net.owner_reserve),
            net.validated_ledger,
            current_fee(&MAINNET).unwrap()
        );
        println!(
            "{} paiements récents",
            history(&MAINNET, rich, 10).unwrap().len()
        );
        let key = SigningKey::from_slice(&[0x5a; 32]).unwrap();
        let account = account_id(&key);
        let payment = Payment {
            account,
            destination: parse_address(rich).unwrap(),
            amount: 1_000_000,
            fee: 12,
            sequence: 1,
            destination_tag: None,
            last_ledger_sequence: net.validated_ledger + LEDGER_MARGIN,
            signing_pub_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let signed = sign(&payment, &key).unwrap();
        let error = submit(&MAINNET, &signed).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("terNO_ACCOUNT"), "{error}");
        // Counter-check: the same transaction with a tampered signature is refused
        // EARLIER.
        let mut blob = signed.blob.clone();
        let at = blob
            .windows(2)
            .position(|w| w[0] == 0x74 && (70..=72).contains(&w[1]))
            .unwrap();
        blob[at + 10] ^= 1;
        let error = submit(
            &MAINNET,
            &Signed {
                blob,
                hash: signed.hash.clone(),
            },
        )
        .unwrap_err()
        .to_string();
        println!("{error}");
        assert!(
            !error.contains("terNO_ACCOUNT") && error.to_lowercase().contains("signature"),
            "{error}"
        );
        assert!(
            plan_xrp(&MAINNET, &encode_address(&account), rich, 1_000_000, None)
                .unwrap_err()
                .to_string()
                .contains("pas encore activé")
        );
        // Network rules, from a funded account (read-only).
        let funded = "rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1";
        let error = plan_xrp(&MAINNET, funded, rich, 1_000_000, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exige un tag"), "{error}");
        let plan = plan_xrp(&MAINNET, funded, rich, 1_000_000, Some(7)).unwrap();
        assert!(
            !plan.activates && plan.fee >= 10 && plan.reserve >= 1_000_000,
            "{plan:?}"
        );
        let fresh = encode_address(&account);
        let error = plan_xrp(&MAINNET, funded, &fresh, 999_999, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("au moins 1.000000 XRP"), "{error}");
        assert!(
            plan_xrp(&MAINNET, funded, &fresh, 1_000_000, None)
                .unwrap()
                .activates
        );
        assert!(max_xrp(&MAINNET, funded).unwrap() > 0);
    }

    /// Real network, testnet (Ripple's free faucet): a payment that ACTIVATES a new
    /// account, then a payment with a destination tag, signed here and validated by the
    /// network.
    /// `cargo test -- --ignored real_xrp_testnet --nocapture`
    #[test]
    #[ignore]
    fn real_xrp_testnet_end_to_end() {
        let random_key = || {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            SigningKey::from_slice(&seed).unwrap()
        };
        let alice = random_key();
        let alice_address = encode_address(&account_id(&alice));
        let funded = client()
            .post("https://faucet.altnet.rippletest.net/accounts")
            .json(&json!({ "destination": alice_address }))
            .send()
            .unwrap();
        println!("robinet : {}", funded.status());
        let wait_balance = |address: &str, expected: Option<u64>| -> u64 {
            for _ in 0..30 {
                let value = balance(&TESTNET, address).unwrap();
                if expected.map_or(value > 0, |e| value == e) {
                    return value;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            panic!("solde de {address} jamais arrivé");
        };
        wait_balance(&alice_address, None);
        let bob = random_key();
        let bob_account = account_id(&bob);
        let bob_address = encode_address(&bob_account);
        assert!(
            plan_xrp(&TESTNET, &alice_address, &bob_address, 500_000, None)
                .unwrap_err()
                .to_string()
                .contains("au moins")
        );
        let first = plan_xrp(&TESTNET, &alice_address, &bob_address, 2_000_000, None).unwrap();
        assert!(first.activates, "{first:?}");
        let activated = send_xrp(
            &TESTNET,
            &alice,
            &bob_account,
            first.amount,
            first.fee,
            None,
        )
        .unwrap();
        println!("activation : {activated}");
        assert_eq!(wait_balance(&bob_address, Some(2_000_000)), 2_000_000);
        let second =
            plan_xrp(&TESTNET, &alice_address, &bob_address, 250_000, Some(12345)).unwrap();
        assert!(!second.activates);
        let paid = send_xrp(
            &TESTNET,
            &alice,
            &bob_account,
            second.amount,
            second.fee,
            Some(12345),
        )
        .unwrap();
        println!("paiement : {paid}");
        assert_eq!(wait_balance(&bob_address, Some(2_250_000)), 2_250_000);
        let tx = rpc(&TESTNET, "tx", json!({ "transaction": paid })).unwrap();
        assert_eq!(
            (
                tx["DestinationTag"].as_u64(),
                tx["meta"]["TransactionResult"].as_str()
            ),
            (Some(12345), Some("tesSUCCESS")),
            "{tx}"
        );
        let received = history(&TESTNET, &bob_address, 10).unwrap();
        assert!(
            received
                .iter()
                .filter(|e| e.kind == history::TxKind::Received)
                .count()
                >= 2
        );
    }
}
