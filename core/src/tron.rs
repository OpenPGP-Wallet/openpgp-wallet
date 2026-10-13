//! Tron: T... address (BIP44 m/44'/195'/0'/0/p), balance, sending TRX, history.
//!
//! Reads and broadcasts through TronGrid (public node, no key, rate limited).
//! Transactions are built and signed here: `raw_data` encoded as protobuf (the
//! subset used: a TRX transfer), ID = SHA-256 of `raw_data`, recoverable secp256k1
//! signature (r ‖ s ‖ v). A real-network test compares the encoding with what a
//! java-tron node produces for the same fields.
//!
//! Fees: a transfer consumes bandwidth (free up to a daily quota, burned otherwise
//! at `getTransactionFee` sun per byte); for an account that does not exist yet,
//! activation (1 TRX) and its bandwidth (0.1 TRX) are added. The maximum is shown,
//! then never exceeded.
//!
//! TRC-20 tokens (USDT): balance read with a read-only contract call; a transfer is
//! a `transfer(address,uint256)` call encoded here, whose energy is estimated by
//! simulating the call from the user's account. Fee in TRX: the energy not covered
//! by staked energy (`getEnergyFee` sun per unit, with a margin), plus bandwidth;
//! `fee_limit` caps what the network can burn.

use crate::{btc_tx, evm_sign, history};
use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Public nodes of the `/wallet` API, in order: PublicNode, then TronGrid (without
/// a key: 3 requests per second, suspended for 5 s beyond that, read on
/// 2026-10-04). The history (`/v1`) only exists at TronGrid.
const NODES: [&str; 2] = ["https://tron-rpc.publicnode.com", "https://api.trongrid.io"];
const TRONGRID: &str = "https://api.trongrid.io";
pub const DECIMALS: u8 = 6;
const ADDRESS_PREFIX: u8 = 0x41;
/// Activating a non-existent account with a transfer: 1 TRX
/// (`getCreateNewAccountFeeInSystemContract`) + 0.1 TRX of bandwidth
/// (`getCreateAccountFee`), read on 2026-10-04.
const NEW_ACCOUNT_FEE: u64 = 1_100_000;
/// Bytes counted on top of the signed transaction (result, java-tron).
const RESULT_BYTES: u64 = 64;
/// Validity of a built transaction (the node refuses beyond 24 h).
const EXPIRATION_MS: i64 = 10 * 60 * 1000;
/// Cap on a token transfer's `fee_limit`: beyond it, refused (a USDT transfer costs
/// about 65,000 to 130,000 energy units, i.e. 6.5 to 13 TRX at the price read on
/// 2026-10-04).
const MAX_TOKEN_FEE_LIMIT: u64 = 100_000_000;

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

fn post(path: &str, body: Value) -> Result<Value> {
    let mut last = anyhow!("nœud Tron injoignable");
    for node in NODES {
        let attempt = (|| -> Result<Value> {
            let response = client().post(format!("{node}{path}")).json(&body).send().context("nœud Tron injoignable")?;
            let status = response.status();
            ensure!(status.is_success(), "nœud Tron : réponse {status}");
            let value: Value = response.json().context("réponse du nœud Tron illisible")?;
            // Refusal from the node itself (rate exceeded...): next node.
            ensure!(value.get("Error").is_none(), "nœud Tron : {}", value["Error"].as_str().unwrap_or("erreur").chars().take(120).collect::<String>());
            Ok(value)
        })();
        match attempt {
            Ok(value) => return Ok(value),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Amount in TRX, 6 decimals ("12.500000").
pub fn format_trx(sun: u64) -> String {
    format!("{}.{:06}", sun / 1_000_000, sun % 1_000_000)
}

// --- Addresses ------------------------------------------------------------------

pub type Address = [u8; 21];

/// T... address of a key: 0x41 ‖ the last 20 bytes of the Keccak-256 of the
/// uncompressed public key (without the 0x04 prefix).
pub fn address_of(key: &SigningKey) -> Address {
    use sha3::Keccak256;
    let public = key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&public.as_bytes()[1..]);
    let mut out = [0u8; 21];
    out[0] = ADDRESS_PREFIX;
    out[1..].copy_from_slice(&hash[12..]);
    out
}

pub fn encode_address(address: &Address) -> String {
    let mut data = address.to_vec();
    let check = btc_tx::dsha256(&data);
    data.extend_from_slice(&check[..4]);
    bs58::encode(data).into_string()
}

/// Tron mainnet address (T...), checksum checked.
pub fn parse_address(text: &str) -> Result<Address> {
    let data = bs58::decode(text.trim()).into_vec().map_err(|_| anyhow!("adresse Tron invalide"))?;
    ensure!(data.len() == 25, "adresse Tron invalide");
    let (body, check) = data.split_at(21);
    ensure!(btc_tx::dsha256(body)[..4] == *check, "adresse Tron invalide (somme de contrôle)");
    ensure!(body[0] == ADDRESS_PREFIX, "adresse Tron invalide (autre réseau)");
    body.try_into().map_err(|_| anyhow!("adresse Tron invalide"))
}

// --- Protobuf encoding (subset) -------------------------------------------------

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    varint(out, field << 3);
    varint(out, value);
}

fn field_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    varint(out, (field << 3) | 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Reference to the recent block that anchors the transaction (replay protection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub ref_block_bytes: [u8; 2],
    pub ref_block_hash: [u8; 8],
    pub timestamp: i64,
}

/// `raw_data` of a TRX transfer.
pub fn transfer_raw(owner: &Address, to: &Address, amount: u64, block: &BlockRef, expiration: i64, timestamp: i64) -> Vec<u8> {
    let mut transfer = Vec::new();
    field_bytes(&mut transfer, 1, owner);
    field_bytes(&mut transfer, 2, to);
    field_varint(&mut transfer, 3, amount);
    let mut any = Vec::new();
    field_bytes(&mut any, 1, b"type.googleapis.com/protocol.TransferContract");
    field_bytes(&mut any, 2, &transfer);
    let mut contract = Vec::new();
    field_varint(&mut contract, 1, 1); // TransferContract
    field_bytes(&mut contract, 2, &any);
    let mut raw = Vec::new();
    field_bytes(&mut raw, 1, &block.ref_block_bytes);
    field_bytes(&mut raw, 4, &block.ref_block_hash);
    field_varint(&mut raw, 8, expiration as u64);
    field_bytes(&mut raw, 11, &contract);
    field_varint(&mut raw, 14, timestamp as u64);
    raw
}

/// Call data of `transfer(address,uint256)` (Solidity ABI).
fn transfer_call_data(to: &Address, amount: u128) -> Vec<u8> {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&to[1..]);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

/// `raw_data` of a contract call (TriggerSmartContract) without attached TRX.
pub fn trigger_raw(owner: &Address, contract: &Address, data: &[u8], fee_limit: u64, block: &BlockRef, expiration: i64, timestamp: i64) -> Vec<u8> {
    let mut trigger = Vec::new();
    field_bytes(&mut trigger, 1, owner);
    field_bytes(&mut trigger, 2, contract);
    field_bytes(&mut trigger, 4, data);
    let mut any = Vec::new();
    field_bytes(&mut any, 1, b"type.googleapis.com/protocol.TriggerSmartContract");
    field_bytes(&mut any, 2, &trigger);
    let mut contract_msg = Vec::new();
    field_varint(&mut contract_msg, 1, 31); // TriggerSmartContract
    field_bytes(&mut contract_msg, 2, &any);
    let mut raw = Vec::new();
    field_bytes(&mut raw, 1, &block.ref_block_bytes);
    field_bytes(&mut raw, 4, &block.ref_block_hash);
    field_varint(&mut raw, 8, expiration as u64);
    field_bytes(&mut raw, 11, &contract_msg);
    field_varint(&mut raw, 14, timestamp as u64);
    field_varint(&mut raw, 18, fee_limit);
    raw
}

pub struct Signed {
    pub txid: String,
    /// Serialized transaction (`raw_data` and signature), for `broadcasthex`.
    pub bytes: Vec<u8>,
}

pub fn sign(raw: &[u8], key: &SigningKey) -> Result<Signed> {
    let txid: [u8; 32] = Sha256::digest(raw).into();
    let signature = evm_sign::sign_digest(key, &txid)?;
    let mut bytes = Vec::new();
    field_bytes(&mut bytes, 1, raw);
    field_bytes(&mut bytes, 2, &signature);
    Ok(Signed { txid: hex::encode(txid), bytes })
}

// --- Node -----------------------------------------------------------------------

fn latest_block() -> Result<BlockRef> {
    let block = post("/wallet/getnowblock", json!({}))?;
    let number = block["block_header"]["raw_data"]["number"].as_u64().context("bloc Tron illisible")?;
    let timestamp = block["block_header"]["raw_data"]["timestamp"].as_i64().context("bloc Tron illisible")?;
    let id = hex::decode(block["blockID"].as_str().context("bloc Tron illisible")?).context("bloc Tron illisible")?;
    ensure!(id.len() == 32, "bloc Tron illisible");
    let number = number.to_be_bytes();
    Ok(BlockRef { ref_block_bytes: [number[6], number[7]], ref_block_hash: id[8..16].try_into().map_err(|_| anyhow!("bloc Tron illisible"))?, timestamp })
}

fn account(address: &str) -> Result<Value> {
    post("/wallet/getaccount", json!({ "address": address, "visible": true }))
}

/// Balance (sun); 0 for an account never activated.
pub fn balance(address: &str) -> Result<u64> {
    parse_address(address)?;
    Ok(account(address)?["balance"].as_u64().unwrap_or(0))
}

/// Does the account exist (already activated by a first transfer)?
pub fn account_exists(address: &str) -> Result<bool> {
    parse_address(address)?;
    Ok(account(address)?.get("address").is_some())
}

/// Activity of a recipient address: (holds TRX, has been used before).
pub fn address_activity(address: &str) -> Result<(bool, bool)> {
    parse_address(address)?;
    let value = account(address)?;
    Ok((value["balance"].as_u64().unwrap_or(0) > 0, value.get("address").is_some()))
}

/// Bandwidth still available today (free + staked).
fn available_bandwidth(address: &str) -> Result<u64> {
    let net = post("/wallet/getaccountnet", json!({ "address": address, "visible": true }))?;
    let get = |k: &str| net[k].as_u64().unwrap_or(0);
    Ok(get("freeNetLimit").saturating_sub(get("freeNetUsed")) + get("NetLimit").saturating_sub(get("NetUsed")))
}

/// Chain parameter (fee per byte, per energy unit...).
fn chain_parameter(key: &str) -> Result<u64> {
    let params = post("/wallet/getchainparameters", json!({}))?;
    params["chainParameter"]
        .as_array()
        .and_then(|list| list.iter().find(|p| p["key"].as_str() == Some(key)))
        .and_then(|p| p["value"].as_u64())
        .with_context(|| format!("paramètre Tron {key} introuvable"))
}

/// Prepared send: amount and maximum fee (sun).
#[derive(Clone, Copy, Debug)]
pub struct TrxPlan {
    pub amount: u64,
    pub fee_max: u64,
    pub new_account: bool,
}

/// Counted size (bytes) of a signed transfer.
fn transfer_size() -> u64 {
    let block = BlockRef { ref_block_bytes: [0; 2], ref_block_hash: [0; 8], timestamp: 0 };
    let raw = transfer_raw(&[ADDRESS_PREFIX; 21], &[ADDRESS_PREFIX; 21], u64::MAX >> 1, &block, i64::MAX >> 1, i64::MAX >> 1);
    // raw_data + signature (65) + protobuf envelope, plus the result.
    raw.len() as u64 + 65 + 6 + RESULT_BYTES
}

/// Maximum fee of a transfer from `from` to `to`.
pub fn plan_trx(from: &str, to: &str, amount: u64) -> Result<TrxPlan> {
    ensure!(amount > 0, "montant nul");
    ensure!(parse_address(from)? != parse_address(to)?, "envoi vers votre propre adresse Tron");
    let new_account = !account_exists(to)?;
    let bytes = transfer_size();
    let bandwidth_fee = if available_bandwidth(from)? >= bytes { 0 } else { bytes * chain_parameter("getTransactionFee")? };
    let fee_max = bandwidth_fee + if new_account { NEW_ACCOUNT_FEE } else { 0 };
    let balance = balance(from)?;
    ensure!(
        amount.checked_add(fee_max).is_some_and(|need| need <= balance),
        "TRX insuffisants : {} TRX disponibles, {} TRX + {} TRX de frais requis",
        format_trx(balance),
        format_trx(amount),
        format_trx(fee_max)
    );
    Ok(TrxPlan { amount, fee_max, new_account })
}

/// Largest amount that can be sent (balance minus the maximum fee).
pub fn max_trx(from: &str, to: Option<&str>) -> Result<u64> {
    let new_account = match to {
        Some(to) => !account_exists(to)?,
        None => false,
    };
    let bytes = transfer_size();
    let bandwidth_fee = if available_bandwidth(from)? >= bytes { 0 } else { bytes * chain_parameter("getTransactionFee")? };
    let fee = bandwidth_fee + if new_account { NEW_ACCOUNT_FEE } else { 0 };
    balance(from)?.checked_sub(fee).filter(|max| *max > 0).context("TRX insuffisants pour couvrir les frais du réseau")
}

// --- TRC-20 tokens --------------------------------------------------------------

/// Read-only contract call, simulated by the node from `owner`.
fn constant_call(owner: &str, contract: &str, selector: &str, parameter: &[u8]) -> Result<Value> {
    let reply = post(
        "/wallet/triggerconstantcontract",
        json!({ "owner_address": owner, "contract_address": contract, "function_selector": selector, "parameter": hex::encode(parameter), "visible": true }),
    )?;
    ensure!(reply["result"]["result"].as_bool() == Some(true), "appel du contrat Tron refusé par le nœud");
    Ok(reply)
}

fn word_u128(hex_word: &str) -> Result<u128> {
    let bytes = hex::decode(hex_word).context("réponse du contrat Tron illisible")?;
    ensure!(bytes.len() == 32 && bytes[..16].iter().all(|b| *b == 0), "réponse du contrat Tron illisible");
    Ok(u128::from_be_bytes(bytes[16..].try_into().map_err(|_| anyhow!("réponse du contrat Tron illisible"))?))
}

/// Decimals of a TRC-20 contract (registry check).
pub fn trc20_decimals(contract: &str) -> Result<u8> {
    let reply = constant_call(contract, contract, "decimals()", &[])?;
    u8::try_from(word_u128(reply["constant_result"][0].as_str().context("réponse du contrat Tron illisible")?)?).context("décimales invalides")
}

/// Balance of a TRC-20 token (token units).
pub fn trc20_balance(owner: &str, contract: &str) -> Result<u128> {
    let address = parse_address(owner)?;
    parse_address(contract)?;
    let mut parameter = vec![0u8; 12];
    parameter.extend_from_slice(&address[1..]);
    let reply = constant_call(owner, contract, "balanceOf(address)", &parameter)?;
    word_u128(reply["constant_result"][0].as_str().context("réponse du contrat Tron illisible")?)
}

/// Prepared token transfer: the maximum fee shown (sun) and the cap on burnable
/// energy signed into the transaction.
#[derive(Clone, Copy, Debug)]
pub struct Trc20Plan {
    pub amount: u128,
    pub fee_limit: u64,
    pub fee_max: u64,
}

/// Energy still available (staked) on the account.
fn available_energy(address: &str) -> Result<u64> {
    let resource = post("/wallet/getaccountresource", json!({ "address": address, "visible": true }))?;
    Ok(resource["EnergyLimit"].as_u64().unwrap_or(0).saturating_sub(resource["EnergyUsed"].as_u64().unwrap_or(0)))
}

/// Counted size (bytes) of a signed token transfer.
fn trigger_size() -> u64 {
    let block = BlockRef { ref_block_bytes: [0; 2], ref_block_hash: [0; 8], timestamp: 0 };
    let data = transfer_call_data(&[ADDRESS_PREFIX; 21], u128::MAX);
    let raw = trigger_raw(&[ADDRESS_PREFIX; 21], &[ADDRESS_PREFIX; 21], &data, u64::MAX >> 1, &block, i64::MAX >> 1, i64::MAX >> 1);
    raw.len() as u64 + 65 + 6 + RESULT_BYTES
}

/// `Transfer(address,address,uint256)` event (topic 0, Keccak-256).
const TRANSFER_TOPIC: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// The simulated transfer emits exactly ONE `Transfer` event: from `owner` to `to`,
/// for the requested amount. (Tether's USDT does not return a boolean: the event is
/// the proof of the effect.)
fn simulated_transfer_matches(logs: &Value, owner: &Address, to: &Address, amount: u128) -> bool {
    let word = |address: &Address| format!("{}{}", "0".repeat(24), hex::encode(&address[1..]));
    let transfers: Vec<&Value> = logs.as_array().map(|l| l.iter().filter(|log| log["topics"][0].as_str() == Some(TRANSFER_TOPIC)).collect()).unwrap_or_default();
    let [log] = transfers.as_slice() else { return false };
    log["topics"][1].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&word(owner)))
        && log["topics"][2].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&word(to)))
        && log["data"].as_str().is_some_and(|d| word_u128(d).is_ok_and(|v| v == amount))
}

/// Fee for transferring `amount` units of token `contract` from `owner` to `to`:
/// simulated transfer (it must emit exactly this transfer, so the token balance is
/// sufficient), energy with a 20% margin, staked energy deducted; enough TRX to pay
/// for it.
pub fn plan_trc20(owner: &str, contract: &str, to: &str, amount: u128) -> Result<Trc20Plan> {
    ensure!(amount > 0, "montant nul");
    let recipient = parse_address(to)?;
    let sender = parse_address(owner)?;
    ensure!(sender != recipient, "envoi vers votre propre adresse Tron");
    let simulated = constant_call(owner, contract, "transfer(address,uint256)", &transfer_call_data(&recipient, amount)[4..])
        .map_err(|_| anyhow!("transfert de jeton Tron refusé en simulation (solde de jeton insuffisant ?)"))?;
    ensure!(
        simulated_transfer_matches(&simulated["logs"], &sender, &recipient, amount),
        "transfert de jeton Tron refusé en simulation (solde de jeton insuffisant ?)"
    );
    let energy = simulated["energy_used"].as_u64().filter(|e| *e > 0).context("énergie du transfert Tron inconnue")?;
    let energy_fee = chain_parameter("getEnergyFee")?;
    let with_margin = energy.saturating_mul(12).div_ceil(10);
    let fee_limit = with_margin.saturating_mul(energy_fee);
    ensure!(fee_limit <= MAX_TOKEN_FEE_LIMIT, "frais du transfert Tron anormalement élevés ({} TRX) — envoi refusé", format_trx(fee_limit));
    let burned_energy = with_margin.saturating_sub(available_energy(owner)?).saturating_mul(energy_fee);
    let bytes = trigger_size();
    let bandwidth_fee = if available_bandwidth(owner)? >= bytes { 0 } else { bytes * chain_parameter("getTransactionFee")? };
    let fee_max = burned_energy + bandwidth_fee;
    let trx = balance(owner)?;
    ensure!(
        fee_max <= trx,
        "TRX insuffisants pour les frais du transfert : {} TRX disponibles, jusqu'à {} TRX nécessaires",
        format_trx(trx),
        format_trx(fee_max)
    );
    Ok(Trc20Plan { amount, fee_limit, fee_max })
}

/// Builds, signs and broadcasts a token transfer; returns its ID.
pub fn send_trc20(key: &SigningKey, contract: &Address, to: &Address, amount: u128, fee_limit: u64) -> Result<String> {
    ensure!(fee_limit <= MAX_TOKEN_FEE_LIMIT, "frais du transfert Tron anormalement élevés — envoi refusé");
    let block = latest_block()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(block.timestamp);
    let raw = trigger_raw(&address_of(key), contract, &transfer_call_data(to, amount), fee_limit, &block, block.timestamp + EXPIRATION_MS, now);
    broadcast(&sign(&raw, key)?)
}

/// Transfers of a TRC-20 token for the address, newest first.
pub fn trc20_history(address: &str, contract: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(address)?;
    parse_address(contract)?;
    let url = format!("{TRONGRID}/v1/accounts/{}/transactions/trc20?limit={}&contract_address={}", address.trim(), limit.clamp(1, 50), contract.trim());
    let reply: Value = client().get(url).send().context("nœud Tron injoignable")?.json().context("réponse du nœud Tron illisible")?;
    let mut entries = Vec::new();
    for tx in reply["data"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let (Some(id), Some(value)) = (tx["transaction_id"].as_str(), tx["value"].as_str().and_then(|v| v.parse::<i128>().ok())) else { continue };
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let outgoing = tx["from"].as_str() == Some(address.trim());
        let incoming = tx["to"].as_str() == Some(address.trim());
        let net = match (outgoing, incoming) {
            (true, false) => -value,
            (false, true) => value,
            _ => 0,
        };
        entries.push(history::TxEntry {
            id: id.to_string(),
            timestamp_unix: tx["block_timestamp"].as_i64().map(|ms| ms / 1000),
            status: history::TxStatus::Confirmed,
            net_amount_minor: Some(net),
            fee_minor: 0,
            kind: match net {
                n if n > 0 => history::TxKind::Received,
                n if n < 0 => history::TxKind::Sent,
                _ => history::TxKind::Other,
            },
        });
    }
    Ok(entries)
}

/// Builds, signs and broadcasts a transfer; returns its ID.
pub fn send_trx(key: &SigningKey, to: &Address, amount: u64) -> Result<String> {
    let block = latest_block()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(block.timestamp);
    let raw = transfer_raw(&address_of(key), to, amount, &block, block.timestamp + EXPIRATION_MS, now);
    let signed = sign(&raw, key)?;
    broadcast(&signed)
}

/// Broadcasts (moving to the next node if one does not answer). Without a clear
/// answer from any of them, it is "maybe sent" (see `wallet_flow::maybe_sent`);
/// already received (`DUP_TRANSACTION_ERROR`, by a previous node that never
/// answered): the same transaction, already sent. Never "refused".
pub fn broadcast(signed: &Signed) -> Result<String> {
    let body = json!({ "transaction": hex::encode(&signed.bytes) });
    let mut uncertain = false;
    let mut last = anyhow!("nœud Tron injoignable");
    for node in NODES {
        let reply: Value = match client().post(format!("{node}/wallet/broadcasthex")).json(&body).send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(value) => value,
                Err(_) => {
                    uncertain = true;
                    continue;
                }
            },
            Ok(response) => {
                uncertain |= crate::wallet_flow::server_error_may_have_sent(response.status());
                last = anyhow!("nœud Tron : réponse {}", response.status());
                continue;
            }
            Err(e) => {
                uncertain |= !crate::wallet_flow::nothing_sent(&e);
                last = anyhow::Error::new(e).context("nœud Tron injoignable");
                continue;
            }
        };
        // Refusal from the node itself (rate exceeded...): next node.
        if reply.get("Error").is_some() {
            last = anyhow!("nœud Tron : {}", reply["Error"].as_str().unwrap_or("erreur").chars().take(120).collect::<String>());
            continue;
        }
        return broadcast_outcome(&reply, &signed.txid);
    }
    Err(if uncertain { crate::wallet_flow::maybe_sent(&signed.txid) } else { last })
}

fn broadcast_outcome(reply: &Value, txid: &str) -> Result<String> {
    if reply["result"].as_bool() == Some(true) {
        return Ok(txid.to_string());
    }
    let code = reply["code"].as_str().unwrap_or("ERREUR");
    if code == "DUP_TRANSACTION_ERROR" {
        return Ok(txid.to_string());
    }
    // Message in hex (TronGrid) or in plain text (PublicNode).
    let message = reply["message"].as_str().map(|m| hex::decode(m).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|_| m.to_string())).unwrap_or_default();
    let message: String = message.chars().take(200).collect();
    bail!("transaction Tron refusée : {code} {message}")
}

// --- History --------------------------------------------------------------------

fn hex_address(text: &str) -> Option<String> {
    let bytes = hex::decode(text).ok()?;
    let address: Address = bytes.try_into().ok()?;
    Some(encode_address(&address))
}

/// TRX transfers of the address, newest first.
pub fn history(address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(address)?;
    let url = format!("{TRONGRID}/v1/accounts/{}/transactions?limit={}", address.trim(), limit.clamp(1, 50));
    let reply: Value = client().get(url).send().context("nœud Tron injoignable")?.json().context("réponse du nœud Tron illisible")?;
    let mut entries = Vec::new();
    for tx in reply["data"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let contract = &tx["raw_data"]["contract"][0];
        if contract["type"].as_str() != Some("TransferContract") {
            continue;
        }
        let value = &contract["parameter"]["value"];
        let (Some(id), Some(amount)) = (tx["txID"].as_str(), value["amount"].as_u64()) else { continue };
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let from = value["owner_address"].as_str().and_then(hex_address);
        let to = value["to_address"].as_str().and_then(hex_address);
        let fee = tx["ret"][0]["fee"].as_u64().unwrap_or(0);
        let outgoing = from.as_deref() == Some(address.trim());
        let incoming = to.as_deref() == Some(address.trim());
        let net: i128 = match (outgoing, incoming) {
            (true, false) => -(i128::from(amount) + i128::from(fee)),
            (false, true) => i128::from(amount),
            _ => -i128::from(fee),
        };
        let failed = tx["ret"][0]["contractRet"].as_str().is_some_and(|r| r != "SUCCESS");
        entries.push(history::TxEntry {
            id: id.to_string(),
            timestamp_unix: tx["block_timestamp"].as_i64().map(|ms| ms / 1000),
            status: if failed { history::TxStatus::Failed } else { history::TxStatus::Confirmed },
            net_amount_minor: Some(net),
            fee_minor: 0,
            kind: if net > 0 { history::TxKind::Received } else { history::TxKind::Sent },
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Already received by a previous node: the same one, already sent; a clear
    /// refusal: refused.
    #[test]
    fn a_duplicate_broadcast_counts_as_sent() {
        assert_eq!(broadcast_outcome(&json!({ "result": true }), "ab").unwrap(), "ab");
        assert_eq!(broadcast_outcome(&json!({ "result": false, "code": "DUP_TRANSACTION_ERROR" }), "ab").unwrap(), "ab");
        assert!(broadcast_outcome(&json!({ "result": false, "code": "SIGERROR", "message": "6261642073696700" }), "ab").unwrap_err().to_string().starts_with("transaction Tron refusée : SIGERROR"));
    }

    #[test]
    fn addresses_match_an_independent_implementation() {
        // BIP39 seed "abandon ... about", m/44'/195'/0'/0/i, computed with bip32 + js-sha3
        // + bs58check (independent of this code).
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        for (index, expected) in [(0, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"), (1, "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK"), (7, "TFj86XAQYBPvwUknt9yxmbc4k3zwUC7iVW")] {
            let (key, address) = crate::derivation::derive_tron_key(&seed, index).unwrap();
            assert_eq!(address, address_of(&key));
            assert_eq!(encode_address(&address), expected, "index {index}");
            assert_eq!(parse_address(expected).unwrap(), address);
        }
        assert!(parse_address("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdJ").is_err(), "somme de contrôle");
        assert!(parse_address("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L").is_err(), "autre réseau");
        assert_eq!(hex_address("41c8599111f29c1e1e061265b4af93ea1f274ad78a").as_deref(), Some("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"));
    }

    #[test]
    fn signatures_recover_the_signing_address() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let block = BlockRef { ref_block_bytes: [0x12, 0x34], ref_block_hash: [7; 8], timestamp: 1_791_000_000_000 };
        let raw = transfer_raw(&address_of(&key), &[ADDRESS_PREFIX; 21], 1_000_000, &block, block.timestamp + EXPIRATION_MS, block.timestamp);
        let signed = sign(&raw, &key).unwrap();
        let digest: [u8; 32] = Sha256::digest(&raw).into();
        assert_eq!(signed.txid, hex::encode(digest));
        // Envelope: field 1 = raw_data, field 2 = 65-byte signature.
        let signature = &signed.bytes[signed.bytes.len() - 65..];
        let recovered = VerifyingKey::recover_from_prehash(&digest, &Signature::from_slice(&signature[..64]).unwrap(), RecoveryId::from_byte(signature[64] - 27).unwrap()).unwrap();
        assert_eq!(recovered, *key.verifying_key());
        assert!(transfer_size() > 200 && transfer_size() < 400, "{}", transfer_size());
    }

    #[test]
    fn token_transfers_are_encoded_like_the_abi() {
        let to = parse_address("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH").unwrap();
        let data = transfer_call_data(&to, 1_500_000);
        assert_eq!(hex::encode(&data), "a9059cbb000000000000000000000000c8599111f29c1e1e061265b4af93ea1f274ad78a000000000000000000000000000000000000000000000000000000000016e360");
        assert_eq!(word_u128("000000000000000000000000000000000000000000000000000000000016e360").unwrap(), 1_500_000);
        assert!(word_u128("ff00000000000000000000000000000000000000000000000000000000000001").is_err(), "au-delà de 128 bits");
        assert!(trigger_size() > 300 && trigger_size() < 500, "{}", trigger_size());
        // Real simulated event (2026-10-04): exactly this transfer.
        let owner = parse_address("TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G").unwrap();
        let logs: Value = serde_json::from_str(r#"[{"topics":["ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","00000000000000000000000089cbcb2372e1c2fbc00f24895a406a0c722c89f3","000000000000000000000000c8599111f29c1e1e061265b4af93ea1f274ad78a"],"data":"00000000000000000000000000000000000000000000000000000000000f4240"}]"#).unwrap();
        assert!(simulated_transfer_matches(&logs, &owner, &to, 1_000_000));
        assert!(!simulated_transfer_matches(&logs, &owner, &to, 999_999), "autre montant");
        assert!(!simulated_transfer_matches(&logs, &to, &owner, 1_000_000), "sens inversé");
        assert!(!simulated_transfer_matches(&json!([]), &owner, &to, 1_000_000), "aucun transfert");
        let twice = json!([logs[0], logs[0]]);
        assert!(!simulated_transfer_matches(&twice, &owner, &to, 1_000_000), "deux transferts");
    }

    /// Real network: USDT TRC-20, with the call encoding identical to the node's, the
    /// balance read through the contract, and a transfer's energy simulated from a
    /// funded address.
    /// `cargo test -- --ignored real_trc20 --nocapture`
    #[test]
    #[ignore]
    fn real_trc20_encoding_balance_and_fee() {
        let usdt = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        let owner = "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G";
        let to = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";
        let held = trc20_balance(owner, usdt).unwrap();
        println!("USDT détenus : {}", held as f64 / 1e6);
        let data = transfer_call_data(&parse_address(to).unwrap(), 1_000_000);
        let built = post(
            "/wallet/triggersmartcontract",
            json!({ "owner_address": owner, "contract_address": usdt, "function_selector": "transfer(address,uint256)", "parameter": hex::encode(&data[4..]), "fee_limit": 30_000_000, "visible": true }),
        )
        .unwrap();
        let tx = &built["transaction"];
        let raw = &tx["raw_data"];
        let bytes = |k: &str| hex::decode(raw[k].as_str().unwrap()).unwrap();
        let block = BlockRef { ref_block_bytes: bytes("ref_block_bytes").try_into().unwrap(), ref_block_hash: bytes("ref_block_hash").try_into().unwrap(), timestamp: 0 };
        let ours = trigger_raw(&parse_address(owner).unwrap(), &parse_address(usdt).unwrap(), &data, 30_000_000, &block, raw["expiration"].as_i64().unwrap(), raw["timestamp"].as_i64().unwrap());
        assert_eq!(hex::encode(&ours), tx["raw_data_hex"].as_str().unwrap(), "encodage identique au nœud");
        let plan = plan_trc20(owner, usdt, to, 1_000_000).unwrap();
        println!("frais max {} TRX, fee_limit {} TRX", format_trx(plan.fee_max), format_trx(plan.fee_limit));
        let entries = trc20_history(owner, usdt, 5).unwrap();
        println!("{} transferts USDT récents", entries.len());
        // Account without USDT: refused in simulation, before any dialog.
        assert!(plan_trc20("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", usdt, owner, 1_000_000_000_000).is_err());
    }

    /// Real network: the local `raw_data` encoding is identical, byte for byte, to a
    /// java-tron node's for the same fields; a transaction signed from an empty account
    /// is refused for the CONTRACT (account does not exist), not for the signature;
    /// balance and history reads.
    /// `cargo test -- --ignored real_tron --nocapture`
    #[test]
    #[ignore]
    fn real_tron_encoding_signature_and_reads() {
        let owner = "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G";
        let to = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";
        let built = post("/wallet/createtransaction", json!({ "owner_address": owner, "to_address": to, "amount": 1_234_567, "visible": true })).unwrap();
        let raw = &built["raw_data"];
        let bytes = |k: &str| hex::decode(raw[k].as_str().unwrap()).unwrap();
        let block = BlockRef { ref_block_bytes: bytes("ref_block_bytes").try_into().unwrap(), ref_block_hash: bytes("ref_block_hash").try_into().unwrap(), timestamp: 0 };
        let ours = transfer_raw(&parse_address(owner).unwrap(), &parse_address(to).unwrap(), 1_234_567, &block, raw["expiration"].as_i64().unwrap(), raw["timestamp"].as_i64().unwrap());
        assert_eq!(hex::encode(&ours), built["raw_data_hex"].as_str().unwrap(), "encodage identique au nœud");
        assert_eq!(hex::encode(Sha256::digest(&ours)), built["txID"].as_str().unwrap());
        // Account never activated: refused by the contract, the signature passes.
        let key = SigningKey::from_slice(&[0x5a; 32]).unwrap();
        let error = send_trx(&key, &parse_address(to).unwrap(), 1_000_000).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("CONTRACT_VALIDATE_ERROR"), "{error}");
        assert!(!error.contains("SIGERROR"));
        println!("solde {} TRX ; activé : {}", format_trx(balance(owner).unwrap()), account_exists(owner).unwrap());
        assert!(!account_exists(&encode_address(&address_of(&key))).unwrap());
        let entries = history(owner, 10).unwrap();
        println!("{} virements TRX récents", entries.len());
    }
}
