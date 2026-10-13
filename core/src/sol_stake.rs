//! Native Solana staking: your SOL delegated to a validator from a stake account
//! for which you remain the only authority (staking and withdrawal). Rewards are
//! added every epoch (about 2 days); to stop: deactivate, then withdraw at the next
//! epoch.
//!
//! Stake accounts are created at an address derived from yours
//! (`CreateAccountWithSeed`, seeds "stake:0", "stake:1"…): a single signature
//! (yours), no extra key to keep, found again without an index. Accounts created
//! elsewhere with the same key are read too (`getProgramAccounts`, withdraw
//! authority = you).
//!
//! Every operation is simulated by the node before the confirmation dialog: the
//! state of the stake account AFTER the transaction is reread and must be exactly
//! what was announced (amount, validator, authorities, no lockup).
//!
//! Formats: the official Stake program and System Program (solana-stake-interface,
//! solana-system-interface), verified by simulation on mainnet (ignored live tests
//! below).

use crate::sol_rpc::{format_lamports, AccountState, SimulationOutcome, SolRpc};
use crate::sol_spl::decode_pubkey;
use crate::sol_tx::{assemble_transaction, build_message, Instruction, SYSTEM_PROGRAM_ID};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const STAKE_PROGRAM: &str = "Stake11111111111111111111111111111111111111";
const SYSVAR_RENT: &str = "SysvarRent111111111111111111111111111111111";
const SYSVAR_CLOCK: &str = "SysvarC1ock11111111111111111111111111111111";
const SYSVAR_STAKE_HISTORY: &str = "SysvarStakeHistory1111111111111111111111111";
/// Deprecated config account, still expected by `DelegateStake` (for compatibility,
/// see `solana_stake_interface::instruction::delegate_stake`).
const STAKE_CONFIG: &str = "StakeConfig11111111111111111111111111111111";

/// Size of a stake account (`StakeStateV2`).
const STAKE_ACCOUNT_SPACE: u64 = 200;
/// Base fee for a single-signature transaction.
pub const FEE_LAMPORTS: u64 = 5_000;
const SEED_PREFIX: &str = "stake:";
/// Seeds read at once to find the next free one.
const SEED_SCAN: u32 = 32;
/// Deactivation epoch of a stake that was never deactivated.
const NO_DEACTIVATION: u64 = u64::MAX;
/// Average slot duration, used to estimate the end of the epoch.
const SLOT_MILLIS: u64 = 400;

/// Validators offered: commission of at most 5%, outside the "superminority" (the
/// largest ones, which together hold a third of the network's stake), at least
/// 20,000 SOL staked (track record), votes among the best.
const MAX_COMMISSION: u64 = 5;
const MIN_VALIDATOR_STAKE_SOL: u64 = 20_000;
const MAX_VALIDATORS: usize = 12;
const STAKEWIZ: &str = "https://api.stakewiz.com/validators";

fn key(text: &str) -> Result<[u8; 32]> {
    bs58::decode(text.trim())
        .into_vec()
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| anyhow!("adresse Solana invalide (base58 attendu)"))
}

fn b58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

/// Address of an account created with a seed: sha256(base ‖ seed ‖ owner program)
/// (`Pubkey::create_with_seed`).
pub fn derived_address(base: &[u8; 32], seed: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(base);
    hasher.update(seed.as_bytes());
    hasher.update(decode_pubkey(STAKE_PROGRAM));
    hasher.finalize().into()
}

// --- Instructions ------------------------------------------------------------------

/// System Program `CreateAccountWithSeed` (variant 3): a 200-byte account owned by
/// the Stake program, paid for by and "based" on `owner`.
fn create_with_seed(owner: &[u8; 32], stake: &[u8; 32], seed: &str, lamports: u64) -> Instruction {
    let mut data = 3u32.to_le_bytes().to_vec();
    data.extend_from_slice(owner);
    data.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    data.extend_from_slice(seed.as_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&STAKE_ACCOUNT_SPACE.to_le_bytes());
    data.extend_from_slice(&decode_pubkey(STAKE_PROGRAM));
    Instruction { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(*owner, true, true), (*stake, false, true), (*owner, true, false)], data }
}

/// `Initialize` (variant 0): stake and withdraw authorities = `owner`, no lockup
/// (timestamp 0, epoch 0, null custodian).
fn initialize(stake: &[u8; 32], owner: &[u8; 32]) -> Instruction {
    let mut data = 0u32.to_le_bytes().to_vec();
    data.extend_from_slice(owner);
    data.extend_from_slice(owner);
    data.extend_from_slice(&[0u8; 48]);
    Instruction { program_id: decode_pubkey(STAKE_PROGRAM), accounts: vec![(*stake, false, true), (decode_pubkey(SYSVAR_RENT), false, false)], data }
}

/// `DelegateStake` (variant 2).
fn delegate(stake: &[u8; 32], vote: &[u8; 32], owner: &[u8; 32]) -> Instruction {
    Instruction {
        program_id: decode_pubkey(STAKE_PROGRAM),
        accounts: vec![
            (*stake, false, true),
            (*vote, false, false),
            (decode_pubkey(SYSVAR_CLOCK), false, false),
            (decode_pubkey(SYSVAR_STAKE_HISTORY), false, false),
            (decode_pubkey(STAKE_CONFIG), false, false),
            (*owner, true, false),
        ],
        data: 2u32.to_le_bytes().to_vec(),
    }
}

/// `Deactivate` (variant 5).
fn deactivate(stake: &[u8; 32], owner: &[u8; 32]) -> Instruction {
    Instruction {
        program_id: decode_pubkey(STAKE_PROGRAM),
        accounts: vec![(*stake, false, true), (decode_pubkey(SYSVAR_CLOCK), false, false), (*owner, true, false)],
        data: 5u32.to_le_bytes().to_vec(),
    }
}

/// `Withdraw` (variant 4) to `owner`.
fn withdraw(stake: &[u8; 32], owner: &[u8; 32], lamports: u64) -> Instruction {
    let mut data = 4u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: decode_pubkey(STAKE_PROGRAM),
        accounts: vec![
            (*stake, false, true),
            (*owner, false, true),
            (decode_pubkey(SYSVAR_CLOCK), false, false),
            (decode_pubkey(SYSVAR_STAKE_HISTORY), false, false),
            (*owner, true, false),
        ],
        data,
    }
}

// --- Reading stake accounts
// ---------------------------------------------------------------

/// Delegation of a stake account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Delegation {
    voter: [u8; 32],
    stake: u64,
    activation: u64,
    deactivation: u64,
}

/// Decoded `StakeStateV2` (bincode): `Initialized(Meta)` or `Stake(Meta, Stake,
/// StakeFlags)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Parsed {
    rent_reserve: u64,
    staker: [u8; 32],
    withdrawer: [u8; 32],
    lockup_timestamp: i64,
    lockup_epoch: u64,
    custodian: [u8; 32],
    delegation: Option<Delegation>,
}

fn parse(data: &[u8]) -> Option<Parsed> {
    let u64_at = |at: usize| data.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().expect("8 octets")));
    let key_at = |at: usize| data.get(at..at + 32).map(|b| <[u8; 32]>::try_from(b).expect("32 octets"));
    let tag = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?);
    let delegation = match tag {
        1 => None,
        2 => Some(Delegation { voter: key_at(124)?, stake: u64_at(156)?, activation: u64_at(164)?, deactivation: u64_at(172)? }),
        _ => return None,
    };
    Some(Parsed {
        rent_reserve: u64_at(4)?,
        staker: key_at(12)?,
        withdrawer: key_at(44)?,
        lockup_timestamp: u64_at(76)? as i64,
        lockup_epoch: u64_at(84)?,
        custodian: key_at(92)?,
        delegation,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeStatus {
    /// Initialized account, never delegated (created elsewhere).
    Undelegated,
    /// Delegated during the current epoch: active from the next one.
    Activating,
    Active,
    /// Deactivated during the current epoch: withdrawable from the next one.
    Deactivating,
    /// Withdrawable.
    Inactive,
}

/// Status at epoch `epoch` (warm-up and cool-down take one epoch, which is the case
/// for any modest stake; longer only if a huge share of the network moves at the
/// same time, and the refused withdrawal is then explained).
fn status(delegation: Option<Delegation>, epoch: u64) -> StakeStatus {
    match delegation {
        None => StakeStatus::Undelegated,
        // Deactivated during its activation epoch: never active.
        Some(d) if d.activation == d.deactivation => StakeStatus::Inactive,
        Some(d) if d.deactivation == NO_DEACTIVATION => {
            if epoch <= d.activation {
                StakeStatus::Activating
            } else {
                StakeStatus::Active
            }
        }
        Some(d) if epoch <= d.deactivation => StakeStatus::Deactivating,
        Some(_) => StakeStatus::Inactive,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StakeAccount {
    pub address: String,
    pub lamports: u64,
    pub status: StakeStatus,
    /// The validator's vote account.
    pub validator: Option<String>,
    /// Delegated stake (rewards included), in lamports.
    pub staked: u64,
    /// The account's reserve, returned on withdrawal.
    pub rent_reserve: u64,
    /// You are the stake authority (deactivation possible).
    pub can_deactivate: bool,
    /// Lockup still in force: withdrawal not possible for now.
    pub locked: bool,
    /// The validator's published name (stakewiz).
    pub validator_name: Option<String>,
    /// Validator flagged since ("sandwiching", seesawing commission…).
    pub validator_flagged: bool,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn lockup_in_force(parsed: &Parsed, owner: &[u8; 32], epoch: u64) -> bool {
    parsed.custodian != *owner && (parsed.lockup_timestamp > now_unix() || parsed.lockup_epoch > epoch)
}

fn stake_account(address: &str, state: &AccountState, owner: &[u8; 32], epoch: u64) -> Option<StakeAccount> {
    if state.owner != STAKE_PROGRAM {
        return None;
    }
    let parsed = parse(&state.data)?;
    if parsed.withdrawer != *owner {
        return None;
    }
    Some(StakeAccount {
        address: address.to_string(),
        lamports: state.lamports,
        status: status(parsed.delegation, epoch),
        validator: parsed.delegation.map(|d| b58(&d.voter)),
        staked: parsed.delegation.map_or(0, |d| d.stake),
        rent_reserve: parsed.rent_reserve,
        can_deactivate: parsed.staker == *owner,
        locked: lockup_in_force(&parsed, owner, epoch),
        validator_name: None,
        validator_flagged: false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EpochInfo {
    pub epoch: u64,
    /// Estimated end of the current epoch (0.4 s per slot).
    pub ends_in_secs: u64,
}

pub fn epoch_info(rpc: &SolRpc) -> Result<EpochInfo> {
    let info = rpc.call("getEpochInfo", json!([{"commitment": "confirmed"}]))?;
    let field = |name: &str| info[name].as_u64().with_context(|| format!("réponse getEpochInfo sans {name}"));
    let remaining = field("slotsInEpoch")?.saturating_sub(field("slotIndex")?);
    Ok(EpochInfo { epoch: field("epoch")?, ends_in_secs: remaining * SLOT_MILLIS / 1000 })
}

fn minimum_delegation(rpc: &SolRpc) -> Result<u64> {
    rpc.call("getStakeMinimumDelegation", json!([{"commitment": "confirmed"}]))?["value"].as_u64().context("réponse getStakeMinimumDelegation inattendue")
}

/// Stake accounts whose withdraw authority is `owner`: search by program; if the
/// node refuses that, read the derived addresses.
fn owned_accounts(rpc: &SolRpc, owner: &[u8; 32]) -> Result<Vec<(String, AccountState)>> {
    let search = rpc.call(
        "getProgramAccounts",
        json!([STAKE_PROGRAM, {
            "encoding": "base64",
            "commitment": "confirmed",
            "filters": [{"dataSize": STAKE_ACCOUNT_SPACE}, {"memcmp": {"offset": 44, "bytes": b58(owner)}}],
        }]),
    );
    if let Ok(Value::Array(entries)) = search {
        let mut found = Vec::new();
        for entry in &entries {
            let address = entry["pubkey"].as_str().context("réponse getProgramAccounts sans adresse")?;
            if let Some(state) = AccountState::from_rpc_value(&entry["account"])? {
                found.push((address.to_string(), state));
            }
        }
        return Ok(found);
    }
    let addresses: Vec<String> = (0..SEED_SCAN).map(|i| b58(&derived_address(owner, &format!("{SEED_PREFIX}{i}")))).collect();
    let states = rpc.multiple_accounts(&addresses)?;
    Ok(addresses.into_iter().zip(states).filter_map(|(address, state)| state.map(|s| (address, s))).collect())
}

/// SOL in `owner`'s stake accounts (reserves included): counted with its balance in
/// the portfolio chart.
pub fn staked_lamports(rpc: &SolRpc, owner: &str) -> Result<u64> {
    let owner = key(owner)?;
    Ok(owned_accounts(rpc, &owner)?.iter().filter(|(_, state)| state.owner == STAKE_PROGRAM && parse(&state.data).is_some_and(|p| p.withdrawer == owner)).map(|(_, state)| state.lamports).sum())
}

/// Overview for the SOL card's "Stake" window.
#[derive(Clone, Debug, Serialize)]
pub struct Overview {
    pub accounts: Vec<StakeAccount>,
    pub epoch: EpochInfo,
    /// The network's minimum stake (1 SOL as of 2026-10-06).
    pub min_delegation: u64,
    /// A stake account's reserve, paid at creation and returned on withdrawal.
    pub rent_reserve: u64,
}

pub fn overview(rpc: &SolRpc, owner: &str) -> Result<Overview> {
    let owner = key(owner)?;
    std::thread::scope(|scope| {
        let epoch = scope.spawn(|| epoch_info(rpc));
        let min = scope.spawn(|| minimum_delegation(rpc));
        let rent = scope.spawn(|| rpc.minimum_rent_exempt_balance(STAKE_ACCOUNT_SPACE));
        let accounts = owned_accounts(rpc, &owner);
        let epoch = epoch.join().map_err(|_| anyhow!("lecture de l'époque interrompue"))??;
        let mut accounts: Vec<StakeAccount> = accounts?.iter().filter_map(|(address, state)| stake_account(address, state, &owner, epoch.epoch)).collect();
        // Validator names (2 MB, kept for 10 min): only if there are any.
        let wiz = if accounts.iter().any(|a| a.validator.is_some()) { wiz_cached() } else { HashMap::new() };
        for account in &mut accounts {
            if let Some(info) = account.validator.as_ref().and_then(|v| wiz.get(v)) {
                account.validator_name = info.name.clone();
                account.validator_flagged = info.flagged;
            }
        }
        accounts.sort_by(|a, b| b.lamports.cmp(&a.lamports).then_with(|| a.address.cmp(&b.address)));
        Ok(Overview {
            accounts,
            epoch,
            min_delegation: min.join().map_err(|_| anyhow!("lecture interrompue"))??,
            rent_reserve: rent.join().map_err(|_| anyhow!("lecture interrompue"))??,
        })
    })
}

// --- Validators ----------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Validator {
    /// Vote account (the one we delegate to).
    pub vote: String,
    /// Name published by the validator (stakewiz); `None` if unknown.
    pub name: Option<String>,
    pub commission: u8,
    /// Total stake received, in SOL.
    pub active_stake_sol: u64,
    /// Estimated annual yield (stakewiz: inflation and MEV), in percent.
    pub apy: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
struct Candidate {
    vote: String,
    commission: u8,
    stake: u64,
    credits: u64,
}

/// Eligible validators according to `getVoteAccounts` (the chain itself): up to
/// date with their votes, commission of at most 5% (and inflation commission, if
/// announced), outside the superminority, at least 20,000 SOL, and vote credits for
/// the last complete epoch of at least 97% of the 90th percentile.
fn eligible(vote_accounts: &Value) -> Result<Vec<Candidate>> {
    let current = vote_accounts["current"].as_array().context("réponse getVoteAccounts inattendue")?;
    let delinquent_stake: u64 = vote_accounts["delinquent"].as_array().map_or(0, |list| list.iter().filter_map(|v| v["activatedStake"].as_u64()).sum());
    let current_epoch = current.iter().filter_map(|v| v["epochCredits"].as_array()?.last()?.get(0)?.as_u64()).max().context("getVoteAccounts sans crédits de vote")?;
    let last_epoch_credits = |v: &Value| -> u64 {
        v["epochCredits"].as_array().into_iter().flatten().find(|e| e.get(0).and_then(Value::as_u64) == Some(current_epoch - 1)).map_or(0, |e| {
            e.get(1).and_then(Value::as_u64).unwrap_or(0).saturating_sub(e.get(2).and_then(Value::as_u64).unwrap_or(u64::MAX))
        })
    };
    let mut all: Vec<(&Value, u64)> = current.iter().map(|v| (v, v["activatedStake"].as_u64().unwrap_or(0))).collect();
    let total: u64 = all.iter().map(|(_, s)| s).sum::<u64>() + delinquent_stake;
    all.sort_by_key(|(_, stake)| std::cmp::Reverse(*stake));
    // Superminority: the largest validators until their total exceeds a third of the
    // stake.
    let mut cumulative = 0u64;
    let mut superminority = 0usize;
    for (_, s) in &all {
        if cumulative * 3 > total {
            break;
        }
        cumulative += s;
        superminority += 1;
    }
    let mut credits: Vec<u64> = current.iter().map(last_epoch_credits).filter(|c| *c > 0).collect();
    credits.sort_unstable();
    let p90 = *credits.get(credits.len() * 9 / 10).context("aucun crédit de vote")?;
    Ok(all
        .into_iter()
        .skip(superminority)
        .filter_map(|(v, stake)| {
            let commission = v["commission"].as_u64()?;
            let inflation_bps = v["inflationRewardsCommissionBps"].as_u64().unwrap_or(commission * 100);
            let credits = last_epoch_credits(v);
            (v["epochVoteAccount"].as_bool() == Some(true)
                && commission <= MAX_COMMISSION
                && inflation_bps <= MAX_COMMISSION * 100
                && stake >= MIN_VALIDATOR_STAKE_SOL * 1_000_000_000
                && credits * 100 >= p90 * 97)
                .then(|| Candidate { vote: v["votePubkey"].as_str().unwrap_or_default().to_string(), commission: commission as u8, stake, credits })
        })
        .filter(|c| key(&c.vote).is_ok())
        .collect())
}

fn vote_accounts(rpc: &SolRpc) -> Result<Value> {
    rpc.call("getVoteAccounts", json!([{"commitment": "confirmed", "keepUnstakedDelinquents": false}]))
}

/// Displayable name: printable characters, 32 at most (third-party data).
fn display_name(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().map(|c| if c.is_control() { ' ' } else { c }).filter(|c| !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')).collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    // Cut at 32 characters, with no dangling separator at the end.
    let cut: String = cleaned.chars().take(32).collect();
    let cut = cut.trim_end_matches([' ', '-', '|', '·', ',']).to_string();
    (!cut.is_empty()).then_some(cut)
}

/// A validator's stakewiz record (keyless): published name, estimated yield,
/// quality score (votes, skipped blocks, age, concentration…) and flags raised by
/// the stakewiz team ("sandwiching", commission alternating between 0 and 100%…).
#[derive(Clone, Debug, Default, PartialEq)]
struct Wiz {
    name: Option<String>,
    apy: Option<f64>,
    score: f64,
    flagged: bool,
}

fn wiz_entry(v: &Value) -> Option<(String, Wiz)> {
    let flagged = v["admin_comment"].as_str().is_some_and(|c| !c.trim().is_empty()) || v["delinquent"].as_bool() == Some(true);
    Some((
        v["vote_identity"].as_str()?.to_string(),
        Wiz {
            name: v["name"].as_str().and_then(display_name),
            apy: v["total_apy"].as_f64().filter(|a| a.is_finite() && *a > 0.0 && *a < 30.0),
            score: v["wiz_score"].as_f64().filter(|s| s.is_finite()).unwrap_or(0.0),
            flagged,
        },
    ))
}

/// Stakewiz records by vote account (empty if the site does not answer).
fn stakewiz() -> HashMap<String, Wiz> {
    let fetch = || -> Option<Value> {
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).user_agent("openpgp-wallet").build().ok()?;
        client.get(STAKEWIZ).send().ok()?.error_for_status().ok()?.json().ok()
    };
    fetch().and_then(|v| v.as_array().cloned()).unwrap_or_default().iter().filter_map(wiz_entry).collect()
}

/// `stakewiz` kept for 10 minutes (2 MB per read).
fn wiz_cached() -> HashMap<String, Wiz> {
    static CACHE: Mutex<Option<(Instant, HashMap<String, Wiz>)>> = Mutex::new(None);
    if let Some((at, map)) = CACHE.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        if at.elapsed() < Duration::from_secs(600) {
            return map.clone();
        }
    }
    let fresh = stakewiz();
    if !fresh.is_empty() {
        *CACHE.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), fresh.clone()));
    }
    fresh
}

/// A validator's published name (confirmation dialog).
pub fn validator_name(vote: &str) -> Option<String> {
    wiz_cached().get(vote.trim()).and_then(|info| info.name.clone())
}

/// Ordering of eligible validators. With stakewiz: flagged and unknown ones
/// dropped, best score first; never the highest advertised yield, which dubious
/// validators inflate (seen on 2026-10-06: the top one by yield was alternating its
/// commission between 0 and 100%). Without stakewiz: the most established (stake
/// received) first.
fn ranked(candidates: Vec<Candidate>, wiz: &HashMap<String, Wiz>) -> Vec<Validator> {
    let mut list: Vec<(Validator, f64, u64)> = candidates
        .into_iter()
        .filter_map(|c| {
            let info = match wiz.get(&c.vote) {
                Some(info) if info.flagged => return None,
                Some(info) => info.clone(),
                None if !wiz.is_empty() => return None,
                None => Wiz::default(),
            };
            Some((Validator { vote: c.vote, name: info.name, commission: c.commission, active_stake_sol: c.stake / 1_000_000_000, apy: info.apy }, info.score, c.credits))
        })
        .collect();
    list.sort_by(|(a, score_a, credits_a), (b, score_b, credits_b)| {
        score_b
            .total_cmp(score_a)
            .then_with(|| b.active_stake_sol.cmp(&a.active_stake_sol))
            .then_with(|| a.commission.cmp(&b.commission))
            .then_with(|| credits_b.cmp(credits_a))
    });
    list.into_iter().take(MAX_VALIDATORS).map(|(v, _, _)| v).collect()
}

/// Validators offered (12 at most).
pub fn validators(rpc: &SolRpc) -> Result<Vec<Validator>> {
    let (accounts, names) = std::thread::scope(|scope| {
        let names = scope.spawn(wiz_cached);
        (vote_accounts(rpc), names.join().unwrap_or_default())
    });
    let list = ranked(eligible(&accounts?)?, &names);
    ensure!(!list.is_empty(), "aucun validateur Solana ne remplit les critères en ce moment — réessayez plus tard");
    Ok(list)
}

// --- Operations ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Delegate,
    Deactivate,
    Withdraw,
}

/// A prepared operation: exactly what will be signed and shown.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Plan {
    pub action: Action,
    pub stake_account: String,
    /// Seed of the new account (staking).
    pub seed: Option<String>,
    pub validator: Option<String>,
    pub commission: Option<u8>,
    /// Amount staked, or returned to your address (withdrawal), in lamports.
    pub lamports: u64,
    /// The stake account's reserve: paid at creation, returned on withdrawal.
    pub rent_reserve: u64,
    pub fee: u64,
}

/// Instructions of `plan` signed by `owner` (the only signer and the payer).
fn instructions(plan: &Plan, owner: &[u8; 32]) -> Result<Vec<Instruction>> {
    let stake = key(&plan.stake_account)?;
    Ok(match plan.action {
        Action::Delegate => {
            let seed = plan.seed.as_deref().context("graine du compte de mise absente")?;
            ensure!(seed.len() <= 32 && derived_address(owner, seed) == stake, "adresse du compte de mise incohérente");
            let vote = key(plan.validator.as_deref().context("validateur absent")?)?;
            let funded = plan.lamports.checked_add(plan.rent_reserve).context("montant trop grand")?;
            vec![create_with_seed(owner, &stake, seed, funded), initialize(&stake, owner), delegate(&stake, &vote, owner)]
        }
        Action::Deactivate => vec![deactivate(&stake, owner)],
        Action::Withdraw => vec![withdraw(&stake, owner, plan.lamports)],
    })
}

/// Message to sign (recent blockhash).
pub fn message(plan: &Plan, owner: &[u8; 32], recent_blockhash: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(build_message(owner, &instructions(plan, owner)?, recent_blockhash))
}

/// SOL kept on your address after staking: an account's minimum reserve (required
/// by Solana) and the fees for the two exit operations.
fn kept_after_delegation(rpc: &SolRpc) -> Result<u64> {
    Ok(rpc.minimum_rent_exempt_balance(0)? + 2 * FEE_LAMPORTS)
}

/// Maximum stake from `owner` (the window's "Max"); below the network minimum, an
/// explanation rather than an impossible amount.
pub fn max_delegation(rpc: &SolRpc, owner: &str) -> Result<u64> {
    let (balance, rent, kept, min) = std::thread::scope(|scope| {
        let rent = scope.spawn(|| rpc.minimum_rent_exempt_balance(STAKE_ACCOUNT_SPACE));
        let kept = scope.spawn(|| kept_after_delegation(rpc));
        let min = scope.spawn(|| minimum_delegation(rpc));
        let join = |r: std::thread::Result<Result<u64>>| r.map_err(|_| anyhow!("lecture interrompue"))?;
        (rpc.balance_lamports(owner.trim()), join(rent.join()), join(kept.join()), join(min.join()))
    });
    let (rent, kept, min) = (rent?, kept?, min?);
    let max = balance?.saturating_sub(rent + FEE_LAMPORTS + kept);
    ensure!(
        max >= min,
        "pas assez de SOL pour staker : il faut au moins {} SOL sur votre adresse (mise minimale {} SOL, réserve du compte de mise et frais)",
        format_lamports(min + rent + FEE_LAMPORTS + kept),
        format_lamports(min)
    );
    Ok(max)
}

/// First free seed (no account at that address, not even SOL sent by a third party,
/// which would make the creation fail).
fn free_seed(rpc: &SolRpc, owner: &[u8; 32]) -> Result<(String, String)> {
    let seeds: Vec<String> = (0..SEED_SCAN).map(|i| format!("{SEED_PREFIX}{i}")).collect();
    let addresses: Vec<String> = seeds.iter().map(|s| b58(&derived_address(owner, s))).collect();
    let states = rpc.multiple_accounts(&addresses)?;
    seeds.into_iter().zip(addresses).zip(states).find(|(_, state)| state.is_none()).map(|(pair, _)| pair).context("trop de comptes de mise : retirez d'abord ceux qui sont arrêtés")
}

pub fn plan_delegate(rpc: &SolRpc, owner: &str, lamports: u64, vote: &str) -> Result<Plan> {
    let owner_key = key(owner)?;
    key(vote)?;
    let (balance, min, rent, kept, accounts, seed) = std::thread::scope(|scope| {
        let min = scope.spawn(|| minimum_delegation(rpc));
        let rent = scope.spawn(|| rpc.minimum_rent_exempt_balance(STAKE_ACCOUNT_SPACE));
        let kept = scope.spawn(|| kept_after_delegation(rpc));
        let accounts = scope.spawn(|| vote_accounts(rpc));
        let seed = scope.spawn(|| free_seed(rpc, &owner_key));
        let balance = rpc.balance_lamports(owner.trim());
        let join = |r: std::thread::Result<Result<u64>>| r.map_err(|_| anyhow!("lecture interrompue"))?;
        (balance, join(min.join()), join(rent.join()), join(kept.join()), accounts.join().map_err(|_| anyhow!("lecture interrompue")), seed.join().map_err(|_| anyhow!("lecture interrompue")))
    });
    let (balance, min, rent, kept) = (balance?, min?, rent?, kept?);
    ensure!(lamports >= min, "mise minimale sur Solana : {} SOL", format_lamports(min));
    let candidate = eligible(&accounts??)?
        .into_iter()
        .find(|c| c.vote == vote.trim())
        .ok_or_else(|| anyhow!("ce validateur n'est plus proposé (retard de votes, commission relevée ou mise trop grosse) — choisissez-en un autre"))?;
    let needed = lamports.checked_add(rent + FEE_LAMPORTS + kept).context("montant trop grand")?;
    ensure!(
        balance >= needed,
        "SOL insuffisant : {} SOL disponibles, il en faut {} (mise, réserve du compte de mise {} SOL rendue au retrait, frais, et {} SOL gardés pour l'arrêt)",
        format_lamports(balance),
        format_lamports(needed),
        format_lamports(rent),
        format_lamports(kept)
    );
    let (seed, stake_account) = seed??;
    let plan = Plan {
        action: Action::Delegate,
        stake_account,
        seed: Some(seed),
        validator: Some(candidate.vote),
        commission: Some(candidate.commission),
        lamports,
        rent_reserve: rent,
        fee: FEE_LAMPORTS,
    };
    simulate(rpc, &owner_key, &plan)?;
    Ok(plan)
}

/// `owner`'s stake account `stake`, read just now.
fn read_own(rpc: &SolRpc, owner: &[u8; 32], stake: &str) -> Result<(AccountState, Parsed, EpochInfo, u64)> {
    let (state, epoch, balance) = std::thread::scope(|scope| {
        let epoch = scope.spawn(|| epoch_info(rpc));
        let balance = scope.spawn(|| rpc.balance_lamports(&b58(owner)));
        (rpc.multiple_accounts(&[stake.trim().to_string()]), epoch.join(), balance.join())
    });
    let state = state?.pop().flatten().context("compte de mise introuvable")?;
    ensure!(state.owner == STAKE_PROGRAM, "ce compte n'est pas un compte de mise");
    let parsed = parse(&state.data).context("compte de mise illisible")?;
    let balance = balance.map_err(|_| anyhow!("lecture interrompue"))??;
    ensure!(balance >= FEE_LAMPORTS, "il faut au moins {} SOL sur votre adresse pour les frais", format_lamports(FEE_LAMPORTS));
    Ok((state, parsed, epoch.map_err(|_| anyhow!("lecture interrompue"))??, balance))
}

pub fn plan_deactivate(rpc: &SolRpc, owner: &str, stake: &str) -> Result<Plan> {
    let owner_key = key(owner)?;
    let (state, parsed, epoch, _) = read_own(rpc, &owner_key, stake)?;
    ensure!(parsed.withdrawer == owner_key && parsed.staker == owner_key, "ce compte de mise n'est pas sous votre contrôle");
    let delegation = parsed.delegation.filter(|_| matches!(status(parsed.delegation, epoch.epoch), StakeStatus::Activating | StakeStatus::Active));
    let delegation = delegation.context("ce compte n'est pas en cours de staking")?;
    let plan = Plan {
        action: Action::Deactivate,
        stake_account: stake.trim().to_string(),
        seed: None,
        validator: Some(b58(&delegation.voter)),
        commission: None,
        lamports: state.lamports,
        rent_reserve: parsed.rent_reserve,
        fee: FEE_LAMPORTS,
    };
    simulate(rpc, &owner_key, &plan)?;
    Ok(plan)
}

pub fn plan_withdraw(rpc: &SolRpc, owner: &str, stake: &str) -> Result<Plan> {
    let owner_key = key(owner)?;
    let (state, parsed, epoch, _) = read_own(rpc, &owner_key, stake)?;
    ensure!(parsed.withdrawer == owner_key, "ce compte de mise n'est pas sous votre contrôle");
    match status(parsed.delegation, epoch.epoch) {
        StakeStatus::Inactive | StakeStatus::Undelegated => {}
        StakeStatus::Deactivating => bail!("retrait possible à la fin de l'époque en cours (dans {} environ)", duration_text(epoch.ends_in_secs)),
        StakeStatus::Activating | StakeStatus::Active => bail!("arrêtez d'abord le staking de ce compte (désactivation), puis retirez-le à l'époque suivante"),
    }
    ensure!(!lockup_in_force(&parsed, &owner_key, epoch.epoch), "ce compte de mise est verrouillé par son créateur : retrait impossible pour l'instant");
    let plan = Plan {
        action: Action::Withdraw,
        stake_account: stake.trim().to_string(),
        seed: None,
        validator: parsed.delegation.map(|d| b58(&d.voter)),
        commission: None,
        lamports: state.lamports,
        rent_reserve: parsed.rent_reserve,
        fee: FEE_LAMPORTS,
    };
    simulate(rpc, &owner_key, &plan)?;
    Ok(plan)
}

/// "14 h", "35 min".
pub fn duration_text(secs: u64) -> String {
    if secs >= 3600 {
        format!("{} h", secs.div_ceil(3600))
    } else {
        format!("{} min", secs.div_ceil(60).max(1))
    }
}

/// Simulation by the node (signature not verified, blockhash replaced), then the
/// stake account's state AFTER the transaction compared with what was announced.
fn simulate(rpc: &SolRpc, owner: &[u8; 32], plan: &Plan) -> Result<()> {
    let raw = assemble_transaction(&[0u8; 64], &message(plan, owner, &[0u8; 32])?);
    match rpc.simulate_with_account_states(&raw, std::slice::from_ref(&plan.stake_account))? {
        SimulationOutcome::Failed { err, logs } => Err(rpc.explain_simulation_failure(&err, &logs).unwrap_or_else(|| match plan.action {
            Action::Withdraw if logs.contains("insufficient funds") => {
                anyhow!("retrait pas encore possible : la désactivation n'est pas terminée — réessayez à l'époque suivante")
            }
            _ => anyhow!("le réseau Solana refuserait cette opération : {err}"),
        })),
        SimulationOutcome::Succeeded { post_states } => verify_after(plan, owner, post_states.into_iter().next().flatten()),
    }
}

fn verify_after(plan: &Plan, owner: &[u8; 32], after: Option<AccountState>) -> Result<()> {
    let wrong = || anyhow!("la simulation ne donne pas le résultat annoncé — opération refusée par sécurité");
    match plan.action {
        Action::Withdraw => ensure!(after.is_none_or(|a| a.lamports == 0), wrong()),
        Action::Delegate | Action::Deactivate => {
            let after = after.ok_or_else(wrong)?;
            let parsed = parse(&after.data).ok_or_else(wrong)?;
            let delegation = parsed.delegation.ok_or_else(wrong)?;
            ensure!(after.owner == STAKE_PROGRAM && parsed.withdrawer == *owner && parsed.staker == *owner, wrong());
            ensure!(Some(b58(&delegation.voter)) == plan.validator, wrong());
            if plan.action == Action::Delegate {
                ensure!(
                    after.lamports == plan.lamports + plan.rent_reserve
                        && delegation.stake == plan.lamports
                        && delegation.deactivation == NO_DEACTIVATION
                        && parsed.lockup_timestamp == 0
                        && parsed.lockup_epoch == 0
                        && parsed.custodian == [0u8; 32],
                    wrong()
                );
            } else {
                ensure!(after.lamports == plan.lamports && delegation.deactivation != NO_DEACTIVATION, wrong());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stake_data(tag: u32, staker: [u8; 32], withdrawer: [u8; 32], delegation: Option<Delegation>) -> Vec<u8> {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&tag.to_le_bytes());
        data[4..12].copy_from_slice(&1_666_240u64.to_le_bytes());
        data[12..44].copy_from_slice(&staker);
        data[44..76].copy_from_slice(&withdrawer);
        if let Some(d) = delegation {
            data[124..156].copy_from_slice(&d.voter);
            data[156..164].copy_from_slice(&d.stake.to_le_bytes());
            data[164..172].copy_from_slice(&d.activation.to_le_bytes());
            data[172..180].copy_from_slice(&d.deactivation.to_le_bytes());
        }
        data
    }

    /// Bincode encoding of the instructions (solana-system-interface and
    /// solana-stake-interface formats); stable address derivation.
    #[test]
    fn instructions_are_encoded() {
        let owner = [7u8; 32];
        let stake = derived_address(&owner, "stake:0");
        assert_ne!(stake, derived_address(&owner, "stake:1"));
        let create = create_with_seed(&owner, &stake, "stake:0", 1_001_666_240);
        assert_eq!(create.data.len(), 4 + 32 + 8 + 7 + 8 + 8 + 32);
        assert_eq!(&create.data[0..4], &3u32.to_le_bytes());
        assert_eq!(&create.data[36..44], &7u64.to_le_bytes());
        assert_eq!(&create.data[51..59], &1_001_666_240u64.to_le_bytes());
        assert_eq!(&create.data[59..67], &200u64.to_le_bytes());
        assert_eq!(create.accounts, vec![(owner, true, true), (stake, false, true), (owner, true, false)]);
        let init = initialize(&stake, &owner);
        assert_eq!(init.data.len(), 116);
        assert!(init.data[68..].iter().all(|b| *b == 0));
        assert_eq!(delegate(&stake, &[9u8; 32], &owner).accounts.len(), 6);
        assert_eq!(deactivate(&stake, &owner).data, 5u32.to_le_bytes());
        let w = withdraw(&stake, &owner, 42);
        assert_eq!(w.data, [4u32.to_le_bytes().as_slice(), 42u64.to_le_bytes().as_slice()].concat());
        // A single signature: yours (payer, base and authority).
        let plan = Plan {
            action: Action::Delegate,
            stake_account: b58(&stake),
            seed: Some("stake:0".into()),
            validator: Some(b58(&[9u8; 32])),
            commission: Some(0),
            lamports: 1_000_000_000,
            rent_reserve: 1_666_240,
            fee: FEE_LAMPORTS,
        };
        let msg = message(&plan, &owner, &[1u8; 32]).unwrap();
        assert_eq!(msg[0], 1);
        // Seed that does not match the address: refused.
        let wrong = Plan { seed: Some("stake:1".into()), ..plan };
        assert!(message(&wrong, &owner, &[1u8; 32]).is_err());
    }

    #[test]
    fn stake_accounts_are_read() {
        let owner = [7u8; 32];
        let other = [8u8; 32];
        let d = |activation, deactivation| Some(Delegation { voter: [9u8; 32], stake: 1_000_000_000, activation, deactivation });
        let parsed = parse(&stake_data(2, owner, owner, d(1000, NO_DEACTIVATION))).unwrap();
        assert_eq!(parsed.rent_reserve, 1_666_240);
        assert_eq!(parsed.delegation.unwrap().stake, 1_000_000_000);
        assert_eq!(status(d(1000, NO_DEACTIVATION), 1000), StakeStatus::Activating);
        assert_eq!(status(d(1000, NO_DEACTIVATION), 1001), StakeStatus::Active);
        assert_eq!(status(d(1000, 1005), 1005), StakeStatus::Deactivating);
        assert_eq!(status(d(1000, 1005), 1006), StakeStatus::Inactive);
        assert_eq!(status(d(1000, 1000), 1000), StakeStatus::Inactive);
        assert_eq!(status(None, 1000), StakeStatus::Undelegated);
        let state = |data| AccountState { lamports: 1_001_666_240, owner: STAKE_PROGRAM.into(), data };
        let mine = stake_account("A", &state(stake_data(2, owner, owner, d(1000, NO_DEACTIVATION))), &owner, 1001).unwrap();
        assert_eq!((mine.status, mine.can_deactivate, mine.locked), (StakeStatus::Active, true, false));
        // Someone else's withdraw authority: not yours; someone else's stake authority: no deactivation.
        assert!(stake_account("B", &state(stake_data(2, owner, other, d(1000, NO_DEACTIVATION))), &owner, 1001).is_none());
        assert!(!stake_account("C", &state(stake_data(2, other, owner, d(1000, NO_DEACTIVATION))), &owner, 1001).unwrap().can_deactivate);
        assert!(stake_account("D", &AccountState { owner: "11111111111111111111111111111111".into(), ..state(stake_data(1, owner, owner, None)) }, &owner, 1).is_none());
        assert!(parse(&[3, 0, 0, 0]).is_none());
        // Lockup in force (future epoch, third-party custodian).
        let mut locked = stake_data(1, owner, owner, None);
        locked[84..92].copy_from_slice(&2000u64.to_le_bytes());
        locked[92..124].copy_from_slice(&other);
        assert!(stake_account("E", &state(locked), &owner, 1001).unwrap().locked);
    }

    fn vote(vote: &str, stake_sol: u64, commission: u64, last: u64) -> Value {
        json!({
            "votePubkey": vote, "activatedStake": stake_sol * 1_000_000_000, "commission": commission, "epochVoteAccount": true,
            "epochCredits": [[1049, 1000 + last, 1000], [1050, 2000 + last, 1000 + last]],
        })
    }

    /// Superminority, commission, minimum stake and lagging votes filtered out.
    #[test]
    fn validators_are_filtered() {
        let k = |n: u8| b58(&[n; 32]);
        let accounts = json!({
            "current": [
                vote(&k(1), 5_000_000, 0, 7000), // superminority
                vote(&k(2), 900_000, 0, 7000),
                vote(&k(3), 900_000, 10, 7000), // commission
                vote(&k(4), 10_000, 0, 7000), // too small
                vote(&k(5), 900_000, 5, 6000), // lagging votes
                vote(&k(6), 900_000, 5, 6990),
                vote(&k(7), 900_000, 0, 7000),
                vote(&k(8), 900_000, 0, 7000),
                vote(&k(9), 900_000, 0, 7000),
                vote(&k(10), 900_000, 0, 7000),
                vote(&k(11), 900_000, 0, 7000),
            ],
            "delinquent": [],
        });
        let votes: Vec<String> = eligible(&accounts).unwrap().into_iter().map(|c| c.vote).collect();
        assert!(!votes.contains(&k(1)) && !votes.contains(&k(3)) && !votes.contains(&k(4)) && !votes.contains(&k(5)));
        assert!(votes.contains(&k(2)) && votes.contains(&k(6)));
        // Without stakewiz: every eligible validator, the most established first.
        let all = ranked(eligible(&accounts).unwrap(), &HashMap::new());
        assert_eq!(all.len(), votes.len());
        // With stakewiz: best score first, flagged and unknown ones dropped, whatever the
        // advertised yield.
        let wiz = |name: &str, apy: f64, score: f64, comment: Value| wiz_entry(&json!({ "vote_identity": "x", "name": name, "total_apy": apy, "wiz_score": score, "admin_comment": comment })).unwrap().1;
        let mut info = HashMap::new();
        info.insert(k(6), wiz("Six", 5.1, 99.0, Value::Null));
        info.insert(k(2), wiz("Deux", 5.2, 95.0, Value::Null));
        info.insert(k(7), wiz("Douteux", 8.2, 99.9, json!("Suspicious commission change pattern.")));
        let list = ranked(eligible(&accounts).unwrap(), &info);
        assert_eq!(list.iter().map(|v| v.name.as_deref().unwrap()).collect::<Vec<_>>(), ["Six", "Deux"]);
        assert_eq!(list[0].apy, Some(5.1));
        assert_eq!(display_name("  A\u{202E}b\nc  "), Some("Ab c".to_string()));
        assert_eq!(display_name("\u{200B}"), None);
        assert_eq!(display_name("Yonta Labs - LST 0%Fee MEV - | - Low").as_deref(), Some("Yonta Labs - LST 0%Fee MEV"));
    }

    fn mainnet() -> SolRpc {
        SolRpc::new(crate::wallet_flow::SOLANA_MAINNET.rpc)
    }

    /// Identity of an offered validator whose address holds at least 3 SOL (dummy payer
    /// for the simulations: signature not verified).
    fn funded_payer(rpc: &SolRpc) -> String {
        let accounts = vote_accounts(rpc).unwrap();
        for v in accounts["current"].as_array().unwrap().iter().take(40) {
            let node = v["nodePubkey"].as_str().unwrap();
            if rpc.balance_lamports(node).unwrap_or(0) > 3_000_000_000 {
                return node.to_string();
            }
        }
        panic!("aucune adresse pourvue trouvée");
    }

    /// Live: validators offered, overview, staking 1 SOL simulated by the node
    /// (creation, initialization, delegation) with the stake account's state checked
    /// afterwards.
    /// `cargo test -- --ignored real_native_staking_simulates --nocapture`
    #[test]
    #[ignore]
    fn real_native_staking_simulates() {
        let rpc = mainnet();
        let list = validators(&rpc).unwrap();
        println!("{} validateurs : {:?}", list.len(), list.iter().take(3).collect::<Vec<_>>());
        let payer = funded_payer(&rpc);
        let view = overview(&rpc, &payer).unwrap();
        println!("époque {:?}, minimum {}, réserve {}, comptes {}", view.epoch, view.min_delegation, view.rent_reserve, view.accounts.len());
        let plan = plan_delegate(&rpc, &payer, view.min_delegation, &list[0].vote).unwrap();
        println!("{plan:?}");
        assert!(max_delegation(&rpc, &payer).unwrap() > view.min_delegation);
        // Validator outside the list (the largest one: superminority): refused.
        let biggest = vote_accounts(&rpc).unwrap()["current"].as_array().unwrap().iter().max_by_key(|v| v["activatedStake"].as_u64()).unwrap()["votePubkey"].as_str().unwrap().to_string();
        assert!(plan_delegate(&rpc, &payer, view.min_delegation, &biggest).is_err());
    }

    /// Live: an existing stake account (delegated to the first validator offered) is
    /// reread and decoded. An account delegated during the current epoch has its
    /// creation as its last transaction: "Staking" in its payer's history, a plain
    /// receipt in the stake account's own history (paid by someone else).
    /// `cargo test -- --ignored real_stake_account_and_history --nocapture`
    #[test]
    #[ignore]
    fn real_stake_account_and_history() {
        let rpc = mainnet();
        let vote = validators(&rpc).unwrap()[0].vote.clone();
        let found = rpc
            .call("getProgramAccounts", json!([STAKE_PROGRAM, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0}, "filters": [{"dataSize": 200}, {"memcmp": {"offset": 124, "bytes": vote}}]}]))
            .unwrap();
        let address = found[0]["pubkey"].as_str().unwrap().to_string();
        let state = rpc.multiple_accounts(std::slice::from_ref(&address)).unwrap().pop().flatten().unwrap();
        let parsed = parse(&state.data).unwrap();
        let epoch = epoch_info(&rpc).unwrap().epoch;
        let account = stake_account(&address, &state, &parsed.withdrawer, epoch).unwrap();
        println!("{account:?}");
        assert_eq!(account.validator.as_deref(), Some(vote.as_str()));
        let fresh = rpc
            .call("getProgramAccounts", json!([STAKE_PROGRAM, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0}, "filters": [{"dataSize": 200}, {"memcmp": {"offset": 164, "bytes": bs58::encode(epoch.to_le_bytes()).into_string()}}]}]))
            .unwrap();
        let fresh = fresh[0]["pubkey"].as_str().unwrap();
        let entries = crate::history::sol_history(crate::wallet_flow::SOLANA_MAINNET.rpc, fresh, 1).unwrap();
        println!("{fresh} : {:?}", entries.iter().map(|e| (&e.id[..8], &e.kind, e.net_amount_minor)).collect::<Vec<_>>());
        assert_ne!(entries[0].kind, crate::history::TxKind::Stake);
        let tx = rpc.call("getTransaction", json!([entries[0].id, {"encoding": "json", "maxSupportedTransactionVersion": 0}])).unwrap();
        let payer = tx.pointer("/transaction/message/accountKeys/0").and_then(Value::as_str).unwrap().to_string();
        let payer_entries = crate::history::sol_history(crate::wallet_flow::SOLANA_MAINNET.rpc, &payer, 10).unwrap();
        let creation = payer_entries.iter().find(|e| e.id == entries[0].id);
        println!("payeur {payer} : {:?}", creation.map(|e| (&e.kind, e.net_amount_minor)));
        assert!(creation.is_none() || creation.unwrap().kind == crate::history::TxKind::Stake);
    }

    /// Live: deactivation and withdrawal simulated in a single transaction (creation,
    /// initialization, delegation, deactivation; then creation, initialization, full
    /// withdrawal): formats accepted by the program.
    /// `cargo test -- --ignored real_stake_exit_simulates --nocapture`
    #[test]
    #[ignore]
    fn real_stake_exit_simulates() {
        let rpc = mainnet();
        let payer_text = funded_payer(&rpc);
        let payer = key(&payer_text).unwrap();
        let vote = key(&validators(&rpc).unwrap()[0].vote).unwrap();
        let rent = rpc.minimum_rent_exempt_balance(STAKE_ACCOUNT_SPACE).unwrap();
        let seed = "stake:test-exit";
        let stake = derived_address(&payer, seed);
        let amount = 1_000_000_000;
        let run = |ixs: Vec<Instruction>| {
            let raw = assemble_transaction(&[0u8; 64], &build_message(&payer, &ixs, &[0u8; 32]));
            rpc.simulate_with_account_states(&raw, &[b58(&stake)]).unwrap()
        };
        match run(vec![create_with_seed(&payer, &stake, seed, amount + rent), initialize(&stake, &payer), delegate(&stake, &vote, &payer), deactivate(&stake, &payer)]) {
            SimulationOutcome::Succeeded { post_states } => {
                let parsed = parse(&post_states[0].as_ref().unwrap().data).unwrap();
                let d = parsed.delegation.unwrap();
                assert_eq!(d.activation, d.deactivation);
            }
            SimulationOutcome::Failed { err, logs } => panic!("{err}\n{logs}"),
        }
        match run(vec![create_with_seed(&payer, &stake, seed, amount + rent), initialize(&stake, &payer), withdraw(&stake, &payer, amount + rent)]) {
            SimulationOutcome::Succeeded { post_states } => assert!(post_states[0].as_ref().is_none_or(|a| a.lamports == 0)),
            SimulationOutcome::Failed { err, logs } => panic!("{err}\n{logs}"),
        }
    }
}
