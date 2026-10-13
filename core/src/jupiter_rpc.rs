//! Minimal Jupiter client: swaps within Solana (unlike cross-chain swaps through
//! THORChain, see thorchain_rpc.rs). Jupiter returns a fully built Solana
//! transaction (v0 message, with an address lookup table) rather than instructions
//! for us to assemble. Unlike the rest of this project, we do not rebuild this
//! message by hand: doing it properly would mean resolving the contents of the
//! address lookup tables ourselves (checked empirically: even the simplest route, a
//! single direct market, uses one), an entire new subsystem and a source of errors
//! at least as risky as trusting the transaction Jupiter has already built.
//!
//! The only thing done to this transaction here is signing it. Before that,
//! `verify_fee_payer` checks that the message's first account (the fee payer /
//! first signer) is indeed OUR OWN key: a minimal but real safeguard against a
//! malformed or unexpected response.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Jupiter API free tier, no key required; checked with a real call before being
/// written here (quote + swap-instructions/swap tested live, responses matching
/// what follows).
const JUPITER_BASE: &str = "https://lite-api.jup.ag";

pub const SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Solana address that receives the platform fees of EVERY Jupiter swap made from
/// this app, whichever installation triggers it: a single fixed address (the
/// developer's), not one derived per installation (otherwise every user would be
/// paying themselves). Same principle as `thorchain_rpc::AFFILIATE_ADDRESS`. It is
/// the developer's own Solana address rather than a derived one: unlike THORChain,
/// Solana is a network this app already supports natively, so no extra derivation
/// is needed.
pub const AFFILIATE_ADDRESS: &str = "F1YBYFJWBteTwi5eS5BjdSy3xDGGv8bhHBJ54n78nzdc";

/// 80 basis points = 0.80%. Taken in one of the two swapped tokens (see
/// `fee_mint_candidates`): for an "ExactIn" swap, Jupiter requires the fee account
/// to hold the mint of one of the swap's two assets.
pub const AFFILIATE_FEE_BPS: u32 = 80;

pub struct JupiterQuote {
    /// Raw quote response, passed AS IS to `/swap` (Jupiter expects to receive exactly
    /// the object it returned, not a reconstruction); never modified or rebuilt here.
    raw: Value,
    /// Expected output amount, in the destination asset's smallest unit; extracted only
    /// for display.
    pub out_amount: u64,
    /// Token for the affiliate fee (`None`: fee-free swap, because no fee account
    /// exists for either token, see `api`).
    pub fee_mint: Option<[u8; 32]>,
}

/// "Prop AMM" market makers excluded from quotes: their oracle-based price is only
/// valid for a few blocks ("replay: slot window"). By the time the app had
/// simulated the transaction on its own node the price was stale, and the swap
/// failed on slippage (error 6001, seen on 2026-10-05 with HumidiFi on a real SOL →
/// USDC). Measured cost of the exclusion on SOL → USDC: 0.0003% (Whirlpool,
/// Manifest… routes). Labels from Jupiter (`/swap/v1/program-id-to-label`), with
/// spaces encoded.
const EXCLUDED_DEXES: &str =
    "HumidiFi,SolFi,SolFi%20V2,TesseraV,ZeroFi,GoonFi%20V2,Obric%20V2,AlphaQ,BisonFi,Aquifer";

/// Priority fee cap requested from Jupiter (0.001 SOL), see
/// `build_swap_transaction`; also set aside by a swap's "Max" (`api::swap_max`).
pub const PRIORITY_FEE_MAX_LAMPORTS: u64 = 1_000_000;

/// `amount` in the source asset's smallest unit (lamports for SOL, micro-USDC for
/// USDC). `slippage_bps`: price slippage tolerance, in basis points (e.g. 50 = 0.50%).
/// `fee_mint`: the token whose affiliate fee account will receive the 0.80% (it must
/// exist, see `fee_mint_candidates`); `None`: no fee.
pub fn quote(
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u32,
    fee_mint: Option<[u8; 32]>,
) -> Result<JupiterQuote> {
    quote_with_fee(
        input_mint,
        output_mint,
        amount,
        slippage_bps,
        fee_mint,
        AFFILIATE_FEE_BPS,
    )
}

/// Like `quote`, at the rate `fee_bps` (liquid staking: lower, see
/// `swap_routes::staking_fee_bps`). A zero rate means no fee account.
pub fn quote_with_fee(
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u32,
    fee_mint: Option<[u8; 32]>,
    fee_bps: u32,
) -> Result<JupiterQuote> {
    let fee_mint = fee_mint.filter(|_| fee_bps > 0);
    let fee = if fee_mint.is_some() {
        format!("&platformFeeBps={fee_bps}")
    } else {
        String::new()
    };
    let url = format!("{JUPITER_BASE}/swap/v1/quote?inputMint={input_mint}&outputMint={output_mint}&amount={amount}&slippageBps={slippage_bps}{fee}&excludeDexes={EXCLUDED_DEXES}");
    let raw: Value = shared_client()
        .get(&url)
        .send()
        .context("requête de devis Jupiter impossible")?
        .json()
        .context("réponse de devis Jupiter illisible")?;

    if let Some(error) = raw.get("error").and_then(Value::as_str) {
        anyhow::bail!("devis Jupiter refusé : {error}");
    }

    let out_amount = raw
        .get("outAmount")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("devis Jupiter sans montant de sortie"))?
        .parse::<u64>()
        .context("montant de sortie Jupiter illisible")?;

    Ok(JupiterQuote {
        raw,
        out_amount,
        fee_mint,
    })
}

/// Possible fee accounts for a swap, in order of preference: the token received,
/// then the token sold. Jupiter requires an EXISTING fee account for one of the two
/// swapped tokens (seen in practice: a USDC account made SOL → USDT fail with
/// "Account not associated with this Mint", and a missing account fails with 6025
/// "InvalidTokenAccount"). Never in native SOL.
pub fn fee_mint_candidates(input_mint: &str, output_mint: &str) -> Vec<[u8; 32]> {
    [output_mint, input_mint]
        .into_iter()
        .filter(|mint| *mint != SOL_MINT)
        .filter_map(|mint| {
            bs58::decode(mint)
                .into_vec()
                .ok()
                .and_then(|v| v.try_into().ok())
        })
        .collect()
}

/// Token program of a mint for its fee account: Token-2022 for the registry's
/// xStocks, the classic program otherwise.
pub fn fee_token_program(mint: &[u8; 32]) -> [u8; 32] {
    let token_2022 = crate::tokens::TOKENS.iter().flat_map(|t| t.deployments).any(|d| {
        matches!(d.kind, crate::tokens::TokenKind::Spl2022 { mint: m } if bs58::decode(m).into_vec().ok().as_deref() == Some(mint.as_slice()))
    });
    if token_2022 {
        crate::sol_spl::token_2022_program_id()
    } else {
        crate::sol_spl::token_program_id()
    }
}

/// Fee account (associated account of `AFFILIATE_ADDRESS`, under the right program)
/// for the token `mint`.
pub fn fee_account(mint: &[u8; 32]) -> Result<[u8; 32]> {
    let owner: [u8; 32] = bs58::decode(AFFILIATE_ADDRESS)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("adresse d'affiliation Jupiter mal formée (bug de compilation)")?;
    Ok(crate::sol_spl::find_associated_token_address_for(
        &owner,
        mint,
        &fee_token_program(mint),
    ))
}

#[derive(Deserialize)]
struct SwapResponseJson {
    #[serde(rename = "swapTransaction")]
    swap_transaction: Option<String>,
    error: Option<String>,
}

/// Builds the swap transaction (still UNSIGNED, signature slot zeroed); see the
/// module docs: never rebuilt by hand, only signed as is after checking the fee
/// payer.
pub fn build_swap_transaction(quote: &JupiterQuote, user_pubkey: &str) -> Result<Vec<u8>> {
    // Fee account: the one for the token chosen at quote time (see
    // `fee_mint_candidates`); none for a fee-free quote.
    let mut body = serde_json::json!({
        "quoteResponse": quote.raw,
        "userPublicKey": user_pubkey,
        // Automatically wraps/unwraps native SOL into wSOL for the duration of the swap
        // (required to swap from/to native SOL, which is not itself an SPL token). This is
        // Jupiter's default behavior, made explicit here so we do not depend on an
        // implicit value.
        "wrapAndUnwrapSol": true,
        // Priority fee capped explicitly (1,000,000 lamports, i.e. 0.001 SOL) rather than
        // left to Jupiter's automatic choice: the effects check before signing
        // (`api::check_swap_effects`) refuses any loss beyond the amount + a fixed fee
        // budget, and without a cap, network congestion could push Jupiter past that
        // budget and cause legitimate refusals.
        "prioritizationFeeLamports": {
            // "medium" and not "high": measured live, "high" pushed the real cost to ~915,000
            // lamports versus ~25,000-105,000 by default. The goal is a CAP, not paying more.
            "priorityLevelWithMaxLamports": { "maxLamports": PRIORITY_FEE_MAX_LAMPORTS, "priorityLevel": "medium" }
        },
    });
    if let Some(mint) = quote.fee_mint {
        body["feeAccount"] = Value::String(bs58::encode(fee_account(&mint)?).into_string());
    }
    let response: SwapResponseJson = shared_client()
        .post(format!("{JUPITER_BASE}/swap/v1/swap"))
        .json(&body)
        .send()
        .context("requête de construction de swap Jupiter impossible")?
        .json()
        .context("réponse de swap Jupiter illisible")?;

    if let Some(error) = response.error {
        anyhow::bail!("construction du swap Jupiter refusée : {error}");
    }
    let swap_transaction = response
        .swap_transaction
        .ok_or_else(|| anyhow!("réponse de swap Jupiter sans transaction"))?;
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, swap_transaction)
        .context("transaction Jupiter illisible (base64 invalide)")
}

/// Reads a "compact-u16" (shortvec) integer as used by the Solana message format;
/// the reading counterpart of `sol_tx::write_shortvec_len` (which only writes).
/// Needed here to locate the message's first account (the fee payer) without
/// deserializing everything.
fn read_shortvec_len(bytes: &[u8]) -> Result<(usize, usize)> {
    let mut len = 0usize;
    let mut shift = 0u32;
    for (i, &byte) in bytes.iter().enumerate().take(3) {
        len |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((len, i + 1));
        }
        shift += 7;
    }
    Err(anyhow!("longueur shortvec illisible"))
}

/// Splits a raw Solana transaction (unsigned, a single signature slot) into
/// (message start offset, borrowed message). Rejects any transaction asking for
/// more than one signer: this project never builds multi-signer swaps, such a
/// response would be unexpected, and failing loudly is better than guessing what to
/// do.
pub(crate) fn split_single_signer_transaction(raw_tx: &[u8]) -> Result<(usize, &[u8])> {
    let (sig_count, consumed) = read_shortvec_len(raw_tx)?;
    anyhow::ensure!(
        sig_count == 1,
        "transaction Jupiter à {sig_count} signataires, un seul attendu"
    );
    let message_start = consumed + 64 * sig_count;
    anyhow::ensure!(raw_tx.len() > message_start, "transaction Jupiter tronquée");
    Ok((message_start, &raw_tx[message_start..]))
}

/// The message's first account = the fee payer (and the only expected signer, see
/// `split_single_signer_transaction`), checked to be OUR OWN key before any
/// signature (see the module docs).
pub(crate) fn message_fee_payer(message: &[u8]) -> Result<[u8; 32]> {
    // Versioned message (v0): the first byte has its high bit set (impossible for a
    // "legacy" message, where that same byte is `num_required_signatures`, always
    // small). The header (3 bytes) follows immediately, preceded by the version byte
    // in this case.
    let header_start = if message.first().is_some_and(|b| b & 0x80 != 0) {
        1
    } else {
        0
    };
    anyhow::ensure!(
        message.len() > header_start + 3,
        "message Jupiter tronqué (en-tête)"
    );
    let account_keys_start = header_start + 3;
    let (_count, consumed) = read_shortvec_len(&message[account_keys_start..])?;
    let fee_payer_start = account_keys_start + consumed;
    anyhow::ensure!(
        message.len() >= fee_payer_start + 32,
        "message Jupiter tronqué (payeur de frais)"
    );
    let mut fee_payer = [0u8; 32];
    fee_payer.copy_from_slice(&message[fee_payer_start..fee_payer_start + 32]);
    Ok(fee_payer)
}

/// Accounts a Solana message can MODIFY: the runtime forbids a transaction (and any
/// CPI it triggers) from touching an account it does not declare writable. Knowing
/// this set is therefore enough to bound everything a transaction built by a third
/// party could do to the user's accounts (see `api::verify_swap_effects`).
pub struct WritableAccounts {
    /// Writable static keys, already resolved.
    pub static_keys: Vec<[u8; 32]>,
    /// Address lookup tables (v0 message): table address + writable indexes, to be
    /// resolved on-chain (never by trusting the third party that built the
    /// transaction).
    pub lookups: Vec<([u8; 32], Vec<u8>)>,
    /// `true` if the first instruction is `AdvanceNonceAccount` (system program,
    /// discriminator 4): the transaction then relies on a "durable nonce" instead of a
    /// recent blockhash, and stays valid INDEFINITELY, replayable much later at a much
    /// worse price. A real Jupiter swap never uses one.
    pub advances_durable_nonce: bool,
}

/// Bounded reader: a message coming from a third party must never be able to cause
/// a panic through an out-of-bounds index.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow!("message Jupiter : longueur invalide"))?;
        anyhow::ensure!(end <= self.bytes.len(), "message Jupiter tronqué");
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn shortvec(&mut self) -> Result<usize> {
        let (len, consumed) = read_shortvec_len(&self.bytes[self.pos.min(self.bytes.len())..])?;
        self.pos += consumed;
        Ok(len)
    }
    fn key(&mut self) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        key.copy_from_slice(self.take(32)?);
        Ok(key)
    }
}

/// Full parse of a Solana message (legacy or v0) to extract its writable accounts;
/// see `WritableAccounts`. Writability rules for static keys, from the message
/// header: among the first `num_required_signatures` keys, the last
/// `num_readonly_signed` are read-only; among the following ones, the last
/// `num_readonly_unsigned` are too.
pub fn message_writable_accounts(message: &[u8]) -> Result<WritableAccounts> {
    let mut r = Reader {
        bytes: message,
        pos: 0,
    };
    let versioned = message.first().is_some_and(|b| b & 0x80 != 0);
    if versioned {
        let version = r.u8()? & 0x7f;
        anyhow::ensure!(
            version == 0,
            "version de message Solana non prise en charge : {version}"
        );
    }
    let num_signed = r.u8()? as usize;
    let num_ro_signed = r.u8()? as usize;
    let num_ro_unsigned = r.u8()? as usize;
    let count = r.shortvec()?;
    let keys: Vec<[u8; 32]> = (0..count).map(|_| r.key()).collect::<Result<_>>()?;
    anyhow::ensure!(
        num_signed <= count && num_ro_signed <= num_signed && num_ro_unsigned <= count - num_signed,
        "en-tête de message Solana incohérent"
    );
    let static_keys = keys
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            if *i < num_signed {
                *i < num_signed - num_ro_signed
            } else {
                *i < count - num_ro_unsigned
            }
        })
        .map(|(_, k)| *k)
        .collect();

    r.take(32)?; // recent blockhash
    let instruction_count = r.shortvec()?;
    let mut advances_durable_nonce = false;
    for i in 0..instruction_count {
        // Program IDs are ALWAYS static keys (the v0 format forbids loading them from a
        // lookup table).
        let program_index = r.u8()? as usize;
        let accounts_len = r.shortvec()?;
        r.take(accounts_len)?;
        let data_len = r.shortvec()?;
        let data = r.take(data_len)?;
        if i == 0 {
            let program = keys
                .get(program_index)
                .ok_or_else(|| anyhow!("message Solana : index de programme invalide"))?;
            advances_durable_nonce = *program == [0u8; 32] && data.starts_with(&[4, 0, 0, 0]);
        }
    }

    let mut lookups = Vec::new();
    if versioned {
        let lookup_count = r.shortvec()?;
        for _ in 0..lookup_count {
            let table = r.key()?;
            let writable_len = r.shortvec()?;
            let writable = r.take(writable_len)?.to_vec();
            let readonly_len = r.shortvec()?;
            r.take(readonly_len)?;
            lookups.push((table, writable));
        }
    }
    anyhow::ensure!(
        r.pos == message.len(),
        "message Solana avec des octets en trop"
    );
    Ok(WritableAccounts {
        static_keys,
        lookups,
        advances_durable_nonce,
    })
}

/// Splits a raw transaction and returns its message (see
/// `split_single_signer_transaction`).
pub fn transaction_message(raw_tx: &[u8]) -> Result<&[u8]> {
    split_single_signer_transaction(raw_tx).map(|(_, message)| message)
}

/// Replaces the recent blockhash of a single-signer transaction with `blockhash`,
/// read from OUR node just before signing. The one chosen by the third party that
/// built the transaction may expire before sending (measured on 2026-10-02: ~35 s
/// of validity for a LI.FI transaction, less than unlocking + simulating after
/// confirmation → "BlockhashNotFound") or be unknown to our node. No effect on the
/// instructions; refused for a durable nonce (where the "blockhash" is the nonce
/// value).
pub fn with_recent_blockhash(raw_tx: &[u8], blockhash: &[u8; 32]) -> Result<Vec<u8>> {
    let (message_start, message) = split_single_signer_transaction(raw_tx)?;
    anyhow::ensure!(
        !message_writable_accounts(message)?.advances_durable_nonce,
        "transaction à nonce durable : blockhash non remplaçable"
    );
    let header_start = if message.first().is_some_and(|b| b & 0x80 != 0) {
        1
    } else {
        0
    };
    let keys_start = header_start + 3;
    anyhow::ensure!(
        message.len() > keys_start,
        "message Solana tronqué (en-tête)"
    );
    let (count, consumed) = read_shortvec_len(&message[keys_start..])?;
    let start = message_start + keys_start + consumed + 32 * count;
    anyhow::ensure!(
        raw_tx.len() >= start + 32,
        "message Solana tronqué (blockhash)"
    );
    let mut out = raw_tx.to_vec();
    out[start..start + 32].copy_from_slice(blockhash);
    Ok(out)
}

/// Signs a Jupiter transaction (see `build_swap_transaction`) after checking that
/// its fee payer is indeed `expected_signer`; refuses to sign otherwise, rather
/// than blindly trusting a third-party transaction.
pub fn sign_swap_transaction(
    raw_tx: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    expected_signer: &[u8; 32],
) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;

    let (message_start, message) = split_single_signer_transaction(raw_tx)?;
    let fee_payer = message_fee_payer(message)?;
    anyhow::ensure!(
        &fee_payer == expected_signer,
        "la transaction Jupiter attend un payeur de frais différent du portefeuille actuel — refus de signer"
    );

    let signature = signing_key.sign(message);
    let mut signed = raw_tx.to_vec();
    signed[1..message_start].copy_from_slice(&signature.to_bytes());
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Does not guarantee the address is correct (only a check against a reference
    /// wallet would); a minimal guard against accidental corruption of the constant
    /// (wrong length, characters outside the base58 alphabet).
    #[test]
    fn affiliate_address_has_the_expected_base58_shape() {
        let bytes = bs58::decode(AFFILIATE_ADDRESS)
            .into_vec()
            .expect("base58 valide");
        assert_eq!(bytes.len(), 32, "une adresse Solana fait 32 octets");
    }

    /// Minimal legacy message: header [1 signer, 0, 1 unsigned read-only], keys [user,
    /// system program], blockhash, 1 instruction.
    fn legacy_message_with_first_instruction(data: &[u8]) -> Vec<u8> {
        let mut m = vec![1, 0, 1, 2];
        m.extend_from_slice(&[7u8; 32]); // user (writable, signer)
        m.extend_from_slice(&[0u8; 32]); // system program (read-only)
        m.extend_from_slice(&[9u8; 32]); // blockhash
        m.push(1); // 1 instruction
        m.push(1); // program = key no. 1 (system)
        m.push(1); // 1 account
        m.push(0);
        m.push(data.len() as u8);
        m.extend_from_slice(data);
        m
    }

    #[test]
    fn message_writable_accounts_parses_writability_and_detects_durable_nonces() {
        let nonce =
            message_writable_accounts(&legacy_message_with_first_instruction(&[4, 0, 0, 0]))
                .unwrap();
        assert!(
            nonce.advances_durable_nonce,
            "AdvanceNonceAccount (discriminant 4) doit être détecté"
        );
        assert_eq!(
            nonce.static_keys,
            vec![[7u8; 32]],
            "seul l'utilisateur est inscriptible ici"
        );
        assert!(
            nonce.lookups.is_empty(),
            "un message legacy n'a pas de table de correspondance"
        );

        let transfer = message_writable_accounts(&legacy_message_with_first_instruction(&[
            2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ]))
        .unwrap();
        assert!(
            !transfer.advances_durable_nonce,
            "un simple transfert n'est pas un nonce durable"
        );

        // Truncated message: a clean error, never a panic.
        let mut truncated = legacy_message_with_first_instruction(&[4, 0, 0, 0]);
        truncated.truncate(truncated.len() - 3);
        assert!(message_writable_accounts(&truncated).is_err());
    }

    /// Blockhash replaced at its exact position (legacy message, then v0), nothing else
    /// moves; refused for a durable nonce.
    #[test]
    fn with_recent_blockhash_replaces_only_the_blockhash() {
        let tx = |message: &[u8]| [&[1u8][..], &[0u8; 64], message].concat();
        let transfer = legacy_message_with_first_instruction(&[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let fresh = [5u8; 32];
        let legacy = tx(&transfer);
        let replaced = with_recent_blockhash(&legacy, &fresh).unwrap();
        let start = 1 + 64 + 4 + 2 * 32; // signature, header + key count, 2 keys
        assert_eq!(replaced[start..start + 32], fresh);
        assert_eq!(
            (&replaced[..start], &replaced[start + 32..]),
            (&legacy[..start], &legacy[start + 32..])
        );
        // v0: version byte first, no lookup table at the end.
        let v0 = tx(&[&[0x80u8][..], &transfer, &[0]].concat());
        let replaced = with_recent_blockhash(&v0, &fresh).unwrap();
        assert_eq!(replaced[start + 1..start + 33], fresh);
        assert_eq!(
            (&replaced[..start + 1], &replaced[start + 33..]),
            (&v0[..start + 1], &v0[start + 33..])
        );
        assert!(
            with_recent_blockhash(
                &tx(&legacy_message_with_first_instruction(&[4, 0, 0, 0])),
                &fresh
            )
            .is_err(),
            "nonce durable"
        );
    }

    #[test]
    fn read_shortvec_len_matches_write_shortvec_len_round_trip() {
        for len in [0usize, 1, 127, 128, 300, 16384] {
            let mut buf = Vec::new();
            crate::sol_tx::write_shortvec_len(&mut buf, len);
            let (decoded, consumed) = read_shortvec_len(&buf).unwrap();
            assert_eq!(decoded, len);
            assert_eq!(consumed, buf.len());
        }
    }

    /// End-to-end check against the real API (read-only for the quote/build; no signing
    /// or broadcasting here). Ignored by default:
    /// `cargo test -- --ignored jupiter_quote_and_build_match_the_real_network`
    #[test]
    #[ignore]
    fn jupiter_quote_and_build_match_the_real_network() {
        // A known public wallet (already used to check the USDC ATA derivation elsewhere
        // in this project): read-only, no risk.
        let owner = "E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk";
        let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let q = quote(SOL_MINT, usdc_mint, 100_000_000, 50, None).expect("devis réel");
        assert!(q.out_amount > 0);

        let raw_tx = build_swap_transaction(&q, owner).expect("construction réelle");
        let (message_start, message) =
            split_single_signer_transaction(&raw_tx).expect("découpage de la transaction");
        assert_eq!(
            message_start, 65,
            "un seul signataire attendu (1 + 64 octets)"
        );
        let fee_payer = message_fee_payer(message).expect("payeur de frais lisible");
        let owner_bytes: [u8; 32] = bs58::decode(owner).into_vec().unwrap().try_into().unwrap();
        assert_eq!(
            fee_payer, owner_bytes,
            "le payeur de frais doit être le compte demandé"
        );
    }
}
