//! MoonPay Trade (the swaps.xyz API, from Decent.xyz, acquired by MoonPay): one
//! more swap provider in "Convert", non-custodial (the transaction is signed by the
//! app; MoonPay never holds the funds).
//!
//! Two kinds of routes (product decision, 2026-10-07):
//! - **same EVM network**: a call to the "UTB" router (the same contract on every
//!   network: identical code, verified source, not upgradeable, as recorded on
//!   2026-10-07), SIMULATED before signing: only the token sold leaves the user,
//!   for the exact amount; the token bought lands on THEIR address, at least the
//!   guaranteed minimum. Offered as one more option;
//! - **deposit** (to another network): an ordinary transfer, built and signed by
//!   the app, to a deposit address provided by MoonPay Trade. What happens next
//!   (delivery on the other network) is handled by the provider: the app CANNOT
//!   verify the final recipient. Only offered if no other provider connects the
//!   pair, and stated in the confirmation dialog.
//!
//! App commission: 0.80% (like LI.FI), requested in every quote from an EVM
//! network; a quote announcing more is refused.
//!
//! API key (console.swaps.xyz) read at build time (`partner-keys.env`, see
//! build.rs). A MoonPay widget key (`pk_…`, `sk_…`) is not a Trade key: it is
//! ignored, and MoonPay Trade is not offered.

use crate::{evm_sign, external_wallets, tokens, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::Value;
use std::sync::OnceLock;

const API_BASE: &str = "https://api-v2.swaps.xyz/api";
/// Key read at build time; only used if `enabled()` (Trade key).
pub const API_KEY: Option<&str> = option_env!("MOONPAY_TRADE_API_KEY");
/// The app's commission (basis points), paid to CoW's partner fee address (the
/// developer's address, see `cow`).
pub const FEE_BPS: u32 = 80;
const FEE_RECEIVER: &str = "0xae702daEd4723ac516492Bb1084F50e07e75573C";
/// MoonPay's own fee on the app's key (recorded on 2026-10-07: 0.30%), on top of
/// the commission; shown in the list of providers. The exact amount for each quote
/// is read from the quote.
pub const PROTOCOL_FEE_BPS: u32 = 30;
/// Above this, the quote is refused (abnormal MoonPay fees).
const MAX_PROTOCOL_FEE_BPS: u32 = 100;
/// Tolerated slippage (basis points), guaranteed by the minimum amount received.
const SLIPPAGE_BPS: u32 = 100;
/// Identifier for native coins at MoonPay Trade (all networks).
const NATIVE: &str = "0x0000000000000000000000000000000000000000";
const SOLANA_CHAIN: u64 = 1_399_811_149;

pub fn enabled() -> bool {
    key().is_some()
}

fn key() -> Option<&'static str> {
    API_KEY.filter(|k| !k.starts_with("pk_") && !k.starts_with("sk_"))
}

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

// --- Cryptos ------------------------------------------------------------------------------

/// Native coins: (card, network, MoonPay Trade chain ID, decimals, symbol). IDs and
/// decimals recorded from `getChainList` / `getTokenList` on 2026-10-07.
const NATIVES: [(&str, &str, u64, u8, &str); 17] = [
    ("evm", "evm_mainnet", 1, 18, "ETH"),
    ("evm", "arbitrum_mainnet", 42161, 18, "ETH"),
    ("evm", "base_mainnet", 8453, 18, "ETH"),
    ("bnb", "bsc_mainnet", 56, 18, "BNB"),
    ("avax", "avax_mainnet", 43114, 18, "AVAX"),
    ("pol", "polygon_mainnet", 137, 18, "POL"),
    ("sol", "sol_mainnet", SOLANA_CHAIN, 9, "SOL"),
    ("btc", "btc_mainnet", 999_000_313, 8, "BTC"),
    ("doge", "doge_mainnet", 2000, 8, "DOGE"),
    ("zec", "zec_mainnet", 999_000_322, 8, "ZEC"),
    ("trx", "tron_mainnet", 728_126_428, 6, "TRX"),
    ("xrp", "xrp_mainnet", 999_000_346, 6, "XRP"),
    ("xlm", "xlm_mainnet", 999_000_338, 7, "XLM"),
    ("near", "near_mainnet", 397, 24, "NEAR"),
    ("ada", "ada_mainnet", 1816, 6, "ADA"),
    ("stx", "stx_mainnet", 999_000_351, 6, "STX"),
    ("xmr", "xmr_mainnet", 999_000_343, 12, "XMR"),
];

/// Networks from which the app can make a MoonPay Trade deposit (ordinary transfer,
/// memo included for XRP); the others are receive-only.
const DEPOSIT_SOURCES: [&str; 12] = [
    "evm_mainnet",
    "arbitrum_mainnet",
    "base_mainnet",
    "bsc_mainnet",
    "avax_mainnet",
    "polygon_mainnet",
    "btc_mainnet",
    "doge_mainnet",
    "zec_mainnet",
    "xrp_mainnet",
    "ada_mainnet",
    "near_mainnet",
];

/// MoonPay Trade's UTB router on each of the app's EVM networks: recorded from real
/// quotes on 2026-10-07, the same code deployed everywhere (identical code hash),
/// verified "UTB" source (Blockscout, Routescan), no proxy.
pub fn router(network: &str) -> Option<&'static str> {
    Some(match network {
        "evm_mainnet" => "0x1b6257CAE4192e62B629eFCa21771be3D759183D",
        "arbitrum_mainnet" => "0x5813877Cdda5F0f56EeaB9326A42804A09e2CD8c",
        "base_mainnet" => "0x0929222bC7Cc533aecC1ccFe9d9Bd6ecbB0CBF43",
        "bsc_mainnet" => "0x39B1F7c5b1ae6a3Cb9bbbd616B44ceD9F53882E0",
        "polygon_mainnet" => "0x38630c8ec92494CF96ded12060d8136B75e7a8b5",
        "avax_mainnet" => "0x0eb3c930944951876E2E7Be8B8fE4759FFd6fb44",
        _ => return None,
    })
}

fn is_evm(network: &str) -> bool {
    router(network).is_some()
}

/// One of the app's cryptos, as MoonPay Trade designates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub coin: &'static str,
    pub network: &'static str,
    pub chain: u64,
    /// Contract (EVM, lowercase), mint (Solana) or `NATIVE`.
    pub token: &'static str,
    pub decimals: u8,
    pub symbol: &'static str,
    pub native: bool,
}

pub fn asset(coin: &str, network: &str) -> Option<Asset> {
    if let Some(&(coin, network, chain, decimals, symbol)) =
        NATIVES.iter().find(|n| n.0 == coin && n.1 == network)
    {
        return Some(Asset {
            coin,
            network,
            chain,
            token: NATIVE,
            decimals,
            symbol,
            native: true,
        });
    }
    let (token, deployment) = tokens::find(coin, network)?;
    let address = match deployment.kind {
        tokens::TokenKind::Erc20 { contract } if is_evm(network) => contract,
        tokens::TokenKind::Spl { mint } if network == "sol_mainnet" => mint,
        _ => return None,
    };
    let chain = NATIVES.iter().find(|n| n.1 == network)?.2;
    Some(Asset {
        coin: token.id,
        network: deployment.network,
        chain,
        token: address,
        decimals: deployment.decimals,
        symbol: token.symbol,
        native: false,
    })
}

pub fn tradable() -> Vec<(&'static str, &'static str)> {
    let natives = NATIVES.iter().map(|n| (n.0, n.1));
    let registry = tokens::TOKENS.iter().flat_map(|t| {
        t.deployments
            .iter()
            .filter(|d| asset(t.id, d.network).is_some())
            .map(move |d| (t.id, d.network))
    });
    natives.chain(registry).collect()
}

/// A route with a verifiable recipient: same EVM network (simulated router), on a
/// network whose node can simulate (not Avalanche: no `eth_simulateV1`, recorded on
/// 2026-10-08; audit round 32).
pub fn verifiable(from: (&str, &str), to: (&str, &str)) -> bool {
    from.1 == to.1 && is_evm(from.1) && crate::lifi::simulates(from.1)
}

/// Does MoonPay Trade connect these two cryptos (ignoring activation and the
/// last-resort rule, which `swap_routes` applies)?
pub fn links(from: (&str, &str), to: (&str, &str)) -> bool {
    from != to
        && asset(from.0, from.1).is_some()
        && asset(to.0, to.1).is_some()
        && (verifiable(from, to) || (from.1 != to.1 && DEPOSIT_SOURCES.contains(&from.1)))
}

// --- Quotes -------------------------------------------------------------------------------

/// Transaction from a verified quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TradeTx {
    /// A call to the UTB router (same EVM network), simulated before signing
    /// (`verify_router`). `value`: the amount sold if it is the network's native coin,
    /// 0 otherwise (the token sold is approved for the router, for the exact amount).
    Router {
        router: [u8; 20],
        data: Vec<u8>,
        value: u128,
    },
    /// Deposit: an ordinary transfer of the exact amount to `address` (memo: XRP
    /// destination tag), built and signed by the app.
    Deposit {
        address: String,
        memo: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct Quote {
    /// MoonPay Trade identifier (deposit registration, tracking).
    pub tx_id: String,
    pub amount: u128,
    pub expected_out: u128,
    pub min_out: u128,
    pub duration_secs: u64,
    /// MoonPay's own fee announced by the quote (basis points of the amount sold,
    /// rounded), on top of the app's commission.
    pub protocol_fee_bps: u32,
    /// Deposit to register after broadcasting (`register`).
    pub register: bool,
    pub tx: TradeTx,
}

/// Quote error returned by MoonPay Trade, in plain words.
fn api_error(body: &Value, status: u16) -> anyhow::Error {
    let error = &body["error"];
    let details = &error["details"];
    match error["code"].as_str() {
        Some(
            "NO_AVAILABLE_ROUTE"
            | "UNSUPPORTED_NETWORK"
            | "UNSUPPORTED_NETWORK_PAIR"
            | "UNSUPPORTED_NETWORK_TOKEN_PAIR"
            | "INSUFFICIENT_LIQUIDITY",
        ) => {
            anyhow!("MoonPay Trade ne propose pas d'échange pour cette paire en ce moment")
        }
        Some("AMOUNT_TOO_LOW") => match details["minAmount"].as_str() {
            Some(min)
                if min.len() <= 40 && min.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
            {
                anyhow!("montant trop faible pour MoonPay Trade (minimum {min})")
            }
            _ => anyhow!("montant trop faible pour MoonPay Trade"),
        },
        Some("AMOUNT_TOO_HIGH") => anyhow!("montant trop élevé pour MoonPay Trade"),
        Some("GEO_BLOCKED") => anyhow!("MoonPay Trade n'est pas disponible dans votre pays"),
        Some("WALLET_SCREENED") => {
            anyhow!("adresse refusée par le contrôle de conformité de MoonPay Trade")
        }
        Some("INVALID_ADDRESS_FORMAT") => anyhow!("adresse refusée par MoonPay Trade (format)"),
        Some("INVALID_API_KEY" | "MISSING_API_KEY" | "FORBIDDEN_API_KEY") => {
            anyhow!("clé MoonPay Trade refusée")
        }
        _ => anyhow!("MoonPay Trade : réponse {status}"),
    }
}

/// Payment (`amountIn`, `amountOut`…): (chain, token, amount).
fn payment(value: &Value, what: &str) -> Result<(u64, String, u128)> {
    let chain = value["chainId"]
        .as_u64()
        .with_context(|| format!("devis MoonPay Trade illisible ({what})"))?;
    let token = value["address"]
        .as_str()
        .with_context(|| format!("devis MoonPay Trade illisible ({what})"))?
        .to_string();
    let amount = match &value["amount"] {
        Value::String(text) => text.parse::<u128>().ok(),
        other => other.as_u64().map(u128::from),
    }
    .with_context(|| format!("devis MoonPay Trade illisible ({what})"))?;
    Ok((chain, token, amount))
}

fn same_token(asset: &Asset, token: &str) -> bool {
    if is_evm(asset.network) || asset.native {
        asset.token.eq_ignore_ascii_case(token)
    } else {
        asset.token == token
    }
}

fn hex_data(text: &str) -> Result<Vec<u8>> {
    hex::decode(text.trim_start_matches("0x")).context("devis MoonPay Trade illisible (données)")
}

fn amount_value(value: &Value) -> Option<u128> {
    match value {
        Value::String(text) => text.parse().ok(),
        Value::Null => Some(0),
        other => other.as_u64().map(u128::from),
    }
}

/// Is `value` one of the 32-byte words in a call's arguments?
fn contains_word(args: &[u8], value: u128) -> bool {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    args.as_chunks::<32>().0.contains(&word)
}

/// ERC-20 call `transfer(to, amount)`.
pub fn erc20_transfer_data(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

/// Fee `field` (`applicationFee`, `protocolFee`) in basis points of the amount
/// sold: exact if counted in the crypto sold, otherwise derived from the quote's
/// dollar amounts. `None`: no fee.
fn fee_bps(body: &Value, field: &str, from: &Asset, amount: u128) -> Result<Option<f64>> {
    if !body[field].is_object() {
        return Ok(None);
    }
    let (chain, token, fee) = payment(&body[field], "commission")?;
    if chain == from.chain && same_token(from, &token) {
        ensure!(amount > 0, "montant nul");
        return Ok(Some(fee as f64 * 10_000.0 / amount as f64));
    }
    if fee == 0 {
        return Ok(Some(0.0));
    }
    match (
        body[field]["usdAmount"].as_f64(),
        body["amountIn"]["usdAmount"].as_f64(),
    ) {
        (Some(fee_usd), Some(sold_usd)) if sold_usd > 0.0 && fee_usd >= 0.0 => {
            Ok(Some(fee_usd * 10_000.0 / sold_usd))
        }
        _ => bail!("devis MoonPay Trade illisible (commission)"),
    }
}

/// Reads and checks the `getAction` response against the request made: pair, exact
/// amount, minimum ≤ expected, commission ≤ `FEE_BPS`, and a transaction of the
/// expected shape for the route (UTB router on the same EVM network, otherwise a
/// deposit transfer). Pure function.
pub fn parse_action(body: &Value, from: &Asset, to: &Asset, amount: u128) -> Result<Quote> {
    let (chain, token, amount_in) = payment(&body["amountIn"], "montant vendu")?;
    ensure!(
        chain == from.chain && same_token(from, &token),
        "le devis MoonPay Trade vend une autre crypto — refus"
    );
    ensure!(
        amount_in == amount,
        "le devis MoonPay Trade porte sur un autre montant — refus"
    );
    let (chain, token, expected_out) = payment(&body["amountOut"], "montant reçu")?;
    ensure!(
        chain == to.chain && same_token(to, &token),
        "le devis MoonPay Trade livre une autre crypto — refus"
    );
    let (chain, token, min_out) = payment(&body["amountOutMin"], "minimum reçu")?;
    ensure!(
        chain == to.chain && same_token(to, &token),
        "le devis MoonPay Trade livre une autre crypto — refus"
    );
    ensure!(
        min_out > 0 && min_out <= expected_out,
        "minimum de réception MoonPay Trade incohérent — refus"
    );
    // App commission: at most `FEE_BPS` of the amount sold; MoonPay's own fee: at most
    // `MAX_PROTOCOL_FEE_BPS` (shown to the user).
    let app_fee = fee_bps(body, "applicationFee", from, amount)?;
    ensure!(
        app_fee.is_none_or(|bps| bps <= f64::from(FEE_BPS) + 0.5),
        "le devis MoonPay Trade prélève une commission supérieure à {:.2} % — refus",
        f64::from(FEE_BPS) / 100.0
    );
    let protocol_fee = fee_bps(body, "protocolFee", from, amount)?.unwrap_or(0.0);
    ensure!(
        protocol_fee <= f64::from(MAX_PROTOCOL_FEE_BPS),
        "le devis MoonPay Trade annonce des frais MoonPay supérieurs à {:.2} % — refus",
        f64::from(MAX_PROTOCOL_FEE_BPS) / 100.0
    );
    ensure!(
        body["executionsType"]
            .as_str()
            .is_none_or(|t| t == "DEFAULT"),
        "devis MoonPay Trade d'une forme non prise en charge — refus"
    );
    let tx_id = body["txId"]
        .as_str()
        .filter(|id| {
            id.len() == 66 && id.starts_with("0x") && id[2..].bytes().all(|b| b.is_ascii_hexdigit())
        })
        .context("devis MoonPay Trade sans identifiant")?;
    let tx = &body["tx"];
    let vm = body["vmId"].as_str().unwrap_or("");
    let tx_chain = tx["chainId"].as_u64();
    let trade_tx = if verifiable((from.coin, from.network), (to.coin, to.network)) {
        ensure!(
            vm == "evm" && tx_chain == Some(from.chain),
            "devis MoonPay Trade d'une forme inattendue — refus"
        );
        let target = tx["to"]
            .as_str()
            .context("devis MoonPay Trade sans destinataire")?;
        let expected_router = router(from.network).expect("réseau EVM");
        ensure!(target.eq_ignore_ascii_case(expected_router), "la transaction MoonPay Trade appelle un autre contrat que son routeur — refus de signer");
        let data = hex_data(tx["data"].as_str().unwrap_or(""))?;
        ensure!(data.len() >= 4, "devis MoonPay Trade sans appel — refus");
        // The minimum shown must be the one the router will enforce
        // (`swapParams.amountOut`, recorded on 2026-10-08 in real transactions);
        // otherwise, refused (audit round 32).
        ensure!(
            contains_word(&data[4..], min_out),
            "la transaction MoonPay Trade ne garantit pas le minimum affiché — refus de signer"
        );
        let value = amount_value(&tx["value"]).context("devis MoonPay Trade illisible (valeur)")?;
        ensure!(
            value == if from.native { amount } else { 0 },
            "la transaction MoonPay Trade enverrait un autre montant — refus de signer"
        );
        TradeTx::Router {
            router: wallet_flow::parse_evm_address(expected_router)?,
            data,
            value,
        }
    } else if is_evm(from.network) {
        ensure!(
            vm == "evm" && tx_chain == Some(from.chain),
            "devis MoonPay Trade d'une forme inattendue — refus"
        );
        let target = tx["to"]
            .as_str()
            .context("devis MoonPay Trade sans destinataire")?;
        let data = hex_data(tx["data"].as_str().unwrap_or("0x"))?;
        let value = amount_value(&tx["value"]).context("devis MoonPay Trade illisible (valeur)")?;
        let deposit = if from.native {
            ensure!(data.is_empty() && value == amount, "le dépôt MoonPay Trade n'est pas un simple virement du montant exact — refus de signer");
            wallet_flow::parse_evm_address(target)?
        } else {
            // Token transfer: `transfer(deposit, exact amount)` on its contract.
            ensure!(
                target.eq_ignore_ascii_case(from.token) && value == 0 && data.len() == 68,
                "le dépôt MoonPay Trade n'est pas un simple virement du jeton — refus de signer"
            );
            let deposit: [u8; 20] = data[16..36].try_into().expect("20 octets");
            ensure!(data == erc20_transfer_data(&deposit, amount), "le dépôt MoonPay Trade n'est pas un simple virement du montant exact — refus de signer");
            deposit
        };
        ensure!(
            deposit != [0u8; 20],
            "adresse de dépôt MoonPay Trade invalide — refus"
        );
        TradeTx::Deposit {
            address: crate::derivation::format_address(&deposit),
            memo: None,
        }
    } else {
        ensure!(
            vm == "alt-vm" && tx_chain == Some(from.chain),
            "devis MoonPay Trade d'une forme inattendue — refus"
        );
        let value = amount_value(&tx["value"]).context("devis MoonPay Trade illisible (valeur)")?;
        ensure!(
            value == amount,
            "le dépôt MoonPay Trade porte sur un autre montant — refus de signer"
        );
        let address = tx["to"]
            .as_str()
            .context("devis MoonPay Trade sans adresse de dépôt")?
            .trim()
            .to_string();
        // An address of a shape the app cannot pay (another network, future SegWit
        // version…): a new quote usually gives a different one. Bitcoin: every standard
        // type (P2SH 3… included, which MoonPay Trade sometimes gives, recorded on
        // 2026-10-07).
        external_wallets::validate_address(from.network, &address).map_err(|_| anyhow!("adresse de dépôt MoonPay Trade d'une forme que l'app ne sait pas payer — demandez un nouveau devis"))?;
        let memo = match tx["toExtra"]
            .as_str()
            .map(str::trim)
            .filter(|m| !m.is_empty())
        {
            None => None,
            // XRP: destination tag (32-bit integer).
            Some(tag) if from.network == "xrp_mainnet" && tag.parse::<u32>().is_ok() => {
                Some(tag.to_string())
            }
            Some(_) => bail!("mémo de dépôt MoonPay Trade non pris en charge — refus"),
        };
        TradeTx::Deposit { address, memo }
    };
    Ok(Quote {
        tx_id: tx_id.to_string(),
        amount,
        expected_out,
        min_out,
        duration_secs: body["estimatedTxTime"]
            .as_f64()
            .filter(|s| s.is_finite() && *s >= 0.0)
            .map(|s| s.ceil() as u64)
            .unwrap_or(0),
        protocol_fee_bps: protocol_fee.round() as u32,
        register: body["requiresRegisterTransaction"]
            .as_bool()
            .unwrap_or(false),
        tx: trade_tx,
    })
}

/// `getAction` parameters. The app's commission is requested on every route, paid
/// to an EVM address (MoonPay Trade requires this even for a Bitcoin or XRP
/// deposit, recorded on 2026-10-07); refunds go to the sender.
fn action_params(
    from: &Asset,
    to: &Asset,
    amount: u128,
    sender: &str,
    recipient: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("actionType", "swap-action".to_string()),
        ("sender", sender.trim().to_string()),
        ("recipient", recipient.trim().to_string()),
        ("refundTo", sender.trim().to_string()),
        ("srcChainId", from.chain.to_string()),
        ("srcToken", from.token.to_string()),
        ("dstChainId", to.chain.to_string()),
        ("dstToken", to.token.to_string()),
        ("slippage", SLIPPAGE_BPS.to_string()),
        ("amount", amount.to_string()),
        ("swapDirection", "exact-amount-in".to_string()),
        (
            "appFees",
            format!("[{{\"bps\":{FEE_BPS},\"receiverAddress\":\"{FEE_RECEIVER}\"}}]"),
        ),
    ]
}

/// Executable MoonPay Trade quote (`getAction`): `sender` sells `amount` of `from`,
/// `recipient` receives `to`; refunds to `sender` (deposit from a non-EVM network).
/// Checked by `parse_action`.
pub fn quote(
    from: &Asset,
    to: &Asset,
    amount: u128,
    sender: &str,
    recipient: &str,
) -> Result<Quote> {
    let key = key().context("MoonPay Trade indisponible dans cette version de l'app")?;
    ensure!(
        links((from.coin, from.network), (to.coin, to.network)),
        "MoonPay Trade ne relie pas ces deux cryptos"
    );
    external_wallets::validate_address(to.network, recipient)?;
    let response = client()
        .get(format!("{API_BASE}/getAction"))
        .header("x-api-key", key)
        .query(&action_params(from, to, amount, sender, recipient))
        .send()
        .map_err(|e| anyhow!("MoonPay Trade injoignable : {}", e.without_url()))?;
    let status = response.status().as_u16();
    let body: Value = response
        .json()
        .context("réponse de MoonPay Trade illisible")?;
    if status != 200 {
        return Err(api_error(&body, status));
    }
    parse_action(&body, from, to, amount)
}

/// Registers a broadcast deposit (required for MoonPay Trade to track it when the
/// quote asks for it).
pub fn register(tx_id: &str, tx_hash: &str) -> Result<()> {
    let key = key().context("MoonPay Trade indisponible dans cette version de l'app")?;
    let response = client()
        .post(format!("{API_BASE}/registerTxs"))
        .header("x-api-key", key)
        .json(&serde_json::json!({ "txId": tx_id, "txHash": tx_hash }))
        .send()
        .map_err(|e| anyhow!("MoonPay Trade injoignable : {}", e.without_url()))?;
    ensure!(
        response.status().is_success(),
        "MoonPay Trade : enregistrement du dépôt refusé ({})",
        response.status().as_u16()
    );
    Ok(())
}

// --- Verifying a swap through the router ---------------------------------------------------

/// What the swap must do, and nothing else.
pub struct Expected {
    pub user: [u8; 20],
    /// Token sold (`None`: the network's native coin).
    pub sell_token: Option<[u8; 20]>,
    pub amount: u128,
    /// Token bought (`None`: the network's native coin).
    pub buy_token: Option<[u8; 20]>,
    pub min_out: u128,
    pub router: [u8; 20],
}

fn word(data: &[u8], index: usize) -> Result<u128> {
    let slot = data
        .get(index * 32..index * 32 + 32)
        .context("événement illisible")?;
    ensure!(slot[..16].iter().all(|b| *b == 0), "montant hors limites");
    Ok(u128::from_be_bytes(
        slot[16..].try_into().expect("16 octets"),
    ))
}

fn padded(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// Checks the simulation (optional approval, then the router call, with native coin
/// movements traced): everything succeeds; only the token sold leaves the user, for
/// the exact amount (approval to the router only, at most the amount); the token
/// bought lands on the user's address, at least the guaranteed minimum. Pure
/// function.
pub fn verify_router(calls: &[crate::eth_rpc::SimulatedCall], expected: &Expected) -> Result<u128> {
    ensure!(
        calls.iter().all(|c| c.success),
        "l'échange MoonPay Trade échouerait (simulation) — rien n'a été envoyé"
    );
    let transfer = evm_sign::keccak(b"Transfer(address,address,uint256)");
    let approval = evm_sign::keccak(b"Approval(address,address,uint256)");
    let approval_for_all = evm_sign::keccak(b"ApprovalForAll(address,address,bool)");
    let native = crate::eth_rpc::NATIVE_TRANSFER_EMITTER;
    let user = padded(&expected.user);
    let sold_token = expected.sell_token.unwrap_or(native);
    let bought_token = expected.buy_token.unwrap_or(native);
    let (mut sent, mut received) = (0u128, 0u128);
    for log in calls.iter().flat_map(|c| &c.logs) {
        let Some(kind) = log.topics.first() else {
            continue;
        };
        if (*kind == transfer || *kind == approval || *kind == approval_for_all)
            && log.topics.get(1) == Some(&user)
        {
            ensure!(
                *kind != approval_for_all && log.topics.len() == 3,
                "l'échange MoonPay Trade toucherait un autre actif de votre portefeuille (NFT ou autorisation globale) — refus de signer"
            );
            ensure!(log.address == sold_token, "l'échange MoonPay Trade ferait sortir une autre crypto de votre portefeuille — refus de signer");
            let value = word(&log.data, 0)?;
            if *kind == transfer {
                sent = sent.checked_add(value).context("montant hors limites")?;
            } else {
                ensure!(
                    log.topics[2] == padded(&expected.router) && value <= expected.amount,
                    "l'échange MoonPay Trade autoriserait un autre contrat ou un autre montant — refus de signer"
                );
            }
        } else if *kind == transfer
            && log.topics.len() == 3
            && log.topics[2] == user
            && log.address == bought_token
        {
            received = received
                .checked_add(word(&log.data, 0)?)
                .context("montant hors limites")?;
        }
    }
    ensure!(
        sent == expected.amount,
        "l'échange MoonPay Trade ferait sortir {sent} unité(s) au lieu de {} — refus de signer",
        expected.amount
    );
    ensure!(
        received >= expected.min_out,
        "l'échange MoonPay Trade livrerait moins que le minimum garanti à votre adresse ({received} au lieu d'au moins {}) — refus de signer",
        expected.min_out
    );
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_rpc::{SimulatedCall, SimulatedLog};
    use serde_json::json;

    /// DEMO key published in the official documentation (docs.swaps.xyz, get-quote
    /// page: "Limited demo key for API Reference"): live tests only, never in the app
    /// (it takes 1% for another integrator).
    const DEMO_KEY: &str = "5c951bc81da566bbd030ba8e20724063";
    const USER: &str = "0x9458af2b720ecf1bb18f525d864a28af5c818cfa";
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    fn a(coin: &str, network: &str) -> Asset {
        asset(coin, network).unwrap()
    }

    fn pay(chain: u64, address: &str, amount: &str) -> Value {
        json!({ "chainId": chain, "address": address, "amount": amount, "usdAmount": 1.0 })
    }

    /// Real response (2026-10-07, demo key): 0.01 ETH → USDC on Ethereum, UTB router;
    /// commission brought down to 0.80% (`appFees`).
    fn eth_usdc() -> Value {
        json!({
            "tx": { "to": "0x1b6257CAE4192e62B629eFCa21771be3D759183D", "chainId": 1, "data": "0x9be111d10000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000180706b", "value": "10000000000000000" },
            "txId": "0x531ea920437f8fa717796865c35583f9dca4659b240ba46c5517cc226dc743d9",
            "vmId": "evm",
            "amountIn": { "chainId": 1, "address": NATIVE, "amount": "10000000000000000", "usdAmount": 25.6 },
            "amountOut": pay(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "25449094"),
            "amountOutMin": pay(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "25194603"),
            "applicationFee": pay(1, NATIVE, "80000000000000"),
            "protocolFee": pay(1, NATIVE, "30000000000000"),
            "estimatedTxTime": 0, "requiresRegisterTransaction": false, "executionsType": "DEFAULT"
        })
    }

    #[test]
    fn assets_and_links() {
        assert_eq!(a("btc", "btc_mainnet").chain, 999_000_313);
        assert_eq!(a("usdc", "evm_mainnet").token, USDC);
        assert_eq!(
            a("usdc", "sol_mainnet").token,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        );
        assert!(
            asset("tao", "tao_mainnet").is_none(),
            "TAO absent de MoonPay Trade"
        );
        assert!(
            asset("usdt", "tron_mainnet").is_none(),
            "jetons Tron pas encore pris en charge"
        );
        // Same EVM network: verifiable.
        assert!(
            verifiable(("evm", "evm_mainnet"), ("usdc", "evm_mainnet"))
                && links(("evm", "evm_mainnet"), ("usdc", "evm_mainnet"))
        );
        // Deposit from a network the app knows, to any network.
        assert!(
            links(("evm", "evm_mainnet"), ("xmr", "xmr_mainnet"))
                && !verifiable(("evm", "evm_mainnet"), ("xmr", "xmr_mainnet"))
        );
        assert!(links(("xrp", "xrp_mainnet"), ("evm", "evm_mainnet")));
        // No deposit from Monero, Solana, Stellar…; no swap on the same non-EVM network.
        assert!(
            !links(("xmr", "xmr_mainnet"), ("evm", "evm_mainnet"))
                && !links(("sol", "sol_mainnet"), ("evm", "evm_mainnet"))
        );
        assert!(!links(("sol", "sol_mainnet"), ("usdc", "sol_mainnet")));
        // Avalanche: node without simulation, router unverifiable, so no swap on that
        // network; deposit to another network possible.
        assert!(
            !verifiable(("avax", "avax_mainnet"), ("usdc", "avax_mainnet"))
                && !links(("avax", "avax_mainnet"), ("usdt", "avax_mainnet"))
        );
        assert!(links(("avax", "avax_mainnet"), ("xmr", "xmr_mainnet")));
        assert!(
            tradable().contains(&("xmr", "xmr_mainnet"))
                && tradable().contains(&("link", "evm_mainnet"))
        );
    }

    /// MoonPay widget key (publishable or secret): not a Trade key.
    #[test]
    fn widget_keys_are_not_trade_keys() {
        for widget in ["pk_test_x", "pk_live_x", "sk_live_x"] {
            assert!(Some(widget)
                .filter(|k| !k.starts_with("pk_") && !k.starts_with("sk_"))
                .is_none());
        }
    }

    #[test]
    fn router_quote_is_read_and_checked() {
        let (eth, usdc) = (a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"));
        let quote = parse_action(&eth_usdc(), &eth, &usdc, 10_000_000_000_000_000).unwrap();
        assert_eq!(
            (
                quote.expected_out,
                quote.min_out,
                quote.register,
                quote.protocol_fee_bps
            ),
            (25_449_094, 25_194_603, false, 30)
        );
        assert!(
            matches!(&quote.tx, TradeTx::Router { value, .. } if *value == 10_000_000_000_000_000)
        );
        // Tampering: every discrepancy is refused.
        let refused = |edit: &dyn Fn(&mut Value)| {
            let mut body = eth_usdc();
            edit(&mut body);
            parse_action(&body, &eth, &usdc, 10_000_000_000_000_000)
                .unwrap_err()
                .to_string()
        };
        assert!(
            refused(&|b| b["tx"]["to"] = json!("0x1111111254eeb25477b68fb85ed929f73a960582"))
                .contains("autre contrat")
        );
        assert!(
            refused(&|b| b["tx"]["value"] = json!("20000000000000000")).contains("autre montant")
        );
        assert!(refused(&|b| b["amountIn"]["amount"] = json!("1")).contains("autre montant"));
        assert!(refused(
            &|b| b["amountOut"]["address"] = json!("0xdac17f958d2ee523a2206206994597c13d831ec7")
        )
        .contains("autre crypto"));
        assert!(
            refused(&|b| b["amountOutMin"]["amount"] = json!("99999999")).contains("incohérent")
        );
        assert!(
            refused(&|b| b["applicationFee"]["amount"] = json!("100000000000000"))
                .contains("commission")
        );
        assert!(
            refused(&|b| b["protocolFee"]["amount"] = json!("150000000000000"))
                .contains("frais MoonPay")
        );
        // Fees counted in another crypto: bounded using the quote's dollar amounts.
        assert!(refused(&|b| b["applicationFee"] =
            json!({ "chainId": 1, "address": USDC, "amount": "260000", "usdAmount": 0.26 }))
        .contains("commission"));
        assert!(refused(&|b| b["executionsType"] = json!("GASLESS")).contains("forme"));
        // The router must enforce the minimum shown.
        assert!(
            refused(&|b| b["amountOutMin"]["amount"] = json!("25000000"))
                .contains("minimum affiché")
        );
        assert!(refused(&|b| b["tx"]["chainId"] = json!(42161)).contains("forme"));
    }

    #[test]
    fn deposit_quotes_are_read_and_checked() {
        let (eth, usdc, btc, xrp) = (
            a("evm", "evm_mainnet"),
            a("usdc", "evm_mainnet"),
            a("btc", "btc_mainnet"),
            a("xrp", "xrp_mainnet"),
        );
        let body = |tx: Value, from: &Asset, amount: &str, vm: &str| {
            json!({
                "tx": tx, "txId": "0xe6f0437787eb10d3bedc71d6e79c87524bc0cbe3dd494ea567a5d41702d2cb7c", "vmId": vm,
                "amountIn": pay(from.chain, from.token, amount),
                "amountOut": pay(999_000_313, NATIVE, "151270"), "amountOutMin": pay(999_000_313, NATIVE, "151270"),
                "requiresRegisterTransaction": true
            })
        };
        // ETH → BTC (real): a plain transfer to the deposit address.
        let eth_btc = body(
            json!({ "to": "0x3De23013a152628C8ad4a122c77732aa5252ad65", "value": "50000000000000000", "chainId": 1, "data": "0x" }),
            &eth,
            "50000000000000000",
            "evm",
        );
        let quote = parse_action(&eth_btc, &eth, &btc, 50_000_000_000_000_000).unwrap();
        assert_eq!(
            quote.tx,
            TradeTx::Deposit {
                address: "0x3De23013a152628C8ad4a122c77732aa5252ad65".into(),
                memo: None
            }
        );
        assert!(quote.register);
        let mut with_call = eth_btc.clone();
        with_call["tx"]["data"] = json!("0x12345678");
        assert!(parse_action(&with_call, &eth, &btc, 50_000_000_000_000_000)
            .unwrap_err()
            .to_string()
            .contains("simple virement"));
        // USDC → BTC (real): `transfer(deposit, amount)` on the USDC contract.
        let usdc_btc = body(
            json!({ "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "value": "0", "chainId": 1, "data": "0xa9059cbb000000000000000000000000e3cf74a4b0690400a2390683d0e2eef46427c6f70000000000000000000000000000000000000000000000000000000008f0d180" }),
            &usdc,
            "150000000",
            "evm",
        );
        let quote = parse_action(&usdc_btc, &usdc, &btc, 150_000_000).unwrap();
        assert!(
            matches!(&quote.tx, TradeTx::Deposit { address, .. } if address.eq_ignore_ascii_case("0xe3cf74a4b0690400a2390683d0e2eef46427c6f7"))
        );
        let mut approve = usdc_btc.clone();
        approve["tx"]["data"] = json!("0x095ea7b3000000000000000000000000e3cf74a4b0690400a2390683d0e2eef46427c6f70000000000000000000000000000000000000000000000000000000008f0d180");
        assert!(
            parse_action(&approve, &usdc, &btc, 150_000_000).is_err(),
            "autorisation au lieu d'un virement"
        );
        // XRP → ETH (real): r… deposit with a destination tag.
        let mut xrp_eth = body(
            json!({ "to": "rKKbNYZRqwPgZYkFWvqNUFBuscEyiFyCE", "toExtra": "962769451", "value": "50000000", "chainId": 999_000_346, "chainKey": "xrp" }),
            &xrp,
            "50000000",
            "alt-vm",
        );
        xrp_eth["amountOut"] = pay(1, NATIVE, "27284700000000000");
        xrp_eth["amountOutMin"] = pay(1, NATIVE, "27284700000000000");
        let quote = parse_action(&xrp_eth, &xrp, &eth, 50_000_000).unwrap();
        assert_eq!(
            quote.tx,
            TradeTx::Deposit {
                address: "rKKbNYZRqwPgZYkFWvqNUFBuscEyiFyCE".into(),
                memo: Some("962769451".into())
            }
        );
        let mut bad_tag = xrp_eth.clone();
        bad_tag["tx"]["toExtra"] = json!("memo texte");
        assert!(parse_action(&bad_tag, &xrp, &eth, 50_000_000).is_err());
        let mut bad_address = xrp_eth.clone();
        bad_address["tx"]["to"] = json!("rKKbNYZRqwPgZYkFWvqNUFBuscEyiFyCF");
        assert!(parse_action(&bad_address, &xrp, &eth, 50_000_000)
            .unwrap_err()
            .to_string()
            .contains("ne sait pas payer"));
        // BTC → ETH (real): P2SH deposit, payable; a deposit address with a future SegWit
        // version: a new quote is requested.
        let mut p2sh = body(
            json!({ "to": "3PFQuK2rjdCSHxCxT7p4jeVB34Fva3qwps", "toExtra": null, "value": "100000", "chainId": 999_000_313, "chainKey": "btc" }),
            &btc,
            "100000",
            "alt-vm",
        );
        p2sh["amountOut"] = pay(1, NATIVE, "31776200000000000");
        p2sh["amountOutMin"] = pay(1, NATIVE, "31776200000000000");
        assert_eq!(
            parse_action(&p2sh, &btc, &eth, 100_000).unwrap().tx,
            TradeTx::Deposit {
                address: "3PFQuK2rjdCSHxCxT7p4jeVB34Fva3qwps".into(),
                memo: None
            }
        );
        p2sh["tx"]["to"] = json!("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs");
        assert!(parse_action(&p2sh, &btc, &eth, 100_000)
            .unwrap_err()
            .to_string()
            .contains("nouveau devis"));
        p2sh["tx"]["to"] = json!("bc1qp4lu3qxd45jv5lnw9uauhm70238fgrzlv5s8he");
        assert!(parse_action(&p2sh, &btc, &eth, 100_000).is_ok());
    }

    #[test]
    fn api_errors_are_explained() {
        let error = |code: &str| {
            api_error(&json!({ "success": false, "error": { "code": code, "details": { "minAmount": "0.0012" } } }), 400).to_string()
        };
        assert!(error("NO_AVAILABLE_ROUTE").contains("ne propose pas"));
        assert_eq!(
            error("AMOUNT_TOO_LOW"),
            "montant trop faible pour MoonPay Trade (minimum 0.0012)"
        );
        assert!(error("WALLET_SCREENED").contains("conformité"));
        assert!(error("INVALID_API_KEY").contains("clé"));
    }

    fn log(address: &str, topics: Vec<[u8; 32]>, amount: u128) -> SimulatedLog {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(&amount.to_be_bytes());
        SimulatedLog {
            address: wallet_flow::parse_evm_address(address).unwrap(),
            topics,
            data,
        }
    }

    fn topic_addr(address: &str) -> [u8; 32] {
        padded(&wallet_flow::parse_evm_address(address).unwrap())
    }

    /// Events from the real simulation on 2026-10-07 (0.01 ETH → USDC, Ethereum, ETH
    /// movements traced), trimmed to the ones that matter.
    #[test]
    fn router_simulation_is_verified() {
        let transfer = evm_sign::keccak(b"Transfer(address,address,uint256)");
        let approval = evm_sign::keccak(b"Approval(address,address,uint256)");
        let eth = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let router = "0x1b6257cae4192e62b629efca21771be3d759183d";
        let executor = "0x18dc2961ddcca0d61b4d2e9c42ff5e1f5c8d25b4";
        let real = || {
            vec![
                log(
                    eth,
                    vec![transfer, topic_addr(USER), topic_addr(router)],
                    10_000_000_000_000_000,
                ),
                log(
                    eth,
                    vec![
                        transfer,
                        topic_addr(router),
                        topic_addr("0x79ad858cdff50ca6728d2531894001f221e805c7"),
                    ],
                    80_000_000_000_000,
                ),
                log(
                    USDC,
                    vec![transfer, topic_addr(executor), topic_addr(USER)],
                    25_194_603,
                ),
                log(
                    USDC,
                    vec![transfer, topic_addr(executor), topic_addr(USER)],
                    254_491,
                ),
            ]
        };
        let expected = Expected {
            user: wallet_flow::parse_evm_address(USER).unwrap(),
            sell_token: None,
            amount: 10_000_000_000_000_000,
            buy_token: Some(wallet_flow::parse_evm_address(USDC).unwrap()),
            min_out: 25_194_603,
            router: wallet_flow::parse_evm_address(router).unwrap(),
        };
        let ok = |logs: Vec<SimulatedLog>| {
            verify_router(
                &[SimulatedCall {
                    success: true,
                    logs,
                }],
                &expected,
            )
        };
        assert_eq!(ok(real()).unwrap(), 25_449_094);
        // Less than the minimum to the user's address.
        let mut short = real();
        short.pop();
        short[2] = log(
            USDC,
            vec![transfer, topic_addr(executor), topic_addr(USER)],
            25_000_000,
        );
        assert!(ok(short).unwrap_err().to_string().contains("minimum"));
        // USDC delivered to someone else.
        let mut elsewhere = real();
        elsewhere[2] = log(
            USDC,
            vec![transfer, topic_addr(executor), topic_addr(router)],
            25_194_603,
        );
        elsewhere.pop();
        assert!(ok(elsewhere).is_err());
        // More ETH than expected, or an extra token from the user.
        let mut more = real();
        more.push(log(
            eth,
            vec![transfer, topic_addr(USER), topic_addr(router)],
            1,
        ));
        assert!(ok(more).unwrap_err().to_string().contains("au lieu de"));
        let mut other_token = real();
        other_token.push(log(
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            vec![transfer, topic_addr(USER), topic_addr(router)],
            5,
        ));
        assert!(ok(other_token)
            .unwrap_err()
            .to_string()
            .contains("autre crypto"));
        // Token sold: approval to the router only, at most the amount.
        let usdc_sell = Expected {
            sell_token: Some(wallet_flow::parse_evm_address(USDC).unwrap()),
            buy_token: None,
            amount: 50_000_000,
            min_out: 1,
            ..expected
        };
        let approve = |spender: &str, amount: u128| {
            log(
                USDC,
                vec![approval, topic_addr(USER), topic_addr(spender)],
                amount,
            )
        };
        let sell = |approval: SimulatedLog| {
            let logs = vec![
                approval,
                log(
                    USDC,
                    vec![transfer, topic_addr(USER), topic_addr(router)],
                    50_000_000,
                ),
                log(
                    eth,
                    vec![transfer, topic_addr(executor), topic_addr(USER)],
                    19_000_000_000_000_000,
                ),
            ];
            verify_router(
                &[SimulatedCall {
                    success: true,
                    logs,
                }],
                &usdc_sell,
            )
        };
        assert!(sell(approve(router, 50_000_000)).is_ok());
        assert!(sell(approve(executor, 50_000_000))
            .unwrap_err()
            .to_string()
            .contains("autre contrat"));
        assert!(sell(approve(router, 50_000_001)).is_err());
        // Failed simulation.
        assert!(verify_router(
            &[SimulatedCall {
                success: false,
                logs: real()
            }],
            &expected
        )
        .unwrap_err()
        .to_string()
        .contains("échouerait"));
    }

    /// Same request as the app (`action_params`), with the demo key.
    fn demo_quote(from: &Asset, to: &Asset, amount: u128, sender: &str, recipient: &str) -> Quote {
        let params = action_params(from, to, amount, sender, recipient);
        let body: Value = client()
            .get(format!("{API_BASE}/getAction"))
            .header("x-api-key", DEMO_KEY)
            .query(&params)
            .send()
            .unwrap()
            .json()
            .unwrap();
        parse_action(&body, from, to, amount).unwrap_or_else(|e| {
            panic!(
                "{e} : {}",
                body.to_string().chars().take(400).collect::<String>()
            )
        })
    }

    /// Live (demo key, nothing is broadcast): ETH → USDC on Ethereum; the router
    /// transaction, simulated from a funded public account (Vitalik's), passes
    /// `verify_router`; an inflated minimum is refused.
    /// `cargo test -- --ignored real_moonpay_trade_router --nocapture`
    #[test]
    #[ignore]
    fn real_moonpay_trade_router() {
        let rich = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let (eth, usdc) = (a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"));
        let quote = demo_quote(&eth, &usdc, 10_000_000_000_000_000, rich, rich);
        let TradeTx::Router {
            router,
            data,
            value,
        } = &quote.tx
        else {
            panic!("routeur attendu")
        };
        let rpc = crate::eth_rpc::EthRpc::new(wallet_flow::evm_network("evm_mainnet").unwrap().rpc);
        let to = crate::derivation::format_address(router);
        let simulated = rpc
            .simulate_v1_with_native_transfers(&[crate::eth_rpc::SimCallRequest {
                from: rich,
                to: &to,
                value: *value,
                data,
            }])
            .unwrap();
        let expected = Expected {
            user: wallet_flow::parse_evm_address(rich).unwrap(),
            sell_token: None,
            amount: quote.amount,
            buy_token: Some(wallet_flow::parse_evm_address(USDC).unwrap()),
            min_out: quote.min_out,
            router: *router,
        };
        let received = verify_router(&simulated, &expected).unwrap();
        println!(
            "0,01 ETH → {received} unités USDC (minimum {}, attendu {})",
            quote.min_out, quote.expected_out
        );
        let inflated = Expected {
            min_out: received + 1,
            ..expected
        };
        assert!(verify_router(&simulated, &inflated).is_err());
    }

    /// Exploration (demo key): shape of the deposit addresses per source network, from
    /// addresses derived from a dummy seed.
    #[test]
    #[ignore]
    fn explore_deposit_address_formats() {
        let seed = [7u8; 64];
        let doge =
            crate::doge::p2pkh_address(&crate::derivation::derive_doge_key(&seed, 0).unwrap().1);
        let zec =
            crate::zcash::p2pkh_address(&crate::derivation::derive_zec_key(&seed, 0).unwrap().1);
        let ada = crate::cardano::address_of(&seed[..32], 0);
        let near = crate::near::implicit_account(&crate::derivation::derive_near_key(&seed, 0));
        let btc = crate::derivation::format_btc_mainnet_address(
            &crate::derivation::derive_btc_mainnet_key(&seed, 0)
                .unwrap()
                .1,
        )
        .unwrap();
        let eth = a("evm", "evm_mainnet");
        for (coin, network, amount, sender) in [
            ("doge", "doge_mainnet", 50_000_000_000u128, doge),
            ("zec", "zec_mainnet", 50_000_000, zec),
            ("ada", "ada_mainnet", 200_000_000, ada),
            (
                "near",
                "near_mainnet",
                50_000_000_000_000_000_000_000_000,
                near,
            ),
            ("btc", "btc_mainnet", 200_000, btc),
        ] {
            let from = a(coin, network);
            let body: Value = client()
                .get(format!("{API_BASE}/getAction"))
                .header("x-api-key", DEMO_KEY)
                .query(&action_params(&from, &eth, amount, &sender, USER))
                .send()
                .unwrap()
                .json()
                .unwrap();
            println!(
                "{coin} ({sender}) → dépôt {} mémo {} vm {}",
                body["tx"]["to"], body["tx"]["toExtra"], body["vmId"]
            );
            if body["tx"].is_null() {
                println!(
                    "   {}",
                    body.to_string().chars().take(300).collect::<String>()
                );
            }
        }
    }

    /// Live (demo key): deposits (ETH → XMR to the Monero project's donation address,
    /// BTC → ETH, XRP → ETH with a tag), read and checked.
    /// `cargo test -- --ignored real_moonpay_trade_deposits --nocapture`
    #[test]
    #[ignore]
    fn real_moonpay_trade_deposits() {
        let xmr_donation = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        let (eth, xmr, btc, xrp) = (
            a("evm", "evm_mainnet"),
            a("xmr", "xmr_mainnet"),
            a("btc", "btc_mainnet"),
            a("xrp", "xrp_mainnet"),
        );
        for (from, to, amount, sender, recipient) in [
            (&eth, &xmr, 50_000_000_000_000_000u128, USER, xmr_donation),
            (
                &btc,
                &eth,
                100_000,
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                USER,
            ),
            (
                &xrp,
                &eth,
                50_000_000,
                "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                USER,
            ),
        ] {
            let body: Value = client()
                .get(format!("{API_BASE}/getAction"))
                .header("x-api-key", DEMO_KEY)
                .query(&action_params(from, to, amount, sender, recipient))
                .send()
                .unwrap()
                .json()
                .unwrap();
            match parse_action(&body, from, to, amount) {
                Ok(quote) => {
                    println!(
                        "{} → {} : {:?}, minimum {} (~{} s)",
                        from.symbol, to.symbol, quote.tx, quote.min_out, quote.duration_secs
                    );
                    assert!(matches!(quote.tx, TradeTx::Deposit { .. }));
                }
                // Bitcoin: a deposit of a non-payable shape (future SegWit version), refused cleanly.
                Err(e)
                    if from.network == "btc_mainnet" && e.to_string().contains("nouveau devis") =>
                {
                    println!("BTC → ETH : {e} ({})", body["tx"]["to"])
                }
                Err(e) => panic!("{e}"),
            }
        }
    }
}
