//! SwapKit (by the THORSwap team): a cross-chain swap aggregator, used here for two
//! DEPOSIT-ADDRESS providers, NEAR Intents and Chainflip, on top of the providers
//! already integrated directly.
//!
//! SwapKit gives the quote, then opens the deposit (an address specific to the
//! swap). Before any signature, the app has the provider's official API,
//! independent of SwapKit, CONFIRM that deposit:
//! - NEAR Intents: signed quote read by deposit address (1Click `/v0/status`);
//! - Chainflip: channel read by identifier (`chainflip-swap` `/v2/swaps`).
//!
//! Checked: deposit address, crypto sold and received, amount (exact for NEAR),
//! destination and refund = addresses given by the app, minimum received (the
//! provider's, shown in the confirmation dialog), deadline, bounded fees. At the
//! slightest mismatch, the swap is refused. The deposit itself is an ordinary
//! transfer built and signed by the app.
//!
//! API key read at build time (`partner-keys.env`, see `build.rs`): if missing,
//! SwapKit is not offered.

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::OnceLock;

const API_BASE: &str = "https://api.swapkit.dev";
pub const API_KEY: Option<&str> = option_env!("SWAPKIT_API_KEY");
const NEAR_STATUS: &str = "https://1click.chaindefuser.com/v0/status";
const CHAINFLIP_STATUS: &str = "https://chainflip-swap.chainflip.io/v2/swaps";
/// Slippage tolerance requested from SwapKit (percent): guaranteed by the provider
/// (minimum received) and checked with it.
const SLIPPAGE_PERCENT: u32 = 1;
/// SwapKit's fee (taken from real quotes: 15 basis points).
pub const SERVICE_FEE_BPS: u32 = 15;
/// The app's fee through SwapKit: 0 until the per-provider receiving identifiers
/// are set up on the dashboard (read on 2026-10-04: `notconfig.near`, `feeBps: 0`).
pub const AFFILIATE_FEE_BPS: u32 = 0;
/// Total fees accepted in a checked deposit (SwapKit + app, with a margin): beyond
/// that, refused.
const MAX_FEE_BPS: u64 = 100;
/// Minimum validity a deposit must still have when signing.
const MIN_VALIDITY_SECS: i64 = 20 * 60;

pub fn enabled() -> bool {
    API_KEY.is_some()
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    #[serde(rename = "NEAR")]
    Near,
    #[serde(rename = "CHAINFLIP")]
    Chainflip,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Near => "NEAR Intents",
            Provider::Chainflip => "Chainflip",
        }
    }

    fn api_name(self) -> &'static str {
        match self {
            Provider::Near => "NEAR",
            Provider::Chainflip => "CHAINFLIP",
        }
    }

    fn from_api(name: &str) -> Option<Self> {
        match name {
            "NEAR" => Some(Provider::Near),
            "CHAINFLIP" => Some(Provider::Chainflip),
            _ => None,
        }
    }
}

/// The app's crypto that can be swapped through SwapKit, with its identifiers at
/// SwapKit, NEAR Intents (1Click `/v0/tokens`) and Chainflip (asset, network),
/// taken from the official lists on 2026-10-04.
pub struct Asset {
    pub coin: &'static str,
    pub network: &'static str,
    pub symbol: &'static str,
    pub swapkit: &'static str,
    pub decimals: u8,
    near: Option<&'static str>,
    chainflip: Option<(&'static str, &'static str)>,
}

const fn asset(
    coin: &'static str,
    network: &'static str,
    symbol: &'static str,
    swapkit: &'static str,
    decimals: u8,
    near: Option<&'static str>,
    chainflip: Option<(&'static str, &'static str)>,
) -> Asset {
    Asset { coin, network, symbol, swapkit, decimals, near, chainflip }
}

pub const ASSETS: [Asset; 20] = [
    asset("btc", "btc_mainnet", "BTC", "BTC.BTC", 8, Some("nep141:btc.omft.near"), Some(("BTC", "Bitcoin"))),
    asset("evm", "evm_mainnet", "ETH", "ETH.ETH", 18, Some("nep141:eth.omft.near"), Some(("ETH", "Ethereum"))),
    asset("evm", "arbitrum_mainnet", "ETH", "ARB.ETH", 18, Some("nep141:arb.omft.near"), Some(("ETH", "Arbitrum"))),
    asset("evm", "base_mainnet", "ETH", "BASE.ETH", 18, Some("nep141:base.omft.near"), None),
    asset("sol", "sol_mainnet", "SOL", "SOL.SOL", 9, Some("nep141:sol.omft.near"), Some(("SOL", "Solana"))),
    asset("bnb", "bsc_mainnet", "BNB", "BSC.BNB", 18, Some("nep245:v2_1.omni.hot.tg:56_11111111111111111111"), None),
    asset("avax", "avax_mainnet", "AVAX", "AVAX.AVAX", 18, Some("nep245:v2_1.omni.hot.tg:43114_11111111111111111111"), None),
    asset("pol", "polygon_mainnet", "POL", "POL.POL", 18, Some("nep245:v2_1.omni.hot.tg:137_11111111111111111111"), None),
    asset(
        "usdc",
        "evm_mainnet",
        "USDC",
        "ETH.USDC-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        6,
        Some("nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near"),
        Some(("USDC", "Ethereum")),
    ),
    asset(
        "usdc",
        "arbitrum_mainnet",
        "USDC",
        "ARB.USDC-0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        6,
        Some("nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near"),
        Some(("USDC", "Arbitrum")),
    ),
    asset(
        "usdc",
        "base_mainnet",
        "USDC",
        "BASE.USDC-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        6,
        Some("nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near"),
        None,
    ),
    asset(
        "usdc",
        "sol_mainnet",
        "USDC",
        "SOL.USDC-EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        6,
        Some("nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near"),
        Some(("USDC", "Solana")),
    ),
    asset(
        "usdt",
        "evm_mainnet",
        "USDT",
        "ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7",
        6,
        Some("nep141:eth-0xdac17f958d2ee523a2206206994597c13d831ec7.omft.near"),
        Some(("USDT", "Ethereum")),
    ),
    asset(
        "usdt",
        "sol_mainnet",
        "USDT",
        "SOL.USDT-Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        6,
        Some("nep141:sol-c800a4bd850783ccb82c2b2c7e84175443606352.omft.near"),
        Some(("USDT", "Solana")),
    ),
    asset("doge", "doge_mainnet", "DOGE", "DOGE.DOGE", 8, Some("nep141:doge.omft.near"), None),
    asset("zec", "zec_mainnet", "ZEC", "ZEC.ZEC", 8, Some("nep141:zec.omft.near"), None),
    asset("trx", "tron_mainnet", "TRX", "TRON.TRX", 6, Some("nep141:tron.omft.near"), None),
    asset("xrp", "xrp_mainnet", "XRP", "XRP.XRP", 6, Some("nep141:xrp.omft.near"), None),
    asset("near", "near_mainnet", "NEAR", "NEAR.NEAR", 24, Some("nep141:wrap.near"), None),
    asset("ada", "ada_mainnet", "ADA", "ADA.ADA", 6, Some("nep141:cardano.omft.near"), None),
];

pub fn find(coin: &str, network: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.coin == coin && a.network == network && (a.near.is_some() || a.chainflip.is_some()))
}

/// Selected SwapKit providers that connect `from` to `to`.
pub fn providers(from: &Asset, to: &Asset) -> Vec<Provider> {
    let mut all = Vec::new();
    if from.near.is_some() && to.near.is_some() {
        all.push(Provider::Near);
    }
    if from.chainflip.is_some() && to.chainflip.is_some() {
        all.push(Provider::Chainflip);
    }
    all
}

/// Does SwapKit connect these two cryptos directly (key present)?
pub fn links(from: (&str, &str), to: (&str, &str)) -> bool {
    enabled() && from != to && find(from.0, from.1).zip(find(to.0, to.1)).is_some_and(|(f, t)| !providers(f, t).is_empty())
}

/// Cryptos that can be swapped through SwapKit (empty without a key).
pub fn tradable() -> Vec<(&'static str, &'static str)> {
    if !enabled() {
        return Vec::new();
    }
    ASSETS.iter().filter(|a| a.near.is_some() || a.chainflip.is_some()).map(|a| (a.coin, a.network)).collect()
}

// --- Amounts --------------------------------------------------------------------

/// "2.217785954" → units (truncated to `decimals` decimals).
fn decimal_units(text: &str, decimals: u8) -> Result<u128> {
    let text = text.trim();
    ensure!(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit() || b == b'.'), "montant SwapKit illisible ({text})");
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    ensure!(!fraction.contains('.'), "montant SwapKit illisible ({text})");
    let fraction: String = fraction.chars().chain(std::iter::repeat('0')).take(decimals as usize).collect();
    let scale = 10u128.checked_pow(u32::from(decimals)).context("décimales invalides")?;
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| anyhow!("montant SwapKit illisible ({text})"))? };
    let fraction: u128 = if fraction.is_empty() { 0 } else { fraction.parse().map_err(|_| anyhow!("montant SwapKit illisible ({text})"))? };
    whole.checked_mul(scale).and_then(|w| w.checked_add(fraction)).context("montant SwapKit hors limites")
}

// --- Quote and deposit ----------------------------------------------------------

/// Route offered by a provider, for the preview.
#[derive(Clone, Debug)]
pub struct Route {
    pub provider: Provider,
    pub route_id: String,
    /// Expected and minimum amount received (units of the received crypto).
    pub expected_out: u128,
    pub min_out: u128,
    pub total_secs: u64,
}

fn post(path: &str, body: Value) -> Result<Value> {
    let key = API_KEY.context("SwapKit non configuré")?;
    let response = client().post(format!("{API_BASE}{path}")).header("x-api-key", key).json(&body).send().context("SwapKit injoignable")?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    // Never the key in a message (it is not echoed back, but on principle).
    let text = text.replace(key, "<clé>");
    let value: Value = serde_json::from_str(&text).map_err(|_| anyhow!("réponse SwapKit illisible ({status})"))?;
    ensure!(status.is_success(), "SwapKit a refusé la demande : {}", value["message"].as_str().or(value["error"].as_str()).unwrap_or("erreur inconnue"));
    Ok(value)
}

/// Quotes from the selected providers for selling `amount` (units) of `from` for
/// `to`; `source` and `destination` are the user's addresses (refund and arrival).
/// Best first.
pub fn quote(from: &Asset, to: &Asset, amount: u128, source: &str, destination: &str) -> Result<Vec<Route>> {
    let wanted = providers(from, to);
    ensure!(!wanted.is_empty(), "échange non disponible via SwapKit entre ces deux cryptos");
    let value = post(
        "/v3/quote",
        json!({
            "sellAsset": from.swapkit,
            "buyAsset": to.swapkit,
            "sellAmount": crate::tokens::format_amount(amount, from.decimals),
            "sourceAddress": source,
            "destinationAddress": destination,
            "slippage": SLIPPAGE_PERCENT,
            "providers": wanted.iter().map(|p| p.api_name()).collect::<Vec<_>>(),
        }),
    )?;
    let mut routes = parse_routes(&value, from, to)?;
    if routes.is_empty() {
        let reasons: Vec<String> = value["providerErrors"]
            .as_array()
            .map(|errors| errors.iter().filter_map(|e| Some(format!("{} : {}", e["provider"].as_str()?, e["errorCode"].as_str()?))).collect())
            .unwrap_or_default();
        bail!("aucune route SwapKit pour cet échange{}", if reasons.is_empty() { String::new() } else { format!(" ({})", reasons.join(", ")) });
    }
    routes.sort_by_key(|r| std::cmp::Reverse(r.expected_out));
    Ok(routes)
}

fn parse_routes(value: &Value, from: &Asset, to: &Asset) -> Result<Vec<Route>> {
    let mut routes = Vec::new();
    for route in value["routes"].as_array().map(Vec::as_slice).unwrap_or_default() {
        // A single provider, one of the two selected; a plain transfer.
        let providers: Vec<&str> = route["providers"].as_array().map(|p| p.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let [name] = providers.as_slice() else { continue };
        let Some(provider) = Provider::from_api(name) else { continue };
        if route["txHint"].as_str() != Some("simpleTransfer") {
            continue;
        }
        if !route["sellAsset"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(from.swapkit)) || !route["buyAsset"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(to.swapkit)) {
            continue;
        }
        routes.push(Route {
            provider,
            route_id: route["routeId"].as_str().context("route SwapKit sans identifiant")?.to_string(),
            expected_out: decimal_units(route["expectedBuyAmount"].as_str().context("réception SwapKit absente")?, to.decimals)?,
            min_out: decimal_units(route["expectedBuyAmountMaxSlippage"].as_str().context("minimum SwapKit absent")?, to.decimals)?,
            total_secs: route["estimatedTime"]["total"].as_f64().unwrap_or(0.0).max(0.0) as u64,
        });
    }
    Ok(routes)
}

/// Deposit opened for a route: where to send, and the reference used for
/// verification.
#[derive(Clone, Debug)]
pub struct Deposit {
    pub provider: Provider,
    pub address: String,
    /// Identifier of the channel (Chainflip) or of the quote (NEAR).
    pub channel_id: String,
    pub expected_out: u128,
    pub min_out: u128,
}

/// Opens the deposit for route `route_id` (no funds are sent here).
pub fn open_deposit(route: &Route, from: &Asset, to: &Asset, source: &str, destination: &str) -> Result<Deposit> {
    // The app builds and signs the deposit itself (an ordinary transfer) and checks
    // the balance before the dialog: neither a transaction nor a balance check is
    // requested from SwapKit.
    let value = post(
        "/v3/swap",
        json!({ "routeId": route.route_id, "sourceAddress": source, "destinationAddress": destination, "disableBuildTx": true, "disableBalanceCheck": true }),
    )?;
    parse_deposit(&value, route.provider, from, to, source, destination)
}

fn same_address(a: &str, b: &str) -> bool {
    if a.starts_with("0x") || a.starts_with("0X") {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn parse_deposit(value: &Value, provider: Provider, from: &Asset, to: &Asset, source: &str, destination: &str) -> Result<Deposit> {
    let providers: Vec<&str> = value["providers"].as_array().map(|p| p.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    ensure!(providers == [provider.api_name()], "SwapKit a changé de fournisseur ({providers:?}) — échange refusé");
    ensure!(value["txHint"].as_str() == Some("simpleTransfer"), "dépôt SwapKit d'un type inattendu — échange refusé");
    ensure!(value["memo"].as_str().is_none_or(str::is_empty), "dépôt SwapKit avec memo, non pris en charge — échange refusé");
    ensure!(
        value["sellAsset"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(from.swapkit)) && value["buyAsset"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(to.swapkit)),
        "SwapKit a changé les cryptos de l'échange — échange refusé"
    );
    ensure!(
        value["sourceAddress"].as_str().is_some_and(|a| same_address(a, source)) && value["destinationAddress"].as_str().is_some_and(|a| same_address(a, destination)),
        "SwapKit a changé les adresses de l'échange — échange refusé"
    );
    let address = value["targetAddress"].as_str().filter(|a| !a.is_empty()).context("adresse de dépôt SwapKit absente")?;
    ensure!(address.len() <= 128 && address.bytes().all(|b| b.is_ascii_alphanumeric()), "adresse de dépôt SwapKit invalide");
    let channel_id = value["meta"]["providerDepositChannelId"].as_str().context("identifiant du dépôt absent")?;
    ensure!(channel_id.len() <= 80 && channel_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'), "identifiant du dépôt invalide");
    Ok(Deposit {
        provider,
        address: address.to_string(),
        channel_id: channel_id.to_string(),
        expected_out: decimal_units(value["expectedBuyAmount"].as_str().context("réception SwapKit absente")?, to.decimals)?,
        min_out: decimal_units(value["expectedBuyAmountMaxSlippage"].as_str().context("minimum SwapKit absent")?, to.decimals)?,
    })
}

// --- Verification with the provider ---------------------------------------------

/// What the provider confirmed, for the confirmation dialog.
#[derive(Clone, Debug)]
pub struct Verified {
    /// Minimum received guaranteed by the provider (units).
    pub min_out: u128,
    /// Deposit deadline (Unix seconds).
    pub deadline: i64,
    /// Total fees (basis points).
    pub fees_bps: u64,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// "2026-10-07T17:01:26.000Z" → Unix seconds (UTC).
fn parse_iso(text: &str) -> Option<i64> {
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = time.trim_end_matches('Z').split(':');
    let (hh, mm) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let ss = t.next()?.split('.').next()?.parse::<i64>().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&day) || !(0..24).contains(&hh) || !(0..60).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + day - 1;
    Some((era * 146_097 + doe - 719_468) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// The deposit, as confirmed by the provider itself.
pub fn verify(deposit: &Deposit, from: &Asset, to: &Asset, amount: u128, source: &str, destination: &str) -> Result<Verified> {
    match deposit.provider {
        Provider::Near => {
            let url = format!("{NEAR_STATUS}?depositAddress={}", deposit.address);
            let status: Value = client().get(url).send().context("NEAR Intents injoignable")?.json().context("réponse NEAR Intents illisible")?;
            check_near(&status, deposit, from, to, amount, source, destination, now())
        }
        Provider::Chainflip => {
            // A freshly opened channel takes a few seconds to be indexed.
            let url = format!("{CHAINFLIP_STATUS}/{}", deposit.channel_id);
            for attempt in 0..15 {
                let status: Value = client().get(&url).send().context("Chainflip injoignable")?.json().context("réponse Chainflip illisible")?;
                if status["message"].as_str() == Some("resource not found") {
                    if attempt < 14 {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                    continue;
                }
                return check_chainflip(&status, deposit, from, to, amount, source, destination, now());
            }
            bail!("canal Chainflip introuvable auprès de Chainflip — échange refusé")
        }
    }
}

/// The provider's minimum: never noticeably below the one SwapKit announced (0.5%
/// rounding gap tolerated).
fn min_consistent(provider_min: u128, swapkit_min: u128) -> bool {
    provider_min.saturating_mul(1000) >= swapkit_min.saturating_mul(995)
}

#[allow(clippy::too_many_arguments)]
fn check_near(status: &Value, deposit: &Deposit, from: &Asset, to: &Asset, amount: u128, source: &str, destination: &str, now: i64) -> Result<Verified> {
    let refused = |what: &str| anyhow!("NEAR Intents ne confirme pas {what} — échange refusé");
    let request = &status["quoteResponse"]["quoteRequest"];
    let quote = &status["quoteResponse"]["quote"];
    ensure!(status["status"].as_str() == Some("PENDING_DEPOSIT"), refused("un dépôt en attente"));
    ensure!(quote["depositAddress"].as_str().is_some_and(|a| same_address(a, &deposit.address)), refused("l'adresse de dépôt"));
    ensure!(request["originAsset"].as_str() == from.near && request["destinationAsset"].as_str() == to.near, refused("les cryptos de l'échange"));
    ensure!(request["amount"].as_str() == Some(amount.to_string().as_str()) && request["swapType"].as_str() == Some("EXACT_INPUT"), refused("le montant"));
    ensure!(
        request["depositType"].as_str() == Some("ORIGIN_CHAIN") && request["recipientType"].as_str() == Some("DESTINATION_CHAIN") && request["refundType"].as_str() == Some("ORIGIN_CHAIN"),
        refused("le type de dépôt")
    );
    // "Simple" deposits only: in memo mode (a shared address where a memo identifies
    // the swap), the app's ordinary transfer, without a memo, would be attributed to
    // no swap at all and the funds would be stuck (31st review round).
    ensure!(
        request["depositMode"].as_str().is_none_or(|mode| mode == "SIMPLE") && quote["depositMemo"].as_str().is_none_or(str::is_empty),
        refused("un dépôt simple, sans memo")
    );
    ensure!(request["recipient"].as_str().is_some_and(|a| same_address(a, destination)), refused("votre adresse d'arrivée"));
    ensure!(request["refundTo"].as_str().is_some_and(|a| same_address(a, source)), refused("votre adresse de remboursement"));
    let min_out: u128 = quote["minAmountOut"].as_str().and_then(|m| m.parse().ok()).ok_or_else(|| refused("le minimum de réception"))?;
    ensure!(min_consistent(min_out, deposit.min_out), refused("le minimum de réception annoncé"));
    let deadline = quote["deadline"].as_str().and_then(parse_iso).ok_or_else(|| refused("l'échéance"))?;
    ensure!(deadline >= now + MIN_VALIDITY_SECS, refused("une échéance assez lointaine"));
    let fees_bps: u64 = request["appFees"].as_array().map(|fees| fees.iter().filter_map(|f| f["fee"].as_u64()).sum()).unwrap_or(0);
    ensure!(fees_bps <= MAX_FEE_BPS, refused("des commissions raisonnables"));
    Ok(Verified { min_out, deadline, fees_bps })
}

#[allow(clippy::too_many_arguments)]
fn check_chainflip(status: &Value, deposit: &Deposit, from: &Asset, to: &Asset, amount: u128, source: &str, destination: &str, now: i64) -> Result<Verified> {
    let refused = |what: &str| anyhow!("Chainflip ne confirme pas {what} — échange refusé");
    let (src, dst) = from.chainflip.zip(to.chainflip).ok_or_else(|| refused("ces cryptos"))?;
    let channel = &status["depositChannel"];
    ensure!(status["state"].as_str() == Some("WAITING"), refused("un canal en attente de dépôt"));
    ensure!(channel["id"].as_str() == Some(deposit.channel_id.as_str()), refused("le canal"));
    ensure!(channel["depositAddress"].as_str().is_some_and(|a| same_address(a, &deposit.address)), refused("l'adresse de dépôt"));
    ensure!(
        status["srcAsset"].as_str() == Some(src.0) && status["srcChain"].as_str() == Some(src.1) && status["destAsset"].as_str() == Some(dst.0) && status["destChain"].as_str() == Some(dst.1),
        refused("les cryptos de l'échange")
    );
    ensure!(status["destAddress"].as_str().is_some_and(|a| same_address(a, destination)), refused("votre adresse d'arrivée"));
    let fill_or_kill = &status["fillOrKillParams"];
    ensure!(fill_or_kill["refundAddress"].as_str().is_some_and(|a| same_address(a, source)), refused("votre adresse de remboursement"));
    // Minimum price (crypto received per unit sold) × amount sold.
    let min_price: f64 = fill_or_kill["minPrice"].as_str().and_then(|p| p.parse().ok()).filter(|p: &f64| p.is_finite() && *p > 0.0).ok_or_else(|| refused("le prix minimum"))?;
    let sold = amount as f64 / 10f64.powi(i32::from(from.decimals));
    let min_out = (sold * min_price * 10f64.powi(i32::from(to.decimals))).floor();
    ensure!(min_out.is_finite() && min_out > 0.0, refused("le minimum de réception"));
    let min_out = min_out as u128;
    ensure!(min_consistent(min_out, deposit.min_out), refused("le minimum de réception annoncé"));
    ensure!(channel["isExpired"].as_bool() == Some(false), refused("un canal encore ouvert"));
    let deadline = channel["estimatedExpiryTime"].as_i64().map(|ms| ms / 1000).ok_or_else(|| refused("l'échéance du canal"))?;
    ensure!(deadline >= now + MIN_VALIDITY_SECS, refused("une échéance assez lointaine"));
    let fees_bps: u64 = status["brokers"].as_array().map(|b| b.iter().filter_map(|x| x["commissionBps"].as_u64()).sum()).unwrap_or(0);
    ensure!(fees_bps <= MAX_FEE_BPS, refused("des commissions raisonnables"));
    Ok(Verified { min_out, deadline, fees_bps })
}

// --- Tracking after the deposit -------------------------------------------------

/// Stage of a swap, read from the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapState {
    AwaitingDeposit,
    Processing,
    Completed,
    Refunded,
    Failed,
    Unknown,
}

fn near_state(status: &str) -> SwapState {
    match status {
        "PENDING_DEPOSIT" => SwapState::AwaitingDeposit,
        "KNOWN_DEPOSIT_TX" | "PROCESSING" | "INCOMPLETE_DEPOSIT" => SwapState::Processing,
        "SUCCESS" => SwapState::Completed,
        "REFUNDED" => SwapState::Refunded,
        "FAILED" => SwapState::Failed,
        _ => SwapState::Unknown,
    }
}

fn chainflip_state(state: &str) -> SwapState {
    match state {
        "WAITING" => SwapState::AwaitingDeposit,
        "RECEIVING" | "SWAPPING" | "SENDING" | "SENT" => SwapState::Processing,
        "COMPLETED" => SwapState::Completed,
        "FAILED" => SwapState::Failed,
        _ => SwapState::Unknown,
    }
}

/// Stage of the swap whose deposit is `deposit_address` (NEAR) or whose channel is
/// `channel_id` (Chainflip), read from the provider.
pub fn status(provider: Provider, channel_id: &str, deposit_address: &str) -> Result<SwapState> {
    ensure!(deposit_address.len() <= 128 && deposit_address.bytes().all(|b| b.is_ascii_alphanumeric()), "adresse de dépôt SwapKit invalide");
    ensure!(channel_id.len() <= 80 && channel_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'), "identifiant du dépôt invalide");
    Ok(match provider {
        Provider::Near => {
            let value: Value = client().get(format!("{NEAR_STATUS}?depositAddress={deposit_address}")).send().context("NEAR Intents injoignable")?.json().context("réponse NEAR Intents illisible")?;
            near_state(value["status"].as_str().unwrap_or_default())
        }
        Provider::Chainflip => {
            let value: Value = client().get(format!("{CHAINFLIP_STATUS}/{channel_id}")).send().context("Chainflip injoignable")?.json().context("réponse Chainflip illisible")?;
            chainflip_state(value["state"].as_str().unwrap_or_default())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_states_are_mapped() {
        assert_eq!(near_state("PENDING_DEPOSIT"), SwapState::AwaitingDeposit);
        assert_eq!(near_state("SUCCESS"), SwapState::Completed);
        assert_eq!(near_state("REFUNDED"), SwapState::Refunded);
        assert_eq!(chainflip_state("SWAPPING"), SwapState::Processing);
        assert_eq!(chainflip_state("COMPLETED"), SwapState::Completed);
        assert_eq!(chainflip_state("???"), SwapState::Unknown);
        assert!(status(Provider::Near, "x", "../admin").is_err());
        assert!(status(Provider::Chainflip, "1-Ethereum-2/../../x", "0xabc").is_err());
    }

    const EVM: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
    const SOL: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

    fn eth() -> &'static Asset {
        find("evm", "evm_mainnet").unwrap()
    }
    fn sol() -> &'static Asset {
        find("sol", "sol_mainnet").unwrap()
    }

    #[test]
    fn assets_and_providers() {
        assert_eq!(providers(eth(), sol()), vec![Provider::Near, Provider::Chainflip]);
        assert_eq!(providers(find("doge", "doge_mainnet").unwrap(), eth()), vec![Provider::Near], "DOGE : NEAR seulement");
        assert!(find("xmr", "xmr_mainnet").is_none());
        for a in &ASSETS {
            if let Some((_, deployment)) = crate::tokens::find(a.coin, a.network) {
                assert_eq!(deployment.decimals, a.decimals, "{}", a.swapkit);
            }
        }
        assert_eq!(decimal_units("2.217785954", 9).unwrap(), 2_217_785_954);
        assert_eq!(decimal_units("0.315729440128514247", 18).unwrap(), 315_729_440_128_514_247);
        assert_eq!(decimal_units("1.123456789", 6).unwrap(), 1_123_456, "tronqué");
        assert!(decimal_units("1e5", 6).is_err());
        assert_eq!(parse_iso("2026-10-07T17:01:26.000Z"), Some(1_791_392_486));
    }

    fn near_deposit() -> Deposit {
        Deposit {
            provider: Provider::Near,
            address: "0x343e292d9508A8D3f1C462f9B6C382F3dEAD296E".into(),
            channel_id: "644eedea-41f6-4e3f-835c-049a09ffd589".into(),
            expected_out: 2_217_785_954,
            min_out: 2_173_430_235,
        }
    }

    /// Real NEAR Intents response (2026-10-04), ETH → SOL.
    fn near_status() -> Value {
        serde_json::from_str(r#"{"status":"PENDING_DEPOSIT","quoteResponse":{"quoteRequest":{"swapType":"EXACT_INPUT","depositMode":"SIMPLE","originAsset":"nep141:eth.omft.near","depositType":"ORIGIN_CHAIN","destinationAsset":"nep141:sol.omft.near","amount":"100000000000000000","refundTo":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","refundType":"ORIGIN_CHAIN","recipient":"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM","recipientType":"DESTINATION_CHAIN","appFees":[{"recipient":"notconfig.near","fee":0},{"recipient":"dde5bb6b","fee":15}]},"quote":{"amountIn":"100000000000000000","amountOut":"2217785954","minAmountOut":"2173430234","depositAddress":"0x343e292d9508A8D3f1C462f9B6C382F3dEAD296E","deadline":"2026-10-07T17:01:26.000Z"}}}"#).unwrap()
    }

    #[test]
    fn near_deposit_is_confirmed_field_by_field() {
        let now = 1_791_129_000;
        let ok = check_near(&near_status(), &near_deposit(), eth(), sol(), 100_000_000_000_000_000, EVM, SOL, now).unwrap();
        assert_eq!((ok.min_out, ok.fees_bps), (2_173_430_234, 15));
        let tampered = |path: &[&str], value: Value| {
            let mut s = near_status();
            let mut target = &mut s;
            for key in &path[..path.len() - 1] {
                target = &mut target[*key];
            }
            target[path[path.len() - 1]] = value;
            check_near(&s, &near_deposit(), eth(), sol(), 100_000_000_000_000_000, EVM, SOL, now).unwrap_err().to_string()
        };
        assert!(tampered(&["quoteResponse", "quoteRequest", "recipient"], json!("AttackerSo1anaAddress111111111111111111111111")).contains("arrivée"));
        assert!(tampered(&["quoteResponse", "quoteRequest", "refundTo"], json!("0x0000000000000000000000000000000000000001")).contains("remboursement"));
        assert!(tampered(&["quoteResponse", "quote", "depositAddress"], json!("0x0000000000000000000000000000000000000002")).contains("dépôt"));
        assert!(tampered(&["quoteResponse", "quoteRequest", "destinationAsset"], json!("nep141:btc.omft.near")).contains("cryptos"));
        assert!(tampered(&["quoteResponse", "quoteRequest", "amount"], json!("99999999999999999")).contains("montant"));
        assert!(tampered(&["quoteResponse", "quote", "minAmountOut"], json!("2000000000")).contains("minimum"));
        assert!(tampered(&["quoteResponse", "quote", "deadline"], json!("2026-10-04T16:00:00.000Z")).contains("échéance"));
        assert!(tampered(&["status"], json!("PROCESSING")).contains("attente"));
        assert!(tampered(&["quoteResponse", "quoteRequest", "depositMode"], json!("MEMO")).contains("sans memo"));
        assert!(tampered(&["quoteResponse", "quote", "depositMemo"], json!("1234567")).contains("sans memo"));
        let mut greedy = near_status();
        greedy["quoteResponse"]["quoteRequest"]["appFees"] = json!([{ "fee": 500 }]);
        assert!(check_near(&greedy, &near_deposit(), eth(), sol(), 100_000_000_000_000_000, EVM, SOL, now).unwrap_err().to_string().contains("commissions"));
    }

    fn chainflip_deposit() -> Deposit {
        Deposit {
            provider: Provider::Chainflip,
            address: "0x0093cc6c716bca51349b6bc6645ae1d064ff3f82".into(),
            channel_id: "15103632-Ethereum-49246".into(),
            expected_out: 2_215_686_583,
            min_out: 2_171_372_851,
        }
    }

    /// Real Chainflip response (2026-10-04), ETH → SOL.
    fn chainflip_status() -> Value {
        serde_json::from_str(r#"{"state":"WAITING","srcAsset":"ETH","srcChain":"Ethereum","destAsset":"SOL","destChain":"Solana","destAddress":"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM","brokers":[{"account":"cFNwtr2m","commissionBps":15}],"depositChannel":{"id":"15103632-Ethereum-49246","depositAddress":"0x0093cc6c716bca51349b6bc6645ae1d064ff3f82","estimatedExpiryTime":1791203700000,"isExpired":false},"fillOrKillParams":{"refundAddress":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045","minPrice":"21.71372851","retryDurationBlocks":150}}"#).unwrap()
    }

    #[test]
    fn chainflip_channel_is_confirmed_field_by_field() {
        let now = 1_791_129_700;
        let ok = check_chainflip(&chainflip_status(), &chainflip_deposit(), eth(), sol(), 100_000_000_000_000_000, EVM, SOL, now).unwrap();
        assert_eq!(ok.fees_bps, 15);
        assert!(ok.min_out.abs_diff(2_171_372_851) <= 1, "{}", ok.min_out);
        let tampered = |key: &str, value: Value| {
            let mut s = chainflip_status();
            s[key] = value;
            check_chainflip(&s, &chainflip_deposit(), eth(), sol(), 100_000_000_000_000_000, EVM, SOL, now).unwrap_err().to_string()
        };
        assert!(tampered("destAddress", json!("AttackerSo1anaAddress111111111111111111111111")).contains("arrivée"));
        assert!(tampered("destAsset", json!("USDC")).contains("cryptos"));
        assert!(tampered("fillOrKillParams", json!({ "refundAddress": "0x0000000000000000000000000000000000000001", "minPrice": "21.7" })).contains("remboursement"));
        assert!(tampered("fillOrKillParams", json!({ "refundAddress": EVM, "minPrice": "15" })).contains("minimum"));
        assert!(tampered("state", json!("RECEIVING")).contains("attente"));
        assert!(tampered("brokers", json!([{ "commissionBps": 300 }])).contains("commissions"));
        let mut moved = chainflip_status();
        moved["depositChannel"]["depositAddress"] = json!("0x0000000000000000000000000000000000000003");
        assert!(check_chainflip(&moved, &chainflip_deposit(), eth(), sol(), 100_000_000_000_000_000, EVM, SOL, now).unwrap_err().to_string().contains("dépôt"));
        // Amount different from the channel's: the minimum no longer holds.
        assert!(check_chainflip(&chainflip_status(), &chainflip_deposit(), eth(), sol(), 50_000_000_000_000_000, EVM, SOL, now).is_err());
    }

    #[test]
    fn deposits_are_parsed_strictly() {
        let value: Value = serde_json::from_str(r#"{"providers":["NEAR"],"txHint":"simpleTransfer","sellAsset":"ETH.ETH","buyAsset":"SOL.SOL","sourceAddress":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","destinationAddress":"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM","targetAddress":"0x343e292d9508A8D3f1C462f9B6C382F3dEAD296E","expectedBuyAmount":"2.217785954","expectedBuyAmountMaxSlippage":"2.173430235","meta":{"providerDepositChannelId":"644eedea-41f6-4e3f-835c-049a09ffd589"}}"#).unwrap();
        let deposit = parse_deposit(&value, Provider::Near, eth(), sol(), EVM, SOL).unwrap();
        assert_eq!((deposit.address.as_str(), deposit.min_out), ("0x343e292d9508A8D3f1C462f9B6C382F3dEAD296E", 2_173_430_235));
        let mut memo = value.clone();
        memo["memo"] = json!("=:e:0xattacker");
        assert!(parse_deposit(&memo, Provider::Near, eth(), sol(), EVM, SOL).is_err());
        let mut other = value.clone();
        other["destinationAddress"] = json!("AttackerSo1anaAddress111111111111111111111111");
        assert!(parse_deposit(&other, Provider::Near, eth(), sol(), EVM, SOL).is_err());
        assert!(parse_deposit(&value, Provider::Chainflip, eth(), sol(), EVM, SOL).is_err(), "fournisseur changé");
        let mut injected = value.clone();
        injected["meta"]["providerDepositChannelId"] = json!("../../admin");
        assert!(parse_deposit(&injected, Provider::Near, eth(), sol(), EVM, SOL).is_err());
    }

    /// Real network: ETH → SOL quote, deposit opened, then confirmed by NEAR Intents
    /// and by Chainflip (no funds sent). Requires the SwapKit key.
    /// `cargo test -- --ignored real_swapkit_deposits --nocapture`
    #[test]
    #[ignore]
    fn real_swapkit_deposits_are_confirmed_by_their_provider() {
        assert!(enabled(), "clé SwapKit absente de partner-keys.env");
        let amount = 100_000_000_000_000_000;
        let routes = quote(eth(), sol(), amount, EVM, SOL).unwrap();
        for provider in [Provider::Near, Provider::Chainflip] {
            let route = routes.iter().find(|r| r.provider == provider).unwrap_or_else(|| panic!("pas de route {provider:?}"));
            let deposit = open_deposit(route, eth(), sol(), EVM, SOL).unwrap();
            let verified = verify(&deposit, eth(), sol(), amount, EVM, SOL).unwrap();
            println!("{} : dépôt {} ; minimum {} SOL ; commissions {} pb", provider.name(), deposit.address, verified.min_out as f64 / 1e9, verified.fees_bps);
            assert_eq!(status(provider, &deposit.channel_id, &deposit.address).unwrap(), SwapState::AwaitingDeposit);
            // Arrival address other than the channel's: refused.
            assert!(verify(&deposit, eth(), sol(), amount, EVM, "So11111111111111111111111111111111111111112").is_err());
        }
    }

    /// Real network: NEAR → ETH deposit opened with NEAR Intents (no funds sent), a
    /// plain transfer to an implicit account, confirmed by NEAR.
    /// `cargo test -- --ignored real_swapkit_near --nocapture`
    #[test]
    #[ignore]
    fn real_swapkit_near_deposit() {
        assert!(enabled(), "clé SwapKit absente de partner-keys.env");
        let near = find("near", "near_mainnet").unwrap();
        let source = "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412";
        let amount = 10_000_000_000_000_000_000_000_000;
        let routes = quote(near, eth(), amount, source, EVM).unwrap();
        let route = routes.iter().find(|r| r.provider == Provider::Near).expect("pas de route NEAR");
        let deposit = open_deposit(route, near, eth(), source, EVM).unwrap();
        crate::near::parse_account(&deposit.address).unwrap();
        let verified = verify(&deposit, near, eth(), amount, source, EVM).unwrap();
        println!("NEAR → ETH : dépôt {} ; minimum {} ETH ; commissions {} pb", deposit.address, verified.min_out as f64 / 1e18, verified.fees_bps);
        assert_eq!(status(Provider::Near, &deposit.channel_id, &deposit.address).unwrap(), SwapState::AwaitingDeposit);
        // Reverse direction: arrival on the implicit account.
        let back = quote(eth(), near, 50_000_000_000_000_000, EVM, source).unwrap();
        assert!(back.iter().any(|r| r.provider == Provider::Near));
    }

    /// Real network: ADA → ETH deposit opened with NEAR Intents (no funds sent); an
    /// addr1... deposit address with a payment key (not a contract).
    /// `cargo test -- --ignored real_swapkit_ada --nocapture`
    #[test]
    #[ignore]
    fn real_swapkit_ada_deposit() {
        assert!(enabled(), "clé SwapKit absente de partner-keys.env");
        let ada = find("ada", "ada_mainnet").unwrap();
        let source = "addr1qxl2jwckw20u69f0cq0vkrnuztx93hcmpwswja60txpnxrunu8tugxe0030m7uyvnz3hlppj4e28jyl9c94cque0gavquchxun";
        let amount = 100_000_000;
        let routes = quote(ada, eth(), amount, source, EVM).unwrap();
        let route = routes.iter().find(|r| r.provider == Provider::Near).expect("pas de route NEAR");
        let deposit = open_deposit(route, ada, eth(), source, EVM).unwrap();
        crate::cardano::parse_address(&deposit.address).unwrap();
        let verified = verify(&deposit, ada, eth(), amount, source, EVM).unwrap();
        println!("ADA → ETH : dépôt {} ; minimum {} ETH ; commissions {} pb", deposit.address, verified.min_out as f64 / 1e18, verified.fees_bps);
        assert_eq!(status(Provider::Near, &deposit.channel_id, &deposit.address).unwrap(), SwapState::AwaitingDeposit);
        assert!(quote(eth(), ada, 50_000_000_000_000_000, EVM, source).unwrap().iter().any(|r| r.provider == Provider::Near));
    }

    /// Real network: XRP → ETH deposit opened with NEAR Intents (no funds sent); a
    /// plain r... address, without a tag or memo, confirmed by NEAR.
    /// `cargo test -- --ignored real_swapkit_xrp --nocapture`
    #[test]
    #[ignore]
    fn real_swapkit_xrp_deposit() {
        assert!(enabled(), "clé SwapKit absente de partner-keys.env");
        let xrp = find("xrp", "xrp_mainnet").unwrap();
        // An account that does not require a tag (NEAR refuses those that do).
        let source = "rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1";
        let amount = 20_000_000;
        let routes = quote(xrp, eth(), amount, source, EVM).unwrap();
        let route = routes.iter().find(|r| r.provider == Provider::Near).expect("pas de route NEAR");
        let deposit = open_deposit(route, xrp, eth(), source, EVM).unwrap();
        crate::xrp::parse_address(&deposit.address).unwrap();
        let verified = verify(&deposit, xrp, eth(), amount, source, EVM).unwrap();
        println!("dépôt {} ; minimum {} ETH ; commissions {} pb", deposit.address, verified.min_out as f64 / 1e18, verified.fees_bps);
        assert_eq!(status(Provider::Near, &deposit.channel_id, &deposit.address).unwrap(), SwapState::AwaitingDeposit);
    }
}
