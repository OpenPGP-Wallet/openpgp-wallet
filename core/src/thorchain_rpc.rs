//! Minimal THORChain client: only what is needed to get a swap quote (read-only, no
//! signing, no secrets involved). THORChain is the external protocol that makes
//! cross-chain swaps possible (BTC/ETH/SOL have no native way to swap with each
//! other).
//!
//! The quote already comes with a `memo` built by THORChain itself: this module
//! NEVER rebuilds that format by hand, so there is no risk of a formatting mistake
//! sending real funds into an invalid swap.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
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

/// Public THORChain gateway operated by Liquify: no key needed for a quote,
/// read-only endpoint. Checked with a real call before being written here:
/// `thornode.ninerealms.com` (often quoted in the docs and older articles) no
/// longer resolved at all at the time of writing, one more proof that a third-party
/// hostname should never be trusted without testing it live.
const THORNODE_BASE: &str = "https://gateway.liquify.com/chain/thorchain_api";

/// THORChain (RUNE) address that receives the affiliate fees of EVERY swap made
/// from this app, whichever installation triggers it: a single fixed address (the
/// developer's), not one derived per installation (otherwise every user would be
/// paying themselves). Derived once through `api::get_thor_fee_address` (see
/// Settings) and checked by the developer before being frozen here.
pub const AFFILIATE_ADDRESS: &str = "thor12j5rrcflhffxmq0ekwvk0h7g0mdy8gn4fg0w3e";

/// THORName (short alias) of `AFFILIATE_ADDRESS`, registered by the developer from
/// the app (Settings, see `native_deposit`). Essential for affiliate fees FROM
/// Bitcoin: the memo has to fit in 80 bytes (OP_RETURN), and the full `thor1…`
/// address (43 characters) made it overflow, as seen on 2026-10-01 ("generated memo
/// too long for source chain"). Only used once it has been read back from the
/// network (exists, not expired, THOR alias = `AFFILIATE_ADDRESS`, see
/// `verified_name`): before it is registered, or if it expires, the app falls back
/// to the full address on its own (and no fee from Bitcoin), without a new release.
/// 2 characters: the largest possible margin in memos (all one-letter names are
/// taken).
pub const AFFILIATE_NAME: Option<&str> = Some("ow");

/// The developer's MAYAName on Maya (same name, same rule), MAYA alias =
/// `MAYA_AFFILIATE_ADDRESS`: affiliate fees from Bitcoin and Zcash.
pub const MAYA_AFFILIATE_NAME: Option<&str> = Some("ow");

/// Number of blocks per year both protocols use for a name's lifetime (a
/// registration includes one year; taken from real registrations).
pub const NAME_BLOCKS_PER_YEAR: u64 = 5_256_000;

/// 80 basis points = 0.80%.
pub const AFFILIATE_FEE_BPS: u32 = 80;

/// An app crypto that can be swapped through THORChain: card identifier, network,
/// and THORChain notation (available pools checked live on 2026-10-01).
pub struct ThorAsset {
    pub coin: &'static str,
    pub network: &'static str,
    pub symbol: &'static str,
    /// `CHAIN.TICKER`, or `CHAIN.TICKER-0XCONTRACT` for a token.
    pub asset: &'static str,
    /// Short code a memo uses for a native asset (taken from real quotes: "s" means
    /// BNB, not SOL).
    pub short_code: Option<&'static str>,
    /// The asset's native decimals (THORChain always counts in 1e8, see
    /// `to_thorchain_amount`).
    pub decimals: u32,
    /// ERC-20 token: contract (deposit through `approve`, then `depositWithExpiry`).
    pub contract: Option<&'static str>,
}

const fn native(
    coin: &'static str,
    network: &'static str,
    symbol: &'static str,
    asset: &'static str,
    short: &'static str,
    decimals: u32,
) -> ThorAsset {
    ThorAsset {
        coin,
        network,
        symbol,
        asset,
        short_code: Some(short),
        decimals,
        contract: None,
    }
}

const fn erc20(
    coin: &'static str,
    network: &'static str,
    symbol: &'static str,
    asset: &'static str,
    decimals: u32,
    contract: &'static str,
) -> ThorAsset {
    ThorAsset {
        coin,
        network,
        symbol,
        asset,
        short_code: None,
        decimals,
        contract: Some(contract),
    }
}

pub const ASSETS: [ThorAsset; 12] = [
    native("btc", "btc_mainnet", "BTC", "BTC.BTC", "b", 8),
    // Dogecoin ("d", taken from a real quote on 2026-10-04: memo `=:d:D…`): as a
    // destination only (see `swap_routes::BUY_ONLY`).
    native("doge", "doge_mainnet", "DOGE", "DOGE.DOGE", "d", 8),
    native("evm", "evm_mainnet", "ETH", "ETH.ETH", "e", 18),
    native("evm", "base_mainnet", "ETH", "BASE.ETH", "f", 18),
    native("sol", "sol_mainnet", "SOL", "SOL.SOL", "o", 9),
    native("bnb", "bsc_mainnet", "BNB", "BSC.BNB", "s", 18),
    native("avax", "avax_mainnet", "AVAX", "AVAX.AVAX", "a", 18),
    erc20(
        "usdc",
        "evm_mainnet",
        "USDC",
        "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
        6,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    ),
    erc20(
        "usdt",
        "evm_mainnet",
        "USDT",
        "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
        6,
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
    ),
    erc20(
        "dai",
        "evm_mainnet",
        "DAI",
        "ETH.DAI-0X6B175474E89094C44DA98B954EEDEAC495271D0F",
        18,
        "0x6b175474e89094c44da98b954eedeac495271d0f",
    ),
    erc20(
        "usdc",
        "base_mainnet",
        "USDC",
        "BASE.USDC-0X833589FCD6EDB6E08F4C7C32D4F71B54BDA02913",
        6,
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    ),
    erc20(
        "vvv",
        "base_mainnet",
        "VVV",
        "BASE.VVV-0XACFE6019ED1A7DC6F7B508C02D1B04EC88CC21BF",
        18,
        "0xacfe6019ed1a7dc6f7b508c02d1b04ec88cc21bf",
    ),
];

/// THORChain asset for one of the app's cryptos on a network.
pub fn asset(coin: &str, network: &str) -> Option<&'static ThorAsset> {
    THORCHAIN.asset(coin, network)
}

/// Affiliate address on Maya: the SAME key as `AFFILIATE_ADDRESS` (same hash160,
/// only the bech32 prefix changes; test
/// `maya_affiliate_is_the_same_key_as_thorchain`).
pub const MAYA_AFFILIATE_ADDRESS: &str = "maya12j5rrcflhffxmq0ekwvk0h7g0mdy8gn4fl3z8f";

/// Pools available on Maya, checked live on 2026-10-01. Maya's own short codes,
/// taken from real quotes: "a" there means Arbitrum ETH (on THORChain, "a" is
/// AVAX). ZEC ("z", taken from Mayanode's `Asset::ShortCode`, pool checked on
/// 2026-10-02): both ways, with no app fee when selling ZEC (see `swap_routes`).
pub const MAYA_ASSETS: [ThorAsset; 7] = [
    native("btc", "btc_mainnet", "BTC", "BTC.BTC", "b", 8),
    native("evm", "evm_mainnet", "ETH", "ETH.ETH", "e", 18),
    native("evm", "arbitrum_mainnet", "ETH", "ARB.ETH", "a", 18),
    erc20(
        "usdc",
        "evm_mainnet",
        "USDC",
        "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
        6,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    ),
    erc20(
        "usdt",
        "evm_mainnet",
        "USDT",
        "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
        6,
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
    ),
    erc20(
        "usdc",
        "arbitrum_mainnet",
        "USDC",
        "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
        6,
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
    ),
    native("zec", "zec_mainnet", "ZEC", "ZEC.ZEC", "z", 8),
];

/// A cross-chain swap protocol from the THORChain family: THORChain and its fork
/// Maya (same quote API, same memo format, same `depositWithExpiry` EVM routers);
/// each has its own gateway, affiliate, pools and short codes.
pub struct CrossChain {
    pub name: &'static str,
    node_base: &'static str,
    /// API route prefix ("thorchain", "mayachain").
    module: &'static str,
    /// Native chain for name aliases ("THOR", "MAYA").
    native_chain: &'static str,
    /// Name resolution route ("thorname", "mayaname").
    name_route: &'static str,
    pub affiliate_address: &'static str,
    /// The affiliate's short name, essential for swaps from Bitcoin (see
    /// `AFFILIATE_NAME`).
    pub affiliate_name: Option<&'static str>,
    pub assets: &'static [ThorAsset],
}

pub const THORCHAIN: CrossChain = CrossChain {
    name: "THORChain",
    node_base: THORNODE_BASE,
    module: "thorchain",
    native_chain: "THOR",
    name_route: "thorname",
    affiliate_address: AFFILIATE_ADDRESS,
    affiliate_name: AFFILIATE_NAME,
    assets: &ASSETS,
};

pub const MAYA: CrossChain = CrossChain {
    name: "Maya",
    // Public Maya node (checked live: quotes, inbound addresses).
    node_base: "https://mayanode.mayachain.info",
    module: "mayachain",
    native_chain: "MAYA",
    name_route: "mayaname",
    affiliate_address: MAYA_AFFILIATE_ADDRESS,
    affiliate_name: MAYA_AFFILIATE_NAME,
    assets: &MAYA_ASSETS,
};

/// State of a chain in `inbound_addresses` (Maya has no pause fields: false by
/// default).
#[derive(Deserialize)]
struct InboundStatusJson {
    chain: String,
    #[serde(default)]
    halted: bool,
    #[serde(default)]
    chain_trading_paused: bool,
    #[serde(default)]
    global_trading_paused: bool,
}

/// Current halts (see `CrossChain::halts`); `all`: global pause.
struct Halts {
    all: bool,
    chains: Vec<String>,
}

impl Halts {
    fn from_statuses(chains: Vec<InboundStatusJson>) -> Self {
        Halts {
            all: chains.iter().any(|c| c.global_trading_paused),
            chains: chains
                .into_iter()
                .filter(|c| c.halted || c.chain_trading_paused)
                .map(|c| c.chain)
                .collect(),
        }
    }

    fn covers(&self, asset: &str) -> bool {
        self.all || self.chains.iter().any(|c| c == chain_of(asset))
    }
}

/// "THORChain has paused swaps on Solana for now…" (networks left out if unknown).
pub fn halted_message(protocol: &str, networks: &[&str]) -> String {
    let place = if networks.is_empty() {
        String::new()
    } else {
        format!(" sur {}", networks.join(" et "))
    };
    format!("{protocol} a suspendu les échanges{place} pour le moment (incident ou maintenance de son côté) — réessayez plus tard ou choisissez un autre fournisseur")
}

/// Chain of an asset: "SOL" for `SOL.SOL`, "ETH" for `ETH.USDC-0X…`.
fn chain_of(asset: &str) -> &str {
    asset.split('.').next().unwrap_or(asset)
}

/// Source chains whose memo travels in an OP_RETURN output, limited to 80 bytes:
/// Bitcoin, Dogecoin, and Zcash on Maya (recorded on 2026-10-03: a 102-byte memo
/// with the full `maya1…` affiliate, refused).
fn memo_in_op_return(asset: &str) -> bool {
    matches!(chain_of(asset), "BTC" | "ZEC" | "DOGE")
}

/// Network name of a chain, for messages.
fn chain_label(chain: &str) -> &str {
    match chain {
        "BTC" => "Bitcoin",
        "ETH" => "Ethereum",
        "SOL" => "Solana",
        "BASE" => "Base",
        "ARB" => "Arbitrum",
        "AVAX" => "Avalanche",
        "BSC" => "BNB Chain",
        "ZEC" => "Zcash",
        "DOGE" => "Dogecoin",
        other => other,
    }
}

#[derive(Deserialize)]
struct ThorNameJson {
    #[serde(default)]
    aliases: Vec<ThorNameAlias>,
    expire_block_height: Option<i64>,
    #[serde(default)]
    owner: String,
}

/// Short name as registered on the protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct NameRecord {
    pub owner: String,
    pub expire_height: i64,
    pub current_height: i64,
    /// Alias on the native chain = the app's affiliate address.
    pub points_to_affiliate: bool,
}

impl NameRecord {
    pub fn expired(&self) -> bool {
        self.expire_height <= self.current_height
    }
}

/// Affiliate for a quote from `from_asset`: the verified short name, otherwise the
/// full address, except from an OP_RETURN chain, where it would overflow the memo:
/// no affiliate (fee-free swap for the app).
fn choose_affiliate(
    verified_name: Option<&'static str>,
    address: &'static str,
    from_asset: &str,
) -> Option<&'static str> {
    match verified_name {
        Some(name) => Some(name),
        None if memo_in_op_return(from_asset) => None,
        None => Some(address),
    }
}

/// A success is kept for the session; a failure (name not registered yet, network
/// unreachable) is checked again after this delay.
const NAME_RECHECK: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Deserialize)]
struct ThorNameAlias {
    chain: String,
    address: String,
}

/// Name resolution response (`None`: does not exist): owner, expiry, and whether
/// the native chain alias is the affiliate address.
fn parse_name(
    body: &str,
    current_height: i64,
    native_chain: &str,
    affiliate_address: &str,
) -> Result<Option<NameRecord>> {
    if body.contains("doesn't exist") {
        return Ok(None);
    }
    let parsed: ThorNameJson = serde_json::from_str(body).context("nom illisible")?;
    Ok(Some(NameRecord {
        points_to_affiliate: parsed
            .aliases
            .iter()
            .any(|a| a.chain == native_chain && a.address == affiliate_address),
        owner: parsed.owner,
        expire_height: parsed.expire_block_height.unwrap_or(0),
        current_height,
    }))
}

impl CrossChain {
    pub fn asset(&self, coin: &str, network: &str) -> Option<&'static ThorAsset> {
        self.assets
            .iter()
            .find(|a| a.coin == coin && a.network == network)
    }

    /// Affiliate to put in a quote from `from_asset` (see `choose_affiliate`).
    pub fn affiliate_for(&self, from_asset: &str) -> Option<&'static str> {
        choose_affiliate(self.verified_name(), self.affiliate_address, from_asset)
    }

    /// Are affiliate fees taken on a swap from `from_asset`? Yes, except from Bitcoin
    /// or Zcash as long as the short name is not registered and verified (4-field
    /// memo).
    pub fn charges_affiliate(&self, from_asset: &str) -> bool {
        self.affiliate_for(from_asset).is_some()
    }

    /// Native chain for name aliases ("THOR", "MAYA").
    pub fn native_chain(&self) -> &'static str {
        self.native_chain
    }

    /// Short name read back from the protocol: it must exist, not be expired, and point
    /// to the affiliate address, otherwise the fees would go to someone else (see
    /// `NAME_RECHECK`). Unit tests: never verified (no network calls).
    fn verified_name(&self) -> Option<&'static str> {
        let name = self.affiliate_name?;
        if cfg!(test) {
            return None;
        }
        type Checked =
            std::sync::Mutex<std::collections::HashMap<&'static str, (bool, std::time::Instant)>>;
        static CHECKED: OnceLock<Checked> = OnceLock::new();
        let cache = CHECKED.get_or_init(Default::default);
        if let Some((ok, at)) = cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(self.module)
            .copied()
        {
            if ok || at.elapsed() < NAME_RECHECK {
                return ok.then_some(name);
            }
        }
        let ok = matches!(self.name_record(name), Ok(Some(record)) if record.points_to_affiliate && !record.expired());
        cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(self.module, (ok, std::time::Instant::now()));
        ok.then_some(name)
    }

    /// Name `name` on this protocol (`None` if it does not exist), with the network's
    /// current height.
    pub fn name_record(&self, name: &str) -> Result<Option<NameRecord>> {
        let label = self.name;
        let body = shared_client()
            .get(format!(
                "{}/{}/{}/{name}",
                self.node_base, self.module, self.name_route
            ))
            .send()
            .with_context(|| format!("nœud {label} injoignable"))?
            .text()
            .with_context(|| format!("réponse {label} illisible"))?;
        if body.contains("doesn't exist") {
            return Ok(None);
        }
        let height: Vec<serde_json::Value> = shared_client()
            .get(format!("{}/{}/lastblock", self.node_base, self.module))
            .send()
            .with_context(|| format!("nœud {label} injoignable"))?
            .json()
            .with_context(|| format!("hauteur {label} illisible"))?;
        let current_height = height
            .first()
            .and_then(|b| b.get(self.module))
            .and_then(serde_json::Value::as_i64)
            .context("hauteur du réseau illisible")?;
        parse_name(
            &body,
            current_height,
            self.native_chain,
            self.affiliate_address,
        )
        .with_context(|| format!("nom {name} illisible chez {label}"))
    }

    /// Chains where swaps are currently halted (chain stopped or trading paused:
    /// incident, maintenance), read from `inbound_addresses`.
    fn halts(&self) -> Result<Halts> {
        let name = self.name;
        let url = format!("{}/{}/inbound_addresses", self.node_base, self.module);
        let chains: Vec<InboundStatusJson> = shared_client()
            .get(&url)
            .send()
            .with_context(|| format!("état des réseaux {name} illisible"))?
            .json()
            .with_context(|| format!("état des réseaux {name} illisible"))?;
        Ok(Halts::from_statuses(chains))
    }

    /// Assets of this protocol that it is not swapping right now.
    pub fn halted_assets(&self) -> Result<Vec<&'static ThorAsset>> {
        let halts = self.halts()?;
        Ok(self
            .assets
            .iter()
            .filter(|a| halts.covers(a.asset))
            .collect())
    }

    /// Swap refused because a chain is halted: which one, in plain words (read live;
    /// not named if the read fails).
    fn halt_message(&self, from_asset: &str, to_asset: &str) -> String {
        let mut networks: Vec<&str> = match self.halts() {
            Ok(halts) => [from_asset, to_asset]
                .into_iter()
                .filter(|a| halts.covers(a))
                .map(|a| chain_label(chain_of(a)))
                .collect(),
            Err(_) => Vec::new(),
        };
        networks.dedup();
        halted_message(self.name, &networks)
    }
}

/// Minimum required output, in basis points BELOW the expected output (1% here).
/// Passed through `liquidity_tolerance_bps`, NOT `tolerance_bps`. Checked live:
/// `tolerance_bps` applies to the price BEFORE fees, so with 100 bps the limit
/// (3,166,856) was already above the expected output (3,161,977) once fees were
/// deducted, and the swap would always have been refunded (network fees wasted).
/// `liquidity_tolerance_bps` gives exactly limit = expected output × (1 −
/// tolerance) (ratios 0.995 / 0.99 / 0.97 measured for 50 / 100 / 300 bps). With no
/// tolerance at all (the previous behavior), the memo had an EMPTY limit: the swap
/// accepted any rate, exposed to a sandwich or price manipulation during the
/// minutes a cross-chain swap takes.
pub const SWAP_TOLERANCE_BPS: u32 = 100;

pub struct SwapQuote {
    /// Vault address to send the source asset to: ALWAYS read live, never cached, since
    /// these addresses rotate regularly.
    pub inbound_address: String,
    /// Address of the "THORChain Router" contract to call for an EVM swap (NEVER send
    /// directly to `inbound_address` on an EVM chain: `depositWithExpiry` must be
    /// called on this contract, see `eth_tx::thorchain_deposit_calldata`). Absent for
    /// non-EVM chains (BTC, SOL...), and always read live like `inbound_address`, since
    /// these contracts are versioned and can change. Checked live: the same value is
    /// also exposed by `/thorchain/inbound_addresses`.
    pub router: Option<String>,
    /// Ready-to-use memo, built by THORChain: never rebuilt by hand on the client side
    /// (see the module docs).
    pub memo: String,
    /// Expected output amount, in the destination asset's smallest unit (8 decimals for
    /// most THORChain assets).
    pub expected_amount_out: u64,
    /// Total THORChain fees (network + liquidity + affiliate), purely informational for
    /// display; already deducted from `expected_amount_out`, never to be subtracted a
    /// second time.
    pub total_fees: Option<u64>,
    /// Recommended fee rate for the deposit (sat/vB on Bitcoin), below which the
    /// protocol may be slow to see it.
    pub recommended_gas_rate: Option<u64>,
    /// Affiliate the app asked for in this quote (short name or address), required as
    /// is in the memo; `None`: fee-free swap for the app.
    pub affiliate: Option<String>,
}

#[derive(Deserialize)]
struct QuoteResponseJson {
    inbound_address: Option<String>,
    router: Option<String>,
    memo: Option<String>,
    expected_amount_out: Option<String>,
    fees: Option<FeesJson>,
    recommended_gas_rate: Option<String>,
    /// Amount below which a deposit is ignored (funds lost), and the recommended
    /// minimum (below it, a refund may fail), in 1e8.
    dust_threshold: Option<String>,
    recommended_min_amount_in: Option<String>,
    /// Present (with `code`) on a real error response, checked against a live call:
    /// `{"code":3,"message":"...","details":[]}`, NOT an `error` field as convention
    /// might suggest.
    code: Option<i64>,
    message: Option<String>,
    /// Error in Maya's format (single field).
    error: Option<String>,
}

#[derive(Deserialize)]
struct FeesJson {
    total: Option<String>,
}

/// THORChain represents ALL amounts with a fixed precision of 8 decimals ("1e8"),
/// whatever the native precision of the source/destination chain (9 for SOL, 18 for
/// ETH, 8 for BTC, 6 for USDC), as documented in the THORChain spec. This
/// conversion must ALWAYS go through this function before calling `quote_swap`,
/// never be recomputed by hand elsewhere (a mistake here would skew the amount
/// actually swapped by a factor of 10, 100 or more).
pub fn to_thorchain_amount(native_amount: u128, native_decimals: u32) -> Result<u64> {
    const THORCHAIN_DECIMALS: u32 = 8;
    let converted = if native_decimals >= THORCHAIN_DECIMALS {
        native_amount / 10u128.pow(native_decimals - THORCHAIN_DECIMALS)
    } else {
        native_amount
            .checked_mul(10u128.pow(THORCHAIN_DECIMALS - native_decimals))
            .context("montant trop grand pour la conversion vers la précision THORChain (1e8)")?
    };
    u64::try_from(converted)
        .context("montant converti trop grand pour la précision THORChain (1e8)")
}

/// `from_asset`/`to_asset` in THORChain format (`CHAIN.ASSET`, e.g. `BTC.BTC`,
/// `ETH.ETH`, `SOL.SOL`, or `CHAIN.TICKER-0XCONTRACT` for a token, see the tables
/// above). `amount` in the source asset's smallest unit. `destination`: the user's
/// address on the destination chain (one of their own addresses, never the
/// developer's).
pub fn quote_swap(
    from_asset: &str,
    to_asset: &str,
    amount: u64,
    destination: &str,
) -> Result<SwapQuote> {
    THORCHAIN.quote_swap(from_asset, to_asset, amount, destination)
}

/// See `CrossChain::verify_swap_memo` (THORChain).
pub fn verify_swap_memo(
    memo: &str,
    to_asset: &str,
    destination: &str,
    expected_amount_out: u64,
) -> Result<()> {
    THORCHAIN.verify_swap_memo(memo, to_asset, destination, expected_amount_out)
}

impl CrossChain {
    /// Swap quote (see `quote_swap`), memo verified before any use, with the affiliate
    /// chosen by `affiliate_for`. From Bitcoin or Zcash, a large swap split up by the
    /// protocol (memo extended with "/0/2147", recorded on 2026-10-03) may no longer
    /// fit in 80 bytes even with the short name: a new quote without an affiliate is
    /// requested (fee-free, stated in the confirmation dialog) rather than refusing.
    pub fn quote_swap(
        &self,
        from_asset: &str,
        to_asset: &str,
        amount: u64,
        destination: &str,
    ) -> Result<SwapQuote> {
        let affiliate = self.affiliate_for(from_asset);
        match self.quote_swap_as(from_asset, to_asset, amount, destination, affiliate) {
            Err(e)
                if affiliate.is_some()
                    && memo_in_op_return(from_asset)
                    && e.to_string().contains("memo too long") =>
            {
                self.quote_swap_as(from_asset, to_asset, amount, destination, None)
            }
            other => other,
        }
    }

    /// Quote with the affiliate `affiliate` imposed (`None`: fee-free), to reread a
    /// quote after confirmation under the conditions shown.
    pub fn quote_swap_as(
        &self,
        from_asset: &str,
        to_asset: &str,
        amount: u64,
        destination: &str,
        affiliate: Option<&str>,
    ) -> Result<SwapQuote> {
        let name = self.name;
        let affiliate_query = affiliate
            .map(|a| format!("&affiliate={a}&affiliate_bps={AFFILIATE_FEE_BPS}"))
            .unwrap_or_default();
        let url = format!(
            "{}/{}/quote/swap?from_asset={from_asset}&to_asset={to_asset}&amount={amount}&destination={destination}{affiliate_query}&liquidity_tolerance_bps={SWAP_TOLERANCE_BPS}",
            self.node_base, self.module
        );
        let response: QuoteResponseJson = shared_client()
            .get(&url)
            .send()
            .with_context(|| format!("requête de devis {name} impossible"))?
            .json()
            .with_context(|| format!("réponse de devis {name} illisible"))?;

        // Error: `code` + `message` on THORChain, `error` alone on Maya (seen in practice:
        // without this field, Maya's message was lost).
        if response.code.is_some() || response.error.is_some() {
            let message = response
                .message
                .or(response.error)
                .unwrap_or_else(|| "raison inconnue".to_string());
            // "trading is halted, can't process swap" (seen on 2026-10-02: Solana halted on
            // THORChain).
            if message.contains("halted") {
                anyhow::bail!("{}", self.halt_message(from_asset, to_asset));
            }
            anyhow::bail!("devis {name} refusé : {message}");
        }

        let inbound_address = response
            .inbound_address
            .ok_or_else(|| anyhow!("devis {name} sans adresse de vault"))?;
        let memo = response
            .memo
            .ok_or_else(|| anyhow!("devis {name} sans memo"))?;
        let expected_amount_out = response
            .expected_amount_out
            .ok_or_else(|| anyhow!("devis {name} sans montant de sortie attendu"))?
            .parse::<u64>()
            .context("montant de sortie attendu illisible")?;
        let total_fees = response
            .fees
            .and_then(|f| f.total)
            .and_then(|s| s.parse::<u64>().ok());
        let number = |field: &Option<String>| field.as_deref().and_then(|s| s.parse::<u64>().ok());

        // Below the dust threshold, the deposit is ignored and the funds would be lost
        // (recorded: 10,000 on Maya for BTC and ZEC, 1,000 on THORChain).
        let minimum =
            number(&response.dust_threshold).max(number(&response.recommended_min_amount_in));
        if let Some(minimum) = minimum.filter(|m| amount < *m) {
            anyhow::bail!(
                "montant trop faible pour {name} : au moins {} {} (en dessous, le dépôt serait ignoré ou son remboursement impossible)",
                format_1e8(minimum),
                ticker(from_asset)
            );
        }

        self.verify_memo(&memo, affiliate, to_asset, destination, expected_amount_out)?;

        Ok(SwapQuote {
            inbound_address,
            router: response.router,
            memo,
            expected_amount_out,
            total_fees,
            recommended_gas_rate: number(&response.recommended_gas_rate),
            affiliate: affiliate.map(str::to_string),
        })
    }
}

/// Amount in 1e8, human-readable ("0.0013944").
fn format_1e8(amount: u64) -> String {
    let text = format!("{}.{:08}", amount / 100_000_000, amount % 100_000_000);
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Symbol of an asset ("BTC", "USDC" for `ETH.USDC-0X…`).
fn ticker(asset: &str) -> &str {
    let ticker = asset.split_once('.').map_or(asset, |(_, t)| t);
    ticker.split_once('-').map_or(ticker, |(t, _)| t)
}

/// Does a memo's asset designate `to_asset`? Forms seen in real quotes: full
/// notation, short code for a native asset ("e", "b", "s" = BNB, "a", "f" = ETH on
/// Base; "o" = SOL, from the THORNode source code), or `CHAIN.TICKER` without the
/// contract for a token ("ETH.USDC", "BASE.VVV": THORChain resolves it to its pool
/// for that token). Short codes are specific to each protocol ("a" = AVAX on
/// THORChain, Arbitrum ETH on Maya).
fn memo_asset_matches(assets: &[ThorAsset], field: &str, to_asset: &str) -> bool {
    if field.eq_ignore_ascii_case(to_asset) {
        return true;
    }
    if assets
        .iter()
        .any(|a| a.asset.eq_ignore_ascii_case(to_asset) && a.short_code == Some(field))
    {
        return true;
    }
    to_asset
        .split_once('-')
        .is_some_and(|(ticker, _)| field.eq_ignore_ascii_case(ticker))
}

/// Checks that the memo returned by the THORChain gateway does EXACTLY what the
/// user confirmed. Found during the "known hot wallet weaknesses" audit (the "what
/// you sign differs from what you see" class, behind the biggest recent losses):
/// the confirmation dialog shows the destination ENTERED by the user, but the
/// transaction carries the memo supplied by a third party, which was never reread.
/// A compromised gateway could therefore return a memo sending the swap output to
/// ITS own address, or inflating the affiliate fee (e.g. 5000 bps = 50% of the
/// swap), with nothing to stop it. This module still never rebuilds the memo by
/// hand (see its docs): it READS it and refuses it if it does not match.
///
/// Expected format, checked live (`=:b:bc1q...:3146167:thor1...:80`) and in the
/// THORNode source code: `TYPE:ASSET:DESTINATION:LIMIT:AFFILIATE:BPS`, exactly 6
/// fields. Any extra field is refused: THORChain accepts DEX aggregator fields
/// after the 6th (intermediate contract, final token, minimum output) that would
/// redirect the output elsewhere. Without an affiliate fee (departure from Bitcoin
/// or Zcash, see `choose_affiliate`): exactly the first 4 fields (recorded live:
/// `=:e:0x59D7…E6ba:31290403`), and an unexpected affiliate is refused. With one:
/// the 5th field must be EXACTLY the affiliate the app asked for (address, or
/// verified short name), otherwise a gateway could swap in a short name registered
/// by someone else.
impl CrossChain {
    /// Memo of a swap with our affiliate fee at the full address.
    pub fn verify_swap_memo(
        &self,
        memo: &str,
        to_asset: &str,
        destination: &str,
        expected_amount_out: u64,
    ) -> Result<()> {
        self.verify_memo(
            memo,
            Some(self.affiliate_address),
            to_asset,
            destination,
            expected_amount_out,
        )
    }

    /// Memo of a swap with the requested affiliate `affiliate` (`None`: without).
    pub fn verify_memo(
        &self,
        memo: &str,
        affiliate: Option<&str>,
        to_asset: &str,
        destination: &str,
        expected_amount_out: u64,
    ) -> Result<()> {
        let fields: Vec<&str> = memo.split(':').collect();
        let expected_fields = if affiliate.is_some() { 6 } else { 4 };
        anyhow::ensure!(
            fields.len() == expected_fields,
            "memo THORChain inattendu ({} champs au lieu de {expected_fields}) : {memo}",
            fields.len()
        );

        // Aliases of the "swap" type in the THORNode source code (`memo.go`): "swap", "s",
        // "=".
        anyhow::ensure!(
            matches!(fields[0].to_ascii_lowercase().as_str(), "=" | "s" | "swap"),
            "memo THORChain qui n'est pas un swap : {memo}"
        );

        anyhow::ensure!(
            memo_asset_matches(self.assets, fields[1], to_asset),
            "le memo THORChain vise un autre actif ({}) que celui demandé ({to_asset})",
            fields[1]
        );

        // EVM addresses (hex) are case-insensitive; base58 (Solana) is case-SENSITIVE, and
        // bech32 (Bitcoin) is compared as is (always lowercase here).
        let dest_ok = if destination.starts_with("0x") {
            fields[2].eq_ignore_ascii_case(destination)
        } else {
            fields[2] == destination
        };
        anyhow::ensure!(
        dest_ok,
        "le memo THORChain enverrait les fonds à une AUTRE adresse ({}) que celle confirmée ({destination}) — swap refusé",
        fields[2]
    );

        // "LIMIT" or "LIMIT/INTERVAL/QUANTITY" (streaming swap).
        let limit: u64 = fields[3]
            .split('/')
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|_| {
                anyhow!(
                    "memo THORChain sans sortie minimale exploitable (« {} ») — swap refusé",
                    fields[3]
                )
            })?;
        // 5 bps margin for rounding on THORChain's side (ratios measured exact to within
        // 1e-5).
        let min_acceptable =
            u128::from(expected_amount_out) * u128::from(10_000 - SWAP_TOLERANCE_BPS - 5) / 10_000;
        anyhow::ensure!(
        limit > 0 && u128::from(limit) >= min_acceptable,
        "sortie minimale du memo THORChain ({limit}) trop basse par rapport à la sortie attendue ({expected_amount_out}) — swap refusé"
    );

        if let Some(affiliate) = affiliate {
            let ours =
                affiliate == self.affiliate_address || self.affiliate_name == Some(affiliate);
            anyhow::ensure!(
                ours && fields[4] == affiliate && fields[5] == AFFILIATE_FEE_BPS.to_string(),
                "frais d'affiliation du memo THORChain inattendus ({}:{}) — swap refusé",
                fields[4],
                fields[5]
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_BTC: &str = "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz";

    /// Real memo returned by the gateway (ETH -> BTC, liquidity_tolerance_bps=50).
    fn real_memo() -> String {
        format!("=:b:{DEST_BTC}:3146167:{AFFILIATE_ADDRESS}:80")
    }

    /// Departure from Bitcoin or Zcash without a short name: quote without an
    /// affiliate, 4-field memo (real forms recorded on 2026-10-03); an affiliate
    /// slipped into such a memo, even ours, is refused (fee not shown).
    #[test]
    fn op_return_sources_carry_no_affiliate() {
        let evm = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        // Affiliate choice: verified name everywhere; otherwise the address, except from
        // Bitcoin / Zcash (none).
        assert_eq!(
            choose_affiliate(Some("ow"), AFFILIATE_ADDRESS, "BTC.BTC"),
            Some("ow")
        );
        assert_eq!(
            choose_affiliate(Some("ow"), AFFILIATE_ADDRESS, "ETH.ETH"),
            Some("ow")
        );
        assert_eq!(choose_affiliate(None, AFFILIATE_ADDRESS, "BTC.BTC"), None);
        assert_eq!(
            choose_affiliate(None, MAYA_AFFILIATE_ADDRESS, "ZEC.ZEC"),
            None
        );
        assert_eq!(
            choose_affiliate(None, AFFILIATE_ADDRESS, "ETH.ETH"),
            Some(AFFILIATE_ADDRESS)
        );
        // Offline tests: name never verified.
        assert!(!THORCHAIN.charges_affiliate("BTC.BTC") && !MAYA.charges_affiliate("ZEC.ZEC"));
        assert!(THORCHAIN.charges_affiliate("ETH.ETH") && MAYA.charges_affiliate("ARB.ETH"));

        THORCHAIN
            .verify_memo(
                &format!("=:e:{evm}:31290403"),
                None,
                "ETH.ETH",
                evm,
                31_606_468,
            )
            .expect("BTC → ETH");
        THORCHAIN
            .verify_memo(
                &format!("=:ETH.USDC:{evm}:83511423369"),
                None,
                "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
                evm,
                84_354_973_100,
            )
            .expect("BTC → USDC");
        let with_fee = format!("=:e:{evm}:31290403:{AFFILIATE_ADDRESS}:80");
        assert!(
            THORCHAIN
                .verify_memo(&with_fee, None, "ETH.ETH", evm, 31_606_468)
                .is_err(),
            "affilié inattendu"
        );
        // Short name: required exactly as requested, never substituted.
        let with_name = format!("=:e:{evm}:31290403:ow:80");
        THORCHAIN
            .verify_memo(&with_name, Some("ow"), "ETH.ETH", evm, 31_606_468)
            .expect("nom court demandé");
        assert!(
            THORCHAIN
                .verify_memo(
                    &with_name,
                    Some(AFFILIATE_ADDRESS),
                    "ETH.ETH",
                    evm,
                    31_606_468
                )
                .is_err(),
            "nom substitué à l'adresse demandée"
        );
        assert!(
            THORCHAIN
                .verify_memo(&with_fee, Some("ow"), "ETH.ETH", evm, 31_606_468)
                .is_err(),
            "adresse à la place du nom demandé"
        );
        assert!(
            THORCHAIN
                .verify_memo(
                    &format!("=:e:{evm}:31290403:zz:80"),
                    Some("zz"),
                    "ETH.ETH",
                    evm,
                    31_606_468
                )
                .is_err(),
            "nom d'un autre"
        );

        MAYA.verify_memo(
            &format!("=:e:{evm}:48048634"),
            None,
            "ETH.ETH",
            evm,
            48_533_974,
        )
        .expect("ZEC → ETH");
        MAYA.verify_memo(
            &format!("=:b:{DEST_BTC}:1521019"),
            None,
            "BTC.BTC",
            DEST_BTC,
            1_536_383,
        )
        .expect("ZEC → BTC");
        MAYA.verify_memo(
            &format!("=:ARB.USDC:{evm}:92037029832"),
            None,
            "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
            evm,
            92_966_696_800,
        )
        .expect("ZEC → USDC Arbitrum");
        MAYA.verify_memo(
            &format!("=:e:{evm}:48048634:ow:80"),
            Some("ow"),
            "ETH.ETH",
            evm,
            48_533_974,
        )
        .expect("MAYAName");
        assert!(
            MAYA.verify_memo(
                "=:e:0x1111111111111111111111111111111111111111:48048634",
                None,
                "ETH.ETH",
                evm,
                48_533_974
            )
            .is_err(),
            "autre destination"
        );
        assert!(
            MAYA.verify_memo(&format!("=:e:{evm}:1000"), None, "ETH.ETH", evm, 48_533_974)
                .is_err(),
            "limite dérisoire"
        );
        assert!(
            MAYA.verify_memo(
                &format!("=:e:{evm}:48048634:maya1autre:9000"),
                None,
                "ETH.ETH",
                evm,
                48_533_974
            )
            .is_err(),
            "affilié étranger"
        );
        assert!(
            MAYA.verify_memo(
                &format!("=:e:{evm}:48048634"),
                Some(MAYA_AFFILIATE_ADDRESS),
                "ETH.ETH",
                evm,
                48_533_974
            )
            .is_err(),
            "affilié exigé"
        );
        assert_eq!(
            (
                format_1e8(139_440),
                format_1e8(100_000_000),
                format_1e8(1_000)
            ),
            (
                "0.0013944".to_string(),
                "1".to_string(),
                "0.00001".to_string()
            )
        );
        assert_eq!(
            (ticker("ZEC.ZEC"), ticker("ETH.USDC-0XA0B8")),
            ("ZEC", "USDC")
        );
    }

    /// Real quotes without an affiliate from Bitcoin and Zcash (read-only), memo
    /// verified, and an amount below the dust threshold refused.
    #[test]
    #[ignore]
    fn real_quotes_from_op_return_sources() {
        let evm = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        for (protocol, from, amount) in [
            (&THORCHAIN, "BTC.BTC", 1_000_000),
            (&MAYA, "BTC.BTC", 1_000_000),
            (&MAYA, "ZEC.ZEC", 100_000_000),
        ] {
            let quote = protocol
                .quote_swap(from, "ETH.ETH", amount, evm)
                .unwrap_or_else(|e| panic!("{} {from} : {e:#}", protocol.name));
            println!(
                "{} {from} : {} ({} octets), gas {:?}",
                protocol.name,
                quote.memo,
                quote.memo.len(),
                quote.recommended_gas_rate
            );
            assert!(quote.memo.len() <= 80);
        }
        // Between the dust threshold (10,000, refused by Maya itself) and the recommended
        // minimum (~139,000): refused by the app.
        let err = MAYA
            .quote_swap("ZEC.ZEC", "ETH.ETH", 50_000, evm)
            .err()
            .expect("montant sous le minimum refusé")
            .to_string();
        assert!(err.contains("trop faible"), "{err}");
    }

    /// Real `inbound_addresses` responses (abridged): Solana halted on THORChain on
    /// 2026-10-02; Maya without pause fields.
    #[test]
    fn reads_halted_chains() {
        let parse = |json: &str| Halts::from_statuses(serde_json::from_str(json).unwrap());
        let thor = parse(
            r#"[{"chain":"BTC","halted":false,"chain_trading_paused":false,"global_trading_paused":false},
                {"chain":"SOL","halted":true,"chain_trading_paused":true,"global_trading_paused":false}]"#,
        );
        assert!(
            thor.covers("SOL.SOL")
                && !thor.covers("BTC.BTC")
                && !thor.covers("ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48")
        );
        let maya = parse(r#"[{"chain":"ZEC","halted":false},{"chain":"ETH","halted":false}]"#);
        assert!(!maya.covers("ZEC.ZEC") && !maya.covers("ETH.ETH"));
        let paused = parse(r#"[{"chain":"BTC","halted":false,"global_trading_paused":true}]"#);
        assert!(
            paused.covers("ETH.ETH"),
            "pause générale : tout est suspendu"
        );
        assert_eq!(
            (chain_of("BASE.ETH"), chain_label("SOL"), chain_label("XYZ")),
            ("BASE", "Solana", "XYZ")
        );
    }

    /// Live: real state of both protocols (read-only).
    #[test]
    #[ignore]
    fn real_halted_assets_are_readable() {
        for protocol in [&THORCHAIN, &MAYA] {
            let halted: Vec<&str> = protocol
                .halted_assets()
                .unwrap()
                .iter()
                .map(|a| a.asset)
                .collect();
            println!("{} : suspendus {halted:?}", protocol.name);
        }
    }

    #[test]
    fn verify_swap_memo_accepts_the_real_memo_shape() {
        verify_swap_memo(
            &real_memo().replace("3146167", "3130357"),
            "BTC.BTC",
            DEST_BTC,
            3_161_977,
        )
        .expect("memo réel (1 %)");
        // Streaming variant "LIMIT/INTERVAL/QUANTITY" and the "swap" type spelled out.
        let streaming = format!("SWAP:BTC.BTC:{DEST_BTC}:3130357/1/0:{AFFILIATE_ADDRESS}:80");
        verify_swap_memo(&streaming, "BTC.BTC", DEST_BTC, 3_161_977).expect("variante streaming");
    }

    #[test]
    fn verify_swap_memo_rejects_a_redirected_destination() {
        let memo = real_memo().replace(DEST_BTC, "bc1qattackerattackerattackerattacker0000");
        let err = verify_swap_memo(&memo, "BTC.BTC", DEST_BTC, 3_161_977).unwrap_err();
        assert!(err.to_string().contains("AUTRE adresse"), "{err}");
    }

    #[test]
    fn verify_swap_memo_rejects_inflated_affiliate_fees_or_a_foreign_affiliate() {
        let inflated = real_memo().replace(":80", ":5000");
        assert!(
            verify_swap_memo(&inflated, "BTC.BTC", DEST_BTC, 3_161_977).is_err(),
            "50 % de frais"
        );
        let foreign = real_memo().replace(
            AFFILIATE_ADDRESS,
            "thor1attackerattackerattackerattacker00000",
        );
        assert!(
            verify_swap_memo(&foreign, "BTC.BTC", DEST_BTC, 3_161_977).is_err(),
            "affilié étranger"
        );
    }

    #[test]
    fn verify_swap_memo_rejects_a_missing_or_too_low_minimum_output() {
        // Empty limit = the behavior BEFORE this fix (any rate accepted).
        let no_limit = format!("=:b:{DEST_BTC}::{AFFILIATE_ADDRESS}:80");
        assert!(
            verify_swap_memo(&no_limit, "BTC.BTC", DEST_BTC, 3_161_977).is_err(),
            "limite vide"
        );
        let too_low = real_memo().replace("3146167", "1");
        assert!(
            verify_swap_memo(&too_low, "BTC.BTC", DEST_BTC, 3_161_977).is_err(),
            "limite dérisoire"
        );
    }

    #[test]
    fn verify_swap_memo_rejects_extra_aggregator_fields_and_wrong_assets() {
        let aggregator = format!("{}:0xAggregator:ETH.USDT:1", real_memo());
        assert!(
            verify_swap_memo(&aggregator, "BTC.BTC", DEST_BTC, 3_161_977).is_err(),
            "champs d'agrégateur"
        );
        // "s" = BSC.BNB in THORNode, not SOL: must NEVER pass for SOL.SOL.
        let sol_dest = "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F";
        let bsc = format!("=:s:{sol_dest}:100:{AFFILIATE_ADDRESS}:80");
        assert!(
            verify_swap_memo(&bsc, "SOL.SOL", sol_dest, 100).is_err(),
            "s n'est pas SOL"
        );
        let sol = format!("=:o:{sol_dest}:100:{AFFILIATE_ADDRESS}:80");
        verify_swap_memo(&sol, "SOL.SOL", sol_dest, 100).expect("o = SOL.SOL");
    }

    #[test]
    fn verify_swap_memo_address_case_rules() {
        let evm = "0x0db14a0288f4637f60b46690f1971b756c58a47e";
        let memo = format!(
            "=:e:{}:100:{AFFILIATE_ADDRESS}:80",
            evm.to_uppercase().replace("0X", "0x")
        );
        verify_swap_memo(&memo, "ETH.ETH", evm, 100).expect("hex EVM insensible à la casse");
        // Base58 (Solana): changing the case gives a DIFFERENT address, which must be
        // refused.
        let sol_dest = "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F";
        let memo = format!("=:o:{}:100:{AFFILIATE_ADDRESS}:80", sol_dest.to_lowercase());
        assert!(
            verify_swap_memo(&memo, "SOL.SOL", sol_dest, 100).is_err(),
            "base58 sensible à la casse"
        );
    }

    /// Does not guarantee the address exists or is correct (only a check against a
    /// reference THORChain wallet would); a minimal guard against accidental corruption
    /// of the constant (wrong prefix, wrong length).
    #[test]
    fn to_thorchain_amount_converts_between_decimal_precisions() {
        // SOL: 9 native decimals -> 8 (divide by 10).
        assert_eq!(to_thorchain_amount(1_000_000_000, 9).unwrap(), 100_000_000);
        // BTC: already 8 decimals, identity.
        assert_eq!(to_thorchain_amount(123_456_789, 8).unwrap(), 123_456_789);
        // ETH: 18 native decimals -> 8 (divide by 1e10).
        assert_eq!(
            to_thorchain_amount(1_000_000_000_000_000_000, 18).unwrap(),
            100_000_000
        );
        // USDC: 6 native decimals -> 8 (multiply by 100).
        assert_eq!(to_thorchain_amount(1_000_000, 6).unwrap(), 100_000_000);
    }

    /// End-to-end check against the real API (read-only, no risk): confirms the base
    /// URL, the real response format (exact field types) and that the affiliate address
    /// is accepted. Ignored by default (depends on the network); run it explicitly
    /// with:
    /// `cargo test -- --ignored quote_swap_matches_the_real_network`
    #[test]
    #[ignore]
    fn quote_swap_matches_the_real_network() {
        // ETH source (comfortable memo margin) to BTC: SOL was paused on THORChain when
        // this test was written (HALTSOLTRADING=1 seen live), so it could not be used here
        // for a check that holds over time.
        let quote = quote_swap(
            "ETH.ETH",
            "BTC.BTC",
            10_000_000,
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        )
        .expect("appel réseau réel");
        assert!(
            quote.inbound_address.starts_with("0x"),
            "vault ETH attendue : {}",
            quote.inbound_address
        );
        assert!(
            quote.memo.contains(AFFILIATE_ADDRESS),
            "le memo doit inclure notre adresse d'affiliation"
        );
        assert!(quote.expected_amount_out > 0);
        let router = quote
            .router
            .expect("un devis source ETH doit renvoyer un routeur");
        assert!(
            router.starts_with("0x") && router.len() == 42,
            "adresse de routeur EVM attendue : {router}"
        );
    }

    /// REAL memos for the new assets (quotes from 2026-10-01): tokens as `CHAIN.TICKER`
    /// without the contract, short codes "s" (BNB), "a" (AVAX), "f" (ETH on Base); one
    /// token is never confused with another.
    #[test]
    fn verify_swap_memo_accepts_the_real_shapes_of_the_new_assets() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let cases = [
            (
                "=:ETH.USDC:{evm}:262548630151:{aff}:80",
                "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
                265_200_000_000u64,
            ),
            (
                "=:ETH.USDT:{evm}:262897955671/0/2:{aff}:80",
                "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                265_550_000_000,
            ),
            (
                "=:BASE.VVV:{evm}:9695825781/0/174:{aff}:80",
                "BASE.VVV-0XACFE6019ED1A7DC6F7B508C02D1B04EC88CC21BF",
                9_793_000_000,
            ),
            ("=:s:{evm}:342440142:{aff}:80", "BSC.BNB", 345_900_000),
            (
                "=:a:{evm}:24145106811/0/2:{aff}:80",
                "AVAX.AVAX",
                24_389_000_000,
            ),
            ("=:f:{evm}:98138595/0/98:{aff}:80", "BASE.ETH", 99_130_000),
        ];
        for (memo, asset, expected) in cases {
            let memo = memo
                .replace("{evm}", evm)
                .replace("{aff}", AFFILIATE_ADDRESS);
            verify_swap_memo(&memo, asset, evm, expected)
                .unwrap_or_else(|e| panic!("{memo} : {e}"));
        }
        let usdt_for_usdc = format!("=:ETH.USDT:{evm}:262548630151:{AFFILIATE_ADDRESS}:80");
        assert!(verify_swap_memo(
            &usdt_for_usdc,
            "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
            evm,
            265_200_000_000
        )
        .is_err());
        let eth_for_base_eth = format!("=:e:{evm}:98138595:{AFFILIATE_ADDRESS}:80");
        assert!(
            verify_swap_memo(&eth_for_base_eth, "BASE.ETH", evm, 99_130_000).is_err(),
            "ETH d'Ethereum n'est pas ETH sur Base"
        );
    }

    /// Tokens in the table = contracts and decimals from the app's token registry
    /// (core/src/tokens.rs); THORChain notation = contract in uppercase.
    #[test]
    fn thorchain_tokens_match_the_token_registry() {
        for a in ASSETS.iter().filter(|a| a.contract.is_some()) {
            let (token, deployment) = crate::tokens::find(a.coin, a.network)
                .unwrap_or_else(|| panic!("{} absent du registre", a.asset));
            let crate::tokens::TokenKind::Erc20 { contract } = deployment.kind else {
                panic!("{} n'est pas ERC-20", a.asset)
            };
            assert_eq!(Some(contract), a.contract, "{}", a.asset);
            assert_eq!(u32::from(deployment.decimals), a.decimals, "{}", a.asset);
            assert_eq!(token.symbol.to_ascii_uppercase(), a.symbol, "{}", a.asset);
            assert!(
                a.asset
                    .ends_with(&format!("-{}", contract.to_ascii_uppercase())),
                "{}",
                a.asset
            );
        }
        assert!(asset("bnb", "bsc_mainnet").is_some() && asset("bnb", "evm_mainnet").is_none());
    }

    /// THORName: THOR alias = affiliate address, not expired (real format of
    /// `/thorchain/thorname/{name}`).
    #[test]
    fn thornames_must_point_to_the_affiliate_address() {
        let name = |alias: &str, expire: i64| {
            format!(
                r#"{{"name":"x","expire_block_height":{expire},"owner":"thor1u7ent5406np9t9u35ls0vxnv8rcmlzudf9zpq0","aliases":[{{"chain":"THOR","address":"{alias}"}},{{"chain":"ETH","address":"0x335fd459eadf098f8b2f26692936ee3d5bb425a2"}}]}}"#
            )
        };
        let usable = |body: &str, height: i64, chain: &str, address: &str| matches!(parse_name(body, height, chain, address), Ok(Some(r)) if r.points_to_affiliate && !r.expired());
        assert!(
            usable(
                &name(AFFILIATE_ADDRESS, 1000),
                999,
                "THOR",
                AFFILIATE_ADDRESS
            ),
            "bon alias, valide"
        );
        assert!(
            !usable(
                &name("thor1xnkml34dfmhtmx3hfxte4jxrxn2j3604mtx5h0", 1000),
                999,
                "THOR",
                AFFILIATE_ADDRESS
            ),
            "autre adresse"
        );
        assert!(
            !usable(
                &name(AFFILIATE_ADDRESS, 1000),
                1000,
                "THOR",
                AFFILIATE_ADDRESS
            ),
            "expiré"
        );
        assert!(
            !usable(
                &name(AFFILIATE_ADDRESS, 1000),
                999,
                "MAYA",
                MAYA_AFFILIATE_ADDRESS
            ),
            "alias THOR, pas MAYA"
        );
        let record = parse_name(
            &name(AFFILIATE_ADDRESS, 1000),
            999,
            "THOR",
            AFFILIATE_ADDRESS,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record.owner, "thor1u7ent5406np9t9u35ls0vxnv8rcmlzudf9zpq0");
        // Real response for a name that does not exist (recorded on 2026-10-03).
        let missing = r#"{"code":3,"message":"fail to fetch THORName: 2 errors occurred:
	* internal error
	* THORName doesn't exist: ow

: invalid request","details":[]}"#;
        assert_eq!(
            parse_name(missing, 0, "THOR", AFFILIATE_ADDRESS).unwrap(),
            None,
            "inexistant"
        );
    }

    /// REAL quotes for the new pairs (read-only): an ERC-20 token as source (router
    /// returned), native coins of BNB Chain, Avalanche and Base, a Base token as
    /// destination; memo verified by `quote_swap`.
    /// `cargo test -- --ignored quote_swap_covers_the_new_assets --nocapture`
    #[test]
    #[ignore]
    fn quote_swap_covers_the_new_assets() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        for (from, to, amount) in [
            (
                "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
                "BSC.BNB",
                10_000_000_000u64,
            ),
            (
                "BSC.BNB",
                "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                100_000_000,
            ),
            ("AVAX.AVAX", "BASE.ETH", 1_000_000_000),
            (
                "BASE.USDC-0X833589FCD6EDB6E08F4C7C32D4F71B54BDA02913",
                "ETH.DAI-0X6B175474E89094C44DA98B954EEDEAC495271D0F",
                10_000_000_000,
            ),
            (
                "ETH.ETH",
                "BASE.VVV-0XACFE6019ED1A7DC6F7B508C02D1B04EC88CC21BF",
                100_000_000,
            ),
        ] {
            let quote = quote_swap(from, to, amount, evm)
                .unwrap_or_else(|e| panic!("{from} -> {to} : {e:#}"));
            println!(
                "{from} -> {to} : {} (routeur {:?})",
                quote.memo, quote.router
            );
            assert!(quote.router.is_some(), "source EVM : routeur attendu");
        }
    }

    /// The Maya affiliate is the SAME key as the THORChain affiliate: same hash160,
    /// only the bech32 prefix changes.
    #[test]
    fn maya_affiliate_is_the_same_key_as_thorchain() {
        let (thor_hrp, thor_data, _) = bech32::decode(AFFILIATE_ADDRESS).unwrap();
        let (maya_hrp, maya_data, _) = bech32::decode(MAYA_AFFILIATE_ADDRESS).unwrap();
        assert_eq!((thor_hrp.as_str(), maya_hrp.as_str()), ("thor", "maya"));
        assert_eq!(thor_data, maya_data);
    }

    /// REAL Maya memos (quotes from 2026-10-01): "a" = Arbitrum ETH on Maya (never
    /// AVAX, which does not exist there), token as `ARB.USDC`; the THORChain affiliate
    /// is refused there, and vice versa.
    #[test]
    fn maya_memos_follow_maya_codes_and_affiliate() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let arb_eth = format!("=:a:{evm}:3594616:{MAYA_AFFILIATE_ADDRESS}:80");
        MAYA.verify_swap_memo(&arb_eth, "ARB.ETH", evm, 3_630_926)
            .expect("a = ARB.ETH sur Maya");
        assert!(
            THORCHAIN
                .verify_swap_memo(&arb_eth, "ARB.ETH", evm, 3_630_926)
                .is_err(),
            "affilié Maya refusé sur THORChain"
        );
        assert!(
            MAYA.verify_swap_memo(&arb_eth, "AVAX.AVAX", evm, 3_630_926)
                .is_err(),
            "a n'est pas AVAX sur Maya"
        );
        let usdc = format!("=:ARB.USDC:{evm}:24506475452:{MAYA_AFFILIATE_ADDRESS}:80");
        MAYA.verify_swap_memo(
            &usdc,
            "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
            evm,
            24_753_000_000,
        )
        .expect("jeton Arbitrum");
        let thor_affiliate = usdc.replace(MAYA_AFFILIATE_ADDRESS, AFFILIATE_ADDRESS);
        assert!(MAYA
            .verify_swap_memo(
                &thor_affiliate,
                "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
                evm,
                24_753_000_000
            )
            .is_err());
    }

    /// Maya tokens = the app's token registry.
    #[test]
    fn maya_tokens_match_the_token_registry() {
        for a in MAYA_ASSETS.iter().filter(|a| a.contract.is_some()) {
            let (_, deployment) = crate::tokens::find(a.coin, a.network)
                .unwrap_or_else(|| panic!("{} absent du registre", a.asset));
            let crate::tokens::TokenKind::Erc20 { contract } = deployment.kind else {
                panic!("{}", a.asset)
            };
            assert_eq!(Some(contract), a.contract, "{}", a.asset);
            assert_eq!(u32::from(deployment.decimals), a.decimals, "{}", a.asset);
        }
    }

    /// REAL quotes on Maya (read-only): Arbitrum to Bitcoin and Ethereum, an Ethereum
    /// token to Arbitrum, a swap within Arbitrum.
    /// `cargo test -- --ignored maya_quotes_match_the_real_network --nocapture`
    #[test]
    #[ignore]
    fn maya_quotes_match_the_real_network() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let zec = crate::zcash::p2pkh_address(&[0x11; 20]);
        for (from, to, amount, dest) in [
            (
                "ARB.ETH",
                "BTC.BTC",
                10_000_000u64,
                "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz",
            ),
            (
                "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
                "ETH.ETH",
                10_000_000_000,
                evm,
            ),
            (
                "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
                "ARB.ETH",
                10_000_000_000,
                evm,
            ),
            (
                "ARB.ETH",
                "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
                10_000_000,
                evm,
            ),
            ("ETH.ETH", "ZEC.ZEC", 10_000_000, zec.as_str()),
            (
                "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831",
                "ZEC.ZEC",
                10_000_000_000,
                zec.as_str(),
            ),
        ] {
            let quote = MAYA
                .quote_swap(from, to, amount, dest)
                .unwrap_or_else(|e| panic!("{from} -> {to} : {e:#}"));
            println!(
                "{from} -> {to} : {} (routeur {:?})",
                quote.memo, quote.router
            );
            assert!(quote.router.is_some());
            MAYA.verify_swap_memo(&quote.memo, to, dest, quote.expected_amount_out)
                .unwrap_or_else(|e| panic!("memo {from} -> {to} : {e:#}"));
        }
    }

    /// REAL quotes on THORChain to Dogecoin (read-only): memo verified (short code "d",
    /// exact D… address, minimum output).
    /// `cargo test -- --ignored thorchain_quotes_to_dogecoin --nocapture`
    #[test]
    #[ignore]
    fn thorchain_quotes_to_dogecoin() {
        let doge = crate::doge::p2pkh_address(&[0x11; 20]);
        for (from, amount) in [
            ("ETH.ETH", 10_000_000u64),
            ("BTC.BTC", 1_000_000),
            ("BSC.BNB", 10_000_000),
        ] {
            let quote = THORCHAIN
                .quote_swap(from, "DOGE.DOGE", amount, &doge)
                .unwrap_or_else(|e| panic!("{from} -> DOGE : {e:#}"));
            println!(
                "{from} -> DOGE : {} ({} DOGE attendus)",
                quote.memo,
                quote.expected_amount_out as f64 / 1e8
            );
            assert!(quote.memo.contains(&format!(":d:{doge}")), "{}", quote.memo);
            // Same check as the app: the quote's affiliate (none from Bitcoin).
            THORCHAIN
                .verify_memo(
                    &quote.memo,
                    quote.affiliate.as_deref(),
                    "DOGE.DOGE",
                    &doge,
                    quote.expected_amount_out,
                )
                .unwrap_or_else(|e| panic!("memo {from} -> DOGE : {e:#}"));
            // A different Dogecoin address in the memo: refused.
            let other = crate::doge::p2pkh_address(&[0x22; 20]);
            assert!(THORCHAIN
                .verify_memo(
                    &quote.memo,
                    quote.affiliate.as_deref(),
                    "DOGE.DOGE",
                    &other,
                    quote.expected_amount_out
                )
                .is_err());
        }
    }

    #[test]
    fn affiliate_address_has_the_expected_bech32_shape() {
        let (hrp, data, _variant) =
            bech32::decode(AFFILIATE_ADDRESS).expect("adresse bech32 valide");
        assert_eq!(hrp, "thor");
        assert_eq!(
            bech32::FromBase32::from_base32(&data).map(|v: Vec<u8>| v.len()),
            Ok(20),
            "une adresse THORChain encode un hash160 (20 octets)"
        );
    }
}
