//! Swap routes between the app's cryptos: which protocol connects one crypto (on a
//! network) to another, directly or in two steps through an intermediate crypto. A
//! pure function with no network calls: the single source of truth for what the UI
//! offers ("Convert") and what the swap commands accept (each step is a direct
//! pair).

use crate::{cow, lifi, moonpay_trade, swapkit, thorchain_rpc, tokens};
use serde::{Deserialize, Serialize};

/// One of the app's cryptos on a network (card identifier, network).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub struct SwapAsset {
    pub coin: &'static str,
    pub network: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Cross-chain: deposit into a THORChain vault with a verified memo.
    Thorchain,
    /// Same Solana wallet: Jupiter transaction, simulated and verified.
    Jupiter,
    /// Cross-chain, a THORChain fork (same mechanics): Arbitrum.
    Maya,
    /// Same EVM network: signed order (EIP-712) executed by CoW Protocol.
    Cow,
    /// Between two ecosystems: the LI.FI aggregator, with a transaction built by LI.FI
    /// and verified before signing (see `core/src/lifi.rs`).
    Lifi,
    /// SwapKit aggregator: NEAR Intents or Chainflip, with the deposit confirmed by the
    /// provider itself before signing (see `core/src/swapkit.rs`).
    Swapkit,
    /// MoonPay Trade (swaps.xyz): a simulated router on the same EVM network;
    /// elsewhere, a deposit whose final recipient cannot be verified, offered only as a
    /// last resort (see `core/src/moonpay_trade.rs`).
    Moonpay,
}

impl Protocol {
    /// The matching THORChain-family protocol (`None` for Jupiter and CoW).
    pub fn cross_chain(self) -> Option<&'static thorchain_rpc::CrossChain> {
        match self {
            Protocol::Thorchain => Some(&thorchain_rpc::THORCHAIN),
            Protocol::Maya => Some(&thorchain_rpc::MAYA),
            Protocol::Jupiter | Protocol::Cow | Protocol::Lifi | Protocol::Swapkit | Protocol::Moonpay => None,
        }
    }
}

/// Cryptos that can be swapped through Jupiter (see `api::send_jupiter_swap`).
const JUPITER: [SwapAsset; 6] = [
    SwapAsset { coin: "sol", network: "sol_mainnet" },
    SwapAsset { coin: "usdc", network: "sol_mainnet" },
    SwapAsset { coin: "usdt", network: "sol_mainnet" },
    SwapAsset { coin: "eurc", network: "sol_mainnet" },
    SwapAsset { coin: "render", network: "sol_mainnet" },
    // Liquid staking: SOL ⇄ JitoSOL.
    SwapAsset { coin: "jitosol", network: "sol_mainnet" },
];

/// Swappable through Jupiter: the list above, plus the tokenized xStocks shares
/// from the registry (Token-2022, amounts converted by `api`).
fn jupiter_supports(asset: &SwapAsset) -> bool {
    JUPITER.contains(asset) || (asset.network == "sol_mainnet" && tokens::is_spl2022(asset.coin))
}

fn jupiter_assets() -> impl Iterator<Item = SwapAsset> {
    JUPITER.into_iter().chain(
        tokens::TOKENS.iter().filter(|t| tokens::is_spl2022(t.id)).map(|t| SwapAsset { coin: t.id, network: "sol_mainnet" }),
    )
}

/// Networks that can be received through a swap but not sold yet: the app does not
/// build the deposit from these networks yet (Dogecoin: memo in an OP_RETURN
/// output). They are not used as intermediates either.
const BUY_ONLY: [&str; 1] = ["doge_mainnet"];

/// Does `protocol` connect `from` to `to`? From Bitcoin or Zcash too: without an
/// affiliate short name, there is simply no fee for the app (see
/// `thorchain_rpc::CrossChain::charges_affiliate`).
fn links(protocol: &thorchain_rpc::CrossChain, from: SwapAsset, to: SwapAsset) -> bool {
    !BUY_ONLY.contains(&from.network) && protocol.asset(from.coin, from.network).is_some() && protocol.asset(to.coin, to.network).is_some()
}

/// Liquid staking (SOL ⇄ JitoSOL, ETH ⇄ stETH): the app's fees are in line with
/// competitors, who take a cut of the REWARDS (Phantom, PSOL: 4% of rewards + 0.1%
/// on exit; MetaMask: 10 to 15% of rewards), i.e. ≈ 0.3% per year. Jito and Lido
/// rewards never pass through the app (non-custodial), so the fee is taken on entry
/// (0.30%) and on exit (0.10%, like Phantom), instead of the 0.80% / 1% of a
/// regular swap (2026-10-06).
pub const STAKING_ENTRY_FEE_BPS: u32 = 30;
pub const STAKING_EXIT_FEE_BPS: u32 = 10;

/// Crypto and network.
type CoinOn = (&'static str, &'static str);

const LIQUID_STAKING: [(CoinOn, CoinOn); 2] = [(("sol", "sol_mainnet"), ("jitosol", "sol_mainnet")), (("evm", "evm_mainnet"), ("steth", "evm_mainnet"))];

/// The app's fee for a liquid staking pair (`None`: any other pair).
pub fn staking_fee_bps(from: (&str, &str), to: (&str, &str)) -> Option<u32> {
    LIQUID_STAKING.iter().find_map(|&(base, token)| {
        if (from, to) == (base, token) {
            Some(STAKING_ENTRY_FEE_BPS)
        } else if (from, to) == (token, base) {
            Some(STAKING_EXIT_FEE_BPS)
        } else {
            None
        }
    })
}

/// The app's affiliate fee (basis points) for a swap from `from` through `protocol`: 0
/// from Bitcoin or Zcash through THORChain or Maya as long as the short name does not
/// exist. Jupiter: without a fee account for the pair, the swap is fee-free (stated in
/// its confirmation dialog).
pub fn affiliate_fee_bps(protocol: Protocol, from: SwapAsset, to: SwapAsset) -> u32 {
    if let (Some(bps), Protocol::Jupiter | Protocol::Cow) = (staking_fee_bps((from.coin, from.network), (to.coin, to.network)), protocol) {
        return bps;
    }
    // Buying an xStock through Jupiter: the fee can only be taken on the xStock
    // received (on the token sold, the route fails; see api::jupiter_fee_mint), and
    // the affiliate has no xStock account, so the swap is fee-free. To revisit if
    // those accounts are created (the quote and the confirmation show the actual
    // fees).
    if protocol == Protocol::Jupiter && tokens::is_spl2022(to.coin) {
        return 0;
    }
    match protocol {
        Protocol::Thorchain | Protocol::Maya => {
            let cross_chain = protocol.cross_chain().expect("THORChain ou Maya");
            match cross_chain.asset(from.coin, from.network) {
                Some(asset) if !cross_chain.charges_affiliate(asset.asset) => 0,
                _ => thorchain_rpc::AFFILIATE_FEE_BPS,
            }
        }
        Protocol::Jupiter => crate::jupiter_rpc::AFFILIATE_FEE_BPS,
        Protocol::Cow => cow::PARTNER_FEE_BPS,
        Protocol::Lifi => (lifi::FEE * 10_000.0).round() as u32,
        // SwapKit's commission (the app does not take one yet, see
        // `swapkit::AFFILIATE_FEE_BPS`).
        Protocol::Swapkit => swapkit::SERVICE_FEE_BPS + swapkit::AFFILIATE_FEE_BPS,
        // MoonPay's fees included, like SwapKit's.
        Protocol::Moonpay => moonpay_trade::FEE_BPS + moonpay_trade::PROTOCOL_FEE_BPS,
    }
}

/// CoW connects two cryptos on the SAME EVM network it supports (the network's
/// native coin is sold through its EthFlow contract).
fn cow_links(from: SwapAsset, to: SwapAsset) -> bool {
    from.network == to.network
        && matches!(cow::token(from.coin, from.network), Some(t) if !t.native || cow::wrapped_native(from.network).is_some())
        && cow::token(to.coin, to.network).is_some()
}

/// CoW is only offered once the partner fee address is set.
fn cow_enabled() -> bool {
    cow::PARTNER_FEE_RECIPIENT.is_some()
}

/// LI.FI is only offered once the integrator name is set.
fn lifi_enabled() -> bool {
    lifi::INTEGRATOR.is_some()
}

/// SwapKit: offered when there is an API key (read at build time). Never in this
/// module's tests, which must not depend on the key being present (SwapKit pairs
/// are tested in `swapkit`).
fn swapkit_enabled() -> bool {
    cfg!(not(test)) && swapkit::enabled()
}

/// MoonPay Trade: offered when there is a Trade key (read at build time). Same rule
/// as SwapKit for this module's tests, except with `MOONPAY_IN_TESTS`.
fn moonpay_enabled() -> bool {
    #[cfg(test)]
    return tests::MOONPAY_IN_TESTS.with(std::cell::Cell::get);
    #[cfg(not(test))]
    moonpay_trade::enabled()
}

/// Every protocol that directly connects `from` to `to`, from most to least preferred: Jupiter (same
/// Solana wallet), CoW on the same EVM network (an order with no swap transaction, best prices), THORChain
/// (deepest pools), Maya (Arbitrum), then LI.FI (aggregator: transaction built by a third party, verified
/// before signing). From Bitcoin, until the THORChain short name is registered and verified, LI.FI comes
/// first: it is the only route that carries the app's fee (a deliberate choice, 2026-10-03). The user can
/// pick any of them; the swap commands refuse a protocol that is not in the list.
pub fn direct_all(from: SwapAsset, to: SwapAsset) -> Vec<Protocol> {
    let mut all = Vec::new();
    if from == to {
        return all;
    }
    if jupiter_supports(&from) && jupiter_supports(&to) {
        all.push(Protocol::Jupiter);
    }
    if cow_enabled() && cow_links(from, to) {
        all.push(Protocol::Cow);
    }
    if links(&thorchain_rpc::THORCHAIN, from, to) {
        all.push(Protocol::Thorchain);
    }
    if links(&thorchain_rpc::MAYA, from, to) {
        all.push(Protocol::Maya);
    }
    // Liquid staking: Jupiter and CoW only (staking fee, see `staking_fee_bps`).
    if lifi_enabled() && staking_fee_bps((from.coin, from.network), (to.coin, to.network)).is_none() && lifi::links((from.coin, from.network), (to.coin, to.network)) {
        if from.network == "btc_mainnet" && !thorchain_rpc::THORCHAIN.charges_affiliate("BTC.BTC") {
            all.insert(0, Protocol::Lifi);
        } else {
            all.push(Protocol::Lifi);
        }
    }
    // Last: one more option, compared on its quote.
    if swapkit_enabled() && swapkit::links((from.coin, from.network), (to.coin, to.network)) {
        all.push(Protocol::Swapkit);
    }
    // MoonPay Trade: one more option when the app can verify the recipient (same EVM
    // network); otherwise only as a last resort, if no other provider connects the
    // pair (product decision, 2026-10-07).
    let (from_pair, to_pair) = ((from.coin, from.network), (to.coin, to.network));
    if moonpay_enabled() && moonpay_trade::links(from_pair, to_pair) && (all.is_empty() || moonpay_trade::verifiable(from_pair, to_pair)) {
        all.push(Protocol::Moonpay);
    }
    all
}

/// Preferred protocol for directly connecting `from` to `to`, if there is one.
pub fn direct(from: SwapAsset, to: SwapAsset) -> Option<Protocol> {
    direct_all(from, to).first().copied()
}

/// Every crypto that at least one protocol can swap.
pub fn assets() -> Vec<SwapAsset> {
    let mut all: Vec<SwapAsset> = Vec::new();
    let cross_chain = thorchain_rpc::ASSETS.iter().chain(thorchain_rpc::MAYA_ASSETS.iter()).map(|a| SwapAsset { coin: a.coin, network: a.network });
    let cow_assets = cow::tradable().into_iter().filter(|_| cow_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    let lifi_assets = lifi::tradable().into_iter().filter(|_| lifi_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    let swapkit_assets = swapkit::tradable().into_iter().filter(|_| swapkit_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    let moonpay_assets = moonpay_trade::tradable().into_iter().filter(|_| moonpay_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    for asset in cross_chain.chain(jupiter_assets()).chain(cow_assets).chain(lifi_assets).chain(swapkit_assets).chain(moonpay_assets) {
        if !all.contains(&asset) {
            all.push(asset);
        }
    }
    all
}

/// A swap in one step (`via` = `None`) or two: the intermediate crypto first lands
/// in the user's wallet, then a second confirmation swaps it for the target
/// (nothing is locked if the second step is never done).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Route {
    pub first: Protocol,
    pub via: Option<(SwapAsset, Protocol)>,
}

/// Preference for an intermediate crypto (lowest first): a network's native coin,
/// which also pays the fee for the second step (the source network's first, then
/// the destination's, then any other); then digital dollars; then the rest; Bitcoin
/// and Zcash as a last resort (slow confirmations, higher fees for the second
/// step).
fn via_rank(via: SwapAsset, from: SwapAsset, to: SwapAsset) -> u8 {
    let native = tokens::find(via.coin, via.network).is_none();
    if matches!(via.network, "btc_mainnet" | "zec_mainnet") {
        return 5;
    }
    match via.coin {
        _ if native && via.network == from.network => 0,
        _ if native && via.network == to.network => 1,
        _ if native => 2,
        "usdc" | "usdt" => 3,
        _ => 4,
    }
}

fn route_among(all: &[SwapAsset], from: SwapAsset, to: SwapAsset) -> Option<Route> {
    if from == to {
        return None;
    }
    if let Some(first) = direct(from, to) {
        return Some(Route { first, via: None });
    }
    all.iter()
        .filter_map(|&via| {
            let first = direct(from, via)?;
            let second = direct(via, to)?;
            Some((via_rank(via, from, to), Route { first, via: Some((via, second)) }))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, route)| route)
}

/// Route from `from` to `to`: direct if a protocol connects them, otherwise in two
/// steps through the preferred intermediate crypto (`via_rank`).
pub fn route(from: SwapAsset, to: SwapAsset) -> Option<Route> {
    route_among(&assets(), from, to)
}

/// Every possible pair, with its route.
pub fn routes() -> Vec<(SwapAsset, SwapAsset, Route)> {
    let all = assets();
    all.iter().flat_map(|&from| all.iter().filter_map(|&to| route_among(&all, from, to).map(|r| (from, to, r))).collect::<Vec<_>>()).collect()
}

/// The app crypto designated by the UI (identifier and network), if it can be
/// swapped.
pub fn find(coin: &str, network: &str) -> Option<SwapAsset> {
    assets().into_iter().find(|a| a.coin == coin && a.network == network)
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// MoonPay Trade enabled for the current test (test thread only).
        pub(super) static MOONPAY_IN_TESTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// MoonPay Trade: one more option on the same EVM network (verified router);
    /// elsewhere, only if no other provider connects the pair (deposit to an
    /// unverifiable recipient); never without a key.
    #[test]
    fn moonpay_is_offered_last_or_as_last_resort() {
        let a = |coin, network| find(coin, network).unwrap_or(SwapAsset { coin, network });
        let (eth, usdc, btc, xmr) = (a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"), a("btc", "btc_mainnet"), SwapAsset { coin: "xmr", network: "xmr_mainnet" });
        assert!(!direct_all(eth, usdc).contains(&Protocol::Moonpay), "sans clé : jamais");
        MOONPAY_IN_TESTS.with(|m| m.set(true));
        let same_network = direct_all(eth, usdc);
        assert_eq!(same_network.last(), Some(&Protocol::Moonpay), "même réseau EVM : une option de plus, en dernier");
        assert!(same_network.len() > 1);
        assert!(!direct_all(eth, btc).contains(&Protocol::Moonpay), "THORChain relie ETH et BTC : pas de dépôt invérifiable");
        assert_eq!(direct_all(eth, xmr), vec![Protocol::Moonpay], "XMR : aucun autre fournisseur, dernier recours");
        assert_eq!(route(eth, xmr), Some(Route { first: Protocol::Moonpay, via: None }));
        assert!(direct_all(xmr, eth).is_empty(), "pas de dépôt depuis Monero");
        assert_eq!(affiliate_fee_bps(Protocol::Moonpay, eth, xmr), 110, "0,80 % pour l'app + 0,30 % pour MoonPay");
        MOONPAY_IN_TESTS.with(|m| m.set(false));
    }

    /// Liquid staking: 0.30% on entry, 0.10% on exit, through Jupiter and CoW; LI.FI
    /// not offered; elsewhere, the usual fees.
    #[test]
    fn liquid_staking_has_its_own_fees() {
        let sol = SwapAsset { coin: "sol", network: "sol_mainnet" };
        let jitosol = SwapAsset { coin: "jitosol", network: "sol_mainnet" };
        let eth = SwapAsset { coin: "evm", network: "evm_mainnet" };
        let steth = SwapAsset { coin: "steth", network: "evm_mainnet" };
        let usdc = SwapAsset { coin: "usdc", network: "sol_mainnet" };
        assert_eq!(affiliate_fee_bps(Protocol::Jupiter, sol, jitosol), 30);
        assert_eq!(affiliate_fee_bps(Protocol::Jupiter, jitosol, sol), 10);
        assert_eq!(affiliate_fee_bps(Protocol::Cow, eth, steth), 30);
        assert_eq!(affiliate_fee_bps(Protocol::Cow, steth, eth), 10);
        assert_eq!(affiliate_fee_bps(Protocol::Jupiter, sol, usdc), crate::jupiter_rpc::AFFILIATE_FEE_BPS);
        assert_eq!(affiliate_fee_bps(Protocol::Jupiter, jitosol, usdc), crate::jupiter_rpc::AFFILIATE_FEE_BPS, "JitoSOL → USDC : un échange ordinaire");
        assert!(!direct_all(sol, jitosol).contains(&Protocol::Lifi));
        assert_eq!(direct_all(sol, jitosol).first(), Some(&Protocol::Jupiter));
    }

    fn a(coin: &'static str, network: &'static str) -> SwapAsset {
        SwapAsset { coin, network }
    }

    /// SOL ⇄ USDC goes through Jupiter (same wallet), the same EVM network through CoW,
    /// the rest through THORChain or Maya; nothing to oneself; Solana USDC has no
    /// THORChain pool.
    #[test]
    fn routes_pick_the_right_protocol() {
        assert_eq!(direct(a("sol", "sol_mainnet"), a("usdc", "sol_mainnet")), Some(Protocol::Jupiter));
        assert_eq!(direct(a("usdc", "evm_mainnet"), a("bnb", "bsc_mainnet")), Some(Protocol::Thorchain));
        let same_network = if cow_enabled() { Protocol::Cow } else { Protocol::Thorchain };
        assert_eq!(direct(a("evm", "base_mainnet"), a("vvv", "base_mainnet")), Some(same_network), "même réseau : CoW une fois activé");
        // Without a native route (no Solana USDC pool on THORChain), LI.FI once enabled.
        let lifi_or_none = lifi_enabled().then_some(Protocol::Lifi);
        assert_eq!(direct(a("usdc", "sol_mainnet"), a("evm", "evm_mainnet")), lifi_or_none, "pas de pool USDC Solana sur THORChain");
        assert_eq!(direct(a("evm", "evm_mainnet"), a("evm", "evm_mainnet")), None);
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("btc", "btc_mainnet")), Some(Protocol::Maya), "Arbitrum : via Maya");
        assert_eq!(direct(a("usdt", "evm_mainnet"), a("usdc", "arbitrum_mainnet")), Some(Protocol::Maya));
        assert_eq!(direct(a("evm", "evm_mainnet"), a("btc", "btc_mainnet")), Some(Protocol::Thorchain), "THORChain avant Maya");
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("bnb", "bsc_mainnet")), lifi_or_none, "aucun protocole natif ne relie les deux");
        assert_eq!(find("usdc", "base_mainnet"), Some(a("usdc", "base_mainnet")));
        assert!(find("hype", "hyperevm_mainnet").is_none(), "HyperEVM retiré de l'app");
    }

    /// CoW: same EVM network only (native coin included, through EthFlow), and only
    /// once the fee address is set.
    ///
    /// Tokenized shares: swapped through Jupiter only (same network); LI.FI, MoonPay
    /// and CoW, written for the classic token program, ignore them.
    #[test]
    fn xstocks_are_swapped_through_jupiter_only() {
        let (usdc, tsla, sol) = (
            SwapAsset { coin: "usdc", network: "sol_mainnet" },
            SwapAsset { coin: "tslax", network: "sol_mainnet" },
            SwapAsset { coin: "sol", network: "sol_mainnet" },
        );
        assert_eq!(direct_all(usdc, tsla), vec![Protocol::Jupiter]);
        assert_eq!(affiliate_fee_bps(Protocol::Jupiter, usdc, tsla), 0, "achat : sans frais");
        assert_eq!(affiliate_fee_bps(Protocol::Jupiter, tsla, usdc), crate::jupiter_rpc::AFFILIATE_FEE_BPS, "vente : frais en USDC");
        assert_eq!(direct_all(tsla, sol), vec![Protocol::Jupiter]);
        assert!(assets().contains(&tsla) && assets().contains(&SwapAsset { coin: "spyx", network: "sol_mainnet" }));
        assert!(lifi::token("tslax", "sol_mainnet").is_none());
        assert!(moonpay_trade::asset("tslax", "sol_mainnet").is_none());
        assert!(cow::token("tslax", "sol_mainnet").is_none());
        assert!(direct_all(SwapAsset { coin: "evm", network: "evm_mainnet" }, tsla).is_empty(), "pas de route directe depuis un autre réseau");
    }

    #[test]
    fn cow_links_same_network_tokens() {
        assert!(cow_links(a("link", "evm_mainnet"), a("usdc", "evm_mainnet")));
        assert!(cow_links(a("usdc", "arbitrum_mainnet"), a("evm", "arbitrum_mainnet")));
        assert!(cow_links(a("aster", "bsc_mainnet"), a("bnb", "bsc_mainnet")));
        assert!(cow_links(a("evm", "evm_mainnet"), a("usdc", "evm_mainnet")), "vente native : EthFlow");
        assert!(cow_links(a("bnb", "bsc_mainnet"), a("aster", "bsc_mainnet")));
        assert!(!cow_links(a("link", "evm_mainnet"), a("usdc", "base_mainnet")), "deux réseaux");
        assert!(!cow_links(a("usdc", "sol_mainnet"), a("usdt", "sol_mainnet")));
        let link_usdc = direct(a("link", "evm_mainnet"), a("usdc", "evm_mainnet"));
        assert_eq!(link_usdc == Some(Protocol::Cow), cow_enabled());
        let eth_usdc = direct(a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"));
        if cow_enabled() {
            assert_eq!(direct(a("usdc", "evm_mainnet"), a("evm", "evm_mainnet")), Some(Protocol::Cow), "CoW avant THORChain sur un même réseau");
            assert_eq!(eth_usdc, Some(Protocol::Cow));
        } else {
            assert!(link_usdc.is_none());
            assert_eq!(find("link", "evm_mainnet"), None);
            assert_eq!(eth_usdc, Some(Protocol::Thorchain));
        }
    }

    /// From Bitcoin: LI.FI first (with the app's fee) as long as the THORName does not
    /// exist, then THORChain and Maya without a fee; to Bitcoin: THORChain first.
    #[test]
    fn bitcoin_sources_offer_lifi_first_then_fee_free_pools() {
        let btc = a("btc", "btc_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(direct(eth, btc), Some(Protocol::Thorchain));
        let mut expected = vec![Protocol::Thorchain, Protocol::Maya];
        if lifi_enabled() {
            if !thorchain_rpc::THORCHAIN.charges_affiliate("BTC.BTC") {
                expected.insert(0, Protocol::Lifi);
            } else {
                expected.push(Protocol::Lifi);
            }
        }
        assert_eq!(direct_all(btc, eth), expected);
        let free = u32::from(thorchain_rpc::THORCHAIN.charges_affiliate("BTC.BTC")) * thorchain_rpc::AFFILIATE_FEE_BPS;
        assert_eq!(affiliate_fee_bps(Protocol::Thorchain, btc, eth), free);
        assert_eq!(affiliate_fee_bps(Protocol::Maya, btc, eth), 0, "Maya : pas de MAYAName");
        assert_eq!(affiliate_fee_bps(Protocol::Thorchain, eth, btc), 80);
        assert_eq!(affiliate_fee_bps(Protocol::Lifi, btc, eth), 80);
        assert_eq!(affiliate_fee_bps(Protocol::Cow, eth, a("usdc", "evm_mainnet")), 100);
        // Every crypto the app swaps can be reached from Bitcoin.
        let all = assets();
        for to in all.iter().filter(|t| **t != btc) {
            assert!(route(btc, *to).is_some(), "aucune route BTC → {to:?}");
        }
    }

    /// LI.FI: between two different networks (Bitcoin included, with a verified PSBT),
    /// and from a network without simulation (Avalanche) to an EVM network only;
    /// offered last (except from Bitcoin), once the integrator name is set.
    #[test]
    fn lifi_links_between_ecosystems() {
        assert!(lifi::links(("render", "sol_mainnet"), ("link", "evm_mainnet")), "le cas qui manquait");
        assert!(lifi::links(("link", "evm_mainnet"), ("render", "sol_mainnet")));
        assert!(lifi::links(("evm", "evm_mainnet"), ("btc", "btc_mainnet")));
        assert!(lifi::links(("avax", "avax_mainnet"), ("usdc", "arbitrum_mainnet")), "AVAX vendu vers un réseau EVM");
        assert!(!lifi::links(("avax", "avax_mainnet"), ("sol", "sol_mainnet")), "Avalanche ne simule pas : pas vers Solana");
        assert!(!lifi::links(("avax", "avax_mainnet"), ("btc", "btc_mainnet")));
        assert!(lifi::links(("btc", "btc_mainnet"), ("evm", "evm_mainnet")), "depuis Bitcoin : PSBT vérifiée");
        assert!(lifi::links(("btc", "btc_mainnet"), ("sol", "sol_mainnet")));
        assert!(!lifi::links(("zec", "zec_mainnet"), ("evm", "evm_mainnet")), "ZEC inconnu de LI.FI");
        assert!(!lifi::links(("link", "evm_mainnet"), ("usdc", "evm_mainnet")), "même réseau : CoW");
        let render_link = direct_all(a("render", "sol_mainnet"), a("link", "evm_mainnet"));
        assert_eq!(render_link.contains(&Protocol::Lifi), lifi_enabled());
        if lifi_enabled() {
            assert_eq!(direct_all(a("evm", "evm_mainnet"), a("btc", "btc_mainnet")).last(), Some(&Protocol::Lifi), "LI.FI en dernier");
        }
    }

    /// ZEC through Maya, both ways; from ZEC without an app fee (no MAYAName); to a
    /// crypto Maya does not have, in two steps through a fast network coin (ETH), never
    /// through Bitcoin.
    #[test]
    fn doge_is_bought_through_thorchain_but_not_sold_yet() {
        let doge = a("doge", "doge_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(direct(eth, doge), Some(Protocol::Thorchain));
        assert_eq!(direct(a("btc", "btc_mainnet"), doge), Some(Protocol::Thorchain));
        assert!(direct_all(doge, eth).is_empty(), "départ DOGE pas encore construit");
        for to in assets().into_iter().filter(|t| *t != doge) {
            assert!(route(doge, to).is_none(), "route depuis DOGE : {to:?}");
            if let Some(route) = route(to, doge) {
                assert!(route.via.is_none_or(|(via, _)| via.network != "doge_mainnet"));
            }
        }
    }

    #[test]
    fn zec_swaps_both_ways_through_maya() {
        let zec = a("zec", "zec_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(direct(eth, zec), Some(Protocol::Maya));
        assert_eq!(direct(a("usdc", "arbitrum_mainnet"), zec), Some(Protocol::Maya));
        assert_eq!(direct_all(zec, eth), vec![Protocol::Maya]);
        assert_eq!(direct_all(zec, a("btc", "btc_mainnet")), vec![Protocol::Maya]);
        assert_eq!(affiliate_fee_bps(Protocol::Maya, zec, eth), 0);
        let to_sol = route(zec, a("sol", "sol_mainnet")).expect("ZEC → SOL en deux étapes");
        let (via, _) = to_sol.via.expect("deux étapes");
        assert!(!matches!(via.network, "btc_mainnet" | "zec_mainnet"), "intermédiaire lent : {via:?}");
        // Tokenized shares: bought from Solana (Jupiter); from ZEC it would take three
        // steps (ZEC → ETH → SOL → xStock).
        for to in assets().into_iter().filter(|t| *t != zec && !tokens::is_spl2022(t.coin)) {
            assert!(route(zec, to).is_some(), "aucune route ZEC → {to:?}");
        }
    }

    /// Several possible providers: all listed, the preferred one first.
    #[test]
    fn every_provider_of_a_pair_is_listed() {
        let eth = a("evm", "evm_mainnet");
        let btc = a("btc", "btc_mainnet");
        let mut eth_btc = vec![Protocol::Thorchain, Protocol::Maya];
        if lifi_enabled() {
            eth_btc.push(Protocol::Lifi);
        }
        assert_eq!(direct_all(eth, btc), eth_btc);
        let usdc = a("usdc", "evm_mainnet");
        let expected = if cow_enabled() { vec![Protocol::Cow, Protocol::Thorchain, Protocol::Maya] } else { vec![Protocol::Thorchain, Protocol::Maya] };
        assert_eq!(direct_all(eth, usdc), expected);
        assert!(direct_all(eth, eth).is_empty());
        assert_eq!(direct_all(a("sol", "sol_mainnet"), a("render", "sol_mainnet")), vec![Protocol::Jupiter]);
        assert_eq!(serde_json::from_str::<Protocol>("\"maya\"").unwrap(), Protocol::Maya);
    }

    /// Two steps when nothing connects directly, preferably through a network's native
    /// coin; each step is a direct pair.
    #[test]
    fn two_step_routes_go_through_a_network_currency() {
        let sol = a("sol", "sol_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(route(eth, a("btc", "btc_mainnet")), Some(Route { first: Protocol::Thorchain, via: None }));
        if lifi_enabled() {
            // Direct through LI.FI.
            let lifi = Some(Route { first: Protocol::Lifi, via: None });
            assert_eq!(route(a("render", "sol_mainnet"), eth), lifi);
            assert_eq!(route(a("evm", "arbitrum_mainnet"), a("bnb", "bsc_mainnet")), lifi);
        } else {
            assert_eq!(route(a("render", "sol_mainnet"), eth), Some(Route { first: Protocol::Jupiter, via: Some((sol, Protocol::Thorchain)) }));
            assert_eq!(route(a("usdc", "sol_mainnet"), a("btc", "btc_mainnet")), Some(Route { first: Protocol::Jupiter, via: Some((sol, Protocol::Thorchain)) }));
            assert_eq!(route(a("evm", "arbitrum_mainnet"), a("bnb", "bsc_mainnet")), Some(Route { first: Protocol::Maya, via: Some((eth, Protocol::Thorchain)) }));
        }
        for (from, to, r) in routes() {
            match r.via {
                None => assert_eq!(direct(from, to), Some(r.first)),
                Some((via, second)) => {
                    assert!(direct(from, to).is_none() && via != from && via != to);
                    assert_eq!((direct(from, via), direct(via, to)), (Some(r.first), Some(second)));
                }
            }
        }
    }
}
