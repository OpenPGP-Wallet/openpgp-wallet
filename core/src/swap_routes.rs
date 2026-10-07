//! Routes d'échange entre les cryptos de l'app : quel protocole relie une
//! crypto (sur un réseau) à une autre, directement ou en deux étapes via une
//! crypto intermédiaire. Fonction pure, sans appel réseau : source unique de
//! ce que l'interface propose (« Convertir ») et de ce que les commandes
//! d'échange acceptent (chaque étape est une paire directe).

use crate::{cow, lifi, moonpay_trade, swapkit, thorchain_rpc, tokens};
use serde::{Deserialize, Serialize};

/// Une crypto de l'app sur un réseau (identifiant de carte, réseau).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub struct SwapAsset {
    pub coin: &'static str,
    pub network: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Cross-chain : dépôt sur un coffre THORChain avec un memo vérifié.
    Thorchain,
    /// Même portefeuille Solana : transaction Jupiter simulée et vérifiée.
    Jupiter,
    /// Cross-chain, fork de THORChain (même mécanique) : Arbitrum.
    Maya,
    /// Même réseau EVM : ordre signé (EIP-712) exécuté par CoW Protocol.
    Cow,
    /// Entre deux écosystèmes : agrégateur LI.FI, transaction construite par
    /// LI.FI et vérifiée avant signature (voir `core/src/lifi.rs`).
    Lifi,
    /// Agrégateur SwapKit : NEAR Intents ou Chainflip, dépôt confirmé par le
    /// fournisseur lui-même avant signature (voir `core/src/swapkit.rs`).
    Swapkit,
    /// MoonPay Trade (swaps.xyz) : routeur simulé sur un même réseau EVM ;
    /// ailleurs, dépôt au destinataire final invérifiable, proposé en dernier
    /// recours seulement (voir `core/src/moonpay_trade.rs`).
    Moonpay,
}

impl Protocol {
    /// Protocole de la famille THORChain correspondant (`None` pour Jupiter
    /// et CoW).
    pub fn cross_chain(self) -> Option<&'static thorchain_rpc::CrossChain> {
        match self {
            Protocol::Thorchain => Some(&thorchain_rpc::THORCHAIN),
            Protocol::Maya => Some(&thorchain_rpc::MAYA),
            Protocol::Jupiter | Protocol::Cow | Protocol::Lifi | Protocol::Swapkit | Protocol::Moonpay => None,
        }
    }
}

/// Cryptos échangeables via Jupiter (voir `api::send_jupiter_swap`).
const JUPITER: [SwapAsset; 6] = [
    SwapAsset { coin: "sol", network: "sol_mainnet" },
    SwapAsset { coin: "usdc", network: "sol_mainnet" },
    SwapAsset { coin: "usdt", network: "sol_mainnet" },
    SwapAsset { coin: "eurc", network: "sol_mainnet" },
    SwapAsset { coin: "render", network: "sol_mainnet" },
    // Staking liquide : SOL ⇄ JitoSOL.
    SwapAsset { coin: "jitosol", network: "sol_mainnet" },
];

/// `protocol` relie-t-il `from` à `to` ? Depuis Bitcoin ou Zcash aussi :
/// sans nom court d'affiliation, sans frais pour l'app (voir
/// `thorchain_rpc::CrossChain::charges_affiliate`).
/// Réseaux reçus par échange mais pas encore vendus : l'app ne construit pas
/// encore le dépôt depuis ce réseau (Dogecoin : memo en sortie OP_RETURN). Ils
/// ne servent pas non plus d'intermédiaire.
const BUY_ONLY: [&str; 1] = ["doge_mainnet"];

fn links(protocol: &thorchain_rpc::CrossChain, from: SwapAsset, to: SwapAsset) -> bool {
    !BUY_ONLY.contains(&from.network) && protocol.asset(from.coin, from.network).is_some() && protocol.asset(to.coin, to.network).is_some()
}

/// Frais d'affiliation de l'app (points de base) d'un échange depuis `from`
/// via `protocol` : 0 depuis Bitcoin ou Zcash par THORChain ou Maya tant que
/// le nom court n'existe pas. Jupiter : sans compte de frais pour la paire,
/// l'échange se fait sans frais (dit dans sa boîte de confirmation).
/// Staking liquide (SOL ⇄ JitoSOL, ETH ⇄ stETH) : frais de l'app alignés sur
/// la concurrence, qui prélève sur les RÉCOMPENSES (Phantom, PSOL : 4 % des
/// récompenses + 0,1 % en sortie ; MetaMask : 10 à 15 % des récompenses),
/// soit ≈ 0,3 % par an. Les récompenses de Jito et de Lido échappent à l'app
/// (non-custodial) : perçus à l'entrée (0,30 %) et à la sortie (0,10 %, comme
/// Phantom), au lieu des 0,80 % / 1 % d'un échange ordinaire (06/10/2026).
pub const STAKING_ENTRY_FEE_BPS: u32 = 30;
pub const STAKING_EXIT_FEE_BPS: u32 = 10;

/// Crypto et réseau.
type CoinOn = (&'static str, &'static str);

const LIQUID_STAKING: [(CoinOn, CoinOn); 2] = [(("sol", "sol_mainnet"), ("jitosol", "sol_mainnet")), (("evm", "evm_mainnet"), ("steth", "evm_mainnet"))];

/// Frais de l'app pour une paire de staking liquide (`None` : autre paire).
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

pub fn affiliate_fee_bps(protocol: Protocol, from: SwapAsset, to: SwapAsset) -> u32 {
    if let (Some(bps), Protocol::Jupiter | Protocol::Cow) = (staking_fee_bps((from.coin, from.network), (to.coin, to.network)), protocol) {
        return bps;
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
        // Commission de SwapKit (l'app n'en touche pas encore, voir
        // `swapkit::AFFILIATE_FEE_BPS`).
        Protocol::Swapkit => swapkit::SERVICE_FEE_BPS + swapkit::AFFILIATE_FEE_BPS,
        Protocol::Moonpay => moonpay_trade::FEE_BPS,
    }
}

/// CoW relie deux cryptos du MÊME réseau EVM qu'il connaît (la monnaie du
/// réseau se vend via son contrat EthFlow).
fn cow_links(from: SwapAsset, to: SwapAsset) -> bool {
    from.network == to.network
        && matches!(cow::token(from.coin, from.network), Some(t) if !t.native || cow::wrapped_native(from.network).is_some())
        && cow::token(to.coin, to.network).is_some()
}

/// CoW n'est proposé qu'une fois l'adresse des frais partenaire renseignée.
fn cow_enabled() -> bool {
    cow::PARTNER_FEE_RECIPIENT.is_some()
}

/// LI.FI n'est proposé qu'une fois le nom d'intégrateur renseigné.
fn lifi_enabled() -> bool {
    lifi::INTEGRATOR.is_some()
}

/// SwapKit : proposé avec une clé d'API (lue à la compilation). Jamais dans
/// les tests de ce module, qui ne doivent pas dépendre de sa présence (les
/// paires SwapKit sont testées dans `swapkit`).
fn swapkit_enabled() -> bool {
    cfg!(not(test)) && swapkit::enabled()
}

/// MoonPay Trade : proposé avec une clé Trade (lue à la compilation). Même
/// règle que SwapKit pour les tests de ce module, sauf `MOONPAY_IN_TESTS`.
fn moonpay_enabled() -> bool {
    #[cfg(test)]
    return tests::MOONPAY_IN_TESTS.with(std::cell::Cell::get);
    #[cfg(not(test))]
    moonpay_trade::enabled()
}

/// Tous les protocoles qui relient directement `from` à `to`, du préféré au
/// moins préféré : Jupiter (même portefeuille Solana), CoW sur un même réseau
/// EVM (ordre sans transaction d'échange, meilleurs prix), THORChain (pools
/// les plus profonds), Maya (Arbitrum), puis LI.FI (agrégateur : transaction
/// construite par un tiers, vérifiée avant signature). Depuis Bitcoin, tant
/// que le nom court THORChain n'est pas inscrit et vérifié, LI.FI d'abord :
/// seule route qui porte les frais de l'app (choix du développeur, 03/10/2026). L'utilisateur peut choisir
/// n'importe lequel ; les commandes d'échange refusent un protocole absent de
/// la liste.
pub fn direct_all(from: SwapAsset, to: SwapAsset) -> Vec<Protocol> {
    let mut all = Vec::new();
    if from == to {
        return all;
    }
    if JUPITER.contains(&from) && JUPITER.contains(&to) {
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
    // Staking liquide : Jupiter et CoW seuls (frais de staking, voir
    // `staking_fee_bps`).
    if lifi_enabled() && staking_fee_bps((from.coin, from.network), (to.coin, to.network)).is_none() && lifi::links((from.coin, from.network), (to.coin, to.network)) {
        if from.network == "btc_mainnet" && !thorchain_rpc::THORCHAIN.charges_affiliate("BTC.BTC") {
            all.insert(0, Protocol::Lifi);
        } else {
            all.push(Protocol::Lifi);
        }
    }
    // En dernier : une option de plus, comparée sur son devis.
    if swapkit_enabled() && swapkit::links((from.coin, from.network), (to.coin, to.network)) {
        all.push(Protocol::Swapkit);
    }
    // MoonPay Trade : une option de plus quand l'app vérifie le destinataire
    // (même réseau EVM) ; sinon en dernier recours seulement, si aucun autre
    // fournisseur ne relie la paire (choix de l'utilisateur, 07/10/2026).
    let (from_pair, to_pair) = ((from.coin, from.network), (to.coin, to.network));
    if moonpay_enabled() && moonpay_trade::links(from_pair, to_pair) && (all.is_empty() || moonpay_trade::verifiable(from_pair, to_pair)) {
        all.push(Protocol::Moonpay);
    }
    all
}

/// Protocole préféré pour relier directement `from` à `to`, s'il en existe un.
pub fn direct(from: SwapAsset, to: SwapAsset) -> Option<Protocol> {
    direct_all(from, to).first().copied()
}

/// Toutes les cryptos qu'au moins un protocole sait échanger.
pub fn assets() -> Vec<SwapAsset> {
    let mut all: Vec<SwapAsset> = Vec::new();
    let cross_chain = thorchain_rpc::ASSETS.iter().chain(thorchain_rpc::MAYA_ASSETS.iter()).map(|a| SwapAsset { coin: a.coin, network: a.network });
    let cow_assets = cow::tradable().into_iter().filter(|_| cow_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    let lifi_assets = lifi::tradable().into_iter().filter(|_| lifi_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    let swapkit_assets = swapkit::tradable().into_iter().filter(|_| swapkit_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    let moonpay_assets = moonpay_trade::tradable().into_iter().filter(|_| moonpay_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    for asset in cross_chain.chain(JUPITER).chain(cow_assets).chain(lifi_assets).chain(swapkit_assets).chain(moonpay_assets) {
        if !all.contains(&asset) {
            all.push(asset);
        }
    }
    all
}

/// Échange en une étape (`via` = `None`) ou en deux : la crypto
/// intermédiaire arrive d'abord sur le portefeuille de l'utilisateur, puis
/// une seconde confirmation l'échange contre la cible (rien n'est bloqué si
/// la seconde étape n'est jamais faite).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Route {
    pub first: Protocol,
    pub via: Option<(SwapAsset, Protocol)>,
}

/// Préférence d'une crypto intermédiaire (la plus petite d'abord) : la
/// monnaie d'un réseau, qui paie aussi les frais de la seconde étape (celle du
/// réseau de départ, puis d'arrivée, puis une autre) ; puis les dollars
/// numériques ; puis le reste ; Bitcoin et Zcash en dernier recours
/// (confirmations lentes, frais de la seconde étape plus élevés).
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

/// Route de `from` vers `to` : directe si un protocole les relie, sinon en
/// deux étapes par la crypto intermédiaire préférée (`via_rank`).
pub fn route(from: SwapAsset, to: SwapAsset) -> Option<Route> {
    route_among(&assets(), from, to)
}

/// Toutes les paires possibles, avec leur route.
pub fn routes() -> Vec<(SwapAsset, SwapAsset, Route)> {
    let all = assets();
    all.iter().flat_map(|&from| all.iter().filter_map(|&to| route_among(&all, from, to).map(|r| (from, to, r))).collect::<Vec<_>>()).collect()
}

/// Crypto de l'app désignée par l'interface (identifiant et réseau), si elle
/// est échangeable.
pub fn find(coin: &str, network: &str) -> Option<SwapAsset> {
    assets().into_iter().find(|a| a.coin == coin && a.network == network)
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// MoonPay Trade activé pour le test en cours (fil de test seul).
        pub(super) static MOONPAY_IN_TESTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// MoonPay Trade : une option de plus sur un même réseau EVM (routeur
    /// vérifié) ; ailleurs, seulement si aucun autre fournisseur ne relie la
    /// paire (dépôt au destinataire invérifiable) ; jamais sans clé.
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
        assert_eq!(affiliate_fee_bps(Protocol::Moonpay, eth, xmr), 80);
        MOONPAY_IN_TESTS.with(|m| m.set(false));
    }

    /// Staking liquide : 0,30 % à l'entrée, 0,10 % à la sortie, par Jupiter
    /// et CoW ; LI.FI pas proposé ; ailleurs, les frais habituels.
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

    /// SOL ⇄ USDC passe par Jupiter (même portefeuille), un même réseau EVM par
    /// CoW, le reste par THORChain ou Maya ; rien vers soi-même ; USDC Solana
    /// n'a pas de pool THORChain.
    #[test]
    fn routes_pick_the_right_protocol() {
        assert_eq!(direct(a("sol", "sol_mainnet"), a("usdc", "sol_mainnet")), Some(Protocol::Jupiter));
        assert_eq!(direct(a("usdc", "evm_mainnet"), a("bnb", "bsc_mainnet")), Some(Protocol::Thorchain));
        let same_network = if cow_enabled() { Protocol::Cow } else { Protocol::Thorchain };
        assert_eq!(direct(a("evm", "base_mainnet"), a("vvv", "base_mainnet")), Some(same_network), "même réseau : CoW une fois activé");
        // Sans route native (pas de pool USDC Solana sur THORChain), LI.FI une
        // fois activé.
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

    /// CoW : même réseau EVM seulement (monnaie du réseau comprise, via
    /// EthFlow), et seulement une fois l'adresse des frais renseignée.
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

    /// Depuis Bitcoin : LI.FI d'abord (avec les frais de l'app) tant que le
    /// THORName n'existe pas, puis THORChain et Maya sans frais ; vers
    /// Bitcoin : THORChain d'abord.
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
        // Toute crypto que l'app échange est joignable depuis Bitcoin.
        let all = assets();
        for to in all.iter().filter(|t| **t != btc) {
            assert!(route(btc, *to).is_some(), "aucune route BTC → {to:?}");
        }
    }

    /// LI.FI : entre deux réseaux différents (Bitcoin compris, PSBT vérifiée),
    /// et depuis un réseau sans simulation (Avalanche) vers un
    /// réseau EVM seulement ; proposé en dernier (sauf depuis Bitcoin), une
    /// fois le nom d'intégrateur renseigné.
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

    /// ZEC via Maya, dans les deux sens ; depuis ZEC sans frais pour l'app
    /// (pas de MAYAName) ; vers une crypto que Maya n'a pas, en deux étapes
    /// par une monnaie de réseau rapide (ETH), jamais par Bitcoin.
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
        for to in assets().into_iter().filter(|t| *t != zec) {
            assert!(route(zec, to).is_some(), "aucune route ZEC → {to:?}");
        }
    }

    /// Plusieurs fournisseurs possibles : tous listés, le préféré d'abord.
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

    /// Deux étapes quand rien ne relie directement, par la monnaie d'un réseau
    /// de préférence ; chaque étape est une paire directe.
    #[test]
    fn two_step_routes_go_through_a_network_currency() {
        let sol = a("sol", "sol_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(route(eth, a("btc", "btc_mainnet")), Some(Route { first: Protocol::Thorchain, via: None }));
        if lifi_enabled() {
            // Directs via LI.FI.
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
