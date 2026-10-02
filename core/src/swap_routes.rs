//! Routes d'échange entre les cryptos de l'app : quel protocole relie une
//! crypto (sur un réseau) à une autre, directement ou en deux étapes via une
//! crypto intermédiaire. Fonction pure, sans appel réseau : source unique de
//! ce que l'interface propose (« Convertir ») et de ce que les commandes
//! d'échange acceptent (chaque étape est une paire directe).

use crate::{cow, lifi, thorchain_rpc, tokens};
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
}

impl Protocol {
    /// Protocole de la famille THORChain correspondant (`None` pour Jupiter
    /// et CoW).
    pub fn cross_chain(self) -> Option<&'static thorchain_rpc::CrossChain> {
        match self {
            Protocol::Thorchain => Some(&thorchain_rpc::THORCHAIN),
            Protocol::Maya => Some(&thorchain_rpc::MAYA),
            Protocol::Jupiter | Protocol::Cow | Protocol::Lifi => None,
        }
    }
}

/// Cryptos échangeables via Jupiter (voir `api::send_jupiter_swap`).
const JUPITER: [SwapAsset; 5] = [
    SwapAsset { coin: "sol", network: "sol_mainnet" },
    SwapAsset { coin: "usdc", network: "sol_mainnet" },
    SwapAsset { coin: "usdt", network: "sol_mainnet" },
    SwapAsset { coin: "eurc", network: "sol_mainnet" },
    SwapAsset { coin: "render", network: "sol_mainnet" },
];

/// `protocol` relie-t-il `from` à `to` ? Depuis Bitcoin, pas tant que son
/// nom court d'affiliation n'est pas enregistré : le memo avec l'adresse
/// complète dépasse les 80 octets d'un OP_RETURN (voir
/// `thorchain_rpc::AFFILIATE_NAME`).
fn links(protocol: &thorchain_rpc::CrossChain, from: SwapAsset, to: SwapAsset) -> bool {
    if from.coin == "btc" && protocol.affiliate_name.is_none() {
        return false;
    }
    protocol.asset(from.coin, from.network).is_some() && protocol.asset(to.coin, to.network).is_some()
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

/// Tous les protocoles qui relient directement `from` à `to`, du préféré au
/// moins préféré : Jupiter (même portefeuille Solana), CoW sur un même réseau
/// EVM (ordre sans transaction d'échange, meilleurs prix), THORChain (pools
/// les plus profonds), Maya (Arbitrum), puis LI.FI (agrégateur : transaction
/// construite par un tiers, vérifiée avant signature). L'utilisateur peut
/// choisir n'importe lequel ; les commandes d'échange refusent un protocole
/// absent de la liste.
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
    if lifi_enabled() && lifi::links((from.coin, from.network), (to.coin, to.network)) {
        all.push(Protocol::Lifi);
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
    for asset in cross_chain.chain(JUPITER).chain(cow_assets).chain(lifi_assets) {
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
/// numériques ; puis le reste.
fn via_rank(via: SwapAsset, from: SwapAsset, to: SwapAsset) -> u8 {
    let native = tokens::find(via.coin, via.network).is_none();
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
        assert_eq!(direct(a("usdc", "sol_mainnet"), a("evm", "evm_mainnet")), None, "pas de pool USDC Solana sur THORChain");
        assert_eq!(direct(a("evm", "evm_mainnet"), a("evm", "evm_mainnet")), None);
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("btc", "btc_mainnet")), Some(Protocol::Maya), "Arbitrum : via Maya");
        assert_eq!(direct(a("usdt", "evm_mainnet"), a("usdc", "arbitrum_mainnet")), Some(Protocol::Maya));
        assert_eq!(direct(a("evm", "evm_mainnet"), a("btc", "btc_mainnet")), Some(Protocol::Thorchain), "THORChain avant Maya");
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("bnb", "bsc_mainnet")), None, "aucun protocole ne relie les deux");
        assert_eq!(find("usdc", "base_mainnet"), Some(a("usdc", "base_mainnet")));
        assert_eq!(find("hype", "hyperevm_mainnet"), None);
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

    /// Depuis Bitcoin : aucune route tant que le THORName n'existe pas ; vers
    /// Bitcoin : oui.
    #[test]
    fn bitcoin_sources_wait_for_the_thorname() {
        let btc = a("btc", "btc_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(direct(eth, btc), Some(Protocol::Thorchain));
        assert_eq!(direct(btc, eth).is_some(), thorchain_rpc::AFFILIATE_NAME.is_some());
        for (from, to, _) in routes() {
            assert!(from != to);
            assert!(from.coin != "btc" || thorchain_rpc::AFFILIATE_NAME.is_some(), "aucune route depuis Bitcoin sans THORName");
        }
    }

    /// LI.FI : entre deux réseaux différents, jamais depuis Bitcoin, et depuis
    /// un réseau sans simulation (Avalanche, HyperEVM) vers un réseau EVM
    /// seulement ; proposé en dernier, une fois le nom d'intégrateur renseigné.
    #[test]
    fn lifi_links_between_ecosystems() {
        assert!(lifi::links(("render", "sol_mainnet"), ("link", "evm_mainnet")), "le cas qui manquait");
        assert!(lifi::links(("link", "evm_mainnet"), ("render", "sol_mainnet")));
        assert!(lifi::links(("evm", "evm_mainnet"), ("btc", "btc_mainnet")));
        assert!(lifi::links(("hype", "hyperevm_mainnet"), ("usdc", "arbitrum_mainnet")), "HYPE vendu vers un réseau EVM");
        assert!(lifi::links(("usdc", "base_mainnet"), ("hype", "hyperevm_mainnet")), "HYPE acheté");
        assert!(!lifi::links(("hype", "hyperevm_mainnet"), ("sol", "sol_mainnet")), "HyperEVM ne simule pas : pas vers Solana");
        assert!(!lifi::links(("avax", "avax_mainnet"), ("btc", "btc_mainnet")));
        assert!(!lifi::links(("btc", "btc_mainnet"), ("evm", "evm_mainnet")), "jamais depuis Bitcoin");
        assert!(!lifi::links(("link", "evm_mainnet"), ("usdc", "evm_mainnet")), "même réseau : CoW");
        let render_link = direct_all(a("render", "sol_mainnet"), a("link", "evm_mainnet"));
        assert_eq!(render_link.contains(&Protocol::Lifi), lifi_enabled());
        if lifi_enabled() {
            assert_eq!(direct_all(a("evm", "evm_mainnet"), a("btc", "btc_mainnet")).last(), Some(&Protocol::Lifi), "LI.FI en dernier");
        }
    }

    /// Plusieurs fournisseurs possibles : tous listés, le préféré d'abord.
    #[test]
    fn every_provider_of_a_pair_is_listed() {
        let eth = a("evm", "evm_mainnet");
        let btc = a("btc", "btc_mainnet");
        assert_eq!(direct_all(eth, btc), vec![Protocol::Thorchain, Protocol::Maya]);
        let usdc = a("usdc", "evm_mainnet");
        let expected = if cow_enabled() { vec![Protocol::Cow, Protocol::Thorchain, Protocol::Maya] } else { vec![Protocol::Thorchain, Protocol::Maya] };
        assert_eq!(direct_all(eth, usdc), expected);
        assert!(direct_all(eth, eth).is_empty());
        assert_eq!(direct_all(a("sol", "sol_mainnet"), a("render", "sol_mainnet")), vec![Protocol::Jupiter]);
        assert_eq!(serde_json::from_str::<Protocol>("\"maya\"").unwrap(), Protocol::Maya);
    }

    /// Deux étapes quand rien ne relie directement, par la monnaie d'un réseau
    /// de préférence ; chaque étape est une paire directe ; rien vers HYPE.
    #[test]
    fn two_step_routes_go_through_a_network_currency() {
        let sol = a("sol", "sol_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(route(a("render", "sol_mainnet"), eth), Some(Route { first: Protocol::Jupiter, via: Some((sol, Protocol::Thorchain)) }));
        assert_eq!(route(a("usdc", "sol_mainnet"), a("btc", "btc_mainnet")), Some(Route { first: Protocol::Jupiter, via: Some((sol, Protocol::Thorchain)) }));
        assert_eq!(route(a("evm", "arbitrum_mainnet"), a("bnb", "bsc_mainnet")), Some(Route { first: Protocol::Maya, via: Some((eth, Protocol::Thorchain)) }));
        assert_eq!(route(eth, a("btc", "btc_mainnet")), Some(Route { first: Protocol::Thorchain, via: None }));
        assert_eq!(route(eth, a("hype", "hyperevm_mainnet")), None);
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
