//! Routes d'échange entre les cryptos de l'app : quel protocole relie une
//! crypto (sur un réseau) à une autre. Fonction pure, sans appel réseau :
//! source unique de ce que l'interface propose (« Convertir ») et de ce que
//! les commandes d'échange acceptent.

use crate::{cow, thorchain_rpc};
use serde::Serialize;

/// Une crypto de l'app sur un réseau (identifiant de carte, réseau).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub struct SwapAsset {
    pub coin: &'static str,
    pub network: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
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
}

impl Protocol {
    /// Protocole de la famille THORChain correspondant (`None` pour Jupiter
    /// et CoW).
    pub fn cross_chain(self) -> Option<&'static thorchain_rpc::CrossChain> {
        match self {
            Protocol::Thorchain => Some(&thorchain_rpc::THORCHAIN),
            Protocol::Maya => Some(&thorchain_rpc::MAYA),
            Protocol::Jupiter | Protocol::Cow => None,
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

/// CoW relie deux cryptos du MÊME réseau EVM qu'il connaît, sauf à vendre la
/// monnaie du réseau (contrat EthFlow pas encore pris en charge).
fn cow_links(from: SwapAsset, to: SwapAsset) -> bool {
    from.network == to.network && matches!(cow::token(from.coin, from.network), Some(t) if !t.native) && cow::token(to.coin, to.network).is_some()
}

/// CoW n'est proposé qu'une fois l'adresse des frais partenaire renseignée.
fn cow_enabled() -> bool {
    cow::PARTNER_FEE_RECIPIENT.is_some()
}

/// Protocole qui relie directement `from` à `to`, s'il existe : Jupiter
/// d'abord (même portefeuille Solana), CoW sur un même réseau EVM (ordre
/// sans transaction d'échange, meilleurs prix), puis THORChain (pools les
/// plus profonds), puis Maya (Arbitrum).
pub fn direct(from: SwapAsset, to: SwapAsset) -> Option<Protocol> {
    if from == to {
        return None;
    }
    if JUPITER.contains(&from) && JUPITER.contains(&to) {
        return Some(Protocol::Jupiter);
    }
    if cow_enabled() && cow_links(from, to) {
        return Some(Protocol::Cow);
    }
    if links(&thorchain_rpc::THORCHAIN, from, to) {
        return Some(Protocol::Thorchain);
    }
    links(&thorchain_rpc::MAYA, from, to).then_some(Protocol::Maya)
}

/// Toutes les cryptos qu'au moins un protocole sait échanger.
pub fn assets() -> Vec<SwapAsset> {
    let mut all: Vec<SwapAsset> = Vec::new();
    let cross_chain = thorchain_rpc::ASSETS.iter().chain(thorchain_rpc::MAYA_ASSETS.iter()).map(|a| SwapAsset { coin: a.coin, network: a.network });
    let cow_assets = cow::tradable().into_iter().filter(|_| cow_enabled()).map(|(coin, network)| SwapAsset { coin, network });
    for asset in cross_chain.chain(JUPITER).chain(cow_assets) {
        if !all.contains(&asset) {
            all.push(asset);
        }
    }
    all
}

/// Toutes les paires reliées directement, avec leur protocole.
pub fn pairs() -> Vec<(SwapAsset, SwapAsset, Protocol)> {
    let all = assets();
    all.iter().flat_map(|&from| all.iter().filter_map(move |&to| direct(from, to).map(|p| (from, to, p)))).collect()
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

    /// SOL ⇄ USDC passe par Jupiter (même portefeuille), le reste par
    /// THORChain ; rien vers soi-même ; USDC Solana n'a pas de pool THORChain.
    #[test]
    fn routes_pick_the_right_protocol() {
        assert_eq!(direct(a("sol", "sol_mainnet"), a("usdc", "sol_mainnet")), Some(Protocol::Jupiter));
        assert_eq!(direct(a("usdc", "evm_mainnet"), a("bnb", "bsc_mainnet")), Some(Protocol::Thorchain));
        assert_eq!(direct(a("evm", "base_mainnet"), a("vvv", "base_mainnet")), Some(Protocol::Thorchain));
        assert_eq!(direct(a("usdc", "sol_mainnet"), a("evm", "evm_mainnet")), None, "pas de pool USDC Solana sur THORChain");
        assert_eq!(direct(a("evm", "evm_mainnet"), a("evm", "evm_mainnet")), None);
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("btc", "btc_mainnet")), Some(Protocol::Maya), "Arbitrum : via Maya");
        assert_eq!(direct(a("usdt", "evm_mainnet"), a("usdc", "arbitrum_mainnet")), Some(Protocol::Maya));
        assert_eq!(direct(a("evm", "evm_mainnet"), a("btc", "btc_mainnet")), Some(Protocol::Thorchain), "THORChain avant Maya");
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("bnb", "bsc_mainnet")), None, "aucun protocole ne relie les deux");
        assert_eq!(find("usdc", "base_mainnet"), Some(a("usdc", "base_mainnet")));
        assert_eq!(find("hype", "hyperevm_mainnet"), None);
    }

    /// CoW : même réseau EVM seulement, jamais en vendant la monnaie du réseau,
    /// et seulement une fois l'adresse des frais renseignée.
    #[test]
    fn cow_links_same_network_tokens() {
        assert!(cow_links(a("link", "evm_mainnet"), a("usdc", "evm_mainnet")));
        assert!(cow_links(a("usdc", "arbitrum_mainnet"), a("evm", "arbitrum_mainnet")));
        assert!(cow_links(a("aster", "bsc_mainnet"), a("bnb", "bsc_mainnet")));
        assert!(!cow_links(a("evm", "evm_mainnet"), a("usdc", "evm_mainnet")), "vente native : EthFlow");
        assert!(!cow_links(a("link", "evm_mainnet"), a("usdc", "base_mainnet")), "deux réseaux");
        assert!(!cow_links(a("usdc", "sol_mainnet"), a("usdt", "sol_mainnet")));
        let link_usdc = direct(a("link", "evm_mainnet"), a("usdc", "evm_mainnet"));
        assert_eq!(link_usdc == Some(Protocol::Cow), cow_enabled());
        if cow_enabled() {
            assert_eq!(direct(a("usdc", "evm_mainnet"), a("evm", "evm_mainnet")), Some(Protocol::Cow), "CoW avant THORChain sur un même réseau");
        } else {
            assert!(link_usdc.is_none());
            assert_eq!(find("link", "evm_mainnet"), None);
        }
        assert_eq!(direct(a("evm", "evm_mainnet"), a("usdc", "evm_mainnet")), Some(Protocol::Thorchain));
    }

    /// Depuis Bitcoin : aucune route tant que le THORName n'existe pas ; vers
    /// Bitcoin : oui.
    #[test]
    fn bitcoin_sources_wait_for_the_thorname() {
        let btc = a("btc", "btc_mainnet");
        let eth = a("evm", "evm_mainnet");
        assert_eq!(direct(eth, btc), Some(Protocol::Thorchain));
        assert_eq!(direct(btc, eth).is_some(), thorchain_rpc::AFFILIATE_NAME.is_some());
        assert!(pairs().iter().all(|(from, to, _)| from != to));
    }
}
