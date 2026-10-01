//! Routes d'échange entre les cryptos de l'app : quel protocole relie une
//! crypto (sur un réseau) à une autre. Fonction pure, sans appel réseau :
//! source unique de ce que l'interface propose (« Convertir ») et de ce que
//! les commandes d'échange acceptent.

use crate::thorchain_rpc;
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
}

/// Cryptos échangeables via Jupiter (voir `api::send_jupiter_swap`).
const JUPITER: [SwapAsset; 2] = [SwapAsset { coin: "sol", network: "sol_mainnet" }, SwapAsset { coin: "usdc", network: "sol_mainnet" }];

fn on_thorchain(asset: SwapAsset) -> bool {
    thorchain_rpc::asset(asset.coin, asset.network).is_some()
}

/// Protocole qui relie directement `from` à `to`, s'il existe. Jupiter
/// d'abord (même portefeuille, sans délai cross-chain). Depuis Bitcoin, pas
/// de route tant que le THORName d'affiliation n'est pas enregistré : le memo
/// avec l'adresse complète dépasse les 80 octets d'un OP_RETURN (voir
/// `thorchain_rpc::AFFILIATE_NAME`).
pub fn direct(from: SwapAsset, to: SwapAsset) -> Option<Protocol> {
    if from == to {
        return None;
    }
    if JUPITER.contains(&from) && JUPITER.contains(&to) {
        return Some(Protocol::Jupiter);
    }
    if from.coin == "btc" && thorchain_rpc::AFFILIATE_NAME.is_none() {
        return None;
    }
    (on_thorchain(from) && on_thorchain(to)).then_some(Protocol::Thorchain)
}

/// Toutes les cryptos qu'au moins un protocole sait échanger.
pub fn assets() -> Vec<SwapAsset> {
    let mut all: Vec<SwapAsset> = thorchain_rpc::ASSETS.iter().map(|a| SwapAsset { coin: a.coin, network: a.network }).collect();
    for asset in JUPITER {
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
        assert_eq!(direct(a("evm", "arbitrum_mainnet"), a("btc", "btc_mainnet")), None, "Arbitrum : pas encore");
        assert_eq!(find("usdc", "base_mainnet"), Some(a("usdc", "base_mainnet")));
        assert_eq!(find("hype", "hyperevm_mainnet"), None);
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
