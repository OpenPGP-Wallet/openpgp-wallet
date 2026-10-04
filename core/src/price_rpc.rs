//! Prix indicatifs des 3 cryptos en monnaie fiduciaire (USD), via l'API publique
//! CoinGecko : aucune clé requise, aucune donnée envoyée sur l'utilisateur ou ses
//! adresses (juste "quel est le prix actuel de l'ETH/BTC/SOL ?", identique pour
//! tout le monde) — contrairement à `eth_rpc`/`btc_rpc`/`sol_rpc`, qui interrogent
//! une adresse précise. Purement informatif pour l'affichage ; ne joue aucun rôle
//! dans la construction ou la signature d'une transaction.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::sync::OnceLock;

const COINGECKO_URL: &str =
    "https://api.coingecko.com/api/v3/simple/price?ids=ethereum,bitcoin,solana&vs_currencies=usd";

pub struct Prices {
    pub eth_usd: f64,
    pub btc_usd: f64,
    pub sol_usd: f64,
}

#[derive(Deserialize)]
struct CoinPrice {
    usd: f64,
}

#[derive(Deserialize)]
struct CoinGeckoResponse {
    ethereum: CoinPrice,
    bitcoin: CoinPrice,
    solana: CoinPrice,
}

pub struct PriceRpc {
    client: reqwest::blocking::Client,
}

// Voir eth_rpc::shared_client : un `reqwest::Client` reconstruit à chaque appel de
// commande jette son pool de connexions keep-alive et repaie une poignée de main
// TCP+TLS complète à chaque clic. Un seul client partagé, construit une fois.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            // Même raison que les autres clients RPC (eth/btc/sol) : sans timeout,
            // un service muet bloquerait l'app indéfiniment sur cet appel purement
            // informatif. `user_agent` explicite : le User-Agent par défaut de
            // reqwest ("reqwest/x.y.z") s'est fait renvoyer un 403 par CoinGecko
            // (probablement filtré comme trafic de bot générique), alors qu'un
            // appel identique avec un User-Agent de navigateur/outil nommé passait.
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("pgp-wallet-poc/0.1 (+https://github.com/)")
            .build()
            .expect("configuration du client HTTP valide")
    })
}

impl PriceRpc {
    pub fn new() -> Self {
        Self {
            client: shared_client().clone(),
        }
    }

    pub fn get_prices(&self) -> Result<Prices> {
        let response = self.client.get(COINGECKO_URL).send().context("appel CoinGecko impossible")?;
        // Distingue explicitement un rate-limit (API publique gratuite, sans clé —
        // attendu occasionnellement, notamment si plusieurs appareils/instances de
        // dev tapent le même service en peu de temps) d'une vraie panne : sans ça,
        // l'erreur générique de désérialisation ("champ manquant") ne dit pas
        // pourquoi le JSON attendu n'est pas là.
        anyhow::ensure!(
            response.status().is_success(),
            "CoinGecko a répondu {} (rate-limit probable si 429 : API gratuite, sans clé)",
            response.status()
        );
        let resp: CoinGeckoResponse = response.json().context("réponse CoinGecko illisible")?;
        Ok(Prices {
            eth_usd: resp.ethereum.usd,
            btc_usd: resp.bitcoin.usd,
            sol_usd: resp.solana.usd,
        })
    }

    /// Prix + capitalisation boursière pour la section "Marchés" du tableau de
    /// bord. Contrairement à `get_prices` (juste le prix, pour convertir un solde
    /// affiché), sert à afficher un mini-classement du marché — trié explicitement
    /// par capitalisation ici, sans se fier uniquement au paramètre `order` de
    /// l'API (verrouille la garantie plutôt que d'espérer qu'elle tienne).
    pub fn get_market_data(&self) -> Result<Vec<MarketCoin>> {
        let url = format!(
            "https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids={}&order=market_cap_desc&price_change_percentage=24h",
            MARKET_IDS.join(",")
        );
        let response = self
            .client
            .get(url)
            .send()
            .context("appel CoinGecko (marchés) impossible")?;
        anyhow::ensure!(
            response.status().is_success(),
            "CoinGecko a répondu {} pour les données de marché",
            response.status()
        );
        let raw: Vec<MarketCoinRaw> = response.json().context("réponse CoinGecko (marchés) illisible")?;
        let mut coins: Vec<MarketCoin> = raw
            .into_iter()
            // Seulement les identifiants demandés, avec un prix : CoinGecko met
            // `null` pour un actif momentanément sans cotation.
            .filter(|c| MARKET_IDS.contains(&c.id.as_str()))
            .filter_map(|c| {
                let price = c.current_price.filter(|p| p.is_finite() && *p > 0.0)?;
                Some((c, price))
            })
            .map(|(c, price)| MarketCoin {
                id: c.id,
                symbol: c.symbol.to_uppercase(),
                name: c.name,
                price_usd: price,
                market_cap_usd: c.market_cap.unwrap_or(0.0),
                // CoinGecko omet ce champ (au lieu de le mettre à 0) pour un actif
                // trop récent/illiquide pour avoir une variation calculable sur 24h ;
                // `Option` plutôt qu'un `0.0` par défaut qui laisserait croire à une
                // vraie stagnation.
                change_24h_percent: c.price_change_percentage_24h,
            })
            .collect();
        coins.sort_by(|a, b| {
            b.market_cap_usd
                .partial_cmp(&a.market_cap_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(coins)
    }
}

/// Cryptos dont l'app affiche le cours (identifiants CoinGecko) : un seul
/// appel pour toutes, trié par capitalisation.
pub const MARKET_IDS: &[&str] = &[
    "bitcoin",
    "ethereum",
    "solana",
    "usd-coin",
    "binancecoin",
    "avalanche-2",
    "polygon-ecosystem-token",
    "hyperliquid",
    "zcash",
    "monero",
    "dogecoin",
    "tron",
    "ripple",
    "stellar",
    // Jetons (core/src/tokens.rs).
    "tether",
    "chainlink",
    "dai",
    "ethena-usde",
    "uniswap",
    "global-dollar",
    "tether-gold",
    "ondo-finance",
    "fetch-ai",
    "euro-coin",
    "gnosis",
    "arbitrum",
    "aster-2",
    "venice-token",
    "render-token",
];

pub struct MarketCoin {
    /// Identifiant CoinGecko (voir `MARKET_IDS`).
    pub id: String,
    pub symbol: String,
    pub name: String,
    pub price_usd: f64,
    pub market_cap_usd: f64,
    pub change_24h_percent: Option<f64>,
}

#[derive(Deserialize)]
struct MarketCoinRaw {
    id: String,
    symbol: String,
    name: String,
    current_price: Option<f64>,
    market_cap: Option<f64>,
    price_change_percentage_24h: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // `#[ignore]` : test réseau réel (pas dans la suite par défaut), lancé
    // explicitement pour diagnostiquer un souci de bout en bout.
    #[test]
    #[ignore]
    fn real_coingecko_call_succeeds() {
        let prices = PriceRpc::new().get_prices().expect("l'appel CoinGecko doit réussir");
        println!("ETH={} BTC={} SOL={}", prices.eth_usd, prices.btc_usd, prices.sol_usd);
        assert!(prices.eth_usd > 0.0);
        assert!(prices.btc_usd > 0.0);
        assert!(prices.sol_usd > 0.0);
    }

    #[test]
    #[ignore]
    fn real_coingecko_markets_call_is_sorted_by_market_cap_desc() {
        let coins = PriceRpc::new().get_market_data().expect("l'appel CoinGecko (marchés) doit réussir");
        assert_eq!(coins.len(), MARKET_IDS.len(), "une entrée par identifiant demandé");
        for pair in coins.windows(2) {
            assert!(
                pair[0].market_cap_usd >= pair[1].market_cap_usd,
                "{} devrait avoir une capitalisation >= {}",
                pair[0].symbol,
                pair[1].symbol
            );
        }
        // BTC a toujours la plus grosse capitalisation du marché crypto à ce jour.
        assert_eq!(coins[0].symbol, "BTC");
        assert!(
            coins[0].change_24h_percent.is_some(),
            "BTC a toujours une variation 24h calculable (actif liquide et ancien)"
        );
    }
}
