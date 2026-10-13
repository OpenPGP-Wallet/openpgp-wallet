//! Indicative prices of the cryptocurrencies in fiat (USD), through the public
//! CoinGecko API: no key required, and no data sent about the user or their
//! addresses (just "what is the current price of ETH/BTC/SOL?", the same for
//! everyone), unlike `eth_rpc`/`btc_rpc`/`sol_rpc`, which query a specific address.
//! Purely informative, for display; plays no part in building or signing a
//! transaction.

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

// See eth_rpc::shared_client: a `reqwest::Client` rebuilt on every command throws
// away its pool of keep-alive connections and pays for a full TCP + TLS handshake
// on every click. A single shared client, built once.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            // Same reason as the other RPC clients (eth/btc/sol): without a timeout, a silent
            // service would block the app forever on this purely informative call. Explicit
            // `user_agent`: reqwest's default User-Agent ("reqwest/x.y.z") got a 403 from
            // CoinGecko (probably filtered as generic bot traffic), while an identical call
            // with a named browser or tool User-Agent went through.
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("openpgp-wallet (+https://github.com/KHADEVS/openpgp-wallet)")
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
        // Explicitly tells a rate limit (free public API without a key, expected now and
        // then, especially when several devices or dev instances hit the same service
        // within a short time) apart from a real outage. Without this, the generic
        // deserialization error ("missing field") does not say why the expected JSON is
        // not there.
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

    /// Price + market cap for the dashboard's "Markets" section. Unlike `get_prices`
    /// (just the price, to convert a displayed balance), it shows a small market
    /// ranking, explicitly sorted by market cap here rather than relying only on the
    /// API's `order` parameter (locks the guarantee in instead of hoping it holds).
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
            // Only the requested IDs, with a price: CoinGecko puts `null` for an asset that
            // temporarily has no quote.
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
                // CoinGecko omits this field (instead of setting it to 0) for an asset too new or
                // illiquid to have a computable 24h change; `Option` rather than a default `0.0`,
                // which would suggest a real flat day.
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

/// Price of an xStocks tokenized stock.
#[derive(Debug, Clone)]
pub struct StockPrice {
    pub mint: String,
    /// Price of one DISPLAYED unit in dollars (measured on 2026-10-09: Jupiter's
    /// `usdPrice` follows the stock price; the price of a raw token is
    /// `usdPricePrescaled`, display multiplier included).
    pub usd: f64,
    pub change_24h_percent: Option<f64>,
    /// Market cap of the company (or fund), if Jupiter provides it.
    pub market_cap_usd: Option<f64>,
}

/// Prices of the `mints` xStocks through Jupiter's price API (free, no key; no data
/// about the user). Purely informative: never used to build or sign a transaction.
/// A mint without a valid price is left out.
pub fn jupiter_stock_prices(mints: &[&str]) -> Result<Vec<StockPrice>> {
    anyhow::ensure!(mints.len() <= 50, "trop de jetons pour un seul appel de prix");
    if mints.is_empty() {
        return Ok(Vec::new());
    }
    let url = format!("https://lite-api.jup.ag/price/v3?ids={}", mints.join(","));
    let response = shared_client().get(url).send().context("appel des prix Jupiter impossible")?;
    anyhow::ensure!(response.status().is_success(), "les prix Jupiter ont répondu {}", response.status());
    let body: serde_json::Value = response.json().context("réponse des prix Jupiter illisible")?;
    Ok(mints
        .iter()
        .filter_map(|mint| {
            let entry = body.get(*mint)?;
            let usd = entry["usdPrice"].as_f64().filter(|p| p.is_finite() && *p > 0.0)?;
            Some(StockPrice {
                mint: mint.to_string(),
                usd,
                change_24h_percent: entry["priceChange24h"].as_f64().filter(|c| c.is_finite()),
                market_cap_usd: entry["stockData"]["mcap"].as_f64().filter(|m| m.is_finite() && *m > 0.0),
            })
        })
        .collect())
}

/// Cryptocurrencies whose price the app shows (CoinGecko IDs): a single call for
/// all of them, sorted by market cap.
pub const MARKET_IDS: &[&str] = &[
    "bitcoin",
    "ethereum",
    "solana",
    "usd-coin",
    "binancecoin",
    "avalanche-2",
    "polygon-ecosystem-token",
    "zcash",
    "monero",
    "dogecoin",
    "tron",
    "ripple",
    "stellar",
    "near",
    "cardano",
    "blockstack",
    "bittensor",
    // Tokens (core/src/tokens.rs).
    "tether",
    "chainlink",
    "dai",
    "ethena-usde",
    "uniswap",
    "global-dollar",
    "tether-gold",
    "ondo-finance",
    "quant-network",
    "fetch-ai",
    "euro-coin",
    "gnosis",
    "arbitrum",
    "aster-2",
    "venice-token",
    "render-token",
    // Liquid staking (JitoSOL, stETH).
    "jito-staked-sol",
    "staked-ether",
];

pub struct MarketCoin {
    /// CoinGecko ID (see `MARKET_IDS`).
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

    // `#[ignore]`: a real network test (not in the default suite), run explicitly to
    // diagnose an end-to-end problem.
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
        // BTC still has the largest market cap in crypto to date.
        assert_eq!(coins[0].symbol, "BTC");
        assert!(
            coins[0].change_24h_percent.is_some(),
            "BTC a toujours une variation 24h calculable (actif liquide et ancien)"
        );
    }
}
