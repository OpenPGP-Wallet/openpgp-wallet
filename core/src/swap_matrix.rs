//! REAL test bench for every swap (read-only, ignored by default): no test network
//! has pools for THORChain, Maya, Jupiter or LI.FI, so each pair is tried with real
//! quotes, through the SAME functions as the app (memo check, LI.FI transaction
//! check, CoW order check...), then the value received is compared with the value
//! sent in dollars: a decimals mistake would show up as a 10^k gap. A second run
//! goes as far as simulation, with funded public addresses (exchanges), without
//! ever signing anything.
//!
//! `cargo test --lib swap_matrix -- --ignored --nocapture --test-threads=1`

use super::*;
use crate::swap_routes::{self, Protocol, SwapAsset};
use std::collections::HashMap;
use std::time::Duration;

/// Value sent per trial (SWAP_MATRIX_USD variable, $50 by default: above the
/// protocols' minimums, negligible slippage).
fn trade_usd() -> f64 {
    std::env::var("SWAP_MATRIX_USD").ok().and_then(|v| v.parse().ok()).unwrap_or(50.0)
}

/// Maximum number of LI.FI quotes (SWAP_MATRIX_LIFI variable, 40 by default; LI.FI
/// allows 75 per 2 hours per IP address without a key).
fn lifi_budget() -> usize {
    std::env::var("SWAP_MATRIX_LIFI").ok().and_then(|v| v.parse().ok()).unwrap_or(40)
}

const EVM_DEST: &str = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
const BTC_DEST: &str = "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz";
/// Funded public addresses (exchanges), used as the sender of the quotes that
/// require one and for simulations.
const EVM_FUNDED: &str = "0x28C6c06298d514Db089934071355E5743bf21d60";
const SOL_FUNDED: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
/// Bitcoin: an exchange address for quotes (LI.FI reads its outputs); for the PSBT
/// check, an ordinary address (`btc_funded`), since Esplora refuses to list the
/// outputs of an address with a huge history.
const BTC_FUNDED: &str = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h";

/// An ordinary funded P2WPKH address (1 to 4 confirmed outputs), found in the
/// latest block.
fn btc_funded() -> String {
    let get = |url: String| -> serde_json::Value { reqwest::blocking::get(url).unwrap().json().unwrap() };
    let tip = reqwest::blocking::get("https://mempool.space/api/blocks/tip/hash").unwrap().text().unwrap();
    for tx in get(format!("https://mempool.space/api/block/{tip}/txs/0")).as_array().unwrap() {
        for out in tx["vout"].as_array().unwrap() {
            let value = out["value"].as_u64().unwrap_or(0);
            if out["scriptpubkey_type"] == "v0_p2wpkh" && (200_000..20_000_000).contains(&value) {
                let address = out["scriptpubkey_address"].as_str().unwrap().to_string();
                let utxos = get(format!("https://mempool.space/api/address/{address}/utxo"));
                let utxos = utxos.as_array().unwrap();
                if (1..=4).contains(&utxos.len()) && utxos.iter().all(|u| u["status"]["confirmed"] == true) {
                    return address;
                }
            }
        }
    }
    panic!("aucune adresse ordinaire trouvée dans le dernier bloc");
}

fn zec_dest() -> String {
    let (_, hash160) = derivation::derive_zec_key(&[3u8; 64], 0).unwrap();
    zcash::p2pkh_address(&hash160)
}

fn doge_dest() -> String {
    let (_, hash160) = derivation::derive_doge_key(&[3u8; 64], 0).unwrap();
    crate::doge::p2pkh_address(&hash160)
}

fn destination(network: &str) -> String {
    match network {
        "btc_mainnet" => BTC_DEST.to_string(),
        "sol_mainnet" => SOL_FUNDED.to_string(),
        "zec_mainnet" => zec_dest(),
        "doge_mainnet" => doge_dest(),
        _ => EVM_DEST.to_string(),
    }
}

fn gecko(coin: &str) -> &'static str {
    match coin {
        "evm" => "ethereum",
        "btc" => "bitcoin",
        "sol" => "solana",
        "usdc" => "usd-coin",
        "bnb" => "binancecoin",
        "avax" => "avalanche-2",
        "pol" => "polygon-ecosystem-token",
        "zec" => "zcash",
        "doge" => "dogecoin",
        "usdt" => "tether",
        "link" => "chainlink",
        "dai" => "dai",
        "usde" => "ethena-usde",
        "uni" => "uniswap",
        "usdg" => "global-dollar",
        "xaut" => "tether-gold",
        "ondo" => "ondo-finance",
        "qnt" => "quant-network",
        "fet" => "fetch-ai",
        "eurc" => "euro-coin",
        "gno" => "gnosis",
        "arb" => "arbitrum",
        "aster" => "aster-2",
        "vvv" => "venice-token",
        "render" => "render-token",
        _ => "",
    }
}

fn prices(assets: &[SwapAsset]) -> HashMap<&'static str, f64> {
    let mut ids: Vec<&str> = assets.iter().map(|a| gecko(a.coin)).filter(|g| !g.is_empty()).collect();
    ids.sort();
    ids.dedup();
    let url = format!("https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd", ids.join(","));
    // Explicit User-Agent, as in `price_rpc` (CoinGecko refuses without one).
    let client = reqwest::blocking::Client::builder().user_agent("openpgp-wallet (+https://github.com/KHADEVS/openpgp-wallet)").build().unwrap();
    let body: serde_json::Value = client.get(url).send().unwrap().json().unwrap();
    assert!(body.get("bitcoin").is_some(), "prix CoinGecko illisibles : {body}");
    assets
        .iter()
        .filter_map(|a| body[gecko(a.coin)]["usd"].as_f64().map(|p| (a.coin, p)))
        .collect()
}

fn decimals(asset: SwapAsset) -> u8 {
    if let Some((_, deployment)) = tokens::find(asset.coin, asset.network) {
        return deployment.decimals;
    }
    match asset.network {
        "btc_mainnet" | "zec_mainnet" | "doge_mainnet" => 8,
        "sol_mainnet" => 9,
        _ => 18,
    }
}

/// Amount worth about `trade_usd()`, 8 decimals at most.
fn amount_for(asset: SwapAsset, price: f64) -> String {
    let shown = decimals(asset).min(8) as usize;
    format!("{:.*}", shown, trade_usd() / price)
}

fn units(asset: SwapAsset, amount: &str) -> u128 {
    tokens::parse_amount(amount, decimals(asset)).unwrap()
}

/// Value received (units → dollars).
fn usd(out_units: u128, out_decimals: u8, price: f64) -> f64 {
    out_units as f64 / 10f64.powi(i32::from(out_decimals)) * price
}

/// One report line: pair, protocol, (value sent, value received) in dollars, or a refusal.
type Row = (String, Protocol, std::result::Result<(f64, f64), String>);

fn pause() {
    std::thread::sleep(Duration::from_millis(350));
}

/// A real quote: output in units of the received token, and its decimals.
fn quote(protocol: Protocol, from: SwapAsset, to: SwapAsset, amount: &str) -> Result<(u128, u8)> {
    match protocol {
        Protocol::Thorchain | Protocol::Maya => {
            let cross = protocol.cross_chain().unwrap();
            let (f, t) = (cross_chain_asset(cross, from.coin, from.network)?, cross_chain_asset(cross, to.coin, to.network)?);
            let q = get_swap_quote(cross, f, t, amount, &destination(to.network))?;
            Ok((u128::from(q.expected_amount_out), 8))
        }
        Protocol::Jupiter => {
            let q = get_jupiter_quote(from.coin, to.coin, amount, 50)?;
            Ok((u128::from(q.out_amount), jupiter_decimals(to.coin)?))
        }
        Protocol::Cow => {
            let (sell, buy) = cow_tokens(from.network, from.coin, to.coin)?;
            let net = wallet_flow::evm_network(from.network).context("réseau EVM")?;
            let order = get_cow_quote(net, &sell, &buy, amount, EVM_FUNDED, crate::cow::PARTNER_FEE_BPS)?;
            anyhow::ensure!(order.sell_amount <= units(from, amount), "CoW vendrait plus que le montant");
            Ok((order.expected_buy, buy.decimals))
        }
        Protocol::Lifi => {
            let (f, t) = lifi_tokens(from.coin, from.network, to.coin, to.network)?;
            let sender = match from.network {
                "sol_mainnet" => SOL_FUNDED,
                "btc_mainnet" => BTC_FUNDED,
                _ => EVM_FUNDED,
            };
            let q = lifi::quote(from.network, &f, to.network, &t, units(from, amount), sender, &destination(to.network), &lifi_initial_deny(from.network, to.network), None)?;
            Ok((q.to_amount, t.decimals))
        }
        Protocol::Swapkit => {
            let (f, t) = crate::swapkit::find(from.coin, from.network).zip(crate::swapkit::find(to.coin, to.network)).context("paire SwapKit")?;
            let sender = match from.network {
                "sol_mainnet" => SOL_FUNDED.to_string(),
                "btc_mainnet" => BTC_FUNDED.to_string(),
                "doge_mainnet" | "zec_mainnet" => destination(from.network),
                _ => EVM_FUNDED.to_string(),
            };
            let routes = crate::swapkit::quote(f, t, units(from, amount), &sender, &destination(to.network))?;
            Ok((routes[0].expected_out, t.decimals))
        }
        // Never offered in tests (the app's key is missing): its real quotes are tested in
        // `moonpay_trade` with the demo key.
        Protocol::Moonpay => anyhow::bail!("MoonPay Trade : devis testés dans moonpay_trade"),
    }
}

/// LI.FI: one pair per (source network, destination family), the network's native
/// coin first, within the quota.
fn lifi_sample(pairs: &[(SwapAsset, SwapAsset)]) -> Vec<(SwapAsset, SwapAsset)> {
    let family = |n: &str| match n {
        "btc_mainnet" => "btc",
        "sol_mainnet" => "sol",
        _ => "evm",
    };
    let mut seen: Vec<(&str, &str, bool)> = Vec::new();
    let mut picked = Vec::new();
    for &(from, to) in pairs {
        let native_from = tokens::find(from.coin, from.network).is_none();
        let key = (from.network, family(to.network), native_from);
        if !seen.contains(&key) && picked.len() < lifi_budget() {
            seen.push(key);
            picked.push((from, to));
        }
    }
    picked
}

#[test]
#[ignore]
fn swap_matrix_real_quotes() {
    let assets = swap_routes::assets();
    let price = prices(&assets);
    let mut lifi_pairs = Vec::new();
    let mut rows: Vec<Row> = Vec::new();
    for &from in &assets {
        for &to in &assets {
            if from == to {
                continue;
            }
            for protocol in swap_routes::direct_all(from, to) {
                if protocol == Protocol::Lifi {
                    lifi_pairs.push((from, to));
                    continue;
                }
                rows.push(run(protocol, from, to, &price));
            }
        }
    }
    for (from, to) in lifi_sample(&lifi_pairs) {
        rows.push(run(Protocol::Lifi, from, to, &price));
    }

    let (mut ok, mut gaps, mut bugs, mut errors) = (0, Vec::new(), Vec::new(), Vec::new());
    for (label, protocol, result) in &rows {
        match result {
            Ok((sent, got)) => {
                let ratio = got / sent;
                let line = format!("{label} via {protocol:?} : envoyé {sent:.2} $, reçu {got:.2} $ (×{ratio:.3})");
                if (0.80..=1.05).contains(&ratio) {
                    ok += 1;
                } else if (0.5..=1.5).contains(&ratio) {
                    gaps.push(line);
                } else {
                    bugs.push(line);
                }
            }
            Err(e) => errors.push(format!("{label} via {protocol:?} : {e}")),
        }
    }
    println!("\n=== {} devis : {ok} cohérents, {} écarts, {} conversions suspectes, {} refus", rows.len(), gaps.len(), bugs.len(), errors.len());
    for line in &gaps {
        println!("ÉCART   {line}");
    }
    for line in &bugs {
        println!("SUSPECT {line}");
    }
    for line in &errors {
        println!("REFUS   {line}");
    }
    assert!(bugs.is_empty(), "conversions suspectes");
}

fn run(protocol: Protocol, from: SwapAsset, to: SwapAsset, price: &HashMap<&'static str, f64>) -> Row {
    let label = format!("{}@{} → {}@{}", from.coin, from.network, to.coin, to.network);
    let (Some(&p_from), Some(&p_to)) = (price.get(from.coin), price.get(to.coin)) else {
        return (label, protocol, Err("prix inconnu".into()));
    };
    let amount = amount_for(from, p_from);
    let result = quote(protocol, from, to, &amount).map(|(out, dec)| (trade_usd(), usd(out, dec, p_to))).map_err(|e| format!("{e:#}"));
    pause();
    (label, protocol, result)
}

/// Up to simulation, with funded public addresses.
#[test]
#[ignore]
fn swap_simulations_real() {
    let price = prices(&swap_routes::assets());
    let a = |coin: &'static str, network: &'static str| SwapAsset { coin, network };
    let mut report = Vec::new();

    // Jupiter: transaction built for the public address, effects checked.
    let rpc = sol_rpc::SolRpc::new(wallet_flow::SOLANA_MAINNET.rpc);
    let owner: [u8; 32] = bs58::decode(SOL_FUNDED).into_vec().unwrap().try_into().unwrap();
    for (from, to) in [("sol", "usdc"), ("usdc", "sol"), ("sol", "usdt"), ("usdt", "usdc"), ("sol", "render")] {
        let amount = amount_for(a(from, "sol_mainnet"), price[from]);
        let result = (|| -> Result<String> {
            let (input, output) = (jupiter_mint_for_coin(from)?, jupiter_mint_for_coin(to)?);
            let native = jupiter_amount(from, &amount)?;
            let fee_mint = jupiter_fee_mint(&rpc, &input, &output)?;
            let q = jupiter_rpc::quote(&input, &output, native, 50, fee_mint)?;
            let raw = jupiter_rpc::build_swap_transaction(&q, SOL_FUNDED)?;
            let min_out = q.out_amount * 9_950 / 10_000;
            check_swap_effects(&rpc, &raw, &swap_effect_limits(owner, from, native, to, min_out)?)?;
            Ok(format!("simulation OK, frais app : {}", if fee_mint.is_some() { "oui" } else { "non" }))
        })();
        report.push(format!("Jupiter {from} → {to} ({amount}) : {}", result.map_err(|e| format!("{e:#}")).unwrap_or_else(|e| format!("ÉCHEC {e}"))));
        pause();
    }

    // LI.FI: full check (EVM / Solana simulation, Bitcoin PSBT).
    let btc_sender = btc_funded();
    for (from, to, sender) in [
        (a("evm", "evm_mainnet"), a("btc", "btc_mainnet"), EVM_FUNDED),
        (a("usdc", "evm_mainnet"), a("sol", "sol_mainnet"), EVM_FUNDED),
        (a("sol", "sol_mainnet"), a("evm", "evm_mainnet"), SOL_FUNDED),
        (a("btc", "btc_mainnet"), a("evm", "evm_mainnet"), btc_sender.as_str()),
        (a("btc", "btc_mainnet"), a("sol", "sol_mainnet"), btc_sender.as_str()),
    ] {
        let amount = amount_for(from, price[from.coin]);
        let result = (|| -> Result<String> {
            let (f, t) = lifi_tokens(from.coin, from.network, to.coin, to.network)?;
            let (q, verified) = lifi_verified_quote(from.network, &f, to.network, &t, &amount, sender, &destination(to.network))?;
            let extra = if from.network == "btc_mainnet" {
                let deposit = lifi_btc_deposit(&q)?;
                format!(", PSBT vérifiée : frais réseau {} sat, frais LI.FI+app {} sat", deposit.network_fee, deposit.service_fees)
            } else {
                String::new()
            };
            let got = usd(q.to_amount, t.decimals, price[to.coin]);
            Ok(format!("OK via {} (destinataire vérifié : {verified}), reçu ≈ {got:.2} ${extra}", q.tool_name))
        })();
        report.push(format!("LI.FI {}@{} → {}@{} ({amount}) : {}", from.coin, from.network, to.coin, to.network, result.map_err(|e| format!("{e:#}")).unwrap_or_else(|e| format!("ÉCHEC {e}"))));
        pause();
    }

    // THORChain from Ethereum: quote checked, then gas estimated for the deposit
    // through the router, on behalf of the public address.
    for (from, to) in [(a("evm", "evm_mainnet"), a("btc", "btc_mainnet")), (a("usdc", "evm_mainnet"), a("btc", "btc_mainnet"))] {
        let amount = amount_for(from, price[from.coin]);
        let result = (|| -> Result<String> {
            let cross = &thorchain_rpc::THORCHAIN;
            let (f, t) = (cross_chain_asset(cross, from.coin, from.network)?, cross_chain_asset(cross, to.coin, to.network)?);
            let q = get_swap_quote(cross, f, t, &amount, BTC_DEST)?;
            let net = wallet_flow::evm_network(from.network).unwrap();
            let gas_price = evm_gas_price_for_confirmation(net)?;
            let fees = evm_swap_fees(net, f, &q, &amount, gas_price, Some(EVM_FUNDED))?;
            Ok(format!("OK, memo {} ; frais max {:.6} ETH ({} autorisation(s))", q.memo, fees.max_total()? as f64 / 1e18, fees.approvals))
        })();
        report.push(format!("THORChain {}@{} → BTC ({amount}) : {}", from.coin, from.network, result.map_err(|e| format!("{e:#}")).unwrap_or_else(|e| format!("ÉCHEC {e}"))));
        pause();
    }

    println!("\n=== Simulations");
    for line in &report {
        println!("{line}");
    }
}
