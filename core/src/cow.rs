//! CoW Protocol: a swap between two cryptos on the SAME EVM network through a
//! signed order (EIP-712), then executed by the protocol's "solvers". Unlike a
//! transaction built by a third party, the order is a structured message built HERE
//! and fully readable: token sold and quantity, token bought and MINIMUM received,
//! recipient (the user), validity, partner fee (`appData`), all verified before
//! signing. Selling a token needs a prior approval for CoW's "VaultRelayer" (for
//! the exact amount, see `api::send_cow_swap`). An order that is not executed
//! expires at no cost.
//!
//! Selling a network's native coin (ETH, BNB…) goes through CoW's EthFlow contract:
//! a `createOrder` transaction (built here) hands it the amount and creates the
//! order on its behalf; if not executed, the order expires and CoW refunds (see
//! `api::send_cow_eth_flow`).
//!
//! Amounts are computed exactly like the official SDK (`@cowprotocol/cow-sdk`,
//! `getQuoteAmountsAndCosts`, read in its code): the quote gives the sell amount
//! after network fees and the matching buy amount; the order signs the TOTAL sell
//! amount (network fees included, `feeAmount` = 0) and a minimum buy amount = the
//! quote's buy amount − partner fee − slippage.

use crate::{evm_sign, tokens, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::OnceLock;

const API_BASE: &str = "https://api.cow.fi";
/// GPv2 settlement contract, at the same address on every CoW network (the order's
/// EIP-712 domain).
pub const SETTLEMENT: &str = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41";
/// Contract that pulls the token sold at settlement time: this is the one that
/// receives the approval (`approve`).
pub const VAULT_RELAYER: &str = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110";
/// CoW convention for a native coin being BOUGHT (ETH, BNB…).
pub const NATIVE_BUY_TOKEN: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
/// CoW's EthFlow contract (selling a network's native coin), at the same address on
/// all its networks (@cowprotocol/sdk-config, ETH_FLOW_ADDRESSES); presence,
/// wrapped coin and settlement contract checked again on each network (test
/// `real_eth_flow_contracts`).
pub const ETH_FLOW: &str = "0xba3cb449bd2b4adddbc894d8697f5170800eadec";
/// Partner fee: 100 bps = 1% (the protocol's cap), paid weekly in WETH on Ethereum
/// to `PARTNER_FEE_RECIPIENT` (CoW keeps a share, see
/// docs.cow.fi/governance/fees/partner-fee).
pub const PARTNER_FEE_BPS: u32 = 100;
/// The developer's Ethereum address that receives the partner fees (provided on
/// 2026-10-02; valid EIP-55 checksum, an ordinary account on Ethereum with no
/// contract code). Without it (`None`), there is no CoW route.
pub const PARTNER_FEE_RECIPIENT: Option<&str> = Some("0xae702daEd4723ac516492Bb1084F50e07e75573C");
/// Slippage tolerated below the expected buy amount (1%).
pub const SLIPPAGE_BPS: u32 = 100;
/// Validity requested for an order, and the maximum accepted from a quote.
const VALID_FOR_SECS: u64 = 1800;
const MAX_VALIDITY_SECS: u64 = 3600;
const APP_CODE: &str = "OpenPGP Wallet";
/// Version of the `appData` schema (`partnerFee` = { volumeBps, recipient }, schema
/// v1.15.0, the latest in the official SDK @cowprotocol/sdk-app-data).
const APP_DATA_VERSION: &str = "1.15.0";

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// CoW API URL segment for one of the app's networks (`None`: not on CoW).
pub fn api_network(network: &str) -> Option<&'static str> {
    Some(match network {
        "evm_mainnet" => "mainnet",
        "arbitrum_mainnet" => "arbitrum_one",
        "base_mainnet" => "base",
        "polygon_mainnet" => "polygon",
        "avax_mainnet" => "avalanche",
        "bsc_mainnet" => "bnb",
        _ => return None,
    })
}

/// "ERC-20 token" version of a network's native coin (WETH, WBNB…), the one an
/// EthFlow order sells (@cowprotocol/sdk-config, WRAPPED_NATIVE_CURRENCIES).
pub fn wrapped_native(network: &str) -> Option<&'static str> {
    Some(match network {
        "evm_mainnet" => "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "arbitrum_mainnet" => "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
        "base_mainnet" => "0x4200000000000000000000000000000000000006",
        "polygon_mainnet" => "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
        "avax_mainnet" => "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",
        "bsc_mainnet" => "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
        _ => return None,
    })
}

/// Card identifier of a network's native coin (ETH = "evm").
fn native_coin(network: &wallet_flow::EvmNetwork) -> &'static str {
    match network.native_symbol {
        "ETH" => "evm",
        "BNB" => "bnb",
        "AVAX" => "avax",
        "POL" => "pol",
        _ => "",
    }
}

/// A crypto that can be swapped on CoW: an ERC-20 token from the registry, or the
/// network's native coin (bought directly, sold through the EthFlow contract).
#[derive(Clone, Debug, PartialEq)]
pub struct CowToken {
    pub address: String,
    pub decimals: u8,
    pub symbol: &'static str,
    pub native: bool,
}

pub fn token(coin: &str, network: &str) -> Option<CowToken> {
    api_network(network)?;
    if let Some((info, deployment)) = tokens::find(coin, network) {
        return match deployment.kind {
            tokens::TokenKind::Erc20 { contract } => Some(CowToken { address: contract.to_string(), decimals: deployment.decimals, symbol: info.symbol, native: false }),
            tokens::TokenKind::Spl { .. } | tokens::TokenKind::Spl2022 { .. } | tokens::TokenKind::Trc20 { .. } => None,
        };
    }
    let net = wallet_flow::evm_network(network)?;
    (native_coin(net) == coin).then(|| CowToken { address: NATIVE_BUY_TOKEN.to_string(), decimals: 18, symbol: net.native_symbol, native: true })
}

/// Every app crypto CoW can swap (identifier, network): native coins and ERC-20
/// tokens from the registry.
pub fn tradable() -> Vec<(&'static str, &'static str)> {
    let natives = wallet_flow::EVM_NETWORKS.iter().filter(|n| api_network(n.id).is_some() && !native_coin(n).is_empty()).map(|n| (native_coin(n), n.id));
    let erc20 = tokens::TOKENS.iter().flat_map(|t| {
        t.deployments
            .iter()
            .filter(|d| api_network(d.network).is_some() && matches!(d.kind, tokens::TokenKind::Erc20 { .. }))
            .map(move |d| (t.id, d.network))
    });
    natives.chain(erc20).collect()
}

/// An order's page on CoW's official explorer (network prefixes taken from the CoW
/// Swap code, libs/common-utils/src/explorer.ts).
pub fn explorer_order_url(network: &str, uid: &str) -> Option<String> {
    let prefix = match network {
        "evm_mainnet" => "",
        "arbitrum_mainnet" => "arb1/",
        "base_mainnet" => "base/",
        "polygon_mainnet" => "pol/",
        "avax_mainnet" => "avax/",
        "bsc_mainnet" => "bnb/",
        _ => return None,
    };
    Some(format!("https://explorer.cow.fi/{prefix}orders/{uid}"))
}

/// The order's `appData` document (sorted keys, compact, like the SDK): the app
/// code and the partner fee (`partner_fee_bps`: `PARTNER_FEE_BPS`, or the liquid
/// staking rate, see `swap_routes::staking_fee_bps`).
pub fn app_data(recipient: &str, partner_fee_bps: u32) -> String {
    format!(r#"{{"appCode":"{APP_CODE}","metadata":{{"partnerFee":{{"recipient":"{recipient}","volumeBps":{partner_fee_bps}}}}},"version":"{APP_DATA_VERSION}"}}"#)
}

/// An order ready to sign, exactly as it will be SHOWN and then signed.
#[derive(Clone, Debug)]
pub struct CowOrder {
    pub network: &'static str,
    pub sell_token: String,
    pub buy_token: String,
    pub receiver: String,
    /// Total signed sell amount (network fees included), in units of the token sold.
    pub sell_amount: u128,
    /// Expected buy amount after all fees, before slippage.
    pub expected_buy: u128,
    /// Signed minimum buy amount (expected − slippage).
    pub min_buy: u128,
    /// Network fee estimated by CoW, in the token sold (already included in
    /// `sell_amount`).
    pub network_fee_sell: u128,
    /// Partner fee, in the token bought.
    pub partner_fee_buy: u128,
    /// Partner fee rate (basis points), the one in the signed appData.
    pub partner_fee_bps: u32,
    pub valid_to: u32,
    pub app_data: String,
    pub app_data_hash: [u8; 32],
    /// Selling the network's native coin through EthFlow (`sell_token` = its wrapped
    /// version): the quote identifier, required by the contract.
    pub eth_flow_quote_id: Option<i64>,
}

fn u128_field(value: &Value, field: &str) -> Result<u128> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("devis CoW sans « {field} » exploitable"))
}

/// a × b / c without intermediate overflow: two 18-decimal tokens with a low unit
/// price (FET, ARB…) produce products above 2^128 (seen on real FET ⇄ ARB quotes:
/// ~1.7e39), which used to cause an "amount out of range" refusal before this
/// extended-precision calculation.
fn mul_div(a: u128, b: u128, c: u128) -> Option<u128> {
    use num_bigint::BigUint;
    if c == 0 {
        return None;
    }
    u128::try_from(BigUint::from(a) * BigUint::from(b) / BigUint::from(c)).ok()
}

/// Order amounts from the quote (sell amount after network fees, matching buy
/// amount, network fee in the token sold, protocol fee in bps), using the official
/// SDK's formula: (total sell amount, expected buy amount, minimum, partner fee).
pub fn order_amounts(sell: u128, buy: u128, fee: u128, protocol_fee_bps: f64, partner_fee_bps: u32) -> Result<(u128, u128, u128, u128)> {
    ensure!(sell > 0 && buy > 0, "devis CoW vide");
    let cost_in_buy = mul_div(buy, fee, sell).context("montant hors limites")?;
    let scaled = (protocol_fee_bps * 100_000.0).round();
    ensure!((0.0..1e9).contains(&scaled), "frais du protocole CoW inattendus");
    let scaled = scaled as u128;
    let protocol_fee = if scaled > 0 { mul_div(buy, scaled, 10_000 * 100_000 - scaled).context("montant hors limites")? } else { 0 };
    let before_all = buy.checked_add(cost_in_buy).and_then(|b| b.checked_add(protocol_fee)).context("montant hors limites")?;
    let partner_fee = before_all.checked_mul(u128::from(partner_fee_bps)).context("montant hors limites")? / 10_000;
    let expected = buy.checked_sub(partner_fee).context("frais supérieurs à la réception")?;
    let min = expected - expected * u128::from(SLIPPAGE_BPS) / 10_000;
    Ok((sell.checked_add(fee).context("montant hors limites")?, expected, min, partner_fee))
}

/// CoW quote for selling `amount` (units) of `sell` for `buy` on `network`, on
/// behalf of `owner` (seller AND recipient). The response is checked again (tokens,
/// recipient, direction, amounts) before the order is derived from it.
pub fn quote(network: &'static str, sell: &CowToken, buy: &CowToken, amount: u128, owner: &str, recipient: &str, partner_fee_bps: u32) -> Result<CowOrder> {
    ensure!(sell.address != buy.address, "échange d'une crypto vers elle-même");
    let api = api_network(network).ok_or_else(|| anyhow!("réseau non pris en charge par CoW"))?;
    // EthFlow: quote on the wrapped version, order created on-chain by the contract
    // (official SDK parameters, ETH_FLOW_AUX_QUOTE_PARAMS).
    let sell_token = if sell.native { wrapped_native(network).context("réseau sans EthFlow")?.to_string() } else { sell.address.clone() };
    ensure!(!(sell.native && buy.native), "échange d'une crypto vers elle-même");
    let app_data = app_data(recipient, partner_fee_bps);
    let app_data_hash = evm_sign::keccak(app_data.as_bytes());
    let mut body = json!({
        "sellToken": sell_token,
        "buyToken": buy.address,
        "from": owner,
        "receiver": owner,
        "appData": app_data,
        "appDataHash": format!("0x{}", hex::encode(app_data_hash)),
        "sellTokenBalance": "erc20",
        "buyTokenBalance": "erc20",
        "priceQuality": "verified",
        "signingScheme": "eip712",
        "onchainOrder": false,
        "kind": "sell",
        "sellAmountBeforeFee": amount.to_string(),
        "validFor": VALID_FOR_SECS,
    });
    if sell.native {
        body["signingScheme"] = json!("eip1271");
        body["onchainOrder"] = json!(true);
        body["verificationGasLimit"] = json!(0);
    }
    let response: Value = shared_client()
        .post(format!("{API_BASE}/{api}/api/v1/quote"))
        .json(&body)
        .send()
        .context("requête de devis CoW impossible")?
        .json()
        .context("réponse de devis CoW illisible")?;
    if let Some(error) = response.get("errorType").and_then(Value::as_str) {
        let detail = response.get("description").and_then(Value::as_str).unwrap_or("");
        bail!("devis CoW refusé : {error} {detail}");
    }
    let q = response.get("quote").ok_or_else(|| anyhow!("réponse de devis CoW sans devis"))?;
    let text = |field: &str| q.get(field).and_then(Value::as_str).unwrap_or_default().to_ascii_lowercase();
    ensure!(text("sellToken") == sell_token.to_ascii_lowercase(), "devis CoW pour un autre jeton vendu");
    ensure!(text("buyToken") == buy.address.to_ascii_lowercase(), "devis CoW pour un autre jeton acheté");
    ensure!(text("receiver") == owner.to_ascii_lowercase(), "devis CoW pour un autre destinataire");
    ensure!(text("kind") == "sell" && q.get("partiallyFillable") == Some(&Value::Bool(false)), "devis CoW d'un autre type d'ordre");
    let (sell_after, buy_quoted, fee) = (u128_field(q, "sellAmount")?, u128_field(q, "buyAmount")?, u128_field(q, "feeAmount")?);
    ensure!(sell_after.checked_add(fee) == Some(amount), "devis CoW pour un autre montant que {amount}");
    let protocol_fee_bps = match response.get("protocolFeeBps") {
        Some(Value::String(s)) => s.parse().context("frais du protocole CoW illisibles")?,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        _ => 0.0,
    };
    let (sell_amount, expected_buy, min_buy, partner_fee_buy) = order_amounts(sell_after, buy_quoted, fee, protocol_fee_bps, partner_fee_bps)?;
    let valid_to = q.get("validTo").and_then(Value::as_u64).ok_or_else(|| anyhow!("devis CoW sans validité"))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).context("horloge système invalide")?.as_secs();
    ensure!(valid_to > now && valid_to <= now + MAX_VALIDITY_SECS, "validité du devis CoW inattendue");
    let eth_flow_quote_id = if sell.native { Some(response.get("id").and_then(Value::as_i64).context("devis CoW sans identifiant (exigé par EthFlow)")?) } else { None };
    Ok(CowOrder {
        network,
        sell_token,
        buy_token: buy.address.clone(),
        receiver: owner.to_string(),
        sell_amount,
        expected_buy,
        min_buy,
        network_fee_sell: fee,
        partner_fee_buy,
        partner_fee_bps,
        valid_to: valid_to as u32,
        app_data,
        app_data_hash,
        eth_flow_quote_id,
    })
}

/// Calldata for the EthFlow contract's `createOrder(EthFlowOrder.Data)` (structure
/// of the official contract: buyToken, receiver, sellAmount, buyAmount, appData,
/// feeAmount, validTo, partiallyFillable, quoteId; fixed-size types only, encoded
/// back to back). The value sent must be `sell_amount`.
pub fn eth_flow_calldata(order: &CowOrder) -> Result<Vec<u8>> {
    let quote_id = order.eth_flow_quote_id.context("ordre CoW sans EthFlow")?;
    let word_address = |address: &str| -> Result<[u8; 32]> {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&wallet_flow::parse_evm_address(address)?);
        Ok(word)
    };
    let word_uint = |value: u128| {
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&value.to_be_bytes());
        word
    };
    let mut quote_word = [if quote_id < 0 { 0xff } else { 0 }; 32];
    quote_word[24..].copy_from_slice(&quote_id.to_be_bytes());
    let mut data = evm_sign::keccak(b"createOrder((address,address,uint256,uint256,bytes32,uint256,uint32,bool,int64))")[..4].to_vec();
    for word in [
        word_address(&order.buy_token)?,
        word_address(&order.receiver)?,
        word_uint(order.sell_amount),
        word_uint(order.min_buy),
        order.app_data_hash,
        word_uint(0),
        word_uint(u128::from(order.valid_to)),
        word_uint(0),
        quote_word,
    ] {
        data.extend_from_slice(&word);
    }
    Ok(data)
}

/// Identifier of the order created by EthFlow: that of the GPv2 order owned by the
/// contract, with maximum validity (the real limit is enforced by the contract),
/// like the official SDK's `calculateUniqueOrderId`.
pub fn eth_flow_uid(order: &CowOrder, chain_id: u64) -> Result<String> {
    ensure!(order.eth_flow_quote_id.is_some(), "ordre CoW sans EthFlow");
    let contract_order = CowOrder { valid_to: u32::MAX, ..order.clone() };
    Ok(order_uid(&digest(&contract_order, chain_id)?, &wallet_flow::parse_evm_address(ETH_FLOW)?, u32::MAX))
}

/// Uploads the `appData` document to CoW: an EthFlow order only carries its hash,
/// and it is this document that declares the partner fee.
pub fn upload_app_data(order: &CowOrder) -> Result<()> {
    let api = api_network(order.network).ok_or_else(|| anyhow!("réseau non pris en charge par CoW"))?;
    let hash = format!("0x{}", hex::encode(order.app_data_hash));
    let response = shared_client()
        .put(format!("{API_BASE}/{api}/api/v1/app_data/{hash}"))
        .json(&json!({ "fullAppData": order.app_data }))
        .send()
        .context("dépôt de l'appData CoW impossible")?;
    let status = response.status();
    let body: Value = response.json().unwrap_or(Value::Null);
    ensure!(status.is_success() && body.as_str().is_some_and(|h| h.eq_ignore_ascii_case(&hash)), "dépôt de l'appData CoW refusé ({status})");
    Ok(())
}

/// EIP-712 typed data for the order (GPv2Settlement domain, the official contract's
/// `Order` type), `feeAmount` = 0.
pub fn typed_data(order: &CowOrder, chain_id: u64) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Order": [
                {"name": "sellToken", "type": "address"},
                {"name": "buyToken", "type": "address"},
                {"name": "receiver", "type": "address"},
                {"name": "sellAmount", "type": "uint256"},
                {"name": "buyAmount", "type": "uint256"},
                {"name": "validTo", "type": "uint32"},
                {"name": "appData", "type": "bytes32"},
                {"name": "feeAmount", "type": "uint256"},
                {"name": "kind", "type": "string"},
                {"name": "partiallyFillable", "type": "bool"},
                {"name": "sellTokenBalance", "type": "string"},
                {"name": "buyTokenBalance", "type": "string"}
            ]
        },
        "primaryType": "Order",
        "domain": {"name": "Gnosis Protocol", "version": "v2", "chainId": chain_id, "verifyingContract": SETTLEMENT},
        "message": {
            "sellToken": order.sell_token,
            "buyToken": order.buy_token,
            "receiver": order.receiver,
            "sellAmount": order.sell_amount.to_string(),
            "buyAmount": order.min_buy.to_string(),
            "validTo": order.valid_to,
            "appData": format!("0x{}", hex::encode(order.app_data_hash)),
            "feeAmount": "0",
            "kind": "sell",
            "partiallyFillable": false,
            "sellTokenBalance": "erc20",
            "buyTokenBalance": "erc20"
        }
    })
}

/// EIP-712 digest to sign.
pub fn digest(order: &CowOrder, chain_id: u64) -> Result<[u8; 32]> {
    evm_sign::parse_typed_data(&typed_data(order, chain_id))?.digest()
}

/// An order's identifier (GPv2 contract format): EIP-712 digest ‖ owner ‖ validity.
pub fn order_uid(digest: &[u8; 32], owner: &[u8; 20], valid_to: u32) -> String {
    format!("0x{}{}{}", hex::encode(digest), hex::encode(owner), hex::encode(valid_to.to_be_bytes()))
}

/// Sends the signed order to CoW's order book and returns its identifier; refused
/// if it does not match the order signed here (`digest`, `owner`).
pub fn submit(order: &CowOrder, digest: &[u8; 32], signature: &[u8; 65], owner: &str) -> Result<String> {
    let owner_bytes = wallet_flow::parse_evm_address(owner)?;
    let api = api_network(order.network).ok_or_else(|| anyhow!("réseau non pris en charge par CoW"))?;
    let body = json!({
        "sellToken": order.sell_token,
        "buyToken": order.buy_token,
        "receiver": order.receiver,
        "sellAmount": order.sell_amount.to_string(),
        "buyAmount": order.min_buy.to_string(),
        "validTo": order.valid_to,
        "appData": order.app_data,
        "appDataHash": format!("0x{}", hex::encode(order.app_data_hash)),
        "feeAmount": "0",
        "kind": "sell",
        "partiallyFillable": false,
        "sellTokenBalance": "erc20",
        "buyTokenBalance": "erc20",
        "signingScheme": "eip712",
        "signature": format!("0x{}", hex::encode(signature)),
        "from": owner,
    });
    let response: Value = shared_client()
        .post(format!("{API_BASE}/{api}/api/v1/orders"))
        .json(&body)
        .send()
        .context("envoi de l'ordre CoW impossible")?
        .json()
        .context("réponse de CoW illisible")?;
    if let Some(uid) = response.as_str() {
        let expected = order_uid(digest, &owner_bytes, order.valid_to);
        ensure!(uid.eq_ignore_ascii_case(&expected), "identifiant d'ordre CoW inattendu ({uid})");
        return Ok(expected);
    }
    let error = response.get("errorType").and_then(Value::as_str).unwrap_or("erreur inconnue");
    let detail = response.get("description").and_then(Value::as_str).unwrap_or("");
    bail!("ordre CoW refusé : {error} {detail}")
}

/// State of an order ("open", "fulfilled", "expired", "cancelled"…).
pub fn order_status(network: &str, uid: &str) -> Result<String> {
    let api = api_network(network).ok_or_else(|| anyhow!("réseau non pris en charge par CoW"))?;
    // Comes from the UI and goes into the URL: exact format required.
    ensure!(uid.len() == 2 + 112 && uid.starts_with("0x") && uid[2..].bytes().all(|b| b.is_ascii_hexdigit()), "identifiant d'ordre CoW invalide");
    let response: Value = shared_client()
        .get(format!("{API_BASE}/{api}/api/v1/orders/{uid}"))
        .send()
        .context("lecture de l'ordre CoW impossible")?
        .json()
        .context("réponse de CoW illisible")?;
    response.get("status").and_then(Value::as_str).map(str::to_string).ok_or_else(|| anyhow!("ordre CoW introuvable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_flow_order() -> CowOrder {
        let app_data = app_data("0x1111111111111111111111111111111111111111", PARTNER_FEE_BPS);
        CowOrder {
            network: "evm_mainnet",
            sell_token: wrapped_native("evm_mainnet").unwrap().into(),
            buy_token: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
            receiver: "0x2222222222222222222222222222222222222222".into(),
            sell_amount: 50_000_000_000_000_000,
            expected_buy: 131_000_000,
            min_buy: 130_000_000,
            network_fee_sell: 0,
            partner_fee_buy: 0,
            partner_fee_bps: PARTNER_FEE_BPS,
            valid_to: 1_790_000_000,
            app_data_hash: evm_sign::keccak(app_data.as_bytes()),
            app_data,
            eth_flow_quote_id: Some(123_456_789),
        }
    }

    /// EthFlow: `createOrder` calldata identical to ethers' encoding with the official
    /// ABI (@cowprotocol/sdk-common, EthFlowAbi), and an order identifier identical to
    /// `computeOrderUid` from @cowprotocol/contracts (owner = EthFlow contract, max
    /// validity).
    #[test]
    fn eth_flow_matches_the_official_libraries() {
        let order = eth_flow_order();
        assert_eq!(
            hex::encode(eth_flow_calldata(&order).unwrap()),
            "322bba21000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000b1a2bc2ec500000000000000000000000000000000000000000000000000000000000007bfa480e2f19f04f6fd06ccb99166260a45bca65d7fbeca47f18afb796f0237c383437e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006ab13b80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000075bcd15"
        );
        assert_eq!(
            eth_flow_uid(&order, 1).unwrap(),
            "0xa349f2f18202cf546cf5613991677bbb7cb3df7ca7938e284f9aa8fc61f015e0ba3cb449bd2b4adddbc894d8697f5170800eadecffffffff"
        );
        let regular = CowOrder { eth_flow_quote_id: None, ..order };
        assert!(eth_flow_calldata(&regular).is_err() && eth_flow_uid(&regular, 1).is_err());
    }

    /// EthFlow contract present on each of the app's CoW networks (live), with the
    /// right wrapped coin and the right settlement contract.
    #[test]
    #[ignore]
    fn real_eth_flow_contracts() {
        for network in ["evm_mainnet", "arbitrum_mainnet", "base_mainnet", "polygon_mainnet", "avax_mainnet", "bsc_mainnet"] {
            let net = wallet_flow::evm_network(network).unwrap();
            let rpc = crate::eth_rpc::EthRpc::new(net.rpc);
            assert!(!rpc.code(ETH_FLOW).unwrap().is_empty(), "{network} : pas de contrat EthFlow");
            let address_of = |selector: &[u8]| hex::encode(&rpc.call_contract(ETH_FLOW, ETH_FLOW, 0, selector).unwrap()[12..32]);
            let wrapped = address_of(&evm_sign::keccak(b"wrappedNativeToken()")[..4]);
            let settlement = address_of(&evm_sign::keccak(b"cowSwapSettlement()")[..4]);
            println!("{network} : {wrapped} {settlement}");
            assert_eq!(format!("0x{wrapped}"), wrapped_native(network).unwrap(), "{network}");
            assert_eq!(format!("0x{settlement}"), SETTLEMENT.to_ascii_lowercase(), "{network}");
        }
    }

    /// Real EthFlow quote, then `createOrder` SIMULATED (eth_call, nothing is sent)
    /// from a well-funded public address: the contract accepts the call and computes
    /// the order hash itself, identical to ours.
    #[test]
    #[ignore]
    fn real_eth_flow_order_simulated() {
        let owner = "0x28C6c06298d514Db089934071355E5743bf21d60";
        for (network, buy, amount) in [("evm_mainnet", "usdc", 50_000_000_000_000_000u128), ("bsc_mainnet", "aster", 100_000_000_000_000_000)] {
            let net = wallet_flow::evm_network(network).unwrap();
            let sell = token(native_coin(net), network).unwrap();
            let order = quote(network, &sell, &token(buy, network).unwrap(), amount, owner, "0x1111111111111111111111111111111111111111", PARTNER_FEE_BPS).unwrap();
            println!("{network} : vente {} minimum {} devis n°{:?}", order.sell_amount, order.min_buy, order.eth_flow_quote_id);
            assert_eq!(order.sell_token, wrapped_native(network).unwrap());
            let rpc = crate::eth_rpc::EthRpc::new(net.rpc);
            let returned = rpc.call_contract(owner, ETH_FLOW, order.sell_amount, &eth_flow_calldata(&order).unwrap()).unwrap();
            let uid = eth_flow_uid(&order, net.chain_id).unwrap();
            assert_eq!(format!("0x{}", hex::encode(&returned)), uid[..66], "{network}");
        }
    }

    /// Real upload of the test appData (dummy address): accepted, CoW returns its hash,
    /// and the document read back is identical.
    #[test]
    #[ignore]
    fn real_app_data_upload() {
        let order = eth_flow_order();
        upload_app_data(&order).unwrap();
        let hash = format!("0x{}", hex::encode(order.app_data_hash));
        let stored: Value = shared_client().get(format!("{API_BASE}/mainnet/api/v1/app_data/{hash}")).send().unwrap().json().unwrap();
        assert_eq!(stored["fullAppData"], order.app_data);
    }

    /// Reference values computed by the official SDK (`getQuoteAmountsAndCosts` from
    /// @cowprotocol/sdk-order-book 9.x, partner fee 100 bps, slippage 100 bps, protocol
    /// fee 2 bps) for a 10 LINK → USDC quote.
    #[test]
    fn order_amounts_match_the_official_sdk() {
        let (sell, expected, min, partner) = order_amounts(9_776_517_981_337_341_408, 140_645_630, 223_482_018_662_658_592, 2.0, PARTNER_FEE_BPS).unwrap();
        assert_eq!(sell, 10_000_000_000_000_000_000);
        assert_eq!(partner, 1_438_887);
        assert_eq!(expected, 139_206_743);
        assert_eq!(min, 137_814_676);
        assert!(order_amounts(0, 1, 0, 0.0, PARTNER_FEE_BPS).is_err());
        assert!(order_amounts(100, 50, 10, -1.0, PARTNER_FEE_BPS).is_err());
        assert!(order_amounts(100, 50, 10, f64::NAN, PARTNER_FEE_BPS).is_err());
        assert!(order_amounts(u128::MAX, u128::MAX, 1, 0.0, PARTNER_FEE_BPS).is_err());
        // Two 18-decimal tokens with a low price (orders of magnitude from a real FET →
        // ARB quote): the product buy × fee exceeds 2^128.
        let (sell, expected, _, partner) = order_amounts(100_000_000_000_000_000_000, 166_000_000_000_000_000_000, 10_000_000_000_000_000_000, 0.0, PARTNER_FEE_BPS).unwrap();
        assert_eq!(sell, 110_000_000_000_000_000_000);
        assert_eq!(partner, (166_000_000_000_000_000_000u128 + 16_600_000_000_000_000_000) / 100);
        assert_eq!(expected, 166_000_000_000_000_000_000 - partner);
        assert_eq!(mul_div(u128::MAX, 2, 4), Some(u128::MAX / 2));
        assert_eq!(mul_div(1, 1, 0), None);
    }

    /// EIP-712 digest identical to `hashOrder` from @cowprotocol/contracts
    /// (GPv2Settlement domain), on Ethereum and on Arbitrum.
    #[test]
    fn order_digest_matches_the_official_library() {
        let app_data = app_data("0x1111111111111111111111111111111111111111", PARTNER_FEE_BPS);
        let order = CowOrder {
            network: "evm_mainnet",
            sell_token: "0x514910771af9ca656af840dff83e8264ecf986ca".into(),
            buy_token: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
            receiver: "0x2222222222222222222222222222222222222222".into(),
            sell_amount: 10_000_000_000_000_000_000,
            expected_buy: 138_000_000,
            min_buy: 137_000_000,
            network_fee_sell: 0,
            partner_fee_buy: 0,
            partner_fee_bps: PARTNER_FEE_BPS,
            valid_to: 1_790_000_000,
            app_data_hash: evm_sign::keccak(app_data.as_bytes()),
            app_data,
            eth_flow_quote_id: None,
        };
        assert_eq!(hex::encode(digest(&order, 1).unwrap()), "c90555a84a12eff8be21d2fbc5ad7a7247a9294132198bdfa2bb309981d8e096");
        assert_eq!(hex::encode(digest(&order, 42161).unwrap()), "b47e9843046df348f0c34a59b9116f6dfc8143d228fd854f710f89e22d59afac");
    }

    /// Real quote (live): 10 LINK → USDC on Ethereum, 20 USDC → ETH on Arbitrum, 100
    /// ASTER → BNB on BNB Chain; the response is checked again and the order amounts
    /// are consistent.
    #[test]
    #[ignore]
    fn real_quotes() {
        let owner = "0x2222222222222222222222222222222222222222";
        let recipient = "0x1111111111111111111111111111111111111111";
        for (network, sell, buy, amount) in [
            ("evm_mainnet", "link", "usdc", 10_000_000_000_000_000_000u128),
            ("arbitrum_mainnet", "usdc", "evm", 20_000_000),
            ("bsc_mainnet", "aster", "bnb", 100_000_000_000_000_000_000),
        ] {
            let (s, b) = (token(sell, network).unwrap(), token(buy, network).unwrap());
            let order = quote(network, &s, &b, amount, owner, recipient, PARTNER_FEE_BPS).unwrap();
            println!("{network} {sell}→{buy} : vente {} attendu {} minimum {} frais réseau {} partenaire {}", order.sell_amount, order.expected_buy, order.min_buy, order.network_fee_sell, order.partner_fee_buy);
            assert_eq!(order.sell_amount, amount);
            assert!(order.min_buy > 0 && order.min_buy < order.expected_buy);
            assert!(order.partner_fee_buy > 0);
        }
    }

    /// Real submission of an order signed by a public test key, WITHOUT funds: CoW must
    /// refuse it for insufficient balance, which proves the format, the EIP-712
    /// signature and the `appData` passed its checks (they are verified before the
    /// balance). Nothing can be executed.
    #[test]
    #[ignore]
    fn real_submit_is_rejected_only_for_balance() {
        let key = k256::ecdsa::SigningKey::from_slice(&evm_sign::keccak(b"openpgp-wallet cow test key, no funds")).unwrap();
        let owner = format!("0x{}", hex::encode(crate::derivation::evm_address_from_key(&key)));
        let (link, usdc) = (token("link", "evm_mainnet").unwrap(), token("usdc", "evm_mainnet").unwrap());
        let order = quote("evm_mainnet", &link, &usdc, 10_000_000_000_000_000_000, &owner, "0x1111111111111111111111111111111111111111", PARTNER_FEE_BPS).unwrap();
        let hash = digest(&order, 1).unwrap();
        let signature = evm_sign::sign_digest(&key, &hash).unwrap();
        let error = submit(&order, &hash, &signature, &owner).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("InsufficientBalance") || error.contains("InsufficientAllowance"), "{error}");
        // Counter-check: the same signature for a different amount is refused BEFORE the
        // balance check (signer ≠ declared owner).
        let mut other = order.clone();
        other.min_buy -= 1;
        let error = submit(&other, &digest(&other, 1).unwrap(), &signature, &owner).unwrap_err().to_string();
        println!("{error}");
        assert!(!error.contains("InsufficientBalance"), "{error}");
    }

    /// Partner fee address, once set: a valid EVM address.
    #[test]
    fn partner_fee_recipient_is_a_valid_address() {
        if let Some(recipient) = PARTNER_FEE_RECIPIENT {
            assert!(wallet_flow::parse_evm_address(recipient).is_ok());
        }
    }

    #[test]
    fn tokens_come_from_the_registry_and_natives_use_the_cow_convention() {
        let link = token("link", "evm_mainnet").unwrap();
        assert_eq!((link.address.as_str(), link.decimals, link.native), ("0x514910771af9ca656af840dff83e8264ecf986ca", 18, false));
        let eth = token("evm", "arbitrum_mainnet").unwrap();
        assert!(wrapped_native("arbitrum_mainnet").is_some() && wrapped_native("hyperevm_mainnet").is_none());
        assert!(eth.native && eth.address == NATIVE_BUY_TOKEN && eth.symbol == "ETH");
        assert_eq!(token("bnb", "bsc_mainnet").unwrap().symbol, "BNB");
        assert!(token("usdc", "sol_mainnet").is_none());
        assert!(token("evm", "evm_sepolia").is_none());
        let all = tradable();
        assert!(all.contains(&("aster", "bsc_mainnet")) && all.contains(&("pol", "polygon_mainnet")) && all.contains(&("usdc", "arbitrum_mainnet")));
        assert!(all.iter().all(|(coin, network)| token(coin, network).is_some()));
        assert!(!all.iter().any(|(_, network)| *network == "sol_mainnet" || *network == "hyperevm_mainnet"));
    }

    /// Order identifier in GPv2 format (56 bytes) and explorer links.
    #[test]
    fn uid_and_explorer_links() {
        let uid = order_uid(&[0xab; 32], &[0x22; 20], 0x6ab0_0000);
        assert_eq!(uid.len(), 2 + 112);
        assert!(uid.ends_with(&format!("{}6ab00000", "22".repeat(20))));
        assert_eq!(explorer_order_url("evm_mainnet", "0x1").unwrap(), "https://explorer.cow.fi/orders/0x1");
        assert_eq!(explorer_order_url("arbitrum_mainnet", "0x1").unwrap(), "https://explorer.cow.fi/arb1/orders/0x1");
        assert!(explorer_order_url("hyperevm_mainnet", "0x1").is_none());
    }

    /// `appData`: a string IDENTICAL to the official SDK's (`generateAppDataDoc` +
    /// `stringifyDeterministic`, validated by its schema) and the same keccak256 hash.
    #[test]
    fn app_data_matches_the_official_sdk() {
        let doc = app_data("0x1111111111111111111111111111111111111111", PARTNER_FEE_BPS);
        assert_eq!(doc, r#"{"appCode":"OpenPGP Wallet","metadata":{"partnerFee":{"recipient":"0x1111111111111111111111111111111111111111","volumeBps":100}},"version":"1.15.0"}"#);
        assert_eq!(hex::encode(evm_sign::keccak(doc.as_bytes())), "e2f19f04f6fd06ccb99166260a45bca65d7fbeca47f18afb796f0237c383437e");
    }
}
