//! CoW Protocol : échange entre deux cryptos d'un MÊME réseau EVM par ordre
//! signé (EIP-712), exécuté ensuite par les « solveurs » du protocole.
//! Contrairement à une transaction construite par un tiers, l'ordre est un
//! message structuré construit ICI et entièrement lisible : jeton vendu et
//! quantité, jeton acheté et MINIMUM reçu, destinataire (l'utilisateur),
//! validité, frais partenaire (`appData`) — tous vérifiés avant signature.
//! Vendre un jeton demande une autorisation préalable au « VaultRelayer » de
//! CoW (au montant exact, voir `api::send_cow_swap`). Un ordre non exécuté
//! expire sans rien coûter.
//!
//! Vendre la monnaie d'un réseau (ETH, BNB…) passe par le contrat EthFlow de
//! CoW : une transaction `createOrder` (construite ici) lui confie le montant
//! et crée l'ordre à sa place ; non exécuté, l'ordre expire et CoW rembourse
//! (voir `api::send_cow_eth_flow`).
//!
//! Montants calculés exactement comme le SDK officiel (`@cowprotocol/cow-sdk`,
//! `getQuoteAmountsAndCosts`, relu dans son code) : le devis donne la vente
//! après frais réseau et la réception correspondante ; l'ordre signe la vente
//! TOTALE (frais réseau compris, `feeAmount` = 0) et une réception minimale =
//! réception du devis − frais partenaire − glissement.

use crate::{evm_sign, tokens, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::OnceLock;

const API_BASE: &str = "https://api.cow.fi";
/// Contrat de règlement GPv2, même adresse sur tous les réseaux de CoW
/// (domaine EIP-712 de l'ordre).
pub const SETTLEMENT: &str = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41";
/// Contrat qui prélève le jeton vendu au moment du règlement : c'est lui qui
/// reçoit l'autorisation (`approve`).
pub const VAULT_RELAYER: &str = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110";
/// Convention CoW pour la monnaie native ACHETÉE (ETH, BNB…).
pub const NATIVE_BUY_TOKEN: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
/// Contrat EthFlow de CoW (vente de la monnaie d'un réseau), même adresse sur
/// tous ses réseaux (@cowprotocol/sdk-config, ETH_FLOW_ADDRESSES) ; présence,
/// monnaie enveloppée et contrat de règlement revérifiés sur chaque réseau
/// (test `real_eth_flow_contracts`).
pub const ETH_FLOW: &str = "0xba3cb449bd2b4adddbc894d8697f5170800eadec";
/// Frais partenaire : 100 bps = 1 % (plafond du protocole), versés chaque
/// semaine en WETH sur Ethereum à `PARTNER_FEE_RECIPIENT` (CoW en garde une
/// part, voir docs.cow.fi/governance/fees/partner-fee).
pub const PARTNER_FEE_BPS: u32 = 100;
/// Adresse Ethereum du développeur qui reçoit les frais partenaire (donnée par
/// l'utilisateur le 02/10/2026 ; checksum EIP-55 valide, compte ordinaire sur
/// Ethereum, sans code de contrat). Sans elle (`None`), aucune route CoW.
pub const PARTNER_FEE_RECIPIENT: Option<&str> = Some("0xae702daEd4723ac516492Bb1084F50e07e75573C");
/// Glissement toléré sous la réception attendue (1 %).
pub const SLIPPAGE_BPS: u32 = 100;
/// Validité demandée pour un ordre, et maximum accepté d'un devis.
const VALID_FOR_SECS: u64 = 1800;
const MAX_VALIDITY_SECS: u64 = 3600;
const APP_CODE: &str = "OpenPGP Wallet";
/// Version du schéma `appData` (`partnerFee` = { volumeBps, recipient }, schéma
/// v1.15.0, la dernière du SDK officiel @cowprotocol/sdk-app-data).
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

/// Segment d'URL de l'API CoW pour un réseau de l'app (`None` : pas sur CoW).
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

/// Version « jeton ERC-20 » de la monnaie d'un réseau (WETH, WBNB…), celle que
/// vend un ordre EthFlow (@cowprotocol/sdk-config, WRAPPED_NATIVE_CURRENCIES).
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

/// Identifiant de carte de la monnaie native d'un réseau (ETH = « evm »).
fn native_coin(network: &wallet_flow::EvmNetwork) -> &'static str {
    match network.native_symbol {
        "ETH" => "evm",
        "BNB" => "bnb",
        "AVAX" => "avax",
        "POL" => "pol",
        _ => "",
    }
}

/// Crypto échangeable sur CoW : jeton ERC-20 du registre, ou monnaie native du
/// réseau (achetée directement, vendue via le contrat EthFlow).
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
            tokens::TokenKind::Spl { .. } => None,
        };
    }
    let net = wallet_flow::evm_network(network)?;
    (native_coin(net) == coin).then(|| CowToken { address: NATIVE_BUY_TOKEN.to_string(), decimals: 18, symbol: net.native_symbol, native: true })
}

/// Toutes les cryptos de l'app que CoW sait échanger (identifiant, réseau) :
/// monnaies natives et jetons ERC-20 du registre.
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

/// Page d'un ordre sur l'explorateur officiel de CoW (préfixes de réseau
/// relevés dans le code de CoW Swap, libs/common-utils/src/explorer.ts).
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

/// Document `appData` de l'ordre (clés triées, compact, comme le SDK) : code
/// de l'app et frais partenaire.
pub fn app_data(recipient: &str) -> String {
    format!(r#"{{"appCode":"{APP_CODE}","metadata":{{"partnerFee":{{"recipient":"{recipient}","volumeBps":{PARTNER_FEE_BPS}}}}},"version":"{APP_DATA_VERSION}"}}"#)
}

/// Ordre prêt à signer, tel qu'il sera AFFICHÉ puis signé.
#[derive(Clone, Debug)]
pub struct CowOrder {
    pub network: &'static str,
    pub sell_token: String,
    pub buy_token: String,
    pub receiver: String,
    /// Vente totale signée (frais réseau compris), unités du jeton vendu.
    pub sell_amount: u128,
    /// Réception attendue après tous les frais, avant glissement.
    pub expected_buy: u128,
    /// Réception minimale signée (attendue − glissement).
    pub min_buy: u128,
    /// Frais réseau estimés par CoW, en jeton vendu (déjà dans `sell_amount`).
    pub network_fee_sell: u128,
    /// Frais partenaire, en jeton acheté.
    pub partner_fee_buy: u128,
    pub valid_to: u32,
    pub app_data: String,
    pub app_data_hash: [u8; 32],
    /// Vente de la monnaie du réseau via EthFlow (`sell_token` = sa version
    /// enveloppée) : identifiant du devis, exigé par le contrat.
    pub eth_flow_quote_id: Option<i64>,
}

fn u128_field(value: &Value, field: &str) -> Result<u128> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("devis CoW sans « {field} » exploitable"))
}

/// Montants de l'ordre à partir du devis (vente après frais réseau, réception
/// correspondante, frais réseau en jeton vendu, frais du protocole en bps),
/// formule du SDK officiel : (vente totale, réception attendue, minimum,
/// frais partenaire).
pub fn order_amounts(sell: u128, buy: u128, fee: u128, protocol_fee_bps: f64) -> Result<(u128, u128, u128, u128)> {
    ensure!(sell > 0 && buy > 0, "devis CoW vide");
    let cost_in_buy = buy.checked_mul(fee).context("montant hors limites")? / sell;
    let scaled = (protocol_fee_bps * 100_000.0).round();
    ensure!((0.0..1e9).contains(&scaled), "frais du protocole CoW inattendus");
    let scaled = scaled as u128;
    let protocol_fee = if scaled > 0 { buy.checked_mul(scaled).context("montant hors limites")? / (10_000 * 100_000 - scaled) } else { 0 };
    let before_all = buy.checked_add(cost_in_buy).and_then(|b| b.checked_add(protocol_fee)).context("montant hors limites")?;
    let partner_fee = before_all.checked_mul(u128::from(PARTNER_FEE_BPS)).context("montant hors limites")? / 10_000;
    let expected = buy.checked_sub(partner_fee).context("frais supérieurs à la réception")?;
    let min = expected - expected * u128::from(SLIPPAGE_BPS) / 10_000;
    Ok((sell.checked_add(fee).context("montant hors limites")?, expected, min, partner_fee))
}

/// Devis CoW pour vendre `amount` (unités) de `sell` contre `buy` sur
/// `network`, au profit de `owner` (vendeur ET destinataire). La réponse est
/// revérifiée (jetons, destinataire, sens, montants) avant d'en tirer l'ordre.
pub fn quote(network: &'static str, sell: &CowToken, buy: &CowToken, amount: u128, owner: &str, recipient: &str) -> Result<CowOrder> {
    ensure!(sell.address != buy.address, "échange d'une crypto vers elle-même");
    let api = api_network(network).ok_or_else(|| anyhow!("réseau non pris en charge par CoW"))?;
    // EthFlow : devis sur la version enveloppée, ordre créé on-chain par le
    // contrat (paramètres du SDK officiel, ETH_FLOW_AUX_QUOTE_PARAMS).
    let sell_token = if sell.native { wrapped_native(network).context("réseau sans EthFlow")?.to_string() } else { sell.address.clone() };
    ensure!(!(sell.native && buy.native), "échange d'une crypto vers elle-même");
    let app_data = app_data(recipient);
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
    let (sell_amount, expected_buy, min_buy, partner_fee_buy) = order_amounts(sell_after, buy_quoted, fee, protocol_fee_bps)?;
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
        valid_to: valid_to as u32,
        app_data,
        app_data_hash,
        eth_flow_quote_id,
    })
}

/// Données de l'appel `createOrder(EthFlowOrder.Data)` du contrat EthFlow
/// (structure du contrat officiel : buyToken, receiver, sellAmount, buyAmount,
/// appData, feeAmount, validTo, partiallyFillable, quoteId — que des types
/// fixes, encodés à la suite). La valeur envoyée doit être `sell_amount`.
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

/// Identifiant de l'ordre créé par EthFlow : celui de l'ordre GPv2 dont le
/// contrat est propriétaire, validité au maximum (la vraie limite est gardée
/// par le contrat) — comme `calculateUniqueOrderId` du SDK officiel.
pub fn eth_flow_uid(order: &CowOrder, chain_id: u64) -> Result<String> {
    ensure!(order.eth_flow_quote_id.is_some(), "ordre CoW sans EthFlow");
    let contract_order = CowOrder { valid_to: u32::MAX, ..order.clone() };
    Ok(order_uid(&digest(&contract_order, chain_id)?, &wallet_flow::parse_evm_address(ETH_FLOW)?, u32::MAX))
}

/// Dépose le document `appData` auprès de CoW : un ordre EthFlow n'en porte
/// que l'empreinte, et c'est ce document qui déclare les frais partenaire.
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

/// Données structurées EIP-712 de l'ordre (domaine GPv2Settlement, type
/// `Order` du contrat officiel), `feeAmount` = 0.
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

/// Empreinte EIP-712 à signer.
pub fn digest(order: &CowOrder, chain_id: u64) -> Result<[u8; 32]> {
    evm_sign::parse_typed_data(&typed_data(order, chain_id))?.digest()
}

/// Identifiant d'un ordre (format du contrat GPv2) : empreinte EIP-712 ‖
/// propriétaire ‖ validité.
pub fn order_uid(digest: &[u8; 32], owner: &[u8; 20], valid_to: u32) -> String {
    format!("0x{}{}{}", hex::encode(digest), hex::encode(owner), hex::encode(valid_to.to_be_bytes()))
}

/// Envoie l'ordre signé au carnet d'ordres de CoW ; renvoie son identifiant,
/// refusé s'il ne correspond pas à l'ordre signé ici (`digest`, `owner`).
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

/// État d'un ordre (« open », « fulfilled », « expired », « cancelled »…).
pub fn order_status(network: &str, uid: &str) -> Result<String> {
    let api = api_network(network).ok_or_else(|| anyhow!("réseau non pris en charge par CoW"))?;
    // Venu de l'interface et placé dans l'URL : format exact exigé.
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
        let app_data = app_data("0x1111111111111111111111111111111111111111");
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
            valid_to: 1_790_000_000,
            app_data_hash: evm_sign::keccak(app_data.as_bytes()),
            app_data,
            eth_flow_quote_id: Some(123_456_789),
        }
    }

    /// EthFlow : données de `createOrder` identiques à l'encodage d'ethers
    /// avec l'ABI officielle (@cowprotocol/sdk-common, EthFlowAbi), et
    /// identifiant d'ordre identique à `computeOrderUid` de
    /// @cowprotocol/contracts (propriétaire = contrat EthFlow, validité max).
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

    /// Contrat EthFlow présent sur chaque réseau CoW de l'app (réseau), avec la
    /// bonne monnaie enveloppée et le bon contrat de règlement.
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

    /// Devis EthFlow réel puis \`createOrder\` SIMULÉ (eth_call, rien n'est
    /// envoyé) depuis une adresse publique bien pourvue : le contrat accepte
    /// l'appel et calcule lui-même l'empreinte de l'ordre, identique à la nôtre.
    #[test]
    #[ignore]
    fn real_eth_flow_order_simulated() {
        let owner = "0x28C6c06298d514Db089934071355E5743bf21d60";
        for (network, buy, amount) in [("evm_mainnet", "usdc", 50_000_000_000_000_000u128), ("bsc_mainnet", "aster", 100_000_000_000_000_000)] {
            let net = wallet_flow::evm_network(network).unwrap();
            let sell = token(native_coin(net), network).unwrap();
            let order = quote(network, &sell, &token(buy, network).unwrap(), amount, owner, "0x1111111111111111111111111111111111111111").unwrap();
            println!("{network} : vente {} minimum {} devis n°{:?}", order.sell_amount, order.min_buy, order.eth_flow_quote_id);
            assert_eq!(order.sell_token, wrapped_native(network).unwrap());
            let rpc = crate::eth_rpc::EthRpc::new(net.rpc);
            let returned = rpc.call_contract(owner, ETH_FLOW, order.sell_amount, &eth_flow_calldata(&order).unwrap()).unwrap();
            let uid = eth_flow_uid(&order, net.chain_id).unwrap();
            assert_eq!(format!("0x{}", hex::encode(&returned)), uid[..66], "{network}");
        }
    }

    /// Dépôt réel de l'appData de test (adresse fictive) : accepté, CoW
    /// renvoie son empreinte, et le document relu est identique.
    #[test]
    #[ignore]
    fn real_app_data_upload() {
        let order = eth_flow_order();
        upload_app_data(&order).unwrap();
        let hash = format!("0x{}", hex::encode(order.app_data_hash));
        let stored: Value = shared_client().get(format!("{API_BASE}/mainnet/api/v1/app_data/{hash}")).send().unwrap().json().unwrap();
        assert_eq!(stored["fullAppData"], order.app_data);
    }

    /// Valeurs de référence calculées par le SDK officiel
    /// (`getQuoteAmountsAndCosts` de @cowprotocol/sdk-order-book 9.x, frais
    /// partenaire 100 bps, glissement 100 bps, frais du protocole 2 bps) pour
    /// un devis de 10 LINK → USDC.
    #[test]
    fn order_amounts_match_the_official_sdk() {
        let (sell, expected, min, partner) = order_amounts(9_776_517_981_337_341_408, 140_645_630, 223_482_018_662_658_592, 2.0).unwrap();
        assert_eq!(sell, 10_000_000_000_000_000_000);
        assert_eq!(partner, 1_438_887);
        assert_eq!(expected, 139_206_743);
        assert_eq!(min, 137_814_676);
        assert!(order_amounts(0, 1, 0, 0.0).is_err());
        assert!(order_amounts(100, 50, 10, -1.0).is_err());
        assert!(order_amounts(100, 50, 10, f64::NAN).is_err());
        assert!(order_amounts(u128::MAX, u128::MAX, 1, 0.0).is_err());
    }

    /// Empreinte EIP-712 identique à `hashOrder` de @cowprotocol/contracts
    /// (domaine GPv2Settlement), sur Ethereum et sur Arbitrum.
    #[test]
    fn order_digest_matches_the_official_library() {
        let app_data = app_data("0x1111111111111111111111111111111111111111");
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
            valid_to: 1_790_000_000,
            app_data_hash: evm_sign::keccak(app_data.as_bytes()),
            app_data,
            eth_flow_quote_id: None,
        };
        assert_eq!(hex::encode(digest(&order, 1).unwrap()), "c90555a84a12eff8be21d2fbc5ad7a7247a9294132198bdfa2bb309981d8e096");
        assert_eq!(hex::encode(digest(&order, 42161).unwrap()), "b47e9843046df348f0c34a59b9116f6dfc8143d228fd854f710f89e22d59afac");
    }

    /// Devis réel (réseau) : 10 LINK → USDC sur Ethereum, 20 USDC → ETH sur
    /// Arbitrum, 100 ASTER → BNB sur BNB Chain — réponse revérifiée et montants
    /// de l'ordre cohérents.
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
            let order = quote(network, &s, &b, amount, owner, recipient).unwrap();
            println!("{network} {sell}→{buy} : vente {} attendu {} minimum {} frais réseau {} partenaire {}", order.sell_amount, order.expected_buy, order.min_buy, order.network_fee_sell, order.partner_fee_buy);
            assert_eq!(order.sell_amount, amount);
            assert!(order.min_buy > 0 && order.min_buy < order.expected_buy);
            assert!(order.partner_fee_buy > 0);
        }
    }

    /// Envoi réel d'un ordre signé par une clé de test publique, SANS fonds :
    /// CoW doit le refuser pour solde insuffisant — preuve que le format, la
    /// signature EIP-712 et l'`appData` ont passé ses contrôles (ils sont
    /// vérifiés avant le solde). Rien ne peut être exécuté.
    #[test]
    #[ignore]
    fn real_submit_is_rejected_only_for_balance() {
        let key = k256::ecdsa::SigningKey::from_slice(&evm_sign::keccak(b"openpgp-wallet cow test key, no funds")).unwrap();
        let owner = format!("0x{}", hex::encode(crate::derivation::evm_address_from_key(&key)));
        let (link, usdc) = (token("link", "evm_mainnet").unwrap(), token("usdc", "evm_mainnet").unwrap());
        let order = quote("evm_mainnet", &link, &usdc, 10_000_000_000_000_000_000, &owner, "0x1111111111111111111111111111111111111111").unwrap();
        let hash = digest(&order, 1).unwrap();
        let signature = evm_sign::sign_digest(&key, &hash).unwrap();
        let error = submit(&order, &hash, &signature, &owner).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("InsufficientBalance") || error.contains("InsufficientAllowance"), "{error}");
        // Contre-épreuve : la même signature pour un autre montant est refusée
        // AVANT le solde (signataire ≠ propriétaire déclaré).
        let mut other = order.clone();
        other.min_buy -= 1;
        let error = submit(&other, &digest(&other, 1).unwrap(), &signature, &owner).unwrap_err().to_string();
        println!("{error}");
        assert!(!error.contains("InsufficientBalance"), "{error}");
    }

    /// Adresse des frais partenaire, une fois renseignée : adresse EVM valide.
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
        assert!(token("hype", "hyperevm_mainnet").is_none(), "HyperEVM : pas sur CoW");
        assert!(token("usdc", "sol_mainnet").is_none());
        assert!(token("evm", "evm_sepolia").is_none());
        let all = tradable();
        assert!(all.contains(&("aster", "bsc_mainnet")) && all.contains(&("pol", "polygon_mainnet")) && all.contains(&("usdc", "arbitrum_mainnet")));
        assert!(all.iter().all(|(coin, network)| token(coin, network).is_some()));
        assert!(!all.iter().any(|(_, network)| *network == "sol_mainnet" || *network == "hyperevm_mainnet"));
    }

    /// Identifiant d'ordre au format GPv2 (56 octets) et liens d'explorateur.
    #[test]
    fn uid_and_explorer_links() {
        let uid = order_uid(&[0xab; 32], &[0x22; 20], 0x6ab0_0000);
        assert_eq!(uid.len(), 2 + 112);
        assert!(uid.ends_with(&format!("{}6ab00000", "22".repeat(20))));
        assert_eq!(explorer_order_url("evm_mainnet", "0x1").unwrap(), "https://explorer.cow.fi/orders/0x1");
        assert_eq!(explorer_order_url("arbitrum_mainnet", "0x1").unwrap(), "https://explorer.cow.fi/arb1/orders/0x1");
        assert!(explorer_order_url("hyperevm_mainnet", "0x1").is_none());
    }

    /// `appData` : chaîne IDENTIQUE à celle du SDK officiel
    /// (`generateAppDataDoc` + `stringifyDeterministic`, validée par son
    /// schéma) et même empreinte keccak256.
    #[test]
    fn app_data_matches_the_official_sdk() {
        let doc = app_data("0x1111111111111111111111111111111111111111");
        assert_eq!(doc, r#"{"appCode":"OpenPGP Wallet","metadata":{"partnerFee":{"recipient":"0x1111111111111111111111111111111111111111","volumeBps":100}},"version":"1.15.0"}"#);
        assert_eq!(hex::encode(evm_sign::keccak(doc.as_bytes())), "e2f19f04f6fd06ccb99166260a45bca65d7fbeca47f18afb796f0237c383437e");
    }
}
