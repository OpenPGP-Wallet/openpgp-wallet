//! MoonPay Trade (API swaps.xyz, issue de Decent.xyz rachetée par MoonPay) :
//! un fournisseur d'échanges de plus dans « Convertir », non-custodial (la
//! transaction est signée par l'app, MoonPay ne détient jamais les fonds).
//!
//! Deux sortes de routes (choix de l'utilisateur du 07/10/2026) :
//! - **même réseau EVM** : appel du routeur « UTB » (même contrat sur chaque
//!   réseau : code identique, source vérifiée, non modifiable — relevé le
//!   07/10/2026), SIMULÉ avant signature : seul le jeton vendu quitte
//!   l'utilisateur, au montant exact ; le jeton acheté arrive sur SON adresse,
//!   au moins le minimum garanti. Proposé comme une option de plus ;
//! - **dépôt** (vers un autre réseau) : virement ordinaire, construit et signé
//!   par l'app, vers une adresse de dépôt fournie par MoonPay Trade. La suite
//!   (livraison sur l'autre réseau) est gérée par le fournisseur : le
//!   destinataire final n'est PAS vérifiable par l'app. Proposé seulement si
//!   aucun autre fournisseur ne relie la paire, et dit dans la boîte de
//!   confirmation.
//!
//! Commission de l'app : 0,80 % (comme LI.FI), demandée dans chaque devis
//! depuis un réseau EVM ; un devis qui en annonce davantage est refusé.
//!
//! Clé d'API (console.swaps.xyz) lue à la compilation (`partner-keys.env`,
//! voir build.rs). Une clé du widget MoonPay (`pk_…`, `sk_…`) n'est pas une
//! clé Trade : ignorée, MoonPay Trade n'est alors pas proposé.

use crate::{evm_sign, external_wallets, tokens, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::Value;
use std::sync::OnceLock;

const API_BASE: &str = "https://api-v2.swaps.xyz/api";
/// Clé lue à la compilation ; ne sert que si `enabled()` (clé Trade).
pub const API_KEY: Option<&str> = option_env!("MOONPAY_TRADE_API_KEY");
/// Commission de l'app (points de base), versée à l'adresse des frais
/// partenaire de CoW (adresse du développeur, voir `cow`).
pub const FEE_BPS: u32 = 80;
const FEE_RECEIVER: &str = "0xae702daEd4723ac516492Bb1084F50e07e75573C";
/// Frais propres à MoonPay sur la clé de l'app (relevés le 07/10/2026 :
/// 0,30 %), en plus de la commission ; affichés dans la liste des
/// fournisseurs. Le montant exact de chaque devis est lu dans le devis.
pub const PROTOCOL_FEE_BPS: u32 = 30;
/// Au-delà, le devis est refusé (frais MoonPay anormaux).
const MAX_PROTOCOL_FEE_BPS: u32 = 100;
/// Glissement toléré (points de base), garanti par le minimum de réception.
const SLIPPAGE_BPS: u32 = 100;
/// Identifiant des monnaies natives chez MoonPay Trade (tous réseaux).
const NATIVE: &str = "0x0000000000000000000000000000000000000000";
const SOLANA_CHAIN: u64 = 1_399_811_149;

pub fn enabled() -> bool {
    key().is_some()
}

fn key() -> Option<&'static str> {
    API_KEY.filter(|k| !k.starts_with("pk_") && !k.starts_with("sk_"))
}

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

// --- Cryptos ------------------------------------------------------------------------------

/// Monnaies natives : (carte, réseau, identifiant de chaîne MoonPay Trade,
/// décimales, symbole). Identifiants et décimales relevés sur
/// `getChainList` / `getTokenList` le 07/10/2026.
const NATIVES: [(&str, &str, u64, u8, &str); 17] = [
    ("evm", "evm_mainnet", 1, 18, "ETH"),
    ("evm", "arbitrum_mainnet", 42161, 18, "ETH"),
    ("evm", "base_mainnet", 8453, 18, "ETH"),
    ("bnb", "bsc_mainnet", 56, 18, "BNB"),
    ("avax", "avax_mainnet", 43114, 18, "AVAX"),
    ("pol", "polygon_mainnet", 137, 18, "POL"),
    ("sol", "sol_mainnet", SOLANA_CHAIN, 9, "SOL"),
    ("btc", "btc_mainnet", 999_000_313, 8, "BTC"),
    ("doge", "doge_mainnet", 2000, 8, "DOGE"),
    ("zec", "zec_mainnet", 999_000_322, 8, "ZEC"),
    ("trx", "tron_mainnet", 728_126_428, 6, "TRX"),
    ("xrp", "xrp_mainnet", 999_000_346, 6, "XRP"),
    ("xlm", "xlm_mainnet", 999_000_338, 7, "XLM"),
    ("near", "near_mainnet", 397, 24, "NEAR"),
    ("ada", "ada_mainnet", 1816, 6, "ADA"),
    ("stx", "stx_mainnet", 999_000_351, 6, "STX"),
    ("xmr", "xmr_mainnet", 999_000_343, 12, "XMR"),
];

/// Réseaux d'où l'app sait faire un dépôt MoonPay Trade (virement ordinaire,
/// mémo compris pour XRP) ; les autres sont reçus seulement.
const DEPOSIT_SOURCES: [&str; 12] = [
    "evm_mainnet",
    "arbitrum_mainnet",
    "base_mainnet",
    "bsc_mainnet",
    "avax_mainnet",
    "polygon_mainnet",
    "btc_mainnet",
    "doge_mainnet",
    "zec_mainnet",
    "xrp_mainnet",
    "ada_mainnet",
    "near_mainnet",
];

/// Routeur UTB de MoonPay Trade sur chaque réseau EVM de l'app : relevé dans
/// de vrais devis le 07/10/2026, même code déployé partout (empreinte du code
/// identique), source vérifiée « UTB » (Blockscout, Routescan), sans proxy.
pub fn router(network: &str) -> Option<&'static str> {
    Some(match network {
        "evm_mainnet" => "0x1b6257CAE4192e62B629eFCa21771be3D759183D",
        "arbitrum_mainnet" => "0x5813877Cdda5F0f56EeaB9326A42804A09e2CD8c",
        "base_mainnet" => "0x0929222bC7Cc533aecC1ccFe9d9Bd6ecbB0CBF43",
        "bsc_mainnet" => "0x39B1F7c5b1ae6a3Cb9bbbd616B44ceD9F53882E0",
        "polygon_mainnet" => "0x38630c8ec92494CF96ded12060d8136B75e7a8b5",
        "avax_mainnet" => "0x0eb3c930944951876E2E7Be8B8fE4759FFd6fb44",
        _ => return None,
    })
}

fn is_evm(network: &str) -> bool {
    router(network).is_some()
}

/// Crypto de l'app telle que MoonPay Trade la désigne.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub coin: &'static str,
    pub network: &'static str,
    pub chain: u64,
    /// Contrat (EVM, minuscules), mint (Solana) ou `NATIVE`.
    pub token: &'static str,
    pub decimals: u8,
    pub symbol: &'static str,
    pub native: bool,
}

pub fn asset(coin: &str, network: &str) -> Option<Asset> {
    if let Some(&(coin, network, chain, decimals, symbol)) = NATIVES.iter().find(|n| n.0 == coin && n.1 == network) {
        return Some(Asset { coin, network, chain, token: NATIVE, decimals, symbol, native: true });
    }
    let (token, deployment) = tokens::find(coin, network)?;
    let address = match deployment.kind {
        tokens::TokenKind::Erc20 { contract } if is_evm(network) => contract,
        tokens::TokenKind::Spl { mint } if network == "sol_mainnet" => mint,
        _ => return None,
    };
    let chain = NATIVES.iter().find(|n| n.1 == network)?.2;
    Some(Asset { coin: token.id, network: deployment.network, chain, token: address, decimals: deployment.decimals, symbol: token.symbol, native: false })
}

pub fn tradable() -> Vec<(&'static str, &'static str)> {
    let natives = NATIVES.iter().map(|n| (n.0, n.1));
    let registry = tokens::TOKENS.iter().flat_map(|t| t.deployments.iter().filter(|d| asset(t.id, d.network).is_some()).map(move |d| (t.id, d.network)));
    natives.chain(registry).collect()
}

/// Route au destinataire vérifiable : même réseau EVM (routeur simulé),
/// sur un réseau dont le nœud sait simuler (pas Avalanche : `eth_simulateV1`
/// absent, relevé le 08/10/2026 — 32ᵉ passage).
pub fn verifiable(from: (&str, &str), to: (&str, &str)) -> bool {
    from.1 == to.1 && is_evm(from.1) && crate::lifi::simulates(from.1)
}

/// MoonPay Trade relie-t-il ces deux cryptos (hors activation et hors règle
/// du dernier recours, appliquée par `swap_routes`) ?
pub fn links(from: (&str, &str), to: (&str, &str)) -> bool {
    from != to
        && asset(from.0, from.1).is_some()
        && asset(to.0, to.1).is_some()
        && (verifiable(from, to) || (from.1 != to.1 && DEPOSIT_SOURCES.contains(&from.1)))
}

// --- Devis --------------------------------------------------------------------------------

/// Transaction d'un devis vérifié.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TradeTx {
    /// Appel du routeur UTB (même réseau EVM), simulé avant signature
    /// (`verify_router`). `value` : montant vendu si c'est la monnaie du
    /// réseau, 0 sinon (le jeton vendu est autorisé au routeur, au montant
    /// exact).
    Router { router: [u8; 20], data: Vec<u8>, value: u128 },
    /// Dépôt : virement ordinaire du montant exact vers `address` (mémo :
    /// tag de destination XRP), construit et signé par l'app.
    Deposit { address: String, memo: Option<String> },
}

#[derive(Clone, Debug)]
pub struct Quote {
    /// Identifiant MoonPay Trade (enregistrement du dépôt, suivi).
    pub tx_id: String,
    pub amount: u128,
    pub expected_out: u128,
    pub min_out: u128,
    pub duration_secs: u64,
    /// Frais propres à MoonPay annoncés par le devis (points de base du
    /// montant vendu, arrondis), en plus de la commission de l'app.
    pub protocol_fee_bps: u32,
    /// Dépôt à déclarer après diffusion (`register`).
    pub register: bool,
    pub tx: TradeTx,
}

/// Erreur de devis renvoyée par MoonPay Trade, en clair.
fn api_error(body: &Value, status: u16) -> anyhow::Error {
    let error = &body["error"];
    let details = &error["details"];
    match error["code"].as_str() {
        Some("NO_AVAILABLE_ROUTE" | "UNSUPPORTED_NETWORK" | "UNSUPPORTED_NETWORK_PAIR" | "UNSUPPORTED_NETWORK_TOKEN_PAIR" | "INSUFFICIENT_LIQUIDITY") => {
            anyhow!("MoonPay Trade ne propose pas d'échange pour cette paire en ce moment")
        }
        Some("AMOUNT_TOO_LOW") => match details["minAmount"].as_str() {
            Some(min) if min.len() <= 40 && min.bytes().all(|b| b.is_ascii_digit() || b == b'.') => anyhow!("montant trop faible pour MoonPay Trade (minimum {min})"),
            _ => anyhow!("montant trop faible pour MoonPay Trade"),
        },
        Some("AMOUNT_TOO_HIGH") => anyhow!("montant trop élevé pour MoonPay Trade"),
        Some("GEO_BLOCKED") => anyhow!("MoonPay Trade n'est pas disponible dans votre pays"),
        Some("WALLET_SCREENED") => anyhow!("adresse refusée par le contrôle de conformité de MoonPay Trade"),
        Some("INVALID_ADDRESS_FORMAT") => anyhow!("adresse refusée par MoonPay Trade (format)"),
        Some("INVALID_API_KEY" | "MISSING_API_KEY" | "FORBIDDEN_API_KEY") => anyhow!("clé MoonPay Trade refusée"),
        _ => anyhow!("MoonPay Trade : réponse {status}"),
    }
}

/// Paiement (`amountIn`, `amountOut`…) : (chaîne, jeton, montant).
fn payment(value: &Value, what: &str) -> Result<(u64, String, u128)> {
    let chain = value["chainId"].as_u64().with_context(|| format!("devis MoonPay Trade illisible ({what})"))?;
    let token = value["address"].as_str().with_context(|| format!("devis MoonPay Trade illisible ({what})"))?.to_string();
    let amount = match &value["amount"] {
        Value::String(text) => text.parse::<u128>().ok(),
        other => other.as_u64().map(u128::from),
    }
    .with_context(|| format!("devis MoonPay Trade illisible ({what})"))?;
    Ok((chain, token, amount))
}

fn same_token(asset: &Asset, token: &str) -> bool {
    if is_evm(asset.network) || asset.native {
        asset.token.eq_ignore_ascii_case(token)
    } else {
        asset.token == token
    }
}

fn hex_data(text: &str) -> Result<Vec<u8>> {
    hex::decode(text.trim_start_matches("0x")).context("devis MoonPay Trade illisible (données)")
}

fn amount_value(value: &Value) -> Option<u128> {
    match value {
        Value::String(text) => text.parse().ok(),
        Value::Null => Some(0),
        other => other.as_u64().map(u128::from),
    }
}

/// `value` est-il l'un des mots de 32 octets des arguments d'un appel ?
fn contains_word(args: &[u8], value: u128) -> bool {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    args.as_chunks::<32>().0.contains(&word)
}

/// Appel ERC-20 `transfer(to, amount)`.
pub fn erc20_transfer_data(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

/// Frais `field` (`applicationFee`, `protocolFee`) en points de base du
/// montant vendu : exacts s'ils sont comptés dans la crypto vendue, sinon
/// d'après les montants en dollars du devis. `None` : frais absents.
fn fee_bps(body: &Value, field: &str, from: &Asset, amount: u128) -> Result<Option<f64>> {
    if !body[field].is_object() {
        return Ok(None);
    }
    let (chain, token, fee) = payment(&body[field], "commission")?;
    if chain == from.chain && same_token(from, &token) {
        ensure!(amount > 0, "montant nul");
        return Ok(Some(fee as f64 * 10_000.0 / amount as f64));
    }
    if fee == 0 {
        return Ok(Some(0.0));
    }
    match (body[field]["usdAmount"].as_f64(), body["amountIn"]["usdAmount"].as_f64()) {
        (Some(fee_usd), Some(sold_usd)) if sold_usd > 0.0 && fee_usd >= 0.0 => Ok(Some(fee_usd * 10_000.0 / sold_usd)),
        _ => bail!("devis MoonPay Trade illisible (commission)"),
    }
}

/// Lit et vérifie la réponse de `getAction` pour la demande faite : paire,
/// montant exact, minimum ≤ attendu, commission ≤ `FEE_BPS`, et transaction
/// de la forme attendue pour la route (routeur UTB sur un même réseau EVM,
/// sinon virement de dépôt). Fonction pure.
pub fn parse_action(body: &Value, from: &Asset, to: &Asset, amount: u128) -> Result<Quote> {
    let (chain, token, amount_in) = payment(&body["amountIn"], "montant vendu")?;
    ensure!(chain == from.chain && same_token(from, &token), "le devis MoonPay Trade vend une autre crypto — refus");
    ensure!(amount_in == amount, "le devis MoonPay Trade porte sur un autre montant — refus");
    let (chain, token, expected_out) = payment(&body["amountOut"], "montant reçu")?;
    ensure!(chain == to.chain && same_token(to, &token), "le devis MoonPay Trade livre une autre crypto — refus");
    let (chain, token, min_out) = payment(&body["amountOutMin"], "minimum reçu")?;
    ensure!(chain == to.chain && same_token(to, &token), "le devis MoonPay Trade livre une autre crypto — refus");
    ensure!(min_out > 0 && min_out <= expected_out, "minimum de réception MoonPay Trade incohérent — refus");
    // Commission de l'app : au plus `FEE_BPS` du montant vendu ; frais propres
    // à MoonPay : au plus `MAX_PROTOCOL_FEE_BPS` (affichés à l'utilisateur).
    let app_fee = fee_bps(body, "applicationFee", from, amount)?;
    ensure!(
        app_fee.is_none_or(|bps| bps <= f64::from(FEE_BPS) + 0.5),
        "le devis MoonPay Trade prélève une commission supérieure à {:.2} % — refus",
        f64::from(FEE_BPS) / 100.0
    );
    let protocol_fee = fee_bps(body, "protocolFee", from, amount)?.unwrap_or(0.0);
    ensure!(
        protocol_fee <= f64::from(MAX_PROTOCOL_FEE_BPS),
        "le devis MoonPay Trade annonce des frais MoonPay supérieurs à {:.2} % — refus",
        f64::from(MAX_PROTOCOL_FEE_BPS) / 100.0
    );
    ensure!(body["executionsType"].as_str().is_none_or(|t| t == "DEFAULT"), "devis MoonPay Trade d'une forme non prise en charge — refus");
    let tx_id = body["txId"].as_str().filter(|id| id.len() == 66 && id.starts_with("0x") && id[2..].bytes().all(|b| b.is_ascii_hexdigit())).context("devis MoonPay Trade sans identifiant")?;
    let tx = &body["tx"];
    let vm = body["vmId"].as_str().unwrap_or("");
    let tx_chain = tx["chainId"].as_u64();
    let trade_tx = if verifiable((from.coin, from.network), (to.coin, to.network)) {
        ensure!(vm == "evm" && tx_chain == Some(from.chain), "devis MoonPay Trade d'une forme inattendue — refus");
        let target = tx["to"].as_str().context("devis MoonPay Trade sans destinataire")?;
        let expected_router = router(from.network).expect("réseau EVM");
        ensure!(target.eq_ignore_ascii_case(expected_router), "la transaction MoonPay Trade appelle un autre contrat que son routeur — refus de signer");
        let data = hex_data(tx["data"].as_str().unwrap_or(""))?;
        ensure!(data.len() >= 4, "devis MoonPay Trade sans appel — refus");
        // Le minimum affiché est celui que le routeur exigera
        // (`swapParams.amountOut`, relevé le 08/10/2026 dans de vraies
        // transactions) : sinon, refus (32ᵉ passage).
        ensure!(contains_word(&data[4..], min_out), "la transaction MoonPay Trade ne garantit pas le minimum affiché — refus de signer");
        let value = amount_value(&tx["value"]).context("devis MoonPay Trade illisible (valeur)")?;
        ensure!(value == if from.native { amount } else { 0 }, "la transaction MoonPay Trade enverrait un autre montant — refus de signer");
        TradeTx::Router { router: wallet_flow::parse_evm_address(expected_router)?, data, value }
    } else if is_evm(from.network) {
        ensure!(vm == "evm" && tx_chain == Some(from.chain), "devis MoonPay Trade d'une forme inattendue — refus");
        let target = tx["to"].as_str().context("devis MoonPay Trade sans destinataire")?;
        let data = hex_data(tx["data"].as_str().unwrap_or("0x"))?;
        let value = amount_value(&tx["value"]).context("devis MoonPay Trade illisible (valeur)")?;
        let deposit = if from.native {
            ensure!(data.is_empty() && value == amount, "le dépôt MoonPay Trade n'est pas un simple virement du montant exact — refus de signer");
            wallet_flow::parse_evm_address(target)?
        } else {
            // Virement du jeton : `transfer(dépôt, montant exact)` sur son contrat.
            ensure!(target.eq_ignore_ascii_case(from.token) && value == 0 && data.len() == 68, "le dépôt MoonPay Trade n'est pas un simple virement du jeton — refus de signer");
            let deposit: [u8; 20] = data[16..36].try_into().expect("20 octets");
            ensure!(data == erc20_transfer_data(&deposit, amount), "le dépôt MoonPay Trade n'est pas un simple virement du montant exact — refus de signer");
            deposit
        };
        ensure!(deposit != [0u8; 20], "adresse de dépôt MoonPay Trade invalide — refus");
        TradeTx::Deposit { address: crate::derivation::format_address(&deposit), memo: None }
    } else {
        ensure!(vm == "alt-vm" && tx_chain == Some(from.chain), "devis MoonPay Trade d'une forme inattendue — refus");
        let value = amount_value(&tx["value"]).context("devis MoonPay Trade illisible (valeur)")?;
        ensure!(value == amount, "le dépôt MoonPay Trade porte sur un autre montant — refus de signer");
        let address = tx["to"].as_str().context("devis MoonPay Trade sans adresse de dépôt")?.trim().to_string();
        // Adresse d'une forme que l'app ne sait pas payer (autre réseau,
        // version SegWit future…) : un nouveau devis en donne en général une
        // autre. Bitcoin : tous les types standard (P2SH 3… compris, donné
        // parfois par MoonPay Trade, relevé le 07/10/2026).
        external_wallets::validate_address(from.network, &address).map_err(|_| anyhow!("adresse de dépôt MoonPay Trade d'une forme que l'app ne sait pas payer — demandez un nouveau devis"))?;
        let memo = match tx["toExtra"].as_str().map(str::trim).filter(|m| !m.is_empty()) {
            None => None,
            // XRP : tag de destination (entier 32 bits).
            Some(tag) if from.network == "xrp_mainnet" && tag.parse::<u32>().is_ok() => Some(tag.to_string()),
            Some(_) => bail!("mémo de dépôt MoonPay Trade non pris en charge — refus"),
        };
        TradeTx::Deposit { address, memo }
    };
    Ok(Quote {
        tx_id: tx_id.to_string(),
        amount,
        expected_out,
        min_out,
        duration_secs: body["estimatedTxTime"].as_f64().filter(|s| s.is_finite() && *s >= 0.0).map(|s| s.ceil() as u64).unwrap_or(0),
        protocol_fee_bps: protocol_fee.round() as u32,
        register: body["requiresRegisterTransaction"].as_bool().unwrap_or(false),
        tx: trade_tx,
    })
}

/// Paramètres de `getAction`. Commission de l'app demandée sur chaque route,
/// versée à une adresse EVM (exigé par MoonPay Trade, même pour un dépôt
/// Bitcoin ou XRP — relevé le 07/10/2026) ; remboursement à l'expéditeur.
fn action_params(from: &Asset, to: &Asset, amount: u128, sender: &str, recipient: &str) -> Vec<(&'static str, String)> {
    vec![
        ("actionType", "swap-action".to_string()),
        ("sender", sender.trim().to_string()),
        ("recipient", recipient.trim().to_string()),
        ("refundTo", sender.trim().to_string()),
        ("srcChainId", from.chain.to_string()),
        ("srcToken", from.token.to_string()),
        ("dstChainId", to.chain.to_string()),
        ("dstToken", to.token.to_string()),
        ("slippage", SLIPPAGE_BPS.to_string()),
        ("amount", amount.to_string()),
        ("swapDirection", "exact-amount-in".to_string()),
        ("appFees", format!("[{{\"bps\":{FEE_BPS},\"receiverAddress\":\"{FEE_RECEIVER}\"}}]")),
    ]
}

/// Devis exécutable de MoonPay Trade (`getAction`) : `sender` vend `amount`
/// de `from`, `recipient` reçoit `to` ; remboursement à `sender` (dépôt
/// depuis un réseau non EVM). Vérifié par `parse_action`.
pub fn quote(from: &Asset, to: &Asset, amount: u128, sender: &str, recipient: &str) -> Result<Quote> {
    let key = key().context("MoonPay Trade indisponible dans cette version de l'app")?;
    ensure!(links((from.coin, from.network), (to.coin, to.network)), "MoonPay Trade ne relie pas ces deux cryptos");
    external_wallets::validate_address(to.network, recipient)?;
    let response = client()
        .get(format!("{API_BASE}/getAction"))
        .header("x-api-key", key)
        .query(&action_params(from, to, amount, sender, recipient))
        .send()
        .map_err(|e| anyhow!("MoonPay Trade injoignable : {}", e.without_url()))?;
    let status = response.status().as_u16();
    let body: Value = response.json().context("réponse de MoonPay Trade illisible")?;
    if status != 200 {
        return Err(api_error(&body, status));
    }
    parse_action(&body, from, to, amount)
}

/// Déclare un dépôt diffusé (exigé pour son suivi par MoonPay Trade quand le
/// devis le demande).
pub fn register(tx_id: &str, tx_hash: &str) -> Result<()> {
    let key = key().context("MoonPay Trade indisponible dans cette version de l'app")?;
    let response = client()
        .post(format!("{API_BASE}/registerTxs"))
        .header("x-api-key", key)
        .json(&serde_json::json!({ "txId": tx_id, "txHash": tx_hash }))
        .send()
        .map_err(|e| anyhow!("MoonPay Trade injoignable : {}", e.without_url()))?;
    ensure!(response.status().is_success(), "MoonPay Trade : enregistrement du dépôt refusé ({})", response.status().as_u16());
    Ok(())
}

// --- Vérification d'un échange par le routeur ----------------------------------------------

/// Ce que l'échange doit faire, et rien d'autre.
pub struct Expected {
    pub user: [u8; 20],
    /// Jeton vendu (`None` : monnaie du réseau).
    pub sell_token: Option<[u8; 20]>,
    pub amount: u128,
    /// Jeton acheté (`None` : monnaie du réseau).
    pub buy_token: Option<[u8; 20]>,
    pub min_out: u128,
    pub router: [u8; 20],
}

fn word(data: &[u8], index: usize) -> Result<u128> {
    let slot = data.get(index * 32..index * 32 + 32).context("événement illisible")?;
    ensure!(slot[..16].iter().all(|b| *b == 0), "montant hors limites");
    Ok(u128::from_be_bytes(slot[16..].try_into().expect("16 octets")))
}

fn padded(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// Vérifie la simulation (autorisation éventuelle, puis appel du routeur,
/// mouvements de monnaie native tracés) : tout réussit ; seul le jeton vendu
/// quitte l'utilisateur, au montant exact (autorisation au routeur seulement,
/// au plus le montant) ; le jeton acheté arrive sur l'adresse de
/// l'utilisateur, au moins le minimum garanti. Fonction pure.
pub fn verify_router(calls: &[crate::eth_rpc::SimulatedCall], expected: &Expected) -> Result<u128> {
    ensure!(calls.iter().all(|c| c.success), "l'échange MoonPay Trade échouerait (simulation) — rien n'a été envoyé");
    let transfer = evm_sign::keccak(b"Transfer(address,address,uint256)");
    let approval = evm_sign::keccak(b"Approval(address,address,uint256)");
    let approval_for_all = evm_sign::keccak(b"ApprovalForAll(address,address,bool)");
    let native = crate::eth_rpc::NATIVE_TRANSFER_EMITTER;
    let user = padded(&expected.user);
    let sold_token = expected.sell_token.unwrap_or(native);
    let bought_token = expected.buy_token.unwrap_or(native);
    let (mut sent, mut received) = (0u128, 0u128);
    for log in calls.iter().flat_map(|c| &c.logs) {
        let Some(kind) = log.topics.first() else { continue };
        if (*kind == transfer || *kind == approval || *kind == approval_for_all) && log.topics.get(1) == Some(&user) {
            ensure!(
                *kind != approval_for_all && log.topics.len() == 3,
                "l'échange MoonPay Trade toucherait un autre actif de votre portefeuille (NFT ou autorisation globale) — refus de signer"
            );
            ensure!(log.address == sold_token, "l'échange MoonPay Trade ferait sortir une autre crypto de votre portefeuille — refus de signer");
            let value = word(&log.data, 0)?;
            if *kind == transfer {
                sent = sent.checked_add(value).context("montant hors limites")?;
            } else {
                ensure!(
                    log.topics[2] == padded(&expected.router) && value <= expected.amount,
                    "l'échange MoonPay Trade autoriserait un autre contrat ou un autre montant — refus de signer"
                );
            }
        } else if *kind == transfer && log.topics.len() == 3 && log.topics[2] == user && log.address == bought_token {
            received = received.checked_add(word(&log.data, 0)?).context("montant hors limites")?;
        }
    }
    ensure!(sent == expected.amount, "l'échange MoonPay Trade ferait sortir {sent} unité(s) au lieu de {} — refus de signer", expected.amount);
    ensure!(
        received >= expected.min_out,
        "l'échange MoonPay Trade livrerait moins que le minimum garanti à votre adresse ({received} au lieu d'au moins {}) — refus de signer",
        expected.min_out
    );
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_rpc::{SimulatedCall, SimulatedLog};
    use serde_json::json;

    /// Clé de DÉMONSTRATION publiée dans la documentation officielle
    /// (docs.swaps.xyz, page get-quote : « Limited demo key for API
    /// Reference ») : tests réels seulement, jamais dans l'app (elle prélève
    /// 1 % pour un autre intégrateur).
    const DEMO_KEY: &str = "5c951bc81da566bbd030ba8e20724063";
    const USER: &str = "0x9458af2b720ecf1bb18f525d864a28af5c818cfa";
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    fn a(coin: &str, network: &str) -> Asset {
        asset(coin, network).unwrap()
    }

    fn pay(chain: u64, address: &str, amount: &str) -> Value {
        json!({ "chainId": chain, "address": address, "amount": amount, "usdAmount": 1.0 })
    }

    /// Réponse réelle (07/10/2026, clé de démo) : 0,01 ETH → USDC sur
    /// Ethereum, routeur UTB ; commission ramenée à 0,80 % (`appFees`).
    fn eth_usdc() -> Value {
        json!({
            "tx": { "to": "0x1b6257CAE4192e62B629eFCa21771be3D759183D", "chainId": 1, "data": "0x9be111d10000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000180706b", "value": "10000000000000000" },
            "txId": "0x531ea920437f8fa717796865c35583f9dca4659b240ba46c5517cc226dc743d9",
            "vmId": "evm",
            "amountIn": { "chainId": 1, "address": NATIVE, "amount": "10000000000000000", "usdAmount": 25.6 },
            "amountOut": pay(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "25449094"),
            "amountOutMin": pay(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "25194603"),
            "applicationFee": pay(1, NATIVE, "80000000000000"),
            "protocolFee": pay(1, NATIVE, "30000000000000"),
            "estimatedTxTime": 0, "requiresRegisterTransaction": false, "executionsType": "DEFAULT"
        })
    }

    #[test]
    fn assets_and_links() {
        assert_eq!(a("btc", "btc_mainnet").chain, 999_000_313);
        assert_eq!(a("usdc", "evm_mainnet").token, USDC);
        assert_eq!(a("usdc", "sol_mainnet").token, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        assert!(asset("tao", "tao_mainnet").is_none(), "TAO absent de MoonPay Trade");
        assert!(asset("usdt", "tron_mainnet").is_none(), "jetons Tron pas encore pris en charge");
        // Même réseau EVM : vérifiable.
        assert!(verifiable(("evm", "evm_mainnet"), ("usdc", "evm_mainnet")) && links(("evm", "evm_mainnet"), ("usdc", "evm_mainnet")));
        // Dépôt depuis un réseau connu de l'app, vers n'importe quel réseau.
        assert!(links(("evm", "evm_mainnet"), ("xmr", "xmr_mainnet")) && !verifiable(("evm", "evm_mainnet"), ("xmr", "xmr_mainnet")));
        assert!(links(("xrp", "xrp_mainnet"), ("evm", "evm_mainnet")));
        // Pas de dépôt depuis Monero, Solana, Stellar… ; pas d'échange sur un même réseau non EVM.
        assert!(!links(("xmr", "xmr_mainnet"), ("evm", "evm_mainnet")) && !links(("sol", "sol_mainnet"), ("evm", "evm_mainnet")));
        assert!(!links(("sol", "sol_mainnet"), ("usdc", "sol_mainnet")));
        // Avalanche : nœud sans simulation, routeur invérifiable — pas d'échange
        // sur ce réseau ; dépôt possible vers un autre.
        assert!(!verifiable(("avax", "avax_mainnet"), ("usdc", "avax_mainnet")) && !links(("avax", "avax_mainnet"), ("usdt", "avax_mainnet")));
        assert!(links(("avax", "avax_mainnet"), ("xmr", "xmr_mainnet")));
        assert!(tradable().contains(&("xmr", "xmr_mainnet")) && tradable().contains(&("link", "evm_mainnet")));
    }

    /// Clé du widget MoonPay (publiable ou secrète) : pas une clé Trade.
    #[test]
    fn widget_keys_are_not_trade_keys() {
        for widget in ["pk_test_x", "pk_live_x", "sk_live_x"] {
            assert!(Some(widget).filter(|k| !k.starts_with("pk_") && !k.starts_with("sk_")).is_none());
        }
    }

    #[test]
    fn router_quote_is_read_and_checked() {
        let (eth, usdc) = (a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"));
        let quote = parse_action(&eth_usdc(), &eth, &usdc, 10_000_000_000_000_000).unwrap();
        assert_eq!((quote.expected_out, quote.min_out, quote.register, quote.protocol_fee_bps), (25_449_094, 25_194_603, false, 30));
        assert!(matches!(&quote.tx, TradeTx::Router { value, .. } if *value == 10_000_000_000_000_000));
        // Falsifications : chaque écart est refusé.
        let refused = |edit: &dyn Fn(&mut Value)| {
            let mut body = eth_usdc();
            edit(&mut body);
            parse_action(&body, &eth, &usdc, 10_000_000_000_000_000).unwrap_err().to_string()
        };
        assert!(refused(&|b| b["tx"]["to"] = json!("0x1111111254eeb25477b68fb85ed929f73a960582")).contains("autre contrat"));
        assert!(refused(&|b| b["tx"]["value"] = json!("20000000000000000")).contains("autre montant"));
        assert!(refused(&|b| b["amountIn"]["amount"] = json!("1")).contains("autre montant"));
        assert!(refused(&|b| b["amountOut"]["address"] = json!("0xdac17f958d2ee523a2206206994597c13d831ec7")).contains("autre crypto"));
        assert!(refused(&|b| b["amountOutMin"]["amount"] = json!("99999999")).contains("incohérent"));
        assert!(refused(&|b| b["applicationFee"]["amount"] = json!("100000000000000")).contains("commission"));
        assert!(refused(&|b| b["protocolFee"]["amount"] = json!("150000000000000")).contains("frais MoonPay"));
        // Frais comptés dans une autre crypto : bornés d'après les dollars du devis.
        assert!(refused(&|b| b["applicationFee"] = json!({ "chainId": 1, "address": USDC, "amount": "260000", "usdAmount": 0.26 })).contains("commission"));
        assert!(refused(&|b| b["executionsType"] = json!("GASLESS")).contains("forme"));
        // Le routeur doit exiger le minimum affiché.
        assert!(refused(&|b| b["amountOutMin"]["amount"] = json!("25000000")).contains("minimum affiché"));
        assert!(refused(&|b| b["tx"]["chainId"] = json!(42161)).contains("forme"));
    }

    #[test]
    fn deposit_quotes_are_read_and_checked() {
        let (eth, usdc, btc, xrp) = (a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"), a("btc", "btc_mainnet"), a("xrp", "xrp_mainnet"));
        let body = |tx: Value, from: &Asset, amount: &str, vm: &str| {
            json!({
                "tx": tx, "txId": "0xe6f0437787eb10d3bedc71d6e79c87524bc0cbe3dd494ea567a5d41702d2cb7c", "vmId": vm,
                "amountIn": pay(from.chain, from.token, amount),
                "amountOut": pay(999_000_313, NATIVE, "151270"), "amountOutMin": pay(999_000_313, NATIVE, "151270"),
                "requiresRegisterTransaction": true
            })
        };
        // ETH → BTC (réel) : virement simple vers l'adresse de dépôt.
        let eth_btc = body(json!({ "to": "0x3De23013a152628C8ad4a122c77732aa5252ad65", "value": "50000000000000000", "chainId": 1, "data": "0x" }), &eth, "50000000000000000", "evm");
        let quote = parse_action(&eth_btc, &eth, &btc, 50_000_000_000_000_000).unwrap();
        assert_eq!(quote.tx, TradeTx::Deposit { address: "0x3De23013a152628C8ad4a122c77732aa5252ad65".into(), memo: None });
        assert!(quote.register);
        let mut with_call = eth_btc.clone();
        with_call["tx"]["data"] = json!("0x12345678");
        assert!(parse_action(&with_call, &eth, &btc, 50_000_000_000_000_000).unwrap_err().to_string().contains("simple virement"));
        // USDC → BTC (réel) : `transfer(dépôt, montant)` sur le contrat USDC.
        let usdc_btc = body(
            json!({ "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "value": "0", "chainId": 1, "data": "0xa9059cbb000000000000000000000000e3cf74a4b0690400a2390683d0e2eef46427c6f70000000000000000000000000000000000000000000000000000000008f0d180" }),
            &usdc,
            "150000000",
            "evm",
        );
        let quote = parse_action(&usdc_btc, &usdc, &btc, 150_000_000).unwrap();
        assert!(matches!(&quote.tx, TradeTx::Deposit { address, .. } if address.eq_ignore_ascii_case("0xe3cf74a4b0690400a2390683d0e2eef46427c6f7")));
        let mut approve = usdc_btc.clone();
        approve["tx"]["data"] = json!("0x095ea7b3000000000000000000000000e3cf74a4b0690400a2390683d0e2eef46427c6f70000000000000000000000000000000000000000000000000000000008f0d180");
        assert!(parse_action(&approve, &usdc, &btc, 150_000_000).is_err(), "autorisation au lieu d'un virement");
        // XRP → ETH (réel) : dépôt r… avec tag de destination.
        let mut xrp_eth = body(json!({ "to": "rKKbNYZRqwPgZYkFWvqNUFBuscEyiFyCE", "toExtra": "962769451", "value": "50000000", "chainId": 999_000_346, "chainKey": "xrp" }), &xrp, "50000000", "alt-vm");
        xrp_eth["amountOut"] = pay(1, NATIVE, "27284700000000000");
        xrp_eth["amountOutMin"] = pay(1, NATIVE, "27284700000000000");
        let quote = parse_action(&xrp_eth, &xrp, &eth, 50_000_000).unwrap();
        assert_eq!(quote.tx, TradeTx::Deposit { address: "rKKbNYZRqwPgZYkFWvqNUFBuscEyiFyCE".into(), memo: Some("962769451".into()) });
        let mut bad_tag = xrp_eth.clone();
        bad_tag["tx"]["toExtra"] = json!("memo texte");
        assert!(parse_action(&bad_tag, &xrp, &eth, 50_000_000).is_err());
        let mut bad_address = xrp_eth.clone();
        bad_address["tx"]["to"] = json!("rKKbNYZRqwPgZYkFWvqNUFBuscEyiFyCF");
        assert!(parse_action(&bad_address, &xrp, &eth, 50_000_000).unwrap_err().to_string().contains("ne sait pas payer"));
        // BTC → ETH (réel) : dépôt P2SH, payable ; adresse de dépôt d'une
        // version SegWit future : nouveau devis demandé.
        let mut p2sh = body(json!({ "to": "3PFQuK2rjdCSHxCxT7p4jeVB34Fva3qwps", "toExtra": null, "value": "100000", "chainId": 999_000_313, "chainKey": "btc" }), &btc, "100000", "alt-vm");
        p2sh["amountOut"] = pay(1, NATIVE, "31776200000000000");
        p2sh["amountOutMin"] = pay(1, NATIVE, "31776200000000000");
        assert_eq!(parse_action(&p2sh, &btc, &eth, 100_000).unwrap().tx, TradeTx::Deposit { address: "3PFQuK2rjdCSHxCxT7p4jeVB34Fva3qwps".into(), memo: None });
        p2sh["tx"]["to"] = json!("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs");
        assert!(parse_action(&p2sh, &btc, &eth, 100_000).unwrap_err().to_string().contains("nouveau devis"));
        p2sh["tx"]["to"] = json!("bc1qp4lu3qxd45jv5lnw9uauhm70238fgrzlv5s8he");
        assert!(parse_action(&p2sh, &btc, &eth, 100_000).is_ok());
    }

    #[test]
    fn api_errors_are_explained() {
        let error = |code: &str| api_error(&json!({ "success": false, "error": { "code": code, "details": { "minAmount": "0.0012" } } }), 400).to_string();
        assert!(error("NO_AVAILABLE_ROUTE").contains("ne propose pas"));
        assert_eq!(error("AMOUNT_TOO_LOW"), "montant trop faible pour MoonPay Trade (minimum 0.0012)");
        assert!(error("WALLET_SCREENED").contains("conformité"));
        assert!(error("INVALID_API_KEY").contains("clé"));
    }

    fn log(address: &str, topics: Vec<[u8; 32]>, amount: u128) -> SimulatedLog {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(&amount.to_be_bytes());
        SimulatedLog { address: wallet_flow::parse_evm_address(address).unwrap(), topics, data }
    }

    fn topic_addr(address: &str) -> [u8; 32] {
        padded(&wallet_flow::parse_evm_address(address).unwrap())
    }

    /// Événements de la vraie simulation du 07/10/2026 (0,01 ETH → USDC,
    /// Ethereum, mouvements d'ETH tracés), réduits à ceux qui comptent.
    #[test]
    fn router_simulation_is_verified() {
        let transfer = evm_sign::keccak(b"Transfer(address,address,uint256)");
        let approval = evm_sign::keccak(b"Approval(address,address,uint256)");
        let eth = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let router = "0x1b6257cae4192e62b629efca21771be3d759183d";
        let executor = "0x18dc2961ddcca0d61b4d2e9c42ff5e1f5c8d25b4";
        let real = || {
            vec![
                log(eth, vec![transfer, topic_addr(USER), topic_addr(router)], 10_000_000_000_000_000),
                log(eth, vec![transfer, topic_addr(router), topic_addr("0x79ad858cdff50ca6728d2531894001f221e805c7")], 80_000_000_000_000),
                log(USDC, vec![transfer, topic_addr(executor), topic_addr(USER)], 25_194_603),
                log(USDC, vec![transfer, topic_addr(executor), topic_addr(USER)], 254_491),
            ]
        };
        let expected = Expected {
            user: wallet_flow::parse_evm_address(USER).unwrap(),
            sell_token: None,
            amount: 10_000_000_000_000_000,
            buy_token: Some(wallet_flow::parse_evm_address(USDC).unwrap()),
            min_out: 25_194_603,
            router: wallet_flow::parse_evm_address(router).unwrap(),
        };
        let ok = |logs: Vec<SimulatedLog>| verify_router(&[SimulatedCall { success: true, logs }], &expected);
        assert_eq!(ok(real()).unwrap(), 25_449_094);
        // Moins que le minimum à l'adresse de l'utilisateur.
        let mut short = real();
        short.pop();
        short[2] = log(USDC, vec![transfer, topic_addr(executor), topic_addr(USER)], 25_000_000);
        assert!(ok(short).unwrap_err().to_string().contains("minimum"));
        // USDC livrés à quelqu'un d'autre.
        let mut elsewhere = real();
        elsewhere[2] = log(USDC, vec![transfer, topic_addr(executor), topic_addr(router)], 25_194_603);
        elsewhere.pop();
        assert!(ok(elsewhere).is_err());
        // Plus d'ETH que prévu, ou un jeton de l'utilisateur en plus.
        let mut more = real();
        more.push(log(eth, vec![transfer, topic_addr(USER), topic_addr(router)], 1));
        assert!(ok(more).unwrap_err().to_string().contains("au lieu de"));
        let mut other_token = real();
        other_token.push(log("0xdac17f958d2ee523a2206206994597c13d831ec7", vec![transfer, topic_addr(USER), topic_addr(router)], 5));
        assert!(ok(other_token).unwrap_err().to_string().contains("autre crypto"));
        // Jeton vendu : autorisation au routeur seulement, au plus le montant.
        let usdc_sell = Expected { sell_token: Some(wallet_flow::parse_evm_address(USDC).unwrap()), buy_token: None, amount: 50_000_000, min_out: 1, ..expected };
        let approve = |spender: &str, amount: u128| log(USDC, vec![approval, topic_addr(USER), topic_addr(spender)], amount);
        let sell = |approval: SimulatedLog| {
            let logs = vec![
                approval,
                log(USDC, vec![transfer, topic_addr(USER), topic_addr(router)], 50_000_000),
                log(eth, vec![transfer, topic_addr(executor), topic_addr(USER)], 19_000_000_000_000_000),
            ];
            verify_router(&[SimulatedCall { success: true, logs }], &usdc_sell)
        };
        assert!(sell(approve(router, 50_000_000)).is_ok());
        assert!(sell(approve(executor, 50_000_000)).unwrap_err().to_string().contains("autre contrat"));
        assert!(sell(approve(router, 50_000_001)).is_err());
        // Simulation en échec.
        assert!(verify_router(&[SimulatedCall { success: false, logs: real() }], &expected).unwrap_err().to_string().contains("échouerait"));
    }

    /// Même requête que l'app (`action_params`), avec la clé de démo.
    fn demo_quote(from: &Asset, to: &Asset, amount: u128, sender: &str, recipient: &str) -> Quote {
        let params = action_params(from, to, amount, sender, recipient);
        let body: Value = client().get(format!("{API_BASE}/getAction")).header("x-api-key", DEMO_KEY).query(&params).send().unwrap().json().unwrap();
        parse_action(&body, from, to, amount).unwrap_or_else(|e| panic!("{e} : {}", body.to_string().chars().take(400).collect::<String>()))
    }

    /// Réel (clé de démo, rien n'est diffusé) : ETH → USDC sur Ethereum ;
    /// la transaction du routeur, simulée depuis un compte public pourvu
    /// (Vitalik), passe `verify_router` ; un minimum gonflé est refusé.
    /// `cargo test -- --ignored real_moonpay_trade_router --nocapture`
    #[test]
    #[ignore]
    fn real_moonpay_trade_router() {
        let rich = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let (eth, usdc) = (a("evm", "evm_mainnet"), a("usdc", "evm_mainnet"));
        let quote = demo_quote(&eth, &usdc, 10_000_000_000_000_000, rich, rich);
        let TradeTx::Router { router, data, value } = &quote.tx else { panic!("routeur attendu") };
        let rpc = crate::eth_rpc::EthRpc::new(wallet_flow::evm_network("evm_mainnet").unwrap().rpc);
        let to = crate::derivation::format_address(router);
        let simulated = rpc.simulate_v1_with_native_transfers(&[crate::eth_rpc::SimCallRequest { from: rich, to: &to, value: *value, data }]).unwrap();
        let expected = Expected {
            user: wallet_flow::parse_evm_address(rich).unwrap(),
            sell_token: None,
            amount: quote.amount,
            buy_token: Some(wallet_flow::parse_evm_address(USDC).unwrap()),
            min_out: quote.min_out,
            router: *router,
        };
        let received = verify_router(&simulated, &expected).unwrap();
        println!("0,01 ETH → {received} unités USDC (minimum {}, attendu {})", quote.min_out, quote.expected_out);
        let inflated = Expected { min_out: received + 1, ..expected };
        assert!(verify_router(&simulated, &inflated).is_err());
    }

    /// Exploration (clé de démo) : forme des adresses de dépôt par réseau de
    /// départ, depuis des adresses dérivées d'une graine fictive.
    #[test]
    #[ignore]
    fn explore_deposit_address_formats() {
        let seed = [7u8; 64];
        let doge = crate::doge::p2pkh_address(&crate::derivation::derive_doge_key(&seed, 0).unwrap().1);
        let zec = crate::zcash::p2pkh_address(&crate::derivation::derive_zec_key(&seed, 0).unwrap().1);
        let ada = crate::cardano::address_of(&seed[..32], 0);
        let near = crate::near::implicit_account(&crate::derivation::derive_near_key(&seed, 0));
        let btc = crate::derivation::format_btc_mainnet_address(&crate::derivation::derive_btc_mainnet_key(&seed, 0).unwrap().1).unwrap();
        let eth = a("evm", "evm_mainnet");
        for (coin, network, amount, sender) in [("doge", "doge_mainnet", 50_000_000_000u128, doge), ("zec", "zec_mainnet", 50_000_000, zec), ("ada", "ada_mainnet", 200_000_000, ada), ("near", "near_mainnet", 50_000_000_000_000_000_000_000_000, near), ("btc", "btc_mainnet", 200_000, btc)] {
            let from = a(coin, network);
            let body: Value = client().get(format!("{API_BASE}/getAction")).header("x-api-key", DEMO_KEY).query(&action_params(&from, &eth, amount, &sender, USER)).send().unwrap().json().unwrap();
            println!("{coin} ({sender}) → dépôt {} mémo {} vm {}", body["tx"]["to"], body["tx"]["toExtra"], body["vmId"]);
            if body["tx"].is_null() {
                println!("   {}", body.to_string().chars().take(300).collect::<String>());
            }
        }
    }

    /// Réel (clé de démo) : dépôts — ETH → XMR (adresse de don du projet
    /// Monero), BTC → ETH, XRP → ETH (tag) — lus et vérifiés.
    /// `cargo test -- --ignored real_moonpay_trade_deposits --nocapture`
    #[test]
    #[ignore]
    fn real_moonpay_trade_deposits() {
        let xmr_donation = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        let (eth, xmr, btc, xrp) = (a("evm", "evm_mainnet"), a("xmr", "xmr_mainnet"), a("btc", "btc_mainnet"), a("xrp", "xrp_mainnet"));
        for (from, to, amount, sender, recipient) in [
            (&eth, &xmr, 50_000_000_000_000_000u128, USER, xmr_donation),
            (&btc, &eth, 100_000, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", USER),
            (&xrp, &eth, 50_000_000, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", USER),
        ] {
            let body: Value = client().get(format!("{API_BASE}/getAction")).header("x-api-key", DEMO_KEY).query(&action_params(from, to, amount, sender, recipient)).send().unwrap().json().unwrap();
            match parse_action(&body, from, to, amount) {
                Ok(quote) => {
                    println!("{} → {} : {:?}, minimum {} (~{} s)", from.symbol, to.symbol, quote.tx, quote.min_out, quote.duration_secs);
                    assert!(matches!(quote.tx, TradeTx::Deposit { .. }));
                }
                // Bitcoin : dépôt d'une forme non payable (version SegWit future), refusé proprement.
                Err(e) if from.network == "btc_mainnet" && e.to_string().contains("nouveau devis") => println!("BTC → ETH : {e} ({})", body["tx"]["to"]),
                Err(e) => panic!("{e}"),
            }
        }
    }
}
