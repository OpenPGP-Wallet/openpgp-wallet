//! LI.FI : échanges directs entre deux écosystèmes (ex. RENDER sur Solana →
//! LINK sur Ethereum), là où THORChain, Maya, Jupiter et CoW ne relient rien.
//! LI.FI est un agrégateur : il choisit un pont (Mayan, Relay, Layerswap…) et
//! construit LUI-MÊME la transaction, que l'app ne peut donc pas reconstruire
//! comme un memo THORChain ou un ordre CoW. Elle est vérifiée avant
//! signature :
//! - source EVM : simulation (`eth_simulateV1`) de l'autorisation et de
//!   l'appel, puis lecture des événements émis par le contrat LI.FI — seul le
//!   jeton vendu quitte l'utilisateur, au montant exact, et le destinataire
//!   émis par le contrat est celui affiché. Un pont qui garde le destinataire
//!   hors chaîne (« Relay depository ») est écarté et un nouveau devis
//!   demandé sans lui. Avalanche et HyperEVM : leurs nœuds ne simulent pas,
//!   le destinataire est lu dans les données de l'appel (destination EVM
//!   seulement) ;
//! - source Solana : simulation des effets sur les comptes de l'utilisateur
//!   (même contrôle que Jupiter, voir `api::send_lifi_solana`) ; le
//!   destinataire, géré hors chaîne par le pont, n'est pas vérifiable — la
//!   boîte de confirmation le dit.
//!
//! Sans clé d'API (elle ne doit jamais être embarquée dans une app installée) :
//! 75 devis par 2 heures et par adresse IP, assez pour un portefeuille. Les
//! frais intégrateur (`FEE`) exigent un compte sur portal.li.fi : tant que
//! `INTEGRATOR` n'est pas renseigné, aucune route LI.FI n'est proposée.

use crate::{eth_rpc, evm_sign, tokens, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::Value;
use std::sync::OnceLock;

const API_BASE: &str = "https://li.quest/v1";
/// Nom d'intégrateur enregistré sur portal.li.fi par l'utilisateur le
/// 02/10/2026 (portefeuilles de frais configurés là-bas ; frais acceptés par
/// LI.FI, vérifié sur de vrais devis : « LIFI Fixed Fee » 1,05 % = 0,25 % de
/// LI.FI + nos 0,80 %). Sans lui (`None`), aucune route LI.FI.
pub const INTEGRATOR: Option<&str> = Some("openpgp-wallet");
/// Frais intégrateur : 0,80 % du montant envoyé (LI.FI prend en plus 0,25 %).
pub const FEE: f64 = 0.008;
/// Glissement toléré (1 %), garanti par le pont.
const SLIPPAGE: &str = "0.01";
/// Identifiants de chaîne LI.FI des réseaux non EVM.
pub const SOLANA_CHAIN: u64 = 1_151_111_081_099_710;
pub const BITCOIN_CHAIN: u64 = 20_000_000_000_001;
/// Destinataire inscrit par le contrat LI.FI quand l'arrivée n'est pas sur un
/// réseau EVM (le vrai est émis à part, `BridgeToNonEVMChain…`).
const NON_EVM_RECEIVER: [u8; 20] = [
    0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1,
];
/// Nouveaux devis demandés au plus quand le pont proposé garde le destinataire
/// hors chaîne.
pub const MAX_ROUTE_ATTEMPTS: usize = 3;

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Contrat d'entrée de LI.FI (« diamond ») sur un réseau EVM de l'app, relevé
/// sur `li.quest/v1/chains` (même adresse partout sauf HyperEVM).
pub fn diamond(network: &str) -> Option<&'static str> {
    Some(match network {
        "evm_mainnet" | "arbitrum_mainnet" | "base_mainnet" | "bsc_mainnet" | "avax_mainnet" | "polygon_mainnet" => "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE",
        "hyperevm_mainnet" => "0x0a0758d937d1059c356D4714e57F5df0239bce1A",
        _ => return None,
    })
}

/// Identifiant de chaîne LI.FI d'un réseau de l'app.
pub fn chain_id(network: &str) -> Option<u64> {
    match network {
        "sol_mainnet" => Some(SOLANA_CHAIN),
        "btc_mainnet" => Some(BITCOIN_CHAIN),
        _ => diamond(network).and(wallet_flow::evm_network(network)).map(|n| n.chain_id),
    }
}

/// Le nœud du réseau sait-il simuler (`eth_simulateV1`, relevé le 02/10/2026) ?
pub fn simulates(network: &str) -> bool {
    !matches!(network, "avax_mainnet" | "hyperevm_mainnet")
}

fn is_evm(network: &str) -> bool {
    diamond(network).is_some()
}

/// Identifiant de carte de la monnaie native d'un réseau EVM.
fn native_coin(network: &wallet_flow::EvmNetwork) -> &'static str {
    match network.native_symbol {
        "ETH" => "evm",
        "BNB" => "bnb",
        "AVAX" => "avax",
        "POL" => "pol",
        "HYPE" => "hype",
        _ => "",
    }
}

/// Crypto de l'app telle que LI.FI la désigne.
#[derive(Clone, Debug, PartialEq)]
pub struct LifiToken {
    pub chain: u64,
    /// Adresse du contrat (EVM), mint (Solana), ou identifiant LI.FI de la
    /// monnaie native (`0x00…00`, `11111111111111111111111111111111`,
    /// `bitcoin`).
    pub address: String,
    pub decimals: u8,
    pub symbol: &'static str,
    pub native: bool,
}

pub fn token(coin: &str, network: &str) -> Option<LifiToken> {
    let chain = chain_id(network)?;
    if let Some((info, deployment)) = tokens::find(coin, network) {
        let address = match deployment.kind {
            tokens::TokenKind::Erc20 { contract } if is_evm(network) => contract,
            tokens::TokenKind::Spl { mint } if network == "sol_mainnet" => mint,
            _ => return None,
        };
        return Some(LifiToken { chain, address: address.to_string(), decimals: deployment.decimals, symbol: info.symbol, native: false });
    }
    let (address, decimals, symbol) = match (coin, network) {
        ("sol", "sol_mainnet") => ("11111111111111111111111111111111", 9, "SOL"),
        ("btc", "btc_mainnet") => ("bitcoin", 8, "BTC"),
        _ => {
            let net = wallet_flow::evm_network(network)?;
            if native_coin(net) != coin {
                return None;
            }
            ("0x0000000000000000000000000000000000000000", 18, net.native_symbol)
        }
    };
    Some(LifiToken { chain, address: address.to_string(), decimals, symbol, native: true })
}

/// Toutes les cryptos de l'app que LI.FI sait désigner (identifiant, réseau).
pub fn tradable() -> Vec<(&'static str, &'static str)> {
    let natives = wallet_flow::EVM_NETWORKS
        .iter()
        .filter(|n| is_evm(n.id) && !native_coin(n).is_empty())
        .map(|n| (native_coin(n), n.id))
        .chain([("sol", "sol_mainnet"), ("btc", "btc_mainnet")]);
    let registry = tokens::TOKENS.iter().flat_map(|t| {
        t.deployments.iter().filter(|d| token(t.id, d.network).is_some()).map(move |d| (t.id, d.network))
    });
    natives.chain(registry).collect()
}

/// LI.FI relie-t-il ces deux cryptos (hors activation) ? Entre deux réseaux
/// différents seulement (un même réseau passe par CoW ou Jupiter) ; jamais
/// depuis Bitcoin (PSBT fournie par LI.FI, pas prise en charge) ; depuis un
/// réseau qui ne simule pas, seulement vers un réseau EVM (destinataire lu
/// dans les données de l'appel).
pub fn links(from: (&str, &str), to: (&str, &str)) -> bool {
    let ((from_coin, from_network), (to_coin, to_network)) = (from, to);
    from_network != to_network
        && from_network != "btc_mainnet"
        && (simulates(from_network) || is_evm(to_network))
        && token(from_coin, from_network).is_some()
        && token(to_coin, to_network).is_some()
}

/// Transaction fournie par LI.FI, à vérifier avant signature.
#[derive(Clone, Debug)]
pub enum LifiTx {
    Evm { to: [u8; 20], data: Vec<u8>, value: u128 },
    /// Transaction Solana sérialisée (un seul signataire : l'utilisateur).
    Solana { raw: Vec<u8> },
}

/// Devis LI.FI revérifié.
#[derive(Clone, Debug)]
pub struct LifiQuote {
    pub from_network: &'static str,
    pub to_network: &'static str,
    pub from: LifiToken,
    pub to: LifiToken,
    pub from_amount: u128,
    pub to_amount: u128,
    pub to_amount_min: u128,
    pub from_address: String,
    pub to_address: String,
    /// Pont choisi par LI.FI (clé technique, et nom affiché).
    pub tool: String,
    pub tool_name: String,
    pub duration_secs: u64,
    pub tx: LifiTx,
}

fn same_address(a: &str, b: &str, evm: bool) -> bool {
    if evm {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn amount_field(value: &Value, field: &str) -> Result<u128> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("devis LI.FI sans « {field} » exploitable"))
}

fn hex_u128(value: Option<&Value>) -> Result<u128> {
    let s = value.and_then(Value::as_str).unwrap_or("0x0");
    u128::from_str_radix(s.trim_start_matches("0x"), 16).context("montant hexadécimal LI.FI illisible")
}

/// Devis LI.FI pour envoyer `amount` (unités) de `from` (sur `from_network`,
/// depuis `from_address`) vers `to` sur `to_network`, livré à `to_address`.
/// `deny` : ponts à écarter ; `allow` : seul pont permis (nouveau devis sur le
/// pont déjà affiché). La réponse est revérifiée (chaînes, jetons, montant,
/// adresses, contrat appelé) avant d'être utilisée.
#[allow(clippy::too_many_arguments)]
pub fn quote(
    from_network: &'static str,
    from: &LifiToken,
    to_network: &'static str,
    to: &LifiToken,
    amount: u128,
    from_address: &str,
    to_address: &str,
    deny: &[String],
    allow: Option<&str>,
) -> Result<LifiQuote> {
    let mut params: Vec<(&str, String)> = vec![
        ("fromChain", from.chain.to_string()),
        ("toChain", to.chain.to_string()),
        ("fromToken", from.address.clone()),
        ("toToken", to.address.clone()),
        ("fromAmount", amount.to_string()),
        ("fromAddress", from_address.to_string()),
        ("toAddress", to_address.to_string()),
        ("slippage", SLIPPAGE.to_string()),
        // Pas d'appel de contrat à l'arrivée : le destinataire émis au départ
        // est alors bien celui qui reçoit.
        ("allowDestinationCall", "false".to_string()),
    ];
    if let Some(integrator) = INTEGRATOR {
        params.push(("integrator", integrator.to_string()));
        if FEE > 0.0 {
            params.push(("fee", FEE.to_string()));
        }
    }
    if !deny.is_empty() {
        params.push(("denyBridges", deny.join(",")));
    }
    if let Some(bridge) = allow {
        params.push(("allowBridges", bridge.to_string()));
    }
    let response = shared_client().get(format!("{API_BASE}/quote")).query(&params).send().context("requête de devis LI.FI impossible")?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!("limite de devis LI.FI atteinte (75 toutes les 2 heures sans compte) — réessayez plus tard");
    }
    let q: Value = response.json().context("réponse de devis LI.FI illisible")?;
    if q.get("transactionRequest").is_none() {
        let message = q.get("message").and_then(Value::as_str).unwrap_or("réponse inattendue");
        bail!("devis LI.FI refusé : {message}");
    }
    parse_quote(&q, from_network, from, to_network, to, amount, from_address, to_address)
}

#[allow(clippy::too_many_arguments)]
fn parse_quote(
    q: &Value,
    from_network: &'static str,
    from: &LifiToken,
    to_network: &'static str,
    to: &LifiToken,
    amount: u128,
    from_address: &str,
    to_address: &str,
) -> Result<LifiQuote> {
    let action = q.get("action").context("devis LI.FI sans action")?;
    let estimate = q.get("estimate").context("devis LI.FI sans estimation")?;
    let (from_evm, to_evm) = (is_evm(from_network), is_evm(to_network));
    let text = |v: &Value, path: &[&str]| -> String {
        let mut cur = v;
        for key in path {
            cur = &cur[*key];
        }
        cur.as_str().unwrap_or_default().to_string()
    };
    ensure!(action["fromChainId"].as_u64() == Some(from.chain) && action["toChainId"].as_u64() == Some(to.chain), "devis LI.FI pour d'autres réseaux");
    ensure!(same_address(&text(action, &["fromToken", "address"]), &from.address, from_evm), "devis LI.FI pour un autre jeton envoyé");
    ensure!(same_address(&text(action, &["toToken", "address"]), &to.address, to_evm), "devis LI.FI pour un autre jeton reçu");
    ensure!(amount_field(action, "fromAmount")? == amount, "devis LI.FI pour un autre montant");
    ensure!(same_address(&text(action, &["fromAddress"]), from_address, from_evm), "devis LI.FI pour un autre expéditeur");
    ensure!(same_address(&text(action, &["toAddress"]), to_address, to_evm), "devis LI.FI pour un autre destinataire");
    if let Some(integrator) = INTEGRATOR {
        ensure!(q["integrator"].as_str() == Some(integrator), "devis LI.FI pour un autre intégrateur");
    }
    let (to_amount, to_amount_min) = (amount_field(estimate, "toAmount")?, amount_field(estimate, "toAmountMin")?);
    ensure!(to_amount_min > 0 && to_amount_min <= to_amount, "devis LI.FI incohérent (minimum)");

    let request = &q["transactionRequest"];
    let tx = if from_evm {
        let diamond = diamond(from_network).context("réseau sans contrat LI.FI")?;
        ensure!(text(request, &["to"]).eq_ignore_ascii_case(diamond), "devis LI.FI vers un autre contrat que celui de LI.FI — refusé");
        if let Some(chain) = request.get("chainId").and_then(Value::as_u64) {
            ensure!(chain == from.chain, "transaction LI.FI pour un autre réseau");
        }
        let value = hex_u128(request.get("value"))?;
        ensure!(value == if from.native { amount } else { 0 }, "transaction LI.FI avec un montant natif inattendu");
        if !from.native {
            ensure!(text(estimate, &["approvalAddress"]).eq_ignore_ascii_case(diamond), "autorisation LI.FI demandée pour un autre contrat — refusé");
        }
        let data = hex::decode(text(request, &["data"]).trim_start_matches("0x")).context("données de transaction LI.FI illisibles")?;
        ensure!(data.len() >= 4, "transaction LI.FI vide");
        LifiTx::Evm { to: wallet_flow::parse_evm_address(diamond)?, data, value }
    } else if from_network == "sol_mainnet" {
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text(request, &["data"])).context("transaction LI.FI Solana illisible")?;
        LifiTx::Solana { raw }
    } else {
        bail!("envoi depuis ce réseau non pris en charge par LI.FI dans l'app");
    };
    Ok(LifiQuote {
        from_network,
        to_network,
        from: from.clone(),
        to: to.clone(),
        from_amount: amount,
        to_amount,
        to_amount_min,
        from_address: from_address.to_string(),
        to_address: to_address.to_string(),
        tool: text(q, &["tool"]),
        tool_name: q["toolDetails"]["name"].as_str().unwrap_or("?").to_string(),
        duration_secs: estimate["executionDuration"].as_f64().unwrap_or(0.0) as u64,
        tx,
    })
}

// --- Décodage ABI (juste ce qu'exige BridgeData) ------------------------------

fn word(data: &[u8], offset: usize) -> Result<&[u8]> {
    data.get(offset..offset + 32).ok_or_else(|| anyhow!("données LI.FI tronquées"))
}

fn word_usize(data: &[u8], offset: usize) -> Result<usize> {
    let w = word(data, offset)?;
    ensure!(w[..24].iter().all(|b| *b == 0), "décalage ABI hors limites");
    Ok(u64::from_be_bytes(w[24..].try_into().expect("8 octets")) as usize)
}

fn word_u128(data: &[u8], offset: usize) -> Result<u128> {
    let w = word(data, offset)?;
    ensure!(w[..16].iter().all(|b| *b == 0), "montant ABI hors limites");
    Ok(u128::from_be_bytes(w[16..].try_into().expect("16 octets")))
}

fn word_address(data: &[u8], offset: usize) -> Result<[u8; 20]> {
    let w = word(data, offset)?;
    ensure!(w[..12].iter().all(|b| *b == 0), "adresse ABI invalide");
    Ok(w[12..].try_into().expect("20 octets"))
}

fn word_bool(data: &[u8], offset: usize) -> Result<bool> {
    match word_u128(data, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("booléen ABI invalide"),
    }
}

fn abi_bytes(data: &[u8], offset: usize) -> Result<&[u8]> {
    let len = word_usize(data, offset)?;
    data.get(offset + 32..offset + 32 + len).ok_or_else(|| anyhow!("données LI.FI tronquées"))
}

/// Structure `ILiFi.BridgeData` du contrat LI.FI.
#[derive(Clone, Debug, PartialEq)]
pub struct BridgeData {
    pub transaction_id: [u8; 32],
    pub bridge: String,
    pub integrator: String,
    pub sending_asset: [u8; 20],
    pub receiver: [u8; 20],
    pub min_amount: u128,
    pub destination_chain: u64,
    pub has_source_swaps: bool,
    pub has_destination_call: bool,
}

/// `BridgeData` encodée en tête de paramètres ABI (structure dynamique en
/// premier paramètre : un décalage, puis la structure) — forme commune aux
/// arguments de toutes les fonctions de pont du contrat
/// (`startBridgeTokensVia…`, `swapAndStartBridgeTokensVia…`) et aux données de
/// l'événement `LiFiTransferStarted`.
pub fn decode_bridge_data(encoded: &[u8]) -> Result<BridgeData> {
    let start = word_usize(encoded, 0)?;
    let tuple = encoded.get(start..).ok_or_else(|| anyhow!("données LI.FI tronquées"))?;
    let string_at = |index: usize| -> Result<String> {
        let offset = word_usize(tuple, index * 32)?;
        String::from_utf8(abi_bytes(tuple, offset)?.to_vec()).context("texte ABI invalide")
    };
    let destination = word_u128(tuple, 7 * 32)?;
    Ok(BridgeData {
        transaction_id: word(tuple, 0)?.try_into().expect("32 octets"),
        bridge: string_at(1)?,
        integrator: string_at(2)?,
        sending_asset: word_address(tuple, 4 * 32)?,
        receiver: word_address(tuple, 5 * 32)?,
        min_amount: word_u128(tuple, 6 * 32)?,
        destination_chain: u64::try_from(destination).context("chaîne de destination hors limites")?,
        has_source_swaps: word_bool(tuple, 8 * 32)?,
        has_destination_call: word_bool(tuple, 9 * 32)?,
    })
}

/// `BridgeData` d'un appel au contrat LI.FI (sélecteur, puis paramètres).
pub fn decode_call_bridge_data(calldata: &[u8]) -> Result<BridgeData> {
    decode_bridge_data(calldata.get(4..).ok_or_else(|| anyhow!("appel LI.FI vide"))?)
}

// --- Vérification avant signature --------------------------------------------

/// Destinataire attendu, sous la forme où le contrat LI.FI l'émet.
#[derive(Clone, Debug, PartialEq)]
pub enum Receiver {
    Evm([u8; 20]),
    /// Clé publique Solana.
    Solana([u8; 32]),
    /// Adresse Bitcoin : texte, et pour une adresse native SegWit v0 de 20
    /// octets (bc1q…), les 32 groupes de 5 bits de son programme témoin —
    /// forme relevée dans l'événement `BridgeToNonEVMChainBytes32`.
    Bitcoin { text: String, five_bit: Option<[u8; 32]> },
}

impl Receiver {
    /// Destinataire saisi pour `network`, vérifié au format du réseau.
    pub fn parse(network: &str, address: &str) -> Result<Self> {
        if is_evm(network) {
            return Ok(Receiver::Evm(wallet_flow::parse_evm_address(address)?));
        }
        match network {
            "sol_mainnet" => {
                let key: [u8; 32] = bs58::decode(address).into_vec().ok().and_then(|v| v.try_into().ok()).context("adresse Solana invalide")?;
                Ok(Receiver::Solana(key))
            }
            "btc_mainnet" => {
                let (hrp, data, _) = bech32::decode(address).context("adresse Bitcoin invalide (bech32 attendu)")?;
                ensure!(hrp == "bc", "adresse Bitcoin du réseau principal attendue (bc1…)");
                let groups: Vec<u8> = data.iter().map(|g| g.to_u8()).collect();
                let five_bit = (groups.first() == Some(&0)).then(|| groups[1..].try_into().ok()).flatten();
                Ok(Receiver::Bitcoin { text: address.to_ascii_lowercase(), five_bit })
            }
            _ => bail!("réseau d'arrivée non pris en charge par LI.FI"),
        }
    }

    fn matches_bytes32(&self, emitted: &[u8; 32]) -> bool {
        match self {
            Receiver::Solana(key) => key == emitted,
            Receiver::Bitcoin { five_bit: Some(groups), .. } => groups == emitted,
            _ => false,
        }
    }

    fn matches_bytes(&self, emitted: &[u8]) -> bool {
        match self {
            Receiver::Solana(key) => emitted == key || emitted == bs58::encode(key).into_string().as_bytes(),
            Receiver::Bitcoin { text, .. } => emitted.eq_ignore_ascii_case(text.as_bytes()),
            Receiver::Evm(_) => false,
        }
    }
}

/// Ce que la transaction doit faire, et rien d'autre.
pub struct Expected<'a> {
    pub user: [u8; 20],
    /// Jeton vendu (`None` : monnaie du réseau, envoyée en valeur).
    pub sell_token: Option<[u8; 20]>,
    pub amount: u128,
    pub diamond: [u8; 20],
    pub destination_chain: u64,
    pub receiver: &'a Receiver,
    pub integrator: Option<&'a str>,
}

/// Issue d'une vérification qui n'a rien trouvé d'anormal.
#[derive(Debug, PartialEq)]
pub enum Verification {
    /// Destinataire émis par le contrat = destinataire affiché.
    Verified,
    /// Le pont garde le destinataire hors chaîne : route à écarter.
    ReceiverHidden { bridge: String },
}

fn topic(signature: &str) -> [u8; 32] {
    evm_sign::keccak(signature.as_bytes())
}

fn padded(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn check_bridge_data(bridge: &BridgeData, expected: &Expected) -> Result<()> {
    ensure!(bridge.destination_chain == expected.destination_chain, "la transaction LI.FI vise un autre réseau d'arrivée — refus de signer");
    ensure!(!bridge.has_destination_call, "la transaction LI.FI appellerait un contrat à l'arrivée (destinataire final invérifiable) — refus de signer");
    if let Some(integrator) = expected.integrator {
        ensure!(bridge.integrator == integrator, "transaction LI.FI d'un autre intégrateur — refus de signer");
    }
    match expected.receiver {
        Receiver::Evm(address) => ensure!(bridge.receiver == *address, "la transaction LI.FI livrerait à une autre adresse que celle affichée — refus de signer"),
        _ => ensure!(bridge.receiver == NON_EVM_RECEIVER, "la transaction LI.FI livrerait à une adresse EVM au lieu de celle affichée — refus de signer"),
    }
    Ok(())
}

/// Destinataire non EVM émis par le contrat : identifiant du transfert,
/// réseau d'arrivée, adresse, et forme (`bytes32` ou octets libres).
type NonEvmReceiver = ([u8; 32], [u8; 32], Vec<u8>, bool);

/// Vérifie la simulation de l'autorisation (s'il y en a une) puis de l'appel
/// LI.FI : tous réussis ; seul le jeton vendu quitte l'utilisateur, pour le
/// montant exact ; autorisations seulement au contrat LI.FI, au plus le
/// montant ; un seul transfert LI.FI, vers le bon réseau, sans appel à
/// l'arrivée ; destinataire émis = destinataire affiché. Fonction pure.
pub fn verify_simulation(calls: &[eth_rpc::SimulatedCall], expected: &Expected) -> Result<Verification> {
    ensure!(calls.iter().all(|c| c.success), "la transaction LI.FI échouerait (simulation) — rien n'a été envoyé");
    let (transfer, approval) = (topic("Transfer(address,address,uint256)"), topic("Approval(address,address,uint256)"));
    let approval_for_all = topic("ApprovalForAll(address,address,bool)");
    let started = topic("LiFiTransferStarted((bytes32,string,string,address,address,address,uint256,uint256,bool,bool))");
    let (non_evm, non_evm_bytes32) = (topic("BridgeToNonEVMChain(bytes32,uint256,bytes)"), topic("BridgeToNonEVMChainBytes32(bytes32,uint256,bytes32)"));
    let user = padded(&expected.user);
    let mut sent: u128 = 0;
    let mut bridges = Vec::new();
    let mut non_evm_receivers: Vec<NonEvmReceiver> = Vec::new();
    for log in calls.iter().flat_map(|c| &c.logs) {
        let Some(kind) = log.topics.first() else { continue };
        // Tout transfert ou toute autorisation AU DÉPART de l'utilisateur : seul
        // le jeton vendu (ERC-20, 3 sujets) est permis — un NFT (ERC-721, 4
        // sujets) ou une autorisation globale (ApprovalForAll) est refusé.
        if (*kind == transfer || *kind == approval || *kind == approval_for_all) && log.topics.get(1) == Some(&user) {
            ensure!(
                *kind != approval_for_all && log.topics.len() == 3,
                "la transaction LI.FI toucherait un autre actif de votre portefeuille (NFT ou autorisation globale) — refus de signer"
            );
            ensure!(
                expected.sell_token == Some(log.address),
                "la transaction LI.FI ferait sortir un autre jeton de votre portefeuille — refus de signer"
            );
            let value = word_u128(&log.data, 0)?;
            if *kind == transfer {
                sent = sent.checked_add(value).context("montant hors limites")?;
            } else {
                ensure!(
                    log.topics[2] == padded(&expected.diamond) && value <= expected.amount,
                    "la transaction LI.FI autoriserait un autre contrat ou un autre montant — refus de signer"
                );
            }
        } else if log.address == expected.diamond && *kind == started {
            bridges.push(decode_bridge_data(&log.data)?);
        } else if log.address == expected.diamond && (*kind == non_evm || *kind == non_evm_bytes32) && log.topics.len() == 3 {
            let receiver = if *kind == non_evm_bytes32 { word(&log.data, 0)?.to_vec() } else { abi_bytes(&log.data, word_usize(&log.data, 0)?)?.to_vec() };
            non_evm_receivers.push((log.topics[1], log.topics[2], receiver, *kind == non_evm_bytes32));
        }
    }
    ensure!(
        sent == if expected.sell_token.is_some() { expected.amount } else { 0 },
        "la transaction LI.FI ferait sortir {sent} unité(s) au lieu de {} — refus de signer",
        expected.amount
    );
    let [bridge] = bridges.as_slice() else { bail!("la transaction LI.FI n'émet pas exactement un transfert — refus de signer") };
    check_bridge_data(bridge, expected)?;
    if matches!(expected.receiver, Receiver::Evm(_)) {
        return Ok(Verification::Verified);
    }
    let chain = {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&expected.destination_chain.to_be_bytes());
        word
    };
    let emitted: Vec<_> = non_evm_receivers.iter().filter(|(id, c, _, _)| *id == bridge.transaction_id && *c == chain).collect();
    if emitted.is_empty() {
        return Ok(Verification::ReceiverHidden { bridge: bridge.bridge.clone() });
    }
    for (_, _, receiver, is_bytes32) in emitted {
        let matches = if *is_bytes32 {
            receiver.as_slice().try_into().is_ok_and(|w: [u8; 32]| expected.receiver.matches_bytes32(&w))
        } else {
            expected.receiver.matches_bytes(receiver)
        };
        ensure!(matches, "la transaction LI.FI livrerait à une autre adresse que celle affichée — refus de signer");
    }
    Ok(Verification::Verified)
}

/// Vérification sans simulation (Avalanche, HyperEVM) : `BridgeData` lue dans
/// l'appel — destination EVM seulement, destinataire = celui affiché, bon
/// réseau, pas d'appel à l'arrivée, jeton envoyé = jeton vendu s'il n'est pas
/// d'abord échangé. Ce qui quitte l'utilisateur reste borné par l'app :
/// autorisation au montant exact, valeur native vérifiée au devis.
pub fn verify_static(calldata: &[u8], expected: &Expected) -> Result<()> {
    ensure!(matches!(expected.receiver, Receiver::Evm(_)), "sur ce réseau, LI.FI n'est proposé que vers un réseau EVM");
    let bridge = decode_call_bridge_data(calldata)?;
    check_bridge_data(&bridge, expected)?;
    if !bridge.has_source_swaps {
        ensure!(bridge.sending_asset == expected.sell_token.unwrap_or([0u8; 20]), "la transaction LI.FI enverrait un autre jeton — refus de signer");
    }
    Ok(())
}

// --- Suivi ---------------------------------------------------------------------

/// État d'un transfert (« NOT_FOUND », « PENDING », « DONE », « FAILED »),
/// suivi du sous-état pour « DONE » (« DONE:COMPLETED », « DONE:REFUNDED »…).
pub fn status(tx_hash: &str, from_chain: u64, to_chain: u64) -> Result<String> {
    // Venu de l'interface et placé dans l'URL : format exact exigé.
    let hash = tx_hash.trim_start_matches("0x");
    ensure!(!hash.is_empty() && hash.len() <= 100 && hash.bytes().all(|b| b.is_ascii_alphanumeric()), "identifiant de transaction invalide");
    let response: Value = shared_client()
        .get(format!("{API_BASE}/status"))
        .query(&[("txHash", tx_hash.to_string()), ("fromChain", from_chain.to_string()), ("toChain", to_chain.to_string())])
        .send()
        .context("suivi LI.FI impossible")?
        .json()
        .context("réponse de suivi LI.FI illisible")?;
    let status = response.get("status").and_then(Value::as_str).unwrap_or("NOT_FOUND");
    Ok(match response.get("substatus").and_then(Value::as_str) {
        Some(sub) if status == "DONE" => format!("DONE:{sub}"),
        _ => status.to_string(),
    })
}

/// Page d'une transaction sur LI.FI Scan.
pub fn explorer_url(tx_hash: &str) -> String {
    format!("https://scan.li.fi/tx/{tx_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_rpc::{SimulatedCall, SimulatedLog};

    /// Appel réel renvoyé par LI.FI le 02/10/2026 (10 LINK Ethereum → RENDER
    /// Solana, pont « relaydepository », `swapAndStartBridgeTokensViaRelayDepository`).
    const REAL_CALLDATA: &str = "0xa3443faa0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000024039c2562bd5b5a02e7a2a86c771b83a11f0ba77c0aca5a3dd2d8d8d664c656f9d00000000000000000000000059d78c44ac60f09369b544778358704b7b18e6ba632d49ef8427b270f90367c38ee0a356c1d20ea4b4f95b78568878e11db5d515000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000011f111f111f111f111f111f111f111f111f111f100000000000000000000000000000000000000000000000000b9be0a563d6e95000000000000000000000000000000000000000000000000000416edef1601be00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f72656c61796465706f7369746f7279000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086c6966692d617069000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000ce40449b773a3e6e5e769adb4e567179d4828cbd000000000000000000000000ce40449b773a3e6e5e769adb4e567179d4828cbd000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a4332d746b000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c06ebbefd94032b85424d51906e2a335efae264b0000000000000000000000000000000000000000000000000058d15e1762800000000000000000000000000000000000000000000000000000000000000000000000000000000000a929c559e5e6537359680f39cb4e3708e1a14dd1000000000000000000000000a929c559e5e6537359680f39cb4e3708e1a14dd1000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000008a6e51a67285800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bf3f0bde25eb7422ec88b9ff78c6f2458ab1a7aa8bb99d84bd4b8600000000000000008a6e51a672858000000000000000000000b9be0a563d6e960622ec88b9ff78c6f2458ab1a7aa8bb99d84bd4b861231deb6f5749ef6ce6943a275a1d3e7486f4eae514910771af9ca656af840dff83e8264ecf986cac02aaa39b223fe8d0a0e5c4f27ead9083c756cc228bf6006d87de7f44445905aa4f5cb8c0d8cba025d4f3c6fa16908609bac31ff148bd002aa6b8c8347050204f928bb9f900301ff00";
    /// Données de `LiFiTransferStarted` encodées par ethers (ABI officielle).
    const EVENT_TO_SOLANA: &str = "00000000000000000000000000000000000000000000000000000000000000201111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000011f111f111f111f111f111f111f111f111f111f10000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000416edef1601be0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000056d6179616e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046f70677000000000000000000000000000000000000000000000000000000000";
    const EVENT_TO_ARBITRUM: &str = "00000000000000000000000000000000000000000000000000000000000000201111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000a4b10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066163726f7373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046f70677000000000000000000000000000000000000000000000000000000000";
    const EVENT_WITH_DESTINATION_CALL: &str = "00000000000000000000000000000000000000000000000000000000000000201111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000011f111f111f111f111f111f111f111f111f111f10000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000416edef1601be0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000056d6179616e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046f70677000000000000000000000000000000000000000000000000000000000";
    /// Données d'un événement `BridgeToNonEVMChain(bytes)` portant une adresse
    /// Bitcoin en texte.
    const BYTES_RECEIVER_EVENT: &str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002a6263317139777a3036756a327534736d76777532716e6c68616c6c6b7966716d6c35346877613030797500000000000000000000000000000000000000000000";
    const LINK: &str = "0x514910771af9ca656af840dff83e8264ecf986ca";
    const DIAMOND: &str = "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE";
    const USER: [u8; 20] = [0x33; 20];
    const AMOUNT: u128 = 10_000_000_000_000_000_000;
    const SOLANA_USER: &str = "4PUcVV4Ax8jXHXsGaRZfh69oRkeRGJyGZbDBPFUD2okm";

    fn addr(s: &str) -> [u8; 20] {
        wallet_flow::parse_evm_address(s).unwrap()
    }

    fn word(v: u128) -> Vec<u8> {
        let mut w = vec![0u8; 16];
        w.extend_from_slice(&v.to_be_bytes());
        w
    }

    fn erc20_log(signature: &str, token: &str, from: [u8; 20], to: [u8; 20], value: u128) -> SimulatedLog {
        SimulatedLog { address: addr(token), topics: vec![topic(signature), padded(&from), padded(&to)], data: word(value) }
    }

    fn started(event_hex: &str) -> SimulatedLog {
        SimulatedLog {
            address: addr(DIAMOND),
            topics: vec![topic("LiFiTransferStarted((bytes32,string,string,address,address,address,uint256,uint256,bool,bool))")],
            data: hex::decode(event_hex).unwrap(),
        }
    }

    fn chain_word(chain: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&chain.to_be_bytes());
        w
    }

    fn non_evm_bytes32(receiver: [u8; 32], chain: u64) -> SimulatedLog {
        SimulatedLog {
            address: addr(DIAMOND),
            topics: vec![topic("BridgeToNonEVMChainBytes32(bytes32,uint256,bytes32)"), [0x11; 32], chain_word(chain)],
            data: receiver.to_vec(),
        }
    }

    fn calls(logs: Vec<SimulatedLog>) -> Vec<SimulatedCall> {
        vec![SimulatedCall { success: true, logs }]
    }

    fn token_flow() -> Vec<SimulatedLog> {
        vec![
            erc20_log("Approval(address,address,uint256)", LINK, USER, addr(DIAMOND), AMOUNT),
            erc20_log("Transfer(address,address,uint256)", LINK, USER, addr(DIAMOND), AMOUNT),
        ]
    }

    fn expected(receiver: &Receiver, destination_chain: u64) -> Expected<'_> {
        Expected { user: USER, sell_token: Some(addr(LINK)), amount: AMOUNT, diamond: addr(DIAMOND), destination_chain, receiver, integrator: Some("opgp") }
    }

    fn solana_receiver() -> Receiver {
        Receiver::parse("sol_mainnet", SOLANA_USER).unwrap()
    }

    /// Décodage de `BridgeData` identique à celui d'ethers sur un appel réel.
    #[test]
    fn bridge_data_matches_the_official_abi_decoding() {
        let bridge = decode_call_bridge_data(&hex::decode(REAL_CALLDATA.trim_start_matches("0x")).unwrap()).unwrap();
        assert_eq!(hex::encode(bridge.transaction_id), "632d49ef8427b270f90367c38ee0a356c1d20ea4b4f95b78568878e11db5d515");
        assert_eq!((bridge.bridge.as_str(), bridge.integrator.as_str()), ("relaydepository", "lifi-api"));
        assert_eq!(bridge.sending_asset, addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"));
        assert_eq!(bridge.receiver, NON_EVM_RECEIVER);
        assert_eq!((bridge.min_amount, bridge.destination_chain), (52_281_822_297_288_341, SOLANA_CHAIN));
        assert!(bridge.has_source_swaps && !bridge.has_destination_call);
    }

    /// Destinataire émis par le contrat = destinataire affiché : vérifié.
    /// Pont qui ne l'émet pas : signalé pour être écarté.
    #[test]
    fn shown_receiver_must_be_emitted_by_the_contract() {
        let receiver = solana_receiver();
        let Receiver::Solana(key) = receiver else { unreachable!() };
        let mut logs = token_flow();
        logs.push(started(EVENT_TO_SOLANA));
        let without_receiver = logs.clone();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert_eq!(verify_simulation(&calls(logs), &expected(&receiver, SOLANA_CHAIN)).unwrap(), Verification::Verified);
        assert_eq!(
            verify_simulation(&calls(without_receiver), &expected(&receiver, SOLANA_CHAIN)).unwrap(),
            Verification::ReceiverHidden { bridge: "mayan".into() }
        );
        let arbitrum = Receiver::Evm([0x22; 20]);
        let mut logs = token_flow();
        logs.push(started(EVENT_TO_ARBITRUM));
        assert_eq!(verify_simulation(&calls(logs), &expected(&arbitrum, 42161)).unwrap(), Verification::Verified);
    }

    /// Chaque détournement est refusé, jamais signalé comme simple pont caché.
    #[test]
    fn diversions_are_refused() {
        let receiver = solana_receiver();
        let Receiver::Solana(key) = receiver else { unreachable!() };
        let run = |logs: Vec<SimulatedLog>, receiver: &Receiver, chain: u64| verify_simulation(&calls(logs), &expected(receiver, chain));
        let base = || {
            let mut logs = token_flow();
            logs.push(started(EVENT_TO_SOLANA));
            logs
        };
        // Autre destinataire émis.
        let mut logs = base();
        logs.push(non_evm_bytes32([0x44; 32], SOLANA_CHAIN));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Un autre jeton quitte l'utilisateur.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(erc20_log("Transfer(address,address,uint256)", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", USER, [0x99; 20], 1));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Autorisation à un autre contrat.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(erc20_log("Approval(address,address,uint256)", LINK, USER, [0x99; 20], AMOUNT));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Plus que le montant.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(erc20_log("Transfer(address,address,uint256)", LINK, USER, [0x99; 20], 1));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Appel de contrat à l'arrivée.
        let mut logs = token_flow();
        logs.push(started(EVENT_WITH_DESTINATION_CALL));
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Autre réseau d'arrivée que celui affiché.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert!(run(logs, &receiver, BITCOIN_CHAIN).is_err());
        // Deux transferts LI.FI.
        let mut logs = base();
        logs.push(started(EVENT_TO_SOLANA));
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Destination EVM : autre adresse.
        let mut logs = token_flow();
        logs.push(started(EVENT_TO_ARBITRUM));
        assert!(run(logs, &Receiver::Evm([0x55; 20]), 42161).is_err());
        // NFT (ERC-721 : 4 sujets) ou autorisation globale au départ de l'utilisateur.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        let mut nft = erc20_log("Transfer(address,address,uint256)", LINK, USER, [0x99; 20], 0);
        nft.topics.push([0x01; 32]);
        logs.push(nft);
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(SimulatedLog { address: [0x77; 20], topics: vec![topic("ApprovalForAll(address,address,bool)"), padded(&USER), padded(&[0x99; 20])], data: word(1) });
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Appel qui échouerait.
        let failed = vec![SimulatedCall { success: false, logs: vec![] }];
        assert!(verify_simulation(&failed, &expected(&receiver, SOLANA_CHAIN)).is_err());
    }

    /// Adresse Bitcoin : forme 5 bits (relevée dans un vrai événement
    /// Layerswap le 02/10/2026) et forme texte.
    #[test]
    fn bitcoin_receiver_forms() {
        let receiver = Receiver::parse("btc_mainnet", "bc1q9wz06uj2u4smvwu2qnlhallkyfqml54hwa00yu").unwrap();
        let emitted: [u8; 32] = hex::decode("050e020f1a1c120a1c15101b0c0e1c0a00131f171d1f1f160409001b1f141517").unwrap().try_into().unwrap();
        assert!(receiver.matches_bytes32(&emitted));
        let data = hex::decode(BYTES_RECEIVER_EVENT).unwrap();
        assert!(receiver.matches_bytes(abi_bytes(&data, 0x20).unwrap()));
        assert!(Receiver::parse("btc_mainnet", "tb1q9wz06uj2u4smvwu2qnlhallkyfqml54hwa00yu").is_err(), "réseau de test refusé");
        assert!(Receiver::parse("sol_mainnet", "0x2222222222222222222222222222222222222222").is_err());
    }

    /// Sans simulation : destinataire lu dans l'appel, destination EVM seulement.
    #[test]
    fn static_check_reads_the_receiver_from_the_call() {
        let mut call = vec![0xde, 0xad, 0xbe, 0xef];
        call.extend(hex::decode(EVENT_TO_ARBITRUM).unwrap());
        let arbitrum = Receiver::Evm([0x22; 20]);
        assert!(verify_static(&call, &expected(&arbitrum, 42161)).is_ok());
        assert!(verify_static(&call, &expected(&Receiver::Evm([0x55; 20]), 42161)).is_err());
        assert!(verify_static(&call, &expected(&arbitrum, 8453)).is_err());
        let real = hex::decode(REAL_CALLDATA.trim_start_matches("0x")).unwrap();
        assert!(verify_static(&real, &expected(&solana_receiver(), SOLANA_CHAIN)).is_err(), "vers Solana : simulation exigée");
    }

    #[test]
    fn tokens_networks_and_contracts() {
        let hype = token("hype", "hyperevm_mainnet").unwrap();
        assert!(hype.native && hype.chain == 999 && hype.symbol == "HYPE");
        assert_eq!(token("render", "sol_mainnet").unwrap().address, "rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof");
        assert_eq!(token("sol", "sol_mainnet").unwrap().address, "11111111111111111111111111111111");
        assert_eq!(token("btc", "btc_mainnet").unwrap().address, "bitcoin");
        assert_eq!(token("evm", "arbitrum_mainnet").unwrap().chain, 42161);
        assert!(token("evm", "evm_sepolia").is_none());
        assert_ne!(diamond("hyperevm_mainnet"), diamond("evm_mainnet"));
        assert!(!simulates("avax_mainnet") && simulates("bsc_mainnet"));
        let all = tradable();
        assert!(all.contains(&("hype", "hyperevm_mainnet")) && all.contains(&("render", "sol_mainnet")) && all.contains(&("btc", "btc_mainnet")));
    }

    fn to_network_of(address: &str) -> &'static str {
        if address.starts_with("0x") {
            "arbitrum_mainnet"
        } else {
            "sol_mainnet"
        }
    }

    /// Devis réels (réseau, lecture seule) dans chaque sens pris en charge.
    #[test]
    #[ignore]
    fn real_quotes() {
        let evm_user = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        for (from, to, amount, from_address, to_address) in [
            (("render", "sol_mainnet"), ("link", "evm_mainnet"), 5_000_000_000u128, SOLANA_USER, evm_user),
            (("link", "evm_mainnet"), ("render", "sol_mainnet"), AMOUNT, evm_user, SOLANA_USER),
            (("evm", "evm_mainnet"), ("btc", "btc_mainnet"), 100_000_000_000_000_000, evm_user, "bc1q9wz06uj2u4smvwu2qnlhallkyfqml54hwa00yu"),
            (("hype", "hyperevm_mainnet"), ("usdc", "arbitrum_mainnet"), 10_000_000_000_000_000_000, evm_user, evm_user),
        ] {
            let (f, t) = (token(from.0, from.1).unwrap(), token(to.0, to.1).unwrap());
            let q = quote(from.1, &f, to.1, &t, amount, from_address, to_address, &[], None).unwrap();
            println!("{from:?} → {to:?} : pont {} ({}), attendu {} minimum {} en ~{} s", q.tool_name, q.tool, q.to_amount, q.to_amount_min, q.duration_secs);
            match q.tx {
                LifiTx::Evm { to, ref data, .. } => {
                    assert_eq!(Some(to), diamond(from.1).map(addr));
                    let bridge = decode_call_bridge_data(data).unwrap();
                    if diamond(to_network_of(to_address)).is_some() {
                        assert_eq!(bridge.receiver, addr(to_address), "vers un réseau EVM, destinataire lu dans l'appel");
                    }
                }
                LifiTx::Solana { ref raw } => assert!(!raw.is_empty()),
            }
        }
    }

    /// Simulation réelle depuis une adresse publique qui détient du LINK
    /// (lecture seule) : « relaydepository » cache le destinataire, Mayan
    /// émet exactement l'adresse Solana affichée.
    #[test]
    #[ignore]
    fn real_simulation_flags_hidden_receivers() {
        let holder = "0x28C6c06298d514Db089934071355E5743bf21d60";
        let (link, render) = (token("link", "evm_mainnet").unwrap(), token("render", "sol_mainnet").unwrap());
        let receiver = solana_receiver();
        let rpc = crate::eth_rpc::EthRpc::new(wallet_flow::evm_network("evm_mainnet").unwrap().rpc);
        for (bridge, want_verified) in [("relaydepository", false), ("mayan", true)] {
            let q = quote("evm_mainnet", &link, "sol_mainnet", &render, AMOUNT, holder, SOLANA_USER, &[], Some(bridge)).unwrap();
            let LifiTx::Evm { to, ref data, value } = q.tx else { panic!("EVM attendu") };
            let approve = crate::api::erc20_approve_data(&to, AMOUNT);
            let diamond_str = format!("0x{}", hex::encode(to));
            let sim = rpc
                .simulate_v1(&[
                    crate::eth_rpc::SimCallRequest { from: holder, to: LINK, value: 0, data: &approve },
                    crate::eth_rpc::SimCallRequest { from: holder, to: &diamond_str, value, data },
                ])
                .unwrap();
            let exp = Expected { user: addr(holder), sell_token: Some(addr(LINK)), amount: AMOUNT, diamond: to, destination_chain: SOLANA_CHAIN, receiver: &receiver, integrator: INTEGRATOR };
            let outcome = verify_simulation(&sim, &exp).unwrap();
            println!("{bridge} : {outcome:?}");
            assert_eq!(outcome == Verification::Verified, want_verified, "{bridge}");
        }
    }
}
