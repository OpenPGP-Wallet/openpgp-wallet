//! Demandes de signature venues de dApps (WalletConnect) : analyse, validation
//! et PRÉPARATION — tout ce qui sera signé, et tout ce qui sera affiché dans la
//! boîte de confirmation native, est calculé ici, une seule fois, à partir de
//! la demande telle que reçue du relais (jamais d'une copie venue du frontend).
//!
//! C'est la surface d'attaque n°1 d'un portefeuille connecté à des sites web
//! (autorisations de dépense illimitées, signatures "permit", transactions
//! opaques) : chaque demande est soit comprise et affichée en clair, soit
//! présentée explicitement comme une signature à l'aveugle, soit refusée.
//! Aucune signature ici : voir `api::sign_dapp_request` (mot de passe exigé).

use crate::evm_sign::{self, CallKind, TypedData, U256};
use crate::{api, eth_rpc, jupiter_rpc, sol_rpc, sol_spl, wallet_flow};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::Value;

// --- Réseaux et méthodes pris en charge ---------------------------------------

pub const EVM_MAINNET: &str = "eip155:1";
pub const EVM_SEPOLIA: &str = "eip155:11155111";
/// Identifiants CAIP-2 Solana = 32 premiers caractères du hash de genèse
/// (namespaces.chainagnostic.org, vérifié contre `getGenesisHash` en réel).
pub const SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
pub const SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

pub const SOLANA_CHAINS: [&str; 2] = [SOLANA_MAINNET, SOLANA_DEVNET];

/// Réseau EVM de l'app désigné par un identifiant CAIP-2 « eip155:<chainId> »
/// (forme canonique seulement : « eip155:01 » n'est pas accepté) — tous les
/// réseaux de `wallet_flow::EVM_NETWORKS`, même adresse partout.
fn evm_network_for_chain(chain: &str) -> Option<&'static wallet_flow::EvmNetwork> {
    let chain_id: u64 = chain.strip_prefix("eip155:")?.parse().ok()?;
    if format!("eip155:{chain_id}") != chain {
        return None;
    }
    wallet_flow::EVM_NETWORKS.iter().copied().find(|n| n.chain_id == chain_id)
}

pub fn evm_chain_supported(chain: &str) -> bool {
    evm_network_for_chain(chain).is_some()
}

/// Identifiant CAIP-2 d'un réseau EVM de l'app.
pub fn evm_caip2(network: &wallet_flow::EvmNetwork) -> String {
    format!("eip155:{}", network.chain_id)
}

/// `eth_sign` (signature d'une empreinte brute, à l'aveugle par construction)
/// est volontairement absent : refusé comme méthode non prise en charge.
pub const EVM_METHODS: [&str; 3] = ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4"];
pub const SOLANA_METHODS: [&str; 5] =
    ["solana_signMessage", "solana_signTransaction", "solana_signAndSendTransaction", "solana_getAccounts", "solana_requestAccounts"];
pub const EVM_EVENTS: [&str; 2] = ["accountsChanged", "chainChanged"];

pub enum Network {
    Evm(&'static wallet_flow::EvmNetwork),
    Solana(&'static wallet_flow::SolNetwork),
}

pub fn network_for_chain(chain: &str) -> Option<Network> {
    match chain {
        SOLANA_MAINNET => Some(Network::Solana(&wallet_flow::SOLANA_MAINNET)),
        SOLANA_DEVNET => Some(Network::Solana(&wallet_flow::SOLANA_DEVNET)),
        other => evm_network_for_chain(other).map(Network::Evm),
    }
}

/// Adresses du profil connecté à la session (publiques).
pub struct Account {
    pub evm: String,
    pub solana: String,
}

// --- Ce qui sera affiché -------------------------------------------------------

/// Message à signer, tel qu'il sera montré : texte s'il est lisible, sinon
/// hexadécimal — et les signaux qui justifient un avertissement.
pub struct MessageView {
    pub text: Option<String>,
    pub hex: String,
    /// 32 octets non textuels : a la forme d'une empreinte (hash) — le signer
    /// peut revenir à signer une transaction ou un ordre à l'aveugle.
    pub looks_like_hash: bool,
    /// Domaine annoncé par un message "Sign-In with Ethereum" (EIP-4361), à
    /// comparer au site qui fait la demande (hameçonnage classique).
    pub siwe_domain: Option<String>,
}

fn message_view(bytes: &[u8]) -> MessageView {
    let text = std::str::from_utf8(bytes)
        .ok()
        .filter(|t| !t.is_empty() && t.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t'))
        .map(str::to_string);
    let siwe_domain = text.as_deref().and_then(|t| {
        let (domain, _) = t.split_once(" wants you to sign in with your Ethereum account")?;
        let domain = domain.lines().last()?.trim();
        (!domain.is_empty()).then(|| domain.to_string())
    });
    MessageView { looks_like_hash: text.is_none() && bytes.len() == 32, text, hex: format!("0x{}", hex::encode(bytes)), siwe_domain }
}

pub enum TypedRisk {
    None,
    /// Autorisation de dépense signée hors chaîne (EIP-2612 "Permit", Permit2
    /// d'Uniswap…) : quiconque détient cette signature peut ensuite vider
    /// l'autorisation SANS autre confirmation de l'utilisateur.
    Permit { spender: Option<String>, amount: Option<String>, unlimited: bool },
    /// Ordre de place de marché (Seaport/OpenSea…) : peut céder des NFT ou des
    /// jetons au prix fixé dans le message.
    Order,
}

pub struct TypedDataView {
    pub primary_type: String,
    pub domain_name: Option<String>,
    pub domain_chain_id: Option<u64>,
    pub verifying_contract: Option<String>,
    pub risk: TypedRisk,
    /// Champs du message (chemin, valeur), aplatis dans l'ordre des types —
    /// seuls les champs déclarés sont signés, donc seuls eux sont montrés.
    pub fields: Vec<(String, String)>,
    pub hidden_fields: usize,
}

pub struct TokenInfo {
    pub symbol: Option<String>,
    pub decimals: Option<u8>,
}

/// Variation simulée d'un actif de l'utilisateur (Solana).
pub struct AssetDelta {
    /// "SOL", ou adresse du mint.
    pub asset: String,
    /// Nom connu (USDC) quand il y en a un.
    pub label: Option<&'static str>,
    pub delta: i128,
    pub decimals: Option<u8>,
}

/// Demande prête à signer : ce qui sera signé ET ce qui sera affiché.
pub enum Prepared {
    EvmPersonalSign { network: &'static wallet_flow::EvmNetwork, message: Vec<u8>, view: MessageView },
    EvmTypedData { network: &'static wallet_flow::EvmNetwork, digest: [u8; 32], view: TypedDataView },
    EvmTransaction {
        network: &'static wallet_flow::EvmNetwork,
        to: [u8; 20],
        value: u128,
        data: Vec<u8>,
        gas_limit: u64,
        gas_price: u128,
        /// Réseaux OP Stack (Base) : frais de publication sur Ethereum, en plus
        /// du gas (voir `api::EvmFee`) ; 0 ailleurs.
        l1_fee: u128,
        call: CallKind,
        to_is_contract: bool,
        token: Option<TokenInfo>,
    },
    SolanaMessage { network: &'static wallet_flow::SolNetwork, message: Vec<u8>, view: MessageView },
    SolanaTransaction { network: &'static wallet_flow::SolNetwork, tx: Vec<u8>, send: bool, effects: Vec<AssetDelta> },
}

// --- Préparation -----------------------------------------------------------------

/// Plafond de gas d'une transaction de dApp (ce qui est affiché comme frais
/// MAXIMUM) : très au-delà d'un échange ou d'un dépôt usuels.
pub const DAPP_MAX_GAS_LIMIT: u64 = 2_000_000;

fn same_evm_address(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn hex_quantity(value: Option<&Value>) -> Result<u128> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(v) => evm_sign::parse_uint256(v)?.to_u128().ok_or_else(|| anyhow!("montant trop grand")),
    }
}

fn hex_data(value: Option<&Value>) -> Result<Vec<u8>> {
    match value.and_then(Value::as_str) {
        None => Ok(Vec::new()),
        Some(s) => hex::decode(s.trim_start_matches("0x")).context("données de transaction invalides"),
    }
}

/// `method`/`params`/`chain` : exactement la demande reçue du relais.
pub fn prepare(method: &str, params: &Value, chain: &str, account: &Account) -> Result<Prepared> {
    let network = network_for_chain(chain).ok_or_else(|| anyhow!("réseau non pris en charge : {chain}"))?;
    match (method, network) {
        ("personal_sign", Network::Evm(network)) => {
            let items = params.as_array().ok_or_else(|| anyhow!("personal_sign : paramètres invalides"))?;
            anyhow::ensure!(items.len() >= 2, "personal_sign : paramètres invalides");
            // Ordre normal [message, adresse] ; certaines dApps l'inversent.
            let (message, address) = if items[1].as_str().is_some_and(|a| same_evm_address(a, &account.evm)) {
                (&items[0], &items[1])
            } else {
                (&items[1], &items[0])
            };
            anyhow::ensure!(
                address.as_str().is_some_and(|a| same_evm_address(a, &account.evm)),
                "la dApp demande la signature d'un AUTRE compte que celui connecté — refusé"
            );
            let message = message.as_str().ok_or_else(|| anyhow!("personal_sign : message invalide"))?;
            let bytes = match message.strip_prefix("0x").map(hex::decode) {
                Some(Ok(bytes)) => bytes,
                _ => message.as_bytes().to_vec(),
            };
            let view = message_view(&bytes);
            Ok(Prepared::EvmPersonalSign { network, message: bytes, view })
        }
        ("eth_signTypedData_v4", Network::Evm(network)) => {
            let items = params.as_array().ok_or_else(|| anyhow!("eth_signTypedData_v4 : paramètres invalides"))?;
            anyhow::ensure!(items.len() >= 2, "eth_signTypedData_v4 : paramètres invalides");
            anyhow::ensure!(
                items[0].as_str().is_some_and(|a| same_evm_address(a, &account.evm)),
                "la dApp demande la signature d'un AUTRE compte que celui connecté — refusé"
            );
            let typed = evm_sign::parse_typed_data(&items[1])?;
            let digest = typed.digest()?;
            let view = typed_data_view(&typed);
            if let Some(chain_id) = view.domain_chain_id {
                anyhow::ensure!(
                    chain_id == network.chain_id,
                    "la signature demandée vise le réseau {chain_id}, pas celui de la connexion ({}) — refusé",
                    network.chain_id
                );
            }
            Ok(Prepared::EvmTypedData { network, digest, view })
        }
        ("eth_sendTransaction", Network::Evm(network)) => prepare_evm_transaction(params, network, account),
        ("solana_signMessage", Network::Solana(network)) => {
            let pubkey = params.get("pubkey").and_then(Value::as_str);
            anyhow::ensure!(
                pubkey.is_none_or(|p| p.trim() == account.solana),
                "la dApp demande la signature d'un AUTRE compte que celui connecté — refusé"
            );
            let message = params.get("message").and_then(Value::as_str).ok_or_else(|| anyhow!("solana_signMessage : message absent"))?;
            let bytes = bs58::decode(message).into_vec().context("solana_signMessage : message base58 invalide")?;
            anyhow::ensure!(!bytes.is_empty(), "message vide");
            // Signer un "message" qui est en réalité une transaction sérialisée
            // revient à signer cette transaction — attaque connue sur Solana.
            anyhow::ensure!(
                jupiter_rpc::message_writable_accounts(&bytes).is_err(),
                "ce « message » est en réalité une TRANSACTION Solana déguisée — refusé"
            );
            let view = message_view(&bytes);
            Ok(Prepared::SolanaMessage { network, message: bytes, view })
        }
        ("solana_signTransaction", Network::Solana(network)) => prepare_solana_transaction(params, network, account, false),
        ("solana_signAndSendTransaction", Network::Solana(network)) => prepare_solana_transaction(params, network, account, true),
        (other, _) => bail!("méthode non prise en charge sur ce réseau : {other}"),
    }
}

fn prepare_evm_transaction(params: &Value, network: &'static wallet_flow::EvmNetwork, account: &Account) -> Result<Prepared> {
    let tx = params
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow!("eth_sendTransaction : paramètres invalides"))?;
    let from = tx.get("from").and_then(Value::as_str).unwrap_or(&account.evm);
    anyhow::ensure!(same_evm_address(from, &account.evm), "la dApp demande l'envoi depuis un AUTRE compte que celui connecté — refusé");
    let to_str = tx
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("création de contrat (pas de destinataire) non prise en charge — refusé"))?;
    let to = wallet_flow::parse_evm_address(to_str)?;
    let value = hex_quantity(tx.get("value"))?;
    let data = hex_data(tx.get("data").or_else(|| tx.get("input")))?;
    let to_hex = crate::derivation::format_address(&to);

    // Prix du gas relu ICI (et plafonné sur mainnet), jamais celui proposé par
    // la dApp : même règle "on signe ce qu'on voit" que les envois normaux.
    let gas_price = api::evm_gas_price_for_confirmation(network)?;
    let rpc = eth_rpc::EthRpc::new(network.rpc);
    // Exécution à blanc : une transaction qui échouerait est refusée avant
    // d'être présentée (sinon elle brûlerait des frais pour rien).
    rpc.call_contract(&account.evm, &to_hex, value, &data)
        .map_err(|e| anyhow!("la transaction échouerait si elle était envoyée : {e:#}"))?;
    let estimated = rpc.estimate_gas(&account.evm, &to_hex, value, &data)?;
    let gas_limit = estimated.saturating_mul(12).div_ceil(10).max(crate::eth_tx::intrinsic_gas(&data));
    anyhow::ensure!(
        gas_limit <= DAPP_MAX_GAS_LIMIT,
        "gas estimé anormalement élevé ({gas_limit}, maximum {DAPP_MAX_GAS_LIMIT}) — refusé"
    );
    let l1_fee = api::evm_l1_fee(network, &to, value, &data, gas_price, gas_limit)?;
    let to_is_contract = !rpc.code(&to_hex)?.is_empty();
    let call = evm_sign::decode_call(&data);
    let token = match call {
        CallKind::TokenTransfer { .. } | CallKind::TokenTransferFrom { .. } | CallKind::TokenApprove { .. } | CallKind::IncreaseAllowance { .. } => {
            Some(token_info(&rpc, &account.evm, &to_hex))
        }
        _ => None,
    };
    Ok(Prepared::EvmTransaction { network, to, value, data, gas_limit, gas_price, l1_fee, call, to_is_contract, token })
}

/// Décimales et symbole d'un jeton ERC-20, au mieux (un contrat peut ne pas
/// les exposer, ou mentir : le symbole est du texte libre, affiché nettoyé).
fn token_info(rpc: &eth_rpc::EthRpc, from: &str, token: &str) -> TokenInfo {
    let decimals = rpc
        .call_contract(from, token, 0, &[0x31, 0x3c, 0xe5, 0x67])
        .ok()
        .filter(|r| r.len() == 32 && r[..31].iter().all(|&b| b == 0))
        .map(|r| r[31]);
    let symbol = rpc.call_contract(from, token, 0, &[0x95, 0xd8, 0x9b, 0x41]).ok().and_then(|r| {
        // Chaîne ABI dynamique : décalage (32), longueur (32), octets.
        let len = usize::try_from(U256(r.get(32..64)?.try_into().ok()?).to_u128()?).ok()?;
        let bytes = r.get(64..64 + len.min(32))?;
        String::from_utf8(bytes.to_vec()).ok()
    });
    TokenInfo { symbol, decimals }
}

fn prepare_solana_transaction(
    params: &Value,
    network: &'static wallet_flow::SolNetwork,
    account: &Account,
    send: bool,
) -> Result<Prepared> {
    let encoded = params
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("transaction absente (format déprécié non pris en charge)"))?;
    let tx = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).context("transaction base64 invalide")?;
    let (_, message) = jupiter_rpc::split_single_signer_transaction(&tx)
        .map_err(|_| anyhow!("transaction à plusieurs signataires : non prise en charge — refusée"))?;
    let owner: [u8; 32] = bs58::decode(&account.solana).into_vec()?.try_into().map_err(|_| anyhow!("adresse Solana invalide"))?;
    anyhow::ensure!(
        jupiter_rpc::message_fee_payer(message)? == owner,
        "la transaction n'est pas payée par le compte connecté — refusée"
    );

    // Même mécanique que la vérification des swaps Jupiter : comptes
    // inscriptibles résolus on-chain (tables de correspondance comprises,
    // nonce durable refusé), état avant, simulation SANS signature avec état
    // après, refus structurels (Assign, délégué, cession…), puis bilan affiché.
    let rpc = sol_rpc::SolRpc::new(network.rpc);
    let addresses = api::resolve_writable_addresses(&rpc, &tx)?;
    let pre = rpc.multiple_accounts(&addresses)?;
    let post = match rpc.simulate_with_account_states(&tx, &addresses)? {
        sol_rpc::SimulationOutcome::Failed { err, logs } => {
            return Err(rpc.explain_simulation_failure(&err, &logs).unwrap_or_else(|| anyhow!("la transaction échouerait (simulation, {err}) :\n{logs}")))
        }
        sol_rpc::SimulationOutcome::Succeeded { post_states } => post_states,
    };
    let effects = api::user_effects(&addresses, &pre, &post, &owner)?;
    Ok(Prepared::SolanaTransaction { network, tx, send, effects: describe_effects(&rpc, &effects) })
}

fn describe_effects(rpc: &sol_rpc::SolRpc, effects: &api::UserEffects) -> Vec<AssetDelta> {
    let mut out = vec![AssetDelta {
        asset: "SOL".to_string(),
        label: Some("SOL"),
        delta: effects.lamports_post as i128 - effects.lamports_pre as i128,
        decimals: Some(9),
    }];
    let mut mints: Vec<[u8; 32]> = effects.tokens_pre.keys().chain(effects.tokens_post.keys()).copied().collect();
    mints.sort();
    mints.dedup();
    let mint_addresses: Vec<String> = mints.iter().map(|m| bs58::encode(m).into_string()).collect();
    // Décimales lues dans le compte du mint (octet 44 de la disposition SPL).
    let mint_states = rpc.multiple_accounts(&mint_addresses).unwrap_or_default();
    for (i, mint) in mints.iter().enumerate() {
        let before = effects.tokens_pre.get(mint).copied().unwrap_or(0) as i128;
        let after = effects.tokens_post.get(mint).copied().unwrap_or(0) as i128;
        if before == after {
            continue;
        }
        let decimals = mint_states
            .get(i)
            .and_then(Option::as_ref)
            .filter(|s| s.owner == api::TOKEN_PROGRAM_ID || s.owner == api::TOKEN_2022_PROGRAM_ID)
            .and_then(|s| s.data.get(44).copied());
        out.push(AssetDelta {
            asset: mint_addresses[i].clone(),
            label: (*mint == sol_spl::usdc_mint_mainnet()).then_some("USDC"),
            delta: after - before,
            decimals,
        });
    }
    out
}

// --- Vue des données structurées --------------------------------------------------

const MAX_TYPED_FIELDS: usize = 40;

fn typed_data_view(typed: &TypedData) -> TypedDataView {
    let domain_name = typed.domain.get("name").and_then(Value::as_str).map(str::to_string);
    let verifying_contract = typed.domain.get("verifyingContract").and_then(Value::as_str).map(str::to_string);
    let mut fields = Vec::new();
    let mut hidden = 0;
    if typed.primary_type != "EIP712Domain" {
        flatten(typed, &typed.primary_type, &typed.message, "", &mut fields, &mut hidden, 0);
    }
    TypedDataView {
        primary_type: typed.primary_type.clone(),
        domain_name,
        domain_chain_id: typed.domain_chain_id(),
        verifying_contract,
        risk: typed_risk(typed),
        fields,
        hidden_fields: hidden,
    }
}

fn flatten(typed: &TypedData, kind: &str, value: &Value, path: &str, out: &mut Vec<(String, String)>, hidden: &mut usize, depth: usize) {
    let mut push = |p: String, v: String| {
        if out.len() < MAX_TYPED_FIELDS {
            out.push((p, v));
        } else {
            *hidden += 1;
        }
    };
    if depth > 8 {
        push(path.to_string(), "…".to_string());
        return;
    }
    if let Some(inner) = kind.strip_suffix("[]").or_else(|| kind.rfind('[').map(|i| &kind[..i])) {
        if kind.ends_with(']') {
            for (i, item) in value.as_array().map(Vec::as_slice).unwrap_or(&[]).iter().enumerate() {
                flatten(typed, inner, item, &format!("{path}[{i}]"), out, hidden, depth + 1);
            }
            return;
        }
    }
    if let Some(fields) = typed.types.get(kind) {
        for field in fields {
            let p = if path.is_empty() { field.name.clone() } else { format!("{path}.{}", field.name) };
            flatten(typed, &field.kind, value.get(&field.name).unwrap_or(&Value::Null), &p, out, hidden, depth + 1);
        }
        return;
    }
    let shown = match value {
        Value::String(s) if kind.starts_with("uint") || kind.starts_with("int") => {
            evm_sign::parse_uint256(value).map(|v| v.to_decimal()).unwrap_or_else(|_| s.clone())
        }
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    push(path.to_string(), shown);
}

fn typed_risk(typed: &TypedData) -> TypedRisk {
    let primary = typed.primary_type.as_str();
    if matches!(primary, "Order" | "OrderComponents" | "BulkOrder") {
        return TypedRisk::Order;
    }
    if !primary.to_ascii_lowercase().contains("permit") {
        return TypedRisk::None;
    }
    let m = &typed.message;
    let spender = m.get("spender").and_then(Value::as_str).map(str::to_string);
    // EIP-2612 : `value` ; Permit2 : `details.amount` ou `permitted.amount`,
    // et en lot (`PermitBatch`, `PermitBatchTransferFrom`) des LISTES de
    // montants — une seule illimitée suffit à l'avertissement (33ᵉ passage :
    // les lots n'étaient pas lus).
    let mut amounts: Vec<&Value> = Vec::new();
    amounts.extend(m.get("value"));
    for key in ["details", "permitted"] {
        match m.get(key) {
            Some(Value::Array(items)) => amounts.extend(items.iter().filter_map(|item| item.get("amount"))),
            Some(item) => amounts.extend(item.get("amount")),
            None => {}
        }
    }
    let amounts: Vec<U256> = amounts.into_iter().filter_map(|v| evm_sign::parse_uint256(v).ok()).collect();
    TypedRisk::Permit {
        spender,
        unlimited: amounts.iter().any(|a| a.is_practically_unlimited()),
        amount: (!amounts.is_empty()).then(|| amounts.iter().map(|a| a.to_decimal()).collect::<Vec<_>>().join(" + ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn account() -> Account {
        Account {
            evm: "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23".to_string(),
            solana: "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F".to_string(),
        }
    }

    #[test]
    fn personal_sign_accepts_both_parameter_orders_and_refuses_another_account() {
        let hello = "0x48656c6c6f";
        for params in [json!([hello, account().evm]), json!([account().evm.to_lowercase(), hello])] {
            match prepare("personal_sign", &params, EVM_MAINNET, &account()).unwrap() {
                Prepared::EvmPersonalSign { message, view, .. } => {
                    assert_eq!(message, b"Hello");
                    assert_eq!(view.text.as_deref(), Some("Hello"));
                }
                _ => panic!(),
            }
        }
        let other = json!([hello, "0x5555555555555555555555555555555555555555"]);
        assert!(prepare("personal_sign", &other, EVM_MAINNET, &account()).is_err());
    }

    #[test]
    fn message_views_flag_hashes_and_extract_siwe_domains() {
        let hash = message_view(&[0xab; 32]);
        assert!(hash.text.is_none() && hash.looks_like_hash);
        let siwe = message_view(b"app.example.com wants you to sign in with your Ethereum account:\n0x2c75...\n\nURI: https://app.example.com");
        assert_eq!(siwe.siwe_domain.as_deref(), Some("app.example.com"));
        assert!(message_view("texte\u{0007}cloche".as_bytes()).text.is_none(), "caractère de contrôle : montré en hexadécimal");
    }

    fn permit(chain_id: u64, value: &str) -> Value {
        json!(["0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", {
            "domain": {"name": "USD Coin", "version": "2", "chainId": chain_id, "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
            "types": {"Permit": [
                {"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}
            ]},
            "primaryType": "Permit",
            "message": {"owner": "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", "spender": "0x5555555555555555555555555555555555555555", "value": value, "nonce": 0, "deadline": "1893456000"}
        }])
    }

    #[test]
    fn typed_data_permits_are_flagged_and_wrong_chains_refused() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        match prepare("eth_signTypedData_v4", &permit(1, max), EVM_MAINNET, &account()).unwrap() {
            Prepared::EvmTypedData { view, digest, .. } => {
                assert_eq!(hex::encode(digest), "fffcc838333500a1d6462f879368eff7deeecc267930a1ff855464b076981216");
                match view.risk {
                    TypedRisk::Permit { spender, unlimited, .. } => {
                        assert!(unlimited);
                        assert_eq!(spender.as_deref(), Some("0x5555555555555555555555555555555555555555"));
                    }
                    _ => panic!("permit non détecté"),
                }
                assert!(view.fields.iter().any(|(p, v)| p == "value" && v == max));
            }
            _ => panic!(),
        }
        // Signature destinée à un autre réseau que celui de la connexion.
        assert!(prepare("eth_signTypedData_v4", &permit(137, "1"), EVM_MAINNET, &account()).is_err());
        // Pour un autre compte.
        let mut other = permit(1, "1");
        other[0] = json!("0x5555555555555555555555555555555555555555");
        assert!(prepare("eth_signTypedData_v4", &other, EVM_MAINNET, &account()).is_err());
    }

    /// Permit2 en lot : une autorisation illimitée dans la liste est signalée.
    #[test]
    fn batch_permits_are_flagged_unlimited() {
        let max = "1461501637330902918203684832716283019655932542975";
        let batch = |amounts: [&str; 2]| {
            json!(["0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", {
                "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
                "types": {
                    "PermitBatch": [{"name": "details", "type": "PermitDetails[]"}, {"name": "spender", "type": "address"}, {"name": "sigDeadline", "type": "uint256"}],
                    "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"}, {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}]
                },
                "primaryType": "PermitBatch",
                "message": {
                    "details": [
                        {"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "amount": amounts[0], "expiration": "1893456000", "nonce": "0"},
                        {"token": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "amount": amounts[1], "expiration": "1893456000", "nonce": "0"}
                    ],
                    "spender": "0x5555555555555555555555555555555555555555",
                    "sigDeadline": "1893456000"
                }
            }])
        };
        let risk = |amounts| match prepare("eth_signTypedData_v4", &batch(amounts), EVM_MAINNET, &account()).unwrap() {
            Prepared::EvmTypedData { view, .. } => view.risk,
            _ => panic!(),
        };
        match risk(["1000000", max]) {
            TypedRisk::Permit { unlimited, amount, .. } => assert!(unlimited && amount.is_some_and(|a| a.starts_with("1000000 + "))),
            _ => panic!("lot non détecté"),
        }
        assert!(matches!(risk(["1000000", "2000000"]), TypedRisk::Permit { unlimited: false, .. }));
    }

    #[test]
    fn unsupported_methods_and_chains_are_refused() {
        assert!(prepare("eth_sign", &json!([account().evm, "0x00"]), EVM_MAINNET, &account()).is_err());
        assert!(prepare("personal_sign", &json!(["0x00", account().evm]), "eip155:10", &account()).is_err(), "réseau non géré par l'app");
        assert!(prepare("personal_sign", &json!(["0x00", account().evm]), "eip155:01", &account()).is_err(), "forme non canonique");
        assert!(network_for_chain("eip155:8453").is_some() && network_for_chain("eip155:999").is_none(), "HyperEVM retiré");
        assert!(prepare("solana_signMessage", &json!({"message": "2"}), EVM_MAINNET, &account()).is_err());
    }

    /// Réseau réel, lecture seule, rien n'est signé :
    /// - identifiants CAIP-2 Solana = 32 premiers caractères du hash de genèse ;
    /// - `eth_sendTransaction` réel préparé depuis une adresse publique : un
    ///   `approve` USDC ILLIMITÉ, exécuté à blanc sur mainnet, décodé, avec les
    ///   décimales et le symbole lus sur le contrat ;
    /// - `solana_signTransaction` réel : un swap Jupiter construit pour le hot
    ///   wallet public, simulé, bilan des effets calculé.
    /// `cargo test -- --ignored dapp_requests_prepare_real_mainnet_requests --nocapture`
    #[test]
    #[ignore]
    fn dapp_requests_prepare_real_mainnet_requests() {
        for (chain, rpc) in [(SOLANA_MAINNET, wallet_flow::SOLANA_MAINNET.rpc), (SOLANA_DEVNET, wallet_flow::SOLANA_DEVNET.rpc)] {
            let genesis: Value = reqwest::blocking::Client::new()
                .post(rpc)
                .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "getGenesisHash"}))
                .send()
                .unwrap()
                .json()
                .unwrap();
            let genesis = genesis["result"].as_str().unwrap();
            assert_eq!(&chain["solana:".len()..], &genesis[..32], "{chain}");
        }

        let vitalik = Account { evm: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(), solana: String::new() };
        let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let approve = format!("0x095ea7b3{:0>64}{}", "5555555555555555555555555555555555555555", "f".repeat(64));
        let params = json!([{"from": vitalik.evm, "to": usdc, "data": approve, "value": "0x0"}]);
        match prepare("eth_sendTransaction", &params, EVM_MAINNET, &vitalik).unwrap() {
            Prepared::EvmTransaction { call, to_is_contract, token, gas_limit, .. } => {
                assert!(matches!(call, CallKind::TokenApprove { ref amount, .. } if amount.is_practically_unlimited()));
                assert!(to_is_contract);
                let token = token.unwrap();
                assert_eq!(token.decimals, Some(6));
                assert_eq!(token.symbol.as_deref(), Some("USDC"));
                println!("approve USDC : gas limite {gas_limit}");
            }
            _ => panic!(),
        }

        // Même demande sur Base (réseau OP Stack) : réseau de la connexion,
        // contrat USDC de Base, frais de publication sur Ethereum comptés.
        let usdc_base = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
        let params = json!([{"from": vitalik.evm, "to": usdc_base, "data": approve, "value": "0x0"}]);
        match prepare("eth_sendTransaction", &params, "eip155:8453", &vitalik).unwrap() {
            Prepared::EvmTransaction { network, token, l1_fee, gas_limit, .. } => {
                assert_eq!(network.id, "base_mainnet");
                assert_eq!(token.unwrap().symbol.as_deref(), Some("USDC"));
                assert!(l1_fee > 0, "frais de publication sur Ethereum");
                println!("approve USDC sur Base : gas limite {gas_limit}, frais L1 {l1_fee} wei");
            }
            _ => panic!(),
        }

        let binance = Account { evm: String::new(), solana: "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9".to_string() };
        let q = jupiter_rpc::quote(jupiter_rpc::SOL_MINT, &bs58::encode(sol_spl::usdc_mint_mainnet()).into_string(), 100_000_000, 50, None).unwrap();
        let tx = jupiter_rpc::build_swap_transaction(&q, &binance.solana).unwrap();
        let params = json!({"transaction": base64::engine::general_purpose::STANDARD.encode(&tx)});
        match prepare("solana_signTransaction", &params, SOLANA_MAINNET, &binance).unwrap() {
            Prepared::SolanaTransaction { effects, send, .. } => {
                assert!(!send);
                for e in &effects {
                    println!("effet : {} {} (décimales {:?})", e.label.unwrap_or(&e.asset), e.delta, e.decimals);
                }
                let sol = effects.iter().find(|e| e.asset == "SOL").unwrap();
                assert!(sol.delta < -100_000_000 + 1 && sol.delta > -110_000_000, "≈ -0,1 SOL moins les frais : {}", sol.delta);
                let usdc = effects.iter().find(|e| e.label == Some("USDC")).expect("USDC reçu");
                assert!(usdc.delta > 0 && usdc.decimals == Some(6));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn solana_sign_message_refuses_disguised_transactions() {
        // Un vrai message de transaction legacy minimal, passé comme "message".
        let mut tx_message = vec![1, 0, 1, 2];
        tx_message.extend_from_slice(&[7u8; 32]);
        tx_message.extend_from_slice(&[0u8; 32]);
        tx_message.extend_from_slice(&[9u8; 32]);
        tx_message.extend_from_slice(&[1, 1, 1, 0, 4, 2, 0, 0, 0]);
        let params = json!({"message": bs58::encode(&tx_message).into_string(), "pubkey": account().solana});
        let err = prepare("solana_signMessage", &params, SOLANA_MAINNET, &account()).err().expect("refus attendu");
        assert!(err.to_string().contains("TRANSACTION"), "{err}");

        let params = json!({"message": bs58::encode("Connexion à example.com").into_string(), "pubkey": account().solana});
        match prepare("solana_signMessage", &params, SOLANA_MAINNET, &account()).unwrap() {
            Prepared::SolanaMessage { view, .. } => assert_eq!(view.text.as_deref(), Some("Connexion à example.com")),
            _ => panic!(),
        }
        let other = json!({"message": bs58::encode("x").into_string(), "pubkey": "11111111111111111111111111111111"});
        assert!(prepare("solana_signMessage", &other, SOLANA_MAINNET, &account()).is_err());
    }
}
