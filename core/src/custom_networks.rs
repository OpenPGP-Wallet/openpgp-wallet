//! Ethereum-compatible networks added by the user ("custom RPC"): an EVM chain the
//! app does not include (Optimism, Linea...), identified by its RPC, its chain ID
//! and the symbol of its coin. Same address as ETH (same key), same signing
//! (EIP-155: the chain ID is signed, so a transaction cannot be replayed on another
//! network).
//!
//! The app cannot check anything else about such a network: its RPC decides which
//! balances and fees it reports. Hence:
//! - the chain ID is checked with the RPC when the network is added;
//! - the IDs of the app's own networks are refused (no "fake Ethereum");
//! - never a dollar price (the symbol says nothing about value);
//! - the confirmation dialog says "network added by you".
//!
//! Stored in the device's `custom_networks.json` file (nothing secret), loaded at
//! startup into a registry that `wallet_flow::evm_network` consults after the app's
//! own networks.

use crate::wallet_flow::{EvmNetwork, EVM_NETWORKS};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::RwLock;

const FILE: &str = "custom_networks.json";
/// At most 20 added networks.
const MAX_NETWORKS: usize = 20;
/// Largest chain ID (an exact integer on the interface side).
const MAX_CHAIN_ID: u64 = (1 << 53) - 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CustomNetwork {
    pub chain_id: u64,
    pub name: String,
    pub rpc: String,
    pub symbol: String,
    /// Explorer (root, without a trailing "/"): `/tx/...` and `/address/...` links.
    pub explorer: Option<String>,
}

impl CustomNetwork {
    /// Identifier in the app (cards, commands): `custom_<chain>_mainnet`, treated
    /// everywhere as real funds.
    pub fn id(&self) -> String {
        id(self.chain_id)
    }
}

pub fn id(chain_id: u64) -> String {
    format!("custom_{chain_id}_mainnet")
}

#[derive(Serialize, Deserialize, Default)]
struct Data {
    networks: Vec<CustomNetwork>,
}

fn load_file(data_dir: &Path) -> Data {
    std::fs::read_to_string(data_dir.join(FILE)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_file(data_dir: &Path, data: &Data) -> Result<()> {
    let content = serde_json::to_string_pretty(data).context("enregistrement des réseaux ajoutés")?;
    std::fs::write(data_dir.join(FILE), content).context("enregistrement des réseaux ajoutés")
}

/// Added networks, valid ones only (a file edited by hand cannot bring in anything
/// that would not have been accepted when adding, apart from the online check).
pub fn list(data_dir: &Path) -> Vec<CustomNetwork> {
    let mut seen = std::collections::HashSet::new();
    load_file(data_dir)
        .networks
        .into_iter()
        .filter_map(|n| validate(n.chain_id, &n.name, &n.rpc, &n.symbol, n.explorer.as_deref()).ok())
        .filter(|n| seen.insert(n.chain_id))
        .take(MAX_NETWORKS)
        .collect()
}

/// Checks and normalizes an entered network, without any network call.
pub fn validate(chain_id: u64, name: &str, rpc: &str, symbol: &str, explorer: Option<&str>) -> Result<CustomNetwork> {
    let name = name.trim();
    ensure!(
        (1..=30).contains(&name.chars().count()) && name.chars().all(|c| c.is_alphanumeric() || " -_.()".contains(c)),
        "nom du réseau : 1 à 30 caractères (lettres, chiffres, espaces, - _ . ( ))"
    );
    let symbol = symbol.trim();
    ensure!(
        (1..=10).contains(&symbol.len()) && symbol.bytes().all(|b| b.is_ascii_alphanumeric()),
        "symbole : 1 à 10 lettres ou chiffres (ex. ETH)"
    );
    ensure!((1..=MAX_CHAIN_ID).contains(&chain_id), "identifiant de chaîne invalide");
    if let Some(builtin) = EVM_NETWORKS.iter().find(|n| n.chain_id == chain_id) {
        bail!("ce réseau est déjà dans l'app ({}, identifiant de chaîne {chain_id})", builtin.name);
    }
    let rpc = normalize_url(rpc, true).map_err(|e| anyhow!("adresse du RPC : {e}"))?;
    let explorer = match explorer.map(str::trim).filter(|e| !e.is_empty()) {
        Some(url) => Some(normalize_url(url, false).map_err(|e| anyhow!("adresse de l'explorateur : {e}"))?),
        None => None,
    };
    Ok(CustomNetwork { chain_id, name: name.to_string(), rpc, symbol: symbol.to_string(), explorer })
}

/// `https://` (or `http://` for a local or LAN node only: in the clear over the
/// Internet, a middleman could show fake balances); no credentials and no fragment.
/// The path is kept for an RPC (often `.../v2/<key>`); for an explorer: the root,
/// without a query or a trailing "/".
fn normalize_url(url: &str, rpc: bool) -> Result<String> {
    let url = url.trim();
    ensure!(!url.is_empty() && url.len() <= 300 && !url.chars().any(|c| c.is_whitespace() || c.is_control()), "https://… attendu");
    let parsed = reqwest::Url::parse(url).map_err(|_| anyhow!("https://… attendu"))?;
    let host = parsed.host_str().filter(|h| !h.is_empty()).ok_or_else(|| anyhow!("hôte manquant"))?;
    ensure!(parsed.username().is_empty() && parsed.password().is_none(), "identifiants dans l'adresse refusés");
    ensure!(parsed.fragment().is_none(), "« # » refusé");
    match parsed.scheme() {
        "https" => {}
        "http" => ensure!(rpc && is_local_host(host), "https:// obligatoire (http:// seulement pour un nœud local)"),
        _ => bail!("https://… attendu"),
    }
    if rpc {
        Ok(parsed.to_string())
    } else {
        ensure!(parsed.query().is_none(), "« ? » refusé");
        Ok(parsed.to_string().trim_end_matches('/').to_string())
    }
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Adds a network: checks, then the chain ID is requested from the RPC (it has to
/// answer, and for that very chain).
pub fn add(data_dir: &Path, chain_id: u64, name: &str, rpc: &str, symbol: &str, explorer: Option<&str>) -> Result<CustomNetwork> {
    let network = validate(chain_id, name, rpc, symbol, explorer)?;
    let mut data = Data { networks: list(data_dir) };
    ensure!(!data.networks.iter().any(|n| n.chain_id == chain_id), "réseau déjà ajouté (identifiant de chaîne {chain_id})");
    ensure!(data.networks.len() < MAX_NETWORKS, "{MAX_NETWORKS} réseaux ajoutés au plus");
    let answered = crate::eth_rpc::EthRpc::new(&network.rpc).chain_id().map_err(|e| anyhow!("RPC injoignable ou invalide : {e:#}"))?;
    ensure!(answered == chain_id, "ce RPC répond pour un autre réseau (identifiant de chaîne {answered} au lieu de {chain_id})");
    data.networks.push(network.clone());
    save_file(data_dir, &data)?;
    load(data_dir);
    Ok(network)
}

pub fn remove(data_dir: &Path, chain_id: u64) -> Result<()> {
    let mut data = Data { networks: list(data_dir) };
    let before = data.networks.len();
    data.networks.retain(|n| n.chain_id != chain_id);
    ensure!(data.networks.len() < before, "réseau ajouté introuvable (identifiant de chaîne {chain_id})");
    save_file(data_dir, &data)?;
    load(data_dir);
    Ok(())
}

/// Added networks in the form the rest of the app uses them (`EvmNetwork`, static
/// lifetime: a removed network stays valid for an operation already under way).
static REGISTRY: RwLock<Vec<&'static EvmNetwork>> = RwLock::new(Vec::new());

/// (Re)loads the registry from the device's file (startup, add, remove).
pub fn load(data_dir: &Path) {
    let networks = list(data_dir);
    let mut registry = REGISTRY.write().unwrap_or_else(|p| p.into_inner());
    let previous = std::mem::take(&mut *registry);
    *registry = networks
        .iter()
        .map(|n| previous.iter().copied().find(|known| same(known, n)).unwrap_or_else(|| Box::leak(Box::new(to_evm_network(n)))))
        .collect();
}

pub fn find(id: &str) -> Option<&'static EvmNetwork> {
    REGISTRY.read().unwrap_or_else(|p| p.into_inner()).iter().copied().find(|n| n.id == id)
}

/// Explorers of the added networks (links allowed to open).
pub fn explorer_origins() -> Vec<&'static str> {
    REGISTRY.read().unwrap_or_else(|p| p.into_inner()).iter().filter(|n| !n.explorer_tx_prefix.is_empty()).map(|n| n.explorer_tx_prefix).collect()
}

fn same(known: &EvmNetwork, n: &CustomNetwork) -> bool {
    known.chain_id == n.chain_id && known.name == n.name && known.rpc == n.rpc && known.native_symbol == n.symbol && known.explorer_tx_prefix == explorer_tx_prefix(n)
}

fn explorer_tx_prefix(n: &CustomNetwork) -> String {
    n.explorer.as_ref().map(|e| format!("{e}/tx/")).unwrap_or_default()
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn to_evm_network(n: &CustomNetwork) -> EvmNetwork {
    EvmNetwork {
        id: leak(n.id()),
        name: leak(n.name.clone()),
        rpc: leak(n.rpc.clone()),
        chain_id: n.chain_id,
        label: leak(format!("{} (réseau ajouté)", n.name)),
        explorer_tx_prefix: leak(explorer_tx_prefix(n)),
        native_symbol: leak(n.symbol.clone()),
        // Treated as real funds (warnings, confirmations).
        mainnet: true,
        // Usual prices on the chain are unknown: no cap; the exact fee is in the
        // confirmation dialog.
        max_gas_price_wei: None,
        // Gas limit estimated by the node (+20%, capped): correct on any compatible chain,
        // including those that count publishing to another chain as gas.
        transfer_gas: None,
        op_stack_l1_fee: false,
        history: None,
        custom: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_custom_networks_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn entries_are_checked_and_normalized() {
        let n = validate(10, " OP Mainnet ", "https://mainnet.optimism.io", "ETH", Some("https://optimistic.etherscan.io/")).unwrap();
        assert_eq!(n.name, "OP Mainnet");
        assert_eq!(n.rpc, "https://mainnet.optimism.io/");
        assert_eq!(n.explorer.as_deref(), Some("https://optimistic.etherscan.io"));
        assert_eq!(n.id(), "custom_10_mainnet");
        // Path (a provider's API key) kept for an RPC.
        assert_eq!(validate(59144, "Linea", "https://linea-mainnet.infura.io/v3/abc123", "ETH", None).unwrap().rpc, "https://linea-mainnet.infura.io/v3/abc123");
        // Local node over http.
        assert!(validate(31337, "Local", "http://127.0.0.1:8545", "ETH", None).is_ok());
        assert!(validate(31337, "Local", "http://192.168.1.20:8545", "ETH", None).is_ok());
        for (rpc, why) in [
            ("http://rpc.example.com", "http distant"),
            ("ftp://rpc.example.com", "schéma"),
            ("https://user:pass@rpc.example.com", "identifiants"),
            ("https://rpc.example.com/#x", "fragment"),
            ("rpc.example.com", "sans schéma"),
            ("https://rpc.example.com/a b", "espace"),
        ] {
            assert!(validate(10, "OP", rpc, "ETH", None).is_err(), "{why}");
        }
        assert!(validate(10, "OP", "https://rpc.example.com", "ETH", Some("http://explorer.example.com")).is_err(), "explorateur en http");
        assert!(validate(10, "OP", "https://rpc.example.com", "ETH", Some("https://explorer.example.com/?q=1")).is_err(), "explorateur avec requête");
        assert!(validate(10, "", "https://rpc.example.com", "ETH", None).is_err(), "nom vide");
        assert!(validate(10, "OP<script>", "https://rpc.example.com", "ETH", None).is_err(), "nom avec < >");
        assert!(validate(10, "OP", "https://rpc.example.com", "E TH", None).is_err(), "symbole avec espace");
        assert!(validate(10, "OP", "https://rpc.example.com", "ABCDEFGHIJK", None).is_err(), "symbole trop long");
        assert!(validate(0, "OP", "https://rpc.example.com", "ETH", None).is_err(), "chaîne 0");
        assert!(validate(1 << 53, "OP", "https://rpc.example.com", "ETH", None).is_err(), "chaîne trop grande");
    }

    /// The app's networks cannot be "added" a second time with another RPC (fake
    /// Ethereum, fake BNB Chain...).
    #[test]
    fn app_networks_cannot_be_added_again() {
        for net in EVM_NETWORKS {
            let err = validate(net.chain_id, "Copie", "https://rpc.example.com", "ETH", None).unwrap_err().to_string();
            assert!(err.contains("déjà dans l'app"), "{}: {err}", net.id);
        }
    }

    /// Registry: a network from the file is found by its ID, with the cautious settings
    /// (real funds, no cap or fixed limit, no price), then disappears once removed; a
    /// tampered file only brings in valid networks, without duplicates.
    #[test]
    fn registry_follows_the_file() {
        let dir = temp_dir("registry");
        let networks = vec![
            CustomNetwork { chain_id: 777_001, name: "Test A".into(), rpc: "https://a.example.com/".into(), symbol: "TA".into(), explorer: Some("https://scan.example.com".into()) },
            CustomNetwork { chain_id: 777_001, name: "Doublon".into(), rpc: "https://b.example.com/".into(), symbol: "TB".into(), explorer: None },
            CustomNetwork { chain_id: 1, name: "Faux Ethereum".into(), rpc: "https://evil.example.com/".into(), symbol: "ETH".into(), explorer: None },
            CustomNetwork { chain_id: 777_002, name: "Test C".into(), rpc: "http://evil.example.com/".into(), symbol: "TC".into(), explorer: None },
        ];
        save_file(&dir, &Data { networks }).unwrap();
        load(&dir);
        assert_eq!(list(&dir).len(), 1);
        let net = crate::wallet_flow::evm_network("custom_777001_mainnet").expect("trouvé par evm_network");
        assert!(net.custom && net.mainnet && net.max_gas_price_wei.is_none() && net.transfer_gas.is_none() && net.history.is_none());
        assert_eq!((net.chain_id, net.name, net.native_symbol, net.explorer_tx_prefix), (777_001, "Test A", "TA", "https://scan.example.com/tx/"));
        assert_eq!(net.explorer_address_url("0xabc", None), "https://scan.example.com/address/0xabc");
        assert!(explorer_origins().contains(&"https://scan.example.com/tx/"));
        assert!(find("custom_777002_mainnet").is_none(), "RPC distant en http refusé");
        // Identical reload: the same network (no new copy).
        load(&dir);
        assert!(std::ptr::eq(net, crate::wallet_flow::evm_network("custom_777001_mainnet").unwrap()));
        remove(&dir, 777_001).unwrap();
        assert!(crate::wallet_flow::evm_network("custom_777001_mainnet").is_none());
        assert!(remove(&dir, 777_001).is_err());
        std::fs::write(dir.join(FILE), "{pas du json").unwrap();
        assert!(list(&dir).is_empty());
    }

    /// Real network: adding OP Mainnet through its public RPC (chain ID checked), and
    /// refusing an RPC that answers for another chain.
    /// `cargo test -p openpgp-wallet-core --lib -- --ignored real_custom_network`
    #[test]
    #[ignore]
    fn real_custom_network() {
        let dir = temp_dir("real");
        let added = add(&dir, 10, "OP Mainnet", "https://mainnet.optimism.io", "ETH", Some("https://optimistic.etherscan.io")).unwrap();
        assert_eq!(added.id(), "custom_10_mainnet");
        let net = find("custom_10_mainnet").unwrap();
        let balance = crate::eth_rpc::EthRpc::new(net.rpc).balance("0x4200000000000000000000000000000000000006").unwrap();
        println!("OP Mainnet : solde de WETH9 (contrat) = {balance} wei");
        let err = add(&dir, 8_453_777, "Faux", "https://mainnet.optimism.io", "ETH", None).unwrap_err().to_string();
        assert!(err.contains("autre réseau"), "{err}");
        remove(&dir, 10).unwrap();
    }
}
