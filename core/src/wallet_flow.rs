//! "Derive a key from a seed, then use a real wallet (receive/send) on
//! testnet/devnet/mainnet" flows, shared by the standalone demos (the wallet_demo*
//! examples, throwaway entropy) and by the Shamir+PGP restore in the shamir_pgp_cli
//! example (rebuilt seed). This module neither generates nor protects the seed: it
//! always receives a ready-made seed and keeps no copy of it beyond the call.

use crate::btc_rpc::EsploraClient;
use crate::btc_tx::BtcTx;
use crate::derivation;
use crate::eth_rpc::EthRpc;
use crate::eth_tx::EthTx;
use crate::sol_rpc::SolRpc;
use crate::sol_tx;
use anyhow::{anyhow, Context, Result};
use std::io::{self, Write};

/// Broadcast without a clear answer (timeout, response cut off or unreadable): the
/// transaction may have gone out. Never shown as refused or as a plain outage:
/// sending again could pay a second time (next nonce or sequence, other UTXOs).
/// Audit round 31.
pub const MAYBE_SENT_PREFIX: &str = "connexion perdue pendant l'envoi : la transaction ";
pub const MAYBE_SENT_SUFFIX: &str =
    " est peut-être partie — vérifiez l'historique avant de renvoyer";

pub fn maybe_sent(id: &str) -> anyhow::Error {
    anyhow!("{MAYBE_SENT_PREFIX}{id}{MAYBE_SENT_SUFFIX}")
}

/// Nothing could have gone out: the connection was never even established.
pub fn nothing_sent(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_builder()
}

/// Network failure while broadcasting to a single server: the original error if
/// nothing could have gone out, `maybe_sent` otherwise.
pub fn broadcast_failure(error: reqwest::Error, context: &'static str, id: &str) -> anyhow::Error {
    if nothing_sent(&error) {
        anyhow::Error::new(error).context(context)
    } else {
        maybe_sent(id)
    }
}

/// HTTP server error in response to a broadcast: the transaction may have been
/// relayed before the error (gateway, timeout), except for 503, service closed.
pub fn server_error_may_have_sent(status: reqwest::StatusCode) -> bool {
    status.is_server_error() && status != reqwest::StatusCode::SERVICE_UNAVAILABLE
}

pub fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// EVM network parameters: the functions in this module are network-agnostic, so
/// "mainnet" is never hard-coded in a test path; the caller chooses mainnet/testnet
/// explicitly. All these networks share the SAME address (same key, same format);
/// each has its own chain ID (EIP-155: a signature is only valid for that chain)
/// and its own fee currency.
pub struct EvmNetwork {
    /// Identifier used by the UI and in files ("evm_mainnet", "bsc_mainnet"…).
    /// "evm_mainnet"/"evm_sepolia" are kept for Ethereum (address book, external
    /// wallets already saved).
    pub id: &'static str,
    /// Short display name (confirmation dialogs, menus): "Arbitrum One"…
    pub name: &'static str,
    pub rpc: &'static str,
    pub chain_id: u64,
    pub label: &'static str,
    pub explorer_tx_prefix: &'static str,
    /// Native currency that pays the fees (ETH, BNB, AVAX…), 18 decimals.
    pub native_symbol: &'static str,
    /// Real funds (`false`: test network).
    pub mainnet: bool,
    /// Safety cap on the gas price announced by the node: above it, the send is refused
    /// rather than trusting the node (`None`: test network). Far above each network's
    /// usual prices.
    pub max_gas_price_wei: Option<u128>,
    /// Gas for a simple native transfer: 21,000 on most networks; `None` (Arbitrum):
    /// estimated by the node, since the cost of posting to Ethereum is counted in gas
    /// there.
    pub transfer_gas: Option<u64>,
    /// Ethereum posting fees charged ON TOP of gas (OP Stack networks, such as Base),
    /// read from the network's oracle contract.
    pub op_stack_l1_fee: bool,
    /// Source of the transaction history; `None`: no source, so the app links to the
    /// network's explorer instead.
    pub history: Option<EvmHistory>,
    /// Network added by the user (custom RPC, see `custom_networks`): never a dollar
    /// price (its symbol says nothing about its value), and flagged in the confirmation
    /// dialog.
    pub custom: bool,
}

/// Source of an EVM address's history (keyless, except NodeReal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmHistory {
    /// Blockscout instance (API v2).
    Blockscout(&'static str),
    /// Routescan's Etherscan-compatible API, by chain ID (Avalanche C-Chain).
    Routescan,
    /// NodeReal, with the key embedded in the app (see `nodereal`): BNB Chain, which no
    /// keyless public service covers.
    NodeReal,
    /// Alchemy, with the key embedded in the app (see `alchemy`): Base and Polygon,
    /// whose Blockscout instances are blocked and reserved for the paid plans of its
    /// official API (as of 2026-10-10).
    Alchemy,
}

impl EvmNetwork {
    /// Page for an address (or, with `token`, for its movements of that token) on the
    /// network's explorer. Every explorer in the app follows the same pattern as its
    /// transaction links (`/tx/` → `/address/`, `/token/`).
    pub fn explorer_address_url(&self, address: &str, token: Option<&str>) -> String {
        let root = self.explorer_tx_prefix.trim_end_matches("tx/");
        match token {
            Some(contract) => format!("{root}token/{contract}?a={address}"),
            None => format!("{root}address/{address}"),
        }
    }
}

const GWEI: u128 = 1_000_000_000;

pub const SEPOLIA: EvmNetwork = EvmNetwork {
    id: "evm_sepolia",
    name: "Ethereum Sepolia",
    rpc: "https://ethereum-sepolia-rpc.publicnode.com",
    chain_id: 11155111,
    label: "Sepolia (testnet — aucune valeur réelle)",
    explorer_tx_prefix: "https://sepolia.etherscan.io/tx/",
    native_symbol: "ETH",
    mainnet: false,
    max_gas_price_wei: None,
    transfer_gas: Some(21_000),
    op_stack_l1_fee: false,
    history: Some(EvmHistory::Blockscout("https://eth-sepolia.blockscout.com")),
    custom: false,
};

pub const ETHEREUM_MAINNET: EvmNetwork = EvmNetwork {
    id: "evm_mainnet",
    name: "Ethereum",
    rpc: "https://ethereum-rpc.publicnode.com",
    chain_id: 1,
    label: "Ethereum MAINNET — FONDS RÉELS",
    explorer_tx_prefix: "https://etherscan.io/tx/",
    native_symbol: "ETH",
    mainnet: true,
    // Found during the "known hot wallet weaknesses" audit (fee manipulation by an RPC
    // node): the gas price was read from the node AFTER confirmation, never shown and
    // never capped. A compromised node announcing 100,000 gwei would have charged 2.1
    // ETH in fees for a simple transfer. 200 gwei leaves a huge margin over real
    // prices.
    max_gas_price_wei: Some(200 * GWEI),
    transfer_gas: Some(21_000),
    op_stack_l1_fee: false,
    history: Some(EvmHistory::Blockscout("https://eth.blockscout.com")),
    custom: false,
};

pub const ARBITRUM_MAINNET: EvmNetwork = EvmNetwork {
    id: "arbitrum_mainnet",
    name: "Arbitrum One",
    rpc: "https://arbitrum-one-rpc.publicnode.com",
    chain_id: 42161,
    label: "Arbitrum One — FONDS RÉELS",
    explorer_tx_prefix: "https://arbiscan.io/tx/",
    native_symbol: "ETH",
    mainnet: true,
    max_gas_price_wei: Some(10 * GWEI),
    transfer_gas: None,
    op_stack_l1_fee: false,
    history: Some(EvmHistory::Blockscout("https://arbitrum.blockscout.com")),
    custom: false,
};

pub const BASE_MAINNET: EvmNetwork = EvmNetwork {
    id: "base_mainnet",
    name: "Base",
    rpc: "https://base-rpc.publicnode.com",
    chain_id: 8453,
    label: "Base — FONDS RÉELS",
    explorer_tx_prefix: "https://basescan.org/tx/",
    native_symbol: "ETH",
    mainnet: true,
    max_gas_price_wei: Some(10 * GWEI),
    transfer_gas: Some(21_000),
    op_stack_l1_fee: true,
    history: Some(EvmHistory::Alchemy),
    custom: false,
};

pub const BSC_MAINNET: EvmNetwork = EvmNetwork {
    id: "bsc_mainnet",
    name: "BNB Smart Chain",
    rpc: "https://bsc-rpc.publicnode.com",
    chain_id: 56,
    label: "BNB Smart Chain — FONDS RÉELS",
    explorer_tx_prefix: "https://bscscan.com/tx/",
    native_symbol: "BNB",
    mainnet: true,
    max_gas_price_wei: Some(100 * GWEI),
    transfer_gas: Some(21_000),
    op_stack_l1_fee: false,
    history: Some(EvmHistory::NodeReal),
    custom: false,
};

pub const AVALANCHE_MAINNET: EvmNetwork = EvmNetwork {
    id: "avax_mainnet",
    name: "Avalanche C-Chain",
    rpc: "https://avalanche-c-chain-rpc.publicnode.com",
    chain_id: 43114,
    label: "Avalanche C-Chain — FONDS RÉELS",
    explorer_tx_prefix: "https://snowtrace.io/tx/",
    native_symbol: "AVAX",
    mainnet: true,
    max_gas_price_wei: Some(1_000 * GWEI),
    transfer_gas: Some(21_000),
    op_stack_l1_fee: false,
    history: Some(EvmHistory::Routescan),
    custom: false,
};

pub const POLYGON_MAINNET: EvmNetwork = EvmNetwork {
    id: "polygon_mainnet",
    name: "Polygon PoS",
    rpc: "https://polygon-bor-rpc.publicnode.com",
    chain_id: 137,
    label: "Polygon PoS — FONDS RÉELS",
    explorer_tx_prefix: "https://polygonscan.com/tx/",
    native_symbol: "POL",
    mainnet: true,
    // Spikes of several thousand gwei measured during congestion.
    max_gas_price_wei: Some(10_000 * GWEI),
    transfer_gas: Some(21_000),
    op_stack_l1_fee: false,
    history: Some(EvmHistory::Alchemy),
    custom: false,
};

/// Every EVM network the app knows.
pub const EVM_NETWORKS: &[&EvmNetwork] = &[
    &ETHEREUM_MAINNET,
    &SEPOLIA,
    &ARBITRUM_MAINNET,
    &BASE_MAINNET,
    &BSC_MAINNET,
    &AVALANCHE_MAINNET,
    &POLYGON_MAINNET,
];

/// EVM network by its identifier ("evm_mainnet", "bsc_mainnet"…): one of the app's
/// networks, or one added by the user (`custom_networks`).
pub fn evm_network(id: &str) -> Option<&'static EvmNetwork> {
    EVM_NETWORKS
        .iter()
        .copied()
        .find(|n| n.id == id)
        .or_else(|| crate::custom_networks::find(id))
}

/// Derives profile `index`'s Bitcoin key from the seed: (signing key, hash160).
pub type DeriveBtcKey = fn(&[u8], u32) -> Result<(k256::ecdsa::SigningKey, [u8; 20])>;

/// Bitcoin network parameters, same idea as EvmNetwork/SolNetwork, except that
/// Bitcoin mainnet and testnet use DIFFERENT ADDRESSES for the same index (separate
/// derivation paths and bech32 prefixes, see `derivation.rs`), unlike EVM/Solana
/// where the same address works on every variant of the network. Hence the function
/// pointers: `send_btc`/`get_btc_balance`/etc. stay network-agnostic without each
/// needing its own `match`.
pub struct BtcNetwork {
    pub esplora_base: &'static str,
    pub label: &'static str,
    pub explorer_tx_prefix: &'static str,
    pub derive_key: DeriveBtcKey,
    pub format_address: fn(&[u8; 20]) -> Result<String>,
    /// The wallet's address (P2WPKH) as a hash160.
    pub parse_address: fn(&str) -> Result<[u8; 20]>,
    /// Destination address, of any standard type, as an output script.
    pub recipient_script: fn(&str) -> Result<Vec<u8>>,
    pub testnet: bool,
}

pub const BTC_MAINNET: BtcNetwork = BtcNetwork {
    esplora_base: crate::btc_rpc::ESPLORA_MAINNET_BASE,
    label: "Bitcoin MAINNET — FONDS RÉELS",
    explorer_tx_prefix: "https://blockstream.info/tx/",
    derive_key: derivation::derive_btc_mainnet_key,
    format_address: derivation::format_btc_mainnet_address,
    parse_address: derivation::parse_btc_mainnet_address,
    recipient_script: derivation::btc_mainnet_recipient_script,
    testnet: false,
};

pub const BTC_TESTNET: BtcNetwork = BtcNetwork {
    esplora_base: crate::btc_rpc::ESPLORA_TESTNET_BASE,
    label: "Bitcoin testnet",
    explorer_tx_prefix: "https://blockstream.info/testnet/tx/",
    derive_key: derivation::derive_btc_testnet_key,
    format_address: derivation::format_btc_testnet_address,
    parse_address: derivation::parse_btc_testnet_address,
    recipient_script: derivation::btc_testnet_recipient_script,
    testnet: true,
};

/// Fixed fee, generous for Bitcoin testnet (avoids a dynamic estimate).
const BTC_FEE_SAT: u64 = 500;
/// Below this threshold, BTC change goes to the fee rather than creating a "dust"
/// output the network could reject as non-standard.
const BTC_DUST_THRESHOLD_SAT: u64 = 1_000;
/// Solana network base fee for a single-signature transaction.
const SOL_FEE_LAMPORTS: u64 = 5_000;

/// Solana network parameters, same idea as EvmNetwork: mainnet is never hard-coded
/// in a test path.
pub struct SolNetwork {
    pub rpc: &'static str,
    pub label: &'static str,
    pub explorer_tx_prefix: &'static str,
    /// Suffix added after the signature in the explorer link (e.g. "?cluster=devnet").
    pub explorer_tx_suffix: &'static str,
    /// The RPC airdrop (`requestAirdrop`) only exists on devnet/testnet, never on mainnet.
    pub supports_airdrop: bool,
}

pub const SOLANA_DEVNET: SolNetwork = SolNetwork {
    rpc: "https://api.devnet.solana.com",
    label: "Solana devnet (aucune valeur réelle)",
    explorer_tx_prefix: "https://explorer.solana.com/tx/",
    explorer_tx_suffix: "?cluster=devnet",
    supports_airdrop: true,
};

pub const SOLANA_MAINNET: SolNetwork = SolNetwork {
    rpc: "https://api.mainnet-beta.solana.com",
    label: "Solana MAINNET — FONDS RÉELS",
    explorer_tx_prefix: "https://explorer.solana.com/tx/",
    explorer_tx_suffix: "", // mainnet is the explorer's default cluster
    supports_airdrop: false,
};

fn read_menu_choice() -> Result<String> {
    println!("1. Vérifier le solde (recevoir)");
    println!("2. Envoyer un virement");
    println!("3. Quitter");
    prompt("Choix : ")
}

// Refusal of an EVM address, in plain words (no "hex" or "bytes"); translated by
// the app.
pub const EVM_ADDRESS_NOT_RECOGNIZED: &str =
    "adresse non reconnue : sur ce réseau, une adresse s'écrit 0x suivi de 40 caractères";
pub const EVM_ADDRESS_WRONG_LENGTH: &str = "adresse incomplète ou trop longue : sur ce réseau, une adresse s'écrit 0x suivi de 40 caractères";
pub const EVM_ADDRESS_MISCOPIED: &str = "adresse mal recopiée : un caractère ne correspond pas (majuscules et minuscules comptent) — copiez-la à nouveau";

pub(crate) fn parse_evm_address(input: &str) -> Result<[u8; 20]> {
    let hex_str = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(hex_str).context(EVM_ADDRESS_NOT_RECOGNIZED)?;
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| anyhow!(EVM_ADDRESS_WRONG_LENGTH))?;

    // EIP-55: a mixed-case address claims to carry a checksum, so we verify it to
    // catch a typo (corrupted copy-paste, altered character) that would otherwise go
    // unnoticed on an address that is still valid hex, and would send the funds
    // irreversibly to a different address. An all-lowercase or all-uppercase address
    // has no case to check (the legacy format without a checksum, still valid under
    // the standard) and is accepted as is.
    let has_mixed_case = hex_str.chars().any(|c| c.is_ascii_uppercase())
        && hex_str.chars().any(|c| c.is_ascii_lowercase());
    if has_mixed_case {
        let expected = derivation::format_address(&address);
        anyhow::ensure!(format!("0x{hex_str}") == expected, EVM_ADDRESS_MISCOPIED);
    }

    Ok(address)
}

/// Converts a decimal amount in ETH (e.g. "0.01") to wei, without losing precision.
pub(crate) fn parse_eth_to_wei(input: &str) -> Result<u128> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 18 {
        return Err(anyhow!("trop de décimales (18 maximum pour l'ETH)"));
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("partie entière invalide")?
    };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 18 {
        frac_padded.push('0');
    }
    let frac_val: u128 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().context("partie décimale invalide")?
    };
    // Checked arithmetic: in the release profile, an integer overflow wraps around
    // silently instead of panicking (`overflow-checks` is off by default). An absurdly
    // large amount must never turn into a small one.
    whole
        .checked_mul(1_000_000_000_000_000_000u128)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant ETH trop grand (dépassement arithmétique)")
}

/// Derives an EVM key from `seed` and opens a receive/send menu on `network` (see
/// SEPOLIA / ETHEREUM_MAINNET).
pub fn run_evm_wallet(seed: &[u8], network: &EvmNetwork) -> Result<()> {
    let (signing_key, address) = derivation::derive_evm_key(seed, 0)?;
    let address_str = derivation::format_address(&address);

    let rpc = EthRpc::new(network.rpc);
    let chain_id = rpc
        .chain_id()
        .context("impossible de contacter le nœud RPC")?;
    if chain_id != network.chain_id {
        println!(
            "Attention : le nœud RPC répond avec chain_id={chain_id}, attendu {}.",
            network.chain_id
        );
    }

    println!("\n=== Wallet EVM — {} ===", network.label);
    println!("Adresse : {address_str}\n");

    loop {
        match read_menu_choice()?.trim() {
            "1" => {
                let balance = rpc.balance(&address_str)?;
                println!(
                    "Solde actuel : {balance} wei ({:.6} ETH).\n",
                    balance as f64 / 1e18
                );
            }
            "2" => {
                if let Err(e) = send_evm(&rpc, &signing_key, &address_str, chain_id, network) {
                    println!("Échec de l'envoi : {e}\n");
                }
            }
            "3" => break,
            other => println!("Choix invalide : '{other}'.\n"),
        }
    }
    Ok(())
}

fn send_evm(
    rpc: &EthRpc,
    signing_key: &k256::ecdsa::SigningKey,
    address_str: &str,
    chain_id: u64,
    network: &EvmNetwork,
) -> Result<()> {
    let to_str = prompt("Adresse destinataire (0x...) : ")?;
    let to = parse_evm_address(&to_str)?;
    let amount_str = prompt("Montant à envoyer en ETH (ex: 0.001) : ")?;
    let value = parse_eth_to_wei(&amount_str)?;

    let nonce = rpc.nonce(address_str)?;
    let gas_price = rpc.gas_price()?;

    let tx = EthTx {
        nonce,
        gas_price,
        gas_limit: 21_000,
        to,
        value,
        chain_id,
        data: Vec::new(),
    };

    let raw_tx = tx.sign(signing_key)?;
    let tx_hash = rpc.send_raw_transaction(&raw_tx)?;

    println!("\nTransaction diffusée : {tx_hash}");
    println!("Suivi : {}{tx_hash}\n", network.explorer_tx_prefix);
    Ok(())
}

pub(crate) fn parse_btc_to_sat(input: &str) -> Result<u64> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 8 {
        return Err(anyhow!("trop de décimales (8 maximum pour le BTC)"));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("partie entière invalide")?
    };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 8 {
        frac_padded.push('0');
    }
    let frac_val: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().context("partie décimale invalide")?
    };
    whole
        .checked_mul(100_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant BTC trop grand (dépassement arithmétique)")
}

/// Derives a Bitcoin testnet key from `seed` and opens a receive/send menu.
pub fn run_btc_wallet(seed: &[u8]) -> Result<()> {
    let (signing_key, hash160) = derivation::derive_btc_testnet_key(seed, 0)?;
    let address = derivation::format_btc_testnet_address(&hash160)?;

    println!("\n=== Wallet Bitcoin testnet ===");
    println!("Adresse : {address}\n");

    let esplora = EsploraClient::new(crate::btc_rpc::ESPLORA_TESTNET_BASE);

    loop {
        match read_menu_choice()?.trim() {
            "1" => {
                let utxos = esplora.utxos(&address)?;
                let total: u64 = utxos.iter().map(|u| u.value_sat).sum();
                println!(
                    "Solde actuel : {total} sat ({:.8} BTC), {} UTXO(s).\n",
                    total as f64 / 1e8,
                    utxos.len()
                );
            }
            "2" => {
                if let Err(e) = send_btc(&esplora, &signing_key, &address, &hash160) {
                    println!("Échec de l'envoi : {e}\n");
                }
            }
            "3" => break,
            other => println!("Choix invalide : '{other}'.\n"),
        }
    }
    Ok(())
}

fn send_btc(
    esplora: &EsploraClient,
    signing_key: &k256::ecdsa::SigningKey,
    address: &str,
    hash160: &[u8; 20],
) -> Result<()> {
    let utxos = esplora.utxos(address)?;
    let total_sat: u64 = utxos.iter().map(|u| u.value_sat).sum();
    if utxos.is_empty() {
        return Err(anyhow!(
            "aucun UTXO confirmé disponible (vérifie le solde d'abord)"
        ));
    }

    let to_str = prompt("Adresse destinataire testnet (tb1…, m…, n… ou 2…) : ")?;
    let to_script = derivation::btc_testnet_recipient_script(&to_str)?;

    let amount_str = prompt("Montant à envoyer en BTC (ex: 0.0001) : ")?;
    let amount_sat = parse_btc_to_sat(&amount_str)?;

    let total_needed = amount_sat
        .checked_add(BTC_FEE_SAT)
        .context("montant + frais dépasse la capacité représentable")?;
    if total_needed > total_sat {
        return Err(anyhow!(
            "Fonds insuffisants : {total_sat} sat disponibles, {amount_sat} sat + {BTC_FEE_SAT} sat de frais requis"
        ));
    }

    let remaining = total_sat - total_needed;
    let change_sat = if remaining > BTC_DUST_THRESHOLD_SAT {
        remaining
    } else {
        0
    };

    let tx = BtcTx {
        inputs: utxos,
        to_script,
        value_sat: amount_sat,
        change_hash160: *hash160,
        change_sat,
        op_return_data: None,
    };

    let raw_tx = tx.sign(signing_key, hash160)?;
    let txid = esplora.broadcast(&raw_tx)?;

    println!("\nTransaction diffusée : {txid}");
    println!("Suivi : https://blockstream.info/testnet/tx/{txid}\n");
    Ok(())
}

/// Converts a decimal amount in SOL (e.g. "0.01") to lamports (9 decimals).
pub(crate) fn parse_sol_to_lamports(input: &str) -> Result<u64> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 9 {
        return Err(anyhow!("trop de décimales (9 maximum pour le SOL)"));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("partie entière invalide")?
    };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 9 {
        frac_padded.push('0');
    }
    let frac_val: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().context("partie décimale invalide")?
    };
    whole
        .checked_mul(1_000_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant SOL trop grand (dépassement arithmétique)")
}

/// Converts a decimal amount in USDC (e.g. "12.50") to its smallest unit (6
/// decimals, just as ETH has 18 and SOL has 9). Same structure as
/// `parse_sol_to_lamports`/`parse_eth_to_wei`.
pub(crate) fn parse_usdc_to_micros(input: &str) -> Result<u64> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 6 {
        return Err(anyhow!("trop de décimales (6 maximum pour l'USDC)"));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("partie entière invalide")?
    };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 6 {
        frac_padded.push('0');
    }
    let frac_val: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().context("partie décimale invalide")?
    };
    whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant USDC trop grand (dépassement arithmétique)")
}

/// Derives a Solana key from `seed` and opens a receive/send menu on `network` (see
/// SOLANA_DEVNET / SOLANA_MAINNET).
pub fn run_sol_wallet(seed: &[u8], network: &SolNetwork) -> Result<()> {
    let signing_key = derivation::derive_solana_key(seed, 0);
    let from_pubkey = signing_key.verifying_key().to_bytes();
    let address = bs58::encode(from_pubkey).into_string();

    let rpc = SolRpc::new(network.rpc);

    println!("\n=== Wallet Solana — {} ===", network.label);
    println!("Adresse : {address}\n");

    if network.supports_airdrop {
        print!("Tentative d'airdrop automatique (1 SOL devnet)... ");
        io::stdout().flush()?;
        match rpc.request_airdrop(&address, 1_000_000_000) {
            Ok(sig) => println!("demandé (signature {sig}).\n"),
            Err(e) => {
                println!("indisponible.");
                println!("  -> Détail : {e}");
                println!("  -> Utilise https://faucet.solana.com (colle l'adresse ci-dessus) si besoin.\n");
            }
        }
    }

    loop {
        match read_menu_choice()?.trim() {
            "1" => {
                let balance = rpc.balance_lamports(&address)?;
                println!(
                    "Solde actuel : {balance} lamports ({:.9} SOL).\n",
                    balance as f64 / 1e9
                );
            }
            "2" => {
                if let Err(e) = send_sol(&rpc, &signing_key, &from_pubkey, &address, network) {
                    println!("Échec de l'envoi : {e}\n");
                }
            }
            "3" => break,
            other => println!("Choix invalide : '{other}'.\n"),
        }
    }
    Ok(())
}

fn send_sol(
    rpc: &SolRpc,
    signing_key: &ed25519_dalek::SigningKey,
    from_pubkey: &[u8; 32],
    address: &str,
    network: &SolNetwork,
) -> Result<()> {
    let balance = rpc.balance_lamports(address)?;

    let to_str = prompt("Adresse destinataire Solana (base58) : ")?;
    let to_bytes = bs58::decode(to_str.trim())
        .into_vec()
        .context("adresse Solana invalide (base58 attendu)")?;
    let to_pubkey: [u8; 32] = to_bytes
        .try_into()
        .map_err(|_| anyhow!("une adresse Solana fait 32 octets"))?;

    let amount_str = prompt("Montant à envoyer en SOL (ex: 0.01) : ")?;
    let lamports = parse_sol_to_lamports(&amount_str)?;

    let total_needed = lamports
        .checked_add(SOL_FEE_LAMPORTS)
        .context("montant + frais dépasse la capacité représentable")?;
    if total_needed > balance {
        return Err(anyhow!(
            "Fonds insuffisants : {balance} lamports disponibles, {lamports} + ~{SOL_FEE_LAMPORTS} de frais requis"
        ));
    }

    let recent_blockhash = rpc.latest_blockhash()?;
    let raw_tx = sol_tx::build_transfer_transaction(
        signing_key,
        from_pubkey,
        &to_pubkey,
        lamports,
        &recent_blockhash,
    );

    let signature = rpc.send_transaction(&raw_tx)?;

    println!("\nTransaction envoyée : {signature}");
    println!(
        "Suivi : {}{signature}{}\n",
        network.explorer_tx_prefix, network.explorer_tx_suffix
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CHECKSUM: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    #[test]
    fn parse_evm_address_accepts_a_correct_eip55_checksum() {
        assert!(parse_evm_address(VALID_CHECKSUM).is_ok());
    }

    #[test]
    fn parse_evm_address_rejects_a_single_flipped_case_character() {
        // A single character with its case flipped compared with the expected checksum
        // ("a" at position 2 becomes "A"): simulates a typo or a bad copy-paste.
        let corrupted = "0x5Aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(parse_evm_address(corrupted).is_err());
    }

    #[test]
    fn parse_evm_address_accepts_all_lowercase_without_checksum() {
        // Legacy format without a checksum (no mixed case): still valid.
        assert!(parse_evm_address(&VALID_CHECKSUM.to_lowercase()).is_ok());
    }

    #[test]
    fn parse_evm_address_accepts_all_uppercase_without_checksum() {
        let all_upper = format!(
            "0x{}",
            VALID_CHECKSUM.trim_start_matches("0x").to_uppercase()
        );
        assert!(parse_evm_address(&all_upper).is_ok());
    }

    #[test]
    fn parse_usdc_to_micros_handles_exact_six_decimals() {
        assert_eq!(parse_usdc_to_micros("12.500000").unwrap(), 12_500_000);
        assert_eq!(parse_usdc_to_micros("0.000001").unwrap(), 1);
        assert_eq!(parse_usdc_to_micros("100").unwrap(), 100_000_000);
    }

    #[test]
    fn parse_usdc_to_micros_rejects_more_than_six_decimals() {
        assert!(parse_usdc_to_micros("1.1234567").is_err());
    }

    #[test]
    fn parse_usdc_to_micros_rejects_overflow_instead_of_wrapping() {
        assert!(parse_usdc_to_micros(&u64::MAX.to_string()).is_err());
    }
}
