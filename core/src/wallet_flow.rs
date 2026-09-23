//! Flux d'interaction "dérive une clé depuis une seed puis utilise un vrai wallet
//! (recevoir/envoyer) testnet/devnet/mainnet", partagés entre les démos autonomes
//! (wallet_demo*, entropie jetable) et la restauration Shamir+PGP dans main.rs
//! (seed reconstruite). Ce module ne génère ni ne protège la seed : il reçoit
//! toujours une seed déjà prête et n'en garde aucune copie au-delà de l'appel.

use crate::btc_rpc::EsploraClient;
use crate::btc_tx::BtcTx;
use crate::derivation;
use crate::eth_rpc::EthRpc;
use crate::eth_tx::EthTx;
use crate::sol_rpc::SolRpc;
use crate::sol_tx;
use anyhow::{anyhow, Context, Result};
use std::io::{self, Write};

pub fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Paramètres réseau EVM : les fonctions de ce module sont agnostiques du réseau,
/// pour ne jamais coder en dur "mainnet" dans un chemin de test — le choix
/// mainnet/testnet est fait explicitement par l'appelant.
pub struct EvmNetwork {
    pub rpc: &'static str,
    pub chain_id: u64,
    pub label: &'static str,
    pub explorer_tx_prefix: &'static str,
}

pub const SEPOLIA: EvmNetwork = EvmNetwork {
    rpc: "https://ethereum-sepolia-rpc.publicnode.com",
    chain_id: 11155111,
    label: "Sepolia (testnet — aucune valeur réelle)",
    explorer_tx_prefix: "https://sepolia.etherscan.io/tx/",
};

pub const ETHEREUM_MAINNET: EvmNetwork = EvmNetwork {
    rpc: "https://ethereum-rpc.publicnode.com",
    chain_id: 1,
    label: "Ethereum MAINNET — FONDS RÉELS",
    explorer_tx_prefix: "https://etherscan.io/tx/",
};

/// Paramètres réseau Bitcoin, même logique que EvmNetwork/SolNetwork — sauf que
/// mainnet et testnet Bitcoin utilisent des ADRESSES DIFFÉRENTES pour un même index
/// (chemins de dérivation et préfixes bech32 distincts, voir `derivation.rs`),
/// contrairement à EVM/Solana où la même adresse sert sur toutes les variantes du
/// réseau. D'où les pointeurs de fonction : `send_btc`/`get_btc_balance`/etc.
/// restent agnostiques du réseau sans avoir chacun leur propre `match`.
pub struct BtcNetwork {
    pub esplora_base: &'static str,
    pub label: &'static str,
    pub explorer_tx_prefix: &'static str,
    pub derive_key: fn(&[u8], u32) -> Result<(k256::ecdsa::SigningKey, [u8; 20])>,
    pub format_address: fn(&[u8; 20]) -> Result<String>,
    pub parse_address: fn(&str) -> Result<[u8; 20]>,
}

pub const BTC_MAINNET: BtcNetwork = BtcNetwork {
    esplora_base: crate::btc_rpc::ESPLORA_MAINNET_BASE,
    label: "Bitcoin MAINNET — FONDS RÉELS",
    explorer_tx_prefix: "https://blockstream.info/tx/",
    derive_key: derivation::derive_btc_mainnet_key,
    format_address: derivation::format_btc_mainnet_address,
    parse_address: derivation::parse_btc_mainnet_address,
};

pub const BTC_TESTNET: BtcNetwork = BtcNetwork {
    esplora_base: crate::btc_rpc::ESPLORA_TESTNET_BASE,
    label: "Bitcoin testnet",
    explorer_tx_prefix: "https://blockstream.info/testnet/tx/",
    derive_key: derivation::derive_btc_testnet_key,
    format_address: derivation::format_btc_testnet_address,
    parse_address: derivation::parse_btc_testnet_address,
};

/// Frais fixes, généreux pour Bitcoin testnet (évite une estimation dynamique).
const BTC_FEE_SAT: u64 = 500;
/// En dessous de ce seuil, la monnaie BTC part dans les frais plutôt que de créer
/// une sortie "poussière" que le réseau pourrait rejeter comme non standard.
const BTC_DUST_THRESHOLD_SAT: u64 = 1_000;
/// Frais de base réseau Solana pour une transaction à une signature.
const SOL_FEE_LAMPORTS: u64 = 5_000;

/// Paramètres réseau Solana, même logique que EvmNetwork : jamais de mainnet codé
/// en dur dans un chemin de test.
pub struct SolNetwork {
    pub rpc: &'static str,
    pub label: &'static str,
    pub explorer_tx_prefix: &'static str,
    /// Suffixe ajouté après la signature dans le lien explorateur (ex: "?cluster=devnet").
    pub explorer_tx_suffix: &'static str,
    /// L'airdrop RPC (`requestAirdrop`) n'existe que sur devnet/testnet, jamais sur mainnet.
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
    explorer_tx_suffix: "", // mainnet est le cluster par défaut de l'explorateur
    supports_airdrop: false,
};

fn read_menu_choice() -> Result<String> {
    println!("1. Vérifier le solde (recevoir)");
    println!("2. Envoyer un virement");
    println!("3. Quitter");
    prompt("Choix : ")
}

pub(crate) fn parse_evm_address(input: &str) -> Result<[u8; 20]> {
    let hex_str = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(hex_str).context("adresse invalide (hex attendu)")?;
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| anyhow!("une adresse EVM fait 20 octets (40 caractères hex)"))?;

    // EIP-55 : une adresse en casse mixte prétend porter un checksum — on le vérifie
    // pour détecter une faute de frappe (copier-coller corrompu, caractère modifié)
    // qui resterait sinon invisible sur une adresse par ailleurs valide en hexadécimal
    // et qui enverrait irrémédiablement les fonds vers une adresse différente. Une
    // adresse tout en minuscules ou tout en majuscules n'a pas de casse à vérifier
    // (format historique sans checksum, toujours valide selon la norme) et est
    // acceptée telle quelle.
    let has_mixed_case =
        hex_str.chars().any(|c| c.is_ascii_uppercase()) && hex_str.chars().any(|c| c.is_ascii_lowercase());
    if has_mixed_case {
        let expected = derivation::format_address(&address);
        anyhow::ensure!(
            format!("0x{hex_str}") == expected,
            "checksum EIP-55 invalide : vérifie l'adresse, elle semble mal recopiée"
        );
    }

    Ok(address)
}

/// Convertit un montant décimal en ETH (ex: "0.01") en wei, sans perte de précision.
pub(crate) fn parse_eth_to_wei(input: &str) -> Result<u128> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 18 {
        return Err(anyhow!("trop de décimales (18 maximum pour l'ETH)"));
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().context("partie entière invalide")? };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 18 {
        frac_padded.push('0');
    }
    let frac_val: u128 = if frac_padded.is_empty() { 0 } else { frac_padded.parse().context("partie décimale invalide")? };
    // Arithmétique vérifiée : en profil release, un dépassement d'entier s'enroule
    // silencieusement au lieu de planter (`overflow-checks` désactivé par défaut) —
    // un montant absurdement grand ne doit jamais se transformer en petit montant.
    whole
        .checked_mul(1_000_000_000_000_000_000u128)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant ETH trop grand (dépassement arithmétique)")
}

/// Dérive une clé EVM depuis `seed` et ouvre un menu recevoir/envoyer sur `network`
/// (voir SEPOLIA / ETHEREUM_MAINNET).
pub fn run_evm_wallet(seed: &[u8], network: &EvmNetwork) -> Result<()> {
    let (signing_key, address) = derivation::derive_evm_key(seed, 0)?;
    let address_str = derivation::format_address(&address);

    let rpc = EthRpc::new(network.rpc);
    let chain_id = rpc.chain_id().context("impossible de contacter le nœud RPC")?;
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
                println!("Solde actuel : {balance} wei ({:.6} ETH).\n", balance as f64 / 1e18);
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
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().context("partie entière invalide")? };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 8 {
        frac_padded.push('0');
    }
    let frac_val: u64 = if frac_padded.is_empty() { 0 } else { frac_padded.parse().context("partie décimale invalide")? };
    whole
        .checked_mul(100_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant BTC trop grand (dépassement arithmétique)")
}

/// Dérive une clé Bitcoin testnet depuis `seed` et ouvre un menu recevoir/envoyer.
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
                println!("Solde actuel : {total} sat ({:.8} BTC), {} UTXO(s).\n", total as f64 / 1e8, utxos.len());
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
        return Err(anyhow!("aucun UTXO confirmé disponible (vérifie le solde d'abord)"));
    }

    let to_str = prompt("Adresse destinataire testnet (tb1...) : ")?;
    let to_hash160 = derivation::parse_btc_testnet_address(&to_str)?;

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
    let change_sat = if remaining > BTC_DUST_THRESHOLD_SAT { remaining } else { 0 };

    let tx = BtcTx {
        inputs: utxos,
        to_hash160,
        value_sat: amount_sat,
        change_hash160: *hash160,
        change_sat,
    };

    let raw_tx = tx.sign(signing_key, hash160)?;
    let txid = esplora.broadcast(&raw_tx)?;

    println!("\nTransaction diffusée : {txid}");
    println!("Suivi : https://blockstream.info/testnet/tx/{txid}\n");
    Ok(())
}

/// Convertit un montant décimal en SOL (ex: "0.01") en lamports (9 décimales).
pub(crate) fn parse_sol_to_lamports(input: &str) -> Result<u64> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 9 {
        return Err(anyhow!("trop de décimales (9 maximum pour le SOL)"));
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().context("partie entière invalide")? };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 9 {
        frac_padded.push('0');
    }
    let frac_val: u64 = if frac_padded.is_empty() { 0 } else { frac_padded.parse().context("partie décimale invalide")? };
    whole
        .checked_mul(1_000_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant SOL trop grand (dépassement arithmétique)")
}

/// Convertit un montant décimal en USDC (ex: "12.50") en plus petite unité
/// (6 décimales, comme l'ETH en a 18 et le SOL en a 9) — même structure que
/// `parse_sol_to_lamports`/`parse_eth_to_wei`.
pub(crate) fn parse_usdc_to_micros(input: &str) -> Result<u64> {
    let input = input.trim();
    let (whole, frac) = input.split_once('.').unwrap_or((input, ""));
    if frac.len() > 6 {
        return Err(anyhow!("trop de décimales (6 maximum pour l'USDC)"));
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().context("partie entière invalide")? };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 6 {
        frac_padded.push('0');
    }
    let frac_val: u64 = if frac_padded.is_empty() { 0 } else { frac_padded.parse().context("partie décimale invalide")? };
    whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .context("montant USDC trop grand (dépassement arithmétique)")
}

/// Dérive une clé Solana depuis `seed` et ouvre un menu recevoir/envoyer sur `network`
/// (voir SOLANA_DEVNET / SOLANA_MAINNET).
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
                println!("Solde actuel : {balance} lamports ({:.9} SOL).\n", balance as f64 / 1e9);
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
    let raw_tx = sol_tx::build_transfer_transaction(signing_key, from_pubkey, &to_pubkey, lamports, &recent_blockhash);

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
        // Un seul caractère dont la casse a été inversée par rapport au checksum attendu
        // ("a" en position 2 devient "A") : simule une faute de frappe/copier-coller.
        let corrupted = "0x5Aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(parse_evm_address(corrupted).is_err());
    }

    #[test]
    fn parse_evm_address_accepts_all_lowercase_without_checksum() {
        // Format historique sans checksum (pas de casse mixte) : toujours valide.
        assert!(parse_evm_address(&VALID_CHECKSUM.to_lowercase()).is_ok());
    }

    #[test]
    fn parse_evm_address_accepts_all_uppercase_without_checksum() {
        let all_upper = format!("0x{}", VALID_CHECKSUM.trim_start_matches("0x").to_uppercase());
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
