//! Comptes de portefeuilles matériels (Ledger) : la clé privée ne quitte
//! jamais l'appareil. Ce module ne conserve que des données PUBLIQUES
//! (adresse, chemin de dérivation, et pour Bitcoin l'empreinte maîtresse et la
//! clé publique étendue du compte — même niveau de sensibilité que les
//! adresses des wallets externes) et orchestre les envois :
//! 1. construction de la transaction avec les mêmes contrôles qu'un envoi du
//!    portefeuille logiciel (réseau du nœud, plafond du prix du gas, solde,
//!    UTXOs revérifiés) ;
//! 2. vérification que l'appareil branché est bien celui du compte ;
//! 3. revue et confirmation sur l'écran de l'appareil, signature ;
//! 4. signature revérifiée ici (voir `ledger`), puis diffusion.
//!
//! Chemins utilisés, ceux de Ledger Live pour le premier compte :
//! Ethereum m/44'/60'/0'/0/0, Solana m/44'/501'/0', Bitcoin natif SegWit
//! m/84'/c'/0' (réception 0/0, monnaie 1/0).

use crate::ledger::{self, Transport};
use crate::{api, btc_rpc, btc_tx, eth_rpc, external_wallets, sol_rpc, sol_tx, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const HARDWARE_ACCOUNTS_FILE: &str = "hardware_accounts.json";
const MAX_ACCOUNTS: usize = 50;
const EVM_PATH: &str = "44'/60'/0'/0/0";
const SOL_PATH: &str = "44'/501'/0'";
const BTC_ACCOUNT: u32 = 0;
/// Indice des adresses Bitcoin utilisées (réception m/…/0/0, monnaie m/…/1/0).
const BTC_ADDRESS_INDEX: u32 = 0;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HardwareAccount {
    pub id: u32,
    pub label: String,
    /// "evm_mainnet"/"evm_sepolia"/"btc_mainnet"/"btc_testnet"/"sol_mainnet"/"sol_devnet".
    pub network: String,
    /// Adresse de réception.
    pub address: String,
    /// Chemin de dérivation : de l'adresse (EVM, Solana) ou du compte (Bitcoin).
    pub path: String,
    /// Bitcoin : empreinte maîtresse (hex) et clé publique étendue du compte.
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub xpub: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct HardwareAccountsData {
    accounts: Vec<HardwareAccount>,
}

fn load(data_dir: &Path) -> HardwareAccountsData {
    std::fs::read_to_string(data_dir.join(HARDWARE_ACCOUNTS_FILE))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Écriture atomique (fichier temporaire puis renommage) : jamais de fichier
/// à moitié écrit en cas d'interruption.
fn save(data_dir: &Path, data: &HardwareAccountsData) -> Result<()> {
    let content = serde_json::to_string_pretty(data).context("sérialisation des comptes Ledger")?;
    let tmp = data_dir.join(format!("{HARDWARE_ACCOUNTS_FILE}.tmp"));
    std::fs::write(&tmp, content).context("écriture des comptes Ledger")?;
    std::fs::rename(&tmp, data_dir.join(HARDWARE_ACCOUNTS_FILE)).context("écriture des comptes Ledger")
}

pub fn list_accounts(data_dir: &Path) -> Vec<HardwareAccount> {
    load(data_dir).accounts
}

pub fn remove_account(data_dir: &Path, id: u32) -> Result<()> {
    let mut data = load(data_dir);
    let before = data.accounts.len();
    data.accounts.retain(|a| a.id != id);
    ensure!(data.accounts.len() < before, "compte Ledger introuvable");
    save(data_dir, &data)
}


fn find(data_dir: &Path, id: u32) -> Result<HardwareAccount> {
    list_accounts(data_dir).into_iter().find(|a| a.id == id).ok_or_else(|| anyhow!("compte Ledger introuvable"))
}

enum Chain {
    Evm(&'static wallet_flow::EvmNetwork),
    Btc(&'static wallet_flow::BtcNetwork, bool),
    Sol(&'static wallet_flow::SolNetwork),
}

fn chain(network: &str) -> Result<Chain> {
    Ok(match network {
        "evm_mainnet" => Chain::Evm(&wallet_flow::ETHEREUM_MAINNET),
        "evm_sepolia" => Chain::Evm(&wallet_flow::SEPOLIA),
        "btc_mainnet" => Chain::Btc(&wallet_flow::BTC_MAINNET, false),
        "btc_testnet" => Chain::Btc(&wallet_flow::BTC_TESTNET, true),
        "sol_mainnet" => Chain::Sol(&wallet_flow::SOLANA_MAINNET),
        "sol_devnet" => Chain::Sol(&wallet_flow::SOLANA_DEVNET),
        other => bail!("réseau inconnu : {other}"),
    })
}

/// Appareil branché en USB. En version de développement et en test seulement
/// (jamais compilé dans l'app livrée), la variable `PGP_WALLET_LEDGER_EMULATOR`
/// (ex. `127.0.0.1:9999`) désigne l'émulateur officiel Speculos à la place,
/// pour tester l'app sans appareil. (Le profil de test désactive
/// `debug_assertions`, voir Cargo.toml, d'où `test` en plus.)
fn open_transport() -> Result<Box<dyn Transport>> {
    #[cfg(any(debug_assertions, test))]
    if let Ok(address) = std::env::var("PGP_WALLET_LEDGER_EMULATOR") {
        return Ok(Box::new(ledger::TcpTransport::connect(&address)?));
    }
    Ok(Box::new(ledger::HidTransport::open_first()?))
}

/// Compte Bitcoin reconstruit à partir des données enregistrées.
fn btc_account(account: &HardwareAccount, testnet: bool) -> Result<ledger::btc::Account> {
    let fingerprint = hex::decode(account.fingerprint.as_deref().unwrap_or_default())
        .ok()
        .and_then(|f| <[u8; 4]>::try_from(f).ok())
        .ok_or_else(|| anyhow!("compte Ledger Bitcoin incomplet"))?;
    let xpub = account.xpub.clone().ok_or_else(|| anyhow!("compte Ledger Bitcoin incomplet"))?;
    Ok(ledger::btc::Account { testnet, account: BTC_ACCOUNT, fingerprint, xpub })
}

/// Lit sur l'appareil (application du réseau ouverte) le compte de `network`,
/// sans rien afficher.
fn read_account(transport: &mut dyn Transport, network: &str, label: &str) -> Result<HardwareAccount> {
    let mut account = HardwareAccount { id: 0, label: label.to_string(), network: network.to_string(), address: String::new(), path: String::new(), fingerprint: None, xpub: None };
    match chain(network)? {
        Chain::Evm(_) => {
            account.address = ledger::eth::get_address(transport, &ledger::parse_path(EVM_PATH)?, false)?;
            account.path = EVM_PATH.into();
        }
        Chain::Sol(_) => {
            account.address = bs58::encode(ledger::solana::get_pubkey(transport, &ledger::parse_path(SOL_PATH)?, false)?).into_string();
            account.path = SOL_PATH.into();
        }
        Chain::Btc(_, testnet) => {
            let btc = ledger::btc::Account::load(transport, testnet, BTC_ACCOUNT)?;
            account.address = btc.address(0, BTC_ADDRESS_INDEX)?;
            account.path = format!("84'/{}'/{BTC_ACCOUNT}'", testnet as u32);
            account.fingerprint = Some(hex::encode(btc.fingerprint));
            account.xpub = Some(btc.xpub);
        }
    }
    external_wallets::validate_address(network, &account.address)?;
    Ok(account)
}

/// Ajoute le compte du Ledger branché pour `network` (l'application du réseau
/// doit être ouverte sur l'appareil).
pub fn connect_ledger(data_dir: &Path, network: &str, label: &str) -> Result<HardwareAccount> {
    let label = label.trim();
    ensure!(!label.is_empty() && label.chars().count() <= 60, "nom du compte Ledger invalide (1 à 60 caractères)");
    let mut transport = open_transport()?;
    let mut account = read_account(transport.as_mut(), network, label)?;
    let mut data = load(data_dir);
    ensure!(data.accounts.len() < MAX_ACCOUNTS, "nombre maximal de comptes Ledger atteint");
    ensure!(
        !data.accounts.iter().any(|a| a.network == account.network && a.address == account.address),
        "ce compte Ledger est déjà ajouté"
    );
    account.id = data.accounts.iter().map(|a| a.id + 1).max().unwrap_or(1);
    data.accounts.push(account.clone());
    save(data_dir, &data)?;
    Ok(account)
}

/// L'appareil branché est-il celui du compte ? (Autre appareil ou autre phrase
/// de récupération : refus clair avant toute demande de signature.)
fn ensure_same_device(transport: &mut dyn Transport, account: &HardwareAccount) -> Result<()> {
    let current = read_account(transport, &account.network, &account.label)?;
    ensure!(
        current.address == account.address && current.xpub == account.xpub && current.fingerprint == account.fingerprint,
        "ce Ledger ne correspond pas au compte « {} » (autre appareil ou autre phrase de récupération)",
        account.label
    );
    Ok(())
}

/// Affiche l'adresse de réception sur l'écran de l'appareil (seul moyen de
/// vérifier qu'elle n'a pas été substituée sur l'ordinateur) ; `Ok` une fois
/// confirmée par l'utilisateur ET identique à celle enregistrée.
pub fn verify_address_on_device(data_dir: &Path, id: u32) -> Result<()> {
    let account = find(data_dir, id)?;
    let mut transport = open_transport()?;
    ensure_same_device(transport.as_mut(), &account)?;
    let shown = match chain(&account.network)? {
        Chain::Evm(_) => ledger::eth::get_address(transport.as_mut(), &ledger::parse_path(&account.path)?, true)?,
        Chain::Sol(_) => bs58::encode(ledger::solana::get_pubkey(transport.as_mut(), &ledger::parse_path(&account.path)?, true)?).into_string(),
        Chain::Btc(_, testnet) => ledger::btc::wallet_address(transport.as_mut(), &btc_account(&account, testnet)?, 0, BTC_ADDRESS_INDEX, true)?,
    };
    ensure!(shown == account.address, "l'adresse affichée par le Ledger diffère de celle enregistrée");
    Ok(())
}

/// Adresses Bitcoin du compte : (réception, monnaie).
fn btc_addresses(account: &ledger::btc::Account) -> Result<(String, String)> {
    Ok((account.address(0, BTC_ADDRESS_INDEX)?, account.address(1, BTC_ADDRESS_INDEX)?))
}

/// Solde dans la plus petite unité (wei, satoshi, lamport). Bitcoin : UTXOs
/// confirmés des adresses de réception ET de monnaie.
pub fn balance(data_dir: &Path, id: u32) -> Result<u128> {
    let account = find(data_dir, id)?;
    Ok(match chain(&account.network)? {
        Chain::Evm(net) => api::get_evm_balance(&account.address, net)?,
        Chain::Sol(net) => api::get_sol_balance(&account.address, net)?.into(),
        Chain::Btc(net, testnet) => {
            let (receive, change) = btc_addresses(&btc_account(&account, testnet)?)?;
            u128::from(api::get_btc_balance(&receive, net)?) + u128::from(api::get_btc_balance(&change, net)?)
        }
    })
}

/// Frais rapide/moyen/lent d'un envoi Bitcoin depuis le compte.
pub fn estimate_btc_fees(data_dir: &Path, id: u32) -> Result<api::BtcFeeEstimate> {
    let account = find(data_dir, id)?;
    let Chain::Btc(net, testnet) = chain(&account.network)? else { bail!("compte Ledger non Bitcoin") };
    let (receive, change) = btc_addresses(&btc_account(&account, testnet)?)?;
    api::estimate_btc_fees_for(&[&receive, &change], net)
}

/// Compte et réseau d'un envoi, vérifiés.
fn account_for(data_dir: &Path, id: u32, network: &str) -> Result<HardwareAccount> {
    let account = find(data_dir, id)?;
    ensure!(account.network == network, "le compte Ledger « {} » n'est pas sur ce réseau", account.label);
    Ok(account)
}

/// Virement ETH signé par l'appareil. `gas_price` : celui affiché dans la
/// boîte de confirmation, utilisé tel quel (voir `api::evm_gas_price_for_confirmation`).
pub fn send_evm(data_dir: &Path, id: u32, network: &str, to: &str, amount_eth: &str, gas_price: u128) -> Result<String> {
    let account = account_for(data_dir, id, network)?;
    let Chain::Evm(net) = chain(network)? else { bail!("réseau EVM attendu") };
    let from = wallet_flow::parse_evm_address(&account.address)?;
    let tx = api::prepare_evm_transfer(net, &from, to, amount_eth, gas_price)?;
    let mut transport = open_transport()?;
    ensure_same_device(transport.as_mut(), &account)?;
    let raw_tx = ledger::eth::sign_transaction(transport.as_mut(), &ledger::parse_path(&account.path)?, &tx, &from)?;
    eth_rpc::EthRpc::new(net.rpc).send_raw_transaction(&raw_tx)
}

/// Virement SOL signé par l'appareil.
pub fn send_sol(data_dir: &Path, id: u32, network: &str, to: &str, amount_sol: &str) -> Result<String> {
    let account = account_for(data_dir, id, network)?;
    let Chain::Sol(net) = chain(network)? else { bail!("réseau Solana attendu") };
    api::check_solana_recipient(to, net)?;
    let from: [u8; 32] = bs58::decode(&account.address)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("adresse Solana du compte invalide"))?;
    let message = api::prepare_sol_transfer(net, &from, to, amount_sol)?;
    let mut transport = open_transport()?;
    ensure_same_device(transport.as_mut(), &account)?;
    let signature = ledger::solana::sign_transaction_message(transport.as_mut(), &ledger::parse_path(&account.path)?, &message, &from)?;
    sol_rpc::SolRpc::new(net.rpc).send_transaction(&sol_tx::assemble_transaction(&signature, &message))
}

/// Virement Bitcoin signé par l'appareil : consomme tous les UTXOs confirmés
/// des adresses de réception et de monnaie (comme `api::send_btc`), monnaie
/// renvoyée sur l'adresse de monnaie (reconnue et masquée par l'appareil).
pub fn send_btc(data_dir: &Path, id: u32, network: &str, to: &str, amount_btc: &str, fee_sat: u64) -> Result<String> {
    let account = account_for(data_dir, id, network)?;
    let Chain::Btc(net, testnet) = chain(network)? else { bail!("réseau Bitcoin attendu") };
    let btc = btc_account(&account, testnet)?;
    let to_hash160 = (net.parse_address)(to)?;
    let amount_sat = wallet_flow::parse_btc_to_sat(amount_btc)?;

    let esplora = btc_rpc::EsploraClient::new(net.esplora_base);
    let (receive, change) = btc_addresses(&btc)?;
    let mut utxos = Vec::new();
    for (change_path, address) in [(0, &receive), (1, &change)] {
        utxos.extend(esplora.utxos(address)?.into_iter().map(|u| (change_path, u)));
    }
    let total_sat = utxos.iter().try_fold(0u64, |sum, (_, u)| sum.checked_add(u.value_sat)).context("total des UTXOs invalide")?;
    let change_sat = api::btc_change(total_sat, amount_sat, fee_sat)?;

    // Transaction complète de chaque UTXO, exigée par l'appareil (txid
    // recalculé ici puis par l'appareil : un serveur menteur est détecté).
    let mut previous: std::collections::HashMap<[u8; 32], Vec<u8>> = std::collections::HashMap::new();
    let mut inputs = Vec::new();
    for (change_path, utxo) in utxos {
        let prev_tx = match previous.entry(utxo.txid) {
            std::collections::hash_map::Entry::Occupied(known) => known.get().clone(),
            std::collections::hash_map::Entry::Vacant(slot) => slot.insert(esplora.raw_transaction(&utxo.txid)?).clone(),
        };
        inputs.push(ledger::btc::Input {
            txid: utxo.txid,
            vout: utxo.vout,
            value_sat: utxo.value_sat,
            prev_tx,
            change: change_path,
            index: BTC_ADDRESS_INDEX,
        });
    }
    let mut outputs = vec![ledger::btc::Output { value_sat: amount_sat, script_pubkey: btc_tx::p2wpkh_script_pubkey(&to_hash160), change_index: None }];
    if change_sat > 0 {
        outputs.push(ledger::btc::Output {
            value_sat: change_sat,
            script_pubkey: btc_tx::p2wpkh_script_pubkey(&btc.hash160(1, BTC_ADDRESS_INDEX)?),
            change_index: Some(BTC_ADDRESS_INDEX),
        });
    }

    let mut transport = open_transport()?;
    ensure_same_device(transport.as_mut(), &account)?;
    let raw_tx = ledger::btc::sign_transaction(transport.as_mut(), &btc, &inputs, &outputs)?;
    esplora.broadcast(&raw_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pgp_wallet_hardware_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample(network: &str, address: &str) -> HardwareAccount {
        HardwareAccount { id: 0, label: "Ledger".into(), network: network.into(), address: address.into(), path: EVM_PATH.into(), fingerprint: None, xpub: None }
    }

    /// Enregistrement, suppression, compte d'un autre réseau refusé ; un
    /// fichier illisible donne une liste vide (jamais d'erreur bloquante).
    #[test]
    fn accounts_are_stored_and_removed() {
        let dir = temp_dir("store");
        let mut data = HardwareAccountsData::default();
        data.accounts.push(HardwareAccount { id: 1, ..sample("evm_mainnet", "0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D") });
        data.accounts.push(HardwareAccount { id: 2, ..sample("sol_mainnet", "11111111111111111111111111111111") });
        save(&dir, &data).unwrap();
        assert_eq!(list_accounts(&dir).len(), 2);
        remove_account(&dir, 1).unwrap();
        assert_eq!(list_accounts(&dir).iter().map(|a| a.id).collect::<Vec<_>>(), vec![2]);
        assert!(remove_account(&dir, 1).is_err(), "déjà supprimé");
        assert!(find(&dir, 2).is_ok());
        assert!(account_for(&dir, 2, "sol_devnet").is_err(), "compte d'un autre réseau refusé");
        std::fs::write(dir.join(HARDWARE_ACCOUNTS_FILE), "{pas du json").unwrap();
        assert!(list_accounts(&dir).is_empty());
        assert!(chain("evm_goerli").is_err());
    }

    /// Parcours complet contre les applications OFFICIELLES dans Speculos
    /// (graine de test publique), réseau par réseau : ajout du compte,
    /// adresse vérifiée à l'écran, refus d'un doublon. Lancer Speculos avec
    /// l'application voulue, puis par exemple :
    /// `PGP_WALLET_LEDGER_EMULATOR=127.0.0.1:9999 LEDGER_TEST_NETWORK=btc_testnet cargo test -- --ignored hardware_accounts_with_the_official_apps --nocapture`
    #[test]
    #[ignore]
    fn hardware_accounts_with_the_official_apps() {
        use crate::ledger::speculos;
        let network = std::env::var("LEDGER_TEST_NETWORK").unwrap();
        let dir = temp_dir("speculos");
        speculos::back_to_home();
        let account = connect_ledger(&dir, &network, "Mon Ledger").unwrap();
        println!("compte : {account:?}");
        // Adresse attendue : NOTRE dérivation depuis la graine de test.
        let seed = bip39::Mnemonic::parse(speculos::TEST_MNEMONIC).unwrap().to_seed("");
        let expected = match chain(&network).unwrap() {
            Chain::Evm(_) => crate::derivation::format_address(&crate::derivation::derive_evm_key(&seed, 0).unwrap().1),
            Chain::Sol(_) => bs58::encode(crate::derivation::derive_ed25519_path(&seed, &[44, 501, 0]).verifying_key().to_bytes()).into_string(),
            Chain::Btc(_, testnet) => {
                let root = bip32::XPrv::derive_from_path(seed, &format!("m/84'/{}'/0'/0/0", testnet as u32).parse().unwrap()).unwrap();
                use sha2::Digest;
                let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(root.public_key().to_bytes()));
                let hash: [u8; 20] = hash.into();
                if testnet { crate::derivation::format_btc_testnet_address(&hash) } else { crate::derivation::format_btc_mainnet_address(&hash) }.unwrap()
            }
        };
        assert_eq!(account.address, expected);
        assert!(connect_ledger(&dir, &network, "Doublon").unwrap_err().to_string().contains("déjà"));
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Confirm", "Approve"]));
        verify_address_on_device(&dir, account.id).unwrap();
        println!("écrans : {}", approver.join().unwrap().join(" | "));
        speculos::back_to_home();
    }

    /// VRAI envoi sur Bitcoin testnet, signé par l'application officielle
    /// « Bitcoin Test » dans Speculos : la graine de test publique détient des
    /// fonds testnet (sans valeur) ; 10 000 sat renvoyés à sa PROPRE adresse de
    /// réception (seuls les frais quittent ce portefeuille public). Le réseau
    /// accepte la transaction = validité réelle, au-delà de nos vérifications.
    /// `PGP_WALLET_LEDGER_EMULATOR=127.0.0.1:9999 cargo test -- --ignored hardware_btc_send_on_testnet_with_the_emulator --nocapture`
    #[test]
    #[ignore]
    fn hardware_btc_send_on_testnet_with_the_emulator() {
        use crate::ledger::speculos;
        let dir = temp_dir("btc_send");
        speculos::back_to_home();
        let account = connect_ledger(&dir, "btc_testnet", "Ledger testnet").unwrap();
        let before = balance(&dir, account.id).unwrap();
        let fees = estimate_btc_fees(&dir, account.id).unwrap();
        println!("solde {before} sat, frais lent {} sat", fees.slow_sat);
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign transaction"]));
        let txid = send_btc(&dir, account.id, "btc_testnet", &account.address, "0.0001", fees.slow_sat).unwrap();
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans : {screens}");
        println!("txid : {txid}");
        assert!(screens.contains("0.0001"), "montant affiché");
        assert_eq!(txid.len(), 64);
        speculos::back_to_home();
    }
}
