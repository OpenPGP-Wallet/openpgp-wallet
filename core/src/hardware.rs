//! Comptes de portefeuilles matériels (Ledger, Trezor) : la clé privée ne
//! quitte jamais l'appareil. Ce module ne conserve que des données PUBLIQUES
//! (adresse, chemin de dérivation, et pour Bitcoin l'empreinte maîtresse et la
//! clé publique étendue du compte — même niveau de sensibilité que les
//! adresses des wallets externes) et orchestre les envois :
//! 1. construction de la transaction avec les mêmes contrôles qu'un envoi du
//!    portefeuille logiciel (réseau du nœud, plafond du prix du gas, solde,
//!    UTXOs revérifiés) ;
//! 2. vérification que l'appareil branché est bien celui du compte ;
//! 3. revue et confirmation sur l'écran de l'appareil, signature ;
//! 4. signature revérifiée ici (voir `ledger`, `trezor`), puis diffusion.
//!
//! Chemins du premier compte, ceux des applications officielles (Ledger Live,
//! Trezor Suite) : Ethereum m/44'/60'/0'/0/0 ; Solana m/44'/501'/0' (Ledger)
//! ou m/44'/501'/0'/0' (Trezor) ; Bitcoin natif SegWit m/84'/c'/0'
//! (réception 0/0, monnaie 1/0).

use crate::ledger::{self, Transport};
use crate::trezor::{self, Trezor};
use crate::{api, btc_rpc, btc_tx, eth_rpc, external_wallets, sol_rpc, sol_tx, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const HARDWARE_ACCOUNTS_FILE: &str = "hardware_accounts.json";
const MAX_ACCOUNTS: usize = 50;
const EVM_PATH: &str = "44'/60'/0'/0/0";
const BTC_ACCOUNT: u32 = 0;
/// Indice des adresses Bitcoin utilisées (réception m/…/0/0, monnaie m/…/1/0).
const BTC_ADDRESS_INDEX: u32 = 0;

fn default_device() -> String {
    "ledger".into()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HardwareAccount {
    pub id: u32,
    pub label: String,
    /// "ledger" ou "trezor" (comptes enregistrés avant l'arrivée du Trezor :
    /// "ledger").
    #[serde(default = "default_device")]
    pub device: String,
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
    let content = serde_json::to_string_pretty(data).context("sérialisation des comptes matériels")?;
    let tmp = data_dir.join(format!("{HARDWARE_ACCOUNTS_FILE}.tmp"));
    std::fs::write(&tmp, content).context("écriture des comptes matériels")?;
    std::fs::rename(&tmp, data_dir.join(HARDWARE_ACCOUNTS_FILE)).context("écriture des comptes matériels")
}

pub fn list_accounts(data_dir: &Path) -> Vec<HardwareAccount> {
    load(data_dir).accounts
}

pub fn remove_account(data_dir: &Path, id: u32) -> Result<()> {
    let mut data = load(data_dir);
    let before = data.accounts.len();
    data.accounts.retain(|a| a.id != id);
    ensure!(data.accounts.len() < before, "compte matériel introuvable");
    save(data_dir, &data)
}

fn find(data_dir: &Path, id: u32) -> Result<HardwareAccount> {
    list_accounts(data_dir).into_iter().find(|a| a.id == id).ok_or_else(|| anyhow!("compte matériel introuvable"))
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Device {
    Ledger,
    Trezor,
}

impl Device {
    fn parse(device: &str) -> Result<Self> {
        match device {
            "ledger" => Ok(Device::Ledger),
            "trezor" => Ok(Device::Trezor),
            other => bail!("appareil inconnu : {other}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Device::Ledger => "Ledger",
            Device::Trezor => "Trezor",
        }
    }

    fn id(self) -> &'static str {
        match self {
            Device::Ledger => "ledger",
            Device::Trezor => "trezor",
        }
    }

    fn sol_path(self) -> &'static str {
        match self {
            Device::Ledger => "44'/501'/0'",
            Device::Trezor => "44'/501'/0'/0'",
        }
    }
}

/// Communication ouverte avec un appareil.
enum Session {
    Ledger(Box<dyn Transport>),
    Trezor(Trezor),
}

/// Appareil branché en USB. En version de développement et en test seulement
/// (jamais compilé dans l'app livrée), `PGP_WALLET_LEDGER_EMULATOR` (ex.
/// `127.0.0.1:9999`) et `PGP_WALLET_TREZOR_EMULATOR` (ex. `127.0.0.1:21424`)
/// désignent les émulateurs officiels à la place, pour tester l'app sans
/// appareil. (Le profil de test désactive `debug_assertions`, voir
/// Cargo.toml, d'où `test` en plus.)
fn open(device: Device) -> Result<Session> {
    match device {
        Device::Ledger => {
            #[cfg(any(debug_assertions, test))]
            if let Ok(address) = std::env::var("PGP_WALLET_LEDGER_EMULATOR") {
                return Ok(Session::Ledger(Box::new(ledger::TcpTransport::connect(&address)?)));
            }
            Ok(Session::Ledger(Box::new(ledger::HidTransport::open_first()?)))
        }
        Device::Trezor => {
            let mut session = Trezor::new(trezor_link()?);
            session.initialize()?;
            Ok(Session::Trezor(session))
        }
    }
}

#[cfg(any(debug_assertions, test))]
fn trezor_link() -> Result<Box<dyn trezor::Link>> {
    if let Ok(address) = std::env::var("PGP_WALLET_TREZOR_EMULATOR") {
        return Ok(Box::new(trezor::RelayLink::connect(&address)?));
    }
    Ok(Box::new(trezor::UsbLink::open_first()?))
}

#[cfg(not(any(debug_assertions, test)))]
fn trezor_link() -> Result<Box<dyn trezor::Link>> {
    Ok(Box::new(trezor::UsbLink::open_first()?))
}

/// Compte Bitcoin reconstruit à partir des données enregistrées.
fn btc_account(account: &HardwareAccount, testnet: bool) -> Result<ledger::btc::Account> {
    let fingerprint = hex::decode(account.fingerprint.as_deref().unwrap_or_default())
        .ok()
        .and_then(|f| <[u8; 4]>::try_from(f).ok())
        .ok_or_else(|| anyhow!("compte Bitcoin matériel incomplet"))?;
    let xpub = account.xpub.clone().ok_or_else(|| anyhow!("compte Bitcoin matériel incomplet"))?;
    Ok(ledger::btc::Account { testnet, account: BTC_ACCOUNT, fingerprint, xpub })
}

/// Lit sur l'appareil (application du réseau ouverte sur un Ledger) le compte
/// de `network`, sans rien afficher.
fn read_account(session: &mut Session, device: Device, network: &str, label: &str) -> Result<HardwareAccount> {
    let mut account = HardwareAccount {
        id: 0,
        label: label.to_string(),
        device: device.id().into(),
        network: network.to_string(),
        address: String::new(),
        path: String::new(),
        fingerprint: None,
        xpub: None,
    };
    match chain(network)? {
        Chain::Evm(_) => {
            let path = ledger::parse_path(EVM_PATH)?;
            account.address = match session {
                Session::Ledger(t) => ledger::eth::get_address(t.as_mut(), &path, false)?,
                Session::Trezor(t) => trezor::ethereum::get_address(t, &path, false)?,
            };
            account.path = EVM_PATH.into();
        }
        Chain::Sol(_) => {
            let path = ledger::parse_path(device.sol_path())?;
            let pubkey = match session {
                Session::Ledger(t) => ledger::solana::get_pubkey(t.as_mut(), &path, false)?,
                Session::Trezor(t) => trezor::solana::get_pubkey(t, &path, false)?,
            };
            account.address = bs58::encode(pubkey).into_string();
            account.path = device.sol_path().into();
        }
        Chain::Btc(_, testnet) => {
            let btc = match session {
                Session::Ledger(t) => ledger::btc::Account::load(t.as_mut(), testnet, BTC_ACCOUNT)?,
                Session::Trezor(t) => trezor::bitcoin::load_account(t, testnet, BTC_ACCOUNT)?,
            };
            account.address = btc.address(0, BTC_ADDRESS_INDEX)?;
            account.path = format!("84'/{}'/{BTC_ACCOUNT}'", testnet as u32);
            account.fingerprint = Some(hex::encode(btc.fingerprint));
            account.xpub = Some(btc.xpub);
        }
    }
    external_wallets::validate_address(network, &account.address)?;
    Ok(account)
}

/// Ajoute le compte de l'appareil branché (`device` : "ledger" ou "trezor")
/// pour `network` (sur un Ledger, l'application du réseau doit être ouverte).
pub fn connect_device(data_dir: &Path, device: &str, network: &str, label: &str) -> Result<HardwareAccount> {
    let device = Device::parse(device)?;
    let label = label.trim();
    ensure!(!label.is_empty() && label.chars().count() <= 60, "nom du compte invalide (1 à 60 caractères)");
    let mut session = open(device)?;
    let mut account = read_account(&mut session, device, network, label)?;
    let mut data = load(data_dir);
    ensure!(data.accounts.len() < MAX_ACCOUNTS, "nombre maximal de comptes matériels atteint");
    ensure!(
        !data.accounts.iter().any(|a| a.network == account.network && a.address == account.address),
        "ce compte est déjà ajouté"
    );
    account.id = data.accounts.iter().map(|a| a.id + 1).max().unwrap_or(1);
    data.accounts.push(account.clone());
    save(data_dir, &data)?;
    Ok(account)
}

/// Ouvre l'appareil du compte et vérifie que c'est bien le sien (autre
/// appareil ou autre phrase de récupération : refus clair avant toute
/// demande de signature).
fn open_for(account: &HardwareAccount) -> Result<Session> {
    let device = Device::parse(&account.device)?;
    let mut session = open(device)?;
    let current = read_account(&mut session, device, &account.network, &account.label)?;
    ensure!(
        current.address == account.address && current.xpub == account.xpub && current.fingerprint == account.fingerprint,
        "ce {} ne correspond pas au compte « {} » (autre appareil ou autre phrase de récupération)",
        device.name(),
        account.label
    );
    Ok(session)
}

/// Affiche l'adresse de réception sur l'écran de l'appareil (seul moyen de
/// vérifier qu'elle n'a pas été substituée sur l'ordinateur) ; `Ok` une fois
/// confirmée par l'utilisateur ET identique à celle enregistrée.
pub fn verify_address_on_device(data_dir: &Path, id: u32) -> Result<()> {
    let account = find(data_dir, id)?;
    let mut session = open_for(&account)?;
    let shown = match (chain(&account.network)?, &mut session) {
        (Chain::Evm(_), Session::Ledger(t)) => ledger::eth::get_address(t.as_mut(), &ledger::parse_path(&account.path)?, true)?,
        (Chain::Evm(_), Session::Trezor(t)) => trezor::ethereum::get_address(t, &ledger::parse_path(&account.path)?, true)?,
        (Chain::Sol(_), Session::Ledger(t)) => bs58::encode(ledger::solana::get_pubkey(t.as_mut(), &ledger::parse_path(&account.path)?, true)?).into_string(),
        (Chain::Sol(_), Session::Trezor(t)) => bs58::encode(trezor::solana::get_pubkey(t, &ledger::parse_path(&account.path)?, true)?).into_string(),
        (Chain::Btc(_, testnet), Session::Ledger(t)) => ledger::btc::wallet_address(t.as_mut(), &btc_account(&account, testnet)?, 0, BTC_ADDRESS_INDEX, true)?,
        (Chain::Btc(_, testnet), Session::Trezor(t)) => trezor::bitcoin::get_address(t, &btc_account(&account, testnet)?, 0, BTC_ADDRESS_INDEX, true)?,
    };
    ensure!(shown == account.address, "l'adresse affichée par l'appareil diffère de celle enregistrée");
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
    let Chain::Btc(net, testnet) = chain(&account.network)? else { bail!("compte non Bitcoin") };
    let (receive, change) = btc_addresses(&btc_account(&account, testnet)?)?;
    api::estimate_btc_fees_for(&[&receive, &change], net)
}

/// Compte et réseau d'un envoi, vérifiés.
fn account_for(data_dir: &Path, id: u32, network: &str) -> Result<HardwareAccount> {
    let account = find(data_dir, id)?;
    ensure!(account.network == network, "le compte « {} » n'est pas sur ce réseau", account.label);
    Ok(account)
}

/// Virement ETH signé par l'appareil. `fee` : les frais affichés dans la
/// boîte de confirmation, utilisés tels quels (voir `api::evm_fee_for_confirmation`).
pub fn send_evm(data_dir: &Path, id: u32, network: &str, to: &str, amount_eth: &str, fee: api::EvmFee) -> Result<String> {
    let account = account_for(data_dir, id, network)?;
    let Chain::Evm(net) = chain(network)? else { bail!("réseau EVM attendu") };
    let from = wallet_flow::parse_evm_address(&account.address)?;
    let tx = api::prepare_evm_transfer(net, &from, to, amount_eth, fee)?;
    let path = ledger::parse_path(&account.path)?;
    let raw_tx = match open_for(&account)? {
        Session::Ledger(mut t) => ledger::eth::sign_transaction(t.as_mut(), &path, &tx, &from)?,
        Session::Trezor(mut t) => trezor::ethereum::sign_transaction(&mut t, &path, &tx, &from)?,
    };
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
    let path = ledger::parse_path(&account.path)?;
    let signature = match open_for(&account)? {
        Session::Ledger(mut t) => ledger::solana::sign_transaction_message(t.as_mut(), &path, &message, &from)?,
        Session::Trezor(mut t) => trezor::solana::sign_transaction_message(&mut t, &path, &message, &from)?,
    };
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

    let raw_tx = match open_for(&account)? {
        Session::Ledger(mut t) => ledger::btc::sign_transaction(t.as_mut(), &btc, &inputs, &outputs)?,
        Session::Trezor(mut t) => trezor::bitcoin::sign_transaction(&mut t, &btc, &inputs, &outputs)?,
    };
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
        HardwareAccount { id: 0, label: "Ledger".into(), device: "ledger".into(), network: network.into(), address: address.into(), path: EVM_PATH.into(), fingerprint: None, xpub: None }
    }

    /// Enregistrement, suppression, compte d'un autre réseau refusé ; un
    /// fichier illisible donne une liste vide (jamais d'erreur bloquante) ;
    /// un compte enregistré avant l'arrivée du Trezor reste un compte Ledger.
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
        std::fs::write(
            dir.join(HARDWARE_ACCOUNTS_FILE),
            r#"{"accounts":[{"id":3,"label":"Ancien","network":"evm_mainnet","address":"0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D","path":"44'/60'/0'/0/0"}]}"#,
        )
        .unwrap();
        assert_eq!(list_accounts(&dir)[0].device, "ledger");
        assert!(Device::parse("keepkey").is_err());
    }

    /// Adresse attendue sur la graine de test publique : NOTRE dérivation.
    fn expected_address(network: &str, device: Device) -> String {
        let seed = bip39::Mnemonic::parse(crate::ledger::speculos::TEST_MNEMONIC).unwrap().to_seed("");
        match chain(network).unwrap() {
            Chain::Evm(_) => crate::derivation::format_address(&crate::derivation::derive_evm_key(&seed, 0).unwrap().1),
            Chain::Sol(_) => {
                let path: Vec<u32> = ledger::parse_path(device.sol_path()).unwrap().iter().map(|i| i & !ledger::HARDENED).collect();
                bs58::encode(crate::derivation::derive_ed25519_path(&seed, &path).verifying_key().to_bytes()).into_string()
            }
            Chain::Btc(_, testnet) => {
                let root = bip32::XPrv::derive_from_path(seed, &format!("m/84'/{}'/0'/0/0", testnet as u32).parse().unwrap()).unwrap();
                use sha2::Digest;
                let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(root.public_key().to_bytes()));
                let hash: [u8; 20] = hash.into();
                if testnet { crate::derivation::format_btc_testnet_address(&hash) } else { crate::derivation::format_btc_mainnet_address(&hash) }.unwrap()
            }
        }
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
        let account = connect_device(&dir, "ledger", &network, "Mon Ledger").unwrap();
        println!("compte : {account:?}");
        assert_eq!(account.address, expected_address(&network, Device::Ledger));
        assert!(connect_device(&dir, "ledger", &network, "Doublon").unwrap_err().to_string().contains("déjà"));
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Confirm", "Approve"]));
        verify_address_on_device(&dir, account.id).unwrap();
        println!("écrans : {}", approver.join().unwrap().join(" | "));
        speculos::back_to_home();
    }

    /// Même parcours avec le firmware officiel Trezor dans son émulateur, sur
    /// les trois réseaux (aucune application à ouvrir sur un Trezor).
    /// `PGP_WALLET_TREZOR_EMULATOR=127.0.0.1:21424 cargo test -- --ignored hardware_accounts_with_the_official_trezor_firmware --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn hardware_accounts_with_the_official_trezor_firmware() {
        let dir = temp_dir("trezor");
        for network in ["evm_sepolia", "sol_devnet", "btc_testnet"] {
            let account = connect_device(&dir, "trezor", network, "Mon Trezor").unwrap();
            println!("compte : {account:?}");
            assert_eq!(account.device, "trezor");
            assert_eq!(account.address, expected_address(network, Device::Trezor));
            assert!(connect_device(&dir, "trezor", network, "Doublon").unwrap_err().to_string().contains("déjà"));
            let reviewer = std::thread::spawn(|| trezor::emulator::DebugLink::connect().review(8, None));
            verify_address_on_device(&dir, account.id).unwrap();
            println!("écrans : {:?}", reviewer.join().unwrap());
        }
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
        let account = connect_device(&dir, "ledger", "btc_testnet", "Ledger testnet").unwrap();
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

    /// Même VRAI envoi testnet, signé cette fois par le firmware officiel
    /// Trezor (même graine publique, mêmes adresses que le Ledger).
    /// `PGP_WALLET_TREZOR_EMULATOR=127.0.0.1:21424 cargo test -- --ignored hardware_btc_send_on_testnet_with_the_trezor_emulator --nocapture`
    #[test]
    #[ignore]
    fn hardware_btc_send_on_testnet_with_the_trezor_emulator() {
        let dir = temp_dir("trezor_btc_send");
        let account = connect_device(&dir, "trezor", "btc_testnet", "Trezor testnet").unwrap();
        let before = balance(&dir, account.id).unwrap();
        let fees = estimate_btc_fees(&dir, account.id).unwrap();
        println!("solde {before} sat, frais lent {} sat", fees.slow_sat);
        let reviewer = std::thread::spawn(|| trezor::emulator::DebugLink::connect().review(25, None));
        let txid = send_btc(&dir, account.id, "btc_testnet", &account.address, "0.0001", fees.slow_sat).unwrap();
        let screens = reviewer.join().unwrap().join(" | ");
        println!("écrans : {screens}");
        println!("txid : {txid}");
        assert!(screens.contains("0.0001"), "montant affiché");
        assert_eq!(txid.len(), 64);
    }
}
