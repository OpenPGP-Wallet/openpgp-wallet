//! Stellar (XLM) : adresse G… (SEP-0005, m/44'/148'/p', clé ed25519), solde,
//! envoi de XLM, historique.
//!
//! Transactions encodées (XDR) et signées ici, vérifiées contre la
//! bibliothèque officielle de la Stellar Development Foundation
//! (@stellar/stellar-base) dans les tests, et de bout en bout sur le réseau
//! de test (test réel).
//!
//! Règles du réseau appliquées avant la boîte de confirmation :
//! - solde minimum (réserve) : 2 × 0,5 XLM, + 0,5 par objet possédé, jamais
//!   envoyable ;
//! - un destinataire jamais activé est CRÉÉ (opération `create_account`),
//!   avec au moins 1 XLM ;
//! - un destinataire qui exige un mémo (SEP-29, plateformes d'échange) ne
//!   reçoit rien sans mémo ;
//! - adresses muxées (M…) refusées, clé secrète (S…) détectée ;
//! - frais : offre plafonnée (0,1 XLM), seul le nécessaire est prélevé ;
//!   validité limitée (3 min).

use crate::history;
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Réseau Stellar : serveur Horizon et phrase du réseau (signée).
pub struct Network {
    pub horizon: &'static str,
    pub passphrase: &'static str,
}

pub const MAINNET: Network = Network { horizon: "https://horizon.stellar.org", passphrase: "Public Global Stellar Network ; September 2015" };
#[cfg(test)]
const TESTNET: Network = Network { horizon: "https://horizon-testnet.stellar.org", passphrase: "Test SDF Network ; September 2015" };

pub const DECIMALS: u8 = 7;
/// Plafond de l'offre de frais (0,1 XLM, quelques centimes ; 0,00001 au repos).
/// Le réseau ne prélève que le nécessaire, jamais toute l'offre.
const MAX_FEE_STROOPS: u32 = 1_000_000;
/// Validité d'une transaction après la fermeture du dernier registre.
const VALIDITY_SECS: u64 = 180;

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("openpgp-wallet")
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Lecture Horizon ; `None` pour une ressource inexistante (404).
fn get(net: &Network, path: &str) -> Result<Option<Value>> {
    let response = client().get(format!("{}{path}", net.horizon)).send().context("serveur Stellar injoignable")?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(status.is_success(), "serveur Stellar : réponse {status}");
    Ok(Some(response.json().context("réponse du serveur Stellar illisible")?))
}

/// « 12.3456789 » → stroops.
fn stroops(text: &str) -> Result<i64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    ensure!(!whole.is_empty() && whole.bytes().all(|b| b.is_ascii_digit()) && fraction.len() <= 7 && fraction.bytes().all(|b| b.is_ascii_digit()), "montant Stellar illisible");
    let fraction = format!("{fraction:0<7}");
    whole.parse::<i64>().ok().and_then(|w| w.checked_mul(10_000_000)).and_then(|w| w.checked_add(fraction.parse::<i64>().ok()?)).context("montant Stellar illisible")
}

/// Montant en XLM, 7 décimales (« 12.5000000 »).
pub fn format_xlm(stroops: i64) -> String {
    let sign = if stroops < 0 { "-" } else { "" };
    let abs = stroops.unsigned_abs();
    format!("{sign}{}.{:07}", abs / 10_000_000, abs % 10_000_000)
}

// --- Adresses (StrKey) ---------------------------------------------------------------

const VERSION_ACCOUNT: u8 = 6 << 3; // G…
const VERSION_SECRET: u8 = 18 << 3; // S…
const VERSION_MUXED: u8 = 12 << 3; // M…
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = BASE32.iter().position(|&b| b == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

pub fn encode_address(public_key: &[u8; 32]) -> String {
    let mut data = vec![VERSION_ACCOUNT];
    data.extend_from_slice(public_key);
    data.extend_from_slice(&crc16_xmodem(&data).to_le_bytes());
    base32_encode(&data)
}

/// Adresse G…, somme de contrôle et clé vérifiées. Adresses muxées (M…)
/// refusées ; une clé SECRÈTE (S…) collée par erreur est signalée.
pub fn parse_address(text: &str) -> Result<[u8; 32]> {
    let text = text.trim();
    ensure!(strkey_version(text, 35) != Some(VERSION_SECRET), "ceci est une clé secrète Stellar (S…), pas une adresse : ne la communiquez jamais");
    ensure!(strkey_version(text, 43) != Some(VERSION_MUXED), "adresse Stellar « M… » (muxée) non prise en charge : demandez l'adresse G… et le mémo");
    ensure!(text.len() == 56 && text.starts_with('G'), "adresse Stellar invalide");
    let data = base32_decode(text).filter(|d| d.len() == 35).context("adresse Stellar invalide")?;
    // Forme canonique seulement (bits de remplissage nuls).
    ensure!(base32_encode(&data) == text, "adresse Stellar invalide");
    let (body, check) = data.split_at(33);
    ensure!(crc16_xmodem(body).to_le_bytes() == *check, "adresse Stellar invalide (somme de contrôle)");
    ensure!(body[0] == VERSION_ACCOUNT, "adresse Stellar invalide");
    let key: [u8; 32] = body[1..].try_into().map_err(|_| anyhow!("adresse Stellar invalide"))?;
    // Une clé hors de la courbe ne serait contrôlée par personne.
    ensure!(ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok(), "adresse Stellar invalide");
    Ok(key)
}

/// Octet de version d'une clé StrKey valide (taille et somme de contrôle
/// vérifiées), pour reconnaître une clé secrète ou une adresse muxée.
fn strkey_version(text: &str, len: usize) -> Option<u8> {
    let data = base32_decode(text).filter(|d| d.len() == len && base32_encode(d) == text)?;
    let (body, check) = data.split_at(len - 2);
    (crc16_xmodem(body).to_le_bytes() == *check).then_some(body[0])
}

// --- Mémo ---------------------------------------------------------------------------

/// Mémo d'un paiement (exigé par les plateformes d'échange).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Memo {
    None,
    /// Identifiant numérique (MEMO_ID).
    Id(u64),
    /// Texte (MEMO_TEXT), 28 octets au plus.
    Text(String),
}

/// Mémo saisi : vide = aucun ; chiffres seulement = identifiant ; sinon texte.
pub fn parse_memo(text: Option<&str>) -> Result<Memo> {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else { return Ok(Memo::None) };
    if text.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(id) = text.parse::<u64>() {
            return Ok(Memo::Id(id));
        }
    }
    ensure!(text.len() <= 28, "mémo Stellar trop long (28 caractères au plus)");
    // ASCII imprimable seulement : rien d'invisible ni de retourné dans la
    // boîte de confirmation (les plateformes d'échange n'utilisent que ça).
    ensure!(text.bytes().all(|b| (0x20..=0x7e).contains(&b)), "mémo Stellar invalide (lettres, chiffres et ponctuation ASCII seulement)");
    Ok(Memo::Text(text.to_string()))
}

impl Memo {
    pub fn is_none(&self) -> bool {
        *self == Memo::None
    }
}

// --- Transaction (XDR) -------------------------------------------------------------------

#[derive(Default)]
struct Xdr(Vec<u8>);

impl Xdr {
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self.0.resize(self.0.len() + (4 - bytes.len() % 4) % 4, 0);
        self
    }
    fn var(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(bytes.len() as u32).fixed(bytes)
    }
    /// Compte : clé ed25519 (type 0).
    fn account(&mut self, key: &[u8; 32]) -> &mut Self {
        self.u32(0).fixed(key)
    }
}

/// Opération unique de la transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Destinataire jamais activé : compte créé avec ce solde de départ.
    CreateAccount { destination: [u8; 32], starting_balance: i64 },
    /// Paiement de XLM (actif natif).
    Payment { destination: [u8; 32], amount: i64 },
}

pub struct Transaction {
    pub source: [u8; 32],
    pub fee: u32,
    pub sequence: i64,
    pub max_time: u64,
    pub memo: Memo,
    pub operation: Operation,
}

const ENVELOPE_TYPE_TX: u32 = 2;

impl Transaction {
    fn body(&self) -> Vec<u8> {
        let mut x = Xdr::default();
        x.account(&self.source).u32(self.fee).i64(self.sequence);
        // Préconditions : bornes de temps (PRECOND_TIME).
        x.u32(1).u64(0).u64(self.max_time);
        match &self.memo {
            Memo::None => x.u32(0),
            Memo::Text(text) => x.u32(1).var(text.as_bytes()),
            Memo::Id(id) => x.u32(2).u64(*id),
        };
        // Une opération, sans compte source propre.
        x.u32(1).u32(0);
        match self.operation {
            Operation::CreateAccount { destination, starting_balance } => x.u32(0).u32(0).fixed(&destination).i64(starting_balance),
            Operation::Payment { destination, amount } => x.u32(1).account(&destination).u32(0).i64(amount),
        };
        x.u32(0); // ext
        x.0
    }

    /// Condensé signé : SHA-256(id du réseau ‖ ENVELOPE_TYPE_TX ‖ transaction).
    fn hash(&self, net: &Network) -> [u8; 32] {
        let mut base = Sha256::digest(net.passphrase.as_bytes()).to_vec();
        base.extend_from_slice(&ENVELOPE_TYPE_TX.to_be_bytes());
        base.extend_from_slice(&self.body());
        Sha256::digest(&base).into()
    }
}

pub struct Signed {
    pub envelope: Vec<u8>,
    pub hash: String,
}

pub fn sign(tx: &Transaction, key: &SigningKey, net: &Network) -> Signed {
    let hash = tx.hash(net);
    let signature = key.sign(&hash);
    let public = key.verifying_key().to_bytes();
    let mut x = Xdr::default();
    x.u32(ENVELOPE_TYPE_TX).fixed(&tx.body());
    // Une signature : indice (4 derniers octets de la clé publique) + 64 octets.
    x.u32(1).fixed(&public[28..]).var(&signature.to_bytes());
    Signed { envelope: x.0, hash: hex::encode(hash) }
}

// --- Compte et réseau ----------------------------------------------------------------------

struct AccountState {
    balance: i64,
    sequence: i64,
    /// Objets comptés dans la réserve (lignes de confiance, offres…).
    reserve_entries: i64,
    selling_liabilities: i64,
    memo_required: bool,
}

fn account_state(net: &Network, address: &str) -> Result<Option<AccountState>> {
    parse_address(address)?;
    let Some(value) = get(net, &format!("/accounts/{}", address.trim()))? else { return Ok(None) };
    let native = value["balances"].as_array().and_then(|b| b.iter().find(|b| b["asset_type"].as_str() == Some("native"))).context("solde Stellar illisible")?;
    let count = |field: &str| value[field].as_i64().unwrap_or(0);
    Ok(Some(AccountState {
        balance: stroops(native["balance"].as_str().context("solde Stellar illisible")?)?,
        sequence: value["sequence"].as_str().and_then(|s| s.parse().ok()).context("séquence Stellar illisible")?,
        reserve_entries: 2 + count("subentry_count") + count("num_sponsoring") - count("num_sponsored"),
        selling_liabilities: native["selling_liabilities"].as_str().map(stroops).transpose()?.unwrap_or(0),
        // SEP-29 : donnée « config.memo_required » = « 1 ».
        memo_required: value["data"]["config.memo_required"].as_str() == Some("MQ=="),
    }))
}

struct Ledger {
    base_reserve: i64,
    base_fee: u32,
    closed_at: u64,
}

fn latest_ledger(net: &Network) -> Result<Ledger> {
    let value = get(net, "/ledgers?order=desc&limit=1")?.context("registre Stellar illisible")?;
    let ledger = &value["_embedded"]["records"][0];
    Ok(Ledger {
        base_reserve: ledger["base_reserve_in_stroops"].as_i64().context("réserve Stellar illisible")?,
        base_fee: ledger["base_fee_in_stroops"].as_u64().and_then(|f| u32::try_from(f).ok()).context("frais Stellar illisibles")?,
        closed_at: ledger["closed_at"].as_str().and_then(crate::blockscout::parse_iso8601_utc).and_then(|t| u64::try_from(t).ok()).context("registre Stellar illisible")?,
    })
}

/// Offre de frais : deux fois le 90ᵉ centile des frais payés récemment (au
/// moins les frais de base), plafonnée. Le réseau ne prélève que le
/// nécessaire, jamais plus que l'offre.
fn fee_bid(net: &Network, base_fee: u32) -> Result<u32> {
    let stats = get(net, "/fee_stats")?.context("frais Stellar illisibles")?;
    let p90 = stats["fee_charged"]["p90"].as_str().and_then(|f| f.parse::<u32>().ok()).context("frais Stellar illisibles")?;
    let bid = p90.saturating_mul(2).max(base_fee);
    ensure!(bid <= MAX_FEE_STROOPS, "frais du réseau Stellar anormalement élevés ({} XLM) — réessayez plus tard", format_xlm(i64::from(bid)));
    Ok(bid)
}

/// Solde total (stroops), réserve comprise ; 0 pour un compte non activé.
pub fn balance(net: &Network, address: &str) -> Result<i64> {
    Ok(account_state(net, address)?.map_or(0, |a| a.balance))
}

/// Activité d'une adresse destinataire : (détient des XLM, existe).
pub fn address_activity(net: &Network, address: &str) -> Result<(bool, bool)> {
    Ok(match account_state(net, address)? {
        Some(a) => (a.balance > 0, true),
        None => (false, false),
    })
}

/// Envoi préparé pour la boîte de confirmation.
#[derive(Clone, Copy, Debug)]
pub struct XlmPlan {
    pub amount: i64,
    /// Offre de frais (prélevés au plus).
    pub fee: u32,
    /// XLM bloqués par la réserve sur le compte de départ.
    pub reserve: i64,
    /// Destinataire jamais activé : le paiement le crée.
    pub creates: bool,
}

const NOT_ACTIVATED: &str = "compte Stellar pas encore activé : il doit d'abord recevoir au moins 1 XLM";

/// Contrôles du réseau (réserve, création, mémo exigé) et frais.
pub fn plan(net: &Network, from: &str, to: &str, amount: i64, memo: &Memo) -> Result<XlmPlan> {
    ensure!(amount > 0, "montant nul");
    ensure!(parse_address(from)? != parse_address(to)?, "envoi vers votre propre adresse Stellar");
    let ledger = latest_ledger(net)?;
    let sender = account_state(net, from)?.context(NOT_ACTIVATED)?;
    let reserve = sender.reserve_entries * ledger.base_reserve;
    let fee = fee_bid(net, ledger.base_fee)?;
    let spendable = sender.balance - reserve - sender.selling_liabilities;
    ensure!(
        amount.checked_add(i64::from(fee)).is_some_and(|need| need <= spendable),
        "XLM insuffisants : {} XLM envoyables ({} XLM restent bloqués par la réserve du réseau), {} XLM + {} XLM de frais demandés",
        format_xlm((spendable - i64::from(fee)).max(0)),
        format_xlm(reserve),
        format_xlm(amount),
        format_xlm(i64::from(fee))
    );
    let destination = account_state(net, to)?;
    match &destination {
        None => {
            let minimum = 2 * ledger.base_reserve;
            ensure!(amount >= minimum, "ce destinataire n'est pas encore activé : envoyez-lui au moins {} XLM (réserve du réseau)", format_xlm(minimum));
        }
        Some(d) => ensure!(!d.memo_required || !memo.is_none(), "ce destinataire exige un mémo (plateforme d'échange) : renseignez-le"),
    }
    Ok(XlmPlan { amount, fee, reserve, creates: destination.is_none() })
}

/// Plus grand montant envoyable : solde moins la réserve et les frais.
pub fn max_amount(net: &Network, from: &str) -> Result<i64> {
    let ledger = latest_ledger(net)?;
    let sender = account_state(net, from)?.context(NOT_ACTIVATED)?;
    let spendable = sender.balance - sender.reserve_entries * ledger.base_reserve - sender.selling_liabilities - i64::from(fee_bid(net, ledger.base_fee)?);
    ensure!(spendable > 0, "XLM insuffisants : tout le solde est bloqué par la réserve du réseau");
    Ok(spendable)
}

/// Construit, signe et diffuse l'envoi préparé ; renvoie son identifiant.
pub fn send(net: &Network, key: &SigningKey, to: &[u8; 32], plan: &XlmPlan, memo: Memo) -> Result<String> {
    ensure!(plan.fee <= MAX_FEE_STROOPS, "frais du réseau Stellar anormalement élevés — envoi refusé");
    let source = key.verifying_key().to_bytes();
    let state = account_state(net, &encode_address(&source))?.context(NOT_ACTIVATED)?;
    let ledger = latest_ledger(net)?;
    let operation = if plan.creates {
        Operation::CreateAccount { destination: *to, starting_balance: plan.amount }
    } else {
        Operation::Payment { destination: *to, amount: plan.amount }
    };
    let tx = Transaction { source, fee: plan.fee, sequence: state.sequence + 1, max_time: ledger.closed_at + VALIDITY_SECS, memo, operation };
    submit(net, &sign(&tx, key, net))
}

pub fn submit(net: &Network, signed: &Signed) -> Result<String> {
    let blob = base64::engine::general_purpose::STANDARD.encode(&signed.envelope);
    let response = client()
        .post(format!("{}/transactions", net.horizon))
        .form(&[("tx", blob)])
        .send()
        .map_err(|e| crate::wallet_flow::broadcast_failure(e, "serveur Stellar injoignable", &signed.hash))?;
    let status = response.status();
    // Délai dépassé côté Horizon : la transaction peut encore entrer dans le
    // registre — surtout pas présentée comme refusée.
    if status == reqwest::StatusCode::GATEWAY_TIMEOUT {
        bail!("réseau Stellar lent : transaction {} envoyée mais pas encore confirmée — vérifiez l'historique avant de renvoyer", signed.hash);
    }
    // Réponse illisible après acceptation, ou erreur de passerelle : peut-être
    // partie (voir `wallet_flow::maybe_sent`).
    let value: Value = match response.json() {
        Ok(value) => value,
        Err(_) if status.is_success() || crate::wallet_flow::server_error_may_have_sent(status) => return Err(crate::wallet_flow::maybe_sent(&signed.hash)),
        Err(_) => bail!("serveur Stellar : réponse {status}"),
    };
    if status.is_success() {
        ensure!(value["hash"].as_str() == Some(signed.hash.as_str()), "le serveur Stellar a renvoyé un autre identifiant de transaction");
        ensure!(value["successful"].as_bool() != Some(false), "transaction Stellar refusée : échouée dans le registre");
        return Ok(signed.hash.clone());
    }
    let codes = &value["extras"]["result_codes"];
    let mut detail: Vec<String> = codes["transaction"].as_str().map(str::to_string).into_iter().collect();
    detail.extend(codes["operations"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(Value::as_str).map(str::to_string));
    if detail.is_empty() {
        detail.push(value["title"].as_str().unwrap_or("erreur inconnue").to_string());
    }
    bail!("transaction Stellar refusée : {}", detail.join(" "))
}

// --- Historique ----------------------------------------------------------------------------

/// Paiements en XLM de l'adresse, les plus récents d'abord.
pub fn history(net: &Network, address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(address)?;
    let address = address.trim();
    let path = format!("/accounts/{address}/payments?order=desc&limit={}&join=transactions", limit.clamp(1, 100));
    let Some(value) = get(net, &path)? else { return Ok(Vec::new()) };
    let mut entries = Vec::new();
    for record in value["_embedded"]["records"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let (from, to, amount) = match record["type"].as_str() {
            Some("payment") if record["asset_type"].as_str() == Some("native") => (record["from"].as_str(), record["to"].as_str(), record["amount"].as_str()),
            Some("create_account") => (record["funder"].as_str(), record["account"].as_str(), record["starting_balance"].as_str()),
            _ => continue,
        };
        let Some(hash) = record["transaction_hash"].as_str().filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())) else { continue };
        let Some(amount) = amount.and_then(|a| stroops(a).ok()) else { continue };
        let outgoing = from == Some(address);
        if !outgoing && to != Some(address) {
            continue;
        }
        // Frais payés par le compte source de la transaction.
        let fee = if record["transaction"]["source_account"].as_str() == Some(address) {
            record["transaction"]["fee_charged"].as_str().and_then(|f| f.parse::<i64>().ok()).unwrap_or(0)
        } else {
            0
        };
        let success = record["transaction_successful"].as_bool() == Some(true);
        entries.push(history::TxEntry {
            id: hash.to_string(),
            timestamp_unix: record["created_at"].as_str().and_then(crate::blockscout::parse_iso8601_utc),
            status: if success { history::TxStatus::Confirmed } else { history::TxStatus::Failed },
            net_amount_minor: Some(if outgoing { -i128::from(amount) - i128::from(fee) } else { i128::from(amount) }),
            fee_minor: 0,
            kind: if outgoing { history::TxKind::Sent } else { history::TxKind::Received },
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn key(index: u32) -> SigningKey {
        crate::derivation::derive_stellar_key(&hex::decode(SEED).unwrap(), index)
    }

    /// Vecteur officiel de SEP-0005 (« illness spike … », compte 0) puis
    /// vecteurs de @stellar/stellar-base + ed25519-hd-key.
    #[test]
    fn addresses_match_sep5_and_the_official_library() {
        use bip39::Mnemonic;
        let illness = Mnemonic::parse("illness spike retreat truth genius clock brain pass fit cave bargain toe").unwrap().to_seed("");
        for (index, expected) in [(0, "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"), (1, "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX"), (2, "GAY5PRAHJ2HIYBYCLZXTHID6SPVELOOYH2LBPH3LD4RUMXUW3DOYTLXW")] {
            let k = crate::derivation::derive_stellar_key(&illness, index);
            assert_eq!(encode_address(&k.verifying_key().to_bytes()), expected, "illness {index}");
        }
        for (index, expected) in [(0, "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX"), (1, "GDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG42MV"), (7, "GAF4AGPVLQXFKEWQV3DZU5YEFU6YP7XJHAEEQH4G3R664MSF77FLLRK3")] {
            let public = key(index).verifying_key().to_bytes();
            assert_eq!(encode_address(&public), expected);
            assert_eq!(parse_address(expected).unwrap(), public);
        }
        assert!(parse_address("GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYY").is_err(), "somme de contrôle");
        assert!(parse_address("MDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG4AAAAAAAAAAAAU7YE").unwrap_err().to_string().contains("muxée"));
        assert!(parse_address("SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN").unwrap_err().to_string().contains("clé secrète"));
        assert!(parse_address("gb3jdwcqjcwmj3iilwigdtqjjc5567pgvevxscvpeqotdn64vjbdqbyx").is_err());
        // Commence par S ou M sans en être une : simple adresse invalide.
        for other in ["So11111111111111111111111111111111111111112", "MDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG4AAAAAAAAAAAAU7YF", "SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMM"] {
            assert_eq!(parse_address(other).unwrap_err().to_string(), "adresse Stellar invalide", "{other}");
        }
    }

    #[test]
    fn memos_are_parsed_strictly() {
        assert_eq!(parse_memo(None).unwrap(), Memo::None);
        assert_eq!(parse_memo(Some("  ")).unwrap(), Memo::None);
        assert_eq!(parse_memo(Some("12345")).unwrap(), Memo::Id(12345));
        assert_eq!(parse_memo(Some("hello")).unwrap(), Memo::Text("hello".into()));
        // Au-delà de u64 : texte (s'il tient en 28 octets).
        assert_eq!(parse_memo(Some("99999999999999999999")).unwrap(), Memo::Text("99999999999999999999".into()));
        assert!(parse_memo(Some("a".repeat(29).as_str())).is_err());
        assert!(parse_memo(Some("a\u{7}b")).is_err());
        assert!(parse_memo(Some("abc\u{202e}def")).is_err(), "retournement de texte");
        assert!(parse_memo(Some("é")).is_err());
    }

    /// Transactions identiques octet pour octet à @stellar/stellar-base
    /// (corps, condensé, enveloppe signée).
    #[test]
    fn transactions_match_the_official_library() {
        let (source, destination) = (key(0).verifying_key().to_bytes(), key(1).verifying_key().to_bytes());
        let payment = Transaction { source, fee: 100, sequence: 123_456_789_013, max_time: 1_760_000_000, memo: Memo::Id(12345), operation: Operation::Payment { destination, amount: 15_000_000 } };
        assert_eq!(hex::encode(payment.body()), "000000007691d85048acc4ed085d9061ce0948bbdf7de6a92b790aaf241d31b7dcaa4238000000640000001cbe991a150000000100000000000000000000000068e7780000000002000000000000303900000001000000000000000100000000eb2c62740276011e6f8365380470e2c678098dc70a2240fd9a68c9497684a66e000000000000000000e4e1c000000000");
        assert_eq!(hex::encode(payment.hash(&MAINNET)), "19826e03f21946276a9ab54bc014c2eda87b7f6b46ab403db1bcea0277984637");
        let signed = sign(&payment, &key(0), &MAINNET);
        assert_eq!(hex::encode(&signed.envelope), "00000002000000007691d85048acc4ed085d9061ce0948bbdf7de6a92b790aaf241d31b7dcaa4238000000640000001cbe991a150000000100000000000000000000000068e7780000000002000000000000303900000001000000000000000100000000eb2c62740276011e6f8365380470e2c678098dc70a2240fd9a68c9497684a66e000000000000000000e4e1c00000000000000001dcaa423800000040bc560adfd4e0ddc4c5fdec217e1235ee0ec42897ed3249de7ea517e01259a62ee0eabfddceca355b48c00915ab11aaf306c4fea533637ca856b632d4a270b708");
        assert_eq!(signed.hash, "19826e03f21946276a9ab54bc014c2eda87b7f6b46ab403db1bcea0277984637");

        let create = Transaction { source, fee: 100, sequence: 43, max_time: 1_760_000_000, memo: Memo::Text("hello".into()), operation: Operation::CreateAccount { destination, starting_balance: 10_000_000 } };
        assert_eq!(hex::encode(create.body()), "000000007691d85048acc4ed085d9061ce0948bbdf7de6a92b790aaf241d31b7dcaa423800000064000000000000002b0000000100000000000000000000000068e77800000000010000000568656c6c6f00000000000001000000000000000000000000eb2c62740276011e6f8365380470e2c678098dc70a2240fd9a68c9497684a66e000000000098968000000000");
        assert_eq!(hex::encode(&sign(&create, &key(0), &MAINNET).envelope), "00000002000000007691d85048acc4ed085d9061ce0948bbdf7de6a92b790aaf241d31b7dcaa423800000064000000000000002b0000000100000000000000000000000068e77800000000010000000568656c6c6f00000000000001000000000000000000000000eb2c62740276011e6f8365380470e2c678098dc70a2240fd9a68c9497684a66e00000000009896800000000000000001dcaa4238000000404d01fac7427a1856247e28dc2f195378d491b05ed1728d97ee96c86d2c6e3ee9ef53d1ee218c36d2bb5bc0f539b0e026cc504747c0e8a15df73d219497d5f807");

        let none = Transaction { source, fee: 100, sequence: 8, max_time: 1_760_000_000, memo: Memo::None, operation: Operation::Payment { destination, amount: 1 } };
        assert_eq!(hex::encode(none.hash(&MAINNET)), "fcbb259a56027a9de8dbe1b4198b7c7202f1255aac06786f02d7126ecd923d05");
    }

    #[test]
    fn amounts_round_trip() {
        assert_eq!(stroops("12.3456789").unwrap(), 123_456_789);
        assert_eq!(stroops("1").unwrap(), 10_000_000);
        assert_eq!(stroops("0.0000001").unwrap(), 1);
        assert!(stroops("1.00000001").is_err() && stroops("-1").is_err() && stroops("").is_err() && stroops("1e5").is_err());
        assert_eq!(format_xlm(123_456_789), "12.3456789");
        assert_eq!(format_xlm(-5), "-0.0000005");
    }

    /// Réel, réseau de test (fonds gratuits du friendbot) : création d'un
    /// compte puis paiement avec mémo, signés ici et acceptés par le réseau ;
    /// signature altérée refusée. Lectures du réseau principal.
    /// `cargo test -- --ignored real_stellar --nocapture`
    #[test]
    #[ignore]
    fn real_stellar_testnet_end_to_end() {
        let alice = SigningKey::from_bytes(&[0x51; 32]);
        let alice_address = encode_address(&alice.verifying_key().to_bytes());
        if account_state(&TESTNET, &alice_address).unwrap().is_none() {
            let funded = client().get(format!("https://friendbot.stellar.org/?addr={alice_address}")).send().unwrap();
            println!("friendbot : {}", funded.status());
        }
        // Destinataire neuf à chaque passage : création, puis paiement.
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let bob = SigningKey::from_bytes(&seed);
        let bob_key = bob.verifying_key().to_bytes();
        let bob_address = encode_address(&bob_key);
        let error = plan(&TESTNET, &alice_address, &bob_address, 9_999_999, &Memo::None).unwrap_err().to_string();
        assert!(error.contains("au moins 1.0000000 XLM"), "{error}");
        let first = plan(&TESTNET, &alice_address, &bob_address, 15_000_000, &Memo::None).unwrap();
        assert!(first.creates, "{first:?}");
        let created = send(&TESTNET, &alice, &bob_key, &first, Memo::None).unwrap();
        println!("création : {created}");
        assert_eq!(balance(&TESTNET, &bob_address).unwrap(), 15_000_000);
        let second = plan(&TESTNET, &alice_address, &bob_address, 2_500_000, &Memo::Id(12345)).unwrap();
        assert!(!second.creates);
        let paid = send(&TESTNET, &alice, &bob_key, &second, Memo::Id(12345)).unwrap();
        println!("paiement : {paid}");
        let tx = get(&TESTNET, &format!("/transactions/{paid}")).unwrap().unwrap();
        assert_eq!((tx["memo_type"].as_str(), tx["memo"].as_str(), tx["successful"].as_bool()), (Some("id"), Some("12345"), Some(true)));
        assert_eq!(balance(&TESTNET, &bob_address).unwrap(), 17_500_000);
        let received = history(&TESTNET, &bob_address, 10).unwrap();
        assert_eq!(received.len(), 2, "historique du destinataire");
        assert!(received.iter().all(|e| e.kind == history::TxKind::Received));
        assert!(history(&TESTNET, &alice_address, 10).unwrap().iter().any(|e| e.id == paid && e.net_amount_minor.is_some_and(|n| n <= -2_500_000)));
        // Signature altérée : refusée par le réseau.
        let state = account_state(&TESTNET, &alice_address).unwrap().unwrap();
        let ledger = latest_ledger(&TESTNET).unwrap();
        let tx = Transaction { source: alice.verifying_key().to_bytes(), fee: 100, sequence: state.sequence + 1, max_time: ledger.closed_at + 180, memo: Memo::None, operation: Operation::Payment { destination: bob_key, amount: 1 } };
        let mut signed = sign(&tx, &alice, &TESTNET);
        let last = signed.envelope.len() - 1;
        signed.envelope[last] ^= 1;
        let error = submit(&TESTNET, &signed).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("tx_bad_auth"), "{error}");
        // Réseau principal : lectures.
        let fees = latest_ledger(&MAINNET).unwrap();
        println!("principal : réserve {} XLM, frais de base {} stroops, offre {} stroops", format_xlm(fees.base_reserve), fees.base_fee, fee_bid(&MAINNET, fees.base_fee).unwrap());
    }
}
