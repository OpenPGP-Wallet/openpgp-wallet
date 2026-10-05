//! Dogecoin : adresse D… (P2PKH, BIP44 m/44'/3'/0'/0/p), solde, envoi,
//! historique.
//!
//! Services publics sans clé :
//! - Bitcore (BitPay) : solde, sorties dépensables, historique, estimation des
//!   frais, diffusion ;
//! - transactions d'origine BRUTES (Blockcypher, Blockchair en secours) au
//!   moment d'un envoi : la signature historique de Dogecoin (pas de SegWit)
//!   n'engage PAS le montant des entrées — un service qui mentirait sur la
//!   valeur d'une sortie ferait partir la différence en frais. Chaque entrée
//!   est relue dans sa transaction d'origine, dont le hash est recalculé
//!   (= son identifiant) : montant et script vérifiés, rien n'est repris de
//!   l'API pour ce qui est signé.
//!
//! Transactions construites et signées ici : condensé SIGHASH_ALL historique
//! (vérifié contre les vecteurs de Bitcoin Core), signatures low-S.

use crate::{btc_tx, history};
use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const BITCORE: &str = "https://api.bitcore.io/api/DOGE/mainnet";
const P2PKH_VERSION: u8 = 0x1e;
const P2SH_VERSION: u8 = 0x16;
pub const DECIMALS: u8 = 8;
/// Plus petite sortie relayée (0,01 DOGE) : montant refusé en dessous,
/// monnaie ajoutée aux frais en dessous.
const DUST: u64 = 1_000_000;
/// Frais (koinus par ko) : estimation du service, bornée (0,01 à 5 DOGE/ko).
const MIN_FEE_PER_KB: u64 = 1_000_000;
const MAX_FEE_PER_KB: u64 = 500_000_000;
const SIGHASH_ALL: u32 = 1;
/// Entrées au plus par transaction : au-delà de ~100 ko, une transaction
/// n'est plus relayée par les nœuds (148 octets par entrée P2PKH).
const MAX_INPUTS: usize = 600;

/// Montant en DOGE, 8 décimales (« 12.50000000 »).
pub fn format_doge(koinus: u64) -> String {
    format!("{}.{:08}", koinus / 100_000_000, koinus % 100_000_000)
}

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

fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T> {
    let response = client().get(url).send().context("service Dogecoin injoignable")?;
    let status = response.status();
    ensure!(status.is_success(), "service Dogecoin : réponse {status}");
    response.json().context("réponse du service Dogecoin illisible")
}

// --- Adresses ----------------------------------------------------------------------

fn base58check(version: u8, payload: &[u8]) -> String {
    let mut data = vec![version];
    data.extend_from_slice(payload);
    let check = btc_tx::dsha256(&data);
    data.extend_from_slice(&check[..4]);
    bs58::encode(data).into_string()
}

pub fn p2pkh_address(hash160: &[u8; 20]) -> String {
    base58check(P2PKH_VERSION, hash160)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
}

impl Recipient {
    fn script(&self) -> Vec<u8> {
        match self {
            Recipient::P2pkh(hash) => p2pkh_script(hash),
            Recipient::P2sh(hash) => [&[0xa9, 0x14][..], hash, &[0x87]].concat(),
        }
    }
}

fn p2pkh_script(hash160: &[u8; 20]) -> Vec<u8> {
    [&[0x76, 0xa9, 0x14][..], hash160, &[0x88, 0xac]].concat()
}

/// Adresse Dogecoin du réseau principal (D… ou 9…/A… pour P2SH), somme de
/// contrôle vérifiée.
pub fn parse_recipient(address: &str) -> Result<Recipient> {
    let data = bs58::decode(address.trim()).into_vec().map_err(|_| anyhow!("adresse Dogecoin invalide"))?;
    ensure!(data.len() == 25, "adresse Dogecoin invalide");
    let (body, check) = data.split_at(21);
    ensure!(btc_tx::dsha256(body)[..4] == *check, "adresse Dogecoin invalide (somme de contrôle)");
    let hash: [u8; 20] = body[1..].try_into().map_err(|_| anyhow!("adresse Dogecoin invalide"))?;
    match body[0] {
        P2PKH_VERSION => Ok(Recipient::P2pkh(hash)),
        P2SH_VERSION => Ok(Recipient::P2sh(hash)),
        _ => bail!("adresse Dogecoin invalide (autre réseau ou autre crypto)"),
    }
}

// --- Transaction historique (non SegWit) -------------------------------------------

#[derive(Clone)]
struct TxIn {
    /// Identifiant de la transaction d'origine, dans l'ordre sérialisé
    /// (inverse de l'affichage).
    prev: [u8; 32],
    vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

#[derive(Clone)]
struct LegacyTx {
    version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<(u64, Vec<u8>)>,
    locktime: u32,
}

impl LegacyTx {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        btc_tx::push_varint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prev);
            out.extend_from_slice(&input.vout.to_le_bytes());
            btc_tx::push_varint(&mut out, input.script_sig.len() as u64);
            out.extend_from_slice(&input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        btc_tx::push_varint(&mut out, self.outputs.len() as u64);
        for (value, script) in &self.outputs {
            out.extend_from_slice(&value.to_le_bytes());
            btc_tx::push_varint(&mut out, script.len() as u64);
            out.extend_from_slice(script);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// Condensé historique de l'entrée `index` (SIGHASH_ALL : entrées et
    /// sorties toutes engagées ; script de l'entrée signée à la place de son
    /// scriptSig, les autres vides).
    fn sighash(&self, index: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
        let mut copy = self.clone();
        for (i, input) in copy.inputs.iter_mut().enumerate() {
            input.script_sig = if i == index { script_code.to_vec() } else { Vec::new() };
        }
        let mut preimage = copy.serialize();
        preimage.extend_from_slice(&hash_type.to_le_bytes());
        btc_tx::dsha256(&preimage)
    }
}

/// Lecteur minimal d'une transaction historique sérialisée.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.data.len()).context("transaction Dogecoin tronquée")?;
        let slice = &self.data[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| anyhow!("transaction Dogecoin tronquée"))?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| anyhow!("transaction Dogecoin tronquée"))?))
    }
    fn varint(&mut self) -> Result<u64> {
        let first = self.take(1)?[0];
        Ok(match first {
            0xfd => u64::from(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| anyhow!("transaction Dogecoin tronquée"))?)),
            0xfe => u64::from(self.u32()?),
            0xff => self.u64()?,
            n => u64::from(n),
        })
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = usize::try_from(self.varint()?).context("transaction Dogecoin invalide")?;
        Ok(self.take(len)?.to_vec())
    }
}

fn parse_tx(raw: &[u8]) -> Result<LegacyTx> {
    let mut r = Reader { data: raw, at: 0 };
    let version = r.u32()?;
    let n_in = r.varint()?;
    ensure!(n_in > 0 && n_in < 10_000, "transaction Dogecoin invalide");
    let mut inputs = Vec::new();
    for _ in 0..n_in {
        let prev: [u8; 32] = r.take(32)?.try_into().map_err(|_| anyhow!("transaction Dogecoin tronquée"))?;
        let vout = r.u32()?;
        let script_sig = r.bytes()?;
        let sequence = r.u32()?;
        inputs.push(TxIn { prev, vout, script_sig, sequence });
    }
    let n_out = r.varint()?;
    ensure!(n_out < 100_000, "transaction Dogecoin invalide");
    let mut outputs = Vec::new();
    for _ in 0..n_out {
        let value = r.u64()?;
        outputs.push((value, r.bytes()?));
    }
    let locktime = r.u32()?;
    ensure!(r.at == raw.len(), "transaction Dogecoin invalide (octets en trop)");
    Ok(LegacyTx { version, inputs, outputs, locktime })
}

fn txid_hex(raw: &[u8]) -> String {
    let mut hash = btc_tx::dsha256(raw);
    hash.reverse();
    hex::encode(hash)
}

// --- Envoi -------------------------------------------------------------------------

/// Sortie dépensable de l'adresse (identifiant dans l'ordre d'affichage).
#[derive(Clone, Debug)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

#[derive(Debug)]
pub struct SendPlan {
    pub inputs: Vec<Utxo>,
    pub amount: u64,
    pub fee: u64,
    /// Rendu à sa propre adresse (0 : pas de sortie de monnaie).
    pub change: u64,
}

fn estimated_size(inputs: usize, outputs: usize) -> u64 {
    10 + 148 * inputs as u64 + 34 * outputs as u64
}

fn fee_for(size: u64, fee_per_kb: u64) -> u64 {
    size.saturating_mul(fee_per_kb).div_ceil(1000)
}

/// Choisit les sorties (les plus grosses d'abord) pour `amount` koinus, frais
/// compris au taux `fee_per_kb` ; une monnaie sous la poussière va aux frais.
pub fn plan_send(mut utxos: Vec<Utxo>, amount: u64, fee_per_kb: u64) -> Result<SendPlan> {
    ensure!(amount >= DUST, "montant trop petit : 0,01 DOGE au moins");
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));
    // Annoncé en cas de refus : le plus grand montant envoyable.
    let sendable = max_amount(&utxos, fee_per_kb).unwrap_or(0);
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for utxo in utxos.into_iter().take(MAX_INPUTS) {
        total = total.checked_add(utxo.value).context("montant hors limites")?;
        inputs.push(utxo);
        let with_change = fee_for(estimated_size(inputs.len(), 2), fee_per_kb);
        let without = fee_for(estimated_size(inputs.len(), 1), fee_per_kb);
        // `checked_add` : un montant proche de u64::MAX ne doit jamais
        // s'enrouler en un besoin minuscule.
        if let Some(change) = amount.checked_add(with_change).and_then(|need| total.checked_sub(need)).filter(|c| *c >= DUST) {
            return Ok(SendPlan { inputs, amount, fee: with_change, change });
        }
        if amount.checked_add(without).is_some_and(|need| total >= need) {
            return Ok(SendPlan { inputs, amount, fee: total - amount, change: 0 });
        }
    }
    bail!("DOGE insuffisants : {} DOGE demandés, {} DOGE envoyables au plus (frais déduits)", format_doge(amount), format_doge(sendable))
}

/// Plus grand montant envoyable en une sortie, sans monnaie, au taux
/// `fee_per_kb` : meilleur choix des k plus grosses sorties (une sortie plus
/// petite que ce qu'elle coûte en frais est laissée de côté).
pub fn max_amount(utxos: &[Utxo], fee_per_kb: u64) -> Result<u64> {
    let mut values: Vec<u64> = utxos.iter().map(|u| u.value).collect();
    values.sort_unstable_by(|a, b| b.cmp(a));
    let (mut total, mut best) = (0u64, 0u64);
    for (index, value) in values.iter().take(MAX_INPUTS).enumerate() {
        total = total.saturating_add(*value);
        best = best.max(total.saturating_sub(fee_for(estimated_size(index + 1, 1), fee_per_kb)));
    }
    ensure!(best >= DUST, "DOGE insuffisants pour couvrir les frais du réseau");
    Ok(best)
}

pub struct Signed {
    pub raw: Vec<u8>,
    pub txid: String,
}

/// Transaction signée du plan : destinataire, puis monnaie à soi.
pub fn build_signed(plan: &SendPlan, key: &SigningKey, own_hash160: &[u8; 20], recipient: &Recipient) -> Result<Signed> {
    let own_script = p2pkh_script(own_hash160);
    let mut outputs = vec![(plan.amount, recipient.script())];
    if plan.change > 0 {
        outputs.push((plan.change, own_script.clone()));
    }
    let mut inputs = Vec::new();
    for utxo in &plan.inputs {
        let mut prev: [u8; 32] = hex::decode(&utxo.txid).ok().and_then(|b| b.try_into().ok()).context("identifiant de transaction Dogecoin invalide")?;
        prev.reverse();
        inputs.push(TxIn { prev, vout: utxo.vout, script_sig: Vec::new(), sequence: 0xffff_ffff });
    }
    let mut tx = LegacyTx { version: 1, inputs, outputs, locktime: 0 };
    let pubkey = key.verifying_key().to_encoded_point(true);
    let mut script_sigs = Vec::new();
    for index in 0..tx.inputs.len() {
        let digest = tx.sighash(index, &own_script, SIGHASH_ALL);
        let signature: Signature = key.sign_prehash(&digest).map_err(|e| anyhow!("signature Dogecoin impossible ({e})"))?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut der = signature.to_der().as_bytes().to_vec();
        der.push(SIGHASH_ALL as u8);
        let mut script = Vec::new();
        script.push(der.len() as u8);
        script.extend_from_slice(&der);
        script.push(pubkey.as_bytes().len() as u8);
        script.extend_from_slice(pubkey.as_bytes());
        script_sigs.push(script);
    }
    for (input, script) in tx.inputs.iter_mut().zip(script_sigs) {
        input.script_sig = script;
    }
    let raw = tx.serialize();
    Ok(Signed { txid: txid_hex(&raw), raw })
}

// --- Services ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Coin {
    mint_txid: String,
    mint_index: u32,
    mint_height: i64,
    spent_txid: String,
    spent_height: i64,
    value: u64,
}

/// Hauteur de dépense Bitcore d'une sortie libre, et d'une sortie dont la
/// dépense attend d'être minée.
const UNSPENT: i64 = -2;
const SPEND_PENDING: i64 = -1;

/// Adresse vérifiée (base58 et somme de contrôle) avant d'entrer dans une URL :
/// les commandes de la carte la reçoivent de l'interface.
fn checked(address: &str) -> Result<&str> {
    parse_recipient(address)?;
    Ok(address.trim())
}

/// Identifiant de transaction tel qu'affiché : 64 caractères hexadécimaux
/// minuscules (ceux du service, avant d'entrer dans une URL ou un lien).
fn is_txid(txid: &str) -> bool {
    txid.len() == 64 && txid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sorties non dépensées de l'adresse (les 1 000 plus récentes), y compris
/// celles en attente (reçues ou en cours de dépense).
fn coins(address: &str) -> Result<Vec<Coin>> {
    get_json(&format!("{BITCORE}/address/{}/?unspent=true&limit=1000", checked(address)?))
}

#[derive(Deserialize)]
struct Totals {
    confirmed: i64,
    unconfirmed: i64,
}

fn totals(address: &str) -> Result<Totals> {
    get_json(&format!("{BITCORE}/address/{}/balance", checked(address)?))
}

/// Solde (koinus) : total du service (réceptions en attente comprises), moins
/// les sorties en cours de dépense, qu'il compte encore jusqu'au bloc suivant.
pub fn balance(address: &str) -> Result<u64> {
    let totals = totals(address)?;
    let being_spent = coins(address)?.iter().filter(|c| c.spent_height == SPEND_PENDING).fold(0u64, |sum, c| sum.saturating_add(c.value));
    Ok(u64::try_from(totals.confirmed.saturating_add(totals.unconfirmed)).unwrap_or(0).saturating_sub(being_spent))
}

/// Lecture comparée par la surveillance en direct (`balance_watch`) : totaux
/// confirmé et en attente — tout envoi ou réception les change dès sa
/// diffusion, puis à son bloc.
pub fn watch_reading(address: &str) -> Result<String> {
    let totals = totals(address)?;
    Ok(format!("{}:{}", totals.confirmed, totals.unconfirmed))
}

/// Envoi ou réception pas encore miné (la carte se rafraîchit plus souvent).
pub fn has_pending(address: &str) -> Result<bool> {
    Ok(totals(address)?.unconfirmed != 0 || coins(address)?.iter().any(|c| c.mint_height <= 0 || c.spent_height == SPEND_PENDING))
}

/// Activité d'une adresse destinataire : (détient des fonds, a déjà servi).
pub fn address_activity(address: &str) -> Result<(bool, bool)> {
    if coins(address)?.iter().any(|c| c.spent_height == UNSPENT && c.value > 0) {
        return Ok((true, true));
    }
    let used: Vec<serde_json::Value> = get_json(&format!("{BITCORE}/address/{}/txs?limit=1", checked(address)?))?;
    Ok((false, !used.is_empty()))
}

/// Sorties CONFIRMÉES et libres (ni en attente de dépense).
pub fn utxos(address: &str) -> Result<Vec<Utxo>> {
    coins(address)?
        .into_iter()
        .filter(|c| c.mint_height > 0 && c.spent_height == UNSPENT)
        .map(|c| {
            ensure!(is_txid(&c.mint_txid), "identifiant de transaction Dogecoin invalide");
            Ok(Utxo { txid: c.mint_txid, vout: c.mint_index, value: c.value })
        })
        .collect()
}

#[derive(Deserialize)]
struct FeeEstimate {
    feerate: f64,
}

/// Taux de frais (koinus par ko) : estimation du service, bornée.
pub fn fee_per_kb() -> Result<u64> {
    let estimate: FeeEstimate = get_json(&format!("{BITCORE}/fee/2"))?;
    let koinus = if estimate.feerate.is_finite() && estimate.feerate > 0.0 { (estimate.feerate * 1e8) as u64 } else { MIN_FEE_PER_KB };
    Ok(koinus.clamp(MIN_FEE_PER_KB, MAX_FEE_PER_KB))
}

/// Transaction brute d'origine, hash recalculé : Blockcypher, Blockchair en
/// secours.
fn raw_transaction(txid: &str) -> Result<Vec<u8>> {
    ensure!(is_txid(txid), "identifiant de transaction Dogecoin invalide");
    #[derive(Deserialize)]
    struct Blockcypher {
        hex: String,
    }
    let from_blockcypher = || -> Result<Vec<u8>> {
        let tx: Blockcypher = get_json(&format!("https://api.blockcypher.com/v1/doge/main/txs/{txid}?includeHex=true&limit=1"))?;
        hex::decode(tx.hex).context("transaction Dogecoin illisible")
    };
    let from_blockchair = || -> Result<Vec<u8>> {
        let value: serde_json::Value = get_json(&format!("https://api.blockchair.com/dogecoin/raw/transaction/{txid}"))?;
        let raw = value["data"][txid]["raw_transaction"].as_str().context("transaction Dogecoin introuvable")?;
        hex::decode(raw).context("transaction Dogecoin illisible")
    };
    let raw = from_blockcypher().or_else(|_| from_blockchair())?;
    ensure!(txid_hex(&raw) == txid, "transaction d'origine falsifiée (hash différent de son identifiant) — envoi refusé");
    Ok(raw)
}

/// Sorties des transactions d'origine déjà relues et vérifiées (immuables :
/// leur identifiant est leur hash) — la préparation puis l'envoi relisent les
/// mêmes, les services sans clé limitent le nombre de requêtes.
type Outputs = Vec<(u64, Vec<u8>)>;
static VERIFIED_OUTPUTS: Mutex<Option<HashMap<String, Outputs>>> = Mutex::new(None);

fn verified_outputs(txid: &str) -> Result<Outputs> {
    if let Some(outputs) = VERIFIED_OUTPUTS.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|m| m.get(txid)) {
        return Ok(outputs.clone());
    }
    let outputs = parse_tx(&raw_transaction(txid)?)?.outputs;
    VERIFIED_OUTPUTS.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).insert(txid.to_string(), outputs.clone());
    Ok(outputs)
}

/// Chaque entrée relue dans sa transaction d'origine : sortie à SA propre
/// adresse, montant exact — la signature historique n'engage pas les montants.
fn verify_inputs(inputs: &[Utxo], own_hash160: &[u8; 20]) -> Result<()> {
    let own_script = p2pkh_script(own_hash160);
    for utxo in inputs {
        let outputs = verified_outputs(&utxo.txid)?;
        let (value, script) = outputs.get(utxo.vout as usize).context("sortie Dogecoin introuvable dans sa transaction d'origine")?;
        ensure!(*script == own_script, "sortie Dogecoin qui n'appartient pas à votre adresse — envoi refusé");
        ensure!(*value == utxo.value, "montant d'une sortie Dogecoin annoncé faux par le service — envoi refusé");
    }
    Ok(())
}

/// Plan d'envoi depuis `own_hash160` (adresse du profil) : sorties relues,
/// vérifiées sur leur transaction d'origine, frais estimés.
pub fn plan(own_hash160: &[u8; 20], amount: u64) -> Result<SendPlan> {
    let plan = plan_send(utxos(&p2pkh_address(own_hash160))?, amount, fee_per_kb()?)?;
    verify_inputs(&plan.inputs, own_hash160)?;
    Ok(plan)
}

/// Maximum envoyable depuis `own_hash160` : sorties confirmées, taux du
/// moment.
pub fn max_send(own_hash160: &[u8; 20]) -> Result<u64> {
    max_amount(&utxos(&p2pkh_address(own_hash160))?, fee_per_kb()?)
}

/// Diffuse la transaction ; renvoie son identifiant.
/// Diffuse ; déjà connue du nœud : la même, partie. Sans réponse nette :
/// « peut-être partie » (voir `wallet_flow::maybe_sent`).
pub fn broadcast(signed: &Signed) -> Result<String> {
    let response = client()
        .post(format!("{BITCORE}/tx/send"))
        .json(&serde_json::json!({ "rawTx": hex::encode(&signed.raw) }))
        .send()
        .map_err(|e| crate::wallet_flow::broadcast_failure(e, "service Dogecoin injoignable", &signed.txid))?;
    let status = response.status();
    let body = response.text().unwrap_or_default();
    if status.is_success() || body.contains("already") {
        return Ok(signed.txid.clone());
    }
    if crate::wallet_flow::server_error_may_have_sent(status) {
        return Err(crate::wallet_flow::maybe_sent(&signed.txid));
    }
    bail!("transaction Dogecoin refusée : {}", body.chars().take(200).collect::<String>())
}

// --- Historique ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxInfo {
    block_time: Option<String>,
}

/// Heure du bloc d'une transaction confirmée (gardée : elle ne change plus).
fn block_time(txid: &str) -> Option<i64> {
    static TIMES: Mutex<Option<HashMap<String, i64>>> = Mutex::new(None);
    if let Some(time) = TIMES.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|m| m.get(txid)) {
        return Some(*time);
    }
    let time = get_json::<TxInfo>(&format!("{BITCORE}/tx/{txid}")).ok()?.block_time.and_then(|t| chrono_like_parse(&t))?;
    TIMES.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).insert(txid.to_string(), time);
    Some(time)
}

/// Transactions de l'adresse, la plus récente d'abord : montant net (reçu
/// moins dépensé, frais compris pour un envoi).
pub fn history(address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    let coins: Vec<Coin> = get_json(&format!("{BITCORE}/address/{}/txs?limit=200", checked(address)?))?;
    // txid → (net, hauteur ; < 0 : en attente)
    let mut txs: Vec<(String, i128, i64)> = Vec::new();
    let mut add = |txid: &str, delta: i128, height: i64| match txs.iter_mut().find(|(t, _, _)| t == txid) {
        Some(entry) => entry.1 += delta,
        None => txs.push((txid.to_string(), delta, height)),
    };
    // Identifiants mal formés ignorés (liens d'explorateur, requêtes).
    for coin in &coins {
        if is_txid(&coin.mint_txid) {
            add(&coin.mint_txid, i128::from(coin.value), coin.mint_height);
        }
        if is_txid(&coin.spent_txid) {
            add(&coin.spent_txid, -i128::from(coin.value), coin.spent_height);
        }
    }
    txs.sort_by_key(|(_, _, height)| std::cmp::Reverse(if *height > 0 { *height } else { i64::MAX }));
    txs.truncate(limit);
    Ok(txs
        .into_iter()
        .map(|(id, net, height)| {
            let timestamp_unix = if height > 0 { block_time(&id) } else { None };
            history::TxEntry {
                id,
                timestamp_unix,
                status: if height > 0 { history::TxStatus::Confirmed } else { history::TxStatus::Pending },
                net_amount_minor: Some(net),
                fee_minor: 0,
                kind: match net {
                    n if n > 0 => history::TxKind::Received,
                    n if n < 0 => history::TxKind::Sent,
                    _ => history::TxKind::Other,
                },
            }
        })
        .collect())
}

/// « 2026-09-22T19:10:21.000Z » → secondes Unix (UTC), sans dépendance de date.
fn chrono_like_parse(text: &str) -> Option<i64> {
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = time.trim_end_matches('Z').split(':');
    let (hh, mm) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let ss = t.next()?.split('.').next()?.parse::<i64>().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&day) || !(0..24).contains(&hh) || !(0..60).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    // Jours depuis 1970 (algorithme de Howard Hinnant).
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteurs SIGHASH_ALL (sans OP_CODESEPARATOR) de
    /// bitcoin/src/test/data/sighash.json : même algorithme historique que
    /// Dogecoin. [transaction brute, script, entrée, type, condensé affiché].
    const SIGHASH_VECTORS: &[(&str, &str, usize, i64, &str)] = &[
        (
            "4504cb1904c7a4acf375ddae431a74de72d5436efc73312cf8e9921f431267ea6852f9714a01000000066a656a656553a2fbd587c098b3a1c5bd1d6480f730a0d6d9b537966e20efc0e352d971576d0f87df0d6d01000000016321aeec3c4dcc819f1290edb463a737118f39ab5765800547522708c425306ebfca3f396603000000055300ac656a1d09281d05bfac57b5eb17eb3fa81ffcedfbcd3a917f1be0985c944d473d2c34d245eb350300000007656a51525152ac263078d9032f470f0500000000066aac00000052e12da60200000000003488410200000000076365006300ab539981e432",
            "52536a52526a",
            1,
            -31909119,
            "f0a2deee7fd8a3a9fad6927e763ded11c940ee47e9e6d410f94fda5001f82e0c",
        ),
        (
            "813eda1103ac8159850b4524ef65e4644e0fc30efe57a5db0c0365a30446d518d9b9aa8fdd0000000003656565c2f1e89448b374b8f12055557927d5b33339c52228f7108228149920e0b77ef0bcd69da60000000006abac00ab63ab82cdb7978d28630c5e1dc630f332c4245581f787936f0b1e84d38d33892141974c75b4750300000004ac53ab65ffffffff0137edfb02000000000000000000",
            "0063",
            1,
            -1948560575,
            "71dfcd2eb7f2e6473aed47b16a6d5fcbd0af22813d892e9765023151e07771ec",
        ),
        (
            "43559290038f32fda86580dd8a4bc4422db88dd22a626b8bd4f10f1c9dd325c8dc49bf479f01000000026351ffffffff401339530e1ed3ffe996578a17c3ec9d6fccb0723dd63e7b3f39e2c44b976b7b0300000006ab6a65656a51ffffffff6fb9ba041c96b886482009f56c09c22e7b0d33091f2ac5418d05708951816ce7000000000551ac525100ffffffff020921e40500000000035365533986f40500000000016a00000000",
            "52ac51",
            0,
            1769771809,
            "02040283ef2291d8e1f79bb71bdabe7c1546c40d7ed615c375643000a8b9600d",
        ),
        (
            "c6a72ed403313b7d027f6864e705ec6b5fa52eb99169f8ea7cd884f5cdb830a150cebade870100000009ac63ab516565ab6a51ffffffff398d5838735ff43c390ca418593dbe43f3445ba69394a6d665b5dc3b4769b5d700000000075265acab515365ffffffff7ee5616a1ee105fd18189806a477300e2a9cf836bf8035464e8192a0d785eea3030000000700ac6a51516a52ffffffff018075fd0000000000015100000000",
            "005251acac5252",
            2,
            -656067295,
            "2cc1c7514fdc512fd45ca7ba4f7be8a9fe6d3318328bc1a61ae6e7675047e654",
        ),
        (
            "cf7bdc250249e22cbe23baf6b648328d31773ea0e771b3b76a48b4748d7fbd390e88a004d30000000003ac536a4ab8cce0e097136c90b2037f231b7fde2063017facd40ed4e5896da7ad00e9c71dd70ae600000000096a0063516352525365ffffffff01b71e3e00000000000300536a00000000",
            "",
            1,
            546970113,
            "6a815ba155270af102322c882f26d22da11c5330a751f520807936b320b9af5d",
        ),
        (
            "b7877f82019c832707a60cf14fba44cfa254d787501fdd676bd58c744f6e951dbba0b3b77f0200000009ac515263ac53525300a5a36e500148f89c0500000000085265ac6a6a65acab00000000",
            "6563",
            0,
            -1785108415,
            "cb6e4322955af12eb29613c70e1a00ddbb559c887ba844df0bcdebed736dffbd",
        ),
    ];

    #[test]
    fn legacy_sighash_matches_bitcoin_core_vectors() {
        for (raw, script, index, hash_type, expected) in SIGHASH_VECTORS {
            let tx = parse_tx(&hex::decode(raw).unwrap()).unwrap();
            assert_eq!(hex::encode(tx.serialize()), *raw, "sérialisation identique");
            let mut digest = tx.sighash(*index, &hex::decode(script).unwrap(), *hash_type as u32);
            digest.reverse();
            assert_eq!(hex::encode(digest), *expected, "vecteur {expected}");
        }
        assert_eq!(SIGHASH_VECTORS.len(), 6);
    }

    #[test]
    fn addresses_round_trip_and_reject_other_networks() {
        // Adresse réelle (Bitcore) et son script P2PKH.
        let hash: [u8; 20] = hex::decode("830a7420e63d76244ff7cbd1c248e94c14463259").unwrap().try_into().unwrap();
        assert_eq!(p2pkh_address(&hash), "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L");
        assert_eq!(parse_recipient("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L").unwrap(), Recipient::P2pkh(hash));
        assert_eq!(Recipient::P2pkh(hash).script(), hex::decode("76a914830a7420e63d76244ff7cbd1c248e94c1446325988ac").unwrap());
        let p2sh = base58check(P2SH_VERSION, &hash);
        assert!(matches!(parse_recipient(&p2sh), Ok(Recipient::P2sh(_))));
        // Adresse Bitcoin (version 0) : refusée ; somme de contrôle fausse aussi.
        assert!(parse_recipient(&base58check(0x00, &hash)).is_err());
        assert!(parse_recipient("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7M").is_err());
        assert!(parse_recipient("pas une adresse").is_err());
        // Ni adresse ni identifiant mal formé dans une URL.
        assert!(checked("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L/../../tx/send").is_err());
        assert!(is_txid("484c94145e97c0b2dd96912c1f056c9e05c8d358ab96ea429c51039d75d0d3c4"));
        for bad in ["484c94145e97c0b2dd96912c1f056c9e05c8d358ab96ea429c51039d75d0d3c", "484C94145E97C0B2DD96912C1F056C9E05C8D358AB96EA429C51039D75D0D3C4", "../../../../../../../../../../../../../../../../../../../../../../"] {
            assert!(!is_txid(bad), "{bad}");
        }
    }

    /// Adresses du chemin BIP44 m/44'/3'/0'/0/i pour la seed BIP39 de test
    /// « abandon … about », calculées indépendamment (bitcoinjs-lib + bip32) :
    /// mêmes adresses que Ledger, Trezor et les autres portefeuilles.
    #[test]
    fn derivation_matches_an_independent_implementation() {
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        for (index, expected) in [(0, "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"), (1, "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas"), (7, "DFYfZKExgT3DB1FhgkxsPooTUsbWTsP7Rw")] {
            let (_, hash160) = crate::derivation::derive_doge_key(&seed, index).unwrap();
            assert_eq!(p2pkh_address(&hash160), expected, "index {index}");
        }
    }

    fn utxo(value: u64) -> Utxo {
        Utxo { txid: format!("{value:064x}"), vout: 0, value }
    }

    #[test]
    fn plans_cover_amount_fee_and_dust() {
        let rate = 1_000_000; // 0,01 DOGE/ko
        let plan = plan_send(vec![utxo(5 * 100_000_000), utxo(100_000_000)], 2 * 100_000_000, rate).unwrap();
        assert_eq!(plan.inputs.len(), 1, "la plus grosse sortie suffit");
        assert_eq!(plan.fee, fee_for(estimated_size(1, 2), rate));
        assert_eq!(plan.amount + plan.fee + plan.change, 5 * 100_000_000);
        // Monnaie sous la poussière : ajoutée aux frais, pas de sortie.
        let exact = 100_000_000 + fee_for(estimated_size(1, 2), rate) + 10;
        let plan = plan_send(vec![utxo(exact)], 100_000_000, rate).unwrap();
        assert_eq!((plan.change, plan.amount + plan.fee), (0, exact));
        assert!(plan_send(vec![utxo(100)], 50, rate).unwrap_err().to_string().contains("trop petit"));
        assert!(plan_send(vec![utxo(1_000_000)], 2_000_000, rate).unwrap_err().to_string().contains("DOGE insuffisants"));
        // Montant proche de u64::MAX, sorties énormes annoncées : refus, jamais
        // un besoin enroulé ni un plan incohérent.
        assert!(plan_send(vec![utxo(u64::MAX / 2), utxo(u64::MAX / 2)], u64::MAX - 10, rate).is_err());
        let huge = plan_send(vec![utxo(u64::MAX), utxo(u64::MAX)], 100_000_000, rate).unwrap();
        assert_eq!((huge.inputs.len(), huge.amount + huge.fee + huge.change), (1, u64::MAX), "plan cohérent");
        assert!(plan_send(vec![utxo(u64::MAX - 5), utxo(u64::MAX - 5)], u64::MAX - 1, rate).unwrap_err().to_string().contains("hors limites"));
    }

    #[test]
    fn max_amount_leaves_exactly_the_fee_and_skips_uneconomic_outputs() {
        let rate = 1_000_000;
        let utxos = vec![utxo(300_000_000), utxo(200_000_000)];
        let max = max_amount(&utxos, rate).unwrap();
        assert_eq!(max, 500_000_000 - fee_for(estimated_size(2, 1), rate));
        // Le plan de ce montant prend tout, sans monnaie, frais exacts.
        let plan = plan_send(utxos, max, rate).unwrap();
        assert_eq!((plan.inputs.len(), plan.change, plan.fee), (2, 0, fee_for(estimated_size(2, 1), rate)));
        // Une sortie minuscule coûte plus qu'elle n'apporte : ignorée.
        let with_dust = vec![utxo(300_000_000), utxo(1_000)];
        assert_eq!(max_amount(&with_dust, rate).unwrap(), 300_000_000 - fee_for(estimated_size(1, 1), rate));
        assert!(max_amount(&[utxo(100_000)], rate).is_err(), "rien d'envoyable");
        assert!(max_amount(&[], rate).is_err());
    }

    #[test]
    fn signed_transactions_parse_back_and_every_signature_verifies() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let own = {
            use ripemd::Ripemd160;
            use sha2::{Digest, Sha256};
            let digest: [u8; 20] = Ripemd160::digest(Sha256::digest(key.verifying_key().to_encoded_point(true).as_bytes())).into();
            digest
        };
        let plan = SendPlan { inputs: vec![utxo(300_000_000), utxo(200_000_000)], amount: 400_000_000, fee: 1_000_000, change: 99_000_000 };
        let to = Recipient::P2sh([7; 20]);
        let signed = build_signed(&plan, &key, &own, &to).unwrap();
        let tx = parse_tx(&signed.raw).unwrap();
        assert_eq!(signed.txid, txid_hex(&signed.raw));
        assert_eq!(tx.outputs, vec![(400_000_000, to.script()), (99_000_000, p2pkh_script(&own))]);
        let mut unsigned = tx.clone();
        unsigned.inputs.iter_mut().for_each(|i| i.script_sig.clear());
        for (index, input) in tx.inputs.iter().enumerate() {
            let sig_len = input.script_sig[0] as usize;
            let der = &input.script_sig[1..sig_len];
            assert_eq!(input.script_sig[sig_len], 0x01, "SIGHASH_ALL");
            let pubkey = &input.script_sig[sig_len + 2..];
            assert_eq!(pubkey, key.verifying_key().to_encoded_point(true).as_bytes());
            let signature = Signature::from_der(der).unwrap();
            assert!(signature.normalize_s().is_none(), "low-S");
            let digest = unsigned.sighash(index, &p2pkh_script(&own), SIGHASH_ALL);
            key.verifying_key().verify_prehash(&digest, &signature).unwrap();
        }
    }

    #[test]
    fn dates_are_parsed_in_utc() {
        assert_eq!(chrono_like_parse("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(chrono_like_parse("2026-09-22T19:10:21.000Z"), Some(1_790_104_221));
        assert_eq!(chrono_like_parse("pas une date"), None);
        assert_eq!(chrono_like_parse("9223372036854775807-01-01T00:00:00Z"), None);
        assert_eq!(chrono_like_parse("2026-13-01T00:00:00Z"), None);
    }

    /// Réel (lecture seule) : solde, sorties, frais, historique d'une adresse
    /// active, et vérification d'une sortie sur sa transaction d'origine.
    /// `cargo test -- --ignored real_bitcore --nocapture`
    #[test]
    #[ignore]
    fn real_bitcore_reads_and_input_verification() {
        let address = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L";
        let hash = match parse_recipient(address).unwrap() {
            Recipient::P2pkh(h) => h,
            Recipient::P2sh(_) => unreachable!(),
        };
        println!("solde {} (en attente : {})", balance(address).unwrap(), has_pending(address).unwrap());
        println!("activité {:?}", address_activity(address).unwrap());
        let unused = p2pkh_address(&[0x5a; 20]);
        assert_eq!(address_activity(&unused).unwrap(), (false, false), "adresse jamais utilisée");
        let utxos = utxos(address).unwrap();
        println!("{} sorties, frais {} koinus/ko", utxos.len(), fee_per_kb().unwrap());
        verify_inputs(&utxos[..1], &hash).unwrap();
        // Montant annoncé faux : refusé.
        let mut lie = utxos[0].clone();
        lie.value -= 1;
        assert!(verify_inputs(&[lie], &hash).unwrap_err().to_string().contains("annoncé faux"));
        // Préparation réelle (1 DOGE) : sorties choisies puis vérifiées sur leur
        // transaction d'origine.
        let planned = plan(&hash, 100_000_000).unwrap();
        assert_eq!(planned.amount + planned.fee + planned.change, planned.inputs.iter().map(|u| u.value).sum::<u64>());
        println!("plan : {} entrée(s), frais {} DOGE, monnaie {} DOGE", planned.inputs.len(), format_doge(planned.fee), format_doge(planned.change));
        let entries = history(address, 5).unwrap();
        println!("{} transactions, première : {:?} {:?}", entries.len(), entries[0].net_amount_minor, entries[0].timestamp_unix);
    }

    /// Réel : les signatures d'une vraie transaction Dogecoin (minée) se
    /// vérifient avec NOTRE condensé, calculé sur le script de la sortie
    /// dépensée relu dans sa transaction d'origine — même algorithme que le
    /// consensus Dogecoin.
    /// `cargo test -- --ignored real_mined_signatures --nocapture`
    #[test]
    #[ignore]
    fn real_mined_signatures_verify_with_our_sighash() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::VerifyingKey;
        let txid = "484c94145e97c0b2dd96912c1f056c9e05c8d358ab96ea429c51039d75d0d3c4";
        let tx = parse_tx(&raw_transaction(txid).unwrap()).unwrap();
        assert!(!tx.inputs.is_empty());
        for (index, input) in tx.inputs.iter().enumerate().take(3) {
            let mut prev = input.prev;
            prev.reverse();
            let outputs = verified_outputs(&hex::encode(prev)).unwrap();
            let script_code = &outputs[input.vout as usize].1;
            assert_eq!((script_code.len(), script_code[0]), (25, 0x76), "sortie P2PKH");
            let script = &input.script_sig;
            let sig_len = script[0] as usize;
            let (der, hash_type) = (&script[1..sig_len], script[sig_len]);
            let pubkey = &script[sig_len + 2..];
            let signature = Signature::from_der(der).unwrap();
            let signature = signature.normalize_s().unwrap_or(signature);
            let digest = tx.sighash(index, script_code, u32::from(hash_type));
            VerifyingKey::from_sec1_bytes(pubkey).unwrap().verify_prehash(&digest, &signature).unwrap();
            println!("entrée {index} : signature vérifiée (type {hash_type})");
        }
    }

    /// Réel : notre transaction signée, dépensant une sortie inexistante, est
    /// DÉCODÉE par le nœud puis refusée seulement pour entrée manquante.
    /// `cargo test -- --ignored real_broadcast_missing --nocapture`
    #[test]
    #[ignore]
    fn real_broadcast_missing_input_is_the_only_rejection() {
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let own = [0x11; 20];
        let plan = SendPlan { inputs: vec![utxo(300_000_000)], amount: 200_000_000, fee: 1_000_000, change: 99_000_000 };
        let signed = build_signed(&plan, &key, &own, &Recipient::P2pkh([0x22; 20])).unwrap();
        let error = broadcast(&signed).unwrap_err().to_string();
        println!("{error}");
        assert!(!error.contains("decode"), "transaction mal formée : {error}");
        assert!(error.to_lowercase().contains("missing") || error.contains("inputs"), "{error}");
    }
}
