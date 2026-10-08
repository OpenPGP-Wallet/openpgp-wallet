//! Cardano (ADA) : adresse de base addr1… (clés BIP32-Ed25519, maître CIP-3
//! « Icarus » tiré de l'entropie maîtresse — 32 octets, celle d'une phrase
//! de 24 mots —, chemins CIP-1852 m/1852'/1815'/p'/0/0 et /2/0, comme Yoroi,
//! Eternl et Lace), solde, envoi d'ADA, historique.
//!
//! Transactions (CBOR, ère Conway) construites et signées ici, identiques
//! octet pour octet à cardano-serialization-lib (bibliothèque officielle
//! d'EMURGO) dans les tests ; signature vérifiée par un nœud réel (test réel :
//! transaction sur une entrée inexistante refusée POUR L'ENTRÉE seulement,
//! signature altérée refusée pour la signature).
//!
//! Règles appliquées avant la boîte de confirmation :
//! - chaque sortie porte un minimum d'ADA (≈ 1 ADA, `coins_per_utxo_size`) ;
//! - sorties portant des jetons jamais dépensées (les jetons seraient perdus
//!   ou la transaction refusée) ;
//! - adresses de contrat (script), de mise en jeu (stake1…), d'un autre
//!   réseau ou Byron refusées ;
//! - frais exacts (44 lovelace/octet + 155 381), validité 15 min.
//!
//! Mise en jeu (délégation à un pool, « Staker » sur la carte Cardano) : les
//! ADA ne bougent pas et restent dépensables. Certificats de l'ère Conway
//! signés par la clé de mise en jeu : inscription + délégation au pool +
//! délégation de vote « abstention » (exigée depuis Conway pour retirer les
//! récompenses), dépôt de 2 ADA rendu à la désinscription ; retrait des
//! récompenses. Format vérifié par un nœud réel (test ignoré).

use crate::history;
use anyhow::{anyhow, bail, ensure, Context, Result};
use bech32::{FromBase32, ToBase32};
use curve25519_dalek::{EdwardsPoint, Scalar};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::sync::OnceLock;
use zeroize::Zeroize;

const KOIOS: &str = "https://api.koios.rest/api/v1";
pub const DECIMALS: u8 = 6;
/// Validité d'une transaction (créneaux d'une seconde).
const TTL_SLOTS: u64 = 900;
/// Entrées au plus par transaction (taille maximale 16 384 octets).
const MAX_INPUTS: usize = 100;
/// Reste trop petit pour une sortie de monnaie : laissé en frais s'il ne
/// dépasse pas 0,2 ADA (sinon refus, avec la consigne d'envoyer le maximum).
const MAX_ABSORBED_CHANGE: u64 = 200_000;
/// Plafond des frais (2 ADA ; ~0,17 ADA pour un virement simple).
const MAX_FEE: u64 = 2_000_000;

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

fn koios_get(path: &str) -> Result<Value> {
    let response = client().get(format!("{KOIOS}{path}")).send().context("service Cardano injoignable")?;
    let status = response.status();
    ensure!(status.is_success(), "service Cardano : réponse {status}");
    response.json().context("réponse du service Cardano illisible")
}

fn koios_post(path: &str, body: Value) -> Result<Value> {
    let response = client().post(format!("{KOIOS}{path}")).json(&body).send().context("service Cardano injoignable")?;
    let status = response.status();
    ensure!(status.is_success(), "service Cardano : réponse {status}");
    response.json().context("réponse du service Cardano illisible")
}

/// Montant en ADA, 6 décimales (« 12.500000 »).
pub fn format_ada(lovelace: u64) -> String {
    format!("{}.{:06}", lovelace / 1_000_000, lovelace % 1_000_000)
}

fn lovelace(value: &Value) -> Result<u64> {
    value.as_str().and_then(|v| v.parse().ok()).or(value.as_u64()).context("montant Cardano illisible")
}

fn blake2b(data: &[u8], len: usize) -> Vec<u8> {
    blake2b_simd::Params::new().hash_length(len).hash(data).as_bytes().to_vec()
}

// --- Clés BIP32-Ed25519 (CIP-3 Icarus, dérivation « V2 ») ------------------------------

/// Clé privée étendue : scalaire (kL), préfixe de signature (kR), code de chaîne.
pub struct XPrv {
    kl: [u8; 32],
    kr: [u8; 32],
    chain: [u8; 32],
}

impl Drop for XPrv {
    fn drop(&mut self) {
        self.kl.zeroize();
        self.kr.zeroize();
        self.chain.zeroize();
    }
}

type HmacSha512 = Hmac<Sha512>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("clé HMAC de taille valide");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA512, 4096 itérations, 96 octets (mot de passe vide).
fn pbkdf2_icarus(entropy: &[u8]) -> [u8; 96] {
    let mut out = [0u8; 96];
    for (block, chunk) in out.chunks_mut(64).enumerate() {
        let mut u = hmac(b"", &[entropy, &(block as u32 + 1).to_be_bytes()]);
        let mut t = u;
        for _ in 1..4096 {
            u = hmac(b"", &[&u]);
            t.iter_mut().zip(u.iter()).for_each(|(a, b)| *a ^= b);
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
        u.zeroize();
        t.zeroize();
    }
    out
}

impl XPrv {
    /// Clé maîtresse CIP-3 (Icarus) depuis l'entropie.
    pub fn master(entropy: &[u8]) -> XPrv {
        let mut out = pbkdf2_icarus(entropy);
        out[0] &= 0b1111_1000;
        out[31] &= 0b0001_1111;
        out[31] |= 0b0100_0000;
        let key = XPrv { kl: out[..32].try_into().expect("32"), kr: out[32..64].try_into().expect("32"), chain: out[64..].try_into().expect("32") };
        out.zeroize();
        key
    }

    pub fn public(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(self.kl)).compress().to_bytes()
    }

    /// Enfant n°`index` (durci au-delà de 2³¹).
    pub fn derive(&self, index: u32) -> XPrv {
        let idx = index.to_le_bytes();
        let (mut z, i) = if index >= 0x8000_0000 {
            (hmac(&self.chain, &[&[0x00], &self.kl, &self.kr, &idx]), hmac(&self.chain, &[&[0x01], &self.kl, &self.kr, &idx]))
        } else {
            let public = self.public();
            (hmac(&self.chain, &[&[0x02], &public, &idx]), hmac(&self.chain, &[&[0x03], &public, &idx]))
        };
        // kL' = kL + 8 × ZL (28 premiers octets), kR' = kR + ZR (mod 2²⁵⁶).
        let mut kl = [0u8; 32];
        let mut carry = 0u16;
        for k in 0..32 {
            // Octet k de 8 × ZL : 5 bits bas de ZL[k] décalés, 3 bits hauts de ZL[k-1].
            let low = if k < 28 { (u16::from(z[k]) << 3) & 0xff } else { 0 };
            let high = if k > 0 && k <= 28 { u16::from(z[k - 1]) >> 5 } else { 0 };
            let zl8 = low | high;
            let sum = u16::from(self.kl[k]) + zl8 + carry;
            kl[k] = sum as u8;
            carry = sum >> 8;
        }
        let mut kr = [0u8; 32];
        let mut carry = 0u16;
        for k in 0..32 {
            let sum = u16::from(self.kr[k]) + u16::from(z[32 + k]) + carry;
            kr[k] = sum as u8;
            carry = sum >> 8;
        }
        z.zeroize();
        XPrv { kl, kr, chain: i[32..].try_into().expect("32") }
    }

    /// Signature Ed25519 avec la clé étendue (r = H(kR ‖ M)).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let public = self.public();
        let r = Scalar::from_bytes_mod_order_wide(&Sha512::new().chain_update(self.kr).chain_update(message).finalize().into());
        let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let h = Scalar::from_bytes_mod_order_wide(&Sha512::new().chain_update(big_r).chain_update(public).chain_update(message).finalize().into());
        let s = r + h * Scalar::from_bytes_mod_order(self.kl);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s.to_bytes());
        signature
    }
}

/// Clés de paiement et de mise en jeu du compte n°`account` (CIP-1852).
pub fn account_keys(entropy: &[u8], account: u32) -> (XPrv, XPrv) {
    let acct = XPrv::master(entropy).derive(0x8000_0000 | 1852).derive(0x8000_0000 | 1815).derive(0x8000_0000 | account);
    (acct.derive(0).derive(0), acct.derive(2).derive(0))
}

// --- Adresses ------------------------------------------------------------------------

/// Adresse de base (paiement + mise en jeu), réseau principal.
pub fn base_address(payment: &[u8; 32], stake: &[u8; 32]) -> String {
    let mut bytes = vec![0x01];
    bytes.extend(blake2b(payment, 28));
    bytes.extend(blake2b(stake, 28));
    bech32::encode("addr", bytes.to_base32(), bech32::Variant::Bech32).expect("adresse Cardano encodable")
}

pub fn address_of(entropy: &[u8], account: u32) -> String {
    let (payment, stake) = account_keys(entropy, account);
    base_address(&payment.public(), &stake.public())
}

/// Adresse Shelley du réseau principal, paiement par CLÉ (base, pointeur ou
/// « entreprise ») ; octets de l'adresse. Le reste est refusé avec la raison.
pub fn parse_address(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    ensure!(!text.starts_with("stake"), "adresse de mise en jeu Cardano (stake1…), pas une adresse de paiement");
    ensure!(!text.starts_with("addr_test"), "adresse Cardano d'un réseau de test — refusée");
    ensure!(!text.starts_with("Ae2") && !text.starts_with("DdzFF"), "ancienne adresse Cardano (Byron) non prise en charge : demandez une adresse addr1…");
    let (hrp, data, variant) = bech32::decode(text).map_err(|_| anyhow!("adresse Cardano invalide"))?;
    ensure!(hrp == "addr" && variant == bech32::Variant::Bech32, "adresse Cardano invalide");
    let bytes = Vec::<u8>::from_base32(&data).map_err(|_| anyhow!("adresse Cardano invalide"))?;
    let header = *bytes.first().context("adresse Cardano invalide")?;
    let (kind, network) = (header >> 4, header & 0x0f);
    ensure!(network == 1, "adresse Cardano d'un autre réseau — refusée");
    ensure!(kind & 1 == 0 || kind > 7, "adresse de contrat Cardano (script) : envoi refusé, les fonds pourraient y rester bloqués");
    let expected = match kind {
        0 | 2 => bytes.len() == 57,
        4 => bytes.len() > 29,
        6 => bytes.len() == 29,
        _ => bail!("adresse Cardano invalide"),
    };
    ensure!(expected, "adresse Cardano invalide");
    Ok(bytes)
}

// --- CBOR et transaction -------------------------------------------------------------------

#[derive(Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(&mut self, major: u8, value: u64) -> &mut Self {
        let m = major << 5;
        match value {
            0..=23 => self.0.push(m | value as u8),
            24..=0xff => self.0.extend([m | 24, value as u8]),
            0x100..=0xffff => {
                self.0.push(m | 25);
                self.0.extend((value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(m | 26);
                self.0.extend((value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(m | 27);
                self.0.extend(value.to_be_bytes());
            }
        }
        self
    }
    fn uint(&mut self, value: u64) -> &mut Self {
        self.head(0, value)
    }
    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.head(2, bytes.len() as u64);
        self.0.extend_from_slice(bytes);
        self
    }
    fn array(&mut self, len: usize) -> &mut Self {
        self.head(4, len as u64)
    }
    fn map(&mut self, len: usize) -> &mut Self {
        self.head(5, len as u64)
    }
    /// Ensemble (étiquette 258), comme cardano-serialization-lib.
    fn set(&mut self, len: usize) -> &mut Self {
        self.head(6, 258).array(len)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub hash: [u8; 32],
    pub index: u32,
}

#[derive(Clone, Debug)]
pub struct Output {
    pub address: Vec<u8>,
    pub lovelace: u64,
}

fn output_cbor(out: &Output) -> Vec<u8> {
    let mut c = Cbor::default();
    c.array(2).bytes(&out.address).uint(out.lovelace);
    c.0
}

/// Certificat de mise en jeu (ère Conway), pour la clé de mise en jeu dont
/// le hachage est `stake`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cert {
    /// Inscription + délégation au pool + vote « abstention », avec dépôt (13).
    RegisterDelegate { stake: [u8; 28], pool: [u8; 28], deposit: u64 },
    /// Délégation au pool + vote « abstention », clé déjà inscrite (10).
    Delegate { stake: [u8; 28], pool: [u8; 28] },
    /// Vote « abstention » seul (exigé pour retirer les récompenses) (9).
    VoteAbstain { stake: [u8; 28] },
    /// Désinscription, dépôt rendu (8).
    Unregister { stake: [u8; 28], deposit: u64 },
}

fn credential(c: &mut Cbor, key_hash: &[u8; 28]) {
    c.array(2).uint(0).bytes(key_hash);
}

/// DRep « toujours s'abstenir » : les récompenses deviennent retirables sans
/// prendre part aux votes de gouvernance.
fn abstain(c: &mut Cbor) {
    c.array(1).uint(2);
}

fn cert_cbor(c: &mut Cbor, cert: &Cert) {
    match cert {
        Cert::RegisterDelegate { stake, pool, deposit } => {
            c.array(5).uint(13);
            credential(c, stake);
            c.bytes(pool);
            abstain(c);
            c.uint(*deposit);
        }
        Cert::Delegate { stake, pool } => {
            c.array(4).uint(10);
            credential(c, stake);
            c.bytes(pool);
            abstain(c);
        }
        Cert::VoteAbstain { stake } => {
            c.array(3).uint(9);
            credential(c, stake);
            abstain(c);
        }
        Cert::Unregister { stake, deposit } => {
            c.array(3).uint(8);
            credential(c, stake);
            c.uint(*deposit);
        }
    }
}

pub struct Body {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub fee: u64,
    pub ttl: u64,
    pub certs: Vec<Cert>,
    /// Retrait de récompenses : (adresse de récompenses, montant).
    pub withdrawal: Option<(Vec<u8>, u64)>,
}

impl Body {
    fn cbor(&self) -> Vec<u8> {
        let mut c = Cbor::default();
        c.map(4 + usize::from(!self.certs.is_empty()) + usize::from(self.withdrawal.is_some())).uint(0).set(self.inputs.len());
        for input in &self.inputs {
            c.array(2).bytes(&input.hash).uint(u64::from(input.index));
        }
        c.uint(1).array(self.outputs.len());
        for out in &self.outputs {
            c.0.extend(output_cbor(out));
        }
        c.uint(2).uint(self.fee).uint(3).uint(self.ttl);
        if !self.certs.is_empty() {
            c.uint(4).set(self.certs.len());
            for cert in &self.certs {
                cert_cbor(&mut c, cert);
            }
        }
        if let Some((account, amount)) = &self.withdrawal {
            c.uint(5).map(1).bytes(account).uint(*amount);
        }
        c.0
    }

    /// Identifiant : BLAKE2b-256 du corps.
    fn hash(&self) -> [u8; 32] {
        blake2b(&self.cbor(), 32).try_into().expect("32")
    }
}

/// Transaction signée (corps, signatures — paiement, et mise en jeu pour un
/// certificat ou un retrait —, valide, sans métadonnées).
fn signed_cbor(body: &Body, witnesses: &[([u8; 32], [u8; 64])]) -> Vec<u8> {
    let mut c = Cbor::default();
    c.array(4);
    c.0.extend(body.cbor());
    c.map(1).uint(0).set(witnesses.len());
    for (public, signature) in witnesses {
        c.array(2).bytes(public).bytes(signature);
    }
    c.0.extend([0xf5, 0xf6]);
    c.0
}

pub struct Signed {
    pub cbor: Vec<u8>,
    pub hash: String,
}

pub fn sign(body: &Body, key: &XPrv) -> Signed {
    sign_with(body, &[key])
}

/// Signée par chacune des clés (paiement, puis mise en jeu).
pub fn sign_with(body: &Body, keys: &[&XPrv]) -> Signed {
    let hash = body.hash();
    let witnesses: Vec<([u8; 32], [u8; 64])> = keys.iter().map(|key| (key.public(), key.sign(&hash))).collect();
    Signed { cbor: signed_cbor(body, &witnesses), hash: hex::encode(hash) }
}

// --- Réseau ------------------------------------------------------------------------------

struct Params {
    fee_a: u64,
    fee_b: u64,
    coins_per_byte: u64,
    /// Dépôt d'inscription d'une clé de mise en jeu (2 ADA).
    key_deposit: u64,
}

fn params() -> Result<Params> {
    let value = koios_get("/epoch_params?limit=1&order=epoch_no.desc&select=epoch_no,min_fee_a,min_fee_b,coins_per_utxo_size,key_deposit")?;
    let p = &value[0];
    Ok(Params {
        fee_a: p["min_fee_a"].as_u64().context("paramètres Cardano illisibles")?,
        fee_b: p["min_fee_b"].as_u64().context("paramètres Cardano illisibles")?,
        coins_per_byte: lovelace(&p["coins_per_utxo_size"]).context("paramètres Cardano illisibles")?,
        key_deposit: lovelace(&p["key_deposit"]).context("paramètres Cardano illisibles")?,
    })
}

fn tip_slot() -> Result<u64> {
    koios_get("/tip")?[0]["abs_slot"].as_u64().context("état du réseau Cardano illisible")
}

impl Params {
    /// Minimum d'ADA d'une sortie (CIP-55 : 160 octets + taille de la sortie).
    fn min_output(&self, address: &[u8]) -> u64 {
        // Taille avec un montant maximal (5 ou 9 octets) : prudent.
        let size = output_cbor(&Output { address: address.to_vec(), lovelace: u64::MAX }).len() as u64;
        self.coins_per_byte * (160 + size)
    }

    /// Frais exacts d'une transaction de cette forme (signature factice de
    /// même taille).
    fn fee(&self, inputs: &[Input], outputs: &[Output], ttl: u64) -> u64 {
        let body = Body { inputs: inputs.to_vec(), outputs: outputs.to_vec(), fee: MAX_FEE, ttl, certs: Vec::new(), withdrawal: None };
        self.fee_of(&body, 1)
    }

    /// Frais exacts de `body` signé par `signatures` clés (frais au plafond
    /// dans le corps : taille maximale).
    fn fee_of(&self, body: &Body, signatures: usize) -> u64 {
        let size = signed_cbor(body, &vec![([0; 32], [0; 64]); signatures]).len() as u64;
        self.fee_a * size + self.fee_b
    }
}

/// Sortie dépensable de l'adresse (ADA seulement).
#[derive(Clone, Debug)]
struct Utxo {
    input: Input,
    lovelace: u64,
}

/// (sorties d'ADA seul, solde total y compris les sorties à jetons).
fn utxos(address: &str) -> Result<(Vec<Utxo>, u64)> {
    let list = koios_post("/address_utxos", json!({ "_addresses": [address], "_extended": true }))?;
    let mut spendable = Vec::new();
    let mut total = 0u64;
    for u in list.as_array().map(Vec::as_slice).unwrap_or_default() {
        let value = lovelace(&u["value"])?;
        total += value;
        // Sorties à jetons ou à donnée : jamais dépensées ici.
        let plain = u["asset_list"].as_array().is_none_or(Vec::is_empty) && u["datum_hash"].is_null() && u["inline_datum"].is_null() && u["reference_script"].is_null();
        if !plain {
            continue;
        }
        let hash: [u8; 32] = u["tx_hash"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|h| h.try_into().ok()).context("sortie Cardano illisible")?;
        let index = u["tx_index"].as_u64().and_then(|i| u32::try_from(i).ok()).context("sortie Cardano illisible")?;
        spendable.push(Utxo { input: Input { hash, index }, lovelace: value });
    }
    spendable.sort_by_key(|u| std::cmp::Reverse(u.lovelace));
    Ok((spendable, total))
}

/// Solde (lovelace), sorties à jetons comprises.
pub fn balance(address: &str) -> Result<u64> {
    parse_address(address)?;
    let info = koios_post("/address_info", json!({ "_addresses": [address.trim()] }))?;
    match info.as_array().and_then(|a| a.first()) {
        Some(entry) => lovelace(&entry["balance"]),
        None => Ok(0),
    }
}

/// Activité d'une adresse destinataire : (détient des ADA, a déjà servi).
pub fn address_activity(address: &str) -> Result<(bool, bool)> {
    parse_address(address)?;
    let txs = koios_post("/address_txs", json!({ "_addresses": [address.trim()] }))?;
    let used = txs.as_array().is_some_and(|t| !t.is_empty());
    Ok((used && balance(address)? > 0, used))
}

/// Envoi préparé pour la boîte de confirmation : exactement ce qui sera signé
/// (hors validité, fixée à l'envoi).
#[derive(Clone, Debug)]
pub struct AdaPlan {
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    inputs: Vec<Input>,
}

fn plan_with(from: &str, to: &str, amount: Option<u64>) -> Result<AdaPlan> {
    let (from_bytes, to_bytes) = (parse_address(from)?, parse_address(to)?);
    ensure!(from_bytes != to_bytes, "envoi vers votre propre adresse Cardano");
    let params = params()?;
    let ttl = tip_slot()? + TTL_SLOTS;
    let (utxos, _) = utxos(from.trim())?;
    ensure!(!utxos.is_empty(), "aucun ADA envoyable sur cette adresse");
    let min_to = params.min_output(&to_bytes);
    let pay = |lovelace| Output { address: to_bytes.clone(), lovelace };
    // Max : tout l'ADA dépensable, une seule sortie.
    let Some(amount) = amount else {
        let inputs: Vec<Input> = utxos.iter().take(MAX_INPUTS).map(|u| u.input.clone()).collect();
        let total: u64 = utxos.iter().take(MAX_INPUTS).map(|u| u.lovelace).sum();
        let fee = params.fee(&inputs, &[pay(total)], ttl);
        let amount = total.checked_sub(fee).filter(|a| *a >= min_to).context("ADA insuffisants pour couvrir les frais et le minimum d'une sortie")?;
        return Ok(AdaPlan { amount, fee, change: 0, inputs });
    };
    ensure!(amount >= min_to, "montant trop petit : chaque envoi Cardano porte au moins {} ADA (minimum du réseau)", format_ada(min_to));
    let min_change = params.min_output(&from_bytes);
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for utxo in utxos.iter().take(MAX_INPUTS) {
        inputs.push(utxo.input.clone());
        total += utxo.lovelace;
        // Avec monnaie rendue.
        let fee = params.fee(&inputs, &[pay(amount), Output { address: from_bytes.clone(), lovelace: total }], ttl);
        if let Some(change) = total.checked_sub(amount + fee).filter(|c| *c >= min_change) {
            return Ok(AdaPlan { amount, fee, change, inputs });
        }
        // Sans monnaie : un reste minime part en frais.
        let fee = params.fee(&inputs, &[pay(amount)], ttl);
        if let Some(rest) = total.checked_sub(amount + fee).filter(|r| *r <= MAX_ABSORBED_CHANGE) {
            return Ok(AdaPlan { amount, fee: fee + rest, change: 0, inputs });
        }
    }
    let spendable: u64 = utxos.iter().take(MAX_INPUTS).map(|u| u.lovelace).sum();
    bail!(
        "ADA insuffisants : {} ADA dépensables, {} ADA + frais demandés, et la monnaie rendue doit porter au moins {} ADA — envoyez le maximum ou un montant plus petit",
        format_ada(spendable),
        format_ada(amount),
        format_ada(min_change)
    )
}

/// Envoi d'un montant précis (monnaie rendue à sa propre adresse).
pub fn plan(from: &str, to: &str, amount: u64) -> Result<AdaPlan> {
    let plan = plan_with(from, to, Some(amount))?;
    ensure!(plan.fee <= MAX_FEE, "frais Cardano anormalement élevés ({} ADA) — envoi refusé", format_ada(plan.fee));
    Ok(plan)
}

/// Bouton « Max » : tout l'ADA dépensable, frais déduits.
pub fn plan_max(from: &str, to: &str) -> Result<AdaPlan> {
    plan_with(from, to, None)
}

/// Plus grand montant envoyable (vers une adresse de base quelconque).
pub fn max_amount(from: &str) -> Result<u64> {
    Ok(plan_max(from, from_placeholder())?.amount)
}

/// Adresse de base de référence (taille d'une sortie habituelle) pour le
/// calcul du maximum quand le destinataire n'est pas encore saisi.
fn from_placeholder() -> &'static str {
    "addr1qxgzh24yclh838lhpraz7htsqk3p6p3xvrwex8h7uakx6vv0ufdahf4ccw55my2vr4ck52z9kjv5rneqkehcf23sqm3smxw2mj"
}

/// Construit, signe et diffuse l'envoi préparé ; renvoie son identifiant.
pub fn send(payment: &XPrv, from: &str, to: &str, plan: &AdaPlan) -> Result<String> {
    let mut outputs = vec![Output { address: parse_address(to)?, lovelace: plan.amount }];
    if plan.change > 0 {
        outputs.push(Output { address: parse_address(from)?, lovelace: plan.change });
    }
    let body = Body { inputs: plan.inputs.clone(), outputs, fee: plan.fee, ttl: tip_slot()? + TTL_SLOTS, certs: Vec::new(), withdrawal: None };
    // La validité réelle peut changer d'un octet la taille : frais revérifiés.
    let params = params()?;
    ensure!(params.fee(&body.inputs, &body.outputs, body.ttl) <= plan.fee, "les frais Cardano ont changé depuis la confirmation — relancez l'envoi");
    submit(&sign(&body, payment))
}

pub fn submit(signed: &Signed) -> Result<String> {
    submit_full(signed)?.map_err(|text| {
        let detail: String = text.chars().filter(|c| !matches!(c, '{' | '}' | '"' | '\\')).take(300).collect();
        anyhow!("transaction Cardano refusée : {detail}")
    })
}

/// Diffusion : `Ok(Err(texte complet))` si le nœud refuse la transaction.
fn submit_full(signed: &Signed) -> Result<std::result::Result<String, String>> {
    let response = client()
        .post(format!("{KOIOS}/submittx"))
        .header("content-type", "application/cbor")
        .body(signed.cbor.clone())
        .send()
        .map_err(|e| crate::wallet_flow::broadcast_failure(e, "service Cardano injoignable", &signed.hash))?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    // Erreur de passerelle : peut-être partie (voir `wallet_flow::maybe_sent`).
    if crate::wallet_flow::server_error_may_have_sent(status) {
        return Err(crate::wallet_flow::maybe_sent(&signed.hash));
    }
    if !status.is_success() {
        return Ok(Err(text));
    }
    // Transaction acceptée : un autre identifiant que le nôtre ne doit pas la faire
    // passer pour refusée — un nouvel envoi la paierait deux fois (32ᵉ passage).
    if text.trim().trim_matches('"') != signed.hash {
        return Err(crate::wallet_flow::maybe_sent(&signed.hash));
    }
    Ok(Ok(signed.hash.clone()))
}

// --- Mise en jeu (délégation à un pool) --------------------------------------------------

/// Hachage d'une clé publique (28 octets).
fn key_hash(public: &[u8; 32]) -> [u8; 28] {
    blake2b(public, 28).try_into().expect("28")
}

/// Hachage de la clé de mise en jeu d'une adresse de base (ses 28 derniers
/// octets) : c'est elle que l'on délègue.
pub fn stake_key_hash(address: &str) -> Result<[u8; 28]> {
    let bytes = parse_address(address)?;
    ensure!(bytes.len() == 57 && bytes[0] >> 4 == 0, "adresse Cardano sans clé de mise en jeu : délégation impossible");
    Ok(bytes[29..].try_into().expect("28"))
}

/// Adresse de récompenses (octets) d'une clé de mise en jeu, réseau principal.
fn reward_bytes(stake: &[u8; 28]) -> Vec<u8> {
    let mut bytes = vec![0xe1];
    bytes.extend(stake);
    bytes
}

/// Adresse de récompenses (stake1…) d'une adresse de base.
pub fn reward_address(address: &str) -> Result<String> {
    Ok(bech32::encode("stake", reward_bytes(&stake_key_hash(address)?).to_base32(), bech32::Variant::Bech32).expect("adresse Cardano encodable"))
}

/// Identifiant d'un pool (pool1…) → hachage de 28 octets.
pub fn parse_pool(text: &str) -> Result<[u8; 28]> {
    let (hrp, data, variant) = bech32::decode(text.trim()).map_err(|_| anyhow!("identifiant de pool Cardano invalide"))?;
    ensure!(hrp == "pool" && variant == bech32::Variant::Bech32, "identifiant de pool Cardano invalide");
    Vec::<u8>::from_base32(&data).ok().and_then(|b| b.try_into().ok()).context("identifiant de pool Cardano invalide")
}

/// État de la mise en jeu d'une adresse.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StakeAccount {
    pub registered: bool,
    /// Pool délégué (pool1…).
    pub pool: Option<String>,
    /// Délégation de vote faite (sans elle, récompenses non retirables).
    pub voting: bool,
    /// Récompenses retirables (lovelace).
    pub rewards: u64,
    /// Dépôt versé à l'inscription (rendu à la désinscription).
    pub deposit: u64,
}

fn stake_account_from(value: &Value) -> Result<StakeAccount> {
    let Some(info) = value.as_array().and_then(|a| a.first()) else { return Ok(StakeAccount::default()) };
    Ok(StakeAccount {
        registered: info["status"].as_str() == Some("registered"),
        pool: info["delegated_pool"].as_str().filter(|p| p.starts_with("pool1")).map(str::to_string),
        voting: info["delegated_drep"].as_str().is_some_and(|d| !d.is_empty()),
        rewards: lovelace(&info["rewards_available"]).unwrap_or(0),
        deposit: lovelace(&info["deposit"]).unwrap_or(0),
    })
}

pub fn stake_account(address: &str) -> Result<StakeAccount> {
    stake_account_from(&koios_post("/account_info", json!({ "_stake_addresses": [reward_address(address)?] }))?)
}

/// Pool proposé : identifiant, nom court, marge, coût fixe par époque,
/// mise en jeu active (lovelace).
#[derive(Clone, Debug, PartialEq)]
pub struct Pool {
    pub id: String,
    pub ticker: String,
    pub margin: f64,
    pub fixed_cost: u64,
    pub active_stake: u64,
}

/// Pools proposés : enregistrés, pas en retraite, marge ≤ 2 %, coût fixe ≤
/// 340 ADA, mise en jeu active entre 10 et 55 millions d'ADA (assez pour
/// produire des blocs chaque époque, loin de la saturation ~72 M) ; les plus
/// petites marges d'abord, puis les plus gros. Douze au plus.
fn pick_pools(list: &[Value]) -> Vec<Pool> {
    let mut pools: Vec<Pool> = list
        .iter()
        .filter_map(|p| {
            Some(Pool {
                id: p["pool_id_bech32"].as_str().filter(|id| parse_pool(id).is_ok())?.to_string(),
                ticker: p["ticker"].as_str().map(|t| t.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect::<String>()).filter(|t| !t.is_empty())?,
                margin: p["margin"].as_f64()?,
                fixed_cost: lovelace(&p["fixed_cost"]).ok()?,
                active_stake: lovelace(&p["active_stake"]).ok()?,
            })
        })
        .filter(|p| p.margin <= 0.02 && p.fixed_cost <= 340_000_000 && (10_000_000_000_000..=55_000_000_000_000).contains(&p.active_stake))
        .collect();
    pools.sort_by(|a, b| a.margin.total_cmp(&b.margin).then(b.active_stake.cmp(&a.active_stake)));
    pools.truncate(12);
    pools
}

pub fn pools() -> Result<Vec<Pool>> {
    let mut list = Vec::new();
    for offset in [0, 1000] {
        let page = koios_get(&format!("/pool_list?pool_status=eq.registered&retiring_epoch=is.null&margin=lte.0.02&ticker=not.is.null&select=pool_id_bech32,ticker,margin,fixed_cost,active_stake&limit=1000&offset={offset}"))?;
        let rows = page.as_array().cloned().unwrap_or_default();
        let full = rows.len() == 1000;
        list.extend(rows);
        if !full {
            break;
        }
    }
    let pools = pick_pools(&list);
    ensure!(!pools.is_empty(), "liste des pools Cardano indisponible pour l'instant");
    Ok(pools)
}

/// Nom court d'un pool (affichage de l'état), `None` s'il est inconnu.
pub fn pool_ticker(pool: &str) -> Option<String> {
    parse_pool(pool).ok()?;
    let rows = koios_get(&format!("/pool_list?pool_id_bech32=eq.{pool}&select=ticker")).ok()?;
    rows[0]["ticker"].as_str().map(|t| t.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect())
}

/// Transaction de mise en jeu préparée : exactement ce qui sera signé (hors
/// validité, fixée à l'envoi).
#[derive(Clone, Debug)]
pub struct StakePlan {
    pub certs: Vec<Cert>,
    /// Récompenses retirées (lovelace).
    pub withdrawal: u64,
    /// Dépôt versé (inscription) ou rendu (désinscription).
    pub deposit: u64,
    pub refund: u64,
    pub fee: u64,
    pub change: u64,
    inputs: Vec<Input>,
}

/// Choisit les entrées : les frais (deux signatures) et le dépôt éventuel
/// payés, tout le reste rendu à sa propre adresse.
fn plan_stake(from: &str, certs: Vec<Cert>, withdrawal: u64, deposit: u64, refund: u64) -> Result<StakePlan> {
    let from_bytes = parse_address(from)?;
    let stake = stake_key_hash(from)?;
    let params = params()?;
    let ttl = tip_slot()? + TTL_SLOTS;
    let (utxos, _) = utxos(from.trim())?;
    ensure!(!utxos.is_empty(), "aucun ADA sur cette adresse pour payer les frais du réseau");
    let min_change = params.min_output(&from_bytes);
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for utxo in utxos.iter().take(MAX_INPUTS) {
        inputs.push(utxo.input.clone());
        total += utxo.lovelace;
        let body = Body {
            inputs: inputs.clone(),
            outputs: vec![Output { address: from_bytes.clone(), lovelace: total }],
            fee: MAX_FEE,
            ttl,
            certs: certs.clone(),
            withdrawal: (withdrawal > 0).then(|| (reward_bytes(&stake), withdrawal)),
        };
        let fee = params.fee_of(&body, 2);
        let available = total.saturating_add(withdrawal).saturating_add(refund);
        if let Some(change) = available.checked_sub(deposit + fee).filter(|c| *c >= min_change) {
            ensure!(fee <= MAX_FEE, "frais Cardano anormalement élevés ({} ADA) — refusé", format_ada(fee));
            return Ok(StakePlan { certs, withdrawal, deposit, refund, fee, change, inputs });
        }
    }
    bail!("ADA insuffisants : il faut au moins {} ADA (dépôt et frais du réseau compris)", format_ada(deposit + min_change + 300_000))
}

/// Déléguer à `pool` : inscription (dépôt) si besoin, vote « abstention ».
pub fn plan_delegate(from: &str, account: &StakeAccount, pool: &str) -> Result<StakePlan> {
    let (stake, pool_hash) = (stake_key_hash(from)?, parse_pool(pool)?);
    ensure!(!(account.pool.as_deref() == Some(pool.trim()) && account.voting), "vos ADA sont déjà délégués à ce pool");
    if account.registered {
        plan_stake(from, vec![Cert::Delegate { stake, pool: pool_hash }], 0, 0, 0)
    } else {
        let deposit = params()?.key_deposit;
        plan_stake(from, vec![Cert::RegisterDelegate { stake, pool: pool_hash, deposit }], 0, deposit, 0)
    }
}

/// Sans délégation de vote, des récompenses ne sont pas retirables — et le
/// réseau vérifie les retraits AVANT les certificats de la même transaction
/// (constaté sur un nœud réel) : vote « abstention » d'abord, seul ; le
/// retrait se fait à l'opération suivante. (Les délégations faites par l'app
/// incluent toujours ce vote.)
fn vote_first(from: &str, account: &StakeAccount) -> Result<Option<StakePlan>> {
    if account.rewards == 0 || account.voting {
        return Ok(None);
    }
    Ok(Some(plan_stake(from, vec![Cert::VoteAbstain { stake: stake_key_hash(from)? }], 0, 0, 0)?))
}

impl StakePlan {
    /// Étape préalable seulement (vote « abstention »), voir `vote_first`.
    pub fn vote_only(&self) -> bool {
        matches!(self.certs.as_slice(), [Cert::VoteAbstain { .. }]) && self.withdrawal == 0
    }
}

/// Retirer les récompenses.
pub fn plan_withdraw(from: &str, account: &StakeAccount) -> Result<StakePlan> {
    ensure!(account.registered && account.rewards > 0, "aucune récompense à retirer pour l'instant");
    if let Some(vote) = vote_first(from, account)? {
        return Ok(vote);
    }
    plan_stake(from, Vec::new(), account.rewards, 0, 0)
}

/// Arrêter la délégation : récompenses retirées, désinscription, dépôt rendu.
pub fn plan_undelegate(from: &str, account: &StakeAccount) -> Result<StakePlan> {
    ensure!(account.registered, "vos ADA ne sont pas délégués");
    if let Some(vote) = vote_first(from, account)? {
        return Ok(vote);
    }
    let stake = stake_key_hash(from)?;
    plan_stake(from, vec![Cert::Unregister { stake, deposit: account.deposit }], account.rewards, 0, account.deposit)
}

/// Construit, signe (paiement + mise en jeu) et diffuse ; renvoie l'identifiant.
pub fn send_stake(payment: &XPrv, stake: &XPrv, from: &str, plan: &StakePlan) -> Result<String> {
    ensure!(key_hash(&stake.public()) == stake_key_hash(from)?, "clé de mise en jeu d'un autre compte — refusé");
    let body = Body {
        inputs: plan.inputs.clone(),
        outputs: vec![Output { address: parse_address(from)?, lovelace: plan.change }],
        fee: plan.fee,
        ttl: tip_slot()? + TTL_SLOTS,
        certs: plan.certs.clone(),
        withdrawal: (plan.withdrawal > 0).then(|| (reward_bytes(&key_hash(&stake.public())), plan.withdrawal)),
    };
    ensure!(params()?.fee_of(&body, 2) <= plan.fee, "les frais Cardano ont changé depuis la confirmation — relancez l'opération");
    submit(&sign_with(&body, &[payment, stake]))
}

// --- Historique ----------------------------------------------------------------------------

/// Transactions de l'adresse (net en ADA : sorties reçues − entrées dépensées),
/// les plus récentes d'abord.
pub fn history(address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(address)?;
    let address = address.trim();
    let list = koios_post("/address_txs", json!({ "_addresses": [address] }))?;
    let mut txs: Vec<(u64, String)> = list
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|t| Some((t["block_height"].as_u64().unwrap_or(u64::MAX), t["tx_hash"].as_str()?.to_string())))
        .collect();
    txs.sort_by_key(|t| std::cmp::Reverse(t.0));
    txs.truncate(limit.clamp(1, 25));
    if txs.is_empty() {
        return Ok(Vec::new());
    }
    let hashes: Vec<&str> = txs.iter().map(|t| t.1.as_str()).collect();
    let details = koios_post("/tx_info", json!({ "_tx_hashes": hashes, "_inputs": true }))?;
    let mut entries = Vec::new();
    for tx in details.as_array().map(Vec::as_slice).unwrap_or_default() {
        if let Some(entry) = history_entry(tx, address) {
            entries.push(entry);
        }
    }
    entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp_unix));
    Ok(entries)
}

fn history_entry(tx: &Value, address: &str) -> Option<history::TxEntry> {
    let hash = tx["tx_hash"].as_str().filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))?;
    let sum = |side: &str| -> i128 {
        tx[side].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter(|io| io["payment_addr"]["bech32"].as_str() == Some(address)).filter_map(|io| lovelace(&io["value"]).ok()).map(i128::from).sum()
    };
    let net = sum("outputs") - sum("inputs");
    if net == 0 {
        return None;
    }
    Some(history::TxEntry {
        id: hash.to_string(),
        timestamp_unix: tx["tx_timestamp"].as_i64(),
        status: history::TxStatus::Confirmed,
        net_amount_minor: Some(net),
        fee_minor: 0,
        kind: if net > 0 { history::TxKind::Received } else { history::TxKind::Sent },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq() -> Vec<u8> {
        (1..=32).collect()
    }

    /// Vecteurs de cardano-serialization-lib (clé maîtresse, clés de paiement
    /// et de mise en jeu, adresses de base), indépendants de ce code.
    #[test]
    fn keys_and_addresses_match_the_official_library() {
        let root = XPrv::master(&[0u8; 32]);
        assert_eq!(
            hex::encode([root.kl, root.kr, root.chain].concat()),
            "b07ff3e63c17cd2e0504e4bfd52a98c47abde183ccd0738efc385e764fd91d4bd7d399eeef3c4df68facb3f11e4a4d45513ea1e2a8018aa35b3c078714cfdcedccc42249e17984c44cf380b489f62c57f84089e150245bf49c436d0b9709c58f"
        );
        for (entropy, account, pay, stake, address) in [
            (vec![0u8; 32], 0, "63c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179", "366598ec425ab8140830c4b5f91716d0f7b113fd7013ef3c90487e9dd1535437", "addr1qyqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden77z73dpdfng2ctw2ekqplqgrljelz7h4dneac27nn3qx3rqrhqvwd"),
            (vec![0u8; 32], 7, "79d3b84e8e0eebd1f703262ea734140e540a9518c915585f9c139b6e67d678cc", "c9c9fbe9ca59e4d45656bc64ff48f52fd007ba51a48c48251278589eca6a73bb", "addr1q9fy4k5qvdn47tj0clrsah7l5fmrztcm5hj02ct4h7vceq4xv844wcw4nlt28mpf7h8tzpvcws8znhqrvst498pp00xs9h2xq8"),
            (seq(), 0, "af7875f0a44da469a31e4d27fa46fde45713039279e1c4f3c6269e36aa5ecf26", "1b4799499dc4e86568b9581508e8a413e7da3966f5b6456cbee6decab911121e", "addr1qxl2jwckw20u69f0cq0vkrnuztx93hcmpwswja60txpnxrunu8tugxe0030m7uyvnz3hlppj4e28jyl9c94cque0gavquchxun"),
            (seq(), 1, "6bb53f9cdd10c375a6a4cbb5aca8daa6e3dcc9d1380de1b8c8d30aa01a21f77d", "6b32bf8d23c5a97416aa054763aaf3818219ef1648a45c6436e8b3308d071246", "addr1qxgzh24yclh838lhpraz7htsqk3p6p3xvrwex8h7uakx6vv0ufdahf4ccw55my2vr4ck52z9kjv5rneqkehcf23sqm3smxw2mj"),
        ] {
            let (p, s) = account_keys(&entropy, account);
            assert_eq!((hex::encode(p.public()), hex::encode(s.public())), (pay.to_string(), stake.to_string()), "compte {account}");
            assert_eq!(address_of(&entropy, account), address);
            assert_eq!(parse_address(address).unwrap().len(), 57);
        }
        let (p, _) = account_keys(&seq(), 7);
        assert_eq!(hex::encode([p.kl, p.kr].concat()), "e0f79fca6c15d0ef84965d9bc5efb0947096c90c34a3277ba3f93ad272a05f4f8b1099eb1e5d2caae5269c44ffa59039ea78f2edfa8cb0900d535a5ecd928f11");
    }

    #[test]
    fn addresses_are_parsed_strictly() {
        assert!(parse_address("stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw").unwrap_err().to_string().contains("mise en jeu"));
        assert!(parse_address("addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae").unwrap_err().to_string().contains("test"));
        assert!(parse_address("DdzFFzCqrhsrcTVhLygT24QwTnNqQqQ8mZrq5jykUzMveU26sxaH529kMpo7VhPrt5pwW3dXeB2k3EEvKcNBRmzCfcQ7dTkyGzTs658C").unwrap_err().to_string().contains("Byron"));
        // Adresse « entreprise » (paiement par clé, sans mise en jeu) acceptée.
        assert_eq!(parse_address("addr1vxlsvgpdqusfhceq0m4tunz4j7vyhd60qlyqglpjm7xu0xswl723x").unwrap().len(), 29);
        // Contrat (script de paiement, type 1/3/5/7) : refusé.
        let mut script = parse_address("addr1qxgzh24yclh838lhpraz7htsqk3p6p3xvrwex8h7uakx6vv0ufdahf4ccw55my2vr4ck52z9kjv5rneqkehcf23sqm3smxw2mj").unwrap();
        script[0] = 0x11;
        let text = bech32::encode("addr", script.to_base32(), bech32::Variant::Bech32).unwrap();
        assert!(parse_address(&text).unwrap_err().to_string().contains("script"));
        assert!(parse_address("addr1qxgzh24yclh838lhpraz7htsqk3p6p3xvrwex8h7uakx6vv0ufdahf4ccw55my2vr4ck52z9kjv5rneqkehcf23sqm3smxw2mk").is_err(), "somme de contrôle");
    }

    /// Transaction identique octet pour octet à cardano-serialization-lib
    /// (corps, identifiant, signature, transaction signée) ; frais et
    /// minimum d'une sortie identiques à ses calculs.
    #[test]
    fn transactions_match_the_official_library() {
        let addr = |a| parse_address(&address_of(&seq(), a)).unwrap();
        let body = Body {
            inputs: vec![
                Input { hash: hex::decode("2c80db2dc0e3a3b957d6e96c5d3b2ca024fccd9eed5319b0c65127896216baaf").unwrap().try_into().unwrap(), index: 1 },
                Input { hash: hex::decode("0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829").unwrap().try_into().unwrap(), index: 0 },
            ],
            outputs: vec![Output { address: addr(1), lovelace: 1_500_000 }, Output { address: addr(0), lovelace: 3_200_000 }],
            fee: 170_253,
            ttl: 199_580_000,
            certs: Vec::new(),
            withdrawal: None,
        };
        assert_eq!(hex::encode(body.cbor()), "a400d90102828258202c80db2dc0e3a3b957d6e96c5d3b2ca024fccd9eed5319b0c65127896216baaf018258200a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627282900018282583901902baaa4c7ee789ff708fa2f5d7005a21d062660dd931efee76c6d318fe25bdba6b8c3a94d914c1d716a2845b49941cf20b66f84aa3006e31a0016e36082583901bea93b16729fcd152fc01ecb0e7c12cc58df1b0ba0e9774f5983330f93e1d7c41b2f7c5fbf708c98a37f8432ae547913e5c16b80732f47581a0030d400021a0002990d031a0be55960");
        assert_eq!(hex::encode(body.hash()), "5da0afaa7e0263f217bdd2feb93ebbca5509f8473c90c9b86a3b1c05e9d1ed99");
        let (payment, _) = account_keys(&seq(), 0);
        let signed = sign(&body, &payment);
        assert_eq!(hex::encode(&signed.cbor[signed.cbor.len() - 68..signed.cbor.len() - 2]), "58406d3cc99b37682ca401accb447a7d77dd5d21bae2262afa2d3ac4ffc9077e957072bda7d448c702f25c66f734ca13914c4780be424c16c55d020cd724b001180f");
        assert_eq!(signed.cbor.len(), 332);
        assert!(hex::encode(&signed.cbor).starts_with("84a400d9010282"));
        assert!(hex::encode(&signed.cbor).ends_with("a100d9010281825820af7875f0a44da469a31e4d27fa46fde45713039279e1c4f3c6269e36aa5ecf2658406d3cc99b37682ca401accb447a7d77dd5d21bae2262afa2d3ac4ffc9077e957072bda7d448c702f25c66f734ca13914c4780be424c16c55d020cd724b001180ff5f6"));
        let params = Params { fee_a: 44, fee_b: 155_381, coins_per_byte: 4310, key_deposit: 2_000_000 };
        assert_eq!(params.fee(&body.inputs, &body.outputs, body.ttl), 169_989);
        // Minimum d'une sortie vers une adresse de base : 969 750 lovelace pour
        // un montant à 5 octets ; prudence avec un montant à 9 octets.
        assert_eq!(params.min_output(&addr(1)), 4310 * (160 + 69));
    }

    #[test]
    fn history_counts_only_this_address() {
        let me = "addr1qxl2jwckw20u69f0cq0vkrnuztx93hcmpwswja60txpnxrunu8tugxe0030m7uyvnz3hlppj4e28jyl9c94cque0gavquchxun";
        let io = |a: &str, v: &str| json!({ "payment_addr": { "bech32": a }, "value": v });
        let sent = json!({ "tx_hash": "a".repeat(64), "tx_timestamp": 1_791_000_000, "inputs": [io(me, "5000000")], "outputs": [io("addr1other", "1500000"), io(me, "3330000")] });
        let entry = history_entry(&sent, me).unwrap();
        assert_eq!((entry.net_amount_minor, entry.kind == history::TxKind::Sent), (Some(-1_670_000), true));
        let received = json!({ "tx_hash": "b".repeat(64), "tx_timestamp": 1, "inputs": [io("addr1other", "9000000")], "outputs": [io(me, "2000000"), io("addr1other", "6800000")] });
        assert_eq!(history_entry(&received, me).unwrap().net_amount_minor, Some(2_000_000));
    }

    /// Réel, réseau principal : lectures, puis transaction bien formée et
    /// signée qui dépense une entrée INEXISTANTE — le nœud doit la refuser pour
    /// l'entrée (BadInputs) et PAS pour la signature ; même transaction à la
    /// signature altérée : refusée pour la signature (InvalidWitnesses).
    /// `cargo test -- --ignored real_cardano --nocapture`
    #[test]
    #[ignore]
    fn real_cardano_reads_and_signature() {
        let rich = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x";
        println!("solde {} ADA, {} transactions récentes", format_ada(balance(rich).unwrap()), history(rich, 5).unwrap().len());
        let p = params().unwrap();
        println!("frais {} × octet + {}, {} lovelace/octet de sortie", p.fee_a, p.fee_b, p.coins_per_byte);
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let (payment, _) = account_keys(&entropy, 0);
        let from = address_of(&entropy, 0);
        // Sortie EXISTANTE d'un tiers (la réserve de transactions refuse
        // d'emblée une entrée inexistante, avant les signatures) : le nœud
        // vérifie les signatures fournies et ne réclame que celle du
        // propriétaire de l'entrée.
        let (theirs, _) = utxos(rich).unwrap();
        let input = theirs.first().expect("aucune sortie de référence").input.clone();
        let body = Body { inputs: vec![input.clone()], outputs: vec![Output { address: parse_address(rich).unwrap(), lovelace: 1_500_000 }], fee: 200_000, ttl: tip_slot().unwrap() + TTL_SLOTS, certs: Vec::new(), withdrawal: None };
        let error = submit_full(&sign(&body, &payment)).unwrap().unwrap_err();
        println!("{}", &error[..error.len().min(600)]);
        assert!(error.contains("MissingVKeyWitnessesUTXOW") && !error.contains("InvalidWitnessesUTXOW"), "{error}");
        let mut tampered = sign(&body, &payment);
        let at = tampered.cbor.len() - 3;
        tampered.cbor[at] ^= 1;
        let error = submit_full(&tampered).unwrap().unwrap_err();
        assert!(error.contains("InvalidWitnessesUTXOW"), "{error}");
        // Adresse neuve : rien à envoyer.
        assert!(plan(&from, rich, 2_000_000).unwrap_err().to_string().contains("aucun ADA"));

        // Délégation (inscription + pool + vote) et retrait + désinscription,
        // signés par les clés de paiement ET de mise en jeu : le nœud lit les
        // certificats (aucune erreur de décodage), accepte nos deux signatures
        // et ne réclame que celle du propriétaire de l'entrée. (Retrait sur
        // une clé jamais inscrite : refus de règles — attendu.)
        let (payment, stake) = account_keys(&entropy, 0);
        let stake_hash = key_hash(&stake.public());
        let pool = pools().unwrap().first().unwrap().id.clone();
        let deposit = params().unwrap().key_deposit;
        for (certs, withdrawal) in [
            (vec![Cert::RegisterDelegate { stake: stake_hash, pool: parse_pool(&pool).unwrap(), deposit }], None),
            (vec![Cert::VoteAbstain { stake: stake_hash }, Cert::Unregister { stake: stake_hash, deposit }], Some((reward_bytes(&stake_hash), 1_000_000))),
        ] {
            let body = Body { inputs: vec![input.clone()], outputs: vec![Output { address: parse_address(rich).unwrap(), lovelace: 1_500_000 }], fee: 300_000, ttl: tip_slot().unwrap() + TTL_SLOTS, certs, withdrawal };
            let error = submit_full(&sign_with(&body, &[&payment, &stake])).unwrap().unwrap_err();
            println!("{}", &error[..error.len().min(900)]);
            assert!(error.contains("MissingVKeyWitnessesUTXOW") && !error.contains("InvalidWitnessesUTXOW") && !error.contains("Deserialis") && !error.contains("DecoderError"), "{error}");
        }
    }

    /// Certificats et retrait : encodage CBOR de l'ère Conway (étiquette 258
    /// pour l'ensemble, identifiants de la spécification) ; adresse de
    /// récompenses et pool.
    #[test]
    fn stake_certificates_are_encoded() {
        let stake = [7u8; 28];
        let pool = [9u8; 28];
        let mut c = Cbor::default();
        cert_cbor(&mut c, &Cert::RegisterDelegate { stake, pool, deposit: 2_000_000 });
        assert_eq!(hex::encode(&c.0), format!("850d8200581c{}581c{}8102{}", hex::encode(stake), hex::encode(pool), "1a001e8480"));
        let mut c = Cbor::default();
        cert_cbor(&mut c, &Cert::Unregister { stake, deposit: 2_000_000 });
        assert_eq!(hex::encode(&c.0), format!("83088200581c{}1a001e8480", hex::encode(stake)));
        let mut c = Cbor::default();
        cert_cbor(&mut c, &Cert::VoteAbstain { stake });
        assert_eq!(hex::encode(&c.0), format!("83098200581c{}8102", hex::encode(stake)));
        let body = Body { inputs: vec![Input { hash: [1; 32], index: 0 }], outputs: vec![], fee: 1, ttl: 2, certs: vec![Cert::Delegate { stake, pool }], withdrawal: Some((reward_bytes(&stake), 5)) };
        let cbor = hex::encode(body.cbor());
        assert!(cbor.starts_with("a6"), "6 champs");
        assert!(cbor.contains(&format!("04d9010281840a8200581c{}581c{}8102", hex::encode(stake), hex::encode(pool))));
        assert!(cbor.ends_with(&format!("05a1581de1{}05", hex::encode(stake))));
        // Adresse de récompenses de l'adresse de base de référence (vecteur de
        // cardano-serialization-lib : clé de mise en jeu du compte 0).
        let address = address_of(&[0u8; 32], 0);
        let (_, stake_key) = account_keys(&[0u8; 32], 0);
        assert_eq!(stake_key_hash(&address).unwrap(), key_hash(&stake_key.public()));
        assert!(reward_address(&address).unwrap().starts_with("stake1u"));
        assert!(reward_address("addr1vxlsvgpdqusfhceq0m4tunz4j7vyhd60qlyqglpjm7xu0xswl723x").is_err(), "adresse sans clé de mise en jeu");
        assert_eq!(parse_pool("pool1z5uqdk7dzdxaae5633fqfcu2eqzy3a3rgtuvy087fdld7yws0xt").unwrap().to_vec(), hex::decode("153806dbcd134ddee69a8c5204e38ac80448f62342f8c23cfe4b7edf").unwrap());
        assert!(parse_pool("stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw").is_err());
    }

    /// État d'un compte (forme réelle de Koios) et choix des pools.
    #[test]
    fn stake_account_and_pools_are_read() {
        let account = stake_account_from(&json!([{ "status": "registered", "delegated_pool": "pool1pu5jlj4q9w9jlxeu370a3c9myx47md5j5m2str0naunn2q3lkdy", "delegated_drep": null, "rewards_available": "1500000", "deposit": "2000000" }])).unwrap();
        assert_eq!((account.registered, account.voting, account.rewards, account.deposit), (true, false, 1_500_000, 2_000_000));
        assert_eq!(stake_account_from(&json!([])).unwrap(), StakeAccount::default(), "jamais inscrite");
        let row = |ticker: &str, margin: f64, stake: &str| json!({ "pool_id_bech32": "pool1z5uqdk7dzdxaae5633fqfcu2eqzy3a3rgtuvy087fdld7yws0xt", "ticker": ticker, "margin": margin, "fixed_cost": "340000000", "active_stake": stake });
        let picked = pick_pools(&[row("BIG", 0.01, "30000000000000"), row("CHEAP", 0.0, "20000000000000"), row("TINY", 0.0, "100000000"), row("FULL", 0.0, "70000000000000"), row("<b>", 0.0, "20000000000000")]);
        let tickers: Vec<&str> = picked.iter().map(|p| p.ticker.as_str()).collect();
        assert_eq!(tickers, vec!["CHEAP", "b", "BIG"], "trop petit et saturé écartés ; nom nettoyé");
    }

}
