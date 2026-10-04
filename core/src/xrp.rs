//! XRP Ledger : adresse r… (BIP44 m/44'/144'/0'/0/p, clé secp256k1),
//! solde, envoi de XRP, historique.
//!
//! Transactions sérialisées et signées ici (format binaire canonique du
//! XRP Ledger, condensé SHA-512Half préfixé « STX\0 », signature DER low-S),
//! vérifiées contre les bibliothèques officielles de Ripple
//! (ripple-binary-codec, ripple-address-codec) dans les tests.
//!
//! Règles du réseau appliquées avant la boîte de confirmation :
//! - réserve : 1 XRP (+ 0,2 par objet possédé) reste bloqué sur le compte,
//!   jamais envoyable (relevé le 04/10/2026, `server_state`) ;
//! - un destinataire jamais activé doit recevoir au moins la réserve de
//!   base, sinon le réseau refuse le paiement ;
//! - un destinataire qui EXIGE un tag de destination (plateformes
//!   d'échange, drapeau `lsfRequireDestTag`) ne reçoit rien sans tag ;
//! - un destinataire « paiements autorisés seulement » (`lsfDepositAuth`)
//!   qui n'a pas autorisé l'expéditeur ferait échouer le paiement, frais
//!   perdus : refusé avant ;
//! - frais : ceux du réseau (`fee`), plafonnés.

use crate::{btc_tx, history};
use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::sync::OnceLock;

/// Nœuds publics (JSON-RPC), dans l'ordre.
const NODES: [&str; 3] = ["https://xrplcluster.com", "https://s1.ripple.com:51234", "https://s2.ripple.com:51234"];
pub const DECIMALS: u8 = 6;
/// Plafond des frais acceptés (0,001 XRP ; 0,00001 au repos).
const MAX_FEE_DROPS: u64 = 1_000;
/// Validité d'une transaction : 20 registres (~1 min) après le dernier validé.
const LEDGER_MARGIN: u32 = 20;
/// Erreurs d'un nœud qui ne disent rien du compte ni de la transaction.
const TRANSIENT_ERRORS: [&str; 6] = ["tooBusy", "slowDown", "noNetwork", "noCurrent", "noClosed", "amendmentBlocked"];
/// Drapeau de compte « tag de destination exigé ».
const LSF_REQUIRE_DEST_TAG: u64 = 0x0002_0000;
/// Drapeau de compte « paiements autorisés seulement » (DepositAuth).
const LSF_DEPOSIT_AUTH: u64 = 0x0100_0000;

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

fn rpc(method: &str, params: Value) -> Result<Value> {
    let mut last = anyhow!("nœud XRP injoignable");
    for node in NODES {
        let attempt = (|| -> Result<Value> {
            let response = client().post(node).json(&json!({ "method": method, "params": [params] })).send().context("nœud XRP injoignable")?;
            let status = response.status();
            ensure!(status.is_success(), "nœud XRP : réponse {status}");
            let value: Value = response.json().context("réponse du nœud XRP illisible")?;
            let result = value["result"].clone();
            // Nœud surchargé ou pas à jour : on essaie le suivant.
            if let Some(error) = result["error"].as_str().filter(|e| TRANSIENT_ERRORS.contains(e)) {
                bail!("nœud XRP : réponse {error}");
            }
            Ok(result)
        })();
        match attempt {
            Ok(result) => return Ok(result),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Montant en XRP, 6 décimales (« 12.500000 »).
pub fn format_xrp(drops: u64) -> String {
    format!("{}.{:06}", drops / 1_000_000, drops % 1_000_000)
}

// --- Adresses ------------------------------------------------------------------------

pub type AccountId = [u8; 20];

/// Identifiant de compte d'une clé : RIPEMD-160(SHA-256(clé publique compressée)).
pub fn account_id(key: &SigningKey) -> AccountId {
    use ripemd::Ripemd160;
    Ripemd160::digest(Sha256::digest(key.verifying_key().to_encoded_point(true).as_bytes())).into()
}

pub fn encode_address(account: &AccountId) -> String {
    let mut data = vec![0u8];
    data.extend_from_slice(account);
    let check = btc_tx::dsha256(&data);
    data.extend_from_slice(&check[..4]);
    bs58::encode(data).with_alphabet(bs58::Alphabet::RIPPLE).into_string()
}

/// Adresse classique r…, somme de contrôle vérifiée. Les adresses « X »
/// (tag intégré) sont refusées avec une consigne.
pub fn parse_address(text: &str) -> Result<AccountId> {
    let text = text.trim();
    ensure!(!text.starts_with('X'), "adresse XRP « X » non prise en charge : demandez l'adresse classique r… et le tag de destination");
    let data = bs58::decode(text).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().map_err(|_| anyhow!("adresse XRP invalide"))?;
    ensure!(data.len() == 25, "adresse XRP invalide");
    let (body, check) = data.split_at(21);
    ensure!(btc_tx::dsha256(body)[..4] == *check, "adresse XRP invalide (somme de contrôle)");
    ensure!(body[0] == 0, "adresse XRP invalide");
    body[1..].try_into().map_err(|_| anyhow!("adresse XRP invalide"))
}

// --- Sérialisation canonique (Payment) ---------------------------------------------------

fn field_id(out: &mut Vec<u8>, type_code: u8, field_code: u8) {
    match (type_code < 16, field_code < 16) {
        (true, true) => out.push((type_code << 4) | field_code),
        (true, false) => out.extend_from_slice(&[type_code << 4, field_code]),
        (false, true) => out.extend_from_slice(&[field_code, type_code]),
        (false, false) => out.extend_from_slice(&[0, type_code, field_code]),
    }
}

fn vl(out: &mut Vec<u8>, bytes: &[u8]) {
    // Longueurs utilisées ici : toujours < 193 (un octet).
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn native_amount(drops: u64) -> [u8; 8] {
    (0x4000_0000_0000_0000u64 | drops).to_be_bytes()
}

/// Paiement de XRP à sérialiser.
#[derive(Clone, Debug)]
pub struct Payment {
    pub account: AccountId,
    pub destination: AccountId,
    pub amount: u64,
    pub fee: u64,
    pub sequence: u32,
    pub destination_tag: Option<u32>,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: [u8; 33],
}

impl Payment {
    /// Champs triés par (type, champ) ; signature incluse si donnée.
    fn serialize(&self, signature: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        field_id(&mut out, 1, 2); // TransactionType
        out.extend_from_slice(&0u16.to_be_bytes()); // Payment
        field_id(&mut out, 2, 2); // Flags
        out.extend_from_slice(&0u32.to_be_bytes());
        field_id(&mut out, 2, 4); // Sequence
        out.extend_from_slice(&self.sequence.to_be_bytes());
        if let Some(tag) = self.destination_tag {
            field_id(&mut out, 2, 14); // DestinationTag
            out.extend_from_slice(&tag.to_be_bytes());
        }
        field_id(&mut out, 2, 27); // LastLedgerSequence
        out.extend_from_slice(&self.last_ledger_sequence.to_be_bytes());
        field_id(&mut out, 6, 1); // Amount
        out.extend_from_slice(&native_amount(self.amount));
        field_id(&mut out, 6, 8); // Fee
        out.extend_from_slice(&native_amount(self.fee));
        field_id(&mut out, 7, 3); // SigningPubKey
        vl(&mut out, &self.signing_pub_key);
        if let Some(signature) = signature {
            field_id(&mut out, 7, 4); // TxnSignature
            vl(&mut out, signature);
        }
        field_id(&mut out, 8, 1); // Account
        vl(&mut out, &self.account);
        field_id(&mut out, 8, 3); // Destination
        vl(&mut out, &self.destination);
        out
    }

    /// Condensé signé : SHA-512Half(« STX\0 » ‖ transaction sans signature).
    fn signing_hash(&self) -> [u8; 32] {
        sha512_half(&[b"STX\0".as_slice(), &self.serialize(None)].concat())
    }
}

fn sha512_half(data: &[u8]) -> [u8; 32] {
    let full = Sha512::digest(data);
    full[..32].try_into().expect("32 octets")
}

pub struct Signed {
    pub blob: Vec<u8>,
    /// Identifiant : SHA-512Half(« TXN\0 » ‖ transaction signée), en majuscules.
    pub hash: String,
}

pub fn sign(payment: &Payment, key: &SigningKey) -> Result<Signed> {
    let signature: Signature = key.sign_prehash(&payment.signing_hash()).map_err(|e| anyhow!("signature XRP impossible ({e})"))?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let der = signature.to_der();
    let blob = payment.serialize(Some(der.as_bytes()));
    let hash = hex::encode_upper(sha512_half(&[b"TXN\0".as_slice(), &blob].concat()));
    Ok(Signed { blob, hash })
}

// --- Compte et réseau ----------------------------------------------------------------------

/// État d'un compte : `None` s'il n'est pas encore activé.
struct AccountState {
    balance: u64,
    sequence: u32,
    owner_count: u64,
    flags: u64,
}

fn account_state(address: &str) -> Result<Option<AccountState>> {
    parse_address(address)?;
    let result = rpc("account_info", json!({ "account": address.trim(), "ledger_index": "validated" }))?;
    if result["error"].as_str() == Some("actNotFound") {
        return Ok(None);
    }
    let data = &result["account_data"];
    ensure!(result["status"].as_str() == Some("success") && data.is_object(), "réponse du nœud XRP illisible");
    Ok(Some(AccountState {
        balance: data["Balance"].as_str().and_then(|b| b.parse().ok()).context("solde XRP illisible")?,
        sequence: data["Sequence"].as_u64().and_then(|s| u32::try_from(s).ok()).context("séquence XRP illisible")?,
        owner_count: data["OwnerCount"].as_u64().unwrap_or(0),
        flags: data["Flags"].as_u64().unwrap_or(0),
    }))
}

struct Network {
    base_reserve: u64,
    owner_reserve: u64,
    validated_ledger: u32,
}

fn network() -> Result<Network> {
    let state = rpc("server_state", json!({}))?;
    let ledger = &state["state"]["validated_ledger"];
    Ok(Network {
        base_reserve: ledger["reserve_base"].as_u64().context("réserve XRP illisible")?,
        owner_reserve: ledger["reserve_inc"].as_u64().context("réserve XRP illisible")?,
        validated_ledger: ledger["seq"].as_u64().and_then(|s| u32::try_from(s).ok()).context("registre XRP illisible")?,
    })
}

/// Frais du moment (drops), plafonnés.
fn current_fee() -> Result<u64> {
    let result = rpc("fee", json!({}))?;
    let fee = result["drops"]["open_ledger_fee"].as_str().and_then(|f| f.parse::<u64>().ok()).context("frais XRP illisibles")?.max(10);
    ensure!(fee <= MAX_FEE_DROPS, "frais du réseau XRP anormalement élevés ({} XRP) — réessayez plus tard", format_xrp(fee));
    Ok(fee)
}

/// Solde total (drops), réserve comprise ; 0 pour un compte non activé.
pub fn balance(address: &str) -> Result<u64> {
    Ok(account_state(address)?.map_or(0, |a| a.balance))
}

/// Activité d'une adresse destinataire : (détient des XRP, a déjà servi).
pub fn address_activity(address: &str) -> Result<(bool, bool)> {
    Ok(match account_state(address)? {
        Some(a) => (a.balance > 0, true),
        None => (false, false),
    })
}

/// Envoi préparé pour la boîte de confirmation.
#[derive(Clone, Copy, Debug)]
pub struct XrpPlan {
    pub amount: u64,
    pub fee: u64,
    /// XRP bloqués par la réserve sur le compte de départ.
    pub reserve: u64,
    /// Destinataire jamais activé (le paiement l'active).
    pub activates: bool,
}

/// Contrôles du réseau (réserve, activation, tag exigé) et frais.
pub fn plan_xrp(from: &str, to: &str, amount: u64, destination_tag: Option<u32>) -> Result<XrpPlan> {
    ensure!(amount > 0, "montant nul");
    ensure!(parse_address(from)? != parse_address(to)?, "envoi vers votre propre adresse XRP");
    let net = network()?;
    let sender = account_state(from)?.context("compte XRP pas encore activé : il doit d'abord recevoir au moins 1 XRP")?;
    let reserve = net.base_reserve + net.owner_reserve * sender.owner_count;
    let fee = current_fee()?;
    let spendable = sender.balance.saturating_sub(reserve);
    ensure!(
        amount.checked_add(fee).is_some_and(|need| need <= spendable),
        "XRP insuffisants : {} XRP envoyables ({} XRP restent bloqués par la réserve du réseau), {} XRP + {} XRP de frais demandés",
        format_xrp(spendable.saturating_sub(fee)),
        format_xrp(reserve),
        format_xrp(amount),
        format_xrp(fee)
    );
    let destination = account_state(to)?;
    if destination.is_none() {
        ensure!(
            amount >= net.base_reserve,
            "ce destinataire n'est pas encore activé : envoyez-lui au moins {} XRP (réserve du réseau)",
            format_xrp(net.base_reserve)
        );
    }
    if let Some(d) = &destination {
        ensure!(destination_tag.is_some() || d.flags & LSF_REQUIRE_DEST_TAG == 0, "ce destinataire exige un tag de destination (plateforme d'échange) : renseignez-le");
        if d.flags & LSF_DEPOSIT_AUTH != 0 {
            let result = rpc("deposit_authorized", json!({ "source_account": from.trim(), "destination_account": to.trim(), "ledger_index": "validated" }))?;
            ensure!(result["deposit_authorized"].as_bool() == Some(true), "ce destinataire n'accepte que les paiements qu'il a autorisés, et pas le vôtre");
        }
    }
    Ok(XrpPlan { amount, fee, reserve, activates: destination.is_none() })
}

/// Plus grand montant envoyable : solde moins la réserve et les frais.
pub fn max_xrp(from: &str) -> Result<u64> {
    let net = network()?;
    let sender = account_state(from)?.context("compte XRP pas encore activé : il doit d'abord recevoir au moins 1 XRP")?;
    let reserve = net.base_reserve + net.owner_reserve * sender.owner_count;
    sender.balance.saturating_sub(reserve).checked_sub(current_fee()?).filter(|m| *m > 0).context("XRP insuffisants : tout le solde est bloqué par la réserve du réseau")
}

/// Construit, signe et diffuse un paiement ; renvoie son identifiant.
pub fn send_xrp(key: &SigningKey, to: &AccountId, amount: u64, fee: u64, destination_tag: Option<u32>) -> Result<String> {
    ensure!(fee <= MAX_FEE_DROPS, "frais du réseau XRP anormalement élevés — envoi refusé");
    let account = account_id(key);
    let state = account_state(&encode_address(&account))?.context("compte XRP pas encore activé")?;
    let net = network()?;
    let payment = Payment {
        account,
        destination: *to,
        amount,
        fee,
        sequence: state.sequence,
        destination_tag,
        last_ledger_sequence: net.validated_ledger + LEDGER_MARGIN,
        signing_pub_key: key.verifying_key().to_encoded_point(true).as_bytes().try_into().map_err(|_| anyhow!("clé XRP invalide"))?,
    };
    let signed = sign(&payment, key)?;
    submit(&signed)
}

pub fn submit(signed: &Signed) -> Result<String> {
    let result = rpc("submit", json!({ "tx_blob": hex::encode_upper(&signed.blob) }))?;
    let engine = result["engine_result"].as_str().unwrap_or("");
    // Accepté (ou mis en file d'attente) par le réseau.
    if engine == "tesSUCCESS" || engine == "terQUEUED" {
        return Ok(signed.hash.clone());
    }
    let message = ["engine_result_message", "error_exception", "error_message", "error"].iter().find_map(|k| result[*k].as_str()).unwrap_or("erreur inconnue");
    let detail = [engine, message].iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join(" ");
    // tec… : le paiement échoue mais la transaction entre dans le registre et
    // ses frais sont prélevés (les contrôles d'avant la boîte l'évitent).
    if engine.starts_with("tec") {
        bail!("transaction XRP refusée : {detail} — frais du réseau prélevés (identifiant {})", signed.hash);
    }
    bail!("transaction XRP refusée : {detail}")
}

// --- Historique ----------------------------------------------------------------------------

/// Paiements en XRP de l'adresse, les plus récents d'abord.
pub fn history(address: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    parse_address(address)?;
    let result = rpc("account_tx", json!({ "account": address.trim(), "limit": limit.clamp(1, 50), "ledger_index_min": -1, "ledger_index_max": -1 }))?;
    if result["error"].as_str() == Some("actNotFound") {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in result["transactions"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let tx = &item["tx"];
        if tx["TransactionType"].as_str() != Some("Payment") {
            continue;
        }
        let Some(hash) = tx["hash"].as_str().filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())) else { continue };
        // Montant réellement livré, en XRP seulement (jetons ignorés).
        let Some(delivered) = item["meta"]["delivered_amount"].as_str().and_then(|d| d.parse::<i128>().ok()) else { continue };
        let fee = tx["Fee"].as_str().and_then(|f| f.parse::<i128>().ok()).unwrap_or(0);
        let outgoing = tx["Account"].as_str() == Some(address.trim());
        // Paiement d'un tiers qui ne fait que traverser le compte : ignoré.
        if !outgoing && tx["Destination"].as_str() != Some(address.trim()) {
            continue;
        }
        let net = if outgoing { -(delivered + fee) } else { delivered };
        let success = item["meta"]["TransactionResult"].as_str() == Some("tesSUCCESS");
        // Date du registre : secondes depuis le 1er janvier 2000 (UTC).
        let timestamp_unix = tx["date"].as_i64().map(|d| d + 946_684_800);
        entries.push(history::TxEntry {
            id: hash.to_string(),
            timestamp_unix,
            status: if success { history::TxStatus::Confirmed } else { history::TxStatus::Failed },
            net_amount_minor: Some(net),
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

    /// Vecteurs calculés avec bip32 + ripple-address-codec / ripple-binary-codec
    /// (bibliothèques officielles de Ripple), indépendants de ce code.
    #[test]
    fn addresses_and_serialization_match_the_official_libraries() {
        let seed = hex::decode(SEED).unwrap();
        for (index, expected) in [(0, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"), (1, "r3AgF9mMBFtaLhKcg96weMhbbEFLZ3mx17"), (7, "rny6pTkxmEcJhTJoUKVK3Xri1QGjjuAXFu")] {
            let (key, account) = crate::derivation::derive_xrp_key(&seed, index).unwrap();
            assert_eq!(account, account_id(&key));
            assert_eq!(encode_address(&account), expected, "index {index}");
            assert_eq!(parse_address(expected).unwrap(), account);
        }
        assert!(parse_address("rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v4").is_err(), "somme de contrôle");
        assert!(parse_address("XVLhHMPHU98es4dbozjVtdWzVrDjtV5fdx1mHp98tDMoQXb").unwrap_err().to_string().contains("« X »"));
        let (key, account) = crate::derivation::derive_xrp_key(&seed, 0).unwrap();
        let payment = Payment {
            account,
            destination: parse_address("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap(),
            amount: 1_500_000,
            fee: 12,
            sequence: 7,
            destination_tag: Some(12345),
            last_ledger_sequence: 107_433_100,
            signing_pub_key: key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap(),
        };
        assert_eq!(
            hex::encode_upper([b"STX\0".as_slice(), &payment.serialize(None)].concat()),
            "53545800120000220000000024000000072E00003039201B06674C8C61400000000016E36068400000000000000C7321031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE8114AFF3C2E33458B30714CA16FFEE19952DD35C17C88314F667B0CA50CC7709A220B0561B85E53A48461FA8"
        );
        assert_eq!(hex::encode(payment.signing_hash()), "4d82007370e98e47d4b1fd2a60d740d6b1b62287cd2b0cdb6b79885bde48c0da");
        let dummy = hex::decode("3045022100AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899022011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();
        let blob = payment.serialize(Some(&dummy));
        assert_eq!(
            hex::encode_upper(&blob),
            "120000220000000024000000072E00003039201B06674C8C61400000000016E36068400000000000000C7321031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE74473045022100AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899022011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEEFF8114AFF3C2E33458B30714CA16FFEE19952DD35C17C88314F667B0CA50CC7709A220B0561B85E53A48461FA8"
        );
        assert_eq!(hex::encode_upper(sha512_half(&[b"TXN\0".as_slice(), &blob].concat())), "8DFC2DEFA82649C9CBAF5205F88C4F971AFFCA477398CA1CD1C2601270BBECF7");
    }

    #[test]
    fn signatures_are_low_s_and_verify() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let seed = hex::decode(SEED).unwrap();
        let (key, account) = crate::derivation::derive_xrp_key(&seed, 0).unwrap();
        let payment = Payment { account, destination: [7; 20], amount: 1, fee: 10, sequence: 1, destination_tag: None, last_ledger_sequence: 1, signing_pub_key: key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap() };
        let signed = sign(&payment, &key).unwrap();
        // TxnSignature : champ 0x74, longueur, DER.
        let at = signed.blob.windows(2).position(|w| w[0] == 0x74 && (70..=72).contains(&w[1])).unwrap();
        let der = &signed.blob[at + 2..at + 2 + signed.blob[at + 1] as usize];
        let signature = Signature::from_der(der).unwrap();
        assert!(signature.normalize_s().is_none(), "low-S");
        key.verifying_key().verify_prehash(&payment.signing_hash(), &signature).unwrap();
        assert_eq!(signed.hash.len(), 64);
    }

    /// Réel : lectures (solde, réserve, frais, historique), règles du réseau
    /// (tag exigé, activation) et paiement signé
    /// depuis un compte jamais activé — refusé pour le COMPTE (terNO_ACCOUNT),
    /// après la vérification de signature du nœud.
    /// `cargo test -- --ignored real_xrp --nocapture`
    #[test]
    #[ignore]
    fn real_xrp_reads_and_signature() {
        let rich = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh";
        println!("solde {} XRP", format_xrp(balance(rich).unwrap()));
        let net = network().unwrap();
        println!("réserve {} + {} XRP, registre {}, frais {} drops", format_xrp(net.base_reserve), format_xrp(net.owner_reserve), net.validated_ledger, current_fee().unwrap());
        println!("{} paiements récents", history(rich, 10).unwrap().len());
        let key = SigningKey::from_slice(&[0x5a; 32]).unwrap();
        let account = account_id(&key);
        let payment = Payment {
            account,
            destination: parse_address(rich).unwrap(),
            amount: 1_000_000,
            fee: 12,
            sequence: 1,
            destination_tag: None,
            last_ledger_sequence: net.validated_ledger + LEDGER_MARGIN,
            signing_pub_key: key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap(),
        };
        let signed = sign(&payment, &key).unwrap();
        let error = submit(&signed).unwrap_err().to_string();
        println!("{error}");
        assert!(error.contains("terNO_ACCOUNT"), "{error}");
        // Contre-épreuve : même transaction, signature altérée → refusée AVANT.
        let mut blob = signed.blob.clone();
        let at = blob.windows(2).position(|w| w[0] == 0x74 && (70..=72).contains(&w[1])).unwrap();
        blob[at + 10] ^= 1;
        let error = submit(&Signed { blob, hash: signed.hash.clone() }).unwrap_err().to_string();
        println!("{error}");
        assert!(!error.contains("terNO_ACCOUNT") && error.to_lowercase().contains("signature"), "{error}");
        assert!(plan_xrp(&encode_address(&account), rich, 1_000_000, None).unwrap_err().to_string().contains("pas encore activé"));
        // Règles du réseau, depuis un compte pourvu (lecture seule).
        let funded = "rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1";
        let error = plan_xrp(funded, rich, 1_000_000, None).unwrap_err().to_string();
        assert!(error.contains("exige un tag"), "{error}");
        let plan = plan_xrp(funded, rich, 1_000_000, Some(7)).unwrap();
        assert!(!plan.activates && plan.fee >= 10 && plan.reserve >= 1_000_000, "{plan:?}");
        let fresh = encode_address(&account);
        let error = plan_xrp(funded, &fresh, 999_999, None).unwrap_err().to_string();
        assert!(error.contains("au moins 1.000000 XRP"), "{error}");
        assert!(plan_xrp(funded, &fresh, 1_000_000, None).unwrap().activates);
        assert!(max_xrp(funded).unwrap() > 0);
    }
}
