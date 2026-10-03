//! Transactions natives THORChain et Maya (Cosmos SDK) : dépôt `MsgDeposit`,
//! seul usage dans l'app — inscrire ou prolonger le nom d'affiliation du
//! développeur (THORName / MAYAName, voir `thorchain_rpc::AFFILIATE_NAME`),
//! payé en RUNE ou en CACAO depuis son adresse d'affiliation.
//!
//! Encodage protobuf écrit ici (quelques champs seulement), reproduit octet
//! pour octet sur de vraies inscriptions relevées sur chaque réseau (tests :
//! corps et informations de signature reconstruits identiques, signature
//! d'origine vérifiée sur le document de signature calculé ici). Signature
//! « DIRECT » : SHA-256 du document de signature, ECDSA secp256k1, S bas.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};
use serde_json::Value;
use std::sync::OnceLock;

/// Réseau natif : paramètres relevés sur de vraies transactions.
pub struct NativeChain {
    pub name: &'static str,
    node_base: &'static str,
    pub chain_id: &'static str,
    /// Préfixe bech32 des adresses (« thor », « maya »).
    pub hrp: &'static str,
    /// Monnaie du réseau dans un dépôt : chaîne, symbole, ticker.
    asset: (&'static str, &'static str, &'static str),
    /// Dénomination de la monnaie dans le module bank (« rune », « cacao »).
    pub denom: &'static str,
    /// Décimales de la monnaie.
    pub decimals: u32,
    /// Champ `decimals` du jeton dans le message (Maya le renseigne,
    /// THORChain non).
    coin_decimals_field: bool,
    /// Frais déclarés dans la transaction (THORChain : 0,02 RUNE ; Maya :
    /// aucun, prélevés par le protocole).
    declared_fee: Option<u64>,
    gas_limit: u64,
    /// Memo recopié dans le corps de la transaction (Maya).
    body_memo: bool,
}

pub const THORCHAIN: NativeChain = NativeChain {
    name: "THORChain",
    node_base: "https://gateway.liquify.com/chain/thorchain_api",
    chain_id: "thorchain-1",
    hrp: "thor",
    asset: ("THOR", "RUNE", "RUNE"),
    denom: "rune",
    decimals: 8,
    coin_decimals_field: false,
    declared_fee: Some(2_000_000),
    gas_limit: 400_000,
    body_memo: false,
};

pub const MAYA: NativeChain = NativeChain {
    name: "Maya",
    node_base: "https://mayanode.mayachain.info",
    chain_id: "mayachain-mainnet-v1",
    hrp: "maya",
    asset: ("MAYA", "CACAO", "CACAO"),
    denom: "cacao",
    decimals: 10,
    coin_decimals_field: true,
    declared_fee: None,
    gas_limit: 2_000_000_000,
    body_memo: true,
};

// --- Encodage protobuf (le strict nécessaire) ---------------------------------

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Champ de longueur variable (texte, octets, message) ; omis s'il est vide,
/// comme le fait protobuf 3.
fn field_bytes(out: &mut Vec<u8>, number: u64, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    varint(out, number << 3 | 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Champ entier ; omis s'il vaut 0.
fn field_varint(out: &mut Vec<u8>, number: u64, value: u64) {
    if value == 0 {
        return;
    }
    varint(out, number << 3);
    varint(out, value);
}

fn any(type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    field_bytes(&mut out, 1, type_url.as_bytes());
    field_bytes(&mut out, 2, value);
    out
}

/// `types.MsgDeposit { coins, memo, signer }`.
fn msg_deposit(chain: &NativeChain, amount: u128, memo: &str, signer: &[u8; 20]) -> Vec<u8> {
    let mut asset = Vec::new();
    field_bytes(&mut asset, 1, chain.asset.0.as_bytes());
    field_bytes(&mut asset, 2, chain.asset.1.as_bytes());
    field_bytes(&mut asset, 3, chain.asset.2.as_bytes());
    let mut coin = Vec::new();
    field_bytes(&mut coin, 1, &asset);
    field_bytes(&mut coin, 2, amount.to_string().as_bytes());
    if chain.coin_decimals_field {
        field_varint(&mut coin, 3, u64::from(chain.decimals));
    }
    let mut msg = Vec::new();
    field_bytes(&mut msg, 1, &coin);
    field_bytes(&mut msg, 2, memo.as_bytes());
    field_bytes(&mut msg, 3, signer);
    msg
}

fn body_bytes(chain: &NativeChain, amount: u128, memo: &str, signer: &[u8; 20]) -> Vec<u8> {
    let mut body = Vec::new();
    field_bytes(&mut body, 1, &any("/types.MsgDeposit", &msg_deposit(chain, amount, memo, signer)));
    if chain.body_memo {
        field_bytes(&mut body, 2, memo.as_bytes());
    }
    body
}

fn auth_info_bytes(chain: &NativeChain, pubkey: &[u8; 33], sequence: u64) -> Vec<u8> {
    let mut key = Vec::new();
    field_bytes(&mut key, 1, pubkey);
    let mut single = Vec::new();
    field_varint(&mut single, 1, 1); // SIGN_MODE_DIRECT
    let mut mode = Vec::new();
    field_bytes(&mut mode, 1, &single);
    let mut signer = Vec::new();
    field_bytes(&mut signer, 1, &any("/cosmos.crypto.secp256k1.PubKey", &key));
    field_bytes(&mut signer, 2, &mode);
    field_varint(&mut signer, 3, sequence);
    let mut fee = Vec::new();
    if let Some(amount) = chain.declared_fee {
        let mut coin = Vec::new();
        field_bytes(&mut coin, 1, chain.denom.as_bytes());
        field_bytes(&mut coin, 2, amount.to_string().as_bytes());
        field_bytes(&mut fee, 1, &coin);
    }
    field_varint(&mut fee, 2, chain.gas_limit);
    let mut auth = Vec::new();
    field_bytes(&mut auth, 1, &signer);
    field_bytes(&mut auth, 2, &fee);
    auth
}

fn sign_doc(body: &[u8], auth: &[u8], chain_id: &str, account_number: u64) -> Vec<u8> {
    let mut doc = Vec::new();
    field_bytes(&mut doc, 1, body);
    field_bytes(&mut doc, 2, auth);
    field_bytes(&mut doc, 3, chain_id.as_bytes());
    field_varint(&mut doc, 4, account_number);
    doc
}

/// Frais réseau d'un dépôt, en plus du montant déposé (THORChain : ceux
/// déclarés ; Maya : prélevés par le protocole, lus dans ses constantes).
pub fn network_fee(chain: &NativeChain) -> Result<u128> {
    match chain.declared_fee {
        Some(fee) => Ok(u128::from(fee)),
        None => Ok(u128::from(constant(chain, "NativeTransactionFee")?)),
    }
}

/// Dépôt signé (octets `TxRaw`) de `amount` (plus petite unité) avec `memo`,
/// au nom de la clé `key`, pour le compte (`account_number`, `sequence`).
pub fn signed_deposit(chain: &NativeChain, key: &SigningKey, amount: u128, memo: &str, account_number: u64, sequence: u64) -> Result<Vec<u8>> {
    ensure!(amount > 0, "dépôt nul");
    let pubkey: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().context("clé publique invalide")?;
    let signer = hash160(&pubkey);
    let body = body_bytes(chain, amount, memo, &signer);
    let auth = auth_info_bytes(chain, &pubkey, sequence);
    let signature: Signature = key.sign(&sign_doc(&body, &auth, chain.chain_id, account_number));
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut tx = Vec::new();
    field_bytes(&mut tx, 1, &body);
    field_bytes(&mut tx, 2, &auth);
    field_bytes(&mut tx, 3, &signature.to_bytes());
    Ok(tx)
}

fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::{Digest as _, Ripemd160};
    use sha2::Sha256;
    Ripemd160::digest(Sha256::digest(data)).into()
}

// --- Réseau ---------------------------------------------------------------------

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

fn get_json(chain: &NativeChain, path: &str) -> Result<Value> {
    shared_client()
        .get(format!("{}{path}", chain.node_base))
        .send()
        .with_context(|| format!("nœud {} injoignable", chain.name))?
        .json()
        .with_context(|| format!("réponse du nœud {} illisible", chain.name))
}

/// Constante du protocole (`/{module}/constants`, valeur entière).
pub fn constant(chain: &NativeChain, name: &str) -> Result<u64> {
    let module = if chain.hrp == "maya" { "mayachain" } else { "thorchain" };
    let constants = get_json(chain, &format!("/{module}/constants"))?;
    constants["int_64_values"][name].as_i64().and_then(|v| u64::try_from(v).ok()).ok_or_else(|| anyhow!("constante {name} absente chez {}", chain.name))
}

/// Solde de la monnaie du réseau (plus petite unité).
pub fn balance(chain: &NativeChain, address: &str) -> Result<u128> {
    let body = get_json(chain, &format!("/cosmos/bank/v1beta1/balances/{address}"))?;
    let balances = body["balances"].as_array().ok_or_else(|| anyhow!("solde {} illisible", chain.name))?;
    Ok(balances
        .iter()
        .find(|b| b["denom"] == chain.denom)
        .and_then(|b| b["amount"].as_str())
        .and_then(|a| a.parse().ok())
        .unwrap_or(0))
}

/// Numéro de compte et séquence ; `None` pour une adresse jamais approvisionnée.
pub fn account(chain: &NativeChain, address: &str) -> Result<Option<(u64, u64)>> {
    let body = get_json(chain, &format!("/cosmos/auth/v1beta1/accounts/{address}"))?;
    if body.get("account").is_none() {
        return Ok(None);
    }
    let number = |field: &str| body["account"][field].as_str().and_then(|s| s.parse::<u64>().ok());
    match (number("account_number"), number("sequence")) {
        (Some(n), Some(s)) => Ok(Some((n, s))),
        _ => bail!("compte {} illisible", chain.name),
    }
}

/// Diffuse une transaction signée ; renvoie son identifiant. Refus du nœud
/// (signature, solde, memo…) : erreur avec son message.
pub fn broadcast(chain: &NativeChain, tx: &[u8]) -> Result<String> {
    let request = serde_json::json!({
        "tx_bytes": base64::engine::general_purpose::STANDARD.encode(tx),
        "mode": "BROADCAST_MODE_SYNC",
    });
    let body: Value = shared_client()
        .post(format!("{}/cosmos/tx/v1beta1/txs", chain.node_base))
        .json(&request)
        .send()
        .with_context(|| format!("nœud {} injoignable", chain.name))?
        .json()
        .with_context(|| format!("réponse du nœud {} illisible", chain.name))?;
    let response = &body["tx_response"];
    let code = response["code"].as_u64().ok_or_else(|| anyhow!("réponse de diffusion {} inattendue : {body}", chain.name))?;
    ensure!(code == 0, "transaction refusée par {} : {}", chain.name, response["raw_log"].as_str().unwrap_or("raison inconnue"));
    response["txhash"].as_str().map(str::to_string).ok_or_else(|| anyhow!("réponse de diffusion {} sans identifiant", chain.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Verifier;
    use k256::ecdsa::VerifyingKey;

    /// Champs de premier niveau d'un message protobuf (numéro → octets).
    fn top_fields(buf: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let mut o = 0;
        let read = |o: &mut usize| {
            let (mut v, mut s) = (0u64, 0);
            loop {
                let b = buf[*o];
                *o += 1;
                v |= u64::from(b & 0x7f) << s;
                if b & 0x80 == 0 {
                    return v;
                }
                s += 7;
            }
        };
        while o < buf.len() {
            let key = read(&mut o);
            assert_eq!(key & 7, 2, "champs de longueur variable attendus");
            let len = read(&mut o) as usize;
            out.push((key >> 3, buf[o..o + len].to_vec()));
            o += len;
        }
        out
    }

    fn signer_of(address: &str) -> [u8; 20] {
        use bech32::FromBase32;
        let (_, data, _) = bech32::decode(address).unwrap();
        Vec::<u8>::from_base32(&data).unwrap().try_into().unwrap()
    }

    /// Reconstruit une vraie inscription (corps et informations de signature
    /// identiques à l'octet) et vérifie sa signature d'origine sur le document
    /// de signature calculé ici.
    #[allow(clippy::too_many_arguments)]
    fn check_real(chain: &NativeChain, raw_hex: &str, amount: u128, memo: &str, signer: &str, pubkey_hex: &str, sequence: u64, account_number: u64) {
        let raw = hex::decode(raw_hex.trim()).unwrap();
        let parts = top_fields(&raw);
        let (body, auth, sig) = (&parts[0].1, &parts[1].1, &parts[2].1);
        assert_eq!(&body_bytes(chain, amount, memo, &signer_of(signer)), body, "corps {}", chain.name);
        let pubkey: [u8; 33] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();
        assert_eq!(&auth_info_bytes(chain, &pubkey, sequence), auth, "informations de signature {}", chain.name);
        assert_eq!(hash160(&pubkey), signer_of(signer), "signataire = hash160 de la clé");
        let key = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let signature = Signature::from_slice(sig).unwrap();
        key.verify(&sign_doc(body, auth, chain.chain_id, account_number), &signature).expect("signature d'origine valide");
        assert!(key.verify(&sign_doc(body, auth, chain.chain_id, account_number + 1), &signature).is_err(), "autre compte : invalide");
    }

    /// Inscription réelle du THORName « zafu » (bloc 28 067 419, compte
    /// 156 733, séquence 3) et du MAYAName « frog » (bloc 18 652 051, compte
    /// 9 713, séquence 37).
    #[test]
    fn real_registrations_are_reproduced_byte_for_byte() {
        let thor = "thor1qnulc66wrfycz6takz9xqdvdmpk9kgd5rzy80k";
        check_real(
            &THORCHAIN,
            include_str!("../testdata/thorname_register_tx.hex"),
            1_100_000_000,
            &format!("name:zafu:THOR:{thor}"),
            thor,
            "031555ef1c86fdc819f98b8474d830bb1161d898ebe37436c8ccb2c9a94512232e",
            3,
            156_733,
        );
        let maya = "maya1krsph5z3pyyxwlw7yfq0jtwa5l0ud0hnsydy3v";
        check_real(
            &MAYA,
            include_str!("../testdata/mayaname_register_tx.hex"),
            205_120_000_000,
            &format!("~:frog:MAYA:{maya}"),
            maya,
            "031dab465783b4b90d32a4df02db1ee5693a2136b6ba80350353701410489743fe",
            37,
            9_713,
        );
    }

    /// Transaction signée ici : relue, même corps, signature valide et S bas.
    #[test]
    fn signed_deposits_verify() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        for chain in [&THORCHAIN, &MAYA] {
            let tx = signed_deposit(chain, &key, 1_105_120_000, "~:ow:THOR:thor1x", 12, 4).unwrap();
            let parts = top_fields(&tx);
            let signature = Signature::from_slice(&parts[2].1).unwrap();
            assert!(signature.normalize_s().is_none(), "S bas");
            key.verifying_key().verify(&sign_doc(&parts[0].1, &parts[1].1, chain.chain_id, 12), &signature).unwrap();
        }
        assert!(signed_deposit(&THORCHAIN, &key, 0, "~:ow", 1, 0).is_err());
    }
}
