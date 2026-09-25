//! Signatures EVM demandées par des dApps (via WalletConnect) : message
//! personnel (EIP-191, `personal_sign`), données structurées (EIP-712,
//! `eth_signTypedData_v4`), et décodage des appels de contrat pour affichage.
//! Fonctions pures, sans réseau ni secret stocké : la clé est fournie par
//! l'appelant (`api`), après mot de passe et boîte de confirmation native.
//!
//! Vérifié octet par octet contre ethers.js v6 (vecteurs dans les tests), y
//! compris l'exemple officiel de la spécification EIP-712.

use anyhow::{anyhow, bail, Context, Result};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeSet, HashMap};

pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Empreinte EIP-191 d'un message personnel :
/// keccak256("\x19Ethereum Signed Message:\n" + longueur décimale + message).
pub fn personal_message_hash(message: &[u8]) -> [u8; 32] {
    let mut data = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    data.extend_from_slice(message);
    keccak(&data)
}

/// Signature recouvrable au format attendu par les dApps : r (32) ‖ s (32) ‖
/// v (27 + identifiant de recouvrement), s normalisé "bas" (EIP-2).
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; 65]> {
    let (signature, recid): (Signature, RecoveryId) =
        key.sign_prehash(digest).map_err(|e| anyhow!("échec de signature ECDSA : {e}"))?;
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&signature.r().to_bytes());
    out[32..64].copy_from_slice(&signature.s().to_bytes());
    out[64] = 27 + recid.to_byte();
    Ok(out)
}

// --- Entiers 256 bits (juste ce qu'exige l'encodage EIP-712) -----------------

/// Entier 256 bits non signé, gros-boutiste. Construit uniquement par
/// `parse_uint256`, jamais par une arithmétique qui pourrait déborder en silence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256(pub [u8; 32]);

impl U256 {
    fn bits(&self) -> u32 {
        match self.0.iter().position(|&b| b != 0) {
            None => 0,
            Some(i) => (32 - i as u32) * 8 - self.0[i].leading_zeros(),
        }
    }

    /// Représentation décimale (affichage).
    pub fn to_decimal(&self) -> String {
        let mut digits = Vec::new();
        let mut n = self.0;
        while n.iter().any(|&b| b != 0) {
            let mut rem = 0u32;
            for byte in n.iter_mut() {
                let cur = (rem << 8) | u32::from(*byte);
                *byte = (cur / 10) as u8;
                rem = cur % 10;
            }
            digits.push(char::from(b'0' + rem as u8));
        }
        if digits.is_empty() {
            "0".to_string()
        } else {
            digits.iter().rev().collect()
        }
    }

    /// `true` à partir de 2^128 : plus que l'offre de n'importe quel jeton réel,
    /// même à 18 décimales — valeur "illimitée" en pratique. Couvre 2^256-1
    /// (approve classique) comme 2^160-1 (maximum de Permit2, en uint160).
    pub fn is_practically_unlimited(&self) -> bool {
        self.bits() > 128
    }

    pub fn to_u128(&self) -> Option<u128> {
        (self.bits() <= 128).then(|| u128::from_be_bytes(self.0[16..].try_into().expect("16 octets")))
    }

    fn twos_complement(&self) -> Self {
        let mut out = self.0.map(|b| !b);
        for byte in out.iter_mut().rev() {
            let (v, carry) = byte.overflowing_add(1);
            *byte = v;
            if !carry {
                break;
            }
        }
        U256(out)
    }
}

/// Décimal ("123"), hexadécimal ("0x7b"), ou nombre JSON entier. Refuse un
/// nombre JSON non entier ou au-delà de 2^53 : serde_json l'a déjà converti en
/// flottant, la valeur exacte voulue par la dApp est donc perdue — signer une
/// approximation serait signer autre chose que ce qui a été demandé.
fn parse_magnitude(text: &str) -> Result<U256> {
    let mut out = [0u8; 32];
    let add_digit = |out: &mut [u8; 32], base: u32, digit: u32| -> Result<()> {
        let mut carry = digit;
        for byte in out.iter_mut().rev() {
            let cur = u32::from(*byte) * base + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        anyhow::ensure!(carry == 0, "nombre supérieur à 2^256");
        Ok(())
    };
    let (digits, base) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    anyhow::ensure!(!digits.is_empty(), "nombre vide");
    for c in digits.chars() {
        let d = c.to_digit(base).ok_or_else(|| anyhow!("nombre invalide : « {text} »"))?;
        add_digit(&mut out, base, d)?;
    }
    Ok(U256(out))
}

/// Entier (signé ou non) d'une valeur JSON : (négatif ?, valeur absolue).
fn parse_integer(value: &Value) -> Result<(bool, U256)> {
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                parse_magnitude(&u.to_string()).map(|m| (false, m))
            } else if let Some(i) = n.as_i64() {
                parse_magnitude(&i.unsigned_abs().to_string()).map(|m| (i < 0, m))
            } else {
                bail!("nombre non entier ou trop grand pour être représenté exactement (écrire les grands nombres entre guillemets)")
            }
        }
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix('-') {
                Some(rest) => parse_magnitude(rest).map(|m| (true, m)),
                None => parse_magnitude(s).map(|m| (false, m)),
            }
        }
        _ => bail!("entier attendu"),
    }
}

pub fn parse_uint256(value: &Value) -> Result<U256> {
    let (negative, magnitude) = parse_integer(value)?;
    anyhow::ensure!(!negative || magnitude.bits() == 0, "entier non signé négatif");
    Ok(magnitude)
}

fn hex_bytes(value: &Value) -> Result<Vec<u8>> {
    let s = value.as_str().ok_or_else(|| anyhow!("octets hexadécimaux attendus"))?;
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).ok_or_else(|| anyhow!("octets hexadécimaux « 0x… » attendus"))?;
    hex::decode(s).context("octets hexadécimaux invalides")
}

pub fn parse_address(value: &Value) -> Result<[u8; 20]> {
    let bytes = hex_bytes(value).context("adresse invalide")?;
    bytes.try_into().map_err(|_| anyhow!("une adresse EVM fait 20 octets"))
}

// --- EIP-712 -----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TypedField {
    pub name: String,
    pub kind: String,
}

/// Données structurées EIP-712 (`eth_signTypedData_v4`).
#[derive(Debug)]
pub struct TypedData {
    pub types: HashMap<String, Vec<TypedField>>,
    pub primary_type: String,
    pub domain: Value,
    pub message: Value,
}

/// Accepte l'objet JSON, ou une chaîne contenant ce JSON (les deux formes
/// circulent selon les dApps pour `eth_signTypedData_v4`).
pub fn parse_typed_data(value: &Value) -> Result<TypedData> {
    let owned;
    let obj = match value {
        Value::String(s) => {
            owned = serde_json::from_str::<Value>(s).context("données structurées : JSON invalide")?;
            &owned
        }
        other => other,
    };
    let types_json = obj.get("types").and_then(Value::as_object).ok_or_else(|| anyhow!("données structurées sans « types »"))?;
    let mut types = HashMap::new();
    for (name, fields) in types_json {
        let fields = fields.as_array().ok_or_else(|| anyhow!("type « {name} » mal formé"))?;
        let mut parsed = Vec::with_capacity(fields.len());
        for field in fields {
            let fname = field.get("name").and_then(Value::as_str).ok_or_else(|| anyhow!("champ sans nom dans « {name} »"))?;
            let kind = field.get("type").and_then(Value::as_str).ok_or_else(|| anyhow!("champ sans type dans « {name} »"))?;
            parsed.push(TypedField { name: fname.to_string(), kind: kind.to_string() });
        }
        types.insert(name.clone(), parsed);
    }
    let primary_type = obj
        .get("primaryType")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("données structurées sans « primaryType »"))?
        .to_string();
    let domain = obj.get("domain").cloned().ok_or_else(|| anyhow!("données structurées sans « domain »"))?;
    let message = obj.get("message").cloned().unwrap_or(Value::Null);
    let mut data = TypedData { types, primary_type, domain, message };
    // Type du domaine absent (forme ethers.js) : déduit des champs présents,
    // dans l'ordre canonique de la spécification — comme `hashDomain` d'ethers.
    if !data.types.contains_key("EIP712Domain") {
        let canonical = [("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address"), ("salt", "bytes32")];
        let fields = canonical
            .iter()
            .filter(|(name, _)| data.domain.get(name).is_some())
            .map(|(name, kind)| TypedField { name: name.to_string(), kind: kind.to_string() })
            .collect();
        data.types.insert("EIP712Domain".to_string(), fields);
    }
    anyhow::ensure!(
        data.primary_type == "EIP712Domain" || data.types.contains_key(&data.primary_type),
        "type principal « {} » non défini",
        data.primary_type
    );
    Ok(data)
}

/// Type de base d'un tableau (`T[]`/`T[N]` -> (T, Some(N) ou None)), `None` si
/// ce n'est pas un tableau.
fn array_parts(kind: &str) -> Option<(&str, Option<usize>)> {
    let inner = kind.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    let len = &inner[open + 1..];
    Some((&inner[..open], if len.is_empty() { None } else { len.parse().ok() }))
}

fn base_struct_name(kind: &str) -> &str {
    let mut k = kind;
    while let Some((base, _)) = array_parts(k) {
        k = base;
    }
    k
}

impl TypedData {
    fn fields(&self, name: &str) -> Result<&Vec<TypedField>> {
        self.types.get(name).ok_or_else(|| anyhow!("type « {name} » non défini"))
    }

    /// Types structurés dont dépend `name` (lui compris) ; les cycles sont gérés.
    fn dependencies(&self, name: &str, found: &mut BTreeSet<String>) {
        if found.contains(name) || !self.types.contains_key(name) {
            return;
        }
        found.insert(name.to_string());
        for field in &self.types[name] {
            self.dependencies(base_struct_name(&field.kind), found);
        }
    }

    /// `Nom(type1 champ1,…)` du type principal, suivi de ses dépendances triées
    /// par ordre alphabétique (règle EIP-712).
    fn encode_type(&self, name: &str) -> Result<String> {
        let mut deps = BTreeSet::new();
        self.dependencies(name, &mut deps);
        deps.remove(name);
        let mut out = String::new();
        for t in std::iter::once(name.to_string()).chain(deps) {
            let fields = self.fields(&t)?;
            let list: Vec<String> = fields.iter().map(|f| format!("{} {}", f.kind, f.name)).collect();
            out.push_str(&format!("{t}({})", list.join(",")));
        }
        Ok(out)
    }

    pub fn hash_struct(&self, name: &str, data: &Value) -> Result<[u8; 32]> {
        let mut encoded = keccak(self.encode_type(name)?.as_bytes()).to_vec();
        for field in self.fields(name)? {
            let value = data
                .get(&field.name)
                .ok_or_else(|| anyhow!("champ « {} » absent de « {name} »", field.name))?;
            encoded.extend_from_slice(&self.encode_value(&field.kind, value)?);
        }
        Ok(keccak(&encoded))
    }

    fn encode_value(&self, kind: &str, value: &Value) -> Result<[u8; 32]> {
        if let Some((base, fixed_len)) = array_parts(kind) {
            let items = value.as_array().ok_or_else(|| anyhow!("tableau attendu pour « {kind} »"))?;
            if let Some(n) = fixed_len {
                anyhow::ensure!(items.len() == n, "tableau « {kind} » : {} éléments au lieu de {n}", items.len());
            }
            let mut concat = Vec::with_capacity(items.len() * 32);
            for item in items {
                concat.extend_from_slice(&self.encode_value(base, item)?);
            }
            return Ok(keccak(&concat));
        }
        if self.types.contains_key(kind) {
            return self.hash_struct(kind, value);
        }
        let mut word = [0u8; 32];
        match kind {
            "string" => return Ok(keccak(value.as_str().ok_or_else(|| anyhow!("texte attendu"))?.as_bytes())),
            "bytes" => return Ok(keccak(&hex_bytes(value)?)),
            "bool" => {
                let b = match value {
                    Value::Bool(b) => *b,
                    Value::String(s) if s == "true" || s == "false" => s == "true",
                    _ => bail!("booléen attendu"),
                };
                word[31] = u8::from(b);
            }
            "address" => word[12..].copy_from_slice(&parse_address(value)?),
            _ => {
                if let Some(n) = kind.strip_prefix("bytes") {
                    let n: usize = n.parse().map_err(|_| anyhow!("type inconnu « {kind} »"))?;
                    anyhow::ensure!((1..=32).contains(&n), "type inconnu « {kind} »");
                    let bytes = hex_bytes(value)?;
                    anyhow::ensure!(bytes.len() == n, "« {kind} » : {} octets au lieu de {n}", bytes.len());
                    word[..n].copy_from_slice(&bytes);
                } else if let Some((signed, bits)) = kind
                    .strip_prefix("uint")
                    .map(|b| (false, b))
                    .or_else(|| kind.strip_prefix("int").map(|b| (true, b)))
                {
                    let bits: u32 = bits.parse().map_err(|_| anyhow!("type inconnu « {kind} »"))?;
                    anyhow::ensure!(bits % 8 == 0 && (8..=256).contains(&bits), "type inconnu « {kind} »");
                    let (negative, magnitude) = parse_integer(value)?;
                    if signed {
                        // Plage [-2^(bits-1), 2^(bits-1) - 1], complément à deux sur 256 bits.
                        let limit = bits - 1;
                        let fits = magnitude.bits() <= limit || (negative && magnitude == pow2(limit));
                        anyhow::ensure!(fits, "« {kind} » : valeur hors limites");
                        word = if negative && magnitude.bits() > 0 { magnitude.twos_complement().0 } else { magnitude.0 };
                    } else {
                        anyhow::ensure!(!negative || magnitude.bits() == 0, "« {kind} » : valeur négative");
                        anyhow::ensure!(magnitude.bits() <= bits, "« {kind} » : valeur hors limites");
                        word = magnitude.0;
                    }
                } else {
                    bail!("type inconnu « {kind} »");
                }
            }
        }
        Ok(word)
    }

    pub fn domain_separator(&self) -> Result<[u8; 32]> {
        self.hash_struct("EIP712Domain", &self.domain)
    }

    /// Empreinte finale à signer : keccak256(0x19 0x01 ‖ domaine ‖ message).
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut data = vec![0x19, 0x01];
        data.extend_from_slice(&self.domain_separator()?);
        if self.primary_type != "EIP712Domain" {
            data.extend_from_slice(&self.hash_struct(&self.primary_type, &self.message)?);
        }
        Ok(keccak(&data))
    }

    /// `chainId` du domaine, s'il est présent et lisible.
    pub fn domain_chain_id(&self) -> Option<u64> {
        let v = parse_uint256(self.domain.get("chainId")?).ok()?;
        (v.bits() <= 64).then(|| u64::from_be_bytes(v.0[24..].try_into().expect("8 octets")))
    }
}

fn pow2(n: u32) -> U256 {
    let mut out = [0u8; 32];
    if n < 256 {
        out[31 - (n / 8) as usize] = 1 << (n % 8);
    }
    U256(out)
}

// --- Décodage des appels de contrat (affichage) ------------------------------

/// Ce qu'un appel de contrat fait, pour les formes reconnues — tout le reste
/// est `Unknown` et doit être présenté comme une signature À L'AVEUGLE.
#[derive(Debug, PartialEq, Eq)]
pub enum CallKind {
    /// Aucune donnée : simple envoi d'ETH.
    PlainTransfer,
    TokenTransfer { to: [u8; 20], amount: U256 },
    TokenTransferFrom { from: [u8; 20], to: [u8; 20], amount: U256 },
    /// Autorise `spender` à dépenser `amount` jetons de l'utilisateur, plus tard, sans lui.
    TokenApprove { spender: [u8; 20], amount: U256 },
    IncreaseAllowance { spender: [u8; 20], amount: U256 },
    /// Autorise `operator` à transférer TOUS les NFT de la collection.
    SetApprovalForAll { operator: [u8; 20], approved: bool },
    Unknown { selector: [u8; 4] },
}

fn word(args: &[u8], i: usize) -> Option<&[u8]> {
    args.get(i * 32..(i + 1) * 32)
}

fn word_address(args: &[u8], i: usize) -> Option<[u8; 20]> {
    let w = word(args, i)?;
    // Une adresse ABI a ses 12 premiers octets à zéro : sinon l'appel est mal formé.
    w[..12].iter().all(|&b| b == 0).then(|| w[12..].try_into().expect("20 octets"))
}

fn word_uint(args: &[u8], i: usize) -> Option<U256> {
    word(args, i).map(|w| U256(w.try_into().expect("32 octets")))
}

fn word_bool(args: &[u8], i: usize) -> Option<bool> {
    let w = word(args, i)?;
    (w[..31].iter().all(|&b| b == 0) && w[31] <= 1).then_some(w[31] == 1)
}

pub fn decode_call(data: &[u8]) -> CallKind {
    if data.is_empty() {
        return CallKind::PlainTransfer;
    }
    let Some(selector) = data.get(..4).map(|s| <[u8; 4]>::try_from(s).expect("4 octets")) else {
        return CallKind::Unknown { selector: [0; 4] };
    };
    let args = &data[4..];
    let decoded = match selector {
        [0xa9, 0x05, 0x9c, 0xbb] if args.len() == 64 => {
            word_address(args, 0).zip(word_uint(args, 1)).map(|(to, amount)| CallKind::TokenTransfer { to, amount })
        }
        [0x23, 0xb8, 0x72, 0xdd] if args.len() == 96 => word_address(args, 0)
            .zip(word_address(args, 1))
            .zip(word_uint(args, 2))
            .map(|((from, to), amount)| CallKind::TokenTransferFrom { from, to, amount }),
        [0x09, 0x5e, 0xa7, 0xb3] if args.len() == 64 => {
            word_address(args, 0).zip(word_uint(args, 1)).map(|(spender, amount)| CallKind::TokenApprove { spender, amount })
        }
        [0x39, 0x50, 0x93, 0x51] if args.len() == 64 => {
            word_address(args, 0).zip(word_uint(args, 1)).map(|(spender, amount)| CallKind::IncreaseAllowance { spender, amount })
        }
        [0xa2, 0x2c, 0xb4, 0x65] if args.len() == 64 => word_address(args, 0)
            .zip(word_bool(args, 1))
            .map(|(operator, approved)| CallKind::SetApprovalForAll { operator, approved }),
        _ => None,
    };
    decoded.unwrap_or(CallKind::Unknown { selector })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn key() -> SigningKey {
        SigningKey::from_slice(&hex::decode(KEY).unwrap()).unwrap()
    }

    fn h(s: &str) -> String {
        format!("0x{s}")
    }

    /// Vecteurs ethers.js v6 (`hashMessage`, `Wallet.signMessage`).
    #[test]
    fn personal_sign_matches_ethers() {
        let hash = personal_message_hash(b"Hello World");
        assert_eq!(h(&hex::encode(hash)), "0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2");
        assert_eq!(
            h(&hex::encode(sign_digest(&key(), &hash).unwrap())),
            "0x6f267aa61dda3067280942299172e2b9f6b4252b492e7c0343ecce6e7edfe0b24110a805ba6777e4303501ea9dfae133855f4ee2e34fd0444bb23d11f296eef31c"
        );
        let hash = personal_message_hash(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(h(&hex::encode(hash)), "0xd1c7f1a06a4f9a535077e50ad23244ce2c6ae443fcd412965226f3df5d28eaaa");
        assert_eq!(
            h(&hex::encode(sign_digest(&key(), &hash).unwrap())),
            "0x27c9251b613f25a4d52f5375c0be39ea8b8f5bb46a29034620f613d71520ac24034d84dcd3e6251af82cff1bda9c38141a238abaa1830bd8ca064474b60c641f1c"
        );
    }

    fn mail() -> Value {
        json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
                "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"}, {"name": "contents", "type": "string"}]
            },
            "primaryType": "Mail",
            "domain": {"name": "Ether Mail", "version": "1", "chainId": 1, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }
        })
    }

    /// Exemple officiel de la spécification EIP-712 (valeurs publiées dans la
    /// spécification elle-même, et reproduites par ethers.js).
    #[test]
    fn eip712_matches_the_specification_example() {
        let data = parse_typed_data(&mail()).unwrap();
        assert_eq!(h(&hex::encode(data.domain_separator().unwrap())), "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
        assert_eq!(
            h(&hex::encode(data.hash_struct("Mail", &data.message).unwrap())),
            "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );
        let digest = data.digest().unwrap();
        assert_eq!(h(&hex::encode(digest)), "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
        assert_eq!(
            h(&hex::encode(sign_digest(&key(), &digest).unwrap())),
            "0x19e4c5dcf77c10f4b30df3d4cb5822a99a69ec18e6f5d7b9a889a5a4815740732656ebdcc5a9c8eee63e684a5ed282d6b59ffe2914076b025a77df76559403111c"
        );
        assert_eq!(data.domain_chain_id(), Some(1));
        // Même contenu transmis sous forme de CHAÎNE JSON (autre forme courante).
        let as_string = Value::String(mail().to_string());
        assert_eq!(parse_typed_data(&as_string).unwrap().digest().unwrap(), digest);
    }

    /// Cas v4 complexe (ethers.js) : tableaux de structures, tableau d'adresses
    /// vide, bytes, bytes32, int256 négatif, bool, uint8, tableau fixe, entier
    /// hexadécimal et entier > 2^128, texte non ASCII, sel de domaine.
    #[test]
    fn eip712_v4_complex_structures_match_ethers() {
        let typed = json!({
            "domain": {"name": "Complexe", "version": "2", "chainId": 11155111, "verifyingContract": "0x1111111111111111111111111111111111111111", "salt": format!("0x{}", "ab".repeat(32))},
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"}, {"name": "version", "type": "string"}, {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}, {"name": "salt", "type": "bytes32"}
                ],
                "Person": [{"name": "name", "type": "string"}, {"name": "wallets", "type": "address[]"}],
                "Group": [
                    {"name": "members", "type": "Person[]"}, {"name": "admin", "type": "Person"}, {"name": "payload", "type": "bytes"},
                    {"name": "id", "type": "bytes32"}, {"name": "delta", "type": "int256"}, {"name": "active", "type": "bool"},
                    {"name": "level", "type": "uint8"}, {"name": "pair", "type": "uint256[2]"}
                ]
            },
            "primaryType": "Group",
            "message": {
                "members": [
                    {"name": "Alice", "wallets": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"]},
                    {"name": "Élodie ✓", "wallets": []}
                ],
                "admin": {"name": "Root", "wallets": ["0x4444444444444444444444444444444444444444"]},
                "payload": "0xdeadbeefcafe",
                "id": format!("0x{}", "cd".repeat(32)),
                "delta": "-123456789",
                "active": true,
                "level": 7,
                "pair": ["0x10", "340282366920938463463374607431768211456"]
            }
        });
        let data = parse_typed_data(&typed).unwrap();
        let digest = data.digest().unwrap();
        assert_eq!(h(&hex::encode(digest)), "0xb645bfd445b07b0a707e3a8d6f82dcca796926e59cbb56550744d0835a54795c");
        assert_eq!(
            h(&hex::encode(sign_digest(&key(), &digest).unwrap())),
            "0xb8fc401dab95360b12e1a06bcbdb192a577d54380442e69a08c4c03afaef8f2e1a3dee6a9a114dce0f2dad76d68723fd443ba0429b151d469ebab972d1eacc581c"
        );
        assert_eq!(data.domain_chain_id(), Some(11_155_111));
    }

    /// Permit EIP-2612 illimité (forme ethers.js : `EIP712Domain` absent des
    /// types, déduit des champs du domaine).
    #[test]
    fn eip712_permit_with_a_max_value_string_matches_ethers() {
        let typed = json!({
            "domain": {"name": "USD Coin", "version": "2", "chainId": 1, "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
            "types": {"Permit": [
                {"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}
            ]},
            "primaryType": "Permit",
            "message": {
                "owner": "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", "spender": "0x5555555555555555555555555555555555555555",
                "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "nonce": 0, "deadline": "1893456000"
            }
        });
        let data = parse_typed_data(&typed).unwrap();
        assert_eq!(h(&hex::encode(data.digest().unwrap())), "0xfffcc838333500a1d6462f879368eff7deeecc267930a1ff855464b076981216");
        let value = parse_uint256(&data.message["value"]).unwrap();
        assert!(value.is_practically_unlimited());
        assert_eq!(value.to_decimal(), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
    }

    #[test]
    fn eip712_refuses_ambiguous_or_malformed_values() {
        let mut typed = mail();
        // Nombre JSON au-delà de 2^53 : déjà arrondi par le parseur JSON.
        typed["domain"]["chainId"] = serde_json::from_str("1e30").unwrap();
        assert!(parse_typed_data(&typed).unwrap().digest().is_err(), "nombre flottant ambigu");
        let mut typed = mail();
        typed["message"]["from"]["wallet"] = json!("0x1234");
        assert!(parse_typed_data(&typed).unwrap().digest().is_err(), "adresse tronquée");
        let mut typed = mail();
        typed["message"].as_object_mut().unwrap().remove("contents");
        assert!(parse_typed_data(&typed).unwrap().digest().is_err(), "champ manquant");
        let mut typed = mail();
        typed["types"]["Mail"][2]["type"] = json!("uint7");
        assert!(parse_typed_data(&typed).unwrap().digest().is_err(), "type inconnu");
        // Types cycliques sans données finies : erreur propre, pas de débordement de pile.
        let cyclic = json!({
            "types": {"A": [{"name": "b", "type": "B"}], "B": [{"name": "a", "type": "A"}]},
            "primaryType": "A", "domain": {"name": "x"}, "message": {"b": {"a": {"b": {}}}}
        });
        assert!(parse_typed_data(&cyclic).unwrap().digest().is_err());
    }

    #[test]
    fn int_and_uint_ranges_are_enforced() {
        let data = parse_typed_data(&json!({"types": {}, "primaryType": "EIP712Domain", "domain": {}})).unwrap();
        assert!(data.encode_value("uint8", &json!(255)).is_ok());
        assert!(data.encode_value("uint8", &json!(256)).is_err());
        assert!(data.encode_value("uint8", &json!("-1")).is_err());
        assert!(data.encode_value("int8", &json!(127)).is_ok());
        assert!(data.encode_value("int8", &json!(128)).is_err());
        assert!(data.encode_value("int8", &json!(-128)).is_ok());
        assert!(data.encode_value("int8", &json!(-129)).is_err());
        assert_eq!(data.encode_value("int256", &json!(-1)).unwrap(), [0xff; 32]);
        assert!(data.encode_value("bytes4", &json!("0x0102")).is_err(), "bytesN : longueur exacte");
        assert!(data.encode_value("bool", &json!(1)).is_err());
    }

    fn call(selector: &str, words: &[String]) -> Vec<u8> {
        hex::decode(format!("{selector}{}", words.concat())).unwrap()
    }

    fn addr_word(a: &str) -> String {
        format!("{:0>64}", a)
    }

    #[test]
    fn known_contract_calls_are_decoded_and_anything_else_is_blind() {
        assert_eq!(decode_call(&[]), CallKind::PlainTransfer);
        let spender = "5555555555555555555555555555555555555555";
        let max = "f".repeat(64);
        match decode_call(&call("095ea7b3", &[addr_word(spender), max.clone()])) {
            CallKind::TokenApprove { spender: s, amount } => {
                assert_eq!(hex::encode(s), spender);
                assert!(amount.is_practically_unlimited());
            }
            other => panic!("{other:?}"),
        }
        match decode_call(&call("a9059cbb", &[addr_word(spender), format!("{:0>64}", "3e8")])) {
            CallKind::TokenTransfer { amount, .. } => assert_eq!(amount.to_decimal(), "1000"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            decode_call(&call("a22cb465", &[addr_word(spender), format!("{:0>64}", "1")])),
            CallKind::SetApprovalForAll { operator: hex::decode(spender).unwrap().try_into().unwrap(), approved: true }
        );
        // Adresse ABI aux octets hauts non nuls, argument manquant ou en trop,
        // sélecteur inconnu : jamais présentés comme un appel reconnu.
        assert!(matches!(decode_call(&call("095ea7b3", &[format!("ff{}", &addr_word(spender)[2..]), max.clone()])), CallKind::Unknown { .. }));
        assert!(matches!(decode_call(&call("095ea7b3", &[addr_word(spender)])), CallKind::Unknown { .. }));
        assert!(matches!(decode_call(&call("095ea7b3", &[addr_word(spender), max.clone(), max])), CallKind::Unknown { .. }));
        assert!(matches!(decode_call(&call("12345678", &[])), CallKind::Unknown { selector: [0x12, 0x34, 0x56, 0x78] }));
        assert!(matches!(decode_call(&[0x09, 0x5e]), CallKind::Unknown { .. }));
    }

    #[test]
    fn u256_decimal_and_bit_length() {
        assert_eq!(parse_uint256(&json!("0")).unwrap().to_decimal(), "0");
        assert_eq!(parse_uint256(&json!("0x10")).unwrap().to_decimal(), "16");
        assert_eq!(parse_uint256(&json!(u64::MAX)).unwrap().to_decimal(), u64::MAX.to_string());
        assert!(parse_uint256(&json!(format!("0x1{}", "0".repeat(64)))).is_err(), "> 2^256");
        assert!(!parse_uint256(&json!("1000000")).unwrap().is_practically_unlimited());
    }
}
