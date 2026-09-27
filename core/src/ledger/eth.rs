//! Application Ethereum du Ledger (`app-ethereum`, spécification `doc/apdu.md`) :
//! adresse, signature de transaction (legacy EIP-155), de message personnel
//! (EIP-191) et de données structurées EIP-712 (mode "empreintes", V0).
//!
//! Chaque signature renvoyée par l'appareil est vérifiée ICI avant usage : elle
//! doit se recouvrer en l'adresse attendue. Un appareil (ou un émulateur, ou un
//! câble) qui renverrait autre chose est refusé avant toute diffusion.

use super::{encode_path, send, Transport};
use crate::eth_tx::EthTx;
use crate::evm_sign::keccak;
use anyhow::{anyhow, Context, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

const CLA: u8 = 0xe0;
const INS_GET_ADDRESS: u8 = 0x02;
const INS_SIGN_TX: u8 = 0x04;
const INS_SIGN_PERSONAL: u8 = 0x08;
const INS_SIGN_EIP712: u8 = 0x0c;
const P1_FIRST: u8 = 0x00;
const P1_MORE: u8 = 0x80;
const MAX_CHUNK: usize = 255;

/// Adresse EVM (format EIP-55) d'une clé publique non compressée (65 octets).
fn address_of(public: &[u8]) -> Result<[u8; 20]> {
    anyhow::ensure!(public.len() == 65 && public[0] == 0x04, "clé publique Ledger mal formée");
    let hash = keccak(&public[1..]);
    Ok(hash[12..].try_into().expect("20 octets"))
}

/// Adresse du compte `path`. `confirm` : l'appareil l'AFFICHE et demande de la
/// valider — le seul moyen pour l'utilisateur de vérifier qu'une adresse de
/// réception n'a pas été substituée entre l'appareil et l'écran de l'ordinateur.
pub fn get_address(transport: &mut dyn Transport, path: &[u32], confirm: bool) -> Result<String> {
    let response = send(transport, CLA, INS_GET_ADDRESS, u8::from(confirm), 0x00, &encode_path(path)?)?;
    let key_len = *response.first().ok_or_else(|| anyhow!("réponse Ledger vide"))? as usize;
    let public = response.get(1..1 + key_len).ok_or_else(|| anyhow!("réponse Ledger tronquée"))?;
    let addr_len = *response.get(1 + key_len).ok_or_else(|| anyhow!("réponse Ledger tronquée"))? as usize;
    let ascii = response.get(2 + key_len..2 + key_len + addr_len).ok_or_else(|| anyhow!("réponse Ledger tronquée"))?;
    let claimed = std::str::from_utf8(ascii).context("adresse Ledger illisible")?;
    // L'adresse annoncée doit être celle de la clé publique renvoyée.
    let derived = address_of(public)?;
    anyhow::ensure!(
        claimed.trim_start_matches("0x").eq_ignore_ascii_case(&hex::encode(derived)),
        "le Ledger a renvoyé une adresse qui ne correspond pas à sa clé publique"
    );
    Ok(crate::derivation::format_address(&derived))
}

/// Découpage en blocs de 255 octets maximum (`hw-app-eth` `safeChunkTransaction`) :
/// pour une transaction legacy, le dernier bloc ne doit jamais contenir QUE tout
/// ou partie du tuple final (`chain_id, 0, 0`) — l'appareil pourrait sinon
/// considérer la transaction comme complète trop tôt.
fn safe_chunks(payload: &[u8], vrs_len: usize) -> Vec<&[u8]> {
    if payload.len() <= MAX_CHUNK {
        return vec![payload];
    }
    let fits = |size: usize| {
        let last = payload.len() % size;
        last == 0 || last > vrs_len
    };
    let size = (1..=MAX_CHUNK).rev().find(|&s| fits(s)).unwrap_or(MAX_CHUNK);
    payload.chunks(size).collect()
}

/// Longueur du tuple final (`chain_id, 0, 0`) sans l'en-tête de liste.
fn vrs_tail_len(chain_id: u64) -> usize {
    let bytes = chain_id.to_be_bytes();
    let trimmed = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(7)..];
    let chain_rlp = if trimmed.len() == 1 && trimmed[0] < 0x80 { 1 } else { 1 + trimmed.len() };
    chain_rlp + 2
}

/// Parité à partir du `v` sur UN octet renvoyé par l'appareil (`hw-app-eth`
/// `getParity`) : l'appareil applique EIP-155 sur un chain_id tronqué à 4
/// octets, avec débordement de l'octet.
fn parity_from_device_v(v: u8, chain_id: u64) -> Result<u8> {
    let bytes = chain_id.to_be_bytes();
    let significant = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(7)..];
    let truncated = significant.iter().take(4).fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let base = truncated * 2 + 35;
    if (base % 256) as u8 == v {
        Ok(0)
    } else if ((base + 1) % 256) as u8 == v {
        Ok(1)
    } else {
        Err(anyhow!("valeur v inattendue renvoyée par le Ledger"))
    }
}

/// r, s (s normalisé "bas", EIP-2) et parité effective.
pub(crate) fn normalized(r: &[u8], s: &[u8], parity: u8) -> Result<(Signature, u8)> {
    let signature = Signature::from_scalars(<[u8; 32]>::try_from(r)?, <[u8; 32]>::try_from(s)?)
        .map_err(|_| anyhow!("signature de l'appareil invalide"))?;
    Ok(match signature.normalize_s() {
        Some(low) => (low, parity ^ 1),
        None => (signature, parity),
    })
}

pub(crate) fn recover_address(digest: &[u8; 32], signature: &Signature, parity: u8) -> Result<[u8; 20]> {
    let recid = RecoveryId::from_byte(parity).ok_or_else(|| anyhow!("parité de signature invalide"))?;
    let key = VerifyingKey::recover_from_prehash(digest, signature, recid).map_err(|_| anyhow!("signature de l'appareil non recouvrable"))?;
    address_of(key.to_encoded_point(false).as_bytes())
}

/// Signe une transaction legacy EIP-155 sur l'appareil (qui AFFICHE
/// destinataire, montant et frais) et renvoie la transaction signée, prête à
/// diffuser — après avoir vérifié qu'elle se recouvre en `expected` (l'adresse
/// du compte, lue sur l'appareil).
pub fn sign_transaction(transport: &mut dyn Transport, path: &[u32], tx: &EthTx, expected: &[u8; 20]) -> Result<Vec<u8>> {
    let rlp = tx.unsigned_rlp();
    let mut payload = encode_path(path)?;
    payload.extend_from_slice(&rlp);
    let mut response = Vec::new();
    for (i, chunk) in safe_chunks(&payload, vrs_tail_len(tx.chain_id)).into_iter().enumerate() {
        response = send(transport, CLA, INS_SIGN_TX, if i == 0 { P1_FIRST } else { P1_MORE }, 0x00, chunk)?;
    }
    anyhow::ensure!(response.len() == 65, "réponse de signature Ledger inattendue");
    let parity = parity_from_device_v(response[0], tx.chain_id)?;
    let (signature, parity) = normalized(&response[1..33], &response[33..65], parity)?;
    anyhow::ensure!(
        recover_address(&keccak(&rlp), &signature, parity)? == *expected,
        "la signature du Ledger ne correspond pas au compte attendu — transaction non diffusée"
    );
    let (r, s) = (signature.r().to_bytes(), signature.s().to_bytes());
    Ok(tx.encode_with_signature(tx.chain_id * 2 + 35 + u64::from(parity), &r.into(), &s.into()))
}

/// Signature (r ‖ s ‖ v, v = 27/28) d'une empreinte déjà signée par l'appareil
/// (`digest` : ce que la signature doit couvrir), vérifiée contre `expected`.
fn finish_message_signature(response: &[u8], digest: &[u8; 32], expected: &[u8; 20]) -> Result<[u8; 65]> {
    anyhow::ensure!(response.len() == 65, "réponse de signature Ledger inattendue");
    let parity = response[0].checked_sub(27).filter(|p| *p <= 1).ok_or_else(|| anyhow!("valeur v inattendue renvoyée par le Ledger"))?;
    let (signature, parity) = normalized(&response[1..33], &response[33..65], parity)?;
    anyhow::ensure!(
        recover_address(digest, &signature, parity)? == *expected,
        "la signature du Ledger ne correspond pas au compte attendu — refusée"
    );
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = 27 + parity;
    Ok(out)
}

/// Message personnel EIP-191 (`personal_sign`), affiché sur l'appareil.
pub fn sign_personal_message(transport: &mut dyn Transport, path: &[u32], message: &[u8], expected: &[u8; 20]) -> Result<[u8; 65]> {
    let mut payload = encode_path(path)?;
    payload.extend_from_slice(&(message.len() as u32).to_be_bytes());
    payload.extend_from_slice(message);
    let mut response = Vec::new();
    for (i, chunk) in payload.chunks(MAX_CHUNK).enumerate() {
        response = send(transport, CLA, INS_SIGN_PERSONAL, if i == 0 { P1_FIRST } else { P1_MORE }, 0x00, chunk)?;
    }
    finish_message_signature(&response, &crate::evm_sign::personal_message_hash(message), expected)
}

/// Données structurées EIP-712 en mode "empreintes" (V0) : l'appareil affiche
/// les empreintes du domaine et du message, pas leur contenu — l'app montre le
/// contenu décodé dans sa propre boîte de confirmation avant d'arriver ici.
pub fn sign_eip712_hashed(
    transport: &mut dyn Transport,
    path: &[u32],
    domain_separator: &[u8; 32],
    message_hash: &[u8; 32],
    expected: &[u8; 20],
) -> Result<[u8; 65]> {
    let mut payload = encode_path(path)?;
    payload.extend_from_slice(domain_separator);
    payload.extend_from_slice(message_hash);
    let response = send(transport, CLA, INS_SIGN_EIP712, 0x00, 0x00, &payload)?;
    let mut data = vec![0x19, 0x01];
    data.extend_from_slice(domain_separator);
    data.extend_from_slice(message_hash);
    finish_message_signature(&response, &keccak(&data), expected)
}

// --- EIP-712 complet (V1) : l'appareil reçoit la structure et les valeurs, et
// AFFICHE lui-même chaque champ (au lieu de deux empreintes illisibles en V0,
// que l'application refuse d'ailleurs sans l'option "signature à l'aveugle").
// Séquence et encodages repris de `hw-app-eth` (`modules/EIP712`), lus
// directement : définitions de TOUS les types (ordre alphabétique), valeurs du
// domaine, valeurs du message, puis signature (INS 0x0C, P2 = 1).

const INS_EIP712_STRUCT_DEF: u8 = 0x1a;
const INS_EIP712_STRUCT_IMPL: u8 = 0x1c;

/// Type de base et niveaux de tableau, de gauche à droite (`uint8[2][]` ->
/// ("uint8", [Some(2), None])) — même lecture que `destructTypeFromString`.
fn split_type(kind: &str) -> Result<(&str, Vec<Option<u8>>)> {
    let base_end = kind.find('[').unwrap_or(kind.len());
    let (base, mut rest) = kind.split_at(base_end);
    let mut levels = Vec::new();
    while !rest.is_empty() {
        let close = rest.find(']').ok_or_else(|| anyhow!("type EIP-712 mal formé : {kind}"))?;
        let size = &rest[1..close];
        levels.push(if size.is_empty() { None } else { Some(size.parse().map_err(|_| anyhow!("taille de tableau EIP-712 non gérée : {kind}"))?) });
        rest = &rest[close + 1..];
        anyhow::ensure!(rest.is_empty() || rest.starts_with('['), "type EIP-712 mal formé : {kind}");
    }
    Ok((base, levels))
}

/// (identifiant de type, taille en octets éventuelle) — `EIP712_TYPE_PROPERTIES`.
fn atomic_type(base: &str) -> Option<(u8, Option<u8>)> {
    let size = |digits: &str, divisor: u32| -> Option<u8> { digits.parse::<u32>().ok().map(|n| (n / divisor) as u8) };
    match base {
        "address" => Some((3, None)),
        "bool" => Some((4, None)),
        "string" => Some((5, None)),
        "bytes" => Some((7, None)),
        _ => {
            if let Some(bits) = base.strip_prefix("uint") {
                size(bits, 8).map(|s| (2, Some(s)))
            } else if let Some(bits) = base.strip_prefix("int") {
                size(bits, 8).map(|s| (1, Some(s)))
            } else {
                base.strip_prefix("bytes").and_then(|n| size(n, 1)).map(|s| (6, Some(s)))
            }
        }
    }
}

/// Définition d'un champ (`makeTypeEntryStructBuffer`).
fn field_definition(name: &str, kind: &str) -> Result<Vec<u8>> {
    let (base, levels) = split_type(kind)?;
    let (key, size) = atomic_type(base).unwrap_or((0, None));
    let mut out = vec![(u8::from(!levels.is_empty()) << 7) | (u8::from(size.is_some()) << 6) | key];
    if key == 0 {
        out.push(u8::try_from(base.len())?);
        out.extend_from_slice(base.as_bytes());
    }
    if let Some(size) = size {
        out.push(size);
    }
    if !levels.is_empty() {
        out.push(u8::try_from(levels.len())?);
        for level in levels {
            match level {
                Some(n) => out.extend_from_slice(&[1, n]),
                None => out.push(0),
            }
        }
    }
    out.push(u8::try_from(name.len())?);
    out.extend_from_slice(name.as_bytes());
    Ok(out)
}

/// Octets bruts d'une valeur atomique (`EIP712_TYPE_ENCODERS`) : entiers en
/// gros-boutiste minimal (complément à deux sur la taille du type s'ils sont
/// négatifs), adresse sur 20 octets, texte UTF-8, octets tels quels.
fn atomic_value(base: &str, key: u8, size: Option<u8>, value: &serde_json::Value) -> Result<Vec<u8>> {
    use crate::evm_sign::{parse_address, parse_uint256};
    let hex_bytes = |v: &serde_json::Value| -> Result<Vec<u8>> {
        let s = v.as_str().ok_or_else(|| anyhow!("octets attendus pour « {base} »"))?;
        hex::decode(s.trim_start_matches("0x")).context("octets hexadécimaux invalides")
    };
    let minimal = |bytes: &[u8]| -> Vec<u8> {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        bytes[start..].to_vec()
    };
    Ok(match key {
        1 => {
            // int : négatif -> complément à deux sur `size` octets.
            let (negative, magnitude) = match value {
                serde_json::Value::String(s) if s.trim().starts_with('-') => (true, parse_uint256(&serde_json::Value::String(s.trim()[1..].to_string()))?),
                serde_json::Value::Number(n) if n.as_i64().is_some_and(|i| i < 0) => {
                    (true, parse_uint256(&serde_json::json!(n.as_i64().expect("vérifié").unsigned_abs()))?)
                }
                other => (false, parse_uint256(other)?),
            };
            let width = usize::from(size.unwrap_or(32));
            if negative && magnitude.0.iter().any(|&b| b != 0) {
                let mut twos = magnitude.0.map(|b| !b);
                for byte in twos.iter_mut().rev() {
                    let (v, carry) = byte.overflowing_add(1);
                    *byte = v;
                    if !carry {
                        break;
                    }
                }
                twos[32 - width..].to_vec()
            } else {
                minimal(&magnitude.0)
            }
        }
        2 => minimal(&parse_uint256(value)?.0),
        3 => parse_address(value)?.to_vec(),
        4 => vec![u8::from(match value {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(s) => s == "true" || s == "1",
            serde_json::Value::Number(n) => n.as_u64() == Some(1),
            _ => false,
        })],
        5 => value.as_str().ok_or_else(|| anyhow!("texte attendu"))?.as_bytes().to_vec(),
        6 => {
            let bytes = hex_bytes(value)?;
            anyhow::ensure!(Some(bytes.len()) == size.map(usize::from), "« {base} » : longueur incorrecte");
            bytes
        }
        _ => hex_bytes(value)?,
    })
}

fn send_struct_value(transport: &mut dyn Transport, typed: &crate::evm_sign::TypedData, kind: &str, value: &serde_json::Value, depth: usize) -> Result<()> {
    anyhow::ensure!(depth < 32, "données EIP-712 trop imbriquées");
    let (base, levels) = split_type(kind)?;
    if !levels.is_empty() {
        let items = value.as_array().ok_or_else(|| anyhow!("tableau attendu pour « {kind} »"))?;
        let count = u8::try_from(items.len()).map_err(|_| anyhow!("tableau EIP-712 de plus de 255 éléments non pris en charge par le Ledger"))?;
        send(transport, CLA, INS_EIP712_STRUCT_IMPL, 0x00, 0x0f, &[count])?;
        // Même descente que hw-app-eth : un niveau de tableau en moins.
        let mut inner = base.to_string();
        for level in &levels[1..] {
            inner.push_str(&level.map_or("[]".to_string(), |n| format!("[{n}]")));
        }
        for item in items {
            send_struct_value(transport, typed, &inner, item, depth + 1)?;
        }
        return Ok(());
    }
    if let Some(fields) = typed.types.get(base) {
        for field in fields {
            let v = value.get(&field.name).ok_or_else(|| anyhow!("champ « {} » absent de « {base} »", field.name))?;
            send_struct_value(transport, typed, &field.kind, v, depth + 1)?;
        }
        return Ok(());
    }
    let (key, size) = atomic_type(base).ok_or_else(|| anyhow!("type EIP-712 inconnu : {base}"))?;
    let bytes = atomic_value(base, key, size, value)?;
    let mut data = u16::try_from(bytes.len()).map_err(|_| anyhow!("valeur EIP-712 trop longue"))?.to_be_bytes().to_vec();
    data.extend_from_slice(&bytes);
    let slices: Vec<&[u8]> = data.chunks(MAX_CHUNK).collect();
    for (i, slice) in slices.iter().enumerate() {
        send(transport, CLA, INS_EIP712_STRUCT_IMPL, u8::from(i + 1 < slices.len()), 0xff, slice)?;
    }
    Ok(())
}

/// Données structurées EIP-712 en mode COMPLET : l'appareil affiche le domaine
/// et chaque champ du message, calcule lui-même les empreintes, puis signe.
pub fn sign_eip712(transport: &mut dyn Transport, path: &[u32], typed: &crate::evm_sign::TypedData, expected: &[u8; 20]) -> Result<[u8; 65]> {
    let digest = typed.digest()?; // aussi une validation complète avant tout envoi
    let mut names: Vec<&String> = typed.types.keys().collect();
    names.sort();
    for name in names {
        send(transport, CLA, INS_EIP712_STRUCT_DEF, 0x00, 0x00, name.as_bytes())?;
        for field in &typed.types[name] {
            send(transport, CLA, INS_EIP712_STRUCT_DEF, 0x00, 0xff, &field_definition(&field.name, &field.kind)?)?;
        }
    }
    let mut roots = vec![("EIP712Domain", &typed.domain)];
    if typed.primary_type != "EIP712Domain" {
        roots.push((typed.primary_type.as_str(), &typed.message));
    }
    for (root, data) in roots {
        send(transport, CLA, INS_EIP712_STRUCT_IMPL, 0x00, 0x00, root.as_bytes())?;
        for field in &typed.types[root] {
            let v = data.get(&field.name).ok_or_else(|| anyhow!("champ « {} » absent de « {root} »", field.name))?;
            send_struct_value(transport, typed, &field.kind, v, 0)?;
        }
    }
    let response = send(transport, CLA, INS_SIGN_EIP712, 0x00, 0x01, &encode_path(path)?)?;
    finish_message_signature(&response, &digest, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transactions et découpages produits par le code officiel de ledgerjs
    /// (`@ethersproject/rlp` + `hw-app-eth` `safeChunkTransaction`) : notre RLP
    /// doit être identique octet par octet, et le découpage aussi — y compris
    /// les deux cas limites où le dernier bloc serait trop court.
    #[test]
    fn rlp_and_chunking_match_ledgerjs() {
        use sha2::{Digest, Sha256};
        let path = super::super::parse_path("44'/60'/0'/0/0").unwrap();
        for (data_len, chain_id, expected_chunks, rlp_sha256) in [
            (300usize, 11_155_111u64, vec![255, 118], "45b31f5316ca51325aebea4b7ffcd912bdb15cb3bd7e9e8c479d48380f0341fd"),
            (189, 1, vec![253, 4], "7e596d0d7d4364aaa6126f00ab2f30d5d897fb07005209a45a85c4b6f55a553b"),
            (187, 11_155_111, vec![251, 7], "f59639a52b9e671f83ea9e7ee2e0aee6b284a5785638f37a04c86da35d2f2697"),
            (0, 1, vec![66], "0ad31083df3f151255abc7d635080d0e6d37fd6f42222b670f14e85bc45058cc"),
        ] {
            let tx = EthTx {
                nonce: 5,
                gas_price: 20_000_000_000,
                gas_limit: 21_000,
                to: [0x11; 20],
                value: 1_000_000_000_000_000_000,
                chain_id,
                data: (0..data_len).map(|i| ((i * 13) & 0xff) as u8).collect(),
            };
            assert_eq!(hex::encode(Sha256::digest(tx.unsigned_rlp())), rlp_sha256, "RLP identique à ledgerjs ({data_len}, {chain_id})");
            let mut payload = encode_path(&path).unwrap();
            payload.extend_from_slice(&tx.unsigned_rlp());
            let lens: Vec<usize> = safe_chunks(&payload, vrs_tail_len(chain_id)).iter().map(|c| c.len()).collect();
            assert_eq!(lens, expected_chunks, "données {data_len}, chain {chain_id}");
        }
        // RLP exact de la transaction Sepolia longue (vecteur ledgerjs, préfixe).
        let tx = EthTx { nonce: 5, gas_price: 20_000_000_000, gas_limit: 21_000, to: [0x11; 20], value: 1_000_000_000_000_000_000, chain_id: 11_155_111, data: (0..300usize).map(|i| ((i * 13) & 0xff) as u8).collect() };
        let rlp = hex::encode(tx.unsigned_rlp());
        assert!(rlp.starts_with("f9015d058504a817c80082520894111111111111111111111111111111111111111188"), "{}", &rlp[..70]);
        assert!(rlp.ends_with("83aa36a78080"));
    }

    /// Application Ethereum OFFICIELLE dans l'émulateur Speculos (graine de test
    /// publique) : adresse identique à NOTRE dérivation de la même graine ;
    /// transaction signée après validation à l'écran, écrans vérifiés (montant,
    /// destinataire, réseau) et signature recouvrée ; refus sur l'appareil
    /// traduit en erreur claire ; message personnel signé et vérifié.
    /// Speculos doit tourner avec `ethereum-nanosp.elf` (voir ETAPES.md).
    /// `cargo test -- --ignored ledger_eth_against_the_official_app_in_speculos --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn ledger_eth_against_the_official_app_in_speculos() {
        use super::super::{speculos, TcpTransport};
        let path = super::super::parse_path("44'/60'/0'/0/0").unwrap();
        let mut t = TcpTransport::connect(speculos::APDU).unwrap();

        // 1. Adresse : celle que NOUS dérivons de la graine de test (BIP39 -> BIP32).
        let seed = bip39::Mnemonic::parse(speculos::TEST_MNEMONIC).unwrap().to_seed("");
        let (_, ours) = crate::derivation::derive_evm_key(&seed, 0).unwrap();
        let device = get_address(&mut t, &path, false).unwrap();
        assert_eq!(device, crate::derivation::format_address(&ours));
        println!("adresse Ledger = adresse dérivée : {device}");
        let expected: [u8; 20] = ours;

        // 2. Transaction Sepolia, validée à l'écran.
        let tx = EthTx { nonce: 7, gas_price: 3_000_000_000, gas_limit: 21_000, to: [0x33; 20], value: 50_000_000_000_000_000, chain_id: 11_155_111, data: vec![] };
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign transaction"]));
        let signed = sign_transaction(&mut t, &path, &tx, &expected).unwrap();
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans : {screens}");
        assert!(screens.contains("0.05 ETH"), "montant affiché");
        assert!(screens.contains("0x33333333333333333"), "destinataire affiché");
        assert!(screens.contains("Sepolia"), "réseau affiché");
        // La transaction signée se décode et se recouvre en notre adresse.
        let items = rlp::Rlp::new(&signed);
        let v: u64 = items.val_at(6).unwrap();
        assert!(v == 11_155_111 * 2 + 35 || v == 11_155_111 * 2 + 36, "v EIP-155 : {v}");

        // 3. Refus sur l'appareil : erreur claire, rien de signé.
        let rejecter = std::thread::spawn(|| speculos::review_and_accept(&["Reject"]));
        let err = sign_transaction(&mut t, &path, &tx, &expected).unwrap_err();
        rejecter.join().unwrap();
        assert!(err.to_string().contains("refusée sur le Ledger"), "{err}");

        // 4. Message personnel.
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign message"]));
        let signature = sign_personal_message(&mut t, &path, b"Connexion a example.com", &expected).unwrap();
        println!("écrans message : {}", approver.join().unwrap().join(" | "));
        assert!(matches!(signature[64], 27 | 28));

        // 5. EIP-712 en mode empreintes : exemple de la spécification (Mail).
        let typed = crate::evm_sign::parse_typed_data(&serde_json::json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
                "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"}, {"name": "contents", "type": "string"}]
            },
            "primaryType": "Mail",
            "domain": {"name": "Ether Mail", "version": "1", "chainId": 1, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
            "message": {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"}, "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"}, "contents": "Hello, Bob!"}
        }))
        .unwrap();
        // Application 1.22 : TOUT message EIP-712 que Ledger ne sait pas
        // "clear-signer" (sans descripteur signé par Ledger) exige l'option
        // "Blind signing" — mode empreintes (V0) comme mode complet (V1).
        let (domain, message) = (typed.domain_separator().unwrap(), typed.hash_struct("Mail", &typed.message).unwrap());
        speculos::set_blind_signing(false);
        let err = sign_eip712_hashed(&mut t, &path, &domain, &message, &expected).unwrap_err();
        assert!(err.to_string().contains("signature à l'aveugle"), "{err}");
        speculos::back_to_home();
        let err = sign_eip712(&mut t, &path, &typed, &expected).unwrap_err();
        assert!(err.to_string().contains("signature à l'aveugle"), "{err}");
        speculos::back_to_home();
        // Option activée : en mode complet l'appareil reçoit la structure et les
        // valeurs, AFFICHE le domaine et l'empreinte du message qu'il a
        // calculée LUI-MÊME — elle doit être celle que NOUS calculons (et celle
        // de la spécification EIP-712 pour cet exemple) ; puis il signe.
        speculos::set_blind_signing(true);
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign typed", "Sign message"]));
        let signature = sign_eip712(&mut t, &path, &typed, &expected).unwrap_or_else(|e| panic!("EIP-712 complet : {e:#} ; écran : {:?}", speculos::screen()));
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans EIP-712 : {screens}");
        assert!(screens.contains("Ether Mail") && screens.contains("verifyingContract"), "domaine affiché par l'appareil");
        // "Message hash (1/2) 0xC52C… | Message hash (2/2) …" : valeurs seules.
        let shown: String = screens
            .split(" | ")
            .filter_map(|s| s.strip_prefix("Message hash").and_then(|rest| rest.split_once(')')).map(|(_, value)| value))
            .collect::<String>()
            .replace([' ', 'x'], "")
            .to_lowercase();
        assert_eq!(shown.trim_start_matches('0'), hex::encode(message).trim_start_matches('0'), "empreinte calculée par l'appareil = la nôtre");
        assert!(matches!(signature[64], 27 | 28));
        speculos::set_blind_signing(false);
    }

    /// Exploration : textes réellement affichés par l'application Ethereum
    /// officielle pendant une signature (écran par écran), pour écrire les
    /// tests suivants sur des faits. Rejette à la fin.
    #[test]
    #[ignore]
    fn explore_speculos_eth_screens() {
        use super::super::{speculos, TcpTransport};
        let path = super::super::parse_path("44'/60'/0'/0/0").unwrap();
        let handle = std::thread::spawn(move || {
            let mut t = TcpTransport::connect(speculos::APDU).unwrap();
            let tx = EthTx { nonce: 1, gas_price: 2_000_000_000, gas_limit: 21_000, to: [0x22; 20], value: 12_345_000_000_000_000, chain_id: 11_155_111, data: vec![] };
            sign_transaction(&mut t, &path, &tx, &[0u8; 20]).err().map(|e| e.to_string())
        });
        for i in 0..14 {
            std::thread::sleep(std::time::Duration::from_millis(400));
            println!("écran {i} : {:?}", speculos::screen());
            speculos::press("right");
        }
        println!("fin : {:?}", speculos::screen());
        speculos::press("both");
        println!("résultat : {:?}", handle.join());
    }

    /// Enregistre chaque APDU et répond "OK" (et une fausse signature à 0x0C).
    struct Recorder(Vec<String>);
    impl Transport for Recorder {
        fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            self.0.push(hex::encode(apdu));
            if apdu[1] == INS_SIGN_EIP712 {
                let mut r = vec![0x1b];
                r.extend_from_slice(&[1u8; 64]);
                r.extend_from_slice(&[0x90, 0x00]);
                return Ok(r);
            }
            Ok(vec![0x90, 0x00])
        }
    }

    /// Séquence d'APDU identique, octet par octet, à celle de `hw-app-eth`
    /// (`signEIP712Message` tel qu'appelé par Ledger Live) : 41 commandes pour un message avec
    /// tableaux de structures, tableau vide, int16 négatif, tableau fixe de
    /// booléens, bytes4 et 300 octets de `bytes` (découpés en 2 commandes).
    #[test]
    fn eip712_full_mode_apdus_match_ledgerjs() {
        use sha2::{Digest, Sha256};
        let typed = crate::evm_sign::parse_typed_data(&serde_json::json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                "Person": [{"name": "name", "type": "string"}, {"name": "wallets", "type": "address[]"}],
                "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person[]"}, {"name": "contents", "type": "string"}, {"name": "delta", "type": "int16"}, {"name": "flags", "type": "bool[2]"}, {"name": "id", "type": "bytes4"}, {"name": "blob", "type": "bytes"}]
            },
            "primaryType": "Mail",
            "domain": {"name": "Ether Mail", "version": "1", "chainId": 11155111, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
            "message": {
                "from": {"name": "Cow", "wallets": ["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"]},
                "to": [{"name": "Bob", "wallets": []}, {"name": "Alice", "wallets": ["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB", "0x2222222222222222222222222222222222222222"]}],
                "contents": "Hello, Bob!", "delta": "-300", "flags": [true, false], "id": "0xdeadbeef", "blob": format!("0x{}", "ab".repeat(300))
            }
        }))
        .unwrap();
        let mut recorder = Recorder(Vec::new());
        let path = super::super::parse_path("44'/60'/0'/0/0").unwrap();
        // La fausse signature ne se recouvre pas : erreur attendue, APDU comparées.
        assert!(sign_eip712(&mut recorder, &path, &typed, &[0u8; 20]).is_err());
        assert_eq!(recorder.0.len(), 41);
        assert_eq!(recorder.0[33], "e01c00ff040002fed4", "int16 -300 en complément à deux");
        assert_eq!(recorder.0[19], "e01c00ff050003aa36a7", "chainId minimal");
        // Signature en mode complet : P2 = 1 (spécification, et appel par défaut
        // de Ledger Live ; le paramètre `fullImplem = true` de hw-app-eth, lui,
        // envoie P2 = 0 — nom trompeur, vérifié dans son code).
        assert_eq!(recorder.0[40], "e00c000115058000002c8000003c800000000000000000000000");
        assert_eq!(hex::encode(Sha256::digest(recorder.0.join("\n"))), "d76254139aacdd485c98aa4366177d37a914f63fca62717bab1917a04ec9ef1b");
    }

    #[test]
    fn device_v_parity_follows_ledgerjs() {
        // Mainnet : 1*2+35 = 37 -> 0x25/0x26.
        assert_eq!(parity_from_device_v(0x25, 1).unwrap(), 0);
        assert_eq!(parity_from_device_v(0x26, 1).unwrap(), 1);
        // Sepolia : (11155111*2+35) % 256 = 0x71 -> 0x71/0x72 (octet débordé).
        assert_eq!(parity_from_device_v(0x71, 11_155_111).unwrap(), 0);
        assert_eq!(parity_from_device_v(0x72, 11_155_111).unwrap(), 1);
        assert!(parity_from_device_v(0x00, 1).is_err());
    }
}
