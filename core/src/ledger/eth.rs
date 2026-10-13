//! Ledger Ethereum app (`app-ethereum`, `doc/apdu.md` specification): address,
//! transaction signing (legacy EIP-155), personal message signing (EIP-191) and
//! EIP-712 typed data signing ("hashes" mode, V0).
//!
//! Every signature returned by the device is verified HERE before it is used: it
//! must recover to the expected address. A device (or emulator, or cable) that
//! returned anything else is refused before any broadcast.

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

/// EVM address (EIP-55 format) of an uncompressed public key (65 bytes).
fn address_of(public: &[u8]) -> Result<[u8; 20]> {
    anyhow::ensure!(public.len() == 65 && public[0] == 0x04, "clé publique Ledger mal formée");
    let hash = keccak(&public[1..]);
    Ok(hash[12..].try_into().expect("20 octets"))
}

/// Address of the `path` account. `confirm`: the device DISPLAYS it and asks for
/// approval. That is the only way for the user to check that a receiving address
/// was not swapped somewhere between the device and the computer screen.
pub fn get_address(transport: &mut dyn Transport, path: &[u32], confirm: bool) -> Result<String> {
    let response = send(transport, CLA, INS_GET_ADDRESS, u8::from(confirm), 0x00, &encode_path(path)?)?;
    let key_len = *response.first().ok_or_else(|| anyhow!("réponse Ledger vide"))? as usize;
    let public = response.get(1..1 + key_len).ok_or_else(|| anyhow!("réponse Ledger tronquée"))?;
    let addr_len = *response.get(1 + key_len).ok_or_else(|| anyhow!("réponse Ledger tronquée"))? as usize;
    let ascii = response.get(2 + key_len..2 + key_len + addr_len).ok_or_else(|| anyhow!("réponse Ledger tronquée"))?;
    let claimed = std::str::from_utf8(ascii).context("adresse Ledger illisible")?;
    // The address announced must be the one of the public key returned.
    let derived = address_of(public)?;
    anyhow::ensure!(
        claimed.trim_start_matches("0x").eq_ignore_ascii_case(&hex::encode(derived)),
        "le Ledger a renvoyé une adresse qui ne correspond pas à sa clé publique"
    );
    Ok(crate::derivation::format_address(&derived))
}

/// Split into chunks of at most 255 bytes (`hw-app-eth` `safeChunkTransaction`):
/// for a legacy transaction, the last chunk must never contain ONLY all or part of
/// the final tuple (`chain_id, 0, 0`), otherwise the device could consider the
/// transaction complete too early.
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

/// Length of the final tuple (`chain_id, 0, 0`) without the list header.
fn vrs_tail_len(chain_id: u64) -> usize {
    let bytes = chain_id.to_be_bytes();
    let trimmed = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(7)..];
    let chain_rlp = if trimmed.len() == 1 && trimmed[0] < 0x80 { 1 } else { 1 + trimmed.len() };
    chain_rlp + 2
}

/// Parity from the ONE-byte `v` returned by the device (`hw-app-eth` `getParity`):
/// the device applies EIP-155 to a chain_id truncated to 4 bytes, and the byte
/// overflows.
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

/// r, s (s normalized to "low", EIP-2) and the effective parity.
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

/// Signs a legacy EIP-155 transaction on the device (which DISPLAYS the recipient,
/// amount and fee) and returns the signed transaction, ready to broadcast, after
/// checking that it recovers to `expected` (the account address, read from the
/// device).
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

/// Signature (r ‖ s ‖ v, v = 27/28) over a digest the device has already signed
/// (`digest`: what the signature must cover), verified against `expected`.
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

/// EIP-191 personal message (`personal_sign`), displayed on the device.
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

/// EIP-712 typed data in "hashes" mode (V0): the device shows the domain and
/// message hashes, not their contents. The app shows the decoded contents in its
/// own confirmation dialog before getting here.
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

// --- Full EIP-712 (V1): the device receives the structure and the values, and
// DISPLAYS every field itself (instead of two unreadable hashes in V0, which the
// app refuses anyway unless "blind signing" is enabled). Sequence and encodings
// taken from `hw-app-eth` (`modules/EIP712`), read directly from its source:
// definitions of ALL types (alphabetical order), domain values, message values,
// then the signature (INS 0x0C, P2 = 1).

const INS_EIP712_STRUCT_DEF: u8 = 0x1a;
const INS_EIP712_STRUCT_IMPL: u8 = 0x1c;

/// Base type and array levels, from left to right (`uint8[2][]` -> ("uint8",
/// [Some(2), None])), parsed the same way as `destructTypeFromString`.
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

/// (type identifier, size in bytes if any), as in `EIP712_TYPE_PROPERTIES`.
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

/// Definition of a field (`makeTypeEntryStructBuffer`).
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

/// Raw bytes of an atomic value (`EIP712_TYPE_ENCODERS`): integers as minimal
/// big-endian (two's complement over the type's size when negative), addresses on
/// 20 bytes, strings as UTF-8, bytes as is.
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
            // int: negative -> two's complement over `size` bytes.
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
        // Same descent as hw-app-eth: one array level fewer.
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

/// EIP-712 typed data in FULL mode: the device displays the domain and every field
/// of the message, computes the hashes itself, then signs.
pub fn sign_eip712(transport: &mut dyn Transport, path: &[u32], typed: &crate::evm_sign::TypedData, expected: &[u8; 20]) -> Result<[u8; 65]> {
    let digest = typed.digest()?; // also a full validation before anything is sent
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

    /// Transactions and chunks produced by the official ledgerjs code
    /// (`@ethersproject/rlp` + `hw-app-eth` `safeChunkTransaction`): our RLP must be
    /// byte-for-byte identical, and so must the chunking, including the two edge cases
    /// where the last chunk would be too short.
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
        // Exact RLP of the long Sepolia transaction (ledgerjs vector, prefix).
        let tx = EthTx { nonce: 5, gas_price: 20_000_000_000, gas_limit: 21_000, to: [0x11; 20], value: 1_000_000_000_000_000_000, chain_id: 11_155_111, data: (0..300usize).map(|i| ((i * 13) & 0xff) as u8).collect() };
        let rlp = hex::encode(tx.unsigned_rlp());
        assert!(rlp.starts_with("f9015d058504a817c80082520894111111111111111111111111111111111111111188"), "{}", &rlp[..70]);
        assert!(rlp.ends_with("83aa36a78080"));
    }

    /// The OFFICIAL Ethereum app in the Speculos emulator (public test seed): address identical to OUR
    /// derivation from the same seed; transaction signed after on-screen approval, screens checked (amount,
    /// recipient, network) and signature recovered; a refusal on the device turned into a clear error;
    /// personal message signed and verified. Speculos must run `ethereum-nanosp.elf`.
    /// `cargo test -- --ignored ledger_eth_against_the_official_app_in_speculos --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn ledger_eth_against_the_official_app_in_speculos() {
        use super::super::{speculos, TcpTransport};
        let path = super::super::parse_path("44'/60'/0'/0/0").unwrap();
        let mut t = TcpTransport::connect(speculos::APDU).unwrap();

        // 1. Address: the one WE derive from the test seed (BIP39 -> BIP32).
        let seed = bip39::Mnemonic::parse(speculos::TEST_MNEMONIC).unwrap().to_seed("");
        let (_, ours) = crate::derivation::derive_evm_key(&seed, 0).unwrap();
        let device = get_address(&mut t, &path, false).unwrap();
        assert_eq!(device, crate::derivation::format_address(&ours));
        println!("adresse Ledger = adresse dérivée : {device}");
        let expected: [u8; 20] = ours;

        // 2. Sepolia transaction, approved on screen.
        let tx = EthTx { nonce: 7, gas_price: 3_000_000_000, gas_limit: 21_000, to: [0x33; 20], value: 50_000_000_000_000_000, chain_id: 11_155_111, data: vec![] };
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign transaction"]));
        let signed = sign_transaction(&mut t, &path, &tx, &expected).unwrap();
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans : {screens}");
        assert!(screens.contains("0.05 ETH"), "montant affiché");
        assert!(screens.contains("0x33333333333333333"), "destinataire affiché");
        assert!(screens.contains("Sepolia"), "réseau affiché");
        // The signed transaction decodes and recovers to our address.
        let items = rlp::Rlp::new(&signed);
        let v: u64 = items.val_at(6).unwrap();
        assert!(v == 11_155_111 * 2 + 35 || v == 11_155_111 * 2 + 36, "v EIP-155 : {v}");

        // 3. Refusal on the device: clear error, nothing signed.
        let rejecter = std::thread::spawn(|| speculos::review_and_accept(&["Reject"]));
        let err = sign_transaction(&mut t, &path, &tx, &expected).unwrap_err();
        rejecter.join().unwrap();
        assert!(err.to_string().contains("refusée sur le Ledger"), "{err}");

        // 4. Personal message.
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign message"]));
        let signature = sign_personal_message(&mut t, &path, b"Connexion a example.com", &expected).unwrap();
        println!("écrans message : {}", approver.join().unwrap().join(" | "));
        assert!(matches!(signature[64], 27 | 28));

        // 5. EIP-712 in hashes mode: the example from the specification (Mail).
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
        // App 1.22: ANY EIP-712 message that Ledger cannot "clear-sign" (no descriptor
        // signed by Ledger) requires the "Blind signing" setting, in hashes mode (V0) as
        // well as full mode (V1).
        let (domain, message) = (typed.domain_separator().unwrap(), typed.hash_struct("Mail", &typed.message).unwrap());
        speculos::set_blind_signing(false);
        let err = sign_eip712_hashed(&mut t, &path, &domain, &message, &expected).unwrap_err();
        assert!(err.to_string().contains("signature à l'aveugle"), "{err}");
        speculos::back_to_home();
        let err = sign_eip712(&mut t, &path, &typed, &expected).unwrap_err();
        assert!(err.to_string().contains("signature à l'aveugle"), "{err}");
        speculos::back_to_home();
        // With the setting enabled, in full mode the device receives the structure and the
        // values, then DISPLAYS the domain and the message hash it computed ITSELF. That
        // hash must match the one WE compute (and the one in the EIP-712 specification for
        // this example); then it signs.
        speculos::set_blind_signing(true);
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Sign typed", "Sign message"]));
        let signature = sign_eip712(&mut t, &path, &typed, &expected).unwrap_or_else(|e| panic!("EIP-712 complet : {e:#} ; écran : {:?}", speculos::screen()));
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans EIP-712 : {screens}");
        assert!(screens.contains("Ether Mail") && screens.contains("verifyingContract"), "domaine affiché par l'appareil");
        // "Message hash (1/2) 0xC52C… | Message hash (2/2) …": values only.
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

    /// Exploration: the text actually displayed by the official Ethereum app during
    /// signing (screen by screen), so that the following tests are written from facts.
    /// Rejects at the end.
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

    /// Records every APDU and answers "OK" (plus a fake signature for 0x0C).
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

    /// APDU sequence identical, byte for byte, to that of `hw-app-eth` (`signEIP712Message` as
    /// called by Ledger Live): 41 commands for a message with arrays of structs, an empty
    /// array, a negative int16, a fixed-size array of booleans, a bytes4 and 300 bytes of
    /// `bytes` (split over 2 commands).
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
        // The fake signature does not recover: error expected, APDUs compared.
        assert!(sign_eip712(&mut recorder, &path, &typed, &[0u8; 20]).is_err());
        assert_eq!(recorder.0.len(), 41);
        assert_eq!(recorder.0[33], "e01c00ff040002fed4", "int16 -300 en complément à deux");
        assert_eq!(recorder.0[19], "e01c00ff050003aa36a7", "chainId minimal");
        // Full-mode signature: P2 = 1 (per the specification, and Ledger Live's default
        // call; hw-app-eth's `fullImplem = true` parameter actually sends P2 = 0, a
        // misleading name, checked in its code).
        assert_eq!(recorder.0[40], "e00c000115058000002c8000003c800000000000000000000000");
        assert_eq!(hex::encode(Sha256::digest(recorder.0.join("\n"))), "d76254139aacdd485c98aa4366177d37a914f63fca62717bab1917a04ec9ef1b");
    }

    #[test]
    fn device_v_parity_follows_ledgerjs() {
        // Mainnet: 1*2+35 = 37 -> 0x25/0x26.
        assert_eq!(parity_from_device_v(0x25, 1).unwrap(), 0);
        assert_eq!(parity_from_device_v(0x26, 1).unwrap(), 1);
        // Sepolia: (11155111*2+35) % 256 = 0x71 -> 0x71/0x72 (the byte overflows).
        assert_eq!(parity_from_device_v(0x71, 11_155_111).unwrap(), 0);
        assert_eq!(parity_from_device_v(0x72, 11_155_111).unwrap(), 1);
        assert!(parity_from_device_v(0x00, 1).is_err());
    }
}
