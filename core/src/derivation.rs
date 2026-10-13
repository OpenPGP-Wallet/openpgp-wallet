use anyhow::{anyhow, Context, Result};
use bech32::{FromBase32, ToBase32, Variant};
use bip32::{DerivationPath, XPrv};
use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use sha2::{Sha256, Sha512};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Derives a private key from the master seed (BIP32) and a derivation path.
///
/// The caller is responsible for the seed: in the app's normal flow it only exists in the
/// clear right after being rebuilt from the decrypted shares (the `wallet_demo` examples use
/// throwaway entropy instead).
fn derive_key_from_path(seed: &[u8], path: &str) -> Result<SigningKey> {
    let root = XPrv::new(seed).context("dérivation BIP32 racine impossible")?;
    let path: DerivationPath = path.parse().context("chemin de dérivation invalide")?;

    let mut child = root;
    for c in path.iter() {
        child = child
            .derive_child(c)
            .context("échec de dérivation d'un segment")?;
    }

    Ok(child.private_key().clone())
}

/// Derives EVM private key no. `index` (path m/44'/60'/0'/0/{index}) and also
/// returns the matching EVM address (20 bytes).
pub fn derive_evm_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/60'/0'/0/{index}"))?;
    let address = evm_address_from_key(&signing_key);
    Ok((signing_key, address))
}

/// Derives Bitcoin testnet private key no. `index` (path m/44'/1'/0'/0/{index},
/// coin_type 1' = testnet) and returns the hash160 (RIPEMD160(SHA256(compressed
/// pubkey))) used to build the P2WPKH address.
pub fn derive_btc_testnet_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/1'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Derives Bitcoin MAINNET private key no. `index` (path m/44'/0'/0'/0/{index},
/// coin_type 0' = Bitcoin mainnet). The path differs from testnet, so the address
/// differs for the same index: the two are never interchangeable, unlike EVM/Solana
/// where the same address works on every variant of the network.
pub fn derive_btc_mainnet_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/0'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Computes the EVM address (last 20 bytes of the Keccak256 of the uncompressed public key,
/// 0x04 prefix excluded).
pub fn evm_address_from_key(signing_key: &SigningKey) -> [u8; 20] {
    let verifying_key = signing_key.verifying_key();
    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // drop the 0x04 prefix

    let hash = Keccak256::digest(pubkey_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Applies EIP-55 checksum casing to an EVM address already in lowercase hex: the case of
/// each letter encodes a checksum of the address itself (Keccak256) without changing its
/// value. Used both for display (`format_address`) and to validate an address entered by
/// the user (`wallet_flow::parse_evm_address`).
fn eip55_checksum(hex_lower: &str) -> String {
    let hash_hex = hex::encode(Keccak256::digest(hex_lower.as_bytes()));
    hex_lower
        .chars()
        .zip(hash_hex.chars())
        .map(|(c, h)| {
            if c.is_ascii_alphabetic() && h.to_digit(16).unwrap_or(0) >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

/// EVM address in EIP-55 format (checksum casing): a single miscopied letter changes the
/// expected case at that position, which lets `parse_evm_address` catch a typo that
/// would otherwise go unnoticed (the hex being otherwise valid).
pub fn format_address(address: &[u8; 20]) -> String {
    format!("0x{}", eip55_checksum(&hex::encode(address)))
}

/// Derives transparent Zcash key no. `index` (BIP44 path m/44'/133'/0'/0/{index},
/// coin_type 133' = Zcash in SLIP-0044, the same path Ledger and Zcash wallets use
/// for transparent addresses) and returns the hash160 of the compressed public key
/// (P2PKH address t1…, see `zcash::p2pkh_address`).
pub fn derive_zec_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/133'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Derives Dogecoin key no. `index` (BIP44 path m/44'/3'/0'/0/{index}, coin_type 3'
/// = Dogecoin in SLIP-0044, the one Ledger, Trezor and Dogecoin Core use) and
/// returns the hash160 of the compressed public key (P2PKH address D…, see
/// `doge::p2pkh_address`).
pub fn derive_doge_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/3'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Derives Tron key no. `index` (BIP44 path m/44'/195'/0'/0/{index}, coin_type 195'
/// = Tron in SLIP-0044, the one Ledger, Trezor and TronLink use) and returns the
/// address (21 bytes, 0x41 prefix; see `tron::address_of`).
pub fn derive_tron_key(seed: &[u8], index: u32) -> Result<(SigningKey, crate::tron::Address)> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/195'/0'/0/{index}"))?;
    let address = crate::tron::address_of(&signing_key);
    Ok((signing_key, address))
}

/// Derives Stacks key no. `index` (path m/44'/5757'/0'/0/{index}, the one Leather
/// and Xverse use; SP… address: see `stacks`).
pub fn derive_stacks_key(seed: &[u8], index: u32) -> Result<SigningKey> {
    derive_key_from_path(seed, &format!("m/44'/5757'/0'/0/{index}"))
}

/// Derives XRP key no. `index` (BIP44 path m/44'/144'/0'/0/{index}, coin_type 144'
/// = XRP in SLIP-0044, the one Ledger and Xaman use) and returns the account ID
/// (hash160 of the compressed key; see `xrp`).
pub fn derive_xrp_key(seed: &[u8], index: u32) -> Result<(SigningKey, crate::xrp::AccountId)> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/144'/0'/0/{index}"))?;
    let account = btc_hash160_from_key(&signing_key);
    Ok((signing_key, account))
}

/// hash160 = RIPEMD160(SHA256(compressed public key)), as Bitcoin uses it to build a
/// P2WPKH address.
fn btc_hash160_from_key(signing_key: &SigningKey) -> [u8; 20] {
    let compressed = signing_key.verifying_key().to_encoded_point(true);
    let sha256 = Sha256::digest(compressed.as_bytes());
    let ripemd = Ripemd160::digest(sha256);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

/// Formats a Bitcoin testnet P2WPKH address (bech32, "tb1q..." prefix).
pub fn format_btc_testnet_address(hash160: &[u8; 20]) -> Result<String> {
    let mut data = vec![bech32::u5::try_from_u8(0).unwrap()]; // witness version 0 (P2WPKH)
    data.extend(hash160.to_base32());
    bech32::encode("tb", data, Variant::Bech32).context("encodage bech32 impossible")
}

/// Formats a Bitcoin MAINNET P2WPKH address (bech32, "bc1q..." prefix).
pub fn format_btc_mainnet_address(hash160: &[u8; 20]) -> Result<String> {
    let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
    data.extend(hash160.to_base32());
    bech32::encode("bc", data, Variant::Bech32).context("encodage bech32 impossible")
}

/// Derives THORChain private key no. `index` (path m/44'/931'/0'/0/{index},
/// coin_type 931', officially registered for RUNE in SLIP-0044) and returns the
/// matching hash160. Same curve (secp256k1) and same hash160 computation as
/// Bitcoin: THORChain, like other Cosmos SDK chains, reuses exactly
/// RIPEMD160(SHA256(compressed public key)) to derive its address. Used to receive
/// a swap's affiliate fees (see api::swap_quote) and to pay for registering the
/// affiliate name (see `native_deposit`); never for regular sends.
pub fn derive_thor_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/931'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Monero base key no. `index`: the secp256k1 BIP32 key at path
/// m/44'/128'/{index}'/0/0, the same path and use as Ledger's Monero app
/// (`monero_init_private_key`); the spend key is drawn from it with keccak (see
/// `monero::spend_key`).
pub fn derive_monero_base_key(seed: &[u8], index: u32) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let key = derive_key_from_path(seed, &format!("m/44'/128'/{index}'/0/0"))?;
    Ok(zeroize::Zeroizing::new(key.to_bytes().into()))
}

/// Formats a THORChain address (bech32, "thor1..." prefix), like Bitcoin but
/// WITHOUT a witness version byte (no SegWit on Cosmos SDK): the hash160 is encoded
/// directly.
pub fn format_thor_address(hash160: &[u8; 20]) -> Result<String> {
    bech32::encode("thor", hash160.to_base32(), Variant::Bech32)
        .context("encodage bech32 impossible")
}

/// SLIP-0010 derivation for ed25519: unlike BIP32/secp256k1, non-hardened derivation
/// does not exist on this curve (no usable public point arithmetic), so EVERY level
/// of the path is hardened ("'" indexes).
fn slip10_ed25519_master(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("clé HMAC de taille valide");
    mac.update(seed);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    chain_code.copy_from_slice(&out[32..]);
    (key, chain_code)
}

fn slip10_ed25519_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> ([u8; 32], [u8; 32]) {
    let hardened_index = index | 0x8000_0000; // forces hardening, whatever the caller
    let mut mac = HmacSha512::new_from_slice(parent_chain_code).expect("clé HMAC de taille valide");
    mac.update(&[0x00]);
    mac.update(parent_key);
    mac.update(&hardened_index.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    chain_code.copy_from_slice(&out[32..]);
    (key, chain_code)
}

/// SLIP-10 ed25519 key for an arbitrary, fully hardened path (indexes given without
/// the hardening bit, since SLIP-10 only allows hardened derivation on ed25519).
/// Tests only: cross-check the keys returned by a Ledger (Ledger Live path
/// m/44'/501'/i') against an independent derivation.
#[cfg(test)]
pub(crate) fn derive_ed25519_path(seed: &[u8], path: &[u32]) -> ed25519_dalek::SigningKey {
    let (mut key, mut chain_code) = slip10_ed25519_master(seed);
    for &index in path {
        let (k, cc) = slip10_ed25519_child(&key, &chain_code, index);
        key = k;
        chain_code = cc;
    }
    ed25519_dalek::SigningKey::from_bytes(&key)
}

/// Derives Solana key no. `account_index` (path m/44'/501'/{account_index}'/0', the
/// convention most Solana wallets use) from the master seed.
pub fn derive_solana_key(seed: &[u8], account_index: u32) -> ed25519_dalek::SigningKey {
    let (mut key, mut chain_code) = slip10_ed25519_master(seed);
    for index in [44u32, 501, account_index, 0] {
        let (k, cc) = slip10_ed25519_child(&key, &chain_code, index);
        key = k;
        chain_code = cc;
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key);
    // `ed25519_dalek::SigningKey::from_bytes` copies `key` internally (and wipes
    // itself when dropped); we also wipe this local copy, which would otherwise stay
    // in the clear on this function's stack for no reason.
    key.zeroize();
    chain_code.zeroize();
    signing_key
}

/// Derives Stellar key no. `account_index` (SEP-0005: m/44'/148'/{account_index}',
/// a fully hardened path, the one Ledger, Lobstr and Freighter use).
pub fn derive_stellar_key(seed: &[u8], account_index: u32) -> ed25519_dalek::SigningKey {
    let (mut key, mut chain_code) = slip10_ed25519_master(seed);
    for index in [44u32, 148, account_index] {
        let (k, cc) = slip10_ed25519_child(&key, &chain_code, index);
        key = k;
        chain_code = cc;
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key);
    key.zeroize();
    chain_code.zeroize();
    signing_key
}

/// Derives NEAR key no. `account_index` (m/44'/397'/{account_index}', the fully
/// hardened path from near-seed-phrase, the one NEAR wallets use); its implicit
/// account is the public key in hexadecimal (see `near`).
pub fn derive_near_key(seed: &[u8], account_index: u32) -> ed25519_dalek::SigningKey {
    let (mut key, mut chain_code) = slip10_ed25519_master(seed);
    for index in [44u32, 397, account_index] {
        let (k, cc) = slip10_ed25519_child(&key, &chain_code, index);
        key = k;
        chain_code = cc;
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key);
    key.zeroize();
    chain_code.zeroize();
    signing_key
}

/// Refusal of a Bitcoin destination address, in plain words.
pub const BTC_ADDRESS_UNSUPPORTED: &str = "type d'adresse Bitcoin pas encore pris en charge (version SegWit future) : demandez une autre adresse au destinataire";
pub const BTC_ADDRESS_MISCOPIED: &str =
    "adresse Bitcoin non reconnue : un caractère semble mal recopié";
pub const BTC_ADDRESS_OTHER_NETWORK: &str = "adresse d'un autre réseau que Bitcoin";

/// Decodes a Bitcoin testnet P2WPKH address (bech32) into a hash160 (20 bytes): the
/// wallet's own address (the only form it uses).
pub fn parse_btc_testnet_address(address: &str) -> Result<[u8; 20]> {
    p2wpkh_hash160(decode_segwit(address, "tb", "testnet")?)
}

/// Decodes a Bitcoin MAINNET P2WPKH address (bech32) into a hash160 (20 bytes): the
/// wallet's own address, or a THORChain/Maya inbound address (always P2WPKH). A
/// DESTINATION address goes through `btc_recipient_script`.
pub fn parse_btc_mainnet_address(address: &str) -> Result<[u8; 20]> {
    p2wpkh_hash160(decode_segwit(address, "bc", "mainnet")?)
}

/// Output script of a Bitcoin MAINNET destination address (see
/// `btc_recipient_script`).
pub fn btc_mainnet_recipient_script(address: &str) -> Result<Vec<u8>> {
    btc_recipient_script(address, false)
}

/// Output script of a Bitcoin testnet destination address.
pub fn btc_testnet_recipient_script(address: &str) -> Result<Vec<u8>> {
    btc_recipient_script(address, true)
}

/// Output script (scriptPubKey) of a Bitcoin destination address: SegWit v0 (P2WPKH
/// bc1q…, or P2WSH), Taproot (bc1p…, 32-byte program only: a version 1 program of
/// any other size is not protected by any key), or legacy (P2PKH 1…, P2SH 3…; m…/n…
/// and 2… on testnet). Future SegWit versions are refused. Refusals are explained
/// in plain words: typo, address from another network.
fn btc_recipient_script(address: &str, testnet: bool) -> Result<Vec<u8>> {
    let address = address.trim();
    let (hrp, network, p2pkh, p2sh, legacy_prefixes) = if testnet {
        ("tb", "testnet", 0x6f, 0xc4, &['m', 'n', '2'][..])
    } else {
        ("bc", "mainnet", 0x00, 0x05, &['1', '3'][..])
    };
    if let Some((version, hash)) = base58check_hash160(address) {
        return match version {
            v if v == p2pkh => Ok([&[0x76, 0xa9, 0x14][..], &hash, &[0x88, 0xac]].concat()),
            v if v == p2sh => Ok([&[0xa9, 0x14][..], &hash, &[0x87]].concat()),
            _ => Err(anyhow!(BTC_ADDRESS_OTHER_NETWORK)),
        };
    }
    match decode_segwit(address, hrp, network) {
        // Version 0: 20- or 32-byte program (checked while decoding).
        Ok((0, program)) => Ok([&[0x00, program.len() as u8][..], &program].concat()),
        Ok((1, program)) if program.len() == 32 => Ok([&[0x51, 0x20][..], &program].concat()),
        Ok(_) => Err(anyhow!(BTC_ADDRESS_UNSUPPORTED)),
        Err(_)
            if address.starts_with(legacy_prefixes)
                || address.to_ascii_lowercase().starts_with(&format!("{hrp}1")) =>
        {
            Err(anyhow!(BTC_ADDRESS_MISCOPIED))
        }
        Err(e) => Err(e),
    }
}

/// Version and hash160 of a 25-byte base58check address (checksum verified),
/// whatever its network.
fn base58check_hash160(address: &str) -> Option<(u8, [u8; 20])> {
    let bytes = bs58::decode(address).into_vec().ok()?;
    if bytes.len() != 25 || Sha256::digest(Sha256::digest(&bytes[..21]))[..4] != bytes[21..] {
        return None;
    }
    Some((bytes[0], bytes[1..21].try_into().ok()?))
}

/// Address of a standard output script (the inverse of `btc_recipient_script`, for
/// display on a Trezor, which expects the address itself).
pub fn btc_script_address(script: &[u8], testnet: bool) -> Result<String> {
    let (hrp, p2pkh, p2sh) = if testnet {
        ("tb", 0x6f, 0xc4)
    } else {
        ("bc", 0x00, 0x05)
    };
    let base58check = |version: u8, hash: &[u8]| {
        let mut payload = vec![version];
        payload.extend_from_slice(hash);
        let check = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&check[..4]);
        bs58::encode(payload).into_string()
    };
    let segwit = |version: u8, program: &[u8], variant: Variant| {
        let mut data = vec![bech32::u5::try_from_u8(version).expect("version 0 ou 1")];
        data.extend(program.to_base32());
        bech32::encode(hrp, data, variant).context("encodage bech32 impossible")
    };
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            Ok(base58check(p2pkh, hash))
        }
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => Ok(base58check(p2sh, hash)),
        [0x00, len, program @ ..]
            if usize::from(*len) == program.len() && matches!(program.len(), 20 | 32) =>
        {
            segwit(0, program, Variant::Bech32)
        }
        [0x51, 0x20, program @ ..] if program.len() == 32 => segwit(1, program, Variant::Bech32m),
        _ => Err(anyhow!("type de sortie Bitcoin non pris en charge")),
    }
}

/// Output script (scriptPubKey) of any Bitcoin MAINNET SegWit address: v0 (bc1q…,
/// P2WPKH or P2WSH) or v1 (bc1p…, Taproot). This is a bridge's deposit address,
/// which the app pays without owning it.
pub fn btc_mainnet_script_pubkey(address: &str) -> Result<Vec<u8>> {
    let (version, program) = decode_segwit(address, "bc", "mainnet")?;
    anyhow::ensure!(
        version <= 1,
        "adresse Bitcoin d'une version SegWit future (v{version}) — refusée"
    );
    // OP_0, or OP_1 (0x51); then the program pushed as is.
    let mut script = vec![if version == 0 { 0x00 } else { 0x51 }, program.len() as u8];
    script.extend_from_slice(&program);
    Ok(script)
}

/// Witness version and program of a SegWit address (BIP173 / BIP350), with the
/// rules bech32 decoding alone does not check: bech32 encoding for version 0 and
/// bech32m above it, valid program sizes. Without them, a 20-byte Taproot address
/// (v1, bech32m) passed as a P2WPKH, and the payment went to a different script
/// from the one entered.
fn decode_segwit(address: &str, expected_hrp: &str, network: &str) -> Result<(u8, Vec<u8>)> {
    let (hrp, data, variant) = bech32::decode(address).context("adresse bech32 invalide")?;
    if hrp != expected_hrp {
        return Err(anyhow!(
            "adresse non-{network} (préfixe '{expected_hrp}' attendu, trouvé '{hrp}')"
        ));
    }
    let (version, program) = data
        .split_first()
        .ok_or_else(|| anyhow!("adresse bech32 vide"))?;
    let version = version.to_u8();
    let program =
        Vec::<u8>::from_base32(program).context("conversion base32 -> octets impossible")?;
    let expected_variant = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    anyhow::ensure!(
        version <= 16
            && variant == expected_variant
            && (2..=40).contains(&program.len())
            && (version != 0 || matches!(program.len(), 20 | 32)),
        "adresse Bitcoin mal formée (version SegWit, encodage ou longueur incohérents)"
    );
    Ok((version, program))
}

fn p2wpkh_hash160((version, program): (u8, Vec<u8>)) -> Result<[u8; 20]> {
    anyhow::ensure!(
        version == 0,
        "programme témoin de taille inattendue (P2WPKH attend 20 octets)"
    );
    program
        .try_into()
        .map_err(|_| anyhow!("programme témoin de taille inattendue (P2WPKH attend 20 octets)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official EIP-55 test vectors: https://eips.ethereum.org/EIPS/eip-55
    #[test]
    fn format_address_matches_eip55_test_vectors() {
        let vectors = [
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];
        for expected_hex in vectors {
            let bytes: [u8; 20] = hex::decode(expected_hex).unwrap().try_into().unwrap();
            assert_eq!(format_address(&bytes), format!("0x{expected_hex}"));
        }
    }

    // A deliberately redundant guard: Bitcoin mainnet and testnet derive DIFFERENT
    // addresses for the same index (unlike EVM/Solana), so a regression here would
    // silently send real funds to an unusable testnet address, or the other way round.
    #[test]
    fn btc_mainnet_and_testnet_derive_different_addresses_for_the_same_seed_and_index() {
        let seed = [7u8; 32];
        let (_mainnet_key, mainnet_hash160) = derive_btc_mainnet_key(&seed, 0).unwrap();
        let (_testnet_key, testnet_hash160) = derive_btc_testnet_key(&seed, 0).unwrap();

        // Different derivation paths (coin_type 0' vs 1'): the same hash160 is not
        // guaranteed, and in practice it differs here with this seed.
        assert_ne!(mainnet_hash160, testnet_hash160);

        let mainnet_address = format_btc_mainnet_address(&mainnet_hash160).unwrap();
        let testnet_address = format_btc_testnet_address(&testnet_hash160).unwrap();
        assert!(
            mainnet_address.starts_with("bc1"),
            "adresse mainnet inattendue : {mainnet_address}"
        );
        assert!(
            testnet_address.starts_with("tb1"),
            "adresse testnet inattendue : {testnet_address}"
        );

        // Round trip: each address must only decode with its own network's parser, never
        // with the other one.
        assert_eq!(
            parse_btc_mainnet_address(&mainnet_address).unwrap(),
            mainnet_hash160
        );
        assert_eq!(
            parse_btc_testnet_address(&testnet_address).unwrap(),
            testnet_hash160
        );
        assert!(parse_btc_mainnet_address(&testnet_address).is_err());
        assert!(parse_btc_testnet_address(&mainnet_address).is_err());
    }

    // Checks the shape only (prefix, determinism, derivation path distinct from
    // Bitcoin), not that the address produced is exact: that takes a comparison
    // against a reference THORChain wallet, which this test does not replace.
    #[test]
    fn thor_address_has_the_expected_bech32_shape_and_is_deterministic() {
        let seed = [7u8; 32];
        let (_key, hash160) = derive_thor_key(&seed, 0).unwrap();
        let address = format_thor_address(&hash160).unwrap();
        assert!(
            address.starts_with("thor1"),
            "adresse THOR inattendue : {address}"
        );

        let (_key_again, hash160_again) = derive_thor_key(&seed, 0).unwrap();
        assert_eq!(
            hash160, hash160_again,
            "la dérivation doit être déterministe"
        );

        // Derivation path distinct from Bitcoin (coin_type 931' vs 0'): no reason to
        // produce the same hash160 for the same seed/index.
        let (_btc_key, btc_hash160) = derive_btc_mainnet_key(&seed, 0).unwrap();
        assert_ne!(hash160, btc_hash160);
    }

    /// Vectors from BIP173 / BIP350, plus the case that used to slip through: a 20-byte
    /// version 1 program (bech32m) read as a P2WPKH.
    #[test]
    fn segwit_addresses_follow_bip173_and_bip350() {
        assert_eq!(
            hex::encode(
                btc_mainnet_script_pubkey("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap()
            ),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert_eq!(
            hex::encode(
                btc_mainnet_script_pubkey(
                    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
                )
                .unwrap()
            ),
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(
            hex::encode(
                parse_btc_mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
            ),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );

        let encode = |version: u8, program: &[u8], variant: Variant| {
            let mut data = vec![bech32::u5::try_from_u8(version).unwrap()];
            data.extend(program.to_base32());
            bech32::encode("bc", data, variant).unwrap()
        };
        let taproot_20 = encode(1, &[0x75; 20], Variant::Bech32m);
        assert!(
            parse_btc_mainnet_address(&taproot_20).is_err(),
            "v1 de 20 octets n'est pas une P2WPKH"
        );
        let v0_bech32m = encode(0, &[0x75; 20], Variant::Bech32m);
        assert!(
            parse_btc_mainnet_address(&v0_bech32m).is_err()
                && btc_mainnet_script_pubkey(&v0_bech32m).is_err(),
            "v0 en bech32m"
        );
        let v1_bech32 = encode(1, &[0x79; 32], Variant::Bech32);
        assert!(
            btc_mainnet_script_pubkey(&v1_bech32).is_err(),
            "v1 en bech32"
        );
        assert!(
            btc_mainnet_script_pubkey(&encode(2, &[0x75; 16], Variant::Bech32m)).is_err(),
            "version future refusée"
        );
        assert!(
            btc_mainnet_script_pubkey(&encode(0, &[0x75; 25], Variant::Bech32)).is_err(),
            "v0 : 20 ou 32 octets"
        );
        assert!(
            parse_btc_mainnet_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").is_err(),
            "testnet"
        );
    }

    /// Destination addresses: each standard form gives its script (BIP173/BIP350
    /// vectors; P2PKH = the genesis block address, P2SH = the example from the Bitcoin
    /// documentation), and the script gives the address back.
    #[test]
    fn recipient_addresses_of_every_standard_type_give_their_script() {
        for (address, script) in [
            (
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            ),
            (
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87",
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ] {
            let decoded = btc_mainnet_recipient_script(address).unwrap();
            assert_eq!(hex::encode(&decoded), script, "{address}");
            assert_eq!(
                btc_script_address(&decoded, false).unwrap(),
                address,
                "{address}"
            );
            assert!(
                btc_testnet_recipient_script(address).is_err(),
                "{address} : adresse du réseau principal refusée sur testnet"
            );
        }
        assert_eq!(
            hex::encode(
                btc_mainnet_recipient_script(" BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4 ")
                    .unwrap()
            ),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        let p2wsh = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
        assert_eq!(
            hex::encode(btc_testnet_recipient_script(p2wsh).unwrap()),
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        );
        for script in [
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ] {
            let script = hex::decode(script).unwrap();
            let address = btc_script_address(&script, true).unwrap();
            assert!(
                address.starts_with(['m', 'n', '2']) || address.starts_with("tb1p"),
                "{address}"
            );
            assert_eq!(
                btc_testnet_recipient_script(&address).unwrap(),
                script,
                "{address}"
            );
        }
        assert!(
            btc_script_address(&hex::decode("6a0568656c6c6f").unwrap(), false).is_err(),
            "OP_RETURN"
        );
    }

    /// Refusals explained in plain words: future SegWit version or Taproot of another
    /// size, typo, other network.
    #[test]
    fn rejected_bitcoin_recipients_are_explained_plainly() {
        let message = |address: &str| {
            btc_mainnet_recipient_script(address)
                .unwrap_err()
                .to_string()
        };
        for unsupported in [
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            "BC1SW50QGDZ25J",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        ] {
            assert_eq!(
                message(unsupported),
                BTC_ADDRESS_UNSUPPORTED,
                "{unsupported}"
            );
        }
        for miscopied in [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL",
        ] {
            assert_eq!(message(miscopied), BTC_ADDRESS_MISCOPIED, "{miscopied}");
        }
        assert_eq!(
            message("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"),
            BTC_ADDRESS_OTHER_NETWORK
        );
        assert_eq!(
            btc_testnet_recipient_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
                .unwrap_err()
                .to_string(),
            BTC_ADDRESS_OTHER_NETWORK
        );
        assert!(message("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").contains("non-mainnet"));
        // The wallet's own address: P2WPKH only, unchanged.
        assert!(parse_btc_mainnet_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err());
        assert!(parse_btc_mainnet_address(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        )
        .is_err());
    }
}
