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

/// Dérive une clé privée à partir de la seed maîtresse (BIP32) et d'un chemin de dérivation.
///
/// ATTENTION : ceci contourne volontairement Shamir/PGP pour l'expérimentation
/// `wallet_demo`. Dans le flux normal du projet, la seed ne doit jamais exister
/// en clair hors de la reconstruction à partir des parts déchiffrées.
fn derive_key_from_path(seed: &[u8], path: &str) -> Result<SigningKey> {
    let root = XPrv::new(seed).context("dérivation BIP32 racine impossible")?;
    let path: DerivationPath = path.parse().context("chemin de dérivation invalide")?;

    let mut child = root;
    for c in path.iter() {
        child = child.derive_child(c).context("échec de dérivation d'un segment")?;
    }

    Ok(child.private_key().clone())
}

/// Dérive la clé privée EVM n°`index` (chemin m/44'/60'/0'/0/{index})
/// et retourne aussi l'adresse EVM correspondante (20 octets).
pub fn derive_evm_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/60'/0'/0/{index}"))?;
    let address = evm_address_from_key(&signing_key);
    Ok((signing_key, address))
}

/// Dérive la clé privée Bitcoin testnet n°`index` (chemin m/44'/1'/0'/0/{index},
/// coin_type 1' = testnet) et retourne le hash160 (RIPEMD160(SHA256(pubkey compressée)))
/// utilisé pour construire l'adresse P2WPKH.
pub fn derive_btc_testnet_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/1'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Dérive la clé privée Bitcoin MAINNET n°`index` (chemin m/44'/0'/0'/0/{index},
/// coin_type 0' = Bitcoin mainnet — chemin distinct du testnet, donc adresse
/// distincte pour un même index : jamais interchangeables, contrairement à
/// EVM/Solana où la même adresse sert sur toutes les variantes du réseau).
pub fn derive_btc_mainnet_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/0'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Calcule l'adresse EVM (20 derniers octets du Keccak256 de la clé publique non compressée,
/// préfixe 0x04 exclu).
pub fn evm_address_from_key(signing_key: &SigningKey) -> [u8; 20] {
    let verifying_key = signing_key.verifying_key();
    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // on retire le préfixe 0x04

    let hash = Keccak256::digest(pubkey_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Applique la casse de contrôle EIP-55 à une adresse EVM déjà en hexadécimal minuscule :
/// la casse de chaque lettre encode un checksum de l'adresse elle-même (Keccak256), sans
/// changer sa valeur. Sert à la fois à l'affichage (`format_address`) et à la validation
/// d'une adresse saisie par l'utilisateur (`wallet_flow::parse_evm_address`).
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

/// Adresse EVM au format EIP-55 (casse de contrôle) : une seule lettre mal recopiée
/// change la casse attendue à cet endroit, ce qui permet à `parse_evm_address` de
/// détecter une faute de frappe qui resterait sinon invisible (hex par ailleurs valide).
pub fn format_address(address: &[u8; 20]) -> String {
    format!("0x{}", eip55_checksum(&hex::encode(address)))
}

/// hash160 = RIPEMD160(SHA256(clé publique compressée)), tel qu'utilisé par Bitcoin
/// pour construire une adresse P2WPKH.
/// Dérive la clé Zcash transparente n°`index` (chemin BIP44
/// m/44'/133'/0'/0/{index}, coin_type 133' = Zcash dans SLIP-0044 — même chemin
/// que Ledger et les portefeuilles Zcash pour les adresses transparentes) et
/// retourne le hash160 de la clé publique compressée (adresse P2PKH t1…, voir
/// `zcash::p2pkh_address`).
pub fn derive_zec_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/133'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Dérive la clé Dogecoin n°`index` (chemin BIP44 m/44'/3'/0'/0/{index},
/// coin_type 3' = Dogecoin dans SLIP-0044 — celui de Ledger, Trezor et
/// Dogecoin Core) et retourne le hash160 de la clé publique compressée
/// (adresse P2PKH D…, voir `doge::p2pkh_address`).
pub fn derive_doge_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/3'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

fn btc_hash160_from_key(signing_key: &SigningKey) -> [u8; 20] {
    let compressed = signing_key.verifying_key().to_encoded_point(true);
    let sha256 = Sha256::digest(compressed.as_bytes());
    let ripemd = Ripemd160::digest(sha256);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

/// Formatte une adresse Bitcoin testnet P2WPKH (bech32, préfixe "tb1q...").
pub fn format_btc_testnet_address(hash160: &[u8; 20]) -> Result<String> {
    let mut data = vec![bech32::u5::try_from_u8(0).unwrap()]; // version témoin 0 (P2WPKH)
    data.extend(hash160.to_base32());
    bech32::encode("tb", data, Variant::Bech32).context("encodage bech32 impossible")
}

/// Formatte une adresse Bitcoin MAINNET P2WPKH (bech32, préfixe "bc1q...").
pub fn format_btc_mainnet_address(hash160: &[u8; 20]) -> Result<String> {
    let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
    data.extend(hash160.to_base32());
    bech32::encode("bc", data, Variant::Bech32).context("encodage bech32 impossible")
}

/// Dérive la clé privée THORChain n°`index` (chemin m/44'/931'/0'/0/{index},
/// coin_type 931' — enregistré officiellement pour RUNE dans SLIP-0044) et
/// retourne le hash160 correspondant. Même courbe (secp256k1) et même calcul
/// de hash160 que Bitcoin : THORChain, comme les autres chaînes Cosmos SDK,
/// réutilise exactement RIPEMD160(SHA256(clé publique compressée)) pour
/// dériver son adresse. Utilisée uniquement pour recevoir les frais
/// d'affiliation d'un swap (voir api::swap_quote) — jamais pour envoyer,
/// aucune construction de transaction RUNE dans cette v1.
pub fn derive_thor_key(seed: &[u8], index: u32) -> Result<(SigningKey, [u8; 20])> {
    let signing_key = derive_key_from_path(seed, &format!("m/44'/931'/0'/0/{index}"))?;
    let hash160 = btc_hash160_from_key(&signing_key);
    Ok((signing_key, hash160))
}

/// Clé de base Monero n°`index` : clé BIP32 secp256k1 du chemin
/// m/44'/128'/{index}'/0/0 — même chemin et même usage que l'app Monero de
/// Ledger (`monero_init_private_key`) ; la clé de dépense en est tirée par
/// keccak (voir `monero::spend_key`).
pub fn derive_monero_base_key(seed: &[u8], index: u32) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let key = derive_key_from_path(seed, &format!("m/44'/128'/{index}'/0/0"))?;
    Ok(zeroize::Zeroizing::new(key.to_bytes().into()))
}

/// Formatte une adresse THORChain (bech32, préfixe "thor1...") — comme
/// Bitcoin mais SANS octet de version témoin (pas de SegWit sur Cosmos SDK) :
/// le hash160 est encodé directement.
pub fn format_thor_address(hash160: &[u8; 20]) -> Result<String> {
    bech32::encode("thor", hash160.to_base32(), Variant::Bech32).context("encodage bech32 impossible")
}

/// Dérivation SLIP-0010 pour ed25519 : contrairement à BIP32/secp256k1, la dérivation
/// non-durcie n'existe pas sur cette courbe (pas d'arithmétique de point publique
/// exploitable), donc TOUS les niveaux du chemin sont durcis (indices "'").
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

fn slip10_ed25519_child(parent_key: &[u8; 32], parent_chain_code: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let hardened_index = index | 0x8000_0000; // force le durcissement, quel que soit l'appelant
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

/// Clé ed25519 SLIP-10 pour un chemin quelconque, entièrement durci (indices
/// donnés sans le bit de durcissement, SLIP-10 n'admettant que des dérivations
/// durcies sur ed25519). Tests seulement : recouper les clés renvoyées par un
/// Ledger (chemin Ledger Live m/44'/501'/i') avec une dérivation indépendante.
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

/// Dérive la clé Solana n°`account_index` (chemin m/44'/501'/{account_index}'/0',
/// convention utilisée par la plupart des wallets Solana) à partir de la seed maîtresse.
pub fn derive_solana_key(seed: &[u8], account_index: u32) -> ed25519_dalek::SigningKey {
    let (mut key, mut chain_code) = slip10_ed25519_master(seed);
    for index in [44u32, 501, account_index, 0] {
        let (k, cc) = slip10_ed25519_child(&key, &chain_code, index);
        key = k;
        chain_code = cc;
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key);
    // `ed25519_dalek::SigningKey::from_bytes` copie `key` en interne (et s'efface
    // elle-même à sa destruction) ; on efface aussi cette copie locale, qui sinon
    // resterait en clair dans la pile de cette fonction sans raison.
    key.zeroize();
    chain_code.zeroize();
    signing_key
}

/// Décode une adresse Bitcoin testnet P2WPKH (bech32) en hash160 (20 octets).
pub fn parse_btc_testnet_address(address: &str) -> Result<[u8; 20]> {
    p2wpkh_hash160(decode_segwit(address, "tb", "testnet")?)
}

/// Décode une adresse Bitcoin MAINNET P2WPKH (bech32) en hash160 (20 octets).
pub fn parse_btc_mainnet_address(address: &str) -> Result<[u8; 20]> {
    p2wpkh_hash160(decode_segwit(address, "bc", "mainnet")?)
}

/// Script de sortie (scriptPubKey) d'une adresse Bitcoin MAINNET SegWit
/// quelconque : v0 (bc1q…, P2WPKH ou P2WSH) ou v1 (bc1p…, Taproot) —
/// l'adresse de dépôt d'un pont, que l'app paie sans la détenir.
pub fn btc_mainnet_script_pubkey(address: &str) -> Result<Vec<u8>> {
    let (version, program) = decode_segwit(address, "bc", "mainnet")?;
    anyhow::ensure!(version <= 1, "adresse Bitcoin d'une version SegWit future (v{version}) — refusée");
    // OP_0, ou OP_1 (0x51) ; puis le programme poussé tel quel.
    let mut script = vec![if version == 0 { 0x00 } else { 0x51 }, program.len() as u8];
    script.extend_from_slice(&program);
    Ok(script)
}

/// Version témoin et programme d'une adresse SegWit (BIP173 / BIP350), avec
/// les règles que le décodage bech32 seul ne vérifie pas : encodage bech32
/// pour la version 0 et bech32m au-delà, tailles de programme valides. Sans
/// elles, une adresse Taproot de 20 octets (v1, bech32m) passait pour une
/// P2WPKH — le paiement partait vers un autre script que celui saisi.
fn decode_segwit(address: &str, expected_hrp: &str, network: &str) -> Result<(u8, Vec<u8>)> {
    let (hrp, data, variant) = bech32::decode(address).context("adresse bech32 invalide")?;
    if hrp != expected_hrp {
        return Err(anyhow!("adresse non-{network} (préfixe '{expected_hrp}' attendu, trouvé '{hrp}')"));
    }
    let (version, program) = data.split_first().ok_or_else(|| anyhow!("adresse bech32 vide"))?;
    let version = version.to_u8();
    let program = Vec::<u8>::from_base32(program).context("conversion base32 -> octets impossible")?;
    let expected_variant = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
    anyhow::ensure!(
        version <= 16 && variant == expected_variant && (2..=40).contains(&program.len()) && (version != 0 || matches!(program.len(), 20 | 32)),
        "adresse Bitcoin mal formée (version SegWit, encodage ou longueur incohérents)"
    );
    Ok((version, program))
}

fn p2wpkh_hash160((version, program): (u8, Vec<u8>)) -> Result<[u8; 20]> {
    anyhow::ensure!(version == 0, "programme témoin de taille inattendue (P2WPKH attend 20 octets)");
    program
        .try_into()
        .map_err(|_| anyhow!("programme témoin de taille inattendue (P2WPKH attend 20 octets)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vecteurs de test officiels de l'EIP-55 : https://eips.ethereum.org/EIPS/eip-55
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

    // Garde-fou volontairement redondant : mainnet et testnet Bitcoin dérivent des
    // adresses DIFFÉRENTES pour le même index (contrairement à EVM/Solana), donc une
    // régression ici enverrait silencieusement des fonds réels vers une adresse
    // testnet inutilisable, ou l'inverse.
    #[test]
    fn btc_mainnet_and_testnet_derive_different_addresses_for_the_same_seed_and_index() {
        let seed = [7u8; 32];
        let (_mainnet_key, mainnet_hash160) = derive_btc_mainnet_key(&seed, 0).unwrap();
        let (_testnet_key, testnet_hash160) = derive_btc_testnet_key(&seed, 0).unwrap();

        // Chemins de dérivation différents (coin_type 0' vs 1') : même hash160 non
        // garanti, et en pratique different ici avec cette seed.
        assert_ne!(mainnet_hash160, testnet_hash160);

        let mainnet_address = format_btc_mainnet_address(&mainnet_hash160).unwrap();
        let testnet_address = format_btc_testnet_address(&testnet_hash160).unwrap();
        assert!(mainnet_address.starts_with("bc1"), "adresse mainnet inattendue : {mainnet_address}");
        assert!(testnet_address.starts_with("tb1"), "adresse testnet inattendue : {testnet_address}");

        // Round-trip : chaque adresse ne doit se décoder qu'avec le parseur de son
        // propre réseau, jamais avec celui de l'autre.
        assert_eq!(parse_btc_mainnet_address(&mainnet_address).unwrap(), mainnet_hash160);
        assert_eq!(parse_btc_testnet_address(&testnet_address).unwrap(), testnet_hash160);
        assert!(parse_btc_mainnet_address(&testnet_address).is_err());
        assert!(parse_btc_testnet_address(&mainnet_address).is_err());
    }

    // Ne remplace PAS la vérification empirique obligatoire contre un
    // portefeuille THORChain de référence avant tout usage réel (voir le plan
    // de la fonctionnalité swap) : garantit seulement la forme (préfixe,
    // déterminisme, chemin de dérivation distinct de Bitcoin), pas
    // l'exactitude de l'adresse produite.
    #[test]
    fn thor_address_has_the_expected_bech32_shape_and_is_deterministic() {
        let seed = [7u8; 32];
        let (_key, hash160) = derive_thor_key(&seed, 0).unwrap();
        let address = format_thor_address(&hash160).unwrap();
        assert!(address.starts_with("thor1"), "adresse THOR inattendue : {address}");

        let (_key_again, hash160_again) = derive_thor_key(&seed, 0).unwrap();
        assert_eq!(hash160, hash160_again, "la dérivation doit être déterministe");

        // Chemin de dérivation distinct de Bitcoin (coin_type 931' vs 0') :
        // aucune raison de produire le même hash160 pour la même seed/index.
        let (_btc_key, btc_hash160) = derive_btc_mainnet_key(&seed, 0).unwrap();
        assert_ne!(hash160, btc_hash160);
    }

    /// Vecteurs de BIP173 / BIP350, et le cas qui passait avant : un programme
    /// de 20 octets en version 1 (bech32m) lu comme une P2WPKH.
    #[test]
    fn segwit_addresses_follow_bip173_and_bip350() {
        assert_eq!(
            hex::encode(btc_mainnet_script_pubkey("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap()),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert_eq!(
            hex::encode(btc_mainnet_script_pubkey("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap()),
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(hex::encode(parse_btc_mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()), "751e76e8199196d454941c45d1b3a323f1433bd6");

        let encode = |version: u8, program: &[u8], variant: Variant| {
            let mut data = vec![bech32::u5::try_from_u8(version).unwrap()];
            data.extend(program.to_base32());
            bech32::encode("bc", data, variant).unwrap()
        };
        let taproot_20 = encode(1, &[0x75; 20], Variant::Bech32m);
        assert!(parse_btc_mainnet_address(&taproot_20).is_err(), "v1 de 20 octets n'est pas une P2WPKH");
        let v0_bech32m = encode(0, &[0x75; 20], Variant::Bech32m);
        assert!(parse_btc_mainnet_address(&v0_bech32m).is_err() && btc_mainnet_script_pubkey(&v0_bech32m).is_err(), "v0 en bech32m");
        let v1_bech32 = encode(1, &[0x79; 32], Variant::Bech32);
        assert!(btc_mainnet_script_pubkey(&v1_bech32).is_err(), "v1 en bech32");
        assert!(btc_mainnet_script_pubkey(&encode(2, &[0x75; 16], Variant::Bech32m)).is_err(), "version future refusée");
        assert!(btc_mainnet_script_pubkey(&encode(0, &[0x75; 25], Variant::Bech32)).is_err(), "v0 : 20 ou 32 octets");
        assert!(parse_btc_mainnet_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").is_err(), "testnet");
    }
}
