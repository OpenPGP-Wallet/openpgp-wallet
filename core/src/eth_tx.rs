use anyhow::{anyhow, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

/// Transaction Ethereum "legacy" (pas EIP-1559) toute simple : un transfert d'ETH
/// sans données ni contrat. Suffisant pour le test "premier virement" du PoC.
pub struct EthTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub chain_id: u64,
    /// Calldata d'appel de contrat. Vide pour un simple transfert (comportement
    /// strictement identique à avant cet ajout). Non-vide pour un swap
    /// THORChain (`thorchain_deposit_calldata`) — `gas_limit` doit alors venir
    /// d'une estimation réelle de l'exécution (`EthRpc::estimate_gas`), jamais
    /// de `intrinsic_gas` seul : ce dernier n'est que le minimum pour SOUMETTRE
    /// la transaction (mesuré : 23 844 contre 45 632 réellement consommés par
    /// un dépôt sur le routeur THORChain).
    pub data: Vec<u8>,
}

/// Encode un entier en RLP "big-endian minimal" (zéros de tête retirés, 0 -> chaîne vide),
/// comme l'exigent les champs entiers d'une transaction Ethereum.
fn trim_be(bytes: &[u8]) -> Vec<u8> {
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(i) => bytes[i..].to_vec(),
        None => Vec::new(),
    }
}

impl EthTx {
    fn encode(&self, v: Option<(u64, &[u8], &[u8])>) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.begin_list(9);
        s.append(&trim_be(&self.nonce.to_be_bytes()));
        s.append(&trim_be(&self.gas_price.to_be_bytes()));
        s.append(&trim_be(&self.gas_limit.to_be_bytes()));
        s.append(&self.to.as_slice());
        s.append(&trim_be(&self.value.to_be_bytes()));
        s.append(&self.data);

        match v {
            None => {
                // Tuple EIP-155 sur la tx non signée : (chain_id, 0, 0)
                s.append(&trim_be(&self.chain_id.to_be_bytes()));
                s.append(&Vec::<u8>::new());
                s.append(&Vec::<u8>::new());
            }
            Some((v, r, sig_s)) => {
                s.append(&trim_be(&v.to_be_bytes()));
                s.append(&r);
                s.append(&sig_s);
            }
        }
        s.out().to_vec()
    }

    fn hash_unsigned(&self) -> [u8; 32] {
        let unsigned = self.encode(None);
        let digest = Keccak256::digest(&unsigned);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Signe la transaction avec la clé privée dérivée et renvoie la transaction
    /// RLP-encodée, prête à être envoyée via `eth_sendRawTransaction`.
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        let hash = self.hash_unsigned();

        let (signature, recid): (Signature, RecoveryId) = key
            .sign_prehash(&hash)
            .map_err(|e| anyhow!("échec de signature ECDSA : {e}"))?;

        let r = signature.r().to_bytes();
        let s_val = signature.s().to_bytes();
        let v = self.chain_id * 2 + 35 + u64::from(recid.to_byte());

        Ok(self.encode(Some((v, trim_be(&r).as_slice(), trim_be(&s_val).as_slice()))))
    }
}

/// Gas intrinsèque réel d'une transaction (règle post-EIP-2028, en vigueur
/// depuis Istanbul) : 21 000 de base + 16 par octet non-nul de calldata + 4 par
/// octet nul. Un simple transfert (`data` vide) redonne exactement 21 000,
/// donc aucune régression sur le chemin d'envoi existant. Ce n'est qu'un
/// PLANCHER (le minimum pour soumettre la transaction) : pour un appel de
/// contrat, l'exécution consomme bien davantage — voir `EthTx::data`.
pub fn intrinsic_gas(data: &[u8]) -> u64 {
    const BASE: u64 = 21_000;
    let (zero, nonzero) = data.iter().fold((0u64, 0u64), |(zero, nonzero), &b| {
        if b == 0 { (zero + 1, nonzero) } else { (zero, nonzero + 1) }
    });
    BASE + zero * 4 + nonzero * 16
}

fn pad_left_32(bytes: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    buf
}

/// Encode l'appel `depositWithExpiry(address vault, address asset, uint256
/// amount, string memo, uint256 expiration)` du contrat "THORChain Router",
/// tel qu'exigé pour un swap THORChain depuis une chaîne EVM (voir
/// `thorchain_rpc` pour le contexte : `vault` = `SwapQuote::inbound_address`,
/// et l'appel doit cibler `SwapQuote::router`, jamais `inbound_address`
/// directement). Sélecteur (`0x44bc937b`) vérifié en direct contre la base
/// publique 4byte.directory, jamais recalculé "à l'oeil". Suit l'encodage ABI
/// Solidity standard : les 3 premiers paramètres statiques sont encodés en
/// place, `memo` (seul type dynamique) est remplacé dans la tête par un
/// décalage vers la queue, `expiration` reste statique après ce décalage —
/// voir le test `thorchain_deposit_calldata_matches_a_hand_computed_reference`
/// pour une vérification octet par octet contre la spec.
pub fn thorchain_deposit_calldata(vault: &[u8; 20], asset: &[u8; 20], amount: u128, memo: &str, expiration: u64) -> Vec<u8> {
    const SELECTOR: [u8; 4] = [0x44, 0xbc, 0x93, 0x7b];
    const HEAD_SLOTS: u128 = 5; // vault, asset, amount, offset(memo), expiration

    let memo_bytes = memo.as_bytes();
    let mut data = Vec::with_capacity(4 + 32 * 5 + 32 + memo_bytes.len().div_ceil(32) * 32);
    data.extend_from_slice(&SELECTOR);

    data.extend_from_slice(&pad_left_32(vault));
    data.extend_from_slice(&pad_left_32(asset));
    data.extend_from_slice(&pad_left_32(&amount.to_be_bytes()));
    data.extend_from_slice(&pad_left_32(&(HEAD_SLOTS * 32).to_be_bytes())); // offset du memo
    data.extend_from_slice(&pad_left_32(&(expiration as u128).to_be_bytes()));

    data.extend_from_slice(&pad_left_32(&(memo_bytes.len() as u128).to_be_bytes()));
    data.extend_from_slice(memo_bytes);
    let padding = (32 - memo_bytes.len() % 32) % 32;
    data.extend(std::iter::repeat(0u8).take(padding));

    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    #[test]
    fn trim_be_removes_leading_zeros() {
        assert_eq!(trim_be(&[0, 0, 1, 2]), vec![1, 2]);
        assert_eq!(trim_be(&[0, 0, 0, 0]), Vec::<u8>::new());
        assert_eq!(trim_be(&[5, 6]), vec![5, 6]);
        assert_eq!(trim_be(&[1]), vec![1]);
    }

    /// Ethereum exige une signature "low-S" depuis Homestead (EIP-2) : une
    /// signature "high-S" est rejetée par le réseau ET permet une seconde
    /// signature valide pour le même message (malléabilité, `s' = n - s`).
    /// `sign()` n'appelle jamais `normalize_s()` explicitement (contrairement à
    /// `btc_tx.rs::sign()`, qui le fait) — ce test vérifie empiriquement que
    /// `k256::ecdsa::SigningKey::sign_prehash` produit déjà toujours une
    /// signature normalisée par elle-même, sur un grand nombre de hachages
    /// distincts, plutôt que de le supposer sans le vérifier.
    #[test]
    fn signatures_are_always_low_s_without_explicit_normalization() {
        let key = SigningKey::from_slice(&[3u8; 32]).expect("clé de test valide");
        for i in 0..2000u32 {
            let hash = Keccak256::digest(i.to_be_bytes());
            let (signature, _recid): (Signature, RecoveryId) =
                key.sign_prehash(&hash).expect("signature réussie");
            assert!(
                signature.normalize_s().is_none(),
                "signature high-S produite pour i={i} : normalize_s() n'aurait jamais dû être nécessaire"
            );
        }
    }

    /// Test de non-régression : signe une transaction, la redécode en RLP et
    /// vérifie que la signature (r, s) correspond bien au hash non-signé recalculé
    /// avec la clé publique correspondante. Aurait détecté le type de bug déjà
    /// rencontré côté Bitcoin (hashOutputs mal construit) s'il existait ici.
    #[test]
    fn signed_tx_round_trips_and_signature_verifies() {
        let key = SigningKey::from_slice(&[7u8; 32]).expect("clé de test valide");
        let tx = EthTx {
            nonce: 3,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: [0xABu8; 20],
            value: 1_000_000_000_000_000_000, // 1 ETH
            chain_id: 11155111,                // Sepolia
            data: Vec::new(),
        };

        let raw = tx.sign(&key).expect("signature réussie");
        let rlp = rlp::Rlp::new(&raw);
        assert_eq!(rlp.item_count().unwrap(), 9);

        let nonce: u64 = rlp.val_at(0).unwrap();
        assert_eq!(nonce, tx.nonce);
        let to: Vec<u8> = rlp.val_at(3).unwrap();
        assert_eq!(to, tx.to.to_vec());
        let value_bytes: Vec<u8> = rlp.val_at(4).unwrap();
        assert_eq!(value_bytes, trim_be(&tx.value.to_be_bytes()));

        let sig_v: u64 = rlp.val_at(6).unwrap();
        let sig_r: Vec<u8> = rlp.val_at(7).unwrap();
        let sig_s: Vec<u8> = rlp.val_at(8).unwrap();

        // v = chain_id*2 + 35 + recid ; recid ne peut être que 0 ou 1.
        let expected_base = tx.chain_id * 2 + 35;
        assert!(sig_v == expected_base || sig_v == expected_base + 1);

        let mut r_padded = [0u8; 32];
        r_padded[32 - sig_r.len()..].copy_from_slice(&sig_r);
        let mut s_padded = [0u8; 32];
        s_padded[32 - sig_s.len()..].copy_from_slice(&sig_s);
        let signature = Signature::from_scalars(r_padded, s_padded).expect("signature reconstructible");

        let verifying_key = VerifyingKey::from(&key);
        let hash = tx.hash_unsigned();
        verifying_key
            .verify_prehash(&hash, &signature)
            .expect("la signature doit vérifier contre la clé publique et le hash non-signé");
    }

    #[test]
    fn intrinsic_gas_matches_the_base_cost_for_an_empty_payload() {
        // Un simple transfert (data vide) doit redonner exactement 21 000 :
        // aucune régression sur le chemin d'envoi existant, qui codait cette
        // valeur en dur avant cet ajout.
        assert_eq!(intrinsic_gas(&[]), 21_000);
    }

    #[test]
    fn intrinsic_gas_counts_zero_and_nonzero_bytes_at_their_real_eip2028_cost() {
        let data = [0x00, 0x00, 0xFF, 0x01]; // 2 octets nuls, 2 non-nuls
        assert_eq!(intrinsic_gas(&data), 21_000 + 2 * 4 + 2 * 16);
    }

    /// Vérifie l'encodage `thorchain_deposit_calldata` octet par octet contre
    /// la spec ABI Solidity, recalculée à la main ici (pas seulement "ça
    /// compile") : sélecteur, 3 champs statiques en place, décalage vers le
    /// memo (seul type dynamique), puis longueur + contenu + padding du memo
    /// dans la queue. Le sélecteur `0x44bc937b` a été vérifié en direct contre
    /// 4byte.directory avant d'être inscrit dans le code (jamais recalculé
    /// "à l'oeil").
    #[test]
    fn thorchain_deposit_calldata_matches_a_hand_computed_reference() {
        let vault = [0x11u8; 20];
        let asset = [0x22u8; 20];
        let amount: u128 = 1000;
        let memo = "AB";
        let expiration: u64 = 5;

        let calldata = thorchain_deposit_calldata(&vault, &asset, amount, memo, expiration);

        // 4 (sélecteur) + 5*32 (tête) + 32 (longueur memo) + 32 (memo paddé à 32) = 228.
        assert_eq!(calldata.len(), 228);

        assert_eq!(&calldata[0..4], &[0x44, 0xbc, 0x93, 0x7b]);

        // vault : 12 octets nuls puis l'adresse (20 octets), alignée à droite.
        assert_eq!(&calldata[4..16], &[0u8; 12]);
        assert_eq!(&calldata[16..36], &vault);

        // asset : même schéma.
        assert_eq!(&calldata[36..48], &[0u8; 12]);
        assert_eq!(&calldata[48..68], &asset);

        // amount : uint256 big-endian, valeur 1000 dans les derniers octets.
        assert_eq!(&calldata[68..98], &[0u8; 30]);
        assert_eq!(&calldata[98..100], &[0x03, 0xe8]); // 1000

        // offset du memo : 5 slots de tête * 32 = 160 = 0xa0.
        assert_eq!(&calldata[100..131], &[0u8; 31]);
        assert_eq!(calldata[131], 0xa0);

        // expiration : uint256 big-endian, valeur 5.
        assert_eq!(&calldata[132..163], &[0u8; 31]);
        assert_eq!(calldata[163], 5);

        // longueur du memo ("AB" = 2 octets) puis contenu et padding.
        assert_eq!(&calldata[164..195], &[0u8; 31]);
        assert_eq!(calldata[195], 2);
        assert_eq!(&calldata[196..198], b"AB");
        assert_eq!(&calldata[198..228], &[0u8; 30], "padding du memo jusqu'à 32 octets");
    }
}
