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
        s.append(&Vec::<u8>::new()); // champ "data", vide pour un simple transfert

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
}
