use anyhow::{anyhow, Result};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// Un UTXO (sortie non dépensée) à consommer comme entrée de transaction.
/// `txid` est stocké dans l'ordre "affiché" (big-endian), comme le montrent
/// les explorateurs de blocs ; il est inversé au moment de la sérialisation.
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

/// Transaction Bitcoin P2WPKH toute simple (un ou plusieurs UTXOs d'une même adresse
/// vers un destinataire, avec sortie de monnaie optionnelle). Suffisant pour le test
/// "premier virement testnet" du PoC.
pub struct BtcTx {
    pub inputs: Vec<Utxo>,
    pub to_hash160: [u8; 20],
    pub value_sat: u64,
    pub change_hash160: [u8; 20],
    /// 0 si la monnaie est sous le seuil de poussière (part alors dans les frais).
    pub change_sat: u64,
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn push_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Taille virtuelle (vbytes) approximative d'une transaction P2WPKH pure (pas de
/// script exotique), utilisée pour estimer les frais AVANT de savoir si la
/// transaction aura une sortie de monnaie (l'ordre logique est : estimer les
/// frais → décider s'il reste assez pour une sortie de monnaie → construire la
/// transaction réelle, voir `api::send_btc`). Formule standard, largement utilisée
/// pour ce type de transaction : ~10.5 vbytes de frais fixes (version, locktime,
/// marker/flag segwit, comptes d'entrées/sorties) + ~68 vbytes par entrée P2WPKH
/// (grâce à la remise de poids segwit sur la signature/clé publique en témoin) +
/// ~31 vbytes par sortie P2WPKH.
pub fn estimate_p2wpkh_vsize(num_inputs: usize, num_outputs: usize) -> u64 {
    (10.5 + (num_inputs as f64) * 68.0 + (num_outputs as f64) * 31.0).ceil() as u64
}

fn p2wpkh_script_pubkey(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14]; // OP_0 + push(20)
    s.extend_from_slice(hash160);
    s
}

/// scriptCode utilisé dans le sighash BIP143 pour un input P2WPKH : équivalent
/// au script P2PKH classique (imposé par la spec, même si l'input n'est pas P2PKH).
fn p2wpkh_script_code(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x19, 0x76, 0xa9, 0x14]; // taille + OP_DUP OP_HASH160 push(20)
    s.extend_from_slice(hash160);
    s.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    s
}

impl BtcTx {
    /// Sorties sérialisées SANS le préfixe de compte (varint) : c'est le format attendu
    /// par le sighash BIP143 pour `hashOutputs` (contrairement à la transaction finale,
    /// qui elle a besoin de ce préfixe — voir `sign()`).
    fn outputs_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.value_sat.to_le_bytes());
        let script = p2wpkh_script_pubkey(&self.to_hash160);
        push_varint(&mut buf, script.len() as u64);
        buf.extend_from_slice(&script);

        if self.change_sat > 0 {
            buf.extend_from_slice(&self.change_sat.to_le_bytes());
            let change_script = p2wpkh_script_pubkey(&self.change_hash160);
            push_varint(&mut buf, change_script.len() as u64);
            buf.extend_from_slice(&change_script);
        }
        buf
    }

    fn hash_prevouts(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for u in &self.inputs {
            let mut txid_le = u.txid;
            txid_le.reverse();
            buf.extend_from_slice(&txid_le);
            buf.extend_from_slice(&u.vout.to_le_bytes());
        }
        dsha256(&buf)
    }

    fn hash_sequence(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for _ in &self.inputs {
            buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        dsha256(&buf)
    }

    fn hash_outputs(&self) -> [u8; 32] {
        dsha256(&self.outputs_body())
    }

    /// Sighash BIP143 pour l'input `index`, dont le scriptCode correspond à `input_hash160`.
    fn sighash(&self, index: usize, input_hash160: &[u8; 20]) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&1u32.to_le_bytes()); // version
        preimage.extend_from_slice(&self.hash_prevouts());
        preimage.extend_from_slice(&self.hash_sequence());

        let input = &self.inputs[index];
        let mut txid_le = input.txid;
        txid_le.reverse();
        preimage.extend_from_slice(&txid_le);
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        preimage.extend_from_slice(&p2wpkh_script_code(input_hash160));
        preimage.extend_from_slice(&input.value_sat.to_le_bytes());
        preimage.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence

        preimage.extend_from_slice(&self.hash_outputs());
        preimage.extend_from_slice(&0u32.to_le_bytes()); // locktime
        preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        dsha256(&preimage)
    }

    /// Construit et signe la transaction. Toutes les entrées doivent appartenir à la
    /// même clé (`input_hash160`), ce qui est le cas dans cette démo mono-adresse.
    pub fn sign(&self, key: &SigningKey, input_hash160: &[u8; 20]) -> Result<Vec<u8>> {
        let pubkey_compressed = key.verifying_key().to_encoded_point(true);

        let mut witnesses = Vec::new();
        for i in 0..self.inputs.len() {
            let hash = self.sighash(i, input_hash160);
            let signature: Signature = key
                .sign_prehash(&hash)
                .map_err(|e| anyhow!("échec de signature ECDSA : {e}"))?;
            let signature = signature.normalize_s().unwrap_or(signature);
            let der = signature.to_der();
            let mut sig_with_type = der.as_bytes().to_vec();
            sig_with_type.push(0x01); // SIGHASH_ALL
            witnesses.push((sig_with_type, pubkey_compressed.as_bytes().to_vec()));
        }

        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.push(0x00); // marker segwit
        tx.push(0x01); // flag segwit

        push_varint(&mut tx, self.inputs.len() as u64);
        for u in &self.inputs {
            let mut txid_le = u.txid;
            txid_le.reverse();
            tx.extend_from_slice(&txid_le);
            tx.extend_from_slice(&u.vout.to_le_bytes());
            tx.push(0x00); // scriptSig vide (segwit natif)
            tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        }

        let n_outputs = if self.change_sat > 0 { 2 } else { 1 };
        push_varint(&mut tx, n_outputs);
        tx.extend_from_slice(&self.outputs_body());

        for (sig, pubkey) in &witnesses {
            push_varint(&mut tx, 2); // 2 éléments de témoin : signature + clé publique
            push_varint(&mut tx, sig.len() as u64);
            tx.extend_from_slice(sig);
            push_varint(&mut tx, pubkey.len() as u64);
            tx.extend_from_slice(pubkey);
        }

        tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    /// Référence largement citée pour une transaction P2WPKH 1 entrée / 2 sorties :
    /// ~141-143 vbytes mesurés en pratique. Garde-fou contre une régression de la
    /// formule (ex: overhead ou coût par entrée/sortie modifié par erreur), pas une
    /// preuve d'exactitude à l'octet près — l'estimation reste volontairement
    /// approximative (voir sa documentation).
    #[test]
    fn estimate_p2wpkh_vsize_matches_known_reference_for_one_input_two_outputs() {
        let vsize = estimate_p2wpkh_vsize(1, 2);
        assert!((140..=143).contains(&vsize), "vsize inattendue : {vsize}");
    }

    #[test]
    fn estimate_p2wpkh_vsize_grows_with_more_inputs_and_outputs() {
        let base = estimate_p2wpkh_vsize(1, 1);
        assert!(estimate_p2wpkh_vsize(2, 1) > base);
        assert!(estimate_p2wpkh_vsize(1, 2) > base);
    }

    #[test]
    fn push_varint_boundaries() {
        let cases: [(u64, &[u8]); 4] = [
            (0x00, &[0x00]),
            (0xfc, &[0xfc]),
            (0xfd, &[0xfd, 0xfd, 0x00]),
            (0x10000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
        ];
        for (value, expected) in cases {
            let mut buf = Vec::new();
            push_varint(&mut buf, value);
            assert_eq!(buf, expected, "varint pour {value}");
        }
    }

    /// Garde-fou direct contre le bug déjà rencontré : `outputs_body` (utilisé pour
    /// `hashOutputs` dans le sighash BIP143) ne doit JAMAIS commencer par un octet
    /// de compte de sorties — seulement par la valeur (8 octets little-endian) de
    /// la première sortie. C'est exactement l'inversion qui causait des signatures
    /// invalides précédemment.
    #[test]
    fn outputs_body_never_starts_with_a_count_byte() {
        let hash160 = [0x33u8; 20];
        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0u8; 32], vout: 0, value_sat: 10_000 }],
            to_hash160: [0x44u8; 20],
            value_sat: 9_000,
            change_hash160: hash160,
            change_sat: 0,
        };
        let body = tx.outputs_body();
        assert_eq!(&body[0..8], &tx.value_sat.to_le_bytes());
        // Une seule sortie ici : 8 (valeur) + 1 (longueur script) + 22 (script P2WPKH).
        assert_eq!(body.len(), 8 + 1 + 22);
    }

    #[test]
    fn outputs_body_includes_change_when_above_dust() {
        let hash160 = [0x11u8; 20];
        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0xAAu8; 32], vout: 0, value_sat: 100_000 }],
            to_hash160: [0x22u8; 20],
            value_sat: 50_000,
            change_hash160: hash160,
            change_sat: 49_000,
        };
        let body = tx.outputs_body();
        // Deux sorties : 2 * (8 + 1 + 22) = 62 octets.
        assert_eq!(body.len(), 2 * (8 + 1 + 22));
    }

    /// Test de non-régression : le sighash BIP143 recalculé de façon indépendante
    /// doit être exactement celui contre lequel la signature produite par `sign()`
    /// est valide — aurait détecté le bug précédent (hashOutputs mal construit).
    #[test]
    fn signature_verifies_against_recomputed_sighash() {
        let key = SigningKey::from_slice(&[9u8; 32]).expect("clé de test valide");
        let hash160 = [0x11u8; 20];

        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0xAAu8; 32], vout: 0, value_sat: 100_000 }],
            to_hash160: [0x22u8; 20],
            value_sat: 50_000,
            change_hash160: hash160,
            change_sat: 49_000,
        };

        // sign() doit réussir (valide la mécanique complète : construction, signature, sérialisation).
        let raw = tx.sign(&key, &hash160).expect("signature réussie");
        assert_eq!(&raw[4..6], &[0x00, 0x01], "marker + flag segwit attendus");

        let expected_hash = tx.sighash(0, &hash160);
        let verifying_key = VerifyingKey::from(&key);
        let signature: Signature = key.sign_prehash(&expected_hash).expect("signature de contrôle");
        verifying_key
            .verify_prehash(&expected_hash, &signature)
            .expect("la signature doit vérifier contre le sighash BIP143 recalculé");
    }
}
