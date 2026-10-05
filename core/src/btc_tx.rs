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
    /// Sortie OP_RETURN optionnelle (valeur 0, non dépensable), utilisée pour
    /// transmettre un memo (ex : memo de swap THORChain). `None` = comportement
    /// strictement identique à avant cet ajout (aucune régression sur l'envoi normal).
    pub op_return_data: Option<Vec<u8>>,
}

pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

pub(crate) fn push_varint(buf: &mut Vec<u8>, n: u64) {
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
/// Identifiant (txid, ordre affiché) d'une transaction sérialisée : double
/// SHA-256 de sa forme SANS témoins (segwit : marqueur, drapeau et témoins
/// retirés). `None` si la sérialisation est illisible.
pub fn txid(raw: &[u8]) -> Option<String> {
    fn varint(raw: &[u8], pos: &mut usize) -> Option<usize> {
        let first = *raw.get(*pos)?;
        let (value, len) = match first {
            0xfd => (u64::from(u16::from_le_bytes(raw.get(*pos + 1..*pos + 3)?.try_into().ok()?)), 3),
            0xfe => (u64::from(u32::from_le_bytes(raw.get(*pos + 1..*pos + 5)?.try_into().ok()?)), 5),
            0xff => (u64::from_le_bytes(raw.get(*pos + 1..*pos + 9)?.try_into().ok()?), 9),
            n => (u64::from(n), 1),
        };
        *pos += len;
        usize::try_from(value).ok()
    }
    let legacy;
    let body: &[u8] = if raw.get(4) == Some(&0) && raw.get(5) == Some(&1) {
        let mut pos = 6;
        for _ in 0..varint(raw, &mut pos)? {
            pos = pos.checked_add(36)?;
            let script = varint(raw, &mut pos)?;
            pos = pos.checked_add(script)?.checked_add(4)?;
        }
        for _ in 0..varint(raw, &mut pos)? {
            pos = pos.checked_add(8)?;
            let script = varint(raw, &mut pos)?;
            pos = pos.checked_add(script)?;
        }
        if raw.len() < pos.checked_add(4)? {
            return None;
        }
        legacy = [&raw[..4], &raw[6..pos], &raw[raw.len() - 4..]].concat();
        &legacy
    } else {
        raw
    };
    let mut hash = dsha256(body);
    hash.reverse();
    Some(hex::encode(hash))
}

pub fn estimate_p2wpkh_vsize(num_inputs: usize, num_outputs: usize) -> u64 {
    (10.5 + (num_inputs as f64) * 68.0 + (num_outputs as f64) * 31.0).ceil() as u64
}

pub(crate) fn p2wpkh_script_pubkey(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14]; // OP_0 + push(20)
    s.extend_from_slice(hash160);
    s
}

/// scriptPubKey OP_RETURN portant `data` en clair (non dépensable, sert
/// uniquement à ancrer des métadonnées, ex : memo de swap). Limité en pratique
/// à ~80 octets par la politique de relais standard du réseau Bitcoin.
fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut s = vec![0x6a]; // OP_RETURN
    if data.len() <= 75 {
        s.push(data.len() as u8); // push direct
    } else {
        s.push(0x4c); // OP_PUSHDATA1
        s.push(data.len() as u8);
    }
    s.extend_from_slice(data);
    s
}

/// Taille (octets, = vbytes : aucune partie témoin) d'une sortie OP_RETURN
/// portant `len` octets : valeur, longueur du script, script.
pub fn op_return_output_size(len: usize) -> u64 {
    let script = 1 + if len <= 75 { 1 } else { 2 } + len as u64;
    8 + varint_len(script) + script
}

/// scriptCode utilisé dans le sighash BIP143 pour un input P2WPKH : équivalent
/// au script P2PKH classique (imposé par la spec, même si l'input n'est pas P2PKH).
fn p2wpkh_script_code(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x19, 0x76, 0xa9, 0x14]; // taille + OP_DUP OP_HASH160 push(20)
    s.extend_from_slice(hash160);
    s.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    s
}

/// Entrée P2WPKH d'une transaction quelconque (voir `RawTx`).
#[derive(Debug)]
pub struct RawInput {
    /// Ordre "affiché" (big-endian), comme `Utxo::txid`.
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
    /// Montant de la sortie dépensée, engagé par la signature (BIP143).
    pub value_sat: u64,
}

/// Transaction dont toutes les entrées sont des P2WPKH d'une même clé, avec
/// des sorties quelconques (valeur, script) : celle que l'app construit
/// (`BtcTx`), ou celle d'une PSBT fournie par un tiers (LI.FI), relue et
/// re-sérialisée ici avant signature.
#[derive(Debug)]
pub struct RawTx {
    pub version: u32,
    pub inputs: Vec<RawInput>,
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub locktime: u32,
}

impl RawTx {
    /// Sorties sérialisées SANS le préfixe de compte (varint) : c'est le format attendu
    /// par le sighash BIP143 pour `hashOutputs` (contrairement à la transaction finale,
    /// qui elle a besoin de ce préfixe — voir `sign()`).
    fn outputs_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (value, script) in &self.outputs {
            buf.extend_from_slice(&value.to_le_bytes());
            push_varint(&mut buf, script.len() as u64);
            buf.extend_from_slice(script);
        }
        buf
    }

    fn hash_prevouts(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            buf.extend_from_slice(&txid_le);
            buf.extend_from_slice(&input.vout.to_le_bytes());
        }
        dsha256(&buf)
    }

    fn hash_sequence(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for input in &self.inputs {
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        dsha256(&buf)
    }

    /// Sighash BIP143 (SIGHASH_ALL) pour l'input `index`, dont le scriptCode correspond à `input_hash160`.
    fn sighash(&self, index: usize, input_hash160: &[u8; 20]) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.version.to_le_bytes());
        preimage.extend_from_slice(&self.hash_prevouts());
        preimage.extend_from_slice(&self.hash_sequence());

        let input = &self.inputs[index];
        let mut txid_le = input.txid;
        txid_le.reverse();
        preimage.extend_from_slice(&txid_le);
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        preimage.extend_from_slice(&p2wpkh_script_code(input_hash160));
        preimage.extend_from_slice(&input.value_sat.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        preimage.extend_from_slice(&dsha256(&self.outputs_body()));
        preimage.extend_from_slice(&self.locktime.to_le_bytes());
        preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        dsha256(&preimage)
    }

    /// Taille hors témoins (version, entrées, sorties, locktime).
    fn base_size(&self) -> u64 {
        let mut size = 4 + 4 + varint_len(self.inputs.len() as u64) + varint_len(self.outputs.len() as u64);
        size += self.inputs.len() as u64 * (32 + 4 + 1 + 4);
        for (_, script) in &self.outputs {
            size += 8 + varint_len(script.len() as u64) + script.len() as u64;
        }
        size
    }

    /// Taille virtuelle une fois signée, au plus (signature DER de 72 octets
    /// avec son type, clé compressée) : sert à vérifier le tarif de frais
    /// d'une transaction préparée par un tiers.
    pub fn signed_vsize(&self) -> u64 {
        // Marqueur et drapeau segwit (2), puis par entrée : compte (1) +
        // signature (1 + 72) + clé (1 + 33).
        let witness = 2 + self.inputs.len() as u64 * (1 + 1 + 72 + 1 + 33);
        (self.base_size() * 4 + witness).div_ceil(4)
    }

    /// Construit et signe la transaction. Toutes les entrées doivent appartenir à la
    /// même clé (`input_hash160`).
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
        tx.extend_from_slice(&self.version.to_le_bytes());
        tx.push(0x00); // marker segwit
        tx.push(0x01); // flag segwit

        push_varint(&mut tx, self.inputs.len() as u64);
        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            tx.extend_from_slice(&txid_le);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            tx.push(0x00); // scriptSig vide (segwit natif)
            tx.extend_from_slice(&input.sequence.to_le_bytes());
        }

        push_varint(&mut tx, self.outputs.len() as u64);
        tx.extend_from_slice(&self.outputs_body());

        for (sig, pubkey) in &witnesses {
            push_varint(&mut tx, 2); // 2 éléments de témoin : signature + clé publique
            push_varint(&mut tx, sig.len() as u64);
            tx.extend_from_slice(sig);
            push_varint(&mut tx, pubkey.len() as u64);
            tx.extend_from_slice(pubkey);
        }

        tx.extend_from_slice(&self.locktime.to_le_bytes());
        Ok(tx)
    }
}

fn varint_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

impl BtcTx {
    /// Même transaction sous forme générique : version 1, séquences
    /// 0xffffffff, locktime 0 ; destinataire, monnaie (si au-dessus de la
    /// poussière) puis OP_RETURN (si présent), dans cet ordre.
    fn to_raw(&self) -> RawTx {
        let mut outputs = vec![(self.value_sat, p2wpkh_script_pubkey(&self.to_hash160))];
        if self.change_sat > 0 {
            outputs.push((self.change_sat, p2wpkh_script_pubkey(&self.change_hash160)));
        }
        if let Some(data) = &self.op_return_data {
            outputs.push((0, op_return_script(data))); // valeur 0 : non dépensable
        }
        let inputs = self.inputs.iter().map(|u| RawInput { txid: u.txid, vout: u.vout, sequence: 0xffff_ffff, value_sat: u.value_sat }).collect();
        RawTx { version: 1, inputs, outputs, locktime: 0 }
    }

    #[cfg(test)]
    fn outputs_body(&self) -> Vec<u8> {
        self.to_raw().outputs_body()
    }

    #[cfg(test)]
    pub(crate) fn sighash(&self, index: usize, input_hash160: &[u8; 20]) -> [u8; 32] {
        self.to_raw().sighash(index, input_hash160)
    }

    /// Construit et signe la transaction. Toutes les entrées doivent appartenir à la
    /// même clé (`input_hash160`), ce qui est le cas dans cette démo mono-adresse.
    pub fn sign(&self, key: &SigningKey, input_hash160: &[u8; 20]) -> Result<Vec<u8>> {
        self.to_raw().sign(key, input_hash160)
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
            op_return_data: None,
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
            op_return_data: None,
        };
        let body = tx.outputs_body();
        // Deux sorties : 2 * (8 + 1 + 22) = 62 octets.
        assert_eq!(body.len(), 2 * (8 + 1 + 22));
    }

    /// La sortie OP_RETURN doit être présente, non dépensable (valeur 0) et
    /// porter le memo en clair, sans casser le reste (garde-fou contre une
    /// régression sur `num_outputs`/`sign` introduite par cet ajout).
    #[test]
    fn outputs_body_includes_op_return_when_present() {
        let hash160 = [0x11u8; 20];
        let memo = b"SWAP:BTC.BTC:bc1qxyz:0/1/0:thor1abc:80".to_vec();
        let tx = BtcTx {
            inputs: vec![Utxo { txid: [0xAAu8; 32], vout: 0, value_sat: 100_000 }],
            to_hash160: [0x22u8; 20],
            value_sat: 50_000,
            change_hash160: hash160,
            change_sat: 49_000,
            op_return_data: Some(memo.clone()),
        };
        let body = tx.outputs_body();
        // Sortie principale + monnaie (2 * 31 octets) puis OP_RETURN : valeur (8,
        // nulle) + longueur script (1) + OP_RETURN (1) + push direct (1) + memo.
        let expected_len = 2 * (8 + 1 + 22) + 8 + 1 + 1 + 1 + memo.len();
        assert_eq!(body.len(), expected_len);
        let op_return_offset = 2 * (8 + 1 + 22);
        assert_eq!(&body[op_return_offset..op_return_offset + 8], &0u64.to_le_bytes());
        assert_eq!(body[op_return_offset + 9], 0x6a, "OP_RETURN attendu");
        assert_eq!(body[op_return_offset + 10], memo.len() as u8, "push direct de la longueur");
        assert_eq!(&body[op_return_offset + 11..], &memo[..]);

        let key = SigningKey::from_slice(&[9u8; 32]).expect("clé de test valide");
        let raw = tx.sign(&key, &hash160).expect("signature réussie avec OP_RETURN");
        // 3 sorties désormais : le varint de compte doit valoir 3.
        // (marker+flag = 2 octets après les 4 de version, puis varint d'entrées =
        // 1 octet ici, 41 octets d'entrée, puis le varint de sorties)
        let outputs_count_offset = 4 + 2 + 1 + 41;
        assert_eq!(raw[outputs_count_offset], 3, "3 sorties attendues (dest + monnaie + OP_RETURN)");
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
            op_return_data: None,
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

    /// Vecteur officiel de BIP143 (« Native P2WPKH ») : version 1, séquence
    /// 0xffffffee sur la première entrée, locktime 17, sorties P2PKH — les
    /// champs qu'une PSBT d'un tiers peut fixer autrement que l'app.
    #[test]
    fn raw_tx_sighash_matches_the_bip143_native_p2wpkh_vector() {
        let display = |le_hex: &str| -> [u8; 32] {
            let mut bytes: [u8; 32] = hex::decode(le_hex).unwrap().try_into().unwrap();
            bytes.reverse();
            bytes
        };
        let tx = RawTx {
            version: 1,
            inputs: vec![
                RawInput { txid: display("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"), vout: 0, sequence: 0xffff_ffee, value_sat: 625_000_000 },
                RawInput { txid: display("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"), vout: 1, sequence: 0xffff_ffff, value_sat: 600_000_000 },
            ],
            outputs: vec![
                (112_340_000, hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").unwrap()),
                (223_450_000, hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").unwrap()),
            ],
            locktime: 17,
        };
        let hash160: [u8; 20] = hex::decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap().try_into().unwrap();
        assert_eq!(hex::encode(tx.sighash(1, &hash160)), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");

        // Signature avec la clé du vecteur : valide pour ce sighash, et taille
        // réelle sous la borne de `signed_vsize`.
        let key = SigningKey::from_slice(&hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9").unwrap()).unwrap();
        let raw = tx.sign(&key, &hash160).unwrap();
        let witness_bytes = raw.len() as u64 - (tx.base_size());
        let real_vsize = (tx.base_size() * 4 + witness_bytes).div_ceil(4);
        assert!(real_vsize <= tx.signed_vsize(), "{real_vsize} > {}", tx.signed_vsize());
        assert_eq!(op_return_output_size(55), 8 + 1 + 57);
        assert_eq!(op_return_output_size(80), 8 + 1 + 83);
    }
}
