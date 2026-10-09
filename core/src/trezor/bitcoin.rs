//! Bitcoin sur Trezor (natif SegWit, BIP 84 : m/84'/c'/n'/{0,1}/i) : clé
//! publique étendue du compte, adresse vérifiée sur l'écran, et signature par
//! le dialogue `SignTx` : l'appareil demande une à une chaque entrée, chaque
//! sortie, puis les transactions précédentes (métadonnées, entrées, sorties)
//! pour vérifier lui-même les montants dépensés ; il affiche destinataires,
//! montants et frais, la monnaie (sortie sur 1/i) étant reconnue et masquée.
//!
//! Comme pour le Ledger, la transaction finale est assemblée ICI à partir des
//! signatures, chacune vérifiée contre notre condensat BIP 143 : rien de ce
//! que renvoie l'appareil n'est diffusé sans avoir été revérifié.

use super::proto::{Message, Writer};
use super::{msg, Trezor};
use crate::btc_tx::p2wpkh_script_pubkey;
use crate::ledger::btc::{hash160, parse_transaction, Account, Input, Output, PrevTx, TxIn, TxOut, UnsignedTx};
use crate::ledger::HARDENED;
use anyhow::{anyhow, bail, ensure, Result};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use std::collections::HashMap;

/// Version, verrouillage et séquence de la transaction — identiques à ceux du
/// Ledger, et repris tels quels pour le condensat local.
const TX_VERSION: u32 = 2;
const SEQUENCE: u32 = 0xffff_ffff;
const SPENDWITNESS: u64 = 3;
const PAYTOADDRESS: u64 = 0;
const PAYTOWITNESS: u64 = 4;

fn coin_name(testnet: bool) -> &'static str {
    if testnet {
        "Testnet"
    } else {
        "Bitcoin"
    }
}

fn account_path(testnet: bool, account: u32) -> Vec<u32> {
    vec![84 | HARDENED, testnet as u32 | HARDENED, account | HARDENED]
}

fn address_path(account: &Account, change: u32, index: u32) -> Vec<u32> {
    let mut path = account_path(account.testnet, account.account);
    path.extend([change, index]);
    path
}

/// Empreinte maîtresse et clé publique étendue du compte m/84'/c'/`account`'.
pub fn load_account(trezor: &mut Trezor, testnet: bool, account: u32) -> Result<Account> {
    ensure!(account < HARDENED, "numéro de compte invalide");
    let payload = Writer::new().uints(1, &account_path(testnet, account)).string(4, coin_name(testnet)).finish();
    let response = trezor.call_expect(msg::GET_PUBLIC_KEY, &payload, msg::PUBLIC_KEY)?;
    let key = Message::parse(&response)?;
    let xpub = key.string(2).ok_or_else(|| anyhow!("clé publique étendue du Trezor absente"))?;
    let fingerprint = key.uint(3).ok_or_else(|| anyhow!("empreinte maîtresse du Trezor absente (firmware trop ancien ?)"))?;
    let loaded = Account { testnet, account, fingerprint: (fingerprint as u32).to_be_bytes(), xpub };
    // Préfixe, réseau et niveau de dérivation contrôlés comme pour le Ledger.
    loaded.address(0, 0)?;
    Ok(loaded)
}

/// Adresse calculée PAR L'APPAREIL (`show` : affichée pour vérification),
/// comparée à celle dérivée localement de la clé étendue.
pub fn get_address(trezor: &mut Trezor, account: &Account, change: u32, index: u32, show: bool) -> Result<String> {
    let expected = account.address(change, index)?;
    let payload = Writer::new()
        .uints(1, &address_path(account, change, index))
        .string(2, coin_name(account.testnet))
        .boolean(3, show)
        .uint(5, SPENDWITNESS)
        .finish();
    let response = trezor.call_expect(msg::GET_ADDRESS, &payload, msg::ADDRESS)?;
    let address = Message::parse(&response)?.string(1).ok_or_else(|| anyhow!("adresse Bitcoin du Trezor absente"))?;
    ensure!(address == expected, "l'adresse calculée par le Trezor ne correspond pas à celle du compte");
    Ok(address)
}

/// Adresse d'une sortie de destination (P2PKH, P2SH, P2WPKH, P2WSH ou
/// Taproot) : le Trezor la reçoit sous cette forme et l'affiche.
fn output_address(account: &Account, script: &[u8]) -> Result<String> {
    crate::derivation::btc_script_address(script, account.testnet)
}

/// Réponse `TxAck` portant une transaction (ou un fragment) : champs 2
/// entrées, 3 sorties brutes, 5 sorties, ou métadonnées.
fn tx_ack(transaction: Writer) -> Vec<u8> {
    Writer::new().message(1, transaction).finish()
}

fn our_input(account: &Account, input: &Input) -> Vec<u8> {
    tx_ack(Writer::new().message(
        2,
        Writer::new()
            .uints(1, &address_path(account, input.change, input.index))
            .bytes(2, &input.txid)
            .uint(3, input.vout.into())
            .uint(5, SEQUENCE.into())
            .uint(6, SPENDWITNESS)
            .uint(8, input.value_sat)
            .uint(20, 0),
    ))
}

fn our_output(account: &Account, output: &Output) -> Result<Vec<u8>> {
    let fields = match output.change_index {
        // Monnaie : désignée par son chemin, l'appareil la vérifie et la masque.
        Some(index) => Writer::new().uints(2, &address_path(account, 1, index)).uint(3, output.value_sat).uint(4, PAYTOWITNESS),
        None => Writer::new().string(1, &output_address(account, &output.script_pubkey)?).uint(3, output.value_sat).uint(4, PAYTOADDRESS),
    };
    Ok(tx_ack(Writer::new().message(5, fields)))
}

fn prev_meta(prev: &PrevTx) -> Vec<u8> {
    tx_ack(
        Writer::new()
            .uint(1, prev.version.into())
            .uint(4, prev.locktime.into())
            .uint(6, prev.inputs.len() as u64)
            .uint(7, prev.outputs.len() as u64)
            .uint(9, 0),
    )
}

fn prev_input(prev: &PrevTx, index: usize) -> Result<Vec<u8>> {
    let input = prev.inputs.get(index).ok_or_else(|| anyhow!("le Trezor demande une entrée inexistante"))?;
    let mut prevout = input.prevout;
    prevout.reverse();
    Ok(tx_ack(Writer::new().message(
        2,
        Writer::new().bytes(2, &prevout).uint(3, input.vout.into()).bytes(4, &input.script_sig).uint(5, input.sequence.into()),
    )))
}

fn prev_output(prev: &PrevTx, index: usize) -> Result<Vec<u8>> {
    let (value, script) = prev.outputs.get(index).ok_or_else(|| anyhow!("le Trezor demande une sortie inexistante"))?;
    Ok(tx_ack(Writer::new().message(3, Writer::new().uint(1, *value).bytes(2, script))))
}

/// Fait signer la transaction par l'appareil, vérifie chaque signature contre
/// le condensat BIP 143 calculé ici, et renvoie la transaction finale.
pub fn sign_transaction(trezor: &mut Trezor, account: &Account, inputs: &[Input], outputs: &[Output]) -> Result<Vec<u8>> {
    ensure!(!inputs.is_empty() && !outputs.is_empty(), "transaction vide");
    // Vérifications locales identiques à celles du Ledger : chaque UTXO doit
    // exister dans sa transaction précédente avec le montant et l'adresse
    // attendus ; chaque monnaie doit être une adresse du compte.
    let mut previous: HashMap<[u8; 32], PrevTx> = HashMap::new();
    let mut keys = Vec::with_capacity(inputs.len());
    for input in inputs {
        let pubkey = account.public_key(input.change, input.index)?;
        let script = p2wpkh_script_pubkey(&hash160(&pubkey));
        let prev = parse_transaction(&input.prev_tx)?;
        ensure!(prev.txid == input.txid, "la transaction précédente fournie ne correspond pas à l'UTXO {}", hex::encode(input.txid));
        ensure!(
            prev.outputs.get(input.vout as usize) == Some(&(input.value_sat, script)),
            "l'UTXO {}:{} n'a pas le montant ou l'adresse attendus",
            hex::encode(input.txid),
            input.vout
        );
        previous.insert(prev.txid, prev);
        keys.push(pubkey);
    }
    for output in outputs {
        if let Some(index) = output.change_index {
            ensure!(output.script_pubkey == p2wpkh_script_pubkey(&account.hash160(1, index)?), "sortie de monnaie incohérente avec le compte");
        }
    }

    let sign_tx = Writer::new()
        .uint(1, outputs.len() as u64)
        .uint(2, inputs.len() as u64)
        .string(3, coin_name(account.testnet))
        .uint(4, TX_VERSION.into())
        .uint(5, 0)
        .finish();
    let mut response = trezor.call_expect(msg::SIGN_TX, &sign_tx, msg::TX_REQUEST)?;
    let mut signatures: Vec<Option<Vec<u8>>> = vec![None; inputs.len()];
    // Borne : un dialogue normal compte quelques dizaines d'échanges.
    for _ in 0..10_000 {
        let request = Message::parse(&response)?;
        if let Some(serialized) = request.message(3)? {
            if let (Some(index), Some(signature)) = (serialized.uint(1), serialized.bytes(2)) {
                let slot = signatures.get_mut(index as usize).ok_or_else(|| anyhow!("signature du Trezor pour une entrée inexistante"))?;
                ensure!(slot.is_none(), "le Trezor a signé deux fois l'entrée {index}");
                *slot = Some(signature.to_vec());
            }
        }
        let details = request.message(2)?;
        let index = details.as_ref().and_then(|d| d.uint(1)).unwrap_or(0) as usize;
        let prev = match details.as_ref().and_then(|d| d.bytes(2)) {
            Some(hash) => {
                let hash: [u8; 32] = hash.try_into().map_err(|_| anyhow!("empreinte de transaction invalide demandée par le Trezor"))?;
                Some(previous.get(&hash).ok_or_else(|| anyhow!("le Trezor demande une transaction inconnue"))?)
            }
            None => None,
        };
        let ack = match (request.uint(1).unwrap_or(0), prev) {
            (0, None) => our_input(account, inputs.get(index).ok_or_else(|| anyhow!("le Trezor demande une entrée inexistante"))?),
            (1, None) => our_output(account, outputs.get(index).ok_or_else(|| anyhow!("le Trezor demande une sortie inexistante"))?)?,
            (2, Some(prev)) => prev_meta(prev),
            (0, Some(prev)) => prev_input(prev, index)?,
            (1, Some(prev)) => prev_output(prev, index)?,
            (3, _) => break,
            (other, _) => bail!("demande inattendue du Trezor (type {other})"),
        };
        response = trezor.call_expect(msg::TX_ACK, &ack, msg::TX_REQUEST)?;
    }

    let unsigned = UnsignedTx {
        version: TX_VERSION,
        inputs: inputs
            .iter()
            .map(|i| {
                let mut prevout = i.txid;
                prevout.reverse();
                TxIn { prevout, vout: i.vout, sequence: SEQUENCE }
            })
            .collect(),
        outputs: outputs.iter().map(|o| TxOut { value: o.value_sat, script: o.script_pubkey.clone() }).collect(),
        locktime: 0,
    };
    let mut witnesses = Vec::with_capacity(inputs.len());
    for (index, (signature, pubkey)) in signatures.into_iter().zip(&keys).enumerate() {
        let der = signature.ok_or_else(|| anyhow!("le Trezor n'a pas signé toutes les entrées"))?;
        let signature = Signature::from_der(&der).map_err(|_| anyhow!("signature du Trezor mal formée"))?;
        ensure!(signature.normalize_s().is_none(), "signature du Trezor non canonique");
        let digest = unsigned.sighash(index, &hash160(pubkey), inputs[index].value_sat);
        VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|_| anyhow!("clé publique invalide"))?
            .verify_prehash(&digest, &signature)
            .map_err(|_| anyhow!("la signature du Trezor ne correspond pas à la transaction attendue — transaction non diffusée"))?;
        let mut encoded = signature.to_der().as_bytes().to_vec();
        encoded.push(0x01); // SIGHASH_ALL
        witnesses.push((encoded, *pubkey));
    }
    Ok(unsigned.serialize_signed(&witnesses))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account() -> Account {
        Account {
            testnet: true,
            account: 0,
            fingerprint: [0xf5, 0xac, 0xc2, 0xfd],
            xpub: "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".into(),
        }
    }

    /// Réponses `TxAck` identiques, octet pour octet, à celles de trezorlib
    /// (TxAckInput, TxAckPrevMeta, TxAckPrevOutput, TxAckOutput de monnaie).
    #[test]
    fn tx_acks_match_trezorlib() {
        let account = test_account();
        let mut txid = [0u8; 32];
        txid.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let input = Input { txid, vout: 1, value_sat: 50_000, prev_tx: Vec::new(), change: 0, index: 0 };
        assert_eq!(
            hex::encode(our_input(&account, &input)),
            "0a4b124908d480808008088180808008088080808008080008001220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f180128ffffffff0f300340d08603a00100"
        );
        let prev = PrevTx { txid: [0; 32], stripped: Vec::new(), version: 2, inputs: vec![crate::ledger::btc::PrevTxIn { prevout: [0; 32], vout: 0, script_sig: Vec::new(), sequence: 0 }], outputs: vec![(50_000, [&[0x00, 0x14][..], &[0x11; 20]].concat()), (1, Vec::new())], locktime: 0 };
        assert_eq!(hex::encode(prev_meta(&prev)), "0a0a08022000300138024800");
        assert_eq!(hex::encode(prev_output(&prev, 0).unwrap()), "0a1e1a1c08d08603121600141111111111111111111111111111111111111111");
        let change = Output { value_sat: 18_000, script_pubkey: p2wpkh_script_pubkey(&account.hash160(1, 4).unwrap()), change_index: Some(4) };
        assert_eq!(hex::encode(our_output(&account, &change).unwrap()), "0a1e2a1c10d4808080081081808080081080808080081001100418d08c012004");
        assert!(prev_output(&prev, 5).is_err());
    }

    /// Firmware officiel dans l'émulateur (graine de test publique) : compte
    /// et adresses = notre dérivation (et celles de l'app Ledger), adresse
    /// affichée, vraie transaction à 2 entrées (0/0 et 1/3) signée après
    /// revue (montant, destinataire, frais ; monnaie masquée), signatures
    /// vérifiées ; refus -> erreur claire.
    /// `cargo test -- --ignored trezor_bitcoin_against_the_official_firmware --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn trezor_bitcoin_against_the_official_firmware() {
        use super::super::emulator::{connect, DebugLink};
        let mut trezor = connect();
        trezor.initialize().unwrap();
        let account = load_account(&mut trezor, true, 0).unwrap();
        assert_eq!(account, test_account(), "compte Trezor = compte Ledger = notre dérivation");
        for (change, index) in [(0, 0), (1, 3)] {
            assert_eq!(get_address(&mut trezor, &account, change, index, false).unwrap(), account.address(change, index).unwrap());
        }
        let reviewer = std::thread::spawn(|| DebugLink::connect().review(8, None));
        get_address(&mut trezor, &account, 0, 0, true).unwrap();
        println!("écrans adresse : {:?}", reviewer.join().unwrap());

        let script = |change, index| p2wpkh_script_pubkey(&account.hash160(change, index).unwrap());
        let mut prev = 2u32.to_le_bytes().to_vec();
        prev.push(1);
        prev.extend([0x42; 32]);
        prev.extend(3u32.to_le_bytes());
        prev.push(0);
        prev.extend(SEQUENCE.to_le_bytes());
        prev.push(2);
        for (value, s) in [(50_000u64, script(0, 0)), (30_000, script(1, 3))] {
            prev.extend(value.to_le_bytes());
            prev.push(s.len() as u8);
            prev.extend(s);
        }
        prev.extend(0u32.to_le_bytes());
        let txid = parse_transaction(&prev).unwrap().txid;
        let inputs = [
            Input { txid, vout: 0, value_sat: 50_000, prev_tx: prev.clone(), change: 0, index: 0 },
            Input { txid, vout: 1, value_sat: 30_000, prev_tx: prev.clone(), change: 1, index: 3 },
        ];
        let outputs = [
            Output { value_sat: 60_000, script_pubkey: p2wpkh_script_pubkey(&[0x55; 20]), change_index: None },
            Output { value_sat: 18_000, script_pubkey: script(1, 4), change_index: Some(4) },
        ];
        let reviewer = std::thread::spawn(|| DebugLink::connect().review(20, None));
        let signed = sign_transaction(&mut trezor, &account, &inputs, &outputs).unwrap();
        let screens = reviewer.join().unwrap().join(" | ");
        println!("écrans transaction : {screens}");
        println!("transaction signée : {}", hex::encode(&signed));
        let compact = screens.replace(' ', "");
        assert!(compact.contains("0.0006"), "montant affiché");
        assert!(compact.contains(&crate::derivation::format_btc_testnet_address(&[0x55; 20]).unwrap()[..12]), "destinataire affiché");
        assert!(compact.contains("0.00002"), "frais affichés");
        assert_eq!(parse_transaction(&signed).unwrap().outputs.len(), 2);

        // Destinataire de chaque autre type standard (P2PKH m…, P2SH 2…,
        // P2WSH, Taproot tb1p…) : transmis au Trezor sous forme d'adresse,
        // affiché, et la transaction signée porte le script attendu.
        for to_script in [
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ] {
            let to_script = hex::decode(to_script).unwrap();
            let address = crate::derivation::btc_script_address(&to_script, true).unwrap();
            let outputs = [
                Output { value_sat: 60_000, script_pubkey: to_script.clone(), change_index: None },
                Output { value_sat: 18_000, script_pubkey: script(1, 4), change_index: Some(4) },
            ];
            let reviewer = std::thread::spawn(|| DebugLink::connect().review(20, None));
            let signed = sign_transaction(&mut trezor, &account, &inputs, &outputs).unwrap();
            let screens = reviewer.join().unwrap().join(" | ");
            println!("{address} : {screens}");
            assert!(screens.replace(' ', "").contains(&address[..12]), "{address} affichée");
            assert_eq!(parse_transaction(&signed).unwrap().outputs[0], (60_000, to_script));
        }

        let refuser = std::thread::spawn(|| DebugLink::connect().review(20, Some("")));
        let err = sign_transaction(&mut trezor, &account, &inputs, &outputs).unwrap_err();
        refuser.join().unwrap();
        assert!(err.to_string().contains("refusée"), "{err}");
    }
}
