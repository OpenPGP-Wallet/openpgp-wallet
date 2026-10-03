//! PSBT (BIP174, version 0) fournie par un tiers — LI.FI pour un échange
//! depuis Bitcoin : lecture de la transaction non signée qu'elle contient.
//! Rien n'est repris des champs propres à chaque entrée (sorties dépensées
//! annoncées, chemins de dérivation…) : l'app relit les sorties qu'elle
//! dépense auprès de son propre serveur (Esplora), vérifie chaque sortie de
//! la transaction (voir `lifi::verify_btc_deposit`), puis signe une
//! transaction qu'elle re-sérialise elle-même (`btc_tx::RawTx`).

use anyhow::{anyhow, bail, ensure, Context, Result};

/// Entrées et sorties au plus : bien au-delà d'un dépôt normal (quelques
/// entrées, 5 sorties), borne contre une PSBT démesurée.
const MAX_INPUTS: usize = 200;
const MAX_OUTPUTS: usize = 16;

/// Entrée de la transaction non signée.
#[derive(Clone, Debug, PartialEq)]
pub struct PsbtInput {
    /// Ordre "affiché" (big-endian), comme `btc_tx::Utxo::txid`.
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
}

/// Transaction non signée d'une PSBT.
#[derive(Clone, Debug, PartialEq)]
pub struct Psbt {
    pub version: u32,
    pub inputs: Vec<PsbtInput>,
    /// (valeur en satoshis, script de sortie).
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub locktime: u32,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.data.len()).ok_or_else(|| anyhow!("PSBT tronquée"))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 octets")))
    }

    fn u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8 octets")))
    }

    /// Entier compact de Bitcoin, sous sa forme minimale seulement.
    fn varint(&mut self) -> Result<usize> {
        let first = self.take(1)?[0];
        let (value, min) = match first {
            0xfd => (u64::from(u16::from_le_bytes(self.take(2)?.try_into().expect("2 octets"))), 0xfd),
            0xfe => (u64::from(self.u32_le()?), 0x1_0000),
            0xff => (self.u64_le()?, 0x1_0000_0000),
            n => (u64::from(n), 0),
        };
        ensure!(value >= min, "PSBT : entier compact non minimal");
        usize::try_from(value).map_err(|_| anyhow!("PSBT : taille hors limites"))
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// Une table clé → valeur de la PSBT (jusqu'au séparateur 0x00).
fn read_map<'a>(reader: &mut Reader<'a>) -> Result<Vec<(&'a [u8], &'a [u8])>> {
    let mut entries: Vec<(&[u8], &[u8])> = Vec::new();
    loop {
        let key_len = reader.varint()?;
        if key_len == 0 {
            return Ok(entries);
        }
        let key = reader.take(key_len)?;
        let value_len = reader.varint()?;
        let value = reader.take(value_len)?;
        ensure!(!entries.iter().any(|(k, _)| *k == key), "PSBT : clé en double");
        entries.push((key, value));
    }
}

/// Transaction non signée (format sans témoins, scripts de signature vides,
/// exigés par BIP174).
fn parse_unsigned_tx(bytes: &[u8]) -> Result<Psbt> {
    let mut reader = Reader { data: bytes, pos: 0 };
    let version = reader.u32_le()?;
    let input_count = reader.varint()?;
    // 0 entrée : c'est le marqueur d'une sérialisation avec témoins, interdite ici.
    ensure!((1..=MAX_INPUTS).contains(&input_count), "PSBT : nombre d'entrées invalide ({input_count})");
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let mut txid: [u8; 32] = reader.take(32)?.try_into().expect("32 octets");
        txid.reverse();
        let vout = reader.u32_le()?;
        ensure!(reader.varint()? == 0, "PSBT : entrée déjà signée (script de signature non vide)");
        let sequence = reader.u32_le()?;
        inputs.push(PsbtInput { txid, vout, sequence });
    }
    let output_count = reader.varint()?;
    ensure!((1..=MAX_OUTPUTS).contains(&output_count), "PSBT : nombre de sorties invalide ({output_count})");
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = reader.u64_le()?;
        let script_len = reader.varint()?;
        ensure!(script_len <= 10_000, "PSBT : script de sortie démesuré");
        outputs.push((value, reader.take(script_len)?.to_vec()));
    }
    let locktime = reader.u32_le()?;
    ensure!(reader.done(), "PSBT : octets en trop après la transaction");
    Ok(Psbt { version, inputs, outputs, locktime })
}

/// Lit une PSBT version 0 : transaction non signée (clé globale 0x00,
/// unique), puis une table par entrée et par sortie, sans octet en trop.
pub fn parse(bytes: &[u8]) -> Result<Psbt> {
    ensure!(bytes.starts_with(b"psbt\xff"), "ce n'est pas une PSBT (en-tête attendu « psbt\\xff »)");
    let mut reader = Reader { data: bytes, pos: 5 };
    let mut psbt = None;
    for (key, value) in read_map(&mut reader)? {
        match key {
            [0x00] => psbt = Some(parse_unsigned_tx(value).context("transaction de la PSBT illisible")?),
            [0xfb] => ensure!(value == [0, 0, 0, 0], "PSBT d'une version non prise en charge"),
            _ => {}
        }
    }
    let psbt = psbt.ok_or_else(|| anyhow!("PSBT sans transaction non signée"))?;
    for _ in 0..psbt.inputs.len() + psbt.outputs.len() {
        read_map(&mut reader)?;
    }
    if !reader.done() {
        bail!("PSBT : octets en trop après les tables");
    }
    Ok(psbt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PSBT réelle renvoyée par LI.FI (BTC → ETH via LayerSwap, 1 000 000
    /// sats depuis une adresse publique, relevée le 03/10/2026) : 1 entrée,
    /// dépôt Taproot, memo, monnaie, frais LI.FI (0,25 %) et intégrateur
    /// (0,80 %).
    pub(crate) const LIFI_PSBT: &str = include_str!("../testdata/lifi_btc_psbt.hex");

    #[test]
    fn reads_a_real_lifi_psbt() {
        let psbt = parse(&hex::decode(LIFI_PSBT.trim()).unwrap()).unwrap();
        assert_eq!((psbt.version, psbt.locktime), (2, 0));
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(hex::encode(psbt.inputs[0].txid), "8b9ad00827c9db077bd4457238c4eb5a732fef9618ad4bb34ebc096af5de68c9");
        assert_eq!(psbt.inputs[0].sequence, 0xffff_fffd);
        let values: Vec<u64> = psbt.outputs.iter().map(|(v, _)| *v).collect();
        assert_eq!(values, [989_500, 0, 24_648_984_862, 2_500, 8_000]);
        assert_eq!(&psbt.outputs[0].1[..2], &[0x51, 0x20], "dépôt Taproot");
        assert_eq!(psbt.outputs[1].1[0], 0x6a, "memo OP_RETURN");
    }

    #[test]
    fn refuses_malformed_psbts() {
        let good = hex::decode(LIFI_PSBT.trim()).unwrap();
        assert!(parse(&good[1..]).is_err(), "en-tête");
        assert!(parse(&good[..good.len() - 1]).is_err(), "tronquée");
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err(), "octet en trop");
        assert!(parse(b"psbt\xff\x00").is_err(), "sans transaction");
    }
}
