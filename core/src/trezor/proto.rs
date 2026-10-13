//! Minimal protobuf encoding, limited to what this module's Trezor messages use:
//! integers (varint) and length-delimited fields (bytes, text, nested messages).
//! Message and field numbers come from the official definitions
//! (`common/protob/*.proto` in the firmware, via trezorlib).

use anyhow::{anyhow, bail, Result};

/// Builds a message field by field, in call order.
#[derive(Default)]
pub struct Writer(Vec<u8>);

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uint(mut self, field: u32, value: u64) -> Self {
        push_varint(&mut self.0, u64::from(field) << 3);
        push_varint(&mut self.0, value);
        self
    }

    pub fn boolean(self, field: u32, value: bool) -> Self {
        self.uint(field, value as u64)
    }

    /// Repeated integer field (one field per value, the non-packed form that protobuf
    /// decoders accept).
    pub fn uints(self, field: u32, values: &[u32]) -> Self {
        values.iter().fold(self, |w, v| w.uint(field, u64::from(*v)))
    }

    pub fn bytes(mut self, field: u32, value: &[u8]) -> Self {
        push_varint(&mut self.0, (u64::from(field) << 3) | 2);
        push_varint(&mut self.0, value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }

    pub fn string(self, field: u32, value: &str) -> Self {
        self.bytes(field, value.as_bytes())
    }

    pub fn message(self, field: u32, value: Writer) -> Self {
        self.bytes(field, &value.0)
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub enum Value<'a> {
    Uint(u64),
    Bytes(&'a [u8]),
}

/// Fields of a decoded message, in order (a repeated field appears several times).
pub struct Message<'a>(Vec<(u32, Value<'a>)>);

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *data.get(*pos).ok_or_else(|| anyhow!("message Trezor tronqué"))?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("entier protobuf trop long")
}

impl<'a> Message<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut fields = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let key = read_varint(data, &mut pos)?;
            let field = u32::try_from(key >> 3).map_err(|_| anyhow!("numéro de champ protobuf invalide"))?;
            match key & 7 {
                0 => fields.push((field, Value::Uint(read_varint(data, &mut pos)?))),
                2 => {
                    let len = usize::try_from(read_varint(data, &mut pos)?).map_err(|_| anyhow!("longueur protobuf invalide"))?;
                    let end = pos.checked_add(len).filter(|end| *end <= data.len()).ok_or_else(|| anyhow!("message Trezor tronqué"))?;
                    fields.push((field, Value::Bytes(&data[pos..end])));
                    pos = end;
                }
                // Fixed-size fields (not present in the messages used here): skipped.
                1 => pos = pos.checked_add(8).filter(|p| *p <= data.len()).ok_or_else(|| anyhow!("message Trezor tronqué"))?,
                5 => pos = pos.checked_add(4).filter(|p| *p <= data.len()).ok_or_else(|| anyhow!("message Trezor tronqué"))?,
                other => bail!("type de champ protobuf non pris en charge ({other})"),
            }
        }
        Ok(Self(fields))
    }

    pub fn uint(&self, field: u32) -> Option<u64> {
        self.0.iter().find_map(|(f, v)| match v {
            Value::Uint(n) if *f == field => Some(*n),
            _ => None,
        })
    }

    pub fn bytes(&self, field: u32) -> Option<&'a [u8]> {
        self.0.iter().find_map(|(f, v)| match v {
            Value::Bytes(b) if *f == field => Some(*b),
            _ => None,
        })
    }

    pub fn all_bytes(&self, field: u32) -> Vec<&'a [u8]> {
        self.0
            .iter()
            .filter_map(|(f, v)| match v {
                Value::Bytes(b) if *f == field => Some(*b),
                _ => None,
            })
            .collect()
    }

    pub fn string(&self, field: u32) -> Option<String> {
        self.bytes(field).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn message(&self, field: u32) -> Result<Option<Message<'a>>> {
        self.bytes(field).map(Message::parse).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference encodings produced by trezorlib (protobuf.dump_message): GetAddress
    /// m/84'/1'/0'/0/0 "Testnet", SPENDWITNESS script.
    #[test]
    fn encoding_matches_trezorlib() {
        let encoded = Writer::new()
            .uints(1, &[0x8000_0054, 0x8000_0001, 0x8000_0000, 0, 0])
            .string(2, "Testnet")
            .boolean(3, false)
            .uint(5, 3)
            .finish();
        assert_eq!(hex::encode(&encoded), "08d480808008088180808008088080808008080008001207546573746e657418002803");
        let parsed = Message::parse(&encoded).unwrap();
        assert_eq!(parsed.string(2).as_deref(), Some("Testnet"));
        assert_eq!(parsed.uint(5), Some(3));
        assert!(Message::parse(&[0x0a, 0x05, 0x01]).is_err(), "longueur au-delà du message");
    }
}
