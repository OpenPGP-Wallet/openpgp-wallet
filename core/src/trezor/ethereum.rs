//! Ethereum on Trezor: address (checked on the device screen) and signing of legacy
//! EIP-155 transactions. The device shows recipient, amount, fee and network before
//! signing. Every signature is checked again here: it must recover to the account's
//! address.

use super::proto::{Message, Writer};
use super::{msg, Trezor};
use crate::eth_tx::EthTx;
use crate::evm_sign::keccak;
use crate::ledger::eth::{normalized, recover_address};
use anyhow::{anyhow, ensure, Result};

/// Size of the first data chunk sent with the signing request.
const INITIAL_CHUNK: usize = 1024;

pub fn get_address(trezor: &mut Trezor, path: &[u32], show: bool) -> Result<String> {
    let payload = Writer::new().uints(1, path).boolean(2, show).finish();
    let response = trezor.call_expect(msg::ETHEREUM_GET_ADDRESS, &payload, msg::ETHEREUM_ADDRESS)?;
    let address = Message::parse(&response)?.string(2).ok_or_else(|| anyhow!("adresse Ethereum du Trezor absente"))?;
    let bytes: [u8; 20] = hex::decode(address.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("adresse Ethereum du Trezor mal formée"))?;
    Ok(crate::derivation::format_address(&bytes))
}

/// Big-endian integer without leading zeros (0 -> empty), the format of
/// `EthereumSignTx` numeric fields.
fn be_minimal(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..].to_vec()
}

/// Signing request, with fields in the message's declaration order (trezorlib's).
fn sign_request(path: &[u32], tx: &EthTx) -> Vec<u8> {
    Writer::new()
        .uints(1, path)
        .bytes(2, &be_minimal(tx.nonce.into()))
        .bytes(3, &be_minimal(tx.gas_price))
        .bytes(4, &be_minimal(tx.gas_limit.into()))
        .string(11, &format!("0x{}", hex::encode(tx.to)))
        .bytes(6, &be_minimal(tx.value))
        .bytes(7, &tx.data[..tx.data.len().min(INITIAL_CHUNK)])
        .uint(8, tx.data.len() as u64)
        .uint(9, tx.chain_id)
        .finish()
}

/// Signs `tx` on the device and returns the signed transaction, ready to broadcast,
/// after checking that it recovers to `expected`.
pub fn sign_transaction(trezor: &mut Trezor, path: &[u32], tx: &EthTx, expected: &[u8; 20]) -> Result<Vec<u8>> {
    let mut response = trezor.call_expect(msg::ETHEREUM_SIGN_TX, &sign_request(path, tx), msg::ETHEREUM_TX_REQUEST)?;
    let mut offset = tx.data.len().min(INITIAL_CHUNK);
    // The device asks for the rest of the data chunk by chunk.
    loop {
        let requested = Message::parse(&response)?.uint(1).unwrap_or(0) as usize;
        if requested == 0 {
            break;
        }
        let end = offset.checked_add(requested).filter(|end| *end <= tx.data.len()).ok_or_else(|| anyhow!("le Trezor demande des données inexistantes"))?;
        let ack = Writer::new().bytes(1, &tx.data[offset..end]).finish();
        response = trezor.call_expect(msg::ETHEREUM_TX_ACK, &ack, msg::ETHEREUM_TX_REQUEST)?;
        offset = end;
    }
    let signature = Message::parse(&response)?;
    let v = signature.uint(2).ok_or_else(|| anyhow!("signature Ethereum du Trezor absente"))?;
    let (r, s) = (signature.bytes(3).unwrap_or_default(), signature.bytes(4).unwrap_or_default());
    ensure!(r.len() == 32 && s.len() == 32, "signature Ethereum du Trezor mal formée");
    // v = 35 + 2 × chain_id + parity (EIP-155), or 27/28.
    let parity = v
        .checked_sub(35 + 2 * tx.chain_id)
        .or_else(|| v.checked_sub(27))
        .filter(|p| *p <= 1)
        .ok_or_else(|| anyhow!("valeur v inattendue renvoyée par le Trezor"))? as u8;
    let (signature, parity) = normalized(r, s, parity)?;
    ensure!(
        recover_address(&keccak(&tx.unsigned_rlp()), &signature, parity)? == *expected,
        "la signature du Trezor ne correspond pas au compte attendu — transaction non diffusée"
    );
    let (r, s) = (signature.r().to_bytes(), signature.s().to_bytes());
    Ok(tx.encode_with_signature(tx.chain_id * 2 + 35 + u64::from(parity), &r.into(), &s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::parse_path;

    fn sample_tx() -> EthTx {
        EthTx { nonce: 7, gas_price: 20_000_000_000, gas_limit: 21_000, to: [0x44; 20], value: 10_000_000_000_000_000, chain_id: 11_155_111, data: Vec::new() }
    }

    /// Same encoding, byte for byte, as trezorlib (`EthereumSignTx`, a 0.01 ETH
    /// transfer on Sepolia).
    #[test]
    fn sign_request_matches_trezorlib() {
        assert_eq!(
            hex::encode(sign_request(&parse_path("44'/60'/0'/0/0").unwrap(), &sample_tx())),
            "08ac8080800808bc80808008088080808008080008001201071a0504a817c800220252085a2a30783434343434343434343434343434343434343434343434343434343434343434343434343434343432072386f26fc100003a00400048a7eda805"
        );
        assert!(be_minimal(0).is_empty());
        assert_eq!(be_minimal(0x0100), vec![1, 0]);
    }

    /// Official firmware in the emulator (public test seed): address = our derivation, shown on screen;
    /// transfer signed after review (recipient, amount) and checked again; a rejection gives a clear error.
    /// Start the emulator and the bridge first.
    /// `cargo test -- --ignored trezor_ethereum_against_the_official_firmware --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn trezor_ethereum_against_the_official_firmware() {
        use super::super::emulator::{connect, DebugLink};
        let path = parse_path("44'/60'/0'/0/0").unwrap();
        let seed = bip39::Mnemonic::parse(crate::ledger::speculos::TEST_MNEMONIC).unwrap().to_seed("");
        let (_, ours) = crate::derivation::derive_evm_key(&seed, 0).unwrap();
        let mut trezor = connect();
        trezor.initialize().unwrap();
        let address = get_address(&mut trezor, &path, false).unwrap();
        assert_eq!(address, crate::derivation::format_address(&ours));
        println!("adresse Trezor = dérivation : {address}");

        let reviewer = std::thread::spawn(|| DebugLink::connect().review(8, None));
        assert_eq!(get_address(&mut trezor, &path, true).unwrap(), address);
        println!("écrans adresse : {:?}", reviewer.join().unwrap());

        let tx = sample_tx();
        let reviewer = std::thread::spawn(|| DebugLink::connect().review(15, None));
        let signed = sign_transaction(&mut trezor, &path, &tx, &ours).unwrap();
        let screens = reviewer.join().unwrap().join(" | ");
        println!("écrans virement : {screens}");
        assert!(screens.contains("0.01"), "montant affiché");
        assert!(screens.to_lowercase().contains("0x4444"), "destinataire affiché");
        println!("transaction signée : 0x{}", hex::encode(&signed));

        let refuser = std::thread::spawn(|| DebugLink::connect().review(15, Some("")));
        let err = sign_transaction(&mut trezor, &path, &tx, &ours).unwrap_err();
        refuser.join().unwrap();
        assert!(err.to_string().contains("refusée"), "{err}");
    }
}
