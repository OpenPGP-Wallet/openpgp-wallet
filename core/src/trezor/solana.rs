//! Solana sur Trezor : clé publique (adresse) et signature du message d'une
//! transaction, affiché sur l'appareil avant signature. Chemin de Trezor
//! Suite pour le premier compte : m/44'/501'/0'/0'. Toute signature est
//! vérifiée ici contre la clé publique du compte.

use super::proto::{Message, Writer};
use super::{msg, Trezor};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn get_pubkey(trezor: &mut Trezor, path: &[u32], show: bool) -> Result<[u8; 32]> {
    let payload = Writer::new().uints(1, path).boolean(2, show).finish();
    let response = trezor.call_expect(msg::SOLANA_GET_ADDRESS, &payload, msg::SOLANA_ADDRESS)?;
    let address = Message::parse(&response)?.string(1).ok_or_else(|| anyhow!("adresse Solana du Trezor absente"))?;
    bs58::decode(&address)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("adresse Solana du Trezor mal formée"))
}

fn sign_request(path: &[u32], message: &[u8]) -> Vec<u8> {
    Writer::new().uints(1, path).bytes(2, message).finish()
}

/// Signe le message (partie signée d'une transaction) ; la signature doit
/// vérifier contre `expected`.
pub fn sign_transaction_message(trezor: &mut Trezor, path: &[u32], message: &[u8], expected: &[u8; 32]) -> Result<[u8; 64]> {
    let response = trezor.call_expect(msg::SOLANA_SIGN_TX, &sign_request(path, message), msg::SOLANA_TX_SIGNATURE)?;
    let signature: [u8; 64] = Message::parse(&response)?
        .bytes(1)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("signature Solana du Trezor mal formée"))?;
    VerifyingKey::from_bytes(expected)
        .map_err(|_| anyhow!("clé publique Solana invalide"))?
        .verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| anyhow!("la signature du Trezor ne correspond pas au compte attendu — transaction non diffusée"))?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::parse_path;

    /// Même encodage que trezorlib (`SolanaSignTx`).
    #[test]
    fn sign_request_matches_trezorlib() {
        assert_eq!(
            hex::encode(sign_request(&parse_path("44'/501'/0'/0'").unwrap(), &[1, 2, 3, 4, 5])),
            "08ac8080800808f58380800808808080800808808080800812050102030405"
        );
    }

    /// Firmware officiel dans l'émulateur : clé publique = NOTRE dérivation
    /// (même chemin que le portefeuille logiciel) ; adresse affichée ; vrai
    /// virement construit par notre code, signé après revue (montant,
    /// destinataire) et vérifié ; refus -> erreur claire.
    /// `cargo test -- --ignored trezor_solana_against_the_official_firmware --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn trezor_solana_against_the_official_firmware() {
        use super::super::emulator::{connect, DebugLink};
        let path = parse_path("44'/501'/0'/0'").unwrap();
        let seed = bip39::Mnemonic::parse(crate::ledger::speculos::TEST_MNEMONIC).unwrap().to_seed("");
        let ours = crate::derivation::derive_solana_key(&seed, 0).verifying_key().to_bytes();
        let mut trezor = connect();
        trezor.initialize().unwrap();
        assert_eq!(get_pubkey(&mut trezor, &path, false).unwrap(), ours);
        println!("clé Trezor = dérivation : {}", bs58::encode(ours).into_string());

        let reviewer = std::thread::spawn(|| DebugLink::connect().review(8, None));
        assert_eq!(get_pubkey(&mut trezor, &path, true).unwrap(), ours);
        println!("écrans adresse : {:?}", reviewer.join().unwrap());

        let to = [0x44u8; 32];
        let message = crate::sol_tx::build_message(&ours, &[crate::sol_tx::transfer_instruction(&ours, &to, 12_300_000)], &[7u8; 32]);
        let reviewer = std::thread::spawn(|| DebugLink::connect().review(15, None));
        sign_transaction_message(&mut trezor, &path, &message, &ours).unwrap();
        let screens = reviewer.join().unwrap().join(" | ");
        println!("écrans virement : {screens}");
        assert!(screens.contains("0.0123"), "montant affiché");
        assert!(screens.contains(&bs58::encode(to).into_string()[..8]), "destinataire affiché");

        let refuser = std::thread::spawn(|| DebugLink::connect().review(15, Some("")));
        let err = sign_transaction_message(&mut trezor, &path, &message, &ours).unwrap_err();
        refuser.join().unwrap();
        assert!(err.to_string().contains("refusée"), "{err}");
    }
}
