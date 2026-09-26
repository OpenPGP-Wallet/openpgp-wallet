//! Application Solana du Ledger (`app-solana`, spécification `doc/api.md`,
//! découpage repris de `hw-app-solana`) : clé publique et signature de
//! transaction. L'appareil signe le MESSAGE de la transaction (ce que couvre
//! la signature ed25519 de Solana) après en avoir affiché le contenu.
//!
//! Toute signature renvoyée est vérifiée ici contre la clé publique du compte
//! avant usage.

use super::{encode_path, send_raw, Transport};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const CLA: u8 = 0xe0;
const INS_GET_PUBKEY: u8 = 0x05;
const INS_SIGN: u8 = 0x06;
const P1_NON_CONFIRM: u8 = 0x00;
const P1_CONFIRM: u8 = 0x01;
const P2_EXTEND: u8 = 0x01;
const P2_MORE: u8 = 0x02;
const MAX_PAYLOAD: usize = 255;

/// Mots d'état propres à l'application Solana, puis sens génériques.
fn check(sw: u16) -> Result<()> {
    match sw {
        0x9000 => Ok(()),
        0x6982 => Err(anyhow!("opération refusée sur le Ledger (0x6982)")),
        0x6808 => Err(anyhow!(
            "le Ledger exige l'option « signature à l'aveugle » (Blind signing) dans l'application Solana pour cette transaction (0x6808)"
        )),
        other => Err(super::status_error(other)),
    }
}

/// Envoi découpé en blocs de 255 octets (`hw-app-solana` `sendToDevice`) :
/// drapeau MORE sur chaque bloc sauf le dernier, EXTEND à partir du deuxième.
fn send_chunked(transport: &mut dyn Transport, ins: u8, p1: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let chunks: Vec<&[u8]> = payload.chunks(MAX_PAYLOAD).collect();
    let mut p2 = 0u8;
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i + 1 == chunks.len();
        let (response, sw) = send_raw(transport, CLA, ins, p1, if last { p2 } else { p2 | P2_MORE }, chunk)?;
        check(sw)?;
        if last {
            return Ok(response);
        }
        p2 |= P2_EXTEND;
    }
    Err(anyhow!("commande Solana vide"))
}

/// Clé publique (adresse) du compte `path`. `confirm` : affichée sur
/// l'appareil pour vérification visuelle.
pub fn get_pubkey(transport: &mut dyn Transport, path: &[u32], confirm: bool) -> Result<[u8; 32]> {
    let response = send_chunked(transport, INS_GET_PUBKEY, if confirm { P1_CONFIRM } else { P1_NON_CONFIRM }, &encode_path(path)?)?;
    response.try_into().map_err(|_| anyhow!("clé publique Solana du Ledger mal formée"))
}

/// Signe le message d'une transaction (`message` = partie signée, sans les
/// signatures) ; la signature doit vérifier contre `expected`.
pub fn sign_transaction_message(transport: &mut dyn Transport, path: &[u32], message: &[u8], expected: &[u8; 32]) -> Result<[u8; 64]> {
    let mut payload = vec![1u8]; // un seul signataire
    payload.extend_from_slice(&encode_path(path)?);
    payload.extend_from_slice(message);
    let response = send_chunked(transport, INS_SIGN, P1_CONFIRM, &payload)?;
    let signature: [u8; 64] = response.try_into().map_err(|_| anyhow!("signature Solana du Ledger mal formée"))?;
    VerifyingKey::from_bytes(expected)
        .map_err(|_| anyhow!("clé publique Solana invalide"))?
        .verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| anyhow!("la signature du Ledger ne correspond pas au compte attendu — transaction non diffusée"))?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder(Vec<(u8, u8, usize)>);
    impl Transport for Recorder {
        fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            self.0.push((apdu[2], apdu[3], apdu[4] as usize));
            Ok(vec![0x90, 0x00])
        }
    }

    /// Même découpage que `hw-app-solana` : 600 octets -> 255 (MORE), 255
    /// (EXTEND|MORE), 90 (EXTEND) ; un bloc unique -> P2 = 0.
    #[test]
    fn chunking_flags_match_hw_app_solana() {
        let mut t = Recorder(Vec::new());
        send_chunked(&mut t, INS_SIGN, P1_CONFIRM, &[0u8; 600]).unwrap();
        assert_eq!(t.0, vec![(0x01, 0x02, 255), (0x01, 0x03, 255), (0x01, 0x01, 90)]);
        let mut t = Recorder(Vec::new());
        send_chunked(&mut t, INS_GET_PUBKEY, P1_NON_CONFIRM, &[0u8; 13]).unwrap();
        assert_eq!(t.0, vec![(0x00, 0x00, 13)]);
    }

    /// Application Solana OFFICIELLE dans Speculos (graine de test publique) :
    /// clés publiques identiques à NOS dérivations (chemin Phantom
    /// m/44'/501'/0'/0' et chemin Ledger Live m/44'/501'/0'), puis un vrai
    /// virement construit par NOTRE code, signé après revue à l'écran (montant et
    /// destinataire affichés), signature vérifiée ; refus -> erreur claire.
    /// Speculos doit tourner avec `solana-nanosp.elf`.
    /// `cargo test -- --ignored ledger_solana_against_the_official_app_in_speculos --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn ledger_solana_against_the_official_app_in_speculos() {
        use super::super::{parse_path, speculos, TcpTransport};
        let mut t = TcpTransport::connect(speculos::APDU).unwrap();
        let seed = bip39::Mnemonic::parse(speculos::TEST_MNEMONIC).unwrap().to_seed("");

        let phantom = parse_path("44'/501'/0'/0'").unwrap();
        let device = get_pubkey(&mut t, &phantom, false).unwrap();
        assert_eq!(device, crate::derivation::derive_solana_key(&seed, 0).verifying_key().to_bytes());
        let ledger_live = parse_path("44'/501'/0'").unwrap();
        let device_ll = get_pubkey(&mut t, &ledger_live, false).unwrap();
        assert_eq!(device_ll, crate::derivation::derive_ed25519_path(&seed, &[44, 501, 0]).verifying_key().to_bytes());
        println!("clés Ledger = dérivations : {} / {}", bs58::encode(device).into_string(), bs58::encode(device_ll).into_string());

        // Virement de 0,0123 SOL construit par notre code (message legacy).
        let to = [0x44u8; 32];
        let dummy = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let tx = crate::sol_tx::build_and_sign_transaction(&dummy, &device_ll, &[crate::sol_tx::transfer_instruction(&device_ll, &to, 12_300_000)], &[7u8; 32]);
        let message = &tx[65..];
        let approver = std::thread::spawn(|| speculos::review_and_accept(&["Approve", "Sign transaction", "Accept"]));
        let signature = sign_transaction_message(&mut t, &ledger_live, message, &device_ll).unwrap();
        let screens = approver.join().unwrap().join(" | ");
        println!("écrans : {screens}");
        assert!(screens.contains("0.0123"), "montant affiché");
        assert!(screens.contains(&bs58::encode(to).into_string()[..8]), "destinataire affiché");
        assert_eq!(signature.len(), 64);

        let rejecter = std::thread::spawn(|| speculos::review_and_accept(&["Reject"]));
        let err = sign_transaction_message(&mut t, &ledger_live, message, &device_ll).unwrap_err();
        rejecter.join().unwrap();
        assert!(err.to_string().contains("refusée"), "{err}");
    }

    struct Status(u16);
    impl Transport for Status {
        fn exchange(&mut self, _apdu: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.to_be_bytes().to_vec())
        }
    }

    #[test]
    fn solana_specific_status_words() {
        let path = super::super::parse_path("44'/501'/0'").unwrap();
        let refused = sign_transaction_message(&mut Status(0x6982), &path, &[1, 2, 3], &[0; 32]).unwrap_err();
        assert!(refused.to_string().contains("refusée"), "0x6982 = refus de l'utilisateur pour Solana : {refused}");
        let blind = sign_transaction_message(&mut Status(0x6808), &path, &[1, 2, 3], &[0; 32]).unwrap_err();
        assert!(blind.to_string().contains("signature à l'aveugle"), "{blind}");
    }
}
