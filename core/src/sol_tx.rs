use ed25519_dalek::{Signer, SigningKey};

/// Program ID du System Program natif de Solana : 32 octets à zéro
/// (base58 : "11111111111111111111111111111111").
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Encodage "compact-u16" (shortvec) utilisé par Solana pour les longueurs de tableaux
/// dans le message d'une transaction (comparable à un varint LEB128 non signé).
fn write_shortvec_len(buf: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
            buf.push(byte);
        } else {
            buf.push(byte);
            break;
        }
    }
}

/// Construit et signe une transaction "legacy" de transfert SOL simple : un seul
/// signataire (l'expéditeur, qui paie aussi les frais), un destinataire, une
/// instruction "Transfer" du System Program. Suffisant pour le test "premier
/// virement devnet" du PoC.
pub fn build_transfer_transaction(
    signing_key: &SigningKey,
    from_pubkey: &[u8; 32],
    to_pubkey: &[u8; 32],
    lamports: u64,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    // Solana rejette une transaction où le même compte apparaît deux fois dans
    // account_keys ("AccountLoadedTwice") : en cas d'auto-virement (from == to),
    // on ne liste ce compte qu'une seule fois et l'instruction y référence l'index 0
    // à la fois comme source et destination.
    let self_transfer = from_pubkey == to_pubkey;

    let mut account_keys: Vec<&[u8; 32]> = vec![from_pubkey];
    let to_index: u8 = if self_transfer {
        0
    } else {
        account_keys.push(to_pubkey);
        1
    };
    let system_program_index = account_keys.len() as u8;
    account_keys.push(&SYSTEM_PROGRAM_ID);

    let mut message = Vec::new();

    // Header : 1 signature requise, 0 compte signé en lecture seule,
    // 1 compte non signé en lecture seule (le System Program).
    message.push(1);
    message.push(0);
    message.push(1);

    write_shortvec_len(&mut message, account_keys.len());
    for key in &account_keys {
        message.extend_from_slice(*key);
    }

    message.extend_from_slice(recent_blockhash);

    // Une seule instruction.
    write_shortvec_len(&mut message, 1);
    message.push(system_program_index);

    write_shortvec_len(&mut message, 2); // comptes utilisés : expéditeur(0), destinataire
    message.push(0);
    message.push(to_index);

    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(&2u32.to_le_bytes()); // variante "Transfer" du System Program
    ix_data.extend_from_slice(&lamports.to_le_bytes());
    write_shortvec_len(&mut message, ix_data.len());
    message.extend_from_slice(&ix_data);

    // ed25519 signe directement le message (pas de pré-hash comme pour ECDSA).
    let signature = signing_key.sign(&message);

    let mut tx = Vec::new();
    write_shortvec_len(&mut tx, 1); // une seule signature
    tx.extend_from_slice(&signature.to_bytes());
    tx.extend_from_slice(&message);
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn write_shortvec_len_boundaries() {
        let cases: [(usize, &[u8]); 4] = [(0, &[0x00]), (127, &[0x7f]), (128, &[0x80, 0x01]), (16384, &[0x80, 0x80, 0x01])];
        for (value, expected) in cases {
            let mut buf = Vec::new();
            write_shortvec_len(&mut buf, value);
            assert_eq!(buf, expected, "shortvec pour {value}");
        }
    }

    /// Test de non-régression pour le bug "AccountLoadedTwice" déjà rencontré :
    /// pour un virement entre deux comptes distincts, les 3 comptes (expéditeur,
    /// destinataire, System Program) doivent apparaître une seule fois chacun, et
    /// la signature ed25519 doit vérifier contre le message produit.
    #[test]
    fn transfer_between_distinct_accounts_lists_three_keys() {
        let key = test_key(1);
        let from = key.verifying_key().to_bytes();
        let to = [0x42u8; 32];
        let blockhash = [0x55u8; 32];

        let tx = build_transfer_transaction(&key, &from, &to, 1_000_000, &blockhash);

        assert_eq!(tx[0], 1, "un seul octet de compte de signatures attendu");
        let signature_bytes: [u8; 64] = tx[1..65].try_into().unwrap();
        let message = &tx[65..];

        // Header : 1 signataire requis, 0 compte signé en lecture seule, 1 compte
        // non signé en lecture seule (le System Program).
        assert_eq!(&message[0..3], &[1, 0, 1]);

        // 3 comptes distincts : expéditeur, destinataire, System Program.
        assert_eq!(message[3], 3);
        let keys_start = 4;
        assert_eq!(&message[keys_start..keys_start + 32], &from);
        assert_eq!(&message[keys_start + 32..keys_start + 64], &to);
        assert_eq!(&message[keys_start + 64..keys_start + 96], &SYSTEM_PROGRAM_ID);

        let blockhash_start = keys_start + 96;
        assert_eq!(&message[blockhash_start..blockhash_start + 32], &blockhash);

        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = VerifyingKey::from_bytes(&from).expect("clé publique valide");
        verifying_key
            .verify(message, &signature)
            .expect("la signature doit vérifier contre le message");
    }

    /// Auto-virement (from == to) : les comptes doivent être dédupliqués, sinon
    /// Solana rejette la transaction avec "AccountLoadedTwice" (bug déjà rencontré).
    #[test]
    fn self_transfer_deduplicates_account_keys() {
        let key = test_key(2);
        let from = key.verifying_key().to_bytes();
        let blockhash = [0x77u8; 32];

        let tx = build_transfer_transaction(&key, &from, &from, 500, &blockhash);
        let message = &tx[65..];

        // 2 comptes seulement (expéditeur/destinataire fusionnés + System Program),
        // jamais 3 avec un doublon.
        assert_eq!(message[3], 2);
        let keys_start = 4;
        assert_eq!(&message[keys_start..keys_start + 32], &from);
        assert_eq!(&message[keys_start + 32..keys_start + 64], &SYSTEM_PROGRAM_ID);
    }
}
