use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;

/// Program ID du System Program natif de Solana : 32 octets à zéro
/// (base58 : "11111111111111111111111111111111").
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// SPL Memo Program (v2) — vérifié contre le dépôt officiel
/// `solana-program`/`spl-memo`. Aucun compte requis pour une instruction memo,
/// juste des octets UTF-8 arbitraires en données (voir `swap` dans api.rs,
/// qui l'utilise pour transmettre le memo THORChain).
pub fn memo_program_id() -> [u8; 32] {
    crate::sol_spl::decode_pubkey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}

/// Encodage "compact-u16" (shortvec) utilisé par Solana pour les longueurs de tableaux
/// dans le message d'une transaction (comparable à un varint LEB128 non signé).
pub(crate) fn write_shortvec_len(buf: &mut Vec<u8>, mut len: usize) {
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

/// Une instruction Solana générique : quel programme, quels comptes (avec les
/// droits QUE CETTE instruction requiert), quelles données. Les droits requis
/// par des instructions différentes pour un même compte sont fusionnés (le
/// plus élevé l'emporte) par `build_and_sign_transaction` lors de la
/// construction du message.
pub struct Instruction {
    pub program_id: [u8; 32],
    /// (pubkey, is_signer, is_writable).
    pub accounts: Vec<([u8; 32], bool, bool)>,
    pub data: Vec<u8>,
}

/// Enregistre `key` avec ses droits dans l'ordre de première apparition
/// (`order`), en fusionnant les droits (OR logique) si la clé a déjà été vue —
/// une même clé référencée en writable par une instruction et en lecture
/// seule par une autre doit être classée writable au final, jamais l'inverse
/// (sous-évaluer un droit ferait rejeter la transaction par le réseau, jamais
/// l'accepter à tort : erreur toujours au sens le plus sûr).
fn note_account(key: [u8; 32], is_signer: bool, is_writable: bool, order: &mut Vec<[u8; 32]>, flags: &mut HashMap<[u8; 32], (bool, bool)>) {
    match flags.get_mut(&key) {
        Some((s, w)) => {
            *s |= is_signer;
            *w |= is_writable;
        }
        None => {
            order.push(key);
            flags.insert(key, (is_signer, is_writable));
        }
    }
}

/// Construit et signe un message Solana "legacy" à partir d'une ou plusieurs
/// instructions, en appliquant les règles réelles de tri des comptes de
/// Solana : chaque clé unique référencée (y compris le program_id de chaque
/// instruction, qui compte comme un compte non-signataire en lecture seule)
/// est dédoublonnée puis classée dans l'ordre [signataire+writable] ->
/// [signataire+lecture seule] -> [non-signataire+writable] ->
/// [non-signataire+lecture seule], l'ordre de première apparition étant
/// conservé au sein de chaque groupe. `payer` est forcé signataire+writable
/// et noté en premier : Solana exige que le payeur des frais soit le compte
/// à l'index 0 du message, ce que garantit cet ordre d'insertion.
///
/// Suppose exactement UN SEUL signataire (aucun cas multisig dans ce projet :
/// `payer` et le "owner" de chaque instruction sont toujours la même clé de
/// portefeuille) — vérifié explicitement plutôt que silencieusement supposé,
/// pour ne jamais produire une transaction avec plus de comptes signataires
/// que de signatures réellement apposées.
pub fn build_and_sign_transaction(signing_key: &SigningKey, payer: &[u8; 32], instructions: &[Instruction], recent_blockhash: &[u8; 32]) -> Vec<u8> {
    let mut order: Vec<[u8; 32]> = Vec::new();
    let mut flags: HashMap<[u8; 32], (bool, bool)> = HashMap::new();

    note_account(*payer, true, true, &mut order, &mut flags);
    for instruction in instructions {
        for (key, is_signer, is_writable) in &instruction.accounts {
            note_account(*key, *is_signer, *is_writable, &mut order, &mut flags);
        }
        note_account(instruction.program_id, false, false, &mut order, &mut flags);
    }

    let mut signer_writable = Vec::new();
    let mut signer_readonly = Vec::new();
    let mut nonsigner_writable = Vec::new();
    let mut nonsigner_readonly = Vec::new();
    for key in &order {
        match flags[key] {
            (true, true) => signer_writable.push(*key),
            (true, false) => signer_readonly.push(*key),
            (false, true) => nonsigner_writable.push(*key),
            (false, false) => nonsigner_readonly.push(*key),
        }
    }

    let num_required_signatures = signer_writable.len() + signer_readonly.len();
    assert_eq!(
        num_required_signatures, 1,
        "build_and_sign_transaction ne gère qu'un seul signataire (payer == owner de chaque instruction) ; {num_required_signatures} comptes signataires distincts trouvés"
    );
    let num_readonly_signed_accounts = signer_readonly.len() as u8;
    let num_readonly_unsigned_accounts = nonsigner_readonly.len() as u8;

    let mut account_keys: Vec<[u8; 32]> = Vec::new();
    account_keys.extend(signer_writable);
    account_keys.extend(signer_readonly);
    account_keys.extend(nonsigner_writable);
    account_keys.extend(nonsigner_readonly);

    let index_of = |key: &[u8; 32]| -> u8 {
        account_keys
            .iter()
            .position(|k| k == key)
            .expect("clé référencée par une instruction mais absente de account_keys (bug interne)") as u8
    };

    let mut message = Vec::new();
    message.push(num_required_signatures as u8);
    message.push(num_readonly_signed_accounts);
    message.push(num_readonly_unsigned_accounts);

    write_shortvec_len(&mut message, account_keys.len());
    for key in &account_keys {
        message.extend_from_slice(key);
    }

    message.extend_from_slice(recent_blockhash);

    write_shortvec_len(&mut message, instructions.len());
    for instruction in instructions {
        message.push(index_of(&instruction.program_id));
        write_shortvec_len(&mut message, instruction.accounts.len());
        for (key, _, _) in &instruction.accounts {
            message.push(index_of(key));
        }
        write_shortvec_len(&mut message, instruction.data.len());
        message.extend_from_slice(&instruction.data);
    }

    // ed25519 signe directement le message (pas de pré-hash comme pour ECDSA).
    let signature = signing_key.sign(&message);

    let mut tx = Vec::new();
    write_shortvec_len(&mut tx, 1); // une seule signature (voir l'assertion ci-dessus)
    tx.extend_from_slice(&signature.to_bytes());
    tx.extend_from_slice(&message);
    tx
}

/// Construit et signe une transaction "legacy" de transfert SOL simple : un seul
/// signataire (l'expéditeur, qui paie aussi les frais), un destinataire, une
/// instruction "Transfer" du System Program. Cas particulier (une seule
/// instruction) de `build_and_sign_transaction`.
/// Instruction "Transfer" du System Program — extraite de
/// `build_transfer_transaction` pour être combinable avec d'autres
/// instructions dans la même transaction (voir `api::send_swap_sol`, qui
/// l'associe à une instruction Memo pour un swap THORChain).
pub fn transfer_instruction(from_pubkey: &[u8; 32], to_pubkey: &[u8; 32], lamports: u64) -> Instruction {
    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(&2u32.to_le_bytes()); // variante "Transfer" du System Program
    ix_data.extend_from_slice(&lamports.to_le_bytes());

    // Le dédoublonnage automatique de `build_and_sign_transaction` (voir
    // `note_account`) gère seul le cas auto-virement (from == to) — plus
    // besoin de le détecter à la main comme avant ce refactor : les deux
    // rôles "source" et "destination" pointant vers la même clé fusionnent
    // en une seule entrée de compte, avec les droits combinés (writable).
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![(*from_pubkey, true, true), (*to_pubkey, false, true)],
        data: ix_data,
    }
}

pub fn build_transfer_transaction(
    signing_key: &SigningKey,
    from_pubkey: &[u8; 32],
    to_pubkey: &[u8; 32],
    lamports: u64,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let instruction = transfer_instruction(from_pubkey, to_pubkey, lamports);
    build_and_sign_transaction(signing_key, from_pubkey, &[instruction], recent_blockhash)
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

    /// Message à 2 instructions (nécessaire pour un envoi USDC : création
    /// idempotente de l'ATA destinataire + transfert), avec un cas de
    /// privilèges qui se chevauchent délibérément construit : `payer` est
    /// noté signataire+writable (compte payeur) par la 1ʳᵉ instruction, mais
    /// seulement signataire+lecture-seule ("owner" du transfert) par la 2ᵉ —
    /// exactement le cas réel de ce projet (payer == owner == la même clé de
    /// portefeuille). Le résultat doit classer `payer` une seule fois, en
    /// writable (le droit le plus élevé demandé), jamais deux fois ni en
    /// lecture seule. Re-découpe les octets bruts indépendamment (pas
    /// d'appel au code testé) et re-vérifie la signature, même style que les
    /// tests ci-dessus.
    #[test]
    fn multi_instruction_message_merges_overlapping_privileges_and_orders_accounts_correctly() {
        let key = test_key(3);
        let payer = key.verifying_key().to_bytes();
        let dest_ata = [0xCCu8; 32];
        let mint = [0xBBu8; 32];
        let prog_a = [0xA1u8; 32];
        let source_ata = [0xAAu8; 32];
        let prog_b = [0xB2u8; 32];
        let blockhash = [0x99u8; 32];

        // Instruction 1 ("CreateIdempotent"-like) : payer signataire+writable.
        let ix1 = Instruction {
            program_id: prog_a,
            accounts: vec![(payer, true, true), (dest_ata, false, true), (mint, false, false)],
            data: vec![1],
        };
        // Instruction 2 ("TransferChecked"-like) : payer référencé de nouveau,
        // mais seulement signataire+LECTURE SEULE cette fois — le droit final
        // doit rester writable (fusion = le plus élevé des deux).
        let ix2 = Instruction {
            program_id: prog_b,
            accounts: vec![(source_ata, false, true), (mint, false, false), (dest_ata, false, true), (payer, true, false)],
            data: vec![12, 1, 2, 3, 4, 5, 6, 7, 8, 6],
        };

        let tx = build_and_sign_transaction(&key, &payer, &[ix1, ix2], &blockhash);

        assert_eq!(tx[0], 1, "une seule signature attendue");
        let signature_bytes: [u8; 64] = tx[1..65].try_into().unwrap();
        let message = &tx[65..];

        // Header : 1 signataire requis, 0 signataire en lecture seule (payer
        // fusionné en writable), 3 comptes non-signataires en lecture seule
        // (mint, prog_a, prog_b).
        assert_eq!(&message[0..3], &[1, 0, 3], "header : payer doit être writable, jamais dégradé en lecture seule");

        // 6 comptes uniques attendus, dans l'ordre :
        // [payer] (signataire+writable)
        // [dest_ata, source_ata] (non-signataire+writable, ordre de première apparition)
        // [mint, prog_a, prog_b] (non-signataire+lecture seule, ordre de première apparition)
        assert_eq!(message[3], 6);
        let keys_start = 4;
        let key_at = |i: usize| -> &[u8] { &message[keys_start + i * 32..keys_start + (i + 1) * 32] };
        assert_eq!(key_at(0), &payer, "payer doit être en position 0 (payeur des frais)");
        assert_eq!(key_at(1), &dest_ata);
        assert_eq!(key_at(2), &source_ata);
        assert_eq!(key_at(3), &mint);
        assert_eq!(key_at(4), &prog_a);
        assert_eq!(key_at(5), &prog_b);

        let blockhash_start = keys_start + 6 * 32;
        assert_eq!(&message[blockhash_start..blockhash_start + 32], &blockhash);

        let ix_count_pos = blockhash_start + 32;
        assert_eq!(message[ix_count_pos], 2, "2 instructions attendues");

        // Instruction 1 : program_id index 4 (prog_a), comptes [0 (payer), 1 (dest_ata), 3 (mint)].
        let ix1_pos = ix_count_pos + 1;
        assert_eq!(message[ix1_pos], 4, "index de prog_a dans account_keys");
        assert_eq!(message[ix1_pos + 1], 3, "3 comptes utilisés par l'instruction 1");
        assert_eq!(&message[ix1_pos + 2..ix1_pos + 5], &[0, 1, 3]);
        assert_eq!(message[ix1_pos + 5], 1, "1 octet de données");
        assert_eq!(message[ix1_pos + 6], 1, "discriminant CreateIdempotent");

        // Instruction 2 : program_id index 5 (prog_b), comptes [2 (source_ata), 3 (mint), 1 (dest_ata), 0 (payer)].
        let ix2_pos = ix1_pos + 7;
        assert_eq!(message[ix2_pos], 5, "index de prog_b dans account_keys");
        assert_eq!(message[ix2_pos + 1], 4, "4 comptes utilisés par l'instruction 2");
        assert_eq!(&message[ix2_pos + 2..ix2_pos + 6], &[2, 3, 1, 0]);
        assert_eq!(message[ix2_pos + 6], 10, "10 octets de données");

        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = VerifyingKey::from_bytes(&payer).expect("clé publique valide");
        verifying_key
            .verify(message, &signature)
            .expect("la signature doit vérifier contre le message multi-instructions");
    }

    #[test]
    #[should_panic(expected = "un seul signataire")]
    fn build_and_sign_transaction_refuses_more_than_one_distinct_signer() {
        let key = test_key(4);
        let payer = key.verifying_key().to_bytes();
        let other_signer = [0xDDu8; 32]; // clé différente de payer, marquée signataire
        let ix = Instruction {
            program_id: [0xEEu8; 32],
            accounts: vec![(other_signer, true, false)],
            data: vec![],
        };
        build_and_sign_transaction(&key, &payer, &[ix], &[0u8; 32]);
    }
}
