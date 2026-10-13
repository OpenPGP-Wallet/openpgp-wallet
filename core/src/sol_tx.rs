use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;

/// Program ID of Solana's native System Program: 32 zero bytes (base58:
/// "11111111111111111111111111111111").
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// SPL Memo Program (v2), checked against the official `solana-program`/`spl-memo`
/// repository. A memo instruction needs no accounts, just arbitrary UTF-8 bytes as
/// data (see `swap` in api.rs, which uses it to carry the THORChain memo).
pub fn memo_program_id() -> [u8; 32] {
    crate::sol_spl::decode_pubkey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}

/// "compact-u16" (shortvec) encoding, used by Solana for array lengths inside a
/// transaction message (similar to an unsigned LEB128 varint).
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

/// A generic Solana instruction: which program, which accounts (with the
/// permissions THIS instruction needs), which data. When different instructions
/// need different permissions on the same account, `build_and_sign_transaction`
/// merges them (the highest wins) while building the message.
pub struct Instruction {
    pub program_id: [u8; 32],
    /// (pubkey, is_signer, is_writable).
    pub accounts: Vec<([u8; 32], bool, bool)>,
    pub data: Vec<u8>,
}

/// Records `key` with its permissions in order of first appearance (`order`),
/// merging the permissions (logical OR) if the key was already seen. A key
/// referenced as writable by one instruction and read-only by another must end up
/// writable, never the other way round (understating a permission would make the
/// network reject the transaction, never wrongly accept it: the error always falls
/// on the safe side).
fn note_account(
    key: [u8; 32],
    is_signer: bool,
    is_writable: bool,
    order: &mut Vec<[u8; 32]>,
    flags: &mut HashMap<[u8; 32], (bool, bool)>,
) {
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

/// Builds and signs a "legacy" Solana message from one or more instructions,
/// following Solana's actual account ordering rules: every unique key referenced
/// (including each instruction's program_id, which counts as a read-only non-signer
/// account) is deduplicated, then sorted into [signer+writable] ->
/// [signer+read-only] -> [non-signer+writable] -> [non-signer+read-only], keeping
/// the order of first appearance within each group. `payer` is forced to
/// signer+writable and recorded first: Solana requires the fee payer to be the
/// account at index 0 of the message, which this insertion order guarantees.
///
/// Assumes exactly ONE signer (there is no multisig in this project: `payer` and
/// the "owner" of every instruction are always the same wallet key). This is
/// checked explicitly rather than silently assumed, so we never produce a
/// transaction with more signer accounts than signatures actually attached.
pub fn build_and_sign_transaction(
    signing_key: &SigningKey,
    payer: &[u8; 32],
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let message = build_message(payer, instructions, recent_blockhash);
    // ed25519 signs the message directly (no pre-hashing, unlike ECDSA).
    let signature = signing_key.sign(&message);
    assemble_transaction(&signature.to_bytes(), &message)
}

/// The message (the signed part) of `build_and_sign_transaction`, without the
/// signature: this is what a hardware wallet receives to display and then sign (see
/// `ledger::solana`).
pub fn build_message(
    payer: &[u8; 32],
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
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

    let index_of =
        |key: &[u8; 32]| -> u8 {
            account_keys.iter().position(|k| k == key).expect(
                "clé référencée par une instruction mais absente de account_keys (bug interne)",
            ) as u8
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

    message
}

/// A complete single-signer transaction: the signature, then the message.
pub fn assemble_transaction(signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut tx = Vec::new();
    write_shortvec_len(&mut tx, 1); // a single signature (see the assertion in `build_message`)
    tx.extend_from_slice(signature);
    tx.extend_from_slice(message);
    tx
}

/// System Program "Transfer" instruction, kept separate so it can be combined with
/// other instructions in the same transaction (see `api::send_swap_sol`, which
/// pairs it with a Memo instruction for a THORChain swap).
pub fn transfer_instruction(
    from_pubkey: &[u8; 32],
    to_pubkey: &[u8; 32],
    lamports: u64,
) -> Instruction {
    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(&2u32.to_le_bytes()); // System Program "Transfer" variant
    ix_data.extend_from_slice(&lamports.to_le_bytes());

    // The automatic deduplication in `build_and_sign_transaction` (see `note_account`)
    // handles the self-transfer case (from == to) on its own; there is no longer any
    // need to detect it by hand as before the refactor. The "source" and "destination"
    // roles point to the same key and merge into a single account entry with the
    // combined permissions (writable).
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![(*from_pubkey, true, true), (*to_pubkey, false, true)],
        data: ix_data,
    }
}

/// Builds and signs a simple "legacy" SOL transfer: a single signer (the sender, who
/// also pays the fee), one recipient, one System Program "Transfer" instruction. The
/// single-instruction case of `build_and_sign_transaction`.
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
        let cases: [(usize, &[u8]); 4] = [
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16384, &[0x80, 0x80, 0x01]),
        ];
        for (value, expected) in cases {
            let mut buf = Vec::new();
            write_shortvec_len(&mut buf, value);
            assert_eq!(buf, expected, "shortvec pour {value}");
        }
    }

    /// Regression test for the "AccountLoadedTwice" bug we already hit: for a transfer
    /// between two distinct accounts, the 3 accounts (sender, recipient, System
    /// Program) must each appear exactly once, and the ed25519 signature must verify
    /// against the message produced.
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

        // Header: 1 required signer, 0 read-only signed accounts, 1 read-only unsigned
        // account (the System Program).
        assert_eq!(&message[0..3], &[1, 0, 1]);

        // 3 distinct accounts: sender, recipient, System Program.
        assert_eq!(message[3], 3);
        let keys_start = 4;
        assert_eq!(&message[keys_start..keys_start + 32], &from);
        assert_eq!(&message[keys_start + 32..keys_start + 64], &to);
        assert_eq!(
            &message[keys_start + 64..keys_start + 96],
            &SYSTEM_PROGRAM_ID
        );

        let blockhash_start = keys_start + 96;
        assert_eq!(&message[blockhash_start..blockhash_start + 32], &blockhash);

        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = VerifyingKey::from_bytes(&from).expect("clé publique valide");
        verifying_key
            .verify(message, &signature)
            .expect("la signature doit vérifier contre le message");
    }

    /// Self-transfer (from == to): the accounts must be deduplicated, otherwise Solana
    /// rejects the transaction with "AccountLoadedTwice" (a bug we already hit).
    #[test]
    fn self_transfer_deduplicates_account_keys() {
        let key = test_key(2);
        let from = key.verifying_key().to_bytes();
        let blockhash = [0x77u8; 32];

        let tx = build_transfer_transaction(&key, &from, &from, 500, &blockhash);
        let message = &tx[65..];

        // Only 2 accounts (sender/recipient merged, plus the System Program), never 3 with
        // a duplicate.
        assert_eq!(message[3], 2);
        let keys_start = 4;
        assert_eq!(&message[keys_start..keys_start + 32], &from);
        assert_eq!(
            &message[keys_start + 32..keys_start + 64],
            &SYSTEM_PROGRAM_ID
        );
    }

    /// A message with 2 instructions (needed to send USDC: idempotent creation of the
    /// recipient's ATA, then the transfer), built on purpose with overlapping
    /// permissions: `payer` is recorded as signer+writable (fee payer) by the 1st
    /// instruction, but only as signer+read-only (the transfer's "owner") by the 2nd.
    /// That is exactly the real case in this project (payer == owner == the same wallet
    /// key). The result must list `payer` once, as writable (the highest permission
    /// requested), never twice and never as read-only. The raw bytes are re-parsed
    /// independently (without calling the code under test) and the signature is
    /// re-verified, in the same style as the tests above.
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

        // Instruction 1 ("CreateIdempotent"-like): payer is signer+writable.
        let ix1 = Instruction {
            program_id: prog_a,
            accounts: vec![
                (payer, true, true),
                (dest_ata, false, true),
                (mint, false, false),
            ],
            data: vec![1],
        };
        // Instruction 2 ("TransferChecked"-like): payer is referenced again, but only as
        // signer+READ-ONLY this time. The final permission must stay writable (merging
        // keeps the higher of the two).
        let ix2 = Instruction {
            program_id: prog_b,
            accounts: vec![
                (source_ata, false, true),
                (mint, false, false),
                (dest_ata, false, true),
                (payer, true, false),
            ],
            data: vec![12, 1, 2, 3, 4, 5, 6, 7, 8, 6],
        };

        let tx = build_and_sign_transaction(&key, &payer, &[ix1, ix2], &blockhash);

        assert_eq!(tx[0], 1, "une seule signature attendue");
        let signature_bytes: [u8; 64] = tx[1..65].try_into().unwrap();
        let message = &tx[65..];

        // Header: 1 required signer, 0 read-only signers (payer merged as writable), 3
        // read-only non-signer accounts (mint, prog_a, prog_b).
        assert_eq!(
            &message[0..3],
            &[1, 0, 3],
            "header : payer doit être writable, jamais dégradé en lecture seule"
        );

        // 6 unique accounts expected, in this order:
        // - [payer] (signer+writable)
        // - [dest_ata, source_ata] (non-signer+writable, order of first appearance)
        // - [mint, prog_a, prog_b] (non-signer+read-only, order of first appearance)
        assert_eq!(message[3], 6);
        let keys_start = 4;
        let key_at =
            |i: usize| -> &[u8] { &message[keys_start + i * 32..keys_start + (i + 1) * 32] };
        assert_eq!(
            key_at(0),
            &payer,
            "payer doit être en position 0 (payeur des frais)"
        );
        assert_eq!(key_at(1), &dest_ata);
        assert_eq!(key_at(2), &source_ata);
        assert_eq!(key_at(3), &mint);
        assert_eq!(key_at(4), &prog_a);
        assert_eq!(key_at(5), &prog_b);

        let blockhash_start = keys_start + 6 * 32;
        assert_eq!(&message[blockhash_start..blockhash_start + 32], &blockhash);

        let ix_count_pos = blockhash_start + 32;
        assert_eq!(message[ix_count_pos], 2, "2 instructions attendues");

        // Instruction 1: program_id index 4 (prog_a), accounts [0 (payer), 1 (dest_ata), 3 (mint)].
        let ix1_pos = ix_count_pos + 1;
        assert_eq!(message[ix1_pos], 4, "index de prog_a dans account_keys");
        assert_eq!(
            message[ix1_pos + 1],
            3,
            "3 comptes utilisés par l'instruction 1"
        );
        assert_eq!(&message[ix1_pos + 2..ix1_pos + 5], &[0, 1, 3]);
        assert_eq!(message[ix1_pos + 5], 1, "1 octet de données");
        assert_eq!(message[ix1_pos + 6], 1, "discriminant CreateIdempotent");

        // Instruction 2: program_id index 5 (prog_b), accounts [2 (source_ata), 3 (mint), 1 (dest_ata), 0 (payer)].
        let ix2_pos = ix1_pos + 7;
        assert_eq!(message[ix2_pos], 5, "index de prog_b dans account_keys");
        assert_eq!(
            message[ix2_pos + 1],
            4,
            "4 comptes utilisés par l'instruction 2"
        );
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
        let other_signer = [0xDDu8; 32]; // a key other than payer, marked as signer
        let ix = Instruction {
            program_id: [0xEEu8; 32],
            accounts: vec![(other_signer, true, false)],
            data: vec![],
        };
        build_and_sign_transaction(&key, &payer, &[ix], &[0u8; 32]);
    }
}
