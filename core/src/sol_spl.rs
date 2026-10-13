//! SPL Token primitives needed for USDC on Solana: Associated Token Account (PDA)
//! derivation, and building the "CreateIdempotent" (Associated Token Program) and
//! "TransferChecked" (Token Program) instructions. Every constant below (mints,
//! program IDs, discriminators, account order) was checked against authoritative
//! public sources (Circle/Solana documentation, the official
//! `solana-program-library` GitHub repository) before being written here. The ATA
//! derivation is also checked empirically against a real address (see its test).
//!
//! Mainnet only: there is no devnet USDC mint we could verify with confidence, and
//! no practical value in testing one.

use crate::sol_tx::Instruction;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// Decodes a base58-encoded Solana public key. Only used for the constants below
/// (fixed, verified values), never for user input (see `derivation`/`wallet_flow`
/// for that).
pub(crate) fn decode_pubkey(base58: &str) -> [u8; 32] {
    let bytes = bs58::decode(base58)
        .into_vec()
        .expect("constante base58 invalide (bug de compilation)");
    bytes
        .try_into()
        .expect("une clé publique Solana fait 32 octets (bug de compilation)")
}

/// Official USDC mint on Solana mainnet-beta (Circle), checked against Circle's
/// official documentation before being written here.
pub fn usdc_mint_mainnet() -> [u8; 32] {
    decode_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
}

/// SPL Token Program (not Token-2022), checked against the official
/// `solana-program-library` repository.
pub fn token_program_id() -> [u8; 32] {
    decode_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

/// Token-2022 program (tokens with extensions: xStocks). Same identifier as
/// `api::TOKEN_2022_PROGRAM_ID`, confirmed on-chain as the owner of the xStocks
/// mints (2026-10-09).
pub fn token_2022_program_id() -> [u8; 32] {
    decode_pubkey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}

/// Associated Token Program, checked against the official `solana-program-library`
/// repository.
pub fn associated_token_program_id() -> [u8; 32] {
    decode_pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}

/// Rent sysvar: required in the account list of the Associated Token Program's
/// Create/CreateIdempotent instruction (for compatibility, even though recent
/// versions of the program no longer really read it). Checked against the official
/// documentation.
pub fn sysvar_rent_id() -> [u8; 32] {
    decode_pubkey("SysvarRent111111111111111111111111111111111")
}

pub const USDC_DECIMALS: u8 = 6;

/// `true` if `pubkey` is a real point on the ed25519 curve, i.e. a public key for
/// which a private key CAN exist. An off-curve address (a PDA, derived from a
/// program) has no private key by construction.
pub fn is_on_curve(pubkey: &[u8; 32]) -> bool {
    CompressedEdwardsY(*pubkey).decompress().is_some()
}

/// Solana's `find_program_address` (Program Derived Address derivation): tries each
/// `bump` from 255 down to 0, with candidate =
/// SHA256(concatenated seeds ++ [bump] ++ program_id ++ b"ProgramDerivedAddress"),
/// and accepts the first candidate that is NOT a valid point on the ed25519 curve. A
/// PDA must be off-curve on purpose: no private key can exist for it, so only the
/// designated program can "sign" for the account through a cross-program invocation,
/// never a real key pair. `CompressedEdwardsY::decompress()` returns `None` exactly
/// when the 32 bytes do not decode to a valid point, which is the test used here.
fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<[u8; 32]> {
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = hasher.finalize().into();
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return Some(candidate);
        }
    }
    None
}

/// Derives the Associated Token Account (ATA) of `owner` for `mint`: seeds `[owner,
/// TOKEN_PROGRAM_ID, mint]`, program `ASSOCIATED_TOKEN_PROGRAM_ID`. **Checked against a
/// real address** (see the test
/// `find_associated_token_address_matches_a_known_real_address`): a mistake here would
/// produce a valid but UNIQUE AND WRONG address, so funds sent there would be lost for
/// good.
pub fn find_associated_token_address(owner: &[u8; 32], mint: &[u8; 32]) -> [u8; 32] {
    find_associated_token_address_for(owner, mint, &token_program_id())
}

/// `find_associated_token_address` for the token program `token_program` (Token or
/// Token-2022: the program is part of the seeds, so the address differs; see the
/// test on a real xStocks account).
pub fn find_associated_token_address_for(
    owner: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
) -> [u8; 32] {
    let program = associated_token_program_id();
    find_program_address(&[owner, token_program, mint], &program)
        .expect("aucun bump valide trouvé entre 255 et 0 (probabilité astronomiquement improbable)")
}

/// Associated Token Program "CreateIdempotent" instruction (discriminator 1):
/// creates the ATA of `owner` for `mint` if it does not exist yet, and silently
/// does nothing if it does. Needed here since we never know in advance whether the
/// recipient has already received USDC. `payer` pays the creation rent (always the
/// sender in this project). Accounts (verified): payer (signer, writable), ata
/// (writable), owner (read-only), mint (read-only), system program (read-only),
/// token program (read-only), rent sysvar (read-only).
pub fn create_ata_idempotent_instruction(
    payer: &[u8; 32],
    owner: &[u8; 32],
    mint: &[u8; 32],
    ata: &[u8; 32],
) -> Instruction {
    create_ata_idempotent_instruction_for(payer, owner, mint, ata, &token_program_id())
}

/// `create_ata_idempotent_instruction` for the token program `token_program`
/// (Token-2022: the account created carries the extensions the mint requires, so
/// its size and rent are larger).
pub fn create_ata_idempotent_instruction_for(
    payer: &[u8; 32],
    owner: &[u8; 32],
    mint: &[u8; 32],
    ata: &[u8; 32],
    token_program: &[u8; 32],
) -> Instruction {
    Instruction {
        program_id: associated_token_program_id(),
        accounts: vec![
            (*payer, true, true),
            (*ata, false, true),
            (*owner, false, false),
            (*mint, false, false),
            (crate::sol_tx::SYSTEM_PROGRAM_ID, false, false),
            (*token_program, false, false),
            (sysvar_rent_id(), false, false),
        ],
        data: vec![1], // CreateIdempotent discriminator (Create=0, CreateIdempotent=1)
    }
}

/// Token Program "TransferChecked" instruction (discriminator 12). Preferred over
/// "Transfer" (discriminator 3, unchecked) because it validates on-chain that
/// `mint`/`decimals` match the source account, an extra safety guarantee in line
/// with the rest of the project (see the EIP-55 checksum check). Accounts
/// (verified): source ATA (writable), mint (read-only), destination ATA (writable),
/// owner (signer).
pub fn transfer_checked_instruction(
    source_ata: &[u8; 32],
    mint: &[u8; 32],
    dest_ata: &[u8; 32],
    owner: &[u8; 32],
    amount: u64,
    decimals: u8,
) -> Instruction {
    transfer_checked_instruction_for(
        source_ata,
        mint,
        dest_ata,
        owner,
        amount,
        decimals,
        &token_program_id(),
    )
}

/// `transfer_checked_instruction` for the token program `token_program` (same
/// instruction and same accounts for Token-2022, with no extra account as long as
/// the mint has no transfer hook program).
pub fn transfer_checked_instruction_for(
    source_ata: &[u8; 32],
    mint: &[u8; 32],
    dest_ata: &[u8; 32],
    owner: &[u8; 32],
    amount: u64,
    decimals: u8,
    token_program: &[u8; 32],
) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            (*source_ata, false, true),
            (*mint, false, false),
            (*dest_ata, false, true),
            (*owner, true, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mandatory empirical check before `find_associated_token_address` can be trusted
    /// for a real send. The ground truth comes from querying the real mainnet RPC live
    /// (read-only, `getTokenAccountsByOwner`) for an existing public wallet that
    /// actually holds USDC, not from a guess or an unconfirmed documentation example:
    ///
    /// ```text owner = E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk mint =
    /// EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (USDC) ATA =
    /// 2gS6PA4z17TuboiWyowsHDzdMbhhb4v5GBGSXBQqLG2U ```
    ///
    /// Full RPC response confirming this triplet (fetched on 2026-09-21): account owned
    /// by `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (Token Program), `space: 165`,
    /// `mint`/`owner` matching exactly, real non-zero balance (46775.731361 USDC), so a
    /// genuine token account, not an artifact.
    #[test]
    fn find_associated_token_address_matches_a_verified_real_mainnet_account() {
        let owner = decode_pubkey("E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk");
        let mint = usdc_mint_mainnet();
        let expected_ata = decode_pubkey("2gS6PA4z17TuboiWyowsHDzdMbhhb4v5GBGSXBQqLG2U");

        let ata = find_associated_token_address(&owner, &mint);

        assert_eq!(
            ata, expected_ata,
            "l'ATA calculée doit correspondre exactement à celle du réseau réel"
        );
        // An extra structural property (not a replacement for the check above): a PDA must
        // never be a valid point on the curve.
        assert!(
            CompressedEdwardsY(ata).decompress().is_none(),
            "une PDA doit être hors de la courbe ed25519"
        );
    }

    /// Same check for Token-2022, on a real xStocks account read on-chain on 2026-10-09
    /// (balances from a recent transaction of the TSLAx mint: an ordinary wallet, on
    /// the curve; the derivation found 7 of the 9 accounts listed, the other 2 not
    /// being associated accounts):
    ///
    /// ```text owner = GLMD3nt75DqvnJXpEXuSTy6jug3NmSnUNFYbVCVy19JB mint =
    /// XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB (Tesla xStock) ATA =
    /// D8mtDK8cHzAKbFiEuhD42MqXYZ13Qu2sR5bBQxRnNJwd ```
    ///
    /// The program is part of the seeds: derived with the legacy program, the address
    /// would be different (an account that does not exist, balance read as 0).
    #[test]
    fn token_2022_associated_address_matches_a_real_xstocks_account() {
        let owner = decode_pubkey("GLMD3nt75DqvnJXpEXuSTy6jug3NmSnUNFYbVCVy19JB");
        let mint = decode_pubkey("XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB");
        let expected = decode_pubkey("D8mtDK8cHzAKbFiEuhD42MqXYZ13Qu2sR5bBQxRnNJwd");
        assert_eq!(
            find_associated_token_address_for(&owner, &mint, &token_2022_program_id()),
            expected
        );
        assert_ne!(find_associated_token_address(&owner, &mint), expected);
    }

    /// Token-2022 instructions: same encoding, with the program and the program account
    /// swapped.
    #[test]
    fn token_2022_instructions_target_the_token_2022_program() {
        let (a, b, c, d) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        let program = token_2022_program_id();
        let create = create_ata_idempotent_instruction_for(&a, &b, &c, &d, &program);
        assert_eq!(create.program_id, associated_token_program_id());
        assert_eq!(create.accounts[5], (program, false, false));
        let transfer = transfer_checked_instruction_for(&a, &b, &c, &d, 42, 8, &program);
        assert_eq!(transfer.program_id, program);
        assert_eq!(
            transfer.data,
            transfer_checked_instruction(&a, &b, &c, &d, 42, 8).data
        );
    }

    /// Without the "off-curve" test, an inverted condition (`is_some()` instead of
    /// `is_none()`) could still pass the test above by coincidence if the first bump
    /// tried (255) already lands off-curve for that exact input. This test deliberately
    /// picks arbitrary seeds/program_id and simply checks that the function terminates
    /// and always returns an off-curve result, however many bumps it rejects before
    /// getting there.
    #[test]
    fn find_program_address_always_returns_an_off_curve_point() {
        for i in 0u8..20 {
            let seed = [i; 32];
            let program = [i.wrapping_add(1); 32];
            let result =
                find_program_address(&[&seed], &program).expect("un bump valide doit exister");
            assert!(CompressedEdwardsY(result).decompress().is_none());
        }
    }

    #[test]
    fn create_ata_idempotent_instruction_has_seven_accounts_and_discriminant_one() {
        let payer = [1u8; 32];
        let owner = [2u8; 32];
        let mint = [3u8; 32];
        let ata = [4u8; 32];
        let ix = create_ata_idempotent_instruction(&payer, &owner, &mint, &ata);
        assert_eq!(ix.data, vec![1]);
        assert_eq!(ix.accounts.len(), 7);
        assert_eq!(ix.accounts[0], (payer, true, true));
        assert_eq!(ix.accounts[1], (ata, false, true));
    }

    #[test]
    fn transfer_checked_instruction_encodes_discriminant_amount_and_decimals() {
        let source = [1u8; 32];
        let mint = [2u8; 32];
        let dest = [3u8; 32];
        let owner = [4u8; 32];
        let ix = transfer_checked_instruction(&source, &mint, &dest, &owner, 1_500_000, 6);
        assert_eq!(ix.data[0], 12);
        assert_eq!(&ix.data[1..9], &1_500_000u64.to_le_bytes());
        assert_eq!(ix.data[9], 6);
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts[3], (owner, true, false));
    }
}
