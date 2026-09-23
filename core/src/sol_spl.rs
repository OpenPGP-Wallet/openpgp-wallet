//! Primitives SPL Token nécessaires pour l'USDC sur Solana : dérivation
//! d'Associated Token Account (PDA), et construction des instructions
//! "CreateIdempotent" (Associated Token Program) et "TransferChecked" (Token
//! Program). Toutes les constantes ci-dessous (mints, program IDs,
//! discriminants, ordre des comptes) ont été vérifiées contre des sources
//! publiques faisant autorité (documentation Circle/Solana, dépôt GitHub
//! officiel `solana-program-library`) avant d'être écrites ici — voir le plan
//! d'implémentation. La fonction de dérivation d'ATA reste néanmoins à
//! valider empiriquement contre une adresse réelle avant toute confiance pour
//! un envoi réel (voir son test).
//!
//! Mainnet uniquement (v1) : pas de mint USDC devnet vérifié avec confiance,
//! et aucun intérêt pratique à en tester un.

use crate::sol_tx::Instruction;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// Décode une clé publique Solana encodée en base58 — utilisé uniquement pour
/// les constantes ci-dessous (valeurs fixes, vérifiées), jamais pour une
/// entrée utilisateur (voir `derivation`/`wallet_flow` pour ça).
fn decode_pubkey(base58: &str) -> [u8; 32] {
    let bytes = bs58::decode(base58).into_vec().expect("constante base58 invalide (bug de compilation)");
    bytes.try_into().expect("une clé publique Solana fait 32 octets (bug de compilation)")
}

/// Mint USDC officiel sur Solana mainnet-beta (Circle) — vérifié contre la
/// documentation officielle Circle avant d'être inscrit ici.
pub fn usdc_mint_mainnet() -> [u8; 32] {
    decode_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
}

/// SPL Token Program (pas Token-2022) — vérifié contre le dépôt officiel
/// `solana-program-library`.
pub fn token_program_id() -> [u8; 32] {
    decode_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

/// Associated Token Program — vérifié contre le dépôt officiel
/// `solana-program-library`.
pub fn associated_token_program_id() -> [u8; 32] {
    decode_pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}

/// Sysvar Rent — requis dans la liste de comptes de l'instruction
/// Create/CreateIdempotent de l'Associated Token Program (compatibilité,
/// même si son contenu n'est plus vraiment lu par les versions récentes du
/// programme) — vérifié contre la documentation officielle.
pub fn sysvar_rent_id() -> [u8; 32] {
    decode_pubkey("SysvarRent111111111111111111111111111111111")
}

pub const USDC_DECIMALS: u8 = 6;

/// Implémentation de l'algorithme `find_program_address` de Solana (dérivation
/// de Program Derived Address) : essaie chaque `bump` de 255 à 0, candidat =
/// SHA256(seeds concaténées ++ [bump] ++ program_id ++ b"ProgramDerivedAddress"),
/// accepte le premier candidat qui n'est PAS un point valide sur la courbe
/// ed25519 (une PDA doit être délibérément hors-courbe : aucune clé privée ne
/// peut exister pour elle, garantissant que seul le programme désigné peut
/// "signer" pour ce compte via une invocation croisée, jamais une vraie paire
/// de clés). `CompressedEdwardsY::decompress()` renvoie `None` exactement
/// quand les 32 octets ne décodent pas en un point valide — c'est le test
/// utilisé ici.
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

/// Dérive l'Associated Token Account (ATA) de `owner` pour `mint` — seeds
/// `[owner, TOKEN_PROGRAM_ID, mint]`, program `ASSOCIATED_TOKEN_PROGRAM_ID`.
/// **À valider contre une adresse réelle avant toute confiance pour un envoi
/// réel** (voir le test `find_associated_token_address_matches_a_known_real_address`) :
/// une erreur ici produirait une adresse valide mais UNIQUE ET FAUSSE, donc
/// des fonds envoyés de façon irrécupérable.
pub fn find_associated_token_address(owner: &[u8; 32], mint: &[u8; 32]) -> [u8; 32] {
    let token_program = token_program_id();
    let program = associated_token_program_id();
    find_program_address(&[owner, &token_program, mint], &program)
        .expect("aucun bump valide trouvé entre 255 et 0 (probabilité astronomiquement improbable)")
}

/// Instruction "CreateIdempotent" (discriminant 1) de l'Associated Token
/// Program : crée l'ATA de `owner` pour `mint` si elle n'existe pas déjà, ne
/// fait rien silencieusement si elle existe déjà — nécessaire ici puisqu'on
/// ne sait jamais à l'avance si le destinataire a déjà reçu de l'USDC.
/// `payer` paie le rent de création (toujours l'expéditeur dans ce projet).
/// Comptes (vérifiés) : payer(signataire,writable), ata(writable),
/// owner(lecture seule), mint(lecture seule), system program(lecture seule),
/// token program(lecture seule), sysvar rent(lecture seule).
pub fn create_ata_idempotent_instruction(payer: &[u8; 32], owner: &[u8; 32], mint: &[u8; 32], ata: &[u8; 32]) -> Instruction {
    Instruction {
        program_id: associated_token_program_id(),
        accounts: vec![
            (*payer, true, true),
            (*ata, false, true),
            (*owner, false, false),
            (*mint, false, false),
            (crate::sol_tx::SYSTEM_PROGRAM_ID, false, false),
            (token_program_id(), false, false),
            (sysvar_rent_id(), false, false),
        ],
        data: vec![1], // discriminant CreateIdempotent (Create=0, CreateIdempotent=1)
    }
}

/// Instruction "TransferChecked" (discriminant 12) du Token Program —
/// préférée à "Transfer" (discriminant 3, sans vérification) car elle valide
/// on-chain que `mint`/`decimals` correspondent bien au compte source, une
/// garantie de sécurité supplémentaire cohérente avec le reste du projet
/// (voir la vérification de checksum EIP-55). Comptes (vérifiés) :
/// source ATA(writable), mint(lecture seule), destination ATA(writable),
/// owner(signataire).
pub fn transfer_checked_instruction(source_ata: &[u8; 32], mint: &[u8; 32], dest_ata: &[u8; 32], owner: &[u8; 32], amount: u64, decimals: u8) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program_id(),
        accounts: vec![(*source_ata, false, true), (*mint, false, false), (*dest_ata, false, true), (*owner, true, false)],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérification empirique obligatoire avant toute confiance dans
    /// `find_associated_token_address` pour un envoi réel. Vecteur de vérité
    /// obtenu en interrogeant le RPC mainnet réel en direct (lecture seule,
    /// `getTokenAccountsByOwner`) pour un portefeuille public existant qui
    /// détient effectivement de l'USDC — pas une supposition ni un exemple de
    /// documentation non confirmé :
    ///
    /// ```text
    /// owner = E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk
    /// mint  = EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (USDC)
    /// ATA   = 2gS6PA4z17TuboiWyowsHDzdMbhhb4v5GBGSXBQqLG2U
    /// ```
    ///
    /// Réponse RPC complète confirmant ce triplet (récupérée le 2026-09-21) :
    /// compte détenu par `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (Token
    /// Program), `space: 165`, `mint`/`owner` correspondant exactement,
    /// solde réel non nul (46775.731361 USDC) — donc un compte de jetons
    /// authentique, pas un artefact.
    #[test]
    fn find_associated_token_address_matches_a_verified_real_mainnet_account() {
        let owner = decode_pubkey("E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk");
        let mint = usdc_mint_mainnet();
        let expected_ata = decode_pubkey("2gS6PA4z17TuboiWyowsHDzdMbhhb4v5GBGSXBQqLG2U");

        let ata = find_associated_token_address(&owner, &mint);

        assert_eq!(ata, expected_ata, "l'ATA calculée doit correspondre exactement à celle du réseau réel");
        // Propriété structurelle en plus (pas un remplacement de la vérification
        // ci-dessus) : une PDA ne doit jamais être un point valide sur la courbe.
        assert!(CompressedEdwardsY(ata).decompress().is_none(), "une PDA doit être hors de la courbe ed25519");
    }

    /// Sans le test "hors-courbe", une inversion de la condition
    /// (`is_some()` au lieu de `is_none()`) passerait quand même le test
    /// ci-dessus par coïncidence si le premier bump testé (255) tombe déjà
    /// hors-courbe pour cette entrée précise. Ce test choisit délibérément des
    /// seeds/program_id arbitraires et vérifie juste que la fonction termine
    /// et renvoie systématiquement un résultat hors-courbe, quel que soit le
    /// nombre de bumps rejetés avant d'y arriver.
    #[test]
    fn find_program_address_always_returns_an_off_curve_point() {
        for i in 0u8..20 {
            let seed = [i; 32];
            let program = [i.wrapping_add(1); 32];
            let result = find_program_address(&[&seed], &program).expect("un bump valide doit exister");
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
