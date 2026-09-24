//! Client Jupiter minimal : swap SOL <-> USDC (même chaîne, contrairement au
//! swap cross-chain via THORChain — voir thorchain_rpc.rs). Jupiter renvoie
//! une transaction Solana déjà entièrement construite (message v0, avec table
//! de correspondance d'adresses) plutôt que des instructions à assembler
//! nous-mêmes : contrairement au reste de ce projet ("from scratch"), on ne
//! reconstruit pas ce message à la main — le faire correctement demanderait
//! de résoudre soi-même le contenu des "address lookup tables" (vérifié
//! empiriquement : même la route la plus simple, un seul market direct, en
//! utilise une), un nouveau sous-système à part entière et une source
//! d'erreur au moins aussi risquée que de faire confiance à la transaction
//! déjà construite par Jupiter.
//!
//! Le seul geste effectué ici sur cette transaction : la signer. Avant ça,
//! `verify_fee_payer` vérifie que le premier compte du message (le payeur des
//! frais / premier signataire) est bien NOTRE PROPRE clé — un garde-fou
//! minimal mais réel contre une réponse malformée ou inattendue.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// Offre gratuite de l'API Jupiter, sans clé requise — vérifiée par un appel
/// réel avant d'être inscrite ici (quote + swap-instructions/swap testés en
/// direct, réponses conformes à ce qui suit).
const JUPITER_BASE: &str = "https://lite-api.jup.ag";

pub const SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Adresse Solana qui reçoit les frais de plateforme de CHAQUE swap Jupiter
/// effectué depuis cette app, quelle que soit l'installation qui le déclenche
/// — une seule adresse fixe (celle du développeur), pas une adresse dérivée
/// par installation (sinon chaque utilisateur se paierait à lui-même), même
/// principe que `thorchain_rpc::AFFILIATE_ADDRESS`. Fournie par l'utilisateur
/// lui-même (sa propre adresse Solana, déjà affichée dans l'app) plutôt que
/// dérivée : contrairement à THORChain, Solana est un réseau que cette app
/// gère déjà nativement, aucune dérivation supplémentaire n'est nécessaire.
pub const AFFILIATE_ADDRESS: &str = "F1YBYFJWBteTwi5eS5BjdSy3xDGGv8bhHBJ54n78nzdc";

/// 80 points de base = 0,80 %. Toujours prélevé en USDC (le compte de frais
/// est l'ATA USDC de `AFFILIATE_ADDRESS`) — valide dans les deux sens
/// (SOL->USDC ou USDC->SOL) puisque l'USDC est systématiquement soit l'actif
/// d'entrée soit celui de sortie, la seule contrainte imposée par Jupiter
/// pour un swap "ExactIn" (voir sa doc : le compte de frais doit avoir le
/// mint de l'un des deux actifs du swap).
pub const AFFILIATE_FEE_BPS: u32 = 80;

pub struct JupiterQuote {
    /// Réponse de devis brute, à retransmettre TELLE QUELLE à `/swap` (Jupiter
    /// s'attend à recevoir exactement l'objet qu'il a renvoyé, pas une
    /// reconstruction) — jamais modifiée ni reconstruite ici.
    raw: Value,
    /// Montant de sortie attendu, dans la plus petite unité de l'actif de
    /// destination — extrait juste pour l'affichage.
    pub out_amount: u64,
}

/// `amount` dans la plus petite unité de l'actif source (lamports pour SOL,
/// micro-USDC pour l'USDC). `slippage_bps` : tolérance de glissement de prix,
/// en points de base (ex: 50 = 0,50 %).
pub fn quote(input_mint: &str, output_mint: &str, amount: u64, slippage_bps: u32) -> Result<JupiterQuote> {
    let url = format!(
        "{JUPITER_BASE}/swap/v1/quote?inputMint={input_mint}&outputMint={output_mint}&amount={amount}&slippageBps={slippage_bps}&platformFeeBps={AFFILIATE_FEE_BPS}"
    );
    let raw: Value = shared_client()
        .get(&url)
        .send()
        .context("requête de devis Jupiter impossible")?
        .json()
        .context("réponse de devis Jupiter illisible")?;

    if let Some(error) = raw.get("error").and_then(Value::as_str) {
        anyhow::bail!("devis Jupiter refusé : {error}");
    }

    let out_amount = raw
        .get("outAmount")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("devis Jupiter sans montant de sortie"))?
        .parse::<u64>()
        .context("montant de sortie Jupiter illisible")?;

    Ok(JupiterQuote { raw, out_amount })
}

#[derive(Deserialize)]
struct SwapResponseJson {
    #[serde(rename = "swapTransaction")]
    swap_transaction: Option<String>,
    error: Option<String>,
}

/// Construit la transaction de swap (encore NON SIGNÉE, emplacement de
/// signature à zéro) — voir la doc du module : jamais reconstruite à la main,
/// seulement signée telle quelle après vérification du payeur de frais.
pub fn build_swap_transaction(quote: &JupiterQuote, user_pubkey: &str) -> Result<Vec<u8>> {
    // Compte de frais = l'ATA USDC de l'adresse d'affiliation (voir sa doc) —
    // Jupiter le crée lui-même via une instruction de préparation s'il
    // n'existe pas encore (même mécanisme que pour le compte de jetons de
    // l'utilisateur), aucune étape préalable nécessaire ici.
    let affiliate_owner_bytes = bs58::decode(AFFILIATE_ADDRESS)
        .into_vec()
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .context("adresse d'affiliation Jupiter mal formée (bug de compilation)")?;
    let fee_ata = crate::sol_spl::find_associated_token_address(&affiliate_owner_bytes, &crate::sol_spl::usdc_mint_mainnet());
    let fee_account = bs58::encode(fee_ata).into_string();

    let body = serde_json::json!({
        "quoteResponse": quote.raw,
        "userPublicKey": user_pubkey,
        "feeAccount": fee_account,
        // Enveloppe/désenveloppe automatiquement le SOL natif en wSOL le
        // temps du swap (obligatoire pour swapper depuis/vers du SOL natif,
        // qui n'est pas lui-même un jeton SPL) — comportement par défaut de
        // Jupiter, explicité ici pour ne pas dépendre d'une valeur implicite.
        "wrapAndUnwrapSol": true,
    });
    let response: SwapResponseJson = shared_client()
        .post(format!("{JUPITER_BASE}/swap/v1/swap"))
        .json(&body)
        .send()
        .context("requête de construction de swap Jupiter impossible")?
        .json()
        .context("réponse de swap Jupiter illisible")?;

    if let Some(error) = response.error {
        anyhow::bail!("construction du swap Jupiter refusée : {error}");
    }
    let swap_transaction = response.swap_transaction.ok_or_else(|| anyhow!("réponse de swap Jupiter sans transaction"))?;
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, swap_transaction)
        .context("transaction Jupiter illisible (base64 invalide)")
}

/// Lit un entier "compact-u16" (shortvec) tel qu'utilisé par le format de
/// message Solana — lecture, symétrique de `sol_tx::write_shortvec_len`
/// (qui ne fait qu'écrire). Nécessaire ici pour localiser le premier compte
/// du message (le payeur de frais) sans avoir à tout désérialiser.
fn read_shortvec_len(bytes: &[u8]) -> Result<(usize, usize)> {
    let mut len = 0usize;
    let mut shift = 0u32;
    for (i, &byte) in bytes.iter().enumerate().take(3) {
        len |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((len, i + 1));
        }
        shift += 7;
    }
    Err(anyhow!("longueur shortvec illisible"))
}

/// Découpe une transaction Solana brute (non signée, un seul emplacement de
/// signature) en (offset de début du message, message emprunté). Rejette
/// toute transaction demandant plus d'un signataire : ce projet ne construit
/// jamais de swap multi-signataires, une telle réponse serait inattendue et
/// mieux vaut échouer bruyamment que de deviner quoi faire.
fn split_single_signer_transaction(raw_tx: &[u8]) -> Result<(usize, &[u8])> {
    let (sig_count, consumed) = read_shortvec_len(raw_tx)?;
    anyhow::ensure!(sig_count == 1, "transaction Jupiter à {sig_count} signataires, un seul attendu");
    let message_start = consumed + 64 * sig_count;
    anyhow::ensure!(raw_tx.len() > message_start, "transaction Jupiter tronquée");
    Ok((message_start, &raw_tx[message_start..]))
}

/// Premier compte du message = le payeur des frais (et unique signataire
/// attendu, voir `split_single_signer_transaction`) — vérifié comme devant
/// être NOTRE PROPRE clé avant toute signature (voir la doc du module).
fn message_fee_payer(message: &[u8]) -> Result<[u8; 32]> {
    // Message versionné (v0) : le premier octet a son bit de poids fort à 1
    // (impossible pour un message "legacy", où ce même octet est
    // `num_required_signatures`, toujours petit). L'en-tête (3 octets) suit
    // immédiatement, précédé de l'octet de version dans ce cas.
    let header_start = if message.first().is_some_and(|b| b & 0x80 != 0) { 1 } else { 0 };
    anyhow::ensure!(message.len() > header_start + 3, "message Jupiter tronqué (en-tête)");
    let account_keys_start = header_start + 3;
    let (_count, consumed) = read_shortvec_len(&message[account_keys_start..])?;
    let fee_payer_start = account_keys_start + consumed;
    anyhow::ensure!(message.len() >= fee_payer_start + 32, "message Jupiter tronqué (payeur de frais)");
    let mut fee_payer = [0u8; 32];
    fee_payer.copy_from_slice(&message[fee_payer_start..fee_payer_start + 32]);
    Ok(fee_payer)
}

/// Signe une transaction Jupiter (voir `build_swap_transaction`) après avoir
/// vérifié que son payeur de frais est bien `expected_signer` — refuse de
/// signer sinon, plutôt que de faire confiance aveuglément à une transaction
/// tierce.
pub fn sign_swap_transaction(raw_tx: &[u8], signing_key: &ed25519_dalek::SigningKey, expected_signer: &[u8; 32]) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;

    let (message_start, message) = split_single_signer_transaction(raw_tx)?;
    let fee_payer = message_fee_payer(message)?;
    anyhow::ensure!(
        &fee_payer == expected_signer,
        "la transaction Jupiter attend un payeur de frais différent du portefeuille actuel — refus de signer"
    );

    let signature = signing_key.sign(message);
    let mut signed = raw_tx.to_vec();
    signed[1..message_start].copy_from_slice(&signature.to_bytes());
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ne garantit pas que l'adresse est correcte (seule une vérification
    /// contre un portefeuille de référence le garantirait) — garde-fou
    /// minimal contre une corruption accidentelle de la constante (mauvaise
    /// longueur, caractères hors alphabet base58).
    #[test]
    fn affiliate_address_has_the_expected_base58_shape() {
        let bytes = bs58::decode(AFFILIATE_ADDRESS).into_vec().expect("base58 valide");
        assert_eq!(bytes.len(), 32, "une adresse Solana fait 32 octets");
    }

    #[test]
    fn read_shortvec_len_matches_write_shortvec_len_round_trip() {
        for len in [0usize, 1, 127, 128, 300, 16384] {
            let mut buf = Vec::new();
            crate::sol_tx::write_shortvec_len(&mut buf, len);
            let (decoded, consumed) = read_shortvec_len(&buf).unwrap();
            assert_eq!(decoded, len);
            assert_eq!(consumed, buf.len());
        }
    }

    /// Vérification de bout en bout contre l'API réelle (lecture seule pour le
    /// devis/la construction ; aucune signature ni diffusion ici). Ignoré par
    /// défaut : `cargo test -- --ignored jupiter_quote_and_build_match_the_real_network`.
    #[test]
    #[ignore]
    fn jupiter_quote_and_build_match_the_real_network() {
        // Wallet public connu (déjà utilisé pour vérifier la dérivation d'ATA
        // USDC ailleurs dans ce projet) — lecture seule, aucun risque.
        let owner = "E645TckHQnDcavVv92Etc6xSWQaq8zzPtPRGBheviRAk";
        let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let q = quote(SOL_MINT, usdc_mint, 100_000_000, 50).expect("devis réel");
        assert!(q.out_amount > 0);

        let raw_tx = build_swap_transaction(&q, owner).expect("construction réelle");
        let (message_start, message) = split_single_signer_transaction(&raw_tx).expect("découpage de la transaction");
        assert_eq!(message_start, 65, "un seul signataire attendu (1 + 64 octets)");
        let fee_payer = message_fee_payer(message).expect("payeur de frais lisible");
        let owner_bytes: [u8; 32] = bs58::decode(owner).into_vec().unwrap().try_into().unwrap();
        assert_eq!(fee_payer, owner_bytes, "le payeur de frais doit être le compte demandé");
    }
}
