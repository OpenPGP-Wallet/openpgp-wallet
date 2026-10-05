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
    /// Jeton des frais d'affiliation (`None` : échange sans frais, faute de
    /// compte de frais existant pour l'un des deux jetons, voir `api`).
    pub fee_mint: Option<[u8; 32]>,
}

/// `amount` dans la plus petite unité de l'actif source (lamports pour SOL,
/// micro-USDC pour l'USDC). `slippage_bps` : tolérance de glissement de prix,
/// en points de base (ex: 50 = 0,50 %). `fee_mint` : jeton dont le compte de
/// frais de l'affilié recevra les 0,80 % (doit exister, voir
/// `fee_mint_candidates`) ; `None` : sans frais.
/// Teneurs de marché « prop AMM » exclus des devis : leur prix, tiré d'un
/// oracle, ne vaut que quelques blocs (« replay: slot window ») — périmé le
/// temps que l'app simule la transaction sur son propre nœud, l'échange
/// échouait en glissement (erreur 6001, constaté le 05/10/2026 avec HumidiFi
/// sur un vrai SOL → USDC). Coût mesuré de l'exclusion sur SOL → USDC :
/// 0,0003 % (routes Whirlpool, Manifest…). Libellés de Jupiter
/// (`/swap/v1/program-id-to-label`), espaces encodés.
const EXCLUDED_DEXES: &str = "HumidiFi,SolFi,SolFi%20V2,TesseraV,ZeroFi,GoonFi%20V2,Obric%20V2,AlphaQ,BisonFi,Aquifer";

/// Plafond des frais de priorité demandé à Jupiter (0,001 SOL) — voir
/// `build_swap_transaction` ; aussi gardé de côté par le « Max » d'un
/// échange (`api::swap_max`).
pub const PRIORITY_FEE_MAX_LAMPORTS: u64 = 1_000_000;

pub fn quote(input_mint: &str, output_mint: &str, amount: u64, slippage_bps: u32, fee_mint: Option<[u8; 32]>) -> Result<JupiterQuote> {
    quote_with_fee(input_mint, output_mint, amount, slippage_bps, fee_mint, AFFILIATE_FEE_BPS)
}

/// Comme `quote`, au taux `fee_bps` (staking liquide : plus bas, voir
/// `swap_routes::staking_fee_bps`). Taux nul : aucun compte de frais.
pub fn quote_with_fee(input_mint: &str, output_mint: &str, amount: u64, slippage_bps: u32, fee_mint: Option<[u8; 32]>, fee_bps: u32) -> Result<JupiterQuote> {
    let fee_mint = fee_mint.filter(|_| fee_bps > 0);
    let fee = if fee_mint.is_some() { format!("&platformFeeBps={fee_bps}") } else { String::new() };
    let url = format!("{JUPITER_BASE}/swap/v1/quote?inputMint={input_mint}&outputMint={output_mint}&amount={amount}&slippageBps={slippage_bps}{fee}&excludeDexes={EXCLUDED_DEXES}");
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

    Ok(JupiterQuote { raw, out_amount, fee_mint })
}

/// Comptes de frais possibles pour un échange, par ordre de préférence : le
/// jeton reçu, puis le jeton vendu — Jupiter exige un compte de frais de
/// l'un des deux jetons échangés, EXISTANT (constaté : un compte USDC faisait
/// échouer SOL → USDT, « Account not associated with this Mint », et un compte
/// absent échoue en 6025 « InvalidTokenAccount »). Jamais en SOL natif.
pub fn fee_mint_candidates(input_mint: &str, output_mint: &str) -> Vec<[u8; 32]> {
    [output_mint, input_mint]
        .into_iter()
        .filter(|mint| *mint != SOL_MINT)
        .filter_map(|mint| bs58::decode(mint).into_vec().ok().and_then(|v| v.try_into().ok()))
        .collect()
}

/// Compte de frais (ATA de `AFFILIATE_ADDRESS`) pour le jeton `mint`.
pub fn fee_account(mint: &[u8; 32]) -> Result<[u8; 32]> {
    let owner: [u8; 32] = bs58::decode(AFFILIATE_ADDRESS)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("adresse d'affiliation Jupiter mal formée (bug de compilation)")?;
    Ok(crate::sol_spl::find_associated_token_address(&owner, mint))
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
    // Compte de frais : celui du jeton choisi au devis (voir `fee_mint_candidates`) ;
    // aucun pour un devis sans frais.
    let mut body = serde_json::json!({
        "quoteResponse": quote.raw,
        "userPublicKey": user_pubkey,
        // Enveloppe/désenveloppe automatiquement le SOL natif en wSOL le
        // temps du swap (obligatoire pour swapper depuis/vers du SOL natif,
        // qui n'est pas lui-même un jeton SPL) — comportement par défaut de
        // Jupiter, explicité ici pour ne pas dépendre d'une valeur implicite.
        "wrapAndUnwrapSol": true,
        // Frais de priorité plafonnés explicitement (1 000 000 lamports, soit
        // 0,001 SOL) plutôt que laissés au choix automatique de Jupiter : la
        // vérification des effets avant signature (`api::check_swap_effects`)
        // refuse toute perte au-delà du montant + un budget de frais fixe —
        // sans plafond, une congestion réseau pourrait pousser Jupiter
        // au-delà de ce budget et provoquer des refus légitimes.
        "prioritizationFeeLamports": {
            // "medium" et pas "high" : mesuré en direct, "high" faisait monter
            // le coût réel à ~915 000 lamports contre ~25 000-105 000 par
            // défaut — le but est un PLAFOND, pas de payer plus cher.
            "priorityLevelWithMaxLamports": { "maxLamports": PRIORITY_FEE_MAX_LAMPORTS, "priorityLevel": "medium" }
        },
    });
    if let Some(mint) = quote.fee_mint {
        body["feeAccount"] = Value::String(bs58::encode(fee_account(&mint)?).into_string());
    }
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
pub(crate) fn split_single_signer_transaction(raw_tx: &[u8]) -> Result<(usize, &[u8])> {
    let (sig_count, consumed) = read_shortvec_len(raw_tx)?;
    anyhow::ensure!(sig_count == 1, "transaction Jupiter à {sig_count} signataires, un seul attendu");
    let message_start = consumed + 64 * sig_count;
    anyhow::ensure!(raw_tx.len() > message_start, "transaction Jupiter tronquée");
    Ok((message_start, &raw_tx[message_start..]))
}

/// Premier compte du message = le payeur des frais (et unique signataire
/// attendu, voir `split_single_signer_transaction`) — vérifié comme devant
/// être NOTRE PROPRE clé avant toute signature (voir la doc du module).
pub(crate) fn message_fee_payer(message: &[u8]) -> Result<[u8; 32]> {
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

/// Comptes qu'un message Solana peut MODIFIER : le runtime interdit à une
/// transaction (et à tout CPI qu'elle déclenche) de toucher un compte qu'elle
/// ne déclare pas inscriptible. Connaître cet ensemble suffit donc à borner
/// tout ce qu'une transaction construite par un tiers pourrait faire aux
/// comptes de l'utilisateur (voir `api::verify_swap_effects`).
pub struct WritableAccounts {
    /// Clés statiques inscriptibles, déjà résolues.
    pub static_keys: Vec<[u8; 32]>,
    /// Tables de correspondance d'adresses (message v0) : adresse de la table
    /// + index inscriptibles, à résoudre on-chain (jamais en faisant confiance
    /// au tiers qui a construit la transaction).
    pub lookups: Vec<([u8; 32], Vec<u8>)>,
    /// `true` si la première instruction est `AdvanceNonceAccount` (programme
    /// système, discriminant 4) : la transaction repose alors sur un "nonce
    /// durable" au lieu d'un blockhash récent, et reste valide INDÉFINIMENT —
    /// rejouable bien plus tard, à un cours bien pire. Un vrai swap Jupiter
    /// n'en utilise jamais.
    pub advances_durable_nonce: bool,
}

/// Lecteur borné : un message venant d'un tiers ne doit jamais pouvoir
/// provoquer de panique par un index hors limites.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| anyhow!("message Jupiter : longueur invalide"))?;
        anyhow::ensure!(end <= self.bytes.len(), "message Jupiter tronqué");
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn shortvec(&mut self) -> Result<usize> {
        let (len, consumed) = read_shortvec_len(&self.bytes[self.pos.min(self.bytes.len())..])?;
        self.pos += consumed;
        Ok(len)
    }
    fn key(&mut self) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        key.copy_from_slice(self.take(32)?);
        Ok(key)
    }
}

/// Parse complet d'un message Solana (legacy ou v0) pour en extraire les
/// comptes inscriptibles — voir `WritableAccounts`. Règles d'inscriptibilité
/// des clés statiques d'après l'en-tête du message : parmi les
/// `num_required_signatures` premières clés, les `num_readonly_signed`
/// dernières sont en lecture seule ; parmi les suivantes, les
/// `num_readonly_unsigned` dernières aussi.
pub fn message_writable_accounts(message: &[u8]) -> Result<WritableAccounts> {
    let mut r = Reader { bytes: message, pos: 0 };
    let versioned = message.first().is_some_and(|b| b & 0x80 != 0);
    if versioned {
        let version = r.u8()? & 0x7f;
        anyhow::ensure!(version == 0, "version de message Solana non prise en charge : {version}");
    }
    let num_signed = r.u8()? as usize;
    let num_ro_signed = r.u8()? as usize;
    let num_ro_unsigned = r.u8()? as usize;
    let count = r.shortvec()?;
    let keys: Vec<[u8; 32]> = (0..count).map(|_| r.key()).collect::<Result<_>>()?;
    anyhow::ensure!(
        num_signed <= count && num_ro_signed <= num_signed && num_ro_unsigned <= count - num_signed,
        "en-tête de message Solana incohérent"
    );
    let static_keys = keys
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            if *i < num_signed {
                *i < num_signed - num_ro_signed
            } else {
                *i < count - num_ro_unsigned
            }
        })
        .map(|(_, k)| *k)
        .collect();

    r.take(32)?; // recent blockhash
    let instruction_count = r.shortvec()?;
    let mut advances_durable_nonce = false;
    for i in 0..instruction_count {
        // Les identifiants de programme sont TOUJOURS des clés statiques (le
        // format v0 interdit de les charger depuis une table de correspondance).
        let program_index = r.u8()? as usize;
        let accounts_len = r.shortvec()?;
        r.take(accounts_len)?;
        let data_len = r.shortvec()?;
        let data = r.take(data_len)?;
        if i == 0 {
            let program = keys.get(program_index).ok_or_else(|| anyhow!("message Solana : index de programme invalide"))?;
            advances_durable_nonce = *program == [0u8; 32] && data.starts_with(&[4, 0, 0, 0]);
        }
    }

    let mut lookups = Vec::new();
    if versioned {
        let lookup_count = r.shortvec()?;
        for _ in 0..lookup_count {
            let table = r.key()?;
            let writable_len = r.shortvec()?;
            let writable = r.take(writable_len)?.to_vec();
            let readonly_len = r.shortvec()?;
            r.take(readonly_len)?;
            lookups.push((table, writable));
        }
    }
    anyhow::ensure!(r.pos == message.len(), "message Solana avec des octets en trop");
    Ok(WritableAccounts { static_keys, lookups, advances_durable_nonce })
}

/// Découpe une transaction brute et renvoie son message (voir
/// `split_single_signer_transaction`).
pub fn transaction_message(raw_tx: &[u8]) -> Result<&[u8]> {
    split_single_signer_transaction(raw_tx).map(|(_, message)| message)
}

/// Remplace le blockhash récent d'une transaction à signataire unique par
/// `blockhash`, lu sur NOTRE nœud juste avant de signer. Celui choisi par le
/// tiers qui a construit la transaction peut expirer avant l'envoi (mesuré le
/// 02/10/2026 : ~35 s de validité pour une transaction LI.FI, moins que
/// déverrouillage + simulation après la confirmation → « BlockhashNotFound »)
/// ou être inconnu de notre nœud. Sans effet sur les instructions ; refusé
/// pour un nonce durable (le « blockhash » y est la valeur du nonce).
pub fn with_recent_blockhash(raw_tx: &[u8], blockhash: &[u8; 32]) -> Result<Vec<u8>> {
    let (message_start, message) = split_single_signer_transaction(raw_tx)?;
    anyhow::ensure!(!message_writable_accounts(message)?.advances_durable_nonce, "transaction à nonce durable : blockhash non remplaçable");
    let header_start = if message.first().is_some_and(|b| b & 0x80 != 0) { 1 } else { 0 };
    let keys_start = header_start + 3;
    anyhow::ensure!(message.len() > keys_start, "message Solana tronqué (en-tête)");
    let (count, consumed) = read_shortvec_len(&message[keys_start..])?;
    let start = message_start + keys_start + consumed + 32 * count;
    anyhow::ensure!(raw_tx.len() >= start + 32, "message Solana tronqué (blockhash)");
    let mut out = raw_tx.to_vec();
    out[start..start + 32].copy_from_slice(blockhash);
    Ok(out)
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

    /// Message legacy minimal : en-tête [1 signataire, 0, 1 lecture seule non
    /// signée], clés [utilisateur, programme système], blockhash, 1 instruction.
    fn legacy_message_with_first_instruction(data: &[u8]) -> Vec<u8> {
        let mut m = vec![1, 0, 1, 2];
        m.extend_from_slice(&[7u8; 32]); // utilisateur (inscriptible, signataire)
        m.extend_from_slice(&[0u8; 32]); // programme système (lecture seule)
        m.extend_from_slice(&[9u8; 32]); // blockhash
        m.push(1); // 1 instruction
        m.push(1); // programme = clé n°1 (système)
        m.push(1); // 1 compte
        m.push(0);
        m.push(data.len() as u8);
        m.extend_from_slice(data);
        m
    }

    #[test]
    fn message_writable_accounts_parses_writability_and_detects_durable_nonces() {
        let nonce = message_writable_accounts(&legacy_message_with_first_instruction(&[4, 0, 0, 0])).unwrap();
        assert!(nonce.advances_durable_nonce, "AdvanceNonceAccount (discriminant 4) doit être détecté");
        assert_eq!(nonce.static_keys, vec![[7u8; 32]], "seul l'utilisateur est inscriptible ici");
        assert!(nonce.lookups.is_empty(), "un message legacy n'a pas de table de correspondance");

        let transfer = message_writable_accounts(&legacy_message_with_first_instruction(&[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        assert!(!transfer.advances_durable_nonce, "un simple transfert n'est pas un nonce durable");

        // Message tronqué : erreur propre, jamais de panique.
        let mut truncated = legacy_message_with_first_instruction(&[4, 0, 0, 0]);
        truncated.truncate(truncated.len() - 3);
        assert!(message_writable_accounts(&truncated).is_err());
    }

    /// Blockhash remplacé à sa place exacte (message legacy puis v0), rien
    /// d'autre ne bouge ; refusé pour un nonce durable.
    #[test]
    fn with_recent_blockhash_replaces_only_the_blockhash() {
        let tx = |message: &[u8]| [&[1u8][..], &[0u8; 64], message].concat();
        let transfer = legacy_message_with_first_instruction(&[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let fresh = [5u8; 32];
        let legacy = tx(&transfer);
        let replaced = with_recent_blockhash(&legacy, &fresh).unwrap();
        let start = 1 + 64 + 4 + 2 * 32; // signature, en-tête + nombre de clés, 2 clés
        assert_eq!(replaced[start..start + 32], fresh);
        assert_eq!((&replaced[..start], &replaced[start + 32..]), (&legacy[..start], &legacy[start + 32..]));
        // v0 : octet de version en tête, aucune table de correspondance en fin.
        let v0 = tx(&[&[0x80u8][..], &transfer, &[0]].concat());
        let replaced = with_recent_blockhash(&v0, &fresh).unwrap();
        assert_eq!(replaced[start + 1..start + 33], fresh);
        assert_eq!((&replaced[..start + 1], &replaced[start + 33..]), (&v0[..start + 1], &v0[start + 33..]));
        assert!(with_recent_blockhash(&tx(&legacy_message_with_first_instruction(&[4, 0, 0, 0])), &fresh).is_err(), "nonce durable");
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
        let q = quote(SOL_MINT, usdc_mint, 100_000_000, 50, None).expect("devis réel");
        assert!(q.out_amount > 0);

        let raw_tx = build_swap_transaction(&q, owner).expect("construction réelle");
        let (message_start, message) = split_single_signer_transaction(&raw_tx).expect("découpage de la transaction");
        assert_eq!(message_start, 65, "un seul signataire attendu (1 + 64 octets)");
        let fee_payer = message_fee_payer(message).expect("payeur de frais lisible");
        let owner_bytes: [u8; 32] = bs58::decode(owner).into_vec().unwrap().try_into().unwrap();
        assert_eq!(fee_payer, owner_bytes, "le payeur de frais doit être le compte demandé");
    }
}
