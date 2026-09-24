//! Client THORChain minimal : uniquement de quoi obtenir un devis de swap
//! (lecture seule, aucune signature, aucun secret impliqué). THORChain est le
//! protocole externe qui rend le swap cross-chain possible (BTC/ETH/SOL n'ont
//! aucun mécanisme natif pour s'échanger entre eux) — voir le plan de la
//! fonctionnalité swap pour le contexte complet.
//!
//! Le devis renvoie déjà un `memo` tout construit par THORChain lui-même :
//! ce module ne reconstruit JAMAIS ce format à la main, pour ne pas risquer
//! une erreur de formatage qui enverrait des fonds réels vers un swap invalide.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
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

/// Passerelle publique THORChain opérée par Liquify — pas de clé requise pour
/// un devis, endpoint en lecture seule. Vérifiée par un appel réel avant
/// d'être inscrite ici : `thornode.ninerealms.com` (souvent cité dans la doc
/// et d'anciens articles) ne résout plus du tout au moment de l'écriture —
/// une preuve de plus qu'il ne faut jamais faire confiance à un hostname
/// tiers sans le tester en direct.
const THORNODE_BASE: &str = "https://gateway.liquify.com/chain/thorchain_api";

/// Adresse THORChain (RUNE) qui reçoit les frais d'affiliation de CHAQUE swap
/// effectué depuis cette app, quelle que soit l'installation qui le déclenche
/// — une seule adresse fixe (celle du développeur), pas une adresse dérivée
/// par installation (sinon chaque utilisateur se paierait à lui-même). Dérivée
/// une fois via `api::get_thor_fee_address` (voir Paramètres), vérifiée par
/// l'utilisateur lui-même avant d'être figée ici.
pub const AFFILIATE_ADDRESS: &str = "thor12j5rrcflhffxmq0ekwvk0h7g0mdy8gn4fg0w3e";

/// 80 points de base = 0,80 %.
pub const AFFILIATE_FEE_BPS: u32 = 80;

pub struct SwapQuote {
    /// Adresse de vault à laquelle envoyer l'actif source — TOUJOURS relue en
    /// direct, jamais mise en cache : ces adresses tournent régulièrement.
    pub inbound_address: String,
    /// Adresse du contrat "THORChain Router" à appeler pour un swap EVM
    /// (JAMAIS envoyer directement à `inbound_address` sur une chaîne EVM :
    /// il faut appeler `depositWithExpiry` sur ce contrat, voir
    /// `eth_tx::thorchain_deposit_calldata`). Absente pour les chaînes non-EVM
    /// (BTC, SOL...), toujours relue en direct comme `inbound_address` — ces
    /// contrats sont versionnés et peuvent changer. Vérifié en direct : la
    /// même valeur est aussi exposée par `/thorchain/inbound_addresses`.
    pub router: Option<String>,
    /// Memo prêt à l'emploi, construit par THORChain : jamais reconstruit à la
    /// main côté client (voir la doc du module).
    pub memo: String,
    /// Montant de sortie attendu, dans la plus petite unité de l'actif de
    /// destination (8 décimales pour la plupart des actifs THORChain).
    pub expected_amount_out: u64,
    /// Total des frais THORChain (réseau + liquidité + affiliation),
    /// purement informatif pour l'affichage — déjà déduit de
    /// `expected_amount_out`, jamais à soustraire une seconde fois.
    pub total_fees: Option<u64>,
}

#[derive(Deserialize)]
struct QuoteResponseJson {
    inbound_address: Option<String>,
    router: Option<String>,
    memo: Option<String>,
    expected_amount_out: Option<String>,
    fees: Option<FeesJson>,
    /// Présent (avec `code`) sur une réponse d'erreur réelle — vérifié contre
    /// un appel en direct : `{"code":3,"message":"...","details":[]}`, PAS un
    /// champ `error` comme on pourrait le supposer par convention.
    code: Option<i64>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct FeesJson {
    total: Option<String>,
}

/// THORChain représente TOUS les montants avec une précision fixe de 8
/// décimales ("1e8"), quelle que soit la précision native de la chaîne
/// source/destination (9 pour SOL, 18 pour ETH, 8 pour BTC, 6 pour l'USDC) —
/// documenté dans la spec THORChain. Cette conversion doit TOUJOURS passer
/// par cette fonction avant d'appeler `quote_swap`, jamais recalculée à la
/// main ailleurs (une erreur ici fausserait le montant réellement échangé
/// d'un facteur 10, 100 ou plus).
pub fn to_thorchain_amount(native_amount: u128, native_decimals: u32) -> Result<u64> {
    const THORCHAIN_DECIMALS: u32 = 8;
    let converted = if native_decimals >= THORCHAIN_DECIMALS {
        native_amount / 10u128.pow(native_decimals - THORCHAIN_DECIMALS)
    } else {
        native_amount
            .checked_mul(10u128.pow(THORCHAIN_DECIMALS - native_decimals))
            .context("montant trop grand pour la conversion vers la précision THORChain (1e8)")?
    };
    u64::try_from(converted).context("montant converti trop grand pour la précision THORChain (1e8)")
}

/// `from_asset`/`to_asset` au format THORChain (`CHAIN.ASSET`, ex: `BTC.BTC`,
/// `ETH.ETH`, `SOL.SOL`) — voir la doc THORChain pour la notation exacte des
/// jetons non natifs (USDC etc.), volontairement pas encore couverte ici (v1
/// limitée aux actifs natifs BTC/ETH/SOL, voir le plan). `amount` dans la plus
/// petite unité de l'actif source. `destination` : adresse de l'utilisateur
/// sur la chaîne de destination (une de ses propres adresses, jamais celle du
/// développeur).
pub fn quote_swap(from_asset: &str, to_asset: &str, amount: u64, destination: &str) -> Result<SwapQuote> {
    let url = format!(
        "{THORNODE_BASE}/thorchain/quote/swap?from_asset={from_asset}&to_asset={to_asset}&amount={amount}&destination={destination}&affiliate={AFFILIATE_ADDRESS}&affiliate_bps={AFFILIATE_FEE_BPS}"
    );
    let response: QuoteResponseJson = shared_client()
        .get(&url)
        .send()
        .context("requête de devis THORChain impossible")?
        .json()
        .context("réponse de devis THORChain illisible")?;

    if response.code.is_some() {
        let message = response.message.unwrap_or_else(|| "raison inconnue".to_string());
        anyhow::bail!("devis THORChain refusé : {message}");
    }

    let inbound_address = response.inbound_address.ok_or_else(|| anyhow!("devis THORChain sans adresse de vault"))?;
    let memo = response.memo.ok_or_else(|| anyhow!("devis THORChain sans memo"))?;
    let expected_amount_out = response
        .expected_amount_out
        .ok_or_else(|| anyhow!("devis THORChain sans montant de sortie attendu"))?
        .parse::<u64>()
        .context("montant de sortie attendu illisible")?;
    let total_fees = response
        .fees
        .and_then(|f| f.total)
        .and_then(|s| s.parse::<u64>().ok());

    Ok(SwapQuote {
        inbound_address,
        router: response.router,
        memo,
        expected_amount_out,
        total_fees,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ne garantit pas que l'adresse existe/est correcte (seule une
    /// vérification contre un portefeuille THORChain de référence le
    /// garantirait, voir le plan) — garde-fou minimal contre une corruption
    /// accidentelle de la constante (mauvais préfixe, mauvaise longueur).
    #[test]
    fn to_thorchain_amount_converts_between_decimal_precisions() {
        // SOL : 9 décimales natives -> 8 (divise par 10).
        assert_eq!(to_thorchain_amount(1_000_000_000, 9).unwrap(), 100_000_000);
        // BTC : déjà 8 décimales, identité.
        assert_eq!(to_thorchain_amount(123_456_789, 8).unwrap(), 123_456_789);
        // ETH : 18 décimales natives -> 8 (divise par 1e10).
        assert_eq!(to_thorchain_amount(1_000_000_000_000_000_000, 18).unwrap(), 100_000_000);
        // USDC : 6 décimales natives -> 8 (multiplie par 100).
        assert_eq!(to_thorchain_amount(1_000_000, 6).unwrap(), 100_000_000);
    }

    /// Vérification de bout en bout contre l'API réelle (lecture seule, aucun
    /// risque) : confirme l'URL de base, le format de réponse réel (types
    /// exacts des champs) et que l'adresse d'affiliation est bien acceptée.
    /// Ignoré par défaut (dépend du réseau) : lancer explicitement avec
    /// `cargo test -- --ignored quote_swap_matches_the_real_network`.
    #[test]
    #[ignore]
    fn quote_swap_matches_the_real_network() {
        // ETH source (marge de memo confortable) vers BTC : SOL est
        // actuellement en pause côté THORChain (HALTSOLTRADING=1 constaté en
        // direct au moment de l'écriture de ce test), donc pas utilisable ici
        // pour une vérification fiable dans la durée.
        let quote = quote_swap(
            "ETH.ETH",
            "BTC.BTC",
            10_000_000,
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        )
        .expect("appel réseau réel");
        assert!(quote.inbound_address.starts_with("0x"), "vault ETH attendue : {}", quote.inbound_address);
        assert!(quote.memo.contains(AFFILIATE_ADDRESS), "le memo doit inclure notre adresse d'affiliation");
        assert!(quote.expected_amount_out > 0);
        let router = quote.router.expect("un devis source ETH doit renvoyer un routeur");
        assert!(router.starts_with("0x") && router.len() == 42, "adresse de routeur EVM attendue : {router}");
    }

    #[test]
    fn affiliate_address_has_the_expected_bech32_shape() {
        let (hrp, data, _variant) = bech32::decode(AFFILIATE_ADDRESS).expect("adresse bech32 valide");
        assert_eq!(hrp, "thor");
        assert_eq!(
            bech32::FromBase32::from_base32(&data).map(|v: Vec<u8>| v.len()),
            Ok(20),
            "une adresse THORChain encode un hash160 (20 octets)"
        );
    }
}
