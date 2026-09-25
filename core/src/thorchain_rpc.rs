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

/// Sortie minimale exigée, en points de base SOUS le montant de sortie attendu
/// (1 % ici). Transmise via `liquidity_tolerance_bps`, PAS `tolerance_bps` —
/// vérifié en direct : `tolerance_bps` s'applique au prix SANS frais, si bien
/// qu'avec 100 bps la limite (3 166 856) dépassait déjà la sortie attendue
/// (3 161 977) une fois les frais déduits, et le swap aurait été
/// systématiquement remboursé (frais réseau perdus pour rien) ;
/// `liquidity_tolerance_bps` donne exactement limite = sortie attendue × (1 −
/// tolérance) (ratios 0,995 / 0,99 / 0,97 mesurés pour 50 / 100 / 300 bps).
/// Sans aucune tolérance (comportement précédent), le memo avait une limite
/// VIDE : le swap acceptait n'importe quel taux, exposé à un sandwich ou à
/// une manipulation de prix pendant les minutes que dure un swap cross-chain.
pub const SWAP_TOLERANCE_BPS: u32 = 100;

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
        "{THORNODE_BASE}/thorchain/quote/swap?from_asset={from_asset}&to_asset={to_asset}&amount={amount}&destination={destination}&affiliate={AFFILIATE_ADDRESS}&affiliate_bps={AFFILIATE_FEE_BPS}&liquidity_tolerance_bps={SWAP_TOLERANCE_BPS}"
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

    verify_swap_memo(&memo, to_asset, destination, expected_amount_out)?;

    Ok(SwapQuote {
        inbound_address,
        router: response.router,
        memo,
        expected_amount_out,
        total_fees,
    })
}

/// Code court THORChain d'un actif dans un memo — copié du code source de
/// THORNode (`common/asset.go`, `Asset::ShortCode`), pas deviné : "s" y
/// désigne BSC.BNB, PAS SOL (SOL.SOL = "o"), une supposition aurait été
/// fausse. Limité aux 3 actifs natifs que cette app sait swapper.
fn memo_short_code(asset: &str) -> Option<&'static str> {
    match asset {
        "BTC.BTC" => Some("b"),
        "ETH.ETH" => Some("e"),
        "SOL.SOL" => Some("o"),
        _ => None,
    }
}

/// Vérifie que le memo renvoyé par la passerelle THORChain fait EXACTEMENT ce
/// que l'utilisateur a confirmé — trouvé lors de l'audit "failles connues des
/// hot wallets" (classe "ce qu'on signe diffère de ce qu'on voit", celle des
/// plus grosses pertes récentes) : la boîte de confirmation affiche la
/// destination SAISIE par l'utilisateur, mais la transaction transporte le
/// memo fourni par un tiers, jamais relu. Une passerelle compromise pouvait
/// donc renvoyer un memo envoyant la sortie du swap à SA propre adresse, ou
/// gonflant les frais d'affiliation (ex : 5000 bps = 50 % du swap), sans que
/// rien ne l'empêche. Ce module ne reconstruit toujours jamais le memo à la
/// main (voir sa doc) : il le LIT et refuse s'il ne correspond pas.
///
/// Format attendu, vérifié en direct (`=:b:bc1q...:3146167:thor1...:80`) et
/// dans le code source de THORNode : `TYPE:ACTIF:DESTINATION:LIMITE:AFFILIÉ:BPS`,
/// exactement 6 champs. Tout champ supplémentaire est refusé : THORChain
/// accepte des champs d'agrégateur DEX après le 6ᵉ (contrat intermédiaire,
/// jeton final, sortie minimale) qui redirigeraient la sortie ailleurs.
pub fn verify_swap_memo(memo: &str, to_asset: &str, destination: &str, expected_amount_out: u64) -> Result<()> {
    let fields: Vec<&str> = memo.split(':').collect();
    anyhow::ensure!(fields.len() == 6, "memo THORChain inattendu ({} champs au lieu de 6) : {memo}", fields.len());

    // Alias du type "swap" dans le code source de THORNode (`memo.go`) : "swap", "s", "=".
    anyhow::ensure!(
        matches!(fields[0].to_ascii_lowercase().as_str(), "=" | "s" | "swap"),
        "memo THORChain qui n'est pas un swap : {memo}"
    );

    let asset_ok = fields[1].eq_ignore_ascii_case(to_asset) || memo_short_code(to_asset) == Some(fields[1]);
    anyhow::ensure!(asset_ok, "le memo THORChain vise un autre actif ({}) que celui demandé ({to_asset})", fields[1]);

    // Adresses EVM (hex) insensibles à la casse ; base58 (Solana) SENSIBLE à la
    // casse, et bech32 (Bitcoin) comparé tel quel (toujours en minuscules ici).
    let dest_ok = if destination.starts_with("0x") {
        fields[2].eq_ignore_ascii_case(destination)
    } else {
        fields[2] == destination
    };
    anyhow::ensure!(
        dest_ok,
        "le memo THORChain enverrait les fonds à une AUTRE adresse ({}) que celle confirmée ({destination}) — swap refusé",
        fields[2]
    );

    // "LIMITE" ou "LIMITE/INTERVALLE/QUANTITÉ" (swap en streaming).
    let limit: u64 = fields[3]
        .split('/')
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|_| anyhow!("memo THORChain sans sortie minimale exploitable (« {} ») — swap refusé", fields[3]))?;
    // Marge de 5 bps pour l'arrondi côté THORChain (ratios mesurés exacts à 1e-5 près).
    let min_acceptable = u128::from(expected_amount_out) * u128::from(10_000 - SWAP_TOLERANCE_BPS - 5) / 10_000;
    anyhow::ensure!(
        limit > 0 && u128::from(limit) >= min_acceptable,
        "sortie minimale du memo THORChain ({limit}) trop basse par rapport à la sortie attendue ({expected_amount_out}) — swap refusé"
    );

    anyhow::ensure!(
        fields[4] == AFFILIATE_ADDRESS && fields[5] == AFFILIATE_FEE_BPS.to_string(),
        "frais d'affiliation du memo THORChain inattendus ({}:{}) — swap refusé",
        fields[4],
        fields[5]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_BTC: &str = "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz";

    /// Memo réel renvoyé par la passerelle (ETH -> BTC, liquidity_tolerance_bps=50).
    fn real_memo() -> String {
        format!("=:b:{DEST_BTC}:3146167:{AFFILIATE_ADDRESS}:80")
    }

    #[test]
    fn verify_swap_memo_accepts_the_real_memo_shape() {
        verify_swap_memo(&real_memo().replace("3146167", "3130357"), "BTC.BTC", DEST_BTC, 3_161_977).expect("memo réel (1 %)");
        // Variante streaming "LIMITE/INTERVALLE/QUANTITÉ" et type "swap" en toutes lettres.
        let streaming = format!("SWAP:BTC.BTC:{DEST_BTC}:3130357/1/0:{AFFILIATE_ADDRESS}:80");
        verify_swap_memo(&streaming, "BTC.BTC", DEST_BTC, 3_161_977).expect("variante streaming");
    }

    #[test]
    fn verify_swap_memo_rejects_a_redirected_destination() {
        let memo = real_memo().replace(DEST_BTC, "bc1qattackerattackerattackerattacker0000");
        let err = verify_swap_memo(&memo, "BTC.BTC", DEST_BTC, 3_161_977).unwrap_err();
        assert!(err.to_string().contains("AUTRE adresse"), "{err}");
    }

    #[test]
    fn verify_swap_memo_rejects_inflated_affiliate_fees_or_a_foreign_affiliate() {
        let inflated = real_memo().replace(":80", ":5000");
        assert!(verify_swap_memo(&inflated, "BTC.BTC", DEST_BTC, 3_161_977).is_err(), "50 % de frais");
        let foreign = real_memo().replace(AFFILIATE_ADDRESS, "thor1attackerattackerattackerattacker00000");
        assert!(verify_swap_memo(&foreign, "BTC.BTC", DEST_BTC, 3_161_977).is_err(), "affilié étranger");
    }

    #[test]
    fn verify_swap_memo_rejects_a_missing_or_too_low_minimum_output() {
        // Limite vide = comportement d'AVANT ce correctif (n'importe quel taux accepté).
        let no_limit = format!("=:b:{DEST_BTC}::{AFFILIATE_ADDRESS}:80");
        assert!(verify_swap_memo(&no_limit, "BTC.BTC", DEST_BTC, 3_161_977).is_err(), "limite vide");
        let too_low = real_memo().replace("3146167", "1");
        assert!(verify_swap_memo(&too_low, "BTC.BTC", DEST_BTC, 3_161_977).is_err(), "limite dérisoire");
    }

    #[test]
    fn verify_swap_memo_rejects_extra_aggregator_fields_and_wrong_assets() {
        let aggregator = format!("{}:0xAggregator:ETH.USDT:1", real_memo());
        assert!(verify_swap_memo(&aggregator, "BTC.BTC", DEST_BTC, 3_161_977).is_err(), "champs d'agrégateur");
        // "s" = BSC.BNB dans THORNode, pas SOL : ne doit JAMAIS passer pour SOL.SOL.
        let sol_dest = "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F";
        let bsc = format!("=:s:{sol_dest}:100:{AFFILIATE_ADDRESS}:80");
        assert!(verify_swap_memo(&bsc, "SOL.SOL", sol_dest, 100).is_err(), "s n'est pas SOL");
        let sol = format!("=:o:{sol_dest}:100:{AFFILIATE_ADDRESS}:80");
        verify_swap_memo(&sol, "SOL.SOL", sol_dest, 100).expect("o = SOL.SOL");
    }

    #[test]
    fn verify_swap_memo_address_case_rules() {
        let evm = "0x0db14a0288f4637f60b46690f1971b756c58a47e";
        let memo = format!("=:e:{}:100:{AFFILIATE_ADDRESS}:80", evm.to_uppercase().replace("0X", "0x"));
        verify_swap_memo(&memo, "ETH.ETH", evm, 100).expect("hex EVM insensible à la casse");
        // Base58 (Solana) : changer la casse donne une AUTRE adresse, doit être refusé.
        let sol_dest = "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F";
        let memo = format!("=:o:{}:100:{AFFILIATE_ADDRESS}:80", sol_dest.to_lowercase());
        assert!(verify_swap_memo(&memo, "SOL.SOL", sol_dest, 100).is_err(), "base58 sensible à la casse");
    }

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
