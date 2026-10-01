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

/// THORName (alias court) de `AFFILIATE_ADDRESS`, une fois enregistré par le
/// développeur. Indispensable aux échanges DEPUIS Bitcoin : son memo tient en
/// 80 octets (OP_RETURN), et l'adresse `thor1…` complète (43 caractères) l'en
/// faisait déborder — constaté le 01/10/2026, THORChain refusait alors tout
/// devis depuis BTC (« generated memo too long for source chain »). Avant
/// usage, le nom est revérifié auprès de THORChain : son alias THOR doit être
/// `AFFILIATE_ADDRESS` (voir `verified_affiliate`).
pub const AFFILIATE_NAME: Option<&str> = None;

/// 80 points de base = 0,80 %.
pub const AFFILIATE_FEE_BPS: u32 = 80;

/// Crypto de l'app échangeable via THORChain : identifiant de carte, réseau, et
/// notation THORChain (pools disponibles relevés en direct le 01/10/2026).
pub struct ThorAsset {
    pub coin: &'static str,
    pub network: &'static str,
    pub symbol: &'static str,
    /// `CHAIN.TICKER`, ou `CHAIN.TICKER-0XCONTRAT` pour un jeton.
    pub asset: &'static str,
    /// Code court qu'un memo emploie pour un actif natif (relevé sur de vrais
    /// devis : « s » désigne BNB, pas SOL).
    pub short_code: Option<&'static str>,
    /// Décimales natives de l'actif (THORChain compte toujours en 1e8, voir
    /// `to_thorchain_amount`).
    pub decimals: u32,
    /// Jeton ERC-20 : contrat (dépôt par `approve` puis `depositWithExpiry`).
    pub contract: Option<&'static str>,
}

const fn native(coin: &'static str, network: &'static str, symbol: &'static str, asset: &'static str, short: &'static str, decimals: u32) -> ThorAsset {
    ThorAsset { coin, network, symbol, asset, short_code: Some(short), decimals, contract: None }
}

const fn erc20(coin: &'static str, network: &'static str, symbol: &'static str, asset: &'static str, decimals: u32, contract: &'static str) -> ThorAsset {
    ThorAsset { coin, network, symbol, asset, short_code: None, decimals, contract: Some(contract) }
}

pub const ASSETS: [ThorAsset; 11] = [
    native("btc", "btc_mainnet", "BTC", "BTC.BTC", "b", 8),
    native("evm", "evm_mainnet", "ETH", "ETH.ETH", "e", 18),
    native("evm", "base_mainnet", "ETH", "BASE.ETH", "f", 18),
    native("sol", "sol_mainnet", "SOL", "SOL.SOL", "o", 9),
    native("bnb", "bsc_mainnet", "BNB", "BSC.BNB", "s", 18),
    native("avax", "avax_mainnet", "AVAX", "AVAX.AVAX", "a", 18),
    erc20("usdc", "evm_mainnet", "USDC", "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", 6, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
    erc20("usdt", "evm_mainnet", "USDT", "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7", 6, "0xdac17f958d2ee523a2206206994597c13d831ec7"),
    erc20("dai", "evm_mainnet", "DAI", "ETH.DAI-0X6B175474E89094C44DA98B954EEDEAC495271D0F", 18, "0x6b175474e89094c44da98b954eedeac495271d0f"),
    erc20("usdc", "base_mainnet", "USDC", "BASE.USDC-0X833589FCD6EDB6E08F4C7C32D4F71B54BDA02913", 6, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
    erc20("vvv", "base_mainnet", "VVV", "BASE.VVV-0XACFE6019ED1A7DC6F7B508C02D1B04EC88CC21BF", 18, "0xacfe6019ed1a7dc6f7b508c02d1b04ec88cc21bf"),
];

/// Actif THORChain d'une crypto de l'app sur un réseau.
pub fn asset(coin: &str, network: &str) -> Option<&'static ThorAsset> {
    ASSETS.iter().find(|a| a.coin == coin && a.network == network)
}

/// Affilié à inscrire dans les devis : le THORName s'il est enregistré (et
/// revérifié), sinon l'adresse complète.
fn affiliate() -> Result<&'static str> {
    match AFFILIATE_NAME {
        Some(name) => verified_affiliate(name),
        None => Ok(AFFILIATE_ADDRESS),
    }
}

#[derive(Deserialize)]
struct ThorNameJson {
    #[serde(default)]
    aliases: Vec<ThorNameAlias>,
    expire_block_height: Option<i64>,
}

#[derive(Deserialize)]
struct ThorNameAlias {
    chain: String,
    address: String,
}

/// THORName `name` relu auprès de THORChain (une fois par session) : il doit
/// exister, ne pas être expiré, et pointer (alias THOR) vers
/// `AFFILIATE_ADDRESS` — sinon les frais iraient à quelqu'un d'autre.
fn verified_affiliate(name: &'static str) -> Result<&'static str> {
    static CHECKED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    let outcome = CHECKED.get_or_init(|| {
        let check = || -> Result<()> {
            let body = shared_client().get(format!("{THORNODE_BASE}/thorchain/thorname/{name}")).send()?.text()?;
            let height: Vec<serde_json::Value> = shared_client().get(format!("{THORNODE_BASE}/thorchain/lastblock")).send()?.json()?;
            let current = height.first().and_then(|b| b.get("thorchain")).and_then(serde_json::Value::as_i64).unwrap_or(0);
            check_thorname(&body, current)
        };
        check().map_err(|e| format!("{e:#}"))
    });
    outcome.as_ref().map(|_| name).map_err(|e| anyhow!("THORName d'affiliation « {name} » refusé : {e}"))
}

/// Réponse `/thorchain/thorname/{nom}` : alias THOR = `AFFILIATE_ADDRESS`, non expiré.
fn check_thorname(body: &str, current_height: i64) -> Result<()> {
    let parsed: ThorNameJson = serde_json::from_str(body).context("THORName introuvable")?;
    anyhow::ensure!(
        parsed.aliases.iter().any(|a| a.chain == "THOR" && a.address == AFFILIATE_ADDRESS),
        "il ne pointe pas vers l'adresse d'affiliation de l'app"
    );
    anyhow::ensure!(parsed.expire_block_height.unwrap_or(0) > current_height, "il a expiré");
    Ok(())
}

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
    let affiliate = affiliate()?;
    let url = format!(
        "{THORNODE_BASE}/thorchain/quote/swap?from_asset={from_asset}&to_asset={to_asset}&amount={amount}&destination={destination}&affiliate={affiliate}&affiliate_bps={AFFILIATE_FEE_BPS}&liquidity_tolerance_bps={SWAP_TOLERANCE_BPS}"
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

/// L'actif d'un memo désigne-t-il `to_asset` ? Formes relevées sur de vrais
/// devis : notation complète, code court d'un actif natif (« e », « b »,
/// « s » = BNB, « a », « f » = ETH sur Base ; « o » = SOL, code source de
/// THORNode), ou `CHAIN.TICKER` sans le contrat pour un jeton (« ETH.USDC »,
/// « BASE.VVV » : THORChain le résout vers son pool de ce jeton).
fn memo_asset_matches(field: &str, to_asset: &str) -> bool {
    if field.eq_ignore_ascii_case(to_asset) {
        return true;
    }
    if ASSETS.iter().any(|a| a.asset.eq_ignore_ascii_case(to_asset) && a.short_code == Some(field)) {
        return true;
    }
    to_asset.split_once('-').is_some_and(|(ticker, _)| field.eq_ignore_ascii_case(ticker))
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

    anyhow::ensure!(
        memo_asset_matches(fields[1], to_asset),
        "le memo THORChain vise un autre actif ({}) que celui demandé ({to_asset})",
        fields[1]
    );

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

    let affiliate_ok = fields[4] == AFFILIATE_ADDRESS || AFFILIATE_NAME == Some(fields[4]);
    anyhow::ensure!(
        affiliate_ok && fields[5] == AFFILIATE_FEE_BPS.to_string(),
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

    /// Memos RÉELS des nouveaux actifs (devis du 01/10/2026) : jetons en
    /// `CHAIN.TICKER` sans contrat, codes courts « s » (BNB), « a » (AVAX),
    /// « f » (ETH sur Base) ; un jeton ne se confond pas avec un autre.
    #[test]
    fn verify_swap_memo_accepts_the_real_shapes_of_the_new_assets() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let cases = [
            ("=:ETH.USDC:{evm}:262548630151:{aff}:80", "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", 265_200_000_000u64),
            ("=:ETH.USDT:{evm}:262897955671/0/2:{aff}:80", "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7", 265_550_000_000),
            ("=:BASE.VVV:{evm}:9695825781/0/174:{aff}:80", "BASE.VVV-0XACFE6019ED1A7DC6F7B508C02D1B04EC88CC21BF", 9_793_000_000),
            ("=:s:{evm}:342440142:{aff}:80", "BSC.BNB", 345_900_000),
            ("=:a:{evm}:24145106811/0/2:{aff}:80", "AVAX.AVAX", 24_389_000_000),
            ("=:f:{evm}:98138595/0/98:{aff}:80", "BASE.ETH", 99_130_000),
        ];
        for (memo, asset, expected) in cases {
            let memo = memo.replace("{evm}", evm).replace("{aff}", AFFILIATE_ADDRESS);
            verify_swap_memo(&memo, asset, evm, expected).unwrap_or_else(|e| panic!("{memo} : {e}"));
        }
        let usdt_for_usdc = format!("=:ETH.USDT:{evm}:262548630151:{AFFILIATE_ADDRESS}:80");
        assert!(verify_swap_memo(&usdt_for_usdc, "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", evm, 265_200_000_000).is_err());
        let eth_for_base_eth = format!("=:e:{evm}:98138595:{AFFILIATE_ADDRESS}:80");
        assert!(verify_swap_memo(&eth_for_base_eth, "BASE.ETH", evm, 99_130_000).is_err(), "ETH d'Ethereum n'est pas ETH sur Base");
    }

    /// Jetons de la table = contrats et décimales du registre des jetons de
    /// l'app (core/src/tokens.rs) ; notation THORChain = contrat en majuscules.
    #[test]
    fn thorchain_tokens_match_the_token_registry() {
        for a in ASSETS.iter().filter(|a| a.contract.is_some()) {
            let (token, deployment) = crate::tokens::find(a.coin, a.network).unwrap_or_else(|| panic!("{} absent du registre", a.asset));
            let crate::tokens::TokenKind::Erc20 { contract } = deployment.kind else { panic!("{} n'est pas ERC-20", a.asset) };
            assert_eq!(Some(contract), a.contract, "{}", a.asset);
            assert_eq!(u32::from(deployment.decimals), a.decimals, "{}", a.asset);
            assert_eq!(token.symbol.to_ascii_uppercase(), a.symbol, "{}", a.asset);
            assert!(a.asset.ends_with(&format!("-{}", contract.to_ascii_uppercase())), "{}", a.asset);
        }
        assert!(asset("bnb", "bsc_mainnet").is_some() && asset("bnb", "evm_mainnet").is_none());
    }

    /// THORName : alias THOR = adresse d'affiliation, non expiré (format réel
    /// de `/thorchain/thorname/{nom}`).
    #[test]
    fn thornames_must_point_to_the_affiliate_address() {
        let name = |alias: &str, expire: i64| {
            format!(r#"{{"name":"x","expire_block_height":{expire},"owner":"thor1u7ent5406np9t9u35ls0vxnv8rcmlzudf9zpq0","aliases":[{{"chain":"THOR","address":"{alias}"}},{{"chain":"ETH","address":"0x335fd459eadf098f8b2f26692936ee3d5bb425a2"}}]}}"#)
        };
        check_thorname(&name(AFFILIATE_ADDRESS, 1000), 999).expect("bon alias, valide");
        assert!(check_thorname(&name("thor1xnkml34dfmhtmx3hfxte4jxrxn2j3604mtx5h0", 1000), 999).is_err(), "autre adresse");
        assert!(check_thorname(&name(AFFILIATE_ADDRESS, 1000), 1000).is_err(), "expiré");
        assert!(check_thorname(r#"{"code":3,"message":"THORName doesn't exist"}"#, 0).is_err(), "inexistant");
    }

    /// Devis RÉELS pour les nouvelles paires (lecture seule) : jeton ERC-20 en
    /// source (routeur renvoyé), monnaies natives de BNB Chain, Avalanche et
    /// Base, jeton de Base en destination ; memo vérifié par `quote_swap`.
    /// `cargo test -- --ignored quote_swap_covers_the_new_assets --nocapture`
    #[test]
    #[ignore]
    fn quote_swap_covers_the_new_assets() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        for (from, to, amount) in [
            ("ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", "BSC.BNB", 10_000_000_000u64),
            ("BSC.BNB", "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7", 100_000_000),
            ("AVAX.AVAX", "BASE.ETH", 1_000_000_000),
            ("BASE.USDC-0X833589FCD6EDB6E08F4C7C32D4F71B54BDA02913", "ETH.DAI-0X6B175474E89094C44DA98B954EEDEAC495271D0F", 10_000_000_000),
            ("ETH.ETH", "BASE.VVV-0XACFE6019ED1A7DC6F7B508C02D1B04EC88CC21BF", 100_000_000),
        ] {
            let quote = quote_swap(from, to, amount, evm).unwrap_or_else(|e| panic!("{from} -> {to} : {e:#}"));
            println!("{from} -> {to} : {} (routeur {:?})", quote.memo, quote.router);
            assert!(quote.router.is_some(), "source EVM : routeur attendu");
        }
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
