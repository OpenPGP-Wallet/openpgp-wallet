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

/// THORName (alias court) de `AFFILIATE_ADDRESS`, inscrit par le développeur
/// depuis l'app (Paramètres, voir `native_deposit`). Indispensable aux frais
/// d'affiliation DEPUIS Bitcoin : son memo tient en 80 octets (OP_RETURN), et
/// l'adresse `thor1…` complète (43 caractères) l'en faisait déborder —
/// constaté le 01/10/2026 (« generated memo too long for source chain »).
/// N'est utilisé qu'une fois relu sur le réseau (existe, non expiré, alias THOR
/// = `AFFILIATE_ADDRESS`, voir `verified_name`) : avant son inscription, ou
/// s'il expire, l'app retombe d'elle-même sur l'adresse complète (et sans
/// frais depuis Bitcoin), sans nouvelle version. 2 caractères : la plus
/// grande marge possible dans les memos (noms d'une lettre tous pris).
pub const AFFILIATE_NAME: Option<&str> = Some("ow");

/// MAYAName du développeur sur Maya (même nom, même règle), alias MAYA =
/// `MAYA_AFFILIATE_ADDRESS` : frais d'affiliation depuis Bitcoin et Zcash.
pub const MAYA_AFFILIATE_NAME: Option<&str> = Some("ow");

/// Nombre de blocs par an retenu par les deux protocoles pour la durée d'un
/// nom (une inscription inclut un an ; relevé sur de vraies inscriptions).
pub const NAME_BLOCKS_PER_YEAR: u64 = 5_256_000;

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

pub const ASSETS: [ThorAsset; 12] = [
    native("btc", "btc_mainnet", "BTC", "BTC.BTC", "b", 8),
    // Dogecoin (« d », relevé sur un vrai devis le 04/10/2026 : memo
    // `=:d:D…`) : en destination seulement (voir `swap_routes::BUY_ONLY`).
    native("doge", "doge_mainnet", "DOGE", "DOGE.DOGE", "d", 8),
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
    THORCHAIN.asset(coin, network)
}

/// Adresse d'affiliation sur Maya : la MÊME clé que `AFFILIATE_ADDRESS`
/// (même hash160, seul le préfixe bech32 change — test
/// `maya_affiliate_is_the_same_key_as_thorchain`).
pub const MAYA_AFFILIATE_ADDRESS: &str = "maya12j5rrcflhffxmq0ekwvk0h7g0mdy8gn4fl3z8f";

/// Pools disponibles sur Maya relevés en direct le 01/10/2026. Codes courts
/// propres à Maya, relevés sur de vrais devis : « a » y désigne l'ETH
/// d'Arbitrum (sur THORChain, « a » est AVAX). ZEC (« z », relevé dans
/// `Asset::ShortCode` de Mayanode, pool vérifié le 02/10/2026) : en
/// destination seulement (voir `swap_routes`).
pub const MAYA_ASSETS: [ThorAsset; 7] = [
    native("btc", "btc_mainnet", "BTC", "BTC.BTC", "b", 8),
    native("evm", "evm_mainnet", "ETH", "ETH.ETH", "e", 18),
    native("evm", "arbitrum_mainnet", "ETH", "ARB.ETH", "a", 18),
    erc20("usdc", "evm_mainnet", "USDC", "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", 6, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
    erc20("usdt", "evm_mainnet", "USDT", "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7", 6, "0xdac17f958d2ee523a2206206994597c13d831ec7"),
    erc20("usdc", "arbitrum_mainnet", "USDC", "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", 6, "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
    native("zec", "zec_mainnet", "ZEC", "ZEC.ZEC", "z", 8),
];

/// Protocole d'échange entre réseaux de la famille THORChain : THORChain et
/// son fork Maya (même API de devis, même format de memo, mêmes routeurs EVM
/// `depositWithExpiry`) ; chacun a sa passerelle, son affilié, ses pools et
/// ses codes courts.
pub struct CrossChain {
    pub name: &'static str,
    node_base: &'static str,
    /// Préfixe des routes de l'API (« thorchain », « mayachain »).
    module: &'static str,
    /// Chaîne native des alias de nom (« THOR », « MAYA »).
    native_chain: &'static str,
    /// Route de résolution d'un nom (« thorname », « mayaname »).
    name_route: &'static str,
    pub affiliate_address: &'static str,
    /// Nom court de l'affilié, indispensable aux échanges depuis Bitcoin
    /// (voir `AFFILIATE_NAME`).
    pub affiliate_name: Option<&'static str>,
    pub assets: &'static [ThorAsset],
}

pub const THORCHAIN: CrossChain = CrossChain {
    name: "THORChain",
    node_base: THORNODE_BASE,
    module: "thorchain",
    native_chain: "THOR",
    name_route: "thorname",
    affiliate_address: AFFILIATE_ADDRESS,
    affiliate_name: AFFILIATE_NAME,
    assets: &ASSETS,
};

pub const MAYA: CrossChain = CrossChain {
    name: "Maya",
    // Nœud public de Maya (vérifié en direct : devis, adresses d'entrée).
    node_base: "https://mayanode.mayachain.info",
    module: "mayachain",
    native_chain: "MAYA",
    name_route: "mayaname",
    affiliate_address: MAYA_AFFILIATE_ADDRESS,
    affiliate_name: MAYA_AFFILIATE_NAME,
    assets: &MAYA_ASSETS,
};

/// État d'une chaîne dans `inbound_addresses` (champs de pause absents chez
/// Maya : faux par défaut).
#[derive(Deserialize)]
struct InboundStatusJson {
    chain: String,
    #[serde(default)]
    halted: bool,
    #[serde(default)]
    chain_trading_paused: bool,
    #[serde(default)]
    global_trading_paused: bool,
}

/// Suspensions en cours (voir `CrossChain::halts`) ; `all` : pause générale.
struct Halts {
    all: bool,
    chains: Vec<String>,
}

impl Halts {
    fn from_statuses(chains: Vec<InboundStatusJson>) -> Self {
        Halts {
            all: chains.iter().any(|c| c.global_trading_paused),
            chains: chains.into_iter().filter(|c| c.halted || c.chain_trading_paused).map(|c| c.chain).collect(),
        }
    }

    fn covers(&self, asset: &str) -> bool {
        self.all || self.chains.iter().any(|c| c == chain_of(asset))
    }
}

/// « THORChain a suspendu les échanges sur Solana pour le moment… » (réseaux
/// omis s'ils sont inconnus).
pub fn halted_message(protocol: &str, networks: &[&str]) -> String {
    let place = if networks.is_empty() { String::new() } else { format!(" sur {}", networks.join(" et ")) };
    format!("{protocol} a suspendu les échanges{place} pour le moment (incident ou maintenance de son côté) — réessayez plus tard ou choisissez un autre fournisseur")
}

/// Chaîne d'un actif : « SOL » pour `SOL.SOL`, « ETH » pour `ETH.USDC-0X…`.
fn chain_of(asset: &str) -> &str {
    asset.split('.').next().unwrap_or(asset)
}

/// Chaînes de départ dont le memo voyage dans une sortie OP_RETURN, limitée
/// à 80 octets : Bitcoin, Dogecoin, et Zcash sur Maya (relevé le 03/10/2026 :
/// memo de 102 octets avec l'affilié `maya1…` complet, refusé).
fn memo_in_op_return(asset: &str) -> bool {
    matches!(chain_of(asset), "BTC" | "ZEC" | "DOGE")
}

/// Nom du réseau d'une chaîne, pour les messages.
fn chain_label(chain: &str) -> &str {
    match chain {
        "BTC" => "Bitcoin",
        "ETH" => "Ethereum",
        "SOL" => "Solana",
        "BASE" => "Base",
        "ARB" => "Arbitrum",
        "AVAX" => "Avalanche",
        "BSC" => "BNB Chain",
        "ZEC" => "Zcash",
        "DOGE" => "Dogecoin",
        other => other,
    }
}

#[derive(Deserialize)]
struct ThorNameJson {
    #[serde(default)]
    aliases: Vec<ThorNameAlias>,
    expire_block_height: Option<i64>,
    #[serde(default)]
    owner: String,
}

/// Nom court tel qu'enregistré sur le protocole.
#[derive(Clone, Debug, PartialEq)]
pub struct NameRecord {
    pub owner: String,
    pub expire_height: i64,
    pub current_height: i64,
    /// Alias de la chaîne native = l'adresse d'affiliation de l'app.
    pub points_to_affiliate: bool,
}

impl NameRecord {
    pub fn expired(&self) -> bool {
        self.expire_height <= self.current_height
    }
}

/// Affilié d'un devis depuis `from_asset` : le nom court vérifié, sinon
/// l'adresse complète — sauf depuis une chaîne à OP_RETURN, où elle ferait
/// déborder le memo : aucun affilié (échange sans frais pour l'app).
fn choose_affiliate(verified_name: Option<&'static str>, address: &'static str, from_asset: &str) -> Option<&'static str> {
    match verified_name {
        Some(name) => Some(name),
        None if memo_in_op_return(from_asset) => None,
        None => Some(address),
    }
}

/// Réussite gardée pour la session ; échec (nom pas encore inscrit, réseau
/// injoignable) relu après ce délai.
const NAME_RECHECK: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Deserialize)]
struct ThorNameAlias {
    chain: String,
    address: String,
}

/// Réponse de résolution d'un nom (`None` : inexistant) : propriétaire,
/// expiration, et si l'alias de la chaîne native est l'adresse d'affiliation.
fn parse_name(body: &str, current_height: i64, native_chain: &str, affiliate_address: &str) -> Result<Option<NameRecord>> {
    if body.contains("doesn't exist") {
        return Ok(None);
    }
    let parsed: ThorNameJson = serde_json::from_str(body).context("nom illisible")?;
    Ok(Some(NameRecord {
        points_to_affiliate: parsed.aliases.iter().any(|a| a.chain == native_chain && a.address == affiliate_address),
        owner: parsed.owner,
        expire_height: parsed.expire_block_height.unwrap_or(0),
        current_height,
    }))
}

impl CrossChain {
    pub fn asset(&self, coin: &str, network: &str) -> Option<&'static ThorAsset> {
        self.assets.iter().find(|a| a.coin == coin && a.network == network)
    }

    /// Affilié à inscrire dans un devis depuis `from_asset` (voir
    /// `choose_affiliate`).
    pub fn affiliate_for(&self, from_asset: &str) -> Option<&'static str> {
        choose_affiliate(self.verified_name(), self.affiliate_address, from_asset)
    }

    /// Frais d'affiliation prélevés sur un échange depuis `from_asset` ? Oui,
    /// sauf depuis Bitcoin ou Zcash tant que le nom court n'est pas inscrit et
    /// vérifié (memo à 4 champs).
    pub fn charges_affiliate(&self, from_asset: &str) -> bool {
        self.affiliate_for(from_asset).is_some()
    }

    /// Chaîne native des alias de nom (« THOR », « MAYA »).
    pub fn native_chain(&self) -> &'static str {
        self.native_chain
    }

    /// Nom court relu auprès du protocole : il doit exister, ne pas être
    /// expiré, et pointer vers l'adresse d'affiliation — sinon les frais
    /// iraient à quelqu'un d'autre (voir `NAME_RECHECK`). Tests unitaires :
    /// jamais vérifié (aucun appel réseau).
    fn verified_name(&self) -> Option<&'static str> {
        let name = self.affiliate_name?;
        if cfg!(test) {
            return None;
        }
        type Checked = std::sync::Mutex<std::collections::HashMap<&'static str, (bool, std::time::Instant)>>;
        static CHECKED: OnceLock<Checked> = OnceLock::new();
        let cache = CHECKED.get_or_init(Default::default);
        if let Some((ok, at)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(self.module).copied() {
            if ok || at.elapsed() < NAME_RECHECK {
                return ok.then_some(name);
            }
        }
        let ok = matches!(self.name_record(name), Ok(Some(record)) if record.points_to_affiliate && !record.expired());
        cache.lock().unwrap_or_else(|p| p.into_inner()).insert(self.module, (ok, std::time::Instant::now()));
        ok.then_some(name)
    }

    /// Nom `name` sur ce protocole (`None` s'il n'existe pas), avec la
    /// hauteur actuelle du réseau.
    pub fn name_record(&self, name: &str) -> Result<Option<NameRecord>> {
        let label = self.name;
        let body = shared_client()
            .get(format!("{}/{}/{}/{name}", self.node_base, self.module, self.name_route))
            .send()
            .with_context(|| format!("nœud {label} injoignable"))?
            .text()
            .with_context(|| format!("réponse {label} illisible"))?;
        if body.contains("doesn't exist") {
            return Ok(None);
        }
        let height: Vec<serde_json::Value> = shared_client()
            .get(format!("{}/{}/lastblock", self.node_base, self.module))
            .send()
            .with_context(|| format!("nœud {label} injoignable"))?
            .json()
            .with_context(|| format!("hauteur {label} illisible"))?;
        let current_height = height.first().and_then(|b| b.get(self.module)).and_then(serde_json::Value::as_i64).context("hauteur du réseau illisible")?;
        parse_name(&body, current_height, self.native_chain, self.affiliate_address).with_context(|| format!("nom {name} illisible chez {label}"))
    }

    /// Chaînes où les échanges sont suspendus en ce moment (chaîne arrêtée ou
    /// échanges en pause : incident, maintenance), lues sur
    /// `inbound_addresses`.
    fn halts(&self) -> Result<Halts> {
        let name = self.name;
        let url = format!("{}/{}/inbound_addresses", self.node_base, self.module);
        let chains: Vec<InboundStatusJson> = shared_client()
            .get(&url)
            .send()
            .with_context(|| format!("état des réseaux {name} illisible"))?
            .json()
            .with_context(|| format!("état des réseaux {name} illisible"))?;
        Ok(Halts::from_statuses(chains))
    }

    /// Actifs de ce protocole qu'il n'échange pas en ce moment.
    pub fn halted_assets(&self) -> Result<Vec<&'static ThorAsset>> {
        let halts = self.halts()?;
        Ok(self.assets.iter().filter(|a| halts.covers(a.asset)).collect())
    }

    /// Échange refusé parce qu'une chaîne est suspendue : laquelle, en clair
    /// (lue en direct ; non nommée si la lecture échoue).
    fn halt_message(&self, from_asset: &str, to_asset: &str) -> String {
        let mut networks: Vec<&str> = match self.halts() {
            Ok(halts) => [from_asset, to_asset].into_iter().filter(|a| halts.covers(a)).map(|a| chain_label(chain_of(a))).collect(),
            Err(_) => Vec::new(),
        };
        networks.dedup();
        halted_message(self.name, &networks)
    }

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
    /// Tarif de frais conseillé pour le dépôt (sat/vB sur Bitcoin), sous
    /// lequel le protocole peut tarder à le voir.
    pub recommended_gas_rate: Option<u64>,
    /// Affilié demandé par l'app pour ce devis (nom court ou adresse), et
    /// exigé tel quel dans le memo ; `None` : échange sans frais pour l'app.
    pub affiliate: Option<String>,
}

#[derive(Deserialize)]
struct QuoteResponseJson {
    inbound_address: Option<String>,
    router: Option<String>,
    memo: Option<String>,
    expected_amount_out: Option<String>,
    fees: Option<FeesJson>,
    recommended_gas_rate: Option<String>,
    /// Montant sous lequel un dépôt est ignoré (fonds perdus), et minimum
    /// conseillé (en dessous, un remboursement peut échouer) — en 1e8.
    dust_threshold: Option<String>,
    recommended_min_amount_in: Option<String>,
    /// Présent (avec `code`) sur une réponse d'erreur réelle — vérifié contre
    /// un appel en direct : `{"code":3,"message":"...","details":[]}`, PAS un
    /// champ `error` comme on pourrait le supposer par convention.
    code: Option<i64>,
    message: Option<String>,
    /// Erreur au format de Maya (champ unique).
    error: Option<String>,
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
    THORCHAIN.quote_swap(from_asset, to_asset, amount, destination)
}

/// Voir `CrossChain::verify_swap_memo` (THORChain).
pub fn verify_swap_memo(memo: &str, to_asset: &str, destination: &str, expected_amount_out: u64) -> Result<()> {
    THORCHAIN.verify_swap_memo(memo, to_asset, destination, expected_amount_out)
}

impl CrossChain {
    /// Devis d'échange (voir `quote_swap`), memo vérifié avant tout usage,
    /// avec l'affilié retenu par `affiliate_for`. Depuis Bitcoin ou Zcash, un
    /// gros échange découpé par le protocole (memo allongé de « /0/2147 »,
    /// relevé le 03/10/2026) peut ne plus tenir en 80 octets même avec le nom
    /// court : nouveau devis sans affilié (sans frais, dit dans la boîte de
    /// confirmation) plutôt qu'un refus.
    pub fn quote_swap(&self, from_asset: &str, to_asset: &str, amount: u64, destination: &str) -> Result<SwapQuote> {
        let affiliate = self.affiliate_for(from_asset);
        match self.quote_swap_as(from_asset, to_asset, amount, destination, affiliate) {
            Err(e) if affiliate.is_some() && memo_in_op_return(from_asset) && e.to_string().contains("memo too long") => {
                self.quote_swap_as(from_asset, to_asset, amount, destination, None)
            }
            other => other,
        }
    }

    /// Devis avec l'affilié `affiliate` imposé (`None` : sans frais) — pour
    /// relire un devis après la confirmation dans les conditions affichées.
    pub fn quote_swap_as(&self, from_asset: &str, to_asset: &str, amount: u64, destination: &str, affiliate: Option<&str>) -> Result<SwapQuote> {
        let name = self.name;
        let affiliate_query = affiliate.map(|a| format!("&affiliate={a}&affiliate_bps={AFFILIATE_FEE_BPS}")).unwrap_or_default();
        let url = format!(
            "{}/{}/quote/swap?from_asset={from_asset}&to_asset={to_asset}&amount={amount}&destination={destination}{affiliate_query}&liquidity_tolerance_bps={SWAP_TOLERANCE_BPS}",
            self.node_base, self.module
        );
        let response: QuoteResponseJson = shared_client()
            .get(&url)
            .send()
            .with_context(|| format!("requête de devis {name} impossible"))?
            .json()
            .with_context(|| format!("réponse de devis {name} illisible"))?;

        // Erreur : `code` + `message` chez THORChain, `error` seul chez Maya
        // (constaté : sans ce champ, le message de Maya était perdu).
        if response.code.is_some() || response.error.is_some() {
            let message = response.message.or(response.error).unwrap_or_else(|| "raison inconnue".to_string());
            // « trading is halted, can't process swap » (constaté le
            // 02/10/2026 : réseau Solana suspendu chez THORChain).
            if message.contains("halted") {
                anyhow::bail!("{}", self.halt_message(from_asset, to_asset));
            }
            anyhow::bail!("devis {name} refusé : {message}");
        }

        let inbound_address = response.inbound_address.ok_or_else(|| anyhow!("devis {name} sans adresse de vault"))?;
        let memo = response.memo.ok_or_else(|| anyhow!("devis {name} sans memo"))?;
        let expected_amount_out = response
            .expected_amount_out
            .ok_or_else(|| anyhow!("devis {name} sans montant de sortie attendu"))?
            .parse::<u64>()
            .context("montant de sortie attendu illisible")?;
        let total_fees = response.fees.and_then(|f| f.total).and_then(|s| s.parse::<u64>().ok());
        let number = |field: &Option<String>| field.as_deref().and_then(|s| s.parse::<u64>().ok());

        // Sous le seuil de poussière, le dépôt est ignoré : les fonds seraient
        // perdus (relevé : 10 000 sur Maya pour BTC et ZEC, 1 000 sur THORChain).
        let minimum = number(&response.dust_threshold).max(number(&response.recommended_min_amount_in));
        if let Some(minimum) = minimum.filter(|m| amount < *m) {
            anyhow::bail!(
                "montant trop faible pour {name} : au moins {} {} (en dessous, le dépôt serait ignoré ou son remboursement impossible)",
                format_1e8(minimum),
                ticker(from_asset)
            );
        }

        self.verify_memo(&memo, affiliate, to_asset, destination, expected_amount_out)?;

        Ok(SwapQuote {
            inbound_address,
            router: response.router,
            memo,
            expected_amount_out,
            total_fees,
            recommended_gas_rate: number(&response.recommended_gas_rate),
            affiliate: affiliate.map(str::to_string),
        })
    }
}

/// Montant en 1e8 lisible (« 0.0013944 »).
fn format_1e8(amount: u64) -> String {
    let text = format!("{}.{:08}", amount / 100_000_000, amount % 100_000_000);
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Symbole d'un actif (« BTC », « USDC » pour `ETH.USDC-0X…`).
fn ticker(asset: &str) -> &str {
    let ticker = asset.split_once('.').map_or(asset, |(_, t)| t);
    ticker.split_once('-').map_or(ticker, |(t, _)| t)
}

/// L'actif d'un memo désigne-t-il `to_asset` ? Formes relevées sur de vrais
/// devis : notation complète, code court d'un actif natif (« e », « b »,
/// « s » = BNB, « a », « f » = ETH sur Base ; « o » = SOL, code source de
/// THORNode), ou `CHAIN.TICKER` sans le contrat pour un jeton (« ETH.USDC »,
/// « BASE.VVV » : THORChain le résout vers son pool de ce jeton).
/// Les codes courts sont propres à chaque protocole (« a » = AVAX sur
/// THORChain, ETH d'Arbitrum sur Maya).
fn memo_asset_matches(assets: &[ThorAsset], field: &str, to_asset: &str) -> bool {
    if field.eq_ignore_ascii_case(to_asset) {
        return true;
    }
    if assets.iter().any(|a| a.asset.eq_ignore_ascii_case(to_asset) && a.short_code == Some(field)) {
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
/// Sans frais d'affiliation (départ Bitcoin ou Zcash, voir
/// `choose_affiliate`) : exactement les 4 premiers champs (relevé en direct :
/// `=:e:0x59D7…E6ba:31290403`) — un affilié inattendu est refusé. Avec : le
/// 5ᵉ champ doit être EXACTEMENT l'affilié demandé par l'app (adresse, ou nom
/// court vérifié) — sinon une passerelle pourrait substituer un nom court
/// inscrit par un autre.
impl CrossChain {
/// Memo d'un échange avec nos frais d'affiliation à l'adresse complète.
pub fn verify_swap_memo(&self, memo: &str, to_asset: &str, destination: &str, expected_amount_out: u64) -> Result<()> {
    self.verify_memo(memo, Some(self.affiliate_address), to_asset, destination, expected_amount_out)
}

/// Memo d'un échange avec l'affilié `affiliate` demandé (`None` : sans).
pub fn verify_memo(&self, memo: &str, affiliate: Option<&str>, to_asset: &str, destination: &str, expected_amount_out: u64) -> Result<()> {
    let fields: Vec<&str> = memo.split(':').collect();
    let expected_fields = if affiliate.is_some() { 6 } else { 4 };
    anyhow::ensure!(
        fields.len() == expected_fields,
        "memo THORChain inattendu ({} champs au lieu de {expected_fields}) : {memo}",
        fields.len()
    );

    // Alias du type "swap" dans le code source de THORNode (`memo.go`) : "swap", "s", "=".
    anyhow::ensure!(
        matches!(fields[0].to_ascii_lowercase().as_str(), "=" | "s" | "swap"),
        "memo THORChain qui n'est pas un swap : {memo}"
    );

    anyhow::ensure!(
        memo_asset_matches(self.assets, fields[1], to_asset),
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

    if let Some(affiliate) = affiliate {
        let ours = affiliate == self.affiliate_address || self.affiliate_name == Some(affiliate);
        anyhow::ensure!(
            ours && fields[4] == affiliate && fields[5] == AFFILIATE_FEE_BPS.to_string(),
            "frais d'affiliation du memo THORChain inattendus ({}:{}) — swap refusé",
            fields[4],
            fields[5]
        );
    }
    Ok(())
}
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_BTC: &str = "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz";

    /// Memo réel renvoyé par la passerelle (ETH -> BTC, liquidity_tolerance_bps=50).
    fn real_memo() -> String {
        format!("=:b:{DEST_BTC}:3146167:{AFFILIATE_ADDRESS}:80")
    }

    /// Départ Bitcoin ou Zcash sans nom court : devis sans affilié, memo à 4
    /// champs (formes réelles relevées le 03/10/2026) ; un affilié glissé dans
    /// un tel memo, même le nôtre, est refusé (frais non affichés).
    #[test]
    fn op_return_sources_carry_no_affiliate() {
        let evm = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        // Choix de l'affilié : nom vérifié partout ; sinon adresse, sauf depuis
        // Bitcoin / Zcash (aucun).
        assert_eq!(choose_affiliate(Some("ow"), AFFILIATE_ADDRESS, "BTC.BTC"), Some("ow"));
        assert_eq!(choose_affiliate(Some("ow"), AFFILIATE_ADDRESS, "ETH.ETH"), Some("ow"));
        assert_eq!(choose_affiliate(None, AFFILIATE_ADDRESS, "BTC.BTC"), None);
        assert_eq!(choose_affiliate(None, MAYA_AFFILIATE_ADDRESS, "ZEC.ZEC"), None);
        assert_eq!(choose_affiliate(None, AFFILIATE_ADDRESS, "ETH.ETH"), Some(AFFILIATE_ADDRESS));
        // Tests hors réseau : nom jamais vérifié.
        assert!(!THORCHAIN.charges_affiliate("BTC.BTC") && !MAYA.charges_affiliate("ZEC.ZEC"));
        assert!(THORCHAIN.charges_affiliate("ETH.ETH") && MAYA.charges_affiliate("ARB.ETH"));

        THORCHAIN.verify_memo(&format!("=:e:{evm}:31290403"), None, "ETH.ETH", evm, 31_606_468).expect("BTC → ETH");
        THORCHAIN
            .verify_memo(&format!("=:ETH.USDC:{evm}:83511423369"), None, "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", evm, 84_354_973_100)
            .expect("BTC → USDC");
        let with_fee = format!("=:e:{evm}:31290403:{AFFILIATE_ADDRESS}:80");
        assert!(THORCHAIN.verify_memo(&with_fee, None, "ETH.ETH", evm, 31_606_468).is_err(), "affilié inattendu");
        // Nom court : exigé tel que demandé, jamais substitué.
        let with_name = format!("=:e:{evm}:31290403:ow:80");
        THORCHAIN.verify_memo(&with_name, Some("ow"), "ETH.ETH", evm, 31_606_468).expect("nom court demandé");
        assert!(THORCHAIN.verify_memo(&with_name, Some(AFFILIATE_ADDRESS), "ETH.ETH", evm, 31_606_468).is_err(), "nom substitué à l'adresse demandée");
        assert!(THORCHAIN.verify_memo(&with_fee, Some("ow"), "ETH.ETH", evm, 31_606_468).is_err(), "adresse à la place du nom demandé");
        assert!(THORCHAIN.verify_memo(&format!("=:e:{evm}:31290403:zz:80"), Some("zz"), "ETH.ETH", evm, 31_606_468).is_err(), "nom d'un autre");

        MAYA.verify_memo(&format!("=:e:{evm}:48048634"), None, "ETH.ETH", evm, 48_533_974).expect("ZEC → ETH");
        MAYA.verify_memo(&format!("=:b:{DEST_BTC}:1521019"), None, "BTC.BTC", DEST_BTC, 1_536_383).expect("ZEC → BTC");
        MAYA.verify_memo(&format!("=:ARB.USDC:{evm}:92037029832"), None, "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", evm, 92_966_696_800)
            .expect("ZEC → USDC Arbitrum");
        MAYA.verify_memo(&format!("=:e:{evm}:48048634:ow:80"), Some("ow"), "ETH.ETH", evm, 48_533_974).expect("MAYAName");
        assert!(MAYA.verify_memo("=:e:0x1111111111111111111111111111111111111111:48048634", None, "ETH.ETH", evm, 48_533_974).is_err(), "autre destination");
        assert!(MAYA.verify_memo(&format!("=:e:{evm}:1000"), None, "ETH.ETH", evm, 48_533_974).is_err(), "limite dérisoire");
        assert!(MAYA.verify_memo(&format!("=:e:{evm}:48048634:maya1autre:9000"), None, "ETH.ETH", evm, 48_533_974).is_err(), "affilié étranger");
        assert!(MAYA.verify_memo(&format!("=:e:{evm}:48048634"), Some(MAYA_AFFILIATE_ADDRESS), "ETH.ETH", evm, 48_533_974).is_err(), "affilié exigé");
        assert_eq!((format_1e8(139_440), format_1e8(100_000_000), format_1e8(1_000)), ("0.0013944".to_string(), "1".to_string(), "0.00001".to_string()));
        assert_eq!((ticker("ZEC.ZEC"), ticker("ETH.USDC-0XA0B8")), ("ZEC", "USDC"));
    }

    /// Devis réels sans affilié depuis Bitcoin et Zcash (lecture seule), memo
    /// vérifié, et montant sous le seuil de poussière refusé.
    #[test]
    #[ignore]
    fn real_quotes_from_op_return_sources() {
        let evm = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        for (protocol, from, amount) in [(&THORCHAIN, "BTC.BTC", 1_000_000), (&MAYA, "BTC.BTC", 1_000_000), (&MAYA, "ZEC.ZEC", 100_000_000)] {
            let quote = protocol.quote_swap(from, "ETH.ETH", amount, evm).unwrap_or_else(|e| panic!("{} {from} : {e:#}", protocol.name));
            println!("{} {from} : {} ({} octets), gas {:?}", protocol.name, quote.memo, quote.memo.len(), quote.recommended_gas_rate);
            assert!(quote.memo.len() <= 80);
        }
        // Entre le seuil de poussière (10 000, refusé par Maya lui-même) et le
        // minimum conseillé (~139 000) : refusé par l'app.
        let err = MAYA.quote_swap("ZEC.ZEC", "ETH.ETH", 50_000, evm).err().expect("montant sous le minimum refusé").to_string();
        assert!(err.contains("trop faible"), "{err}");
    }

    /// Réponses réelles de `inbound_addresses` (abrégées) : réseau Solana
    /// suspendu chez THORChain le 02/10/2026 ; Maya sans champs de pause.
    #[test]
    fn reads_halted_chains() {
        let parse = |json: &str| Halts::from_statuses(serde_json::from_str(json).unwrap());
        let thor = parse(
            r#"[{"chain":"BTC","halted":false,"chain_trading_paused":false,"global_trading_paused":false},
                {"chain":"SOL","halted":true,"chain_trading_paused":true,"global_trading_paused":false}]"#,
        );
        assert!(thor.covers("SOL.SOL") && !thor.covers("BTC.BTC") && !thor.covers("ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48"));
        let maya = parse(r#"[{"chain":"ZEC","halted":false},{"chain":"ETH","halted":false}]"#);
        assert!(!maya.covers("ZEC.ZEC") && !maya.covers("ETH.ETH"));
        let paused = parse(r#"[{"chain":"BTC","halted":false,"global_trading_paused":true}]"#);
        assert!(paused.covers("ETH.ETH"), "pause générale : tout est suspendu");
        assert_eq!((chain_of("BASE.ETH"), chain_label("SOL"), chain_label("XYZ")), ("BASE", "Solana", "XYZ"));
    }

    /// Réseau : état réel des deux protocoles (lecture seule).
    #[test]
    #[ignore]
    fn real_halted_assets_are_readable() {
        for protocol in [&THORCHAIN, &MAYA] {
            let halted: Vec<&str> = protocol.halted_assets().unwrap().iter().map(|a| a.asset).collect();
            println!("{} : suspendus {halted:?}", protocol.name);
        }
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
        let usable = |body: &str, height: i64, chain: &str, address: &str| {
            matches!(parse_name(body, height, chain, address), Ok(Some(r)) if r.points_to_affiliate && !r.expired())
        };
        assert!(usable(&name(AFFILIATE_ADDRESS, 1000), 999, "THOR", AFFILIATE_ADDRESS), "bon alias, valide");
        assert!(!usable(&name("thor1xnkml34dfmhtmx3hfxte4jxrxn2j3604mtx5h0", 1000), 999, "THOR", AFFILIATE_ADDRESS), "autre adresse");
        assert!(!usable(&name(AFFILIATE_ADDRESS, 1000), 1000, "THOR", AFFILIATE_ADDRESS), "expiré");
        assert!(!usable(&name(AFFILIATE_ADDRESS, 1000), 999, "MAYA", MAYA_AFFILIATE_ADDRESS), "alias THOR, pas MAYA");
        let record = parse_name(&name(AFFILIATE_ADDRESS, 1000), 999, "THOR", AFFILIATE_ADDRESS).unwrap().unwrap();
        assert_eq!(record.owner, "thor1u7ent5406np9t9u35ls0vxnv8rcmlzudf9zpq0");
        // Réponse réelle d'un nom inexistant (relevée le 03/10/2026).
        let missing = r#"{"code":3,"message":"fail to fetch THORName: 2 errors occurred:
	* internal error
	* THORName doesn't exist: ow

: invalid request","details":[]}"#;
        assert_eq!(parse_name(missing, 0, "THOR", AFFILIATE_ADDRESS).unwrap(), None, "inexistant");
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

    /// L'affilié Maya est la MÊME clé que l'affilié THORChain : même hash160,
    /// seul le préfixe bech32 change.
    #[test]
    fn maya_affiliate_is_the_same_key_as_thorchain() {
        let (thor_hrp, thor_data, _) = bech32::decode(AFFILIATE_ADDRESS).unwrap();
        let (maya_hrp, maya_data, _) = bech32::decode(MAYA_AFFILIATE_ADDRESS).unwrap();
        assert_eq!((thor_hrp.as_str(), maya_hrp.as_str()), ("thor", "maya"));
        assert_eq!(thor_data, maya_data);
    }

    /// Memos RÉELS de Maya (devis du 01/10/2026) : « a » = ETH d'Arbitrum sur
    /// Maya (jamais AVAX, qui n'y existe pas), jeton en `ARB.USDC` ; l'affilié
    /// THORChain y est refusé, et inversement.
    #[test]
    fn maya_memos_follow_maya_codes_and_affiliate() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let arb_eth = format!("=:a:{evm}:3594616:{MAYA_AFFILIATE_ADDRESS}:80");
        MAYA.verify_swap_memo(&arb_eth, "ARB.ETH", evm, 3_630_926).expect("a = ARB.ETH sur Maya");
        assert!(THORCHAIN.verify_swap_memo(&arb_eth, "ARB.ETH", evm, 3_630_926).is_err(), "affilié Maya refusé sur THORChain");
        assert!(MAYA.verify_swap_memo(&arb_eth, "AVAX.AVAX", evm, 3_630_926).is_err(), "a n'est pas AVAX sur Maya");
        let usdc = format!("=:ARB.USDC:{evm}:24506475452:{MAYA_AFFILIATE_ADDRESS}:80");
        MAYA.verify_swap_memo(&usdc, "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", evm, 24_753_000_000).expect("jeton Arbitrum");
        let thor_affiliate = usdc.replace(MAYA_AFFILIATE_ADDRESS, AFFILIATE_ADDRESS);
        assert!(MAYA.verify_swap_memo(&thor_affiliate, "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", evm, 24_753_000_000).is_err());
    }

    /// Jetons de Maya = registre des jetons de l'app.
    #[test]
    fn maya_tokens_match_the_token_registry() {
        for a in MAYA_ASSETS.iter().filter(|a| a.contract.is_some()) {
            let (_, deployment) = crate::tokens::find(a.coin, a.network).unwrap_or_else(|| panic!("{} absent du registre", a.asset));
            let crate::tokens::TokenKind::Erc20 { contract } = deployment.kind else { panic!("{}", a.asset) };
            assert_eq!(Some(contract), a.contract, "{}", a.asset);
            assert_eq!(u32::from(deployment.decimals), a.decimals, "{}", a.asset);
        }
    }

    /// Devis RÉELS sur Maya (lecture seule) : Arbitrum vers Bitcoin et
    /// Ethereum, jeton Ethereum vers Arbitrum, échange sur Arbitrum même.
    /// `cargo test -- --ignored maya_quotes_match_the_real_network --nocapture`
    #[test]
    #[ignore]
    fn maya_quotes_match_the_real_network() {
        let evm = "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3";
        let zec = crate::zcash::p2pkh_address(&[0x11; 20]);
        for (from, to, amount, dest) in [
            ("ARB.ETH", "BTC.BTC", 10_000_000u64, "bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz"),
            ("ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", "ETH.ETH", 10_000_000_000, evm),
            ("ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7", "ARB.ETH", 10_000_000_000, evm),
            ("ARB.ETH", "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", 10_000_000, evm),
            ("ETH.ETH", "ZEC.ZEC", 10_000_000, zec.as_str()),
            ("ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", "ZEC.ZEC", 10_000_000_000, zec.as_str()),
        ] {
            let quote = MAYA.quote_swap(from, to, amount, dest).unwrap_or_else(|e| panic!("{from} -> {to} : {e:#}"));
            println!("{from} -> {to} : {} (routeur {:?})", quote.memo, quote.router);
            assert!(quote.router.is_some());
            MAYA.verify_swap_memo(&quote.memo, to, dest, quote.expected_amount_out).unwrap_or_else(|e| panic!("memo {from} -> {to} : {e:#}"));
        }
    }

    /// Devis RÉELS sur THORChain vers Dogecoin (lecture seule) : memo vérifié
    /// (code court « d », adresse D… exacte, minimum de sortie).
    /// `cargo test -- --ignored thorchain_quotes_to_dogecoin --nocapture`
    #[test]
    #[ignore]
    fn thorchain_quotes_to_dogecoin() {
        let doge = crate::doge::p2pkh_address(&[0x11; 20]);
        for (from, amount) in [("ETH.ETH", 10_000_000u64), ("BTC.BTC", 1_000_000), ("BSC.BNB", 10_000_000)] {
            let quote = THORCHAIN.quote_swap(from, "DOGE.DOGE", amount, &doge).unwrap_or_else(|e| panic!("{from} -> DOGE : {e:#}"));
            println!("{from} -> DOGE : {} ({} DOGE attendus)", quote.memo, quote.expected_amount_out as f64 / 1e8);
            assert!(quote.memo.contains(&format!(":d:{doge}")), "{}", quote.memo);
            // Même vérification que l'app : affilié du devis (aucun depuis Bitcoin).
            THORCHAIN.verify_memo(&quote.memo, quote.affiliate.as_deref(), "DOGE.DOGE", &doge, quote.expected_amount_out).unwrap_or_else(|e| panic!("memo {from} -> DOGE : {e:#}"));
            // Une autre adresse Dogecoin dans le memo : refusée.
            let other = crate::doge::p2pkh_address(&[0x22; 20]);
            assert!(THORCHAIN.verify_memo(&quote.memo, quote.affiliate.as_deref(), "DOGE.DOGE", &other, quote.expected_amount_out).is_err());
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
