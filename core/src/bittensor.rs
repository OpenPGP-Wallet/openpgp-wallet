//! Bittensor (TAO) : chaîne Substrate. Adresse SS58 (format 42, « 5… »),
//! clé sr25519 tirée de l'entropie maîtresse (même schéma que les
//! portefeuilles Substrate : mini-secret = PBKDF2-HMAC-SHA512(entropie,
//! « mnemonic », 2048)[..32], profils > 0 par dérivation dure « //n »),
//! solde, envoi (`Balances.transfer_keep_alive`), historique (Taostats).
//!
//! Le format d'une transaction dépend du runtime du réseau (mis à jour
//! souvent) : à chaque envoi, ses métadonnées sont relues et doivent
//! correspondre exactement à ce que ce module sait encoder (module et appel,
//! types du destinataire et du montant, extensions de signature) ; sinon,
//! refus net — jamais une transaction mal formée. Avant la diffusion, la
//! transaction est validée par le nœud lui-même (`validate_transaction`).
//!
//! Formats vérifiés le 07/10/2026 sur le réseau réel (runtime 473) et contre
//! les vecteurs de test de Substrate (comptes de développement).

use anyhow::{anyhow, bail, ensure, Context, Result};
use blake2b_simd::Params;
use frame_metadata::{v14::RuntimeMetadataV14, RuntimeMetadata, RuntimeMetadataPrefixed};
use parity_scale_codec::{Compact, Decode, Encode};
use scale_info::{form::PortableForm, PortableRegistry, TypeDef, TypeDefPrimitive};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey};
use serde_json::{json, Value};
use crate::history;
use std::sync::Mutex;
use std::time::Duration;

/// Nœud public de Bittensor (Opentensor Foundation).
pub const RPC: &str = "https://entrypoint-finney.opentensor.ai";
/// Bloc d'origine du réseau principal : tout autre nœud est refusé.
const GENESIS: [u8; 32] = hex_literal("2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03");
pub const DECIMALS: u8 = 9;
const SS58_PREFIX: u8 = 42;
/// Clé de stockage de `System.Account` : twox128("System") ++ twox128("Account").
const SYSTEM_ACCOUNT: [u8; 32] = hex_literal("26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9");
/// Durée de validité d'une transaction, en blocs (~13 min à 12 s le bloc).
const ERA_PERIOD: u64 = 64;

const fn hex_literal(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hexadécimal invalide"),
    }
}

fn blake2(len: usize, data: &[u8]) -> Vec<u8> {
    Params::new().hash_length(len).hash(data).as_bytes().to_vec()
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    blake2(32, data).try_into().expect("32 octets")
}

// --- Clés et adresses ---------------------------------------------------------------------

/// Paire de clés sr25519 du profil : racine pour le profil 0, dérivation
/// dure « //n » au-delà (chemin numérique Substrate : n encodé en u64).
pub fn keypair(entropy: &[u8], profile: u32) -> Result<Keypair> {
    ensure!((16..=32).contains(&entropy.len()) && entropy.len().is_multiple_of(4), "entropie de taille inattendue");
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(entropy, b"mnemonic", 2048, seed.as_mut());
    let mini = MiniSecretKey::from_bytes(&seed[..32]).map_err(|e| anyhow!("clé Bittensor : {e}"))?;
    let root = mini.expand_to_keypair(ExpansionMode::Ed25519);
    if profile == 0 {
        return Ok(root);
    }
    Ok(hard_derive(&root, &junction(&u64::from(profile).encode())))
}

/// Code de chaîne d'un segment de chemin (ses octets SCALE, complétés à 32,
/// ou leur blake2-256 au-delà).
fn junction(encoded: &[u8]) -> [u8; 32] {
    let mut cc = [0u8; 32];
    if encoded.len() > 32 {
        cc = blake2_256(encoded);
    } else {
        cc[..encoded.len()].copy_from_slice(encoded);
    }
    cc
}

fn hard_derive(pair: &Keypair, cc: &[u8; 32]) -> Keypair {
    pair.secret.hard_derive_mini_secret_key(Some(schnorrkel::derive::ChainCode(*cc)), b"").0.expand_to_keypair(ExpansionMode::Ed25519)
}

/// Adresse SS58 (format 42) d'une clé publique.
pub fn address(public: &[u8; 32]) -> String {
    let mut body = vec![SS58_PREFIX];
    body.extend_from_slice(public);
    let checksum = ss58_checksum(&body);
    body.extend_from_slice(&checksum[..2]);
    bs58::encode(body).into_string()
}

fn ss58_checksum(body: &[u8]) -> Vec<u8> {
    let mut data = b"SS58PRE".to_vec();
    data.extend_from_slice(body);
    blake2(64, &data)
}

/// Compte d'une adresse SS58 Bittensor (format 42, somme de contrôle
/// vérifiée). Une adresse d'un autre réseau Substrate (Polkadot « 1… »,
/// Kusama…) est refusée : c'est souvent une adresse de dépôt d'une
/// plateforme pour CE réseau-là.
pub fn parse_address(text: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(text.trim()).into_vec().map_err(|_| anyhow!("adresse Bittensor invalide"))?;
    ensure!(bytes.len() == 35, "adresse Bittensor invalide");
    ensure!(bytes[0] == SS58_PREFIX, "adresse d'un autre réseau que Bittensor (format SS58 {} au lieu de 42)", bytes[0]);
    ensure!(ss58_checksum(&bytes[..33])[..2] == bytes[33..], "adresse Bittensor invalide (somme de contrôle)");
    Ok(bytes[1..33].try_into().expect("32 octets"))
}

// --- Nœud -----------------------------------------------------------------------------------

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().expect("configuration du client HTTP valide"))
}

/// Erreur JSON-RPC du nœud (code et données), pour distinguer un refus net.
#[derive(Debug)]
pub struct NodeError {
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "le nœud Bittensor a refusé : {}", self.message)
    }
}

impl std::error::Error for NodeError {}

fn rpc(method: &str, params: Value) -> Result<Value> {
    let reply: Value = client()
        .post(RPC)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .map_err(|e| anyhow!("nœud Bittensor injoignable : {}", e.without_url()))?
        .json()
        .context("réponse du nœud Bittensor illisible")?;
    if let Some(error) = reply.get("error") {
        let message = match (error["message"].as_str(), error["data"].as_str()) {
            (Some(m), Some(d)) => format!("{m} ({d})"),
            (Some(m), None) => m.to_string(),
            _ => error.to_string(),
        };
        return Err(NodeError { code: error["code"].as_i64().unwrap_or(0), message }.into());
    }
    reply.get("result").cloned().context("réponse du nœud Bittensor sans résultat")
}

fn hex_bytes(value: &Value) -> Result<Vec<u8>> {
    let text = value.as_str().context("hexadécimal attendu")?;
    hex::decode(text.trim_start_matches("0x")).context("hexadécimal invalide")
}

fn state_call(method: &str, data: &[u8], at: Option<&[u8; 32]>) -> Result<Vec<u8>> {
    let mut params = vec![json!(method), json!(format!("0x{}", hex::encode(data)))];
    if let Some(at) = at {
        params.push(json!(format!("0x{}", hex::encode(at))));
    }
    hex_bytes(&rpc("state_call", Value::Array(params))?)
}

// --- Compte ---------------------------------------------------------------------------------

/// État d'un compte (en RAO, 10⁻⁹ TAO).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub nonce: u32,
    pub free: u64,
    pub reserved: u64,
    pub frozen: u64,
}

impl Account {
    /// Dépensable : le libre moins la part gelée qui n'est pas déjà réservée.
    pub fn spendable(&self) -> u64 {
        self.free.saturating_sub(self.frozen.saturating_sub(self.reserved))
    }
}

fn decode_account(bytes: &[u8]) -> Result<Account> {
    #[derive(Decode)]
    struct Info {
        nonce: u32,
        _consumers: u32,
        _providers: u32,
        _sufficients: u32,
        free: u64,
        reserved: u64,
        frozen: u64,
        _flags: u128,
    }
    let info = Info::decode(&mut &bytes[..]).context("compte Bittensor illisible")?;
    Ok(Account { nonce: info.nonce, free: info.free, reserved: info.reserved, frozen: info.frozen })
}

pub fn account(address_text: &str) -> Result<Account> {
    account_of(&parse_address(address_text)?)
}

fn account_of(id: &[u8; 32]) -> Result<Account> {
    let mut key = SYSTEM_ACCOUNT.to_vec();
    key.extend_from_slice(&blake2(16, id));
    key.extend_from_slice(id);
    match rpc("state_getStorage", json!([format!("0x{}", hex::encode(key))]))? {
        Value::Null => Ok(Account::default()),
        value => decode_account(&hex_bytes(&value)?),
    }
}

/// Solde affiché : TAO libres (en RAO).
pub fn balance(address_text: &str) -> Result<u64> {
    Ok(account(address_text)?.free)
}

/// RAO → texte en TAO (9 décimales, comme les autres soldes).
pub fn format_tao(rao: u64) -> String {
    format!("{}.{:09}", rao / 1_000_000_000, rao % 1_000_000_000)
}

// --- Format des transactions ----------------------------------------------------------------

/// Extension de signature, telle que ce module l'encode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Extension {
    /// Sans contenu (rien d'encodé).
    Empty,
    SpecVersion,
    TxVersion,
    Genesis,
    Mortality,
    Nonce,
    Tip,
    MetadataHash,
}

/// Ce que les métadonnées du runtime imposent, vérifié une fois par version.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Layout {
    spec_version: u32,
    tx_version: u32,
    balances: u8,
    transfer_keep_alive: u8,
    /// Réserve minimale d'un compte (`Balances.ExistentialDeposit`, 500 RAO
    /// le 07/10/2026).
    existential_deposit: u64,
    extensions: Vec<Extension>,
}

/// Type sans contenu (rien à encoder) ?
fn zero_sized(registry: &PortableRegistry, id: u32) -> bool {
    match registry.resolve(id).map(|t| &t.type_def) {
        Some(TypeDef::Composite(c)) => c.fields.iter().all(|f| zero_sized(registry, f.ty.id)),
        Some(TypeDef::Tuple(t)) => t.fields.iter().all(|f| zero_sized(registry, f.id)),
        Some(TypeDef::Array(a)) => a.len == 0 || zero_sized(registry, a.type_param.id),
        _ => false,
    }
}

/// Le type `id` (ou son seul champ) est-il de cette forme ?
fn unwrap_single(registry: &PortableRegistry, id: u32) -> Option<&TypeDef<PortableForm>> {
    let def = &registry.resolve(id)?.type_def;
    match def {
        TypeDef::Composite(c) if c.fields.len() == 1 => unwrap_single(registry, c.fields[0].ty.id),
        _ => Some(def),
    }
}

fn is_primitive(registry: &PortableRegistry, id: u32, primitive: TypeDefPrimitive) -> bool {
    matches!(unwrap_single(registry, id), Some(TypeDef::Primitive(p)) if *p == primitive)
}

fn is_hash(registry: &PortableRegistry, id: u32) -> bool {
    matches!(unwrap_single(registry, id), Some(TypeDef::Array(a)) if a.len == 32 && is_primitive(registry, a.type_param.id, TypeDefPrimitive::U8))
}

fn is_compact_of(registry: &PortableRegistry, id: u32, primitive: TypeDefPrimitive) -> bool {
    matches!(unwrap_single(registry, id), Some(TypeDef::Compact(c)) if is_primitive(registry, c.type_param.id, primitive))
}

/// Extensions reconnues : nom, et forme exacte de leurs données.
fn classify_extension(registry: &PortableRegistry, name: &str, extra: u32, additional: u32) -> Result<Extension> {
    let (empty_extra, empty_additional) = (zero_sized(registry, extra), zero_sized(registry, additional));
    let ok = match name {
        "CheckSpecVersion" if empty_extra && is_primitive(registry, additional, TypeDefPrimitive::U32) => Some(Extension::SpecVersion),
        "CheckTxVersion" if empty_extra && is_primitive(registry, additional, TypeDefPrimitive::U32) => Some(Extension::TxVersion),
        "CheckGenesis" if empty_extra && is_hash(registry, additional) => Some(Extension::Genesis),
        "CheckMortality" | "CheckEra" if is_hash(registry, additional) && matches!(unwrap_single(registry, extra), Some(TypeDef::Variant(_))) => Some(Extension::Mortality),
        "CheckNonce" if empty_additional && is_compact_of(registry, extra, TypeDefPrimitive::U32) => Some(Extension::Nonce),
        "ChargeTransactionPayment" if empty_additional && is_compact_of(registry, extra, TypeDefPrimitive::U64) => Some(Extension::Tip),
        "CheckMetadataHash" if matches!(unwrap_single(registry, extra), Some(TypeDef::Variant(_))) => Some(Extension::MetadataHash),
        _ if empty_extra && empty_additional => Some(Extension::Empty),
        _ => None,
    };
    ok.with_context(|| format!("le réseau Bittensor demande une donnée de transaction inconnue de cette version de l'app ({name}) : mettez l'app à jour"))
}

fn layout_from(metadata: &RuntimeMetadataV14, spec_version: u32, tx_version: u32) -> Result<Layout> {
    let update = "le format des transactions Bittensor a changé : mettez l'app à jour";
    ensure!(metadata.extrinsic.version == 4, update);
    let registry = &metadata.types;
    let pallet = metadata.pallets.iter().find(|p| p.name == "Balances").context(update)?;
    let calls = pallet.calls.as_ref().context(update)?;
    let Some(TypeDef::Variant(variants)) = registry.resolve(calls.ty.id).map(|t| &t.type_def) else { bail!(update) };
    let call = variants.variants.iter().find(|v| v.name == "transfer_keep_alive").context(update)?;
    ensure!(call.fields.len() == 2, update);
    // Destinataire : MultiAddress, « Id » en variante 0 ; montant : Compact<u64>.
    let Some(TypeDef::Variant(dest)) = registry.resolve(call.fields[0].ty.id).map(|t| &t.type_def) else { bail!(update) };
    let id = dest.variants.iter().find(|v| v.name == "Id").context(update)?;
    ensure!(id.index == 0 && id.fields.len() == 1 && unwrap_single(registry, id.fields[0].ty.id).is_some_and(|d| matches!(d, TypeDef::Array(a) if a.len == 32)), update);
    ensure!(is_compact_of(registry, call.fields[1].ty.id, TypeDefPrimitive::U64), update);
    let extensions = metadata
        .extrinsic
        .signed_extensions
        .iter()
        .map(|e| classify_extension(registry, &e.identifier, e.ty.id, e.additional_signed.id))
        .collect::<Result<Vec<_>>>()?;
    for required in [Extension::SpecVersion, Extension::TxVersion, Extension::Genesis, Extension::Mortality, Extension::Nonce, Extension::Tip] {
        ensure!(extensions.contains(&required), update);
    }
    let existential_deposit = pallet.constants.iter().find(|c| c.name == "ExistentialDeposit").and_then(|c| u64::decode(&mut &c.value[..]).ok()).context(update)?;
    ensure!(existential_deposit <= 1_000_000_000, update);
    Ok(Layout { spec_version, tx_version, balances: pallet.index, transfer_keep_alive: call.index, existential_deposit, extensions })
}

/// Format du runtime en cours (relu à chaque changement de version).
fn layout() -> Result<Layout> {
    static CACHE: Mutex<Option<Layout>> = Mutex::new(None);
    let runtime = rpc("state_getRuntimeVersion", json!([]))?;
    let spec_version = runtime["specVersion"].as_u64().and_then(|v| u32::try_from(v).ok()).context("version du runtime Bittensor illisible")?;
    let tx_version = runtime["transactionVersion"].as_u64().and_then(|v| u32::try_from(v).ok()).context("version des transactions Bittensor illisible")?;
    if let Some(cached) = CACHE.lock().unwrap_or_else(|p| p.into_inner()).as_ref().filter(|l| l.spec_version == spec_version && l.tx_version == tx_version) {
        return Ok(cached.clone());
    }
    let bytes = hex_bytes(&rpc("state_getMetadata", json!([]))?)?;
    let RuntimeMetadata::V14(metadata) = RuntimeMetadataPrefixed::decode(&mut &bytes[..]).context("métadonnées Bittensor illisibles")?.1 else {
        bail!("métadonnées Bittensor d'une version inattendue : mettez l'app à jour")
    };
    let fresh = layout_from(&metadata, spec_version, tx_version)?;
    *CACHE.lock().unwrap_or_else(|p| p.into_inner()) = Some(fresh.clone());
    Ok(fresh)
}

/// Ère mortelle (période, bloc courant) encodée sur 2 octets.
fn mortal_era(period: u64, current: u64) -> [u8; 2] {
    let period = period.next_power_of_two().clamp(4, 1 << 16);
    let phase = current % period;
    let quantize = (period >> 12).max(1);
    let encoded = (period.trailing_zeros() - 1).clamp(1, 15) as u16 | (((phase / quantize) << 4) as u16);
    encoded.to_le_bytes()
}

/// Données variables d'une transaction (lues sur le réseau).
#[derive(Clone, Debug, PartialEq, Eq)]
struct TxContext {
    nonce: u32,
    block_number: u64,
    block_hash: [u8; 32],
}

/// Appel `Balances.transfer_keep_alive(Id(dest), Compact(value))`.
fn transfer_call(layout: &Layout, dest: &[u8; 32], value: u64) -> Vec<u8> {
    let mut call = vec![layout.balances, layout.transfer_keep_alive, 0x00];
    call.extend_from_slice(dest);
    Compact(value).encode_to(&mut call);
    call
}

/// Données des extensions : « extra » (dans la transaction) et
/// « additionnelles » (signées seulement).
fn extensions(layout: &Layout, ctx: &TxContext) -> (Vec<u8>, Vec<u8>) {
    let (mut extra, mut additional) = (Vec::new(), Vec::new());
    for extension in &layout.extensions {
        match extension {
            Extension::Empty => {}
            Extension::SpecVersion => layout.spec_version.encode_to(&mut additional),
            Extension::TxVersion => layout.tx_version.encode_to(&mut additional),
            Extension::Genesis => additional.extend_from_slice(&GENESIS),
            Extension::Mortality => {
                extra.extend_from_slice(&mortal_era(ERA_PERIOD, ctx.block_number));
                additional.extend_from_slice(&ctx.block_hash);
            }
            Extension::Nonce => Compact(ctx.nonce).encode_to(&mut extra),
            Extension::Tip => Compact(0u64).encode_to(&mut extra),
            Extension::MetadataHash => {
                extra.push(0); // mode « Disabled »
                additional.push(0); // None
            }
        }
    }
    (extra, additional)
}

/// Transaction signée (encodée, longueur comprise). `sign` reçoit les
/// octets à signer (le message, ou son blake2-256 au-delà de 256 octets).
fn signed_extrinsic(layout: &Layout, ctx: &TxContext, from: &[u8; 32], call: &[u8], sign: impl FnOnce(&[u8]) -> [u8; 64]) -> Vec<u8> {
    let (extra, additional) = extensions(layout, ctx);
    let mut payload = call.to_vec();
    payload.extend_from_slice(&extra);
    payload.extend_from_slice(&additional);
    let signature = if payload.len() > 256 { sign(&blake2_256(&payload)) } else { sign(&payload) };
    let mut body = vec![0x84, 0x00];
    body.extend_from_slice(from);
    body.push(0x01); // MultiSignature::Sr25519
    body.extend_from_slice(&signature);
    body.extend_from_slice(&extra);
    body.extend_from_slice(call);
    let mut encoded = Compact(body.len() as u32).encode();
    encoded.extend_from_slice(&body);
    encoded
}

fn sr25519_sign(pair: &Keypair, message: &[u8]) -> [u8; 64] {
    pair.sign(schnorrkel::signing_context(b"substrate").bytes(message)).to_bytes()
}

/// Bloc finalisé (numéro, empreinte), nonce du compte, et contrôle du réseau.
fn context(from: &str) -> Result<TxContext> {
    let genesis = hex_bytes(&rpc("chain_getBlockHash", json!([0]))?)?;
    ensure!(genesis == GENESIS, "ce nœud n'est pas sur le réseau principal Bittensor");
    let hash_value = rpc("chain_getFinalizedHead", json!([]))?;
    let block_hash: [u8; 32] = hex_bytes(&hash_value)?.try_into().map_err(|_| anyhow!("empreinte de bloc Bittensor invalide"))?;
    let header = rpc("chain_getHeader", json!([hash_value]))?;
    let block_number = u64::from_str_radix(header["number"].as_str().context("numéro de bloc Bittensor absent")?.trim_start_matches("0x"), 16).context("numéro de bloc Bittensor invalide")?;
    let nonce = rpc("system_accountNextIndex", json!([from]))?.as_u64().and_then(|n| u32::try_from(n).ok()).context("nonce Bittensor illisible")?;
    Ok(TxContext { nonce, block_number, block_hash })
}

/// Résultat de la validation par le nœud (sans diffusion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    Valid,
    /// Refus du runtime : 1 = frais impayables, 4 = signature invalide…
    Invalid(u8),
    /// Validité indéterminée (code « Unknown »).
    Unknown(u8),
}

fn validate(extrinsic: &[u8], at: &[u8; 32]) -> Result<Validity> {
    let mut data = vec![2u8]; // TransactionSource::External
    data.extend_from_slice(extrinsic);
    data.extend_from_slice(at);
    let reply = state_call("TaggedTransactionQueue_validate_transaction", &data, None)?;
    Ok(match reply.as_slice() {
        [0, ..] => Validity::Valid,
        [1, 0, code, ..] => Validity::Invalid(*code),
        [1, 1, code, ..] => Validity::Unknown(*code),
        _ => bail!("réponse de validation Bittensor inattendue"),
    })
}

/// Frais estimés par le runtime (`TransactionPaymentApi_query_info`), en RAO.
fn query_fee(extrinsic: &[u8]) -> Result<u64> {
    let mut data = extrinsic.to_vec();
    (extrinsic.len() as u32).encode_to(&mut data);
    let reply = state_call("TransactionPaymentApi_query_info", &data, None)?;
    #[derive(Decode)]
    struct Info {
        _ref_time: Compact<u64>,
        _proof_size: Compact<u64>,
        _class: u8,
        partial_fee: u64,
    }
    Ok(Info::decode(&mut &reply[..]).context("frais Bittensor illisibles")?.partial_fee)
}

fn validity_error(validity: Validity) -> anyhow::Error {
    match validity {
        Validity::Invalid(1) => anyhow!("TAO insuffisants pour payer les frais du réseau"),
        Validity::Invalid(4) => anyhow!("transaction Bittensor refusée : signature invalide (format du réseau changé ?) — rien n'a été envoyé"),
        Validity::Invalid(3) | Validity::Invalid(2) => anyhow!("transaction Bittensor refusée (nonce) : une autre transaction est peut-être en cours — réessayez dans un instant"),
        other => anyhow!("transaction Bittensor refusée par le réseau ({other:?}) — rien n'a été envoyé"),
    }
}

/// Envoi préparé pour la boîte de confirmation : montant et frais exacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaoPlan {
    pub to: String,
    pub amount: u64,
    pub fee: u64,
}

/// Frais au-delà desquels l'envoi est refusé (un virement coûte ~0,0001 TAO
/// le 07/10/2026) : un nœud qui annoncerait des frais aberrants.
const MAX_FEE: u64 = 10_000_000;

/// Frais d'un virement de `amount` vers `to_id`, estimés sur la transaction
/// réelle signée par une signature factice (même longueur).
fn transfer_fee(layout: &Layout, ctx: &TxContext, from_id: &[u8; 32], to_id: &[u8; 32], amount: u64) -> Result<u64> {
    let fee = query_fee(&signed_extrinsic(layout, ctx, from_id, &transfer_call(layout, to_id, amount), |_| [0u8; 64]))?;
    ensure!(fee <= MAX_FEE, "frais du réseau Bittensor anormalement élevés ({} TAO) — réessayez plus tard", format_tao(fee));
    Ok(fee)
}

/// Prépare un virement : solde, frais, réserve minimale de l'envoyeur
/// (`transfer_keep_alive`), et compte destinataire ouvert par ce virement.
/// Ces refus-là ne sont PAS vus par la validation du nœud : la transaction
/// partirait, frais payés, puis échouerait.
pub fn plan(from: &str, to: &str, amount: u64) -> Result<TaoPlan> {
    let from_id = parse_address(from)?;
    let to_id = parse_address(to)?;
    ensure!(from_id != to_id, "envoi vers votre propre adresse Bittensor");
    ensure!(amount > 0, "montant nul");
    let layout = layout()?;
    let ctx = context(from)?;
    let fee = transfer_fee(&layout, &ctx, &from_id, &to_id, amount)?;
    let account = account(from)?;
    let needed = amount.checked_add(fee).and_then(|n| n.checked_add(layout.existential_deposit)).context("montant trop grand")?;
    ensure!(
        account.spendable() >= needed,
        "TAO insuffisants : {} TAO disponibles, {} TAO requis (frais {} TAO et réserve du compte {} TAO compris)",
        format_tao(account.spendable()),
        format_tao(needed),
        format_tao(fee),
        format_tao(layout.existential_deposit)
    );
    let recipient = account_of(&to_id)?;
    ensure!(
        recipient.free.saturating_add(recipient.reserved) > 0 || amount >= layout.existential_deposit,
        "montant trop faible pour ce destinataire (compte vide) : au moins {} TAO",
        format_tao(layout.existential_deposit)
    );
    Ok(TaoPlan { to: address(&to_id), amount, fee })
}

/// État d'une adresse destinataire, pour les avertissements de la boîte :
/// (détient des TAO, déjà utilisée).
pub fn address_activity(address_text: &str) -> Result<(bool, bool)> {
    let account = account(address_text)?;
    Ok((account.free.saturating_add(account.reserved) > 0, account.nonce > 0))
}

/// Montant maximal envoyable (frais et réserve minimale déduits).
pub fn max_amount(from: &str, to: Option<&str>) -> Result<u64> {
    let from_id = parse_address(from)?;
    let to_id = to.and_then(|t| parse_address(t).ok()).unwrap_or([1u8; 32]);
    let layout = layout()?;
    let ctx = context(from)?;
    let account = account(from)?;
    let fee = transfer_fee(&layout, &ctx, &from_id, &to_id, account.spendable())?;
    let max = account.spendable().saturating_sub(fee).saturating_sub(layout.existential_deposit);
    ensure!(max > 0, "aucun TAO envoyable sur cette adresse");
    Ok(max)
}

/// Signe, fait valider par le nœud, puis diffuse ; renvoie l'empreinte de
/// la transaction. Refus net : rien n'est parti ; sans réponse nette après
/// l'envoi : « peut-être partie » (voir `wallet_flow::maybe_sent`).
pub fn send(pair: &Keypair, plan: &TaoPlan) -> Result<String> {
    let from_id = pair.public.to_bytes();
    let from = address(&from_id);
    let to_id = parse_address(&plan.to)?;
    let layout = layout()?;
    let ctx = context(&from)?;
    let extrinsic = signed_extrinsic(&layout, &ctx, &from_id, &transfer_call(&layout, &to_id, plan.amount), |m| sr25519_sign(pair, m));
    match validate(&extrinsic, &ctx.block_hash)? {
        Validity::Valid => {}
        other => return Err(validity_error(other)),
    }
    let hash = format!("0x{}", hex::encode(blake2_256(&extrinsic)));
    match rpc("author_submitExtrinsic", json!([format!("0x{}", hex::encode(&extrinsic))])) {
        Ok(returned) => {
            // Le nœud renvoie l'empreinte de ce qu'il a reçu : la même. Sinon,
            // transaction quand même acceptée : « peut-être partie », jamais
            // « refusée » — un nouvel envoi la paierait deux fois (32ᵉ passage).
            if !returned.as_str().is_some_and(|r| r.eq_ignore_ascii_case(&hash)) {
                return Err(crate::wallet_flow::maybe_sent(&hash));
            }
            Ok(hash)
        }
        Err(e) => {
            let node = e.downcast_ref::<NodeError>();
            if node.is_some_and(|n| n.message.contains("already imported") || n.code == 1013 && n.message.contains("Already")) {
                return Ok(hash);
            }
            if node.is_some() {
                // Refus net du nœud (validation, débit) : rien n'est parti.
                return Err(e);
            }
            match e.chain().find_map(|c| c.downcast_ref::<reqwest::Error>()) {
                Some(network) if crate::wallet_flow::nothing_sent(network) => Err(e),
                _ => Err(crate::wallet_flow::maybe_sent(&hash)),
            }
        }
    }
}

// --- Historique (Taostats) ----------------------------------------------------------------

/// Clé de l'API Taostats, intégrée À LA COMPILATION (`TAOSTATS_API_KEY` dans
/// `partner-keys.env`, voir build.rs) : sans elle, la page de l'adresse sur
/// l'explorateur à la place.
const TAOSTATS_KEY: Option<&str> = option_env!("TAOSTATS_API_KEY");
const TAOSTATS: &str = "https://api.taostats.io/api/transfer/v1";
pub const HISTORY_KEY_MISSING: &str = "historique Bittensor indisponible dans cette version de l'app";
pub const HISTORY_LIMITED: &str = "historique Bittensor momentanément indisponible (limite du service atteinte) — réessayez plus tard";

pub fn history_available() -> bool {
    TAOSTATS_KEY.is_some()
}

/// Page de l'adresse sur l'explorateur Taostats.
pub fn explorer_address_url(address_text: &str) -> String {
    format!("https://taostats.io/account/{}", address_text.trim())
}

/// Lien d'une transaction de l'historique (identifiant « bloc-index »).
pub fn explorer_tx_url(extrinsic_id: &str) -> String {
    format!("https://taostats.io/extrinsic/{extrinsic_id}")
}

/// Virements de TAO de l'adresse (reçus − envoyés, frais de l'envoyeur à
/// part), les plus récents d'abord. Identifiant : « bloc-index » de la
/// transaction (celui des liens de Taostats).
pub fn history(address_text: &str, limit: usize) -> Result<Vec<history::TxEntry>> {
    let me = parse_address(address_text)?;
    let key = TAOSTATS_KEY.ok_or_else(|| anyhow!(HISTORY_KEY_MISSING))?;
    let url = format!("{TAOSTATS}?network=finney&address={}&limit={}&order=block_number_desc", address(&me), limit.clamp(1, 200));
    let response = client().get(url).header("Authorization", key).send().map_err(|e| anyhow!("Taostats injoignable : {}", e.without_url()))?;
    match response.status().as_u16() {
        429 => bail!(HISTORY_LIMITED),
        401 | 403 => bail!("clé Taostats refusée"),
        code if !(200..300).contains(&code) => bail!("Taostats : réponse {code}"),
        _ => {}
    }
    parse_transfers(&response.json().context("réponse de Taostats illisible")?, &me)
}

/// Compte d'une partie (« from »/« to ») d'un virement Taostats.
fn party(value: &Value) -> Option<[u8; 32]> {
    value["ss58"].as_str().and_then(|s| parse_address(s).ok()).or_else(|| hex::decode(value["hex"].as_str()?.trim_start_matches("0x")).ok()?.try_into().ok())
}

fn rao(value: &Value) -> Option<i128> {
    match value {
        Value::String(text) => text.parse::<u64>().ok().map(i128::from),
        other => other.as_u64().map(i128::from),
    }
}

fn parse_transfers(body: &Value, me: &[u8; 32]) -> Result<Vec<history::TxEntry>> {
    let items = body["data"].as_array().context("réponse de Taostats illisible")?;
    let mut entries: Vec<history::TxEntry> = Vec::new();
    for item in items {
        let Some(id) = item["extrinsic_id"].as_str().filter(|id| id.split_once('-').is_some_and(|(b, i)| !b.is_empty() && !i.is_empty() && b.bytes().chain(i.bytes()).all(|c| c.is_ascii_digit()))) else { continue };
        let (Some(from), Some(to), Some(amount)) = (party(&item["from"]), party(&item["to"]), rao(&item["amount"])) else { continue };
        let (sent, received) = (from == *me, to == *me);
        if !sent && !received {
            continue;
        }
        let net = if received { amount } else { 0 } - if sent { amount } else { 0 };
        let fee = if sent { rao(&item["fee"]).unwrap_or(0) } else { 0 };
        // Plusieurs virements dans une même transaction (lot) : une ligne,
        // frais comptés une fois.
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.net_amount_minor = entry.net_amount_minor.map(|n| n + net);
            entry.fee_minor = entry.fee_minor.max(fee);
            continue;
        }
        entries.push(history::TxEntry {
            id: id.to_string(),
            timestamp_unix: item["timestamp"].as_str().and_then(crate::blockscout::parse_iso8601_utc),
            // Taostats ne liste que les virements exécutés.
            status: history::TxStatus::Confirmed,
            net_amount_minor: Some(net),
            fee_minor: fee,
            kind: history::TxKind::Other,
        });
    }
    for entry in &mut entries {
        entry.kind = match entry.net_amount_minor {
            Some(n) if n > 0 => history::TxKind::Received,
            Some(n) if n < 0 => history::TxKind::Sent,
            _ => history::TxKind::Other,
        };
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    fn dev_entropy() -> Vec<u8> {
        bip39::Mnemonic::parse(DEV_PHRASE).unwrap().to_entropy()
    }

    /// Vecteurs des comptes de développement Substrate (phrase publique
    /// DEV_PHRASE) : chemins durs « //Alice », « //Bob », adresses SS58 42.
    #[test]
    fn keys_and_addresses_match_substrate() {
        let mini = {
            let mut seed = [0u8; 64];
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&dev_entropy(), b"mnemonic", 2048, &mut seed);
            MiniSecretKey::from_bytes(&seed[..32]).unwrap().expand_to_keypair(ExpansionMode::Ed25519)
        };
        let derive = |name: &str| hard_derive(&mini, &junction(&name.encode()));
        let alice = derive("Alice");
        assert_eq!(hex::encode(alice.public.to_bytes()), "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
        assert_eq!(address(&alice.public.to_bytes()), "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
        assert_eq!(address(&derive("Bob").public.to_bytes()), "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
        // Racine (profil 0) et profil 1 (« //1 ») : distincts et stables.
        let root = keypair(&dev_entropy(), 0).unwrap();
        assert_eq!(root.public, mini.public);
        assert_ne!(keypair(&dev_entropy(), 1).unwrap().public, root.public);
        assert_eq!(keypair(&dev_entropy(), 1).unwrap().public, hard_derive(&mini, &junction(&1u64.encode())).public);
        // Lecture d'adresse : somme de contrôle, réseau.
        assert_eq!(parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap(), alice.public.to_bytes());
        assert!(parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ").is_err());
        // Même compte au format Polkadot (0) : refusé.
        let polkadot = {
            let mut body = vec![0u8];
            body.extend_from_slice(&alice.public.to_bytes());
            let mut data = b"SS58PRE".to_vec();
            data.extend_from_slice(&body);
            body.extend_from_slice(&blake2(64, &data)[..2]);
            bs58::encode(body).into_string()
        };
        assert!(parse_address(&polkadot).unwrap_err().to_string().contains("autre réseau"));
    }

    /// Ère mortelle : vecteurs de Substrate (`Era::mortal`).
    #[test]
    fn eras_match_substrate() {
        assert_eq!(mortal_era(64, 42), [0xa5, 0x02]);
        assert_eq!(mortal_era(32768, 20_000), [78, 156]);
    }

    #[test]
    fn amounts_and_accounts_are_read() {
        assert_eq!(format_tao(1_500_000_000), "1.500000000");
        assert_eq!(format_tao(83_124), "0.000083124");
        let mut bytes = Vec::new();
        (7u32, 0u32, 1u32, 0u32, 5_000u64, 100u64, 300u64, 0u128).encode_to(&mut bytes);
        let account = decode_account(&bytes).unwrap();
        assert_eq!((account.nonce, account.free, account.spendable()), (7, 5_000, 4_800));
    }

    /// Virements Taostats (format de leur documentation) : sens, frais de
    /// l'envoyeur seulement, lot d'une même transaction fusionné, lignes
    /// d'autres comptes ou illisibles écartées.
    #[test]
    fn taostats_transfers_are_read() {
        let me = parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
        let bob = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
        let me_hex = format!("0x{}", hex::encode(me));
        let body = json!({ "pagination": { "current_page": 1 }, "data": [
            { "extrinsic_id": "6611494-0037", "timestamp": "2025-02-26T13:57:36Z", "amount": "1500000000", "fee": "83124",
              "from": { "ss58": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "hex": me_hex }, "to": { "ss58": bob } },
            { "extrinsic_id": "6611400-0002", "timestamp": "2025-02-26T13:00:00Z", "amount": "250000000", "fee": "90000",
              "from": { "ss58": bob }, "to": { "ss58": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" } },
            // Lot : deux virements dans la même transaction.
            { "extrinsic_id": "6611300-0005", "amount": "100", "fee": "70000", "from": { "hex": me_hex }, "to": { "ss58": bob } },
            { "extrinsic_id": "6611300-0005", "amount": "200", "fee": "70000", "from": { "hex": me_hex }, "to": { "ss58": bob } },
            { "extrinsic_id": "6611200-0001", "amount": "5", "fee": "1", "from": { "ss58": bob }, "to": { "ss58": bob } },
            { "extrinsic_id": "../evil", "amount": "5", "fee": "1", "from": { "ss58": bob }, "to": { "hex": me_hex } },
        ]});
        let entries = parse_transfers(&body, &me).unwrap();
        let summary: Vec<_> = entries.iter().map(|e| (e.id.as_str(), e.net_amount_minor, e.fee_minor, &e.kind)).collect();
        assert_eq!(
            summary,
            [
                ("6611494-0037", Some(-1_500_000_000), 83_124, &history::TxKind::Sent),
                ("6611400-0002", Some(250_000_000), 0, &history::TxKind::Received),
                ("6611300-0005", Some(-300), 70_000, &history::TxKind::Sent),
            ]
        );
        assert_eq!(entries[0].timestamp_unix, Some(1_740_578_256));
        assert!(parse_transfers(&json!({ "message": "x" }), &me).is_err());
    }

    /// Réel : métadonnées du réseau conformes au format encodé ici.
    /// `cargo test -- --ignored real_bittensor_layout --nocapture`
    #[test]
    #[ignore]
    fn real_bittensor_layout() {
        let layout = layout().unwrap();
        println!("{layout:?}");
        assert_eq!((layout.balances, layout.transfer_keep_alive, layout.existential_deposit), (5, 3, 500));
    }

    /// Réel : un virement correctement signé depuis un compte vide est
    /// refusé par le nœud pour frais impayables (code 1) — jamais pour
    /// signature invalide (4) : signature et extensions sont donc justes.
    /// Une signature altérée, elle, est refusée comme invalide. Rien n'est
    /// diffusé (`validate_transaction` seulement). Frais estimés.
    /// `cargo test -- --ignored real_bittensor_signature --nocapture`
    #[test]
    #[ignore]
    fn real_bittensor_signature() {
        let pair = keypair(&[9u8; 32], 7).unwrap();
        let from = address(&pair.public.to_bytes());
        let to = parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
        let layout = layout().unwrap();
        let ctx = context(&from).unwrap();
        let call = transfer_call(&layout, &to, 1_000_000);
        let extrinsic = signed_extrinsic(&layout, &ctx, &pair.public.to_bytes(), &call, |m| sr25519_sign(&pair, m));
        let validity = validate(&extrinsic, &ctx.block_hash).unwrap();
        println!("compte vide {from} : {validity:?}, frais estimés {} TAO", format_tao(query_fee(&extrinsic).unwrap()));
        assert_eq!(validity, Validity::Invalid(1), "frais impayables attendus");
        let forged = signed_extrinsic(&layout, &ctx, &pair.public.to_bytes(), &call, |m| {
            let mut s = sr25519_sign(&pair, m);
            s[10] ^= 1;
            s
        });
        assert_eq!(validate(&forged, &ctx.block_hash).unwrap(), Validity::Invalid(4), "signature altérée : refus attendu");
    }

    /// Réel (clé Taostats requise) : historique d'un compte actif recoupé
    /// avec la chaîne. Chaque ligne « bloc-index » désigne bien la
    /// transaction dont Taostats donne l'empreinte (blake2-256 des octets lus
    /// sur le nœud) ; pour un virement direct (`Balances`), destinataire et
    /// montant relus dans la transaction = ceux de l'historique.
    /// `cargo test -- --ignored real_taostats_history --nocapture`
    #[test]
    #[ignore]
    fn real_taostats_history() {
        assert!(history_available(), "TAOSTATS_API_KEY absente de partner-keys.env");
        let me_text = "5FHxxe8ZKYaNmGcSLdG5ekxXeZDhQnk9cbpHdsJW8RunGpSs";
        let me = parse_address(me_text).unwrap();
        let entries = history(me_text, 20).unwrap();
        assert!(!entries.is_empty(), "aucun virement");
        // Données brutes (empreintes), même requête.
        let raw: Value = client()
            .get(format!("{TAOSTATS}?network=finney&address={me_text}&limit=20&order=block_number_desc"))
            .header("Authorization", TAOSTATS_KEY.unwrap())
            .send()
            .unwrap()
            .json()
            .unwrap();
        let layout = layout().unwrap();
        let (mut hashes, mut amounts) = (0, 0);
        for entry in &entries {
            let (block, index) = entry.id.split_once('-').unwrap();
            let (block, index): (u64, usize) = (block.parse().unwrap(), index.parse().unwrap());
            let hash = rpc("chain_getBlockHash", json!([block])).unwrap();
            let extrinsic = hex_bytes(&rpc("chain_getBlock", json!([hash])).unwrap()["block"]["extrinsics"][index]).unwrap();
            let expected = raw["data"].as_array().unwrap().iter().find(|i| i["extrinsic_id"] == entry.id.as_str()).unwrap()["transaction_hash"].as_str().unwrap().to_lowercase();
            assert_eq!(format!("0x{}", hex::encode(blake2_256(&extrinsic))), expected, "{} : autre transaction à cette position", entry.id);
            hashes += 1;
            // Virement direct signé (format du runtime actuel) : appel relu.
            let mut input = &extrinsic[..];
            let _len = Compact::<u32>::decode(&mut input).unwrap();
            if input.len() < 100 || input[0] != 0x84 || input[1] != 0x00 || input[34] != 0x01 {
                continue;
            }
            let signer: [u8; 32] = input[2..34].try_into().unwrap();
            input = &input[99..];
            for extension in &layout.extensions {
                match extension {
                    Extension::Mortality => input = &input[if input[0] == 0 { 1 } else { 2 }..],
                    Extension::Nonce => drop(Compact::<u32>::decode(&mut input).unwrap()),
                    Extension::Tip => drop(Compact::<u64>::decode(&mut input).unwrap()),
                    Extension::MetadataHash => input = &input[1..],
                    _ => {}
                }
            }
            if input.len() < 35 || input[0] != layout.balances || !matches!(input[1], 0 | 3) || input[2] != 0x00 {
                continue;
            }
            let dest: [u8; 32] = input[3..35].try_into().unwrap();
            let mut rest = &input[35..];
            let value = i128::from(Compact::<u64>::decode(&mut rest).unwrap().0);
            let net = entry.net_amount_minor.unwrap();
            if signer == me {
                assert_eq!(net, -value, "{} : montant envoyé", entry.id);
            } else {
                assert_eq!(dest, me, "{} : destinataire", entry.id);
                assert_eq!(net, value, "{} : montant reçu", entry.id);
            }
            amounts += 1;
            println!("{} {:?} {} TAO (frais {}) vérifié sur la chaîne", entry.id, entry.kind, format_tao(value as u64), format_tao(entry.fee_minor as u64));
        }
        println!("{} lignes : {hashes} empreintes identiques, {amounts} montants relus dans la transaction", entries.len());
        assert!(amounts > 0, "aucun virement direct à recouper");
    }

    /// Réel : signataires de transactions récentes : nonce décodé égal à
    /// celui du nœud (`system_accountNextIndex`, autre chemin) à quelques
    /// transactions en attente près ; au moins un compte actif (nonce et
    /// solde non nuls — un compte vidé est supprimé, nonce compris).
    /// `cargo test -- --ignored real_bittensor_account --nocapture`
    #[test]
    #[ignore]
    fn real_bittensor_account() {
        let mut hash = rpc("chain_getFinalizedHead", json!([])).unwrap();
        let mut signers = Vec::new();
        for _ in 0..40 {
            let block = rpc("chain_getBlock", json!([hash])).unwrap();
            for xt in block["block"]["extrinsics"].as_array().unwrap() {
                let bytes = hex_bytes(xt).unwrap();
                let mut input = &bytes[..];
                let _len = Compact::<u32>::decode(&mut input).unwrap();
                if input.len() > 34 && input[0] == 0x84 && input[1] == 0x00 {
                    let signer = address(&input[2..34].try_into().unwrap());
                    if !signers.contains(&signer) {
                        signers.push(signer);
                    }
                }
            }
            if signers.len() >= 6 {
                break;
            }
            hash = block["block"]["header"]["parentHash"].clone();
        }
        assert!(!signers.is_empty(), "aucune transaction signée trouvée");
        let mut active = 0;
        for signer in &signers {
            let account = account(signer).unwrap();
            let next = rpc("system_accountNextIndex", json!([signer])).unwrap().as_u64().unwrap();
            println!("{signer} : {account:?}, nonce du nœud {next}, {} TAO", format_tao(account.free));
            assert!(u64::from(account.nonce) <= next && next - u64::from(account.nonce) < 50, "nonce décodé incohérent");
            if account.nonce > 0 && account.free > 0 {
                active += 1;
            }
        }
        assert!(active > 0, "aucun compte actif parmi les signataires");
    }
}
