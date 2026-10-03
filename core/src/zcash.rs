//! Zcash, adresses transparentes (t1…) : solde, réception, envoi, historique.
//! Comme Bitcoin, une adresse transparente est publique : montants et
//! échanges visibles sur la chaîne (le mode protégé viendra plus tard).
//!
//! - Réseau : serveurs lightwalletd (infrastructure officielle des
//!   portefeuilles Zcash, ECC LightWalletD sur un nœud Zebra), en gRPC sur
//!   HTTP/2 (`tonic`) ; messages définis ici, petit runtime tokio par appel
//!   (le reste du cœur est synchrone). Serveur suivant si l'un ne répond pas.
//! - Transaction : construite avec les bibliothèques officielles
//!   (`zcash_transparent`, `zcash_primitives`) — version de transaction de la
//!   branche de consensus en cours (v5, v6 à partir de NU6.3), empreinte de
//!   signature ZIP-244 et signature par `apply_signatures`, exactement la
//!   séquence du constructeur officiel, sans la partie preuves (transparent
//!   seulement). Frais ZIP-317 (5 000 zatoshis par action, 2 au minimum).
//! - Garde-fou : la branche de consensus utilisée doit être celle annoncée
//!   par le serveur, sinon refus (une mise à niveau du réseau inconnue de la
//!   bibliothèque donnerait une transaction rejetée) : il faut mettre l'app à
//!   jour.

use anyhow::{anyhow, bail, ensure, Context, Result};
use std::time::Duration;
use zcash_address::{ConversionError, ToAddress, TryFromAddress, ZcashAddress};
use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Authorized, Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork, NetworkType};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::{Script, TransparentAddress};
use zcash_transparent::builder::{TransparentBuilder, TransparentSigningSet};
use zcash_transparent::bundle::{OutPoint, TxOut};

/// Serveurs lightwalletd essayés dans l'ordre.
pub const SERVERS: [&str; 3] = ["https://zec.rocks:443", "https://na.zec.rocks:443", "https://eu.zec.rocks:443"];
const SERVICE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer";
/// Frais ZIP-317 : 5 000 zatoshis par action logique, 2 actions au minimum.
pub const MARGINAL_FEE: u64 = 5_000;
const GRACE_ACTIONS: u64 = 2;
/// Monnaie rendue plus petite : ajoutée aux frais plutôt qu'une sortie de
/// poussière (montrée dans la boîte de confirmation).
const DUST_CHANGE: u64 = 5_000;
/// Validité d'une transaction : 40 blocs (~50 min) après la hauteur visée.
const EXPIRY_DELTA: u32 = 40;
/// Transactions lues au plus pour l'historique.
pub const HISTORY_LIMIT: usize = 50;

// --- Adresses ------------------------------------------------------------------

/// Adresse transparente P2PKH (t1…) d'un hash160, encodée par la bibliothèque
/// officielle.
pub fn p2pkh_address(hash160: &[u8; 20]) -> String {
    ZcashAddress::from_transparent_p2pkh(NetworkType::Main, *hash160).encode()
}

/// Destinataire transparent d'un envoi.
#[derive(Clone, Debug, PartialEq)]
pub enum Recipient {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
}

impl Recipient {
    fn address(&self) -> TransparentAddress {
        match self {
            Recipient::P2pkh(h) => TransparentAddress::PublicKeyHash(*h),
            Recipient::P2sh(h) => TransparentAddress::ScriptHash(*h),
        }
    }
}

impl TryFromAddress for Recipient {
    type Error = &'static str;

    fn try_from_sapling(_net: NetworkType, _data: [u8; 43]) -> Result<Self, ConversionError<Self::Error>> {
        Err(ConversionError::User(SHIELDED_REFUSED))
    }

    fn try_from_unified(_net: NetworkType, _data: zcash_address::unified::Address) -> Result<Self, ConversionError<Self::Error>> {
        Err(ConversionError::User(SHIELDED_REFUSED))
    }

    fn try_from_sprout(_net: NetworkType, _data: [u8; 64]) -> Result<Self, ConversionError<Self::Error>> {
        Err(ConversionError::User(SHIELDED_REFUSED))
    }

    fn try_from_transparent_p2pkh(_net: NetworkType, data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Recipient::P2pkh(data))
    }

    fn try_from_transparent_p2sh(_net: NetworkType, data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Recipient::P2sh(data))
    }

    /// Adresse TEX (ZIP-320, exigée par certaines plateformes d'échange) : un
    /// P2PKH qui n'accepte que des fonds transparents — ce qu'envoie l'app.
    fn try_from_tex(_net: NetworkType, data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Recipient::P2pkh(data))
    }
}

const SHIELDED_REFUSED: &str = "envoi vers une adresse Zcash protégée (zs…, u1…) pas encore pris en charge — utilisez une adresse transparente t1…";

/// Destinataire saisi : t1…, t3… ou tex1… du réseau principal.
pub fn parse_recipient(address: &str) -> Result<Recipient> {
    let parsed = ZcashAddress::try_from_encoded(address.trim()).map_err(|_| anyhow!("adresse Zcash invalide"))?;
    parsed.convert_if_network::<Recipient>(NetworkType::Main).map_err(|e| match e {
        ConversionError::User(message) => anyhow!(message),
        ConversionError::IncorrectNetwork { .. } => anyhow!("adresse Zcash d'un autre réseau (test) — refusée"),
        ConversionError::Unsupported(_) => anyhow!("type d'adresse Zcash non pris en charge"),
    })
}

/// Script de sortie d'une adresse P2PKH (pour reconnaître ses sorties).
fn p2pkh_script(hash160: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(hash160);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

fn script_from_bytes(bytes: Vec<u8>) -> Script {
    Script(zcash_script::script::Code(bytes))
}

// --- lightwalletd (gRPC) ---------------------------------------------------------

mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Empty {}

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct LightdInfo {
        #[prost(string, tag = "1")]
        pub version: String,
        #[prost(string, tag = "4")]
        pub chain_name: String,
        #[prost(string, tag = "6")]
        pub consensus_branch_id: String,
        #[prost(uint64, tag = "7")]
        pub block_height: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AddressList {
        #[prost(string, repeated, tag = "1")]
        pub addresses: Vec<String>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Balance {
        #[prost(int64, tag = "1")]
        pub value_zat: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetAddressUtxosArg {
        #[prost(string, repeated, tag = "1")]
        pub addresses: Vec<String>,
        #[prost(uint64, tag = "2")]
        pub start_height: u64,
        #[prost(uint32, tag = "3")]
        pub max_entries: u32,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetAddressUtxosReply {
        #[prost(bytes = "vec", tag = "1")]
        pub txid: Vec<u8>,
        #[prost(int32, tag = "2")]
        pub index: i32,
        #[prost(bytes = "vec", tag = "3")]
        pub script: Vec<u8>,
        #[prost(int64, tag = "4")]
        pub value_zat: i64,
        #[prost(uint64, tag = "5")]
        pub height: u64,
        #[prost(string, tag = "6")]
        pub address: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetAddressUtxosReplyList {
        #[prost(message, repeated, tag = "1")]
        pub address_utxos: Vec<GetAddressUtxosReply>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct RawTransaction {
        #[prost(bytes = "vec", tag = "1")]
        pub data: Vec<u8>,
        #[prost(uint64, tag = "2")]
        pub height: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct SendResponse {
        #[prost(int32, tag = "1")]
        pub error_code: i32,
        #[prost(string, tag = "2")]
        pub error_message: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct BlockId {
        #[prost(uint64, tag = "1")]
        pub height: u64,
        #[prost(bytes = "vec", tag = "2")]
        pub hash: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct BlockRange {
        #[prost(message, optional, tag = "1")]
        pub start: Option<BlockId>,
        #[prost(message, optional, tag = "2")]
        pub end: Option<BlockId>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct TransparentAddressBlockFilter {
        #[prost(string, tag = "1")]
        pub address: String,
        #[prost(message, optional, tag = "2")]
        pub range: Option<BlockRange>,
    }

    /// `CompactBlock` réduit à son horodatage (les autres champs sont ignorés).
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CompactBlockTime {
        #[prost(uint32, tag = "5")]
        pub time: u32,
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().context("démarrage du client Zcash impossible")
}

async fn connect(server: &'static str) -> Result<tonic::transport::Channel> {
    let tls = tonic::transport::ClientTlsConfig::new().with_webpki_roots();
    tonic::transport::Channel::from_static(server)
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .with_context(|| format!("serveur Zcash {server} injoignable"))
}

fn method_path(method: &str) -> Result<tonic::codegen::http::uri::PathAndQuery> {
    tonic::codegen::http::uri::PathAndQuery::try_from(format!("{SERVICE}/{method}")).map_err(|e| anyhow!("chemin gRPC invalide : {e}"))
}

async fn unary<Q, R>(channel: tonic::transport::Channel, method: &str, request: Q) -> Result<R, tonic::Status>
where
    Q: prost::Message + Send + Sync + 'static,
    R: prost::Message + Default + Send + Sync + 'static,
{
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|e| tonic::Status::unavailable(e.to_string()))?;
    let path = method_path(method).map_err(|e| tonic::Status::internal(e.to_string()))?;
    let codec: tonic_prost::ProstCodec<Q, R> = tonic_prost::ProstCodec::default();
    grpc.unary(tonic::Request::new(request), path, codec).await.map(tonic::Response::into_inner)
}

async fn server_stream<Q, R>(channel: tonic::transport::Channel, method: &str, request: Q, limit: usize) -> Result<Vec<R>, tonic::Status>
where
    Q: prost::Message + Send + Sync + 'static,
    R: prost::Message + Default + Send + Sync + 'static,
{
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|e| tonic::Status::unavailable(e.to_string()))?;
    let path = method_path(method).map_err(|e| tonic::Status::internal(e.to_string()))?;
    let codec: tonic_prost::ProstCodec<Q, R> = tonic_prost::ProstCodec::default();
    let mut stream = grpc.server_streaming(tonic::Request::new(request), path, codec).await?.into_inner();
    let mut out = Vec::new();
    while let Some(message) = stream.message().await? {
        out.push(message);
        if out.len() > limit {
            out.remove(0);
        }
    }
    Ok(out)
}

/// Premiers messages seulement d'un flux (le reste n'est pas lu).
async fn server_stream_first<Q, R>(channel: tonic::transport::Channel, method: &str, request: Q, count: usize) -> Result<Vec<R>, tonic::Status>
where
    Q: prost::Message + Send + Sync + 'static,
    R: prost::Message + Default + Send + Sync + 'static,
{
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|e| tonic::Status::unavailable(e.to_string()))?;
    let path = method_path(method).map_err(|e| tonic::Status::internal(e.to_string()))?;
    let codec: tonic_prost::ProstCodec<Q, R> = tonic_prost::ProstCodec::default();
    let mut stream = grpc.server_streaming(tonic::Request::new(request), path, codec).await?.into_inner();
    let mut out = Vec::new();
    while out.len() < count {
        match stream.message().await? {
            Some(message) => out.push(message),
            None => break,
        }
    }
    Ok(out)
}

/// Erreur passagère d'un serveur (on essaie le suivant) ou définitive.
fn retryable(status: &tonic::Status) -> bool {
    matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown | tonic::Code::Internal | tonic::Code::ResourceExhausted)
}

/// Appel unaire avec bascule sur le serveur suivant si l'un ne répond pas.
fn call<Q, R>(method: &str, request: Q) -> Result<R>
where
    Q: prost::Message + Clone + Send + Sync + 'static,
    R: prost::Message + Default + Send + Sync + 'static,
{
    runtime()?.block_on(async {
        let mut last = anyhow!("aucun serveur Zcash joignable");
        for server in SERVERS {
            match connect(server).await {
                Ok(channel) => match unary(channel, method, request.clone()).await {
                    Ok(response) => return Ok(response),
                    Err(status) if retryable(&status) => last = anyhow!("serveur Zcash {server} : {}", status.message()),
                    Err(status) => bail!("serveur Zcash : {}", status.message()),
                },
                Err(e) => last = e,
            }
        }
        Err(last)
    })
}

fn call_stream<Q, R>(method: &str, request: Q, limit: usize) -> Result<Vec<R>>
where
    Q: prost::Message + Clone + Send + Sync + 'static,
    R: prost::Message + Default + Send + Sync + 'static,
{
    runtime()?.block_on(async {
        let mut last = anyhow!("aucun serveur Zcash joignable");
        for server in SERVERS {
            match connect(server).await {
                Ok(channel) => match server_stream(channel, method, request.clone(), limit).await {
                    Ok(response) => return Ok(response),
                    Err(status) if retryable(&status) => last = anyhow!("serveur Zcash {server} : {}", status.message()),
                    Err(status) => bail!("serveur Zcash : {}", status.message()),
                },
                Err(e) => last = e,
            }
        }
        Err(last)
    })
}

/// Adresse transparente lisible par lightwalletd (t1 / t3 ; une TEX est
/// interrogée sous sa forme t1).
pub fn transparent_address(recipient: &Recipient) -> String {
    match recipient {
        Recipient::P2pkh(h) => p2pkh_address(h),
        Recipient::P2sh(h) => ZcashAddress::from_transparent_p2sh(NetworkType::Main, *h).encode(),
    }
}

/// Activité d'une adresse : (détient des fonds, a déjà des transactions).
pub fn address_activity(address: &str) -> Result<(bool, bool)> {
    if balance(address)? > 0 {
        return Ok((true, true));
    }
    let tip = chain_info()?.height;
    let filter = proto::TransparentAddressBlockFilter {
        address: address.to_string(),
        range: Some(proto::BlockRange {
            start: Some(proto::BlockId { height: 1, hash: vec![] }),
            end: Some(proto::BlockId { height: u64::from(tip), hash: vec![] }),
        }),
    };
    let first: Vec<proto::RawTransaction> = runtime()?.block_on(async {
        let mut last = anyhow!("aucun serveur Zcash joignable");
        for server in SERVERS {
            match connect(server).await {
                Ok(channel) => match server_stream_first(channel, "GetTaddressTxids", filter.clone(), 1).await {
                    Ok(found) => return Ok(found),
                    Err(status) => last = anyhow!("serveur Zcash {server} : {}", status.message()),
                },
                Err(e) => last = e,
            }
        }
        Err(last)
    })?;
    Ok((false, !first.is_empty()))
}

/// Hauteur de la chaîne et branche de consensus annoncées par le serveur.
pub struct ChainInfo {
    pub height: u32,
    pub branch_id: u32,
}

pub fn chain_info() -> Result<ChainInfo> {
    let info: proto::LightdInfo = call("GetLightdInfo", proto::Empty {})?;
    ensure!(info.chain_name == "main", "le serveur Zcash répond pour un autre réseau ({})", info.chain_name);
    let branch_id = u32::from_str_radix(info.consensus_branch_id.trim_start_matches("0x"), 16).context("branche de consensus illisible")?;
    Ok(ChainInfo { height: u32::try_from(info.block_height).context("hauteur hors limites")?, branch_id })
}

/// Solde transparent confirmé de `address`, en zatoshis.
pub fn balance(address: &str) -> Result<u64> {
    let balance: proto::Balance = call("GetTaddressBalance", proto::AddressList { addresses: vec![address.to_string()] })?;
    u64::try_from(balance.value_zat).context("solde Zcash négatif")
}

/// Sortie non dépensée.
#[derive(Clone, Debug, PartialEq)]
pub struct Utxo {
    /// Identifiant de la transaction, dans l'ordre des octets de la chaîne.
    pub txid: [u8; 32],
    pub index: u32,
    pub script: Vec<u8>,
    pub value: u64,
    pub height: u64,
}

pub fn utxos(address: &str) -> Result<Vec<Utxo>> {
    let list: proto::GetAddressUtxosReplyList =
        call("GetAddressUtxos", proto::GetAddressUtxosArg { addresses: vec![address.to_string()], start_height: 0, max_entries: 0 })?;
    list.address_utxos
        .into_iter()
        .map(|u| {
            Ok(Utxo {
                txid: u.txid.as_slice().try_into().map_err(|_| anyhow!("identifiant de transaction Zcash invalide"))?,
                index: u32::try_from(u.index).context("index de sortie invalide")?,
                script: u.script,
                value: u64::try_from(u.value_zat).context("montant négatif")?,
                height: u.height,
            })
        })
        .collect()
}

/// Réponse d'un nœud qui connaît déjà la transaction (déjà en file ou dans
/// la réserve de transactions) : elle est sur le réseau.
fn already_known(message: &str) -> bool {
    message.to_ascii_lowercase().contains("already")
}

/// Diffuse une transaction signée ; renvoie son identifiant (affichage).
/// Serveur suivant seulement si la CONNEXION échoue : une fois connecté, la
/// transaction a pu être reçue, la renvoyer ailleurs n'apporterait qu'un
/// « déjà en file » (constaté : Zebra attend les entrées d'une transaction
/// avant de répondre, et un nouvel essai après le délai tombe sur la même).
pub fn broadcast(raw: &[u8], txid: &str) -> Result<String> {
    let request = proto::RawTransaction { data: raw.to_vec(), height: 0 };
    runtime()?.block_on(async {
        let mut last = anyhow!("aucun serveur Zcash joignable");
        for server in SERVERS {
            let channel = match connect(server).await {
                Ok(channel) => channel,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            return match unary::<_, proto::SendResponse>(channel, "SendTransaction", request).await {
                Ok(response) if response.error_code == 0 || already_known(&response.error_message) => Ok(txid.to_string()),
                Ok(response) => Err(anyhow!("transaction Zcash refusée par le réseau : {}", response.error_message)),
                Err(status) if status.code() == tonic::Code::DeadlineExceeded => Err(anyhow!(
                    "transaction Zcash envoyée ({txid}) mais pas encore acceptée par le réseau — vérifiez l'historique dans quelques minutes avant de recommencer"
                )),
                Err(status) => Err(anyhow!("envoi Zcash impossible : {}", status.message())),
            };
        }
        Err(last)
    })
}

// --- Envoi ---------------------------------------------------------------------

/// Taille sérialisée d'une sortie P2PKH (valeur, longueur, script de 25 octets).
const P2PKH_OUTPUT_SIZE: u64 = 34;

/// Frais ZIP-317 d'une transaction transparente P2PKH : une action par entrée
/// (150 octets) ou par sortie (34 octets au plus), le plus grand des deux, 2
/// au minimum.
pub fn zip317_fee(inputs: usize, outputs: usize) -> u64 {
    zip317_fee_with_memo(inputs, outputs, None)
}

/// Comme `zip317_fee`, avec en plus une sortie OP_RETURN de `memo_len`
/// octets : ZIP-317 compte les sorties transparentes par TAILLE (34 octets
/// par action), si bien qu'un memo de 55 octets (66 octets de sortie) pèse
/// deux actions.
pub fn zip317_fee_with_memo(inputs: usize, outputs: usize, memo_len: Option<usize>) -> u64 {
    let output_size = outputs as u64 * P2PKH_OUTPUT_SIZE + memo_len.map_or(0, crate::btc_tx::op_return_output_size);
    MARGINAL_FEE * GRACE_ACTIONS.max((inputs as u64).max(output_size.div_ceil(P2PKH_OUTPUT_SIZE)))
}

/// Envoi préparé : ce qui est montré dans la boîte de confirmation, puis signé.
#[derive(Clone, Debug, PartialEq)]
pub struct SendPlan {
    pub inputs: Vec<Utxo>,
    pub amount: u64,
    pub fee: u64,
    /// Rendu à sa propre adresse (0 : pas de sortie de monnaie).
    pub change: u64,
    /// Memo d'un dépôt d'échange (Maya), en sortie OP_RETURN sans valeur
    /// après la monnaie — l'ordre demandé par Maya (coffre, monnaie, memo).
    pub memo: Option<Vec<u8>>,
}

/// Choisit les sorties à dépenser (les plus grosses d'abord) pour `amount`
/// zatoshis, frais ZIP-317 compris. Une monnaie inférieure à `DUST_CHANGE` va
/// aux frais. Fonction pure.
pub fn plan_send(utxos: Vec<Utxo>, amount: u64) -> Result<SendPlan> {
    plan(utxos, amount, None)
}

/// Dépôt d'échange : comme `plan_send`, avec le memo (80 octets au plus,
/// limite d'une sortie OP_RETURN standard) compté dans les frais.
pub fn plan_deposit(utxos: Vec<Utxo>, amount: u64, memo: &[u8]) -> Result<SendPlan> {
    ensure!(memo.len() <= 80, "memo d'échange trop long pour une sortie OP_RETURN ({} octets, 80 au plus)", memo.len());
    plan(utxos, amount, Some(memo.to_vec()))
}

fn plan(mut utxos: Vec<Utxo>, amount: u64, memo: Option<Vec<u8>>) -> Result<SendPlan> {
    ensure!(amount > 0, "montant nul");
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));
    let available: u64 = utxos.iter().map(|u| u.value).sum();
    let memo_len = memo.as_ref().map(Vec::len);
    let mut inputs = Vec::new();
    let mut total: u64 = 0;
    for utxo in utxos {
        total = total.checked_add(utxo.value).context("montant hors limites")?;
        inputs.push(utxo);
        let fee_with_change = zip317_fee_with_memo(inputs.len(), 2, memo_len);
        let fee_without = zip317_fee_with_memo(inputs.len(), 1, memo_len);
        if total >= amount + fee_with_change && total - amount - fee_with_change >= DUST_CHANGE {
            return Ok(SendPlan { inputs, amount, fee: fee_with_change, change: total - amount - fee_with_change, memo });
        }
        if total >= amount + fee_without {
            // Pas de monnaie (ou poussière, ajoutée aux frais).
            return Ok(SendPlan { inputs, amount, fee: total - amount, change: 0, memo });
        }
    }
    bail!(
        "ZEC insuffisants : {} disponibles, {} demandés + frais du réseau",
        format_zec(available),
        format_zec(amount)
    )
}

pub fn format_zec(zat: u64) -> String {
    format!("{}.{:08}", zat / 100_000_000, zat % 100_000_000)
}

/// Autorisation d'une transaction transparente non signée (bundles protégés
/// toujours absents).
struct TransparentOnly;

impl Authorization for TransparentOnly {
    type TransparentAuth = zcash_transparent::builder::Unauthorized;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// Branche de consensus visée à `target_height`, refusée si elle diffère de
/// celle annoncée par le serveur.
pub fn branch_for(target_height: u32, server_branch: u32) -> Result<BranchId> {
    let branch = BranchId::for_height(&MainNetwork, BlockHeight::from_u32(target_height));
    ensure!(
        u32::from(branch) == server_branch,
        "le réseau Zcash a changé de version (branche {server_branch:08x}, l'app connaît {:08x}) — mettez l'app à jour avant d'envoyer",
        u32::from(branch)
    );
    Ok(branch)
}

/// Transaction signée : octets et identifiant (forme d'affichage).
pub struct SignedTx {
    pub raw: Vec<u8>,
    pub txid: String,
}

/// Construit et signe la transaction d'un envoi préparé, avec la séquence du
/// constructeur officiel : bundle transparent, données de transaction de la
/// version de la branche, empreinte ZIP-244 de chaque entrée, signatures.
pub fn build_signed(plan: &SendPlan, key: &k256::ecdsa::SigningKey, own_hash160: &[u8; 20], recipient: &Recipient, target_height: u32, branch: BranchId) -> Result<SignedTx> {
    build_signed_with_sighashes(plan, key, own_hash160, recipient, target_height, branch).map(|(tx, _)| tx)
}

/// Comme `build_signed`, avec l'empreinte signée de chaque entrée (vérifiée
/// par l'interpréteur de scripts officiel dans les tests).
fn build_signed_with_sighashes(
    plan: &SendPlan,
    key: &k256::ecdsa::SigningKey,
    own_hash160: &[u8; 20],
    recipient: &Recipient,
    target_height: u32,
    branch: BranchId,
) -> Result<(SignedTx, Vec<[u8; 32]>)> {
    let mut signing = TransparentSigningSet::new();
    let secret = secp256k1::SecretKey::from_slice(&key.to_bytes()).context("clé Zcash invalide")?;
    let pubkey = signing.add_key(secret);
    let own_script = p2pkh_script(own_hash160);

    let mut builder = TransparentBuilder::empty();
    for utxo in &plan.inputs {
        ensure!(utxo.script == own_script, "une sortie à dépenser n'appartient pas à cette adresse — envoi refusé");
        let coin = TxOut::new(Zatoshis::from_u64(utxo.value).map_err(|_| anyhow!("montant hors limites"))?, script_from_bytes(utxo.script.clone()));
        builder.add_p2pkh_input(pubkey, OutPoint::new(utxo.txid, utxo.index), coin).map_err(|e| anyhow!("entrée Zcash refusée : {e:?}"))?;
    }
    let zat = |v: u64| Zatoshis::from_u64(v).map_err(|_| anyhow!("montant hors limites"));
    builder.add_output(&recipient.address(), zat(plan.amount)?).map_err(|e| anyhow!("sortie Zcash refusée : {e:?}"))?;
    if plan.change > 0 {
        builder.add_output(&TransparentAddress::PublicKeyHash(*own_hash160), zat(plan.change)?).map_err(|e| anyhow!("sortie Zcash refusée : {e:?}"))?;
    }
    if let Some(memo) = &plan.memo {
        builder.add_null_data_output(memo).map_err(|e| anyhow!("memo Zcash refusé : {e:?}"))?;
    }
    let inputs_total: u64 = plan.inputs.iter().map(|u| u.value).sum();
    ensure!(inputs_total == plan.amount + plan.fee + plan.change, "envoi Zcash incohérent (entrées ≠ montant + frais + monnaie)");
    let bundle = builder.build().context("transaction Zcash vide")?;

    let expiry = BlockHeight::from_u32(target_height + EXPIRY_DELTA);
    let version = TxVersion::suggested_for_branch(branch);
    let unauthed: TransactionData<TransparentOnly> = if version == TxVersion::V6 {
        TransactionData::from_parts_v6(branch, 0, expiry, Some(bundle), None, None, None)
    } else {
        TransactionData::from_parts(version, branch, 0, expiry, Some(bundle), None, None, None)
    };
    let txid_parts = unauthed.digest(TxIdDigester);
    let sighashes = std::cell::RefCell::new(Vec::new());
    let authorized = unauthed
        .transparent_bundle()
        .context("transaction Zcash sans entrées")?
        .clone()
        .apply_signatures(
            |input| {
                let sighash = *signature_hash(&unauthed, &SignableInput::Transparent(input), &txid_parts).as_ref();
                sighashes.borrow_mut().push(sighash);
                sighash
            },
            &signing,
        )
        .map_err(|e| anyhow!("signature Zcash impossible : {e:?}"))?;
    let signed: TransactionData<Authorized> = if version == TxVersion::V6 {
        TransactionData::from_parts_v6(branch, 0, expiry, Some(authorized), None, None, None)
    } else {
        TransactionData::from_parts(version, branch, 0, expiry, Some(authorized), None, None, None)
    };
    let tx = signed.freeze().context("transaction Zcash invalide")?;
    let mut raw = Vec::new();
    tx.write(&mut raw).context("sérialisation de la transaction Zcash impossible")?;
    Ok((SignedTx { raw, txid: tx.txid().to_string() }, sighashes.into_inner()))
}

// --- Historique ----------------------------------------------------------------

/// Transaction de l'historique : montant net pour l'adresse (positif : reçu).
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryTx {
    pub txid: String,
    pub height: u64,
    pub net_zat: i128,
    pub time: Option<i64>,
}

/// Bilan des transactions `raw` (hauteur croissante) pour `hash160` : reçu =
/// sorties vers l'adresse ; envoyé = entrées qui dépensent une sortie de
/// l'adresse vue plus tôt dans la même liste. Fonction pure.
pub fn net_amounts(raw: &[(Vec<u8>, u64)], hash160: &[u8; 20]) -> Result<Vec<(String, u64, i128)>> {
    let own_script = p2pkh_script(hash160);
    let mut own_outputs: std::collections::HashMap<([u8; 32], u32), u64> = std::collections::HashMap::new();
    let mut out = Vec::new();
    for (data, height) in raw {
        let branch = BranchId::for_height(&MainNetwork, BlockHeight::from_u32(u32::try_from(*height).unwrap_or(u32::MAX).max(1)));
        let tx = Transaction::read(&data[..], branch).context("transaction Zcash illisible")?;
        let txid = tx.txid();
        let mut net: i128 = 0;
        if let Some(bundle) = tx.transparent_bundle() {
            for input in &bundle.vin {
                let prevout = input.prevout();
                if let Some(value) = own_outputs.remove(&(*prevout.hash(), prevout.n())) {
                    net -= i128::from(value);
                }
            }
            for (n, output) in bundle.vout.iter().enumerate() {
                let mut script = Vec::new();
                output.script_pubkey().write(&mut script)?;
                // `write` préfixe la longueur (un octet pour un script P2PKH).
                if script.get(1..) == Some(own_script.as_slice()) {
                    let value = u64::from(output.value());
                    net += i128::from(value);
                    own_outputs.insert((*txid.as_ref(), n as u32), value);
                }
            }
        }
        out.push((txid.to_string(), *height, net));
    }
    Ok(out)
}

/// Dernières transactions de l'adresse (au plus `HISTORY_LIMIT`), les plus
/// récentes d'abord, avec l'heure de leur bloc.
pub fn history(address: &str, hash160: &[u8; 20]) -> Result<Vec<HistoryTx>> {
    let tip = chain_info()?.height;
    let filter = proto::TransparentAddressBlockFilter {
        address: address.to_string(),
        range: Some(proto::BlockRange {
            start: Some(proto::BlockId { height: 1, hash: vec![] }),
            end: Some(proto::BlockId { height: u64::from(tip), hash: vec![] }),
        }),
    };
    // Toute l'histoire est lue (les montants envoyés se retrouvent grâce aux
    // sorties reçues plus tôt), seules les dernières sont gardées ensuite.
    let raw: Vec<proto::RawTransaction> = call_stream("GetTaddressTxids", filter, usize::MAX - 1)?;
    let mut txs: Vec<(Vec<u8>, u64)> = raw.into_iter().map(|t| (t.data, t.height)).collect();
    txs.sort_by_key(|(_, height)| if *height == 0 || *height == u64::MAX { u64::MAX } else { *height });
    let mut entries = net_amounts(&txs, hash160)?;
    entries.reverse();
    entries.truncate(HISTORY_LIMIT);
    let mut times: std::collections::HashMap<u64, Option<i64>> = std::collections::HashMap::new();
    Ok(entries
        .into_iter()
        .map(|(txid, height, net_zat)| {
            let confirmed = height != 0 && height != u64::MAX;
            let time = if confirmed { *times.entry(height).or_insert_with(|| block_time(height).ok()) } else { None };
            HistoryTx { txid, height: if confirmed { height } else { 0 }, net_zat, time }
        })
        .collect())
}

fn block_time(height: u64) -> Result<i64> {
    let block: proto::CompactBlockTime = call("GetBlock", proto::BlockId { height, hash: vec![] })?;
    Ok(i64::from(block.time))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_primitives::transaction::fees::transparent::InputSize;
    use zcash_primitives::transaction::fees::FeeRule as _;
    use zcash_transparent::keys::{AccountPrivKey, NonHardenedChildIndex};

    /// Seed de test (aucun fonds) : jamais celle d'un vrai portefeuille.
    const SEED: [u8; 32] = [0x5a; 32];

    fn own() -> (k256::ecdsa::SigningKey, [u8; 20]) {
        crate::derivation::derive_zec_key(&SEED, 0).unwrap()
    }

    fn utxo(value: u64, tag: u8, hash160: &[u8; 20]) -> Utxo {
        Utxo { txid: [tag; 32], index: 1, script: p2pkh_script(hash160), value, height: 100 }
    }

    /// Notre dérivation (m/44'/133'/0'/0/i) donne la même clé que celle de la
    /// bibliothèque officielle (`AccountPrivKey`, compte 0, chaîne externe).
    #[test]
    fn derivation_matches_the_official_library() {
        for index in [0, 3] {
            let (ours, hash160) = crate::derivation::derive_zec_key(&SEED, index).unwrap();
            let account = AccountPrivKey::from_seed(&MainNetwork, &SEED, zip32::AccountId::ZERO).unwrap();
            let official = account.derive_external_secret_key(NonHardenedChildIndex::from_index(index).unwrap()).unwrap();
            assert_eq!(ours.to_bytes()[..], official.secret_bytes()[..]);
            assert!(p2pkh_address(&hash160).starts_with("t1"));
        }
    }

    #[test]
    fn recipients_transparent_only() {
        let (_, hash160) = own();
        assert_eq!(parse_recipient(&p2pkh_address(&hash160)).unwrap(), Recipient::P2pkh(hash160));
        let p2sh = ZcashAddress::from_transparent_p2sh(NetworkType::Main, [1; 20]).encode();
        assert!(p2sh.starts_with("t3"));
        assert_eq!(parse_recipient(&p2sh).unwrap(), Recipient::P2sh([1; 20]));
        let tex = ZcashAddress::from_tex(NetworkType::Main, [2; 20]).encode();
        assert!(tex.starts_with("tex1"));
        assert_eq!(parse_recipient(&tex).unwrap(), Recipient::P2pkh([2; 20]));
        let sapling = ZcashAddress::from_sapling(NetworkType::Main, [3; 43]).encode();
        assert!(parse_recipient(&sapling).unwrap_err().to_string().contains("protégée"));
        let testnet = ZcashAddress::from_transparent_p2pkh(NetworkType::Test, [4; 20]).encode();
        assert!(parse_recipient(&testnet).unwrap_err().to_string().contains("autre réseau"));
        assert!(parse_recipient("t1notanaddress").is_err());
    }

    /// Frais identiques à la règle ZIP-317 officielle.
    #[test]
    fn fees_match_the_official_zip317_rule() {
        let rule = zcash_primitives::transaction::fees::zip317::FeeRule::standard();
        for (inputs, outputs) in [(1, 1), (1, 2), (2, 2), (3, 2), (5, 1), (1, 4)] {
            let official = rule
                .fee_required(&MainNetwork, BlockHeight::from_u32(3_000_000), vec![InputSize::STANDARD_P2PKH; inputs], vec![34; outputs], 0, 0, 0, 0)
                .unwrap();
            assert_eq!(zip317_fee(inputs, outputs), u64::from(official), "{inputs} entrées, {outputs} sorties");
        }
        // Avec un memo OP_RETURN (dépôt Maya), sortie comptée par sa taille.
        for (inputs, outputs, memo) in [(1, 2, 55), (1, 1, 54), (2, 2, 65), (1, 2, 80), (3, 2, 10), (1, 2, 76)] {
            let mut sizes = vec![34; outputs];
            sizes.push(crate::btc_tx::op_return_output_size(memo) as usize);
            let official = rule
                .fee_required(&MainNetwork, BlockHeight::from_u32(3_000_000), vec![InputSize::STANDARD_P2PKH; inputs], sizes, 0, 0, 0, 0)
                .unwrap();
            assert_eq!(zip317_fee_with_memo(inputs, outputs, Some(memo)), u64::from(official), "{inputs} entrées, {outputs} sorties, memo {memo}");
        }
    }

    #[test]
    fn plan_picks_inputs_and_handles_change() {
        let (_, h) = own();
        let coins = vec![utxo(20_000, 1, &h), utxo(100_000, 2, &h), utxo(50_000, 3, &h)];
        let plan = plan_send(coins.clone(), 30_000).unwrap();
        assert_eq!((plan.inputs.len(), plan.fee, plan.change), (1, 10_000, 60_000));
        let plan = plan_send(coins.clone(), 95_000).unwrap();
        assert_eq!((plan.inputs.len(), plan.fee, plan.change), (2, 10_000, 45_000));
        // Monnaie de poussière ajoutée aux frais.
        let plan = plan_send(vec![utxo(105_000, 4, &h)], 92_000).unwrap();
        assert_eq!((plan.fee, plan.change), (13_000, 0));
        assert!(plan_send(coins, 200_000).unwrap_err().to_string().contains("insuffisants"));
    }

    /// Transaction construite puis relue par la bibliothèque officielle, et
    /// chaque signature validée par l'interpréteur de scripts officiel
    /// (`zcash_script`, celui de Zebra) — une empreinte modifiée est refusée.
    #[test]
    fn signed_transaction_is_valid_for_the_official_interpreter() {
        let (key, h) = own();
        let plan = plan_send(vec![utxo(150_000, 7, &h), utxo(40_000, 8, &h)], 160_000).unwrap();
        assert_eq!(plan.inputs.len(), 2);
        let target = 3_000_000;
        let branch = BranchId::for_height(&MainNetwork, BlockHeight::from_u32(target));
        let recipient = Recipient::P2pkh([9; 20]);
        let (signed, sighashes) = build_signed_with_sighashes(&plan, &key, &h, &recipient, target, branch).unwrap();
        let tx = Transaction::read(&signed.raw[..], branch).unwrap();
        assert_eq!(tx.txid().to_string(), signed.txid);
        let bundle = tx.transparent_bundle().unwrap();
        assert_eq!(bundle.vin.len(), 2);
        let values: Vec<u64> = bundle.vout.iter().map(|o| u64::from(o.value())).collect();
        assert_eq!(values, vec![160_000, plan.change]);
        assert_eq!(sighashes.len(), 2);
        let flags = zcash_script::interpreter::Flags::P2SH
            | zcash_script::interpreter::Flags::StrictEnc
            | zcash_script::interpreter::Flags::LowS
            | zcash_script::interpreter::Flags::SigPushOnly;
        for (input, sighash) in bundle.vin.iter().zip(&sighashes) {
            let mut sig = Vec::new();
            input.script_sig().write(&mut sig).unwrap();
            let script = zcash_script::script::Raw::from_raw_parts(sig[1..].to_vec(), p2pkh_script(&h));
            let good = *sighash;
            let checker = zcash_script::interpreter::CallbackTransactionSignatureChecker { sighash: &move |_, _| Some(good), lock_time: 0, is_final: true };
            assert_eq!(script.eval(flags, &checker), Ok(true));
            let mut bad = good;
            bad[0] ^= 1;
            let tampered = zcash_script::interpreter::CallbackTransactionSignatureChecker { sighash: &move |_, _| Some(bad), lock_time: 0, is_final: true };
            assert_ne!(script.eval(flags, &tampered), Ok(true));
        }
        // Une sortie qui n'est pas à cette adresse : refus.
        let foreign = SendPlan { inputs: vec![utxo(150_000, 1, &[0xee; 20])], amount: 100_000, fee: 10_000, change: 40_000, memo: None };
        assert!(build_signed(&foreign, &key, &h, &recipient, target, branch).is_err());
    }

    /// Dépôt Maya (memo réel d'un devis ZEC → ETH) : sorties coffre, monnaie,
    /// puis OP_RETURN sans valeur portant le memo ; relu par la bibliothèque
    /// officielle, sortie memo de la taille comptée dans les frais.
    #[test]
    fn deposit_carries_the_memo_after_the_change() {
        let (key, h) = own();
        let memo = b"=:e:0x59D78c44ac60F09369b544778358704B7b18E6ba:48048634";
        let plan = plan_deposit(vec![utxo(500_000, 3, &h)], 139_440, memo).unwrap();
        assert_eq!((plan.fee, plan.change), (20_000, 500_000 - 139_440 - 20_000), "1 entrée, 34 + 34 + 66 octets de sorties : 4 actions");
        assert!(plan_deposit(vec![utxo(500_000, 3, &h)], 139_440, &[b'x'; 81]).is_err(), "memo de 81 octets");
        let target = 3_000_000;
        let branch = BranchId::for_height(&MainNetwork, BlockHeight::from_u32(target));
        let vault = parse_recipient("t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE").unwrap();
        let signed = build_signed(&plan, &key, &h, &vault, target, branch).unwrap();
        let tx = Transaction::read(&signed.raw[..], branch).unwrap();
        let outputs = &tx.transparent_bundle().unwrap().vout;
        let values: Vec<u64> = outputs.iter().map(|o| u64::from(o.value())).collect();
        assert_eq!(values, vec![139_440, plan.change, 0]);
        let mut memo_output = Vec::new();
        outputs[2].write(&mut memo_output).unwrap();
        assert_eq!(memo_output.len() as u64, crate::btc_tx::op_return_output_size(memo.len()));
        assert_eq!(&memo_output[memo_output.len() - memo.len()..], memo);
        assert_eq!(memo_output[9], 0x6a, "OP_RETURN");
    }

    /// Bilan de l'historique : réception, puis envoi qui dépense cette
    /// réception (montant envoyé + frais) avec monnaie rendue.
    #[test]
    fn history_net_amounts() {
        let (key, h) = own();
        let target = 3_000_000;
        let branch = BranchId::for_height(&MainNetwork, BlockHeight::from_u32(target));
        // Réception de 120 000 sur l'adresse (entrée étrangère : clé de test 2).
        let (other_key, other_h) = crate::derivation::derive_zec_key(&SEED, 9).unwrap();
        let incoming = plan_send(vec![utxo(200_000, 1, &other_h)], 120_000).unwrap();
        let receive = build_signed(&incoming, &other_key, &other_h, &Recipient::P2pkh(h), target, branch).unwrap();
        let receive_tx = Transaction::read(&receive.raw[..], branch).unwrap();
        // Envoi de 50 000 depuis cette réception.
        let received = Utxo { txid: *receive_tx.txid().as_ref(), index: 0, script: p2pkh_script(&h), value: 120_000, height: 101 };
        let outgoing = plan_send(vec![received], 50_000).unwrap();
        let send = build_signed(&outgoing, &key, &h, &Recipient::P2pkh([9; 20]), target, branch).unwrap();
        let entries = net_amounts(&[(receive.raw, 101), (send.raw, 102)], &h).unwrap();
        assert_eq!(entries[0].2, 120_000);
        assert_eq!(entries[1].2, -(50_000 + i128::from(outgoing.fee)));
    }

    /// Réseau (lecture seule) : serveur sur le réseau principal, branche de
    /// consensus connue de la bibliothèque, solde et sorties d'une adresse
    /// publique pourvue (dépôt Maya).
    #[test]
    #[ignore]
    fn real_chain_and_utxos() {
        let info = chain_info().unwrap();
        println!("hauteur {} branche {:08x}", info.height, info.branch_id);
        branch_for(info.height + 1, info.branch_id).unwrap();
        let vault = "t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE";
        let coins = utxos(vault).unwrap();
        let total: u64 = coins.iter().map(|u| u.value).sum();
        println!("{} sorties, {} ZEC (solde {})", coins.len(), format_zec(total), format_zec(balance(vault).unwrap()));
        assert!(!coins.is_empty());
    }

    /// Diffusion réelle d'une transaction bien formée qui dépense une sortie
    /// inexistante (clé de test, aucun fonds). Zebra attend l'entrée au lieu de
    /// refuser (constaté) : la transaction ne doit PAS être refusée d'emblée —
    /// une transaction mal formée (version, branche, encodage) l'est aussitôt.
    #[test]
    #[ignore]
    fn real_broadcast_is_not_rejected_as_malformed() {
        let (key, h) = own();
        let info = chain_info().unwrap();
        let branch = branch_for(info.height + 1, info.branch_id).unwrap();
        // Sortie inventée différente à chaque essai (sinon le nœud répond que
        // la même transaction est déjà en file d'attente).
        let tag = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() % 251) as u8;
        let plan = plan_send(vec![utxo(1_000_000, tag, &h)], 100_000).unwrap();
        let signed = build_signed(&plan, &key, &h, &Recipient::P2pkh([9; 20]), info.height + 1, branch).unwrap();
        // Dépôt d'échange Maya (memo en sortie OP_RETURN), même épreuve.
        let deposit_plan = plan_deposit(vec![utxo(1_000_000, tag.wrapping_add(1), &h)], 139_440, b"=:e:0x59D78c44ac60F09369b544778358704B7b18E6ba:48048634").unwrap();
        let vault = parse_recipient("t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE").unwrap();
        let deposit = build_signed(&deposit_plan, &key, &h, &vault, info.height + 1, branch).unwrap();
        for tx in [&signed, &deposit] {
            match broadcast(&tx.raw, &tx.txid) {
                Ok(txid) => println!("mise en file de vérification par le nœud : {txid}"),
                Err(e) => {
                    let error = e.to_string();
                    println!("{error}");
                    assert!(error.contains("pas encore acceptée"), "refusée d'emblée : {error}");
                }
            }
        }
        // Une transaction tronquée, elle, est refusée tout de suite.
        let truncated = broadcast(&signed.raw[..signed.raw.len() - 10], &signed.txid).unwrap_err().to_string();
        println!("tronquée : {truncated}");
        assert!(truncated.contains("refusée"), "{truncated}");
    }

    /// Activité réelle (lecture seule) : adresse pourvue (dépôt Maya) et
    /// adresse jamais utilisée (clé de test).
    #[test]
    #[ignore]
    fn real_address_activity() {
        assert_eq!(address_activity("t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE").unwrap(), (true, true));
        let (_, h) = own();
        assert_eq!(address_activity(&p2pkh_address(&h)).unwrap(), (false, false));
    }

    /// Historique réel (lecture seule) d'une adresse sans transaction.
    #[test]
    #[ignore]
    fn real_history_of_an_empty_address() {
        let (_, h) = own();
        assert!(history(&p2pkh_address(&h), &h).unwrap().is_empty());
    }
}
