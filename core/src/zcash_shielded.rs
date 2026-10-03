//! Zcash protégé (Orchard) : adresse unifiée u1… (récepteur Orchard seul),
//! réception, solde, puis protection des ZEC transparents et envoi.
//!
//! Pile officielle des portefeuilles légers (celle de Zashi) :
//! - `zcash_client_sqlite` : base de portefeuille locale (notes, arbres de
//!   commitments). Elle ne contient que des clés de VISUALISATION (UFVK) : la
//!   clé de dépense est dérivée de la seed (mot de passe) au moment de signer.
//!   Fuite de cette base = historique protégé visible, jamais de fonds perdus.
//! - `zcash_client_backend::sync` : synchronisation par les serveurs
//!   lightwalletd déjà utilisés pour le transparent (blocs compacts, déchiffrement
//!   par essai), sans rien envoyer d'autre que des demandes de blocs.
//!
//! Compte protégé n°p = compte ZIP-32 n°p de la seed (profil n°p). L'adresse
//! t1 existante du profil (m/44'/133'/0'/0/p) y est importée pour pouvoir la
//! protéger. Naissance commune à tous les comptes (`BIRTHDAY_HEIGHT`) : aucune
//! adresse protégée de l'app n'existait avant, donc rien ne peut être manqué, et
//! une restauration sur un autre appareil retrouve tout sans rescanner la chaîne.

use crate::{derivation, zcash};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::path::Path;
use std::sync::Mutex;
use zcash_client_backend::data_api::chain::{error as chain_error, BlockCache, BlockSource};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{Account as _, AccountBirthday, AccountPurpose, WalletRead, WalletWrite, Zip32Derivation};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, AccountUuid, WalletDb};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{BlockHeight, MainNetwork};

/// Hauteur de naissance de tous les comptes protégés : juste avant la
/// première version de l'app qui affiche une adresse u1 (chaîne à 3 505 105
/// le 03/10/2026).
pub const BIRTHDAY_HEIGHT: u32 = 3_504_000;
const WALLET_FILE: &str = "zcash_shielded.sqlite";
/// Blocs téléchargés puis analysés par lot.
const SYNC_BATCH: u32 = 1_000;

type Db = WalletDb<rusqlite::Connection, MainNetwork, SystemClock, rand_core::OsRng>;

fn open(data_dir: &Path) -> Result<Db> {
    let mut db = WalletDb::for_path(data_dir.join(WALLET_FILE), MainNetwork, SystemClock, rand_core::OsRng).context("base Zcash protégée illisible")?;
    init_wallet_db(&mut db, None).map_err(|e| anyhow!("base Zcash protégée : migration impossible ({e})"))?;
    Ok(db)
}

fn account_index(profile: u32) -> Result<zip32::AccountId> {
    zip32::AccountId::try_from(profile).map_err(|_| anyhow!("profil hors des comptes Zcash possibles"))
}

/// Clé de visualisation du compte protégé du profil (calcul local, à partir
/// de la seed).
pub fn viewing_key(seed: &[u8], profile: u32) -> Result<UnifiedFullViewingKey> {
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, seed, account_index(profile)?).map_err(|e| anyhow!("clé Zcash protégée : {e:?}"))?;
    Ok(usk.to_unified_full_viewing_key())
}

/// Adresse protégée du profil : adresse unifiée au seul récepteur Orchard.
pub fn address(ufvk: &UnifiedFullViewingKey) -> Result<String> {
    let (address, _) = ufvk.default_address(UnifiedAddressRequest::ORCHARD).map_err(|e| anyhow!("adresse Zcash protégée : {e:?}"))?;
    Ok(address.encode(&MainNetwork))
}

/// Compte protégé du profil dans la base, s'il existe.
fn find_account(db: &Db, profile: u32) -> Result<Option<AccountUuid>> {
    let wanted = account_index(profile)?;
    for id in db.get_account_ids()? {
        if let Some(account) = db.get_account(id)? {
            // Compte importé par sa clé de visualisation (`AccountSource::Imported`)
            // ou dérivé : même métadonnée de dérivation ZIP-32.
            if account.source().key_derivation().is_some_and(|d| d.account_index() == wanted) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

// --- lightwalletd ---------------------------------------------------------------

/// Connexion sans délai par requête (un lot de blocs compacts peut dépasser
/// les 30 s du client transparent), serveurs essayés dans l'ordre.
async fn client() -> Result<CompactTxStreamerClient<tonic::transport::Channel>> {
    let mut last = anyhow!("aucun serveur Zcash configuré");
    for server in zcash::SERVERS {
        let tls = tonic::transport::ClientTlsConfig::new().with_webpki_roots();
        let endpoint = tonic::transport::Channel::from_static(server).tls_config(tls)?.connect_timeout(std::time::Duration::from_secs(10));
        match endpoint.connect().await {
            Ok(channel) => return Ok(CompactTxStreamerClient::new(channel)),
            Err(e) => last = anyhow!("serveur Zcash {server} injoignable : {e}"),
        }
    }
    Err(last)
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().context("démarrage du client Zcash impossible")
}

/// Naissance des comptes : état des arbres de commitments juste avant
/// `BIRTHDAY_HEIGHT`.
async fn birthday(client: &mut CompactTxStreamerClient<tonic::transport::Channel>) -> Result<AccountBirthday> {
    let state = client
        .get_tree_state(BlockId { height: u64::from(BIRTHDAY_HEIGHT - 1), hash: vec![] })
        .await
        .map_err(|e| anyhow!("état de la chaîne Zcash illisible : {}", e.message()))?
        .into_inner();
    AccountBirthday::from_treestate(state, None).map_err(|_| anyhow!("état de la chaîne Zcash invalide"))
}

/// Clés d'un profil pour `ensure_accounts`, dérivées de la seed : clé de
/// visualisation, clé publique de l'adresse t1, empreinte de la seed.
pub type ProfileKeys = (u32, UnifiedFullViewingKey, [u8; 33], zip32::fingerprint::SeedFingerprint);

pub fn profile_keys(seed: &[u8], profile: u32) -> Result<ProfileKeys> {
    let ufvk = viewing_key(seed, profile)?;
    let (t1_key, _) = derivation::derive_zec_key(seed, profile)?;
    let pubkey: [u8; 33] = t1_key.verifying_key().to_encoded_point(true).as_bytes().try_into().context("clé publique Zcash invalide")?;
    let seed_fp = zip32::fingerprint::SeedFingerprint::from_seed(seed).context("seed trop courte pour Zcash")?;
    Ok((profile, ufvk, pubkey, seed_fp))
}

/// Crée (une fois) le compte protégé de chaque profil — appelé après le
/// déverrouillage, sans la seed (clés déjà dérivées).
pub fn ensure_accounts(data_dir: &Path, profiles: &[ProfileKeys]) -> Result<()> {
    let mut db = open(data_dir)?;
    let mut missing = Vec::new();
    for keys in profiles {
        if find_account(&db, keys.0)?.is_none() {
            missing.push(keys);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let birthday = runtime()?.block_on(async { birthday(&mut client().await?).await })?;
    for (profile, ufvk, t1_pubkey, seed_fp) in missing {
        let purpose = AccountPurpose::Spending { derivation: Some(Zip32Derivation::new(*seed_fp, account_index(*profile)?)) };
        let account = db
            .import_account_ufvk(&format!("Profil {profile}"), ufvk, &birthday, purpose, Some("openpgp-wallet"))
            .map_err(|e| anyhow!("compte Zcash protégé : création impossible ({e})"))?;
        // Profil principal : son adresse t1 est déjà la première adresse
        // transparente du compte 0 ; les autres sont importées.
        if *profile != 0 {
            let pubkey = secp256k1::PublicKey::from_slice(t1_pubkey).context("clé publique Zcash invalide")?;
            db.import_standalone_transparent_pubkey(account.id(), pubkey).map_err(|e| anyhow!("adresse t1 : import impossible ({e})"))?;
        }
    }
    Ok(())
}

/// Synchronise tous les comptes protégés jusqu'au bout de la chaîne.
pub fn sync(data_dir: &Path) -> Result<()> {
    let mut db = open(data_dir)?;
    if db.get_account_ids()?.is_empty() {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = client().await?;
        let cache = MemoryCache::default();
        zcash_client_backend::sync::run(&mut client, &MainNetwork, &cache, &mut db, SYNC_BATCH).await.map_err(|e| anyhow!("synchronisation Zcash protégée : {e}"))
    })
}

/// Solde du compte protégé du profil (zatoshis).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ShieldedBalance {
    /// Dépensable maintenant (notes Orchard confirmées).
    pub spendable: u64,
    /// Reçu mais pas encore dépensable (confirmations en attente).
    pub pending: u64,
    /// Hauteur jusqu'où la chaîne a été analysée (`None` : pas encore).
    pub scanned_height: Option<u32>,
    pub chain_height: Option<u32>,
}

pub fn balance(data_dir: &Path, profile: u32) -> Result<ShieldedBalance> {
    let db = open(data_dir)?;
    let Some(account) = find_account(&db, profile)? else { return Ok(ShieldedBalance::default()) };
    let Some(summary) = db.get_wallet_summary(ConfirmationsPolicy::default())? else { return Ok(ShieldedBalance::default()) };
    let Some(balances) = summary.account_balances().get(&account) else { return Ok(ShieldedBalance::default()) };
    let orchard = balances.orchard_balance();
    let spendable = u64::from(orchard.spendable_value());
    let total = u64::from(orchard.total());
    Ok(ShieldedBalance {
        spendable,
        pending: total.saturating_sub(spendable),
        scanned_height: Some(u32::from(summary.fully_scanned_height())),
        chain_height: Some(u32::from(summary.chain_tip_height())),
    })
}

// --- Dépenses : protéger les ZEC transparents, envoyer depuis Orchard -------------
// Comme ailleurs dans l'app : la transaction est d'abord PROPOSÉE (entrées,
// frais ZIP-317, monnaie, sans aucune clé de dépense), son résumé est
// confirmé dans une boîte native, puis CETTE proposition est signée avec la
// clé dérivée de la seed (mot de passe) et diffusée par lightwalletd.

use zcash_client_backend::data_api::wallet::input_selection::{GreedyInputSelector, SpendPolicy};
use zcash_client_backend::data_api::wallet::{create_proposed_transactions, propose_shielding, propose_transfer, SpendingKeys};
use zcash_client_backend::data_api::CoinbaseFilter;
use zcash_client_backend::fees::{zip317::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool};

/// Prouveur Sapling absent : l'app ne dépense ni ne crée jamais de note
/// Sapling (Orchard seul : destinataires transparents ou Orchard, monnaie vers
/// Orchard, vérifiés avant la proposition). Une dépense Sapling échouerait à la
/// préparation du circuit ; une sortie Sapling donnerait une preuve vide que
/// le réseau refuserait — jamais de fonds engagés.
struct NoSapling;

impl sapling_crypto::prover::SpendProver for NoSapling {
    type Proof = ();

    fn prepare_circuit(
        _: sapling_crypto::ProofGenerationKey,
        _: sapling_crypto::Diversifier,
        _: sapling_crypto::Rseed,
        _: sapling_crypto::value::NoteValue,
        _: jubjub::Fr,
        _: sapling_crypto::value::ValueCommitTrapdoor,
        _: bls12_381::Scalar,
        _: sapling_crypto::MerklePath,
    ) -> Option<sapling_crypto::circuit::Spend> {
        None
    }

    fn create_proof<R: rand_core::RngCore>(&self, _: sapling_crypto::circuit::Spend, _: &mut R) -> Self::Proof {}

    fn encode_proof(_: Self::Proof) -> sapling_crypto::bundle::GrothProofBytes {
        // Taille d'une preuve Groth16 (48 + 96 + 48 octets).
        [0; 192]
    }
}

impl sapling_crypto::prover::OutputProver for NoSapling {
    type Proof = ();

    fn prepare_circuit(
        _: &sapling_crypto::keys::EphemeralSecretKey,
        _: sapling_crypto::PaymentAddress,
        _: jubjub::Fr,
        _: sapling_crypto::value::NoteValue,
        _: sapling_crypto::value::ValueCommitTrapdoor,
    ) -> sapling_crypto::circuit::Output {
        sapling_crypto::circuit::Output { value_commitment_opening: None, payment_address: None, commitment_randomness: None, esk: None }
    }

    fn create_proof<R: rand_core::RngCore>(&self, _: sapling_crypto::circuit::Output, _: &mut R) -> Self::Proof {}

    fn encode_proof(_: Self::Proof) -> sapling_crypto::bundle::GrothProofBytes {
        // Taille d'une preuve Groth16 (48 + 96 + 48 octets).
        [0; 192]
    }
}

/// Résumé d'une dépense, montré dans la boîte de confirmation.
#[derive(Clone, Debug, PartialEq)]
pub struct SpendSummary {
    /// Montant qui arrive au destinataire (ou protégé), en zatoshis.
    pub amount: u64,
    /// Frais ZIP-317.
    pub fee: u64,
    /// Destinataire (adresse protégée du profil pour une protection).
    pub recipient: String,
}

fn change_strategy() -> SingleOutputChangeStrategy<StandardFeeRule, Db> {
    SingleOutputChangeStrategy::new(StandardFeeRule::Zip317, None, ShieldedPool::Orchard, DustOutputPolicy::default())
}

/// Clés de dépense du profil : clé unifiée du compte ZIP-32, et clé de
/// l'adresse t1 importée (profils autres que le principal).
fn spending_keys(seed: &[u8], profile: u32) -> Result<SpendingKeys> {
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, seed, account_index(profile)?).map_err(|e| anyhow!("clé Zcash protégée : {e:?}"))?;
    let mut standalone = std::collections::HashMap::new();
    if profile != 0 {
        let (key, hash160) = derivation::derive_zec_key(seed, profile)?;
        let secret = secp256k1::SecretKey::from_slice(&key.to_bytes()).context("clé Zcash invalide")?;
        standalone.insert(zcash_transparent::address::TransparentAddress::PublicKeyHash(hash160), vec![secret]);
    }
    Ok(SpendingKeys::new(usk, standalone))
}

/// Signe la proposition et diffuse ses transactions ; renvoie le dernier
/// identifiant.
fn create_and_broadcast<N: std::fmt::Display>(db: &mut Db, proposal: &Proposal<StandardFeeRule, N>, keys: &SpendingKeys) -> Result<String> {
    // Types d'erreur de sélection et de monnaie : propres à la proposition,
    // jamais produits par la construction.
    let txids = create_proposed_transactions::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(db, &MainNetwork, &NoSapling, &NoSapling, keys, OvkPolicy::Sender, proposal, None)
        .map_err(|e| anyhow!("transaction Zcash protégée : construction impossible ({e})"))?;
    let mut last = String::new();
    for txid in txids {
        let tx = db.get_transaction(txid)?.context("transaction Zcash protégée introuvable après sa construction")?;
        let mut raw = Vec::new();
        tx.write(&mut raw).context("sérialisation de la transaction Zcash impossible")?;
        last = zcash::broadcast(&raw, &txid.to_string())?;
    }
    Ok(last)
}

/// Fonds insuffisants, en clair : messages de la bibliothèque relevés en
/// réel (« Insufficient balance (have 0, need 1010000 including fee) »,
/// « Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were
/// available »).
fn insufficient(message: &str) -> Option<anyhow::Error> {
    let number_after = |marker: &str| -> Option<u64> {
        let rest = &message[message.find(marker)? + marker.len()..];
        rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    };
    let (have, need) = match (number_after("have "), number_after("need ")) {
        (Some(have), Some(need)) => (have, need),
        _ => (number_after("but only ")?, number_after("required ")?),
    };
    Some(anyhow!("ZEC insuffisants : {} disponibles, {} nécessaires (frais compris)", zcash::format_zec(have), zcash::format_zec(need)))
}

fn proposal_fee<N>(proposal: &Proposal<StandardFeeRule, N>) -> u64 {
    proposal.steps().iter().map(|step| u64::from(step.balance().fee_required())).sum()
}

/// Protège les ZEC de l'adresse t1 `t1` du profil (vers son adresse
/// Orchard) : propose, fait confirmer le résumé (`confirm`), puis signe avec
/// la seed (`seed`) et diffuse. `Ok(None)` : confirmation refusée.
pub fn shield(
    data_dir: &Path,
    profile: u32,
    t1: &str,
    confirm: impl FnOnce(&SpendSummary) -> bool,
    seed: impl FnOnce() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Option<String>> {
    let mut db = open(data_dir)?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let from = match zcash::parse_recipient(t1)? {
        zcash::Recipient::P2pkh(hash) => zcash_transparent::address::TransparentAddress::PublicKeyHash(hash),
        zcash::Recipient::P2sh(_) => anyhow::bail!("adresse t1 du profil attendue"),
    };
    let proposal = propose_shielding::<_, _, _, _, std::convert::Infallible>(
        &mut db,
        &MainNetwork,
        &GreedyInputSelector::new(),
        &change_strategy(),
        Zatoshis::const_from_u64(10_000),
        &[from],
        account,
        ConfirmationsPolicy::default(),
        CoinbaseFilter::AllTransparentOutputs,
        None,
    )
    .map_err(|e| insufficient(&e.to_string()).unwrap_or_else(|| anyhow!("rien à protéger pour l'instant ({e})")))?;
    let fee = proposal_fee(&proposal);
    let inputs: u64 = proposal.steps().iter().flat_map(|s| s.transparent_inputs()).map(|i| u64::from(i.txout().value())).sum();
    let ufvk = db.get_account(account)?.and_then(|a| a.ufvk().cloned()).context("compte Zcash protégé sans clé de visualisation")?;
    let summary = SpendSummary { amount: inputs.saturating_sub(fee), fee, recipient: address(&ufvk)? };
    if !confirm(&summary) {
        return Ok(None);
    }
    let seed = seed()?;
    create_and_broadcast(&mut db, &proposal, &spending_keys(&seed, profile)?).map(Some)
}

/// Le destinataire peut-il recevoir sans Sapling (transparent, ou adresse
/// unifiée avec un récepteur Orchard) ?
pub fn check_recipient(address: &str) -> Result<zcash_address::ZcashAddress> {
    let parsed = zcash_address::ZcashAddress::try_from_encoded(address.trim()).map_err(|_| anyhow!("adresse Zcash invalide"))?;
    anyhow::ensure!(parsed.can_receive_as(PoolType::ORCHARD) || parsed.can_receive_as(PoolType::TRANSPARENT), "adresse Zcash Sapling seule (zs…) pas prise en charge — demandez une adresse u1… ou t1…");
    let mainnet = ["u1", "t1", "t3", "tex1"].iter().any(|prefix| address.trim().starts_with(prefix));
    anyhow::ensure!(mainnet, "adresse Zcash d'un autre réseau (test) — refusée");
    Ok(parsed)
}

/// Envoie `amount` zatoshis depuis les fonds protégés du profil vers `to` :
/// mêmes étapes que `shield`.
pub fn send(
    data_dir: &Path,
    profile: u32,
    to: &str,
    amount: u64,
    confirm: impl FnOnce(&SpendSummary) -> bool,
    seed: impl FnOnce() -> Result<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Option<String>> {
    let recipient = check_recipient(to)?;
    let mut db = open(data_dir)?;
    let account = find_account(&db, profile)?.context("fonds protégés pas encore prêts (synchronisation en cours)")?;
    let value = Zatoshis::from_u64(amount).map_err(|_| anyhow!("montant hors limites"))?;
    let request = TransactionRequest::new(vec![Payment::without_memo(recipient, value)]).map_err(|e| anyhow!("demande de paiement invalide ({e:?})"))?;
    let proposal = propose_transfer::<_, _, _, _, std::convert::Infallible>(
        &mut db,
        &MainNetwork,
        account,
        &GreedyInputSelector::new(),
        &change_strategy(),
        request,
        ConfirmationsPolicy::default(),
        &SpendPolicy::default(),
        None,
        None,
    )
    .map_err(|e| insufficient(&e.to_string()).unwrap_or_else(|| anyhow!("envoi Zcash protégé impossible ({e})")))?;
    let summary = SpendSummary { amount, fee: proposal_fee(&proposal), recipient: to.trim().to_string() };
    if !confirm(&summary) {
        return Ok(None);
    }
    let seed = seed()?;
    create_and_broadcast(&mut db, &proposal, &spending_keys(&seed, profile)?).map(Some)
}

// --- Cache de blocs en mémoire (le temps d'une synchronisation) -------------------

#[derive(Debug)]
pub struct CacheError(String);

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cache de blocs : {}", self.0)
    }
}

impl std::error::Error for CacheError {}

#[derive(Default)]
struct MemoryCache {
    blocks: Mutex<Vec<CompactBlock>>,
}

fn height_of(block: &CompactBlock) -> BlockHeight {
    BlockHeight::from_u32(block.height as u32)
}

fn poisoned() -> CacheError {
    CacheError("verrou empoisonné".into())
}

impl BlockSource for MemoryCache {
    type Error = CacheError;

    fn with_blocks<F, WalletErrT>(&self, from_height: Option<BlockHeight>, limit: Option<usize>, mut with_block: F) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain_error::Error<WalletErrT, Self::Error>>,
    {
        let mut blocks: Vec<CompactBlock> = {
            let cached = self.blocks.lock().map_err(|_| chain_error::Error::BlockSource(poisoned()))?;
            cached.iter().filter(|b| from_height.is_none_or(|h| height_of(b) >= h)).cloned().collect()
        };
        blocks.sort_by_key(|b| b.height);
        for block in blocks.into_iter().take(limit.unwrap_or(usize::MAX)) {
            with_block(block)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemoryCache {
    fn get_tip_height(&self, range: Option<&ScanRange>) -> Result<Option<BlockHeight>, Self::Error> {
        let cached = self.blocks.lock().map_err(|_| poisoned())?;
        Ok(cached.iter().map(height_of).filter(|h| range.is_none_or(|r| r.block_range().contains(h))).max())
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let cached = self.blocks.lock().map_err(|_| poisoned())?;
        let mut blocks: Vec<CompactBlock> = cached.iter().filter(|b| range.block_range().contains(&height_of(b))).cloned().collect();
        blocks.sort_by_key(|b| b.height);
        Ok(blocks)
    }

    async fn insert(&self, mut compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        self.blocks.lock().map_err(|_| poisoned())?.append(&mut compact_blocks);
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        self.blocks.lock().map_err(|_| poisoned())?.retain(|b| !range.block_range().contains(&height_of(b)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_address::ToAddress as _;

    const SEED: [u8; 64] = [5u8; 64];

    /// Adresse u1 au seul récepteur Orchard, propre à chaque profil, relue
    /// par la bibliothèque d'adresses officielle.
    #[test]
    fn orchard_only_unified_addresses_per_profile() {
        let a0 = address(&viewing_key(&SEED, 0).unwrap()).unwrap();
        let a1 = address(&viewing_key(&SEED, 1).unwrap()).unwrap();
        assert!(a0.starts_with("u1") && a1.starts_with("u1") && a0 != a1);
        assert_eq!(a0, address(&viewing_key(&SEED, 0).unwrap()).unwrap(), "déterministe");
        let parsed = zcash_address::ZcashAddress::try_from_encoded(&a0).unwrap();
        assert!(parsed.can_receive_as(zcash_protocol::PoolType::ORCHARD));
        assert!(!parsed.can_receive_as(zcash_protocol::PoolType::SAPLING) && !parsed.can_receive_as(zcash_protocol::PoolType::TRANSPARENT));
    }

    /// Destinataires : t1 et u1 Orchard acceptés ; Sapling seule refusée.
    #[test]
    fn recipients_without_sapling() {
        let u1 = address(&viewing_key(&SEED, 0).unwrap()).unwrap();
        assert!(check_recipient(&u1).is_ok());
        assert!(check_recipient("t1VtnnhTYhmADh7L2uKU3Sev7GscBHT6HfE").is_ok());
        // Adresse Sapling seule bien formée (encodage officiel, somme de contrôle valide).
        let sapling = zcash_address::ZcashAddress::from_sapling(zcash_protocol::consensus::NetworkType::Main, [7u8; 43]).encode();
        assert!(sapling.starts_with("zs1"));
        assert!(check_recipient(&sapling).unwrap_err().to_string().contains("Sapling"), "Sapling seule");
        let testnet = zcash_address::ZcashAddress::from_transparent_p2pkh(zcash_protocol::consensus::NetworkType::Test, [7u8; 20]).encode();
        assert!(check_recipient(&testnet).is_err(), "réseau de test");
        assert!(check_recipient("pas une adresse").is_err());
    }

    /// Fonds insuffisants : messages réels de la bibliothèque, en clair.
    #[test]
    fn insufficient_funds_in_plain_words() {
        let send = insufficient("Insufficient balance (have 0, need 1010000 including fee)").unwrap().to_string();
        assert_eq!(send, "ZEC insuffisants : 0.00000000 disponibles, 0.01010000 nécessaires (frais compris)");
        let shield = insufficient("Change output generation failed: Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were available.").unwrap().to_string();
        assert_eq!(shield, "ZEC insuffisants : 0.00000000 disponibles, 0.00010000 nécessaires (frais compris)");
        assert!(insufficient("autre erreur").is_none());
    }

    /// Réseau réel (lecture seule) : comptes créés à la naissance commune,
    /// synchronisés jusqu'au bout de la chaîne, solde nul, puis relus sans
    /// nouvelle création.
    /// `cargo test --lib real_shielded_sync -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_shielded_sync() {
        let dir = std::env::temp_dir().join(format!("zec-shielded-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [profile_keys(&SEED, 0).unwrap(), profile_keys(&SEED, 1).unwrap()];
        ensure_accounts(&dir, &keys).unwrap();
        ensure_accounts(&dir, &keys).unwrap();
        let start = std::time::Instant::now();
        sync(&dir).unwrap();
        let b = balance(&dir, 1).unwrap();
        println!("synchronisé en {:?} : {b:?}", start.elapsed());
        assert_eq!((b.spendable, b.pending), (0, 0));
        assert!(b.scanned_height.unwrap() + 5 >= b.chain_height.unwrap() && b.chain_height.unwrap() > BIRTHDAY_HEIGHT);
        assert_eq!(open(&dir).unwrap().get_account_ids().unwrap().len(), 2, "un compte par profil, une seule fois");
        std::fs::remove_dir_all(&dir).ok();
    }
}
