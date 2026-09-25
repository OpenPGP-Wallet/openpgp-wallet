//! Machine à états du protocole WalletConnect v2 côté portefeuille (appairage,
//! proposition de session, approbation, demandes, pings, déconnexion), SANS
//! aucune entrée-sortie : elle reçoit des messages déjà extraits du relais et
//! renvoie des `Action`s (s'abonner, publier, prévenir l'interface) que
//! `relay.rs` exécute. Testable de bout en bout contre une dApp simulée.
//!
//! Déroulé, d'après le moteur du SDK officiel (`sign-client/src/controllers/
//! engine.ts`, étiquettes et durées de `constants/engine.ts`, lus directement) :
//! 1. l'utilisateur colle un lien `wc:` -> abonnement au canal d'appairage ;
//! 2. la dApp y publie `wc_sessionPropose` (sa clé publique X25519) ;
//! 3. approbation : clé de session = X25519 + HKDF, canal = SHA-256 de la clé,
//!    réponse (notre clé publique) sur le canal d'appairage, puis
//!    `wc_sessionSettle` (comptes, méthodes) sur le canal de session ;
//! 4. la dApp envoie des `wc_sessionRequest`, le portefeuille répond.

use super::crypto;
use crate::dapp_requests;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Étiquettes et durées de vie (secondes) des messages, reprises du SDK officiel.
pub const TAG_PAIRING_DELETE_RES: u32 = 1001;
pub const TAG_PAIRING_PING_RES: u32 = 1003;
pub const TAG_SESSION_PROPOSE_RES: u32 = 1101;
pub const TAG_SESSION_SETTLE_REQ: u32 = 1102;
pub const TAG_SESSION_UPDATE_RES: u32 = 1105;
pub const TAG_SESSION_EXTEND_RES: u32 = 1107;
pub const TAG_SESSION_REQUEST_RES: u32 = 1109;
pub const TAG_SESSION_EVENT_RES: u32 = 1111;
pub const TAG_SESSION_DELETE_REQ: u32 = 1112;
pub const TAG_SESSION_DELETE_RES: u32 = 1113;
pub const TAG_SESSION_PING_RES: u32 = 1115;
pub const TAG_SESSION_PROPOSE_REJECT: u32 = 1120;

const FIVE_MINUTES: u64 = 300;
const ONE_DAY: u64 = 86_400;
const SEVEN_DAYS: u64 = 7 * ONE_DAY;
const THIRTY_DAYS: u64 = 30 * ONE_DAY;

// Codes d'erreur du SDK officiel (`utils/src/errors.ts`).
pub const USER_REJECTED: (i64, &str) = (5000, "User rejected.");
pub const UNSUPPORTED_CHAINS: (i64, &str) = (5100, "Unsupported chains.");
pub const UNSUPPORTED_METHODS: (i64, &str) = (5101, "Unsupported methods.");
pub const USER_DISCONNECTED: (i64, &str) = (6000, "User disconnected.");
pub const UNSUPPORTED_WC_METHOD: (i64, &str) = (10001, "Unsupported wc_ method.");

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Identifiant JSON-RPC, même forme que `payloadId()` du SDK : millisecondes
/// × 1000 + 3 chiffres aléatoires.
pub fn payload_id() -> u64 {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let mut r = [0u8; 2];
    let _ = getrandom::getrandom(&mut r);
    ms * 1000 + u64::from(u16::from_le_bytes(r) % 1000)
}

/// Identité d'une dApp telle qu'elle la DÉCLARE elle-même (rien n'est vérifié :
/// n'importe quel site peut annoncer n'importe quel nom ou URL).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PeerMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub icons: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Pairing {
    pub topic: String,
    sym_key: String,
    pub expiry: u64,
    #[serde(default)]
    pub active: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    pub topic: String,
    sym_key: String,
    self_public: String,
    pub pairing_topic: String,
    pub peer: PeerMetadata,
    pub namespaces: Value,
    pub expiry: u64,
    pub profile_index: u32,
    pub evm_address: String,
    pub solana_address: String,
    #[serde(default)]
    pub acknowledged: bool,
}

impl Session {
    pub fn chains(&self) -> Vec<String> {
        self.namespaces
            .as_object()
            .map(|ns| {
                ns.values()
                    .flat_map(|n| n.get("chains").and_then(Value::as_array).cloned().unwrap_or_default())
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn allows(&self, chain: &str, method: &str) -> bool {
        let namespace = chain.split(':').next().unwrap_or("");
        self.namespaces.get(namespace).is_some_and(|n| {
            let has = |field: &str, v: &str| n.get(field).and_then(Value::as_array).is_some_and(|a| a.iter().any(|x| x == v));
            has("chains", chain) && has("methods", method)
        })
    }

    pub fn account(&self) -> dapp_requests::Account {
        dapp_requests::Account { evm: self.evm_address.clone(), solana: self.solana_address.clone() }
    }
}

/// État persisté (`walletconnect.json`) : identité de ce client auprès du
/// relais, appairages et sessions. Aucun secret du PORTEFEUILLE ici : les clés
/// de session ne donnent accès qu'au contenu des échanges avec la dApp, pas
/// aux fonds — voir la doc de `store`.
#[derive(Serialize, Deserialize, Default)]
pub struct PersistedState {
    #[serde(default)]
    pub client_seed: String,
    #[serde(default)]
    pub pairings: Vec<Pairing>,
    #[serde(default)]
    pub sessions: Vec<Session>,
}

pub struct PendingProposal {
    pub id: u64,
    pub pairing_topic: String,
    pub proposer_public: [u8; 32],
    pub peer: PeerMetadata,
    /// Espaces de noms qui seraient accordés, ou raison de l'incompatibilité.
    pub namespaces: Result<Value, String>,
    pub expiry: u64,
}

#[derive(Clone)]
pub struct PendingRequest {
    pub id: u64,
    pub topic: String,
    pub method: String,
    pub params: Value,
    pub chain: String,
    pub expiry: u64,
}

/// Événements destinés à l'interface.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind")]
pub enum WcEvent {
    Proposal { id: u64, peer: PeerMetadata, chains: Vec<String>, methods: Vec<String>, incompatible: Option<String> },
    Request { id: u64, topic: String, peer: PeerMetadata, method: String, chain: String },
    SessionsChanged,
    RelayStatus { connected: bool, error: Option<String> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Subscribe(String),
    Unsubscribe(String),
    /// Récupère les messages déjà publiés sur un canal avant l'abonnement.
    FetchMessages(String),
    Publish { topic: String, message: String, ttl: u64, tag: u32, prompt: bool },
    Emit(WcEvent),
    Persist,
}

/// Métadonnées de CE portefeuille, envoyées à la dApp. Aucune URL de domaine
/// réel : le projet n'en possède pas, et en emprunter un serait trompeur.
fn own_metadata() -> Value {
    json!({
        "name": "PGP Wallet",
        "description": "Portefeuille non-custodial (preuve de concept)",
        "url": "https://pgp-wallet-poc.local",
        "icons": []
    })
}

pub struct Engine {
    pub state: PersistedState,
    proposals: HashMap<u64, PendingProposal>,
    requests: HashMap<u64, PendingRequest>,
}

fn key_from_hex(hex_key: &str) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex_key, &mut key).context("clé WalletConnect enregistrée illisible")?;
    Ok(key)
}

fn rpc_result(id: u64, result: Value) -> String {
    json!({"id": id, "jsonrpc": "2.0", "result": result}).to_string()
}

fn rpc_error(id: u64, (code, message): (i64, &str)) -> String {
    json!({"id": id, "jsonrpc": "2.0", "error": {"code": code, "message": message}}).to_string()
}

/// Espaces de noms accordés pour une proposition : réseaux demandés (exigés
/// ou facultatifs) que ce portefeuille gère, avec les comptes du profil et
/// SES méthodes. Refus si un réseau, une méthode ou un événement EXIGÉ n'est
/// pas géré : une session qui ne tiendrait pas ce qu'exige la dApp serait de
/// toute façon rejetée par elle.
pub fn session_namespaces(params: &Value, account: Option<&dapp_requests::Account>) -> Result<Value, String> {
    let mut requested: HashMap<&str, Vec<String>> = HashMap::new();
    let mut required_methods: Vec<String> = Vec::new();
    let mut required_events: Vec<String> = Vec::new();
    for (field, required) in [("requiredNamespaces", true), ("optionalNamespaces", false)] {
        let Some(map) = params.get(field).and_then(Value::as_object) else { continue };
        for (key, ns) in map {
            // Clé "eip155" avec une liste `chains`, ou clé "eip155:1" directement.
            let mut chains: Vec<String> = ns
                .get("chains")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            if key.contains(':') {
                chains.push(key.clone());
            }
            for chain in chains {
                let namespace = chain.split(':').next().unwrap_or("").to_string();
                let supported = match namespace.as_str() {
                    "eip155" => dapp_requests::EVM_CHAINS.contains(&chain.as_str()),
                    "solana" => dapp_requests::SOLANA_CHAINS.contains(&chain.as_str()),
                    _ => false,
                };
                if supported {
                    let entry = match namespace.as_str() {
                        "eip155" => requested.entry("eip155").or_default(),
                        _ => requested.entry("solana").or_default(),
                    };
                    if !entry.contains(&chain) {
                        entry.push(chain);
                    }
                } else if required {
                    return Err(format!("réseau exigé non pris en charge : {chain}"));
                }
            }
            if required {
                let list = |f: &str| -> Vec<String> {
                    ns.get(f).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
                };
                required_methods.extend(list("methods"));
                required_events.extend(list("events"));
            }
        }
    }
    let supported_methods: Vec<&str> = dapp_requests::EVM_METHODS.iter().chain(dapp_requests::SOLANA_METHODS.iter()).copied().collect();
    if let Some(m) = required_methods.iter().find(|m| !supported_methods.contains(&m.as_str())) {
        return Err(format!("méthode exigée non prise en charge : {m}"));
    }
    if let Some(e) = required_events.iter().find(|e| !dapp_requests::EVM_EVENTS.contains(&e.as_str())) {
        return Err(format!("événement exigé non pris en charge : {e}"));
    }
    if requested.is_empty() {
        return Err("aucun réseau demandé n'est pris en charge (Ethereum, Solana)".to_string());
    }
    let mut namespaces = serde_json::Map::new();
    for (namespace, chains) in requested {
        let address = account.map(|a| if namespace == "eip155" { a.evm.clone() } else { a.solana.clone() });
        let accounts: Vec<String> = chains.iter().filter_map(|c| address.as_ref().map(|a| format!("{c}:{a}"))).collect();
        let (methods, events): (&[&str], &[&str]) = if namespace == "eip155" {
            (&dapp_requests::EVM_METHODS, &dapp_requests::EVM_EVENTS)
        } else {
            (&dapp_requests::SOLANA_METHODS, &[])
        };
        namespaces.insert(namespace.to_string(), json!({"chains": chains, "accounts": accounts, "methods": methods, "events": events}));
    }
    Ok(Value::Object(namespaces))
}

impl Engine {
    pub fn new(mut state: PersistedState) -> Result<Self> {
        if state.client_seed.len() != 64 {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| anyhow!("génération d'aléa impossible : {e}"))?;
            state.client_seed = hex::encode(seed);
        }
        let mut engine = Self { state, proposals: HashMap::new(), requests: HashMap::new() };
        engine.drop_expired();
        Ok(engine)
    }

    pub fn client_seed(&self) -> Result<[u8; 32]> {
        key_from_hex(&self.state.client_seed)
    }

    /// Canaux à écouter (appairages + sessions), après reconnexion notamment.
    pub fn topics(&self) -> Vec<String> {
        self.state.pairings.iter().map(|p| p.topic.clone()).chain(self.state.sessions.iter().map(|s| s.topic.clone())).collect()
    }

    pub fn sessions(&self) -> &[Session] {
        &self.state.sessions
    }

    pub fn pending_request(&self, id: u64) -> Option<&PendingRequest> {
        self.requests.get(&id)
    }

    pub fn session(&self, topic: &str) -> Option<&Session> {
        self.state.sessions.iter().find(|s| s.topic == topic)
    }

    pub fn proposal(&self, id: u64) -> Option<&PendingProposal> {
        self.proposals.get(&id)
    }

    /// Supprime appairages, sessions, propositions et demandes expirés.
    pub fn drop_expired(&mut self) -> Vec<Action> {
        let t = now();
        let mut actions = Vec::new();
        for s in self.state.sessions.iter().filter(|s| s.expiry <= t) {
            actions.push(Action::Unsubscribe(s.topic.clone()));
        }
        for p in self.state.pairings.iter().filter(|p| p.expiry <= t) {
            actions.push(Action::Unsubscribe(p.topic.clone()));
        }
        let before = self.state.sessions.len() + self.state.pairings.len();
        self.state.sessions.retain(|s| s.expiry > t);
        self.state.pairings.retain(|p| p.expiry > t);
        self.proposals.retain(|_, p| p.expiry > t);
        self.requests.retain(|_, r| r.expiry > t);
        if self.state.sessions.len() + self.state.pairings.len() != before {
            actions.push(Action::Persist);
            actions.push(Action::Emit(WcEvent::SessionsChanged));
        }
        actions
    }

    /// Lien `wc:` collé par l'utilisateur.
    pub fn pair(&mut self, uri: &str) -> Result<Vec<Action>> {
        let parsed = super::uri::parse(uri)?;
        anyhow::ensure!(parsed.expiry.is_none_or(|e| e > now()), "ce lien WalletConnect a expiré : demandez-en un nouveau à la dApp");
        anyhow::ensure!(
            !self.state.pairings.iter().any(|p| p.topic == parsed.topic),
            "ce lien WalletConnect a déjà été utilisé : demandez-en un nouveau à la dApp"
        );
        self.state.pairings.push(Pairing {
            topic: parsed.topic.clone(),
            sym_key: hex::encode(*parsed.sym_key),
            expiry: parsed.expiry.unwrap_or(now() + FIVE_MINUTES),
            active: false,
        });
        Ok(vec![Action::Persist, Action::Subscribe(parsed.topic.clone()), Action::FetchMessages(parsed.topic)])
    }

    fn sym_key_for(&self, topic: &str) -> Option<[u8; 32]> {
        self.state
            .pairings
            .iter()
            .find(|p| p.topic == topic)
            .map(|p| p.sym_key.as_str())
            .or_else(|| self.state.sessions.iter().find(|s| s.topic == topic).map(|s| s.sym_key.as_str()))
            .and_then(|k| key_from_hex(k).ok())
    }

    fn publish(&self, topic: &str, payload: &str, ttl: u64, tag: u32) -> Result<Action> {
        let key = self.sym_key_for(topic).ok_or_else(|| anyhow!("canal WalletConnect inconnu"))?;
        Ok(Action::Publish { topic: topic.to_string(), message: crypto::encrypt_type0(&key, payload)?, ttl, tag, prompt: false })
    }

    /// Message chiffré reçu du relais sur `topic`. Tout message illisible,
    /// d'un canal inconnu ou mal formé est ignoré (jamais d'erreur fatale sur
    /// une donnée venue du réseau).
    pub fn handle_incoming(&mut self, topic: &str, encrypted: &str) -> Vec<Action> {
        let Some(key) = self.sym_key_for(topic) else { return Vec::new() };
        let Ok(opened) = crypto::decrypt(&key, encrypted) else { return Vec::new() };
        let Ok(payload) = serde_json::from_str::<Value>(&opened.plaintext) else { return Vec::new() };
        let Some(id) = payload.get("id").and_then(Value::as_u64) else { return Vec::new() };
        let is_pairing = self.state.pairings.iter().any(|p| p.topic == topic);
        match payload.get("method").and_then(Value::as_str) {
            Some(method) => {
                let params = payload.get("params").cloned().unwrap_or(Value::Null);
                if is_pairing {
                    self.on_pairing_request(topic, id, method, params)
                } else {
                    self.on_session_request(topic, id, method, params)
                }
            }
            // Réponse (à `wc_sessionSettle` notamment).
            None => {
                if payload.get("result") == Some(&Value::Bool(true)) {
                    if let Some(s) = self.state.sessions.iter_mut().find(|s| s.topic == topic && !s.acknowledged) {
                        s.acknowledged = true;
                        return vec![Action::Persist];
                    }
                }
                Vec::new()
            }
        }
    }

    fn on_pairing_request(&mut self, topic: &str, id: u64, method: &str, params: Value) -> Vec<Action> {
        match method {
            "wc_sessionPropose" => {
                let proposer_public = params
                    .pointer("/proposer/publicKey")
                    .and_then(Value::as_str)
                    .and_then(|k| key_from_hex(k).ok());
                let Some(proposer_public) = proposer_public else { return Vec::new() };
                let peer: PeerMetadata =
                    params.pointer("/proposer/metadata").and_then(|m| serde_json::from_value(m.clone()).ok()).unwrap_or_default();
                let namespaces = session_namespaces(&params, None);
                let (chains, methods) = match &namespaces {
                    Ok(ns) => (
                        ns.as_object()
                            .map(|o| o.values().flat_map(|n| n["chains"].as_array().cloned().unwrap_or_default()).filter_map(|c| c.as_str().map(str::to_string)).collect())
                            .unwrap_or_default(),
                        ns.as_object()
                            .map(|o| o.values().flat_map(|n| n["methods"].as_array().cloned().unwrap_or_default()).filter_map(|c| c.as_str().map(str::to_string)).collect())
                            .unwrap_or_default(),
                    ),
                    Err(_) => (Vec::new(), Vec::new()),
                };
                let expiry = params.get("expiryTimestamp").and_then(Value::as_u64).unwrap_or(now() + FIVE_MINUTES);
                let incompatible = namespaces.as_ref().err().cloned();
                self.proposals.insert(
                    id,
                    PendingProposal { id, pairing_topic: topic.to_string(), proposer_public, peer: peer.clone(), namespaces: namespaces.map(|_| params.clone()), expiry },
                );
                vec![Action::Emit(WcEvent::Proposal { id, peer, chains, methods, incompatible })]
            }
            "wc_pairingPing" => self.publish(topic, &rpc_result(id, json!(true)), 30, TAG_PAIRING_PING_RES).into_iter().collect(),
            "wc_pairingDelete" => {
                let mut actions: Vec<Action> = self.publish(topic, &rpc_result(id, json!(true)), ONE_DAY, TAG_PAIRING_DELETE_RES).into_iter().collect();
                self.state.pairings.retain(|p| p.topic != topic);
                actions.extend([Action::Unsubscribe(topic.to_string()), Action::Persist]);
                actions
            }
            // Authentification "en un clic" (wc_sessionAuthenticate) non prise
            // en charge : sans réponse, la dApp retombe sur une proposition classique.
            _ => Vec::new(),
        }
    }

    fn on_session_request(&mut self, topic: &str, id: u64, method: &str, params: Value) -> Vec<Action> {
        let Some(session) = self.session(topic).cloned() else { return Vec::new() };
        match method {
            "wc_sessionRequest" => {
                let chain = params.get("chainId").and_then(Value::as_str).unwrap_or("").to_string();
                let request_method = params.pointer("/request/method").and_then(Value::as_str).unwrap_or("").to_string();
                let request_params = params.pointer("/request/params").cloned().unwrap_or(Value::Null);
                if !session.allows(&chain, &request_method) {
                    let error = if dapp_requests::network_for_chain(&chain).is_none() { UNSUPPORTED_CHAINS } else { UNSUPPORTED_METHODS };
                    return self.publish(topic, &rpc_error(id, error), 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES).into_iter().collect();
                }
                // Lecture des comptes : aucune signature, réponse immédiate.
                if matches!(request_method.as_str(), "solana_getAccounts" | "solana_requestAccounts") {
                    let result = json!([{"pubkey": session.solana_address}]);
                    return self.publish(topic, &rpc_result(id, result), 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES).into_iter().collect();
                }
                let expiry = params.pointer("/request/expiryTimestamp").and_then(Value::as_u64).unwrap_or(now() + 3 * FIVE_MINUTES);
                self.requests.insert(
                    id,
                    PendingRequest { id, topic: topic.to_string(), method: request_method.clone(), params: request_params, chain: chain.clone(), expiry },
                );
                vec![Action::Emit(WcEvent::Request { id, topic: topic.to_string(), peer: session.peer, method: request_method, chain })]
            }
            "wc_sessionPing" => self.publish(topic, &rpc_result(id, json!(true)), ONE_DAY, TAG_SESSION_PING_RES).into_iter().collect(),
            "wc_sessionDelete" => {
                let mut actions: Vec<Action> = self.publish(topic, &rpc_result(id, json!(true)), ONE_DAY, TAG_SESSION_DELETE_RES).into_iter().collect();
                self.remove_session(topic);
                actions.extend([Action::Unsubscribe(topic.to_string()), Action::Persist, Action::Emit(WcEvent::SessionsChanged)]);
                actions
            }
            // Seul le portefeuille (contrôleur) peut modifier ou prolonger une session.
            "wc_sessionUpdate" => self.publish(topic, &rpc_error(id, (3003, "Unauthorized update request.")), ONE_DAY, TAG_SESSION_UPDATE_RES).into_iter().collect(),
            "wc_sessionExtend" => self.publish(topic, &rpc_error(id, (3004, "Unauthorized extend request.")), ONE_DAY, TAG_SESSION_EXTEND_RES).into_iter().collect(),
            "wc_sessionEvent" => self.publish(topic, &rpc_error(id, (3002, "Unauthorized event.")), FIVE_MINUTES, TAG_SESSION_EVENT_RES).into_iter().collect(),
            _ => self.publish(topic, &rpc_error(id, UNSUPPORTED_WC_METHOD), ONE_DAY, 0).into_iter().collect(),
        }
    }

    fn remove_session(&mut self, topic: &str) {
        self.state.sessions.retain(|s| s.topic != topic);
        self.requests.retain(|_, r| r.topic != topic);
    }

    /// Approbation d'une proposition par l'utilisateur, pour le profil choisi.
    pub fn approve(&mut self, proposal_id: u64, profile_index: u32, account: &dapp_requests::Account) -> Result<Vec<Action>> {
        let proposal = self.proposals.remove(&proposal_id).ok_or_else(|| anyhow!("proposition de connexion introuvable ou expirée"))?;
        let params = proposal.namespaces.map_err(|reason| anyhow!("connexion impossible : {reason}"))?;
        let namespaces = session_namespaces(&params, Some(account)).map_err(|reason| anyhow!("connexion impossible : {reason}"))?;

        let own = crypto::KeyPair::generate()?;
        let sym_key = crypto::derive_sym_key(&own.private, &proposal.proposer_public)?;
        let session_topic = crypto::topic_for_key(&sym_key);
        let expiry = now() + SEVEN_DAYS;
        let own_public = hex::encode(own.public);

        let response = rpc_result(proposal.id, json!({"relay": {"protocol": "irn"}, "responderPublicKey": own_public}));
        let pairing_publish = self.publish(&proposal.pairing_topic, &response, FIVE_MINUTES, TAG_SESSION_PROPOSE_RES)?;

        self.state.sessions.push(Session {
            topic: session_topic.clone(),
            sym_key: hex::encode(*sym_key),
            self_public: own_public.clone(),
            pairing_topic: proposal.pairing_topic.clone(),
            peer: proposal.peer.clone(),
            namespaces: namespaces.clone(),
            expiry,
            profile_index,
            evm_address: account.evm.clone(),
            solana_address: account.solana.clone(),
            acknowledged: false,
        });
        if let Some(p) = self.state.pairings.iter_mut().find(|p| p.topic == proposal.pairing_topic) {
            p.active = true;
            p.expiry = now() + THIRTY_DAYS;
        }
        let settle = json!({
            "id": payload_id(), "jsonrpc": "2.0", "method": "wc_sessionSettle",
            "params": {
                "relay": {"protocol": "irn"},
                "namespaces": namespaces,
                "controller": {"publicKey": own_public, "metadata": own_metadata()},
                "expiry": expiry
            }
        })
        .to_string();
        let settle_publish = self.publish(&session_topic, &settle, FIVE_MINUTES, TAG_SESSION_SETTLE_REQ)?;
        Ok(vec![
            Action::Persist,
            Action::Subscribe(session_topic),
            pairing_publish,
            settle_publish,
            Action::Emit(WcEvent::SessionsChanged),
        ])
    }

    pub fn reject(&mut self, proposal_id: u64) -> Result<Vec<Action>> {
        let proposal = self.proposals.remove(&proposal_id).ok_or_else(|| anyhow!("proposition de connexion introuvable ou expirée"))?;
        Ok(vec![self.publish(&proposal.pairing_topic, &rpc_error(proposal.id, USER_REJECTED), FIVE_MINUTES, TAG_SESSION_PROPOSE_REJECT)?])
    }

    /// Réponse à une demande : résultat de la signature, ou erreur (refus).
    pub fn respond(&mut self, request_id: u64, result: std::result::Result<Value, (i64, String)>) -> Result<Vec<Action>> {
        let request = self.requests.remove(&request_id).ok_or_else(|| anyhow!("demande introuvable ou expirée"))?;
        let payload = match result {
            Ok(value) => rpc_result(request.id, value),
            Err((code, message)) => json!({"id": request.id, "jsonrpc": "2.0", "error": {"code": code, "message": message}}).to_string(),
        };
        Ok(vec![self.publish(&request.topic, &payload, 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES)?])
    }

    /// Déconnexion à l'initiative de l'utilisateur.
    pub fn disconnect(&mut self, topic: &str) -> Result<Vec<Action>> {
        anyhow::ensure!(self.session(topic).is_some(), "connexion introuvable");
        let delete = json!({
            "id": payload_id(), "jsonrpc": "2.0", "method": "wc_sessionDelete",
            "params": {"code": USER_DISCONNECTED.0, "message": USER_DISCONNECTED.1}
        })
        .to_string();
        let publish = self.publish(topic, &delete, ONE_DAY, TAG_SESSION_DELETE_REQ)?;
        self.remove_session(topic);
        Ok(vec![publish, Action::Unsubscribe(topic.to_string()), Action::Persist, Action::Emit(WcEvent::SessionsChanged)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dApp simulée, avec les mêmes primitives (elles-mêmes vérifiées contre
    /// le SDK officiel) : crée le lien, propose, déchiffre les réponses.
    struct FakeDapp {
        pairing_key: [u8; 32],
        pairing_topic: String,
        keys: crypto::KeyPair,
        session_key: Option<[u8; 32]>,
    }

    impl FakeDapp {
        fn new() -> Self {
            let pairing_key = [0x42; 32];
            Self { pairing_topic: crypto::topic_for_key(&pairing_key), pairing_key, keys: crypto::KeyPair::generate().unwrap(), session_key: None }
        }
        fn uri(&self) -> String {
            format!("wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp={}", self.pairing_topic, hex::encode(self.pairing_key), now() + 300)
        }
        fn propose(&self, id: u64, required: Value, optional: Value) -> String {
            let payload = json!({"id": id, "jsonrpc": "2.0", "method": "wc_sessionPropose", "params": {
                "relays": [{"protocol": "irn"}],
                "requiredNamespaces": required, "optionalNamespaces": optional,
                "proposer": {"publicKey": hex::encode(self.keys.public), "metadata": {"name": "Démo dApp", "description": "", "url": "https://dapp.example", "icons": []}}
            }});
            crypto::encrypt_type0(&self.pairing_key, &payload.to_string()).unwrap()
        }
        fn open(&self, key: &[u8; 32], message: &str) -> Value {
            serde_json::from_str(&crypto::decrypt(key, message).unwrap().plaintext).unwrap()
        }
    }

    fn account() -> dapp_requests::Account {
        dapp_requests::Account { evm: "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23".into(), solana: "9waCLiN9G99f1GXMVBQqifbPMwGMYvJZFUHywRCQPG5F".into() }
    }

    fn published(actions: &[Action]) -> Vec<(String, String, u32)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Publish { topic, message, tag, .. } => Some((topic.clone(), message.clone(), *tag)),
                _ => None,
            })
            .collect()
    }

    /// Déroulé complet contre une dApp simulée : appairage, proposition,
    /// approbation (la dApp retrouve la clé de session et lit les comptes),
    /// demande de signature, réponse, ping, déconnexion.
    #[test]
    fn full_session_flow_against_a_simulated_dapp() {
        let mut dapp = FakeDapp::new();
        let mut engine = Engine::new(PersistedState::default()).unwrap();
        let actions = engine.pair(&dapp.uri()).unwrap();
        assert!(actions.contains(&Action::Subscribe(dapp.pairing_topic.clone())));
        assert!(actions.contains(&Action::FetchMessages(dapp.pairing_topic.clone())));

        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["eth_sendTransaction", "personal_sign"], "events": ["accountsChanged", "chainChanged"]}});
        let optional = json!({"eip155": {"chains": ["eip155:137", "eip155:11155111"], "methods": ["eth_signTypedData_v4", "wallet_switchEthereumChain"], "events": []}, "solana": {"chains": [dapp_requests::SOLANA_MAINNET], "methods": ["solana_signMessage"], "events": []}});
        let actions = engine.handle_incoming(&dapp.pairing_topic.clone(), &dapp.propose(7, required, optional));
        match &actions[..] {
            [Action::Emit(WcEvent::Proposal { id: 7, peer, chains, incompatible: None, .. })] => {
                assert_eq!(peer.name, "Démo dApp");
                assert!(chains.contains(&"eip155:1".to_string()) && chains.contains(&"eip155:11155111".to_string()));
                assert!(!chains.contains(&"eip155:137".to_string()), "réseau facultatif non géré : omis");
            }
            other => panic!("{other:?}"),
        }

        let actions = engine.approve(7, 0, &account()).unwrap();
        let pubs = published(&actions);
        assert_eq!(pubs.len(), 2);
        // Réponse à la proposition, sur le canal d'appairage : notre clé publique.
        let (topic, message, tag) = &pubs[0];
        assert_eq!((topic, *tag), (&dapp.pairing_topic, TAG_SESSION_PROPOSE_RES));
        let response = dapp.open(&dapp.pairing_key, message);
        assert_eq!(response["id"], 7);
        let wallet_public = key_from_hex(response["result"]["responderPublicKey"].as_str().unwrap()).unwrap();
        // La dApp dérive la MÊME clé de session et le même canal.
        let session_key = *crypto::derive_sym_key(&dapp.keys.private, &wallet_public).unwrap();
        let session_topic = crypto::topic_for_key(&session_key);
        dapp.session_key = Some(session_key);
        let (topic, message, tag) = &pubs[1];
        assert_eq!((topic, *tag), (&session_topic, TAG_SESSION_SETTLE_REQ));
        let settle = dapp.open(&session_key, message);
        assert_eq!(settle["method"], "wc_sessionSettle");
        let ns = &settle["params"]["namespaces"];
        assert_eq!(ns["eip155"]["accounts"][0], format!("eip155:1:{}", account().evm));
        assert_eq!(ns["solana"]["accounts"][0], format!("{}:{}", dapp_requests::SOLANA_MAINNET, account().solana));
        assert!(ns["eip155"]["methods"].as_array().unwrap().iter().all(|m| m != "eth_sign"));
        assert!(actions.contains(&Action::Subscribe(session_topic.clone())));

        // Demande de signature.
        let request = json!({"id": 99, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {
            "request": {"method": "personal_sign", "params": ["0x48656c6c6f", account().evm]}, "chainId": "eip155:1"}});
        let actions = engine.handle_incoming(&session_topic, &crypto::encrypt_type0(&session_key, &request.to_string()).unwrap());
        assert!(matches!(&actions[..], [Action::Emit(WcEvent::Request { id: 99, method, .. })] if method == "personal_sign"));
        assert_eq!(engine.pending_request(99).unwrap().params[0], "0x48656c6c6f");
        let actions = engine.respond(99, Ok(json!("0xsignature"))).unwrap();
        let (_, message, tag) = &published(&actions)[0];
        assert_eq!(*tag, TAG_SESSION_REQUEST_RES);
        assert_eq!(dapp.open(&session_key, message), json!({"id": 99, "jsonrpc": "2.0", "result": "0xsignature"}));
        assert!(engine.respond(99, Ok(json!("rejouée"))).is_err(), "une demande ne reçoit qu'une réponse");

        // Méthode hors session (eth_sign) et réseau hors session : erreur immédiate, jamais montrée.
        for (method, chain, code) in [("eth_sign", "eip155:1", 5101), ("personal_sign", "eip155:137", 5100)] {
            let request = json!({"id": 100, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {"request": {"method": method, "params": []}, "chainId": chain}});
            let actions = engine.handle_incoming(&session_topic, &crypto::encrypt_type0(&session_key, &request.to_string()).unwrap());
            let (_, message, _) = &published(&actions)[0];
            assert_eq!(dapp.open(&session_key, message)["error"]["code"], code, "{method} {chain}");
        }

        // Ping, puis déconnexion par le portefeuille.
        let ping = json!({"id": 5, "jsonrpc": "2.0", "method": "wc_sessionPing", "params": {}});
        let actions = engine.handle_incoming(&session_topic, &crypto::encrypt_type0(&session_key, &ping.to_string()).unwrap());
        assert_eq!(dapp.open(&session_key, &published(&actions)[0].1)["result"], true);
        let actions = engine.disconnect(&session_topic).unwrap();
        assert_eq!(dapp.open(&session_key, &published(&actions)[0].1)["method"], "wc_sessionDelete");
        assert!(engine.sessions().is_empty());
    }

    #[test]
    fn incompatible_proposals_cannot_be_approved_and_rejections_reach_the_dapp() {
        let dapp = FakeDapp::new();
        let mut engine = Engine::new(PersistedState::default()).unwrap();
        engine.pair(&dapp.uri()).unwrap();
        let required = json!({"eip155": {"chains": ["eip155:137"], "methods": ["eth_sendTransaction"], "events": []}});
        let actions = engine.handle_incoming(&dapp.pairing_topic.clone(), &dapp.propose(8, required, json!({})));
        assert!(matches!(&actions[..], [Action::Emit(WcEvent::Proposal { incompatible: Some(_), .. })]));
        assert!(engine.approve(8, 0, &account()).is_err());

        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["eth_sign"], "events": []}});
        engine.handle_incoming(&dapp.pairing_topic.clone(), &dapp.propose(9, required, json!({})));
        assert!(engine.approve(9, 0, &account()).is_err(), "eth_sign exigé : incompatible");

        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["personal_sign"], "events": []}});
        engine.handle_incoming(&dapp.pairing_topic.clone(), &dapp.propose(10, required, json!({})));
        let actions = engine.reject(10).unwrap();
        let (_, message, tag) = &published(&actions)[0];
        assert_eq!(*tag, TAG_SESSION_PROPOSE_REJECT);
        assert_eq!(dapp.open(&dapp.pairing_key, message)["error"]["code"], 5000);
    }

    #[test]
    fn garbage_foreign_or_replayed_input_is_ignored() {
        let dapp = FakeDapp::new();
        let mut engine = Engine::new(PersistedState::default()).unwrap();
        engine.pair(&dapp.uri()).unwrap();
        assert!(engine.pair(&dapp.uri()).is_err(), "lien déjà utilisé");
        assert!(engine.handle_incoming("canal-inconnu", &dapp.propose(1, json!({}), json!({}))).is_empty());
        assert!(engine.handle_incoming(&dapp.pairing_topic.clone(), "pas une enveloppe").is_empty());
        let other_key = crypto::encrypt_type0(&[1; 32], "{}").unwrap();
        assert!(engine.handle_incoming(&dapp.pairing_topic.clone(), &other_key).is_empty());
        let expired = format!("wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp=1000", "ab".repeat(32), "cd".repeat(32));
        assert!(engine.pair(&expired).is_err());
    }
}
