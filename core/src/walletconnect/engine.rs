//! Wallet-side state machine for the WalletConnect v2 protocol (pairing, session
//! proposal, approval, requests, pings, disconnection), with NO input/output of its
//! own: it takes messages already extracted from the relay and returns `Action`s
//! (subscribe, publish, notify the UI) that `relay.rs` carries out. Testable end to
//! end against a simulated dApp.
//!
//! Flow, following the official SDK engine
//! (`sign-client/src/controllers/engine.ts`, with tags and lifetimes from
//! `constants/engine.ts`, read directly):
//! 1. the user pastes a `wc:` link -> subscribe to the pairing topic;
//! 2. the dApp publishes `wc_sessionPropose` there (its X25519 public key);
//! 3. approval: session key = X25519 + HKDF, topic = SHA-256 of the key, response
//!    (our public key) on the pairing topic, then `wc_sessionSettle` (accounts,
//!    methods) on the session topic;
//! 4. the dApp sends `wc_sessionRequest`s and the wallet answers.

use super::crypto;
use crate::dapp_requests;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Message tags and lifetimes (seconds), taken from the official SDK.
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
/// Maximum lifetime of a pending request or proposal, whatever the dApp announces
/// (`expiryTimestamp`, which it picks itself).
const MAX_PENDING_LIFETIME: u64 = 3 * FIVE_MINUTES;
/// Beyond this, new requests/proposals are refused: a dApp can neither exhaust
/// memory nor flood the user with windows.
const MAX_PENDING_REQUESTS: usize = 20;
/// Per connection: one dApp cannot take up the whole queue at the expense of the
/// others.
const MAX_PENDING_PER_SESSION: usize = 8;
const MAX_PENDING_PROPOSALS: usize = 10;
/// Messages already received are kept in memory (and on disk) for one day, at most
/// `MAX_SEEN`: longer than the relay's message lifetime.
const SEEN_LIFETIME: u64 = ONE_DAY;
const MAX_SEEN: usize = 500;

// Error codes from the official SDK (`utils/src/errors.ts`).
pub const USER_REJECTED: (i64, &str) = (5000, "User rejected.");
pub const UNSUPPORTED_CHAINS: (i64, &str) = (5100, "Unsupported chains.");
pub const UNSUPPORTED_METHODS: (i64, &str) = (5101, "Unsupported methods.");
pub const USER_DISCONNECTED: (i64, &str) = (6000, "User disconnected.");
pub const UNSUPPORTED_WC_METHOD: (i64, &str) = (10001, "Unsupported wc_ method.");
pub const DUPLICATE_REQUEST: (i64, &str) = (-32600, "Request id already pending.");
pub const TOO_MANY_REQUESTS: (i64, &str) = (-32005, "Too many pending requests.");

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// JSON-RPC identifier, same shape as the SDK's `payloadId()`: milliseconds × 1000
/// + 3 random digits.
pub fn payload_id() -> u64 {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let mut r = [0u8; 2];
    let _ = getrandom::getrandom(&mut r);
    ms * 1000 + u64::from(u16::from_le_bytes(r) % 1000)
}

/// A dApp's identity as it DECLARES it (nothing is verified: any website can
/// announce any name or URL).
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

/// A request or proposal already received (topic, JSON-RPC identifier).
#[derive(Serialize, Deserialize, Clone)]
pub struct SeenMessage {
    pub topic: String,
    pub id: u64,
    pub expiry: u64,
}

/// Persisted state (`walletconnect.json`): this client's identity on the relay,
/// pairings and sessions. No WALLET secret here: session keys only give access to
/// the content exchanged with the dApp, not to funds (see the docs of `store`).
#[derive(Serialize, Deserialize, Default)]
pub struct PersistedState {
    #[serde(default)]
    pub client_seed: String,
    #[serde(default)]
    pub pairings: Vec<Pairing>,
    #[serde(default)]
    pub sessions: Vec<Session>,
    /// Messages already received: the relay guarantees "at least once" delivery and may
    /// deliver a message again (reconnection, lost acknowledgement). Without this
    /// history, a request that had ALREADY BEEN SIGNED came back as new, and an
    /// `eth_sendTransaction` confirmed a second time would have paid twice. Kept on
    /// disk, since a redelivery can come after a restart. Found in audit round 24 (the
    /// official SDK keeps a similar history).
    #[serde(default)]
    pub seen: Vec<SeenMessage>,
}

pub struct PendingProposal {
    pub id: u64,
    pub pairing_topic: String,
    pub proposer_public: [u8; 32],
    pub peer: PeerMetadata,
    /// Namespaces that would be granted, or the reason they are incompatible.
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

/// Events for the UI.
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
    /// Fetches the messages already published on a topic before subscribing.
    FetchMessages(String),
    Publish { topic: String, message: String, ttl: u64, tag: u32, prompt: bool },
    Emit(WcEvent),
    Persist,
}

/// THIS wallet's metadata, sent to the dApp. No real domain URL: the project does
/// not own one, and borrowing one would be misleading.
fn own_metadata() -> Value {
    json!({
        "name": "OpenPGP Wallet",
        "description": "Portefeuille non-custodial (preuve de concept)",
        // Unchanged until a new URL is tested against a live dApp.
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

/// Namespaces granted for a proposal: the requested networks (required or optional)
/// this wallet supports, with the profile's accounts and ITS methods. Refused if a
/// REQUIRED network, method or event is not supported: a session that could not
/// deliver what the dApp requires would be rejected by the dApp anyway.
pub fn session_namespaces(params: &Value, account: Option<&dapp_requests::Account>) -> Result<Value, String> {
    let mut requested: HashMap<&str, Vec<String>> = HashMap::new();
    let mut required_methods: Vec<String> = Vec::new();
    let mut required_events: Vec<String> = Vec::new();
    for (field, required) in [("requiredNamespaces", true), ("optionalNamespaces", false)] {
        let Some(map) = params.get(field).and_then(Value::as_object) else { continue };
        for (key, ns) in map {
            // "eip155" key with a `chains` list, or an "eip155:1" key directly.
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
                    "eip155" => dapp_requests::evm_chain_supported(&chain),
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
        return Err("aucun réseau demandé n'est pris en charge (réseaux EVM de l'app, Solana)".to_string());
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

    /// Topics to listen to (pairings + sessions), notably after reconnecting.
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

    /// Removes expired pairings, sessions, proposals and requests.
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
        self.state.seen.retain(|m| m.expiry > t);
        if self.state.sessions.len() + self.state.pairings.len() != before {
            actions.push(Action::Persist);
            actions.push(Action::Emit(WcEvent::SessionsChanged));
        }
        actions
    }

    /// A `wc:` link pasted by the user.
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

    /// (`topic`, `id`) already accepted (shown to the user).
    fn already_seen(&self, topic: &str, id: u64) -> bool {
        self.state.seen.iter().any(|m| m.id == id && m.topic == topic)
    }

    /// Remembers (`topic`, `id`) once the request or proposal has been ACCEPTED: a
    /// refused request (queue full…) can safely come back, since it was never shown.
    fn remember(&mut self, topic: &str, id: u64) {
        if self.state.seen.len() >= MAX_SEEN {
            self.state.seen.remove(0);
        }
        self.state.seen.push(SeenMessage { topic: topic.to_string(), id, expiry: now() + SEEN_LIFETIME });
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

    /// Encrypted message received from the relay on `topic`. Anything unreadable, from
    /// an unknown topic or malformed is ignored (data from the network never causes a
    /// fatal error).
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
            // A response (notably to `wc_sessionSettle`).
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
                // Already received (redelivery), identifier reused by another pairing, or too many
                // proposals: ignored. See `on_session_request`.
                if self.already_seen(topic, id) || self.proposals.contains_key(&id) || self.proposals.len() >= MAX_PENDING_PROPOSALS {
                    return Vec::new();
                }
                self.remember(topic, id);
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
                let expiry = params.get("expiryTimestamp").and_then(Value::as_u64).unwrap_or(now() + FIVE_MINUTES).min(now() + MAX_PENDING_LIFETIME);
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
            // "One-click" authentication (wc_sessionAuthenticate) is not supported: with no
            // answer, the dApp falls back to a regular proposal.
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
                // Reading accounts: no signature, immediate answer.
                if matches!(request_method.as_str(), "solana_getAccounts" | "solana_requestAccounts") {
                    let result = json!([{"pubkey": session.solana_address}]);
                    return self.publish(topic, &rpc_result(id, result), 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES).into_iter().collect();
                }
                // Already received on this topic: a relay redelivery, ignored without an answer
                // (if still pending, it keeps its window; if already handled, it does not come
                // back as a new request).
                if self.already_seen(topic, id) {
                    return Vec::new();
                }
                // The JSON-RPC identifier is chosen by the dApp and is only unique for THAT dApp:
                // another connected dApp could reuse the identifier of a request awaiting
                // confirmation, replace it, and receive the signature meant for the first one. An
                // identifier already pending is refused; the first request stays.
                if self.requests.contains_key(&id) {
                    return self.publish(topic, &rpc_error(id, DUPLICATE_REQUEST), 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES).into_iter().collect();
                }
                let from_session = self.requests.values().filter(|r| r.topic == topic).count();
                if self.requests.len() >= MAX_PENDING_REQUESTS || from_session >= MAX_PENDING_PER_SESSION {
                    return self.publish(topic, &rpc_error(id, TOO_MANY_REQUESTS), 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES).into_iter().collect();
                }
                let expiry = params
                    .pointer("/request/expiryTimestamp")
                    .and_then(Value::as_u64)
                    .unwrap_or(now() + 3 * FIVE_MINUTES)
                    .min(now() + MAX_PENDING_LIFETIME);
                self.remember(topic, id);
                self.requests.insert(
                    id,
                    PendingRequest { id, topic: topic.to_string(), method: request_method.clone(), params: request_params, chain: chain.clone(), expiry },
                );
                vec![Action::Persist, Action::Emit(WcEvent::Request { id, topic: topic.to_string(), peer: session.peer, method: request_method, chain })]
            }
            "wc_sessionPing" => self.publish(topic, &rpc_result(id, json!(true)), ONE_DAY, TAG_SESSION_PING_RES).into_iter().collect(),
            "wc_sessionDelete" => {
                let mut actions: Vec<Action> = self.publish(topic, &rpc_result(id, json!(true)), ONE_DAY, TAG_SESSION_DELETE_RES).into_iter().collect();
                self.remove_session(topic);
                actions.extend([Action::Unsubscribe(topic.to_string()), Action::Persist, Action::Emit(WcEvent::SessionsChanged)]);
                actions
            }
            // Only the wallet (the controller) can update or extend a session.
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

    /// The user approves a proposal, for the chosen profile.
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

    /// Answer to a request: the signature result, or an error (refusal).
    pub fn respond(&mut self, request_id: u64, result: std::result::Result<Value, (i64, String)>) -> Result<Vec<Action>> {
        let request = self.requests.remove(&request_id).ok_or_else(|| anyhow!("demande introuvable ou expirée"))?;
        let payload = match result {
            Ok(value) => rpc_result(request.id, value),
            Err((code, message)) => json!({"id": request.id, "jsonrpc": "2.0", "error": {"code": code, "message": message}}).to_string(),
        };
        Ok(vec![self.publish(&request.topic, &payload, 3 * FIVE_MINUTES, TAG_SESSION_REQUEST_RES)?])
    }

    /// Disconnection initiated by the user.
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

    /// Simulated dApp, using the same primitives (themselves checked against the
    /// official SDK): creates the link, proposes, decrypts the responses.
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

    /// Full flow against a simulated dApp: pairing, proposal, approval (the dApp
    /// recovers the session key and reads the accounts), signing request, response,
    /// ping, disconnection.
    #[test]
    fn full_session_flow_against_a_simulated_dapp() {
        let mut dapp = FakeDapp::new();
        let mut engine = Engine::new(PersistedState::default()).unwrap();
        let actions = engine.pair(&dapp.uri()).unwrap();
        assert!(actions.contains(&Action::Subscribe(dapp.pairing_topic.clone())));
        assert!(actions.contains(&Action::FetchMessages(dapp.pairing_topic.clone())));

        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["eth_sendTransaction", "personal_sign"], "events": ["accountsChanged", "chainChanged"]}});
        let optional = json!({"eip155": {"chains": ["eip155:10", "eip155:11155111", "eip155:8453"], "methods": ["eth_signTypedData_v4", "wallet_switchEthereumChain"], "events": []}, "solana": {"chains": [dapp_requests::SOLANA_MAINNET], "methods": ["solana_signMessage"], "events": []}});
        let actions = engine.handle_incoming(&dapp.pairing_topic.clone(), &dapp.propose(7, required, optional));
        match &actions[..] {
            [Action::Emit(WcEvent::Proposal { id: 7, peer, chains, incompatible: None, .. })] => {
                assert_eq!(peer.name, "Démo dApp");
                assert!(chains.contains(&"eip155:1".to_string()) && chains.contains(&"eip155:11155111".to_string()));
                assert!(!chains.contains(&"eip155:10".to_string()), "réseau facultatif non géré : omis");
                assert!(chains.contains(&"eip155:8453".to_string()), "Base, géré par l'app : accordé");
            }
            other => panic!("{other:?}"),
        }

        let actions = engine.approve(7, 0, &account()).unwrap();
        let pubs = published(&actions);
        assert_eq!(pubs.len(), 2);
        // Response to the proposal, on the pairing topic: our public key.
        let (topic, message, tag) = &pubs[0];
        assert_eq!((topic, *tag), (&dapp.pairing_topic, TAG_SESSION_PROPOSE_RES));
        let response = dapp.open(&dapp.pairing_key, message);
        assert_eq!(response["id"], 7);
        let wallet_public = key_from_hex(response["result"]["responderPublicKey"].as_str().unwrap()).unwrap();
        // The dApp derives the SAME session key and the same topic.
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

        // Signing request.
        let request = json!({"id": 99, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {
            "request": {"method": "personal_sign", "params": ["0x48656c6c6f", account().evm]}, "chainId": "eip155:1"}});
        let actions = engine.handle_incoming(&session_topic, &crypto::encrypt_type0(&session_key, &request.to_string()).unwrap());
        assert!(matches!(&actions[..], [Action::Persist, Action::Emit(WcEvent::Request { id: 99, method, .. })] if method == "personal_sign"));
        assert_eq!(engine.pending_request(99).unwrap().params[0], "0x48656c6c6f");
        let actions = engine.respond(99, Ok(json!("0xsignature"))).unwrap();
        let (_, message, tag) = &published(&actions)[0];
        assert_eq!(*tag, TAG_SESSION_REQUEST_RES);
        assert_eq!(dapp.open(&session_key, message), json!({"id": 99, "jsonrpc": "2.0", "result": "0xsignature"}));
        assert!(engine.respond(99, Ok(json!("rejouée"))).is_err(), "une demande ne reçoit qu'une réponse");

        // A method outside the session (eth_sign) and a network outside the session: immediate
        // error, never shown.
        for (method, chain, code) in [("eth_sign", "eip155:1", 5101), ("personal_sign", "eip155:10", 5100)] {
            let request = json!({"id": 100, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {"request": {"method": method, "params": []}, "chainId": chain}});
            let actions = engine.handle_incoming(&session_topic, &crypto::encrypt_type0(&session_key, &request.to_string()).unwrap());
            let (_, message, _) = &published(&actions)[0];
            assert_eq!(dapp.open(&session_key, message)["error"]["code"], code, "{method} {chain}");
        }

        // Ping, then disconnection by the wallet.
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
        let required = json!({"eip155": {"chains": ["eip155:10"], "methods": ["eth_sendTransaction"], "events": []}});
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

    /// A connected dApp (pairing, proposal, approval): session topic and key.
    fn connect(engine: &mut Engine, pairing_key: [u8; 32], proposal_id: u64) -> (FakeDapp, String, [u8; 32]) {
        let dapp = FakeDapp { pairing_topic: crypto::topic_for_key(&pairing_key), pairing_key, keys: crypto::KeyPair::generate().unwrap(), session_key: None };
        engine.pair(&dapp.uri()).unwrap();
        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["personal_sign"], "events": []}});
        engine.handle_incoming(&dapp.pairing_topic.clone(), &dapp.propose(proposal_id, required, json!({})));
        let pubs = published(&engine.approve(proposal_id, 0, &account()).unwrap());
        let response = dapp.open(&dapp.pairing_key, &pubs[0].1);
        let wallet_public = key_from_hex(response["result"]["responderPublicKey"].as_str().unwrap()).unwrap();
        let key = *crypto::derive_sym_key(&dapp.keys.private, &wallet_public).unwrap();
        (dapp, crypto::topic_for_key(&key), key)
    }

    fn sign_request(key: &[u8; 32], id: u64, expiry: Option<u64>) -> String {
        let mut request = json!({"id": id, "jsonrpc": "2.0", "method": "wc_sessionRequest", "params": {
            "request": {"method": "personal_sign", "params": ["0x48656c6c6f", account().evm]}, "chainId": "eip155:1"}});
        if let Some(expiry) = expiry {
            request["params"]["request"]["expiryTimestamp"] = json!(expiry);
        }
        crypto::encrypt_type0(key, &request.to_string()).unwrap()
    }

    /// Audit round 24: the relay may deliver a message again. A request received twice
    /// does not open a second window and does not get an error; a request ALREADY
    /// handled does not come back as new (a payment confirmed twice), even after a
    /// restart (the history is saved with the state).
    #[test]
    fn redelivered_messages_are_ignored_even_after_a_restart() {
        let mut engine = Engine::new(PersistedState::default()).unwrap();
        let (_, topic, key) = connect(&mut engine, [0x42; 32], 1);
        let message = sign_request(&key, 42, None);
        assert!(!engine.handle_incoming(&topic, &message).is_empty());
        assert!(engine.handle_incoming(&topic, &message).is_empty(), "redélivrée en attente : rien, pas d'erreur");
        assert!(engine.pending_request(42).is_some());
        engine.respond(42, Ok(json!("0xsignature"))).unwrap();
        assert!(engine.handle_incoming(&topic, &message).is_empty(), "redélivrée après la réponse : ignorée");
        assert!(engine.pending_request(42).is_none(), "ne redevient pas une demande en attente");

        let saved = serde_json::to_string(&engine.state).unwrap();
        let mut restarted = Engine::new(serde_json::from_str(&saved).unwrap()).unwrap();
        assert!(restarted.handle_incoming(&topic, &message).is_empty(), "après redémarrage : toujours ignorée");
        assert!(restarted.pending_request(42).is_none());
        let fresh = restarted.handle_incoming(&topic, &sign_request(&key, 43, None));
        assert!(matches!(&fresh[..], [Action::Persist, Action::Emit(WcEvent::Request { id: 43, .. })]), "une vraie nouvelle demande passe");

        // Redelivered proposal: a single window.
        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["personal_sign"], "events": []}});
        let other = FakeDapp { pairing_topic: crypto::topic_for_key(&[0x45; 32]), pairing_key: [0x45; 32], keys: crypto::KeyPair::generate().unwrap(), session_key: None };
        restarted.pair(&other.uri()).unwrap();
        let proposal = other.propose(77, required, json!({}));
        assert!(!restarted.handle_incoming(&other.pairing_topic.clone(), &proposal).is_empty());
        assert!(restarted.handle_incoming(&other.pairing_topic.clone(), &proposal).is_empty());
    }

    /// Audit round 23: a request's identifier is chosen by the dApp. ANOTHER dApp
    /// reusing the identifier of a pending request does not replace it (otherwise it
    /// would receive the signature meant for the first one); the lifetime announced by
    /// the dApp is capped, and the number of pending requests and proposals is bounded.
    #[test]
    fn a_dapp_cannot_take_over_or_flood_pending_requests() {
        let mut engine = Engine::new(PersistedState::default()).unwrap();
        let (_, topic_a, key_a) = connect(&mut engine, [0x42; 32], 1);
        let (dapp_b, topic_b, key_b) = connect(&mut engine, [0x43; 32], 2);

        engine.handle_incoming(&topic_a, &sign_request(&key_a, 500, None));
        let actions = engine.handle_incoming(&topic_b, &sign_request(&key_b, 500, None));
        let (topic, message, _) = &published(&actions)[0];
        assert_eq!(topic, &topic_b);
        assert_eq!(dapp_b.open(&key_b, message)["error"]["code"], DUPLICATE_REQUEST.0);
        assert_eq!(engine.pending_request(500).unwrap().topic, topic_a, "la demande de la 1re dApp reste");

        engine.handle_incoming(&topic_a, &sign_request(&key_a, 501, Some(u64::MAX)));
        assert!(engine.pending_request(501).unwrap().expiry <= now() + MAX_PENDING_LIFETIME);

        // One dApp: at most 8 pending requests, without blocking the others.
        for id in 600..620 {
            engine.handle_incoming(&topic_b, &sign_request(&key_b, id, None));
        }
        let actions = engine.handle_incoming(&topic_b, &sign_request(&key_b, 700, None));
        assert_eq!(dapp_b.open(&key_b, &published(&actions)[0].1)["error"]["code"], TOO_MANY_REQUESTS.0);
        assert!(engine.pending_request(700).is_none());
        assert_eq!(engine.requests.values().filter(|r| r.topic == topic_b).count(), MAX_PENDING_PER_SESSION);
        // Refused for lack of room, it was never shown: redelivered once there is room
        // again, it is accepted (not ignored as "already seen").
        engine.respond(600, Err((5000, "User rejected.".into()))).unwrap();
        engine.handle_incoming(&topic_b, &sign_request(&key_b, 700, None));
        assert!(engine.pending_request(700).is_some());
        engine.handle_incoming(&topic_a, &sign_request(&key_a, 502, None));
        assert!(engine.pending_request(502).is_some(), "la 1re dApp n'est pas bloquée par la 2de");
        // Across all connections: at most 20.
        let mut next_id = 800;
        for key in 0x50..0x54u8 {
            let (_, topic, session_key) = connect(&mut engine, [key; 32], u64::from(key));
            for _ in 0..MAX_PENDING_PER_SESSION {
                engine.handle_incoming(&topic, &sign_request(&session_key, next_id, None));
                next_id += 1;
            }
        }
        assert_eq!(engine.requests.len(), MAX_PENDING_REQUESTS);

        // Proposals: the same identifier on another pairing is ignored; the number is
        // bounded.
        let other = FakeDapp { pairing_topic: crypto::topic_for_key(&[0x44; 32]), pairing_key: [0x44; 32], keys: crypto::KeyPair::generate().unwrap(), session_key: None };
        engine.pair(&other.uri()).unwrap();
        let required = json!({"eip155": {"chains": ["eip155:1"], "methods": ["personal_sign"], "events": []}});
        engine.handle_incoming(&other.pairing_topic.clone(), &other.propose(900, required.clone(), json!({})));
        assert!(engine.handle_incoming(&other.pairing_topic.clone(), &other.propose(900, required.clone(), json!({}))).is_empty());
        for id in 901..920 {
            engine.handle_incoming(&other.pairing_topic.clone(), &other.propose(id, required.clone(), json!({})));
        }
        assert_eq!(engine.proposals.len(), MAX_PENDING_PROPOSALS);
    }
}
