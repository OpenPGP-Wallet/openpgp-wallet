//! Transport to the WalletConnect relay: a WebSocket connection (TLS) held by a
//! dedicated thread, which runs the engine's `Action`s and hands it the received
//! messages. The relay's JSON-RPC methods come from the official SDK
//! (`relay-api/src/jsonrpc.ts`, "irn" protocol): `irn_subscribe`,
//! `irn_unsubscribe`, `irn_publish`, `irn_batchFetchMessages`, and incoming
//! `irn_subscription` messages, to be acknowledged with `true`.
//!
//! The connection is only open when there is a channel to listen to (a pasted link
//! or an active session) and closed otherwise; it reconnects with a growing delay
//! and resubscribes to every known channel.

use super::engine::{payload_id, Action, WcEvent};
use super::{auth, Inner};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

pub const RELAY_URL: &str = "wss://relay.walletconnect.org";
const RELAY_HOST: &str = "relay.walletconnect.org";
const HEARTBEAT: Duration = Duration::from_secs(30);
const MAX_BACKOFF_SECS: u64 = 60;
/// Beyond this, actions queued during an outage are dropped (protocol messages
/// expire within minutes anyway).
const MAX_QUEUED: usize = 200;

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

fn connect(project_id: &str, client_seed: &[u8; 32]) -> Result<Socket> {
    let mut sub = [0u8; 32];
    getrandom::getrandom(&mut sub).map_err(|e| anyhow!("génération d'aléa impossible : {e}"))?;
    let jwt = auth::sign_jwt(client_seed, &hex::encode(sub), RELAY_URL, super::engine::now());
    let url = format!("{RELAY_URL}/?auth={jwt}&ua=wc-2/rust-0.1/windows/openpgp-wallet&projectId={project_id}");

    let address = (RELAY_HOST, 443)
        .to_socket_addrs()
        .context("relais WalletConnect injoignable (DNS)")?
        .next()
        .ok_or_else(|| anyhow!("relais WalletConnect injoignable (DNS)"))?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10)).context("relais WalletConnect injoignable")?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let (mut socket, _) = tungstenite::client_tls(url, tcp).map_err(|e| match e {
        tungstenite::HandshakeError::Failure(tungstenite::Error::Http(response)) => {
            let status = response.status().as_u16();
            if matches!(status, 401 | 403) {
                anyhow!("le relais WalletConnect refuse le Project ID (HTTP {status}) : vérifiez-le sur dashboard.reown.com")
            } else {
                anyhow!("le relais WalletConnect a refusé la connexion (HTTP {status})")
            }
        }
        other => anyhow!("connexion au relais WalletConnect impossible : {other}"),
    })?;
    // Short read: the same thread also has to send the queued actions.
    match socket.get_mut() {
        MaybeTlsStream::NativeTls(tls) => tls.get_ref().set_read_timeout(Some(Duration::from_millis(200)))?,
        MaybeTlsStream::Plain(tcp) => tcp.set_read_timeout(Some(Duration::from_millis(200)))?,
        _ => {}
    }
    Ok(socket)
}

/// State specific to ONE connection: confirmed subscriptions (channel ->
/// subscription ID, needed to unsubscribe) and in-flight requests.
#[derive(Default)]
struct Connection {
    subscriptions: HashMap<String, String>,
    in_flight: HashMap<u64, (String, String)>,
}

impl Connection {
    fn request(&mut self, socket: &mut Socket, method: &str, params: Value, topic: &str) -> Result<()> {
        let id = payload_id();
        self.in_flight.insert(id, (method.to_string(), topic.to_string()));
        socket.send(Message::text(json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params}).to_string()))?;
        Ok(())
    }

    fn execute(&mut self, socket: &mut Socket, action: &Action) -> Result<()> {
        match action {
            Action::Subscribe(topic) => self.request(socket, "irn_subscribe", json!({"topic": topic}), topic),
            Action::Unsubscribe(topic) => match self.subscriptions.remove(topic) {
                Some(id) => self.request(socket, "irn_unsubscribe", json!({"topic": topic, "id": id}), topic),
                None => Ok(()),
            },
            Action::FetchMessages(topic) => self.request(socket, "irn_batchFetchMessages", json!({"topics": [topic]}), topic),
            Action::Publish { topic, message, ttl, tag, prompt } => self.request(
                socket,
                "irn_publish",
                json!({"topic": topic, "message": message, "ttl": ttl, "tag": tag, "prompt": prompt}),
                topic,
            ),
            Action::Emit(_) | Action::Persist => Ok(()),
        }
    }
}

/// Text received from the relay: a channel message (acknowledged, then handed to
/// the engine), fetched pending messages, or the answer to one of our requests.
/// Returns the network actions the engine produced, to send next.
fn on_text(inner: &Inner, conn: &mut Connection, socket: &mut Socket, text: &str) -> Vec<Action> {
    let Ok(payload) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let mut deliveries: Vec<(String, String)> = Vec::new();
    if payload.get("method").and_then(Value::as_str) == Some("irn_subscription") {
        if let Some(id) = payload.get("id") {
            let _ = socket.send(Message::text(json!({"id": id, "jsonrpc": "2.0", "result": true}).to_string()));
        }
        if let (Some(topic), Some(message)) = (
            payload.pointer("/params/data/topic").and_then(Value::as_str),
            payload.pointer("/params/data/message").and_then(Value::as_str),
        ) {
            deliveries.push((topic.to_string(), message.to_string()));
        }
    } else if let Some(id) = payload.get("id").and_then(Value::as_u64) {
        let Some((method, topic)) = conn.in_flight.remove(&id) else { return Vec::new() };
        if let Some(error) = payload.get("error") {
            inner.emit(WcEvent::RelayStatus { connected: true, error: Some(format!("relais : échec de {method} ({error})")) });
            return Vec::new();
        }
        match method.as_str() {
            "irn_subscribe" => {
                if let Some(sub_id) = payload.get("result").and_then(Value::as_str) {
                    conn.subscriptions.insert(topic, sub_id.to_string());
                }
            }
            "irn_batchFetchMessages" => {
                for m in payload.pointer("/result/messages").and_then(Value::as_array).cloned().unwrap_or_default() {
                    if let (Some(t), Some(msg)) = (m.get("topic").and_then(Value::as_str), m.get("message").and_then(Value::as_str)) {
                        deliveries.push((t.to_string(), msg.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    let mut network = Vec::new();
    for (topic, message) in deliveries {
        let actions = inner.engine().handle_incoming(&topic, &message);
        network.extend(inner.apply_local(actions));
    }
    network
}

#[cfg(test)]
mod tests {
    /// Real relay without a valid Project ID: the TLS connection and the WebSocket
    /// handshake (JWT included) must get as far as the HTTP refusal of the Project ID,
    /// and that refusal must be turned into a clear message.
    /// `cargo test -- --ignored relay_refuses_a_missing_project_id --nocapture`
    #[test]
    #[ignore]
    fn relay_refuses_a_missing_project_id() {
        for project_id in ["", "00000000000000000000000000000000"] {
            let err = super::connect(project_id, &[7u8; 32]).err().expect("refus attendu");
            println!("Project ID « {project_id} » : {err:#}");
            assert!(err.to_string().contains("HTTP"), "{err:#}");
        }
    }
}

pub(super) fn run(inner: Arc<Inner>, commands: Receiver<Action>) {
    let mut queue: VecDeque<Action> = VecDeque::new();
    let mut backoff = 1u64;
    loop {
        // Nothing to listen to: no connection, wait for a command.
        if inner.engine().topics().is_empty() && queue.is_empty() {
            match commands.recv_timeout(Duration::from_secs(5)) {
                Ok(action) => queue.push_back(action),
                Err(RecvTimeoutError::Timeout) => {
                    let actions = inner.engine().drop_expired();
                    queue.extend(inner.apply_local(actions));
                }
                Err(RecvTimeoutError::Disconnected) => return,
            }
            continue;
        }
        let seed = match inner.engine().client_seed() {
            Ok(seed) => seed,
            Err(e) => {
                inner.emit(WcEvent::RelayStatus { connected: false, error: Some(format!("{e:#}")) });
                return;
            }
        };
        let mut socket = match connect(super::PROJECT_ID, &seed) {
            Ok(socket) => socket,
            Err(e) => {
                inner.emit(WcEvent::RelayStatus { connected: false, error: Some(format!("{e:#}")) });
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(MAX_BACKOFF_SECS);
                while let Ok(action) = commands.try_recv() {
                    queue.push_back(action);
                }
                while queue.len() > MAX_QUEUED {
                    queue.pop_front();
                }
                continue;
            }
        };
        backoff = 1;
        inner.emit(WcEvent::RelayStatus { connected: true, error: None });

        let mut conn = Connection::default();
        let (topics, pairings) = {
            let engine = inner.engine();
            (engine.topics(), engine.state.pairings.iter().map(|p| p.topic.clone()).collect::<Vec<_>>())
        };
        // Resubscribe to everything known (subscriptions do not survive the connection);
        // fetch the pending messages of pairings.
        let mut outgoing: VecDeque<Action> = topics.into_iter().map(Action::Subscribe).collect();
        outgoing.extend(pairings.into_iter().map(Action::FetchMessages));
        outgoing.append(&mut queue);

        let mut last_ping = Instant::now();
        let mut last_cleanup = Instant::now();
        let mut broken = false;
        while !broken {
            while let Some(action) = outgoing.pop_front().or_else(|| commands.try_recv().ok()) {
                if conn.execute(&mut socket, &action).is_err() {
                    queue.push_back(action);
                    broken = true;
                    break;
                }
            }
            if broken {
                break;
            }
            match socket.read() {
                Ok(Message::Text(text)) => outgoing.extend(on_text(&inner, &mut conn, &mut socket, text.as_str())),
                Ok(Message::Close(_)) => broken = true,
                Ok(_) => {}
                Err(tungstenite::Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => broken = true,
            }
            if last_ping.elapsed() >= HEARTBEAT {
                broken = socket.send(Message::Ping(Vec::new().into())).is_err();
                last_ping = Instant::now();
            }
            if last_cleanup.elapsed() >= Duration::from_secs(60) {
                let actions = inner.engine().drop_expired();
                outgoing.extend(inner.apply_local(actions));
                last_cleanup = Instant::now();
            }
            // Nothing left to listen to: close cleanly.
            if outgoing.is_empty() && inner.engine().topics().is_empty() {
                let _ = socket.close(None);
                break;
            }
        }
        inner.emit(WcEvent::RelayStatus { connected: false, error: None });
        queue.extend(outgoing);
    }
}
