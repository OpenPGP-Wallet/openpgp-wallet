//! WalletConnect v2 (Reown), côté PORTEFEUILLE, implémenté en Rust : permet à
//! une dApp (site web) de demander des signatures à ce portefeuille, via un
//! relais chiffré de bout en bout. Choix de l'utilisateur plutôt que le SDK
//! JavaScript officiel : aucune dépendance npm dans la webview où le mot de
//! passe est saisi, CSP inchangée, et toute la cryptographie reste en Rust.
//!
//! Référence : le code du SDK officiel (monorepo `WalletConnect/walletconnect-
//! monorepo`, branche v2.0, et `walletconnect-utils`), lu directement plutôt
//! que supposé ; chaque primitive est vérifiée contre des vecteurs produits par
//! les bibliothèques mêmes de ce SDK.
//!
//! Aucune fonction de ce module ne signe quoi que ce soit : il transporte les
//! demandes des dApps et renvoie les réponses. Les signatures passent par
//! `api::sign_dapp_request` (mot de passe exigé) et la boîte native de l'app.

pub mod auth;
pub mod crypto;
pub mod engine;
mod relay;
pub mod uri;

use anyhow::{anyhow, Context, Result};
use engine::{Action, Engine, PendingRequest, PersistedState, Session, WcEvent};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard};

/// Identifiant du projet chez Reown (dashboard.reown.com), exigé par le relais
/// pour toute connexion. Public par nature (inclus dans l'app, comme dans
/// toute dApp) : ce n'est pas un secret. Projet de type « WalletKit ».
pub const PROJECT_ID: &str = "b40fbfec04c3137a8f14a25edd9905e6";

const STATE_FILE: &str = "walletconnect.json";

pub type EventSink = Arc<dyn Fn(WcEvent) + Send + Sync>;

pub(crate) struct Inner {
    engine: Mutex<Engine>,
    data_dir: PathBuf,
    events: EventSink,
}

impl Inner {
    fn engine(&self) -> MutexGuard<'_, Engine> {
        self.engine.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn emit(&self, event: WcEvent) {
        (self.events)(event);
    }

    /// Exécute sur place ce qui est local (sauvegarde, événements pour
    /// l'interface) et renvoie les actions réseau, pour le fil du relais. Le
    /// moteur n'est jamais verrouillé pendant l'appel des événements.
    fn apply_local(&self, actions: Vec<Action>) -> Vec<Action> {
        let mut network = Vec::new();
        for action in actions {
            match action {
                Action::Persist => {
                    let _ = self.save();
                }
                Action::Emit(event) => self.emit(event),
                other => network.push(other),
            }
        }
        network
    }

    /// Écriture atomique (fichier temporaire puis renommage) : une coupure en
    /// pleine écriture ne laisse jamais un fichier tronqué.
    fn save(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.engine().state).context("sérialisation de l'état WalletConnect")?;
        let tmp = self.data_dir.join(format!("{STATE_FILE}.tmp"));
        std::fs::write(&tmp, content).context("écriture de l'état WalletConnect")?;
        std::fs::rename(&tmp, self.data_dir.join(STATE_FILE)).context("écriture de l'état WalletConnect")
    }
}

/// Session telle qu'affichée (sans aucune clé).
#[derive(serde::Serialize, Clone)]
pub struct SessionView {
    pub topic: String,
    pub peer: engine::PeerMetadata,
    pub chains: Vec<String>,
    pub profile_index: u32,
    pub expiry: u64,
}

pub struct WalletConnect {
    inner: Arc<Inner>,
    commands: Mutex<Sender<Action>>,
}

impl WalletConnect {
    /// Charge l'état enregistré et démarre le fil du relais (qui ne se
    /// connecte que s'il y a un canal à écouter).
    pub fn start(data_dir: &Path, events: EventSink) -> Result<Self> {
        let state: PersistedState = std::fs::read_to_string(data_dir.join(STATE_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let inner = Arc::new(Inner { engine: Mutex::new(Engine::new(state)?), data_dir: data_dir.to_path_buf(), events });
        inner.save()?;
        let (tx, rx) = mpsc::channel();
        let relay_inner = inner.clone();
        std::thread::Builder::new()
            .name("walletconnect-relay".into())
            .spawn(move || relay::run(relay_inner, rx))
            .context("démarrage du fil WalletConnect impossible")?;
        Ok(Self { inner, commands: Mutex::new(tx) })
    }

    fn dispatch(&self, actions: Vec<Action>) {
        let network = self.inner.apply_local(actions);
        let commands = self.commands.lock().unwrap_or_else(|p| p.into_inner());
        for action in network {
            let _ = commands.send(action);
        }
    }

    pub fn pair(&self, uri: &str) -> Result<()> {
        anyhow::ensure!(
            !PROJECT_ID.is_empty(),
            "WalletConnect n'est pas encore configuré : le Project ID (dashboard.reown.com) n'a pas été renseigné"
        );
        let actions = self.inner.engine().pair(uri)?;
        self.dispatch(actions);
        Ok(())
    }

    pub fn approve(&self, proposal_id: u64, profile_index: u32, account: &crate::dapp_requests::Account) -> Result<()> {
        let actions = self.inner.engine().approve(proposal_id, profile_index, account)?;
        self.dispatch(actions);
        Ok(())
    }

    pub fn reject(&self, proposal_id: u64) -> Result<()> {
        let actions = self.inner.engine().reject(proposal_id)?;
        self.dispatch(actions);
        Ok(())
    }

    pub fn respond(&self, request_id: u64, result: std::result::Result<serde_json::Value, (i64, String)>) -> Result<()> {
        let actions = self.inner.engine().respond(request_id, result)?;
        self.dispatch(actions);
        Ok(())
    }

    pub fn disconnect(&self, topic: &str) -> Result<()> {
        let actions = self.inner.engine().disconnect(topic)?;
        self.dispatch(actions);
        Ok(())
    }

    /// Déconnecte toutes les sessions (réinitialisation du portefeuille).
    pub fn disconnect_all(&self) {
        let topics: Vec<String> = self.inner.engine().sessions().iter().map(|s| s.topic.clone()).collect();
        for topic in topics {
            let _ = self.disconnect(&topic);
        }
    }

    pub fn sessions(&self) -> Vec<SessionView> {
        self.inner
            .engine()
            .sessions()
            .iter()
            .map(|s| SessionView { topic: s.topic.clone(), peer: s.peer.clone(), chains: s.chains(), profile_index: s.profile_index, expiry: s.expiry })
            .collect()
    }

    pub fn session(&self, topic: &str) -> Option<Session> {
        self.inner.engine().session(topic).cloned()
    }

    pub fn pending_request(&self, id: u64) -> Option<PendingRequest> {
        self.inner.engine().pending_request(id).cloned()
    }

    pub fn proposal_peer(&self, id: u64) -> Result<engine::PeerMetadata> {
        self.inner.engine().proposal(id).map(|p| p.peer.clone()).ok_or_else(|| anyhow!("proposition de connexion introuvable ou expirée"))
    }
}
