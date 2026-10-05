//! État des fournisseurs d'échange, lu à l'ouverture de « Convertir » : un
//! service qui ne répond pas est signalé AVANT le devis (message rouge dans la
//! fenêtre), au lieu d'un échec plus loin. Les suspensions d'une crypto par
//! THORChain ou Maya viennent de `thorchain_rpc::halted_assets` (commande
//! `swap_halts`) ; la lenteur, des échanges en cours suivis par l'interface.
//!
//! Requêtes légères et sans clé (sauf SwapKit, avec la clé de l'app), en
//! parallèle, 6 s au plus chacune ; aucune donnée de l'utilisateur envoyée.

use crate::swap_routes::Protocol;
use crate::thorchain_rpc::{MAYA, THORCHAIN};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Échange possible mais dégradé (orange).
    Warning,
    /// Échange impossible par ce fournisseur pour l'instant (rouge).
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub protocol: Protocol,
    /// Nom affiché : celui du service réel (« NEAR Intents » pour SwapKit…).
    pub provider: &'static str,
    pub severity: Severity,
    /// « unreachable » : le service ne répond pas.
    pub kind: &'static str,
}

/// Une vérification : adresse, en-tête éventuel, contenu attendu.
struct Probe {
    protocol: Protocol,
    provider: &'static str,
    url: &'static str,
    api_key: Option<&'static str>,
    /// Fragment attendu dans la réponse (vide : code 200 suffit).
    expect: &'static str,
}

const PROBES: [Probe; 6] = [
    // Petit devis SOL → USDC : la cotation elle-même répond.
    Probe {
        protocol: Protocol::Jupiter,
        provider: "Jupiter",
        url: "https://lite-api.jup.ag/swap/v1/quote?inputMint=So11111111111111111111111111111111111111112&outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=1000000&slippageBps=50",
        api_key: None,
        expect: "outAmount",
    },
    Probe { protocol: Protocol::Lifi, provider: "LI.FI", url: "https://li.quest/v1/chains?chainTypes=SVM", api_key: None, expect: "chains" },
    Probe { protocol: Protocol::Cow, provider: "CoW", url: "https://api.cow.fi/mainnet/api/v1/version", api_key: None, expect: "" },
    Probe { protocol: Protocol::Swapkit, provider: "SwapKit", url: "https://api.swapkit.dev/providers", api_key: crate::swapkit::API_KEY, expect: "" },
    Probe { protocol: Protocol::Swapkit, provider: "NEAR Intents", url: "https://1click.chaindefuser.com/v0/tokens", api_key: None, expect: "assetId" },
    Probe { protocol: Protocol::Swapkit, provider: "Chainflip", url: "https://chainflip-swap.chainflip.io/healthcheck", api_key: None, expect: "" },
];

fn responds(probe: &Probe) -> bool {
    let Ok(client) = reqwest::blocking::Client::builder().timeout(Duration::from_secs(6)).user_agent("openpgp-wallet").build() else { return false };
    let mut request = client.get(probe.url);
    if let Some(key) = probe.api_key {
        request = request.header("x-api-key", key);
    }
    match request.send() {
        Ok(response) if response.status().is_success() => probe.expect.is_empty() || response.text().is_ok_and(|body| body.contains(probe.expect)),
        _ => false,
    }
}

/// Fournisseurs qui ne répondent pas en ce moment.
pub fn check() -> Vec<Issue> {
    let unreachable = |protocol, provider| Issue { protocol, provider, severity: Severity::Error, kind: "unreachable" };
    std::thread::scope(|scope| {
        let probes: Vec<_> = PROBES
            .iter()
            // SwapKit sans clé : non proposé, rien à vérifier.
            .filter(|p| p.protocol != Protocol::Swapkit || crate::swapkit::enabled())
            .map(|probe| (probe, scope.spawn(move || responds(probe))))
            .collect();
        let thorchain = scope.spawn(|| THORCHAIN.halted_assets().is_ok());
        let maya = scope.spawn(|| MAYA.halted_assets().is_ok());
        let mut issues: Vec<Issue> =
            probes.into_iter().filter_map(|(probe, handle)| (!handle.join().unwrap_or(false)).then(|| unreachable(probe.protocol, probe.provider))).collect();
        if !thorchain.join().unwrap_or(false) {
            issues.push(unreachable(Protocol::Thorchain, "THORChain"));
        }
        if !maya.join().unwrap_or(false) {
            issues.push(unreachable(Protocol::Maya, "Maya"));
        }
        issues
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Réel : tous les fournisseurs répondent (sinon, lequel).
    /// `cargo test -- --ignored real_swap_health --nocapture`
    #[test]
    #[ignore]
    fn real_swap_health() {
        let start = std::time::Instant::now();
        let issues = check();
        println!("{} ms : {issues:?}", start.elapsed().as_millis());
        assert!(issues.is_empty(), "{issues:?}");
        assert!(start.elapsed() < Duration::from_secs(8), "vérifications en parallèle");
    }

    /// Un fournisseur injoignable est signalé (adresse qui ne répond pas).
    #[test]
    fn an_unreachable_service_is_reported() {
        let probe = Probe { protocol: Protocol::Cow, provider: "CoW", url: "http://127.0.0.1:9/", api_key: None, expect: "" };
        assert!(!responds(&probe));
    }
}
