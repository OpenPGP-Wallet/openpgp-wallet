//! Status of the swap providers, read when "Convert" opens: a service that does not
//! answer is flagged BEFORE the quote (red message in the window) instead of
//! failing further down. Assets halted by THORChain or Maya come from
//! `thorchain_rpc::halted_assets` (the `swap_halts` command); slowness comes from
//! the in-progress swaps the interface tracks.
//!
//! Lightweight requests without a key (except SwapKit, with the app's key), in
//! parallel, 6 s at most each; no user data is sent.

use crate::swap_routes::Protocol;
use crate::thorchain_rpc::{MAYA, THORCHAIN};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Swap possible but degraded (orange).
    Warning,
    /// Swap currently impossible with this provider (red).
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub protocol: Protocol,
    /// Display name: the actual service ("NEAR Intents" for SwapKit...).
    pub provider: &'static str,
    pub severity: Severity,
    /// "unreachable": the service does not answer.
    pub kind: &'static str,
}

/// One check: URL, optional header, expected content.
struct Probe {
    protocol: Protocol,
    provider: &'static str,
    url: &'static str,
    api_key: Option<&'static str>,
    /// Fragment expected in the response (empty: a 200 status is enough).
    expect: &'static str,
}

const PROBES: [Probe; 7] = [
    // Small SOL → USDC quote: the quoting itself answers.
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
    Probe { protocol: Protocol::Moonpay, provider: "MoonPay Trade", url: "https://api-v2.swaps.xyz/api/getChainList", api_key: crate::moonpay_trade::API_KEY, expect: "chainId" },
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

/// Providers that are not answering right now.
pub fn check() -> Vec<Issue> {
    let unreachable = |protocol, provider| Issue { protocol, provider, severity: Severity::Error, kind: "unreachable" };
    std::thread::scope(|scope| {
        let probes: Vec<_> = PROBES
            .iter()
            // SwapKit without a key: not offered, nothing to check.
            .filter(|p| p.protocol != Protocol::Swapkit || crate::swapkit::enabled())
            .filter(|p| p.protocol != Protocol::Moonpay || crate::moonpay_trade::enabled())
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

    /// Real network: every provider answers (otherwise, which one does not).
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

    /// An unreachable provider is flagged (an address that does not answer).
    #[test]
    fn an_unreachable_service_is_reported() {
        let probe = Probe { protocol: Protocol::Cow, provider: "CoW", url: "http://127.0.0.1:9/", api_key: None, expect: "" };
        assert!(!responds(&probe));
    }
}
