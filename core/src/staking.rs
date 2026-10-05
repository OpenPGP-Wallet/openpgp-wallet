//! Staking liquide : rendements annuels annoncés par Jito (JitoSOL) et Lido
//! (stETH), pour la note de la fenêtre « Convertir » (« Staker » sur les
//! cartes SOL et ETH). Le staking lui-même est un échange ordinaire (Jupiter
//! pour SOL → JitoSOL, CoW pour ETH → stETH), déjà vérifié avant signature :
//! rien n'est signé ici, et ces taux ne servent qu'à l'affichage.
//!
//! API publiques sans clé, en parallèle, 6 s au plus ; aucune donnée de
//! l'utilisateur envoyée.

use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

const LIDO_APR: &str = "https://eth-api.lido.fi/v1/protocol/steth/apr/sma";
const JITO_STATS: &str = "https://kobe.mainnet.jito.network/api/v1/stake_pool_stats";

/// Rendements annuels en pour cent (`None` : source injoignable ou réponse
/// hors des bornes plausibles).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Aprs {
    pub jitosol: Option<f64>,
    pub steth: Option<f64>,
}

fn get(url: &str) -> Option<Value> {
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(6)).user_agent("openpgp-wallet").build().ok()?;
    client.get(url).send().ok()?.json().ok()
}

/// Taux plausible (0 à 30 %/an) : jamais un chiffre aberrant affiché.
fn plausible(percent: f64) -> Option<f64> {
    (percent.is_finite() && percent > 0.0 && percent < 30.0).then_some(percent)
}

/// Lido : moyenne mobile sur 7 jours (`smaApr`, déjà en pour cent).
fn lido(value: &Value) -> Option<f64> {
    plausible(value["data"]["smaApr"].as_f64()?)
}

/// Jito : dernier rendement annuel (`apy`, en fraction).
fn jito(value: &Value) -> Option<f64> {
    plausible(value["apy"].as_array()?.last()?["data"].as_f64()? * 100.0)
}

pub fn aprs() -> Aprs {
    std::thread::scope(|scope| {
        let steth = scope.spawn(|| get(LIDO_APR).as_ref().and_then(lido));
        let jitosol = scope.spawn(|| get(JITO_STATS).as_ref().and_then(jito));
        Aprs { jitosol: jitosol.join().ok().flatten(), steth: steth.join().ok().flatten() }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Formes réelles des réponses (05/10/2026) ; valeurs aberrantes écartées.
    #[test]
    fn rates_are_read_and_bounded() {
        assert_eq!(lido(&json!({ "data": { "smaApr": 2.225 } })), Some(2.225));
        assert_eq!(jito(&json!({ "apy": [{ "data": 0.0490 }, { "data": 0.0483 }] })), Some(4.83));
        assert_eq!(lido(&json!({ "data": { "smaApr": 250.0 } })), None);
        assert_eq!(jito(&json!({ "apy": [] })), None);
        assert_eq!(lido(&json!({ "error": "x" })), None);
    }

    /// Réel : les deux sources répondent avec un taux plausible.
    /// `cargo test -- --ignored real_staking_aprs --nocapture`
    #[test]
    #[ignore]
    fn real_staking_aprs() {
        let rates = aprs();
        println!("{rates:?}");
        assert!(rates.jitosol.is_some() && rates.steth.is_some());
    }
}
