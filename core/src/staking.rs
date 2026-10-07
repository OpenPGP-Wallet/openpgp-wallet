//! Rendements annuels du staking, pour l'affichage seulement (bouton
//! « Staker » à côté du nom des cartes SOL, ETH et Cardano, note de la fenêtre
//! « Convertir ») : Jito (JitoSOL), Lido (stETH), et pour Cardano la moyenne du
//! réseau calculée depuis Koios. Le staking lui-même est vérifié ailleurs
//! avant signature (Jupiter, CoW, sol_stake, cardano) : rien n'est signé ici.
//!
//! API publiques sans clé, en parallèle, 6 s au plus ; aucune donnée de
//! l'utilisateur envoyée.

use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

const LIDO_APR: &str = "https://eth-api.lido.fi/v1/protocol/steth/apr/sma";
const JITO_STATS: &str = "https://kobe.mainnet.jito.network/api/v1/stake_pool_stats";
/// Dernières époques Cardano : mise active et récompenses distribuées.
const KOIOS_EPOCHS: &str = "https://api.koios.rest/api/v1/epoch_info?select=epoch_no,active_stake,total_rewards&order=epoch_no.desc&limit=5";

/// Rendements annuels en pour cent (`None` : source injoignable ou réponse
/// hors des bornes plausibles).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Aprs {
    pub jitosol: Option<f64>,
    pub steth: Option<f64>,
    /// Cardano : moyenne du réseau, avant la part des pools.
    pub ada: Option<f64>,
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

/// Cardano : récompenses de la dernière époque connue (les plus récentes ne
/// sont pas encore calculées) rapportées à la mise active, sur un an (73
/// époques de 5 jours). Constaté le 07/10/2026 : environ 2,1 %.
fn cardano(value: &Value) -> Option<f64> {
    let epoch = value.as_array()?.iter().find(|e| e["total_rewards"].is_string())?;
    let rewards: f64 = epoch["total_rewards"].as_str()?.parse().ok()?;
    let stake: f64 = epoch["active_stake"].as_str()?.parse().ok()?;
    (stake > 0.0).then(|| rewards / stake * 73.0 * 100.0).and_then(plausible)
}

pub fn aprs() -> Aprs {
    std::thread::scope(|scope| {
        let steth = scope.spawn(|| get(LIDO_APR).as_ref().and_then(lido));
        let jitosol = scope.spawn(|| get(JITO_STATS).as_ref().and_then(jito));
        let ada = scope.spawn(|| get(KOIOS_EPOCHS).as_ref().and_then(cardano));
        Aprs { jitosol: jitosol.join().ok().flatten(), steth: steth.join().ok().flatten(), ada: ada.join().ok().flatten() }
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
        // Koios : époques en cours sans récompenses, puis la dernière connue.
        let epochs = json!([
            { "epoch_no": 660, "active_stake": "21266994047499493", "total_rewards": null },
            { "epoch_no": 658, "active_stake": "21320779780311110", "total_rewards": "6201561548026" },
        ]);
        let ada = cardano(&epochs).unwrap();
        assert!((ada - 2.123).abs() < 0.01, "{ada}");
        assert_eq!(cardano(&json!([{ "active_stake": "0", "total_rewards": "5" }])), None);
    }

    /// Réel : les deux sources répondent avec un taux plausible.
    /// `cargo test -- --ignored real_staking_aprs --nocapture`
    #[test]
    #[ignore]
    fn real_staking_aprs() {
        let rates = aprs();
        println!("{rates:?}");
        assert!(rates.jitosol.is_some() && rates.steth.is_some() && rates.ada.is_some());
    }
}
