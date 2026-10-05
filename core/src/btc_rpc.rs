use crate::btc_tx::Utxo;
use anyhow::{anyhow, Context, Result};
use reqwest::blocking::{RequestBuilder, Response};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// Voir eth_rpc::shared_client : un `reqwest::Client` reconstruit à chaque appel de
// commande jette son pool de connexions keep-alive et repaie une poignée de main
// TCP+TLS complète à chaque clic. Un seul client partagé, construit une fois.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// API Esplora publique de Blockstream : pas de clé requise, suffisant pour
/// interroger les UTXOs et diffuser une transaction dans ce PoC. Mainnet et
/// testnet sont deux déploiements distincts de la même API, d'où le paramètre
/// `base_url` de `EsploraClient::new` plutôt qu'une constante unique.
pub const ESPLORA_TESTNET_BASE: &str = "https://blockstream.info/testnet/api";
pub const ESPLORA_MAINNET_BASE: &str = "https://blockstream.info/api";

/// Serveurs essayés dans l'ordre : Blockstream, puis mempool.space (même API
/// Esplora). Blockstream limite les requêtes par IP : réponses 429 constatées
/// le 05/10/2026, solde Bitcoin et courbe du portefeuille alors en échec. Un
/// serveur saturé (429), en panne (5xx) ou injoignable passe la main au
/// suivant et reste en retrait `MIRROR_COOLDOWN`.
const MAINNET_MIRRORS: [&str; 2] = [ESPLORA_MAINNET_BASE, "https://mempool.space/api"];
const TESTNET_MIRRORS: [&str; 2] = [ESPLORA_TESTNET_BASE, "https://mempool.space/testnet/api"];
const MIRROR_COOLDOWN: Duration = Duration::from_secs(60);

/// Tous les serveurs ont échoué (saturés, en panne ou injoignables).
pub const BITCOIN_SERVERS_DOWN: &str = "serveurs Bitcoin indisponibles pour l'instant (trop de requêtes ou panne) — réessayez dans une minute";
/// Requête refusée par le serveur (adresse invalide…).
pub const BITCOIN_REQUEST_REFUSED: &str = "requête refusée par le serveur Bitcoin";

/// Serveurs en retrait, jusqu'à quel instant.
fn cooling() -> std::sync::MutexGuard<'static, HashMap<&'static str, Instant>> {
    static COOLING: OnceLock<Mutex<HashMap<&'static str, Instant>>> = OnceLock::new();
    COOLING.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner())
}

pub struct EsploraClient {
    client: reqwest::blocking::Client,
    mirrors: Vec<&'static str>,
}

#[derive(Deserialize)]
struct UtxoJson {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Deserialize)]
struct UtxoStatus {
    confirmed: bool,
}

#[derive(Deserialize)]
struct AddressTxJson {
    txid: String,
    vin: Vec<VinJson>,
    vout: Vec<VoutJson>,
    status: AddressTxStatusJson,
}

#[derive(Deserialize)]
struct VinJson {
    prevout: Option<PrevoutJson>,
}

#[derive(Deserialize)]
struct PrevoutJson {
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize)]
struct VoutJson {
    scriptpubkey_address: Option<String>,
    value: u64,
    #[serde(default)]
    scriptpubkey: String,
}

#[derive(Deserialize)]
struct AddressTxStatusJson {
    confirmed: bool,
    block_time: Option<i64>,
}

#[derive(Deserialize)]
struct TxoStatsJson {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
    tx_count: u64,
}

#[derive(Deserialize)]
struct AddressStatsJson {
    chain_stats: TxoStatsJson,
    mempool_stats: TxoStatsJson,
}

/// Voir `EsploraClient::address_stats`.
pub struct AddressStats {
    /// Transactions confirmées + en mempool touchant l'adresse.
    pub tx_count: u64,
    /// Solde confirmé + mempool, en satoshis.
    pub balance_sat: i128,
    /// Solde confirmé seul, en satoshis.
    pub confirmed_sat: i128,
}

pub struct AddressTx {
    pub txid: String,
    pub confirmed: bool,
    pub block_time: Option<i64>,
    /// Positif si `address` a reçu net, négatif si elle a envoyé net, en satoshis —
    /// calculé à partir des vin/vout déjà fournis par Esplora (pas d'appel
    /// supplémentaire nécessaire, contrairement à Solana où le détail par
    /// transaction demande une requête séparée).
    pub net_sat: i128,
    /// Texte de la première sortie OP_RETURN (memo), s'il y en a une lisible
    /// (ex : memo d'un swap THORChain, voir `history`).
    pub memo: Option<String>,
}

/// Données d'un script OP_RETURN, en texte : `OP_RETURN` suivi d'UNE poussée
/// (directe jusqu'à 75 octets, `OP_PUSHDATA1` ou `OP_PUSHDATA2`) couvrant le
/// reste du script. `None` pour tout autre script ou un texte non UTF-8.
fn op_return_text(script_hex: &str) -> Option<String> {
    let script = hex::decode(script_hex).ok()?;
    let (&opcode, rest) = script.strip_prefix(&[0x6a])?.split_first()?;
    let (len, data) = match opcode {
        1..=75 => (opcode as usize, rest),
        0x4c => (*rest.first()? as usize, &rest[1..]),
        0x4d => (u16::from_le_bytes([*rest.first()?, *rest.get(1)?]) as usize, &rest[2..]),
        _ => return None,
    };
    (data.len() == len).then(|| String::from_utf8(data.to_vec()).ok()).flatten()
}

impl EsploraClient {
    /// `base_url` : `ESPLORA_TESTNET_BASE` ou `ESPLORA_MAINNET_BASE` (voir
    /// `api::has_pending_btc`/`get_btc_balance`/`send_btc` pour le choix selon le
    /// réseau demandé par le frontend).
    pub fn new(base_url: &'static str) -> Self {
        let mirrors = match base_url {
            ESPLORA_MAINNET_BASE => MAINNET_MIRRORS.to_vec(),
            ESPLORA_TESTNET_BASE => TESTNET_MIRRORS.to_vec(),
            other => vec![other],
        };
        Self::with_mirrors(mirrors)
    }

    fn with_mirrors(mirrors: Vec<&'static str>) -> Self {
        Self { client: shared_client().clone(), mirrors }
    }

    /// Ordre d'essai : ceux en retrait en dernier (tri stable : sinon l'ordre
    /// de préférence).
    fn ordered_mirrors(&self) -> Vec<&'static str> {
        let now = Instant::now();
        let cooling = cooling();
        let mut mirrors = self.mirrors.clone();
        mirrors.sort_by_key(|mirror| cooling.get(mirror).is_some_and(|until| *until > now));
        mirrors
    }

    /// Réponse du premier serveur qui répond vraiment : 429, 5xx ou serveur
    /// injoignable, le suivant ; toute autre réponse (succès, 400 d'une
    /// transaction refusée, 404…) est rendue telle quelle, sans autre essai.
    fn request(&self, path: &str, build: impl Fn(&str) -> RequestBuilder) -> Result<Response> {
        for mirror in self.ordered_mirrors() {
            match build(&format!("{mirror}{path}")).send() {
                Ok(response) if response.status() != StatusCode::TOO_MANY_REQUESTS && !response.status().is_server_error() => return Ok(response),
                _ => {
                    cooling().insert(mirror, Instant::now() + MIRROR_COOLDOWN);
                }
            }
        }
        Err(anyhow!(BITCOIN_SERVERS_DOWN))
    }

    /// GET JSON ; `label` nomme l'appel dans l'erreur (sans l'adresse).
    fn get_json<T: DeserializeOwned>(&self, path: &str, label: &str) -> Result<T> {
        let response = self.request(path, |url| self.client.get(url))?;
        anyhow::ensure!(response.status().is_success(), BITCOIN_REQUEST_REFUSED);
        response.json().with_context(|| format!("réponse esplora {label} illisible"))
    }

    /// UTXOs confirmés disponibles pour `address`.
    pub fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        let raw: Vec<UtxoJson> = self.get_json(&format!("/address/{address}/utxo"), "/utxo")?;

        raw.into_iter()
            .filter(|u| u.status.confirmed)
            .map(|u| {
                let bytes = hex::decode(&u.txid).context("txid invalide")?;
                let txid: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow!("txid de taille inattendue"))?;
                Ok(Utxo {
                    txid,
                    vout: u.vout,
                    value_sat: u.value,
                })
            })
            .collect()
    }

    /// `true` si au moins une transaction non confirmée (mempool) touche `address` —
    /// fonds entrants ou sortants pas encore minés. Utilise l'endpoint Esplora dédié
    /// (`/txs/mempool`) plutôt que `address_history` filtré : plus léger, puisqu'il
    /// n'a pas besoin de calculer les montants (vin/vout) de chaque transaction pour
    /// répondre à une simple question oui/non, appelée à chaque rafraîchissement
    /// automatique du solde (voir main.js::refreshBalance).
    pub fn has_mempool_tx(&self, address: &str) -> Result<bool> {
        let raw: Vec<serde_json::Value> = self.get_json(&format!("/address/{address}/txs/mempool"), "/txs/mempool")?;
        Ok(!raw.is_empty())
    }

    /// Historique des transactions (confirmées ou non) touchant `address`, du plus
    /// récent au plus ancien (ordre déjà garanti par Esplora).
    pub fn address_history(&self, address: &str) -> Result<Vec<AddressTx>> {
        self.address_history_after(address, None)
    }

    /// Page d'historique : sans `after`, la première (mempool puis 25
    /// transactions confirmées) ; avec, les 25 transactions confirmées
    /// suivantes, plus anciennes que `after` (`/txs/chain/:dernier_txid_vu`).
    pub fn address_history_after(&self, address: &str, after: Option<&str>) -> Result<Vec<AddressTx>> {
        let path = match after {
            None => format!("/address/{address}/txs"),
            Some(txid) => format!("/address/{address}/txs/chain/{txid}"),
        };
        self.transactions_at(&path, address)
    }

    /// Transactions non confirmées (mempool) touchant `address`.
    pub fn mempool_history(&self, address: &str) -> Result<Vec<AddressTx>> {
        self.transactions_at(&format!("/address/{address}/txs/mempool"), address)
    }

    fn transactions_at(&self, path: &str, address: &str) -> Result<Vec<AddressTx>> {
        let raw: Vec<AddressTxJson> = self.get_json(path, "/txs")?;

        Ok(raw
            .into_iter()
            .map(|tx| {
                let received: i128 = tx
                    .vout
                    .iter()
                    .filter(|o| o.scriptpubkey_address.as_deref() == Some(address))
                    .map(|o| o.value as i128)
                    .sum();
                let sent: i128 = tx
                    .vin
                    .iter()
                    .filter_map(|i| i.prevout.as_ref())
                    .filter(|p| p.scriptpubkey_address.as_deref() == Some(address))
                    .map(|p| p.value as i128)
                    .sum();
                AddressTx {
                    memo: tx.vout.iter().find_map(|o| op_return_text(&o.scriptpubkey)),
                    txid: tx.txid,
                    confirmed: tx.status.confirmed,
                    block_time: tx.status.block_time,
                    net_sat: received - sent,
                }
            })
            .collect())
    }

    /// Nombre total de transactions et solde (confirmé + mempool) de `address` —
    /// un seul appel (`/address/{address}`), sans le détail des transactions.
    /// Sert à prévenir avant un envoi vers une adresse jamais utilisée ou vide
    /// (voir `api::btc_recipient_activity`). Solde calculé en signé : les
    /// dépenses en mempool peuvent dépasser les réceptions en mempool (elles
    /// consomment des sorties déjà confirmées) — constaté sur de vraies adresses.
    pub fn address_stats(&self, address: &str) -> Result<AddressStats> {
        let raw: AddressStatsJson = self.get_json(&format!("/address/{address}"), "/address")?;
        let balance = |s: &TxoStatsJson| i128::from(s.funded_txo_sum) - i128::from(s.spent_txo_sum);
        Ok(AddressStats {
            tx_count: raw.chain_stats.tx_count.saturating_add(raw.mempool_stats.tx_count),
            balance_sat: balance(&raw.chain_stats) + balance(&raw.mempool_stats),
            confirmed_sat: balance(&raw.chain_stats),
        })
    }

    /// Transaction brute `txid` (ordre affiché). Aucune confiance accordée au
    /// serveur : l'appelant recalcule le txid de ce qu'il reçoit (voir
    /// `ledger::btc`, qui refuse toute transaction ne correspondant pas à l'UTXO).
    pub fn raw_transaction(&self, txid: &[u8; 32]) -> Result<Vec<u8>> {
        let resp = self.request(&format!("/tx/{}/hex", hex::encode(txid)), |url| self.client.get(url))?;
        anyhow::ensure!(resp.status().is_success(), "transaction {} introuvable sur esplora", hex::encode(txid));
        hex::decode(resp.text().context("réponse esplora /tx/hex illisible")?.trim()).context("transaction brute esplora invalide")
    }

    /// Diffuse une transaction brute (hex-encodée pour l'API) et renvoie son
    /// txid. Serveur suivant seulement si le premier est saturé, en panne ou
    /// injoignable (une même transaction diffusée deux fois reste une seule
    /// dépense) ; une transaction refusée ne l'est pas ailleurs.
    pub fn broadcast(&self, raw_tx: &[u8]) -> Result<String> {
        let hex_tx = hex::encode(raw_tx);
        let resp = self.request("/tx", |url| self.client.post(url).body(hex_tx.clone()))?;

        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("échec de diffusion de la transaction : {body}"));
        }
        Ok(resp.text().context("réponse esplora /tx illisible")?.trim().to_string())
    }

    /// Tarifs de frais actuels (sat/vByte) par objectif de confirmation (en blocs),
    /// triés par objectif croissant — ex: `[(2, 12.5), (6, 5.0), (144, 1.2)]`. Sert à
    /// proposer un choix rapide/moyen/lent avant l'envoi (voir `api::estimate_btc_fees`).
    /// Frais dictés par le marché sur mainnet (contrairement au testnet, où ils sont
    /// dérisoires) : sans estimation dynamique, une transaction réelle sous-payée
    /// resterait non confirmée indéfiniment. Jamais sous 1 sat/vByte :
    /// mempool.space annonce des tarifs plus bas (0,28 le 05/10/2026), que
    /// des nœuds encore réglés à 1 sat/vByte (peut-être le serveur de
    /// diffusion, pas forcément celui de l'estimation) ne relaieraient pas.
    pub fn fee_estimates(&self) -> Result<Vec<(u32, f64)>> {
        let raw: HashMap<String, f64> = self.get_json("/fee-estimates", "/fee-estimates")?;

        let mut estimates: Vec<(u32, f64)> = raw
            .into_iter()
            .filter_map(|(target, rate)| target.parse::<u32>().ok().map(|t| (t, rate.max(1.0))))
            .collect();
        estimates.sort_by_key(|(target, _)| *target);
        Ok(estimates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Petit serveur HTTP local : répond `status` et `body` à chaque
    /// requête ; compte les requêtes reçues.
    fn local_server(status: &'static str, body: &'static str) -> (&'static str, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url: &'static str = Box::leak(format!("http://{}", listener.local_addr().unwrap()).into_boxed_str());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (url, hits)
    }

    /// Serveur saturé (429) : réponse du suivant, et le saturé passe en
    /// dernier pour les appels suivants.
    #[test]
    fn a_rate_limited_server_hands_over_to_the_next_one() {
        let (busy, busy_hits) = local_server("429 Too Many Requests", "Too Many Requests");
        let (spare, spare_hits) = local_server("200 OK", r#"{"1":12.5,"6":0.3}"#);
        let client = EsploraClient::with_mirrors(vec![busy, spare]);
        assert_eq!(client.fee_estimates().unwrap(), vec![(1, 12.5), (6, 1.0)], "tarif plancher 1 sat/vByte");
        assert_eq!(client.fee_estimates().unwrap().len(), 2);
        assert_eq!(busy_hits.load(Ordering::SeqCst), 1, "en retrait après son 429");
        assert_eq!(spare_hits.load(Ordering::SeqCst), 2);
    }

    /// Requête refusée (400) : pas d'autre essai ailleurs (une transaction
    /// refusée par un nœud l'est par les autres).
    #[test]
    fn a_refusal_is_not_retried_elsewhere() {
        let (refusing, _) = local_server("400 Bad Request", "sendrawtransaction RPC error: bad-txns-inputs-missingorspent");
        let (spare, spare_hits) = local_server("200 OK", "ok");
        let client = EsploraClient::with_mirrors(vec![refusing, spare]);
        let err = client.broadcast(&[0u8; 10]).unwrap_err().to_string();
        assert!(err.contains("bad-txns-inputs-missingorspent"), "{err}");
        assert_eq!(client.address_stats("bc1qtest").err().unwrap().to_string(), BITCOIN_REQUEST_REFUSED);
        assert_eq!(spare_hits.load(Ordering::SeqCst), 0);
    }

    /// Tous saturés ou injoignables : message clair, pas « illisible ».
    #[test]
    fn all_servers_down_gives_a_clear_message() {
        let (busy, _) = local_server("503 Service Unavailable", "");
        let client = EsploraClient::with_mirrors(vec![busy, "http://127.0.0.1:9"]);
        assert_eq!(client.utxos("bc1qtest").err().unwrap().to_string(), BITCOIN_SERVERS_DOWN);
    }

    /// Réel : mempool.space seul lit les mêmes réponses que Blockstream
    /// (solde, historique, UTXO, frais, transaction brute).
    /// `cargo test -- --ignored real_mempool_space_mirror --nocapture`
    #[test]
    #[ignore]
    fn real_mempool_space_mirror() {
        let client = EsploraClient::with_mirrors(vec![MAINNET_MIRRORS[1]]);
        let address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
        let stats = client.address_stats(address).unwrap();
        assert!(stats.tx_count > 0);
        let history = client.address_history(address).unwrap();
        assert!(!history.is_empty());
        let older = client.address_history_after(address, Some(&history.last().unwrap().txid)).unwrap();
        assert!(older.iter().all(|tx| tx.confirmed));
        // UTXO d'une adresse ordinaire (premier destinataire d'une transaction
        // du dernier bloc) : mempool.space refuse la liste au-delà de 500 UTXO
        // (400 « Too many unspent transaction outputs »), cas de `address`.
        let tip = reqwest::blocking::get(format!("{}/blocks/tip/hash", MAINNET_MIRRORS[1])).unwrap().text().unwrap();
        let block: serde_json::Value = reqwest::blocking::get(format!("{}/block/{tip}/txs", MAINNET_MIRRORS[1])).unwrap().json().unwrap();
        let ordinary = block[1]["vout"][0]["scriptpubkey_address"].as_str().unwrap().to_string();
        let utxos = client.utxos(&ordinary).unwrap();
        assert!(client.utxos(address).is_err(), "plus de 500 UTXO : refusé");
        let fees = client.fee_estimates().unwrap();
        assert!(fees.iter().all(|(_, rate)| *rate >= 1.0));
        let txid: [u8; 32] = hex::decode(&history.last().unwrap().txid).unwrap().try_into().unwrap();
        assert!(!client.raw_transaction(&txid).unwrap().is_empty());
        let testnet = EsploraClient::with_mirrors(vec![TESTNET_MIRRORS[1]]);
        assert!(testnet.fee_estimates().is_ok());
        println!("{} tx, {} dans la 1re page, {} plus anciennes, {} UTXO, frais {:?}", stats.tx_count, history.len(), older.len(), utxos.len(), &fees[..3.min(fees.len())]);
    }

    /// Scripts OP_RETURN de vraies transactions THORChain du réseau principal
    /// (lues sur Esplora) : poussée directe (e8bf29df…), `OP_PUSHDATA1`
    /// (990fb6f4…), paiement sortant « OUT: » (909686b5…).
    #[test]
    fn op_return_memos_of_real_transactions_are_read() {
        assert_eq!(
            op_return_text("6a423d3a783a72444466356e47696d3352514e4475536150626d79727848714448676f796e6876563a3435363632313837373830302f302f303a2d5f2f74313a302f3730").as_deref(),
            Some("=:x:rDDf5nGim3RQNDuSaPbmyrxHqDHgoynhvV:456621877800/0/0:-_/t1:0/70")
        );
        assert_eq!(
            op_return_text("6a4c503d3a4554482e555344433a3078643139303266363632613239326362393634614231334546354661344630343541633235386138323a32343438333135303430302f302f303a2d5f2f74313a302f3730").as_deref(),
            Some("=:ETH.USDC:0xd1902f662a292cb964aB13EF5Fa4F045Ac258a82:24483150400/0/0:-_/t1:0/70")
        );
        assert_eq!(
            op_return_text("6a444f55543a32363430324233373338463143463934423431454630423739343645463141423734464239354145463045374137443345423945443636433833443236313636").as_deref(),
            Some("OUT:26402B3738F1CF94B41EF0B7946EF1AB74FB95AEF0E7A7D3EB9ED66C83D26166")
        );
        // Pas un OP_RETURN, longueur incohérente, texte non UTF-8, script vide.
        for bad in ["0014751e76e8199196d454941c45d1b3a323f1433bd6", "6a05616263", "6a02ffff", "", "zz"] {
            assert_eq!(op_return_text(bad), None, "{bad}");
        }
    }
}
