use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Limits of the public Solana nodes, per IP address, over a 10 s window. The
/// documentation announces 40 requests per method, but the node grants far fewer
/// for some of them, and says so in its headers (`x-ratelimit-method-limit`: 10 for
/// `getTransaction`, measured); refused requests count too. Hence: a per-method
/// pace learned from the headers (cautious while unknown), a global limit, and
/// after a refusal, no more sends of that method for the requested delay
/// (`Retry-After`). Without this, a chart that reads the history of several
/// addresses (one `getTransaction` request per transaction) failed entirely.
const RATE_WINDOW: Duration = Duration::from_secs(10);
/// Per method, until the node has announced its limit.
const DEFAULT_METHOD_CAP: usize = 9;
const MAX_PER_ENDPOINT: usize = 80;
/// Delay after a refusal when the node does not specify one.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(10);
/// Retries after a refusal, each after the requested delay.
const MAX_RETRIES: u32 = 4;
pub const RATE_LIMITED_ERROR: &str = "le nœud Solana public limite le nombre de requêtes : réessayez dans un instant";
/// Details of finalized transactions are kept (in memory and, if the app configured
/// it, on disk): they never change.
const DETAILS_CACHE_MAX: usize = 20_000;

/// Recent sends of a method and its known limit.
#[derive(Default)]
struct MethodWindow {
    sent: VecDeque<Instant>,
    /// Limit announced by the node, minus a margin.
    cap: Option<usize>,
    /// Refusal received: no sends before this time.
    blocked_until: Option<Instant>,
}

/// Recent sends to a node, in total and per method.
#[derive(Default)]
struct RateWindow {
    all: VecDeque<Instant>,
    per_method: HashMap<String, MethodWindow>,
}

impl RateWindow {
    /// Records a send at `now` if it is allowed; otherwise returns the delay before it
    /// will be.
    fn try_acquire(&mut self, method: &str, now: Instant) -> Option<Duration> {
        let expire = |queue: &mut VecDeque<Instant>| {
            while queue.front().is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW) {
                queue.pop_front();
            }
        };
        let wait = |queue: &VecDeque<Instant>, cap: usize| {
            (queue.len() >= cap).then(|| (queue[queue.len() - cap] + RATE_WINDOW).saturating_duration_since(now))
        };
        expire(&mut self.all);
        let window = self.per_method.entry(method.to_string()).or_default();
        expire(&mut window.sent);
        let blocked = window.blocked_until.filter(|until| *until > now).map(|until| until - now);
        let delay = wait(&self.all, MAX_PER_ENDPOINT).max(wait(&window.sent, window.cap.unwrap_or(DEFAULT_METHOD_CAP))).max(blocked);
        if delay.is_none() {
            self.all.push_back(now);
            window.sent.push_back(now);
        }
        delay
    }

    /// Limit announced by the node for `method` (minus one as a margin), and any
    /// refusal.
    fn record(&mut self, method: &str, announced_limit: Option<usize>, refused_for: Option<Duration>, now: Instant) {
        let window = self.per_method.entry(method.to_string()).or_default();
        if let Some(limit) = announced_limit {
            window.cap = Some(limit.saturating_sub(1).max(1));
        }
        if let Some(delay) = refused_for {
            window.blocked_until = Some(now + delay);
        }
    }
}

fn rate_windows() -> &'static Mutex<HashMap<String, RateWindow>> {
    static WINDOWS: OnceLock<Mutex<HashMap<String, RateWindow>>> = OnceLock::new();
    WINDOWS.get_or_init(Default::default)
}

/// Waits until a send of `method` to `endpoint` is allowed.
fn wait_for_slot(endpoint: &str, method: &str) {
    loop {
        let delay =
            rate_windows().lock().unwrap_or_else(|p| p.into_inner()).entry(endpoint.to_string()).or_default().try_acquire(method, Instant::now());
        match delay {
            None => return,
            Some(delay) => std::thread::sleep(delay.max(Duration::from_millis(10))),
        }
    }
}

/// Trimmed details of finalized transactions (see `compact_transaction`), by
/// signature, and the file where they are kept from one session to the next.
#[derive(Default)]
struct DetailsCache {
    entries: HashMap<String, Arc<Value>>,
    file: Option<PathBuf>,
    loaded: bool,
}

impl DetailsCache {
    /// Rereads the file on first use. An unreadable line (interrupted write) is
    /// skipped: this is only a cache of public data.
    fn ensure_loaded(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let Some(file) = self.file.as_ref().and_then(|path| std::fs::File::open(path).ok()) else { return };
        for line in std::io::BufReader::new(file).lines().map_while(std::result::Result::ok) {
            let Ok(entry) = serde_json::from_str::<Value>(&line) else { continue };
            if let (Some(signature), Some(detail)) = (entry.get("s").and_then(Value::as_str), entry.get("t")) {
                if self.entries.len() < DETAILS_CACHE_MAX {
                    self.entries.insert(signature.to_string(), Arc::new(detail.clone()));
                }
            }
        }
    }

    /// Adds details (in memory, then at the end of the file).
    fn insert(&mut self, new: Vec<(String, Arc<Value>)>) {
        let mut lines = String::new();
        for (signature, detail) in new {
            if self.entries.len() >= DETAILS_CACHE_MAX || self.entries.contains_key(&signature) {
                continue;
            }
            lines.push_str(&json!({"s": signature, "t": detail.as_ref()}).to_string());
            lines.push('\n');
            self.entries.insert(signature, detail);
        }
        if let (false, Some(path)) = (lines.is_empty(), self.file.as_ref()) {
            let written = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| f.write_all(lines.as_bytes()));
            if let Err(e) = written {
                eprintln!("cache des transactions Solana non écrit : {e}");
            }
        }
    }
}

fn details_cache() -> &'static Mutex<DetailsCache> {
    static CACHE: OnceLock<Mutex<DetailsCache>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Keeps the details of finalized transactions in `path` (the app's folder): the
/// history of an address already read is no longer requested from the public node,
/// which only grants about one per second. Public chain data (amounts, accounts,
/// memos), no keys.
pub fn use_details_cache_file(path: PathBuf) {
    let mut cache = details_cache().lock().unwrap_or_else(|p| p.into_inner());
    cache.file = Some(path);
    cache.loaded = false;
}

pub struct SolRpc {
    endpoint: String,
    client: reqwest::blocking::Client,
}

// See eth_rpc::shared_client: a `reqwest::Client` rebuilt on every command call
// throws away its pool of keep-alive connections and pays for a full TCP+TLS
// handshake on every click. One shared client, built once.
fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            // Without an explicit timeout, reqwest waits forever for a node that never
            // answers, blocking the whole app on that call.
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

impl SolRpc {
    /// `endpoint`: JSON-RPC URL of the target cluster (devnet or mainnet-beta, see
    /// wallet_flow::SOLANA_DEVNET / SOLANA_MAINNET).
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: shared_client().clone(),
        }
    }

    pub(crate) fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut attempt = 0;
        let resp: Value = loop {
            wait_for_slot(&self.endpoint, method);
            let response = self.client.post(&self.endpoint).json(&body).send().with_context(|| format!("appel RPC {method} impossible"))?;
            let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<u64>().ok());
            let announced_limit = header("x-ratelimit-method-limit").map(|limit| limit as usize);
            let retry_after = header("retry-after").map(Duration::from_secs);
            let too_many = response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS;
            let parsed: Result<Value> = response.json().with_context(|| format!("réponse RPC {method} illisible"));
            let too_many = too_many || parsed.as_ref().ok().and_then(|r| r.pointer("/error/code")).and_then(Value::as_i64) == Some(429);
            let refused_for = too_many.then(|| retry_after.unwrap_or(DEFAULT_RETRY_AFTER).min(Duration::from_secs(30)));
            rate_windows().lock().unwrap_or_else(|p| p.into_inner()).entry(self.endpoint.clone()).or_default().record(
                method,
                announced_limit,
                refused_for,
                Instant::now(),
            );
            if !too_many {
                break parsed?;
            }
            if attempt == MAX_RETRIES {
                return Err(anyhow!(RATE_LIMITED_ERROR));
            }
            attempt += 1;
        };

        if let Some(err) = resp.get("error") {
            return Err(anyhow!("erreur RPC {method} : {err}"));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("réponse RPC {method} sans champ 'result'"))
    }

    /// Balance in lamports (1 SOL = 1_000_000_000 lamports), at the "confirmed" level
    /// (~1 s after a transaction) rather than "finalized", the node's default (~13 s
    /// behind): a send or receipt shows up straight away, as live monitoring
    /// (`balance_watch`) reports it.
    pub fn balance_lamports(&self, pubkey_b58: &str) -> Result<u64> {
        let result = self.call("getBalance", json!([pubkey_b58, {"commitment": "confirmed"}]))?;
        result
            .get("value")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("réponse getBalance inattendue"))
    }

    pub fn latest_blockhash(&self) -> Result<[u8; 32]> {
        let result = self.call("getLatestBlockhash", json!([{"commitment": "finalized"}]))?;
        let blockhash_str = result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("réponse getLatestBlockhash inattendue"))?;
        let bytes = bs58::decode(blockhash_str)
            .into_vec()
            .context("blockhash base58 invalide")?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("blockhash de taille inattendue"))
    }

    /// Requests a devnet airdrop (may fail if the built-in faucet is rate-limited; in
    /// that case, use https://faucet.solana.com manually).
    pub fn request_airdrop(&self, pubkey_b58: &str, lamports: u64) -> Result<String> {
        let result = self.call("requestAirdrop", json!([pubkey_b58, lamports]))?;
        result
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow!("réponse requestAirdrop inattendue"))
    }

    /// Broadcasts a signed transaction and returns its signature (identifier, read from
    /// the transaction). A flat refusal from the node (preflight simulation, rate
    /// limit) means nothing went out. Without a clear answer: "maybe sent" (see
    /// `wallet_flow::maybe_sent`). Already processed: it is the same transaction.
    pub fn send_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        // First signature, after the count (one byte: fewer than 128).
        let signature = raw_tx.get(1..65).filter(|_| raw_tx.first().is_some_and(|n| (1..128).contains(n))).map(|s| bs58::encode(s).into_string()).context("transaction Solana sans signature")?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_tx);
        match self.call("sendTransaction", json!([b64, {"encoding": "base64"}])) {
            Ok(result) => result.as_str().map(String::from).ok_or_else(|| crate::wallet_flow::maybe_sent(&signature)),
            Err(e) => {
                let text = e.to_string();
                if text.contains("\"BlockhashNotFound\"") {
                    Err(anyhow!(BLOCKHASH_EXPIRED_ERROR))
                } else if text.contains("AlreadyProcessed") || text.contains("already been processed") {
                    Ok(signature)
                } else if text.starts_with("erreur RPC sendTransaction")
                    || text == RATE_LIMITED_ERROR
                    || e.chain().find_map(|c| c.downcast_ref::<reqwest::Error>()).is_some_and(crate::wallet_flow::nothing_sent)
                {
                    // Flat refusal from the node, rate limit exceeded, or connection never established:
                    // nothing went out.
                    Err(e)
                } else {
                    Err(crate::wallet_flow::maybe_sent(&signature))
                }
            }
        }
    }

    /// Raw state (lamports, owner program, data) of several accounts at once, `None`
    /// for an account that does not exist. At most 100 per call (the
    /// `getMultipleAccounts` limit), split into batches here.
    pub fn multiple_accounts(&self, pubkeys: &[String]) -> Result<Vec<Option<AccountState>>> {
        let mut states = Vec::with_capacity(pubkeys.len());
        for chunk in pubkeys.chunks(100) {
            let result = self.call("getMultipleAccounts", json!([chunk, {"encoding": "base64"}]))?;
            let values = result
                .get("value")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("réponse getMultipleAccounts inattendue"))?;
            anyhow::ensure!(values.len() == chunk.len(), "réponse getMultipleAccounts incomplète");
            for value in values {
                states.push(AccountState::from_rpc_value(value)?);
            }
        }
        Ok(states)
    }

    /// Like `simulate_transaction`, but also returns the state of `addresses` AFTER the
    /// simulation (the `accounts` config of `simulateTransaction`). This makes it
    /// possible to check what a transaction built by a third party would actually do to
    /// the user's accounts, instead of trusting it (see `api::verify_swap_effects`).
    /// The simulation is run by THIS RPC node, a party independent of the one that
    /// built the transaction (Jupiter).
    pub fn simulate_with_account_states(&self, raw_tx: &[u8], addresses: &[String]) -> Result<SimulationOutcome> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_tx);
        let result = self.call(
            "simulateTransaction",
            json!([b64, {
                "encoding": "base64",
                "replaceRecentBlockhash": true,
                "sigVerify": false,
                "accounts": {"encoding": "base64", "addresses": addresses},
            }]),
        )?;
        let err = result.pointer("/value/err");
        if !(err.is_none() || err == Some(&Value::Null)) {
            let logs = result
                .pointer("/value/logs")
                .and_then(Value::as_array)
                .map(|entries| entries.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"))
                .unwrap_or_default();
            return Ok(SimulationOutcome::Failed { err: err.cloned().unwrap_or(Value::Null), logs });
        }
        let accounts = result
            .pointer("/value/accounts")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("simulation sans état de comptes (champ 'accounts' absent)"))?;
        anyhow::ensure!(accounts.len() == addresses.len(), "simulation : nombre d'états de comptes inattendu");
        let post_states = accounts.iter().map(AccountState::from_rpc_value).collect::<Result<Vec<_>>>()?;
        Ok(SimulationOutcome::Succeeded { post_states })
    }

    /// `true` if the most recent transaction involving `pubkey_b58` has not reached
    /// finality yet (`confirmationStatus` other than `"finalized"`): incoming or
    /// outgoing funds not yet definitively settled. A single call limited to the latest
    /// signature, without the second `getTransaction` call that `signature_history`
    /// makes to compute an amount. It is called on every automatic balance refresh (see
    /// main.js::refreshBalance), so it has to stay light.
    pub fn has_unfinalized_tx(&self, pubkey_b58: &str) -> Result<bool> {
        let result = self.call("getSignaturesForAddress", json!([pubkey_b58, {"limit": 1}]))?;
        let entries = result.as_array().cloned().unwrap_or_default();
        Ok(entries
            .first()
            .and_then(|e| e.get("confirmationStatus"))
            .and_then(Value::as_str)
            .is_some_and(|status| status != "finalized"))
    }

    /// `true` if at least one transaction has ever involved `pubkey_b58`: tells an
    /// address that has never been used apart from one that has been emptied (neither
    /// has an on-chain account any more). A single signature requested, no details.
    pub fn has_any_signature(&self, pubkey_b58: &str) -> Result<bool> {
        let result = self.call("getSignaturesForAddress", json!([pubkey_b58, {"limit": 1}]))?;
        let entries = result.as_array().ok_or_else(|| anyhow!("réponse getSignaturesForAddress inattendue"))?;
        Ok(!entries.is_empty())
    }

    /// History of the signatures involving `pubkey_b58`, newest first (an order
    /// `getSignaturesForAddress` already guarantees). The net amount of each
    /// transaction needs a second call (`getTransaction`): unlike Bitcoin, where
    /// Esplora already includes vin/vout in the same response, Solana only gives
    /// balance history transaction by transaction.
    pub fn signature_history(&self, pubkey_b58: &str, limit: u32) -> Result<Vec<SolTx>> {
        self.signature_history_before(pubkey_b58, limit, None)
    }

    /// Next page of `signature_history`: signatures older than `before`.
    pub fn signature_history_before(&self, pubkey_b58: &str, limit: u32, before: Option<&str>) -> Result<Vec<SolTx>> {
        self.history_with_details(pubkey_b58, limit, before, net_lamports)
    }

    /// Signatures involving `account` (older than `before`), each with its details read
    /// (amount through `amount`, swap detection).
    fn history_with_details(&self, account: &str, limit: u32, before: Option<&str>, amount: fn(&Value, &str) -> Option<i128>) -> Result<Vec<SolTx>> {
        let mut options = json!({"limit": limit});
        if let Some(before) = before {
            options["before"] = json!(before);
        }
        let result = self.call("getSignaturesForAddress", json!([account, options]))?;
        let entries = result.as_array().cloned().unwrap_or_default();
        let signatures: Vec<(String, bool)> = entries
            .iter()
            .map(|e| {
                let signature = e.get("signature").and_then(Value::as_str).unwrap_or_default().to_string();
                (signature, e.get("confirmationStatus").and_then(Value::as_str) == Some("finalized"))
            })
            .collect();
        let details = self.transactions(&signatures);

        Ok(entries
            .into_iter()
            .zip(signatures.into_iter().map(|(signature, _)| signature))
            .zip(details)
            .map(|((entry, signature), details)| {
                let block_time = entry.get("blockTime").and_then(Value::as_i64);
                let confirmation_status = entry.get("confirmationStatus").and_then(Value::as_str).unwrap_or("");
                let failed = entry.get("err").map(|e| !e.is_null()).unwrap_or(false);
                SolTx {
                    net_lamports: details.as_deref().and_then(|tx| amount(tx, account)),
                    swap: details.as_deref().is_some_and(is_swap_transaction),
                    stake: details.as_deref().is_some_and(|tx| is_stake_transaction(tx, account)),
                    signature,
                    block_time,
                    confirmed: matches!(confirmation_status, "confirmed" | "finalized"),
                    failed,
                }
            })
            .collect())
    }

    /// Details (trimmed, see `compact_transaction`) of several transactions
    /// `(signature, finalized)`, in batches of 4 concurrent requests, at the pace set
    /// by `wait_for_slot`. A finalized transaction's details never change: kept in
    /// memory, they are never requested again. An error fetching a detail is
    /// deliberately swallowed: a transaction whose amount could not be determined (a
    /// node that purged an old signature, etc.) must stay displayable without an amount
    /// rather than failing the whole history.
    fn transactions(&self, signatures: &[(String, bool)]) -> Vec<Option<Arc<Value>>> {
        const PARALLEL: usize = 4;
        let mut details: Vec<Option<Arc<Value>>> = {
            let mut cache = details_cache().lock().unwrap_or_else(|p| p.into_inner());
            cache.ensure_loaded();
            signatures.iter().map(|(signature, _)| cache.entries.get(signature).cloned()).collect()
        };
        let missing: Vec<usize> = (0..signatures.len()).filter(|&i| details[i].is_none()).collect();
        for chunk in missing.chunks(PARALLEL) {
            let fetched: Vec<Option<Arc<Value>>> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|&i| {
                        let signature = &signatures[i].0;
                        scope.spawn(move || self.transaction(signature).ok().flatten().map(|tx| Arc::new(compact_transaction(&tx))))
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().ok().flatten()).collect()
            });
            let mut finalized = Vec::new();
            for (&i, detail) in chunk.iter().zip(fetched) {
                if let (Some(detail), true) = (&detail, signatures[i].1) {
                    finalized.push((signatures[i].0.clone(), detail.clone()));
                }
                details[i] = detail;
            }
            details_cache().lock().unwrap_or_else(|p| p.into_inner()).insert(finalized);
        }
        details
    }

    /// Balance of an SPL token account (Associated Token Account), in the smallest unit
    /// (e.g. micro-USDC, 6 decimals). `None` if the account does not exist yet (this
    /// token was never received). `getTokenAccountBalance` returns a JSON-RPC error in
    /// that case (not a `value: null` like `getAccountInfo`), detected here by its
    /// message rather than by a structured code, for lack of anything better from this
    /// endpoint. "Confirmed" level, like `balance_lamports`.
    pub fn token_account_balance(&self, ata_b58: &str) -> Result<Option<u64>> {
        match self.call("getTokenAccountBalance", json!([ata_b58, {"commitment": "confirmed"}])) {
            Ok(result) => {
                let amount_str = result
                    .pointer("/value/amount")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("réponse getTokenAccountBalance inattendue"))?;
                Ok(Some(amount_str.parse::<u64>().context("montant getTokenAccountBalance illisible")?))
            }
            Err(e) if e.to_string().to_lowercase().contains("could not find account") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `true` if an account (ATA or other) already exists on-chain. Used to find out
    /// whether the CreateIdempotent instruction will actually create an account (and
    /// therefore charge rent) before showing that cost in the confirmation dialog.
    pub fn account_exists(&self, pubkey_b58: &str) -> Result<bool> {
        let result = self.call("getAccountInfo", json!([pubkey_b58, {"encoding": "base64"}]))?;
        Ok(!result.get("value").map(Value::is_null).unwrap_or(true))
    }

    /// Minimum lamports for an account of `data_len` bytes to be rent-exempt, queried
    /// live rather than hard-coded: this network parameter changes over time, and a
    /// fixed figure would silently become too low or too high.
    pub fn minimum_rent_exempt_balance(&self, data_len: u64) -> Result<u64> {
        let result = self.call("getMinimumBalanceForRentExemption", json!([data_len]))?;
        result.as_u64().ok_or_else(|| anyhow!("réponse getMinimumBalanceForRentExemption inattendue"))
    }

    /// A clear message for a failed simulation whose cause is known: missing SOL found
    /// in the log (`insufficient_lamports_error`), or an account that would end up
    /// below Solana's minimum reserve. The latter does NOT appear in the log (the
    /// network checks it after the instructions, which all succeed): only in `err`, as
    /// seen on 2026-10-02 on a LI.FI swap of almost the whole balance. `None`: unknown
    /// cause, and it is up to the caller to show `err` and the log.
    pub fn explain_simulation_failure(&self, err: &Value, logs: &str) -> Option<anyhow::Error> {
        if let Some(error) = insufficient_lamports_error(logs) {
            return Some(error);
        }
        let index = err.pointer("/InsufficientFundsForRent/account_index").and_then(Value::as_u64)?;
        // Reserve for an account with no data, read live: this network parameter has
        // already gone down (0.00089088 SOL before, 0.00065024 seen on 2026-10-02); that
        // last value is used if the read fails.
        let reserve = format_lamports(self.minimum_rent_exempt_balance(0).unwrap_or(650_240));
        // Account 0: the fee payer, which is the user in every transaction the app agrees
        // to sign (single signer and payer checked, see jupiter_rpc::sign_swap_transaction
        // and dapp_requests). Reducing the amount of SOL sent by the reserve is always
        // enough: what would remain is positive, otherwise the transfer itself would have
        // failed.
        Some(if index == 0 {
            anyhow!(
                "solde SOL trop juste : il doit rester au moins {reserve} SOL sur votre compte après l'opération (réserve minimale imposée par Solana) — réduisez le montant de SOL envoyé d'autant, ou ajoutez du SOL"
            )
        } else {
            anyhow!("un autre compte touché par l'opération finirait sous la réserve minimale de Solana ({reserve} SOL), le réseau la refuserait — essayez un montant plus élevé")
        })
    }

    /// Details of a transaction (`getTransaction`); `None` if the node no longer has it
    /// (old signature purged). "Version 1" transactions are accepted (seen on
    /// 2026-10-09: requested as version 0, the node refused them with error -32015 and
    /// they stayed without an amount in the history); in JSON, they have the same
    /// account keys and balances as earlier versions (`compact_transaction`).
    fn transaction(&self, signature: &str) -> Result<Option<Value>> {
        let result = self.call(
            "getTransaction",
            json!([signature, {"encoding": "json", "maxSupportedTransactionVersion": 1}]),
        )?;
        Ok((!result.is_null()).then_some(result))
    }

    /// Same principle as `signature_history`, but for the history of an SPL token (e.g.
    /// USDC): queries the signatures that directly involve the associated token account
    /// (ATA), not the wallet's "owner" address, since it is the ATA, not the owner's
    /// system account, that actually receives/sends the token. The `net_lamports` field
    /// of the returned `SolTx` actually holds an amount in the token's smallest unit
    /// (e.g. micro-USDC), not lamports; the same struct is reused rather than
    /// duplicating an identical one.
    pub fn token_signature_history(&self, ata_b58: &str, limit: u32) -> Result<Vec<SolTx>> {
        self.token_signature_history_before(ata_b58, limit, None)
    }

    /// Next page of `token_signature_history`: signatures older than `before`.
    pub fn token_signature_history_before(&self, ata_b58: &str, limit: u32, before: Option<&str>) -> Result<Vec<SolTx>> {
        self.history_with_details(ata_b58, limit, before, net_token_amount)
    }
}

/// A transaction's details trimmed to the fields read here (amounts, swap): account
/// keys (including those loaded from address tables in v0 transactions, which
/// follow the static keys in the balance arrays, writable then read-only), balances
/// before/after and the memo lines of the log. A few hundred bytes instead of tens
/// of KB.
fn compact_transaction(tx: &Value) -> Value {
    let mut keys = tx.pointer("/transaction/message/accountKeys").and_then(Value::as_array).cloned().unwrap_or_default();
    for group in ["writable", "readonly"] {
        if let Some(loaded) = tx.pointer(&format!("/meta/loadedAddresses/{group}")).and_then(Value::as_array) {
            keys.extend(loaded.iter().cloned());
        }
    }
    let meta = |field: &str| tx.pointer(&format!("/meta/{field}")).cloned().unwrap_or(Value::Null);
    // Token balances: only the account index and the amount are read.
    let token_balances = |field: &str| match tx.pointer(&format!("/meta/{field}")).and_then(Value::as_array) {
        Some(entries) => Value::Array(
            entries
                .iter()
                .map(|e| json!({"accountIndex": e.get("accountIndex"), "uiTokenAmount": {"amount": e.pointer("/uiTokenAmount/amount")}}))
                .collect(),
        ),
        None => Value::Null,
    };
    let memos: Vec<Value> = tx
        .pointer("/meta/logMessages")
        .and_then(Value::as_array)
        .map(|logs| logs.iter().filter(|line| line.as_str().is_some_and(|l| l.starts_with("Program log: Memo (len "))).cloned().collect())
        .unwrap_or_default();
    json!({
        "transaction": {"message": {"accountKeys": keys}},
        "meta": {
            "preBalances": meta("preBalances"),
            "postBalances": meta("postBalances"),
            "preTokenBalances": token_balances("preTokenBalances"),
            "postTokenBalances": token_balances("postTokenBalances"),
            "logMessages": memos,
        },
    })
}

/// Change in the SOL balance of `pubkey_b58` within a transaction
/// (`getTransaction`).
fn net_lamports(tx: &Value, pubkey_b58: &str) -> Option<i128> {
    let account_keys = tx.pointer("/transaction/message/accountKeys")?.as_array()?;
    let index = account_keys.iter().position(|k| k.as_str() == Some(pubkey_b58))?;
    let pre = tx.pointer("/meta/preBalances")?.as_array()?.get(index)?.as_i64()?;
    let post = tx.pointer("/meta/postBalances")?.as_array()?.get(index)?.as_i64()?;
    Some((post - pre) as i128)
}

/// The equivalent of `net_lamports` for an SPL token account: Solana does not give
/// token balance history in `preBalances`/`postBalances` (reserved for the native
/// SOL balance) but in `preTokenBalances`/`postTokenBalances`, indexed by the
/// account's position in `accountKeys` (the same indexing mechanism). Absence from
/// `preTokenBalances` is treated as a balance of 0 before the transaction (the case
/// of an ATA just created by that same transaction, through CreateIdempotent).
fn net_token_amount(tx: &Value, ata_b58: &str) -> Option<i128> {
    let account_keys = tx.pointer("/transaction/message/accountKeys")?.as_array()?;
    let index = account_keys.iter().position(|k| k.as_str() == Some(ata_b58))?;
    let amount_at_index = |balances: &[Value]| -> Option<i128> {
        balances
            .iter()
            .find(|entry| entry.get("accountIndex").and_then(Value::as_u64) == Some(index as u64))
            .and_then(|entry| entry.pointer("/uiTokenAmount/amount"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<i128>().ok())
    };
    let pre_amount = tx.pointer("/meta/preTokenBalances").and_then(Value::as_array).and_then(|b| amount_at_index(b)).unwrap_or(0);
    amount_at_index(tx.pointer("/meta/postTokenBalances")?.as_array()?).map(|post| post - pre_amount)
}

/// Jupiter's swap aggregation program (v6), the one the app uses.
const JUPITER_PROGRAM: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

/// Native staking operation by `account` (stake, unstake or withdraw, see
/// `sol_stake`): the Stake program among the accounts, and `account` as the fee
/// payer (first account). A third-party transaction that also touches the Stake
/// program stays an ordinary receipt.
fn is_stake_transaction(tx: &Value, account: &str) -> bool {
    tx.pointer("/transaction/message/accountKeys").and_then(Value::as_array).is_some_and(|keys| {
        keys.first().and_then(Value::as_str) == Some(account) && keys.iter().any(|k| k.as_str() == Some(crate::sol_stake::STAKE_PROGRAM))
    })
}

/// Swap: the Jupiter program is called (always among the message's static keys, since
/// a program cannot come from an address table), or a THORChain swap memo appears in
/// the Memo program's log (`Program log: Memo (len N): "…"`).
fn is_swap_transaction(tx: &Value) -> bool {
    let jupiter = tx
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(JUPITER_PROGRAM)));
    let memo_swap = tx.pointer("/meta/logMessages").and_then(Value::as_array).is_some_and(|logs| {
        logs.iter().filter_map(Value::as_str).any(|line| {
            line.strip_prefix("Program log: Memo (len ")
                .and_then(|rest| rest.split_once("): \""))
                .and_then(|(_, memo)| memo.strip_suffix('"'))
                .is_some_and(crate::history::is_swap_memo)
        })
    });
    jupiter || memo_swap
}

/// Transaction whose blockhash expired (or is unknown to the node) before sending:
/// refused before any broadcast.
pub const BLOCKHASH_EXPIRED_ERROR: &str =
    "la transaction a expiré avant d'être envoyée (délai de validité de Solana dépassé) — rien n'a été envoyé ni débité, réessayez";

/// Lamports as SOL, without needless zeros ("0.00065024").
pub fn format_lamports(lamports: u64) -> String {
    let text = format!("{}.{:09}", lamports / 1_000_000_000, lamports % 1_000_000_000);
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Looks for the pattern "Transfer: insufficient lamports X, need Y" in a simulation
/// log (see `SolRpc::simulate_transaction`) and, if found, builds a clear message with
/// the exact shortfall. Much more readable than the raw log for an amount, fee or rent
/// that cannot be reliably predicted in advance (e.g. the exact cost of a Jupiter swap
/// route, which varies from one call to the next).
pub fn insufficient_lamports_error(logs: &str) -> Option<anyhow::Error> {
    let line = logs.lines().find(|l| l.contains("insufficient lamports"))?;
    let numbers: Vec<u64> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();
    let (&available, &needed) = (numbers.first()?, numbers.get(1)?);
    let missing = needed.saturating_sub(available);
    Some(anyhow!(
        "SOL insuffisant pour cette opération : il manque environ {missing} lamports ({available} disponibles, {needed} requis à cette étape)"
    ))
}

/// Raw state of a Solana account as returned by the RPC (base64 encoding).
#[derive(Clone, Debug, PartialEq)]
pub struct AccountState {
    pub lamports: u64,
    /// The account's owner program (base58).
    pub owner: String,
    pub data: Vec<u8>,
}

impl AccountState {
    pub(crate) fn from_rpc_value(value: &Value) -> Result<Option<Self>> {
        if value.is_null() {
            return Ok(None);
        }
        let lamports = value.get("lamports").and_then(Value::as_u64).ok_or_else(|| anyhow!("compte sans lamports"))?;
        let owner = value.get("owner").and_then(Value::as_str).ok_or_else(|| anyhow!("compte sans propriétaire"))?.to_string();
        let data_b64 = value
            .get("data")
            .and_then(Value::as_array)
            .and_then(|d| d.first())
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("compte sans données base64"))?;
        let data = base64::engine::general_purpose::STANDARD.decode(data_b64).context("données de compte base64 invalides")?;
        Ok(Some(Self { lamports, owner, data }))
    }
}

pub enum SimulationOutcome {
    /// `err`: transaction error returned by the node (the only trace of some causes,
    /// see `SolRpc::explain_simulation_failure`).
    Failed { err: Value, logs: String },
    Succeeded { post_states: Vec<Option<AccountState>> },
}

pub struct SolTx {
    pub signature: String,
    pub block_time: Option<i64>,
    /// `confirmed`/`finalized` (see `confirmationStatus`); `processed` (the least safe
    /// level, not replicated yet) is treated as unconfirmed.
    pub confirmed: bool,
    pub failed: bool,
    /// Positive if received on net, negative if sent on net, in lamports; `None` if the
    /// details could not be fetched.
    pub net_lamports: Option<i128>,
    /// Jupiter or THORChain swap (see `is_swap_transaction`).
    pub swap: bool,
    /// Native staking (see `is_stake_transaction`).
    pub stake: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real log line seen when a Jupiter swap simulation failed (rent/wrapping
    // SOL<->wSOL underestimated): checks that the exact pattern returned by the Solana
    // validator is recognized.
    #[test]
    fn insufficient_lamports_error_extracts_the_real_shortfall() {
        let logs = "Program log: Instruction: Route\nProgram 11111111111111111111111111111111 invoke [2]\nTransfer: insufficient lamports 6460932, need 13045440\nProgram 11111111111111111111111111111111 failed: custom program error: 0x1";
        let err = insufficient_lamports_error(logs).expect("motif reconnu");
        let message = err.to_string();
        assert!(message.contains("6460932"), "{message}");
        assert!(message.contains("13045440"), "{message}");
        assert!(message.contains("6584508"), "manque exact attendu : {message}");
    }

    #[test]
    fn insufficient_lamports_error_returns_none_without_the_pattern() {
        assert!(insufficient_lamports_error("Program log: Instruction: Route\nProgram ... success").is_none());
    }

    /// Real failure from 2026-10-02 (a LI.FI swap of almost the whole balance,
    /// reproduced in simulation): every instruction succeeds, and only the error says
    /// an account would end up below the minimum reserve. Node unreachable here:
    /// default reserve.
    #[test]
    fn explains_a_balance_left_under_the_rent_reserve() {
        let rpc = SolRpc::new("http://127.0.0.1:1");
        let logs = "Program 99vQwtBwYtrqqD9YSXbdum3KBdxPAVxYTaQ3cfnJSrN2 invoke [1]\nProgram log: Instruction: DepositNative\nProgram 99vQwtBwYtrqqD9YSXbdum3KBdxPAVxYTaQ3cfnJSrN2 success";
        let own = rpc.explain_simulation_failure(&json!({"InsufficientFundsForRent": {"account_index": 0}}), logs).expect("cause reconnue").to_string();
        assert!(own.starts_with("solde SOL trop juste") && own.contains("0.00065024 SOL"), "{own}");
        let other = rpc.explain_simulation_failure(&json!({"InsufficientFundsForRent": {"account_index": 3}}), logs).expect("cause reconnue").to_string();
        assert!(other.starts_with("un autre compte") && other.contains("0.00065024 SOL"), "{other}");
        assert!(rpc.explain_simulation_failure(&json!({"InstructionError": [6, {"Custom": 1}]}), logs).is_none());
    }

    #[test]
    fn formats_lamports_as_sol() {
        assert_eq!(format_lamports(890_880), "0.00089088");
        assert_eq!(format_lamports(1_500_000_000), "1.5");
        assert_eq!(format_lamports(10_000_000_000), "10");
        assert_eq!(format_lamports(0), "0");
    }

    /// Formats of real mainnet transactions: a Jupiter swap (program among the static
    /// keys of a v0 transaction), a THORChain swap deposit and a THORChain payout (Memo
    /// program log lines copied verbatim), an ordinary transfer.
    #[test]
    fn swaps_are_detected_in_real_transaction_formats() {
        let tx = |keys: &[&str], logs: &[&str]| json!({"transaction": {"message": {"accountKeys": keys}}, "meta": {"logMessages": logs}});
        let jupiter = tx(&["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", JUPITER_PROGRAM], &["Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 invoke [1]"]);
        assert!(is_swap_transaction(&jupiter));
        let deposit = tx(
            &["11111111111111111111111111111111", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"],
            &[
                "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr invoke [1]",
                "Program log: Memo (len 53): \"=:BSC.USDT:0xd63678741D8e155e337c0Fe35cE143886fA04750\"",
            ],
        );
        assert!(is_swap_transaction(&deposit));
        let payout = tx(&[], &["Program log: Memo (len 68): \"OUT:69F129E7A9CC7D8C71D4A261C56EF2291275DF572A29F9218A535B743EAAEB15\""]);
        assert!(is_swap_transaction(&payout));
        let transfer = tx(&["11111111111111111111111111111111"], &["Program 11111111111111111111111111111111 invoke [1]", "Program log: Memo (len 5): \"merci\""]);
        assert!(!is_swap_transaction(&transfer));
        assert!(!is_swap_transaction(&json!({})));
    }

    /// Net SOL and token amounts, computed from the same transaction details.
    #[test]
    fn net_amounts_are_read_from_transaction_details() {
        let tx = json!({
            "transaction": {"message": {"accountKeys": ["Owner", "Ata", "Other"]}},
            "meta": {
                "preBalances": [1_000_000, 2_039_280, 5], "postBalances": [990_000, 2_039_280, 5],
                "preTokenBalances": [], "postTokenBalances": [{"accountIndex": 1, "uiTokenAmount": {"amount": "2500000"}}]
            }
        });
        assert_eq!(net_lamports(&tx, "Owner"), Some(-10_000));
        assert_eq!(net_lamports(&tx, "Absent"), None);
        assert_eq!(net_token_amount(&tx, "Ata"), Some(2_500_000), "compte de jetons créé par la transaction : solde avant = 0");
        assert_eq!(net_token_amount(&tx, "Other"), None);
    }

    /// Method with an unknown limit: 9 sends per 10 s, the 10th waits for the oldest to
    /// leave the window; another method is not affected; limit announced by the node
    /// (minus one as a margin); after a refusal, nothing for the requested delay;
    /// global limit of 80.
    #[test]
    fn requests_are_paced_under_the_public_node_limits() {
        let mut window = RateWindow::default();
        let t0 = Instant::now();
        for i in 0..DEFAULT_METHOD_CAP {
            assert_eq!(window.try_acquire("getTransaction", t0 + Duration::from_millis(i as u64)), None);
        }
        let later = t0 + Duration::from_secs(1);
        assert_eq!(window.try_acquire("getTransaction", later), Some(Duration::from_secs(9)));
        assert_eq!(window.try_acquire("getBalance", later), None, "autre méthode : pas concernée");
        assert_eq!(window.try_acquire("getTransaction", t0 + RATE_WINDOW), None, "place libérée après 10 s");

        window.record("getBalance", Some(40), None, later);
        for _ in 1..39 {
            assert_eq!(window.try_acquire("getBalance", later), None);
        }
        assert!(window.try_acquire("getBalance", later).is_some(), "limite annoncée 40 : 39 envois");

        window.record("getSignaturesForAddress", None, Some(Duration::from_secs(10)), later);
        assert_eq!(window.try_acquire("getSignaturesForAddress", later + Duration::from_secs(4)), Some(Duration::from_secs(6)), "refus : attendre");
        assert_eq!(window.try_acquire("getSignaturesForAddress", later + Duration::from_secs(10)), None);

        let mut window = RateWindow::default();
        for i in 0..MAX_PER_ENDPOINT {
            assert_eq!(window.try_acquire(&format!("m{}", i % 10), t0), None);
        }
        assert_eq!(window.try_acquire("autre", t0 + Duration::from_secs(2)), Some(Duration::from_secs(8)), "limite totale");
    }

    /// Disk cache: reread from one session to the next, duplicates ignored, damaged
    /// line (interrupted write) skipped.
    #[test]
    fn transaction_details_survive_a_restart() {
        let path = std::env::temp_dir().join(format!("sol_details_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut cache = DetailsCache { file: Some(path.clone()), ..Default::default() };
        cache.ensure_loaded();
        let detail = Arc::new(json!({"meta": {"preBalances": [1]}}));
        cache.insert(vec![("sigA".into(), detail.clone()), ("sigB".into(), detail.clone())]);
        cache.insert(vec![("sigA".into(), detail.clone())]);
        std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"s\":\"sigC\",\"t\"").unwrap();

        let mut reloaded = DetailsCache { file: Some(path.clone()), ..Default::default() };
        reloaded.ensure_loaded();
        assert_eq!(reloaded.entries.len(), 2);
        assert_eq!(reloaded.entries.get("sigA").map(|d| d.as_ref()), Some(detail.as_ref()));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3, "deux entrées + la ligne abîmée");
        let _ = std::fs::remove_file(&path);
    }

    /// Trimmed details: keys loaded from an address table are added after the static
    /// keys (writable then read-only), as in the balance arrays; only the memo lines of
    /// the log are kept; amounts and swap detection are identical on the trimmed
    /// details.
    #[test]
    fn compact_details_keep_what_amounts_and_swaps_need() {
        let tx = json!({
            "transaction": {"message": {"accountKeys": ["Payer", "11111111111111111111111111111111"], "instructions": [{"data": "x"}]}},
            "meta": {
                "preBalances": [5_000_000, 1, 2_000, 7], "postBalances": [3_995_000, 1, 1_002_000, 7],
                "preTokenBalances": [{"accountIndex": 3, "mint": "EPjF", "owner": "Payer", "uiTokenAmount": {"amount": "700", "decimals": 6, "uiAmount": 0.0007}}],
                "postTokenBalances": [{"accountIndex": 3, "mint": "EPjF", "owner": "Payer", "uiTokenAmount": {"amount": "200", "decimals": 6, "uiAmount": 0.0002}}],
                "loadedAddresses": {"writable": ["Receiver"], "readonly": ["Lookup"]},
                "logMessages": ["Program 11111111111111111111111111111111 invoke [1]", "Program log: Memo (len 12): \"=:ETH.ETH:0x\""],
                "computeUnitsConsumed": 150
            }
        });
        assert_eq!(net_lamports(&tx, "Receiver"), None, "clé chargée invisible sans le détail réduit");
        let compact = compact_transaction(&tx);
        assert_eq!(net_lamports(&compact, "Receiver"), Some(1_000_000));
        assert_eq!(net_lamports(&compact, "Payer"), Some(-1_005_000));
        assert_eq!(net_lamports(&compact, "Lookup"), Some(0));
        assert_eq!(net_token_amount(&compact, "Lookup"), Some(-500), "compte de jetons chargé d'une table");
        assert_eq!(compact.pointer("/meta/postTokenBalances/0"), Some(&json!({"accountIndex": 3, "uiTokenAmount": {"amount": "200"}})));
        assert!(is_swap_transaction(&compact));
        assert_eq!(compact.pointer("/meta/logMessages").and_then(Value::as_array).map(Vec::len), Some(1));
        assert!(compact.pointer("/transaction/message/instructions").is_none());
        assert!(compact.pointer("/meta/computeUnitsConsumed").is_none());
    }
}
