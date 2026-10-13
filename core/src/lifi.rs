//! LI.FI: direct swaps between two ecosystems (e.g. RENDER on Solana → LINK on
//! Ethereum), where THORChain, Maya, Jupiter and CoW connect nothing. LI.FI is an
//! aggregator: it picks a bridge (Mayan, Relay, Layerswap…) and builds the
//! transaction ITSELF, so the app cannot rebuild it the way it does a THORChain
//! memo or a CoW order. It is verified before signing:
//! - EVM source: simulation (`eth_simulateV1`) of the approval and the call, then
//!   reading the events emitted by the LI.FI contract. Only the token sold leaves
//!   the user, for the exact amount, and the recipient emitted by the contract is
//!   the one shown. A bridge that keeps the recipient off-chain ("Relay
//!   depository") is dropped and a new quote requested without it. Avalanche: its
//!   nodes do not simulate, so the recipient is read from the calldata (EVM
//!   destination only);
//! - Solana source: simulation of the effects on the user's accounts (same check as
//!   Jupiter, see `api::send_lifi_solana`); the recipient, handled off-chain by the
//!   bridge, cannot be verified, and the confirmation dialog says so;
//! - Bitcoin source: the PSBT is reread output by output (`verify_btc_deposit`: the
//!   user's inputs, a single deposit, bounded fees), then re-serialized and signed
//!   by the app; the recipient cannot be verified either (off-chain bridge), as
//!   stated in the confirmation dialog.
//!
//! No API key (one must never be embedded in an installed app): 75 quotes per 2
//! hours per IP address, plenty for a wallet. Integrator fees (`FEE`) require an
//! account on portal.li.fi: as long as `INTEGRATOR` is not set, no LI.FI route is
//! offered.

use crate::{btc_psbt, btc_tx, derivation, eth_rpc, evm_sign, tokens, wallet_flow};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::Value;
use std::sync::OnceLock;

const API_BASE: &str = "https://li.quest/v1";
/// Integrator name registered on portal.li.fi on 2026-10-02 (fee wallets configured
/// there; fees accepted by LI.FI, checked on real quotes: "LIFI Fixed Fee" 1.05% =
/// LI.FI's 0.25% + our 0.80%). Without it (`None`), no LI.FI route.
pub const INTEGRATOR: Option<&str> = Some("openpgp-wallet");
/// Integrator fee: 0.80% of the amount sent (LI.FI takes an extra 0.25%).
pub const FEE: f64 = 0.008;
/// LI.FI's own fee, on top of ours (recorded on real quotes: "LIFI Fixed Fee" 1.05%
/// = 0.25% + our 0.80%).
const LIFI_OWN_FEE_BPS: u128 = 25;
/// Tolerated slippage (1%), guaranteed by the bridge.
const SLIPPAGE: &str = "0.01";
/// LI.FI chain IDs for non-EVM networks.
pub const SOLANA_CHAIN: u64 = 1_151_111_081_099_710;
pub const BITCOIN_CHAIN: u64 = 20_000_000_000_001;
/// Recipient written by the LI.FI contract when the destination is not an EVM
/// network (the real one is emitted separately, `BridgeToNonEVMChain…`).
const NON_EVM_RECEIVER: [u8; 20] = [
    0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1, 0x11, 0xf1,
    0x11, 0xf1, 0x11, 0xf1,
];
/// LI.FI quote from a Bitcoin address with no confirmed funds.
pub const NO_CONFIRMED_BTC: &str = "aucun BTC confirmé sur votre adresse : LI.FI prépare le dépôt à partir de fonds reçus et confirmés (au moins une confirmation)";
/// Maximum number of new quotes requested when the proposed bridge keeps the
/// recipient off-chain.
pub const MAX_ROUTE_ATTEMPTS: usize = 3;

fn shared_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("configuration du client HTTP valide")
    })
}

/// LI.FI's entry contract ("diamond") on one of the app's EVM networks, taken from
/// `li.quest/v1/chains` (same address everywhere).
pub fn diamond(network: &str) -> Option<&'static str> {
    Some(match network {
        "evm_mainnet" | "arbitrum_mainnet" | "base_mainnet" | "bsc_mainnet" | "avax_mainnet"
        | "polygon_mainnet" => "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE",
        _ => return None,
    })
}

/// LI.FI chain ID of one of the app's networks.
pub fn chain_id(network: &str) -> Option<u64> {
    match network {
        "sol_mainnet" => Some(SOLANA_CHAIN),
        "btc_mainnet" => Some(BITCOIN_CHAIN),
        _ => diamond(network)
            .and(wallet_flow::evm_network(network))
            .map(|n| n.chain_id),
    }
}

/// Can the network's node simulate (`eth_simulateV1`, recorded on 2026-10-02)?
pub fn simulates(network: &str) -> bool {
    network != "avax_mainnet"
}

fn is_evm(network: &str) -> bool {
    diamond(network).is_some()
}

/// Card identifier of an EVM network's native coin.
fn native_coin(network: &wallet_flow::EvmNetwork) -> &'static str {
    match network.native_symbol {
        "ETH" => "evm",
        "BNB" => "bnb",
        "AVAX" => "avax",
        "POL" => "pol",
        _ => "",
    }
}

/// One of the app's cryptos, as LI.FI designates it.
#[derive(Clone, Debug, PartialEq)]
pub struct LifiToken {
    pub chain: u64,
    /// Contract address (EVM), mint (Solana), or LI.FI identifier for the native coin
    /// (`0x00…00`, `11111111111111111111111111111111`, `bitcoin`).
    pub address: String,
    pub decimals: u8,
    pub symbol: &'static str,
    pub native: bool,
}

pub fn token(coin: &str, network: &str) -> Option<LifiToken> {
    let chain = chain_id(network)?;
    if let Some((info, deployment)) = tokens::find(coin, network) {
        let address = match deployment.kind {
            tokens::TokenKind::Erc20 { contract } if is_evm(network) => contract,
            tokens::TokenKind::Spl { mint } if network == "sol_mainnet" => mint,
            _ => return None,
        };
        return Some(LifiToken {
            chain,
            address: address.to_string(),
            decimals: deployment.decimals,
            symbol: info.symbol,
            native: false,
        });
    }
    let (address, decimals, symbol) = match (coin, network) {
        ("sol", "sol_mainnet") => ("11111111111111111111111111111111", 9, "SOL"),
        ("btc", "btc_mainnet") => ("bitcoin", 8, "BTC"),
        _ => {
            let net = wallet_flow::evm_network(network)?;
            if native_coin(net) != coin {
                return None;
            }
            (
                "0x0000000000000000000000000000000000000000",
                18,
                net.native_symbol,
            )
        }
    };
    Some(LifiToken {
        chain,
        address: address.to_string(),
        decimals,
        symbol,
        native: true,
    })
}

/// Every app crypto LI.FI can designate (identifier, network).
pub fn tradable() -> Vec<(&'static str, &'static str)> {
    let natives = wallet_flow::EVM_NETWORKS
        .iter()
        .filter(|n| is_evm(n.id) && !native_coin(n).is_empty())
        .map(|n| (native_coin(n), n.id))
        .chain([("sol", "sol_mainnet"), ("btc", "btc_mainnet")]);
    let registry = tokens::TOKENS.iter().flat_map(|t| {
        t.deployments
            .iter()
            .filter(|d| token(t.id, d.network).is_some())
            .map(move |d| (t.id, d.network))
    });
    natives.chain(registry).collect()
}

/// Does LI.FI connect these two cryptos (ignoring activation)? Only between two
/// different networks (the same network goes through CoW or Jupiter); from a
/// network that does not simulate, only to an EVM network (recipient read from the
/// calldata). From Bitcoin: PSBT verified by `verify_btc_deposit` (recorded on
/// 2026-10-03: LI.FI offers BTC to every one of the app's networks, through
/// LayerSwap or Relay).
pub fn links(from: (&str, &str), to: (&str, &str)) -> bool {
    let ((from_coin, from_network), (to_coin, to_network)) = (from, to);
    from_network != to_network
        && (simulates(from_network) || is_evm(to_network))
        && token(from_coin, from_network).is_some()
        && token(to_coin, to_network).is_some()
}

/// Transaction provided by LI.FI, to be verified before signing.
#[derive(Clone, Debug)]
pub enum LifiTx {
    Evm {
        to: [u8; 20],
        data: Vec<u8>,
        value: u128,
    },
    /// Serialized Solana transaction (a single signer: the user).
    Solana { raw: Vec<u8> },
    /// PSBT for a Bitcoin deposit to the bridge's address (`deposit`, script
    /// `deposit_script`), verified by `verify_btc_deposit` before signing.
    Bitcoin {
        psbt: btc_psbt::Psbt,
        deposit: String,
        deposit_script: Vec<u8>,
    },
}

/// LI.FI quote, checked again.
#[derive(Clone, Debug)]
pub struct LifiQuote {
    pub from_network: &'static str,
    pub to_network: &'static str,
    pub from: LifiToken,
    pub to: LifiToken,
    pub from_amount: u128,
    pub to_amount: u128,
    pub to_amount_min: u128,
    pub from_address: String,
    pub to_address: String,
    /// Bridge chosen by LI.FI (technical key, and display name).
    pub tool: String,
    pub tool_name: String,
    pub duration_secs: u64,
    pub tx: LifiTx,
}

fn same_address(a: &str, b: &str, evm: bool) -> bool {
    if evm {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn amount_field(value: &Value, field: &str) -> Result<u128> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("devis LI.FI sans « {field} » exploitable"))
}

fn hex_u128(value: Option<&Value>) -> Result<u128> {
    let s = value.and_then(Value::as_str).unwrap_or("0x0");
    u128::from_str_radix(s.trim_start_matches("0x"), 16)
        .context("montant hexadécimal LI.FI illisible")
}

/// LI.FI quote for sending `amount` (units) of `from` (on `from_network`, from
/// `from_address`) to `to` on `to_network`, delivered to `to_address`. `deny`:
/// bridges to exclude; `allow`: the only bridge allowed (a new quote on the bridge
/// already shown). The response is checked again (chains, tokens, amount,
/// addresses, contract called) before being used.
#[allow(clippy::too_many_arguments)]
pub fn quote(
    from_network: &'static str,
    from: &LifiToken,
    to_network: &'static str,
    to: &LifiToken,
    amount: u128,
    from_address: &str,
    to_address: &str,
    deny: &[String],
    allow: Option<&str>,
) -> Result<LifiQuote> {
    let mut params: Vec<(&str, String)> = vec![
        ("fromChain", from.chain.to_string()),
        ("toChain", to.chain.to_string()),
        ("fromToken", from.address.clone()),
        ("toToken", to.address.clone()),
        ("fromAmount", amount.to_string()),
        ("fromAddress", from_address.to_string()),
        ("toAddress", to_address.to_string()),
        ("slippage", SLIPPAGE.to_string()),
        // No contract call on arrival: the recipient emitted at departure is then indeed
        // the one who receives.
        ("allowDestinationCall", "false".to_string()),
    ];
    if let Some(integrator) = INTEGRATOR {
        params.push(("integrator", integrator.to_string()));
        if FEE > 0.0 {
            params.push(("fee", FEE.to_string()));
        }
    }
    if !deny.is_empty() {
        params.push(("denyBridges", deny.join(",")));
    }
    if let Some(bridge) = allow {
        params.push(("allowBridges", bridge.to_string()));
    }
    let response = shared_client()
        .get(format!("{API_BASE}/quote"))
        .query(&params)
        .send()
        .context("requête de devis LI.FI impossible")?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!("limite de devis LI.FI atteinte (75 toutes les 2 heures sans compte) — réessayez plus tard");
    }
    let q: Value = response
        .json()
        .context("réponse de devis LI.FI illisible")?;
    if q.get("transactionRequest").is_none() {
        let message = q
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("réponse inattendue");
        // From Bitcoin, LI.FI builds the deposit from the address's confirmed outputs
        // (real response without them: "No UTXOs found for any sender addresses").
        if message.contains("No UTXOs found") {
            bail!(NO_CONFIRMED_BTC);
        }
        bail!("devis LI.FI refusé : {message}");
    }
    parse_quote(
        &q,
        from_network,
        from,
        to_network,
        to,
        amount,
        from_address,
        to_address,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_quote(
    q: &Value,
    from_network: &'static str,
    from: &LifiToken,
    to_network: &'static str,
    to: &LifiToken,
    amount: u128,
    from_address: &str,
    to_address: &str,
) -> Result<LifiQuote> {
    let action = q.get("action").context("devis LI.FI sans action")?;
    let estimate = q.get("estimate").context("devis LI.FI sans estimation")?;
    let (from_evm, to_evm) = (is_evm(from_network), is_evm(to_network));
    let text = |v: &Value, path: &[&str]| -> String {
        let mut cur = v;
        for key in path {
            cur = &cur[*key];
        }
        cur.as_str().unwrap_or_default().to_string()
    };
    ensure!(
        action["fromChainId"].as_u64() == Some(from.chain)
            && action["toChainId"].as_u64() == Some(to.chain),
        "devis LI.FI pour d'autres réseaux"
    );
    ensure!(
        same_address(
            &text(action, &["fromToken", "address"]),
            &from.address,
            from_evm
        ),
        "devis LI.FI pour un autre jeton envoyé"
    );
    ensure!(
        same_address(&text(action, &["toToken", "address"]), &to.address, to_evm),
        "devis LI.FI pour un autre jeton reçu"
    );
    ensure!(
        amount_field(action, "fromAmount")? == amount,
        "devis LI.FI pour un autre montant"
    );
    ensure!(
        same_address(&text(action, &["fromAddress"]), from_address, from_evm),
        "devis LI.FI pour un autre expéditeur"
    );
    ensure!(
        same_address(&text(action, &["toAddress"]), to_address, to_evm),
        "devis LI.FI pour un autre destinataire"
    );
    if let Some(integrator) = INTEGRATOR {
        ensure!(
            q["integrator"].as_str() == Some(integrator),
            "devis LI.FI pour un autre intégrateur"
        );
    }
    let (to_amount, to_amount_min) = (
        amount_field(estimate, "toAmount")?,
        amount_field(estimate, "toAmountMin")?,
    );
    ensure!(
        to_amount_min > 0 && to_amount_min <= to_amount,
        "devis LI.FI incohérent (minimum)"
    );

    let request = &q["transactionRequest"];
    let tx = if from_evm {
        let diamond = diamond(from_network).context("réseau sans contrat LI.FI")?;
        ensure!(
            text(request, &["to"]).eq_ignore_ascii_case(diamond),
            "devis LI.FI vers un autre contrat que celui de LI.FI — refusé"
        );
        if let Some(chain) = request.get("chainId").and_then(Value::as_u64) {
            ensure!(
                chain == from.chain,
                "transaction LI.FI pour un autre réseau"
            );
        }
        let value = hex_u128(request.get("value"))?;
        ensure!(
            value == if from.native { amount } else { 0 },
            "transaction LI.FI avec un montant natif inattendu"
        );
        if !from.native {
            ensure!(
                text(estimate, &["approvalAddress"]).eq_ignore_ascii_case(diamond),
                "autorisation LI.FI demandée pour un autre contrat — refusé"
            );
        }
        let data = hex::decode(text(request, &["data"]).trim_start_matches("0x"))
            .context("données de transaction LI.FI illisibles")?;
        ensure!(data.len() >= 4, "transaction LI.FI vide");
        LifiTx::Evm {
            to: wallet_flow::parse_evm_address(diamond)?,
            data,
            value,
        }
    } else if from_network == "sol_mainnet" {
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            text(request, &["data"]),
        )
        .context("transaction LI.FI Solana illisible")?;
        LifiTx::Solana { raw }
    } else if from_network == "btc_mainnet" {
        // `to`: the bridge's deposit address; `value`: amount (decimal); `data`: PSBT in
        // hexadecimal (recorded on real quotes).
        ensure!(
            text(request, &["value"]) == amount.to_string(),
            "transaction LI.FI avec un autre montant que celui demandé"
        );
        let deposit = text(request, &["to"]);
        let deposit_script = derivation::btc_mainnet_script_pubkey(&deposit)
            .context("adresse de dépôt LI.FI invalide")?;
        let bytes = hex::decode(text(request, &["data"]).trim_start_matches("0x"))
            .context("PSBT LI.FI illisible")?;
        LifiTx::Bitcoin {
            psbt: btc_psbt::parse(&bytes)?,
            deposit,
            deposit_script,
        }
    } else {
        bail!("envoi depuis ce réseau non pris en charge par LI.FI dans l'app");
    };
    Ok(LifiQuote {
        from_network,
        to_network,
        from: from.clone(),
        to: to.clone(),
        from_amount: amount,
        to_amount,
        to_amount_min,
        from_address: from_address.to_string(),
        to_address: to_address.to_string(),
        tool: text(q, &["tool"]),
        tool_name: q["toolDetails"]["name"].as_str().unwrap_or("?").to_string(),
        duration_secs: estimate["executionDuration"].as_f64().unwrap_or(0.0) as u64,
        tx,
    })
}

// --- Bitcoin deposit (PSBT) -----------------------------------------------------

/// Bitcoin deposit from a LI.FI quote, verified: the transaction to sign and what
/// the confirmation dialog shows.
#[derive(Debug)]
pub struct BtcDeposit {
    pub tx: btc_tx::RawTx,
    pub network_fee: u64,
    /// Upper bound on the size once signed.
    pub vsize: u64,
    /// Fee outputs to LI.FI and to the integrator.
    pub service_fees: u64,
    /// Total leaving the address: deposit, LI.FI and integrator fees, network fee
    /// (shown in the confirmation dialog).
    pub total_debit: u64,
}

/// Smallest P2WPKH output relayed by the Bitcoin network (Bitcoin Core's dust
/// threshold): LI.FI rounds a smaller fee share up to this amount, with the
/// difference coming out of the change (recorded on 2026-10-03: 0.25% of 58,928
/// sats = 147, output of 294).
const BTC_DUST_SAT: u64 = 294;

/// Verifies the PSBT of a LI.FI deposit from Bitcoin, output by output, against the
/// user's spendable outputs as reread by the app (`utxos`, confirmed). Nothing is
/// taken from the amounts the PSBT announces:
/// - each input spends one of THEIR outputs, exactly once (amount reread, committed
///   to by the BIP143 signature), with no relative timelock (sequence at least
///   0xfffffffd);
/// - exactly one payment to the announced deposit address (`deposit_script`);
/// - change goes back to their address; at most one OP_RETURN memo, with no value;
/// - the rest (LI.FI and integrator fees, 3 outputs at most): deposit at least the
///   amount minus 1.05%, fees at most 1.05%, plus, per fee output, the top-up to
///   the dust threshold (`BTC_DUST_SAT`) when a share is too small to be relayed;
/// - network fee at most `max_fee_rate` sat/vB (maximum signed size).
///
/// The destination address, handled off-chain by the bridge, remains unverifiable
/// (stated in the confirmation dialog).
pub fn verify_btc_deposit(
    psbt: &btc_psbt::Psbt,
    deposit_script: &[u8],
    own_script: &[u8],
    utxos: &[btc_tx::Utxo],
    amount: u64,
    max_fee_rate: u64,
) -> Result<BtcDeposit> {
    ensure!(
        matches!(psbt.version, 1 | 2),
        "transaction Bitcoin LI.FI d'une version inattendue"
    );
    ensure!(
        deposit_script != own_script,
        "dépôt LI.FI vers votre propre adresse — refusé"
    );
    ensure!(
        psbt.inputs.iter().all(|i| i.sequence >= 0xffff_fffd),
        "transaction Bitcoin LI.FI avec un verrou temporel — refusé"
    );
    let mut inputs: Vec<btc_tx::RawInput> = Vec::with_capacity(psbt.inputs.len());
    for input in &psbt.inputs {
        ensure!(
            !inputs
                .iter()
                .any(|i| i.txid == input.txid && i.vout == input.vout),
            "transaction Bitcoin LI.FI qui dépense deux fois la même sortie — refusé"
        );
        let utxo = utxos
            .iter()
            .find(|u| u.txid == input.txid && u.vout == input.vout)
            .ok_or_else(|| anyhow!("la transaction LI.FI dépense une sortie absente (ou pas encore confirmée) de votre adresse Bitcoin — refusé"))?;
        inputs.push(btc_tx::RawInput {
            txid: input.txid,
            vout: input.vout,
            sequence: input.sequence,
            value_sat: utxo.value_sat,
        });
    }

    let (mut deposits, mut deposit, mut memos, mut service_outputs, mut service_fees) =
        (0, 0u64, 0, 0, 0u64);
    for (value, script) in &psbt.outputs {
        if script.as_slice() == deposit_script {
            deposits += 1;
            deposit = *value;
        } else if script.as_slice() == own_script {
            // Change returned: stays with the user.
        } else if script.first() == Some(&0x6a) {
            memos += 1;
            ensure!(
                *value == 0 && script.len() <= 83,
                "memo OP_RETURN inattendu dans la transaction LI.FI — refusé"
            );
        } else {
            service_outputs += 1;
            service_fees = service_fees
                .checked_add(*value)
                .context("montant hors limites")?;
        }
    }
    ensure!(
        deposits == 1,
        "la transaction LI.FI ne paie pas exactement une fois l'adresse de dépôt annoncée — refusé"
    );
    ensure!(
        memos <= 1 && service_outputs <= 3,
        "transaction LI.FI avec des sorties inattendues — refusé"
    );
    let fee_bps = LIFI_OWN_FEE_BPS + (FEE * 10_000.0).round() as u128;
    let fee_share = u128::from(amount) * fee_bps / 10_000 + 1;
    let dust_top_up = u128::from(BTC_DUST_SAT) * service_outputs as u128;
    ensure!(
        u128::from(deposit) + fee_share >= u128::from(amount),
        "la transaction LI.FI dépose moins que le montant affiché, frais annoncés déduits — refusé"
    );
    ensure!(
        u128::from(deposit) + u128::from(service_fees) <= u128::from(amount) + dust_top_up,
        "la transaction LI.FI envoie plus que le montant affiché — refusé"
    );
    ensure!(
        u128::from(service_fees) <= fee_share + dust_top_up,
        "frais LI.FI de la transaction Bitcoin au-delà de {},{:02} % — refusé",
        fee_bps / 100,
        fee_bps % 100
    );

    let inputs_total = inputs
        .iter()
        .try_fold(0u64, |sum, i| sum.checked_add(i.value_sat))
        .context("montant hors limites")?;
    let outputs_total = psbt
        .outputs
        .iter()
        .try_fold(0u64, |sum, (v, _)| sum.checked_add(*v))
        .context("montant hors limites")?;
    let network_fee = inputs_total
        .checked_sub(outputs_total)
        .context("la transaction LI.FI dépense plus que ses entrées — refusé")?;
    let tx = btc_tx::RawTx {
        version: psbt.version,
        inputs,
        outputs: psbt.outputs.clone(),
        locktime: psbt.locktime,
    };
    let vsize = tx.signed_vsize();
    ensure!(
        network_fee <= vsize.saturating_mul(max_fee_rate),
        "frais réseau Bitcoin anormalement élevés dans la transaction LI.FI ({network_fee} sat pour ~{vsize} vB, plafond {max_fee_rate} sat/vB) — refusé"
    );
    let total_debit = deposit + service_fees + network_fee;
    Ok(BtcDeposit {
        tx,
        network_fee,
        vsize,
        service_fees,
        total_debit,
    })
}

// --- ABI decoding (just what BridgeData needs) ---------------------------------

fn word(data: &[u8], offset: usize) -> Result<&[u8]> {
    data.get(offset..offset + 32)
        .ok_or_else(|| anyhow!("données LI.FI tronquées"))
}

fn word_usize(data: &[u8], offset: usize) -> Result<usize> {
    let w = word(data, offset)?;
    ensure!(w[..24].iter().all(|b| *b == 0), "décalage ABI hors limites");
    Ok(u64::from_be_bytes(w[24..].try_into().expect("8 octets")) as usize)
}

fn word_u128(data: &[u8], offset: usize) -> Result<u128> {
    let w = word(data, offset)?;
    ensure!(w[..16].iter().all(|b| *b == 0), "montant ABI hors limites");
    Ok(u128::from_be_bytes(w[16..].try_into().expect("16 octets")))
}

fn word_address(data: &[u8], offset: usize) -> Result<[u8; 20]> {
    let w = word(data, offset)?;
    ensure!(w[..12].iter().all(|b| *b == 0), "adresse ABI invalide");
    Ok(w[12..].try_into().expect("20 octets"))
}

fn word_bool(data: &[u8], offset: usize) -> Result<bool> {
    match word_u128(data, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("booléen ABI invalide"),
    }
}

fn abi_bytes(data: &[u8], offset: usize) -> Result<&[u8]> {
    let len = word_usize(data, offset)?;
    data.get(offset + 32..offset + 32 + len)
        .ok_or_else(|| anyhow!("données LI.FI tronquées"))
}

/// The LI.FI contract's `ILiFi.BridgeData` struct.
#[derive(Clone, Debug, PartialEq)]
pub struct BridgeData {
    pub transaction_id: [u8; 32],
    pub bridge: String,
    pub integrator: String,
    pub sending_asset: [u8; 20],
    pub receiver: [u8; 20],
    pub min_amount: u128,
    pub destination_chain: u64,
    pub has_source_swaps: bool,
    pub has_destination_call: bool,
}

/// `BridgeData` encoded at the start of ABI parameters (a dynamic struct as the
/// first parameter: an offset, then the struct). This shape is shared by the
/// arguments of every bridge function in the contract (`startBridgeTokensVia…`,
/// `swapAndStartBridgeTokensVia…`) and by the data of the `LiFiTransferStarted`
/// event.
pub fn decode_bridge_data(encoded: &[u8]) -> Result<BridgeData> {
    let start = word_usize(encoded, 0)?;
    let tuple = encoded
        .get(start..)
        .ok_or_else(|| anyhow!("données LI.FI tronquées"))?;
    let string_at = |index: usize| -> Result<String> {
        let offset = word_usize(tuple, index * 32)?;
        String::from_utf8(abi_bytes(tuple, offset)?.to_vec()).context("texte ABI invalide")
    };
    let destination = word_u128(tuple, 7 * 32)?;
    Ok(BridgeData {
        transaction_id: word(tuple, 0)?.try_into().expect("32 octets"),
        bridge: string_at(1)?,
        integrator: string_at(2)?,
        sending_asset: word_address(tuple, 4 * 32)?,
        receiver: word_address(tuple, 5 * 32)?,
        min_amount: word_u128(tuple, 6 * 32)?,
        destination_chain: u64::try_from(destination)
            .context("chaîne de destination hors limites")?,
        has_source_swaps: word_bool(tuple, 8 * 32)?,
        has_destination_call: word_bool(tuple, 9 * 32)?,
    })
}

/// `BridgeData` from a call to the LI.FI contract (selector, then parameters).
pub fn decode_call_bridge_data(calldata: &[u8]) -> Result<BridgeData> {
    decode_bridge_data(
        calldata
            .get(4..)
            .ok_or_else(|| anyhow!("appel LI.FI vide"))?,
    )
}

// --- Verification before signing ---------------------------------------------

/// Expected recipient, in the form the LI.FI contract emits it.
#[derive(Clone, Debug, PartialEq)]
pub enum Receiver {
    Evm([u8; 20]),
    /// Solana public key.
    Solana([u8; 32]),
    /// Bitcoin address: text, and for a 20-byte native SegWit v0 address (bc1q…), the
    /// 32 five-bit groups of its witness program, the form found in the
    /// `BridgeToNonEVMChainBytes32` event.
    Bitcoin {
        text: String,
        five_bit: Option<[u8; 32]>,
    },
}

impl Receiver {
    /// Recipient entered for `network`, checked against the network's format.
    pub fn parse(network: &str, address: &str) -> Result<Self> {
        if is_evm(network) {
            return Ok(Receiver::Evm(wallet_flow::parse_evm_address(address)?));
        }
        match network {
            "sol_mainnet" => {
                let key: [u8; 32] = bs58::decode(address)
                    .into_vec()
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .context("adresse Solana invalide")?;
                Ok(Receiver::Solana(key))
            }
            "btc_mainnet" => {
                // Consistent SegWit version and encoding (see `derivation::decode_segwit`).
                derivation::btc_mainnet_script_pubkey(address)
                    .context("adresse Bitcoin invalide (bech32 attendu)")?;
                let (hrp, data, _) =
                    bech32::decode(address).context("adresse Bitcoin invalide (bech32 attendu)")?;
                ensure!(
                    hrp == "bc",
                    "adresse Bitcoin du réseau principal attendue (bc1…)"
                );
                let groups: Vec<u8> = data.iter().map(|g| g.to_u8()).collect();
                let five_bit = (groups.first() == Some(&0))
                    .then(|| groups[1..].try_into().ok())
                    .flatten();
                Ok(Receiver::Bitcoin {
                    text: address.to_ascii_lowercase(),
                    five_bit,
                })
            }
            _ => bail!("réseau d'arrivée non pris en charge par LI.FI"),
        }
    }

    fn matches_bytes32(&self, emitted: &[u8; 32]) -> bool {
        match self {
            Receiver::Solana(key) => key == emitted,
            Receiver::Bitcoin {
                five_bit: Some(groups),
                ..
            } => groups == emitted,
            _ => false,
        }
    }

    fn matches_bytes(&self, emitted: &[u8]) -> bool {
        match self {
            Receiver::Solana(key) => {
                emitted == key || emitted == bs58::encode(key).into_string().as_bytes()
            }
            Receiver::Bitcoin { text, .. } => emitted.eq_ignore_ascii_case(text.as_bytes()),
            Receiver::Evm(_) => false,
        }
    }
}

/// What the transaction must do, and nothing else.
pub struct Expected<'a> {
    pub user: [u8; 20],
    /// Token sold (`None`: the network's native coin, sent as value).
    pub sell_token: Option<[u8; 20]>,
    pub amount: u128,
    pub diamond: [u8; 20],
    pub destination_chain: u64,
    pub receiver: &'a Receiver,
    pub integrator: Option<&'a str>,
}

/// Outcome of a verification that found nothing abnormal.
#[derive(Debug, PartialEq)]
pub enum Verification {
    /// Recipient emitted by the contract = recipient shown.
    Verified,
    /// The bridge keeps the recipient off-chain: route to drop.
    ReceiverHidden { bridge: String },
}

fn topic(signature: &str) -> [u8; 32] {
    evm_sign::keccak(signature.as_bytes())
}

fn padded(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn check_bridge_data(bridge: &BridgeData, expected: &Expected) -> Result<()> {
    ensure!(
        bridge.destination_chain == expected.destination_chain,
        "la transaction LI.FI vise un autre réseau d'arrivée — refus de signer"
    );
    ensure!(!bridge.has_destination_call, "la transaction LI.FI appellerait un contrat à l'arrivée (destinataire final invérifiable) — refus de signer");
    if let Some(integrator) = expected.integrator {
        ensure!(
            bridge.integrator == integrator,
            "transaction LI.FI d'un autre intégrateur — refus de signer"
        );
    }
    match expected.receiver {
        Receiver::Evm(address) => ensure!(bridge.receiver == *address, "la transaction LI.FI livrerait à une autre adresse que celle affichée — refus de signer"),
        _ => ensure!(bridge.receiver == NON_EVM_RECEIVER, "la transaction LI.FI livrerait à une adresse EVM au lieu de celle affichée — refus de signer"),
    }
    Ok(())
}

/// Non-EVM recipient emitted by the contract: transfer ID, destination network,
/// address, and form (`bytes32` or raw bytes).
type NonEvmReceiver = ([u8; 32], [u8; 32], Vec<u8>, bool);

/// Checks the simulation of the approval (if any), then of the LI.FI call: all
/// succeed; only the token sold leaves the user, for the exact amount; approvals
/// only to the LI.FI contract, at most the amount; a single LI.FI transfer, to the
/// right network, with no call on arrival; emitted recipient = recipient shown.
/// Pure function.
pub fn verify_simulation(
    calls: &[eth_rpc::SimulatedCall],
    expected: &Expected,
) -> Result<Verification> {
    ensure!(
        calls.iter().all(|c| c.success),
        "la transaction LI.FI échouerait (simulation) — rien n'a été envoyé"
    );
    let (transfer, approval) = (
        topic("Transfer(address,address,uint256)"),
        topic("Approval(address,address,uint256)"),
    );
    let approval_for_all = topic("ApprovalForAll(address,address,bool)");
    let started = topic("LiFiTransferStarted((bytes32,string,string,address,address,address,uint256,uint256,bool,bool))");
    let (non_evm, non_evm_bytes32) = (
        topic("BridgeToNonEVMChain(bytes32,uint256,bytes)"),
        topic("BridgeToNonEVMChainBytes32(bytes32,uint256,bytes32)"),
    );
    let user = padded(&expected.user);
    let mut sent: u128 = 0;
    let mut bridges = Vec::new();
    let mut non_evm_receivers: Vec<NonEvmReceiver> = Vec::new();
    for log in calls.iter().flat_map(|c| &c.logs) {
        let Some(kind) = log.topics.first() else {
            continue;
        };
        // Any transfer or approval FROM the user: only the token sold (ERC-20, 3 topics)
        // is allowed; an NFT (ERC-721, 4 topics) or a global approval (ApprovalForAll) is
        // refused.
        if (*kind == transfer || *kind == approval || *kind == approval_for_all)
            && log.topics.get(1) == Some(&user)
        {
            ensure!(
                *kind != approval_for_all && log.topics.len() == 3,
                "la transaction LI.FI toucherait un autre actif de votre portefeuille (NFT ou autorisation globale) — refus de signer"
            );
            ensure!(
                expected.sell_token == Some(log.address),
                "la transaction LI.FI ferait sortir un autre jeton de votre portefeuille — refus de signer"
            );
            let value = word_u128(&log.data, 0)?;
            if *kind == transfer {
                sent = sent.checked_add(value).context("montant hors limites")?;
            } else {
                ensure!(
                    log.topics[2] == padded(&expected.diamond) && value <= expected.amount,
                    "la transaction LI.FI autoriserait un autre contrat ou un autre montant — refus de signer"
                );
            }
        } else if log.address == expected.diamond && *kind == started {
            bridges.push(decode_bridge_data(&log.data)?);
        } else if log.address == expected.diamond
            && (*kind == non_evm || *kind == non_evm_bytes32)
            && log.topics.len() == 3
        {
            let receiver = if *kind == non_evm_bytes32 {
                word(&log.data, 0)?.to_vec()
            } else {
                abi_bytes(&log.data, word_usize(&log.data, 0)?)?.to_vec()
            };
            non_evm_receivers.push((
                log.topics[1],
                log.topics[2],
                receiver,
                *kind == non_evm_bytes32,
            ));
        }
    }
    ensure!(
        sent == if expected.sell_token.is_some() {
            expected.amount
        } else {
            0
        },
        "la transaction LI.FI ferait sortir {sent} unité(s) au lieu de {} — refus de signer",
        expected.amount
    );
    let [bridge] = bridges.as_slice() else {
        bail!("la transaction LI.FI n'émet pas exactement un transfert — refus de signer")
    };
    check_bridge_data(bridge, expected)?;
    if matches!(expected.receiver, Receiver::Evm(_)) {
        return Ok(Verification::Verified);
    }
    let chain = {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&expected.destination_chain.to_be_bytes());
        word
    };
    let emitted: Vec<_> = non_evm_receivers
        .iter()
        .filter(|(id, c, _, _)| *id == bridge.transaction_id && *c == chain)
        .collect();
    if emitted.is_empty() {
        return Ok(Verification::ReceiverHidden {
            bridge: bridge.bridge.clone(),
        });
    }
    for (_, _, receiver, is_bytes32) in emitted {
        let matches = if *is_bytes32 {
            receiver
                .as_slice()
                .try_into()
                .is_ok_and(|w: [u8; 32]| expected.receiver.matches_bytes32(&w))
        } else {
            expected.receiver.matches_bytes(receiver)
        };
        ensure!(matches, "la transaction LI.FI livrerait à une autre adresse que celle affichée — refus de signer");
    }
    Ok(Verification::Verified)
}

/// Verification without simulation (Avalanche): `BridgeData` read from the call.
/// EVM destination only, recipient = the one shown, right network, no call on
/// arrival, token sent = token sold unless it is swapped first. What leaves the
/// user stays bounded by the app: approval for the exact amount, native value
/// checked at quote time.
pub fn verify_static(calldata: &[u8], expected: &Expected) -> Result<()> {
    ensure!(
        matches!(expected.receiver, Receiver::Evm(_)),
        "sur ce réseau, LI.FI n'est proposé que vers un réseau EVM"
    );
    let bridge = decode_call_bridge_data(calldata)?;
    check_bridge_data(&bridge, expected)?;
    if !bridge.has_source_swaps {
        ensure!(
            bridge.sending_asset == expected.sell_token.unwrap_or([0u8; 20]),
            "la transaction LI.FI enverrait un autre jeton — refus de signer"
        );
    }
    Ok(())
}

// --- Tracking ------------------------------------------------------------------

/// State of a transfer ("NOT_FOUND", "PENDING", "DONE", "FAILED"), followed by the
/// substate for "DONE" ("DONE:COMPLETED", "DONE:REFUNDED"…).
pub fn status(tx_hash: &str, from_chain: u64, to_chain: u64) -> Result<String> {
    // Comes from the UI and goes into the URL: exact format required.
    let hash = tx_hash.trim_start_matches("0x");
    ensure!(
        !hash.is_empty() && hash.len() <= 100 && hash.bytes().all(|b| b.is_ascii_alphanumeric()),
        "identifiant de transaction invalide"
    );
    let response: Value = shared_client()
        .get(format!("{API_BASE}/status"))
        .query(&[
            ("txHash", tx_hash.to_string()),
            ("fromChain", from_chain.to_string()),
            ("toChain", to_chain.to_string()),
        ])
        .send()
        .context("suivi LI.FI impossible")?
        .json()
        .context("réponse de suivi LI.FI illisible")?;
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("NOT_FOUND");
    Ok(match response.get("substatus").and_then(Value::as_str) {
        Some(sub) if status == "DONE" => format!("DONE:{sub}"),
        _ => status.to_string(),
    })
}

/// A transaction's page on LI.FI Scan.
pub fn explorer_url(tx_hash: &str) -> String {
    format!("https://scan.li.fi/tx/{tx_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_rpc::{SimulatedCall, SimulatedLog};

    /// Real call returned by LI.FI on 2026-10-02 (10 LINK on Ethereum → RENDER on
    /// Solana, bridge "relaydepository", `swapAndStartBridgeTokensViaRelayDepository`).
    const REAL_CALLDATA: &str = "0xa3443faa0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000024039c2562bd5b5a02e7a2a86c771b83a11f0ba77c0aca5a3dd2d8d8d664c656f9d00000000000000000000000059d78c44ac60f09369b544778358704b7b18e6ba632d49ef8427b270f90367c38ee0a356c1d20ea4b4f95b78568878e11db5d515000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000011f111f111f111f111f111f111f111f111f111f100000000000000000000000000000000000000000000000000b9be0a563d6e95000000000000000000000000000000000000000000000000000416edef1601be00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f72656c61796465706f7369746f7279000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086c6966692d617069000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000ce40449b773a3e6e5e769adb4e567179d4828cbd000000000000000000000000ce40449b773a3e6e5e769adb4e567179d4828cbd000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a4332d746b000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c06ebbefd94032b85424d51906e2a335efae264b0000000000000000000000000000000000000000000000000058d15e1762800000000000000000000000000000000000000000000000000000000000000000000000000000000000a929c559e5e6537359680f39cb4e3708e1a14dd1000000000000000000000000a929c559e5e6537359680f39cb4e3708e1a14dd1000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000008a6e51a67285800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bf3f0bde25eb7422ec88b9ff78c6f2458ab1a7aa8bb99d84bd4b8600000000000000008a6e51a672858000000000000000000000b9be0a563d6e960622ec88b9ff78c6f2458ab1a7aa8bb99d84bd4b861231deb6f5749ef6ce6943a275a1d3e7486f4eae514910771af9ca656af840dff83e8264ecf986cac02aaa39b223fe8d0a0e5c4f27ead9083c756cc228bf6006d87de7f44445905aa4f5cb8c0d8cba025d4f3c6fa16908609bac31ff148bd002aa6b8c8347050204f928bb9f900301ff00";
    /// `LiFiTransferStarted` data encoded by ethers (official ABI).
    const EVENT_TO_SOLANA: &str = "00000000000000000000000000000000000000000000000000000000000000201111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000011f111f111f111f111f111f111f111f111f111f10000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000416edef1601be0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000056d6179616e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046f70677000000000000000000000000000000000000000000000000000000000";
    const EVENT_TO_ARBITRUM: &str = "00000000000000000000000000000000000000000000000000000000000000201111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000a4b10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066163726f7373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046f70677000000000000000000000000000000000000000000000000000000000";
    const EVENT_WITH_DESTINATION_CALL: &str = "00000000000000000000000000000000000000000000000000000000000000201111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca00000000000000000000000011f111f111f111f111f111f111f111f111f111f10000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000416edef1601be0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000056d6179616e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046f70677000000000000000000000000000000000000000000000000000000000";
    /// Data of a `BridgeToNonEVMChain(bytes)` event carrying a Bitcoin address as text.
    const BYTES_RECEIVER_EVENT: &str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002a6263317139777a3036756a327534736d76777532716e6c68616c6c6b7966716d6c35346877613030797500000000000000000000000000000000000000000000";
    const LINK: &str = "0x514910771af9ca656af840dff83e8264ecf986ca";
    const DIAMOND: &str = "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE";
    const USER: [u8; 20] = [0x33; 20];
    const AMOUNT: u128 = 10_000_000_000_000_000_000;
    const SOLANA_USER: &str = "4PUcVV4Ax8jXHXsGaRZfh69oRkeRGJyGZbDBPFUD2okm";

    fn addr(s: &str) -> [u8; 20] {
        wallet_flow::parse_evm_address(s).unwrap()
    }

    fn word(v: u128) -> Vec<u8> {
        let mut w = vec![0u8; 16];
        w.extend_from_slice(&v.to_be_bytes());
        w
    }

    fn erc20_log(
        signature: &str,
        token: &str,
        from: [u8; 20],
        to: [u8; 20],
        value: u128,
    ) -> SimulatedLog {
        SimulatedLog {
            address: addr(token),
            topics: vec![topic(signature), padded(&from), padded(&to)],
            data: word(value),
        }
    }

    fn started(event_hex: &str) -> SimulatedLog {
        SimulatedLog {
            address: addr(DIAMOND),
            topics: vec![topic("LiFiTransferStarted((bytes32,string,string,address,address,address,uint256,uint256,bool,bool))")],
            data: hex::decode(event_hex).unwrap(),
        }
    }

    fn chain_word(chain: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&chain.to_be_bytes());
        w
    }

    fn non_evm_bytes32(receiver: [u8; 32], chain: u64) -> SimulatedLog {
        SimulatedLog {
            address: addr(DIAMOND),
            topics: vec![
                topic("BridgeToNonEVMChainBytes32(bytes32,uint256,bytes32)"),
                [0x11; 32],
                chain_word(chain),
            ],
            data: receiver.to_vec(),
        }
    }

    fn calls(logs: Vec<SimulatedLog>) -> Vec<SimulatedCall> {
        vec![SimulatedCall {
            success: true,
            logs,
        }]
    }

    fn token_flow() -> Vec<SimulatedLog> {
        vec![
            erc20_log(
                "Approval(address,address,uint256)",
                LINK,
                USER,
                addr(DIAMOND),
                AMOUNT,
            ),
            erc20_log(
                "Transfer(address,address,uint256)",
                LINK,
                USER,
                addr(DIAMOND),
                AMOUNT,
            ),
        ]
    }

    fn expected(receiver: &Receiver, destination_chain: u64) -> Expected<'_> {
        Expected {
            user: USER,
            sell_token: Some(addr(LINK)),
            amount: AMOUNT,
            diamond: addr(DIAMOND),
            destination_chain,
            receiver,
            integrator: Some("opgp"),
        }
    }

    fn solana_receiver() -> Receiver {
        Receiver::parse("sol_mainnet", SOLANA_USER).unwrap()
    }

    /// `BridgeData` decoding identical to ethers' on a real call.
    #[test]
    fn bridge_data_matches_the_official_abi_decoding() {
        let bridge =
            decode_call_bridge_data(&hex::decode(REAL_CALLDATA.trim_start_matches("0x")).unwrap())
                .unwrap();
        assert_eq!(
            hex::encode(bridge.transaction_id),
            "632d49ef8427b270f90367c38ee0a356c1d20ea4b4f95b78568878e11db5d515"
        );
        assert_eq!(
            (bridge.bridge.as_str(), bridge.integrator.as_str()),
            ("relaydepository", "lifi-api")
        );
        assert_eq!(
            bridge.sending_asset,
            addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        );
        assert_eq!(bridge.receiver, NON_EVM_RECEIVER);
        assert_eq!(
            (bridge.min_amount, bridge.destination_chain),
            (52_281_822_297_288_341, SOLANA_CHAIN)
        );
        assert!(bridge.has_source_swaps && !bridge.has_destination_call);
    }

    /// Recipient emitted by the contract = recipient shown: verified. A bridge that
    /// does not emit it: flagged to be dropped.
    #[test]
    fn shown_receiver_must_be_emitted_by_the_contract() {
        let receiver = solana_receiver();
        let Receiver::Solana(key) = receiver else {
            unreachable!()
        };
        let mut logs = token_flow();
        logs.push(started(EVENT_TO_SOLANA));
        let without_receiver = logs.clone();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert_eq!(
            verify_simulation(&calls(logs), &expected(&receiver, SOLANA_CHAIN)).unwrap(),
            Verification::Verified
        );
        assert_eq!(
            verify_simulation(&calls(without_receiver), &expected(&receiver, SOLANA_CHAIN))
                .unwrap(),
            Verification::ReceiverHidden {
                bridge: "mayan".into()
            }
        );
        let arbitrum = Receiver::Evm([0x22; 20]);
        let mut logs = token_flow();
        logs.push(started(EVENT_TO_ARBITRUM));
        assert_eq!(
            verify_simulation(&calls(logs), &expected(&arbitrum, 42161)).unwrap(),
            Verification::Verified
        );
    }

    /// Every diversion is refused, never flagged as just a hidden bridge.
    #[test]
    fn diversions_are_refused() {
        let receiver = solana_receiver();
        let Receiver::Solana(key) = receiver else {
            unreachable!()
        };
        let run = |logs: Vec<SimulatedLog>, receiver: &Receiver, chain: u64| {
            verify_simulation(&calls(logs), &expected(receiver, chain))
        };
        let base = || {
            let mut logs = token_flow();
            logs.push(started(EVENT_TO_SOLANA));
            logs
        };
        // A different recipient emitted.
        let mut logs = base();
        logs.push(non_evm_bytes32([0x44; 32], SOLANA_CHAIN));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Another token leaves the user.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(erc20_log(
            "Transfer(address,address,uint256)",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            USER,
            [0x99; 20],
            1,
        ));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Approval to another contract.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(erc20_log(
            "Approval(address,address,uint256)",
            LINK,
            USER,
            [0x99; 20],
            AMOUNT,
        ));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // More than the amount.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(erc20_log(
            "Transfer(address,address,uint256)",
            LINK,
            USER,
            [0x99; 20],
            1,
        ));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // Contract call on arrival.
        let mut logs = token_flow();
        logs.push(started(EVENT_WITH_DESTINATION_CALL));
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // A destination network other than the one shown.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert!(run(logs, &receiver, BITCOIN_CHAIN).is_err());
        // Two LI.FI transfers.
        let mut logs = base();
        logs.push(started(EVENT_TO_SOLANA));
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // EVM destination: a different address.
        let mut logs = token_flow();
        logs.push(started(EVENT_TO_ARBITRUM));
        assert!(run(logs, &Receiver::Evm([0x55; 20]), 42161).is_err());
        // NFT (ERC-721: 4 topics) or global approval from the user.
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        let mut nft = erc20_log(
            "Transfer(address,address,uint256)",
            LINK,
            USER,
            [0x99; 20],
            0,
        );
        nft.topics.push([0x01; 32]);
        logs.push(nft);
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        let mut logs = base();
        logs.push(non_evm_bytes32(key, SOLANA_CHAIN));
        logs.push(SimulatedLog {
            address: [0x77; 20],
            topics: vec![
                topic("ApprovalForAll(address,address,bool)"),
                padded(&USER),
                padded(&[0x99; 20]),
            ],
            data: word(1),
        });
        assert!(run(logs, &receiver, SOLANA_CHAIN).is_err());
        // A call that would fail.
        let failed = vec![SimulatedCall {
            success: false,
            logs: vec![],
        }];
        assert!(verify_simulation(&failed, &expected(&receiver, SOLANA_CHAIN)).is_err());
    }

    /// Bitcoin address: five-bit form (taken from a real Layerswap event on 2026-10-02)
    /// and text form.
    #[test]
    fn bitcoin_receiver_forms() {
        let receiver =
            Receiver::parse("btc_mainnet", "bc1q9wz06uj2u4smvwu2qnlhallkyfqml54hwa00yu").unwrap();
        let emitted: [u8; 32] =
            hex::decode("050e020f1a1c120a1c15101b0c0e1c0a00131f171d1f1f160409001b1f141517")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(receiver.matches_bytes32(&emitted));
        let data = hex::decode(BYTES_RECEIVER_EVENT).unwrap();
        assert!(receiver.matches_bytes(abi_bytes(&data, 0x20).unwrap()));
        assert!(
            Receiver::parse("btc_mainnet", "tb1q9wz06uj2u4smvwu2qnlhallkyfqml54hwa00yu").is_err(),
            "réseau de test refusé"
        );
        assert!(
            Receiver::parse("sol_mainnet", "0x2222222222222222222222222222222222222222").is_err()
        );
    }

    /// Without simulation: recipient read from the call, EVM destination only.
    #[test]
    fn static_check_reads_the_receiver_from_the_call() {
        let mut call = vec![0xde, 0xad, 0xbe, 0xef];
        call.extend(hex::decode(EVENT_TO_ARBITRUM).unwrap());
        let arbitrum = Receiver::Evm([0x22; 20]);
        assert!(verify_static(&call, &expected(&arbitrum, 42161)).is_ok());
        assert!(verify_static(&call, &expected(&Receiver::Evm([0x55; 20]), 42161)).is_err());
        assert!(verify_static(&call, &expected(&arbitrum, 8453)).is_err());
        let real = hex::decode(REAL_CALLDATA.trim_start_matches("0x")).unwrap();
        assert!(
            verify_static(&real, &expected(&solana_receiver(), SOLANA_CHAIN)).is_err(),
            "vers Solana : simulation exigée"
        );
    }

    #[test]
    fn tokens_networks_and_contracts() {
        let avax = token("avax", "avax_mainnet").unwrap();
        assert!(avax.native && avax.chain == 43114 && avax.symbol == "AVAX");
        assert_eq!(
            token("render", "sol_mainnet").unwrap().address,
            "rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof"
        );
        assert_eq!(
            token("sol", "sol_mainnet").unwrap().address,
            "11111111111111111111111111111111"
        );
        assert_eq!(token("btc", "btc_mainnet").unwrap().address, "bitcoin");
        assert_eq!(token("evm", "arbitrum_mainnet").unwrap().chain, 42161);
        assert!(token("evm", "evm_sepolia").is_none());
        assert!(
            diamond("hyperevm_mainnet").is_none(),
            "HyperEVM retiré de l'app"
        );
        assert!(!simulates("avax_mainnet") && simulates("bsc_mainnet"));
        let all = tradable();
        assert!(
            all.contains(&("avax", "avax_mainnet"))
                && all.contains(&("render", "sol_mainnet"))
                && all.contains(&("btc", "btc_mainnet"))
        );
    }

    fn to_network_of(address: &str) -> &'static str {
        if address.starts_with("0x") {
            "arbitrum_mainnet"
        } else {
            "sol_mainnet"
        }
    }

    /// Real quotes (live, read-only) in each supported direction.
    #[test]
    #[ignore]
    fn real_quotes() {
        let evm_user = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        for (from, to, amount, from_address, to_address) in [
            (
                ("render", "sol_mainnet"),
                ("link", "evm_mainnet"),
                5_000_000_000u128,
                SOLANA_USER,
                evm_user,
            ),
            (
                ("link", "evm_mainnet"),
                ("render", "sol_mainnet"),
                AMOUNT,
                evm_user,
                SOLANA_USER,
            ),
            (
                ("evm", "evm_mainnet"),
                ("btc", "btc_mainnet"),
                100_000_000_000_000_000,
                evm_user,
                "bc1q9wz06uj2u4smvwu2qnlhallkyfqml54hwa00yu",
            ),
        ] {
            let (f, t) = (token(from.0, from.1).unwrap(), token(to.0, to.1).unwrap());
            let q = quote(
                from.1,
                &f,
                to.1,
                &t,
                amount,
                from_address,
                to_address,
                &[],
                None,
            )
            .unwrap();
            println!(
                "{from:?} → {to:?} : pont {} ({}), attendu {} minimum {} en ~{} s",
                q.tool_name, q.tool, q.to_amount, q.to_amount_min, q.duration_secs
            );
            match q.tx {
                LifiTx::Evm { to, ref data, .. } => {
                    assert_eq!(Some(to), diamond(from.1).map(addr));
                    let bridge = decode_call_bridge_data(data).unwrap();
                    if diamond(to_network_of(to_address)).is_some() {
                        assert_eq!(
                            bridge.receiver,
                            addr(to_address),
                            "vers un réseau EVM, destinataire lu dans l'appel"
                        );
                    }
                }
                LifiTx::Solana { ref raw } => assert!(!raw.is_empty()),
                LifiTx::Bitcoin { ref psbt, .. } => assert!(!psbt.inputs.is_empty()),
            }
        }
    }

    /// Real simulation from a public address holding LINK (read-only):
    /// "relaydepository" hides the recipient, Mayan emits exactly the Solana address
    /// shown.
    #[test]
    #[ignore]
    fn real_simulation_flags_hidden_receivers() {
        let holder = "0x28C6c06298d514Db089934071355E5743bf21d60";
        let (link, render) = (
            token("link", "evm_mainnet").unwrap(),
            token("render", "sol_mainnet").unwrap(),
        );
        let receiver = solana_receiver();
        let rpc = crate::eth_rpc::EthRpc::new(wallet_flow::evm_network("evm_mainnet").unwrap().rpc);
        for (bridge, want_verified) in [("relaydepository", false), ("mayan", true)] {
            let q = quote(
                "evm_mainnet",
                &link,
                "sol_mainnet",
                &render,
                AMOUNT,
                holder,
                SOLANA_USER,
                &[],
                Some(bridge),
            )
            .unwrap();
            let LifiTx::Evm {
                to,
                ref data,
                value,
            } = q.tx
            else {
                panic!("EVM attendu")
            };
            let approve = crate::api::erc20_approve_data(&to, AMOUNT);
            let diamond_str = format!("0x{}", hex::encode(to));
            let sim = rpc
                .simulate_v1(&[
                    crate::eth_rpc::SimCallRequest {
                        from: holder,
                        to: LINK,
                        value: 0,
                        data: &approve,
                    },
                    crate::eth_rpc::SimCallRequest {
                        from: holder,
                        to: &diamond_str,
                        value,
                        data,
                    },
                ])
                .unwrap();
            let exp = Expected {
                user: addr(holder),
                sell_token: Some(addr(LINK)),
                amount: AMOUNT,
                diamond: to,
                destination_chain: SOLANA_CHAIN,
                receiver: &receiver,
                integrator: INTEGRATOR,
            };
            let outcome = verify_simulation(&sim, &exp).unwrap();
            println!("{bridge} : {outcome:?}");
            assert_eq!(outcome == Verification::Verified, want_verified, "{bridge}");
        }
    }

    /// Real BTC → ETH quote (LayerSwap, testdata): read, then its PSBT verified against
    /// the spent output (amount taken from Esplora); every tampering that would cost
    /// the user is refused.
    #[test]
    fn bitcoin_deposits_are_verified_output_by_output() {
        let q: Value =
            serde_json::from_str(include_str!("../testdata/lifi_btc_quote.json")).unwrap();
        let (from, to) = (
            token("btc", "btc_mainnet").unwrap(),
            token("evm", "evm_mainnet").unwrap(),
        );
        let user = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h";
        let evm_user = "0x59D78c44ac60F09369b544778358704B7b18E6ba";
        let quote = parse_quote(
            &q,
            "btc_mainnet",
            &from,
            "evm_mainnet",
            &to,
            1_000_000,
            user,
            evm_user,
        )
        .unwrap();
        assert!(
            parse_quote(
                &q,
                "btc_mainnet",
                &from,
                "evm_mainnet",
                &to,
                900_000,
                user,
                evm_user
            )
            .is_err(),
            "autre montant"
        );
        let LifiTx::Bitcoin {
            psbt,
            deposit,
            deposit_script,
        } = &quote.tx
        else {
            panic!("PSBT attendue")
        };
        assert_eq!(
            deposit,
            "bc1plxa9q77gz9r33g8pd4c2ygzezchjffuedtzdrkclyceseyw8v80qasmquf"
        );
        let own = derivation::btc_mainnet_script_pubkey(user).unwrap();
        let utxos = [btc_tx::Utxo {
            txid: psbt.inputs[0].txid,
            vout: 0,
            value_sat: 24_649_986_775,
        }];
        let check = |psbt: &btc_psbt::Psbt| {
            verify_btc_deposit(psbt, deposit_script, &own, &utxos, 1_000_000, 50)
        };

        let ok = check(psbt).unwrap();
        assert_eq!(
            (ok.network_fee, ok.service_fees, ok.total_debit),
            (1_913, 10_500, 1_001_913)
        );
        assert!((240..=250).contains(&ok.vsize), "{}", ok.vsize);

        let other = |byte: u8| [vec![0x00, 0x14], vec![byte; 20]].concat();
        let altered = |change: &dyn Fn(&mut btc_psbt::Psbt)| {
            let mut copy = psbt.clone();
            change(&mut copy);
            check(&copy).is_err()
        };
        assert!(
            verify_btc_deposit(psbt, deposit_script, &own, &[], 1_000_000, 50).is_err(),
            "sortie absente ou non confirmée"
        );
        assert!(
            verify_btc_deposit(psbt, deposit_script, &own, &utxos, 900_000, 50).is_err(),
            "autre montant"
        );
        assert!(
            verify_btc_deposit(psbt, deposit_script, &own, &utxos, 1_000_000, 5).is_err(),
            "frais réseau au-delà du plafond"
        );
        assert!(
            altered(&|p| {
                p.outputs[4].0 += 5_000;
                p.outputs[2].0 -= 5_000
            }),
            "frais LI.FI gonflés sur la monnaie"
        );
        assert!(
            altered(&|p| p.outputs[2].1 = other(0x66)),
            "monnaie détournée"
        );
        assert!(altered(&|p| p.outputs[0].1 = other(0x77)), "dépôt redirigé");
        assert!(
            altered(&|p| p.outputs[2].0 -= 100_000),
            "frais réseau excessifs"
        );
        assert!(
            altered(&|p| {
                p.outputs[1].0 = 1_000;
                p.outputs[2].0 -= 1_000
            }),
            "memo avec valeur"
        );
        assert!(
            altered(&|p| {
                let dup = p.inputs[0].clone();
                p.inputs.push(dup)
            }),
            "même sortie dépensée deux fois"
        );
        assert!(
            altered(&|p| {
                let dup = p.outputs[0].clone();
                p.outputs.push(dup)
            }),
            "deux dépôts"
        );
        assert!(altered(&|p| p.version = 3), "version inattendue");
        assert!(
            altered(&|p| p.inputs[0].sequence = 144),
            "verrou temporel relatif"
        );
        assert!(
            verify_btc_deposit(psbt, &own, &own, &utxos, 1_000_000, 50).is_err(),
            "dépôt vers soi"
        );
        assert!(
            altered(&|p| {
                p.outputs[0].0 -= 2_000;
                p.outputs[2].0 += 2_000
            }),
            "dépôt réduit au-delà des frais annoncés"
        );
    }

    /// Small amount (real shape recorded on 2026-10-03 for 58,928 sats): LI.FI's share
    /// (147 sats) is rounded up to the dust threshold (294), the difference taken from
    /// the change. Accepted, and counted in the total debited; beyond the threshold,
    /// refused.
    #[test]
    fn small_bitcoin_deposits_allow_the_dust_top_up() {
        let own =
            derivation::btc_mainnet_script_pubkey("bc1q0syth5ya7up2k0jj36uw8l03c2dpru2c3hhjy3")
                .unwrap();
        let deposit_script = derivation::btc_mainnet_script_pubkey(
            "bc1plxa9q77gz9r33g8pd4c2ygzezchjffuedtzdrkclyceseyw8v80qasmquf",
        )
        .unwrap();
        let p2wpkh = |hex_hash: &str| [vec![0x00, 0x14], hex::decode(hex_hash).unwrap()].concat();
        let psbt = |lifi_fee: u64, change: u64| btc_psbt::Psbt {
            version: 2,
            inputs: vec![btc_psbt::PsbtInput {
                txid: [0x28; 32],
                vout: 0,
                sequence: 0xffff_fffd,
            }],
            outputs: vec![
                (58_310, deposit_script.clone()),
                (0, vec![0x6a, 0x02, 0x11, 0xab]),
                (change, own.clone()),
                (lifi_fee, p2wpkh("9ab105ce5f65cc9d3e51e4b2403eef1831eb5bfd")),
                (471, p2wpkh("16ee74e3d28cc8dd0b97e97d191236fb9b568781")),
            ],
            locktime: 0,
        };
        let utxos = [btc_tx::Utxo {
            txid: [0x28; 32],
            vout: 0,
            value_sat: 550_000,
        }];
        let ok = verify_btc_deposit(
            &psbt(294, 489_395),
            &deposit_script,
            &own,
            &utxos,
            58_928,
            50,
        )
        .unwrap();
        assert_eq!(
            (ok.service_fees, ok.network_fee, ok.total_debit),
            (765, 1_530, 60_605)
        );
        assert!(
            verify_btc_deposit(
                &psbt(900, 488_789),
                &deposit_script,
                &own,
                &utxos,
                58_928,
                50
            )
            .is_err(),
            "au-delà du complément de poussière"
        );
    }
}
