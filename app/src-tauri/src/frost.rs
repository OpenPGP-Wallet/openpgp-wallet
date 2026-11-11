//! Commands of the FROST tab: a FROST 2-of-3 shielded Zcash account where this
//! app is member 1 (the coordinator) and a co-signer holds member 2 (core:
//! `zcash_frost`, protocol: frost-zec).
//!
//! Messages to the co-signer are shown as animated QR codes (the UR parts are
//! returned here and drawn by the UI with `generate_qr_svg`); its answers are
//! read with the camera (`frost_scan`) or pasted as `ur:zcash-frost/...` text.
//! The state of a setup or a send lives in `FrostState` between two scans.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use frost_zec::wire;
use openpgp_wallet_core::api;
use openpgp_wallet_core::zcash_frost::{self, Net, PendingSignature, PreparedSend, SetupStep};
use serde::Serialize;
use tauri::{Emitter, Manager};

use crate::{
    data_dir, lang, run_blocking, send_grace_period, shielded_dialog, GraceRecap, TranslatedResult,
};

/// Bytes per QR fragment, as in the frost-zec co-signer: sparse enough for a
/// 640×480 camera (a phone used as a webcam) to read on a screen. 200 was too
/// dense for one.
const FRAGMENT: usize = 120;

#[derive(Default)]
pub struct FrostState {
    setup: Mutex<Option<SetupStep>>,
    prepared: Mutex<Option<PreparedSend>>,
    pending: Mutex<Option<PendingSignature>>,
    scan_cancel: Arc<AtomicBool>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn net(network: &str) -> Result<Net, String> {
    Net::parse(network).t_err()
}

/// A message to show: animated QR parts, and the same payload as one
/// `ur:zcash-frost/...` text for a co-signer that reads text instead.
#[derive(Serialize)]
pub struct QrDto {
    parts: Vec<String>,
    text: String,
}

fn qr(payload: &[u8]) -> Result<QrDto, String> {
    Ok(QrDto {
        parts: parts(payload)?,
        text: wire::single_part(payload).map_err(|e| e.to_string())?,
    })
}

/// The UR parts of a payload, three times around the fountain, to show in a loop.
fn parts(payload: &[u8]) -> Result<Vec<String>, String> {
    let mut encoder = wire::encoder(payload, FRAGMENT).map_err(|e| e.to_string())?;
    let count = encoder.fragment_count();
    (0..count * 3 + 2)
        .map(|_| {
            encoder
                .next_part()
                .map(|part| part.to_ascii_uppercase())
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// A payload from scanned or pasted text: one `ur:zcash-frost/...` text, or
/// several parts separated by spaces or new lines.
fn payload(text: &str) -> Result<Vec<u8>, String> {
    let mut reader = wire::Reader::default();
    for part in text.split_whitespace() {
        if let Some(payload) = reader.receive(part).map_err(|e| e.to_string())? {
            return Ok(payload);
        }
    }
    Err(lang(
        "QR code incomplet : il manque des parties",
        "incomplete QR code: some parts are missing",
    )
    .to_string())
}

/// What the card shows. The group's viewing key stays in the backend: the page
/// does not need it, and it would reveal the account's whole history.
#[derive(Serialize)]
pub struct FrostAccountDto {
    network: String,
    address: String,
    birthday: u32,
    spendable: u64,
    pending: u64,
    scanned_height: Option<u32>,
    chain_height: Option<u32>,
}

/// The FROST accounts that exist, with their balances (local database only).
#[tauri::command]
pub async fn frost_accounts(app: tauri::AppHandle) -> Result<Vec<FrostAccountDto>, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let mut accounts = Vec::new();
        for (network, net) in [("main", Net::Main), ("test", Net::Test)] {
            if let Some(account) = zcash_frost::account(&dir, net).t_err()? {
                let balance = zcash_frost::balance(&dir, net).t_err()?;
                accounts.push(FrostAccountDto {
                    network: network.to_string(),
                    address: account.address,
                    birthday: account.birthday,
                    spendable: balance.spendable,
                    pending: balance.pending,
                    scanned_height: balance.scanned_height,
                    chain_height: balance.chain_height,
                });
            }
        }
        Ok(accounts)
    })
    .await
}

#[tauri::command]
pub async fn frost_sync(network: String, app: tauri::AppHandle) -> Result<(), String> {
    let net = net(&network)?;
    run_blocking(move || zcash_frost::sync(&data_dir(&app)?, net).t_err()).await
}

#[derive(Clone, Serialize)]
struct ScanProgress {
    camera: Option<String>,
    done: usize,
    total: usize,
}

/// Reads the co-signer's next QR code with the camera. Returns it as text for
/// the next step. `frost_scan_cancel` stops it.
#[tauri::command]
pub async fn frost_scan(app: tauri::AppHandle) -> Result<String, String> {
    let cancel = Arc::clone(&app.state::<FrostState>().scan_cancel);
    cancel.store(false, Ordering::Relaxed);
    run_blocking(move || {
        let found = frost_zec::camera::scan(&cancel, |progress| {
            let event = match progress {
                frost_zec::camera::Progress::Camera(name) => ScanProgress {
                    camera: Some(name),
                    done: 0,
                    total: 0,
                },
                frost_zec::camera::Progress::Fragments(done, total) => ScanProgress {
                    camera: None,
                    done,
                    total,
                },
            };
            let _ = app.emit("frost-scan-progress", event);
        })
        .map_err(|e| e.to_string())?;
        let payload =
            found.ok_or_else(|| lang("Lecture annulée.", "Scan cancelled.").to_string())?;
        wire::single_part(&payload).map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub fn frost_scan_cancel(state: tauri::State<'_, FrostState>) {
    state.scan_cancel.store(true, Ordering::Relaxed);
}

/// Forgets any setup or send in progress (the window was closed).
#[tauri::command]
pub fn frost_cancel(state: tauri::State<'_, FrostState>) {
    state.scan_cancel.store(true, Ordering::Relaxed);
    *locked(&state.setup) = None;
    *locked(&state.prepared) = None;
    *locked(&state.pending) = None;
}

// --- Setup --------------------------------------------------------------------------

#[tauri::command]
pub fn frost_setup_start(
    network: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, FrostState>,
) -> Result<QrDto, String> {
    let (step, shown) = zcash_frost::setup_start(&data_dir(&app)?, net(&network)?).t_err()?;
    *locked(&state.setup) = Some(step);
    qr(&shown)
}

#[derive(Serialize)]
pub struct CodeDto {
    qr: QrDto,
    code: String,
}

/// Takes the co-signer's pair-response: shows pair-confirm, and the code.
#[tauri::command]
pub fn frost_setup_response(
    ur: String,
    state: tauri::State<'_, FrostState>,
) -> Result<CodeDto, String> {
    let step = locked(&state.setup).take().ok_or_else(|| {
        lang("Aucune configuration en cours.", "No setup in progress.").to_string()
    })?;
    let (step, shown, code) = zcash_frost::setup_response(step, &payload(&ur)?).t_err()?;
    *locked(&state.setup) = Some(step);
    Ok(CodeDto {
        qr: qr(&shown)?,
        code,
    })
}

/// Asks the user, in a native window the web page cannot draw or click, whether
/// the co-signer shows the same code. The frontend is untrusted: if a
/// compromised one could confirm the code itself, it could pair the wallet with
/// an attacker's co-signer, who would then hold members 2 and 3, two of three.
#[tauri::command]
pub async fn frost_setup_code_confirmed(app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || {
        let state = app.state::<FrostState>();
        // The step leaves the state before the window opens, so the pairing
        // confirmed is the one whose code the window shows.
        let confirmed = zcash_frost::confirm_code(&state.setup, |code| {
            let message = if crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                format!("Pairing code: {code}\n\nDoes your co-signer show exactly this code?\n\nIf it shows another code, choose Cancel: another device may be reading or changing the QR codes.")
            } else {
                format!("Code de jumelage : {code}\n\nVotre co-signataire affiche-t-il exactement ce code ?\n\nS'il affiche un autre code, choisissez Annuler : un autre appareil lit ou modifie peut-être les QR codes.")
            };
            shielded_dialog(&app, ("Comparer le code", "Compare the code"), message)
        })
        .t_err()?;
        if !confirmed {
            return Err(lang(
                "Codes différents : configuration annulée.",
                "The codes differ: setup cancelled.",
            )
            .to_string());
        }
        Ok(())
    })
    .await
}

#[derive(Serialize)]
pub struct SetupDoneDto {
    qr: QrDto,
    address: String,
}

/// Takes the co-signer's keys: finishes the group and stores member 1 (the
/// device password encrypts its seat). Shows the last QR code.
#[tauri::command]
pub async fn frost_setup_finish(
    ur: String,
    password: String,
    app: tauri::AppHandle,
) -> Result<SetupDoneDto, String> {
    let password = zeroize::Zeroizing::new(password);
    run_blocking(move || {
        let state = app.state::<FrostState>();
        let keys = payload(&ur)?;
        // Everything that can fail and be retried comes first: the network
        // (account birthday) and the password. Only then is the setup consumed.
        let net = locked(&state.setup)
            .as_ref()
            .map(SetupStep::net)
            .ok_or_else(|| {
                lang("Aucune configuration en cours.", "No setup in progress.").to_string()
            })?;
        let birthday = zcash_frost::chain_birthday(net).t_err()?;
        api::check_device_password(&data_dir(&app)?, &password).t_err()?;
        let step = locked(&state.setup).take().ok_or_else(|| {
            lang("Aucune configuration en cours.", "No setup in progress.").to_string()
        })?;
        // Another setup may have replaced this one meanwhile.
        if step.net() != net {
            return Err(lang(
                "Étape de configuration inattendue.",
                "Unexpected setup step.",
            )
            .to_string());
        }
        let (shown, account) =
            api::frost_setup_finish(&data_dir(&app)?, &password, step, &keys, &birthday).t_err()?;
        Ok(SetupDoneDto {
            qr: qr(&shown)?,
            address: account.address,
        })
    })
    .await
}

// --- Send ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SummaryDto {
    amount: String,
    fee: String,
    recipient: String,
}

/// Builds the PCZT for a payment, then asks for confirmation in a native
/// window and runs the cancellation delay, before anything is signed.
#[tauri::command]
pub async fn frost_send_prepare(
    network: String,
    to: String,
    amount: String,
    memo: Option<String>,
    app: tauri::AppHandle,
) -> Result<SummaryDto, String> {
    let net = net(&network)?;
    run_blocking(move || {
        let amount = api::canonical_zec_amount(&amount).t_err()?;
        let units = u64::try_from(openpgp_wallet_core::tokens::parse_amount(&amount, 8).t_err()?)
            .map_err(|_| lang("montant hors limites", "amount out of range").to_string())?;
        let prepared =
            zcash_frost::send_prepare(&data_dir(&app)?, net, &to, units, memo.as_deref()).t_err()?;
        let (amount, fee) = (
            openpgp_wallet_core::zcash::format_zec(prepared.summary.amount),
            openpgp_wallet_core::zcash::format_zec(prepared.summary.fee),
        );
        let recipient = prepared.summary.recipient.clone();
        let network_name = match net {
            Net::Main => "Zcash",
            Net::Test => lang("Zcash (réseau de test)", "Zcash (testnet)"),
        };
        // Escaped as the co-signer shows it: new lines or direction marks in a
        // memo cannot draw fake lines in the window.
        let memo_line = memo
            .as_deref()
            .filter(|m| !m.is_empty())
            .map(|m| {
                format!(
                    "\n{} {}",
                    lang("Mémo :", "Memo:"),
                    frost_zec::check::printable(m)
                )
            })
            .unwrap_or_default();
        let message = if crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("Send from your FROST 2-of-3 account ({network_name})\n\nTo: {recipient}\nAmount: {amount} ZEC\nNetwork fee: {fee} ZEC{memo_line}\n\nYour co-signer will check and approve it too.\nThis is irreversible once signed.\n\nConfirm this transfer?")
        } else {
            format!("Envoi depuis votre compte FROST 2-of-3 ({network_name})\n\nVers : {recipient}\nMontant : {amount} ZEC\nFrais réseau : {fee} ZEC{memo_line}\n\nVotre co-signataire le vérifiera et l'approuvera aussi.\nC'est irréversible une fois signé.\n\nConfirmer cet envoi ?")
        };
        if !shielded_dialog(&app, ("Confirmer l'envoi", "Confirm the transfer"), message) {
            return Err(lang("Envoi annulé (confirmation refusée).", "Transfer cancelled (confirmation refused).").to_string());
        }
        send_grace_period(
            &app,
            GraceRecap::new(network_name, format!("{amount} ZEC"), recipient.clone()).on("zec_shielded"),
        )?;
        *locked(&app.state::<FrostState>().prepared) = Some(prepared);
        Ok(SummaryDto { amount, fee, recipient })
    })
    .await
}

#[derive(Serialize)]
pub struct RequestDto {
    qr: QrDto,
    /// The coordinator's own reading of the PCZT, as the co-signer will see it.
    lines: Vec<String>,
}

/// Takes the co-signer's commitments; shows the signing request.
#[tauri::command]
pub async fn frost_send_request(
    ur: String,
    password: String,
    app: tauri::AppHandle,
) -> Result<RequestDto, String> {
    let password = zeroize::Zeroizing::new(password);
    run_blocking(move || {
        let state = app.state::<FrostState>();
        let commitments = payload(&ur)?;
        api::check_device_password(&data_dir(&app)?, &password).t_err()?;
        let prepared = locked(&state.prepared)
            .take()
            .ok_or_else(|| lang("Aucun envoi en cours.", "No transfer in progress.").to_string())?;
        let (pending, shown, report) =
            match api::frost_send_request(&data_dir(&app)?, &password, &prepared, &commitments) {
                Ok(result) => result,
                Err(e) => {
                    // The user approved this send: keep it for another scan,
                    // unless another send was approved meanwhile.
                    locked(&state.prepared).get_or_insert(prepared);
                    return Err(e).t_err();
                }
            };
        *locked(&state.pending) = Some(pending);
        Ok(RequestDto {
            qr: qr(&shown)?,
            lines: report.lines,
        })
    })
    .await
}

/// Takes the co-signer's reply: aggregates, proves and broadcasts. Returns the
/// transaction id.
#[tauri::command]
pub async fn frost_send_finish(ur: String, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let state = app.state::<FrostState>();
        let reply = payload(&ur)?;
        let pending = locked(&state.pending).take().ok_or_else(|| {
            lang("Aucune signature en cours.", "No signature in progress.").to_string()
        })?;
        zcash_frost::send_finish(&data_dir(&app)?, pending, &reply).t_err()
    })
    .await
}
