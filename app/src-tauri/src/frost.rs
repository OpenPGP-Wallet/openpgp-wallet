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
use openpgp_wallet_core::zcash_frost::{
    self, Net, PendingSignature, PreparedSend, RecoveryInput, SetupStep,
};
use serde::Serialize;
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::{
    data_dir, lang, run_blocking, send_grace_period, shielded_dialog, translate_error, GraceRecap,
    TranslatedResult,
};

/// Bytes per QR fragment, as in the frost-zec co-signer: sparse enough for a
/// 640×480 camera (a phone used as a webcam) to read on a screen. 200 was too
/// dense for one.
const FRAGMENT: usize = 120;

#[derive(Default)]
pub struct FrostState {
    setup: Mutex<Option<SetupStep>>,
    /// During a recovery: member 3's backup, read and checked, until the
    /// setup's last step stores the old account.
    recovery: Mutex<Option<RecoveryInput>>,
    /// The backup file picked for a recovery, read by the backend only.
    picked: Mutex<Option<zeroize::Zeroizing<Vec<u8>>>>,
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
    /// False until the co-signer acknowledged the end of the setup
    /// (`frost_setup_done`): the page then gets no address and offers no way
    /// to receive.
    confirmed: bool,
    /// An old account a recovery sweeps to the current one (frost-zec spec
    /// § 7.2): its card offers the sweep and its removal, nothing else.
    old: bool,
}

/// The unit amounts are shown in: testnet coins are not ZEC.
fn unit(net: Net) -> &'static str {
    match net {
        Net::Main => "ZEC",
        Net::Test => "TAZ",
    }
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
                    // No address before the co-signer acknowledged: funds sent
                    // to an account it may not hold would be stuck.
                    address: if account.confirmed {
                        account.address
                    } else {
                        String::new()
                    },
                    birthday: account.birthday,
                    spendable: balance.spendable,
                    pending: balance.pending,
                    scanned_height: balance.scanned_height,
                    chain_height: balance.chain_height,
                    confirmed: account.confirmed,
                    old: false,
                });
            }
            if let Some(account) = zcash_frost::old_account(&dir, net).t_err()? {
                let balance = zcash_frost::balance_old(&dir, net).t_err()?;
                accounts.push(FrostAccountDto {
                    network: network.to_string(),
                    address: account.address,
                    birthday: account.birthday,
                    spendable: balance.spendable,
                    pending: balance.pending,
                    scanned_height: balance.scanned_height,
                    chain_height: balance.chain_height,
                    confirmed: true,
                    old: true,
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
    run_blocking(move || {
        let dir = data_dir(&app)?;
        zcash_frost::sync(&dir, net).t_err()?;
        // The old account of a recovery, scanned until it is swept.
        zcash_frost::sync_old(&dir, net).t_err()
    })
    .await
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
    *locked(&state.recovery) = None;
    *locked(&state.picked) = None;
}

/// The co-signer's message on the clipboard, for the "Paste" button. Only a
/// `ur:zcash-frost/...` text is returned: anything else copied (a password,
/// say) never reaches the page.
#[tauri::command]
pub async fn frost_clipboard() -> Result<Option<String>, String> {
    run_blocking(|| {
        let copied = arboard::Clipboard::new()
            .and_then(|mut board| board.get_text())
            .unwrap_or_default();
        let text = copied.trim();
        let prefix = format!("ur:{}/", wire::UR_TYPE);
        let ours = text
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(&prefix));
        Ok(ours.then(|| text.to_string()))
    })
    .await
}

/// Takes the FROST account on `network` out of the wallet, so that a new one
/// can be set up there (core: `zcash_frost::remove`, which sets its files
/// aside and deletes nothing). Asked in a native window the web page cannot
/// draw or click. Returns false if the user said no.
#[tauri::command]
pub async fn frost_remove(network: String, app: tauri::AppHandle) -> Result<bool, String> {
    let net = net(&network)?;
    run_blocking(move || {
        let dir = data_dir(&app)?;
        if zcash_frost::account(&dir, net).t_err()?.is_none() {
            return Err(lang(
                "Aucun compte FROST sur ce réseau.",
                "No FROST account on this network.",
            )
            .to_string());
        }
        // A broken account must stay removable: an unreadable balance is said
        // as such, it does not block.
        let held = zcash_frost::balance(&dir, net)
            .ok()
            .map(|balance| balance.spendable.saturating_add(balance.pending));
        let english = crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
        let network_name = match (net, english) {
            (Net::Main, _) => "Mainnet",
            (Net::Test, true) => "testnet",
            (Net::Test, false) => "réseau de test",
        };
        let funds = match held {
            Some(0) => String::new(),
            Some(zats) => {
                let amount = openpgp_wallet_core::zcash::format_zec(zats);
                let unit = unit(net);
                if english {
                    format!("\n\nIt still holds {amount} {unit}.")
                } else {
                    format!("\n\nIl contient encore {amount} {unit}.")
                }
            }
            None => lang(
                "\n\nSon solde n'a pas pu être lu.",
                "\n\nIts balance could not be read.",
            )
            .to_string(),
        };
        let message = if english {
            format!("Remove the FROST account ({network_name}) from this wallet?{funds}\n\nNothing is deleted: its files are set aside in the wallet's data folder ({}). Putting them back restores the account and its funds.\n\nYou can then create a new FROST account on this network.", zcash_frost::REMOVED_DIR)
        } else {
            format!("Retirer le compte FROST ({network_name}) de ce portefeuille ?{funds}\n\nRien n'est effacé : ses fichiers sont mis de côté dans le dossier de données du portefeuille ({}). Les remettre en place rend le compte et ses fonds.\n\nVous pourrez ensuite créer un nouveau compte FROST sur ce réseau.", zcash_frost::REMOVED_DIR)
        };
        if !shielded_dialog(
            &app,
            ("Retirer le compte FROST", "Remove the FROST account"),
            message,
        ) {
            return Ok(false);
        }
        // A setup or a send left half-way goes with the account.
        frost_cancel(app.state::<FrostState>());
        zcash_frost::remove(&dir, net).t_err()?;
        Ok(true)
    })
    .await
}

/// Whether the recipient typed in the send form can be paid from the FROST
/// account on `network` (core: `zcash_frost::check_recipient`), for the line
/// under the field as it is typed. No I/O, so a plain synchronous command.
#[tauri::command]
pub fn frost_check_recipient(network: String, to: String) -> Result<(), String> {
    zcash_frost::check_recipient(net(&network)?, &to).t_err()
}

// --- Recovery after a lost wallet (frost-zec spec § 7.2) ---------------------------

/// Opens the native "Open" window for member 3's backup (a backup file from
/// the co-signer, or a bare backup string) and keeps its bytes here: they never
/// reach the page. Returns the file's name, or `None` if the user cancelled.
#[tauri::command]
pub async fn frost_recover_pick(app: tauri::AppHandle) -> Result<Option<String>, String> {
    run_blocking(move || {
        let Some(file_path) = app
            .dialog()
            .file()
            .add_filter(
                lang("Sauvegarde du membre 3", "Member 3 backup"),
                &["zkfrost", "txt"],
            )
            .add_filter(lang("Tous les fichiers", "All files"), &["*"])
            .blocking_pick_file()
        else {
            return Ok(None);
        };
        let path = file_path.into_path().t_err()?;
        let size = std::fs::metadata(&path)
            .map(|m| m.len())
            .unwrap_or(u64::MAX);
        if size > zcash_frost::BACKUP_FILE_MAX as u64 {
            return Err(lang(
                "Fichier anormalement gros pour une sauvegarde du membre 3.",
                "File unusually large for a member 3 backup.",
            )
            .to_string());
        }
        let bytes = zeroize::Zeroizing::new(std::fs::read(&path).map_err(|e| e.to_string())?);
        *locked(&app.state::<FrostState>().picked) = Some(bytes);
        Ok(Some(
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ))
    })
    .await
}

/// Starts a recovery on `network`: member 3's backup, picked above, is read
/// and checked under its passphrase before any pairing, then the setup starts
/// as for a new account. Returns pair-init.
#[tauri::command]
pub async fn frost_recover_start(
    network: String,
    passphrase: String,
    app: tauri::AppHandle,
) -> Result<QrDto, String> {
    let net = net(&network)?;
    let passphrase = zeroize::Zeroizing::new(passphrase);
    run_blocking(move || {
        let state = app.state::<FrostState>();
        let dir = data_dir(&app)?;
        if zcash_frost::old_account(&dir, net).t_err()?.is_some() {
            return Err(translate_error(zcash_frost::OLD_EXISTS));
        }
        let input = {
            let picked = locked(&state.picked);
            let bytes = picked.as_ref().ok_or_else(|| {
                lang(
                    "Choisissez d'abord le fichier de sauvegarde du membre 3.",
                    "Choose member 3's backup file first.",
                )
                .to_string()
            })?;
            zcash_frost::recovery_input(bytes, &passphrase).t_err()?
        };
        let (step, shown) = zcash_frost::setup_start(&dir, net).t_err()?;
        *locked(&state.setup) = Some(step);
        *locked(&state.recovery) = Some(input);
        *locked(&state.picked) = None;
        qr(&shown)
    })
    .await
}

/// The sweep of a recovery: every spendable note of the old account to the
/// new one. Confirmed in a native window, then the cancellation delay; the
/// signing goes on as for any send (`frost_send_request`, `frost_send_finish`).
#[tauri::command]
pub async fn frost_sweep_prepare(
    network: String,
    app: tauri::AppHandle,
) -> Result<SummaryDto, String> {
    let net = net(&network)?;
    run_blocking(move || {
        let prepared = zcash_frost::sweep_prepare(&data_dir(&app)?, net).t_err()?;
        let (amount, fee) = (
            openpgp_wallet_core::zcash::format_zec(prepared.summary.amount),
            openpgp_wallet_core::zcash::format_zec(prepared.summary.fee),
        );
        let recipient = prepared.summary.recipient.clone();
        let unit = unit(net);
        let network_name = match net {
            Net::Main => "Zcash",
            Net::Test => lang("Zcash (réseau de test)", "Zcash (testnet)"),
        };
        let message = if crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("Move everything from the old FROST account to the new one ({network_name})\n\nTo the new account: {recipient}\nAmount: {amount} {unit}\nNetwork fee: {fee} {unit}\n\nThe co-signer will check and approve it too, with member 3 restored on this computer.\nThis is irreversible once signed.\n\nConfirm this transfer?")
        } else {
            format!("Tout transférer de l'ancien compte FROST vers le nouveau ({network_name})\n\nVers le nouveau compte : {recipient}\nMontant : {amount} {unit}\nFrais réseau : {fee} {unit}\n\nLe co-signataire le vérifiera et l'approuvera aussi, avec le membre 3 restauré sur cet ordinateur.\nC'est irréversible une fois signé.\n\nConfirmer ce transfert ?")
        };
        if !shielded_dialog(
            &app,
            ("Transférer l'ancien compte", "Move the old account"),
            message,
        ) {
            return Err(lang(
                "Transfert annulé (confirmation refusée).",
                "Transfer cancelled (confirmation refused).",
            )
            .to_string());
        }
        send_grace_period(
            &app,
            GraceRecap::new(network_name, format!("{amount} {unit}"), recipient.clone())
                .on("zec_shielded"),
        )?;
        *locked(&app.state::<FrostState>().prepared) = Some(prepared);
        Ok(SummaryDto {
            amount,
            fee,
            recipient,
        })
    })
    .await
}

/// Takes a swept old account out of the wallet (core: `zcash_frost::remove_old`,
/// which sets its files aside and deletes nothing). Asked in a native window.
#[tauri::command]
pub async fn frost_remove_old(network: String, app: tauri::AppHandle) -> Result<bool, String> {
    let net = net(&network)?;
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let held = zcash_frost::balance_old(&dir, net)
            .ok()
            .map(|b| b.spendable.saturating_add(b.pending));
        let unit = unit(net);
        let funds = match held {
            Some(0) => String::new(),
            Some(zats) => {
                let amount = openpgp_wallet_core::zcash::format_zec(zats);
                if crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                    format!("\n\nIt still holds {amount} {unit}: move it to the new account first.")
                } else {
                    format!("\n\nIl contient encore {amount} {unit} : transférez-les d'abord vers le nouveau compte.")
                }
            }
            None => String::new(),
        };
        let message = if crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("Remove the old FROST account from this wallet?{funds}\n\nNothing is deleted: its files, member 3 restored included, are set aside in the wallet's data folder ({}). Delete them yourself once the transfer is confirmed.", zcash_frost::REMOVED_DIR)
        } else {
            format!("Retirer l'ancien compte FROST de ce portefeuille ?{funds}\n\nRien n'est effacé : ses fichiers, membre 3 restauré compris, sont mis de côté dans le dossier de données du portefeuille ({}). Supprimez-les vous-même une fois le transfert confirmé.", zcash_frost::REMOVED_DIR)
        };
        if !shielded_dialog(
            &app,
            ("Retirer l'ancien compte", "Remove the old account"),
            message,
        ) {
            return Ok(false);
        }
        zcash_frost::remove_old(&dir, net).t_err()?;
        Ok(true)
    })
    .await
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

/// Takes the co-signer's keys: finishes the group and stores member 1 (the
/// device password encrypts its seat), unconfirmed. Shows the last QR code;
/// the co-signer's acknowledgement comes next (`frost_setup_done`).
#[tauri::command]
pub async fn frost_setup_finish(
    ur: String,
    password: String,
    app: tauri::AppHandle,
) -> Result<QrDto, String> {
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
        // A recovery also scans the old account, from its own birthday.
        let old_birthday = match locked(&state.recovery).as_ref() {
            Some(input) => Some(zcash_frost::recovery_birthday(net, input).t_err()?),
            None => None,
        };
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
        let recovery = locked(&state.recovery).take();
        let result = api::frost_setup_finish(
            &data_dir(&app)?,
            &password,
            step,
            &keys,
            &birthday,
            recovery.as_ref().zip(old_birthday.as_ref()),
        );
        let (shown, step) = match result {
            Ok(done) => done,
            Err(e) => {
                // The setup is consumed; the backup is kept for another try.
                *locked(&state.recovery) = recovery;
                return Err(e).t_err();
            }
        };
        *locked(&state.setup) = Some(step);
        qr(&shown)
    })
    .await
}

/// Takes the co-signer's acknowledgement: once it matches, the account is
/// confirmed and its address is returned, the first time the page gets it. A
/// wrong paste leaves the setup waiting for the right one.
#[tauri::command]
pub async fn frost_setup_done(ur: String, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let state = app.state::<FrostState>();
        let acknowledgement = payload(&ur)?;
        let dir = data_dir(&app)?;
        let mut slot = locked(&state.setup);
        let step = slot.as_ref().ok_or_else(|| {
            lang("Aucune configuration en cours.", "No setup in progress.").to_string()
        })?;
        let account = zcash_frost::setup_done(&dir, step, &acknowledgement).t_err()?;
        *slot = None;
        Ok(account.address)
    })
    .await
}

/// Takes the co-signer's acknowledgement for an account whose setup was left
/// unfinished (the app was closed before it came): the device password unlocks
/// the seat, from which the wallet checks it.
#[tauri::command]
pub async fn frost_setup_done_later(
    network: String,
    ur: String,
    password: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let net = net(&network)?;
    let password = zeroize::Zeroizing::new(password);
    run_blocking(move || {
        let acknowledgement = payload(&ur)?;
        let dir = data_dir(&app)?;
        api::check_device_password(&dir, &password).t_err()?;
        api::frost_setup_done_later(&dir, &password, net, &acknowledgement).t_err()?;
        Ok(())
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
        let unit = unit(net);
        let message = if crate::UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("Send from your FROST 2-of-3 account ({network_name})\n\nTo: {recipient}\nAmount: {amount} {unit}\nNetwork fee: {fee} {unit}{memo_line}\n\nYour co-signer will check and approve it too.\nThis is irreversible once signed.\n\nConfirm this transfer?")
        } else {
            format!("Envoi depuis votre compte FROST 2-of-3 ({network_name})\n\nVers : {recipient}\nMontant : {amount} {unit}\nFrais réseau : {fee} {unit}{memo_line}\n\nVotre co-signataire le vérifiera et l'approuvera aussi.\nC'est irréversible une fois signé.\n\nConfirmer cet envoi ?")
        };
        if !shielded_dialog(&app, ("Confirmer l'envoi", "Confirm the transfer"), message) {
            return Err(lang("Envoi annulé (confirmation refusée).", "Transfer cancelled (confirmation refused).").to_string());
        }
        send_grace_period(
            &app,
            GraceRecap::new(network_name, format!("{amount} {unit}"), recipient.clone()).on("zec_shielded"),
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

/// Opens the signing session for the send the user approved: shows the
/// request. One request per approval: the approved send is taken, and put
/// back only if the request could not be made.
#[tauri::command]
pub async fn frost_send_request(
    password: String,
    app: tauri::AppHandle,
) -> Result<RequestDto, String> {
    let password = zeroize::Zeroizing::new(password);
    run_blocking(move || {
        let state = app.state::<FrostState>();
        api::check_device_password(&data_dir(&app)?, &password).t_err()?;
        let prepared = locked(&state.prepared)
            .take()
            .ok_or_else(|| lang("Aucun envoi en cours.", "No transfer in progress.").to_string())?;
        let (pending, shown, report) =
            match api::frost_send_request(&data_dir(&app)?, &password, &prepared) {
                Ok(result) => result,
                Err(e) => {
                    // The user approved this send: keep it for another try,
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

/// Takes the co-signer's reply: signs this member's part, aggregates, proves
/// and broadcasts. Returns the transaction id. A paste that is not this
/// session's reply leaves the session waiting; a reply for it ends the session,
/// whatever happens next, since its nonces are then used.
#[tauri::command]
pub async fn frost_send_finish(ur: String, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let state = app.state::<FrostState>();
        let reply = payload(&ur)?;
        let no_session =
            || lang("Aucune signature en cours.", "No signature in progress.").to_string();
        let reply = {
            let pending = locked(&state.pending);
            zcash_frost::read_reply(pending.as_ref().ok_or_else(no_session)?, &reply).t_err()?
        };
        let pending = locked(&state.pending).take().ok_or_else(no_session)?;
        zcash_frost::send_finish(&data_dir(&app)?, pending, &reply).t_err()
    })
    .await
}
