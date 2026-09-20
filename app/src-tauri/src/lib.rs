//! Commandes Tauri : la seule porte d'entrée entre le frontend web (non fiable,
//! ne doit jamais voir de secret) et le worker crypto (`pgp_wallet_poc::api`).
//! Aucune donnée sensible (entropie, clé privée, passphrase) ne doit jamais être
//! journalisée ici ni renvoyée au frontend — seules des adresses publiques et des
//! confirmations/erreurs le sont.

use base64::Engine;
use pgp_wallet_poc::{api, history, messaging, price_rpc, wallet_flow};
use serde::Serialize;
use std::path::PathBuf;
use tauri::Manager;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

fn data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("répertoire de données introuvable : {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("création du répertoire de données impossible : {e}"))?;
    Ok(dir)
}

#[derive(Serialize)]
struct AddressesDto {
    evm: String,
    btc_testnet: String,
    btc_mainnet: String,
    solana: String,
}

impl From<api::Addresses> for AddressesDto {
    fn from(a: api::Addresses) -> Self {
        Self {
            evm: a.evm,
            btc_testnet: a.btc_testnet,
            btc_mainnet: a.btc_mainnet,
            solana: a.solana,
        }
    }
}

#[derive(Serialize)]
struct ProfileDto {
    index: u32,
    label: String,
    /// `null` côté JS quand le profil a été créé sans mot de passe : l'adresse
    /// n'a pas encore été dérivée (voir `api::create_profile`), elle apparaîtra
    /// au prochain déverrouillage complet.
    addresses: Option<AddressesDto>,
}

impl From<api::ProfileAddresses> for ProfileDto {
    fn from(p: api::ProfileAddresses) -> Self {
        Self {
            index: p.profile.index,
            label: p.profile.label,
            addresses: p.addresses.map(Into::into),
        }
    }
}

/// Label+index seuls, sans adresse : utilisé pour la liste des profils archivés,
/// où on n'a jamais besoin de la seed (voir `api::list_archived_profiles`).
#[derive(Serialize)]
struct ProfileLabelDto {
    index: u32,
    label: String,
}

impl From<api::Profile> for ProfileLabelDto {
    fn from(p: api::Profile) -> Self {
        Self { index: p.index, label: p.label }
    }
}

#[derive(Serialize)]
struct BackupShareDto {
    label: String,
    passphrase: String,
    /// PGP binaire, encodé en base64 pour le transport JSON.
    encrypted_share_b64: String,
    /// PGP déjà en ASCII-armor, mais base64 pour rester cohérent côté frontend.
    privkey_armored_b64: String,
}

impl From<api::BackupShare> for BackupShareDto {
    fn from(b: api::BackupShare) -> Self {
        Self {
            label: b.label,
            passphrase: b.passphrase,
            encrypted_share_b64: base64::engine::general_purpose::STANDARD.encode(&b.encrypted_share),
            privkey_armored_b64: base64::engine::general_purpose::STANDARD.encode(&b.privkey_armored),
        }
    }
}

#[derive(Serialize)]
struct CreateWalletDto {
    addresses: AddressesDto,
    backups: Vec<BackupShareDto>,
}

/// Écrit un contenu (fourni en base64 par le frontend) dans un fichier — le chemin
/// est choisi ICI, côté Rust, via la boîte de dialogue native "Enregistrer sous"
/// (pas transmis par le frontend). Une version antérieure acceptait un `path: String`
/// venant du JS : un frontend compromis aurait alors pu écrire n'importe quel
/// contenu à n'importe quel emplacement du disque (ex: dossier de démarrage
/// Windows) sans aucune interaction utilisateur. Avec ce design, l'utilisateur doit
/// obligatoirement passer par la boîte de dialogue native pour choisir où écrire —
/// impossible à scripter/contourner depuis la webview.
#[tauri::command]
fn save_bytes_with_dialog(suggested_name: String, content_b64: String, app: tauri::AppHandle) -> Result<bool, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&content_b64)
        .map_err(|e| format!("contenu base64 invalide : {e}"))?;

    let chosen = app.dialog().file().set_file_name(&suggested_name).blocking_save_file();

    match chosen {
        Some(file_path) => {
            let path = file_path.into_path().map_err(|e| e.to_string())?;
            std::fs::write(path, bytes).map_err(|e| format!("écriture du fichier impossible : {e}"))?;
            Ok(true)
        }
        None => Ok(false), // l'utilisateur a annulé la boîte de dialogue
    }
}

/// Liste blanche des domaines d'explorateurs de blocs réellement utilisés par l'app
/// (voir `explorer_tx_prefix` dans `wallet_flow.rs` et `ESPLORA_*_BASE` dans
/// `btc_rpc.rs`) : plus restrictif qu'un simple contrôle de schéma `https://`, qui
/// aurait laissé un frontend compromis ouvrir n'importe quelle page — un vecteur
/// de phishing simple, ouvert sans aucun bénéfice fonctionnel puisqu'aucun appel
/// légitime de cette commande ne cible jamais autre chose que ces domaines.
const ALLOWED_EXTERNAL_LINK_PREFIXES: [&str; 4] = [
    "https://etherscan.io/",
    "https://sepolia.etherscan.io/",
    "https://explorer.solana.com/",
    "https://blockstream.info/",
];

/// Ouvre un lien externe (explorateur de blocs) dans le navigateur système : un
/// `<a target="_blank">` classique ne s'ouvre pas de façon fiable dans la webview
/// Tauri (navigation interceptée pour raisons de sécurité), même limite déjà
/// rencontrée pour les téléchargements (voir `save_bytes_with_dialog`). `url` vient
/// du frontend (non fiable, voir en-tête de ce fichier) : restreint à la liste
/// blanche ci-dessus, pas seulement au schéma https://.
#[tauri::command]
fn open_external_link(url: String, app: tauri::AppHandle) -> Result<(), String> {
    if !ALLOWED_EXTERNAL_LINK_PREFIXES.iter().any(|prefix| url.starts_with(prefix)) {
        return Err("lien refusé : seuls les explorateurs de blocs connus de l'app sont autorisés".to_string());
    }
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

/// Génère un QR code (SVG) pour une adresse publique — aucune donnée sensible,
/// juste un confort d'affichage pour recevoir des fonds.
#[tauri::command]
fn generate_qr_svg(text: String) -> Result<String, String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .build())
}

#[tauri::command]
fn wallet_exists(app: tauri::AppHandle) -> Result<bool, String> {
    let dir = data_dir(&app)?;
    Ok(api::device_vault_exists(&dir))
}

/// Supprime le coffre local (voir `api::reset_wallet`) : permet de revenir à
/// l'onboarding sans avoir à retrouver/effacer manuellement le répertoire de
/// données de l'app. Le wallet reste récupérable via les 3 parts de sauvegarde
/// exportées à la création, si elles ont été conservées.
#[tauri::command]
fn reset_wallet(app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    api::reset_wallet(&dir).map_err(|e| e.to_string())
}

#[tauri::command]
fn create_wallet(password: String, app: tauri::AppHandle) -> Result<CreateWalletDto, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let result = api::create_wallet(&dir, &password).map_err(|e| e.to_string())?;

    let backups = result.backups.into_iter().map(Into::into).collect();

    Ok(CreateWalletDto {
        addresses: result.addresses.into(),
        backups,
    })
}

/// Sans cette confirmation, régénérer un kit serait la façon la plus discrète
/// d'exfiltrer le contrôle total du wallet : contrairement à un envoi de fonds
/// (visible on-chain, ponctuel), obtenir un kit Shamir valide donne un accès
/// SILENCIEUX et PERSISTANT — un ancien kit reste valable même après un
/// changement de mot de passe de l'appareil (voir `generate_backup_kit`), donc
/// voler ce kit une fois suffit pour toujours pouvoir reconstruire la clé
/// maîtresse plus tard, sans jamais retoucher au coffre ni déclencher la moindre
/// transaction détectable. Un script ayant déjà volé le mot de passe (ex: capture
/// du champ de saisie) pourrait sinon appeler cette commande sans que
/// l'utilisateur s'en aperçoive jamais. Le dialogue natif de l'OS rend cette
/// tentative visible et impossible à supprimer silencieusement.
fn confirm_regenerate_backup_native(app: &tauri::AppHandle) -> bool {
    app.dialog()
        .message(
            "Ceci va générer un nouveau kit de sauvegarde (3 fichiers + 3 mots de passe permettant \
             à quiconque les possède de reconstruire votre portefeuille, sans jamais avoir besoin de \
             votre mot de passe d'appareil). Ne continuez que si vous avez demandé cette action vous-même.",
        )
        .title("Confirmer la régénération du kit de sauvegarde")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Régénère un kit de sauvegarde Shamir 2-sur-3 tout neuf (voir
/// `api::regenerate_backup_kit`) sans toucher au coffre local ni changer les
/// adresses — utile si l'utilisateur a perdu un ou plusieurs de ses fichiers de
/// sauvegarde d'origine. Redemande le mot de passe : régénérer suppose de
/// redéchiffrer la seed, jamais mise en cache.
#[tauri::command]
fn regenerate_backup_kit(password: String, app: tauri::AppHandle) -> Result<Vec<BackupShareDto>, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;

    if !confirm_regenerate_backup_native(&app) {
        return Err("Régénération annulée (confirmation refusée).".to_string());
    }

    api::regenerate_backup_kit(&dir, &password)
        .map(|backups| backups.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn unlock_wallet(password: String, app: tauri::AppHandle) -> Result<Vec<ProfileDto>, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::unlock_wallet(&dir, &password)
        .map(|profiles| profiles.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

/// Ajoute un profil (nouvelle adresse par réseau, dérivée de la même seed — voir
/// `api::create_profile`) : redemande le mot de passe puisque dériver une adresse
/// suppose de redéchiffrer la seed, jamais mise en cache entre deux appels.
#[tauri::command]
fn create_profile(password: Option<String>, label: String, app: tauri::AppHandle) -> Result<ProfileDto, String> {
    let password = password.map(Zeroizing::new);
    let dir = data_dir(&app)?;
    api::create_profile(&dir, password.as_ref().map(|p| p.as_str()), &label)
        .map(Into::into)
        .map_err(|e| e.to_string())
}

/// Retire un profil de la liste (voir `api::delete_profile`) : redemande le mot de
/// passe, pas parce que la suppression touche à la seed, mais parce que cette
/// application n'offre aucun moyen de recréer un profil à un index précis —
/// concrètement, supprimer un profil qui a déjà reçu des fonds revient à en perdre
/// l'accès depuis cette interface. Ce n'est pas une simple opération de confort sur
/// une liste de labels, d'où une confirmation à la hauteur (comme pour un envoi de
/// fonds), au lieu d'un simple `confirm()` JS.
#[tauri::command]
fn delete_profile(password: String, index: u32, app: tauri::AppHandle) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::delete_profile(&dir, &password, index).map_err(|e| e.to_string())
}

/// Suppression "légère" et réversible (voir `api::archive_profile`) : pas de mot de
/// passe requis, rien n'est irréversible — le profil peut être restauré à tout
/// moment via `unarchive_profile`.
#[tauri::command]
fn archive_profile(index: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    api::archive_profile(&dir, index).map_err(|e| e.to_string())
}

#[tauri::command]
fn unarchive_profile(index: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    api::unarchive_profile(&dir, index).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_archived_profiles(app: tauri::AppHandle) -> Result<Vec<ProfileLabelDto>, String> {
    let dir = data_dir(&app)?;
    Ok(api::list_archived_profiles(&dir).into_iter().map(Into::into).collect())
}

/// Boîte de dialogue native avertissant qu'une restauration va remplacer le coffre
/// actuel de cet appareil. Sans elle, un script capable d'invoquer directement la
/// commande Tauri `restore_wallet` (devtools, dépendance compromise) pourrait
/// substituer silencieusement un tout autre wallet — par exemple un wallet dont
/// l'attaquant possède lui-même les parts de sauvegarde — sans que l'utilisateur
/// clique jamais sur "envoyer". Les adresses affichées ensuite dans le tableau de
/// bord seraient alors celles de l'attaquant : un dépôt fait de bonne foi via l'écran
/// "recevoir" irait droit vers lui. Même logique de défense que
/// `confirm_transaction_native` : dialogue piloté par l'OS, pas par la webview,
/// donc impossible à falsifier ou à contourner depuis un frontend compromis.
fn confirm_restore_native(app: &tauri::AppHandle) -> bool {
    app.dialog()
        .message(
            "Ceci va remplacer le portefeuille actuel de cet appareil par celui reconstruit \
             à partir des 2 fichiers de sauvegarde fournis. Ne continuez que si vous êtes sûr(e) de \
             leur provenance — quelqu'un d'autre en possession de 2 de vos parts pourrait sinon \
             substituer son propre wallet au vôtre.",
        )
        .title("Confirmer la restauration")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn restore_wallet(
    new_password: String,
    backup1_b64: String,
    privkey1_armored_b64: String,
    passphrase1: String,
    backup2_b64: String,
    privkey2_armored_b64: String,
    passphrase2: String,
    app: tauri::AppHandle,
) -> Result<AddressesDto, String> {
    let new_password = Zeroizing::new(new_password);
    let passphrase1 = Zeroizing::new(passphrase1);
    let passphrase2 = Zeroizing::new(passphrase2);
    let dir = data_dir(&app)?;

    if !confirm_restore_native(&app) {
        return Err("Restauration annulée (confirmation refusée).".to_string());
    }

    let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| e.to_string());

    let share1 = decode(&backup1_b64)?;
    let priv1 = decode(&privkey1_armored_b64)?;
    let share2 = decode(&backup2_b64)?;
    let priv2 = decode(&privkey2_armored_b64)?;

    // Une restauration ne recrée toujours qu'un seul profil par défaut (voir
    // `api::restore_wallet`) : les éventuelles étiquettes de profils supplémentaires
    // créées sur l'ancien appareil ne font pas partie de la sauvegarde Shamir.
    api::restore_wallet(
        &dir,
        &new_password,
        (&share1, &priv1, &passphrase1),
        (&share2, &priv2, &passphrase2),
    )
    .map(Into::into)
    .map_err(|e| e.to_string())
}

fn evm_network(network: &str) -> Result<&'static wallet_flow::EvmNetwork, String> {
    match network {
        "evm_sepolia" => Ok(&wallet_flow::SEPOLIA),
        "evm_mainnet" => Ok(&wallet_flow::ETHEREUM_MAINNET),
        other => Err(format!("réseau EVM inconnu : {other}")),
    }
}

fn sol_network(network: &str) -> Result<&'static wallet_flow::SolNetwork, String> {
    match network {
        "sol_devnet" => Ok(&wallet_flow::SOLANA_DEVNET),
        "sol_mainnet" => Ok(&wallet_flow::SOLANA_MAINNET),
        other => Err(format!("réseau Solana inconnu : {other}")),
    }
}

fn btc_network(network: &str) -> Result<&'static wallet_flow::BtcNetwork, String> {
    match network {
        "btc_testnet" => Ok(&wallet_flow::BTC_TESTNET),
        "btc_mainnet" => Ok(&wallet_flow::BTC_MAINNET),
        other => Err(format!("réseau Bitcoin inconnu : {other}")),
    }
}

#[tauri::command]
fn get_balance(network: String, address: String) -> Result<String, String> {
    match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => {
            let net = evm_network(&network)?;
            let wei = api::get_evm_balance(&address, net).map_err(|e| e.to_string())?;
            Ok(format!("{:.6}", wei as f64 / 1e18))
        }
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            let sat = api::get_btc_balance(&address, net).map_err(|e| e.to_string())?;
            Ok(format!("{:.8}", sat as f64 / 1e8))
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            let lamports = api::get_sol_balance(&address, net).map_err(|e| e.to_string())?;
            Ok(format!("{:.9}", lamports as f64 / 1e9))
        }
        other => Err(format!("réseau inconnu : {other}")),
    }
}

#[derive(Serialize)]
struct BtcFeeEstimateDto {
    fast_sat: u64,
    medium_sat: u64,
    slow_sat: u64,
}

/// Frais rapide/moyen/lent (en sats) pour un virement Bitcoin depuis `address` —
/// uniquement Bitcoin : EVM/Solana calculent déjà leurs frais automatiquement
/// (gas price / frais de base réseau), pas de choix à proposer à l'utilisateur.
#[tauri::command]
fn estimate_btc_fees(network: String, address: String) -> Result<BtcFeeEstimateDto, String> {
    let net = btc_network(&network)?;
    let estimate = api::estimate_btc_fees(&address, net).map_err(|e| e.to_string())?;
    Ok(BtcFeeEstimateDto {
        fast_sat: estimate.fast_sat,
        medium_sat: estimate.medium_sat,
        slow_sat: estimate.slow_sat,
    })
}

/// `false` pour EVM plutôt qu'une erreur : aucun nœud public n'expose les
/// transactions en attente pour Ethereum (voir `api::has_pending_btc`/`has_pending_sol`),
/// donc l'indicateur "transaction en attente" ne peut structurellement jamais
/// s'allumer pour ETH — un no-op silencieux, pas un échec, pour ne pas faire
/// planter le rafraîchissement automatique du solde sur ce réseau.
#[tauri::command]
fn has_pending_tx(network: String, address: String) -> Result<bool, String> {
    match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => Ok(false),
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            api::has_pending_btc(&address, net).map_err(|e| e.to_string())
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            api::has_pending_sol(&address, net).map_err(|e| e.to_string())
        }
        other => Err(format!("réseau inconnu : {other}")),
    }
}

const HISTORY_LIMIT: u32 = 15;

#[derive(Serialize)]
struct TxEntryDto {
    id: String,
    timestamp_unix: Option<i64>,
    status: String,
    /// Chaîne décimale signée dans l'unité principale du réseau (ex: "+0.001234",
    /// "-0.05") ; `None` quand le montant n'a pas pu être déterminé.
    amount: Option<String>,
    explorer_url: String,
}

fn format_signed_amount(net_amount_minor: Option<i128>, decimals: i32) -> Option<String> {
    net_amount_minor.map(|v| {
        let value = v as f64 / 10f64.powi(decimals);
        format!("{:+.*}", decimals as usize, value)
    })
}

fn status_str(status: &pgp_wallet_poc::history::TxStatus) -> &'static str {
    use pgp_wallet_poc::history::TxStatus;
    match status {
        TxStatus::Confirmed => "confirmed",
        TxStatus::Pending => "pending",
        TxStatus::Failed => "failed",
    }
}

#[tauri::command]
fn get_tx_history(network: String, address: String) -> Result<Vec<TxEntryDto>, String> {
    let entries = match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => {
            let net = evm_network(&network)?;
            let txs = history::evm_history(net.chain_id, &address, HISTORY_LIMIT as usize).map_err(|e| e.to_string())?;
            txs.into_iter()
                .map(|tx| TxEntryDto {
                    id: tx.id.clone(),
                    timestamp_unix: tx.timestamp_unix,
                    status: status_str(&tx.status).to_string(),
                    amount: format_signed_amount(tx.net_amount_minor, 18),
                    explorer_url: format!("{}{}", net.explorer_tx_prefix, tx.id),
                })
                .collect()
        }
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            let txs = history::btc_history(net, &address).map_err(|e| e.to_string())?;
            txs.into_iter()
                .map(|tx| TxEntryDto {
                    id: tx.id.clone(),
                    timestamp_unix: tx.timestamp_unix,
                    status: status_str(&tx.status).to_string(),
                    amount: format_signed_amount(tx.net_amount_minor, 8),
                    explorer_url: format!("{}{}", net.explorer_tx_prefix, tx.id),
                })
                .collect()
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            let txs = history::sol_history(net.rpc, &address, HISTORY_LIMIT).map_err(|e| e.to_string())?;
            txs.into_iter()
                .map(|tx| TxEntryDto {
                    id: tx.id.clone(),
                    timestamp_unix: tx.timestamp_unix,
                    status: status_str(&tx.status).to_string(),
                    amount: format_signed_amount(tx.net_amount_minor, 9),
                    explorer_url: format!("{}{}{}", net.explorer_tx_prefix, tx.id, net.explorer_tx_suffix),
                })
                .collect()
        }
        other => return Err(format!("réseau inconnu : {other}")),
    };
    Ok(entries)
}

#[derive(Serialize)]
struct PricesDto {
    eth_usd: f64,
    btc_usd: f64,
    sol_usd: f64,
}

/// Prix indicatifs en USD (voir `core/src/price_rpc.rs`) : purement informatif,
/// aucune donnée sur l'utilisateur ou ses adresses n'est envoyée à ce service.
#[tauri::command]
fn get_crypto_prices() -> Result<PricesDto, String> {
    price_rpc::PriceRpc::new()
        .get_prices()
        .map(|p| PricesDto { eth_usd: p.eth_usd, btc_usd: p.btc_usd, sol_usd: p.sol_usd })
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct MarketCoinDto {
    symbol: String,
    name: String,
    price_usd: f64,
    market_cap_usd: f64,
    /// `null` côté JS si CoinGecko n'a pas de variation 24h calculable pour cet
    /// actif (trop récent/illiquide) — voir `price_rpc::MarketCoin`.
    change_24h_percent: Option<f64>,
}

/// Section "Marchés" du tableau de bord : déjà triée par capitalisation
/// décroissante côté Rust (voir `price_rpc::get_market_data`), le frontend n'a
/// qu'à afficher l'ordre reçu.
#[tauri::command]
fn get_market_prices() -> Result<Vec<MarketCoinDto>, String> {
    price_rpc::PriceRpc::new()
        .get_market_data()
        .map(|coins| {
            coins
                .into_iter()
                .map(|c| MarketCoinDto {
                    symbol: c.symbol,
                    name: c.name,
                    price_usd: c.price_usd,
                    market_cap_usd: c.market_cap_usd,
                    change_24h_percent: c.change_24h_percent,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// Libellé humain du réseau pour la boîte de dialogue de confirmation.
fn network_label(network: &str) -> &str {
    match network {
        "evm_sepolia" => "Ethereum Sepolia (testnet)",
        "evm_mainnet" => "Ethereum MAINNET — fonds réels",
        "btc_testnet" => "Bitcoin testnet",
        "btc_mainnet" => "Bitcoin MAINNET — fonds réels",
        "sol_devnet" => "Solana devnet",
        "sol_mainnet" => "Solana MAINNET — fonds réels",
        other => other,
    }
}

/// Boîte de dialogue native de confirmation, affichée par l'OS et non par la
/// webview : contrairement à une modale HTML, un frontend compromis ne peut ni
/// la falsifier ni la court-circuiter silencieusement. Montre exactement ce que
/// le backend Rust a compris (réseau, destinataire, montant, ET profil source
/// depuis l'ajout des profils multiples — sans lui, cette boîte ne montrerait plus
/// "exactement" ce qui va être signé : le profil source détermine maintenant
/// l'adresse d'où partent les fonds, tout autant que le réseau/destinataire/montant)
/// juste avant de signer — protection spécifique contre un détournement discret.
fn confirm_transaction_native(
    app: &tauri::AppHandle,
    network: &str,
    to: &str,
    amount: &str,
    from_label: &str,
    fee_line: Option<&str>,
) -> bool {
    let fee_line = fee_line.map(|f| format!("\n{f}")).unwrap_or_default();
    app.dialog()
        .message(format!(
            "Réseau : {}\nDepuis le profil : {from_label}\nDestinataire : {to}\nMontant : {amount}{fee_line}\n\nConfirmer cet envoi ? C'est irréversible.",
            network_label(network)
        ))
        .title("Confirmer le virement")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn send_transaction(
    network: String,
    password: String,
    to: String,
    amount: String,
    fee_sat: Option<u64>,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;

    let from_label = api::list_profiles(&dir)
        .into_iter()
        .find(|p| p.index == profile_index)
        .map(|p| p.label)
        .unwrap_or_else(|| format!("profil #{profile_index}"));

    // Affiché dans la boîte de dialogue native (voir sa doc : "montre exactement ce
    // que le backend a compris") uniquement pour Bitcoin, seul réseau où les frais
    // sont un choix explicite de l'utilisateur plutôt que calculés automatiquement.
    let fee_line = fee_sat.map(|f| format!("Frais : {f} sat"));

    if !confirm_transaction_native(&app, &network, &to, &amount, &from_label, fee_line.as_deref()) {
        return Err("Virement annulé (confirmation refusée).".to_string());
    }

    match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => {
            let net = evm_network(&network)?;
            api::send_evm(&dir, &password, net, &to, &amount, profile_index).map_err(|e| e.to_string())
        }
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            let fee_sat = fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
            api::send_btc(&dir, &password, net, &to, &amount, fee_sat, profile_index).map_err(|e| e.to_string())
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            api::send_sol(&dir, &password, net, &to, &amount, profile_index).map_err(|e| e.to_string())
        }
        other => Err(format!("réseau inconnu : {other}")),
    }
}

#[derive(Serialize)]
struct RecipientDto {
    label: String,
    pubkey_armored: String,
    /// Empreinte PGP du destinataire, affichée dans le carnet pour permettre à
    /// l'utilisateur de la comparer à une source hors-ligne (message vocal,
    /// rencontre en personne, etc.) : `recipients.json` est un fichier local
    /// ordinaire, modifiable par tout code tournant avec les droits de
    /// l'utilisateur — sans un moyen de vérification visible, un remplacement
    /// silencieux de la clé stockée passerait inaperçu (chiffrement futur pour
    /// le mauvais destinataire). Recalculée à la volée depuis pubkey_armored,
    /// jamais lue depuis le fichier : une empreinte falsifiée ne correspondrait
    /// plus à la clé réellement utilisée pour chiffrer.
    fingerprint: String,
}

impl From<messaging::Recipient> for RecipientDto {
    fn from(r: messaging::Recipient) -> Self {
        let fingerprint = messaging::cert_info(&r.pubkey_armored)
            .map(|info| info.fingerprint)
            .unwrap_or_else(|_| "invalide".to_string());
        Self {
            label: r.label,
            pubkey_armored: r.pubkey_armored,
            fingerprint,
        }
    }
}

#[derive(Serialize)]
struct CertInfoDto {
    fingerprint: String,
    key_id: String,
    user_id: String,
    pubkey_armored: String,
}

impl From<messaging::CertInfo> for CertInfoDto {
    fn from(c: messaging::CertInfo) -> Self {
        Self {
            fingerprint: c.fingerprint,
            key_id: c.key_id,
            user_id: c.user_id,
            pubkey_armored: c.pubkey_armored,
        }
    }
}

/// Certificat (clé publique) de CET appareil — à partager pour que d'autres
/// puissent t'ajouter comme destinataire et t'envoyer des messages chiffrés.
#[tauri::command]
fn get_own_certificate(app: tauri::AppHandle) -> Result<CertInfoDto, String> {
    let dir = data_dir(&app)?;
    let armored = api::read_device_pubkey_armored(&dir).map_err(|e| e.to_string())?;
    messaging::cert_info(&armored).map(Into::into).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_recipients(app: tauri::AppHandle) -> Result<Vec<RecipientDto>, String> {
    let dir = data_dir(&app)?;
    messaging::list_recipients(&dir)
        .map(|v| v.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn add_recipient(label: String, pubkey_armored: String, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;

    if let Some((old_fingerprint, new_fingerprint)) =
        messaging::recipient_key_change(&dir, &label, &pubkey_armored).map_err(|e| e.to_string())?
    {
        // Boîte de dialogue native, même mécanisme que pour un envoi de fonds : un
        // remplacement de clé pour un contact déjà enregistré n'est pas anodin (voir
        // la doc de `recipient_key_change`), donc pas question de le laisser passer
        // silencieusement comme le ferait `messaging::add_recipient` seule.
        let confirmed = app
            .dialog()
            .message(format!(
                "\"{label}\" a déjà une clé enregistrée, différente de celle-ci.\n\n\
                 Ancienne empreinte : {old_fingerprint}\n\
                 Nouvelle empreinte : {new_fingerprint}\n\n\
                 Si vous n'avez pas vérifié ce changement avec {label} par un autre moyen que l'app, \
                 ceci pourrait être une tentative de substitution. Remplacer quand même ?"
            ))
            .title("Clé du destinataire modifiée")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show();
        if !confirmed {
            return Err("Ajout annulé (clé différente refusée).".to_string());
        }
    }

    messaging::add_recipient(&dir, &label, &pubkey_armored).map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_recipient(label: String, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    messaging::remove_recipient(&dir, &label).map_err(|e| e.to_string())
}

#[tauri::command]
fn encrypt_message(pubkey_armored: String, message: String) -> Result<String, String> {
    messaging::encrypt_message(&pubkey_armored, &message).map_err(|e| e.to_string())
}

/// Déchiffre un message reçu par cet appareil (nécessite le mot de passe pour
/// déverrouiller la clé privée locale, comme pour un envoi de fonds).
#[tauri::command]
fn decrypt_message(password: String, ciphertext: String, app: tauri::AppHandle) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::decrypt_incoming_message(&dir, &password, &ciphertext).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            save_bytes_with_dialog,
            open_external_link,
            generate_qr_svg,
            wallet_exists,
            reset_wallet,
            create_wallet,
            regenerate_backup_kit,
            unlock_wallet,
            create_profile,
            delete_profile,
            archive_profile,
            unarchive_profile,
            list_archived_profiles,
            restore_wallet,
            get_balance,
            has_pending_tx,
            get_tx_history,
            estimate_btc_fees,
            get_crypto_prices,
            get_market_prices,
            send_transaction,
            get_own_certificate,
            list_recipients,
            add_recipient,
            remove_recipient,
            encrypt_message,
            decrypt_message,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
