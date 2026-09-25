//! Commandes Tauri : la seule porte d'entrée entre le frontend web (non fiable,
//! ne doit jamais voir de secret) et le worker crypto (`pgp_wallet_poc::api`).
//! Aucune donnée sensible (entropie, clé privée, passphrase) ne doit jamais être
//! journalisée ici ni renvoyée au frontend — seules des adresses publiques et des
//! confirmations/erreurs le sont.

use base64::Engine;
use pgp_wallet_poc::{address_book, api, external_wallets, history, messaging, price_rpc, sent_recipients, wallet_flow};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::Manager;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

// --- Traduction des messages d'erreur ---------------------------------------
// `core/` ignore volontairement tout concept d'interface graphique (voir sa doc :
// pensé pour être réutilisable tel quel par une future cible CLI/mobile) — la
// langue affichée à l'utilisateur est donc une préoccupation d'exposition, traitée
// ici, au point unique où une erreur `anyhow::Result` produite par `core/` devient
// la `String` envoyée au frontend. Pas de dépendance `regex` ajoutée pour ça : les
// quelques messages avec une valeur interpolée (index, nom, montant...) sont
// recomposés par découpage de chaîne plutôt que par expression régulière.
static UI_LANG_IS_ENGLISH: AtomicBool = AtomicBool::new(false);

/// Appelée par le frontend à chaque changement de langue (bouton FR/EN) et au
/// démarrage. Un simple booléen process-wide suffit : ce n'est qu'une préférence
/// d'affichage, jamais une donnée de sécurité.
#[tauri::command]
fn set_ui_language(lang: String) {
    UI_LANG_IS_ENGLISH.store(lang == "en", Ordering::Relaxed);
}

/// Messages sans valeur interpolée : correspondance exacte avec le texte français
/// tel qu'écrit dans `core/` et dans ce fichier.
const EXACT_ERROR_TRANSLATIONS: &[(&str, &str)] = &[
    // core/src/api.rs
    ("sérialisation des profils", "profile serialization"),
    ("écriture des profils", "writing profiles"),
    ("lecture de la clé publique de l'appareil", "reading the device's public key"),
    ("le message déchiffré n'est pas du texte UTF-8 valide", "the decrypted message is not valid UTF-8 text"),
    ("coffre local introuvable", "local vault not found"),
    ("gas_price * gas_limit dépasse la capacité représentable", "gas_price * gas_limit exceeds the representable range"),
    ("montant + frais de gas dépasse la capacité représentable", "amount + gas fee exceeds the representable range"),
    ("montant + frais dépasse la capacité représentable", "amount + fee exceeds the representable range"),
    ("adresse Solana invalide (base58 attendu)", "invalid Solana address (base58 expected)"),
    ("une adresse Solana fait 32 octets", "a Solana address is 32 bytes"),
    // core/src/api.rs — audit "failles connues des hot wallets"
    (
        "cette adresse est un compte de jetons (ou un mint), pas un portefeuille : les fonds y seraient perdus. Demandez l'adresse du PORTEFEUILLE du destinataire.",
        "this address is a token account (or a mint), not a wallet: funds sent there would be lost. Ask for the recipient's WALLET address.",
    ),
    (
        "cette adresse appartient à un programme, pas à un portefeuille — envoi refusé (fonds probablement irrécupérables)",
        "this address belongs to a program, not a wallet — transfer refused (funds would likely be unrecoverable)",
    ),
    (
        "cette adresse n'a aucune clé privée (dérivée d'un programme) et n'a jamais été utilisée — les fonds y seraient très probablement perdus",
        "this address has no private key (program-derived) and has never been used — funds sent there would very likely be lost",
    ),
    (
        "l'adresse de dépôt THORChain a changé pendant la confirmation — relancez l'échange pour voir la nouvelle",
        "the THORChain deposit address changed during confirmation — restart the swap to see the new one",
    ),
    (
        "le cours a bougé pendant la confirmation (sortie minimale sous 99 % du montant affiché) — relancez l'échange",
        "the price moved during confirmation (minimum output below 99% of the amount shown) — restart the swap",
    ),
    (
        "la transaction changerait le programme propriétaire de votre compte principal (Assign) — refus de signer",
        "the transaction would change your main account's owner program (Assign) — refusing to sign",
    ),
    (
        "la transaction allouerait des données sur votre compte principal — refus de signer",
        "the transaction would allocate data on your main account — refusing to sign",
    ),
    (
        "la transaction ajouterait un délégué sur un de vos comptes de jetons (Approve : droit de le vider plus tard) — refus de signer",
        "the transaction would add a delegate on one of your token accounts (Approve: the right to drain it later) — refusing to sign",
    ),
    (
        "la transaction changerait l'autorité de fermeture d'un de vos comptes de jetons — refus de signer",
        "the transaction would change the close authority of one of your token accounts — refusing to sign",
    ),
    (
        "la transaction transférerait la propriété d'un de vos comptes de jetons (SetAuthority) — refus de signer",
        "the transaction would transfer ownership of one of your token accounts (SetAuthority) — refusing to sign",
    ),
    (
        "la transaction vous céderait un compte de jetons existant — refus de signer",
        "the transaction would hand you an existing token account — refusing to sign",
    ),
    (
        "un compte de jetons créé pour vous aurait déjà un délégué ou une autorité de fermeture — refus de signer",
        "a token account created for you would already have a delegate or close authority — refusing to sign",
    ),
    // core/src/api.rs + app/src-tauri/src/lib.rs — 22ᵉ passage d'auto-revue
    (
        "la transaction livrerait vos jetons sur un compte non standard, invisible dans l'app — refus de signer",
        "the transaction would deliver your tokens to a non-standard account, invisible in the app — refusing to sign",
    ),
    (
        "ce « message » est le coffre du portefeuille lui-même — déchiffrement refusé",
        "this \"message\" is the wallet's own vault — decryption refused",
    ),
    (
        "adresse invalide : espaces, retours à la ligne ou caractères invisibles refusés",
        "invalid address: spaces, line breaks or invisible characters are refused",
    ),
    ("Réinitialisation annulée (confirmation refusée).", "Reset cancelled (confirmation refused)."),
    ("Échange annulé (confirmation refusée).", "Swap cancelled (confirmation refused)."),
    // core/src/messaging.rs
    ("clé publique PGP invalide", "invalid PGP public key"),
    ("au moins un destinataire est requis", "at least one recipient is required"),
    ("lecture du carnet de destinataires", "reading the recipient book"),
    ("carnet de destinataires corrompu", "recipient book corrupted"),
    ("sérialisation du carnet de destinataires", "recipient book serialization"),
    ("écriture du carnet de destinataires", "writing the recipient book"),
    ("initialisation de l'armure PGP", "PGP armor initialization"),
    ("initialisation du chiffreur PGP", "PGP encryptor initialization"),
    ("initialisation de l'écriture littérale", "literal writer initialization"),
    ("finalisation de l'armure PGP", "PGP armor finalization"),
    ("résultat PGP non-UTF8 (inattendu)", "non-UTF8 PGP result (unexpected)"),
    ("certificat invalide", "invalid certificate"),
    // core/src/pgp_engine.rs
    ("aucune part PKESK n'a pu être déchiffrée avec cette clé", "no PKESK share could be decrypted with this key"),
    ("passphrase incorrecte ou clé privée corrompue", "incorrect passphrase or corrupted private key"),
    ("clé privée inutilisable pour le déchiffrement", "private key unusable for decryption"),
    ("lecture du message PGP chiffré", "reading the encrypted PGP message"),
    ("échec du déchiffrement (mauvaise clé ou message corrompu)", "decryption failed (wrong key or corrupted message)"),
    ("lecture du contenu déchiffré", "reading the decrypted content"),
    // core/src/derivation.rs
    ("dérivation BIP32 racine impossible", "root BIP32 derivation failed"),
    ("chemin de dérivation invalide", "invalid derivation path"),
    ("échec de dérivation d'un segment", "failed to derive a path segment"),
    ("encodage bech32 impossible", "bech32 encoding failed"),
    ("adresse bech32 invalide", "invalid bech32 address"),
    ("adresse bech32 vide", "empty bech32 address"),
    ("conversion base32 -> octets impossible", "base32 -> bytes conversion failed"),
    (
        "programme témoin de taille inattendue (P2WPKH attend 20 octets)",
        "witness program has an unexpected size (P2WPKH expects 20 bytes)",
    ),
    // core/src/shamir.rs
    ("format de part invalide", "invalid share format"),
    (
        "échec de la reconstruction (parts insuffisantes ou corrompues)",
        "reconstruction failed (insufficient or corrupted shares)",
    ),
    // core/src/wallet_flow.rs (fonctions de parsing réutilisées par la GUI)
    ("adresse invalide (hex attendu)", "invalid address (hex expected)"),
    ("partie entière invalide", "invalid integer part"),
    ("partie décimale invalide", "invalid decimal part"),
    ("montant ETH trop grand (dépassement arithmétique)", "ETH amount too large (arithmetic overflow)"),
    ("montant BTC trop grand (dépassement arithmétique)", "BTC amount too large (arithmetic overflow)"),
    ("montant SOL trop grand (dépassement arithmétique)", "SOL amount too large (arithmetic overflow)"),
    ("trop de décimales (18 maximum pour l'ETH)", "too many decimals (18 maximum for ETH)"),
    ("trop de décimales (8 maximum pour le BTC)", "too many decimals (8 maximum for BTC)"),
    ("trop de décimales (9 maximum pour le SOL)", "too many decimals (9 maximum for SOL)"),
    (
        "aucun UTXO confirmé disponible (vérifie le solde d'abord)",
        "no confirmed UTXO available (check the balance first)",
    ),
    ("impossible de contacter le nœud RPC", "unable to reach the RPC node"),
    // core/src/eth_rpc.rs / sol_rpc.rs (messages sans valeur interpolée)
    ("réponse getBalance inattendue", "unexpected getBalance response"),
    ("réponse eth_gasPrice non textuelle", "non-textual eth_gasPrice response"),
    ("réponse eth_getBalance non textuelle", "non-textual eth_getBalance response"),
    ("réponse eth_sendRawTransaction non textuelle", "non-textual eth_sendRawTransaction response"),
    ("réponse getLatestBlockhash inattendue", "unexpected getLatestBlockhash response"),
    ("blockhash base58 invalide", "invalid base58 blockhash"),
    ("blockhash de taille inattendue", "blockhash has an unexpected size"),
    ("réponse requestAirdrop inattendue", "unexpected requestAirdrop response"),
    ("réponse sendTransaction inattendue", "unexpected sendTransaction response"),
    // core/src/btc_rpc.rs
    ("appel esplora /utxo impossible", "esplora /utxo call failed"),
    ("réponse esplora /utxo illisible", "unreadable esplora /utxo response"),
    ("txid invalide", "invalid txid"),
    ("txid de taille inattendue", "txid has an unexpected size"),
    ("appel esplora /txs/mempool impossible", "esplora /txs/mempool call failed"),
    ("réponse esplora /txs/mempool illisible", "unreadable esplora /txs/mempool response"),
    ("appel esplora /txs impossible", "esplora /txs call failed"),
    ("réponse esplora /txs illisible", "unreadable esplora /txs response"),
    ("appel esplora /tx impossible", "esplora /tx call failed"),
    ("réponse esplora /tx illisible", "unreadable esplora /tx response"),
    ("appel esplora /fee-estimates impossible", "esplora /fee-estimates call failed"),
    ("réponse esplora /fee-estimates illisible", "unreadable esplora /fee-estimates response"),
    // core/src/blockscout.rs
    ("appel Blockscout impossible", "Blockscout call failed"),
    ("réponse Blockscout illisible", "unreadable Blockscout response"),
    ("montant de transaction Blockscout invalide", "invalid Blockscout transaction amount"),
    // core/src/price_rpc.rs
    ("appel CoinGecko impossible", "CoinGecko call failed"),
    ("réponse CoinGecko illisible", "unreadable CoinGecko response"),
    ("appel CoinGecko (marchés) impossible", "CoinGecko (markets) call failed"),
    ("réponse CoinGecko (marchés) illisible", "unreadable CoinGecko (markets) response"),
    // app/src-tauri/src/lib.rs
    (
        "lien refusé : seuls les explorateurs de blocs connus de l'app sont autorisés",
        "link refused: only the app's known block explorers are allowed",
    ),
    ("Régénération annulée (confirmation refusée).", "Regeneration cancelled (confirmation refused)."),
    ("Restauration annulée (confirmation refusée).", "Restoration cancelled (confirmation refused)."),
    ("Virement annulé (confirmation refusée).", "Transfer cancelled (confirmation refused)."),
    ("Ajout annulé (clé différente refusée).", "Addition cancelled (different key refused)."),
    ("Activation annulée (confirmation refusée).", "Activation cancelled (confirmation refused)."),
    ("Désactivation annulée (confirmation refusée).", "Deactivation cancelled (confirmation refused)."),
    ("USDC n'est disponible que sur Solana mainnet.", "USDC is only available on Solana mainnet."),
    // core/src/windows_hello.rs (contexte fixe de `to_anyhow`, sans le suffixe
    // dynamique ": {err} (code ...)", géré par translate_dynamic_error)
    ("clé TPM déjà absente, rien à supprimer", "TPM key already absent, nothing to remove"),
    // core/src/sol_rpc.rs (nouvelles méthodes SPL)
    ("réponse getTokenAccountBalance inattendue", "unexpected getTokenAccountBalance response"),
    ("montant getTokenAccountBalance illisible", "unreadable getTokenAccountBalance amount"),
    ("réponse getMinimumBalanceForRentExemption inattendue", "unexpected getMinimumBalanceForRentExemption response"),
    // core/src/api.rs (biométrie + USDC)
    (
        "le déverrouillage biométrique n'est disponible que sous Windows",
        "biometric unlock is only available on Windows",
    ),
    ("déverrouillage biométrique non activé sur cet appareil", "biometric unlock is not enabled on this device"),
    ("métadonnées de la clé biométrique corrompues", "biometric key metadata corrupted"),
    (
        "vérification post-ré-chiffrement du coffre : le mot de passe existant ne fonctionne plus, activation annulée",
        "post-re-encryption vault check: the existing password no longer works, activation cancelled",
    ),
    (
        "vérification post-ré-chiffrement du coffre : le mot de passe existant ne fonctionne plus, désactivation annulée",
        "post-re-encryption vault check: the existing password no longer works, deactivation cancelled",
    ),
    ("secret biométrique scellé introuvable", "sealed biometric secret not found"),
    ("aucun compte USDC trouvé pour cette adresse (solde 0)", "no USDC account found for this address (balance 0)"),
    ("frais + rent dépasse la capacité représentable", "fee + rent exceeds the representable range"),
    // core/src/wallet_flow.rs (parse_usdc_to_micros)
    ("trop de décimales (6 maximum pour l'USDC)", "too many decimals (6 maximum for USDC)"),
    ("montant USDC trop grand (dépassement arithmétique)", "USDC amount too large (arithmetic overflow)"),
    // core/src/external_wallets.rs
    ("sérialisation des wallets externes", "external wallet serialization"),
    ("écriture des wallets externes", "writing external wallets"),
    // core/src/address_book.rs
    ("sérialisation du carnet d'adresses", "address book serialization"),
    ("écriture du carnet d'adresses", "writing the address book"),
];

/// Messages avec une valeur interpolée (index, méthode RPC, montant...) : la
/// correspondance exacte ne peut pas fonctionner, donc reconstruction par
/// découpage autour de la partie fixe du message.
fn translate_dynamic_error(msg: &str) -> Option<String> {
    if let Some(rest) = msg.strip_prefix("profil actif introuvable (index ") {
        return Some(format!("active profile not found (index {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("profil archivé introuvable (index ") {
        return Some(format!("archived profile not found (index {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("profil introuvable (index ") {
        return Some(format!("profile not found (index {rest}"));
    }
    if msg == "une adresse EVM fait 20 octets (40 caractères hex)" {
        return Some("an EVM address is 20 bytes (40 hex characters)".to_string());
    }
    if let Some(rest) = msg.strip_prefix("adresse non-testnet (préfixe 'tb' attendu, trouvé '") {
        return Some(format!("non-testnet address (prefix 'tb' expected, found '{rest}"));
    }
    if let Some(rest) = msg.strip_prefix("adresse non-mainnet (préfixe 'bc' attendu, trouvé '") {
        return Some(format!("non-mainnet address (prefix 'bc' expected, found '{rest}"));
    }
    if let Some(rest) = msg.strip_prefix("erreur RPC ") {
        if let Some((method, err)) = rest.split_once(" : ") {
            return Some(format!("RPC error {method}: {err}"));
        }
    }
    if let Some(rest) = msg.strip_prefix("réponse RPC ") {
        if let Some(method) = rest.strip_suffix(" sans champ 'result'") {
            return Some(format!("RPC response {method} has no 'result' field"));
        }
    }
    if let Some(method) = msg.strip_prefix("réponse ").and_then(|s| s.strip_suffix(" non textuelle")) {
        return Some(format!("non-textual {method} response"));
    }
    if let Some(rest) = msg.strip_prefix("aucune clé de déchiffrement trouvée dans ") {
        return Some(format!("no decryption key found in {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("échec de diffusion de la transaction : ") {
        return Some(format!("failed to broadcast the transaction: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("échec de signature ECDSA : ") {
        return Some(format!("ECDSA signing failed: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("trop de tentatives incorrectes récentes ; réessayez dans ") {
        return Some(format!("too many recent incorrect attempts; try again in {}", rest.replace("seconde(s)", "second(s)")));
    }
    if let Some(rest) = msg.strip_prefix("fonds insuffisants : ") {
        let translated = rest
            .replace("disponibles", "available")
            .replace("de frais de gas requis", "gas fee required")
            .replace("de frais requis", "fee required");
        return Some(format!("insufficient funds: {translated}"));
    }
    if let Some(rest) =
        msg.strip_suffix("\" n'a aucune sous-clé de chiffrement valide (expirée ou révoquée) — message non envoyé")
    {
        return Some(format!(
            "{rest}\" has no valid encryption subkey (expired or revoked) — message not sent"
        ));
    }
    if let Some(rest) = msg.strip_prefix("réseau EVM inconnu : ") {
        return Some(format!("unknown EVM network: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("réseau Solana inconnu : ") {
        return Some(format!("unknown Solana network: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("réseau Bitcoin inconnu : ") {
        return Some(format!("unknown Bitcoin network: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("réseau inconnu : ") {
        return Some(format!("unknown network: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("répertoire de données introuvable : ") {
        return Some(format!("data directory not found: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("création du répertoire de données impossible : ") {
        return Some(format!("could not create the data directory: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("contenu base64 invalide : ") {
        return Some(format!("invalid base64 content: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("écriture du fichier impossible : ") {
        return Some(format!("could not write the file: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("fonds USDC insuffisants : ") {
        let translated = rest.replace("disponibles (unité 10^-6 USDC)", "available (10^-6 USDC unit)").replace("requis", "required");
        return Some(format!("insufficient USDC funds: {translated}"));
    }
    if let Some(rest) = msg.strip_prefix("SOL insuffisant pour les frais") {
        if let Some((extra, numbers)) = rest.split_once(" : ") {
            let extra_en = extra.replace(" + création du compte de jetons du destinataire", " + creating the recipient's token account");
            let numbers_en = numbers.replace("disponibles", "available").replace("requis", "required");
            return Some(format!("insufficient SOL for fees{extra_en}: {numbers_en}"));
        }
    }
    if let Some(rest) = msg.strip_prefix("groupe introuvable (id ") {
        return Some(format!("group not found (id {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("wallet externe introuvable (id ") {
        return Some(format!("external wallet not found (id {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("entrée du carnet d'adresses introuvable (id ") {
        return Some(format!("address book entry not found (id {rest}"));
    }
    // core/src/windows_hello.rs : `to_anyhow` construit "{contexte} : {err} (code
    // ...)" — seul le contexte fixe (en français) est traduisible, le message
    // d'erreur Windows lui-même (`{err}`) est déjà dans la langue du système
    // d'exploitation, hors de notre contrôle.
    const WINDOWS_HELLO_CONTEXTS: &[(&str, &str)] = &[
        ("ouverture du fournisseur TPM (Microsoft Platform Crypto Provider)", "opening the TPM provider (Microsoft Platform Crypto Provider)"),
        ("création de la clé TPM persistée", "creating the persisted TPM key"),
        ("réglage de la taille de clé TPM", "setting the TPM key size"),
        ("réglage de la politique Windows Hello sur la clé TPM", "setting the Windows Hello policy on the TPM key"),
        ("finalisation de la clé TPM", "finalizing the TPM key"),
        ("calcul de la taille du blob scellé", "computing the sealed blob size"),
        ("scellement du secret dans le TPM", "sealing the secret in the TPM"),
        ("ouverture de la clé TPM (déverrouillage biométrique désactivé ou clé absente ?)", "opening the TPM key (biometric unlock disabled or key missing?)"),
        ("calcul de la taille du secret déchiffré", "computing the decrypted secret size"),
        ("vérification Windows Hello refusée, annulée ou échouée", "Windows Hello verification refused, cancelled, or failed"),
        ("suppression de la clé TPM", "removing the TPM key"),
    ];
    for (fr, en) in WINDOWS_HELLO_CONTEXTS {
        if let Some(rest) = msg.strip_prefix(fr) {
            if let Some(rest) = rest.strip_prefix(" : ") {
                return Some(format!("{en}: {rest}"));
            }
        }
    }
    None
}

fn translate_error(msg: &str) -> String {
    if !UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        return msg.to_string();
    }
    if let Some((_, en)) = EXACT_ERROR_TRANSLATIONS.iter().find(|(fr, _)| *fr == msg) {
        return en.to_string();
    }
    if let Some(en) = translate_dynamic_error(msg) {
        return en;
    }
    // Message inconnu de la table (probablement une erreur brute d'une bibliothèque
    // tierce, déjà en anglais/technique — reqwest, serde_json, io::Error...) :
    // laissé tel quel plutôt que de risquer une traduction incorrecte.
    msg.to_string()
}

/// Choisit le texte français ou anglais selon la langue d'interface courante —
/// utilisé pour le texte des boîtes de dialogue natives (`app.dialog()...`),
/// qui ne passent jamais par `translate_error`/`.t_err()` puisqu'elles ne sont
/// pas des erreurs mais des messages de confirmation construits directement
/// ici, jamais renvoyés par `core/`.
fn lang<'a>(fr: &'a str, en: &'a str) -> &'a str {
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        en
    } else {
        fr
    }
}

/// Remplace `.t_err()` : convertit une erreur en `String`
/// traduite selon la langue d'interface courante, au lieu d'un `.to_string()` brut.
trait TranslatedResult<T> {
    fn t_err(self) -> Result<T, String>;
}

impl<T, E: std::fmt::Display> TranslatedResult<T> for Result<T, E> {
    fn t_err(self) -> Result<T, String> {
        self.map_err(|e| translate_error(&e.to_string()))
    }
}

// Sans ce hook, un panic imprévu (bug non détecté, dépendance tierce) ne laissait
// absolument aucune trace : la fenêtre disparaissait instantanément et silencieusement
// (pas de console en release, voir `windows_subsystem = "windows"` dans main.rs). On
// journalise l'emplacement et le message du panic — jamais de secret : nos propres
// `.expect()`/`panic!` n'embarquent que des messages statiques, jamais une valeur
// secrète (mot de passe, clé, entropie), et un panic venant d'une dépendance tierce ne
// peut porter que des données déjà publiques (adresse, réponse RPC), jamais un secret
// qui ne transite jamais par un message de panic dans ce projet.
fn install_panic_hook(log_dir: PathBuf) {
    let log_path = log_dir.join("crash.log");
    std::panic::set_hook(Box::new(move |info| {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "emplacement inconnu".to_string());
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "message indisponible".to_string());
        let line = format!("[{timestamp}] panic à {location} : {message}\n");
        // Best-effort : si l'écriture du log échoue, on ne doit surtout pas déclencher
        // un second panic depuis le hook lui-même.
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            use std::io::Write;
            let _ = file.write_all(line.as_bytes());
        }
    }));
}

fn data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| translate_error(&format!("répertoire de données introuvable : {e}")))?;
    std::fs::create_dir_all(&dir).map_err(|e| translate_error(&format!("création du répertoire de données impossible : {e}")))?;
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
        .map_err(|e| translate_error(&format!("contenu base64 invalide : {e}")))?;

    let chosen = app.dialog().file().set_file_name(&suggested_name).blocking_save_file();

    match chosen {
        Some(file_path) => {
            let path = file_path.into_path().t_err()?;
            std::fs::write(path, bytes).map_err(|e| translate_error(&format!("écriture du fichier impossible : {e}")))?;
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
        return Err(translate_error(
            "lien refusé : seuls les explorateurs de blocs connus de l'app sont autorisés",
        ));
    }
    app.opener().open_url(url, None::<&str>).t_err()
}

/// Génère un QR code (SVG) pour une adresse publique — aucune donnée sensible,
/// juste un confort d'affichage pour recevoir des fonds.
#[tauri::command]
fn generate_qr_svg(text: String) -> Result<String, String> {
    let code = qrcode::QrCode::new(text.as_bytes()).t_err()?;
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

/// Trouvé lors du 22ᵉ passage : la seule action IRRÉVERSIBLE de l'app sans
/// confirmation native. Restaurer, régénérer le kit, activer/désactiver
/// Windows Hello passent tous par une boîte de l'OS (un frontend compromis
/// ne peut ni la simuler ni la contourner) ; supprimer le coffre ne passait
/// que par un `confirm()` JavaScript, que ce même frontend peut sauter — un
/// script aurait pu effacer le portefeuille sans mot de passe ni clic, et
/// sans kit de sauvegarde les fonds étaient perdus pour toujours. Pas de mot
/// de passe exigé (réinitialiser reste le recours en cas d'oubli), mais une
/// boîte native, comme pour les autres actions de ce niveau.
fn confirm_reset_native(app: &tauri::AppHandle) -> bool {
    app.dialog()
        .message(lang(
            "Ceci va SUPPRIMER le portefeuille de cet appareil (coffre et clé de l'appareil). \
             Il ne pourra être récupéré qu'avec 2 des 3 parts de votre kit de sauvegarde : sans elles, \
             les fonds seront définitivement perdus. Ne continuez que si vous avez initié cette action vous-même.",
            "This will DELETE the wallet from this device (vault and device key). It can only be recovered \
             with 2 of the 3 shares of your backup kit: without them, the funds will be lost forever. Only \
             continue if you initiated this action yourself.",
        ))
        .title(lang("Confirmer la suppression du portefeuille", "Confirm wallet deletion"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Supprime le coffre local (voir `api::reset_wallet`) : permet de revenir à
/// l'onboarding sans avoir à retrouver/effacer manuellement le répertoire de
/// données de l'app. Le wallet reste récupérable via les 3 parts de sauvegarde
/// exportées à la création, si elles ont été conservées.
#[tauri::command]
fn reset_wallet(app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    if !confirm_reset_native(&app) {
        return Err(translate_error("Réinitialisation annulée (confirmation refusée)."));
    }
    api::reset_wallet(&dir).t_err()
}

#[tauri::command]
fn create_wallet(password: String, app: tauri::AppHandle) -> Result<CreateWalletDto, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let result = api::create_wallet(&dir, &password).t_err()?;

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
        .message(lang(
            "Ceci va générer un nouveau kit de sauvegarde (3 fichiers + 3 mots de passe permettant \
             à quiconque les possède de reconstruire votre portefeuille, sans jamais avoir besoin de \
             votre mot de passe d'appareil). Ne continuez que si vous avez initié cette action vous-même.",
            "This will generate a new backup kit (3 files + 3 passwords letting anyone who has them \
             rebuild your wallet, without ever needing your device password). Only continue if you \
             initiated this action yourself.",
        ))
        .title(lang("Confirmer la régénération du kit de sauvegarde", "Confirm backup kit regeneration"))
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
        return Err(translate_error("Régénération annulée (confirmation refusée)."));
    }

    api::regenerate_backup_kit(&dir, &password)
        .map(|backups| backups.into_iter().map(Into::into).collect())
        .t_err()
}

/// Adresse THORChain (RUNE) dérivée de la même entropie maître (voir
/// `api::get_thor_fee_address`) : purement informatif, sert uniquement à
/// recevoir les frais d'affiliation des swaps. Pas de confirmation native
/// ici (lecture seule, aucun fonds ne bouge) — le mot de passe suffit,
/// exactement comme pour afficher les autres adresses du portefeuille.
#[tauri::command]
fn get_thor_fee_address(password: String, app: tauri::AppHandle) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::get_thor_fee_address(&dir, &password).t_err()
}

#[tauri::command]
fn unlock_wallet(password: String, app: tauri::AppHandle) -> Result<Vec<ProfileDto>, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::unlock_wallet(&dir, &password)
        .map(|profiles| profiles.into_iter().map(Into::into).collect())
        .t_err()
}

/// Heuristique d'affichage uniquement (ne fait pas partie de la barrière de
/// sécurité) : indique si Windows Hello semble configuré sur cette machine,
/// pour ne proposer le bouton d'activation que quand ça a une chance de
/// fonctionner. `false` sur toute plateforme autre que Windows.
#[tauri::command]
fn biometric_unlock_available() -> bool {
    #[cfg(windows)]
    {
        pgp_wallet_poc::windows_hello::is_available()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[tauri::command]
fn biometric_unlock_enrolled(app: tauri::AppHandle) -> Result<bool, String> {
    let dir = data_dir(&app)?;
    Ok(api::biometric_unlock_enrolled(&dir))
}

/// Même raison que `confirm_regenerate_backup_native` : activer un second moyen
/// de déverrouiller le coffre est une action de sécurité, rendue visible et
/// impossible à déclencher silencieusement par un frontend compromis grâce au
/// dialogue natif de l'OS.
fn confirm_enroll_biometric_native(app: &tauri::AppHandle) -> bool {
    app.dialog()
        .message(lang(
            "Ceci va activer un second moyen de déverrouiller ce portefeuille sur CET appareil, via \
             Windows Hello (empreinte, visage ou code confidentiel), en plus du mot de passe actuel — \
             celui-ci reste nécessaire pour les actions sensibles (sauvegarde, suppression de profil, \
             désactivation de cette option). Ne continuez que si vous avez initié cette action vous-même.",
            "This will enable a second way to unlock this wallet on THIS device, via Windows Hello \
             (fingerprint, face, or PIN), in addition to your current password — which remains required \
             for sensitive actions (backup, profile deletion, disabling this option). Only continue if \
             you initiated this action yourself.",
        ))
        .title(lang("Confirmer l'activation de Windows Hello", "Confirm enabling Windows Hello"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn enroll_biometric_unlock(password: String, app: tauri::AppHandle) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    if !confirm_enroll_biometric_native(&app) {
        return Err(translate_error("Activation annulée (confirmation refusée)."));
    }
    api::enroll_biometric_unlock(&dir, &password).t_err()
}

/// Déverrouille le coffre via Windows Hello plutôt que le mot de passe — voir
/// `api::unlock_wallet_biometric`. Renvoie les mêmes `ProfileDto` que
/// `unlock_wallet`.
#[tauri::command]
fn unlock_wallet_biometric(app: tauri::AppHandle) -> Result<Vec<ProfileDto>, String> {
    let dir = data_dir(&app)?;
    api::unlock_wallet_biometric(&dir)
        .map(|profiles| profiles.into_iter().map(Into::into).collect())
        .t_err()
}

fn confirm_disable_biometric_native(app: &tauri::AppHandle) -> bool {
    app.dialog()
        .message(lang(
            "Ceci va désactiver le déverrouillage par Windows Hello sur cet appareil — seul le mot de \
             passe permettra ensuite de déverrouiller ce portefeuille. Ne continuez que si vous avez \
             initié cette action vous-même.",
            "This will disable Windows Hello unlock on this device — only the password will then unlock \
             this wallet. Only continue if you initiated this action yourself.",
        ))
        .title(lang("Confirmer la désactivation de Windows Hello", "Confirm disabling Windows Hello"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn disable_biometric_unlock(password: String, app: tauri::AppHandle) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    if !confirm_disable_biometric_native(&app) {
        return Err(translate_error("Désactivation annulée (confirmation refusée)."));
    }
    api::disable_biometric_unlock(&dir, &password).t_err()
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
        .t_err()
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
    api::delete_profile(&dir, &password, index).t_err()
}

/// Suppression "légère" et réversible (voir `api::archive_profile`) : pas de mot de
/// passe requis, rien n'est irréversible — le profil peut être restauré à tout
/// moment via `unarchive_profile`.
#[tauri::command]
fn archive_profile(index: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    api::archive_profile(&dir, index).t_err()
}

#[tauri::command]
fn unarchive_profile(index: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    api::unarchive_profile(&dir, index).t_err()
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
        .message(lang(
            "Ceci va remplacer le portefeuille actuel de cet appareil par celui reconstruit \
             à partir des 2 fichiers de sauvegarde fournis. Ne continuez que si vous êtes sûr(e) de \
             leur provenance — quelqu'un d'autre en possession de 2 de vos parts pourrait sinon \
             substituer son propre wallet au vôtre.",
            "This will replace the current wallet on this device with the one rebuilt from the 2 backup \
             files provided. Only continue if you are sure of their origin — someone else in possession \
             of 2 of your shares could otherwise substitute their own wallet for yours.",
        ))
        .title(lang("Confirmer la restauration", "Confirm restoration"))
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
        return Err(translate_error("Restauration annulée (confirmation refusée)."));
    }

    let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).t_err();

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
    .t_err()
}

fn evm_network(network: &str) -> Result<&'static wallet_flow::EvmNetwork, String> {
    match network {
        "evm_sepolia" => Ok(&wallet_flow::SEPOLIA),
        "evm_mainnet" => Ok(&wallet_flow::ETHEREUM_MAINNET),
        other => Err(translate_error(&format!("réseau EVM inconnu : {other}"))),
    }
}

fn sol_network(network: &str) -> Result<&'static wallet_flow::SolNetwork, String> {
    match network {
        "sol_devnet" => Ok(&wallet_flow::SOLANA_DEVNET),
        "sol_mainnet" => Ok(&wallet_flow::SOLANA_MAINNET),
        other => Err(translate_error(&format!("réseau Solana inconnu : {other}"))),
    }
}

fn btc_network(network: &str) -> Result<&'static wallet_flow::BtcNetwork, String> {
    match network {
        "btc_testnet" => Ok(&wallet_flow::BTC_TESTNET),
        "btc_mainnet" => Ok(&wallet_flow::BTC_MAINNET),
        other => Err(translate_error(&format!("réseau Bitcoin inconnu : {other}"))),
    }
}

#[tauri::command]
fn get_balance(network: String, address: String) -> Result<String, String> {
    match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => {
            let net = evm_network(&network)?;
            let wei = api::get_evm_balance(&address, net).t_err()?;
            Ok(format!("{:.6}", wei as f64 / 1e18))
        }
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            let sat = api::get_btc_balance(&address, net).t_err()?;
            Ok(format!("{:.8}", sat as f64 / 1e8))
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            let lamports = api::get_sol_balance(&address, net).t_err()?;
            Ok(format!("{:.9}", lamports as f64 / 1e9))
        }
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
    }
}

/// Solde USDC — mainnet uniquement (voir sol_spl.rs : pas de mint devnet
/// vérifié avec confiance, et aucun intérêt pratique à en tester un).
#[tauri::command]
fn get_usdc_balance(network: String, address: String) -> Result<String, String> {
    if network != "sol_mainnet" {
        return Err(translate_error("USDC n'est disponible que sur Solana mainnet."));
    }
    let net = sol_network(&network)?;
    let micros = api::get_usdc_balance(&address, net).t_err()?;
    Ok(format!("{:.6}", micros as f64 / 1e6))
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
    let estimate = api::estimate_btc_fees(&address, net).t_err()?;
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
            api::has_pending_btc(&address, net).t_err()
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            api::has_pending_sol(&address, net).t_err()
        }
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
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
            let txs = history::evm_history(net.chain_id, &address, HISTORY_LIMIT as usize).t_err()?;
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
            let txs = history::btc_history(net, &address).t_err()?;
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
            let txs = history::sol_history(net.rpc, &address, HISTORY_LIMIT).t_err()?;
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
        other => return Err(translate_error(&format!("réseau inconnu : {other}"))),
    };
    Ok(entries)
}

/// Mainnet uniquement (v1, voir core/src/sol_spl.rs — même contrainte que
/// `get_usdc_balance`/`send_usdc_transaction`) : `network` n'est là que pour
/// rester cohérent avec `get_tx_history` côté frontend, une seule valeur est
/// acceptée.
#[tauri::command]
fn get_usdc_tx_history(network: String, address: String) -> Result<Vec<TxEntryDto>, String> {
    if network != "sol_mainnet" {
        return Err(translate_error(&format!("réseau inconnu : {network}")));
    }
    let net = sol_network(&network)?;
    let txs = api::get_usdc_tx_history(&address, net, HISTORY_LIMIT).t_err()?;
    Ok(txs
        .into_iter()
        .map(|tx| TxEntryDto {
            id: tx.id.clone(),
            timestamp_unix: tx.timestamp_unix,
            status: status_str(&tx.status).to_string(),
            amount: format_signed_amount(tx.net_amount_minor, 6),
            explorer_url: format!("{}{}{}", net.explorer_tx_prefix, tx.id, net.explorer_tx_suffix),
        })
        .collect())
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
        .t_err()
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
        .t_err()
}

// --- Texte des boîtes de dialogue natives -------------------------------------
// Trouvé lors du 22ᵉ passage, et reproduit pour de vrai (même bibliothèque,
// même TaskDialog Windows) : ces boîtes affichaient TELS QUELS des textes
// venus du frontend ou saisis librement — libellé de profil, libellé d'un
// contact du carnet, adresse, montant. Un libellé contenant des retours à la
// ligne y injectait un faux "Destinataire / Montant" en tête, et repoussait
// les vraies valeurs (et les boutons) hors de l'écran — la touche Entrée
// confirmait quand même. Or cette boîte est précisément la dernière barrière
// contre un frontend compromis : rien de ce qu'il contrôle ne doit pouvoir y
// imiter autre chose que ce qu'il est.

/// Caractère qui ne doit jamais atteindre une boîte native depuis une donnée
/// non fiable : contrôles (retours à la ligne, tabulations, NEL…), espaces
/// autres que l'espace ordinaire (séparateurs de ligne/paragraphe Unicode…),
/// et caractères invisibles ou de contrôle de direction du texte (qui peuvent
/// réordonner visuellement une adresse).
fn is_dialog_hazard(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(
            c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}'
        )
}

/// Libellé libre (profil, contact) prêt pour une boîte native : une seule
/// ligne, sans caractère invisible, longueur bornée.
fn dialog_label(label: &str) -> String {
    const MAX_CHARS: usize = 40;
    let cleaned: String = label.chars().map(|c| if is_dialog_hazard(c) { ' ' } else { c }).collect();
    let cleaned = cleaned.split(' ').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() > MAX_CHARS {
        format!("{}…", cleaned.chars().take(MAX_CHARS).collect::<String>())
    } else {
        cleaned
    }
}

/// Adresse saisie : espaces de bord retirés, puis REFUS de tout caractère
/// invisible ou espace restant — aucune adresse valide n'en contient. La
/// valeur renvoyée est celle affichée ET transmise à la signature.
fn canonical_address_input(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c == ' ' || is_dialog_hazard(c)) {
        return Err(translate_error("adresse invalide : espaces, retours à la ligne ou caractères invisibles refusés"));
    }
    Ok(trimmed.to_string())
}

/// Libellé humain du réseau pour la boîte de dialogue de confirmation.
fn network_label(network: &str) -> &str {
    match network {
        "evm_sepolia" => "Ethereum Sepolia (testnet)",
        "evm_mainnet" => lang("Ethereum MAINNET — fonds réels", "Ethereum MAINNET — real funds"),
        "btc_testnet" => lang("Bitcoin testnet", "Bitcoin testnet"),
        "btc_mainnet" => lang("Bitcoin MAINNET — fonds réels", "Bitcoin MAINNET — real funds"),
        "sol_devnet" => lang("Solana devnet", "Solana devnet"),
        "sol_mainnet" => lang("Solana MAINNET — fonds réels", "Solana MAINNET — real funds"),
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
    warning: Option<&str>,
) -> bool {
    app.dialog()
        .message(transaction_confirmation_text(network, to, amount, from_label, fee_line, warning))
        .title(lang("Confirmer le virement", "Confirm the transfer"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Texte de `confirm_transaction_native`, séparé pour être testable sans
/// ouvrir de fenêtre (voir `dialog_text_cannot_be_spoofed_by_untrusted_strings`).
fn transaction_confirmation_text(
    network: &str,
    to: &str,
    amount: &str,
    from_label: &str,
    fee_line: Option<&str>,
    warning: Option<&str>,
) -> String {
    let fee_line = fee_line.map(|f| format!("\n{f}")).unwrap_or_default();
    // En TÊTE du message : c'est la première chose lue, avant l'adresse.
    let warning = warning.map(|w| format!("{w}\n\n")).unwrap_or_default();
    let from_label = dialog_label(from_label);
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "{warning}Network: {}\nFrom profile: {from_label}\nRecipient: {to}\nAmount: {amount}{fee_line}\n\nConfirm this transfer? It is irreversible.",
            network_label(network)
        )
    } else {
        format!(
            "{warning}Réseau : {}\nDepuis le profil : {from_label}\nDestinataire : {to}\nMontant : {amount}{fee_line}\n\nConfirmer cet envoi ? C'est irréversible.",
            network_label(network)
        )
    }
}

/// Avertissement "empoisonnement d'adresse" (voir
/// `address_book::lookalike_entry`) : l'adresse saisie imite début et fin
/// d'un contact du carnet sans être la sienne.
fn lookalike_warning(dir: &std::path::Path, to: &str) -> Option<String> {
    let entries = address_book::list_entries(dir);
    let entry = address_book::lookalike_entry(&entries, to)?;
    let label = dialog_label(&entry.label);
    Some(if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "WARNING: this address LOOKS LIKE \"{label}\" from your address book (same beginning and end) but it is NOT the same address. \
             This is a common scam (address poisoning): compare every character before confirming."
        )
    } else {
        format!(
            "ATTENTION : cette adresse RESSEMBLE à « {label} » de votre carnet (même début, même fin) mais ce n'est PAS la même adresse. \
             Arnaque courante (empoisonnement d'adresse) : comparez chaque caractère avant de confirmer."
        )
    })
}

/// Avertissements "adresse destinataire" en tête de la boîte de confirmation,
/// demandés par l'utilisateur : (1) aucun envoi vers cette adresse n'est
/// enregistré dans ce portefeuille (voir `sent_recipients`) ; (2) sur la
/// blockchain, l'adresse n'a jamais servi, ou est vide ; `activity` à `None`
/// si cette lecture a échoué — dit explicitement plutôt qu'un silence qui
/// passerait pour rassurant. `coin` : "evm", "btc", "sol" ou "usdc" (nomme
/// l'actif absent, une adresse "vide" de SOL pouvant détenir autre chose).
fn recipient_warning_lines(first_send: bool, coin: &str, activity: Option<api::RecipientActivity>) -> Vec<String> {
    let mut lines = Vec::new();
    if first_send {
        lines.push(
            lang(
                "ATTENTION — NOUVELLE ADRESSE : vous n'avez jamais envoyé de fonds à cette adresse depuis ce portefeuille. \
                 Vérifiez-la caractère par caractère auprès du destinataire.",
                "WARNING — NEW ADDRESS: you have never sent funds to this address from this wallet. \
                 Check it character by character with the recipient.",
            )
            .to_string(),
        );
    }
    let (asset_fr, asset_en) = match coin {
        "evm" => ("aucun ETH", "no ETH"),
        "btc" => ("aucun BTC", "no BTC"),
        "usdc" => ("ni SOL ni USDC", "neither SOL nor USDC"),
        _ => ("aucun SOL", "no SOL"),
    };
    let (history_fr, history_en) = if coin == "evm" {
        ("aucune transaction envoyée, aucun ETH", "no transaction sent, no ETH")
    } else {
        ("aucune transaction", "no transaction")
    };
    match activity {
        Some(api::RecipientActivity::Funded) => {}
        Some(api::RecipientActivity::Unused) => lines.push(if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!(
                "On the blockchain, this address has NEVER been used ({history_en}). If you meant to pay an exchange or a usual contact, this is probably a copy mistake."
            )
        } else {
            format!(
                "Sur la blockchain, cette adresse n'a JAMAIS servi ({history_fr}). Si vous pensiez payer une plateforme ou un contact habituel, c'est probablement une erreur de copie."
            )
        }),
        Some(api::RecipientActivity::Empty) => lines.push(if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("On the blockchain, this address is EMPTY: it has been used before, but currently holds {asset_en}.")
        } else {
            format!("Sur la blockchain, cette adresse est VIDE : elle a déjà servi, mais ne contient actuellement {asset_fr}.")
        }),
        None => lines.push(
            lang(
                "État de cette adresse sur la blockchain : impossible à vérifier pour le moment (réseau).",
                "Status of this address on the blockchain: could not be checked right now (network).",
            )
            .to_string(),
        ),
    }
    lines
}

/// Tous les avertissements d'un envoi, dans l'ordre de gravité : sosie d'un
/// contact du carnet, puis nouvelle adresse, puis état on-chain.
fn send_warnings(dir: &std::path::Path, network: &str, coin: &str, to: &str, activity: Option<api::RecipientActivity>) -> Option<String> {
    let mut lines: Vec<String> = lookalike_warning(dir, to).into_iter().collect();
    lines.extend(recipient_warning_lines(!sent_recipients::has_sent_to(dir, network, to), coin, activity));
    (!lines.is_empty()).then(|| lines.join("\n\n"))
}

/// Frais EVM MAXIMUM (prix du gas × limite de gas) : une transaction legacy
/// paie `gas consommé × prix`, jamais plus que la limite — c'est donc une
/// borne réelle, pas une estimation qui pourrait être dépassée.
fn evm_fee_line(gas_price: u128, gas_limit: u64) -> String {
    let max_fee_eth = (gas_price.saturating_mul(u128::from(gas_limit))) as f64 / 1e18;
    let gwei = gas_price as f64 / 1e9;
    lang(
        &format!("Frais réseau maximum : {max_fee_eth:.6} ETH ({gwei:.2} gwei)"),
        &format!("Maximum network fee: {max_fee_eth:.6} ETH ({gwei:.2} gwei)"),
    )
    .to_string()
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

    // Réseau validé AVANT la boîte de confirmation (22ᵉ passage) : un réseau
    // inconnu était jusqu'ici affiché tel quel (texte libre du frontend) dans
    // la boîte, l'erreur n'arrivant qu'après. Adresse et montant remplacés par
    // leur forme canonique, utilisée pour l'affichage ET la signature (voir
    // `canonical_address_input`/`api::canonical_amount`).
    let coin = match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => "evm",
        "btc_testnet" | "btc_mainnet" => "btc",
        "sol_devnet" | "sol_mainnet" => "sol",
        other => return Err(translate_error(&format!("réseau inconnu : {other}"))),
    };
    let to = canonical_address_input(&to)?;
    let amount = api::canonical_amount(coin, &amount).t_err()?;

    let from_label = api::list_profiles(&dir)
        .into_iter()
        .find(|p| p.index == profile_index)
        .map(|p| p.label)
        .unwrap_or_else(|| format!("profil #{profile_index}"));

    // Frais affichés dans la boîte de dialogue native (voir sa doc : "montre
    // exactement ce que le backend a compris") : choisis par l'utilisateur pour
    // Bitcoin ; pour EVM, prix du gas lu MAINTENANT et utilisé tel quel pour
    // signer — avant, il était lu auprès du nœud APRÈS la confirmation, jamais
    // affiché (voir `api::evm_gas_price_for_confirmation`).
    let evm_gas_price = match coin {
        "evm" => Some(api::evm_gas_price_for_confirmation(evm_network(&network)?).t_err()?),
        _ => None,
    };
    // Adresse refusée AVANT la confirmation si elle est mal formée (EVM/BTC :
    // jusqu'ici seulement au moment de signer) ou, pour Solana, si ce n'est
    // pas un portefeuille (voir `api::check_solana_recipient`). Puis état de
    // l'adresse sur la blockchain, pour les avertissements de la boîte.
    let activity = match coin {
        "evm" => {
            api::validate_evm_recipient(&to).t_err()?;
            api::evm_recipient_activity(&to, evm_network(&network)?).ok()
        }
        "btc" => {
            let net = btc_network(&network)?;
            api::validate_btc_recipient(&to, net).t_err()?;
            api::btc_recipient_activity(&to, net).ok()
        }
        _ => {
            let net = sol_network(&network)?;
            api::check_solana_recipient(&to, net).t_err()?;
            api::sol_recipient_activity(&to, net).ok()
        }
    };
    // Ligne de frais choisie d'après le RÉSEAU, jamais d'après la simple
    // présence de `fee_sat` (22ᵉ passage) : un `fee_sat` envoyé pour un
    // virement ETH remplaçait jusqu'ici l'affichage des vrais frais de gas par
    // un "Frais : 1 sat" sans rapport avec ce qui serait payé.
    let fee_line = match coin {
        "btc" => {
            let fee_sat = fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
            Some(format!("{} : {fee_sat} sat", lang("Frais", "Fee")))
        }
        _ => evm_gas_price.map(|gas_price| evm_fee_line(gas_price, api::EVM_TRANSFER_GAS_LIMIT)),
    };

    let warning = send_warnings(&dir, &network, coin, &to, activity);
    if !confirm_transaction_native(&app, &network, &to, &amount, &from_label, fee_line.as_deref(), warning.as_deref()) {
        return Err(translate_error("Virement annulé (confirmation refusée)."));
    }

    let result = match network.as_str() {
        "evm_sepolia" | "evm_mainnet" => {
            let net = evm_network(&network)?;
            let gas_price = evm_gas_price.ok_or_else(|| "prix du gas manquant".to_string())?;
            api::send_evm(&dir, &password, net, &to, &amount, gas_price, profile_index).t_err()
        }
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            let fee_sat = fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
            api::send_btc(&dir, &password, net, &to, &amount, fee_sat, profile_index).t_err()
        }
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            api::send_sol(&dir, &password, net, &to, &amount, profile_index).t_err()
        }
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
    };
    // Destinataire mémorisé SEULEMENT après une diffusion réussie (voir
    // `sent_recipients`). Un échec d'écriture du journal ne doit pas faire
    // croire à l'échec d'un envoi déjà parti.
    if result.is_ok() {
        let _ = sent_recipients::record_sent(&dir, &network, &to);
    }
    result
}

/// Indique si l'envoi USDC vers `to` va facturer un rent supplémentaire (le
/// destinataire n'a pas encore de compte USDC) — lecture seule, appelée AVANT
/// la confirmation pour ne jamais présenter un coût caché après coup. `None`
/// si l'ATA du destinataire existe déjà (aucun coût supplémentaire), ou si
/// `to` n'est pas une adresse Solana valide ou que la lecture réseau échoue
/// (l'erreur sera de toute façon remontée normalement par `send_usdc` juste
/// après ; ici on préfère ne rien afficher plutôt que de bloquer sur un
/// problème réseau avant même la confirmation).
fn describe_possible_ata_rent(net: &wallet_flow::SolNetwork, to: &str) -> Option<String> {
    let rent_lamports = api::usdc_ata_rent_lamports_if_missing(to, net).ok()??;
    let sol = rent_lamports as f64 / 1e9;
    Some(if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "The recipient doesn't have a USDC account yet: creating it will cost about {sol:.6} extra SOL in rent (paid by you, once), on top of the usual network fee."
        )
    } else {
        format!(
            "Le destinataire n'a pas encore de compte USDC : sa création coûtera environ {sol:.6} SOL de rent supplémentaire (payé par vous, une seule fois), en plus des frais réseau habituels."
        )
    })
}

// --- Swap (THORChain) --------------------------------------------------------
// Un swap réel entre BTC/ETH/SOL n'a aucun mécanisme on-chain natif : passe
// nécessairement par un protocole externe (voir core/src/thorchain_rpc.rs).
// v1 : source Solana uniquement (le moins de nouveau code, voir le plan) ;
// obtenir un devis reste possible pour n'importe quelle paire connue
// (lecture seule, aucun risque), seul l'ENVOI est restreint à "sol" pour
// l'instant.

#[derive(Serialize)]
struct SwapQuoteDto {
    inbound_address: String,
    memo: String,
    /// Déjà à l'échelle 1e8 utilisée par THORChain pour TOUS les actifs —
    /// donc affichable tel quel (divisé par 1e8), sans jamais repasser par les
    /// décimales natives de l'actif de destination.
    expected_amount_out: String,
    total_fees: Option<String>,
}

fn format_1e8(amount: u64) -> String {
    format!("{:.8}", amount as f64 / 1e8)
}

#[tauri::command]
fn get_swap_quote(from_coin: String, to_coin: String, amount: String, destination: String) -> Result<SwapQuoteDto, String> {
    let quote = api::get_swap_quote(&from_coin, &to_coin, &amount, &destination).t_err()?;
    Ok(SwapQuoteDto {
        inbound_address: quote.inbound_address,
        memo: quote.memo,
        expected_amount_out: format_1e8(quote.expected_amount_out),
        total_fees: quote.total_fees.map(format_1e8),
    })
}

/// Confirmation native spécifique au swap : contrairement à un envoi normal,
/// mentionne explicitement qu'il s'agit d'un protocole EXTERNE (THORChain),
/// avec ses propres frais + les 0,80% d'affiliation, et que l'app elle-même
/// ne peut garantir le bon déroulement au-delà de l'envoi de cette
/// transaction (voir core/src/thorchain_rpc.rs pour le contexte complet).
///
/// Montre aussi l'adresse de vault réelle (`inbound_address`, et le contrat
/// routeur pour un swap EVM) — trouvé lors de l'audit de cette
/// fonctionnalité : contrairement à `confirm_transaction_native` (envoi
/// normal), qui montre TOUJOURS le destinataire réel pour se protéger
/// justement de la "signature aveugle" (voir ETAPES.md, 15ᵉ passage), cette
/// boîte ne montrait jusqu'ici que le montant/l'actif, jamais l'adresse
/// réellement payée. Cette adresse vient d'un tiers (la passerelle THORChain
/// interrogée pour le devis, jamais un nœud opéré par ce projet) : l'afficher
/// ne le rend pas plus fiable en soi, mais restaure le même principe "on
/// signe ce qu'on voit" que le reste de l'app, et donne à un utilisateur
/// attentif une chance de repérer une adresse manifestement incohérente.
///
/// Montre aussi `final_destination` (l'adresse sur la chaîne d'ARRIVÉE, celle
/// que THORChain paiera une fois le swap exécuté) — trouvé dans le même audit :
/// contrairement au vault (opaque, l'utilisateur ne peut pas juger s'il est
/// légitime), cette adresse est normalement LA SIENNE (pré-remplie par le
/// frontend, mais reste modifiable) — exactement le genre de valeur qu'un
/// détournement d'adresse (presse-papier, frontend compromis) chercherait à
/// altérer, et que l'utilisateur PEUT vérifier lui-même contre l'adresse déjà
/// affichée ailleurs dans l'app pour ce réseau.
fn confirm_swap_native(
    app: &tauri::AppHandle,
    from_label: &str,
    amount: &str,
    expected_out: &str,
    to_coin: &str,
    pay_to: &str,
    router: Option<&str>,
    final_destination: &str,
    network_fee_line: Option<&str>,
) -> bool {
    let network_fee_line = network_fee_line.map(|f| format!("{f}\n")).unwrap_or_default();
    let from_label = dialog_label(from_label);
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let vault_line = match (router, english) {
        (Some(router), true) => format!("Actual destination: router contract {router}\n(THORChain vault targeted: {pay_to})\n"),
        (Some(router), false) => format!("Destination réelle : contrat routeur {router}\n(coffre THORChain visé : {pay_to})\n"),
        (None, true) => format!("Actual destination: {pay_to}\n"),
        (None, false) => format!("Destination réelle : {pay_to}\n"),
    };
    let arrival_line = if final_destination.is_empty() {
        String::new()
    } else if english {
        format!("Funds will arrive at: {final_destination}\n(verify this is really your own address)\n")
    } else {
        format!("Les fonds arriveront sur : {final_destination}\n(vérifiez qu'il s'agit bien de votre propre adresse)\n")
    };
    let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "Swap via THORChain (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nSending: {amount}\nExpected to receive: ~{expected_out} {}\n{vault_line}{arrival_line}{network_fee_line}\nIncludes THORChain's own network/liquidity fees, plus a 0.80% affiliate fee.\nThis is irreversible, and once sent this app can no longer track or reverse it.\n\nConfirm this swap?",
            to_coin.to_uppercase()
        )
    } else {
        format!(
            "Échange via THORChain (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {amount}\nRéception attendue : ~{expected_out} {}\n{vault_line}{arrival_line}{network_fee_line}\nInclut les frais propres à THORChain (réseau/liquidité), plus 0,80% de frais d'affiliation.\nC'est irréversible, et une fois envoyé cette app ne peut plus ni suivre ni annuler l'opération.\n\nConfirmer cet échange ?",
            to_coin.to_uppercase()
        )
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn swap_transaction(
    password: String,
    from_coin: String,
    to_coin: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;

    if !matches!(from_coin.as_str(), "sol" | "btc" | "evm") {
        return Err(translate_error(&format!(
            "envoi de swap non pris en charge pour cet actif : {from_coin}"
        )));
    }
    // Formes canoniques, affichées ET utilisées pour le devis et la signature
    // (voir `send_transaction`).
    let amount = api::canonical_amount(&from_coin, &amount).t_err()?;
    let destination = canonical_address_input(&destination)?;

    let from_label = api::list_profiles(&dir)
        .into_iter()
        .find(|p| p.index == profile_index)
        .map(|p| p.label)
        .unwrap_or_else(|| format!("profil #{profile_index}"));

    // Devis obtenu ICI, juste avant la confirmation, jamais mis en cache
    // (adresse de vault THORChain vivante, voir thorchain_rpc::SwapQuote).
    let quote = api::get_swap_quote(&from_coin, &to_coin, &amount, &destination).t_err()?;
    let amount_line = format!("{amount} {}", from_coin.to_uppercase());

    // Frais réseau affichés AVANT confirmation (et, pour EVM, prix du gas
    // réutilisé tel quel pour signer — voir `api::evm_gas_price_for_confirmation`).
    // Swap mainnet uniquement dans tous les cas : les pools THORChain n'ont
    // aucune existence sur les réseaux de test.
    let evm_gas_price = if from_coin == "evm" {
        Some(api::evm_gas_price_for_confirmation(evm_network("evm_mainnet")?).t_err()?)
    } else {
        None
    };
    let network_fee_line = match from_coin.as_str() {
        "evm" => evm_gas_price.map(|gp| evm_fee_line(gp, api::EVM_SWAP_MAX_GAS_LIMIT)),
        "sol" => Some(lang("Frais réseau : 0,000005 SOL", "Network fee: 0.000005 SOL").to_string()),
        _ => Some(
            lang(
                &format!("Frais réseau : vitesse moyenne, au plus {} sat/vB", api::BTC_SWAP_MAX_FEE_RATE_SAT_VB),
                &format!("Network fee: medium speed, at most {} sat/vB", api::BTC_SWAP_MAX_FEE_RATE_SAT_VB),
            )
            .to_string(),
        ),
    };

    let router_for_from_coin = if from_coin == "evm" { quote.router.as_deref() } else { None };
    if !confirm_swap_native(
        &app,
        &from_label,
        &amount_line,
        &format_1e8(quote.expected_amount_out),
        &to_coin,
        &quote.inbound_address,
        router_for_from_coin,
        &destination,
        network_fee_line.as_deref(),
    ) {
        return Err(translate_error("Échange annulé (confirmation refusée)."));
    }

    // Devis RE-lu après la confirmation (la boîte native bloque un temps
    // arbitraire, pendant lequel le vault peut tourner), mais refusé s'il ne
    // correspond plus à ce qui a été AFFICHÉ — voir
    // `api::refresh_swap_quote_matching`.
    let quote = api::refresh_swap_quote_matching(&from_coin, &to_coin, &amount, &destination, &quote).t_err()?;

    match from_coin.as_str() {
        "sol" => {
            let network = sol_network("sol_mainnet")?;
            api::send_swap_sol(&dir, &password, network, &quote, &amount, profile_index).t_err()
        }
        "btc" => {
            let network = btc_network("btc_mainnet")?;
            api::send_swap_btc(&dir, &password, network, &quote, &amount, profile_index).t_err()
        }
        "evm" => {
            let network = evm_network("evm_mainnet")?;
            let gas_price = evm_gas_price.ok_or_else(|| "prix du gas manquant".to_string())?;
            api::send_swap_evm(&dir, &password, network, &quote, &amount, gas_price, profile_index).t_err()
        }
        other => Err(translate_error(&format!("envoi de swap non pris en charge pour cet actif : {other}"))),
    }
}

// --- Swap (Jupiter) ----------------------------------------------------------
// Même chaîne uniquement (SOL <-> USDC), contrairement au swap cross-chain
// THORChain ci-dessus — voir core/src/jupiter_rpc.rs pour le contexte
// complet, notamment pourquoi la transaction elle-même n'est pas
// reconstruite à la main ici (seulement vérifiée puis signée).

const JUPITER_DEFAULT_SLIPPAGE_BPS: u32 = 50; // 0,50 %

fn decimals_for_swap_coin(coin: &str) -> u32 {
    if coin == "usdc" {
        6
    } else {
        9 // "sol"
    }
}

fn format_native_amount(amount: u64, decimals: u32) -> String {
    format!("{:.*}", decimals as usize, amount as f64 / 10f64.powi(decimals as i32))
}

#[tauri::command]
fn get_jupiter_quote(from_coin: String, to_coin: String, amount: String) -> Result<String, String> {
    let out_amount = api::get_jupiter_quote(&from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS).t_err()?;
    Ok(format_native_amount(out_amount, decimals_for_swap_coin(&to_coin)))
}

/// Confirmation native spécifique à Jupiter : contrairement à THORChain, ce
/// n'est pas un protocole cross-chain, mais reste un protocole EXTERNE non
/// audité par cette app, et la transaction elle-même est construite par
/// Jupiter (voir core/src/jupiter_rpc.rs), pas par cette app — simulée et
/// vérifiée (effets sur les comptes de l'utilisateur, voir
/// `api::check_swap_effects`) AVANT d'être signée, jamais reconstruite. Le
/// texte disait encore "vérifiée (payeur de frais)", resté de l'avant-21ᵉ
/// passage : il sous-décrivait la protection réelle.
fn confirm_jupiter_swap_native(app: &tauri::AppHandle, from_label: &str, amount: &str, expected_out: &str, to_coin: &str) -> bool {
    let from_label = dialog_label(from_label);
    let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "Swap via Jupiter (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nSending: {amount}\nExpected to receive: ~{expected_out} {}\nIncludes a 0.80% affiliate fee\n\nThe swap transaction itself is built by Jupiter, not by this app. Before signing, it is simulated and refused if it would take more than the amount sent plus network fees, or deliver less than the amount shown (0.5% slippage).\nThis is irreversible.\n\nConfirm this swap?",
            to_coin.to_uppercase()
        )
    } else {
        format!(
            "Échange via Jupiter (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {amount}\nRéception attendue : ~{expected_out} {}\nInclut 0,80% de frais d'affiliation\n\nLa transaction de swap elle-même est construite par Jupiter, pas par cette app. Avant signature, elle est simulée et refusée si elle prenait plus que le montant envoyé et les frais réseau, ou livrait moins que le montant affiché (glissement de 0,5 %).\nC'est irréversible.\n\nConfirmer cet échange ?",
            to_coin.to_uppercase()
        )
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn jupiter_swap_transaction(
    password: String,
    from_coin: String,
    to_coin: String,
    amount: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let network = sol_network("sol_mainnet")?; // Jupiter mainnet uniquement (pas de liquidité fiable en devnet)
    // Forme canonique, affichée ET signée (voir `send_transaction`).
    let amount = api::canonical_amount(&from_coin, &amount).t_err()?;

    let from_label = api::list_profiles(&dir)
        .into_iter()
        .find(|p| p.index == profile_index)
        .map(|p| p.label)
        .unwrap_or_else(|| format!("profil #{profile_index}"));

    // Devis relu ICI, juste avant la confirmation — jamais celui affiché dans
    // l'aperçu du frontend, potentiellement déjà légèrement périmé.
    let out_amount = api::get_jupiter_quote(&from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS).t_err()?;
    let expected_out = format_native_amount(out_amount, decimals_for_swap_coin(&to_coin));
    let amount_line = format!("{amount} {}", from_coin.to_uppercase());

    if !confirm_jupiter_swap_native(&app, &from_label, &amount_line, &expected_out, &to_coin) {
        return Err(translate_error("Échange annulé (confirmation refusée)."));
    }

    // `out_amount` = la sortie AFFICHÉE ci-dessus : la transaction réellement
    // signée devra la livrer (au glissement près), vérifié par simulation.
    api::send_jupiter_swap(&dir, &password, network, &from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS, out_amount, profile_index)
        .t_err()
}

#[tauri::command]
fn send_usdc_transaction(password: String, to: String, amount: String, profile_index: u32, app: tauri::AppHandle) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let network = "sol_mainnet"; // USDC v1 : mainnet uniquement (voir sol_spl.rs)
    let net = sol_network(network)?;
    // Formes canoniques, affichées ET signées (voir `send_transaction`).
    let to = canonical_address_input(&to)?;
    let amount = api::canonical_amount("usdc", &amount).t_err()?;

    let from_label = api::list_profiles(&dir)
        .into_iter()
        .find(|p| p.index == profile_index)
        .map(|p| p.label)
        .unwrap_or_else(|| format!("profil #{profile_index}"));

    // Refus AVANT la boîte de confirmation si le destinataire n'est pas un
    // portefeuille (voir `api::check_solana_recipient`) — le cas type étant
    // l'adresse d'un compte de jetons copiée depuis un explorateur.
    api::check_solana_recipient(&to, net).t_err()?;

    let rent_line = describe_possible_ata_rent(net, &to);
    let amount_line = format!("{amount} USDC");
    // Même journal que les envois SOL (même réseau, même portefeuille
    // destinataire) : avoir déjà payé cette adresse en SOL compte.
    let warning = send_warnings(&dir, network, "usdc", &to, api::usdc_recipient_activity(&to, net).ok());
    if !confirm_transaction_native(&app, network, &to, &amount_line, &from_label, rent_line.as_deref(), warning.as_deref()) {
        return Err(translate_error("Virement annulé (confirmation refusée)."));
    }

    let result = api::send_usdc(&dir, &password, net, &to, &amount, profile_index).t_err();
    if result.is_ok() {
        let _ = sent_recipients::record_sent(&dir, network, &to);
    }
    result
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
    /// Identifiant de clé et identité PGP (nom/e-mail embarqués dans le
    /// certificat) — ajoutés pour la consultation détaillée d'un destinataire
    /// (modale "Consulter la clé"), même trio d'informations que l'onglet
    /// Certificat pour la propre identité de l'appareil.
    key_id: String,
    user_id: String,
}

impl From<messaging::Recipient> for RecipientDto {
    fn from(r: messaging::Recipient) -> Self {
        let info = messaging::cert_info(&r.pubkey_armored).ok();
        Self {
            label: r.label,
            pubkey_armored: r.pubkey_armored,
            fingerprint: info.as_ref().map(|i| i.fingerprint.clone()).unwrap_or_else(|| "invalide".to_string()),
            key_id: info.as_ref().map(|i| i.key_id.clone()).unwrap_or_default(),
            user_id: info.map(|i| i.user_id).unwrap_or_default(),
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
    let armored = api::read_device_pubkey_armored(&dir).t_err()?;
    messaging::cert_info(&armored).map(Into::into).t_err()
}

#[tauri::command]
fn list_recipients(app: tauri::AppHandle) -> Result<Vec<RecipientDto>, String> {
    let dir = data_dir(&app)?;
    messaging::list_recipients(&dir)
        .map(|v| v.into_iter().map(Into::into).collect())
        .t_err()
}

#[tauri::command]
fn add_recipient(label: String, pubkey_armored: String, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;

    if let Some((old_fingerprint, new_fingerprint)) =
        messaging::recipient_key_change(&dir, &label, &pubkey_armored).t_err()?
    {
        // Boîte de dialogue native, même mécanisme que pour un envoi de fonds : un
        // remplacement de clé pour un contact déjà enregistré n'est pas anodin (voir
        // la doc de `recipient_key_change`), donc pas question de le laisser passer
        // silencieusement comme le ferait `messaging::add_recipient` seule.
        // Libellé nettoyé pour l'affichage uniquement (voir `dialog_label`).
        let label = dialog_label(&label);
        let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!(
                "\"{label}\" already has a registered key, different from this one.\n\n\
                 Old fingerprint: {old_fingerprint}\n\
                 New fingerprint: {new_fingerprint}\n\n\
                 If you haven't verified this change with {label} through a channel other than the app, \
                 this could be a substitution attempt. Replace anyway?"
            )
        } else {
            format!(
                "\"{label}\" a déjà une clé enregistrée, différente de celle-ci.\n\n\
                 Ancienne empreinte : {old_fingerprint}\n\
                 Nouvelle empreinte : {new_fingerprint}\n\n\
                 Si vous n'avez pas vérifié ce changement avec {label} par un autre moyen que l'app, \
                 ceci pourrait être une tentative de substitution. Remplacer quand même ?"
            )
        };
        let confirmed = app
            .dialog()
            .message(message)
            .title(lang("Clé du destinataire modifiée", "Recipient key changed"))
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show();
        if !confirmed {
            return Err(translate_error("Ajout annulé (clé différente refusée)."));
        }
    }

    messaging::add_recipient(&dir, &label, &pubkey_armored).t_err()
}

#[tauri::command]
fn remove_recipient(label: String, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    messaging::remove_recipient(&dir, &label).t_err()
}

#[tauri::command]
fn encrypt_message(pubkeys_armored: Vec<String>, message: String) -> Result<String, String> {
    messaging::encrypt_message(&pubkeys_armored, &message).t_err()
}

/// Déchiffre un message reçu par cet appareil (nécessite le mot de passe pour
/// déverrouiller la clé privée locale, comme pour un envoi de fonds).
#[tauri::command]
fn decrypt_message(password: String, ciphertext: String, app: tauri::AppHandle) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::decrypt_incoming_message(&dir, &password, &ciphertext).t_err()
}

// --- Wallets externes --------------------------------------------------------
// Suivi en lecture seule d'adresses qui n'appartiennent pas à ce portefeuille
// (voir core/src/external_wallets.rs) : aucun secret impliqué, le solde de
// chacune passe par la commande `get_balance` déjà existante, exactement comme
// pour les propres profils du wallet.

#[tauri::command]
fn list_external_wallets(app: tauri::AppHandle) -> Result<Vec<external_wallets::ExternalWallet>, String> {
    let dir = data_dir(&app)?;
    Ok(external_wallets::list_wallets(&dir))
}

#[tauri::command]
fn list_external_wallet_groups(app: tauri::AppHandle) -> Result<Vec<external_wallets::ExternalWalletGroup>, String> {
    let dir = data_dir(&app)?;
    Ok(external_wallets::list_groups(&dir))
}

#[tauri::command]
fn add_external_wallet(
    label: String,
    network: String,
    address: String,
    group_id: Option<u32>,
    app: tauri::AppHandle,
) -> Result<external_wallets::ExternalWallet, String> {
    let dir = data_dir(&app)?;
    external_wallets::add_wallet(&dir, &label, &network, &address, group_id).t_err()
}

#[tauri::command]
fn remove_external_wallet(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::remove_wallet(&dir, id).t_err()
}

#[tauri::command]
fn set_external_wallet_group(id: u32, group_id: Option<u32>, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::set_wallet_group(&dir, id, group_id).t_err()
}

#[tauri::command]
fn create_external_wallet_group(name: String, app: tauri::AppHandle) -> Result<external_wallets::ExternalWalletGroup, String> {
    let dir = data_dir(&app)?;
    external_wallets::create_group(&dir, &name).t_err()
}

#[tauri::command]
fn rename_external_wallet_group(id: u32, name: String, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::rename_group(&dir, id, &name).t_err()
}

#[tauri::command]
fn delete_external_wallet_group(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::delete_group(&dir, id).t_err()
}

// --- Carnet d'adresses -------------------------------------------------------
// Associer un label à une adresse pour la retrouver au moment d'envoyer des
// fonds (voir core/src/address_book.rs) — distinct des wallets externes
// (aucun solde interrogé ici, jamais).

#[tauri::command]
fn list_address_book(app: tauri::AppHandle) -> Result<Vec<address_book::AddressBookEntry>, String> {
    let dir = data_dir(&app)?;
    Ok(address_book::list_entries(&dir))
}

#[tauri::command]
fn add_address_book_entry(
    label: String,
    network: String,
    address: String,
    app: tauri::AppHandle,
) -> Result<address_book::AddressBookEntry, String> {
    let dir = data_dir(&app)?;
    address_book::add_entry(&dir, &label, &network, &address).t_err()
}

#[tauri::command]
fn remove_address_book_entry(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    address_book::remove_entry(&dir, id).t_err()
}

/// `true` uniquement pour les pages de l'app elle-même : `tauri://localhost`
/// (macOS/Linux) ou `http(s)://tauri.localhost` (Windows/WebView2). Trouvé lors
/// de l'audit "failles connues des hot wallets" : rien n'empêchait la fenêtre
/// de l'app de naviguer vers un site externe (lien injecté via un message
/// d'erreur d'un serveur tiers, par exemple) — ce site se serait alors affiché
/// DANS la fenêtre du wallet, sans barre d'adresse, libre d'imiter l'app pour
/// demander le mot de passe. Les liens externes légitimes passent déjà par
/// `open_external_link` (navigateur système + liste blanche de domaines).
///
/// `dev_url` : serveur de développement de `tauri dev` (`http://127.0.0.1:1430/`
/// ici), à ne passer QU'EN MODE DÉVELOPPEMENT (voir `run`) — seule son origine
/// EXACTE (schéma, hôte, port) est alors autorisée. Oubli du 21ᵉ passage,
/// signalé par l'utilisateur : le garde n'avait été vérifié que sur un build
/// de production (`http://tauri.localhost/`) ; en `tauri dev`, il bloquait la
/// page de l'app elle-même au chargement — fenêtre vide.
fn is_app_origin(url: &tauri::Url, dev_url: Option<&tauri::Url>) -> bool {
    if dev_url.is_some_and(|dev| url.origin() == dev.origin()) {
        return true;
    }
    match url.scheme() {
        "tauri" => true,
        "http" | "https" => url.host_str() == Some("tauri.localhost"),
        "about" => url.path() == "blank",
        _ => false,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("navigation-guard")
                .on_navigation(|webview, url| {
                    // `tauri::is_dev()` est faux dans tout build produit par
                    // `tauri build` (fonctionnalité `custom-protocol`) : le
                    // serveur de développement n'y est jamais autorisé.
                    let dev_url = if tauri::is_dev() { webview.config().build.dev_url.clone() } else { None };
                    let allowed = is_app_origin(url, dev_url.as_ref());
                    if !allowed {
                        eprintln!("navigation bloquée hors de l'app : {url}");
                    }
                    allowed
                })
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                install_panic_hook(dir);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            set_ui_language,
            save_bytes_with_dialog,
            open_external_link,
            generate_qr_svg,
            wallet_exists,
            reset_wallet,
            create_wallet,
            regenerate_backup_kit,
            get_thor_fee_address,
            unlock_wallet,
            biometric_unlock_available,
            biometric_unlock_enrolled,
            enroll_biometric_unlock,
            unlock_wallet_biometric,
            disable_biometric_unlock,
            create_profile,
            delete_profile,
            archive_profile,
            unarchive_profile,
            list_archived_profiles,
            restore_wallet,
            get_balance,
            get_usdc_balance,
            has_pending_tx,
            get_tx_history,
            get_usdc_tx_history,
            estimate_btc_fees,
            get_crypto_prices,
            get_market_prices,
            send_transaction,
            send_usdc_transaction,
            get_swap_quote,
            swap_transaction,
            get_jupiter_quote,
            jupiter_swap_transaction,
            get_own_certificate,
            list_recipients,
            add_recipient,
            remove_recipient,
            encrypt_message,
            decrypt_message,
            list_external_wallets,
            list_external_wallet_groups,
            add_external_wallet,
            remove_external_wallet,
            set_external_wallet_group,
            create_external_wallet_group,
            rename_external_wallet_group,
            delete_external_wallet_group,
            list_address_book,
            add_address_book_entry,
            remove_address_book_entry,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> tauri::Url {
        tauri::Url::parse(s).expect("URL de test valide")
    }

    /// 22ᵉ passage : reproduit l'attaque vérifiée en réel sur la boîte native
    /// (libellé de profil contenant de faux "Destinataire/Montant" suivis de
    /// dizaines de retours à la ligne) — le texte final ne doit contenir
    /// qu'UNE ligne "Destinataire", la vraie, et garder un nombre de lignes fixe.
    #[test]
    fn dialog_text_cannot_be_spoofed_by_untrusted_strings() {
        let injected_label = format!(
            "Principal\nDestinataire : bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz\nMontant : 0.001\u{2028}Frais : 1200 sat{}",
            "\n".repeat(80)
        );
        let real_to = canonical_address_input(&format!("{}bc1qattacker", "\n".repeat(80))).unwrap();
        let text = transaction_confirmation_text("btc_mainnet", &real_to, "2.5", &injected_label, Some("Frais : 1200 sat"), None);
        // Le mot peut subsister DANS le libellé (aplati sur la ligne "Depuis le
        // profil", tronqué avant toute adresse complète) : ce qui compte est
        // qu'aucune AUTRE ligne ne se présente comme destinataire ou montant.
        assert_eq!(text.lines().filter(|l| l.starts_with("Destinataire")).count(), 1, "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("Montant")).count(), 1, "{text}");
        assert!(text.contains("Destinataire : bc1qattacker\nMontant : 2.5\n"), "{text}");
        let clean = transaction_confirmation_text("btc_mainnet", "bc1qx", "1", "Principal", Some("Frais : 1 sat"), None);
        assert_eq!(text.lines().count(), clean.lines().count(), "le libellé ne doit ajouter aucune ligne");

        // Chaque caractère dangereux, isolément.
        for hazard in ['\n', '\r', '\t', '\u{0085}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{200B}', '\u{FEFF}', '\u{00AD}'] {
            assert!(!dialog_label(&format!("a{hazard}b")).contains(hazard), "{:?}", hazard);
            assert!(canonical_address_input(&format!("bc1q{hazard}abc")).is_err(), "{:?}", hazard);
        }
        assert_eq!(dialog_label("  Épargne   perso "), "Épargne perso");
        assert_eq!(dialog_label(&"x".repeat(100)).chars().count(), 41, "tronqué à 40 + « … »");
        assert_eq!(canonical_address_input("  0xabc\n").unwrap(), "0xabc");
        assert!(canonical_address_input("bc1q abc").is_err());
        assert!(canonical_address_input("  ").is_err());
    }

    #[test]
    fn recipient_warnings_cover_new_unused_empty_and_unknown_addresses() {
        use api::RecipientActivity::*;
        // Adresse jamais payée ET jamais utilisée on-chain : les deux avertissements.
        let lines = recipient_warning_lines(true, "evm", Some(Unused));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("NOUVELLE ADRESSE"), "{lines:?}");
        assert!(lines[1].contains("JAMAIS servi") && lines[1].contains("aucun ETH"), "{lines:?}");

        // Destinataire habituel qui détient des fonds : rien à signaler.
        assert!(recipient_warning_lines(false, "btc", Some(Funded)).is_empty());

        // Vide : l'actif absent est nommé (un portefeuille sans SOL peut détenir de l'USDC).
        let lines = recipient_warning_lines(false, "usdc", Some(Empty));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("VIDE") && lines[0].contains("ni SOL ni USDC"), "{lines:?}");
        assert!(recipient_warning_lines(false, "sol", Some(Empty))[0].contains("aucun SOL"));

        // Lecture réseau en échec : dit explicitement, jamais un silence rassurant.
        let lines = recipient_warning_lines(false, "sol", None);
        assert!(lines.len() == 1 && lines[0].contains("impossible à vérifier"), "{lines:?}");

        // Chaque avertissement tient sur un seul paragraphe (mise en page de la boîte).
        for coin in ["evm", "btc", "sol", "usdc"] {
            for activity in [Some(Unused), Some(Empty), None] {
                assert!(recipient_warning_lines(true, coin, activity).iter().all(|l| !l.contains('\n')));
            }
        }
    }

    #[test]
    fn navigation_guard_allows_only_the_app_itself() {
        assert!(is_app_origin(&url("tauri://localhost/index.html"), None));
        assert!(is_app_origin(&url("http://tauri.localhost/index.html"), None));
        assert!(is_app_origin(&url("https://tauri.localhost/"), None));
        assert!(is_app_origin(&url("about:blank"), None));

        assert!(!is_app_origin(&url("https://evil.example/fake-wallet"), None));
        // Sosies du nom d'hôte de l'app : le contrôle doit porter sur l'hôte EXACT.
        assert!(!is_app_origin(&url("https://tauri.localhost.evil.example/"), None));
        assert!(!is_app_origin(&url("https://eviltauri.localhost/"), None));
        assert!(!is_app_origin(&url("https://tauri.localhost@evil.example/"), None));
        assert!(!is_app_origin(&url("file:///C:/Windows/System32/"), None));
        assert!(!is_app_origin(&url("javascript:alert(1)"), None));
    }

    /// Régression du 21ᵉ passage signalée par l'utilisateur : en `tauri dev`,
    /// la page de l'app (servie par le serveur de développement) était
    /// bloquée. Autorisée désormais — mais seulement l'origine EXACTE du
    /// serveur, et jamais hors mode développement (`dev_url` = `None`).
    #[test]
    fn navigation_guard_allows_the_dev_server_only_in_dev_mode() {
        let dev = url("http://127.0.0.1:1430/");
        assert!(is_app_origin(&url("http://127.0.0.1:1430/"), Some(&dev)));
        assert!(is_app_origin(&url("http://127.0.0.1:1430/index.html"), Some(&dev)));

        assert!(!is_app_origin(&url("http://127.0.0.1:1430/"), None), "build de production : jamais");
        assert!(!is_app_origin(&url("http://127.0.0.1:1431/"), Some(&dev)), "autre port");
        assert!(!is_app_origin(&url("https://127.0.0.1:1430/"), Some(&dev)), "autre schéma");
        assert!(!is_app_origin(&url("http://localhost:1430/"), Some(&dev)), "autre hôte");
        assert!(!is_app_origin(&url("https://evil.example/"), Some(&dev)));
    }
}
