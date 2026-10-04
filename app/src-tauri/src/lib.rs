//! Commandes Tauri : la seule porte d'entrée entre le frontend web (non fiable,
//! ne doit jamais voir de secret) et le worker crypto (`pgp_wallet_poc::api`).
//! Aucune donnée sensible (entropie, clé privée, passphrase) ne doit jamais être
//! journalisée ici ni renvoyée au frontend — seules des adresses publiques et des
//! confirmations/erreurs le sont.

use base64::Engine;
use pgp_wallet_poc::{address_book, api, cow, dapp_requests, external_wallets, hardware, history, messaging, price_history, price_rpc, sent_recipients, wallet_flow};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tauri::{Emitter, Manager};
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

/// Le profil principal déverrouillé est-il le portefeuille du développeur
/// (adresse THOR = adresse d'affiliation de l'app) ? Seul lui voit et peut
/// utiliser l'inscription du nom d'affiliation.
static IS_AFFILIATE_WALLET: AtomicBool = AtomicBool::new(false);

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
    // Solana (core/src/sol_rpc.rs)
    (
        pgp_wallet_poc::sol_rpc::BLOCKHASH_EXPIRED_ERROR,
        "the transaction expired before being sent (Solana validity window exceeded) — nothing was sent or debited, try again",
    ),
    // Réseaux EVM (core/src/api.rs, history.rs)
    ("adresse d'envoi inconnue : déverrouillez le portefeuille", "sending address unknown: unlock the wallet"),
    ("historique pas encore disponible sur ce réseau", "history not available on this network yet"),
    ("historique des jetons pas encore disponible sur ce réseau", "token history not available on this network yet"),
    ("jeton non pris en charge sur ce réseau", "token not supported on this network"),
    ("destinataire refusé : c'est le contrat d'un jeton, les fonds y seraient perdus à jamais", "recipient refused: it is a token contract, the funds would be lost forever"),
    ("solde de jeton insuffisant, ou transfert refusé par le contrat du jeton", "insufficient token balance, or transfer refused by the token contract"),
    ("réponse du contrat de jeton inattendue", "unexpected answer from the token contract"),
    ("solde de jeton hors limites", "token balance out of range"),
    ("limite de gas trop basse pour ce transfert", "gas limit too low for this transfer"),
    ("le montant doit être supérieur à zéro", "the amount must be greater than zero"),
    ("montant invalide", "invalid amount"),
    ("montant trop grand", "amount too large"),
    ("mint invalide", "invalid mint"),
    ("fonds insuffisants pour ce montant et les frais du réseau", "insufficient funds for this amount and the network fee"),
    ("limite de gas trop basse pour un virement", "gas limit too low for a transfer"),
    ("réponse de l'oracle de frais inattendue", "unexpected answer from the fee oracle"),
    ("frais de publication annoncés anormalement élevés", "abnormally high posting fee announced"),
    ("frais de gas dépassant la capacité représentable", "gas fee beyond the representable range"),
    // core/src/usb_backup.rs, sauvegarde sur clé USB
    ("clé USB introuvable : branchez-la puis réessayez", "USB drive not found: plug it in and try again"),
    ("écriture sur la clé USB impossible", "cannot write to the USB drive"),
    ("relecture de la clé USB impossible", "cannot read back the USB drive"),
    ("la relecture de la clé USB ne correspond pas à ce qui a été écrit : clé défectueuse ?", "reading the USB drive back does not match what was written: faulty drive?"),
    ("la relecture de la clé USB ne correspond pas à ce qui a été écrit", "reading the USB drive back does not match what was written"),
    ("numéro de part invalide", "invalid share number"),
    ("identifiant de kit invalide", "invalid kit identifier"),
    ("cette clé USB contient déjà une part d'une autre sauvegarde (ancienne, ou d'un autre portefeuille) : utilisez une clé vide, ou supprimez vous-même son dossier PGP-Wallet-Sauvegarde si vous n'en avez plus besoin", "this USB drive already holds a share of another backup (an older one, or another wallet's): use an empty drive, or delete its PGP-Wallet-Sauvegarde folder yourself if you no longer need it"),
    ("espace insuffisant sur la clé USB", "not enough space on the USB drive"),
    ("la part écrite sur la clé USB ne se déchiffre pas : sauvegarde inutilisable", "the share written to the USB drive cannot be decrypted: backup unusable"),
    ("aucune sauvegarde OpenPGP Wallet sur cette clé USB", "no OpenPGP Wallet backup on this USB drive"),
    ("lecture de la clé USB impossible", "cannot read the USB drive"),
    ("mot de passe de la part illisible sur la clé USB", "the share's password on the USB drive is unreadable"),
    ("part de sauvegarde vide", "empty backup share"),
    ("branchez deux clés USB portant deux parts différentes d'une même sauvegarde", "plug in two USB drives holding two different shares of the same backup"),
    // core/src/sol_rpc.rs
    (
        "le nœud Solana public limite le nombre de requêtes : réessayez dans un instant",
        "the public Solana node is limiting requests: try again in a moment",
    ),
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
    // CoW Protocol (core/src/cow.rs, core/src/api.rs)
    ("échange via CoW pas encore activé", "swaps via CoW are not enabled yet"),
    // Zcash (core/src/zcash.rs, core/src/api.rs)
    ("adresse Zcash invalide", "invalid Zcash address"),
    (
        "envoi vers une adresse Zcash protégée (zs…, u1…) pas encore pris en charge — utilisez une adresse transparente t1…",
        "sending to a shielded Zcash address (zs…, u1…) is not supported yet — use a transparent t1… address",
    ),
    ("adresse Zcash d'un autre réseau (test) — refusée", "Zcash address from another network (test) — refused"),
    ("envoi vers votre propre adresse Zcash", "sending to your own Zcash address"),
    ("aucun serveur Zcash joignable", "no Zcash server reachable"),
    // Délai d'annulation et bouton « Max »
    ("Virement annulé pendant le délai d'annulation.", "Transfer cancelled during the cancellation delay."),
    ("Échange annulé pendant le délai d'annulation.", "Swap cancelled during the cancellation delay."),
    ("ZEC insuffisants pour couvrir les frais du réseau", "not enough ZEC to cover the network fee"),
    ("ZEC protégés insuffisants pour couvrir les frais du réseau", "not enough shielded ZEC to cover the network fee"),
    ("DOGE insuffisants pour couvrir les frais du réseau", "not enough DOGE to cover the network fee"),
    ("SOL insuffisants pour couvrir les frais du réseau", "not enough SOL to cover the network fee"),
    ("BTC insuffisants pour couvrir les frais choisis", "not enough BTC to cover the chosen fee"),
    ("aucun jeton à envoyer", "no tokens to send"),
    // Dogecoin (core/src/doge.rs, core/src/api.rs)
    ("service Dogecoin injoignable", "Dogecoin service unreachable"),
    ("réponse du service Dogecoin illisible", "unreadable Dogecoin service response"),
    ("adresse Dogecoin invalide", "invalid Dogecoin address"),
    ("adresse Dogecoin invalide (somme de contrôle)", "invalid Dogecoin address (checksum)"),
    ("adresse Dogecoin invalide (autre réseau ou autre crypto)", "invalid Dogecoin address (another network or another crypto)"),
    ("adresse Dogecoin du profil invalide", "invalid Dogecoin address for this profile"),
    ("envoi vers votre propre adresse Dogecoin", "sending to your own Dogecoin address"),
    ("montant trop petit : 0,01 DOGE au moins", "amount too small: at least 0.01 DOGE"),
    ("transaction Dogecoin tronquée", "truncated Dogecoin transaction"),
    ("transaction Dogecoin invalide", "invalid Dogecoin transaction"),
    ("transaction Dogecoin invalide (octets en trop)", "invalid Dogecoin transaction (trailing bytes)"),
    ("transaction Dogecoin illisible", "unreadable Dogecoin transaction"),
    ("transaction Dogecoin introuvable", "Dogecoin transaction not found"),
    ("identifiant de transaction Dogecoin invalide", "invalid Dogecoin transaction id"),
    (
        "transaction d'origine falsifiée (hash différent de son identifiant) — envoi refusé",
        "falsified source transaction (hash different from its id) — transfer refused",
    ),
    ("sortie Dogecoin introuvable dans sa transaction d'origine", "Dogecoin output not found in its source transaction"),
    ("sortie Dogecoin qui n'appartient pas à votre adresse — envoi refusé", "Dogecoin output that does not belong to your address — transfer refused"),
    ("montant d'une sortie Dogecoin annoncé faux par le service — envoi refusé", "Dogecoin output amount misreported by the service — transfer refused"),
    // LI.FI (core/src/lifi.rs, core/src/api.rs)
    (
        "limite de devis LI.FI atteinte (75 toutes les 2 heures sans compte) — réessayez plus tard",
        "LI.FI quote limit reached (75 every 2 hours without an account) — try again later",
    ),
    ("LI.FI propose maintenant un autre pont que celui affiché — relancez l'échange", "LI.FI now offers a different bridge than the one shown — start the swap again"),
    (
        "le minimum annoncé par LI.FI a baissé de plus de 1 % depuis l'affichage — relancez l'échange",
        "the minimum announced by LI.FI dropped by more than 1% since it was shown — start the swap again",
    ),
    (
        "la nouvelle transaction LI.FI ne passe plus la même vérification — relancez l'échange",
        "the new LI.FI transaction no longer passes the same check — start the swap again",
    ),
    ("la transaction LI.FI n'est pas au nom de ce profil — échange refusé", "the LI.FI transaction is not in this profile's name — swap refused"),
    ("transaction LI.FI incohérente — échange refusé", "inconsistent LI.FI transaction — swap refused"),
    ("le devis CoW a expiré — relancez l'échange", "the CoW quote expired — start the swap again"),
    ("ordre CoW incohérent — échange refusé", "inconsistent CoW order — swap refused"),
    ("l'ordre CoW n'est pas au nom de ce profil — échange refusé", "the CoW order is not in this profile's name — swap refused"),
    (
        "le devis CoW a expiré pendant l'autorisation — relancez l'échange (l'autorisation reste acquise)",
        "the CoW quote expired during the approval — start the swap again (the approval is kept)",
    ),
    ("adresse du profil inconnue — déverrouillez le portefeuille", "profile address unknown — unlock the wallet"),
    ("identifiant d'ordre CoW invalide", "invalid CoW order identifier"),
    // WalletConnect (core/src/walletconnect/, core/src/dapp_requests.rs, lib.rs)
    ("lien WalletConnect invalide : il doit commencer par « wc: »", "invalid WalletConnect link: it must start with \"wc:\""),
    ("lien WalletConnect incomplet (paramètres absents)", "incomplete WalletConnect link (missing parameters)"),
    ("lien WalletConnect incomplet (version absente)", "incomplete WalletConnect link (missing version)"),
    ("lien WalletConnect invalide (identifiant de canal)", "invalid WalletConnect link (channel identifier)"),
    ("lien WalletConnect incomplet (clé absente)", "incomplete WalletConnect link (missing key)"),
    ("lien WalletConnect invalide (clé)", "invalid WalletConnect link (key)"),
    ("lien WalletConnect : protocole de relais non pris en charge", "WalletConnect link: unsupported relay protocol"),
    ("ce lien WalletConnect a expiré : demandez-en un nouveau à la dApp", "this WalletConnect link has expired: ask the dApp for a new one"),
    ("ce lien WalletConnect a déjà été utilisé : demandez-en un nouveau à la dApp", "this WalletConnect link was already used: ask the dApp for a new one"),
    (
        "WalletConnect n'est pas encore configuré : le Project ID (dashboard.reown.com) n'a pas été renseigné",
        "WalletConnect is not configured yet: the Project ID (dashboard.reown.com) has not been set",
    ),
    ("proposition de connexion introuvable ou expirée", "connection proposal not found or expired"),
    ("demande introuvable ou expirée", "request not found or expired"),
    ("la demande a changé depuis son affichage — refusée", "the request changed since it was displayed — refused"),
    ("connexion introuvable", "connection not found"),
    ("WalletConnect indisponible (démarrage impossible)", "WalletConnect unavailable (failed to start)"),
    (
        "adresses du profil inconnues : déverrouillez le portefeuille avec le mot de passe",
        "profile addresses unknown: unlock the wallet with the password",
    ),
    (
        "la dApp demande la signature d'un AUTRE compte que celui connecté — refusé",
        "the dApp asks for a signature from ANOTHER account than the connected one — refused",
    ),
    (
        "la dApp demande l'envoi depuis un AUTRE compte que celui connecté — refusé",
        "the dApp asks to send from ANOTHER account than the connected one — refused",
    ),
    ("création de contrat (pas de destinataire) non prise en charge — refusé", "contract creation (no recipient) not supported — refused"),
    ("ce « message » est en réalité une TRANSACTION Solana déguisée — refusé", "this \"message\" is actually a disguised Solana TRANSACTION — refused"),
    ("transaction à plusieurs signataires : non prise en charge — refusée", "multi-signer transaction: not supported — refused"),
    ("la transaction n'est pas payée par le compte connecté — refusée", "the transaction is not paid by the connected account — refused"),
    ("le compte de la session ne correspond pas au profil — signature refusée", "the session account does not match the profile — signature refused"),
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
    (
        "adresse Bitcoin mal formée (version SegWit, encodage ou longueur incohérents)",
        "malformed Bitcoin address (inconsistent SegWit version, encoding or length)",
    ),
    // Échanges depuis Bitcoin (LI.FI, core/src/lifi.rs) et Zcash (Maya, core/src/api.rs)
    ("dépôt LI.FI vers votre propre adresse — refusé", "LI.FI deposit to your own address — refused"),
    ("transaction Bitcoin LI.FI d'une version inattendue", "LI.FI Bitcoin transaction with an unexpected version"),
    ("transaction Bitcoin LI.FI avec un verrou temporel — refusé", "LI.FI Bitcoin transaction with a time lock — refused"),
    ("transaction Bitcoin LI.FI qui dépense deux fois la même sortie — refusé", "LI.FI Bitcoin transaction spending the same output twice — refused"),
    (
        "la transaction LI.FI dépense une sortie absente (ou pas encore confirmée) de votre adresse Bitcoin — refusé",
        "the LI.FI transaction spends an output that is missing (or not yet confirmed) on your Bitcoin address — refused",
    ),
    ("memo OP_RETURN inattendu dans la transaction LI.FI — refusé", "unexpected OP_RETURN memo in the LI.FI transaction — refused"),
    (
        "la transaction LI.FI ne paie pas exactement une fois l'adresse de dépôt annoncée — refusé",
        "the LI.FI transaction does not pay the announced deposit address exactly once — refused",
    ),
    ("transaction LI.FI avec des sorties inattendues — refusé", "LI.FI transaction with unexpected outputs — refused"),
    ("la transaction LI.FI envoie plus que le montant affiché — refusé", "the LI.FI transaction sends more than the amount shown — refused"),
    (
        "la transaction LI.FI dépose moins que le montant affiché, frais annoncés déduits — refusé",
        "the LI.FI transaction deposits less than the amount shown, announced fees deducted — refused",
    ),
    ("la transaction LI.FI dépense plus que ses entrées — refusé", "the LI.FI transaction spends more than its inputs — refused"),
    ("transaction LI.FI avec un autre montant que celui demandé", "LI.FI transaction for another amount than the one requested"),
    ("adresse de dépôt LI.FI invalide", "invalid LI.FI deposit address"),
    ("PSBT LI.FI illisible", "unreadable LI.FI PSBT"),
    (
        "l'adresse de dépôt du pont a changé pendant la confirmation — relancez l'échange",
        "the bridge's deposit address changed during the confirmation — start the swap again",
    ),
    (
        "les frais réseau Bitcoin de la transaction LI.FI ont augmenté depuis la confirmation — relancez l'échange",
        "the Bitcoin network fee of the LI.FI transaction increased since the confirmation — start the swap again",
    ),
    ("adresse de dépôt Maya égale à votre propre adresse — échange refusé", "Maya deposit address equal to your own address — swap refused"),
    ("adresse de dépôt Maya invalide", "invalid Maya deposit address"),
    // Nom d'affiliation (core/src/api.rs, core/src/native_deposit.rs)
    (
        "ce portefeuille n'est pas celui qui reçoit les frais d'affiliation de l'app — inscription réservée à ce dernier",
        "this wallet is not the one receiving the app's affiliate fees — registration is reserved for it",
    ),
    ("le coût du nom a changé depuis la confirmation — relancez l'inscription", "the name's cost changed since the confirmation — start the registration again"),
    ("adresse d'affiliation jamais approvisionnée sur ce réseau", "affiliate address never funded on this network"),
    ("Inscription annulée (confirmation refusée).", "Registration cancelled (confirmation declined)."),
    ("aucun nom d'affiliation prévu sur ce réseau", "no affiliate name planned on this network"),
    // Zcash protégé (core/src/zcash_shielded.rs)
    ("Protection annulée (confirmation refusée).", "Shielding cancelled (confirmation declined)."),
    ("fonds protégés pas encore prêts (synchronisation en cours)", "shielded funds not ready yet (sync in progress)"),
    ("adresse Zcash Sapling seule (zs…) pas prise en charge — demandez une adresse u1… ou t1…", "Sapling-only Zcash address (zs…) not supported — ask for a u1… or t1… address"),
    ("adresse Zcash protégée invalide (u1… attendue)", "invalid shielded Zcash address (u1… expected)"),
    ("adresse Zcash protégée inconnue de ce portefeuille", "shielded Zcash address unknown to this wallet"),
    ("compte Zcash protégé introuvable", "shielded Zcash account not found"),
    ("identifiant de transaction Zcash invalide", "invalid Zcash transaction id"),
    ("base Zcash protégée illisible", "unreadable shielded Zcash database"),
    // Monero (core/src/monero.rs)
    ("envoi vers votre propre adresse Monero", "transfer to your own Monero address"),
    ("Monero : synchronisation en cours, réessayez dans un instant", "Monero: sync in progress, try again in a moment"),
    ("Monero : synchronisation pas encore faite, réessayez dans un instant", "Monero: not synced yet, try again in a moment"),
    ("Monero : synchronisation pas encore lancée", "Monero: sync not started yet"),
    ("adresse Monero d'un réseau de test (stagenet/testnet) : refusée", "Monero address from a test network (stagenet/testnet): refused"),
    ("adresse Monero invalide", "invalid Monero address"),
    ("adresse Monero inconnue de ce portefeuille", "Monero address unknown to this wallet"),
    ("format d'adresse Monero non standard : refusé", "non-standard Monero address format: refused"),
    ("adresse de nœud invalide : https://hôte:port attendu", "invalid node address: https://host:port expected"),
    ("adresse de nœud invalide : https://hôte:port attendu, sans chemin", "invalid node address: https://host:port expected, without a path"),
    ("adresse de nœud invalide : hôte manquant", "invalid node address: missing host"),
    ("nœud distant : https:// obligatoire (http:// seulement pour un nœud local)", "remote node: https:// required (http:// only for a local node)"),
    ("enregistrement du nœud Monero impossible", "could not save the Monero node"),
    ("réanalyse Zcash protégée : demande impossible", "shielded Zcash rescan: request failed"),
    ("suppression du nœud Monero impossible", "could not remove the Monero node"),
    ("état Monero illisible", "unreadable Monero state"),
    ("enregistrement de l'état Monero impossible", "could not save the Monero state"),
    ("sortie Monero illisible", "unreadable Monero output"),
    ("frais Monero incohérents", "inconsistent Monero fee"),
    ("clé publique Monero invalide", "invalid Monero public key"),
    ("clé de visualisation Monero invalide", "invalid Monero view key"),
    ("démarrage du client Monero impossible", "could not start the Monero client"),
    ("envoi Monero non préparé", "Monero transfer not prepared"),
    // Clé Etherscan (core/src/etherscan_key.rs, core/src/routescan.rs)
    (
        "clé Etherscan invalide : 34 lettres majuscules et chiffres attendus (à copier depuis etherscan.io/myapikey)",
        "invalid Etherscan key: 34 uppercase letters and digits expected (copy it from etherscan.io/myapikey)",
    ),
    (pgp_wallet_poc::routescan::ETHERSCAN_KEY_MISSING, "history of this network: add your free Etherscan key in Settings"),
    (pgp_wallet_poc::routescan::ETHERSCAN_KEY_REFUSED, "Etherscan refuses the saved key (invalid or revoked) — check it in Settings"),
    (
        pgp_wallet_poc::lifi::NO_CONFIRMED_BTC,
        "no confirmed BTC on your address: LI.FI builds the deposit from funds received and confirmed (at least one confirmation)",
    ),
    ("enregistrement de la clé Etherscan impossible", "could not save the Etherscan key"),
    ("suppression de la clé Etherscan impossible", "could not remove the Etherscan key"),
    ("clé Etherscan illisible", "unreadable Etherscan key"),
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
    // core/src/hardware.rs, core/src/ledger/, core/src/trezor/
    ("compte matériel introuvable", "hardware wallet account not found"),
    ("ce compte est déjà ajouté", "this account has already been added"),
    ("nom du compte invalide (1 à 60 caractères)", "invalid account name (1 to 60 characters)"),
    ("nombre maximal de comptes matériels atteint", "maximum number of hardware wallet accounts reached"),
    ("l'adresse affichée par l'appareil diffère de celle enregistrée", "the address shown by the device differs from the saved one"),
    ("compte Bitcoin matériel incomplet", "incomplete hardware Bitcoin account"),
    ("aucun Trezor détecté : branchez-le et déverrouillez-le", "no Trezor detected: plug it in and unlock it"),
    (
        "ouverture du Trezor impossible (déjà utilisé par Trezor Suite ou une autre application ?)",
        "cannot open the Trezor (already used by Trezor Suite or another application?)",
    ),
    (
        "Trezor déjà utilisé par une autre application : fermez Trezor Suite puis réessayez",
        "Trezor already used by another application: close Trezor Suite and try again",
    ),
    (
        "Trezor Model One détecté : ce modèle n'est pas pris en charge (saisie du PIN depuis l'ordinateur)",
        "Trezor Model One detected: this model is not supported (PIN entered from the computer)",
    ),
    (
        "ce Trezor demande la saisie du PIN depuis l'ordinateur (Model One) : non pris en charge",
        "this Trezor asks for the PIN to be entered from the computer (Model One): not supported",
    ),
    ("opération refusée sur le Trezor", "operation refused on the Trezor"),
    ("saisie du PIN annulée sur le Trezor", "PIN entry cancelled on the Trezor"),
    ("PIN incorrect sur le Trezor", "wrong PIN on the Trezor"),
    ("Trezor non initialisé : configurez-le d'abord avec Trezor Suite", "Trezor not initialized: set it up with Trezor Suite first"),
    ("accès USB impossible", "USB access unavailable"),
    ("écriture USB vers le Trezor impossible", "USB write to the Trezor failed"),
    (
        "la signature du Trezor ne correspond pas à la transaction attendue — transaction non diffusée",
        "the Trezor signature does not match the expected transaction — transaction not broadcast",
    ),
    (
        "la signature du Trezor ne correspond pas au compte attendu — transaction non diffusée",
        "the Trezor signature does not match the expected account — transaction not broadcast",
    ),
    ("le Trezor n'a pas signé toutes les entrées", "the Trezor did not sign every input"),
    ("l'adresse calculée par le Trezor ne correspond pas à celle du compte", "the address computed by the Trezor does not match the account's"),
    (
        "aucun Ledger détecté : branchez-le, déverrouillez-le et ouvrez l'application du réseau",
        "no Ledger detected: plug it in, unlock it and open the network's app",
    ),
    ("ouverture du Ledger impossible (déjà utilisé par une autre application ?)", "cannot open the Ledger (already used by another application?)"),
    ("accès USB (HID) impossible", "USB (HID) access unavailable"),
    ("écriture USB vers le Ledger impossible", "USB write to the Ledger failed"),
    ("lecture USB depuis le Ledger impossible", "USB read from the Ledger failed"),
    (
        "la signature du Ledger ne correspond pas à la transaction attendue — transaction non diffusée",
        "the Ledger signature does not match the expected transaction — transaction not broadcast",
    ),
    (
        "la signature du Ledger ne correspond pas au compte attendu — transaction non diffusée",
        "the Ledger signature does not match the expected account — transaction not broadcast",
    ),
    ("le Ledger n'a pas signé toutes les entrées", "the Ledger did not sign every input"),
    ("l'adresse calculée par le Ledger ne correspond pas à celle du compte", "the address computed by the Ledger does not match the account's"),
    ("le Ledger a renvoyé une adresse qui ne correspond pas à sa clé publique", "the Ledger returned an address that does not match its public key"),
];

/// Messages Ledger suivis d'une valeur (mot d'état, nom d'application...) :
/// préfixe français -> préfixe anglais, la suite étant conservée.
const LEDGER_PREFIX_TRANSLATIONS: &[(&str, &str)] = &[
    ("opération refusée sur le Ledger", "operation refused on the Ledger"),
    ("Ledger verrouillé : saisissez votre code PIN sur l'appareil", "Ledger locked: enter your PIN on the device"),
    (
        "application non ouverte sur le Ledger : ouvrez l'application du réseau concerné",
        "app not open on the Ledger: open the app of the network concerned",
    ),
    (
        "données refusées par le Ledger (option « signature à l'aveugle » désactivée, ou transaction non prise en charge)",
        "data refused by the Ledger (\"Blind signing\" option disabled, or unsupported transaction)",
    ),
    (
        "le Ledger exige l'option « signature à l'aveugle » (Blind signing) dans l'application Solana pour cette transaction",
        "the Ledger requires the \"Blind signing\" option in the Solana app for this transaction",
    ),
    (
        "transaction refusée par l'application Bitcoin du Ledger : données incohérentes",
        "transaction refused by the Ledger Bitcoin app: inconsistent data",
    ),
    ("le Ledger n'est pas sur le bon réseau : ouvrez l'application", "the Ledger is not on the right network: open the app"),
    ("Ledger : mémoire insuffisante pour cette opération", "Ledger: not enough memory for this operation"),
    ("Ledger : paramètre de commande refusé (version d'application trop ancienne ?)", "Ledger: command parameter refused (app version too old?)"),
    ("le Ledger a renvoyé l'erreur", "the Ledger returned error"),
    ("données refusées par le Trezor : ", "data refused by the Trezor: "),
    ("le Trezor a renvoyé une erreur : ", "the Trezor returned an error: "),
    ("lecture USB depuis le Trezor impossible : ", "USB read from the Trezor failed: "),
];

/// Messages avec une valeur interpolée (index, méthode RPC, montant...) : la
/// correspondance exacte ne peut pas fonctionner, donc reconstruction par
/// découpage autour de la partie fixe du message.
fn translate_dynamic_error(msg: &str) -> Option<String> {
    if let Some(n) = msg.strip_prefix("trop de décimales (").and_then(|rest| rest.strip_suffix(" au plus pour ce jeton)")) {
        return Some(format!("too many decimals (at most {n} for this token)"));
    }
    if let Some(rest) = msg.strip_prefix("gas estimé anormalement élevé (").and_then(|rest| rest.strip_suffix(") — envoi refusé")) {
        return Some(format!("abnormally high estimated gas ({rest}) — transfer refused"));
    }
    if let Some(part) = msg
        .strip_prefix("cette clé USB contient déjà la part n°")
        .and_then(|rest| rest.strip_suffix(" de ce kit : deux parts sur une même clé suffiraient à tout récupérer — utilisez une autre clé"))
    {
        return Some(format!("this USB drive already holds share {part} of this kit: two shares on one drive would be enough to recover everything — use another drive"));
    }
    if let Some(name) = msg.strip_prefix("sauvegarde incomplète sur la clé USB (").and_then(|rest| rest.strip_suffix(" absent)")) {
        return Some(format!("incomplete backup on the USB drive ({name} missing)"));
    }
    if let Some(name) = msg.strip_prefix("fichier de sauvegarde anormalement gros sur la clé USB (").and_then(|rest| rest.strip_suffix(')')) {
        return Some(format!("abnormally large backup file on the USB drive ({name})"));
    }
    if let Some((en, rest)) = LEDGER_PREFIX_TRANSLATIONS.iter().find_map(|(fr, en)| msg.strip_prefix(fr).map(|rest| (en, rest))) {
        return Some(format!("{en}{rest}"));
    }
    for device in ["Ledger", "Trezor"] {
        if let Some(label) = msg
            .strip_prefix(&format!("ce {device} ne correspond pas au compte « "))
            .and_then(|rest| rest.strip_suffix(" » (autre appareil ou autre phrase de récupération)"))
        {
            return Some(format!("this {device} does not match the account \"{label}\" (another device or another recovery phrase)"));
        }
    }
    if let Some(label) = msg.strip_prefix("le compte « ").and_then(|rest| rest.strip_suffix(" » n'est pas sur ce réseau")) {
        return Some(format!("the account \"{label}\" is not on this network"));
    }
    if let Some(rest) = msg.strip_prefix("ZEC insuffisants : ") {
        return Some(format!("insufficient ZEC: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("DOGE insuffisants : ") {
        return Some(format!(
            "insufficient DOGE: {}",
            rest.replace(" demandés, ", " requested, ").replace(" envoyables au plus (frais déduits)", " sendable at most (fees deducted)")
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction Dogecoin refusée : ") {
        return Some(format!("Dogecoin transaction refused: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("service Dogecoin : réponse ") {
        return Some(format!("Dogecoin service: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("signature Dogecoin impossible (") {
        return Some(format!("Dogecoin signature failed ({rest}"));
    }
    if let Some((name, rest)) = msg.split_once(" a suspendu les échanges") {
        if let Some(place) = rest.strip_suffix(" pour le moment (incident ou maintenance de son côté) — réessayez plus tard ou choisissez un autre fournisseur") {
            let place = place.strip_prefix(" sur ").map(|p| format!(" on {}", p.replace(" et ", " and "))).unwrap_or_default();
            return Some(format!("{name} has paused swaps{place} for now (incident or maintenance on their side) — try again later or choose another provider"));
        }
    }
    if let Some(reserve) = msg.strip_prefix("solde SOL trop juste : il doit rester au moins ").and_then(|rest| {
        rest.strip_suffix(" SOL sur votre compte après l'opération (réserve minimale imposée par Solana) — réduisez le montant de SOL envoyé d'autant, ou ajoutez du SOL")
    }) {
        return Some(format!(
            "SOL balance too tight: at least {reserve} SOL must remain in your account after the operation (minimum reserve required by Solana) — reduce the amount of SOL sent by that much, or add SOL"
        ));
    }
    if let Some(reserve) = msg
        .strip_prefix("un autre compte touché par l'opération finirait sous la réserve minimale de Solana (")
        .and_then(|rest| rest.strip_suffix(" SOL), le réseau la refuserait — essayez un montant plus élevé"))
    {
        return Some(format!("another account touched by the operation would end up below Solana's minimum reserve ({reserve} SOL); the network would refuse it — try a larger amount"));
    }
    if let Some(rest) = msg.strip_prefix("transaction Zcash refusée par le réseau : ") {
        return Some(format!("Zcash transaction refused by the network: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("le réseau Zcash a changé de version") {
        return Some(format!("the Zcash network was upgraded{rest} — update the app before sending"));
    }
    if let Some(rest) = msg.strip_prefix("devis LI.FI refusé : ") {
        return Some(format!("LI.FI quote refused: {rest}"));
    }
    for name in ["THORChain", "Maya"] {
        if let Some(rest) = msg.strip_prefix(&format!("devis {name} refusé : ")) {
            return Some(format!("{name} quote refused: {rest}"));
        }
    }
    for name in ["Etherscan", "Routescan"] {
        if let Some(rest) = msg.strip_prefix(&format!("{name} a refusé la demande : ")) {
            return Some(format!("{name} refused the request: {rest}"));
        }
        if let Some(rest) = msg.strip_prefix(&format!("appel {name} impossible : ")) {
            return Some(format!("could not reach {name}: {rest}"));
        }
    }
    if let Some((name, minimum)) = msg
        .strip_prefix("montant trop faible pour ")
        .and_then(|rest| rest.strip_suffix(" (en dessous, le dépôt serait ignoré ou son remboursement impossible)"))
        .and_then(|rest| rest.split_once(" : au moins "))
    {
        return Some(format!("amount too small for {name}: at least {minimum} (below that, the deposit would be ignored or its refund impossible)"));
    }
    if let Some(cap) = msg.strip_prefix("frais LI.FI de la transaction Bitcoin au-delà de ").and_then(|rest| rest.strip_suffix(" — refusé")) {
        return Some(format!("LI.FI fees in the Bitcoin transaction above {} — refused", cap.replace(',', ".").replace(" %", "%")));
    }
    if let Some(detail) = msg
        .strip_prefix("frais réseau Bitcoin anormalement élevés dans la transaction LI.FI (")
        .and_then(|rest| rest.strip_suffix(") — refusé"))
    {
        return Some(format!("abnormally high Bitcoin network fee in the LI.FI transaction ({}) — refused", detail.replace(" pour ", " for ").replace("plafond", "cap")));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Zcash ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'échange").or_else(|| rest.strip_suffix(") — relancez l'envoi")))
    {
        return Some(format!("Zcash fees increased since the confirmation ({}) — start again", detail.replace(" au lieu de ", " instead of ")));
    }
    if let Some(detail) = msg.strip_prefix("les frais Dogecoin ont augmenté depuis la confirmation (").and_then(|rest| rest.strip_suffix(") — relancez l'envoi")) {
        return Some(format!("Dogecoin fees increased since the confirmation ({}) — start again", detail.replace(" au lieu de ", " instead of ")));
    }
    if let Some(rest) = msg.strip_prefix("solde insuffisant sur l'adresse d'affiliation ") {
        return Some(format!(
            "insufficient balance on the affiliate address on {}",
            rest.replace(" disponibles, ", " available, ").replace(" nécessaires (dépôt + frais réseau)", " needed (deposit + network fee)")
        ));
    }
    if let Some((name, network)) = msg.strip_prefix("le nom « ").and_then(|rest| rest.split_once(" » appartient déjà à quelqu'un d'autre sur ")) {
        return Some(format!("the name \"{name}\" already belongs to someone else on {network}"));
    }
    if let Some(rest) = msg.strip_prefix("transaction refusée par ") {
        if let Some((network, reason)) = rest.split_once(" : ") {
            return Some(format!("transaction refused by {network}: {reason}"));
        }
    }
    if let Some(rest) = msg.strip_prefix("XMR insuffisants pour les frais (") {
        return Some(format!("insufficient XMR for the fee ({}", rest.replace(") : maximum envoyable ", "): maximum sendable ")));
    }
    if let Some(rest) = msg.strip_prefix("XMR insuffisants : ") {
        let rest = rest
            .replace(" demandés", " requested")
            .replace(" disponibles", " available")
            .replace(" encore bloqués : 10 confirmations, ≈ 20 min", " still locked: 10 confirmations, ≈ 20 min");
        return Some(format!("insufficient XMR: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("aucun nœud Monero joignable (") {
        return Some(format!("no reachable Monero node ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("nœud Monero : ") {
        return Some(format!("Monero node: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("transaction refusée par le nœud Monero : ") {
        return Some(format!("transaction refused by the Monero node: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("diffusion Monero incertaine (") {
        if let Some(reason) = rest.strip_suffix(") : vérifiez l'historique dans quelques minutes avant de renvoyer") {
            return Some(format!("uncertain Monero broadcast ({reason}): check the history in a few minutes before sending again"));
        }
    }
    if let Some(rest) = msg.strip_prefix("réseau Monero mis à niveau (version ") {
        if let Some(version) = rest.strip_suffix(") : mettez l'app à jour avant d'envoyer") {
            return Some(format!("Monero network upgraded (version {version}): update the app before sending"));
        }
    }
    if let Some(rest) = msg.strip_prefix("signature Monero impossible (") {
        return Some(format!("Monero signing failed ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("envoi Monero impossible (") {
        return Some(format!("Monero transfer impossible ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("clés Monero invalides (") {
        return Some(format!("invalid Monero keys ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("bloc Monero ") {
        if let Some((number, reason)) = rest.split_once(" illisible (") {
            return Some(format!("unreadable Monero block {number} ({reason}"));
        }
    }
    if let Some(rest) = msg.strip_prefix("rien à protéger pour l'instant (") {
        return Some(format!("nothing to shield for now ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("envoi Zcash protégé impossible (") {
        return Some(format!("shielded Zcash transfer impossible ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("transaction Zcash protégée : construction impossible (") {
        return Some(format!("shielded Zcash transaction: could not build it ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("memo Maya trop long pour une sortie OP_RETURN (") {
        return Some(format!("Maya memo too long for an OP_RETURN output ({}", rest.replace("octets", "bytes")));
    }
    if let Some(rest) = msg.strip_prefix("aucune route LI.FI dont le destinataire soit vérifiable (ponts écartés : ") {
        return Some(format!("no LI.FI route with a verifiable recipient (bridges excluded: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("devis CoW refusé : ") {
        return Some(format!("CoW quote refused: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("ordre CoW refusé : ") {
        return Some(format!("CoW order refused: {rest}"));
    }
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
            .replace("sat confirmés disponibles", "confirmed sat available")
            .replace("disponibles", "available")
            .replace("de frais de gas requis", "gas fee required")
            .replace("de frais requis", "fee required")
            .replace(" requis", " required");
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
    zcash: String,
    zcash_shielded: String,
    monero: String,
    doge: String,
}

impl From<api::Addresses> for AddressesDto {
    fn from(a: api::Addresses) -> Self {
        Self {
            evm: a.evm,
            btc_testnet: a.btc_testnet,
            btc_mainnet: a.btc_mainnet,
            solana: a.solana,
            zcash: a.zcash,
            zcash_shielded: a.zcash_shielded,
            monero: a.monero,
            doge: a.doge,
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
    /// Identifiant du kit (commun aux 3 parts, voir `api::backup_kit_id`) et
    /// numéro de la part : pour la sauvegarde sur clé USB.
    kit_id: String,
    part: u8,
}

/// Parts d'un kit, avec leur identifiant de kit commun et leur numéro.
fn backup_dtos(backups: Vec<api::BackupShare>) -> Vec<BackupShareDto> {
    let kit_id = api::backup_kit_id(&backups);
    backups
        .into_iter()
        .enumerate()
        .map(|(i, b)| BackupShareDto {
            label: b.label,
            passphrase: b.passphrase,
            encrypted_share_b64: base64::engine::general_purpose::STANDARD.encode(&b.encrypted_share),
            privkey_armored_b64: base64::engine::general_purpose::STANDARD.encode(&b.privkey_armored),
            kit_id: kit_id.clone(),
            part: (i + 1) as u8,
        })
        .collect()
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
const ALLOWED_EXTERNAL_LINK_PREFIXES: [&str; 7] = [
    "https://explorer.solana.com/",
    "https://blockstream.info/",
    "https://explorer.cow.fi/",
    "https://scan.li.fi/",
    "https://blockchair.com/zcash/",
    "https://xmrchain.net/",
    "https://blockchair.com/dogecoin/",
];

/// Lien vers un explorateur connu de l'app : Solana, Bitcoin, ou l'explorateur
/// d'un réseau EVM (origine de `explorer_tx_prefix` : Etherscan, Arbiscan,
/// BscScan…). Avant, seuls etherscan.io et sepolia.etherscan.io étaient
/// admis : les liens des historiques Arbitrum, Base et Polygon étaient refusés.
fn external_link_allowed(url: &str) -> bool {
    let evm_origins = wallet_flow::EVM_NETWORKS.iter().filter_map(|n| {
        let rest = n.explorer_tx_prefix.strip_prefix("https://")?;
        Some(&n.explorer_tx_prefix[..8 + rest.find('/')? + 1])
    });
    ALLOWED_EXTERNAL_LINK_PREFIXES.into_iter().chain(evm_origins).any(|prefix| url.starts_with(prefix))
}

/// Ouvre un lien externe (explorateur de blocs) dans le navigateur système : un
/// `<a target="_blank">` classique ne s'ouvre pas de façon fiable dans la webview
/// Tauri (navigation interceptée pour raisons de sécurité), même limite déjà
/// rencontrée pour les téléchargements (voir `save_bytes_with_dialog`). `url` vient
/// du frontend (non fiable, voir en-tête de ce fichier) : restreint à la liste
/// blanche ci-dessus, pas seulement au schéma https://.
#[tauri::command]
fn open_external_link(url: String, app: tauri::AppHandle) -> Result<(), String> {
    if !external_link_allowed(&url) {
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
    api::reset_wallet(&dir).t_err()?;
    forget_wallet_connections(&app);
    Ok(())
}

#[tauri::command]
fn create_wallet(password: String, app: tauri::AppHandle) -> Result<CreateWalletDto, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let result = api::create_wallet(&dir, &password).t_err()?;
    remember_addresses(&app, 0, &result.addresses);

    let backups = backup_dtos(result.backups);

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

    api::regenerate_backup_kit(&dir, &password).map(backup_dtos).t_err()
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

// --- Nom d'affiliation (portefeuille du développeur seulement) -----------------

#[derive(Serialize)]
struct AffiliateNameDto {
    /// « thorchain » ou « maya ».
    chain: &'static str,
    protocol: &'static str,
    name: &'static str,
    /// « free », « ours », « taken ».
    state: &'static str,
    years_left: Option<f64>,
    address: &'static str,
    symbol: &'static str,
    balance: String,
    deposit: String,
    network_fee: String,
}

fn native_amount(units: u128, decimals: u32) -> String {
    pgp_wallet_poc::tokens::format_amount(units, decimals as u8)
}

/// État du nom d'affiliation sur THORChain et Maya (données publiques) ;
/// `None` si le profil principal n'est pas le portefeuille du développeur.
#[tauri::command]
async fn affiliate_names_status() -> Result<Option<Vec<AffiliateNameDto>>, String> {
    if !IS_AFFILIATE_WALLET.load(Ordering::Relaxed) {
        return Ok(None);
    }
    run_blocking(|| {
        let read = |chain: &'static str| -> Result<AffiliateNameDto, String> {
            let (native, protocol) = api::affiliate_name_chains(chain).t_err()?;
            let status = api::affiliate_name_status(chain).t_err()?;
            let (state, years_left) = match status.state {
                api::NameState::Free => ("free", None),
                api::NameState::Ours { years_left, .. } => ("ours", Some(years_left)),
                api::NameState::Taken => ("taken", None),
            };
            Ok(AffiliateNameDto {
                chain,
                protocol: protocol.name,
                name: status.name,
                state,
                years_left,
                address: status.address,
                symbol: if chain == "maya" { "CACAO" } else { "RUNE" },
                balance: native_amount(status.balance, native.decimals),
                deposit: native_amount(status.deposit, native.decimals),
                network_fee: native_amount(status.network_fee, native.decimals),
            })
        };
        let (thorchain, maya) = std::thread::scope(|scope| {
            let thorchain = scope.spawn(|| read("thorchain"));
            (thorchain.join().unwrap_or_else(|_| Err("lecture THORChain interrompue".to_string())), read("maya"))
        });
        Ok(Some(vec![thorchain?, maya?]))
    })
    .await
}

/// Inscrit (ou prolonge d'un an) le nom d'affiliation sur `chain`, après une
/// boîte de confirmation native construite à partir de l'état relu ICI.
#[tauri::command]
async fn register_affiliate_name(password: String, chain: String, app: tauri::AppHandle) -> Result<String, String> {
    if !IS_AFFILIATE_WALLET.load(Ordering::Relaxed) {
        return Err(translate_error("ce portefeuille n'est pas celui qui reçoit les frais d'affiliation de l'app — inscription réservée à ce dernier"));
    }
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (native, protocol) = api::affiliate_name_chains(&chain).t_err()?;
        let status = api::affiliate_name_status(&chain).t_err()?;
        let symbol = if chain == "maya" { "CACAO" } else { "RUNE" };
        let amount = |units: u128| format!("{} {symbol}", native_amount(units, native.decimals));
        let (action_fr, action_en) = match status.state {
            api::NameState::Free => ("Inscription (un an inclus) et un an de plus", "Registration (one year included) plus one more year"),
            api::NameState::Ours { .. } => ("Prolongation d'un an", "One-year extension"),
            api::NameState::Taken => return Err(translate_error(&format!("le nom « {} » appartient déjà à quelqu'un d'autre sur {}", status.name, native.name))),
        };
        let (name, network) = (status.name, protocol.name);
        let (deposit, fee, address) = (amount(status.deposit), amount(status.network_fee), status.address);
        let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!(
                "Affiliate name \"{name}\" on {network}\n\n{action_en}: {deposit}\nNetwork fee: {fee}\nPaid from, owned by, and fees sent to: {address}\n\nOnce registered, swaps from Bitcoin (and Zcash on Maya) include the app's 0.80% affiliate fee. This deposit is irreversible.\n\nConfirm?"
            )
        } else {
            format!(
                "Nom d'affiliation « {name} » sur {network}\n\n{action_fr} : {deposit}\nFrais réseau : {fee}\nPayé par, appartenant à, et frais versés à : {address}\n\nUne fois inscrit, les échanges depuis Bitcoin (et Zcash sur Maya) incluent les 0,80 % d'affiliation de l'app. Ce dépôt est irréversible.\n\nConfirmer ?"
            )
        };
        let confirmed = app
            .dialog()
            .message(message)
            .title(lang("Confirmer l'inscription du nom", "Confirm the name registration"))
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show();
        if !confirmed {
            return Err(translate_error("Inscription annulée (confirmation refusée)."));
        }
        api::register_affiliate_name(&dir, &password, &chain, status.deposit).t_err()
    })
    .await
}

#[tauri::command]
fn unlock_wallet(password: String, app: tauri::AppHandle) -> Result<Vec<ProfileDto>, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let profiles = api::unlock_wallet(&dir, &password).t_err()?;
    remember_profiles(&app, &profiles);
    Ok(profiles.into_iter().map(Into::into).collect())
}

fn remember_profiles(app: &tauri::AppHandle, profiles: &[api::ProfileAddresses]) {
    for p in profiles {
        if let Some(a) = &p.addresses {
            remember_addresses(app, p.profile.index, a);
        }
    }
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
    let profiles = api::unlock_wallet_biometric(&dir).t_err()?;
    remember_profiles(&app, &profiles);
    Ok(profiles.into_iter().map(Into::into).collect())
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
    let profile = api::create_profile(&dir, password.as_ref().map(|p| p.as_str()), &label).t_err()?;
    remember_profiles(&app, std::slice::from_ref(&profile));
    Ok(profile.into())
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

#[derive(Serialize)]
struct BackupDriveDto {
    /// Racine (`E:\`), à renvoyer telle quelle aux commandes suivantes.
    root: String,
    label: String,
    free_bytes: u64,
    /// Parts déjà présentes (kit, numéro).
    shares: Vec<pgp_wallet_poc::usb_backup::ShareInfo>,
}

/// Clés USB branchées, et la part de sauvegarde que chacune contient (aucun
/// secret : kit et numéro de part seulement). Appelée à intervalles réguliers
/// par l'interface pour détecter une clé dès qu'elle est branchée.
#[tauri::command]
async fn list_backup_drives() -> Result<Vec<BackupDriveDto>, String> {
    run_blocking(|| {
        Ok(pgp_wallet_poc::usb_backup::removable_drives()
            .into_iter()
            .map(|d| BackupDriveDto { root: d.root.to_string_lossy().into_owned(), label: d.label, free_bytes: d.free_bytes, shares: d.shares })
            .collect())
    })
    .await
}

/// Écrit une part COMPLÈTE du kit (fichier de part, clé privée, mot de passe)
/// sur la clé USB `root` — seule une clé USB détectée est acceptée, jamais un
/// chemin quelconque — puis la relit et vérifie qu'elle se déchiffre. Voir
/// `core/src/usb_backup.rs` (une part par clé).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn save_backup_to_usb(
    root: String,
    kit_id: String,
    part: u8,
    encrypted_share_b64: String,
    privkey_armored_b64: String,
    passphrase: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).t_err();
        let files = pgp_wallet_poc::usb_backup::ShareFiles {
            encrypted_share: decode(&encrypted_share_b64)?,
            privkey_armored: decode(&privkey_armored_b64)?,
            passphrase: Zeroizing::new(passphrase),
        };
        let drive = pgp_wallet_poc::usb_backup::write_share(&root, &kit_id, part, &files, |written| {
            api::verify_backup_share(&dir, &written.encrypted_share, &written.privkey_armored, &written.passphrase)
        })
        .t_err()?;
        Ok(drive.label)
    })
    .await
}

#[derive(serde::Deserialize)]
struct KitShareDto {
    part: u8,
    encrypted_share_b64: String,
    privkey_armored_b64: String,
    passphrase: String,
}

/// Boîte native avant d'écrire TOUT le kit sur une seule clé : cette clé
/// suffira à elle seule à tout récupérer, sans mot de passe.
fn confirm_kit_on_one_drive_native(app: &tauri::AppHandle, drive: &str) -> bool {
    let drive = dialog_label(drive);
    let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!("Save the 3 shares on the single USB drive \"{drive}\"?\n\nThis drive will then be enough ON ITS OWN to recover the whole wallet and its funds, with no password: whoever finds or steals it gets everything. Keep it somewhere safe (a safe), never with the computer.\n\nSafer: save each share on its own drive, in different places.")
    } else {
        format!("Enregistrer les 3 parts sur la seule clé USB « {drive} » ?\n\nCette clé suffira alors À ELLE SEULE à récupérer tout le portefeuille et ses fonds, sans aucun mot de passe : qui la trouve ou la vole a accès à tout. Rangez-la en lieu sûr (coffre), jamais avec l'ordinateur.\n\nPlus sûr : enregistrer chaque part sur sa propre clé, à des endroits différents.")
    };
    app.dialog()
        .message(message)
        .title(lang("Tout le kit sur une clé USB", "Whole kit on one USB drive"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Écrit TOUT le kit (les 3 parts complètes) sur la clé USB `root`, après la
/// boîte native qui en dit la conséquence, puis vérifie chaque part relue.
/// Renvoie le nom de la clé ; `None` si l'utilisateur a refusé dans la boîte.
#[tauri::command]
async fn save_kit_to_usb(root: String, kit_id: String, shares: Vec<KitShareDto>, app: tauri::AppHandle) -> Result<Option<String>, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).t_err();
        let mut parts = Vec::with_capacity(shares.len());
        for share in shares {
            let files = pgp_wallet_poc::usb_backup::ShareFiles {
                encrypted_share: decode(&share.encrypted_share_b64)?,
                privkey_armored: decode(&share.privkey_armored_b64)?,
                passphrase: Zeroizing::new(share.passphrase),
            };
            parts.push((share.part, files));
        }
        let name = pgp_wallet_poc::usb_backup::removable_drives()
            .into_iter()
            .find(|d| d.root.to_string_lossy().eq_ignore_ascii_case(root.trim()))
            .map(|d| if d.label.is_empty() { d.root.to_string_lossy().into_owned() } else { format!("{} ({})", d.label, d.root.to_string_lossy().trim_end_matches('\\')) })
            .ok_or_else(|| translate_error("clé USB introuvable : branchez-la puis réessayez"))?;
        if !confirm_kit_on_one_drive_native(&app, &name) {
            return Ok(None);
        }
        let drive = pgp_wallet_poc::usb_backup::write_kit(&root, &kit_id, &parts, |written| {
            api::verify_backup_share(&dir, &written.encrypted_share, &written.privkey_armored, &written.passphrase)
        })
        .t_err()?;
        Ok(Some(drive.label))
    })
    .await
}

/// Parts lues sur des clés USB pour une restauration (gardées ici, jamais
/// envoyées à l'interface) : les clés peuvent être branchées l'une après l'autre.
#[derive(Default)]
struct UsbRestoreState(std::sync::Mutex<Vec<(pgp_wallet_poc::usb_backup::ShareInfo, pgp_wallet_poc::usb_backup::ShareFiles)>>);

/// Lit toutes les parts de la clé USB `root` pour une restauration à venir ;
/// renvoie celles lues (kit, numéro — aucun secret).
#[tauri::command]
async fn usb_restore_load(root: String, app: tauri::AppHandle) -> Result<Vec<pgp_wallet_poc::usb_backup::ShareInfo>, String> {
    run_blocking(move || {
        let drive_shares = pgp_wallet_poc::usb_backup::removable_drives()
            .into_iter()
            .find(|d| d.root.to_string_lossy().eq_ignore_ascii_case(root.trim()))
            .map(|d| d.shares)
            .ok_or_else(|| translate_error("clé USB introuvable : branchez-la puis réessayez"))?;
        let mut read = Vec::with_capacity(drive_shares.len());
        for info in drive_shares {
            read.push(pgp_wallet_poc::usb_backup::read_share(&root, info.part).t_err()?);
        }
        let state = app.state::<UsbRestoreState>();
        let mut loaded = state.0.lock().unwrap_or_else(|p| p.into_inner());
        let mut infos = Vec::with_capacity(read.len());
        for (info, files) in read {
            loaded.retain(|(i, _)| *i != info);
            infos.push(info.clone());
            loaded.push((info, files));
        }
        Ok(infos)
    })
    .await
}

/// Oublie les parts lues (restauration abandonnée).
#[tauri::command]
fn usb_restore_clear(app: tauri::AppHandle) {
    app.state::<UsbRestoreState>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

/// Restauration à partir de deux parts d'un même kit lues sur des clés USB
/// (`usb_restore_load`) — même chemin que `restore_wallet` ensuite.
#[tauri::command]
fn restore_wallet_from_usb(new_password: String, app: tauri::AppHandle) -> Result<AddressesDto, String> {
    let new_password = Zeroizing::new(new_password);
    let dir = data_dir(&app)?;
    let state = app.state::<UsbRestoreState>();
    let (first, second) = {
        let loaded = state.0.lock().unwrap_or_else(|p| p.into_inner());
        let pair = loaded.iter().enumerate().find_map(|(i, (a, _))| {
            loaded.iter().enumerate().skip(i + 1).find(|(_, (b, _))| b.kit == a.kit && b.part != a.part).map(|(j, _)| (i, j))
        });
        let (i, j) = pair.ok_or_else(|| translate_error("branchez deux clés USB portant deux parts différentes d'une même sauvegarde"))?;
        let copy = |k: usize| {
            let (_, f) = &loaded[k];
            (f.encrypted_share.clone(), f.privkey_armored.clone(), Zeroizing::new(f.passphrase.to_string()))
        };
        (copy(i), copy(j))
    };
    if !confirm_restore_native(&app) {
        return Err(translate_error("Restauration annulée (confirmation refusée)."));
    }
    let addresses = api::restore_wallet(
        &dir,
        &new_password,
        (&first.0, &first.1, &first.2),
        (&second.0, &second.1, &second.2),
    )
    .t_err()?;
    state.0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    forget_wallet_connections(&app);
    remember_addresses(&app, 0, &addresses);
    Ok(addresses.into())
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
    let addresses = api::restore_wallet(
        &dir,
        &new_password,
        (&share1, &priv1, &passphrase1),
        (&share2, &priv2, &passphrase2),
    )
    .t_err()?;
    // Nouveau portefeuille : les connexions et adresses de l'ancien ne valent plus.
    forget_wallet_connections(&app);
    remember_addresses(&app, 0, &addresses);
    Ok(addresses.into())
}

/// Réinitialisation/restauration : les dApps connectées l'étaient à l'ANCIEN
/// portefeuille — déconnectées, et adresses mémorisées oubliées.
fn forget_wallet_connections(app: &tauri::AppHandle) {
    if let Ok(client) = wc_client(app) {
        client.disconnect_all();
    }
    forget_session(app);
}

/// Verrouillage (bouton, ou inactivité) : clés de visualisation Zcash protégé
/// et Monero, adresses mémorisées et demandes de dApps préparées oubliées
/// jusqu'au prochain déverrouillage — la synchronisation de fond s'arrête
/// faute de clés, et aucune commande ne répond plus pour un profil. Les
/// connexions WalletConnect restent (reprises au déverrouillage).
#[tauri::command]
fn lock_session(app: tauri::AppHandle) {
    forget_session(&app);
}

fn forget_session(app: &tauri::AppHandle) {
    // Envois encore dans leur délai d'annulation : annulés.
    for sender in app.state::<SendGrace>().0.lock().unwrap_or_else(|p| p.into_inner()).values() {
        let _ = sender.send(false);
    }
    app.state::<WcState>().prepared.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<ProfileZcashCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<ProfileBtcCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<ProfileDogeCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<ProfileBtcTestnetCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<ShieldedKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.state::<MoneroKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
    IS_AFFILIATE_WALLET.store(false, Ordering::Relaxed);
}

fn evm_network(network: &str) -> Result<&'static wallet_flow::EvmNetwork, String> {
    wallet_flow::evm_network(network).ok_or_else(|| translate_error(&format!("réseau EVM inconnu : {network}")))
}

/// Réseau EVM (Ethereum, ses L2, BNB Chain, Avalanche, Polygon…) : même
/// adresse, même code d'envoi, voir `wallet_flow::EVM_NETWORKS`.
fn is_evm(network: &str) -> bool {
    wallet_flow::evm_network(network).is_some()
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
async fn get_balance(network: String, address: String, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        match network.as_str() {
            n if is_evm(n) => {
                let net = evm_network(&network)?;
                let wei = api::get_evm_balance(&address, net).t_err()?;
                Ok(format!("{:.6}", wei as f64 / 1e18))
            }
            "btc_testnet" | "btc_mainnet" => {
                let net = btc_network(&network)?;
                // Confirmé moins les envois en attente ; les réceptions non
                // confirmées sont montrées à part (`get_btc_pending_incoming`).
                let sat = api::get_btc_balance_view(&address, net).t_err()?.settled_sat;
                Ok(format!("{:.8}", sat as f64 / 1e8))
            }
            "sol_devnet" | "sol_mainnet" => {
                let net = sol_network(&network)?;
                let lamports = api::get_sol_balance(&address, net).t_err()?;
                Ok(format!("{:.9}", lamports as f64 / 1e9))
            }
            "zec_mainnet" => Ok(pgp_wallet_poc::zcash::format_zec(api::get_zec_balance(&address).t_err()?)),
            "doge_mainnet" => Ok(pgp_wallet_poc::doge::format_doge(api::get_doge_balance(&address).t_err()?)),
            // Base locale (synchronisation de fond) : dépensable + en attente.
            "zec_shielded" => {
                let balance = api::zec_shielded_balance(&data_dir(&app)?, shielded_profile(&app, &address)?).t_err()?;
                Ok(pgp_wallet_poc::zcash::format_zec(balance.spendable.saturating_add(balance.pending)))
            }
            // État local (synchronisation de fond) : dépensable + bloqué.
            "xmr_mainnet" => {
                let balance = api::xmr_balance(&data_dir(&app)?, monero_profile(&app, &address)?).t_err()?;
                Ok(pgp_wallet_poc::monero::format_xmr(balance.unlocked.saturating_add(balance.locked)))
            }
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        }
    })
    .await
}

/// Réceptions Bitcoin non confirmées de `address` (montant BTC), `None` s'il n'y
/// en a pas : affichées à part sur la carte, jamais comptées dans le solde —
/// elles peuvent encore être annulées par leur émetteur (voir
/// `api::BtcBalanceView`).
#[tauri::command]
async fn get_btc_pending_incoming(network: String, address: String) -> Result<Option<String>, String> {
    run_blocking(move || {
        let net = btc_network(&network)?;
        let sat = api::get_btc_balance_view(&address, net).t_err()?.incoming_pending_sat;
        Ok((sat > 0).then(|| format!("{:.8}", sat as f64 / 1e8)))
    })
    .await
}

/// Solde USDC — mainnet uniquement (voir sol_spl.rs : pas de mint devnet
/// vérifié avec confiance, et aucun intérêt pratique à en tester un).
#[tauri::command]
async fn get_usdc_balance(network: String, address: String) -> Result<String, String> {
    run_blocking(move || {
        if network != "sol_mainnet" {
            return Err(translate_error("USDC n'est disponible que sur Solana mainnet."));
        }
        let net = sol_network(&network)?;
        let micros = api::get_usdc_balance(&address, net).t_err()?;
        Ok(format!("{:.6}", micros as f64 / 1e6))
    })
    .await
}

#[derive(serde::Deserialize)]
struct WatchTargetDto {
    /// Carte à relire ("evm", "btc", "sol", "usdc"), rendue telle quelle.
    id: String,
    network: String,
    address: String,
    /// Jeton du registre ; absent : la monnaie du réseau.
    #[serde(default)]
    token: Option<String>,
}

/// Surveillance en direct des soldes des cartes affichées.
#[derive(Default)]
struct BalanceWatchState(std::sync::Mutex<Option<pgp_wallet_poc::balance_watch::BalanceWatch>>);

/// Remplace la surveillance en direct des soldes (voir
/// `core/src/balance_watch.rs`) : à chaque changement, l'événement
/// "balance-changed" donne l'id de la carte à relire. Liste vide : arrêt
/// (verrouillage). Adresses publiques seulement.
#[tauri::command]
fn watch_balances(targets: Vec<WatchTargetDto>, app: tauri::AppHandle, state: tauri::State<BalanceWatchState>) -> Result<(), String> {
    let mut current = state.0.lock().unwrap_or_else(|p| p.into_inner());
    *current = None; // arrête la surveillance précédente
    if targets.is_empty() {
        return Ok(());
    }
    let notify: pgp_wallet_poc::balance_watch::Notify = std::sync::Arc::new(move |id: &str| {
        let _ = app.emit("balance-changed", id);
    });
    let targets = targets
        .into_iter()
        .map(|t| pgp_wallet_poc::balance_watch::Target { id: t.id, network: t.network, address: t.address, token: t.token })
        .collect();
    *current = Some(pgp_wallet_poc::balance_watch::start(targets, notify).t_err()?);
    Ok(())
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
async fn estimate_btc_fees(network: String, address: String) -> Result<BtcFeeEstimateDto, String> {
    run_blocking(move || {
        let net = btc_network(&network)?;
        let estimate = api::estimate_btc_fees(&address, net).t_err()?;
        Ok(BtcFeeEstimateDto {
            fast_sat: estimate.fast_sat,
            medium_sat: estimate.medium_sat,
            slow_sat: estimate.slow_sat,
        })
    })
    .await
}

/// `false` pour EVM plutôt qu'une erreur : aucun nœud public n'expose les
/// transactions en attente pour Ethereum (voir `api::has_pending_btc`/`has_pending_sol`),
/// donc l'indicateur "transaction en attente" ne peut structurellement jamais
/// s'allumer pour ETH — un no-op silencieux, pas un échec, pour ne pas faire
/// planter le rafraîchissement automatique du solde sur ce réseau.
#[tauri::command]
async fn has_pending_tx(network: String, address: String, app: tauri::AppHandle) -> Result<bool, String> {
    run_blocking(move || {
        match network.as_str() {
            n if is_evm(n) => Ok(false),
            "btc_testnet" | "btc_mainnet" => {
                let net = btc_network(&network)?;
                api::has_pending_btc(&address, net).t_err()
            }
            "sol_devnet" | "sol_mainnet" => {
                let net = sol_network(&network)?;
                api::has_pending_sol(&address, net).t_err()
            }
            // Pas de lecture de la réserve de transactions : un envoi apparaît
            // à sa confirmation (~75 s).
            "zec_mainnet" | "zec_shielded" => Ok(false),
            "doge_mainnet" => api::has_pending_doge(&address).t_err(),
            "xmr_mainnet" => api::has_pending_xmr(&data_dir(&app)?, monero_profile(&app, &address)?).t_err(),
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        }
    })
    .await
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
    /// "received", "sent", "swap" ou "other" (voir `history::TxKind`).
    kind: &'static str,
    /// Valeur absolue du montant en dollars AU MOMENT de la transaction (voir
    /// `price_history`) ; `None` sur un réseau de test, pour une transaction
    /// trop ancienne, ou si le service de prix est injoignable.
    usd_value: Option<f64>,
    explorer_url: String,
}

/// Montant exact, chiffre par chiffre : un passage par `f64` (≈ 16 chiffres
/// significatifs) inventait les derniers chiffres d'un montant à 18 décimales
/// (« +0.245947228364191028 » pour 245947228364191044 wei).
fn format_signed_amount(net_amount_minor: Option<i128>, decimals: i32) -> Option<String> {
    net_amount_minor.map(|v| {
        let sign = if v < 0 { '-' } else { '+' };
        let digits = v.unsigned_abs().to_string();
        let decimals = decimals.max(0) as usize;
        let padded = format!("{digits:0>width$}", width = decimals + 1);
        let (int_part, frac_part) = padded.split_at(padded.len() - decimals);
        if decimals == 0 {
            format!("{sign}{int_part}")
        } else {
            format!("{sign}{int_part}.{frac_part}")
        }
    })
}

fn status_str(status: &history::TxStatus) -> &'static str {
    use history::TxStatus;
    match status {
        TxStatus::Confirmed => "confirmed",
        TxStatus::Pending => "pending",
        TxStatus::Failed => "failed",
    }
}

fn kind_str(kind: &history::TxKind) -> &'static str {
    use history::TxKind;
    match kind {
        TxKind::Received => "received",
        TxKind::Sent => "sent",
        TxKind::Swap => "swap",
        TxKind::Other => "other",
    }
}

/// Entrées d'historique prêtes à afficher. `asset` : actif valorisé en
/// dollars au moment de chaque transaction (`None` sur un réseau de test :
/// fonds sans valeur). Historique et séries de prix lus en parallèle ; sans
/// prix (service injoignable), l'historique s'affiche quand même, sans valeur.
fn history_dtos<E: std::fmt::Display>(
    fetch: impl FnOnce() -> Result<Vec<history::TxEntry>, E>,
    asset: Option<price_history::Asset>,
    decimals: i32,
    explorer_url: impl Fn(&str) -> String,
) -> Result<Vec<TxEntryDto>, String> {
    let (entries, prices) = std::thread::scope(|scope| {
        let prices = asset.map(|a| scope.spawn(move || price_history::series(a)));
        let entries = fetch();
        (entries, prices.and_then(|handle| handle.join().ok()).and_then(Result::ok))
    });
    Ok(entries
        .t_err()?
        .into_iter()
        .map(|tx| TxEntryDto {
            // Pas de « ≈ 0,00 $ » pour une transaction qui ne déplace rien.
            usd_value: prices
                .as_deref()
                .zip(tx.net_amount_minor.filter(|net| *net != 0))
                .and_then(|(series, net)| price_history::usd_value(series, net, decimals, tx.timestamp_unix)),
            kind: kind_str(&tx.kind),
            explorer_url: explorer_url(&tx.id),
            amount: format_signed_amount(tx.net_amount_minor, decimals),
            status: status_str(&tx.status).to_string(),
            timestamp_unix: tx.timestamp_unix,
            id: tx.id,
        })
        .collect())
}

/// Historique d'une crypto sur un réseau.
#[derive(Serialize)]
struct HistoryDto {
    entries: Vec<TxEntryDto>,
    /// Réseau sans source d'historique utilisable : page de l'adresse sur
    /// l'explorateur du réseau, à ouvrir à la place (`entries` vide).
    explorer_url: Option<String>,
    /// Pourquoi : « no_key » (clé Etherscan gratuite à saisir dans
    /// Paramètres), « paid_key » (sans clé, sur un réseau que seule une offre
    /// Etherscan payante couvre), « paid_plan » (clé enregistrée refusée pour
    /// ce réseau par l'offre gratuite).
    reason: Option<&'static str>,
}

impl HistoryDto {
    fn read(entries: Result<Vec<TxEntryDto>, String>) -> Result<Self, String> {
        Ok(Self { entries: entries?, explorer_url: None, reason: None })
    }

    /// Historique EVM : sans clé Etherscan pour ce réseau, ou refusé par
    /// l'offre gratuite, la page de l'explorateur avec le motif.
    fn evm(net: &wallet_flow::EvmNetwork, explorer_url: String, read: impl FnOnce() -> Result<Vec<TxEntryDto>, String>) -> Result<Self, String> {
        if !history::evm_history_available(net) {
            let reason = (net.history == Some(wallet_flow::EvmHistory::Etherscan))
                .then_some(if pgp_wallet_poc::routescan::etherscan_free_tier_covers(net.chain_id) { "no_key" } else { "paid_key" });
            return Ok(Self { entries: Vec::new(), explorer_url: Some(explorer_url), reason });
        }
        match read() {
            Err(e) if pgp_wallet_poc::routescan::is_paid_plan_refusal(&e) => Ok(Self { entries: Vec::new(), explorer_url: Some(explorer_url), reason: Some("paid_plan") }),
            entries => Self::read(entries),
        }
    }
}

#[tauri::command]
async fn get_tx_history(network: String, address: String, app: tauri::AppHandle) -> Result<HistoryDto, String> {
    run_blocking(move || match network.as_str() {
        n if is_evm(n) => {
            let net = evm_network(&network)?;
            api::validate_evm_recipient(&address).t_err()?;
            // Valeur en dollars : la monnaie du réseau (fonds réels seulement).
            let asset = if net.mainnet { price_history::price_asset(net.native_symbol) } else { None };
            HistoryDto::evm(net, net.explorer_address_url(&address, None), || {
                history_dtos(
                    || history::evm_history(net.chain_id, &address, HISTORY_LIMIT as usize),
                    asset,
                    18,
                    |id| format!("{}{}", net.explorer_tx_prefix, id),
                )
            })
        }
        "btc_testnet" | "btc_mainnet" => {
            let net = btc_network(&network)?;
            let asset = (network == "btc_mainnet").then_some(price_history::Asset::Btc);
            HistoryDto::read(history_dtos(|| history::btc_history(net, &address), asset, 8, |id| format!("{}{}", net.explorer_tx_prefix, id)))
        }
        "zec_shielded" => {
            let profile = shielded_profile(&app, &address)?;
            let dir = data_dir(&app)?;
            HistoryDto::read(history_dtos(
                || api::zec_shielded_history(&dir, profile),
                Some(price_history::Asset::Pair("ZECUSDT")),
                8,
                |id| format!("https://blockchair.com/zcash/transaction/{id}"),
            ))
        }
        "xmr_mainnet" => {
            let profile = monero_profile(&app, &address)?;
            let dir = data_dir(&app)?;
            HistoryDto::read(history_dtos(
                || api::xmr_history(&dir, profile),
                Some(price_history::Asset::Kraken("XMRUSD")),
                12,
                |id| format!("https://xmrchain.net/tx/{id}"),
            ))
        }
        "zec_mainnet" => HistoryDto::read(history_dtos(
            || history::zec_history(&address),
            Some(price_history::Asset::Pair("ZECUSDT")),
            8,
            |id| format!("https://blockchair.com/zcash/transaction/{id}"),
        )),
        "doge_mainnet" => HistoryDto::read(history_dtos(
            || pgp_wallet_poc::doge::history(&address, HISTORY_LIMIT as usize),
            Some(price_history::Asset::Pair("DOGEUSDT")),
            8,
            |id| format!("https://blockchair.com/dogecoin/transaction/{id}"),
        )),
        "sol_devnet" | "sol_mainnet" => {
            let net = sol_network(&network)?;
            let asset = (network == "sol_mainnet").then_some(price_history::Asset::Sol);
            HistoryDto::read(history_dtos(
                || history::sol_history(net.rpc, &address, HISTORY_LIMIT),
                asset,
                9,
                |id| format!("{}{}{}", net.explorer_tx_prefix, id, net.explorer_tx_suffix),
            ))
        }
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
    })
    .await
}

/// Clé Etherscan enregistrée sur l'appareil, sous forme masquée seulement
/// (voir `core/src/etherscan_key.rs`) : jamais renvoyée en entier.
#[tauri::command]
fn etherscan_key_status() -> Option<String> {
    pgp_wallet_poc::etherscan_key::masked()
}

/// Enregistre (ou, vide, supprime) la clé Etherscan de l'utilisateur ;
/// renvoie sa forme masquée.
#[tauri::command]
fn set_etherscan_key(key: String, app: tauri::AppHandle) -> Result<Option<String>, String> {
    let key = Zeroizing::new(key);
    let dir = data_dir(&app)?;
    pgp_wallet_poc::etherscan_key::save(&dir, &key).t_err()
}

/// Historique d'un jeton du registre (`core/src/tokens.rs`) : ERC-20 via
/// l'indexeur du réseau, SPL via le compte de jetons associé. Seuls l'id du
/// jeton et le réseau viennent du frontend : contrat et mint sont ceux du
/// registre, jamais une adresse fournie par l'interface.
#[tauri::command]
async fn get_token_tx_history(token: String, network: String, address: String) -> Result<HistoryDto, String> {
    run_blocking(move || {
        let (info, deployment) =
            pgp_wallet_poc::tokens::find(&token, &network).ok_or_else(|| translate_error("jeton non pris en charge sur ce réseau"))?;
        let asset = price_history::price_asset(&info.symbol.to_ascii_uppercase());
        let decimals = i32::from(deployment.decimals);
        match deployment.kind {
            pgp_wallet_poc::tokens::TokenKind::Erc20 { contract } => {
                let net = evm_network(&network)?;
                api::validate_evm_recipient(&address).t_err()?;
                HistoryDto::evm(net, net.explorer_address_url(&address, Some(contract)), || {
                    history_dtos(
                        || history::erc20_history_page(net.chain_id, &address, contract, None).map(|(mut entries, _)| {
                            entries.truncate(HISTORY_LIMIT as usize);
                            entries
                        }),
                        asset,
                        decimals,
                        |id| format!("{}{}", net.explorer_tx_prefix, id),
                    )
                })
            }
            pgp_wallet_poc::tokens::TokenKind::Spl { .. } => {
                let net = sol_network(&network)?;
                let mint = api::registered_spl_mint(&token).t_err()?;
                HistoryDto::read(history_dtos(
                    || api::get_spl_tx_history(&address, &mint, net, HISTORY_LIMIT),
                    asset,
                    decimals,
                    |id| format!("{}{}{}", net.explorer_tx_prefix, id, net.explorer_tx_suffix),
                ))
            }
        }
    })
    .await
}

fn chart_range(range: &str) -> Result<price_history::ChartRange, String> {
    price_history::ChartRange::parse(range).ok_or_else(|| translate_error(&format!("période inconnue : {range}")))
}

/// Courbe de prix (instant, prix en dollars) d'une crypto sur la période
/// ("1d", "7d", "30d", "1y", "all") ; `symbol` : "BTC", "ETH", "SOL" ou "USDC".
#[tauri::command]
async fn get_price_chart(symbol: String, range: String) -> Result<Vec<(i64, f64)>, String> {
    run_blocking(move || {
        // Liste blanche des paires Binance ("EUR" : dollars pour 1 euro, pour
        // l'affichage en euros).
        let upper = symbol.to_ascii_uppercase();
        let asset = price_history::price_asset(&upper).ok_or_else(|| translate_error(&format!("crypto inconnue : {upper}")))?;
        price_history::chart(asset, chart_range(&range)?).map(|points| points.as_ref().clone()).t_err()
    })
    .await
}

#[derive(serde::Deserialize)]
struct HoldingDto {
    network: String,
    address: String,
    /// Jeton du registre ; absent : monnaie du réseau.
    #[serde(default)]
    token: Option<String>,
}

#[derive(Serialize)]
struct PortfolioHistoryDto {
    points: Vec<(i64, f64)>,
    since: Option<i64>,
    approximate: bool,
    loading: bool,
    transactions_read: usize,
    constant: Vec<String>,
}

/// Valeur en dollars d'un ensemble d'adresses publiques au fil de la période
/// (voir `core/src/portfolio.rs`) : profil du portefeuille ou wallets externes.
#[tauri::command]
async fn get_portfolio_history(holdings: Vec<HoldingDto>, range: String) -> Result<PortfolioHistoryDto, String> {
    run_blocking(move || {
        let holdings: Vec<pgp_wallet_poc::portfolio::Holding> = holdings
            .into_iter()
            .map(|h| pgp_wallet_poc::portfolio::Holding { network: h.network, address: h.address, token: h.token })
            .collect();
        let history = pgp_wallet_poc::portfolio::portfolio_history(&holdings, chart_range(&range)?).t_err()?;
        Ok(PortfolioHistoryDto {
            points: history.points,
            since: history.since,
            approximate: history.approximate,
            loading: history.loading,
            transactions_read: history.transactions_read,
            constant: history.constant,
        })
    })
    .await
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
async fn get_crypto_prices() -> Result<PricesDto, String> {
    run_blocking(move || {
        price_rpc::PriceRpc::new()
            .get_prices()
            .map(|p| PricesDto { eth_usd: p.eth_usd, btc_usd: p.btc_usd, sol_usd: p.sol_usd })
            .t_err()
    })
    .await
}

#[derive(Serialize)]
struct MarketCoinDto {
    /// Identifiant CoinGecko : l'interface retrouve la crypto par lui.
    id: String,
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
async fn get_market_prices() -> Result<Vec<MarketCoinDto>, String> {
    run_blocking(move || {
        price_rpc::PriceRpc::new()
            .get_market_data()
            .map(|coins| {
                coins
                    .into_iter()
                    .map(|c| MarketCoinDto {
                        id: c.id,
                        symbol: c.symbol,
                        name: c.name,
                        price_usd: c.price_usd,
                        market_cap_usd: c.market_cap_usd,
                        change_24h_percent: c.change_24h_percent,
                    })
                    .collect()
            })
            .t_err()
    })
    .await
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

/// Adresse Ethereum venue d'une dApp (contrat, bénéficiaire d'une autorisation
/// de dépense) : montrée EN ENTIER, sous sa forme EIP-55. `dialog_label` la
/// tronquait à 40 caractères sur 42 — les derniers, justement ceux où une
/// adresse sosie diffère (vu lors du premier test réel avec une dApp). Autre
/// chose qu'une adresse : traité comme un libellé.
fn dialog_address(value: &str) -> String {
    let value = value.trim();
    let hex_part = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or("");
    if hex_part.len() != 40 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return dialog_label(value);
    }
    let mut bytes = [0u8; 20];
    for (i, byte) in bytes.iter_mut().enumerate() {
        // 40 chiffres hexadécimaux ASCII vérifiés : découpage et lecture sûrs.
        *byte = u8::from_str_radix(&hex_part[2 * i..2 * i + 2], 16).unwrap_or_default();
    }
    pgp_wallet_poc::derivation::format_address(&bytes)
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
fn network_label(network: &str) -> String {
    match network {
        "evm_sepolia" => "Ethereum Sepolia (testnet)".to_string(),
        "evm_mainnet" => lang("Ethereum MAINNET — fonds réels", "Ethereum MAINNET — real funds").to_string(),
        "btc_testnet" => lang("Bitcoin testnet", "Bitcoin testnet").to_string(),
        "btc_mainnet" => lang("Bitcoin MAINNET — fonds réels", "Bitcoin MAINNET — real funds").to_string(),
        "sol_devnet" => lang("Solana devnet", "Solana devnet").to_string(),
        "sol_mainnet" => lang("Solana MAINNET — fonds réels", "Solana MAINNET — real funds").to_string(),
        "zec_mainnet" => lang("Zcash MAINNET — fonds réels", "Zcash MAINNET — real funds").to_string(),
        "doge_mainnet" => lang("Dogecoin MAINNET — fonds réels", "Dogecoin MAINNET — real funds").to_string(),
        "xmr_mainnet" => lang("Monero MAINNET — fonds réels", "Monero MAINNET — real funds").to_string(),
        "zec_shielded" => lang("Zcash MAINNET — fonds protégés", "Zcash MAINNET — shielded funds").to_string(),
        other => match wallet_flow::evm_network(other) {
            Some(net) if net.mainnet => format!("{} — {}", net.name, lang("fonds réels", "real funds")),
            Some(net) => format!("{} (testnet)", net.name),
            None => other.to_string(),
        },
    }
}

/// Unité du montant d'un virement natif sur `network` (affichée à côté du
/// montant dans la boîte de confirmation).
fn network_unit(network: &str) -> &'static str {
    match network {
        "btc_testnet" | "btc_mainnet" => "BTC",
        "sol_devnet" | "sol_mainnet" => "SOL",
        "zec_mainnet" | "zec_shielded" => "ZEC",
        "xmr_mainnet" => "XMR",
        "doge_mainnet" => "DOGE",
        other => wallet_flow::evm_network(other).map(|n| n.native_symbol).unwrap_or(""),
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
#[allow(clippy::too_many_arguments)]
fn confirm_transaction_native(
    app: &tauri::AppHandle,
    network: &str,
    to: &str,
    amount: &str,
    from_label: &str,
    fee_line: Option<&str>,
    warning: Option<&str>,
    token_line: Option<&str>,
) -> bool {
    app.dialog()
        .message(transaction_confirmation_text(network, to, amount, from_label, fee_line, warning, token_line))
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
    token_line: Option<&str>,
) -> String {
    let fee_line = fee_line.map(|f| format!("\n{f}")).unwrap_or_default();
    // Jeton (virement de jetons) : nom et contrat, venus du registre Rust.
    let token_line = token_line.map(|l| format!("\n{l}")).unwrap_or_default();
    // En TÊTE du message : c'est la première chose lue, avant l'adresse.
    let warning = warning.map(|w| format!("{w}\n\n")).unwrap_or_default();
    let from_label = dialog_label(from_label);
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "{warning}Network: {}\nFrom profile: {from_label}{token_line}\nRecipient: {to}\nAmount: {amount}{fee_line}\n\nConfirm this transfer? It is irreversible.",
            network_label(network)
        )
    } else {
        format!(
            "{warning}Réseau : {}\nDepuis le profil : {from_label}{token_line}\nDestinataire : {to}\nMontant : {amount}{fee_line}\n\nConfirmer cet envoi ? C'est irréversible.",
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
/// passerait pour rassurant. `coin` : "evm", "btc", "sol", "usdc", "zec",
/// "xmr" ou "zecs" (nomme l'actif absent, une adresse "vide" de SOL pouvant
/// détenir autre chose).
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
    // Monero, Zcash protégé : adresses et montants invisibles sur la chaîne —
    // rien à vérifier, et pas une panne de réseau à signaler.
    if matches!(coin, "xmr" | "zecs") {
        return lines;
    }
    let (asset_fr, asset_en) = match coin {
        "evm" => ("aucun ETH", "no ETH"),
        "btc" => ("aucun BTC", "no BTC"),
        "usdc" => ("ni SOL ni USDC", "neither SOL nor USDC"),
        "zec" => ("aucun ZEC", "no ZEC"),
        "doge" => ("aucun DOGE", "no DOGE"),
        "sol" => ("aucun SOL", "no SOL"),
        _ => ("aucun fonds", "no funds"),
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
/// contact du carnet, puis nouvelle adresse, puis état on-chain. Adresse d'un
/// profil de ce portefeuille : le profil est nommé à la place des deux
/// derniers (ni « nouvelle adresse » ni « jamais servi » à craindre).
fn send_warnings(app: &tauri::AppHandle, dir: &std::path::Path, network: &str, coin: &str, to: &str, activity: Option<api::RecipientActivity>) -> Option<String> {
    let mut lines: Vec<String> = lookalike_warning(dir, to).into_iter().collect();
    match own_profile_label(app, dir, network, to) {
        Some(label) => lines.push(own_profile_line(&label)),
        None => lines.extend(recipient_warning_lines(!sent_recipients::has_sent_to(dir, network, to), coin, activity)),
    }
    (!lines.is_empty()).then(|| lines.join("\n\n"))
}

fn own_profile_line(label: &str) -> String {
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!("Recognized recipient: your profile \"{label}\" (an address of this wallet).")
    } else {
        format!("Destinataire reconnu : votre profil « {label} » (adresse de ce portefeuille).")
    }
}

/// Profil de ce portefeuille dont `to` est l'adresse sur `network`, d'après
/// les adresses dérivées de la seed au déverrouillage (caches Rust) — jamais
/// d'après l'interface. Nom nettoyé pour la boîte native.
fn own_profile_label(app: &tauri::AppHandle, dir: &std::path::Path, network: &str, to: &str) -> Option<String> {
    let to = to.trim();
    let in_cache = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>, same: fn(&str, &str) -> bool| {
        cache.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|(_, address)| same(address, to)).map(|(index, _)| *index)
    };
    let exact = |a: &str, b: &str| a == b;
    // Hexadécimal (EVM) et bech32 (Bitcoin, u1) : insensibles à la casse.
    let any_case = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let index = match network {
        n if is_evm(n) => {
            app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|(_, (evm, _))| evm.eq_ignore_ascii_case(to)).map(|(index, _)| *index)
        }
        "sol_mainnet" | "sol_devnet" | "usdc_solana" => {
            app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|(_, (_, sol))| sol == to).map(|(index, _)| *index)
        }
        "btc_mainnet" => in_cache(&app.state::<ProfileBtcCache>().0, any_case),
        "zec_mainnet" => in_cache(&app.state::<ProfileZcashCache>().0, exact),
        "doge_mainnet" => in_cache(&app.state::<ProfileDogeCache>().0, exact),
        "xmr_mainnet" => {
            app.state::<MoneroKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|(_, (address, _))| address == to).map(|(index, _)| *index)
        }
        // Depuis les fonds protégés : vers une adresse u1, ou t1, d'un profil.
        "zec_shielded" => app
            .state::<ShieldedKeysCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, (address, _))| address.eq_ignore_ascii_case(to))
            .map(|(index, _)| *index)
            .or_else(|| in_cache(&app.state::<ProfileZcashCache>().0, exact)),
        _ => None,
    }?;
    let label = api::list_profiles(dir).into_iter().find(|p| p.index == index)?.label;
    Some(dialog_label(&label))
}

/// Ligne de frais d'un envoi EVM, dans la monnaie de frais du réseau (`symbol`) :
/// maximum = gas × prix, plus les frais de publication sur Ethereum (réseaux
/// OP Stack, estimés) le cas échéant.
fn evm_fee_line_for(fee: api::EvmFee, symbol: &str) -> String {
    let gas_fee = fee.gas_price.saturating_mul(u128::from(fee.gas_limit)) as f64 / 1e18;
    let max_fee = gas_fee + fee.l1_fee as f64 / 1e18;
    let gwei = fee.gas_price as f64 / 1e9;
    let mut line = lang(
        &format!("Frais réseau maximum : {max_fee:.8} {symbol} ({gwei:.4} gwei)"),
        &format!("Maximum network fee: {max_fee:.8} {symbol} ({gwei:.4} gwei)"),
    )
    .to_string();
    if fee.l1_fee > 0 {
        let l1 = fee.l1_fee as f64 / 1e18;
        line.push_str(lang(
            &format!(", dont ≈ {l1:.8} {symbol} de publication sur Ethereum"),
            &format!(", incl. ≈ {l1:.8} {symbol} for posting to Ethereum"),
        ));
    }
    line
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn send_transaction(
    network: String,
    password: String,
    to: String,
    amount: String,
    fee_sat: Option<u64>,
    profile_index: u32,
    max: Option<bool>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));
        // Adresse EVM du profil (mémorisée au déverrouillage) : estimation du
        // gas là où elle est nécessaire (Arbitrum).
        let from_evm = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(evm, _)| evm.clone());
        let from_zec = app.state::<ProfileZcashCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned();
        let from_xmr = app.state::<MoneroKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(_, keys)| keys.clone());
        let from_sol = app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(_, sol)| sol.clone());
        let from_doge = app.state::<ProfileDogeCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned();
        let from_btc = match network.as_str() {
            "btc_mainnet" => app.state::<ProfileBtcCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned(),
            "btc_testnet" => app.state::<ProfileBtcTestnetCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned(),
            _ => None,
        };
        let from = SendFrom {
            evm: from_evm.as_deref(),
            sol: from_sol.as_deref(),
            zec: from_zec.as_deref(),
            xmr: from_xmr.as_ref(),
            doge: from_doge.as_deref(),
            btc: from_btc.as_deref(),
        };
        let mut send = confirm_send(&app, &dir, &network, &to, &amount, fee_sat, &from_label, None, from, max.unwrap_or(false))?;
        send_grace_period(&app)?;

        let result = match network.as_str() {
            n if is_evm(n) => {
                let net = evm_network(&network)?;
                let fee = send.evm_fee.ok_or_else(|| "frais EVM manquants".to_string())?;
                api::send_evm(&dir, &password, net, &send.to, &send.amount, fee, profile_index).t_err()
            }
            "btc_testnet" | "btc_mainnet" => {
                let net = btc_network(&network)?;
                let fee_sat = send.fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
                api::send_btc(&dir, &password, net, &send.to, &send.amount, fee_sat, profile_index).t_err()
            }
            "sol_devnet" | "sol_mainnet" => {
                let net = sol_network(&network)?;
                api::send_sol(&dir, &password, net, &send.to, &send.amount, profile_index).t_err()
            }
            "zec_mainnet" => {
                let shown_fee = send.zec_fee.ok_or_else(|| "frais Zcash manquants".to_string())?;
                api::send_zec(&dir, &password, &send.to, &send.amount, shown_fee, profile_index).t_err()
            }
            "doge_mainnet" => {
                let shown_fee = send.doge_fee.ok_or_else(|| "frais Dogecoin manquants".to_string())?;
                api::send_doge(&dir, &password, &send.to, &send.amount, shown_fee, profile_index).t_err()
            }
            // Exactement l'envoi préparé et affiché (sorties, leurres, frais).
            "xmr_mainnet" => match send.xmr_plan.take() {
                Some(plan) => {
                    let sent = api::send_xmr(&dir, &password, plan).t_err();
                    // Envoi marqué en attente dans l'état : solde relu aussitôt.
                    XMR_SYNC_KICK.store(true, Ordering::SeqCst);
                    sent
                }
                None => Err(translate_error("envoi Monero non préparé")),
            },
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        };
        // Destinataire mémorisé SEULEMENT après une diffusion réussie (voir
        // `sent_recipients`). Un échec d'écriture du journal ne doit pas faire
        // croire à l'échec d'un envoi déjà parti.
        if result.is_ok() {
            let _ = sent_recipients::record_sent(&dir, &network, &send.to);
        }
        result
    })
    .await
}

/// Délai laissé, APRÈS la boîte de confirmation native et AVANT la signature,
/// pour annuler un envoi : l'interface affiche un compte à rebours avec
/// « Envoyer maintenant » et « Annuler ». Sans réponse, l'envoi part au bout
/// du délai. Imposé ici : l'interface ne peut que l'écourter ou annuler,
/// jamais l'éviter ; la seed n'est déverrouillée qu'après.
const SEND_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Envois en attente de leur délai : identifiant → canal de la décision
/// (`true` : envoyer maintenant, `false` : annuler).
#[derive(Default)]
struct SendGrace(std::sync::Mutex<std::collections::HashMap<u64, std::sync::mpsc::Sender<bool>>>);

#[derive(Clone, Serialize)]
struct SendCountdownDto {
    id: u64,
    seconds: u64,
}

/// Attend la fin du délai d'annulation (ou la décision de l'utilisateur).
/// `Err` si l'envoi est annulé.
fn send_grace_period(app: &tauri::AppHandle) -> Result<(), String> {
    grace_period(app, "Virement annulé pendant le délai d'annulation.")
}

/// Même délai pour un échange, après sa boîte de confirmation.
fn swap_grace_period(app: &tauri::AppHandle) -> Result<(), String> {
    grace_period(app, "Échange annulé pendant le délai d'annulation.")
}

fn grace_period(app: &tauri::AppHandle, cancelled: &str) -> Result<(), String> {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (sender, receiver) = std::sync::mpsc::channel();
    app.state::<SendGrace>().0.lock().unwrap_or_else(|p| p.into_inner()).insert(id, sender);
    let _ = app.emit("send-countdown", SendCountdownDto { id, seconds: SEND_GRACE.as_secs() });
    let decision = receiver.recv_timeout(SEND_GRACE);
    app.state::<SendGrace>().0.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
    let _ = app.emit("send-countdown-end", id);
    match decision {
        Ok(false) => Err(translate_error(cancelled)),
        // Délai écoulé, ou « Envoyer maintenant ».
        _ => Ok(()),
    }
}

/// Montant maximal envoyable (bouton « Max ») depuis le profil, frais du
/// moment déduits ; `token` : un jeton du registre (USDC compris), tout son
/// solde. Aperçu seulement : il est recalculé à la confirmation.
#[tauri::command]
async fn max_send_amount(network: String, token: Option<String>, profile_index: u32, fee_sat: Option<u64>, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let unknown = || translate_error("adresse du profil inconnue — déverrouillez le portefeuille");
        let cached = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>| cache.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned().ok_or_else(unknown);
        let (evm, sol) = app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned().ok_or_else(unknown)?;
        if let Some(token) = token {
            let owner = if is_evm(&network) { evm } else { sol };
            return api::token_max(&token, &network, &owner).t_err();
        }
        match network.as_str() {
            n if is_evm(n) => {
                let net = evm_network(n)?;
                let fee = api::evm_max_fee(net, Some(&evm), &evm).t_err()?;
                api::evm_max_native(net, &evm, fee).t_err()
            }
            "sol_devnet" | "sol_mainnet" => api::sol_max(sol_network(&network)?, &sol).t_err(),
            "btc_mainnet" | "btc_testnet" => {
                let address = if network == "btc_mainnet" { cached(&app.state::<ProfileBtcCache>().0)? } else { cached(&app.state::<ProfileBtcTestnetCache>().0)? };
                let fee_sat = fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
                api::btc_max(btc_network(&network)?, &address, fee_sat).t_err()
            }
            "zec_mainnet" => api::zec_max(&cached(&app.state::<ProfileZcashCache>().0)?).t_err(),
            "doge_mainnet" => api::doge_max(&cached(&app.state::<ProfileDogeCache>().0)?).t_err(),
            "xmr_mainnet" => {
                let keys = app.state::<MoneroKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(_, keys)| keys.clone()).ok_or_else(unknown)?;
                Ok(pgp_wallet_poc::monero::format_xmr(api::xmr_send_plan_max(&dir, &keys, None).t_err()?.amount))
            }
            "zec_shielded" => {
                let address = app.state::<ShieldedKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(address, _)| address.clone()).ok_or_else(unknown)?;
                api::zec_shielded_max(&dir, profile_index, &address).t_err()
            }
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        }
    })
    .await
}

/// Décision de l'utilisateur pendant le délai d'annulation d'un envoi.
#[tauri::command]
fn resolve_send_countdown(id: u64, send: bool, state: tauri::State<SendGrace>) {
    if let Some(sender) = state.0.lock().unwrap_or_else(|p| p.into_inner()).get(&id) {
        let _ = sender.send(send);
    }
}

/// Ligne de frais suivie, après une ligne vide, de la consigne de l'appareil
/// (la ligne de frais est déjà précédée d'un retour à la ligne dans la boîte).
fn fee_and_device_note(fee_line: Option<String>, device_note: Option<&str>) -> Option<String> {
    match (fee_line, device_note) {
        (Some(fee), Some(note)) => Some(format!("{fee}\n\n{note}")),
        (None, Some(note)) => Some(format!("\n{note}")),
        (fee, None) => fee,
    }
}

/// Ce qu'un envoi a validé et fait confirmer : exactement ce qui sera signé.
struct ConfirmedSend {
    to: String,
    amount: String,
    evm_fee: Option<api::EvmFee>,
    fee_sat: Option<u64>,
    /// Frais Zcash affichés (plafond à l'envoi).
    zec_fee: Option<u64>,
    /// Envoi Monero préparé (sorties, leurres, frais) : signé tel qu'affiché.
    xmr_plan: Option<pgp_wallet_poc::monero::SendPlan>,
    /// Frais Dogecoin affichés (plafond à l'envoi).
    doge_fee: Option<u64>,
}

/// Adresses (et clés de visualisation Monero) du compte qui envoie, connues
/// sans mot de passe : préparation de l'envoi AVANT la boîte de confirmation.
#[derive(Default)]
struct SendFrom<'a> {
    evm: Option<&'a str>,
    sol: Option<&'a str>,
    zec: Option<&'a str>,
    xmr: Option<&'a pgp_wallet_poc::monero::ViewKeys>,
    doge: Option<&'a str>,
    btc: Option<&'a str>,
}

/// Validation, avertissements et boîte de confirmation native, communs aux
/// envois du portefeuille et des comptes matériels (`device_note` : consigne
/// ajoutée à la boîte pour la confirmation sur l'appareil). `Err` si refusé.
#[allow(clippy::too_many_arguments)]
fn confirm_send(
    app: &tauri::AppHandle,
    dir: &std::path::Path,
    network: &str,
    to: &str,
    amount: &str,
    fee_sat: Option<u64>,
    from_label: &str,
    device_note: Option<&str>,
    from: SendFrom<'_>,
    max: bool,
) -> Result<ConfirmedSend, String> {
    // Réseau validé AVANT la boîte de confirmation (22ᵉ passage) : un réseau
    // inconnu était jusqu'ici affiché tel quel (texte libre du frontend) dans
    // la boîte, l'erreur n'arrivant qu'après. Adresse et montant remplacés par
    // leur forme canonique, utilisée pour l'affichage ET la signature (voir
    // `canonical_address_input`/`api::canonical_amount`).
    let coin = match network {
        n if is_evm(n) => "evm",
        "btc_testnet" | "btc_mainnet" => "btc",
        "sol_devnet" | "sol_mainnet" => "sol",
        "zec_mainnet" => "zec",
        "xmr_mainnet" => "xmr",
        "doge_mainnet" => "doge",
        other => return Err(translate_error(&format!("réseau inconnu : {other}"))),
    };
    let to = canonical_address_input(to)?;
    let unknown_profile = || translate_error("adresse du profil inconnue — déverrouillez le portefeuille");
    // « Max » : montant recalculé MAINTENANT (solde moins les frais du moment,
    // mêmes règles que l'envoi), affiché dans la boîte puis signé tel quel.
    let mut evm_fee = None;
    let mut xmr_plan = None;
    let amount = if max {
        match coin {
            "evm" => {
                let net = evm_network(network)?;
                let fee = api::evm_max_fee(net, from.evm, &to).t_err()?;
                evm_fee = Some(fee);
                api::evm_max_native(net, from.evm.ok_or_else(unknown_profile)?, fee).t_err()?
            }
            "sol" => api::sol_max(sol_network(network)?, from.sol.ok_or_else(unknown_profile)?).t_err()?,
            "btc" => {
                let fee_sat = fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
                api::btc_max(btc_network(network)?, from.btc.ok_or_else(unknown_profile)?, fee_sat).t_err()?
            }
            "zec" => api::zec_max(from.zec.ok_or_else(unknown_profile)?).t_err()?,
            "doge" => api::doge_max(from.doge.ok_or_else(unknown_profile)?).t_err()?,
            _ => {
                let plan = api::xmr_send_plan_max(dir, from.xmr.ok_or_else(unknown_profile)?, Some(&to)).t_err()?;
                let amount = pgp_wallet_poc::monero::format_xmr(plan.amount);
                xmr_plan = Some(plan);
                amount
            }
        }
    } else {
        amount.to_string()
    };
    let amount = match coin {
        "zec" => api::canonical_zec_amount(&amount).t_err()?,
        "doge" => api::canonical_doge_amount(&amount).t_err()?,
        "xmr" => api::canonical_xmr_amount(&amount).t_err()?,
        _ => api::canonical_amount(coin, &amount).t_err()?,
    };

    // Frais affichés dans la boîte de dialogue native (voir sa doc : "montre
    // exactement ce que le backend a compris") : choisis par l'utilisateur pour
    // Bitcoin ; pour EVM, prix du gas lu MAINTENANT et utilisé tel quel pour
    // signer — avant, il était lu auprès du nœud APRÈS la confirmation, jamais
    // affiché (voir `api::evm_gas_price_for_confirmation`).
    // Frais EVM complets (prix, limite de gas — estimée là où elle n'est pas
    // fixe —, frais de publication OP Stack), affichés puis signés tels quels.
    let evm_fee = match (coin, evm_fee) {
        ("evm", None) => Some(api::evm_transfer_fee_for_confirmation(evm_network(network)?, from.evm, &to, &amount).t_err()?),
        (_, fee) => fee,
    };
    // Solde suffisant (montant + frais) vérifié AVANT la boîte : jamais
    // confirmer un envoi refusé juste après.
    match (coin, evm_fee, from.evm, from.sol) {
        ("evm", Some(fee), Some(from), _) => api::ensure_evm_transfer_funds(evm_network(network)?, from, &amount, fee).t_err()?,
        ("sol", _, _, Some(from)) => api::ensure_sol_transfer_funds(sol_network(network)?, from, &amount).t_err()?,
        _ => {}
    }
    // Bitcoin (portefeuille) : toutes les sorties couvrent montant et frais
    // choisis. Comptes matériels : leurs adresses sont relues par l'appareil.
    if let ("btc", Some(from), Some(fee)) = (coin, from.btc, fee_sat) {
        api::ensure_btc_transfer_funds(btc_network(network)?, from, &amount, fee).t_err()?;
    }
    // Zcash : destinataire vérifié, sorties choisies et frais ZIP-317
    // calculés MAINTENANT, affichés, puis jamais dépassés à l'envoi.
    let zec_plan = match coin {
        "zec" => {
            let from = from.zec.ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
            Some(api::zec_send_plan(from, &to, &amount).t_err()?)
        }
        _ => None,
    };
    // Dogecoin : destinataire vérifié, sorties choisies et vérifiées sur leurs
    // transactions d'origine (montants), frais calculés MAINTENANT, affichés,
    // puis jamais dépassés à l'envoi.
    let doge_plan = match coin {
        "doge" => {
            let from = from.doge.ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
            Some(api::doge_send_plan(from, &to, &amount).t_err()?)
        }
        _ => None,
    };
    // Monero : destinataire vérifié, sorties choisies, leurres tirés et frais
    // calculés MAINTENANT (clés de visualisation, sans la seed) ; c'est cet
    // envoi-là, inchangé, qui sera signé.
    let xmr_plan = match (coin, xmr_plan) {
        ("xmr", None) => {
            let keys = from.xmr.ok_or_else(unknown_profile)?;
            Some(api::xmr_send_plan(dir, keys, &to, &amount).t_err()?)
        }
        (_, plan) => plan,
    };
    // Adresse refusée AVANT la confirmation si elle est mal formée (EVM/BTC :
    // jusqu'ici seulement au moment de signer) ou, pour Solana, si ce n'est
    // pas un portefeuille (voir `api::check_solana_recipient`). Puis état de
    // l'adresse sur la blockchain, pour les avertissements de la boîte.
    let activity = match coin {
        "evm" => {
            api::validate_evm_recipient(&to).t_err()?;
            api::evm_recipient_activity(&to, evm_network(network)?).ok()
        }
        "btc" => {
            let net = btc_network(network)?;
            api::validate_btc_recipient(&to, net).t_err()?;
            api::btc_recipient_activity(&to, net).ok()
        }
        // Adresse déjà vérifiée par la préparation de l'envoi.
        "zec" => api::zec_recipient_activity(&to).ok(),
        "doge" => api::doge_recipient_activity(&to).ok(),
        // Adresse vérifiée par la préparation ; aucune activité lisible
        // (adresses et montants invisibles sur la chaîne Monero).
        "xmr" => None,
        _ => {
            let net = sol_network(network)?;
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
        "zec" => zec_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} ZEC (ZIP-317)", lang("Frais", "Fee"), pgp_wallet_poc::zcash::format_zec(plan.fee));
            if plan.change > 0 {
                let change = pgp_wallet_poc::zcash::format_zec(plan.change);
                line.push_str(lang(&format!("
Monnaie rendue à votre adresse : {change} ZEC"), &format!("
Change returned to your address: {change} ZEC")));
            }
            line
        }),
        "doge" => doge_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} DOGE", lang("Frais", "Fee"), pgp_wallet_poc::doge::format_doge(plan.fee));
            if plan.change > 0 {
                let change = pgp_wallet_poc::doge::format_doge(plan.change);
                line.push_str(lang(&format!("\nMonnaie rendue à votre adresse : {change} DOGE"), &format!("\nChange returned to your address: {change} DOGE")));
            }
            line
        }),
        "xmr" => xmr_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} XMR", lang("Frais", "Fee"), pgp_wallet_poc::monero::format_xmr(plan.fee));
            if plan.change > 0 {
                let change = pgp_wallet_poc::monero::format_xmr(plan.change);
                line.push_str(lang(
                    &format!("
Monnaie rendue à votre adresse : {change} XMR (dépensable après 10 confirmations, ≈ 20 min)"),
                    &format!("
Change returned to your address: {change} XMR (spendable after 10 confirmations, ≈ 20 min)"),
                ));
            }
            line
        }),
        _ => evm_fee.map(|fee| evm_fee_line_for(fee, network_unit(network))),
    };
    let fee_line = fee_and_device_note(fee_line, device_note);

    let warning = send_warnings(app, dir, network, coin, &to, activity);
    let mut amount_line = format!("{amount} {}", network_unit(network));
    if max {
        amount_line.push_str(lang(" (maximum, frais déduits)", " (maximum, fees deducted)"));
    }
    if !confirm_transaction_native(app, network, &to, &amount_line, from_label, fee_line.as_deref(), warning.as_deref(), None) {
        return Err(translate_error("Virement annulé (confirmation refusée)."));
    }
    Ok(ConfirmedSend { to, amount, evm_fee, fee_sat, zec_fee: zec_plan.map(|plan| plan.fee), xmr_plan, doge_fee: doge_plan.map(|plan| plan.fee) })
}

// --- Comptes Ledger / Trezor (core/src/hardware.rs) ----------------------------
// Commandes qui parlent à l'appareil ou au réseau exécutées via `run_blocking` :
// l'appareil attend la confirmation physique de l'utilisateur, parfois
// longtemps, et la fenêtre ne doit pas se figer pendant ce temps.

/// Compte matériel tel qu'affiché : l'empreinte et la clé publique étendue
/// Bitcoin restent côté Rust (inutiles à l'affichage).
#[derive(Serialize)]
struct HardwareAccountDto {
    id: u32,
    label: String,
    /// "ledger" ou "trezor".
    device: String,
    network: String,
    address: String,
    path: String,
}

impl From<hardware::HardwareAccount> for HardwareAccountDto {
    fn from(a: hardware::HardwareAccount) -> Self {
        Self { id: a.id, label: a.label, device: a.device, network: a.network, address: a.address, path: a.path }
    }
}

fn hardware_account(dir: &std::path::Path, id: u32) -> Result<hardware::HardwareAccount, String> {
    hardware::list_accounts(dir).into_iter().find(|a| a.id == id).ok_or_else(|| translate_error("compte matériel introuvable"))
}

#[tauri::command]
fn hardware_accounts(app: tauri::AppHandle) -> Result<Vec<HardwareAccountDto>, String> {
    Ok(hardware::list_accounts(&data_dir(&app)?).into_iter().map(Into::into).collect())
}

/// Exécute `work` sur un fil réservé aux opérations bloquantes (attente de la
/// confirmation sur l'appareil, appels réseau `reqwest::blocking`, boîte de
/// dialogue native) : ni sur le fil principal (fenêtre figée), ni directement
/// dans une tâche asynchrone — ce que fait `#[tauri::command(async)]` sur une
/// fonction synchrone, où `reqwest::blocking` panique et la commande reste
/// alors sans réponse (constaté en réel sur le solde d'un compte Ledger).
async fn run_blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work).await.map_err(|e| format!("opération interrompue : {e}"))?
}

#[tauri::command]
async fn hardware_connect(device: String, network: String, label: String, app: tauri::AppHandle) -> Result<HardwareAccountDto, String> {
    run_blocking(move || hardware::connect_device(&data_dir(&app)?, &device, &network, &label).map(Into::into).t_err()).await
}

#[tauri::command]
fn hardware_remove(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    hardware::remove_account(&data_dir(&app)?, id).t_err()
}

#[tauri::command]
async fn hardware_verify_address(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || hardware::verify_address_on_device(&data_dir(&app)?, id).t_err()).await
}

/// Même format que `get_balance` (Bitcoin : réception + monnaie).
#[tauri::command]
async fn hardware_balance(id: u32, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let network = hardware_account(&dir, id)?.network;
        let amount = hardware::balance(&dir, id).t_err()? as f64;
        Ok(match network.as_str() {
            n if is_evm(n) => format!("{:.6}", amount / 1e18),
            "btc_testnet" | "btc_mainnet" => format!("{:.8}", amount / 1e8),
            _ => format!("{:.9}", amount / 1e9),
        })
    })
    .await
}

#[tauri::command]
async fn hardware_estimate_btc_fees(id: u32, app: tauri::AppHandle) -> Result<BtcFeeEstimateDto, String> {
    run_blocking(move || {
        let estimate = hardware::estimate_btc_fees(&data_dir(&app)?, id).t_err()?;
        Ok(BtcFeeEstimateDto { fast_sat: estimate.fast_sat, medium_sat: estimate.medium_sat, slow_sat: estimate.slow_sat })
    })
    .await
}

/// Envoi depuis un compte matériel : mêmes validations, avertissements et boîte
/// native qu'un envoi du portefeuille (aucun mot de passe : rien à
/// déverrouiller ici), puis revue et confirmation sur l'écran de l'appareil.
#[tauri::command]
async fn hardware_send(id: u32, to: String, amount: String, fee_sat: Option<u64>, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let account = hardware_account(&dir, id)?;
        let network = account.network.clone();
        let device = if account.device == "trezor" { "Trezor" } else { "Ledger" };
        let note = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("Signed on the {device}: check on ITS screen that the recipient and amount are identical, then confirm there.")
        } else {
            format!("Signature sur le {device} : vérifiez sur SON écran que le destinataire et le montant sont identiques, puis confirmez-y.")
        };
        let from = SendFrom { evm: Some(&account.address), sol: Some(&account.address), ..SendFrom::default() };
        let send = confirm_send(&app, &dir, &network, &to, &amount, fee_sat, &format!("{device} — {}", account.label), Some(&note), from, false)?;
        send_grace_period(&app)?;
        let result = match network.as_str() {
            n if is_evm(n) => {
                let fee = send.evm_fee.ok_or_else(|| "frais EVM manquants".to_string())?;
                hardware::send_evm(&dir, id, &network, &send.to, &send.amount, fee).t_err()
            }
            "btc_testnet" | "btc_mainnet" => {
                let fee_sat = send.fee_sat.ok_or_else(|| "frais Bitcoin manquants (choisis une vitesse d'envoi)".to_string())?;
                hardware::send_btc(&dir, id, &network, &send.to, &send.amount, fee_sat).t_err()
            }
            "sol_devnet" | "sol_mainnet" => hardware::send_sol(&dir, id, &network, &send.to, &send.amount).t_err(),
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        };
        if result.is_ok() {
            let _ = sent_recipients::record_sent(&dir, &network, &send.to);
        }
        result
    })
    .await
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
async fn get_swap_quote(
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    protocol: pgp_wallet_poc::swap_routes::Protocol,
) -> Result<SwapQuoteDto, String> {
    run_blocking(move || {
        let (protocol, from, to) = cross_chain_pair(&from_coin, &from_network, &to_coin, &to_network, protocol)?;
        let quote = api::get_swap_quote(protocol, from, to, &amount, &destination).t_err()?;
        Ok(SwapQuoteDto {
            inbound_address: quote.inbound_address,
            memo: quote.memo,
            expected_amount_out: format_1e8(quote.expected_amount_out),
            total_fees: quote.total_fees.map(format_1e8),
        })
    })
    .await
}

type CrossChainPair = (
    &'static pgp_wallet_poc::thorchain_rpc::CrossChain,
    &'static pgp_wallet_poc::thorchain_rpc::ThorAsset,
    &'static pgp_wallet_poc::thorchain_rpc::ThorAsset,
);

/// Le fournisseur choisi dans l'interface relie-t-il directement ces deux
/// cryptos (voir `swap_routes::direct_all`) ?
fn provider_links(protocol: pgp_wallet_poc::swap_routes::Protocol, from_coin: &str, from_network: &str, to_coin: &str, to_network: &str) -> bool {
    use pgp_wallet_poc::swap_routes;
    swap_routes::find(from_coin, from_network)
        .zip(swap_routes::find(to_coin, to_network))
        .is_some_and(|(f, t)| swap_routes::direct_all(f, t).contains(&protocol))
}

/// Paire d'échange entre réseaux désignée par l'interface, avec le
/// fournisseur choisi (THORChain ou Maya) : refusée s'il ne la relie pas.
fn cross_chain_pair(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
    protocol: pgp_wallet_poc::swap_routes::Protocol,
) -> Result<CrossChainPair, String> {
    let protocol = protocol
        .cross_chain()
        .filter(|_| provider_links(protocol, from_coin, from_network, to_coin, to_network))
        .ok_or_else(|| translate_error("échange non disponible entre ces deux cryptos"))?;
    Ok((
        protocol,
        api::cross_chain_asset(protocol, from_coin, from_network).t_err()?,
        api::cross_chain_asset(protocol, to_coin, to_network).t_err()?,
    ))
}

/// Frais réseau maximum d'un échange depuis un réseau EVM : dépôt, plus les
/// autorisations préalables, plus les frais de publication sur Ethereum (Base).
fn evm_swap_fee_line(fees: &api::EvmSwapFees, symbol: &str) -> Result<String, String> {
    let total = fees.max_total().t_err()? as f64 / 1e18;
    let gwei = fees.deposit.gas_price as f64 / 1e9;
    let l1 = (fees.deposit.l1_fee + fees.approve.l1_fee * fees.approvals as u128) as f64 / 1e18;
    let mut line = lang(
        &format!("Frais réseau maximum : {total:.8} {symbol} ({gwei:.4} gwei)"),
        &format!("Maximum network fee: {total:.8} {symbol} ({gwei:.4} gwei)"),
    )
    .to_string();
    if fees.approvals > 0 {
        line.push_str(lang(", autorisation comprise", ", approval included"));
    }
    if l1 > 0.0 {
        line.push_str(lang(&format!(", dont ≈ {l1:.8} {symbol} de publication sur Ethereum"), &format!(", incl. ≈ {l1:.8} {symbol} for posting to Ethereum")));
    }
    Ok(line)
}

/// Actifs (`coin@network`) que THORChain et Maya n'échangent pas en ce moment
/// (réseau suspendu : incident, maintenance).
#[derive(Serialize)]
struct SwapHaltsDto {
    thorchain: Vec<String>,
    maya: Vec<String>,
}

/// Lu à l'ouverture de la fenêtre « Convertir » : un fournisseur suspendu
/// pour l'échange choisi n'y est plus proposé par défaut. Lecture en échec :
/// rien de marqué (le devis dira alors la suspension en clair).
#[tauri::command]
async fn swap_halts() -> Result<SwapHaltsDto, String> {
    use pgp_wallet_poc::thorchain_rpc::{CrossChain, MAYA, THORCHAIN};
    run_blocking(|| {
        let keys = |protocol: &CrossChain| -> Vec<String> {
            match protocol.halted_assets() {
                Ok(assets) => assets.iter().map(|a| format!("{}@{}", a.coin, a.network)).collect(),
                Err(e) => {
                    eprintln!("état des réseaux {} : {e:#}", protocol.name);
                    Vec::new()
                }
            }
        };
        let (thorchain, maya) = std::thread::scope(|s| {
            let thorchain = s.spawn(|| keys(&THORCHAIN));
            let maya = keys(&MAYA);
            (thorchain.join().unwrap_or_default(), maya)
        });
        Ok(SwapHaltsDto { thorchain, maya })
    })
    .await
}

#[derive(Serialize)]
struct SwapPairDto {
    from_coin: &'static str,
    from_network: &'static str,
    to_coin: &'static str,
    to_network: &'static str,
    /// Protocole de la (première) étape.
    protocol: pgp_wallet_poc::swap_routes::Protocol,
    /// Paire directe : tous les fournisseurs possibles, le préféré d'abord
    /// (vide pour un échange en deux étapes).
    protocols: Vec<pgp_wallet_poc::swap_routes::Protocol>,
    /// Frais d'affiliation de l'app pour chacun de `protocols` (points de
    /// base) : 0 depuis Bitcoin ou Zcash via THORChain ou Maya sans nom court.
    fees_bps: Vec<u32>,
    /// Échange en deux étapes : crypto intermédiaire et protocole de la
    /// seconde étape (`None` pour un échange direct).
    via: Option<pgp_wallet_poc::swap_routes::SwapAsset>,
    then_protocol: Option<pgp_wallet_poc::swap_routes::Protocol>,
}

/// Paires d'échange possibles, directes ou en deux étapes (voir
/// `core/src/swap_routes.rs`) : ce que la fenêtre « Convertir » propose. Les
/// commandes d'échange n'acceptent qu'une paire directe : une étape à la fois.
/// Asynchrone : les frais affichés dépendent du nom d'affiliation, relu sur
/// THORChain et Maya (voir `thorchain_rpc::CrossChain::affiliate_for`).
#[tauri::command]
async fn swap_pairs() -> Vec<SwapPairDto> {
    run_blocking(|| Ok::<_, String>(swap_pair_dtos())).await.unwrap_or_default()
}

fn swap_pair_dtos() -> Vec<SwapPairDto> {
    pgp_wallet_poc::swap_routes::routes()
        .into_iter()
        .map(|(from, to, route)| {
            let protocols = if route.via.is_none() { pgp_wallet_poc::swap_routes::direct_all(from, to) } else { Vec::new() };
            SwapPairDto {
                from_coin: from.coin,
                from_network: from.network,
                to_coin: to.coin,
                to_network: to.network,
                protocol: route.first,
                fees_bps: protocols.iter().map(|p| pgp_wallet_poc::swap_routes::affiliate_fee_bps(*p, from)).collect(),
                protocols,
                via: route.via.map(|(via, _)| via),
                then_protocol: route.via.map(|(_, second)| second),
            }
        })
        .collect()
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
#[allow(clippy::too_many_arguments)]
fn confirm_swap_native(
    app: &tauri::AppHandle,
    protocol: &str,
    from_label: &str,
    amount: &str,
    expected_out: &str,
    to_symbol: &str,
    pay_to: &str,
    router: Option<&str>,
    final_destination: &str,
    network_fee_line: Option<&str>,
    approval_line: Option<&str>,
    affiliate: bool,
    own_destination: Option<&str>,
) -> bool {
    let network_fee_line = network_fee_line.map(|f| format!("{f}\n")).unwrap_or_default();
    // Depuis Bitcoin ou Zcash sans nom court : aucun frais pour l'app (voir
    // `thorchain_rpc::CrossChain::charges_affiliate`).
    let affiliate_en = if affiliate { ", plus a 0.80% affiliate fee" } else { ", with no affiliate fee for this app on this swap" };
    let affiliate_fr = if affiliate { ", plus 0,80% de frais d'affiliation" } else { ", sans frais d'affiliation pour cette app sur cet échange" };
    let approval_line = approval_line.map(|a| format!("{a}\n")).unwrap_or_default();
    let from_label = dialog_label(from_label);
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let vault_line = match (router, english) {
        (Some(router), true) => format!("Actual destination: router contract {router}\n({protocol} vault targeted: {pay_to})\n"),
        (Some(router), false) => format!("Destination réelle : contrat routeur {router}\n(coffre {protocol} visé : {pay_to})\n"),
        (None, true) => format!("Actual destination: {pay_to}\n"),
        (None, false) => format!("Destination réelle : {pay_to}\n"),
    };
    // Adresse d'un profil de ce portefeuille (adresses dérivées côté Rust) :
    // nommé, à la place de « vérifiez qu'il s'agit bien de votre adresse ».
    let arrival_line = if final_destination.is_empty() {
        String::new()
    } else if let Some(label) = own_destination {
        if english {
            format!("Funds will arrive at: {final_destination}\n(your profile \"{label}\" — an address of this wallet)\n")
        } else {
            format!("Les fonds arriveront sur : {final_destination}\n(votre profil « {label} » — adresse de ce portefeuille)\n")
        }
    } else if english {
        format!("Funds will arrive at: {final_destination}\n(verify this is really your own address)\n")
    } else {
        format!("Les fonds arriveront sur : {final_destination}\n(vérifiez qu'il s'agit bien de votre propre adresse)\n")
    };
    let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "Swap via {protocol} (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nSending: {amount}\nExpected to receive: ~{expected_out} {to_symbol}\n{vault_line}{arrival_line}{approval_line}{network_fee_line}\nIncludes {protocol}'s own network/liquidity fees{affiliate_en}.\nThis is irreversible, and once sent this app can no longer track or reverse it.\n\nConfirm this swap?"
        )
    } else {
        format!(
            "Échange via {protocol} (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {amount}\nRéception attendue : ~{expected_out} {to_symbol}\n{vault_line}{arrival_line}{approval_line}{network_fee_line}\nInclut les frais propres à {protocol} (réseau/liquidité){affiliate_fr}.\nC'est irréversible, et une fois envoyé cette app ne peut plus ni suivre ni annuler l'opération.\n\nConfirmer cet échange ?"
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
#[allow(clippy::too_many_arguments)]
async fn swap_transaction(
    password: String,
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    protocol: pgp_wallet_poc::swap_routes::Protocol,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (protocol, from, to) = cross_chain_pair(&from_coin, &from_network, &to_coin, &to_network, protocol)?;

        // Formes canoniques, affichées ET utilisées pour le devis et la signature
        // (voir `send_transaction`).
        let amount = api::canonical_swap_amount(from, &amount).t_err()?;
        let destination = canonical_address_input(&destination)?;

        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Devis obtenu ICI, juste avant la confirmation, jamais mis en cache
        // (adresse de vault THORChain vivante, voir thorchain_rpc::SwapQuote).
        let quote = api::get_swap_quote(protocol, from, to, &amount, &destination).t_err()?;
        let amount_line = format!("{amount} {}", from.symbol);

        // Frais réseau affichés AVANT confirmation (et, pour un réseau EVM, prix
        // du gas réutilisé tel quel pour signer — voir
        // `api::evm_gas_price_for_confirmation`). Réseaux principaux seulement :
        // les pools THORChain n'existent pas sur les réseaux de test.
        let evm_net = wallet_flow::evm_network(from.network);
        let evm_gas_price = match evm_net {
            Some(net) => Some(api::evm_gas_price_for_confirmation(net).t_err()?),
            None => None,
        };
        let mut approval_line = None;
        let mut zec_fee = None;
        let network_fee_line = match (evm_net, evm_gas_price) {
            (Some(net), Some(gas_price)) => {
                let owner = app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(evm, _)| evm.clone());
                let fees = api::evm_swap_fees(net, from, &quote, &amount, gas_price, owner.as_deref()).t_err()?;
                if fees.approvals > 0 {
                    let router = quote.router.as_deref().unwrap_or("?");
                    approval_line = Some(lang(
                        &format!("Autorisation préalable (transaction séparée) : le routeur {router} pourra prélever exactement {amount_line}, une seule fois."),
                        &format!("Prior approval (separate transaction): router {router} will be allowed to take exactly {amount_line}, once."),
                    ).to_string());
                }
                Some(evm_swap_fee_line(&fees, net.native_symbol)?)
            }
            _ if from.network == "sol_mainnet" => Some(lang("Frais réseau : 0,000005 SOL", "Network fee: 0.000005 SOL").to_string()),
            _ if from.network == "zec_mainnet" => {
                let from_zec = app
                    .state::<ProfileZcashCache>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&profile_index)
                    .cloned()
                    .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
                let plan = api::zec_swap_plan(&from_zec, &quote, &amount).t_err()?;
                zec_fee = Some(plan.fee);
                let fee = pgp_wallet_poc::zcash::format_zec(plan.fee);
                Some(lang(&format!("Frais réseau Zcash : au plus {fee} ZEC (ZIP-317)"), &format!("Zcash network fee: at most {fee} ZEC (ZIP-317)")).to_string())
            }
            _ => Some(
                lang(
                    &format!("Frais réseau : vitesse moyenne, au plus {} sat/vB", api::BTC_SWAP_MAX_FEE_RATE_SAT_VB),
                    &format!("Network fee: medium speed, at most {} sat/vB", api::BTC_SWAP_MAX_FEE_RATE_SAT_VB),
                )
                .to_string(),
            ),
        };

        let router_for_source = if evm_net.is_some() { quote.router.as_deref() } else { None };
        let own_destination = own_profile_label(&app, &dir, to.network, &destination);
        if !confirm_swap_native(
            &app,
            protocol.name,
            &from_label,
            &amount_line,
            &format_1e8(quote.expected_amount_out),
            to.symbol,
            &quote.inbound_address,
            router_for_source,
            &destination,
            network_fee_line.as_deref(),
            approval_line.as_deref(),
            quote.affiliate.is_some(),
            own_destination.as_deref(),
        ) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(&app)?;

        // Devis RE-lu après la confirmation (la boîte native bloque un temps
        // arbitraire, pendant lequel le vault peut tourner), mais refusé s'il ne
        // correspond plus à ce qui a été AFFICHÉ — voir
        // `api::refresh_swap_quote_matching`.
        let quote = api::refresh_swap_quote_matching(protocol, from, to, &amount, &destination, &quote).t_err()?;

        match (from.network, evm_net, evm_gas_price) {
            ("sol_mainnet", _, _) => api::send_swap_sol(&dir, &password, sol_network("sol_mainnet")?, &quote, &amount, profile_index).t_err(),
            ("btc_mainnet", _, _) => api::send_swap_btc(&dir, &password, btc_network("btc_mainnet")?, &quote, &amount, profile_index).t_err(),
            ("zec_mainnet", _, _) => {
                let shown_fee = zec_fee.ok_or_else(|| "frais Zcash manquants".to_string())?;
                api::send_swap_zec(&dir, &password, &quote, &amount, shown_fee, profile_index).t_err()
            }
            (_, Some(net), Some(gas_price)) if from.contract.is_some() => {
                api::send_swap_erc20(&dir, &password, net, from, &quote, &amount, gas_price, profile_index).t_err()
            }
            (_, Some(net), Some(gas_price)) => api::send_swap_evm(&dir, &password, net, &quote, &amount, gas_price, profile_index).t_err(),
            _ => Err(translate_error(&format!("envoi de swap non pris en charge pour cet actif : {from_coin}"))),
        }
    })
    .await
}

// --- Swap (Jupiter) ----------------------------------------------------------
// Même chaîne uniquement (SOL <-> USDC), contrairement au swap cross-chain
// THORChain ci-dessus — voir core/src/jupiter_rpc.rs pour le contexte
// complet, notamment pourquoi la transaction elle-même n'est pas
// reconstruite à la main ici (seulement vérifiée puis signée).

const JUPITER_DEFAULT_SLIPPAGE_BPS: u32 = 50; // 0,50 %

/// Paire Jupiter désignée par l'interface (réseau Solana) : refusée si Jupiter
/// ne la relie pas (voir `swap_routes::direct_all`).
fn jupiter_pair(from_coin: &str, to_coin: &str) -> Result<(), String> {
    if provider_links(pgp_wallet_poc::swap_routes::Protocol::Jupiter, from_coin, "sol_mainnet", to_coin, "sol_mainnet") {
        Ok(())
    } else {
        Err(translate_error("échange non disponible entre ces deux cryptos"))
    }
}

fn format_native_amount(amount: u64, decimals: u32) -> String {
    format!("{:.*}", decimals as usize, amount as f64 / 10f64.powi(decimals as i32))
}

#[tauri::command]
async fn get_jupiter_quote(from_coin: String, to_coin: String, amount: String) -> Result<String, String> {
    run_blocking(move || {
        jupiter_pair(&from_coin, &to_coin)?;
        let quote = api::get_jupiter_quote(&from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS).t_err()?;
        Ok(format_native_amount(quote.out_amount, u32::from(api::jupiter_decimals(&to_coin).t_err()?)))
    })
    .await
}

/// Confirmation native spécifique à Jupiter : contrairement à THORChain, ce
/// n'est pas un protocole cross-chain, mais reste un protocole EXTERNE non
/// audité par cette app, et la transaction elle-même est construite par
/// Jupiter (voir core/src/jupiter_rpc.rs), pas par cette app — simulée et
/// vérifiée (effets sur les comptes de l'utilisateur, voir
/// `api::check_swap_effects`) AVANT d'être signée, jamais reconstruite. Le
/// texte disait encore "vérifiée (payeur de frais)", resté de l'avant-21ᵉ
/// passage : il sous-décrivait la protection réelle.
fn confirm_jupiter_swap_native(app: &tauri::AppHandle, from_label: &str, amount: &str, expected_out: &str, to_symbol: &str, with_fee: bool) -> bool {
    let from_label = dialog_label(from_label);
    // Sans compte de frais existant pour ces jetons, l'échange se fait sans
    // frais d'affiliation (voir `api::jupiter_fee_mint`) : la boîte le dit.
    let fee_line = match (with_fee, UI_LANG_IS_ENGLISH.load(Ordering::Relaxed)) {
        (true, true) => "Includes a 0.80% affiliate fee",
        (true, false) => "Inclut 0,80% de frais d'affiliation",
        (false, true) => "No affiliate fee on this pair",
        (false, false) => "Sans frais d'affiliation pour cette paire",
    };
    let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!(
            "Swap via Jupiter (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nSending: {amount}\nExpected to receive: ~{expected_out} {to_symbol}\n{fee_line}\n\nThe swap transaction itself is built by Jupiter, not by this app. Before signing, it is simulated and refused if it would take more than the amount sent plus network fees, or deliver less than the amount shown (0.5% slippage).\nThis is irreversible.\n\nConfirm this swap?"
        )
    } else {
        format!(
            "Échange via Jupiter (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {amount}\nRéception attendue : ~{expected_out} {to_symbol}\n{fee_line}\n\nLa transaction de swap elle-même est construite par Jupiter, pas par cette app. Avant signature, elle est simulée et refusée si elle prenait plus que le montant envoyé et les frais réseau, ou livrait moins que le montant affiché (glissement de 0,5 %).\nC'est irréversible.\n\nConfirmer cet échange ?"
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
async fn jupiter_swap_transaction(
    password: String,
    from_coin: String,
    to_coin: String,
    amount: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let network = sol_network("sol_mainnet")?; // Jupiter mainnet uniquement (pas de liquidité fiable en devnet)
        jupiter_pair(&from_coin, &to_coin)?;
        // Forme canonique, affichée ET signée (voir `send_transaction`).
        let amount = api::canonical_jupiter_amount(&from_coin, &amount).t_err()?;

        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Devis relu ICI, juste avant la confirmation — jamais celui affiché dans
        // l'aperçu du frontend, potentiellement déjà légèrement périmé.
        let quote = api::get_jupiter_quote(&from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS).t_err()?;
        let out_amount = quote.out_amount;
        let expected_out = format_native_amount(out_amount, u32::from(api::jupiter_decimals(&to_coin).t_err()?));
        let amount_line = format!("{amount} {}", api::jupiter_symbol(&from_coin).t_err()?);

        if !confirm_jupiter_swap_native(&app, &from_label, &amount_line, &expected_out, api::jupiter_symbol(&to_coin).t_err()?, quote.fee_mint.is_some()) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(&app)?;

        // `out_amount` = la sortie AFFICHÉE ci-dessus : la transaction réellement
        // signée devra la livrer (au glissement près), vérifié par simulation.
        api::send_jupiter_swap(&dir, &password, network, &from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS, out_amount, quote.fee_mint, profile_index)
            .t_err()
    })
    .await
}

// --- Swap (CoW Protocol) -----------------------------------------------------
// Même réseau EVM : ordre signé (EIP-712) construit et vérifié côté Rust (voir
// core/src/cow.rs), exécuté ensuite par CoW. Aucune transaction d'échange :
// seule une éventuelle autorisation du jeton vendu part sur le réseau.

/// Paire CoW désignée par l'interface : refusée si CoW ne la relie pas (voir
/// `swap_routes::direct_all`).
fn cow_pair(network: &str, from_coin: &str, to_coin: &str) -> Result<(cow::CowToken, cow::CowToken), String> {
    if !provider_links(pgp_wallet_poc::swap_routes::Protocol::Cow, from_coin, network, to_coin, network) {
        return Err(translate_error("échange non disponible entre ces deux cryptos"));
    }
    api::cow_tokens(network, from_coin, to_coin).t_err()
}

/// Adresse EVM publique du profil (mémorisée au déverrouillage) : vendeur ET
/// destinataire d'un ordre CoW. L'envoi revérifie qu'elle est bien celle de
/// la clé qui signe (`api::send_cow_swap`).
fn profile_evm_address(app: &tauri::AppHandle, profile_index: u32) -> Result<String, String> {
    app.state::<ProfileAddressCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&profile_index)
        .map(|(evm, _)| evm.clone())
        .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))
}

/// Montant affiché : 8 décimales au plus, TRONQUÉ (un minimum garanti n'est
/// jamais affiché au-dessus de sa vraie valeur).
fn cow_amount(units: u128, token: &cow::CowToken) -> String {
    let cut = 10u128.pow(u32::from(token.decimals.saturating_sub(8)));
    format!("{} {}", pgp_wallet_poc::tokens::format_amount(units / cut * cut, token.decimals), token.symbol)
}

#[derive(Serialize)]
struct CowQuoteDto {
    expected_out: String,
    min_out: String,
    partner_fee: String,
    network_fee: String,
}

#[tauri::command]
async fn get_cow_quote(network: String, from_coin: String, to_coin: String, amount: String, profile_index: u32, app: tauri::AppHandle) -> Result<CowQuoteDto, String> {
    run_blocking(move || {
        let (sell, buy) = cow_pair(&network, &from_coin, &to_coin)?;
        let owner = profile_evm_address(&app, profile_index)?;
        let order = api::get_cow_quote(evm_network(&network)?, &sell, &buy, &amount, &owner).t_err()?;
        Ok(CowQuoteDto {
            expected_out: cow_amount(order.expected_buy, &buy),
            min_out: cow_amount(order.min_buy, &buy),
            partner_fee: cow_amount(order.partner_fee_buy, &buy),
            network_fee: cow_amount(order.network_fee_sell, &sell),
        })
    })
    .await
}

/// Confirmation native d'un ordre CoW : tout ce qui sera signé (vente,
/// minimum reçu, destinataire, validité, frais) et la transaction qui
/// l'accompagne s'il y en a une (autorisation du jeton, ou dépôt EthFlow pour
/// la monnaie du réseau) — texte construit uniquement à partir de l'ordre
/// préparé côté Rust.
#[allow(clippy::too_many_arguments)]
fn confirm_cow_swap_native(
    app: &tauri::AppHandle,
    from_label: &str,
    network_name: &str,
    sell_line: &str,
    network_fee: &str,
    expected_out: &str,
    min_out: &str,
    partner_fee: &str,
    receiver: &str,
    minutes: u64,
    transaction_lines: Option<&str>,
    eth_flow: bool,
) -> bool {
    let from_label = dialog_label(from_label);
    let transaction_lines = transaction_lines.map(|a| format!("{a}\n")).unwrap_or_default();
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let (expiry, closing) = match (eth_flow, english) {
        (true, true) => ("if not executed, it expires and CoW refunds you automatically.", "Once executed, the swap is irreversible."),
        (true, false) => ("non exécuté, il expire et CoW vous rembourse automatiquement.", "Une fois exécuté, l'échange est irréversible."),
        (false, true) => ("if not executed, it expires at no cost.", "This signs an order (no swap transaction): once executed, it is irreversible."),
        (false, false) => (
            "non exécuté, il expire sans rien coûter.",
            "Ceci signe un ordre (pas de transaction d'échange) : une fois exécuté, il est irréversible.",
        ),
    };
    let message = if english {
        format!(
            "Swap via CoW Protocol (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nNetwork: {network_name}\nSelling: {sell_line} (incl. ≈ {network_fee} of CoW network costs)\nExpected to receive: ~{expected_out}\nGuaranteed minimum: {min_out} (otherwise the order is not executed)\nFunds will arrive at: {receiver}\n(verify this is really your own address)\nIncludes a 1% integration fee (≈ {partner_fee}).\nOrder valid for about {minutes} minutes; {expiry}\n{transaction_lines}\n{closing}\n\nConfirm this swap?"
        )
    } else {
        format!(
            "Échange via CoW Protocol (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nRéseau : {network_name}\nVente : {sell_line} (dont ≈ {network_fee} de frais réseau de CoW)\nRéception attendue : ~{expected_out}\nMinimum garanti : {min_out} (sinon l'ordre n'est pas exécuté)\nLes fonds arriveront sur : {receiver}\n(vérifiez qu'il s'agit bien de votre propre adresse)\nInclut 1 % de frais d'intégration (≈ {partner_fee}).\nOrdre valable environ {minutes} minutes ; {expiry}\n{transaction_lines}\n{closing}\n\nConfirmer cet échange ?"
        )
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Lignes de la boîte native pour la transaction qui accompagne l'ordre :
/// dépôt EthFlow (monnaie du réseau) ou autorisation préalable du jeton au
/// VaultRelayer de CoW (aucune si celle déjà accordée suffit).
fn cow_transaction_lines(net: &wallet_flow::EvmNetwork, sell: &cow::CowToken, order: &cow::CowOrder, gas_price: u128, sell_line: &str) -> Result<Option<String>, String> {
    let gwei = gas_price as f64 / 1e9;
    let symbol = net.native_symbol;
    if sell.native {
        let total = api::cow_eth_flow_fee(net, order, gas_price).t_err()?.max_total().t_err()? as f64 / 1e18;
        return Ok(Some(
            lang(
                &format!("Transaction : {sell_line} confiés au contrat EthFlow de CoW {}, qui les garde jusqu'à l'exécution de l'ordre.\nFrais réseau maximum de cette transaction : {total:.8} {symbol} ({gwei:.4} gwei)", cow::ETH_FLOW),
                &format!("Transaction: {sell_line} entrusted to CoW's EthFlow contract {}, which holds it until the order is executed.\nMaximum network fee for this transaction: {total:.8} {symbol} ({gwei:.4} gwei)", cow::ETH_FLOW),
            )
            .to_string(),
        ));
    }
    let (approve_fee, approvals) = api::cow_approval_fees(net, order, gas_price).t_err()?;
    if approvals == 0 {
        return Ok(None);
    }
    let total = approve_fee.max_total().t_err()?.saturating_mul(approvals as u128) as f64 / 1e18;
    Ok(Some(
        lang(
            &format!("Autorisation préalable (transaction séparée) : le contrat de CoW {} pourra prélever exactement {sell_line}, une seule fois.\nFrais réseau maximum de l'autorisation : {total:.8} {symbol} ({gwei:.4} gwei)", cow::VAULT_RELAYER),
            &format!("Prior approval (separate transaction): CoW's contract {} will be allowed to take exactly {sell_line}, once.\nMaximum network fee for the approval: {total:.8} {symbol} ({gwei:.4} gwei)", cow::VAULT_RELAYER),
        )
        .to_string(),
    ))
}

#[derive(Serialize)]
struct CowOrderDto {
    uid: String,
    explorer_url: Option<String>,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn cow_swap_transaction(
    password: String,
    network: String,
    from_coin: String,
    to_coin: String,
    amount: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<CowOrderDto, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (sell, buy) = cow_pair(&network, &from_coin, &to_coin)?;
        let net = evm_network(&network)?;
        // Forme canonique, affichée ET signée (voir `send_transaction`).
        let amount = api::canonical_cow_amount(&sell, &amount).t_err()?;
        let owner = profile_evm_address(&app, profile_index)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Devis obtenu ICI, juste avant la confirmation : l'ordre affiché est
        // exactement celui qui sera signé (aucun nouveau devis ensuite).
        let order = api::get_cow_quote(net, &sell, &buy, &amount, &owner).t_err()?;
        let gas_price = api::evm_gas_price_for_confirmation(net).t_err()?;
        let sell_line = cow_amount(order.sell_amount, &sell);
        let transaction_lines = cow_transaction_lines(net, &sell, &order, gas_price, &sell_line)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let minutes = u64::from(order.valid_to).saturating_sub(now) / 60;
        if !confirm_cow_swap_native(
            &app,
            &from_label,
            &network_label(&network),
            &sell_line,
            &cow_amount(order.network_fee_sell, &sell),
            &cow_amount(order.expected_buy, &buy),
            &cow_amount(order.min_buy, &buy),
            &cow_amount(order.partner_fee_buy, &buy),
            &order.receiver,
            minutes,
            transaction_lines.as_deref(),
            sell.native,
        ) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(&app)?;

        // Monnaie du réseau : transaction EthFlow ; jeton : ordre signé.
        let uid = if sell.native {
            api::send_cow_eth_flow(&dir, &password, net, &order, gas_price, profile_index).t_err()?.1
        } else {
            api::send_cow_swap(&dir, &password, net, &sell, &order, gas_price, profile_index).t_err()?
        };
        Ok(CowOrderDto { explorer_url: cow::explorer_order_url(&network, &uid), uid })
    })
    .await
}

// --- Swap (LI.FI) ------------------------------------------------------------
// Entre deux écosystèmes : transaction construite par LI.FI, vérifiée avant
// signature (voir core/src/lifi.rs et api::lifi_verified_quote).

type LifiPair = (&'static str, &'static str, pgp_wallet_poc::lifi::LifiToken, pgp_wallet_poc::lifi::LifiToken);

/// Paire LI.FI désignée par l'interface : refusée si LI.FI ne la relie pas
/// (voir `swap_routes::direct_all`). Renvoie les réseaux (identifiants
/// statiques) et les jetons LI.FI.
fn lifi_pair(from_coin: &str, from_network: &str, to_coin: &str, to_network: &str) -> Result<LifiPair, String> {
    use pgp_wallet_poc::swap_routes;
    let (from, to) = swap_routes::find(from_coin, from_network)
        .zip(swap_routes::find(to_coin, to_network))
        .filter(|(f, t)| swap_routes::direct_all(*f, *t).contains(&swap_routes::Protocol::Lifi))
        .ok_or_else(|| translate_error("échange non disponible entre ces deux cryptos"))?;
    let (from_token, to_token) = api::lifi_tokens(from_coin, from_network, to_coin, to_network).t_err()?;
    Ok((from.network, to.network, from_token, to_token))
}

/// Adresse publique du profil sur le réseau de départ (mémorisée au
/// déverrouillage) : l'envoi revérifie qu'elle est celle de la clé qui signe.
fn profile_address_on(app: &tauri::AppHandle, profile_index: u32, network: &str) -> Result<String, String> {
    if network == "btc_mainnet" {
        let cache = app.state::<ProfileBtcCache>();
        let cache = cache.0.lock().unwrap_or_else(|p| p.into_inner());
        return cache.get(&profile_index).cloned().ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"));
    }
    let cache = app.state::<ProfileAddressCache>();
    let cache = cache.0.lock().unwrap_or_else(|p| p.into_inner());
    let (evm, solana) = cache.get(&profile_index).ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
    match network {
        "sol_mainnet" => Ok(solana.clone()),
        _ if wallet_flow::evm_network(network).is_some() => Ok(evm.clone()),
        _ => Err(translate_error("échange non disponible entre ces deux cryptos")),
    }
}

/// Montant affiché : 8 décimales au plus, TRONQUÉ.
fn lifi_amount(units: u128, token: &pgp_wallet_poc::lifi::LifiToken) -> String {
    let cut = 10u128.pow(u32::from(token.decimals.saturating_sub(8)));
    format!("{} {}", pgp_wallet_poc::tokens::format_amount(units / cut * cut, token.decimals), token.symbol)
}

#[derive(Serialize)]
struct LifiQuoteDto {
    expected_out: String,
    min_out: String,
    bridge: String,
    duration_secs: u64,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn get_lifi_quote(
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<LifiQuoteDto, String> {
    run_blocking(move || {
        let (from_net, to_net, from, to) = lifi_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        let from_address = profile_address_on(&app, profile_index, from_net)?;
        let destination = canonical_address_input(&destination)?;
        let quote = api::get_lifi_quote(from_net, &from, to_net, &to, &amount, &from_address, &destination).t_err()?;
        Ok(LifiQuoteDto {
            expected_out: lifi_amount(quote.to_amount, &to),
            min_out: lifi_amount(quote.to_amount_min, &to),
            bridge: quote.tool_name,
            duration_secs: quote.duration_secs,
        })
    })
    .await
}

fn lifi_duration(secs: u64) -> String {
    let minutes = secs.div_ceil(60).max(1);
    lang(&format!("≈ {minutes} min"), &format!("≈ {minutes} min")).to_string()
}

/// Confirmation native d'un échange LI.FI : pont, montants, adresse d'arrivée
/// et niveau de vérification de cette adresse (vérifiée dans la simulation,
/// ou gérée hors chaîne par le pont depuis Solana), frais, transactions —
/// texte construit uniquement à partir du devis vérifié côté Rust.
#[allow(clippy::too_many_arguments)]
fn confirm_lifi_swap_native(
    app: &tauri::AppHandle,
    from_label: &str,
    route: &str,
    sell_line: &str,
    expected_out: &str,
    min_out: &str,
    bridge: &str,
    duration: &str,
    destination: &str,
    receiver_verified: bool,
    fee_lines: &str,
) -> bool {
    let from_label = dialog_label(from_label);
    let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        let receiver_line = if receiver_verified {
            "(address checked by the app in a simulation of the transaction — verify this is really yours)".to_string()
        } else {
            format!("⚠ This address is handled off-chain by the {bridge} bridge: the app checked what leaves your wallet, but cannot verify the arrival address.")
        };
        format!(
            "Swap via LI.FI (external aggregator, not audited by this app)\n\nFrom profile: {from_label}\nRoute: {route}\nSending: {sell_line}\nBridge chosen by LI.FI: {bridge} (estimated time {duration})\nExpected to receive: ~{expected_out}\nMinimum announced by LI.FI: {min_out} (guaranteed by the bridge, not verifiable by this app)\nFunds will arrive at: {destination}\n{receiver_line}\n{fee_lines}\nIncludes a 0.80% affiliate fee, plus LI.FI's and the bridge's own fees.\nThis is irreversible.\n\nConfirm this swap?"
        )
    } else {
        let receiver_line = if receiver_verified {
            "(adresse vérifiée par l'app dans une simulation de la transaction — vérifiez qu'il s'agit bien de la vôtre)".to_string()
        } else {
            format!("⚠ Cette adresse est gérée hors chaîne par le pont {bridge} : l'app a vérifié ce qui quitte votre portefeuille, mais ne peut pas vérifier l'adresse d'arrivée.")
        };
        format!(
            "Échange via LI.FI (agrégateur externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nTrajet : {route}\nEnvoi : {sell_line}\nPont choisi par LI.FI : {bridge} (durée estimée {duration})\nRéception attendue : ~{expected_out}\nMinimum annoncé par LI.FI : {min_out} (garanti par le pont, non vérifiable par cette app)\nLes fonds arriveront sur : {destination}\n{receiver_line}\n{fee_lines}\nInclut 0,80 % de frais d'affiliation, plus les frais de LI.FI et du pont.\nC'est irréversible.\n\nConfirmer cet échange ?"
        )
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[derive(Serialize)]
struct LifiTransferDto {
    tx_hash: String,
    explorer_url: String,
    from_chain: u64,
    to_chain: u64,
    duration_secs: u64,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn lifi_swap_transaction(
    password: String,
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<LifiTransferDto, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (from_net, to_net, from, to) = lifi_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        // Formes canoniques, affichées ET signées (voir `send_transaction`).
        let amount = api::canonical_lifi_amount(&from, &amount).t_err()?;
        let destination = canonical_address_input(&destination)?;
        let from_address = profile_address_on(&app, profile_index, from_net)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Devis obtenu ICI et sa transaction vérifiée AVANT la confirmation.
        let (quote, receiver_verified) = api::lifi_verified_quote(from_net, &from, to_net, &to, &amount, &from_address, &destination).t_err()?;
        let sell_line = lifi_amount(quote.from_amount, &from);
        let evm_net = wallet_flow::evm_network(from_net);
        let gas_price = match evm_net {
            Some(net) => Some(api::evm_gas_price_for_confirmation(net).t_err()?),
            None => None,
        };
        // Bitcoin : frais réseau fixés par la PSBT de LI.FI, montrés et bornés
        // (au plus 1,5 fois ceux affichés après le nouveau devis).
        let mut btc_max_network_fee = None;
        let fee_lines = match (evm_net, gas_price) {
            _ if from_net == "btc_mainnet" => {
                let deposit = api::lifi_btc_deposit(&quote).t_err()?;
                let pgp_wallet_poc::lifi::LifiTx::Bitcoin { deposit: address, .. } = &quote.tx else {
                    return Err(translate_error("devis LI.FI non Bitcoin"));
                };
                let (fee, rate) = (deposit.network_fee, deposit.network_fee as f64 / deposit.vsize.max(1) as f64);
                let max_fee = fee.saturating_mul(3) / 2;
                btc_max_network_fee = Some(max_fee);
                let (service, total) = (deposit.service_fees, deposit.total_debit);
                lang(
                    &format!("Dépôt Bitcoin vers l'adresse du pont : {address}\nFrais réseau Bitcoin : {fee} sat (≈ {rate:.1} sat/vB), au plus {max_fee} sat\nFrais de LI.FI et de l'app : {service} sat\nTotal débité de votre adresse : {total} sat"),
                    &format!("Bitcoin deposit to the bridge's address: {address}\nBitcoin network fee: {fee} sat (≈ {rate:.1} sat/vB), at most {max_fee} sat\nLI.FI's and the app's fees: {service} sat\nTotal debited from your address: {total} sat"),
                )
                .to_string()
            }
            (Some(net), Some(gas_price)) => {
                let (call, approve, approvals) = api::lifi_evm_fees(net, &quote, gas_price).t_err()?;
                let total = call.max_total().t_err()?.saturating_add(approve.max_total().t_err()?.saturating_mul(approvals as u128)) as f64 / 1e18;
                let (gwei, symbol) = (gas_price as f64 / 1e9, net.native_symbol);
                let diamond = pgp_wallet_poc::lifi::diamond(from_net).unwrap_or("?");
                let mut lines = lang(
                    &format!("Frais réseau maximum : {total:.8} {symbol} ({gwei:.4} gwei)"),
                    &format!("Maximum network fee: {total:.8} {symbol} ({gwei:.4} gwei)"),
                )
                .to_string();
                if approvals > 0 {
                    lines.push_str(lang(
                        &format!("\nAutorisation préalable (transaction séparée) : le contrat LI.FI {diamond} pourra prélever exactement {sell_line}, une seule fois."),
                        &format!("\nPrior approval (separate transaction): LI.FI's contract {diamond} will be allowed to take exactly {sell_line}, once."),
                    ));
                }
                lines
            }
            _ => lang("Frais réseau Solana : au plus 0,01 SOL", "Solana network fee: at most 0.01 SOL").to_string(),
        };
        let short_name = |network: &str| match network {
            "sol_mainnet" => "Solana".to_string(),
            "btc_mainnet" => "Bitcoin".to_string(),
            _ => wallet_flow::evm_network(network).map(|n| n.name.to_string()).unwrap_or_else(|| network.to_string()),
        };
        let route = format!("{} → {}", short_name(from_net), short_name(to_net));
        if !confirm_lifi_swap_native(
            &app,
            &from_label,
            &route,
            &sell_line,
            &lifi_amount(quote.to_amount, &to),
            &lifi_amount(quote.to_amount_min, &to),
            &quote.tool_name,
            &lifi_duration(quote.duration_secs),
            &quote.to_address,
            receiver_verified,
            &fee_lines,
        ) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(&app)?;

        // Nouveau devis sur le même pont (la transaction d'un pont expire
        // vite), refusé s'il ne correspond plus à ce qui a été affiché.
        let fresh = api::refresh_lifi_quote_matching(&quote, receiver_verified).t_err()?;
        let tx_hash = match (evm_net, gas_price) {
            _ if from_net == "btc_mainnet" => {
                let max_fee = btc_max_network_fee.ok_or_else(|| "frais Bitcoin manquants".to_string())?;
                api::send_lifi_btc(&dir, &password, &fresh, max_fee, profile_index).t_err()?
            }
            (Some(net), Some(gas_price)) => api::send_lifi_evm(&dir, &password, net, &fresh, gas_price, profile_index).t_err()?,
            _ => api::send_lifi_solana(&dir, &password, &fresh, profile_index).t_err()?,
        };
        Ok(LifiTransferDto {
            explorer_url: pgp_wallet_poc::lifi::explorer_url(&tx_hash),
            tx_hash,
            from_chain: fresh.from.chain,
            to_chain: fresh.to.chain,
            duration_secs: fresh.duration_secs,
        })
    })
    .await
}

/// État d'un transfert LI.FI, suivi par l'interface après l'envoi.
#[tauri::command]
async fn lifi_status(tx_hash: String, from_chain: u64, to_chain: u64) -> Result<String, String> {
    run_blocking(move || pgp_wallet_poc::lifi::status(&tx_hash, from_chain, to_chain).t_err()).await
}

/// État d'un ordre CoW (« open », « fulfilled », « expired »…), suivi par
/// l'interface après l'envoi.
#[tauri::command]
async fn cow_order_status(network: String, uid: String) -> Result<String, String> {
    run_blocking(move || cow::order_status(&network, &uid).t_err()).await
}

#[tauri::command]
async fn send_usdc_transaction(password: String, to: String, amount: String, profile_index: u32, max: Option<bool>, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let network = "sol_mainnet"; // USDC v1 : mainnet uniquement (voir sol_spl.rs)
        let net = sol_network(network)?;
        // Formes canoniques, affichées ET signées (voir `send_transaction`).
        let to = canonical_address_input(&to)?;
        let from_sol = app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(_, sol)| sol.clone());
        // « Max » : tout le solde USDC (les frais sont payés en SOL).
        let amount = match (max.unwrap_or(false), &from_sol) {
            (true, Some(from)) => api::token_max("usdc", network, from).t_err()?,
            (true, None) => return Err(translate_error("adresse du profil inconnue — déverrouillez le portefeuille")),
            (false, _) => amount,
        };
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
        // Solde suffisant vérifié AVANT la boîte de confirmation.
        if let Some(from) = app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(_, sol)| sol.clone()) {
            api::ensure_token_funds("usdc", network, &from, &amount).t_err()?;
        }

        let rent_line = describe_possible_ata_rent(net, &to);
        let amount_line = format!("{amount} USDC");
        // Même journal que les envois SOL (même réseau, même portefeuille
        // destinataire) : avoir déjà payé cette adresse en SOL compte.
        let warning = send_warnings(&app, &dir, network, "usdc", &to, api::usdc_recipient_activity(&to, net).ok());
        if !confirm_transaction_native(&app, network, &to, &amount_line, &from_label, rent_line.as_deref(), warning.as_deref(), None) {
            return Err(translate_error("Virement annulé (confirmation refusée)."));
        }
        send_grace_period(&app)?;

        let result = api::send_usdc(&dir, &password, net, &to, &amount, profile_index).t_err();
        if result.is_ok() {
            let _ = sent_recipients::record_sent(&dir, network, &to);
        }
        result
    })
    .await
}

/// Solde d'un jeton du registre (`core/src/tokens.rs`) sur `network`, au
/// plus 6 décimales affichées (tronqué, jamais arrondi au supérieur).
#[tauri::command]
async fn get_token_balance(token: String, network: String, address: String) -> Result<String, String> {
    run_blocking(move || {
        let (units, decimals) = api::get_token_balance(&token, &network, &address).t_err()?;
        Ok(pgp_wallet_poc::tokens::format_balance(units, decimals, 6))
    })
    .await
}

/// Virement d'un jeton du registre : l'interface ne donne que l'identifiant du
/// jeton et le réseau — contrat/mint et décimales viennent du registre Rust,
/// et la boîte native les affiche (nom, contrat, montant, frais).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn send_token_transaction(
    token: String,
    network: String,
    password: String,
    to: String,
    amount: String,
    profile_index: u32,
    max: Option<bool>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (info, deployment) = pgp_wallet_poc::tokens::find(&token, &network).ok_or_else(|| translate_error("jeton non pris en charge sur ce réseau"))?;
        let to = canonical_address_input(&to)?;
        // « Max » : tout le solde du jeton (les frais sont payés dans la
        // monnaie du réseau).
        let amount = if max.unwrap_or(false) {
            let owner = app
                .state::<ProfileAddressCache>()
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&profile_index)
                .map(|(evm, sol)| if is_evm(&network) { evm.clone() } else { sol.clone() })
                .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
            api::token_max(&token, &network, &owner).t_err()?
        } else {
            amount
        };
        let amount = api::canonical_token_amount(&token, &network, &amount).t_err()?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));
        let amount_line = format!("{amount} {}", info.symbol);
        let result = match deployment.kind {
            pgp_wallet_poc::tokens::TokenKind::Erc20 { contract } => {
                let net = evm_network(&network)?;
                api::validate_evm_recipient(&to).t_err()?;
                let from_evm = app
                    .state::<ProfileAddressCache>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&profile_index)
                    .map(|(evm, _)| evm.clone())
                    .ok_or_else(|| translate_error("adresse d'envoi inconnue : déverrouillez le portefeuille"))?;
                let fee = api::erc20_fee_for_confirmation(&token, &network, &from_evm, &to, &amount).t_err()?;
                // Jeton ET gas suffisants, vérifiés AVANT la boîte de confirmation.
                api::ensure_token_funds(&token, &network, &from_evm, &amount).t_err()?;
                api::ensure_evm_gas_funds(net, &from_evm, fee).t_err()?;
                let token_line = lang(
                    &format!("Jeton : {} ({}) — contrat {}", info.name, info.symbol, dialog_address(contract)),
                    &format!("Token: {} ({}) — contract {}", info.name, info.symbol, dialog_address(contract)),
                )
                .to_string();
                let warning = send_warnings(&app, &dir, &network, "evm", &to, api::evm_recipient_activity(&to, net).ok());
                let fee_line = evm_fee_line_for(fee, net.native_symbol);
                if !confirm_transaction_native(&app, &network, &to, &amount_line, &from_label, Some(&fee_line), warning.as_deref(), Some(&token_line)) {
                    return Err(translate_error("Virement annulé (confirmation refusée)."));
                }
                send_grace_period(&app)?;
                api::send_erc20(&dir, &password, &token, &network, &to, &amount, fee, profile_index).t_err()
            }
            pgp_wallet_poc::tokens::TokenKind::Spl { mint } => {
                let net = sol_network(&network)?;
                api::check_solana_recipient(&to, net).t_err()?;
                if let Some(from) = app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(_, sol)| sol.clone()) {
                    api::ensure_token_funds(&token, &network, &from, &amount).t_err()?;
                }
                let token_line = lang(
                    &format!("Jeton : {} ({}) — mint {mint}", info.name, info.symbol),
                    &format!("Token: {} ({}) — mint {mint}", info.name, info.symbol),
                )
                .to_string();
                let warning = send_warnings(&app, &dir, &network, "sol", &to, api::sol_recipient_activity(&to, net).ok());
                // Compte de jetons du destinataire à créer : coût annoncé avant.
                let rent_line = api::registered_spl_mint(&token)
                    .ok()
                    .and_then(|mint| api::spl_ata_rent_lamports_if_missing(&to, &mint, net).ok().flatten())
                    .map(|lamports| {
                        let sol = lamports as f64 / 1e9;
                        lang(
                            &format!("Le destinataire n'a pas encore de compte {} : sa création coûtera environ {sol:.6} SOL de rent supplémentaire (payé par vous, une seule fois), en plus des frais réseau habituels.", info.symbol),
                            &format!("The recipient doesn't have a {} account yet: creating it will cost about {sol:.6} extra SOL in rent (paid by you, once), on top of the usual network fee.", info.symbol),
                        )
                        .to_string()
                    });
                if !confirm_transaction_native(&app, &network, &to, &amount_line, &from_label, rent_line.as_deref(), warning.as_deref(), Some(&token_line)) {
                    return Err(translate_error("Virement annulé (confirmation refusée)."));
                }
                send_grace_period(&app)?;
                api::send_registered_spl(&dir, &password, &token, &to, &amount, profile_index).t_err()
            }
        };
        if result.is_ok() {
            let _ = sent_recipients::record_sent(&dir, &network, &to);
        }
        result
    })
    .await
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
async fn decrypt_message(password: String, ciphertext: String, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        api::decrypt_incoming_message(&dir, &password, &ciphertext).t_err()
    })
    .await
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

// --- WalletConnect (dApps) -----------------------------------------------------
// Voir core/src/walletconnect/ (protocole) et core/src/dapp_requests.rs
// (préparation des demandes). Ici : état de l'app, commandes, et les boîtes de
// confirmation NATIVES — dont le texte est construit uniquement à partir de la
// demande préparée côté Rust, jamais d'une donnée renvoyée par le frontend.

/// Adresses PUBLIQUES des profils, mémorisées au déverrouillage : connecter une
/// dApp ne demande pas le mot de passe (aucune signature), seulement de savoir
/// quelles adresses lui présenter. Vidé à la réinitialisation.
#[derive(Default)]
struct ProfileAddressCache(std::sync::Mutex<std::collections::HashMap<u32, (String, String)>>);

/// Adresse Zcash transparente de chaque profil, mémorisée au même moment :
/// préparer un envoi ZEC (sorties à dépenser, frais) demande l'adresse de
/// départ AVANT la boîte de confirmation, donc avant tout mot de passe.
#[derive(Default)]
struct ProfileZcashCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Adresse Bitcoin testnet de chaque profil (bouton « Max » d'un envoi testnet).
#[derive(Default)]
struct ProfileBtcTestnetCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Adresse Dogecoin de chaque profil, mémorisée au même moment : préparer un
/// envoi DOGE (sorties vérifiées, frais) demande l'adresse de départ AVANT la
/// boîte de confirmation.
#[derive(Default)]
struct ProfileDogeCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Adresse Bitcoin (réseau principal) de chaque profil, mémorisée au même
/// moment : un échange LI.FI depuis Bitcoin demande un devis (PSBT construite
/// sur ses sorties) AVANT la boîte de confirmation.
#[derive(Default)]
struct ProfileBtcCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

#[derive(Default)]
struct WcState {
    client: std::sync::OnceLock<std::sync::Arc<pgp_wallet_poc::walletconnect::WalletConnect>>,
    /// Demandes préparées (ce qui sera signé ET affiché), par identifiant,
    /// avec la connexion (topic) dont elles viennent.
    prepared: std::sync::Mutex<std::collections::HashMap<u64, (String, dapp_requests::Prepared)>>,
}

fn remember_addresses(app: &tauri::AppHandle, index: u32, addresses: &api::Addresses) {
    if index == 0 {
        IS_AFFILIATE_WALLET.store(addresses.thor == pgp_wallet_poc::thorchain_rpc::AFFILIATE_ADDRESS, Ordering::Relaxed);
    }
    if let Some(cache) = app.try_state::<ProfileAddressCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, (addresses.evm.clone(), addresses.solana.clone()));
    }
    if let Some(cache) = app.try_state::<ProfileZcashCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, addresses.zcash.clone());
    }
    if let Some(cache) = app.try_state::<ProfileBtcCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, addresses.btc_mainnet.clone());
    }
    if let Some(cache) = app.try_state::<ProfileDogeCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, addresses.doge.clone());
    }
    if let Some(cache) = app.try_state::<ProfileBtcTestnetCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, addresses.btc_testnet.clone());
    }
    if let Some(cache) = app.try_state::<ShieldedKeysCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, (addresses.zcash_shielded.clone(), addresses.zcash_shielded_keys.clone()));
    }
    if let Some(cache) = app.try_state::<MoneroKeysCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(index, (addresses.monero.clone(), addresses.monero_keys.clone()));
    }
    start_shielded_sync(app);
    start_monero_sync(app);
}

/// Adresse et clés de visualisation Monero de chaque profil, mémorisées au
/// déverrouillage (jamais envoyées à l'interface) : synchronisation de fond
/// et préparation des envois avant la boîte de confirmation.
#[derive(Default)]
struct MoneroKeysCache(std::sync::Mutex<std::collections::HashMap<u32, (String, pgp_wallet_poc::monero::ViewKeys)>>);

/// Profil de l'adresse Monero `address` (les commandes génériques de la carte
/// reçoivent une adresse).
fn monero_profile(app: &tauri::AppHandle, address: &str) -> Result<u32, String> {
    app.state::<MoneroKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(_, (known, _))| known == address)
        .map(|(index, _)| *index)
        .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))
}

/// Carte Monero affichée (`set_xmr_sync`) : sans elle, et sans fonds déjà
/// reçus, aucun bloc n'est téléchargé (~15 Mo par jour de chaîne).
static XMR_SYNC_WANTED: AtomicBool = AtomicBool::new(false);
/// Passage demandé tout de suite (carte activée, envoi diffusé).
static XMR_SYNC_KICK: AtomicBool = AtomicBool::new(false);

/// Synchronisation Monero en arrière-plan, une seule à la fois : blocs
/// analysés jusqu'au bout de la chaîne, puis toutes les 30 s (un bloc toutes
/// les 2 minutes en moyenne : une réception apparaît peu après son bloc ; un
/// passage sans nouveau bloc ne coûte qu'une lecture de hauteur). L'interface
/// est prévenue après chaque passage (`xmr-synced`) ; un échec réseau est
/// retenté au passage suivant.
fn start_monero_sync(app: &tauri::AppHandle) {
    static RUNNING: AtomicBool = AtomicBool::new(false);
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || loop {
        let keys: Vec<_> = app.state::<MoneroKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).values().map(|(_, keys)| keys.clone()).collect();
        let wanted = XMR_SYNC_WANTED.load(Ordering::Relaxed) || data_dir(&app).is_ok_and(|dir| api::xmr_has_received(&dir));
        if wanted && !keys.is_empty() {
            match data_dir(&app) {
                Ok(dir) => match catch_sync_panic(|| api::sync_xmr(&dir, &keys)) {
                    Ok(()) => {
                        let _ = app.emit("xmr-synced", ());
                    }
                    Err(e) => eprintln!("Monero : {e:#}"),
                },
                Err(e) => eprintln!("Monero : {e}"),
            }
        }
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if XMR_SYNC_KICK.swap(false, Ordering::SeqCst) {
                break;
            }
        }
    });
}

/// Carte Monero affichée ou non (choix de l'utilisateur) : la synchronisation
/// de fond ne tourne que pour elle (ou si des fonds ont déjà été reçus).
#[tauri::command]
fn set_xmr_sync(enabled: bool) {
    let was = XMR_SYNC_WANTED.swap(enabled, Ordering::SeqCst);
    if enabled && !was {
        XMR_SYNC_KICK.store(true, Ordering::SeqCst);
    }
}

#[derive(Serialize)]
struct MoneroStatusDto {
    unlocked: String,
    locked: String,
    /// Chaîne entièrement analysée (le solde est à jour).
    synced: bool,
}

/// Solde Monero détaillé du profil (état local, aucun appel réseau) : la
/// carte montre la part encore bloquée et l'état de la synchronisation.
#[tauri::command]
async fn xmr_status(profile_index: u32, app: tauri::AppHandle) -> Result<MoneroStatusDto, String> {
    run_blocking(move || {
        let balance = api::xmr_balance(&data_dir(&app)?, profile_index).t_err()?;
        Ok(MoneroStatusDto {
            unlocked: pgp_wallet_poc::monero::format_xmr(balance.unlocked),
            locked: pgp_wallet_poc::monero::format_xmr(balance.locked),
            synced: balance.synced,
        })
    })
    .await
}

/// Nœud Monero choisi dans Paramètres (`None` : nœuds publics par défaut).
#[tauri::command]
fn xmr_node(app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(api::xmr_node(&data_dir(&app)?))
}

/// « Réanalyser depuis le début » (Paramètres) : Monero et Zcash protégé
/// relus depuis la naissance fixe de l'app (fonds plus anciens que la création
/// du portefeuille sur cet appareil).
#[tauri::command]
fn rescan_private_funds(app: tauri::AppHandle) -> Result<(), String> {
    api::rescan_private_funds(&data_dir(&app)?).t_err()?;
    XMR_SYNC_KICK.store(true, Ordering::SeqCst);
    Ok(())
}

/// Enregistre le nœud Monero (vide : retour aux nœuds publics), utilisé dès
/// la synchronisation suivante.
#[tauri::command]
fn set_xmr_node(url: String, app: tauri::AppHandle) -> Result<Option<String>, String> {
    let node = api::set_xmr_node(&data_dir(&app)?, &url).t_err()?;
    XMR_SYNC_KICK.store(true, Ordering::SeqCst);
    Ok(node)
}

/// Passage de synchronisation de fond protégé contre une panique d'une
/// bibliothèque (donnée inattendue d'un nœud) : sans cela le fil s'arrêterait
/// pour de bon, sans le dire, jusqu'au redémarrage de l'app.
fn catch_sync_panic<E: std::fmt::Display>(sync: impl FnOnce() -> Result<(), E>) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(sync)) {
        Ok(result) => result.map_err(|e| format!("{e:#}")),
        Err(_) => Err("synchronisation interrompue (erreur interne), reprise au passage suivant".to_string()),
    }
}

/// Clés de visualisation des comptes Zcash protégés, mémorisées au
/// déverrouillage (jamais envoyées à l'interface).
#[derive(Default)]
struct ShieldedKeysCache(std::sync::Mutex<std::collections::HashMap<u32, (String, pgp_wallet_poc::zcash_shielded::ProfileKeys)>>);

/// Profil de l'adresse Zcash protégée `address` (carte « Zcash protégé »).
fn shielded_profile(app: &tauri::AppHandle, address: &str) -> Result<u32, String> {
    app.state::<ShieldedKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(_, (known, _))| known == address)
        .map(|(index, _)| *index)
        .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))
}

/// Passage de synchronisation Zcash protégée demandé tout de suite (envoi ou
/// protection diffusés).
static ZECS_SYNC_KICK: AtomicBool = AtomicBool::new(false);

/// Synchronisation Zcash protégée en arrière-plan, une seule à la fois :
/// comptes manquants créés, chaîne analysée, puis toutes les 30 s (un bloc
/// toutes les 75 s) tant que l'app est ouverte. L'interface est prévenue après chaque passage
/// (`zec-shielded-synced`) ; un échec réseau est retenté au passage suivant.
fn start_shielded_sync(app: &tauri::AppHandle) {
    static RUNNING: AtomicBool = AtomicBool::new(false);
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || loop {
        let keys: Vec<_> = app.state::<ShieldedKeysCache>().0.lock().unwrap_or_else(|p| p.into_inner()).values().map(|(_, keys)| keys.clone()).collect();
        if !keys.is_empty() {
            match data_dir(&app) {
                Ok(dir) => match catch_sync_panic(|| api::sync_zec_shielded(&dir, &keys)) {
                    Ok(()) => {
                        let _ = app.emit("zec-shielded-synced", ());
                    }
                    Err(e) => eprintln!("Zcash protégé : {e:#}"),
                },
                Err(e) => eprintln!("Zcash protégé : {e}"),
            }
        }
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if ZECS_SYNC_KICK.swap(false, Ordering::SeqCst) {
                break;
            }
        }
    });
}

#[derive(Serialize)]
struct ShieldedBalanceDto {
    spendable: String,
    pending: String,
    /// Chaîne entièrement analysée (le solde est à jour).
    synced: bool,
}

fn shielded_dialog(app: &tauri::AppHandle, title: (&str, &str), message: String) -> bool {
    app.dialog().message(message).title(lang(title.0, title.1)).kind(MessageDialogKind::Warning).buttons(MessageDialogButtons::OkCancel).blocking_show()
}

/// Protège les ZEC transparents du profil (t1 → adresse Orchard du même
/// profil) après une boîte de confirmation native (montant, frais ZIP-317).
#[tauri::command]
async fn zec_shield(password: String, profile_index: u32, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let t1 = app
            .state::<ProfileZcashCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned()
            .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
        let confirm = |s: &pgp_wallet_poc::zcash_shielded::SpendSummary| {
            let (amount, fee) = (pgp_wallet_poc::zcash::format_zec(s.amount), pgp_wallet_poc::zcash::format_zec(s.fee));
            let to = &s.recipient;
            let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                format!("Shield your transparent ZEC\n\nFrom: {t1}\nTo your shielded address: {to}\nAmount shielded: {amount} ZEC\nNetwork fee: {fee} ZEC (ZIP-317)\n\nOnce shielded, amounts and addresses are no longer visible on the blockchain.\n\nConfirm?")
            } else {
                format!("Protéger vos ZEC transparents\n\nDepuis : {t1}\nVers votre adresse protégée : {to}\nMontant protégé : {amount} ZEC\nFrais réseau : {fee} ZEC (ZIP-317)\n\nUne fois protégés, montants et adresses ne sont plus visibles sur la blockchain.\n\nConfirmer ?")
            };
            shielded_dialog(&app, ("Confirmer la protection", "Confirm shielding"), message)
        };
        match api::shield_zec(&dir, &password, profile_index, &t1, confirm).t_err()? {
            Some(txid) => {
                // Note en attente dans la base : soldes relus aussitôt.
                ZECS_SYNC_KICK.store(true, Ordering::SeqCst);
                Ok(txid)
            }
            None => Err(translate_error("Protection annulée (confirmation refusée).")),
        }
    })
    .await
}

/// Envoie depuis les fonds Zcash protégés du profil, après une boîte de
/// confirmation native (destinataire, montant, frais).
#[tauri::command]
async fn zec_send_shielded(password: String, profile_index: u32, to: String, amount: String, max: Option<bool>, app: tauri::AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let to = canonical_address_input(&to)?;
        let max = max.unwrap_or(false);
        // « Max » : montant fixé par la proposition « tout envoyer », affiché
        // dans la boîte (`SpendSummary`).
        let amount = if max { String::new() } else { api::canonical_zec_amount(&amount).t_err()? };
        let from_label = api::list_profiles(&dir).into_iter().find(|p| p.index == profile_index).map(|p| p.label).unwrap_or_else(|| format!("profil #{profile_index}"));
        let from_label = dialog_label(&from_label);
        // Comme les autres envois : adresse ressemblante, jamais payée, et —
        // vers une adresse transparente — état sur la chaîne.
        let warning = if to.starts_with('t') {
            send_warnings(&app, &dir, "zec_shielded", "zec", &to, api::zec_recipient_activity(&to).ok())
        } else {
            send_warnings(&app, &dir, "zec_shielded", "zecs", &to, None)
        };
        let warning = warning.map(|w| format!("{w}\n\n")).unwrap_or_default();
        let confirm = |s: &pgp_wallet_poc::zcash_shielded::SpendSummary| {
            let (amount, fee) = (pgp_wallet_poc::zcash::format_zec(s.amount), pgp_wallet_poc::zcash::format_zec(s.fee));
            let to = &s.recipient;
            let max_note = if max { lang(" (maximum, frais déduits)", " (maximum, fees deducted)") } else { "" };
            let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                format!("{warning}Send from your shielded ZEC\n\nFrom profile: {from_label}\nTo: {to}\nAmount: {amount} ZEC{max_note}\nNetwork fee: {fee} ZEC (ZIP-317)\n\nThis is irreversible.\n\nConfirm this transfer?")
            } else {
                format!("{warning}Envoi depuis vos ZEC protégés\n\nDepuis le profil : {from_label}\nVers : {to}\nMontant : {amount} ZEC{max_note}\nFrais réseau : {fee} ZEC (ZIP-317)\n\nC'est irréversible.\n\nConfirmer cet envoi ?")
            };
            // Puis le délai d'annulation, avant la signature.
            shielded_dialog(&app, ("Confirmer l'envoi", "Confirm the transfer"), message) && send_grace_period(&app).is_ok()
        };
        let sent = if max {
            api::send_zec_shielded_max(&dir, &password, profile_index, &to, confirm)
        } else {
            api::send_zec_shielded(&dir, &password, profile_index, &to, &amount, confirm)
        };
        match sent.t_err()? {
            Some(txid) => {
                // Destinataire mémorisé après une diffusion réussie seulement.
                let _ = sent_recipients::record_sent(&dir, "zec_shielded", &to);
                ZECS_SYNC_KICK.store(true, Ordering::SeqCst);
                Ok(txid)
            }
            None => Err(translate_error("Envoi annulé (confirmation refusée).")),
        }
    })
    .await
}

/// Solde Zcash protégé du profil (lu dans la base locale, aucun appel réseau).
#[tauri::command]
async fn zec_shielded_balance(profile_index: u32, app: tauri::AppHandle) -> Result<ShieldedBalanceDto, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let balance = api::zec_shielded_balance(&dir, profile_index).t_err()?;
        let synced = matches!((balance.scanned_height, balance.chain_height), (Some(s), Some(c)) if s + 2 >= c);
        Ok(ShieldedBalanceDto {
            spendable: pgp_wallet_poc::zcash::format_zec(balance.spendable),
            pending: pgp_wallet_poc::zcash::format_zec(balance.pending),
            synced,
        })
    })
    .await
}

fn wc_client(app: &tauri::AppHandle) -> Result<std::sync::Arc<pgp_wallet_poc::walletconnect::WalletConnect>, String> {
    app.state::<WcState>()
        .client
        .get()
        .cloned()
        .ok_or_else(|| translate_error("WalletConnect indisponible (démarrage impossible)"))
}

fn caip2_label(chain: &str) -> String {
    match dapp_requests::network_for_chain(chain) {
        Some(dapp_requests::Network::Evm(net)) if net.mainnet => format!("{} MAINNET — {}", net.name, lang("fonds réels", "real funds")),
        Some(dapp_requests::Network::Evm(net)) => format!("{} (testnet)", net.name),
        Some(dapp_requests::Network::Solana(_)) if chain == dapp_requests::SOLANA_MAINNET => {
            lang("Solana MAINNET — fonds réels", "Solana MAINNET — real funds").to_string()
        }
        Some(dapp_requests::Network::Solana(_)) => "Solana devnet".to_string(),
        None => lang("réseau inconnu", "unknown network").to_string(),
    }
}

/// Montant entier (plus petite unité) mis en forme avec `decimals` décimales.
fn format_units(integer: &str, decimals: Option<u8>) -> String {
    let Some(decimals) = decimals.map(usize::from) else {
        return format!("{integer} {}", lang("(unités brutes, décimales inconnues)", "(raw units, unknown decimals)"));
    };
    let (negative, digits) = integer.strip_prefix('-').map_or((false, integer), |d| (true, d));
    let padded = format!("{digits:0>width$}", width = decimals + 1);
    let (whole, frac) = padded.split_at(padded.len() - decimals);
    let frac = frac.trim_end_matches('0');
    let sign = if negative { "-" } else { "" };
    if frac.is_empty() { format!("{sign}{whole}") } else { format!("{sign}{whole}.{frac}") }
}

/// Texte libre venu d'une dApp (message à signer, champs EIP-712) montré dans
/// une boîte native : chaque ligne nettoyée (voir `dialog_label`, sans
/// troncature à 40), préfixée d'une barre verticale qui la distingue des
/// lignes de l'app — impossible d'y imiter "Réseau :" ou "Montant :" — et
/// nombre de lignes borné pour que les boutons restent visibles.
fn quoted_block(lines: impl IntoIterator<Item = String>, max_lines: usize) -> String {
    const MAX_CHARS: usize = 90;
    let all: Vec<String> = lines
        .into_iter()
        .map(|l| {
            let clean: String = l.chars().map(|c| if is_dialog_hazard(c) { ' ' } else { c }).collect();
            if clean.chars().count() > MAX_CHARS { format!("{}…", clean.chars().take(MAX_CHARS).collect::<String>()) } else { clean }
        })
        .collect();
    let mut out: Vec<String> = all.iter().take(max_lines).map(|l| format!("  │ {l}")).collect();
    if all.len() > max_lines {
        out.push(format!("  │ … ({} {})", all.len() - max_lines, lang("ligne(s) de plus", "more line(s)")));
    }
    out.join("\n")
}

fn host_of(url: &str) -> String {
    tauri::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default()
}

/// Texte de la demande préparée — le même dans la modale de l'app et dans la
/// boîte native (seule cette dernière fait foi). `danger` : au moins un
/// avertissement grave (autorisation illimitée, appel non décodé…).
fn describe_prepared(prepared: &dapp_requests::Prepared, peer: &pgp_wallet_poc::walletconnect::engine::PeerMetadata, from_label: &str, account: &str) -> (String, bool) {
    use dapp_requests::{Prepared, TypedRisk};
    use pgp_wallet_poc::evm_sign::CallKind;
    let en = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let mut danger = false;
    let mut lines: Vec<String> = Vec::new();
    let site = dialog_label(&peer.name);
    let url = dialog_label(&peer.url);
    lines.push(if en {
        format!("Request from \"{site}\"\nSite (self-declared, NOT verified): {url}")
    } else {
        format!("Demande de « {site} »\nSite (déclaré par la dApp, NON vérifié) : {url}")
    });
    let network = match prepared {
        Prepared::EvmPersonalSign { network, .. } | Prepared::EvmTypedData { network, .. } | Prepared::EvmTransaction { network, .. } => {
            dapp_requests::evm_caip2(network)
        }
        Prepared::SolanaMessage { network, .. } | Prepared::SolanaTransaction { network, .. } => {
            if network.rpc == wallet_flow::SOLANA_MAINNET.rpc { dapp_requests::SOLANA_MAINNET } else { dapp_requests::SOLANA_DEVNET }.to_string()
        }
    };
    let from_label = dialog_label(from_label);
    lines.push(if en {
        format!("Network: {}\nAccount: {account} (profile \"{from_label}\")", caip2_label(&network))
    } else {
        format!("Réseau : {}\nCompte : {account} (profil « {from_label} »)", caip2_label(&network))
    });

    let message_block = |view: &dapp_requests::MessageView| -> String {
        match &view.text {
            Some(text) => quoted_block(text.lines().map(str::to_string), 12),
            None => quoted_block(view.hex.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).into_owned()), 6),
        }
    };
    match prepared {
        Prepared::EvmPersonalSign { view, .. } | Prepared::SolanaMessage { view, .. } => {
            lines.push(lang(
                "Signature d'un MESSAGE (aucun fonds ne bouge directement) :",
                "Signing a MESSAGE (no funds move directly):",
            ).to_string());
            lines.push(message_block(view));
            if view.looks_like_hash {
                danger = true;
                lines.push(lang(
                    "⚠ Ce message a la forme d'une empreinte (hash) : le signer peut revenir à signer À L'AVEUGLE une transaction ou un ordre. Refusez si vous n'êtes pas certain de ce que c'est.",
                    "⚠ This message looks like a hash: signing it can amount to BLINDLY signing a transaction or an order. Reject unless you are certain what it is.",
                ).to_string());
            }
            if let Some(domain) = &view.siwe_domain {
                let host = host_of(&peer.url);
                if !host.is_empty() && !domain.eq_ignore_ascii_case(&host) {
                    danger = true;
                    let domain = dialog_label(domain);
                    lines.push(if en {
                        format!("⚠ The message says \"sign in to {domain}\" but the request comes from {host}: likely a phishing attempt.")
                    } else {
                        format!("⚠ Le message annonce « connexion à {domain} » mais la demande vient de {host} : tentative d'hameçonnage probable.")
                    });
                }
            }
        }
        Prepared::EvmTypedData { view, .. } => {
            let primary = dialog_label(&view.primary_type);
            let contract = view.verifying_contract.as_deref().map(dialog_address).unwrap_or_else(|| "—".into());
            let app = view.domain_name.as_deref().map(dialog_label).unwrap_or_else(|| "—".into());
            lines.push(if en {
                format!("Signing STRUCTURED DATA (EIP-712) \"{primary}\"\nApplication: {app}\nContract: {contract}")
            } else {
                format!("Signature de DONNÉES STRUCTURÉES (EIP-712) « {primary} »\nApplication : {app}\nContrat : {contract}")
            });
            match &view.risk {
                TypedRisk::Permit { spender, amount, unlimited } => {
                    danger = true;
                    let spender = spender.as_deref().map(dialog_address).unwrap_or_else(|| "?".into());
                    let amount = if *unlimited {
                        lang("un montant ILLIMITÉ", "an UNLIMITED amount").to_string()
                    } else {
                        amount.clone().map(|a| format!("{a} {}", lang("unité(s) brute(s)", "raw unit(s)"))).unwrap_or_else(|| "?".into())
                    };
                    lines.push(if en {
                        format!("⚠ SPENDING PERMISSION: this signature lets {spender} spend {amount} of your tokens (contract {contract}) WITHOUT any further confirmation from you. This is the #1 way wallets get drained.")
                    } else {
                        format!("⚠ AUTORISATION DE DÉPENSE : cette signature permet à {spender} de dépenser {amount} de vos jetons (contrat {contract}) SANS autre confirmation de votre part. C'est la première méthode de vol des portefeuilles.")
                    });
                }
                TypedRisk::Order => {
                    danger = true;
                    lines.push(lang(
                        "⚠ ORDRE DE PLACE DE MARCHÉ : cette signature peut céder vos NFT ou jetons au prix indiqué, à quiconque l'exécutera.",
                        "⚠ MARKETPLACE ORDER: this signature can hand over your NFTs or tokens at the stated price to whoever executes it.",
                    ).to_string());
                }
                TypedRisk::None => lines.push(lang(
                    "Ne signez que si vous comprenez ce que ces données autorisent.",
                    "Only sign if you understand what this data authorizes.",
                ).to_string()),
            }
            let mut field_lines: Vec<String> = view.fields.iter().map(|(p, v)| format!("{p} : {v}")).collect();
            if view.hidden_fields > 0 {
                field_lines.push(format!("… ({} {})", view.hidden_fields, lang("champ(s) non affiché(s)", "field(s) not shown")));
            }
            lines.push(quoted_block(field_lines, 12));
        }
        Prepared::EvmTransaction { network, to, value, gas_limit, gas_price, l1_fee, call, to_is_contract, token, data } => {
            let to = pgp_wallet_poc::derivation::format_address(to);
            let kind = if *to_is_contract { lang("contrat", "contract") } else { lang("adresse ordinaire", "regular address") };
            let symbol = token.as_ref().and_then(|t| t.symbol.as_deref()).map(dialog_label).unwrap_or_else(|| lang("jetons", "tokens").to_string());
            let decimals = token.as_ref().and_then(|t| t.decimals);
            let tokens = |amount: &pgp_wallet_poc::evm_sign::U256| format!("{} {symbol}", format_units(&amount.to_decimal(), decimals));
            lines.push(if en {
                format!("TRANSACTION to {to} ({kind})\n{} sent: {}", network.native_symbol, format_units(&value.to_string(), Some(18)))
            } else {
                format!("TRANSACTION vers {to} ({kind})\n{} envoyé : {}", network.native_symbol, format_units(&value.to_string(), Some(18)))
            });
            let addr = |a: &[u8; 20]| pgp_wallet_poc::derivation::format_address(a);
            lines.push(match call {
                CallKind::PlainTransfer => lang("Simple envoi d'ETH.", "Plain ETH transfer.").to_string(),
                CallKind::TokenTransfer { to, amount } => {
                    if en { format!("Token transfer: {} to {}", tokens(amount), addr(to)) } else { format!("Envoi de jetons : {} vers {}", tokens(amount), addr(to)) }
                }
                CallKind::TokenTransferFrom { from, to, amount } => {
                    if en {
                        format!("Transfer through an allowance: {} from {} to {}", tokens(amount), addr(from), addr(to))
                    } else {
                        format!("Transfert via une autorisation : {} de {} vers {}", tokens(amount), addr(from), addr(to))
                    }
                }
                CallKind::TokenApprove { spender, amount } | CallKind::IncreaseAllowance { spender, amount } => {
                    danger = true;
                    if amount.is_practically_unlimited() {
                        if en {
                            format!("⚠ UNLIMITED PERMISSION: {} will be able to spend ALL your {symbol}, now and in the future, without any further confirmation.", addr(spender))
                        } else {
                            format!("⚠ AUTORISATION ILLIMITÉE : {} pourra dépenser TOUS vos {symbol}, maintenant et à l'avenir, sans autre confirmation.", addr(spender))
                        }
                    } else if en {
                        format!("⚠ Spending permission: {} will be able to spend up to {} without any further confirmation.", addr(spender), tokens(amount))
                    } else {
                        format!("⚠ Autorisation de dépense : {} pourra dépenser jusqu'à {} sans autre confirmation.", addr(spender), tokens(amount))
                    }
                }
                CallKind::SetApprovalForAll { operator, approved: true } => {
                    danger = true;
                    if en {
                        format!("⚠ CONTROL OF THE WHOLE COLLECTION: {} will be able to transfer ALL your NFTs from this contract.", addr(operator))
                    } else {
                        format!("⚠ CONTRÔLE DE TOUTE LA COLLECTION : {} pourra transférer TOUS vos NFT de ce contrat.", addr(operator))
                    }
                }
                CallKind::SetApprovalForAll { approved: false, .. } => {
                    lang("Retrait d'une autorisation sur une collection (sans risque).", "Revoking a collection permission (safe).").to_string()
                }
                CallKind::Unknown { selector } => {
                    danger = true;
                    if en {
                        format!("⚠ UNDECODED CONTRACT CALL (function 0x{}): there is no way to know what this transaction does. Only confirm if you fully trust this site.", selector.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    } else {
                        format!("⚠ APPEL DE CONTRAT NON DÉCODÉ (fonction 0x{}) : impossible de savoir ce que fait cette transaction. Ne confirmez que si vous faites entièrement confiance à ce site.", selector.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    }
                }
            });
            if !data.is_empty() && !to_is_contract {
                danger = true;
                lines.push(lang(
                    "⚠ Des données sont jointes, mais le destinataire n'est pas un contrat.",
                    "⚠ Data is attached, but the recipient is not a contract.",
                ).to_string());
            }
            lines.push(evm_fee_line_for(api::EvmFee { gas_price: *gas_price, gas_limit: *gas_limit, l1_fee: *l1_fee }, network.native_symbol));
        }
        Prepared::SolanaTransaction { send, effects, .. } => {
            lines.push(if *send {
                lang("TRANSACTION Solana — signée ET envoyée par ce portefeuille.", "Solana TRANSACTION — signed AND sent by this wallet.")
            } else {
                lang("TRANSACTION Solana — signée ici, envoyée ensuite par la dApp.", "Solana TRANSACTION — signed here, then sent by the dApp.")
            }.to_string());
            lines.push(lang("Effets simulés sur vos comptes :", "Simulated effects on your accounts:").to_string());
            let effect_lines: Vec<String> = effects
                .iter()
                .map(|e| {
                    let name = e.label.map(str::to_string).unwrap_or_else(|| format!("{} {}", lang("jeton", "token"), e.asset));
                    let amount = format_units(&e.delta.to_string(), e.decimals);
                    let amount = if e.delta > 0 { format!("+{amount}") } else { amount };
                    format!("{name} : {amount}")
                })
                .collect();
            lines.push(quoted_block(effect_lines, 10));
            lines.push(lang(
                "Simulation : l'effet réel peut différer si l'état du réseau change d'ici l'exécution.",
                "Simulation: the actual effect may differ if the network state changes before execution.",
            ).to_string());
        }
    }
    (lines.join("\n\n"), danger)
}

fn confirm_dapp_request_native(app: &tauri::AppHandle, text: &str, danger: bool) -> bool {
    let footer = lang("Confirmer ? C'est irréversible.", "Confirm? This is irreversible.");
    app.dialog()
        .message(format!("{text}\n\n{footer}"))
        .title(lang("Demande d'une application (WalletConnect)", "Application request (WalletConnect)"))
        .kind(if danger { MessageDialogKind::Warning } else { MessageDialogKind::Info })
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn wc_pair(uri: String, app: tauri::AppHandle) -> Result<(), String> {
    wc_client(&app)?.pair(&uri).t_err()
}

#[tauri::command]
fn wc_sessions(app: tauri::AppHandle) -> Result<Vec<pgp_wallet_poc::walletconnect::SessionView>, String> {
    Ok(wc_client(&app)?.sessions())
}

#[tauri::command]
fn wc_disconnect(topic: String, app: tauri::AppHandle) -> Result<(), String> {
    wc_client(&app)?.disconnect(&topic).t_err()
}

/// Connexion d'une dApp : aucune signature, mais la dApp verra les adresses du
/// profil et pourra ensuite DEMANDER des signatures — d'où une boîte native.
#[tauri::command]
async fn wc_approve_session(proposal_id: u64, profile_index: u32, app: tauri::AppHandle) -> Result<bool, String> {
    run_blocking(move || {
        let client = wc_client(&app)?;
        let peer = client.proposal_peer(proposal_id).t_err()?;
        let (evm, solana) = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned()
            .ok_or_else(|| translate_error("adresses du profil inconnues : déverrouillez le portefeuille avec le mot de passe"))?;
        let dir = data_dir(&app)?;
        let label = api::list_profiles(&dir).into_iter().find(|p| p.index == profile_index).map(|p| p.label).unwrap_or_else(|| format!("#{profile_index}"));
        let (site, url, label) = (dialog_label(&peer.name), dialog_label(&peer.url), dialog_label(&label));
        let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!(
                "Connect \"{site}\" to your wallet?\nSite (self-declared, NOT verified): {url}\n\nProfile \"{label}\" — the site will see these addresses:\n{evm}\n{solana}\n\nIt will then be able to REQUEST signatures: each one will require your password and a confirmation like this one. Only connect sites you trust, reached through their real address."
            )
        } else {
            format!(
                "Connecter « {site} » à votre portefeuille ?\nSite (déclaré par la dApp, NON vérifié) : {url}\n\nProfil « {label} » — le site verra ces adresses :\n{evm}\n{solana}\n\nIl pourra ensuite DEMANDER des signatures : chacune exigera votre mot de passe et une confirmation comme celle-ci. Ne connectez que des sites de confiance, ouverts depuis leur vraie adresse."
            )
        };
        let confirmed = app
            .dialog()
            .message(message)
            .title(lang("Connexion d'une application (WalletConnect)", "Application connection (WalletConnect)"))
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show();
        if !confirmed {
            let _ = client.reject(proposal_id);
            return Ok(false);
        }
        client.approve(proposal_id, profile_index, &dapp_requests::Account { evm, solana }).t_err()?;
        Ok(true)
    })
    .await
}

#[tauri::command]
fn wc_reject_session(proposal_id: u64, app: tauri::AppHandle) -> Result<(), String> {
    wc_client(&app)?.reject(proposal_id).t_err()
}

#[derive(Serialize)]
struct PreparedRequestDto {
    text: String,
    danger: bool,
}

/// Analyse une demande reçue (exécution à blanc, simulation, décodage) et
/// renvoie son texte pour la modale de l'app. Une demande invalide ou
/// dangereuse par construction est refusée ici et la dApp en est informée.
#[tauri::command]
async fn wc_prepare_request(request_id: u64, app: tauri::AppHandle) -> Result<PreparedRequestDto, String> {
    run_blocking(move || {
        let client = wc_client(&app)?;
        let request = client.pending_request(request_id).ok_or_else(|| translate_error("demande introuvable ou expirée"))?;
        let session = client.session(&request.topic).ok_or_else(|| translate_error("connexion introuvable"))?;
        let prepared = match dapp_requests::prepare(&request.method, &request.params, &request.chain, &session.account()) {
            Ok(p) => p,
            Err(e) => {
                let message = format!("{e:#}");
                let _ = client.respond(request_id, Err((5000, message.clone())));
                return Err(translate_error(&message));
            }
        };
        let dir = data_dir(&app)?;
        let label = api::list_profiles(&dir).into_iter().find(|p| p.index == session.profile_index).map(|p| p.label).unwrap_or_default();
        let account = if request.chain.starts_with("solana:") { session.solana_address.clone() } else { session.evm_address.clone() };
        let (text, danger) = describe_prepared(&prepared, &session.peer, &label, &account);
        app.state::<WcState>().prepared.lock().unwrap_or_else(|p| p.into_inner()).insert(request_id, (request.topic.clone(), prepared));
        Ok(PreparedRequestDto { text, danger })
    })
    .await
}

/// Signe une demande préparée, après mot de passe ET boîte native. Refus dans
/// la boîte = refus transmis à la dApp. Échec de signature (mauvais mot de
/// passe…) : la demande reste en attente, l'utilisateur peut réessayer.
#[tauri::command]
async fn wc_approve_request(request_id: u64, password: String, app: tauri::AppHandle) -> Result<bool, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let client = wc_client(&app)?;
        let state = app.state::<WcState>();
        let (prepared_topic, prepared) = state
            .prepared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&request_id)
            .ok_or_else(|| translate_error("demande introuvable ou expirée"))?;
        let request = client.pending_request(request_id).ok_or_else(|| translate_error("demande introuvable ou expirée"))?;
        // La réponse part vers la connexion de la demande EN ATTENTE : elle doit
        // être celle de la demande préparée et affichée (défense en profondeur,
        // voir le refus des identifiants en double dans `engine`).
        if request.topic != prepared_topic {
            return Err(translate_error("la demande a changé depuis son affichage — refusée"));
        }
        let session = client.session(&request.topic).ok_or_else(|| translate_error("connexion introuvable"))?;
        let dir = data_dir(&app)?;
        let label = api::list_profiles(&dir).into_iter().find(|p| p.index == session.profile_index).map(|p| p.label).unwrap_or_default();
        let account = if request.chain.starts_with("solana:") { session.solana_address.clone() } else { session.evm_address.clone() };
        let (text, danger) = describe_prepared(&prepared, &session.peer, &label, &account);
        if !confirm_dapp_request_native(&app, &text, danger) {
            let _ = client.respond(request_id, Err((5000, "User rejected.".to_string())));
            return Ok(false);
        }
        // Transaction (fonds qui partent) : même délai d'annulation qu'un envoi ;
        // annulée, elle est refusée à la dApp.
        let moves_funds = matches!(prepared, dapp_requests::Prepared::EvmTransaction { .. } | dapp_requests::Prepared::SolanaTransaction { .. });
        if moves_funds && send_grace_period(&app).is_err() {
            let _ = client.respond(request_id, Err((5000, "User rejected.".to_string())));
            return Ok(false);
        }
        match api::sign_dapp_request(&dir, &password, session.profile_index, &session.account(), &prepared) {
            Ok(result) => client.respond(request_id, Ok(result)).t_err().map(|_| true),
            Err(e) => {
                state.prepared.lock().unwrap_or_else(|p| p.into_inner()).insert(request_id, (prepared_topic, prepared));
                Err(translate_error(&e.to_string()))
            }
        }
    })
    .await
}

#[tauri::command]
fn wc_reject_request(request_id: u64, app: tauri::AppHandle) -> Result<(), String> {
    app.state::<WcState>().prepared.lock().unwrap_or_else(|p| p.into_inner()).remove(&request_id);
    wc_client(&app)?.respond(request_id, Err((5000, "User rejected.".to_string()))).t_err()
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
        .manage(ProfileAddressCache::default())
        .manage(ProfileZcashCache::default())
        .manage(SendGrace::default())
        .manage(ProfileBtcTestnetCache::default())
        .manage(ProfileDogeCache::default())
        .manage(ProfileBtcCache::default())
        .manage(ShieldedKeysCache::default())
        .manage(MoneroKeysCache::default())
        .manage(WcState::default())
        .manage(BalanceWatchState::default())
        .manage(UsbRestoreState::default())
        .setup(|app| {
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                install_panic_hook(dir.clone());
                // Détails des transactions Solana finalisées déjà lus (données publiques) :
                // le nœud public n'en accorde qu'environ un par seconde.
                pgp_wallet_poc::sol_rpc::use_details_cache_file(dir.join("solana_tx_cache.jsonl"));
                // Clé Etherscan de l'utilisateur (historiques HyperEVM et BNB Chain).
                if let Err(e) = pgp_wallet_poc::etherscan_key::load(&dir) {
                    eprintln!("clé Etherscan : {e:#}");
                }
                // Événements WalletConnect (proposition, demande, état du relais)
                // relayés au frontend ; le contenu des demandes, lui, n'est
                // jamais relu depuis le frontend (voir `wc_prepare_request`).
                let handle = app.handle().clone();
                let sink: pgp_wallet_poc::walletconnect::EventSink = std::sync::Arc::new(move |event| {
                    let _ = handle.emit("wc-event", &event);
                });
                match pgp_wallet_poc::walletconnect::WalletConnect::start(&dir, sink) {
                    Ok(client) => {
                        let _ = app.state::<WcState>().client.set(std::sync::Arc::new(client));
                    }
                    Err(e) => eprintln!("WalletConnect indisponible : {e:#}"),
                }
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
            affiliate_names_status,
            register_affiliate_name,
            zec_shielded_balance,
            xmr_status,
            set_xmr_sync,
            rescan_private_funds,
            lock_session,
            xmr_node,
            set_xmr_node,
            zec_shield,
            zec_send_shielded,
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
            get_btc_pending_incoming,
            list_backup_drives,
            save_backup_to_usb,
            save_kit_to_usb,
            usb_restore_load,
            usb_restore_clear,
            get_token_balance,
            send_token_transaction,
            restore_wallet_from_usb,
            watch_balances,
            has_pending_tx,
            get_tx_history,
            get_token_tx_history,
            etherscan_key_status,
            set_etherscan_key,
            estimate_btc_fees,
            get_crypto_prices,
            get_market_prices,
            send_transaction,
            resolve_send_countdown,
            max_send_amount,
            send_usdc_transaction,
            get_swap_quote,
            swap_transaction,
            swap_pairs,
            swap_halts,
            get_jupiter_quote,
            jupiter_swap_transaction,
            get_cow_quote,
            cow_swap_transaction,
            cow_order_status,
            get_lifi_quote,
            lifi_swap_transaction,
            lifi_status,
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
            wc_pair,
            wc_sessions,
            wc_disconnect,
            wc_approve_session,
            wc_reject_session,
            wc_prepare_request,
            wc_approve_request,
            wc_reject_request,
            hardware_accounts,
            hardware_connect,
            hardware_remove,
            hardware_verify_address,
            hardware_balance,
            hardware_estimate_btc_fees,
            hardware_send,
            get_price_chart,
            get_portfolio_history,
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

    /// Montants d'historique exacts, même à 18 décimales (valeur relevée sur
    /// un vrai historique Avalanche).
    #[test]
    fn history_amounts_are_exact() {
        assert_eq!(format_signed_amount(Some(245_947_228_364_191_044), 18).as_deref(), Some("+0.245947228364191044"));
        assert_eq!(format_signed_amount(Some(-1_500_000), 6).as_deref(), Some("-1.500000"));
        assert_eq!(format_signed_amount(Some(0), 8).as_deref(), Some("+0.00000000"));
        assert_eq!(format_signed_amount(Some(12_345_678_901), 8).as_deref(), Some("+123.45678901"));
        assert_eq!(format_signed_amount(None, 9), None);
    }

    /// Liens ouverts dans le navigateur : explorateurs de chaque réseau EVM
    /// (transactions, adresses, jetons), Solana, Bitcoin ; rien d'autre, même
    /// déguisé (sous-domaine trompeur, http, explorateur cité en paramètre).
    #[test]
    fn external_links_are_limited_to_known_explorers() {
        for allowed in [
            "https://etherscan.io/tx/0x01",
            "https://sepolia.etherscan.io/tx/0x01",
            "https://arbiscan.io/tx/0x01",
            "https://basescan.org/tx/0x01",
            "https://polygonscan.com/tx/0x01",
            "https://snowtrace.io/tx/0x01",
            "https://bscscan.com/address/0x01",
            "https://bscscan.com/token/0x000ae314e2a2172a039b26378814c252734f556a?a=0x01",
            "https://hyperevmscan.io/address/0x01",
            "https://explorer.solana.com/tx/abc",
            "https://blockstream.info/tx/abc",
        ] {
            assert!(external_link_allowed(allowed), "{allowed}");
        }
        for refused in ["https://arbiscan.io.evil.com/tx/0x01", "http://etherscan.io/tx/0x01", "https://evil.com/?u=https://etherscan.io/", "https://bscscan.co/"] {
            assert!(!external_link_allowed(refused), "{refused}");
        }
        for net in wallet_flow::EVM_NETWORKS {
            assert!(external_link_allowed(&net.explorer_address_url("0x01", None)), "{}", net.id);
            assert!(external_link_allowed(&net.explorer_address_url("0x01", Some("0x02"))), "{}", net.id);
        }
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
        let text = transaction_confirmation_text("btc_mainnet", &real_to, "2.5 BTC", &injected_label, Some("Frais : 1200 sat"), None, None);
        // Le mot peut subsister DANS le libellé (aplati sur la ligne "Depuis le
        // profil", tronqué avant toute adresse complète) : ce qui compte est
        // qu'aucune AUTRE ligne ne se présente comme destinataire ou montant.
        assert_eq!(text.lines().filter(|l| l.starts_with("Destinataire")).count(), 1, "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("Montant")).count(), 1, "{text}");
        assert!(text.contains("Destinataire : bc1qattacker\nMontant : 2.5 BTC\n"), "{text}");
        let clean = transaction_confirmation_text("btc_mainnet", "bc1qx", "1 BTC", "Principal", Some("Frais : 1 sat"), None, None);
        assert_eq!(text.lines().count(), clean.lines().count(), "le libellé ne doit ajouter aucune ligne");

        // Chaque caractère dangereux, isolément.
        for hazard in ['\n', '\r', '\t', '\u{0085}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{200B}', '\u{FEFF}', '\u{00AD}'] {
            assert!(!dialog_label(&format!("a{hazard}b")).contains(hazard), "{:?}", hazard);
            assert!(canonical_address_input(&format!("bc1q{hazard}abc")).is_err(), "{:?}", hazard);
        }
        assert_eq!(dialog_label("  Épargne   perso "), "Épargne perso");
        assert_eq!(dialog_label(&"x".repeat(100)).chars().count(), 41, "tronqué à 40 + « … »");
        // Adresse de dApp : jamais tronquée, forme EIP-55 ; sinon, libellé.
        let spender = "0x5555555555555555555555555555555555555abc";
        assert_eq!(dialog_address(spender).len(), 42);
        assert_eq!(dialog_address(spender).to_lowercase(), spender);
        assert_eq!(dialog_address("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"), "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC");
        assert_eq!(dialog_address(&format!("0x{}
{}", "1".repeat(40), "x".repeat(60))).chars().count(), 41, "pas une adresse : libellé");
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

        // Zcash transparent : l'actif absent est ZEC (pas SOL).
        assert!(recipient_warning_lines(false, "zec", Some(Empty))[0].contains("aucun ZEC"));
        assert!(recipient_warning_lines(false, "doge", Some(Empty))[0].contains("aucun DOGE"));

        // Monero, Zcash protégé : rien n'est lisible sur la chaîne — seule
        // l'alerte « nouvelle adresse », jamais une fausse panne réseau.
        for coin in ["xmr", "zecs"] {
            assert!(recipient_warning_lines(false, coin, None).is_empty(), "{coin}");
            let lines = recipient_warning_lines(true, coin, None);
            assert!(lines.len() == 1 && lines[0].contains("NOUVELLE ADRESSE"), "{coin} : {lines:?}");
        }

        // Chaque avertissement tient sur un seul paragraphe (mise en page de la boîte).
        for coin in ["evm", "btc", "sol", "usdc", "zec", "doge", "xmr", "zecs"] {
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

    /// Messages Ledger suivis d'un mot d'état ou d'un nom : traduits en
    /// conservant la valeur ; nom de compte repris tel quel.
    #[test]
    fn ledger_errors_are_translated_with_their_values() {
        assert_eq!(translate_dynamic_error("opération refusée sur le Ledger (0x6985)").unwrap(), "operation refused on the Ledger (0x6985)");
        assert_eq!(translate_dynamic_error("le Ledger a renvoyé l'erreur 0x1234").unwrap(), "the Ledger returned error 0x1234");
        assert_eq!(
            translate_dynamic_error("le Ledger n'est pas sur le bon réseau : ouvrez l'application « Bitcoin Test »").unwrap(),
            "the Ledger is not on the right network: open the app « Bitcoin Test »"
        );
        assert_eq!(
            translate_dynamic_error("ce Ledger ne correspond pas au compte « Épargne » (autre appareil ou autre phrase de récupération)").unwrap(),
            "this Ledger does not match the account \"Épargne\" (another device or another recovery phrase)"
        );
        assert_eq!(
            translate_dynamic_error("ce Trezor ne correspond pas au compte « B » (autre appareil ou autre phrase de récupération)").unwrap(),
            "this Trezor does not match the account \"B\" (another device or another recovery phrase)"
        );
        assert_eq!(translate_dynamic_error("le compte « A » n'est pas sur ce réseau").unwrap(), "the account \"A\" is not on this network");
        assert_eq!(translate_dynamic_error("données refusées par le Trezor : Invalid path").unwrap(), "data refused by the Trezor: Invalid path");
        assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == "compte matériel introuvable"));
    }

    /// Échange suspendu chez THORChain/Maya, solde SOL sous la réserve
    /// minimale : messages produits par le code de `core` lui-même (un texte
    /// renommé là-bas ferait échouer ce test).
    #[test]
    fn swap_halt_and_rent_errors_are_translated() {
        use pgp_wallet_poc::{sol_rpc, thorchain_rpc};
        assert_eq!(
            translate_dynamic_error(&thorchain_rpc::halted_message("THORChain", &["Solana"])).unwrap(),
            "THORChain has paused swaps on Solana for now (incident or maintenance on their side) — try again later or choose another provider"
        );
        assert!(translate_dynamic_error(&thorchain_rpc::halted_message("Maya", &["Bitcoin", "Zcash"])).unwrap().starts_with("Maya has paused swaps on Bitcoin and Zcash for now"));
        assert!(translate_dynamic_error(&thorchain_rpc::halted_message("Maya", &[])).unwrap().starts_with("Maya has paused swaps for now"));
        // Nœud injoignable : réserve par défaut (0,00065024 SOL).
        let rpc = sol_rpc::SolRpc::new("http://127.0.0.1:1");
        let rent = |index: u64| rpc.explain_simulation_failure(&serde_json::json!({"InsufficientFundsForRent": {"account_index": index}}), "").unwrap().to_string();
        assert!(translate_dynamic_error(&rent(0)).unwrap().starts_with("SOL balance too tight: at least 0.00065024 SOL must remain"));
        assert!(translate_dynamic_error(&rent(2)).unwrap().starts_with("another account touched by the operation would end up below Solana's minimum reserve (0.00065024 SOL)"));
    }

    /// Échanges depuis Bitcoin et Zcash : messages dynamiques de `core`
    /// traduits (formes produites par le code de `core`).
    #[test]
    fn bitcoin_and_zcash_swap_errors_are_translated() {
        assert_eq!(
            translate_dynamic_error("montant trop faible pour Maya : au moins 0.0013944 ZEC (en dessous, le dépôt serait ignoré ou son remboursement impossible)").unwrap(),
            "amount too small for Maya: at least 0.0013944 ZEC (below that, the deposit would be ignored or its refund impossible)"
        );
        assert_eq!(translate_dynamic_error("frais LI.FI de la transaction Bitcoin au-delà de 1,05 % — refusé").unwrap(), "LI.FI fees in the Bitcoin transaction above 1.05% — refused");
        assert_eq!(
            translate_dynamic_error("frais réseau Bitcoin anormalement élevés dans la transaction LI.FI (101913 sat pour ~244 vB, plafond 50 sat/vB) — refusé").unwrap(),
            "abnormally high Bitcoin network fee in the LI.FI transaction (101913 sat for ~244 vB, cap 50 sat/vB) — refused"
        );
        assert_eq!(
            translate_dynamic_error("les frais Zcash ont augmenté depuis la confirmation (0.00025000 au lieu de 0.00020000 ZEC) — relancez l'échange").unwrap(),
            "Zcash fees increased since the confirmation (0.00025000 instead of 0.00020000 ZEC) — start again"
        );
        assert_eq!(translate_dynamic_error("devis Maya refusé : amount less than dust threshold").unwrap(), "Maya quote refused: amount less than dust threshold");
        for fr in ["la transaction LI.FI envoie plus que le montant affiché — refusé", "adresse de dépôt Maya invalide", "PSBT LI.FI illisible"] {
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(text, _)| *text == fr), "{fr}");
        }
    }

    /// Messages d'erreur Dogecoin : présents dans le code (fixes), tous traduits
    /// (fixes et variables).
    #[test]
    fn dogecoin_error_messages_all_have_a_translation() {
        let sources = [include_str!("../../../core/src/doge.rs"), include_str!("../../../core/src/api.rs")];
        for message in [
            "service Dogecoin injoignable",
            "réponse du service Dogecoin illisible",
            "adresse Dogecoin invalide",
            "adresse Dogecoin invalide (somme de contrôle)",
            "adresse Dogecoin invalide (autre réseau ou autre crypto)",
            "adresse Dogecoin du profil invalide",
            "envoi vers votre propre adresse Dogecoin",
            "montant trop petit : 0,01 DOGE au moins",
            "transaction Dogecoin tronquée",
            "transaction Dogecoin invalide",
            "transaction Dogecoin invalide (octets en trop)",
            "transaction Dogecoin illisible",
            "transaction Dogecoin introuvable",
            "identifiant de transaction Dogecoin invalide",
            "transaction d'origine falsifiée (hash différent de son identifiant) — envoi refusé",
            "sortie Dogecoin introuvable dans sa transaction d'origine",
            "sortie Dogecoin qui n'appartient pas à votre adresse — envoi refusé",
            "montant d'une sortie Dogecoin annoncé faux par le service — envoi refusé",
        ] {
            assert!(sources.iter().any(|s| s.contains(&format!("\"{message}\""))), "message absent du code : {message}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == message), "sans traduction : {message}");
        }
        assert_eq!(
            translate_dynamic_error("DOGE insuffisants : 12.00000000 DOGE demandés, 3.49885600 DOGE envoyables au plus (frais déduits)").unwrap(),
            "insufficient DOGE: 12.00000000 DOGE requested, 3.49885600 DOGE sendable at most (fees deducted)"
        );
        assert_eq!(
            translate_dynamic_error("les frais Dogecoin ont augmenté depuis la confirmation (0.12000000 au lieu de 0.11000000 DOGE) — relancez l'envoi").unwrap(),
            "Dogecoin fees increased since the confirmation (0.12000000 instead of 0.11000000 DOGE) — start again"
        );
        assert_eq!(translate_dynamic_error("transaction Dogecoin refusée : Missing inputs").unwrap(), "Dogecoin transaction refused: Missing inputs");
        assert_eq!(translate_dynamic_error("service Dogecoin : réponse 429 Too Many Requests").unwrap(), "Dogecoin service: response 429 Too Many Requests");
        for prefix in ["DOGE insuffisants : ", "les frais Dogecoin ont augmenté depuis la confirmation (", "transaction Dogecoin refusée : ", "service Dogecoin : réponse ", "signature Dogecoin impossible ("] {
            assert!(sources.iter().any(|s| s.contains(prefix)), "préfixe absent du code : {prefix}");
        }
    }

    /// Chaque message d'erreur des modules matériels a sa traduction : les
    /// textes exacts du code sont relus ici, pour qu'un message renommé côté
    /// Rust ne perde pas silencieusement sa version anglaise.
    #[test]
    fn hardware_error_messages_all_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/hardware.rs"),
            include_str!("../../../core/src/trezor/mod.rs"),
            include_str!("../../../core/src/trezor/bitcoin.rs"),
            include_str!("../../../core/src/trezor/ethereum.rs"),
            include_str!("../../../core/src/trezor/solana.rs"),
        ];
        for message in [
            "compte matériel introuvable",
            "ce compte est déjà ajouté",
            "nom du compte invalide (1 à 60 caractères)",
            "nombre maximal de comptes matériels atteint",
            "l'adresse affichée par l'appareil diffère de celle enregistrée",
            "aucun Trezor détecté : branchez-le et déverrouillez-le",
            "opération refusée sur le Trezor",
            "la signature du Trezor ne correspond pas au compte attendu — transaction non diffusée",
            "la signature du Trezor ne correspond pas à la transaction attendue — transaction non diffusée",
        ] {
            assert!(sources.iter().any(|s| s.contains(message)), "message absent du code : {message}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == message), "sans traduction : {message}");
        }
    }

    /// Contrats et mints des jetons écrits dans l'interface (demandes de
    /// paiement seulement : un envoi ne passe que l'identifiant du jeton)
    /// identiques au registre Rust, dans les deux sens, réseaux compris — un QR
    /// ne peut pas désigner un autre contrat que celui des envois.
    #[test]
    fn frontend_token_contracts_match_the_registry() {
        use pgp_wallet_poc::tokens::{TokenKind, TOKENS};
        let main_js = include_str!("../../src/main.js");
        let address_of = |kind: TokenKind| match kind {
            TokenKind::Erc20 { contract } => contract,
            TokenKind::Spl { mint } => mint,
        };
        for token in TOKENS {
            let marker = format!("coin: \"{}\"", token.id);
            let line = main_js
                .lines()
                .find(|l| l.contains(&marker) && l.contains("contracts:"))
                .unwrap_or_else(|| panic!("{} absent du registre de l'interface", token.id));
            let networks = line.split("networks: [").nth(1).and_then(|r| r.split(']').next()).expect("networks");
            assert_eq!(networks.split(',').count(), token.deployments.len(), "{} : réseaux de l'interface", token.id);
            let contracts = line.split("contracts: {").nth(1).and_then(|r| r.split('}').next()).expect("contracts");
            let entries: Vec<(&str, &str)> = contracts
                .split(',')
                .map(|entry| {
                    let (network, address) = entry.split_once(':').expect("réseau: adresse");
                    (network.trim(), address.trim().trim_matches('"'))
                })
                .collect();
            assert_eq!(entries.len(), token.deployments.len(), "{} : contrats de l'interface", token.id);
            for d in token.deployments {
                assert!(networks.contains(&format!("\"{}\"", d.network)), "{} : réseau {} absent de l'interface", token.id, d.network);
                assert!(entries.contains(&(d.network, address_of(d.kind))), "{} sur {} : contrat différent dans l'interface", token.id, d.network);
            }
        }
    }

    /// Chaque message de la sauvegarde sur clé USB existe dans le code et a sa
    /// traduction anglaise (messages à numéro de part ou nom de fichier :
    /// traduits par `translate_dynamic_error`).
    #[test]
    fn usb_backup_messages_all_have_a_translation() {
        let sources = [include_str!("../../../core/src/usb_backup.rs"), include_str!("../../../core/src/api.rs"), include_str!("lib.rs")];
        for message in [
            "clé USB introuvable : branchez-la puis réessayez",
            "écriture sur la clé USB impossible",
            "relecture de la clé USB impossible",
            "la relecture de la clé USB ne correspond pas à ce qui a été écrit : clé défectueuse ?",
            "la relecture de la clé USB ne correspond pas à ce qui a été écrit",
            "numéro de part invalide",
            "identifiant de kit invalide",
            "espace insuffisant sur la clé USB",
            "la part écrite sur la clé USB ne se déchiffre pas : sauvegarde inutilisable",
            "aucune sauvegarde OpenPGP Wallet sur cette clé USB",
            "lecture de la clé USB impossible",
            "mot de passe de la part illisible sur la clé USB",
            "part de sauvegarde vide",
            "branchez deux clés USB portant deux parts différentes d'une même sauvegarde",
        ] {
            assert!(sources.iter().any(|s| s.contains(message)), "message absent du code : {message}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == message), "sans traduction : {message}");
        }
        assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| fr.starts_with("cette clé USB contient déjà une part d'une autre sauvegarde")));
        for (message, english) in [
            ("cette clé USB contient déjà la part n°2 de ce kit : deux parts sur une même clé suffiraient à tout récupérer — utilisez une autre clé", "share 2 of this kit"),
            ("sauvegarde incomplète sur la clé USB (part.asc absent)", "(part.asc missing)"),
            ("fichier de sauvegarde anormalement gros sur la clé USB (part.asc)", "(part.asc)"),
        ] {
            assert!(translate_dynamic_error(message).is_some_and(|en| en.contains(english)), "{message}");
        }
    }

    /// Consigne Ledger toujours séparée du montant ou des frais par une ligne
    /// vide (constaté sans ligne vide pour Solana, qui n'a pas de ligne de frais).
    #[test]
    fn device_note_is_set_apart_in_the_confirmation() {
        let text = |fee: Option<&str>| transaction_confirmation_text("sol_devnet", "Dest", "0.01 SOL", "Ledger — A", fee_and_device_note(fee.map(str::to_string), Some("NOTE")).as_deref(), None, None);
        assert!(text(None).contains("0.01 SOL\n\nNOTE\n\n"), "{}", text(None));
        assert!(text(Some("Frais : 212 sat")).contains("0.01 SOL\nFrais : 212 sat\n\nNOTE\n\n"));
        assert_eq!(fee_and_device_note(Some("F".into()), None).as_deref(), Some("F"));
        assert_eq!(fee_and_device_note(None, None), None);
    }
}
