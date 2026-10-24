//! Tauri commands: the only gateway between the web frontend (untrusted, must never
//! see a secret) and the crypto worker (`openpgp_wallet_core::api`). No sensitive
//! data (entropy, private key, passphrase) is ever logged here or returned to the
//! frontend; only public addresses and confirmations/errors are.

use openpgp_wallet_core::{
    address_book, api, cow, dapp_requests, external_wallets, hardware, history, messaging,
    price_history, price_rpc, sent_recipients, wallet_flow,
};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

// --- Error message translation ---------------------------------------------
//
// `core/` deliberately knows nothing about graphical interfaces (see its docs:
// designed to be reusable as is by a future CLI/mobile target), so the language
// shown to the user is a presentation concern, handled here, at the single point
// where an `anyhow::Result` error produced by `core/` becomes the `String` sent to
// the frontend. No `regex` dependency added for this: the few messages with an
// interpolated value (index, name, amount...) are rebuilt by splitting the string
// rather than with a regular expression.
static UI_LANG_IS_ENGLISH: AtomicBool = AtomicBool::new(false);

/// Is the unlocked main profile the developer's wallet (THOR address = the app's
/// affiliate address)? Only that wallet sees and can use the affiliate name
/// registration.
static IS_AFFILIATE_WALLET: AtomicBool = AtomicBool::new(false);

/// Called by the frontend whenever the language changes (FR/EN button) and at
/// startup. A simple process-wide boolean is enough: it is only a display
/// preference, never security data.
#[tauri::command]
fn set_ui_language(lang: String) {
    UI_LANG_IS_ENGLISH.store(lang == "en", Ordering::Relaxed);
}

/// Messages with no interpolated value: an exact match on the French text as
/// written in `core/` and in this file.
const EXACT_ERROR_TRANSLATIONS: &[(&str, &str)] = &[
    // Solana (core/src/sol_rpc.rs)
    (
        openpgp_wallet_core::sol_rpc::BLOCKHASH_EXPIRED_ERROR,
        "the transaction expired before being sent (Solana validity window exceeded) — nothing was sent or debited, try again",
    ),
    // EVM networks (core/src/api.rs, history.rs)
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
    // core/src/usb_backup.rs, USB drive backup
    ("clé USB introuvable : branchez-la puis réessayez", "USB drive not found: plug it in and try again"),
    ("écriture sur la clé USB impossible", "cannot write to the USB drive"),
    ("relecture de la clé USB impossible", "cannot read back the USB drive"),
    ("la relecture de la clé USB ne correspond pas à ce qui a été écrit : clé défectueuse ?", "reading the USB drive back does not match what was written: faulty drive?"),
    ("la relecture de la clé USB ne correspond pas à ce qui a été écrit", "reading the USB drive back does not match what was written"),
    ("numéro de part invalide", "invalid share number"),
    ("identifiant de kit invalide", "invalid kit identifier"),
    ("nom de la sauvegarde : 1 à 30 caractères (lettres, chiffres, espaces, - _)", "backup name: 1 to 30 characters (letters, digits, spaces, - _)"),
    ("un dossier de sauvegarde de ce nom existe déjà sur la clé USB : choisissez un autre nom", "a backup folder with this name already exists on the USB drive: choose another name"),
    ("plusieurs sauvegardes complètes trouvées : choisissez celle à restaurer", "several complete backups found: choose the one to restore"),
    // core/src/api.rs, new device password
    ("mot de passe trop court : au moins 12 caractères", "password too short: at least 12 characters"),
    ("mot de passe trop faible ou trop prévisible : mélangez lettres, chiffres et symboles", "password too weak or too predictable: mix letters, digits and symbols"),
    // app: backup kit kept on the Rust side, restore from files
    ("kit de sauvegarde introuvable : générez-en un nouveau", "backup kit not found: create a new one"),
    ("type de fichier de sauvegarde inconnu", "unknown backup file type"),
    ("fichier anormalement gros pour une sauvegarde", "file abnormally large for a backup"),
    ("choisissez les fichiers des deux parts", "choose the files of both shares"),
    // core/src/zcash.rs, core/src/api.rs: height announced by the server
    ("hauteur de chaîne Zcash hors limites", "Zcash chain height out of range"),
    ("serveur Zcash trop lent : nouvel essai au prochain passage", "Zcash server too slow: trying again at the next pass"),
    // core: a server chosen by the user, approved in the secure window first
    ("ajout du réseau annulé", "network not added"),
    ("nœud Monero non modifié (confirmation refusée)", "Monero node not changed (confirmation declined)"),
    // core/src/blockscout.rs
    ("l'explorateur de ce réseau refuse pour l'instant les requêtes automatiques : historique indisponible", "this network's explorer currently refuses automated requests: history unavailable"),
    ("historique de ce réseau momentanément indisponible (limite du service atteinte) — réessayez plus tard", "this network's history is temporarily unavailable (service limit reached) — try again later"),
    // core/src/alchemy.rs, core/src/nodereal.rs
    ("historique de ce réseau indisponible dans cette version de l'app", "this network's history is unavailable in this version of the app"),
    ("le service d'historique a renvoyé un autre jeton que celui demandé", "the history service returned a different token than the one requested"),
    // core/src/api.rs, xStocks tokenized shares
    ("transferts de ce jeton suspendus par son émetteur : réessayez plus tard", "transfers of this token are paused by its issuer: try again later"),
    ("l'émetteur de ce jeton a ajouté une règle de transfert que l'app ne gère pas encore : envoi refusé, rien n'a été dépensé", "this token's issuer added a transfer rule the app doesn't support yet: transfer refused, nothing was spent"),
    ("le coefficient de ce jeton change en ce moment (dividende ou division d'action) : réessayez dans quelques minutes", "this token's multiplier is changing right now (dividend or stock split): try again in a few minutes"),
    ("montant trop petit pour ce jeton", "amount too small for this token"),
    ("coefficient d'affichage absent du mint", "display multiplier missing from the token"),
    ("coefficient d'affichage illisible", "unreadable display multiplier"),
    ("mint du jeton inattendu sur le réseau", "unexpected token on the network"),
    // core/src/api.rs, backup shares that do not belong together
    ("ces deux parts viennent de deux kits de sauvegarde différents : utilisez deux parts d'un même kit", "these two shares come from two different backup kits: use two shares of the same kit"),
    ("ces deux parts ne redonnent pas le portefeuille de leur kit : essayez avec une autre part de ce kit", "these two shares do not give back their kit's wallet: try another share of this kit"),
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
    // core/src/api.rs: "known hot wallet weaknesses" audit
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
    // core/src/api.rs + app/src-tauri/src/lib.rs: self-review round 22
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
    ("Suppression annulée (confirmation refusée).", "Deletion cancelled (confirmation refused)."),
    ("Échange annulé (confirmation refusée).", "Swap cancelled (confirmation refused)."),
    ("Opération annulée (confirmation refusée).", "Operation cancelled (confirmation refused)."),
    ("Opération annulée pendant le délai d'annulation.", "Operation cancelled during the cancellation delay."),
    ("vos ADA sont déjà délégués à ce pool", "your ADA is already delegated to this pool"),
    ("aucune récompense à retirer pour l'instant", "no rewards to withdraw yet"),
    ("vos ADA ne sont pas délégués", "your ADA is not delegated"),
    ("liste des pools Cardano indisponible pour l'instant", "Cardano pool list unavailable right now"),
    ("aucun ADA sur cette adresse pour payer les frais du réseau", "no ADA on this address to pay the network fee"),
    ("adresse Cardano sans clé de mise en jeu : délégation impossible", "Cardano address without a stake key: delegation impossible"),
    ("identifiant de pool Cardano invalide", "invalid Cardano pool id"),
    ("pool Cardano non choisi", "no Cardano pool chosen"),
    ("clé de mise en jeu d'un autre compte — refusé", "stake key of another account — refused"),
    ("les frais Cardano ont changé depuis la confirmation — relancez l'opération", "Cardano fees changed since the confirmation — start the operation again"),
    ("l'état de votre délégation Cardano a changé depuis la confirmation — relancez l'opération", "your Cardano delegation changed since the confirmation — start the operation again"),
    ("l'état de votre staking Solana a changé depuis la confirmation — relancez l'opération", "your Solana staking changed since the confirmation — start the operation again"),
    ("ce validateur n'est plus proposé (retard de votes, commission relevée ou mise trop grosse) — choisissez-en un autre", "this validator is no longer offered (behind on votes, raised commission or too much stake) — choose another one"),
    ("trop de comptes de mise : retirez d'abord ceux qui sont arrêtés", "too many stake accounts: withdraw the stopped ones first"),
    ("compte de mise introuvable", "stake account not found"),
    ("ce compte n'est pas un compte de mise", "this account is not a stake account"),
    ("compte de mise illisible", "unreadable stake account"),
    ("ce compte de mise n'est pas sous votre contrôle", "this stake account is not under your control"),
    ("ce compte n'est pas en cours de staking", "this account is not staking"),
    ("arrêtez d'abord le staking de ce compte (désactivation), puis retirez-le à l'époque suivante", "stop staking this account first (deactivation), then withdraw it in the next epoch"),
    ("ce compte de mise est verrouillé par son créateur : retrait impossible pour l'instant", "this stake account is locked by its creator: withdrawal is not possible yet"),
    ("retrait pas encore possible : la désactivation n'est pas terminée — réessayez à l'époque suivante", "withdrawal not possible yet: deactivation is not finished — try again in the next epoch"),
    ("la simulation ne donne pas le résultat annoncé — opération refusée par sécurité", "the simulation does not give the announced result — operation refused for safety"),
    ("aucun validateur Solana ne remplit les critères en ce moment — réessayez plus tard", "no Solana validator meets the criteria right now — try again later"),
    ("montant à staker absent", "no amount to stake"),
    ("il faut au moins 0.000005 SOL sur votre adresse pour les frais", "you need at least 0.000005 SOL on your address for the fee"),
    ("graine du compte de mise absente", "stake account seed missing"),
    ("adresse du compte de mise incohérente", "inconsistent stake account address"),
    ("validateur absent", "no validator"),
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
    // Tron (core/src/tron.rs, core/src/api.rs)
    ("nœud Tron injoignable", "Tron node unreachable"),
    ("réponse du nœud Tron illisible", "unreadable Tron node response"),
    ("adresse Tron invalide", "invalid Tron address"),
    ("adresse Tron invalide (somme de contrôle)", "invalid Tron address (checksum)"),
    ("adresse Tron invalide (autre réseau)", "invalid Tron address (another network)"),
    ("envoi vers votre propre adresse Tron", "sending to your own Tron address"),
    ("bloc Tron illisible", "unreadable Tron block"),
    ("TRX insuffisants pour couvrir les frais du réseau", "not enough TRX to cover the network fee"),
    ("transfert de jeton Tron refusé en simulation (solde de jeton insuffisant ?)", "Tron token transfer refused in simulation (not enough tokens?)"),
    ("appel du contrat Tron refusé par le nœud", "Tron contract call refused by the node"),
    ("réponse du contrat Tron illisible", "unreadable Tron contract response"),
    ("énergie du transfert Tron inconnue", "Tron transfer energy unknown"),
    ("frais du transfert Tron anormalement élevés — envoi refusé", "abnormally high Tron transfer fee — transfer refused"),
    ("jeton TRC-20 attendu", "TRC-20 token expected"),
    // XRP Ledger (core/src/xrp.rs, core/src/api.rs)
    ("nœud XRP injoignable", "XRP node unreachable"),
    ("réponse du nœud XRP illisible", "unreadable XRP node response"),
    (
        "adresse XRP « X » non prise en charge : demandez l'adresse classique r… et le tag de destination",
        "XRP \"X\" address not supported: ask for the classic r… address and the destination tag",
    ),
    ("adresse XRP invalide", "invalid XRP address"),
    ("adresse XRP invalide (somme de contrôle)", "invalid XRP address (checksum)"),
    ("solde XRP illisible", "unreadable XRP balance"),
    ("séquence XRP illisible", "unreadable XRP sequence"),
    ("réserve XRP illisible", "unreadable XRP reserve"),
    ("registre XRP illisible", "unreadable XRP ledger"),
    ("frais XRP illisibles", "unreadable XRP fee"),
    ("envoi vers votre propre adresse XRP", "sending to your own XRP address"),
    ("compte XRP pas encore activé : il doit d'abord recevoir au moins 1 XRP", "XRP account not activated yet: it must first receive at least 1 XRP"),
    ("compte XRP pas encore activé", "XRP account not activated yet"),
    ("ce destinataire exige un tag de destination (plateforme d'échange) : renseignez-le", "this recipient requires a destination tag (exchange): fill it in"),
    ("ce destinataire n'accepte que les paiements qu'il a autorisés, et pas le vôtre", "this recipient only accepts payments it has authorized, and not yours"),
    ("XRP insuffisants : tout le solde est bloqué par la réserve du réseau", "insufficient XRP: the whole balance is locked by the network reserve"),
    ("frais du réseau XRP anormalement élevés — envoi refusé", "abnormally high XRP network fee — transfer refused"),
    ("clé XRP invalide", "invalid XRP key"),
    ("tag de destination invalide (nombre entier de 0 à 4294967295)", "invalid destination tag (whole number from 0 to 4294967295)"),
    ("tag de destination : réservé aux envois XRP", "destination tag: only for XRP transfers"),
    ("frais XRP manquants", "XRP fee missing"),
    // Stellar (core/src/stellar.rs, core/src/api.rs)
    ("serveur Stellar injoignable", "Stellar server unreachable"),
    ("réponse du serveur Stellar illisible", "unreadable Stellar server response"),
    ("montant Stellar illisible", "unreadable Stellar amount"),
    ("ceci est une clé secrète Stellar (S…), pas une adresse : ne la communiquez jamais", "this is a Stellar SECRET key (S…), not an address: never share it"),
    (
        "adresse Stellar « M… » (muxée) non prise en charge : demandez l'adresse G… et le mémo",
        "Stellar \"M…\" (muxed) address not supported: ask for the G… address and the memo",
    ),
    ("adresse Stellar invalide", "invalid Stellar address"),
    ("adresse Stellar invalide (somme de contrôle)", "invalid Stellar address (checksum)"),
    ("mémo Stellar trop long (28 caractères au plus)", "Stellar memo too long (28 characters at most)"),
    ("mémo Stellar invalide (lettres, chiffres et ponctuation ASCII seulement)", "invalid Stellar memo (ASCII letters, digits and punctuation only)"),
    ("solde Stellar illisible", "unreadable Stellar balance"),
    ("séquence Stellar illisible", "unreadable Stellar sequence"),
    ("registre Stellar illisible", "unreadable Stellar ledger"),
    ("réserve Stellar illisible", "unreadable Stellar reserve"),
    ("frais Stellar illisibles", "unreadable Stellar fee"),
    ("envoi vers votre propre adresse Stellar", "sending to your own Stellar address"),
    ("compte Stellar pas encore activé : il doit d'abord recevoir au moins 1 XLM", "Stellar account not activated yet: it must first receive at least 1 XLM"),
    ("ce destinataire exige un mémo (plateforme d'échange) : renseignez-le", "this recipient requires a memo (exchange): fill it in"),
    ("XLM insuffisants : tout le solde est bloqué par la réserve du réseau", "insufficient XLM: the whole balance is locked by the network reserve"),
    ("frais du réseau Stellar anormalement élevés — envoi refusé", "abnormally high Stellar network fee — transfer refused"),
    ("transaction Stellar refusée : échouée dans le registre", "Stellar transaction refused: failed in the ledger"),
    ("frais Stellar manquants", "Stellar fee missing"),
    ("mémo : réservé aux envois Stellar et Stacks", "memo: only for Stellar and Stacks transfers"),
    ("tag de destination et mémo : un seul des deux", "destination tag and memo: only one of the two"),
    // NEAR (core/src/near.rs, core/src/api.rs)
    ("nœud NEAR injoignable", "NEAR node unreachable"),
    ("réponse du nœud NEAR illisible", "unreadable NEAR node response"),
    ("montant NEAR illisible", "unreadable NEAR amount"),
    ("adresse Ethereum : pour envoyer sur Ethereum, utilisez la carte Ethereum (pas NEAR)", "Ethereum address: to send on Ethereum, use the Ethereum card (not NEAR)"),
    ("adresse NEAR invalide (minuscules seulement)", "invalid NEAR address (lowercase only)"),
    ("adresse NEAR invalide", "invalid NEAR address"),
    ("solde NEAR illisible", "unreadable NEAR balance"),
    ("configuration NEAR illisible", "unreadable NEAR configuration"),
    ("prix du gaz NEAR illisible", "unreadable NEAR gas price"),
    ("compte NEAR pas encore activé : il doit d'abord recevoir des NEAR", "NEAR account not activated yet: it must first receive some NEAR"),
    ("envoi vers votre propre adresse NEAR", "sending to your own NEAR address"),
    ("ce compte NEAR n'existe pas : vérifiez l'adresse", "this NEAR account does not exist: check the address"),
    ("NEAR insuffisants pour couvrir les frais du réseau", "not enough NEAR to cover the network fee"),
    ("clé d'accès NEAR illisible", "unreadable NEAR access key"),
    ("bloc NEAR illisible", "unreadable NEAR block"),
    ("index NEAR injoignable", "NEAR index unreachable"),
    ("réponse de l'index NEAR illisible", "unreadable NEAR index response"),
    ("frais NEAR manquants", "NEAR fee missing"),
    // Cardano (core/src/cardano.rs, core/src/api.rs)
    ("service Cardano injoignable", "Cardano service unreachable"),
    ("réponse du service Cardano illisible", "unreadable Cardano service response"),
    ("montant Cardano illisible", "unreadable Cardano amount"),
    ("adresse de mise en jeu Cardano (stake1…), pas une adresse de paiement", "Cardano staking address (stake1…), not a payment address"),
    ("adresse Cardano d'un réseau de test — refusée", "Cardano address from a test network — refused"),
    ("ancienne adresse Cardano (Byron) non prise en charge : demandez une adresse addr1…", "old Cardano address (Byron) not supported: ask for an addr1… address"),
    ("adresse Cardano invalide", "invalid Cardano address"),
    ("adresse Cardano d'un autre réseau — refusée", "Cardano address from another network — refused"),
    ("adresse de contrat Cardano (script) : envoi refusé, les fonds pourraient y rester bloqués", "Cardano contract (script) address: transfer refused, funds could stay locked there"),
    ("paramètres Cardano illisibles", "unreadable Cardano parameters"),
    ("état du réseau Cardano illisible", "unreadable Cardano network state"),
    ("sortie Cardano illisible", "unreadable Cardano output"),
    ("envoi vers votre propre adresse Cardano", "sending to your own Cardano address"),
    ("aucun ADA envoyable sur cette adresse", "no sendable ADA on this address"),
    ("ADA insuffisants pour couvrir les frais et le minimum d'une sortie", "not enough ADA to cover the fee and the minimum of an output"),
    ("les frais Cardano ont changé depuis la confirmation — relancez l'envoi", "Cardano fees changed since the confirmation — start again"),
    ("frais Cardano manquants", "Cardano fee missing"),
    // Stacks (core/src/stacks.rs, core/src/api.rs)
    ("service Stacks injoignable", "Stacks service unreachable"),
    ("réponse du service Stacks illisible", "unreadable Stacks service response"),
    ("montant Stacks illisible", "unreadable Stacks amount"),
    ("adresse de contrat Stacks : envoi refusé (adresse de portefeuille SP… attendue)", "Stacks contract address: transfer refused (SP… wallet address expected)"),
    ("adresse Stacks invalide", "invalid Stacks address"),
    ("adresse Stacks invalide (somme de contrôle)", "invalid Stacks address (checksum)"),
    ("adresse Stacks d'un autre réseau — refusée", "Stacks address from another network — refused"),
    ("mémo Stacks trop long (34 caractères au plus)", "Stacks memo too long (34 characters at most)"),
    ("mémo Stacks invalide (lettres, chiffres et ponctuation ASCII seulement)", "invalid Stacks memo (ASCII letters, digits and punctuation only)"),
    ("frais Stacks illisibles", "unreadable Stacks fee"),
    ("envoi vers votre propre adresse Stacks", "sending to your own Stacks address"),
    ("STX insuffisants pour couvrir les frais du réseau", "not enough STX to cover the network fee"),
    ("nonce Stacks illisible", "unreadable Stacks nonce"),
    ("frais Stacks manquants", "Stacks fee missing"),
    // MoonPay Trade (core/src/moonpay_trade.rs, core/src/api.rs, lib.rs)
    ("MoonPay Trade indisponible dans cette version de l'app", "MoonPay Trade unavailable in this version of the app"),
    ("MoonPay Trade n'est pas disponible dans votre pays", "MoonPay Trade is not available in your country"),
    ("MoonPay Trade ne propose pas d'échange pour cette paire en ce moment", "MoonPay Trade offers no swap for this pair right now"),
    ("MoonPay Trade ne relie pas ces deux cryptos", "MoonPay Trade does not link these two cryptos"),
    ("adresse de dépôt MoonPay Trade d'une forme que l'app ne sait pas payer — demandez un nouveau devis", "MoonPay Trade deposit address of a kind the app cannot pay — request a new quote"),
    ("adresse de dépôt MoonPay Trade invalide — refus", "invalid MoonPay Trade deposit address — refused"),
    ("adresse refusée par MoonPay Trade (format)", "address refused by MoonPay Trade (format)"),
    ("adresse refusée par le contrôle de conformité de MoonPay Trade", "address refused by MoonPay Trade's compliance screening"),
    ("clé MoonPay Trade refusée", "MoonPay Trade key refused"),
    ("devis MoonPay Trade illisible (données)", "unreadable MoonPay Trade quote (data)"),
    ("devis MoonPay Trade illisible (valeur)", "unreadable MoonPay Trade quote (value)"),
    ("devis MoonPay Trade illisible (montant vendu)", "unreadable MoonPay Trade quote (amount sold)"),
    ("devis MoonPay Trade illisible (montant reçu)", "unreadable MoonPay Trade quote (amount received)"),
    ("devis MoonPay Trade illisible (minimum reçu)", "unreadable MoonPay Trade quote (minimum received)"),
    ("devis MoonPay Trade illisible (commission)", "unreadable MoonPay Trade quote (fee)"),
    ("devis MoonPay Trade sans adresse de dépôt", "MoonPay Trade quote without a deposit address"),
    ("devis MoonPay Trade sans appel — refus", "MoonPay Trade quote without a call — refused"),
    ("devis MoonPay Trade sans destinataire", "MoonPay Trade quote without a recipient"),
    ("devis MoonPay Trade sans identifiant", "MoonPay Trade quote without an identifier"),
    ("devis MoonPay Trade d'une forme inattendue — refus", "MoonPay Trade quote of an unexpected form — refused"),
    ("devis MoonPay Trade d'une forme non prise en charge — refus", "MoonPay Trade quote of an unsupported form — refused"),
    ("devis MoonPay Trade sans routeur", "MoonPay Trade quote without a router"),
    ("l'échange MoonPay Trade ferait sortir une autre crypto de votre portefeuille — refus de signer", "the MoonPay Trade swap would take another crypto out of your wallet — refusing to sign"),
    ("l'échange MoonPay Trade toucherait un autre actif de votre portefeuille (NFT ou autorisation globale) — refus de signer", "the MoonPay Trade swap would touch another asset of your wallet (NFT or global approval) — refusing to sign"),
    ("l'échange MoonPay Trade autoriserait un autre contrat ou un autre montant — refus de signer", "the MoonPay Trade swap would approve another contract or another amount — refusing to sign"),
    ("l'échange MoonPay Trade échouerait (simulation) — rien n'a été envoyé", "the MoonPay Trade swap would fail (simulation) — nothing was sent"),
    ("la transaction MoonPay Trade appelle un autre contrat que son routeur — refus de signer", "the MoonPay Trade transaction calls another contract than its router — refusing to sign"),
    ("la transaction MoonPay Trade enverrait un autre montant — refus de signer", "the MoonPay Trade transaction would send another amount — refusing to sign"),
    ("le devis MoonPay Trade livre une autre crypto — refus", "the MoonPay Trade quote delivers another crypto — refused"),
    ("le devis MoonPay Trade porte sur un autre montant — refus", "the MoonPay Trade quote is for another amount — refused"),
    ("le devis MoonPay Trade vend une autre crypto — refus", "the MoonPay Trade quote sells another crypto — refused"),
    ("le dépôt MoonPay Trade n'est pas un simple virement du jeton — refus de signer", "the MoonPay Trade deposit is not a plain token transfer — refusing to sign"),
    ("le dépôt MoonPay Trade n'est pas un simple virement du montant exact — refus de signer", "the MoonPay Trade deposit is not a plain transfer of the exact amount — refusing to sign"),
    ("le dépôt MoonPay Trade porte sur un autre montant — refus de signer", "the MoonPay Trade deposit is for another amount — refusing to sign"),
    ("minimum de réception MoonPay Trade incohérent — refus", "inconsistent MoonPay Trade minimum to receive — refused"),
    ("montant trop faible pour MoonPay Trade", "amount too small for MoonPay Trade"),
    ("montant trop élevé pour MoonPay Trade", "amount too large for MoonPay Trade"),
    ("mémo de dépôt MoonPay Trade non pris en charge — refus", "MoonPay Trade deposit memo not supported — refused"),
    ("réponse de MoonPay Trade illisible", "unreadable MoonPay Trade response"),
    ("la transaction MoonPay Trade ne garantit pas le minimum affiché — refus de signer", "the MoonPay Trade transaction does not guarantee the displayed minimum — refusing to sign"),
    ("le devis MoonPay Trade a expiré pendant la confirmation — rien n'a été envoyé, relancez l'échange", "the MoonPay Trade quote expired during the confirmation — nothing was sent, start the swap again"),
    ("crypto non échangeable via MoonPay Trade", "crypto not swappable via MoonPay Trade"),
    ("échange MoonPay Trade par le routeur : même réseau seulement", "MoonPay Trade swap through the router: same network only"),
    ("transaction MoonPay Trade incohérente — échange refusé", "inconsistent MoonPay Trade transaction — swap refused"),
    ("l'échange MoonPay Trade n'est pas au nom de ce profil — échange refusé", "the MoonPay Trade swap is not in this profile's name — swap refused"),
    // Bittensor (core/src/bittensor.rs, core/src/api.rs)
    ("adresse Bittensor invalide", "invalid Bittensor address"),
    ("adresse Bittensor invalide (somme de contrôle)", "invalid Bittensor address (checksum)"),
    ("réponse du nœud Bittensor illisible", "unreadable Bittensor node response"),
    ("réponse du nœud Bittensor sans résultat", "Bittensor node response without a result"),
    ("compte Bittensor illisible", "unreadable Bittensor account"),
    ("le format des transactions Bittensor a changé : mettez l'app à jour", "the Bittensor transaction format changed: update the app"),
    ("version du runtime Bittensor illisible", "unreadable Bittensor runtime version"),
    ("version des transactions Bittensor illisible", "unreadable Bittensor transaction version"),
    ("métadonnées Bittensor illisibles", "unreadable Bittensor metadata"),
    ("métadonnées Bittensor d'une version inattendue : mettez l'app à jour", "Bittensor metadata of an unexpected version: update the app"),
    ("ce nœud n'est pas sur le réseau principal Bittensor", "this node is not on the Bittensor main network"),
    ("empreinte de bloc Bittensor invalide", "invalid Bittensor block hash"),
    ("numéro de bloc Bittensor absent", "Bittensor block number missing"),
    ("numéro de bloc Bittensor invalide", "invalid Bittensor block number"),
    ("nonce Bittensor illisible", "unreadable Bittensor nonce"),
    ("réponse de validation Bittensor inattendue", "unexpected Bittensor validation response"),
    ("frais Bittensor illisibles", "unreadable Bittensor fee"),
    ("TAO insuffisants pour payer les frais du réseau", "not enough TAO to pay the network fee"),
    ("transaction Bittensor refusée : signature invalide (format du réseau changé ?) — rien n'a été envoyé", "Bittensor transaction refused: invalid signature (network format changed?) — nothing was sent"),
    ("transaction Bittensor refusée (nonce) : une autre transaction est peut-être en cours — réessayez dans un instant", "Bittensor transaction refused (nonce): another transaction may be in progress — try again in a moment"),
    ("envoi vers votre propre adresse Bittensor", "sending to your own Bittensor address"),
    ("frais Bittensor manquants", "Bittensor fee missing"),
    ("historique Bittensor indisponible dans cette version de l'app", "Bittensor history unavailable in this version of the app"),
    ("historique Bittensor momentanément indisponible (limite du service atteinte) — réessayez plus tard", "Bittensor history temporarily unavailable (service limit reached) — try again later"),
    ("aucun TAO envoyable sur cette adresse", "no sendable TAO on this address"),
    ("clé Taostats refusée", "Taostats key refused"),
    ("réponse de Taostats illisible", "unreadable Taostats response"),
    (
        "le prix a bougé pendant la préparation de l'échange (au-delà du glissement toléré) — rien n'a été envoyé, relancez l'échange",
        "the price moved while the swap was being prepared (beyond the tolerated slippage) — nothing was sent, start the swap again",
    ),
    ("montant nul", "zero amount"),
    ("montant hors limites", "amount out of range"),
    // SwapKit (core/src/swapkit.rs)
    ("SwapKit non configuré", "SwapKit is not configured"),
    ("SwapKit injoignable", "SwapKit unreachable"),
    ("échange non disponible via SwapKit entre ces deux cryptos", "swap not available via SwapKit between these two cryptos"),
    ("dépôt SwapKit d'un type inattendu — échange refusé", "unexpected SwapKit deposit type — swap refused"),
    ("dépôt SwapKit avec memo, non pris en charge — échange refusé", "SwapKit deposit with a memo, not supported — swap refused"),
    ("SwapKit a changé les cryptos de l'échange — échange refusé", "SwapKit changed the cryptos of the swap — swap refused"),
    ("SwapKit a changé les adresses de l'échange — échange refusé", "SwapKit changed the addresses of the swap — swap refused"),
    ("adresse de dépôt SwapKit absente", "SwapKit deposit address missing"),
    ("adresse de dépôt SwapKit invalide", "invalid SwapKit deposit address"),
    ("identifiant du dépôt absent", "deposit identifier missing"),
    ("identifiant du dépôt invalide", "invalid deposit identifier"),
    ("réception SwapKit absente", "SwapKit expected amount missing"),
    ("minimum SwapKit absent", "SwapKit minimum missing"),
    ("route SwapKit sans identifiant", "SwapKit route without an identifier"),
    ("montant SwapKit hors limites", "SwapKit amount out of range"),
    ("NEAR Intents injoignable", "NEAR Intents unreachable"),
    ("réponse NEAR Intents illisible", "unreadable NEAR Intents response"),
    ("Chainflip injoignable", "Chainflip unreachable"),
    ("réponse Chainflip illisible", "unreadable Chainflip response"),
    ("canal Chainflip introuvable auprès de Chainflip — échange refusé", "Chainflip channel not found at Chainflip — swap refused"),
    // Cancellation delay and "Max" button
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
        openpgp_wallet_core::derivation::BTC_ADDRESS_UNSUPPORTED,
        "Bitcoin address type not supported yet (future SegWit version): ask the recipient for another address",
    ),
    (openpgp_wallet_core::derivation::BTC_ADDRESS_MISCOPIED, "Bitcoin address not recognized: a character seems miscopied"),
    (openpgp_wallet_core::derivation::BTC_ADDRESS_OTHER_NETWORK, "address from another network than Bitcoin"),
    // Networks added by the user (core/src/custom_networks.rs)
    ("nom du réseau : 1 à 30 caractères (lettres, chiffres, espaces, - _ . ( ))", "network name: 1 to 30 characters (letters, digits, spaces, - _ . ( ))"),
    ("symbole : 1 à 10 lettres ou chiffres (ex. ETH)", "symbol: 1 to 10 letters or digits (e.g. ETH)"),
    ("identifiant de chaîne invalide", "invalid chain ID"),
    ("enregistrement des réseaux ajoutés", "could not save the added networks"),
    ("20 réseaux ajoutés au plus", "20 added networks at most"),
    ("historique indisponible : aucun explorateur indiqué pour ce réseau ajouté", "history unavailable: no explorer given for this added network"),
    (
        "adresse Bitcoin mal formée (version SegWit, encodage ou longueur incohérents)",
        "malformed Bitcoin address (inconsistent SegWit version, encoding or length)",
    ),
    // Swaps from Bitcoin (LI.FI, core/src/lifi.rs) and Zcash (Maya, core/src/api.rs)
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
    // Affiliate name (core/src/api.rs, core/src/native_deposit.rs)
    (
        "ce portefeuille n'est pas celui qui reçoit les frais d'affiliation de l'app — inscription réservée à ce dernier",
        "this wallet is not the one receiving the app's affiliate fees — registration is reserved for it",
    ),
    ("le coût du nom a changé depuis la confirmation — relancez l'inscription", "the name's cost changed since the confirmation — start the registration again"),
    ("adresse d'affiliation jamais approvisionnée sur ce réseau", "affiliate address never funded on this network"),
    ("Inscription annulée (confirmation refusée).", "Registration cancelled (confirmation declined)."),
    ("aucun nom d'affiliation prévu sur ce réseau", "no affiliate name planned on this network"),
    // Shielded Zcash (core/src/zcash_shielded.rs)
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
    // BNB Chain history (core/src/nodereal.rs)
    (openpgp_wallet_core::nodereal::KEY_MISSING, "BNB Chain history unavailable in this version of the app"),
    (openpgp_wallet_core::nodereal::LIMITED, "BNB Chain history temporarily unavailable (service limit reached) — try again later"),
    (
        openpgp_wallet_core::lifi::NO_CONFIRMED_BTC,
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
    // core/src/wallet_flow.rs (parsing functions reused by the GUI)
    (wallet_flow::EVM_ADDRESS_NOT_RECOGNIZED, "address not recognized: on this network, an address is 0x followed by 40 characters"),
    (wallet_flow::EVM_ADDRESS_WRONG_LENGTH, "address incomplete or too long: on this network, an address is 0x followed by 40 characters"),
    (wallet_flow::EVM_ADDRESS_MISCOPIED, "address miscopied: a character doesn't match (upper and lower case matter) — copy it again"),
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
    // core/src/eth_rpc.rs / sol_rpc.rs (messages with no interpolated value)
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
    (
        "serveurs Bitcoin indisponibles pour l'instant (trop de requêtes ou panne) — réessayez dans une minute",
        "Bitcoin servers unavailable right now (too many requests or outage) — try again in a minute",
    ),
    ("requête refusée par le serveur Bitcoin", "request refused by the Bitcoin server"),
    // core/src/address_book.rs
    ("cette adresse n'est pas une adresse de ce réseau", "this address does not belong to this network"),
    (
        "« Max » indisponible pour cet échange — saisissez le montant",
        "\"Max\" is not available for this swap — enter the amount",
    ),
    ("SOL insuffisants pour couvrir les frais de l'échange", "not enough SOL to cover the swap fees"),
    ("BTC insuffisants pour couvrir les frais de l'échange", "not enough BTC to cover the swap fees"),
    ("réponse esplora /utxo illisible", "unreadable esplora /utxo response"),
    ("txid invalide", "invalid txid"),
    ("txid de taille inattendue", "txid has an unexpected size"),
    ("réponse esplora /txs/mempool illisible", "unreadable esplora /txs/mempool response"),
    ("réponse esplora /txs illisible", "unreadable esplora /txs response"),
    ("réponse esplora /address illisible", "unreadable esplora /address response"),
    ("réponse esplora /tx/hex illisible", "unreadable esplora /tx/hex response"),
    ("réponse esplora /tx illisible", "unreadable esplora /tx response"),
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
    ("fenêtre de confirmation inconnue", "unknown confirmation window"),
    ("confirmation trop rapide : relisez, puis confirmez", "confirmed too quickly: read it, then confirm"),
    ("phrase de confirmation incorrecte", "the confirmation phrase does not match"),
    ("opération interrompue", "operation interrupted"),
    ("Restauration annulée (confirmation refusée).", "Restoration cancelled (confirmation refused)."),
    ("Virement annulé (confirmation refusée).", "Transfer cancelled (confirmation refused)."),
    ("Ajout annulé (clé différente refusée).", "Addition cancelled (different key refused)."),
    ("Activation annulée (confirmation refusée).", "Activation cancelled (confirmation refused)."),
    ("Désactivation annulée (confirmation refusée).", "Deactivation cancelled (confirmation refused)."),
    ("USDC n'est disponible que sur Solana mainnet.", "USDC is only available on Solana mainnet."),
    // core/src/windows_hello.rs (the fixed context of `to_anyhow`, without the dynamic
    // suffix ": {err} (code ...)", handled by translate_dynamic_error)
    ("clé TPM déjà absente, rien à supprimer", "TPM key already absent, nothing to remove"),
    // core/src/sol_rpc.rs (new SPL methods)
    ("réponse getTokenAccountBalance inattendue", "unexpected getTokenAccountBalance response"),
    ("montant getTokenAccountBalance illisible", "unreadable getTokenAccountBalance amount"),
    ("réponse getMinimumBalanceForRentExemption inattendue", "unexpected getMinimumBalanceForRentExemption response"),
    // core/src/api.rs (biometrics + USDC)
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

/// Ledger messages followed by a value (status word, app name...): French prefix ->
/// English prefix, the rest kept as is.
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

/// Refusal to add a network (core/src/custom_networks.rs) that carries a value.
fn translate_custom_network_error(msg: &str) -> Option<String> {
    let chain = |s: &str| {
        s.replace("identifiant de chaîne", "chain ID")
            .replace(" au lieu de ", " instead of ")
    };
    let url_reason = |reason: &str| match reason {
        "https://… attendu" => Some("https://… expected"),
        "hôte manquant" => Some("missing host"),
        "identifiants dans l'adresse refusés" => Some("credentials in the address refused"),
        "« # » refusé" => Some("« # » refused"),
        "« ? » refusé" => Some("« ? » refused"),
        "https:// obligatoire (http:// seulement pour un nœud local)" => {
            Some("https:// required (http:// only for a local node)")
        }
        _ => None,
    };
    if let Some(reason) = msg.strip_prefix("adresse du RPC : ") {
        return url_reason(reason).map(|en| format!("RPC address: {en}"));
    }
    if let Some(reason) = msg.strip_prefix("adresse de l'explorateur : ") {
        return url_reason(reason).map(|en| format!("explorer address: {en}"));
    }
    if let Some(rest) = msg.strip_prefix("ce réseau est déjà dans l'app (") {
        return Some(format!(
            "this network is already in the app ({}",
            chain(rest)
        ));
    }
    if let Some(rest) = msg.strip_prefix("réseau déjà ajouté (") {
        return Some(format!("network already added ({}", chain(rest)));
    }
    if let Some(rest) = msg.strip_prefix("réseau ajouté introuvable (") {
        return Some(format!("added network not found ({}", chain(rest)));
    }
    if let Some(rest) = msg.strip_prefix("ce RPC répond pour un autre réseau (") {
        return Some(format!(
            "this RPC answers for another network ({}",
            chain(rest)
        ));
    }
    msg.strip_prefix("RPC injoignable ou invalide : ")
        .map(|rest| format!("RPC unreachable or invalid: {rest}"))
}

/// Messages with an interpolated value (index, RPC method, amount...): an exact match
/// cannot work, so they are rebuilt by splitting around the fixed part of the message.
fn translate_dynamic_error(msg: &str) -> Option<String> {
    if let Some(amount) = msg
        .strip_prefix("ADA insuffisants : il faut au moins ")
        .and_then(|r| r.strip_suffix(" ADA (dépôt et frais du réseau compris)"))
    {
        return Some(format!(
            "not enough ADA: at least {amount} ADA needed (deposit and network fee included)"
        ));
    }
    if let Some(amount) = msg
        .strip_prefix(api::BTC_DUST_PREFIX)
        .and_then(|r| r.strip_suffix(" BTC vers cette adresse"))
    {
        return Some(format!(
            "amount too small for the Bitcoin network: at least {amount} BTC to this address"
        ));
    }
    if let Some(en) = translate_custom_network_error(msg) {
        return Some(en);
    }
    use openpgp_wallet_core::wallet_flow::{MAYBE_SENT_PREFIX, MAYBE_SENT_SUFFIX};
    if let Some(id) = msg
        .strip_prefix(MAYBE_SENT_PREFIX)
        .and_then(|rest| rest.strip_suffix(MAYBE_SENT_SUFFIX))
    {
        return Some(format!("connection lost while sending: transaction {id} may have gone through — check the history before sending again"));
    }
    if let Some(n) = msg
        .strip_prefix("trop de décimales (")
        .and_then(|rest| rest.strip_suffix(" au plus pour ce jeton)"))
    {
        return Some(format!("too many decimals (at most {n} for this token)"));
    }
    if let Some(rest) = msg
        .strip_prefix("gas estimé anormalement élevé (")
        .and_then(|rest| rest.strip_suffix(") — envoi refusé"))
    {
        return Some(format!(
            "abnormally high estimated gas ({rest}) — transfer refused"
        ));
    }
    if let Some(part) = msg
        .strip_prefix("cette clé USB contient déjà la part n°")
        .and_then(|rest| rest.strip_suffix(" de ce kit : deux parts sur une même clé suffiraient à tout récupérer — utilisez une autre clé"))
    {
        return Some(format!("this USB drive already holds share {part} of this kit: two shares on one drive would be enough to recover everything — use another drive"));
    }
    if let Some(name) = msg
        .strip_prefix("sauvegarde incomplète sur la clé USB (")
        .and_then(|rest| rest.strip_suffix(" absent)"))
    {
        return Some(format!(
            "incomplete backup on the USB drive ({name} missing)"
        ));
    }
    if let Some(name) = msg
        .strip_prefix("fichier de sauvegarde anormalement gros sur la clé USB (")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some(format!(
            "abnormally large backup file on the USB drive ({name})"
        ));
    }
    if let Some((en, rest)) = LEDGER_PREFIX_TRANSLATIONS
        .iter()
        .find_map(|(fr, en)| msg.strip_prefix(fr).map(|rest| (en, rest)))
    {
        return Some(format!("{en}{rest}"));
    }
    for device in ["Ledger", "Trezor"] {
        if let Some(label) = msg
            .strip_prefix(&format!("ce {device} ne correspond pas au compte « "))
            .and_then(|rest| {
                rest.strip_suffix(" » (autre appareil ou autre phrase de récupération)")
            })
        {
            return Some(format!("this {device} does not match the account \"{label}\" (another device or another recovery phrase)"));
        }
    }
    if let Some(label) = msg
        .strip_prefix("le compte « ")
        .and_then(|rest| rest.strip_suffix(" » n'est pas sur ce réseau"))
    {
        return Some(format!("the account \"{label}\" is not on this network"));
    }
    if let Some(rest) = msg
        .strip_prefix("pas assez de SOL pour staker : il faut au moins ")
        .and_then(|rest| rest.strip_suffix(" SOL, réserve du compte de mise et frais)"))
    {
        if let Some((total, min)) = rest.split_once(" SOL sur votre adresse (mise minimale ") {
            return Some(format!("not enough SOL to stake: you need at least {total} SOL on your address (minimum stake {min} SOL, stake account reserve and fee)"));
        }
    }
    if let Some(rest) = msg.strip_prefix("mise minimale sur Solana : ") {
        return Some(format!("minimum stake on Solana: {rest}"));
    }
    if let Some(rest) = msg
        .strip_prefix("retrait possible à la fin de l'époque en cours (dans ")
        .and_then(|rest| rest.strip_suffix(" environ)"))
    {
        return Some(format!(
            "withdrawal possible at the end of the current epoch (in about {rest})"
        ));
    }
    if let Some(rest) = msg.strip_prefix("le réseau Solana refuserait cette opération : ") {
        return Some(format!(
            "the Solana network would refuse this operation: {rest}"
        ));
    }
    if let Some(rest) = msg.strip_prefix("SOL insuffisant : ") {
        let numbers: Vec<&str> = rest
            .split(' ')
            .filter(|w| w.starts_with(|c: char| c.is_ascii_digit()))
            .collect();
        if let [available, needed, reserve, kept] = numbers[..] {
            return Some(format!(
                "insufficient SOL: {available} SOL available, {needed} needed (stake, stake account reserve {reserve} SOL returned on withdrawal, fee, and {kept} SOL kept for stopping)"
            ));
        }
    }
    if let Some(rest) = msg.strip_prefix("ZEC insuffisants : ") {
        return Some(format!("insufficient ZEC: {rest}"));
    }
    // "NEAR Intents ne confirme pas votre adresse d'arrivée — échange refusé" (NEAR
    // Intents does not confirm your destination address: swap refused)
    for provider in ["NEAR Intents", "Chainflip"] {
        if let Some(what) = msg
            .strip_prefix(&format!("{provider} ne confirme pas "))
            .and_then(|rest| rest.strip_suffix(" — échange refusé"))
        {
            let what = match what {
                "un dépôt en attente" => "a pending deposit",
                "l'adresse de dépôt" => "the deposit address",
                "les cryptos de l'échange" => "the cryptos of the swap",
                "le montant" => "the amount",
                "le type de dépôt" => "the deposit type",
                "votre adresse d'arrivée" => "your destination address",
                "votre adresse de remboursement" => "your refund address",
                "le minimum de réception" => "the minimum received",
                "le minimum de réception annoncé" => "the announced minimum received",
                "l'échéance" | "l'échéance du canal" => "the deadline",
                "une échéance assez lointaine" => "a deadline far enough away",
                "des commissions raisonnables" => "reasonable fees",
                "ces cryptos" => "these cryptos",
                "un canal en attente de dépôt" => "a channel waiting for a deposit",
                "le canal" => "the channel",
                "le prix minimum" => "the minimum price",
                "un canal encore ouvert" => "an open channel",
                other => other,
            };
            return Some(format!("{provider} does not confirm {what} — swap refused"));
        }
    }
    if let Some(rest) = msg.strip_prefix("SwapKit a refusé la demande : ") {
        return Some(format!("SwapKit refused the request: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("aucune route SwapKit pour cet échange") {
        return Some(format!("no SwapKit route for this swap{rest}"));
    }
    if let Some(rest) = msg.strip_prefix("réponse SwapKit illisible (") {
        return Some(format!("unreadable SwapKit response ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("montant SwapKit illisible (") {
        return Some(format!("unreadable SwapKit amount ({rest}"));
    }
    if let Some(rest) = msg.strip_prefix("SwapKit a changé de fournisseur (") {
        return Some(format!(
            "SwapKit changed provider ({}",
            rest.replace("— échange refusé", "— swap refused")
        ));
    }
    if let Some(rest) = msg.strip_prefix("TRX insuffisants pour les frais du transfert : ") {
        return Some(format!(
            "not enough TRX for the transfer fee: {}",
            rest.replace(" disponibles, jusqu'à ", " available, up to ")
                .replace(" nécessaires", " needed")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("frais du transfert Tron anormalement élevés (")
        .and_then(|r| r.strip_suffix(") — envoi refusé"))
    {
        return Some(format!(
            "abnormally high Tron transfer fee ({rest}) — transfer refused"
        ));
    }
    if let Some(rest) = msg.strip_prefix("TRX insuffisants : ") {
        return Some(format!(
            "insufficient TRX: {}",
            rest.replace(" disponibles, ", " available, ")
                .replace(" de frais requis", " in fees required")
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction Tron refusée : ") {
        return Some(format!("Tron transaction refused: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("nœud Tron : réponse ") {
        return Some(format!("Tron node: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("nœud Tron : ") {
        return Some(format!("Tron node: {rest}"));
    }
    if let Some(rest) = msg
        .strip_prefix("paramètre Tron ")
        .and_then(|r| r.strip_suffix(" introuvable"))
    {
        return Some(format!("Tron parameter {rest} not found"));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Tron ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "Tron fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("XRP insuffisants : ") {
        return Some(format!(
            "insufficient XRP: {}",
            rest.replace(" XRP envoyables (", " XRP sendable (")
                .replace(
                    " XRP restent bloqués par la réserve du réseau), ",
                    " XRP stay locked by the network reserve), "
                )
                .replace(" XRP de frais demandés", " XRP in fees requested")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("ce destinataire n'est pas encore activé : envoyez-lui au moins ")
        .and_then(|r| r.strip_suffix(" XRP (réserve du réseau)"))
    {
        return Some(format!(
            "this recipient is not activated yet: send it at least {rest} XRP (network reserve)"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("frais du réseau XRP anormalement élevés (")
        .and_then(|r| r.strip_suffix(" XRP) — réessayez plus tard"))
    {
        return Some(format!(
            "abnormally high XRP network fee ({rest} XRP) — try again later"
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction XRP refusée : ") {
        return Some(format!(
            "XRP transaction refused: {}",
            rest.replace(
                " — frais du réseau prélevés (identifiant ",
                " — network fee charged (ID "
            )
        ));
    }
    if let Some(rest) = msg.strip_prefix("nœud XRP : réponse ") {
        return Some(format!("XRP node: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("signature XRP impossible (") {
        return Some(format!("XRP signature impossible ({rest}"));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais XRP ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "XRP fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("XLM insuffisants : ") {
        return Some(format!(
            "insufficient XLM: {}",
            rest.replace(" XLM envoyables (", " XLM sendable (")
                .replace(
                    " XLM restent bloqués par la réserve du réseau), ",
                    " XLM stay locked by the network reserve), "
                )
                .replace(" XLM de frais demandés", " XLM in fees requested")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("ce destinataire n'est pas encore activé : envoyez-lui au moins ")
        .and_then(|r| r.strip_suffix(" XLM (réserve du réseau)"))
    {
        return Some(format!(
            "this recipient is not activated yet: send it at least {rest} XLM (network reserve)"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("frais du réseau Stellar anormalement élevés (")
        .and_then(|r| r.strip_suffix(" XLM) — réessayez plus tard"))
    {
        return Some(format!(
            "abnormally high Stellar network fee ({rest} XLM) — try again later"
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction Stellar refusée : ") {
        return Some(format!("Stellar transaction refused: {rest}"));
    }
    if let Some(hash) = msg
        .strip_prefix("réseau Stellar lent : transaction ")
        .and_then(|r| {
            r.strip_suffix(
                " envoyée mais pas encore confirmée — vérifiez l'historique avant de renvoyer",
            )
        })
    {
        return Some(format!("slow Stellar network: transaction {hash} sent but not confirmed yet — check the history before sending again"));
    }
    if let Some(rest) = msg.strip_prefix("serveur Stellar : réponse ") {
        return Some(format!("Stellar server: response {rest}"));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Stellar ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "Stellar fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("NEAR insuffisants : ") {
        return Some(format!(
            "insufficient NEAR: {}",
            rest.replace(" NEAR envoyables (", " NEAR sendable (")
                .replace(
                    " NEAR restent réservés au stockage du compte), ",
                    " NEAR stay reserved for the account storage), "
                )
                .replace(" NEAR de frais demandés", " NEAR in fees requested")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("ce destinataire n'est pas encore activé : envoyez-lui au moins ")
        .and_then(|r| r.strip_suffix(" NEAR (stockage du compte)"))
    {
        return Some(format!(
            "this recipient is not activated yet: send it at least {rest} NEAR (account storage)"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("frais du réseau NEAR anormalement élevés (")
        .and_then(|r| r.strip_suffix(" NEAR) — réessayez plus tard"))
    {
        return Some(format!(
            "abnormally high NEAR network fee ({rest} NEAR) — try again later"
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction NEAR refusée : ") {
        return Some(format!("NEAR transaction refused: {rest}"));
    }
    if let Some(hash) = msg
        .strip_prefix("réseau NEAR lent : transaction ")
        .and_then(|r| {
            r.strip_suffix(
                " envoyée mais pas encore confirmée — vérifiez l'historique avant de renvoyer",
            )
        })
    {
        return Some(format!("slow NEAR network: transaction {hash} sent but not confirmed yet — check the history before sending again"));
    }
    if let Some(rest) = msg.strip_prefix("nœud NEAR : réponse ") {
        return Some(format!("NEAR node: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("nœud NEAR : ") {
        return Some(format!("NEAR node: {rest}"));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais NEAR ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "NEAR fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("ADA insuffisants : ") {
        return Some(format!(
            "insufficient ADA: {}",
            rest.replace(" ADA dépensables, ", " ADA spendable, ")
                .replace(
                    " ADA + frais demandés, et la monnaie rendue doit porter au moins ",
                    " ADA + fees requested, and the change must carry at least "
                )
                .replace(
                    " ADA — envoyez le maximum ou un montant plus petit",
                    " ADA — send the maximum or a smaller amount"
                )
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("montant trop petit : chaque envoi Cardano porte au moins ")
        .and_then(|r| r.strip_suffix(" ADA (minimum du réseau)"))
    {
        return Some(format!("amount too small: every Cardano transfer carries at least {rest} ADA (network minimum)"));
    }
    if let Some(rest) = msg
        .strip_prefix("frais Cardano anormalement élevés (")
        .and_then(|r| r.strip_suffix(" ADA) — envoi refusé"))
    {
        return Some(format!(
            "abnormally high Cardano fee ({rest} ADA) — transfer refused"
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction Cardano refusée : ") {
        return Some(format!("Cardano transaction refused: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("service Cardano : réponse ") {
        return Some(format!("Cardano service: response {rest}"));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Cardano ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "Cardano fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("STX insuffisants : ") {
        return Some(format!(
            "insufficient STX: {}",
            rest.replace(" STX disponibles", " STX available")
                .replace(" STX bloqués par le stacking)", " STX locked by stacking)")
                .replace(" STX de frais demandés", " STX in fees requested")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("frais du réseau Stacks anormalement élevés (")
        .and_then(|r| r.strip_suffix(" STX) — réessayez plus tard"))
    {
        return Some(format!(
            "abnormally high Stacks network fee ({rest} STX) — try again later"
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction Stacks refusée : ") {
        return Some(format!("Stacks transaction refused: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("service Stacks : réponse ") {
        return Some(format!("Stacks service: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("signature Stacks impossible (") {
        return Some(format!("Stacks signature impossible ({rest}"));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Stacks ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "Stacks fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("montant trop faible pour MoonPay Trade (minimum ")
        .and_then(|r| r.strip_suffix(')'))
    {
        return Some(format!(
            "amount too small for MoonPay Trade (minimum {rest})"
        ));
    }
    if let Some(rest) = msg.strip_prefix("MoonPay Trade injoignable : ") {
        return Some(format!("MoonPay Trade unreachable: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("MoonPay Trade : réponse ") {
        return Some(format!("MoonPay Trade: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("MoonPay Trade : enregistrement du dépôt refusé (") {
        return Some(format!(
            "MoonPay Trade: deposit registration refused ({rest}"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("le devis MoonPay Trade annonce des frais MoonPay supérieurs à ")
        .and_then(|r| r.strip_suffix(" % — refus"))
    {
        return Some(format!(
            "the MoonPay Trade quote announces MoonPay fees above {rest}% — refused"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("le devis MoonPay Trade prélève une commission supérieure à ")
        .and_then(|r| r.strip_suffix(" % — refus"))
    {
        return Some(format!(
            "the MoonPay Trade quote charges a fee above {rest}% — refused"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("l'échange MoonPay Trade ferait sortir ")
        .and_then(|r| r.strip_suffix(" — refus de signer"))
    {
        return Some(format!(
            "the MoonPay Trade swap would take out {} — refusing to sign",
            rest.replace(" unité(s) au lieu de ", " unit(s) instead of ")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix(
            "l'échange MoonPay Trade livrerait moins que le minimum garanti à votre adresse (",
        )
        .and_then(|r| r.strip_suffix(") — refus de signer"))
    {
        return Some(format!("the MoonPay Trade swap would deliver less than the guaranteed minimum to your address ({}) — refusing to sign", rest.replace(" au lieu d'au moins ", " instead of at least ")));
    }
    if let Some(rest) = msg
        .strip_prefix("gas estimé anormalement élevé pour l'échange MoonPay Trade (")
        .and_then(|r| r.strip_suffix(") — échange refusé"))
    {
        return Some(format!(
            "abnormally high estimated gas for the MoonPay Trade swap ({rest}) — swap refused"
        ));
    }
    if let Some(rest) = msg.strip_prefix("TAO insuffisants : ") {
        return Some(format!(
            "insufficient TAO: {}",
            rest.replace(" TAO disponibles, ", " TAO available, ")
                .replace(" TAO requis (frais ", " TAO required (fee ")
                .replace(" TAO et réserve du compte ", " TAO and account reserve ")
                .replace(" TAO compris)", " TAO included)")
        ));
    }
    if let Some(rest) =
        msg.strip_prefix("montant trop faible pour ce destinataire (compte vide) : au moins ")
    {
        return Some(format!(
            "amount too small for this recipient (empty account): at least {rest}"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("frais du réseau Bittensor anormalement élevés (")
        .and_then(|r| r.strip_suffix(" TAO) — réessayez plus tard"))
    {
        return Some(format!(
            "abnormally high Bittensor network fee ({rest} TAO) — try again later"
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("transaction Bittensor refusée par le réseau (")
        .and_then(|r| r.strip_suffix(") — rien n'a été envoyé"))
    {
        return Some(format!(
            "Bittensor transaction refused by the network ({rest}) — nothing was sent"
        ));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Bittensor ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "Bittensor fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("adresse d'un autre réseau que Bittensor (format SS58 ")
        .and_then(|r| r.strip_suffix(" au lieu de 42)"))
    {
        return Some(format!(
            "address from another network than Bittensor (SS58 format {rest} instead of 42)"
        ));
    }
    if let Some(rest) = msg.strip_prefix("le réseau Bittensor demande une donnée de transaction inconnue de cette version de l'app (").and_then(|r| r.strip_suffix(") : mettez l'app à jour")) {
        return Some(format!("the Bittensor network requires transaction data unknown to this version of the app ({rest}): update the app"));
    }
    if let Some(rest) = msg.strip_prefix("le nœud Bittensor a refusé : ") {
        return Some(format!("the Bittensor node refused: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("nœud Bittensor injoignable : ") {
        return Some(format!("Bittensor node unreachable: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("Taostats injoignable : ") {
        return Some(format!("Taostats unreachable: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("Taostats : réponse ") {
        return Some(format!("Taostats: response {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("DOGE insuffisants : ") {
        return Some(format!(
            "insufficient DOGE: {}",
            rest.replace(" demandés, ", " requested, ").replace(
                " envoyables au plus (frais déduits)",
                " sendable at most (fees deducted)"
            )
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
        .strip_prefix(
            "un autre compte touché par l'opération finirait sous la réserve minimale de Solana (",
        )
        .and_then(|rest| {
            rest.strip_suffix(" SOL), le réseau la refuserait — essayez un montant plus élevé")
        })
    {
        return Some(format!("another account touched by the operation would end up below Solana's minimum reserve ({reserve} SOL); the network would refuse it — try a larger amount"));
    }
    if let Some(rest) = msg.strip_prefix("transaction Zcash refusée par le réseau : ") {
        return Some(format!("Zcash transaction refused by the network: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("le réseau Zcash a changé de version") {
        return Some(format!(
            "the Zcash network was upgraded{rest} — update the app before sending"
        ));
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
        .and_then(|rest| {
            rest.strip_suffix(
                " (en dessous, le dépôt serait ignoré ou son remboursement impossible)",
            )
        })
        .and_then(|rest| rest.split_once(" : au moins "))
    {
        return Some(format!("amount too small for {name}: at least {minimum} (below that, the deposit would be ignored or its refund impossible)"));
    }
    if let Some(cap) = msg
        .strip_prefix("frais LI.FI de la transaction Bitcoin au-delà de ")
        .and_then(|rest| rest.strip_suffix(" — refusé"))
    {
        return Some(format!(
            "LI.FI fees in the Bitcoin transaction above {} — refused",
            cap.replace(',', ".").replace(" %", "%")
        ));
    }
    if let Some(detail) = msg
        .strip_prefix("frais réseau Bitcoin anormalement élevés dans la transaction LI.FI (")
        .and_then(|rest| rest.strip_suffix(") — refusé"))
    {
        return Some(format!(
            "abnormally high Bitcoin network fee in the LI.FI transaction ({}) — refused",
            detail.replace(" pour ", " for ").replace("plafond", "cap")
        ));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Zcash ont augmenté depuis la confirmation (")
        .and_then(|rest| {
            rest.strip_suffix(") — relancez l'échange")
                .or_else(|| rest.strip_suffix(") — relancez l'envoi"))
        })
    {
        return Some(format!(
            "Zcash fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(detail) = msg
        .strip_prefix("les frais Dogecoin ont augmenté depuis la confirmation (")
        .and_then(|rest| rest.strip_suffix(") — relancez l'envoi"))
    {
        return Some(format!(
            "Dogecoin fees increased since the confirmation ({}) — start again",
            detail.replace(" au lieu de ", " instead of ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("solde insuffisant sur l'adresse d'affiliation ") {
        return Some(format!(
            "insufficient balance on the affiliate address on {}",
            rest.replace(" disponibles, ", " available, ").replace(
                " nécessaires (dépôt + frais réseau)",
                " needed (deposit + network fee)"
            )
        ));
    }
    if let Some((name, network)) = msg
        .strip_prefix("le nom « ")
        .and_then(|rest| rest.split_once(" » appartient déjà à quelqu'un d'autre sur "))
    {
        return Some(format!(
            "the name \"{name}\" already belongs to someone else on {network}"
        ));
    }
    if let Some(rest) = msg.strip_prefix("transaction refusée par ") {
        if let Some((network, reason)) = rest.split_once(" : ") {
            return Some(format!("transaction refused by {network}: {reason}"));
        }
    }
    if let Some(rest) = msg.strip_prefix("XMR insuffisants pour les frais (") {
        return Some(format!(
            "insufficient XMR for the fee ({}",
            rest.replace(") : maximum envoyable ", "): maximum sendable ")
        ));
    }
    if let Some(rest) = msg.strip_prefix("XMR insuffisants : ") {
        let rest = rest
            .replace(" demandés", " requested")
            .replace(" disponibles", " available")
            .replace(
                " encore bloqués : 10 confirmations, ≈ 20 min",
                " still locked: 10 confirmations, ≈ 20 min",
            );
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
        if let Some(reason) =
            rest.strip_suffix(") : vérifiez l'historique dans quelques minutes avant de renvoyer")
        {
            return Some(format!("uncertain Monero broadcast ({reason}): check the history in a few minutes before sending again"));
        }
    }
    if let Some(rest) = msg.strip_prefix("réseau Monero mis à niveau (version ") {
        if let Some(version) = rest.strip_suffix(") : mettez l'app à jour avant d'envoyer") {
            return Some(format!(
                "Monero network upgraded (version {version}): update the app before sending"
            ));
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
    if let Some(rest) = msg.strip_prefix("transaction Zcash protégée : construction impossible (")
    {
        return Some(format!(
            "shielded Zcash transaction: could not build it ({rest}"
        ));
    }
    if let Some(rest) = msg.strip_prefix("memo Maya trop long pour une sortie OP_RETURN (") {
        return Some(format!(
            "Maya memo too long for an OP_RETURN output ({}",
            rest.replace("octets", "bytes")
        ));
    }
    if let Some(rest) = msg
        .strip_prefix("aucune route LI.FI dont le destinataire soit vérifiable (ponts écartés : ")
    {
        return Some(format!(
            "no LI.FI route with a verifiable recipient (bridges excluded: {rest}"
        ));
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
    if let Some(rest) = msg.strip_prefix("adresse non-testnet (préfixe 'tb' attendu, trouvé '") {
        return Some(format!(
            "non-testnet address (prefix 'tb' expected, found '{rest}"
        ));
    }
    if let Some(rest) = msg.strip_prefix("adresse non-mainnet (préfixe 'bc' attendu, trouvé '") {
        return Some(format!(
            "non-mainnet address (prefix 'bc' expected, found '{rest}"
        ));
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
    if let Some(method) = msg
        .strip_prefix("réponse ")
        .and_then(|s| s.strip_suffix(" non textuelle"))
    {
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
    if let Some(rest) =
        msg.strip_prefix("trop de tentatives incorrectes récentes ; réessayez dans ")
    {
        return Some(format!(
            "too many recent incorrect attempts; try again in {}",
            rest.replace("seconde(s)", "second(s)")
        ));
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
    if let Some(rest) = msg.strip_suffix(
        "\" n'a aucune sous-clé de chiffrement valide (expirée ou révoquée) — message non envoyé",
    ) {
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
    if let Some(rest) = msg.strip_prefix("écriture du fichier impossible : ") {
        return Some(format!("could not write the file: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("lecture du fichier impossible : ") {
        return Some(format!("could not read the file: {rest}"));
    }
    if let Some(rest) = msg.strip_prefix("fonds USDC insuffisants : ") {
        let translated = rest
            .replace(
                "disponibles (unité 10^-6 USDC)",
                "available (10^-6 USDC unit)",
            )
            .replace("requis", "required");
        return Some(format!("insufficient USDC funds: {translated}"));
    }
    if let Some(rest) = msg.strip_prefix("SOL insuffisant pour les frais") {
        if let Some((extra, numbers)) = rest.split_once(" : ") {
            let extra_en = extra.replace(
                " + création du compte de jetons du destinataire",
                " + creating the recipient's token account",
            );
            let numbers_en = numbers
                .replace("disponibles", "available")
                .replace("requis", "required");
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
    // core/src/windows_hello.rs: `to_anyhow` builds "{context} : {err} (code ...)".
    // Only the fixed context (in French) can be translated; the Windows error message
    // itself (`{err}`) is already in the operating system's language, outside our
    // control.
    const WINDOWS_HELLO_CONTEXTS: &[(&str, &str)] = &[
        (
            "ouverture du fournisseur TPM (Microsoft Platform Crypto Provider)",
            "opening the TPM provider (Microsoft Platform Crypto Provider)",
        ),
        (
            "création de la clé TPM persistée",
            "creating the persisted TPM key",
        ),
        (
            "réglage de la taille de clé TPM",
            "setting the TPM key size",
        ),
        (
            "réglage de la politique Windows Hello sur la clé TPM",
            "setting the Windows Hello policy on the TPM key",
        ),
        ("finalisation de la clé TPM", "finalizing the TPM key"),
        (
            "calcul de la taille du blob scellé",
            "computing the sealed blob size",
        ),
        (
            "scellement du secret dans le TPM",
            "sealing the secret in the TPM",
        ),
        (
            "ouverture de la clé TPM (déverrouillage biométrique désactivé ou clé absente ?)",
            "opening the TPM key (biometric unlock disabled or key missing?)",
        ),
        (
            "calcul de la taille du secret déchiffré",
            "computing the decrypted secret size",
        ),
        (
            "vérification Windows Hello refusée, annulée ou échouée",
            "Windows Hello verification refused, cancelled, or failed",
        ),
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
    // A message not in the table (most likely a raw error from a third-party library,
    // already in English/technical: reqwest, serde_json, io::Error...): left as is
    // rather than risking a wrong translation.
    msg.to_string()
}

/// Picks the French or English text according to the current UI language. Used for
/// the text of native dialogs (`app.dialog()...`), which never go through
/// `translate_error`/`.t_err()` since they are not errors but confirmation messages
/// built directly here, never returned by `core/`.
fn lang<'a>(fr: &'a str, en: &'a str) -> &'a str {
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        en
    } else {
        fr
    }
}

/// Replaces `.t_err()`: converts an error into a `String` translated into the
/// current UI language, instead of a raw `.to_string()`.
trait TranslatedResult<T> {
    fn t_err(self) -> Result<T, String>;
}

impl<T, E: std::fmt::Display> TranslatedResult<T> for Result<T, E> {
    fn t_err(self) -> Result<T, String> {
        self.map_err(|e| translate_error(&e.to_string()))
    }
}

// Without this hook, an unexpected panic (undetected bug, third-party dependency) left
// no trace at all: the window vanished instantly and silently (no console in release
// builds, see `windows_subsystem = "windows"` in main.rs). We log the panic's location
// and message, never a secret: our own `.expect()`/`panic!` only carry static
// messages, never a secret value (password, key, entropy), and a panic from a
// third-party dependency can only carry data that is already public (address, RPC
// response), since in this project a secret never travels through a panic message.
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
        // Best-effort: if writing the log fails, we must not trigger a second panic from
        // inside the hook itself.
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
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
    std::fs::create_dir_all(&dir).map_err(|e| {
        translate_error(&format!(
            "création du répertoire de données impossible : {e}"
        ))
    })?;
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
    tron: String,
    xrp: String,
    stellar: String,
    near: String,
    cardano: String,
    stacks: String,
    bittensor: String,
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
            tron: a.tron,
            xrp: a.xrp,
            stellar: a.stellar,
            near: a.near,
            cardano: a.cardano,
            stacks: a.stacks,
            bittensor: a.bittensor,
        }
    }
}

#[derive(Serialize)]
struct ProfileDto {
    index: u32,
    label: String,
    /// `null` on the JS side when the profile was created without a password: the
    /// address has not been derived yet (see `api::create_profile`), and it will appear
    /// at the next full unlock.
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

/// Label + index only, no address: used for the list of archived profiles, which
/// never needs the seed (see `api::list_archived_profiles`).
#[derive(Serialize)]
struct ProfileLabelDto {
    index: u32,
    label: String,
}

impl From<api::Profile> for ProfileLabelDto {
    fn from(p: api::Profile) -> Self {
        Self {
            index: p.index,
            label: p.label,
        }
    }
}

/// What the UI gets for each share of a new kit: its label, its number and its
/// passphrase, which the user has to read to write it down. The encrypted share and
/// its private key stay on the Rust side (`PendingKitState`): with them, a
/// compromised frontend could copy a working kit and keep full control of the wallet
/// for good.
#[derive(Serialize)]
struct BackupShareDto {
    label: String,
    passphrase: String,
    /// Kit identifier (shared by the 3 shares, see `api::backup_kit_id`) and share
    /// number: how the save commands (file, USB drive) name the share.
    kit_id: String,
    part: u8,
}

/// The kit generated last (wallet creation or regeneration), kept here until its
/// shares are saved. The save commands take a kit identifier and a share number and
/// write the content themselves, so the encrypted shares and private keys never
/// reach the UI. Memory only: replaced by the next kit, cleared by
/// `forget_pending_kit`, gone when the app closes.
#[derive(Default)]
struct PendingKitState(std::sync::Mutex<Option<PendingKit>>);

struct PendingKit {
    kit_id: String,
    shares: Vec<api::BackupShare>,
}

impl PendingKit {
    /// Share `part` (numbered from 1, as shown to the user).
    fn share(&self, part: u8) -> Result<&api::BackupShare, String> {
        part.checked_sub(1)
            .and_then(|index| self.shares.get(usize::from(index)))
            .ok_or_else(|| translate_error("numéro de part invalide"))
    }
}

/// The files written to a USB drive for one share.
fn share_files(share: &api::BackupShare) -> openpgp_wallet_core::usb_backup::ShareFiles {
    openpgp_wallet_core::usb_backup::ShareFiles {
        encrypted_share: share.encrypted_share.clone(),
        privkey_armored: share.privkey_armored.clone(),
        passphrase: Zeroizing::new(share.passphrase.clone()),
    }
}

impl Drop for PendingKit {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for share in &mut self.shares {
            share.passphrase.zeroize();
            share.encrypted_share.zeroize();
            share.privkey_armored.zeroize();
        }
    }
}

/// What the UI may show of a kit (see `BackupShareDto`).
fn backup_share_dtos(kit_id: &str, backups: &[api::BackupShare]) -> Vec<BackupShareDto> {
    backups
        .iter()
        .enumerate()
        .map(|(i, b)| BackupShareDto {
            label: b.label.clone(),
            passphrase: b.passphrase.clone(),
            kit_id: kit_id.to_owned(),
            part: (i + 1) as u8,
        })
        .collect()
}

/// Keeps a new kit on the Rust side and returns what the UI may show of it.
fn keep_pending_kit(app: &tauri::AppHandle, backups: Vec<api::BackupShare>) -> Vec<BackupShareDto> {
    let kit_id = api::backup_kit_id(&backups);
    let dtos = backup_share_dtos(&kit_id, &backups);
    *app.state::<PendingKitState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(PendingKit {
        kit_id,
        shares: backups,
    });
    dtos
}

/// Runs `f` on the pending kit, if it is the kit `kit_id` the UI names. A kit the
/// screen still shows but that was replaced or forgotten meanwhile is refused rather
/// than silently swapped for another one.
fn with_pending_kit<T>(
    app: &tauri::AppHandle,
    kit_id: &str,
    f: impl FnOnce(&PendingKit) -> Result<T, String>,
) -> Result<T, String> {
    let state = app.state::<PendingKitState>();
    let pending = state.0.lock().unwrap_or_else(|p| p.into_inner());
    let kit = pending
        .as_ref()
        .filter(|kit| kit.kit_id == kit_id)
        .ok_or_else(|| translate_error("kit de sauvegarde introuvable : générez-en un nouveau"))?;
    f(kit)
}

/// Forgets the pending kit: its shares are saved, or the screen was left.
#[tauri::command]
fn forget_pending_kit(app: tauri::AppHandle) {
    *app.state::<PendingKitState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = None;
}

#[derive(Serialize)]
struct CreateWalletDto {
    addresses: AddressesDto,
    backups: Vec<BackupShareDto>,
}

/// Saves one file of a pending kit share (`kind`: "share" for the encrypted share,
/// "privkey" for its private key) where the user chooses. Both the path and the
/// content are decided HERE, on the Rust side: the path through the native "Save as"
/// dialog, the content from `PendingKitState`. An earlier version took a `path:
/// String` from JS (a compromised frontend could write anything anywhere on disk,
/// e.g. the Windows startup folder), and the next one still took the content in
/// base64 from JS, which meant the kit had gone through the webview first.
#[tauri::command]
fn save_backup_file(
    kit_id: String,
    part: u8,
    kind: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    // Copied out of the state so the lock isn't held while the dialog is open.
    let (suggested_name, bytes) = with_pending_kit(&app, &kit_id, |kit| {
        let share = kit.share(part)?;
        match kind.as_str() {
            "share" => Ok((
                format!("{}_share.asc", share.label),
                Zeroizing::new(share.encrypted_share.clone()),
            )),
            "privkey" => Ok((
                format!("{}_privkey.asc", share.label),
                Zeroizing::new(share.privkey_armored.clone()),
            )),
            _ => Err(translate_error("type de fichier de sauvegarde inconnu")),
        }
    })?;

    let chosen = app
        .dialog()
        .file()
        .set_file_name(&suggested_name)
        .blocking_save_file();

    match chosen {
        Some(file_path) => {
            let path = file_path.into_path().t_err()?;
            std::fs::write(path, &*bytes)
                .map_err(|e| translate_error(&format!("écriture du fichier impossible : {e}")))?;
            Ok(true)
        }
        None => Ok(false), // the user cancelled the dialog
    }
}

/// Allowlist of the block explorer domains the app actually uses (see
/// `explorer_tx_prefix` in `wallet_flow.rs` and `ESPLORA_*_BASE` in `btc_rpc.rs`).
/// Stricter than a plain `https://` scheme check, which would have let a
/// compromised frontend open any page: a simple phishing vector, opened for no
/// functional benefit since no legitimate call to this command ever targets
/// anything other than these domains.
const ALLOWED_EXTERNAL_LINK_PREFIXES: [&str; 15] = [
    "https://explorer.solana.com/",
    "https://blockstream.info/",
    "https://explorer.cow.fi/",
    "https://scan.li.fi/",
    "https://blockchair.com/zcash/",
    "https://xmrchain.net/",
    "https://blockchair.com/dogecoin/",
    "https://tronscan.org/",
    "https://livenet.xrpl.org/",
    "https://stellar.expert/explorer/public/",
    "https://nearblocks.io/txns/",
    "https://cardanoscan.io/transaction/",
    "https://explorer.hiro.so/txid/",
    "https://taostats.io/extrinsic/",
    "https://taostats.io/account/",
];

/// A link to an explorer the app knows: Solana, Bitcoin, or an EVM network's
/// explorer (the origin of `explorer_tx_prefix`: Etherscan, Arbiscan, BscScan…).
/// Previously only etherscan.io and sepolia.etherscan.io were allowed, so the
/// Arbitrum, Base and Polygon history links were refused.
fn external_link_allowed(url: &str) -> bool {
    let evm_origins = wallet_flow::EVM_NETWORKS.iter().filter_map(|n| {
        let rest = n.explorer_tx_prefix.strip_prefix("https://")?;
        Some(&n.explorer_tx_prefix[..8 + rest.find('/')? + 1])
    });
    let custom_origins: Vec<&str> = openpgp_wallet_core::custom_networks::explorer_origins()
        .into_iter()
        .filter_map(|prefix| {
            let rest = prefix.strip_prefix("https://")?;
            Some(&prefix[..8 + rest.find('/')? + 1])
        })
        .collect();
    ALLOWED_EXTERNAL_LINK_PREFIXES
        .into_iter()
        .chain(evm_origins)
        .chain(custom_origins)
        .any(|prefix| url.starts_with(prefix))
}

/// Opens an external link (block explorer) in the system browser: a regular `<a
/// target="_blank">` does not open reliably in the Tauri webview (navigation
/// intercepted for security reasons), the same limit already hit for downloads (see
/// `save_backup_file`). `url` comes from the frontend (untrusted, see this
/// file's header): restricted to the allowlist above, not just to the https://
/// scheme.
#[tauri::command]
fn open_external_link(url: String, app: tauri::AppHandle) -> Result<(), String> {
    if !external_link_allowed(&url) {
        return Err(translate_error(
            "lien refusé : seuls les explorateurs de blocs connus de l'app sont autorisés",
        ));
    }
    app.opener().open_url(url, None::<&str>).t_err()
}

/// Generates a QR code (SVG) for a public address: no sensitive data, just a
/// display convenience for receiving funds.
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

// --- Secure confirmation window
// ---------------------------------------------------
//
// Sensitive actions that are not transactions (reset, backup kit, restore, Windows
// Hello, whole kit on one drive): a window styled like the app, opened HERE. The
// main page can neither create it (no window permission: capabilities/default.json
// only grants core:default), nor reach it (a different webview), nor answer in its
// place: the answer is only accepted from THIS window, identified by its label,
// which Tauri takes from the calling webview, never from the message. The same
// guarantee as the OS dialog it replaces (2026-10-07, at the user's request: easier
// to read), plus: "Cancel" by default, confirmation refused during the first second
// (an Enter key pressed in the app as it appears does not confirm it), and a phrase
// to type for the reset. Transactions (address, amount) keep the OS dialog.

/// Delay before a confirmation is accepted (guards against an accidental "Enter").
const SECURE_CONFIRM_DELAY: std::time::Duration = std::time::Duration::from_millis(900);

/// Content of a confirmation window (texts built here, in the UI language;
/// displayed through `textContent`, never as HTML).
#[derive(Clone, Serialize)]
struct SecureConfirmDetails {
    lang: &'static str,
    /// Icon: "trash", "key", "swap", "usb", "fingerprint", "globe".
    icon: &'static str,
    title: String,
    paragraphs: Vec<String>,
    note: String,
    confirm_label: String,
    cancel_label: String,
    /// Red button: destructive action.
    danger: bool,
    /// Phrase to type to confirm, and its instruction.
    phrase: Option<String>,
    phrase_prompt: Option<String>,
}

impl SecureConfirmDetails {
    fn new(
        icon: &'static str,
        title: (&str, &str),
        paragraphs: Vec<String>,
        confirm_label: (&str, &str),
    ) -> Self {
        Self {
            lang: lang("fr", "en"),
            icon,
            title: lang(title.0, title.1).to_string(),
            paragraphs,
            note: lang(
                "Vous n'avez pas demandé ça ? Cliquez sur Annuler.",
                "Didn't ask for this? Click Cancel.",
            )
            .to_string(),
            confirm_label: lang(confirm_label.0, confirm_label.1).to_string(),
            cancel_label: lang("Annuler", "Cancel").to_string(),
            danger: false,
            phrase: None,
            phrase_prompt: None,
        }
    }
}

/// Paragraph in the UI language.
fn text(fr: &str, en: &str) -> String {
    lang(fr, en).to_string()
}

struct PendingConfirm {
    details: SecureConfirmDetails,
    /// Content displayed (window shown): the starting point of the delay.
    shown_at: Option<std::time::Instant>,
    answer: std::sync::mpsc::Sender<bool>,
}

/// Open confirmation windows, by label.
#[derive(Default)]
struct SecureConfirmState(std::sync::Mutex<std::collections::HashMap<String, PendingConfirm>>);

static NEXT_CONFIRM: AtomicU64 = AtomicU64::new(1);
static OPEN_CONFIRMS: AtomicU64 = AtomicU64::new(0);

/// The main window is disabled while a confirmation is open (as under an OS
/// dialog), then re-enabled and brought back to the front.
struct MainWindowDisabled(Option<tauri::WebviewWindow>);

impl MainWindowDisabled {
    fn new(app: &tauri::AppHandle) -> Self {
        let main = app.get_webview_window("main");
        if OPEN_CONFIRMS.fetch_add(1, Ordering::SeqCst) == 0 {
            if let Some(main) = &main {
                let _ = main.set_enabled(false);
            }
        }
        Self(main)
    }
}

impl Drop for MainWindowDisabled {
    fn drop(&mut self) {
        if OPEN_CONFIRMS.fetch_sub(1, Ordering::SeqCst) == 1 {
            if let Some(main) = &self.0 {
                let _ = main.set_enabled(true);
                let _ = main.set_focus();
            }
        }
    }
}

fn finish_confirm(app: &tauri::AppHandle, label: &str, accepted: bool) {
    if let Some(pending) = app
        .state::<SecureConfirmState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(label)
    {
        let _ = pending.answer.send(accepted);
    }
}

/// Opens the window and waits for the answer: `true` only if the user confirmed IN
/// this window. Always called off the main thread (a synchronous command would
/// block there, and the window needs that thread). Closed with its X button, or
/// impossible to open: refusal.
fn secure_confirm(app: &tauri::AppHandle, details: SecureConfirmDetails) -> bool {
    let label = format!("confirm-{}", NEXT_CONFIRM.fetch_add(1, Ordering::SeqCst));
    let title = details.title.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    app.state::<SecureConfirmState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            label.clone(),
            PendingConfirm {
                details,
                shown_at: None,
                answer: sender,
            },
        );
    let main = app.get_webview_window("main");
    let mut builder = tauri::WebviewWindowBuilder::new(
        app,
        &label,
        tauri::WebviewUrl::App("confirm.html".into()),
    )
    .title(&title)
    .inner_size(460.0, 380.0)
    .resizable(false)
    .minimizable(false)
    .maximizable(false)
    .skip_taskbar(true)
    .visible(false)
    .center();
    if let Some(main) = &main {
        builder = match builder.parent(main) {
            Ok(builder) => builder,
            Err(e) => {
                eprintln!("fenêtre de confirmation : {e}");
                finish_confirm(app, &label, false);
                return false;
            }
        };
    }
    let window = match builder.build() {
        Ok(window) => window,
        Err(e) => {
            eprintln!("fenêtre de confirmation : {e}");
            finish_confirm(app, &label, false);
            return false;
        }
    };
    let disabled = MainWindowDisabled::new(app);
    {
        let app = app.clone();
        let label = label.clone();
        window.on_window_event(move |event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) {
                finish_confirm(&app, &label, false);
            }
        });
    }
    // Page never ready (loading error): shown anyway, so it can be closed.
    {
        let window = window.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            if window.is_visible().ok() == Some(false) {
                let _ = window.show();
                let _ = window.set_focus();
            }
        });
    }
    let accepted = receiver.recv().unwrap_or(false);
    // Main window re-enabled BEFORE closing: otherwise Windows brings another
    // application to the front.
    drop(disabled);
    let _ = window.destroy();
    accepted
}

/// Comparison of the typed phrase: case and repeated spaces ignored.
fn normalize_phrase(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

/// Content of the CALLING confirmation window (and of no other).
#[tauri::command]
fn secure_confirm_details(
    webview: tauri::Webview,
    state: tauri::State<SecureConfirmState>,
) -> Result<SecureConfirmDetails, String> {
    state
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(webview.label())
        .map(|p| p.details.clone())
        .ok_or_else(|| translate_error("fenêtre de confirmation inconnue"))
}

/// Content displayed: window sized to its height, matched to the theme, shown.
#[tauri::command]
fn secure_confirm_ready(
    webview: tauri::Webview,
    theme: String,
    height: f64,
    state: tauri::State<SecureConfirmState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let label = webview.label().to_string();
    // A pending confirmation window first: no other window (the main one) can be
    // resized or shown through this call (audit round 32).
    if !state
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(&label)
    {
        return Err(translate_error("fenêtre de confirmation inconnue"));
    }
    let window = app
        .get_webview_window(&label)
        .ok_or_else(|| translate_error("fenêtre de confirmation inconnue"))?;
    let height = if height.is_finite() {
        height.clamp(200.0, 760.0)
    } else {
        380.0
    };
    apply_window_frame(&window, &theme);
    let _ = window.set_size(tauri::LogicalSize::new(460.0, height));
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let mut pending = state.0.lock().unwrap_or_else(|p| p.into_inner());
    pending
        .get_mut(&label)
        .ok_or_else(|| translate_error("fenêtre de confirmation inconnue"))?
        .shown_at = Some(std::time::Instant::now());
    Ok(())
}

/// Answer from the CALLING confirmation window: a confirmation is only accepted
/// after the delay, and with the exact phrase if one is required.
#[tauri::command]
fn secure_confirm_answer(
    webview: tauri::Webview,
    accepted: bool,
    typed: Option<String>,
    state: tauri::State<SecureConfirmState>,
) -> Result<(), String> {
    let mut pending = state.0.lock().unwrap_or_else(|p| p.into_inner());
    let entry = pending
        .get(webview.label())
        .ok_or_else(|| translate_error("fenêtre de confirmation inconnue"))?;
    if accepted {
        if !entry
            .shown_at
            .is_some_and(|shown| shown.elapsed() >= SECURE_CONFIRM_DELAY)
        {
            return Err(translate_error(
                "confirmation trop rapide : relisez, puis confirmez",
            ));
        }
        if let Some(phrase) = &entry.details.phrase {
            if normalize_phrase(typed.as_deref().unwrap_or_default()) != normalize_phrase(phrase) {
                return Err(translate_error("phrase de confirmation incorrecte"));
            }
        }
    }
    if let Some(entry) = pending.remove(webview.label()) {
        let _ = entry.answer.send(accepted);
    }
    Ok(())
}

/// Work to run on the main thread (Windows Hello: as it was before its confirmation
/// moved to the secure window), from another thread.
fn on_main_thread<T: Send + 'static>(
    app: &tauri::AppHandle,
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = sender.send(work());
    })
    .map_err(|e| e.to_string())?;
    receiver
        .recv()
        .map_err(|_| translate_error("opération interrompue"))?
}

/// Found in round 22: the app's only IRREVERSIBLE action without a native
/// confirmation. Restoring, regenerating the kit, enabling/disabling Windows Hello
/// all go through an OS dialog (which a compromised frontend can neither fake nor
/// bypass); deleting the vault only went through a JavaScript `confirm()`, which
/// that same frontend can skip. A script could have erased the wallet without a
/// password or a click, and without a backup kit the funds were lost forever. No
/// password required (resetting remains the way out if it is forgotten), but a
/// native dialog, as for the other actions at this level.
///
/// Since 2026-10-07: the secure window (see `secure_confirm`), with a phrase to
/// type.
fn confirm_reset_window(app: &tauri::AppHandle) -> bool {
    let mut details = SecureConfirmDetails::new(
        "trash",
        ("Supprimer le portefeuille ?", "Delete the wallet?"),
        vec![
            text("Il sera effacé de cet ordinateur.", "It will be erased from this computer."),
            text(
                "Pour le retrouver, il vous faudra 2 parts de votre kit de sauvegarde. Sans elles, vos fonds seront perdus.",
                "To get it back, you will need 2 shares of your backup kit. Without them, your funds will be lost.",
            ),
        ],
        ("Supprimer", "Delete"),
    );
    details.danger = true;
    details.phrase = Some(text(
        "CECI VA SUPPRIMER LE WALLET",
        "THIS WILL DELETE THE WALLET",
    ));
    details.phrase_prompt = Some(text("Pour confirmer, écrivez :", "To confirm, type:"));
    secure_confirm(app, details)
}

/// Deletes the local vault (see `api::reset_wallet`): lets the user go back to
/// onboarding without having to find/delete the app's data directory by hand. The
/// wallet can still be recovered through the 3 backup shares exported at creation,
/// if they were kept.
///
/// Keys are forgotten first (no sync can start again with them), then the data is
/// erased, which waits for running syncs to stop, hence an asynchronous command
/// (see `seed_state`).
#[tauri::command]
async fn reset_wallet(app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        if !confirm_reset_window(&app) {
            return Err(translate_error(
                "Réinitialisation annulée (confirmation refusée).",
            ));
        }
        forget_session(&app);
        api::reset_wallet(&dir).t_err()?;
        forget_wallet_connections(&app);
        Ok(())
    })
    .await
}

#[tauri::command]
fn create_wallet(password: String, app: tauri::AppHandle) -> Result<CreateWalletDto, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    let result = api::create_wallet(&dir, &password).t_err()?;
    remember_addresses(&app, 0, &result.addresses);

    let backups = keep_pending_kit(&app, result.backups);

    Ok(CreateWalletDto {
        addresses: result.addresses.into(),
        backups,
    })
}

/// Without this confirmation, regenerating a kit would be the stealthiest way to
/// exfiltrate full control of the wallet. Unlike a send of funds (visible on-chain,
/// one-off), getting a valid Shamir kit gives SILENT and PERSISTENT access: an old
/// kit stays valid even after the device password changes (see
/// `generate_backup_kit`), so stealing the kit once is enough to rebuild the master
/// key forever after, without touching the vault again or triggering any detectable
/// transaction. A script that had already stolen the password (e.g. by capturing
/// the input field) could otherwise call this command without the user ever
/// noticing. The secure confirmation window (see `secure_confirm`) makes such an
/// attempt visible and impossible to approve without the user.
fn confirm_regenerate_backup_window(app: &tauri::AppHandle) -> bool {
    secure_confirm(
        app,
        SecureConfirmDetails::new(
            "key",
            ("Créer un nouveau kit de sauvegarde ?", "Create a new backup kit?"),
            vec![
                text("Vous allez obtenir 3 nouvelles parts, chacune avec son mot de passe.", "You will get 3 new shares, each with its own password."),
                text(
                    "2 parts suffisent pour récupérer tout votre portefeuille : rangez-les à des endroits différents.",
                    "2 shares are enough to recover your whole wallet: keep them in different places.",
                ),
            ],
            ("Créer le kit", "Create the kit"),
        ),
    )
}

/// Regenerates a brand-new 2-of-3 Shamir backup kit (see
/// `api::regenerate_backup_kit`) without touching the local vault or changing the
/// addresses; useful if the user lost one or more of their original backup files.
/// Asks for the password again: regenerating means decrypting the seed again, which
/// is never cached.
#[tauri::command]
async fn regenerate_backup_kit(
    password: String,
    app: tauri::AppHandle,
) -> Result<Vec<BackupShareDto>, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        if !confirm_regenerate_backup_window(&app) {
            return Err(translate_error(
                "Régénération annulée (confirmation refusée).",
            ));
        }
        api::regenerate_backup_kit(&dir, &password)
            .map(|backups| keep_pending_kit(&app, backups))
            .t_err()
    })
    .await
}

/// THORChain (RUNE) address derived from the same master entropy (see
/// `api::get_thor_fee_address`): purely informational, used to receive swap
/// affiliate fees. No native confirmation here (read-only, no funds move): the
/// password is enough, exactly as for showing the wallet's other addresses.
#[tauri::command]
fn get_thor_fee_address(password: String, app: tauri::AppHandle) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let dir = data_dir(&app)?;
    api::get_thor_fee_address(&dir, &password).t_err()
}

// --- Affiliate name (developer's wallet only) ---------------------------------

#[derive(Serialize)]
struct AffiliateNameDto {
    /// "thorchain" or "maya".
    chain: &'static str,
    protocol: &'static str,
    name: &'static str,
    /// "free", "ours", "taken".
    state: &'static str,
    years_left: Option<f64>,
    address: &'static str,
    symbol: &'static str,
    balance: String,
    deposit: String,
    network_fee: String,
}

fn native_amount(units: u128, decimals: u32) -> String {
    openpgp_wallet_core::tokens::format_amount(units, decimals as u8)
}

/// State of the affiliate name on THORChain and Maya (public data); `None` if the
/// main profile is not the developer's wallet.
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
            (
                thorchain
                    .join()
                    .unwrap_or_else(|_| Err("lecture THORChain interrompue".to_string())),
                read("maya"),
            )
        });
        Ok(Some(vec![thorchain?, maya?]))
    })
    .await
}

/// Registers (or extends by a year) the affiliate name on `chain`, after a native
/// confirmation dialog built from the state read HERE.
#[tauri::command]
async fn register_affiliate_name(
    password: String,
    chain: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
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
        // Cancellation delay, as for any movement of funds (audit round 33).
        send_grace_period(&app, GraceRecap::new(network.to_string(), deposit.clone(), address.to_string()))?;
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

/// Display heuristic only (not part of the security barrier): tells whether Windows
/// Hello seems to be set up on this machine, so the enable button is only offered
/// when it has a chance of working. `false` on any platform other than Windows.
#[tauri::command]
fn biometric_unlock_available() -> bool {
    #[cfg(windows)]
    {
        openpgp_wallet_core::windows_hello::is_available()
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

/// Same reason as `confirm_regenerate_backup_window`: enabling a second way to
/// unlock the vault is a security action, made visible and impossible for a
/// compromised frontend to trigger silently thanks to the secure confirmation
/// window.
fn confirm_enroll_biometric_window(app: &tauri::AppHandle) -> bool {
    secure_confirm(
        app,
        SecureConfirmDetails::new(
            "fingerprint",
            ("Activer Windows Hello ?", "Enable Windows Hello?"),
            vec![
                text(
                    "Vous pourrez ouvrir votre portefeuille avec votre empreinte, votre visage ou votre code PIN.",
                    "You will be able to open your wallet with your fingerprint, face or PIN.",
                ),
                text("Votre mot de passe restera demandé pour les actions importantes.", "Your password will still be asked for important actions."),
            ],
            ("Activer", "Enable"),
        ),
    )
}

#[tauri::command]
async fn enroll_biometric_unlock(password: String, app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        if !confirm_enroll_biometric_window(&app) {
            return Err(translate_error(
                "Activation annulée (confirmation refusée).",
            ));
        }
        on_main_thread(&app, move || {
            api::enroll_biometric_unlock(&dir, &password).t_err()
        })
    })
    .await
}

/// Unlocks the vault through Windows Hello rather than the password; see
/// `api::unlock_wallet_biometric`. Returns the same `ProfileDto`s as
/// `unlock_wallet`.
#[tauri::command]
fn unlock_wallet_biometric(app: tauri::AppHandle) -> Result<Vec<ProfileDto>, String> {
    let dir = data_dir(&app)?;
    let profiles = api::unlock_wallet_biometric(&dir).t_err()?;
    remember_profiles(&app, &profiles);
    Ok(profiles.into_iter().map(Into::into).collect())
}

fn confirm_disable_biometric_window(app: &tauri::AppHandle) -> bool {
    secure_confirm(
        app,
        SecureConfirmDetails::new(
            "fingerprint",
            ("Désactiver Windows Hello ?", "Disable Windows Hello?"),
            vec![text(
                "Vous ouvrirez votre portefeuille uniquement avec votre mot de passe.",
                "You will open your wallet with your password only.",
            )],
            ("Désactiver", "Disable"),
        ),
    )
}

#[tauri::command]
async fn disable_biometric_unlock(password: String, app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        if !confirm_disable_biometric_window(&app) {
            return Err(translate_error(
                "Désactivation annulée (confirmation refusée).",
            ));
        }
        on_main_thread(&app, move || {
            api::disable_biometric_unlock(&dir, &password).t_err()
        })
    })
    .await
}

/// Adds a profile (a new address per network, derived from the same seed; see
/// `api::create_profile`): asks for the password again, since deriving an address
/// means decrypting the seed again, which is never cached between calls.
#[tauri::command]
fn create_profile(
    password: Option<String>,
    label: String,
    app: tauri::AppHandle,
) -> Result<ProfileDto, String> {
    let password = password.map(Zeroizing::new);
    let dir = data_dir(&app)?;
    let profile =
        api::create_profile(&dir, password.as_ref().map(|p| p.as_str()), &label).t_err()?;
    remember_profiles(&app, std::slice::from_ref(&profile));
    Ok(profile.into())
}

/// Removes a profile from the list (see `api::delete_profile`): asks for the
/// password again, not because the removal touches the seed, but because this app
/// offers no way to recreate a profile at a specific index. In practice, removing a
/// profile that has already received funds means losing access to them from this
/// interface. It is not a mere convenience operation on a list of labels, hence a
/// confirmation to match (as for a send of funds), instead of a plain JS
/// `confirm()`.
///
/// Confirmed in the secure window (profile name read here, not supplied by the
/// page): with the password alone, a page script that had captured it could remove
/// a funded profile without showing anything (audit round 33).
#[tauri::command]
async fn delete_profile(password: String, index: u32, app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let label = api::profile_label(&dir, index)
            .ok_or_else(|| translate_error(&format!("profil introuvable (index {index})")))?;
        api::check_device_password(&dir, &password).t_err()?;
        if !confirm_delete_profile_window(&app, &label) {
            return Err(translate_error(
                "Suppression annulée (confirmation refusée).",
            ));
        }
        api::delete_profile(&dir, &password, index).t_err()
    })
    .await
}

fn confirm_delete_profile_window(app: &tauri::AppHandle, label: &str) -> bool {
    let label = dialog_label(label);
    let mut details = SecureConfirmDetails::new(
        "trash",
        ("Supprimer ce profil ?", "Delete this profile?"),
        vec![
            text(
                &format!("Le profil « {label} » sera supprimé définitivement."),
                &format!("The profile \"{label}\" will be deleted for good."),
            ),
            text(
                "S'il reste des fonds sur ses adresses, l'app ne pourra plus y accéder.",
                "If funds remain on its addresses, the app will no longer be able to reach them.",
            ),
        ],
        ("Supprimer", "Delete"),
    );
    details.danger = true;
    secure_confirm(app, details)
}

/// "Soft", reversible removal (see `api::archive_profile`): no password required,
/// nothing is irreversible, and the profile can be restored at any time through
/// `unarchive_profile`.
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
    Ok(api::list_archived_profiles(&dir)
        .into_iter()
        .map(Into::into)
        .collect())
}

/// Confirmation of a restore (secure window), after both shares have been checked
/// (`api::check_restore`): it shows the addresses the restore will give back, and says
/// whether the shares were proven to come from the same kit (marked kits) or whether the
/// user should recognize these addresses (kits from before marks existed).
///
/// A restore replaces this device's current vault. Without this confirmation, a script
/// able to invoke the `restore_wallet` Tauri command directly (devtools, compromised
/// dependency) could silently swap in an entirely different wallet (for instance one whose
/// backup shares the attacker holds) without the user ever clicking "send". The addresses
/// then shown on the dashboard would be the attacker's, and a deposit made in good faith
/// through the "receive" screen would go straight to them. The same defense as
/// `confirm_transaction_native`: a confirmation outside the main page (see
/// `secure_confirm`), so it cannot be faked or bypassed from a compromised frontend.
fn confirm_restore_window(app: &tauri::AppHandle, check: &api::RestoreCheck) -> bool {
    let short = |address: &str| {
        let chars: Vec<char> = address.chars().collect();
        if chars.len() <= 20 {
            address.to_string()
        } else {
            format!(
                "{}…{}",
                chars[..10].iter().collect::<String>(),
                chars[chars.len() - 8..].iter().collect::<String>()
            )
        }
    };
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    secure_confirm(
        app,
        SecureConfirmDetails::new(
            "swap",
            ("Restaurer ce portefeuille ?", "Restore this wallet?"),
            vec![
                text("Il remplacera celui de cet ordinateur.", "It will replace the one on this computer."),
                if check.verified {
                    text(
                        "Parts vérifiées : elles viennent du même kit et redonnent bien son portefeuille.",
                        "Shares verified: they come from the same kit and give back its wallet.",
                    )
                } else {
                    text(
                        "Sauvegarde faite avant les vérifications : assurez-vous que ces adresses sont bien les vôtres.",
                        "Backup made before checks existed: make sure these addresses are yours.",
                    )
                },
                if english { format!("Ethereum address: {}", short(&check.addresses.evm)) } else { format!("Adresse Ethereum : {}", short(&check.addresses.evm)) },
                if english { format!("Bitcoin address: {}", short(&check.addresses.btc_mainnet)) } else { format!("Adresse Bitcoin : {}", short(&check.addresses.btc_mainnet)) },
                text(
                    "Utilisez uniquement les parts de votre propre kit, jamais celles qu'on vous aurait données.",
                    "Only use the shares of your own kit, never ones someone gave you.",
                ),
            ],
            ("Restaurer", "Restore"),
        ),
    )
}

#[derive(Serialize)]
struct BackupDriveDto {
    /// Root (`E:\`), to pass back as is to the following commands.
    root: String,
    label: String,
    free_bytes: u64,
    /// Shares already present (kit, number).
    shares: Vec<openpgp_wallet_core::usb_backup::ShareInfo>,
}

/// Plugged-in USB drives, and the backup share each one holds (no secret: kit and
/// share number only). Called at regular intervals by the UI to detect a drive as
/// soon as it is plugged in.
#[tauri::command]
async fn list_backup_drives() -> Result<Vec<BackupDriveDto>, String> {
    run_blocking(|| {
        Ok(openpgp_wallet_core::usb_backup::removable_drives()
            .into_iter()
            .map(|d| BackupDriveDto {
                root: d.root.to_string_lossy().into_owned(),
                label: d.label,
                free_bytes: d.free_bytes,
                shares: d.shares,
            })
            .collect())
    })
    .await
}

/// Writes a COMPLETE share of the kit (share file, private key, password) to the
/// USB drive `root` (only a detected USB drive is accepted, never an arbitrary
/// path), then rereads it and checks that it decrypts. See `core/src/usb_backup.rs`
/// (one share per drive; `name`: the backup's name, kept if it is already on the
/// drive). The share is taken from the pending kit (`PendingKitState`), never from
/// the UI.
#[tauri::command]
async fn save_backup_to_usb(
    root: String,
    kit_id: String,
    name: String,
    part: u8,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let files = with_pending_kit(&app, &kit_id, |kit| kit.share(part).map(share_files))?;
        let drive = openpgp_wallet_core::usb_backup::write_share(
            &root,
            &kit_id,
            &name,
            part,
            &files,
            |written| {
                api::verify_backup_share(
                    &dir,
                    &written.encrypted_share,
                    &written.privkey_armored,
                    &written.passphrase,
                )
            },
        )
        .t_err()?;
        Ok(drive.label)
    })
    .await
}

/// Confirmation (secure window) before writing the WHOLE kit to a single drive: that drive
/// alone will be enough to recover everything, with no password.
fn confirm_kit_on_one_drive_window(app: &tauri::AppHandle, drive: &str, name: &str) -> bool {
    let drive = dialog_label(drive);
    let name = dialog_label(name);
    let mut details = SecureConfirmDetails::new(
        "usb",
        ("Tout mettre sur une seule clé USB ?", "Put everything on one USB drive?"),
        vec![
            if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                format!("The 3 shares of \"{name}\" will be saved on \"{drive}\".")
            } else {
                format!("Les 3 parts de « {name} » seront enregistrées sur « {drive} ».")
            },
            text(
                "Cette clé suffira à elle seule pour accéder à vos fonds, sans mot de passe. Rangez-la en lieu sûr, jamais avec l'ordinateur.",
                "This drive alone will give access to your funds, with no password. Keep it somewhere safe, never with the computer.",
            ),
        ],
        ("Tout enregistrer", "Save everything"),
    );
    details.note = text(
        "Plus sûr : une part par clé.",
        "Safer: one share per drive.",
    );
    secure_confirm(app, details)
}

/// Writes the WHOLE kit (the 3 complete shares of the pending kit `kit_id`) to the
/// USB drive `root`, after the confirmation that states the consequence, then checks
/// every reread share. Returns the drive's name; `None` if the user declined in the
/// dialog.
#[tauri::command]
async fn save_kit_to_usb(
    root: String,
    kit_id: String,
    name: String,
    app: tauri::AppHandle,
) -> Result<Option<String>, String> {
    run_blocking(move || {
        let name = openpgp_wallet_core::usb_backup::normalize_name(&name).t_err()?;
        let dir = data_dir(&app)?;
        let parts: Vec<_> = with_pending_kit(&app, &kit_id, |kit| {
            Ok(kit
                .shares
                .iter()
                .enumerate()
                .map(|(i, share)| ((i + 1) as u8, share_files(share)))
                .collect())
        })?;
        let drive_name = openpgp_wallet_core::usb_backup::removable_drives()
            .into_iter()
            .find(|d| d.root.to_string_lossy().eq_ignore_ascii_case(root.trim()))
            .map(|d| {
                if d.label.is_empty() {
                    d.root.to_string_lossy().into_owned()
                } else {
                    format!(
                        "{} ({})",
                        d.label,
                        d.root.to_string_lossy().trim_end_matches('\\')
                    )
                }
            })
            .ok_or_else(|| translate_error("clé USB introuvable : branchez-la puis réessayez"))?;
        if !confirm_kit_on_one_drive_window(&app, &drive_name, &name) {
            return Ok(None);
        }
        let drive =
            openpgp_wallet_core::usb_backup::write_kit(&root, &kit_id, &name, &parts, |written| {
                api::verify_backup_share(
                    &dir,
                    &written.encrypted_share,
                    &written.privkey_armored,
                    &written.passphrase,
                )
            })
            .t_err()?;
        Ok(Some(drive.label))
    })
    .await
}

/// Shares read from USB drives for a restore (kept here, never sent to the UI): the
/// drives can be plugged in one after the other.
#[derive(Default)]
struct UsbRestoreState(
    std::sync::Mutex<
        Vec<(
            openpgp_wallet_core::usb_backup::ShareInfo,
            openpgp_wallet_core::usb_backup::ShareFiles,
        )>,
    >,
);

/// Reads every share on the USB drive `root` (from every wallet it holds) for an
/// upcoming restore; returns the ones read (kit, number, name; no secret).
#[tauri::command]
async fn usb_restore_load(
    root: String,
    app: tauri::AppHandle,
) -> Result<Vec<openpgp_wallet_core::usb_backup::ShareInfo>, String> {
    run_blocking(move || {
        let drive_shares = openpgp_wallet_core::usb_backup::removable_drives()
            .into_iter()
            .find(|d| d.root.to_string_lossy().eq_ignore_ascii_case(root.trim()))
            .map(|d| d.shares)
            .ok_or_else(|| translate_error("clé USB introuvable : branchez-la puis réessayez"))?;
        let mut read = Vec::with_capacity(drive_shares.len());
        for info in drive_shares {
            read.push(
                openpgp_wallet_core::usb_backup::read_share(&root, &info.kit, info.part).t_err()?,
            );
        }
        let state = app.state::<UsbRestoreState>();
        let mut loaded = state.0.lock().unwrap_or_else(|p| p.into_inner());
        let mut infos = Vec::with_capacity(read.len());
        for (info, files) in read {
            loaded.retain(|(i, _)| !(i.kit == info.kit && i.part == info.part));
            infos.push(info.clone());
            loaded.push((info, files));
        }
        Ok(infos)
    })
    .await
}

/// "Check my backup drives": rereads and decrypts each share on the USB drive
/// `root` (detected drive only), without writing or restoring anything; returns the
/// state of each (kit, number, name, problem; no secret).
#[tauri::command]
async fn check_usb_backup(
    root: String,
    app: tauri::AppHandle,
) -> Result<Vec<openpgp_wallet_core::usb_backup::ShareCheck>, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        openpgp_wallet_core::usb_backup::check_drive(&root, |files| {
            api::verify_backup_share(
                &dir,
                &files.encrypted_share,
                &files.privkey_armored,
                &files.passphrase,
            )
        })
        .t_err()
    })
    .await
}

/// Forgets the shares read (restore abandoned).
#[tauri::command]
fn usb_restore_clear(app: tauri::AppHandle) {
    app.state::<UsbRestoreState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
}

/// Restore from two shares of the same kit read from USB drives
/// (`usb_restore_load`), then the same path as `restore_wallet`. `kit`: the backup
/// chosen, needed when several are complete.
#[tauri::command]
async fn restore_wallet_from_usb(
    new_password: String,
    kit: Option<String>,
    app: tauri::AppHandle,
) -> Result<AddressesDto, String> {
    run_blocking(move || restore_wallet_from_usb_blocking(new_password, kit, &app)).await
}

/// Kits for which at least two different shares have been read, in reading order.
fn complete_kits(
    loaded: &[(
        openpgp_wallet_core::usb_backup::ShareInfo,
        openpgp_wallet_core::usb_backup::ShareFiles,
    )],
) -> Vec<String> {
    let mut kits: Vec<String> = Vec::new();
    for (a, _) in loaded {
        if !kits.contains(&a.kit)
            && loaded
                .iter()
                .any(|(b, _)| b.kit == a.kit && b.part != a.part)
        {
            kits.push(a.kit.clone());
        }
    }
    kits
}

fn restore_wallet_from_usb_blocking(
    new_password: String,
    kit: Option<String>,
    app: &tauri::AppHandle,
) -> Result<AddressesDto, String> {
    let app = app.clone();
    let new_password = Zeroizing::new(new_password);
    let dir = data_dir(&app)?;
    let state = app.state::<UsbRestoreState>();
    let (first, second) = {
        let loaded = state.0.lock().unwrap_or_else(|p| p.into_inner());
        let complete = complete_kits(&loaded);
        let chosen = match kit {
            Some(kit) => complete.into_iter().find(|k| *k == kit),
            None if complete.len() > 1 => {
                return Err(translate_error(
                    "plusieurs sauvegardes complètes trouvées : choisissez celle à restaurer",
                ))
            }
            None => complete.into_iter().next(),
        };
        let chosen = chosen.ok_or_else(|| {
            translate_error(
                "branchez deux clés USB portant deux parts différentes d'une même sauvegarde",
            )
        })?;
        let mut indices = loaded
            .iter()
            .enumerate()
            .filter(|(_, (info, _))| info.kit == chosen)
            .map(|(i, _)| i);
        let pair = indices.next().and_then(|i| {
            indices
                .find(|&j| loaded[j].0.part != loaded[i].0.part)
                .map(|j| (i, j))
        });
        let (i, j) = pair.ok_or_else(|| {
            translate_error(
                "branchez deux clés USB portant deux parts différentes d'une même sauvegarde",
            )
        })?;
        let copy = |k: usize| {
            let (_, f) = &loaded[k];
            (
                f.encrypted_share.clone(),
                f.privkey_armored.clone(),
                Zeroizing::new(f.passphrase.to_string()),
            )
        };
        (copy(i), copy(j))
    };
    // A weak new password or shares that do not belong together: refused here, before
    // the confirmation (`api::restore_wallet` checks the password again).
    api::check_new_password(&new_password).t_err()?;
    let check = api::check_restore(
        &dir,
        (&first.0, &first.1, &first.2),
        (&second.0, &second.1, &second.2),
    )
    .t_err()?;
    if !confirm_restore_window(&app, &check) {
        return Err(translate_error(
            "Restauration annulée (confirmation refusée).",
        ));
    }
    // The old wallet's keys are forgotten before its state is erased.
    forget_session(&app);
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

/// Backup files chosen for a restore from files (`restore_pick_file`), kept here and
/// never sent to the UI, like the shares read from USB drives (`UsbRestoreState`).
/// Slots, in order: share 1, private key 1, share 2, private key 2.
#[derive(Default)]
struct FileRestoreState(std::sync::Mutex<[Option<Zeroizing<Vec<u8>>>; 4]>);

/// Same bound as the files of a USB drive backup (`MAX_FILE_BYTES` in
/// `core/src/usb_backup.rs`): a real share or private key is a few KB, so anything
/// bigger is not a backup file and is not loaded in memory.
const BACKUP_FILE_MAX_BYTES: u64 = 1 << 20;

/// Slot of `FileRestoreState` for file `kind` ("share" or "privkey") of share `part`
/// (1 or 2).
fn restore_file_slot(part: u8, kind: &str) -> Result<usize, String> {
    let offset = match kind {
        "share" => 0,
        "privkey" => 1,
        _ => return Err(translate_error("type de fichier de sauvegarde inconnu")),
    };
    match part {
        1 | 2 => Ok(usize::from(part - 1) * 2 + offset),
        _ => Err(translate_error("numéro de part invalide")),
    }
}

/// Opens the native "Open" dialog for one backup file of a restore and loads it here
/// (see `FileRestoreState`). Returns the file's name to show it, or `None` if the
/// user cancelled. Until this version the UI read the files itself and sent them in
/// base64, so the two shares and their private keys went through the webview.
#[tauri::command]
fn restore_pick_file(
    part: u8,
    kind: String,
    app: tauri::AppHandle,
) -> Result<Option<String>, String> {
    let slot = restore_file_slot(part, &kind)?;
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let Some(file_path) = app
        .dialog()
        .file()
        .add_filter(
            if english {
                "Backup file"
            } else {
                "Fichier de sauvegarde"
            },
            &["asc"],
        )
        .add_filter(
            if english {
                "All files"
            } else {
                "Tous les fichiers"
            },
            &["*"],
        )
        .blocking_pick_file()
    else {
        return Ok(None); // the user cancelled the dialog
    };
    let path = file_path.into_path().t_err()?;
    let too_big = std::fs::metadata(&path)
        .map_err(|e| translate_error(&format!("lecture du fichier impossible : {e}")))?
        .len()
        > BACKUP_FILE_MAX_BYTES;
    if too_big {
        return Err(translate_error(
            "fichier anormalement gros pour une sauvegarde",
        ));
    }
    let bytes = Zeroizing::new(
        std::fs::read(&path)
            .map_err(|e| translate_error(&format!("lecture du fichier impossible : {e}")))?,
    );
    app.state::<FileRestoreState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())[slot] = Some(bytes);
    Ok(Some(
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    ))
}

/// Forgets the backup files chosen (restore abandoned).
#[tauri::command]
fn restore_files_clear(app: tauri::AppHandle) {
    *app.state::<FileRestoreState>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Default::default();
}

/// Restore from the backup files chosen with `restore_pick_file`. The UI only sends
/// the new device password and the passwords of the two shares, typed by the user.
#[tauri::command]
async fn restore_wallet(
    new_password: String,
    passphrase1: String,
    passphrase2: String,
    app: tauri::AppHandle,
) -> Result<AddressesDto, String> {
    run_blocking(move || restore_wallet_blocking(new_password, passphrase1, passphrase2, &app))
        .await
}

fn restore_wallet_blocking(
    new_password: String,
    passphrase1: String,
    passphrase2: String,
    app: &tauri::AppHandle,
) -> Result<AddressesDto, String> {
    let app = app.clone();
    let new_password = Zeroizing::new(new_password);
    let passphrase1 = Zeroizing::new(passphrase1);
    let passphrase2 = Zeroizing::new(passphrase2);
    let dir = data_dir(&app)?;

    let [share1, priv1, share2, priv2] = {
        let chosen = app
            .state::<FileRestoreState>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match chosen {
            [Some(a), Some(b), Some(c), Some(d)] => [a, b, c, d],
            _ => return Err(translate_error("choisissez les fichiers des deux parts")),
        }
    };

    // A weak new password or shares that do not belong together (two different kits):
    // refused here, before the confirmation; otherwise, the confirmation shows the
    // addresses.
    api::check_new_password(&new_password).t_err()?;
    let check = api::check_restore(
        &dir,
        (&share1, &priv1, &passphrase1),
        (&share2, &priv2, &passphrase2),
    )
    .t_err()?;
    if !confirm_restore_window(&app, &check) {
        return Err(translate_error(
            "Restauration annulée (confirmation refusée).",
        ));
    }

    // A restore still only recreates a single default profile (see
    // `api::restore_wallet`): any extra profile labels created on the old device are
    // not part of the Shamir backup. The old wallet's keys are forgotten before its
    // state is erased.
    forget_session(&app);
    let addresses = api::restore_wallet(
        &dir,
        &new_password,
        (&share1, &priv1, &passphrase1),
        (&share2, &priv2, &passphrase2),
    )
    .t_err()?;
    restore_files_clear(app.clone());
    // New wallet: the old one's connections and addresses no longer apply.
    forget_wallet_connections(&app);
    remember_addresses(&app, 0, &addresses);
    Ok(addresses.into())
}

/// Reset/restore: the connected dApps were connected to the OLD wallet, so they are
/// disconnected and the remembered addresses forgotten.
fn forget_wallet_connections(app: &tauri::AppHandle) {
    if let Ok(client) = wc_client(app) {
        client.disconnect_all();
    }
    forget_session(app);
}

/// Locking (button, or inactivity): shielded Zcash and Monero view keys, remembered
/// addresses and prepared dApp requests are forgotten until the next unlock.
/// Background sync stops for lack of keys, and no command answers for a profile any
/// more. WalletConnect connections stay (resumed on unlock).
#[tauri::command]
fn lock_session(app: tauri::AppHandle) {
    forget_session(&app);
}

fn forget_session(app: &tauri::AppHandle) {
    // A kit not saved yet is not kept past a lock: it can be regenerated.
    forget_pending_kit(app.clone());
    // Sends still within their cancellation delay: cancelled.
    for sender in app
        .state::<SendGrace>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .values()
    {
        let _ = sender.send(false);
    }
    app.state::<WcState>()
        .prepared
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileAddressCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileZcashCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileBtcCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileDogeCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileBtcTestnetCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileTronCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileXrpCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileStellarCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileNearCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileCardanoCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileStacksCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ProfileBittensorCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<ShieldedKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    app.state::<MoneroKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    IS_AFFILIATE_WALLET.store(false, Ordering::Relaxed);
}

fn evm_network(network: &str) -> Result<&'static wallet_flow::EvmNetwork, String> {
    wallet_flow::evm_network(network)
        .ok_or_else(|| translate_error(&format!("réseau EVM inconnu : {network}")))
}

/// EVM network (Ethereum, its L2s, BNB Chain, Avalanche, Polygon…): same address,
/// same send code, see `wallet_flow::EVM_NETWORKS`.
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
        other => Err(translate_error(&format!(
            "réseau Bitcoin inconnu : {other}"
        ))),
    }
}

#[tauri::command]
async fn get_balance(
    network: String,
    address: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        match network.as_str() {
            n if is_evm(n) => {
                let net = evm_network(&network)?;
                let wei = api::get_evm_balance(&address, net).t_err()?;
                Ok(format!("{:.6}", wei as f64 / 1e18))
            }
            "btc_testnet" | "btc_mainnet" => {
                let net = btc_network(&network)?;
                // Confirmed minus pending sends; unconfirmed receipts are shown separately
                // (`get_btc_pending_incoming`).
                let sat = api::get_btc_balance_view(&address, net)
                    .t_err()?
                    .settled_sat;
                Ok(format!("{:.8}", sat as f64 / 1e8))
            }
            "sol_devnet" | "sol_mainnet" => {
                let net = sol_network(&network)?;
                let lamports = api::get_sol_balance(&address, net).t_err()?;
                Ok(format!("{:.9}", lamports as f64 / 1e9))
            }
            "zec_mainnet" => Ok(openpgp_wallet_core::zcash::format_zec(
                api::get_zec_balance(&address).t_err()?,
            )),
            "doge_mainnet" => Ok(openpgp_wallet_core::doge::format_doge(
                api::get_doge_balance(&address).t_err()?,
            )),
            "tron_mainnet" => Ok(openpgp_wallet_core::tron::format_trx(
                api::get_trx_balance(&address).t_err()?,
            )),
            "xrp_mainnet" => Ok(openpgp_wallet_core::xrp::format_xrp(
                api::get_xrp_balance(&address).t_err()?,
            )),
            "xlm_mainnet" => Ok(openpgp_wallet_core::stellar::format_xlm(
                api::get_xlm_balance(&address).t_err()?,
            )),
            "near_mainnet" => Ok(openpgp_wallet_core::near::format_near(
                api::get_near_balance(&address).t_err()?,
            )),
            "ada_mainnet" => Ok(openpgp_wallet_core::cardano::format_ada(
                api::get_ada_balance(&address).t_err()?,
            )),
            "stx_mainnet" => Ok(openpgp_wallet_core::stacks::format_stx(
                api::get_stx_balance(&address).t_err()?,
            )),
            "tao_mainnet" => Ok(openpgp_wallet_core::bittensor::format_tao(
                api::get_tao_balance(&address).t_err()?,
            )),
            // Local database (background sync): spendable + pending.
            "zec_shielded" => {
                let balance =
                    api::zec_shielded_balance(&data_dir(&app)?, shielded_profile(&app, &address)?)
                        .t_err()?;
                Ok(openpgp_wallet_core::zcash::format_zec(
                    balance.spendable.saturating_add(balance.pending),
                ))
            }
            // Local state (background sync): spendable + locked.
            "xmr_mainnet" => {
                let balance =
                    api::xmr_balance(&data_dir(&app)?, monero_profile(&app, &address)?).t_err()?;
                Ok(openpgp_wallet_core::monero::format_xmr(
                    balance.unlocked.saturating_add(balance.locked),
                ))
            }
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        }
    })
    .await
}

/// Unconfirmed Bitcoin receipts of `address` (BTC amount), `None` if there are
/// none: shown separately on the card, never counted in the balance, since their
/// sender can still cancel them (see `api::BtcBalanceView`).
#[tauri::command]
async fn get_btc_pending_incoming(
    network: String,
    address: String,
) -> Result<Option<String>, String> {
    run_blocking(move || {
        let net = btc_network(&network)?;
        let sat = api::get_btc_balance_view(&address, net)
            .t_err()?
            .incoming_pending_sat;
        Ok((sat > 0).then(|| format!("{:.8}", sat as f64 / 1e8)))
    })
    .await
}

/// USDC balance, mainnet only (see sol_spl.rs: no devnet mint we could verify with
/// confidence, and no practical value in testing one).
#[tauri::command]
async fn get_usdc_balance(network: String, address: String) -> Result<String, String> {
    run_blocking(move || {
        if network != "sol_mainnet" {
            return Err(translate_error(
                "USDC n'est disponible que sur Solana mainnet.",
            ));
        }
        let net = sol_network(&network)?;
        let micros = api::get_usdc_balance(&address, net).t_err()?;
        Ok(format!("{:.6}", micros as f64 / 1e6))
    })
    .await
}

#[derive(serde::Deserialize)]
struct WatchTargetDto {
    /// Card to reread ("evm", "btc", "sol", "usdc"), passed back as is.
    id: String,
    network: String,
    address: String,
    /// Registry token; absent: the network's native coin.
    #[serde(default)]
    token: Option<String>,
}

/// Live monitoring of the balances of the cards on screen.
#[derive(Default)]
struct BalanceWatchState(
    std::sync::Mutex<Option<openpgp_wallet_core::balance_watch::BalanceWatch>>,
);

/// Replaces the live balance monitoring (see `core/src/balance_watch.rs`): on every
/// change, the "balance-changed" event gives the id of the card to reread. Empty
/// list: stop (lock). Public addresses only.
#[tauri::command]
fn watch_balances(
    targets: Vec<WatchTargetDto>,
    app: tauri::AppHandle,
    state: tauri::State<BalanceWatchState>,
) -> Result<(), String> {
    let mut current = state.0.lock().unwrap_or_else(|p| p.into_inner());
    *current = None; // stops the previous monitoring
    if targets.is_empty() {
        return Ok(());
    }
    let notify: openpgp_wallet_core::balance_watch::Notify =
        std::sync::Arc::new(move |id: &str| {
            let _ = app.emit("balance-changed", id);
        });
    let targets = targets
        .into_iter()
        .map(|t| openpgp_wallet_core::balance_watch::Target {
            id: t.id,
            network: t.network,
            address: t.address,
            token: t.token,
        })
        .collect();
    *current = Some(openpgp_wallet_core::balance_watch::start(targets, notify).t_err()?);
    Ok(())
}

#[derive(Serialize)]
struct BtcFeeEstimateDto {
    fast_sat: u64,
    medium_sat: u64,
    slow_sat: u64,
}

/// Fast/medium/slow fees (in sats) for a Bitcoin transfer from `address`. Bitcoin
/// only: EVM/Solana already compute their fees automatically (gas price / network
/// base fee), so there is no choice to offer the user.
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

/// `false` for EVM rather than an error: no public node exposes pending transactions for
/// Ethereum (see `api::has_pending_btc`/`has_pending_sol`), so the "pending transaction"
/// indicator can structurally never light up for ETH. A silent no-op, not a failure, so
/// the automatic balance refresh does not break on this network.
#[tauri::command]
async fn has_pending_tx(
    network: String,
    address: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
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
            // No mempool reading: a send shows up when it is confirmed (~75 s).
            "zec_mainnet" | "zec_shielded" => Ok(false),
            "doge_mainnet" => api::has_pending_doge(&address).t_err(),
            // One block every 3 s: a send is confirmed before the next reread.
            "tron_mainnet" => Ok(false),
            // Ledger validated every 3 to 5 s: same.
            "xrp_mainnet" | "xlm_mainnet" | "near_mainnet" => Ok(false),
            // One block every 20 s; the send shows up when it is confirmed.
            "ada_mainnet" | "stx_mainnet" => Ok(false),
            // One block every 12 s; the send shows up when it is included.
            "tao_mainnet" => Ok(false),
            "xmr_mainnet" => {
                api::has_pending_xmr(&data_dir(&app)?, monero_profile(&app, &address)?).t_err()
            }
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
    /// Signed decimal string in the network's main unit (e.g. "+0.001234", "-0.05");
    /// `None` when the amount could not be determined.
    amount: Option<String>,
    /// "received", "sent", "swap" or "other" (see `history::TxKind`).
    kind: &'static str,
    /// Absolute dollar value of the amount AT THE TIME of the transaction (see
    /// `price_history`); `None` on a test network, for a transaction that is too old,
    /// or if the price service is unreachable.
    usd_value: Option<f64>,
    explorer_url: String,
}

/// Exact amount, digit by digit: going through `f64` (≈ 16 significant digits)
/// invented the last digits of an 18-decimal amount ("+0.245947228364191028" for
/// 245947228364191044 wei).
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
        TxKind::Stake => "stake",
        TxKind::Other => "other",
    }
}

/// History entries ready to display. `asset`: the asset valued in dollars at the
/// time of each transaction (`None` on a test network: worthless funds). History
/// and price series are read in parallel; without prices (service unreachable), the
/// history still shows, without values.
fn history_dtos<E: std::fmt::Display>(
    fetch: impl FnOnce() -> Result<Vec<history::TxEntry>, E>,
    asset: Option<price_history::Asset>,
    decimals: i32,
    explorer_url: impl Fn(&str) -> String,
) -> Result<Vec<TxEntryDto>, String> {
    let (entries, prices) = std::thread::scope(|scope| {
        let prices = asset.map(|a| scope.spawn(move || price_history::series(a)));
        let entries = fetch();
        (
            entries,
            prices
                .and_then(|handle| handle.join().ok())
                .and_then(Result::ok),
        )
    });
    Ok(entries
        .t_err()?
        .into_iter()
        .map(|tx| TxEntryDto {
            // No "≈ $0.00" for a transaction that moves nothing.
            usd_value: prices
                .as_deref()
                .zip(tx.net_amount_minor.filter(|net| *net != 0))
                .and_then(|(series, net)| {
                    price_history::usd_value(series, net, decimals, tx.timestamp_unix)
                }),
            kind: kind_str(&tx.kind),
            explorer_url: explorer_url(&tx.id),
            amount: format_signed_amount(tx.net_amount_minor, decimals),
            status: status_str(&tx.status).to_string(),
            timestamp_unix: tx.timestamp_unix,
            id: tx.id,
        })
        .collect())
}

/// History of a crypto on a network.
#[derive(Serialize)]
struct HistoryDto {
    entries: Vec<TxEntryDto>,
    /// Network with no usable history source: the address's page on the network's
    /// explorer, to open instead (`entries` empty).
    explorer_url: Option<String>,
    /// Why, if known: "limited" (free-tier limit reached: NodeReal for BNB Chain,
    /// Alchemy for Base and Polygon, Blockscout's official API for Arbitrum).
    reason: Option<&'static str>,
}

impl HistoryDto {
    fn read(entries: Result<Vec<TxEntryDto>, String>) -> Result<Self, String> {
        Ok(Self {
            entries: entries?,
            explorer_url: None,
            reason: None,
        })
    }

    /// EVM history: with no usable source (BNB Chain without a NodeReal key in this
    /// build), or once the free-tier limit is reached, the explorer's page, with the
    /// reason.
    fn evm(
        net: &wallet_flow::EvmNetwork,
        explorer_url: String,
        read: impl FnOnce() -> Result<Vec<TxEntryDto>, String>,
    ) -> Result<Self, String> {
        if !history::evm_history_available(net) {
            return Ok(Self {
                entries: Vec::new(),
                explorer_url: Some(explorer_url),
                reason: None,
            });
        }
        match read() {
            Err(e)
                if e == translate_error(openpgp_wallet_core::nodereal::LIMITED)
                    || e == translate_error(
                        openpgp_wallet_core::blockscout::BLOCKSCOUT_LIMITED,
                    ) =>
            {
                Ok(Self {
                    entries: Vec::new(),
                    explorer_url: Some(explorer_url),
                    reason: Some("limited"),
                })
            }
            // Explorer blocked with no usable key: its page, without an error.
            Err(e) if e == translate_error(openpgp_wallet_core::blockscout::BLOCKSCOUT_BLOCKED) => {
                Ok(Self {
                    entries: Vec::new(),
                    explorer_url: Some(explorer_url),
                    reason: None,
                })
            }
            entries => Self::read(entries),
        }
    }
}

#[tauri::command]
async fn get_tx_history(
    network: String,
    address: String,
    app: tauri::AppHandle,
) -> Result<HistoryDto, String> {
    run_blocking(move || match network.as_str() {
        n if is_evm(n) => {
            let net = evm_network(&network)?;
            api::validate_evm_recipient(&address).t_err()?;
            if net.custom && net.explorer_tx_prefix.is_empty() {
                return Err(translate_error(
                    "historique indisponible : aucun explorateur indiqué pour ce réseau ajouté",
                ));
            }
            // Dollar value: the network's native coin (real funds only; never for a network
            // added by the user, whose symbol says nothing about its value).
            let asset = if net.mainnet && !net.custom {
                price_history::price_asset(net.native_symbol)
            } else {
                None
            };
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
            HistoryDto::read(history_dtos(
                || history::btc_history(net, &address),
                asset,
                8,
                |id| format!("{}{}", net.explorer_tx_prefix, id),
            ))
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
            || openpgp_wallet_core::doge::history(&address, HISTORY_LIMIT as usize),
            Some(price_history::Asset::Pair("DOGEUSDT")),
            8,
            |id| format!("https://blockchair.com/dogecoin/transaction/{id}"),
        )),
        "tron_mainnet" => HistoryDto::read(history_dtos(
            || openpgp_wallet_core::tron::history(&address, HISTORY_LIMIT as usize),
            Some(price_history::Asset::Pair("TRXUSDT")),
            6,
            |id| format!("https://tronscan.org/#/transaction/{id}"),
        )),
        "xrp_mainnet" => HistoryDto::read(history_dtos(
            || {
                openpgp_wallet_core::xrp::history(
                    &openpgp_wallet_core::xrp::MAINNET,
                    &address,
                    HISTORY_LIMIT as usize,
                )
            },
            Some(price_history::Asset::Pair("XRPUSDT")),
            6,
            |id| format!("https://livenet.xrpl.org/transactions/{id}"),
        )),
        "xlm_mainnet" => HistoryDto::read(history_dtos(
            || {
                openpgp_wallet_core::stellar::history(
                    &openpgp_wallet_core::stellar::MAINNET,
                    &address,
                    HISTORY_LIMIT as usize,
                )
            },
            Some(price_history::Asset::Pair("XLMUSDT")),
            7,
            |id| format!("https://stellar.expert/explorer/public/tx/{id}"),
        )),
        "near_mainnet" => HistoryDto::read(history_dtos(
            || {
                openpgp_wallet_core::near::history(
                    &openpgp_wallet_core::near::MAINNET,
                    &address,
                    HISTORY_LIMIT as usize,
                )
            },
            Some(price_history::Asset::Pair("NEARUSDT")),
            24,
            |id| format!("https://nearblocks.io/txns/{id}"),
        )),
        "ada_mainnet" => HistoryDto::read(history_dtos(
            || openpgp_wallet_core::cardano::history(&address, HISTORY_LIMIT as usize),
            Some(price_history::Asset::Pair("ADAUSDT")),
            6,
            |id| format!("https://cardanoscan.io/transaction/{id}"),
        )),
        "stx_mainnet" => HistoryDto::read(history_dtos(
            || {
                openpgp_wallet_core::stacks::history(
                    &openpgp_wallet_core::stacks::MAINNET,
                    &address,
                    HISTORY_LIMIT as usize,
                )
            },
            Some(price_history::Asset::Pair("STXUSDT")),
            6,
            |id| format!("https://explorer.hiro.so/txid/0x{id}?chain=mainnet"),
        )),
        "tao_mainnet" => {
            openpgp_wallet_core::bittensor::parse_address(&address).t_err()?;
            let explorer = openpgp_wallet_core::bittensor::explorer_address_url(&address);
            if !openpgp_wallet_core::bittensor::history_available() {
                return Ok(HistoryDto {
                    entries: Vec::new(),
                    explorer_url: Some(explorer),
                    reason: None,
                });
            }
            match history_dtos(
                || openpgp_wallet_core::bittensor::history(&address, HISTORY_LIMIT as usize),
                Some(price_history::Asset::Pair("TAOUSDT")),
                9,
                openpgp_wallet_core::bittensor::explorer_tx_url,
            ) {
                Err(e) if e == translate_error(openpgp_wallet_core::bittensor::HISTORY_LIMITED) => {
                    Ok(HistoryDto {
                        entries: Vec::new(),
                        explorer_url: Some(explorer),
                        reason: Some("limited"),
                    })
                }
                entries => HistoryDto::read(entries),
            }
        }
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

/// History of a registry token (`core/src/tokens.rs`): ERC-20 through the network's
/// indexer, SPL through the associated token account. Only the token id and the
/// network come from the frontend: contract and mint are the registry's, never an
/// address supplied by the UI.
#[tauri::command]
async fn get_token_tx_history(
    token: String,
    network: String,
    address: String,
) -> Result<HistoryDto, String> {
    run_blocking(move || {
        let (info, deployment) = openpgp_wallet_core::tokens::find(&token, &network)
            .ok_or_else(|| translate_error("jeton non pris en charge sur ce réseau"))?;
        let asset = price_history::price_asset(&info.symbol.to_ascii_uppercase());
        let decimals = i32::from(deployment.decimals);
        match deployment.kind {
            openpgp_wallet_core::tokens::TokenKind::Erc20 { contract } => {
                let net = evm_network(&network)?;
                api::validate_evm_recipient(&address).t_err()?;
                HistoryDto::evm(
                    net,
                    net.explorer_address_url(&address, Some(contract)),
                    || {
                        history_dtos(
                            || {
                                history::erc20_history_page(net.chain_id, &address, contract, None)
                                    .map(|(mut entries, _)| {
                                        entries.truncate(HISTORY_LIMIT as usize);
                                        entries
                                    })
                            },
                            asset,
                            decimals,
                            |id| format!("{}{}", net.explorer_tx_prefix, id),
                        )
                    },
                )
            }
            openpgp_wallet_core::tokens::TokenKind::Trc20 { contract } => {
                HistoryDto::read(history_dtos(
                    || {
                        openpgp_wallet_core::tron::trc20_history(
                            &address,
                            contract,
                            HISTORY_LIMIT as usize,
                        )
                    },
                    asset,
                    decimals,
                    |id| format!("https://tronscan.org/#/transaction/{id}"),
                ))
            }
            // xStocks included: Token-2022 associated account, amounts in displayed units.
            openpgp_wallet_core::tokens::TokenKind::Spl { .. }
            | openpgp_wallet_core::tokens::TokenKind::Spl2022 { .. } => {
                let net = sol_network(&network)?;
                HistoryDto::read(history_dtos(
                    || api::get_registered_spl_tx_history(&token, &address, net, HISTORY_LIMIT),
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
    price_history::ChartRange::parse(range)
        .ok_or_else(|| translate_error(&format!("période inconnue : {range}")))
}

/// Price chart (time, price in dollars) of a crypto or a tokenized share over the
/// period ("1d", "7d", "30d", "1y", "all"); `symbol`: "BTC", "ETH"…, or a share's
/// uppercase symbol ("TSLAX").
#[tauri::command]
async fn get_price_chart(symbol: String, range: String) -> Result<Vec<(i64, f64)>, String> {
    run_blocking(move || {
        // Allowlist of Binance pairs ("EUR": dollars per euro, for display in euros).
        let upper = symbol.to_ascii_uppercase();
        let asset = price_history::price_asset(&upper)
            .ok_or_else(|| translate_error(&format!("crypto inconnue : {upper}")))?;
        price_history::chart(asset, chart_range(&range)?)
            .map(|points| points.as_ref().clone())
            .t_err()
    })
    .await
}

#[derive(serde::Deserialize)]
struct HoldingDto {
    network: String,
    address: String,
    /// Registry token; absent: the network's native coin.
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
    unavailable: Vec<String>,
}

/// Dollar value of a set of public addresses over the period (see
/// `core/src/portfolio.rs`): the wallet profile or external wallets.
#[tauri::command]
async fn get_portfolio_history(
    holdings: Vec<HoldingDto>,
    range: String,
) -> Result<PortfolioHistoryDto, String> {
    run_blocking(move || {
        let holdings: Vec<openpgp_wallet_core::portfolio::Holding> = holdings
            .into_iter()
            .map(|h| openpgp_wallet_core::portfolio::Holding {
                network: h.network,
                address: h.address,
                token: h.token,
            })
            .collect();
        let history =
            openpgp_wallet_core::portfolio::portfolio_history(&holdings, chart_range(&range)?)
                .t_err()?;
        Ok(PortfolioHistoryDto {
            points: history.points,
            since: history.since,
            approximate: history.approximate,
            loading: history.loading,
            transactions_read: history.transactions_read,
            constant: history.constant,
            unavailable: history.unavailable,
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

/// Indicative USD prices (see `core/src/price_rpc.rs`): purely informational, no
/// data about the user or their addresses is sent to this service.
#[tauri::command]
async fn get_crypto_prices() -> Result<PricesDto, String> {
    run_blocking(move || {
        price_rpc::PriceRpc::new()
            .get_prices()
            .map(|p| PricesDto {
                eth_usd: p.eth_usd,
                btc_usd: p.btc_usd,
                sol_usd: p.sol_usd,
            })
            .t_err()
    })
    .await
}

#[derive(Serialize)]
struct MarketCoinDto {
    /// CoinGecko identifier: the UI finds the crypto by it.
    id: String,
    symbol: String,
    name: String,
    price_usd: f64,
    market_cap_usd: f64,
    /// `null` on the JS side if CoinGecko has no computable 24h change for this asset
    /// (too new/illiquid); see `price_rpc::MarketCoin`.
    change_24h_percent: Option<f64>,
}

/// The dashboard's "Markets" section: already sorted by descending market cap on
/// the Rust side (see `price_rpc::get_market_data`), so the frontend only has to
/// show the order received.
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

// --- Text of native dialogs -------------------------------------------------
//
// Found in round 22, and reproduced for real (same library, same Windows
// TaskDialog): these dialogs displayed text coming from the frontend or typed
// freely AS IS: profile label, address book contact label, address, amount. A
// label containing line breaks injected a fake "Recipient / Amount" at the top and
// pushed the real values (and the buttons) off the screen, while the Enter key
// still confirmed. Yet this dialog is precisely the last barrier against a
// compromised frontend: nothing it controls must be able to pass for anything
// other than what it is.

/// A character that must never reach a native dialog from untrusted data: control
/// characters (line breaks, tabs, NEL…), spaces other than the ordinary space
/// (Unicode line/paragraph separators…), and invisible or text-direction control
/// characters (which can visually reorder an address).
fn is_dialog_hazard(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(
            c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}'
        )
}

/// A free-form label (profile, contact) made ready for a native dialog: a single
/// line, no invisible characters, bounded length.
fn dialog_label(label: &str) -> String {
    const MAX_CHARS: usize = 40;
    let cleaned: String = label
        .chars()
        .map(|c| if is_dialog_hazard(c) { ' ' } else { c })
        .collect();
    let cleaned = cleaned
        .split(' ')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.chars().count() > MAX_CHARS {
        format!("{}…", cleaned.chars().take(MAX_CHARS).collect::<String>())
    } else {
        cleaned
    }
}

/// An Ethereum address coming from a dApp (contract, spender of an approval): shown
/// IN FULL, in its EIP-55 form. `dialog_label` truncated it to 40 characters out of
/// 42, cutting off the last ones, which are exactly where a lookalike address
/// differs (seen during the first real test with a dApp). Anything other than an
/// address is treated as a label.
fn dialog_address(value: &str) -> String {
    let value = value.trim();
    let hex_part = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or("");
    if hex_part.len() != 40 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return dialog_label(value);
    }
    let mut bytes = [0u8; 20];
    for (i, byte) in bytes.iter_mut().enumerate() {
        // 40 ASCII hex digits, checked: slicing and reading are safe.
        *byte = u8::from_str_radix(&hex_part[2 * i..2 * i + 2], 16).unwrap_or_default();
    }
    openpgp_wallet_core::derivation::format_address(&bytes)
}

/// Address entered: surrounding spaces removed, then any remaining invisible
/// character or space is REFUSED, since no valid address contains one. The value
/// returned is the one shown AND passed to signing.
fn canonical_address_input(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c == ' ' || is_dialog_hazard(c)) {
        return Err(translate_error(
            "adresse invalide : espaces, retours à la ligne ou caractères invisibles refusés",
        ));
    }
    Ok(trimmed.to_string())
}

/// Human-readable network label for the confirmation dialog.
fn network_label(network: &str) -> String {
    match network {
        "evm_sepolia" => lang(
            "Ethereum Sepolia (réseau de test)",
            "Ethereum Sepolia (test network)",
        )
        .to_string(),
        "evm_mainnet" => lang("Ethereum — fonds réels", "Ethereum — real funds").to_string(),
        "btc_testnet" => lang("Bitcoin (réseau de test)", "Bitcoin (test network)").to_string(),
        "btc_mainnet" => lang("Bitcoin — fonds réels", "Bitcoin — real funds").to_string(),
        "sol_devnet" => lang("Solana (réseau de test)", "Solana (test network)").to_string(),
        "sol_mainnet" => lang("Solana — fonds réels", "Solana — real funds").to_string(),
        "zec_mainnet" => lang("Zcash — fonds réels", "Zcash — real funds").to_string(),
        "doge_mainnet" => lang("Dogecoin — fonds réels", "Dogecoin — real funds").to_string(),
        "tron_mainnet" => lang("Tron — fonds réels", "Tron — real funds").to_string(),
        "xrp_mainnet" => lang("XRP Ledger — fonds réels", "XRP Ledger — real funds").to_string(),
        "xlm_mainnet" => lang("Stellar — fonds réels", "Stellar — real funds").to_string(),
        "near_mainnet" => lang("NEAR — fonds réels", "NEAR — real funds").to_string(),
        "ada_mainnet" => lang("Cardano — fonds réels", "Cardano — real funds").to_string(),
        "stx_mainnet" => lang("Stacks — fonds réels", "Stacks — real funds").to_string(),
        "tao_mainnet" => lang("Bittensor — fonds réels", "Bittensor — real funds").to_string(),
        "xmr_mainnet" => lang("Monero — fonds réels", "Monero — real funds").to_string(),
        "zec_shielded" => lang("Zcash — fonds protégés", "Zcash — shielded funds").to_string(),
        other => match wallet_flow::evm_network(other) {
            Some(net) if net.custom => format!(
                "{} — {}",
                net.name,
                lang("réseau ajouté par vous", "network added by you")
            ),
            Some(net) if net.mainnet => {
                format!("{} — {}", net.name, lang("fonds réels", "real funds"))
            }
            Some(net) => format!("{} (testnet)", net.name),
            None => other.to_string(),
        },
    }
}

/// Unit of a native transfer's amount on `network` (shown next to the amount in the
/// confirmation dialog).
fn network_unit(network: &str) -> &'static str {
    match network {
        "btc_testnet" | "btc_mainnet" => "BTC",
        "sol_devnet" | "sol_mainnet" => "SOL",
        "zec_mainnet" | "zec_shielded" => "ZEC",
        "xmr_mainnet" => "XMR",
        "doge_mainnet" => "DOGE",
        "tron_mainnet" => "TRX",
        "xrp_mainnet" => "XRP",
        "xlm_mainnet" => "XLM",
        "near_mainnet" => "NEAR",
        "ada_mainnet" => "ADA",
        "stx_mainnet" => "STX",
        "tao_mainnet" => "TAO",
        other => wallet_flow::evm_network(other)
            .map(|n| n.native_symbol)
            .unwrap_or(""),
    }
}

/// Native confirmation dialog, shown by the OS and not by the webview: unlike an
/// HTML modal, a compromised frontend can neither fake it nor silently bypass it. It
/// shows exactly what the Rust backend understood (network, recipient, amount, AND
/// the source profile since multiple profiles were added; without it, the dialog
/// would no longer show "exactly" what will be signed, since the source profile now
/// determines the address the funds leave from, just as much as the
/// network/recipient/amount) right before signing: a specific protection against a
/// discreet diversion.
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
        .message(transaction_confirmation_text(
            network, to, amount, from_label, fee_line, warning, token_line,
        ))
        .title(lang("Confirmer le virement", "Confirm the transfer"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Text of `confirm_transaction_native`, kept separate so it can be tested without
/// opening a window (see `dialog_text_cannot_be_spoofed_by_untrusted_strings`).
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
    // Token (token transfer): name and contract, from the Rust registry.
    let token_line = token_line.map(|l| format!("\n{l}")).unwrap_or_default();
    // At the TOP of the message: it is the first thing read, before the address.
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

/// "Address poisoning" warning (see `address_book::lookalike_entry`): the address
/// entered mimics the start and end of an address book contact without being
/// theirs.
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

/// "Recipient address" warnings at the top of the confirmation dialog, requested by
/// the user: (1) no send to this address is recorded in this wallet (see
/// `sent_recipients`); (2) on the blockchain, the address has never been used, or
/// is empty. `activity` is `None` if that read failed, which is said explicitly
/// rather than a silence that would pass for reassurance. `coin`: "evm", "btc",
/// "sol", "usdc", "zec", "xmr" or "zecs" (names the missing asset, since an address
/// "empty" of SOL may hold something else).
fn recipient_warning_lines(
    first_send: bool,
    coin: &str,
    activity: Option<api::RecipientActivity>,
) -> Vec<String> {
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
    // Monero, shielded Zcash: addresses and amounts are invisible on-chain, so there
    // is nothing to check, and no network failure to report.
    if matches!(coin, "xmr" | "zecs") {
        return lines;
    }
    let (asset_fr, asset_en) = match coin {
        "evm" => ("aucun ETH", "no ETH"),
        "btc" => ("aucun BTC", "no BTC"),
        "usdc" => ("ni SOL ni USDC", "neither SOL nor USDC"),
        "zec" => ("aucun ZEC", "no ZEC"),
        "doge" => ("aucun DOGE", "no DOGE"),
        "trx" => ("aucun TRX", "no TRX"),
        "xrp" => ("aucun XRP", "no XRP"),
        "xlm" => ("aucun XLM", "no XLM"),
        "near" => ("aucun NEAR", "no NEAR"),
        "ada" => ("aucun ADA", "no ADA"),
        "stx" => ("aucun STX", "no STX"),
        "tao" => ("aucun TAO", "no TAO"),
        "sol" => ("aucun SOL", "no SOL"),
        _ => ("aucun fonds", "no funds"),
    };
    let (history_fr, history_en) = if coin == "evm" {
        (
            "aucune transaction envoyée, aucun ETH",
            "no transaction sent, no ETH",
        )
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

/// All the warnings for a send, in order of severity: lookalike of an address book
/// contact, then new address, then on-chain state. For the address of a profile of
/// this wallet, the profile is named instead of the last two (neither "new address"
/// nor "never used" to worry about).
fn send_warnings(
    app: &tauri::AppHandle,
    dir: &std::path::Path,
    network: &str,
    coin: &str,
    to: &str,
    activity: Option<api::RecipientActivity>,
) -> Option<String> {
    let lines: Vec<String> = recipient_warning_list(app, dir, network, coin, to, activity)
        .into_iter()
        .map(|w| w.text)
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n\n"))
}

/// A warning about the recipient and its severity: "danger" (address almost
/// identical to a known one, lookalike of a contact), "warning" (new address, never
/// used, empty), "ok" (one of your profiles), "info" (state could not be checked).
#[derive(Serialize)]
struct RecipientWarning {
    level: &'static str,
    text: String,
}

/// All the warnings for a send, most to least severe: the same lines in the native
/// dialog and in the UI preview.
fn recipient_warning_list(
    app: &tauri::AppHandle,
    dir: &std::path::Path,
    network: &str,
    coin: &str,
    to: &str,
    activity: Option<api::RecipientActivity>,
) -> Vec<RecipientWarning> {
    let mut list = Vec::new();
    // Network added by the user: its RPC decides what it announces.
    let custom = wallet_flow::evm_network(network).is_some_and(|n| n.custom);
    if custom {
        list.push(RecipientWarning {
            level: "warning",
            text: lang(
                "Réseau ajouté par vous : l'app ne peut vérifier ni ce réseau ni les soldes et frais annoncés par son RPC.",
                "Network added by you: the app cannot verify this network, nor the balances and fees reported by its RPC.",
            )
            .to_string(),
        });
    }
    // Almost identical to a known address: more precise than the address book
    // lookalike check (start and end only), which is then not repeated.
    if let Some(text) = near_miss_warning(app, dir, to).or_else(|| lookalike_warning(dir, to)) {
        list.push(RecipientWarning {
            level: "danger",
            text,
        });
    }
    match own_profile_label(app, dir, network, to) {
        Some(label) => list.push(RecipientWarning {
            level: "ok",
            text: own_profile_line(&label),
        }),
        None => {
            let first_send = !sent_recipients::has_sent_to(dir, network, to);
            let unverified = activity.is_none();
            // Added network: "no funds", not "no ETH".
            let coin = if custom { "custom" } else { coin };
            for (i, text) in recipient_warning_lines(first_send, coin, activity)
                .into_iter()
                .enumerate()
            {
                let level = if unverified && !(first_send && i == 0) {
                    "info"
                } else {
                    "warning"
                };
                list.push(RecipientWarning { level, text });
            }
        }
    }
    list
}

/// Known addresses, with who they belong to: profiles of this wallet (Rust caches),
/// address book contacts, recipients already paid.
fn known_recipients(app: &tauri::AppHandle, dir: &std::path::Path) -> Vec<(String, String)> {
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let labels: std::collections::HashMap<u32, String> = api::list_profiles(dir)
        .into_iter()
        .map(|p| (p.index, p.label))
        .collect();
    let profile = |index: &u32| {
        let label = dialog_label(labels.get(index).map(String::as_str).unwrap_or("?"));
        if english {
            format!("your profile \"{label}\"")
        } else {
            format!("votre profil « {label} »")
        }
    };
    let mut known: Vec<(String, String)> = Vec::new();
    for (index, (evm, sol)) in app
        .state::<ProfileAddressCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
    {
        known.push((profile(index), evm.clone()));
        known.push((profile(index), sol.clone()));
    }
    let mut simple = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>| {
        for (index, address) in cache.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            known.push((profile(index), address.clone()));
        }
    };
    simple(&app.state::<ProfileBtcCache>().0);
    simple(&app.state::<ProfileZcashCache>().0);
    simple(&app.state::<ProfileDogeCache>().0);
    simple(&app.state::<ProfileTronCache>().0);
    simple(&app.state::<ProfileXrpCache>().0);
    simple(&app.state::<ProfileStellarCache>().0);
    simple(&app.state::<ProfileNearCache>().0);
    simple(&app.state::<ProfileCardanoCache>().0);
    simple(&app.state::<ProfileStacksCache>().0);
    simple(&app.state::<ProfileBittensorCache>().0);
    for (index, (address, _)) in app
        .state::<MoneroKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
    {
        known.push((profile(index), address.clone()));
    }
    for (index, (address, _)) in app
        .state::<ShieldedKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
    {
        known.push((profile(index), address.clone()));
    }
    for entry in address_book::list_entries(dir) {
        let label = dialog_label(&entry.label);
        known.push((
            if english {
                format!("your contact \"{label}\"")
            } else {
                format!("votre contact « {label} »")
            },
            entry.address,
        ));
    }
    let paid = lang(
        "une adresse à qui vous avez déjà envoyé",
        "an address you have already sent to",
    )
    .to_string();
    known.extend(
        sent_recipients::addresses(dir)
            .into_iter()
            .map(|address| (paid.clone(), address)),
    );
    known
}

/// `to` almost identical to a known address (see
/// `openpgp_wallet_core::recipient_check`): which one, and the exact difference.
fn near_miss_warning(app: &tauri::AppHandle, dir: &std::path::Path, to: &str) -> Option<String> {
    let known = known_recipients(app, dir);
    let (address, difference) =
        openpgp_wallet_core::recipient_check::near_miss(known.iter().map(|(_, a)| a.as_str()), to)?;
    let who = &known.iter().find(|(_, a)| a == address)?.0;
    Some(near_miss_line(who, address, &difference))
}

fn near_miss_line(
    who: &str,
    known: &str,
    difference: &openpgp_wallet_core::recipient_check::Difference,
) -> String {
    use openpgp_wallet_core::recipient_check::Difference;
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let chars: Vec<char> = known.trim().chars().collect();
    let short = if chars.len() > 14 {
        format!(
            "{}…{}",
            chars[..6].iter().collect::<String>(),
            chars[chars.len() - 6..].iter().collect::<String>()
        )
    } else {
        chars.iter().collect()
    };
    // Typed character (address entered): never a layout character.
    let shown = |c: char| if is_dialog_hazard(c) { '?' } else { c };
    let place = |position: usize| match (position, english) {
        (0, false) => "au début".to_string(),
        (0, true) => "at the start".to_string(),
        (p, false) if p + 1 >= chars.len() => "à la fin".to_string(),
        (p, true) if p + 1 >= chars.len() => "at the end".to_string(),
        (p, false) => format!("en {}ᵉ position", p + 1),
        (p, true) => format!("at position {}", p + 1),
    };
    let what = match (difference, english) {
        (Difference::Missing { position, expected }, false) => {
            format!("il manque « {} » {}", shown(*expected), place(*position))
        }
        (Difference::Missing { position, expected }, true) => {
            format!("\"{}\" is missing {}", shown(*expected), place(*position))
        }
        (Difference::Extra { position, typed }, false) => {
            format!("« {} » en trop {}", shown(*typed), place(*position))
        }
        (Difference::Extra { position, typed }, true) => {
            format!("an extra \"{}\" {}", shown(*typed), place(*position))
        }
        (
            Difference::Changed {
                position,
                typed,
                expected,
            },
            false,
        ) => format!(
            "« {} » au lieu de « {} » {}",
            shown(*typed),
            shown(*expected),
            place(*position)
        ),
        (
            Difference::Changed {
                position,
                typed,
                expected,
            },
            true,
        ) => format!(
            "\"{}\" instead of \"{}\" {}",
            shown(*typed),
            shown(*expected),
            place(*position)
        ),
        (Difference::Swapped { position }, false) => {
            format!("deux caractères inversés {}", place(*position))
        }
        (Difference::Swapped { position }, true) => {
            format!("two characters swapped {}", place(*position))
        }
        (Difference::Two, false) => "deux caractères diffèrent".to_string(),
        (Difference::Two, true) => "two characters differ".to_string(),
    };
    if english {
        format!("WARNING — ALMOST THE SAME ADDRESS as {who} ({short}): {what}. Probably a copy mistake: check it before going on.")
    } else {
        format!("ATTENTION — ADRESSE PRESQUE IDENTIQUE à {who} ({short}) : {what}. Sans doute une erreur de copie : vérifiez-la avant de continuer.")
    }
}

/// Recipient warnings for the UI PREVIEW (the same lines as the native dialog,
/// which remains the only real protection): address almost identical to a known
/// one, lookalike of a contact, new address, blockchain state. `token`: a registry
/// token, or "usdc" for Solana USDC (dedicated path). Invalid address: no warning
/// (the send will refuse it with its own message).
#[tauri::command]
async fn recipient_warnings(
    app: tauri::AppHandle,
    network: String,
    token: Option<String>,
    to: String,
) -> Result<Vec<RecipientWarning>, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let to = canonical_address_input(&to)?;
        let usdc_solana = token.as_deref() == Some("usdc")
            && openpgp_wallet_core::tokens::find("usdc", &network).is_none();
        let network = if usdc_solana {
            "sol_mainnet".to_string()
        } else {
            network
        };
        if openpgp_wallet_core::recipient_check::validate(&network, &to).is_err() {
            return Ok(Vec::new());
        }
        let (coin, activity) = match token.as_deref() {
            Some(_) if usdc_solana => (
                "usdc",
                api::usdc_recipient_activity(&to, sol_network(&network)?).ok(),
            ),
            Some(token) => {
                let (_, deployment) = openpgp_wallet_core::tokens::find(token, &network)
                    .ok_or_else(|| translate_error("jeton non pris en charge sur ce réseau"))?;
                match deployment.kind {
                    openpgp_wallet_core::tokens::TokenKind::Erc20 { .. } => (
                        "evm",
                        api::evm_recipient_activity(&to, evm_network(&network)?).ok(),
                    ),
                    openpgp_wallet_core::tokens::TokenKind::Trc20 { .. } => {
                        ("trx", api::trx_recipient_activity(&to).ok())
                    }
                    openpgp_wallet_core::tokens::TokenKind::Spl { .. }
                    | openpgp_wallet_core::tokens::TokenKind::Spl2022 { .. } => (
                        "sol",
                        api::sol_recipient_activity(&to, sol_network(&network)?).ok(),
                    ),
                }
            }
            None => {
                let coin = send_coin(&network)?;
                (coin, recipient_activity(coin, &network, &to)?)
            }
        };
        Ok(recipient_warning_list(
            &app, &dir, &network, coin, &to, activity,
        ))
    })
    .await
}

fn own_profile_line(label: &str) -> String {
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        format!("Recognized recipient: your profile \"{label}\" (an address of this wallet).")
    } else {
        format!("Destinataire reconnu : votre profil « {label} » (adresse de ce portefeuille).")
    }
}

/// Profile of this wallet whose address on `network` is `to`, based on the
/// addresses derived from the seed at unlock (Rust caches), never on the UI. Name
/// cleaned up for the native dialog.
fn own_profile_label(
    app: &tauri::AppHandle,
    dir: &std::path::Path,
    network: &str,
    to: &str,
) -> Option<String> {
    let to = to.trim();
    let in_cache = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>,
                    same: fn(&str, &str) -> bool| {
        cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, address)| same(address, to))
            .map(|(index, _)| *index)
    };
    let exact = |a: &str, b: &str| a == b;
    // Hex (EVM) and bech32 (Bitcoin, u1): case-insensitive.
    let any_case = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let index = match network {
        n if is_evm(n) => app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, (evm, _))| evm.eq_ignore_ascii_case(to))
            .map(|(index, _)| *index),
        "sol_mainnet" | "sol_devnet" | "usdc_solana" => app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, (_, sol))| sol == to)
            .map(|(index, _)| *index),
        "btc_mainnet" => in_cache(&app.state::<ProfileBtcCache>().0, any_case),
        "zec_mainnet" => in_cache(&app.state::<ProfileZcashCache>().0, exact),
        "doge_mainnet" => in_cache(&app.state::<ProfileDogeCache>().0, exact),
        "tron_mainnet" => in_cache(&app.state::<ProfileTronCache>().0, exact),
        "xrp_mainnet" => in_cache(&app.state::<ProfileXrpCache>().0, exact),
        "xlm_mainnet" => in_cache(&app.state::<ProfileStellarCache>().0, exact),
        "near_mainnet" => in_cache(&app.state::<ProfileNearCache>().0, exact),
        "ada_mainnet" => in_cache(&app.state::<ProfileCardanoCache>().0, exact),
        "stx_mainnet" => in_cache(&app.state::<ProfileStacksCache>().0, exact),
        "tao_mainnet" => in_cache(&app.state::<ProfileBittensorCache>().0, exact),
        "xmr_mainnet" => app
            .state::<MoneroKeysCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, (address, _))| address == to)
            .map(|(index, _)| *index),
        // From shielded funds: to a profile's u1 or t1 address.
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
    let label = api::list_profiles(dir)
        .into_iter()
        .find(|p| p.index == index)?
        .label;
    Some(dialog_label(&label))
}

/// Fee line for an EVM send, in the network's fee currency (`symbol`): maximum =
/// gas × price, plus Ethereum posting fees (OP Stack networks, estimated) where
/// applicable.
fn evm_fee_line_for(fee: api::EvmFee, symbol: &str) -> String {
    let gas_fee = fee.gas_price.saturating_mul(u128::from(fee.gas_limit)) as f64 / 1e18;
    let max_fee = gas_fee + fee.l1_fee as f64 / 1e18;
    let mut line = lang(
        &format!("Frais réseau maximum : {max_fee:.8} {symbol}"),
        &format!("Maximum network fee: {max_fee:.8} {symbol}"),
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

/// Window title bar and border in the app's theme colors.
#[tauri::command]
fn set_window_frame(theme: String, window: tauri::WebviewWindow) {
    apply_window_frame(&window, &theme);
}

/// Windows dark mode (title bar and the Close, Maximize… buttons) for dark themes;
/// on Windows 11, title bar and border exactly the color of the app's background
/// (no effect, and no error, on Windows 10).
fn apply_window_frame(window: &tauri::WebviewWindow, theme: &str) {
    // Background of each theme (styles.css, `--bg`), as 0xRRGGBB.
    let (dark, background) = match theme {
        "light" => (false, 0xf5f6f8u32),
        "purple" => (true, 0x0a090e),
        "emerald" => (true, 0x070a09),
        "ocean" => (true, 0x070a0d),
        "rose" => (true, 0x0c080a),
        "orange" => (true, 0x0b0908),
        "dark" => (true, 0x000000),
        _ => (true, 0x08090c),
    };
    let _ = window.set_theme(Some(if dark {
        tauri::Theme::Dark
    } else {
        tauri::Theme::Light
    }));
    #[cfg(windows)]
    if let Ok(hwnd) = window.hwnd() {
        use windows::Win32::Foundation::{COLORREF, HWND};
        use windows::Win32::Graphics::Dwm::{
            DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
        };
        // COLORREF: 0x00BBGGRR.
        let colorref =
            |rgb: u32| COLORREF(((rgb & 0xff) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 0xff));
        let hwnd = HWND(hwnd.0 as _);
        let text = if dark { 0xf4f5f7 } else { 0x111111 };
        for (attribute, rgb) in [
            (DWMWA_CAPTION_COLOR, background),
            (DWMWA_BORDER_COLOR, background),
            (DWMWA_TEXT_COLOR, text),
        ] {
            let color = colorref(rgb);
            // SAFETY: a live window (held by `window`), and a pointer to a local COLORREF of
            // the announced size.
            let _ = unsafe {
                DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    std::ptr::from_ref(&color).cast(),
                    std::mem::size_of::<COLORREF>() as u32,
                )
            };
        }
    }
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
    destination_tag: Option<String>,
    memo: Option<String>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let memo = memo.filter(|m| !m.trim().is_empty());
        let note = match (
            api::parse_destination_tag(destination_tag.as_deref()).t_err()?,
            memo,
        ) {
            (None, None) => None,
            (Some(tag), None) => Some(DestinationNote::XrpTag(tag)),
            (None, Some(memo)) if network == "stx_mainnet" => Some(DestinationNote::StacksMemo(
                api::parse_stacks_memo(Some(&memo)).t_err()?,
            )),
            (None, Some(memo)) => Some(DestinationNote::StellarMemo(
                api::parse_stellar_memo(Some(&memo)).t_err()?,
            )),
            (Some(_), Some(_)) => {
                return Err(translate_error(
                    "tag de destination et mémo : un seul des deux",
                ))
            }
        };
        let dir = data_dir(&app)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));
        // The profile's EVM address (remembered at unlock): gas estimate where it is
        // needed (Arbitrum).
        let from_evm = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(evm, _)| evm.clone());
        let from_zec = app
            .state::<ProfileZcashCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_xmr = app
            .state::<MoneroKeysCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(_, keys)| keys.clone());
        let from_sol = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(_, sol)| sol.clone());
        let from_doge = app
            .state::<ProfileDogeCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_btc = match network.as_str() {
            "btc_mainnet" => app
                .state::<ProfileBtcCache>()
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&profile_index)
                .cloned(),
            "btc_testnet" => app
                .state::<ProfileBtcTestnetCache>()
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&profile_index)
                .cloned(),
            _ => None,
        };
        let from_tron = app
            .state::<ProfileTronCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_xrp = app
            .state::<ProfileXrpCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_stellar = app
            .state::<ProfileStellarCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_near = app
            .state::<ProfileNearCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_cardano = app
            .state::<ProfileCardanoCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_stacks = app
            .state::<ProfileStacksCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from_bittensor = app
            .state::<ProfileBittensorCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned();
        let from = SendFrom {
            evm: from_evm.as_deref(),
            sol: from_sol.as_deref(),
            zec: from_zec.as_deref(),
            xmr: from_xmr.as_ref(),
            doge: from_doge.as_deref(),
            btc: from_btc.as_deref(),
            tron: from_tron.as_deref(),
            xrp: from_xrp.as_deref(),
            stellar: from_stellar.as_deref(),
            near: from_near.as_deref(),
            cardano: from_cardano.as_deref(),
            stacks: from_stacks.as_deref(),
            bittensor: from_bittensor.as_deref(),
        };
        let mut send = confirm_send(
            &app,
            &dir,
            &network,
            &to,
            &amount,
            fee_sat,
            &from_label,
            None,
            from,
            max.unwrap_or(false),
            note,
        )?;
        // Tag / memo: always repeated on these networks ("none" included).
        let note = match (&send.note, network.as_str()) {
            (Some(note), _) => Some(note.recap()),
            (None, "xrp_mainnet") => Some((
                lang("Tag de destination", "Destination tag").to_string(),
                lang("aucun", "none").to_string(),
            )),
            (None, "xlm_mainnet" | "stx_mainnet") => Some((
                lang("Mémo", "Memo").to_string(),
                lang("aucun", "none").to_string(),
            )),
            _ => None,
        };
        let recap = GraceRecap {
            note,
            ..GraceRecap::new(
                network_label(&network),
                format!("{} {}", send.amount, network_unit(&network)),
                send.to.clone(),
            )
            .on(&network)
        };
        send_grace_period(&app, recap)?;

        let result = match network.as_str() {
            n if is_evm(n) => {
                let net = evm_network(&network)?;
                let fee = send
                    .evm_fee
                    .ok_or_else(|| "frais EVM manquants".to_string())?;
                api::send_evm(
                    &dir,
                    &password,
                    net,
                    &send.to,
                    &send.amount,
                    fee,
                    profile_index,
                )
                .t_err()
            }
            "btc_testnet" | "btc_mainnet" => {
                let net = btc_network(&network)?;
                let fee_sat = send.fee_sat.ok_or_else(|| {
                    lang(
                        "frais Bitcoin manquants : choisissez une vitesse d'envoi",
                        "Bitcoin fee missing: choose a sending speed",
                    )
                    .to_string()
                })?;
                api::send_btc(
                    &dir,
                    &password,
                    net,
                    &send.to,
                    &send.amount,
                    fee_sat,
                    profile_index,
                )
                .t_err()
            }
            "sol_devnet" | "sol_mainnet" => {
                let net = sol_network(&network)?;
                api::send_sol(&dir, &password, net, &send.to, &send.amount, profile_index).t_err()
            }
            "zec_mainnet" => {
                let shown_fee = send
                    .zec_fee
                    .ok_or_else(|| "frais Zcash manquants".to_string())?;
                api::send_zec(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "doge_mainnet" => {
                let shown_fee = send
                    .doge_fee
                    .ok_or_else(|| "frais Dogecoin manquants".to_string())?;
                api::send_doge(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "tron_mainnet" => {
                let shown_fee = send
                    .trx_fee
                    .ok_or_else(|| "frais Tron manquants".to_string())?;
                api::send_trx(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "xrp_mainnet" => {
                let shown_fee = send
                    .xrp_fee
                    .ok_or_else(|| translate_error("frais XRP manquants"))?;
                api::send_xrp(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    send.xrp_tag(),
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "xlm_mainnet" => {
                let shown_fee = send
                    .xlm_fee
                    .ok_or_else(|| translate_error("frais Stellar manquants"))?;
                api::send_xlm(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    send.stellar_memo(),
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "near_mainnet" => {
                let shown_fee = send
                    .near_fee
                    .ok_or_else(|| translate_error("frais NEAR manquants"))?;
                api::send_near(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "ada_mainnet" => {
                let shown_fee = send
                    .ada_fee
                    .ok_or_else(|| translate_error("frais Cardano manquants"))?;
                api::send_ada(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "stx_mainnet" => {
                let shown_fee = send
                    .stx_fee
                    .ok_or_else(|| translate_error("frais Stacks manquants"))?;
                api::send_stx(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    send.stacks_memo(),
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            "tao_mainnet" => {
                let shown_fee = send
                    .tao_fee
                    .ok_or_else(|| translate_error("frais Bittensor manquants"))?;
                api::send_tao(
                    &dir,
                    &password,
                    &send.to,
                    &send.amount,
                    shown_fee,
                    profile_index,
                )
                .t_err()
            }
            // Exactly the send prepared and shown (outputs, decoys, fee).
            "xmr_mainnet" => match send.xmr_plan.take() {
                Some(plan) => {
                    let sent = api::send_xmr(&dir, &password, plan).t_err();
                    // Send marked as pending in the state: balance reread straight away.
                    XMR_SYNC_KICK.store(true, Ordering::SeqCst);
                    sent
                }
                None => Err(translate_error("envoi Monero non préparé")),
            },
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        };
        // Recipient remembered ONLY after a successful broadcast (see `sent_recipients`).
        // Failing to write the log must not make a send that already went out look like it
        // failed.
        if result.is_ok() {
            let _ = sent_recipients::record_sent(&dir, &network, &send.to);
        }
        result
    })
    .await
}

/// Delay left, AFTER the native confirmation dialog and BEFORE signing, to cancel a
/// send: the UI shows a countdown with "Send now" and "Cancel". Without an answer,
/// the send goes out when the delay ends. Enforced here: the UI can only shorten it
/// or cancel, never skip it; the seed is only unlocked afterwards.
const SEND_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Sends waiting for their delay: identifier → decision channel (`true`: send now,
/// `false`: cancel).
#[derive(Default)]
struct SendGrace(std::sync::Mutex<std::collections::HashMap<u64, std::sync::mpsc::Sender<bool>>>);

#[derive(Clone, Serialize)]
struct SendCountdownDto {
    id: u64,
    seconds: u64,
    recap: GraceRecap,
}

/// Reminder shown during the cancellation delay: network, amount and address, the
/// same values as the native dialog just approved (computed here, never reread from
/// the UI).
#[derive(Clone, Serialize)]
struct GraceRecap {
    /// Network identifier ("xrp_mainnet"…): the logo shown by the UI.
    network_id: String,
    network: String,
    amount: String,
    to_label: String,
    to: String,
    /// Destination tag or memo (XRP, Stellar, Stacks): (label, value).
    note: Option<(String, String)>,
}

impl GraceRecap {
    /// Send: recipient.
    fn new(network: impl Into<String>, amount: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            network_id: String::new(),
            network: network.into(),
            amount: amount.into(),
            to_label: lang("Destinataire", "Recipient").to_string(),
            to: to.into(),
            note: None,
        }
    }

    /// Swap: the address where the funds arrive.
    fn swap(
        route: impl Into<String>,
        amount: impl Into<String>,
        arrival: impl Into<String>,
    ) -> Self {
        Self {
            network_id: String::new(),
            network: route.into(),
            amount: amount.into(),
            to_label: lang("Adresse d'arrivée", "Arrival address").to_string(),
            to: arrival.into(),
            note: None,
        }
    }

    /// Network the funds leave from (its logo is shown).
    fn on(self, network_id: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            ..self
        }
    }
}

/// Waits for the end of the cancellation delay (or the user's decision). `Err` if
/// the send is cancelled.
fn send_grace_period(app: &tauri::AppHandle, recap: GraceRecap) -> Result<(), String> {
    grace_period(app, "Virement annulé pendant le délai d'annulation.", recap)
}

/// The same delay for a swap, after its confirmation dialog.
fn swap_grace_period(app: &tauri::AppHandle, recap: GraceRecap) -> Result<(), String> {
    grace_period(app, "Échange annulé pendant le délai d'annulation.", recap)
}

fn grace_period(app: &tauri::AppHandle, cancelled: &str, recap: GraceRecap) -> Result<(), String> {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (sender, receiver) = std::sync::mpsc::channel();
    app.state::<SendGrace>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, sender);
    let _ = app.emit(
        "send-countdown",
        SendCountdownDto {
            id,
            seconds: SEND_GRACE.as_secs(),
            recap,
        },
    );
    let decision = receiver.recv_timeout(SEND_GRACE);
    app.state::<SendGrace>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
    let _ = app.emit("send-countdown-end", id);
    match decision {
        Ok(false) => Err(translate_error(cancelled)),
        // Delay over, or "Send now".
        _ => Ok(()),
    }
}

/// Maximum amount that can be sent ("Max" button) from the profile, current fees
/// deducted; `token`: a registry token (USDC included), its whole balance. A
/// preview only: it is recomputed at confirmation.
#[tauri::command]
async fn max_send_amount(
    network: String,
    token: Option<String>,
    profile_index: u32,
    fee_sat: Option<u64>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let unknown =
            || translate_error("adresse du profil inconnue — déverrouillez le portefeuille");
        let cached = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>| {
            cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&profile_index)
                .cloned()
                .ok_or_else(unknown)
        };
        let (evm, sol) = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned()
            .ok_or_else(unknown)?;
        if let Some(token) = token {
            let owner = match network.as_str() {
                n if is_evm(n) => evm,
                "tron_mainnet" => cached(&app.state::<ProfileTronCache>().0)?,
                _ => sol,
            };
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
                let address = if network == "btc_mainnet" {
                    cached(&app.state::<ProfileBtcCache>().0)?
                } else {
                    cached(&app.state::<ProfileBtcTestnetCache>().0)?
                };
                let fee_sat = fee_sat.ok_or_else(|| {
                    lang(
                        "frais Bitcoin manquants : choisissez une vitesse d'envoi",
                        "Bitcoin fee missing: choose a sending speed",
                    )
                    .to_string()
                })?;
                api::btc_max(btc_network(&network)?, &address, fee_sat).t_err()
            }
            "zec_mainnet" => api::zec_max(&cached(&app.state::<ProfileZcashCache>().0)?).t_err(),
            "doge_mainnet" => api::doge_max(&cached(&app.state::<ProfileDogeCache>().0)?).t_err(),
            "tron_mainnet" => {
                api::trx_max(&cached(&app.state::<ProfileTronCache>().0)?, None).t_err()
            }
            "xrp_mainnet" => api::xrp_max(&cached(&app.state::<ProfileXrpCache>().0)?).t_err(),
            "xlm_mainnet" => api::xlm_max(&cached(&app.state::<ProfileStellarCache>().0)?).t_err(),
            "near_mainnet" => {
                api::near_max(&cached(&app.state::<ProfileNearCache>().0)?, None).t_err()
            }
            "ada_mainnet" => {
                api::ada_max(&cached(&app.state::<ProfileCardanoCache>().0)?, None).t_err()
            }
            "stx_mainnet" => api::stx_max(&cached(&app.state::<ProfileStacksCache>().0)?).t_err(),
            "tao_mainnet" => {
                api::tao_max(&cached(&app.state::<ProfileBittensorCache>().0)?, None).t_err()
            }
            "xmr_mainnet" => {
                let keys = app
                    .state::<MoneroKeysCache>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&profile_index)
                    .map(|(_, keys)| keys.clone())
                    .ok_or_else(unknown)?;
                Ok(openpgp_wallet_core::monero::format_xmr(
                    api::xmr_send_plan_max(&dir, &keys, None).t_err()?.amount,
                ))
            }
            "zec_shielded" => {
                let address = app
                    .state::<ShieldedKeysCache>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&profile_index)
                    .map(|(address, _)| address.clone())
                    .ok_or_else(unknown)?;
                api::zec_shielded_max(&dir, profile_index, &address).t_err()
            }
            other => Err(translate_error(&format!("réseau inconnu : {other}"))),
        }
    })
    .await
}

/// The user's decision during a send's cancellation delay.
#[tauri::command]
fn resolve_send_countdown(id: u64, send: bool, state: tauri::State<SendGrace>) {
    if let Some(sender) = state.0.lock().unwrap_or_else(|p| p.into_inner()).get(&id) {
        let _ = sender.send(send);
    }
}

/// Fee line followed, after a blank line, by the device's instruction (the fee line
/// is already preceded by a line break in the dialog).
fn fee_and_device_note(fee_line: Option<String>, device_note: Option<&str>) -> Option<String> {
    match (fee_line, device_note) {
        (Some(fee), Some(note)) => Some(format!("{fee}\n\n{note}")),
        (None, Some(note)) => Some(format!("\n{note}")),
        (fee, None) => fee,
    }
}

/// What a send validated and had confirmed: exactly what will be signed.
struct ConfirmedSend {
    to: String,
    amount: String,
    evm_fee: Option<api::EvmFee>,
    fee_sat: Option<u64>,
    /// Zcash fee shown (cap at send time).
    zec_fee: Option<u64>,
    /// Prepared Monero send (outputs, decoys, fee): signed as shown.
    xmr_plan: Option<openpgp_wallet_core::monero::SendPlan>,
    /// Dogecoin fee shown (cap at send time).
    doge_fee: Option<u64>,
    /// Maximum Tron fee shown (cap at send time).
    trx_fee: Option<u64>,
    /// XRP fee shown (cap at send time).
    xrp_fee: Option<u64>,
    /// Stellar fee (bid) shown (cap at send time).
    xlm_fee: Option<u32>,
    /// Maximum NEAR fee (hold) shown (cap at send time).
    near_fee: Option<u128>,
    /// Cardano fee shown (cap at send time).
    ada_fee: Option<u64>,
    /// Stacks fee shown (cap at send time).
    stx_fee: Option<u64>,
    /// Bittensor fee shown (cap at send time, within 10%).
    tao_fee: Option<u64>,
    /// Tag (XRP) or memo (Stellar) shown in the dialog, signed as is.
    note: Option<DestinationNote>,
}

/// Recipient detail required by exchanges: destination tag (XRP) or memo (Stellar).
#[derive(Clone, Debug)]
enum DestinationNote {
    XrpTag(u32),
    StellarMemo(StellarMemo),
    /// Stacks memo (ASCII, at most 34 bytes).
    StacksMemo(String),
}

use openpgp_wallet_core::stellar::Memo as StellarMemo;

impl DestinationNote {
    /// (label, value) of the reminder during the cancellation delay.
    fn recap(&self) -> (String, String) {
        let (label, value) = match self {
            DestinationNote::XrpTag(tag) => (
                lang("Tag de destination", "Destination tag"),
                tag.to_string(),
            ),
            DestinationNote::StellarMemo(StellarMemo::Id(id)) => {
                (lang("Mémo (identifiant)", "Memo (ID)"), id.to_string())
            }
            DestinationNote::StellarMemo(StellarMemo::Text(text)) => {
                (lang("Mémo (texte)", "Memo (text)"), format!("\"{text}\""))
            }
            DestinationNote::StellarMemo(StellarMemo::None) => {
                (lang("Mémo", "Memo"), lang("aucun", "none").to_string())
            }
            DestinationNote::StacksMemo(text) => (lang("Mémo", "Memo"), format!("\"{text}\"")),
        };
        (label.to_string(), value)
    }
}

impl ConfirmedSend {
    fn xrp_tag(&self) -> Option<u32> {
        match self.note {
            Some(DestinationNote::XrpTag(tag)) => Some(tag),
            _ => None,
        }
    }

    fn stacks_memo(&self) -> &str {
        match &self.note {
            Some(DestinationNote::StacksMemo(memo)) => memo,
            _ => "",
        }
    }

    fn stellar_memo(&self) -> StellarMemo {
        match &self.note {
            Some(DestinationNote::StellarMemo(memo)) => memo.clone(),
            _ => StellarMemo::None,
        }
    }
}

/// Addresses (and Monero view keys) of the sending account, known without the
/// password: preparing the send BEFORE the confirmation dialog.
#[derive(Default)]
struct SendFrom<'a> {
    evm: Option<&'a str>,
    sol: Option<&'a str>,
    zec: Option<&'a str>,
    xmr: Option<&'a openpgp_wallet_core::monero::ViewKeys>,
    doge: Option<&'a str>,
    btc: Option<&'a str>,
    tron: Option<&'a str>,
    xrp: Option<&'a str>,
    stellar: Option<&'a str>,
    near: Option<&'a str>,
    cardano: Option<&'a str>,
    stacks: Option<&'a str>,
    bittensor: Option<&'a str>,
}

/// State of `to` on the blockchain, for the warnings (`None`: could not be read).
/// The address is refused here if it is malformed (EVM/BTC: until now only at
/// signing time) or, for Solana, if it is not a wallet (see
/// `api::check_solana_recipient`).
fn recipient_activity(
    coin: &str,
    network: &str,
    to: &str,
) -> Result<Option<api::RecipientActivity>, String> {
    Ok(match coin {
        "evm" => {
            api::validate_evm_recipient(to).t_err()?;
            api::evm_recipient_activity(to, evm_network(network)?).ok()
        }
        "btc" => {
            let net = btc_network(network)?;
            api::validate_btc_recipient(to, net).t_err()?;
            api::btc_recipient_activity(to, net).ok()
        }
        // Address already checked (send preparation, or format checked by
        // `recipient_warnings` for the preview).
        "zec" => api::zec_recipient_activity(to).ok(),
        "doge" => api::doge_recipient_activity(to).ok(),
        "trx" => api::trx_recipient_activity(to).ok(),
        "xrp" => api::xrp_recipient_activity(to).ok(),
        "xlm" => api::xlm_recipient_activity(to).ok(),
        "near" => api::near_recipient_activity(to).ok(),
        "ada" => api::ada_recipient_activity(to).ok(),
        "stx" => api::stx_recipient_activity(to).ok(),
        "tao" => api::tao_recipient_activity(to).ok(),
        // Address checked by the preparation; no readable activity (addresses and amounts
        // are invisible on the Monero chain).
        "xmr" => None,
        _ => {
            let net = sol_network(network)?;
            api::check_solana_recipient(to, net).t_err()?;
            api::sol_recipient_activity(to, net).ok()
        }
    })
}

/// Currency of a send according to its network (`Err`: unknown network).
fn send_coin(network: &str) -> Result<&'static str, String> {
    Ok(match network {
        n if is_evm(n) => "evm",
        "btc_testnet" | "btc_mainnet" => "btc",
        "sol_devnet" | "sol_mainnet" => "sol",
        "zec_mainnet" => "zec",
        "xmr_mainnet" => "xmr",
        "doge_mainnet" => "doge",
        "tron_mainnet" => "trx",
        "xrp_mainnet" => "xrp",
        "xlm_mainnet" => "xlm",
        "near_mainnet" => "near",
        "ada_mainnet" => "ada",
        "stx_mainnet" => "stx",
        "tao_mainnet" => "tao",
        other => return Err(translate_error(&format!("réseau inconnu : {other}"))),
    })
}

/// Validation, warnings and native confirmation dialog, shared by wallet sends and
/// hardware account sends (`device_note`: an instruction added to the dialog for
/// confirming on the device). `Err` if refused.
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
    note: Option<DestinationNote>,
) -> Result<ConfirmedSend, String> {
    // Network validated BEFORE the confirmation dialog (round 22): an unknown network
    // used to be shown as is (free text from the frontend) in the dialog, with the
    // error only coming afterwards. Address and amount are replaced by their canonical
    // form, used for display AND signing (see
    // `canonical_address_input`/`api::canonical_amount`).
    let coin = send_coin(network)?;
    match (&note, coin) {
        (Some(DestinationNote::XrpTag(_)), c) if c != "xrp" => {
            return Err(translate_error(
                "tag de destination : réservé aux envois XRP",
            ))
        }
        (Some(DestinationNote::StellarMemo(_)), c) if c != "xlm" => {
            return Err(translate_error(
                "mémo : réservé aux envois Stellar et Stacks",
            ))
        }
        (Some(DestinationNote::StacksMemo(_)), c) if c != "stx" => {
            return Err(translate_error(
                "mémo : réservé aux envois Stellar et Stacks",
            ))
        }
        _ => {}
    }
    let destination_tag = match note {
        Some(DestinationNote::XrpTag(tag)) => Some(tag),
        _ => None,
    };
    let memo = match &note {
        Some(DestinationNote::StellarMemo(memo)) => memo.clone(),
        _ => StellarMemo::None,
    };
    let to = canonical_address_input(to)?;
    let unknown_profile =
        || translate_error("adresse du profil inconnue — déverrouillez le portefeuille");
    // "Max": the amount recomputed NOW (balance minus current fees, same rules as the
    // send), shown in the dialog and then signed as is.
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
            "sol" => api::sol_max(sol_network(network)?, from.sol.ok_or_else(unknown_profile)?)
                .t_err()?,
            "btc" => {
                let fee_sat = fee_sat.ok_or_else(|| {
                    lang(
                        "frais Bitcoin manquants : choisissez une vitesse d'envoi",
                        "Bitcoin fee missing: choose a sending speed",
                    )
                    .to_string()
                })?;
                api::btc_max(
                    btc_network(network)?,
                    from.btc.ok_or_else(unknown_profile)?,
                    fee_sat,
                )
                .t_err()?
            }
            "zec" => api::zec_max(from.zec.ok_or_else(unknown_profile)?).t_err()?,
            "doge" => api::doge_max(from.doge.ok_or_else(unknown_profile)?).t_err()?,
            "trx" => api::trx_max(from.tron.ok_or_else(unknown_profile)?, Some(&to)).t_err()?,
            "xrp" => api::xrp_max(from.xrp.ok_or_else(unknown_profile)?).t_err()?,
            "xlm" => api::xlm_max(from.stellar.ok_or_else(unknown_profile)?).t_err()?,
            "near" => api::near_max(from.near.ok_or_else(unknown_profile)?, Some(&to)).t_err()?,
            "ada" => api::ada_max(from.cardano.ok_or_else(unknown_profile)?, Some(&to)).t_err()?,
            "stx" => api::stx_max(from.stacks.ok_or_else(unknown_profile)?).t_err()?,
            "tao" => {
                api::tao_max(from.bittensor.ok_or_else(unknown_profile)?, Some(&to)).t_err()?
            }
            _ => {
                let plan =
                    api::xmr_send_plan_max(dir, from.xmr.ok_or_else(unknown_profile)?, Some(&to))
                        .t_err()?;
                let amount = openpgp_wallet_core::monero::format_xmr(plan.amount);
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
        "trx" => api::canonical_trx_amount(&amount).t_err()?,
        "xrp" => api::canonical_xrp_amount(&amount).t_err()?,
        "xlm" => api::canonical_xlm_amount(&amount).t_err()?,
        "near" => api::canonical_near_amount(&amount).t_err()?,
        "ada" => api::canonical_ada_amount(&amount).t_err()?,
        "stx" => api::canonical_stx_amount(&amount).t_err()?,
        "tao" => api::canonical_tao_amount(&amount).t_err()?,
        "xmr" => api::canonical_xmr_amount(&amount).t_err()?,
        _ => api::canonical_amount(coin, &amount).t_err()?,
    };

    // Fees shown in the native dialog (see its docs: "shows exactly what the backend
    // understood"): chosen by the user for Bitcoin; for EVM, the full fees (price, gas
    // limit (estimated where it is not fixed), OP Stack posting fees) read NOW, shown,
    // then signed as is. They used to be read from the node AFTER confirmation and
    // never shown (see `api::evm_gas_price_for_confirmation`).
    let evm_fee = match (coin, evm_fee) {
        ("evm", None) => Some(
            api::evm_transfer_fee_for_confirmation(evm_network(network)?, from.evm, &to, &amount)
                .t_err()?,
        ),
        (_, fee) => fee,
    };
    // Enough balance (amount + fees) checked BEFORE the dialog: never confirm a send
    // that is refused right after.
    match (coin, evm_fee, from.evm, from.sol) {
        ("evm", Some(fee), Some(from), _) => {
            api::ensure_evm_transfer_funds(evm_network(network)?, from, &amount, fee).t_err()?
        }
        ("sol", _, _, Some(from)) => {
            api::ensure_sol_transfer_funds(sol_network(network)?, from, &amount).t_err()?
        }
        _ => {}
    }
    // Bitcoin (wallet): all the outputs cover the amount and the chosen fee. Hardware
    // accounts: their addresses are reread by the device.
    if let ("btc", Some(from), Some(fee)) = (coin, from.btc, fee_sat) {
        api::ensure_btc_transfer_funds(btc_network(network)?, from, &amount, fee).t_err()?;
    }
    // Zcash: recipient checked, outputs chosen and ZIP-317 fee computed NOW, shown,
    // then never exceeded at send time.
    let zec_plan = match coin {
        "zec" => {
            let from = from.zec.ok_or_else(|| {
                translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
            })?;
            Some(api::zec_send_plan(from, &to, &amount).t_err()?)
        }
        _ => None,
    };
    // Dogecoin: recipient checked, outputs chosen and verified against their source
    // transactions (amounts), fee computed NOW, shown, then never exceeded at send
    // time.
    let doge_plan = match coin {
        "doge" => {
            let from = from.doge.ok_or_else(|| {
                translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
            })?;
            Some(api::doge_send_plan(from, &to, &amount).t_err()?)
        }
        _ => None,
    };
    // Tron: recipient checked, maximum fee (bandwidth, activating an account that does
    // not exist) and balance checked NOW, shown, then never exceeded at send time.
    let trx_plan = match coin {
        "trx" => {
            Some(api::trx_send_plan(from.tron.ok_or_else(unknown_profile)?, &to, &amount).t_err()?)
        }
        _ => None,
    };
    // XRP: network reserve, activation of a new recipient, tag required by the
    // recipient and fee checked NOW, shown, then never exceeded at send time.
    let xrp_plan = match coin {
        "xrp" => Some(
            api::xrp_send_plan(
                from.xrp.ok_or_else(unknown_profile)?,
                &to,
                &amount,
                destination_tag,
            )
            .t_err()?,
        ),
        _ => None,
    };
    // Stellar: network reserve, creation of a new recipient, memo required by the
    // recipient (SEP-29) and fee checked NOW.
    let xlm_plan = match coin {
        "xlm" => Some(
            api::xlm_send_plan(
                from.stellar.ok_or_else(unknown_profile)?,
                &to,
                &amount,
                &memo,
            )
            .t_err()?,
        ),
        _ => None,
    };
    // NEAR: account storage, creation of a new implicit account, existing named
    // account and fee (maximum hold) checked NOW.
    let near_plan = match coin {
        "near" => Some(
            api::near_send_plan(from.near.ok_or_else(unknown_profile)?, &to, &amount).t_err()?,
        ),
        _ => None,
    };
    // Cardano: outputs chosen (ADA only), exact fee, change returned and output
    // minimum computed NOW, shown, never exceeded.
    let ada_plan = match coin {
        "ada" => Some(
            api::ada_send_plan(from.cardano.ok_or_else(unknown_profile)?, &to, &amount).t_err()?,
        ),
        _ => None,
    };
    // Stacks: available balance (excluding stacking) and fee checked NOW.
    let stx_plan = match coin {
        "stx" => Some(
            api::stx_send_plan(from.stacks.ok_or_else(unknown_profile)?, &to, &amount).t_err()?,
        ),
        _ => None,
    };
    // Bittensor: fee, the sender's minimum balance and an empty recipient account
    // checked NOW (refusals the node's validation does not see).
    let tao_plan = match coin {
        "tao" => Some(
            api::tao_send_plan(from.bittensor.ok_or_else(unknown_profile)?, &to, &amount)
                .t_err()?,
        ),
        _ => None,
    };
    // Monero: recipient checked, outputs chosen, decoys drawn and fee computed NOW
    // (view keys, without the seed); that exact send, unchanged, is what will be
    // signed.
    let xmr_plan = match (coin, xmr_plan) {
        ("xmr", None) => {
            let keys = from.xmr.ok_or_else(unknown_profile)?;
            Some(api::xmr_send_plan(dir, keys, &to, &amount).t_err()?)
        }
        (_, plan) => plan,
    };
    let activity = recipient_activity(coin, network, &to)?;
    // Fee line chosen according to the NETWORK, never according to the mere presence
    // of `fee_sat` (round 22): a `fee_sat` sent for an ETH transfer used to replace
    // the real gas fee display with a "Fee: 1 sat" that had nothing to do with what
    // would be paid.
    let fee_line = match coin {
        "btc" => {
            let fee_sat = fee_sat.ok_or_else(|| lang("frais Bitcoin manquants : choisissez une vitesse d'envoi", "Bitcoin fee missing: choose a sending speed").to_string())?;
            Some(format!("{} : {} BTC", lang("Frais", "Fee"), openpgp_wallet_core::tokens::format_amount(u128::from(fee_sat), 8)))
        }
        "zec" => zec_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} ZEC", lang("Frais", "Fee"), openpgp_wallet_core::zcash::format_zec(plan.fee));
            if plan.change > 0 {
                let change = openpgp_wallet_core::zcash::format_zec(plan.change);
                line.push_str(lang(&format!("
Monnaie rendue à votre adresse : {change} ZEC"), &format!("
Change returned to your address: {change} ZEC")));
            }
            line
        }),
        "doge" => doge_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} DOGE", lang("Frais", "Fee"), openpgp_wallet_core::doge::format_doge(plan.fee));
            if plan.change > 0 {
                let change = openpgp_wallet_core::doge::format_doge(plan.change);
                line.push_str(lang(&format!("\nMonnaie rendue à votre adresse : {change} DOGE"), &format!("\nChange returned to your address: {change} DOGE")));
            }
            line
        }),
        "trx" => trx_plan.map(|plan| {
            let fee = openpgp_wallet_core::tron::format_trx(plan.fee_max);
            let mut line = lang(&format!("Frais : jusqu'à {fee} TRX"), &format!("Fee: up to {fee} TRX")).to_string();
            if plan.new_account {
                line.push_str(lang(", dont 1,1 TRX d'activation du compte destinataire (encore jamais utilisé)", ", including 1.1 TRX to activate the recipient account (never used yet)"));
            }
            line
        }),
        "xrp" => xrp_plan.map(|plan| {
            let (fee, reserve) = (openpgp_wallet_core::xrp::format_xrp(plan.fee), openpgp_wallet_core::xrp::format_xrp(plan.reserve));
            let mut line = lang(
                &format!("Frais : {fee} XRP\nRéserve du réseau : {reserve} XRP restent bloqués sur votre compte"),
                &format!("Fee: {fee} XRP\nNetwork reserve: {reserve} XRP stay locked on your account"),
            )
            .to_string();
            if plan.activates {
                line.push_str(lang("\nCe paiement active le compte destinataire (encore jamais utilisé)", "\nThis payment activates the recipient account (never used yet)"));
            }
            line
        }),
        "xlm" => xlm_plan.map(|plan| {
            let (fee, reserve) = (openpgp_wallet_core::stellar::format_xlm(i64::from(plan.fee)), openpgp_wallet_core::stellar::format_xlm(plan.reserve));
            let mut line = lang(
                &format!("Frais : jusqu'à {fee} XLM (seul le nécessaire est prélevé)\nRéserve du réseau : {reserve} XLM restent bloqués sur votre compte"),
                &format!("Fee: up to {fee} XLM (only what is needed is charged)\nNetwork reserve: {reserve} XLM stay locked on your account"),
            )
            .to_string();
            if plan.creates {
                line.push_str(lang("\nCe paiement crée le compte destinataire (encore jamais utilisé)", "\nThis payment creates the recipient account (never used yet)"));
            }
            line
        }),
        "near" => near_plan.map(|plan| {
            use openpgp_wallet_core::near::format_near_exact;
            let (actual, held, reserved) = (format_near_exact(plan.fee_actual), format_near_exact(plan.fee), format_near_exact(plan.reserved));
            let mut line = lang(
                &format!("Frais : environ {actual} NEAR (jusqu'à {held} NEAR retenus le temps de l'exécution, le surplus revient en quelques secondes)\nStockage du compte : {reserved} NEAR restent réservés"),
                &format!("Fee: about {actual} NEAR (up to {held} NEAR held during execution, the surplus comes back within seconds)\nAccount storage: {reserved} NEAR stay reserved"),
            )
            .to_string();
            if plan.creates {
                line.push_str(lang("\nCe virement crée le compte destinataire (encore jamais utilisé)", "\nThis transfer creates the recipient account (never used yet)"));
            }
            line
        }),
        "stx" => stx_plan.map(|plan| format!("{} : {} STX", lang("Frais", "Fee"), openpgp_wallet_core::stacks::format_stx(plan.fee))),
        "tao" => tao_plan.as_ref().map(|plan| format!("{} : {} TAO", lang("Frais", "Fee"), openpgp_wallet_core::bittensor::format_tao(plan.fee))),
        "ada" => ada_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} ADA", lang("Frais", "Fee"), openpgp_wallet_core::cardano::format_ada(plan.fee));
            if plan.change > 0 {
                let change = openpgp_wallet_core::cardano::format_ada(plan.change);
                line.push_str(lang(&format!("\nMonnaie rendue à votre adresse : {change} ADA"), &format!("\nChange returned to your address: {change} ADA")));
            }
            line
        }),
        "xmr" => xmr_plan.as_ref().map(|plan| {
            let mut line = format!("{} : {} XMR", lang("Frais", "Fee"), openpgp_wallet_core::monero::format_xmr(plan.fee));
            if plan.change > 0 {
                let change = openpgp_wallet_core::monero::format_xmr(plan.change);
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
        amount_line.push_str(lang(
            " (maximum, frais déduits)",
            " (maximum, fees deducted)",
        ));
    }
    // XRP: destination tag ALWAYS shown ("none" included), under the recipient, so a
    // tag forgotten for an exchange is noticed.
    let to_line = match (coin, destination_tag) {
        ("xrp", Some(tag)) => format!(
            "{to}\n{} {tag}",
            lang("Tag de destination :", "Destination tag:")
        ),
        ("xrp", None) => format!(
            "{to}\n{}",
            lang("Tag de destination : aucun", "Destination tag: none")
        ),
        // Stellar: memo ALWAYS shown, with its type (printable ASCII only, see
        // `stellar::parse_memo`).
        ("xlm", _) => match &memo {
            StellarMemo::None => format!("{to}\n{}", lang("Mémo : aucun", "Memo: none")),
            StellarMemo::Id(id) => {
                format!("{to}\n{} {id}", lang("Mémo (identifiant) :", "Memo (ID):"))
            }
            StellarMemo::Text(text) => format!(
                "{to}\n{} \"{text}\"",
                lang("Mémo (texte) :", "Memo (text):")
            ),
        },
        // Stacks: memo ALWAYS shown (printable ASCII only).
        ("stx", _) => match &note {
            Some(DestinationNote::StacksMemo(text)) => {
                format!("{to}\n{} \"{text}\"", lang("Mémo :", "Memo:"))
            }
            _ => format!("{to}\n{}", lang("Mémo : aucun", "Memo: none")),
        },
        _ => to.clone(),
    };
    if !confirm_transaction_native(
        app,
        network,
        &to_line,
        &amount_line,
        from_label,
        fee_line.as_deref(),
        warning.as_deref(),
        None,
    ) {
        return Err(translate_error("Virement annulé (confirmation refusée)."));
    }
    Ok(ConfirmedSend {
        to,
        amount,
        evm_fee,
        fee_sat,
        zec_fee: zec_plan.map(|plan| plan.fee),
        xmr_plan,
        doge_fee: doge_plan.map(|plan| plan.fee),
        trx_fee: trx_plan.map(|plan| plan.fee_max),
        xrp_fee: xrp_plan.map(|plan| plan.fee),
        xlm_fee: xlm_plan.map(|plan| plan.fee),
        near_fee: near_plan.map(|plan| plan.fee),
        ada_fee: ada_plan.map(|plan| plan.fee),
        stx_fee: stx_plan.map(|plan| plan.fee),
        tao_fee: tao_plan.map(|plan| plan.fee),
        note,
    })
}

// --- Ledger / Trezor accounts (core/src/hardware.rs) ---------------------------
//
// Commands that talk to the device or the network run through `run_blocking`: the
// device waits for the user's physical confirmation, sometimes for a long time,
// and the window must not freeze meanwhile.

/// Hardware account as displayed: the fingerprint and the Bitcoin extended public
/// key stay on the Rust side (not needed for display).
#[derive(Serialize)]
struct HardwareAccountDto {
    id: u32,
    label: String,
    /// "ledger" or "trezor".
    device: String,
    network: String,
    address: String,
    path: String,
}

impl From<hardware::HardwareAccount> for HardwareAccountDto {
    fn from(a: hardware::HardwareAccount) -> Self {
        Self {
            id: a.id,
            label: a.label,
            device: a.device,
            network: a.network,
            address: a.address,
            path: a.path,
        }
    }
}

fn hardware_account(dir: &std::path::Path, id: u32) -> Result<hardware::HardwareAccount, String> {
    hardware::list_accounts(dir)
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| translate_error("compte matériel introuvable"))
}

#[tauri::command]
fn hardware_accounts(app: tauri::AppHandle) -> Result<Vec<HardwareAccountDto>, String> {
    Ok(hardware::list_accounts(&data_dir(&app)?)
        .into_iter()
        .map(Into::into)
        .collect())
}

/// Runs `work` on a thread reserved for blocking operations (waiting for
/// confirmation on the device, `reqwest::blocking` network calls, native dialog):
/// neither on the main thread (frozen window), nor directly in an async task, which
/// is what `#[tauri::command(async)]` does with a synchronous function, where
/// `reqwest::blocking` panics and the command never answers (seen for real on a
/// Ledger account's balance).
async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| format!("opération interrompue : {e}"))?
}

#[tauri::command]
async fn hardware_connect(
    device: String,
    network: String,
    label: String,
    app: tauri::AppHandle,
) -> Result<HardwareAccountDto, String> {
    run_blocking(move || {
        hardware::connect_device(&data_dir(&app)?, &device, &network, &label)
            .map(Into::into)
            .t_err()
    })
    .await
}

#[tauri::command]
fn hardware_remove(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    hardware::remove_account(&data_dir(&app)?, id).t_err()
}

#[tauri::command]
async fn hardware_verify_address(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    run_blocking(move || hardware::verify_address_on_device(&data_dir(&app)?, id).t_err()).await
}

/// Same format as `get_balance` (Bitcoin: receive + change).
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
async fn hardware_estimate_btc_fees(
    id: u32,
    app: tauri::AppHandle,
) -> Result<BtcFeeEstimateDto, String> {
    run_blocking(move || {
        let estimate = hardware::estimate_btc_fees(&data_dir(&app)?, id).t_err()?;
        Ok(BtcFeeEstimateDto {
            fast_sat: estimate.fast_sat,
            medium_sat: estimate.medium_sat,
            slow_sat: estimate.slow_sat,
        })
    })
    .await
}

/// Send from a hardware account: the same validations, warnings and native dialog
/// as a wallet send (no password: nothing to unlock here), then review and
/// confirmation on the device's screen.
#[tauri::command]
async fn hardware_send(
    id: u32,
    to: String,
    amount: String,
    fee_sat: Option<u64>,
    app: tauri::AppHandle,
) -> Result<String, String> {
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
        let send = confirm_send(&app, &dir, &network, &to, &amount, fee_sat, &format!("{device} — {}", account.label), Some(&note), from, false, None)?;
        send_grace_period(&app, GraceRecap::new(network_label(&network), format!("{} {}", send.amount, network_unit(&network)), send.to.clone()).on(&network))?;
        let result = match network.as_str() {
            n if is_evm(n) => {
                let fee = send.evm_fee.ok_or_else(|| "frais EVM manquants".to_string())?;
                hardware::send_evm(&dir, id, &network, &send.to, &send.amount, fee).t_err()
            }
            "btc_testnet" | "btc_mainnet" => {
                let fee_sat = send.fee_sat.ok_or_else(|| lang("frais Bitcoin manquants : choisissez une vitesse d'envoi", "Bitcoin fee missing: choose a sending speed").to_string())?;
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

/// Tells whether a USDC send to `to` will charge extra rent (the recipient has no
/// USDC account yet). Read-only, called BEFORE confirmation so a hidden cost is
/// never revealed after the fact. `None` if the recipient's ATA already exists (no
/// extra cost), or if `to` is not a valid Solana address or the network read fails
/// (the error will be reported normally by `send_usdc` right after anyway; here we
/// would rather show nothing than block on a network problem before the
/// confirmation even starts).
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
//
// A real swap between different chains has no native on-chain mechanism: it
// necessarily goes through an external protocol (see core/src/thorchain_rpc.rs).

#[derive(Serialize)]
struct SwapQuoteDto {
    inbound_address: String,
    memo: String,
    /// Already on the 1e8 scale THORChain uses for ALL assets, so it can be displayed
    /// as is (divided by 1e8), without ever going back through the destination asset's
    /// native decimals.
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
    protocol: openpgp_wallet_core::swap_routes::Protocol,
) -> Result<SwapQuoteDto, String> {
    run_blocking(move || {
        let (protocol, from, to) =
            cross_chain_pair(&from_coin, &from_network, &to_coin, &to_network, protocol)?;
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
    &'static openpgp_wallet_core::thorchain_rpc::CrossChain,
    &'static openpgp_wallet_core::thorchain_rpc::ThorAsset,
    &'static openpgp_wallet_core::thorchain_rpc::ThorAsset,
);

/// Does the provider chosen in the UI directly connect these two cryptos (see
/// `swap_routes::direct_all`)?
fn provider_links(
    protocol: openpgp_wallet_core::swap_routes::Protocol,
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
) -> bool {
    use openpgp_wallet_core::swap_routes;
    swap_routes::find(from_coin, from_network)
        .zip(swap_routes::find(to_coin, to_network))
        .is_some_and(|(f, t)| swap_routes::direct_all(f, t).contains(&protocol))
}

/// Cross-chain swap pair designated by the UI, with the chosen provider (THORChain
/// or Maya): refused if that provider does not connect it.
fn cross_chain_pair(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
    protocol: openpgp_wallet_core::swap_routes::Protocol,
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

/// Maximum network fee for a swap from an EVM network: the deposit, plus the prior
/// approvals, plus the Ethereum posting fees (Base).
fn evm_swap_fee_line(fees: &api::EvmSwapFees, symbol: &str) -> Result<String, String> {
    let total = fees.max_total().t_err()? as f64 / 1e18;
    let l1 = (fees.deposit.l1_fee + fees.approve.l1_fee * fees.approvals as u128) as f64 / 1e18;
    let mut line = lang(
        &format!("Frais réseau maximum : {total:.8} {symbol}"),
        &format!("Maximum network fee: {total:.8} {symbol}"),
    )
    .to_string();
    if fees.approvals > 0 {
        line.push_str(lang(", autorisation comprise", ", approval included"));
    }
    if l1 > 0.0 {
        line.push_str(lang(
            &format!(", dont ≈ {l1:.8} {symbol} de publication sur Ethereum"),
            &format!(", incl. ≈ {l1:.8} {symbol} for posting to Ethereum"),
        ));
    }
    Ok(line)
}

/// Assets (`coin@network`) that THORChain and Maya are not swapping right now
/// (network halted: incident, maintenance).
#[derive(Serialize)]
struct SwapHaltsDto {
    thorchain: Vec<String>,
    maya: Vec<String>,
}

/// Address of profile `profile_index` on `network` (Rust caches filled at unlock).
fn profile_address(
    app: &tauri::AppHandle,
    network: &str,
    profile_index: u32,
) -> Result<String, String> {
    let unknown = || translate_error("adresse du profil inconnue — déverrouillez le portefeuille");
    let cached = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>| {
        cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned()
            .ok_or_else(unknown)
    };
    let evm_sol = || {
        app.state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned()
            .ok_or_else(unknown)
    };
    match network {
        n if is_evm(n) => Ok(evm_sol()?.0),
        "sol_mainnet" | "sol_devnet" => Ok(evm_sol()?.1),
        "btc_mainnet" => cached(&app.state::<ProfileBtcCache>().0),
        "btc_testnet" => cached(&app.state::<ProfileBtcTestnetCache>().0),
        "zec_mainnet" => cached(&app.state::<ProfileZcashCache>().0),
        "doge_mainnet" => cached(&app.state::<ProfileDogeCache>().0),
        "tron_mainnet" => cached(&app.state::<ProfileTronCache>().0),
        "xrp_mainnet" => cached(&app.state::<ProfileXrpCache>().0),
        "xlm_mainnet" => cached(&app.state::<ProfileStellarCache>().0),
        "near_mainnet" => cached(&app.state::<ProfileNearCache>().0),
        "ada_mainnet" => cached(&app.state::<ProfileCardanoCache>().0),
        "stx_mainnet" => cached(&app.state::<ProfileStacksCache>().0),
        "tao_mainnet" => cached(&app.state::<ProfileBittensorCache>().0),
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
    }
}

/// "Max" in the "Convert" window: the maximum amount for this swap, the swap's fees
/// deducted (see `api::swap_max`).
#[tauri::command]
async fn swap_max_amount(
    app: tauri::AppHandle,
    protocol: String,
    from_coin: String,
    from_network: String,
    to_coin: String,
    profile_index: u32,
) -> Result<String, String> {
    run_blocking(move || {
        let owner = profile_address(&app, &from_network, profile_index)?;
        api::swap_max(&protocol, &from_coin, &from_network, &to_coin, &owner).t_err()
    })
    .await
}

/// The profile's Cardano staking: registration, delegated pool, rewards.
#[derive(Serialize)]
struct AdaStakeStatusDto {
    reward_address: String,
    registered: bool,
    pool: Option<String>,
    ticker: Option<String>,
    voting: bool,
    rewards: String,
    rewards_lovelace: u64,
    deposit: String,
}

#[tauri::command]
async fn cardano_stake_status(
    app: tauri::AppHandle,
    profile_index: u32,
) -> Result<AdaStakeStatusDto, String> {
    run_blocking(move || {
        let from = own_address_on(&app, "ada_mainnet", profile_index)?;
        let account = openpgp_wallet_core::cardano::stake_account(&from).t_err()?;
        Ok(AdaStakeStatusDto {
            reward_address: openpgp_wallet_core::cardano::reward_address(&from).t_err()?,
            registered: account.registered,
            ticker: account
                .pool
                .as_deref()
                .and_then(openpgp_wallet_core::cardano::pool_ticker),
            pool: account.pool,
            voting: account.voting,
            rewards: openpgp_wallet_core::cardano::format_ada(account.rewards),
            rewards_lovelace: account.rewards,
            deposit: openpgp_wallet_core::cardano::format_ada(account.deposit),
        })
    })
    .await
}

#[derive(Serialize)]
struct AdaPoolDto {
    id: String,
    ticker: String,
    margin_percent: f64,
    fixed_cost_ada: u64,
    active_stake_ada: u64,
}

/// Cardano pools offered (see `cardano::pools`).
#[tauri::command]
async fn cardano_pools() -> Result<Vec<AdaPoolDto>, String> {
    run_blocking(|| {
        Ok(openpgp_wallet_core::cardano::pools()
            .t_err()?
            .into_iter()
            .map(|p| AdaPoolDto {
                margin_percent: p.margin * 100.0,
                fixed_cost_ada: p.fixed_cost / 1_000_000,
                active_stake_ada: p.active_stake / 1_000_000,
                id: p.id,
                ticker: p.ticker,
            })
            .collect())
    })
    .await
}

/// Native dialog for a Cardano staking operation.
fn confirm_ada_stake_native(
    app: &tauri::AppHandle,
    from_label: &str,
    action: api::AdaStakeAction,
    plan: &openpgp_wallet_core::cardano::StakePlan,
    pool: Option<(&str, Option<&str>)>,
) -> bool {
    use openpgp_wallet_core::cardano::format_ada;
    let from_label = dialog_label(from_label);
    let fee = format_ada(plan.fee);
    let pool_line = pool.map(|(id, ticker)| {
        let short = format!(
            "{}…{}",
            &id[..id.len().min(12)],
            &id[id.len().saturating_sub(6)..]
        );
        match ticker {
            Some(t) => format!("{} ({short})", dialog_label(t)),
            None => short,
        }
    });
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let (title, body) = match (action, plan.vote_only(), english) {
        (_, true, false) => (
            "Activer le retrait des récompenses",
            format!("Étape 1 sur 2 — délégation de vote « abstention », exigée par Cardano pour retirer des récompenses.

Depuis le profil : {from_label}
Frais du réseau : {fee} ADA

Relancez ensuite l'opération pour retirer vos récompenses."),
        ),
        (_, true, true) => (
            "Enable reward withdrawal",
            format!("Step 1 of 2 — \"abstain\" vote delegation, required by Cardano to withdraw rewards.

From profile: {from_label}
Network fee: {fee} ADA

Then run the operation again to withdraw your rewards."),
        ),
        (api::AdaStakeAction::Delegate, false, false) => (
            "Staker vos ADA",
            format!(
                "Délégation Cardano à un pool

Depuis le profil : {from_label}
Pool : {}
{}Frais du réseau : {fee} ADA

Vos ADA restent dans votre portefeuille et dépensables à tout moment. Délégation de vote : « abstention » (exigée pour retirer les récompenses).
Récompenses : dès 15 à 20 jours, puis tous les 5 jours.

Confirmer ?",
                pool_line.unwrap_or_default(),
                if plan.deposit > 0 { format!("Dépôt : {} ADA (rendu à l'arrêt de la délégation)
", format_ada(plan.deposit)) } else { String::new() }
            ),
        ),
        (api::AdaStakeAction::Delegate, false, true) => (
            "Stake your ADA",
            format!(
                "Cardano delegation to a pool

From profile: {from_label}
Pool: {}
{}Network fee: {fee} ADA

Your ADA stays in your wallet and spendable at any time. Vote delegation: \"abstain\" (required to withdraw rewards).
Rewards: from 15 to 20 days, then every 5 days.

Confirm?",
                pool_line.unwrap_or_default(),
                if plan.deposit > 0 { format!("Deposit: {} ADA (returned when you stop delegating)
", format_ada(plan.deposit)) } else { String::new() }
            ),
        ),
        (api::AdaStakeAction::Withdraw, false, false) => (
            "Retirer vos récompenses",
            format!("Retrait des récompenses Cardano

Depuis le profil : {from_label}
Récompenses : {} ADA
Frais du réseau : {fee} ADA

Elles arrivent sur votre adresse Cardano. La délégation continue.

Confirmer ?", format_ada(plan.withdrawal)),
        ),
        (api::AdaStakeAction::Withdraw, false, true) => (
            "Withdraw your rewards",
            format!("Cardano reward withdrawal

From profile: {from_label}
Rewards: {} ADA
Network fee: {fee} ADA

They arrive on your Cardano address. Delegation continues.

Confirm?", format_ada(plan.withdrawal)),
        ),
        (api::AdaStakeAction::Undelegate, false, false) => (
            "Arrêter le staking",
            format!("Arrêt de la délégation Cardano

Depuis le profil : {from_label}
Récompenses retirées : {} ADA
Dépôt rendu : {} ADA
Frais du réseau : {fee} ADA

Confirmer ?", format_ada(plan.withdrawal), format_ada(plan.refund)),
        ),
        (api::AdaStakeAction::Undelegate, false, true) => (
            "Stop staking",
            format!("Stopping Cardano delegation

From profile: {from_label}
Rewards withdrawn: {} ADA
Deposit returned: {} ADA
Network fee: {fee} ADA

Confirm?", format_ada(plan.withdrawal), format_ada(plan.refund)),
        ),
    };
    app.dialog()
        .message(body)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Cardano staking operation: prepared, confirmed (native dialog), cancellation
/// delay, then signed and broadcast.
#[tauri::command]
async fn cardano_stake(
    app: tauri::AppHandle,
    password: String,
    action: String,
    pool: Option<String>,
    profile_index: u32,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let action = match action.as_str() {
            "delegate" => api::AdaStakeAction::Delegate,
            "withdraw" => api::AdaStakeAction::Withdraw,
            "undelegate" => api::AdaStakeAction::Undelegate,
            other => return Err(translate_error(&format!("opération inconnue : {other}"))),
        };
        let pool = if action == api::AdaStakeAction::Delegate {
            pool
        } else {
            None
        };
        let from = own_address_on(&app, "ada_mainnet", profile_index)?;
        let account = openpgp_wallet_core::cardano::stake_account(&from).t_err()?;
        let plan = api::ada_stake_plan(&from, &account, action, pool.as_deref()).t_err()?;
        let ticker = pool
            .as_deref()
            .and_then(openpgp_wallet_core::cardano::pool_ticker);
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));
        if !confirm_ada_stake_native(
            &app,
            &from_label,
            action,
            &plan,
            pool.as_deref().map(|id| (id, ticker.as_deref())),
        ) {
            return Err(translate_error("Opération annulée (confirmation refusée)."));
        }
        let what = match (action, plan.vote_only()) {
            (_, true) => lang("Délégation de vote Cardano", "Cardano vote delegation"),
            (api::AdaStakeAction::Delegate, _) => lang("Staking Cardano", "Cardano staking"),
            (api::AdaStakeAction::Withdraw, _) => {
                lang("Retrait des récompenses", "Reward withdrawal")
            }
            (api::AdaStakeAction::Undelegate, _) => lang("Arrêt du staking", "Stop staking"),
        };
        let amount = match action {
            api::AdaStakeAction::Delegate => {
                ticker.clone().or_else(|| pool.clone()).unwrap_or_default()
            }
            _ => format!(
                "{} ADA",
                openpgp_wallet_core::cardano::format_ada(plan.withdrawal)
            ),
        };
        grace_period(
            &app,
            "Opération annulée pendant le délai d'annulation.",
            GraceRecap::new(what, amount, from.clone()).on("ada_mainnet"),
        )?;
        api::send_ada_stake(
            &dir,
            &password,
            action,
            pool.as_deref(),
            &plan,
            profile_index,
        )
        .t_err()
    })
    .await
}

/// The profile's native Solana staking: stake accounts, epoch, minimum.
#[derive(Serialize)]
struct SolStakeAccountDto {
    address: String,
    status: openpgp_wallet_core::sol_stake::StakeStatus,
    amount: String,
    lamports: u64,
    validator: Option<String>,
    validator_name: Option<String>,
    validator_flagged: bool,
    can_deactivate: bool,
    locked: bool,
}

#[derive(Serialize)]
struct SolStakeStatusDto {
    accounts: Vec<SolStakeAccountDto>,
    /// Total SOL in the stake accounts (reserves included).
    total: String,
    total_lamports: u64,
    epoch_ends_in: String,
    min_delegation: String,
    rent_reserve: String,
}

#[tauri::command]
async fn sol_stake_status(
    app: tauri::AppHandle,
    profile_index: u32,
) -> Result<SolStakeStatusDto, String> {
    use openpgp_wallet_core::sol_rpc::format_lamports;
    run_blocking(move || {
        let owner = own_address_on(&app, "sol_mainnet", profile_index)?;
        let view = api::sol_stake_overview(&owner).t_err()?;
        let total_lamports = view.accounts.iter().map(|a| a.lamports).sum();
        Ok(SolStakeStatusDto {
            accounts: view
                .accounts
                .into_iter()
                .map(|a| SolStakeAccountDto {
                    amount: format_lamports(a.lamports),
                    address: a.address,
                    status: a.status,
                    lamports: a.lamports,
                    validator: a.validator,
                    validator_name: a.validator_name,
                    validator_flagged: a.validator_flagged,
                    can_deactivate: a.can_deactivate,
                    locked: a.locked,
                })
                .collect(),
            total: format_lamports(total_lamports),
            total_lamports,
            epoch_ends_in: openpgp_wallet_core::sol_stake::duration_text(view.epoch.ends_in_secs),
            min_delegation: format_lamports(view.min_delegation),
            rent_reserve: format_lamports(view.rent_reserve),
        })
    })
    .await
}

/// SOL natively staked by the profile (lamports), for the SOL card: a single read,
/// without the detailed state of `sol_stake_status`.
#[tauri::command]
async fn sol_staked_total(app: tauri::AppHandle, profile_index: u32) -> Result<u64, String> {
    run_blocking(move || {
        let owner = own_address_on(&app, "sol_mainnet", profile_index)?;
        api::sol_staked_lamports(&owner).t_err()
    })
    .await
}

/// Solana validators offered (see `sol_stake::validators`).
#[tauri::command]
async fn sol_validators() -> Result<Vec<openpgp_wallet_core::sol_stake::Validator>, String> {
    run_blocking(|| api::sol_validators().t_err()).await
}

/// "Max" of the native staking window.
#[tauri::command]
async fn sol_stake_max(app: tauri::AppHandle, profile_index: u32) -> Result<String, String> {
    run_blocking(move || {
        let owner = own_address_on(&app, "sol_mainnet", profile_index)?;
        api::sol_stake_max(&owner).t_err()
    })
    .await
}

/// Native dialog for a native Solana staking operation.
fn confirm_sol_stake_native(
    app: &tauri::AppHandle,
    from_label: &str,
    plan: &openpgp_wallet_core::sol_stake::Plan,
    validator_name: Option<&str>,
    epoch_ends_in: &str,
) -> bool {
    use openpgp_wallet_core::sol_rpc::format_lamports;
    use openpgp_wallet_core::sol_stake::Action;
    let from_label = dialog_label(from_label);
    let fee = format_lamports(plan.fee);
    let amount = format_lamports(plan.lamports);
    let rent = format_lamports(plan.rent_reserve);
    let short = |text: &str| {
        format!(
            "{}…{}",
            &text[..text.len().min(6)],
            &text[text.len().saturating_sub(6)..]
        )
    };
    let validator = plan.validator.as_deref().map(|vote| match validator_name {
        Some(name) => format!("{} ({})", dialog_label(name), short(vote)),
        None => short(vote),
    });
    let stake_account = short(&plan.stake_account);
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let (title, body) = match (plan.action, english) {
        (Action::Delegate, false) => (
            "Staker vos SOL",
            format!(
                "Staking natif Solana

Depuis le profil : {from_label}
Montant : {amount} SOL
Validateur : {}
Commission du validateur : {} %
Réserve du compte de mise : {rent} SOL (rendue au retrait)
Frais du réseau : {fee} SOL

Vos SOL restent à vous, sur un compte de mise dont vous êtes la seule autorité. Récompenses à chaque époque (environ 2 jours), dès la prochaine.
Pour les récupérer : arrêt du staking, puis retrait à l'époque suivante.

Confirmer ?",
                validator.unwrap_or_default(),
                plan.commission.unwrap_or(0)
            ),
        ),
        (Action::Delegate, true) => (
            "Stake your SOL",
            format!(
                "Solana native staking

From profile: {from_label}
Amount: {amount} SOL
Validator: {}
Validator commission: {}%
Stake account reserve: {rent} SOL (returned on withdrawal)
Network fee: {fee} SOL

Your SOL stays yours, in a stake account you alone control. Rewards every epoch (about 2 days), starting with the next one.
To get it back: stop staking, then withdraw in the following epoch.

Confirm?",
                validator.unwrap_or_default(),
                plan.commission.unwrap_or(0)
            ),
        ),
        (Action::Deactivate, false) => (
            "Arrêter le staking",
            format!(
                "Arrêt du staking natif Solana

Depuis le profil : {from_label}
Compte de mise : {stake_account} — {amount} SOL
Validateur : {}
Frais du réseau : {fee} SOL

Les récompenses s'arrêtent à la fin de l'époque en cours. Retrait possible ensuite, dans {epoch_ends_in} environ.

Confirmer ?",
                validator.unwrap_or_default()
            ),
        ),
        (Action::Deactivate, true) => (
            "Stop staking",
            format!(
                "Stopping Solana native staking

From profile: {from_label}
Stake account: {stake_account} — {amount} SOL
Validator: {}
Network fee: {fee} SOL

Rewards stop at the end of the current epoch. Withdrawal is possible after that, in about {epoch_ends_in}.

Confirm?",
                validator.unwrap_or_default()
            ),
        ),
        (Action::Withdraw, false) => (
            "Retirer vos SOL",
            format!(
                "Retrait d'un compte de mise Solana

Depuis le profil : {from_label}
Compte de mise : {stake_account}
Montant : {amount} SOL (réserve comprise), vers votre adresse Solana
Frais du réseau : {fee} SOL

Le compte de mise est ensuite fermé.

Confirmer ?"
            ),
        ),
        (Action::Withdraw, true) => (
            "Withdraw your SOL",
            format!(
                "Withdrawal from a Solana stake account

From profile: {from_label}
Stake account: {stake_account}
Amount: {amount} SOL (reserve included), to your Solana address
Network fee: {fee} SOL

The stake account is then closed.

Confirm?"
            ),
        ),
    };
    app.dialog()
        .message(body)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Native Solana staking operation: prepared and simulated, confirmed (native
/// dialog), cancellation delay, then signed and broadcast.
#[tauri::command]
async fn sol_stake(
    app: tauri::AppHandle,
    password: String,
    action: String,
    amount: Option<String>,
    target: String,
    profile_index: u32,
) -> Result<String, String> {
    use openpgp_wallet_core::sol_stake::Action;
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let action = match action.as_str() {
            "delegate" => Action::Delegate,
            "deactivate" => Action::Deactivate,
            "withdraw" => Action::Withdraw,
            other => return Err(translate_error(&format!("opération inconnue : {other}"))),
        };
        let amount = if action == Action::Delegate {
            amount
        } else {
            None
        };
        let owner = own_address_on(&app, "sol_mainnet", profile_index)?;
        let plan = api::sol_stake_plan(&owner, action, amount.as_deref(), &target).t_err()?;
        // Validator name and end of epoch: display only.
        let view = if action == Action::Delegate {
            None
        } else {
            api::sol_stake_overview(&owner).ok()
        };
        let validator_name = match action {
            Action::Delegate => plan
                .validator
                .as_deref()
                .and_then(openpgp_wallet_core::sol_stake::validator_name),
            _ => view.as_ref().and_then(|v| {
                v.accounts
                    .iter()
                    .find(|a| a.address == plan.stake_account)
                    .and_then(|a| a.validator_name.clone())
            }),
        };
        let epoch_ends_in = view
            .map(|v| openpgp_wallet_core::sol_stake::duration_text(v.epoch.ends_in_secs))
            .unwrap_or_else(|| "2 j".into());
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));
        if !confirm_sol_stake_native(
            &app,
            &from_label,
            &plan,
            validator_name.as_deref(),
            &epoch_ends_in,
        ) {
            return Err(translate_error("Opération annulée (confirmation refusée)."));
        }
        let what = match action {
            Action::Delegate => lang("Staking Solana", "Solana staking"),
            Action::Deactivate => lang("Arrêt du staking", "Stop staking"),
            Action::Withdraw => lang("Retrait du staking", "Staking withdrawal"),
        };
        let amount_text = format!(
            "{} SOL",
            openpgp_wallet_core::sol_rpc::format_lamports(plan.lamports)
        );
        grace_period(
            &app,
            "Opération annulée pendant le délai d'annulation.",
            GraceRecap::new(what, amount_text, plan.stake_account.clone()).on("sol_mainnet"),
        )?;
        api::send_sol_stake(
            &dir,
            &password,
            action,
            amount.as_deref(),
            &target,
            &plan,
            profile_index,
        )
        .t_err()
    })
    .await
}

/// Annual yields of liquid staking (JitoSOL, stETH), for the note in "Convert" (see
/// `core/src/staking.rs`).
#[tauri::command]
async fn staking_aprs() -> Result<openpgp_wallet_core::staking::Aprs, String> {
    run_blocking(|| Ok(openpgp_wallet_core::staking::aprs())).await
}

/// Swap providers that are not responding right now (the red messages in the
/// "Convert" window, see `swap_health`).
#[tauri::command]
async fn swap_health() -> Result<Vec<openpgp_wallet_core::swap_health::Issue>, String> {
    run_blocking(|| Ok(openpgp_wallet_core::swap_health::check())).await
}

/// Read when the "Convert" window opens: a provider that is halted for the chosen swap
/// is no longer offered by default. If the read fails, nothing is flagged (the quote
/// will then state the halt in plain words).
#[tauri::command]
async fn swap_halts() -> Result<SwapHaltsDto, String> {
    use openpgp_wallet_core::thorchain_rpc::{CrossChain, MAYA, THORCHAIN};
    run_blocking(|| {
        let keys = |protocol: &CrossChain| -> Vec<String> {
            match protocol.halted_assets() {
                Ok(assets) => assets
                    .iter()
                    .map(|a| format!("{}@{}", a.coin, a.network))
                    .collect(),
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
    /// Protocol of the (first) step.
    protocol: openpgp_wallet_core::swap_routes::Protocol,
    /// Direct pair: every possible provider, the preferred one first (empty for a
    /// two-step swap).
    protocols: Vec<openpgp_wallet_core::swap_routes::Protocol>,
    /// The app's affiliate fee for each of `protocols` (basis points): 0 from Bitcoin
    /// or Zcash through THORChain or Maya without a short name.
    fees_bps: Vec<u32>,
    /// Two-step swap: intermediate crypto and the second step's protocol (`None` for a
    /// direct swap).
    via: Option<openpgp_wallet_core::swap_routes::SwapAsset>,
    then_protocol: Option<openpgp_wallet_core::swap_routes::Protocol>,
}

/// Possible swap pairs, direct or in two steps (see `core/src/swap_routes.rs`):
/// what the "Convert" window offers. The swap commands only accept a direct pair:
/// one step at a time. Asynchronous: the fees shown depend on the affiliate name,
/// read from THORChain and Maya (see `thorchain_rpc::CrossChain::affiliate_for`).
#[tauri::command]
async fn swap_pairs() -> Vec<SwapPairDto> {
    run_blocking(|| Ok::<_, String>(swap_pair_dtos()))
        .await
        .unwrap_or_default()
}

fn swap_pair_dtos() -> Vec<SwapPairDto> {
    openpgp_wallet_core::swap_routes::routes()
        .into_iter()
        .map(|(from, to, route)| {
            let protocols = if route.via.is_none() {
                openpgp_wallet_core::swap_routes::direct_all(from, to)
            } else {
                Vec::new()
            };
            SwapPairDto {
                from_coin: from.coin,
                from_network: from.network,
                to_coin: to.coin,
                to_network: to.network,
                protocol: route.first,
                fees_bps: protocols
                    .iter()
                    .map(|p| openpgp_wallet_core::swap_routes::affiliate_fee_bps(*p, from, to))
                    .collect(),
                protocols,
                via: route.via.map(|(via, _)| via),
                then_protocol: route.via.map(|(_, second)| second),
            }
        })
        .collect()
}

/// Native confirmation specific to swaps: unlike a normal send, it states
/// explicitly that an EXTERNAL protocol (THORChain) is involved, with its own fees
/// plus the 0.80% affiliate fee, and that the app itself cannot guarantee how things
/// go beyond sending this transaction (see core/src/thorchain_rpc.rs for the full
/// context).
///
/// It also shows the real vault address (`inbound_address`, and the router contract
/// for an EVM swap). Found during this feature's audit: unlike
/// `confirm_transaction_native` (normal send), which ALWAYS shows the real
/// recipient precisely to guard against "blind signing" (audit round 15), this
/// dialog only showed the amount/asset, never the address actually paid. That
/// address comes from a third party (the THORChain gateway queried for the quote,
/// never a node run by this project): showing it does not make it more trustworthy
/// in itself, but it restores the same "sign what you see" principle as the rest of
/// the app, and gives an attentive user a chance to spot an obviously inconsistent
/// address.
///
/// It also shows `final_destination` (the address on the DESTINATION chain, the one
/// THORChain will pay once the swap executes). Found in the same audit: unlike the
/// vault (opaque, the user cannot judge whether it is legitimate), this address is
/// normally THEIR OWN (pre-filled by the frontend, but still editable), exactly the
/// kind of value an address hijack (clipboard, compromised frontend) would try to
/// alter, and one the user CAN check against the address already shown elsewhere in
/// the app for that network.
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
    let network_fee_line = network_fee_line
        .map(|f| format!("{f}\n"))
        .unwrap_or_default();
    // From Bitcoin or Zcash without a short name: no fee for the app (see
    // `thorchain_rpc::CrossChain::charges_affiliate`).
    let affiliate_en = if affiliate {
        ", plus a 0.80% affiliate fee"
    } else {
        ", with no affiliate fee for this app on this swap"
    };
    let affiliate_fr = if affiliate {
        ", plus 0,80% de frais d'affiliation"
    } else {
        ", sans frais d'affiliation pour cette app sur cet échange"
    };
    let approval_line = approval_line.map(|a| format!("{a}\n")).unwrap_or_default();
    let from_label = dialog_label(from_label);
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let vault_line = match (router, english) {
        (Some(router), true) => format!(
            "Actual destination: router contract {router}\n({protocol} vault targeted: {pay_to})\n"
        ),
        (Some(router), false) => format!(
            "Destination réelle : contrat routeur {router}\n(coffre {protocol} visé : {pay_to})\n"
        ),
        (None, true) => format!("Actual destination: {pay_to}\n"),
        (None, false) => format!("Destination réelle : {pay_to}\n"),
    };
    // Address of a profile of this wallet (addresses derived on the Rust side): named,
    // instead of "check that this really is your address".
    let arrival_line = if final_destination.is_empty() {
        String::new()
    } else if let Some(label) = own_destination {
        if english {
            format!("Funds will arrive at: {final_destination}\n(your profile \"{label}\" — an address of this wallet)\n")
        } else {
            format!("Les fonds arriveront sur : {final_destination}\n(votre profil « {label} » — adresse de ce portefeuille)\n")
        }
    } else if english {
        format!(
            "Funds will arrive at: {final_destination}\n(verify this is really your own address)\n"
        )
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
    protocol: openpgp_wallet_core::swap_routes::Protocol,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (protocol, from, to) = cross_chain_pair(&from_coin, &from_network, &to_coin, &to_network, protocol)?;

        // Canonical forms, shown AND used for the quote and the signature (see
        // `send_transaction`).
        let amount = api::canonical_swap_amount(from, &amount).t_err()?;
        let destination = canonical_address_input(&destination)?;

        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Quote obtained HERE, just before the confirmation, never cached (a live
        // THORChain vault address, see thorchain_rpc::SwapQuote).
        let quote = api::get_swap_quote(protocol, from, to, &amount, &destination).t_err()?;
        let amount_line = format!("{amount} {}", from.symbol);

        // Network fees shown BEFORE confirmation (and, for an EVM network, the gas price
        // reused as is for signing; see `api::evm_gas_price_for_confirmation`). Mainnets
        // only: THORChain pools do not exist on test networks.
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
                let fee = openpgp_wallet_core::zcash::format_zec(plan.fee);
                Some(lang(&format!("Frais réseau Zcash : au plus {fee} ZEC"), &format!("Zcash network fee: at most {fee} ZEC")).to_string())
            }
            _ => Some(
                lang(
                    "Frais réseau : vitesse moyenne (plafonnés par l'app)",
                    "Network fee: medium speed (capped by the app)",
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
        swap_grace_period(
            &app,
            GraceRecap::swap(
                lang(&format!("Échange via {}", protocol.name), &format!("Swap via {}", protocol.name)),
                format!("{amount_line} → ~{} {}", format_1e8(quote.expected_amount_out), to.symbol),
                destination.clone(),
            )
            .on(from.network),
        )?;

        // Quote reread after the confirmation (the native dialog blocks for an arbitrary
        // time, during which the vault may rotate), but refused if it no longer matches
        // what was SHOWN; see `api::refresh_swap_quote_matching`.
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

// --- Swap through SwapKit (NEAR Intents, Chainflip)
// ------------------------------
//
// See core/src/swapkit.rs: SwapKit opens a deposit, which the provider itself
// confirms (address, cryptos, amount, delivery and refund to the user, minimum,
// deadline) before the native dialog; the deposit is an ordinary transfer built
// and signed here.

fn swapkit_pair(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
) -> Result<
    (
        &'static openpgp_wallet_core::swapkit::Asset,
        &'static openpgp_wallet_core::swapkit::Asset,
    ),
    String,
> {
    use openpgp_wallet_core::swapkit;
    if !provider_links(
        openpgp_wallet_core::swap_routes::Protocol::Swapkit,
        from_coin,
        from_network,
        to_coin,
        to_network,
    ) {
        return Err(translate_error(
            "échange non disponible entre ces deux cryptos",
        ));
    }
    swapkit::find(from_coin, from_network)
        .zip(swapkit::find(to_coin, to_network))
        .ok_or_else(|| translate_error("échange non disponible entre ces deux cryptos"))
}

/// The profile's address on the source network (refund of a failed swap), based on
/// the addresses derived at unlock.
fn own_address_on(
    app: &tauri::AppHandle,
    network: &str,
    profile_index: u32,
) -> Result<String, String> {
    let unknown = || translate_error("adresse du profil inconnue — déverrouillez le portefeuille");
    let from_cache = |cache: &std::sync::Mutex<std::collections::HashMap<u32, String>>| {
        cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .cloned()
            .ok_or_else(unknown)
    };
    match network {
        n if is_evm(n) => app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(evm, _)| evm.clone())
            .ok_or_else(unknown),
        "sol_mainnet" => app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(_, sol)| sol.clone())
            .ok_or_else(unknown),
        "btc_mainnet" => from_cache(&app.state::<ProfileBtcCache>().0),
        "doge_mainnet" => from_cache(&app.state::<ProfileDogeCache>().0),
        "zec_mainnet" => from_cache(&app.state::<ProfileZcashCache>().0),
        "tron_mainnet" => from_cache(&app.state::<ProfileTronCache>().0),
        "xrp_mainnet" => from_cache(&app.state::<ProfileXrpCache>().0),
        "near_mainnet" => from_cache(&app.state::<ProfileNearCache>().0),
        "ada_mainnet" => from_cache(&app.state::<ProfileCardanoCache>().0),
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
    }
}

#[derive(Serialize)]
struct SwapkitQuoteDto {
    provider: &'static str,
    expected_out: String,
    min_out: String,
    duration_secs: u64,
    fee_bps: u32,
}

/// Preview: the best quote from NEAR Intents and Chainflip through SwapKit (the
/// deposit is only opened, then checked, at confirmation).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn get_swapkit_quote(
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<SwapkitQuoteDto, String> {
    run_blocking(move || {
        let (from, to) = swapkit_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        let units = openpgp_wallet_core::tokens::parse_amount(&amount, from.decimals).t_err()?;
        let destination = canonical_address_input(&destination)?;
        let source = own_address_on(&app, from.network, profile_index)?;
        let routes =
            openpgp_wallet_core::swapkit::quote(from, to, units, &source, &destination).t_err()?;
        let best = &routes[0];
        Ok(SwapkitQuoteDto {
            provider: best.provider.name(),
            // At most 8 decimals, TRUNCATED: the minimum shown never exceeds the guaranteed
            // minimum (NEAR: 24 decimals on-chain).
            expected_out: openpgp_wallet_core::tokens::format_balance(
                best.expected_out,
                to.decimals,
                8,
            ),
            min_out: openpgp_wallet_core::tokens::format_balance(best.min_out, to.decimals, 8),
            duration_secs: best.total_secs,
            fee_bps: openpgp_wallet_core::swapkit::SERVICE_FEE_BPS
                + openpgp_wallet_core::swapkit::AFFILIATE_FEE_BPS,
        })
    })
    .await
}

/// Deposit for a swap (SwapKit, MoonPay Trade): an ordinary transfer prepared
/// BEFORE the dialog, with the fee shown and then never exceeded, balance checked.
enum DepositSend {
    Evm(api::EvmFee),
    Erc20(api::EvmFee),
    Sol,
    Spl,
    Btc(u64),
    Doge(u64),
    Zec(u64),
    Trx(u64),
    Xrp(u64),
    Near(u128),
    Ada(u64),
}

/// `xrp_tag`: destination tag of an XRP deposit (MoonPay Trade).
fn prepare_deposit(
    coin: &str,
    network: &str,
    source: &str,
    deposit: &str,
    amount: &str,
    xrp_tag: Option<u32>,
) -> Result<(DepositSend, String), String> {
    let native = openpgp_wallet_core::tokens::find(coin, network).is_none();
    match network {
        n if is_evm(n) => {
            let net = evm_network(n)?;
            api::validate_evm_recipient(deposit).t_err()?;
            if native {
                let fee =
                    api::evm_transfer_fee_for_confirmation(net, Some(source), deposit, amount)
                        .t_err()?;
                api::ensure_evm_transfer_funds(net, source, amount, fee).t_err()?;
                Ok((
                    DepositSend::Evm(fee),
                    evm_fee_line_for(fee, net.native_symbol),
                ))
            } else {
                let fee =
                    api::erc20_fee_for_confirmation(coin, n, source, deposit, amount).t_err()?;
                api::ensure_token_funds(coin, n, source, amount).t_err()?;
                api::ensure_evm_gas_funds(net, source, fee).t_err()?;
                Ok((
                    DepositSend::Erc20(fee),
                    evm_fee_line_for(fee, net.native_symbol),
                ))
            }
        }
        "sol_mainnet" => {
            let net = sol_network("sol_mainnet")?;
            api::check_solana_recipient(deposit, net).t_err()?;
            if native {
                api::ensure_sol_transfer_funds(net, source, amount).t_err()?;
                Ok((
                    DepositSend::Sol,
                    lang("Frais réseau : 0,000005 SOL", "Network fee: 0.000005 SOL").to_string(),
                ))
            } else {
                api::ensure_token_funds(coin, "sol_mainnet", source, amount).t_err()?;
                let mint = if coin == "usdc" {
                    Ok(openpgp_wallet_core::sol_spl::usdc_mint_mainnet())
                } else {
                    api::registered_spl_mint(coin)
                };
                let rent = mint.ok().and_then(|mint| {
                    api::spl_ata_rent_lamports_if_missing(deposit, &mint, net)
                        .ok()
                        .flatten()
                });
                let line = match rent {
                    Some(lamports) => {
                        let sol = lamports as f64 / 1e9;
                        lang(
                            &format!("Frais réseau : 0,000005 SOL, plus ≈ {sol:.6} SOL de création du compte de jetons de l'adresse de dépôt"),
                            &format!("Network fee: 0.000005 SOL, plus ≈ {sol:.6} SOL to create the deposit address's token account"),
                        )
                        .to_string()
                    }
                    None => {
                        lang("Frais réseau : 0,000005 SOL", "Network fee: 0.000005 SOL").to_string()
                    }
                };
                Ok((DepositSend::Spl, line))
            }
        }
        "btc_mainnet" => {
            let net = btc_network("btc_mainnet")?;
            api::check_btc_recipient(net, deposit, amount).t_err()?;
            let fee_sat = api::estimate_btc_fees(source, net).t_err()?.medium_sat;
            api::ensure_btc_transfer_funds(net, source, amount, fee_sat).t_err()?;
            Ok((
                DepositSend::Btc(fee_sat),
                format!(
                    "{} : {} BTC",
                    lang("Frais réseau", "Network fee"),
                    openpgp_wallet_core::tokens::format_amount(u128::from(fee_sat), 8)
                ),
            ))
        }
        "doge_mainnet" => {
            let plan = api::doge_send_plan(source, deposit, amount).t_err()?;
            Ok((
                DepositSend::Doge(plan.fee),
                format!(
                    "{} : {} DOGE",
                    lang("Frais réseau", "Network fee"),
                    openpgp_wallet_core::doge::format_doge(plan.fee)
                ),
            ))
        }
        "zec_mainnet" => {
            let plan = api::zec_send_plan(source, deposit, amount).t_err()?;
            Ok((
                DepositSend::Zec(plan.fee),
                format!(
                    "{} : {} ZEC",
                    lang("Frais réseau", "Network fee"),
                    openpgp_wallet_core::zcash::format_zec(plan.fee)
                ),
            ))
        }
        "tron_mainnet" => {
            let plan = api::trx_send_plan(source, deposit, amount).t_err()?;
            let fee = openpgp_wallet_core::tron::format_trx(plan.fee_max);
            Ok((
                DepositSend::Trx(plan.fee_max),
                lang(
                    &format!("Frais réseau : jusqu'à {fee} TRX"),
                    &format!("Network fee: up to {fee} TRX"),
                )
                .to_string(),
            ))
        }
        // r… deposit address, with the provider's tag if it gives one; without a tag, a
        // deposit that would require one is refused by the preparation (account flag
        // reread).
        "xrp_mainnet" => {
            let plan = api::xrp_send_plan(source, deposit, amount, xrp_tag).t_err()?;
            let fee = openpgp_wallet_core::xrp::format_xrp(plan.fee);
            Ok((
                DepositSend::Xrp(plan.fee),
                lang(
                    &format!("Frais réseau : {fee} XRP"),
                    &format!("Network fee: {fee} XRP"),
                )
                .to_string(),
            ))
        }
        // Deposit address with a payment key (a contract would be refused).
        "ada_mainnet" => {
            let plan = api::ada_send_plan(source, deposit, amount).t_err()?;
            Ok((
                DepositSend::Ada(plan.fee),
                format!(
                    "{} : {} ADA",
                    lang("Frais réseau", "Network fee"),
                    openpgp_wallet_core::cardano::format_ada(plan.fee)
                ),
            ))
        }
        // A plain transfer to the deposit's implicit account.
        "near_mainnet" => {
            let plan = api::near_send_plan(source, deposit, amount).t_err()?;
            let (actual, held) = (
                openpgp_wallet_core::near::format_near_exact(plan.fee_actual),
                openpgp_wallet_core::near::format_near_exact(plan.fee),
            );
            Ok((
                DepositSend::Near(plan.fee),
                lang(&format!("Frais réseau : environ {actual} NEAR (jusqu'à {held} NEAR retenus un instant)"), &format!("Network fee: about {actual} NEAR (up to {held} NEAR held briefly)")).to_string(),
            ))
        }
        other => Err(translate_error(&format!("réseau inconnu : {other}"))),
    }
}

/// Sends the deposit prepared by `prepare_deposit` (fee shown).
#[allow(clippy::too_many_arguments)]
fn send_deposit(
    prepared: DepositSend,
    coin: &str,
    network: &str,
    dir: &std::path::Path,
    password: &str,
    deposit: &str,
    amount: &str,
    xrp_tag: Option<u32>,
    profile_index: u32,
) -> Result<String, String> {
    match prepared {
        DepositSend::Evm(fee) => api::send_evm(
            dir,
            password,
            evm_network(network)?,
            deposit,
            amount,
            fee,
            profile_index,
        ),
        DepositSend::Erc20(fee) => api::send_erc20(
            dir,
            password,
            coin,
            network,
            deposit,
            amount,
            fee,
            profile_index,
        ),
        DepositSend::Sol => api::send_sol(
            dir,
            password,
            sol_network("sol_mainnet")?,
            deposit,
            amount,
            profile_index,
        ),
        DepositSend::Spl if coin == "usdc" => api::send_usdc(
            dir,
            password,
            sol_network("sol_mainnet")?,
            deposit,
            amount,
            profile_index,
        ),
        DepositSend::Spl => {
            api::send_registered_spl(dir, password, coin, deposit, amount, profile_index)
        }
        DepositSend::Btc(fee_sat) => api::send_btc(
            dir,
            password,
            btc_network("btc_mainnet")?,
            deposit,
            amount,
            fee_sat,
            profile_index,
        ),
        DepositSend::Doge(fee) => {
            api::send_doge(dir, password, deposit, amount, fee, profile_index)
        }
        DepositSend::Zec(fee) => api::send_zec(dir, password, deposit, amount, fee, profile_index),
        DepositSend::Trx(fee) => api::send_trx(dir, password, deposit, amount, fee, profile_index),
        DepositSend::Xrp(fee) => {
            api::send_xrp(dir, password, deposit, amount, xrp_tag, fee, profile_index)
        }
        DepositSend::Near(fee) => {
            api::send_near(dir, password, deposit, amount, fee, profile_index)
        }
        DepositSend::Ada(fee) => api::send_ada(dir, password, deposit, amount, fee, profile_index),
    }
    .t_err()
}

#[allow(clippy::too_many_arguments)]
fn confirm_swapkit_native(
    app: &tauri::AppHandle,
    provider: &str,
    from_label: &str,
    amount_line: &str,
    expected_line: &str,
    min_line: &str,
    deposit: &str,
    destination: &str,
    own_destination: Option<&str>,
    refund: &str,
    fee_line: &str,
    minutes_left: i64,
) -> bool {
    let from_label = dialog_label(from_label);
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let arrival = match (own_destination, english) {
        (Some(label), true) => format!("Funds will arrive at: {destination}\n(your profile \"{label}\" — an address of this wallet)"),
        (Some(label), false) => format!("Les fonds arriveront sur : {destination}\n(votre profil « {label} » — adresse de ce portefeuille)"),
        (None, true) => format!("Funds will arrive at: {destination}\n(verify this is really your own address)"),
        (None, false) => format!("Les fonds arriveront sur : {destination}\n(vérifiez qu'il s'agit bien de votre propre adresse)"),
    };
    let fee_percent = format!(
        "{:.2}",
        f64::from(
            openpgp_wallet_core::swapkit::SERVICE_FEE_BPS
                + openpgp_wallet_core::swapkit::AFFILIATE_FEE_BPS
        ) / 100.0
    );
    let message = if english {
        format!(
            "Swap via {provider} (through SwapKit — external protocols, not audited by this app)\n\nFrom profile: {from_label}\nSending: {amount_line}\nExpected to receive: ~{expected_line}\nGuaranteed minimum: {min_line} (confirmed by {provider} itself)\nDeposit to: {deposit} ({provider} deposit address, valid ~{minutes_left} min)\n{arrival}\nRefund if the swap fails: {refund}\n{fee_line}\nSwapKit fee {fee_percent}%; {provider}'s own fees are included in the amount received.\nThis is irreversible.\n\nConfirm this swap?"
        )
    } else {
        format!(
            "Échange via {provider} (par SwapKit — protocoles externes, non audités par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {amount_line}\nRéception attendue : ~{expected_line}\nMinimum garanti : {min_line} (confirmé par {provider} lui-même)\nDépôt vers : {deposit} (adresse de dépôt de {provider}, valable ~{minutes_left} min)\n{arrival}\nRemboursement si l'échange échoue : {refund}\n{fee_line}\nFrais de SwapKit {fee_percent} % ; frais propres à {provider} déjà déduits de la réception.\nC'est irréversible.\n\nConfirmer cet échange ?"
        )
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Deposit sent: what is needed to track the swap with the provider.
#[derive(Serialize)]
struct SwapkitSentDto {
    tx_hash: String,
    provider: openpgp_wallet_core::swapkit::Provider,
    provider_name: &'static str,
    channel_id: String,
    deposit_address: String,
}

/// Stage of a SwapKit swap ("awaiting_deposit", "processing", "completed",
/// "refunded", "failed", "unknown"), tracked by the UI after the deposit.
#[tauri::command]
async fn swapkit_status(
    provider: openpgp_wallet_core::swapkit::Provider,
    channel_id: String,
    deposit_address: String,
) -> Result<openpgp_wallet_core::swapkit::SwapState, String> {
    run_blocking(move || {
        openpgp_wallet_core::swapkit::status(provider, &channel_id, &deposit_address).t_err()
    })
    .await
}

/// Swap through SwapKit: quote, deposit opened then CONFIRMED by the provider,
/// native dialog, cancellation delay, then the transfer to the deposit address.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn swapkit_swap_transaction(
    password: String,
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<SwapkitSentDto, String> {
    use openpgp_wallet_core::{swapkit, tokens};
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (from, to) = swapkit_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        let units = tokens::parse_amount(&amount, from.decimals).t_err()?;
        let amount = tokens::format_amount(units, from.decimals);
        let destination = canonical_address_input(&destination)?;
        let source = own_address_on(&app, from.network, profile_index)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        let routes = swapkit::quote(from, to, units, &source, &destination).t_err()?;
        let route = &routes[0];
        let deposit = swapkit::open_deposit(route, from, to, &source, &destination).t_err()?;
        let verified = swapkit::verify(&deposit, from, to, units, &source, &destination).t_err()?;
        let (prepared, fee_line) = prepare_deposit(
            from.coin,
            from.network,
            &source,
            &deposit.address,
            &amount,
            None,
        )?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let own_destination = own_profile_label(&app, &dir, to.network, &destination);
        if !confirm_swapkit_native(
            &app,
            deposit.provider.name(),
            &from_label,
            &format!("{amount} {}", from.symbol),
            &format!(
                "{} {}",
                tokens::format_balance(deposit.expected_out, to.decimals, 8),
                to.symbol
            ),
            &format!(
                "{} {}",
                tokens::format_balance(verified.min_out, to.decimals, 8),
                to.symbol
            ),
            &deposit.address,
            &destination,
            own_destination.as_deref(),
            &source,
            &fee_line,
            (verified.deadline - now) / 60,
        ) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(
            &app,
            GraceRecap::swap(
                format!(
                    "{} SwapKit ({})",
                    lang("Échange via", "Swap via"),
                    deposit.provider.name()
                ),
                format!(
                    "{amount} {} → ~{} {}",
                    from.symbol,
                    tokens::format_balance(deposit.expected_out, to.decimals, 8),
                    to.symbol
                ),
                destination.clone(),
            )
            .on(from.network),
        )?;

        let sent = send_deposit(
            prepared,
            from.coin,
            from.network,
            &dir,
            &password,
            &deposit.address,
            &amount,
            None,
            profile_index,
        );
        Ok(SwapkitSentDto {
            tx_hash: sent?,
            provider: deposit.provider,
            provider_name: deposit.provider.name(),
            channel_id: deposit.channel_id,
            deposit_address: deposit.address,
        })
    })
    .await
}

// --- MoonPay Trade swap (core/src/moonpay_trade.rs) ------------------------------
//
// Same EVM network: router simulated before the dialog, then again just before signing
// (purchases arrive at the profile's address). Elsewhere, as a last resort: an
// ordinary deposit transfer; delivery on the other network is handled by MoonPay
// Trade, which the confirmation dialog states.

/// Maximum age of a MoonPay Trade deposit quote at send time.
const MOONPAY_DEPOSIT_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

fn moonpay_pair(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
) -> Result<
    (
        openpgp_wallet_core::moonpay_trade::Asset,
        openpgp_wallet_core::moonpay_trade::Asset,
    ),
    String,
> {
    if !provider_links(
        openpgp_wallet_core::swap_routes::Protocol::Moonpay,
        from_coin,
        from_network,
        to_coin,
        to_network,
    ) {
        return Err(translate_error(
            "échange non disponible entre ces deux cryptos",
        ));
    }
    api::moonpay_assets(from_coin, from_network, to_coin, to_network).t_err()
}

/// Recipient of a MoonPay Trade swap: the profile's address on the same EVM network
/// (same wallet), otherwise the one entered.
fn moonpay_destination(
    from: &openpgp_wallet_core::moonpay_trade::Asset,
    to: &openpgp_wallet_core::moonpay_trade::Asset,
    source: &str,
    destination: &str,
) -> Result<String, String> {
    if openpgp_wallet_core::moonpay_trade::verifiable(
        (from.coin, from.network),
        (to.coin, to.network),
    ) {
        Ok(source.to_string())
    } else {
        canonical_address_input(destination)
    }
}

/// Explorer link for a transaction just sent ("Track the transaction" button): the
/// same addresses as the history, all on the external link allowlist. `None`: an
/// unexpected identifier, or a network whose explorer needs something other than
/// the hash (TAO: block and extrinsic numbers, only known after inclusion).
fn sent_tx_explorer_url(network: &str, tx: &str) -> Option<String> {
    let id = tx.trim();
    if id.is_empty() || id.len() > 130 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(match network {
        n if is_evm(n) => {
            let prefix = wallet_flow::evm_network(n)?.explorer_tx_prefix;
            if prefix.is_empty() {
                return None;
            }
            format!("{prefix}{id}")
        }
        "btc_mainnet" | "btc_testnet" => {
            format!("{}{id}", btc_network(network).ok()?.explorer_tx_prefix)
        }
        "sol_mainnet" | "sol_devnet" => {
            let net = sol_network(network).ok()?;
            format!("{}{id}{}", net.explorer_tx_prefix, net.explorer_tx_suffix)
        }
        "zec_mainnet" | "zec_shielded" => format!("https://blockchair.com/zcash/transaction/{id}"),
        "xmr_mainnet" => format!("https://xmrchain.net/tx/{id}"),
        "doge_mainnet" => format!("https://blockchair.com/dogecoin/transaction/{id}"),
        "tron_mainnet" => format!("https://tronscan.org/#/transaction/{id}"),
        "xrp_mainnet" => format!("https://livenet.xrpl.org/transactions/{id}"),
        "xlm_mainnet" => format!("https://stellar.expert/explorer/public/tx/{id}"),
        "near_mainnet" => format!("https://nearblocks.io/txns/{id}"),
        "ada_mainnet" => format!("https://cardanoscan.io/transaction/{id}"),
        "stx_mainnet" => format!(
            "https://explorer.hiro.so/txid/0x{}?chain=mainnet",
            id.trim_start_matches("0x")
        ),
        _ => return None,
    })
}

#[tauri::command]
fn tx_explorer_url(network: String, tx: String) -> Option<String> {
    sent_tx_explorer_url(&network, &tx)
}

#[derive(Serialize)]
struct FeeEstimateDto {
    /// Amount in the network's native coin (decimal text).
    amount: String,
    symbol: &'static str,
    /// Card of the network's native coin: the price read by the UI.
    coin: &'static str,
    /// A cap rather than an estimate (Tron: energy and bandwidth).
    up_to: bool,
}

/// UI card for an EVM network's native coin.
fn evm_native_coin(network: &wallet_flow::EvmNetwork) -> &'static str {
    if network.custom {
        return network.id;
    }
    match network.native_symbol {
        "BNB" => "bnb",
        "AVAX" => "avax",
        "POL" => "pol",
        _ => "evm",
    }
}

/// ESTIMATED network fee for a send, for the UI preview (users' number one
/// complaint: fees discovered at the last moment). The same preparations as the
/// real send, READ-only: nothing is signed, and the native confirmation dialog
/// remains the reference. `None`: no estimate (Bitcoin, whose speed is already
/// shown; Monero; test networks).
#[tauri::command]
async fn estimate_send_fee(
    network: String,
    token: Option<String>,
    to: String,
    amount: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<Option<FeeEstimateDto>, String> {
    use openpgp_wallet_core::tokens::format_amount;
    run_blocking(move || {
        let to = canonical_address_input(&to)?;
        let estimate =
            |units: u128, decimals: u8, symbol: &'static str, coin: &'static str, up_to: bool| {
                Some(FeeEstimateDto {
                    amount: format_amount(units, decimals),
                    symbol,
                    coin,
                    up_to,
                })
            };
        let token = token.as_deref().filter(|t| !t.is_empty());
        if is_evm(&network) {
            let net = evm_network(&network)?;
            if !net.mainnet {
                return Ok(None);
            }
            let from = profile_address(&app, &network, profile_index)?;
            let fee = match token {
                // Token balance first, like the send: without it, the gas estimate fails with a
                // raw contract error.
                Some(token) => {
                    api::ensure_token_funds(token, &network, &from, &amount).and_then(|()| {
                        api::erc20_fee_for_confirmation(token, &network, &from, &to, &amount)
                    })
                }
                None => api::evm_transfer_fee_for_confirmation(net, Some(&from), &to, &amount),
            }
            .t_err()?;
            return Ok(estimate(
                fee.max_total().t_err()?,
                18,
                net.native_symbol,
                evm_native_coin(net),
                false,
            ));
        }
        let from = || profile_address(&app, &network, profile_index);
        Ok(match (network.as_str(), token) {
            ("sol_mainnet", None) => estimate(5_000, 9, "SOL", "sol", false),
            // Token: includes creating the recipient's token account if they do not have one
            // yet.
            ("sol_mainnet", Some(token)) => {
                let net = sol_network("sol_mainnet")?;
                // Account under the right program and of the right size (xStocks: Token-2022, 179
                // bytes).
                let rent = api::token_account_rent_if_missing(token, &to, net)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                estimate(
                    u128::from(rent.saturating_add(5_000)),
                    9,
                    "SOL",
                    "sol",
                    false,
                )
            }
            ("zec_mainnet", None) => estimate(
                u128::from(api::zec_send_plan(&from()?, &to, &amount).t_err()?.fee),
                8,
                "ZEC",
                "zec",
                false,
            ),
            ("doge_mainnet", None) => estimate(
                u128::from(api::doge_send_plan(&from()?, &to, &amount).t_err()?.fee),
                8,
                "DOGE",
                "doge",
                false,
            ),
            ("tron_mainnet", None) => estimate(
                u128::from(api::trx_send_plan(&from()?, &to, &amount).t_err()?.fee_max),
                6,
                "TRX",
                "trx",
                true,
            ),
            ("tron_mainnet", Some(token)) => estimate(
                u128::from(
                    api::trc20_send_plan(token, &from()?, &to, &amount)
                        .t_err()?
                        .0
                        .fee_max,
                ),
                6,
                "TRX",
                "trx",
                true,
            ),
            ("xrp_mainnet", None) => estimate(
                u128::from(
                    api::xrp_send_plan(&from()?, &to, &amount, None)
                        .t_err()?
                        .fee,
                ),
                6,
                "XRP",
                "xrp",
                false,
            ),
            ("xlm_mainnet", None) => estimate(
                u128::from(
                    api::xlm_send_plan(&from()?, &to, &amount, &StellarMemo::None)
                        .t_err()?
                        .fee,
                ),
                7,
                "XLM",
                "xlm",
                false,
            ),
            ("near_mainnet", None) => estimate(
                api::near_send_plan(&from()?, &to, &amount)
                    .t_err()?
                    .fee_actual,
                24,
                "NEAR",
                "near",
                false,
            ),
            ("ada_mainnet", None) => estimate(
                u128::from(api::ada_send_plan(&from()?, &to, &amount).t_err()?.fee),
                6,
                "ADA",
                "ada",
                false,
            ),
            ("stx_mainnet", None) => estimate(
                u128::from(api::stx_send_plan(&from()?, &to, &amount).t_err()?.fee),
                6,
                "STX",
                "stx",
                false,
            ),
            ("tao_mainnet", None) => estimate(
                u128::from(api::tao_send_plan(&from()?, &to, &amount).t_err()?.fee),
                9,
                "TAO",
                "tao",
                false,
            ),
            // No estimate (Bitcoin: speed chosen in the window; Monero), but the address is
            // checked from the preview onwards, as elsewhere: the same parsers as the send.
            ("btc_mainnet", None) => {
                api::check_btc_recipient(btc_network(&network)?, &to, &amount).t_err()?;
                None
            }
            ("xmr_mainnet", None) => {
                openpgp_wallet_core::monero::parse_recipient(&to).t_err()?;
                None
            }
            _ => None,
        })
    })
    .await
}

#[derive(Serialize)]
struct MoonpayQuoteDto {
    expected_out: String,
    min_out: String,
    duration_secs: u64,
    fee_bps: u32,
    /// Recipient verified by the app (simulated router, same EVM network).
    verified: bool,
}

/// Preview: MoonPay Trade quote (its transaction is verified at confirmation).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn get_moonpay_quote(
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<MoonpayQuoteDto, String> {
    use openpgp_wallet_core::{moonpay_trade, tokens};
    run_blocking(move || {
        let (from, to) = moonpay_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        let source = own_address_on(&app, from.network, profile_index)?;
        let destination = moonpay_destination(&from, &to, &source, &destination)?;
        let quote = api::moonpay_quote(&from, &to, &amount, &source, &destination).t_err()?;
        Ok(MoonpayQuoteDto {
            // At most 8 decimals, TRUNCATED: the minimum shown never exceeds the guaranteed
            // minimum.
            expected_out: tokens::format_balance(quote.expected_out, to.decimals, 8),
            min_out: tokens::format_balance(quote.min_out, to.decimals, 8),
            duration_secs: quote.duration_secs,
            fee_bps: moonpay_trade::FEE_BPS + quote.protocol_fee_bps,
            verified: moonpay_trade::verifiable((from.coin, from.network), (to.coin, to.network)),
        })
    })
    .await
}

/// Native dialog for a MoonPay Trade swap. `deposit`: deposit address and tag (a
/// route whose recipient cannot be verified); `None`: simulated router.
#[allow(clippy::too_many_arguments)]
fn confirm_moonpay_native(
    app: &tauri::AppHandle,
    from_label: &str,
    sell_line: &str,
    expected_line: &str,
    min_line: &str,
    deposit: Option<(&str, Option<u32>)>,
    destination: &str,
    own_destination: Option<&str>,
    refund: &str,
    fee_lines: &str,
    protocol_fee_bps: u32,
) -> bool {
    let from_label = dialog_label(from_label);
    let english = UI_LANG_IS_ENGLISH.load(Ordering::Relaxed);
    let percent = |bps: u32| format!("{:.2}", f64::from(bps) / 100.0);
    let (fee, moonpay_fee) = (
        percent(openpgp_wallet_core::moonpay_trade::FEE_BPS),
        percent(protocol_fee_bps),
    );
    let message = match (deposit, english) {
        (None, false) => format!(
            "Échange via MoonPay Trade (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {sell_line}\nRéception attendue : ~{expected_line}\nMinimum garanti : {min_line}\nVérifié par simulation : ce qui est acheté arrive sur votre adresse {destination}\n{fee_lines}\nFrais : MoonPay {moonpay_fee} % + commission de l'app {fee} % (compris dans le devis).\nC'est irréversible.\n\nConfirmer cet échange ?"
        ),
        (None, true) => format!(
            "Swap via MoonPay Trade (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nSending: {sell_line}\nExpected to receive: ~{expected_line}\nGuaranteed minimum: {min_line}\nVerified by simulation: what you buy arrives at your address {destination}\n{fee_lines}\nFees: MoonPay {moonpay_fee}% + app fee {fee}% (included in the quote).\nThis is irreversible.\n\nConfirm this swap?"
        ),
        (Some((address, tag)), english) => {
            let tag_line = match (tag, english) {
                (Some(tag), false) => format!("\nTag de destination : {tag}"),
                (Some(tag), true) => format!("\nDestination tag: {tag}"),
                (None, _) => String::new(),
            };
            let arrival = match (own_destination, english) {
                (Some(label), true) => format!("Funds will arrive at: {destination}\n(your profile \"{label}\" — an address of this wallet)"),
                (Some(label), false) => format!("Les fonds arriveront sur : {destination}\n(votre profil « {label} » — adresse de ce portefeuille)"),
                (None, true) => format!("Funds will arrive at: {destination}\n(verify this is really your own address)"),
                (None, false) => format!("Les fonds arriveront sur : {destination}\n(vérifiez qu'il s'agit bien de votre propre adresse)"),
            };
            if english {
                format!(
                    "Swap via MoonPay Trade (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nSending: {sell_line}\nExpected to receive: ~{expected_line}\nAnnounced minimum: {min_line}\nDeposit to: {address} (MoonPay Trade's deposit address){tag_line}\n{arrival}\nOnly provider for this pair: delivery is handled by MoonPay Trade, the app cannot verify it.\nRefund if the swap fails: {refund}\n{fee_lines}\nFees: MoonPay {moonpay_fee}% + app fee {fee}% (included in the quote).\nThis is irreversible.\n\nConfirm this swap?"
                )
            } else {
                format!(
                    "Échange via MoonPay Trade (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nEnvoi : {sell_line}\nRéception attendue : ~{expected_line}\nMinimum annoncé : {min_line}\nDépôt vers : {address} (adresse de dépôt de MoonPay Trade){tag_line}\n{arrival}\nSeul fournisseur pour cette paire : la livraison est gérée par MoonPay Trade, l'app ne peut pas la vérifier.\nRemboursement si l'échange échoue : {refund}\n{fee_lines}\nFrais : MoonPay {moonpay_fee} % + commission de l'app {fee} % (compris dans le devis).\nC'est irréversible.\n\nConfirmer cet échange ?"
                )
            }
        }
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[derive(Serialize)]
struct MoonpaySentDto {
    tx_hash: String,
    /// Deposit registered with MoonPay Trade (tracking), when the quote asked for it.
    registered: bool,
    duration_secs: u64,
    /// Deposit (delivery handled by MoonPay Trade), or a swap through the router.
    deposit: bool,
}

/// Swap through MoonPay Trade: quote, verification (router simulation, or deposit
/// preparation), native dialog, cancellation delay, send.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn moonpay_swap_transaction(
    password: String,
    from_coin: String,
    from_network: String,
    to_coin: String,
    to_network: String,
    amount: String,
    destination: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<MoonpaySentDto, String> {
    use openpgp_wallet_core::{moonpay_trade, tokens};
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let (from, to) = moonpay_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        let units = tokens::parse_amount(&amount, from.decimals).t_err()?;
        let amount = tokens::format_amount(units, from.decimals);
        let source = own_address_on(&app, from.network, profile_index)?;
        let destination = moonpay_destination(&from, &to, &source, &destination)?;
        let from_label = api::list_profiles(&dir).into_iter().find(|p| p.index == profile_index).map(|p| p.label).unwrap_or_else(|| format!("profil #{profile_index}"));

        let quote = api::moonpay_quote(&from, &to, &amount, &source, &destination).t_err()?;
        let quoted_at = std::time::Instant::now();
        let sell_line = format!("{amount} {}", from.symbol);
        let expected_line = format!("{} {}", tokens::format_balance(quote.expected_out, to.decimals, 8), to.symbol);
        let min_line = format!("{} {}", tokens::format_balance(quote.min_out, to.decimals, 8), to.symbol);
        let recap = || GraceRecap::swap(lang("Échange via MoonPay Trade", "Swap via MoonPay Trade").to_string(), format!("{sell_line} → ~{expected_line}"), destination.clone()).on(from.network);
        match &quote.tx {
            moonpay_trade::TradeTx::Router { router, .. } => {
                let net = evm_network(from.network)?;
                let gas_price = api::evm_gas_price_for_confirmation(net).t_err()?;
                let (call, approve, approvals) = api::moonpay_router_fees(&from, &quote, &source, gas_price).t_err()?;
                // Balance checked first (clear message), then the swap simulated BEFORE the dialog
                // (and again before signing).
                if from.native {
                    api::ensure_evm_transfer_funds(net, &source, &amount, call).t_err()?;
                } else {
                    api::ensure_token_funds(from.coin, from.network, &source, &amount).t_err()?;
                    let count = approvals as u64;
                    let gas = api::EvmFee {
                        gas_price,
                        gas_limit: call.gas_limit.saturating_add(approve.gas_limit.saturating_mul(count)),
                        l1_fee: call.l1_fee.saturating_add(approve.l1_fee.saturating_mul(u128::from(count))),
                    };
                    api::ensure_evm_gas_funds(net, &source, gas).t_err()?;
                }
                api::verify_moonpay_router(&from, &to, &quote, &source).t_err()?;
                let total = call.max_total().t_err()?.saturating_add(approve.max_total().t_err()?.saturating_mul(approvals as u128)) as f64 / 1e18;
                let symbol = net.native_symbol;
                let mut fee_lines = lang(&format!("Frais réseau maximum : {total:.8} {symbol}"), &format!("Maximum network fee: {total:.8} {symbol}")).to_string();
                if approvals > 0 {
                    let router = openpgp_wallet_core::derivation::format_address(router);
                    fee_lines.push_str(lang(
                        &format!("\nAutorisation préalable (transaction séparée) : le routeur MoonPay Trade {router} pourra prélever exactement {sell_line}, une seule fois."),
                        &format!("\nPrior approval (separate transaction): MoonPay Trade's router {router} will be allowed to take exactly {sell_line}, once."),
                    ));
                }
                if !confirm_moonpay_native(&app, &from_label, &sell_line, &expected_line, &min_line, None, &destination, None, &source, &fee_lines, quote.protocol_fee_bps) {
                    return Err(translate_error("Échange annulé (confirmation refusée)."));
                }
                swap_grace_period(&app, recap())?;
                let tx_hash = api::send_moonpay_router(&dir, &password, &from, &to, &quote, &source, gas_price, profile_index).t_err()?;
                Ok(MoonpaySentDto { tx_hash, registered: false, duration_secs: quote.duration_secs, deposit: false })
            }
            moonpay_trade::TradeTx::Deposit { address, memo } => {
                let xrp_tag = memo.as_deref().map(str::parse::<u32>).transpose().map_err(|_| translate_error("mémo de dépôt MoonPay Trade non pris en charge — refus"))?;
                let (prepared, fee_line) = prepare_deposit(from.coin, from.network, &source, address, &amount, xrp_tag)?;
                let own_destination = own_profile_label(&app, &dir, to.network, &destination);
                if !confirm_moonpay_native(&app, &from_label, &sell_line, &expected_line, &min_line, Some((address, xrp_tag)), &destination, own_destination.as_deref(), &source, &fee_line, quote.protocol_fee_bps) {
                    return Err(translate_error("Échange annulé (confirmation refusée)."));
                }
                swap_grace_period(&app, recap())?;
                // Unknown lifetime of the deposit address (no deadline in the quote): after 10
                // minutes in the confirmation, a new quote is required rather than depositing to
                // an address that may no longer be watched (audit round 32).
                if quoted_at.elapsed() > MOONPAY_DEPOSIT_MAX_AGE {
                    return Err(translate_error("le devis MoonPay Trade a expiré pendant la confirmation — rien n'a été envoyé, relancez l'échange"));
                }
                let tx_hash = send_deposit(prepared, from.coin, from.network, &dir, &password, address, &amount, xrp_tag, profile_index)?;
                // Registering the deposit (tracking at MoonPay Trade): a few attempts; a failure
                // cancels nothing (the deposit has gone out).
                let registered = !quote.register
                    || (0..3).any(|attempt| {
                        if attempt > 0 {
                            std::thread::sleep(std::time::Duration::from_secs(3));
                        }
                        moonpay_trade::register(&quote.tx_id, &tx_hash).is_ok()
                    });
                Ok(MoonpaySentDto { tx_hash, registered, duration_secs: quote.duration_secs, deposit: true })
            }
        }
    })
    .await
}

// --- Swap (Jupiter) ----------------------------------------------------------
//
// Within Solana only, unlike the THORChain cross-chain swap above; see
// core/src/jupiter_rpc.rs for the full context, notably why the transaction itself
// is not rebuilt by hand here (only verified, then signed).

const JUPITER_DEFAULT_SLIPPAGE_BPS: u32 = 50; // 0.50%

/// Jupiter pair designated by the UI (Solana network): refused if Jupiter does not
/// connect it (see `swap_routes::direct_all`).
fn jupiter_pair(from_coin: &str, to_coin: &str) -> Result<(), String> {
    if provider_links(
        openpgp_wallet_core::swap_routes::Protocol::Jupiter,
        from_coin,
        "sol_mainnet",
        to_coin,
        "sol_mainnet",
    ) {
        Ok(())
    } else {
        Err(translate_error(
            "échange non disponible entre ces deux cryptos",
        ))
    }
}

fn format_native_amount(amount: u64, decimals: u32) -> String {
    format!(
        "{:.*}",
        decimals as usize,
        amount as f64 / 10f64.powi(decimals as i32)
    )
}

#[tauri::command]
async fn get_jupiter_quote(
    from_coin: String,
    to_coin: String,
    amount: String,
) -> Result<String, String> {
    run_blocking(move || {
        jupiter_pair(&from_coin, &to_coin)?;
        let quote =
            api::get_jupiter_quote(&from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS)
                .t_err()?;
        Ok(format_native_amount(
            quote.out_amount,
            u32::from(api::jupiter_decimals(&to_coin).t_err()?),
        ))
    })
    .await
}

/// Native confirmation specific to Jupiter: unlike THORChain, this is not a
/// cross-chain protocol, but it is still an EXTERNAL protocol not audited by this
/// app, and the transaction itself is built by Jupiter (see
/// core/src/jupiter_rpc.rs), not by this app. It is simulated and verified (effects
/// on the user's accounts, see `api::check_swap_effects`) BEFORE being signed,
/// never rebuilt. The text still said "verified (fee payer)", left over from before
/// round 21: it understated the real protection.
fn confirm_jupiter_swap_native(
    app: &tauri::AppHandle,
    from_label: &str,
    amount: &str,
    expected_out: &str,
    to_symbol: &str,
    fee_bps: Option<u32>,
) -> bool {
    let from_label = dialog_label(from_label);
    // Without an existing fee account for these tokens, the swap goes ahead without an
    // affiliate fee (see `api::jupiter_fee_mint`): the dialog says so.
    let fee_line = match (
        fee_bps.filter(|bps| *bps > 0),
        UI_LANG_IS_ENGLISH.load(Ordering::Relaxed),
    ) {
        (Some(bps), true) => format!("Includes a {}% affiliate fee", percent_text(bps)),
        (Some(bps), false) => format!("Inclut {} % de frais d'affiliation", percent_text(bps)),
        (None, true) => "No affiliate fee on this pair".to_string(),
        (None, false) => "Sans frais d'affiliation pour cette paire".to_string(),
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
        let network = sol_network("sol_mainnet")?; // Jupiter on mainnet only (no reliable liquidity on devnet)
        jupiter_pair(&from_coin, &to_coin)?;
        // Canonical form, shown AND signed (see `send_transaction`).
        let amount = api::canonical_jupiter_amount(&from_coin, &amount).t_err()?;

        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Quote reread HERE, just before the confirmation, never the one shown in the
        // frontend's preview, which may already be slightly stale.
        let quote =
            api::get_jupiter_quote(&from_coin, &to_coin, &amount, JUPITER_DEFAULT_SLIPPAGE_BPS)
                .t_err()?;
        let out_amount = quote.out_amount;
        let expected_out = format_native_amount(
            out_amount,
            u32::from(api::jupiter_decimals(&to_coin).t_err()?),
        );
        let amount_line = format!("{amount} {}", api::jupiter_symbol(&from_coin).t_err()?);
        let own_solana = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(_, sol)| sol.clone())
            .unwrap_or_default();
        // Without funds: refused BEFORE the confirmation dialog, as for a send.
        if !own_solana.is_empty() {
            api::ensure_jupiter_funds(&from_coin, &own_solana, &amount).t_err()?;
        }

        if !confirm_jupiter_swap_native(
            &app,
            &from_label,
            &amount_line,
            &expected_out,
            api::jupiter_symbol(&to_coin).t_err()?,
            quote.fee_mint.map(|_| quote.fee_bps),
        ) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(
            &app,
            GraceRecap::swap(
                lang("Solana — échange via Jupiter", "Solana — swap via Jupiter"),
                format!(
                    "{amount_line} → ~{expected_out} {}",
                    api::jupiter_symbol(&to_coin).t_err()?
                ),
                own_solana,
            )
            .on("sol_mainnet"),
        )?;

        // `out_amount` = the output SHOWN above: the transaction actually signed must
        // deliver it (give or take slippage), checked by simulation.
        api::send_jupiter_swap(
            &dir,
            &password,
            network,
            &from_coin,
            &to_coin,
            &amount,
            JUPITER_DEFAULT_SLIPPAGE_BPS,
            out_amount,
            quote.fee_mint,
            profile_index,
        )
        .t_err()
    })
    .await
}

// --- Swap (CoW Protocol) -----------------------------------------------------
//
// Same EVM network: a signed order (EIP-712) built and verified on the Rust side
// (see core/src/cow.rs), then executed by CoW. No swap transaction: only an
// approval of the token sold, if needed, goes out on the network.

/// CoW pair designated by the UI: refused if CoW does not connect it (see
/// `swap_routes::direct_all`).
fn cow_pair(
    network: &str,
    from_coin: &str,
    to_coin: &str,
) -> Result<(cow::CowToken, cow::CowToken), String> {
    if !provider_links(
        openpgp_wallet_core::swap_routes::Protocol::Cow,
        from_coin,
        network,
        to_coin,
        network,
    ) {
        return Err(translate_error(
            "échange non disponible entre ces deux cryptos",
        ));
    }
    api::cow_tokens(network, from_coin, to_coin).t_err()
}

/// The profile's public EVM address (remembered at unlock): seller AND recipient of
/// a CoW order. The send checks again that it belongs to the signing key
/// (`api::send_cow_swap`).
fn profile_evm_address(app: &tauri::AppHandle, profile_index: u32) -> Result<String, String> {
    app.state::<ProfileAddressCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&profile_index)
        .map(|(evm, _)| evm.clone())
        .ok_or_else(|| {
            translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
        })
}

/// Amount shown: at most 8 decimals, TRUNCATED (a guaranteed minimum is never shown
/// above its real value).
fn cow_amount(units: u128, token: &cow::CowToken) -> String {
    let cut = 10u128.pow(u32::from(token.decimals.saturating_sub(8)));
    format!(
        "{} {}",
        openpgp_wallet_core::tokens::format_amount(units / cut * cut, token.decimals),
        token.symbol
    )
}

#[derive(Serialize)]
struct CowQuoteDto {
    expected_out: String,
    min_out: String,
    partner_fee: String,
    network_fee: String,
}

#[tauri::command]
async fn get_cow_quote(
    network: String,
    from_coin: String,
    to_coin: String,
    amount: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<CowQuoteDto, String> {
    run_blocking(move || {
        let (sell, buy) = cow_pair(&network, &from_coin, &to_coin)?;
        let owner = profile_evm_address(&app, profile_index)?;
        let order = api::get_cow_quote(
            evm_network(&network)?,
            &sell,
            &buy,
            &amount,
            &owner,
            cow_fee_bps(&network, &from_coin, &to_coin),
        )
        .t_err()?;
        Ok(CowQuoteDto {
            expected_out: cow_amount(order.expected_buy, &buy),
            min_out: cow_amount(order.min_buy, &buy),
            partner_fee: cow_amount(order.partner_fee_buy, &buy),
            network_fee: cow_amount(order.network_fee_sell, &sell),
        })
    })
    .await
}

/// Native confirmation of a CoW order: everything that will be signed (sale,
/// minimum received, recipient, validity, fees) and the accompanying transaction if
/// there is one (token approval, or EthFlow deposit for the native coin), with text
/// built solely from the order prepared on the Rust side.
#[allow(clippy::too_many_arguments)]
/// CoW partner fee for the pair: lower for liquid staking (see
/// `swap_routes::staking_fee_bps`), otherwise `cow::PARTNER_FEE_BPS`.
fn cow_fee_bps(network: &str, from_coin: &str, to_coin: &str) -> u32 {
    openpgp_wallet_core::swap_routes::staking_fee_bps((from_coin, network), (to_coin, network))
        .unwrap_or(openpgp_wallet_core::cow::PARTNER_FEE_BPS)
}

/// Rate as a percentage, without needless zeros ("1", "0,3" in French; "0.3" in
/// English).
fn percent_text(bps: u32) -> String {
    let text = format!("{:.2}", f64::from(bps) / 100.0);
    let text = text.trim_end_matches('0').trim_end_matches('.').to_string();
    if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
        text
    } else {
        text.replace('.', ",")
    }
}

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
    partner_fee_bps: u32,
    receiver: &str,
    minutes: u64,
    transaction_lines: Option<&str>,
    eth_flow: bool,
) -> bool {
    let from_label = dialog_label(from_label);
    let fee_percent = percent_text(partner_fee_bps);
    let transaction_lines = transaction_lines
        .map(|a| format!("{a}\n"))
        .unwrap_or_default();
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
            "Swap via CoW Protocol (external protocol, not audited by this app)\n\nFrom profile: {from_label}\nNetwork: {network_name}\nSelling: {sell_line} (incl. ≈ {network_fee} of CoW network costs)\nExpected to receive: ~{expected_out}\nGuaranteed minimum: {min_out} (otherwise the order is not executed)\nFunds will arrive at: {receiver}\n(verify this is really your own address)\nIncludes a {fee_percent}% integration fee (≈ {partner_fee}).\nOrder valid for about {minutes} minutes; {expiry}\n{transaction_lines}\n{closing}\n\nConfirm this swap?"
        )
    } else {
        format!(
            "Échange via CoW Protocol (protocole externe, non audité par cette app)\n\nDepuis le profil : {from_label}\nRéseau : {network_name}\nVente : {sell_line} (dont ≈ {network_fee} de frais réseau de CoW)\nRéception attendue : ~{expected_out}\nMinimum garanti : {min_out} (sinon l'ordre n'est pas exécuté)\nLes fonds arriveront sur : {receiver}\n(vérifiez qu'il s'agit bien de votre propre adresse)\nInclut {fee_percent} % de frais d'intégration (≈ {partner_fee}).\nOrdre valable environ {minutes} minutes ; {expiry}\n{transaction_lines}\n{closing}\n\nConfirmer cet échange ?"
        )
    };
    app.dialog()
        .message(message)
        .title(lang("Confirmer l'échange", "Confirm the swap"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Native dialog lines for the transaction that accompanies the order: EthFlow
/// deposit (native coin) or a prior approval of the token for CoW's VaultRelayer
/// (none if the one already granted is enough).
fn cow_transaction_lines(
    net: &wallet_flow::EvmNetwork,
    sell: &cow::CowToken,
    order: &cow::CowOrder,
    gas_price: u128,
    sell_line: &str,
) -> Result<Option<String>, String> {
    let symbol = net.native_symbol;
    if sell.native {
        let total = api::cow_eth_flow_fee(net, order, gas_price)
            .t_err()?
            .max_total()
            .t_err()? as f64
            / 1e18;
        return Ok(Some(
            lang(
                &format!("Transaction : {sell_line} confiés au contrat EthFlow de CoW {}, qui les garde jusqu'à l'exécution de l'ordre.\nFrais réseau maximum de cette transaction : {total:.8} {symbol}", cow::ETH_FLOW),
                &format!("Transaction: {sell_line} entrusted to CoW's EthFlow contract {}, which holds it until the order is executed.\nMaximum network fee for this transaction: {total:.8} {symbol}", cow::ETH_FLOW),
            )
            .to_string(),
        ));
    }
    let (approve_fee, approvals) = api::cow_approval_fees(net, order, gas_price).t_err()?;
    if approvals == 0 {
        return Ok(None);
    }
    let total = approve_fee
        .max_total()
        .t_err()?
        .saturating_mul(approvals as u128) as f64
        / 1e18;
    Ok(Some(
        lang(
            &format!("Autorisation préalable (transaction séparée) : le contrat de CoW {} pourra prélever exactement {sell_line}, une seule fois.\nFrais réseau maximum de l'autorisation : {total:.8} {symbol}", cow::VAULT_RELAYER),
            &format!("Prior approval (separate transaction): CoW's contract {} will be allowed to take exactly {sell_line}, once.\nMaximum network fee for the approval: {total:.8} {symbol}", cow::VAULT_RELAYER),
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
        // Canonical form, shown AND signed (see `send_transaction`).
        let amount = api::canonical_cow_amount(&sell, &amount).t_err()?;
        let owner = profile_evm_address(&app, profile_index)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Quote obtained HERE, just before the confirmation: the order shown is exactly
        // the one that will be signed (no new quote afterwards).
        let order = api::get_cow_quote(
            net,
            &sell,
            &buy,
            &amount,
            &owner,
            cow_fee_bps(&network, &from_coin, &to_coin),
        )
        .t_err()?;
        let gas_price = api::evm_gas_price_for_confirmation(net).t_err()?;
        let sell_line = cow_amount(order.sell_amount, &sell);
        let transaction_lines = cow_transaction_lines(net, &sell, &order, gas_price, &sell_line)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
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
            order.partner_fee_bps,
            &order.receiver,
            minutes,
            transaction_lines.as_deref(),
            sell.native,
        ) {
            return Err(translate_error("Échange annulé (confirmation refusée)."));
        }
        swap_grace_period(
            &app,
            GraceRecap::swap(
                format!(
                    "{} — {}",
                    network_label(&network),
                    lang("échange via CoW", "swap via CoW")
                ),
                format!("{sell_line} → ~{}", cow_amount(order.expected_buy, &buy)),
                order.receiver.clone(),
            )
            .on(&network),
        )?;

        // Native coin: EthFlow transaction; token: signed order.
        let uid = if sell.native {
            api::send_cow_eth_flow(&dir, &password, net, &order, gas_price, profile_index)
                .t_err()?
                .1
        } else {
            api::send_cow_swap(
                &dir,
                &password,
                net,
                &sell,
                &order,
                gas_price,
                profile_index,
            )
            .t_err()?
        };
        Ok(CowOrderDto {
            explorer_url: cow::explorer_order_url(&network, &uid),
            uid,
        })
    })
    .await
}

// --- Swap (LI.FI) ------------------------------------------------------------
//
// Between two ecosystems: a transaction built by LI.FI, verified before signing
// (see core/src/lifi.rs and api::lifi_verified_quote).

type LifiPair = (
    &'static str,
    &'static str,
    openpgp_wallet_core::lifi::LifiToken,
    openpgp_wallet_core::lifi::LifiToken,
);

/// LI.FI pair designated by the UI: refused if LI.FI does not connect it (see
/// `swap_routes::direct_all`). Returns the networks (static identifiers) and the
/// LI.FI tokens.
fn lifi_pair(
    from_coin: &str,
    from_network: &str,
    to_coin: &str,
    to_network: &str,
) -> Result<LifiPair, String> {
    use openpgp_wallet_core::swap_routes;
    let (from, to) = swap_routes::find(from_coin, from_network)
        .zip(swap_routes::find(to_coin, to_network))
        .filter(|(f, t)| swap_routes::direct_all(*f, *t).contains(&swap_routes::Protocol::Lifi))
        .ok_or_else(|| translate_error("échange non disponible entre ces deux cryptos"))?;
    let (from_token, to_token) =
        api::lifi_tokens(from_coin, from_network, to_coin, to_network).t_err()?;
    Ok((from.network, to.network, from_token, to_token))
}

/// The profile's public address on the source network (remembered at unlock): the
/// send checks again that it belongs to the signing key.
fn profile_address_on(
    app: &tauri::AppHandle,
    profile_index: u32,
    network: &str,
) -> Result<String, String> {
    if network == "btc_mainnet" {
        let cache = app.state::<ProfileBtcCache>();
        let cache = cache.0.lock().unwrap_or_else(|p| p.into_inner());
        return cache.get(&profile_index).cloned().ok_or_else(|| {
            translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
        });
    }
    let cache = app.state::<ProfileAddressCache>();
    let cache = cache.0.lock().unwrap_or_else(|p| p.into_inner());
    let (evm, solana) = cache.get(&profile_index).ok_or_else(|| {
        translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
    })?;
    match network {
        "sol_mainnet" => Ok(solana.clone()),
        _ if wallet_flow::evm_network(network).is_some() => Ok(evm.clone()),
        _ => Err(translate_error(
            "échange non disponible entre ces deux cryptos",
        )),
    }
}

/// Amount shown: at most 8 decimals, TRUNCATED.
fn lifi_amount(units: u128, token: &openpgp_wallet_core::lifi::LifiToken) -> String {
    let cut = 10u128.pow(u32::from(token.decimals.saturating_sub(8)));
    format!(
        "{} {}",
        openpgp_wallet_core::tokens::format_amount(units / cut * cut, token.decimals),
        token.symbol
    )
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
        let (from_net, to_net, from, to) =
            lifi_pair(&from_coin, &from_network, &to_coin, &to_network)?;
        let from_address = profile_address_on(&app, profile_index, from_net)?;
        let destination = canonical_address_input(&destination)?;
        let quote = api::get_lifi_quote(
            from_net,
            &from,
            to_net,
            &to,
            &amount,
            &from_address,
            &destination,
        )
        .t_err()?;
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

/// Native confirmation of a LI.FI swap: bridge, amounts, destination address and
/// how well that address was verified (checked in the simulation, or handled
/// off-chain by the bridge from Solana), fees, transactions; text built solely from
/// the quote verified on the Rust side.
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
        // Canonical forms, shown AND signed (see `send_transaction`).
        let amount = api::canonical_lifi_amount(&from, &amount).t_err()?;
        let destination = canonical_address_input(&destination)?;
        let from_address = profile_address_on(&app, profile_index, from_net)?;
        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Quote obtained HERE and its transaction verified BEFORE the confirmation.
        let (quote, receiver_verified) = api::lifi_verified_quote(from_net, &from, to_net, &to, &amount, &from_address, &destination).t_err()?;
        let sell_line = lifi_amount(quote.from_amount, &from);
        let evm_net = wallet_flow::evm_network(from_net);
        let gas_price = match evm_net {
            Some(net) => Some(api::evm_gas_price_for_confirmation(net).t_err()?),
            None => None,
        };
        // Bitcoin: network fee set by LI.FI's PSBT, shown and bounded (at most 1.5 times
        // the one shown after the new quote).
        let mut btc_max_network_fee = None;
        let fee_lines = match (evm_net, gas_price) {
            _ if from_net == "btc_mainnet" => {
                let deposit = api::lifi_btc_deposit(&quote).t_err()?;
                let openpgp_wallet_core::lifi::LifiTx::Bitcoin { deposit: address, .. } = &quote.tx else {
                    return Err(translate_error("devis LI.FI non Bitcoin"));
                };
                let fee = deposit.network_fee;
                let max_fee = fee.saturating_mul(3) / 2;
                btc_max_network_fee = Some(max_fee);
                let (service, total) = (deposit.service_fees, deposit.total_debit);
                lang(
                    &format!("Dépôt Bitcoin vers l'adresse du pont : {address}\nFrais réseau Bitcoin : {fee} sat, au plus {max_fee} sat\nFrais de LI.FI et de l'app : {service} sat\nTotal débité de votre adresse : {total} sat"),
                    &format!("Bitcoin deposit to the bridge's address: {address}\nBitcoin network fee: {fee} sat, at most {max_fee} sat\nLI.FI's and the app's fees: {service} sat\nTotal debited from your address: {total} sat"),
                )
                .to_string()
            }
            (Some(net), Some(gas_price)) => {
                let (call, approve, approvals) = api::lifi_evm_fees(net, &quote, gas_price).t_err()?;
                let total = call.max_total().t_err()?.saturating_add(approve.max_total().t_err()?.saturating_mul(approvals as u128)) as f64 / 1e18;
                let symbol = net.native_symbol;
                let diamond = openpgp_wallet_core::lifi::diamond(from_net).unwrap_or("?");
                let mut lines = lang(
                    &format!("Frais réseau maximum : {total:.8} {symbol}"),
                    &format!("Maximum network fee: {total:.8} {symbol}"),
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
        swap_grace_period(&app, GraceRecap::swap(format!("{route} ({})", quote.tool_name), format!("{sell_line} → ~{}", lifi_amount(quote.to_amount, &to)), quote.to_address.clone()).on(from_net))?;

        // New quote on the same bridge (a bridge's transaction expires quickly), refused
        // if it no longer matches what was shown.
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
            explorer_url: openpgp_wallet_core::lifi::explorer_url(&tx_hash),
            tx_hash,
            from_chain: fresh.from.chain,
            to_chain: fresh.to.chain,
            duration_secs: fresh.duration_secs,
        })
    })
    .await
}

/// State of a LI.FI transfer, tracked by the UI after sending.
#[tauri::command]
async fn lifi_status(tx_hash: String, from_chain: u64, to_chain: u64) -> Result<String, String> {
    run_blocking(move || openpgp_wallet_core::lifi::status(&tx_hash, from_chain, to_chain).t_err())
        .await
}

/// State of a CoW order ("open", "fulfilled", "expired"…), tracked by the UI after
/// sending.
#[tauri::command]
async fn cow_order_status(network: String, uid: String) -> Result<String, String> {
    run_blocking(move || cow::order_status(&network, &uid).t_err()).await
}

#[tauri::command]
async fn send_usdc_transaction(
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
        let network = "sol_mainnet"; // USDC: mainnet only (see sol_spl.rs)
        let net = sol_network(network)?;
        // Canonical forms, shown AND signed (see `send_transaction`).
        let to = canonical_address_input(&to)?;
        let from_sol = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(_, sol)| sol.clone());
        // "Max": the whole USDC balance (fees are paid in SOL).
        let amount = match (max.unwrap_or(false), &from_sol) {
            (true, Some(from)) => api::token_max("usdc", network, from).t_err()?,
            (true, None) => {
                return Err(translate_error(
                    "adresse du profil inconnue — déverrouillez le portefeuille",
                ))
            }
            (false, _) => amount,
        };
        let amount = api::canonical_amount("usdc", &amount).t_err()?;

        let from_label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == profile_index)
            .map(|p| p.label)
            .unwrap_or_else(|| format!("profil #{profile_index}"));

        // Refused BEFORE the confirmation dialog if the recipient is not a wallet (see
        // `api::check_solana_recipient`), the typical case being a token account address
        // copied from an explorer.
        api::check_solana_recipient(&to, net).t_err()?;
        // Enough balance checked BEFORE the confirmation dialog.
        if let Some(from) = app
            .state::<ProfileAddressCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&profile_index)
            .map(|(_, sol)| sol.clone())
        {
            api::ensure_token_funds("usdc", network, &from, &amount).t_err()?;
        }

        let rent_line = describe_possible_ata_rent(net, &to);
        let amount_line = format!("{amount} USDC");
        // The same log as SOL sends (same network, same recipient wallet): having already
        // paid this address in SOL counts.
        let warning = send_warnings(
            &app,
            &dir,
            network,
            "usdc",
            &to,
            api::usdc_recipient_activity(&to, net).ok(),
        );
        if !confirm_transaction_native(
            &app,
            network,
            &to,
            &amount_line,
            &from_label,
            rent_line.as_deref(),
            warning.as_deref(),
            None,
        ) {
            return Err(translate_error("Virement annulé (confirmation refusée)."));
        }
        send_grace_period(
            &app,
            GraceRecap::new(network_label(network), amount_line.clone(), to.clone()).on(network),
        )?;

        let result = api::send_usdc(&dir, &password, net, &to, &amount, profile_index).t_err();
        if result.is_ok() {
            let _ = sent_recipients::record_sent(&dir, network, &to);
        }
        result
    })
    .await
}

/// Balance of a registry token (`core/src/tokens.rs`) on `network`, at most 6
/// decimals shown (truncated, never rounded up).
#[tauri::command]
async fn get_token_balance(
    token: String,
    network: String,
    address: String,
) -> Result<String, String> {
    run_blocking(move || {
        let (units, decimals) = api::get_token_balance(&token, &network, &address).t_err()?;
        Ok(openpgp_wallet_core::tokens::format_balance(
            units, decimals, 6,
        ))
    })
    .await
}

/// Balances of the xStocks tokenized shares of `address` (Solana) in a single
/// request: `[(identifier, displayed balance)]`, in the format of
/// `get_token_balance` (tokens with no balance absent).
#[tauri::command]
async fn get_stock_balances(address: String) -> Result<Vec<(String, String)>, String> {
    run_blocking(move || {
        Ok(api::stock_balances(&address)
            .t_err()?
            .into_iter()
            .map(|(id, units)| {
                (
                    id.to_string(),
                    openpgp_wallet_core::tokens::format_balance(units, 8, 6),
                )
            })
            .collect())
    })
    .await
}

#[derive(Serialize)]
struct StockPriceDto {
    /// Token identifier (`tslax`…).
    id: String,
    price_usd: f64,
    change_24h_percent: Option<f64>,
    market_cap_usd: Option<f64>,
}

/// Prices of the xStocks tokenized shares (price per displayed unit, Jupiter).
#[tauri::command]
async fn get_stock_prices() -> Result<Vec<StockPriceDto>, String> {
    run_blocking(move || {
        let stocks: Vec<(&str, &str)> = openpgp_wallet_core::tokens::TOKENS
            .iter()
            .filter(|t| openpgp_wallet_core::tokens::is_spl2022(t.id))
            .filter_map(|t| {
                api::registered_solana_token(t.id)
                    .ok()
                    .map(|s| (t.id, s.mint_b58))
            })
            .collect();
        let mints: Vec<&str> = stocks.iter().map(|(_, mint)| *mint).collect();
        let prices = openpgp_wallet_core::price_rpc::jupiter_stock_prices(&mints).t_err()?;
        Ok(prices
            .into_iter()
            .filter_map(|p| {
                let id = stocks.iter().find(|(_, mint)| *mint == p.mint)?.0;
                Some(StockPriceDto {
                    id: id.to_string(),
                    price_usd: p.usd,
                    change_24h_percent: p.change_24h_percent,
                    market_cap_usd: p.market_cap_usd,
                })
            })
            .collect())
    })
    .await
}

/// Transfer of a registry token: the UI only provides the token identifier and the
/// network; contract/mint and decimals come from the Rust registry, and the native
/// dialog shows them (name, contract, amount, fee).
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
        let (info, deployment) = openpgp_wallet_core::tokens::find(&token, &network).ok_or_else(|| translate_error("jeton non pris en charge sur ce réseau"))?;
        let to = canonical_address_input(&to)?;
        // "Max": the whole token balance (fees are paid in the network's native coin).
        let amount = if max.unwrap_or(false) {
            let owner = if network == "tron_mainnet" {
                app.state::<ProfileTronCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).cloned()
            } else {
                app.state::<ProfileAddressCache>().0.lock().unwrap_or_else(|p| p.into_inner()).get(&profile_index).map(|(evm, sol)| if is_evm(&network) { evm.clone() } else { sol.clone() })
            }
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
            openpgp_wallet_core::tokens::TokenKind::Erc20 { contract } => {
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
                // Enough token AND gas, checked BEFORE the confirmation dialog.
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
                send_grace_period(&app, GraceRecap::new(network_label(&network), amount_line.clone(), to.clone()).on(&network))?;
                api::send_erc20(&dir, &password, &token, &network, &to, &amount, fee, profile_index).t_err()
            }
            openpgp_wallet_core::tokens::TokenKind::Trc20 { contract } => {
                let from_tron = app
                    .state::<ProfileTronCache>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&profile_index)
                    .cloned()
                    .ok_or_else(|| translate_error("adresse du profil inconnue — déverrouillez le portefeuille"))?;
                // Token AND TRX for fees checked, transfer simulated (it must emit exactly this
                // transfer) BEFORE the dialog.
                let (plan, _) = api::trc20_send_plan(&token, &from_tron, &to, &amount).t_err()?;
                let token_line = lang(
                    &format!("Jeton : {} ({}) — contrat {contract}", info.name, info.symbol),
                    &format!("Token: {} ({}) — contract {contract}", info.name, info.symbol),
                )
                .to_string();
                let warning = send_warnings(&app, &dir, &network, "trx", &to, api::trx_recipient_activity(&to).ok());
                let (fee, limit) = (openpgp_wallet_core::tron::format_trx(plan.fee_max), openpgp_wallet_core::tron::format_trx(plan.fee_limit));
                let fee_line = lang(
                    &format!("Frais : jusqu'à {fee} TRX (énergie et bande passante ; le réseau ne peut pas brûler plus de {limit} TRX)"),
                    &format!("Fee: up to {fee} TRX (energy and bandwidth; the network cannot burn more than {limit} TRX)"),
                )
                .to_string();
                if !confirm_transaction_native(&app, &network, &to, &amount_line, &from_label, Some(&fee_line), warning.as_deref(), Some(&token_line)) {
                    return Err(translate_error("Virement annulé (confirmation refusée)."));
                }
                send_grace_period(&app, GraceRecap::new(network_label(&network), amount_line.clone(), to.clone()).on(&network))?;
                api::send_trc20(&dir, &password, &token, &to, &amount, plan.fee_max, profile_index).t_err()
            }
            openpgp_wallet_core::tokens::TokenKind::Spl { mint } | openpgp_wallet_core::tokens::TokenKind::Spl2022 { mint } => {
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
                // Recipient's token account to create: the cost is announced beforehand.
                let rent_line = api::token_account_rent_if_missing(&token, &to, net)
                    .ok()
                    .flatten()
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
                send_grace_period(&app, GraceRecap::new(network_label(&network), amount_line.clone(), to.clone()).on(&network))?;
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
    /// PGP fingerprint of the recipient, shown in the address book so the user can
    /// compare it with an offline source (voice message, meeting in person, etc.):
    /// `recipients.json` is an ordinary local file that any code running with the
    /// user's rights can modify, so without a visible way to verify it, a silent swap
    /// of the stored key would go unnoticed (future encryption for the wrong
    /// recipient). Recomputed on the fly from pubkey_armored, never read from the file:
    /// a forged fingerprint would no longer match the key actually used for encryption.
    fingerprint: String,
    /// Key ID and PGP identity (name/email embedded in the certificate), added for
    /// viewing a recipient in detail (the "View key" modal): the same three pieces of
    /// information as the Certificate tab shows for the device's own identity.
    key_id: String,
    user_id: String,
}

impl From<messaging::Recipient> for RecipientDto {
    fn from(r: messaging::Recipient) -> Self {
        let info = messaging::cert_info(&r.pubkey_armored).ok();
        Self {
            label: r.label,
            pubkey_armored: r.pubkey_armored,
            fingerprint: info
                .as_ref()
                .map(|i| i.fingerprint.clone())
                .unwrap_or_else(|| "invalide".to_string()),
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

/// Certificate (public key) of THIS device: to share so that others can add you as
/// a recipient and send you encrypted messages.
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
fn add_recipient(
    label: String,
    pubkey_armored: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let dir = data_dir(&app)?;

    if let Some((old_fingerprint, new_fingerprint)) =
        messaging::recipient_key_change(&dir, &label, &pubkey_armored).t_err()?
    {
        // Native dialog, the same mechanism as for a send of funds: replacing the key of a
        // contact who is already saved is not trivial (see the docs of
        // `recipient_key_change`), so it must not go through silently as
        // `messaging::add_recipient` alone would allow. Label cleaned up for display only
        // (see `dialog_label`).
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
            .title(lang(
                "Clé du destinataire modifiée",
                "Recipient key changed",
            ))
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

/// Decrypts a message received by this device (requires the password to unlock the
/// local private key, as for a send of funds).
#[tauri::command]
async fn decrypt_message(
    password: String,
    ciphertext: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        api::decrypt_incoming_message(&dir, &password, &ciphertext).t_err()
    })
    .await
}

// --- External wallets --------------------------------------------------------
//
// Read-only tracking of addresses that do not belong to this wallet (see
// core/src/external_wallets.rs): no secrets involved, and each one's balance goes
// through the existing `get_balance` command, exactly as for the wallet's own
// profiles.

#[tauri::command]
fn list_external_wallets(
    app: tauri::AppHandle,
) -> Result<Vec<external_wallets::ExternalWallet>, String> {
    let dir = data_dir(&app)?;
    Ok(external_wallets::list_wallets(&dir))
}

#[tauri::command]
fn list_external_wallet_groups(
    app: tauri::AppHandle,
) -> Result<Vec<external_wallets::ExternalWalletGroup>, String> {
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
fn set_external_wallet_group(
    id: u32,
    group_id: Option<u32>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::set_wallet_group(&dir, id, group_id).t_err()
}

#[tauri::command]
fn create_external_wallet_group(
    name: String,
    app: tauri::AppHandle,
) -> Result<external_wallets::ExternalWalletGroup, String> {
    let dir = data_dir(&app)?;
    external_wallets::create_group(&dir, &name).t_err()
}

#[tauri::command]
fn rename_external_wallet_group(
    id: u32,
    name: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::rename_group(&dir, id, &name).t_err()
}

#[tauri::command]
fn delete_external_wallet_group(id: u32, app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    external_wallets::delete_group(&dir, id).t_err()
}

// --- Address book -------------------------------------------------------------
//
// Attach a label to an address to find it again when sending funds (see
// core/src/address_book.rs); separate from external wallets (no balance is ever
// queried here).

#[tauri::command]
fn list_address_book(app: tauri::AppHandle) -> Result<Vec<address_book::AddressBookEntry>, String> {
    let dir = data_dir(&app)?;
    Ok(address_book::list_entries(&dir))
}

/// Networks on which an address is valid (address book, external wallets): the UI's
/// "Network" menu only offers those.
#[tauri::command]
fn address_networks(address: String) -> Vec<&'static str> {
    address_book::networks_for(&address)
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
//
// See core/src/walletconnect/ (protocol) and core/src/dapp_requests.rs (request
// preparation). Here: app state, commands, and the NATIVE confirmation dialogs,
// whose text is built solely from the request prepared on the Rust side, never
// from data returned by the frontend.

/// PUBLIC addresses of the profiles, remembered at unlock: connecting a dApp does
/// not ask for the password (no signature), only for knowing which addresses to
/// present to it. Cleared on reset.
#[derive(Default)]
struct ProfileAddressCache(std::sync::Mutex<std::collections::HashMap<u32, (String, String)>>);

/// Transparent Zcash address of each profile, remembered at the same time:
/// preparing a ZEC send (outputs to spend, fees) needs the source address BEFORE
/// the confirmation dialog, so before any password.
#[derive(Default)]
struct ProfileZcashCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Tron address of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileTronCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// XRP address of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileXrpCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Stellar address of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileStellarCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// NEAR implicit account of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileNearCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Cardano address of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileCardanoCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Stacks address of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileStacksCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Bittensor address of each profile (preparing a send before the dialog).
#[derive(Default)]
struct ProfileBittensorCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Bitcoin testnet address of each profile ("Max" button of a testnet send).
#[derive(Default)]
struct ProfileBtcTestnetCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Dogecoin address of each profile, remembered at the same time: preparing a DOGE
/// send (verified outputs, fees) needs the source address BEFORE the confirmation
/// dialog.
#[derive(Default)]
struct ProfileDogeCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

/// Bitcoin (mainnet) address of each profile, remembered at the same time: a LI.FI
/// swap from Bitcoin needs a quote (a PSBT built on its outputs) BEFORE the
/// confirmation dialog.
#[derive(Default)]
struct ProfileBtcCache(std::sync::Mutex<std::collections::HashMap<u32, String>>);

#[derive(Default)]
struct WcState {
    client: std::sync::OnceLock<std::sync::Arc<openpgp_wallet_core::walletconnect::WalletConnect>>,
    /// Prepared requests (what will be signed AND shown), by identifier, with the
    /// connection (topic) they came from.
    prepared: std::sync::Mutex<std::collections::HashMap<u64, (String, dapp_requests::Prepared)>>,
}

fn remember_addresses(app: &tauri::AppHandle, index: u32, addresses: &api::Addresses) {
    if index == 0 {
        IS_AFFILIATE_WALLET.store(
            addresses.thor == openpgp_wallet_core::thorchain_rpc::AFFILIATE_ADDRESS,
            Ordering::Relaxed,
        );
    }
    if let Some(cache) = app.try_state::<ProfileAddressCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, (addresses.evm.clone(), addresses.solana.clone()));
    }
    if let Some(cache) = app.try_state::<ProfileZcashCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.zcash.clone());
    }
    if let Some(cache) = app.try_state::<ProfileBtcCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.btc_mainnet.clone());
    }
    if let Some(cache) = app.try_state::<ProfileDogeCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.doge.clone());
    }
    if let Some(cache) = app.try_state::<ProfileBtcTestnetCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.btc_testnet.clone());
    }
    if let Some(cache) = app.try_state::<ProfileTronCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.tron.clone());
    }
    if let Some(cache) = app.try_state::<ProfileXrpCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.xrp.clone());
    }
    if let Some(cache) = app.try_state::<ProfileStellarCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.stellar.clone());
    }
    if let Some(cache) = app.try_state::<ProfileNearCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.near.clone());
    }
    if let Some(cache) = app.try_state::<ProfileCardanoCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.cardano.clone());
    }
    if let Some(cache) = app.try_state::<ProfileStacksCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.stacks.clone());
    }
    if let Some(cache) = app.try_state::<ProfileBittensorCache>() {
        cache
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(index, addresses.bittensor.clone());
    }
    if let Some(cache) = app.try_state::<ShieldedKeysCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(
            index,
            (
                addresses.zcash_shielded.clone(),
                addresses.zcash_shielded_keys.clone(),
            ),
        );
    }
    if let Some(cache) = app.try_state::<MoneroKeysCache>() {
        cache.0.lock().unwrap_or_else(|p| p.into_inner()).insert(
            index,
            (addresses.monero.clone(), addresses.monero_keys.clone()),
        );
    }
    start_shielded_sync(app);
    start_monero_sync(app);
}

/// Monero address and view keys of each profile, remembered at unlock (never sent
/// to the UI): background sync and send preparation before the confirmation dialog.
#[derive(Default)]
struct MoneroKeysCache(
    std::sync::Mutex<
        std::collections::HashMap<u32, (String, openpgp_wallet_core::monero::ViewKeys)>,
    >,
);

/// Profile of the Monero address `address` (the card's generic commands receive an
/// address).
fn monero_profile(app: &tauri::AppHandle, address: &str) -> Result<u32, String> {
    app.state::<MoneroKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(_, (known, _))| known == address)
        .map(|(index, _)| *index)
        .ok_or_else(|| {
            translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
        })
}

/// Monero card shown (`set_xmr_sync`): without it, and without funds already
/// received, no blocks are downloaded (~15 MB per day of chain).
static XMR_SYNC_WANTED: AtomicBool = AtomicBool::new(false);
/// A pass requested right away (card enabled, send broadcast).
static XMR_SYNC_KICK: AtomicBool = AtomicBool::new(false);

/// Background Monero sync, one at a time: blocks scanned up to the tip of the
/// chain, then every 30 s (one block every 2 minutes on average: a receipt shows up
/// shortly after its block; a pass with no new block only costs a height read). The
/// UI is notified after each pass (`xmr-synced`); a network failure is retried at
/// the next pass.
fn start_monero_sync(app: &tauri::AppHandle) {
    static RUNNING: AtomicBool = AtomicBool::new(false);
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || loop {
        // Generation read BEFORE the keys (see `seed_state`).
        let generation = openpgp_wallet_core::seed_state::generation();
        let keys: Vec<_> = app
            .state::<MoneroKeysCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|(_, keys)| keys.clone())
            .collect();
        let wanted = XMR_SYNC_WANTED.load(Ordering::Relaxed)
            || data_dir(&app).is_ok_and(|dir| api::xmr_has_received(&dir));
        if wanted && !keys.is_empty() {
            match data_dir(&app) {
                Ok(dir) => match catch_sync_panic(|| api::sync_xmr(&dir, &keys, generation)) {
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

/// Monero card shown or not (the user's choice): background sync only runs for it
/// (or if funds have already been received).
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
    /// Chain fully scanned (the balance is up to date).
    synced: bool,
}

/// The profile's detailed Monero balance (local state, no network call): the card
/// shows the part still locked and the sync state.
#[tauri::command]
async fn xmr_status(profile_index: u32, app: tauri::AppHandle) -> Result<MoneroStatusDto, String> {
    run_blocking(move || {
        let balance = api::xmr_balance(&data_dir(&app)?, profile_index).t_err()?;
        Ok(MoneroStatusDto {
            unlocked: openpgp_wallet_core::monero::format_xmr(balance.unlocked),
            locked: openpgp_wallet_core::monero::format_xmr(balance.locked),
            synced: balance.synced,
        })
    })
    .await
}

/// Ethereum-compatible network added by the user (Settings, "Custom RPC"), as the
/// UI shows it: one card per network.
#[derive(Serialize)]
struct CustomNetworkDto {
    id: String,
    chain_id: u64,
    name: String,
    rpc: String,
    symbol: String,
    explorer: Option<String>,
}

impl From<openpgp_wallet_core::custom_networks::CustomNetwork> for CustomNetworkDto {
    fn from(n: openpgp_wallet_core::custom_networks::CustomNetwork) -> Self {
        Self {
            id: n.id(),
            chain_id: n.chain_id,
            name: n.name,
            rpc: n.rpc,
            symbol: n.symbol,
            explorer: n.explorer,
        }
    }
}

#[tauri::command]
fn list_custom_networks(app: tauri::AppHandle) -> Result<Vec<CustomNetworkDto>, String> {
    Ok(openpgp_wallet_core::custom_networks::list(&data_dir(&app)?)
        .into_iter()
        .map(Into::into)
        .collect())
}

/// A server address for a confirmation window: hazardous characters removed, and,
/// when too long, its END kept, since that is where the domain that receives the
/// requests is (`rpc.example.com.attacker.net` must not read as `rpc.example.com…`).
/// Hosts arrive already in ASCII (punycode for an international name), so a
/// lookalike letter cannot pass for another one.
fn dialog_host(host: &str) -> String {
    const MAX_CHARS: usize = 60;
    let cleaned: String = host
        .chars()
        .filter(|&c| !is_dialog_hazard(c) && !c.is_whitespace())
        .collect();
    let count = cleaned.chars().count();
    if count > MAX_CHARS {
        format!(
            "…{}",
            cleaned.chars().skip(count - MAX_CHARS).collect::<String>()
        )
    } else {
        cleaned
    }
}

/// Before an added network's RPC is contacted for the first time (see
/// `custom_networks::add`): the host the requests will go to, and the explorer the
/// links will open.
fn confirm_custom_network_window(
    app: &tauri::AppHandle,
    network: &openpgp_wallet_core::custom_networks::CustomNetwork,
) -> bool {
    let host = dialog_host(&openpgp_wallet_core::custom_networks::rpc_host(network));
    let name = dialog_label(&network.name);
    let mut paragraphs = vec![
        if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("The app will contact \"{host}\" to check \"{name}\", then use it for this network's balances and sends.")
        } else {
            format!("L'app va contacter «\u{a0}{host}\u{a0}» pour vérifier «\u{a0}{name}\u{a0}», puis s'en servir pour les soldes et les envois de ce réseau.")
        },
        text(
            "Ce serveur verra votre adresse IP et votre adresse sur ce réseau.",
            "This server will see your IP address and your address on this network.",
        ),
    ];
    if let Some(explorer) = &network.explorer {
        let explorer = dialog_host(
            explorer
                .strip_prefix("https://")
                .and_then(|rest| rest.split(['/', ':']).next())
                .unwrap_or(explorer),
        );
        paragraphs.push(if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
            format!("Explorer links will open \"{explorer}\".")
        } else {
            format!("Les liens d'explorateur ouvriront «\u{a0}{explorer}\u{a0}».")
        });
    }
    secure_confirm(
        app,
        SecureConfirmDetails::new(
            "globe",
            ("Ajouter ce réseau ?", "Add this network?"),
            paragraphs,
            ("Ajouter le réseau", "Add the network"),
        ),
    )
}

/// Adds a network: checks, the user's approval of the server (secure window), then
/// the chain ID verified with the RPC (network call, off the main thread).
#[tauri::command]
async fn add_custom_network(
    chain_id: u64,
    name: String,
    rpc: String,
    symbol: String,
    explorer: Option<String>,
    app: tauri::AppHandle,
) -> Result<CustomNetworkDto, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        openpgp_wallet_core::custom_networks::add(
            &dir,
            chain_id,
            &name,
            &rpc,
            &symbol,
            explorer.as_deref(),
            |network| confirm_custom_network_window(&app, network),
        )
        .t_err()
        .map(Into::into)
    })
    .await
}

/// Removes an added network: its card disappears, the funds stay on-chain (adding
/// it again brings them back).
#[tauri::command]
fn remove_custom_network(chain_id: u64, app: tauri::AppHandle) -> Result<(), String> {
    openpgp_wallet_core::custom_networks::remove(&data_dir(&app)?, chain_id).t_err()
}

/// Monero node chosen in Settings (`None`: the default public nodes).
#[tauri::command]
fn xmr_node(app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(api::xmr_node(&data_dir(&app)?))
}

/// "Rescan from the beginning" (Settings): Monero and shielded Zcash reread from
/// the app's fixed birthday (funds older than the wallet's creation on this
/// device).
#[tauri::command]
fn rescan_private_funds(app: tauri::AppHandle) -> Result<(), String> {
    api::rescan_private_funds(&data_dir(&app)?).t_err()?;
    XMR_SYNC_KICK.store(true, Ordering::SeqCst);
    Ok(())
}

/// Before a Monero node chosen in Settings is saved, and so contacted (see
/// `monero::set_custom_node`).
fn confirm_xmr_node_window(app: &tauri::AppHandle, url: &str) -> bool {
    let node = dialog_host(url.split_once("://").map_or(url, |(_, rest)| rest));
    secure_confirm(
        app,
        SecureConfirmDetails::new(
            "globe",
            ("Utiliser ce nœud Monero ?", "Use this Monero node?"),
            vec![
                if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                    format!("The app will sync your Monero balance with \"{node}\".")
                } else {
                    format!("L'app va synchroniser votre solde Monero avec «\u{a0}{node}\u{a0}».")
                },
                text(
                    "Ce nœud verra votre adresse IP. Choisissez un nœud que vous connaissez.",
                    "This node will see your IP address. Pick a node you know.",
                ),
            ],
            ("Utiliser ce nœud", "Use this node"),
        ),
    )
}

/// Saves the Monero node (empty: back to the public nodes), used from the next sync
/// onwards, once approved in the secure window. Off the main thread: the window
/// needs it.
#[tauri::command]
async fn set_xmr_node(url: String, app: tauri::AppHandle) -> Result<Option<String>, String> {
    run_blocking(move || {
        let node = api::set_xmr_node(&data_dir(&app)?, &url, |node| {
            confirm_xmr_node_window(&app, node)
        })
        .t_err()?;
        XMR_SYNC_KICK.store(true, Ordering::SeqCst);
        Ok(node)
    })
    .await
}

/// A background sync pass protected against a library panic (unexpected data from a
/// node): otherwise the thread would stop for good, silently, until the app is
/// restarted.
fn catch_sync_panic<E: std::fmt::Display>(
    sync: impl FnOnce() -> Result<(), E>,
) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(sync)) {
        Ok(result) => result.map_err(|e| format!("{e:#}")),
        Err(_) => Err(
            "synchronisation interrompue (erreur interne), reprise au passage suivant".to_string(),
        ),
    }
}

/// Viewing keys of the shielded Zcash accounts, remembered at unlock (never sent to
/// the UI).
#[derive(Default)]
struct ShieldedKeysCache(
    std::sync::Mutex<
        std::collections::HashMap<u32, (String, openpgp_wallet_core::zcash_shielded::ProfileKeys)>,
    >,
);

/// Profile of the shielded Zcash address `address` ("Shielded Zcash" card).
fn shielded_profile(app: &tauri::AppHandle, address: &str) -> Result<u32, String> {
    app.state::<ShieldedKeysCache>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(_, (known, _))| known == address)
        .map(|(index, _)| *index)
        .ok_or_else(|| {
            translate_error("adresse du profil inconnue — déverrouillez le portefeuille")
        })
}

/// A shielded Zcash sync pass requested right away (send or shielding broadcast).
static ZECS_SYNC_KICK: AtomicBool = AtomicBool::new(false);
/// The last shielded sync pass failed: the card says so instead of "Syncing" forever.
/// Until v2.14.0 a failure only reached the log, and a wallet whose every pass failed
/// (2026-10-17) looked like it was still syncing two days later.
static ZECS_SYNC_FAILED: AtomicBool = AtomicBool::new(false);

/// Background shielded Zcash sync, one at a time: missing accounts created, chain scanned,
/// then every 30 s (one block every 75 s, every 25 s from NU7) while the app is open. The
/// UI is notified after each pass (`zec-shielded-synced`); a network failure is retried at
/// the next pass.
fn start_shielded_sync(app: &tauri::AppHandle) {
    static RUNNING: AtomicBool = AtomicBool::new(false);
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || loop {
        let generation = openpgp_wallet_core::seed_state::generation();
        let keys: Vec<_> = app
            .state::<ShieldedKeysCache>()
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|(_, keys)| keys.clone())
            .collect();
        if keys.is_empty() {
            ZECS_SYNC_FAILED.store(false, Ordering::SeqCst);
        } else {
            let outcome = data_dir(&app).and_then(|dir| {
                catch_sync_panic(|| api::sync_zec_shielded(&dir, &keys, generation))
            });
            ZECS_SYNC_FAILED.store(outcome.is_err(), Ordering::SeqCst);
            match outcome {
                Ok(()) => {
                    let _ = app.emit("zec-shielded-synced", ());
                }
                Err(e) => eprintln!("Zcash protégé : {e:#}"),
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
    /// Chain fully scanned (the balance is up to date).
    synced: bool,
    /// While syncing: share of the blocks already scanned, in percent.
    progress: Option<u8>,
    /// The last sync pass failed (it is retried every 30 s).
    failed: bool,
}

fn shielded_dialog(app: &tauri::AppHandle, title: (&str, &str), message: String) -> bool {
    app.dialog()
        .message(message)
        .title(lang(title.0, title.1))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Shields the profile's transparent ZEC (t1 → the same profile's shielded address)
/// after a native confirmation dialog (amount, ZIP-317 fee).
#[tauri::command]
async fn zec_shield(
    password: String,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<String, String> {
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
        let confirm = |s: &openpgp_wallet_core::zcash_shielded::SpendSummary| {
            let (amount, fee) = (openpgp_wallet_core::zcash::format_zec(s.amount), openpgp_wallet_core::zcash::format_zec(s.fee));
            let to = &s.recipient;
            let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                format!("Shield your transparent ZEC\n\nFrom: {t1}\nTo your shielded address: {to}\nAmount shielded: {amount} ZEC\nNetwork fee: {fee} ZEC\n\nOnce shielded, amounts and addresses are no longer visible on the blockchain.\n\nConfirm?")
            } else {
                format!("Protéger vos ZEC transparents\n\nDepuis : {t1}\nVers votre adresse protégée : {to}\nMontant protégé : {amount} ZEC\nFrais réseau : {fee} ZEC\n\nUne fois protégés, montants et adresses ne sont plus visibles sur la blockchain.\n\nConfirmer ?")
            };
            // Then the cancellation delay, before signing (audit round 33: it was missing
            // here, as it had been everywhere else until round 29).
            shielded_dialog(&app, ("Confirmer la protection", "Confirm shielding"), message)
                && send_grace_period(&app, GraceRecap::new(network_label("zec_shielded"), format!("{amount} ZEC"), to.to_string()).on("zec_mainnet")).is_ok()
        };
        match api::shield_zec(&dir, &password, profile_index, &t1, confirm).t_err()? {
            Some(txid) => {
                // Pending note in the database: balances reread straight away.
                ZECS_SYNC_KICK.store(true, Ordering::SeqCst);
                Ok(txid)
            }
            None => Err(translate_error("Protection annulée (confirmation refusée).")),
        }
    })
    .await
}

/// Sends from the profile's shielded Zcash funds, after a native confirmation
/// dialog (recipient, amount, fee).
#[tauri::command]
async fn zec_send_shielded(
    password: String,
    profile_index: u32,
    to: String,
    amount: String,
    max: Option<bool>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    run_blocking(move || {
        let password = Zeroizing::new(password);
        let dir = data_dir(&app)?;
        let to = canonical_address_input(&to)?;
        let max = max.unwrap_or(false);
        // "Max": the amount set by the "send everything" proposal, shown in the dialog
        // (`SpendSummary`).
        let amount = if max { String::new() } else { api::canonical_zec_amount(&amount).t_err()? };
        let from_label = api::list_profiles(&dir).into_iter().find(|p| p.index == profile_index).map(|p| p.label).unwrap_or_else(|| format!("profil #{profile_index}"));
        let from_label = dialog_label(&from_label);
        // Like the other sends: lookalike address, never paid, and (to a transparent
        // address) on-chain state.
        let warning = if to.starts_with('t') {
            send_warnings(&app, &dir, "zec_shielded", "zec", &to, api::zec_recipient_activity(&to).ok())
        } else {
            send_warnings(&app, &dir, "zec_shielded", "zecs", &to, None)
        };
        let warning = warning.map(|w| format!("{w}\n\n")).unwrap_or_default();
        let confirm = |s: &openpgp_wallet_core::zcash_shielded::SpendSummary| {
            let (amount, fee) = (openpgp_wallet_core::zcash::format_zec(s.amount), openpgp_wallet_core::zcash::format_zec(s.fee));
            let to = &s.recipient;
            let max_note = if max { lang(" (maximum, frais déduits)", " (maximum, fees deducted)") } else { "" };
            let message = if UI_LANG_IS_ENGLISH.load(Ordering::Relaxed) {
                format!("{warning}Send from your shielded ZEC\n\nFrom profile: {from_label}\nTo: {to}\nAmount: {amount} ZEC{max_note}\nNetwork fee: {fee} ZEC\n\nThis is irreversible.\n\nConfirm this transfer?")
            } else {
                format!("{warning}Envoi depuis vos ZEC protégés\n\nDepuis le profil : {from_label}\nVers : {to}\nMontant : {amount} ZEC{max_note}\nFrais réseau : {fee} ZEC\n\nC'est irréversible.\n\nConfirmer cet envoi ?")
            };
            // Then the cancellation delay, before signing.
            shielded_dialog(&app, ("Confirmer l'envoi", "Confirm the transfer"), message)
                && send_grace_period(&app, GraceRecap::new(network_label("zec_shielded"), format!("{amount} ZEC{max_note}"), to.to_string()).on("zec_shielded")).is_ok()
        };
        let sent = if max {
            api::send_zec_shielded_max(&dir, &password, profile_index, &to, confirm)
        } else {
            api::send_zec_shielded(&dir, &password, profile_index, &to, &amount, confirm)
        };
        match sent.t_err()? {
            Some(txid) => {
                // Recipient remembered only after a successful broadcast.
                let _ = sent_recipients::record_sent(&dir, "zec_shielded", &to);
                ZECS_SYNC_KICK.store(true, Ordering::SeqCst);
                Ok(txid)
            }
            None => Err(translate_error("Envoi annulé (confirmation refusée).")),
        }
    })
    .await
}

/// The profile's shielded Zcash balance (read from the local database, no network
/// call).
#[tauri::command]
async fn zec_shielded_balance(
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<ShieldedBalanceDto, String> {
    run_blocking(move || {
        let dir = data_dir(&app)?;
        let balance = api::zec_shielded_balance(&dir, profile_index).t_err()?;
        let synced = matches!((balance.scanned_height, balance.chain_height), (Some(s), Some(c)) if s + 2 >= c);
        Ok(ShieldedBalanceDto {
            spendable: openpgp_wallet_core::zcash::format_zec(balance.spendable),
            pending: openpgp_wallet_core::zcash::format_zec(balance.pending),
            synced,
            progress: balance.progress,
            failed: ZECS_SYNC_FAILED.load(Ordering::SeqCst),
        })
    })
    .await
}

fn wc_client(
    app: &tauri::AppHandle,
) -> Result<std::sync::Arc<openpgp_wallet_core::walletconnect::WalletConnect>, String> {
    app.state::<WcState>()
        .client
        .get()
        .cloned()
        .ok_or_else(|| translate_error("WalletConnect indisponible (démarrage impossible)"))
}

fn caip2_label(chain: &str) -> String {
    match dapp_requests::network_for_chain(chain) {
        Some(dapp_requests::Network::Evm(net)) if net.mainnet => {
            format!("{} — {}", net.name, lang("fonds réels", "real funds"))
        }
        Some(dapp_requests::Network::Evm(net)) => format!("{} (testnet)", net.name),
        Some(dapp_requests::Network::Solana(_)) if chain == dapp_requests::SOLANA_MAINNET => {
            lang("Solana — fonds réels", "Solana — real funds").to_string()
        }
        Some(dapp_requests::Network::Solana(_)) => "Solana devnet".to_string(),
        None => lang("réseau inconnu", "unknown network").to_string(),
    }
}

/// Integer amount (smallest unit) formatted with `decimals` decimals.
fn format_units(integer: &str, decimals: Option<u8>) -> String {
    let Some(decimals) = decimals.map(usize::from) else {
        return format!(
            "{integer} {}",
            lang(
                "(unités brutes, décimales inconnues)",
                "(raw units, unknown decimals)"
            )
        );
    };
    let (negative, digits) = integer
        .strip_prefix('-')
        .map_or((false, integer), |d| (true, d));
    let padded = format!("{digits:0>width$}", width = decimals + 1);
    let (whole, frac) = padded.split_at(padded.len() - decimals);
    let frac = frac.trim_end_matches('0');
    let sign = if negative { "-" } else { "" };
    if frac.is_empty() {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{frac}")
    }
}

/// Free text from a dApp (message to sign, EIP-712 fields) shown in a native
/// dialog: each line cleaned up (see `dialog_label`, without the 40-character
/// truncation), prefixed with a vertical bar that sets it apart from the app's own
/// lines (so it cannot imitate "Network:" or "Amount:"), and the number of lines
/// bounded so the buttons stay visible.
fn quoted_block(lines: impl IntoIterator<Item = String>, max_lines: usize) -> String {
    const MAX_CHARS: usize = 90;
    let all: Vec<String> = lines
        .into_iter()
        .map(|l| {
            let clean: String = l
                .chars()
                .map(|c| if is_dialog_hazard(c) { ' ' } else { c })
                .collect();
            if clean.chars().count() > MAX_CHARS {
                format!("{}…", clean.chars().take(MAX_CHARS).collect::<String>())
            } else {
                clean
            }
        })
        .collect();
    let mut out: Vec<String> = all
        .iter()
        .take(max_lines)
        .map(|l| format!("  │ {l}"))
        .collect();
    if all.len() > max_lines {
        out.push(format!(
            "  │ … ({} {})",
            all.len() - max_lines,
            lang("ligne(s) de plus", "more line(s)")
        ));
    }
    out.join("\n")
}

fn host_of(url: &str) -> String {
    tauri::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default()
}

/// Text of the prepared request: the same in the app's modal and in the native
/// dialog (only the latter counts). `danger`: at least one serious warning
/// (unlimited approval, undecoded call…).
fn describe_prepared(
    prepared: &dapp_requests::Prepared,
    peer: &openpgp_wallet_core::walletconnect::engine::PeerMetadata,
    from_label: &str,
    account: &str,
) -> (String, bool) {
    use dapp_requests::{Prepared, TypedRisk};
    use openpgp_wallet_core::evm_sign::CallKind;
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
        Prepared::EvmPersonalSign { network, .. }
        | Prepared::EvmTypedData { network, .. }
        | Prepared::EvmTransaction { network, .. } => dapp_requests::evm_caip2(network),
        Prepared::SolanaMessage { network, .. } | Prepared::SolanaTransaction { network, .. } => {
            if network.rpc == wallet_flow::SOLANA_MAINNET.rpc {
                dapp_requests::SOLANA_MAINNET
            } else {
                dapp_requests::SOLANA_DEVNET
            }
            .to_string()
        }
    };
    let from_label = dialog_label(from_label);
    lines.push(if en {
        format!(
            "Network: {}\nAccount: {account} (profile \"{from_label}\")",
            caip2_label(&network)
        )
    } else {
        format!(
            "Réseau : {}\nCompte : {account} (profil « {from_label} »)",
            caip2_label(&network)
        )
    });

    let message_block = |view: &dapp_requests::MessageView| -> String {
        match &view.text {
            Some(text) => quoted_block(text.lines().map(str::to_string), 12),
            None => quoted_block(
                view.hex
                    .as_bytes()
                    .chunks(64)
                    .map(|c| String::from_utf8_lossy(c).into_owned()),
                6,
            ),
        }
    };
    match prepared {
        Prepared::EvmPersonalSign { view, .. } | Prepared::SolanaMessage { view, .. } => {
            lines.push(
                lang(
                    "Signature d'un MESSAGE (aucun fonds ne bouge directement) :",
                    "Signing a MESSAGE (no funds move directly):",
                )
                .to_string(),
            );
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
            let contract = view
                .verifying_contract
                .as_deref()
                .map(dialog_address)
                .unwrap_or_else(|| "—".into());
            let app = view
                .domain_name
                .as_deref()
                .map(dialog_label)
                .unwrap_or_else(|| "—".into());
            lines.push(if en {
                format!("Signing STRUCTURED DATA (EIP-712) \"{primary}\"\nApplication: {app}\nContract: {contract}")
            } else {
                format!("Signature de DONNÉES STRUCTURÉES (EIP-712) « {primary} »\nApplication : {app}\nContrat : {contract}")
            });
            match &view.risk {
                TypedRisk::Permit {
                    spender,
                    amount,
                    unlimited,
                } => {
                    danger = true;
                    let spender = spender
                        .as_deref()
                        .map(dialog_address)
                        .unwrap_or_else(|| "?".into());
                    let amount = if *unlimited {
                        lang("un montant ILLIMITÉ", "an UNLIMITED amount").to_string()
                    } else {
                        amount
                            .clone()
                            .map(|a| format!("{a} {}", lang("unité(s) brute(s)", "raw unit(s)")))
                            .unwrap_or_else(|| "?".into())
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
                TypedRisk::None => lines.push(
                    lang(
                        "Ne signez que si vous comprenez ce que ces données autorisent.",
                        "Only sign if you understand what this data authorizes.",
                    )
                    .to_string(),
                ),
            }
            let mut field_lines: Vec<String> = view
                .fields
                .iter()
                .map(|(p, v)| format!("{p} : {v}"))
                .collect();
            if view.hidden_fields > 0 {
                field_lines.push(format!(
                    "… ({} {})",
                    view.hidden_fields,
                    lang("champ(s) non affiché(s)", "field(s) not shown")
                ));
            }
            lines.push(quoted_block(field_lines, 12));
        }
        Prepared::EvmTransaction {
            network,
            to,
            value,
            gas_limit,
            gas_price,
            l1_fee,
            call,
            to_is_contract,
            token,
            data,
        } => {
            let to = openpgp_wallet_core::derivation::format_address(to);
            let kind = if *to_is_contract {
                lang("contrat", "contract")
            } else {
                lang("adresse ordinaire", "regular address")
            };
            let symbol = token
                .as_ref()
                .and_then(|t| t.symbol.as_deref())
                .map(dialog_label)
                .unwrap_or_else(|| lang("jetons", "tokens").to_string());
            let decimals = token.as_ref().and_then(|t| t.decimals);
            let tokens = |amount: &openpgp_wallet_core::evm_sign::U256| {
                format!("{} {symbol}", format_units(&amount.to_decimal(), decimals))
            };
            lines.push(if en {
                format!(
                    "TRANSACTION to {to} ({kind})\n{} sent: {}",
                    network.native_symbol,
                    format_units(&value.to_string(), Some(18))
                )
            } else {
                format!(
                    "TRANSACTION vers {to} ({kind})\n{} envoyé : {}",
                    network.native_symbol,
                    format_units(&value.to_string(), Some(18))
                )
            });
            let addr = |a: &[u8; 20]| openpgp_wallet_core::derivation::format_address(a);
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
                lines.push(
                    lang(
                        "⚠ Des données sont jointes, mais le destinataire n'est pas un contrat.",
                        "⚠ Data is attached, but the recipient is not a contract.",
                    )
                    .to_string(),
                );
            }
            lines.push(evm_fee_line_for(
                api::EvmFee {
                    gas_price: *gas_price,
                    gas_limit: *gas_limit,
                    l1_fee: *l1_fee,
                },
                network.native_symbol,
            ));
        }
        Prepared::SolanaTransaction { send, effects, .. } => {
            lines.push(
                if *send {
                    lang(
                        "TRANSACTION Solana — signée ET envoyée par ce portefeuille.",
                        "Solana TRANSACTION — signed AND sent by this wallet.",
                    )
                } else {
                    lang(
                        "TRANSACTION Solana — signée ici, envoyée ensuite par la dApp.",
                        "Solana TRANSACTION — signed here, then sent by the dApp.",
                    )
                }
                .to_string(),
            );
            lines.push(
                lang(
                    "Effets simulés sur vos comptes :",
                    "Simulated effects on your accounts:",
                )
                .to_string(),
            );
            let effect_lines: Vec<String> = effects
                .iter()
                .map(|e| {
                    let name = e
                        .label
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{} {}", lang("jeton", "token"), e.asset));
                    let amount = format_units(&e.delta.to_string(), e.decimals);
                    let amount = if e.delta > 0 {
                        format!("+{amount}")
                    } else {
                        amount
                    };
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
    let footer = lang(
        "Confirmer ? C'est irréversible.",
        "Confirm? This is irreversible.",
    );
    app.dialog()
        .message(format!("{text}\n\n{footer}"))
        .title(lang(
            "Demande d'une application (WalletConnect)",
            "Application request (WalletConnect)",
        ))
        .kind(if danger {
            MessageDialogKind::Warning
        } else {
            MessageDialogKind::Info
        })
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

#[tauri::command]
fn wc_pair(uri: String, app: tauri::AppHandle) -> Result<(), String> {
    wc_client(&app)?.pair(&uri).t_err()
}

#[tauri::command]
fn wc_sessions(
    app: tauri::AppHandle,
) -> Result<Vec<openpgp_wallet_core::walletconnect::SessionView>, String> {
    Ok(wc_client(&app)?.sessions())
}

#[tauri::command]
fn wc_disconnect(topic: String, app: tauri::AppHandle) -> Result<(), String> {
    wc_client(&app)?.disconnect(&topic).t_err()
}

/// Connecting a dApp: no signature, but the dApp will see the profile's addresses
/// and can then REQUEST signatures, hence a native dialog.
#[tauri::command]
async fn wc_approve_session(
    proposal_id: u64,
    profile_index: u32,
    app: tauri::AppHandle,
) -> Result<bool, String> {
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

/// Analyzes a received request (dry run, simulation, decoding) and returns its text
/// for the app's modal. A request that is invalid or dangerous by construction is
/// refused here and the dApp is told.
#[tauri::command]
async fn wc_prepare_request(
    request_id: u64,
    app: tauri::AppHandle,
) -> Result<PreparedRequestDto, String> {
    run_blocking(move || {
        let client = wc_client(&app)?;
        let request = client
            .pending_request(request_id)
            .ok_or_else(|| translate_error("demande introuvable ou expirée"))?;
        let session = client
            .session(&request.topic)
            .ok_or_else(|| translate_error("connexion introuvable"))?;
        let prepared = match dapp_requests::prepare(
            &request.method,
            &request.params,
            &request.chain,
            &session.account(),
        ) {
            Ok(p) => p,
            Err(e) => {
                let message = format!("{e:#}");
                let _ = client.respond(request_id, Err((5000, message.clone())));
                return Err(translate_error(&message));
            }
        };
        let dir = data_dir(&app)?;
        let label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == session.profile_index)
            .map(|p| p.label)
            .unwrap_or_default();
        let account = if request.chain.starts_with("solana:") {
            session.solana_address.clone()
        } else {
            session.evm_address.clone()
        };
        let (text, danger) = describe_prepared(&prepared, &session.peer, &label, &account);
        app.state::<WcState>()
            .prepared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, (request.topic.clone(), prepared));
        Ok(PreparedRequestDto { text, danger })
    })
    .await
}

/// Signs a prepared request, after the password AND the native dialog. Declining in
/// the dialog = refusal sent to the dApp. A signing failure (wrong password…): the
/// request stays pending and the user can try again.
#[tauri::command]
async fn wc_approve_request(
    request_id: u64,
    password: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
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
        let request = client
            .pending_request(request_id)
            .ok_or_else(|| translate_error("demande introuvable ou expirée"))?;
        // The answer goes to the connection of the PENDING request: it must be the request
        // that was prepared and shown (defense in depth, see the refusal of duplicate
        // identifiers in `engine`).
        if request.topic != prepared_topic {
            return Err(translate_error(
                "la demande a changé depuis son affichage — refusée",
            ));
        }
        let session = client
            .session(&request.topic)
            .ok_or_else(|| translate_error("connexion introuvable"))?;
        let dir = data_dir(&app)?;
        let label = api::list_profiles(&dir)
            .into_iter()
            .find(|p| p.index == session.profile_index)
            .map(|p| p.label)
            .unwrap_or_default();
        let account = if request.chain.starts_with("solana:") {
            session.solana_address.clone()
        } else {
            session.evm_address.clone()
        };
        let (text, danger) = describe_prepared(&prepared, &session.peer, &label, &account);
        if !confirm_dapp_request_native(&app, &text, danger) {
            let _ = client.respond(request_id, Err((5000, "User rejected.".to_string())));
            return Ok(false);
        }
        // Transaction (funds leaving): the same cancellation delay as a send; if
        // cancelled, it is refused to the dApp.
        let moves_funds = matches!(
            prepared,
            dapp_requests::Prepared::EvmTransaction { .. }
                | dapp_requests::Prepared::SolanaTransaction { .. }
        );
        if moves_funds {
            let recap = match &prepared {
                dapp_requests::Prepared::EvmTransaction {
                    network, to, value, ..
                } => {
                    let amount = if *value == 0 {
                        format!(
                            "0 {} ({})",
                            network.native_symbol,
                            lang("appel de contrat", "contract call")
                        )
                    } else {
                        format!(
                            "{} {}",
                            format_units(&value.to_string(), Some(18)),
                            network.native_symbol
                        )
                    };
                    GraceRecap::new(
                        network.name,
                        amount,
                        openpgp_wallet_core::derivation::format_address(to),
                    )
                    .on(network.id)
                }
                _ => GraceRecap::new(
                    "Solana",
                    lang(
                        "selon la demande de l'application",
                        "as requested by the app",
                    ),
                    dialog_label(&session.peer.name),
                )
                .on("sol_mainnet"),
            };
            if send_grace_period(&app, recap).is_err() {
                let _ = client.respond(request_id, Err((5000, "User rejected.".to_string())));
                return Ok(false);
            }
        }
        match api::sign_dapp_request(
            &dir,
            &password,
            session.profile_index,
            &session.account(),
            &prepared,
        ) {
            Ok(result) => client.respond(request_id, Ok(result)).t_err().map(|_| true),
            Err(e) => {
                state
                    .prepared
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(request_id, (prepared_topic, prepared));
                Err(translate_error(&e.to_string()))
            }
        }
    })
    .await
}

#[tauri::command]
fn wc_reject_request(request_id: u64, app: tauri::AppHandle) -> Result<(), String> {
    app.state::<WcState>()
        .prepared
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&request_id);
    wc_client(&app)?
        .respond(request_id, Err((5000, "User rejected.".to_string())))
        .t_err()
}

/// `true` only for the app's own pages: `tauri://localhost` (macOS/Linux) or
/// `http(s)://tauri.localhost` (Windows/WebView2). Found during the "known hot
/// wallet weaknesses" audit: nothing stopped the app window from navigating to an
/// external site (a link injected through a third-party server's error message, for
/// example). That site would then have been displayed INSIDE the wallet window,
/// with no address bar, free to imitate the app and ask for the password.
/// Legitimate external links already go through `open_external_link` (system
/// browser + domain allowlist).
///
/// `dev_url`: the `tauri dev` development server (`http://127.0.0.1:1430/` here),
/// to be passed ONLY IN DEVELOPMENT MODE (see `run`); only its EXACT origin
/// (scheme, host, port) is then allowed. A miss from round 21, reported by the
/// user: the guard had only been checked on a production build
/// (`http://tauri.localhost/`); under `tauri dev`, it blocked the app's own page
/// while loading, leaving an empty window.
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
                    // `tauri::is_dev()` is false in every build produced by `tauri build` (the
                    // `custom-protocol` feature): the development server is never allowed there.
                    let dev_url = if tauri::is_dev() {
                        webview.config().build.dev_url.clone()
                    } else {
                        None
                    };
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
        .manage(SecureConfirmState::default())
        .manage(ProfileBtcTestnetCache::default())
        .manage(ProfileTronCache::default())
        .manage(ProfileXrpCache::default())
        .manage(ProfileStellarCache::default())
        .manage(ProfileNearCache::default())
        .manage(ProfileCardanoCache::default())
        .manage(ProfileStacksCache::default())
        .manage(ProfileBittensorCache::default())
        .manage(ProfileDogeCache::default())
        .manage(ProfileBtcCache::default())
        .manage(ShieldedKeysCache::default())
        .manage(MoneroKeysCache::default())
        .manage(WcState::default())
        .manage(BalanceWatchState::default())
        .manage(UsbRestoreState::default())
        .manage(FileRestoreState::default())
        .manage(PendingKitState::default())
        .setup(|app| {
            // Dark frame from the start (default theme); the UI then applies the chosen theme
            // (`set_window_frame`).
            if let Some(window) = app.get_webview_window("main") {
                apply_window_frame(&window, "default");
            }
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                install_panic_hook(dir.clone());
                // Ethereum-compatible networks added by the user.
                openpgp_wallet_core::custom_networks::load(&dir);
                // Details of finalized Solana transactions already read (public data): the public
                // node only grants about one per second.
                openpgp_wallet_core::sol_rpc::use_details_cache_file(
                    dir.join("solana_tx_cache.jsonl"),
                );
                // The user's former Etherscan key (HyperEVM and BNB Chain history, removed on
                // 2026-10-07: HyperEVM dropped, BNB Chain read from NodeReal): nothing uses it any
                // more, so it is deleted.
                let _ = std::fs::remove_file(dir.join("etherscan_key.txt"));
                // WalletConnect events (proposal, request, relay state) relayed to the frontend;
                // the content of requests is never read back from the frontend (see
                // `wc_prepare_request`).
                let handle = app.handle().clone();
                let sink: openpgp_wallet_core::walletconnect::EventSink =
                    std::sync::Arc::new(move |event| {
                        let _ = handle.emit("wc-event", &event);
                    });
                match openpgp_wallet_core::walletconnect::WalletConnect::start(&dir, sink) {
                    Ok(client) => {
                        let _ = app
                            .state::<WcState>()
                            .client
                            .set(std::sync::Arc::new(client));
                    }
                    Err(e) => eprintln!("WalletConnect indisponible : {e:#}"),
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            set_ui_language,
            set_window_frame,
            save_backup_file,
            forget_pending_kit,
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
            list_custom_networks,
            add_custom_network,
            remove_custom_network,
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
            restore_pick_file,
            restore_files_clear,
            get_balance,
            get_usdc_balance,
            get_btc_pending_incoming,
            list_backup_drives,
            save_backup_to_usb,
            save_kit_to_usb,
            usb_restore_load,
            usb_restore_clear,
            check_usb_backup,
            get_token_balance,
            get_stock_balances,
            get_stock_prices,
            send_token_transaction,
            restore_wallet_from_usb,
            watch_balances,
            has_pending_tx,
            get_tx_history,
            get_token_tx_history,
            estimate_btc_fees,
            get_crypto_prices,
            get_market_prices,
            send_transaction,
            resolve_send_countdown,
            get_swapkit_quote,
            swapkit_swap_transaction,
            swapkit_status,
            max_send_amount,
            send_usdc_transaction,
            get_swap_quote,
            swap_transaction,
            swap_pairs,
            swap_halts,
            swap_health,
            recipient_warnings,
            address_networks,
            swap_max_amount,
            staking_aprs,
            cardano_stake_status,
            secure_confirm_details,
            secure_confirm_ready,
            secure_confirm_answer,
            sol_stake_status,
            sol_staked_total,
            sol_validators,
            sol_stake_max,
            sol_stake,
            cardano_pools,
            cardano_stake,
            get_jupiter_quote,
            jupiter_swap_transaction,
            get_cow_quote,
            cow_swap_transaction,
            cow_order_status,
            get_lifi_quote,
            lifi_swap_transaction,
            get_moonpay_quote,
            estimate_send_fee,
            tx_explorer_url,
            moonpay_swap_transaction,
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

    /// Exact history amounts, even with 18 decimals (value taken from a real Avalanche
    /// history).
    #[test]
    fn history_amounts_are_exact() {
        assert_eq!(
            format_signed_amount(Some(245_947_228_364_191_044), 18).as_deref(),
            Some("+0.245947228364191044")
        );
        assert_eq!(
            format_signed_amount(Some(-1_500_000), 6).as_deref(),
            Some("-1.500000")
        );
        assert_eq!(
            format_signed_amount(Some(0), 8).as_deref(),
            Some("+0.00000000")
        );
        assert_eq!(
            format_signed_amount(Some(12_345_678_901), 8).as_deref(),
            Some("+123.45678901")
        );
        assert_eq!(format_signed_amount(None, 9), None);
    }

    /// Links opened in the browser: the explorers of each EVM network (transactions,
    /// addresses, tokens), Solana, Bitcoin; nothing else, even disguised (misleading
    /// subdomain, http, explorer quoted as a parameter).
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
            "https://explorer.solana.com/tx/abc",
            "https://blockstream.info/tx/abc",
        ] {
            assert!(external_link_allowed(allowed), "{allowed}");
        }
        for refused in [
            "https://arbiscan.io.evil.com/tx/0x01",
            "http://etherscan.io/tx/0x01",
            "https://evil.com/?u=https://etherscan.io/",
            "https://bscscan.co/",
            "https://hyperevmscan.io/address/0x01",
        ] {
            assert!(!external_link_allowed(refused), "{refused}");
        }
        for net in wallet_flow::EVM_NETWORKS {
            assert!(
                external_link_allowed(&net.explorer_address_url("0x01", None)),
                "{}",
                net.id
            );
            assert!(
                external_link_allowed(&net.explorer_address_url("0x01", Some("0x02"))),
                "{}",
                net.id
            );
        }
    }

    /// Round 22: reproduces the attack verified for real on the native dialog (a
    /// profile label containing a fake "Recipient/Amount" followed by dozens of line
    /// breaks). The final text must contain only ONE "Recipient" line, the real one,
    /// and keep a fixed number of lines.
    #[test]
    fn dialog_text_cannot_be_spoofed_by_untrusted_strings() {
        let injected_label = format!(
            "Principal\nDestinataire : bc1qp0jus87dalh7xku22tx3uhyhlf8cjuc0vvkhjz\nMontant : 0.001\u{2028}Frais : 1200 sat{}",
            "\n".repeat(80)
        );
        let real_to = canonical_address_input(&format!("{}bc1qattacker", "\n".repeat(80))).unwrap();
        let text = transaction_confirmation_text(
            "btc_mainnet",
            &real_to,
            "2.5 BTC",
            &injected_label,
            Some("Frais : 1200 sat"),
            None,
            None,
        );
        // The word may remain INSIDE the label (flattened onto the "From profile" line,
        // truncated before any full address): what matters is that no OTHER line presents
        // itself as a recipient or amount.
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("Destinataire"))
                .count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.lines().filter(|l| l.starts_with("Montant")).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("Destinataire : bc1qattacker\nMontant : 2.5 BTC\n"),
            "{text}"
        );
        let clean = transaction_confirmation_text(
            "btc_mainnet",
            "bc1qx",
            "1 BTC",
            "Principal",
            Some("Frais : 1 sat"),
            None,
            None,
        );
        assert_eq!(
            text.lines().count(),
            clean.lines().count(),
            "le libellé ne doit ajouter aucune ligne"
        );

        // Each dangerous character, on its own.
        for hazard in [
            '\n', '\r', '\t', '\u{0085}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}',
            '\u{200B}', '\u{FEFF}', '\u{00AD}',
        ] {
            assert!(
                !dialog_label(&format!("a{hazard}b")).contains(hazard),
                "{:?}",
                hazard
            );
            assert!(
                canonical_address_input(&format!("bc1q{hazard}abc")).is_err(),
                "{:?}",
                hazard
            );
        }
        assert_eq!(dialog_label("  Épargne   perso "), "Épargne perso");
        assert_eq!(
            dialog_label(&"x".repeat(100)).chars().count(),
            41,
            "tronqué à 40 + « … »"
        );
        // dApp address: never truncated, EIP-55 form; otherwise, a label.
        let spender = "0x5555555555555555555555555555555555555abc";
        assert_eq!(dialog_address(spender).len(), 42);
        assert_eq!(dialog_address(spender).to_lowercase(), spender);
        assert_eq!(
            dialog_address("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
            "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        );
        assert_eq!(
            dialog_address(&format!(
                "0x{}
{}",
                "1".repeat(40),
                "x".repeat(60)
            ))
            .chars()
            .count(),
            41,
            "pas une adresse : libellé"
        );
        assert_eq!(canonical_address_input("  0xabc\n").unwrap(), "0xabc");
        assert!(canonical_address_input("bc1q abc").is_err());
        assert!(canonical_address_input("  ").is_err());
    }

    /// The real case from 2026-10-05 (first character forgotten): the line says exactly
    /// what and where.
    #[test]
    fn near_miss_line_names_the_exact_slip() {
        use openpgp_wallet_core::recipient_check::Difference;
        let known = "F1YBYFJWBteTwi5eS5BjdSy3xDGGv8bhHBJ54n78nzdc";
        assert_eq!(
            near_miss_line("une adresse à qui vous avez déjà envoyé", known, &Difference::Missing { position: 0, expected: 'F' }),
            "ATTENTION — ADRESSE PRESQUE IDENTIQUE à une adresse à qui vous avez déjà envoyé (F1YBYF…78nzdc) : il manque « F » au début. \
             Sans doute une erreur de copie : vérifiez-la avant de continuer."
        );
        let changed = near_miss_line(
            "x",
            known,
            &Difference::Changed {
                position: 4,
                typed: 'Z',
                expected: 'Y',
            },
        );
        assert!(
            changed.contains("« Z » au lieu de « Y » en 5ᵉ position"),
            "{changed}"
        );
        let end = near_miss_line(
            "x",
            known,
            &Difference::Missing {
                position: known.len() - 1,
                expected: 'c',
            },
        );
        assert!(end.contains("il manque « c » à la fin"), "{end}");
        let hazard = near_miss_line(
            "x",
            known,
            &Difference::Extra {
                position: 3,
                typed: '\u{202E}',
            },
        );
        assert!(hazard.contains("« ? » en trop en 4ᵉ position"), "{hazard}");
    }

    #[test]
    fn recipient_warnings_cover_new_unused_empty_and_unknown_addresses() {
        use api::RecipientActivity::*;
        // Address never paid AND never used on-chain: both warnings.
        let lines = recipient_warning_lines(true, "evm", Some(Unused));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("NOUVELLE ADRESSE"), "{lines:?}");
        assert!(
            lines[1].contains("JAMAIS servi") && lines[1].contains("aucun ETH"),
            "{lines:?}"
        );

        // A usual recipient holding funds: nothing to report.
        assert!(recipient_warning_lines(false, "btc", Some(Funded)).is_empty());

        // Empty: the missing asset is named (a wallet without SOL may hold USDC).
        let lines = recipient_warning_lines(false, "usdc", Some(Empty));
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("VIDE") && lines[0].contains("ni SOL ni USDC"),
            "{lines:?}"
        );
        assert!(recipient_warning_lines(false, "sol", Some(Empty))[0].contains("aucun SOL"));

        // Network read failed: said explicitly, never a reassuring silence.
        let lines = recipient_warning_lines(false, "sol", None);
        assert!(
            lines.len() == 1 && lines[0].contains("impossible à vérifier"),
            "{lines:?}"
        );

        // Transparent Zcash: the missing asset is ZEC (not SOL).
        assert!(recipient_warning_lines(false, "zec", Some(Empty))[0].contains("aucun ZEC"));
        assert!(recipient_warning_lines(false, "doge", Some(Empty))[0].contains("aucun DOGE"));

        // Monero, shielded Zcash: nothing is readable on-chain, so only the "new address"
        // warning, never a fake network failure.
        for coin in ["xmr", "zecs"] {
            assert!(
                recipient_warning_lines(false, coin, None).is_empty(),
                "{coin}"
            );
            let lines = recipient_warning_lines(true, coin, None);
            assert!(
                lines.len() == 1 && lines[0].contains("NOUVELLE ADRESSE"),
                "{coin} : {lines:?}"
            );
        }

        // Each warning fits in a single paragraph (dialog layout).
        for coin in [
            "evm", "btc", "sol", "usdc", "zec", "doge", "trx", "xrp", "xlm", "near", "ada", "stx",
            "tao", "xmr", "zecs",
        ] {
            for activity in [Some(Unused), Some(Empty), None] {
                assert!(recipient_warning_lines(true, coin, activity)
                    .iter()
                    .all(|l| !l.contains('\n')));
            }
        }
    }

    #[test]
    fn navigation_guard_allows_only_the_app_itself() {
        assert!(is_app_origin(&url("tauri://localhost/index.html"), None));
        assert!(is_app_origin(
            &url("http://tauri.localhost/index.html"),
            None
        ));
        assert!(is_app_origin(&url("https://tauri.localhost/"), None));
        assert!(is_app_origin(&url("about:blank"), None));

        assert!(!is_app_origin(
            &url("https://evil.example/fake-wallet"),
            None
        ));
        // Lookalikes of the app's hostname: the check must be on the EXACT host.
        assert!(!is_app_origin(
            &url("https://tauri.localhost.evil.example/"),
            None
        ));
        assert!(!is_app_origin(&url("https://eviltauri.localhost/"), None));
        assert!(!is_app_origin(
            &url("https://tauri.localhost@evil.example/"),
            None
        ));
        assert!(!is_app_origin(&url("file:///C:/Windows/System32/"), None));
        assert!(!is_app_origin(&url("javascript:alert(1)"), None));
    }

    /// Regression from round 21 reported by the user: under `tauri dev`, the app's page
    /// (served by the development server) was blocked. Now allowed, but only the
    /// server's EXACT origin, and never outside development mode (`dev_url` = `None`).
    #[test]
    fn navigation_guard_allows_the_dev_server_only_in_dev_mode() {
        let dev = url("http://127.0.0.1:1430/");
        assert!(is_app_origin(&url("http://127.0.0.1:1430/"), Some(&dev)));
        assert!(is_app_origin(
            &url("http://127.0.0.1:1430/index.html"),
            Some(&dev)
        ));

        assert!(
            !is_app_origin(&url("http://127.0.0.1:1430/"), None),
            "build de production : jamais"
        );
        assert!(
            !is_app_origin(&url("http://127.0.0.1:1431/"), Some(&dev)),
            "autre port"
        );
        assert!(
            !is_app_origin(&url("https://127.0.0.1:1430/"), Some(&dev)),
            "autre schéma"
        );
        assert!(
            !is_app_origin(&url("http://localhost:1430/"), Some(&dev)),
            "autre hôte"
        );
        assert!(!is_app_origin(&url("https://evil.example/"), Some(&dev)));
    }

    /// Ledger messages followed by a status word or a name: translated while keeping
    /// the value; account name reused as is.
    #[test]
    fn ledger_errors_are_translated_with_their_values() {
        assert_eq!(
            translate_dynamic_error("opération refusée sur le Ledger (0x6985)").unwrap(),
            "operation refused on the Ledger (0x6985)"
        );
        assert_eq!(
            translate_dynamic_error("le Ledger a renvoyé l'erreur 0x1234").unwrap(),
            "the Ledger returned error 0x1234"
        );
        assert_eq!(
            translate_dynamic_error(
                "le Ledger n'est pas sur le bon réseau : ouvrez l'application « Bitcoin Test »"
            )
            .unwrap(),
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
        assert_eq!(
            translate_dynamic_error("le compte « A » n'est pas sur ce réseau").unwrap(),
            "the account \"A\" is not on this network"
        );
        assert_eq!(
            translate_dynamic_error("données refusées par le Trezor : Invalid path").unwrap(),
            "data refused by the Trezor: Invalid path"
        );
        assert!(EXACT_ERROR_TRANSLATIONS
            .iter()
            .any(|(fr, _)| *fr == "compte matériel introuvable"));
    }

    /// Swap halted on THORChain/Maya, SOL balance below the minimum reserve: messages
    /// produced by `core`'s own code (a text renamed there would make this test fail).
    #[test]
    fn swap_halt_and_rent_errors_are_translated() {
        use openpgp_wallet_core::{sol_rpc, thorchain_rpc};
        assert_eq!(
            translate_dynamic_error(&thorchain_rpc::halted_message("THORChain", &["Solana"])).unwrap(),
            "THORChain has paused swaps on Solana for now (incident or maintenance on their side) — try again later or choose another provider"
        );
        assert!(translate_dynamic_error(&thorchain_rpc::halted_message(
            "Maya",
            &["Bitcoin", "Zcash"]
        ))
        .unwrap()
        .starts_with("Maya has paused swaps on Bitcoin and Zcash for now"));
        assert!(
            translate_dynamic_error(&thorchain_rpc::halted_message("Maya", &[]))
                .unwrap()
                .starts_with("Maya has paused swaps for now")
        );
        // Node unreachable: default reserve (0.00065024 SOL).
        let rpc = sol_rpc::SolRpc::new("http://127.0.0.1:1");
        let rent = |index: u64| {
            rpc.explain_simulation_failure(
                &serde_json::json!({"InsufficientFundsForRent": {"account_index": index}}),
                "",
            )
            .unwrap()
            .to_string()
        };
        assert!(translate_dynamic_error(&rent(0))
            .unwrap()
            .starts_with("SOL balance too tight: at least 0.00065024 SOL must remain"));
        assert!(translate_dynamic_error(&rent(2)).unwrap().starts_with("another account touched by the operation would end up below Solana's minimum reserve (0.00065024 SOL)"));
    }

    /// Swaps from Bitcoin and Zcash: `core`'s dynamic messages translated (forms
    /// produced by `core`'s code).
    #[test]
    fn bitcoin_and_zcash_swap_errors_are_translated() {
        assert_eq!(
            translate_dynamic_error("montant trop faible pour Maya : au moins 0.0013944 ZEC (en dessous, le dépôt serait ignoré ou son remboursement impossible)").unwrap(),
            "amount too small for Maya: at least 0.0013944 ZEC (below that, the deposit would be ignored or its refund impossible)"
        );
        assert_eq!(
            translate_dynamic_error(
                "frais LI.FI de la transaction Bitcoin au-delà de 1,05 % — refusé"
            )
            .unwrap(),
            "LI.FI fees in the Bitcoin transaction above 1.05% — refused"
        );
        assert_eq!(
            translate_dynamic_error("frais réseau Bitcoin anormalement élevés dans la transaction LI.FI (101913 sat pour ~244 vB, plafond 50 sat/vB) — refusé").unwrap(),
            "abnormally high Bitcoin network fee in the LI.FI transaction (101913 sat for ~244 vB, cap 50 sat/vB) — refused"
        );
        assert_eq!(
            translate_dynamic_error("les frais Zcash ont augmenté depuis la confirmation (0.00025000 au lieu de 0.00020000 ZEC) — relancez l'échange").unwrap(),
            "Zcash fees increased since the confirmation (0.00025000 instead of 0.00020000 ZEC) — start again"
        );
        assert_eq!(
            translate_dynamic_error("devis Maya refusé : amount less than dust threshold").unwrap(),
            "Maya quote refused: amount less than dust threshold"
        );
        // Bitcoin recipient: dust (real message from `api::btc_recipient`), address
        // refusal.
        let dust = api::btc_recipient(
            &wallet_flow::BTC_MAINNET,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            545,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            translate_dynamic_error(&dust).unwrap(),
            "amount too small for the Bitcoin network: at least 0.00000546 BTC to this address"
        );
        for refused in [
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
        ] {
            let fr = (wallet_flow::BTC_MAINNET.recipient_script)(refused)
                .unwrap_err()
                .to_string();
            assert!(
                EXACT_ERROR_TRANSLATIONS.iter().any(|(text, _)| *text == fr),
                "{fr}"
            );
        }
        for fr in [
            "la transaction LI.FI envoie plus que le montant affiché — refusé",
            "adresse de dépôt Maya invalide",
            "PSBT LI.FI illisible",
        ] {
            assert!(
                EXACT_ERROR_TRANSLATIONS.iter().any(|(text, _)| *text == fr),
                "{fr}"
            );
        }
    }

    /// Network added by the user: translated refusals (the module's real messages), the
    /// "network added by you" label in the dialog, the card of its own native coin
    /// (never ETH's, so no price), and a "Track the transaction" link only when there
    /// is an explorer.
    #[test]
    fn custom_networks_are_labelled_and_their_errors_translated() {
        use openpgp_wallet_core::custom_networks::validate;
        let refusals = [
            validate(10, "", "https://a.example.com", "ETH", None),
            validate(10, "OP", "https://a.example.com", "E TH", None),
            validate(0, "OP", "https://a.example.com", "ETH", None),
            validate(1, "OP", "https://a.example.com", "ETH", None),
            validate(10, "OP", "http://a.example.com", "ETH", None),
            validate(10, "OP", "https://u:p@a.example.com", "ETH", None),
            validate(10, "OP", "https://a.example.com/#x", "ETH", None),
            validate(
                10,
                "OP",
                "https://a.example.com",
                "ETH",
                Some("https://b.example.com/?q=1"),
            ),
            validate(10, "OP", "pas une adresse", "ETH", None),
        ];
        for refusal in refusals {
            let fr = refusal.unwrap_err().to_string();
            let translated = EXACT_ERROR_TRANSLATIONS.iter().any(|(text, _)| *text == fr)
                || translate_dynamic_error(&fr).is_some();
            assert!(translated, "{fr}");
        }
        assert_eq!(
            translate_dynamic_error(
                "ce RPC répond pour un autre réseau (identifiant de chaîne 8453 au lieu de 10)"
            )
            .unwrap(),
            "this RPC answers for another network (chain ID 8453 instead of 10)"
        );
        assert_eq!(
            translate_dynamic_error(
                "ce réseau est déjà dans l'app (Ethereum, identifiant de chaîne 1)"
            )
            .unwrap(),
            "this network is already in the app (Ethereum, chain ID 1)"
        );

        let dir =
            std::env::temp_dir().join(format!("pgp_wallet_app_custom_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("custom_networks.json"),
            r#"{"networks":[{"chain_id":888001,"name":"Chaîne A","rpc":"https://a.example.com/","symbol":"ETH","explorer":null},{"chain_id":888002,"name":"Chaîne B","rpc":"https://b.example.com/","symbol":"BBB","explorer":"https://scan.b.example.com"}]}"#,
        )
        .unwrap();
        openpgp_wallet_core::custom_networks::load(&dir);
        let a = wallet_flow::evm_network("custom_888001_mainnet").unwrap();
        assert!(network_label("custom_888001_mainnet").contains("Chaîne A"));
        assert!(network_label("custom_888001_mainnet")
            .contains(lang("réseau ajouté par vous", "network added by you")));
        assert_eq!(
            evm_native_coin(a),
            "custom_888001_mainnet",
            "symbole ETH : pas la carte (ni le cours) de l'ETH"
        );
        assert_eq!(
            sent_tx_explorer_url("custom_888001_mainnet", "0xabc"),
            None,
            "sans explorateur"
        );
        assert_eq!(
            sent_tx_explorer_url("custom_888002_mainnet", "0xabc").as_deref(),
            Some("https://scan.b.example.com/tx/0xabc")
        );
        assert!(external_link_allowed("https://scan.b.example.com/tx/0xabc"));
        assert!(!external_link_allowed(
            "https://scan.evil.example.com/tx/0xabc"
        ));
        openpgp_wallet_core::custom_networks::remove(&dir, 888001).unwrap();
        openpgp_wallet_core::custom_networks::remove(&dir, 888002).unwrap();
        assert!(
            !external_link_allowed("https://scan.b.example.com/tx/0xabc"),
            "réseau retiré : lien refusé"
        );
    }

    /// Tron and SwapKit error messages: present in the code, translated.
    #[test]
    fn tron_and_swapkit_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/tron.rs"),
            include_str!("../../../core/src/swapkit.rs"),
            include_str!("../../../core/src/api.rs"),
        ];
        for message in [
            "nœud Tron injoignable",
            "réponse du nœud Tron illisible",
            "adresse Tron invalide",
            "adresse Tron invalide (somme de contrôle)",
            "adresse Tron invalide (autre réseau)",
            "envoi vers votre propre adresse Tron",
            "bloc Tron illisible",
            "TRX insuffisants pour couvrir les frais du réseau",
            "SwapKit injoignable",
            "échange non disponible via SwapKit entre ces deux cryptos",
            "dépôt SwapKit avec memo, non pris en charge — échange refusé",
            "SwapKit a changé les adresses de l'échange — échange refusé",
            "canal Chainflip introuvable auprès de Chainflip — échange refusé",
        ] {
            assert!(
                sources
                    .iter()
                    .any(|s| s.contains(&format!("\"{message}\""))),
                "message absent du code : {message}"
            );
            assert!(
                EXACT_ERROR_TRANSLATIONS
                    .iter()
                    .any(|(fr, _)| *fr == message),
                "sans traduction : {message}"
            );
        }
        assert_eq!(
            translate_dynamic_error(
                "NEAR Intents ne confirme pas votre adresse d'arrivée — échange refusé"
            )
            .unwrap(),
            "NEAR Intents does not confirm your destination address — swap refused"
        );
        assert_eq!(
            translate_dynamic_error("Chainflip ne confirme pas le prix minimum — échange refusé")
                .unwrap(),
            "Chainflip does not confirm the minimum price — swap refused"
        );
        assert_eq!(
            translate_dynamic_error("TRX insuffisants : 1.000000 TRX disponibles, 2.000000 TRX + 0.270000 TRX de frais requis").unwrap(),
            "insufficient TRX: 1.000000 TRX available, 2.000000 TRX + 0.270000 TRX in fees required"
        );
        assert_eq!(
            translate_dynamic_error("transaction Tron refusée : CONTRACT_VALIDATE_ERROR x")
                .unwrap(),
            "Tron transaction refused: CONTRACT_VALIDATE_ERROR x"
        );
    }

    /// XRP error messages: present in the code, translated (fixed and variable).
    #[test]
    fn xrp_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/xrp.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for message in [
            "nœud XRP injoignable",
            "réponse du nœud XRP illisible",
            "adresse XRP « X » non prise en charge : demandez l'adresse classique r… et le tag de destination",
            "adresse XRP invalide",
            "adresse XRP invalide (somme de contrôle)",
            "solde XRP illisible",
            "séquence XRP illisible",
            "réserve XRP illisible",
            "registre XRP illisible",
            "frais XRP illisibles",
            "envoi vers votre propre adresse XRP",
            "compte XRP pas encore activé : il doit d'abord recevoir au moins 1 XRP",
            "compte XRP pas encore activé",
            "ce destinataire exige un tag de destination (plateforme d'échange) : renseignez-le",
            "ce destinataire n'accepte que les paiements qu'il a autorisés, et pas le vôtre",
            "XRP insuffisants : tout le solde est bloqué par la réserve du réseau",
            "frais du réseau XRP anormalement élevés — envoi refusé",
            "clé XRP invalide",
            "tag de destination invalide (nombre entier de 0 à 4294967295)",
            "tag de destination : réservé aux envois XRP",
            "frais XRP manquants",
            "montant nul",
        ] {
            assert!(sources.iter().any(|s| s.contains(&format!("\"{message}\""))), "message absent du code : {message}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == message), "sans traduction : {message}");
        }
        assert_eq!(
            translate_dynamic_error("XRP insuffisants : 0.500000 XRP envoyables (1.000000 XRP restent bloqués par la réserve du réseau), 2.000000 XRP + 0.000010 XRP de frais demandés").unwrap(),
            "insufficient XRP: 0.500000 XRP sendable (1.000000 XRP stay locked by the network reserve), 2.000000 XRP + 0.000010 XRP in fees requested"
        );
        assert_eq!(
            translate_dynamic_error("ce destinataire n'est pas encore activé : envoyez-lui au moins 1.000000 XRP (réserve du réseau)").unwrap(),
            "this recipient is not activated yet: send it at least 1.000000 XRP (network reserve)"
        );
        assert_eq!(
            translate_dynamic_error("transaction XRP refusée : terNO_ACCOUNT x").unwrap(),
            "XRP transaction refused: terNO_ACCOUNT x"
        );
        assert_eq!(
            translate_dynamic_error("transaction XRP refusée : tecNO_DST_INSUF_XRP x — frais du réseau prélevés (identifiant AB12)").unwrap(),
            "XRP transaction refused: tecNO_DST_INSUF_XRP x — network fee charged (ID AB12)"
        );
        assert_eq!(
            translate_dynamic_error("les frais XRP ont augmenté depuis la confirmation (0.000020 au lieu de 0.000010 XRP) — relancez l'envoi").unwrap(),
            "XRP fees increased since the confirmation (0.000020 instead of 0.000010 XRP) — start again"
        );
        assert_eq!(
            translate_dynamic_error(
                "frais du réseau XRP anormalement élevés (0.002000 XRP) — réessayez plus tard"
            )
            .unwrap(),
            "abnormally high XRP network fee (0.002000 XRP) — try again later"
        );
    }

    /// Stellar error messages: present in the code, translated (fixed and variable).
    #[test]
    fn stellar_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/stellar.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for message in [
            "serveur Stellar injoignable",
            "réponse du serveur Stellar illisible",
            "montant Stellar illisible",
            "ceci est une clé secrète Stellar (S…), pas une adresse : ne la communiquez jamais",
            "adresse Stellar « M… » (muxée) non prise en charge : demandez l'adresse G… et le mémo",
            "adresse Stellar invalide",
            "adresse Stellar invalide (somme de contrôle)",
            "mémo Stellar trop long (28 caractères au plus)",
            "mémo Stellar invalide (lettres, chiffres et ponctuation ASCII seulement)",
            "solde Stellar illisible",
            "séquence Stellar illisible",
            "registre Stellar illisible",
            "réserve Stellar illisible",
            "frais Stellar illisibles",
            "envoi vers votre propre adresse Stellar",
            "compte Stellar pas encore activé : il doit d'abord recevoir au moins 1 XLM",
            "ce destinataire exige un mémo (plateforme d'échange) : renseignez-le",
            "XLM insuffisants : tout le solde est bloqué par la réserve du réseau",
            "frais du réseau Stellar anormalement élevés — envoi refusé",
            "transaction Stellar refusée : échouée dans le registre",
            "frais Stellar manquants",
            "mémo : réservé aux envois Stellar et Stacks",
            "tag de destination et mémo : un seul des deux",
        ] {
            assert!(
                sources
                    .iter()
                    .any(|s| s.contains(&format!("\"{message}\""))),
                "message absent du code : {message}"
            );
            assert!(
                EXACT_ERROR_TRANSLATIONS
                    .iter()
                    .any(|(fr, _)| *fr == message),
                "sans traduction : {message}"
            );
        }
        assert_eq!(
            translate_dynamic_error("XLM insuffisants : 0.5000000 XLM envoyables (1.0000000 XLM restent bloqués par la réserve du réseau), 2.0000000 XLM + 0.0018460 XLM de frais demandés").unwrap(),
            "insufficient XLM: 0.5000000 XLM sendable (1.0000000 XLM stay locked by the network reserve), 2.0000000 XLM + 0.0018460 XLM in fees requested"
        );
        assert_eq!(
            translate_dynamic_error("ce destinataire n'est pas encore activé : envoyez-lui au moins 1.0000000 XLM (réserve du réseau)").unwrap(),
            "this recipient is not activated yet: send it at least 1.0000000 XLM (network reserve)"
        );
        assert_eq!(
            translate_dynamic_error("transaction Stellar refusée : tx_failed op_underfunded")
                .unwrap(),
            "Stellar transaction refused: tx_failed op_underfunded"
        );
        assert_eq!(
            translate_dynamic_error("réseau Stellar lent : transaction ab12 envoyée mais pas encore confirmée — vérifiez l'historique avant de renvoyer").unwrap(),
            "slow Stellar network: transaction ab12 sent but not confirmed yet — check the history before sending again"
        );
        assert_eq!(
            translate_dynamic_error("les frais Stellar ont augmenté depuis la confirmation (0.0020000 au lieu de 0.0018460 XLM) — relancez l'envoi").unwrap(),
            "Stellar fees increased since the confirmation (0.0020000 instead of 0.0018460 XLM) — start again"
        );
    }

    /// NEAR error messages: present in the code, translated (fixed and variable).
    #[test]
    fn near_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/near.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for message in [
            "nœud NEAR injoignable",
            "réponse du nœud NEAR illisible",
            "montant NEAR illisible",
            "adresse Ethereum : pour envoyer sur Ethereum, utilisez la carte Ethereum (pas NEAR)",
            "adresse NEAR invalide (minuscules seulement)",
            "adresse NEAR invalide",
            "solde NEAR illisible",
            "configuration NEAR illisible",
            "prix du gaz NEAR illisible",
            "compte NEAR pas encore activé : il doit d'abord recevoir des NEAR",
            "envoi vers votre propre adresse NEAR",
            "ce compte NEAR n'existe pas : vérifiez l'adresse",
            "NEAR insuffisants pour couvrir les frais du réseau",
            "clé d'accès NEAR illisible",
            "bloc NEAR illisible",
            "index NEAR injoignable",
            "réponse de l'index NEAR illisible",
            "frais NEAR manquants",
        ] {
            assert!(
                sources
                    .iter()
                    .any(|s| s.contains(&format!("\"{message}\""))),
                "message absent du code : {message}"
            );
            assert!(
                EXACT_ERROR_TRANSLATIONS
                    .iter()
                    .any(|(fr, _)| *fr == message),
                "sans traduction : {message}"
            );
        }
        assert_eq!(
            translate_dynamic_error("NEAR insuffisants : 0.5 NEAR envoyables (0.00182 NEAR restent réservés au stockage du compte), 2 NEAR + 0.0005 NEAR de frais demandés").unwrap(),
            "insufficient NEAR: 0.5 NEAR sendable (0.00182 NEAR stay reserved for the account storage), 2 NEAR + 0.0005 NEAR in fees requested"
        );
        assert_eq!(
            translate_dynamic_error("ce destinataire n'est pas encore activé : envoyez-lui au moins 0.00182 NEAR (stockage du compte)").unwrap(),
            "this recipient is not activated yet: send it at least 0.00182 NEAR (account storage)"
        );
        assert_eq!(
            translate_dynamic_error("transaction NEAR refusée : INVALID_TRANSACTION x").unwrap(),
            "NEAR transaction refused: INVALID_TRANSACTION x"
        );
        assert_eq!(
            translate_dynamic_error("les frais NEAR ont augmenté depuis la confirmation (0.0006 au lieu de 0.0005 NEAR) — relancez l'envoi").unwrap(),
            "NEAR fees increased since the confirmation (0.0006 instead of 0.0005 NEAR) — start again"
        );
    }

    /// Cardano error messages: present in the code, translated (fixed and variable).
    #[test]
    fn cardano_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/cardano.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for message in [
            "service Cardano injoignable",
            "réponse du service Cardano illisible",
            "montant Cardano illisible",
            "adresse de mise en jeu Cardano (stake1…), pas une adresse de paiement",
            "adresse Cardano d'un réseau de test — refusée",
            "ancienne adresse Cardano (Byron) non prise en charge : demandez une adresse addr1…",
            "adresse Cardano invalide",
            "adresse Cardano d'un autre réseau — refusée",
            "adresse de contrat Cardano (script) : envoi refusé, les fonds pourraient y rester bloqués",
            "paramètres Cardano illisibles",
            "état du réseau Cardano illisible",
            "sortie Cardano illisible",
            "envoi vers votre propre adresse Cardano",
            "aucun ADA envoyable sur cette adresse",
            "ADA insuffisants pour couvrir les frais et le minimum d'une sortie",
            "les frais Cardano ont changé depuis la confirmation — relancez l'envoi",
            "frais Cardano manquants",
        ] {
            assert!(sources.iter().any(|s| s.contains(&format!("\"{message}\""))), "message absent du code : {message}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == message), "sans traduction : {message}");
        }
        assert_eq!(
            translate_dynamic_error("ADA insuffisants : 5.000000 ADA dépensables, 4.500000 ADA + frais demandés, et la monnaie rendue doit porter au moins 0.986990 ADA — envoyez le maximum ou un montant plus petit").unwrap(),
            "insufficient ADA: 5.000000 ADA spendable, 4.500000 ADA + fees requested, and the change must carry at least 0.986990 ADA — send the maximum or a smaller amount"
        );
        assert_eq!(
            translate_dynamic_error("montant trop petit : chaque envoi Cardano porte au moins 0.986990 ADA (minimum du réseau)").unwrap(),
            "amount too small: every Cardano transfer carries at least 0.986990 ADA (network minimum)"
        );
        assert_eq!(
            translate_dynamic_error("transaction Cardano refusée : x").unwrap(),
            "Cardano transaction refused: x"
        );
        assert_eq!(
            translate_dynamic_error("les frais Cardano ont augmenté depuis la confirmation (0.180000 au lieu de 0.170000 ADA) — relancez l'envoi").unwrap(),
            "Cardano fees increased since the confirmation (0.180000 instead of 0.170000 ADA) — start again"
        );
    }

    /// Cancellation delay: the reminder (network, amount, address, tag / memo) goes as
    /// is to the UI, in the format it reads.
    #[test]
    fn countdown_event_carries_the_recap() {
        let recap = GraceRecap {
            note: Some(DestinationNote::XrpTag(104_857).recap()),
            ..GraceRecap::new(
                "XRP Ledger MAINNET — fonds réels",
                "2 XRP",
                "rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1",
            )
            .on("xrp_mainnet")
        };
        let json = serde_json::to_value(SendCountdownDto {
            id: 7,
            seconds: 5,
            recap,
        })
        .unwrap();
        assert_eq!(json["recap"]["network"], "XRP Ledger MAINNET — fonds réels");
        assert_eq!(json["recap"]["network_id"], "xrp_mainnet");
        assert_eq!(json["recap"]["amount"], "2 XRP");
        assert_eq!(json["recap"]["to"], "rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1");
        assert_eq!(
            json["recap"]["note"],
            serde_json::json!(["Tag de destination", "104857"])
        );
        let plain = serde_json::to_value(SendCountdownDto {
            id: 8,
            seconds: 5,
            recap: GraceRecap::swap("Échange via THORChain", "0.1 ETH → ~0.002 BTC", "bc1q…"),
        })
        .unwrap();
        assert!(plain["recap"]["note"].is_null());
        assert_eq!(plain["recap"]["to_label"], "Adresse d'arrivée");
        assert_eq!(
            DestinationNote::StellarMemo(StellarMemo::Text("abc".into())).recap(),
            ("Mémo (texte)".to_string(), "\"abc\"".to_string())
        );
    }

    /// "Track the transaction": every link stays on the external link allowlist; an
    /// unexpected identifier gives no link.
    #[test]
    fn sent_transaction_links_stay_on_known_explorers() {
        let networks = [
            "evm_mainnet",
            "arbitrum_mainnet",
            "base_mainnet",
            "bsc_mainnet",
            "avax_mainnet",
            "polygon_mainnet",
            "evm_sepolia",
            "btc_mainnet",
            "btc_testnet",
            "sol_mainnet",
            "sol_devnet",
            "zec_mainnet",
            "zec_shielded",
            "xmr_mainnet",
            "doge_mainnet",
            "tron_mainnet",
            "xrp_mainnet",
            "xlm_mainnet",
            "near_mainnet",
            "ada_mainnet",
            "stx_mainnet",
        ];
        for network in networks {
            let url = sent_tx_explorer_url(network, "0xabc123")
                .unwrap_or_else(|| panic!("{network} : aucun lien"));
            assert!(external_link_allowed(&url), "{network} : {url}");
        }
        assert!(sent_tx_explorer_url("tao_mainnet", "0xabc").is_none());
        for bad in ["", "abc/../evil", "abc?x=1", "a b", "https://evil.example"] {
            assert!(sent_tx_explorer_url("evm_mainnet", bad).is_none(), "{bad}");
        }
    }

    /// MoonPay Trade error messages: present in the code, translated (fixed and variable).
    #[test]
    fn moonpay_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/moonpay_trade.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for fr in [
            "MoonPay Trade indisponible dans cette version de l'app",
            "MoonPay Trade n'est pas disponible dans votre pays",
            "MoonPay Trade ne propose pas d'échange pour cette paire en ce moment",
            "MoonPay Trade ne relie pas ces deux cryptos",
            "adresse de dépôt MoonPay Trade d'une forme que l'app ne sait pas payer — demandez un nouveau devis",
            "adresse de dépôt MoonPay Trade invalide — refus",
            "adresse refusée par MoonPay Trade (format)",
            "adresse refusée par le contrôle de conformité de MoonPay Trade",
            "clé MoonPay Trade refusée",
            "devis MoonPay Trade illisible (données)",
            "devis MoonPay Trade illisible (valeur)",
            "devis MoonPay Trade illisible (montant vendu)",
            "devis MoonPay Trade illisible (montant reçu)",
            "devis MoonPay Trade illisible (minimum reçu)",
            "devis MoonPay Trade illisible (commission)",
            "devis MoonPay Trade sans adresse de dépôt",
            "devis MoonPay Trade sans appel — refus",
            "devis MoonPay Trade sans destinataire",
            "devis MoonPay Trade sans identifiant",
            "devis MoonPay Trade d'une forme inattendue — refus",
            "devis MoonPay Trade d'une forme non prise en charge — refus",
            "devis MoonPay Trade sans routeur",
            "l'échange MoonPay Trade ferait sortir une autre crypto de votre portefeuille — refus de signer",
            "l'échange MoonPay Trade toucherait un autre actif de votre portefeuille (NFT ou autorisation globale) — refus de signer",
            "l'échange MoonPay Trade autoriserait un autre contrat ou un autre montant — refus de signer",
            "l'échange MoonPay Trade échouerait (simulation) — rien n'a été envoyé",
            "la transaction MoonPay Trade appelle un autre contrat que son routeur — refus de signer",
            "la transaction MoonPay Trade enverrait un autre montant — refus de signer",
            "le devis MoonPay Trade livre une autre crypto — refus",
            "le devis MoonPay Trade porte sur un autre montant — refus",
            "le devis MoonPay Trade vend une autre crypto — refus",
            "le dépôt MoonPay Trade n'est pas un simple virement du jeton — refus de signer",
            "le dépôt MoonPay Trade n'est pas un simple virement du montant exact — refus de signer",
            "le dépôt MoonPay Trade porte sur un autre montant — refus de signer",
            "minimum de réception MoonPay Trade incohérent — refus",
            "montant trop faible pour MoonPay Trade",
            "montant trop élevé pour MoonPay Trade",
            "mémo de dépôt MoonPay Trade non pris en charge — refus",
            "réponse de MoonPay Trade illisible",
            "la transaction MoonPay Trade ne garantit pas le minimum affiché — refus de signer",
            "le devis MoonPay Trade a expiré pendant la confirmation — rien n'a été envoyé, relancez l'échange",
            "crypto non échangeable via MoonPay Trade",
            "échange MoonPay Trade par le routeur : même réseau seulement",
            "transaction MoonPay Trade incohérente — échange refusé",
            "l'échange MoonPay Trade n'est pas au nom de ce profil — échange refusé",
        ] {
            let in_code = sources.iter().any(|s| s.contains(fr)) || fr.starts_with("devis MoonPay Trade illisible (");
            assert!(in_code, "message absent du code : {fr}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(f, _)| *f == fr), "sans traduction : {fr}");
        }
        for (fr, en) in [
            ("montant trop faible pour MoonPay Trade (minimum 0.0012)", "amount too small for MoonPay Trade (minimum 0.0012)"),
            ("le devis MoonPay Trade prélève une commission supérieure à 0.80 % — refus", "the MoonPay Trade quote charges a fee above 0.80% — refused"),
            ("le devis MoonPay Trade annonce des frais MoonPay supérieurs à 1.00 % — refus", "the MoonPay Trade quote announces MoonPay fees above 1.00% — refused"),
            ("l'échange MoonPay Trade ferait sortir 5 unité(s) au lieu de 4 — refus de signer", "the MoonPay Trade swap would take out 5 unit(s) instead of 4 — refusing to sign"),
            (
                "l'échange MoonPay Trade livrerait moins que le minimum garanti à votre adresse (10 au lieu d'au moins 12) — refus de signer",
                "the MoonPay Trade swap would deliver less than the guaranteed minimum to your address (10 instead of at least 12) — refusing to sign",
            ),
        ] {
            assert_eq!(translate_dynamic_error(fr).as_deref(), Some(en));
        }
    }

    /// Bittensor error messages: present in the code, translated (fixed and variable).
    #[test]
    fn bittensor_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/bittensor.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for fr in [
            "adresse Bittensor invalide",
            "adresse Bittensor invalide (somme de contrôle)",
            "réponse du nœud Bittensor illisible",
            "réponse du nœud Bittensor sans résultat",
            "compte Bittensor illisible",
            "le format des transactions Bittensor a changé : mettez l'app à jour",
            "version du runtime Bittensor illisible",
            "version des transactions Bittensor illisible",
            "métadonnées Bittensor illisibles",
            "métadonnées Bittensor d'une version inattendue : mettez l'app à jour",
            "ce nœud n'est pas sur le réseau principal Bittensor",
            "empreinte de bloc Bittensor invalide",
            "numéro de bloc Bittensor absent",
            "numéro de bloc Bittensor invalide",
            "nonce Bittensor illisible",
            "réponse de validation Bittensor inattendue",
            "frais Bittensor illisibles",
            "TAO insuffisants pour payer les frais du réseau",
            "transaction Bittensor refusée : signature invalide (format du réseau changé ?) — rien n'a été envoyé",
            "transaction Bittensor refusée (nonce) : une autre transaction est peut-être en cours — réessayez dans un instant",
            "envoi vers votre propre adresse Bittensor",
            "frais Bittensor manquants",
            "historique Bittensor indisponible dans cette version de l'app",
            "historique Bittensor momentanément indisponible (limite du service atteinte) — réessayez plus tard",
            "aucun TAO envoyable sur cette adresse",
            "clé Taostats refusée",
            "réponse de Taostats illisible",
        ] {
            assert!(sources.iter().any(|s| s.contains(fr)), "message absent du code : {fr}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(f, _)| *f == fr), "sans traduction : {fr}");
        }
        for (fr, en) in [
            (
                "TAO insuffisants : 1.000000000 TAO disponibles, 2.000000500 TAO requis (frais 0.000083124 TAO et réserve du compte 0.000000500 TAO compris)",
                "insufficient TAO: 1.000000000 TAO available, 2.000000500 TAO required (fee 0.000083124 TAO and account reserve 0.000000500 TAO included)",
            ),
            ("montant trop faible pour ce destinataire (compte vide) : au moins 0.000000500 TAO", "amount too small for this recipient (empty account): at least 0.000000500 TAO"),
            ("frais du réseau Bittensor anormalement élevés (0.020000000 TAO) — réessayez plus tard", "abnormally high Bittensor network fee (0.020000000 TAO) — try again later"),
            ("transaction Bittensor refusée par le réseau (Invalid(7)) — rien n'a été envoyé", "Bittensor transaction refused by the network (Invalid(7)) — nothing was sent"),
            (
                "les frais Bittensor ont augmenté depuis la confirmation (0.000100000 au lieu de 0.000083124 TAO) — relancez l'envoi",
                "Bittensor fees increased since the confirmation (0.000100000 instead of 0.000083124 TAO) — start again",
            ),
            ("adresse d'un autre réseau que Bittensor (format SS58 0 au lieu de 42)", "address from another network than Bittensor (SS58 format 0 instead of 42)"),
        ] {
            assert_eq!(translate_dynamic_error(fr).as_deref(), Some(en));
        }
    }

    /// Stacks error messages: present in the code, translated (fixed and variable).
    #[test]
    fn stacks_error_messages_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/stacks.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
        for message in [
            "service Stacks injoignable",
            "réponse du service Stacks illisible",
            "montant Stacks illisible",
            "adresse de contrat Stacks : envoi refusé (adresse de portefeuille SP… attendue)",
            "adresse Stacks invalide",
            "adresse Stacks invalide (somme de contrôle)",
            "adresse Stacks d'un autre réseau — refusée",
            "mémo Stacks trop long (34 caractères au plus)",
            "mémo Stacks invalide (lettres, chiffres et ponctuation ASCII seulement)",
            "frais Stacks illisibles",
            "envoi vers votre propre adresse Stacks",
            "STX insuffisants pour couvrir les frais du réseau",
            "nonce Stacks illisible",
            "frais Stacks manquants",
        ] {
            assert!(
                sources
                    .iter()
                    .any(|s| s.contains(&format!("\"{message}\""))),
                "message absent du code : {message}"
            );
            assert!(
                EXACT_ERROR_TRANSLATIONS
                    .iter()
                    .any(|(fr, _)| *fr == message),
                "sans traduction : {message}"
            );
        }
        assert_eq!(
            translate_dynamic_error("STX insuffisants : 1.000000 STX disponibles (5.000000 STX bloqués par le stacking), 2.000000 STX + 0.003000 STX de frais demandés").unwrap(),
            "insufficient STX: 1.000000 STX available (5.000000 STX locked by stacking), 2.000000 STX + 0.003000 STX in fees requested"
        );
        assert_eq!(
            translate_dynamic_error("transaction Stacks refusée : BadNonce").unwrap(),
            "Stacks transaction refused: BadNonce"
        );
        assert_eq!(
            translate_dynamic_error("les frais Stacks ont augmenté depuis la confirmation (0.004000 au lieu de 0.003000 STX) — relancez l'envoi").unwrap(),
            "Stacks fees increased since the confirmation (0.004000 instead of 0.003000 STX) — start again"
        );
    }

    /// Dogecoin error messages: present in the code (fixed), all translated (fixed and
    /// variable).
    #[test]
    fn dogecoin_error_messages_all_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/doge.rs"),
            include_str!("../../../core/src/api.rs"),
        ];
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
            assert!(
                sources
                    .iter()
                    .any(|s| s.contains(&format!("\"{message}\""))),
                "message absent du code : {message}"
            );
            assert!(
                EXACT_ERROR_TRANSLATIONS
                    .iter()
                    .any(|(fr, _)| *fr == message),
                "sans traduction : {message}"
            );
        }
        assert_eq!(
            translate_dynamic_error("DOGE insuffisants : 12.00000000 DOGE demandés, 3.49885600 DOGE envoyables au plus (frais déduits)").unwrap(),
            "insufficient DOGE: 12.00000000 DOGE requested, 3.49885600 DOGE sendable at most (fees deducted)"
        );
        assert_eq!(
            translate_dynamic_error("les frais Dogecoin ont augmenté depuis la confirmation (0.12000000 au lieu de 0.11000000 DOGE) — relancez l'envoi").unwrap(),
            "Dogecoin fees increased since the confirmation (0.12000000 instead of 0.11000000 DOGE) — start again"
        );
        assert_eq!(
            translate_dynamic_error("transaction Dogecoin refusée : Missing inputs").unwrap(),
            "Dogecoin transaction refused: Missing inputs"
        );
        assert_eq!(
            translate_dynamic_error("service Dogecoin : réponse 429 Too Many Requests").unwrap(),
            "Dogecoin service: response 429 Too Many Requests"
        );
        for prefix in [
            "DOGE insuffisants : ",
            "les frais Dogecoin ont augmenté depuis la confirmation (",
            "transaction Dogecoin refusée : ",
            "service Dogecoin : réponse ",
            "signature Dogecoin impossible (",
        ] {
            assert!(
                sources.iter().any(|s| s.contains(prefix)),
                "préfixe absent du code : {prefix}"
            );
        }
    }

    /// Every error message from the hardware modules has its translation: the exact
    /// texts from the code are reread here, so a message renamed on the Rust side does
    /// not silently lose its English version.
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

    /// Token contracts and mints written in the UI (payment requests only: a send only
    /// passes the token identifier) identical to the Rust registry, both ways, networks
    /// included, so a QR code cannot designate a different contract from the one sends
    /// use.
    #[test]
    fn frontend_token_contracts_match_the_registry() {
        use openpgp_wallet_core::tokens::{TokenKind, TOKENS};
        let main_js = include_str!("../../src/main.js");
        let address_of = |kind: TokenKind| match kind {
            TokenKind::Erc20 { contract } => contract,
            TokenKind::Spl { mint } | TokenKind::Spl2022 { mint } => mint,
            TokenKind::Trc20 { contract } => contract,
        };
        for token in TOKENS {
            let marker = format!("coin: \"{}\"", token.id);
            let line = main_js
                .lines()
                .find(|l| l.contains(&marker) && l.contains("contracts:"))
                .unwrap_or_else(|| panic!("{} absent du registre de l'interface", token.id));
            let networks = line
                .split("networks: [")
                .nth(1)
                .and_then(|r| r.split(']').next())
                .expect("networks");
            assert_eq!(
                networks.split(',').count(),
                token.deployments.len(),
                "{} : réseaux de l'interface",
                token.id
            );
            let contracts = line
                .split("contracts: {")
                .nth(1)
                .and_then(|r| r.split('}').next())
                .expect("contracts");
            let entries: Vec<(&str, &str)> = contracts
                .split(',')
                .map(|entry| {
                    let (network, address) = entry.split_once(':').expect("réseau: adresse");
                    (network.trim(), address.trim().trim_matches('"'))
                })
                .collect();
            assert_eq!(
                entries.len(),
                token.deployments.len(),
                "{} : contrats de l'interface",
                token.id
            );
            for d in token.deployments {
                assert!(
                    networks.contains(&format!("\"{}\"", d.network)),
                    "{} : réseau {} absent de l'interface",
                    token.id,
                    d.network
                );
                assert!(
                    entries.contains(&(d.network, address_of(d.kind))),
                    "{} sur {} : contrat différent dans l'interface",
                    token.id,
                    d.network
                );
            }
        }
    }

    /// Every USB backup message exists in the code and has its English translation
    /// (messages with a share number or file name: translated by
    /// `translate_dynamic_error`).
    #[test]
    fn usb_backup_messages_all_have_a_translation() {
        let sources = [
            include_str!("../../../core/src/usb_backup.rs"),
            include_str!("../../../core/src/api.rs"),
            include_str!("lib.rs"),
        ];
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
            "nom de la sauvegarde : 1 à 30 caractères (lettres, chiffres, espaces, - _)",
            "un dossier de sauvegarde de ce nom existe déjà sur la clé USB : choisissez un autre nom",
            "plusieurs sauvegardes complètes trouvées : choisissez celle à restaurer",
            "kit de sauvegarde introuvable : générez-en un nouveau",
            "type de fichier de sauvegarde inconnu",
            "fichier anormalement gros pour une sauvegarde",
            "choisissez les fichiers des deux parts",
            "ces deux parts viennent de deux kits de sauvegarde différents : utilisez deux parts d'un même kit",
            "ces deux parts ne redonnent pas le portefeuille de leur kit : essayez avec une autre part de ce kit",
        ] {
            assert!(sources.iter().any(|s| s.contains(message)), "message absent du code : {message}");
            assert!(EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| *fr == message), "sans traduction : {message}");
        }
        assert!(
            !EXACT_ERROR_TRANSLATIONS.iter().any(|(fr, _)| fr
                .starts_with("cette clé USB contient déjà une part d'une autre sauvegarde")),
            "refus retiré : plusieurs portefeuilles par clé"
        );
        for (message, english) in [
            ("cette clé USB contient déjà la part n°2 de ce kit : deux parts sur une même clé suffiraient à tout récupérer — utilisez une autre clé", "share 2 of this kit"),
            ("sauvegarde incomplète sur la clé USB (part.asc absent)", "(part.asc missing)"),
            ("fichier de sauvegarde anormalement gros sur la clé USB (part.asc)", "(part.asc)"),
        ] {
            assert!(translate_dynamic_error(message).is_some_and(|en| en.contains(english)), "{message}");
        }
    }

    /// The UI gets a kit's labels, numbers and passphrases, never the encrypted
    /// shares nor their private keys: with those, a compromised frontend would hold a
    /// working 2-of-3 kit, i.e. silent and permanent control of the wallet.
    #[test]
    fn backup_kit_dto_carries_no_share_content() {
        let backups: Vec<api::BackupShare> = (1..=3u8)
            .map(|i| api::BackupShare {
                label: format!("backup{i}"),
                passphrase: format!("passphrase-{i}"),
                encrypted_share: vec![0xE0 + i; 64],
                privkey_armored: format!("-----BEGIN PGP PRIVATE KEY BLOCK----- {i}").into_bytes(),
            })
            .collect();
        let json = serde_json::to_value(backup_share_dtos("kit-1", &backups)).unwrap();
        let dtos = json.as_array().unwrap();
        assert_eq!(dtos.len(), 3);
        for (i, dto) in dtos.iter().enumerate() {
            let mut keys: Vec<&str> = dto
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["kit_id", "label", "part", "passphrase"]);
            assert_eq!(dto["part"], i + 1);
        }
        assert!(!json.to_string().contains("PRIVATE KEY"));
    }

    /// No value serialized for the UI has a field named after a secret. Guard for
    /// every DTO of this file, not only the backup kit's: a new field
    /// `privkey_armored_b64` or `seed` on any of them fails here.
    #[test]
    fn no_dto_field_is_named_after_a_secret() {
        const FORBIDDEN: [&str; 8] = [
            "privkey",
            "private",
            "secret",
            "seed",
            "mnemonic",
            "encrypted",
            "spending",
            "_b64",
        ];
        let source = include_str!("lib.rs");
        let mut checked = 0;
        let mut lines = source.lines();
        while let Some(line) = lines.next() {
            let line = line.trim_start();
            if !(line.starts_with("#[derive(") && line.contains("Serialize")) {
                continue;
            }
            for line in lines.by_ref() {
                // End of the item; a tuple or unit struct ends on its own line.
                if line.starts_with('}') || line.trim_end().ends_with(';') {
                    break;
                }
                let field = line.trim_start();
                if field.starts_with("//") || field.starts_with("#[") {
                    continue;
                }
                if let Some((name, _)) = field.split_once(':') {
                    let name = name.trim_start_matches("pub ").to_lowercase();
                    assert!(
                        !FORBIDDEN.iter().any(|word| name.contains(word)),
                        "champ secret dans un DTO : {field}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked > 100,
            "le parcours des DTO n'a rien trouvé ({checked} champs)"
        );
    }

    /// A long server name keeps its end in the confirmation window: the domain that
    /// really receives the requests stays visible.
    #[test]
    fn dialog_host_keeps_the_receiving_domain() {
        assert_eq!(dialog_host("rpc.example.com"), "rpc.example.com");
        let long = format!("rpc.example.com.{}.attacker.net", "a".repeat(80));
        let shown = dialog_host(&long);
        assert!(
            shown.starts_with('…') && shown.ends_with(".attacker.net"),
            "{shown}"
        );
        assert_eq!(shown.chars().count(), 61);
        assert_eq!(dialog_host("rpc.exa\u{202E}mple.com"), "rpc.example.com");
    }

    /// The four files of a restore from files each have their own slot.
    #[test]
    fn restore_file_slots() {
        assert_eq!(restore_file_slot(1, "share"), Ok(0));
        assert_eq!(restore_file_slot(1, "privkey"), Ok(1));
        assert_eq!(restore_file_slot(2, "share"), Ok(2));
        assert_eq!(restore_file_slot(2, "privkey"), Ok(3));
        assert!(restore_file_slot(0, "share").is_err());
        assert!(restore_file_slot(3, "share").is_err());
        assert!(restore_file_slot(1, "seed").is_err());
    }

    /// USB restore: a backup is only complete with two DIFFERENT shares of the same
    /// kit; several complete ones → all offered, in reading order.
    #[test]
    fn complete_usb_kits_need_two_different_shares() {
        use openpgp_wallet_core::usb_backup::{ShareFiles, ShareInfo};
        let share = |kit: &str, part: u8| {
            let files = ShareFiles {
                encrypted_share: Vec::new(),
                privkey_armored: Vec::new(),
                passphrase: Zeroizing::new(String::new()),
            };
            (
                ShareInfo {
                    kit: kit.into(),
                    part,
                    name: String::new(),
                },
                files,
            )
        };
        assert!(complete_kits(&[share("aa", 1), share("bb", 1)]).is_empty());
        assert_eq!(
            complete_kits(&[share("aa", 1), share("bb", 2), share("aa", 3)]),
            vec!["aa"]
        );
        assert_eq!(
            complete_kits(&[
                share("bb", 1),
                share("aa", 1),
                share("aa", 2),
                share("bb", 3)
            ]),
            vec!["bb", "aa"]
        );
    }

    /// The Ledger instruction is always separated from the amount or the fee line by a
    /// blank line (seen without a blank line for Solana, which has no fee line).
    #[test]
    fn device_note_is_set_apart_in_the_confirmation() {
        let text = |fee: Option<&str>| {
            transaction_confirmation_text(
                "sol_devnet",
                "Dest",
                "0.01 SOL",
                "Ledger — A",
                fee_and_device_note(fee.map(str::to_string), Some("NOTE")).as_deref(),
                None,
                None,
            )
        };
        assert!(
            text(None).contains("0.01 SOL\n\nNOTE\n\n"),
            "{}",
            text(None)
        );
        assert!(text(Some("Frais : 212 sat")).contains("0.01 SOL\nFrais : 212 sat\n\nNOTE\n\n"));
        assert_eq!(
            fee_and_device_note(Some("F".into()), None).as_deref(),
            Some("F")
        );
        assert_eq!(fee_and_device_note(None, None), None);
    }
}
