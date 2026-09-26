const { invoke } = window.__TAURI__.core;

// --- Thème -----------------------------------------------------------------
// Préférence purement visuelle par appareil (pas une donnée du wallet) : stockage
// local suffit, pas besoin de passer par le coffre chiffré. `try/catch` seul
// (localStorage peut être bloqué selon la configuration) : le thème par défaut
// s'applique alors sans jamais faire planter l'app.
const THEME_STORAGE_KEY = "pgp-wallet-theme";
const VALID_THEMES = ["default", "purple", "orange", "dark"];

// Changer `data-theme` sur <html> invalide le style de TOUTE la page (les
// variables CSS sont héritées partout) et force un recalcul complet. Choisir
// plusieurs thèmes coup sur coup dans le menu déroulant déclenchait donc une
// rafale de recalculs de page consécutifs, plus vite que le moteur de rendu ne
// pouvait les absorber — regroupés ici via `requestAnimationFrame` : si
// plusieurs appels arrivent avant la prochaine image, seul le dernier choisi
// est réellement appliqué, une seule fois.
let pendingThemeFrame = null;

function applyTheme(theme) {
  if (pendingThemeFrame !== null) cancelAnimationFrame(pendingThemeFrame);
  pendingThemeFrame = requestAnimationFrame(() => {
    pendingThemeFrame = null;
    if (VALID_THEMES.includes(theme) && theme !== "default") {
      document.documentElement.dataset.theme = theme;
    } else {
      delete document.documentElement.dataset.theme;
    }
  });
}

let currentTheme = "default";
try {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (VALID_THEMES.includes(saved)) currentTheme = saved;
} catch (e) {
  // localStorage indisponible : reste sur le thème par défaut.
}
applyTheme(currentTheme);

const themeSelect = document.getElementById("theme-select");
themeSelect.value = currentTheme;
themeSelect.addEventListener("change", () => {
  const next = themeSelect.value;
  applyTheme(next);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch (e) {
    // Best-effort : le thème reste actif pour cette session même si la sauvegarde échoue.
  }
});

// Même préférence purement visuelle que le thème ci-dessus (stockage local
// suffit). `applyRoundedButtons` cible directement `<html>` (voir styles.css :
// `:root[data-rounded-buttons="true"] button`), une seule règle CSS qui couvre
// tous les boutons de l'app puisqu'ils sont tous de vrais éléments `<button>`.
const ROUNDED_BUTTONS_STORAGE_KEY = "pgp-wallet-rounded-buttons";

function applyRoundedButtons(enabled) {
  if (enabled) {
    document.documentElement.dataset.roundedButtons = "true";
  } else {
    delete document.documentElement.dataset.roundedButtons;
  }
}

let roundedButtonsEnabled = false;
try {
  roundedButtonsEnabled = localStorage.getItem(ROUNDED_BUTTONS_STORAGE_KEY) === "true";
} catch (e) {
  // localStorage indisponible : reste sur des boutons non arrondis par défaut.
}
applyRoundedButtons(roundedButtonsEnabled);

const roundedButtonsToggle = document.getElementById("rounded-buttons-toggle");
roundedButtonsToggle.checked = roundedButtonsEnabled;
roundedButtonsToggle.addEventListener("change", () => {
  const enabled = roundedButtonsToggle.checked;
  applyRoundedButtons(enabled);
  try {
    localStorage.setItem(ROUNDED_BUTTONS_STORAGE_KEY, String(enabled));
  } catch (e) {
    // Best-effort : le réglage reste actif pour cette session même si la sauvegarde échoue.
  }
});

// Vue liste du portefeuille : même préférence purement visuelle/locale que les
// deux précédentes. `applyWalletListView` cible `<html>` (voir styles.css :
// `:root[data-wallet-list-view="true"] .wallet-card`) — du CSS pur, aucun
// changement de structure DOM, donc aucun autre code (refresh/historique/envoi)
// n'a besoin de savoir dans quel mode d'affichage il tourne.
const WALLET_LIST_VIEW_STORAGE_KEY = "pgp-wallet-list-view";

function applyWalletListView(enabled) {
  if (enabled) {
    document.documentElement.dataset.walletListView = "true";
  } else {
    delete document.documentElement.dataset.walletListView;
  }
}

let walletListViewEnabled = false;
try {
  walletListViewEnabled = localStorage.getItem(WALLET_LIST_VIEW_STORAGE_KEY) === "true";
} catch (e) {
  // localStorage indisponible : reste en vue cartes par défaut.
}
applyWalletListView(walletListViewEnabled);

const walletListViewToggle = document.getElementById("wallet-list-view-toggle");
walletListViewToggle.checked = walletListViewEnabled;
walletListViewToggle.addEventListener("change", () => {
  const enabled = walletListViewToggle.checked;
  applyWalletListView(enabled);
  try {
    localStorage.setItem(WALLET_LIST_VIEW_STORAGE_KEY, String(enabled));
  } catch (e) {
    // Best-effort : le réglage reste actif pour cette session même si la sauvegarde échoue.
  }
});

// --- Langue ------------------------------------------------------------------
// Préférence purement visuelle par appareil (comme le thème ci-dessus) : stockage
// local suffit. Ne traduit que le frontend (HTML statique + messages générés en
// JS) — les messages d'erreur renvoyés depuis le backend Rust (via `invoke()`)
// restent en français quelle que soit la langue choisie ici, les traduire
// nécessiterait de faire remonter un paramètre de langue jusqu'au backend.
const LANG_STORAGE_KEY = "pgp-wallet-lang";
const VALID_LANGS = ["fr", "en"];

const I18N = {
  fr: {
    "loading.text": "Chargement…",
    "onboarding.title": "Créer votre portefeuille",
    "onboarding.subtitle":
      "Choisissez un mot de passe pour cet appareil. Il vous servira à ouvrir votre portefeuille et à valider chaque virement — comme un cadenas, sans que vous ayez jamais à voir la clé qu'il y a derrière.",
    "onboarding.passwordLabel": "Mot de passe",
    "onboarding.confirmLabel": "Confirmation",
    "onboarding.confirmPlaceholder": "Retapez le mot de passe",
    "onboarding.submit": "Créer mon portefeuille",
    "common.minChars": "Au moins 12 caractères",
    "common.cancel": "Annuler",
    "common.add": "Ajouter",
    "common.copy": "Copier",
    "common.clear": "Effacer",
    "common.close": "Fermer",
    "common.create": "Créer",
    "common.busy": "Patientez…",
    "common.passwordMinLength": "Le mot de passe doit faire au moins {min} caractères.",
    "common.passwordHint": "Au moins {min} caractères, mélange de types recommandé.",
    "common.strengthWeak": "Force : faible",
    "common.strengthMedium": "Force : moyenne",
    "common.strengthGood": "Force : bonne",
    "common.passwordTooWeak":
      "Ce mot de passe est trop faible ou trop prévisible — essayez un mélange de lettres, chiffres et symboles.",
    "common.passwordsMismatch": "Les deux mots de passe ne correspondent pas.",
    "common.passwordRequired": "Mot de passe requis.",
    "common.saveFailed": "Échec de l'enregistrement : {err}",
    "common.error": "Erreur : {err}",
    "common.copyFailed": "Copie impossible : {err}",
    "common.copied": "Copié !",
    "backup.title": "Sauvegardez votre kit de récupération",
    "backup.subtitle":
      "Ces 3 fichiers protègent votre portefeuille en cas de perte de cet appareil. <strong>2 des 3 suffisent</strong> à tout récupérer, mais aucun des 3 seul ne sert à rien — c'est voulu, personne (y compris vous) ne peut voler votre wallet avec une seule part. Téléchargez les 3 et notez les 3 mots de passe quelque part de sûr, séparément.",
    "backup.confirmCheckbox": "J'ai téléchargé et sauvegardé mes 3 parts et leurs mots de passe",
    "backup.continue": "Continuer vers mon portefeuille",
    "backup.partTitle": "Part {n} — {label}",
    "backup.partPassword": "Mot de passe de cette part :",
    "backup.downloadShare": "Télécharger le fichier de part",
    "backup.downloadPrivkey": "Télécharger la clé privée",
    "unlock.title": "Portefeuille verrouillé",
    "unlock.biometricButton": "Déverrouiller avec Windows Hello",
    "unlock.orPassword": "ou",
    "unlock.passwordPlaceholder": "Votre mot de passe",
    "unlock.submit": "Déverrouiller",
    "unlock.gotoRestore": "Restaurer depuis une sauvegarde",
    "unlock.resetWallet": "Réinitialiser cet appareil (supprime le coffre local)",
    "restore.title": "Restaurer depuis une sauvegarde",
    "restore.subtitle":
      "Fournissez 2 des 3 fichiers de part + leur mot de passe, et choisissez un nouveau mot de passe pour cet appareil.",
    "restore.share1": "Part n°1",
    "restore.share2": "Part n°2",
    "restore.shareFile": "Fichier de part (.asc)",
    "restore.privkeyFile": "Fichier de clé privée (.asc)",
    "restore.sharePassword": "Mot de passe de cette part",
    "restore.newPasswordLabel": "Nouveau mot de passe pour cet appareil",
    "restore.submit": "Restaurer",
    "restore.filesRequired": "Les 4 fichiers (2 parts + 2 clés privées) sont requis.",
    "nav.wallet": "Portefeuille",
    "nav.history": "Historique",
    "nav.message": "Message",
    "nav.certificate": "Certificat",
    "nav.external": "Wallets externes",
    "nav.addressBook": "Carnet d'adresses",
    "nav.settings": "Paramètres",
    "nav.lock": "Verrouiller",
    "external.title": "Wallets externes",
    "external.subtitle":
      "Suivez le solde d'adresses qui ne vous appartiennent pas — collez juste une adresse publique. Lecture seule : aucune clé privée n'est jamais impliquée. Regroupez plusieurs wallets pour additionner leur valeur.",
    "external.addWallet": "+ Ajouter un wallet externe",
    "external.addGroup": "+ Nouveau groupe",
    "external.refresh": "Actualiser",
    "external.addWalletTitle": "Ajouter un wallet externe",
    "external.label": "Nom (pour vous y retrouver)",
    "external.network": "Réseau",
    "external.netEvmMainnet": "Ethereum — Mainnet",
    "external.netEvmSepolia": "Ethereum — Sepolia (testnet)",
    "external.netBtcMainnet": "Bitcoin — Mainnet",
    "external.netBtcTestnet": "Bitcoin — Testnet",
    "external.netSolMainnet": "Solana — Mainnet",
    "external.netSolDevnet": "Solana — Devnet",
    "external.netUsdcSolana": "USDC — Solana (Mainnet)",
    "external.address": "Adresse",
    "external.group": "Groupe (optionnel)",
    "external.noGroup": "Aucun groupe",
    "external.add": "Ajouter",
    "external.addGroupTitle": "Nouveau groupe",
    "external.groupName": "Nom du groupe",
    "external.empty": "Aucun wallet externe pour l'instant — ajoutez-en un avec le bouton ci-dessus.",
    "external.groupEmpty": "Aucun wallet dans ce groupe.",
    "external.ungrouped": "Non groupés",
    "external.deleteGroup": "Supprimer le groupe",
    "external.remove": "Retirer",
    "external.labelAndAddressRequired": "Le nom et l'adresse sont requis.",
    "external.groupNameRequired": "Le nom du groupe est requis.",
    "addressBook.title": "Carnet d'adresses",
    "addressBook.subtitle":
      "Enregistrez une adresse sous un nom pour la retrouver rapidement au moment d'envoyer des fonds, sans avoir à la recopier à chaque fois.",
    "addressBook.addEntry": "+ Ajouter une adresse",
    "addressBook.addTitle": "Ajouter une adresse",
    "addressBook.label": "Nom (pour vous y retrouver)",
    "addressBook.network": "Réseau",
    "addressBook.address": "Adresse",
    "addressBook.add": "Ajouter",
    "addressBook.remove": "Supprimer",
    "addressBook.empty": "Aucune adresse enregistrée pour l'instant — ajoutez-en une avec le bouton ci-dessus.",
    "addressBook.pickPlaceholder": "— Choisir depuis le carnet d'adresses —",
    "nav.walletconnect": "Applications",
    "wc.title": "Applications connectées (WalletConnect)",
    "wc.subtitle": "Connectez ce portefeuille à un site (dApp) : sur le site, choisissez WalletConnect, copiez le lien de connexion (« wc:… ») et collez-le ici. Chaque signature demandée par un site exigera votre mot de passe et une confirmation de Windows.",
    "wc.uriLabel": "Lien de connexion",
    "wc.pair": "Se connecter",
    "wc.pairing": "En attente de la demande du site…",
    "wc.sessions": "Sites connectés",
    "wc.noSession": "Aucun site connecté.",
    "wc.disconnect": "Déconnecter",
    "wc.relayConnected": "Relais WalletConnect : connecté.",
    "wc.relayDisconnected": "Relais WalletConnect : déconnecté.",
    "wc.proposalTitle": "Demande de connexion",
    "wc.unverified": "Nom et adresse déclarés par le site lui-même : rien n'est vérifié. Ne connectez que des sites ouverts depuis leur vraie adresse.",
    "wc.networks": "Réseaux : {chains}",
    "wc.profile": "Profil à connecter",
    "wc.noProfile": "Déverrouillez le portefeuille avec votre mot de passe pour connecter un site.",
    "wc.approve": "Connecter",
    "wc.reject": "Refuser",
    "wc.requestTitle": "Demande de signature",
    "wc.analyzing": "Analyse de la demande…",
    "wc.danger": "Cette demande comporte un avertissement grave : lisez-la entièrement avant de décider.",
    "wc.sign": "Signer",
    "wc.expires": "expire le {date}",
    "wallet.profile": "Profil",
    "wallet.receive": "Recevoir",
    "wallet.receiveEth": "Recevoir ETH",
    "wallet.receiveBtc": "Recevoir BTC",
    "wallet.receiveSol": "Recevoir SOL",
    "wallet.newProfile": "+ Nouveau profil",
    "wallet.archiveProfile": "Archiver ce profil",
    "wallet.cannotArchiveLastProfile": "Impossible d'archiver le dernier profil actif restant.",
    "wallet.archiveConfirm":
      "Archiver le profil \"{label}\" ? Il disparaîtra du sélecteur mais restera récupérable à tout moment depuis Paramètres → Profils archivés.",
    "wallet.mainnet": "Mainnet — Fonds réels",
    "wallet.sepolia": "Sepolia (testnet)",
    "wallet.testnet": "Testnet",
    "wallet.devnet": "Devnet",
    "wallet.refresh": "Actualiser",
    "wallet.send": "Envoyer",
    "wallet.swap": "Échanger",
    "wallet.pendingBadge": "⏳ Transaction en attente détectée",
    "wallet.marketsTitle": "Prix des cryptomonnaies en direct",
    "wallet.showQr": "Afficher en QR code",
    "wallet.copyAddress": "Copier l'adresse",
    "wallet.addressCopied": "Adresse copiée !",
    "wallet.marketsLoadError": "Impossible de charger les données de marché.",
    "wallet.qrError": "Impossible de générer le QR code : {err}",
    "wallet.linkError": "Impossible d'ouvrir le lien : {err}",
    "wallet.noArchivedProfile": "Aucun profil archivé.",
    "wallet.restoreProfile": "Restaurer",
    "wallet.deleteProfileForever": "Supprimer définitivement",
    "history.subtitle":
      "Triées par réseau, dans le réseau actuellement sélectionné pour chaque carte du portefeuille (mainnet ou testnet).",
    "history.ethereum": "Ethereum",
    "history.bitcoin": "Bitcoin",
    "history.solana": "Solana",
    "history.kindReceived": "Reçu",
    "history.kindSent": "Envoyé",
    "history.kindSwap": "Swap",
    "history.kindOther": "Autre",
    "history.usdAtTime": "Valeur en dollars au moment de la transaction",
    "wallet.historyLoading": "Chargement…",
    "wallet.historyAddressUnavailable":
      "Adresse pas encore disponible pour ce profil — déverrouillez le portefeuille une fois pour la faire apparaître.",
    "wallet.historyEmpty": "Aucune transaction pour cette adresse.",
    "wallet.historyViewLink": "Voir ↗",
    "wallet.historyConfirmed": "Confirmée",
    "wallet.historyPending": "En attente",
    "wallet.historyFailed": "Échouée",
    "wallet.feeCalculating": "Calcul des frais…",
    "wallet.feeAddressUnavailable": "Adresse indisponible.",
    "wallet.feeUnavailable": "Frais indisponibles : {err}",
    "wallet.feeFast": "Rapide",
    "wallet.feeFastHint": "~10 min",
    "wallet.feeMedium": "Moyen",
    "wallet.feeMediumHint": "~30 min",
    "wallet.feeSlow": "Lent",
    "wallet.feeSlowHint": "~1 h",
    "wallet.btcFeesNotLoaded": "Frais Bitcoin non chargés — patiente un instant ou réessaie.",
    "wallet.allFieldsRequired": "Tous les champs sont requis.",
    "wallet.balanceError": "erreur",
    "message.title": "Chiffrer un message",
    "message.subtitle":
      "L'usage d'origine de PGP, avant qu'on le détourne ici pour protéger une seed : chiffrer un message pour que seul le destinataire puisse le lire.",
    "message.recipientsTitle": "Destinataires",
    "message.addRecipient": "Ajouter un destinataire",
    "message.name": "Nom",
    "message.namePlaceholder": "ex: Alice",
    "message.theirPubkey": "Sa clé publique PGP (ASCII-armor)",
    "message.messageTitle": "Message",
    "message.recipientsPickerLabel": "Destinataires (un ou plusieurs)",
    "message.plaintextLabel": "Message en clair",
    "message.plaintextPlaceholder": "Votre message...",
    "message.encrypt": "Chiffrer",
    "message.encryptedResultLabel": "Message chiffré (à copier/envoyer)",
    "message.decryptTitle": "Déchiffrer un message reçu",
    "message.decryptSubtitle":
      "Collez ici un message chiffré avec votre clé publique (celle de l'onglet Certificat) — vous seul pouvez le lire.",
    "message.encryptedMessageLabel": "Message chiffré",
    "message.passwordToUnlock": "Mot de passe (pour déverrouiller votre clé)",
    "message.decrypt": "Déchiffrer",
    "message.decryptedMessageLabel": "Message déchiffré",
    "message.noRecipientYet": "Aucun destinataire pour l'instant.",
    "message.addRecipientFirst": "Ajoutez d'abord un destinataire ci-dessus.",
    "message.nameAndPubkeyRequired": "Nom et clé publique requis.",
    "message.chooseAtLeastOneRecipient": "Choisissez au moins un destinataire (ajoutez-en un si la liste est vide).",
    "message.cannotBeEmpty": "Le message ne peut pas être vide.",
    "message.encryptedAndPasswordRequired": "Message chiffré et mot de passe requis.",
    "message.removeRecipient": "Supprimer",
    "recipientKey.view": "Consulter la clé",
    "recipientKey.title": "Clé publique du destinataire",
    "recipientKey.copy": "Copier cette clé publique",
    "certificate.title": "Votre certificat PGP",
    "certificate.subtitle":
      "C'est votre clé publique — partagez-la avec quelqu'un pour qu'il puisse vous ajouter comme destinataire et vous envoyer des messages chiffrés que vous seul pouvez lire.",
    "certificate.identity": "Identité",
    "certificate.fingerprint": "Empreinte (fingerprint)",
    "certificate.keyId": "Identifiant de clé",
    "certificate.fullKey": "Clé publique complète (ASCII-armor)",
    "certificate.copy": "Copier ma clé publique",
    "settings.appearance": "Apparence",
    "settings.theme": "Thème",
    "settings.blue": "Bleu",
    "settings.purple": "Violet",
    "settings.orange": "Orange",
    "settings.dark": "Sombre",
    "settings.roundedButtons": "Boutons arrondis",
    "settings.walletListView": "Affichage compact (liste) du portefeuille",
    "settings.archivedProfiles": "Profils archivés",
    "settings.archivedProfilesHint":
      "Un profil archivé disparaît du sélecteur principal mais reste entièrement récupérable — rien n'est perdu tant qu'il apparaît ici.",
    "settings.backup": "Sauvegarde",
    "settings.regenerateBackup": "Régénérer mon kit de sauvegarde",
    "settings.regenerateBackupHint":
      "Si vous avez perdu un ou plusieurs de vos 3 fichiers de sauvegarde d'origine, générez-en un nouveau jeu de 3 (mot de passe requis). Vos adresses ne changent pas.",
    "settings.thorTitle": "Adresse THOR (frais de swap)",
    "settings.thorHint":
      "Adresse THORChain dérivée de votre clé maîtresse — lecture seule, aucune fonction d'envoi ni de solde RUNE dans cette version. Sert uniquement de référence pour la fonctionnalité d'échange (swap).",
    "settings.thorShow": "Afficher l'adresse",
    "settings.deviceSecurity": "Sécurité de l'appareil",
    "settings.biometricTitle": "Déverrouillage biométrique",
    "settings.biometricHint":
      "Active Windows Hello (empreinte, visage ou code confidentiel) comme moyen rapide de déverrouiller ce portefeuille, en plus du mot de passe qui reste toujours disponible en secours pour les actions sensibles.",
    "settings.biometricUnavailable":
      "Windows Hello n'est pas configuré sur cet appareil — configurez-le dans les paramètres Windows pour activer cette option.",
    "settings.biometricEnable": "Activer Windows Hello",
    "settings.biometricDisable": "Désactiver Windows Hello",
    "settings.biometricEnableModalTitle": "Activer Windows Hello",
    "settings.biometricEnableModalSubtitle":
      "Votre mot de passe reste nécessaire pour les actions sensibles (sauvegarde, suppression de profil, désactivation de cette option). Une confirmation Windows Hello vous sera aussi demandée juste après.",
    "settings.biometricEnableConfirm": "Activer",
    "settings.biometricDisableModalTitle": "Désactiver Windows Hello",
    "settings.biometricDisableConfirm": "Désactiver",
    "settings.biometricEnabledStatus": "Windows Hello est activé sur cet appareil.",
    "send.title": "Envoyer",
    "send.fromProfile": "Depuis le profil : <strong id=\"send-from-profile\"></strong>",
    "send.mainnetWarning": "/!\\ Réseau MAINNET — ceci dépense de vrais fonds, irréversible.",
    "send.toAddress": "Adresse destinataire",
    "send.amount": "Montant",
    "send.percentMax": "Max",
    "send.percentUnavailable": "Pourcentages indisponibles (solde non chargé).",
    "send.feeSpeed": "Vitesse d'envoi (frais réseau)",
    "send.passwordToConfirm": "Mot de passe (pour valider la transaction)",
    "send.confirm": "Confirmer l'envoi",
    "send.previewTitle": "Vérifiez avant d'envoyer",
    "send.previewSubtitle": "Une confirmation de Windows s'ouvrira juste après — c'est elle qui valide réellement l'envoi.",
    "send.previewNetwork": "Réseau",
    "send.previewFrom": "Depuis",
    "send.previewConfirm": "Continuer",
    "send.previewBack": "Modifier",
    "send.txSent": "Transaction envoyée : {tx}",
    "swap.title": "Échanger",
    "swap.subtitle":
      "Passe par un protocole externe non audité par cette app — voir \"Comment ça marche\" pour le détail. Chaque échange (cross-chain via THORChain ou SOL/USDC via Jupiter) inclut 0,80% de frais d'affiliation.",
    "swap.fromAsset": "Depuis",
    "swap.fromSol": "Solana (SOL)",
    "swap.fromUsdc": "USDC",
    "swap.fromBtc": "Bitcoin (BTC)",
    "swap.fromEth": "Ethereum (ETH)",
    "swap.toAsset": "Vers",
    "swap.toBtc": "Bitcoin (BTC)",
    "swap.toEth": "Ethereum (ETH)",
    "swap.toUsdc": "USDC (via Jupiter, même portefeuille)",
    "swap.toSol": "Solana (SOL, via Jupiter, même portefeuille)",
    "swap.toSolCrossChain": "Solana (SOL)",
    "swap.amount": "Montant",
    "swap.destination": "Adresse de destination",
    "swap.destinationHint":
      "Pré-remplie avec votre propre adresse sur le réseau choisi — modifiable si vous voulez échanger vers une autre adresse.",
    "swap.jupiterHint":
      "Même portefeuille : les USDC arrivent directement sur votre adresse Solana, pas besoin d'adresse de destination séparée.",
    "swap.getQuote": "Obtenir un devis",
    "swap.previewTitle": "Vérifiez avant d'échanger",
    "swap.previewSending": "Envoi",
    "swap.previewReceiving": "Réception estimée",
    "swap.previewFees": "Frais THORChain (inclus)",
    "addProfile.title": "Nouveau profil",
    "addProfile.subtitle":
      "Un profil = une nouvelle adresse par réseau, dérivée de la même clé maîtresse déjà protégée par Shamir/PGP — aucune nouvelle sauvegarde à faire.",
    "addProfile.nameLabel": "Nom du profil",
    "addProfile.namePlaceholder": "ex : Épargne",
    "addProfile.passwordOptional": "Mot de passe (optionnel)",
    "addProfile.passwordPlaceholder": "Laissez vide pour voir l'adresse plus tard",
    "addProfile.passwordHint":
      "Avec le mot de passe : l'adresse s'affiche tout de suite. Sans lui : le profil est créé quand même, son adresse apparaîtra à votre prochain déverrouillage.",
    "addProfile.nameRequired": "Nom du profil requis.",
    "deleteProfile.title": "Supprimer ce profil ?",
    "deleteProfile.subtitle":
      "Cette application ne permet pas de recréer un profil au même index plus tard : si vous avez déjà reçu des fonds sur cette adresse, vous en perdrez l'accès depuis cette interface.",
    "deleteProfile.passwordLabel": "Mot de passe de l'appareil",
    "deleteProfile.confirm": "Supprimer quand même",
    "deleteProfile.warning":
      "Vous êtes sur le point de supprimer définitivement le profil \"{label}\". Si des fonds ont déjà été envoyés sur son adresse, ils deviendront inaccessibles depuis cette application.",
    "regenBackup.title": "Régénérer le kit de sauvegarde",
    "regenBackup.subtitle":
      "Ça crée 3 nouveaux fichiers de part + 3 nouvelles passphrases, sans toucher à vos adresses ni à votre mot de passe d'appareil. Vos anciens fichiers de sauvegarde restent valables (ce n'est pas un remplacement, juste un jeu supplémentaire).",
    "regenBackup.confirm": "Régénérer",
    "regenBackup.resultTitle": "Nouveau kit de sauvegarde",
    "regenBackup.resultSubtitle":
      "<strong>2 des 3 suffisent</strong> à tout récupérer. Téléchargez les 3 et notez les 3 mots de passe quelque part de sûr, séparément.",
    "regenBackup.resultClose": "J'ai téléchargé mes 3 nouvelles parts",
    "nav.ledger": "Ledger",
    "ledger.title": "Portefeuille matériel Ledger",
    "ledger.subtitle":
      "Les clés d'un Ledger ne quittent jamais l'appareil : chaque envoi s'affiche sur son écran et doit y être confirmé. Avant chaque opération, branchez-le, déverrouillez-le et ouvrez l'application du réseau (Ethereum, Bitcoin ou Solana).",
    "ledger.add": "+ Ajouter un compte Ledger",
    "ledger.refresh": "Actualiser",
    "ledger.btcNote":
      "Bitcoin : compte natif SegWit (m/84'), première adresse de réception et première adresse de monnaie. Des fonds reçus sur d'autres adresses (par exemple avec Ledger Live) n'apparaissent pas ici.",
    "ledger.empty": "Aucun compte Ledger pour l'instant — ajoutez-en un avec le bouton ci-dessus.",
    "ledger.addTitle": "Ajouter un compte Ledger",
    "ledger.addHint": "Branchez et déverrouillez le Ledger, puis ouvrez-y l'application du réseau choisi.",
    "ledger.label": "Nom (pour vous y retrouver)",
    "ledger.network": "Réseau",
    "ledger.read": "Lire le compte sur le Ledger",
    "ledger.labelRequired": "Le nom est requis.",
    "ledger.verify": "Vérifier sur le Ledger",
    "ledger.verifyPrompt": "Comparez l'adresse affichée par le Ledger avec celle-ci, puis confirmez-la sur l'appareil :\n{address}",
    "ledger.verified": "Adresse confirmée sur le Ledger.",
    "ledger.send": "Envoyer",
    "ledger.remove": "Retirer",
    "ledger.sendTitle": "Envoyer depuis « {label} »",
    "ledger.to": "Destinataire",
    "ledger.amount": "Montant ({unit})",
    "ledger.fee": "Frais",
    "ledger.feeFast": "Rapide (~10 min) : {sat} sat",
    "ledger.feeMedium": "Moyen (~30 min) : {sat} sat",
    "ledger.feeSlow": "Lent (~1 h) : {sat} sat",
    "ledger.feeLoading": "Estimation des frais…",
    "ledger.sendHint": "Après la confirmation de Windows, vérifiez le destinataire et le montant sur l'écran du Ledger, puis confirmez-y.",
    "ledger.waitDevice": "Confirmez sur le Ledger…",
    "ledger.sent": "Transaction envoyée : {txid}",
    "ledger.fieldsRequired": "Le destinataire et le montant sont requis.",
  },
  en: {
    "loading.text": "Loading…",
    "onboarding.title": "Create your wallet",
    "onboarding.subtitle":
      "Choose a password for this device. It will be used to open your wallet and confirm every transfer — like a lock, without you ever having to see the key behind it.",
    "onboarding.passwordLabel": "Password",
    "onboarding.confirmLabel": "Confirmation",
    "onboarding.confirmPlaceholder": "Retype the password",
    "onboarding.submit": "Create my wallet",
    "common.minChars": "At least 12 characters",
    "common.cancel": "Cancel",
    "common.add": "Add",
    "common.copy": "Copy",
    "common.clear": "Clear",
    "common.close": "Close",
    "common.create": "Create",
    "common.busy": "Please wait…",
    "common.passwordMinLength": "The password must be at least {min} characters long.",
    "common.passwordHint": "At least {min} characters, mixing types recommended.",
    "common.strengthWeak": "Strength: weak",
    "common.strengthMedium": "Strength: medium",
    "common.strengthGood": "Strength: good",
    "common.passwordTooWeak": "This password is too weak or too predictable — try mixing letters, digits and symbols.",
    "common.passwordsMismatch": "The two passwords don't match.",
    "common.passwordRequired": "Password required.",
    "common.saveFailed": "Save failed: {err}",
    "common.error": "Error: {err}",
    "common.copyFailed": "Copy failed: {err}",
    "common.copied": "Copied!",
    "backup.title": "Save your recovery kit",
    "backup.subtitle":
      "These 3 files protect your wallet if you lose this device. <strong>2 out of 3 are enough</strong> to recover everything, but none of the 3 alone is of any use — that's intentional, nobody (including you) can steal your wallet with a single share. Download all 3 and write down the 3 passwords somewhere safe, separately.",
    "backup.confirmCheckbox": "I have downloaded and saved my 3 shares and their passwords",
    "backup.continue": "Continue to my wallet",
    "backup.partTitle": "Share {n} — {label}",
    "backup.partPassword": "Password for this share:",
    "backup.downloadShare": "Download the share file",
    "backup.downloadPrivkey": "Download the private key",
    "unlock.title": "Wallet locked",
    "unlock.biometricButton": "Unlock with Windows Hello",
    "unlock.orPassword": "or",
    "unlock.passwordPlaceholder": "Your password",
    "unlock.submit": "Unlock",
    "unlock.gotoRestore": "Restore from a backup",
    "unlock.resetWallet": "Reset this device (deletes the local vault)",
    "restore.title": "Restore from a backup",
    "restore.subtitle":
      "Provide 2 of the 3 share files + their password, and choose a new password for this device.",
    "restore.share1": "Share #1",
    "restore.share2": "Share #2",
    "restore.shareFile": "Share file (.asc)",
    "restore.privkeyFile": "Private key file (.asc)",
    "restore.sharePassword": "Password for this share",
    "restore.newPasswordLabel": "New password for this device",
    "restore.submit": "Restore",
    "restore.filesRequired": "All 4 files (2 shares + 2 private keys) are required.",
    "nav.wallet": "Wallet",
    "nav.history": "History",
    "nav.message": "Message",
    "nav.certificate": "Certificate",
    "nav.external": "External wallets",
    "nav.addressBook": "Address book",
    "nav.settings": "Settings",
    "nav.lock": "Lock",
    "external.title": "External wallets",
    "external.subtitle":
      "Track the balance of addresses you don't own — just paste a public address. Read-only: no private key is ever involved. Group several wallets together to add up their value.",
    "external.addWallet": "+ Add an external wallet",
    "external.addGroup": "+ New group",
    "external.refresh": "Refresh",
    "external.addWalletTitle": "Add an external wallet",
    "external.label": "Name (for your own reference)",
    "external.network": "Network",
    "external.netEvmMainnet": "Ethereum — Mainnet",
    "external.netEvmSepolia": "Ethereum — Sepolia (testnet)",
    "external.netBtcMainnet": "Bitcoin — Mainnet",
    "external.netBtcTestnet": "Bitcoin — Testnet",
    "external.netSolMainnet": "Solana — Mainnet",
    "external.netSolDevnet": "Solana — Devnet",
    "external.netUsdcSolana": "USDC — Solana (Mainnet)",
    "external.address": "Address",
    "external.group": "Group (optional)",
    "external.noGroup": "No group",
    "external.add": "Add",
    "external.addGroupTitle": "New group",
    "external.groupName": "Group name",
    "external.empty": "No external wallet yet — add one with the button above.",
    "external.groupEmpty": "No wallet in this group.",
    "external.ungrouped": "Ungrouped",
    "external.deleteGroup": "Delete group",
    "external.remove": "Remove",
    "external.labelAndAddressRequired": "Name and address are required.",
    "external.groupNameRequired": "Group name is required.",
    "addressBook.title": "Address book",
    "addressBook.subtitle":
      "Save an address under a name so you can find it quickly when sending funds, without retyping it every time.",
    "addressBook.addEntry": "+ Add an address",
    "addressBook.addTitle": "Add an address",
    "addressBook.label": "Name (for your own reference)",
    "addressBook.network": "Network",
    "addressBook.address": "Address",
    "addressBook.add": "Add",
    "addressBook.remove": "Remove",
    "addressBook.empty": "No saved address yet — add one with the button above.",
    "addressBook.pickPlaceholder": "— Choose from the address book —",
    "nav.walletconnect": "Apps",
    "wc.title": "Connected apps (WalletConnect)",
    "wc.subtitle": "Connect this wallet to a site (dApp): on the site, choose WalletConnect, copy the connection link (\"wc:…\") and paste it here. Every signature a site asks for will require your password and a Windows confirmation.",
    "wc.uriLabel": "Connection link",
    "wc.pair": "Connect",
    "wc.pairing": "Waiting for the site's request…",
    "wc.sessions": "Connected sites",
    "wc.noSession": "No connected site.",
    "wc.disconnect": "Disconnect",
    "wc.relayConnected": "WalletConnect relay: connected.",
    "wc.relayDisconnected": "WalletConnect relay: disconnected.",
    "wc.proposalTitle": "Connection request",
    "wc.unverified": "Name and address declared by the site itself: nothing is verified. Only connect sites opened from their real address.",
    "wc.networks": "Networks: {chains}",
    "wc.profile": "Profile to connect",
    "wc.noProfile": "Unlock the wallet with your password to connect a site.",
    "wc.approve": "Connect",
    "wc.reject": "Reject",
    "wc.requestTitle": "Signature request",
    "wc.analyzing": "Analyzing the request…",
    "wc.danger": "This request carries a serious warning: read all of it before deciding.",
    "wc.sign": "Sign",
    "wc.expires": "expires on {date}",
    "wallet.profile": "Profile",
    "wallet.receive": "Receive",
    "wallet.receiveEth": "Receive ETH",
    "wallet.receiveBtc": "Receive BTC",
    "wallet.receiveSol": "Receive SOL",
    "wallet.newProfile": "+ New profile",
    "wallet.archiveProfile": "Archive this profile",
    "wallet.cannotArchiveLastProfile": "Cannot archive the last remaining active profile.",
    "wallet.archiveConfirm":
      "Archive profile \"{label}\"? It will disappear from the selector but stay recoverable at any time from Settings → Archived profiles.",
    "wallet.mainnet": "Mainnet — Real funds",
    "wallet.sepolia": "Sepolia (testnet)",
    "wallet.testnet": "Testnet",
    "wallet.devnet": "Devnet",
    "wallet.refresh": "Refresh",
    "wallet.send": "Send",
    "wallet.swap": "Swap",
    "wallet.pendingBadge": "⏳ Pending transaction detected",
    "wallet.marketsTitle": "Live cryptocurrency prices",
    "wallet.showQr": "Show as QR code",
    "wallet.copyAddress": "Copy address",
    "wallet.addressCopied": "Address copied!",
    "wallet.marketsLoadError": "Unable to load market data.",
    "wallet.qrError": "Unable to generate the QR code: {err}",
    "wallet.linkError": "Unable to open the link: {err}",
    "wallet.noArchivedProfile": "No archived profile.",
    "wallet.restoreProfile": "Restore",
    "wallet.deleteProfileForever": "Delete permanently",
    "history.subtitle":
      "Sorted by network, using whichever network is currently selected for each wallet card (mainnet or testnet).",
    "history.ethereum": "Ethereum",
    "history.bitcoin": "Bitcoin",
    "history.solana": "Solana",
    "history.kindReceived": "Received",
    "history.kindSent": "Sent",
    "history.kindSwap": "Swap",
    "history.kindOther": "Other",
    "history.usdAtTime": "Value in dollars at the time of the transaction",
    "wallet.historyLoading": "Loading…",
    "wallet.historyAddressUnavailable":
      "Address not available yet for this profile — unlock the wallet once to make it appear.",
    "wallet.historyEmpty": "No transaction for this address.",
    "wallet.historyViewLink": "View ↗",
    "wallet.historyConfirmed": "Confirmed",
    "wallet.historyPending": "Pending",
    "wallet.historyFailed": "Failed",
    "wallet.feeCalculating": "Calculating fees…",
    "wallet.feeAddressUnavailable": "Address unavailable.",
    "wallet.feeUnavailable": "Fees unavailable: {err}",
    "wallet.feeFast": "Fast",
    "wallet.feeFastHint": "~10 min",
    "wallet.feeMedium": "Medium",
    "wallet.feeMediumHint": "~30 min",
    "wallet.feeSlow": "Slow",
    "wallet.feeSlowHint": "~1 h",
    "wallet.btcFeesNotLoaded": "Bitcoin fees not loaded — wait a moment or try again.",
    "wallet.allFieldsRequired": "All fields are required.",
    "wallet.balanceError": "error",
    "message.title": "Encrypt a message",
    "message.subtitle":
      "The original purpose of PGP, before it got repurposed here to protect a seed: encrypting a message so only the recipient can read it.",
    "message.recipientsTitle": "Recipients",
    "message.addRecipient": "Add a recipient",
    "message.name": "Name",
    "message.namePlaceholder": "e.g. Alice",
    "message.theirPubkey": "Their PGP public key (ASCII-armor)",
    "message.messageTitle": "Message",
    "message.recipientsPickerLabel": "Recipients (one or more)",
    "message.plaintextLabel": "Plaintext message",
    "message.plaintextPlaceholder": "Your message...",
    "message.encrypt": "Encrypt",
    "message.encryptedResultLabel": "Encrypted message (copy/send it)",
    "message.decryptTitle": "Decrypt a received message",
    "message.decryptSubtitle":
      "Paste here a message encrypted with your public key (the one on the Certificate tab) — only you can read it.",
    "message.encryptedMessageLabel": "Encrypted message",
    "message.passwordToUnlock": "Password (to unlock your key)",
    "message.decrypt": "Decrypt",
    "message.decryptedMessageLabel": "Decrypted message",
    "message.noRecipientYet": "No recipient yet.",
    "message.addRecipientFirst": "Add a recipient above first.",
    "message.nameAndPubkeyRequired": "Name and public key are required.",
    "message.chooseAtLeastOneRecipient": "Choose at least one recipient (add one if the list is empty).",
    "message.cannotBeEmpty": "The message cannot be empty.",
    "message.encryptedAndPasswordRequired": "Encrypted message and password are required.",
    "message.removeRecipient": "Remove",
    "recipientKey.view": "View key",
    "recipientKey.title": "Recipient's public key",
    "recipientKey.copy": "Copy this public key",
    "certificate.title": "Your PGP certificate",
    "certificate.subtitle":
      "This is your public key — share it with someone so they can add you as a recipient and send you encrypted messages that only you can read.",
    "certificate.identity": "Identity",
    "certificate.fingerprint": "Fingerprint",
    "certificate.keyId": "Key ID",
    "certificate.fullKey": "Full public key (ASCII-armor)",
    "certificate.copy": "Copy my public key",
    "settings.appearance": "Appearance",
    "settings.theme": "Theme",
    "settings.blue": "Blue",
    "settings.purple": "Purple",
    "settings.orange": "Orange",
    "settings.dark": "Dark",
    "settings.roundedButtons": "Rounded buttons",
    "settings.walletListView": "Compact (list) wallet display",
    "settings.archivedProfiles": "Archived profiles",
    "settings.archivedProfilesHint":
      "An archived profile disappears from the main selector but stays fully recoverable — nothing is lost as long as it appears here.",
    "settings.backup": "Backup",
    "settings.regenerateBackup": "Regenerate my backup kit",
    "settings.regenerateBackupHint":
      "If you lost one or more of your original 3 backup files, generate a new set of 3 (password required). Your addresses don't change.",
    "settings.thorTitle": "THOR address (swap fee)",
    "settings.thorHint":
      "THORChain address derived from your master key — read-only, no send function or RUNE balance in this version. Used only as a reference for the swap feature.",
    "settings.thorShow": "Show address",
    "settings.deviceSecurity": "Device security",
    "settings.biometricTitle": "Biometric unlock",
    "settings.biometricHint":
      "Enables Windows Hello (fingerprint, face, or PIN) as a quick way to unlock this wallet, in addition to your password, which remains available as a fallback for sensitive actions.",
    "settings.biometricUnavailable":
      "Windows Hello isn't set up on this device — configure it in Windows Settings to enable this option.",
    "settings.biometricEnable": "Enable Windows Hello",
    "settings.biometricDisable": "Disable Windows Hello",
    "settings.biometricEnableModalTitle": "Enable Windows Hello",
    "settings.biometricEnableModalSubtitle":
      "Your password remains required for sensitive actions (backup, profile deletion, disabling this option). A Windows Hello confirmation will also be requested right after.",
    "settings.biometricEnableConfirm": "Enable",
    "settings.biometricDisableModalTitle": "Disable Windows Hello",
    "settings.biometricDisableConfirm": "Disable",
    "settings.biometricEnabledStatus": "Windows Hello is enabled on this device.",
    "send.title": "Send",
    "send.fromProfile": "From profile: <strong id=\"send-from-profile\"></strong>",
    "send.mainnetWarning": "/!\\ MAINNET network — this spends real funds, irreversible.",
    "send.toAddress": "Recipient address",
    "send.amount": "Amount",
    "send.percentMax": "Max",
    "send.percentUnavailable": "Percentages unavailable (balance not loaded).",
    "send.feeSpeed": "Sending speed (network fee)",
    "send.passwordToConfirm": "Password (to confirm the transaction)",
    "send.confirm": "Confirm send",
    "send.previewTitle": "Review before sending",
    "send.previewSubtitle": "A Windows confirmation will open right after — that's what actually validates the send.",
    "send.previewNetwork": "Network",
    "send.previewFrom": "From",
    "send.previewConfirm": "Continue",
    "send.previewBack": "Edit",
    "send.txSent": "Transaction sent: {tx}",
    "swap.title": "Swap",
    "swap.subtitle":
      "Goes through an external protocol not audited by this app — see \"How it works\" for details. Every swap (cross-chain via THORChain or SOL/USDC via Jupiter) includes a 0.80% affiliate fee.",
    "swap.fromAsset": "From",
    "swap.fromSol": "Solana (SOL)",
    "swap.fromUsdc": "USDC",
    "swap.fromBtc": "Bitcoin (BTC)",
    "swap.fromEth": "Ethereum (ETH)",
    "swap.toAsset": "To",
    "swap.toBtc": "Bitcoin (BTC)",
    "swap.toEth": "Ethereum (ETH)",
    "swap.toUsdc": "USDC (via Jupiter, same wallet)",
    "swap.toSol": "Solana (SOL, via Jupiter, same wallet)",
    "swap.toSolCrossChain": "Solana (SOL)",
    "swap.amount": "Amount",
    "swap.destination": "Destination address",
    "swap.destinationHint": "Pre-filled with your own address on the chosen network — editable if you want to swap to a different address.",
    "swap.jupiterHint": "Same wallet: the USDC lands directly on your Solana address, no separate destination address needed.",
    "swap.getQuote": "Get a quote",
    "swap.previewTitle": "Review before swapping",
    "swap.previewSending": "Sending",
    "swap.previewReceiving": "Estimated receive",
    "swap.previewFees": "THORChain fees (included)",
    "addProfile.title": "New profile",
    "addProfile.subtitle":
      "A profile = a new address per network, derived from the same master key already protected by Shamir/PGP — no new backup needed.",
    "addProfile.nameLabel": "Profile name",
    "addProfile.namePlaceholder": "e.g. Savings",
    "addProfile.passwordOptional": "Password (optional)",
    "addProfile.passwordPlaceholder": "Leave empty to see the address later",
    "addProfile.passwordHint":
      "With the password: the address shows up right away. Without it: the profile is created anyway, its address will appear on your next full unlock.",
    "addProfile.nameRequired": "Profile name required.",
    "deleteProfile.title": "Delete this profile?",
    "deleteProfile.subtitle":
      "This application does not allow recreating a profile at the same index later: if you've already received funds on this address, you will lose access to them from this interface.",
    "deleteProfile.passwordLabel": "Device password",
    "deleteProfile.confirm": "Delete anyway",
    "deleteProfile.warning":
      "You are about to permanently delete the profile \"{label}\". If funds have already been sent to its address, they will become inaccessible from this application.",
    "regenBackup.title": "Regenerate the backup kit",
    "regenBackup.subtitle":
      "This creates 3 new share files + 3 new passphrases, without touching your addresses or your device password. Your old backup files remain valid (this isn't a replacement, just an extra set).",
    "regenBackup.confirm": "Regenerate",
    "regenBackup.resultTitle": "New backup kit",
    "regenBackup.resultSubtitle":
      "<strong>2 out of 3 are enough</strong> to recover everything. Download all 3 and write down the 3 passwords somewhere safe, separately.",
    "regenBackup.resultClose": "I have downloaded my 3 new shares",
    "nav.ledger": "Ledger",
    "ledger.title": "Ledger hardware wallet",
    "ledger.subtitle":
      "A Ledger's keys never leave the device: every transfer is shown on its screen and must be confirmed there. Before each operation, plug it in, unlock it and open the network's app (Ethereum, Bitcoin or Solana).",
    "ledger.add": "+ Add a Ledger account",
    "ledger.refresh": "Refresh",
    "ledger.btcNote":
      "Bitcoin: native SegWit account (m/84'), first receive address and first change address. Funds received on other addresses (for example with Ledger Live) do not show up here.",
    "ledger.empty": "No Ledger account yet — add one with the button above.",
    "ledger.addTitle": "Add a Ledger account",
    "ledger.addHint": "Plug in and unlock the Ledger, then open the chosen network's app on it.",
    "ledger.label": "Name (for your own reference)",
    "ledger.network": "Network",
    "ledger.read": "Read the account from the Ledger",
    "ledger.labelRequired": "The name is required.",
    "ledger.verify": "Verify on the Ledger",
    "ledger.verifyPrompt": "Compare the address shown by the Ledger with this one, then confirm it on the device:\n{address}",
    "ledger.verified": "Address confirmed on the Ledger.",
    "ledger.send": "Send",
    "ledger.remove": "Remove",
    "ledger.sendTitle": "Send from \"{label}\"",
    "ledger.to": "Recipient",
    "ledger.amount": "Amount ({unit})",
    "ledger.fee": "Fee",
    "ledger.feeFast": "Fast (~10 min): {sat} sat",
    "ledger.feeMedium": "Medium (~30 min): {sat} sat",
    "ledger.feeSlow": "Slow (~1 h): {sat} sat",
    "ledger.feeLoading": "Estimating fees…",
    "ledger.sendHint": "After the Windows confirmation, check the recipient and amount on the Ledger's screen, then confirm there.",
    "ledger.waitDevice": "Confirm on the Ledger…",
    "ledger.sent": "Transaction sent: {txid}",
    "ledger.fieldsRequired": "Recipient and amount are required.",
  },
};

function t(key, vars) {
  const dict = I18N[currentLang] || I18N.fr;
  let text = dict[key] ?? I18N.fr[key] ?? key;
  if (vars) {
    for (const [name, value] of Object.entries(vars)) {
      text = text.replaceAll(`{${name}}`, value);
    }
  }
  return text;
}

function applyLanguage(lang) {
  currentLang = VALID_LANGS.includes(lang) ? lang : "fr";
  document.documentElement.lang = currentLang;
  // Les messages d'erreur renvoyés par le backend Rust (core/) sont eux aussi
  // traduits, mais côté Rust (app/src-tauri/src/lib.rs::translate_error) : core/
  // ignore volontairement tout concept d'interface, la langue affichée n'est donc
  // jamais transmise plus profond que cette commande dédiée. Best-effort : si
  // l'appel échoue (ex. tout premier appel avant que le backend soit prêt), les
  // erreurs backend restent simplement en français le temps du prochain switch.
  invoke("set_ui_language", { lang: currentLang }).catch(() => {});
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = t(el.dataset.i18nHtml);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    el.title = t(el.dataset.i18nTitle);
  });
  // Les <option> viennent d'être retraduits ci-dessus, mais l'étiquette visible
  // du menu déroulant personnalisé (.custom-select-label) et sa liste (<li>) sont
  // de simples copies figées, synchronisées seulement à l'ouverture ou à un choix
  // (voir syncCustomSelect) — sans ce ré-appel, elles resteraient dans l'ancienne
  // langue jusqu'au prochain clic sur le menu.
  document.querySelectorAll(".custom-select select").forEach(syncCustomSelect);
  document.querySelectorAll(".lang-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.lang === currentLang);
  });
}

let currentLang = "fr";
try {
  const savedLang = localStorage.getItem(LANG_STORAGE_KEY);
  if (VALID_LANGS.includes(savedLang)) currentLang = savedLang;
} catch (e) {
  // localStorage indisponible : reste sur le français par défaut.
}
applyLanguage(currentLang);

document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    applyLanguage(btn.dataset.lang);
    // Contenu déjà généré dynamiquement à partir de données déjà en mémoire (pas
    // besoin de rappeler le backend) : ré-affiché tout de suite dans la nouvelle
    // langue. Les autres listes dynamiques (historique, frais, kit de sauvegarde...)
    // adopteront la nouvelle langue à leur prochain affichage.
    renderRecipientList();
    try {
      localStorage.setItem(LANG_STORAGE_KEY, currentLang);
    } catch (e) {
      // Best-effort : la langue reste active pour cette session même si la sauvegarde échoue.
    }
  });
});

// --- Menus déroulants personnalisés -----------------------------------------
// Un <select> natif n'expose aucun moyen fiable (CSS ou JS) de savoir si son menu
// est réellement ouvert ou fermé — seulement s'il a le focus, qu'il garde après
// un choix ou après un second clic qui referme déjà le menu nativement. Résultat
// avec une simple flèche en CSS (:focus-within) : elle reste tournée après la
// fermeture tant qu'on ne clique pas ailleurs. Le <select> reste la source de
// vérité (valeur, options, événement "change" — tout le reste du code continue à
// le lire/écouter normalement) mais devient invisible ; ce composant pilote
// entièrement l'affichage et l'ouverture/fermeture, en JS, donc de façon exacte.

function syncCustomSelect(select) {
  const wrapper = select.closest(".custom-select");
  if (!wrapper) return;
  const label = wrapper.querySelector(".custom-select-label");
  const list = wrapper.querySelector(".custom-select-options");
  list.innerHTML = "";
  Array.from(select.options).forEach((option) => {
    const li = document.createElement("li");
    li.textContent = option.textContent;
    li.dataset.value = option.value;
    if (option.selected) {
      li.classList.add("selected");
      label.textContent = option.textContent;
    }
    list.appendChild(li);
  });
}

// `.dropdown` : classe partagée par les menus à valeur (.custom-select, ci-dessus)
// et les menus d'action pure comme le bouton "Recevoir" (voir plus bas) — mêmes
// mécanismes d'ouverture/fermeture/flèche, sans qu'un menu d'action ait besoin
// d'un <select> sous-jacent.
function closeAllDropdowns(except) {
  document.querySelectorAll(".dropdown.open").forEach((wrapper) => {
    if (wrapper !== except) wrapper.classList.remove("open");
  });
}

function initCustomSelect(wrapper) {
  const select = wrapper.querySelector("select");
  const trigger = wrapper.querySelector(".custom-select-trigger");
  const list = wrapper.querySelector(".custom-select-options");

  // Le <select> natif reste focusable au clavier par défaut (tabulation) : ça
  // créerait un second arrêt invisible qui fait exactement doublon avec le bouton
  // visible juste à côté. Seul ce dernier doit rester dans l'ordre de tabulation.
  select.tabIndex = -1;

  syncCustomSelect(select);

  trigger.addEventListener("click", () => {
    const wasOpen = wrapper.classList.contains("open");
    closeAllDropdowns();
    wrapper.classList.toggle("open", !wasOpen);
  });

  // Flèches directionnelles au clavier, comme un <select> natif : sans ça, le
  // rendre non-focusable (tabIndex -1) juste au-dessus aurait rendu ce menu
  // inutilisable sans souris.
  trigger.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const options = Array.from(select.options);
    if (options.length === 0) return;
    const currentIndex = options.findIndex((o) => o.value === select.value);
    const delta = e.key === "ArrowDown" ? 1 : -1;
    const nextIndex = Math.min(options.length - 1, Math.max(0, currentIndex + delta));
    if (options[nextIndex].value !== select.value) {
      select.value = options[nextIndex].value;
      select.dispatchEvent(new Event("change", { bubbles: true }));
      syncCustomSelect(select);
    }
  });

  list.addEventListener("click", (e) => {
    const li = e.target.closest("li");
    if (!li) return;
    if (select.value !== li.dataset.value) {
      select.value = li.dataset.value;
      // Synthétique : déclenche exactement les mêmes gestionnaires "change" que si
      // l'utilisateur avait choisi cette option dans un <select> natif.
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    syncCustomSelect(select);
    wrapper.classList.remove("open");
  });
}

// --- Menu d'action "Recevoir" (barre de profil) -----------------------------
// Raccourci vers le même QR/adresse que le bouton QR de chaque carte (voir
// openQrModal) : pas de valeur "sélectionnée" à retenir, chaque clic déclenche
// directement une action, donc pas de <select> sous-jacent ici contrairement à
// .custom-select.
function initActionMenu(wrapper) {
  const trigger = wrapper.querySelector(".custom-select-trigger");
  const list = wrapper.querySelector(".custom-select-options");

  trigger.addEventListener("click", () => {
    const wasOpen = wrapper.classList.contains("open");
    closeAllDropdowns();
    wrapper.classList.toggle("open", !wasOpen);
  });

  list.addEventListener("click", (e) => {
    const li = e.target.closest("li");
    if (!li) return;
    wrapper.classList.remove("open");
    const card = document.querySelector(`.wallet-card[data-coin="${li.dataset.coin}"]`);
    if (card) openQrModal(card);
  });
}

document.addEventListener("click", (e) => {
  if (!e.target.closest(".dropdown")) closeAllDropdowns();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeAllDropdowns();
});

document.querySelectorAll(".custom-select").forEach(initCustomSelect);
document.querySelectorAll(".action-menu").forEach(initActionMenu);

// --- État "en cours" des boutons d'action ----------------------------------
// Aucune opération sensible (déverrouillage, envoi, création de profil...) ne
// désactivait son bouton pendant l'attente : certaines sont volontairement
// lentes (coût S2K maximal pour protéger le mot de passe, appels réseau pour
// un envoi), donc sans retour visuel l'app paraît figée — et un double-clic
// peut déclencher deux opérations en parallèle (ex: deux envois superposés).
function withBusyButton(button, action) {
  return async (...args) => {
    if (button.disabled) return; // déjà en cours : ignore un second clic
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = t("common.busy");
    try {
      await action(...args);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  };
}

// Comme `withBusyButton`, mais le bouton reste désactivé au moins `cooldownMs`
// après le clic, même si la requête elle-même a fini plus vite — sans ça, un
// clic répété dès que le bouton redevient actif suffit à spammer l'API
// (solde/historique) à peu près à la fréquence du réseau. Réservé aux boutons
// "Actualiser", qui sont justement ceux qu'on peut spammer sans rien taper
// entre deux clics (contrairement à "Envoyer"/"Ajouter", qui demandent de
// remplir un formulaire à chaque fois).
function withThrottledButton(button, cooldownMs, action) {
  return async (...args) => {
    if (button.disabled) return;
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = t("common.busy");
    const start = Date.now();
    try {
      await action(...args);
    } finally {
      const remaining = cooldownMs - (Date.now() - start);
      if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
      }
      button.disabled = false;
      button.textContent = originalText;
    }
  };
}

const REFRESH_COOLDOWN_MS = 1500;

const views = {
  loading: document.getElementById("view-loading"),
  onboarding: document.getElementById("view-onboarding"),
  backup: document.getElementById("view-backup"),
  unlock: document.getElementById("view-unlock"),
  restore: document.getElementById("view-restore"),
  dashboard: document.getElementById("view-dashboard"),
};

function showView(name) {
  for (const [key, el] of Object.entries(views)) {
    el.classList.toggle("hidden", key !== name);
  }
}

function showError(el, message) {
  el.textContent = message;
  el.classList.remove("hidden");
}

function hideError(el) {
  el.classList.add("hidden");
}

let copyToastHideTimeout = null;
let copyToastCleanupTimeout = null;

function showCopyToast(message) {
  const toast = document.getElementById("copy-toast");
  document.getElementById("copy-toast-text").textContent = message;
  clearTimeout(copyToastHideTimeout);
  clearTimeout(copyToastCleanupTimeout);
  toast.classList.remove("hidden");
  // Force le recalcul de style avant d'ajouter `.visible` : sans ça, un clic
  // pendant que le toast précédent est encore affiché ne redéclencherait pas
  // la transition (déjà à son état final), donc pas d'animation visible.
  void toast.offsetWidth;
  toast.classList.add("visible");
  copyToastHideTimeout = setTimeout(() => {
    toast.classList.remove("visible");
    copyToastCleanupTimeout = setTimeout(() => toast.classList.add("hidden"), 200);
  }, 1800);
}

async function copyText(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    showCopyToast(successMessage || t("common.copied"));
  } catch (e) {
    alert(t("common.copyFailed", { err: e }));
  }
}

// --- Onboarding ---------------------------------------------------------

let pendingCreateResult = null;

const MIN_PASSWORD_LENGTH = 12;
const COMMON_PASSWORD_PATTERNS = [
  "password",
  "motdepasse",
  "azerty",
  "qwerty",
  "123456",
  "00000000",
  "letmein",
  "admin",
];

// Heuristique volontairement simple (pas de dépendance JS externe, cohérent
// avec le frontend "léger" sans bibliothèque tierce) : longueur + diversité de
// caractères, avec un filtre sur les motifs les plus évidents à deviner.
function estimatePasswordStrength(password) {
  if (password.length < MIN_PASSWORD_LENGTH) return "faible";

  const lower = password.toLowerCase();
  if (COMMON_PASSWORD_PATTERNS.some((p) => lower.includes(p))) return "faible";

  let score = 0;
  if (password.length >= MIN_PASSWORD_LENGTH) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  if (score <= 2) return "faible";
  if (score <= 3) return "moyen";
  return "fort";
}

function updateStrengthHint(inputEl, hintEl) {
  const password = inputEl.value;
  hintEl.classList.remove("strength-faible", "strength-moyen", "strength-fort");
  if (!password) {
    hintEl.textContent = t("common.passwordHint", { min: MIN_PASSWORD_LENGTH });
    return;
  }
  const strength = estimatePasswordStrength(password);
  const labels = {
    faible: t("common.strengthWeak"),
    moyen: t("common.strengthMedium"),
    fort: t("common.strengthGood"),
  };
  hintEl.textContent = labels[strength];
  hintEl.classList.add(`strength-${strength}`);
}

document.getElementById("onboarding-password").addEventListener("input", (e) => {
  updateStrengthHint(e.target, document.getElementById("onboarding-strength"));
});

const onboardingSubmitBtn = document.getElementById("onboarding-submit");
onboardingSubmitBtn.addEventListener("click", withBusyButton(onboardingSubmitBtn, async () => {
  const password = document.getElementById("onboarding-password").value;
  const confirm = document.getElementById("onboarding-password-confirm").value;
  const errorEl = document.getElementById("onboarding-error");
  hideError(errorEl);

  if (password.length < MIN_PASSWORD_LENGTH) {
    showError(errorEl, t("common.passwordMinLength", { min: MIN_PASSWORD_LENGTH }));
    return;
  }
  if (estimatePasswordStrength(password) === "faible") {
    showError(errorEl, t("common.passwordTooWeak"));
    return;
  }
  if (password !== confirm) {
    showError(errorEl, t("common.passwordsMismatch"));
    return;
  }

  try {
    const result = await invoke("create_wallet", { password });
    pendingCreateResult = result;
    renderBackupList(result.backups);
    showView("backup");
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    // Le mot de passe ne doit pas rester dans le DOM plus longtemps que nécessaire.
    document.getElementById("onboarding-password").value = "";
    document.getElementById("onboarding-password-confirm").value = "";
  }
}));

// Les liens <a download> classiques ne fonctionnent pas de façon fiable dans la
// webview Tauri (navigation interceptée pour raisons de sécurité) : on utilise à
// la place une commande Rust qui ouvre elle-même la boîte de dialogue native
// "Enregistrer sous" et écrit le fichier. Le chemin n'est jamais choisi côté JS :
// un script compromis ne peut donc pas forcer une écriture vers un emplacement
// arbitraire.
async function saveBase64ToFile(base64Content, suggestedName) {
  return await invoke("save_bytes_with_dialog", {
    suggestedName,
    contentB64: base64Content,
  });
}

function renderBackupList(backups, containerId = "backup-list") {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  backups.forEach((backup, i) => {
    const item = document.createElement("div");
    item.className = "backup-item";
    item.innerHTML = `
      <h3>${t("backup.partTitle", { n: i + 1, label: backup.label })}</h3>
      <p class="muted">${t("backup.partPassword")}</p>
      <div class="passphrase">${backup.passphrase}</div>
      <div class="row-buttons">
        <button class="secondary" data-kind="share">${t("backup.downloadShare")}</button>
        <button class="secondary" data-kind="privkey">${t("backup.downloadPrivkey")}</button>
      </div>
    `;
    item.querySelector('[data-kind="share"]').addEventListener("click", async (e) => {
      try {
        await saveBase64ToFile(backup.encrypted_share_b64, `${backup.label}_share.asc`);
      } catch (err) {
        alert(t("common.saveFailed", { err }));
      }
    });
    item.querySelector('[data-kind="privkey"]').addEventListener("click", async (e) => {
      try {
        await saveBase64ToFile(backup.privkey_armored_b64, `${backup.label}_privkey.asc`);
      } catch (err) {
        alert(t("common.saveFailed", { err }));
      }
    });
    container.appendChild(item);
  });
}

document.getElementById("backup-confirm").addEventListener("change", (e) => {
  document.getElementById("backup-continue").disabled = !e.target.checked;
});

document.getElementById("backup-continue").addEventListener("click", () => {
  if (pendingCreateResult) {
    renderDashboardAddresses(singleProfileList(pendingCreateResult.addresses));
    pendingCreateResult = null;
    showView("dashboard");
    refreshAllBalances();
    startBalanceAutoRefresh();
  }
});

// --- Unlock --------------------------------------------------------------

const unlockSubmitBtn = document.getElementById("unlock-submit");
unlockSubmitBtn.addEventListener("click", withBusyButton(unlockSubmitBtn, async () => {
  const password = document.getElementById("unlock-password").value;
  const errorEl = document.getElementById("unlock-error");
  hideError(errorEl);
  try {
    const profiles = await invoke("unlock_wallet", { password });
    renderDashboardAddresses(profiles);
    showView("dashboard");
    refreshAllBalances();
    startBalanceAutoRefresh();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("unlock-password").value = "";
  }
}));

// Le mot de passe reste TOUJOURS visible et fonctionnel juste en dessous
// (jamais remplacé par la biométrie, seulement complété par elle) : un capteur
// défaillant ou Windows Hello mal configuré ne doit jamais bloquer l'accès au
// portefeuille. Le bouton biométrique ne se déclenche que sur un clic explicite
// (voir `showUnlockView`) — jamais automatiquement à l'arrivée sur cet écran,
// pour ne jamais faire apparaître un prompt OS sans action volontaire.
const unlockBiometricBtn = document.getElementById("unlock-biometric-btn");
const attemptBiometricUnlock = withBusyButton(unlockBiometricBtn, async () => {
  const errorEl = document.getElementById("unlock-biometric-error");
  hideError(errorEl);
  try {
    const profiles = await invoke("unlock_wallet_biometric");
    renderDashboardAddresses(profiles);
    showView("dashboard");
    refreshAllBalances();
    startBalanceAutoRefresh();
  } catch (e) {
    showError(errorEl, String(e));
  }
});
unlockBiometricBtn.addEventListener("click", attemptBiometricUnlock);

/// Affiche l'écran de déverrouillage et, si la biométrie est activée sur cet
/// appareil, révèle le bouton dédié — l'utilisateur déclenche lui-même le
/// prompt Windows Hello en cliquant dessus, jamais automatiquement à l'arrivée
/// sur cet écran.
async function showUnlockView() {
  showView("unlock");
  const biometricBtn = document.getElementById("unlock-biometric-btn");
  const divider = document.getElementById("unlock-biometric-divider");
  hideError(document.getElementById("unlock-biometric-error"));
  let enrolled = false;
  try {
    enrolled = await invoke("biometric_unlock_enrolled");
  } catch (e) {
    enrolled = false;
  }
  biometricBtn.classList.toggle("hidden", !enrolled);
  divider.classList.toggle("hidden", !enrolled);
}

document.getElementById("goto-restore").addEventListener("click", () => showView("restore"));
document.getElementById("goto-unlock").addEventListener("click", () => showUnlockView());

// Pas de confirm() JavaScript : la confirmation est une boîte NATIVE côté Rust
// (`confirm_reset_native`), la seule qu'un frontend compromis ne peut pas sauter.
document.getElementById("reset-wallet").addEventListener("click", async () => {
  try {
    await invoke("reset_wallet");
    profilesCache = [];
    currentProfileIndex = 0;
    showView("onboarding");
  } catch (e) {
    showError(document.getElementById("unlock-error"), String(e));
  }
});

document.getElementById("reset-wallet-dashboard").addEventListener("click", async () => {
  try {
    await invoke("reset_wallet");
    profilesCache = [];
    currentProfileIndex = 0;
    stopBalanceAutoRefresh();
    showView("onboarding");
  } catch (e) {
    alert(t("common.error", { err: e }));
  }
});

// --- Déverrouillage biométrique (Windows Hello), onglet Paramètres ---------

async function loadBiometricSettings() {
  const enableBtn = document.getElementById("enable-biometric-btn");
  const disableBtn = document.getElementById("disable-biometric-btn");
  const unavailableHint = document.getElementById("biometric-unavailable-hint");

  // Les deux appels sont indépendants (disponibilité Windows Hello côté OS vs.
  // statut d'activation côté fichiers) : lancés en parallèle plutôt que l'un
  // après l'autre, même principe que le reste de l'app (voir refreshBalance).
  let available = false;
  let enrolled = false;
  try {
    [available, enrolled] = await Promise.all([
      invoke("biometric_unlock_available"),
      invoke("biometric_unlock_enrolled"),
    ]);
  } catch (e) {
    console.error(e);
  }

  // `available` est une heuristique d'affichage côté OS (voir
  // `windows_hello::is_available`), jamais la barrière de sécurité elle-même :
  // se tromper ici ne peut que proposer un bouton qui échouera ensuite, jamais
  // affaiblir quoi que ce soit.
  unavailableHint.classList.toggle("hidden", available || enrolled);
  enableBtn.classList.toggle("hidden", enrolled || !available);
  disableBtn.classList.toggle("hidden", !enrolled);
}

document.getElementById("enable-biometric-btn").addEventListener("click", () => {
  document.getElementById("enable-biometric-password").value = "";
  hideError(document.getElementById("enable-biometric-error"));
  document.getElementById("enable-biometric-password-modal").classList.remove("hidden");
});

document.getElementById("enable-biometric-cancel").addEventListener("click", () => {
  document.getElementById("enable-biometric-password-modal").classList.add("hidden");
  document.getElementById("enable-biometric-password").value = "";
});

const enableBiometricConfirmBtn = document.getElementById("enable-biometric-confirm");
enableBiometricConfirmBtn.addEventListener("click", withBusyButton(enableBiometricConfirmBtn, async () => {
  const errorEl = document.getElementById("enable-biometric-error");
  hideError(errorEl);
  const password = document.getElementById("enable-biometric-password").value;
  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }
  try {
    await invoke("enroll_biometric_unlock", { password });
    document.getElementById("enable-biometric-password-modal").classList.add("hidden");
    loadBiometricSettings();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("enable-biometric-password").value = "";
  }
}));

document.getElementById("disable-biometric-btn").addEventListener("click", () => {
  document.getElementById("disable-biometric-password").value = "";
  hideError(document.getElementById("disable-biometric-error"));
  document.getElementById("disable-biometric-password-modal").classList.remove("hidden");
});

document.getElementById("disable-biometric-cancel").addEventListener("click", () => {
  document.getElementById("disable-biometric-password-modal").classList.add("hidden");
  document.getElementById("disable-biometric-password").value = "";
});

const disableBiometricConfirmBtn = document.getElementById("disable-biometric-confirm");
disableBiometricConfirmBtn.addEventListener("click", withBusyButton(disableBiometricConfirmBtn, async () => {
  const errorEl = document.getElementById("disable-biometric-error");
  hideError(errorEl);
  const password = document.getElementById("disable-biometric-password").value;
  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }
  try {
    await invoke("disable_biometric_unlock", { password });
    document.getElementById("disable-biometric-password-modal").classList.add("hidden");
    loadBiometricSettings();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("disable-biometric-password").value = "";
  }
}));

// --- Régénération du kit de sauvegarde ------------------------------------

document.getElementById("open-regenerate-backup").addEventListener("click", () => {
  document.getElementById("regenerate-backup-password").value = "";
  hideError(document.getElementById("regenerate-backup-error"));
  document.getElementById("regenerate-backup-password-modal").classList.remove("hidden");
});

document.getElementById("regenerate-backup-cancel").addEventListener("click", () => {
  document.getElementById("regenerate-backup-password-modal").classList.add("hidden");
  document.getElementById("regenerate-backup-password").value = "";
});

const regenerateBackupConfirmBtn = document.getElementById("regenerate-backup-confirm");
regenerateBackupConfirmBtn.addEventListener("click", withBusyButton(regenerateBackupConfirmBtn, async () => {
  const errorEl = document.getElementById("regenerate-backup-error");
  hideError(errorEl);
  const password = document.getElementById("regenerate-backup-password").value;
  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }

  try {
    const backups = await invoke("regenerate_backup_kit", { password });
    document.getElementById("regenerate-backup-password-modal").classList.add("hidden");
    renderBackupList(backups, "regenerate-backup-list");
    document.getElementById("regenerate-backup-result-modal").classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("regenerate-backup-password").value = "";
  }
}));

document.getElementById("regenerate-backup-close").addEventListener("click", () => {
  document.getElementById("regenerate-backup-result-modal").classList.add("hidden");
  document.getElementById("regenerate-backup-list").innerHTML = "";
});

// --- Adresse THOR (frais de swap) -------------------------------------------
// Purement informatif (voir api::get_thor_fee_address) : aucune fonction
// d'envoi/solde RUNE, juste la dérivation + l'affichage de l'adresse.

document.getElementById("show-thor-address-btn").addEventListener("click", () => {
  document.getElementById("thor-address-password").value = "";
  hideError(document.getElementById("thor-address-error"));
  document.getElementById("thor-address-password-modal").classList.remove("hidden");
});

document.getElementById("thor-address-cancel").addEventListener("click", () => {
  document.getElementById("thor-address-password-modal").classList.add("hidden");
});

const thorAddressConfirmBtn = document.getElementById("thor-address-confirm");
thorAddressConfirmBtn.addEventListener("click", withBusyButton(thorAddressConfirmBtn, async () => {
  const errorEl = document.getElementById("thor-address-error");
  hideError(errorEl);
  const password = document.getElementById("thor-address-password").value;
  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }

  try {
    const address = await invoke("get_thor_fee_address", { password });
    document.getElementById("thor-address-password-modal").classList.add("hidden");
    const display = document.getElementById("thor-address-display");
    display.textContent = address;
    display.classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("thor-address-password").value = "";
  }
}));

function lockWallet() {
  profilesCache = [];
  currentProfileIndex = 0;
  stopBalanceAutoRefresh();
  document.getElementById("unlock-password").value = "";
  showUnlockView();
}

document.getElementById("lock-wallet").addEventListener("click", lockWallet);

// --- Verrouillage automatique après inactivité -------------------------------
// Rien n'est mis en cache en mémoire entre deux actions sensibles (chaque envoi/
// déchiffrement redemande le mot de passe, voir "Modèle retenu" dans ETAPES.md) :
// le verrouillage automatique ne protège donc pas un secret déjà déchiffré, mais
// laisser le tableau de bord ouvert (adresses, soldes, historique) expose ces
// informations à quiconque a un accès physique à l'appareil en votre absence —
// l'hygiène standard attendue de n'importe quel wallet.
const AUTO_LOCK_MS = 10 * 60 * 1000; // 10 minutes d'inactivité
let autoLockTimer = null;
let lastActivityReset = 0;

function resetAutoLockTimer() {
  // Throttle : "mousemove"/"scroll" peuvent se déclencher des centaines de fois par
  // seconde, et recréer un setTimeout à chaque fois est un travail inutile pour un
  // délai de 10 minutes — une précision à la seconde près suffit largement et évite
  // ce churn pendant tout mouvement de souris.
  const now = Date.now();
  if (now - lastActivityReset < 1000) return;
  lastActivityReset = now;
  if (autoLockTimer) clearTimeout(autoLockTimer);
  autoLockTimer = setTimeout(() => {
    if (!views.dashboard.classList.contains("hidden")) lockWallet();
  }, AUTO_LOCK_MS);
}

["mousemove", "keydown", "mousedown", "scroll"].forEach((evt) => {
  document.addEventListener(evt, resetAutoLockTimer, { passive: true });
});
resetAutoLockTimer();

// --- Onglets de navigation ---------------------------------------------

document.querySelectorAll(".nav-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".nav-tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const target = tab.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.classList.toggle("hidden", panel.dataset.panel !== target);
    });
    if (target === "history") loadAllHistory();
    if (target === "certificate") loadCertificate();
    if (target === "message") loadRecipients();
    if (target === "external") loadExternalWallets();
    if (target === "addressbook") loadAddressBook();
    if (target === "walletconnect") loadWcSessions();
    if (target === "ledger") loadLedgerAccounts();
    if (target === "settings") {
      loadArchivedProfiles();
      loadBiometricSettings();
    }
  });
});

// --- Restore ---------------------------------------------------------------

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const b64 = reader.result.split(",")[1];
      resolve(b64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

document.getElementById("restore-new-password").addEventListener("input", (e) => {
  updateStrengthHint(e.target, document.getElementById("restore-strength"));
});

const restoreSubmitBtn = document.getElementById("restore-submit");
restoreSubmitBtn.addEventListener("click", withBusyButton(restoreSubmitBtn, async () => {
  const errorEl = document.getElementById("restore-error");
  hideError(errorEl);

  const shareFile1 = document.getElementById("restore-share-1").files[0];
  const privkeyFile1 = document.getElementById("restore-privkey-1").files[0];
  const shareFile2 = document.getElementById("restore-share-2").files[0];
  const privkeyFile2 = document.getElementById("restore-privkey-2").files[0];
  const passphrase1 = document.getElementById("restore-passphrase-1").value;
  const passphrase2 = document.getElementById("restore-passphrase-2").value;
  const newPassword = document.getElementById("restore-new-password").value;

  if (!shareFile1 || !privkeyFile1 || !shareFile2 || !privkeyFile2) {
    showError(errorEl, t("restore.filesRequired"));
    return;
  }
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    showError(errorEl, t("common.passwordMinLength", { min: MIN_PASSWORD_LENGTH }));
    return;
  }
  if (estimatePasswordStrength(newPassword) === "faible") {
    showError(errorEl, t("common.passwordTooWeak"));
    return;
  }

  try {
    const [backup1_b64, privkey1_armored_b64, backup2_b64, privkey2_armored_b64] = await Promise.all([
      readFileAsBase64(shareFile1),
      readFileAsBase64(privkeyFile1),
      readFileAsBase64(shareFile2),
      readFileAsBase64(privkeyFile2),
    ]);

    const addresses = await invoke("restore_wallet", {
      newPassword,
      backup1B64: backup1_b64,
      privkey1ArmoredB64: privkey1_armored_b64,
      passphrase1,
      backup2B64: backup2_b64,
      privkey2ArmoredB64: privkey2_armored_b64,
      passphrase2,
    });

    renderDashboardAddresses(singleProfileList(addresses));
    showView("dashboard");
    refreshAllBalances();
    startBalanceAutoRefresh();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("restore-new-password").value = "";
    document.getElementById("restore-passphrase-1").value = "";
    document.getElementById("restore-passphrase-2").value = "";
  }
}));

// --- Dashboard ---------------------------------------------------------

let balanceRefreshTimer = null;

// Rafraîchit les soldes toutes les 15s tant que le tableau de bord est ouvert,
// pour que les montants suivent les changements réels sur la blockchain sans
// action manuelle. Arrêté au verrouillage/réinitialisation pour ne pas laisser
// tourner des appels réseau en arrière-plan une fois le wallet quitté. Les prix
// (voir plus bas) suivent le même cycle de vie, avec un intervalle plus long : ce
// sont des cours de marché, pas des montants qui bougent à chaque bloc, et l'API
// publique utilisée (CoinGecko, gratuite) a une limite de requêtes par minute.
function startBalanceAutoRefresh() {
  stopBalanceAutoRefresh();
  balanceRefreshTimer = setInterval(refreshAllBalances, 15000);
  startPriceAutoRefresh();
}

function stopBalanceAutoRefresh() {
  stopPriceAutoRefresh();
  if (balanceRefreshTimer) {
    clearInterval(balanceRefreshTimer);
    balanceRefreshTimer = null;
  }
}

// --- Prix indicatifs (USD) --------------------------------------------------
// Purement informatif (voir core/src/price_rpc.rs) : aucune donnée sur l'adresse
// ou le solde de l'utilisateur n'est envoyée à ce service, juste "quel est le prix
// actuel de l'ETH/BTC/SOL" — identique pour tout le monde.

let latestPrices = null;
let priceRefreshTimer = null;
let pricesRefreshing = false;

function priceForCoin(coin) {
  // USDC est un stablecoin indexé sur le dollar : pas d'appel de prix
  // nécessaire, toujours ~1 $ — évite un cas particulier dans
  // updateFiatValue/renderQuickAmounts pour ce seul actif.
  if (coin === "usdc") return 1;
  if (!latestPrices) return null;
  if (coin === "evm") return latestPrices.eth_usd;
  if (coin === "btc") return latestPrices.btc_usd;
  if (coin === "sol") return latestPrices.sol_usd;
  return null;
}

function updateFiatValue(card) {
  const fiatEl = card.querySelector('[data-field="fiat"]');
  if (!fiatEl) return;
  const price = priceForCoin(card.dataset.coin);
  const balance = Number.parseFloat(card.querySelector('[data-field="balance"]').textContent);
  if (price == null || Number.isNaN(balance)) {
    fiatEl.textContent = "—";
    return;
  }
  const value = (balance * price).toLocaleString("fr-FR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  fiatEl.textContent = `≈ ${value} $`;
}

async function refreshPrices() {
  // Même logique de verrou que refreshBalance : évite qu'un cycle lent (CoinGecko
  // limite le débit gratuit) ne se fasse recouvrir par le tick suivant du minuteur.
  if (pricesRefreshing) return;
  pricesRefreshing = true;
  try {
    try {
      latestPrices = await invoke("get_crypto_prices");
    } catch (e) {
      console.error(e);
      latestPrices = null;
    }
    document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
    await loadMarkets();
    // Garde les montants rapides de la modale d'envoi synchronisés avec le cours si
    // elle reste ouverte pendant un cycle de rafraîchissement (toutes les 60s, voir
    // startPriceAutoRefresh) — sans ça, un montant rapide cliqué plus tard dans une
    // session longue refléterait un prix périmé.
    if (!sendModal.classList.contains("hidden")) renderQuickAmounts();
  } finally {
    pricesRefreshing = false;
  }
}

function formatMarketCap(value) {
  if (value >= 1e12) return `${(value / 1e12).toLocaleString("fr-FR", { maximumFractionDigits: 2 })} T$`;
  if (value >= 1e9) return `${(value / 1e9).toLocaleString("fr-FR", { maximumFractionDigits: 2 })} Md$`;
  if (value >= 1e6) return `${(value / 1e6).toLocaleString("fr-FR", { maximumFractionDigits: 2 })} M$`;
  return `${value.toLocaleString("fr-FR")} $`;
}

// Déjà triée par capitalisation décroissante côté Rust (voir
// core/src/price_rpc.rs::get_market_data) : le frontend affiche l'ordre reçu tel
// quel, sans re-trier.
async function loadMarkets() {
  const container = document.getElementById("markets-list");
  try {
    const coins = await invoke("get_market_prices");
    container.innerHTML = "";
    coins.forEach((coin) => {
      const row = document.createElement("div");
      row.className = "market-row";

      const nameDiv = document.createElement("div");
      nameDiv.className = "market-name";
      nameDiv.textContent = coin.name;
      const symbolSpan = document.createElement("span");
      symbolSpan.className = "market-symbol";
      symbolSpan.textContent = coin.symbol;
      nameDiv.appendChild(symbolSpan);

      const figures = document.createElement("div");
      figures.className = "market-figures";
      const priceDiv = document.createElement("div");
      priceDiv.className = "market-price";
      priceDiv.textContent = coin.price_usd.toLocaleString("fr-FR", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + " $";
      const capDiv = document.createElement("div");
      capDiv.className = "market-cap";
      capDiv.textContent = formatMarketCap(coin.market_cap_usd);

      const changeDiv = document.createElement("div");
      changeDiv.className = "market-change";
      if (coin.change_24h_percent == null) {
        changeDiv.textContent = "—";
      } else {
        const isUp = coin.change_24h_percent >= 0;
        changeDiv.classList.add(isUp ? "up" : "down");
        const arrow = isUp ? "▲" : "▼";
        changeDiv.textContent = `${arrow} ${Math.abs(coin.change_24h_percent).toFixed(2)} %`;
      }

      figures.appendChild(changeDiv);
      figures.appendChild(priceDiv);
      figures.appendChild(capDiv);

      row.appendChild(nameDiv);
      row.appendChild(figures);
      container.appendChild(row);
    });
  } catch (e) {
    container.innerHTML = `<p class="muted">${t("wallet.marketsLoadError")}</p>`;
    console.error(e);
  }
}

function startPriceAutoRefresh() {
  stopPriceAutoRefresh();
  refreshPrices();
  priceRefreshTimer = setInterval(refreshPrices, 30000);
}

function stopPriceAutoRefresh() {
  if (priceRefreshTimer) {
    clearInterval(priceRefreshTimer);
    priceRefreshTimer = null;
  }
}

const coinConfig = {
  evm: { defaultNetwork: "evm_mainnet" },
  btc: { defaultNetwork: "btc_mainnet" },
  sol: { defaultNetwork: "sol_mainnet" },
  // USDC (jeton SPL sur Solana, pas un réseau à part) : mainnet uniquement en
  // v1 (voir core/src/sol_spl.rs), jamais devnet.
  usdc: { defaultNetwork: "sol_mainnet" },
};

// Un "profil" = un index de dérivation supplémentaire sur la même clé maîtresse
// (voir core/src/api.rs) : plusieurs adresses par réseau, toujours protégées par
// le même Shamir 2-sur-3 + PGP. `create_wallet`/`restore_wallet` ne renvoient
// qu'un seul jeu d'adresses (un seul profil existe à ce moment-là) ; on
// l'enveloppe dans le même format de liste que `unlock_wallet`/`create_profile`
// pour que le reste du tableau de bord n'ait qu'une seule forme de données à gérer.
function singleProfileList(addresses, label = "Principal") {
  return [{ index: 0, label, addresses }];
}

let profilesCache = [];
let currentProfileIndex = 0;

function currentProfile() {
  return profilesCache.find((p) => p.index === currentProfileIndex) || profilesCache[0] || null;
}

// `network` ne sert qu'à Bitcoin : mainnet et testnet dérivent des adresses
// DIFFÉRENTES pour un même profil (voir core/src/derivation.rs), contrairement à
// EVM/Solana où la même adresse sert sur toutes les variantes du réseau — pour ces
// deux-là, le paramètre est ignoré.
function addressForCoin(coin, network) {
  const profile = currentProfile();
  // `addresses` est absent quand le profil a été créé sans mot de passe (voir
  // add-profile-confirm) : l'adresse n'est pas encore dérivée, elle apparaîtra
  // au prochain déverrouillage complet (voir core/src/api.rs::create_profile).
  if (!profile || !profile.addresses) return "";
  if (coin === "evm") return profile.addresses.evm;
  if (coin === "btc") return network === "btc_mainnet" ? profile.addresses.btc_mainnet : profile.addresses.btc_testnet;
  // USDC utilise la même adresse propriétaire que Solana (le compte de jetons
  // associé qui détient réellement l'USDC est un détail invisible pour
  // l'utilisateur, dérivé côté Rust — voir core/src/sol_spl.rs).
  if (coin === "sol" || coin === "usdc") return profile.addresses.solana;
  return "";
}

function renderProfileSelect() {
  const select = document.getElementById("profile-select");
  select.innerHTML = "";
  profilesCache.forEach((p) => {
    const option = document.createElement("option");
    option.value = String(p.index);
    option.textContent = p.addresses ? p.label : `${p.label} (déverrouillez pour voir l'adresse)`;
    select.appendChild(option);
  });
  select.value = String(currentProfileIndex);
  syncCustomSelect(select);
}

function renderCardAddress(card) {
  const coin = card.dataset.coin;
  card.querySelector('[data-field="address"]').textContent = addressForCoin(coin, networkForCard(card));
}

function renderCardAddresses() {
  document.querySelectorAll(".wallet-card").forEach(renderCardAddress);
}

function renderDashboardAddresses(profiles) {
  profilesCache = profiles;
  currentProfileIndex = profiles[0] ? profiles[0].index : 0;
  renderProfileSelect();
  renderCardAddresses();
}

document.getElementById("profile-select").addEventListener("change", (e) => {
  currentProfileIndex = Number(e.target.value);
  renderCardAddresses();
  refreshAllBalances();
});

document.getElementById("add-profile-btn").addEventListener("click", () => {
  document.getElementById("add-profile-label").value = "";
  document.getElementById("add-profile-password").value = "";
  hideError(document.getElementById("add-profile-error"));
  document.getElementById("add-profile-modal").classList.remove("hidden");
});

document.getElementById("add-profile-cancel").addEventListener("click", () => {
  document.getElementById("add-profile-modal").classList.add("hidden");
  document.getElementById("add-profile-password").value = "";
});

const addProfileConfirmBtn = document.getElementById("add-profile-confirm");
addProfileConfirmBtn.addEventListener("click", withBusyButton(addProfileConfirmBtn, async () => {
  const errorEl = document.getElementById("add-profile-error");
  hideError(errorEl);
  const label = document.getElementById("add-profile-label").value.trim();
  const password = document.getElementById("add-profile-password").value;

  if (!label) {
    showError(errorEl, t("addProfile.nameRequired"));
    return;
  }

  try {
    // Mot de passe optionnel : sans lui, le profil (nom + index) est enregistré tout
    // de suite, mais son adresse n'est dérivée qu'au prochain déverrouillage complet
    // (la seed n'est jamais mise en cache, voir core/src/api.rs::create_profile).
    const profile = await invoke("create_profile", { password: password || null, label });
    profilesCache.push(profile);
    currentProfileIndex = profile.index;
    renderProfileSelect();
    renderCardAddresses();
    document.getElementById("add-profile-modal").classList.add("hidden");
    refreshAllBalances();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("add-profile-password").value = "";
  }
}));

// --- Archivage de profil (léger, réversible) --------------------------------
// Contrairement à la suppression définitive (plus bas), archiver ne touche jamais
// à la seed et ne demande pas de mot de passe : le profil disparaît juste du
// sélecteur principal, mais reste entièrement récupérable depuis "Profils
// archivés" dans les Paramètres (voir core/src/api.rs::archive_profile). C'est le
// chemin par défaut proposé à l'utilisateur ; la suppression définitive n'est
// accessible que depuis la liste des archives, jamais directement ici.
const archiveProfileBtn = document.getElementById("archive-profile-btn");
archiveProfileBtn.addEventListener("click", withBusyButton(archiveProfileBtn, async () => {
  if (profilesCache.length <= 1) {
    alert(t("wallet.cannotArchiveLastProfile"));
    return;
  }
  const profile = currentProfile();
  if (!profile) return;

  const sure = confirm(t("wallet.archiveConfirm", { label: profile.label }));
  if (!sure) return;

  try {
    await invoke("archive_profile", { index: profile.index });
    profilesCache = profilesCache.filter((p) => p.index !== profile.index);
    currentProfileIndex = profilesCache[0].index;
    renderProfileSelect();
    renderCardAddresses();
    refreshAllBalances();
  } catch (e) {
    alert(t("common.error", { err: e }));
  }
}));

// --- Profils archivés (Paramètres) : restaurer ou supprimer définitivement -----

async function loadArchivedProfiles() {
  const container = document.getElementById("archived-profiles-list");
  try {
    const archived = await invoke("list_archived_profiles");
    container.innerHTML = "";
    if (archived.length === 0) {
      container.innerHTML = `<p class="muted">${t("wallet.noArchivedProfile")}</p>`;
      return;
    }
    archived.forEach((profile) => {
      const item = document.createElement("div");
      item.className = "recipient-item";

      const labelDiv = document.createElement("div");
      labelDiv.className = "recipient-label";
      labelDiv.textContent = profile.label;

      const restoreBtn = document.createElement("button");
      restoreBtn.className = "secondary";
      restoreBtn.textContent = t("wallet.restoreProfile");
      restoreBtn.addEventListener("click", async () => {
        try {
          await invoke("unarchive_profile", { index: profile.index });
          // L'adresse du profil restauré n'est pas connue tant que le mot de passe
          // n'a pas été retapé (même principe que `create_profile` sans mot de
          // passe) : elle apparaîtra au prochain déverrouillage complet.
          profilesCache.push({ index: profile.index, label: profile.label, addresses: null });
          currentProfileIndex = profile.index;
          renderProfileSelect();
          renderCardAddresses();
          loadArchivedProfiles();
        } catch (e) {
          alert(t("common.error", { err: e }));
        }
      });

      const deleteBtn = document.createElement("button");
      deleteBtn.className = "secondary";
      deleteBtn.textContent = t("wallet.deleteProfileForever");
      deleteBtn.addEventListener("click", () => openDeleteProfileModal(profile));

      const actions = document.createElement("div");
      actions.className = "item-actions";
      actions.appendChild(restoreBtn);
      actions.appendChild(deleteBtn);

      item.appendChild(labelDiv);
      item.appendChild(actions);
      container.appendChild(item);
    });
  } catch (e) {
    console.error(e);
  }
}

// Contrairement à l'archivage, cette suppression est irréversible et redemande le
// mot de passe : l'app n'offre aucun moyen de recréer un profil au même index plus
// tard, donc supprimer un profil qui a déjà reçu des fonds en perd concrètement
// l'accès depuis cette interface (voir core/src/api.rs::delete_profile). Le
// message d'avertissement le dit explicitement plutôt que de rassurer à tort.
// Volontairement accessible SEULEMENT depuis la liste des archives (pas
// directement sur un profil actif) : on doit d'abord archiver avant de pouvoir
// supprimer pour de bon, comme une corbeille.
let profileToDelete = null;

function openDeleteProfileModal(profile) {
  profileToDelete = profile;
  document.getElementById("delete-profile-warning").textContent = t("deleteProfile.warning", { label: profile.label });
  document.getElementById("delete-profile-password").value = "";
  hideError(document.getElementById("delete-profile-error"));
  document.getElementById("delete-profile-modal").classList.remove("hidden");
}

document.getElementById("delete-profile-cancel").addEventListener("click", () => {
  document.getElementById("delete-profile-modal").classList.add("hidden");
  document.getElementById("delete-profile-password").value = "";
  profileToDelete = null;
});

const deleteProfileConfirmBtn = document.getElementById("delete-profile-confirm");
deleteProfileConfirmBtn.addEventListener("click", withBusyButton(deleteProfileConfirmBtn, async () => {
  if (!profileToDelete) return;
  const errorEl = document.getElementById("delete-profile-error");
  hideError(errorEl);
  const password = document.getElementById("delete-profile-password").value;

  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }

  try {
    await invoke("delete_profile", { password, index: profileToDelete.index });
    document.getElementById("delete-profile-modal").classList.add("hidden");
    profileToDelete = null;
    loadArchivedProfiles();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("delete-profile-password").value = "";
  }
}));

function networkForCard(card) {
  const select = card.querySelector(".network-select");
  if (select) return select.value;
  return coinConfig[card.dataset.coin].defaultNetwork;
}

async function refreshBalance(card) {
  // Verrou par carte, partagé entre le clic manuel (bouton "Actualiser") et le
  // rafraîchissement automatique (setInterval, toutes les 15s) : sans lui, un appel
  // réseau qui dépasse 15s (fréquent sur des endpoints publics gratuits) se ferait
  // recouvrir par le tick suivant, empilant des requêtes concurrentes pour la même
  // carte — même symptôme de lag qu'un double-clic, mais déclenché par le minuteur.
  if (card.dataset.refreshing === "1") return;
  card.dataset.refreshing = "1";
  try {
    const coin = card.dataset.coin;
    const network = networkForCard(card);
    const address = addressForCoin(coin, network);
    const balanceEl = card.querySelector('[data-field="balance"]');
    balanceEl.textContent = "…";
    // Le solde et l'indicateur "transaction en attente" sont deux appels
    // indépendants (l'un ne dépend pas du résultat de l'autre) : les lancer en
    // parallèle plutôt que l'un après l'autre coupe la latence perçue du
    // rafraîchissement en deux.
    // USDC est un jeton SPL, pas un "réseau" au sens où get_balance l'entend
    // (pas de notion de décimales/mint par actif dans cette commande) : une
    // commande dédiée, voir core/src/api.rs::get_usdc_balance.
    const balanceCommand = coin === "usdc" ? "get_usdc_balance" : "get_balance";
    const balancePromise = invoke(balanceCommand, { network, address })
      .then((balance) => {
        balanceEl.textContent = balance;
      })
      .catch((e) => {
        balanceEl.textContent = t("wallet.balanceError");
        console.error(e);
      });
    const pendingPromise = checkPendingTx(card, address, network);
    await Promise.all([balancePromise, pendingPromise]);
    updateFiatValue(card);
  } finally {
    card.dataset.refreshing = "";
  }
}

// Signale une transaction détectée mais pas encore finalisée (mempool Bitcoin,
// signature Solana pas encore "finalized") — utile pour voir des fonds entrants
// arriver avant qu'ils ne comptent dans le solde. Toujours `false` pour Ethereum
// (voir core/src/api.rs::has_pending_btc/has_pending_sol) : aucun nœud EVM public
// n'expose les transactions en attente pour une adresse, le badge ne s'allumera
// donc jamais sur les cartes ETH — pas un bug, une limite du réseau public utilisé.
async function checkPendingTx(card, address, network) {
  const badge = card.querySelector('[data-field="pending"]');
  if (!badge || !address) return;
  try {
    const pending = await invoke("has_pending_tx", { network, address });
    badge.classList.toggle("visible", pending);
  } catch (e) {
    console.error(e);
  }
}

function refreshAllBalances() {
  document.querySelectorAll(".wallet-card").forEach(refreshBalance);
}

document.querySelectorAll(".wallet-card").forEach((card) => {
  const refreshBtn = card.querySelector('[data-action="refresh"]');
  refreshBtn.addEventListener("click", withThrottledButton(refreshBtn, REFRESH_COOLDOWN_MS, () => refreshBalance(card)));
  card.querySelector('[data-action="send"]').addEventListener("click", () => openSendModal(card));
  card.querySelector('[data-action="qr"]').addEventListener("click", () => openQrModal(card));
  // Cliquer l'adresse elle-même l'affiche en entier (même modale que le bouton QR,
  // qui montre déjà le texte complet à côté du code QR) — utile surtout en vue
  // liste (voir styles.css : `.address` y est tronquée avec "…" pour la
  // compacité), mais garde le même geste en vue cartes aussi, par cohérence.
  card.querySelector('[data-field="address"]').addEventListener("click", () => openQrModal(card));
  card.querySelector('[data-action="copy-address"]').addEventListener("click", () => {
    const address = card.querySelector('[data-field="address"]').textContent;
    if (!address) {
      alert(t("wallet.historyAddressUnavailable"));
      return;
    }
    copyText(address, t("wallet.addressCopied"));
  });
  const swapBtn = card.querySelector('[data-action="swap"]');
  if (swapBtn) swapBtn.addEventListener("click", () => openSwapModal(card));
  const select = card.querySelector(".network-select");
  if (select) {
    // Contrairement à EVM/Solana, changer de réseau Bitcoin change aussi l'adresse
    // affichée (mainnet et testnet dérivent des adresses différentes pour un même
    // profil, voir addressForCoin) — recalculée pour toutes les cartes sans risque,
    // puisqu'elle ne change de valeur que pour "btc".
    select.addEventListener("change", () => {
      renderCardAddress(card);
      refreshBalance(card);
    });
  }
});

// --- QR modal --------------------------------------------------------------

const qrModal = document.getElementById("qr-modal");

async function openQrModal(card) {
  const address = addressForCoin(card.dataset.coin, networkForCard(card));
  if (!address) {
    alert(t("wallet.historyAddressUnavailable"));
    return;
  }
  try {
    const svg = await invoke("generate_qr_svg", { text: address });
    document.getElementById("qr-container").innerHTML = svg;
    document.getElementById("qr-address-text").textContent = address;
    qrModal.classList.remove("hidden");
  } catch (e) {
    alert(t("wallet.qrError", { err: e }));
  }
}

document.getElementById("qr-close").addEventListener("click", () => {
  qrModal.classList.add("hidden");
});

// --- Historique de transactions (onglet dédié, trié par réseau) -------------
// Un réseau = une carte du tableau de bord (voir data-coin) : la carte reste
// la seule source de vérité pour "quel réseau/quelle adresse" (mainnet ou
// testnet, choisi via son sélecteur), l'onglet ne fait que relire cet état,
// jamais son propre choix de réseau séparé.

const HISTORY_COINS = ["evm", "btc", "sol", "usdc"];

function formatTxTimestamp(unixSeconds) {
  if (unixSeconds == null) return "en attente";
  return new Date(unixSeconds * 1000).toLocaleString("fr-FR");
}

function historyStatusLabel(status) {
  if (status === "confirmed") return t("wallet.historyConfirmed");
  if (status === "pending") return t("wallet.historyPending");
  if (status === "failed") return t("wallet.historyFailed");
  return status;
}

// "≈ 1 234,56 $" / "≈ $1,234.56" ; sous le centime : "< 0,01 $".
function formatUsdApprox(usd) {
  const english = currentLang === "en";
  if (usd > 0 && usd < 0.01) return english ? "< $0.01" : "< 0,01 $";
  const number = usd.toLocaleString(english ? "en-US" : "fr-FR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return english ? `≈ $${number}` : `≈ ${number} $`;
}

function buildHistoryRow(tx) {
  const row = document.createElement("div");
  row.className = "history-row";

  const left = document.createElement("div");
  left.className = "history-left";
  const idDiv = document.createElement("div");
  idDiv.className = "history-id";
  idDiv.textContent = tx.id;
  const meta = document.createElement("div");
  meta.className = "history-meta";
  const dateSpan = document.createElement("span");
  dateSpan.textContent = formatTxTimestamp(tx.timestamp_unix);
  const statusSpan = document.createElement("span");
  statusSpan.className = `history-status history-status-${tx.status}`;
  statusSpan.textContent = historyStatusLabel(tx.status);
  const kindKey = { received: "history.kindReceived", sent: "history.kindSent", swap: "history.kindSwap", other: "history.kindOther" }[tx.kind];
  if (kindKey) {
    const kindSpan = document.createElement("span");
    kindSpan.className = `history-kind history-kind-${tx.kind}`;
    kindSpan.textContent = t(kindKey);
    meta.appendChild(kindSpan);
  }
  meta.appendChild(dateSpan);
  meta.appendChild(statusSpan);
  left.appendChild(idDiv);
  left.appendChild(meta);

  const right = document.createElement("div");
  right.className = "history-right";
  const amountDiv = document.createElement("div");
  amountDiv.className = "history-amount";
  if (tx.amount != null) {
    // Montant nul (transaction « Autre ») : ni vert ni rouge.
    if (Number.parseFloat(tx.amount) !== 0) {
      amountDiv.classList.add(tx.amount.startsWith("-") ? "negative" : "positive");
    }
    amountDiv.textContent = tx.amount;
  } else {
    amountDiv.textContent = "—";
  }
  const amountBox = document.createElement("div");
  amountBox.className = "history-amount-box";
  amountBox.appendChild(amountDiv);
  // Valeur calculée côté Rust au prix du moment de la transaction (voir
  // core/src/price_history.rs) ; absente sur les réseaux de test.
  if (tx.usd_value != null) {
    const usdDiv = document.createElement("div");
    usdDiv.className = "history-usd";
    usdDiv.textContent = formatUsdApprox(tx.usd_value);
    usdDiv.title = t("history.usdAtTime");
    amountBox.appendChild(usdDiv);
  }
  // Un <a target="_blank"> classique ne s'ouvre pas de façon fiable dans la
  // webview Tauri (navigation interceptée pour raisons de sécurité) : on passe
  // par la commande dédiée qui ouvre le navigateur système (voir
  // app/src-tauri/src/lib.rs::open_external_link).
  const link = document.createElement("button");
  link.type = "button";
  link.className = "history-link";
  link.textContent = t("wallet.historyViewLink");
  link.addEventListener("click", () => {
    invoke("open_external_link", { url: tx.explorer_url }).catch((e) => alert(t("wallet.linkError", { err: e })));
  });
  right.appendChild(amountBox);
  right.appendChild(link);

  row.appendChild(left);
  row.appendChild(right);
  return row;
}

async function loadHistorySection(coin) {
  const card = document.querySelector(`.wallet-card[data-coin="${coin}"]`);
  const container = document.getElementById(`history-list-${coin}`);
  const networkEl = document.getElementById(`history-network-${coin}`);
  if (!card || !container || !networkEl) return;

  const network = networkForCard(card);
  const address = addressForCoin(coin, network);
  networkEl.textContent = networkLabelForCard(card);
  container.innerHTML = `<p class="muted">${t("wallet.historyLoading")}</p>`;

  if (!address) {
    container.innerHTML = `<p class="muted">${t("wallet.historyAddressUnavailable")}</p>`;
    return;
  }

  try {
    // USDC (jeton SPL) lit preTokenBalances/postTokenBalances via l'ATA du
    // propriétaire plutôt que preBalances/postBalances de l'adresse elle-même
    // (voir core/src/sol_rpc.rs::token_signature_history) : commande dédiée,
    // comme pour le solde et l'envoi. Mainnet uniquement (sol_spl.rs).
    const entries =
      coin === "usdc"
        ? await invoke("get_usdc_tx_history", { network: "sol_mainnet", address })
        : await invoke("get_tx_history", { network, address });
    container.innerHTML = "";
    if (entries.length === 0) {
      container.innerHTML = `<p class="muted">${t("wallet.historyEmpty")}</p>`;
      return;
    }
    entries.forEach((tx) => container.appendChild(buildHistoryRow(tx)));
  } catch (e) {
    // textContent, jamais innerHTML : le message d'erreur vient de Rust, qui y
    // recopie le JSON d'erreur renvoyé par le serveur RPC — un serveur
    // malveillant aurait pu y glisser du HTML (faux formulaire, lien de
    // phishing) directement dans l'interface du wallet.
    container.replaceChildren(mutedParagraph(String(e)));
  }
}

function mutedParagraph(text) {
  const p = document.createElement("p");
  p.className = "muted";
  p.textContent = text;
  return p;
}

function loadAllHistory() {
  HISTORY_COINS.forEach(loadHistorySection);
}

document.getElementById("refresh-history-btn").addEventListener("click", loadAllHistory);

// --- Send modal ----------------------------------------------------------

const sendModal = document.getElementById("send-modal");
let sendContext = null;

// N'accepte que des chiffres et un séparateur décimal (point ou virgule) : un
// montant à envoyer ne peut structurellement rien contenir d'autre, autant
// l'empêcher à la frappe plutôt que de laisser taper "dqdz" et le rejeter
// après coup. Un seul séparateur gardé (le premier), les suivants supprimés,
// pour empêcher "1.2.3" ou "1,2,3".
const sendAmountInput = document.getElementById("send-amount");
sendAmountInput.addEventListener("input", () => {
  let value = sendAmountInput.value.replace(/[^0-9.,]/g, "");
  const separatorIndex = value.search(/[.,]/);
  if (separatorIndex !== -1) {
    value = value.slice(0, separatorIndex + 1) + value.slice(separatorIndex + 1).replace(/[.,]/g, "");
  }
  if (value !== sendAmountInput.value) {
    sendAmountInput.value = value;
  }
});

// Montants rapides en dollars : convertis en crypto au prix en direct (voir
// `latestPrices`/`refreshPrices`), pas des montants fixes en ETH/BTC/SOL — ça n'a
// de sens que si le montant en dollars reste identique quel que soit le cours du
// jour. Mêmes décimales que le formatage des soldes côté Rust
// (app/src-tauri/src/lib.rs::get_balance), pour que le montant rempli soit celui
// réellement envoyé, pas une valeur arrondie différente.
const QUICK_AMOUNTS_USD = [5, 10, 50];
const COIN_DECIMALS = { evm: 6, btc: 8, sol: 9, usdc: 6 };
const COIN_SYMBOL = { evm: "ETH", btc: "BTC", sol: "SOL", usdc: "USDC" };

function renderQuickAmounts() {
  const container = document.getElementById("send-quick-amounts");
  container.innerHTML = "";
  if (!sendContext) return;
  const coin = sendContext.coin;
  const price = priceForCoin(coin);
  const decimals = COIN_DECIMALS[coin];
  const symbol = COIN_SYMBOL[coin];

  if (price == null) {
    container.innerHTML = '<p class="muted quick-amounts-hint">Montants rapides indisponibles (prix non chargé).</p>';
    return;
  }

  QUICK_AMOUNTS_USD.forEach((usd) => {
    const cryptoAmount = (usd / price).toFixed(decimals);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-amount-btn";
    const usdSpan = document.createElement("span");
    usdSpan.className = "quick-amount-usd";
    usdSpan.textContent = `${usd} $`;
    const cryptoSpan = document.createElement("span");
    cryptoSpan.className = "quick-amount-crypto";
    cryptoSpan.textContent = `≈ ${cryptoAmount} ${symbol}`;
    btn.appendChild(usdSpan);
    btn.appendChild(cryptoSpan);
    btn.addEventListener("click", () => {
      document.getElementById("send-amount").value = cryptoAmount;
    });
    container.appendChild(btn);
  });
}

// Pourcentages du solde actuellement affiché sur la carte (pas un nouvel appel
// réseau : réutilise `[data-field="balance"]`, déjà tenu à jour par
// refreshBalance). Pas de déduction de frais réseau pour "Max" (100 %) : les
// frais sont estimés différemment par réseau (sat/vB pour Bitcoin, gas pour
// EVM, frais fixe pour Solana) et le backend refuse déjà clairement l'envoi
// AVANT toute diffusion si le solde restant ne couvre pas les frais (voir
// api.rs::send_sol/send_btc/send_evm/send_usdc) — pas la peine de deviner ici
// un montant de frais qu'on ne peut pas garantir exact.
const QUICK_PERCENTAGES = [25, 50, 100];

function renderQuickPercentages() {
  const container = document.getElementById("send-quick-percentages");
  container.innerHTML = "";
  if (!sendContext) return;
  const balance = Number.parseFloat(sendContext.card.querySelector('[data-field="balance"]').textContent);
  const decimals = COIN_DECIMALS[sendContext.coin];
  const symbol = COIN_SYMBOL[sendContext.coin];

  if (!Number.isFinite(balance) || balance <= 0) {
    container.innerHTML = `<p class="muted quick-amounts-hint">${t("send.percentUnavailable")}</p>`;
    return;
  }

  QUICK_PERCENTAGES.forEach((percent) => {
    const cryptoAmount = ((balance * percent) / 100).toFixed(decimals);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-amount-btn";
    const percentSpan = document.createElement("span");
    percentSpan.className = "quick-amount-usd";
    percentSpan.textContent = percent === 100 ? t("send.percentMax") : `${percent}%`;
    const cryptoSpan = document.createElement("span");
    cryptoSpan.className = "quick-amount-crypto";
    cryptoSpan.textContent = `≈ ${cryptoAmount} ${symbol}`;
    btn.appendChild(percentSpan);
    btn.appendChild(cryptoSpan);
    btn.addEventListener("click", () => {
      document.getElementById("send-amount").value = cryptoAmount;
    });
    container.appendChild(btn);
  });
}

function openSendModal(card) {
  // Le profil source est figé à l'ouverture (`sendContext.profileIndex`) plutôt que
  // relu depuis `currentProfileIndex` au moment de confirmer : la modale plein écran
  // empêche déjà de changer de profil pendant qu'elle est ouverte, mais figer la
  // valeur explicitement évite de dépendre de cet effet de bord d'affichage pour une
  // garantie de sécurité (quel profil signe la transaction).
  const profile = currentProfile();
  sendContext = { coin: card.dataset.coin, card, profileIndex: profile ? profile.index : currentProfileIndex };
  const network = networkForCard(card);
  document.getElementById("send-modal-title").textContent = `Envoyer (${card.querySelector("h2").textContent})`;
  document.getElementById("send-from-profile").textContent = profile ? profile.label : "—";
  document.getElementById("send-mainnet-warning").classList.toggle("hidden", !network.endsWith("mainnet"));
  document.getElementById("send-to").value = "";
  document.getElementById("send-amount").value = "";
  document.getElementById("send-password").value = "";
  hideError(document.getElementById("send-error"));
  document.getElementById("send-success").classList.add("hidden");
  renderQuickAmounts();
  renderQuickPercentages();
  loadBtcFeeOptions(card, network);
  sendModal.classList.remove("hidden");
  loadAddressBook().then(() => refreshSendAddressBookPicker(card.dataset.coin));
}

// Bitcoin est le seul réseau où les frais sont un choix explicite de l'utilisateur
// (voir core/src/api.rs::estimate_btc_fees) : EVM/Solana calculent déjà les leurs
// automatiquement (gas price / frais de base réseau), rien à proposer pour eux.
async function loadBtcFeeOptions(card, network) {
  const block = document.getElementById("send-fee-block");
  const container = document.getElementById("send-fee-options");
  sendContext.feeSat = null;

  if (card.dataset.coin !== "btc") {
    block.classList.add("hidden");
    return;
  }
  block.classList.remove("hidden");
  container.innerHTML = `<p class="muted">${t("wallet.feeCalculating")}</p>`;

  const address = addressForCoin("btc", network);
  if (!address) {
    container.innerHTML = `<p class="muted">${t("wallet.feeAddressUnavailable")}</p>`;
    return;
  }

  try {
    const fees = await invoke("estimate_btc_fees", { network, address });
    const tiers = [
      { key: "fast_sat", label: t("wallet.feeFast"), hint: t("wallet.feeFastHint") },
      { key: "medium_sat", label: t("wallet.feeMedium"), hint: t("wallet.feeMediumHint") },
      { key: "slow_sat", label: t("wallet.feeSlow"), hint: t("wallet.feeSlowHint") },
    ];
    container.innerHTML = "";
    tiers.forEach((tier, index) => {
      const sat = fees[tier.key];
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "fee-option-btn";

      const labelSpan = document.createElement("span");
      labelSpan.className = "fee-option-label";
      labelSpan.textContent = tier.label;
      const hintSpan = document.createElement("span");
      hintSpan.className = "fee-option-hint";
      hintSpan.textContent = tier.hint;
      const satSpan = document.createElement("span");
      satSpan.className = "fee-option-sat";
      satSpan.textContent = `${sat} sat`;
      btn.appendChild(labelSpan);
      btn.appendChild(hintSpan);
      btn.appendChild(satSpan);

      btn.addEventListener("click", () => {
        container.querySelectorAll(".fee-option-btn").forEach((b) => b.classList.remove("selected"));
        btn.classList.add("selected");
        sendContext.feeSat = sat;
      });

      // "Moyen" présélectionné : compromis raisonnable par défaut, l'utilisateur
      // reste libre de choisir plus rapide/moins cher avant de confirmer.
      if (index === 1) {
        btn.classList.add("selected");
        sendContext.feeSat = sat;
      }
      container.appendChild(btn);
    });
  } catch (e) {
    // Même raison que dans loadHistorySection : texte d'erreur venant d'un
    // serveur tiers (Esplora), jamais interprété comme du HTML.
    container.replaceChildren(mutedParagraph(t("wallet.feeUnavailable", { err: e })));
  }
}

document.getElementById("send-cancel").addEventListener("click", () => {
  sendModal.classList.add("hidden");
  sendContext = null;
});

function networkLabelForCard(card) {
  var label = card.querySelector(".custom-select-label") || card.querySelector(".network-fixed-label");
  return label ? label.textContent.trim() : networkForCard(card);
}

const sendPreviewModal = document.getElementById("send-preview-modal");

// Étape 1 : valide les champs puis affiche un aperçu stylé (réseau,
// destinataire, montant, frais) — pas encore d'appel réseau ni de secret
// impliqué ici, juste relire ce qui est déjà dans le formulaire.
const sendConfirmBtn = document.getElementById("send-confirm");
sendConfirmBtn.addEventListener("click", () => {
  if (!sendContext) return;
  const errorEl = document.getElementById("send-error");
  const successEl = document.getElementById("send-success");
  hideError(errorEl);
  successEl.classList.add("hidden");

  const to = document.getElementById("send-to").value.trim();
  const amount = document.getElementById("send-amount").value.trim().replace(",", ".");
  const password = document.getElementById("send-password").value;

  if (!to || !amount || !password) {
    showError(errorEl, t("wallet.allFieldsRequired"));
    return;
  }
  if (sendContext.coin === "btc" && !sendContext.feeSat) {
    showError(errorEl, t("wallet.btcFeesNotLoaded"));
    return;
  }

  document.getElementById("send-preview-network").textContent = networkLabelForCard(sendContext.card);
  document.getElementById("send-preview-from").textContent = document.getElementById("send-from-profile").textContent;
  document.getElementById("send-preview-to").textContent = to;
  document.getElementById("send-preview-amount").textContent = `${amount} ${COIN_SYMBOL[sendContext.coin]}`;

  const feeRow = document.getElementById("send-preview-fee-row");
  const selectedFeeBtn = document.querySelector("#send-fee-options .fee-option-btn.selected");
  if (sendContext.coin === "btc" && selectedFeeBtn) {
    // Les 3 <span> du bouton (label/indication/sat) n'ont pas d'espace entre
    // eux dans le DOM (juste juxtaposés visuellement en flex) : lus un par un
    // et rejoints ici plutôt que via `.textContent` global, qui les collerait
    // ("Rapide~10 min1240 sat" au lieu de "Rapide · ~10 min · 1240 sat").
    const parts = [".fee-option-label", ".fee-option-hint", ".fee-option-sat"]
      .map((sel) => selectedFeeBtn.querySelector(sel)?.textContent)
      .filter(Boolean);
    document.getElementById("send-preview-fee").textContent = parts.join(" · ");
    feeRow.classList.remove("hidden");
  } else {
    feeRow.classList.add("hidden");
  }

  sendPreviewModal.classList.remove("hidden");
});

document.getElementById("send-preview-back").addEventListener("click", () => {
  sendPreviewModal.classList.add("hidden");
});

// Étape 2 : c'est ICI, et seulement ici, que la vraie transaction part — la
// boîte de dialogue native de l'OS (confirm_transaction_native côté Rust,
// voir son commentaire) s'ouvre pendant cet appel et reste la seule
// protection réelle contre un frontend compromis. L'aperçu ci-dessus n'est
// qu'un résumé agréable à lire avant d'y arriver, jamais un remplacement.
const sendPreviewConfirmBtn = document.getElementById("send-preview-confirm");
sendPreviewConfirmBtn.addEventListener("click", withBusyButton(sendPreviewConfirmBtn, async () => {
  if (!sendContext) return;
  const errorEl = document.getElementById("send-error");
  const successEl = document.getElementById("send-success");

  const network = networkForCard(sendContext.card);
  const to = document.getElementById("send-to").value.trim();
  // La virgule est acceptée à la saisie (voir le filtre sur #send-amount plus
  // bas) mais les parseurs Rust (parse_btc_to_sat/parse_eth_to_wei/
  // parse_sol_to_lamports/parse_usdc_to_micros) n'acceptent qu'un point.
  const amount = document.getElementById("send-amount").value.trim().replace(",", ".");
  const password = document.getElementById("send-password").value;

  sendPreviewModal.classList.add("hidden");

  try {
    // USDC (jeton SPL) suit un chemin dédié, distinct de send_transaction :
    // pas de "network" à transmettre (mainnet uniquement, voir sol_spl.rs) ni
    // de frais Bitcoin-style, et la construction de la transaction elle-même
    // est entièrement différente côté Rust (deux instructions au lieu d'une).
    const txResult = sendContext.coin === "usdc"
      ? await invoke("send_usdc_transaction", { password, to, amount, profileIndex: sendContext.profileIndex })
      : await invoke("send_transaction", {
          network,
          password,
          to,
          amount,
          feeSat: sendContext.coin === "btc" ? sendContext.feeSat : null,
          profileIndex: sendContext.profileIndex,
        });
    successEl.textContent = t("send.txSent", { tx: txResult });
    successEl.classList.remove("hidden");
    refreshBalance(sendContext.card);
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("send-password").value = "";
  }
}));

// --- Swap (THORChain cross-chain + Jupiter même-chaîne) ---------------------
// Passe par un protocole externe non audité par cette app — THORChain pour
// un swap cross-chain (vers BTC/ETH, voir core/src/thorchain_rpc.rs), Jupiter
// pour SOL<->USDC dans le même portefeuille (voir core/src/jupiter_rpc.rs).
// Actifs source limités à SOL/USDC (le moins de nouveau code, voir le plan
// swap). Même principe en deux étapes que l'envoi normal (devis -> aperçu
// stylé -> confirmation native), sauf que le devis lui-même est déjà une
// étape réseau (donc pas juste une relecture du formulaire comme pour
// l'envoi).

const swapModal = document.getElementById("swap-modal");
const swapPreviewModal = document.getElementById("swap-preview-modal");
let swapContext = null;

// Options "Vers" possibles selon l'actif "Depuis" : depuis SOL, on peut viser
// BTC/ETH (cross-chain, via THORChain) ou USDC (même portefeuille, via
// Jupiter) ; depuis USDC, seul SOL a du sens (Jupiter uniquement — THORChain
// ne prend pas en charge un jeton SPL comme actif source dans cette v1) ;
// depuis BTC/ETH, uniquement cross-chain via THORChain vers les deux autres
// actifs natifs (pas de jeton SPL comme destination directe depuis une
// chaîne non-Solana).
const SWAP_TO_OPTIONS = {
  sol: [
    { value: "btc", key: "swap.toBtc", fallback: "Bitcoin (BTC)" },
    { value: "evm", key: "swap.toEth", fallback: "Ethereum (ETH)" },
    { value: "usdc", key: "swap.toUsdc", fallback: "USDC (via Jupiter, même portefeuille)" },
  ],
  usdc: [{ value: "sol", key: "swap.toSol", fallback: "Solana (SOL, via Jupiter, même portefeuille)" }],
  btc: [
    { value: "evm", key: "swap.toEth", fallback: "Ethereum (ETH)" },
    { value: "sol", key: "swap.toSolCrossChain", fallback: "Solana (SOL)" },
  ],
  evm: [
    { value: "btc", key: "swap.toBtc", fallback: "Bitcoin (BTC)" },
    { value: "sol", key: "swap.toSolCrossChain", fallback: "Solana (SOL)" },
  ],
};

function updateSwapToOptions() {
  const fromCoin = document.getElementById("swap-from-coin").value;
  const toSelect = document.getElementById("swap-to-coin");
  toSelect.innerHTML = "";
  SWAP_TO_OPTIONS[fromCoin].forEach((opt) => {
    const optionEl = document.createElement("option");
    optionEl.value = opt.value;
    optionEl.dataset.i18n = opt.key;
    optionEl.textContent = t(opt.key) || opt.fallback;
    toSelect.appendChild(optionEl);
  });
  syncCustomSelect(toSelect);

  document.getElementById("swap-amount-label").textContent = `${t("swap.amount")} (${COIN_SYMBOL[fromCoin]})`;
  updateSwapDestination();
}

document.getElementById("swap-from-coin").addEventListener("change", updateSwapToOptions);

function openSwapModal(card) {
  const profile = currentProfile();
  swapContext = { card, profileIndex: profile ? profile.index : currentProfileIndex };
  document.getElementById("swap-amount").value = "";
  hideError(document.getElementById("swap-error"));
  const fromSelect = document.getElementById("swap-from-coin");
  fromSelect.value = SWAP_TO_OPTIONS[card.dataset.coin] ? card.dataset.coin : "sol";
  syncCustomSelect(fromSelect);
  updateSwapToOptions();
  swapModal.classList.remove("hidden");
}

// USDC<->SOL (via Jupiter) reste dans le même portefeuille Solana : pas
// d'adresse de destination séparée à saisir, contrairement à un swap
// cross-chain (via THORChain, quels que soient les deux actifs impliqués)
// qui en a réellement besoin. Seule la paire {sol, usdc} passe par Jupiter —
// btc/evm impliqués d'un côté ou de l'autre sont TOUJOURS cross-chain.
function isJupiterSwap(fromCoin, toCoin) {
  const jupiterCoins = new Set(["sol", "usdc"]);
  return jupiterCoins.has(fromCoin) && jupiterCoins.has(toCoin);
}

function updateSwapDestination() {
  const fromCoin = document.getElementById("swap-from-coin").value;
  const toCoin = document.getElementById("swap-to-coin").value;
  const jupiter = isJupiterSwap(fromCoin, toCoin);
  document.getElementById("swap-destination-block").classList.toggle("hidden", jupiter);
  document.getElementById("swap-jupiter-hint").classList.toggle("hidden", !jupiter);
  if (!jupiter) {
    const network = toCoin === "btc" ? "btc_mainnet" : toCoin === "evm" ? "evm_mainnet" : "sol_mainnet";
    document.getElementById("swap-destination").value = addressForCoin(toCoin, network);
  }
}

document.getElementById("swap-to-coin").addEventListener("change", updateSwapDestination);

function closeSwapModal() {
  swapModal.classList.add("hidden");
  swapContext = null;
}

document.getElementById("swap-cancel").addEventListener("click", closeSwapModal);
document.getElementById("swap-close-x").addEventListener("click", closeSwapModal);
document.getElementById("swap-preview-close-x").addEventListener("click", () => {
  swapPreviewModal.classList.add("hidden");
  swapContext = null;
});

const swapQuoteBtn = document.getElementById("swap-quote-btn");
swapQuoteBtn.addEventListener("click", withBusyButton(swapQuoteBtn, async () => {
  if (!swapContext) return;
  const errorEl = document.getElementById("swap-error");
  hideError(errorEl);

  const fromCoin = document.getElementById("swap-from-coin").value;
  const toCoin = document.getElementById("swap-to-coin").value;
  const amount = document.getElementById("swap-amount").value.trim().replace(",", ".");
  const jupiter = isJupiterSwap(fromCoin, toCoin);
  const destination = jupiter ? "" : document.getElementById("swap-destination").value.trim();

  if (!amount || (!jupiter && !destination)) {
    showError(errorEl, t("wallet.allFieldsRequired"));
    return;
  }

  try {
    const destRow = document.getElementById("swap-preview-destination").closest(".send-preview-row");
    const feeRow = document.getElementById("swap-preview-fees").closest(".send-preview-row");
    let receivingText;
    if (jupiter) {
      const outAmount = await invoke("get_jupiter_quote", { fromCoin, toCoin, amount });
      receivingText = `≈ ${outAmount} ${COIN_SYMBOL[toCoin] || toCoin.toUpperCase()}`;
      destRow.classList.add("hidden");
      feeRow.classList.add("hidden");
    } else {
      const quote = await invoke("get_swap_quote", { fromCoin, toCoin, amount, destination });
      receivingText = `≈ ${quote.expected_amount_out} ${COIN_SYMBOL[toCoin] || toCoin.toUpperCase()}`;
      document.getElementById("swap-preview-fees").textContent = quote.total_fees != null ? quote.total_fees : "—";
      document.getElementById("swap-preview-destination").textContent = destination;
      destRow.classList.remove("hidden");
      feeRow.classList.remove("hidden");
    }

    document.getElementById("swap-preview-sending").textContent = `${amount} ${COIN_SYMBOL[fromCoin] || fromCoin.toUpperCase()}`;
    document.getElementById("swap-preview-receiving").textContent = receivingText;
    document.getElementById("swap-preview-password").value = "";
    hideError(document.getElementById("swap-preview-error"));
    document.getElementById("swap-success").classList.add("hidden");

    swapModal.classList.add("hidden");
    swapPreviewModal.classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

document.getElementById("swap-preview-back").addEventListener("click", () => {
  swapPreviewModal.classList.add("hidden");
  swapModal.classList.remove("hidden");
});

// Le devis affiché ici (aperçu) n'est qu'une estimation pour décider de
// continuer : `swap_transaction` en relit un tout nouveau côté Rust juste
// avant la confirmation native, jamais celui-ci (voir sa doc) — l'adresse de
// vault THORChain change régulièrement, un devis de quelques secondes peut
// déjà être périmé.
const swapPreviewConfirmBtn = document.getElementById("swap-preview-confirm");
swapPreviewConfirmBtn.addEventListener("click", withBusyButton(swapPreviewConfirmBtn, async () => {
  if (!swapContext) return;
  const errorEl = document.getElementById("swap-preview-error");
  const successEl = document.getElementById("swap-success");
  hideError(errorEl);
  successEl.classList.add("hidden");

  const fromCoin = document.getElementById("swap-from-coin").value;
  const toCoin = document.getElementById("swap-to-coin").value;
  const amount = document.getElementById("swap-amount").value.trim().replace(",", ".");
  const jupiter = isJupiterSwap(fromCoin, toCoin);
  const destination = jupiter ? "" : document.getElementById("swap-destination").value.trim();
  const password = document.getElementById("swap-preview-password").value;

  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }

  try {
    const txResult = jupiter
      ? await invoke("jupiter_swap_transaction", { password, fromCoin, toCoin, amount, profileIndex: swapContext.profileIndex })
      : await invoke("swap_transaction", {
          password,
          fromCoin,
          toCoin,
          amount,
          destination,
          profileIndex: swapContext.profileIndex,
        });
    successEl.textContent = t("send.txSent", { tx: txResult });
    successEl.classList.remove("hidden");
    // Un swap peut affecter le solde de PLUSIEURS cartes (source ET
    // destination si elle est aussi gérée par ce wallet, ex: SOL<->USDC) —
    // toutes rafraîchies plutôt que juste celle d'où le swap a été ouvert.
    refreshAllBalances();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("swap-preview-password").value = "";
  }
}));

// --- Certificat ------------------------------------------------------------

async function loadCertificate() {
  try {
    const info = await invoke("get_own_certificate");
    document.getElementById("cert-userid").textContent = info.user_id;
    document.getElementById("cert-fingerprint").textContent = info.fingerprint;
    document.getElementById("cert-keyid").textContent = info.key_id;
    document.getElementById("cert-armored").value = info.pubkey_armored;
  } catch (e) {
    console.error(e);
  }
}

document.getElementById("copy-cert").addEventListener("click", () => {
  copyText(document.getElementById("cert-armored").value);
});

// --- Message (destinataires + chiffrement) ---------------------------------

let recipientsCache = [];

async function loadRecipients() {
  try {
    recipientsCache = await invoke("list_recipients");
    renderRecipientList();
  } catch (e) {
    console.error(e);
  }
}

function renderRecipientList() {
  const container = document.getElementById("recipient-list");
  const picker = document.getElementById("message-recipients-picker");
  // On garde la sélection en cours (cases déjà cochées) d'un rafraîchissement à l'autre.
  const previouslyChecked = new Set(
    Array.from(picker.querySelectorAll("input[type=checkbox]:checked")).map((cb) => cb.value)
  );
  container.innerHTML = "";
  picker.innerHTML = "";

  if (recipientsCache.length === 0) {
    container.innerHTML = `<p class="muted">${t("message.noRecipientYet")}</p>`;
    picker.innerHTML = `<p class="muted">${t("message.addRecipientFirst")}</p>`;
    return;
  }

  recipientsCache.forEach((r) => {
    // `r.label` est saisi par l'utilisateur : on construit le DOM avec textContent
    // plutôt qu'un innerHTML avec interpolation, pour ne jamais l'interpréter comme
    // du HTML (même si la CSP stricte bloquerait déjà l'exécution d'un script injecté
    // ainsi, autant ne pas dépendre uniquement de ça).
    const item = document.createElement("div");
    item.className = "recipient-item";

    const labelDiv = document.createElement("div");
    labelDiv.className = "recipient-label";
    labelDiv.textContent = r.label;

    // Empreinte affichée pour permettre une vérification hors-ligne de l'identité
    // (voir le commentaire sur RecipientDto.fingerprint côté Rust) : sans ça, un
    // remplacement de la clé stockée localement passerait inaperçu.
    const fingerprintDiv = document.createElement("div");
    fingerprintDiv.className = "recipient-fp";
    fingerprintDiv.textContent = r.fingerprint;

    const infoDiv = document.createElement("div");
    infoDiv.className = "recipient-info";
    infoDiv.appendChild(labelDiv);
    infoDiv.appendChild(fingerprintDiv);

    const actionsDiv = document.createElement("div");
    actionsDiv.className = "item-actions";

    const viewKeyBtn = document.createElement("button");
    viewKeyBtn.className = "secondary";
    viewKeyBtn.textContent = t("recipientKey.view");
    viewKeyBtn.addEventListener("click", () => openRecipientKeyModal(r));

    const removeBtn = document.createElement("button");
    removeBtn.textContent = t("message.removeRecipient");
    removeBtn.addEventListener("click", async () => {
      await invoke("remove_recipient", { label: r.label });
      loadRecipients();
    });

    actionsDiv.appendChild(viewKeyBtn);
    actionsDiv.appendChild(removeBtn);
    item.appendChild(infoDiv);
    item.appendChild(actionsDiv);
    container.appendChild(item);

    const pickerItem = document.createElement("label");
    pickerItem.className = "recipient-picker-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = r.label;
    checkbox.checked = previouslyChecked.has(r.label);

    const pickerLabel = document.createElement("span");
    pickerLabel.textContent = r.label;

    pickerItem.appendChild(checkbox);
    pickerItem.appendChild(pickerLabel);
    picker.appendChild(pickerItem);
  });
}

// Consultation de la clé publique complète d'un destinataire déjà enregistré
// (identité/empreinte/identifiant de clé/texte ASCII-armor complet) — même
// gabarit que l'onglet Certificat pour la propre identité de l'appareil.
// Toutes les données viennent déjà de `recipientsCache` (voir RecipientDto
// côté Rust) : aucun nouvel appel Tauri nécessaire pour ouvrir cette modale.
function openRecipientKeyModal(recipient) {
  document.getElementById("recipient-key-label").textContent = recipient.label;
  document.getElementById("recipient-key-userid").textContent = recipient.user_id;
  document.getElementById("recipient-key-fingerprint").textContent = recipient.fingerprint;
  document.getElementById("recipient-key-keyid").textContent = recipient.key_id;
  document.getElementById("recipient-key-armored").value = recipient.pubkey_armored;
  document.getElementById("recipient-key-modal").classList.remove("hidden");
}

function closeRecipientKeyModal() {
  document.getElementById("recipient-key-modal").classList.add("hidden");
}

document.getElementById("recipient-key-close").addEventListener("click", closeRecipientKeyModal);
document.getElementById("recipient-key-copy").addEventListener("click", () => {
  copyText(document.getElementById("recipient-key-armored").value);
});

document.getElementById("show-add-recipient").addEventListener("click", () => {
  document.getElementById("add-recipient-form").classList.remove("hidden");
});

document.getElementById("cancel-add-recipient").addEventListener("click", () => {
  document.getElementById("add-recipient-form").classList.add("hidden");
  document.getElementById("new-recipient-label").value = "";
  document.getElementById("new-recipient-pubkey").value = "";
  hideError(document.getElementById("add-recipient-error"));
});

const confirmAddRecipientBtn = document.getElementById("confirm-add-recipient");
confirmAddRecipientBtn.addEventListener("click", withBusyButton(confirmAddRecipientBtn, async () => {
  const label = document.getElementById("new-recipient-label").value.trim();
  const pubkey = document.getElementById("new-recipient-pubkey").value.trim();
  const errorEl = document.getElementById("add-recipient-error");
  hideError(errorEl);

  if (!label || !pubkey) {
    showError(errorEl, t("message.nameAndPubkeyRequired"));
    return;
  }

  try {
    await invoke("add_recipient", { label, pubkeyArmored: pubkey });
    document.getElementById("add-recipient-form").classList.add("hidden");
    document.getElementById("new-recipient-label").value = "";
    document.getElementById("new-recipient-pubkey").value = "";
    loadRecipients();
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

const encryptMessageBtn = document.getElementById("encrypt-message-btn");
encryptMessageBtn.addEventListener("click", withBusyButton(encryptMessageBtn, async () => {
  const errorEl = document.getElementById("encrypt-error");
  hideError(errorEl);
  document.getElementById("encrypt-result-block").classList.add("hidden");

  const picker = document.getElementById("message-recipients-picker");
  const checkedLabels = Array.from(picker.querySelectorAll("input[type=checkbox]:checked")).map((cb) => cb.value);
  const message = document.getElementById("message-plaintext").value;
  const pubkeysArmored = recipientsCache
    .filter((r) => checkedLabels.includes(r.label))
    .map((r) => r.pubkey_armored);

  if (pubkeysArmored.length === 0) {
    showError(errorEl, t("message.chooseAtLeastOneRecipient"));
    return;
  }
  if (!message) {
    showError(errorEl, t("message.cannotBeEmpty"));
    return;
  }

  try {
    const encrypted = await invoke("encrypt_message", { pubkeysArmored, message });
    document.getElementById("encrypt-result").value = encrypted;
    document.getElementById("encrypt-result-block").classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

document.getElementById("copy-encrypted").addEventListener("click", () => {
  copyText(document.getElementById("encrypt-result").value);
});

document.getElementById("clear-encrypted").addEventListener("click", () => {
  document.getElementById("encrypt-result-block").classList.add("hidden");
  document.getElementById("encrypt-result").value = "";
  document.getElementById("message-plaintext").value = "";
});

const decryptMessageBtn = document.getElementById("decrypt-message-btn");
decryptMessageBtn.addEventListener("click", withBusyButton(decryptMessageBtn, async () => {
  const errorEl = document.getElementById("decrypt-error");
  hideError(errorEl);
  document.getElementById("decrypt-result-block").classList.add("hidden");

  const ciphertext = document.getElementById("decrypt-input").value.trim();
  const password = document.getElementById("decrypt-password").value;

  if (!ciphertext || !password) {
    showError(errorEl, t("message.encryptedAndPasswordRequired"));
    return;
  }

  try {
    const plaintext = await invoke("decrypt_message", { password, ciphertext });
    document.getElementById("decrypt-result").value = plaintext;
    document.getElementById("decrypt-result-block").classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("decrypt-password").value = "";
  }
}));

document.getElementById("clear-decrypted").addEventListener("click", () => {
  document.getElementById("decrypt-result-block").classList.add("hidden");
  document.getElementById("decrypt-result").value = "";
  document.getElementById("decrypt-input").value = "";
});

// --- Wallets externes --------------------------------------------------------
// Suivi en lecture seule d'adresses qui n'appartiennent pas à ce portefeuille :
// on réutilise directement la commande `get_balance` déjà utilisée pour les
// propres cartes du wallet (aucun secret impliqué, juste une adresse publique).

let externalWalletsCache = [];
let externalGroupsCache = [];

function externalWalletCoin(network) {
  // "usdc_solana" avant "sol" : sinon startsWith("sol") ne matcherait de
  // toute façon pas ("usdc_solana" ne commence pas par "sol"), mais autant
  // rester explicite plutôt que de dépendre de cet ordre par accident.
  if (network === "usdc_solana") return "usdc";
  if (network.startsWith("evm")) return "evm";
  if (network.startsWith("btc")) return "btc";
  if (network.startsWith("sol")) return "sol";
  return null;
}

function externalNetworkLabel(network) {
  const key = {
    evm_mainnet: "external.netEvmMainnet",
    evm_sepolia: "external.netEvmSepolia",
    btc_mainnet: "external.netBtcMainnet",
    btc_testnet: "external.netBtcTestnet",
    sol_mainnet: "external.netSolMainnet",
    sol_devnet: "external.netSolDevnet",
    usdc_solana: "external.netUsdcSolana",
  }[network];
  return key ? t(key) : network;
}

async function loadExternalWallets() {
  try {
    [externalWalletsCache, externalGroupsCache] = await Promise.all([
      invoke("list_external_wallets"),
      invoke("list_external_wallet_groups"),
    ]);
  } catch (e) {
    console.error(e);
    return;
  }
  renderExternalWallets();
  refreshExternalWalletBalances();
}

function renderExternalWalletRow(wallet) {
  const row = document.createElement("div");
  row.className = "recipient-item";
  row.dataset.externalWalletRow = String(wallet.id);
  row.dataset.externalGroup = wallet.group_id != null ? String(wallet.group_id) : "none";

  const info = document.createElement("div");
  info.className = "recipient-info";
  const labelEl = document.createElement("span");
  labelEl.className = "recipient-label";
  labelEl.textContent = wallet.label;
  const meta = document.createElement("span");
  meta.className = "recipient-fp";
  meta.textContent = `${externalNetworkLabel(wallet.network)} · ${wallet.address}`;
  info.appendChild(labelEl);
  info.appendChild(meta);

  const actions = document.createElement("div");
  actions.className = "item-actions";

  const balanceEl = document.createElement("span");
  balanceEl.dataset.field = "external-balance";
  balanceEl.textContent = "…";

  const groupSelect = document.createElement("select");
  groupSelect.className = "external-wallet-group-select";
  const noneOption = document.createElement("option");
  noneOption.value = "";
  noneOption.textContent = t("external.noGroup");
  groupSelect.appendChild(noneOption);
  externalGroupsCache.forEach((g) => {
    const opt = document.createElement("option");
    opt.value = String(g.id);
    opt.textContent = g.name;
    groupSelect.appendChild(opt);
  });
  groupSelect.value = wallet.group_id != null ? String(wallet.group_id) : "";
  groupSelect.addEventListener("change", async () => {
    const groupId = groupSelect.value === "" ? null : Number.parseInt(groupSelect.value, 10);
    try {
      await invoke("set_external_wallet_group", { id: wallet.id, groupId });
      loadExternalWallets();
    } catch (e) {
      alert(t("common.error", { err: e }));
    }
  });

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "link";
  copyBtn.textContent = t("common.copy");
  copyBtn.addEventListener("click", () => copyText(wallet.address, t("wallet.addressCopied")));

  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "link";
  removeBtn.textContent = t("external.remove");
  removeBtn.addEventListener("click", async () => {
    try {
      await invoke("remove_external_wallet", { id: wallet.id });
      loadExternalWallets();
    } catch (e) {
      alert(t("common.error", { err: e }));
    }
  });

  actions.appendChild(balanceEl);
  actions.appendChild(groupSelect);
  actions.appendChild(copyBtn);
  actions.appendChild(removeBtn);
  row.appendChild(info);
  row.appendChild(actions);
  return row;
}

function renderExternalGroupBlock(group, wallets) {
  const groupKey = group ? String(group.id) : "none";
  const block = document.createElement("div");
  block.className = "external-group";

  const header = document.createElement("div");
  header.className = "external-group-header";

  const nameEl = document.createElement("h3");
  nameEl.textContent = group ? group.name : t("external.ungrouped");

  const totalEl = document.createElement("span");
  totalEl.className = "external-group-total";
  totalEl.dataset.externalGroupTotal = groupKey;
  totalEl.textContent = "…";

  header.appendChild(nameEl);
  header.appendChild(totalEl);

  if (group) {
    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "link";
    deleteBtn.textContent = t("external.deleteGroup");
    deleteBtn.addEventListener("click", async () => {
      try {
        await invoke("delete_external_wallet_group", { id: group.id });
        loadExternalWallets();
      } catch (e) {
        alert(t("common.error", { err: e }));
      }
    });
    header.appendChild(deleteBtn);
  }

  block.appendChild(header);

  const list = document.createElement("div");
  list.className = "recipient-list";
  if (wallets.length === 0) {
    list.innerHTML = `<p class="muted">${t("external.groupEmpty")}</p>`;
  } else {
    wallets.forEach((wallet) => list.appendChild(renderExternalWalletRow(wallet)));
  }
  block.appendChild(list);

  return block;
}

function renderExternalWallets() {
  const container = document.getElementById("external-wallets-container");
  container.innerHTML = "";

  if (externalWalletsCache.length === 0) {
    container.innerHTML = `<p class="muted">${t("external.empty")}</p>`;
    return;
  }

  externalGroupsCache.forEach((group) => {
    const wallets = externalWalletsCache.filter((w) => w.group_id === group.id);
    container.appendChild(renderExternalGroupBlock(group, wallets));
  });

  const ungrouped = externalWalletsCache.filter((w) => w.group_id == null);
  if (ungrouped.length > 0 || externalGroupsCache.length === 0) {
    container.appendChild(renderExternalGroupBlock(null, ungrouped));
  }
}

function updateAllExternalGroupTotals() {
  document.querySelectorAll("[data-external-group-total]").forEach((totalEl) => {
    const groupKey = totalEl.dataset.externalGroupTotal;
    const rows = document.querySelectorAll(`[data-external-wallet-row][data-external-group="${groupKey}"]`);
    let sum = 0;
    let any = false;
    rows.forEach((row) => {
      if (row.dataset.usd) {
        sum += Number.parseFloat(row.dataset.usd);
        any = true;
      }
    });
    totalEl.textContent = any
      ? `${sum.toLocaleString("fr-FR", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} $`
      : "—";
  });
}

async function refreshExternalWalletBalances() {
  await Promise.all(
    externalWalletsCache.map(async (wallet) => {
      const row = document.querySelector(`[data-external-wallet-row="${wallet.id}"]`);
      if (!row) return;
      const balanceEl = row.querySelector('[data-field="external-balance"]');
      try {
        // USDC n'est pas un "network" au sens où get_balance l'entend (pas de
        // notion de décimales/mint par actif) : commande dédiée, comme pour la
        // carte USDC du propre wallet. Mainnet uniquement (voir sol_spl.rs) —
        // "usdc_solana" est stocké tel quel dans external_wallets.json, mais
        // get_usdc_balance attend le vrai identifiant de cluster ("sol_mainnet").
        const balance =
          wallet.network === "usdc_solana"
            ? await invoke("get_usdc_balance", { network: "sol_mainnet", address: wallet.address })
            : await invoke("get_balance", { network: wallet.network, address: wallet.address });
        const price = priceForCoin(externalWalletCoin(wallet.network));
        const usd = price != null ? Number.parseFloat(balance) * price : null;
        balanceEl.textContent = balance;
        row.dataset.usd = usd != null && Number.isFinite(usd) ? String(usd) : "";
      } catch (e) {
        balanceEl.textContent = t("wallet.balanceError");
        row.dataset.usd = "";
      }
    })
  );
  updateAllExternalGroupTotals();
}

const refreshExternalWalletsBtn = document.getElementById("refresh-external-wallets-btn");
refreshExternalWalletsBtn.addEventListener(
  "click",
  withThrottledButton(refreshExternalWalletsBtn, REFRESH_COOLDOWN_MS, async () => {
    renderExternalWallets();
    await refreshExternalWalletBalances();
  })
);

// --- Modale ajout d'un wallet externe ---------------------------------------

document.getElementById("add-external-wallet-btn").addEventListener("click", () => {
  document.getElementById("external-wallet-label").value = "";
  document.getElementById("external-wallet-address").value = "";
  hideError(document.getElementById("add-external-wallet-error"));

  const groupSelect = document.getElementById("external-wallet-group");
  groupSelect.innerHTML = "";
  const noneOption = document.createElement("option");
  noneOption.value = "";
  noneOption.textContent = t("external.noGroup");
  groupSelect.appendChild(noneOption);
  externalGroupsCache.forEach((g) => {
    const opt = document.createElement("option");
    opt.value = String(g.id);
    opt.textContent = g.name;
    groupSelect.appendChild(opt);
  });
  groupSelect.value = "";
  syncCustomSelect(groupSelect);

  document.getElementById("add-external-wallet-modal").classList.remove("hidden");
});

document.getElementById("add-external-wallet-cancel").addEventListener("click", () => {
  document.getElementById("add-external-wallet-modal").classList.add("hidden");
});

const addExternalWalletConfirmBtn = document.getElementById("add-external-wallet-confirm");
addExternalWalletConfirmBtn.addEventListener("click", withBusyButton(addExternalWalletConfirmBtn, async () => {
  const errorEl = document.getElementById("add-external-wallet-error");
  hideError(errorEl);
  const label = document.getElementById("external-wallet-label").value.trim();
  const network = document.getElementById("external-wallet-network").value;
  const address = document.getElementById("external-wallet-address").value.trim();
  const groupValue = document.getElementById("external-wallet-group").value;
  const groupId = groupValue === "" ? null : Number.parseInt(groupValue, 10);

  if (!label || !address) {
    showError(errorEl, t("external.labelAndAddressRequired"));
    return;
  }

  try {
    await invoke("add_external_wallet", { label, network, address, groupId });
    document.getElementById("add-external-wallet-modal").classList.add("hidden");
    loadExternalWallets();
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

// --- Modale nouveau groupe ---------------------------------------------------

document.getElementById("add-external-group-btn").addEventListener("click", () => {
  document.getElementById("external-group-name").value = "";
  hideError(document.getElementById("add-external-group-error"));
  document.getElementById("add-external-group-modal").classList.remove("hidden");
});

document.getElementById("add-external-group-cancel").addEventListener("click", () => {
  document.getElementById("add-external-group-modal").classList.add("hidden");
});

const addExternalGroupConfirmBtn = document.getElementById("add-external-group-confirm");
addExternalGroupConfirmBtn.addEventListener("click", withBusyButton(addExternalGroupConfirmBtn, async () => {
  const errorEl = document.getElementById("add-external-group-error");
  hideError(errorEl);
  const name = document.getElementById("external-group-name").value.trim();
  if (!name) {
    showError(errorEl, t("external.groupNameRequired"));
    return;
  }
  try {
    await invoke("create_external_wallet_group", { name });
    document.getElementById("add-external-group-modal").classList.add("hidden");
    loadExternalWallets();
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

// --- Carnet d'adresses -------------------------------------------------------
// Associer un label à une adresse pour la retrouver au moment d'envoyer des
// fonds (voir core/src/address_book.rs) — distinct des wallets externes :
// aucun solde n'est jamais interrogé ici.

let addressBookCache = [];

async function loadAddressBook() {
  try {
    addressBookCache = await invoke("list_address_book");
  } catch (e) {
    console.error(e);
    return;
  }
  renderAddressBook();
}

function renderAddressBookRow(entry) {
  const row = document.createElement("div");
  row.className = "recipient-item";

  const info = document.createElement("div");
  info.className = "recipient-info";
  const labelEl = document.createElement("span");
  labelEl.className = "recipient-label";
  labelEl.textContent = entry.label;
  const meta = document.createElement("span");
  meta.className = "recipient-fp";
  meta.textContent = `${externalNetworkLabel(entry.network)} · ${entry.address}`;
  info.appendChild(labelEl);
  info.appendChild(meta);

  const actions = document.createElement("div");
  actions.className = "item-actions";
  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "link";
  copyBtn.textContent = t("common.copy");
  copyBtn.addEventListener("click", () => copyText(entry.address, t("wallet.addressCopied")));

  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "link";
  removeBtn.textContent = t("addressBook.remove");
  removeBtn.addEventListener("click", async () => {
    try {
      await invoke("remove_address_book_entry", { id: entry.id });
      loadAddressBook();
    } catch (e) {
      alert(t("common.error", { err: e }));
    }
  });
  actions.appendChild(copyBtn);
  actions.appendChild(removeBtn);

  row.appendChild(info);
  row.appendChild(actions);
  return row;
}

function renderAddressBook() {
  const container = document.getElementById("address-book-container");
  container.innerHTML = "";
  if (addressBookCache.length === 0) {
    container.innerHTML = `<p class="muted">${t("addressBook.empty")}</p>`;
    return;
  }
  const list = document.createElement("div");
  list.className = "recipient-list";
  addressBookCache.forEach((entry) => list.appendChild(renderAddressBookRow(entry)));
  container.appendChild(list);
}

document.getElementById("add-address-book-btn").addEventListener("click", () => {
  document.getElementById("address-book-label").value = "";
  document.getElementById("address-book-address").value = "";
  hideError(document.getElementById("add-address-book-error"));
  document.getElementById("add-address-book-modal").classList.remove("hidden");
});

document.getElementById("add-address-book-cancel").addEventListener("click", () => {
  document.getElementById("add-address-book-modal").classList.add("hidden");
});

const addAddressBookConfirmBtn = document.getElementById("add-address-book-confirm");
addAddressBookConfirmBtn.addEventListener("click", withBusyButton(addAddressBookConfirmBtn, async () => {
  const errorEl = document.getElementById("add-address-book-error");
  hideError(errorEl);
  const label = document.getElementById("address-book-label").value.trim();
  const network = document.getElementById("address-book-network").value;
  const address = document.getElementById("address-book-address").value.trim();

  if (!label || !address) {
    showError(errorEl, t("external.labelAndAddressRequired"));
    return;
  }

  try {
    await invoke("add_address_book_entry", { label, network, address });
    document.getElementById("add-address-book-modal").classList.add("hidden");
    loadAddressBook();
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

// Sélecteur "choisir depuis le carnet d'adresses" dans la modale d'envoi :
// filtré par coin (même correspondance réseau->coin que pour les wallets
// externes, voir externalWalletCoin), masqué s'il n'y a aucune entrée
// compatible pour ce coin. Choisir une entrée remplit juste le champ adresse,
// le sélecteur repart ensuite sur son placeholder (action, pas un état persistant).
function refreshSendAddressBookPicker(coin) {
  const wrapper = document.getElementById("send-address-book-picker");
  const select = document.getElementById("send-address-book-select");
  const matches = addressBookCache.filter((entry) => externalWalletCoin(entry.network) === coin);

  select.innerHTML = `<option value="" data-i18n="addressBook.pickPlaceholder">${t("addressBook.pickPlaceholder")}</option>`;
  matches.forEach((entry) => {
    const opt = document.createElement("option");
    opt.value = String(entry.id);
    opt.textContent = `${entry.label} — ${entry.address}`;
    select.appendChild(opt);
  });
  syncCustomSelect(select);
  wrapper.classList.toggle("hidden", matches.length === 0);
}

document.getElementById("send-address-book-select").addEventListener("change", (e) => {
  const entry = addressBookCache.find((entry) => String(entry.id) === e.target.value);
  if (entry) {
    document.getElementById("send-to").value = entry.address;
  }
  e.target.value = "";
  syncCustomSelect(e.target);
});

// --- Valider avec Entrée -----------------------------------------------------
// Aucun de ces champs n'est dans un vrai <form> (tout est soumis via un clic
// de bouton géré en JS) : Entrée ne fait donc rien par défaut, contrairement à
// un formulaire HTML classique. Ce mapping recrée ce comportement pour chaque
// champ de mot de passe de l'app, sans dupliquer un `keydown` par écran.
const ENTER_SUBMIT_MAP = {
  "onboarding-password": "onboarding-submit",
  "onboarding-password-confirm": "onboarding-submit",
  "unlock-password": "unlock-submit",
  "restore-passphrase-1": "restore-submit",
  "restore-passphrase-2": "restore-submit",
  "restore-new-password": "restore-submit",
  "decrypt-password": "decrypt-message-btn",
  "send-password": "send-confirm",
  "add-profile-password": "add-profile-confirm",
  "delete-profile-password": "delete-profile-confirm",
  "regenerate-backup-password": "regenerate-backup-confirm",
  "thor-address-password": "thor-address-confirm",
  "swap-preview-password": "swap-preview-confirm",
  "enable-biometric-password": "enable-biometric-confirm",
  "disable-biometric-password": "disable-biometric-confirm",
};

Object.entries(ENTER_SUBMIT_MAP).forEach(([inputId, buttonId]) => {
  const input = document.getElementById(inputId);
  const button = document.getElementById(buttonId);
  if (!input || !button) return;
  input.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    button.click();
  });
});

// --- Démarrage -------------------------------------------------------------

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const exists = await invoke("wallet_exists");
    if (exists) {
      showUnlockView();
    } else {
      showView("onboarding");
    }
  } catch (e) {
    console.error(e);
    showView("onboarding");
  }
});

// --- WalletConnect (applications connectées) ---------------------------------
// Le frontend ne fait qu'afficher et relayer : le contenu d'une demande est
// relu et préparé côté Rust (`wc_prepare_request`, jamais à partir d'une copie
// d'ici), et chaque signature passe par une boîte native de Windows. Tout le
// texte venu d'un site est inséré par `textContent`, jamais comme du HTML.

const { listen } = window.__TAURI__.event;
const wcQueue = [];
let wcCurrent = null;

function wcChainLabel(chain) {
  return (
    {
      "eip155:1": "Ethereum",
      "eip155:11155111": "Ethereum Sepolia",
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "Solana",
      "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "Solana devnet",
    }[chain] || chain
  );
}

// Une seule fenêtre à la fois : propositions et demandes attendent leur tour.
function wcProcessQueue() {
  if (wcCurrent || wcQueue.length === 0) return;
  wcCurrent = wcQueue.shift();
  if (wcCurrent.kind === "Proposal") showWcProposal(wcCurrent);
  else showWcRequest(wcCurrent);
}

function wcClose(modalId) {
  document.getElementById(modalId).classList.add("hidden");
  wcCurrent = null;
  wcProcessQueue();
}

listen("wc-event", (event) => {
  const e = event.payload;
  if (e.kind === "Proposal" || e.kind === "Request") {
    wcQueue.push(e);
    wcProcessQueue();
  } else if (e.kind === "SessionsChanged") {
    loadWcSessions();
  } else if (e.kind === "RelayStatus") {
    document.getElementById("wc-status").textContent = e.connected ? t("wc.relayConnected") : t("wc.relayDisconnected");
    const errorEl = document.getElementById("wc-error");
    if (e.error) showError(errorEl, e.error);
    else if (e.connected) hideError(errorEl);
  }
});

function showWcProposal(proposal) {
  document.getElementById("wc-proposal-peer").textContent = proposal.peer.name || "?";
  document.getElementById("wc-proposal-url").textContent = proposal.peer.url || "?";
  document.getElementById("wc-proposal-chains").textContent = t("wc.networks", {
    chains: proposal.chains.map(wcChainLabel).join(", ") || "—",
  });
  const incompatible = document.getElementById("wc-proposal-incompatible");
  if (proposal.incompatible) showError(incompatible, proposal.incompatible);
  else hideError(incompatible);

  const select = document.getElementById("wc-proposal-profile");
  select.replaceChildren();
  const usable = profilesCache.filter((p) => p.addresses);
  for (const profile of usable) {
    const option = document.createElement("option");
    option.value = String(profile.index);
    option.textContent = profile.label;
    option.selected = profile.index === currentProfileIndex;
    select.appendChild(option);
  }
  const errorEl = document.getElementById("wc-proposal-error");
  hideError(errorEl);
  if (usable.length === 0) showError(errorEl, t("wc.noProfile"));
  document.getElementById("wc-proposal-approve").disabled = Boolean(proposal.incompatible) || usable.length === 0;
  document.getElementById("wc-proposal-modal").classList.remove("hidden");
}

const wcProposalApproveBtn = document.getElementById("wc-proposal-approve");
wcProposalApproveBtn.addEventListener(
  "click",
  withBusyButton(wcProposalApproveBtn, async () => {
    const proposal = wcCurrent;
    if (!proposal || proposal.kind !== "Proposal") return;
    try {
      // `false` : refusée dans la boîte native (la dApp en est déjà informée).
      await invoke("wc_approve_session", {
        proposalId: proposal.id,
        profileIndex: Number(document.getElementById("wc-proposal-profile").value),
      });
      wcClose("wc-proposal-modal");
      loadWcSessions();
    } catch (e) {
      showError(document.getElementById("wc-proposal-error"), String(e));
    }
  }),
);

document.getElementById("wc-proposal-reject").addEventListener("click", async () => {
  const proposal = wcCurrent;
  if (proposal && proposal.kind === "Proposal") {
    try {
      await invoke("wc_reject_session", { proposalId: proposal.id });
    } catch (e) {
      console.error(e);
    }
  }
  wcClose("wc-proposal-modal");
});

async function showWcRequest(request) {
  const textEl = document.getElementById("wc-request-text");
  const loading = document.getElementById("wc-request-loading");
  const danger = document.getElementById("wc-request-danger");
  const errorEl = document.getElementById("wc-request-error");
  const approve = document.getElementById("wc-request-approve");
  textEl.classList.add("hidden");
  danger.classList.add("hidden");
  hideError(errorEl);
  loading.classList.remove("hidden");
  approve.disabled = true;
  document.getElementById("wc-request-password").value = "";
  document.getElementById("wc-request-modal").classList.remove("hidden");
  try {
    const prepared = await invoke("wc_prepare_request", { requestId: request.id });
    textEl.textContent = prepared.text;
    textEl.classList.remove("hidden");
    danger.classList.toggle("hidden", !prepared.danger);
    approve.disabled = false;
  } catch (e) {
    // Demande invalide ou dangereuse par construction : déjà refusée côté Rust.
    showError(errorEl, String(e));
  } finally {
    loading.classList.add("hidden");
  }
}

const wcRequestApproveBtn = document.getElementById("wc-request-approve");
wcRequestApproveBtn.addEventListener(
  "click",
  withBusyButton(wcRequestApproveBtn, async () => {
    const request = wcCurrent;
    if (!request || request.kind !== "Request") return;
    const passwordEl = document.getElementById("wc-request-password");
    const errorEl = document.getElementById("wc-request-error");
    if (!passwordEl.value) {
      showError(errorEl, t("common.passwordRequired"));
      return;
    }
    try {
      // `false` : refusée dans la boîte native (la dApp en est déjà informée).
      await invoke("wc_approve_request", { requestId: request.id, password: passwordEl.value });
      passwordEl.value = "";
      wcClose("wc-request-modal");
    } catch (e) {
      // Mauvais mot de passe, fonds insuffisants… : la demande reste ouverte.
      showError(errorEl, String(e));
    }
  }),
);

document.getElementById("wc-request-reject").addEventListener("click", async () => {
  const request = wcCurrent;
  if (request && request.kind === "Request") {
    try {
      await invoke("wc_reject_request", { requestId: request.id });
    } catch (e) {
      console.error(e);
    }
  }
  document.getElementById("wc-request-password").value = "";
  wcClose("wc-request-modal");
});

const wcPairBtn = document.getElementById("wc-pair-btn");
wcPairBtn.addEventListener(
  "click",
  withBusyButton(wcPairBtn, async () => {
    const input = document.getElementById("wc-uri");
    const errorEl = document.getElementById("wc-error");
    hideError(errorEl);
    const uri = input.value.trim();
    if (!uri) return;
    try {
      await invoke("wc_pair", { uri });
      input.value = "";
      document.getElementById("wc-status").textContent = t("wc.pairing");
    } catch (e) {
      showError(errorEl, String(e));
    }
  }),
);

async function loadWcSessions() {
  let sessions = [];
  try {
    sessions = await invoke("wc_sessions");
  } catch (e) {
    console.error(e);
  }
  const container = document.getElementById("wc-sessions");
  container.replaceChildren();
  if (sessions.length === 0) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = t("wc.noSession");
    container.appendChild(empty);
    return;
  }
  for (const session of sessions) {
    const row = document.createElement("div");
    row.className = "recipient-item";
    const info = document.createElement("div");
    info.className = "recipient-info";
    const label = document.createElement("span");
    label.className = "recipient-label";
    label.textContent = session.peer.name || "?";
    const meta = document.createElement("span");
    meta.className = "recipient-fp";
    const profile = profilesCache.find((p) => p.index === session.profile_index);
    const expires = new Date(session.expiry * 1000).toLocaleDateString(currentLang === "en" ? "en-GB" : "fr-FR");
    meta.textContent = [
      session.peer.url,
      session.chains.map(wcChainLabel).join(", "),
      profile ? profile.label : `#${session.profile_index}`,
      t("wc.expires", { date: expires }),
    ].join(" · ");
    info.appendChild(label);
    info.appendChild(meta);
    const actions = document.createElement("div");
    actions.className = "item-actions";
    const disconnect = document.createElement("button");
    disconnect.type = "button";
    disconnect.className = "link";
    disconnect.textContent = t("wc.disconnect");
    disconnect.addEventListener("click", async () => {
      try {
        await invoke("wc_disconnect", { topic: session.topic });
      } catch (e) {
        console.error(e);
      }
      loadWcSessions();
    });
    actions.appendChild(disconnect);
    row.appendChild(info);
    row.appendChild(actions);
    container.appendChild(row);
  }
}

// --- Comptes Ledger ------------------------------------------------------------
// Tout ce qui parle à l'appareil passe par le backend Rust (core/src/hardware.rs),
// qui revérifie chaque réponse ; la dernière barrière reste l'écran du Ledger.

let ledgerAccountsCache = [];
let ledgerSendAccount = null;

function ledgerCoin(network) {
  if (network.startsWith("evm")) return "evm";
  if (network.startsWith("btc")) return "btc";
  return "sol";
}

function ledgerUnit(network) {
  return { evm: "ETH", btc: "BTC", sol: "SOL" }[ledgerCoin(network)];
}

async function loadLedgerAccounts() {
  try {
    ledgerAccountsCache = await invoke("hardware_accounts");
  } catch (e) {
    console.error(e);
    return;
  }
  renderLedgerAccounts();
  refreshLedgerBalances();
}

function ledgerLinkButton(text, onClick) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "link";
  b.textContent = text;
  b.addEventListener("click", onClick);
  return b;
}

function renderLedgerAccounts() {
  const container = document.getElementById("ledger-accounts");
  container.innerHTML = "";
  if (ledgerAccountsCache.length === 0) {
    container.innerHTML = `<p class="muted">${t("ledger.empty")}</p>`;
    return;
  }
  ledgerAccountsCache.forEach((account) => {
    const row = document.createElement("div");
    row.className = "recipient-item";
    row.dataset.ledgerRow = String(account.id);

    const info = document.createElement("div");
    info.className = "recipient-info";
    const labelEl = document.createElement("span");
    labelEl.className = "recipient-label";
    labelEl.textContent = account.label;
    const meta = document.createElement("span");
    meta.className = "recipient-fp";
    meta.textContent = `${externalNetworkLabel(account.network)} · ${account.address} · m/${account.path}`;
    info.append(labelEl, meta);

    const actions = document.createElement("div");
    actions.className = "item-actions";
    const balanceEl = document.createElement("span");
    balanceEl.dataset.field = "ledger-balance";
    balanceEl.textContent = "…";

    const copyBtn = ledgerLinkButton(t("common.copy"), () => copyText(account.address, t("wallet.addressCopied")));
    const verifyBtn = ledgerLinkButton(t("ledger.verify"), () => {});
    verifyBtn.title = t("ledger.verifyPrompt", { address: account.address });
    verifyBtn.addEventListener(
      "click",
      withBusyButton(verifyBtn, async () => {
        showCopyToast(t("ledger.waitDevice"));
        try {
          await invoke("hardware_verify_address", { id: account.id });
          alert(t("ledger.verified"));
        } catch (e) {
          alert(t("common.error", { err: e }));
        }
      })
    );
    const sendBtn = ledgerLinkButton(t("ledger.send"), () => openLedgerSend(account));
    const removeBtn = ledgerLinkButton(t("ledger.remove"), async () => {
      try {
        await invoke("hardware_remove", { id: account.id });
      } catch (e) {
        alert(t("common.error", { err: e }));
      }
      loadLedgerAccounts();
    });

    actions.append(balanceEl, copyBtn, verifyBtn, sendBtn, removeBtn);
    row.append(info, actions);
    container.appendChild(row);
  });
}

async function refreshLedgerBalances() {
  await Promise.all(
    ledgerAccountsCache.map(async (account) => {
      const balanceEl = document.querySelector(`[data-ledger-row="${account.id}"] [data-field="ledger-balance"]`);
      if (!balanceEl) return;
      try {
        balanceEl.textContent = `${await invoke("hardware_balance", { id: account.id })} ${ledgerUnit(account.network)}`;
      } catch (e) {
        balanceEl.textContent = t("wallet.balanceError");
      }
    })
  );
}

const ledgerRefreshBtn = document.getElementById("ledger-refresh-btn");
ledgerRefreshBtn.addEventListener(
  "click",
  withThrottledButton(ledgerRefreshBtn, REFRESH_COOLDOWN_MS, async () => {
    renderLedgerAccounts();
    await refreshLedgerBalances();
  })
);

document.getElementById("ledger-add-btn").addEventListener("click", () => {
  document.getElementById("ledger-add-label").value = "";
  hideError(document.getElementById("ledger-add-error"));
  document.getElementById("ledger-add-modal").classList.remove("hidden");
});

document.getElementById("ledger-add-cancel").addEventListener("click", () => {
  document.getElementById("ledger-add-modal").classList.add("hidden");
});

const ledgerAddConfirmBtn = document.getElementById("ledger-add-confirm");
ledgerAddConfirmBtn.addEventListener(
  "click",
  withBusyButton(ledgerAddConfirmBtn, async () => {
    const errorEl = document.getElementById("ledger-add-error");
    hideError(errorEl);
    const label = document.getElementById("ledger-add-label").value.trim();
    const network = document.getElementById("ledger-add-network").value;
    if (!label) {
      showError(errorEl, t("ledger.labelRequired"));
      return;
    }
    try {
      await invoke("hardware_connect", { network, label });
      document.getElementById("ledger-add-modal").classList.add("hidden");
      loadLedgerAccounts();
    } catch (e) {
      showError(errorEl, String(e));
    }
  })
);

async function openLedgerSend(account) {
  ledgerSendAccount = account;
  document.getElementById("ledger-send-title").textContent = t("ledger.sendTitle", { label: account.label });
  document.getElementById("ledger-send-from").textContent = `${externalNetworkLabel(account.network)} · ${account.address}`;
  document.getElementById("ledger-send-amount-label").textContent = t("ledger.amount", { unit: ledgerUnit(account.network) });
  document.getElementById("ledger-send-to").value = "";
  document.getElementById("ledger-send-amount").value = "";
  document.getElementById("ledger-send-status").textContent = "";
  hideError(document.getElementById("ledger-send-error"));
  const feeBlock = document.getElementById("ledger-send-fee-block");
  const feeSelect = document.getElementById("ledger-send-fee");
  feeSelect.innerHTML = "";
  const isBtc = ledgerCoin(account.network) === "btc";
  feeBlock.classList.toggle("hidden", !isBtc);
  document.getElementById("ledger-send-modal").classList.remove("hidden");
  if (!isBtc) return;
  const loading = document.createElement("option");
  loading.value = "";
  loading.textContent = t("ledger.feeLoading");
  feeSelect.appendChild(loading);
  try {
    const fees = await invoke("hardware_estimate_btc_fees", { id: account.id });
    if (ledgerSendAccount !== account) return;
    feeSelect.innerHTML = "";
    [
      ["ledger.feeFast", fees.fast_sat],
      ["ledger.feeMedium", fees.medium_sat],
      ["ledger.feeSlow", fees.slow_sat],
    ].forEach(([key, sat]) => {
      const opt = document.createElement("option");
      opt.value = String(sat);
      opt.textContent = t(key, { sat });
      feeSelect.appendChild(opt);
    });
    feeSelect.value = String(fees.medium_sat);
  } catch (e) {
    feeSelect.innerHTML = "";
    showError(document.getElementById("ledger-send-error"), String(e));
  }
}

document.getElementById("ledger-send-cancel").addEventListener("click", () => {
  ledgerSendAccount = null;
  document.getElementById("ledger-send-modal").classList.add("hidden");
});

const ledgerSendConfirmBtn = document.getElementById("ledger-send-confirm");
ledgerSendConfirmBtn.addEventListener(
  "click",
  withBusyButton(ledgerSendConfirmBtn, async () => {
    const account = ledgerSendAccount;
    if (!account) return;
    const errorEl = document.getElementById("ledger-send-error");
    const statusEl = document.getElementById("ledger-send-status");
    hideError(errorEl);
    statusEl.textContent = "";
    const to = document.getElementById("ledger-send-to").value;
    const amount = document.getElementById("ledger-send-amount").value;
    if (!to.trim() || !amount.trim()) {
      showError(errorEl, t("ledger.fieldsRequired"));
      return;
    }
    let feeSat = null;
    if (ledgerCoin(account.network) === "btc") {
      feeSat = Number.parseInt(document.getElementById("ledger-send-fee").value, 10);
      if (!Number.isSafeInteger(feeSat)) {
        showError(errorEl, t("ledger.feeLoading"));
        return;
      }
    }
    statusEl.textContent = t("ledger.waitDevice");
    try {
      const txid = await invoke("hardware_send", { id: account.id, to, amount, feeSat });
      statusEl.textContent = t("ledger.sent", { txid });
      refreshLedgerBalances();
    } catch (e) {
      statusEl.textContent = "";
      showError(errorEl, String(e));
    }
  })
);
