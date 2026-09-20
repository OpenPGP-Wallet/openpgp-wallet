const { invoke } = window.__TAURI__.core;

// --- Thème -----------------------------------------------------------------
// Préférence purement visuelle par appareil (pas une donnée du wallet) : stockage
// local suffit, pas besoin de passer par le coffre chiffré. `try/catch` seul
// (localStorage peut être bloqué selon la configuration) : le thème par défaut
// s'applique alors sans jamais faire planter l'app.
const THEME_STORAGE_KEY = "pgp-wallet-theme";
const VALID_THEMES = ["default", "purple", "orange", "dark"];

function applyTheme(theme) {
  if (VALID_THEMES.includes(theme) && theme !== "default") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
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
    "common.busy": "Patiente…",
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
    "unlock.passwordPlaceholder": "Votre mot de passe",
    "unlock.submit": "Déverrouiller",
    "unlock.gotoRestore": "Restaurer depuis une sauvegarde",
    "unlock.resetWallet": "Réinitialiser cet appareil (supprime le coffre local)",
    "unlock.resetConfirm":
      "Supprimer le coffre local de cet appareil ? Vous ne pourrez le récupérer qu'avec 2 de vos 3 parts de sauvegarde. Continuer ?",
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
    "nav.message": "Message",
    "nav.certificate": "Certificat",
    "nav.settings": "Paramètres",
    "nav.lock": "Verrouiller",
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
    "wallet.history": "Historique",
    "wallet.send": "Envoyer",
    "wallet.pendingBadge": "⏳ Transaction en attente détectée",
    "wallet.marketsTitle": "Prix des cryptomonnaies en direct",
    "wallet.showQr": "Afficher en QR code",
    "wallet.marketsLoadError": "Impossible de charger les données de marché.",
    "wallet.qrError": "Impossible de générer le QR code : {err}",
    "wallet.linkError": "Impossible d'ouvrir le lien : {err}",
    "wallet.noArchivedProfile": "Aucun profil archivé.",
    "wallet.restoreProfile": "Restaurer",
    "wallet.deleteProfileForever": "Supprimer définitivement",
    "wallet.historyTitle": "Historique — {coin}",
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
    "settings.archivedProfiles": "Profils archivés",
    "settings.archivedProfilesHint":
      "Un profil archivé disparaît du sélecteur principal mais reste entièrement récupérable — rien n'est perdu tant qu'il apparaît ici.",
    "settings.backup": "Sauvegarde",
    "settings.regenerateBackup": "Régénérer mon kit de sauvegarde",
    "settings.regenerateBackupHint":
      "Si vous avez perdu un ou plusieurs de vos 3 fichiers de sauvegarde d'origine, générez-en un nouveau jeu de 3 (mot de passe requis). Vos adresses ne changent pas.",
    "settings.deviceSecurity": "Sécurité de l'appareil",
    "send.title": "Envoyer",
    "send.fromProfile": "Depuis le profil : <strong id=\"send-from-profile\"></strong>",
    "send.mainnetWarning": "/!\\ Réseau MAINNET — ceci dépense de vrais fonds, irréversible.",
    "send.toAddress": "Adresse destinataire",
    "send.amount": "Montant",
    "send.feeSpeed": "Vitesse d'envoi (frais réseau)",
    "send.passwordToConfirm": "Mot de passe (pour valider la transaction)",
    "send.confirm": "Confirmer l'envoi",
    "send.txSent": "Transaction envoyée : {tx}",
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
    "unlock.passwordPlaceholder": "Your password",
    "unlock.submit": "Unlock",
    "unlock.gotoRestore": "Restore from a backup",
    "unlock.resetWallet": "Reset this device (deletes the local vault)",
    "unlock.resetConfirm":
      "Delete the local vault on this device? You will only be able to recover it with 2 of your 3 backup shares. Continue?",
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
    "nav.message": "Message",
    "nav.certificate": "Certificate",
    "nav.settings": "Settings",
    "nav.lock": "Lock",
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
    "wallet.history": "History",
    "wallet.send": "Send",
    "wallet.pendingBadge": "⏳ Pending transaction detected",
    "wallet.marketsTitle": "Live cryptocurrency prices",
    "wallet.showQr": "Show as QR code",
    "wallet.marketsLoadError": "Unable to load market data.",
    "wallet.qrError": "Unable to generate the QR code: {err}",
    "wallet.linkError": "Unable to open the link: {err}",
    "wallet.noArchivedProfile": "No archived profile.",
    "wallet.restoreProfile": "Restore",
    "wallet.deleteProfileForever": "Delete permanently",
    "wallet.historyTitle": "History — {coin}",
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
    "settings.archivedProfiles": "Archived profiles",
    "settings.archivedProfilesHint":
      "An archived profile disappears from the main selector but stays fully recoverable — nothing is lost as long as it appears here.",
    "settings.backup": "Backup",
    "settings.regenerateBackup": "Regenerate my backup kit",
    "settings.regenerateBackupHint":
      "If you lost one or more of your original 3 backup files, generate a new set of 3 (password required). Your addresses don't change.",
    "settings.deviceSecurity": "Device security",
    "send.title": "Send",
    "send.fromProfile": "From profile: <strong id=\"send-from-profile\"></strong>",
    "send.mainnetWarning": "/!\\ MAINNET network — this spends real funds, irreversible.",
    "send.toAddress": "Recipient address",
    "send.amount": "Amount",
    "send.feeSpeed": "Sending speed (network fee)",
    "send.passwordToConfirm": "Password (to confirm the transaction)",
    "send.confirm": "Confirm send",
    "send.txSent": "Transaction sent: {tx}",
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

document.getElementById("goto-restore").addEventListener("click", () => showView("restore"));
document.getElementById("goto-unlock").addEventListener("click", () => showView("unlock"));

document.getElementById("reset-wallet").addEventListener("click", async () => {
  const sure = confirm(t("unlock.resetConfirm"));
  if (!sure) return;
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
  const sure = confirm(t("unlock.resetConfirm"));
  if (!sure) return;
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

function lockWallet() {
  profilesCache = [];
  currentProfileIndex = 0;
  stopBalanceAutoRefresh();
  document.getElementById("unlock-password").value = "";
  showView("unlock");
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
    if (target === "certificate") loadCertificate();
    if (target === "message") loadRecipients();
    if (target === "settings") loadArchivedProfiles();
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
  if (coin === "sol") return profile.addresses.solana;
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
    try {
      const balance = await invoke("get_balance", { network, address });
      balanceEl.textContent = balance;
    } catch (e) {
      balanceEl.textContent = t("wallet.balanceError");
      console.error(e);
    }
    updateFiatValue(card);
    await checkPendingTx(card, address, network);
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
  refreshBtn.addEventListener("click", withBusyButton(refreshBtn, () => refreshBalance(card)));
  card.querySelector('[data-action="send"]').addEventListener("click", () => openSendModal(card));
  card.querySelector('[data-action="qr"]').addEventListener("click", () => openQrModal(card));
  const historyBtn = card.querySelector('[data-action="history"]');
  historyBtn.addEventListener("click", withBusyButton(historyBtn, () => openHistoryModal(card)));
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

// --- Historique de transactions (séparé par crypto) -------------------------

const historyModal = document.getElementById("history-modal");

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

async function openHistoryModal(card) {
  const coin = card.dataset.coin;
  const network = networkForCard(card);
  const address = addressForCoin(coin, network);
  const coinLabel = card.querySelector("h2").textContent.trim();
  document.getElementById("history-modal-title").textContent = t("wallet.historyTitle", { coin: coinLabel });
  const container = document.getElementById("history-list");
  container.innerHTML = `<p class="muted">${t("wallet.historyLoading")}</p>`;
  historyModal.classList.remove("hidden");

  if (!address) {
    container.innerHTML = `<p class="muted">${t("wallet.historyAddressUnavailable")}</p>`;
    return;
  }

  try {
    const entries = await invoke("get_tx_history", { network, address });
    container.innerHTML = "";
    if (entries.length === 0) {
      container.innerHTML = `<p class="muted">${t("wallet.historyEmpty")}</p>`;
      return;
    }
    entries.forEach((tx) => {
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
      meta.appendChild(dateSpan);
      meta.appendChild(statusSpan);
      left.appendChild(idDiv);
      left.appendChild(meta);

      const right = document.createElement("div");
      right.className = "history-right";
      const amountDiv = document.createElement("div");
      amountDiv.className = "history-amount";
      if (tx.amount != null) {
        amountDiv.classList.add(tx.amount.startsWith("-") ? "negative" : "positive");
        amountDiv.textContent = tx.amount;
      } else {
        amountDiv.textContent = "—";
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
      right.appendChild(amountDiv);
      right.appendChild(link);

      row.appendChild(left);
      row.appendChild(right);
      container.appendChild(row);
    });
  } catch (e) {
    container.innerHTML = `<p class="muted">${e}</p>`;
  }
}

document.getElementById("history-close").addEventListener("click", () => {
  historyModal.classList.add("hidden");
});

// --- Send modal ----------------------------------------------------------

const sendModal = document.getElementById("send-modal");
let sendContext = null;

// Montants rapides en dollars : convertis en crypto au prix en direct (voir
// `latestPrices`/`refreshPrices`), pas des montants fixes en ETH/BTC/SOL — ça n'a
// de sens que si le montant en dollars reste identique quel que soit le cours du
// jour. Mêmes décimales que le formatage des soldes côté Rust
// (app/src-tauri/src/lib.rs::get_balance), pour que le montant rempli soit celui
// réellement envoyé, pas une valeur arrondie différente.
const QUICK_AMOUNTS_USD = [5, 10, 50];
const COIN_DECIMALS = { evm: 6, btc: 8, sol: 9 };
const COIN_SYMBOL = { evm: "ETH", btc: "BTC", sol: "SOL" };

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
  loadBtcFeeOptions(card, network);
  sendModal.classList.remove("hidden");
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
    container.innerHTML = `<p class="muted">${t("wallet.feeUnavailable", { err: e })}</p>`;
  }
}

document.getElementById("send-cancel").addEventListener("click", () => {
  sendModal.classList.add("hidden");
  sendContext = null;
});

const sendConfirmBtn = document.getElementById("send-confirm");
sendConfirmBtn.addEventListener("click", withBusyButton(sendConfirmBtn, async () => {
  if (!sendContext) return;
  const errorEl = document.getElementById("send-error");
  const successEl = document.getElementById("send-success");
  hideError(errorEl);
  successEl.classList.add("hidden");

  const network = networkForCard(sendContext.card);
  const to = document.getElementById("send-to").value.trim();
  const amount = document.getElementById("send-amount").value.trim();
  const password = document.getElementById("send-password").value;

  if (!to || !amount || !password) {
    showError(errorEl, t("wallet.allFieldsRequired"));
    return;
  }
  if (sendContext.coin === "btc" && !sendContext.feeSat) {
    showError(errorEl, t("wallet.btcFeesNotLoaded"));
    return;
  }

  try {
    const txResult = await invoke("send_transaction", {
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

document.getElementById("copy-cert").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(document.getElementById("cert-armored").value);
  } catch (e) {
    alert(t("common.copyFailed", { err: e }));
  }
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

    const removeBtn = document.createElement("button");
    removeBtn.textContent = t("message.removeRecipient");
    removeBtn.addEventListener("click", async () => {
      await invoke("remove_recipient", { label: r.label });
      loadRecipients();
    });

    item.appendChild(infoDiv);
    item.appendChild(removeBtn);
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

document.getElementById("copy-encrypted").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(document.getElementById("encrypt-result").value);
  } catch (e) {
    alert(t("common.copyFailed", { err: e }));
  }
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

// --- Démarrage -------------------------------------------------------------

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const exists = await invoke("wallet_exists");
    showView(exists ? "unlock" : "onboarding");
  } catch (e) {
    console.error(e);
    showView("onboarding");
  }
});
