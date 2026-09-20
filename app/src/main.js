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
    button.dataset.busyText ??= "Patiente…";
    button.textContent = button.dataset.busyText;
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
    hintEl.textContent = `Au moins ${MIN_PASSWORD_LENGTH} caractères, mélange de types recommandé.`;
    return;
  }
  const strength = estimatePasswordStrength(password);
  const labels = {
    faible: "Force : faible",
    moyen: "Force : moyenne",
    fort: "Force : bonne",
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
    showError(errorEl, `Le mot de passe doit faire au moins ${MIN_PASSWORD_LENGTH} caractères.`);
    return;
  }
  if (estimatePasswordStrength(password) === "faible") {
    showError(errorEl, "Ce mot de passe est trop faible ou trop prévisible — essayez un mélange de lettres, chiffres et symboles.");
    return;
  }
  if (password !== confirm) {
    showError(errorEl, "Les deux mots de passe ne correspondent pas.");
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
      <h3>Part ${i + 1} — ${backup.label}</h3>
      <p class="muted">Mot de passe de cette part :</p>
      <div class="passphrase">${backup.passphrase}</div>
      <div class="row-buttons">
        <button class="secondary" data-kind="share">Télécharger le fichier de part</button>
        <button class="secondary" data-kind="privkey">Télécharger la clé privée</button>
      </div>
    `;
    item.querySelector('[data-kind="share"]').addEventListener("click", async (e) => {
      try {
        await saveBase64ToFile(backup.encrypted_share_b64, `${backup.label}_share.asc`);
      } catch (err) {
        alert(`Échec de l'enregistrement : ${err}`);
      }
    });
    item.querySelector('[data-kind="privkey"]').addEventListener("click", async (e) => {
      try {
        await saveBase64ToFile(backup.privkey_armored_b64, `${backup.label}_privkey.asc`);
      } catch (err) {
        alert(`Échec de l'enregistrement : ${err}`);
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
  const sure = confirm(
    "Supprimer le coffre local de cet appareil ? Vous ne pourrez le récupérer qu'avec 2 de vos 3 parts de sauvegarde. Continuer ?"
  );
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
  const sure = confirm(
    "Supprimer le coffre local de cet appareil ? Vous ne pourrez le récupérer qu'avec 2 de vos 3 parts de sauvegarde. Continuer ?"
  );
  if (!sure) return;
  try {
    await invoke("reset_wallet");
    profilesCache = [];
    currentProfileIndex = 0;
    stopBalanceAutoRefresh();
    showView("onboarding");
  } catch (e) {
    alert(`Erreur : ${e}`);
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
    showError(errorEl, "Mot de passe requis.");
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

function resetAutoLockTimer() {
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
    showError(errorEl, "Les 4 fichiers (2 parts + 2 clés privées) sont requis.");
    return;
  }
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    showError(errorEl, `Le nouveau mot de passe doit faire au moins ${MIN_PASSWORD_LENGTH} caractères.`);
    return;
  }
  if (estimatePasswordStrength(newPassword) === "faible") {
    showError(errorEl, "Ce mot de passe est trop faible ou trop prévisible — essayez un mélange de lettres, chiffres et symboles.");
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
  try {
    latestPrices = await invoke("get_crypto_prices");
  } catch (e) {
    console.error(e);
    latestPrices = null;
  }
  document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
  loadMarkets();
  // Garde les montants rapides de la modale d'envoi synchronisés avec le cours si
  // elle reste ouverte pendant un cycle de rafraîchissement (toutes les 60s, voir
  // startPriceAutoRefresh) — sans ça, un montant rapide cliqué plus tard dans une
  // session longue refléterait un prix périmé.
  if (!sendModal.classList.contains("hidden")) renderQuickAmounts();
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
    container.innerHTML = '<p class="muted">Impossible de charger les données de marché.</p>';
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
    showError(errorEl, "Nom du profil requis.");
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
    alert("Impossible d'archiver le dernier profil actif restant.");
    return;
  }
  const profile = currentProfile();
  if (!profile) return;

  const sure = confirm(
    `Archiver le profil "${profile.label}" ? Il disparaîtra du sélecteur mais restera récupérable ` +
      "à tout moment depuis Paramètres → Profils archivés."
  );
  if (!sure) return;

  try {
    await invoke("archive_profile", { index: profile.index });
    profilesCache = profilesCache.filter((p) => p.index !== profile.index);
    currentProfileIndex = profilesCache[0].index;
    renderProfileSelect();
    renderCardAddresses();
    refreshAllBalances();
  } catch (e) {
    alert(`Erreur : ${e}`);
  }
}));

// --- Profils archivés (Paramètres) : restaurer ou supprimer définitivement -----

async function loadArchivedProfiles() {
  const container = document.getElementById("archived-profiles-list");
  try {
    const archived = await invoke("list_archived_profiles");
    container.innerHTML = "";
    if (archived.length === 0) {
      container.innerHTML = '<p class="muted">Aucun profil archivé.</p>';
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
      restoreBtn.textContent = "Restaurer";
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
          alert(`Erreur : ${e}`);
        }
      });

      const deleteBtn = document.createElement("button");
      deleteBtn.className = "secondary";
      deleteBtn.textContent = "Supprimer définitivement";
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
  document.getElementById("delete-profile-warning").textContent =
    `Vous êtes sur le point de supprimer définitivement le profil "${profile.label}". Si des fonds ont déjà été ` +
    "envoyés sur son adresse, ils deviendront inaccessibles depuis cette application.";
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
    showError(errorEl, "Mot de passe requis.");
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
  const coin = card.dataset.coin;
  const network = networkForCard(card);
  const address = addressForCoin(coin, network);
  const balanceEl = card.querySelector('[data-field="balance"]');
  balanceEl.textContent = "…";
  try {
    const balance = await invoke("get_balance", { network, address });
    balanceEl.textContent = balance;
  } catch (e) {
    balanceEl.textContent = "erreur";
    console.error(e);
  }
  updateFiatValue(card);
  checkPendingTx(card, address, network);
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
  card.querySelector('[data-action="refresh"]').addEventListener("click", () => refreshBalance(card));
  card.querySelector('[data-action="send"]').addEventListener("click", () => openSendModal(card));
  card.querySelector('[data-action="qr"]').addEventListener("click", () => openQrModal(card));
  card.querySelector('[data-action="history"]').addEventListener("click", () => openHistoryModal(card));
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
    alert("Adresse pas encore disponible pour ce profil — déverrouillez le portefeuille une fois pour la faire apparaître.");
    return;
  }
  try {
    const svg = await invoke("generate_qr_svg", { text: address });
    document.getElementById("qr-container").innerHTML = svg;
    document.getElementById("qr-address-text").textContent = address;
    qrModal.classList.remove("hidden");
  } catch (e) {
    alert(`Impossible de générer le QR code : ${e}`);
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
  if (status === "confirmed") return "Confirmée";
  if (status === "pending") return "En attente";
  if (status === "failed") return "Échouée";
  return status;
}

async function openHistoryModal(card) {
  const coin = card.dataset.coin;
  const network = networkForCard(card);
  const address = addressForCoin(coin, network);
  const coinLabel = card.querySelector("h2").textContent.trim();
  document.getElementById("history-modal-title").textContent = `Historique — ${coinLabel}`;
  const container = document.getElementById("history-list");
  container.innerHTML = '<p class="muted">Chargement…</p>';
  historyModal.classList.remove("hidden");

  if (!address) {
    container.innerHTML =
      '<p class="muted">Adresse pas encore disponible pour ce profil — déverrouillez le portefeuille une fois pour la faire apparaître.</p>';
    return;
  }

  try {
    const entries = await invoke("get_tx_history", { network, address });
    container.innerHTML = "";
    if (entries.length === 0) {
      container.innerHTML = '<p class="muted">Aucune transaction pour cette adresse.</p>';
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
      link.textContent = "Voir ↗";
      link.addEventListener("click", () => {
        invoke("open_external_link", { url: tx.explorer_url }).catch((e) => alert(`Impossible d'ouvrir le lien : ${e}`));
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
  container.innerHTML = '<p class="muted">Calcul des frais…</p>';

  const address = addressForCoin("btc", network);
  if (!address) {
    container.innerHTML = '<p class="muted">Adresse indisponible.</p>';
    return;
  }

  try {
    const fees = await invoke("estimate_btc_fees", { network, address });
    const tiers = [
      { key: "fast_sat", label: "Rapide", hint: "~20 min" },
      { key: "medium_sat", label: "Moyen", hint: "~1 h" },
      { key: "slow_sat", label: "Lent", hint: "~1 jour" },
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
    container.innerHTML = `<p class="muted">Frais indisponibles : ${e}</p>`;
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
    showError(errorEl, "Tous les champs sont requis.");
    return;
  }
  if (sendContext.coin === "btc" && !sendContext.feeSat) {
    showError(errorEl, "Frais Bitcoin non chargés — patiente un instant ou réessaie.");
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
    successEl.textContent = `Transaction envoyée : ${txResult}`;
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
    alert(`Copie impossible : ${e}`);
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
    container.innerHTML = '<p class="muted">Aucun destinataire pour l\'instant.</p>';
    picker.innerHTML = '<p class="muted">Ajoutez d\'abord un destinataire ci-dessus.</p>';
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
    removeBtn.textContent = "Supprimer";
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
    showError(errorEl, "Nom et clé publique requis.");
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
    showError(errorEl, "Choisissez au moins un destinataire (ajoutez-en un si la liste est vide).");
    return;
  }
  if (!message) {
    showError(errorEl, "Le message ne peut pas être vide.");
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
    alert(`Copie impossible : ${e}`);
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
    showError(errorEl, "Message chiffré et mot de passe requis.");
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
