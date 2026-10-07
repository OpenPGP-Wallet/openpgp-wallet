// Fenêtre de confirmation ouverte par Rust pour les actions sensibles qui ne
// sont pas des transactions (voir lib.rs, `secure_confirm`). Elle affiche le
// contenu donné par Rust et lui renvoie la réponse ; c'est Rust qui vérifie le
// délai et la phrase, et qui n'accepte la réponse que de CETTE fenêtre — la
// page principale de l'app ne peut ni l'ouvrir, ni l'atteindre, ni répondre.
const { invoke } = window.__TAURI__.core;

// Même thème que l'app (même stockage local).
const THEMES = ["default", "purple", "orange", "dark", "light"];
let theme = "default";
try {
  const saved = localStorage.getItem("pgp-wallet-theme");
  if (THEMES.includes(saved)) theme = saved;
} catch (e) {
  // Stockage indisponible : thème par défaut.
}
if (theme !== "default") document.documentElement.dataset.theme = theme;

// Pictogrammes : constantes, jamais de contenu reçu inséré comme HTML.
const svg = (paths) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;
const ICONS = {
  trash: svg('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3" />'),
  key: svg('<circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M16 7l3 3M14 9l2 2" />'),
  swap: svg('<path d="M4 8h13l-3-3M20 16H7l3 3" />'),
  usb: svg('<path d="M9 2h6v6H9zM7 8h10v6a5 5 0 0 1-10 0zM12 19v3" />'),
  fingerprint: svg(
    '<path d="M12 11v3a8 8 0 0 1-1 4M8 12a4 4 0 0 1 8 0v1a12 12 0 0 1-1 5M5 10a7 7 0 0 1 14 0v2M4 15c.5-1 .8-2 1-3M19 15.5c.3-1 .6-2 .7-3" />'
  ),
};

// Délai avant de pouvoir confirmer (Rust le vérifie aussi) : une touche
// Entrée tapée dans l'app au moment où la fenêtre apparaît ne la valide pas.
const CONFIRM_DELAY_MS = 1000;

const normalize = (text) => text.trim().split(/\s+/).join(" ").toLocaleUpperCase();

const root = document.getElementById("secure-confirm");
const ok = document.getElementById("confirm-ok");
const cancel = document.getElementById("confirm-cancel");
const input = document.getElementById("confirm-phrase-input");
const errorEl = document.getElementById("confirm-error");
let phrase = null;
let delayOver = false;

function refreshOk() {
  const matches = phrase !== null && normalize(input.value) === normalize(phrase);
  document.body.classList.toggle("phrase-ok", matches);
  ok.disabled = !delayOver || (phrase !== null && !matches);
}

async function answer(accepted) {
  if (accepted && ok.disabled) return;
  ok.disabled = true;
  cancel.disabled = true;
  errorEl.classList.add("hidden");
  try {
    await invoke("secure_confirm_answer", { accepted, typed: phrase === null ? null : input.value });
  } catch (e) {
    errorEl.textContent = String(e);
    errorEl.classList.remove("hidden");
    cancel.disabled = false;
    refreshOk();
  }
}

async function start() {
  const details = await invoke("secure_confirm_details");
  document.documentElement.lang = details.lang;
  document.title = details.title;
  document.body.dataset.tone = details.danger ? "danger" : "warning";
  document.getElementById("confirm-icon").innerHTML = ICONS[details.icon] ?? ICONS.key;
  document.getElementById("confirm-title").textContent = details.title;
  document.getElementById("confirm-body").replaceChildren(
    ...details.paragraphs.map((paragraph) => Object.assign(document.createElement("p"), { textContent: paragraph }))
  );
  const note = document.getElementById("confirm-note");
  note.textContent = details.note;
  note.classList.toggle("hidden", !details.note);
  ok.textContent = details.confirm_label;
  ok.classList.toggle("danger", details.danger);
  cancel.textContent = details.cancel_label;
  if (details.phrase) {
    phrase = details.phrase;
    document.getElementById("confirm-phrase-block").classList.remove("hidden");
    document.getElementById("confirm-phrase-prompt").textContent = details.phrase_prompt ?? "";
    document.getElementById("confirm-phrase").textContent = details.phrase;
  }
  refreshOk();
  root.classList.remove("hidden");
  await invoke("secure_confirm_ready", { theme, height: Math.ceil(root.getBoundingClientRect().height) + 2 });
  // « Annuler » par défaut ; la phrase, s'il faut l'écrire.
  (phrase !== null ? input : cancel).focus();
  setTimeout(() => {
    delayOver = true;
    refreshOk();
  }, CONFIRM_DELAY_MS);
}

ok.addEventListener("click", () => answer(true));
cancel.addEventListener("click", () => answer(false));
input.addEventListener("input", refreshOk);
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") answer(true);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") answer(false);
});

start().catch((e) => {
  document.getElementById("confirm-title").textContent = String(e);
  root.classList.remove("hidden");
});
