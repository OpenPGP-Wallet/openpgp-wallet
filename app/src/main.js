import { renderLineChart, renderSparkline } from "./charts.js";

// --- Cryptos du portefeuille --------------------------------------------------
// Une carte par crypto, un ou plusieurs réseaux par carte (menu réseau).
// `family` : format d'adresse et chemin d'envoi — « evm » : même adresse sur
// tous les réseaux EVM, virement natif par `send_transaction` (le backend
// valide le réseau et affiche la confirmation). Les 4 premières ont leur carte
// dans index.html ; les autres sont générées ci-dessous, avec exactement la
// même structure (tout le reste du code les traite de la même façon).
// `decimals` : décimales affichées pour les montants rapides de l'envoi.
const ASSETS = [
  { coin: "evm", name: "Ethereum", symbol: "ETH", family: "evm", icon: "/assets/eth.svg", gecko: "ethereum", decimals: 6, chart: "ETH", networks: ["evm_mainnet", "arbitrum_mainnet", "base_mainnet", "evm_sepolia"] },
  { coin: "btc", name: "Bitcoin", symbol: "BTC", family: "btc", icon: "/assets/btc.webp", gecko: "bitcoin", decimals: 8, chart: "BTC", networks: ["btc_mainnet", "btc_testnet"] },
  { coin: "sol", name: "Solana", symbol: "SOL", family: "sol", icon: "/assets/sol.png", gecko: "solana", decimals: 9, chart: "SOL", networks: ["sol_mainnet", "sol_devnet"] },
  // USDC : jeton SPL sur Solana (chemin USDC historique, core/src/sol_spl.rs) et
  // ERC-20 sur Ethereum, Base et Arbitrum (registre des jetons).
  { coin: "usdc", name: "USDC", symbol: "USDC", token: true, icon: "/assets/usdc.png", gecko: "usd-coin", decimals: 6, unitDecimals: 6, chart: "USDC", networks: ["sol_mainnet", "evm_mainnet", "base_mainnet", "arbitrum_mainnet"], contracts: { sol_mainnet: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", evm_mainnet: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", base_mainnet: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", arbitrum_mainnet: "0xaf88d065e77c8cc2239327c5edb3a432268e5831" } },
  { coin: "bnb", name: "BNB", symbol: "BNB", family: "evm", icon: "/assets/bnb.png", gecko: "binancecoin", decimals: 6, chart: "BNB", networks: ["bsc_mainnet"] },
  { coin: "avax", name: "Avalanche", symbol: "AVAX", family: "evm", icon: "/assets/avax.png", gecko: "avalanche-2", decimals: 6, chart: "AVAX", networks: ["avax_mainnet"] },
  { coin: "pol", name: "Polygon", symbol: "POL", family: "evm", icon: "/assets/pol.png", gecko: "polygon-ecosystem-token", decimals: 6, chart: "POL", networks: ["polygon_mainnet"] },
  { coin: "hype", name: "Hyperliquid", symbol: "HYPE", family: "evm", icon: "/assets/hype.jpg", iconRound: true, gecko: "hyperliquid", decimals: 6, chart: "HYPE", networks: ["hyperevm_mainnet"] },
  { coin: "zec", name: "Zcash", symbol: "ZEC", family: "zec", icon: "/assets/zec.png", gecko: "zcash", decimals: 8, chart: "ZEC", networks: ["zec_mainnet"] },
  // Jetons (`token: true`) : contrats et mints relevés dans core/src/tokens.rs —
  // SEUL le registre Rust fait foi pour un envoi (l'interface n'envoie que
  // l'identifiant et le réseau) ; ceux-ci ne servent qu'aux demandes de
  // paiement (QR). Test `frontend_token_contracts_match_the_registry` (lib.rs).
  { coin: "usdt", name: "Tether", symbol: "USDT", token: true, icon: "/assets/usdt.png", gecko: "tether", decimals: 6, unitDecimals: 6, chart: null, networks: ["evm_mainnet", "sol_mainnet"], contracts: { evm_mainnet: "0xdac17f958d2ee523a2206206994597c13d831ec7", sol_mainnet: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" } },
  { coin: "link", name: "Chainlink", symbol: "LINK", token: true, icon: "/assets/link.png", gecko: "chainlink", decimals: 6, unitDecimals: 18, chart: "LINK", networks: ["evm_mainnet", "arbitrum_mainnet", "base_mainnet"], contracts: { evm_mainnet: "0x514910771af9ca656af840dff83e8264ecf986ca", arbitrum_mainnet: "0xf97f4df75117a78c1a5a0dbb814af92458539fb4", base_mainnet: "0x88fb150bdc53a65fe94dea0c9ba0a6daf8c6e196" } },
  { coin: "dai", name: "Dai", symbol: "DAI", token: true, icon: "/assets/dai.png", gecko: "dai", decimals: 6, unitDecimals: 18, chart: "DAI", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x6b175474e89094c44da98b954eedeac495271d0f" } },
  { coin: "usde", name: "Ethena USDe", symbol: "USDe", token: true, icon: "/assets/usde.png", gecko: "ethena-usde", decimals: 6, unitDecimals: 18, chart: "USDE", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x4c9edd5852cd905f086c759e8383e09bff1e68b3" } },
  { coin: "uni", name: "Uniswap", symbol: "UNI", token: true, icon: "/assets/uni.png", gecko: "uniswap", decimals: 6, unitDecimals: 18, chart: "UNI", networks: ["evm_mainnet", "arbitrum_mainnet"], contracts: { evm_mainnet: "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", arbitrum_mainnet: "0xfa7f8980b0f1e64a2062791cc3b0871572f1f7f0" } },
  { coin: "usdg", name: "Global Dollar", symbol: "USDG", token: true, icon: "/assets/usdg.png", gecko: "global-dollar", decimals: 6, unitDecimals: 6, chart: null, networks: ["evm_mainnet", "arbitrum_mainnet"], contracts: { evm_mainnet: "0xe343167631d89b6ffc58b88d6b7fb0228795491d", arbitrum_mainnet: "0x004b506865409877c9fa29bfb1eba929984b9bbc" } },
  { coin: "xaut", name: "Tether Gold", symbol: "XAUt", token: true, icon: "/assets/xaut.png", gecko: "tether-gold", decimals: 6, unitDecimals: 6, chart: "XAUT", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x68749665ff8d2d112fa859aa293f07a622782f38" } },
  { coin: "ondo", name: "Ondo", symbol: "ONDO", token: true, icon: "/assets/ondo.png", gecko: "ondo-finance", decimals: 6, unitDecimals: 18, chart: "ONDO", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0xfaba6f8e4a5e8ab82f62fe7c39859fa577269be3" } },
  { coin: "fet", name: "Fetch.ai (ASI)", symbol: "FET", token: true, icon: "/assets/fet.png", gecko: "fetch-ai", decimals: 6, unitDecimals: 18, chart: "FET", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0xaea46a60368a7bd060eec7df8cba43b7ef41ad85" } },
  { coin: "eurc", name: "EURC", symbol: "EURC", token: true, icon: "/assets/eurc.png", gecko: "euro-coin", decimals: 6, unitDecimals: 6, chart: "EURC", networks: ["evm_mainnet", "base_mainnet", "sol_mainnet"], contracts: { evm_mainnet: "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c", base_mainnet: "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42", sol_mainnet: "HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr" } },
  { coin: "gno", name: "Gnosis", symbol: "GNO", token: true, icon: "/assets/gno.png", gecko: "gnosis", decimals: 6, unitDecimals: 18, chart: "GNO", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x6810e776880c02933d47db1b9fc05908e5386b96" } },
  { coin: "arb", name: "Arbitrum", symbol: "ARB", token: true, icon: "/assets/arb.jpg", iconRound: true, gecko: "arbitrum", decimals: 6, unitDecimals: 18, chart: "ARB", networks: ["arbitrum_mainnet", "evm_mainnet"], contracts: { arbitrum_mainnet: "0x912ce59144191c1204e64559fe8253a0e49e6548", evm_mainnet: "0xb50721bcf8d664c30412cfbc6cf7a15145234ad1" } },
  { coin: "aster", name: "Aster", symbol: "ASTER", token: true, icon: "/assets/aster.png", gecko: "aster-2", decimals: 6, unitDecimals: 18, chart: "ASTER", networks: ["bsc_mainnet"], contracts: { bsc_mainnet: "0x000ae314e2a2172a039b26378814c252734f556a" } },
  { coin: "vvv", name: "Venice", symbol: "VVV", token: true, icon: "/assets/vvv.png", gecko: "venice-token", decimals: 6, unitDecimals: 18, chart: "VVV", networks: ["base_mainnet"], contracts: { base_mainnet: "0xacfe6019ed1a7dc6f7b508c02d1b04ec88cc21bf" } },
  { coin: "render", name: "Render", symbol: "RENDER", token: true, icon: "/assets/render.png", gecko: "render-token", decimals: 6, unitDecimals: 8, chart: "RENDER", networks: ["sol_mainnet"], contracts: { sol_mainnet: "rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof" } },
];
const ASSET_BY_COIN = Object.fromEntries(ASSETS.map((asset) => [asset.coin, asset]));
const ASSET_BY_GECKO = Object.fromEntries(ASSETS.map((asset) => [asset.gecko, asset]));
// Monnaie native de chaque réseau (ETH sur Ethereum, Arbitrum et Base ; BNB
// sur BNB Chain…) : unité et prix des wallets externes et comptes matériels.
const NATIVE_ASSET_BY_NETWORK = Object.fromEntries(
  ASSETS.filter((asset) => !asset.token).flatMap((asset) => asset.networks.map((network) => [network, asset]))
);

// Logo d'une crypto, devant son nom partout où il apparaît (titres, menus,
// listes, aperçus) ; `null` pour un identifiant inconnu.
function coinIconEl(coin) {
  const asset = ASSET_BY_COIN[coin];
  if (!asset) return null;
  const img = document.createElement("img");
  img.src = asset.icon;
  img.alt = "";
  img.className = "coin-icon-inline";
  if (asset.iconRound) img.classList.add("coin-icon-round");
  if (coin === "sol") img.classList.add("coin-icon-inline-sol");
  return img;
}

// Remplace le contenu de `el` par le logo de `coin` suivi de `text`.
function setWithCoinIcon(el, coin, text) {
  const icon = coinIconEl(coin);
  el.replaceChildren(...(icon ? [icon] : []), document.createTextNode(text));
}

// Échange (« Convertir ») : paires possibles, lues auprès de Rust au démarrage
// (`swap_pairs`, core/src/swap_routes.rs) —
// [{ from_coin, from_network, to_coin, to_network, protocol, via, then_protocol }].
let swapPairs = [];
// Échange en 2 étapes en cours (voir « suivi de la crypto intermédiaire »).
let pendingRoute = null;
let routePollTimer = null;

const ICON_CONVERT = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 8h13l-3-3M20 16H7l3 3" /></svg>`;

// Champ de montant : chiffres et un seul séparateur décimal (point ou virgule),
// filtrés à la frappe plutôt que refusés après coup — un montant ne peut rien
// contenir d'autre. Écouteur en phase de capture : il passe avant ceux qui
// lisent la valeur (QR, conversion).
function restrictToAmount(input, onChange) {
  input.addEventListener(
    "input",
    () => {
      let value = input.value.replace(/[^0-9.,]/g, "");
      const separatorIndex = value.search(/[.,]/);
      if (separatorIndex !== -1) {
        value = value.slice(0, separatorIndex + 1) + value.slice(separatorIndex + 1).replace(/[.,]/g, "");
      }
      if (value !== input.value) input.value = value;
      if (onChange) onChange();
    },
    true
  );
}

// Réseau → format d'adresse : même adresse sur tous les réseaux EVM, une
// adresse Solana (SOL et jetons SPL), Bitcoin à part.
function isEvmNetwork(network) {
  return network in EVM_CHAIN_IDS;
}

// Jeton passant par le registre Rust (get_token_balance/send_token_transaction) :
// tout jeton, sauf l'USDC sur Solana qui garde son chemin historique.
function usesTokenRegistry(coin, network) {
  return ASSET_BY_COIN[coin]?.token === true && !(coin === "usdc" && network === "sol_mainnet");
}

// Réseaux EVM : identifiant de chaîne (demande de paiement EIP-681). Mêmes
// valeurs que core/src/wallet_flow.rs::EVM_NETWORKS.
const EVM_CHAIN_IDS = {
  evm_mainnet: 1,
  evm_sepolia: 11155111,
  arbitrum_mainnet: 42161,
  base_mainnet: 8453,
  bsc_mainnet: 56,
  avax_mainnet: 43114,
  polygon_mainnet: 137,
  hyperevm_mainnet: 999,
};

const ICON_COPY = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" /></svg>`;
const ICON_QR = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true"><path d="M3 3h6v6H3z" fill="none" stroke="currentColor" stroke-width="1.6" /><rect x="5.2" y="5.2" width="1.6" height="1.6" /><path d="M15 3h6v6h-6z" fill="none" stroke="currentColor" stroke-width="1.6" /><rect x="17.2" y="5.2" width="1.6" height="1.6" /><path d="M3 15h6v6H3z" fill="none" stroke="currentColor" stroke-width="1.6" /><rect x="5.2" y="17.2" width="1.6" height="1.6" /><rect x="15" y="15" width="2.5" height="2.5" /><rect x="18.5" y="15" width="2.5" height="2.5" /><rect x="15" y="18.5" width="2.5" height="2.5" /><rect x="18.5" y="18.5" width="2.5" height="2.5" /></svg>`;
const ICON_EYE = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>`;

// Carte d'une crypto à un seul réseau (même structure que celles d'index.html).
// Textes via data-i18n (traduits par applyLanguage) ; nom et symbole fixes.
function buildAssetCard(asset) {
  const card = document.createElement("section");
  card.className = "wallet-card";
  card.dataset.coin = asset.coin;
  card.dataset.collapseKey = `wallet-${asset.coin}`;
  const iconClass = asset.iconRound ? "coin-icon coin-icon-round" : "coin-icon";
  card.innerHTML = `
    <header>
      <h2>
        <button type="button" class="collapse-toggle" aria-expanded="true" aria-controls="wallet-body-${asset.coin}">
          <span class="collapse-chevron" aria-hidden="true"></span>
          <img class="${iconClass}" src="${asset.icon}" alt="" /><span class="coin-name"></span>
        </button>
      </h2>
      ${
        asset.networks.length > 1
          ? `<div class="custom-select dropdown">
        <select class="network-select" data-coin="${asset.coin}">${asset.networks.map((n) => `<option value="${n}" data-i18n="net.${n}"></option>`).join("")}</select>
        <button type="button" class="custom-select-trigger"><span class="custom-select-label"></span><span class="select-arrow"></span></button>
        <ul class="custom-select-options"></ul>
      </div>`
          : `<span class="network-fixed-label muted" data-i18n="net.${asset.networks[0]}"></span>`
      }
    </header>
    <div class="balance-row">
      <p class="balance"><span data-field="balance">—</span> <span class="coin-symbol"></span></p>
      <div class="collapsed-actions">
        <button type="button" class="qr-btn" data-action="toggle-address" aria-pressed="false" data-i18n-title="wallet.showAddress">${ICON_EYE}</button>
        <button type="button" class="qr-btn" data-action="copy-address" data-i18n-title="wallet.copyAddress">${ICON_COPY}</button>
        <button type="button" class="qr-btn" data-action="qr" data-i18n-title="wallet.showQr">${ICON_QR}</button>
      </div>
    </div>
    <p class="fiat-value" data-field="fiat">—</p>
    <p class="address collapsed-address hidden" data-field="collapsed-address"></p>
    <div class="collapsible-body" id="wallet-body-${asset.coin}">
      <div class="collapsible-inner">
        <div class="address-row">
          <p class="address" data-field="address"></p>
          <button class="qr-btn" data-action="copy-address" data-i18n-title="wallet.copyAddress">${ICON_COPY}</button>
          <button class="qr-btn" data-action="qr" data-i18n-title="wallet.showQr">${ICON_QR}</button>
          <button class="convert-btn hidden" data-action="swap" data-i18n-title="wallet.convertHint">${ICON_CONVERT}<span data-i18n="wallet.convert">Convertir</span></button>
        </div>
        <div class="row-buttons">
          <button class="secondary" data-action="refresh" data-i18n="wallet.refresh">Actualiser</button>
          <button class="secondary" data-action="history" data-i18n="wallet.history">Historique</button>
          <button class="primary" data-action="send" data-i18n="wallet.send">Envoyer</button>
        </div>
      </div>
    </div>`;
  card.querySelector(".coin-name").textContent = asset.name;
  card.querySelector(".coin-symbol").textContent = asset.symbol;
  return card;
}

// Section de l'onglet Historique d'une crypto générée.
function buildHistorySection(asset) {
  const section = document.createElement("div");
  section.className = "history-section";
  section.id = `history-section-${asset.coin}`;
  section.innerHTML = `
    <div class="history-section-header">
      <h2 class="section-title"></h2>
      <span id="history-network-${asset.coin}" class="muted"></span>
    </div>
    <div id="history-list-${asset.coin}" class="history-list"></div>`;
  setWithCoinIcon(section.querySelector("h2"), asset.coin, asset.name);
  return section;
}

{
  const grid = document.querySelector(".wallet-grid");
  const historyCard = document.querySelector('.tab-panel[data-panel="history"] .card');
  for (const asset of ASSETS) {
    if (document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`)) continue; // carte d'index.html
    grid.appendChild(buildAssetCard(asset));
    historyCard.appendChild(buildHistorySection(asset));
  }
}

// --- Mes cryptos : cartes affichées -------------------------------------------
// Choix explicites { coin: true|false }, retenus sur l'appareil ; sans choix :
// les cryptos par défaut, et toute crypto sur laquelle des fonds sont
// détectés (voir refreshBalance) s'affiche d'elle-même.
const ASSETS_STORAGE_KEY = "pgp-wallet-assets";
const DEFAULT_ASSETS = ["evm", "btc", "sol", "usdc"];
let assetChoices = {};
try {
  const saved = JSON.parse(localStorage.getItem(ASSETS_STORAGE_KEY) || "{}");
  if (saved && typeof saved === "object") {
    for (const [coin, shown] of Object.entries(saved)) if (ASSET_BY_COIN[coin] && typeof shown === "boolean") assetChoices[coin] = shown;
  }
} catch (e) {
  // localStorage indisponible : cryptos par défaut.
}

function isAssetVisible(coin) {
  return coin in assetChoices ? assetChoices[coin] : DEFAULT_ASSETS.includes(coin);
}

function saveAssetChoices() {
  try {
    localStorage.setItem(ASSETS_STORAGE_KEY, JSON.stringify(assetChoices));
  } catch (e) {
    // Best-effort : le choix reste appliqué pour cette session.
  }
}

// Cartes et sections d'historique masquées selon les choix. Le menu
// « Recevoir » est reconstruit ailleurs (renderReceiveMenu, qui a besoin des
// traductions).
function applyAssetVisibility() {
  for (const asset of ASSETS) {
    const visible = isAssetVisible(asset.coin);
    document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`)?.classList.toggle("asset-hidden", !visible);
    document.getElementById(`history-section-${asset.coin}`)?.classList.toggle("asset-hidden", !visible);
  }
}
applyAssetVisibility();

// Cartes masquées (« Gérer mes cryptos ») : relues une seule fois par
// déverrouillage ou changement de profil — assez pour détecter des fonds et
// les afficher (revealIfFunded), sans relire une vingtaine de soldes chaque
// minute.
let hiddenBalancesChecked = false;

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
  // En vue liste, les cartes sont déjà des lignes compactes : leur repli n'y a
  // pas cours (voir « Panneaux repliables ») — titre retiré du parcours clavier.
  document.querySelectorAll(".wallet-card .collapse-toggle").forEach((toggle) => {
    toggle.tabIndex = enabled ? -1 : 0;
  });
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
    "onboarding.haveWallet": "J'ai déjà un portefeuille",
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
      "Ces 3 parts protègent votre portefeuille en cas de perte de cet appareil. <strong>2 des 3 suffisent</strong> à tout récupérer, mais aucune seule ne sert à rien — c'est voulu, personne (y compris vous) ne peut voler votre wallet avec une seule part. Le plus simple : enregistrez chaque part sur sa propre clé USB (rien à noter) et rangez les clés à des endroits différents. Sinon, téléchargez les fichiers et notez les mots de passe, séparément.",
    "backup.confirmCheckbox": "J'ai sauvegardé mes 3 parts (sur clés USB, ou fichiers et mots de passe)",
    "backup.saveUsb": "Enregistrer sur une clé USB",
    "backup.savedUsb": "✓ Enregistrée et vérifiée sur la clé « {label} »",
    "usb.title": "Part n°{n} sur une clé USB",
    "usb.hint": "Branchez une clé USB : elle est détectée automatiquement. Une clé = une part : deux parts réunies donnent accès à tout, gardez chaque clé à un endroit différent.",
    "usb.waiting": "En attente d'une clé USB…",
    "usb.write": "Écrire la part n°{n} ici",
    "usb.rewrite": "Contient déjà cette part — la réécrire",
    "usb.otherPart": "Contient déjà la part n°{part} de ce kit : une seule part par clé",
    "usb.otherKit": "Contient déjà une autre sauvegarde",
    "usb.writing": "Écriture et vérification…",
    "usb.done": "Part n°{n} enregistrée et vérifiée sur « {label} ». Retirez la clé et rangez-la à part, loin des autres parts.",
    "usb.free": "{mb} Mo libres",
    "backup.disclaimerTitle": "⚠ Une part par appareil, à des endroits différents",
    "backup.disclaimerText":
      "Mettez chaque part sur un appareil différent, rangé ailleurs. Deux parts réunies donnent accès à tout le portefeuille.",
    "backup.statusTodo": "À sauvegarder",
    "backup.statusDone": "✓ Sauvegardée",
    "backup.shareDownloaded": "✓ Fichier de part téléchargé",
    "backup.privkeyDownloaded": "✓ Clé privée téléchargée",
    "backup.progress": "Parts sauvegardées : {n}/{total} — sauvegardez-les toutes pour continuer.",
    "backup.progressDone": "✓ Les {total} parts sont sauvegardées.",
    "backup.saveAllUsb": "Tout enregistrer sur une seule clé USB",
    "backup.saveAllHint": "Plus simple, mais cette clé suffira seule à tout récupérer : rangez-la en lieu sûr.",
    "usb.titleAll": "Les 3 parts sur une clé USB",
    "usb.hintAll": "Branchez une clé USB : elle est détectée automatiquement. Les 3 parts y seront enregistrées : cette clé suffira à elle seule à tout récupérer.",
    "usb.writeAll": "Tout écrire ici",
    "usb.rewriteAll": "Contient déjà des parts de ce kit — tout réécrire",
    "usb.doneAll": "Les 3 parts enregistrées et vérifiées sur « {label} ». Cette clé suffit à tout récupérer : rangez-la en lieu sûr, jamais avec l'ordinateur.",
    "restore.usbTitle": "Avec mes clés USB de sauvegarde",
    "restore.usbHint": "Branchez vos clés de sauvegarde, l'une après l'autre si besoin : l'app les lit toute seule. Deux parts différentes suffisent.",
    "restore.usbWaiting": "Aucune clé de sauvegarde détectée pour l'instant.",
    "restore.usbPart": "✓ Part n°{n} lue (clé « {label} »)",
    "restore.usbReady": "Deux parts lues : choisissez un nouveau mot de passe puis restaurez. Vous pouvez retirer les clés.",
    "restore.usbSubmit": "Restaurer depuis les clés USB",
    "restore.orFiles": "ou avec les fichiers",
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
      "Branchez 2 de vos 3 clés USB de sauvegarde, ou fournissez 2 fichiers de part avec leur mot de passe, puis choisissez un nouveau mot de passe pour cet appareil.",
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
    "wallet.history": "Historique",
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
    "nav.walletconnect": "WalletConnect",
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
    "wallet.convert": "Convertir",
    "wallet.convertHint": "Échanger contre une autre crypto",
    "wallet.pendingBadge": "⏳ Transaction en attente détectée",
    "wallet.pendingIncoming": "⏳ Réception en attente : +{amount} BTC (comptée une fois confirmée)",
    "wallet.marketsTitle": "Prix des cryptomonnaies en direct",
    "wallet.showQr": "Afficher en QR code",
    "wallet.copyAddress": "Copier l'adresse",
    "wallet.showAddress": "Afficher l'adresse",
    "wallet.hideAddress": "Masquer l'adresse",
    "wallet.addressCopied": "Adresse copiée !",
    "wallet.ethereumMainnet": "Ethereum — Fonds réels",
    "wallet.arbitrum": "Arbitrum — Fonds réels",
    "wallet.base": "Base — Fonds réels",
    "net.bsc_mainnet": "BNB Chain — Fonds réels",
    "net.evm_mainnet": "Ethereum — Fonds réels",
    "net.arbitrum_mainnet": "Arbitrum — Fonds réels",
    "net.base_mainnet": "Base — Fonds réels",
    "net.sol_mainnet": "Solana — Fonds réels",
    "net.zec_mainnet": "Zcash — Fonds réels",
    "wallet.historyExplorerOnly": "Pas d'historique ici pour ce réseau : aucun service public gratuit ne le fournit. Il reste consultable sur l'explorateur du réseau.",
    "wallet.historyOpenExplorer": "Voir sur l'explorateur",
    "net.avax_mainnet": "Avalanche — Fonds réels",
    "net.polygon_mainnet": "Polygon — Fonds réels",
    "net.hyperevm_mainnet": "HyperEVM — Fonds réels",
    "wallet.receiveAsset": "Recevoir {symbol}",
    "assets.manage": "Gérer mes cryptos",
    "assets.organize": "Organiser",
    "organize.sortBy": "Trier :",
    "organize.custom": "Mon ordre",
    "organize.value": "Valeur détenue",
    "organize.name": "Nom",
    "organize.hint": "Glissez les cartes pour les réordonner (ou utilisez les flèches).",
    "organize.done": "Terminé",
    "organize.drag": "Glisser pour déplacer",
    "organize.moveUp": "Avancer",
    "organize.moveDown": "Reculer",
    "assets.title": "Mes cryptos",
    "assets.hint": "Cochez les cryptos à afficher. Une crypto sur laquelle des fonds arrivent s'affiche d'elle-même.",
    "assets.done": "Terminé",
    "assets.autoShown": "{symbol} affiché : des fonds ont été détectés.",
    "charts.constantBalance": "Sans historique sur leur réseau : {list} — solde actuel compté sur toute la période.",
    "settings.currency": "Devise d'affichage",
    "settings.usd": "Dollar ($)",
    "settings.eur": "Euro (€)",
    "charts.eurNote": "Montants en euros au taux EUR/USD de chaque date (Binance).",
    "charts.eurNoteBefore2020": "Avant le 3 janvier 2020 (début de la cotation) : taux de ce jour-là.",
    "send.quickUnavailable": "Montants rapides indisponibles (prix non chargé).",
    "qr.amountLabel": "Montant à demander (facultatif)",
    "qr.amountHint": "Le QR code contient aussi ce montant : l'application de la personne qui paie le pré-remplit (si elle le prend en charge).",
    "qr.amountInvalid": "Montant invalide : un nombre positif, {decimals} décimales au plus.",
    "wallet.received": "Reçu : +{amount} {symbol}{fiat}",
    "wallet.receivedPending": "Réception en attente : +{amount} BTC (comptée une fois confirmée)",
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
    "collapse.collapse": "Replier",
    "collapse.expand": "Déplier",
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
    "send.mainnetWarning": "⚠ Réseau MAINNET — ceci dépense de vrais fonds, irréversible.",
    "send.toAddress": "Adresse destinataire",
    "send.amount": "Montant",
    "send.amountFiat": "Montant dans la devise affichée",
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
      "Passe par un protocole externe non audité par cette app (voir \"Comment ça marche\"). Frais d'affiliation inclus : 0,80 % (THORChain, Maya, Jupiter, LI.FI), 1 % (CoW, sur un même réseau EVM), sauf mention contraire dans la confirmation.",
    "swap.fromAsset": "Depuis",
    "swap.toAsset": "Vers",
    "swap.viaJupiter": "via Jupiter, même portefeuille",
    "swap.viaCow": "via CoW, même portefeuille",
    "swap.viaTwoSteps": "en 2 étapes, via {via}",
    "swap.provider": "Fournisseur",
    "swap.providerOption": "{name} — frais {fee}",
    "swap.providerRecommended": "{name} — frais {fee} (recommandé)",
    "swap.twoStepHint":
      "Pas de route directe : l'échange se fait en 2 étapes. 1) {from} → {via} ({first}), reçu sur votre propre adresse. 2) Dès que {via} est arrivé, l'app vous propose {via} → {to} ({second}), avec une seconde confirmation.",
    "swap.previewRoute": "Étape 1 sur 2 : vers {via} ({first}). Ensuite, {via} → {to} ({second}) vous sera proposé dès l'arrivée de {via}.",
    "swap.routeStep1Sent": "Étape 1 envoyée : l'étape 2 vous sera proposée dès l'arrivée de {via}.",
    "swap.routeWaiting": "Échange en 2 étapes vers {to} : en attente de l'arrivée de {via} (étape 1). Entre deux réseaux, cela peut prendre jusqu'à une heure.",
    "swap.routeReady": "Étape 1 terminée : +{amount} {via} reçus. Étape 2 prête : {via} → {to}.",
    "swap.routeReadyToast": "{via} reçu : l'étape 2 de votre échange est prête.",
    "swap.routeLate": "{via} n'est pas encore arrivé (étape 1) : vérifiez l'historique. Vous pouvez arrêter le suivi, les fonds restent les vôtres.",
    "swap.routeContinue": "Faire l'étape 2",
    "swap.routeAbandon": "Arrêter le suivi",
    "swap.unavailable": "Échange non disponible entre ces deux cryptos.",
    "swap.amount": "Montant",
    "swap.destination": "Adresse de destination",
    "swap.destinationHint":
      "Pré-remplie avec votre propre adresse sur le réseau choisi — modifiable si vous voulez échanger vers une autre adresse.",
    "swap.jupiterHint":
      "Même portefeuille : la crypto reçue arrive directement sur votre adresse de ce réseau, pas besoin d'adresse de destination séparée.",
    "swap.getQuote": "Obtenir un devis",
    "swap.previewTitle": "Vérifiez avant d'échanger",
    "swap.previewSending": "Envoi",
    "swap.previewReceiving": "Réception estimée",
    "swap.previewFees": "Frais du protocole (inclus)",
    "swap.previewFeesOf": "Frais {name} (inclus)",
    "swap.previewMin": "Minimum garanti",
    "swap.previewCost": "Coût estimé",
    "swap.previewCostTitle": "Écart entre la valeur envoyée et la valeur reçue au cours du marché, frais compris",
    "swap.previewCostHigh":
      "Coût élevé pour cet échange : vérifiez le montant. Sur un petit montant, les frais fixes du réseau pèsent lourd.",
    "swap.cowOrderSent": "Ordre envoyé à CoW — en attente d'exécution (au plus {minutes} min).",
    "swap.cowOrderFilled": "Ordre exécuté : les fonds sont arrivés.",
    "swap.cowOrderExpired": "Ordre expiré sans être exécuté : rien n'a été échangé.",
    "swap.cowOrderCancelled": "Ordre annulé : rien n'a été échangé.",
    "swap.cowOrderUnknown": "Suivi de l'ordre indisponible pour l'instant — voir CoW Explorer.",
    "swap.cowViewOrder": "Voir l'ordre",
    "swap.viaLifi": "via LI.FI",
    "swap.previewLifiRoute": "Pont (via LI.FI)",
    "swap.lifiDuration": "≈ {minutes} min",
    "swap.lifiSent": "Transaction envoyée. Transfert en cours (≈ {minutes} min)…",
    "swap.lifiDone": "Échange terminé : les fonds sont arrivés.",
    "swap.lifiPartial": "Échange terminé, mais reçu dans une autre crypto que prévu — voir LI.FI Scan.",
    "swap.lifiRefunded": "Le pont a remboursé le montant : l'échange n'a pas eu lieu.",
    "swap.lifiFailed": "Le transfert a échoué — voir LI.FI Scan (le pont rembourse selon ses règles).",
    "swap.lifiUnknown": "Suivi indisponible pour l'instant — voir LI.FI Scan.",
    "swap.lifiView": "Voir sur LI.FI Scan",
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
      "<strong>2 des 3 suffisent</strong> à tout récupérer. Le plus simple : chaque part sur sa propre clé USB (rien à noter), rangées à des endroits différents. Sinon, téléchargez les fichiers et notez les mots de passe, séparément.",
    "regenBackup.resultClose": "J'ai sauvegardé mes 3 nouvelles parts",
    "nav.ledger": "Ledger / Trezor",
    "ledger.title": "Portefeuille matériel (Ledger, Trezor)",
    "ledger.subtitle":
      "Les clés d'un portefeuille matériel ne quittent jamais l'appareil : chaque envoi s'affiche sur son écran et doit y être confirmé. Avant chaque opération, branchez-le et déverrouillez-le ; sur un Ledger, ouvrez aussi l'application du réseau (Ethereum, Bitcoin ou Solana) ; sur un Trezor, fermez Trezor Suite.",
    "ledger.add": "+ Ajouter un compte",
    "ledger.refresh": "Actualiser",
    "ledger.btcNote":
      "Bitcoin : compte natif SegWit (m/84'), première adresse de réception et première adresse de monnaie. Des fonds reçus sur d'autres adresses (par exemple avec Ledger Live ou Trezor Suite) n'apparaissent pas ici.",
    "ledger.empty": "Aucun compte matériel pour l'instant — ajoutez-en un avec le bouton ci-dessus.",
    "ledger.addTitle": "Ajouter un compte matériel",
    "ledger.addHint": "Branchez et déverrouillez l'appareil. Ledger : ouvrez-y l'application du réseau choisi. Trezor : fermez Trezor Suite.",
    "ledger.device": "Appareil",
    "ledger.label": "Nom (pour vous y retrouver)",
    "ledger.network": "Réseau",
    "ledger.read": "Lire le compte sur l'appareil",
    "ledger.labelRequired": "Le nom est requis.",
    "ledger.verify": "Vérifier sur l'appareil",
    "ledger.verifyPrompt": "Comparez l'adresse affichée par l'appareil avec celle-ci, puis confirmez-la sur l'appareil :\n{address}",
    "ledger.verified": "Adresse confirmée sur l'appareil.",
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
    "ledger.sendHint": "Après la confirmation de Windows, vérifiez le destinataire et le montant sur l'écran de l'appareil, puis confirmez-y.",
    "ledger.waitDevice": "Confirmez sur l'appareil…",
    "ledger.sent": "Transaction envoyée : {txid}",
    "ledger.fieldsRequired": "Le destinataire et le montant sont requis.",
    "charts.portfolioTitle": "Évolution du portefeuille",
    "charts.portfolioScope": "Profil affiché, fonds réels (mainnet)",
    "charts.externalTitle": "Évolution des wallets externes",
    "charts.externalAll": "Tous les wallets externes",
    "charts.expand": "Agrandir",
    "charts.marketsHint": "Cliquez sur une crypto pour voir sa courbe en grand.",
    "charts.showTable": "Afficher les données",
    "charts.hideTable": "Masquer les données",
    "charts.loading": "Chargement de la courbe…",
    "charts.noData": "Aucune donnée pour cette période.",
    "charts.portfolioEmpty": "Aucun fonds réel sur ce profil pour le moment.",
    "charts.externalEmpty": "Aucun fonds réel sur ces wallets externes.",
    "charts.since": "Valeur reconstruite à partir des dernières transactions de chaque adresse : connue depuis le {date}.",
    "charts.loadingHistoryStart":
      "Lecture de l'historique en cours — le nœud Solana public n'accorde qu'environ une transaction par seconde ; les chargements suivants seront presque immédiats.",
    "charts.loadingHistory":
      "Lecture de l'historique en cours ({count} transactions lues) — la courbe se complète au fur et à mesure. Le nœud Solana public n'accorde qu'environ une transaction par seconde ; les suivantes s'afficheront ensuite presque aussitôt.",
    "charts.approximate":
      "Valeur indicative : certains mouvements n'apparaissent pas dans l'historique lu (transferts internes de contrats, par exemple).",
    "charts.priceSource": "Prix Binance (paires en USDT, ≈ 1 dollar).",
    "charts.priceSourceKraken": "Prix Kraken (en dollars).",
    "charts.delta": "{arrow} {pct} % {period}",
    "charts.deltaUsd": "{arrow} {amount} {period}",
    "charts.period.1d": "sur 24 h",
    "charts.period.7d": "sur 7 jours",
    "charts.period.30d": "sur 30 jours",
    "charts.period.1y": "sur 1 an",
    "charts.periodSince": "depuis le {date}",
    "charts.range.1d": "24 h",
    "charts.range.7d": "7 j",
    "charts.range.30d": "30 j",
    "charts.range.1y": "1 an",
    "charts.range.all": "Tout",
    "charts.openPrice": "Voir la courbe de {name}",
    "charts.tableDate": "Date",
    "charts.tableValue": "Valeur",
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
    "onboarding.haveWallet": "I already have a wallet",
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
      "These 3 shares protect your wallet if you lose this device. <strong>2 out of 3 are enough</strong> to recover everything, but none alone is of any use — that's intentional, nobody (including you) can steal your wallet with a single share. Simplest: save each share on its own USB drive (nothing to write down) and keep the drives in different places. Otherwise, download the files and write down the passwords, separately.",
    "backup.confirmCheckbox": "I have saved my 3 shares (on USB drives, or files and passwords)",
    "backup.saveUsb": "Save to a USB drive",
    "backup.savedUsb": "✓ Saved and verified on drive \"{label}\"",
    "usb.title": "Share {n} on a USB drive",
    "usb.hint": "Plug in a USB drive: it is detected automatically. One drive = one share: two shares together give access to everything, keep each drive in a different place.",
    "usb.waiting": "Waiting for a USB drive…",
    "usb.write": "Write share {n} here",
    "usb.rewrite": "Already holds this share — write it again",
    "usb.otherPart": "Already holds share {part} of this kit: one share per drive",
    "usb.otherKit": "Already holds another backup",
    "usb.writing": "Writing and verifying…",
    "usb.done": "Share {n} saved and verified on \"{label}\". Unplug the drive and store it apart, away from the other shares.",
    "usb.free": "{mb} MB free",
    "backup.disclaimerTitle": "⚠ One share per device, in different places",
    "backup.disclaimerText":
      "Put each share on a different device, kept somewhere else. Two shares together give access to the whole wallet.",
    "backup.statusTodo": "Not saved yet",
    "backup.statusDone": "✓ Saved",
    "backup.shareDownloaded": "✓ Share file downloaded",
    "backup.privkeyDownloaded": "✓ Private key downloaded",
    "backup.progress": "Shares saved: {n}/{total} — save them all to continue.",
    "backup.progressDone": "✓ All {total} shares are saved.",
    "backup.saveAllUsb": "Save everything on a single USB drive",
    "backup.saveAllHint": "Simpler, but that drive alone will be enough to recover everything: keep it somewhere safe.",
    "usb.titleAll": "The 3 shares on a USB drive",
    "usb.hintAll": "Plug in a USB drive: it is detected automatically. The 3 shares will be saved on it: that drive will be enough on its own to recover everything.",
    "usb.writeAll": "Write everything here",
    "usb.rewriteAll": "Already holds shares of this kit — write everything again",
    "usb.doneAll": "The 3 shares saved and verified on \"{label}\". This drive is enough to recover everything: keep it somewhere safe, never with the computer.",
    "restore.usbTitle": "With my backup USB drives",
    "restore.usbHint": "Plug in your backup drives, one after the other if needed: the app reads them on its own. Two different shares are enough.",
    "restore.usbWaiting": "No backup drive detected yet.",
    "restore.usbPart": "✓ Share {n} read (drive \"{label}\")",
    "restore.usbReady": "Two shares read: choose a new password, then restore. You can unplug the drives.",
    "restore.usbSubmit": "Restore from the USB drives",
    "restore.orFiles": "or with the files",
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
      "Plug in 2 of your 3 backup USB drives, or provide 2 share files with their password, then choose a new password for this device.",
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
    "wallet.history": "History",
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
    "nav.walletconnect": "WalletConnect",
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
    "wallet.convert": "Convert",
    "wallet.convertHint": "Swap for another crypto",
    "wallet.pendingBadge": "⏳ Pending transaction detected",
    "wallet.pendingIncoming": "⏳ Incoming, unconfirmed: +{amount} BTC (counted once confirmed)",
    "wallet.marketsTitle": "Live cryptocurrency prices",
    "wallet.showQr": "Show as QR code",
    "wallet.copyAddress": "Copy address",
    "wallet.showAddress": "Show address",
    "wallet.hideAddress": "Hide address",
    "wallet.addressCopied": "Address copied!",
    "wallet.ethereumMainnet": "Ethereum — Real funds",
    "wallet.arbitrum": "Arbitrum — Real funds",
    "wallet.base": "Base — Real funds",
    "net.bsc_mainnet": "BNB Chain — Real funds",
    "net.evm_mainnet": "Ethereum — Real funds",
    "net.arbitrum_mainnet": "Arbitrum — Real funds",
    "net.base_mainnet": "Base — Real funds",
    "net.sol_mainnet": "Solana — Real funds",
    "net.zec_mainnet": "Zcash — Real funds",
    "wallet.historyExplorerOnly": "No history here for this network: no free public service provides it. You can still see it on the network's explorer.",
    "wallet.historyOpenExplorer": "View on the explorer",
    "net.avax_mainnet": "Avalanche — Real funds",
    "net.polygon_mainnet": "Polygon — Real funds",
    "net.hyperevm_mainnet": "HyperEVM — Real funds",
    "wallet.receiveAsset": "Receive {symbol}",
    "assets.manage": "Manage my cryptos",
    "assets.organize": "Organize",
    "organize.sortBy": "Sort:",
    "organize.custom": "My order",
    "organize.value": "Value held",
    "organize.name": "Name",
    "organize.hint": "Drag the cards to reorder them (or use the arrows).",
    "organize.done": "Done",
    "organize.drag": "Drag to move",
    "organize.moveUp": "Move earlier",
    "organize.moveDown": "Move later",
    "assets.title": "My cryptos",
    "assets.hint": "Tick the cryptos to show. A crypto that receives funds shows up by itself.",
    "assets.done": "Done",
    "assets.autoShown": "{symbol} shown: funds detected.",
    "charts.constantBalance": "No history on their network: {list} — current balance counted over the whole period.",
    "settings.currency": "Display currency",
    "settings.usd": "US dollar ($)",
    "settings.eur": "Euro (€)",
    "charts.eurNote": "Amounts in euros at each date's EUR/USD rate (Binance).",
    "charts.eurNoteBefore2020": "Before 3 January 2020 (start of trading): that day's rate.",
    "send.quickUnavailable": "Quick amounts unavailable (price not loaded).",
    "qr.amountLabel": "Amount to request (optional)",
    "qr.amountHint": "The QR code also holds this amount: the payer's app fills it in (if it supports it).",
    "qr.amountInvalid": "Invalid amount: a positive number, at most {decimals} decimals.",
    "wallet.received": "Received: +{amount} {symbol}{fiat}",
    "wallet.receivedPending": "Incoming, unconfirmed: +{amount} BTC (counted once confirmed)",
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
    "collapse.collapse": "Collapse",
    "collapse.expand": "Expand",
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
    "send.mainnetWarning": "⚠ MAINNET network — this spends real funds, irreversible.",
    "send.toAddress": "Recipient address",
    "send.amount": "Amount",
    "send.amountFiat": "Amount in the display currency",
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
      "Goes through an external protocol not audited by this app (see \"How it works\"). Affiliate fee included: 0.80% (THORChain, Maya, Jupiter, LI.FI), 1% (CoW, on a single EVM network), unless the confirmation says otherwise.",
    "swap.fromAsset": "From",
    "swap.toAsset": "To",
    "swap.viaJupiter": "via Jupiter, same wallet",
    "swap.viaCow": "via CoW, same wallet",
    "swap.viaTwoSteps": "in 2 steps, via {via}",
    "swap.provider": "Provider",
    "swap.providerOption": "{name} — {fee} fee",
    "swap.providerRecommended": "{name} — {fee} fee (recommended)",
    "swap.twoStepHint":
      "No direct route: the swap takes 2 steps. 1) {from} → {via} ({first}), received on your own address. 2) As soon as the {via} arrives, the app offers {via} → {to} ({second}), with a second confirmation.",
    "swap.previewRoute": "Step 1 of 2: to {via} ({first}). Then {via} → {to} ({second}) will be offered as soon as the {via} arrives.",
    "swap.routeStep1Sent": "Step 1 sent: step 2 will be offered as soon as the {via} arrives.",
    "swap.routeWaiting": "2-step swap to {to}: waiting for the {via} to arrive (step 1). Across networks this can take up to an hour.",
    "swap.routeReady": "Step 1 done: +{amount} {via} received. Step 2 ready: {via} → {to}.",
    "swap.routeReadyToast": "{via} received: step 2 of your swap is ready.",
    "swap.routeLate": "The {via} has not arrived yet (step 1): check the history. You can stop tracking, the funds remain yours.",
    "swap.routeContinue": "Do step 2",
    "swap.routeAbandon": "Stop tracking",
    "swap.unavailable": "No swap available between these two cryptos.",
    "swap.amount": "Amount",
    "swap.destination": "Destination address",
    "swap.destinationHint": "Pre-filled with your own address on the chosen network — editable if you want to swap to a different address.",
    "swap.jupiterHint": "Same wallet: the crypto you receive lands directly on your address on this network, no separate destination address needed.",
    "swap.getQuote": "Get a quote",
    "swap.previewTitle": "Review before swapping",
    "swap.previewSending": "Sending",
    "swap.previewReceiving": "Estimated receive",
    "swap.previewFees": "Protocol fees (included)",
    "swap.previewFeesOf": "{name} fees (included)",
    "swap.previewMin": "Guaranteed minimum",
    "swap.previewCost": "Estimated cost",
    "swap.previewCostTitle": "Gap between the value sent and the value received at market price, fees included",
    "swap.previewCostHigh": "High cost for this swap: check the amount. On a small amount, fixed network fees weigh heavily.",
    "swap.cowOrderSent": "Order sent to CoW — waiting for execution (at most {minutes} min).",
    "swap.cowOrderFilled": "Order executed: the funds have arrived.",
    "swap.cowOrderExpired": "Order expired without being executed: nothing was swapped.",
    "swap.cowOrderCancelled": "Order cancelled: nothing was swapped.",
    "swap.cowOrderUnknown": "Order tracking unavailable for now — see CoW Explorer.",
    "swap.cowViewOrder": "View order",
    "swap.viaLifi": "via LI.FI",
    "swap.previewLifiRoute": "Bridge (via LI.FI)",
    "swap.lifiDuration": "≈ {minutes} min",
    "swap.lifiSent": "Transaction sent. Transfer in progress (≈ {minutes} min)…",
    "swap.lifiDone": "Swap completed: the funds have arrived.",
    "swap.lifiPartial": "Swap completed, but received in a different crypto than planned — see LI.FI Scan.",
    "swap.lifiRefunded": "The bridge refunded the amount: the swap did not happen.",
    "swap.lifiFailed": "The transfer failed — see LI.FI Scan (the bridge refunds according to its rules).",
    "swap.lifiUnknown": "Tracking unavailable for now — see LI.FI Scan.",
    "swap.lifiView": "View on LI.FI Scan",
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
      "<strong>2 out of 3 are enough</strong> to recover everything. Simplest: each share on its own USB drive (nothing to write down), kept in different places. Otherwise, download the files and write down the passwords, separately.",
    "regenBackup.resultClose": "I have saved my 3 new shares",
    "nav.ledger": "Ledger / Trezor",
    "ledger.title": "Hardware wallet (Ledger, Trezor)",
    "ledger.subtitle":
      "A hardware wallet's keys never leave the device: every transfer is shown on its screen and must be confirmed there. Before each operation, plug it in and unlock it; on a Ledger, also open the network's app (Ethereum, Bitcoin or Solana); on a Trezor, close Trezor Suite.",
    "ledger.add": "+ Add an account",
    "ledger.refresh": "Refresh",
    "ledger.btcNote":
      "Bitcoin: native SegWit account (m/84'), first receive address and first change address. Funds received on other addresses (for example with Ledger Live or Trezor Suite) do not show up here.",
    "ledger.empty": "No hardware wallet account yet — add one with the button above.",
    "ledger.addTitle": "Add a hardware wallet account",
    "ledger.addHint": "Plug in and unlock the device. Ledger: open the chosen network's app on it. Trezor: close Trezor Suite.",
    "ledger.device": "Device",
    "ledger.label": "Name (for your own reference)",
    "ledger.network": "Network",
    "ledger.read": "Read the account from the device",
    "ledger.labelRequired": "The name is required.",
    "ledger.verify": "Verify on the device",
    "ledger.verifyPrompt": "Compare the address shown by the device with this one, then confirm it on the device:\n{address}",
    "ledger.verified": "Address confirmed on the device.",
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
    "ledger.sendHint": "After the Windows confirmation, check the recipient and amount on the device's screen, then confirm there.",
    "ledger.waitDevice": "Confirm on the device…",
    "ledger.sent": "Transaction sent: {txid}",
    "ledger.fieldsRequired": "Recipient and amount are required.",
    "charts.portfolioTitle": "Wallet value over time",
    "charts.portfolioScope": "Displayed profile, real funds (mainnet)",
    "charts.externalTitle": "External wallets over time",
    "charts.externalAll": "All external wallets",
    "charts.expand": "Expand",
    "charts.marketsHint": "Click a crypto to see its chart in full size.",
    "charts.showTable": "Show data",
    "charts.hideTable": "Hide data",
    "charts.loading": "Loading chart…",
    "charts.noData": "No data for this period.",
    "charts.portfolioEmpty": "No real funds on this profile yet.",
    "charts.externalEmpty": "No real funds on these external wallets.",
    "charts.since": "Value rebuilt from each address's latest transactions: known since {date}.",
    "charts.loadingHistoryStart":
      "Reading the history — the public Solana node only allows about one transaction per second; later loads will be almost instant.",
    "charts.loadingHistory":
      "Reading the history ({count} transactions so far) — the chart fills in as it goes. The public Solana node only allows about one transaction per second; later loads will be almost instant.",
    "charts.approximate": "Indicative value: some movements are missing from the history read (internal contract transfers, for example).",
    "charts.priceSource": "Binance prices (USDT pairs, ≈ 1 dollar).",
    "charts.priceSourceKraken": "Kraken prices (in dollars).",
    "charts.delta": "{arrow} {pct}% {period}",
    "charts.deltaUsd": "{arrow} {amount} {period}",
    "charts.period.1d": "over 24h",
    "charts.period.7d": "over 7 days",
    "charts.period.30d": "over 30 days",
    "charts.period.1y": "over 1 year",
    "charts.periodSince": "since {date}",
    "charts.range.1d": "24h",
    "charts.range.7d": "7d",
    "charts.range.30d": "30d",
    "charts.range.1y": "1y",
    "charts.range.all": "All",
    "charts.openPrice": "See the {name} chart",
    "charts.tableDate": "Date",
    "charts.tableValue": "Value",
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
  document.querySelectorAll("[data-i18n-aria-label]").forEach((el) => {
    el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
  });
  document.querySelectorAll(".collapse-toggle").forEach(syncCollapseToggle);
  // Libellés d'une autre longueur : la barre tient-elle encore sur une ligne ?
  fitNavbar();
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
    // Valeur en dollars des cartes (« ≈ 1 234,56 $ » / « ≈ $1,234.56 ») :
    // recalculée sur place, sans appel réseau.
    document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
    renderReceiveMenu();
    try {
      localStorage.setItem(LANG_STORAGE_KEY, currentLang);
    } catch (e) {
      // Best-effort : la langue reste active pour cette session même si la sauvegarde échoue.
    }
  });
});

// --- Panneaux repliables -------------------------------------------------------
// Un clic sur le titre d'un panneau (carte d'une crypto, courbe du portefeuille,
// prix en direct) le replie ou le déplie : une carte repliée garde son nom et
// son solde. Pas de repli des cartes en vue liste (déjà compacte). Préférence
// purement visuelle, par appareil, comme le thème : stockage local.
const COLLAPSED_STORAGE_KEY = "pgp-wallet-collapsed";
// Durée de l'animation de repli (styles.css, `.collapsible-body`).
const COLLAPSE_MS = 220;

const collapsedPanels = (() => {
  try {
    const list = JSON.parse(localStorage.getItem(COLLAPSED_STORAGE_KEY) || "[]");
    return new Set(Array.isArray(list) ? list.filter((key) => typeof key === "string") : []);
  } catch (e) {
    return new Set();
  }
})();

// État lu dans le DOM (pas dans `collapsedPanels`) : aussi appelée par
// `applyLanguage`, qui peut tourner avant l'initialisation ci-dessous.
function syncCollapseToggle(toggle) {
  const collapsed = toggle.closest("[data-collapse-key]").classList.contains("collapsed");
  toggle.setAttribute("aria-expanded", String(!collapsed));
  toggle.title = t(collapsed ? "collapse.expand" : "collapse.collapse");
}

function setPanelCollapsed(panel, collapsed, animate) {
  if (animate) {
    // Contenu rogné pendant l'animation seulement : déplié, rien n'est coupé
    // (anneau de focus, ombres des boutons).
    panel.classList.add("collapse-animating");
    clearTimeout(panel._collapseTimer);
    panel._collapseTimer = setTimeout(() => panel.classList.remove("collapse-animating"), COLLAPSE_MS + 40);
  }
  panel.classList.toggle("collapsed", collapsed);
  syncCollapseToggle(panel.querySelector(".collapse-toggle"));
}

document.querySelectorAll("[data-collapse-key]").forEach((panel) => {
  const key = panel.dataset.collapseKey;
  setPanelCollapsed(panel, collapsedPanels.has(key), false);
  panel.querySelector(".collapse-toggle").addEventListener("click", () => {
    if (panel.classList.contains("wallet-card") && document.documentElement.dataset.walletListView === "true") return;
    const collapsed = !panel.classList.contains("collapsed");
    setPanelCollapsed(panel, collapsed, true);
    if (collapsed) collapsedPanels.add(key);
    else collapsedPanels.delete(key);
    try {
      localStorage.setItem(COLLAPSED_STORAGE_KEY, JSON.stringify([...collapsedPanels]));
    } catch (e) {
      // Best-effort : l'état reste appliqué pour cette session.
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
    // Option d'une crypto (`data-coin`) : son logo devant le nom.
    if (option.dataset.coin) setWithCoinIcon(li, option.dataset.coin, option.textContent);
    else li.textContent = option.textContent;
    li.dataset.value = option.value;
    if (option.selected) {
      li.classList.add("selected");
      if (option.dataset.coin) setWithCoinIcon(label, option.dataset.coin, option.textContent);
      else label.textContent = option.textContent;
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
// remplir un formulaire à chaque fois). `keepLabel` : le libellé reste (le
// bouton grisé suffit), pour les boutons voisins d'autres boutons —
// « Patientez… », plus long, élargissait le bouton et décalait ses voisins.
function withThrottledButton(button, cooldownMs, action, { keepLabel = false } = {}) {
  return async (...args) => {
    if (button.disabled) return;
    const originalText = button.textContent;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    if (!keepLabel) button.textContent = t("common.busy");
    const start = Date.now();
    try {
      await action(...args);
    } finally {
      const remaining = cooldownMs - (Date.now() - start);
      if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
      }
      button.disabled = false;
      button.removeAttribute("aria-busy");
      if (!keepLabel) button.textContent = originalText;
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

// `coin` : logo de la crypto concernée devant le message (réception…).
function showCopyToast(message, durationMs = 1800, coin = null) {
  const toast = document.getElementById("copy-toast");
  const text = document.getElementById("copy-toast-text");
  if (coin) setWithCoinIcon(text, coin, message);
  else text.textContent = message;
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
  }, durationMs);
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
    document.getElementById("backup-confirm").checked = false;
    renderBackupList(result.backups);
    updateBackupContinue();
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
  // Avertissement bien visible AVANT les parts : la sécurité du kit tient à la
  // séparation des parts (deux réunies = accès complet).
  const disclaimer = document.createElement("div");
  disclaimer.className = "backup-disclaimer";
  disclaimer.setAttribute("role", "note");
  const disclaimerTitle = document.createElement("strong");
  disclaimerTitle.textContent = t("backup.disclaimerTitle");
  const disclaimerText = document.createElement("p");
  disclaimerText.textContent = t("backup.disclaimerText");
  disclaimer.append(disclaimerTitle, disclaimerText);
  container.appendChild(disclaimer);
  backups.forEach((backup, i) => {
    const item = document.createElement("div");
    item.className = "backup-item";
    item.innerHTML = `
      <div class="backup-item-header">
        <h3>${t("backup.partTitle", { n: i + 1, label: backup.label })}</h3>
        <span class="backup-status" data-field="status"></span>
      </div>
      <p class="muted">${t("backup.partPassword")}</p>
      <div class="passphrase">${backup.passphrase}</div>
      <div class="row-buttons">
        <button class="primary" data-kind="usb">${t("backup.saveUsb")}</button>
        <button class="secondary" data-kind="share">${t("backup.downloadShare")}</button>
        <button class="secondary" data-kind="privkey">${t("backup.downloadPrivkey")}</button>
      </div>
      <p class="success hidden" data-field="usb-saved"></p>
    `;
    // Part sauvegardée : écrite sur une clé USB, ou ses DEUX fichiers
    // téléchargés (une part ne sert qu'avec sa clé privée). Chaque changement
    // met à jour la coche et prévient l'écran (bouton « Continuer »).
    const saved = { usb: false, share: false, privkey: false };
    const statusEl = item.querySelector('[data-field="status"]');
    const refreshStatus = () => {
      const done = saved.usb || (saved.share && saved.privkey);
      item.dataset.saved = done ? "1" : "";
      statusEl.textContent = done ? t("backup.statusDone") : t("backup.statusTodo");
      statusEl.classList.toggle("done", done);
      container.dispatchEvent(new Event("backup-progress"));
    };
    item._markSaved = (kind) => {
      saved[kind] = true;
      refreshStatus();
    };
    const markDownloaded = (button, kind) => {
      button.textContent = t(kind === "share" ? "backup.shareDownloaded" : "backup.privkeyDownloaded");
      item._markSaved(kind);
    };
    item.querySelector('[data-kind="usb"]').addEventListener("click", () => openUsbModal({ mode: "one", backup, item }));
    // Bouton gardé AVANT l'attente : après un `await`, `e.currentTarget` est vide.
    item.querySelector('[data-kind="share"]').addEventListener("click", async (e) => {
      const button = e.currentTarget;
      try {
        // `false` : boîte « Enregistrer sous » annulée, rien d'enregistré.
        if (await saveBase64ToFile(backup.encrypted_share_b64, `${backup.label}_share.asc`)) markDownloaded(button, "share");
      } catch (err) {
        alert(t("common.saveFailed", { err }));
      }
    });
    item.querySelector('[data-kind="privkey"]').addEventListener("click", async (e) => {
      const button = e.currentTarget;
      try {
        if (await saveBase64ToFile(backup.privkey_armored_b64, `${backup.label}_privkey.asc`)) markDownloaded(button, "privkey");
      } catch (err) {
        alert(t("common.saveFailed", { err }));
      }
    });
    container.appendChild(item);
    refreshStatus();
  });
  // Tout le kit sur une seule clé : plus simple, mais cette clé suffit alors à
  // tout récupérer (confirmé par une boîte native côté Rust).
  const all = document.createElement("div");
  all.className = "backup-all";
  const allButton = document.createElement("button");
  allButton.className = "primary";
  allButton.textContent = t("backup.saveAllUsb");
  const allHint = document.createElement("p");
  allHint.className = "backup-all-warning";
  allHint.textContent = t("backup.saveAllHint");
  const allSaved = document.createElement("p");
  allSaved.className = "success hidden";
  allButton.addEventListener("click", () => openUsbModal({ mode: "all", backups, container, saved: allSaved }));
  all.append(allButton, allHint, allSaved);
  container.appendChild(all);
}

// « Continuer » : seulement une fois les 3 parts sauvegardées (coches) ET la
// confirmation cochée — elle-même activable seulement à ce moment-là.
function updateBackupContinue() {
  const items = [...document.querySelectorAll("#backup-list .backup-item")];
  const saved = items.filter((item) => item.dataset.saved === "1").length;
  const all = items.length > 0 && saved === items.length;
  const progress = document.getElementById("backup-progress");
  progress.textContent = all ? t("backup.progressDone", { total: items.length }) : t("backup.progress", { n: saved, total: items.length });
  progress.classList.toggle("done", all);
  const confirm = document.getElementById("backup-confirm");
  confirm.disabled = !all;
  if (!all) confirm.checked = false;
  document.getElementById("backup-continue").disabled = !(all && confirm.checked);
}

document.getElementById("backup-list").addEventListener("backup-progress", updateBackupContinue);
document.getElementById("backup-confirm").addEventListener("change", updateBackupContinue);

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

// Restauration ouverte depuis le déverrouillage ou depuis le premier lancement
// (« J'ai déjà un portefeuille ») : Annuler ramène à l'écran d'origine.
let restoreOrigin = "unlock";

function openRestore(origin) {
  restoreOrigin = origin;
  showView("restore");
  startUsbRestore();
}

document.getElementById("goto-restore").addEventListener("click", () => openRestore("unlock"));
document.getElementById("onboarding-goto-restore").addEventListener("click", () => openRestore("onboarding"));
document.getElementById("goto-unlock").addEventListener("click", () => {
  stopUsbRestore(true);
  if (restoreOrigin === "onboarding") showView("onboarding");
  else showUnlockView();
});

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
    stopBalanceWatch();
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
  stopBalanceWatch();
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

// Barre sur une ligne (onglets centrés) quand tout y tient ; sinon, logo et
// boutons sur une rangée, onglets en dessous (renvoyés à la ligne au besoin) :
// la page ne défile jamais horizontalement. Mesuré, pas deviné par une largeur
// fixe : la place prise dépend de la langue et de la police. Élément relu à
// chaque appel : aussi appelée par `applyLanguage`, qui tourne plus haut.
function fitNavbar() {
  const navbar = document.querySelector(".navbar");
  if (!navbar || navbar.clientWidth === 0) return; // tableau de bord caché
  navbar.classList.remove("stacked");
  const tabs = navbar.querySelector(".nav-tabs");
  const overflows = navbar.scrollWidth > navbar.clientWidth + 1 || tabs.scrollWidth > tabs.clientWidth + 1;
  navbar.classList.toggle("stacked", overflows);
  // Messages (« Adresse copiée ! », fonds reçus) placés juste sous la barre,
  // plus haute sur deux rangées.
  document.documentElement.style.setProperty("--navbar-height", `${navbar.offsetHeight}px`);
}

{
  // Largeur seulement : le passage sur deux rangées change la hauteur de la
  // barre, qui ne doit pas relancer la mesure.
  let lastWidth = 0;
  new ResizeObserver(([entry]) => {
    const width = Math.round(entry.contentRect.width);
    if (width === lastWidth) return;
    lastWidth = width;
    fitNavbar();
  }).observe(document.querySelector(".navbar"));
  if (document.fonts) document.fonts.ready.then(fitNavbar);
}

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

    stopUsbRestore(true);
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

// --- Sauvegarde et restauration par clé USB (core/src/usb_backup.rs) -------
// Les clés sont détectées en interrogeant la liste des lecteurs amovibles à
// intervalle court tant que la fenêtre concernée est ouverte : brancher la clé
// suffit. Les secrets ne font que transiter vers Rust (écriture) ; à la
// restauration, les parts lues restent côté Rust, l'interface ne voit que le
// numéro de part et le kit.
const USB_POLL_MS = 1500;

function usbDriveName(drive) {
  const letter = drive.root.replace(/\\$/, "");
  return drive.label ? `${drive.label} (${letter})` : letter;
}

let usbModalTimer = null;
const usbModal = document.getElementById("usb-modal");

// `target` : { mode: "one", backup, item } (une part, sur sa propre clé) ou
// { mode: "all", backups, container, saved } (tout le kit sur une clé).
function openUsbModal(target) {
  const all = target.mode === "all";
  document.getElementById("usb-modal-title").textContent = all ? t("usb.titleAll") : t("usb.title", { n: target.backup.part });
  document.getElementById("usb-modal-hint").textContent = all ? t("usb.hintAll") : t("usb.hint");
  hideError(document.getElementById("usb-error"));
  document.getElementById("usb-success").classList.add("hidden");
  document.getElementById("usb-drive-list").replaceChildren();
  usbModal.classList.remove("hidden");
  const refresh = () => refreshUsbDrives(target);
  refresh();
  clearInterval(usbModalTimer);
  usbModalTimer = setInterval(refresh, USB_POLL_MS);
}

function closeUsbModal() {
  clearInterval(usbModalTimer);
  usbModalTimer = null;
  usbModal.classList.add("hidden");
}

document.getElementById("usb-close").addEventListener("click", closeUsbModal);

let usbWriting = false;

async function refreshUsbDrives(target) {
  if (usbWriting) return;
  const all = target.mode === "all";
  const kit = all ? target.backups[0].kit_id : target.backup.kit_id;
  let drives;
  try {
    drives = await invoke("list_backup_drives");
  } catch (e) {
    console.error(e);
    return;
  }
  const list = document.getElementById("usb-drive-list");
  if (drives.length === 0) {
    list.replaceChildren(Object.assign(document.createElement("li"), { className: "muted", textContent: t("usb.waiting") }));
    return;
  }
  list.replaceChildren(
    ...drives.map((drive) => {
      const li = document.createElement("li");
      li.className = "usb-drive";
      const name = document.createElement("span");
      name.textContent = `${usbDriveName(drive)} — ${t("usb.free", { mb: Math.floor(drive.free_bytes / 1048576).toLocaleString(chartLocale()) })}`;
      const button = document.createElement("button");
      button.className = "secondary";
      const shares = drive.shares || [];
      const otherKit = shares.some((s) => s.kit !== kit);
      const otherPart = all ? null : shares.find((s) => s.kit === kit && s.part !== target.backup.part);
      if (otherKit) {
        button.disabled = true;
        button.textContent = t("usb.otherKit");
      } else if (otherPart) {
        button.disabled = true;
        button.textContent = t("usb.otherPart", { part: otherPart.part });
      } else {
        if (all) button.textContent = shares.length ? t("usb.rewriteAll") : t("usb.writeAll");
        else button.textContent = shares.length ? t("usb.rewrite") : t("usb.write", { n: target.backup.part });
        button.addEventListener("click", () => writeToUsb(target, drive, button));
      }
      li.append(name, button);
      return li;
    })
  );
}

async function writeToUsb(target, drive, button) {
  const errorEl = document.getElementById("usb-error");
  const successEl = document.getElementById("usb-success");
  hideError(errorEl);
  successEl.classList.add("hidden");
  usbWriting = true;
  button.disabled = true;
  button.textContent = t("usb.writing");
  try {
    if (target.mode === "all") {
      // Champs en snake_case : structure imbriquée, désérialisée telle quelle.
      const shares = target.backups.map((b) => ({
        part: b.part,
        encrypted_share_b64: b.encrypted_share_b64,
        privkey_armored_b64: b.privkey_armored_b64,
        passphrase: b.passphrase,
      }));
      const label = await invoke("save_kit_to_usb", { root: drive.root, kitId: target.backups[0].kit_id, shares });
      if (label === null) return; // refusé dans la boîte de confirmation
      const name = label || drive.root;
      successEl.textContent = t("usb.doneAll", { label: name });
      successEl.classList.remove("hidden");
      target.saved.textContent = t("backup.savedUsb", { label: name });
      target.saved.classList.remove("hidden");
      target.container.querySelectorAll('[data-field="usb-saved"]').forEach((el) => {
        el.textContent = t("backup.savedUsb", { label: name });
        el.classList.remove("hidden");
      });
      target.container.querySelectorAll(".backup-item").forEach((el) => el._markSaved("usb"));
    } else {
      const backup = target.backup;
      const label = await invoke("save_backup_to_usb", {
        root: drive.root,
        kitId: backup.kit_id,
        part: backup.part,
        encryptedShareB64: backup.encrypted_share_b64,
        privkeyArmoredB64: backup.privkey_armored_b64,
        passphrase: backup.passphrase,
      });
      const name = label || drive.root;
      successEl.textContent = t("usb.done", { n: backup.part, label: name });
      successEl.classList.remove("hidden");
      const saved = target.item.querySelector('[data-field="usb-saved"]');
      saved.textContent = t("backup.savedUsb", { label: name });
      saved.classList.remove("hidden");
      target.item._markSaved("usb");
    }
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    usbWriting = false;
    refreshUsbDrives(target);
  }
}

let usbRestoreTimer = null;
// Parts déjà lues : "kit:part" -> nom de la clé.
const usbRestoreLoaded = new Map();

function startUsbRestore() {
  usbRestoreLoaded.clear();
  invoke("usb_restore_clear").catch((e) => console.error(e));
  renderUsbRestore();
  pollUsbRestore();
  clearInterval(usbRestoreTimer);
  usbRestoreTimer = setInterval(pollUsbRestore, USB_POLL_MS);
}

function stopUsbRestore(forget) {
  clearInterval(usbRestoreTimer);
  usbRestoreTimer = null;
  if (forget) {
    usbRestoreLoaded.clear();
    invoke("usb_restore_clear").catch((e) => console.error(e));
  }
}

async function pollUsbRestore() {
  let drives;
  try {
    drives = await invoke("list_backup_drives");
  } catch (e) {
    console.error(e);
    return;
  }
  for (const drive of drives) {
    const shares = drive.shares || [];
    if (shares.every((s) => usbRestoreLoaded.has(`${s.kit}:${s.part}`))) continue;
    try {
      const read = await invoke("usb_restore_load", { root: drive.root });
      read.forEach((s) => usbRestoreLoaded.set(`${s.kit}:${s.part}`, usbDriveName(drive)));
    } catch (e) {
      showError(document.getElementById("restore-error"), String(e));
    }
  }
  renderUsbRestore();
}

// Deux parts différentes d'un même kit lues : restauration possible.
function usbRestoreReady() {
  const byKit = new Map();
  for (const key of usbRestoreLoaded.keys()) {
    const kit = key.split(":")[0];
    byKit.set(kit, (byKit.get(kit) || 0) + 1);
  }
  return [...byKit.values()].some((count) => count >= 2);
}

function renderUsbRestore() {
  const list = document.getElementById("restore-usb-status");
  const items = [...usbRestoreLoaded.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, name]) => Object.assign(document.createElement("li"), { textContent: t("restore.usbPart", { n: key.split(":")[1], label: name }) }));
  if (items.length === 0) items.push(Object.assign(document.createElement("li"), { className: "muted", textContent: t("restore.usbWaiting") }));
  const ready = usbRestoreReady();
  if (ready) items.push(Object.assign(document.createElement("li"), { className: "success", textContent: t("restore.usbReady") }));
  list.replaceChildren(...items);
  document.getElementById("restore-usb-submit").classList.toggle("hidden", !ready);
}

const restoreUsbSubmitBtn = document.getElementById("restore-usb-submit");
restoreUsbSubmitBtn.addEventListener("click", withBusyButton(restoreUsbSubmitBtn, async () => {
  const errorEl = document.getElementById("restore-error");
  hideError(errorEl);
  const newPassword = document.getElementById("restore-new-password").value;
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    showError(errorEl, t("common.passwordMinLength", { min: MIN_PASSWORD_LENGTH }));
    return;
  }
  if (estimatePasswordStrength(newPassword) === "faible") {
    showError(errorEl, t("common.passwordTooWeak"));
    return;
  }
  try {
    const addresses = await invoke("restore_wallet_from_usb", { newPassword });
    stopUsbRestore(true);
    renderDashboardAddresses(singleProfileList(addresses));
    showView("dashboard");
    refreshAllBalances();
    startBalanceAutoRefresh();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("restore-new-password").value = "";
  }
}));

// --- Dashboard ---------------------------------------------------------

let balanceRefreshTimer = null;

// Rafraîchit les soldes toutes les 60 s tant que le tableau de bord est ouvert :
// filet de sécurité, les changements étant signalés en direct (voir
// updateBalanceWatch) — 15 s auparavant, avant la surveillance en direct, soit
// quatre fois plus d'appels aux nœuds publics pour rien. Arrêté au verrouillage/réinitialisation pour ne pas laisser
// tourner des appels réseau en arrière-plan une fois le wallet quitté. Les prix
// (voir plus bas) suivent le même cycle de vie, avec un intervalle plus long : ce
// sont des cours de marché, pas des montants qui bougent à chaque bloc, et l'API
// publique utilisée (CoinGecko, gratuite) a une limite de requêtes par minute.
function startBalanceAutoRefresh() {
  stopBalanceAutoRefresh();
  balanceRefreshTimer = setInterval(refreshAllBalances, 60000);
  startPriceAutoRefresh();
}

function stopBalanceAutoRefresh() {
  stopPriceAutoRefresh();
  if (balanceRefreshTimer) {
    clearInterval(balanceRefreshTimer);
    balanceRefreshTimer = null;
  }
}

// Portefeuille quitté (verrouillage, réinitialisation) : plus aucune adresse
// surveillée. Pas dans stopBalanceAutoRefresh, que startBalanceAutoRefresh
// appelle juste après que les adresses affichées ont lancé la surveillance.
function stopBalanceWatch() {
  invoke("watch_balances", { targets: [] }).catch((e) => console.error(e));
}

// --- Prix indicatifs (USD) --------------------------------------------------
// Purement informatif (voir core/src/price_rpc.rs) : aucune donnée sur l'adresse
// ou le solde de l'utilisateur n'est envoyée à ce service, juste "quel est le prix
// actuel de l'ETH/BTC/SOL" — identique pour tout le monde.

let latestPrices = null;

// --- Devise d'affichage -----------------------------------------------------
// Tout est calculé en dollars (prix, historiques, portefeuilles) ; en euros,
// chaque montant est converti à l'affichage : taux du moment pour les valeurs
// actuelles, taux de CHAQUE DATE pour les courbes et les transactions passées
// (paire EUR/USDT de Binance, cotée depuis le 03/01/2020 ; avant, le premier
// taux connu). Préférence d'affichage, par appareil : stockage local.
const CURRENCY_STORAGE_KEY = "pgp-wallet-currency";
let displayCurrency = "usd";
try {
  if (localStorage.getItem(CURRENCY_STORAGE_KEY) === "eur") displayCurrency = "eur";
} catch (e) {
  // localStorage indisponible : dollars.
}
// Dollars pour 1 euro, au moment présent (`null` tant qu'il n'est pas lu).
let usdPerEur = null;
// Séries du taux par période de courbe : { points, loadedAt }.
const eurSeriesCache = new Map();
const EUR_SERIES_TTL_MS = 10 * 60 * 1000;

async function eurSeries(range) {
  const cached = eurSeriesCache.get(range);
  if (cached && Date.now() - cached.loadedAt < EUR_SERIES_TTL_MS) return cached.points;
  const points = await invoke("get_price_chart", { symbol: "EUR", range });
  if (points.length === 0) throw new Error("taux EUR/USD indisponible");
  eurSeriesCache.set(range, { points, loadedAt: Date.now() });
  return points;
}

// Taux à l'instant `t` (secondes) : dernier point connu à cette date ; avant
// le premier point, le premier (voir plus haut).
function rateAt(points, t) {
  let lo = 0;
  let hi = points.length - 1;
  if (t <= points[0][0]) return points[0][1];
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (points[mid][0] <= t) lo = mid;
    else hi = mid - 1;
  }
  return points[lo][1];
}

async function refreshEurRate() {
  try {
    const points = await eurSeries("1d");
    usdPerEur = points[points.length - 1][1];
  } catch (e) {
    console.error(e);
  }
}

// Montant en dollars → devise affichée, au taux actuel ; `null` si le taux
// n'est pas encore connu (affiché « — »).
function usdToFiat(usd) {
  if (displayCurrency !== "eur") return usd;
  return usdPerEur ? usd / usdPerEur : null;
}

// Même chose au taux d'une date passée (transactions) : série journalière
// complète si elle est déjà chargée, sinon taux actuel.
function usdToFiatAt(usd, timestamp) {
  if (displayCurrency !== "eur") return usd;
  const all = eurSeriesCache.get("all");
  if (all && timestamp) return usd / rateAt(all.points, timestamp);
  return usdToFiat(usd);
}

// Premier taux EUR/USD connu (03/01/2020) : avant, celui-ci est utilisé.
const EUR_SERIES_START = 1578009600;

// Note sous une courbe en euros ; la précision « avant 2020 » seulement si la
// courbe commence avant.
function eurChartNote(points) {
  if (displayCurrency !== "eur" || points.length === 0) return "";
  return points[0][0] < EUR_SERIES_START ? `${t("charts.eurNote")} ${t("charts.eurNoteBefore2020")}` : t("charts.eurNote");
}

// Points [instant, dollars] d'une courbe → devise affichée, au taux de chaque
// instant.
async function toDisplayCurrency(points, range) {
  if (displayCurrency !== "eur" || points.length === 0) return points;
  const rates = await eurSeries(range);
  return points.map(([time, usd]) => [time, usd / rateAt(rates, time)]);
}

// Réglage « Devise d'affichage » : tout ce qui est déjà affiché est converti
// tout de suite (taux et séries chargés au besoin).
const currencySelect = document.getElementById("currency-select");
currencySelect.value = displayCurrency;
// Menu déjà construit plus haut (initCustomSelect) : étiquette resynchronisée.
syncCustomSelect(currencySelect);
currencySelect.addEventListener("change", async () => {
  displayCurrency = currencySelect.value === "eur" ? "eur" : "usd";
  try {
    localStorage.setItem(CURRENCY_STORAGE_KEY, displayCurrency);
  } catch (e) {
    // Best-effort : la devise reste active pour cette session.
  }
  if (displayCurrency === "eur") {
    await refreshEurRate();
    eurSeries("all").catch((e) => console.error(e)); // valeur des transactions passées
  }
  refreshCurrencyDisplays();
});

function refreshCurrencyDisplays() {
  document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
  if (lastMarketCoins) renderMarkets(lastMarketCoins);
  updateAllExternalGroupTotals();
  if (portfolioView.rangesEl.childElementCount) refreshChart(portfolioView);
  if (externalChartView.rangesEl.childElementCount) refreshChart(externalChartView);
  if (!document.querySelector('.tab-panel[data-panel="history"]').classList.contains("hidden")) loadAllHistory();
  if (!sendModal.classList.contains("hidden")) {
    renderQuickAmounts();
    renderSendAmountUnits();
  }
}
let priceRefreshTimer = null;
let pricesRefreshing = false;

function priceForCoin(coin) {
  // USDC est un stablecoin indexé sur le dollar : pas d'appel de prix
  // nécessaire, toujours ~1 $ — évite un cas particulier dans
  // updateFiatValue/renderQuickAmounts pour ce seul actif.
  if (coin === "usdc") return 1;
  const asset = ASSET_BY_COIN[coin];
  if (!latestPrices || !asset) return null;
  return latestPrices[asset.gecko] ?? null;
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
  // Dans la langue choisie (« ≈ 1 234,56 $ » / « ≈ $1,234.56 ») ; restait au
  // format français en anglais.
  const text = formatUsdApprox(balance * price);
  if (fiatEl.textContent !== text) fiatEl.textContent = text;
}

// Dernière liste des marchés reçue : réaffichée telle quelle au changement de
// devise, sans nouvel appel.
let lastMarketCoins = null;

async function refreshPrices() {
  // Même logique de verrou que refreshBalance : évite qu'un cycle lent (CoinGecko
  // limite le débit gratuit) ne se fasse recouvrir par le tick suivant du minuteur.
  if (pricesRefreshing) return;
  pricesRefreshing = true;
  try {
    // Un seul appel CoinGecko par cycle : la liste des marchés donne déjà le
    // cours de BTC/ETH/SOL (un appel `simple/price` séparé doublait la
    // consommation de la limite gratuite). Échec passager : les derniers prix
    // restent, au lieu de faire passer toutes les valeurs en dollars à « — ».
    let coins = null;
    if (displayCurrency === "eur") {
      await refreshEurRate();
      // Taux de chaque jour, pour la valeur des transactions passées.
      if (!eurSeriesCache.has("all")) eurSeries("all").catch((e) => console.error(e));
    }
    try {
      coins = await invoke("get_market_prices");
      lastMarketCoins = coins;
      // Cours par identifiant CoinGecko (voir ASSETS[].gecko).
      const next = Object.fromEntries(coins.filter((c) => Number.isFinite(c.price_usd) && c.price_usd > 0).map((c) => [c.id, c.price_usd]));
      if (Object.keys(next).length > 0) latestPrices = next;
    } catch (e) {
      console.error(e);
    }
    document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
    scheduleCardResort();
    renderMarkets(coins);
    // Garde les montants rapides de la modale d'envoi synchronisés avec le cours si
    // elle reste ouverte pendant un cycle de rafraîchissement (toutes les 60s, voir
    // startPriceAutoRefresh) — sans ça, un montant rapide cliqué plus tard dans une
    // session longue refléterait un prix périmé.
    if (!sendModal.classList.contains("hidden")) {
      renderQuickAmounts();
      renderSendAmountUnits();
    }
  } finally {
    pricesRefreshing = false;
  }
}

// Capitalisation abrégée, dans la langue et la devise choisies : « 1,67 T$ »,
// « 325,43 Md€ » / « $1.67T », « €325.43B ».
function formatMarketCap(usd) {
  const value = usdToFiat(usd);
  if (value == null) return "—";
  const en = currentLang === "en";
  const symbol = displayCurrency === "eur" ? "€" : "$";
  const scaled = (n, frUnit, enUnit) => {
    const shown = n.toLocaleString(chartLocale(), { maximumFractionDigits: 2 });
    return en ? `${symbol}${shown}${enUnit}` : `${shown} ${frUnit}${symbol}`;
  };
  if (value >= 1e12) return scaled(value / 1e12, "T", "T");
  if (value >= 1e9) return scaled(value / 1e9, "Md", "B");
  if (value >= 1e6) return scaled(value / 1e6, "M", "M");
  return withCurrency(value.toLocaleString(chartLocale()));
}

// Déjà triée par capitalisation décroissante côté Rust (voir
// core/src/price_rpc.rs::get_market_data) : le frontend affiche l'ordre reçu tel
// quel, sans re-trier. Mise à jour SUR PLACE toutes les 30 s (lignes gardées,
// textes changés seulement s'ils diffèrent, mini-courbe remplacée quand la
// nouvelle arrive) : reconstruire la liste faisait disparaître puis réapparaître
// toutes les mini-courbes et perdre le focus clavier d'une ligne.
// Logo des cryptos suivies : mêmes fichiers que les cartes du portefeuille.
// Logos : ceux des cartes (ASSETS), retrouvés par identifiant CoinGecko.

function createMarketRow(coin) {
  const row = document.createElement("div");
  row.className = "market-row";
  row.dataset.symbol = coin.symbol;
  const chartSymbol = ASSET_BY_GECKO[coin.id]?.chart ?? null;
  row.dataset.chart = chartSymbol ?? "";
  row.innerHTML = `<div class="market-name"><span class="market-label"><span class="market-symbol"></span></span></div><div class="market-spark"></div>
    <div class="market-figures"><div class="market-change"></div><div class="market-price"></div><div class="market-cap"></div></div>`;
  row.querySelector(".market-label").prepend(document.createTextNode(coin.name));
  row.querySelector(".market-symbol").textContent = coin.symbol;
  const asset = ASSET_BY_GECKO[coin.id];
  if (asset) {
    const icon = document.createElement("img");
    icon.className = asset.coin === "sol" ? "coin-icon coin-icon-sol" : asset.iconRound ? "coin-icon coin-icon-round" : "coin-icon";
    icon.src = asset.icon;
    icon.alt = "";
    row.querySelector(".market-name").prepend(icon);
  }
  // Un clic (ou Entrée) ouvre la courbe en grand, période au choix.
  const openChart = () =>
    openChartModal({
      title: `${coin.name} (${coin.symbol})`,
      coin: asset?.coin,
      ranges: CHART_RANGES,
      range: "7d",
      load: (range) => loadPriceChart(chartSymbol, range),
      emptyKey: "charts.noData",
    });
  // Pas de courbe (stablecoin sans cotation, jeton non coté sur Binance) :
  // ligne non cliquable.
  if (!chartSymbol) return row;
  row.classList.add("clickable");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-label", t("charts.openPrice", { name: coin.name }));
  row.addEventListener("click", openChart);
  row.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openChart();
    }
  });
  return row;
}

function setText(el, text) {
  if (el.textContent !== text) el.textContent = text;
}

function fillMarketRow(row, coin) {
  const decimals = { minimumFractionDigits: 2, maximumFractionDigits: 2 };
  const price = usdToFiat(coin.price_usd);
  setText(row.querySelector(".market-price"), price == null ? "—" : withCurrency(price.toLocaleString(chartLocale(), decimals)));
  setText(row.querySelector(".market-cap"), formatMarketCap(coin.market_cap_usd));
  const changeDiv = row.querySelector(".market-change");
  changeDiv.classList.remove("up", "down");
  // Variation arrondie à 0,00 % : ni hausse ni baisse (USDC, typiquement).
  const trend = trendOf(coin.change_24h_percent);
  if (coin.change_24h_percent == null) {
    setText(changeDiv, "—");
  } else {
    const shown = Math.abs(coin.change_24h_percent).toLocaleString(chartLocale(), decimals) + (currentLang === "en" ? "%" : "\u00a0%");
    if (trend) changeDiv.classList.add(trend);
    setText(changeDiv, trend ? `${trend === "up" ? "▲" : "▼"} ${shown}` : shown);
  }
  // Courbe des dernières 24 h (comme la variation affichée), de la même couleur
  // que cette variation ; l'ancienne reste affichée jusqu'à l'arrivée de la
  // nouvelle.
  const spark = row.querySelector(".market-spark");
  if (!row.dataset.chart) return;
  invoke("get_price_chart", { symbol: row.dataset.chart, range: "1d" })
    .then((points) => renderSparkline(spark, points, trend))
    .catch((e) => console.error(e));
}

// `coins` : liste reçue par refreshPrices, `null` si l'appel a échoué.
function renderMarkets(coins) {
  const container = document.getElementById("markets-list");
  try {
    if (!coins) throw new Error("marchés indisponibles");
    const existing = new Map([...container.querySelectorAll(".market-row")].map((row) => [row.dataset.symbol, row]));
    // Seulement les cryptos affichées sur le tableau de bord.
    const rows = coins.filter((coin) => ASSET_BY_GECKO[coin.id] && isAssetVisible(ASSET_BY_GECKO[coin.id].coin)).map((coin) => {
      const row = existing.get(coin.symbol) || createMarketRow(coin);
      fillMarketRow(row, coin);
      return row;
    });
    const sameOrder = rows.length === container.children.length && rows.every((row, i) => container.children[i] === row);
    if (!sameOrder) container.replaceChildren(...rows);
  } catch (e) {
    // Échec passager : les derniers prix affichés restent plutôt qu'un message
    // à la place de toute la liste.
    if (!container.querySelector(".market-row")) container.innerHTML = `<p class="muted">${t("wallet.marketsLoadError")}</p>`;
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

// Réseau d'une carte sans menu réseau : le premier de sa crypto (ASSETS).
const coinConfig = Object.fromEntries(ASSETS.map((asset) => [asset.coin, { defaultNetwork: asset.networks[0] }]));

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
  // Même adresse sur tous les réseaux EVM (Ethereum, L2, BNB Chain…), jetons
  // compris.
  if (isEvmNetwork(network)) return profile.addresses.evm;
  if (coin === "btc") return network === "btc_mainnet" ? profile.addresses.btc_mainnet : profile.addresses.btc_testnet;
  // Zcash transparent (t1…) ; absente d'un profil dérivé avant son ajout,
  // jusqu'au prochain déverrouillage.
  if (coin === "zec") return profile.addresses.zcash ?? "";
  // Jetons Solana (USDC, USDT…) : même adresse propriétaire que SOL (le compte
  // de jetons associé qui les détient réellement est un détail invisible pour
  // l'utilisateur, dérivé côté Rust — voir core/src/sol_spl.rs).
  if (coin === "sol" || network === "sol_mainnet" || network === "sol_devnet") return profile.addresses.solana;
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
  const address = addressForCoin(coin, networkForCard(card));
  card.querySelector('[data-field="address"]').textContent = address;
  // Copie affichée par le bouton « adresse » d'une carte repliée.
  card.querySelector('[data-field="collapsed-address"]').textContent = address;
  updateConvertButton(card);
}

// « Convertir » seulement là où un échange existe pour la crypto ET le réseau
// affichés (voir `swapPairs`) : pas sur un réseau de test, ni là où il
// échangerait les fonds d'un autre réseau que celui affiché.
function updateConvertButton(card) {
  const convert = card.querySelector('[data-action="swap"]');
  if (!convert) return;
  const coin = card.dataset.coin;
  const network = networkForCard(card);
  const available = swapPairs.some((p) => p.from_coin === coin && p.from_network === network);
  convert.classList.toggle("hidden", !addressForCoin(coin, network) || !available);
}

function renderCardAddresses() {
  document.querySelectorAll(".wallet-card").forEach(renderCardAddress);
  hiddenBalancesChecked = false; // nouvelles adresses : cartes masquées relues
  updateBalanceWatch();
  // Adresses du profil changées (déverrouillage, changement de profil) : la
  // courbe d'évolution suit.
  loadPortfolioChart();
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

// Réseau et adresse d'une carte : ce à quoi correspond le solde affiché.
function balanceKey(card) {
  const network = networkForCard(card);
  return `${network}|${addressForCoin(card.dataset.coin, network)}`;
}

async function refreshBalance(card) {
  // Verrou par carte, partagé entre le clic manuel (bouton "Actualiser") et le
  // rafraîchissement automatique (setInterval, toutes les 60 s) : sans lui, un appel
  // réseau qui dépasse 15s (fréquent sur des endpoints publics gratuits) se ferait
  // recouvrir par le tick suivant, empilant des requêtes concurrentes pour la même
  // carte — même symptôme de lag qu'un double-clic, mais déclenché par le minuteur.
  // Demande arrivée pendant une lecture (changement signalé en direct juste
  // après l'envoi de la requête) : relue à la fin, pas perdue.
  if (card.dataset.refreshing === "1") {
    card.dataset.refreshAgain = "1";
    return;
  }
  card.dataset.refreshing = "1";
  card.dataset.refreshAgain = "";
  const key = balanceKey(card);
  try {
    const coin = card.dataset.coin;
    const network = networkForCard(card);
    const address = addressForCoin(coin, network);
    const balanceEl = card.querySelector('[data-field="balance"]');
    // Solde déjà affiché pour ce réseau et cette adresse : il reste pendant la
    // lecture, et après un échec passager. Le remplacer par « … » à chaque
    // actualisation (toutes les 15 s) faisait clignoter tous les soldes et, en
    // vue liste, bouger toutes les lignes (colonne ajustée à « … »). Autre
    // réseau ou autre profil : l'ancien solde ne vaut plus rien.
    const shown = card.dataset.balanceKey === key;
    if (!shown) balanceEl.textContent = "…";
    // Le solde et l'indicateur "transaction en attente" sont deux appels
    // indépendants (l'un ne dépend pas du résultat de l'autre) : les lancer en
    // parallèle plutôt que l'un après l'autre coupe la latence perçue du
    // rafraîchissement en deux.
    // USDC est un jeton SPL, pas un "réseau" au sens où get_balance l'entend
    // (pas de notion de décimales/mint par actif dans cette commande) : une
    // commande dédiée, voir core/src/api.rs::get_usdc_balance.
    const balancePromise = (
      usesTokenRegistry(coin, network)
        ? invoke("get_token_balance", { token: coin, network, address })
        : invoke(coin === "usdc" ? "get_usdc_balance" : "get_balance", { network, address })
    )
      .then((balance) => {
        if (balanceKey(card) !== key) return; // réseau ou profil changé entre-temps
        // Solde précédent de CETTE adresse sur CE réseau (pas au premier
        // affichage, ni après un changement de profil ou de réseau).
        const previous = card.dataset.balanceKey === key ? balanceEl.textContent : null;
        if (balanceEl.textContent !== balance) balanceEl.textContent = balance;
        card.dataset.balanceKey = key;
        const received = previous == null ? null : balanceIncrease(previous, balance);
        if (received) announceReceived(card, network, received);
        revealIfFunded(card, balance);
        scheduleCardResort();
      })
      .catch((e) => {
        console.error(e);
        if (balanceKey(card) !== key || shown) return;
        balanceEl.textContent = t("wallet.balanceError");
      });
    const pendingPromise = checkPendingTx(card, address, network);
    await Promise.all([balancePromise, pendingPromise]);
    updateFiatValue(card);
  } finally {
    card.dataset.refreshing = "";
  }
  // Réseau ou profil changé pendant la lecture (ignorée), ou changement
  // signalé entre-temps : relire.
  if (balanceKey(card) !== key || card.dataset.refreshAgain === "1") refreshBalance(card);
}

// Crypto masquée SANS choix explicite de l'utilisateur, avec des fonds :
// affichée (et retenue comme telle). Une crypto masquée volontairement le reste.
function revealIfFunded(card, balance) {
  const coin = card.dataset.coin;
  if (isAssetVisible(coin) || coin in assetChoices || !(Number.parseFloat(balance) > 0)) return;
  assetChoices[coin] = true;
  saveAssetChoices();
  refreshAssetDisplays();
  showCopyToast(t("assets.autoShown", { symbol: ASSET_BY_COIN[coin].symbol }), 5000);
}

// Hausse exacte entre deux soldes affichés (« 0.12345678 ») — calcul sur des
// entiers à l'échelle des décimales, jamais en flottants —, sans zéros
// inutiles (« 0.01 ») ; `null` si le solde n'a pas monté ou n'est pas un nombre.
function balanceIncrease(before, after) {
  const number = /^\d+(\.\d+)?$/;
  if (!number.test(before) || !number.test(after)) return null;
  const decimals = Math.max((before.split(".")[1] || "").length, (after.split(".")[1] || "").length);
  const scaled = (s) => {
    const [whole, fraction = ""] = s.split(".");
    return BigInt(whole + fraction.padEnd(decimals, "0"));
  };
  const diff = scaled(after) - scaled(before);
  if (diff <= 0n) return null;
  const digits = diff.toString().padStart(decimals + 1, "0");
  const whole = digits.slice(0, digits.length - decimals);
  const fraction = digits.slice(digits.length - decimals).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

// Fonds arrivés sur une carte affichée : message (5 s) et solde brièvement
// éclairé. Valeur en dollars seulement sur le réseau principal (des jetons de
// test ne valent rien).
function announceReceived(card, network, amount) {
  const coin = card.dataset.coin;
  const symbol = card.querySelector(".balance").textContent.trim().split(/\s+/).pop();
  const price = priceForCoin(coin);
  const mainnet = network.endsWith("_mainnet");
  const fiat = mainnet && price != null ? ` (${formatUsdApprox(Number(amount) * price)})` : "";
  showCopyToast(t("wallet.received", { amount, symbol, fiat }), 5000, coin);
  const balance = card.querySelector(".balance");
  balance.classList.remove("balance-received");
  void balance.offsetWidth; // relance l'animation si une autre réception suit
  balance.classList.add("balance-received");
}

// Surveillance en direct (voir core/src/balance_watch.rs) : dès qu'un envoi ou
// une réception change le solde d'une carte affichée, Rust le signale
// ("balance-changed") et la carte est relue aussitôt — Solana/USDC poussés par
// le nœud (~1 s), Ethereum relu toutes les 6 s, Bitcoin toutes les 10 s (mempool
// compris). Le rafraîchissement toutes les 15 s reste en filet de sécurité.
function updateBalanceWatch() {
  const targets = [...document.querySelectorAll(".wallet-card:not(.asset-hidden)")]
    .map((card) => {
      const coin = card.dataset.coin;
      const network = networkForCard(card);
      // Jetons du registre : pas de surveillance en direct (solde relu avec
      // les autres toutes les 60 s) — la surveillance lit un solde natif.
      if (usesTokenRegistry(coin, network)) return { address: "" };
      // Zcash : pas de surveillance en direct (solde relu toutes les 15 s).
      if (coin === "zec") return { address: "" };
      return { id: coin, network: coin === "usdc" ? "usdc_solana" : network, address: addressForCoin(coin, network) };
    })
    .filter((target) => target.address);
  invoke("watch_balances", { targets }).catch((e) => console.error(e));
}

window.__TAURI__.event.listen("balance-changed", (event) => {
  const card = document.querySelector(`.wallet-card[data-coin="${event.payload}"]`);
  if (card) refreshBalance(card);
});

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
    // Bitcoin : une réception non confirmée n'est PAS comptée dans le solde
    // (son émetteur peut encore l'annuler) — son montant est montré ici.
    const incoming = pending && network.startsWith("btc") ? await invoke("get_btc_pending_incoming", { network, address }) : null;
    const text = incoming ? t("wallet.pendingIncoming", { amount: incoming }) : t("wallet.pendingBadge");
    if (badge.textContent !== text) badge.textContent = text;
    badge.classList.toggle("visible", pending);
    // Nouvelle réception Bitcoin en attente (pas encore comptée dans le
    // solde) : signalée dès qu'elle apparaît, par la HAUSSE du total en
    // attente — une baisse (réception confirmée, passée dans le solde) n'est
    // pas une nouvelle réception. Rien au premier affichage, ni après un
    // changement de profil ou de réseau.
    const key = balanceKey(card);
    const seen = card._pendingIncoming;
    const increase = incoming && seen && seen.key === key ? balanceIncrease(seen.amount || "0", incoming) : null;
    if (increase) showCopyToast(t("wallet.receivedPending", { amount: increase }), 5000);
    card._pendingIncoming = { key, amount: incoming };
    // Transaction pas encore finalisée : revérifiée dans 15 s, la surveillance
    // en direct ne signalant pas la finalisation (le solde ne bouge plus). Un
    // seul minuteur par carte : chaque actualisation le remplace.
    clearTimeout(card._pendingRecheck);
    if (pending) card._pendingRecheck = setTimeout(() => refreshBalance(card), 15000);
  } catch (e) {
    console.error(e);
  }
}

function refreshAllBalances() {
  document.querySelectorAll(".wallet-card").forEach((card) => {
    if (!card.classList.contains("asset-hidden") || !hiddenBalancesChecked) refreshBalance(card);
  });
  hiddenBalancesChecked = true;
  renderRouteBanner();
}

document.querySelectorAll(".wallet-card").forEach((card) => {
  const refreshBtn = card.querySelector('[data-action="refresh"]');
  refreshBtn.addEventListener("click", withThrottledButton(refreshBtn, REFRESH_COOLDOWN_MS, () => refreshBalance(card), { keepLabel: true }));
  card.querySelector('[data-action="send"]').addEventListener("click", () => openSendModal(card));
  // Boutons QR et copie : ceux de la ligne d'adresse ET ceux de la carte repliée.
  card.querySelectorAll('[data-action="qr"]').forEach((button) => button.addEventListener("click", () => openQrModal(card)));
  // Cliquer l'adresse elle-même l'affiche en entier (même modale que le bouton QR,
  // qui montre déjà le texte complet à côté du code QR) — utile surtout en vue
  // liste (voir styles.css : `.address` y est tronquée avec "…" pour la
  // compacité), mais garde le même geste en vue cartes aussi, par cohérence.
  card.querySelectorAll('[data-field="address"], [data-field="collapsed-address"]').forEach((el) => el.addEventListener("click", () => openQrModal(card)));
  card.querySelectorAll('[data-action="copy-address"]').forEach((button) =>
    button.addEventListener("click", () => {
      const address = card.querySelector('[data-field="address"]').textContent;
      if (!address) {
        alert(t("wallet.historyAddressUnavailable"));
        return;
      }
      copyText(address, t("wallet.addressCopied"));
    })
  );
  // Carte repliée : afficher / masquer l'adresse sans déplier la carte.
  const toggleAddress = card.querySelector('[data-action="toggle-address"]');
  toggleAddress.addEventListener("click", () => {
    const shown = card.querySelector('[data-field="collapsed-address"]').classList.toggle("hidden") === false;
    toggleAddress.setAttribute("aria-pressed", String(shown));
    toggleAddress.dataset.i18nTitle = shown ? "wallet.hideAddress" : "wallet.showAddress";
    toggleAddress.title = t(toggleAddress.dataset.i18nTitle);
  });
  const swapBtn = card.querySelector('[data-action="swap"]');
  if (swapBtn) swapBtn.addEventListener("click", () => openSwapModal(card));
  // Même historique que l'onglet « Historique », ouvert directement sur cette
  // crypto : plus facile à trouver depuis la carte que l'onglet seul.
  card.querySelector('[data-action="history"]').addEventListener("click", () => openHistoryFor(card.dataset.coin));
  const select = card.querySelector(".network-select");
  if (select) {
    // Contrairement à EVM/Solana, changer de réseau Bitcoin change aussi l'adresse
    // affichée (mainnet et testnet dérivent des adresses différentes pour un même
    // profil, voir addressForCoin) — recalculée pour toutes les cartes sans risque,
    // puisqu'elle ne change de valeur que pour "btc".
    select.addEventListener("change", () => {
      renderCardAddress(card);
      refreshBalance(card);
      updateBalanceWatch();
    });
  }
});

// --- QR modal --------------------------------------------------------------

const qrModal = document.getElementById("qr-modal");

// Demande de paiement : montant facultatif inscrit dans le QR code, au format
// standard de chaque réseau — celui qui scanne voit l'adresse ET le montant :
// BIP21 pour Bitcoin, Solana Pay pour SOL (et USDC, désigné par son mint),
// EIP-681 pour Ethereum (montant en wei, réseau par son chain id). Sans
// montant : l'adresse seule, lisible par toutes les applications.
// Décimales maximales d'un montant demandé : 18 pour toute monnaie EVM.
const QR_DECIMALS = new Proxy({ btc: 8, sol: 9 }, { get: (known, coin) => ASSET_BY_COIN[coin]?.unitDecimals ?? known[coin] ?? 18 });
// Même mint que core/src/sol_spl.rs::usdc_mint_mainnet.
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
let qrCard = null;
let qrRenderToken = 0;

// Montant saisi (« 0,01 » accepté) → décimal normalisé (« 0.01 »), `null` si
// vide ou nul ; lève une erreur s'il est invalide.
function parseRequestAmount(raw, decimals) {
  const text = raw.trim().replace(",", ".");
  if (!text) return null;
  if (!/^\d+(\.\d+)?$/.test(text)) throw new Error("invalid");
  const [whole, fraction = ""] = text.split(".");
  if (fraction.length > decimals) throw new Error("invalid");
  const trimmedWhole = whole.replace(/^0+(?=\d)/, "");
  const trimmedFraction = fraction.replace(/0+$/, "");
  if (/^0*$/.test(trimmedWhole + trimmedFraction)) return null;
  return trimmedFraction ? `${trimmedWhole}.${trimmedFraction}` : trimmedWhole;
}

function paymentUri(coin, network, address, amount) {
  if (amount == null) return address;
  const asset = ASSET_BY_COIN[coin];
  if (asset?.token && isEvmNetwork(network)) {
    // EIP-681, appel transfer du contrat du jeton (montant en unités exactes).
    const [whole, fraction = ""] = amount.split(".");
    const units = BigInt(whole + fraction.padEnd(asset.unitDecimals, "0")).toString();
    return `ethereum:${asset.contracts[network]}@${EVM_CHAIN_IDS[network]}/transfer?address=${address}&uint256=${units}`;
  }
  if (asset?.token && network === "sol_mainnet") return `solana:${address}?amount=${amount}&spl-token=${asset.contracts.sol_mainnet}`;
  if (coin === "btc") return `bitcoin:${address}?amount=${amount}`;
  if (coin === "zec") return `zcash:${address}?amount=${amount}`;
  if (coin === "sol") return `solana:${address}?amount=${amount}`;
  if (coin === "usdc") return `solana:${address}?amount=${amount}&spl-token=${USDC_MINT}`;
  if (ASSET_BY_COIN[coin]?.family === "evm") {
    const chainId = EVM_CHAIN_IDS[network] ?? 1;
    const [whole, fraction = ""] = amount.split(".");
    const wei = BigInt(whole + fraction.padEnd(18, "0")).toString();
    return `ethereum:${address}@${chainId}?value=${wei}`;
  }
  return address;
}

// QR code de la carte ouverte, avec le montant saisi s'il est valide (sinon
// l'adresse seule, et l'erreur sous le champ).
async function renderQr() {
  const card = qrCard;
  if (!card) return;
  const coin = card.dataset.coin;
  const network = networkForCard(card);
  const address = addressForCoin(coin, network);
  const errorEl = document.getElementById("qr-amount-error");
  let amount = null;
  try {
    amount = parseRequestAmount(document.getElementById("qr-amount").value, QR_DECIMALS[coin]);
    hideError(errorEl);
  } catch (e) {
    showError(errorEl, t("qr.amountInvalid", { decimals: QR_DECIMALS[coin] }));
  }
  document.getElementById("qr-amount-hint").classList.toggle("hidden", amount == null);
  const token = ++qrRenderToken;
  const svg = await invoke("generate_qr_svg", { text: paymentUri(coin, network, address, amount) });
  if (token !== qrRenderToken || qrCard !== card) return; // saisie plus récente
  document.getElementById("qr-container").innerHTML = svg;
}

async function openQrModal(card) {
  const address = addressForCoin(card.dataset.coin, networkForCard(card));
  if (!address) {
    alert(t("wallet.historyAddressUnavailable"));
    return;
  }
  qrCard = card;
  setWithCoinIcon(document.getElementById("qr-coin"), card.dataset.coin, ASSET_BY_COIN[card.dataset.coin]?.name ?? "");
  document.getElementById("qr-amount").value = "";
  document.getElementById("qr-amount-unit").textContent = card.querySelector(".balance").textContent.trim().split(/\s+/).pop();
  try {
    await renderQr();
    document.getElementById("qr-address-text").textContent = address;
    qrModal.classList.remove("hidden");
  } catch (e) {
    alert(t("wallet.qrError", { err: e }));
  }
}

restrictToAmount(document.getElementById("qr-amount"));
document.getElementById("qr-amount").addEventListener("input", () => {
  renderQr().catch((e) => console.error(e));
});

document.getElementById("qr-close").addEventListener("click", () => {
  qrModal.classList.add("hidden");
  qrCard = null;
});

// --- Historique de transactions (onglet dédié, trié par réseau) -------------
// Un réseau = une carte du tableau de bord (voir data-coin) : la carte reste
// la seule source de vérité pour "quel réseau/quelle adresse" (mainnet ou
// testnet, choisi via son sélecteur), l'onglet ne fait que relire cet état,
// jamais son propre choix de réseau séparé.

const HISTORY_COINS = ASSETS.map((asset) => asset.coin);

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

// Montant en dollars affiché dans la devise choisie : « ≈ 1 234,56 $ » /
// « ≈ $1,234.56 » / « ≈ 1 085,20 € » ; sous le centime : « < 0,01 $ ».
// `fiat` : montant déjà converti (sinon, conversion au taux actuel).
function formatUsdApprox(usd, fiat = usdToFiat(usd)) {
  if (fiat == null) return "—";
  if (fiat > 0 && fiat < 0.01) return `< ${withCurrency((0.01).toLocaleString(chartLocale()))}`;
  return `≈ ${withCurrency(fiat.toLocaleString(chartLocale(), { minimumFractionDigits: 2, maximumFractionDigits: 2 }))}`;
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
    usdDiv.textContent = formatUsdApprox(tx.usd_value, usdToFiatAt(tx.usd_value, tx.timestamp_unix));
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
    // Jetons (registre Rust) : commande dédiée, l'interface n'envoie que
    // l'identifiant du jeton et le réseau (contrat ou mint lus côté Rust).
    const result = ASSET_BY_COIN[coin]?.token
      ? await invoke("get_token_tx_history", { token: coin, network, address })
      : await invoke("get_tx_history", { network, address });
    // Réseau sans source publique d'historique (BNB Chain, HyperEVM) : lien
    // vers la page de l'adresse sur l'explorateur du réseau.
    if (result.explorer_url) {
      container.replaceChildren(historyExplorerOnly(result.explorer_url));
      return;
    }
    const entries = result.entries;
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

function historyExplorerOnly(url) {
  const box = document.createElement("div");
  box.className = "history-explorer-only";
  const open = document.createElement("button");
  open.type = "button";
  open.className = "secondary";
  open.textContent = t("wallet.historyOpenExplorer");
  open.addEventListener("click", () => {
    invoke("open_external_link", { url }).catch((e) => alert(t("wallet.linkError", { err: e })));
  });
  box.append(mutedParagraph(t("wallet.historyExplorerOnly")), open);
  return box;
}

function loadAllHistory() {
  HISTORY_COINS.filter(isAssetVisible).forEach(loadHistorySection);
}

document.getElementById("refresh-history-btn").addEventListener("click", loadAllHistory);

// Menu « Recevoir » : une entrée par crypto affichée (ETH, BTC, SOL gardent
// leur libellé d'origine ; USDC reçoit à l'adresse Solana).
function renderReceiveMenu() {
  const list = document.querySelector(".action-menu .custom-select-options");
  const items = ASSETS.filter((asset) => asset.coin !== "usdc" && isAssetVisible(asset.coin)).map((asset) => {
    const li = document.createElement("li");
    li.dataset.coin = asset.coin;
    setWithCoinIcon(li, asset.coin, t("wallet.receiveAsset", { symbol: asset.symbol }));
    return li;
  });
  list.replaceChildren(...items);
}
renderReceiveMenu();

// Après un changement des cryptos affichées : cartes, menu, surveillance,
// prix en direct, courbe du portefeuille.
function refreshAssetDisplays() {
  applyAssetVisibility();
  renderReceiveMenu();
  updateBalanceWatch();
  if (lastMarketCoins) renderMarkets(lastMarketCoins);
  if (portfolioView.rangesEl.childElementCount) refreshChart(portfolioView);
}

// Fenêtre « Gérer mes cryptos ».
const assetsModal = document.getElementById("assets-modal");
document.getElementById("manage-assets-btn").addEventListener("click", () => {
  const list = document.getElementById("assets-list");
  list.replaceChildren(
    ...orderedCoins().map((coin) => ASSET_BY_COIN[coin]).map((asset) => {
      const li = document.createElement("li");
      const label = document.createElement("label");
      label.className = "asset-choice";
      const icon = Object.assign(document.createElement("img"), { src: asset.icon, alt: "", className: asset.iconRound ? "coin-icon coin-icon-round" : asset.coin === "sol" ? "coin-icon coin-icon-sol" : "coin-icon" });
      const name = Object.assign(document.createElement("span"), { className: "asset-choice-name", textContent: asset.name });
      const symbol = Object.assign(document.createElement("span"), { className: "muted", textContent: asset.symbol });
      const box = Object.assign(document.createElement("input"), { type: "checkbox", checked: isAssetVisible(asset.coin) });
      box.addEventListener("change", () => {
        assetChoices[asset.coin] = box.checked;
        saveAssetChoices();
        refreshAssetDisplays();
        if (box.checked) refreshBalance(document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`));
      });
      label.append(icon, name, symbol, box);
      li.appendChild(label);
      return li;
    })
  );
  assetsModal.classList.remove("hidden");
});
// Fermée par « Terminé », la croix, Échap, ou un clic à côté — seulement si
// le clic a aussi COMMENCÉ à côté : un geste commencé dans la fenêtre (faire
// défiler la liste, sélectionner du texte) et relâché dehors ne la ferme pas.
const closeAssetsModal = () => assetsModal.classList.add("hidden");
document.getElementById("assets-done").addEventListener("click", closeAssetsModal);
document.getElementById("assets-close-x").addEventListener("click", closeAssetsModal);
let assetsPressedOutside = false;
assetsModal.addEventListener("pointerdown", (e) => {
  assetsPressedOutside = e.target === assetsModal;
});
assetsModal.addEventListener("click", (e) => {
  if (e.target === assetsModal && assetsPressedOutside) closeAssetsModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !assetsModal.classList.contains("hidden")) closeAssetsModal();
});

// --- Ordre des cartes (« Organiser ») ------------------------------------------
// Trois modes : « Mon ordre » (glisser-déposer ou flèches), « Valeur détenue »
// (valeur en devise du solde affiché, décroissante, recalculée à chaque
// nouveau solde ou cours) et « Nom ». Préférence d'affichage par appareil,
// retenue localement comme la vue liste. Réordonner ne change que la place
// des éléments dans la grille (et dans l'onglet Historique, et la liste
// « Gérer mes cryptos ») : aucun autre code n'en dépend.

const CARD_ORDER_STORAGE_KEY = "pgp-wallet-card-order";
const CARD_ORDER_MODES = ["custom", "value", "name"];
const walletGrid = document.querySelector(".wallet-grid");
// Ordre d'origine (cartes d'index.html, puis celles générées depuis ASSETS) :
// base de « Mon ordre » pour les cryptos jamais déplacées.
const DEFAULT_CARD_ORDER = [...walletGrid.querySelectorAll(".wallet-card")].map((card) => card.dataset.coin);
let cardOrder = { mode: "custom", custom: [] };
try {
  const saved = JSON.parse(localStorage.getItem(CARD_ORDER_STORAGE_KEY) || "null");
  if (saved && CARD_ORDER_MODES.includes(saved.mode) && Array.isArray(saved.custom)) {
    cardOrder = { mode: saved.mode, custom: saved.custom.filter((coin) => DEFAULT_CARD_ORDER.includes(coin)) };
  }
} catch (e) {
  // localStorage indisponible : ordre d'origine.
}
let organizing = false;
let draggingCard = null;
let cardResortTimer = null;

function saveCardOrder() {
  try {
    localStorage.setItem(CARD_ORDER_STORAGE_KEY, JSON.stringify(cardOrder));
  } catch (e) {
    // Best-effort : l'ordre reste appliqué pour cette session.
  }
}

// « Mon ordre » complet : l'ordre enregistré, puis les cryptos qui n'y sont
// pas encore (ajoutées depuis), à leur place d'origine.
function customOrder() {
  return [...cardOrder.custom, ...DEFAULT_CARD_ORDER.filter((coin) => !cardOrder.custom.includes(coin))];
}

// Valeur en devise du solde affiché par la carte (réseau de test : aucune).
function cardValue(coin) {
  const card = walletGrid.querySelector(`.wallet-card[data-coin="${coin}"]`);
  if (!card || TEST_NETWORKS.includes(networkForCard(card))) return 0;
  const amount = Number.parseFloat(card.querySelector('[data-field="balance"]').textContent);
  const price = priceForCoin(coin);
  return Number.isFinite(amount) && price != null ? amount * price : 0;
}

function orderedCoins() {
  const custom = customOrder();
  if (cardOrder.mode === "value") {
    const values = new Map(custom.map((coin) => [coin, cardValue(coin)]));
    const rank = new Map(custom.map((coin, i) => [coin, i]));
    return [...custom].sort((a, b) => values.get(b) - values.get(a) || rank.get(a) - rank.get(b));
  }
  if (cardOrder.mode === "name") {
    const collator = new Intl.Collator(currentLang);
    return [...custom].sort((a, b) => collator.compare(ASSET_BY_COIN[a].name, ASSET_BY_COIN[b].name));
  }
  return custom;
}

// Place les éléments dans l'ordre voulu, sans rien déplacer s'ils y sont
// déjà (pas de saut d'affichage ni de perte du focus à chaque recalcul).
function placeInOrder(container, elements) {
  const current = [...container.children].filter((el) => elements.includes(el));
  if (current.length === elements.length && current.every((el, i) => el === elements[i])) return;
  for (const el of elements) container.appendChild(el);
}

function applyCardOrder() {
  if (draggingCard) return;
  const coins = orderedCoins();
  placeInOrder(walletGrid, coins.map((coin) => walletGrid.querySelector(`.wallet-card[data-coin="${coin}"]`)).filter(Boolean));
  const historyCard = document.querySelector('.tab-panel[data-panel="history"] .card');
  placeInOrder(historyCard, coins.map((coin) => document.getElementById(`history-section-${coin}`)).filter(Boolean));
}

// « Valeur détenue » : recalcul après un nouveau solde ou cours, regroupé
// (plusieurs soldes arrivent presque ensemble).
function scheduleCardResort() {
  if (cardOrder.mode !== "value") return;
  clearTimeout(cardResortTimer);
  cardResortTimer = setTimeout(applyCardOrder, 500);
}

function setCardOrderMode(mode) {
  cardOrder.mode = mode;
  saveCardOrder();
  applyCardOrder();
  renderOrganizeModes();
}

function renderOrganizeModes() {
  document.querySelectorAll("[data-order-mode]").forEach((button) => {
    const active = button.dataset.orderMode === cardOrder.mode;
    button.classList.toggle("primary", active);
    button.classList.toggle("secondary", !active);
    button.setAttribute("aria-pressed", String(active));
  });
}

// Ordre affiché actuel → « Mon ordre » (après un glisser ou une flèche).
function adoptDisplayedOrder() {
  cardOrder.custom = [...walletGrid.querySelectorAll(".wallet-card")].map((card) => card.dataset.coin);
  setCardOrderMode("custom");
}

// Poignée et flèches de chaque carte, visibles seulement en mode « Organiser ».
function addOrganizeControls(card) {
  const controls = document.createElement("div");
  controls.className = "organize-controls";
  controls.innerHTML = `
    <span class="drag-handle" aria-hidden="true" data-i18n-title="organize.drag">⠿</span>
    <button type="button" class="organize-move" data-move="-1" data-i18n-title="organize.moveUp" aria-label="${t("organize.moveUp")}">↑</button>
    <button type="button" class="organize-move" data-move="1" data-i18n-title="organize.moveDown" aria-label="${t("organize.moveDown")}">↓</button>`;
  controls.querySelectorAll("[data-move]").forEach((button) => {
    button.title = t(button.dataset.move === "-1" ? "organize.moveUp" : "organize.moveDown");
    button.addEventListener("click", () => moveCard(card, Number(button.dataset.move), button));
  });
  card.prepend(controls);
}
walletGrid.querySelectorAll(".wallet-card").forEach(addOrganizeControls);

// Déplace une carte d'un cran parmi les cartes AFFICHÉES (les masquées
// gardent leur place relative).
function moveCard(card, step, focusAfter) {
  const visible = [...walletGrid.querySelectorAll(".wallet-card:not(.asset-hidden)")];
  const neighbor = visible[visible.indexOf(card) + step];
  if (!neighbor) return;
  walletGrid.insertBefore(card, step < 0 ? neighbor : neighbor.nextSibling);
  adoptDisplayedOrder();
  focusAfter?.focus();
}

function setOrganizing(on) {
  organizing = on;
  document.getElementById("organize-bar").classList.toggle("hidden", !on);
  document.getElementById("organize-btn").setAttribute("aria-pressed", String(on));
  walletGrid.classList.toggle("organizing", on);
  walletGrid.querySelectorAll(".wallet-card").forEach((card) => {
    card.draggable = on;
  });
  renderOrganizeModes();
}

document.getElementById("organize-btn").addEventListener("click", () => setOrganizing(!organizing));
document.getElementById("organize-done").addEventListener("click", () => setOrganizing(false));
document.querySelectorAll("[data-order-mode]").forEach((button) => {
  button.addEventListener("click", () => setCardOrderMode(button.dataset.orderMode));
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && organizing && !document.querySelector(".modal-overlay:not(.hidden)")) setOrganizing(false);
});

// Glisser-déposer (souris) : la carte survolée s'écarte en direct ; insertion
// avant ou après elle selon la position du pointeur (horizontale en grille,
// verticale sur une seule colonne, vue liste comprise).
walletGrid.addEventListener("dragstart", (e) => {
  const card = e.target.closest?.(".wallet-card");
  if (!organizing || !card) return;
  draggingCard = card;
  card.classList.add("dragging");
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", card.dataset.coin);
});
walletGrid.addEventListener("dragover", (e) => {
  if (!draggingCard) return;
  e.preventDefault();
  const target = e.target.closest?.(".wallet-card");
  if (!target || target === draggingCard) return;
  const rect = target.getBoundingClientRect();
  const columns = getComputedStyle(walletGrid).gridTemplateColumns.split(" ").filter(Boolean).length;
  const before = columns > 1 ? e.clientX < rect.left + rect.width / 2 : e.clientY < rect.top + rect.height / 2;
  const reference = before ? target : target.nextSibling;
  if (reference !== draggingCard) walletGrid.insertBefore(draggingCard, reference);
});
walletGrid.addEventListener("drop", (e) => {
  if (draggingCard) e.preventDefault();
});
walletGrid.addEventListener("dragend", () => {
  if (!draggingCard) return;
  draggingCard.classList.remove("dragging");
  draggingCard = null;
  adoptDisplayedOrder();
});

// Ordre initial une fois tout le module chargé (« Valeur détenue » lit des
// constantes déclarées plus bas dans ce fichier).
setTimeout(applyCardOrder, 0);

// Onglet Historique, défilé jusqu'à la section de `coin` (sous la barre de
// navigation, qui reste en haut) et brièvement mise en évidence.
function openHistoryFor(coin) {
  document.querySelector('.nav-tab[data-tab="history"]').click();
  const section = document.getElementById(`history-section-${coin}`);
  if (!section) return;
  const navbar = document.querySelector(".navbar");
  window.scrollTo({ top: section.getBoundingClientRect().top + window.scrollY - navbar.offsetHeight - 16 });
  section.classList.remove("history-section-flash");
  void section.offsetWidth; // relance l'animation si on reclique aussitôt
  section.classList.add("history-section-flash");
}

// --- Send modal ----------------------------------------------------------

const sendModal = document.getElementById("send-modal");
let sendContext = null;

// Montant en crypto OU dans la devise affichée (€ ou $), les deux champs liés
// au cours en direct. Le montant en crypto reste le seul envoyé, affiché dans
// l'aperçu puis dans la boîte de confirmation de Windows ; le montant en
// devise n'est qu'une aide à la saisie. Sur un réseau de test (fonds sans
// valeur) ou sans cours connu, le champ en devise est désactivé.
const sendAmountInput = document.getElementById("send-amount");
const sendFiatInput = document.getElementById("send-amount-fiat");

// Cours de la crypto envoyée : dollars pour 1 unité, dollars pour 1 unité de la
// devise affichée ; `null` si inconnu ou réseau de test.
function sendRate() {
  if (!sendContext || !networkForCard(sendContext.card).endsWith("mainnet")) return null;
  const price = priceForCoin(sendContext.coin);
  const usdPerUnit = displayCurrency === "eur" ? usdPerEur : 1;
  return price != null && price > 0 && usdPerUnit ? { price, usdPerUnit } : null;
}

function parseAmountInput(text) {
  const value = Number.parseFloat(text.replace(",", "."));
  return Number.isFinite(value) ? value : null;
}

function syncSendFiatFromCrypto() {
  const rate = sendRate();
  const crypto = parseAmountInput(sendAmountInput.value);
  if (!rate || crypto == null) {
    sendFiatInput.value = "";
    return;
  }
  const fiat = ((crypto * rate.price) / rate.usdPerUnit).toFixed(2);
  sendFiatInput.value = currentLang === "fr" ? fiat.replace(".", ",") : fiat;
}

function syncSendCryptoFromFiat() {
  const rate = sendRate();
  const fiat = parseAmountInput(sendFiatInput.value);
  sendAmountInput.value = rate && fiat != null ? ((fiat * rate.usdPerUnit) / rate.price).toFixed(COIN_DECIMALS[sendContext.coin]) : "";
}

function setSendCryptoAmount(value) {
  sendAmountInput.value = value;
  syncSendFiatFromCrypto();
}

restrictToAmount(sendAmountInput, syncSendFiatFromCrypto);
restrictToAmount(sendFiatInput, syncSendCryptoFromFiat);

// Unités à droite des deux champs, champ en devise activé ou non.
function renderSendAmountUnits() {
  if (!sendContext) return;
  setWithCoinIcon(document.getElementById("send-amount-unit"), sendContext.coin, COIN_SYMBOL[sendContext.coin]);
  document.getElementById("send-amount-fiat-unit").textContent = displayCurrency === "eur" ? "€" : "$";
  const rate = sendRate();
  sendFiatInput.disabled = !rate;
  sendFiatInput.placeholder = rate ? (currentLang === "fr" ? "0,00" : "0.00") : "—";
}

// Montants rapides en dollars : convertis en crypto au prix en direct (voir
// `latestPrices`/`refreshPrices`), pas des montants fixes en ETH/BTC/SOL — ça n'a
// de sens que si le montant en dollars reste identique quel que soit le cours du
// jour. Mêmes décimales que le formatage des soldes côté Rust
// (app/src-tauri/src/lib.rs::get_balance), pour que le montant rempli soit celui
// réellement envoyé, pas une valeur arrondie différente.
// Montants rapides, dans la devise affichée (5 $ ou 5 €…).
const QUICK_AMOUNTS = [5, 10, 50];
const COIN_DECIMALS = Object.fromEntries(ASSETS.map((asset) => [asset.coin, asset.decimals]));
const COIN_SYMBOL = Object.fromEntries(ASSETS.map((asset) => [asset.coin, asset.symbol]));

function renderQuickAmounts() {
  const container = document.getElementById("send-quick-amounts");
  container.innerHTML = "";
  if (!sendContext) return;
  const coin = sendContext.coin;
  const price = priceForCoin(coin);
  const decimals = COIN_DECIMALS[coin];
  const symbol = COIN_SYMBOL[coin];

  // Dollars pour 1 unité de la devise affichée (1 pour le dollar).
  const usdPerUnit = displayCurrency === "eur" ? usdPerEur : 1;
  if (price == null || !usdPerUnit) {
    container.replaceChildren(Object.assign(document.createElement("p"), { className: "muted quick-amounts-hint", textContent: t("send.quickUnavailable") }));
    return;
  }

  QUICK_AMOUNTS.forEach((amount) => {
    const cryptoAmount = ((amount * usdPerUnit) / price).toFixed(decimals);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-amount-btn";
    const usdSpan = document.createElement("span");
    usdSpan.className = "quick-amount-usd";
    usdSpan.textContent = withCurrency(String(amount));
    const cryptoSpan = document.createElement("span");
    cryptoSpan.className = "quick-amount-crypto";
    cryptoSpan.textContent = `≈ ${cryptoAmount} ${symbol}`;
    btn.appendChild(usdSpan);
    btn.appendChild(cryptoSpan);
    btn.addEventListener("click", () => {
      setSendCryptoAmount(cryptoAmount);
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
      setSendCryptoAmount(cryptoAmount);
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
  // Nom lu sur la carte, sans l'indentation du HTML (le titre contient le
  // bouton de repli) : « Bitcoin », « USDC Solana ».
  const coinName = card.querySelector("h2").textContent.trim().replace(/\s+/g, " ");
  setWithCoinIcon(document.getElementById("send-modal-title"), card.dataset.coin, `${t("send.title")} (${coinName})`);
  document.getElementById("send-from-profile").textContent = profile ? profile.label : "—";
  document.getElementById("send-mainnet-warning").classList.toggle("hidden", !network.endsWith("mainnet"));
  document.getElementById("send-to").value = "";
  document.getElementById("send-amount").value = "";
  sendFiatInput.value = "";
  document.getElementById("send-password").value = "";
  hideError(document.getElementById("send-error"));
  document.getElementById("send-success").classList.add("hidden");
  renderSendAmountUnits();
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
  const rate = sendRate();
  const approx = rate ? ` (${formatUsdApprox(Number(amount) * rate.price)})` : "";
  setWithCoinIcon(document.getElementById("send-preview-amount"), sendContext.coin, `${amount} ${COIN_SYMBOL[sendContext.coin]}${approx}`);

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
    // Jetons du registre : identifiant et réseau seulement (contrat, décimales
    // et boîte de confirmation côté Rust).
    const txResult = usesTokenRegistry(sendContext.coin, network)
      ? await invoke("send_token_transaction", { token: sendContext.coin, network, password, to, amount, profileIndex: sendContext.profileIndex })
      : sendContext.coin === "usdc"
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

// --- Échange (« Convertir ») -------------------------------------------------
// Passe par un protocole externe non audité par cette app : THORChain ou Maya
// pour un échange entre réseaux (core/src/thorchain_rpc.rs), Jupiter dans le
// même portefeuille Solana (core/src/jupiter_rpc.rs), CoW sur un même réseau
// EVM (ordre signé, core/src/cow.rs). Les paires proposées viennent
// de Rust (`swapPairs`, core/src/swap_routes.rs) : l'interface ne propose que
// ce que les commandes d'échange acceptent. Même principe en deux étapes que
// l'envoi (devis -> aperçu -> confirmation native de Windows).

const swapModal = document.getElementById("swap-modal");
const swapPreviewModal = document.getElementById("swap-preview-modal");
let swapContext = null;

invoke("swap_pairs")
  .then((pairs) => {
    swapPairs = pairs;
    document.querySelectorAll(".wallet-card").forEach(updateConvertButton);
  })
  .catch((e) => console.error(e));

const swapKey = (coin, network) => `${coin}@${network}`;

function parseSwapKey(key) {
  const [coin, network] = key.split("@");
  return { coin, network };
}

// « USDC (USDC) — Base » ; réseau omis pour une crypto qui n'en a qu'un.
function swapAssetLabel(coin, network) {
  const asset = ASSET_BY_COIN[coin];
  if (!asset) return coin;
  const mainnets = asset.networks.filter((n) => !TEST_NETWORKS.includes(n));
  const label = asset.name === asset.symbol ? asset.name : `${asset.name} (${asset.symbol})`;
  return mainnets.length > 1 ? `${label} — ${t(`net.${network}`).split(" — ")[0]}` : label;
}

// Cryptos de départ : celles qu'un échange sait vendre, affichées dans le
// portefeuille (plus celle de la carte d'où la fenêtre s'ouvre).
function fillSwapFromOptions(selectedKey) {
  const select = document.getElementById("swap-from-coin");
  const keys = [...new Set(swapPairs.map((p) => swapKey(p.from_coin, p.from_network)))].filter(
    (key) => key === selectedKey || isAssetVisible(parseSwapKey(key).coin)
  );
  select.replaceChildren(
    ...keys.map((key) => {
      const { coin, network } = parseSwapKey(key);
      const option = document.createElement("option");
      option.value = key;
      option.dataset.coin = coin;
      option.textContent = swapAssetLabel(coin, network);
      return option;
    })
  );
  select.value = keys.includes(selectedKey) ? selectedKey : (keys[0] ?? "");
  syncCustomSelect(select);
}

// Paire choisie dans la fenêtre, telle que Rust l'a déclarée (`null` sinon).
function selectedSwapPair() {
  const from = parseSwapKey(document.getElementById("swap-from-coin").value);
  const to = parseSwapKey(document.getElementById("swap-to-coin").value);
  const pair = swapPairs.find((p) => p.from_coin === from.coin && p.from_network === from.network && p.to_coin === to.coin && p.to_network === to.network);
  if (!pair) return null;
  // Fournisseurs de l'étape à faire maintenant (la paire elle-même, ou sa
  // première étape vers l'intermédiaire), le préféré d'abord ; celui choisi
  // dans le menu s'il en fait partie.
  const stepTo = pair.via ?? to;
  const direct = swapPairs.find((p) => p.from_coin === from.coin && p.from_network === from.network && p.to_coin === stepTo.coin && p.to_network === stepTo.network && !p.via);
  const providers = direct?.protocols?.length ? direct.protocols : [pair.protocol];
  const chosen = document.getElementById("swap-provider").value;
  return { from, to, protocol: providers.includes(chosen) ? chosen : providers[0], providers, via: pair.via ?? null, thenProtocol: pair.then_protocol ?? null };
}

// Frais d'affiliation de chaque fournisseur, en % (voir core/src/cow.rs et
// core/src/thorchain_rpc.rs).
const SWAP_PROVIDER_FEE_PERCENT = { thorchain: 0.8, maya: 0.8, jupiter: 0.8, cow: 1, lifi: 0.8 };

// Menu « Fournisseur » : tous ceux qui savent faire l'étape, le recommandé
// en premier et choisi par défaut à chaque changement de paire.
function fillSwapProviderOptions() {
  const select = document.getElementById("swap-provider");
  const pair = selectedSwapPair();
  const providers = pair ? pair.providers : [];
  select.replaceChildren(
    ...providers.map((protocol, index) => {
      const option = document.createElement("option");
      option.value = protocol;
      const fee = `${SWAP_PROVIDER_FEE_PERCENT[protocol].toLocaleString(chartLocale(), { minimumFractionDigits: 2 })}\u00a0%`;
      option.textContent = t(index === 0 ? "swap.providerRecommended" : "swap.providerOption", { name: SWAP_PROTOCOL_NAMES[protocol], fee });
      return option;
    })
  );
  select.value = providers[0] ?? "";
  syncCustomSelect(select);
}

function onSwapTargetChange() {
  fillSwapProviderOptions();
  updateSwapDestination();
}

const SWAP_PROTOCOL_NAMES = { thorchain: "THORChain", maya: "Maya", jupiter: "Jupiter", cow: "CoW", lifi: "LI.FI" };

// Au-delà de ce coût estimé (frais et écart au cours du marché), l'aperçu
// avertit avant de continuer.
const SWAP_HIGH_COST_PERCENT = 5;

// « SOL », « ETH (Arbitrum) » : symbole, et réseau pour une crypto qui en a
// plusieurs.
function swapShortLabel({ coin, network }) {
  const asset = ASSET_BY_COIN[coin];
  const symbol = COIN_SYMBOL[coin] ?? coin.toUpperCase();
  const mainnets = asset ? asset.networks.filter((n) => !TEST_NETWORKS.includes(n)) : [];
  return mainnets.length > 1 ? `${symbol} (${t(`net.${network}`).split(" — ")[0]})` : symbol;
}

// Étape à faire maintenant : la paire elle-même, ou sa première étape (vers
// la crypto intermédiaire) pour un échange en 2 étapes — les commandes
// d'échange n'acceptent qu'une paire directe.
function currentSwapStep(pair) {
  return pair.via ? { from: pair.from, to: pair.via, protocol: pair.protocol } : pair;
}

// Adresse d'arrivée de l'étape : aucune dans le même portefeuille ; celle de
// l'utilisateur pour la crypto intermédiaire (TOUJOURS la sienne) ; sinon
// celle saisie.
function swapStepDestination(pair, step) {
  if (isSameWalletSwap(step)) return "";
  if (pair.via) return addressForCoin(pair.via.coin, pair.via.network);
  return document.getElementById("swap-destination").value.trim();
}

function swapRouteVars(pair) {
  return {
    from: swapShortLabel(pair.from),
    via: swapShortLabel(pair.via),
    to: swapShortLabel(pair.to),
    first: SWAP_PROTOCOL_NAMES[pair.protocol],
    second: SWAP_PROTOCOL_NAMES[pair.thenProtocol],
  };
}

function updateSwapToOptions() {
  const from = parseSwapKey(document.getElementById("swap-from-coin").value);
  const toSelect = document.getElementById("swap-to-coin");
  toSelect.replaceChildren(
    ...swapPairs
      .filter((p) => p.from_coin === from.coin && p.from_network === from.network)
      .sort((a, b) => Number(Boolean(a.via)) - Number(Boolean(b.via)))
      .map((p) => {
        const option = document.createElement("option");
        option.value = swapKey(p.to_coin, p.to_network);
        option.dataset.coin = p.to_coin;
        const note = p.via ? t("swap.viaTwoSteps", { via: swapShortLabel(p.via) }) : { jupiter: t("swap.viaJupiter"), cow: t("swap.viaCow"), lifi: t("swap.viaLifi") }[p.protocol];
        option.textContent = swapAssetLabel(p.to_coin, p.to_network) + (note ? ` · ${note}` : "");
        return option;
      })
  );
  syncCustomSelect(toSelect);
  setWithCoinIcon(document.getElementById("swap-amount-label"), from.coin, `${t("swap.amount")} (${COIN_SYMBOL[from.coin] ?? ""})`);
  onSwapTargetChange();
}

// Montant à échanger : chiffres seulement (comme à l'envoi).
restrictToAmount(document.getElementById("swap-amount"));

document.getElementById("swap-from-coin").addEventListener("change", updateSwapToOptions);

function openSwapModal(card, preset = null) {
  const profile = currentProfile();
  swapContext = { card, profileIndex: profile ? profile.index : currentProfileIndex };
  document.getElementById("swap-amount").value = preset?.amount ?? "";
  hideError(document.getElementById("swap-error"));
  fillSwapFromOptions(preset ? swapKey(preset.from.coin, preset.from.network) : swapKey(card.dataset.coin, networkForCard(card)));
  updateSwapToOptions();
  if (preset) {
    const toSelect = document.getElementById("swap-to-coin");
    toSelect.value = swapKey(preset.to.coin, preset.to.network);
    syncCustomSelect(toSelect);
    onSwapTargetChange();
  }
  swapModal.classList.remove("hidden");
}

// Jupiter (Solana) et CoW (un même réseau EVM) restent dans le même
// portefeuille : pas d'adresse de destination à saisir, contrairement à un
// échange entre réseaux (THORChain, Maya), où elle est pré-remplie avec
// l'adresse du profil sur le réseau d'arrivée.
const isSameWalletSwap = (pair) => pair?.protocol === "jupiter" || pair?.protocol === "cow";

function updateSwapDestination() {
  const pair = selectedSwapPair();
  const twoSteps = Boolean(pair?.via);
  const sameWallet = !twoSteps && isSameWalletSwap(pair);
  document.getElementById("swap-destination-block").classList.toggle("hidden", sameWallet || twoSteps);
  document.getElementById("swap-jupiter-hint").classList.toggle("hidden", !sameWallet);
  const routeHint = document.getElementById("swap-route-hint");
  routeHint.classList.toggle("hidden", !twoSteps);
  if (twoSteps) routeHint.textContent = t("swap.twoStepHint", swapRouteVars(pair));
  if (pair && !sameWallet && !twoSteps) document.getElementById("swap-destination").value = addressForCoin(pair.to.coin, pair.to.network);
}

document.getElementById("swap-to-coin").addEventListener("change", onSwapTargetChange);
document.getElementById("swap-provider").addEventListener("change", updateSwapDestination);

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

  const pair = selectedSwapPair();
  if (!pair) {
    showError(errorEl, t("swap.unavailable"));
    return;
  }
  const step = currentSwapStep(pair);
  const { coin: fromCoin, network: fromNetwork } = step.from;
  const { coin: toCoin, network: toNetwork } = step.to;
  const amount = document.getElementById("swap-amount").value.trim().replace(",", ".");
  const sameWallet = isSameWalletSwap(step);
  const destination = swapStepDestination(pair, step);

  if (!amount || (!sameWallet && !destination)) {
    showError(errorEl, t("wallet.allFieldsRequired"));
    return;
  }

  try {
    const destRow = document.getElementById("swap-preview-destination").closest(".send-preview-row");
    const feeRow = document.getElementById("swap-preview-fees").closest(".send-preview-row");
    const minRow = document.getElementById("swap-preview-min").closest(".send-preview-row");
    minRow.classList.add("hidden");
    let receivingText;
    let receivedAmount = Number.NaN;
    if (step.protocol === "cow") {
      // Ordre CoW : réception attendue, minimum garanti signé, frais (1 %
      // d'intégration dans la crypto reçue + frais réseau de CoW pris sur la
      // crypto vendue), tous déjà comptés.
      const quote = await invoke("get_cow_quote", { network: fromNetwork, fromCoin, toCoin, amount, profileIndex: swapContext.profileIndex });
      receivingText = `≈ ${quote.expected_out}`;
      receivedAmount = Number.parseFloat(quote.expected_out);
      document.getElementById("swap-preview-min").textContent = quote.min_out;
      document.getElementById("swap-preview-fees-label").textContent = t("swap.previewFeesOf", { name: "CoW" });
      document.getElementById("swap-preview-fees").textContent = `${quote.partner_fee} + ${quote.network_fee}`;
      minRow.classList.remove("hidden");
      destRow.classList.add("hidden");
      feeRow.classList.remove("hidden");
    } else if (step.protocol === "lifi") {
      // LI.FI : pont choisi par l'agrégateur, durée estimée, minimum annoncé
      // (garanti par le pont) ; la transaction elle-même est vérifiée à la
      // confirmation.
      const quote = await invoke("get_lifi_quote", { fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, profileIndex: swapContext.profileIndex });
      receivingText = `≈ ${quote.expected_out}`;
      receivedAmount = Number.parseFloat(quote.expected_out);
      document.getElementById("swap-preview-min").textContent = quote.min_out;
      document.getElementById("swap-preview-fees-label").textContent = t("swap.previewLifiRoute");
      document.getElementById("swap-preview-fees").textContent = `${quote.bridge}, ${t("swap.lifiDuration", { minutes: Math.max(1, Math.ceil(quote.duration_secs / 60)) })}`;
      document.getElementById("swap-preview-destination").textContent = destination;
      minRow.classList.remove("hidden");
      destRow.classList.remove("hidden");
      feeRow.classList.remove("hidden");
    } else if (step.protocol === "jupiter") {
      const outAmount = await invoke("get_jupiter_quote", { fromCoin, toCoin, amount });
      receivingText = `≈ ${outAmount} ${COIN_SYMBOL[toCoin] || toCoin.toUpperCase()}`;
      receivedAmount = Number(outAmount);
      destRow.classList.add("hidden");
      feeRow.classList.add("hidden");
    } else {
      const quote = await invoke("get_swap_quote", { fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, protocol: step.protocol });
      receivingText = `≈ ${quote.expected_amount_out} ${COIN_SYMBOL[toCoin] || toCoin.toUpperCase()}`;
      receivedAmount = Number(quote.expected_amount_out);
      // Frais du protocole (THORChain ou Maya), dans la crypto reçue (déjà
      // déduits de la réception).
      document.getElementById("swap-preview-fees-label").textContent = t("swap.previewFeesOf", { name: SWAP_PROTOCOL_NAMES[step.protocol] });
      document.getElementById("swap-preview-fees").textContent = quote.total_fees != null ? `${quote.total_fees} ${COIN_SYMBOL[toCoin] ?? ""}` : "—";
      document.getElementById("swap-preview-destination").textContent = destination;
      destRow.classList.remove("hidden");
      feeRow.classList.remove("hidden");
    }

    const routeNote = document.getElementById("swap-preview-route");
    routeNote.classList.toggle("hidden", !pair.via);
    if (pair.via) routeNote.textContent = t("swap.previewRoute", swapRouteVars(pair));
    // Valeur en devise de l'envoi et de la réception (cours du marché) et
    // leur écart : frais compris, un repère pour juger le devis d'un
    // protocole externe. Masqué sans cours connu.
    const fromPrice = priceForCoin(fromCoin);
    const toPrice = priceForCoin(toCoin);
    const sentValue = fromPrice != null ? Number(amount) * fromPrice : null;
    const receivedValue = toPrice != null && Number.isFinite(receivedAmount) ? receivedAmount * toPrice : null;
    const withValue = (text, value) => (value != null && Number.isFinite(value) ? `${text} (${formatUsdApprox(value)})` : text);
    setWithCoinIcon(document.getElementById("swap-preview-sending"), fromCoin, withValue(`${amount} ${COIN_SYMBOL[fromCoin] || fromCoin.toUpperCase()}`, sentValue));
    setWithCoinIcon(document.getElementById("swap-preview-receiving"), toCoin, withValue(receivingText, receivedValue));
    const costRow = document.getElementById("swap-preview-cost").closest(".send-preview-row");
    const costWarning = document.getElementById("swap-preview-cost-warning");
    const costKnown = sentValue > 0 && receivedValue != null && Number.isFinite(receivedValue);
    costRow.classList.toggle("hidden", !costKnown);
    costWarning.classList.add("hidden");
    if (costKnown) {
      const cost = sentValue - receivedValue;
      const percent = (cost / sentValue) * 100;
      const percentText = percent.toLocaleString(chartLocale(), { maximumFractionDigits: 1 });
      document.getElementById("swap-preview-cost").textContent = `${cost > 0 ? formatUsdApprox(cost) : "—"} (${percentText}\u00a0%)`;
      costWarning.classList.toggle("hidden", percent <= SWAP_HIGH_COST_PERCENT);
    }
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

  const pair = selectedSwapPair();
  if (!pair) {
    showError(errorEl, t("swap.unavailable"));
    return;
  }
  const step = currentSwapStep(pair);
  const { coin: fromCoin, network: fromNetwork } = step.from;
  const { coin: toCoin, network: toNetwork } = step.to;
  const amount = document.getElementById("swap-amount").value.trim().replace(",", ".");
  const destination = swapStepDestination(pair, step);
  const password = document.getElementById("swap-preview-password").value;
  const profileIndex = swapContext.profileIndex;

  if (!password) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }

  try {
    // 2 étapes : solde de la crypto intermédiaire relevé AVANT l'envoi, pour
    // reconnaître son arrivée (et le montant reçu) ensuite.
    const routeAddress = pair.via ? addressForCoin(pair.via.coin, pair.via.network) : "";
    const routeBefore = pair.via ? await readAssetBalance(pair.via.coin, pair.via.network, routeAddress) : null;

    if (step.protocol === "cow") {
      const order = await invoke("cow_swap_transaction", { password, network: fromNetwork, fromCoin, toCoin, amount, profileIndex });
      trackCowOrder(successEl, fromNetwork, order);
    } else if (step.protocol === "lifi") {
      const transfer = await invoke("lifi_swap_transaction", { password, fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, profileIndex });
      trackLifiTransfer(successEl, transfer);
    } else {
      const txResult = step.protocol === "jupiter"
        ? await invoke("jupiter_swap_transaction", { password, fromCoin, toCoin, amount, profileIndex })
        : await invoke("swap_transaction", { password, fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, protocol: step.protocol, profileIndex });
      successEl.textContent = t("send.txSent", { tx: txResult });
      successEl.classList.remove("hidden");
    }

    if (pair.via) {
      savePendingRoute({ from: pair.from, via: pair.via, to: pair.to, profileIndex, address: routeAddress, before: routeBefore, startedAt: Date.now() });
      const note = document.createElement("span");
      note.textContent = ` ${t("swap.routeStep1Sent", { via: swapShortLabel(pair.via) })}`;
      successEl.append(note);
    } else if (pendingRoute && sameSwapAsset(pendingRoute.via, pair.from) && sameSwapAsset(pendingRoute.to, pair.to)) {
      // Seconde étape d'un échange en 2 étapes : terminé.
      savePendingRoute(null);
    }
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

// --- Échange en 2 étapes : suivi de la crypto intermédiaire ---------------------
// Après l'étape 1, la route est gardée localement (même après un redémarrage)
// et le solde de la crypto intermédiaire relu toutes les 20 s : dès qu'il
// monte, l'étape 2 est proposée avec le montant reçu (fenêtre « Convertir »
// pré-remplie, nouveau devis et nouvelle confirmation native). Rien n'est
// bloqué si elle n'est jamais faite : l'intermédiaire reste sur le
// portefeuille de l'utilisateur.

const PENDING_ROUTE_STORAGE_KEY = "pendingSwapRoute";
const ROUTE_POLL_MS = 20000;
const ROUTE_MAX_WAIT_MS = 3 * 60 * 60 * 1000;

const sameSwapAsset = (a, b) => Boolean(a && b) && a.coin === b.coin && a.network === b.network;

// Solde d'une crypto sur un réseau, comme sur sa carte (texte « 0.123 »).
function readAssetBalance(coin, network, address) {
  return usesTokenRegistry(coin, network)
    ? invoke("get_token_balance", { token: coin, network, address })
    : invoke(coin === "usdc" ? "get_usdc_balance" : "get_balance", { network, address });
}

function savePendingRoute(route) {
  pendingRoute = route;
  try {
    if (route) localStorage.setItem(PENDING_ROUTE_STORAGE_KEY, JSON.stringify(route));
    else localStorage.removeItem(PENDING_ROUTE_STORAGE_KEY);
  } catch {
    // localStorage indisponible : suivi pour cette session seulement.
  }
  renderRouteBanner();
  scheduleRoutePoll();
}

// Bandeau du portefeuille : seulement pour le profil (et l'adresse) qui a
// lancé l'échange.
function renderRouteBanner() {
  const banner = document.getElementById("swap-route-banner");
  const route = pendingRoute;
  const active = Boolean(route) && route.profileIndex === currentProfileIndex && route.address === addressForCoin(route.via.coin, route.via.network);
  banner.classList.toggle("hidden", !active);
  if (!active) return;
  const vars = { via: swapShortLabel(route.via), to: swapShortLabel(route.to), amount: route.received };
  const late = !route.received && Date.now() - route.startedAt > ROUTE_MAX_WAIT_MS;
  document.getElementById("swap-route-text").textContent = t(route.received ? "swap.routeReady" : late ? "swap.routeLate" : "swap.routeWaiting", vars);
  document.getElementById("swap-route-continue").classList.toggle("hidden", !route.received);
}

function scheduleRoutePoll() {
  clearTimeout(routePollTimer);
  if (!pendingRoute || pendingRoute.received || Date.now() - pendingRoute.startedAt > ROUTE_MAX_WAIT_MS) return;
  routePollTimer = setTimeout(pollPendingRoute, ROUTE_POLL_MS);
}

async function pollPendingRoute() {
  const route = pendingRoute;
  if (!route || route.received) return;
  try {
    const balance = await readAssetBalance(route.via.coin, route.via.network, route.address);
    if (pendingRoute !== route) return;
    const received = balanceIncrease(route.before, balance);
    if (received) {
      savePendingRoute({ ...route, received });
      showCopyToast(t("swap.routeReadyToast", { via: swapShortLabel(route.via) }), 6000, route.via.coin);
      return;
    }
  } catch (e) {
    console.error(e);
  }
  renderRouteBanner();
  scheduleRoutePoll();
}

document.getElementById("swap-route-continue").addEventListener("click", () => {
  const route = pendingRoute;
  const card = route && document.querySelector(`.wallet-card[data-coin="${route.via.coin}"]`);
  if (!card) return;
  openSwapModal(card, { from: route.via, to: route.to, amount: route.received });
});

document.getElementById("swap-route-abandon").addEventListener("click", () => savePendingRoute(null));

try {
  pendingRoute = JSON.parse(localStorage.getItem(PENDING_ROUTE_STORAGE_KEY) || "null");
} catch {
  pendingRoute = null;
}
scheduleRoutePoll();

// Suivi d'un ordre CoW après l'envoi : son état est relu toutes les 15 s
// jusqu'à son exécution, son expiration (30 min au plus) ou son annulation ;
// lien vers CoW Explorer.
const COW_ORDER_POLL_MS = 15000;
const COW_ORDER_MAX_WAIT_MS = 35 * 60 * 1000;

// Suivi d'un transfert LI.FI : état relu toutes les 15 s jusqu'à son arrivée,
// son échec ou un remboursement (au plus 2 h) ; lien vers LI.FI Scan.
const LIFI_POLL_MS = 15000;
const LIFI_MAX_WAIT_MS = 2 * 60 * 60 * 1000;

function trackLifiTransfer(successEl, transfer) {
  const text = document.createElement("span");
  const setText = (key, vars) => {
    text.textContent = t(key, vars);
  };
  setText("swap.lifiSent", { minutes: Math.max(1, Math.ceil(transfer.duration_secs / 60)) });
  const link = document.createElement("button");
  link.type = "button";
  link.className = "link";
  link.textContent = t("swap.lifiView");
  link.addEventListener("click", () => {
    invoke("open_external_link", { url: transfer.explorer_url }).catch((e) => alert(t("wallet.linkError", { err: e })));
  });
  successEl.replaceChildren(text, " ", link);
  successEl.classList.remove("hidden");

  const started = Date.now();
  const poll = async () => {
    let status;
    try {
      status = await invoke("lifi_status", { txHash: transfer.tx_hash, fromChain: transfer.from_chain, toChain: transfer.to_chain });
    } catch (e) {
      console.error(e);
    }
    const final = {
      "DONE:COMPLETED": "swap.lifiDone",
      "DONE:PARTIAL": "swap.lifiPartial",
      "DONE:REFUNDED": "swap.lifiRefunded",
      FAILED: "swap.lifiFailed",
    }[status] ?? (status?.startsWith("DONE") ? "swap.lifiDone" : null);
    if (final) {
      setText(final);
      refreshAllBalances();
      return;
    }
    if (Date.now() - started > LIFI_MAX_WAIT_MS) {
      setText("swap.lifiUnknown");
      return;
    }
    setTimeout(poll, LIFI_POLL_MS);
  };
  setTimeout(poll, LIFI_POLL_MS);
}

function trackCowOrder(successEl, network, order) {
  const text = document.createElement("span");
  const setText = (key, vars) => {
    text.textContent = t(key, vars);
  };
  setText("swap.cowOrderSent", { minutes: 30 });
  successEl.replaceChildren(text);
  if (order.explorer_url) {
    const link = document.createElement("button");
    link.type = "button";
    link.className = "link";
    link.textContent = t("swap.cowViewOrder");
    link.addEventListener("click", () => {
      invoke("open_external_link", { url: order.explorer_url }).catch((e) => alert(t("wallet.linkError", { err: e })));
    });
    successEl.append(" ", link);
  }
  successEl.classList.remove("hidden");

  const started = Date.now();
  const poll = async () => {
    let status;
    try {
      status = await invoke("cow_order_status", { network, uid: order.uid });
    } catch (e) {
      console.error(e);
    }
    if (status === "fulfilled") {
      setText("swap.cowOrderFilled");
      refreshAllBalances();
      return;
    }
    if (status === "expired" || status === "cancelled") {
      setText(status === "expired" ? "swap.cowOrderExpired" : "swap.cowOrderCancelled");
      return;
    }
    if (Date.now() - started > COW_ORDER_MAX_WAIT_MS) {
      setText("swap.cowOrderUnknown");
      return;
    }
    setTimeout(poll, COW_ORDER_POLL_MS);
  };
  setTimeout(poll, COW_ORDER_POLL_MS);
}

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
  if (isEvmNetwork(network)) return "evm";
  if (network.startsWith("btc")) return "btc";
  if (network.startsWith("sol")) return "sol";
  return null;
}

// Crypto dont le prix valorise un wallet externe : la monnaie du réseau (BNB
// sur BNB Chain…), ou USDC pour « USDC — Solana ».
function externalWalletPriceCoin(network) {
  if (network === "usdc_solana") return "usdc";
  return NATIVE_ASSET_BY_NETWORK[network]?.coin ?? null;
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
  if (key) return t(key);
  // Autres réseaux EVM (Arbitrum, BNB Chain…) : même libellé que sur les cartes.
  return isEvmNetwork(network) ? t(`net.${network}`) : network;
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
  loadExternalChart();
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
  setWithCoinIcon(labelEl, externalWalletPriceCoin(wallet.network), wallet.label);
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
    const fiat = any ? usdToFiat(sum) : null;
    totalEl.textContent = fiat != null ? withCurrency(fiat.toLocaleString(chartLocale(), { minimumFractionDigits: 2, maximumFractionDigits: 2 })) : "—";
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
        const price = priceForCoin(externalWalletPriceCoin(wallet.network));
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
  // Sur place : reconstruire la liste remettait tous les soldes à « — » avant
  // de les relire (tout clignotait et bougeait).
  withThrottledButton(refreshExternalWalletsBtn, REFRESH_COOLDOWN_MS, refreshExternalWalletBalances, { keepLabel: true })
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
  setWithCoinIcon(labelEl, externalWalletPriceCoin(entry.network), entry.label);
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

// Réseaux EVM : tous ceux de l'app (identifiant « eip155:<chainId> »).
function wcChainLabel(chain) {
  const evm = Object.keys(EVM_CHAIN_IDS).find((network) => `eip155:${EVM_CHAIN_IDS[network]}` === chain);
  if (evm === "evm_sepolia") return "Ethereum Sepolia";
  if (evm) return t(`net.${evm}`);
  return (
    {
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

restrictToAmount(document.getElementById("ledger-send-amount"));

function ledgerCoin(network) {
  if (isEvmNetwork(network)) return "evm";
  if (network.startsWith("btc")) return "btc";
  return "sol";
}

// Monnaie du réseau du compte (ETH, BNB, AVAX…).
function ledgerUnit(network) {
  return NATIVE_ASSET_BY_NETWORK[network]?.symbol ?? { evm: "ETH", btc: "BTC", sol: "SOL" }[ledgerCoin(network)];
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
    setWithCoinIcon(labelEl, NATIVE_ASSET_BY_NETWORK[account.network]?.coin, account.label);
    const meta = document.createElement("span");
    meta.className = "recipient-fp";
    const deviceName = account.device === "trezor" ? "Trezor" : "Ledger";
    meta.textContent = `${deviceName} · ${externalNetworkLabel(account.network)} · ${account.address} · m/${account.path}`;
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
    const device = document.getElementById("ledger-add-device").value;
    if (!label) {
      showError(errorEl, t("ledger.labelRequired"));
      return;
    }
    try {
      await invoke("hardware_connect", { device, network, label });
      document.getElementById("ledger-add-modal").classList.add("hidden");
      loadLedgerAccounts();
    } catch (e) {
      showError(errorEl, String(e));
    }
  })
);

async function openLedgerSend(account) {
  ledgerSendAccount = account;
  setWithCoinIcon(document.getElementById("ledger-send-title"), NATIVE_ASSET_BY_NETWORK[account.network]?.coin, t("ledger.sendTitle", { label: account.label }));
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

// --- Courbes : prix, évolution du portefeuille, wallets externes -----------------
// Données calculées côté Rust (core/src/price_history.rs, core/src/portfolio.rs) ;
// tracé par app/src/charts.js. Une vue = un graphique et ses contrôles
// (boutons de période au-dessus, résumé, note), rechargée en gardant l'ancienne
// courbe estompée plutôt qu'un écran vide.

const CHART_RANGES = ["1d", "7d", "30d", "1y", "all"];

function chartLocale() {
  return currentLang === "en" ? "en-US" : "fr-FR";
}

// Symbole de la devise affichée, placé selon la langue : « 12 $ » / « $12 »,
// « 12 € » / « €12 ».
function withCurrency(number) {
  const symbol = displayCurrency === "eur" ? "€" : "$";
  return currentLang === "en" ? `${symbol}${number}` : `${number} ${symbol}`;
}

// Valeur DÉJÀ dans la devise affichée (points de courbe convertis).
function formatFiatValue(value) {
  const maxDigits = Math.abs(value) < 10 ? 4 : 2;
  return withCurrency(value.toLocaleString(chartLocale(), { minimumFractionDigits: 2, maximumFractionDigits: maxDigits }));
}

function formatAxisValue(value, step) {
  if (Math.abs(value) >= 10000) {
    return withCurrency(new Intl.NumberFormat(chartLocale(), { notation: "compact", maximumFractionDigits: 1 }).format(value));
  }
  const digits = step >= 1 ? 0 : Math.min(6, Math.ceil(-Math.log10(step)));
  return withCurrency(value.toLocaleString(chartLocale(), { minimumFractionDigits: digits, maximumFractionDigits: digits }));
}

// Précision des dates selon la durée RÉELLEMENT couverte par les points (une
// courbe de portefeuille peut ne couvrir que quelques jours d'une période de
// 30 jours) : sinon des graduations voisines affichaient la même date.
const DAY_SECONDS = 86400;

function formatChartTime(t, span) {
  const options =
    span <= 1.5 * DAY_SECONDS
      ? { hour: "2-digit", minute: "2-digit" }
      : span <= 6 * DAY_SECONDS
        ? { day: "numeric", month: "short", hour: "2-digit" }
        : span <= 60 * DAY_SECONDS
          ? { day: "numeric", month: "short" }
          : { month: "short", year: "2-digit" };
  return new Date(t * 1000).toLocaleString(chartLocale(), options);
}

function formatChartTooltipTime(t, span) {
  const options =
    span > 60 * DAY_SECONDS ? { day: "numeric", month: "short", year: "numeric" } : { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" };
  return new Date(t * 1000).toLocaleString(chartLocale(), options);
}

function chartSpan(points) {
  return points.length ? points[points.length - 1][0] - points[0][0] : 0;
}

// Valeur actuelle, puis variation sur la période (couleur selon le sens) — ou
// depuis le début des données connues, quand elles ne couvrent pas toute la
// période ; « Tout » : depuis le premier point. En % pour un prix ; en dollars
// (`deltaMode` "usd") pour la valeur d'un portefeuille, que dépôts et retraits
// font varier sans rapport avec une performance (un % depuis un premier dépôt
// de 1 $ affichait « +338 270 % »).
// Variation entre le premier et le dernier point affichés : en % pour un prix,
// en dollars pour un portefeuille ; `null` si elle n'a pas de sens (prix de
// départ nul, moins de deux points).
function chartChange(points, deltaMode) {
  if (points.length < 2) return null;
  const first = points[0][1];
  const last = points[points.length - 1][1];
  if (deltaMode === "usd") return last - first;
  return first > 0 ? ((last - first) / first) * 100 : null;
}

// Sens de la variation : UNE règle pour la flèche et la couleur du résumé ET
// pour la couleur de la courbe (verte en hausse, rouge en baisse). Variation
// qui s'affiche 0 (moins de 0,005 % ou 0,005 $) : ni hausse ni baisse.
function trendOf(change) {
  if (change == null || Math.abs(change) < 0.005) return null;
  return change > 0 ? "up" : "down";
}

function renderChartSummary(el, points, range, since, deltaMode = "pct") {
  el.replaceChildren();
  if (points.length === 0) return;
  if (!since && range === "all") since = points[0][0];
  el.appendChild(document.createTextNode(formatFiatValue(points[points.length - 1][1])));
  const change = chartChange(points, deltaMode);
  if (change == null) return;
  const trend = trendOf(change);
  const delta = document.createElement("span");
  delta.className = `chart-delta ${trend || ""}`.trim();
  const period = since
    ? t("charts.periodSince", { date: new Date(since * 1000).toLocaleDateString(chartLocale()) })
    : t(`charts.period.${range}`);
  const arrow = trend === "up" ? "▲" : trend === "down" ? "▼" : "";
  delta.textContent = (
    deltaMode === "usd"
      ? t("charts.deltaUsd", { arrow, amount: formatFiatValue(Math.abs(change)), period })
      : t("charts.delta", { arrow, pct: Math.abs(change).toLocaleString(chartLocale(), { maximumFractionDigits: 2 }), period })
  ).trim();
  el.appendChild(delta);
}

function mountChart(view) {
  view.rangesEl.replaceChildren(
    ...view.ranges.map((range) => {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.range = range;
      button.textContent = t(`charts.range.${range}`);
      button.addEventListener("click", () => {
        view.range = range;
        refreshChart(view);
      });
      return button;
    })
  );
  return refreshChart(view);
}

// Historique encore en cours de lecture côté Rust (`loading`) : nouvel appel
// peu après, sans estomper la courbe — elle se complète au fur et à mesure.
// Changer de période ou fermer la fenêtre (jeton changé) arrête la suite.
const CHART_POLL_MS = 1500;

async function refreshChart(view, { poll = false } = {}) {
  const token = (view.token = (view.token || 0) + 1);
  view.rangesEl.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.range === view.range)));
  if (!poll) {
    if (!view.chartEl.firstChild) view.chartEl.replaceChildren(mutedParagraph(t("charts.loading")));
    view.chartEl.classList.add("chart-loading");
  }
  try {
    const data = await view.load(view.range);
    if (token !== view.token) return; // une demande plus récente l'emporte
    // En euros : chaque point converti au taux de sa date.
    const points = await toDisplayCurrency(data.points.every((p) => p[1] === 0) ? [] : data.points, view.range);
    if (token !== view.token) return;
    view.points = points;
    renderChartSummary(view.summaryEl, points, view.range, data.since, view.deltaMode);
    renderLineChart(view.chartEl, points, {
      height: view.height,
      formatValue: formatFiatValue,
      formatAxis: formatAxisValue,
      formatTime: formatChartTime,
      formatTooltipTime: formatChartTooltipTime,
      emptyText: data.loading ? t("charts.loading") : t(view.emptyKey),
      ariaLabel: view.title(),
      trend: trendOf(chartChange(points, view.deltaMode)),
    });
    view.noteEl.textContent = [data.note, eurChartNote(points)].filter(Boolean).join(" ");
    if (view.onRender) view.onRender();
    if (data.loading) {
      setTimeout(() => {
        if (token === view.token) refreshChart(view, { poll: true });
      }, CHART_POLL_MS);
    }
  } catch (e) {
    if (token !== view.token) return;
    view.points = [];
    view.chartEl.classList.remove("chart-loading");
    view.chartEl.replaceChildren(mutedParagraph(String(e)));
    view.summaryEl.replaceChildren();
    view.noteEl.textContent = "";
  }
}

// Valeur d'un ensemble d'adresses (portefeuille ou wallets externes).
async function loadHoldingsHistory(holdings, range) {
  if (holdings.length === 0) return { points: [] };
  const result = await invoke("get_portfolio_history", { holdings, range });
  const notes = [];
  if (result.loading) {
    const count = result.transactions_read;
    notes.push(count ? t("charts.loadingHistory", { count: count.toLocaleString(chartLocale()) }) : t("charts.loadingHistoryStart"));
  }
  else if (result.since) notes.push(t("charts.since", { date: new Date(result.since * 1000).toLocaleDateString(chartLocale()) }));
  if (result.approximate && !result.loading) notes.push(t("charts.approximate"));
  // Réseau sans historique public (BNB Chain, HyperEVM) : solde actuel compté
  // sur toute la période (voir core/src/portfolio.rs).
  if (result.constant?.length) notes.push(t("charts.constantBalance", { list: result.constant.join(", ") }));
  return { points: result.points, since: result.since, note: notes.join(" "), loading: result.loading };
}

// Courbes servies par Kraken (absentes de Binance, voir core/src/price_history.rs).
const KRAKEN_CHARTS = ["VVV"];

async function loadPriceChart(symbol, range) {
  const note = t(KRAKEN_CHARTS.includes(symbol) ? "charts.priceSourceKraken" : "charts.priceSource");
  return { points: await invoke("get_price_chart", { symbol, range }), note };
}

// --- Courbe en grand -------------------------------------------------------------

const chartModal = document.getElementById("chart-modal");
const chartModalTable = document.getElementById("chart-modal-table");
const chartModalTableToggle = document.getElementById("chart-modal-table-toggle");
const chartModalView = {
  chartEl: document.getElementById("chart-modal-chart"),
  summaryEl: document.getElementById("chart-modal-summary"),
  noteEl: document.getElementById("chart-modal-note"),
  rangesEl: document.getElementById("chart-modal-ranges"),
  height: 320,
  onRender: () => {
    if (!chartModalTable.classList.contains("hidden")) renderChartTable();
  },
};

// Vue tableau : les mêmes valeurs sans survol (accessibilité).
function renderChartTable() {
  const table = document.createElement("table");
  const head = table.createTHead().insertRow();
  [t("charts.tableDate"), t("charts.tableValue")].forEach((label) => {
    const th = document.createElement("th");
    th.textContent = label;
    head.appendChild(th);
  });
  const body = table.createTBody();
  for (const [time, value] of chartModalView.points || []) {
    const row = body.insertRow();
    row.insertCell().textContent = formatChartTooltipTime(time, chartSpan(chartModalView.points));
    row.insertCell().textContent = formatFiatValue(value);
  }
  chartModalTable.replaceChildren(table);
}

function openChartModal({ title, coin = null, ranges, range, load, emptyKey, deltaMode = "pct" }) {
  const titleEl = document.getElementById("chart-modal-title");
  if (coin) setWithCoinIcon(titleEl, coin, title);
  else titleEl.textContent = title;
  Object.assign(chartModalView, { title: () => title, ranges, range, load, emptyKey, deltaMode, points: [] });
  chartModalView.chartEl.replaceChildren();
  chartModalView.summaryEl.replaceChildren();
  chartModalView.noteEl.textContent = "";
  chartModalTable.classList.add("hidden");
  chartModalTableToggle.textContent = t("charts.showTable");
  chartModal.classList.remove("hidden");
  mountChart(chartModalView);
}

function closeChartModal() {
  chartModal.classList.add("hidden");
  chartModalView.token = (chartModalView.token || 0) + 1; // ignore une réponse tardive
}

document.getElementById("chart-modal-close").addEventListener("click", closeChartModal);
chartModal.addEventListener("click", (e) => {
  if (e.target === chartModal) closeChartModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !chartModal.classList.contains("hidden")) closeChartModal();
});
chartModalTableToggle.addEventListener("click", () => {
  const show = chartModalTable.classList.contains("hidden");
  chartModalTable.classList.toggle("hidden", !show);
  chartModalTableToggle.textContent = t(show ? "charts.hideTable" : "charts.showTable");
  if (show) renderChartTable();
});

// --- Évolution du portefeuille (profil affiché, réseaux principaux) ----------------

// Réseaux de test : fonds sans valeur, hors de la courbe.
const TEST_NETWORKS = ["evm_sepolia", "btc_testnet", "sol_devnet"];

// Chaque crypto affichée, sur chacun de ses réseaux principaux (ETH sur
// Ethereum, Arbitrum et Base ; USDC sur Solana et ses trois réseaux EVM…) :
// la valeur de chaque avoir est reconstruite côté Rust (core/src/portfolio.rs).
function currentProfileHoldings() {
  const holdings = [];
  for (const asset of ASSETS.filter((a) => isAssetVisible(a.coin))) {
    for (const network of asset.networks.filter((n) => !TEST_NETWORKS.includes(n))) {
      const address = addressForCoin(asset.coin, network);
      if (address) holdings.push(asset.token ? { network, address, token: asset.coin } : { network, address });
    }
  }
  return holdings;
}

function sectionView(section, extra) {
  return {
    chartEl: section.querySelector('[data-field="chart"]'),
    summaryEl: section.querySelector('[data-field="summary"]'),
    noteEl: section.querySelector('[data-field="note"]'),
    rangesEl: section.querySelector(".chart-ranges"),
    height: 220,
    range: "30d",
    ranges: ["7d", "30d", "1y", "all"],
    deltaMode: "usd",
    ...extra,
  };
}

const portfolioSection = document.getElementById("portfolio-chart-section");
const portfolioView = sectionView(portfolioSection, {
  title: () => t("charts.portfolioTitle"),
  emptyKey: "charts.portfolioEmpty",
  load: (range) => loadHoldingsHistory(currentProfileHoldings(), range),
});

function loadPortfolioChart() {
  if (portfolioView.rangesEl.childElementCount === 0) mountChart(portfolioView);
  else refreshChart(portfolioView);
}

portfolioSection.querySelector(".chart-expand").addEventListener("click", () =>
  openChartModal({
    title: t("charts.portfolioTitle"),
    ranges: portfolioView.ranges,
    range: portfolioView.range,
    load: portfolioView.load,
    emptyKey: portfolioView.emptyKey,
    deltaMode: portfolioView.deltaMode,
  })
);

// --- Évolution des wallets externes (tous, ou un groupe) -------------------------

const externalChartSection = document.getElementById("external-chart-section");
const externalChartScope = document.getElementById("external-chart-scope");

function externalChartHoldings() {
  const scope = externalChartScope.value || "all";
  return externalWalletsCache
    .filter((w) => scope === "all" || String(w.group_id) === scope)
    .map((w) => ({ network: w.network, address: w.address }));
}

const externalChartView = sectionView(externalChartSection, {
  title: () => t("charts.externalTitle"),
  emptyKey: "charts.externalEmpty",
  load: (range) => loadHoldingsHistory(externalChartHoldings(), range),
});

function renderExternalChartScope() {
  const previous = externalChartScope.value || "all";
  externalChartScope.replaceChildren();
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = t("charts.externalAll");
  externalChartScope.appendChild(all);
  externalGroupsCache.forEach((g) => {
    const option = document.createElement("option");
    option.value = String(g.id);
    option.textContent = g.name;
    externalChartScope.appendChild(option);
  });
  externalChartScope.value = [...externalChartScope.options].some((o) => o.value === previous) ? previous : "all";
  syncCustomSelect(externalChartScope);
}

function loadExternalChart() {
  renderExternalChartScope();
  if (externalChartView.rangesEl.childElementCount === 0) mountChart(externalChartView);
  else refreshChart(externalChartView);
}

externalChartScope.addEventListener("change", () => refreshChart(externalChartView));
externalChartSection.querySelector(".chart-expand").addEventListener("click", () =>
  openChartModal({
    title: t("charts.externalTitle"),
    ranges: externalChartView.ranges,
    range: externalChartView.range,
    load: externalChartView.load,
    emptyKey: externalChartView.emptyKey,
    deltaMode: externalChartView.deltaMode,
  })
);
