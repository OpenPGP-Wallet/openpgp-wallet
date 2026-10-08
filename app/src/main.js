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
  { coin: "zec", name: "Zcash", symbol: "ZEC", family: "zec", icon: "/assets/zec.png", gecko: "zcash", decimals: 8, chart: "ZEC", networks: ["zec_mainnet"] },
  // Fonds Zcash protégés (Orchard, adresse u1) : leur propre carte, à côté de
  // la carte transparente (t1). `nameKey` : nom traduit (voir `assetName`).
  { coin: "zecs", name: "Zcash protégé", nameKey: "coin.zecsName", symbol: "ZEC", family: "zecs", icon: "/assets/zec-shielded.svg", gecko: "zcash", decimals: 8, chart: "ZEC", networks: ["zec_shielded"] },
  { coin: "xmr", name: "Monero", symbol: "XMR", family: "xmr", icon: "/assets/xmr.png", gecko: "monero", decimals: 6, chart: "XMR", networks: ["xmr_mainnet"] },
  { coin: "doge", name: "Dogecoin", symbol: "DOGE", family: "doge", icon: "/assets/doge.png", gecko: "dogecoin", decimals: 8, chart: "DOGE", networks: ["doge_mainnet"] },
  { coin: "trx", name: "Tron", symbol: "TRX", family: "trx", icon: "/assets/trx.png", gecko: "tron", decimals: 6, chart: "TRX", networks: ["tron_mainnet"] },
  { coin: "xrp", name: "XRP", symbol: "XRP", family: "xrp", icon: "/assets/xrp.svg", gecko: "ripple", decimals: 6, chart: "XRP", networks: ["xrp_mainnet"] },
  { coin: "xlm", name: "Stellar", symbol: "XLM", family: "xlm", icon: "/assets/xlm.jpg", iconRound: true, gecko: "stellar", decimals: 7, chart: "XLM", networks: ["xlm_mainnet"] },
  // NEAR : 24 décimales sur la chaîne ; 6 suffisent à la saisie (Max renvoie le montant exact).
  { coin: "near", name: "NEAR", symbol: "NEAR", family: "near", icon: "/assets/near.jpg", iconRound: true, gecko: "near", decimals: 6, chart: "NEAR", networks: ["near_mainnet"] },
  { coin: "ada", name: "Cardano", symbol: "ADA", family: "ada", icon: "/assets/ada.png", gecko: "cardano", decimals: 6, chart: "ADA", networks: ["ada_mainnet"] },
  { coin: "stx", name: "Stacks", symbol: "STX", family: "stx", icon: "/assets/stx.png", gecko: "blockstack", decimals: 6, chart: "STX", networks: ["stx_mainnet"] },
  { coin: "tao", name: "Bittensor", symbol: "TAO", family: "tao", icon: "/assets/tao.jpg", iconRound: true, gecko: "bittensor", decimals: 9, chart: "TAO", networks: ["tao_mainnet"] },
  // Jetons (`token: true`) : contrats et mints relevés dans core/src/tokens.rs —
  // SEUL le registre Rust fait foi pour un envoi (l'interface n'envoie que
  // l'identifiant et le réseau) ; ceux-ci ne servent qu'aux demandes de
  // paiement (QR). Test `frontend_token_contracts_match_the_registry` (lib.rs).
  { coin: "usdt", name: "Tether", symbol: "USDT", token: true, icon: "/assets/usdt.png", gecko: "tether", decimals: 6, unitDecimals: 6, chart: null, networks: ["evm_mainnet", "sol_mainnet", "tron_mainnet"], contracts: { evm_mainnet: "0xdac17f958d2ee523a2206206994597c13d831ec7", sol_mainnet: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", tron_mainnet: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" } },
  { coin: "link", name: "Chainlink", symbol: "LINK", token: true, icon: "/assets/link.png", gecko: "chainlink", decimals: 6, unitDecimals: 18, chart: "LINK", networks: ["evm_mainnet", "arbitrum_mainnet", "base_mainnet"], contracts: { evm_mainnet: "0x514910771af9ca656af840dff83e8264ecf986ca", arbitrum_mainnet: "0xf97f4df75117a78c1a5a0dbb814af92458539fb4", base_mainnet: "0x88fb150bdc53a65fe94dea0c9ba0a6daf8c6e196" } },
  { coin: "dai", name: "Dai", symbol: "DAI", token: true, icon: "/assets/dai.png", gecko: "dai", decimals: 6, unitDecimals: 18, chart: "DAI", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x6b175474e89094c44da98b954eedeac495271d0f" } },
  { coin: "usde", name: "Ethena USDe", symbol: "USDe", token: true, icon: "/assets/usde.png", gecko: "ethena-usde", decimals: 6, unitDecimals: 18, chart: "USDE", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x4c9edd5852cd905f086c759e8383e09bff1e68b3" } },
  { coin: "uni", name: "Uniswap", symbol: "UNI", token: true, icon: "/assets/uni.png", gecko: "uniswap", decimals: 6, unitDecimals: 18, chart: "UNI", networks: ["evm_mainnet", "arbitrum_mainnet"], contracts: { evm_mainnet: "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", arbitrum_mainnet: "0xfa7f8980b0f1e64a2062791cc3b0871572f1f7f0" } },
  { coin: "usdg", name: "Global Dollar", symbol: "USDG", token: true, icon: "/assets/usdg.png", gecko: "global-dollar", decimals: 6, unitDecimals: 6, chart: null, networks: ["evm_mainnet", "arbitrum_mainnet"], contracts: { evm_mainnet: "0xe343167631d89b6ffc58b88d6b7fb0228795491d", arbitrum_mainnet: "0x004b506865409877c9fa29bfb1eba929984b9bbc" } },
  { coin: "xaut", name: "Tether Gold", symbol: "XAUt", token: true, icon: "/assets/xaut.png", gecko: "tether-gold", decimals: 6, unitDecimals: 6, chart: "XAUT", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x68749665ff8d2d112fa859aa293f07a622782f38" } },
  { coin: "ondo", name: "Ondo", symbol: "ONDO", token: true, icon: "/assets/ondo.png", gecko: "ondo-finance", decimals: 6, unitDecimals: 18, chart: "ONDO", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0xfaba6f8e4a5e8ab82f62fe7c39859fa577269be3" } },
  { coin: "qnt", name: "Quant", symbol: "QNT", token: true, icon: "/assets/qnt.jpg", iconRound: true, gecko: "quant-network", decimals: 6, unitDecimals: 18, chart: "QNT", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x4a220e6096b25eadb88358cb44068a3248254675" } },
  { coin: "fet", name: "Fetch.ai (ASI)", symbol: "FET", token: true, icon: "/assets/fet.png", gecko: "fetch-ai", decimals: 6, unitDecimals: 18, chart: "FET", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0xaea46a60368a7bd060eec7df8cba43b7ef41ad85" } },
  { coin: "eurc", name: "EURC", symbol: "EURC", token: true, icon: "/assets/eurc.png", gecko: "euro-coin", decimals: 6, unitDecimals: 6, chart: "EURC", networks: ["evm_mainnet", "base_mainnet", "sol_mainnet"], contracts: { evm_mainnet: "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c", base_mainnet: "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42", sol_mainnet: "HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr" } },
  { coin: "gno", name: "Gnosis", symbol: "GNO", token: true, icon: "/assets/gno.png", gecko: "gnosis", decimals: 6, unitDecimals: 18, chart: "GNO", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0x6810e776880c02933d47db1b9fc05908e5386b96" } },
  { coin: "arb", name: "Arbitrum", symbol: "ARB", token: true, icon: "/assets/arb.jpg", iconRound: true, gecko: "arbitrum", decimals: 6, unitDecimals: 18, chart: "ARB", networks: ["arbitrum_mainnet", "evm_mainnet"], contracts: { arbitrum_mainnet: "0x912ce59144191c1204e64559fe8253a0e49e6548", evm_mainnet: "0xb50721bcf8d664c30412cfbc6cf7a15145234ad1" } },
  { coin: "aster", name: "Aster", symbol: "ASTER", token: true, icon: "/assets/aster.png", gecko: "aster-2", decimals: 6, unitDecimals: 18, chart: "ASTER", networks: ["bsc_mainnet"], contracts: { bsc_mainnet: "0x000ae314e2a2172a039b26378814c252734f556a" } },
  { coin: "vvv", name: "Venice", symbol: "VVV", token: true, icon: "/assets/vvv.png", gecko: "venice-token", decimals: 6, unitDecimals: 18, chart: "VVV", networks: ["base_mainnet"], contracts: { base_mainnet: "0xacfe6019ed1a7dc6f7b508c02d1b04ec88cc21bf" } },
  { coin: "jitosol", name: "Jito Staked SOL", symbol: "JitoSOL", token: true, icon: "/assets/jitosol.png", gecko: "jito-staked-sol", decimals: 6, unitDecimals: 9, chart: "JITOSOL", networks: ["sol_mainnet"], contracts: { sol_mainnet: "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn" } },
  { coin: "steth", name: "Lido Staked ETH", symbol: "stETH", token: true, icon: "/assets/steth.png", gecko: "staked-ether", decimals: 6, unitDecimals: 18, chart: "STETH", networks: ["evm_mainnet"], contracts: { evm_mainnet: "0xae7ab96520de3a18e5e111b5eaab095312d7fe84" } },
  { coin: "render", name: "Render", symbol: "RENDER", token: true, icon: "/assets/render.png", gecko: "render-token", decimals: 6, unitDecimals: 8, chart: "RENDER", networks: ["sol_mainnet"], contracts: { sol_mainnet: "rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof" } },
];
const ASSET_BY_COIN = Object.fromEntries(ASSETS.map((asset) => [asset.coin, asset]));
// Première crypto de chaque identifiant CoinGecko (Zcash, pas Zcash protégé,
// qui a le même cours) : marchés et courbes.
const ASSET_BY_GECKO = Object.fromEntries([...ASSETS].reverse().map((asset) => [asset.gecko, asset]));

// Nom affiché d'une crypto : traduit pour celles qui en ont un (« Zcash
// protégé »), sinon son nom propre. Pas au chargement du module (traductions
// déclarées plus bas) : les éléments créés alors portent `data-i18n`.
function assetName(asset) {
  return asset.nameKey ? t(asset.nameKey) : asset.name;
}
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

// Logo d'un réseau : celui de sa crypto native (Arbitrum : son propre logo ;
// Base et Sepolia : celui d'Ethereum). `null` pour un réseau inconnu.
function coinForNetwork(network) {
  if (network === "arbitrum_mainnet") return "arb";
  return ASSETS.find((asset) => !asset.token && asset.networks.includes(network))?.coin ?? null;
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
      </h2>${asset.coin === "ada" ? `
      <button type="button" class="stake-chip" data-action="stake" data-i18n-title="staking.chipHint" title="Staker : vos cryptos vous rapportent (rendement annuel estimé)"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21v-9" /><path d="M12 12c0-4 3-7 8-7 0 5-3 7-8 7z" /><path d="M12 14c0-3.5-2.5-6-7-6 0 4 2.5 6 7 6z" /></svg><span class="stake-label" data-i18n="staking.action">Staker</span><span class="stake-rate hidden" data-field="stake-rate"></span></button>` : ""}
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
    <p class="fiat-value" data-field="fiat">—</p>${
      asset.coin === "xmr" || asset.coin === "zecs" ? `
    <p class="coin-status muted" data-field="coin-status"></p>` : ""
    }
    <p class="address collapsed-address hidden" data-field="collapsed-address"></p>
    <div class="collapsible-body" id="wallet-body-${asset.coin}">
      <div class="collapsible-inner">
        <div class="address-row">
          <p class="address" data-field="address"></p>
          <div class="address-tools">
            <button class="qr-btn" data-action="copy-address" data-i18n-title="wallet.copyAddress">${ICON_COPY}</button>
            <button class="qr-btn" data-action="qr" data-i18n-title="wallet.showQr">${ICON_QR}</button>
          </div>
          <button class="convert-btn hidden" data-action="swap" data-i18n-title="wallet.convertHint">${ICON_CONVERT}<span data-i18n="wallet.convert">Convertir</span></button>
        </div>
        <div class="row-buttons">
          <button class="secondary" data-action="refresh" data-i18n="wallet.refresh" data-i18n-title="wallet.refresh">Actualiser</button>
          <button class="secondary receive-action" data-action="qr" data-i18n="wallet.receive">Recevoir</button>${
            asset.coin === "zecs"
              ? `
          <button class="secondary" data-action="shield" data-i18n="shielded.shieldAction" data-i18n-title="shielded.shieldTitle">Protéger</button>`
              : ""
          }
          <button class="secondary" data-action="history" data-i18n="wallet.history">Historique</button>
          <button class="primary" data-action="send" data-i18n="wallet.send">Envoyer</button>
        </div>
      </div>
    </div>`;
  card.querySelector(".coin-name").textContent = asset.name;
  if (asset.nameKey) card.querySelector(".coin-name").dataset.i18n = asset.nameKey;
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
  if (asset.nameKey) {
    const label = Object.assign(document.createElement("span"), { textContent: asset.name });
    label.dataset.i18n = asset.nameKey;
    section.querySelector("h2").lastChild.replaceWith(label);
  }
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
  if (coin in assetChoices) return assetChoices[coin];
  // Zcash protégé suit la carte Zcash tant qu'aucun choix n'est fait pour lui.
  if (coin === "zecs") return isAssetVisible("zec");
  return DEFAULT_ASSETS.includes(coin);
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
  // Monero : blocs téléchargés et analysés seulement si sa carte est affichée
  // (ou si des fonds ont déjà été reçus, voir `set_xmr_sync`) — par
  // `window.__TAURI__` : appelée au chargement, avant `invoke` ci-dessous.
  window.__TAURI__.core.invoke("set_xmr_sync", { enabled: isAssetVisible("xmr") }).catch((e) => console.error(e));
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
const VALID_THEMES = ["default", "purple", "orange", "dark", "light"];

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
    // Barre de titre et contour de la fenêtre Windows assortis au thème.
    invoke("set_window_frame", { theme: VALID_THEMES.includes(theme) ? theme : "default" }).catch(() => {});
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
    "errors.network": "Connexion au réseau impossible pour l'instant : vérifiez votre connexion Internet, puis réessayez dans un moment.",
    "errors.rejected": "Le réseau a refusé la demande. Vérifiez le montant et votre solde, puis réessayez ; si cela persiste, réessayez plus tard.",
    "errors.details": "Détail technique : {detail}",
    "common.saveFailed": "Échec de l'enregistrement : {err}",
    "common.error": "Erreur : {err}",
    "common.copyFailed": "Copie impossible : {err}",
    "common.copied": "Copié !",
    "qr.copy": "Copier l'adresse",
    "qr.networkChoose": "Réseau à choisir :",
    "qr.networkWarning": "Depuis une plateforme d'échange, sélectionnez exactement ce réseau pour le retrait. Sur un autre réseau, les fonds peuvent être perdus.",
    "qr.testnetWarning": "Réseau de test : n'envoyez jamais de vrais fonds à cette adresse.",
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
      "Mettez chaque part sur un appareil différent, rangé ailleurs. Deux parts réunies donnent accès à tout le portefeuille. Personne — ni un support, ni l'équipe de l'app — ne vous demandera jamais vos parts ou leurs phrases de passe : quiconque le fait cherche à vous voler.",
    "backup.statusTodo": "À sauvegarder",
    "backup.statusDone": "✓ Sauvegardée",
    "backup.shareDownloaded": "✓ Fichier de part téléchargé",
    "backup.privkeyDownloaded": "✓ Clé de la part téléchargée",
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
    "backup.downloadPrivkey": "Télécharger la clé de cette part",
    "unlock.title": "Portefeuille verrouillé",
    "unlock.biometricButton": "Déverrouiller avec Windows Hello",
    "unlock.orPassword": "ou",
    "unlock.passwordPlaceholder": "Votre mot de passe",
    "unlock.submit": "Déverrouiller",
    "unlock.gotoRestore": "Restaurer depuis une sauvegarde",
    "unlock.resetWallet": "Réinitialiser cet appareil (efface le portefeuille de cet ordinateur)",
    "restore.title": "Restaurer depuis une sauvegarde",
    "restore.subtitle":
      "Branchez 2 de vos 3 clés USB de sauvegarde, ou fournissez 2 fichiers de part avec leur mot de passe, puis choisissez un nouveau mot de passe pour cet appareil.",
    "restore.share1": "Part n°1",
    "restore.share2": "Part n°2",
    "restore.shareFile": "Fichier de part (.asc)",
    "restore.privkeyFile": "Fichier de clé de la part (.asc)",
    "restore.sharePassword": "Mot de passe de cette part",
    "restore.newPasswordLabel": "Nouveau mot de passe pour cet appareil",
    "restore.submit": "Restaurer",
    "restore.filesRequired": "Les 4 fichiers (2 parts et leurs 2 clés) sont requis.",
    "nav.wallet": "Portefeuille",
    "nav.history": "Activité",
    "coinHistory.title": "Historique {name}",
    "wallet.history": "Historique",
    "wallet.xmrSyncing": "Synchronisation Monero en cours…",
    "wallet.xmrLocked": "dont {amount} XMR en attente (10 confirmations, ≈ 20 min)",
    "coin.zecsName": "Zcash protégé",
    "shielded.shieldAction": "Protéger",
    "shielded.shieldTitle": "Protéger mes ZEC",
    "shielded.sendTitle": "Envoyer des ZEC protégés",
    "shielded.shieldHint": "Déplace les ZEC de votre adresse transparente (t1…) vers votre adresse protégée : montants et adresses ne seront plus visibles sur la blockchain. Les ZEC doivent avoir quelques confirmations.",
    "shielded.sendHint": "Depuis vos fonds protégés, vers une adresse u1… (protégée) ou t1… (transparente). Les adresses Sapling seules (zs…) ne sont pas prises en charge.",
    "shielded.password": "Mot de passe",
    "wallet.shieldedSyncing": "Synchronisation des fonds protégés…",
    "wallet.shieldedPending": "dont {amount} ZEC en attente de confirmation",
    "wallet.shieldSuggestion": "Vous avez des ZEC transparents : « Protéger » les déplace ici.",
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
    "external.netEvmMainnet": "Ethereum",
    "external.netEvmSepolia": "Ethereum — Sepolia (réseau de test)",
    "external.netBtcMainnet": "Bitcoin",
    "external.netBtcTestnet": "Bitcoin — réseau de test",
    "external.netSolMainnet": "Solana",
    "external.netSolDevnet": "Solana — réseau de test",
    "external.netUsdcSolana": "USDC — Solana",
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
    "send.pickPlaceholder": "— Carnet d'adresses ou autre profil —",
    "send.pickBook": "Carnet d'adresses",
    "send.pickProfiles": "Mes profils",
    "shielded.pickProfile": "— Vers un autre de vos profils —",
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
    "wallet.totalValue": "Valeur totale",
    "wallet.change24h": "{change} sur 24 h",
    "wallet.receiveEth": "Recevoir ETH",
    "wallet.receiveBtc": "Recevoir BTC",
    "wallet.receiveSol": "Recevoir SOL",
    "wallet.newProfile": "+ Nouveau profil",
    "wallet.archiveProfile": "Archiver ce profil",
    "wallet.cannotArchiveLastProfile": "Impossible d'archiver le dernier profil actif restant.",
    "wallet.archiveConfirm":
      "Archiver le profil \"{label}\" ? Il disparaîtra du sélecteur mais restera récupérable à tout moment depuis Paramètres → Profils archivés.",
    "wallet.mainnet": "Réseau principal",
    "wallet.sepolia": "Sepolia (réseau de test)",
    "wallet.testnet": "Réseau de test",
    "wallet.devnet": "Réseau de test",
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
    "wallet.ethereumMainnet": "Ethereum",
    "wallet.arbitrum": "Arbitrum",
    "wallet.base": "Base",
    "net.bsc_mainnet": "BNB Chain",
    "net.evm_mainnet": "Ethereum",
    "net.arbitrum_mainnet": "Arbitrum",
    "net.base_mainnet": "Base",
    "net.sol_mainnet": "Solana",
    "net.zec_mainnet": "Zcash",
    "net.zec_shielded": "Zcash — Fonds protégés",
    "net.xmr_mainnet": "Monero",
    "net.doge_mainnet": "Dogecoin",
    "net.tron_mainnet": "Tron",
    "net.xrp_mainnet": "XRP Ledger",
    "net.xlm_mainnet": "Stellar",
    "net.near_mainnet": "NEAR",
    "net.ada_mainnet": "Cardano",
    "net.stx_mainnet": "Stacks",
    "net.tao_mainnet": "Bittensor",
    "wallet.historyExplorerOnly": "Pas d'historique ici pour ce réseau : aucun service public gratuit ne le fournit. Il reste consultable sur l'explorateur du réseau.",
    "wallet.historyOpenExplorer": "Voir sur l'explorateur",
    "wallet.historyLimited": "L'historique de ce réseau est momentanément indisponible (trop de demandes). Réessayez plus tard, ou consultez-le sur l'explorateur du réseau.",
    "net.avax_mainnet": "Avalanche",
    "net.polygon_mainnet": "Polygon",
    "wallet.receiveAsset": "Recevoir {symbol}",
    "assets.manage": "Gérer mes cryptos",
    "assets.search": "Rechercher une crypto…",
    "assets.noMatch": "Aucune crypto ne correspond.",
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
    "charts.unavailable": "{list} : données momentanément illisibles, la courbe sera complétée plus tard.",
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
      "Toutes vos transactions, crypto par crypto, sur le réseau choisi dans chaque carte du portefeuille.",
    "history.ethereum": "Ethereum",
    "history.bitcoin": "Bitcoin",
    "history.solana": "Solana",
    "history.kindReceived": "Reçu",
    "history.kindSent": "Envoyé",
    "history.kindSwap": "Swap",
    "history.kindStake": "Staking",
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
    "settings.light": "Blanc",
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
    "settings.affiliateTitle": "Nom d'affiliation (frais des échanges)",
    "settings.affiliateHint":
      "Visible seulement sur le portefeuille qui reçoit les frais d'affiliation de l'app. Un nom court inscrit sur THORChain et Maya permet de prélever les 0,80 % aussi sur les échanges depuis Bitcoin et Zcash. Approvisionnez d'abord chaque adresse (RUNE sur THORChain, CACAO sur Maya), puis inscrivez le nom.",
    "settings.affiliateFree": "« {name} » sur {protocol} : libre",
    "settings.affiliateOurs": "« {name} » sur {protocol} : inscrit à votre nom, encore environ {years} an(s)",
    "settings.affiliateTaken": "« {name} » sur {protocol} : déjà pris par quelqu'un d'autre",
    "settings.affiliateBalance": "Adresse : {address} · solde : {balance} {symbol}",
    "settings.affiliateRegister": "Inscrire « {name} » ({deposit} {symbol} + {fee} de frais)",
    "settings.affiliateRenew": "Prolonger d'un an ({deposit} {symbol} + {fee} de frais)",
    "settings.affiliateCopy": "Copier l'adresse",
    "settings.affiliatePassword": "Mot de passe (pour signer l'inscription)",
    "settings.affiliateCopied": "Adresse copiée",
    "settings.affiliateDone": "Transaction envoyée : {tx}. Le nom apparaît ici en quelques secondes.",
    "settings.rescanTitle": "Réanalyser les fonds privés",
    "settings.rescanHint":
      "Monero et Zcash protégé sont analysés à partir de la création de ce portefeuille sur cet appareil. Si des fonds plus anciens n'apparaissent pas (portefeuille venu d'une autre app), relancez l'analyse depuis le début — elle peut prendre longtemps.",
    "settings.rescanButton": "Réanalyser depuis le début",
    "settings.rescanStarted": "Réanalyse lancée : les soldes Monero et Zcash protégé se mettront à jour au fil de l'analyse.",
    "settings.xmrNodeTitle": "Nœud Monero",
    "settings.xmrNodeHint":
      "L'app lit la chaîne Monero auprès de nœuds publics (Cake Wallet, Stack Wallet…) et analyse les blocs sur cet appareil : le nœud ne sait pas quelles transactions sont les vôtres, mais voit votre adresse IP et les transactions que vous envoyez. Pour plus de confidentialité, indiquez votre propre nœud (https://, ou http:// sur votre réseau local).",
    "settings.xmrNodeLabel": "Adresse du nœud (https://hôte:port)",
    "settings.xmrNodeSave": "Utiliser ce nœud",
    "settings.xmrNodeReset": "Revenir aux nœuds publics",
    "settings.xmrNodeDefault": "Nœuds publics par défaut.",
    "settings.xmrNodeCustom": "Nœud utilisé : {node}",
    "settings.xmrNodeEmpty": "Indiquez d'abord l'adresse du nœud.",
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
    "send.fromShort": "Depuis",
    "send.available": "Disponible : {amount}{approx}",
    "send.mainnetWarning": "⚠ Envoi définitif : une fois partie, une transaction ne peut être ni annulée ni remboursée. Vérifiez bien l'adresse.",
    "send.feeEstimate": "Frais réseau estimés",
    "send.networkNoteBefore": "Cette crypto existe sur plusieurs réseaux : elle partira sur",
    "send.networkNoteAfter": "Pour un dépôt sur une plateforme d'échange, vérifiez que vous y avez choisi ce même réseau.",
    "send.feeEstimateLoading": "calcul…",
    "send.feeUpTo": "jusqu'à {fee}",
    "send.toAddress": "Adresse destinataire",
    "send.destinationTag": "Tag de destination (facultatif)",
    "send.destinationTagHint": "Exigé par les plateformes d'échange : recopiez exactement celui qu'elles indiquent. Sans tag, les fonds peuvent y être perdus.",
    "send.destinationTagNone": "aucun",
    "send.destinationTagShort": "Tag de destination",
    "send.destinationTagInvalid": "Tag de destination : un nombre entier de 0 à 4294967295.",
    "send.memo": "Mémo (facultatif)",
    "send.memoHint": "Exigé par les plateformes d'échange : recopiez exactement celui qu'elles indiquent (chiffres ou texte). Sans mémo, les fonds peuvent y être perdus.",
    "send.memoShort": "Mémo",
    "send.memoInvalid": "Mémo : lettres, chiffres et ponctuation sans accents, longueur limitée.",
    "send.amount": "Montant",
    "send.amountFiat": "Montant dans la devise affichée",
    "send.percentMax": "Max",
    "send.maxHint": "frais déduits",
    "send.maxComputing": "calcul…",
    "send.maxSuffix": " (maximum, frais déduits)",
    "send.maxSuffixToken": " (tout le solde)",
    "countdown.title": "Envoi dans quelques secondes",
    "countdown.text": "Envoi définitif dans {seconds} s — vous pouvez encore l'annuler.",
    "countdown.sendNow": "Confirmer maintenant",
    "countdown.cancel": "Annuler l'envoi",
    "send.percentUnavailable": "Pourcentages indisponibles (solde non chargé).",
    "send.percentZero": "Solde à zéro : rien à envoyer pour l'instant.",
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
    "send.sentFriendly": "Envoi parti ✓ Le réseau le confirme en général en quelques minutes (Bitcoin : jusqu'à une heure) ; votre solde se met à jour tout seul.",
    "send.track": "Suivre la transaction",
    "swap.title": "Échanger",
    "swap.subtitle":
      "L'échange est réalisé par un service externe. Les frais de chaque fournisseur sont indiqués dans la liste, et le montant reçu est déjà calculé frais compris.",
    "swap.fromAsset": "Depuis",
    "swap.toAsset": "Vers",
    "swap.viaJupiter": "via Jupiter, même portefeuille",
    "swap.viaCow": "via CoW, même portefeuille",
    "swap.viaTwoSteps": "en 2 étapes, via {via}",
    "swap.provider": "Fournisseur",
    "swap.providerOption": "{name} — frais {fee}",
    "swap.providerRecommended": "{name} — frais {fee} (recommandé)",
    "swap.providerHalted": "{name} — suspendu en ce moment",
    "swap.alert.unreachable": "{provider} ne répond pas en ce moment : échange impossible par ce fournisseur.",
    "send.checkingRecipient": "Vérification de l'adresse…",
    "swap.maxHint": "Montant maximal, frais de l'échange déduits",
    "staking.action": "Staker",
    "staking.chipHint": "Staker : vos cryptos vous rapportent (rendement annuel estimé)",
    "staking.hint": "Staking liquide : vos cryptos rapportent des récompenses, revendables à tout moment",
    "staking.noteSol": "Gagnez {apr} % par an sur vos SOL avec Jito. Vos JitoSOL restent à vous et se revendent quand vous voulez.",
    "staking.noteEth": "Gagnez {apr} % par an sur vos ETH avec Lido. Vos stETH restent à vous et se revendent quand vous voulez.",
    "staking.unstake": "Retour en {to} immédiat, au prix du marché.",
    "staking.apr": "Gagnez des récompenses sur vos {coin} : elles s'ajoutent toutes seules, revente quand vous voulez.",
    "staking.fee": " Frais : {fee} %.",
    "staking.adaHint": "Staker vos ADA : ils restent à vous et dépensables, les récompenses s'ajoutent",
    "staking.adaTitle": "Staker vos ADA",
    "staking.adaIntro": "Gagnez environ 2 à 3 % par an sur vos ADA. Ils restent dans votre portefeuille, dépensables à tout moment. Dépôt de 2 ADA, rendu à l'arrêt.",
    "staking.adaPool": "Pool",
    "staking.adaPoolOption": "{ticker} — marge {margin} % · {stake} M ADA délégués",
    "staking.adaLoading": "Lecture de votre délégation…",
    "staking.adaNone": "Pas encore staké.",
    "staking.adaStatus": "Staké avec {pool} · récompenses disponibles : {rewards} ADA",
    "staking.adaStatusPending": "Staké avec {pool} · premières récompenses dans 15 à 20 jours",
    "staking.adaDelegate": "Staker",
    "staking.adaChange": "Changer de pool",
    "staking.adaWithdraw": "Retirer les récompenses",
    "staking.adaStop": "Arrêter",
    "staking.adaSent": "Envoyé (transaction {tx}). Visible dans quelques secondes.",
    "staking.solTitle": "Staker vos SOL",
    "staking.solLiquid": "Staking liquide — JitoSOL",
    "staking.solLiquidText": "Vos SOL échangés contre des JitoSOL, qui prennent de la valeur. Revente immédiate quand vous voulez.",
    "staking.solLiquidApr": "Environ {apr} % par an : vos SOL échangés contre des JitoSOL, revendables immédiatement quand vous voulez.",
    "staking.solNative": "Staking natif",
    "staking.solNativeIntro": "Vos SOL délégués à un validateur, sur un compte de mise dont vous êtes la seule autorité. Aucun frais de l'app. Pour récupérer vos SOL : arrêt, puis retrait 2 à 3 jours plus tard.",
    "staking.solValidator": "Validateur",
    "staking.solValidatorOption": "{name} — commission {commission} % · ≈ {apy} % par an",
    "staking.solValidatorOptionNoApy": "{name} — commission {commission} %",
    "staking.solAmount": "Montant à staker",
    "staking.solMin": "Minimum {min} SOL · réserve du compte de mise {reserve} SOL, rendue au retrait",
    "staking.solMaxHint": "Montant maximal : réserve du compte de mise, frais et SOL pour l'arrêt gardés",
    "staking.solDelegate": "Staker",
    "staking.solLoading": "Lecture de vos comptes de mise…",
    "staking.solNone": "Aucun SOL staké en natif pour l'instant.",
    "staking.solTotal": "{amount} SOL stakés en natif",
    "staking.solActivating": "En activation — actif dans {eta} environ",
    "staking.solActive": "Actif — récompenses à chaque époque",
    "staking.solDeactivating": "En arrêt — retirable dans {eta} environ",
    "staking.solInactive": "Arrêté — prêt à être retiré",
    "staking.solUndelegated": "Non délégué",
    "staking.solFlagged": "Validateur signalé depuis (pratiques douteuses) : arrêtez et choisissez-en un autre.",
    "staking.solStop": "Arrêter",
    "staking.solWithdraw": "Retirer",
    "staking.solStakedLine": "+ {amount} SOL stakés",
    "addressBook.networkFirst": "Saisissez d'abord l'adresse",
    "addressBook.networkUnknown": "Adresse non reconnue",
    "send.bookOtherNetwork": "enregistrée pour {network}",
    "swap.alert.halted": "{provider} a suspendu les échanges de {coins} (maintenance ou incident de ce réseau) : échange impossible par ce fournisseur pour l'instant.",
    "swap.alert.slow": "Un de vos échanges via {provider} attend depuis {minutes} min : ce service est lent en ce moment.",
    "swap.previewSwapkitRoute": "Fournisseur (via SwapKit)",
    "swap.swapkitRoute": "{provider} — frais SwapKit {fee} %, ~{minutes} min",
    "swap.swapkit.sent": "Dépôt envoyé ({tx}) — {provider} attend sa confirmation sur le réseau…",
    "swap.swapkit.processing": "Dépôt reçu par {provider} — échange en cours…",
    "swap.swapkit.completed": "Échange terminé par {provider} : les fonds sont arrivés.",
    "swap.swapkit.refunded": "{provider} a remboursé le dépôt sur votre adresse (échange non exécuté).",
    "swap.swapkit.failed": "{provider} signale un échec de l'échange — le remboursement est prévu sur votre adresse.",
    "swap.swapkit.unknown": "Suivi arrêté après 3 h — vérifiez l'arrivée des fonds sur votre carte (dépôt {tx}).",
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
    "swap.balance": "Disponible : {balance}",
    "swap.balanceUnavailable": "Solde indisponible pour le moment.",
    "swap.balanceShort": "montant supérieur au solde",
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
    "swap.viaMoonpay": "via MoonPay Trade",
    "swap.previewMoonpayRoute": "Fournisseur",
    "swap.moonpayRoute": "MoonPay Trade — frais {fee} %, vérifié par simulation",
    "swap.moonpayRouteUnverified": "MoonPay Trade — frais {fee} %, ~{minutes} min. Seul fournisseur pour cette paire : la livraison est gérée par MoonPay Trade, l'app ne peut pas la vérifier.",
    "swap.moonpaySent": "Échange envoyé ({tx}).",
    "swap.moonpayDepositSent": "Dépôt envoyé ({tx}) — MoonPay Trade livre en ~{minutes} min.",
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
    "charts.portfolioScope": "Profil affiché, fonds réels (hors réseaux de test)",
    "charts.externalTitle": "Évolution des wallets externes",
    "charts.externalAll": "Tous les wallets externes",
    "charts.expand": "Agrandir",
    "charts.marketsHint": "Cliquez sur une crypto pour voir sa courbe en grand.",
    "charts.showTable": "Afficher les données",
    "charts.hideTable": "Masquer les données",
    "charts.loading": "Chargement de la courbe…",
    "charts.noData": "Aucune donnée pour cette période.",
    "charts.portfolioEmpty": "Aucun fonds sur ce profil pour le moment. Pour commencer, cliquez sur « Recevoir » : votre adresse s'affiche, à donner à qui vous envoie des cryptos.",
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
    "errors.network": "Can't reach the network right now: check your Internet connection, then try again in a moment.",
    "errors.rejected": "The network refused the request. Check the amount and your balance, then try again; if it persists, try again later.",
    "errors.details": "Technical detail: {detail}",
    "common.saveFailed": "Save failed: {err}",
    "common.error": "Error: {err}",
    "common.copyFailed": "Copy failed: {err}",
    "common.copied": "Copied!",
    "qr.copy": "Copy address",
    "qr.networkChoose": "Network to choose:",
    "qr.networkWarning": "When withdrawing from an exchange, select exactly this network. On another network, the funds can be lost.",
    "qr.testnetWarning": "Test network: never send real funds to this address.",
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
      "Put each share on a different device, kept somewhere else. Two shares together give access to the whole wallet. Nobody — no support, no one from the app — will ever ask for your shares or their passphrases: anyone who does is trying to rob you.",
    "backup.statusTodo": "Not saved yet",
    "backup.statusDone": "✓ Saved",
    "backup.shareDownloaded": "✓ Share file downloaded",
    "backup.privkeyDownloaded": "✓ Share key downloaded",
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
    "backup.downloadPrivkey": "Download this share's key",
    "unlock.title": "Wallet locked",
    "unlock.biometricButton": "Unlock with Windows Hello",
    "unlock.orPassword": "or",
    "unlock.passwordPlaceholder": "Your password",
    "unlock.submit": "Unlock",
    "unlock.gotoRestore": "Restore from a backup",
    "unlock.resetWallet": "Reset this device (erases the wallet from this computer)",
    "restore.title": "Restore from a backup",
    "restore.subtitle":
      "Plug in 2 of your 3 backup USB drives, or provide 2 share files with their password, then choose a new password for this device.",
    "restore.share1": "Share #1",
    "restore.share2": "Share #2",
    "restore.shareFile": "Share file (.asc)",
    "restore.privkeyFile": "Share key file (.asc)",
    "restore.sharePassword": "Password for this share",
    "restore.newPasswordLabel": "New password for this device",
    "restore.submit": "Restore",
    "restore.filesRequired": "The 4 files (2 shares and their 2 keys) are required.",
    "nav.wallet": "Wallet",
    "nav.history": "Activity",
    "coinHistory.title": "{name} history",
    "wallet.history": "History",
    "wallet.xmrSyncing": "Monero sync in progress…",
    "wallet.xmrLocked": "incl. {amount} XMR pending (10 confirmations, ≈ 20 min)",
    "coin.zecsName": "Shielded Zcash",
    "shielded.shieldAction": "Shield",
    "shielded.shieldTitle": "Shield my ZEC",
    "shielded.sendTitle": "Send shielded ZEC",
    "shielded.shieldHint": "Moves the ZEC of your transparent address (t1…) to your shielded address: amounts and addresses will no longer be visible on the blockchain. The ZEC need a few confirmations.",
    "shielded.sendHint": "From your shielded funds, to a u1… (shielded) or t1… (transparent) address. Sapling-only addresses (zs…) are not supported.",
    "shielded.password": "Password",
    "wallet.shieldedSyncing": "Syncing shielded funds…",
    "wallet.shieldedPending": "incl. {amount} ZEC awaiting confirmation",
    "wallet.shieldSuggestion": "You have transparent ZEC: “Shield” moves them here.",
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
    "external.netEvmMainnet": "Ethereum",
    "external.netEvmSepolia": "Ethereum — Sepolia (test network)",
    "external.netBtcMainnet": "Bitcoin",
    "external.netBtcTestnet": "Bitcoin — test network",
    "external.netSolMainnet": "Solana",
    "external.netSolDevnet": "Solana — test network",
    "external.netUsdcSolana": "USDC — Solana",
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
    "send.pickPlaceholder": "— Address book or another profile —",
    "send.pickBook": "Address book",
    "send.pickProfiles": "My profiles",
    "shielded.pickProfile": "— To another of your profiles —",
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
    "wallet.totalValue": "Total value",
    "wallet.change24h": "{change} over 24h",
    "wallet.receiveEth": "Receive ETH",
    "wallet.receiveBtc": "Receive BTC",
    "wallet.receiveSol": "Receive SOL",
    "wallet.newProfile": "+ New profile",
    "wallet.archiveProfile": "Archive this profile",
    "wallet.cannotArchiveLastProfile": "Cannot archive the last remaining active profile.",
    "wallet.archiveConfirm":
      "Archive profile \"{label}\"? It will disappear from the selector but stay recoverable at any time from Settings → Archived profiles.",
    "wallet.mainnet": "Main network",
    "wallet.sepolia": "Sepolia (test network)",
    "wallet.testnet": "Test network",
    "wallet.devnet": "Test network",
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
    "wallet.ethereumMainnet": "Ethereum",
    "wallet.arbitrum": "Arbitrum",
    "wallet.base": "Base",
    "net.bsc_mainnet": "BNB Chain",
    "net.evm_mainnet": "Ethereum",
    "net.arbitrum_mainnet": "Arbitrum",
    "net.base_mainnet": "Base",
    "net.sol_mainnet": "Solana",
    "net.zec_mainnet": "Zcash",
    "net.zec_shielded": "Zcash — Shielded funds",
    "net.xmr_mainnet": "Monero",
    "net.doge_mainnet": "Dogecoin",
    "net.tron_mainnet": "Tron",
    "net.xrp_mainnet": "XRP Ledger",
    "net.xlm_mainnet": "Stellar",
    "net.near_mainnet": "NEAR",
    "net.ada_mainnet": "Cardano",
    "net.stx_mainnet": "Stacks",
    "net.tao_mainnet": "Bittensor",
    "wallet.historyExplorerOnly": "No history here for this network: no free public service provides it. You can still see it on the network's explorer.",
    "wallet.historyOpenExplorer": "View on the explorer",
    "wallet.historyLimited": "This network's history is temporarily unavailable (too many requests). Try again later, or see it on the network's explorer.",
    "net.avax_mainnet": "Avalanche",
    "net.polygon_mainnet": "Polygon",
    "wallet.receiveAsset": "Receive {symbol}",
    "assets.manage": "Manage my cryptos",
    "assets.search": "Search a crypto…",
    "assets.noMatch": "No crypto matches.",
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
    "charts.unavailable": "{list}: data temporarily unreadable, the chart will be completed later.",
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
      "All your transactions, crypto by crypto, on the network chosen in each wallet card.",
    "history.ethereum": "Ethereum",
    "history.bitcoin": "Bitcoin",
    "history.solana": "Solana",
    "history.kindReceived": "Received",
    "history.kindSent": "Sent",
    "history.kindSwap": "Swap",
    "history.kindStake": "Staking",
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
    "settings.light": "White",
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
    "settings.affiliateTitle": "Affiliate name (swap fees)",
    "settings.affiliateHint":
      "Visible only on the wallet that receives the app's affiliate fees. A short name registered on THORChain and Maya lets the app take its 0.80% on swaps from Bitcoin and Zcash too. First fund each address (RUNE on THORChain, CACAO on Maya), then register the name.",
    "settings.affiliateFree": "\"{name}\" on {protocol}: available",
    "settings.affiliateOurs": "\"{name}\" on {protocol}: registered to you, about {years} more year(s)",
    "settings.affiliateTaken": "\"{name}\" on {protocol}: already taken by someone else",
    "settings.affiliateBalance": "Address: {address} · balance: {balance} {symbol}",
    "settings.affiliateRegister": "Register \"{name}\" ({deposit} {symbol} + {fee} fee)",
    "settings.affiliateRenew": "Extend by one year ({deposit} {symbol} + {fee} fee)",
    "settings.affiliateCopy": "Copy address",
    "settings.affiliatePassword": "Password (to sign the registration)",
    "settings.affiliateCopied": "Address copied",
    "settings.affiliateDone": "Transaction sent: {tx}. The name shows here within a few seconds.",
    "settings.rescanTitle": "Rescan private funds",
    "settings.rescanHint":
      "Monero and shielded Zcash are scanned from when this wallet was created on this device. If older funds don't show up (wallet coming from another app), restart the scan from the beginning — it can take a long time.",
    "settings.rescanButton": "Rescan from the beginning",
    "settings.rescanStarted": "Rescan started: Monero and shielded Zcash balances will update as the scan progresses.",
    "settings.xmrNodeTitle": "Monero node",
    "settings.xmrNodeHint":
      "The app reads the Monero chain from public nodes (Cake Wallet, Stack Wallet…) and scans blocks on this device: the node does not know which transactions are yours, but sees your IP address and the transactions you send. For more privacy, set your own node (https://, or http:// on your local network).",
    "settings.xmrNodeLabel": "Node address (https://host:port)",
    "settings.xmrNodeSave": "Use this node",
    "settings.xmrNodeReset": "Back to public nodes",
    "settings.xmrNodeDefault": "Default public nodes.",
    "settings.xmrNodeCustom": "Node in use: {node}",
    "settings.xmrNodeEmpty": "Enter the node address first.",
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
    "send.fromShort": "From",
    "send.available": "Available: {amount}{approx}",
    "send.mainnetWarning": "⚠ Final transfer: once sent, a transaction can neither be cancelled nor refunded. Double-check the address.",
    "send.feeEstimate": "Estimated network fee",
    "send.networkNoteBefore": "This crypto exists on several networks: it will leave on",
    "send.networkNoteAfter": "For a deposit to an exchange, check you chose this same network there.",
    "send.feeEstimateLoading": "calculating…",
    "send.feeUpTo": "up to {fee}",
    "send.toAddress": "Recipient address",
    "send.destinationTag": "Destination tag (optional)",
    "send.destinationTagHint": "Required by exchanges: copy exactly the one they show. Without a tag, funds sent there may be lost.",
    "send.destinationTagNone": "none",
    "send.destinationTagShort": "Destination tag",
    "send.destinationTagInvalid": "Destination tag: a whole number from 0 to 4294967295.",
    "send.memo": "Memo (optional)",
    "send.memoHint": "Required by exchanges: copy exactly the one they show (digits or text). Without a memo, funds sent there may be lost.",
    "send.memoShort": "Memo",
    "send.memoInvalid": "Memo: unaccented letters, digits and punctuation, limited length.",
    "send.amount": "Amount",
    "send.amountFiat": "Amount in the display currency",
    "send.percentMax": "Max",
    "send.maxHint": "fees deducted",
    "send.maxComputing": "computing…",
    "send.maxSuffix": " (maximum, fees deducted)",
    "send.maxSuffixToken": " (whole balance)",
    "countdown.title": "Sending in a few seconds",
    "countdown.text": "Final send in {seconds} s — you can still cancel it.",
    "countdown.sendNow": "Confirm now",
    "countdown.cancel": "Cancel the transfer",
    "send.percentUnavailable": "Percentages unavailable (balance not loaded).",
    "send.percentZero": "Zero balance: nothing to send yet.",
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
    "send.sentFriendly": "Sent ✓ The network usually confirms it within a few minutes (Bitcoin: up to an hour); your balance updates on its own.",
    "send.track": "Track the transaction",
    "swap.title": "Swap",
    "swap.subtitle":
      "The swap is carried out by an external service. Each provider's fees are shown in the list, and the amount received already accounts for them.",
    "swap.fromAsset": "From",
    "swap.toAsset": "To",
    "swap.viaJupiter": "via Jupiter, same wallet",
    "swap.viaCow": "via CoW, same wallet",
    "swap.viaTwoSteps": "in 2 steps, via {via}",
    "swap.provider": "Provider",
    "swap.providerOption": "{name} — {fee} fee",
    "swap.providerRecommended": "{name} — {fee} fee (recommended)",
    "swap.providerHalted": "{name} — paused right now",
    "swap.alert.unreachable": "{provider} is not responding right now: no swap through this provider.",
    "send.checkingRecipient": "Checking the address…",
    "swap.maxHint": "Maximum amount, swap fees deducted",
    "staking.action": "Stake",
    "staking.chipHint": "Stake: your crypto earns rewards (estimated yearly yield)",
    "staking.hint": "Liquid staking: your crypto earns rewards and can be sold back at any time",
    "staking.noteSol": "Earn {apr}% a year on your SOL with Jito. Your JitoSOL stays yours and can be sold back anytime.",
    "staking.noteEth": "Earn {apr}% a year on your ETH with Lido. Your stETH stays yours and can be sold back anytime.",
    "staking.unstake": "Back to {to} instantly, at the market price.",
    "staking.apr": "Earn rewards on your {coin}: they add up on their own, sell back anytime.",
    "staking.fee": " Fee: {fee}%.",
    "staking.adaHint": "Stake your ADA: it stays yours and spendable, rewards add up",
    "staking.adaTitle": "Stake your ADA",
    "staking.adaIntro": "Earn about 2 to 3% a year on your ADA. It stays in your wallet, spendable at any time. 2 ADA deposit, returned when you stop.",
    "staking.adaPool": "Pool",
    "staking.adaPoolOption": "{ticker} — {margin}% margin · {stake}M ADA delegated",
    "staking.adaLoading": "Reading your delegation…",
    "staking.adaNone": "Not staked yet.",
    "staking.adaStatus": "Staked with {pool} · rewards available: {rewards} ADA",
    "staking.adaStatusPending": "Staked with {pool} · first rewards in 15 to 20 days",
    "staking.adaDelegate": "Stake",
    "staking.adaChange": "Change pool",
    "staking.adaWithdraw": "Withdraw rewards",
    "staking.adaStop": "Stop",
    "staking.adaSent": "Sent (transaction {tx}). Visible in a few seconds.",
    "staking.solTitle": "Stake your SOL",
    "staking.solLiquid": "Liquid staking — JitoSOL",
    "staking.solLiquidText": "Your SOL swapped for JitoSOL, which grows in value. Sell back instantly whenever you want.",
    "staking.solLiquidApr": "About {apr}% a year: your SOL swapped for JitoSOL, which you can sell back instantly whenever you want.",
    "staking.solNative": "Native staking",
    "staking.solNativeIntro": "Your SOL delegated to a validator, in a stake account you alone control. No app fee. To get your SOL back: stop, then withdraw 2 to 3 days later.",
    "staking.solValidator": "Validator",
    "staking.solValidatorOption": "{name} — {commission}% commission · ≈ {apy}% a year",
    "staking.solValidatorOptionNoApy": "{name} — {commission}% commission",
    "staking.solAmount": "Amount to stake",
    "staking.solMin": "Minimum {min} SOL · stake account reserve {reserve} SOL, returned on withdrawal",
    "staking.solMaxHint": "Maximum amount: stake account reserve, fee and SOL for stopping kept",
    "staking.solDelegate": "Stake",
    "staking.solLoading": "Reading your stake accounts…",
    "staking.solNone": "No SOL natively staked yet.",
    "staking.solTotal": "{amount} SOL natively staked",
    "staking.solActivating": "Activating — active in about {eta}",
    "staking.solActive": "Active — rewards every epoch",
    "staking.solDeactivating": "Stopping — withdrawable in about {eta}",
    "staking.solInactive": "Stopped — ready to withdraw",
    "staking.solUndelegated": "Not delegated",
    "staking.solFlagged": "Validator flagged since (questionable practices): stop and choose another one.",
    "staking.solStop": "Stop",
    "staking.solWithdraw": "Withdraw",
    "staking.solStakedLine": "+ {amount} SOL staked",
    "addressBook.networkFirst": "Enter the address first",
    "addressBook.networkUnknown": "Address not recognized",
    "send.bookOtherNetwork": "saved for {network}",
    "swap.alert.halted": "{provider} has paused {coins} swaps (network maintenance or incident): no swap through this provider for now.",
    "swap.alert.slow": "One of your swaps through {provider} has been waiting for {minutes} min: this service is slow right now.",
    "swap.previewSwapkitRoute": "Provider (via SwapKit)",
    "swap.swapkitRoute": "{provider} — SwapKit fee {fee}%, ~{minutes} min",
    "swap.swapkit.sent": "Deposit sent ({tx}) — {provider} is waiting for its confirmation on the network…",
    "swap.swapkit.processing": "Deposit received by {provider} — swap in progress…",
    "swap.swapkit.completed": "Swap completed by {provider}: the funds have arrived.",
    "swap.swapkit.refunded": "{provider} refunded the deposit to your address (swap not executed).",
    "swap.swapkit.failed": "{provider} reports the swap failed — a refund to your address is planned.",
    "swap.swapkit.unknown": "Tracking stopped after 3 h — check the funds have arrived on your card (deposit {tx}).",
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
    "swap.balance": "Available: {balance}",
    "swap.balanceUnavailable": "Balance unavailable right now.",
    "swap.balanceShort": "more than your balance",
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
    "swap.viaMoonpay": "via MoonPay Trade",
    "swap.previewMoonpayRoute": "Provider",
    "swap.moonpayRoute": "MoonPay Trade — fee {fee}%, verified by simulation",
    "swap.moonpayRouteUnverified": "MoonPay Trade — fee {fee}%, ~{minutes} min. Only provider for this pair: delivery is handled by MoonPay Trade, the app cannot verify it.",
    "swap.moonpaySent": "Swap sent ({tx}).",
    "swap.moonpayDepositSent": "Deposit sent ({tx}) — MoonPay Trade delivers in ~{minutes} min.",
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
    "charts.portfolioScope": "Displayed profile, real funds (test networks excluded)",
    "charts.externalTitle": "External wallets over time",
    "charts.externalAll": "All external wallets",
    "charts.expand": "Expand",
    "charts.marketsHint": "Click a crypto to see its chart in full size.",
    "charts.showTable": "Show data",
    "charts.hideTable": "Hide data",
    "charts.loading": "Loading chart…",
    "charts.noData": "No data for this period.",
    "charts.portfolioEmpty": "No funds on this profile yet. To get started, click “Receive”: your address appears, to give to whoever sends you crypto.",
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
    renderAffiliateNames();
    renderStakeChips();
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
  let group = null;
  Array.from(select.options).forEach((option) => {
    const parent = option.parentElement;
    if (parent.tagName === "OPTGROUP" && parent !== group) {
      list.appendChild(Object.assign(document.createElement("li"), { className: "custom-select-group", textContent: parent.label }));
    }
    group = parent.tagName === "OPTGROUP" ? parent : null;
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
    if (!li || li.classList.contains("custom-select-group")) return;
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

// Événement de fond (synchronisation, surveillance) arrivé hors du tableau de
// bord — verrouillé, réinitialisé, restauration en cours : rien à relire.
// Constaté le 07/10/2026 : la fin d'une synchronisation Zcash lancée avant
// une réinitialisation relisait encore des soldes.
function dashboardShown() {
  return !views.dashboard.classList.contains("hidden");
}

function showError(el, message) {
  const friendly = friendlyError(String(message));
  if (friendly) {
    const detail = document.createElement("span");
    detail.className = "error-detail";
    detail.textContent = t("errors.details", { detail: String(message) });
    el.replaceChildren(friendly, detail);
  } else {
    el.textContent = message;
  }
  el.classList.remove("hidden");
}

// Erreur technique brute (bibliothèque réseau, nœud) : phrase simple à
// montrer d'abord (`null` : message déjà clair, montré tel quel). Jamais
// pour un envoi « peut-être parti » : ce message-là dit quoi faire (vérifier
// l'historique avant de renvoyer) et doit rester intact.
function friendlyError(message) {
  if (/peut-être partie|may have been sent|vérifiez l'historique|check the history/i.test(message)) return null;
  if (/error sending request|timed out|operation timed out|connection (refused|reset|closed)|dns error|tcp connect|failed to lookup|network is unreachable|connexion impossible/i.test(message)) {
    return t("errors.network");
  }
  if (/erreur RPC|RPC error|"code"\s*:\s*-?\d+|InvalidFEOpcode|execution reverted/i.test(message)) return t("errors.rejected");
  return null;
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
const resetWalletBtn = document.getElementById("reset-wallet");
resetWalletBtn.addEventListener("click", withBusyButton(resetWalletBtn, async () => {
  try {
    await invoke("reset_wallet");
    profilesCache = [];
    currentProfileIndex = 0;
    writePendingSwaps([]);
    showView("onboarding");
  } catch (e) {
    showError(document.getElementById("unlock-error"), String(e));
  }
}));

const resetWalletDashboardBtn = document.getElementById("reset-wallet-dashboard");
resetWalletDashboardBtn.addEventListener("click", withBusyButton(resetWalletDashboardBtn, async () => {
  try {
    await invoke("reset_wallet");
    profilesCache = [];
    currentProfileIndex = 0;
    writePendingSwaps([]);
    stopBalanceAutoRefresh();
    stopBalanceWatch();
    showView("onboarding");
  } catch (e) {
    alert(t("common.error", { err: e }));
  }
}));

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

// --- Nom d'affiliation (portefeuille du développeur seulement) -----------------
// Rust ne renvoie rien (null) pour un autre portefeuille : la section reste
// cachée. L'inscription passe par une boîte de confirmation native, construite
// côté Rust à partir de l'état relu sur le réseau.

let affiliateNames = null;

function renderAffiliateNames() {
  const section = document.getElementById("affiliate-names-section");
  section.classList.toggle("hidden", !affiliateNames);
  if (!affiliateNames) return;
  const list = document.getElementById("affiliate-names-list");
  list.replaceChildren(
    ...affiliateNames.map((item) => {
      const row = document.createElement("div");
      row.className = "affiliate-name";
      const years = item.years_left == null ? "" : item.years_left.toLocaleString(chartLocale(), { maximumFractionDigits: 1 });
      const stateKey = { free: "settings.affiliateFree", ours: "settings.affiliateOurs", taken: "settings.affiliateTaken" }[item.state];
      const title = document.createElement("p");
      title.className = "affiliate-name-state";
      title.textContent = t(stateKey, { name: item.name, protocol: item.protocol, years });
      const balance = mutedParagraph(t("settings.affiliateBalance", { address: item.address, balance: item.balance, symbol: item.symbol }));
      balance.classList.add("mono");
      const actions = document.createElement("div");
      actions.className = "affiliate-name-actions";
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "link";
      copy.textContent = t("settings.affiliateCopy");
      copy.addEventListener("click", () => copyText(item.address, t("settings.affiliateCopied")));
      actions.append(copy);
      if (item.state !== "taken") {
        const register = document.createElement("button");
        register.type = "button";
        register.className = "secondary";
        const vars = { name: item.name, deposit: item.deposit, symbol: item.symbol, fee: item.network_fee };
        register.textContent = t(item.state === "free" ? "settings.affiliateRegister" : "settings.affiliateRenew", vars);
        register.addEventListener("click", withBusyButton(register, () => registerAffiliateName(item.chain)));
        actions.prepend(register);
      }
      row.append(title, balance, actions);
      return row;
    })
  );
}

function loadAffiliateNames() {
  invoke("affiliate_names_status")
    .then((names) => {
      affiliateNames = names;
      renderAffiliateNames();
    })
    .catch((e) => {
      console.error(e);
      showError(document.getElementById("affiliate-names-error"), String(e));
    });
}

async function registerAffiliateName(chain) {
  const errorEl = document.getElementById("affiliate-names-error");
  const successEl = document.getElementById("affiliate-names-success");
  hideError(errorEl);
  successEl.classList.add("hidden");
  const passwordEl = document.getElementById("affiliate-password");
  if (!passwordEl.value) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }
  try {
    const tx = await invoke("register_affiliate_name", { password: passwordEl.value, chain });
    successEl.textContent = t("settings.affiliateDone", { tx });
    successEl.classList.remove("hidden");
    setTimeout(loadAffiliateNames, 8000);
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    passwordEl.value = "";
  }
}

// --- Nœud Monero ----------------------------------------------------------------
// Nœuds publics par défaut ; l'utilisateur peut indiquer le sien (validé et
// gardé côté Rust, core/src/monero.rs).

function renderXmrNode(node) {
  document.getElementById("xmr-node-status").textContent = node ? t("settings.xmrNodeCustom", { node }) : t("settings.xmrNodeDefault");
  document.getElementById("xmr-node-reset").classList.toggle("hidden", !node);
}

function loadXmrNode() {
  invoke("xmr_node")
    .then(renderXmrNode)
    .catch((e) => console.error(e));
}

async function saveXmrNode(url) {
  const errorEl = document.getElementById("xmr-node-error");
  hideError(errorEl);
  try {
    renderXmrNode(await invoke("set_xmr_node", { url }));
    document.getElementById("xmr-node-input").value = "";
  } catch (e) {
    showError(errorEl, String(e));
  }
}

const xmrNodeSaveBtn = document.getElementById("xmr-node-save");
xmrNodeSaveBtn.addEventListener("click", withBusyButton(xmrNodeSaveBtn, async () => {
  const url = document.getElementById("xmr-node-input").value.trim();
  if (!url) {
    showError(document.getElementById("xmr-node-error"), t("settings.xmrNodeEmpty"));
    return;
  }
  await saveXmrNode(url);
}));

// Réanalyse complète des fonds privés (Monero, Zcash protégé) : soldes mis à
// jour au fil de la synchronisation de fond.
const rescanPrivateBtn = document.getElementById("rescan-private-funds");
rescanPrivateBtn.addEventListener("click", withBusyButton(rescanPrivateBtn, async () => {
  const status = document.getElementById("rescan-private-status");
  const errorEl = document.getElementById("rescan-private-error");
  status.classList.add("hidden");
  hideError(errorEl);
  try {
    await invoke("rescan_private_funds");
    status.textContent = t("settings.rescanStarted");
    status.classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

const xmrNodeResetBtn = document.getElementById("xmr-node-reset");
xmrNodeResetBtn.addEventListener("click", withBusyButton(xmrNodeResetBtn, () => saveXmrNode("")));

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
  if (coinHistoryOpen()) closeCoinHistory();
  // Côté Rust : clés de visualisation et adresses mémorisées oubliées.
  invoke("lock_session").catch((e) => console.error(e));
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

// Navigation en barre latérale (voir styles.css, « Barre latérale ») : plus
// rien à mesurer ni à replier selon la largeur. Gardée (aussi appelée par
// `applyLanguage`, plus haut) pour la hauteur réservée en haut de page, nulle
// avec une barre sur le côté.
function fitNavbar() {
  document.documentElement.style.setProperty("--navbar-height", "0px");
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
      loadXmrNode();
      loadAffiliateNames();
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
    writePendingSwaps([]);
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
    writePendingSwaps([]);
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
  loadStakingAprs();
  // Toujours précédé d'une relecture complète (déverrouillage, création,
  // restauration) : le rattrapage au focus n'a pas à la refaire.
  lastAutoBalances = Date.now();
  balanceRefreshTimer = setInterval(autoRefreshBalances, BALANCE_REFRESH_MS);
  startPriceAutoRefresh();
}

// Fenêtre réduite : ni soldes ni cours relus (une vingtaine d'appels par
// minute aux nœuds publics, pour un écran que personne ne regarde). Les
// réceptions restent signalées par la surveillance en direct (Rust) ; tout
// est relu dès que la fenêtre reprend le focus. `document.hidden` reste faux
// dans WebView2 fenêtre réduite (constaté le 06/10/2026) : Tauri répond.
const BALANCE_REFRESH_MS = 60000;
const PRICE_REFRESH_MS = 30000;
let lastAutoBalances = 0;
let lastAutoPrices = 0;

async function windowMinimized() {
  try {
    return await window.__TAURI__.window.getCurrentWindow().isMinimized();
  } catch (e) {
    return false;
  }
}

// Relu il y a moins d'une demi-période (rattrapage au retour du focus) :
// ce tick attend le suivant.
async function autoRefreshBalances() {
  if (Date.now() - lastAutoBalances < BALANCE_REFRESH_MS / 2 || (await windowMinimized())) return;
  lastAutoBalances = Date.now();
  refreshAllBalances();
}

async function autoRefreshPrices() {
  if (Date.now() - lastAutoPrices < PRICE_REFRESH_MS / 2 || (await windowMinimized())) return;
  lastAutoPrices = Date.now();
  refreshPrices();
}

try {
  // Focus rendu : relecture directe — `isMinimized` répond encore « vrai »
  // à cet instant (constaté le 06/10/2026), l'interroger ici l'annulerait.
  window.__TAURI__.window.getCurrentWindow().onFocusChanged(({ payload: focused }) => {
    if (!focused) return;
    if (balanceRefreshTimer && Date.now() - lastAutoBalances > BALANCE_REFRESH_MS) {
      lastAutoBalances = Date.now();
      refreshAllBalances();
    }
    if (priceRefreshTimer && Date.now() - lastAutoPrices > PRICE_REFRESH_MS) {
      lastAutoPrices = Date.now();
      refreshPrices();
    }
  }).catch((e) => console.error(e));
} catch (e) {
  console.error(e);
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
    renderSendAvailable();
  }
  if (!swapModal.classList.contains("hidden")) renderSwapAmount();
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

// --- Valeur totale (en-tête du tableau de bord) -----------------------------
// Somme des cartes affichées sur un réseau principal (solde × cours, comme leur
// valeur en devise : fonds de test exclus) et variation sur 24 h pondérée par
// la valeur de chaque crypto (variations de la liste des marchés).
function marketChange24h(coin) {
  const gecko = ASSET_BY_COIN[coin]?.gecko;
  const market = gecko && lastMarketCoins ? lastMarketCoins.find((c) => c.id === gecko) : null;
  return market && Number.isFinite(market.change_24h_percent) ? market.change_24h_percent : null;
}

// SOL stakés du profil affiché, liés à son adresse (`balanceKey`) : comptés
// dans la valeur de la carte SOL et dans la valeur totale. Relus toutes les
// 5 min au plus (les récompenses tombent tous les 2 jours), et aussitôt
// après une opération.
let solStaked = { key: "", lamports: 0, at: 0 };
const SOL_STAKED_TTL_MS = 5 * 60 * 1000;

// Solde affiché d'une carte (valeur en devise, valeur totale), SOL stakés
// compris (staking natif : ils ont quitté l'adresse mais restent à vous).
function cardTotalBalance(card) {
  return Number.parseFloat(card.querySelector('[data-field="balance"]').textContent) + solStakedFor(card);
}

function updatePortfolioTotal() {
  const totalEl = document.getElementById("portfolio-total");
  const changeEl = document.getElementById("portfolio-change");
  if (!totalEl) return;
  let usd = 0;
  let weighted = 0;
  let weight = 0;
  let known = false;
  document.querySelectorAll(".wallet-card:not(.asset-hidden)").forEach((card) => {
    if (!networkForCard(card).endsWith("mainnet")) return;
    const balance = cardTotalBalance(card);
    const price = priceForCoin(card.dataset.coin);
    if (!Number.isFinite(balance) || price == null) return;
    known = true;
    const value = balance * price;
    usd += value;
    const change = marketChange24h(card.dataset.coin);
    if (change != null && value > 0) {
      weighted += value * change;
      weight += value;
    }
  });
  const fiat = known ? usdToFiat(usd) : null;
  const text = fiat == null ? "—" : withCurrency(fiat.toLocaleString(chartLocale(), { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
  if (totalEl.textContent !== text) totalEl.textContent = text;
  // Variation : seulement avec des fonds (pondérée par leur valeur).
  const change = weight > 0 ? weighted / weight : null;
  changeEl.classList.toggle("up", change != null && change > 0);
  changeEl.classList.toggle("down", change != null && change < 0);
  if (change == null) {
    changeEl.textContent = "";
    return;
  }
  const shown = `${change > 0 ? "▲" : change < 0 ? "▼" : ""} ${Math.abs(change).toLocaleString(chartLocale(), { minimumFractionDigits: 2, maximumFractionDigits: 2 })}${currentLang === "en" ? "%" : "\u00a0%"}`.trim();
  changeEl.textContent = t("wallet.change24h", { change: shown });
}

function updateFiatValue(card) {
  updatePortfolioTotal();
  const fiatEl = card.querySelector('[data-field="fiat"]');
  if (!fiatEl) return;
  const price = priceForCoin(card.dataset.coin);
  const balance = cardTotalBalance(card);
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
      renderSendAvailable();
    }
    if (!swapModal.classList.contains("hidden")) renderSwapAmount();
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
  lastAutoPrices = Date.now();
  refreshPrices();
  priceRefreshTimer = setInterval(autoRefreshPrices, PRICE_REFRESH_MS);
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
  return addressOfProfile(currentProfile(), coin, network);
}

// Adresse de `profile` pour une crypto et un réseau (celle de sa carte).
function addressOfProfile(profile, coin, network) {
  // `addresses` est absent quand le profil a été créé sans mot de passe (voir
  // add-profile-confirm) : l'adresse n'est pas encore dérivée, elle apparaîtra
  // au prochain déverrouillage complet (voir core/src/api.rs::create_profile).
  if (!profile || !profile.addresses) return "";
  // Même adresse sur tous les réseaux EVM (Ethereum, L2, BNB Chain…), jetons
  // compris.
  if (isEvmNetwork(network)) return profile.addresses.evm;
  // Tron : TRX et jetons TRC-20 (USDT) à la même adresse T….
  if (network === "tron_mainnet") return profile.addresses.tron ?? "";
  if (coin === "btc") return network === "btc_mainnet" ? profile.addresses.btc_mainnet : profile.addresses.btc_testnet;
  // Zcash transparent (t1…) ; absente d'un profil dérivé avant son ajout,
  // jusqu'au prochain déverrouillage.
  if (coin === "zec") return profile.addresses.zcash ?? "";
  // Monero : adresse principale (4…) ; absente d'un profil dérivé avant son
  // ajout, jusqu'au prochain déverrouillage.
  if (coin === "xmr") return profile.addresses.monero ?? "";
  // Dogecoin (D…) ; absente d'un profil dérivé avant son ajout, jusqu'au
  // prochain déverrouillage.
  if (coin === "doge") return profile.addresses.doge ?? "";
  // Tron (T…) ; absente d'un profil dérivé avant son ajout.
  if (coin === "trx") return profile.addresses.tron ?? "";
  // XRP (r…) ; absente d'un profil dérivé avant son ajout.
  if (coin === "xrp") return profile.addresses.xrp ?? "";
  // Stellar (G…) ; absente d'un profil dérivé avant son ajout.
  if (coin === "xlm") return profile.addresses.stellar ?? "";
  // NEAR : compte implicite (64 hex) ; absent d'un profil dérivé avant son ajout.
  if (coin === "near") return profile.addresses.near ?? "";
  // Cardano : adresse de base (addr1…) ; absente d'un profil dérivé avant son ajout.
  if (coin === "ada") return profile.addresses.cardano ?? "";
  // Stacks (SP…) ; absente d'un profil dérivé avant son ajout.
  if (coin === "stx") return profile.addresses.stacks ?? "";
  // Bittensor (5…, SS58) ; absente d'un profil dérivé avant son ajout.
  if (coin === "tao") return profile.addresses.bittensor ?? "";
  // Zcash protégé : adresse u1 (récepteur Orchard seul).
  if (coin === "zecs") return profile.addresses.zcash_shielded ?? "";
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
  // Adresse très longue (u1…, Monero) : début et fin seulement sur la carte ;
  // en entier dans l'infobulle, la fenêtre QR et la copie.
  const shown = address.length > 64 ? `${address.slice(0, 14)}…${address.slice(-12)}` : address;
  // Copie affichée par le bouton « adresse » d'une carte repliée.
  for (const field of ["address", "collapsed-address"]) {
    const el = card.querySelector(`[data-field="${field}"]`);
    el.textContent = shown;
    el.title = address.length > 64 ? address : "";
  }
  updateConvertButton(card);
}

// « Convertir » seulement là où un échange existe pour la crypto ET le réseau
// affichés (voir `swapPairs`) : pas sur un réseau de test, ni là où il
// échangerait les fonds d'un autre réseau que celui affiché.
// Staking liquide : jeton reçu pour la monnaie de chaque réseau concerné.
const LIQUID_STAKING = { sol_mainnet: { from: "sol", to: "jitosol" }, evm_mainnet: { from: "evm", to: "steth" } };

function liquidStakingFor(coin, network) {
  const target = LIQUID_STAKING[network];
  return target && target.from === coin && swapPairs.some((p) => p.from_coin === coin && p.from_network === network && p.to_coin === target.to) ? target : null;
}

// Staking liquide : échange vers le jeton de staking dans « Convertir ».
function openLiquidStaking(card) {
  const network = networkForCard(card);
  const target = liquidStakingFor(card.dataset.coin, network);
  if (!target) return;
  // Carte du jeton de staking affichée : le solde reçu s'y verra.
  assetChoices[target.to] = true;
  saveAssetChoices();
  applyAssetVisibility();
  openSwapModal(card, { from: { coin: target.from, network }, to: { coin: target.to, network } });
}

function updateConvertButton(card) {
  // Cardano (délégation) et Solana (staking natif) : toujours ; ailleurs,
  // seulement si le staking liquide est possible.
  const native = card.dataset.coin === "ada" || (card.dataset.coin === "sol" && networkForCard(card) === "sol_mainnet");
  card.querySelector('[data-action="stake"]')?.classList.toggle("hidden", !native && !liquidStakingFor(card.dataset.coin, networkForCard(card)));
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

// Solde de `coin` sur `network` à `address`, tel que Rust le formate
// (« 0.500000 », sans symbole). USDC est un jeton SPL, pas un "réseau" au sens
// où get_balance l'entend (pas de notion de décimales/mint par actif dans
// cette commande) : une commande dédiée, voir core/src/api.rs::get_usdc_balance.
function fetchBalance(coin, network, address) {
  return usesTokenRegistry(coin, network)
    ? invoke("get_token_balance", { token: coin, network, address })
    : invoke(coin === "usdc" ? "get_usdc_balance" : "get_balance", { network, address });
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
    // actualisation périodique faisait clignoter tous les soldes et, en
    // vue liste, bouger toutes les lignes (colonne ajustée à « … »). Autre
    // réseau ou autre profil : l'ancien solde ne vaut plus rien.
    const shown = card.dataset.balanceKey === key;
    if (!shown) balanceEl.textContent = "…";
    // Le solde et l'indicateur "transaction en attente" sont deux appels
    // indépendants (l'un ne dépend pas du résultat de l'autre) : les lancer en
    // parallèle plutôt que l'un après l'autre coupe la latence perçue du
    // rafraîchissement en deux.
    const balancePromise = fetchBalance(coin, network, address)
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
    const statusPromise = coin === "zecs" ? refreshShieldedStatus(card) : coin === "xmr" ? refreshXmrStatus(card) : coin === "sol" ? refreshSolStaked(card) : Promise.resolve();
    await Promise.all([balancePromise, pendingPromise, statusPromise]);
    updateFiatValue(card);
  } finally {
    card.dataset.refreshing = "";
  }
  // Réseau ou profil changé pendant la lecture (ignorée), ou changement
  // signalé entre-temps : relire.
  if (balanceKey(card) !== key || card.dataset.refreshAgain === "1") refreshBalance(card);
}

// --- Monero --------------------------------------------------------------------
// Solde tenu par la synchronisation de fond côté Rust (blocs analysés avec la
// clé de visualisation, voir core/src/monero.rs) : la carte relit l'état local
// après chaque passage, et montre la part encore bloquée (10 confirmations).

async function refreshXmrStatus(card) {
  const statusEl = card.querySelector('[data-field="coin-status"]');
  if (!statusEl) return;
  try {
    const status = await invoke("xmr_status", { profileIndex: currentProfileIndex });
    statusEl.textContent = !status.synced
      ? t("wallet.xmrSyncing")
      : Number.parseFloat(status.locked) > 0
        ? t("wallet.xmrLocked", { amount: status.locked })
        : "";
  } catch (e) {
    console.error(e);
    statusEl.textContent = "";
  }
}

window.__TAURI__.event.listen("xmr-synced", () => {
  const card = document.querySelector('.wallet-card[data-coin="xmr"]');
  if (card && dashboardShown()) refreshBalance(card);
}).catch((e) => console.error(e));

// --- Zcash protégé ------------------------------------------------------------
// Carte à part (adresse u1, récepteur Orchard seul) : solde et historique lus
// côté Rust dans la base locale que la synchronisation de fond met à jour.
// Sa ligne d'état dit si la synchronisation est en cours, ce qui attend une
// confirmation, ou invite à protéger les ZEC de la carte transparente.

async function refreshShieldedStatus(card) {
  const statusEl = card.querySelector('[data-field="coin-status"]');
  try {
    const status = await invoke("zec_shielded_balance", { profileIndex: currentProfileIndex });
    const transparent = Number.parseFloat(document.querySelector('.wallet-card[data-coin="zec"] [data-field="balance"]')?.textContent);
    statusEl.textContent = !status.synced
      ? t("wallet.shieldedSyncing")
      : Number.parseFloat(status.pending) > 0
        ? t("wallet.shieldedPending", { amount: status.pending })
        : transparent > 0
          ? t("wallet.shieldSuggestion")
          : "";
  } catch (e) {
    console.error(e);
    statusEl.textContent = "";
  }
}

function refreshZcashCards() {
  for (const coin of ["zec", "zecs"]) {
    const card = document.querySelector(`.wallet-card[data-coin="${coin}"]`);
    if (card) refreshBalance(card);
  }
}

// Fenêtre des dépenses protégées : « shield » (mot de passe seul) ou « send »
// (destinataire, montant). La boîte de confirmation native, construite côté
// Rust à partir de la transaction proposée, montre montant et frais.
let shieldedMode = "send";

// Autres profils proposés comme destinataires (leur adresse protégée u1),
// comme sous le carnet d'adresses de l'envoi ordinaire ; la boîte native nomme
// le profil reconnu d'après les adresses dérivées côté Rust.
function refreshShieldedPicker() {
  const wrapper = document.getElementById("shielded-picker");
  const select = document.getElementById("shielded-picker-select");
  const profiles = profilesCache
    .filter((profile) => profile.index !== currentProfileIndex)
    .map((profile) => ({ profile, address: addressOfProfile(profile, "zecs", "zec_shielded") }))
    .filter(({ address }) => address);
  select.replaceChildren(Object.assign(document.createElement("option"), { value: "", textContent: t("shielded.pickProfile") }));
  if (profiles.length) {
    const optgroup = Object.assign(document.createElement("optgroup"), { label: t("send.pickProfiles") });
    optgroup.append(
      ...profiles.map(({ profile, address }) =>
        Object.assign(document.createElement("option"), { value: String(profile.index), textContent: `${profile.label} — ${address.slice(0, 10)}…${address.slice(-8)}` })
      )
    );
    select.appendChild(optgroup);
  }
  syncCustomSelect(select);
  wrapper.classList.toggle("hidden", profiles.length === 0);
}

document.getElementById("shielded-picker-select").addEventListener("change", (e) => {
  const profile = profilesCache.find((p) => String(p.index) === e.target.value);
  const address = addressOfProfile(profile, "zecs", "zec_shielded");
  if (address) document.getElementById("shielded-to").value = address;
  e.target.value = "";
  syncCustomSelect(e.target);
});

function openShieldedModal(mode) {
  shieldedMode = mode;
  const title = document.getElementById("shielded-modal-title");
  title.dataset.i18n = mode === "shield" ? "shielded.shieldTitle" : "shielded.sendTitle";
  title.textContent = t(title.dataset.i18n);
  document.getElementById("shielded-modal-hint").textContent = t(mode === "shield" ? "shielded.shieldHint" : "shielded.sendHint");
  document.getElementById("shielded-send-fields").classList.toggle("hidden", mode === "shield");
  for (const id of ["shielded-to", "shielded-amount", "shielded-password"]) document.getElementById(id).value = "";
  shieldedMax = false;
  if (mode === "send") refreshShieldedPicker();
  hideError(document.getElementById("shielded-error"));
  document.getElementById("shielded-success").classList.add("hidden");
  document.getElementById("shielded-modal").classList.remove("hidden");
}

document.getElementById("shielded-cancel").addEventListener("click", () => {
  document.getElementById("shielded-modal").classList.add("hidden");
  document.getElementById("shielded-password").value = "";
});

restrictToAmount(document.getElementById("shielded-amount"));
// « Max » : tous les fonds protégés dépensables, frais déduits (proposition de
// la bibliothèque Zcash), recalculé à l'envoi.
let shieldedMax = false;
document.getElementById("shielded-amount").addEventListener("input", () => {
  shieldedMax = false;
});
const shieldedMaxBtn = document.getElementById("shielded-max");
shieldedMaxBtn.addEventListener("click", withBusyButton(shieldedMaxBtn, async () => {
  const errorEl = document.getElementById("shielded-error");
  hideError(errorEl);
  try {
    document.getElementById("shielded-amount").value = await invoke("max_send_amount", { network: "zec_shielded", token: null, profileIndex: currentProfileIndex, feeSat: null });
    shieldedMax = true;
  } catch (e) {
    showError(errorEl, String(e));
  }
}));

const shieldedConfirmBtn = document.getElementById("shielded-confirm");
shieldedConfirmBtn.addEventListener("click", withBusyButton(shieldedConfirmBtn, async () => {
  const errorEl = document.getElementById("shielded-error");
  const successEl = document.getElementById("shielded-success");
  hideError(errorEl);
  successEl.classList.add("hidden");
  const passwordEl = document.getElementById("shielded-password");
  if (!passwordEl.value) {
    showError(errorEl, t("common.passwordRequired"));
    return;
  }
  try {
    const txid = shieldedMode === "shield"
      ? await invoke("zec_shield", { password: passwordEl.value, profileIndex: currentProfileIndex })
      : await invoke("zec_send_shielded", {
          password: passwordEl.value,
          profileIndex: currentProfileIndex,
          to: document.getElementById("shielded-to").value.trim(),
          amount: document.getElementById("shielded-amount").value.trim().replace(",", "."),
          max: shieldedMax,
        });
    showSentTransaction(successEl, "zec_shielded", txid);
    refreshZcashCards();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    passwordEl.value = "";
  }
}));

window.__TAURI__.event.listen("zec-shielded-synced", () => {
  const card = document.querySelector('.wallet-card[data-coin="zecs"]');
  if (card && dashboardShown()) refreshBalance(card);
}).catch((e) => console.error(e));

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
// le nœud (~1 s), Ethereum relu toutes les 6 s, Bitcoin et Dogecoin toutes les
// 10 s (transactions en attente comprises), Zcash transparent toutes les 20 s,
// jetons du registre (ERC-20 toutes les 12 s, Solana poussés). Monero et Zcash
// protégé : synchronisation de fond toutes les 30 s. Le rafraîchissement
// toutes les 60 s reste en filet de sécurité.
function updateBalanceWatch() {
  const targets = [...document.querySelectorAll(".wallet-card:not(.asset-hidden)")]
    .map((card) => {
      const coin = card.dataset.coin;
      const network = networkForCard(card);
      // Jetons du registre : contrat ou mint lus côté Rust (seul l'identifiant
      // part d'ici).
      if (usesTokenRegistry(coin, network)) return { id: coin, network, address: addressForCoin(coin, network), token: coin };
      // Monero, Zcash protégé : solde tenu par la synchronisation de fond
      // (événements `xmr-synced`, `zec-shielded-synced`).
      if (coin === "xmr" || coin === "zecs") return { address: "" };
      return { id: coin, network: coin === "usdc" ? "usdc_solana" : network, address: addressForCoin(coin, network) };
    })
    .filter((target) => target.address);
  invoke("watch_balances", { targets }).catch((e) => console.error(e));
}

// Délai d'annulation d'un envoi (Rust : `send_grace_period`), après la
// confirmation de Windows et avant la signature : compte à rebours,
// « Confirmer maintenant » ou « Annuler l'envoi ». Sans réponse, l'envoi part
// à la fin du délai — c'est Rust qui attend, ces boutons ne font que
// l'écourter ou l'annuler.
const countdownModal = document.getElementById("send-countdown-modal");
let sendCountdown = null;

function closeSendCountdown() {
  if (!sendCountdown) return;
  clearInterval(sendCountdown.timer);
  sendCountdown = null;
  countdownModal.classList.add("hidden");
  document.getElementById("send-countdown-progress").classList.remove("running");
}

function resolveSendCountdown(send) {
  if (!sendCountdown) return;
  invoke("resolve_send_countdown", { id: sendCountdown.id, send }).catch((e) => console.error(e));
  closeSendCountdown();
}

window.__TAURI__.event.listen("send-countdown", (event) => {
  closeSendCountdown();
  const { id, seconds, recap } = event.payload;
  // Réseau, montant, adresse (et tag / mémo) : ceux de la boîte de Windows.
  setWithCoinIcon(document.getElementById("send-countdown-network"), coinForNetwork(recap?.network_id), recap?.network ?? "");
  document.getElementById("send-countdown-amount").textContent = recap?.amount ?? "";
  document.getElementById("send-countdown-to-label").textContent = recap?.to_label ?? "";
  document.getElementById("send-countdown-to").textContent = recap?.to ?? "";
  const note = recap?.note;
  document.getElementById("send-countdown-note-row").classList.toggle("hidden", !note);
  document.getElementById("send-countdown-note-label").textContent = note ? note[0] : "";
  document.getElementById("send-countdown-note").textContent = note ? note[1] : "";
  const end = Date.now() + seconds * 1000;
  const text = document.getElementById("send-countdown-text");
  const tick = () => {
    text.textContent = t("countdown.text", { seconds: Math.max(0, Math.ceil((end - Date.now()) / 1000)) });
  };
  tick();
  sendCountdown = { id, timer: setInterval(tick, 200) };
  const progress = document.getElementById("send-countdown-progress");
  progress.classList.remove("running");
  void progress.offsetWidth; // relance l'animation
  progress.classList.add("running");
  countdownModal.classList.remove("hidden");
  // Annuler par défaut : une touche Entrée ne confirme jamais par mégarde.
  document.getElementById("send-countdown-cancel").focus();
});

window.__TAURI__.event.listen("send-countdown-end", (event) => {
  if (sendCountdown?.id === event.payload) closeSendCountdown();
});

document.getElementById("send-countdown-confirm").addEventListener("click", () => resolveSendCountdown(true));
document.getElementById("send-countdown-cancel").addEventListener("click", () => resolveSendCountdown(false));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && sendCountdown) resolveSendCountdown(false);
});

window.__TAURI__.event.listen("balance-changed", (event) => {
  const card = document.querySelector(`.wallet-card[data-coin="${event.payload}"]`);
  if (card && dashboardShown()) refreshBalance(card);
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
  // Zcash protégé : envoi depuis les fonds protégés (fenêtre dédiée).
  card.querySelector('[data-action="send"]').addEventListener("click", () => (card.dataset.coin === "zecs" ? openShieldedModal("send") : openSendModal(card)));
  // Boutons QR et copie : ceux de la ligne d'adresse ET ceux de la carte repliée.
  card.querySelectorAll('[data-action="qr"]').forEach((button) => button.addEventListener("click", () => openQrModal(card)));
  // Cliquer l'adresse elle-même l'affiche en entier (même modale que le bouton QR,
  // qui montre déjà le texte complet à côté du code QR) — utile surtout en vue
  // liste (voir styles.css : `.address` y est tronquée avec "…" pour la
  // compacité), mais garde le même geste en vue cartes aussi, par cohérence.
  card.querySelectorAll('[data-field="address"], [data-field="collapsed-address"]').forEach((el) => el.addEventListener("click", () => openQrModal(card)));
  card.querySelectorAll('[data-action="copy-address"]').forEach((button) =>
    button.addEventListener("click", () => {
      const address = addressForCoin(card.dataset.coin, networkForCard(card));
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
  card.querySelector('[data-action="shield"]')?.addEventListener("click", () => openShieldedModal("shield"));
  card.querySelector('[data-action="stake"]')?.addEventListener("click", () => {
    if (card.dataset.coin === "ada") {
      openAdaStakeModal(card);
      return;
    }
    if (card.dataset.coin === "sol" && networkForCard(card) === "sol_mainnet") {
      openSolStakeModal(card);
      return;
    }
    openLiquidStaking(card);
  });
  // Même historique que l'onglet « Historique », ouvert directement sur cette
  // crypto : plus facile à trouver depuis la carte que l'onglet seul.
  card.querySelector('[data-action="history"]').addEventListener("click", () => openCoinHistory(card.dataset.coin));
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
const QR_DECIMALS = new Proxy({ btc: 8, sol: 9, zec: 8, zecs: 8, xmr: 12, doge: 8, trx: 6, xrp: 6, xlm: 7, near: 24, ada: 6, stx: 6 }, { get: (known, coin) => ASSET_BY_COIN[coin]?.unitDecimals ?? known[coin] ?? 18 });
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
  if (coin === "zec" || coin === "zecs") return `zcash:${address}?amount=${amount}`;
  if (coin === "xmr") return `monero:${address}?tx_amount=${amount}`;
  if (coin === "doge") return `dogecoin:${address}?amount=${amount}`;
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

// Nom du réseau tel que les plateformes d'échange l'affichent au retrait
// (Binance, Coinbase, Kraken…) : celui à choisir pour envoyer ici.
const EXCHANGE_NETWORK_NAMES = {
  evm_mainnet: "Ethereum (ERC20)",
  arbitrum_mainnet: "Arbitrum One",
  base_mainnet: "Base",
  bsc_mainnet: "BNB Smart Chain (BEP20)",
  avax_mainnet: "Avalanche C-Chain",
  polygon_mainnet: "Polygon",
  sol_mainnet: "Solana",
  btc_mainnet: "Bitcoin",
  zec_mainnet: "Zcash",
  zec_shielded: "Zcash",
  xmr_mainnet: "Monero",
  doge_mainnet: "Dogecoin",
  tron_mainnet: "Tron (TRC20)",
  xrp_mainnet: "XRP Ledger",
  xlm_mainnet: "Stellar",
  near_mainnet: "NEAR",
  ada_mainnet: "Cardano",
  stx_mainnet: "Stacks",
  tao_mainnet: "Bittensor",
};

function renderQrNetworkHint(network) {
  const hint = document.getElementById("qr-network-hint");
  const name = EXCHANGE_NETWORK_NAMES[network];
  if (!name) {
    hint.textContent = t("qr.testnetWarning");
    return;
  }
  const strong = document.createElement("strong");
  strong.textContent = name;
  hint.replaceChildren(`${t("qr.networkChoose")} `, strong, document.createElement("br"), t("qr.networkWarning"));
}

async function openQrModal(card) {
  const address = addressForCoin(card.dataset.coin, networkForCard(card));
  if (!address) {
    alert(t("wallet.historyAddressUnavailable"));
    return;
  }
  qrCard = card;
  const asset = ASSET_BY_COIN[card.dataset.coin];
  setWithCoinIcon(document.getElementById("qr-coin"), card.dataset.coin, asset ? assetName(asset) : "");
  document.getElementById("qr-amount").value = "";
  document.getElementById("qr-amount-unit").textContent = card.querySelector(".balance").textContent.trim().split(/\s+/).pop();
  try {
    await renderQr();
    document.getElementById("qr-address-text").textContent = address;
    renderQrNetworkHint(networkForCard(card));
    qrModal.classList.remove("hidden");
  } catch (e) {
    alert(t("wallet.qrError", { err: e }));
  }
}

restrictToAmount(document.getElementById("qr-amount"));
document.getElementById("qr-amount").addEventListener("input", () => {
  renderQr().catch((e) => console.error(e));
});

document.getElementById("qr-copy").addEventListener("click", () => {
  const address = document.getElementById("qr-address-text").textContent;
  if (address) copyText(address, t("wallet.addressCopied"));
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
  const kindKey = { received: "history.kindReceived", sent: "history.kindSent", swap: "history.kindSwap", stake: "history.kindStake", other: "history.kindOther" }[tx.kind];
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
  if (tx.amount != null && Number.parseFloat(tx.amount) !== 0) {
    amountDiv.classList.add(tx.amount.startsWith("-") ? "negative" : "positive");
    amountDiv.textContent = tx.amount;
  } else {
    // Rien de cette crypto déplacé (transaction « Autre » : jeton reçu,
    // opération payée par un tiers…) : un tiret plutôt que « +0.000000000 ».
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

function loadHistorySection(coin) {
  return renderHistory(coin, document.getElementById(`history-list-${coin}`), document.getElementById(`history-network-${coin}`));
}

// Historique de `coin` (réseau et adresse de sa carte) dans `container`.
// Une lecture plus récente dans le même conteneur (autre crypto ouverte entre-
// temps, Actualiser) l'emporte : une réponse arrivée après elle est ignorée.
async function renderHistory(coin, container, networkEl) {
  const card = document.querySelector(`.wallet-card[data-coin="${coin}"]`);
  if (!card || !container || !networkEl) return;
  const load = String((Number(container.dataset.load) || 0) + 1);
  container.dataset.load = load;
  const current = () => container.dataset.load === load;

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
    if (!current()) return;
    // Historique indisponible (BNB Chain sans clé NodeReal dans cette
    // version, ou limite du service atteinte) : motif, et lien vers la page
    // de l'adresse sur l'explorateur du réseau.
    if (result.explorer_url) {
      container.replaceChildren(historyExplorerOnly(result.explorer_url, result.reason));
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
    if (!current()) return;
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

function historyExplorerOnly(url, reason) {
  const box = document.createElement("div");
  box.className = "history-explorer-only";
  const open = document.createElement("button");
  open.type = "button";
  open.className = "secondary";
  open.textContent = t("wallet.historyOpenExplorer");
  open.addEventListener("click", () => {
    invoke("open_external_link", { url }).catch((e) => alert(t("wallet.linkError", { err: e })));
  });
  box.append(mutedParagraph(t(reason === "limited" ? "wallet.historyLimited" : "wallet.historyExplorerOnly")));
  box.append(open);
  return box;
}

function loadAllHistory() {
  HISTORY_COINS.filter(isAssetVisible).forEach(loadHistorySection);
}

document.getElementById("refresh-history-btn").addEventListener("click", loadAllHistory);

// Menu « Recevoir » : une entrée par crypto affichée, USDC compris (la
// fenêtre de réception dit le réseau de sa carte, à choisir à l'envoi).
function renderReceiveMenu() {
  const list = document.querySelector(".action-menu .custom-select-options");
  const items = ASSETS.filter((asset) => isAssetVisible(asset.coin)).map((asset) => {
    const li = document.createElement("li");
    li.dataset.coin = asset.coin;
    setWithCoinIcon(li, asset.coin, t("wallet.receiveAsset", { symbol: asset.nameKey ? assetName(asset) : asset.symbol }));
    return li;
  });
  list.replaceChildren(...items);
}
renderReceiveMenu();

// Après un changement des cryptos affichées : cartes, menu, surveillance,
// prix en direct, courbe du portefeuille.
function refreshAssetDisplays() {
  applyAssetVisibility();
  updatePortfolioTotal();
  renderReceiveMenu();
  updateBalanceWatch();
  if (lastMarketCoins) renderMarkets(lastMarketCoins);
  if (portfolioView.rangesEl.childElementCount) refreshChart(portfolioView);
}

// Fenêtre « Gérer mes cryptos ».
const assetsModal = document.getElementById("assets-modal");
// Recherche : nom (affiché et d'origine), symbole ; sans tenir compte des
// majuscules ni des accents (« zcash protege » trouve « Zcash protégé »).
function normalizeSearch(text) {
  return text.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase().trim();
}

const assetsSearch = document.getElementById("assets-search");

function filterAssetsList() {
  const query = normalizeSearch(assetsSearch.value);
  let shown = 0;
  document.querySelectorAll("#assets-list li").forEach((li) => {
    const match = !query || li.dataset.search.includes(query);
    li.classList.toggle("hidden", !match);
    if (match) shown += 1;
  });
  document.getElementById("assets-no-match").classList.toggle("hidden", shown > 0);
}

assetsSearch.addEventListener("input", filterAssetsList);
// Échap dans une recherche non vide : l'efface (la fenêtre reste ouverte).
assetsSearch.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && assetsSearch.value) {
    e.stopPropagation();
    assetsSearch.value = "";
    filterAssetsList();
  }
});

document.getElementById("manage-assets-btn").addEventListener("click", () => {
  const list = document.getElementById("assets-list");
  const boxes = new Map();
  list.replaceChildren(
    ...orderedCoins().map((coin) => ASSET_BY_COIN[coin]).map((asset) => {
      const li = document.createElement("li");
      li.dataset.search = normalizeSearch(`${assetName(asset)} ${asset.name} ${asset.symbol}`);
      const label = document.createElement("label");
      label.className = "asset-choice";
      const icon = Object.assign(document.createElement("img"), { src: asset.icon, alt: "", className: asset.iconRound ? "coin-icon coin-icon-round" : asset.coin === "sol" ? "coin-icon coin-icon-sol" : "coin-icon" });
      const name = Object.assign(document.createElement("span"), { className: "asset-choice-name", textContent: assetName(asset) });
      const symbol = Object.assign(document.createElement("span"), { className: "muted", textContent: asset.symbol });
      const box = Object.assign(document.createElement("input"), { type: "checkbox", checked: isAssetVisible(asset.coin) });
      boxes.set(asset.coin, box);
      box.addEventListener("change", () => {
        assetChoices[asset.coin] = box.checked;
        saveAssetChoices();
        refreshAssetDisplays();
        // Cases qui suivent une autre (Zcash protégé suit Zcash sans choix
        // propre) : remises à jour.
        for (const [coin, other] of boxes) {
          other.checked = isAssetVisible(coin);
          if (other !== box && other.checked) refreshBalance(document.querySelector(`.wallet-card[data-coin="${coin}"]`));
        }
        if (box.checked) refreshBalance(document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`));
      });
      label.append(icon, name, symbol, box);
      li.appendChild(label);
      return li;
    })
  );
  assetsSearch.value = "";
  filterAssetsList();
  assetsModal.classList.remove("hidden");
  assetsSearch.focus();
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
  const order = [...cardOrder.custom];
  // Crypto ajoutée depuis (Zcash protégé…) : juste après celle qui la
  // précède dans l'ordre d'origine, pas en fin de liste.
  DEFAULT_CARD_ORDER.forEach((coin, i) => {
    if (order.includes(coin)) return;
    const before = DEFAULT_CARD_ORDER.slice(0, i).reverse().find((c) => order.includes(c));
    order.splice(before ? order.indexOf(before) + 1 : 0, 0, coin);
  });
  return order;
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
    return [...custom].sort((a, b) => collator.compare(assetName(ASSET_BY_COIN[a]), assetName(ASSET_BY_COIN[b])));
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
  if (draggingCard) return;
  const visible = [...walletGrid.querySelectorAll(".wallet-card:not(.asset-hidden)")];
  const neighbor = visible[visible.indexOf(card) + step];
  if (!neighbor) return;
  animateLayout(() => walletGrid.insertBefore(card, step < 0 ? neighbor : neighbor.nextSibling));
  adoptDisplayedOrder();
  focusAfter?.focus();
}

function setOrganizing(on) {
  if (!on && pointerDrag) cancelCardDrag();
  organizing = on;
  document.getElementById("organize-bar").classList.toggle("hidden", !on);
  document.getElementById("organize-btn").setAttribute("aria-pressed", String(on));
  walletGrid.classList.toggle("organizing", on);
  renderOrganizeModes();
}

document.getElementById("organize-btn").addEventListener("click", () => setOrganizing(!organizing));
document.getElementById("organize-done").addEventListener("click", () => setOrganizing(false));
document.querySelectorAll("[data-order-mode]").forEach((button) => {
  button.addEventListener("click", () => setCardOrderMode(button.dataset.orderMode));
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape" || !organizing || document.querySelector(".modal-overlay:not(.hidden)")) return;
  if (pointerDrag) cancelCardDrag();
  else setOrganizing(false);
});

// Glisser-déposer au pointeur (souris, stylet, tactile) — pas le
// glisser-déposer HTML5 : sous Windows, Tauri intercepte le glissement dans
// la fenêtre (dépôt de fichiers) et ses événements n'arrivent jamais aux
// cartes. Après quelques pixels, la carte elle-même se soulève et suit le
// pointeur (légèrement inclinée, ombrée) ; un emplacement en pointillés
// marque l'endroit où elle sera rangée et se déplace entre les autres cartes,
// qui glissent en douceur ; près du bord de la fenêtre, la page défile ; au
// relâchement, la carte glisse jusqu'à l'emplacement (Échap la ramène à sa
// place d'origine). Aucune copie de carte : la carte soulevée reste la vraie
// (son solde continue d'être mis à jour).
const DRAG_START_DISTANCE = 6;
const DRAG_SCROLL_EDGE = 70;
const DRAG_SCROLL_MAX_SPEED = 18;
const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let pointerDrag = null;

// Rectangle de mise en page (sans les translations des animations en cours),
// en coordonnées de la fenêtre.
function layoutRect(el) {
  const rect = el.getBoundingClientRect();
  const transform = getComputedStyle(el).transform;
  const matrix = transform && transform !== "none" ? new DOMMatrixReadOnly(transform) : null;
  const dx = matrix ? matrix.m41 : 0;
  const dy = matrix ? matrix.m42 : 0;
  return { left: rect.left - dx, top: rect.top - dy, width: rect.width, height: rect.height, right: rect.right - dx, bottom: rect.bottom - dy };
}

// Réordonne (`change`) puis fait glisser chaque carte et l'emplacement de leur
// ancienne position visuelle à la nouvelle (technique FLIP), animations en
// cours comprises.
function animateLayout(change) {
  const items = [...walletGrid.querySelectorAll(".wallet-card:not(.asset-hidden):not(.drag-floating), .card-placeholder")];
  const before = new Map(items.map((el) => [el, el.getBoundingClientRect()]));
  change();
  if (prefersReducedMotion()) return;
  for (const el of items) {
    el.style.transition = "none";
    el.style.transform = "";
  }
  const moved = [];
  for (const el of items) {
    const was = before.get(el);
    const now = el.getBoundingClientRect();
    const dx = was.left - now.left;
    const dy = was.top - now.top;
    if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) {
      el.style.transition = "";
      continue;
    }
    el.style.transform = `translate(${dx}px, ${dy}px)`;
    moved.push(el);
  }
  requestAnimationFrame(() => {
    for (const el of moved) {
      el.style.transition = "transform 200ms cubic-bezier(0.2, 0.8, 0.2, 1)";
      el.style.transform = "";
      // Fin du glissement : plus aucun style en ligne. Interrompu par un
      // nouveau réordonnancement, ce dernier reprend la main sur la carte.
      const done = (e) => {
        if (e.target !== el || e.propertyName !== "transform") return;
        el.removeEventListener("transitionend", done);
        if (!el.style.transform) el.style.transition = "";
      };
      el.addEventListener("transitionend", done);
    }
  });
}

// Colonnes d'une carte en largeurs fixes. En vue liste, la carte est un
// sous-grille (`subgrid`) qui n'a plus de colonnes une fois hors de la grille :
// elle reçoit celles de la grille, moins sa marge intérieure et sa bordure aux
// bords (que le sous-grille reporte sur les éléments des colonnes extrêmes).
function frozenColumns(style) {
  if (!style.gridTemplateColumns.startsWith("subgrid")) return style.gridTemplateColumns;
  const tracks = (getComputedStyle(walletGrid).gridTemplateColumns.match(/[\d.]+px/g) || []).map(parseFloat);
  if (!tracks.length) return "";
  tracks[0] -= parseFloat(style.paddingLeft) + parseFloat(style.borderLeftWidth);
  tracks[tracks.length - 1] -= parseFloat(style.paddingRight) + parseFloat(style.borderRightWidth);
  return tracks.map((track) => `${Math.max(track, 0)}px`).join(" ");
}

function startCardDrag(drag) {
  const { card } = drag;
  const rect = card.getBoundingClientRect();
  const style = getComputedStyle(card);
  // Colonnes de la grille figées le temps du glisser : en vue liste, leur
  // largeur dépend du contenu de toutes les cartes, et les autres cartes
  // changeraient de colonnes en perdant la carte soulevée.
  walletGrid.style.gridTemplateColumns = getComputedStyle(walletGrid).gridTemplateColumns;
  const placeholder = document.createElement("div");
  placeholder.className = "card-placeholder";
  placeholder.style.height = `${rect.height}px`;
  walletGrid.insertBefore(placeholder, card);
  // La carte sort de la grille (position fixe) en gardant sa taille et ses
  // colonnes.
  card.style.gridTemplateColumns = frozenColumns(style);
  card.style.left = `${rect.left}px`;
  card.style.top = `${rect.top}px`;
  card.style.width = `${rect.width}px`;
  card.style.height = `${rect.height}px`;
  card.style.transition = "none";
  card.classList.add("drag-floating");
  Object.assign(drag, { started: true, placeholder, originLeft: rect.left, originTop: rect.top, lastX: drag.startX, lastY: drag.startY });
  draggingCard = card;
  followPointer(drag);
  drag.scrollFrame = requestAnimationFrame(() => autoScroll(drag));
}

function followPointer(drag) {
  const { card, startX, startY, lastX, lastY } = drag;
  card.style.transform = `translate(${lastX - startX}px, ${lastY - startY}px) rotate(1.5deg) scale(1.02)`;
}

// Place l'emplacement selon la carte survolée (rectangles de mise en page,
// pour ne pas osciller pendant les animations) : avant ou après elle, à la
// verticale quand elle occupe toute la largeur (une colonne, vue liste), à
// l'horizontale sinon.
function placePlaceholder(drag) {
  const { placeholder, lastX: x, lastY: y } = drag;
  const candidates = [...walletGrid.querySelectorAll(".wallet-card:not(.asset-hidden):not(.drag-floating)")];
  const target = candidates.find((el) => {
    const r = layoutRect(el);
    return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
  });
  if (!target) return;
  const r = layoutRect(target);
  const fullRow = r.width > walletGrid.clientWidth * 0.75;
  const before = fullRow ? y < r.top + r.height / 2 : x < r.left + r.width / 2;
  const reference = before ? target : target.nextSibling;
  if (reference === placeholder || placeholder.nextSibling === reference) return;
  animateLayout(() => walletGrid.insertBefore(placeholder, reference));
}

// Défilement continu près du bord de la fenêtre, plus rapide tout au bord.
function autoScroll(drag) {
  if (pointerDrag !== drag || !drag.started) return;
  const { lastY } = drag;
  let speed = 0;
  if (lastY < DRAG_SCROLL_EDGE) speed = -DRAG_SCROLL_MAX_SPEED * (1 - Math.max(lastY, 0) / DRAG_SCROLL_EDGE);
  else if (lastY > window.innerHeight - DRAG_SCROLL_EDGE) speed = DRAG_SCROLL_MAX_SPEED * (1 - Math.max(window.innerHeight - lastY, 0) / DRAG_SCROLL_EDGE);
  if (speed) {
    window.scrollBy(0, speed);
    placePlaceholder(drag);
  }
  drag.scrollFrame = requestAnimationFrame(() => autoScroll(drag));
}

walletGrid.addEventListener("pointerdown", (e) => {
  if (!organizing || e.button !== 0 || pointerDrag || draggingCard || e.target.closest(".organize-move")) return;
  const card = e.target.closest(".wallet-card");
  if (!card) return;
  pointerDrag = { card, pointerId: e.pointerId, startX: e.clientX, startY: e.clientY, started: false };
  card.setPointerCapture(e.pointerId);
  e.preventDefault();
});

// Mouvement et relâchement écoutés sur toute la page : la carte soulevée
// n'est plus sous le pointeur, et le relâchement peut avoir lieu hors de la
// grille.
document.addEventListener("pointermove", (e) => {
  const drag = pointerDrag;
  if (!drag || e.pointerId !== drag.pointerId) return;
  if (!drag.started) {
    if (Math.hypot(e.clientX - drag.startX, e.clientY - drag.startY) < DRAG_START_DISTANCE) return;
    startCardDrag(drag);
  }
  drag.lastX = e.clientX;
  drag.lastY = e.clientY;
  followPointer(drag);
  placePlaceholder(drag);
});

// Fin du glisser : la carte glisse jusqu'à l'emplacement, puis y reprend sa
// place dans la grille ; `draggingCard` reste posé jusque-là (pas de tri ni de
// nouveau glisser pendant qu'elle se pose).
function finishCardDrag(drag, { adopt }) {
  const { card, placeholder } = drag;
  pointerDrag = null;
  if (card.hasPointerCapture(drag.pointerId)) card.releasePointerCapture(drag.pointerId);
  if (!drag.started) return;
  cancelAnimationFrame(drag.scrollFrame);
  const settle = () => {
    card.classList.remove("drag-floating", "drag-landing");
    for (const property of ["gridTemplateColumns", "left", "top", "width", "height", "transform", "transition"]) card.style[property] = "";
    placeholder.replaceWith(card);
    walletGrid.style.gridTemplateColumns = "";
    draggingCard = null;
    if (adopt) adoptDisplayedOrder();
  };
  if (prefersReducedMotion()) {
    settle();
    return;
  }
  const target = layoutRect(placeholder);
  card.style.transition = "transform 180ms cubic-bezier(0.2, 0.8, 0.2, 1), box-shadow 180ms ease";
  card.style.transform = `translate(${target.left - drag.originLeft}px, ${target.top - drag.originTop}px)`;
  card.classList.add("drag-landing");
  setTimeout(settle, 190);
}

// Échap (ou sortie du mode) pendant le glisser : la carte retourne à sa place
// d'origine — elle n'a jamais quitté sa position dans la grille, seul
// l'emplacement a bougé — et le mode de tri ne change pas.
function cancelCardDrag() {
  const drag = pointerDrag;
  if (drag.started) animateLayout(() => walletGrid.insertBefore(drag.placeholder, drag.card));
  finishCardDrag(drag, { adopt: false });
}

function endPointerDrag(e) {
  if (pointerDrag && e.pointerId === pointerDrag.pointerId) finishCardDrag(pointerDrag, { adopt: true });
}
document.addEventListener("pointerup", endPointerDrag);
document.addEventListener("pointercancel", (e) => {
  if (pointerDrag && e.pointerId === pointerDrag.pointerId) cancelCardDrag();
});

// Ordre initial une fois tout le module chargé (« Valeur détenue » lit des
// constantes déclarées plus bas dans ce fichier).
setTimeout(applyCardOrder, 0);

// --- Historique d'une crypto (fenêtre) --------------------------------------
// Bouton « Historique » d'une carte : grande fenêtre au-dessus du portefeuille,
// qui reste visible derrière, flouté ; cette crypto seule (l'onglet
// « Activité » garde toutes les cryptos). Fermée par la croix, Échap, ou un
// clic à côté commencé à côté (comme « Gérer mes cryptos »).

const coinHistoryModal = document.getElementById("coin-history-modal");
let coinHistoryCoin = null;

function coinHistoryOpen() {
  return !coinHistoryModal.classList.contains("hidden");
}

function renderCoinHistoryTitle() {
  const card = document.querySelector(`.wallet-card[data-coin="${coinHistoryCoin}"]`);
  if (!card) return;
  // Nom lu sur la carte, sans l'indentation du HTML : « Bitcoin », « USDC Solana ».
  const name = card.querySelector("h2").textContent.trim().replace(/\s+/g, " ");
  setWithCoinIcon(document.getElementById("coin-history-title"), coinHistoryCoin, t("coinHistory.title", { name }));
}

function loadCoinHistory() {
  renderCoinHistoryTitle();
  renderHistory(coinHistoryCoin, document.getElementById("coin-history-list"), document.getElementById("coin-history-network"));
}

function openCoinHistory(coin) {
  if (!document.querySelector(`.wallet-card[data-coin="${coin}"]`)) return;
  coinHistoryCoin = coin;
  coinHistoryModal.classList.remove("hidden");
  coinHistoryModal.scrollTop = 0;
  loadCoinHistory();
}

function closeCoinHistory() {
  coinHistoryModal.classList.add("hidden");
  coinHistoryCoin = null;
  // Lecture encore en cours : sa réponse est ignorée (voir `renderHistory`).
  const list = document.getElementById("coin-history-list");
  list.dataset.load = String((Number(list.dataset.load) || 0) + 1);
  list.replaceChildren();
}

document.getElementById("coin-history-close").addEventListener("click", closeCoinHistory);
let coinHistoryPressedOutside = false;
coinHistoryModal.addEventListener("pointerdown", (e) => {
  coinHistoryPressedOutside = e.target === coinHistoryModal;
});
coinHistoryModal.addEventListener("click", (e) => {
  if (e.target === coinHistoryModal && coinHistoryPressedOutside) closeCoinHistory();
});
document.getElementById("coin-history-refresh").addEventListener("click", () => {
  if (coinHistoryCoin) loadCoinHistory();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && coinHistoryOpen()) closeCoinHistory();
});
// Nouvelle langue : titre et lignes retraduits (après `applyLanguage`,
// abonnée plus haut).
document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (coinHistoryOpen()) loadCoinHistory();
  });
});

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

// Cours d'une crypto : dollars pour 1 unité, dollars pour 1 unité de la devise
// affichée ; `null` si inconnu ou réseau de test (fonds sans valeur).
function fiatRate(coin, network) {
  if (!network?.endsWith("mainnet")) return null;
  const price = priceForCoin(coin);
  const usdPerUnit = displayCurrency === "eur" ? usdPerEur : 1;
  return price != null && price > 0 && usdPerUnit ? { price, usdPerUnit } : null;
}

function sendRate() {
  return sendContext ? fiatRate(sendContext.coin, networkForCard(sendContext.card)) : null;
}

function parseAmountInput(text) {
  const value = Number.parseFloat(text.replace(",", "."));
  return Number.isFinite(value) ? value : null;
}

// Texte du champ en devise pour un montant en crypto (« 12,34 »), et texte du
// champ en crypto pour un montant en devise (aux décimales de la crypto).
function fiatAmountText(crypto, rate) {
  const fiat = ((crypto * rate.price) / rate.usdPerUnit).toFixed(2);
  return currentLang === "fr" ? fiat.replace(".", ",") : fiat;
}

function cryptoAmountText(fiat, rate, coin) {
  return ((fiat * rate.usdPerUnit) / rate.price).toFixed(COIN_DECIMALS[coin]);
}

function syncSendFiatFromCrypto() {
  const rate = sendRate();
  const crypto = parseAmountInput(sendAmountInput.value);
  sendFiatInput.value = rate && crypto != null ? fiatAmountText(crypto, rate) : "";
}

function syncSendCryptoFromFiat() {
  const rate = sendRate();
  const fiat = parseAmountInput(sendFiatInput.value);
  sendAmountInput.value = rate && fiat != null ? cryptoAmountText(fiat, rate, sendContext.coin) : "";
}

function setSendCryptoAmount(value) {
  sendAmountInput.value = value;
  syncSendFiatFromCrypto();
}

restrictToAmount(sendAmountInput, syncSendFiatFromCrypto);
restrictToAmount(sendFiatInput, syncSendCryptoFromFiat);
// Montant tapé à la main : ce n'est plus le maximum.
for (const input of [sendAmountInput, sendFiatInput]) {
  input.addEventListener("input", () => {
    if (sendContext) sendContext.max = false;
  });
}

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
    btn.title = cryptoSpan.textContent;
    btn.addEventListener("click", () => {
      setSendCryptoAmount(cryptoAmount);
    });
    container.appendChild(btn);
  });
}

// Pourcentages du solde actuellement affiché sur la carte (pas un nouvel appel
// réseau : réutilise `[data-field="balance"]`, déjà tenu à jour par
// refreshBalance). « Max » : le plus grand montant ENVOYABLE, frais du réseau
// déduits, calculé côté Rust (`max_send_amount`) avec les mêmes règles que
// l'envoi — puis recalculé à la confirmation (`max: true`), si bien que le
// montant affiché dans la boîte de Windows reste exact si les frais bougent.
const QUICK_PERCENTAGES = [25, 50, 100];

// Jeton du registre (ou USDC) envoyé depuis la carte : son identifiant, sinon
// `null` (monnaie du réseau).
function sendTokenId(coin, network) {
  return usesTokenRegistry(coin, network) || coin === "usdc" ? coin : null;
}

async function fillMaxAmount(btn) {
  if (!sendContext) return;
  const context = sendContext;
  const network = networkForCard(context.card);
  const cryptoSpan = btn?.querySelector(".quick-amount-crypto");
  if (cryptoSpan) cryptoSpan.textContent = t("send.maxComputing");
  btn?.classList.add("busy");
  hideError(document.getElementById("send-error"));
  try {
    const amount = await invoke("max_send_amount", {
      network,
      token: sendTokenId(context.coin, network),
      profileIndex: context.profileIndex,
      feeSat: context.coin === "btc" ? context.feeSat : null,
    });
    if (sendContext !== context) return;
    setSendCryptoAmount(amount);
    context.max = true;
    if (cryptoSpan) cryptoSpan.textContent = `${amount} ${COIN_SYMBOL[context.coin]}`;
  } catch (e) {
    if (cryptoSpan) cryptoSpan.textContent = t("send.maxHint");
    showError(document.getElementById("send-error"), String(e));
  } finally {
    btn?.classList.remove("busy");
    if (btn && cryptoSpan) btn.title = cryptoSpan.textContent;
  }
}

// « Disponible : 0.0419 SOL (≈ 5,03 $) » à droite de « Montant » : le solde
// affiché sur la carte, sans zéros inutiles.
function renderSendAvailable() {
  const el = document.getElementById("send-available");
  if (!sendContext) return;
  const text = sendContext.card.querySelector('[data-field="balance"]').textContent.trim();
  const balance = Number.parseFloat(text);
  if (!Number.isFinite(balance)) {
    el.textContent = "";
    return;
  }
  const rate = sendRate();
  const approx = rate && balance > 0 ? ` (${formatUsdApprox(balance * rate.price)})` : "";
  const amount = text.includes(".") ? text.replace(/0+$/, "").replace(/\.$/, "") : text;
  el.textContent = t("send.available", { amount: `${amount} ${COIN_SYMBOL[sendContext.coin]}`, approx });
}

function renderQuickPercentages() {
  const container = document.getElementById("send-quick-percentages");
  container.innerHTML = "";
  if (!sendContext) return;
  const balance = Number.parseFloat(sendContext.card.querySelector('[data-field="balance"]').textContent);
  const decimals = COIN_DECIMALS[sendContext.coin];
  const symbol = COIN_SYMBOL[sendContext.coin];

  if (!Number.isFinite(balance) || balance <= 0) {
    container.innerHTML = `<p class="muted quick-amounts-hint">${t(Number.isFinite(balance) ? "send.percentZero" : "send.percentUnavailable")}</p>`;
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
    cryptoSpan.textContent = percent === 100 ? t("send.maxHint") : `≈ ${cryptoAmount} ${symbol}`;
    btn.appendChild(percentSpan);
    btn.appendChild(cryptoSpan);
    btn.title = cryptoSpan.textContent;
    btn.addEventListener("click", () => {
      if (percent === 100) {
        fillMaxAmount(btn);
        return;
      }
      setSendCryptoAmount(cryptoAmount);
      sendContext.max = false;
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
  sendContext = { coin: card.dataset.coin, card, profileIndex: profile ? profile.index : currentProfileIndex, max: false };
  const network = networkForCard(card);
  // Nom lu sur la carte, sans l'indentation du HTML (le titre contient le
  // bouton de repli) : « Bitcoin », « USDC Solana ».
  const coinName = card.querySelector("h2").textContent.trim().replace(/\s+/g, " ");
  setWithCoinIcon(document.getElementById("send-modal-title"), card.dataset.coin, `${t("send.title")} (${coinName})`);
  document.getElementById("send-from-profile").textContent = profile ? profile.label : "—";
  setWithCoinIcon(document.getElementById("send-network-chip"), coinForNetwork(network), contactNetworkLabel(network));
  document.getElementById("send-mainnet-warning").classList.toggle("hidden", !network.endsWith("mainnet"));
  document.getElementById("send-to").value = "";
  document.getElementById("send-amount").value = "";
  document.getElementById("send-tag").value = "";
  document.getElementById("send-tag-block").classList.toggle("hidden", !NOTE_COINS.has(card.dataset.coin));
  setNoteLabels(card.dataset.coin);
  sendFiatInput.value = "";
  document.getElementById("send-password").value = "";
  hideError(document.getElementById("send-error"));
  document.getElementById("send-success").classList.add("hidden");
  renderSendAmountUnits();
  renderSendAvailable();
  renderQuickAmounts();
  renderQuickPercentages();
  loadBtcFeeOptions(card, network);
  sendModal.classList.remove("hidden");
  loadAddressBook().then(() => refreshSendAddressBookPicker(card.dataset.coin, network, sendContext.profileIndex));
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
        // Maximum dépendant des frais choisis : recalculé.
        if (sendContext.max) fillMaxAmount(document.querySelector("#send-quick-percentages .quick-amount-btn:last-child"));
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

// Complément du destinataire exigé par les plateformes d'échange : tag de
// destination (XRP, chiffres) ou mémo (Stellar, texte ASCII court).
const NOTE_COINS = new Set(["xrp", "xlm", "stx"]);
// Mémo : longueur maximale selon le réseau (Stellar 28 octets, Stacks 34).
const MEMO_MAX = { xlm: 28, stx: 34 };

// Libellés du champ, de sa consigne et de la ligne d'aperçu selon la crypto
// (clés i18n changées aussi, pour un changement de langue fenêtre ouverte).
function setNoteLabels(coin) {
  const memo = coin in MEMO_MAX;
  const input = document.getElementById("send-tag");
  input.inputMode = memo ? "text" : "numeric";
  input.maxLength = memo ? MEMO_MAX[coin] : 10;
  for (const [selector, tagKey, memoKey] of [
    ['label[for="send-tag"]', "send.destinationTag", "send.memo"],
    ["#send-tag-block .tag-hint", "send.destinationTagHint", "send.memoHint"],
    ["#send-preview-tag-row .send-preview-label", "send.destinationTagShort", "send.memoShort"],
  ]) {
    const el = document.querySelector(selector);
    el.dataset.i18n = memo ? memoKey : tagKey;
    el.textContent = t(el.dataset.i18n);
  }
}

// Valeur saisie pour la crypto de la fenêtre, `null` si vide ou autre crypto.
function sendNote(coin) {
  if (sendContext?.coin !== coin) return null;
  const value = document.getElementById("send-tag").value.trim();
  return value === "" ? null : value;
}
const sendDestinationTag = () => sendNote("xrp");
const sendMemo = () => (sendContext?.coin in MEMO_MAX ? sendNote(sendContext.coin) : null);

// XRP : chiffres seulement ; Stellar : ASCII imprimable (collage compris).
document.getElementById("send-tag").addEventListener("input", (event) => {
  const max = MEMO_MAX[sendContext?.coin];
  const filtered = max ? event.target.value.replace(/[^\x20-\x7e]/g, "").slice(0, max) : event.target.value.replace(/\D/g, "").slice(0, 10);
  if (filtered !== event.target.value) event.target.value = filtered;
});

// Champs d'adresse : aucune espace possible (touche Espace bloquée, espaces
// retirées d'un collage) — une adresse n'en contient jamais, une espace
// glissée par mégarde la rendrait invalide.
for (const id of ["send-to", "shielded-to", "swap-destination", "external-wallet-address", "ledger-send-to", "address-book-address", "wc-uri"]) {
  const input = document.getElementById(id);
  if (!input) continue;
  input.addEventListener("keydown", (event) => {
    if (event.key === " " || event.code === "Space") event.preventDefault();
  });
  input.addEventListener("input", () => {
    if (!/\s/.test(input.value)) return;
    const caret = input.selectionStart ?? input.value.length;
    const removedBefore = (input.value.slice(0, caret).match(/\s/g) ?? []).length;
    input.value = input.value.replace(/\s+/g, "");
    input.setSelectionRange(caret - removedBefore, caret - removedBefore);
  });
}

function networkLabelForCard(card) {
  var label = card.querySelector(".custom-select-label") || card.querySelector(".network-fixed-label");
  return label ? label.textContent.trim() : networkForCard(card);
}

const sendPreviewModal = document.getElementById("send-preview-modal");

// Avertissements sur le destinataire dans l'aperçu (Rust, `recipient_warnings`) :
// adresse presque identique à une adresse connue, sosie d'un contact,
// nouvelle adresse, état sur la blockchain — les mêmes que la boîte de
// Windows, qui reste la vraie protection.
let recipientCheck = 0;

async function showRecipientWarnings(to) {
  const box = document.getElementById("send-preview-warnings");
  const check = ++recipientCheck;
  const line = (level, text) => {
    const p = document.createElement("p");
    p.className = `send-warning ${level}`;
    p.textContent = text;
    return p;
  };
  box.replaceChildren(line("info", t("send.checkingRecipient")));
  box.classList.remove("hidden");
  const network = networkForCard(sendContext.card);
  const coin = sendContext.coin;
  // Même aiguillage que l'envoi : jeton du registre, USDC Solana, monnaie.
  const token = usesTokenRegistry(coin, network) ? coin : coin === "usdc" ? "usdc" : null;
  let warnings = [];
  try {
    warnings = await invoke("recipient_warnings", { network, token, to });
  } catch (e) {
    // Adresse refusée (compte de jetons Solana, adresse mal formée…) :
    // l'envoi le sera aussi, autant le dire dès l'aperçu.
    warnings = [{ level: "danger", text: String(e) }];
  }
  if (check !== recipientCheck) return;
  box.replaceChildren(...warnings.map((w) => line(w.level, w.text)));
  box.classList.toggle("hidden", warnings.length === 0);
}

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
  const tag = sendDestinationTag();
  if (tag !== null && !(/^\d{1,10}$/.test(tag) && Number(tag) <= 4294967295)) {
    showError(errorEl, t("send.destinationTagInvalid"));
    return;
  }
  const memo = sendMemo();
  if (memo !== null && !(/^[\x20-\x7e]+$/.test(memo) && memo.length <= MEMO_MAX[sendContext.coin])) {
    showError(errorEl, t("send.memoInvalid"));
    return;
  }

  document.getElementById("send-preview-network").textContent = networkLabelForCard(sendContext.card);
  document.getElementById("send-preview-from").textContent = document.getElementById("send-from-profile").textContent;
  document.getElementById("send-preview-to").textContent = to;
  // XRP, Stellar : tag ou mémo toujours montré (« aucun » compris), comme
  // dans la boîte native.
  document.getElementById("send-preview-tag-row").classList.toggle("hidden", !NOTE_COINS.has(sendContext.coin));
  document.getElementById("send-preview-tag").textContent = tag ?? memo ?? t("send.destinationTagNone");
  const rate = sendRate();
  const approx = rate ? ` (${formatUsdApprox(Number(amount) * rate.price)})` : "";
  // Jeton : tout son solde part (les frais sont payés dans la crypto du réseau).
  const tokenMax = sendContext.coin === "usdc" || usesTokenRegistry(sendContext.coin, networkForCard(sendContext.card));
  const maxNote = sendContext.max ? t(tokenMax ? "send.maxSuffixToken" : "send.maxSuffix") : "";
  setWithCoinIcon(document.getElementById("send-preview-amount"), sendContext.coin, `${amount} ${COIN_SYMBOL[sendContext.coin]}${maxNote}${approx}`);

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

  showRecipientWarnings(to);
  showSendNetworkNote();
  showSendFeeEstimate(to, amount);
  sendPreviewModal.classList.remove("hidden");
});

// Crypto présente sur plusieurs réseaux (ETH, USDC, USDT…) : rappel du
// réseau de départ — un dépôt sur une plateforme d'échange par un autre
// réseau que celui qu'elle attend est l'une des pertes les plus fréquentes.
function showSendNetworkNote() {
  const note = document.getElementById("send-preview-network-note");
  const asset = ASSET_BY_COIN[sendContext.coin];
  const network = networkForCard(sendContext.card);
  const mainnets = asset ? asset.networks.filter((n) => !TEST_NETWORKS.includes(n)) : [];
  if (mainnets.length < 2 || TEST_NETWORKS.includes(network)) {
    note.classList.add("hidden");
    return;
  }
  const strong = document.createElement("strong");
  strong.textContent = EXCHANGE_NETWORK_NAMES[network] ?? t(`net.${network}`);
  note.replaceChildren(`⚠ ${t("send.networkNoteBefore")} `, strong, `. ${t("send.networkNoteAfter")}`);
  note.classList.remove("hidden");
}

// Frais réseau estimés dans l'aperçu, en devise et dans la monnaie du réseau
// (la boîte de confirmation native, ensuite, montre le montant exact) :
// découvrir les frais au dernier moment est l'une des plaintes les plus
// fréquentes des utilisateurs de portefeuilles. Bitcoin : vitesse déjà
// affichée ; Monero et réseaux de test : pas d'estimation.
let sendFeeEstimate = 0;
async function showSendFeeEstimate(to, amount) {
  const row = document.getElementById("send-preview-estimate-row");
  const value = document.getElementById("send-preview-estimate");
  const check = ++sendFeeEstimate;
  const network = networkForCard(sendContext.card);
  const token = sendContext.coin === "usdc" ? "usdc" : usesTokenRegistry(sendContext.coin, network) ? sendContext.coin : null;
  if (sendContext.coin === "btc" || !network.endsWith("mainnet")) {
    row.classList.add("hidden");
    return;
  }
  value.textContent = t("send.feeEstimateLoading");
  row.classList.remove("hidden");
  try {
    const fee = await invoke("estimate_send_fee", { network, token, to, amount, profileIndex: sendContext.profileIndex });
    if (check !== sendFeeEstimate) return;
    if (!fee) {
      row.classList.add("hidden");
      return;
    }
    const price = priceForCoin(fee.coin);
    // 3 chiffres significatifs : « 0,0000508 ETH », pas 15 décimales.
    const native = `${Number(fee.amount).toLocaleString(chartLocale(), { maximumSignificantDigits: 3 })} ${fee.symbol}`;
    const text = price != null ? `${formatUsdApprox(Number(fee.amount) * price)} (${native})` : native;
    value.textContent = fee.up_to ? t("send.feeUpTo", { fee: text }) : text;
  } catch (e) {
    // Solde insuffisant, adresse refusée… : dit ici déjà, plutôt qu'à la fin.
    if (check !== sendFeeEstimate) return;
    value.textContent = friendlyError(String(e)) ?? String(e);
  }
}

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
      ? await invoke("send_token_transaction", { token: sendContext.coin, network, password, to, amount, profileIndex: sendContext.profileIndex, max: sendContext.max })
      : sendContext.coin === "usdc"
      ? await invoke("send_usdc_transaction", { password, to, amount, profileIndex: sendContext.profileIndex, max: sendContext.max })
      : await invoke("send_transaction", {
          network,
          password,
          to,
          amount,
          feeSat: sendContext.coin === "btc" ? sendContext.feeSat : null,
          profileIndex: sendContext.profileIndex,
          max: sendContext.max,
          destinationTag: sendDestinationTag(),
          memo: sendMemo(),
        });
    showSentTransaction(successEl, network, txResult);
    refreshBalance(sendContext.card);
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("send-password").value = "";
  }
}));

// Envoi parti : ce qui va se passer (confirmation par le réseau, solde mis à
// jour tout seul), l'identifiant, et un bouton vers l'explorateur du réseau —
// « j'ai envoyé et rien n'est arrivé » est la plainte n°1 des utilisateurs
// de portefeuilles.
async function showSentTransaction(successEl, network, tx) {
  const text = document.createElement("span");
  text.textContent = `${t("send.sentFriendly")} `;
  const id = document.createElement("span");
  id.className = "mono sent-tx-id";
  id.textContent = tx;
  successEl.replaceChildren(text, id);
  successEl.classList.remove("hidden");
  const url = await invoke("tx_explorer_url", { network, tx }).catch(() => null);
  if (!url) return;
  const link = document.createElement("button");
  link.type = "button";
  link.className = "link sent-tx-link";
  link.textContent = t("send.track");
  link.addEventListener("click", () => invoke("open_external_link", { url }).catch((e) => alert(t("wallet.linkError", { err: e }))));
  successEl.append(" ", link);
}

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
  // Frais d'affiliation de l'app pour cette étape, en points de base, déclarés
  // par Rust pour chaque fournisseur (0 depuis Bitcoin ou Zcash via THORChain
  // ou Maya, voir `swap_routes::affiliate_fee_bps`).
  const feesBps = Object.fromEntries((direct?.protocols ?? []).map((protocol, index) => [protocol, direct.fees_bps?.[index]]));
  const chosen = document.getElementById("swap-provider").value;
  return { from, to, protocol: providers.includes(chosen) ? chosen : providers[0], providers, feesBps, via: pair.via ?? null, thenProtocol: pair.then_protocol ?? null };
}

// Frais d'affiliation par défaut de chaque fournisseur, en % (voir
// core/src/cow.rs et core/src/thorchain_rpc.rs), quand Rust n'en déclare pas
// pour la paire.
const SWAP_PROVIDER_FEE_PERCENT = { thorchain: 0.8, maya: 0.8, jupiter: 0.8, cow: 1, lifi: 0.8, swapkit: 0.15, moonpay: 1.1 };

function swapProviderFeePercent(pair, protocol) {
  const bps = pair?.feesBps?.[protocol];
  return typeof bps === "number" ? bps / 100 : SWAP_PROVIDER_FEE_PERCENT[protocol];
}

// Actifs que THORChain et Maya n'échangent pas en ce moment (`coin@network`,
// réseau suspendu : incident, maintenance), lus à chaque ouverture de la
// fenêtre (commande `swap_halts`).
let swapHalts = {};

// Le fournisseur `protocol` a-t-il suspendu l'un des deux actifs de l'étape ?
function isProviderHalted(protocol, step) {
  const halted = swapHalts[protocol] ?? [];
  return [step.from, step.to].some(({ coin, network }) => halted.includes(swapKey(coin, network)));
}

// Menu « Fournisseur » : tous ceux qui savent faire l'étape, le recommandé
// en premier et choisi par défaut à chaque changement de paire. Un
// fournisseur suspendu passe en dernier, marqué : choisi par défaut seulement
// s'il n'y en a pas d'autre (son devis dira alors la suspension en clair).
function fillSwapProviderOptions() {
  const select = document.getElementById("swap-provider");
  const pair = selectedSwapPair();
  const providers = pair ? pair.providers : [];
  const halted = (protocol) => isProviderHalted(protocol, { from: pair.from, to: pair.via ?? pair.to });
  const ordered = [...providers.filter((protocol) => !halted(protocol)), ...providers.filter(halted)];
  select.replaceChildren(
    ...ordered.map((protocol, index) => {
      const option = document.createElement("option");
      option.value = protocol;
      const fee = `${swapProviderFeePercent(pair, protocol).toLocaleString(chartLocale(), { minimumFractionDigits: 2 })}\u00a0%`;
      const label = halted(protocol) ? "swap.providerHalted" : index === 0 ? "swap.providerRecommended" : "swap.providerOption";
      option.textContent = t(label, { name: SWAP_PROTOCOL_NAMES[protocol], fee });
      return option;
    })
  );
  select.value = ordered[0] ?? "";
  syncCustomSelect(select);
}

// --- Staking Cardano (délégation à un pool) -----------------------------------
// Les ADA restent dans le portefeuille ; tout se décide côté Rust (pools
// proposés, état du compte, transaction, boîte native, délai d'annulation).
const adaStakeModal = document.getElementById("ada-stake-modal");
let adaStakeContext = null;

async function openAdaStakeModal(card) {
  const profile = currentProfile();
  const context = { profileIndex: profile ? profile.index : currentProfileIndex, status: null };
  adaStakeContext = context;
  const statusEl = document.getElementById("ada-stake-status");
  const select = document.getElementById("ada-stake-pool");
  statusEl.textContent = t("staking.adaLoading");
  document.getElementById("ada-stake-password").value = "";
  hideError(document.getElementById("ada-stake-error"));
  document.getElementById("ada-stake-success").classList.add("hidden");
  for (const id of ["ada-stake-withdraw", "ada-stake-stop"]) document.getElementById(id).classList.add("hidden");
  adaStakeModal.classList.remove("hidden");
  const [status, pools] = await Promise.allSettled([invoke("cardano_stake_status", { profileIndex: context.profileIndex }), invoke("cardano_pools")]);
  if (adaStakeContext !== context) return;
  if (pools.status === "fulfilled") {
    select.replaceChildren(
      ...pools.value.map((p) => Object.assign(document.createElement("option"), {
        value: p.id,
        textContent: t("staking.adaPoolOption", { ticker: p.ticker, margin: p.margin_percent.toLocaleString(chartLocale(), { maximumFractionDigits: 2 }), stake: Math.round(p.active_stake_ada / 1e6).toLocaleString(chartLocale()) }),
      }))
    );
  } else {
    showError(document.getElementById("ada-stake-error"), String(pools.reason));
  }
  if (status.status === "fulfilled") {
    const s = status.value;
    context.status = s;
    const pool = s.ticker ?? s.pool;
    statusEl.textContent = !s.registered || !s.pool ? t("staking.adaNone") : t(s.rewards_lovelace > 0 ? "staking.adaStatus" : "staking.adaStatusPending", { pool, rewards: s.rewards });
    if (s.pool && [...select.options].some((o) => o.value === s.pool)) select.value = s.pool;
    else if (s.pool) select.prepend(Object.assign(document.createElement("option"), { value: s.pool, textContent: pool, selected: true }));
    document.getElementById("ada-stake-delegate").textContent = t(s.registered && s.pool ? "staking.adaChange" : "staking.adaDelegate");
    document.getElementById("ada-stake-withdraw").classList.toggle("hidden", !(s.rewards_lovelace > 0));
    document.getElementById("ada-stake-stop").classList.toggle("hidden", !s.registered);
  } else {
    statusEl.textContent = "";
    showError(document.getElementById("ada-stake-error"), String(status.reason));
  }
  syncCustomSelect(select);
}

async function runAdaStake(action) {
  if (!adaStakeContext) return;
  const errorEl = document.getElementById("ada-stake-error");
  const successEl = document.getElementById("ada-stake-success");
  hideError(errorEl);
  successEl.classList.add("hidden");
  const password = document.getElementById("ada-stake-password").value;
  if (!password) {
    showError(errorEl, t("wallet.allFieldsRequired"));
    return;
  }
  try {
    const tx = await invoke("cardano_stake", { password, action, pool: document.getElementById("ada-stake-pool").value || null, profileIndex: adaStakeContext.profileIndex });
    successEl.textContent = t("staking.adaSent", { tx: `${tx.slice(0, 10)}…` });
    successEl.classList.remove("hidden");
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("ada-stake-password").value = "";
  }
}

for (const [id, action] of [["ada-stake-delegate", "delegate"], ["ada-stake-withdraw", "withdraw"], ["ada-stake-stop", "undelegate"]]) {
  const button = document.getElementById(id);
  button.addEventListener("click", withBusyButton(button, () => runAdaStake(action)));
}
document.getElementById("ada-stake-close").addEventListener("click", () => {
  adaStakeModal.classList.add("hidden");
  adaStakeContext = null;
});

// --- Staking Solana (liquide ou natif) -------------------------------------------
// Liquide : échange SOL → JitoSOL dans « Convertir ». Natif : compte de mise
// délégué à un validateur ; tout se décide et se vérifie côté Rust
// (validateurs proposés, simulation, boîte native, délai d'annulation).
const solStakeModal = document.getElementById("sol-stake-modal");
let solStakeContext = null;

function solStakedFor(card) {
  return card.dataset.coin === "sol" && solStaked.key === balanceKey(card) ? solStaked.lamports / 1e9 : 0;
}

function renderSolStaked(card) {
  const statusEl = card.querySelector('[data-field="coin-status"]');
  if (!statusEl) return;
  const staked = solStakedFor(card);
  const text = staked > 0 ? t("staking.solStakedLine", { amount: staked.toLocaleString(chartLocale(), { maximumFractionDigits: 4 }) }) : "";
  if (statusEl.textContent !== text) statusEl.textContent = text;
}

async function refreshSolStaked(card, force = false) {
  const key = balanceKey(card);
  const fresh = solStaked.key === key && Date.now() - solStaked.at < SOL_STAKED_TTL_MS;
  if (networkForCard(card) === "sol_mainnet" && (force || !fresh)) {
    try {
      const lamports = await invoke("sol_staked_total", { profileIndex: currentProfileIndex });
      if (balanceKey(card) === key) solStaked = { key, lamports, at: Date.now() };
    } catch (e) {
      console.error(e);
    }
  }
  renderSolStaked(card);
}

function shortAccount(text) {
  return `${text.slice(0, 6)}…${text.slice(-6)}`;
}

function renderSolStakeAccounts(context, status) {
  const list = document.getElementById("sol-stake-accounts");
  const label = (a) => a.validator_name ?? (a.validator ? shortAccount(a.validator) : shortAccount(a.address));
  const stateText = {
    activating: () => t("staking.solActivating", { eta: status.epoch_ends_in }),
    active: () => t("staking.solActive"),
    deactivating: () => t("staking.solDeactivating", { eta: status.epoch_ends_in }),
    inactive: () => t("staking.solInactive"),
    undelegated: () => t("staking.solUndelegated"),
  };
  list.replaceChildren(
    ...status.accounts.map((a) => {
      const item = document.createElement("li");
      item.className = "sol-stake-account";
      const main = document.createElement("div");
      main.className = "sol-stake-account-main";
      const amount = document.createElement("span");
      amount.className = "sol-stake-amount";
      amount.textContent = `${Number.parseFloat(a.amount).toLocaleString(chartLocale(), { maximumFractionDigits: 6 })} SOL`;
      const who = document.createElement("span");
      who.className = "muted";
      who.textContent = label(a);
      main.append(amount, who);
      const state = document.createElement("span");
      state.className = `sol-stake-state ${a.status}`;
      state.textContent = stateText[a.status]?.() ?? a.status;
      item.append(main, state);
      if (a.validator_flagged && (a.status === "active" || a.status === "activating")) {
        const warn = document.createElement("span");
        warn.className = "sol-stake-flag";
        warn.textContent = t("staking.solFlagged");
        item.append(warn);
      }
      const action = (a.status === "active" || a.status === "activating") && a.can_deactivate ? "deactivate" : (a.status === "inactive" || a.status === "undelegated") && !a.locked ? "withdraw" : null;
      if (action) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary";
        button.textContent = t(action === "deactivate" ? "staking.solStop" : "staking.solWithdraw");
        button.addEventListener("click", withBusyButton(button, () => runSolStake(action, a.address)));
        item.append(button);
      }
      return item;
    })
  );
  document.getElementById("sol-stake-status").textContent = status.accounts.length
    ? t("staking.solTotal", { amount: Number.parseFloat(status.total).toLocaleString(chartLocale(), { maximumFractionDigits: 6 }) })
    : t("staking.solNone");
  document.getElementById("sol-stake-min").textContent = t("staking.solMin", { min: status.min_delegation, reserve: status.rent_reserve });
  // Même lecture pour la carte SOL et la valeur totale.
  const key = balanceKey(context.card);
  solStaked = { key, lamports: status.total_lamports, at: Date.now() };
  renderSolStaked(context.card);
  updateFiatValue(context.card);
}

async function loadSolStakeStatus(context) {
  try {
    const status = await invoke("sol_stake_status", { profileIndex: context.profileIndex });
    if (solStakeContext === context) renderSolStakeAccounts(context, status);
  } catch (e) {
    if (solStakeContext !== context) return;
    document.getElementById("sol-stake-status").textContent = "";
    showError(document.getElementById("sol-stake-error"), String(e));
  }
}

async function openSolStakeModal(card) {
  const profile = currentProfile();
  const context = { profileIndex: profile ? profile.index : currentProfileIndex, card };
  solStakeContext = context;
  const liquid = liquidStakingFor("sol", "sol_mainnet");
  document.getElementById("sol-stake-liquid").classList.toggle("hidden", !liquid);
  const renderLiquid = () => {
    const apr = stakingAprs?.jitosol;
    document.getElementById("sol-stake-liquid-text").textContent = apr
      ? t("staking.solLiquidApr", { apr: apr.toLocaleString(chartLocale(), { maximumFractionDigits: 1 }) })
      : t("staking.solLiquidText");
  };
  renderLiquid();
  if (!stakingAprs) {
    loadStakingAprs().then(() => {
      if (solStakeContext === context) renderLiquid();
    });
  }
  document.getElementById("sol-stake-status").textContent = t("staking.solLoading");
  document.getElementById("sol-stake-accounts").replaceChildren();
  document.getElementById("sol-stake-min").textContent = "";
  document.getElementById("sol-stake-amount").value = "";
  document.getElementById("sol-stake-password").value = "";
  hideError(document.getElementById("sol-stake-error"));
  document.getElementById("sol-stake-success").classList.add("hidden");
  const select = document.getElementById("sol-stake-validator");
  select.replaceChildren();
  syncCustomSelect(select);
  solStakeModal.classList.remove("hidden");
  const [, validators] = await Promise.allSettled([loadSolStakeStatus(context), invoke("sol_validators")]);
  if (solStakeContext !== context) return;
  if (validators.status === "fulfilled") {
    select.replaceChildren(
      ...validators.value.map((v) => Object.assign(document.createElement("option"), {
        value: v.vote,
        textContent: t(v.apy ? "staking.solValidatorOption" : "staking.solValidatorOptionNoApy", {
          name: v.name ?? shortAccount(v.vote),
          commission: v.commission,
          apy: v.apy?.toLocaleString(chartLocale(), { maximumFractionDigits: 1 }),
        }),
      }))
    );
  } else {
    showError(document.getElementById("sol-stake-error"), String(validators.reason));
  }
  syncCustomSelect(select);
}

async function runSolStake(action, target) {
  const context = solStakeContext;
  if (!context) return;
  const errorEl = document.getElementById("sol-stake-error");
  const successEl = document.getElementById("sol-stake-success");
  hideError(errorEl);
  successEl.classList.add("hidden");
  const password = document.getElementById("sol-stake-password").value;
  const amount = action === "delegate" ? document.getElementById("sol-stake-amount").value.trim() : null;
  if (!password || !target || (action === "delegate" && !amount)) {
    showError(errorEl, t("wallet.allFieldsRequired"));
    return;
  }
  try {
    const tx = await invoke("sol_stake", { password, action, amount, target, profileIndex: context.profileIndex });
    successEl.textContent = t("staking.adaSent", { tx: `${tx.slice(0, 10)}…` });
    successEl.classList.remove("hidden");
    if (action === "delegate") document.getElementById("sol-stake-amount").value = "";
    // Relu une fois la transaction confirmée (quelques secondes).
    setTimeout(() => {
      if (solStakeContext === context) loadSolStakeStatus(context);
      else refreshSolStaked(context.card, true);
      refreshBalance(context.card);
    }, 5000);
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("sol-stake-password").value = "";
  }
}

{
  const delegateBtn = document.getElementById("sol-stake-delegate");
  delegateBtn.addEventListener("click", withBusyButton(delegateBtn, () => runSolStake("delegate", document.getElementById("sol-stake-validator").value)));
  const maxBtn = document.getElementById("sol-stake-max");
  maxBtn.addEventListener("click", withBusyButton(maxBtn, async () => {
    const context = solStakeContext;
    if (!context) return;
    hideError(document.getElementById("sol-stake-error"));
    try {
      const max = await invoke("sol_stake_max", { profileIndex: context.profileIndex });
      if (solStakeContext === context) document.getElementById("sol-stake-amount").value = max;
    } catch (e) {
      showError(document.getElementById("sol-stake-error"), String(e));
    }
  }));
  document.getElementById("sol-stake-liquid").addEventListener("click", () => {
    const context = solStakeContext;
    solStakeModal.classList.add("hidden");
    solStakeContext = null;
    if (context) openLiquidStaking(context.card);
  });
  document.getElementById("sol-stake-close").addEventListener("click", () => {
    solStakeModal.classList.add("hidden");
    solStakeContext = null;
  });
}

// Rendements annuels estimés (Rust, `staking_aprs`) : lus au déverrouillage,
// une fois par heure au plus. Affichés à côté de « Staker » (renderStakeChips),
// dans la note de « Convertir » et dans la fenêtre « Staker vos SOL ».
let stakingAprs = null;
let stakingAprsAt = 0;
// Taux affiché par carte : SOL → Jito, ETH → Lido, Cardano → moyenne du réseau.
const STAKE_RATE_SOURCE = { sol: "jitosol", evm: "steth", ada: "ada" };

function loadStakingAprs() {
  if (stakingAprs && Date.now() - stakingAprsAt < 60 * 60 * 1000) return Promise.resolve(stakingAprs);
  stakingAprsAt = Date.now();
  if (!stakingAprs) stakingAprs = {};
  return invoke("staking_aprs")
    .then((rates) => {
      stakingAprs = rates;
      renderStakeChips();
      renderStakingNote();
      return rates;
    })
    .catch((e) => {
      console.error(e);
      stakingAprsAt = 0;
    });
}

function renderStakeChips() {
  document.querySelectorAll(".stake-chip").forEach((chip) => {
    const rate = stakingAprs?.[STAKE_RATE_SOURCE[chip.closest(".wallet-card")?.dataset.coin]];
    const known = Number.isFinite(rate) && rate > 0;
    const el = chip.querySelector('[data-field="stake-rate"]');
    const text = known ? rate.toLocaleString(chartLocale(), { maximumFractionDigits: 1 }) : "";
    el.textContent = known ? (currentLang === "en" ? `${text}%` : `${text}\u00a0%`) : "";
    el.classList.toggle("hidden", !known);
  });
}

function renderStakingNote() {
  const el = document.getElementById("swap-staking-note");
  const pair = selectedSwapPair();
  const lst = { jitosol: "sol", steth: "evm" };
  let text = "";
  if (pair && !pair.via && lst[pair.to.coin] === pair.from.coin) {
    const apr = stakingAprs?.[pair.to.coin];
    // Taux annoncé (Jito, Lido) ; inconnu : message sans chiffre.
    text = apr
      ? t(pair.to.coin === "jitosol" ? "staking.noteSol" : "staking.noteEth", { apr: apr.toLocaleString(chartLocale(), { maximumFractionDigits: 1 }) })
      : t("staking.apr", { coin: COIN_SYMBOL[pair.from.coin] });
    if (!stakingAprs) loadStakingAprs();
  } else if (pair && !pair.via && lst[pair.from.coin] === pair.to.coin) {
    text = t("staking.unstake", { from: COIN_SYMBOL[pair.from.coin], to: COIN_SYMBOL[pair.to.coin] });
  }
  // Frais de l'app pour ce fournisseur et cette paire (Rust, `fees_bps`).
  const bps = pair?.feesBps?.[pair.protocol];
  if (text && bps != null) text += t("staking.fee", { fee: (bps / 100).toLocaleString(chartLocale(), { maximumFractionDigits: 2 }) });
  el.textContent = text;
  el.classList.toggle("hidden", !text);
}

function onSwapTargetChange() {
  fillSwapProviderOptions();
  updateSwapDestination();
  renderSwapAlerts();
  renderStakingNote();
  if (swapMaxActive) fillSwapMax();
}

// --- État des fournisseurs ----------------------------------------------------
// Messages orange (échange dégradé) ou rouge (impossible par ce fournisseur)
// sous son choix : service qui ne répond pas (Rust, `swap_health`), crypto
// suspendue par THORChain ou Maya (`swap_halts`), échange en cours
// anormalement long (suivi ici, gardé d'une ouverture de l'app à l'autre).
let swapHealth = [];
let swapSlow = [];
const PENDING_SWAPS_KEY = "pgp-wallet-pending-swaps";
// « Lent » : au-delà de 15 min, ou de 3 fois la durée annoncée. Oublié après
// 48 h (et à la réinitialisation ou la restauration du portefeuille) : au-delà,
// « lent en ce moment » ne voudrait plus rien dire.
const SLOW_SWAP_MIN_MS = 15 * 60 * 1000;
const PENDING_SWAP_MAX_MS = 48 * 60 * 60 * 1000;

function readPendingSwaps() {
  try {
    const list = JSON.parse(localStorage.getItem(PENDING_SWAPS_KEY) ?? "[]");
    return Array.isArray(list) ? list.filter((e) => Date.now() - e.started < PENDING_SWAP_MAX_MS) : [];
  } catch (e) {
    return [];
  }
}

function writePendingSwaps(list) {
  try {
    localStorage.setItem(PENDING_SWAPS_KEY, JSON.stringify(list.slice(-20)));
  } catch (e) {
    // Préférence d'affichage seulement : sans stockage, pas d'alerte de lenteur.
  }
}

function addPendingSwap(entry) {
  writePendingSwaps([...readPendingSwaps().filter((e) => e.id !== entry.id), entry]);
}

function removePendingSwap(id) {
  writePendingSwaps(readPendingSwaps().filter((e) => e.id !== id));
}

// Échanges en cours depuis trop longtemps : état relu chez le fournisseur ;
// ceux qui sont terminés sortent de la liste.
async function slowPendingSwaps() {
  const slow = [];
  for (const entry of readPendingSwaps()) {
    if (Date.now() - entry.started < Math.max(SLOW_SWAP_MIN_MS, 3 * (entry.expected_secs ?? 0) * 1000)) continue;
    let done = false;
    try {
      if (entry.kind === "swapkit") done = ["completed", "refunded", "failed"].includes(await invoke("swapkit_status", entry.status_args));
      if (entry.kind === "lifi") {
        const status = String(await invoke("lifi_status", entry.status_args));
        done = status === "FAILED" || status.startsWith("DONE");
      }
    } catch (e) {
      console.error(e);
    }
    if (done) removePendingSwap(entry.id);
    else slow.push(entry);
  }
  return slow;
}

function renderSwapAlerts() {
  const box = document.getElementById("swap-alerts");
  const pair = selectedSwapPair();
  const alerts = [];
  if (pair) {
    // Étape à faire maintenant (un fournisseur au choix), puis la seconde d'un
    // échange en deux étapes, depuis l'intermédiaire.
    const steps = new Map(pair.providers.map((protocol) => [protocol, [pair.from, pair.via ?? pair.to]]));
    if (pair.thenProtocol) steps.set(pair.thenProtocol, [...(steps.get(pair.thenProtocol) ?? []), pair.via, pair.to]);
    for (const [protocol, coins] of steps) {
      const halted = coins.filter(({ coin, network }) => (swapHalts[protocol] ?? []).includes(swapKey(coin, network))).map(({ coin }) => COIN_SYMBOL[coin] ?? coin);
      if (halted.length) alerts.push({ protocol, severity: "error", text: t("swap.alert.halted", { provider: SWAP_PROTOCOL_NAMES[protocol], coins: [...new Set(halted)].join(", ") }) });
      for (const issue of swapHealth.filter((i) => i.protocol === protocol)) {
        alerts.push({ protocol, severity: issue.severity, text: t("swap.alert.unreachable", { provider: issue.provider }) });
      }
      for (const entry of swapSlow.filter((e) => e.protocol === protocol)) {
        alerts.push({ protocol, severity: "warning", text: t("swap.alert.slow", { provider: entry.provider_name, minutes: Math.round((Date.now() - entry.started) / 60000) }) });
      }
    }
    // Fournisseur choisi d'abord, puis le rouge avant l'orange.
    const rank = (a) => (a.protocol === pair.protocol ? 0 : 2) + (a.severity === "error" ? 0 : 1);
    alerts.sort((a, b) => rank(a) - rank(b));
  }
  box.replaceChildren(
    ...alerts.map((alert) => {
      const line = document.createElement("p");
      line.className = `swap-alert ${alert.severity}`;
      line.textContent = alert.text;
      return line;
    })
  );
  box.classList.toggle("hidden", alerts.length === 0);
}

const SWAP_PROTOCOL_NAMES = { thorchain: "THORChain", maya: "Maya", jupiter: "Jupiter", cow: "CoW", lifi: "LI.FI", swapkit: "SwapKit", moonpay: "MoonPay Trade" };

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
        const note = p.via ? t("swap.viaTwoSteps", { via: swapShortLabel(p.via) }) : { jupiter: t("swap.viaJupiter"), cow: t("swap.viaCow"), lifi: t("swap.viaLifi"), moonpay: t("swap.viaMoonpay") }[p.protocol];
        option.textContent = swapAssetLabel(p.to_coin, p.to_network) + (note ? ` · ${note}` : "");
        return option;
      })
  );
  syncCustomSelect(toSelect);
  renderSwapAmount();
  loadSwapBalance();
  onSwapTargetChange();
}

// Montant à échanger en crypto OU dans la devise affichée, comme à l'envoi :
// seul le montant en crypto part dans le devis (puis dans l'aperçu et la
// boîte de confirmation de Windows). Quand la crypto de départ change ou que
// le cours est rafraîchi, le dernier champ saisi fait foi : 20 € restent
// 20 €, 0,1 reste 0,1.
const swapAmountInput = document.getElementById("swap-amount");
const swapFiatInput = document.getElementById("swap-amount-fiat");
let swapAmountTypedIn = "crypto";

const swapFromAsset = () => parseSwapKey(document.getElementById("swap-from-coin").value);

function syncSwapFiatFromCrypto() {
  const { coin, network } = swapFromAsset();
  const rate = fiatRate(coin, network);
  const crypto = parseAmountInput(swapAmountInput.value);
  swapFiatInput.value = rate && crypto != null ? fiatAmountText(crypto, rate) : "";
}

function syncSwapCryptoFromFiat() {
  const { coin, network } = swapFromAsset();
  const rate = fiatRate(coin, network);
  const fiat = parseAmountInput(swapFiatInput.value);
  swapAmountInput.value = rate && fiat != null ? cryptoAmountText(fiat, rate, coin) : "";
}

restrictToAmount(swapAmountInput, () => {
  swapAmountTypedIn = "crypto";
  syncSwapFiatFromCrypto();
  renderSwapBalance();
});
restrictToAmount(swapFiatInput, () => {
  swapAmountTypedIn = "fiat";
  syncSwapCryptoFromFiat();
  renderSwapBalance();
});

// « Max » : montant maximal pour l'échange choisi, frais de l'échange
// déduits (Rust, `swap_max_amount` : tout le solde d'un jeton ; pour la
// monnaie du réseau, le solde moins les frais au plus de ce fournisseur).
// Recalculé si le fournisseur ou la paire change tant que le montant n'a
// pas été retouché ; la vérification des fonds de l'échange fait foi.
let swapMaxActive = false;
const swapMaxBtn = document.getElementById("swap-max");

async function fillSwapMax() {
  const pair = selectedSwapPair();
  if (!pair || !swapContext) return;
  const context = swapContext;
  const errorEl = document.getElementById("swap-error");
  hideError(errorEl);
  swapMaxBtn.classList.add("busy");
  try {
    const amount = await invoke("swap_max_amount", {
      protocol: pair.protocol,
      fromCoin: pair.from.coin,
      fromNetwork: pair.from.network,
      toCoin: (pair.via ?? pair.to).coin,
      profileIndex: context.profileIndex,
    });
    if (swapContext !== context) return;
    swapAmountInput.value = amount;
    swapAmountTypedIn = "crypto";
    syncSwapFiatFromCrypto();
    renderSwapBalance();
    swapMaxActive = true;
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    swapMaxBtn.classList.remove("busy");
  }
}

swapMaxBtn.addEventListener("click", fillSwapMax);
// Montant tapé à la main : ce n'est plus le maximum.
for (const input of [swapAmountInput, swapFiatInput]) {
  input.addEventListener("input", () => {
    swapMaxActive = false;
  });
}

// Unités à droite des deux champs, champ en devise activé ou non, montants
// resynchronisés.
function renderSwapAmount() {
  const { coin, network } = swapFromAsset();
  setWithCoinIcon(document.getElementById("swap-amount-unit"), coin, COIN_SYMBOL[coin] ?? "");
  document.getElementById("swap-amount-fiat-unit").textContent = displayCurrency === "eur" ? "€" : "$";
  const rate = fiatRate(coin, network);
  swapFiatInput.disabled = !rate;
  swapFiatInput.placeholder = rate ? (currentLang === "fr" ? "0,00" : "0.00") : "—";
  if (swapAmountTypedIn === "fiat" && rate) syncSwapCryptoFromFiat();
  else syncSwapFiatFromCrypto();
  renderSwapBalance();
}

// Solde de la crypto de départ, sous le montant : relu sur son réseau à chaque
// choix (la carte peut afficher un autre réseau, ou un solde d'il y a 15 s).
// `{ key, text, amount }` une fois lu, `text: null` pendant la lecture,
// `failed` après un échec.
let swapBalance = null;

async function loadSwapBalance() {
  const { coin, network } = swapFromAsset();
  swapBalance = null;
  if (!coin) {
    renderSwapBalance(); // aucune crypto de départ proposée
    return;
  }
  const key = swapKey(coin, network);
  const address = addressForCoin(coin, network);
  swapBalance = { key, text: null };
  renderSwapBalance();
  let next;
  try {
    if (!address) throw new Error("adresse inconnue");
    const text = await fetchBalance(coin, network, address);
    next = { key, text, amount: Number.parseFloat(text) };
  } catch (e) {
    console.error(e);
    next = { key, failed: true };
  }
  if (swapBalance?.key !== key) return; // autre crypto choisie entre-temps
  swapBalance = next;
  renderSwapBalance();
}

// « Disponible : 0.500000 ETH (≈ 1 234,56 €) », signalé quand le montant
// saisi le dépasse (simple aide : les frais du réseau ne sont pas déduits).
function renderSwapBalance() {
  const el = document.getElementById("swap-balance");
  el.classList.remove("swap-balance-short");
  if (!swapBalance) {
    el.textContent = "";
    return;
  }
  if (swapBalance.failed) {
    el.textContent = t("swap.balanceUnavailable");
    return;
  }
  const { coin, network } = parseSwapKey(swapBalance.key);
  if (swapBalance.text == null) {
    el.textContent = t("swap.balance", { balance: "…" });
    return;
  }
  const rate = fiatRate(coin, network);
  const fiat = rate && Number.isFinite(swapBalance.amount) ? ` (${formatUsdApprox(swapBalance.amount * rate.price)})` : "";
  el.textContent = t("swap.balance", { balance: `${swapBalance.text} ${COIN_SYMBOL[coin] ?? ""}${fiat}` });
  const amount = parseAmountInput(swapAmountInput.value);
  if (amount != null && Number.isFinite(swapBalance.amount) && amount > swapBalance.amount) {
    el.textContent += ` — ${t("swap.balanceShort")}`;
    el.classList.add("swap-balance-short");
  }
}

document.getElementById("swap-from-coin").addEventListener("change", updateSwapToOptions);

function openSwapModal(card, preset = null) {
  const profile = currentProfile();
  swapContext = { card, profileIndex: profile ? profile.index : currentProfileIndex };
  swapAmountInput.value = preset?.amount ?? "";
  swapFiatInput.value = "";
  swapAmountTypedIn = "crypto";
  swapMaxActive = false;
  swapBalance = null;
  swapHealth = [];
  swapSlow = [];
  invoke("swap_health")
    .then((issues) => {
      if (swapContext?.card !== card) return;
      swapHealth = issues;
      renderSwapAlerts();
    })
    .catch((e) => console.error(e));
  slowPendingSwaps()
    .then((slow) => {
      if (swapContext?.card !== card) return;
      swapSlow = slow;
      renderSwapAlerts();
    })
    .catch((e) => console.error(e));
  swapHalts = {};
  invoke("swap_halts")
    .then((halts) => {
      if (swapContext?.card !== card) return; // fenêtre fermée ou rouverte entre-temps
      swapHalts = halts;
      onSwapTargetChange();
    })
    .catch((e) => console.error(e));
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
// MoonPay Trade sur un même réseau EVM : routeur, achats sur l'adresse du
// profil (vérifié par simulation).
const isSameWalletSwap = (pair) => pair?.protocol === "jupiter" || pair?.protocol === "cow" || (pair?.protocol === "moonpay" && pair.from?.network === pair.to?.network);

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
document.getElementById("swap-provider").addEventListener("change", renderSwapAlerts);
document.getElementById("swap-provider").addEventListener("change", renderStakingNote);
document.getElementById("swap-provider").addEventListener("change", () => {
  if (swapMaxActive) fillSwapMax();
});

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
    } else if (step.protocol === "swapkit") {
      // SwapKit : meilleur devis de NEAR Intents et de Chainflip ; le dépôt
      // n'est ouvert, puis confirmé par le fournisseur lui-même, qu'à la
      // confirmation.
      const quote = await invoke("get_swapkit_quote", { fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, profileIndex: swapContext.profileIndex });
      const symbol = COIN_SYMBOL[toCoin] || toCoin.toUpperCase();
      receivingText = `≈ ${quote.expected_out} ${symbol}`;
      receivedAmount = Number.parseFloat(quote.expected_out);
      document.getElementById("swap-preview-min").textContent = `${quote.min_out} ${symbol}`;
      document.getElementById("swap-preview-fees-label").textContent = t("swap.previewSwapkitRoute");
      document.getElementById("swap-preview-fees").textContent = t("swap.swapkitRoute", {
        provider: quote.provider,
        fee: (quote.fee_bps / 100).toLocaleString(chartLocale(), { minimumFractionDigits: 2 }),
        minutes: Math.max(1, Math.ceil(quote.duration_secs / 60)),
      });
      document.getElementById("swap-preview-destination").textContent = destination;
      minRow.classList.remove("hidden");
      destRow.classList.remove("hidden");
      feeRow.classList.remove("hidden");
    } else if (step.protocol === "moonpay") {
      // MoonPay Trade : sur un même réseau EVM, routeur simulé à la
      // confirmation (achats sur l'adresse du profil) ; ailleurs, dépôt dont
      // la livraison est gérée par MoonPay Trade — dit ici et dans la boîte.
      const quote = await invoke("get_moonpay_quote", { fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, profileIndex: swapContext.profileIndex });
      const symbol = COIN_SYMBOL[toCoin] || toCoin.toUpperCase();
      receivingText = `≈ ${quote.expected_out} ${symbol}`;
      receivedAmount = Number.parseFloat(quote.expected_out);
      document.getElementById("swap-preview-min").textContent = `${quote.min_out} ${symbol}`;
      document.getElementById("swap-preview-fees-label").textContent = t("swap.previewMoonpayRoute");
      document.getElementById("swap-preview-fees").textContent = t(quote.verified ? "swap.moonpayRoute" : "swap.moonpayRouteUnverified", {
        fee: (quote.fee_bps / 100).toLocaleString(chartLocale(), { minimumFractionDigits: 2 }),
        minutes: Math.max(1, Math.ceil(quote.duration_secs / 60)),
      });
      document.getElementById("swap-preview-destination").textContent = destination;
      minRow.classList.remove("hidden");
      destRow.classList.toggle("hidden", quote.verified);
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
    } else if (step.protocol === "moonpay") {
      const sent = await invoke("moonpay_swap_transaction", { password, fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, profileIndex });
      successEl.textContent = sent.deposit
        ? t("swap.moonpayDepositSent", { tx: sent.tx_hash, minutes: Math.max(1, Math.ceil(sent.duration_secs / 60)) })
        : t("swap.moonpaySent", { tx: sent.tx_hash });
      successEl.classList.remove("hidden");
    } else if (step.protocol === "swapkit") {
      const sent = await invoke("swapkit_swap_transaction", { password, fromCoin, fromNetwork, toCoin, toNetwork, amount, destination, profileIndex });
      trackSwapkitSwap(successEl, sent);
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
  const pendingId = `lifi:${transfer.tx_hash}`;
  addPendingSwap({ id: pendingId, kind: "lifi", protocol: "lifi", provider_name: "LI.FI", started, expected_secs: transfer.duration_secs ?? 0, status_args: { txHash: transfer.tx_hash, fromChain: transfer.from_chain, toChain: transfer.to_chain } });
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
      removePendingSwap(pendingId);
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

// Échange SwapKit : étape lue auprès du fournisseur (NEAR Intents ou
// Chainflip) toutes les 20 s, jusqu'à l'arrivée, au remboursement ou à
// l'échec (3 h au plus).
const SWAPKIT_POLL_MS = 20000;
const SWAPKIT_MAX_WAIT_MS = 3 * 60 * 60 * 1000;

function trackSwapkitSwap(successEl, sent) {
  const text = document.createElement("span");
  const show = (state) => {
    text.textContent = t(`swap.swapkit.${state}`, { provider: sent.provider_name, tx: sent.tx_hash });
  };
  show("sent");
  successEl.replaceChildren(text);
  successEl.classList.remove("hidden");
  const started = Date.now();
  const pendingId = `swapkit:${sent.deposit_address}`;
  addPendingSwap({ id: pendingId, kind: "swapkit", protocol: "swapkit", provider_name: sent.provider_name, started, expected_secs: 0, status_args: { provider: sent.provider, channelId: sent.channel_id, depositAddress: sent.deposit_address } });
  const poll = async () => {
    let state = null;
    try {
      state = await invoke("swapkit_status", { provider: sent.provider, channelId: sent.channel_id, depositAddress: sent.deposit_address });
    } catch (e) {
      console.error(e);
    }
    if (state === "completed" || state === "refunded" || state === "failed") {
      show(state);
      removePendingSwap(pendingId);
      refreshAllBalances();
      return;
    }
    if (state === "processing") show("processing");
    if (Date.now() - started > SWAPKIT_MAX_WAIT_MS) {
      show("unknown");
      return;
    }
    setTimeout(poll, SWAPKIT_POLL_MS);
  };
  setTimeout(poll, SWAPKIT_POLL_MS);
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
  // Autres réseaux (Arbitrum, Zcash, XRP…) : même libellé que sur les cartes.
  const label = t(`net.${network}`);
  return label === `net.${network}` ? network : label;
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

// Nom court d'un réseau pour une adresse enregistrée (« Ethereum », « Base »,
// « XRP Ledger ») ; réseaux de test et cas à part : libellé complet.
function contactNetworkLabel(network) {
  if (network === "btc_mainnet") return "Bitcoin";
  const label = t(`net.${network}`);
  if (network.endsWith("_mainnet") && label !== `net.${network}`) return label.split(" — ")[0];
  return externalNetworkLabel(network);
}

// Menu « Réseau » qui suit l'adresse saisie (carnet d'adresses, wallets
// externes) : seulement les réseaux où elle est valide, d'après Rust
// (`address_networks`, mêmes parseurs que l'envoi), parmi ceux que
// `allowed` accepte ; choisi d'office s'il n'y en a qu'un. Adresse vide ou
// non reconnue : le menu le dit. Renvoie la fonction de mise à jour.
function networkFollowsAddress(input, select, allowed) {
  let check = 0;
  const refresh = async () => {
    const address = input.value.trim();
    const current = select.value;
    const mine = ++check;
    let networks = [];
    if (address) {
      try {
        networks = await invoke("address_networks", { address });
      } catch (e) {
        console.error(e);
      }
    }
    if (mine !== check) return;
    networks = networks.filter(allowed);
    const option = (value, text) => Object.assign(document.createElement("option"), { value, textContent: text });
    if (networks.length) {
      select.replaceChildren(...networks.map((network) => option(network, contactNetworkLabel(network))));
      select.value = networks.includes(current) ? current : networks[0];
    } else {
      select.replaceChildren(option("", t(address ? "addressBook.networkUnknown" : "addressBook.networkFirst")));
    }
    const wrapper = select.closest(".custom-select");
    wrapper.classList.toggle("is-empty", networks.length === 0);
    wrapper.querySelector(".custom-select-trigger").disabled = networks.length < 2;
    syncCustomSelect(select);
  };
  input.addEventListener("input", refresh);
  return refresh;
}

// --- Modale ajout d'un wallet externe ---------------------------------------
// Réseaux suivis (soldes lisibles), d'après le menu d'origine.
const EXTERNAL_WALLET_NETWORKS = [...document.getElementById("external-wallet-network").options].map((o) => o.value);
const refreshExternalWalletNetwork = networkFollowsAddress(
  document.getElementById("external-wallet-address"),
  document.getElementById("external-wallet-network"),
  (network) => EXTERNAL_WALLET_NETWORKS.includes(network)
);

document.getElementById("add-external-wallet-btn").addEventListener("click", () => {
  document.getElementById("external-wallet-label").value = "";
  document.getElementById("external-wallet-address").value = "";
  refreshExternalWalletNetwork();
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
  meta.textContent = `${contactNetworkLabel(entry.network)} · ${entry.address}`;
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

// « USDC — Solana » : ancien réseau du carnet, plus proposé (une adresse
// Solana sert pour le SOL comme pour ses jetons) ; ses entrées restent lues.
const refreshAddressBookNetwork = networkFollowsAddress(
  document.getElementById("address-book-address"),
  document.getElementById("address-book-network"),
  (network) => network !== "usdc_solana"
);

document.getElementById("add-address-book-btn").addEventListener("click", () => {
  document.getElementById("address-book-label").value = "";
  document.getElementById("address-book-address").value = "";
  refreshAddressBookNetwork();
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
  if (!network) {
    showError(errorEl, t("addressBook.networkUnknown"));
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
// contacts dont l'adresse a le format du réseau de l'envoi (voir
// addressFamily), masqué s'il n'y en a aucun ni d'autre profil. Choisir une
// entrée remplit juste le champ adresse,
// le sélecteur repart ensuite sur son placeholder (action, pas un état persistant).
// Destinataires proposés à l'envoi : contacts du carnet, puis les AUTRES
// profils de ce portefeuille (leur adresse pour la même crypto et le même
// réseau). La boîte de confirmation native nomme le profil reconnu, d'après
// les adresses dérivées côté Rust — jamais d'après ce menu.
// Format d'adresse d'un réseau : tous les EVM ont le même ; les réseaux
// Solana aussi (« USDC — Solana » compris) ; chaque autre a le sien.
function addressFamily(network) {
  if (isEvmNetwork(network)) return "evm";
  if (network === "usdc_solana" || network.startsWith("sol_")) return "sol";
  return network;
}

function refreshSendAddressBookPicker(coin, network, sourceProfileIndex) {
  const wrapper = document.getElementById("send-address-book-picker");
  const select = document.getElementById("send-address-book-select");
  const matches = addressBookCache.filter((entry) => addressFamily(entry.network) === addressFamily(network));
  const profiles = profilesCache
    .filter((profile) => profile.index !== sourceProfileIndex)
    .map((profile) => ({ profile, address: addressOfProfile(profile, coin, network) }))
    .filter(({ address }) => address);

  select.replaceChildren(Object.assign(document.createElement("option"), { value: "", textContent: t(profiles.length ? "send.pickPlaceholder" : "addressBook.pickPlaceholder") }));
  const group = (labelKey, items) => {
    if (items.length === 0) return;
    const optgroup = Object.assign(document.createElement("optgroup"), { label: t(labelKey) });
    optgroup.append(...items);
    select.appendChild(optgroup);
  };
  group(
    "send.pickBook",
    matches.map((entry) => {
      // Contact enregistré pour un autre réseau du même format (Ethereum pour
      // un envoi sur Base…) : dit, une plateforme d'échange pouvant ne pas
      // accepter ce réseau-là.
      const other = entry.network === network ? "" : ` (${t("send.bookOtherNetwork", { network: contactNetworkLabel(entry.network) })})`;
      return Object.assign(document.createElement("option"), { value: `book:${entry.id}`, textContent: `${entry.label} — ${entry.address}${other}` });
    })
  );
  group(
    "send.pickProfiles",
    profiles.map(({ profile, address }) => {
      const shown = address.length > 24 ? `${address.slice(0, 10)}…${address.slice(-8)}` : address;
      return Object.assign(document.createElement("option"), { value: `profile:${profile.index}`, textContent: `${profile.label} — ${shown}` });
    })
  );
  syncCustomSelect(select);
  wrapper.classList.toggle("hidden", matches.length === 0 && profiles.length === 0);
}

document.getElementById("send-address-book-select").addEventListener("change", (e) => {
  const [kind, id] = e.target.value.split(":");
  if (kind === "book") {
    const entry = addressBookCache.find((entry) => String(entry.id) === id);
    if (entry) document.getElementById("send-to").value = entry.address;
  } else if (kind === "profile" && sendContext) {
    const profile = profilesCache.find((p) => String(p.index) === id);
    const address = addressOfProfile(profile, sendContext.coin, networkForCard(sendContext.card));
    if (address) document.getElementById("send-to").value = address;
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
      // Clé gardée : relibellé au changement de langue (« 1 an » → « 1y »).
      button.dataset.i18n = `charts.range.${range}`;
      button.textContent = t(button.dataset.i18n);
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
    if (!view.chartEl.firstChild) {
      const loading = mutedParagraph(t("charts.loading"));
      loading.dataset.i18n = "charts.loading";
      view.chartEl.replaceChildren(loading);
    }
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
  // Adresse illisible (service saturé ou en panne) : courbe sans elle, dit
  // en premier (voir core/src/portfolio.rs).
  if (result.unavailable?.length) notes.push(t("charts.unavailable", { list: result.unavailable.join(", ") }));
  if (result.loading) {
    const count = result.transactions_read;
    notes.push(count ? t("charts.loadingHistory", { count: count.toLocaleString(chartLocale()) }) : t("charts.loadingHistoryStart"));
  }
  else if (result.since) notes.push(t("charts.since", { date: new Date(result.since * 1000).toLocaleDateString(chartLocale()) }));
  if (result.approximate && !result.loading) notes.push(t("charts.approximate"));
  // Réseau sans historique utilisable (BNB Chain sans clé NodeReal) : solde actuel compté
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
