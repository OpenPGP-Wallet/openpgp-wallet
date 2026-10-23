import { renderLineChart, renderSparkline } from "./charts.js";

// --- Wallet cryptos ----------------------------------------------------------
//
// One card per crypto, one or more networks per card (network menu). `family`:
// address format and send path. "evm": the same address on every EVM network,
// native transfer through `send_transaction` (the backend validates the network
// and shows the confirmation). The first 4 have their card in index.html; the
// others are generated below, with exactly the same structure (the rest of the
// code treats them all the same way). `decimals`: decimals shown for the send
// window's quick amounts.
const ASSETS = [
  { coin: "evm", name: "Ethereum", symbol: "ETH", family: "evm", icon: "/assets/eth.svg", gecko: "ethereum", decimals: 6, chart: "ETH", networks: ["evm_mainnet", "arbitrum_mainnet", "base_mainnet", "evm_sepolia"] },
  { coin: "btc", name: "Bitcoin", symbol: "BTC", family: "btc", icon: "/assets/btc.webp", gecko: "bitcoin", decimals: 8, chart: "BTC", networks: ["btc_mainnet", "btc_testnet"] },
  { coin: "sol", name: "Solana", symbol: "SOL", family: "sol", icon: "/assets/sol.png", gecko: "solana", decimals: 9, chart: "SOL", networks: ["sol_mainnet", "sol_devnet"] },
  // USDC: SPL token on Solana (the historical USDC path, core/src/sol_spl.rs) and
  // ERC-20 on Ethereum, Base and Arbitrum (token registry).
  { coin: "usdc", name: "USDC", symbol: "USDC", token: true, icon: "/assets/usdc.png", gecko: "usd-coin", decimals: 6, unitDecimals: 6, chart: "USDC", networks: ["sol_mainnet", "evm_mainnet", "base_mainnet", "arbitrum_mainnet"], contracts: { sol_mainnet: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", evm_mainnet: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", base_mainnet: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", arbitrum_mainnet: "0xaf88d065e77c8cc2239327c5edb3a432268e5831" } },
  { coin: "bnb", name: "BNB", symbol: "BNB", family: "evm", icon: "/assets/bnb.png", gecko: "binancecoin", decimals: 6, chart: "BNB", networks: ["bsc_mainnet"] },
  { coin: "avax", name: "Avalanche", symbol: "AVAX", family: "evm", icon: "/assets/avax.png", gecko: "avalanche-2", decimals: 6, chart: "AVAX", networks: ["avax_mainnet"] },
  { coin: "pol", name: "Polygon", symbol: "POL", family: "evm", icon: "/assets/pol.png", gecko: "polygon-ecosystem-token", decimals: 6, chart: "POL", networks: ["polygon_mainnet"] },
  { coin: "zec", name: "Zcash", symbol: "ZEC", family: "zec", icon: "/assets/zec.png", gecko: "zcash", decimals: 8, chart: "ZEC", networks: ["zec_mainnet"] },
  // Shielded Zcash funds (u1 address): their own card, next to the transparent (t1)
  // card. `nameKey`: translated name (see `assetName`).
  { coin: "zecs", name: "Zcash protégé", nameKey: "coin.zecsName", symbol: "ZEC", family: "zecs", icon: "/assets/zec-shielded.svg", gecko: "zcash", decimals: 8, chart: "ZEC", networks: ["zec_shielded"] },
  { coin: "xmr", name: "Monero", symbol: "XMR", family: "xmr", icon: "/assets/xmr.png", gecko: "monero", decimals: 6, chart: "XMR", networks: ["xmr_mainnet"] },
  { coin: "doge", name: "Dogecoin", symbol: "DOGE", family: "doge", icon: "/assets/doge.png", gecko: "dogecoin", decimals: 8, chart: "DOGE", networks: ["doge_mainnet"] },
  { coin: "trx", name: "Tron", symbol: "TRX", family: "trx", icon: "/assets/trx.png", gecko: "tron", decimals: 6, chart: "TRX", networks: ["tron_mainnet"] },
  { coin: "xrp", name: "XRP", symbol: "XRP", family: "xrp", icon: "/assets/xrp.svg", gecko: "ripple", decimals: 6, chart: "XRP", networks: ["xrp_mainnet"] },
  { coin: "xlm", name: "Stellar", symbol: "XLM", family: "xlm", icon: "/assets/xlm.jpg", iconRound: true, gecko: "stellar", decimals: 7, chart: "XLM", networks: ["xlm_mainnet"] },
  // NEAR: 24 decimals on-chain; 6 are enough for input (Max returns the exact amount).
  { coin: "near", name: "NEAR", symbol: "NEAR", family: "near", icon: "/assets/near.jpg", iconRound: true, gecko: "near", decimals: 6, chart: "NEAR", networks: ["near_mainnet"] },
  { coin: "ada", name: "Cardano", symbol: "ADA", family: "ada", icon: "/assets/ada.png", gecko: "cardano", decimals: 6, chart: "ADA", networks: ["ada_mainnet"] },
  { coin: "stx", name: "Stacks", symbol: "STX", family: "stx", icon: "/assets/stx.png", gecko: "blockstack", decimals: 6, chart: "STX", networks: ["stx_mainnet"] },
  { coin: "tao", name: "Bittensor", symbol: "TAO", family: "tao", icon: "/assets/tao.jpg", iconRound: true, gecko: "bittensor", decimals: 9, chart: "TAO", networks: ["tao_mainnet"] },
  // Tokens (`token: true`): contracts and mints taken from core/src/tokens.rs. ONLY
  // the Rust registry counts for a send (the UI only sends the identifier and the
  // network); these are only used for payment requests (QR). Test
  // `frontend_token_contracts_match_the_registry` (lib.rs).
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
  // xStocks tokenized shares (`stock: true`, Solana, Token-2022 program,
  // core/src/tokens.rs): hidden by default, prices and charts from Jupiter per
  // displayed unit (`chart`: uppercase symbol, see price_history.rs), balances read
  // in one request (get_stock_balances). Official token logos (Backed metadata).
  { coin: "tslax", name: "Tesla xStock", symbol: "TSLAx", token: true, stock: true, icon: "/assets/xstocks/tslax.png", gecko: "xstock:tslax", decimals: 6, unitDecimals: 8, chart: "TSLAX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB" } },
  { coin: "nvdax", name: "NVIDIA xStock", symbol: "NVDAx", token: true, stock: true, icon: "/assets/xstocks/nvdax.png", gecko: "xstock:nvdax", decimals: 6, unitDecimals: 8, chart: "NVDAX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xsc9qvGR1efVDFGLrVsmkzv3qi45LTBjeUKSPmx9qEh" } },
  { coin: "aaplx", name: "Apple xStock", symbol: "AAPLx", token: true, stock: true, icon: "/assets/xstocks/aaplx.png", gecko: "xstock:aaplx", decimals: 6, unitDecimals: 8, chart: "AAPLX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsbEhLAtcf6HdfpFZ5xEMdqW8nfAvcsP5bdudRLJzJp" } },
  { coin: "msftx", name: "Microsoft xStock", symbol: "MSFTx", token: true, stock: true, icon: "/assets/xstocks/msftx.png", gecko: "xstock:msftx", decimals: 6, unitDecimals: 8, chart: "MSFTX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XspzcW1PRtgf6Wj92HCiZdjzKCyFekVD8P5Ueh3dRMX" } },
  { coin: "googlx", name: "Alphabet xStock", symbol: "GOOGLx", token: true, stock: true, icon: "/assets/xstocks/googlx.png", gecko: "xstock:googlx", decimals: 6, unitDecimals: 8, chart: "GOOGLX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsCPL9dNWBMvFtTmwcCA5v3xWPSMEBCszbQdiLLq6aN" } },
  { coin: "amznx", name: "Amazon.com xStock", symbol: "AMZNx", token: true, stock: true, icon: "/assets/xstocks/amznx.png", gecko: "xstock:amznx", decimals: 6, unitDecimals: 8, chart: "AMZNX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xs3eBt7uRfJX8QUs4suhyU8p2M6DoUDrJyWBa8LLZsg" } },
  { coin: "metax", name: "Meta xStock", symbol: "METAx", token: true, stock: true, icon: "/assets/xstocks/metax.png", gecko: "xstock:metax", decimals: 6, unitDecimals: 8, chart: "METAX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xsa62P5mvPszXL1krVUnU5ar38bBSVcWAB6fmPCo5Zu" } },
  { coin: "spyx", name: "SP500 xStock", symbol: "SPYx", token: true, stock: true, icon: "/assets/xstocks/spyx.png", gecko: "xstock:spyx", decimals: 6, unitDecimals: 8, chart: "SPYX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W" } },
  { coin: "qqqx", name: "Nasdaq xStock", symbol: "QQQx", token: true, stock: true, icon: "/assets/xstocks/qqqx.png", gecko: "xstock:qqqx", decimals: 6, unitDecimals: 8, chart: "QQQX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xs8S1uUs1zvS2p7iwtsG3b6fkhpvmwz4GYU3gWAmWHZ" } },
  { coin: "gldx", name: "Gold xStock", symbol: "GLDx", token: true, stock: true, icon: "/assets/xstocks/gldx.png", gecko: "xstock:gldx", decimals: 6, unitDecimals: 8, chart: "GLDX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xsv9hRk1z5ystj9MhnA7Lq4vjSsLwzL2nxrwmwtD3re" } },
  { coin: "coinx", name: "Coinbase xStock", symbol: "COINx", token: true, stock: true, icon: "/assets/xstocks/coinx.png", gecko: "xstock:coinx", decimals: 6, unitDecimals: 8, chart: "COINX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xs7ZdzSHLU9ftNJsii5fCeJhoRWSC32SQGzGQtePxNu" } },
  { coin: "mstrx", name: "MicroStrategy xStock", symbol: "MSTRx", token: true, stock: true, icon: "/assets/xstocks/mstrx.png", gecko: "xstock:mstrx", decimals: 6, unitDecimals: 8, chart: "MSTRX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsP7xzNPvEHS1m6qfanPUGjNmdnmsLKEoNAnHjdxxyZ" } },
  { coin: "crclx", name: "Circle xStock", symbol: "CRCLx", token: true, stock: true, icon: "/assets/xstocks/crclx.png", gecko: "xstock:crclx", decimals: 6, unitDecimals: 8, chart: "CRCLX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsueG8BtpquVJX9LVLLEGuViXUungE6WmK5YZ3p3bd1" } },
  { coin: "hoodx", name: "Robinhood xStock", symbol: "HOODx", token: true, stock: true, icon: "/assets/xstocks/hoodx.png", gecko: "xstock:hoodx", decimals: 6, unitDecimals: 8, chart: "HOODX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsvNBAYkrDRNhA7wPHQfX3ZUXZyZLdnCQDfHZ56bzpg" } },
  { coin: "pltrx", name: "Palantir xStock", symbol: "PLTRx", token: true, stock: true, icon: "/assets/xstocks/pltrx.png", gecko: "xstock:pltrx", decimals: 6, unitDecimals: 8, chart: "PLTRX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsoBhf2ufR8fTyNSjqfU71DYGaE6Z3SUGAidpzriAA4" } },
  { coin: "mcdx", name: "McDonald's xStock", symbol: "MCDx", token: true, stock: true, icon: "/assets/xstocks/mcdx.png", gecko: "xstock:mcdx", decimals: 6, unitDecimals: 8, chart: "MCDX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2" } },
  { coin: "gmex", name: "Gamestop xStock", symbol: "GMEx", token: true, stock: true, icon: "/assets/xstocks/gmex.png", gecko: "xstock:gmex", decimals: 6, unitDecimals: 8, chart: "GMEX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xsf9mBktVB9BSU5kf4nHxPq5hCBJ2j2ui3ecFGxPRGc" } },
  { coin: "brkbx", name: "Berkshire Hathaway xStock", symbol: "BRK.Bx", token: true, stock: true, icon: "/assets/xstocks/brkbx.png", gecko: "xstock:brkbx", decimals: 6, unitDecimals: 8, chart: "BRK.BX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xs6B6zawENwAbWVi7w92rjazLuAr5Az59qgWKcNb45x" } },
  { coin: "spcxx", name: "SpaceX xStock", symbol: "SPCXx", token: true, stock: true, icon: "/assets/xstocks/spcxx.png", gecko: "xstock:spcxx", decimals: 6, unitDecimals: 8, chart: "SPCXX", networks: ["sol_mainnet"], contracts: { sol_mainnet: "Xs3oZwbHvqis4NYcf4YKWmEia2eC84wSiVrcYcTqpH8" } },
];
// Ethereum-compatible networks added by the user (Settings, "Custom RPC"): one
// card each, like one of the app's cryptos (same address as ETH), with no logo,
// price or swap. Read before the cards are built; adding or removing one reloads
// the UI.
const CUSTOM_NETWORKS = await window.__TAURI__.core.invoke("list_custom_networks").catch((e) => {
  console.error(e);
  return [];
});
for (const net of CUSTOM_NETWORKS) {
  ASSETS.push({ coin: net.id, name: net.name, symbol: net.symbol, family: "evm", icon: null, gecko: null, decimals: 6, chart: null, networks: [net.id], custom: true });
}
// Network name (cards, menus, send preview): label "net.<id>".
const CUSTOM_NETWORK_LABELS = Object.fromEntries(CUSTOM_NETWORKS.map((net) => [`net.${net.id}`, net.name]));

const ASSET_BY_COIN = Object.fromEntries(ASSETS.map((asset) => [asset.coin, asset]));
// The first crypto for each CoinGecko identifier (Zcash, not shielded Zcash, which
// has the same price): markets and charts.
const ASSET_BY_GECKO = Object.fromEntries([...ASSETS].reverse().map((asset) => [asset.gecko, asset]));

// Display name of a crypto: translated for those that have one ("Shielded Zcash"),
// otherwise its own name. Not at module load time (translations are declared
// further down): elements created at that point carry `data-i18n`.
function assetName(asset) {
  return asset.nameKey ? t(asset.nameKey) : asset.name;
}
// Native currency of each network (ETH on Ethereum, Arbitrum and Base; BNB on BNB
// Chain…): unit and price for external wallets and hardware accounts.
const NATIVE_ASSET_BY_NETWORK = Object.fromEntries(
  ASSETS.filter((asset) => !asset.token).flatMap((asset) => asset.networks.map((network) => [network, asset]))
);

// Logo of a crypto, in front of its name wherever it appears (titles, menus,
// lists, previews); `null` for an unknown identifier.
function coinIconEl(coin) {
  const asset = ASSET_BY_COIN[coin];
  if (!asset) return null;
  if (!asset.icon) return letterIcon(asset, "coin-icon-inline");
  const img = document.createElement("img");
  img.src = asset.icon;
  img.alt = "";
  img.className = "coin-icon-inline";
  if (asset.iconRound) img.classList.add("coin-icon-round");
  if (coin === "sol") img.classList.add("coin-icon-inline-sol");
  return img;
}

// Crypto without a logo (added network): a badge with the first letter of its
// symbol.
function letterIcon(asset, className) {
  const span = document.createElement("span");
  span.className = `${className} coin-icon-letter`;
  span.setAttribute("aria-hidden", "true");
  span.textContent = asset.symbol.slice(0, 1).toUpperCase();
  return span;
}

// Logo of a network: that of its native crypto (Arbitrum: its own logo; Base and
// Sepolia: Ethereum's). `null` for an unknown network.
function coinForNetwork(network) {
  if (network === "arbitrum_mainnet") return "arb";
  return ASSETS.find((asset) => !asset.token && asset.networks.includes(network))?.coin ?? null;
}

// Replaces the content of `el` with the logo of `coin` followed by `text`.
function setWithCoinIcon(el, coin, text) {
  const icon = coinIconEl(coin);
  el.replaceChildren(...(icon ? [icon] : []), document.createTextNode(text));
}

// Swaps ("Convert"): possible pairs, read from Rust at startup (`swap_pairs`,
// core/src/swap_routes.rs): [{ from_coin, from_network, to_coin, to_network,
// protocol, via, then_protocol }].
let swapPairs = [];
// Two-step swap in progress (see "tracking the intermediate crypto").
let pendingRoute = null;
let routePollTimer = null;

const ICON_CONVERT = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 8h13l-3-3M20 16H7l3 3" /></svg>`;

// Amount field: digits and a single decimal separator (dot or comma), filtered as
// you type rather than refused afterwards, so an amount cannot contain anything
// else. Listener in the capture phase: it runs before the ones that read the value
// (QR, conversion).
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

// Network → address format: the same address on every EVM network, one Solana
// address (SOL and SPL tokens), Bitcoin separate.
function isEvmNetwork(network) {
  return network in EVM_CHAIN_IDS || CUSTOM_NETWORKS.some((net) => net.id === network);
}

// A token that goes through the Rust registry
// (get_token_balance/send_token_transaction): every token except USDC on Solana,
// which keeps its historical path.
function usesTokenRegistry(coin, network) {
  return ASSET_BY_COIN[coin]?.token === true && !(coin === "usdc" && network === "sol_mainnet");
}

// EVM networks: chain ID (EIP-681 payment request). The same values as
// core/src/wallet_flow.rs::EVM_NETWORKS.
const EVM_CHAIN_IDS = {
  evm_mainnet: 1,
  evm_sepolia: 11155111,
  arbitrum_mainnet: 42161,
  base_mainnet: 8453,
  bsc_mainnet: 56,
  avax_mainnet: 43114,
  polygon_mainnet: 137,
};
for (const net of CUSTOM_NETWORKS) EVM_CHAIN_IDS[net.id] = net.chain_id;

const ICON_COPY = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" /></svg>`;
const ICON_QR = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true"><path d="M3 3h6v6H3z" fill="none" stroke="currentColor" stroke-width="1.6" /><rect x="5.2" y="5.2" width="1.6" height="1.6" /><path d="M15 3h6v6h-6z" fill="none" stroke="currentColor" stroke-width="1.6" /><rect x="17.2" y="5.2" width="1.6" height="1.6" /><path d="M3 15h6v6H3z" fill="none" stroke="currentColor" stroke-width="1.6" /><rect x="5.2" y="17.2" width="1.6" height="1.6" /><rect x="15" y="15" width="2.5" height="2.5" /><rect x="18.5" y="15" width="2.5" height="2.5" /><rect x="15" y="18.5" width="2.5" height="2.5" /><rect x="18.5" y="18.5" width="2.5" height="2.5" /></svg>`;
const ICON_EYE = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>`;

// Card for a single-network crypto (same structure as the ones in index.html).
// Texts through data-i18n (translated by applyLanguage); fixed name and symbol.
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
          ${asset.icon ? `<img class="${iconClass}" src="${asset.icon}" alt="" />` : `<span class="coin-icon coin-icon-letter" aria-hidden="true"></span>`}<span class="coin-name"></span>
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
          <button class="secondary" data-action="history" data-i18n="wallet.history" data-i18n-title="wallet.history">Historique</button>
          <button class="primary" data-action="send" data-i18n="wallet.send">Envoyer</button>
        </div>
      </div>
    </div>`;
  card.querySelector(".coin-name").textContent = asset.name;
  if (asset.nameKey) card.querySelector(".coin-name").dataset.i18n = asset.nameKey;
  const letter = card.querySelector(".coin-icon-letter");
  if (letter) letter.textContent = asset.symbol.slice(0, 1).toUpperCase();
  card.querySelector(".coin-symbol").textContent = asset.symbol;
  return card;
}

// History tab section for a generated crypto.
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
  // Tokenized shares: their own tab ("Stocks"), separate from the cryptos.
  const stocksGrid = document.querySelector(".stocks-grid");
  const historyCard = document.querySelector('.tab-panel[data-panel="history"] .card');
  for (const asset of ASSETS) {
    if (document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`)) continue; // card from index.html
    (asset.stock ? stocksGrid : grid).appendChild(buildAssetCard(asset));
    historyCard.appendChild(buildHistorySection(asset));
  }
}

// Collapsed cards in the same row get the same height: a name on two lines
// ("Shielded Zcash") or a Stake badge made one card stick out below its neighbors.
// Height of the tallest collapsed card in the row (same vertical position); the
// header absorbs the difference, so balance and buttons stay aligned (see
// styles.css). Expanded cards and the list view: their own height. Recomputed on
// every size change (collapse, language, window, badge loaded…): reset, measure
// and new height in the same frame, so it is stable from one frame to the next.
for (const grid of document.querySelectorAll(".wallet-grid")) {
  let frame = null;
  const align = () => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      const cards = [...grid.querySelectorAll(".wallet-card")];
      cards.forEach((card) => card.style.removeProperty("min-height"));
      if (document.documentElement.dataset.walletListView === "true") return;
      const rows = new Map();
      for (const card of cards) {
        if (!card.classList.contains("collapsed") || !card.getClientRects().length) continue;
        rows.set(card.offsetTop, [...(rows.get(card.offsetTop) ?? []), card]);
      }
      for (const row of rows.values()) {
        const height = Math.max(...row.map((card) => card.offsetHeight));
        row.filter((card) => card.offsetHeight < height).forEach((card) => (card.style.minHeight = `${height}px`));
      }
    });
  };
  const observer = new ResizeObserver(align);
  observer.observe(grid);
  grid.querySelectorAll(".wallet-card").forEach((card) => observer.observe(card));
}

// --- My cryptos: cards shown -------------------------------------------------
//
// Explicit choices { coin: true|false }, remembered on the device; without a
// choice: the default cryptos, and any crypto on which funds are detected (see
// refreshBalance) shows up on its own.
const ASSETS_STORAGE_KEY = "pgp-wallet-assets";
const DEFAULT_ASSETS = ["evm", "btc", "sol", "usdc"];
let assetChoices = {};
try {
  const saved = JSON.parse(localStorage.getItem(ASSETS_STORAGE_KEY) || "{}");
  if (saved && typeof saved === "object") {
    for (const [coin, shown] of Object.entries(saved)) if (ASSET_BY_COIN[coin] && typeof shown === "boolean") assetChoices[coin] = shown;
  }
} catch (e) {
  // localStorage unavailable: default cryptos.
}

function isAssetVisible(coin) {
  if (coin in assetChoices) return assetChoices[coin];
  // Shielded Zcash follows the Zcash card as long as no choice has been made for it.
  if (coin === "zecs") return isAssetVisible("zec");
  return DEFAULT_ASSETS.includes(coin);
}

function saveAssetChoices() {
  try {
    localStorage.setItem(ASSETS_STORAGE_KEY, JSON.stringify(assetChoices));
  } catch (e) {
    // Best-effort: the choice stays applied for this session.
  }
}

// Cards and history sections hidden according to the choices. The "Receive" menu
// is rebuilt elsewhere (renderReceiveMenu, which needs the translations).
function applyAssetVisibility() {
  for (const asset of ASSETS) {
    const visible = isAssetVisible(asset.coin);
    document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`)?.classList.toggle("asset-hidden", !visible);
    document.getElementById(`history-section-${asset.coin}`)?.classList.toggle("asset-hidden", !visible);
  }
  document.getElementById("stocks-empty")?.classList.toggle("hidden", ASSETS.some((asset) => asset.stock && isAssetVisible(asset.coin)));
  // Monero: blocks are downloaded and scanned only if its card is shown (or if funds
  // have already been received, see `set_xmr_sync`). Uses `window.__TAURI__`: called
  // at load time, before `invoke` below.
  window.__TAURI__.core.invoke("set_xmr_sync", { enabled: isAssetVisible("xmr") }).catch((e) => console.error(e));
}
applyAssetVisibility();

// Hidden cards ("Manage my cryptos"): read only once per unlock or profile change,
// enough to detect funds and show them (revealIfFunded), without rereading twenty
// balances every minute.
let hiddenBalancesChecked = false;

const { invoke } = window.__TAURI__.core;

// --- Theme -------------------------------------------------------------------
//
// A purely visual, per-device preference (not wallet data): local storage is
// enough, no need to go through the encrypted vault. `try/catch` only
// (localStorage can be blocked depending on the configuration): the default theme
// then applies without ever crashing the app.
const THEME_STORAGE_KEY = "pgp-wallet-theme";
const VALID_THEMES = ["default", "purple", "emerald", "ocean", "rose", "orange", "dark", "light"];

// Changing `data-theme` on <html> invalidates the style of the WHOLE page (CSS
// variables are inherited everywhere) and forces a full recalculation. Picking
// several themes in a row from the dropdown therefore triggered a burst of
// consecutive page recalculations, faster than the rendering engine could absorb
// them. They are batched here through `requestAnimationFrame`: if several calls
// arrive before the next frame, only the last one chosen is actually applied,
// once.
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
    // Windows window title bar and border matched to the theme.
    invoke("set_window_frame", { theme: VALID_THEMES.includes(theme) ? theme : "default" }).catch(() => {});
  });
}

let currentTheme = "default";
try {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (VALID_THEMES.includes(saved)) currentTheme = saved;
} catch (e) {
  // localStorage unavailable: stays on the default theme.
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
    // Best-effort: the theme stays active for this session even if saving fails.
  }
});

// The same purely visual preference as the theme above (local storage is enough).
// `applyRoundedButtons` targets `<html>` directly (see styles.css:
// `:root[data-rounded-buttons="true"] button`), a single CSS rule that covers
// every button in the app since they are all real `<button>` elements.
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
  // localStorage unavailable: stays on non-rounded buttons by default.
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
    // Best-effort: the setting stays active for this session even if saving fails.
  }
});

// Wallet list view: the same purely visual/local preference as the previous two.
// `applyWalletListView` targets `<html>` (see styles.css:
// `:root[data-wallet-list-view="true"] .wallet-card`): pure CSS, no change to the
// DOM structure, so no other code (refresh/history/send) needs to know which
// display mode it is running in.
const WALLET_LIST_VIEW_STORAGE_KEY = "pgp-wallet-list-view";
// Last successful check of the backup drives (or kit creation, or restore):
// reminder on the dashboard one year later.
const BACKUP_CHECK_STORAGE_KEY = "pgp-wallet-backup-checked-at";
const BACKUP_CHECK_INTERVAL_MS = 365 * 24 * 3600 * 1000;
const BACKUP_CHECK_SNOOZE_MS = 30 * 24 * 3600 * 1000;

function applyWalletListView(enabled) {
  if (enabled) {
    document.documentElement.dataset.walletListView = "true";
  } else {
    delete document.documentElement.dataset.walletListView;
  }
  // In list view, the cards are already compact rows: collapsing does not apply
  // there (see "Collapsible panels"), so the title is taken out of the keyboard tab
  // order.
  document.querySelectorAll(".wallet-card .collapse-toggle").forEach((toggle) => {
    toggle.tabIndex = enabled ? -1 : 0;
  });
}

let walletListViewEnabled = false;
try {
  walletListViewEnabled = localStorage.getItem(WALLET_LIST_VIEW_STORAGE_KEY) === "true";
} catch (e) {
  // localStorage unavailable: stays in card view by default.
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
    // Best-effort: the setting stays active for this session even if saving fails.
  }
});

// --- Language ----------------------------------------------------------------
//
// A purely visual, per-device preference (like the theme above): local storage is
// enough. This only translates the frontend (static HTML + messages generated in
// JS); error messages returned by the Rust backend are translated on the Rust side
// (see below).
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
    "usb.nameLabel": "Nom de cette sauvegarde",
    "usb.nameHint": "Il identifie ce portefeuille sur la clé : une même clé peut en garder plusieurs.",
    "usb.defaultName": "Mon portefeuille",
    "usb.nameInvalid": "Nom : 1 à 30 caractères (lettres, chiffres, espaces, - _).",
    "usb.onDrive": "Déjà dessus : {list}",
    "usb.sharePart": "{name} (part n°{part})",
    "usb.unnamed": "sans nom",
    "settings.checkBackup": "Vérifier mes clés de sauvegarde",
    "settings.checkBackupHint": "Relit et déchiffre les parts d'une clé USB, sans rien modifier. À faire une fois par an : une clé peut s'abîmer avec le temps.",
    "backupCheck.title": "Vérifier mes clés de sauvegarde",
    "backupCheck.hint": "Branchez vos clés de sauvegarde, l'une après l'autre : l'app relit et déchiffre chaque part, sans rien modifier ni restaurer.",
    "backupCheck.checking": "Vérification…",
    "backupCheck.none": "Aucune sauvegarde OpenPGP Wallet sur cette clé.",
    "backupCheck.part": "Part n°{n}",
    "backupCheck.partOf": "Part n°{n} de « {name} »",
    "backupCheck.partFolder": "Part n°{n} (dossier « {name} »)",
    "backupCheck.ok": "intacte",
    "backupCheck.line": "{label} : {status}",
    "backupCheck.unreadable": "fichier manquant ou illisible",
    "backupCheck.decrypt": "ne se déchiffre plus",
    "backupCheck.unrecognized": "fichier sauvegarde.json abîmé, la part n'est plus reconnue",
    "backupCheck.advice": "Une part abîmée ne sert plus. Régénérez votre kit de sauvegarde (Paramètres → Sauvegarde), puis remplacez vos anciennes clés.",
    "backupCheck.reminder": "Pensez à vérifier vos clés de sauvegarde : une clé USB peut s'abîmer avec les années.",
    "backupCheck.checkNow": "Vérifier maintenant",
    "backupCheck.later": "Plus tard",
    "assets.stocksGroup": "Actions tokenisées (xStocks)",
    "nav.stocks": "Actions",
    "stocks.title": "Mes actions",
    "stocks.total": "Valeur des actions",
    "stocks.manage": "Gérer mes actions",
    "stocks.manageHint": "Cochez les actions tokenisées à afficher. Une action sur laquelle des fonds arrivent s'affiche d'elle-même.",
    "stocks.empty": "Aucune action affichée pour l'instant : choisissez-en dans « Gérer mes actions ».",
    "assets.stocksNotice": "Émises par Backed Assets sur Solana : chaque jeton suit le cours d'une action ou d'un fonds, sans droits d'actionnaire (pas de vote). Interdites aux personnes des États-Unis, non proposées au Royaume-Uni, au Canada ni en Australie. Le prix peut s'écarter de celui de la Bourse, surtout quand elle est fermée, et l'émetteur peut suspendre les transferts.",
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
    "restore.usbPartOf": "✓ Part n°{n} de « {name} » lue (clé « {label} »)",
    "restore.usbUnnamed": "sauvegarde sans nom",
    "restore.usbChoose": "Plusieurs sauvegardes complètes : choisissez celle à restaurer.",
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
    "restore.chooseFile": "Choisir le fichier…",
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
    "wallet.shieldedSyncingProgress": "Synchronisation des fonds protégés… {percent} %",
    "wallet.shieldedSyncFailed": "Synchronisation des fonds protégés en échec, nouvel essai dans 30 s.",
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
    "wallet.pendingIncoming": "⏳ Réception en attente : +{amount} BTC",
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
    "stocks.search": "Rechercher une action…",
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
    "wallet.receivedPending": "Réception en attente : +{amount} BTC",
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
    "wallet.btcFeesNotLoaded": "Frais Bitcoin pas encore chargés : patientez un instant, puis réessayez.",
    "wallet.allFieldsRequired": "Tous les champs sont requis.",
    "wallet.balanceError": "erreur",
    "message.title": "Chiffrer un message",
    "message.subtitle":
      "Chiffrez un message pour que seul son destinataire puisse le lire — l'usage d'origine de PGP, la technologie qui protège aussi votre portefeuille.",
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
    "settings.emerald": "Émeraude",
    "settings.ocean": "Océan",
    "settings.rose": "Rose",
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
    "settings.customNetworksTitle": "Réseaux ajoutés (RPC personnalisé)",
    "settings.customNetworksHint":
      "Ajoutez un réseau compatible Ethereum absent de l'app (Optimism, Linea…) : il utilise la même adresse que vos ETH. N'indiquez qu'un RPC de confiance : l'app ne peut pas vérifier les soldes et les frais qu'il annonce. Pas de valeur en dollars ni d'échange sur ces réseaux. Retirer un réseau ne touche pas aux fonds, qui restent sur la chaîne.",
    "settings.customNetworkName": "Nom du réseau",
    "settings.customNetworkRpc": "Adresse du RPC",
    "settings.customNetworkChain": "Identifiant de chaîne (chain ID)",
    "settings.customNetworkSymbol": "Symbole de la monnaie",
    "settings.customNetworkExplorer": "Explorateur de blocs (facultatif)",
    "settings.customNetworkAdd": "Ajouter ce réseau",
    "settings.customNetworkChainShort": "ID de chaîne",
    "settings.customNetworkRemove": "Retirer",
    "settings.customNetworkChainInvalid": "Identifiant de chaîne : un nombre entier (par exemple 10 pour OP Mainnet).",
    "settings.customNetworkAdded": "Réseau « {name} » ajouté. L'app se recharge : déverrouillez-la pour voir sa carte.",
    "settings.customNetworkRemoved": "Réseau retiré. L'app se recharge.",
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
    "send.evmAddressFamily": "Ethereum ou compatible (Base, BNB Chain…)",
    "send.addressOtherNetwork": "Cette adresse est une adresse {network}, pas {cardNetwork} : l'envoi serait refusé. Demandez au destinataire son adresse {cardNetwork}.",
    "send.addressSwitchNetwork": "Cette adresse est une adresse {network}. Pour y envoyer des {symbol}, choisissez d'abord ce réseau dans le menu de la carte, et vérifiez que le destinataire l'attend bien.",
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
    "ledger.feeFast": "Rapide (~10 min) : {fee}",
    "ledger.feeMedium": "Moyen (~30 min) : {fee}",
    "ledger.feeSlow": "Lent (~1 h) : {fee}",
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
    "charts.priceSourceJupiter": "Prix Jupiter (en dollars, par action).",
    "stocks.marketsTitle": "Cours des actions en direct",
    "organize.cap": "Capitalisation",
    "stocks.marketsHint": "Cliquez sur une action pour voir sa courbe en grand.",
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
    "usb.nameLabel": "Name of this backup",
    "usb.nameHint": "It identifies this wallet on the drive: one drive can hold several.",
    "usb.defaultName": "My wallet",
    "usb.nameInvalid": "Name: 1 to 30 characters (letters, digits, spaces, - _).",
    "usb.onDrive": "Already on it: {list}",
    "usb.sharePart": "{name} (share {part})",
    "usb.unnamed": "unnamed",
    "settings.checkBackup": "Check my backup drives",
    "settings.checkBackupHint": "Reads back and decrypts the shares on a USB drive, without changing anything. Do it once a year: a drive can wear out over time.",
    "backupCheck.title": "Check my backup drives",
    "backupCheck.hint": "Plug in your backup drives, one after the other: the app reads back and decrypts each share, without changing or restoring anything.",
    "backupCheck.checking": "Checking…",
    "backupCheck.none": "No OpenPGP Wallet backup on this drive.",
    "backupCheck.part": "Share {n}",
    "backupCheck.partOf": "Share {n} of \"{name}\"",
    "backupCheck.partFolder": "Share {n} (folder \"{name}\")",
    "backupCheck.ok": "intact",
    "backupCheck.line": "{label}: {status}",
    "backupCheck.unreadable": "file missing or unreadable",
    "backupCheck.decrypt": "no longer decrypts",
    "backupCheck.unrecognized": "sauvegarde.json file damaged, the share is no longer recognized",
    "backupCheck.advice": "A damaged share is useless. Regenerate your backup kit (Settings → Backup), then replace your old drives.",
    "backupCheck.reminder": "Remember to check your backup drives: a USB drive can wear out over the years.",
    "backupCheck.checkNow": "Check now",
    "backupCheck.later": "Later",
    "assets.stocksGroup": "Tokenized stocks (xStocks)",
    "nav.stocks": "Stocks",
    "stocks.title": "My stocks",
    "stocks.total": "Stocks value",
    "stocks.manage": "Manage my stocks",
    "stocks.manageHint": "Tick the tokenized stocks to show. A stock that receives funds shows up on its own.",
    "stocks.empty": "No stocks shown yet: pick some in \"Manage my stocks\".",
    "assets.stocksNotice": "Issued by Backed Assets on Solana: each token tracks the price of a stock or fund, without shareholder rights (no voting). Not for US persons, not offered in the UK, Canada or Australia. The price can drift from the stock market's, especially when it is closed, and the issuer can pause transfers.",
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
    "restore.usbPartOf": "✓ Share {n} of \"{name}\" read (drive \"{label}\")",
    "restore.usbUnnamed": "unnamed backup",
    "restore.usbChoose": "Several complete backups: choose the one to restore.",
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
    "restore.chooseFile": "Choose the file…",
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
    "wallet.shieldedSyncingProgress": "Syncing shielded funds… {percent}%",
    "wallet.shieldedSyncFailed": "Shielded funds sync failed, retrying in 30 s.",
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
    "wallet.pendingIncoming": "⏳ Incoming, unconfirmed: +{amount} BTC",
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
    "stocks.search": "Search a stock…",
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
    "wallet.receivedPending": "Incoming, unconfirmed: +{amount} BTC",
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
      "Encrypt a message so only its recipient can read it — the original purpose of PGP, the technology that also protects your wallet.",
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
    "settings.emerald": "Emerald",
    "settings.ocean": "Ocean",
    "settings.rose": "Rose",
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
    "settings.customNetworksTitle": "Added networks (custom RPC)",
    "settings.customNetworksHint":
      "Add an Ethereum-compatible network the app doesn't have (Optimism, Linea…): it uses the same address as your ETH. Only enter an RPC you trust: the app cannot verify the balances and fees it reports. No dollar value or swaps on these networks. Removing a network doesn't touch the funds, which stay on the chain.",
    "settings.customNetworkName": "Network name",
    "settings.customNetworkRpc": "RPC address",
    "settings.customNetworkChain": "Chain ID",
    "settings.customNetworkSymbol": "Currency symbol",
    "settings.customNetworkExplorer": "Block explorer (optional)",
    "settings.customNetworkAdd": "Add this network",
    "settings.customNetworkChainShort": "Chain ID",
    "settings.customNetworkRemove": "Remove",
    "settings.customNetworkChainInvalid": "Chain ID: a whole number (for example 10 for OP Mainnet).",
    "settings.customNetworkAdded": "Network \"{name}\" added. The app reloads: unlock it to see its card.",
    "settings.customNetworkRemoved": "Network removed. The app reloads.",
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
    "send.evmAddressFamily": "Ethereum or compatible (Base, BNB Chain…)",
    "send.addressOtherNetwork": "This address is for {network}, not {cardNetwork}: the send would be refused. Ask the recipient for their {cardNetwork} address.",
    "send.addressSwitchNetwork": "This address is for {network}. To send {symbol} there, first choose that network in the card's menu, and check the recipient expects it.",
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
    "ledger.feeFast": "Fast (~10 min): {fee}",
    "ledger.feeMedium": "Medium (~30 min): {fee}",
    "ledger.feeSlow": "Slow (~1 h): {fee}",
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
    "charts.priceSourceJupiter": "Jupiter prices (in dollars, per share).",
    "stocks.marketsTitle": "Live stock prices",
    "organize.cap": "Market cap",
    "stocks.marketsHint": "Click a stock to see its chart in full.",
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
  let text = dict[key] ?? I18N.fr[key] ?? CUSTOM_NETWORK_LABELS[key] ?? key;
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
  // Error messages returned by the Rust backend (core/) are translated too, but on
  // the Rust side (app/src-tauri/src/lib.rs::translate_error): core/ deliberately
  // knows nothing about interfaces, so the display language never travels deeper
  // than this dedicated command. Best-effort: if the call fails (e.g. the very first
  // call before the backend is ready), backend errors simply stay in French until
  // the next switch.
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
  // Labels of a different length: does the bar still fit on one line?
  fitNavbar();
  // The <option> elements have just been translated again above, but the visible
  // label of the custom dropdown (.custom-select-label) and its list (<li>) are
  // plain frozen copies, only synced when it opens or on a choice (see
  // syncCustomSelect). Without this extra call, they would stay in the old language
  // until the next click on the menu.
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
  // localStorage unavailable: stays on French by default.
}
applyLanguage(currentLang);

document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    applyLanguage(btn.dataset.lang);
    // Content already generated dynamically from data already in memory (no need to
    // call the backend again): redrawn straight away in the new language. The other
    // dynamic lists (history, fees, backup kit...) will switch language the next time
    // they are shown.
    renderRecipientList();
    renderAffiliateNames();
    renderStakeChips();
    // Dollar value of the cards ("≈ 1 234,56 $" / "≈ $1,234.56"): recomputed in place,
    // with no network call.
    document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
    renderReceiveMenu();
    try {
      localStorage.setItem(LANG_STORAGE_KEY, currentLang);
    } catch (e) {
      // Best-effort: the language stays active for this session even if saving fails.
    }
  });
});

// --- Collapsible panels -------------------------------------------------------
//
// Clicking a panel's title (a crypto card, the portfolio chart, live prices)
// collapses or expands it: a collapsed card keeps its name and balance. Cards do
// not collapse in list view (already compact). A purely visual, per-device
// preference, like the theme: local storage.
const COLLAPSED_STORAGE_KEY = "pgp-wallet-collapsed";
// Duration of the collapse animation (styles.css, `.collapsible-body`).
const COLLAPSE_MS = 220;

const collapsedPanels = (() => {
  try {
    const list = JSON.parse(localStorage.getItem(COLLAPSED_STORAGE_KEY) || "[]");
    return new Set(Array.isArray(list) ? list.filter((key) => typeof key === "string") : []);
  } catch (e) {
    return new Set();
  }
})();

// State read from the DOM (not from `collapsedPanels`): also called by
// `applyLanguage`, which may run before the initialization below.
function syncCollapseToggle(toggle) {
  const collapsed = toggle.closest("[data-collapse-key]").classList.contains("collapsed");
  toggle.setAttribute("aria-expanded", String(!collapsed));
  toggle.title = t(collapsed ? "collapse.expand" : "collapse.collapse");
}

function setPanelCollapsed(panel, collapsed, animate) {
  if (animate) {
    // Content clipped during the animation only: when expanded, nothing is cut off
    // (focus ring, button shadows).
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
      // Best-effort: the state stays applied for this session.
    }
  });
});

// --- Custom dropdowns -------------------------------------------------------
//
// A native <select> offers no reliable way (CSS or JS) to know whether its menu is
// actually open or closed, only whether it has focus, which it keeps after a
// choice or after a second click that already closes the menu natively. The result
// with a simple CSS arrow (:focus-within): it stays rotated after closing until
// you click elsewhere. The <select> remains the source of truth (value, options,
// "change" event: the rest of the code keeps reading/listening to it normally) but
// becomes invisible; this component fully drives the display and the
// opening/closing, in JS, and therefore exactly.

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
    // A crypto's option (`data-coin`): its logo before the name.
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

// `.dropdown`: a class shared by value menus (.custom-select, above) and pure
// action menus like the "Receive" button (see below): the same open/close/arrow
// mechanics, without an action menu needing an underlying <select>.
function closeAllDropdowns(except) {
  document.querySelectorAll(".dropdown.open").forEach((wrapper) => {
    if (wrapper !== except) wrapper.classList.remove("open");
  });
}

function initCustomSelect(wrapper) {
  const select = wrapper.querySelector("select");
  const trigger = wrapper.querySelector(".custom-select-trigger");
  const list = wrapper.querySelector(".custom-select-options");

  // The native <select> stays keyboard-focusable by default (tab): that would create
  // a second, invisible stop that exactly duplicates the visible button right next
  // to it. Only the latter must stay in the tab order.
  select.tabIndex = -1;

  syncCustomSelect(select);

  trigger.addEventListener("click", () => {
    const wasOpen = wrapper.classList.contains("open");
    closeAllDropdowns();
    wrapper.classList.toggle("open", !wasOpen);
  });

  // Arrow keys, like a native <select>: without this, making it non-focusable
  // (tabIndex -1) just above would have made this menu unusable without a mouse.
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
      // Synthetic: triggers exactly the same "change" handlers as if the user had picked
      // this option in a native <select>.
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    syncCustomSelect(select);
    wrapper.classList.remove("open");
  });
}

// --- "Receive" action menu (profile bar) ---------------------------------
//
// A shortcut to the same QR/address as each card's QR button (see openQrModal): no
// "selected" value to remember, each click triggers an action directly, so there
// is no underlying <select> here, unlike .custom-select.
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

// Give every password field our own reveal eye. The native WebView2 eye only
// appears on the focused field and disappears after some interactions, so the
// user could lose the ability to re-check what they typed. Ours stays in place.
const ICON_EYE_OFF = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M3 3l18 18" /><path d="M10.6 5.1A10.9 10.9 0 0 1 12 5c6.5 0 10 7 10 7a18.2 18.2 0 0 1-3.2 4.1M6.3 6.3A18.2 18.2 0 0 0 2 12s3.5 7 10 7a10.9 10.9 0 0 0 4-.8" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>`;

function enhancePasswordField(input) {
  if (!input || input.dataset.pwEnhanced) return;
  input.dataset.pwEnhanced = "1";

  const wrap = document.createElement("div");
  wrap.className = "pw-wrap";
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  const eye = document.createElement("button");
  eye.type = "button";
  eye.className = "pw-eye";
  eye.tabIndex = -1;
  eye.setAttribute("aria-label", "Afficher ou masquer le mot de passe");
  eye.innerHTML = ICON_EYE;
  wrap.appendChild(eye);

  eye.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    eye.innerHTML = show ? ICON_EYE_OFF : ICON_EYE;
  });
}

document.querySelectorAll('input[type="password"]').forEach(enhancePasswordField);

// --- "In progress" state of action buttons ----------------------------------
//
// No sensitive operation (unlock, send, profile creation...) disabled its button
// while waiting. Some are deliberately slow (maximum S2K cost to protect the
// password, network calls for a send), so without visual feedback the app looks
// frozen, and a double click can trigger two operations in parallel (e.g. two
// overlapping sends).
function withBusyButton(button, action) {
  return async (...args) => {
    if (button.disabled) return; // already running: ignore a second click
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

// Like `withBusyButton`, but the button stays disabled for at least `cooldownMs`
// after the click, even if the request itself finished sooner. Without this,
// clicking again as soon as the button becomes active is enough to spam the API
// (balance/history) at roughly the network's speed. Reserved for "Refresh"
// buttons, which are precisely the ones you can spam without typing anything
// between clicks (unlike "Send"/"Add", which require filling in a form each time).
// `keepLabel`: the label stays (the greyed-out button is enough), for buttons next
// to other buttons, since "Please wait…", being longer, widened the button and
// shifted its neighbors.
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
  if (name === "dashboard") updateBackupReminder();
}

// A background event (sync, monitoring) arriving outside the dashboard (locked,
// reset, restore in progress): nothing to reread. Seen on 2026-10-07: the end of a
// Zcash sync started before a reset was still rereading balances.
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

// A raw technical error (network library, node): a simple sentence to show first
// (`null`: the message is already clear and shown as is). Never for a "maybe sent"
// send: that message says what to do (check the history before sending again) and
// must stay intact.
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

// `coin`: logo of the crypto concerned, in front of the message (incoming funds…).
function showCopyToast(message, durationMs = 1800, coin = null) {
  const toast = document.getElementById("copy-toast");
  const text = document.getElementById("copy-toast-text");
  if (coin) setWithCoinIcon(text, coin, message);
  else text.textContent = message;
  clearTimeout(copyToastHideTimeout);
  clearTimeout(copyToastCleanupTimeout);
  toast.classList.remove("hidden");
  // Forces a style recalculation before adding `.visible`: without it, a click while
  // the previous toast is still shown would not restart the transition (already in
  // its final state), so there would be no visible animation.
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

// A deliberately simple heuristic (no external JS dependency, in keeping with the
// "light" frontend with no third-party library): length + character variety, with
// a filter on the most obvious guessable patterns.
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
    markBackupChecked();
    pendingCreateResult = result;
    document.getElementById("backup-confirm").checked = false;
    renderBackupList(result.backups);
    updateBackupContinue();
    showView("backup");
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    // The password must not stay in the DOM longer than necessary.
    document.getElementById("onboarding-password").value = "";
    document.getElementById("onboarding-password-confirm").value = "";
  }
}));

// Saves one file of a share (`kind`: "share" or "privkey"). The UI never holds the
// share's content: Rust keeps the kit it generated, opens the native "Save as" dialog
// itself and writes the file. Neither the path nor the content comes from the JS side.
async function saveBackupFile(backup, kind) {
  return await invoke("save_backup_file", { kitId: backup.kit_id, part: backup.part, kind });
}

function renderBackupList(backups, containerId = "backup-list") {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  // A clearly visible warning BEFORE the shares: the kit's security depends on
  // keeping the shares apart (two together = full access).
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
    // Built node by node: the passphrase and the label go in as text, never as HTML.
    const header = document.createElement("div");
    header.className = "backup-item-header";
    const title = document.createElement("h3");
    title.textContent = t("backup.partTitle", { n: i + 1, label: backup.label });
    const statusEl = document.createElement("span");
    statusEl.className = "backup-status";
    statusEl.dataset.field = "status";
    header.append(title, statusEl);
    const passwordHint = document.createElement("p");
    passwordHint.className = "muted";
    passwordHint.textContent = t("backup.partPassword");
    const passphrase = document.createElement("div");
    passphrase.className = "passphrase";
    passphrase.textContent = backup.passphrase;
    const buttons = document.createElement("div");
    buttons.className = "row-buttons";
    for (const [kind, className, label] of [
      ["usb", "primary", "backup.saveUsb"],
      ["share", "secondary", "backup.downloadShare"],
      ["privkey", "secondary", "backup.downloadPrivkey"],
    ]) {
      const button = Object.assign(document.createElement("button"), { className, textContent: t(label) });
      button.dataset.kind = kind;
      buttons.appendChild(button);
    }
    const usbSaved = document.createElement("p");
    usbSaved.className = "success hidden";
    usbSaved.dataset.field = "usb-saved";
    item.append(header, passwordHint, passphrase, buttons, usbSaved);
    // Share saved: written to a USB drive, or BOTH its files downloaded (a share is
    // only useful with its private key). Each change updates the checkmark and
    // notifies the screen ("Continue" button).
    const saved = { usb: false, share: false, privkey: false };
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
    // Button kept BEFORE the await: after an `await`, `e.currentTarget` is empty.
    item.querySelector('[data-kind="share"]').addEventListener("click", async (e) => {
      const button = e.currentTarget;
      try {
        // `false`: "Save as" dialog cancelled, nothing saved.
        if (await saveBackupFile(backup, "share")) markDownloaded(button, "share");
      } catch (err) {
        alert(t("common.saveFailed", { err }));
      }
    });
    item.querySelector('[data-kind="privkey"]').addEventListener("click", async (e) => {
      const button = e.currentTarget;
      try {
        if (await saveBackupFile(backup, "privkey")) markDownloaded(button, "privkey");
      } catch (err) {
        alert(t("common.saveFailed", { err }));
      }
    });
    container.appendChild(item);
    refreshStatus();
  });
  // The whole kit on a single drive: simpler, but that drive is then enough to
  // recover everything (confirmed through a native dialog on the Rust side).
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

// "Continue": only once the 3 shares are saved (checkmarks) AND the confirmation
// is ticked, which itself can only be ticked at that point.
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
    // Every share is saved: Rust can forget the kit.
    invoke("forget_pending_kit").catch((e) => console.error(e));
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

// The password stays ALWAYS visible and usable just below (never replaced by
// biometrics, only complemented by them): a faulty sensor or a misconfigured
// Windows Hello must never block access to the wallet. The biometric button only
// fires on an explicit click (see `showUnlockView`), never automatically when
// arriving on this screen, so an OS prompt never appears without a deliberate
// action.
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

/// Shows the unlock screen and, if biometrics are enabled on this device, reveals
/// the dedicated button: the user triggers the Windows Hello prompt themselves by
/// clicking it, never automatically on arriving at this screen.
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

// Restore opened from the unlock screen or from the first launch ("I already have
// a wallet"): Cancel goes back to the screen it came from.
let restoreOrigin = "unlock";

function openRestore(origin) {
  restoreOrigin = origin;
  clearRestoreFiles();
  showView("restore");
  startUsbRestore();
}

document.getElementById("goto-restore").addEventListener("click", () => openRestore("unlock"));
document.getElementById("onboarding-goto-restore").addEventListener("click", () => openRestore("onboarding"));
document.getElementById("goto-unlock").addEventListener("click", () => {
  stopUsbRestore(true);
  clearRestoreFiles();
  if (restoreOrigin === "onboarding") showView("onboarding");
  else showUnlockView();
});

// No JavaScript confirm(): the confirmation is a NATIVE dialog on the Rust side
// (`confirm_reset_native`), the only kind a compromised frontend cannot skip.
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

// --- Biometric unlock (Windows Hello), Settings tab -------------------------

async function loadBiometricSettings() {
  const enableBtn = document.getElementById("enable-biometric-btn");
  const disableBtn = document.getElementById("disable-biometric-btn");
  const unavailableHint = document.getElementById("biometric-unavailable-hint");

  // The two calls are independent (Windows Hello availability on the OS side vs.
  // enrollment status on the file side): run in parallel rather than one after the
  // other, the same principle as the rest of the app (see refreshBalance).
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

  // `available` is an OS-side display heuristic (see `windows_hello::is_available`),
  // never the security barrier itself: getting it wrong can only offer a button that
  // will then fail, never weaken anything.
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

// --- Backup kit regeneration ------------------------------------------------

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
    markBackupChecked();
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
  invoke("forget_pending_kit").catch((e) => console.error(e));
});

// --- Affiliate name (developer's wallet only) ---------------------------------
//
// Rust returns nothing (null) for any other wallet: the section stays hidden.
// Registration goes through a native confirmation dialog, built on the Rust side
// from the state read from the network.

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

// --- Monero node ----------------------------------------------------------------
//
// Public nodes by default; the user can enter their own (validated and stored on
// the Rust side, core/src/monero.rs).

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

// Full rescan of private funds (Monero, shielded Zcash): balances update as the
// background sync progresses.
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

// --- THOR address (swap fees) -----------------------------------------------
//
// Purely informational (see api::get_thor_fee_address): no RUNE send/balance
// feature, just deriving and showing the address.

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
  // Rust side: view keys and remembered addresses forgotten.
  invoke("lock_session").catch((e) => console.error(e));
  profilesCache = [];
  currentProfileIndex = 0;
  stopBalanceAutoRefresh();
  stopBalanceWatch();
  document.getElementById("unlock-password").value = "";
  showUnlockView();
}

document.getElementById("lock-wallet").addEventListener("click", lockWallet);

// --- Automatic lock after inactivity --------------------------------------------
//
// Nothing is cached in memory between two sensitive actions (every send/decryption
// asks for the password again, see the model described at the top of
// core/src/api.rs), so the automatic lock does not protect an already-decrypted
// secret. But leaving the dashboard open (addresses, balances, history) exposes
// that information to anyone with physical access to the device while you are
// away: the standard hygiene expected of any wallet.
const AUTO_LOCK_MS = 10 * 60 * 1000; // 10 minutes of inactivity
let autoLockTimer = null;
let lastActivityReset = 0;

function resetAutoLockTimer() {
  // Throttle: "mousemove"/"scroll" can fire hundreds of times per second, and
  // recreating a setTimeout each time is pointless work for a 10-minute delay.
  // One-second precision is plenty and avoids that churn during any mouse movement.
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

// --- Added networks (Settings) ---------------------------------------------
//
// Adding: checks and the chain ID verified by Rust (the RPC must answer for that
// chain). Adding or removing: the session is locked, then the UI reloads, which
// rebuilds the cards with the new list.
function reloadAfterNetworkChange() {
  setTimeout(async () => {
    await invoke("lock_session").catch((e) => console.error(e));
    location.reload();
  }, 1500);
}

function renderCustomNetworks() {
  const list = document.getElementById("custom-networks-list");
  list.replaceChildren(
    ...CUSTOM_NETWORKS.map((net) => {
      const li = document.createElement("li");
      const info = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = `${net.name} (${net.symbol})`;
      const detail = document.createElement("span");
      detail.className = "muted";
      const chainLabel = Object.assign(document.createElement("span"), { textContent: t("settings.customNetworkChainShort") });
      chainLabel.dataset.i18n = "settings.customNetworkChainShort";
      let host = net.rpc;
      try {
        host = new URL(net.rpc).host;
      } catch (e) {
        // Address already validated by Rust; otherwise shown as is.
      }
      detail.append(chainLabel, ` ${net.chain_id} · ${host}`);
      info.append(title, detail);
      const remove = Object.assign(document.createElement("button"), { type: "button", className: "link", textContent: t("settings.customNetworkRemove") });
      remove.dataset.i18n = "settings.customNetworkRemove";
      remove.addEventListener(
        "click",
        withBusyButton(remove, async () => {
          const errorEl = document.getElementById("custom-network-error");
          hideError(errorEl);
          try {
            await invoke("remove_custom_network", { chainId: net.chain_id });
            const success = document.getElementById("custom-network-success");
            success.textContent = t("settings.customNetworkRemoved");
            success.classList.remove("hidden");
            reloadAfterNetworkChange();
          } catch (e) {
            showError(errorEl, String(e));
          }
        })
      );
      li.append(info, remove);
      return li;
    })
  );
  list.classList.toggle("hidden", CUSTOM_NETWORKS.length === 0);
}
renderCustomNetworks();

const customNetworkAddBtn = document.getElementById("custom-network-add");
customNetworkAddBtn.addEventListener(
  "click",
  withBusyButton(customNetworkAddBtn, async () => {
    const errorEl = document.getElementById("custom-network-error");
    const success = document.getElementById("custom-network-success");
    hideError(errorEl);
    success.classList.add("hidden");
    const value = (id) => document.getElementById(id).value.trim();
    const chain = value("custom-network-chain");
    if (!/^\d{1,16}$/.test(chain) || !Number.isSafeInteger(Number(chain))) {
      showError(errorEl, t("settings.customNetworkChainInvalid"));
      return;
    }
    try {
      const net = await invoke("add_custom_network", {
        chainId: Number(chain),
        name: value("custom-network-name"),
        rpc: value("custom-network-rpc"),
        symbol: value("custom-network-symbol"),
        explorer: value("custom-network-explorer") || null,
      });
      assetChoices[net.id] = true;
      saveAssetChoices();
      success.textContent = t("settings.customNetworkAdded", { name: net.name });
      success.classList.remove("hidden");
      reloadAfterNetworkChange();
    } catch (e) {
      showError(errorEl, String(e));
    }
  })
);

// --- Navigation tabs ---------------------------------------------

// Navigation in a sidebar (see styles.css, "Sidebar"): nothing left to measure or
// collapse depending on the width. Kept (also called by `applyLanguage`, above)
// for the height reserved at the top of the page, which is zero with a sidebar.
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
    if (target === "stocks") {
      refreshStockPrices().then(() => {
        document.querySelectorAll(".stocks-grid .wallet-card").forEach(updateFiatValue);
        scheduleCardResort();
        renderStockMarkets();
      });
    }
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

// Restore from files: each file is picked in the native "Open" dialog and loaded on
// the Rust side, where it stays; the UI only shows its name. "part:kind" of the files
// chosen.
const restoreFilesChosen = new Set();

document.querySelectorAll("[data-restore-kind]").forEach((button) => {
  button.addEventListener("click", async () => {
    const { restorePart, restoreKind } = button.dataset;
    const errorEl = document.getElementById("restore-error");
    hideError(errorEl);
    try {
      const name = await invoke("restore_pick_file", { part: Number(restorePart), kind: restoreKind });
      if (name === null) return; // dialog cancelled: the previous choice stays
      restoreFilesChosen.add(`${restorePart}:${restoreKind}`);
      button.parentElement.querySelector("[data-file-name]").textContent = name;
    } catch (e) {
      showError(errorEl, String(e));
    }
  });
});

function clearRestoreFiles() {
  restoreFilesChosen.clear();
  document.querySelectorAll("[data-file-name]").forEach((el) => {
    el.textContent = "";
  });
  invoke("restore_files_clear").catch((e) => console.error(e));
}

document.getElementById("restore-new-password").addEventListener("input", (e) => {
  updateStrengthHint(e.target, document.getElementById("restore-strength"));
});

const restoreSubmitBtn = document.getElementById("restore-submit");
restoreSubmitBtn.addEventListener("click", withBusyButton(restoreSubmitBtn, async () => {
  const errorEl = document.getElementById("restore-error");
  hideError(errorEl);

  const passphrase1 = document.getElementById("restore-passphrase-1").value;
  const passphrase2 = document.getElementById("restore-passphrase-2").value;
  const newPassword = document.getElementById("restore-new-password").value;

  if (restoreFilesChosen.size < 4) {
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
    // The files themselves are already on the Rust side (`restore_pick_file`).
    const addresses = await invoke("restore_wallet", { newPassword, passphrase1, passphrase2 });
    markBackupChecked();

    stopUsbRestore(true);
    clearRestoreFiles();
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

// --- USB drive backup and restore (core/src/usb_backup.rs) -------------------
//
// Drives are detected by polling the list of removable drives at a short interval
// while the relevant window is open: plugging the drive in is enough. The shares
// never go through here: Rust writes the kit it generated (named by kit and number)
// and keeps the shares it reads for a restore; the UI only sees the share number,
// the kit and the backup name. One drive can hold backups of several wallets, each under its own
// name.
const USB_POLL_MS = 1500;

function usbDriveName(drive) {
  const letter = drive.root.replace(/\\$/, "");
  return drive.label ? `${drive.label} (${letter})` : letter;
}

let usbModalTimer = null;
const usbModal = document.getElementById("usb-modal");
const usbNameInput = document.getElementById("usb-name");
// Name given to each kit during the session: suggested for its other shares.
const usbKitNames = new Map();

// Same rule as core/src/usb_backup.rs::normalize_name (which has the final say).
function normalizeUsbName(value) {
  const name = value.trim().split(/\s+/).join(" ");
  return /^[\p{L}\p{N} _-]{1,30}$/u.test(name) ? name : null;
}

// Content of a drive, per backup: "Perso (share 1), Pro (share 2)".
function usbDriveContents(shares) {
  return shares.map((s) => t("usb.sharePart", { name: s.name || t("usb.unnamed"), part: s.part })).join(", ");
}

usbNameInput.addEventListener("input", () => {
  usbNameInput.dataset.touched = "1";
});

// `target`: { mode: "one", backup, item } (one share, on its own drive) or { mode:
// "all", backups, container, saved } (the whole kit on one drive).
function openUsbModal(target) {
  const all = target.mode === "all";
  document.getElementById("usb-modal-title").textContent = all ? t("usb.titleAll") : t("usb.title", { n: target.backup.part });
  document.getElementById("usb-modal-hint").textContent = all ? t("usb.hintAll") : t("usb.hint");
  hideError(document.getElementById("usb-error"));
  document.getElementById("usb-success").classList.add("hidden");
  document.getElementById("usb-drive-list").replaceChildren();
  const kit = all ? target.backups[0].kit_id : target.backup.kit_id;
  usbNameInput.value = usbKitNames.get(kit) || t("usb.defaultName");
  delete usbNameInput.dataset.touched;
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
  // This kit is already on a drive under a name: that name is kept, so we might as
  // well show it.
  const knownName = drives.flatMap((d) => d.shares || []).find((s) => s.kit === kit && s.name)?.name;
  if (knownName && !usbNameInput.dataset.touched && !usbKitNames.has(kit)) usbNameInput.value = knownName;
  const list = document.getElementById("usb-drive-list");
  if (drives.length === 0) {
    list.replaceChildren(Object.assign(document.createElement("li"), { className: "muted", textContent: t("usb.waiting") }));
    return;
  }
  list.replaceChildren(
    ...drives.map((drive) => {
      const li = document.createElement("li");
      li.className = "usb-drive";
      const info = document.createElement("div");
      info.className = "usb-drive-info";
      const name = document.createElement("span");
      name.textContent = `${usbDriveName(drive)} — ${t("usb.free", { mb: Math.floor(drive.free_bytes / 1048576).toLocaleString(chartLocale()) })}`;
      info.append(name);
      const shares = drive.shares || [];
      if (shares.length) {
        info.append(Object.assign(document.createElement("small"), { className: "muted", textContent: t("usb.onDrive", { list: usbDriveContents(shares) }) }));
      }
      const button = document.createElement("button");
      button.className = "secondary";
      // Other wallets' backups do not get in the way; only ANOTHER share of this kit
      // blocks (two shares on one drive = full access).
      const mine = shares.filter((s) => s.kit === kit);
      const otherPart = all ? null : mine.find((s) => s.part !== target.backup.part);
      if (otherPart) {
        button.disabled = true;
        button.textContent = t("usb.otherPart", { part: otherPart.part });
      } else {
        if (all) button.textContent = mine.length ? t("usb.rewriteAll") : t("usb.writeAll");
        else button.textContent = mine.length ? t("usb.rewrite") : t("usb.write", { n: target.backup.part });
        button.addEventListener("click", () => writeToUsb(target, drive, button));
      }
      li.append(info, button);
      return li;
    })
  );
}

async function writeToUsb(target, drive, button) {
  const errorEl = document.getElementById("usb-error");
  const successEl = document.getElementById("usb-success");
  hideError(errorEl);
  successEl.classList.add("hidden");
  const backupName = normalizeUsbName(usbNameInput.value);
  if (!backupName) {
    showError(errorEl, t("usb.nameInvalid"));
    usbNameInput.focus();
    return;
  }
  const kit = target.mode === "all" ? target.backups[0].kit_id : target.backup.kit_id;
  usbWriting = true;
  button.disabled = true;
  button.textContent = t("usb.writing");
  try {
    // The shares are named by kit and number: Rust writes the content it holds.
    if (target.mode === "all") {
      const label = await invoke("save_kit_to_usb", { root: drive.root, kitId: kit, name: backupName });
      if (label === null) return; // declined in the confirmation dialog
      usbKitNames.set(kit, backupName);
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
        name: backupName,
        part: backup.part,
      });
      usbKitNames.set(kit, backupName);
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
// Shares already read: "kit:part" -> { kit, part, name, label } (label: the drive's
// name).
const usbRestoreLoaded = new Map();
// Backup to restore (kit identifier): the only complete one, or the one the user
// ticked when several are complete; never one picked automatically while another
// complete one has appeared since.
let usbRestoreChoice = null;
let usbRestoreUserChose = false;
// Last render: nothing is rebuilt as long as nothing changes (a keyboard choice
// keeps its focus between two detections).
let usbRestoreRendered = "";

function startUsbRestore() {
  usbRestoreLoaded.clear();
  usbRestoreChoice = null;
  usbRestoreUserChose = false;
  usbRestoreRendered = "";
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
    usbRestoreChoice = null;
    usbRestoreUserChose = false;
    usbRestoreRendered = "";
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
      read.forEach((s) => usbRestoreLoaded.set(`${s.kit}:${s.part}`, { kit: s.kit, part: s.part, name: s.name, label: usbDriveName(drive) }));
    } catch (e) {
      showError(document.getElementById("restore-error"), String(e));
    }
  }
  renderUsbRestore();
}

// Shares read, per backup (kit), in reading order. Name: the one found on one of
// its drives (empty: a backup written before names existed).
function usbRestoreKits() {
  const kits = new Map();
  for (const share of usbRestoreLoaded.values()) {
    const kit = kits.get(share.kit) || { kit: share.kit, name: "", parts: [] };
    if (!kit.name && share.name) kit.name = share.name;
    kit.parts.push(share);
    kits.set(share.kit, kit);
  }
  const list = [...kits.values()];
  list.forEach((kit) => kit.parts.sort((a, b) => a.part - b.part));
  return list;
}

// Display name of a backup; the start of the identifier if two have the same name.
function usbKitTitle(kit, kits) {
  const name = kit.name || t("restore.usbUnnamed");
  return kits.filter((k) => k.name === kit.name).length > 1 ? `${name} (${kit.kit.slice(0, 6)})` : name;
}

function renderUsbRestore() {
  const kits = usbRestoreKits();
  // Two different shares of the same kit read: restore possible.
  const complete = kits.filter((k) => new Set(k.parts.map((p) => p.part)).size >= 2);
  if (complete.length === 1) usbRestoreChoice = complete[0].kit;
  else if (!usbRestoreUserChose || !complete.some((k) => k.kit === usbRestoreChoice)) {
    usbRestoreChoice = null;
    usbRestoreUserChose = false;
  }
  document.getElementById("restore-usb-submit").classList.toggle("hidden", !usbRestoreChoice);
  const signature = JSON.stringify([currentLang, kits]);
  if (signature === usbRestoreRendered) return;
  usbRestoreRendered = signature;
  const several = kits.length > 1;
  const items = kits.flatMap((kit) =>
    kit.parts.map((share) =>
      Object.assign(document.createElement("li"), {
        textContent: several
          ? t("restore.usbPartOf", { n: share.part, name: usbKitTitle(kit, kits), label: share.label })
          : t("restore.usbPart", { n: share.part, label: share.label }),
      })
    )
  );
  if (items.length === 0) items.push(Object.assign(document.createElement("li"), { className: "muted", textContent: t("restore.usbWaiting") }));
  if (complete.length === 1) items.push(Object.assign(document.createElement("li"), { className: "success", textContent: t("restore.usbReady") }));
  if (complete.length > 1) {
    items.push(Object.assign(document.createElement("li"), { className: "success", textContent: t("restore.usbChoose") }));
    for (const kit of complete) {
      const li = document.createElement("li");
      li.className = "usb-choice";
      const label = document.createElement("label");
      const radio = Object.assign(document.createElement("input"), { type: "radio", name: "usb-restore-kit", value: kit.kit, checked: kit.kit === usbRestoreChoice });
      radio.addEventListener("change", () => {
        usbRestoreChoice = kit.kit;
        usbRestoreUserChose = true;
        document.getElementById("restore-usb-submit").classList.remove("hidden");
      });
      label.append(radio, Object.assign(document.createElement("span"), { textContent: usbKitTitle(kit, kits) }));
      li.append(label);
      items.push(li);
    }
  }
  document.getElementById("restore-usb-status").replaceChildren(...items);
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
    const addresses = await invoke("restore_wallet_from_usb", { newPassword, kit: usbRestoreChoice });
    markBackupChecked();
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

// --- Checking the backup drives (core/src/usb_backup.rs) ----------------------
//
// A USB drive can degrade over the years: each plugged-in drive is reread and its
// shares decrypted (check_usb_backup), without writing or restoring anything. A
// damaged share is reported while the other two still exist.

function setBackupCheckedAt(time) {
  try {
    localStorage.setItem(BACKUP_CHECK_STORAGE_KEY, String(time));
  } catch (e) {
    // localStorage unavailable: no reminder.
  }
}

function markBackupChecked() {
  setBackupCheckedAt(Date.now());
  updateBackupReminder();
}

// Reminder due one year after the last check; with no known date (first version
// with this reminder), the count starts now.
function backupCheckDue() {
  let last;
  try {
    last = Number(localStorage.getItem(BACKUP_CHECK_STORAGE_KEY));
  } catch (e) {
    return false;
  }
  if (!last) {
    setBackupCheckedAt(Date.now());
    return false;
  }
  return Date.now() - last > BACKUP_CHECK_INTERVAL_MS;
}

function updateBackupReminder() {
  document.getElementById("backup-check-reminder").classList.toggle("hidden", !backupCheckDue());
}

let backupCheckTimer = null;
let backupCheckDrives = [];
// Drive (root + shares) -> { running } | { checks } | { error }: each drive is
// only checked once as long as its content does not change.
const backupCheckResults = new Map();
const backupCheckModal = document.getElementById("backup-check-modal");

function backupCheckKey(drive) {
  return `${drive.root}|${(drive.shares || []).map((s) => `${s.kit}:${s.part}`).join(",")}`;
}

function openBackupCheck() {
  backupCheckResults.clear();
  backupCheckDrives = [];
  document.getElementById("backup-check-list").replaceChildren();
  backupCheckModal.classList.remove("hidden");
  refreshBackupCheck();
  clearInterval(backupCheckTimer);
  backupCheckTimer = setInterval(refreshBackupCheck, USB_POLL_MS);
}

function closeBackupCheck() {
  clearInterval(backupCheckTimer);
  backupCheckTimer = null;
  backupCheckModal.classList.add("hidden");
}

async function refreshBackupCheck() {
  let drives;
  try {
    drives = await invoke("list_backup_drives");
  } catch (e) {
    console.error(e);
    return;
  }
  backupCheckDrives = drives;
  for (const drive of drives) {
    const key = backupCheckKey(drive);
    if (backupCheckResults.has(key)) continue;
    backupCheckResults.set(key, { running: true });
    invoke("check_usb_backup", { root: drive.root })
      .then((checks) => {
        backupCheckResults.set(key, { checks });
        if (checks.length && checks.every((c) => !c.problem)) markBackupChecked();
      })
      .catch((e) => backupCheckResults.set(key, { error: String(e) }))
      .finally(renderBackupCheck);
  }
  renderBackupCheck();
}

function backupCheckLine(check) {
  const label = check.problem === "unrecognized"
    ? t("backupCheck.partFolder", { n: check.part, name: check.name || "PGP-Wallet-Sauvegarde" })
    : check.name
      ? t("backupCheck.partOf", { n: check.part, name: check.name })
      : t("backupCheck.part", { n: check.part });
  const status = check.problem ? t(`backupCheck.${check.problem}`) : t("backupCheck.ok");
  return Object.assign(document.createElement("p"), {
    className: check.problem ? "backup-check-line bad" : "backup-check-line ok",
    textContent: `${check.problem ? "✗" : "✓"} ${t("backupCheck.line", { label, status })}`,
  });
}

function renderBackupCheck() {
  if (backupCheckModal.classList.contains("hidden")) return;
  const list = document.getElementById("backup-check-list");
  if (backupCheckDrives.length === 0) {
    list.replaceChildren(Object.assign(document.createElement("li"), { className: "muted", textContent: t("usb.waiting") }));
    return;
  }
  list.replaceChildren(
    ...backupCheckDrives.map((drive) => {
      const li = document.createElement("li");
      li.className = "usb-drive backup-check-drive";
      const title = Object.assign(document.createElement("span"), { className: "backup-check-name", textContent: usbDriveName(drive) });
      li.append(title);
      const result = backupCheckResults.get(backupCheckKey(drive)) || { running: true };
      if (result.running) {
        li.append(Object.assign(document.createElement("p"), { className: "muted backup-check-line", textContent: t("backupCheck.checking") }));
      } else if (result.error) {
        li.append(Object.assign(document.createElement("p"), { className: "error backup-check-line", textContent: result.error }));
      } else if (result.checks.length === 0) {
        li.append(Object.assign(document.createElement("p"), { className: "muted backup-check-line", textContent: t("backupCheck.none") }));
      } else {
        li.append(...result.checks.map(backupCheckLine));
        if (result.checks.some((c) => c.problem)) {
          li.append(Object.assign(document.createElement("p"), { className: "backup-check-advice", textContent: t("backupCheck.advice") }));
        }
      }
      return li;
    })
  );
}

document.getElementById("open-backup-check").addEventListener("click", openBackupCheck);
document.getElementById("backup-check-close").addEventListener("click", closeBackupCheck);
document.getElementById("backup-reminder-check").addEventListener("click", openBackupCheck);
document.getElementById("backup-reminder-later").addEventListener("click", () => {
  setBackupCheckedAt(Date.now() - BACKUP_CHECK_INTERVAL_MS + BACKUP_CHECK_SNOOZE_MS);
  updateBackupReminder();
});

// --- Dashboard ---------------------------------------------------------

let balanceRefreshTimer = null;

// Refreshes the balances every 60 s while the dashboard is open, as a safety net, since changes are reported live
// (see updateBalanceWatch). It used to be 15 s, before live monitoring existed: four times as many calls to public
// nodes for nothing. Stopped on lock/reset so no network calls keep running in the background once the wallet is
// closed. Prices (see below) follow the same lifecycle with a longer interval: they are market prices, not amounts
// that move with every block, and the public API used (CoinGecko, free) has a per-minute request limit.
function startBalanceAutoRefresh() {
  stopBalanceAutoRefresh();
  loadStakingAprs();
  // Always preceded by a full reread (unlock, creation, restore): the catch-up on
  // focus does not need to redo it.
  lastAutoBalances = Date.now();
  balanceRefreshTimer = setInterval(autoRefreshBalances, BALANCE_REFRESH_MS);
  startPriceAutoRefresh();
}

// Window minimized: neither balances nor prices are reread (twenty-odd calls a
// minute to public nodes, for a screen nobody is looking at). Incoming funds are
// still reported by live monitoring (Rust); everything is reread as soon as the
// window regains focus. `document.hidden` stays false in a minimized WebView2
// window (seen on 2026-10-06): Tauri answers instead.
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

// Reread less than half a period ago (catch-up when focus returned): this tick
// waits for the next one.
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
  // Focus regained: reread directly, since `isMinimized` still answers "true" at
  // this moment (seen on 2026-10-06), and asking it here would cancel the reread.
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

// Wallet closed (lock, reset): no address is monitored any more. Not in
// stopBalanceAutoRefresh, which startBalanceAutoRefresh calls right after the
// displayed addresses have started the monitoring.
function stopBalanceWatch() {
  invoke("watch_balances", { targets: [] }).catch((e) => console.error(e));
}

// --- Indicative prices (USD) -------------------------------------------------
//
// Purely informational (see core/src/price_rpc.rs): no data about the user's
// address or balance is sent to this service, just "what is the current price of
// ETH/BTC/SOL", which is the same for everyone.

let latestPrices = null;

// --- Display currency -----------------------------------------------------
//
// Everything is computed in dollars (prices, histories, portfolios); in euros,
// each amount is converted at display time: the current rate for current values,
// the rate of EACH DATE for charts and past transactions (Binance's EUR/USDT pair,
// listed since 2020-01-03; before that, the first known rate). A display
// preference, per device: local storage.
const CURRENCY_STORAGE_KEY = "pgp-wallet-currency";
let displayCurrency = "usd";
try {
  if (localStorage.getItem(CURRENCY_STORAGE_KEY) === "eur") displayCurrency = "eur";
} catch (e) {
  // localStorage unavailable: dollars.
}
// Dollars per euro, right now (`null` until it has been read).
let usdPerEur = null;
// Rate series per chart period: { points, loadedAt }.
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

// Rate at time `t` (seconds): the last known point at that date; before the first
// point, the first one (see above).
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

// Dollar amount → display currency, at the current rate; `null` if the rate is not
// known yet (shown as "—").
function usdToFiat(usd) {
  if (displayCurrency !== "eur") return usd;
  return usdPerEur ? usd / usdPerEur : null;
}

// The same at a past date's rate (transactions): the full daily series if it is
// already loaded, otherwise the current rate.
function usdToFiatAt(usd, timestamp) {
  if (displayCurrency !== "eur") return usd;
  const all = eurSeriesCache.get("all");
  if (all && timestamp) return usd / rateAt(all.points, timestamp);
  return usdToFiat(usd);
}

// First known EUR/USD rate (2020-01-03): used for earlier dates.
const EUR_SERIES_START = 1578009600;

// Note under a chart in euros; the "before 2020" detail only if the chart starts
// earlier.
function eurChartNote(points) {
  if (displayCurrency !== "eur" || points.length === 0) return "";
  return points[0][0] < EUR_SERIES_START ? `${t("charts.eurNote")} ${t("charts.eurNoteBefore2020")}` : t("charts.eurNote");
}

// Points [time, dollars] of a chart → display currency, at each point's rate.
async function toDisplayCurrency(points, range) {
  if (displayCurrency !== "eur" || points.length === 0) return points;
  const rates = await eurSeries(range);
  return points.map(([time, usd]) => [time, usd / rateAt(rates, time)]);
}

// "Display currency" setting: everything already shown is converted straight away
// (rates and series loaded as needed).
const currencySelect = document.getElementById("currency-select");
currencySelect.value = displayCurrency;
// Menu already built above (initCustomSelect): label resynced.
syncCustomSelect(currencySelect);
currencySelect.addEventListener("change", async () => {
  displayCurrency = currencySelect.value === "eur" ? "eur" : "usd";
  try {
    localStorage.setItem(CURRENCY_STORAGE_KEY, displayCurrency);
  } catch (e) {
    // Best-effort: the currency stays active for this session.
  }
  if (displayCurrency === "eur") {
    await refreshEurRate();
    eurSeries("all").catch((e) => console.error(e)); // value of past transactions
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

// Prices of tokenized shares (Jupiter: the price of one displayed unit, i.e. the
// share's): only requested if one of them is shown.
let stockQuotes = {};
// `force`: even with no share shown ("Manage my stocks", sorted by market cap).
async function refreshStockPrices(force = false) {
  if (!force && !ASSETS.some((asset) => asset.stock && isAssetVisible(asset.coin))) return;
  try {
    const quotes = await invoke("get_stock_prices");
    const next = Object.fromEntries(quotes.map((quote) => [quote.id, quote]));
    if (Object.keys(next).length > 0) stockQuotes = next;
  } catch (e) {
    console.error(e);
  }
}

function priceForCoin(coin) {
  // USDC is a dollar-pegged stablecoin: no price call needed, always ~$1. Avoids a
  // special case in updateFiatValue/renderQuickAmounts for this one asset.
  if (coin === "usdc") return 1;
  const asset = ASSET_BY_COIN[coin];
  if (asset?.stock) return stockQuotes[coin]?.price_usd ?? null;
  if (!latestPrices || !asset) return null;
  return latestPrices[asset.gecko] ?? null;
}

// --- Total value (dashboard header) -----------------------------------------
//
// Sum of the cards shown on a mainnet (balance × price, like their currency value:
// test funds excluded) and the 24 h change weighted by each crypto's value
// (changes from the market list).
function marketChange24h(coin) {
  if (ASSET_BY_COIN[coin]?.stock) {
    const change = stockQuotes[coin]?.change_24h_percent;
    return Number.isFinite(change) ? change : null;
  }
  const gecko = ASSET_BY_COIN[coin]?.gecko;
  const market = gecko && lastMarketCoins ? lastMarketCoins.find((c) => c.id === gecko) : null;
  return market && Number.isFinite(market.change_24h_percent) ? market.change_24h_percent : null;
}

// Staked SOL of the profile shown, tied to its address (`balanceKey`): counted in
// the SOL card's value and in the total value. Reread at most every 5 min (rewards
// land every 2 days), and straight after an operation.
let solStaked = { key: "", lamports: 0, at: 0 };
const SOL_STAKED_TTL_MS = 5 * 60 * 1000;

// A card's displayed balance (currency value, total value), staked SOL included
// (native staking: it has left the address but still belongs to you).
function cardTotalBalance(card) {
  return Number.parseFloat(card.querySelector('[data-field="balance"]').textContent) + solStakedFor(card);
}

function updatePortfolioTotal() {
  renderCardsTotal("portfolio-total", "portfolio-change", false);
  renderCardsTotal("stocks-total", "stocks-change", true);
}

// Value and 24 h change of the cards shown, cryptos (`stocks` false) or tokenized
// shares: each tab has its own.
function renderCardsTotal(totalId, changeId, stocks) {
  const totalEl = document.getElementById(totalId);
  const changeEl = document.getElementById(changeId);
  if (!totalEl) return;
  let usd = 0;
  let weighted = 0;
  let weight = 0;
  let known = false;
  document.querySelectorAll(".wallet-card:not(.asset-hidden)").forEach((card) => {
    if (Boolean(ASSET_BY_COIN[card.dataset.coin]?.stock) !== stocks) return;
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
  // Change: only with funds (weighted by their value).
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
  // In the chosen language ("≈ 1 234,56 $" / "≈ $1,234.56"); it used to stay in
  // French format in English.
  const text = formatUsdApprox(balance * price);
  if (fiatEl.textContent !== text) fiatEl.textContent = text;
}

// Last market list received: shown again as is when the currency changes, with no
// new call.
let lastMarketCoins = null;

async function refreshPrices() {
  // Same lock logic as refreshBalance: prevents a slow cycle (CoinGecko rate-limits
  // the free tier) from being overlapped by the timer's next tick.
  if (pricesRefreshing) return;
  pricesRefreshing = true;
  try {
    // A single CoinGecko call per cycle: the market list already gives the BTC/ETH/SOL
    // prices (a separate `simple/price` call doubled the use of the free limit). On a
    // transient failure, the last prices stay, instead of every dollar value turning
    // into "—".
    let coins = null;
    if (displayCurrency === "eur") {
      await refreshEurRate();
      // Daily rates, for the value of past transactions.
      if (!eurSeriesCache.has("all")) eurSeries("all").catch((e) => console.error(e));
    }
    try {
      coins = await invoke("get_market_prices");
      lastMarketCoins = coins;
      // Prices by CoinGecko identifier (see ASSETS[].gecko).
      const next = Object.fromEntries(coins.filter((c) => Number.isFinite(c.price_usd) && c.price_usd > 0).map((c) => [c.id, c.price_usd]));
      if (Object.keys(next).length > 0) latestPrices = next;
    } catch (e) {
      console.error(e);
    }
    await refreshStockPrices();
    document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
    scheduleCardResort();
    renderMarkets(coins);
    renderStockMarkets();
    // Keeps the send window's quick amounts in sync with the price if it stays open
    // across a refresh cycle (every 60 s, see startPriceAutoRefresh); otherwise a
    // quick amount clicked later in a long session would reflect a stale price.
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

// Abbreviated market cap, in the chosen language and currency: "1,67 T$", "325,43
// Md€" / "$1.67T", "€325.43B".
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

// Already sorted by descending market cap on the Rust side (see
// core/src/price_rpc.rs::get_market_data): the frontend shows the order received
// as is, without re-sorting. Updated IN PLACE every 30 s (rows kept, texts only
// changed when they differ, mini chart replaced when the new one arrives):
// rebuilding the list made every mini chart disappear and reappear, and lost a
// row's keyboard focus. Logos: the same files as the wallet cards (ASSETS), found
// by CoinGecko identifier.

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
  // A click (or Enter) opens the chart full size, with a choice of period.
  const openChart = () =>
    openChartModal({
      title: `${coin.name} (${coin.symbol})`,
      coin: asset?.coin,
      ranges: CHART_RANGES,
      range: "7d",
      load: (range) => loadPriceChart(chartSymbol, range),
      emptyKey: "charts.noData",
    });
  // No chart (unlisted stablecoin, token not listed on Binance): row not clickable.
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
  // Change rounded to 0.00%: neither up nor down (USDC, typically).
  const trend = trendOf(coin.change_24h_percent);
  if (coin.change_24h_percent == null) {
    setText(changeDiv, "—");
  } else {
    const shown = Math.abs(coin.change_24h_percent).toLocaleString(chartLocale(), decimals) + (currentLang === "en" ? "%" : "\u00a0%");
    if (trend) changeDiv.classList.add(trend);
    setText(changeDiv, trend ? `${trend === "up" ? "▲" : "▼"} ${shown}` : shown);
  }
  // Chart of the last 24 h (like the change shown), in the same color as that
  // change; the old one stays shown until the new one arrives.
  const spark = row.querySelector(".market-spark");
  if (!row.dataset.chart) return;
  invoke("get_price_chart", { symbol: row.dataset.chart, range: "1d" })
    .then((points) => renderSparkline(spark, points, trend))
    .catch((e) => console.error(e));
}

// `coins`: the list received by refreshPrices, `null` if the call failed.
function renderMarkets(coins) {
  const container = document.getElementById("markets-list");
  try {
    if (!coins) throw new Error("marchés indisponibles");
    const existing = new Map([...container.querySelectorAll(".market-row")].map((row) => [row.dataset.symbol, row]));
    // Only the cryptos shown on the dashboard.
    const rows = coins.filter((coin) => ASSET_BY_GECKO[coin.id] && isAssetVisible(ASSET_BY_GECKO[coin.id].coin)).map((coin) => {
      const row = existing.get(coin.symbol) || createMarketRow(coin);
      fillMarketRow(row, coin);
      return row;
    });
    const sameOrder = rows.length === container.children.length && rows.every((row, i) => container.children[i] === row);
    if (!sameOrder) container.replaceChildren(...rows);
  } catch (e) {
    // Transient failure: the last prices shown stay, rather than a message in place of
    // the whole list.
    if (!container.querySelector(".market-row")) container.innerHTML = `<p class="muted">${t("wallet.marketsLoadError")}</p>`;
    console.error(e);
  }
}

// Prices of the shares shown, under their cards ("Stocks" tab): the same layout as
// the cryptos (24 h mini chart, change, price, company market cap); a click opens
// the chart full size.
function renderStockMarkets() {
  const container = document.getElementById("stocks-markets-list");
  if (!container) return;
  const existing = new Map([...container.querySelectorAll(".market-row")].map((row) => [row.dataset.symbol, row]));
  // By market cap, descending, like the crypto list.
  const cap = (asset) => stockQuotes[asset.coin].market_cap_usd ?? -1;
  const visible = ASSETS.filter((asset) => asset.stock && isAssetVisible(asset.coin) && stockQuotes[asset.coin]);
  const rows = visible.sort((a, b) => cap(b) - cap(a)).map((asset) => {
    const quote = stockQuotes[asset.coin];
    const coin = { id: asset.gecko, symbol: asset.symbol, name: asset.name, price_usd: quote.price_usd, market_cap_usd: quote.market_cap_usd ?? 0, change_24h_percent: quote.change_24h_percent ?? null };
    const row = existing.get(coin.symbol) || createMarketRow(coin);
    fillMarketRow(row, coin);
    if (coin.market_cap_usd === 0) setText(row.querySelector(".market-cap"), "");
    return row;
  });
  const sameOrder = rows.length === container.children.length && rows.every((row, i) => container.children[i] === row);
  if (!sameOrder) container.replaceChildren(...rows);
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

// Network of a card without a network menu: the first one for its crypto (ASSETS).
const coinConfig = Object.fromEntries(ASSETS.map((asset) => [asset.coin, { defaultNetwork: asset.networks[0] }]));

// A "profile" = an extra derivation index on the same master key (see
// core/src/api.rs): several addresses per network, always protected by the same
// 2-of-3 Shamir + PGP. `create_wallet`/`restore_wallet` only return one set of
// addresses (a single profile exists at that point); it is wrapped in the same list
// format as `unlock_wallet`/`create_profile` so the rest of the dashboard only has
// one data shape to handle.
function singleProfileList(addresses, label = "Principal") {
  return [{ index: 0, label, addresses }];
}

let profilesCache = [];
let currentProfileIndex = 0;

function currentProfile() {
  return profilesCache.find((p) => p.index === currentProfileIndex) || profilesCache[0] || null;
}

// `network` only matters for Bitcoin: mainnet and testnet derive DIFFERENT
// addresses for the same profile (see core/src/derivation.rs), unlike EVM/Solana
// where the same address works on every variant of the network; for those two, the
// parameter is ignored.
function addressForCoin(coin, network) {
  return addressOfProfile(currentProfile(), coin, network);
}

// Address of `profile` for a crypto and a network (the one on its card).
function addressOfProfile(profile, coin, network) {
  // `addresses` is missing when the profile was created without a password (see
  // add-profile-confirm): the address has not been derived yet and will appear at
  // the next full unlock (see core/src/api.rs::create_profile).
  if (!profile || !profile.addresses) return "";
  // The same address on every EVM network (Ethereum, L2s, BNB Chain…), tokens
  // included.
  if (isEvmNetwork(network)) return profile.addresses.evm;
  // Tron: TRX and TRC-20 tokens (USDT) at the same T… address.
  if (network === "tron_mainnet") return profile.addresses.tron ?? "";
  if (coin === "btc") return network === "btc_mainnet" ? profile.addresses.btc_mainnet : profile.addresses.btc_testnet;
  // Transparent Zcash (t1…); missing from a profile derived before it was added,
  // until the next unlock.
  if (coin === "zec") return profile.addresses.zcash ?? "";
  // Monero: primary address (4…); missing from a profile derived before it was
  // added, until the next unlock.
  if (coin === "xmr") return profile.addresses.monero ?? "";
  // Dogecoin (D…); missing from a profile derived before it was added, until the
  // next unlock.
  if (coin === "doge") return profile.addresses.doge ?? "";
  // Tron (T…); missing from a profile derived before it was added.
  if (coin === "trx") return profile.addresses.tron ?? "";
  // XRP (r…); missing from a profile derived before it was added.
  if (coin === "xrp") return profile.addresses.xrp ?? "";
  // Stellar (G…); missing from a profile derived before it was added.
  if (coin === "xlm") return profile.addresses.stellar ?? "";
  // NEAR: implicit account (64 hex); missing from a profile derived before it was
  // added.
  if (coin === "near") return profile.addresses.near ?? "";
  // Cardano: base address (addr1…); missing from a profile derived before it was
  // added.
  if (coin === "ada") return profile.addresses.cardano ?? "";
  // Stacks (SP…); missing from a profile derived before it was added.
  if (coin === "stx") return profile.addresses.stacks ?? "";
  // Bittensor (5…, SS58); missing from a profile derived before it was added.
  if (coin === "tao") return profile.addresses.bittensor ?? "";
  // Shielded Zcash: u1 address (Orchard receiver only).
  if (coin === "zecs") return profile.addresses.zcash_shielded ?? "";
  // Solana tokens (USDC, USDT…): the same owner address as SOL (the associated token
  // account that actually holds them is a detail invisible to the user, derived on
  // the Rust side; see core/src/sol_spl.rs).
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
  // Very long address (u1…, Monero): only the start and end on the card; in full in
  // the tooltip, the QR window and the copy.
  const shown = address.length > 64 ? `${address.slice(0, 14)}…${address.slice(-12)}` : address;
  // Copy shown by the "address" button of a collapsed card.
  for (const field of ["address", "collapsed-address"]) {
    const el = card.querySelector(`[data-field="${field}"]`);
    el.textContent = shown;
    el.title = address.length > 64 ? address : "";
  }
  updateConvertButton(card);
}

// "Convert" only where a swap exists for the crypto AND the network shown (see
// `swapPairs`): not on a test network, nor where it would swap the funds of a
// network other than the one shown.
//
// Liquid staking: the token received for each relevant network's native coin.
const LIQUID_STAKING = { sol_mainnet: { from: "sol", to: "jitosol" }, evm_mainnet: { from: "evm", to: "steth" } };

function liquidStakingFor(coin, network) {
  const target = LIQUID_STAKING[network];
  return target && target.from === coin && swapPairs.some((p) => p.from_coin === coin && p.from_network === network && p.to_coin === target.to) ? target : null;
}

// Liquid staking: a swap to the staking token in "Convert".
function openLiquidStaking(card) {
  const network = networkForCard(card);
  const target = liquidStakingFor(card.dataset.coin, network);
  if (!target) return;
  // Staking token card shown: the balance received will appear there.
  assetChoices[target.to] = true;
  saveAssetChoices();
  applyAssetVisibility();
  openSwapModal(card, { from: { coin: target.from, network }, to: { coin: target.to, network } });
}

function updateConvertButton(card) {
  // Cardano (delegation) and Solana (native staking): always; elsewhere, only if
  // liquid staking is possible.
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
  hiddenBalancesChecked = false; // new addresses: hidden cards reread
  updateBalanceWatch();
  // Profile addresses changed (unlock, profile switch): the portfolio chart follows.
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
    // Optional password: without it, the profile (name + index) is saved straight
    // away, but its address is only derived at the next full unlock (the seed is never
    // cached, see core/src/api.rs::create_profile).
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

// --- Profile archiving (soft, reversible) --------------------------------
//
// Unlike permanent deletion (below), archiving never touches the seed and asks for
// no password: the profile just disappears from the main selector, but remains
// fully recoverable from "Archived profiles" in Settings (see
// core/src/api.rs::archive_profile). This is the default path offered to the user;
// permanent deletion is only reachable from the archive list, never directly here.
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

// --- Archived profiles (Settings): restore or delete permanently -----

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
          // The restored profile's address is not known until the password has been entered
          // again (same principle as `create_profile` without a password): it will appear at
          // the next full unlock.
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

// Unlike archiving, this deletion is irreversible and asks for the password again:
// the app offers no way to recreate a profile at the same index later, so deleting
// a profile that has already received funds effectively loses access to them from
// this interface (see core/src/api.rs::delete_profile). The warning message says
// so explicitly rather than reassuring wrongly. Deliberately reachable ONLY from
// the archive list (not directly on an active profile): you have to archive first
// before you can delete for good, like a recycle bin.
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

// Network and address of a card: what the balance shown corresponds to.
function balanceKey(card) {
  const network = networkForCard(card);
  return `${network}|${addressForCoin(card.dataset.coin, network)}`;
}

// Quantity shown without needless zeros after the point ("0.24000000" → "0.24",
// "5000.000000" → "5000"). Nothing is rounded: Rust has already truncated to the
// number of decimals shown, only trailing zeros go. Readings of the displayed text
// (sort by value, Max, percentages, receipt) stay correct: parseFloat and
// balanceIncrease accept this form.
function displayAmount(raw) {
  return /^\d+\.\d+$/.test(raw) ? raw.replace(/\.?0+$/, "") : raw;
}

// Balance of `coin` on `network` at `address`, as Rust formats it ("0.500000", no
// symbol). USDC is an SPL token, not a "network" in the sense get_balance means
// (that command has no notion of decimals/mint per asset): a dedicated command,
// see core/src/api.rs::get_usdc_balance.
function fetchBalance(coin, network, address) {
  if (ASSET_BY_COIN[coin]?.stock) return stockBalance(coin, address);
  return usesTokenRegistry(coin, network)
    ? invoke("get_token_balance", { token: coin, network, address })
    : invoke(coin === "usdc" ? "get_usdc_balance" : "get_balance", { network, address });
}

// Balances of tokenized shares: a single request for all of them
// (get_stock_balances), shared for 5 s between the cards of the same address,
// instead of 19 reads, especially at unlock (hidden cards read once to spot
// funds).
const stockBalanceRequests = new Map();
function stockBalance(coin, address) {
  let entry = stockBalanceRequests.get(address);
  if (!entry || Date.now() - entry.at > 5000) {
    entry = { at: Date.now(), promise: invoke("get_stock_balances", { address }).then((list) => Object.fromEntries(list)) };
    stockBalanceRequests.set(address, entry);
    entry.promise.catch(() => stockBalanceRequests.delete(address));
  }
  return entry.promise.then((balances) => balances[coin] ?? "0.000000");
}

async function refreshBalance(card) {
  // Per-card lock, shared between the manual click ("Refresh" button) and the
  // automatic refresh (setInterval, every 60 s): without it, a network call taking
  // longer than 15 s (common with free public endpoints) would be overlapped by the
  // next tick, piling up concurrent requests for the same card; the same lag as a
  // double click, but triggered by the timer. A request arriving during a read (a
  // change reported live just after the request was sent): reread at the end, not
  // lost.
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
    // A balance already shown for this network and this address: it stays during the
    // read, and after a transient failure. Replacing it with "…" on every periodic
    // refresh made every balance flicker and, in list view, moved every row (column
    // fitted to "…"). Different network or profile: the old balance no longer means
    // anything.
    const shown = card.dataset.balanceKey === key;
    if (!shown) balanceEl.textContent = "…";
    // The balance and the "pending transaction" indicator are two independent calls
    // (neither depends on the other's result): running them in parallel rather than
    // one after the other halves the perceived refresh latency.
    const balancePromise = fetchBalance(coin, network, address)
      .then((balance) => {
        if (balanceKey(card) !== key) return; // network or profile changed in the meantime
        // Previous balance of THIS address on THIS network (not on first display, nor
        // after a profile or network change).
        const previous = card.dataset.balanceKey === key ? balanceEl.textContent : null;
        const text = displayAmount(balance);
        if (balanceEl.textContent !== text) balanceEl.textContent = text;
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
  // Network or profile changed during the read (ignored), or a change reported in
  // the meantime: reread.
  if (balanceKey(card) !== key || card.dataset.refreshAgain === "1") refreshBalance(card);
}

// --- Monero --------------------------------------------------------------------
//
// Balance kept by the background sync on the Rust side (blocks scanned with the
// view key, see core/src/monero.rs): the card rereads the local state after each
// pass, and shows the part still locked (10 confirmations).

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

// --- Shielded Zcash ------------------------------------------------------------
//
// A separate card (u1 address, Orchard receiver only): balance and history read on
// the Rust side from the local database that the background sync keeps up to date.
// Its status line says whether the sync is running, what is waiting for
// confirmation, or invites the user to shield the ZEC on the transparent card.

// While the sync runs, the status line is reread every 5 s (a local read, no
// network request): the automatic refresh only comes every 60 s, about as long as
// a whole sync, so the percentage would barely move otherwise. Not more often:
// each read slows the sync a little (it shares the database).
const SHIELDED_POLL_MS = 5000;
let shieldedPollTimer = null;

// Status line while the sync has not reached the tip of the chain.
function shieldedSyncText(status) {
  if (status.failed) return t("wallet.shieldedSyncFailed");
  // 0 % lasts the first ~20 s (first batch of blocks): plain text, so it never looks
  // stuck.
  if (status.progress) return t("wallet.shieldedSyncingProgress", { percent: status.progress });
  return t("wallet.shieldedSyncing");
}

async function refreshShieldedStatus(card) {
  const statusEl = card.querySelector('[data-field="coin-status"]');
  clearTimeout(shieldedPollTimer);
  try {
    const status = await invoke("zec_shielded_balance", { profileIndex: currentProfileIndex });
    const transparent = Number.parseFloat(document.querySelector('.wallet-card[data-coin="zec"] [data-field="balance"]')?.textContent);
    if (!status.synced) {
      shieldedPollTimer = setTimeout(() => {
        if (card.isConnected && dashboardShown() && !card.classList.contains("asset-hidden")) refreshShieldedStatus(card);
      }, SHIELDED_POLL_MS);
    }
    statusEl.textContent = !status.synced
      ? shieldedSyncText(status)
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

// Shielded spending window: "shield" (password only) or "send" (recipient,
// amount). The native confirmation dialog, built on the Rust side from the
// proposed transaction, shows the amount and fee.
let shieldedMode = "send";

// Other profiles offered as recipients (their shielded u1 address), like the
// address book under the regular send; the native dialog names the recognized
// profile based on the addresses derived on the Rust side.
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
// "Max": all spendable shielded funds, fee deducted (the Zcash library's
// proposal), recomputed at send time.
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

// A crypto hidden WITHOUT an explicit choice from the user, holding funds: shown
// (and remembered as such). A crypto hidden on purpose stays hidden.
function revealIfFunded(card, balance) {
  const coin = card.dataset.coin;
  if (isAssetVisible(coin) || coin in assetChoices || !(Number.parseFloat(balance) > 0)) return;
  assetChoices[coin] = true;
  saveAssetChoices();
  refreshAssetDisplays();
  showCopyToast(t("assets.autoShown", { symbol: ASSET_BY_COIN[coin].symbol }), 5000);
}

// Exact increase between two displayed balances ("0.12345678"), computed on
// integers scaled to the decimals, never in floating point, without needless zeros
// ("0.01"); `null` if the balance did not go up or is not a number.
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

// Funds arrived on a card shown: a message (5 s) and the balance briefly
// highlighted. Dollar value only on mainnet (test tokens are worthless).
function announceReceived(card, network, amount) {
  const coin = card.dataset.coin;
  const symbol = card.querySelector(".balance").textContent.trim().split(/\s+/).pop();
  const price = priceForCoin(coin);
  const mainnet = network.endsWith("_mainnet");
  const fiat = mainnet && price != null ? ` (${formatUsdApprox(Number(amount) * price)})` : "";
  showCopyToast(t("wallet.received", { amount, symbol, fiat }), 5000, coin);
  const balance = card.querySelector(".balance");
  balance.classList.remove("balance-received");
  void balance.offsetWidth; // restarts the animation if another receipt follows
  balance.classList.add("balance-received");
}

// Live monitoring (see core/src/balance_watch.rs): as soon as a send or receipt
// changes the balance of a card shown, Rust reports it ("balance-changed") and the
// card is reread straight away. Solana/USDC are pushed by the node (~1 s),
// Ethereum is reread every 6 s, Bitcoin and Dogecoin every 10 s (pending
// transactions included), transparent Zcash every 20 s, registry tokens (ERC-20
// every 12 s, Solana pushed). Monero and shielded Zcash: background sync every 30
// s. The 60 s refresh remains as a safety net.
function updateBalanceWatch() {
  const targets = [...document.querySelectorAll(".wallet-card:not(.asset-hidden)")]
    .map((card) => {
      const coin = card.dataset.coin;
      const network = networkForCard(card);
      // Registry tokens: contract or mint read on the Rust side (only the identifier
      // leaves from here).
      if (usesTokenRegistry(coin, network)) return { id: coin, network, address: addressForCoin(coin, network), token: coin };
      // Monero, shielded Zcash: balance kept by the background sync (`xmr-synced`,
      // `zec-shielded-synced` events).
      if (coin === "xmr" || coin === "zecs") return { address: "" };
      return { id: coin, network: coin === "usdc" ? "usdc_solana" : network, address: addressForCoin(coin, network) };
    })
    .filter((target) => target.address);
  invoke("watch_balances", { targets }).catch((e) => console.error(e));
}

// Cancellation delay of a send (Rust: `send_grace_period`), after the Windows
// confirmation and before signing: a countdown, "Confirm now" or "Cancel the
// send". Without an answer, the send goes out when the delay ends; it is Rust that
// waits, and these buttons can only shorten it or cancel.
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
  // Network, amount, address (and tag / memo): the ones from the Windows dialog.
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
  void progress.offsetWidth; // restarts the animation
  progress.classList.add("running");
  countdownModal.classList.remove("hidden");
  // Cancel by default: an Enter key never confirms by accident.
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

// Flags a transaction that has been detected but not finalized yet (Bitcoin
// mempool, Solana signature not yet "finalized"), useful for seeing incoming funds
// arrive before they count in the balance. Always `false` for Ethereum (see
// core/src/api.rs::has_pending_btc/has_pending_sol): no public EVM node exposes the
// pending transactions of an address, so the badge will never light up on ETH
// cards. Not a bug, a limit of the public network service used.
async function checkPendingTx(card, address, network) {
  const badge = card.querySelector('[data-field="pending"]');
  if (!badge || !address) return;
  try {
    const pending = await invoke("has_pending_tx", { network, address });
    // Bitcoin: an unconfirmed receipt is NOT counted in the balance (its sender can
    // still cancel it); its amount is shown here.
    const incoming = pending && network.startsWith("btc") ? await invoke("get_btc_pending_incoming", { network, address }) : null;
    const text = incoming ? t("wallet.pendingIncoming", { amount: incoming }) : t("wallet.pendingBadge");
    if (badge.textContent !== text) badge.textContent = text;
    badge.classList.toggle("visible", pending);
    // A new pending Bitcoin receipt (not counted in the balance yet): reported as soon
    // as it appears, through an INCREASE of the pending total; a decrease (receipt
    // confirmed, moved into the balance) is not a new receipt. Nothing on first
    // display, nor after a profile or network change.
    const key = balanceKey(card);
    const seen = card._pendingIncoming;
    const increase = incoming && seen && seen.key === key ? balanceIncrease(seen.amount || "0", incoming) : null;
    if (increase) showCopyToast(t("wallet.receivedPending", { amount: increase }), 5000);
    card._pendingIncoming = { key, amount: incoming };
    // Transaction not finalized yet: checked again in 15 s, since live monitoring does
    // not report finalization (the balance no longer moves). A single timer per card:
    // each refresh replaces it.
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
  // Shielded Zcash: sending from shielded funds (dedicated window).
  card.querySelector('[data-action="send"]').addEventListener("click", () => (card.dataset.coin === "zecs" ? openShieldedModal("send") : openSendModal(card)));
  // QR and copy buttons: those of the address line AND those of the collapsed card.
  card.querySelectorAll('[data-action="qr"]').forEach((button) => button.addEventListener("click", () => openQrModal(card)));
  // Clicking the address itself shows it in full (the same modal as the QR button,
  // which already shows the full text next to the QR code). Mostly useful in list
  // view (see styles.css: `.address` is truncated with "…" there for compactness),
  // but the same gesture is kept in card view for consistency.
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
  // Collapsed card: show / hide the address without expanding the card.
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
  // The same history as the "History" tab, opened directly on this crypto: easier to
  // find from the card than the tab alone.
  card.querySelector('[data-action="history"]').addEventListener("click", () => openCoinHistory(card.dataset.coin));
  const select = card.querySelector(".network-select");
  if (select) {
    // Unlike EVM/Solana, switching Bitcoin network also changes the address shown
    // (mainnet and testnet derive different addresses for the same profile, see
    // addressForCoin). Recomputed for every card safely, since it only changes value
    // for "btc".
    select.addEventListener("change", () => {
      renderCardAddress(card);
      refreshBalance(card);
      updateBalanceWatch();
    });
  }
});

// --- QR modal --------------------------------------------------------------

const qrModal = document.getElementById("qr-modal");

// Payment request: an optional amount written into the QR code, in each network's
// standard format, so whoever scans it sees the address AND the amount: BIP21 for
// Bitcoin, Solana Pay for SOL (and USDC, designated by its mint), EIP-681 for
// Ethereum (amount in wei, network by its chain ID). Without an amount: the
// address alone, readable by every app.
//
// Maximum decimals for a requested amount: 18 for any EVM currency.
const QR_DECIMALS = new Proxy({ btc: 8, sol: 9, zec: 8, zecs: 8, xmr: 12, doge: 8, trx: 6, xrp: 6, xlm: 7, near: 24, ada: 6, stx: 6 }, { get: (known, coin) => ASSET_BY_COIN[coin]?.unitDecimals ?? known[coin] ?? 18 });
// Same mint as core/src/sol_spl.rs::usdc_mint_mainnet.
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
let qrCard = null;
let qrRenderToken = 0;

// Amount entered ("0,01" accepted) → normalized decimal ("0.01"), `null` if empty
// or zero; throws an error if it is invalid.
function parseRequestAmount(raw, decimals) {
  let text = raw.trim().replace(",", ".");
  // Input in progress ("0.", "."): no amount yet, but not an error either; the red
  // message used to appear and disappear with every decimal amount typed. ".5" means
  // 0.5.
  if (!text || text === "." || /^\d+\.$/.test(text)) return null;
  if (/^\.\d+$/.test(text)) text = `0${text}`;
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
    // EIP-681, a transfer call on the token's contract (amount in exact units).
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

// QR code of the open card, with the amount entered if it is valid (otherwise the
// address alone, and the error under the field).
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
  if (token !== qrRenderToken || qrCard !== card) return; // a more recent input
  document.getElementById("qr-container").innerHTML = svg;
}

// Network name as exchanges show it when withdrawing (Binance, Coinbase, Kraken…):
// the one to pick to send here.
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
  // Added network: its name, as the user entered it.
  const name = EXCHANGE_NETWORK_NAMES[network] ?? CUSTOM_NETWORKS.find((net) => net.id === network)?.name;
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

// --- Transaction history (dedicated tab, sorted by network) -------------
//
// One network = one dashboard card (see data-coin): the card stays the single
// source of truth for "which network/which address" (mainnet or testnet, chosen
// with its selector); the tab only rereads that state, never a separate network
// choice of its own.

const HISTORY_COINS = ASSETS.map((asset) => asset.coin);

// Not in a block yet: no date (the status says "Pending").
function formatTxTimestamp(unixSeconds) {
  if (unixSeconds == null) return "";
  return new Date(unixSeconds * 1000).toLocaleString(chartLocale());
}

// Sends made from the app during this session that the network's history does not
// list yet (indexer a few seconds to a few minutes behind): shown as "Pending" at
// the top, so a send never seems to have disappeared. In memory only; forgotten as
// soon as the history lists them, or after an hour.
const RECENT_SEND_MAX_AGE_MS = 60 * 60 * 1000;
const recentSends = [];

function normalizeTxId(id) {
  return String(id).toLowerCase().replace(/^0x/, "");
}

function rememberRecentSend(coin, network, id, amount) {
  const address = addressForCoin(coin, network);
  if (!address || typeof id !== "string" || !id) return;
  const send = { coin, network, address, id, amount, at: Date.now(), explorerUrl: null };
  recentSends.push(send);
  invoke("tx_explorer_url", { network, tx: id }).then((url) => { send.explorerUrl = url; }).catch(() => {});
}

// Sends for `network`/`address` still missing from `entries`, newest first. Listed
// = same identifier; otherwise (TAO: the history designates a transaction by block
// and position, not by its hash) each send newer than the oldest one expected,
// with an unknown identifier, stands in for it, oldest to newest.
function recentSendsAwaiting(network, address, entries) {
  const now = Date.now();
  const ids = new Set(entries.map((tx) => normalizeTxId(tx.id)));
  const mine = recentSends.filter((send) => send.network === network && send.address === address && now - send.at < RECENT_SEND_MAX_AGE_MS);
  const known = new Set(mine.map((send) => normalizeTxId(send.id)));
  let waiting = mine.filter((send) => !ids.has(normalizeTxId(send.id))).sort((a, b) => a.at - b.at);
  if (waiting.length) {
    const since = waiting[0].at / 1000 - 120;
    const newer = entries.filter((tx) => tx.kind === "sent" && !known.has(normalizeTxId(tx.id)) && tx.timestamp_unix != null && tx.timestamp_unix >= since).length;
    waiting = waiting.slice(newer);
  }
  for (let i = recentSends.length - 1; i >= 0; i--) {
    const send = recentSends[i];
    const forget = now - send.at >= RECENT_SEND_MAX_AGE_MS || (send.network === network && send.address === address && !waiting.includes(send));
    if (forget) recentSends.splice(i, 1);
  }
  return waiting.reverse();
}

// History row for a pending send, in the same format as the others.
function recentSendEntry(send) {
  const price = TEST_NETWORKS.includes(send.network) ? null : priceForCoin(send.coin);
  return {
    id: send.id,
    timestamp_unix: Math.floor(send.at / 1000),
    status: "pending",
    kind: "sent",
    amount: `-${send.amount}`,
    usd_value: price != null ? Number(send.amount) * price : null,
    explorer_url: send.explorerUrl,
  };
}

// A send still pending: the history is reread every 30 s while it is shown
// (Activity tab or a crypto's history window) and the app window is visible, so it
// can be seen turning "Confirmed" without clicking Refresh. Cancelled by any new
// read of the same container.
function recheckHistoryLater(container, reload) {
  container._recheck = setTimeout(() => {
    if (document.hidden || !container.isConnected || container.offsetParent === null) return;
    reload();
  }, 30000);
}

function historyStatusLabel(status) {
  if (status === "confirmed") return t("wallet.historyConfirmed");
  if (status === "pending") return t("wallet.historyPending");
  if (status === "failed") return t("wallet.historyFailed");
  return status;
}

// Dollar amount shown in the chosen currency: "≈ 1 234,56 $" / "≈ $1,234.56" / "≈
// 1 085,20 €"; under a cent: "< 0,01 $". `fiat`: an amount already converted
// (otherwise, converted at the current rate).
function formatUsdApprox(usd, fiat = usdToFiat(usd)) {
  if (fiat == null) return "—";
  if (fiat > 0 && fiat < 0.01) return `< ${withCurrency((0.01).toLocaleString(chartLocale()))}`;
  return `≈ ${withCurrency(fiat.toLocaleString(chartLocale(), { minimumFractionDigits: 2, maximumFractionDigits: 2 }))}`;
}

// "-0.010000000000000000" → "-0.01": trailing zeros removed.
function trimAmount(amount) {
  return amount.includes(".") ? amount.replace(/0+$/, "").replace(/\.$/, "") : amount;
}

// Readable amount: decimals cut to the card's (`decimals`), but at least 3
// significant digits for a very small sum ("+0.00000000000123" stays readable);
// never rounded up. The exact amount from Rust stays available on hover (title).
function shortAmount(amount, decimals) {
  const [int, frac = ""] = amount.split(".");
  const firstDigit = frac.search(/[1-9]/);
  const keep = /^[+-]?0$/.test(int) && firstDigit >= 0 ? Math.max(decimals, firstDigit + 3) : decimals;
  return trimAmount(frac.length > keep ? `${int}.${frac.slice(0, keep)}` : amount);
}

function buildHistoryRow(tx, symbol, decimals) {
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
  if (dateSpan.textContent) meta.appendChild(dateSpan);
  meta.appendChild(statusSpan);
  left.appendChild(idDiv);
  left.appendChild(meta);

  const right = document.createElement("div");
  right.className = "history-right";
  const amountDiv = document.createElement("div");
  amountDiv.className = "history-amount";
  if (tx.amount != null && Number.parseFloat(tx.amount) !== 0) {
    amountDiv.classList.add(tx.amount.startsWith("-") ? "negative" : "positive");
    const shown = decimals != null ? shortAmount(tx.amount, decimals) : trimAmount(tx.amount);
    amountDiv.textContent = symbol ? `${shown} ${symbol}` : shown;
    if (shown !== trimAmount(tx.amount)) amountDiv.title = symbol ? `${trimAmount(tx.amount)} ${symbol}` : trimAmount(tx.amount);
  } else {
    // Nothing of this crypto moved (an "Other" transaction: token received, operation
    // paid for by a third party…): a dash rather than "+0.000000000".
    amountDiv.textContent = "—";
  }
  const amountBox = document.createElement("div");
  amountBox.className = "history-amount-box";
  amountBox.appendChild(amountDiv);
  // Value computed on the Rust side at the price at the time of the transaction (see
  // core/src/price_history.rs); absent on test networks.
  if (tx.usd_value != null) {
    const usdDiv = document.createElement("div");
    usdDiv.className = "history-usd";
    usdDiv.textContent = formatUsdApprox(tx.usd_value, usdToFiatAt(tx.usd_value, tx.timestamp_unix));
    usdDiv.title = t("history.usdAtTime");
    amountBox.appendChild(usdDiv);
  }
  // A regular <a target="_blank"> does not open reliably in the Tauri webview
  // (navigation intercepted for security reasons): we go through the dedicated
  // command that opens the system browser (see
  // app/src-tauri/src/lib.rs::open_external_link).
  const link = document.createElement("button");
  link.type = "button";
  link.className = "history-link";
  link.textContent = t("wallet.historyViewLink");
  link.addEventListener("click", () => {
    invoke("open_external_link", { url: tx.explorer_url }).catch((e) => alert(t("wallet.linkError", { err: e })));
  });
  right.appendChild(amountBox);
  if (tx.explorer_url) right.appendChild(link);

  row.appendChild(left);
  row.appendChild(right);
  return row;
}

function loadHistorySection(coin) {
  return renderHistory(coin, document.getElementById(`history-list-${coin}`), document.getElementById(`history-network-${coin}`));
}

// History of `coin` (its card's network and address) in `container`. A more recent
// read in the same container (another crypto opened in the meantime, Refresh)
// wins: a response arriving after it is ignored.
async function renderHistory(coin, container, networkEl) {
  const card = document.querySelector(`.wallet-card[data-coin="${coin}"]`);
  if (!card || !container || !networkEl) return;
  const load = String((Number(container.dataset.load) || 0) + 1);
  container.dataset.load = load;
  clearTimeout(container._recheck);
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
    // Tokens (Rust registry): a dedicated command; the UI only sends the token
    // identifier and the network (contract or mint read on the Rust side).
    const result = ASSET_BY_COIN[coin]?.token
      ? await invoke("get_token_tx_history", { token: coin, network, address })
      : await invoke("get_tx_history", { network, address });
    if (!current()) return;
    // History unavailable (BNB Chain without a NodeReal key in this build, or the
    // service's limit reached): the reason, and a link to the address's page on the
    // network's explorer.
    if (result.explorer_url) {
      container.replaceChildren(historyExplorerOnly(result.explorer_url, result.reason));
      return;
    }
    const entries = result.entries;
    const waiting = recentSendsAwaiting(network, address, entries);
    container.innerHTML = "";
    if (entries.length === 0 && waiting.length === 0) {
      container.innerHTML = `<p class="muted">${t("wallet.historyEmpty")}</p>`;
      return;
    }
    // Amount of a pending send: as entered, never cut.
    const { symbol, decimals } = ASSET_BY_COIN[coin] ?? {};
    waiting.forEach((send) => container.appendChild(buildHistoryRow(recentSendEntry(send), symbol)));
    entries.forEach((tx) => container.appendChild(buildHistoryRow(tx, symbol, decimals)));
    if (waiting.length) recheckHistoryLater(container, () => renderHistory(coin, container, networkEl));
  } catch (e) {
    if (!current()) return;
    // textContent, never innerHTML: the error message comes from Rust, which copies
    // into it the error JSON returned by the RPC server. A malicious server could have
    // slipped HTML into it (fake form, phishing link) straight into the wallet's
    // interface.
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

// "Receive" menu: one entry per crypto shown, USDC included (the receive window
// states its card's network, to be chosen when sending).
function renderReceiveMenu() {
  const list = document.querySelector(".action-menu .custom-select-options");
  const items = ASSETS.filter((asset) => !asset.stock && isAssetVisible(asset.coin)).map((asset) => {
    const li = document.createElement("li");
    li.dataset.coin = asset.coin;
    setWithCoinIcon(li, asset.coin, t("wallet.receiveAsset", { symbol: asset.nameKey ? assetName(asset) : asset.symbol }));
    return li;
  });
  list.replaceChildren(...items);
}
renderReceiveMenu();

// After a change to the cryptos shown: cards, menu, monitoring, live prices,
// portfolio chart.
function refreshAssetDisplays() {
  applyAssetVisibility();
  updatePortfolioTotal();
  renderReceiveMenu();
  updateBalanceWatch();
  if (lastMarketCoins) renderMarkets(lastMarketCoins);
  renderStockMarkets();
  if (portfolioView.rangesEl.childElementCount) refreshChart(portfolioView);
}

// "Manage my cryptos" window.
const assetsModal = document.getElementById("assets-modal");
// Search: name (displayed and original), symbol; ignoring case and accents ("zcash
// protege" finds "Zcash protégé").
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
// Escape in a non-empty search: clears it (the window stays open).
assetsSearch.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && assetsSearch.value) {
    e.stopPropagation();
    assetsSearch.value = "";
    filterAssetsList();
  }
});

// `stocks`: tokenized shares ("Stocks" tab), otherwise cryptos.
function openAssetsModal(stocks) {
  const list = document.getElementById("assets-list");
  const boxes = new Map();
  const title = assetsModal.querySelector(".modal-header-row h2");
  const hint = assetsModal.querySelector(".modal-header-row + p");
  title.dataset.i18n = stocks ? "stocks.title" : "assets.title";
  hint.dataset.i18n = stocks ? "stocks.manageHint" : "assets.hint";
  title.textContent = t(title.dataset.i18n);
  hint.textContent = t(hint.dataset.i18n);
  const search = stocks ? "stocks.search" : "assets.search";
  assetsSearch.dataset.i18nPlaceholder = search;
  assetsSearch.dataset.i18nAriaLabel = search;
  assetsSearch.placeholder = t(search);
  assetsSearch.setAttribute("aria-label", t(search));
  // Stocks: by company market cap, descending (those without a price: after the rest).
  const cap = (coin) => stockQuotes[coin]?.market_cap_usd ?? -1;
  const coins = stocks
    ? ASSETS.filter((asset) => asset.stock).map((asset) => asset.coin).sort((a, b) => cap(b) - cap(a))
    : orderedCoins().filter((coin) => !ASSET_BY_COIN[coin].stock);
  list.replaceChildren(
    ...coins.map((coin) => ASSET_BY_COIN[coin]).map((asset) => {
      const li = document.createElement("li");
      li.dataset.coin = asset.coin;
      if (asset.stock) li.dataset.stock = "1";
      li.dataset.search = normalizeSearch(`${assetName(asset)} ${asset.name} ${asset.symbol} ${asset.stock ? "action xstock stock" : ""}`);
      const label = document.createElement("label");
      label.className = "asset-choice";
      const icon = asset.icon
        ? Object.assign(document.createElement("img"), { src: asset.icon, alt: "", className: asset.iconRound ? "coin-icon coin-icon-round" : asset.coin === "sol" ? "coin-icon coin-icon-sol" : "coin-icon" })
        : letterIcon(asset, "coin-icon");
      const name = Object.assign(document.createElement("span"), { className: "asset-choice-name", textContent: assetName(asset) });
      const symbol = Object.assign(document.createElement("span"), { className: "muted", textContent: asset.symbol });
      const box = Object.assign(document.createElement("input"), { type: "checkbox", checked: isAssetVisible(asset.coin) });
      boxes.set(asset.coin, box);
      box.addEventListener("change", () => {
        assetChoices[asset.coin] = box.checked;
        saveAssetChoices();
        refreshAssetDisplays();
        // Checkboxes that follow another one (shielded Zcash follows Zcash when it has no
        // choice of its own): updated.
        for (const [coin, other] of boxes) {
          other.checked = isAssetVisible(coin);
          if (other !== box && other.checked) refreshBalance(document.querySelector(`.wallet-card[data-coin="${coin}"]`));
        }
        if (box.checked) refreshBalance(document.querySelector(`.wallet-card[data-coin="${asset.coin}"]`));
        // Tokenized share shown: its price straight away, without waiting for the next
        // cycle.
        if (box.checked && asset.stock) {
          refreshStockPrices().then(() => {
            document.querySelectorAll(".wallet-card").forEach(updateFiatValue);
            scheduleCardResort();
            renderStockMarkets();
          });
        }
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
  // Prices not requested yet (no share shown): the window opens straight away, then
  // the list sorts itself as soon as they arrive.
  if (stocks && Object.keys(stockQuotes).length === 0) {
    refreshStockPrices(true).then(() => {
      if (assetsModal.classList.contains("hidden") || title.dataset.i18n !== "stocks.title") return;
      list.append(...[...list.children].sort((a, b) => cap(b.dataset.coin) - cap(a.dataset.coin)));
    });
  }
}

document.getElementById("manage-assets-btn").addEventListener("click", () => openAssetsModal(false));
document.getElementById("manage-stocks-btn").addEventListener("click", () => openAssetsModal(true));
// Closed by "Done", the X button, Escape, or a click outside, but only if the
// click also STARTED outside: a gesture started inside the window (scrolling the
// list, selecting text) and released outside does not close it.
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

// --- Card order ("Arrange") ------------------------------------------
//
// Three modes: "My order" (drag and drop or arrows), "Value held" (currency value
// of the balance shown, descending, recomputed with each new balance or price) and
// "Name". A per-device display preference, remembered locally like the list view.
// Reordering only changes where elements sit in the grid (and in the History tab,
// and the "Manage my cryptos" list): no other code depends on it.

// Two "boards", each with its own grid, order and "Arrange" bar: the cryptos
// ("Wallet" tab) and the tokenized shares ("Stocks" tab, which also has the
// "Market cap" sort, the default there).
const CARD_ORDER_STORAGE_KEY = "pgp-wallet-card-order";
const STOCK_ORDER_STORAGE_KEY = "pgp-wallet-stock-order";
const walletGrid = document.querySelector(".wallet-grid");

function makeBoard({ grid, storageKey, modes, defaultMode, bar, button, done }) {
  // Original order (index.html cards, then those generated from ASSETS): the basis
  // of "My order" for cards that were never moved.
  const defaultOrder = [...grid.querySelectorAll(".wallet-card")].map((card) => card.dataset.coin);
  let order = { mode: defaultMode, custom: [] };
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    if (saved && modes.includes(saved.mode) && Array.isArray(saved.custom)) {
      order = { mode: saved.mode, custom: saved.custom.filter((coin) => defaultOrder.includes(coin)) };
    }
  } catch (e) {
    // localStorage unavailable: original order.
  }
  return { grid, storageKey, defaultOrder, order, bar, button, done, organizing: false, resortTimer: null };
}

const BOARDS = {
  wallet: makeBoard({
    grid: walletGrid,
    storageKey: CARD_ORDER_STORAGE_KEY,
    modes: ["custom", "value", "name"],
    defaultMode: "custom",
    bar: document.getElementById("organize-bar"),
    button: document.getElementById("organize-btn"),
    done: document.getElementById("organize-done"),
  }),
  stocks: makeBoard({
    grid: document.querySelector(".stocks-grid"),
    storageKey: STOCK_ORDER_STORAGE_KEY,
    modes: ["cap", "custom", "value", "name"],
    defaultMode: "cap",
    bar: document.getElementById("stocks-organize-bar"),
    button: document.getElementById("stocks-organize-btn"),
    done: document.getElementById("stocks-organize-done"),
  }),
};
let draggingCard = null;

function saveCardOrder(board) {
  try {
    localStorage.setItem(board.storageKey, JSON.stringify(board.order));
  } catch (e) {
    // Best-effort: the order stays applied for this session.
  }
}

// Full "My order": the saved order, then the cryptos that are not in it yet (added
// since), at their original place.
function customOrder(board) {
  const order = [...board.order.custom];
  // A crypto added since (shielded Zcash…): right after the one that precedes it in
  // the original order, not at the end of the list.
  board.defaultOrder.forEach((coin, i) => {
    if (order.includes(coin)) return;
    const before = board.defaultOrder.slice(0, i).reverse().find((c) => order.includes(c));
    order.splice(before ? order.indexOf(before) + 1 : 0, 0, coin);
  });
  return order;
}

// Currency value of the balance shown on the card (test network: none).
function cardValue(board, coin) {
  const card = board.grid.querySelector(`.wallet-card[data-coin="${coin}"]`);
  if (!card || TEST_NETWORKS.includes(networkForCard(card))) return 0;
  const amount = Number.parseFloat(card.querySelector('[data-field="balance"]').textContent);
  const price = priceForCoin(coin);
  return Number.isFinite(amount) && price != null ? amount * price : 0;
}

function orderedCoins(board = BOARDS.wallet) {
  const custom = customOrder(board);
  const rank = new Map(custom.map((coin, i) => [coin, i]));
  if (board.order.mode === "value") {
    const values = new Map(custom.map((coin) => [coin, cardValue(board, coin)]));
    return [...custom].sort((a, b) => values.get(b) - values.get(a) || rank.get(a) - rank.get(b));
  }
  // Company market cap (Jupiter price), descending; without a price: after the rest,
  // in "My order".
  if (board.order.mode === "cap") {
    const cap = (coin) => stockQuotes[coin]?.market_cap_usd ?? -1;
    return [...custom].sort((a, b) => cap(b) - cap(a) || rank.get(a) - rank.get(b));
  }
  if (board.order.mode === "name") {
    const collator = new Intl.Collator(currentLang);
    return [...custom].sort((a, b) => collator.compare(assetName(ASSET_BY_COIN[a]), assetName(ASSET_BY_COIN[b])));
  }
  return custom;
}

// Puts the elements in the desired order without moving anything that is already
// in place (no display jump or loss of focus on each recalculation).
function placeInOrder(container, elements) {
  const current = [...container.children].filter((el) => elements.includes(el));
  if (current.length === elements.length && current.every((el, i) => el === elements[i])) return;
  for (const el of elements) container.appendChild(el);
}

// Without a board: both.
function applyCardOrder(board) {
  if (draggingCard) return;
  if (!board) {
    Object.values(BOARDS).forEach(applyCardOrder);
    return;
  }
  const coins = orderedCoins(board);
  placeInOrder(board.grid, coins.map((coin) => board.grid.querySelector(`.wallet-card[data-coin="${coin}"]`)).filter(Boolean));
  // History tab: the cryptos, then the stocks, each in the order of its own tab.
  const historyCard = document.querySelector('.tab-panel[data-panel="history"] .card');
  const all = [...orderedCoins(BOARDS.wallet), ...orderedCoins(BOARDS.stocks)];
  placeInOrder(historyCard, all.map((coin) => document.getElementById(`history-section-${coin}`)).filter(Boolean));
}

// "Value held" and "Market cap": recomputed after a new balance or price, batched
// (several balances arrive almost together).
function scheduleCardResort() {
  for (const board of Object.values(BOARDS)) {
    if (board.order.mode !== "value" && board.order.mode !== "cap") continue;
    clearTimeout(board.resortTimer);
    board.resortTimer = setTimeout(() => applyCardOrder(board), 500);
  }
}

function setCardOrderMode(board, mode) {
  board.order.mode = mode;
  saveCardOrder(board);
  applyCardOrder(board);
  renderOrganizeModes(board);
}

function renderOrganizeModes(board) {
  board.bar.querySelectorAll("[data-order-mode]").forEach((button) => {
    const active = button.dataset.orderMode === board.order.mode;
    button.classList.toggle("primary", active);
    button.classList.toggle("secondary", !active);
    button.setAttribute("aria-pressed", String(active));
  });
}

// Current display order → "My order" (after a drag or an arrow).
function adoptDisplayedOrder(board) {
  board.order.custom = [...board.grid.querySelectorAll(".wallet-card")].map((card) => card.dataset.coin);
  setCardOrderMode(board, "custom");
}

// Each card's handle and arrows, only visible in "Arrange" mode.
function addOrganizeControls(board, card) {
  const controls = document.createElement("div");
  controls.className = "organize-controls";
  controls.innerHTML = `
    <span class="drag-handle" aria-hidden="true" data-i18n-title="organize.drag">⠿</span>
    <button type="button" class="organize-move" data-move="-1" data-i18n-title="organize.moveUp" aria-label="${t("organize.moveUp")}">↑</button>
    <button type="button" class="organize-move" data-move="1" data-i18n-title="organize.moveDown" aria-label="${t("organize.moveDown")}">↓</button>`;
  controls.querySelectorAll("[data-move]").forEach((button) => {
    button.title = t(button.dataset.move === "-1" ? "organize.moveUp" : "organize.moveDown");
    button.addEventListener("click", () => moveCard(board, card, Number(button.dataset.move), button));
  });
  card.prepend(controls);
}
for (const board of Object.values(BOARDS)) board.grid.querySelectorAll(".wallet-card").forEach((card) => addOrganizeControls(board, card));

// Moves a card one step among the cards SHOWN (hidden ones keep their relative
// place).
function moveCard(board, card, step, focusAfter) {
  if (draggingCard) return;
  const visible = [...board.grid.querySelectorAll(".wallet-card:not(.asset-hidden)")];
  const neighbor = visible[visible.indexOf(card) + step];
  if (!neighbor) return;
  animateLayout(board, () => board.grid.insertBefore(card, step < 0 ? neighbor : neighbor.nextSibling));
  adoptDisplayedOrder(board);
  focusAfter?.focus();
}

function setOrganizing(board, on) {
  if (!on && pointerDrag?.board === board) cancelCardDrag();
  board.organizing = on;
  board.bar.classList.toggle("hidden", !on);
  board.button.setAttribute("aria-pressed", String(on));
  board.grid.classList.toggle("organizing", on);
  renderOrganizeModes(board);
}

for (const board of Object.values(BOARDS)) {
  board.button.addEventListener("click", () => setOrganizing(board, !board.organizing));
  board.done.addEventListener("click", () => setOrganizing(board, false));
  board.bar.querySelectorAll("[data-order-mode]").forEach((button) => {
    button.addEventListener("click", () => setCardOrderMode(board, button.dataset.orderMode));
  });
}
document.addEventListener("keydown", (e) => {
  const board = Object.values(BOARDS).find((b) => b.organizing);
  if (e.key !== "Escape" || !board || document.querySelector(".modal-overlay:not(.hidden)")) return;
  if (pointerDrag) cancelCardDrag();
  else setOrganizing(board, false);
});

// Pointer-based drag and drop (mouse, pen, touch), not HTML5 drag and drop: on
// Windows, Tauri intercepts dragging in the window (file drop) and its events
// never reach the cards. After a few pixels, the card itself lifts and follows the
// pointer (slightly tilted, shadowed); a dotted placeholder marks where it will be
// put and moves between the other cards, which slide smoothly; near the edge of
// the window, the page scrolls; on release, the card slides to the placeholder
// (Escape takes it back to where it was). No copy of the card: the lifted card
// stays the real one (its balance keeps updating).
const DRAG_START_DISTANCE = 6;
const DRAG_SCROLL_EDGE = 70;
const DRAG_SCROLL_MAX_SPEED = 18;
const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let pointerDrag = null;

// Layout rectangle (without the translations of running animations), in window
// coordinates.
function layoutRect(el) {
  const rect = el.getBoundingClientRect();
  const transform = getComputedStyle(el).transform;
  const matrix = transform && transform !== "none" ? new DOMMatrixReadOnly(transform) : null;
  const dx = matrix ? matrix.m41 : 0;
  const dy = matrix ? matrix.m42 : 0;
  return { left: rect.left - dx, top: rect.top - dy, width: rect.width, height: rect.height, right: rect.right - dx, bottom: rect.bottom - dy };
}

// Reorders (`change`), then slides each card and the placeholder from their old
// visual position to the new one (FLIP technique), running animations included.
function animateLayout(board, change) {
  const items = [...board.grid.querySelectorAll(".wallet-card:not(.asset-hidden):not(.drag-floating), .card-placeholder")];
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
      // End of the slide: no inline styles left. If it is interrupted by a new reorder,
      // that one takes over the card.
      const done = (e) => {
        if (e.target !== el || e.propertyName !== "transform") return;
        el.removeEventListener("transitionend", done);
        if (!el.style.transform) el.style.transition = "";
      };
      el.addEventListener("transitionend", done);
    }
  });
}

// A card's columns at fixed widths. In list view, the card is a subgrid
// (`subgrid`) that has no columns once it is out of the grid: it gets the grid's
// columns, minus its padding and border at the edges (which the subgrid passes on
// to the elements in the outermost columns).
function frozenColumns(board, style) {
  if (!style.gridTemplateColumns.startsWith("subgrid")) return style.gridTemplateColumns;
  const tracks = (getComputedStyle(board.grid).gridTemplateColumns.match(/[\d.]+px/g) || []).map(parseFloat);
  if (!tracks.length) return "";
  tracks[0] -= parseFloat(style.paddingLeft) + parseFloat(style.borderLeftWidth);
  tracks[tracks.length - 1] -= parseFloat(style.paddingRight) + parseFloat(style.borderRightWidth);
  return tracks.map((track) => `${Math.max(track, 0)}px`).join(" ");
}

function startCardDrag(drag) {
  const { card, board } = drag;
  const rect = card.getBoundingClientRect();
  const style = getComputedStyle(card);
  // Grid columns frozen for the duration of the drag: in list view, their width
  // depends on the content of every card, and the other cards would change columns
  // when losing the lifted card.
  board.grid.style.gridTemplateColumns = getComputedStyle(board.grid).gridTemplateColumns;
  const placeholder = document.createElement("div");
  placeholder.className = "card-placeholder";
  placeholder.style.height = `${rect.height}px`;
  board.grid.insertBefore(placeholder, card);
  // The card leaves the grid (fixed position) while keeping its size and columns.
  card.style.gridTemplateColumns = frozenColumns(board, style);
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

// Places the placeholder according to the card under the pointer (layout
// rectangles, so it does not oscillate during animations): before or after it,
// vertically when it spans the full width (one column, list view), horizontally
// otherwise.
function placePlaceholder(drag) {
  const { placeholder, lastX: x, lastY: y, board } = drag;
  const candidates = [...board.grid.querySelectorAll(".wallet-card:not(.asset-hidden):not(.drag-floating)")];
  const target = candidates.find((el) => {
    const r = layoutRect(el);
    return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
  });
  if (!target) return;
  const r = layoutRect(target);
  const fullRow = r.width > board.grid.clientWidth * 0.75;
  const before = fullRow ? y < r.top + r.height / 2 : x < r.left + r.width / 2;
  const reference = before ? target : target.nextSibling;
  if (reference === placeholder || placeholder.nextSibling === reference) return;
  animateLayout(board, () => board.grid.insertBefore(placeholder, reference));
}

// Continuous scrolling near the edge of the window, faster right at the edge.
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

for (const board of Object.values(BOARDS)) {
  board.grid.addEventListener("pointerdown", (e) => {
    if (!board.organizing || e.button !== 0 || pointerDrag || draggingCard || e.target.closest(".organize-move")) return;
    const card = e.target.closest(".wallet-card");
    if (!card) return;
    pointerDrag = { board, card, pointerId: e.pointerId, startX: e.clientX, startY: e.clientY, started: false };
    card.setPointerCapture(e.pointerId);
    e.preventDefault();
  });
}

// Movement and release are listened for on the whole page: the lifted card is no
// longer under the pointer, and the release may happen outside the grid.
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

// End of the drag: the card slides to the placeholder, then takes its place back
// in the grid; `draggingCard` stays set until then (no sorting or new drag while
// it settles).
function finishCardDrag(drag, { adopt }) {
  const { card, placeholder, board } = drag;
  pointerDrag = null;
  if (card.hasPointerCapture(drag.pointerId)) card.releasePointerCapture(drag.pointerId);
  if (!drag.started) return;
  cancelAnimationFrame(drag.scrollFrame);
  const settle = () => {
    card.classList.remove("drag-floating", "drag-landing");
    for (const property of ["gridTemplateColumns", "left", "top", "width", "height", "transform", "transition"]) card.style[property] = "";
    placeholder.replaceWith(card);
    board.grid.style.gridTemplateColumns = "";
    draggingCard = null;
    if (adopt) adoptDisplayedOrder(board);
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

// Escape (or leaving the mode) during the drag: the card goes back to its original
// place (it never left its position in the grid, only the placeholder moved), and
// the sort mode does not change.
function cancelCardDrag() {
  const drag = pointerDrag;
  if (drag.started) animateLayout(drag.board, () => drag.board.grid.insertBefore(drag.placeholder, drag.card));
  finishCardDrag(drag, { adopt: false });
}

function endPointerDrag(e) {
  if (pointerDrag && e.pointerId === pointerDrag.pointerId) finishCardDrag(pointerDrag, { adopt: true });
}
document.addEventListener("pointerup", endPointerDrag);
document.addEventListener("pointercancel", (e) => {
  if (pointerDrag && e.pointerId === pointerDrag.pointerId) cancelCardDrag();
});

// Initial order once the whole module has loaded ("Value held" reads constants
// declared further down in this file).
setTimeout(() => applyCardOrder(), 0);

// --- A crypto's history (window) --------------------------------------
//
// A card's "History" button: a large window above the wallet, which stays visible
// behind it, blurred; this crypto only (the "Activity" tab keeps every crypto).
// Closed by the X button, Escape, or a click outside that also started outside
// (like "Manage my cryptos").

const coinHistoryModal = document.getElementById("coin-history-modal");
let coinHistoryCoin = null;

function coinHistoryOpen() {
  return !coinHistoryModal.classList.contains("hidden");
}

function renderCoinHistoryTitle() {
  const card = document.querySelector(`.wallet-card[data-coin="${coinHistoryCoin}"]`);
  if (!card) return;
  // Name read from the card, without the HTML indentation: "Bitcoin", "USDC Solana".
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
  // A read still in progress: its response is ignored (see `renderHistory`).
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
// New language: title and rows translated again (after `applyLanguage`, subscribed
// above).
document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (coinHistoryOpen()) loadCoinHistory();
  });
});

// --- Send modal ----------------------------------------------------------

const sendModal = document.getElementById("send-modal");
let sendContext = null;

// Amount in crypto OR in the display currency (€ or $), the two fields linked by
// the live price. The crypto amount is the only one sent, shown in the preview and
// then in the Windows confirmation dialog; the currency amount is only an input
// aid. On a test network (worthless funds) or with no known price, the currency
// field is disabled.
const sendAmountInput = document.getElementById("send-amount");
const sendFiatInput = document.getElementById("send-amount-fiat");

// Price of a crypto: dollars per unit, dollars per unit of the display currency;
// `null` if unknown or on a test network (worthless funds).
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

// Text of the currency field for a crypto amount ("12,34"), and text of the crypto
// field for a currency amount (at the crypto's decimals).
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
// Amount typed by hand: it is no longer the maximum.
for (const input of [sendAmountInput, sendFiatInput]) {
  input.addEventListener("input", () => {
    if (sendContext) sendContext.max = false;
  });
}

// Units to the right of both fields, currency field enabled or not.
function renderSendAmountUnits() {
  if (!sendContext) return;
  setWithCoinIcon(document.getElementById("send-amount-unit"), sendContext.coin, COIN_SYMBOL[sendContext.coin]);
  document.getElementById("send-amount-fiat-unit").textContent = displayCurrency === "eur" ? "€" : "$";
  const rate = sendRate();
  sendFiatInput.disabled = !rate;
  sendFiatInput.placeholder = rate ? (currentLang === "fr" ? "0,00" : "0.00") : "—";
}

// Quick amounts in dollars: converted to crypto at the live price (see
// `latestPrices`/`refreshPrices`), not fixed amounts in ETH/BTC/SOL, which only
// makes sense if the dollar amount stays the same whatever the day's price. The
// same decimals as the balance formatting on the Rust side
// (app/src-tauri/src/lib.rs::get_balance), so the amount filled in is the one
// actually sent, not a differently rounded value.
//
// Quick amounts, in the display currency ($5 or €5…).
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

  // Dollars per unit of the display currency (1 for the dollar).
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

// Percentages of the balance currently shown on the card (no new network call:
// reuses `[data-field="balance"]`, already kept up to date by refreshBalance).
// "Max": the largest amount that CAN BE SENT, network fees deducted, computed on
// the Rust side (`max_send_amount`) with the same rules as the send, then
// recomputed at confirmation (`max: true`), so the amount shown in the Windows
// dialog stays exact if the fees move.
const QUICK_PERCENTAGES = [25, 50, 100];

// Registry token (or USDC) sent from the card: its identifier, otherwise `null`
// (the network's native coin).
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

// "Available: 0.0419 SOL (≈ $5.03)" to the right of "Amount": the balance shown on
// the card, without needless zeros.
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
  // The source profile is frozen when the window opens (`sendContext.profileIndex`)
  // rather than reread from `currentProfileIndex` at confirmation time. The
  // full-screen modal already prevents switching profile while it is open, but
  // freezing the value explicitly avoids relying on that display side effect for a
  // security guarantee (which profile signs the transaction).
  const profile = currentProfile();
  sendContext = { coin: card.dataset.coin, card, profileIndex: profile ? profile.index : currentProfileIndex, max: false };
  const network = networkForCard(card);
  // Name read from the card, without the HTML indentation (the title contains the
  // collapse button): "Bitcoin", "USDC Solana".
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

// Bitcoin fee for a tier (total in satoshis) stated in the display currency, or in
// BTC without a price (test network, price not loaded yet).
function btcFeeText(sat, network) {
  const btc = sat / 1e8;
  const price = network === "btc_mainnet" ? priceForCoin("btc") : null;
  return price != null ? formatUsdApprox(btc * price) : `${btc.toLocaleString(chartLocale(), { maximumSignificantDigits: 3 })} BTC`;
}

// Bitcoin is the only network where the fee is an explicit choice by the user (see
// core/src/api.rs::estimate_btc_fees): EVM/Solana already compute theirs
// automatically (gas price / network base fee), so there is nothing to offer for
// them.
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
      satSpan.textContent = btcFeeText(sat, network);
      satSpan.title = `${sat} sat`;
      btn.appendChild(labelSpan);
      btn.appendChild(hintSpan);
      btn.appendChild(satSpan);

      btn.addEventListener("click", () => {
        container.querySelectorAll(".fee-option-btn").forEach((b) => b.classList.remove("selected"));
        btn.classList.add("selected");
        sendContext.feeSat = sat;
        // Maximum depends on the chosen fee: recomputed.
        if (sendContext.max) fillMaxAmount(document.querySelector("#send-quick-percentages .quick-amount-btn:last-child"));
      });

      // "Medium" preselected: a reasonable default compromise; the user is still free to
      // pick faster/cheaper before confirming.
      if (index === 1) {
        btn.classList.add("selected");
        sendContext.feeSat = sat;
      }
      container.appendChild(btn);
    });
  } catch (e) {
    // Same reason as in loadHistorySection: error text coming from a third-party
    // server (Esplora), never interpreted as HTML.
    container.replaceChildren(mutedParagraph(t("wallet.feeUnavailable", { err: e })));
  }
}

document.getElementById("send-cancel").addEventListener("click", () => {
  sendModal.classList.add("hidden");
  sendContext = null;
});

// Recipient detail required by exchanges: destination tag (XRP, digits) or memo
// (Stellar, short ASCII text).
const NOTE_COINS = new Set(["xrp", "xlm", "stx"]);
// Memo: maximum length depends on the network (Stellar 28 bytes, Stacks 34).
const MEMO_MAX = { xlm: 28, stx: 34 };

// Labels of the field, its hint and the preview row depending on the crypto (i18n
// keys changed too, for a language switch while the window is open).
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

// Value entered for the window's crypto, `null` if empty or for another crypto.
function sendNote(coin) {
  if (sendContext?.coin !== coin) return null;
  const value = document.getElementById("send-tag").value.trim();
  return value === "" ? null : value;
}
const sendDestinationTag = () => sendNote("xrp");
const sendMemo = () => (sendContext?.coin in MEMO_MAX ? sendNote(sendContext.coin) : null);

// XRP: digits only; Stellar: printable ASCII (pasting included).
document.getElementById("send-tag").addEventListener("input", (event) => {
  const max = MEMO_MAX[sendContext?.coin];
  const filtered = max ? event.target.value.replace(/[^\x20-\x7e]/g, "").slice(0, max) : event.target.value.replace(/\D/g, "").slice(0, 10);
  if (filtered !== event.target.value) event.target.value = filtered;
});

// Address fields: no space possible (Space key blocked, spaces removed from a
// paste). An address never contains one, and a space slipped in by mistake would
// make it invalid.
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

// Recipient warnings in the preview (Rust, `recipient_warnings`): address almost
// identical to a known one, lookalike of a contact, new address, blockchain state;
// the same ones as the Windows dialog, which remains the real protection.
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
  // Same routing as the send: registry token, Solana USDC, native coin.
  const token = usesTokenRegistry(coin, network) ? coin : coin === "usdc" ? "usdc" : null;
  let warnings = [];
  try {
    warnings = await invoke("recipient_warnings", { network, token, to });
  } catch (e) {
    // Address refused (Solana token account, malformed address…): the send would
    // refuse it too, so we might as well say so in the preview.
    warnings = [{ level: "danger", text: String(e) }];
  }
  if (check !== recipientCheck) return;
  box.replaceChildren(...warnings.map((w) => line(w.level, w.text)));
  box.classList.toggle("hidden", warnings.length === 0);
}

// Step 1: validates the fields, then shows a styled preview (network, recipient,
// amount, fees). No network call or secret involved here yet, just rereading what
// is already in the form.
const sendConfirmBtn = document.getElementById("send-confirm");

// An address from another network (a Bitcoin address on the Ethereum card, an
// Ethereum address on the USDC card set to Solana…): said at this step, in plain
// words, rather than at the end of the send. Networks recognized by Rust
// (`address_networks`, the same parsers as the send); nothing is said if the
// address is recognized nowhere (a rare form: the send will decide), nor if the
// wallet's own address is not recognized on that network.
async function wrongNetworkMessage(coin, network, to) {
  try {
    const own = addressForCoin(coin, network);
    const [networks, ownNetworks] = await Promise.all([invoke("address_networks", { address: to }), own ? invoke("address_networks", { address: own }) : []]);
    if (networks.length === 0 || networks.includes(network) || !ownNetworks.includes(network)) return null;
    const found = networks.some(isEvmNetwork) ? t("send.evmAddressFamily") : contactNetworkLabel(networks[0]);
    const symbol = COIN_SYMBOL[coin];
    // The same crypto offered on that network by the card: switching to it is enough.
    if (ASSET_BY_COIN[coin]?.networks.some((n) => networks.includes(n))) return t("send.addressSwitchNetwork", { network: found, symbol });
    return t("send.addressOtherNetwork", { network: found, cardNetwork: contactNetworkLabel(network) });
  } catch (e) {
    console.error(e);
    return null;
  }
}

sendConfirmBtn.addEventListener("click", withBusyButton(sendConfirmBtn, async () => {
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
  const context = sendContext;
  const wrongNetwork = await wrongNetworkMessage(context.coin, networkForCard(context.card), to);
  if (sendContext !== context) return;
  if (wrongNetwork) {
    showError(errorEl, wrongNetwork);
    return;
  }

  document.getElementById("send-preview-network").textContent = networkLabelForCard(sendContext.card);
  document.getElementById("send-preview-from").textContent = document.getElementById("send-from-profile").textContent;
  document.getElementById("send-preview-to").textContent = to;
  // XRP, Stellar: tag or memo always shown ("none" included), as in the native
  // dialog.
  document.getElementById("send-preview-tag-row").classList.toggle("hidden", !NOTE_COINS.has(sendContext.coin));
  document.getElementById("send-preview-tag").textContent = tag ?? memo ?? t("send.destinationTagNone");
  const rate = sendRate();
  const approx = rate ? ` (${formatUsdApprox(Number(amount) * rate.price)})` : "";
  // Token: its whole balance goes (fees are paid in the network's crypto).
  const tokenMax = sendContext.coin === "usdc" || usesTokenRegistry(sendContext.coin, networkForCard(sendContext.card));
  const maxNote = sendContext.max ? t(tokenMax ? "send.maxSuffixToken" : "send.maxSuffix") : "";
  setWithCoinIcon(document.getElementById("send-preview-amount"), sendContext.coin, `${amount} ${COIN_SYMBOL[sendContext.coin]}${maxNote}${approx}`);

  const feeRow = document.getElementById("send-preview-fee-row");
  const selectedFeeBtn = document.querySelector("#send-fee-options .fee-option-btn.selected");
  if (sendContext.coin === "btc" && selectedFeeBtn) {
    // The button's 3 <span> elements (label/hint/sat) have no space between them in
    // the DOM (just placed side by side visually with flex): read one by one and
    // joined here rather than through the global `.textContent`, which would glue them
    // together ("Fast~10 min1240 sat" instead of "Fast · ~10 min · 1240 sat").
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
}));

// A crypto available on several networks (ETH, USDC, USDT…): a reminder of the
// source network, since depositing to an exchange over a different network than
// the one it expects is one of the most common losses.
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

// Estimated network fee in the preview, in currency and in the network's coin (the
// native confirmation dialog then shows the exact amount): discovering fees at the
// last moment is one of wallet users' most common complaints. Bitcoin (speed
// already shown) and Monero: no estimate, and the row only appears if the address
// is refused; test networks: nothing.
let sendFeeEstimate = 0;
async function showSendFeeEstimate(to, amount) {
  const row = document.getElementById("send-preview-estimate-row");
  const value = document.getElementById("send-preview-estimate");
  const check = ++sendFeeEstimate;
  const network = networkForCard(sendContext.card);
  const token = sendContext.coin === "usdc" ? "usdc" : usesTokenRegistry(sendContext.coin, network) ? sendContext.coin : null;
  const addressOnly = sendContext.coin === "btc" || network === "xmr_mainnet";
  row.classList.add("hidden");
  if (!network.endsWith("mainnet")) return;
  if (!addressOnly) {
    value.textContent = t("send.feeEstimateLoading");
    row.classList.remove("hidden");
  }
  try {
    const fee = await invoke("estimate_send_fee", { network, token, to, amount, profileIndex: sendContext.profileIndex });
    if (check !== sendFeeEstimate) return;
    if (!fee) {
      row.classList.add("hidden");
      return;
    }
    const price = priceForCoin(fee.coin);
    // 3 significant digits: "0.0000508 ETH", not 15 decimals.
    const native = `${Number(fee.amount).toLocaleString(chartLocale(), { maximumSignificantDigits: 3 })} ${fee.symbol}`;
    const text = price != null ? `${formatUsdApprox(Number(fee.amount) * price)} (${native})` : native;
    value.textContent = fee.up_to ? t("send.feeUpTo", { fee: text }) : text;
  } catch (e) {
    // Insufficient balance, address refused…: said here already, rather than at the
    // end.
    if (check !== sendFeeEstimate) return;
    value.textContent = friendlyError(String(e)) ?? String(e);
    row.classList.remove("hidden");
  }
}

document.getElementById("send-preview-back").addEventListener("click", () => {
  sendPreviewModal.classList.add("hidden");
});

// Step 2: it is HERE, and only here, that the real transaction goes out. The OS
// native dialog (confirm_transaction_native on the Rust side, see its comment)
// opens during this call and remains the only real protection against a
// compromised frontend. The preview above is only a pleasant summary to read
// beforehand, never a replacement.
const sendPreviewConfirmBtn = document.getElementById("send-preview-confirm");
sendPreviewConfirmBtn.addEventListener("click", withBusyButton(sendPreviewConfirmBtn, async () => {
  if (!sendContext) return;
  const errorEl = document.getElementById("send-error");
  const successEl = document.getElementById("send-success");

  const network = networkForCard(sendContext.card);
  const to = document.getElementById("send-to").value.trim();
  // The comma is accepted as input (see the filter on #send-amount further down),
  // but the Rust parsers
  // (parse_btc_to_sat/parse_eth_to_wei/parse_sol_to_lamports/parse_usdc_to_micros)
  // only accept a dot.
  const amount = document.getElementById("send-amount").value.trim().replace(",", ".");
  const password = document.getElementById("send-password").value;

  sendPreviewModal.classList.add("hidden");

  try {
    // USDC (SPL token) follows a dedicated path, separate from send_transaction: no
    // "network" to pass (mainnet only, see sol_spl.rs) and no Bitcoin-style fee, and
    // building the transaction itself is entirely different on the Rust side (two
    // instructions instead of one).
    //
    // Registry tokens: identifier and network only (contract, decimals and
    // confirmation dialog on the Rust side).
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
    rememberRecentSend(sendContext.coin, network, txResult, amount);
    refreshBalance(sendContext.card);
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("send-password").value = "";
  }
}));

// Send gone out: what will happen next (confirmation by the network, balance
// updated on its own), the identifier, and a button to the network's explorer,
// since "I sent it and nothing arrived" is wallet users' number one complaint.
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

// --- Swap ("Convert") -------------------------------------------------
//
// Goes through an external protocol not audited by this app: THORChain or Maya for
// a cross-chain swap (core/src/thorchain_rpc.rs), Jupiter within the same Solana
// wallet (core/src/jupiter_rpc.rs), CoW on the same EVM network (signed order,
// core/src/cow.rs), and LI.FI, SwapKit or MoonPay Trade between ecosystems. The
// pairs offered come from Rust (`swapPairs`, core/src/swap_routes.rs): the UI only
// offers what the swap commands accept. The same two-step principle as the send
// (quote -> preview -> native Windows confirmation).

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

// "USDC (USDC) — Base"; network left out for a crypto that only has one.
function swapAssetLabel(coin, network) {
  const asset = ASSET_BY_COIN[coin];
  if (!asset) return coin;
  const mainnets = asset.networks.filter((n) => !TEST_NETWORKS.includes(n));
  const label = asset.name === asset.symbol ? asset.name : `${asset.name} (${asset.symbol})`;
  return mainnets.length > 1 ? `${label} — ${t(`net.${network}`).split(" — ")[0]}` : label;
}

// Source cryptos: those a swap can sell that are shown in the wallet (plus the one
// on the card the window was opened from).
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

// Pair chosen in the window, as Rust declared it (`null` otherwise).
function selectedSwapPair() {
  const from = parseSwapKey(document.getElementById("swap-from-coin").value);
  const to = parseSwapKey(document.getElementById("swap-to-coin").value);
  const pair = swapPairs.find((p) => p.from_coin === from.coin && p.from_network === from.network && p.to_coin === to.coin && p.to_network === to.network);
  if (!pair) return null;
  // Providers for the step to do now (the pair itself, or its first step towards the
  // intermediate), the preferred one first; the one chosen in the menu if it is
  // among them.
  const stepTo = pair.via ?? to;
  const direct = swapPairs.find((p) => p.from_coin === from.coin && p.from_network === from.network && p.to_coin === stepTo.coin && p.to_network === stepTo.network && !p.via);
  const providers = direct?.protocols?.length ? direct.protocols : [pair.protocol];
  // The app's affiliate fee for this step, in basis points, declared by Rust for
  // each provider (0 from Bitcoin or Zcash through THORChain or Maya, see
  // `swap_routes::affiliate_fee_bps`).
  const feesBps = Object.fromEntries((direct?.protocols ?? []).map((protocol, index) => [protocol, direct.fees_bps?.[index]]));
  const chosen = document.getElementById("swap-provider").value;
  return { from, to, protocol: providers.includes(chosen) ? chosen : providers[0], providers, feesBps, via: pair.via ?? null, thenProtocol: pair.then_protocol ?? null };
}

// Each provider's default affiliate fee, in % (see core/src/cow.rs and
// core/src/thorchain_rpc.rs), when Rust does not declare one for the pair.
const SWAP_PROVIDER_FEE_PERCENT = { thorchain: 0.8, maya: 0.8, jupiter: 0.8, cow: 1, lifi: 0.8, swapkit: 0.15, moonpay: 1.1 };

function swapProviderFeePercent(pair, protocol) {
  const bps = pair?.feesBps?.[protocol];
  return typeof bps === "number" ? bps / 100 : SWAP_PROVIDER_FEE_PERCENT[protocol];
}

// Assets that THORChain and Maya are not swapping right now (`coin@network`,
// network halted: incident, maintenance), read each time the window opens
// (`swap_halts` command).
let swapHalts = {};

// Has provider `protocol` halted either of the step's two assets?
function isProviderHalted(protocol, step) {
  const halted = swapHalts[protocol] ?? [];
  return [step.from, step.to].some(({ coin, network }) => halted.includes(swapKey(coin, network)));
}

// "Provider" menu: every provider that can do the step, the recommended one first
// and chosen by default whenever the pair changes. A halted provider goes last,
// marked: chosen by default only if there is no other (its quote will then state
// the halt in plain words).
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

// --- Cardano staking (delegation to a pool) -----------------------------------
//
// The ADA stays in the wallet; everything is decided on the Rust side (pools
// offered, account state, transaction, native dialog, cancellation delay).
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

// --- Solana staking (liquid or native) -------------------------------------------
//
// Liquid: a SOL → JitoSOL swap in "Convert". Native: a stake account delegated to a
// validator; everything is decided and checked on the Rust side (validators
// offered, simulation, native dialog, cancellation delay).
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
  // The same read for the SOL card and the total value.
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
    // Reread once the transaction is confirmed (a few seconds).
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

// Estimated annual yields (Rust, `staking_aprs`): read at unlock, at most once an
// hour. Shown next to "Stake" (renderStakeChips), in the "Convert" note and in the
// "Stake your SOL" window.
let stakingAprs = null;
let stakingAprsAt = 0;
// Rate shown per card: SOL → Jito, ETH → Lido, Cardano → network average.
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
    // Announced rate (Jito, Lido); unknown: a message without a figure.
    text = apr
      ? t(pair.to.coin === "jitosol" ? "staking.noteSol" : "staking.noteEth", { apr: apr.toLocaleString(chartLocale(), { maximumFractionDigits: 1 }) })
      : t("staking.apr", { coin: COIN_SYMBOL[pair.from.coin] });
    if (!stakingAprs) loadStakingAprs();
  } else if (pair && !pair.via && lst[pair.from.coin] === pair.to.coin) {
    text = t("staking.unstake", { from: COIN_SYMBOL[pair.from.coin], to: COIN_SYMBOL[pair.to.coin] });
  }
  // The app's fee for this provider and this pair (Rust, `fees_bps`).
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

// --- Provider status ----------------------------------------------------
//
// Orange messages (degraded swap) or red ones (impossible through this provider)
// under its choice: a service that does not answer (Rust, `swap_health`), a crypto
// halted by THORChain or Maya (`swap_halts`), a swap in progress that is taking
// abnormally long (tracked here, kept from one app launch to the next).
let swapHealth = [];
let swapSlow = [];
const PENDING_SWAPS_KEY = "pgp-wallet-pending-swaps";
// "Slow": beyond 15 min, or 3 times the announced duration. Forgotten after 48 h
// (and on wallet reset or restore): beyond that, "slow right now" would mean
// nothing.
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
    // Display preference only: without storage, no slowness warning.
  }
}

function addPendingSwap(entry) {
  writePendingSwaps([...readPendingSwaps().filter((e) => e.id !== entry.id), entry]);
}

function removePendingSwap(id) {
  writePendingSwaps(readPendingSwaps().filter((e) => e.id !== id));
}

// Swaps in progress for too long: state reread from the provider; finished ones
// leave the list.
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
    // Step to do now (one provider of your choice), then the second step of a two-step
    // swap, from the intermediate.
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
    // Chosen provider first, then red before orange.
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

// Above this estimated cost (fees and gap to the market price), the preview warns
// before continuing.
const SWAP_HIGH_COST_PERCENT = 5;

// "SOL", "ETH (Arbitrum)": symbol, plus the network for a crypto that has several.
function swapShortLabel({ coin, network }) {
  const asset = ASSET_BY_COIN[coin];
  const symbol = COIN_SYMBOL[coin] ?? coin.toUpperCase();
  const mainnets = asset ? asset.networks.filter((n) => !TEST_NETWORKS.includes(n)) : [];
  return mainnets.length > 1 ? `${symbol} (${t(`net.${network}`).split(" — ")[0]})` : symbol;
}

// Step to do now: the pair itself, or its first step (towards the intermediate
// crypto) for a two-step swap, since the swap commands only accept a direct pair.
function currentSwapStep(pair) {
  return pair.via ? { from: pair.from, to: pair.via, protocol: pair.protocol } : pair;
}

// Destination address of the step: none within the same wallet; the user's own for
// the intermediate crypto (ALWAYS theirs); otherwise the one entered.
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

// Amount to swap in crypto OR in the display currency, as for a send: only the
// crypto amount goes into the quote (then into the preview and the Windows
// confirmation dialog). When the source crypto changes or the price is refreshed,
// the last field typed into wins: €20 stays €20, 0.1 stays 0.1.
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

// "Max": the maximum amount for the chosen swap, the swap's fees deducted (Rust,
// `swap_max_amount`: a token's whole balance; for the native coin, the balance
// minus this provider's maximum fees). Recomputed if the provider or the pair
// changes as long as the amount has not been edited; the swap's funds check is the
// one that counts.
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
// Amount typed by hand: it is no longer the maximum.
for (const input of [swapAmountInput, swapFiatInput]) {
  input.addEventListener("input", () => {
    swapMaxActive = false;
  });
}

// Units to the right of both fields, currency field enabled or not, amounts
// resynced.
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

// Balance of the source crypto, under the amount: reread on its network for every
// choice (the card may show another network, or a balance from 15 s ago). `{ key,
// text, amount }` once read, `text: null` while reading, `failed` after a failure.
let swapBalance = null;

async function loadSwapBalance() {
  const { coin, network } = swapFromAsset();
  swapBalance = null;
  if (!coin) {
    renderSwapBalance(); // no source crypto offered
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
  if (swapBalance?.key !== key) return; // another crypto chosen in the meantime
  swapBalance = next;
  renderSwapBalance();
}

// "Available: 0.5 ETH (≈ €1,234.56)", flagged when the amount entered exceeds it
// (just an aid: network fees are not deducted).
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
  el.textContent = t("swap.balance", { balance: `${displayAmount(swapBalance.text)} ${COIN_SYMBOL[coin] ?? ""}${fiat}` });
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
      if (swapContext?.card !== card) return; // window closed or reopened in the meantime
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

// Jupiter (Solana) and CoW (the same EVM network) stay within the same wallet: no
// destination address to enter, unlike a cross-chain swap (THORChain, Maya), where
// it is pre-filled with the profile's address on the destination network.
//
// MoonPay Trade on the same EVM network: router, purchases to the profile's
// address (checked by simulation).
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
      // CoW order: expected amount, signed guaranteed minimum, fees (1% integration fee
      // in the crypto received + CoW's network fee taken from the crypto sold), all
      // already counted.
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
      // LI.FI: bridge chosen by the aggregator, estimated duration, announced minimum
      // (guaranteed by the bridge); the transaction itself is verified at confirmation.
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
      // SwapKit: the best quote from NEAR Intents and Chainflip; the deposit is only
      // opened, then confirmed by the provider itself, at confirmation.
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
      // MoonPay Trade: on the same EVM network, router simulated at confirmation
      // (purchases to the profile's address); elsewhere, a deposit whose delivery is
      // handled by MoonPay Trade, as stated here and in the dialog.
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
      // Protocol fees (THORChain or Maya), in the crypto received (already deducted from
      // the amount received).
      document.getElementById("swap-preview-fees-label").textContent = t("swap.previewFeesOf", { name: SWAP_PROTOCOL_NAMES[step.protocol] });
      document.getElementById("swap-preview-fees").textContent = quote.total_fees != null ? `${quote.total_fees} ${COIN_SYMBOL[toCoin] ?? ""}` : "—";
      document.getElementById("swap-preview-destination").textContent = destination;
      destRow.classList.remove("hidden");
      feeRow.classList.remove("hidden");
    }

    const routeNote = document.getElementById("swap-preview-route");
    routeNote.classList.toggle("hidden", !pair.via);
    if (pair.via) routeNote.textContent = t("swap.previewRoute", swapRouteVars(pair));
    // Currency value of what is sent and received (market price) and the gap between
    // them: fees included, a benchmark for judging an external protocol's quote.
    // Hidden with no known price.
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

// The quote shown here (preview) is only an estimate to decide whether to
// continue: `swap_transaction` rereads a brand-new one on the Rust side just
// before the native confirmation, never this one (see its docs). THORChain's vault
// address changes regularly, so a quote a few seconds old may already be stale.
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
    // Two steps: the intermediate crypto's balance recorded BEFORE sending, to
    // recognize its arrival (and the amount received) afterwards.
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
      // Second step of a two-step swap: done.
      savePendingRoute(null);
    }
    // A swap can affect the balance of SEVERAL cards (source AND destination if it is
    // also managed by this wallet, e.g. SOL<->USDC): all of them are refreshed rather
    // than just the one the swap was opened from.
    refreshAllBalances();
  } catch (e) {
    showError(errorEl, String(e));
  } finally {
    document.getElementById("swap-preview-password").value = "";
  }
}));

// --- Two-step swap: tracking the intermediate crypto ---------------------
//
// After step 1, the route is kept locally (even across a restart) and the
// intermediate crypto's balance is reread every 20 s: as soon as it goes up, step
// 2 is offered with the amount received ("Convert" window pre-filled, new quote
// and new native confirmation). Nothing is locked if it is never done: the
// intermediate stays in the user's wallet.

const PENDING_ROUTE_STORAGE_KEY = "pendingSwapRoute";
const ROUTE_POLL_MS = 20000;
const ROUTE_MAX_WAIT_MS = 3 * 60 * 60 * 1000;

const sameSwapAsset = (a, b) => Boolean(a && b) && a.coin === b.coin && a.network === b.network;

// Balance of a crypto on a network, as on its card (text "0.123").
function readAssetBalance(coin, network, address) {
  if (ASSET_BY_COIN[coin]?.stock) return stockBalance(coin, address);
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
    // localStorage unavailable: tracking for this session only.
  }
  renderRouteBanner();
  scheduleRoutePoll();
}

// Wallet banner: only for the profile (and the address) that started the swap.
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

// Tracking a CoW order after sending: its state is reread every 15 s until it is
// executed, expires (30 min at most) or is cancelled; link to CoW Explorer.
const COW_ORDER_POLL_MS = 15000;
const COW_ORDER_MAX_WAIT_MS = 35 * 60 * 1000;

// Tracking a LI.FI transfer: state reread every 15 s until it arrives, fails or is
// refunded (2 h at most); link to LI.FI Scan.
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

// SwapKit swap: stage read from the provider (NEAR Intents or Chainflip) every 20
// s, until arrival, refund or failure (3 h at most).
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

// --- Certificate ------------------------------------------------------------

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

// --- Message (recipients + encryption) ---------------------------------

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
  // The current selection (boxes already ticked) is kept from one refresh to the next.
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
    // `r.label` is typed by the user: the DOM is built with textContent rather than
    // innerHTML with interpolation, so it is never interpreted as HTML (even though
    // the strict CSP would already block a script injected this way, better not to
    // rely on that alone).
    const item = document.createElement("div");
    item.className = "recipient-item";

    const labelDiv = document.createElement("div");
    labelDiv.className = "recipient-label";
    labelDiv.textContent = r.label;

    // Fingerprint shown to allow an offline identity check (see the comment on
    // RecipientDto.fingerprint on the Rust side): without it, a swap of the locally
    // stored key would go unnoticed.
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

// Viewing the full public key of a recipient already saved
// (identity/fingerprint/key ID/full ASCII-armored text), with the same layout as
// the Certificate tab for the device's own identity. All the data already comes
// from `recipientsCache` (see RecipientDto on the Rust side): no new Tauri call is
// needed to open this modal.
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

// --- External wallets --------------------------------------------------------
//
// Read-only tracking of addresses that do not belong to this wallet: the
// `get_balance` command already used for the wallet's own cards is reused directly
// (no secrets involved, just a public address).

let externalWalletsCache = [];
let externalGroupsCache = [];

// Crypto whose price values an external wallet: the network's native coin (BNB on
// BNB Chain…), or USDC for "USDC — Solana".
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
  // Other networks (Arbitrum, Zcash, XRP…): the same label as on the cards.
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
        // USDC is not a "network" in the sense get_balance means (no notion of
        // decimals/mint per asset): a dedicated command, as for the wallet's own USDC
        // card. Mainnet only (see sol_spl.rs): "usdc_solana" is stored as is in
        // external_wallets.json, but get_usdc_balance expects the real cluster identifier
        // ("sol_mainnet").
        const balance =
          wallet.network === "usdc_solana"
            ? await invoke("get_usdc_balance", { network: "sol_mainnet", address: wallet.address })
            : await invoke("get_balance", { network: wallet.network, address: wallet.address });
        const price = priceForCoin(externalWalletPriceCoin(wallet.network));
        const usd = price != null ? Number.parseFloat(balance) * price : null;
        balanceEl.textContent = displayAmount(balance);
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
  // In place: rebuilding the list reset every balance to "—" before rereading them
  // (everything flickered and moved).
  withThrottledButton(refreshExternalWalletsBtn, REFRESH_COOLDOWN_MS, refreshExternalWalletBalances, { keepLabel: true })
);

// Short network name for a saved address ("Ethereum", "Base", "XRP Ledger"); test
// networks and special cases: full label.
function contactNetworkLabel(network) {
  if (network === "btc_mainnet") return "Bitcoin";
  const label = t(`net.${network}`);
  if (network.endsWith("_mainnet") && label !== `net.${network}`) return label.split(" — ")[0];
  return externalNetworkLabel(network);
}

// "Network" menu that follows the address entered (address book, external
// wallets): only the networks where it is valid, according to Rust
// (`address_networks`, the same parsers as the send), among those `allowed`
// accepts; chosen automatically if there is only one. Empty or unrecognized
// address: the menu says so. Returns the update function.
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

// --- Add external wallet modal ---------------------------------------
//
// Tracked networks (readable balances), based on the original menu.
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

// --- New group modal ---------------------------------------------------

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

// --- Address book -------------------------------------------------------------
//
// Attach a label to an address to find it again when sending funds (see
// core/src/address_book.rs); separate from external wallets: no balance is ever
// queried here.

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

// "USDC — Solana": an old address book network, no longer offered (a Solana
// address works for SOL as well as its tokens); its entries are still read.
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

// "Choose from the address book" selector in the send modal: contacts whose address
// has the send network's format (see addressFamily), hidden if there are none and
// no other profile. Choosing an entry only fills in the address field; the selector
// then goes back to its placeholder (an action, not a persistent state).
//
// Recipients offered when sending: address book contacts, then the OTHER profiles
// of this wallet (their address for the same crypto and network). The native
// confirmation dialog names the recognized profile based on the addresses derived
// on the Rust side, never on this menu.
//
// Address format of a network: all EVM networks share one; so do the Solana
// networks ("USDC — Solana" included); every other network has its own.
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
      // A contact saved for another network with the same format (Ethereum for a send on
      // Base…): said, since an exchange may not accept that network.
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

// --- Submit with Enter -----------------------------------------------------
//
// None of these fields is in a real <form> (everything is submitted through a
// button click handled in JS), so Enter does nothing by default, unlike a classic
// HTML form. This mapping recreates that behavior for every password field in the
// app, without duplicating a `keydown` per screen.
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

// --- Startup -------------------------------------------------------------

async function startApp() {
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
}

// The module waits for the list of added networks before building the cards (see
// CUSTOM_NETWORKS): the page may already be ready when we get here, and
// DOMContentLoaded already past.
if (document.readyState === "loading") {
  window.addEventListener("DOMContentLoaded", startApp);
} else {
  startApp();
}

// --- WalletConnect (connected apps) ---------------------------------
//
// The frontend only displays and relays: a request's content is reread and
// prepared on the Rust side (`wc_prepare_request`, never from a copy held here),
// and every signature goes through a native Windows dialog. All text coming from a
// website is inserted through `textContent`, never as HTML.

const { listen } = window.__TAURI__.event;
const wcQueue = [];
let wcCurrent = null;

// EVM networks: all of the app's (identifier "eip155:<chainId>").
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

// One window at a time: proposals and requests wait their turn.
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
      // `false`: declined in the native dialog (the dApp has already been told).
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
    // A request that is invalid or dangerous by construction: already refused on the
    // Rust side.
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
      // `false`: declined in the native dialog (the dApp has already been told).
      await invoke("wc_approve_request", { requestId: request.id, password: passwordEl.value });
      passwordEl.value = "";
      wcClose("wc-request-modal");
    } catch (e) {
      // Wrong password, insufficient funds…: the request stays open.
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

// --- Ledger accounts ------------------------------------------------------------
//
// Everything that talks to the device goes through the Rust backend
// (core/src/hardware.rs), which checks every response again; the last barrier
// remains the Ledger's screen.

let ledgerAccountsCache = [];
let ledgerSendAccount = null;

restrictToAmount(document.getElementById("ledger-send-amount"));

function ledgerCoin(network) {
  if (isEvmNetwork(network)) return "evm";
  if (network.startsWith("btc")) return "btc";
  return "sol";
}

// The account's network coin (ETH, BNB, AVAX…).
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
        balanceEl.textContent = `${displayAmount(await invoke("hardware_balance", { id: account.id }))} ${ledgerUnit(account.network)}`;
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
      opt.textContent = t(key, { fee: btcFeeText(sat, account.network) });
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

// --- Charts: prices, portfolio history, external wallets -----------------
//
// Data computed on the Rust side (core/src/price_history.rs,
// core/src/portfolio.rs); drawn by app/src/charts.js. One view = a chart and its
// controls (period buttons above, summary, note), reloaded while keeping the old
// chart dimmed rather than showing an empty screen.

const CHART_RANGES = ["1d", "7d", "30d", "1y", "all"];

function chartLocale() {
  return currentLang === "en" ? "en-US" : "fr-FR";
}

// Symbol of the display currency, placed according to the language: "12 $" /
// "$12", "12 €" / "€12".
function withCurrency(number) {
  const symbol = displayCurrency === "eur" ? "€" : "$";
  return currentLang === "en" ? `${symbol}${number}` : `${number} ${symbol}`;
}

// A value ALREADY in the display currency (converted chart points).
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

// Date precision based on the duration ACTUALLY covered by the points (a portfolio
// chart may only cover a few days of a 30-day period): otherwise neighboring ticks
// showed the same date.
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

// Current value, then the change over the period (colored by direction), or since
// the start of the known data when it does not cover the whole period; "All":
// since the first point. In % for a price; in dollars (`deltaMode` "usd") for a
// portfolio's value, which deposits and withdrawals move without any relation to
// performance (a % since a first $1 deposit showed "+338,270%").
//
// Change between the first and last points shown: in % for a price, in dollars for
// a portfolio; `null` if it makes no sense (zero starting price, fewer than two
// points).
function chartChange(points, deltaMode) {
  if (points.length < 2) return null;
  const first = points[0][1];
  const last = points[points.length - 1][1];
  if (deltaMode === "usd") return last - first;
  return first > 0 ? ((last - first) / first) * 100 : null;
}

// Direction of the change: ONE rule for the summary's arrow and color AND for the
// chart's color (green going up, red going down). A change that displays as 0
// (under 0.005% or $0.005): neither up nor down.
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
      // Key kept: relabeled when the language changes ("1 an" → "1y").
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

// History still being read on the Rust side (`loading`): another call shortly
// after, without dimming the chart, which fills in as it goes. Changing the period
// or closing the window (token changed) stops the follow-ups.
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
    if (token !== view.token) return; // a more recent request wins
    // In euros: each point converted at the rate of its date.
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

// Value of a set of addresses (wallet or external wallets).
async function loadHoldingsHistory(holdings, range) {
  if (holdings.length === 0) return { points: [] };
  const result = await invoke("get_portfolio_history", { holdings, range });
  const notes = [];
  // An unreadable address (service overloaded or down): chart without it, said first
  // (see core/src/portfolio.rs).
  if (result.unavailable?.length) notes.push(t("charts.unavailable", { list: result.unavailable.join(", ") }));
  if (result.loading) {
    const count = result.transactions_read;
    notes.push(count ? t("charts.loadingHistory", { count: count.toLocaleString(chartLocale()) }) : t("charts.loadingHistoryStart"));
  }
  else if (result.since) notes.push(t("charts.since", { date: new Date(result.since * 1000).toLocaleDateString(chartLocale()) }));
  if (result.approximate && !result.loading) notes.push(t("charts.approximate"));
  // Network with no usable history (BNB Chain without a NodeReal key): current balance
  // counted over the whole period (see core/src/portfolio.rs).
  if (result.constant?.length) notes.push(t("charts.constantBalance", { list: result.constant.join(", ") }));
  return { points: result.points, since: result.since, note: notes.join(" "), loading: result.loading };
}

// Charts served by Kraken (not on Binance, see core/src/price_history.rs).
const KRAKEN_CHARTS = ["VVV"];

async function loadPriceChart(symbol, range) {
  const stock = ASSETS.some((asset) => asset.stock && asset.chart === symbol);
  const note = t(stock ? "charts.priceSourceJupiter" : KRAKEN_CHARTS.includes(symbol) ? "charts.priceSourceKraken" : "charts.priceSource");
  return { points: await invoke("get_price_chart", { symbol, range }), note };
}

// --- Full-size chart -------------------------------------------------------------

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

// Table view: the same values without hovering (accessibility).
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
  chartModalView.token = (chartModalView.token || 0) + 1; // ignore a late response
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

// --- Portfolio history (profile shown, mainnets) ----------------

// Test networks: worthless funds, left out of the chart.
const TEST_NETWORKS = ["evm_sepolia", "btc_testnet", "sol_devnet"];

// Each crypto shown, on each of its mainnets (ETH on Ethereum, Arbitrum and Base;
// USDC on Solana and its three EVM networks…): the value of each holding is
// rebuilt on the Rust side (core/src/portfolio.rs).
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

// --- External wallets history (all of them, or one group)
// -------------------------

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
