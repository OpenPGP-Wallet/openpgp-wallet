//! Tokens the app can display and send: ERC-20 on EVM networks, SPL (the classic
//! SPL Token program) on Solana, TRC-20 on Tron, and xStocks tokenized stocks (the
//! Token-2022 program on Solana, see `TokenKind::Spl2022`).
//!
//! The registry is FIXED HERE, on the Rust side: the interface only refers to a
//! token by its ID and a network, never by a contract address, so a compromised
//! frontend cannot get a fake token sent under a real one's name. Each contract was
//! taken from CoinGecko (token page, contracts per network) and then checked on
//! chain: the contract's symbol and decimals (EVM), the SPL Token program and the
//! mint's decimals (Solana); see the ignored test
//! `token_contracts_match_the_real_networks`. Ruled out during that check: Global
//! Dollar on Solana (Token-2022 program, not handled), RENDER on Ethereum (the old
//! "RNDR" contract; the token migrated to Solana).

use anyhow::{anyhow, bail, ensure, Context, Result};

/// Where a token lives on a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// ERC-20 contract (lower-case address).
    Erc20 { contract: &'static str },
    /// SPL Token mint (base58).
    Spl { mint: &'static str },
    /// TRC-20 contract on Tron (T... address).
    Trc20 { contract: &'static str },
    /// Token-2022 program mint with a display multiplier ("Scaled UI Amount"
    /// extension): the xStocks tokenized stocks. The displayed balance is the raw
    /// balance times the current multiplier (reinvested dividends, stock splits); the
    /// app counts and displays in DISPLAYED units and only converts to raw units when
    /// signing (`api::send_registered_spl`, Jupiter swaps). A separate variant: any
    /// code written for the classic program (LI.FI, MoonPay...) ignores these tokens
    /// until it has been adapted.
    Spl2022 { mint: &'static str },
}

/// Metadata update authority of every xStock on Solana (read back from each mint on
/// 2026-10-09, see `xstocks_match_the_real_mints`): together with the metadata
/// address at Backed, this is what tells a real xStock from a copy with the same
/// name.
pub const XSTOCKS_UPDATE_AUTHORITY: &str = "5aMNNLQJwAEeoemTEMkv5NVjqKwvvefRYCQ5Z67HFvEq";

/// Size of an xStocks token account (immutableOwner, pausableAccount and
/// transferHookAccount extensions, required by the mint): 179 bytes, read from real
/// accounts on 2026-10-09. The basis of the rent paid to create a recipient's
/// account.
pub const XSTOCK_ACCOUNT_SIZE: u64 = 179;

#[derive(Debug)]
pub struct Deployment {
    /// Network identifier ("evm_mainnet", "arbitrum_mainnet", "sol_mainnet"...).
    pub network: &'static str,
    pub kind: TokenKind,
    pub decimals: u8,
}

#[derive(Debug)]
pub struct Token {
    /// Identifier used by the interface ("usdt", "link"...).
    pub id: &'static str,
    pub symbol: &'static str,
    pub name: &'static str,
    pub deployments: &'static [Deployment],
}

const fn erc20(network: &'static str, contract: &'static str, decimals: u8) -> Deployment {
    Deployment { network, kind: TokenKind::Erc20 { contract }, decimals }
}

const fn spl(mint: &'static str, decimals: u8) -> Deployment {
    Deployment { network: "sol_mainnet", kind: TokenKind::Spl { mint }, decimals }
}

const fn trc20(contract: &'static str, decimals: u8) -> Deployment {
    Deployment { network: "tron_mainnet", kind: TokenKind::Trc20 { contract }, decimals }
}

/// xStocks tokenized stock on Solana: Token-2022 mint, 8 decimals.
const fn xstock(mint: &'static str) -> Deployment {
    Deployment { network: "sol_mainnet", kind: TokenKind::Spl2022 { mint }, decimals: 8 }
}

pub const TOKENS: &[Token] = &[
    Token {
        id: "usdt",
        symbol: "USDT",
        name: "Tether",
        // USDT on Tron: Tether's official contract (CoinGecko, Tronscan).
        deployments: &[
            erc20("evm_mainnet", "0xdac17f958d2ee523a2206206994597c13d831ec7", 6),
            spl("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", 6),
            trc20("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 6),
        ],
    },
    Token {
        id: "usdc",
        symbol: "USDC",
        name: "USDC",
        deployments: &[
            spl("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6),
            erc20("evm_mainnet", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
            erc20("base_mainnet", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),
            erc20("arbitrum_mainnet", "0xaf88d065e77c8cc2239327c5edb3a432268e5831", 6),
        ],
    },
    Token {
        id: "link",
        symbol: "LINK",
        name: "Chainlink",
        deployments: &[
            erc20("evm_mainnet", "0x514910771af9ca656af840dff83e8264ecf986ca", 18),
            erc20("arbitrum_mainnet", "0xf97f4df75117a78c1a5a0dbb814af92458539fb4", 18),
            erc20("base_mainnet", "0x88fb150bdc53a65fe94dea0c9ba0a6daf8c6e196", 18),
        ],
    },
    Token { id: "dai", symbol: "DAI", name: "Dai", deployments: &[erc20("evm_mainnet", "0x6b175474e89094c44da98b954eedeac495271d0f", 18)] },
    Token { id: "usde", symbol: "USDe", name: "Ethena USDe", deployments: &[erc20("evm_mainnet", "0x4c9edd5852cd905f086c759e8383e09bff1e68b3", 18)] },
    Token {
        id: "uni",
        symbol: "UNI",
        name: "Uniswap",
        deployments: &[
            erc20("evm_mainnet", "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", 18),
            erc20("arbitrum_mainnet", "0xfa7f8980b0f1e64a2062791cc3b0871572f1f7f0", 18),
        ],
    },
    Token {
        id: "usdg",
        symbol: "USDG",
        name: "Global Dollar",
        deployments: &[
            erc20("evm_mainnet", "0xe343167631d89b6ffc58b88d6b7fb0228795491d", 6),
            erc20("arbitrum_mainnet", "0x004b506865409877c9fa29bfb1eba929984b9bbc", 6),
        ],
    },
    Token { id: "xaut", symbol: "XAUt", name: "Tether Gold", deployments: &[erc20("evm_mainnet", "0x68749665ff8d2d112fa859aa293f07a622782f38", 6)] },
    Token { id: "ondo", symbol: "ONDO", name: "Ondo", deployments: &[erc20("evm_mainnet", "0xfaba6f8e4a5e8ab82f62fe7c39859fa577269be3", 18)] },
    // Quant: contract, symbol and 18 decimals read from Ethereum (2026-10-07).
    Token { id: "qnt", symbol: "QNT", name: "Quant", deployments: &[erc20("evm_mainnet", "0x4a220e6096b25eadb88358cb44068a3248254675", 18)] },
    Token { id: "fet", symbol: "FET", name: "Artificial Superintelligence Alliance", deployments: &[erc20("evm_mainnet", "0xaea46a60368a7bd060eec7df8cba43b7ef41ad85", 18)] },
    Token {
        id: "eurc",
        symbol: "EURC",
        name: "EURC",
        deployments: &[
            erc20("evm_mainnet", "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c", 6),
            erc20("base_mainnet", "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42", 6),
            spl("HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr", 6),
        ],
    },
    Token { id: "gno", symbol: "GNO", name: "Gnosis", deployments: &[erc20("evm_mainnet", "0x6810e776880c02933d47db1b9fc05908e5386b96", 18)] },
    Token {
        id: "arb",
        symbol: "ARB",
        name: "Arbitrum",
        deployments: &[
            erc20("arbitrum_mainnet", "0x912ce59144191c1204e64559fe8253a0e49e6548", 18),
            erc20("evm_mainnet", "0xb50721bcf8d664c30412cfbc6cf7a15145234ad1", 18),
        ],
    },
    Token { id: "aster", symbol: "ASTER", name: "Aster", deployments: &[erc20("bsc_mainnet", "0x000ae314e2a2172a039b26378814c252734f556a", 18)] },
    Token { id: "vvv", symbol: "VVV", name: "Venice Token", deployments: &[erc20("base_mainnet", "0xacfe6019ed1a7dc6f7b508c02d1b04ec88cc21bf", 18)] },
    Token { id: "render", symbol: "RENDER", name: "Render", deployments: &[spl("rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof", 8)] },
    // Liquid staking ("Stake" on the SOL and ETH cards, see staking.rs): Jito's
    // JitoSOL (mint read on chain: SPL Token program, 9 decimals) and Lido's stETH (18
    // decimals; the balance grows every day with the rewards).
    Token { id: "jitosol", symbol: "JitoSOL", name: "Jito Staked SOL", deployments: &[spl("J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", 9)] },
    Token { id: "steth", symbol: "stETH", name: "Lido Staked ETH", deployments: &[erc20("evm_mainnet", "0xae7ab96520de3a18e5e111b5eaab095312d7fe84", 18)] },
    // xStocks tokenized stocks (Backed Assets) on Solana: Jupiter's verified list
    // ("verified" and "xstocks" tags), then each mint read from the network on
    // 2026-10-09: Token-2022 program, 8 decimals, name and symbol from the metadata,
    // `XSTOCKS_UPDATE_AUTHORITY` authority, metadata hosted at Backed (see
    // `xstocks_match_the_real_mints`). Left out: preferred shares (STRCx) and thinly
    // traded securities.
    Token { id: "tslax", symbol: "TSLAx", name: "Tesla xStock", deployments: &[xstock("XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB")] },
    Token { id: "nvdax", symbol: "NVDAx", name: "NVIDIA xStock", deployments: &[xstock("Xsc9qvGR1efVDFGLrVsmkzv3qi45LTBjeUKSPmx9qEh")] },
    Token { id: "aaplx", symbol: "AAPLx", name: "Apple xStock", deployments: &[xstock("XsbEhLAtcf6HdfpFZ5xEMdqW8nfAvcsP5bdudRLJzJp")] },
    Token { id: "msftx", symbol: "MSFTx", name: "Microsoft xStock", deployments: &[xstock("XspzcW1PRtgf6Wj92HCiZdjzKCyFekVD8P5Ueh3dRMX")] },
    Token { id: "googlx", symbol: "GOOGLx", name: "Alphabet xStock", deployments: &[xstock("XsCPL9dNWBMvFtTmwcCA5v3xWPSMEBCszbQdiLLq6aN")] },
    Token { id: "amznx", symbol: "AMZNx", name: "Amazon.com xStock", deployments: &[xstock("Xs3eBt7uRfJX8QUs4suhyU8p2M6DoUDrJyWBa8LLZsg")] },
    Token { id: "metax", symbol: "METAx", name: "Meta xStock", deployments: &[xstock("Xsa62P5mvPszXL1krVUnU5ar38bBSVcWAB6fmPCo5Zu")] },
    Token { id: "spyx", symbol: "SPYx", name: "SP500 xStock", deployments: &[xstock("XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W")] },
    Token { id: "qqqx", symbol: "QQQx", name: "Nasdaq xStock", deployments: &[xstock("Xs8S1uUs1zvS2p7iwtsG3b6fkhpvmwz4GYU3gWAmWHZ")] },
    Token { id: "gldx", symbol: "GLDx", name: "Gold xStock", deployments: &[xstock("Xsv9hRk1z5ystj9MhnA7Lq4vjSsLwzL2nxrwmwtD3re")] },
    Token { id: "coinx", symbol: "COINx", name: "Coinbase xStock", deployments: &[xstock("Xs7ZdzSHLU9ftNJsii5fCeJhoRWSC32SQGzGQtePxNu")] },
    Token { id: "mstrx", symbol: "MSTRx", name: "MicroStrategy xStock", deployments: &[xstock("XsP7xzNPvEHS1m6qfanPUGjNmdnmsLKEoNAnHjdxxyZ")] },
    Token { id: "crclx", symbol: "CRCLx", name: "Circle xStock", deployments: &[xstock("XsueG8BtpquVJX9LVLLEGuViXUungE6WmK5YZ3p3bd1")] },
    Token { id: "hoodx", symbol: "HOODx", name: "Robinhood xStock", deployments: &[xstock("XsvNBAYkrDRNhA7wPHQfX3ZUXZyZLdnCQDfHZ56bzpg")] },
    Token { id: "pltrx", symbol: "PLTRx", name: "Palantir xStock", deployments: &[xstock("XsoBhf2ufR8fTyNSjqfU71DYGaE6Z3SUGAidpzriAA4")] },
    Token { id: "mcdx", symbol: "MCDx", name: "McDonald's xStock", deployments: &[xstock("XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2")] },
    Token { id: "gmex", symbol: "GMEx", name: "Gamestop xStock", deployments: &[xstock("Xsf9mBktVB9BSU5kf4nHxPq5hCBJ2j2ui3ecFGxPRGc")] },
    Token { id: "brkbx", symbol: "BRK.Bx", name: "Berkshire Hathaway xStock", deployments: &[xstock("Xs6B6zawENwAbWVi7w92rjazLuAr5Az59qgWKcNb45x")] },
    Token { id: "spcxx", symbol: "SPCXx", name: "SpaceX xStock", deployments: &[xstock("Xs3oZwbHvqis4NYcf4YKWmEia2eC84wSiVrcYcTqpH8")] },
];

/// Is this registry token handled by the Token-2022 program (xStocks)?
pub fn is_spl2022(id: &str) -> bool {
    TOKENS.iter().any(|t| t.id == id && t.deployments.iter().any(|d| matches!(d.kind, TokenKind::Spl2022 { .. })))
}

/// Token `id` on `network`, if it is in the registry.
pub fn find(id: &str, network: &str) -> Option<(&'static Token, &'static Deployment)> {
    let token = TOKENS.iter().find(|t| t.id == id)?;
    let deployment = token.deployments.iter().find(|d| d.network == network)?;
    Some((token, deployment))
}

/// Every known ERC-20 contract (all tokens, all networks): tokens transferred TO a
/// token contract are lost forever.
pub fn is_known_contract(address: &str) -> bool {
    let address = address.trim().to_ascii_lowercase();
    TOKENS
        .iter()
        .flat_map(|t| t.deployments)
        .any(|d| matches!(d.kind, TokenKind::Erc20 { contract } if contract == address))
}

/// Decimal amount ("12.5") → whole token units (`decimals` decimals), exactly:
/// refuses more decimals than the token has, a zero amount, a sign or any other
/// character.
pub fn parse_amount(input: &str, decimals: u8) -> Result<u128> {
    let input = input.trim();
    ensure!(!input.is_empty() && input.bytes().all(|b| b.is_ascii_digit() || b == b'.'), "montant invalide");
    let (whole, fraction) = input.split_once('.').unwrap_or((input, ""));
    ensure!(!fraction.contains('.'), "montant invalide");
    ensure!(fraction.len() <= decimals as usize, "trop de décimales ({decimals} au plus pour ce jeton)");
    let scale = 10u128.checked_pow(u32::from(decimals)).context("décimales du jeton invalides")?;
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| anyhow!("montant invalide"))? };
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<width$}", width = decimals as usize).parse().map_err(|_| anyhow!("montant invalide"))?
    };
    let units = whole.checked_mul(scale).and_then(|w| w.checked_add(fraction)).context("montant trop grand")?;
    if units == 0 {
        bail!("le montant doit être supérieur à zéro");
    }
    Ok(units)
}

/// Units → full decimal text, without trailing zeros ("12.5").
pub fn format_amount(units: u128, decimals: u8) -> String {
    let scale = 10u128.pow(u32::from(decimals));
    let (whole, fraction) = (units / scale, units % scale);
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:0width$}", width = decimals as usize);
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// Balance to display: at most `shown` decimals, TRUNCATED (never rounded up: the
/// displayed balance never exceeds the real balance).
pub fn format_balance(units: u128, decimals: u8, shown: u8) -> String {
    let shown = shown.min(decimals);
    let cut = 10u128.pow(u32::from(decimals - shown));
    let truncated = units / cut;
    let scale = 10u128.pow(u32::from(shown));
    if shown == 0 {
        return truncated.to_string();
    }
    format!("{}.{:0width$}", truncated / scale, truncated % scale, width = shown as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Consistent registry: unique IDs, known networks, lower-case contracts in the
    /// right format, decodable SPL mints, never the same network twice for one token.
    #[test]
    fn registry_is_consistent() {
        for (i, token) in TOKENS.iter().enumerate() {
            assert!(TOKENS[i + 1..].iter().all(|t| t.id != token.id), "{} en double", token.id);
            assert!(!token.deployments.is_empty(), "{}", token.id);
            for (j, d) in token.deployments.iter().enumerate() {
                assert!(token.deployments[j + 1..].iter().all(|e| e.network != d.network), "{} : réseau en double", token.id);
                match d.kind {
                    TokenKind::Erc20 { contract } => {
                        assert!(crate::wallet_flow::evm_network(d.network).is_some_and(|n| n.mainnet), "{} : réseau {}", token.id, d.network);
                        assert!(contract.len() == 42 && contract.starts_with("0x") && contract[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{} : {contract}", token.id);
                    }
                    TokenKind::Spl { mint } => {
                        assert_eq!(d.network, "sol_mainnet", "{}", token.id);
                        assert_eq!(bs58::decode(mint).into_vec().map(|b| b.len()).ok(), Some(32), "{} : {mint}", token.id);
                    }
                    TokenKind::Spl2022 { mint } => {
                        assert_eq!((d.network, d.decimals), ("sol_mainnet", 8), "{}", token.id);
                        assert_eq!(bs58::decode(mint).into_vec().map(|b| b.len()).ok(), Some(32), "{} : {mint}", token.id);
                        assert!(mint.starts_with("Xs") && token.name.ends_with(" xStock") && token.symbol.ends_with('x'), "{}", token.id);
                    }
                    TokenKind::Trc20 { contract } => {
                        assert_eq!(d.network, "tron_mainnet", "{}", token.id);
                        assert!(crate::tron::parse_address(contract).is_ok(), "{} : {contract}", token.id);
                    }
                }
                assert!(d.decimals <= 18, "{}", token.id);
            }
        }
        assert_eq!(find("usdt", "evm_mainnet").map(|(t, d)| (t.symbol, d.decimals)), Some(("USDT", 6)));
        assert!(find("usdt", "bsc_mainnet").is_none(), "réseau non enregistré : refusé");
        assert!(find("inconnu", "evm_mainnet").is_none());
        assert!(is_known_contract(" 0xDAC17F958D2EE523A2206206994597C13D831EC7 "));
        assert!(!is_known_contract("0x000000000000000000000000000000000000dEaD"));
    }

    /// Each xStock in the registry, read from the network (read-only): Token-2022
    /// program mint, 8 decimals, name and symbol from the on-chain metadata, Backed's
    /// update authority, metadata hosted at Backed, display multiplier present, no
    /// transfer fee and no active transfer hook.
    #[test]
    #[ignore]
    fn xstocks_match_the_real_mints() {
        let rpc = crate::sol_rpc::SolRpc::new(crate::wallet_flow::SOLANA_MAINNET.rpc);
        let mut checked = 0;
        for token in TOKENS {
            for d in token.deployments {
                let TokenKind::Spl2022 { mint } = d.kind else { continue };
                let result = (0..5)
                    .find_map(|attempt| {
                        std::thread::sleep(std::time::Duration::from_millis(1200 * attempt));
                        rpc.call("getAccountInfo", serde_json::json!([mint, {"encoding": "jsonParsed"}])).ok()
                    })
                    .unwrap_or_else(|| panic!("{} : nœud injoignable", token.id));
                let value = &result["value"];
                assert_eq!(value["owner"], "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "{}", token.id);
                let info = &value["data"]["parsed"]["info"];
                assert_eq!(info["decimals"].as_u64(), Some(u64::from(d.decimals)), "{}", token.id);
                let extension = |name: &str| info["extensions"].as_array().and_then(|list| list.iter().find(|e| e["extension"] == name)).map(|e| e["state"].clone());
                let metadata = extension("tokenMetadata").unwrap_or_else(|| panic!("{} : métadonnées absentes", token.id));
                assert_eq!((metadata["name"].as_str(), metadata["symbol"].as_str()), (Some(token.name), Some(token.symbol)), "{}", token.id);
                assert_eq!(metadata["updateAuthority"], XSTOCKS_UPDATE_AUTHORITY, "{}", token.id);
                assert_eq!(metadata["uri"].as_str(), Some(format!("https://xstocks-metadata.backed.fi/tokens/Solana/{}/metadata.json", token.symbol).as_str()), "{}", token.id);
                assert!(extension("scaledUiAmountConfig").is_some(), "{} : coefficient d'affichage absent", token.id);
                assert!(extension("transferFeeConfig").is_none(), "{} : frais de transfert", token.id);
                assert!(extension("transferHook").is_none_or(|hook| hook["programId"].is_null()), "{} : crochet de transfert actif", token.id);
                checked += 1;
            }
        }
        assert_eq!(checked, TOKENS.iter().filter(|t| is_spl2022(t.id)).count());
        assert!(checked >= 19);
    }

    #[test]
    fn amounts_are_parsed_and_formatted_exactly() {
        assert_eq!(parse_amount("12.5", 6).unwrap(), 12_500_000);
        assert_eq!(parse_amount("0.000001", 6).unwrap(), 1);
        assert_eq!(parse_amount(".5", 18).unwrap(), 500_000_000_000_000_000);
        assert_eq!(parse_amount("1", 0).unwrap(), 1);
        for bad in ["", "0", "0.0", "-1", "+1", "1e5", "1.2.3", "1,5", " ", "abc"] {
            assert!(parse_amount(bad, 6).is_err(), "{bad:?}");
        }
        assert!(parse_amount("0.0000001", 6).is_err(), "trop de décimales");
        assert!(parse_amount("999999999999999999999999999999999999999", 18).is_err(), "dépassement");
        assert_eq!(format_amount(12_500_000, 6), "12.5");
        assert_eq!(format_amount(3_000_000, 6), "3");
        assert_eq!(format_balance(1_999_999_999_999_999_999, 18, 6), "1.999999", "tronqué, jamais arrondi");
        assert_eq!(format_balance(5, 6, 6), "0.000005");
        assert_eq!(format_balance(123_456_789, 8, 6), "1.234567");
        assert_eq!(format_balance(42, 0, 6), "42");
    }
}
