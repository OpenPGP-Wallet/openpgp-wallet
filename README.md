# OpenPGP Wallet

A non-custodial, multi-network crypto wallet for the desktop with **no seed phrase to write down**. The master key
is protected by OpenPGP and a 2-of-3 Shamir backup kit instead of 12 or 24 words on a piece of paper.

> [!WARNING]
> **Pre-audit software.** OpenPGP Wallet works end to end and is used with small real amounts, but it has not
> been reviewed by an independent auditor and the Windows binaries are not code-signed yet. Do not use it with
> funds you cannot afford to lose. See [SECURITY.md](SECURITY.md) and the
> [threat model](docs/THREAT_MODEL.md).

Website and video guides: <https://khadevs.github.io/openpgp-wallet-site/>

## Why no seed phrase?

A seed phrase is a single point of failure. Whoever sees the words owns the funds, and whoever loses them loses
the funds. The whole security of a classic wallet rests on a piece of paper that the user has to write down, hide
and never photograph, and the weakest link is almost always the human, not the cryptography.

OpenPGP Wallet keeps one master secret, and protects it in two independent ways:

```
Master entropy (256 bits, generated once by the OS CSPRNG)
│
├── Local vault on this device (one password)
│   └── Everyday use: balances, addresses, signing
│
└── 2-of-3 Shamir backup kit (generated once, independent of the vault)
    ├── Share A, PGP-encrypted with its own passphrase
    ├── Share B, PGP-encrypted with its own passphrase
    └── Share C, PGP-encrypted with its own passphrase
        └── any 2 shares → restore on a new device
```

A single share is useless on its own, so the three shares can live in three different places (USB drives, a
safe, a trusted person) without any one of them being a risk. The app can write each share, complete with its
key and passphrase, to a USB drive and check that it decrypts before saying it is done.

## Features

- **18 networks from one master key**: Bitcoin, Ethereum and its L2s (Arbitrum, Base), BNB Chain, Avalanche,
  Polygon, Solana, Zcash (transparent and shielded), Monero, Dogecoin, Tron, XRP Ledger, Stellar, NEAR, Cardano,
  Stacks and Bittensor, plus custom EVM networks added by RPC.
- **Tokens**: USDC, USDT and other ERC-20, SPL and TRC-20 tokens from a built-in registry, and xStocks tokenized
  shares on Solana.
- **Swaps** through THORChain, Maya, Jupiter, CoW Protocol, LI.FI, SwapKit (NEAR Intents, Chainflip) and MoonPay
  Trade. Quotes, memos and third-party transactions are checked or simulated before anything is signed.
- **Staking**: native Solana staking, Cardano delegation, liquid staking (JitoSOL, stETH).
- **Hardware wallets**: Ledger and Trezor, with on-device review.
- **WalletConnect v2**, implemented in Rust (no JavaScript SDK in the webview).
- **Windows Hello** as an optional second way to unlock, sealed in the TPM. The password keeps working.
- **Safer sends**: native OS confirmation dialog, a 5-second cancellation delay, warnings for new, unused and
  lookalike addresses, and a balance check before you confirm.
- **Encrypted messaging** with OpenPGP, multiple profiles, an address book, watch-only external wallets,
  portfolio charts, French and English interface.

## Security model in short

- The web interface is treated as **untrusted**. It never receives the seed, a private key or a backup share:
  the backup kit is written and read back in Rust, and the interface only shows the share passphrases the user
  has to note. Everything that is signed is rebuilt and checked in Rust. What the user types in the interface
  (device password, share passphrases at restore) goes through it on its way to Rust.
- Every send goes through a **native OS dialog** that shows exactly what will be signed. A compromised frontend
  can neither fake it nor skip it. Other sensitive actions (reset, new backup kit, restore, added network…) are
  confirmed in a separate secure window that the interface cannot script.
- The password rule (12 characters minimum, not guessable) is enforced in the core, not only in the interface.
- The seed is never cached: it is decrypted for each sensitive operation, kept in locked memory and wiped
  (`zeroize`) right after.
- Unlock attempts are rate-limited, the device key lives in the Windows Credential Manager, and the password is
  stretched with the maximum OpenPGP S2K cost.

The full picture, including what is **not** protected, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Repository layout

```
core/            Rust crate `openpgp-wallet-core`: Shamir, OpenPGP, key derivation, transaction building and
                 signing for every network, swap and staking logic. No UI code.
  examples/      Small command-line demos (Shamir, PGP, wallet flows, hardware spikes).
app/             Tauri v2 desktop application.
  src-tauri/     Rust backend: exposes `core` to the frontend through typed Tauri commands.
  src/           Frontend in plain HTML, CSS and JavaScript (no framework, no runtime JS dependency).
docs/            Threat model and architecture notes.
```

`core/` knows nothing about Tauri or any interface on purpose, so the same signing code can be reused by a
future mobile app. More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Building from source

Windows 10 or 11 is the only platform tested so far. You need:

- [Rust](https://rustup.rs/) (stable),
- [Node.js](https://nodejs.org/) 18 or later,
- the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform (on Windows: the Microsoft
  C++ Build Tools and WebView2).

```bash
cd app
npm install
npm run tauri dev      # development build with hot reload
npm run tauri build    # release build and installers
```

### Optional partner API keys

A few providers need an API key: SwapKit, MoonPay Trade, NodeReal (BNB Chain history), Taostats (Bittensor
history), Blockscout and Alchemy (Arbitrum, Base and Polygon history). The keys are read **at build time** from
`partner-keys.env` at the repository root, which git ignores. Copy
[`partner-keys.env.example`](partner-keys.env.example) and fill in the ones you have. Without a key, the matching
provider is simply not offered and the app links to the block explorer instead.

### Tests

```bash
cargo test --workspace
```

Tests that talk to real networks are marked `#[ignore]` and are run on demand, for example
`cargo test -p openpgp-wallet-core -- --ignored real_near --nocapture`. Each one documents its command next to
its definition.

### Command-line demos

```bash
cargo run -p openpgp-wallet-core --example shamir_demo     # Shamir split and recovery
cargo run -p openpgp-wallet-core --example pgp_demo        # PGP encryption and decryption
cargo run -p openpgp-wallet-core --example shamir_pgp_cli  # the full Shamir + PGP flow
```

## Status and roadmap

The current release is **2.15.0** (see [CHANGELOG.md](CHANGELOG.md)). Before the wallet can be recommended for
real funds, it still needs Authenticode code signing, an independent security audit and reproducible builds.

Next on the list is user-friendly threshold signing with FROST for shielded Zcash (2-of-3 between a computer, a
phone and a backup, coordinated by QR codes with no server). The design is described in the
[FROST white paper](https://khadevs.github.io/openpgp-wallet-site/frost-white-paper.html).

## Contributing

Bug reports, reviews and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first, and
report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Khadim
