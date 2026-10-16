# Architecture

This document describes how OpenPGP Wallet is put together: the components, where secrets live, how a
transaction travels from a click to the network, and where to find the code for each network. For what the
design protects against, read the [threat model](THREAT_MODEL.md).

## Components

```
┌───────────────────────────────┐   Tauri commands    ┌──────────────────────────────┐
│ Frontend (app/src)            │ ──────────────────► │ Backend (app/src-tauri)      │
│ HTML / CSS / JS, untrusted    │ ◄────────────────── │ commands, native dialogs,    │
│ public data only              │  addresses, amounts │ confirmation windows, caches │
└───────────────────────────────┘                     └──────────────┬───────────────┘
                                                                     │ Rust calls
                                                      ┌──────────────▼───────────────┐
                                                      │ Core (core/, no UI code)     │
                                                      │ vault, Shamir, OpenPGP,      │
                                                      │ derivation, signing, swaps   │
                                                      └──────────────┬───────────────┘
                                                                     │ HTTPS / gRPC / WSS
                                                         nodes, indexers, swap providers,
                                                         WalletConnect relay, USB, TPM
```

- **Frontend** (`app/src`): plain HTML, CSS and JavaScript, no framework and no runtime dependency. It is treated
  as untrusted. A strict CSP (`connect-src 'self'`) stops it from reaching the network directly. It receives public
  data (addresses, balances, transaction IDs) and, once, the passphrases of a new backup kit, which the user has
  to note; never the seed, a private key or a backup share. Backup files are saved and opened through native
  dialogs on the Rust side, which writes and reads their content.
- **Backend** (`app/src-tauri/src/lib.rs`): the Tauri commands. It validates every input coming from the
  frontend, opens the native OS confirmation dialogs and the secure confirmation window, enforces the
  cancellation delay before signing, and translates errors (French/English).
- **Core** (`core/`, crate `openpgp-wallet-core`): everything else. It knows nothing about Tauri, so the same code
  can serve a future mobile app. `core/src/api.rs` is the entry point the backend uses.

## Keys and storage

All wallet data lives in the app's data folder (on Windows, under `%APPDATA%`). The main files are:

| File | Content |
|---|---|
| `device_vault.asc` | The master entropy, PGP-encrypted for the device identity (and the biometric identity, if enabled) |
| `device_pubkey.asc` | The device's public key |
| Windows Credential Manager entry | The device's PGP private key, itself encrypted with the password (`device_privkey.asc` only as a fallback) |
| `device_biometric_*` | The optional Windows Hello identity; its passphrase is a random secret sealed in the TPM |
| `profiles.json` | Profile labels and derivation indexes (no secret) |
| `unlock_attempts*.json` | Failure counters for the unlock rate limit |
| `zcash_shielded.sqlite`, `monero_wallet.json` | Local state of the private cryptos (viewing keys only, never spending keys) |
| `address_book.json`, `recipients.json`, `external_wallets.json`, `sent_recipients.json`, `hardware_accounts.json`, `custom_networks.json`, `walletconnect.json` | Convenience data, public information only |

There is one master secret: 32 bytes of entropy from the OS CSPRNG (`core/src/entropy.rs`). Every key for every
network and profile is derived from it on demand (`core/src/derivation.rs`, plus the network modules for schemes
such as Cardano, Monero and Bittensor) and wiped right after use.

The **backup kit** is a 2-of-3 Shamir split of the same entropy (`core/src/shamir.rs`), each share encrypted with
its own throwaway PGP identity and random passphrase. Shares carry an encrypted kit mark, so two shares from
different kits are refused instead of silently rebuilding a wrong secret. `core/src/usb_backup.rs` writes shares
to USB drives and reads them back.

`core/src/memory_guard.rs` locks sensitive buffers in memory (`VirtualLock`/`mlock`), and `zeroize` wipes them.
`core/src/seed_state.rs` stops background syncs cleanly when the wallet is reset or restored.

## The life of a send

1. **Preview.** The frontend shows a preview built from data the backend prepared: recipient warnings, estimated
   fees, available balance. Nothing is signed and no secret is involved.
2. **Preparation.** The backend validates the network, the address and the amount, rebuilds their canonical
   form, checks the balance, and prepares exactly what will be signed (fees, UTXOs, nonce, memo…). For swaps,
   it fetches a fresh quote and verifies it (memo, PSBT, simulation of the effects).
3. **Native confirmation.** An OS dialog, which the webview cannot fake or skip, shows the network, the source
   profile, the recipient, the amount and the fees.
4. **Cancellation delay.** Five seconds with a countdown in the interface, during which Rust waits; the user
   can send now or cancel. A guard against the user's own mistakes: the countdown lives in the interface, so
   the native dialog is the barrier against a compromised one.
5. **Signing.** Only now is the seed decrypted with the password (rate-limited), the key derived, the
   transaction signed, and the seed wiped.
6. **Broadcast.** The transaction is sent. If the result is ambiguous (timeout, cut connection), the app reports
   "may have gone out, check the history" rather than "failed", so the user is never led to pay twice
   (`wallet_flow::maybe_sent`).

Hardware wallets (`core/src/ledger/`, `core/src/trezor/`, `core/src/hardware.rs`) follow the same steps, with
signing done on the device after an on-screen review, and every returned signature checked before broadcast.

## Background work

- **Live balances** (`core/src/balance_watch.rs`): WebSocket subscriptions or polling per network; the backend
  emits a `balance-changed` event and the card is reread.
- **Private cryptos**: Monero (`core/src/monero.rs`) and shielded Zcash (`core/src/zcash_shielded.rs`) scan the
  chain locally with viewing keys, in the background, every 30 seconds.
- **Charts** (`core/src/price_history.rs`, `core/src/portfolio.rs`): price series and portfolio value rebuilt
  from on-chain history, requested as full series so no provider learns when the user transacted.

Slow or network-bound commands run off the main thread (`run_blocking` in the backend) so the window never
freezes.

## Network modules

| Network | Module(s) | Notes |
|---|---|---|
| Bitcoin | `btc_tx.rs`, `btc_rpc.rs`, `btc_psbt.rs` | Esplora (Blockstream, mempool.space fallback), BIP143 signing, all address types |
| EVM networks | `eth_tx.rs`, `eth_rpc.rs`, `evm_sign.rs`, `blockscout.rs`, `routescan.rs`, `nodereal.rs`, `alchemy.rs`, `custom_networks.rs` | Legacy EIP-155 transactions; history from the indexer suited to each network |
| Solana | `sol_tx.rs`, `sol_rpc.rs`, `sol_spl.rs`, `sol_stake.rs` | Transactions built by hand; SPL and Token-2022 tokens; native staking |
| Zcash | `zcash.rs`, `zcash_shielded.rs` | Official librustzcash crates; lightwalletd over gRPC; Orchard and Ironwood |
| Monero | `monero.rs` | monero-oxide; Ledger key scheme; local scanning |
| Dogecoin | `doge.rs` | Legacy signatures, every input checked against its source transaction |
| Tron | `tron.rs` | TRC-20 transfers simulated before signing |
| XRP Ledger | `xrp.rs` | Destination tags always shown |
| Stellar | `stellar.rs` | Memos always shown |
| NEAR | `near.rs` | Implicit accounts, Borsh transactions |
| Cardano | `cardano.rs` | CIP-3 Icarus keys, Conway-era CBOR, pool delegation |
| Stacks | `stacks.rs` | Memos always shown |
| Bittensor | `bittensor.rs` | Runtime metadata checked on every send, node-side validation |

Tokens come from a single registry (`core/src/tokens.rs`): the frontend only passes a token identifier, never a
contract address.

## Swaps and staking

- `swap_routes.rs` decides which provider can connect two cryptos, directly or in two steps.
- `thorchain_rpc.rs` (THORChain and Maya), `jupiter_rpc.rs`, `cow.rs`, `lifi.rs`, `swapkit.rs`,
  `moonpay_trade.rs`: one module per provider. Each one verifies what the provider returns before anything is
  signed (memo, order, PSBT or simulated effects).
- `swap_health.rs` reports providers that are not responding; `native_deposit.rs` registers the affiliate name.
- `staking.rs` reads staking yields; `sol_stake.rs` and `cardano.rs` implement native staking.

## WalletConnect

`core/src/walletconnect/` implements the WalletConnect v2 protocol in Rust (relay connection, pairing, session
state machine, encryption), checked against vectors from the official SDK. `core/src/dapp_requests.rs` parses
and prepares each dApp request so that what is signed and what is shown in the native dialog come from the same
data, never from the frontend.

## Where to start reading

- `core/src/api.rs`: the high-level operations (create, unlock, restore, send).
- `app/src-tauri/src/lib.rs`: how each command validates its input and what the confirmation dialogs show.
- The module-level documentation at the top of each file in `core/src/`, which explains the design choices and
  the checks made against official implementations.
