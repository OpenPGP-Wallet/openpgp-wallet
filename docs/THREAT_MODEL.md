# Threat model: OpenPGP Wallet (Windows application)

Working document, last reviewed on 2026-10-04 (v2.9.0 and later commits); the list of networks was brought up to
date on 2026-10-13 (Bittensor added, HyperEVM removed). It gives structure to the project's informal threat
model ("active malware vs. offline file theft") with a professional audit in mind: what is protected, against
whom, by what means, and what remains at risk. Each countermeasure points to the code that implements it.
**None of these protections has been verified by an independent auditor yet.**

## 1. Scope

- Tauri v2 desktop application for Windows: Rust core (`core/`), command bridge (`app/src-tauri`), local web
  interface (`app/src`).
- Non-custodial multi-network wallet: Bitcoin, EVM networks (Ethereum, L2s, BNB Chain, Avalanche, Polygon),
  Solana, Zcash (transparent and shielded), Monero, Dogecoin, Tron (TRX and TRC-20 USDT), XRP Ledger, Stellar,
  NEAR, Cardano, Stacks, Bittensor, and the tokens in the registry (`tokens.rs`).
- Out of scope: the iOS version (not started), the third-party services themselves (nodes, swap aggregators),
  the operating system and the hardware.

## 2. Assets

| Asset | Where it lives | Consequence of a leak |
|---|---|---|
| Master entropy (HD seed) | Encrypted local vault `device_vault.asc`; in the clear only for the duration of an operation, in locked memory | Total loss of funds on every network and profile |
| Device PGP private key | Windows vault (Credential Manager), encrypted file as a fallback | With the password: access to the local vault |
| Device password | The user's head; never stored | With the device key: access to the vault |
| Shamir backup kit (3 shares, any 2 are enough) | The user's files or USB drives, each share PGP-encrypted with its own passphrase | 2 shares + their passphrases: total loss |
| Derived (signing) keys | Derived on the fly from the seed, wiped after use | Loss of funds on the network concerned |
| Zcash (UFVK) and Monero (private view key) viewing keys | Process memory after unlock; the UFVK is also in `zcash_shielded.sqlite` | Privacy: shielded history and balances visible, no funds lost |
| Local state of the private cryptos | `zcash_shielded.sqlite`, `monero_wallet.json` | Privacy only |
| Convenience data | Profiles, address book, recipients already paid, Monero node | Privacy (addresses, habits) |
| Integrity of what is signed | The transaction building pipeline | Funds sent somewhere other than intended |

## 3. Trust boundaries

1. **Web interface ↔ Rust core**: the interface is treated as untrusted. It only receives public data
   (addresses, balances, transaction identifiers); everything that gets signed is recomputed and confirmed on
   the Rust side (`app/src-tauri/src/lib.rs`).
2. **Process ↔ operating system**: Windows vault, Windows Hello, native dialogs.
3. **Application ↔ network**: public nodes, indexers, swap aggregators, WalletConnect.
4. **Application ↔ hardware devices**: Ledger, Trezor (USB).
5. **Application ↔ user**: what they see and confirm (native dialog), what they type.

## 4. Attackers

| Code | Attacker | Assumed capabilities |
|---|---|---|
| A1 | Offline thief | Copy of the disk or the data folder, without an open session |
| A2 | Malware in the session | Reads the screen, the clipboard, keystrokes; may read the process's memory |
| A3 | Malicious or compromised network service | Node, indexer, swap aggregator, relay: false answers, booby-trapped transactions |
| A4 | Malicious third-party application (dApp) | Signing requests through WalletConnect |
| A5 | Network attacker (MITM) | Intercepts or modifies unencrypted traffic |
| A6 | Supply chain | Compromised dependency, binary tampered with on download |
| A7 | Social engineering | Fake support, fake update, asking for the backup files |
| A8 | Content injected into the interface | Malicious text in a network response that gets displayed (XSS) |

## 5. Threats and countermeasures

### 5.1 Offline theft (A1)
- **Encrypted vault** with the device's PGP identity (sequoia-openpgp, `crypto-cng` backend); the device's
  private key is encrypted with the password (S2K) and stored in the Windows vault
  (`core/src/secure_storage.rs`). A copied disk holds no seed in the clear.
- **Strong password** required at creation (12 characters minimum, strength indicator).
- **Unlock attempt limiting**: 5 free attempts, then a growing wait from 5 s to 300 s, persisted
  (`api::enforce_unlock_lockout`).
- **Changing the wallet on the device** (reset, restore): state tied to the old seed (shielded Zcash database,
  Monero state, recipients already paid) is deleted, and at unlock, Zcash accounts with another seed
  fingerprint and Monero state for another key are set aside before anything is displayed.
- **2-of-3 Shamir kit**: a single share reveals nothing; each share has its own passphrase; two shares are
  refused on the same USB drive (`usb_backup.rs`).
- *Residual risk*: a weak password remains open to offline brute force if the device's private key is
  extracted from the Windows vault (same user session); privacy of the state files (shielded Zcash, Monero,
  address book), which are not encrypted.

### 5.2 Malware in the session (A2)
- **Seed never kept**: decrypted again for each sensitive operation (send, name registration, kit
  regeneration), then wiped (`zeroize`); memory locked against being written to disk (`memory_guard::lock`,
  `VirtualLock`).
- **Automatic lock** after 10 minutes of inactivity (interface); viewing keys and address caches are cleared
  on lock.
- **Native confirmation dialog** (OS, not HTML) showing the exact recipient, amount and fees that will be
  signed; warnings for an address never paid, an address that looks like one already used
  (`lookalike_warning`) and an address never used on-chain.
- **Windows Hello** can replace the password for unlocking (no keystrokes to capture).
- **Hardware wallets** (Ledger, Trezor): the key never leaves the device, with on-screen review.
- **Balance checked before the confirmation dialog** for every wallet send (Bitcoin included since v2.10): an
  impossible send is never presented for confirmation.
- **5 s cancellation delay** after the native dialog, before any signing, enforced on the Rust side
  (`send_grace_period`): the interface can only shorten it or cancel; the seed is only unlocked afterwards; a
  lock cancels pending sends.
- **Recognized recipient**: when the address belongs to another profile of the wallet (addresses derived at
  unlock, never supplied by the interface), the native dialog names that profile.
- **"Max"** recomputed on the Rust side when the dialog opens (balance minus current fees), shown as "maximum,
  fees deducted" and then signed as is: a flag forged by the interface only changes the amount shown.
- *Residual risk*: malware able to read memory at signing time, or to capture the password, gets the seed; a
  clipboard address swap is only detected if it looks like an address already paid. No software wallet fully
  protects against A2 (which is why hardware wallets exist).

### 5.3 Malicious network services (A3) and network attacker (A5)
- **Everything over HTTPS** (nodes, indexers, aggregators); a Monero node over `http://` is only accepted on
  the machine itself or the local network (`monero::normalize_node`).
- **Transactions built and signed locally** from checked fields: EVM chain ID set by the app, `pending` nonce,
  gas price shown and then signed as is, fee caps (Monero: 400,000 piconeros per unit of weight; Zcash: ZIP-317
  fees never higher than those shown).
- **Network version guard**: Zcash (consensus branch compared with the server), Monero (hard fork 16
  expected); a send is refused if the network has moved beyond what the library knows.
- **Swaps**:
  - THORChain/Maya: memo reread and checked (asset, destination address is the user's own, minimum output,
    affiliate name only if verified on the network) before signing (`thorchain_rpc::verify_memo`);
  - LI.FI: only routes whose recipient can be verified are kept; a Bitcoin transaction prepared by LI.FI is
    checked output by output (the user's funds only, a single deposit, change returned to the user, bounded
    fees; `lifi.rs`);
  - CoW, Jupiter: order and transaction reread before signing (`cow.rs`, `jupiter_rpc.rs`);
  - SwapKit (NEAR Intents, Chainflip): the deposit opened by SwapKit is confirmed by the provider's official
    API, independent of SwapKit (deposit address, cryptos, amount, delivery and refund to the user's
    addresses, minimum, deadline, bounded commissions); the deposit is a transfer built and signed by the app
    (`swapkit.rs`). Residual risk: SwapKit and the provider compromised at the same time; once deposited, the
    funds depend on the provider executing the swap (a refund is planned otherwise).
- **Monero**: blocks scanned locally (the node does not learn which outputs are the user's); decoy selection
  refuses a node that lies about the output being spent; reorganizations are detected.
- **Shielded Zcash**: compact blocks decrypted locally (lightwalletd only sees block requests).
- **Dogecoin**: the legacy signature scheme (no SegWit) does not commit to the input amounts, so a service
  lying about an output's value would turn the difference into fees. Each input is reread from its raw source
  transaction, whose recomputed hash must equal the identifier: amount and script are checked before signing
  (`doge::verify_inputs`); fees are bounded (0.01 to 5 DOGE/kB), shown and then never exceeded.
- **Tron**: transactions encoded and signed locally (encoding compared byte for byte with a java-tron
  node's); a TRC-20 token transfer is first SIMULATED from the user's account and must emit exactly the
  intended transfer (sender, recipient, amount); maximum fees shown, `fee_limit` signed and capped (100 TRX).
- **XRP Ledger**: payments serialized and signed locally (canonical binary format checked against Ripple's
  official libraries; signature accepted by a real node, tampered version refused). Network rules applied
  BEFORE the dialog: the reserve (1 XRP + 0.2 per object) can never be sent, a new recipient is only activated
  with at least the base reserve, a recipient that requires a destination tag (exchanges) is refused without
  one, a "deposit authorization" recipient is refused if it has not authorized the sender; "X" addresses are
  refused. The tag is always shown in the native dialog ("none" included); fees capped (0.001 XRP), validity
  limited to ~1 min (`LastLedgerSequence`).
- **Stellar**: XDR transactions encoded and signed locally (bytes identical to the SDF's official library;
  account creation and payment with a memo accepted end to end on testnet, tampered signature refused
  `tx_bad_auth`). Before the dialog: the reserve can never be sent, a new recipient is CREATED with at least
  1 XLM, a recipient that requires a memo (SEP-29) is refused without one; muxed addresses (M…) refused, a
  secret key (S…) pasted by mistake is flagged. The memo is always shown with its type in the native dialog;
  text memos are limited to printable ASCII (no invisible or direction-flipping characters). Fee bid capped
  (0.1 XLM), 3-minute validity based on the latest ledger's time (not the local clock).
- **NEAR**: transfers serialized (Borsh) and signed locally (bytes identical to the official library;
  creation of an implicit account and a transfer back executed end to end on testnet, actual fees exact to the
  yoctoNEAR, tampered signature refused `InvalidSignature`). Before the dialog: account storage can never be
  sent, a new implicit account is created with at least its storage, a named account that does not exist is
  refused, an Ethereum address (0x…) is refused with guidance. Fees: the network's hold (execution gas at the
  minimum purchase price, + 20%) is the maximum shown and checked; the actual fees, much lower, are shown next
  to it. Node timeout: "sent but not confirmed yet", never "refused".
- **Cardano**: BIP32-Ed25519 keys (CIP-3 Icarus from the master entropy, CIP-1852 paths) and CBOR transactions
  built and signed locally (bytes identical to cardano-serialization-lib; a real node verifies the signature:
  only the MISSING signature of a third-party input's owner is requested, and the tampered version is refused
  `InvalidWitnessesUTXOW`). Before the dialog: outputs with tokens or datums are never spent, minimum ADA per
  output, exact fees, change shown; contract (script), staking, testnet and Byron addresses refused. The public
  service (Koios) could lie about outputs: at worst the network refuses the transaction (amounts are committed
  to by the signature, no possible loss).
- **Stacks**: transfers serialized and signed locally (bytes identical to @stacks/transactions; a send with a
  memo executed end to end on testnet, tampered signature refused `SignatureValidation`). Before the dialog:
  STX locked by stacking are never spent, fees capped (0.1 STX), contract (SP….name) and other-network
  addresses refused; the memo (34 bytes, printable ASCII) is always shown in the native dialog. Nonce read with
  pending transactions included.
- **Bittensor**: transfers encoded (SCALE) and signed locally (sr25519). On every send, the runtime's metadata
  is reread and must match exactly what the app knows how to encode, with the pallet and call indexes frozen
  (a node announcing other indexes is refused); the node validates the transaction before it is broadcast
  (`validate_transaction`), and fees above a cap are refused (`bittensor.rs`).
- *Residual risks*: a malicious node can show false balances or a false history (light wallet); a malicious
  Monero or Zcash node can weaken a send's privacy; public nodes see the IP address and the addresses queried;
  an aggregator can offer a bad rate (the minimum output shown bounds the loss, without guaranteeing the best
  price).

### 5.4 Third-party applications through WalletConnect (A4)
- Requests prepared on the Rust side (`dapp_requests::prepare`): supported methods and networks only, the
  transaction decoded and shown in the native dialog before any signature; the interface only relays.
- *Residual risk*: signing arbitrary messages (logging in to a dApp) remains possible after confirmation, so
  the user must understand what they sign; transaction signing through WalletConnect has not been tested in
  real conditions.

### 5.5 Supply chain (A6)
- `cargo audit` and `npm audit` at each release (0 vulnerabilities at v2.9.0; "unmaintained" warnings on
  transitive dependencies); well-known libraries for the cryptography (sequoia-openpgp, librustzcash,
  monero-oxide, k256, ed25519-dalek).
- SHA-256 hashes of the binaries published with each release.
- *Residual risks*: **unsigned binary** (Authenticode), so nothing proves its origin and SmartScreen warns
  about it; non-reproducible build; no verified automatic update (manual download).

### 5.6 Social engineering (A7)
- The user never sees a recovery phrase; the kit's passphrases are shown once, to be stored offline.
- A reminder shown with the kit: nobody will ever ask for the shares or their passphrases.
- *Residual risk*: a user who nevertheless hands two shares and their passphrases to fake support loses their
  funds.

### 5.7 Content injected into the interface (A8)
- **Strict CSP** (`tauri.conf.json`) and minimal Tauri permissions (`core:default` only): no file or shell
  access from the interface.
- Text coming from the network inserted with `textContent`, never `innerHTML` (error messages, histories).
- External links limited to an allowlist enforced on the Rust side (`open_external_link`).
- *Residual risk*: a flaw in WebView2 or in Tauri would bypass these protections; even then, the interface has
  no access to any secret or any signature without the native dialog.

## 6. Assumptions
- The operating system is not compromised at the kernel level; the Windows vault and Windows Hello do what
  they claim.
- The cryptographic libraries used are correct.
- The user reads the native confirmation dialog before approving.
- The shares of the backup kit are stored in separate places.

## 7. Open items (before any public trust)
1. Authenticode code signing of the binary (certificate to be bought by the project owner).
2. Security audit by an independent firm.
3. Encryption of the local state files (shielded Zcash, Monero, address book) with a key derived from the
   vault, for privacy against A1.
4. Real-world tests: Monero and shielded Zcash spends, swaps from BTC/ZEC, restore from a USB drive,
   Ledger/Trezor on real devices, WalletConnect signatures.
5. Reproducible build and verification of updates.
