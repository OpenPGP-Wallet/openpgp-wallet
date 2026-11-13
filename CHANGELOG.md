# Changelog

All notable changes to OpenPGP Wallet are listed here, newest first. Dates are release dates (UTC). Download
links and SHA-256 hashes of each build are on the [releases page](https://github.com/OpenPGP-Wallet/openpgp-wallet/releases).

## [Unreleased]

### Added
- FROST tab: recovery after a lost computer (frost-zec spec § 7.2). « Recover on Mainnet / testnet » opens member 3's
  backup file in a native window (it never reaches the page) and asks for its passphrase; the wallet then pairs
  with the co-signer (`frost-zec qr recover`), checks the old account the co-signer describes against member 3 and
  the file's viewing key before sending anything secret, and creates a new account. The old account gets its own
  card: once synced, « Move everything to the new account » sends all its funds there, signed by member 3 restored
  and the co-signer, after a Windows confirmation and the cancellation delay; it is then removed (set aside).

## [2.17.0] - 2026-11-13

### Changed
- FROST tab: the wallet speaks version 1.0 of the co-signing protocol (frost-zec spec v1.0), after the review of
  version 0.1 by @danielgorgonha from @deegalabs. It needs a co-signer of the same version; with an older one,
  the wallet says to update it. Accounts already set up keep their keys.
  - A send takes two messages instead of three: the wallet sends its signing request first, and the co-signer
    answers once. A pasted message that is not the answer to this request leaves the request waiting.
  - A new account ends with the co-signer's acknowledgement: the co-signer confirms it saved its share and checked
    the backup, and only then does the wallet show the account's address. This replaces the comparison of the
    address in a Windows window. An account whose setup was left before that step is finished from its card,
    with the co-signer's acknowledgement (`frost-zec qr done` shows it again).
  - Until the acknowledgement, the page is not given the account's address at all.
- FROST tab, testnet: the details of a signing request, as the wallet and the co-signer show them, are in TAZ
  instead of ZEC.

## [2.16.3] - 2026-11-12

### Fixed
- FROST tab: the wallet checks the transaction with the co-signer's own rules before it sends the signing request,
  and these are stricter now (frost-zec 5fc6b6e). A fee above ZIP 317 for the actions the payment needs, zero-value
  padding, an expiry far beyond the current height, and a zero-value note to another address are refused. The lower
  fee of ZIP 2009 passes. Reported by Daniel Gorgonha (DeegaLabs).

## [2.16.2] - 2026-11-12

### Fixed
- FROST tab: an account could be funded before its co-signer had finished. At the last setup step the wallet
  already holds the account and shows its address, but the co-signer computes its share and the backup's only
  from that step's message: if the message never reached it, the account could never sign and funds sent to it
  were lost. A new account now stays "setup not finished", with no address on its card and no way to send, until
  the user confirms in a native window, showing the whole address, that the co-signer shows the same one. The
  last step's button says so instead of "Done", and comes before the QR code. Accounts set up before keep
  working as they are.
- FROST tab: recipients the co-signer refuses (transparent, TEX or Sapling addresses, or a unified address with no
  Orchard receiver) are refused before anything is built, instead of at the co-signer after every confirmation.

### Added
- FROST tab: a line under the recipient field says, as it is typed, whether the address is valid, on the
  account's network, and accepted by the co-signer. The card of a confirmed account says "Address confirmed with
  the co-signer".

### Changed
- FROST tab: amounts on testnet are shown in TAZ, not ZEC, on the card, in the send steps and in the native
  windows.
- FROST tab: the red "Unaudited prototype: small amounts only" line at the top of the tab is removed.

## [2.16.1] - 2026-11-12

### Added
- FROST tab: "Remove this account from the wallet", to set up a new FROST account on the same network. It asks
  in a native window, says how much the account still holds, and deletes nothing: the account's files are set
  aside in the `zcash_frost_removed` folder of the wallet's data, and putting them back restores the account and
  its funds.
- FROST tab: a button copies the transaction ID after a send.
- FROST tab: "Paste the co-signer's message" takes the co-signer's answer from the clipboard in one click, next to
  a short note on what to do without a camera. The clipboard is read by the backend, which passes on only a
  `ur:zcash-frost` message: nothing else copied reaches the page. If the clipboard still holds the wallet's own
  message, or no message at all, the window says so.

### Changed
- FROST tab: "Copy as text" is a full button instead of a grey link, and it comes before the QR code with the
  paste button and the password, so that a co-signer on the same computer needs no scrolling. Errors show under the
  step. The animated QR codes are drawn larger (up to 520 px), so that a phone used as a webcam can read them.
- FROST tab: each step says how to give the message to the co-signer and get its answer with or without a camera.

## [2.16.0] - 2026-11-11

### Added
- FROST tab: a FROST 2-of-3 shielded Zcash account (Ironwood pool, mainnet and testnet). The wallet is member 1;
  a co-signer ([frost-zec](https://github.com/OpenPGP-Wallet/frost-zec)) creates members 2 and 3 and approves each
  send. The devices talk through animated QR codes, or the same messages as text (camera, or Ctrl+V). The pairing
  code is compared in a native window, every send is confirmed in a native window first, and member 1's keys are
  stored encrypted with a key derived from the wallet's master key.
- The co-signer checks every transaction on its own before it signs, and shows the address the user was given,
  once it has checked that the payment really goes there.

### Security
- RUSTSEC-2026-0459 (libsqlite3-sys < 0.39) is listed as open: the fix needs rusqlite 0.41, and the Zcash wallet
  library still requires 0.37. The app opens only its own databases in its data folder.

## [2.15.0] - 2026-10-24

### Security
- rustls-webpki 0.103.16 (RUSTSEC-2026-0382: distrusted intermediates could be accepted) and webpki-roots 1.0.11
  (RUSTSEC-2026-0381: distrusted emSign intermediates).

### Changed
- Zcash: ready for NU7, which activates on mainnet at block 3,543,405 (around November 5), with the Zcash
  libraries released on 2026-10-21. From NU7, earlier versions refuse every ZEC send and ask for an update; no
  funds are at risk, but update before then.
- Zcash: transparent sends stay valid for about 50 minutes after NU7 too (120 blocks of 25 s instead of 40 blocks
  of 75 s).
- Zcash: unified addresses in the new format (zu1…, tu1…, ZIP 316 Revision 2) are accepted as recipients. The
  wallet's own shielded addresses stay u1….
- Password fields: every field has its own eye to show or hide what was typed. The system one only appeared on
  the focused field and could disappear.

### Fixed
- Shielded Zcash: once NU7 is active, a wallet created more than about a day and a half before its shielded
  account was set up or rebuilt would have started scanning after its creation date, hiding its first shielded
  funds until a full rescan. The first block to scan now follows the real block spacing (75 s, then 25 s).

## [2.14.1] - 2026-10-17

### Changed
- Shielded Zcash: the card shows how far the sync has got ("Syncing shielded funds… 48%").

### Fixed
- Shielded Zcash: adding a profile could stop the shielded sync for good. The Zcash library refused to add its
  account to some existing databases ("Data DB is corrupted: the Ironwood note commitment tree retains
  checkpoints…"), and every later pass failed before syncing anything. The database, which only holds viewing
  keys and data read from the chain, is now rebuilt and rescanned instead. "Rescan from the beginning" rebuilds
  it too.
- Shielded Zcash: a failing sync is now shown on the card ("Shielded funds sync failed, retrying in 30 s")
  instead of "Syncing" forever.
- Shielded Zcash: a sync stuck on a server that stops answering now restarts on its own (each pass is bounded
  to 5 minutes and retried 30 s later, keeping the blocks already scanned). Before, it only restarted with the
  app.
- Development build: the Zcash libraries are optimized like the Monero ones, so syncing shielded funds takes
  about a minute instead of six.

## [2.14.0] - 2026-10-17

### Security
- The backup kit no longer goes through the interface. The encrypted shares and their private keys stay in
  Rust, which writes them to files or USB drives and reads them back for a restore; the interface only shows
  each share's label, number and passphrase. Restoring from files now opens the native "Open" dialog.
- The password rule (12 characters minimum, no common pattern, some variety) is enforced in the core at
  creation and restore, not only by the interface.
- Adding a network or choosing a Monero node now asks for confirmation in the secure window, showing the
  server, before the app contacts it for the first time.
- Shielded Zcash sends lock the seed in memory like every other send; heights announced by the Zcash server
  can no longer overflow.
- rustls 0.23.46 (RUSTSEC-2026-0346 to 0349).

### Changed
- Inter for headings and amounts too (Space Grotesk dropped).
- Threat model, architecture and README: the cancellation delay is described as a guard against mistakes, the
  secure confirmation window is documented, and the interface's access to secrets is stated exactly.

## [2.13.2] - 2026-10-13

### Added
- Shielded Zcash: support for the Ironwood pool introduced by the NU6.3 network upgrade (block 3,428,143, after
  which the Orchard pool accepts no new funds). Funds received in Ironwood are counted in the balance and the
  history and can be spent, and change goes to Ironwood.

### Changed
- Installer descriptions in English.
- The repository is prepared for open source: MIT license, security policy, English code comments and
  documentation, threat model in English, continuous integration.
- The core crate is renamed `openpgp-wallet-core`; the command-line demos moved to `core/examples/`.
- The showcase website moved to its own repository, and the project to the OpenPGP-Wallet GitHub organization.

## [2.13.1] - 2026-10-12

### Changed
- Quantities are shown without needless trailing zeros ("0.24" instead of "0.24000000") on wallet cards, watched
  wallets, Ledger and Trezor accounts and the swap window. Nothing is rounded.

### Fixed
- Requested amount (QR code): typing "0," or "," no longer shows an error while typing, and ",5" means 0.5.

## [2.13.0] - 2026-10-11

### Changed
- More modern interface: Space Grotesk headings, "glass" cards and windows, deeper background with accent glows,
  translucent sidebar.
- Violet, Orange, Black and White themes redone on the model of Blue, with two colors per theme.

### Added
- Three new themes: Emerald, Ocean and Pink. The Windows title bar takes the theme's background color.

## [2.12.0] - 2026-10-10

### Added
- **Tokenized shares**: 19 xStocks (Backed Assets, on Solana), in their own "Stocks" tab, with live prices,
  charts, buying and selling through Jupiter and sending from the card. Display multipliers and issuer
  transfer pauses are handled.
- **Custom EVM networks** added by RPC, with the chain ID verified and no dollar price.
- USB backup: several wallets on one drive, each in its own named folder; "Check my backup drives" (read-only)
  with a yearly reminder.

### Fixed
- Shares from two different kits are refused (mixing them used to rebuild a wrong secret silently); the restore
  confirmation shows the addresses of the recovered wallet.
- History and charts are back on Arbitrum, Base and Polygon, whose public explorers now block automated
  requests (Blockscout's official API and Alchemy are used instead).
- Backups no longer depend on the computer's clock; backups from earlier versions still restore.

### Changed
- The compact list view is redone: one readable row per crypto, icon buttons, works in narrow windows.

## [2.11.0] - 2026-10-09

### Added
- **Staking**: liquid staking (JitoSOL, stETH), native Solana staking with every operation simulated before
  signing, and Cardano delegation.
- **Bittensor (TAO)**: balance, sending, history. Quant (QNT) on Ethereum. Full BNB Chain history.
- **MoonPay Trade** as a swap provider: simulated router on the same EVM network; elsewhere offered only as a
  last resort, with delivery flagged as unverifiable.
- Bitcoin: sending to every address type (1…, 3…, bc1q…, bc1p…), including from Ledger and Trezor.
- "Track the transaction" button after sending; sends appear as "Pending" in the history right away.
- Secure confirmation window for sensitive actions that are not transactions.

### Changed
- Network fees estimated in the send preview, Bitcoin fees shown in currency, clearer receive screen (which
  network to pick on an exchange).

### Removed
- HyperEVM.

### Security
- Audit rounds 32 and 33: a send accepted by the network is never shown as refused; batched Permit2 approvals
  are detected; reset really erases the previous wallet's state.

## [2.10.0] - 2026-10-05

### Added
- Seven new networks: Dogecoin, Tron (with TRC-20 USDT), XRP Ledger, Stellar, Stacks, NEAR and Cardano.
- **SwapKit** (NEAR Intents, Chainflip): each deposit is confirmed with the provider itself before signing.
- Provider status messages, a "Max" button for swaps, guided two-step swaps.
- 5-second cancellation delay after the native confirmation, for sends, swaps and WalletConnect.
- Warning for an address almost identical to a known one, with the exact position of the difference.

### Changed
- Redesigned send window; a crypto's history opens in its own window; the History tab becomes "Activity".

### Fixed
- A network drop during a send now says "the transaction may have gone out, check the history before sending
  again" instead of a misleading "refused".
- Bitcoin falls back to mempool.space when Blockstream rate-limits requests.

## [2.9.0] - 2026-10-03

### Added
- **Monero**: primary address, receiving, balance, history and sending; blocks scanned on the device with the
  view key; public nodes by default or your own.
- **Shielded Zcash**: u1 address, shielding transparent ZEC, sending from shielded funds.
- White theme.

### Fixed
- CoW: arithmetic overflow on some 18-decimal tokens; drag and drop in "Arrange".

## [2.8.0] - 2026-10-03

The app is renamed **OpenPGP Wallet**.

### Added
- Swaps from Bitcoin (LI.FI, THORChain, Maya) and from Zcash (Maya); several providers per swap (THORChain,
  Maya, Jupiter, CoW Protocol, LI.FI); every crypto can now be swapped with every other.
- Transparent Zcash: balance, receiving, sending, history.
- History and portfolio chart for every crypto, tokens included.
- New interface with a sidebar, total value header and "Arrange" (drag and drop, sort by value or name).

### Security
- SegWit address encoding rules (BIP173/BIP350) fully checked: a malformed Taproot address could previously be
  paid as a regular one.

## [2.7.0] - 2026-10-01

The app is renamed "PGP Wallet".

### Added
- BNB Chain, Avalanche, Polygon, and ETH on Arbitrum and Base, with full fee computation including layer 1 fees.
- Tokens from a built-in registry (USDT, LINK, DAI, USDe, UNI and more), USDC on Ethereum, Base and Arbitrum.
- "Manage my cryptos", amounts in euros, incoming funds notifications, payment requests with an amount in the
  QR code, a History button on each card.

## [2.6.0] - 2026-09-28

### Added
- **USB backup**: each share written complete to a USB drive and decrypted back before the app says it is done;
  restore from two drives; "I already have a wallet" on first launch.
- Collapsible cards, green or red charts.

### Fixed
- The send window no longer gets cut off in small windows.

## [2.5.0] - 2026-09-27

### Added
- **WalletConnect** enabled, on Ethereum and Solana, with every signature behind the password and a native
  confirmation.

## [2.4.0] - 2026-09-27

### Added
- **Trezor** (Model T, Safe 3, Safe 5) for Ethereum, Bitcoin and Solana.
- Live balances, unconfirmed Bitcoin receipts shown separately, "All" period on charts.

## [2.3.0] - 2026-09-27

### Added
- **Swaps** through THORChain and Jupiter, with the quote, minimum output and real effects checked before signing.
- **Ledger** for Ethereum, Bitcoin and Solana.
- Transaction types and historical dollar values in the history, price and portfolio charts, warnings before
  sending to new, unused or lookalike addresses.

### Security
- Device private key stored in the Windows Credential Manager; fees shown and capped before confirmation.

## [2.2.0] - 2026-09-23

### Added
- Compact list view with aligned columns, one-click address copy, percentage quick amounts, Enter to submit
  passwords, throttled Refresh buttons.

## [2.1.0] - 2026-09-23

### Added
- USDC (SPL token): balance, sending, history. Address book, watch-only external wallets.

## [2.0.0] - 2026-09-20

### Added
- PGP messages encrypted for several recipients at once; translated backend errors (French/English).
- **Windows Hello** as an optional second way to unlock, sealed in the TPM.

### Changed
- Shared HTTP client and parallel RPC calls; recalibrated Bitcoin fee targets.

### Fixed
- Removed `panic = "abort"` from the release profile and added a local crash log; the installer now installs
  WebView2 when it is missing.

## [0.1.0] - 2026-09-20

First working proof of concept: a non-custodial Bitcoin, Ethereum and Solana wallet whose master key is
protected by 2-of-3 Shamir secret sharing and OpenPGP, with no seed phrase.

[Unreleased]: https://github.com/OpenPGP-Wallet/openpgp-wallet/compare/v2.17.0...HEAD
[2.17.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.17.0
[2.16.3]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.16.3
[2.16.2]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.16.2
[2.16.1]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.16.1
[2.16.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.16.0
[2.15.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.15.0
[2.14.1]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.14.1
[2.14.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.14.0
[2.13.2]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.13.2
[2.13.1]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.13.1
[2.13.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.13.0
[2.12.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.12.0
[2.11.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.11.0
[2.10.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.10.0
[2.9.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.9.0
[2.8.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.8.0
[2.7.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.7.0
[2.6.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.6.0
[2.5.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.5.0
[2.4.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.4.0
[2.3.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.3.0
[2.2.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.2.0
[2.1.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.1.0
[2.0.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v2.0.0
[0.1.0]: https://github.com/OpenPGP-Wallet/openpgp-wallet/releases/tag/v0.1.0
