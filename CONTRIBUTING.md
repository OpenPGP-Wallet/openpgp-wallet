# Contributing to OpenPGP Wallet

Thanks for taking the time to look at this project. Bug reports, reviews of the cryptographic code and pull
requests are all welcome. This guide explains how the project is organized and what a good contribution looks
like here.

**Security issues are not reported here.** Please follow [SECURITY.md](SECURITY.md) and write privately instead
of opening a public issue.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the approach before you spend
  time on it.
- Read the [architecture notes](docs/ARCHITECTURE.md) and the [threat model](docs/THREAT_MODEL.md). Most review
  comments in this project come back to the trust boundaries described there.

## Ground rules for wallet code

These are not style preferences; a pull request that breaks one of them will not be merged.

- **No secret ever reaches the frontend, a log or an error message.** Seeds, private keys, passphrases and
  passwords stay in Rust, in `Zeroizing` buffers, for as short a time as possible.
- **Everything that is signed is built and checked in Rust.** The web frontend is untrusted: it may suggest
  values, but the Rust side recomputes them, and the user confirms them in a native OS dialog that shows exactly
  what will be signed.
- **Data from the network is untrusted.** Quotes, memos, PSBTs and transactions supplied by a third party are
  parsed, checked or simulated before signing. A response that cannot be fully verified is refused, or clearly
  labeled as unverifiable in the confirmation dialog.
- **Never report a broadcast as failed when it may have gone out.** If the outcome is unknown, say so; a "failed"
  message that leads the user to send again can make them pay twice.
- **Backups must stay restorable.** Never change the on-disk format of backup kits or USB drives without keeping
  the old one readable, and never edit the frozen test kits in `core/testdata/`.

## Development setup

See [Building from source](README.md#building-from-source) in the README. Builds produce a large `target/`
folder; make sure you have a few tens of gigabytes free.

## Coding style

The project follows the usual Rust conventions and the spirit of
[librustzcash's guidelines](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md):

- Format with `cargo fmt` (default settings) before committing.
- Keep `cargo clippy --workspace --all-targets` free of warnings.
- Prefer clear, explicit code over clever code. Handle errors with `anyhow` and `?`; do not `unwrap()` or
  `expect()` on anything that comes from the network, a file or the user.
- Use checked arithmetic (`checked_add`, `checked_mul`…) for amounts: release builds wrap on overflow silently.
- Write comments and documentation in English. Explain **why** something is done, especially when it guards
  against an attack or a real-world failure; cite the specification, the official library or the measurement
  the code relies on.
- The frontend (`app/src`) is plain HTML, CSS and JavaScript with no framework and no runtime dependency. Insert
  untrusted text with `textContent`, never `innerHTML`.
- The interface is bilingual. Every user-facing string needs both a French and an English version (see the
  `I18N` tables in `app/src/main.js`, and `translate_error` in `app/src-tauri/src/lib.rs` for messages coming
  from Rust).

## Tests

- Run `cargo test --workspace` before opening a pull request.
- Add unit tests for new logic, ideally against vectors produced by an independent, official implementation
  (the existing tests compare encodings byte for byte with the reference libraries of each network).
- Tests that need the real network are marked `#[ignore]`. Document the exact command to run them in the test's
  doc comment, and never make them spend real funds.
- Automated tests are not enough for code that touches the operating system (vault, Windows Hello, USB, hardware
  wallets). Describe in the pull request how you checked it by hand.

## Commits and pull requests

- Keep each commit focused on one change and make sure every commit builds.
- Write commit messages in the imperative mood with a short type prefix, as in the existing history:
  `fix(zcash): count shielded funds in the Ironwood pool`, `feat(app): …`, `docs: …`, `chore: …`.
- In the pull request, explain what changes, why, and how you tested it. Screenshots help for interface
  changes.
- Add a line to the `[Unreleased]` section of [CHANGELOG.md](CHANGELOG.md) for any change a user would notice.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE), the same as
the rest of the project.
