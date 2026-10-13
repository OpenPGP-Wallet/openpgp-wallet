## What and why

<!-- What does this change, and why is it needed? Link the related issue if there is one. -->

## How it was tested

<!-- Commands run, networks used, manual checks. For code that touches the OS (vault, Windows Hello, USB,
     hardware wallets), describe how you checked it by hand. -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets` are clean
- [ ] `cargo test --workspace` passes
- [ ] No secret can reach the frontend, a log or an error message
- [ ] User-facing strings exist in French and English
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if users will notice the change
