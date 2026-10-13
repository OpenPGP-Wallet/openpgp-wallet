# Security Policy

OpenPGP Wallet is pre-release software. It has not been audited by an independent firm yet, so please don't trust it with funds you can't afford to lose. That also makes outside review especially valuable, and I'm grateful for it.

## Reporting a vulnerability

Please report security issues privately by email rather than in a public GitHub issue:

- **Email:** openpgp-wallet@protonmail.com
- **PGP fingerprint:** `6457 EFC3 9B91 69C7 6240  C335 D7C3 4A98 9CA8 DFCD`

Encrypting your report is encouraged, especially if it includes a proof of concept. The public key is at the end of this file.

A useful report includes:

- the affected version or commit;
- what an attacker can achieve, and under which conditions (malware on the machine, a malicious RPC node, a hostile dApp, physical access to a backup drive, and so on);
- steps to reproduce, or a proof of concept;
- a suggested fix, if you have one.

## What to expect

This is a one-person project, so these are commitments I can actually keep:

- an acknowledgement within 3 days;
- a first assessment within 10 days;
- a fix, or a clear plan, as fast as the severity calls for. Anything that could lead to a loss of funds comes first.

I'll keep you posted along the way and credit you in the release notes, unless you'd rather stay anonymous.

## Disclosure

Please allow time for a fix to ship before going public: 90 days by default, or sooner once a fixed release is out. If an issue is being actively exploited, say so and we'll agree on a faster timeline together.

## Scope

**In scope:** this repository, meaning the Rust core (`core/`) and the desktop app (`app/`), and in particular how they handle keys, backups, transaction building and signing, and what they trust from the outside world.

**Out of scope:** the third-party services the app talks to (blockchain nodes, indexers, swap providers, the WalletConnect relay), unless the app trusts their answers in a way it shouldn't. The showcase website (`site/`) is in scope only for issues that could affect users' safety.

I won't take any action against anyone who researches in good faith, avoids harming users, and never touches funds that aren't theirs.

## Supported versions

Security fixes go into the latest release only.

## PGP public key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: ProtonMail

xjMEass+dBYJKwYBBAHaRw8BAQdAfSrNGgli0pQwIXVmG1Ti+LisD/vw8xlq
csRSYUZ9RejNPW9wZW5wZ3Atd2FsbGV0QHByb3Rvbm1haWwuY29tIDxvcGVu
cGdwLXdhbGxldEBwcm90b25tYWlsLmNvbT7CwBEEExYKAIMFgmrLPnQDCwkH
CRDXw0qYnKjfzUUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu
b3JnYTXV6HjwYVhJINp695psNA+eDuXIsQWo4fqgGF9ltNUDFQoIBBYAAgEC
GQECmwMCHgEWIQRkV+/Dm5Fpx2JAwzXXw0qYnKjfzQAAbUMBAKvgaxIm6/8J
G8xQiMOel0Zt47lxshkFtQieT6cfDNpdAQDwwKGmJYNGZ6UIIa5kUslIovaG
nFPzpzZ4c8a+D7kVDcLAHgQQFggAkAWCass+sQWDAO1OAAkQ2AbBr1l46Mc1
FAAAAAAAHAAQc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ7B26Z4Fif4I
j5yDa+BLA/wsHG9wZW5wZ3AtY2FAcHJvdG9uLm1lIDxvcGVucGdwLWNhQHBy
b3Rvbi5tZT4WIQQKhlL+XVM4YFeJn+nYBsGvWXjoxwAAy4cBAKKiykeFsfsw
/Ugx6SJY9J2vV9c6a/EIeTPj+BlbAJxsAQD4ufv8Bs3ipPCI96Y/uzYyc/hI
eVjkDusUIA9/pPCpCc44BGrLPnQSCisGAQQBl1UBBQEBB0Ct8aRfQHZ6ps+N
/P+zR+9JmacFuck2w0Q+0uDgfrlrawMBCAfCvgQYFgoAcAWCass+dAkQ18NK
mJyo381FFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ7q2
P+L4MG90gnSRQsh7cl6W/+pgaoxpk2BTt3FgBWePApsMFiEEZFfvw5uRacdi
QMM118NKmJyo380AAPqnAP4pzsFi+z0cOv5GP8WxAK02X6D6cHVA/0f2hFyM
yl+W2QD/azrqev8kPLxQkVPZPuqB+XbHL5070qdEXW8t5WlrCwc=
=Qki8
-----END PGP PUBLIC KEY BLOCK-----
```
