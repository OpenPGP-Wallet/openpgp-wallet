# PGP Wallet PoC

Portefeuille crypto multi-réseaux (Bitcoin, Ethereum, Solana), **non-custodial** — la clé maîtresse n'existe jamais en clair hors de l'appareil, et n'est jamais visible par un tiers.

Contrairement aux wallets classiques, il n'y a **aucune seed phrase de 12/24 mots à noter**. La clé maîtresse est protégée par un partage de secret de Shamir (2 parts sur 3 suffisent, aucune seule ne sert à rien) chiffré avec OpenPGP, plutôt que par un unique artefact papier dont la moindre fuite compromet tout.

> **Statut : preuve de concept.** Fonctionnel de bout en bout sur les trois réseaux, mais pas encore audité par un tiers indépendant ni distribué à de vrais utilisateurs. À ne pas utiliser avec des fonds dont la perte serait un problème.

## Fonctionnalités

- **Bitcoin, Ethereum et Solana** depuis une seule entropie maître (dérivation HD), mainnet et testnet/devnet pour chaque réseau.
- **Profils multiples** : plusieurs adresses par réseau, un seul secret à protéger.
- Soldes, prix et capitalisations en direct, historique de transactions par crypto, détection des transactions en attente.
- Estimation dynamique des frais Bitcoin (rapide / moyen / lent) plutôt qu'un montant fixe.
- Messagerie chiffrée PGP entre destinataires (bonus : le protocole qui protège le wallet sert aussi à son usage d'origine).
- Confirmation systématique par boîte de dialogue **native de l'OS** avant tout envoi de fonds — jamais une simple modale web, pour rester fiable même si l'interface était compromise.

## Architecture

### Le problème avec une seed phrase

Une seed phrase classique est un point de défaillance unique : les 12/24 mots donnent un accès complet et immédiat aux fonds. Les perdre, c'est tout perdre ; les montrer une seule fois à la mauvaise personne (photo, malware presse-papier, épaule indiscrète), c'est aussi tout perdre. Toute la sécurité du wallet repose sur un seul artefact que l'utilisateur doit lui-même noter et cacher correctement — la partie la plus fragile de la chaîne étant systématiquement l'humain, pas la cryptographie.

### Modèle retenu : coffre local + kit de sauvegarde à seuil

La clé maîtresse (256 bits d'entropie, source de toutes les adresses du wallet) n'existe sous deux formes distinctes, chacune adaptée à un usage :

1. **Coffre local de l'appareil** — l'entropie complète, chiffrée par une identité PGP propre à cet appareil, déverrouillée par un seul mot de passe. C'est le chemin du quotidien : consulter un solde, envoyer un virement. Chaque opération sensible redéchiffre le coffre à la volée avec le mot de passe fourni ; rien n'est mis en cache en mémoire entre deux actions.
2. **Kit de sauvegarde Shamir 2-sur-3** — généré une seule fois à la création, indépendant du coffre local. L'entropie est découpée en 3 parts mathématiques (Shamir's Secret Sharing) ; 2 d'entre elles suffisent à tout reconstruire, mais **aucune part seule n'a de valeur**. Chaque part est elle-même chiffrée avec sa propre identité PGP et sa propre passphrase générée aléatoirement — donc distribuable sur 3 supports distincts (clé USB, coffre-fort, personne de confiance) sans qu'aucun d'eux, pris isolément, ne représente un risque.

```
Entropie maître (256 bits, générée une seule fois via le CSPRNG de l'OS)
│
├── Coffre local de l'appareil (1 mot de passe)
│   └── Usage quotidien : consulter un solde, dériver les adresses, signer un envoi
│
└── Kit de sauvegarde Shamir 2-sur-3 (généré une fois, indépendant du coffre)
    ├── Part A — chiffrée PGP, passphrase dédiée
    ├── Part B — chiffrée PGP, passphrase dédiée
    └── Part C — chiffrée PGP, passphrase dédiée
        └── 2 parts sur 3 (n'importe lesquelles) → reconstruction sur un nouvel appareil
```

Une seule primitive mathématique (l'entropie maître) protégée deux fois, pour deux usages différents — jamais de compromis entre "facile à utiliser au quotidien" et "sûr en cas de perte de l'appareil".

### Structure du code

```
core/     Worker cryptographique (Rust), indépendant de toute interface : Shamir, OpenPGP,
          dérivation multi-réseaux, construction et signature de transactions "from scratch"
          (pas de SDK lourd type rust-bitcoin/solana-sdk). Bibliothèque + binaires CLI de démo.
app/      Application de bureau Tauri v2.
  ├─ src-tauri/   Backend Rust : expose core/ au frontend via des commandes Tauri typées.
  └─ src/         Frontend web (HTML/CSS/JS vanilla, sans framework ni dépendance JS).
```

`core/` ne sait rien de Tauri ni d'une interface graphique — c'est délibéré : la même logique de dérivation/signature est réutilisable telle quelle sur une future cible mobile (iOS/Android), sans dupliquer le code sensible.

### Frontière de confiance frontend/backend

Le frontend web est traité comme **non fiable par principe**, même si c'est le seul code de ce projet qui s'exécute dans ce dépôt. Concrètement :

- Il ne reçoit jamais un secret (clé privée, entropie, mot de passe en retour) — seulement des adresses publiques, des soldes et des identifiants de transaction. Chaque commande Tauri qui traverse cette frontière est un point de passage explicite, jamais un accès direct au système de fichiers ou au réseau.
- Une CSP stricte (`connect-src 'self'`) empêche le frontend de contacter un serveur directement : tout appel réseau (prix, historique, diffusion de transaction) passe obligatoirement par le backend Rust.
- Avant tout envoi de fonds, une **boîte de dialogue native de l'OS** (pas une modale HTML) affiche réseau, destinataire, montant et frais, et exige une confirmation explicite. Un frontend compromis — dépendance JS piégée, faille XSS — ne peut ni la falsifier ni la contourner silencieusement, puisqu'elle n'est pas rendue par la webview.

## Développement

Prérequis : [Rust](https://rustup.rs/), [Node.js](https://nodejs.org/), et les [prérequis Tauri](https://tauri.app/start/prerequisites/) pour votre plateforme.

```bash
cd app
npm install
npm run tauri dev
```

Les binaires de démonstration du worker crypto (sans interface graphique) sont accessibles depuis `core/` :

```bash
cd core
cargo run --bin shamir_demo      # Découpage/reconstruction Shamir, isolé
cargo run --bin pgp_demo         # Chiffrement/déchiffrement PGP, isolé
cargo run --bin wallet_demo      # Dérivation + virement EVM (testnet)
```

## Sécurité

- Entropie maître générée via le CSPRNG de l'OS, jamais un générateur maison.
- Effacement mémoire (`zeroize`) et verrouillage anti-swap (`mlock`/`VirtualLock`) sur tout secret en clair.
- Coût de dérivation de clé (S2K) au maximum du format OpenPGP sur le mot de passe de l'appareil.
- Verrouillage anti-brute-force avec délai croissant sur toute commande qui redéchiffre le coffre.
- Aucune clé API tierce nécessaire ni stockée (CoinGecko, Blockscout, Esplora et les RPC publics utilisés sont tous accessibles sans authentification).

Aucun rapport d'audit externe n'existe encore pour ce projet — les protections ci-dessus sont le résultat de plusieurs rounds de relecture interne, pas d'une validation indépendante.
