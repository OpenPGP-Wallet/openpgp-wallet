# Modèle de menace — OpenPGP Wallet (application Windows)

Document de travail, à jour au 04/10/2026 (v2.9.0 et commits suivants). Il structure le modèle informel de
`ETAPES.md` (« Modèle de menace : malware actif vs vol de fichier hors ligne ») en vue d'un audit professionnel :
ce que l'on protège, contre qui, par quels moyens, et ce qui reste à risque. Chaque contre-mesure renvoie au code
qui la met en œuvre. **Aucune de ces protections n'a encore été vérifiée par un auditeur indépendant.**

## 1. Périmètre

- Application de bureau Tauri v2 pour Windows : cœur Rust (`core/`), pont de commandes (`app/src-tauri`),
  interface web locale (`app/src`).
- Portefeuille non dépositaire multi-réseaux : Bitcoin, réseaux EVM (Ethereum, L2, BNB Chain, Avalanche,
  Polygon, HyperEVM), Solana, Zcash (transparent et protégé Orchard), Monero, Dogecoin, jetons du registre
  (`tokens.rs`).
- Hors périmètre : la version iOS (non démarrée), les services tiers eux-mêmes (nœuds, agrégateurs d'échange),
  le système d'exploitation et le matériel.

## 2. Actifs

| Actif | Où il vit | Conséquence d'une fuite |
|---|---|---|
| Entropie maîtresse (seed HD) | Coffre local chiffré `device_vault.asc` ; en clair seulement le temps d'une opération, en mémoire verrouillée | Perte totale des fonds de tous les réseaux et profils |
| Clé privée PGP de l'appareil | Coffre Windows (Credential Manager), repli fichier chiffré | Avec le mot de passe : accès au coffre local |
| Mot de passe de l'appareil | Tête de l'utilisateur ; jamais stocké | Avec la clé de l'appareil : accès au coffre |
| Kit de sauvegarde Shamir (3 parts, 2 suffisent) | Fichiers ou clés USB de l'utilisateur, chaque part chiffrée PGP par sa propre phrase de passe | 2 parts + leurs phrases : perte totale |
| Clés dérivées (signature) | Dérivées à la volée de la seed, effacées après usage | Perte des fonds du réseau concerné |
| Clés de visualisation Zcash (UFVK) et Monero (clé privée de vue) | Mémoire du processus après déverrouillage ; UFVK aussi dans `zcash_shielded.sqlite` | Confidentialité : historique et soldes protégés visibles, aucun fonds perdu |
| État local des cryptos privées | `zcash_shielded.sqlite`, `monero_wallet.json` | Confidentialité seulement |
| Données de confort | Profils, carnet d'adresses, destinataires déjà payés, clé Etherscan, nœud Monero | Confidentialité (adresses, habitudes) |
| Intégrité de ce qui est signé | Chaîne de construction des transactions | Fonds envoyés ailleurs que voulu |

## 3. Frontières de confiance

1. **Interface web ↔ cœur Rust** : l'interface est traitée comme non fiable. Elle ne reçoit que des données
   publiques (adresses, soldes, identifiants de transaction) ; tout ce qui est signé est recalculé et confirmé
   côté Rust (`app/src-tauri/src/lib.rs`).
2. **Processus ↔ système d'exploitation** : coffre Windows, Windows Hello, boîtes de dialogue natives.
3. **Application ↔ réseau** : nœuds publics, indexeurs, agrégateurs d'échange, WalletConnect.
4. **Application ↔ appareils matériels** : Ledger, Trezor (USB).
5. **Application ↔ utilisateur** : ce qu'il voit et confirme (boîte native), ce qu'il saisit.

## 4. Attaquants

| Code | Attaquant | Capacités supposées |
|---|---|---|
| A1 | Voleur hors ligne | Copie du disque ou du dossier de données, sans session ouverte |
| A2 | Logiciel malveillant dans la session | Lit l'écran, le presse-papiers, les frappes ; peut lire la mémoire du processus |
| A3 | Service réseau malveillant ou compromis | Nœud, indexeur, agrégateur d'échange, relais : réponses fausses, transactions piégées |
| A4 | Application tierce malveillante (dApp) | Demandes de signature via WalletConnect |
| A5 | Attaquant réseau (MITM) | Intercepte ou modifie le trafic non chiffré |
| A6 | Chaîne d'approvisionnement | Dépendance compromise, binaire falsifié en téléchargement |
| A7 | Ingénierie sociale | Faux support, fausse mise à jour, demande des fichiers de sauvegarde |
| A8 | Contenu injecté dans l'interface | Texte malveillant dans une réponse réseau affichée (XSS) |

## 5. Menaces et contre-mesures

### 5.1 Vol hors ligne (A1)
- **Coffre chiffré** par l'identité PGP de l'appareil (sequoia-openpgp, backend `crypto-cng`) ; la clé privée
  de l'appareil est chiffrée par le mot de passe (S2K) et rangée dans le coffre Windows
  (`core/src/secure_storage.rs`). Un disque copié ne contient pas de seed en clair.
- **Mot de passe fort** exigé à la création (12 caractères minimum, indicateur de force).
- **Limitation des essais** de déverrouillage : 5 essais libres, puis attente croissante de 5 s à 300 s, état
  persistant (`api::enforce_unlock_lockout`).
- **Changement de portefeuille sur l'appareil** (réinitialisation, restauration) : l'état propre à l'ancienne
  seed (base Zcash protégée, état Monero, destinataires déjà payés) est supprimé, et au déverrouillage les
  comptes Zcash d'une autre empreinte de seed et l'état Monero d'une autre clé sont écartés avant tout affichage.
- **Kit Shamir 2-sur-3** : une part seule ne révèle rien ; chaque part a sa propre phrase de passe ; deux parts
  refusées sur une même clé USB (`usb_backup.rs`).
- *Risque résiduel* : un mot de passe faible reste attaquable par force brute hors ligne si la clé privée de
  l'appareil est extraite du coffre Windows (même session utilisateur) ; confidentialité des fichiers d'état
  (Zcash protégé, Monero, carnet d'adresses), qui ne sont pas chiffrés.

### 5.2 Logiciel malveillant dans la session (A2)
- **Seed jamais gardée** : redéchiffrée pour chaque opération sensible (envoi, inscription, régénération du kit),
  puis effacée (`zeroize`) ; mémoire verrouillée contre l'écriture sur disque (`memory_guard::lock`,
  `VirtualLock`).
- **Verrouillage automatique** après 10 minutes d'inactivité (interface) ; les clés de visualisation et les
  caches d'adresses sont vidés au verrouillage.
- **Boîte de confirmation native** (OS, pas HTML) affichant le destinataire, le montant et les frais exacts qui
  seront signés ; avertissements d'adresse jamais payée, d'adresse ressemblante à une adresse déjà utilisée
  (`lookalike_warning`) et d'adresse jamais utilisée sur la chaîne.
- **Windows Hello** possible à la place du mot de passe pour le déverrouillage (pas de frappe à capturer).
- **Portefeuilles matériels** (Ledger, Trezor) : la clé ne quitte jamais l'appareil, revue à l'écran.
- **Solde vérifié avant la boîte de confirmation** pour tous les envois du portefeuille (Bitcoin compris depuis
  la v2.10) : un envoi impossible n'est jamais présenté à la confirmation.
- **Délai d'annulation de 5 s** après la boîte native, avant toute signature, imposé côté Rust
  (`send_grace_period`) : l'interface peut seulement l'écourter ou annuler ; la seed n'est déverrouillée
  qu'après ; un verrouillage annule les envois en attente.
- **Destinataire reconnu** : quand l'adresse est celle d'un autre profil du portefeuille (adresses dérivées au
  déverrouillage, jamais fournies par l'interface), la boîte native nomme ce profil.
- **« Max »** recalculé côté Rust au moment de la boîte (solde moins les frais du moment), affiché « maximum,
  frais déduits » puis signé tel quel : un drapeau falsifié par l'interface ne change que le montant montré.
- *Risque résiduel* : un malware capable de lire la mémoire au moment d'une signature, ou de capturer le mot de
  passe, obtient la seed ; un remplacement d'adresse dans le presse-papiers n'est détecté que s'il ressemble à
  une adresse déjà payée. Aucun portefeuille logiciel ne protège totalement contre A2 (raison d'être des
  portefeuilles matériels).

### 5.3 Services réseau malveillants (A3) et attaquant réseau (A5)
- **Tout en HTTPS** (nœuds, indexeurs, agrégateurs) ; nœud Monero en `http://` accepté seulement sur la machine
  ou le réseau local (`monero::normalize_node`).
- **Transactions construites et signées localement** à partir de champs vérifiés : identifiant de chaîne EVM fixé
  par l'app, nonce `pending`, prix du gas affiché puis signé tel quel, plafonds de frais (Monero : 400 000
  piconeros par unité de poids ; Zcash : frais ZIP-317 jamais supérieurs à ceux affichés).
- **Garde de version du réseau** : Zcash (branche de consensus comparée au serveur), Monero (mise à niveau 16
  attendue) ; envoi refusé si le réseau a évolué au-delà de ce que la bibliothèque connaît.
- **Échanges** :
  - THORChain/Maya : memo relu et vérifié (actif, adresse de destination à soi, minimum de sortie, nom
    d'affiliation seulement s'il est vérifié sur le réseau) avant signature (`thorchain_rpc::verify_memo`) ;
  - LI.FI : seules les routes dont le destinataire est vérifiable sont gardées ; transaction Bitcoin préparée
    par LI.FI vérifiée sortie par sortie (fonds de l'utilisateur seulement, un seul dépôt, monnaie rendue à
    soi, frais bornés — `lifi.rs`) ;
  - CoW, Jupiter : ordre et transaction relus avant signature (`cow.rs`, `jupiter_rpc.rs`) ;
  - SwapKit (NEAR Intents, Chainflip) : le dépôt ouvert par SwapKit est confirmé par l'API officielle du
    fournisseur, indépendante de SwapKit (adresse de dépôt, cryptos, montant, arrivée et remboursement sur les
    adresses de l'utilisateur, minimum, échéance, commissions bornées) ; le dépôt est un virement construit et
    signé par l'app (`swapkit.rs`). Risque résiduel : compromission simultanée de SwapKit et du fournisseur ;
    une fois déposés, les fonds dépendent de l'exécution par le fournisseur (remboursement prévu sinon).
- **Monero** : blocs analysés localement (le nœud ne sait pas quelles sorties sont à soi) ; la sélection des
  leurres refuse un nœud qui ment sur la sortie dépensée ; réorganisations détectées.
- **Zcash protégé** : blocs compacts déchiffrés localement (lightwalletd ne voit que des demandes de blocs).
- **Dogecoin** : la signature historique (sans SegWit) n'engage pas le montant des entrées — un service qui
  mentirait sur la valeur d'une sortie ferait partir la différence en frais. Chaque entrée est relue dans sa
  transaction d'origine brute, dont le hash recalculé doit égaler l'identifiant : montant et script vérifiés
  avant signature (`doge::verify_inputs`) ; frais bornés (0,01 à 5 DOGE/ko), affichés puis jamais dépassés.
- *Risques résiduels* : un nœud malveillant peut afficher de faux soldes ou un faux historique (portefeuille
  léger) ; un nœud Monero ou Zcash malveillant peut affaiblir la confidentialité d'un envoi ; les nœuds publics
  voient l'adresse IP et les adresses interrogées ; un agrégateur peut proposer un mauvais cours (le minimum de
  sortie affiché borne la perte, sans garantir le meilleur prix).

### 5.4 Applications tierces via WalletConnect (A4)
- Demandes préparées côté Rust (`dapp_requests::prepare`) : méthodes et réseaux pris en charge seulement,
  transaction décodée et affichée dans la boîte native avant toute signature ; l'interface ne fait que relayer.
- *Risque résiduel* : la signature de messages arbitraires (connexion à une dApp) reste possible après
  confirmation — l'utilisateur doit comprendre ce qu'il signe ; signature de transactions via WalletConnect non
  testée en conditions réelles.

### 5.5 Chaîne d'approvisionnement (A6)
- `cargo audit` et `npm audit` à chaque version (0 vulnérabilité à la v2.9.0 ; avertissements « non maintenu »
  sur des dépendances transitives) ; bibliothèques reconnues pour la cryptographie (sequoia-openpgp,
  librustzcash, monero-oxide, k256, ed25519-dalek).
- Empreintes SHA-256 des binaires publiées avec chaque version.
- *Risques résiduels* : **binaire non signé** (Authenticode) — rien ne prouve son origine, et SmartScreen
  l'avertit ; compilation non reproductible ; pas de mise à jour automatique vérifiée (téléchargement manuel).

### 5.6 Ingénierie sociale (A7)
- L'utilisateur ne voit jamais de phrase de récupération ; les phrases de passe du kit sont affichées une fois,
  pour être rangées hors ligne.
- Rappel affiché avec le kit : personne ne demandera jamais les parts ni leurs phrases de passe.
- *Risque résiduel* : un utilisateur qui remet malgré tout deux parts et leurs phrases à un faux support perd
  ses fonds.

### 5.7 Contenu injecté dans l'interface (A8)
- **CSP stricte** (`tauri.conf.json`) et permissions Tauri minimales (`core:default` seul) : pas d'accès fichiers
  ni shell depuis l'interface.
- Textes venant du réseau insérés en `textContent`, jamais en `innerHTML` (messages d'erreur, historiques).
- Liens externes limités à une liste blanche ouverte côté Rust (`open_external_link`).
- *Risque résiduel* : une faille dans WebView2 ou dans Tauri contournerait ces protections ; même alors,
  l'interface n'a accès à aucun secret ni à aucune signature sans la boîte native.

## 6. Hypothèses
- Le système d'exploitation n'est pas compromis au niveau noyau ; le coffre Windows et Windows Hello font ce
  qu'ils annoncent.
- Les bibliothèques cryptographiques utilisées sont correctes.
- L'utilisateur lit la boîte de confirmation native avant de valider.
- Les parts du kit de sauvegarde sont rangées dans des endroits distincts.

## 7. Points ouverts (avant toute confiance publique)
1. Signature de code Authenticode du binaire (achat d'un certificat par le porteur du projet).
2. Audit de sécurité par un prestataire indépendant.
3. Chiffrement des fichiers d'état locaux (Zcash protégé, Monero, carnet d'adresses) par une clé dérivée du
   coffre, pour la confidentialité face à A1.
4. Tests en conditions réelles : dépenses Monero et Zcash protégé, échanges depuis BTC/ZEC, restauration depuis
   clé USB, Ledger/Trezor sur de vrais appareils, signatures WalletConnect.
5. Compilation reproductible et vérification des mises à jour.
