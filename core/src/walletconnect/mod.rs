//! WalletConnect v2 (Reown), côté PORTEFEUILLE, implémenté en Rust : permet à
//! une dApp (site web) de demander des signatures à ce portefeuille, via un
//! relais chiffré de bout en bout. Choix de l'utilisateur plutôt que le SDK
//! JavaScript officiel : aucune dépendance npm dans la webview où le mot de
//! passe est saisi, CSP inchangée, et toute la cryptographie reste en Rust.
//!
//! Référence : le code du SDK officiel (monorepo `WalletConnect/walletconnect-
//! monorepo`, branche v2.0, et `walletconnect-utils`), lu directement plutôt
//! que supposé ; chaque primitive est vérifiée contre des vecteurs produits par
//! les bibliothèques mêmes de ce SDK.
//!
//! Aucune fonction de ce module ne signe quoi que ce soit : il transporte les
//! demandes des dApps et renvoie les réponses. Les signatures passent par
//! `api` (mot de passe exigé) et par la boîte de confirmation native.

pub mod auth;
pub mod crypto;
pub mod uri;
