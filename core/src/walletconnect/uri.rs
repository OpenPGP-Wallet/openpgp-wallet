//! WalletConnect v2 pairing link, pasted by the user from the dApp:
//! `wc:{topic}@2?relay-protocol=irn&symKey={key}&expiryTimestamp={unix}` (the
//! format of `formatUri`/`parseUri` in `packages/utils/src/uri.ts` of the official
//! SDK). Strict validation: a malformed link is rejected before any network access.

use anyhow::{anyhow, Context, Result};
use zeroize::Zeroizing;

pub struct PairingUri {
    pub topic: String,
    pub sym_key: Zeroizing<[u8; 32]>,
    /// Unix expiry timestamp announced by the dApp, if any.
    pub expiry: Option<u64>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn parse(uri: &str) -> Result<PairingUri> {
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("wc://")
        .or_else(|| uri.strip_prefix("wc:"))
        .ok_or_else(|| anyhow!("lien WalletConnect invalide : il doit commencer par « wc: »"))?;
    let (path, query) = rest.split_once('?').ok_or_else(|| anyhow!("lien WalletConnect incomplet (paramètres absents)"))?;
    let (topic, version) = path.split_once('@').ok_or_else(|| anyhow!("lien WalletConnect incomplet (version absente)"))?;
    let topic = topic.strip_prefix("//").unwrap_or(topic);
    anyhow::ensure!(version == "2", "lien WalletConnect version {version} : seule la version 2 est prise en charge");
    anyhow::ensure!(is_hex64(topic), "lien WalletConnect invalide (identifiant de canal)");

    let mut sym_key = None;
    let mut relay_protocol = None;
    let mut expiry = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name {
            "symKey" => sym_key = Some(value),
            "relay-protocol" => relay_protocol = Some(value),
            "expiryTimestamp" => expiry = Some(value.parse::<u64>().context("lien WalletConnect : expiration illisible")?),
            _ => {}
        }
    }
    let sym_key = sym_key.ok_or_else(|| anyhow!("lien WalletConnect incomplet (clé absente)"))?;
    anyhow::ensure!(is_hex64(sym_key), "lien WalletConnect invalide (clé)");
    anyhow::ensure!(
        relay_protocol.is_none_or(|p| p == "irn"),
        "lien WalletConnect : protocole de relais non pris en charge"
    );

    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(sym_key, key.as_mut_slice()).context("lien WalletConnect invalide (clé)")?;
    Ok(PairingUri { topic: topic.to_ascii_lowercase(), sym_key: key, expiry })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOPIC: &str = "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9";
    const KEY: &str = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303";

    #[test]
    fn parses_the_official_uri_format() {
        // The shape produced by `formatUri` (sorted parameters).
        let uri = format!("wc:{TOPIC}@2?expiryTimestamp=1705667684&relay-protocol=irn&symKey={KEY}");
        let parsed = parse(&uri).unwrap();
        assert_eq!(parsed.topic, TOPIC);
        assert_eq!(hex::encode(*parsed.sym_key), KEY);
        assert_eq!(parsed.expiry, Some(1_705_667_684));
        // "wc://" variant (Android), and the "methods" parameter is ignored.
        let uri = format!("wc://{TOPIC}@2?relay-protocol=irn&symKey={KEY}&methods=%5Bwc_sessionPropose%5D");
        assert!(parse(&uri).unwrap().expiry.is_none());
    }

    #[test]
    fn refuses_malformed_or_foreign_links() {
        for bad in [
            String::new(),
            format!("https://{TOPIC}@2?symKey={KEY}"),
            format!("wc:{TOPIC}@1?bridge=https%3A%2F%2Fx&key={KEY}"), // WalletConnect v1, discontinued
            format!("wc:{TOPIC}@2?relay-protocol=irn"),
            format!("wc:{TOPIC}@2?relay-protocol=waku&symKey={KEY}"),
            format!("wc:abc@2?relay-protocol=irn&symKey={KEY}"),
            format!("wc:{TOPIC}@2?symKey={}", &KEY[..63]),
            format!("wc:{TOPIC}@2?symKey={KEY}&expiryTimestamp=demain"),
            format!("wc:{TOPIC}"),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }
}
