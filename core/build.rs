//! Clés de partenaires (SwapKit, MoonPay Trade, NodeReal) lues À LA COMPILATION dans
//! `partner-keys.env`, à la racine du dépôt (ignoré par git), ou à défaut dans
//! l'environnement : jamais dans le code ni dans l'historique. Clé absente :
//! le fournisseur correspondant n'est simplement pas proposé.

const KEYS: &[&str] = &["SWAPKIT_API_KEY", "MOONPAY_TRADE_API_KEY", "NODEREAL_API_KEY"];

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR fourni par cargo");
    let file = std::path::Path::new(&manifest).join("..").join("partner-keys.env");
    println!("cargo:rerun-if-changed={}", file.display());
    let contents = std::fs::read_to_string(&file).unwrap_or_default();
    for key in KEYS {
        println!("cargo:rerun-if-env-changed={key}");
        let from_file = contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_once('='))
            .find(|(name, _)| name.trim() == *key)
            .map(|(_, value)| value.trim().trim_matches('"').to_string());
        // Une clé d'API : caractères visibles seulement (rien qui casse une
        // en-tête HTTP).
        let value = from_file.or_else(|| std::env::var(key).ok()).filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_graphic()));
        if let Some(value) = value {
            println!("cargo:rustc-env={key}={value}");
        }
    }
}
