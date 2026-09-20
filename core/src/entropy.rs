/// Génère 256 bits (32 octets) d'entropie cryptographiquement sûre.
/// Le buffer retourné doit être effacé explicitement après usage
/// (voir memory_guard::wipe).
pub fn generate_master_entropy() -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    getrandom::getrandom(&mut buf).expect("échec de la génération d'entropie sécurisée");
    buf
}
