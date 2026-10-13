/// Generates 256 bits (32 bytes) of cryptographically secure entropy. The caller
/// must wipe the returned buffer once done with it (see memory_guard::wipe).
pub fn generate_master_entropy() -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    getrandom::getrandom(&mut buf).expect("échec de la génération d'entropie sécurisée");
    buf
}
