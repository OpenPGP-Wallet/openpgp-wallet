use zeroize::Zeroize;

/// Efface explicitement un buffer sensible en mémoire (écrase avec des zéros
/// de façon à ce que le compilateur n'optimise pas l'opération).
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Verrouille les pages mémoire d'un buffer sensible contre le swap disque
/// (`mlock` sur Unix, `VirtualLock` sur Windows, via la crate `region`).
/// Retourne un guard qui déverrouille automatiquement à sa destruction — à
/// garder en vie (ne pas `drop` ni laisser sortir de portée) tant que le
/// buffer contient un secret, puis appeler [`wipe`] avant ou pendant qu'il
/// se libère.
///
/// ATTENTION : le buffer verrouillé ne doit plus être réalloué (`resize`,
/// `push` au-delà de sa capacité, `clone`...) tant que le guard est actif :
/// l'adresse verrouillée deviendrait obsolète et le nouveau buffer ne serait
/// plus protégé. Utiliser sur un buffer déjà à sa taille finale.
///
/// Best-effort : si le verrouillage échoue (limite système, permissions —
/// possible en conteneur ou avec `ulimit -l` bas), un avertissement est
/// affiché mais l'appelant continue sans bloquer. `zeroize` reste la garantie
/// principale d'effacement ; `lock` n'est qu'une couche défensive en plus.
#[must_use = "le verrouillage se termine dès que le guard est abandonné"]
pub fn lock(buf: &[u8]) -> Option<region::LockGuard> {
    if buf.is_empty() {
        return None;
    }
    match region::lock(buf.as_ptr(), buf.len()) {
        Ok(guard) => Some(guard),
        Err(e) => {
            eprintln!("avertissement : verrouillage mémoire (mlock) impossible : {e}");
            None
        }
    }
}
