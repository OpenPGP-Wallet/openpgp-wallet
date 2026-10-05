//! Adresse PRESQUE identique à une adresse connue (destinataire déjà payé,
//! contact du carnet, profil de ce portefeuille) : un caractère manquant, en
//! trop, différent, ou deux inversés — l'erreur de copie typique. Constaté le
//! 05/10/2026 : 1,18 USDC envoyés à l'adresse de l'utilisateur privée de son
//! premier caractère (encore une adresse Solana valide), malgré les
//! avertissements génériques « nouvelle adresse » / « jamais servi ».
//!
//! Deux adresses distinctes générées normalement ne sont jamais à deux
//! caractères près : à cette distance, c'est une faute de frappe ou de copie.

/// Distance retenue (au-delà : adresse sans rapport).
const MAX_DISTANCE: usize = 2;

/// Ce qui distingue l'adresse saisie de l'adresse connue (positions à partir
/// de 0, en caractères).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Difference {
    /// Caractère `expected` absent à `position`.
    Missing { position: usize, expected: char },
    /// Caractère `typed` en trop à `position`.
    Extra { position: usize, typed: char },
    /// `typed` au lieu de `expected` à `position`.
    Changed { position: usize, typed: char, expected: char },
    /// Caractères `position` et `position + 1` inversés.
    Swapped { position: usize },
    /// Deux caractères diffèrent.
    Two,
}

/// Forme de comparaison : hex EVM et bech32 sont insensibles à la casse
/// (même adresse), base58 y est SENSIBLE (autre adresse).
fn normalize(address: &str) -> Vec<char> {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("0x") || lower.starts_with("bc1") || lower.starts_with("tb1") {
        lower.chars().collect()
    } else {
        trimmed.chars().collect()
    }
}

/// Distance d'édition avec inversion de deux voisins (« optimal string
/// alignment ») ; `None` au-delà de `MAX_DISTANCE`.
fn distance(a: &[char], b: &[char]) -> Option<usize> {
    if a.len().abs_diff(b.len()) > MAX_DISTANCE {
        return None;
    }
    let width = b.len() + 1;
    let mut d = vec![0usize; (a.len() + 1) * width];
    for i in 0..=a.len() {
        d[i * width] = i;
    }
    for (j, cell) in d.iter_mut().enumerate().take(width) {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[(i - 1) * width + j] + 1).min(d[i * width + j - 1] + 1).min(d[(i - 1) * width + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[(i - 2) * width + j - 2] + 1);
            }
            d[i * width + j] = best;
        }
    }
    let result = d[a.len() * width + b.len()];
    (result <= MAX_DISTANCE).then_some(result)
}

fn describe(typed: &[char], known: &[char], distance: usize) -> Difference {
    if distance != 1 {
        return Difference::Two;
    }
    let first = typed.iter().zip(known).position(|(t, k)| t != k).unwrap_or(typed.len().min(known.len()));
    match typed.len().cmp(&known.len()) {
        std::cmp::Ordering::Less => Difference::Missing { position: first, expected: known[first] },
        std::cmp::Ordering::Greater => Difference::Extra { position: first, typed: typed[first] },
        std::cmp::Ordering::Equal if typed.get(first + 1) == known.get(first) && typed.get(first) == known.get(first + 1) && typed[first + 2..] == known[first + 2..] => {
            Difference::Swapped { position: first }
        }
        std::cmp::Ordering::Equal => Difference::Changed { position: first, typed: typed[first], expected: known[first] },
    }
}

/// Format de `address` pour `network` (mêmes parseurs que le reste de
/// l'app) : l'aperçu de l'envoi n'avertit que pour une adresse valide.
pub fn validate(network: &str, address: &str) -> anyhow::Result<()> {
    crate::external_wallets::validate_address(network, address)
}

/// Adresse de `known` la plus proche de `typed` parmi les presque
/// identiques (à égalité, la première : ordre de priorité de l'appelant),
/// avec la différence. Jamais identique : `None` si `typed` est l'une d'elles.
pub fn near_miss<'a>(known: impl IntoIterator<Item = &'a str>, typed: &str) -> Option<(&'a str, Difference)> {
    let typed_chars = normalize(typed);
    if typed_chars.is_empty() {
        return None;
    }
    let known: Vec<(&str, Vec<char>)> = known.into_iter().map(|k| (k, normalize(k))).collect();
    if known.iter().any(|(_, k)| *k == typed_chars) {
        return None;
    }
    let (address, chars, d) = known
        .into_iter()
        .filter_map(|(address, chars)| distance(&typed_chars, &chars).map(|d| (address, chars, d)))
        .min_by_key(|(_, _, d)| *d)?;
    Some((address, describe(&typed_chars, &chars, d)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "F1YBYFJWBteTwi5eS5BjdSy3xDGGv8bhHBJ54n78nzdc";

    /// Le cas réel du 05/10/2026 : premier caractère oublié.
    #[test]
    fn the_real_missing_first_character_is_caught() {
        let typed = "1YBYFJWBteTwi5eS5BjdSy3xDGGv8bhHBJ54n78nzdc";
        assert_eq!(near_miss([USER], typed), Some((USER, Difference::Missing { position: 0, expected: 'F' })));
    }

    #[test]
    fn each_kind_of_slip_is_described() {
        let last = USER.len() - 1;
        assert_eq!(near_miss([USER], &USER[..last]).unwrap().1, Difference::Missing { position: last, expected: 'c' });
        assert_eq!(near_miss([USER], &format!("{USER}c")).unwrap().1, Difference::Extra { position: last + 1, typed: 'c' });
        assert_eq!(near_miss([USER], &USER.replacen("YBYF", "YBZF", 1)).unwrap().1, Difference::Changed { position: 4, typed: 'Z', expected: 'Y' });
        assert_eq!(near_miss([USER], &USER.replacen("1Y", "Y1", 1)).unwrap().1, Difference::Swapped { position: 1 });
        assert_eq!(near_miss([USER], &format!("{}x", &USER[..last])).unwrap().1, Difference::Changed { position: last, typed: 'x', expected: 'c' });
        assert_eq!(near_miss([USER], &format!("{}cd", &USER[..last - 1])).unwrap().1, Difference::Swapped { position: last - 1 });
        assert_eq!(near_miss([USER], &USER[2..]).unwrap().1, Difference::Two);
        // Base58 : la casse compte (une autre adresse, à un caractère près).
        assert_eq!(near_miss([USER], &USER.replacen('F', "f", 1)).unwrap().1, Difference::Changed { position: 0, typed: 'f', expected: 'F' });
    }

    /// Identique (aux espaces près, ou à la casse près en hex/bech32) : rien ;
    /// sans rapport : rien.
    #[test]
    fn same_or_unrelated_addresses_are_not_flagged() {
        assert_eq!(near_miss([USER], &format!(" {USER} ")), None);
        let evm = "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3";
        assert_eq!(near_miss([evm], &evm.to_ascii_lowercase()), None);
        assert_eq!(near_miss([USER], "4PUcVV4Ax8jXHXsGaRZfh69oRkeRGJyGZbDBPFUD2okm"), None);
        assert_eq!(near_miss([USER], &USER[3..]), None, "trois caractères de moins : au-delà");
        assert_eq!(near_miss([USER], ""), None);
        // Une adresse identique à une autre connue l'emporte.
        assert_eq!(near_miss([USER, &USER[1..]], &USER[1..]), None);
    }

    /// La plus proche l'emporte, pas la première : constaté en vrai, la faute
    /// déjà payée (« 1YBY… », à deux caractères) passait avant l'adresse
    /// exacte (à un caractère).
    #[test]
    fn the_closest_known_address_wins() {
        let slip = &USER[1..];
        let typed = format!("{}d", &USER[..USER.len() - 1]);
        assert_eq!(near_miss([slip, USER], &typed), Some((USER, Difference::Changed { position: USER.len() - 1, typed: 'd', expected: 'c' })));
    }

    #[test]
    fn evm_comparison_ignores_case() {
        let evm = "0x34deb5AF3e37BD0495dDc1bb1C53c14d7CE064c3";
        let typed = "0x34deb5af3e37bd0495ddc1bb1c53c14d7ce064c";
        assert_eq!(near_miss([evm], typed).unwrap().1, Difference::Missing { position: 41, expected: '3' });
    }
}
