//! Portefeuilles matériels Ledger : la clé privée ne quitte JAMAIS l'appareil,
//! qui affiche lui-même ce qu'il signe (destinataire, montant) et exige une
//! confirmation physique. Cette app ne fait que construire les transactions,
//! les transmettre à l'appareil et diffuser le résultat signé.
//!
//! Protocole : commandes APDU (ISO 7816) propres à chaque application Ledger
//! (Ethereum, Solana, Bitcoin), transportées en USB HID (appareil réel) ou en
//! TCP (émulateur officiel Speculos, pour les tests). Détails repris du code
//! officiel de Ledger (ledgerjs `hid-framing`, `hw-app-eth`, spécifications
//! `doc/apdu.md` des applications, `speculos/mcu/apdu.py`), lus directement ;
//! vérifiés contre des vecteurs produits par ce code officiel et contre les
//! vraies applications Ledger exécutées dans l'émulateur.

pub mod eth;
pub mod solana;

use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Identifiant USB des appareils Ledger.
pub const LEDGER_VENDOR_ID: u16 = 0x2c97;
/// Page d'usage HID de l'interface APDU (les autres interfaces servent à U2F/FIDO).
const LEDGER_USAGE_PAGE: u16 = 0xffa0;
const HID_PACKET_SIZE: usize = 64;
const HID_TAG: u8 = 0x05;

/// Canal de transport vers un appareil (réel ou émulé) : envoie une APDU
/// complète, renvoie la réponse complète (données + mot d'état sur 2 octets).
pub trait Transport {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
}

// --- Cadrage USB HID (ledgerjs `hid-framing`) ---------------------------------

/// Découpe une APDU en paquets HID de 64 octets : en-tête canal (2) | 0x05 |
/// numéro de séquence (2), longueur totale (2) dans le premier paquet seulement,
/// bourrage à zéro.
pub fn hid_frames(channel: u16, apdu: &[u8]) -> Vec<[u8; HID_PACKET_SIZE]> {
    let mut data = (apdu.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(apdu);
    let block = HID_PACKET_SIZE - 5;
    data.chunks(block)
        .enumerate()
        .map(|(i, chunk)| {
            let mut frame = [0u8; HID_PACKET_SIZE];
            frame[..2].copy_from_slice(&channel.to_be_bytes());
            frame[2] = HID_TAG;
            frame[3..5].copy_from_slice(&(i as u16).to_be_bytes());
            frame[5..5 + chunk.len()].copy_from_slice(chunk);
            frame
        })
        .collect()
}

/// Réassemble une réponse à partir des paquets reçus, en vérifiant canal,
/// étiquette et ordre des séquences (tout écart = erreur, jamais de données
/// mélangées avec celles d'un autre échange).
pub struct HidReassembler {
    channel: u16,
    expected: Option<usize>,
    sequence: u16,
    data: Vec<u8>,
}

impl HidReassembler {
    pub fn new(channel: u16) -> Self {
        Self { channel, expected: None, sequence: 0, data: Vec::new() }
    }

    /// Ajoute un paquet ; renvoie la réponse quand elle est complète.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        anyhow::ensure!(frame.len() >= 7, "paquet USB Ledger trop court");
        anyhow::ensure!(u16::from_be_bytes([frame[0], frame[1]]) == self.channel, "paquet USB Ledger d'un autre canal");
        anyhow::ensure!(frame[2] == HID_TAG, "paquet USB Ledger d'un type inattendu");
        anyhow::ensure!(u16::from_be_bytes([frame[3], frame[4]]) == self.sequence, "paquet USB Ledger hors séquence");
        let payload = if self.expected.is_none() {
            self.expected = Some(u16::from_be_bytes([frame[5], frame[6]]) as usize);
            &frame[7..]
        } else {
            &frame[5..]
        };
        self.sequence = self.sequence.wrapping_add(1);
        self.data.extend_from_slice(payload);
        let expected = self.expected.expect("défini au premier paquet");
        if self.data.len() >= expected {
            self.data.truncate(expected);
            return Ok(Some(std::mem::take(&mut self.data)));
        }
        Ok(None)
    }
}

/// Appareil Ledger réel branché en USB.
pub struct HidTransport {
    device: hidapi::HidDevice,
    channel: u16,
}

impl HidTransport {
    /// Premier appareil Ledger trouvé (interface APDU).
    pub fn open_first() -> Result<Self> {
        let api = hidapi::HidApi::new().context("accès USB (HID) impossible")?;
        let info = api
            .device_list()
            .find(|d| d.vendor_id() == LEDGER_VENDOR_ID && (d.usage_page() == LEDGER_USAGE_PAGE || d.interface_number() == 0))
            .ok_or_else(|| anyhow!("aucun Ledger détecté : branchez-le, déverrouillez-le et ouvrez l'application du réseau"))?;
        let device = info.open_device(&api).context("ouverture du Ledger impossible (déjà utilisé par une autre application ?)")?;
        let mut channel = [0u8; 2];
        getrandom::getrandom(&mut channel).map_err(|e| anyhow!("génération d'aléa impossible : {e}"))?;
        Ok(Self { device, channel: u16::from_be_bytes(channel) })
    }
}

impl Transport for HidTransport {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        for frame in hid_frames(self.channel, apdu) {
            // Octet d'identifiant de rapport (0) exigé devant chaque écriture HID.
            let mut report = vec![0u8];
            report.extend_from_slice(&frame);
            self.device.write(&report).context("écriture USB vers le Ledger impossible")?;
        }
        let mut reassembler = HidReassembler::new(self.channel);
        loop {
            let mut frame = [0u8; HID_PACKET_SIZE];
            // Pas de délai maximal : l'appareil attend la confirmation physique
            // de l'utilisateur, qui peut prendre le temps qu'il faut.
            let n = self.device.read(&mut frame).context("lecture USB depuis le Ledger impossible")?;
            if let Some(response) = reassembler.push(&frame[..n])? {
                return Ok(response);
            }
        }
    }
}

/// Émulateur officiel Speculos (tests) : APDU préfixée de sa longueur sur 4
/// octets ; réponse = longueur des données sur 4 octets, données, puis mot
/// d'état sur 2 octets (`speculos/mcu/apdu.py`).
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn connect(address: &str) -> Result<Self> {
        let stream = TcpStream::connect(address).with_context(|| format!("émulateur Ledger injoignable ({address})"))?;
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        Ok(Self { stream })
    }
}

impl Transport for TcpTransport {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut request = (apdu.len() as u32).to_be_bytes().to_vec();
        request.extend_from_slice(apdu);
        self.stream.write_all(&request)?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len)?;
        let mut response = vec![0u8; u32::from_be_bytes(len) as usize + 2];
        self.stream.read_exact(&mut response)?;
        Ok(response)
    }
}

// --- APDU ---------------------------------------------------------------------

/// Mots d'état Ledger, traduits en messages compréhensibles.
pub(crate) fn status_error(sw: u16) -> anyhow::Error {
    let message = match sw {
        0x6985 | 0x5501 => "opération refusée sur le Ledger",
        0x5515 | 0x6982 => "Ledger verrouillé : saisissez votre code PIN sur l'appareil",
        0x6d00 | 0x6e00 | 0x6e01 | 0x6511 => "application non ouverte sur le Ledger : ouvrez l'application du réseau concerné",
        0x6a80 => "données refusées par le Ledger (option « signature à l'aveugle » désactivée, ou transaction non prise en charge)",
        0x6a84 | 0x6a85 => "Ledger : mémoire insuffisante pour cette opération",
        0x6b00 | 0x6a86 => "Ledger : paramètre de commande refusé (version d'application trop ancienne ?)",
        0x6700 => "Ledger : longueur de commande incorrecte",
        _ => return anyhow!("le Ledger a renvoyé l'erreur 0x{sw:04x}"),
    };
    anyhow!("{message} (0x{sw:04x})")
}

/// Envoie une commande ; renvoie les données et le mot d'état, sans
/// interprétation (certaines applications donnent un sens propre à un mot
/// d'état : 0x6982 = refus de l'utilisateur pour Solana, par exemple).
pub fn send_raw(transport: &mut dyn Transport, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<(Vec<u8>, u16)> {
    anyhow::ensure!(data.len() <= 255, "commande Ledger trop longue ({} octets)", data.len());
    let mut apdu = vec![cla, ins, p1, p2, data.len() as u8];
    apdu.extend_from_slice(data);
    let mut response = transport.exchange(&apdu)?;
    anyhow::ensure!(response.len() >= 2, "réponse du Ledger trop courte");
    let sw = u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
    response.truncate(response.len() - 2);
    Ok((response, sw))
}

/// Envoie une commande et renvoie les données de réponse (mot d'état 0x9000
/// exigé, tout autre mot d'état devient une erreur explicite).
pub fn send(transport: &mut dyn Transport, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
    let (response, sw) = send_raw(transport, cla, ins, p1, p2, data)?;
    if sw != 0x9000 {
        return Err(status_error(sw));
    }
    Ok(response)
}

/// Chemin de dérivation BIP32 au format des applications Ledger : nombre
/// d'indices (1 octet) puis chaque indice sur 4 octets gros-boutistes (bit de
/// poids fort = indice durci).
pub fn encode_path(path: &[u32]) -> Result<Vec<u8>> {
    anyhow::ensure!(!path.is_empty() && path.len() <= 10, "chemin de dérivation invalide (1 à 10 niveaux)");
    let mut out = vec![path.len() as u8];
    for index in path {
        out.extend_from_slice(&index.to_be_bytes());
    }
    Ok(out)
}

pub const HARDENED: u32 = 0x8000_0000;

/// "44'/60'/0'/0/0" -> indices.
pub fn parse_path(path: &str) -> Result<Vec<u32>> {
    path.trim_start_matches("m/")
        .split('/')
        .map(|part| {
            let (digits, hardened) = match part.strip_suffix('\'').or_else(|| part.strip_suffix('h')) {
                Some(d) => (d, true),
                None => (part, false),
            };
            let index: u32 = digits.parse().map_err(|_| anyhow!("chemin de dérivation invalide : {path}"))?;
            if index >= HARDENED {
                bail!("chemin de dérivation invalide : {path}");
            }
            Ok(if hardened { index | HARDENED } else { index })
        })
        .collect()
}

/// Pilotage de l'émulateur Speculos pendant les tests (API REST : écran,
/// boutons) — l'équivalent automatisé des pressions de bouton de l'utilisateur.
#[cfg(test)]
pub(crate) mod speculos {
    pub const APDU: &str = "127.0.0.1:9999";
    const API: &str = "http://127.0.0.1:5000";
    /// Graine de test PUBLIQUE, par défaut dans Speculos (`speculos/main.py`).
    pub const TEST_MNEMONIC: &str = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";

    pub fn screen() -> Vec<String> {
        let events: serde_json::Value = reqwest::blocking::get(format!("{API}/events?currentscreenonly=true")).unwrap().json().unwrap();
        events["events"].as_array().unwrap().iter().filter_map(|e| e["text"].as_str().map(str::to_string)).collect()
    }

    pub fn press(button: &str) {
        reqwest::blocking::Client::new()
            .post(format!("{API}/button/{button}"))
            .json(&serde_json::json!({"action": "press-and-release"}))
            .send()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    /// Revient à l'écran d'accueil de l'application (ferme un avertissement
    /// affiché après un refus, comme "Blind signing must be enabled").
    pub fn back_to_home() {
        for _ in 0..10 {
            let joined = screen().join(" ");
            if joined.contains("is ready") {
                return;
            }
            press("both");
        }
        panic!("écran d'accueil introuvable : {:?}", screen());
    }

    /// Règle l'option "Blind signing" de l'application Ethereum (menu App
    /// settings, première entrée), comme le ferait l'utilisateur à la main.
    pub fn set_blind_signing(enabled: bool) {
        back_to_home();
        press("right");
        assert!(screen().join(" ").contains("App settings"), "menu inattendu : {:?}", screen());
        press("both");
        let state = screen().join(" ");
        assert!(state.contains("Blind signing"), "réglage inattendu : {state}");
        if state.contains("Enabled") != enabled {
            press("both");
        }
        assert_eq!(screen().join(" ").contains("Enabled"), enabled);
        for _ in 0..10 {
            if screen().join(" ").contains("Back") {
                press("both");
                break;
            }
            press("right");
        }
        for _ in 0..4 {
            if screen().join(" ").contains("is ready") {
                return;
            }
            press("left");
        }
        panic!("retour à l'accueil impossible : {:?}", screen());
    }

    /// Fait défiler les écrans (bouton droit) en les notant, jusqu'à l'écran
    /// de validation (`accept`), puis valide (deux boutons). Renvoie tout ce
    /// qui a été affiché — pour vérifier que l'appareil a MONTRÉ les bonnes
    /// valeurs, pas seulement qu'il a signé.
    pub fn review_and_accept(accept: &[&str]) -> Vec<String> {
        let mut seen = Vec::new();
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let texts = screen();
            let joined = texts.join(" ");
            seen.push(joined.clone());
            if accept.iter().any(|a| joined.contains(a)) {
                press("both");
                return seen;
            }
            // Avertissement "Blind signing ahead — press both buttons" : il faut
            // l'accepter pour voir le contenu (ce que ferait l'utilisateur).
            if joined.contains("press") && joined.contains("both buttons") {
                press("both");
                continue;
            }
            press("right");
        }
        panic!("écran de validation introuvable ; écrans vus : {seen:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteurs produits par le code officiel de ledgerjs (`hid-framing.js`,
    /// canal 0x0101, paquets de 64 octets) : une APDU de 205 octets sur 4
    /// paquets, puis une réponse de 70 octets sur 2 paquets.
    #[test]
    fn hid_framing_matches_ledgerjs() {
        let mut apdu = vec![0xe0, 0x04, 0x00, 0x00, 0xc8];
        apdu.extend((0..200u32).map(|i| (i & 0xff) as u8));
        let frames: Vec<String> = hid_frames(0x0101, &apdu).iter().map(hex::encode).collect();
        assert_eq!(
            frames,
            [
                "010105000000cde0040000c8000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233",
                "01010500013435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e",
                "01010500026f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9",
                "0101050003aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c70000000000000000000000000000000000000000000000000000000000",
            ]
        );

        let response_frames = [
            "0101050000004600070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a8188",
            "01010500018f969da4abb2b9c0c7ced5900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ];
        let mut reassembler = HidReassembler::new(0x0101);
        assert!(reassembler.push(&hex::decode(response_frames[0]).unwrap()).unwrap().is_none());
        let response = reassembler.push(&hex::decode(response_frames[1]).unwrap()).unwrap().unwrap();
        assert_eq!(
            hex::encode(response),
            "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced59000"
        );
    }

    #[test]
    fn hid_reassembly_refuses_foreign_or_out_of_order_frames() {
        let frame = hex::decode("0101050000004600070e151c").unwrap();
        assert!(HidReassembler::new(0x0202).push(&frame).is_err(), "autre canal");
        let mut wrong_tag = frame.clone();
        wrong_tag[2] = 0x06;
        assert!(HidReassembler::new(0x0101).push(&wrong_tag).is_err(), "autre étiquette");
        let mut out_of_order = frame.clone();
        out_of_order[4] = 1;
        assert!(HidReassembler::new(0x0101).push(&out_of_order).is_err(), "hors séquence");
        assert!(HidReassembler::new(0x0101).push(&[1, 1, 5]).is_err(), "trop court");
    }

    /// Même encodage que `splitPath` + tampon de chemin de hw-app-eth.
    #[test]
    fn path_encoding_matches_ledgerjs() {
        let path = parse_path("44'/60'/0'/0/0").unwrap();
        assert_eq!(hex::encode(encode_path(&path).unwrap()), "058000002c8000003c800000000000000000000000");
        assert_eq!(parse_path("m/84h/0h/1h/0/7").unwrap(), vec![84 | HARDENED, HARDENED, 1 | HARDENED, 0, 7]);
        for bad in ["", "44'/x", "2147483648/0", "44''/0"] {
            assert!(parse_path(bad).is_err(), "{bad}");
        }
        assert!(encode_path(&[0; 11]).is_err());
    }

    struct Scripted(Vec<Vec<u8>>);
    impl Transport for Scripted {
        fn exchange(&mut self, _apdu: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.remove(0))
        }
    }

    #[test]
    fn status_words_become_clear_errors() {
        let mut t = Scripted(vec![vec![0xaa, 0x90, 0x00], vec![0x69, 0x85], vec![0x55, 0x15], vec![0x6e, 0x00], vec![0x12, 0x34]]);
        assert_eq!(send(&mut t, 0xe0, 0x02, 0, 0, &[]).unwrap(), vec![0xaa]);
        assert!(send(&mut t, 0xe0, 0x02, 0, 0, &[]).unwrap_err().to_string().contains("refusée"));
        assert!(send(&mut t, 0xe0, 0x02, 0, 0, &[]).unwrap_err().to_string().contains("verrouillé"));
        assert!(send(&mut t, 0xe0, 0x02, 0, 0, &[]).unwrap_err().to_string().contains("application non ouverte"));
        assert!(send(&mut t, 0xe0, 0x02, 0, 0, &[]).unwrap_err().to_string().contains("0x1234"));
        assert!(send(&mut t, 0xe0, 0x02, 0, 0, &[0; 256]).is_err(), "APDU > 255 octets refusée avant envoi");
    }
}
