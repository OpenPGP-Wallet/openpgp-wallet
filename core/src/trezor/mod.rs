//! Portefeuilles matériels Trezor (modèle T, Safe 3, Safe 5 : firmware
//! « core ») : la clé privée ne quitte jamais l'appareil, qui affiche lui-même
//! ce qu'il signe et exige une confirmation physique. Cette app construit les
//! transactions, les transmet, revérifie chaque signature, puis diffuse.
//!
//! Protocole : messages protobuf (définitions officielles du firmware) dans
//! des paquets de 64 octets (« protocole v1 » : `?##` + type + longueur dans le
//! premier paquet, `?` en tête des suivants), sur USB (interface WebUSB) pour
//! un vrai appareil, ou vers l'émulateur officiel pour les tests. Vérifié
//! contre la bibliothèque officielle trezorlib et contre le firmware officiel
//! exécuté dans son émulateur.
//!
//! Non pris en charge : le Trezor Model One (saisie du PIN depuis l'ordinateur)
//! et le Safe 7 (nouveau protocole chiffré « THP »).

pub mod bitcoin;
pub mod ethereum;
pub mod solana;
pub mod proto;

use anyhow::{anyhow, bail, ensure, Context, Result};
use proto::{Message, Writer};
use std::time::Duration;

/// Numéros de messages (énumération `MessageType` des définitions officielles).
pub(crate) mod msg {
    pub const INITIALIZE: u16 = 0;
    pub const FAILURE: u16 = 3;
    pub const GET_PUBLIC_KEY: u16 = 11;
    pub const PUBLIC_KEY: u16 = 12;
    pub const SIGN_TX: u16 = 15;
    pub const FEATURES: u16 = 17;
    pub const PIN_MATRIX_REQUEST: u16 = 18;
    pub const CANCEL: u16 = 20;
    pub const TX_REQUEST: u16 = 21;
    pub const TX_ACK: u16 = 22;
    pub const BUTTON_REQUEST: u16 = 26;
    pub const BUTTON_ACK: u16 = 27;
    pub const GET_ADDRESS: u16 = 29;
    pub const ADDRESS: u16 = 30;
    pub const PASSPHRASE_REQUEST: u16 = 41;
    pub const PASSPHRASE_ACK: u16 = 42;
    pub const ETHEREUM_GET_ADDRESS: u16 = 56;
    pub const ETHEREUM_ADDRESS: u16 = 57;
    pub const ETHEREUM_SIGN_TX: u16 = 58;
    pub const ETHEREUM_TX_REQUEST: u16 = 59;
    pub const ETHEREUM_TX_ACK: u16 = 60;
    pub const SOLANA_GET_ADDRESS: u16 = 902;
    pub const SOLANA_ADDRESS: u16 = 903;
    pub const SOLANA_SIGN_TX: u16 = 904;
    pub const SOLANA_TX_SIGNATURE: u16 = 905;
}

const PACKET: usize = 64;

/// Canal vers un appareil : paquets de 64 octets dans les deux sens.
pub trait Link {
    fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<()>;
    fn read_packet(&mut self) -> Result<[u8; PACKET]>;
}

/// Découpe un message en paquets : `?##` + type (2 octets) + longueur
/// (4 octets) + début des données, puis `?` + suite ; bourrage à zéro.
pub fn encode_packets(msg_type: u16, payload: &[u8]) -> Vec<[u8; PACKET]> {
    let mut data = b"##".to_vec();
    data.extend(msg_type.to_be_bytes());
    data.extend((payload.len() as u32).to_be_bytes());
    data.extend_from_slice(payload);
    data.chunks(PACKET - 1)
        .map(|chunk| {
            let mut packet = [0u8; PACKET];
            packet[0] = b'?';
            packet[1..1 + chunk.len()].copy_from_slice(chunk);
            packet
        })
        .collect()
}

/// Taille maximale d'une réponse acceptée (aucun message utilisé n'approche).
const MAX_MESSAGE: usize = 1 << 20;

/// Réassemble une réponse ; tout paquet mal formé est une erreur.
pub fn read_message(link: &mut dyn Link) -> Result<(u16, Vec<u8>)> {
    let first = link.read_packet()?;
    ensure!(&first[..3] == b"?##", "paquet Trezor inattendu");
    let msg_type = u16::from_be_bytes([first[3], first[4]]);
    let len = u32::from_be_bytes([first[5], first[6], first[7], first[8]]) as usize;
    ensure!(len <= MAX_MESSAGE, "réponse du Trezor anormalement longue");
    let mut payload = first[9..].to_vec();
    while payload.len() < len {
        let packet = link.read_packet()?;
        ensure!(packet[0] == b'?', "paquet Trezor inattendu");
        payload.extend_from_slice(&packet[1..]);
    }
    payload.truncate(len);
    Ok((msg_type, payload))
}

/// Trezor branché en USB (interface WebUSB : identifiants 1209:53c1,
/// terminaison 0x01 en sortie, 0x81 en entrée).
pub struct UsbLink {
    handle: rusb::DeviceHandle<rusb::GlobalContext>,
}

const TREZOR_VENDOR_ID: u16 = 0x1209;
const TREZOR_PRODUCT_ID: u16 = 0x53c1;
const LEGACY_VENDOR_ID: u16 = 0x534c;

impl UsbLink {
    pub fn open_first() -> Result<Self> {
        let devices = rusb::devices().context("accès USB impossible")?;
        let mut legacy = false;
        for device in devices.iter() {
            let Ok(descriptor) = device.device_descriptor() else { continue };
            legacy |= descriptor.vendor_id() == LEGACY_VENDOR_ID;
            if descriptor.vendor_id() != TREZOR_VENDOR_ID || descriptor.product_id() != TREZOR_PRODUCT_ID {
                continue;
            }
            let handle = device
                .open()
                .context("ouverture du Trezor impossible (déjà utilisé par Trezor Suite ou une autre application ?)")?;
            handle
                .claim_interface(0)
                .context("Trezor déjà utilisé par une autre application : fermez Trezor Suite puis réessayez")?;
            return Ok(Self { handle });
        }
        if legacy {
            bail!("Trezor Model One détecté : ce modèle n'est pas pris en charge (saisie du PIN depuis l'ordinateur)");
        }
        bail!("aucun Trezor détecté : branchez-le et déverrouillez-le")
    }
}

impl Link for UsbLink {
    fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<()> {
        let written = self.handle.write_interrupt(0x01, packet, Duration::from_secs(5)).context("écriture USB vers le Trezor impossible")?;
        ensure!(written == PACKET, "écriture USB vers le Trezor incomplète");
        Ok(())
    }

    fn read_packet(&mut self) -> Result<[u8; PACKET]> {
        let mut packet = [0u8; PACKET];
        // Pas de délai maximal global : l'appareil attend la confirmation
        // physique de l'utilisateur, qui peut prendre le temps qu'il faut.
        loop {
            match self.handle.read_interrupt(0x81, &mut packet, Duration::from_secs(1)) {
                Ok(n) if n == PACKET => return Ok(packet),
                Ok(_) => bail!("paquet USB Trezor incomplet"),
                Err(rusb::Error::Timeout) => continue,
                Err(e) => return Err(anyhow!("lecture USB depuis le Trezor impossible : {e}")),
            }
        }
    }
}

/// Relais TCP vers l'émulateur officiel (tests et version de développement
/// seulement : l'émulateur tourne sous WSL, qui ne transmet que le TCP à
/// Windows ; un relais y renvoie chaque paquet de 64 octets en UDP).
#[cfg(any(debug_assertions, test))]
pub struct RelayLink {
    stream: std::net::TcpStream,
}

#[cfg(any(debug_assertions, test))]
impl RelayLink {
    pub fn connect(address: &str) -> Result<Self> {
        let stream = std::net::TcpStream::connect(address).with_context(|| format!("émulateur Trezor injoignable ({address})"))?;
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        stream.set_nodelay(true)?;
        Ok(Self { stream })
    }
}

#[cfg(any(debug_assertions, test))]
impl Link for RelayLink {
    fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<()> {
        use std::io::Write;
        Ok(self.stream.write_all(packet)?)
    }

    fn read_packet(&mut self) -> Result<[u8; PACKET]> {
        use std::io::Read;
        let mut packet = [0u8; PACKET];
        self.stream.read_exact(&mut packet)?;
        Ok(packet)
    }
}

/// Erreur `Failure` de l'appareil, traduite.
fn failure_error(payload: &[u8]) -> anyhow::Error {
    let message = Message::parse(payload).ok();
    let code = message.as_ref().and_then(|m| m.uint(1)).unwrap_or(0);
    let detail = message.as_ref().and_then(|m| m.string(2)).unwrap_or_default();
    match code {
        4 => anyhow!("opération refusée sur le Trezor"),
        6 => anyhow!("saisie du PIN annulée sur le Trezor"),
        7 => anyhow!("PIN incorrect sur le Trezor"),
        11 => anyhow!("Trezor non initialisé : configurez-le d'abord avec Trezor Suite"),
        3 => anyhow!("données refusées par le Trezor : {detail}"),
        _ => anyhow!("le Trezor a renvoyé une erreur : {detail}"),
    }
}

/// Informations de l'appareil (réponse à `Initialize`).
#[derive(Debug)]
pub struct Features {
    pub model: String,
    pub version: (u32, u32, u32),
    pub initialized: bool,
}

/// Session avec un appareil.
pub struct Trezor {
    link: Box<dyn Link>,
}

impl Trezor {
    pub fn new(link: Box<dyn Link>) -> Self {
        Self { link }
    }

    fn send(&mut self, msg_type: u16, payload: &[u8]) -> Result<()> {
        for packet in encode_packets(msg_type, payload) {
            self.link.write_packet(&packet)?;
        }
        Ok(())
    }

    /// Envoie un message et renvoie la réponse utile, en répondant aux
    /// demandes intermédiaires : confirmation à l'écran (`ButtonRequest`),
    /// phrase secrète (saisie sur l'appareil lui-même, jamais sur
    /// l'ordinateur). `Failure` devient une erreur explicite.
    pub fn call(&mut self, msg_type: u16, payload: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.send(msg_type, payload)?;
        loop {
            let (response_type, response) = read_message(self.link.as_mut())?;
            match response_type {
                msg::BUTTON_REQUEST => self.send(msg::BUTTON_ACK, &[])?,
                msg::PASSPHRASE_REQUEST => self.send(msg::PASSPHRASE_ACK, &Writer::new().boolean(3, true).finish())?,
                msg::PIN_MATRIX_REQUEST => {
                    self.send(msg::CANCEL, &[])?;
                    let _ = read_message(self.link.as_mut());
                    bail!("ce Trezor demande la saisie du PIN depuis l'ordinateur (Model One) : non pris en charge");
                }
                msg::FAILURE => return Err(failure_error(&response)),
                _ => return Ok((response_type, response)),
            }
        }
    }

    /// `call` avec un type de réponse attendu.
    pub fn call_expect(&mut self, msg_type: u16, payload: &[u8], expected: u16) -> Result<Vec<u8>> {
        let (response_type, response) = self.call(msg_type, payload)?;
        ensure!(response_type == expected, "réponse inattendue du Trezor (message {response_type})");
        Ok(response)
    }

    /// Ouvre une session et lit les informations de l'appareil.
    pub fn initialize(&mut self) -> Result<Features> {
        let payload = self.call_expect(msg::INITIALIZE, &[], msg::FEATURES)?;
        let features = Message::parse(&payload)?;
        let version = |f| features.uint(f).unwrap_or(0) as u32;
        let result = Features {
            model: features.string(21).unwrap_or_default(),
            version: (version(2), version(3), version(4)),
            initialized: features.uint(12) == Some(1),
        };
        ensure!(result.initialized, "Trezor non initialisé : configurez-le d'abord avec Trezor Suite");
        Ok(result)
    }
}

/// Pilotage de l'émulateur officiel pendant les tests : son lien de test
/// (« debuglink ») lit l'écran et appuie sur les boutons à la place de
/// l'utilisateur.
#[cfg(test)]
pub(crate) mod emulator {
    use super::*;

    pub const ADDRESS: &str = "127.0.0.1:21424";
    const DEBUG_ADDRESS: &str = "127.0.0.1:21425";
    const DEBUG_DECISION: u16 = 100;
    const DEBUG_GET_STATE: u16 = 101;
    const DEBUG_STATE: u16 = 102;
    const DEBUG_WATCH_LAYOUT: u16 = 9006;

    pub fn connect() -> Trezor {
        Trezor::new(Box::new(RelayLink::connect(ADDRESS).unwrap()))
    }

    pub struct DebugLink(RelayLink);

    impl DebugLink {
        pub fn connect() -> Self {
            let mut link = Self(RelayLink::connect(DEBUG_ADDRESS).unwrap());
            link.send(DEBUG_WATCH_LAYOUT, &Writer::new().boolean(1, true).finish());
            // Réponse (Success) à la surveillance de l'écran.
            let _ = read_message(&mut link.0);
            link
        }

        fn send(&mut self, msg_type: u16, payload: &[u8]) {
            for packet in encode_packets(msg_type, payload) {
                self.0.write_packet(&packet).unwrap();
            }
        }

        /// Texte de l'écran courant.
        pub fn screen(&mut self) -> String {
            self.send(DEBUG_GET_STATE, &[]);
            let (msg_type, payload) = read_message(&mut self.0).unwrap();
            assert_eq!(msg_type, DEBUG_STATE);
            let state = Message::parse(&payload).unwrap();
            state.all_bytes(13).iter().map(|t| String::from_utf8_lossy(t)).collect::<Vec<_>>().join("")
        }

        /// Bouton « oui » (valide aussi un écran « maintenir pour confirmer »).
        pub fn press_yes(&mut self) {
            self.send(DEBUG_DECISION, &Writer::new().uint(1, 1).finish());
        }

        pub fn press_no(&mut self) {
            self.send(DEBUG_DECISION, &Writer::new().uint(1, 0).finish());
        }

        /// Confirme chaque écran qui apparaît pendant `seconds`, en notant son
        /// texte (pour vérifier ce que l'appareil a MONTRÉ, pas seulement
        /// qu'il a signé) ; `refuse_on` : refuse à la place sur l'écran qui
        /// contient ce texte.
        pub fn review(&mut self, seconds: u64, refuse_on: Option<&str>) -> Vec<String> {
            let mut seen: Vec<String> = Vec::new();
            let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
            while std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(400));
                let text = self.screen();
                if std::env::var("TREZOR_DEBUG_SCREENS").is_ok() {
                    eprintln!("[écran] {}", &text[..text.len().min(160)]);
                }
                // Jamais d'appui sur l'écran d'accueil : l'émulateur garderait
                // la décision en attente et l'appliquerait à l'écran suivant
                // (constaté : l'écran du destinataire était validé sans être vu).
                if text.is_empty() || text.contains("\"Homescreen\"") || seen.last() == Some(&text) {
                    continue;
                }
                seen.push(text.clone());
                if refuse_on.is_some_and(|r| text.contains(r)) {
                    self.press_no();
                    return seen;
                }
                self.press_yes();
            }
            seen
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paquets du protocole v1 : message de 262 octets (réponse `Features`
    /// réelle de l'émulateur) sur 5 paquets ; réassemblage exact.
    #[test]
    fn packets_follow_the_v1_protocol() {
        let payload: Vec<u8> = (0..262u32).map(|i| i as u8).collect();
        let packets = encode_packets(msg::FEATURES, &payload);
        assert_eq!(packets.len(), 5);
        assert_eq!(&packets[0][..9], &[b'?', b'#', b'#', 0, 17, 0, 0, 1, 6]);
        assert!(packets[1..].iter().all(|p| p[0] == b'?'));
        assert_eq!(encode_packets(msg::INITIALIZE, &[])[0][..9], [b'?', b'#', b'#', 0, 0, 0, 0, 0, 0]);

        struct Replay(Vec<[u8; PACKET]>);
        impl Link for Replay {
            fn write_packet(&mut self, _: &[u8; PACKET]) -> Result<()> {
                Ok(())
            }
            fn read_packet(&mut self) -> Result<[u8; PACKET]> {
                Ok(self.0.remove(0))
            }
        }
        let (msg_type, decoded) = read_message(&mut Replay(packets)).unwrap();
        assert_eq!((msg_type, decoded), (msg::FEATURES, payload));
        let mut bad = encode_packets(msg::FEATURES, &[1, 2, 3]);
        bad[0][1] = b'x';
        assert!(read_message(&mut Replay(bad)).is_err());
    }

    #[test]
    fn device_failures_become_clear_errors() {
        let failure = |code: u64, text: &str| Writer::new().uint(1, code).string(2, text).finish();
        assert!(failure_error(&failure(4, "Cancelled")).to_string().contains("refusée"));
        assert!(failure_error(&failure(7, "")).to_string().contains("PIN incorrect"));
        assert!(failure_error(&failure(3, "Invalid path")).to_string().contains("Invalid path"));
    }

    /// Émulateur officiel (firmware core 2.7.0, modèle T) via le relais :
    /// session ouverte, modèle et version lus.
    /// `cargo test -- --ignored trezor_emulator_answers --nocapture`
    #[test]
    #[ignore]
    fn trezor_emulator_answers() {
        let mut trezor = emulator::connect();
        let features = trezor.initialize().unwrap();
        println!("{features:?}");
        assert_eq!(features.model, "T");
        assert!(features.version >= (2, 7, 0));
    }
}
