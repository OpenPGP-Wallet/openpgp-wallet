//! Trezor hardware wallets (Model T, Safe 3, Safe 5: "core" firmware): the private
//! key never leaves the device, which itself shows what it signs and requires a
//! physical confirmation. This app builds the transactions, sends them over, checks
//! every signature again, then broadcasts.
//!
//! Protocol: protobuf messages (official firmware definitions) in 64-byte packets
//! ("protocol v1": `?##` + type + length in the first packet, `?` at the start of
//! the following ones), over USB (WebUSB interface) for a real device, or to the
//! official emulator for tests. Checked against the official trezorlib library and
//! against the official firmware running in its emulator.
//!
//! Not supported: the Trezor Model One (PIN entered on the computer) and the Safe 7
//! (new "THP" encrypted protocol).

pub mod bitcoin;
pub mod ethereum;
pub mod proto;
pub mod solana;

use anyhow::{anyhow, bail, ensure, Context, Result};
use proto::{Message, Writer};
use std::time::Duration;

/// Message numbers (the `MessageType` enum of the official definitions).
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

/// Channel to a device: 64-byte packets in both directions.
pub trait Link {
    fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<()>;
    fn read_packet(&mut self) -> Result<[u8; PACKET]>;
}

/// Splits a message into packets: `?##` + type (2 bytes) + length (4 bytes) + start
/// of the data, then `?` + the rest; zero padding.
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

/// Largest response accepted (no message used here comes close).
const MAX_MESSAGE: usize = 1 << 20;

/// Reassembles a response; any malformed packet is an error.
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

/// Trezor connected over USB (WebUSB interface: IDs 1209:53c1, endpoint 0x01 out,
/// 0x81 in).
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
            let Ok(descriptor) = device.device_descriptor() else {
                continue;
            };
            legacy |= descriptor.vendor_id() == LEGACY_VENDOR_ID;
            if descriptor.vendor_id() != TREZOR_VENDOR_ID
                || descriptor.product_id() != TREZOR_PRODUCT_ID
            {
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
        let written = self
            .handle
            .write_interrupt(0x01, packet, Duration::from_secs(5))
            .context("écriture USB vers le Trezor impossible")?;
        ensure!(written == PACKET, "écriture USB vers le Trezor incomplète");
        Ok(())
    }

    fn read_packet(&mut self) -> Result<[u8; PACKET]> {
        let mut packet = [0u8; PACKET];
        // No global timeout: the device waits for the user's physical confirmation, which
        // can take as long as it takes.
        loop {
            match self
                .handle
                .read_interrupt(0x81, &mut packet, Duration::from_secs(1))
            {
                Ok(n) if n == PACKET => return Ok(packet),
                Ok(_) => bail!("paquet USB Trezor incomplet"),
                Err(rusb::Error::Timeout) => continue,
                Err(e) => return Err(anyhow!("lecture USB depuis le Trezor impossible : {e}")),
            }
        }
    }
}

/// TCP bridge to the official emulator (tests and development builds only: the
/// emulator runs under WSL, which only forwards TCP to Windows; a bridge there
/// relays each 64-byte packet over UDP).
#[cfg(any(debug_assertions, test))]
pub struct RelayLink {
    stream: std::net::TcpStream,
}

#[cfg(any(debug_assertions, test))]
impl RelayLink {
    pub fn connect(address: &str) -> Result<Self> {
        let stream = std::net::TcpStream::connect(address)
            .with_context(|| format!("émulateur Trezor injoignable ({address})"))?;
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

/// Device `Failure` error, translated.
fn failure_error(payload: &[u8]) -> anyhow::Error {
    let message = Message::parse(payload).ok();
    let code = message.as_ref().and_then(|m| m.uint(1)).unwrap_or(0);
    let detail = message
        .as_ref()
        .and_then(|m| m.string(2))
        .unwrap_or_default();
    match code {
        4 => anyhow!("opération refusée sur le Trezor"),
        6 => anyhow!("saisie du PIN annulée sur le Trezor"),
        7 => anyhow!("PIN incorrect sur le Trezor"),
        11 => anyhow!("Trezor non initialisé : configurez-le d'abord avec Trezor Suite"),
        3 => anyhow!("données refusées par le Trezor : {detail}"),
        _ => anyhow!("le Trezor a renvoyé une erreur : {detail}"),
    }
}

/// Device information (answer to `Initialize`).
#[derive(Debug)]
pub struct Features {
    pub model: String,
    pub version: (u32, u32, u32),
    pub initialized: bool,
}

/// Session with a device.
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

    /// Sends a message and returns the useful answer, handling the intermediate
    /// requests: on-screen confirmation (`ButtonRequest`), passphrase (entered on the
    /// device itself, never on the computer). `Failure` becomes an explicit error.
    pub fn call(&mut self, msg_type: u16, payload: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.send(msg_type, payload)?;
        loop {
            let (response_type, response) = read_message(self.link.as_mut())?;
            match response_type {
                msg::BUTTON_REQUEST => self.send(msg::BUTTON_ACK, &[])?,
                msg::PASSPHRASE_REQUEST => self.send(
                    msg::PASSPHRASE_ACK,
                    &Writer::new().boolean(3, true).finish(),
                )?,
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

    /// `call` with an expected answer type.
    pub fn call_expect(&mut self, msg_type: u16, payload: &[u8], expected: u16) -> Result<Vec<u8>> {
        let (response_type, response) = self.call(msg_type, payload)?;
        ensure!(
            response_type == expected,
            "réponse inattendue du Trezor (message {response_type})"
        );
        Ok(response)
    }

    /// Opens a session and reads the device information.
    pub fn initialize(&mut self) -> Result<Features> {
        let payload = self.call_expect(msg::INITIALIZE, &[], msg::FEATURES)?;
        let features = Message::parse(&payload)?;
        let version = |f| features.uint(f).unwrap_or(0) as u32;
        let result = Features {
            model: features.string(21).unwrap_or_default(),
            version: (version(2), version(3), version(4)),
            initialized: features.uint(12) == Some(1),
        };
        ensure!(
            result.initialized,
            "Trezor non initialisé : configurez-le d'abord avec Trezor Suite"
        );
        Ok(result)
    }
}

/// Driving the official emulator during tests: its test link ("debuglink") reads
/// the screen and presses the buttons on the user's behalf.
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
            // Answer (Success) to the screen watch.
            let _ = read_message(&mut link.0);
            link
        }

        fn send(&mut self, msg_type: u16, payload: &[u8]) {
            for packet in encode_packets(msg_type, payload) {
                self.0.write_packet(&packet).unwrap();
            }
        }

        /// Text of the current screen.
        pub fn screen(&mut self) -> String {
            self.send(DEBUG_GET_STATE, &[]);
            let (msg_type, payload) = read_message(&mut self.0).unwrap();
            assert_eq!(msg_type, DEBUG_STATE);
            let state = Message::parse(&payload).unwrap();
            state
                .all_bytes(13)
                .iter()
                .map(|t| String::from_utf8_lossy(t))
                .collect::<Vec<_>>()
                .join("")
        }

        /// "Yes" button (also confirms a "hold to confirm" screen).
        pub fn press_yes(&mut self) {
            self.send(DEBUG_DECISION, &Writer::new().uint(1, 1).finish());
        }

        pub fn press_no(&mut self) {
            self.send(DEBUG_DECISION, &Writer::new().uint(1, 0).finish());
        }

        /// Confirms every screen that appears for `seconds`, noting its text (to check what
        /// the device SHOWED, not just that it signed); `refuse_on`: refuses instead on the
        /// screen containing that text.
        pub fn review(&mut self, seconds: u64, refuse_on: Option<&str>) -> Vec<String> {
            let mut seen: Vec<String> = Vec::new();
            let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
            while std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(400));
                let text = self.screen();
                if std::env::var("TREZOR_DEBUG_SCREENS").is_ok() {
                    eprintln!("[écran] {}", &text[..text.len().min(160)]);
                }
                // Never press on the home screen: the emulator would keep the decision pending and
                // apply it to the next screen (observed: the recipient screen was confirmed
                // without being seen).
                if text.is_empty() || text.contains("\"Homescreen\"") || seen.last() == Some(&text)
                {
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

    /// Protocol v1 packets: a 262-byte message (a real `Features` answer from the
    /// emulator) over 5 packets; exact reassembly.
    #[test]
    fn packets_follow_the_v1_protocol() {
        let payload: Vec<u8> = (0..262u32).map(|i| i as u8).collect();
        let packets = encode_packets(msg::FEATURES, &payload);
        assert_eq!(packets.len(), 5);
        assert_eq!(&packets[0][..9], &[b'?', b'#', b'#', 0, 17, 0, 0, 1, 6]);
        assert!(packets[1..].iter().all(|p| p[0] == b'?'));
        assert_eq!(
            encode_packets(msg::INITIALIZE, &[])[0][..9],
            [b'?', b'#', b'#', 0, 0, 0, 0, 0, 0]
        );

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
        assert!(failure_error(&failure(4, "Cancelled"))
            .to_string()
            .contains("refusée"));
        assert!(failure_error(&failure(7, ""))
            .to_string()
            .contains("PIN incorrect"));
        assert!(failure_error(&failure(3, "Invalid path"))
            .to_string()
            .contains("Invalid path"));
    }

    /// Official emulator (core firmware 2.7.0, Model T) through the bridge: session
    /// opened, model and version read.
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
