//! GameSpy NAT negotiation v3 wire codec.
//!
//! Layout follows the client's packet structs: a 12-byte base header (magic,
//! version, type, cookie) followed by one of the init/connect/report bodies.
//! The client sends `INIT` from up to four sources -- the game socket
//! (`port_type` 0, only when it negotiates with a game socket) and the three
//! matchup hosts (1, 2, 3) -- and will not advance until every one of those
//! sources has been acknowledged.
use std::net::{Ipv4Addr, SocketAddrV4};

pub const MAGIC: [u8; 6] = [0xfd, 0xfc, 0x1e, 0x66, 0x6a, 0xb2];
pub const VERSION: u8 = 3;

/// Packet types used by this rendezvous.
pub const INIT: u8 = 0;
pub const INIT_ACK: u8 = 1;
pub const CONNECT: u8 = 5;
pub const CONNECT_ACK: u8 = 6;
pub const REPORT: u8 = 13;
pub const REPORT_ACK: u8 = 14;

/// Highest `port_type` the client uses: the game port plus three matchup hosts.
pub const MAX_PORT_TYPE: u8 = 3;
/// The matchup-host sources the client requires an acknowledgement from.
pub const HOST_PORT_TYPES: std::ops::RangeInclusive<usize> = 1..=3;
/// The game-socket source, present only when the client negotiates with one.
pub const GAME_PORT_TYPE: usize = 0;

/// `finished` codes in a server-sent `CONNECT`. Anything other than
/// `FINISHED_OK` makes the client abandon negotiation with that error, so a
/// waiting client fails promptly instead of sitting out its own timeout.
pub const FINISHED_OK: u8 = 0;
pub const FINISHED_DEADBEAT_PARTNER: u8 = 1;

const BASE: usize = 12;
/// Init body: port type, client index, use-game-port, private IP, private port.
const INIT_BODY: usize = 9;
/// Connect body: remote IP, remote port, got-your-data, finished.
const CONNECT_BODY: usize = 8;
/// Report body: port type, client index, result, NAT type, mapping scheme, game.
const REPORT_BODY: usize = 61;
const REPORT_GAME: usize = 23;
const MAX_GAME: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    pub cookie: u32,
    pub port_type: u8,
    pub client: u8,
    pub use_game_port: bool,
    /// The address the client reports for itself, used when both clients are
    /// behind one public address. Only the later matchup-host packets carry a
    /// port: the client fills it in after its first send, so the game-port and
    /// first-host packets report zero.
    pub private: Option<SocketAddrV4>,
    pub game: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Init(Init),
    ConnectAck {
        cookie: u32,
        client: u8,
    },
    Report {
        cookie: u32,
        client: u8,
        game: String,
        result: u8,
    },
}

fn game(bytes: &[u8]) -> Result<String, &'static str> {
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or("missing game terminator")?;
    let name = &bytes[..end];
    if name.is_empty()
        || name.len() >= MAX_GAME
        || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return Err("invalid game");
    }
    String::from_utf8(name.to_vec()).map_err(|_| "invalid game")
}

pub fn parse(data: &[u8]) -> Result<Packet, &'static str> {
    if data.len() < BASE || data[..6] != MAGIC || data[6] != VERSION {
        return Err("invalid NATNEG header");
    }
    let cookie = u32::from_be_bytes(data[8..12].try_into().unwrap());
    match data[7] {
        // The client appends its game name after the init body.
        INIT if (BASE + INIT_BODY + 1..=BASE + INIT_BODY + MAX_GAME).contains(&data.len()) => {
            if data[12] > MAX_PORT_TYPE || data[13] > 1 || data[14] > 1 {
                return Err("invalid init fields");
            }
            let ip = Ipv4Addr::new(data[15], data[16], data[17], data[18]);
            let port = u16::from_be_bytes([data[19], data[20]]);
            Ok(Packet::Init(Init {
                cookie,
                port_type: data[12],
                client: data[13],
                use_game_port: data[14] != 0,
                private: (port != 0 && !ip.is_unspecified() && !ip.is_broadcast())
                    .then(|| SocketAddrV4::new(ip, port)),
                game: game(&data[BASE + INIT_BODY..])?,
            }))
        }
        // The client builds its connect ack from the init body and leaves the
        // port type uninitialized, so only the client index may be read.
        CONNECT_ACK if data.len() >= BASE + INIT_BODY && data[13] < 2 => Ok(Packet::ConnectAck {
            cookie,
            client: data[13],
        }),
        REPORT if data.len() >= BASE + REPORT_BODY && data[13] < 2 => Ok(Packet::Report {
            cookie,
            client: data[13],
            game: game(&data[REPORT_GAME..BASE + REPORT_BODY])?,
            result: data[14],
        }),
        _ => Err("unsupported or malformed NATNEG packet"),
    }
}

fn header(kind: u8, cookie: u32, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    out[..6].copy_from_slice(&MAGIC);
    out[6] = VERSION;
    out[7] = kind;
    out[8..12].copy_from_slice(&cookie.to_be_bytes());
    out
}

/// `INIT_ACK` and `REPORT_ACK` share the init body. The client reads the port
/// type from an init ack to tick off the source that packet came from.
pub fn ack(kind: u8, cookie: u32, port_type: u8, client: u8) -> Vec<u8> {
    let mut out = header(kind, cookie, BASE + INIT_BODY);
    out[12] = port_type;
    out[13] = client;
    out
}

/// Tell one client where its partner is, or why there will not be one.
pub fn connect(cookie: u32, remote: SocketAddrV4, finished: u8) -> Vec<u8> {
    let mut out = header(CONNECT, cookie, BASE + CONNECT_BODY);
    out[12..16].copy_from_slice(&remote.ip().octets());
    out[16..18].copy_from_slice(&remote.port().to_be_bytes());
    // `got_your_data` stays zero: the server never takes part in the
    // client-to-client ping exchange that field belongs to.
    out[19] = finished;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_bytes(cookie: u32, port_type: u8, client: u8, game: &str) -> Vec<u8> {
        let mut p = header(INIT, cookie, BASE + INIT_BODY);
        p[12] = port_type;
        p[13] = client;
        p[14] = 1;
        p[15..19].copy_from_slice(&[192, 168, 1, 50]);
        p[19..21].copy_from_slice(&3658u16.to_be_bytes());
        p.extend_from_slice(game.as_bytes());
        p.push(0);
        p
    }

    #[test]
    fn init_reads_cookie_private_address_and_title() {
        let p = init_bytes(0x12345678, 1, 0, "testgame");
        assert_eq!(
            parse(&p),
            Ok(Packet::Init(Init {
                cookie: 0x12345678,
                port_type: 1,
                client: 0,
                use_game_port: true,
                private: Some("192.168.1.50:3658".parse().unwrap()),
                game: "testgame".into()
            }))
        );
        let mut truncated = p.clone();
        truncated.pop();
        assert!(parse(&truncated).is_err());
        assert!(parse(&init_bytes(1, 1, 0, "")).is_err());
    }

    #[test]
    fn zero_or_unspecified_private_address_is_not_routable() {
        // The game-port and first-host inits go out before the client knows
        // its own port, so they must not be taken as an address.
        let mut p = init_bytes(1, 0, 0, "test");
        p[19..21].copy_from_slice(&0u16.to_be_bytes());
        let Ok(Packet::Init(init)) = parse(&p) else {
            panic!("expected init");
        };
        assert_eq!(init.private, None);

        let mut p = init_bytes(1, 2, 0, "test");
        p[15..19].copy_from_slice(&[0, 0, 0, 0]);
        let Ok(Packet::Init(init)) = parse(&p) else {
            panic!("expected init");
        };
        assert_eq!(init.private, None);
    }

    #[test]
    fn connect_has_client_layout_and_carries_failure_codes() {
        assert_eq!(
            connect(
                1,
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6500),
                FINISHED_OK
            ),
            vec![
                253, 252, 30, 102, 106, 178, 3, 5, 0, 0, 0, 1, 10, 0, 0, 2, 25, 100, 0, 0
            ]
        );
        let failed = connect(
            1,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            FINISHED_DEADBEAT_PARTNER,
        );
        assert_eq!(failed.len(), BASE + CONNECT_BODY);
        assert_eq!(failed[19], FINISHED_DEADBEAT_PARTNER);
    }

    #[test]
    fn rejects_bad_indices_versions_and_truncation() {
        let mut p = init_bytes(1, 0, 0, "test");
        p[13] = 2;
        assert!(parse(&p).is_err());
        p[13] = 0;
        p[12] = MAX_PORT_TYPE + 1;
        assert!(parse(&p).is_err());
        p[12] = 0;
        p[6] = 2;
        assert!(parse(&p).is_err());
        p[6] = VERSION;
        for n in 0..BASE + INIT_BODY + 1 {
            assert!(parse(&p[..n]).is_err(), "accepted {n} bytes");
        }
    }

    #[test]
    fn decodes_report_and_connect_ack_at_client_sizes() {
        let mut report = header(REPORT, 0x12345678, BASE + REPORT_BODY);
        report[13] = 1;
        report[14] = 1;
        report[REPORT_GAME..REPORT_GAME + 5].copy_from_slice(b"test\0");
        assert_eq!(
            parse(&report),
            Ok(Packet::Report {
                cookie: 0x12345678,
                client: 1,
                game: "test".into(),
                result: 1
            })
        );
        assert!(parse(&report[..BASE + REPORT_BODY - 1]).is_err());

        let ack_bytes = ack(CONNECT_ACK, 42, 0, 1);
        assert_eq!(ack_bytes.len(), BASE + INIT_BODY);
        assert_eq!(
            parse(&ack_bytes),
            Ok(Packet::ConnectAck {
                cookie: 42,
                client: 1
            })
        );
        assert!(parse(&ack_bytes[..BASE + INIT_BODY - 1]).is_err());
    }

    #[test]
    fn init_ack_reports_the_source_it_acknowledges() {
        let p = ack(INIT_ACK, 7, 3, 1);
        assert_eq!(&p[6..14], &[VERSION, INIT_ACK, 0, 0, 0, 7, 3, 1]);
        assert_eq!(&ack(REPORT_ACK, 7, 0, 1)[6..8], &[VERSION, REPORT_ACK]);
    }
}
