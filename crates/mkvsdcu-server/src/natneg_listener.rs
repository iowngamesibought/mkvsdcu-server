//! NATNEG rendezvous: the transport that gets two consoles into one match.
//!
//! Each console starts negotiation with a cookie its title agreed on through
//! room metadata, so this service never invents cookies or picks partners. It
//! acknowledges every source the client registers, pairs the two clients that
//! share a cookie, and tells each one where the other is. After that the
//! consoles ping each other directly; the server is not in the game path.
//!
//! All three matchup host names must resolve here, on this one UDP port: the
//! client holds negotiation until every source it sent an init from has been
//! acknowledged. See DEPLOYMENT.md.
use mkvsdcu_proto::natneg::{self, Packet};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// How long a pair is kept after its first init.
const TTL: Duration = Duration::from_secs(60);
/// How long a lone client waits before it is told no partner arrived. Kept
/// below the client's own partner timeout so the failure is this explicit one.
const PARTNER_WAIT: Duration = Duration::from_secs(30);
const CONNECT_RETRY: Duration = Duration::from_secs(1);
const MAX_CONNECT_ATTEMPTS: u8 = 10;
const MAX_PAIRS: usize = 1024;

#[derive(Clone)]
struct Client {
    /// The address this client was actually seen from.
    ip: Ipv4Addr,
    /// Observed source per `port_type`, indexed as the client numbers them.
    sources: [Option<SocketAddrV4>; 4],
    /// The address the client reported for itself, when it gave a usable one.
    private: Option<SocketAddrV4>,
    use_game_port: bool,
    acked: bool,
    reported: bool,
}

impl Client {
    /// The negotiate socket, which is where server packets go.
    fn control(&self) -> Option<SocketAddrV4> {
        self.sources[*natneg::HOST_PORT_TYPES.start()]
    }

    /// The address a partner should connect to: the game socket when the
    /// client negotiated with one, otherwise its negotiate socket.
    fn public(&self) -> Option<SocketAddrV4> {
        self.sources[if self.use_game_port {
            natneg::GAME_PORT_TYPE
        } else {
            *natneg::HOST_PORT_TYPES.start()
        }]
    }

    /// The client will not progress until every source it used is acknowledged.
    fn ready(&self) -> bool {
        natneg::HOST_PORT_TYPES
            .clone()
            .all(|i| self.sources[i].is_some())
            && (!self.use_game_port || self.sources[natneg::GAME_PORT_TYPE].is_some())
    }
}

struct Pair {
    clients: [Option<Client>; 2],
    created: Instant,
    last_send: Option<Instant>,
    attempts: u8,
    /// Set once a lone client has been told its partner never arrived.
    abandoned: bool,
}

#[derive(Default)]
struct Rendezvous {
    pairs: HashMap<(String, u32), Pair>,
}

type Send = (SocketAddrV4, Vec<u8>);

impl Rendezvous {
    fn handle(&mut self, packet: Packet, from: SocketAddrV4, now: Instant) -> Vec<Send> {
        self.expire(now);
        match packet {
            Packet::Init(init) => self.init(init, from, now),
            Packet::ConnectAck { cookie, client } => {
                // Stop retrying for a client that confirms from its own source.
                for ((_, pair_cookie), pair) in &mut self.pairs {
                    if *pair_cookie == cookie
                        && let Some(entry) = &mut pair.clients[usize::from(client)]
                        && entry.control() == Some(from)
                    {
                        entry.acked = true;
                    }
                }
                vec![]
            }
            Packet::Report {
                cookie,
                client,
                game,
                result,
            } => {
                if let Some(pair) = self.pairs.get_mut(&(game, cookie))
                    && let Some(entry) = &mut pair.clients[usize::from(client)]
                    && entry.control() == Some(from)
                {
                    entry.acked = true;
                    if !entry.reported {
                        println!(
                            "[natneg] cookie={cookie:#010x} client={client} report result={result}"
                        );
                        entry.reported = true;
                    }
                    // The client waits for this ack before completing.
                    return vec![(from, natneg::ack(natneg::REPORT_ACK, cookie, 0, client))];
                }
                vec![]
            }
        }
    }

    fn init(&mut self, init: natneg::Init, from: SocketAddrV4, now: Instant) -> Vec<Send> {
        let key = (init.game, init.cookie);
        if !self.pairs.contains_key(&key) && self.pairs.len() >= MAX_PAIRS {
            return vec![];
        }
        let pair = self.pairs.entry(key).or_insert_with(|| Pair {
            clients: [None, None],
            created: now,
            last_send: None,
            attempts: 0,
            abandoned: false,
        });
        if pair.abandoned {
            return vec![];
        }
        let slot = &mut pair.clients[usize::from(init.client)];
        // A client index belongs to one source address for the whole exchange.
        if let Some(client) = slot
            && (client.ip != *from.ip() || client.use_game_port != init.use_game_port)
        {
            return vec![];
        }
        let client = slot.get_or_insert_with(|| Client {
            ip: *from.ip(),
            sources: [None; 4],
            private: None,
            use_game_port: init.use_game_port,
            acked: false,
            reported: false,
        });
        let source = &mut client.sources[usize::from(init.port_type)];
        if source.is_some_and(|previous| previous != from) {
            return vec![];
        }
        if source.is_none() {
            println!(
                "[natneg] cookie={:#010x} client={} registered porttype={} from={from}",
                init.cookie, init.client, init.port_type
            );
        }
        *source = Some(from);
        // Later packets carry the reported address; earlier ones have no port.
        if init.private.is_some() {
            client.private = init.private;
        }
        let mut out = vec![(
            from,
            natneg::ack(natneg::INIT_ACK, init.cookie, init.port_type, init.client),
        )];
        out.extend(Self::connects(pair, init.cookie, now));
        out
    }

    /// Where `partner` should be reached from `client`'s position.
    fn target(client: &Client, partner: &Client) -> Option<SocketAddrV4> {
        // Two clients seen at one public address are behind the same router.
        // Connecting to that shared address usually fails, so hand over the
        // address the partner reported for itself.
        if client.ip == partner.ip
            && let Some(private) = partner.private
        {
            return Some(private);
        }
        partner.public()
    }

    fn connects(pair: &mut Pair, cookie: u32, now: Instant) -> Vec<Send> {
        let [Some(a), Some(b)] = &pair.clients else {
            return vec![];
        };
        if !a.ready() || !b.ready() || pair.attempts >= MAX_CONNECT_ATTEMPTS {
            return vec![];
        }
        if pair
            .last_send
            .is_some_and(|sent| now.duration_since(sent) < CONNECT_RETRY)
        {
            return vec![];
        }
        let mut out = vec![];
        for (client, partner) in [(a, b), (b, a)] {
            if client.acked {
                continue;
            }
            let (Some(to), Some(target)) = (client.control(), Self::target(client, partner)) else {
                continue;
            };
            out.push((to, natneg::connect(cookie, target, natneg::FINISHED_OK)));
            println!(
                "[natneg] cookie={cookie:#010x} connect to={to} partner={target} attempt={}",
                pair.attempts + 1
            );
        }
        if !out.is_empty() {
            if pair.attempts == 0 {
                println!("[natneg] cookie={cookie:#010x} paired both clients");
            }
            pair.attempts += 1;
            pair.last_send = Some(now);
        }
        out
    }

    /// Tell a client that waited alone that no partner is coming.
    fn abandon(pair: &mut Pair, cookie: u32, now: Instant) -> Vec<Send> {
        if pair.abandoned || now.duration_since(pair.created) < PARTNER_WAIT {
            return vec![];
        }
        if pair.clients.iter().all(Option::is_some) {
            return vec![];
        }
        pair.abandoned = true;
        pair.clients
            .iter()
            .flatten()
            .filter_map(|client| {
                let to = client.control()?;
                println!("[natneg] cookie={cookie:#010x} no partner for {to}");
                Some((
                    to,
                    natneg::connect(
                        cookie,
                        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                        natneg::FINISHED_DEADBEAT_PARTNER,
                    ),
                ))
            })
            .collect()
    }

    fn expire(&mut self, now: Instant) {
        self.pairs
            .retain(|_, pair| now.duration_since(pair.created) < TTL);
    }

    fn tick(&mut self, now: Instant) -> Vec<Send> {
        self.expire(now);
        let mut out = vec![];
        for ((_, cookie), pair) in &mut self.pairs {
            out.extend(Self::abandon(pair, *cookie, now));
            out.extend(Self::connects(pair, *cookie, now));
        }
        out
    }
}

pub fn spawn(bind: SocketAddr) -> Result<JoinHandle<()>, String> {
    let socket = UdpSocket::bind(bind).map_err(|e| format!("bind NATNEG {bind}: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    println!(
        "[natneg] listening on {} (UDP, v3 rendezvous)",
        socket.local_addr().map_err(|e| e.to_string())?
    );
    Ok(thread::spawn(move || {
        let mut state = Rendezvous::default();
        let mut buf = [0; 512];
        loop {
            let mut responses = vec![];
            match socket.recv_from(&mut buf) {
                Ok((n, SocketAddr::V4(from))) => {
                    if let Ok(packet) = natneg::parse(&buf[..n]) {
                        responses = state.handle(packet, from, Instant::now());
                    }
                }
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => {
                    eprintln!("[natneg] receive error: {e}");
                    thread::sleep(Duration::from_millis(250));
                }
            }
            responses.extend(state.tick(Instant::now()));
            for (to, bytes) in responses {
                if let Err(e) = socket.send_to(&bytes, to) {
                    eprintln!("[natneg] send error: {e}");
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAME_PORT: u16 = 3658;
    const CONTROL_PORT: u16 = 50000;

    fn public(host: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, host), port)
    }

    fn private(host: u8) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, host), GAME_PORT)
    }

    fn init(game: &str, client: u8, port_type: u8, private: Option<SocketAddrV4>) -> Packet {
        Packet::Init(natneg::Init {
            cookie: 99,
            port_type,
            client,
            use_game_port: true,
            private,
            game: game.into(),
        })
    }

    /// Register every source the client uses, from `source`'s address.
    fn register(
        state: &mut Rendezvous,
        client: u8,
        from: impl Fn(u8) -> SocketAddrV4,
        private: Option<SocketAddrV4>,
        now: Instant,
    ) -> Vec<Send> {
        let mut last = vec![];
        for port_type in 0..4u8 {
            // The client only reports its own port in the later packets.
            let reported = if port_type >= 2 { private } else { None };
            last = state.handle(
                init("test", client, port_type, reported),
                from(port_type),
                now,
            );
        }
        last
    }

    fn connect_target(send: &Send) -> SocketAddrV4 {
        SocketAddrV4::new(
            Ipv4Addr::new(send.1[12], send.1[13], send.1[14], send.1[15]),
            u16::from_be_bytes([send.1[16], send.1[17]]),
        )
    }

    #[test]
    fn every_source_is_acknowledged_with_its_own_port_type() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        for port_type in 0..4u8 {
            let out = state.handle(
                init("test", 0, port_type, None),
                public(1, CONTROL_PORT),
                now,
            );
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].1[7], natneg::INIT_ACK);
            // The client ticks off the source named in the ack.
            assert_eq!(out[0].1[12], port_type);
        }
    }

    #[test]
    fn distinct_addresses_pair_on_the_game_port_and_retry_until_acked() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        register(
            &mut state,
            0,
            |p| public(1, if p == 0 { GAME_PORT } else { CONTROL_PORT }),
            Some(private(10)),
            now,
        );
        let last = register(
            &mut state,
            1,
            |p| public(2, if p == 0 { GAME_PORT } else { CONTROL_PORT }),
            Some(private(11)),
            now,
        );
        // The final init is acked and both clients are told about each other.
        assert_eq!(last.len(), 3);
        let to_first: Vec<_> = last
            .iter()
            .filter(|(to, _)| *to == public(1, CONTROL_PORT))
            .collect();
        assert_eq!(to_first.len(), 1);
        // Observed public addresses differ, so the routable game port is used.
        assert_eq!(connect_target(to_first[0]), public(2, GAME_PORT));
        assert_eq!(to_first[0].1[19], natneg::FINISHED_OK);

        assert_eq!(state.tick(now + CONNECT_RETRY).len(), 2);
        state.handle(
            Packet::ConnectAck {
                cookie: 99,
                client: 0,
            },
            public(1, CONTROL_PORT),
            now,
        );
        assert_eq!(state.tick(now + CONNECT_RETRY * 2).len(), 1);
    }

    #[test]
    fn shared_public_address_hands_over_the_reported_address() {
        // Two consoles behind one router cannot reach each other through it.
        let mut state = Rendezvous::default();
        let now = Instant::now();
        register(
            &mut state,
            0,
            |p| public(1, if p == 0 { GAME_PORT } else { CONTROL_PORT }),
            Some(private(10)),
            now,
        );
        let last = register(
            &mut state,
            1,
            |p| {
                public(
                    1,
                    if p == 0 {
                        GAME_PORT + 1
                    } else {
                        CONTROL_PORT + 1
                    },
                )
            },
            Some(private(11)),
            now,
        );
        let targets: Vec<_> = last
            .iter()
            .filter(|(_, bytes)| bytes[7] == natneg::CONNECT)
            .map(connect_target)
            .collect();
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&private(10)));
        assert!(targets.contains(&private(11)));
    }

    #[test]
    fn a_lone_client_is_told_its_partner_never_arrived() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        register(
            &mut state,
            0,
            |p| public(1, if p == 0 { GAME_PORT } else { CONTROL_PORT }),
            Some(private(10)),
            now,
        );
        assert!(state.tick(now + PARTNER_WAIT - CONNECT_RETRY).is_empty());
        let out = state.tick(now + PARTNER_WAIT);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, public(1, CONTROL_PORT));
        assert_eq!(out[0].1[7], natneg::CONNECT);
        assert_eq!(out[0].1[19], natneg::FINISHED_DEADBEAT_PARTNER);
        // Said once, and a late partner cannot revive the abandoned pair.
        assert!(state.tick(now + PARTNER_WAIT + CONNECT_RETRY).is_empty());
        assert!(
            state
                .handle(init("test", 1, 1, None), public(2, CONTROL_PORT), now)
                .is_empty()
        );
    }

    #[test]
    fn an_incomplete_client_is_never_paired() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        // Client 1 skips the third matchup host, so it is not ready.
        register(
            &mut state,
            0,
            |p| public(1, if p == 0 { GAME_PORT } else { CONTROL_PORT }),
            None,
            now,
        );
        for port_type in [0, 1, 2] {
            state.handle(
                init("test", 1, port_type, None),
                public(
                    2,
                    if port_type == 0 {
                        GAME_PORT
                    } else {
                        CONTROL_PORT
                    },
                ),
                now,
            );
        }
        assert!(state.tick(now + CONNECT_RETRY).is_empty());
    }

    #[test]
    fn different_games_cannot_pair_and_expire() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        for client in 0..2u8 {
            for port_type in 0..4u8 {
                assert_eq!(
                    state
                        .handle(
                            init(
                                if client == 0 { "one" } else { "two" },
                                client,
                                port_type,
                                None
                            ),
                            public(client + 1, CONTROL_PORT),
                            now
                        )
                        .len(),
                    1
                );
            }
        }
        assert!(state.tick(now + TTL).is_empty());
        assert!(state.pairs.is_empty());
    }

    #[test]
    fn cannot_replace_a_registered_source() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        state.handle(init("test", 0, 0, None), public(1, GAME_PORT), now);
        assert!(
            state
                .handle(init("test", 0, 0, None), public(2, GAME_PORT), now)
                .is_empty()
        );
        assert!(
            state
                .handle(init("test", 0, 0, None), public(1, GAME_PORT + 1), now)
                .is_empty()
        );
    }

    #[test]
    fn report_ack_is_source_bound_and_repeatable() {
        let mut state = Rendezvous::default();
        let now = Instant::now();
        state.handle(init("test", 0, 1, None), public(1, CONTROL_PORT), now);
        let report = Packet::Report {
            cookie: 99,
            client: 0,
            game: "test".into(),
            result: 1,
        };
        assert!(
            state
                .handle(report.clone(), public(2, CONTROL_PORT), now)
                .is_empty()
        );
        for _ in 0..2 {
            assert_eq!(
                state.handle(report.clone(), public(1, CONTROL_PORT), now)[0].1[7],
                natneg::REPORT_ACK
            );
        }
    }
}
