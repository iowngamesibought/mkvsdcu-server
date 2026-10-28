//! PeerChat secure registration and shared in-memory channels.
//!
//! Update 01.01 uses ordinary peerConnectA after GPCM, observed as:
//! CRYPT -> 705 -> encrypted USRIP -> 302 -> USER + NICK -> 001.
//! USER carries the SDK-encoded IP and profile; registration correlates its
//! profile and actual peer address with an authenticated GPCM session.
//!
//! The alternate SDK pre-authentication path remains supported:
//! CRYPT -> 705 -> LOGINPREAUTH -> 707 -> USRIP -> 302 -> USER + NICK -> 001.
//! Both paths then support CDKEY and channel operations. The real game's
//! ordinary path does not send LOGINPREAUTH and must not receive an unsolicited 707.
//!
//! Rooms carry the match handshake: players publish their address, profile and
//! chosen match identity as room metadata and challenge each other through it.
//! The session tracker watches those updates, but the match itself runs between
//! the consoles after NAT negotiation and is not carried here.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mkvsdcu_proto::peerchat::{self, ChatCipher, ClientCommand, MAX_LINE_BYTES};

use crate::config::Config;
use crate::session::AuthSessions;

/// Set `MKVSDCU_CHAT_TRACE=1` to log every decrypted chat line in both
/// directions. This is the only way to see what the title actually puts in a
/// challenge or in its room metadata, so it is the first thing to enable when
/// a match will not start. The lines contain player addresses and profile IDs:
/// send the output to ignored local storage only, and leave it off otherwise.
fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("MKVSDCU_CHAT_TRACE").is_some_and(|value| value == "1"))
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RANDOM_KEY_BYTES: usize = 24;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const DEAD_PEER_TIMEOUT: Duration = Duration::from_secs(180);

pub fn spawn(
    config: Config,
    sessions: Arc<AuthSessions>,
    matches: Arc<crate::matches::Matches>,
) -> Result<JoinHandle<()>, String> {
    let listener = TcpListener::bind(config.peerchat.bind)
        .map_err(|error| format!("bind peerchat listener {}: {error}", config.peerchat.bind))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("peerchat local address: {error}"))?;
    println!("[peerchat] listening on {local} (TCP, PeerChat)");

    let mut initial = RoomHub::default();
    initial.rooms.watch_sessions(matches);
    let hub = Arc::new(Mutex::new(initial));
    Ok(thread::spawn(move || {
        for accepted in listener.incoming() {
            match accepted {
                Ok(socket) => {
                    let sessions = Arc::clone(&sessions);
                    let hub = Arc::clone(&hub);
                    let secret = config.peerchat.title_secret.clone();
                    thread::spawn(move || {
                        if let Err(error) =
                            handle_connection_with_rooms(socket, &sessions, &secret, hub)
                        {
                            eprintln!("[peerchat] connection error: {error}");
                        }
                    });
                }
                Err(error) => eprintln!("[peerchat] accept error: {error}"),
            }
        }
    }))
}

/// Serve one PeerChat connection. Public so the loopback test drives the same
/// state machine as the accept loop.
pub fn handle_connection(
    socket: TcpStream,
    sessions: &AuthSessions,
    title_secret: &str,
) -> Result<(), String> {
    handle_connection_with_rooms(
        socket,
        sessions,
        title_secret,
        Arc::new(Mutex::new(RoomHub::default())),
    )
}

pub fn handle_connection_with_rooms(
    socket: TcpStream,
    sessions: &AuthSessions,
    title_secret: &str,
    hub: Arc<Mutex<RoomHub>>,
) -> Result<(), String> {
    let mut client = Client::new(socket)?;
    let peer = client.peer;

    client
        .socket
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("{peer}: peerchat read timeout: {error}"))?;
    client
        .socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("{peer}: peerchat write timeout: {error}"))?;

    let first = client
        .read_line_plain()?
        .ok_or_else(|| format!("{peer}: closed before CRYPT"))?;
    let (version, game_name) = match ClientCommand::parse(&first)
        .map_err(|error| format!("{peer}: peerchat CRYPT: {error}"))?
    {
        ClientCommand::Crypt { version, game_name } => (version.to_owned(), game_name.to_owned()),
        other => return Err(format!("{peer}: expected CRYPT, got {other:?}")),
    };
    println!("[peerchat] {peer} CRYPT des {version} game={game_name:?}");

    let out_key = random_key(title_secret)?;
    let in_key = random_key(title_secret)?;
    client.write_line_plain(&peerchat::secure_key_message("*", &out_key, &in_key))?;

    let inbound = peerchat::derive_cipher(&out_key, title_secret)
        .map_err(|error| format!("{peer}: derive inbound key: {error}"))?;
    let outbound = peerchat::derive_cipher(&in_key, title_secret)
        .map_err(|error| format!("{peer}: derive outbound key: {error}"))?;
    client.writer = Some(Arc::new(Mutex::new(EncryptedWriter {
        socket: client.socket.try_clone().map_err(|e| e.to_string())?,
        cipher: outbound,
    })));
    client.cipher = Some(CipherPair { inbound });

    let registration = read_registration(&mut client, sessions)?;
    let session = registration.session;
    let mut nick = registration.nick;
    let writer = client.writer.as_ref().unwrap().clone();
    {
        let mut state = hub.lock().map_err(|_| "room hub poisoned")?;
        if state.writers.contains_key(&nick) {
            return Err("duplicate active PeerChat identity".to_owned());
        }
        state.writers.insert(nick.clone(), writer);
    }
    let mut membership = Membership {
        hub: hub.clone(),
        nick: nick.clone(),
    };
    if registration.preauthenticated {
        client.write_line_encrypted(&peerchat::login_message(
            &nick,
            session.user_id,
            session.profile_id,
        ))?;
        println!(
            "[peerchat] {peer} LOGINPREAUTH accepted profileid={} userid={}",
            session.profile_id, session.user_id
        );
    } else {
        println!(
            "[peerchat] {peer} secure USER/NICK registration correlated profileid={}",
            session.profile_id
        );
    }
    if let Some((user, real_name)) = &registration.user {
        hub.lock()
            .map_err(|_| "room hub poisoned")?
            .rooms
            .set_identity(&nick, user, &peer.ip().to_string(), real_name);
    }
    client
        .socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| format!("{peer}: clear peerchat read timeout: {error}"))?;

    let mut user_seen = registration.user.is_some();
    let mut nick_seen = !registration.preauthenticated;
    let mut welcomed = false;
    maybe_welcome(&mut client, &nick, user_seen, nick_seen, &mut welcomed)?;
    client.heartbeat = Some(Heartbeat::new(Instant::now()));
    while let Some(line) = client.read_line()? {
        if trace_enabled() {
            println!("[peerchat] trace {peer} nick={nick:?} in  {line:?}");
        }
        let command = match ClientCommand::parse(&line) {
            Ok(command) => command,
            Err(error) => {
                eprintln!("[peerchat] {peer} invalid line: {error}");
                continue;
            }
        };
        match command {
            ClientCommand::UserIp => {
                let ip = peer.ip().to_string();
                client.write_line_encrypted(&peerchat::user_ip_message(&nick, "*", &ip))?;
            }
            ClientCommand::User { user, real_name } => {
                if welcomed {
                    client
                        .write_line_encrypted(&format!(":s 462 {nick} :Already registered\r\n"))?;
                    continue;
                }
                if user.is_empty() || user.contains(['!', '@', ':', ' ']) {
                    return Err("invalid USER prefix component".to_owned());
                }
                hub.lock()
                    .map_err(|_| "room hub poisoned")?
                    .rooms
                    .set_identity(&nick, user, &peer.ip().to_string(), real_name.unwrap_or(""));
                user_seen = true;
                println!("[peerchat] {peer} USER {user:?}");
                maybe_welcome(&mut client, &nick, user_seen, nick_seen, &mut welcomed)?;
            }
            ClientCommand::Nick { nick: requested } => {
                if welcomed {
                    let dispatch = hub
                        .lock()
                        .map_err(|_| "room hub poisoned")?
                        .dispatch
                        .clone();
                    let _ordered = dispatch.lock().map_err(|_| "room dispatch poisoned")?;
                    let result = {
                        let mut state = hub.lock().map_err(|_| "room hub poisoned")?;
                        if requested != nick && state.writers.contains_key(requested) {
                            Err("Nickname already in use".to_owned())
                        } else {
                            state.rooms.rename(&nick, requested).inspect(|_| {
                                if let Some(writer) = state.writers.remove(&nick) {
                                    state.writers.insert(requested.to_owned(), writer);
                                }
                            })
                        }
                    };
                    match result {
                        Ok(deliveries) => {
                            nick = requested.to_owned();
                            membership.nick = nick.clone();
                            deliver(&hub, deliveries);
                        }
                        Err(error) => {
                            let code = if error == "Nickname already in use" {
                                433
                            } else {
                                432
                            };
                            client.write_line_encrypted(&format!(
                                ":s {code} {nick} {requested} :{error}\r\n"
                            ))?;
                        }
                    }
                    continue;
                }
                nick_seen = true;
                if requested != "*" {
                    println!("[peerchat] {peer} requested nick {requested:?}, using {nick:?}");
                }
                maybe_welcome(&mut client, &nick, user_seen, nick_seen, &mut welcomed)?;
            }
            ClientCommand::CdKey { .. } => {
                client.write_line_encrypted(&peerchat::cdkey_message(&nick, 0, "Accepted"))?;
                println!(
                    "[peerchat] {peer} CDKEY accepted profileid={}",
                    session.profile_id
                );
            }
            ClientCommand::Ping => {
                let parsed = peerchat::parse_line(&line).map_err(|e| e.to_string())?;
                client.write_line_encrypted(&format!(
                    ":s PONG s :{}\r\n",
                    parsed.params.first().copied().unwrap_or("s")
                ))?;
            }
            ClientCommand::Quit => {
                println!("[peerchat] {peer} QUIT");
                break;
            }
            ClientCommand::Other(command) => {
                if command == "PONG" {
                    continue;
                }
                if matches!(
                    command,
                    "LIST"
                        | "JOIN"
                        | "NAMES"
                        | "PART"
                        | "TOPIC"
                        | "MODE"
                        | "SETGROUP"
                        | "PRIVMSG"
                        | "NOTICE"
                        | "UTM"
                        | "ATM"
                        | "WHO"
                        | "WHOIS"
                        | "GETCKEY"
                        | "SETCKEY"
                        | "GETCHANKEY"
                        | "SETCHANKEY"
                        | "GETKEY"
                        | "SETKEY"
                        | "INVITE"
                        | "KICK"
                ) {
                    if !welcomed {
                        client
                            .write_line_encrypted(&format!(":s 451 {nick} :Register first\r\n"))?;
                        continue;
                    }
                    let message = peerchat::parse_line(&line).map_err(|e| e.to_string())?;
                    // A match is set up by a challenge and its reply, sent as
                    // player-targeted peer messages. Watch them go past so a
                    // later result can be tied to the pairing they formed.
                    if matches!(command, "UTM" | "ATM")
                        && let Some(target) = message.params.first()
                        && !target.starts_with('#')
                        && let Some(body) = message.params.get(1)
                        && let Some(peer_message) = crate::matches::parse_peer_message(body)
                    {
                        let tracker = hub
                            .lock()
                            .map_err(|_| "room hub poisoned")?
                            .rooms
                            .session_tracker();
                        if let Some(tracker) = tracker {
                            match peer_message.msg {
                                crate::matches::MSG_CHALLENGE => {
                                    tracker.challenge(&nick, target, &peer_message)
                                }
                                crate::matches::MSG_ANSWER => {
                                    tracker.answer(&nick, target, &peer_message);
                                }
                                other => println!(
                                    "[match] profileid={} peer message msg={other} not a challenge",
                                    session.profile_id
                                ),
                            }
                            // Nothing runs on a timer: a challenge or an
                            // answer is the event that drives a result
                            // still waiting on a silent opponent.
                            crate::gstats_listener::flush_due_results(&tracker, sessions);
                        }
                    }
                    let dispatch = hub
                        .lock()
                        .map_err(|_| "room hub poisoned")?
                        .dispatch
                        .clone();
                    let _ordered = dispatch.lock().map_err(|_| "room dispatch poisoned")?;
                    let deliveries = hub
                        .lock()
                        .map_err(|_| "room hub poisoned")?
                        .rooms
                        .command(&nick, &message);
                    let codes: std::collections::BTreeSet<_> = deliveries
                        .iter()
                        .filter_map(|(_, response)| response.split_whitespace().nth(1))
                        .filter(|code| code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()))
                        .collect();
                    println!(
                        "[peerchat] profileid={} command={command} params={} deliveries={} codes={codes:?}",
                        session.profile_id,
                        message.params.len(),
                        deliveries.len()
                    );
                    deliver(&hub, deliveries);
                } else {
                    println!("[peerchat] {peer} unsupported command {command:?}");
                    client.write_line_encrypted(&format!(
                        ":s 421 {nick} {command} :Unknown command\r\n"
                    ))?;
                }
            }
            ClientCommand::Crypt { .. } | ClientCommand::LoginPreAuth { .. } => {
                println!("[peerchat] {peer} ignored repeated handshake command");
            }
        }
    }

    Ok(())
}

struct Registration {
    session: crate::session::AuthSession,
    nick: String,
    user: Option<(String, String)>,
    preauthenticated: bool,
}

fn read_registration(client: &mut Client, sessions: &AuthSessions) -> Result<Registration, String> {
    let mut user: Option<(String, String)> = None;
    let mut nick: Option<String> = None;
    // Bound pre-registration chatter; socket also retains its handshake timeout.
    for _ in 0..16 {
        let line = client
            .read_line()?
            .ok_or("closed before PeerChat registration")?;
        match ClientCommand::parse(&line).map_err(|error| error.to_string())? {
            ClientCommand::UserIp => {
                client.write_line_encrypted(&peerchat::user_ip_message(
                    "*",
                    "*",
                    &client.peer.ip().to_string(),
                ))?;
            }
            ClientCommand::User {
                user: value,
                real_name,
            } => {
                if value.is_empty() || value.contains(['!', '@', ':', ' ']) {
                    return Err("invalid USER prefix component".to_owned());
                }
                user = Some((value.to_owned(), real_name.unwrap_or("").to_owned()));
            }
            ClientCommand::Nick { nick: value } => {
                if value.is_empty()
                    || value == "*"
                    || value.contains(['!', '@', ':', ' ', '#', ','])
                {
                    return Err("invalid ordinary PeerChat nickname".to_owned());
                }
                nick = Some(value.to_owned());
            }
            ClientCommand::LoginPreAuth {
                auth_token,
                partner_challenge,
            } => {
                let Some(session) = sessions.begin_gp_login(auth_token) else {
                    client.write_line_encrypted(&peerchat::login_failed_message(
                        "*",
                        "unknown auth token",
                    ))?;
                    return Err("unknown or expired auth token".to_owned());
                };
                if session.partner_challenge != partner_challenge {
                    client.write_line_encrypted(&peerchat::login_failed_message(
                        "*",
                        "partner challenge mismatch",
                    ))?;
                    return Err("partner challenge mismatch".to_owned());
                }
                return Ok(Registration {
                    nick: format!("player{}", session.profile_id),
                    session,
                    user,
                    preauthenticated: true,
                });
            }
            ClientCommand::Quit => return Err("quit before registration".to_owned()),
            _ => return Err("unexpected command before PeerChat registration".to_owned()),
        }
        if let (Some((value, _)), Some(nickname)) = (&user, &nick) {
            let profile_id = user_profile_id(value).ok_or("invalid encoded USER profile")?;
            let session = sessions
                .for_peer_profile(client.peer.ip(), profile_id)
                .ok_or("USER profile has no matching authenticated GPCM connection")?;
            return Ok(Registration {
                session,
                nick: nickname.clone(),
                user,
                preauthenticated: false,
            });
        }
    }
    Err("too many commands before PeerChat registration".to_owned())
}

// Peer SDK piMangleUser uses X<8 encoded-IP characters>X|<decimal profile>.
// Correlate profile and actual socket address with GPCM; never trust USER alone.
fn user_profile_id(user: &str) -> Option<u32> {
    let bytes = user.as_bytes();
    if bytes.len() < 12 || bytes[0] != b'X' || bytes[9] != b'X' || bytes[10] != b'|' {
        return None;
    }
    let profile = user.get(11..)?;
    if !profile.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    profile
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0 && *value <= i32::MAX as u32)
}
fn maybe_welcome(
    client: &mut Client,
    nick: &str,
    user_seen: bool,
    nick_seen: bool,
    welcomed: &mut bool,
) -> Result<(), String> {
    if *welcomed || !user_seen || !nick_seen {
        return Ok(());
    }
    client.write_line_encrypted(&peerchat::welcome_message(nick, "Welcome to MKVSDCU"))?;
    *welcomed = true;
    println!("[peerchat] {} connected as {nick}", client.peer);
    Ok(())
}

struct CipherPair {
    inbound: ChatCipher,
}

struct Client {
    socket: TcpStream,
    peer: SocketAddr,
    pending: Vec<u8>,
    cipher: Option<CipherPair>,
    writer: Option<Arc<Mutex<EncryptedWriter>>>,
    heartbeat: Option<Heartbeat>,
}

struct Heartbeat {
    last_activity: Instant,
    ping_sent: bool,
}
#[derive(Debug, PartialEq, Eq)]
enum HeartbeatAction {
    Wait,
    Ping,
    Disconnect,
}
impl Heartbeat {
    fn new(now: Instant) -> Self {
        Self {
            last_activity: now,
            ping_sent: false,
        }
    }
    fn received(&mut self, now: Instant) {
        self.last_activity = now;
        self.ping_sent = false;
    }
    fn tick(&mut self, now: Instant) -> HeartbeatAction {
        let idle = now.duration_since(self.last_activity);
        if idle >= DEAD_PEER_TIMEOUT {
            return HeartbeatAction::Disconnect;
        }
        if idle >= HEARTBEAT_INTERVAL && !self.ping_sent {
            self.ping_sent = true;
            return HeartbeatAction::Ping;
        }
        HeartbeatAction::Wait
    }
}

impl Client {
    fn new(socket: TcpStream) -> Result<Self, String> {
        let peer = socket
            .peer_addr()
            .map_err(|error| format!("peerchat peer address: {error}"))?;
        Ok(Self {
            socket,
            peer,
            pending: Vec::new(),
            cipher: None,
            writer: None,
            heartbeat: None,
        })
    }

    fn read_line_plain(&mut self) -> Result<Option<String>, String> {
        self.read_line_inner(false)
    }

    fn read_line(&mut self) -> Result<Option<String>, String> {
        self.read_line_inner(true)
    }

    fn read_line_inner(&mut self, encrypted: bool) -> Result<Option<String>, String> {
        loop {
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                return String::from_utf8(line)
                    .map(Some)
                    .map_err(|_| format!("{}: PeerChat line is not valid UTF-8", self.peer));
            }
            if self.pending.len() > MAX_LINE_BYTES + 2 {
                return Err(format!(
                    "{}: PeerChat line exceeds {MAX_LINE_BYTES} bytes",
                    self.peer
                ));
            }
            let mut chunk = [0u8; 1024];
            let read = match self.socket.read(&mut chunk) {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && self.heartbeat.is_some() =>
                {
                    match self.heartbeat.as_mut().unwrap().tick(Instant::now()) {
                        HeartbeatAction::Ping => self.write_line_encrypted("PING :s\r\n")?,
                        HeartbeatAction::Disconnect => {
                            return Err(format!("{}: PeerChat heartbeat expired", self.peer));
                        }
                        HeartbeatAction::Wait => {}
                    }
                    continue;
                }
                Err(error) => return Err(format!("{}: read PeerChat line: {error}", self.peer)),
            };
            if read == 0 {
                if self.pending.is_empty() {
                    return Ok(None);
                }
                return Err(format!("{}: closed mid-line", self.peer));
            }
            if encrypted {
                let cipher = self
                    .cipher
                    .as_mut()
                    .ok_or_else(|| format!("{}: encrypted read before CRYPT", self.peer))?;
                cipher.inbound.apply(&mut chunk[..read]);
            }
            if let Some(heartbeat) = &mut self.heartbeat {
                heartbeat.received(Instant::now());
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    fn write_line_plain(&mut self, line: &str) -> Result<(), String> {
        self.socket
            .write_all(line.as_bytes())
            .map_err(|error| format!("{}: write PeerChat line: {error}", self.peer))
    }

    fn write_line_encrypted(&mut self, line: &str) -> Result<(), String> {
        self.writer
            .as_ref()
            .ok_or("encrypted write before CRYPT")?
            .lock()
            .map_err(|_| "PeerChat writer poisoned")?
            .send(line)
    }
}

/// Generate a printable key string that cannot contain a zero after the XOR
/// with the title secret. The pinned client measures the key length before the
/// XOR, so a zero byte is valid there; avoiding it is a defensive measure for
/// builds that might measure the string after the XOR.
fn random_key(secret: &str) -> Result<String, String> {
    let secret = secret.as_bytes();
    if secret.is_empty() {
        return Err("PeerChat title secret is empty".to_owned());
    }
    let mut bytes = vec![0u8; RANDOM_KEY_BYTES];
    openssl::rand::rand_bytes(&mut bytes).map_err(|error| format!("OpenSSL RNG: {error}"))?;
    let key: String = bytes
        .into_iter()
        .enumerate()
        .map(|(index, byte)| {
            let mut value = b'!' + byte % 94;
            if value == secret[index % secret.len()] {
                value = if value == b'~' { b'!' } else { value + 1 };
            }
            char::from(value)
        })
        .collect();
    Ok(key)
}

struct EncryptedWriter {
    socket: TcpStream,
    cipher: ChatCipher,
}
impl EncryptedWriter {
    fn send(&mut self, line: &str) -> Result<(), String> {
        let mut bytes = line.as_bytes().to_vec();
        self.cipher.apply(&mut bytes);
        self.socket.write_all(&bytes).map_err(|e| e.to_string())
    }
}
#[derive(Default)]
pub struct RoomHub {
    dispatch: Arc<Mutex<()>>,
    rooms: crate::rooms::Rooms,
    writers: HashMap<String, Arc<Mutex<EncryptedWriter>>>,
}
fn deliver(hub: &Arc<Mutex<RoomHub>>, deliveries: Vec<crate::rooms::Delivery>) {
    for (nick, line) in deliveries {
        if trace_enabled() {
            println!("[peerchat] trace to={nick:?} out {line:?}");
        }
        let writer = hub.lock().ok().and_then(|h| h.writers.get(&nick).cloned());
        if let Some(writer) = writer
            && let Ok(mut writer) = writer.lock()
            && let Err(error) = writer.send(&line)
        {
            eprintln!("[peerchat] channel delivery failed: {error}");
            let _ = writer.socket.shutdown(std::net::Shutdown::Both);
        }
    }
}
struct Membership {
    hub: Arc<Mutex<RoomHub>>,
    nick: String,
}
impl Drop for Membership {
    fn drop(&mut self) {
        let dispatch = match self.hub.lock() {
            Ok(hub) => hub.dispatch.clone(),
            Err(_) => return,
        };
        let Ok(_ordered) = dispatch.lock() else {
            return;
        };
        let deliveries = if let Ok(mut hub) = self.hub.lock() {
            hub.writers.remove(&self.nick);
            hub.rooms.disconnect(&self.nick)
        } else {
            Vec::new()
        };
        deliver(&self.hub, deliveries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    const SECRET: &str = "0123456789";

    #[test]
    fn heartbeat_expires_dead_peers_and_refreshes_on_traffic() {
        let start = Instant::now();
        let mut heartbeat = Heartbeat::new(start);
        assert_eq!(heartbeat.tick(start), HeartbeatAction::Wait);
        assert_eq!(
            heartbeat.tick(start + HEARTBEAT_INTERVAL),
            HeartbeatAction::Ping
        );
        assert_eq!(
            heartbeat.tick(start + HEARTBEAT_INTERVAL),
            HeartbeatAction::Wait
        );
        heartbeat.received(start + HEARTBEAT_INTERVAL);
        assert_eq!(
            heartbeat.tick(start + HEARTBEAT_INTERVAL),
            HeartbeatAction::Wait
        );
        assert_eq!(
            heartbeat.tick(start + HEARTBEAT_INTERVAL + DEAD_PEER_TIMEOUT),
            HeartbeatAction::Disconnect
        );
    }

    #[test]
    fn loopback_preauth_login_reaches_welcome() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("token-1".to_owned(), "challenge-1".to_owned());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_sessions = Arc::clone(&sessions);
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle_connection(socket, &server_sessions, SECRET).unwrap();
        });

        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client = TestClient {
            socket,
            pending: Vec::new(),
            inbound: None,
            outbound: None,
        };

        client.send_plain("CRYPT des 1 mkvsdcu\r\n");
        let secure = client.read_plain();
        assert!(secure.starts_with(":s 705 * "), "{secure}");
        let fields: Vec<&str> = secure.trim_end().split(' ').collect();
        assert_eq!(fields.len(), 5, "{secure}");
        let out_key = fields[3];
        let in_key = fields[4];
        client.outbound = Some(peerchat::derive_cipher(out_key, SECRET).unwrap());
        client.inbound = Some(peerchat::derive_cipher(in_key, SECRET).unwrap());

        client.send_encrypted("LOGINPREAUTH token-1 challenge-1\r\n");
        let login = client.read_encrypted();
        assert_eq!(login, ":s 707 player1 1 1\r\n");

        client.send_encrypted("USRIP\r\n");
        let ip = client.read_encrypted();
        assert!(ip.starts_with(":s 302 player1 :*@127.0.0.1"), "{ip}");

        client.send_encrypted("USER abc 127.0.0.1 peerchat :MKVSDCU\r\n");
        client.send_encrypted("NICK *\r\n");
        let welcome = client.read_encrypted();
        assert!(welcome.starts_with(":s 001 player1 :"), "{welcome}");

        client.send_encrypted("CDKEY 1234\r\n");
        let cdkey = client.read_encrypted();
        assert_eq!(cdkey, ":s 706 player1 0 :Accepted\r\n");

        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn unknown_token_is_rejected_after_the_secure_key_line() {
        let sessions = Arc::new(AuthSessions::new());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let _ = handle_connection(socket, &sessions, SECRET);
        });

        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client = TestClient {
            socket,
            pending: Vec::new(),
            inbound: None,
            outbound: None,
        };
        client.send_plain("CRYPT des 1 mkvsdcu\r\n");
        let secure = client.read_plain();
        let fields: Vec<&str> = secure.trim_end().split(' ').collect();
        client.outbound = Some(peerchat::derive_cipher(fields[3], SECRET).unwrap());
        client.inbound = Some(peerchat::derive_cipher(fields[4], SECRET).unwrap());
        client.send_encrypted("LOGINPREAUTH missing challenge-1\r\n");
        assert_eq!(client.read_encrypted(), ":s 708 * :unknown auth token\r\n");
        server.join().unwrap();
    }

    fn secure_test_client(address: SocketAddr) -> TestClient {
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut client = TestClient {
            socket,
            pending: Vec::new(),
            inbound: None,
            outbound: None,
        };
        client.send_plain("CRYPT des 1 test\r\n");
        let secure = client.read_plain();
        let fields: Vec<_> = secure.trim_end().split(' ').collect();
        client.outbound = Some(peerchat::derive_cipher(fields[3], SECRET).unwrap());
        client.inbound = Some(peerchat::derive_cipher(fields[4], SECRET).unwrap());
        client
    }

    #[test]
    fn secure_usrip_user_nick_uses_existing_gp_profile() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("ordinary".into(), "partner".into());
        sessions.bind_gp_peer("ordinary", "127.0.0.1".parse().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle_connection(socket, &sessions, SECRET).unwrap();
        });
        let mut client = secure_test_client(address);
        client.send_encrypted("USRIP\r\n");
        assert!(client.read_encrypted().contains(" 302 * :*@127.0.0.1"));
        client.send_encrypted("USER XabcdefghX|1 0 0 :Console\r\nNICK console_nick\r\n");
        assert!(client.read_encrypted().starts_with(":s 001 console_nick :"));
        client.send_encrypted("WHO console_nick\r\n");
        let who = client.read_encrypted();
        assert!(who.contains("XabcdefghX|1 127.0.0.1 s console_nick"));
        assert!(client.read_encrypted().contains(" 315 "));
        client.send_encrypted("CDKEY 1234\r\n");
        assert!(client.read_encrypted().contains(" 706 console_nick 0 "));
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn ordinary_registration_rejects_uncorrelated_profile() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("ordinary".into(), "partner".into());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle_connection(socket, &sessions, SECRET).unwrap_err()
        });
        let mut client = secure_test_client(address);
        client.send_encrypted("USER XabcdefghX|1 0 0 :Console\r\nNICK console_nick\r\n");
        assert!(
            server
                .join()
                .unwrap()
                .contains("no matching authenticated GPCM")
        );
    }

    #[test]
    fn usrip_before_preauth_is_supported() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("token".into(), "partner".into());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle_connection(socket, &sessions, SECRET).unwrap();
        });
        let mut client = secure_test_client(address);
        client.send_encrypted("USRIP\r\n");
        assert!(client.read_encrypted().contains(" 302 "));
        client.send_encrypted("LOGINPREAUTH token partner\r\n");
        assert!(client.read_encrypted().contains(" 707 player1 1 1"));
        client.send_encrypted("USER test 0 0 :test\r\nNICK *\r\n");
        assert!(client.read_encrypted().contains(" 001 player1 "));
        drop(client);
        server.join().unwrap();
    }

    fn connect_test(address: SocketAddr, token: &str, challenge: &str) -> TestClient {
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut client = TestClient {
            socket,
            pending: Vec::new(),
            inbound: None,
            outbound: None,
        };
        client.send_plain("CRYPT des 1 test\r\n");
        let secure = client.read_plain();
        let fields: Vec<_> = secure.trim_end().split(' ').collect();
        client.outbound = Some(peerchat::derive_cipher(fields[3], SECRET).unwrap());
        client.inbound = Some(peerchat::derive_cipher(fields[4], SECRET).unwrap());
        client.send_encrypted(&format!("LOGINPREAUTH {token} {challenge}\r\n"));
        assert!(client.read_encrypted().contains(" 707 "));
        client.send_encrypted("USER user 0 0 :test\r\nNICK *\r\n");
        assert!(client.read_encrypted().contains(" 001 "));
        client
    }

    #[test]
    fn encrypted_two_client_rooms_broadcast_and_disconnect() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("one".to_owned(), "c1".to_owned());
        sessions.insert("two".to_owned(), "c2".to_owned());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let hub = Arc::new(Mutex::new(RoomHub::default()));
        let server = thread::spawn(move || {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let (socket, _) = listener.accept().unwrap();
                let sessions = sessions.clone();
                let hub = hub.clone();
                workers.push(thread::spawn(move || {
                    handle_connection_with_rooms(socket, &sessions, SECRET, hub).unwrap()
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let mut a = connect_test(address, "one", "c1");
        let mut b = connect_test(address, "two", "c2");
        a.send_encrypted("WHO player2\r\n");
        let who = a.read_encrypted();
        let parsed = peerchat::parse_line(&who).unwrap();
        assert_eq!(parsed.command, "352");
        assert_eq!(parsed.params.len(), 8);
        assert_eq!(parsed.params[2], "user");
        assert_eq!(parsed.params[3], "127.0.0.1");
        assert_eq!(parsed.params[5], "player2");
        assert!(a.read_encrypted().contains(" 315 "));
        for command in ["PRIVMSG", "NOTICE", "UTM", "ATM"] {
            a.send_encrypted(&format!("{command} player2 :opaque data\r\n"));
            assert_eq!(
                b.read_encrypted(),
                format!(":player1!user@127.0.0.1 {command} player2 :opaque data\r\n")
            );
        }
        a.send_encrypted("JOIN #test\r\n");
        while !a.read_encrypted().contains(" 366 ") {}
        b.send_encrypted("JOIN #test\r\n");
        assert!(a.read_encrypted().contains("player2!user@127.0.0.1 JOIN"));
        while !b.read_encrypted().contains(" 366 ") {}
        b.send_encrypted("UTM #test :opaque launch\r\n");
        assert!(a.read_encrypted().contains("UTM #test :opaque launch"));
        b.send_encrypted("PRIVMSG #test :hello\r\n");
        assert!(a.read_encrypted().contains("PRIVMSG #test :hello"));
        a.send_encrypted("TOPIC #test :visible\r\n");
        assert!(a.read_encrypted().contains("TOPIC #test :visible"));
        assert!(b.read_encrypted().contains("TOPIC #test :visible"));
        drop(a);
        let first = b.read_encrypted();
        let second = b.read_encrypted();
        assert!(first.contains("MODE #test +o player2"));
        assert!(second.contains("QUIT"));
        b.send_encrypted("LIST\r\n");
        assert!(b.read_encrypted().contains(" 321 "));
        assert!(b.read_encrypted().contains("#test 1 :visible"));
        assert!(b.read_encrypted().contains(" 323 "));
        b.send_encrypted("PART #test\r\n");
        assert!(b.read_encrypted().contains("PART #test"));
        b.send_encrypted("LIST\r\n");
        assert!(b.read_encrypted().contains(" 321 "));
        assert!(b.read_encrypted().contains(" 323 "));
        drop(b);
        server.join().unwrap();
    }

    // Exercise actual encrypted socket dispatch and SDK numeric/cookie contracts,
    // not merely the in-memory room methods. Fixtures are entirely synthetic.
    fn sdk_exchange(client: &mut TestClient, commands: &str) -> Vec<String> {
        client.send_encrypted(&format!("{commands}PING :acceptance_barrier\r\n"));
        let mut lines = Vec::new();
        loop {
            let line = client.read_encrypted();
            let parsed = peerchat::parse_line(&line).unwrap();
            if parsed.command == "PONG" {
                assert!(parsed.params.contains(&"acceptance_barrier"));
                return lines;
            }
            lines.push(line);
            assert!(lines.len() < 100, "unbounded reply stream");
        }
    }
    fn numeric(lines: &[String], code: &str) -> Vec<Vec<String>> {
        lines
            .iter()
            .filter_map(|line| {
                let parsed = peerchat::parse_line(line).unwrap();
                (parsed.command == code)
                    .then(|| parsed.params.iter().map(|p| (*p).to_owned()).collect())
            })
            .collect()
    }
    // Independent game-shaped consumer: the generic SDK accepts four IRC
    // fields, then the game's room callback looks up topic/limit in field 4.
    // A syntactically valid 322 with a plain topic is not a visible room.
    fn visible_game_rooms(lines: &[String]) -> Vec<(String, usize, String, usize)> {
        numeric(lines, "322")
            .into_iter()
            .filter_map(|row| {
                if row.len() != 4 {
                    return None;
                }
                let fields: Vec<_> = row[3].strip_prefix('\\')?.split('\\').collect();
                if !fields.len().is_multiple_of(2) {
                    return None;
                }
                let topic = fields.as_chunks::<2>().0.iter().find(|p| p[0] == "topic")?[1];
                let limit = fields.as_chunks::<2>().0.iter().find(|p| p[0] == "limit")?[1]
                    .parse()
                    .ok()?;
                Some((
                    row[1].clone(),
                    row[2].parse().ok()?,
                    topic.to_owned(),
                    limit,
                ))
            })
            .collect()
    }
    #[test]
    fn encrypted_sdk_room_lifecycle_metadata_and_management() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("alpha".into(), "one".into());
        sessions.insert("bravo".into(), "two".into());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let hub = Arc::new(Mutex::new(RoomHub::default()));
        let server = thread::spawn(move || {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let (socket, _) = listener.accept().unwrap();
                let sessions = sessions.clone();
                let hub = hub.clone();
                workers.push(thread::spawn(move || {
                    handle_connection_with_rooms(socket, &sessions, SECRET, hub).unwrap()
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let mut a = connect_test(address, "alpha", "one");
        let mut b = connect_test(address, "bravo", "two");
        assert_eq!(
            numeric(&sdk_exchange(&mut a, "JOIN #synthetic_lobby\r\n"), "366").len(),
            1
        );
        assert_eq!(
            numeric(&sdk_exchange(&mut b, "JOIN #synthetic_lobby\r\n"), "366").len(),
            1
        );
        sdk_exchange(&mut a, "");
        let sent = sdk_exchange(
            &mut a,
            "SETCKEY #synthetic_lobby player1 :\\b_ready\\1\\score\\7\r\n",
        );
        let changed = numeric(&sent, "702");
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].len(), 5);
        assert_eq!(changed[0][3], "BCAST");
        assert_eq!(changed[0][4], "\\b_ready\\1");
        let received = sdk_exchange(
            &mut b,
            "GETCKEY #synthetic_lobby * 001 0 :\\b_ready\\score\r\n",
        );
        let rows = numeric(&received, "702");
        assert!(
            rows.iter()
                .any(|r| r[2] == "player1" && r[3] == "001" && r[4] == "\\1\\7")
        );
        assert!(rows.iter().all(|r| r.len() == 5));
        let ends = numeric(&received, "703");
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].len(), 4);
        assert_eq!(ends[0][2], "001");
        sdk_exchange(&mut a, "SETKEY :\\status\\online\r\n");
        let globals = numeric(
            &sdk_exchange(&mut b, "GETKEY player1 002 0 :\\status\r\n"),
            "700",
        );
        assert_eq!(globals[0], vec!["player2", "player1", "002", "\\online"]);
        for body in ["hello lobby", "\x01ACTION waves\x01"] {
            sdk_exchange(&mut a, &format!("PRIVMSG #synthetic_lobby :{body}\r\n"));
            let lines = sdk_exchange(&mut b, "");
            assert!(
                lines
                    .iter()
                    .any(|l| l.ends_with(&format!("PRIVMSG #synthetic_lobby :{body}\r\n")))
            );
        }
        sdk_exchange(
            &mut a,
            "JOIN #synthetic_room\r\nMODE #synthetic_room -i+p-s-m-n-t+l-e 8\r\nSETGROUP #synthetic_room synthetic_m1\r\nTOPIC #synthetic_room :Synthetic room metadata\r\nSETCHANKEY #synthetic_room :\\b_state\\waiting\\map\\synthetic\r\n",
        );
        let listed = sdk_exchange(&mut b, "LIST synthetic_m1 k\r\n");
        let rooms = numeric(&listed, "322");
        assert_eq!(rooms.len(), 1);
        assert_eq!(
            visible_game_rooms(&listed),
            vec![(
                "#synthetic_room".into(),
                1,
                "Synthetic room metadata".into(),
                8
            )]
        );
        assert!(
            visible_game_rooms(&[
                ":s 322 player2 #synthetic_room 1 :Synthetic room metadata\r\n".into()
            ])
            .is_empty()
        );
        let plain = sdk_exchange(&mut b, "LIST #synthetic_room\r\n");
        assert_eq!(numeric(&plain, "322")[0][3], "Synthetic room metadata");
        assert_eq!(numeric(&listed, "323").len(), 1);
        let properties = numeric(
            &sdk_exchange(&mut b, "GETCHANKEY #synthetic_room 003 0 :\\map\\b_*\r\n"),
            "704",
        );
        assert_eq!(properties[0].len(), 4);
        assert_eq!(properties[0][2], "003");
        assert_eq!(properties[0][3], "\\synthetic\\b_state\\waiting");
        assert_eq!(
            numeric(&sdk_exchange(&mut b, "JOIN #synthetic_room\r\n"), "366").len(),
            1
        );
        sdk_exchange(&mut a, "");
        // A member that only joined still configures the room: both consoles
        // apply their own room settings while setting a match up.
        assert!(
            numeric(
                &sdk_exchange(&mut b, "MODE #synthetic_room +k joinerkey\r\n"),
                "482"
            )
            .is_empty()
        );
        // Standing over another member is still operator-only.
        assert_eq!(
            numeric(
                &sdk_exchange(&mut b, "MODE #synthetic_room +o b\r\n"),
                "482"
            )
            .len(),
            1
        );
        for command in ["UTM", "ATM"] {
            sdk_exchange(
                &mut a,
                &format!("{command} #synthetic_room :opaque synthetic payload\r\n"),
            );
            assert!(
                sdk_exchange(&mut b, "")
                    .iter()
                    .any(|l| l.ends_with(&format!(
                        "{command} #synthetic_room :opaque synthetic payload\r\n"
                    )))
            );
        }
        sdk_exchange(
            &mut a,
            "MODE #synthetic_room +ikl secret 2\r\nTOPIC #synthetic_room :Changed room metadata\r\n",
        );
        sdk_exchange(&mut b, "");
        assert_eq!(
            visible_game_rooms(&sdk_exchange(&mut b, "LIST synthetic_m1 k\r\n")),
            vec![(
                "#synthetic_room".into(),
                2,
                "Changed room metadata".into(),
                2
            )]
        );
        sdk_exchange(&mut b, "PART #synthetic_room\r\n");
        sdk_exchange(&mut a, "");
        assert_eq!(
            numeric(
                &sdk_exchange(&mut b, "JOIN #synthetic_room secret\r\n"),
                "473"
            )
            .len(),
            1
        );
        let invited = sdk_exchange(&mut a, "INVITE player2 #synthetic_room\r\n");
        assert_eq!(numeric(&invited, "341").len(), 1);
        assert!(
            sdk_exchange(&mut b, "")
                .iter()
                .any(|l| l.contains(" INVITE player2 :#synthetic_room"))
        );
        assert_eq!(
            numeric(
                &sdk_exchange(&mut b, "JOIN #synthetic_room secret\r\n"),
                "366"
            )
            .len(),
            1
        );
        sdk_exchange(&mut a, "");
        sdk_exchange(&mut a, "KICK #synthetic_room player2 :managed removal\r\n");
        assert!(
            sdk_exchange(&mut b, "")
                .iter()
                .any(|l| l.contains(" KICK #synthetic_room player2 :managed removal"))
        );
        sdk_exchange(&mut a, "MODE #synthetic_room -ik\r\n");
        assert_eq!(
            numeric(&sdk_exchange(&mut b, "JOIN #synthetic_room\r\n"), "366").len(),
            1
        );
        sdk_exchange(&mut a, "");
        sdk_exchange(&mut a, "PART #synthetic_room\r\n");
        assert!(
            sdk_exchange(&mut b, "")
                .iter()
                .any(|l| l.contains("MODE #synthetic_room +o player2"))
        );
        assert!(
            sdk_exchange(&mut b, "TOPIC #synthetic_room :Updated by successor\r\n")
                .iter()
                .any(|l| l.contains("TOPIC #synthetic_room :Updated by successor"))
        );
        assert_eq!(
            visible_game_rooms(&sdk_exchange(&mut a, "LIST synthetic_m1 k\r\n")),
            vec![(
                "#synthetic_room".into(),
                1,
                "Updated by successor".into(),
                2
            )]
        );
        sdk_exchange(&mut b, "PART #synthetic_room\r\n");
        let deleted = sdk_exchange(&mut a, "LIST synthetic_m1 k\r\n");
        assert!(numeric(&deleted, "322").is_empty());
        assert!(visible_game_rooms(&deleted).is_empty());
        assert_eq!(numeric(&deleted, "323").len(), 1);
        let globals = sdk_exchange(&mut b, "GETKEY #synthetic_lobby 004 0 :\\status\r\n");
        assert_eq!(numeric(&globals, "700").len(), 2);
        let end_global = numeric(&globals, "701");
        assert_eq!(end_global.len(), 1);
        assert_eq!(end_global[0].len(), 4);
        assert_eq!(end_global[0][2], "004");
        assert_eq!(
            numeric(&sdk_exchange(&mut a, "NICK player2\r\n"), "433").len(),
            1
        );
        sdk_exchange(&mut a, "NICK renamed_player\r\n");
        assert!(
            sdk_exchange(&mut b, "")
                .iter()
                .any(|line| line.contains(" NICK :renamed_player"))
        );
        let renamed = sdk_exchange(
            &mut b,
            "GETCKEY #synthetic_lobby renamed_player 005 0 :\\b_ready\\score\r\nGETKEY renamed_player 006 0 :\\status\r\n",
        );
        assert_eq!(
            numeric(&renamed, "702")[0],
            vec![
                "player2",
                "#synthetic_lobby",
                "renamed_player",
                "005",
                "\\1\\7"
            ]
        );
        assert_eq!(
            numeric(&renamed, "700")[0],
            vec!["player2", "renamed_player", "006", "\\online"]
        );
        sdk_exchange(&mut b, "PRIVMSG renamed_player :routing follows rename\r\n");
        assert!(
            sdk_exchange(&mut a, "")
                .iter()
                .any(|line| line.contains("PRIVMSG renamed_player :routing follows rename"))
        );
        // QUIT has no acknowledgement: observe the peer's broadcast as a
        // deterministic barrier before checking renamed membership cleanup.
        a.send_encrypted("QUIT :finished\r\n");
        loop {
            if b.read_encrypted().contains("QUIT") {
                break;
            }
        }
        let cleaned = sdk_exchange(&mut b, "GETCKEY #synthetic_lobby * 007 0 :\\b_ready\r\n");
        let members = numeric(&cleaned, "702");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0][2], "player2");
        drop(a);
        drop(b);
        server.join().unwrap();
    }

    struct TestClient {
        socket: TcpStream,
        pending: Vec<u8>,
        inbound: Option<ChatCipher>,
        outbound: Option<ChatCipher>,
    }

    impl TestClient {
        fn send_plain(&mut self, line: &str) {
            self.socket.write_all(line.as_bytes()).unwrap();
        }

        fn send_encrypted(&mut self, line: &str) {
            let mut bytes = line.as_bytes().to_vec();
            self.outbound.as_mut().unwrap().apply(&mut bytes);
            self.socket.write_all(&bytes).unwrap();
        }

        fn read_plain(&mut self) -> String {
            self.read_line(false)
        }

        fn read_encrypted(&mut self) -> String {
            self.read_line(true)
        }

        fn read_line(&mut self, encrypted: bool) -> String {
            loop {
                if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = self.pending.drain(..=end).collect();
                    return String::from_utf8(line).unwrap();
                }
                let mut chunk = [0u8; 512];
                let read = self.socket.read(&mut chunk).unwrap();
                assert!(read > 0, "server closed");
                if encrypted {
                    self.inbound.as_mut().unwrap().apply(&mut chunk[..read]);
                }
                self.pending.extend_from_slice(&chunk[..read]);
            }
        }
    }

    #[test]
    fn generated_key_has_no_zero_after_xor() {
        for _ in 0..64 {
            let key = random_key(SECRET).unwrap();
            assert_eq!(key.len(), RANDOM_KEY_BYTES);
            assert!(peerchat::key_material(&key, SECRET).unwrap().len() == RANDOM_KEY_BYTES);
        }
    }
}
