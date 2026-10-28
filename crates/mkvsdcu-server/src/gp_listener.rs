//! GPCM listener: the pre-authenticated GameSpy Presence login.
//!
//! This establishes the player session every later service checks: chat
//! registration, result reporting and the records all trace back to the token
//! minted here. Buddy and status operations are not answered; the title does
//! not need them to reach a match. A logout ends the session.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mkvsdcu_proto::gp::{self, LoginSuccess, MAX_MESSAGE_BYTES};

use crate::config::Config;
use crate::session::AuthSessions;

const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const BAD_PREAUTH: u16 = 0x010a;

fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("MKVSDCU_CHAT_TRACE").is_some_and(|value| value == "1"))
}

pub fn spawn(config: Config, sessions: Arc<AuthSessions>) -> Result<JoinHandle<()>, String> {
    let listener = TcpListener::bind(config.gp.bind)
        .map_err(|error| format!("bind gp listener {}: {error}", config.gp.bind))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("gp local address: {error}"))?;
    println!("[gp] listening on {local} (TCP, GPCM)");

    Ok(thread::spawn(move || {
        for accepted in listener.incoming() {
            match accepted {
                Ok(socket) => {
                    let sessions = Arc::clone(&sessions);
                    thread::spawn(move || {
                        if let Err(error) = handle_connection(socket, &sessions) {
                            eprintln!("[gp] connection error: {error}");
                        }
                    });
                }
                Err(error) => eprintln!("[gp] accept error: {error}"),
            }
        }
    }))
}

/// Serve one GPCM connection. Public so the loopback integration test drives
/// the same state machine as the accept loop.
pub fn handle_connection(mut socket: TcpStream, sessions: &AuthSessions) -> Result<(), String> {
    let peer = socket
        .peer_addr()
        .map_err(|error| format!("gp peer address: {error}"))?;
    socket
        .set_read_timeout(Some(LOGIN_TIMEOUT))
        .map_err(|error| format!("gp read timeout: {error}"))?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("gp write timeout: {error}"))?;

    // Explicitly enabled local diagnostics; contains authentication material.
    // Never enable this with a public-tree destination.
    let mut trace = match std::env::var_os("MKVSDCU_GP_TRACE_DIR") {
        Some(directory) => {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos();
            let path = std::path::PathBuf::from(directory).join(format!("gp-{stamp}.log"));
            Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| format!("create GP trace: {error}"))?,
            )
        }
        None => None,
    };
    let server_challenge = random_digits(10)?;
    let challenge = gp::challenge_message(&server_challenge)
        .map_err(|error| format!("build GP challenge: {error:?}"))?;
    socket
        .write_all(challenge.as_bytes())
        .map_err(|error| format!("{peer}: write GP challenge: {error}"))?;

    trace_frame(&mut trace, "server", &challenge)?;
    let mut buffer = Vec::new();
    let message = read_frame(&mut socket, &mut buffer)?
        .ok_or_else(|| format!("{peer}: closed before GP login"))?;
    trace_frame(&mut trace, "client", &message)?;
    let login =
        gp::parse_login(&message).map_err(|error| format!("{peer}: GP login: {error:?}"))?;
    println!(
        "[gp] {peer} login productid={:?} namespaceid={:?} gamename={:?} port={:?}",
        login.product_id, login.namespace_id, login.game_name, login.port
    );

    let Some(session) = sessions.begin_gp_login(&login.auth_token) else {
        let _ = socket.write_all(gp::error_message(BAD_PREAUTH, "unknown auth token").as_bytes());
        return Err(format!("{peer}: unknown or expired auth token"));
    };

    let expected_response = gp::proof(
        &session.partner_challenge,
        &login.auth_token,
        &login.user_challenge,
        &server_challenge,
    );
    let fields: Vec<_> = message.split('\\').collect();
    let supplied_response = fields
        .windows(2)
        .find(|pair| pair[0] == "response")
        .map(|pair| pair[1]);
    println!(
        "[gp] {peer} client authentication response matches={}",
        supplied_response == Some(expected_response.as_str())
    );
    if supplied_response == Some(expected_response.as_str()) {
        sessions.bind_gp_peer(&login.auth_token, peer.ip());
    }
    let proof = gp::proof(
        &session.partner_challenge,
        &login.auth_token,
        &server_challenge,
        &login.user_challenge,
    );
    let sess_key = random_nonzero_u32()?;
    let unique_nick = format!("player{}", session.profile_id);
    let response = gp::login_response(&LoginSuccess {
        sess_key,
        user_id: session.user_id,
        profile_id: session.profile_id,
        unique_nick: &unique_nick,
        proof: &proof,
    })
    .map_err(|error| format!("build GP login response: {error:?}"))?;
    socket
        .write_all(response.as_bytes())
        .map_err(|error| format!("{peer}: write GP login response: {error}"))?;
    println!(
        "[gp] {peer} login success sent profileid={} userid={} sesskey={}",
        session.profile_id, session.user_id, sess_key
    );

    trace_frame(&mut trace, "server", &response)?;

    // The connection is long-lived. Keep reading framed messages so the client
    // sees an open connection; answer its keep-alive with the same shape.
    socket
        .set_read_timeout(None)
        .map_err(|error| format!("{peer}: clear GP read timeout: {error}"))?;
    loop {
        match read_frame(&mut socket, &mut buffer) {
            Ok(Some(message)) => {
                trace_frame(&mut trace, "client", &message)?;
                if message.starts_with("\\logout\\") {
                    // The login ends here: the token must not outlive it.
                    let profile = sessions.expire(&login.auth_token);
                    println!("[gp] {peer} logout profileid={profile:?}");
                    break;
                }
                if message.starts_with("\\ka\\") {
                    socket
                        .write_all(b"\\ka\\\\final\\")
                        .map_err(|error| format!("{peer}: write keep-alive: {error}"))?;
                    continue;
                }
                if trace_enabled() {
                    println!("[gp] trace {peer} unsolicited {:?}", message.as_str());
                }
                println!(
                    "[gp] {peer} ignored unsupported unsolicited message ({} bytes)",
                    message.len()
                );
            }
            Ok(None) => break,
            Err(error) => {
                eprintln!("[gp] {peer} read error: {error}");
                break;
            }
        }
    }
    Ok(())
}

fn read_frame(socket: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<Option<String>, String> {
    loop {
        if let Some(end) = gp::find_message_end(buffer) {
            let frame: Vec<u8> = buffer.drain(..end).collect();
            let text = String::from_utf8(frame)
                .map_err(|_| "GPCM message is not valid UTF-8/ASCII".to_owned())?;
            return Ok(Some(text));
        }
        if buffer.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "GPCM message exceeds {MAX_MESSAGE_BYTES} bytes without a terminator"
            ));
        }
        let mut chunk = [0u8; 2048];
        let read = socket
            .read(&mut chunk)
            .map_err(|error| format!("read GPCM message: {error}"))?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn random_digits(count: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; count];
    openssl::rand::rand_bytes(&mut bytes).map_err(|error| format!("OpenSSL RNG: {error}"))?;
    Ok(bytes
        .into_iter()
        .map(|byte| char::from(b'0' + byte % 10))
        .collect())
}

fn random_nonzero_u32() -> Result<u32, String> {
    loop {
        let mut bytes = [0u8; 4];
        openssl::rand::rand_bytes(&mut bytes).map_err(|error| format!("OpenSSL RNG: {error}"))?;
        // The SDK parses sesskey with atoi into a signed int.
        let value = u32::from_be_bytes(bytes) & i32::MAX as u32;
        if value != 0 {
            return Ok(value);
        }
    }
}

fn trace_frame(
    trace: &mut Option<std::fs::File>,
    direction: &str,
    frame: &str,
) -> Result<(), String> {
    if let Some(file) = trace {
        writeln!(file, "{direction}: {frame}")
            .and_then(|_| file.flush())
            .map_err(|error| format!("write GP trace: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn loopback_login_returns_proof_for_the_minted_session() {
        let sessions = Arc::new(AuthSessions::new());
        sessions.insert("token-1".to_owned(), "partner-1".to_owned());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_sessions = Arc::clone(&sessions);
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle_connection(socket, &server_sessions).unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut challenge = String::new();
        read_until_final(&mut client, &mut challenge);
        assert!(challenge.starts_with("\\lc\\1\\challenge\\"), "{challenge}");
        assert!(challenge.ends_with("\\id\\1\\final\\"), "{challenge}");
        let server_challenge = between(&challenge, "\\challenge\\", "\\id\\");

        let login = "\\login\\\\challenge\\user-challenge\\authtoken\\token-1\\partnerid\\33\\port\\6500\\productid\\11507\\gamename\\mkvsdcu\\namespaceid\\40\\id\\1\\final\\";
        client.write_all(login.as_bytes()).unwrap();

        let mut response = String::new();
        read_until_final(&mut client, &mut response);
        assert!(response.starts_with("\\lc\\2\\"), "{response}");
        assert!(response.contains("\\profileid\\1\\"), "{response}");
        let proof = between(&response, "\\proof\\", "\\id\\");
        let expected = gp::proof("partner-1", "token-1", server_challenge, "user-challenge");
        assert_eq!(proof, expected);
        assert_eq!(proof.len(), 32);

        drop(client);
        server.join().unwrap();
    }

    fn read_until_final(socket: &mut TcpStream, output: &mut String) {
        let mut bytes = Vec::new();
        loop {
            if let Some(end) = gp::find_message_end(&bytes) {
                bytes.truncate(end);
                output.push_str(std::str::from_utf8(&bytes).unwrap());
                return;
            }
            if bytes.len() > MAX_MESSAGE_BYTES {
                panic!("message too long");
            }
            let mut chunk = [0u8; 512];
            let read = socket.read(&mut chunk).unwrap();
            assert!(read > 0, "connection closed");
            bytes.extend_from_slice(&chunk[..read]);
        }
    }

    fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let start = text.find(start).unwrap() + start.len();
        let end = text[start..].find(end).unwrap() + start;
        &text[start..end]
    }
}
