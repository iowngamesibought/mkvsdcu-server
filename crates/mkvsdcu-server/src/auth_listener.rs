//! AuthService listener: SSL3 / RC4-MD5 + HTTP POST + certificate-login SOAP.
//!
//! Scope is deliberately narrow: one HTTP request per connection, no keep-alive
//! and no other AuthService method. The token and partner challenge are minted
//! here; GPCM will later accept them without validating GameSpy proofs.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use openssl::ssl::{HandshakeError, SslStream};

use mkvsdcu_proto::authservice::{CertLoginResponse, build_cert_login_response, parse_cert_login};
use mkvsdcu_proto::http::{self, find_header_end};

use crate::config::Config;
use crate::session::AuthSessions;
use crate::tls::LegacyTls;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 16 * 1024;

pub fn spawn(
    config: Config,
    tls: Arc<LegacyTls>,
    sessions: Arc<AuthSessions>,
) -> Result<JoinHandle<()>, String> {
    let listener = TcpListener::bind(config.auth.bind)
        .map_err(|error| format!("bind auth listener {}: {error}", config.auth.bind))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("auth local address: {error}"))?;
    println!("[auth] listening on {local} (TCP, SSLv3, RC4-MD5, self-signed)");

    Ok(thread::spawn(move || {
        for accepted in listener.incoming() {
            match accepted {
                Ok(socket) => {
                    let config = config.clone();
                    let tls = Arc::clone(&tls);
                    let sessions = Arc::clone(&sessions);
                    thread::spawn(move || {
                        if let Err(error) = handle_connection(socket, &tls, &config, &sessions) {
                            eprintln!("[auth] connection error: {error}");
                        }
                    });
                }
                Err(error) => eprintln!("[auth] accept error: {error}"),
            }
        }
    }))
}

/// Perform TLS, read one HTTP request and answer it. Public for the loopback
/// integration test; the production accept loop calls the same function.
pub fn handle_connection(
    socket: TcpStream,
    tls: &LegacyTls,
    config: &Config,
    sessions: &AuthSessions,
) -> Result<(), String> {
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set read timeout: {error}"))?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set write timeout: {error}"))?;
    let peer = socket
        .peer_addr()
        .map_err(|error| format!("peer address: {error}"))?;

    let mut stream = tls
        .acceptor
        .accept(socket)
        .map_err(|error| match error {
            HandshakeError::Failure(mid) | HandshakeError::WouldBlock(mid) => {
                let ssl = mid.ssl();
                let cipher = ssl.current_cipher().map(|c| c.name()).unwrap_or("none");
                format!(
                    "TLS accept from {peer}: {}; state={}; version={}; cipher={cipher}; error_code={:?}",
                    mid.error(), ssl.state_string_long(), ssl.version_str(), mid.error().code()
                )
            }
            HandshakeError::SetupFailure(error) => {
                format!("TLS setup from {peer}: {error}")
            }
        })?;
    let version = stream.ssl().version_str().to_owned();
    let cipher = stream
        .ssl()
        .current_cipher()
        .map(|cipher| cipher.name().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("[auth] {peer} negotiated {version} / {cipher}");

    let raw = read_http_message(&mut stream, config.auth.max_request_bytes)?;
    let request = match http::parse_request(&raw, config.auth.max_request_bytes) {
        Ok(request) => request,
        Err(error) => {
            let _ = respond_error(
                &mut stream,
                "400 Bad Request",
                &format!("bad request: {error:?}"),
            );
            return Err(format!("{peer}: HTTP parse error: {error:?}"));
        }
    };

    if request.method != "POST" {
        let _ = respond_error(&mut stream, "405 Method Not Allowed", "POST required");
        return Err(format!("{peer}: method {}", request.method));
    }
    let soap_action = request.header("soapaction").unwrap_or("");
    if !soap_action.is_empty()
        && !soap_action.contains(mkvsdcu_proto::authservice::CERT_LOGIN_METHOD)
    {
        let _ = respond_error(
            &mut stream,
            "500 Internal Server Error",
            "unsupported SOAP action",
        );
        return Err(format!("{peer}: unsupported SOAPAction {soap_action:?}"));
    }

    let body = match std::str::from_utf8(request.body) {
        Ok(body) => body,
        Err(_) => {
            let _ = respond_error(&mut stream, "400 Bad Request", "SOAP body is not UTF-8");
            return Err(format!("{peer}: SOAP body is not UTF-8"));
        }
    };
    let parsed = match parse_cert_login(body) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = respond_error(
                &mut stream,
                "400 Bad Request",
                "unrecognized AuthService request",
            );
            return Err(format!("{peer}: {error:?}"));
        }
    };

    let ticket_chars = parsed
        .account_ticket_base64
        .as_deref()
        .map(|ticket| ticket.len())
        .unwrap_or(0);
    println!(
        "[auth] cert login gameid={:?} partnercode={:?} namespaceid={:?} version={:?} account_ticket_chars={ticket_chars}",
        parsed.game_id, parsed.partner_code, parsed.namespace_id, parsed.version
    );

    let token = random_hex(32)?;
    let challenge = random_hex(32)?;
    sessions
        .insert_ticket(
            token.clone(),
            challenge.clone(),
            parsed.account_ticket_base64.as_deref(),
        )
        .map_err(|_| format!("{peer}: invalid ticket identity or unavailable identity storage"))?;
    let response = build_cert_login_response(&CertLoginResponse {
        auth_token: token,
        partner_challenge: challenge,
    });
    let bytes = http::response("200 OK", "text/xml; charset=utf-8", response.as_bytes());
    stream
        .write_all(&bytes)
        .map_err(|error| format!("{peer}: write response: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("{peer}: flush response: {error}"))?;
    let _ = stream.shutdown();
    println!("[auth] {peer} cert login responseCode=0");
    Ok(())
}

fn read_http_message(
    stream: &mut SslStream<TcpStream>,
    max_body: usize,
) -> Result<Vec<u8>, String> {
    let max_total = max_body + MAX_HEADER_BYTES;
    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let mut expected_total = None;

    loop {
        if let Some(header_end) = find_header_end(&buffer) {
            if expected_total.is_none() {
                let head = std::str::from_utf8(&buffer[..header_end])
                    .map_err(|_| "request headers are not UTF-8".to_owned())?;
                let body_length = declared_content_length(head)?;
                if body_length > max_body {
                    return Err(format!(
                        "request body {body_length} exceeds limit {max_body}"
                    ));
                }
                let total = header_end
                    .checked_add(4)
                    .and_then(|value| value.checked_add(body_length))
                    .ok_or_else(|| "request length overflow".to_owned())?;
                if total > max_total {
                    return Err(format!("request {total} exceeds limit {max_total}"));
                }
                expected_total = Some(total);
            }
            if let Some(total) = expected_total
                && buffer.len() >= total
            {
                buffer.truncate(total);
                return Ok(buffer);
            }
        }

        if buffer.len() > max_total {
            return Err(format!("request exceeds limit {max_total}"));
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("read request: {error}"))?;
        if read == 0 {
            return Err("connection closed before a complete request".to_owned());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn declared_content_length(head: &str) -> Result<usize, String> {
    let mut lines = head.split("\r\n");
    let _request_line = lines.next();
    let mut declared = None;
    for line in lines {
        let Some((name, raw_value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        if declared.is_some() {
            return Err("duplicate Content-Length".to_owned());
        }
        declared = Some(
            raw_value
                .trim()
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_owned())?,
        );
    }
    declared.ok_or_else(|| "missing Content-Length".to_owned())
}

fn respond_error(
    stream: &mut SslStream<TcpStream>,
    status: &str,
    message: &str,
) -> Result<(), String> {
    let bytes = http::response(status, "text/plain; charset=utf-8", message.as_bytes());
    stream
        .write_all(&bytes)
        .map_err(|error| format!("write error response: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush error response: {error}"))
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut buffer).map_err(|error| format!("OpenSSL RNG: {error}"))?;
    Ok(buffer.iter().map(|byte| format!("{byte:02x}")).collect())
}
