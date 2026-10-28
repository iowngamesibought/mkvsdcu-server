//! Diagnostic TCP probe listeners.
//!
//! Temporary instrumentation, not part of the service. A probe accepts a
//! connection, records where it came from and every byte the client sends,
//! and closes. It answers one question only: does the console contact this
//! port at all? Nothing here speaks a protocol, so a client that waits for
//! the server to talk first will simply time out, which is itself the
//! observation.
//!
//! Enabled with `MKVSDCU_PROBE_BIND`, a comma-separated list of bind
//! addresses, e.g. `MKVSDCU_PROBE_BIND=0.0.0.0:29901`.

use std::io::{ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const ENV: &str = "MKVSDCU_PROBE_BIND";
/// How long one connection is held open while waiting for the client to speak.
const HOLD: Duration = Duration::from_secs(45);

/// Spawn a probe for every address in `MKVSDCU_PROBE_BIND`. Returns the number
/// spawned; a bind failure is reported and skipped rather than fatal, since a
/// diagnostic must never stop the service from starting.
pub fn spawn_from_env() -> usize {
    let Ok(value) = std::env::var(ENV) else {
        return 0;
    };
    let mut spawned = 0;
    for address in value.split(',').map(str::trim).filter(|a| !a.is_empty()) {
        match TcpListener::bind(address) {
            Ok(listener) => {
                let label = address.to_owned();
                println!("[probe] listening on {label} (TCP, diagnostic only)");
                thread::spawn(move || accept_loop(listener, label));
                spawned += 1;
            }
            Err(error) => eprintln!("[probe] bind {address} failed: {error}"),
        }
    }
    spawned
}

fn accept_loop(listener: TcpListener, label: String) {
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                let label = label.clone();
                thread::spawn(move || {
                    println!("[probe] {label} connection from {peer}");
                    record(stream, &label, &peer.to_string());
                });
            }
            Err(error) => eprintln!("[probe] {label} accept failed: {error}"),
        }
    }
}

fn record(mut stream: TcpStream, label: &str, peer: &str) {
    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
        eprintln!("[probe] {label} {peer} set timeout: {error}");
        return;
    }
    let started = Instant::now();
    let mut total = 0usize;
    let mut buffer = [0u8; 2048];
    while started.elapsed() < HOLD {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("[probe] {label} {peer} closed by client after {total} bytes");
                return;
            }
            Ok(length) => {
                total += length;
                let bytes = &buffer[..length];
                let text = String::from_utf8_lossy(bytes);
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                println!("[probe] {label} {peer} recv {length} bytes {text:?}");
                println!("[probe] {label} {peer} hex {hex}");
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(error) => {
                println!("[probe] {label} {peer} read ended after {total} bytes: {error}");
                return;
            }
        }
    }
    println!("[probe] {label} {peer} held {HOLD:?} with {total} bytes, closing");
}
