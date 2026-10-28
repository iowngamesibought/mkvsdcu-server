//! GPSP search listener (TCP 29901).
//!
//! The title resolves a unique nickname to a profile here, and will not
//! complete a match until the lookup of its opponent returns. It opens one
//! connection per lookup and issues them concurrently -- a console was
//! observed opening thirty-one at once for its friend list -- so each
//! connection is served on its own thread and closed when the search is
//! answered.
//!
//! A request is answered only for a profile that holds a live login session
//! from the address the request arrives on, the same proof the result
//! listener requires. A nickname this server has never seen is answered with
//! a completed, empty search rather than an error: most friend-list names
//! will never exist here, and the client treats a parse error as fatal.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mkvsdcu_proto::gpsp::{self, MAX_REQUEST_BYTES};

use crate::identity::IdentityStore;
use crate::session::AuthSessions;

/// How long one connection may stay idle before it is dropped.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Concurrent searches served at once. A console opens one connection per
/// lookup and issues its whole friend list in parallel -- thirty-one at once
/// was observed -- so this has to be generous, but not unbounded: a client
/// that loops must not be able to spawn threads without limit.
const MAX_CONNECTIONS: usize = 96;

pub fn spawn(bind: SocketAddr, sessions: Arc<AuthSessions>) -> Result<JoinHandle<()>, String> {
    let listener =
        TcpListener::bind(bind).map_err(|error| format!("bind gpsp listener {bind}: {error}"))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("gpsp local address: {error}"))?;
    println!("[gpsp] listening on {local} (TCP, profile search)");

    let count = Arc::new(AtomicUsize::new(0));
    Ok(thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    if count.fetch_add(1, AtomicOrdering::SeqCst) >= MAX_CONNECTIONS {
                        count.fetch_sub(1, AtomicOrdering::SeqCst);
                        eprintln!(
                            "[gpsp] {peer} refused: {MAX_CONNECTIONS} searches already in flight"
                        );
                        continue;
                    }
                    let sessions = Arc::clone(&sessions);
                    let count = Arc::clone(&count);
                    thread::spawn(move || {
                        if let Err(error) = serve(stream, peer, &sessions) {
                            eprintln!("[gpsp] {peer}: {error}");
                        }
                        count.fetch_sub(1, AtomicOrdering::SeqCst);
                    });
                }
                Err(error) => eprintln!("[gpsp] accept failed: {error}"),
            }
        }
    }))
}

fn serve(
    mut stream: TcpStream,
    peer: SocketAddr,
    sessions: &Arc<AuthSessions>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|error| format!("set read timeout: {error}"))?;
    let store = sessions.identity_store();
    let mut pending = String::new();
    let mut buffer = [0u8; 1024];
    loop {
        // Answer every complete request already buffered before reading more.
        while let Some(end) = gpsp::request_end(&pending) {
            let request: String = pending.drain(..end).collect();
            let reply = answer(&request, peer, sessions, store.as_deref());
            stream
                .write_all(reply.as_bytes())
                .map_err(|error| format!("write reply: {error}"))?;
            stream
                .flush()
                .map_err(|error| format!("flush reply: {error}"))?;
        }
        if pending.len() > MAX_REQUEST_BYTES {
            return Err(format!(
                "unterminated request over {MAX_REQUEST_BYTES} bytes"
            ));
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(length) => pending.push_str(&String::from_utf8_lossy(&buffer[..length])),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(());
            }
            Err(error) => return Err(format!("read: {error}")),
        }
    }
}

/// Resolve one request into the exact bytes to send back.
fn answer(
    request: &str,
    peer: SocketAddr,
    sessions: &Arc<AuthSessions>,
    store: Option<&IdentityStore>,
) -> String {
    let search = match gpsp::parse_search_unique(request) {
        Ok(search) => search,
        Err(error) => {
            eprintln!("[gpsp] {peer} ignored request: {error:?}");
            return gpsp::no_results();
        }
    };
    if sessions
        .for_peer_profile(peer.ip(), search.profile_id)
        .is_none()
    {
        println!(
            "[gpsp] {peer} search uniquenick={:?} rejected: no live session for profileid={}",
            search.uniquenick, search.profile_id
        );
        return gpsp::no_results();
    }
    let Some(store) = store else {
        println!(
            "[gpsp] {peer} search uniquenick={:?} no match: no identity store",
            search.uniquenick
        );
        return gpsp::no_results();
    };
    let found = match store.leaderboard() {
        Ok(rows) => rows
            .into_iter()
            .find(|row| row.name.eq_ignore_ascii_case(&search.uniquenick)),
        Err(error) => {
            eprintln!("[gpsp] {peer} identity read failed: {error}");
            None
        }
    };
    match found {
        Some(row) => {
            match gpsp::search_result(row.profile_id, &row.name, &row.name, search.namespace_id) {
                Some(reply) => {
                    println!(
                        "[gpsp] {peer} search uniquenick={:?} found profileid={}",
                        search.uniquenick, row.profile_id
                    );
                    reply
                }
                None => {
                    // A stored name carrying the separator cannot be framed.
                    eprintln!(
                        "[gpsp] {peer} stored name {:?} is not representable in a reply",
                        row.name
                    );
                    gpsp::no_results()
                }
            }
        }
        None => {
            println!(
                "[gpsp] {peer} search uniquenick={:?} no match",
                search.uniquenick
            );
            gpsp::no_results()
        }
    }
}
