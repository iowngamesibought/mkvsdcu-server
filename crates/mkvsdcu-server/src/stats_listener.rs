//! HTTP views of durable local player aggregates and leaderboard.
use crate::identity::{IdentityStore, PlayerRow};
use mkvsdcu_proto::{http, stats};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_HEADER: usize = 16 * 1024;

pub fn spawn(
    bind: SocketAddr,
    identities: Option<Arc<IdentityStore>>,
) -> Result<JoinHandle<()>, String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("bind stats {bind}: {e}"))?;
    println!(
        "[stats] listening on {} (TCP, HTTP)",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    Ok(thread::spawn(move || {
        for connection in listener.incoming() {
            match connection {
                Ok(socket) => {
                    let identities = identities.clone();
                    thread::spawn(move || {
                        if let Err(error) = handle_connection(socket, identities.as_deref()) {
                            eprintln!("[stats] connection error: {error}");
                        }
                    });
                }
                Err(error) => eprintln!("[stats] accept error: {error}"),
            }
        }
    }))
}

pub fn handle_connection(
    mut socket: TcpStream,
    identities: Option<&IdentityStore>,
) -> Result<(), String> {
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    loop {
        if http::find_header_end(&bytes).is_some() {
            break;
        }
        if bytes.len() >= MAX_HEADER {
            return send(
                &mut socket,
                "431 Request Header Fields Too Large",
                "header too large",
            );
        }
        let mut chunk = [0; 1024];
        let count = socket.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("closed before HTTP header".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let end = http::find_header_end(&bytes).unwrap();
    if end + 4 > MAX_HEADER {
        return send(
            &mut socket,
            "431 Request Header Fields Too Large",
            "header too large",
        );
    }
    let Ok(header) = std::str::from_utf8(&bytes[..end]) else {
        return send(&mut socket, "400 Bad Request", "invalid header");
    };
    let mut lines = header.split("\r\n");
    let parts: Vec<_> = lines.next().unwrap_or("").split_whitespace().collect();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return send(&mut socket, "400 Bad Request", "invalid request line");
    }
    let mut has_length = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return send(&mut socket, "400 Bad Request", "invalid header");
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return send(&mut socket, "400 Bad Request", "body unsupported");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if has_length || value.trim() != "0" {
                return send(&mut socket, "400 Bad Request", "body unsupported");
            }
            has_length = true;
        }
    }
    if parts[0] != "GET" {
        return send(&mut socket, "405 Method Not Allowed", "GET required");
    }
    let path = parts[1].split('?').next().unwrap_or("");
    if path != stats::PLAYER_PATH && path != stats::LEADERBOARD_PATH {
        return send(&mut socket, "404 Not Found", "unknown endpoint");
    }
    let id = if path == stats::PLAYER_PATH {
        match stats::profile_id(parts[1]) {
            Ok(id) => Some(id),
            Err(_) => return send(&mut socket, "400 Bad Request", "invalid profile_id"),
        }
    } else {
        if parts[1] != stats::LEADERBOARD_PATH {
            return send(
                &mut socket,
                "400 Bad Request",
                "unexpected leaderboard query",
            );
        }
        None
    };
    let rows = match identities.map(IdentityStore::leaderboard).transpose() {
        Ok(rows) => ranked(rows.unwrap_or_default()),
        Err(error) => {
            eprintln!("[stats] aggregate read failed: {error}");
            return send(&mut socket, "503 Service Unavailable", "stats unavailable");
        }
    };
    let body = match id {
        Some(id) => rows
            .iter()
            .find(|row| row.profile_id == id)
            .map(stats::player)
            .unwrap_or_else(|| stats::empty_player(id)),
        None => stats::leaderboard(&rows),
    };
    let response = http::response("200 OK", "text/xml; charset=utf-8", body.as_bytes());
    socket.write_all(&response).map_err(|e| e.to_string())?;
    println!(
        "[stats] read view={} rows={}",
        if id.is_some() {
            "player"
        } else {
            "leaderboard"
        },
        rows.len()
    );
    Ok(())
}

/// Number the rows. The aggregate store owns the ordering so that both views
/// and every reader agree on one ranking; this only assigns the positions.
fn ranked(rows: Vec<PlayerRow>) -> Vec<stats::PlayerStats> {
    rows.into_iter()
        .enumerate()
        .map(|(index, row)| stats::PlayerStats {
            profile_id: row.profile_id,
            name: row.name,
            position: index + 1,
            wins: row.wins,
            losses: row.losses,
            disconnects: row.disconnects,
            games: row.games,
            streak: row.streak,
            best_streak: row.best_streak,
        })
        .collect()
}

fn send(socket: &mut TcpStream, status: &str, body: &str) -> Result<(), String> {
    socket
        .write_all(&http::response(status, "text/plain", body.as_bytes()))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(id: u32, name: &str, wins: u32, losses: u32, disconnects: u32) -> PlayerRow {
        PlayerRow {
            profile_id: id,
            name: name.into(),
            wins,
            losses,
            disconnects,
            games: wins + losses,
            streak: 0,
            best_streak: 0,
        }
    }
    #[test]
    fn positions_follow_the_order_the_store_supplied() {
        let rows = ranked(vec![
            row(5, "Top", 5, 9, 9),
            row(4, "adam", 4, 1, 0),
            row(1, "Zulu", 4, 2, 0),
        ]);
        assert_eq!(
            rows.iter()
                .map(|r| (r.profile_id, r.position))
                .collect::<Vec<_>>(),
            vec![(5, 1), (4, 2), (1, 3)]
        );
    }
    fn request(line: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker =
            thread::spawn(move || handle_connection(listener.accept().unwrap().0, None).unwrap());
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(format!("{line}\r\nHost: test.local\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        response
    }
    #[test]
    fn leaderboard_get_is_xml_and_rejects_unobserved_mutations() {
        let response = request(&format!("GET {} HTTP/1.1", stats::LEADERBOARD_PATH));
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            response
                .contains("<ONLINE_STATS group=\"1\"><STATS reset_type=\"0\"><HEADER></HEADER>")
        );
        assert!(
            request(&format!("POST {} HTTP/1.1", stats::LEADERBOARD_PATH))
                .contains("405 Method Not Allowed")
        );
        assert!(
            request(&format!("GET {}?x=1 HTTP/1.1", stats::LEADERBOARD_PATH))
                .contains("400 Bad Request")
        );
    }
    #[test]
    fn durable_nonempty_aggregate_reaches_both_http_views() {
        let directory = std::env::temp_dir().join(format!(
            "mkvdc-http-stats-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("state.toml"),
            "version=1\n[players.testplayer]\nprofile_id=7\nname='TestPlayer'\nwins=3\nlosses=1\ndisconnects=1\ngames=4\nstreak=2\nbest_streak=3\n").unwrap();
        let store = Arc::new(IdentityStore::open(directory.clone()).unwrap());
        for target in [
            stats::LEADERBOARD_PATH.to_owned(),
            format!("{}?profile_id=7", stats::PLAYER_PATH),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let identity = store.clone();
            let worker = thread::spawn(move || {
                handle_connection(listener.accept().unwrap().0, Some(&identity)).unwrap()
            });
            let mut socket = TcpStream::connect(addr).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .write_all(format!("GET {target} HTTP/1.1\r\nHost: test.local\r\n\r\n").as_bytes())
                .unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).unwrap();
            worker.join().unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK"));
            if target == stats::LEADERBOARD_PATH {
                assert!(response.contains(
                    "<HEADER></HEADER><ENTRY column_1=\"1\" column_2=\"TestPlayer\" column_3=\"3\""
                ));
            } else {
                assert!(response.contains("never_wins=\"3\" never_losses=\"1\""));
            }
        }
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn serves_fragmented_get_without_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server =
            thread::spawn(move || handle_connection(listener.accept().unwrap().0, None).unwrap());
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            // Built from the constant: the path is the one the console
            // requests, and this test is what checks it is matched.
            .write_all(format!("GET {}?profile_id=7 HTTP/1.1\r\n", stats::PLAYER_PATH).as_bytes())
            .unwrap();
        client.write_all(b"Host: test.local\r\n\r\n").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("<PLAYER profile_id=\"7\"></PLAYER>"));
        server.join().unwrap();
    }
}
