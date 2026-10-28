//! UDP availability responder on port 27900.
//!
//! The SDK sends the probe described in `mkvsdcu-proto::availability` and
//! expects the reply from the same address and port. Every valid probe is
//! answered with "available" (all service bits clear). The SDK is fail-open,
//! but a deterministic answer keeps the client out of its timeout path.

use std::net::UdpSocket;
use std::thread::{self, JoinHandle};

use mkvsdcu_proto::availability::{parse_probe, response};

use crate::config::Config;

pub fn spawn(config: Config) -> Result<JoinHandle<()>, String> {
    let socket = UdpSocket::bind(config.availability.bind).map_err(|error| {
        format!(
            "bind availability listener {}: {error}",
            config.availability.bind
        )
    })?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("availability local address: {error}"))?;
    println!("[availability] listening on {local} (UDP)");

    Ok(thread::spawn(move || {
        let mut buffer = [0u8; 128];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((length, peer)) => match parse_probe(&buffer[..length]) {
                    Ok(game_name) => {
                        println!("[availability] probe game={game_name:?} from {peer}");
                        if let Err(error) = socket.send_to(&response(0), peer) {
                            eprintln!("[availability] reply to {peer} failed: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "[availability] ignored {length}-byte probe from {peer}: {error:?}"
                        );
                    }
                },
                Err(error) => eprintln!("[availability] receive error: {error}"),
            }
        }
    }))
}
