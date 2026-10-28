//! MKVSDCU private service.
//!
//! The online flow this serves: a console signs in to the platform's account service itself, then logs in
//! here (availability, AuthService, GPCM), reads its player history over HTTP,
//! registers on PeerChat and enters a room. Players challenge each other
//! through room metadata; the two that agree on a match are introduced by NAT
//! negotiation and then play each other directly. The console reports the
//! result, which updates both players' records.
//!
//! The server is never in the gameplay path and never contacts the platform's account service.

pub mod auth_listener;
pub mod availability_listener;
pub mod cert;
pub mod config;
pub mod gp_listener;
pub mod gpsp_listener;
pub mod gstats_listener;
pub mod identity;
pub mod matches;
pub mod natneg_listener;
pub mod peerchat_listener;
pub mod probe_listener;
pub mod rooms;
pub mod session;
pub mod stats_listener;
pub mod tls;

use std::env;
use std::path::Path;
use std::sync::Arc;

use config::{CliCommand, Config};
use session::AuthSessions;
use tls::LegacyTls;

/// Match generations reserved per start. A run would need more pairings than
/// this to exhaust its block, and skipped numbers cost nothing.
const GENERATION_BLOCK: u64 = 1_000_000;

pub fn run() -> Result<(), String> {
    match config::parse_cli(env::args().skip(1))? {
        CliCommand::Help => {
            print_help();
            Ok(())
        }
        CliCommand::Check(path) => check_config(&path),
        CliCommand::Run(path) => run_server(&path),
    }
}

fn check_config(path: &Path) -> Result<(), String> {
    let config = Config::load(path)?;
    println!(
        "config.valid availability={} auth={} gp={} peerchat={} stats={}",
        config.availability.bind,
        config.auth.bind,
        config.gp.bind,
        config.peerchat.bind,
        config
            .stats
            .as_ref()
            .map(|s| s.bind.to_string())
            .unwrap_or_else(|| "disabled".into())
    );
    if let Some(service) = &config.natneg {
        println!("config.natneg bind={}", service.bind);
    }
    if let Some(service) = &config.gpsp {
        println!("config.gpsp bind={}", service.bind);
    }
    if let Some(service) = &config.gstats {
        println!("config.gstats bind={}", service.bind);
    }
    Ok(())
}

fn run_server(path: &Path) -> Result<(), String> {
    let config = Config::load(path)?;
    let sessions = Arc::new(match &config.identity {
        Some(settings) => AuthSessions::with_identity(identity::IdentityStore::open(
            settings.storage_dir.clone(),
        )?),
        None => AuthSessions::new(),
    });
    // Generations key the durable result markers, so they are reserved from
    // the store rather than restarted in memory on every run.
    let matches = Arc::new(match sessions.identity_store() {
        Some(store) => {
            let base = store.reserve_generations(GENERATION_BLOCK)?;
            println!("[match] issuing generations from {base}");
            matches::Matches::starting_at(base)
        }
        // Without durable records there is nothing to deduplicate against.
        None => matches::Matches::new(),
    });
    let generated = cert::generate_self_signed()?;
    let tls = Arc::new(LegacyTls::new(&generated.certificate, &generated.key)?);

    let availability = availability_listener::spawn(config.clone())?;
    let auth = auth_listener::spawn(config.clone(), tls, Arc::clone(&sessions))?;
    let gp = gp_listener::spawn(config.clone(), Arc::clone(&sessions))?;
    let stats = config
        .stats
        .as_ref()
        .map(|stats| stats_listener::spawn(stats.bind, sessions.identity_store()))
        .transpose()?;
    let natneg = config
        .natneg
        .as_ref()
        .map(|service| natneg_listener::spawn(service.bind))
        .transpose()?;
    let gpsp = config
        .gpsp
        .as_ref()
        .map(|service| gpsp_listener::spawn(service.bind, Arc::clone(&sessions)))
        .transpose()?;
    let gstats = config
        .gstats
        .as_ref()
        .map(|service| {
            gstats_listener::spawn(
                service.bind,
                Arc::clone(&sessions),
                Arc::clone(&matches),
                config.peerchat.title_secret.clone(),
            )
        })
        .transpose()?;
    probe_listener::spawn_from_env();
    let peerchat = peerchat_listener::spawn(config, sessions, matches)?;

    println!(
        "mkvsdcu-server: login, stats, rooms, match rendezvous and result recording; two-console play is not yet hardware-verified"
    );

    availability
        .join()
        .map_err(|_| "availability thread panicked".to_owned())?;
    auth.join().map_err(|_| "auth thread panicked".to_owned())?;
    gp.join().map_err(|_| "gp thread panicked".to_owned())?;
    peerchat
        .join()
        .map_err(|_| "peerchat thread panicked".to_owned())?;
    if let Some(gpsp) = gpsp {
        gpsp.join().map_err(|_| "gpsp thread panicked".to_owned())?;
    }
    if let Some(gstats) = gstats {
        gstats
            .join()
            .map_err(|_| "gstats thread panicked".to_owned())?;
    }
    if let Some(natneg) = natneg {
        natneg
            .join()
            .map_err(|_| "natneg thread panicked".to_owned())?;
    }
    if let Some(stats) = stats {
        stats
            .join()
            .map_err(|_| "stats thread panicked".to_owned())?;
    }
    Ok(())
}

fn print_help() {
    println!(
        "mkvsdcu-server {}\n\
         \n\
         Usage:\n\
           mkvsdcu-server run --config <file>\n\
           mkvsdcu-server --check-config --config <file>\n\
         \n\
         The config file is TOML with [availability], [auth], [gp] and\n\
         [peerchat] and optional [stats] sections.\n\
         See mkvsdcu-server.example.toml. Without --config the server reads\n\
         {DEFAULT} from the current directory.",
        env!("CARGO_PKG_VERSION"),
        DEFAULT = config::DEFAULT_CONFIG_FILE
    );
}
