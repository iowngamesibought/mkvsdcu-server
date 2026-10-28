//! Operator configuration loaded from TOML.
//!
//! The schema is deliberately small and rejects unknown keys. Each service has
//! its own bind address because the game uses different transports and ports.
//! This service has no runtime game-file dependency: the only game-derived
//! value is the title secret the operator supplies here. Player records are
//! the one thing written to disk, under the optional identity directory.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_CONFIG_FILE: &str = "mkvsdcu-server.toml";
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MIN_MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Peer sets `sbSecretKey` through a `PI_SB_LEN` (32-byte) `strzcpy`, so the
/// effective title secret is at most 31 bytes plus the terminator.
pub const MAX_TITLE_SECRET_BYTES: usize = 31;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub availability: ServiceConfig,
    pub auth: AuthConfig,
    pub gp: ServiceConfig,
    pub peerchat: PeerChatConfig,
    #[serde(default)]
    pub stats: Option<ServiceConfig>,
    #[serde(default)]
    pub natneg: Option<ServiceConfig>,
    #[serde(default)]
    pub gpsp: Option<ServiceConfig>,
    #[serde(default)]
    pub gstats: Option<GStatsConfig>,
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub storage_dir: PathBuf,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GStatsConfig {
    pub bind: SocketAddr,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub bind: SocketAddr,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerChatConfig {
    pub bind: SocketAddr,
    /// The title's `sbSecretKey`, supplied by the operator from their own copy
    /// of the game. It is deliberately not written to the public tree.
    pub title_secret: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let metadata = fs::metadata(path)
            .map_err(|error| format!("read config {}: {error}", path.display()))?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(format!(
                "config {} is {} bytes, limit is {MAX_CONFIG_BYTES}",
                path.display(),
                metadata.len()
            ));
        }
        let text = fs::read_to_string(path)
            .map_err(|error| format!("read config {}: {error}", path.display()))?;
        let mut config =
            Self::parse(&text).map_err(|error| format!("config {}: {error}", path.display()))?;
        config.resolve_paths_against(path.parent().unwrap_or(Path::new(".")));
        Ok(config)
    }

    /// Resolve relative paths against the configuration file's own folder, so
    /// a config can name `game/players` and be moved with its folder. An
    /// absolute path is left alone.
    fn resolve_paths_against(&mut self, base: &Path) {
        if let Some(identity) = &mut self.identity
            && identity.storage_dir.is_relative()
        {
            identity.storage_dir = base.join(&identity.storage_dir);
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        validate_bind("availability.bind", self.availability.bind)?;
        validate_bind("auth.bind", self.auth.bind)?;
        validate_bind("gp.bind", self.gp.bind)?;
        validate_bind("peerchat.bind", self.peerchat.bind)?;
        let mut tcp_binds = vec![
            ("auth.bind", self.auth.bind),
            ("gp.bind", self.gp.bind),
            ("peerchat.bind", self.peerchat.bind),
        ];
        if let Some(stats) = &self.stats {
            validate_bind("stats.bind", stats.bind)?;
            tcp_binds.push(("stats.bind", stats.bind));
        }
        if let Some(gpsp) = &self.gpsp {
            validate_bind("gpsp.bind", gpsp.bind)?;
            tcp_binds.push(("gpsp.bind", gpsp.bind));
        }
        if let Some(gstats) = &self.gstats {
            validate_bind("gstats.bind", gstats.bind)?;
            tcp_binds.push(("gstats.bind", gstats.bind));
        }
        validate_distinct_tcp_binds(&tcp_binds)?;
        if let Some(natneg) = &self.natneg {
            validate_bind("natneg.bind", natneg.bind)?;
            if natneg.bind == self.availability.bind {
                return Err(
                    "natneg.bind and availability.bind must not be the same UDP address".into(),
                );
            }
        }
        if let Some(identity) = &self.identity
            && identity.storage_dir.as_os_str().is_empty()
        {
            return Err("identity.storage_dir must not be empty".into());
        }
        validate_title_secret(&self.peerchat.title_secret)?;
        if !(MIN_MAX_REQUEST_BYTES..=MAX_MAX_REQUEST_BYTES).contains(&self.auth.max_request_bytes) {
            return Err(format!(
                "auth.max_request_bytes must be between {MIN_MAX_REQUEST_BYTES} and {MAX_MAX_REQUEST_BYTES}"
            ));
        }
        Ok(())
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(DEFAULT_CONFIG_FILE)
    }
}

fn default_max_request_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BYTES
}

fn validate_bind(name: &str, bind: SocketAddr) -> Result<(), String> {
    if bind.port() == 0 {
        return Err(format!("{name} must use a nonzero port"));
    }
    Ok(())
}

fn validate_distinct_tcp_binds(binds: &[(&str, SocketAddr)]) -> Result<(), String> {
    for (index, (name, bind)) in binds.iter().enumerate() {
        for (other_name, other_bind) in &binds[index + 1..] {
            if bind == other_bind {
                return Err(format!(
                    "{name} and {other_name} must not be the same TCP address"
                ));
            }
        }
    }
    Ok(())
}

fn validate_title_secret(secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("peerchat.title_secret must be the title's sbSecretKey (not empty)".to_owned());
    }
    if secret.len() > MAX_TITLE_SECRET_BYTES {
        return Err(format!(
            "peerchat.title_secret is {} bytes, limit is {MAX_TITLE_SECRET_BYTES}",
            secret.len()
        ));
    }
    if !secret.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err("peerchat.title_secret must be printable ASCII without spaces".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Run(PathBuf),
    Check(PathBuf),
    Help,
}

pub fn parse_cli<I>(arguments: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let mut mode = None;
    let mut config_path = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "run" if mode.is_none() => mode = Some(false),
            "--check-config" if mode.is_none() => mode = Some(true),
            "--help" | "-h" if mode.is_none() => return Ok(CliCommand::Help),
            "--config" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--config requires a path".to_owned())?;
                if config_path.replace(PathBuf::from(value)).is_some() {
                    return Err("--config specified more than once".to_owned());
                }
            }
            other => {
                if let Some(value) = other.strip_prefix("--config=") {
                    if value.is_empty() {
                        return Err("--config requires a path".to_owned());
                    }
                    if config_path.replace(PathBuf::from(value)).is_some() {
                        return Err("--config specified more than once".to_owned());
                    }
                } else {
                    return Err(format!("unrecognized argument {other:?}"));
                }
            }
        }
    }

    let mode = mode.ok_or_else(|| "expected `run` or `--check-config`".to_owned())?;
    let path = config_path.unwrap_or_else(Config::default_path);
    Ok(if mode {
        CliCommand::Check(path)
    } else {
        CliCommand::Run(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[availability]
bind = "127.0.0.1:27900"

[auth]
bind = "127.0.0.1:18443"
max_request_bytes = 65536

[gp]
bind = "127.0.0.1:29900"

[peerchat]
bind = "127.0.0.1:16667"
title_secret = "0123456789"
"#;

    #[test]
    fn optional_gameplay_services_validate_without_opening_storage() {
        let text = format!(
            "{VALID}\n[natneg]\nbind=\"127.0.0.1:27901\"\n[gstats]\nbind=\"127.0.0.1:29920\"\n"
        );
        assert!(Config::parse(&text).is_ok());
        assert!(Config::parse(&text.replace("127.0.0.1:27901", "127.0.0.1:27900")).is_err());
        assert!(Config::parse(&text.replace("127.0.0.1:29920", "127.0.0.1:29900")).is_err());
        // Raw reports are never written, so the old storage key is gone and is
        // now rejected like any other unknown key.
        assert!(Config::parse(&format!("{text}storage_dir=\"x\"\n")).is_err());
    }
    #[test]
    fn parses_the_example_schema() {
        let config = Config::parse(VALID).unwrap();
        assert_eq!(config.availability.bind.port(), 27900);
        assert_eq!(config.auth.bind.port(), 18443);
        assert_eq!(config.gp.bind.port(), 29900);
        assert_eq!(config.peerchat.bind.port(), 16667);
        assert_eq!(config.auth.max_request_bytes, 65536);
    }

    #[test]
    fn optional_stats_bind_is_validated() {
        assert!(Config::parse(VALID).unwrap().stats.is_none());
        let enabled = format!("{VALID}\n[stats]\nbind = \"127.0.0.1:80\"\n");
        assert_eq!(
            Config::parse(&enabled).unwrap().stats.unwrap().bind.port(),
            80
        );
        assert!(Config::parse(&enabled.replace("127.0.0.1:80", "127.0.0.1:0")).is_err());
        assert!(Config::parse(&enabled.replace("127.0.0.1:80", "127.0.0.1:29900")).is_err());
    }
    #[test]
    fn rejects_unknown_keys() {
        let text = VALID.replace("[gp]\n", "[gp]\nunknown = true\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_port_zero_and_duplicate_tcp_binds() {
        let zero = VALID.replace("127.0.0.1:27900", "127.0.0.1:0");
        assert!(Config::parse(&zero).unwrap_err().contains("nonzero port"));

        let duplicate = VALID.replace("127.0.0.1:29900", "127.0.0.1:18443");
        assert!(
            Config::parse(&duplicate)
                .unwrap_err()
                .contains("must not be the same")
        );

        let duplicate_peerchat = VALID.replace("127.0.0.1:16667", "127.0.0.1:29900");
        assert!(
            Config::parse(&duplicate_peerchat)
                .unwrap_err()
                .contains("must not be the same")
        );
    }

    #[test]
    fn rejects_bad_title_secret() {
        let empty = VALID.replace("title_secret = \"0123456789\"", "title_secret = \"\"");
        assert!(Config::parse(&empty).unwrap_err().contains("title_secret"));

        let long = VALID.replace(
            "title_secret = \"0123456789\"",
            &format!(
                "title_secret = \"{}\"",
                "a".repeat(MAX_TITLE_SECRET_BYTES + 1)
            ),
        );
        assert!(Config::parse(&long).unwrap_err().contains("limit"));

        let space = VALID.replace(
            "title_secret = \"0123456789\"",
            "title_secret = \"abc def\"",
        );
        assert!(
            Config::parse(&space)
                .unwrap_err()
                .contains("printable ASCII")
        );
    }

    #[test]
    fn rejects_out_of_range_request_limit() {
        let text = VALID.replace("65536", "0");
        assert!(
            Config::parse(&text)
                .unwrap_err()
                .contains("max_request_bytes")
        );
    }

    #[test]
    fn parses_run_and_check_commands() {
        assert_eq!(
            parse_cli(["run".to_owned(), "--config".to_owned(), "a.toml".to_owned()]).unwrap(),
            CliCommand::Run(PathBuf::from("a.toml"))
        );
        assert_eq!(
            parse_cli(["--check-config".to_owned(), "--config=b.toml".to_owned()]).unwrap(),
            CliCommand::Check(PathBuf::from("b.toml"))
        );
        assert_eq!(parse_cli(["--help".to_owned()]).unwrap(), CliCommand::Help);
        assert!(parse_cli(["run".to_owned(), "--config".to_owned()]).is_err());
        assert!(parse_cli(["run".to_owned(), "extra".to_owned()]).is_err());
    }
}
