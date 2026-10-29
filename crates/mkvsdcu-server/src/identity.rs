//! Name-keyed local profiles and transactional counters. No platform signature validation.
//! Ticket format: https://github.com/RPCS3/rpcs3/blob/master/rpcs3/Emu/NP/np_handler.cpp
//! Names deliberately define identity; a future name change requires explicit migration.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_TICKET: usize = 8192;
const MAX_PROFILES: usize = 10000;
const MAX_STATE: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlayerRow {
    pub profile_id: u32,
    pub name: String,
    pub wins: u32,
    pub losses: u32,
    pub disconnects: u32,
    pub games: u32,
    pub streak: u32,
    pub best_streak: u32,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// A match leaves nothing behind but the counters it moved. Earlier builds
/// also kept one marker per committed match and a durable generation counter
/// to key those markers by; both existed only to stop a result being counted
/// twice, which the pending-result queue in `matches` now guarantees. Those
/// fields are not accepted: a store written by such a build fails to open
/// rather than being silently rewritten.
struct State {
    version: u32,
    players: BTreeMap<String, PlayerRow>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            players: BTreeMap::new(),
        }
    }
}
pub struct IdentityStore {
    directory: PathBuf,
    state: Mutex<State>,
    _lock: File,
}
impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityStore").finish_non_exhaustive()
    }
}
impl IdentityStore {
    pub fn open(directory: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&directory).map_err(|_| "cannot create identity directory")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("store.lock"))
            .map_err(|_| "cannot open identity lock")?;
        lock.try_lock()
            .map_err(|_| "identity store already open or cannot be locked")?;
        for entry in fs::read_dir(&directory).map_err(|_| "cannot read identity directory")? {
            if entry
                .map_err(|_| "cannot inspect identity directory")?
                .path()
                .extension()
                .and_then(|s| s.to_str())
                == Some("profile")
            {
                return Err("legacy account-keyed identity records require a separate name-keyed storage directory".into());
            }
        }
        let path = directory.join("state.toml");
        let state = match File::open(path) {
            Ok(file) => {
                if file
                    .metadata()
                    .map_err(|_| "cannot inspect identity state")?
                    .len()
                    > MAX_STATE
                {
                    return Err("identity state exceeds capacity".into());
                }
                let mut body = String::new();
                file.take(MAX_STATE + 1)
                    .read_to_string(&mut body)
                    .map_err(|_| "cannot read identity state")?;
                if body.len() as u64 > MAX_STATE {
                    return Err("identity state exceeds capacity".into());
                }
                // Do not expose serde diagnostics: they can contain player names/state.
                toml::from_str::<State>(&body).map_err(|_| "invalid identity state")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(_) => return Err("cannot open identity state".into()),
        };
        validate_state(&state)?;
        Ok(Self {
            directory,
            state: Mutex::new(state),
            _lock: lock,
        })
    }
    pub fn profile_for_ticket(&self, base64: &str) -> Result<u32, String> {
        let name = ticket_identity(base64)?;
        let mut current = self
            .state
            .lock()
            .map_err(|_| "identity store lock failed")?;
        if let Some(row) = current.players.get(&name.to_ascii_lowercase()) {
            return Ok(row.profile_id);
        }
        if current.players.len() >= MAX_PROFILES {
            return Err("profile capacity exceeded".into());
        }
        let id = current
            .players
            .values()
            .map(|p| p.profile_id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|id| *id <= i32::MAX as u32)
            .ok_or("profile id space exhausted")?;
        let mut next = current.clone();
        next.players.insert(
            name.to_ascii_lowercase(),
            PlayerRow {
                profile_id: id,
                name,
                wins: 0,
                losses: 0,
                disconnects: 0,
                games: 0,
                streak: 0,
                best_streak: 0,
            },
        );
        self.persist(&next)?;
        *current = next;
        Ok(id)
    }
    pub fn player(&self, profile_id: u32) -> Result<Option<PlayerRow>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "identity store lock failed")?;
        Ok(state
            .players
            .values()
            .find(|p| p.profile_id == profile_id)
            .cloned())
    }
    pub fn leaderboard(&self) -> Result<Vec<PlayerRow>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "identity store lock failed")?;
        let mut rows: Vec<_> = state.players.values().cloned().collect();
        rows.sort_by(|a, b| {
            b.wins
                .cmp(&a.wins)
                .then(a.losses.cmp(&b.losses))
                .then(a.disconnects.cmp(&b.disconnects))
                .then(
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase()),
                )
                .then(a.profile_id.cmp(&b.profile_id))
        });
        Ok(rows)
    }
    /// Move both players' counters by one decided result, in one transaction.
    ///
    /// The result itself is not recorded: a match leaves only the counter
    /// changes it caused. Nothing here can therefore tell a second call apart
    /// from a second match, so the caller owns at-most-once. The queue in
    /// `matches` hands each decided result over once and only re-offers it if
    /// this call fails, which is what makes the retry safe.
    ///
    /// The caller must also establish the authoritative outcome; this does not
    /// interpret reports.
    pub fn apply_outcome(
        &self,
        winner: u32,
        loser: u32,
        disconnect: Option<u32>,
    ) -> Result<(), String> {
        let mut current = self
            .state
            .lock()
            .map_err(|_| "identity store lock failed")?;
        validate_participants(winner, loser, disconnect, &current)?;
        let mut next = current.clone();
        for row in next
            .players
            .values_mut()
            .filter(|p| p.profile_id == winner || p.profile_id == loser)
        {
            row.games = increment(row.games)?;
            if row.profile_id == winner {
                row.wins = increment(row.wins)?;
                row.streak = increment(row.streak)?;
                row.best_streak = row.best_streak.max(row.streak);
            } else {
                row.losses = increment(row.losses)?;
                row.streak = 0;
            }
            if disconnect == Some(row.profile_id) {
                row.disconnects = increment(row.disconnects)?;
            }
        }
        self.persist(&next)?;
        *current = next;
        Ok(())
    }
    fn persist(&self, state: &State) -> Result<(), String> {
        let body = toml::to_string(state).map_err(|_| "cannot serialize identity state")?;
        if body.len() as u64 > MAX_STATE {
            return Err("identity state exceeds capacity".into());
        }
        let mut nonce = [0; 16];
        openssl::rand::rand_bytes(&mut nonce).map_err(|_| "identity randomness failed")?;
        let temporary = self.directory.join(format!("{}.pending", hex(&nonce)));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| "cannot create identity transaction")?;
            file.write_all(body.as_bytes())
                .map_err(|_| "cannot write identity transaction")?;
            file.sync_all()
                .map_err(|_| "cannot sync identity transaction")?;
            drop(file);
            // std::fs::rename replaces an existing file on Windows too. Never
            // delete the destination first: old or new complete state stays visible.
            fs::rename(&temporary, self.directory.join("state.toml"))
                .map_err(|_| "cannot commit identity transaction")?;
            Ok::<(), String>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
fn increment(v: u32) -> Result<u32, String> {
    v.checked_add(1)
        .filter(|v| *v <= i32::MAX as u32)
        .ok_or_else(|| "stats counter exhausted".into())
}
fn validate_name(name: &str) -> Result<(), String> {
    if !(3..=16).contains(&name.len())
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("invalid NP online name".into());
    }
    Ok(())
}
fn validate_participants(
    winner: u32,
    loser: u32,
    disconnect: Option<u32>,
    state: &State,
) -> Result<(), String> {
    if winner == loser
        || ![winner, loser]
            .iter()
            .all(|id| state.players.values().any(|p| p.profile_id == *id))
        || disconnect.is_some_and(|id| id != winner && id != loser)
    {
        return Err("invalid outcome participants".into());
    }
    Ok(())
}
fn validate_state(state: &State) -> Result<(), String> {
    if state.version != 1 || state.players.len() > MAX_PROFILES {
        return Err("invalid identity state capacity/version".into());
    }
    let mut ids = BTreeSet::new();
    for (name, row) in &state.players {
        validate_name(name)?;
        validate_name(&row.name)?;
        if row.name.to_ascii_lowercase() != *name
            || row.profile_id == 0
            || row.profile_id > i32::MAX as u32
            || !ids.insert(row.profile_id)
            || [
                row.wins,
                row.losses,
                row.disconnects,
                row.games,
                row.streak,
                row.best_streak,
            ]
            .iter()
            .any(|v| *v > i32::MAX as u32)
            || row.wins.checked_add(row.losses) != Some(row.games)
            || row.streak > row.best_streak
            || row.best_streak > row.wins
            || row.disconnects > row.games
        {
            return Err("invalid player aggregate".into());
        }
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ticket_identity(encoded: &str) -> Result<String, String> {
    // Reject ignored whitespace/garbage and noncanonical padding before decoding.
    if encoded.is_empty() || encoded.len() > MAX_TICKET * 4 / 3 + 4 || !encoded.is_ascii() {
        return Err("invalid account ticket encoding".into());
    }
    let data =
        openssl::base64::decode_block(encoded).map_err(|_| "invalid account ticket encoding")?;
    if data.len() > MAX_TICKET || openssl::base64::encode_block(&data) != encoded {
        return Err("invalid account ticket encoding".into());
    }
    if data.len() < 8
        || data[..4] != 0x21010000u32.to_be_bytes()
        || u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize != data.len() - 8
    {
        return Err("invalid account ticket header".into());
    }
    let top = nodes(&data[8..])?;
    if top.len() != 2 || top[0].0 != 0x3000 || top[1].0 != 0x3002 {
        return Err("invalid account ticket containers".into());
    }
    let user = nodes(top[0].1)?;
    let expected = [
        (8, 20),
        (1, 4),
        (7, 8),
        (7, 8),
        (2, 8),
        (4, 32),
        (8, 4),
        (4, 4),
        (8, 24),
        (1, 4),
    ];
    if user.len() < expected.len()
        || !user
            .iter()
            .zip(expected)
            .all(|((tag, bytes), (t, n))| *tag == t && bytes.len() == n)
    {
        return Err("invalid account ticket identity schema".into());
    }
    let signature = nodes(top[1].1)?;
    if signature.len() != 2
        || signature
            .iter()
            .any(|(tag, bytes)| *tag != 8 || bytes.is_empty())
    {
        return Err("invalid account ticket signature container".into());
    }
    let padded = user[5].1;
    let end = padded.iter().position(|b| *b == 0).unwrap_or(padded.len());
    if padded[end..].iter().any(|b| *b != 0) {
        return Err("invalid NP online name padding".into());
    }
    let name = std::str::from_utf8(&padded[..end]).map_err(|_| "invalid NP online name")?;
    validate_name(name)?;
    Ok(name.to_owned())
}

fn nodes(mut data: &[u8]) -> Result<Vec<(u16, &[u8])>, String> {
    let mut result = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 || result.len() >= 32 {
            return Err("invalid account ticket TLV".into());
        }
        let tag = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if len > data.len() - 4 {
            return Err("invalid account ticket TLV length".into());
        }
        result.push((tag, &data[4..4 + len]));
        data = &data[4 + len..];
    }
    Ok(result)
}

/// Synthetic ticket construction shared by this crate's tests. These are
/// locally built byte patterns, never captured account material.
#[cfg(test)]
pub mod tests_support {
    fn tlv(tag: u16, data: &[u8], out: &mut Vec<u8>) {
        out.extend(tag.to_be_bytes());
        out.extend((data.len() as u16).to_be_bytes());
        out.extend(data);
    }
    pub fn ticket(name: &[u8], serial: u8) -> String {
        let mut user = Vec::new();
        let mut name = name.to_vec();
        name.resize(32, 0);
        for (tag, value) in [
            (8, vec![serial; 20]),
            (1, 256u32.to_be_bytes().to_vec()),
            (7, vec![0; 8]),
            (7, vec![1; 8]),
            (2, 101u64.to_be_bytes().to_vec()),
            (4, name),
            (8, vec![0; 4]),
            (4, vec![0; 4]),
            (8, vec![0; 24]),
            (1, vec![0; 4]),
            (0, vec![]),
            (0, vec![]),
        ] {
            tlv(tag, &value, &mut user);
        }
        let mut sig = Vec::new();
        tlv(8, &[0; 4], &mut sig);
        tlv(8, &[0; 56], &mut sig);
        let mut body = Vec::new();
        tlv(0x3000, &user, &mut body);
        tlv(0x3002, &sig, &mut body);
        let mut bytes = 0x21010000u32.to_be_bytes().to_vec();
        bytes.extend((body.len() as u32).to_be_bytes());
        bytes.extend(body);
        openssl::base64::encode_block(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::ticket;
    use super::*;
    fn directory() -> PathBuf {
        let mut random = [0; 16];
        openssl::rand::rand_bytes(&mut random).unwrap();
        std::env::temp_dir().join(format!("identity-test-{}", hex(&random)))
    }
    #[test]
    fn name_identity_and_counters_survive_restart() {
        let dir = directory();
        let store = IdentityStore::open(dir.clone()).unwrap();
        let a = store
            .profile_for_ticket(&ticket(b"Synthetic_A", 1))
            .unwrap();
        assert_eq!(
            a,
            store
                .profile_for_ticket(&ticket(b"synthetic_a", 2))
                .unwrap()
        );
        let b = store
            .profile_for_ticket(&ticket(b"Synthetic_B", 1))
            .unwrap();
        assert_ne!(a, b);
        assert!(IdentityStore::open(dir.clone()).is_err());
        store.apply_outcome(a, b, None).unwrap();
        // A profile that does not exist is not a participant.
        assert!(store.apply_outcome(a, 999, None).is_err());
        store.apply_outcome(a, b, Some(b)).unwrap();
        store.apply_outcome(b, a, None).unwrap();
        let winner = store.player(a).unwrap().unwrap();
        let loser = store.player(b).unwrap().unwrap();
        assert_eq!(
            (
                winner.wins,
                winner.losses,
                winner.games,
                winner.streak,
                winner.best_streak
            ),
            (2, 1, 3, 0, 2)
        );
        assert_eq!(
            (
                loser.wins,
                loser.losses,
                loser.games,
                loser.streak,
                loser.disconnects
            ),
            (1, 2, 3, 1, 1)
        );
        assert_eq!(store.leaderboard().unwrap()[0].profile_id, a);
        // The store owns the ranking: wins descending, then losses and
        // disconnects ascending, then the canonical name.
        assert_eq!(
            store
                .leaderboard()
                .unwrap()
                .iter()
                .map(|row| row.profile_id)
                .collect::<Vec<_>>(),
            vec![a, b]
        );
        drop(store);
        let reopened = IdentityStore::open(dir.clone()).unwrap();
        assert_eq!(reopened.player(a).unwrap(), Some(winner));
        assert_eq!(reopened.player(b).unwrap(), Some(loser));
        drop(reopened);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn failed_transaction_leaves_the_players_unchanged() {
        let dir = directory();
        let store = IdentityStore::open(dir.clone()).unwrap();
        let a = store.profile_for_ticket(&ticket(b"Alpha", 1)).unwrap();
        let b = store.profile_for_ticket(&ticket(b"Bravo", 1)).unwrap();
        let before = store.leaderboard().unwrap();
        assert!(store.apply_outcome(a, 999, None).is_err());
        // Force replacement failure after the transaction file is synced.
        fs::rename(dir.join("state.toml"), dir.join("saved.toml")).unwrap();
        fs::create_dir(dir.join("state.toml")).unwrap();
        assert!(store.apply_outcome(a, b, None).is_err());
        assert_eq!(store.leaderboard().unwrap(), before);
        fs::remove_dir(dir.join("state.toml")).unwrap();
        fs::rename(dir.join("saved.toml"), dir.join("state.toml")).unwrap();
        store.apply_outcome(a, b, None).unwrap();
        drop(store);
        let reopened = IdentityStore::open(dir.clone()).unwrap();
        assert_eq!(reopened.player(a).unwrap().unwrap().wins, 1);
        assert_eq!(reopened.player(b).unwrap().unwrap().losses, 1);
        drop(reopened);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rejects_malformed_names_and_tickets_without_state() {
        let dir = directory();
        let store = IdentityStore::open(dir.clone()).unwrap();
        for name in [
            b"".as_slice(),
            b"a",
            b"1Name",
            b"has space",
            b"Name\0hidden",
            b"way_too_long_name_here",
            b"No\xff",
        ] {
            assert!(store.profile_for_ticket(&ticket(name, 1)).is_err());
        }
        let data = openssl::base64::decode_block(&ticket(b"Alpha", 1)).unwrap();
        for end in 0..data.len() {
            assert!(
                store
                    .profile_for_ticket(&openssl::base64::encode_block(&data[..end]))
                    .is_err()
            );
        }
        assert!(!dir.join("state.toml").exists());
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn corrupted_state_and_legacy_store_fail_closed() {
        let dir = directory();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("old.profile"), "1\n").unwrap();
        assert!(IdentityStore::open(dir.clone()).is_err());
        fs::remove_file(dir.join("old.profile")).unwrap();
        fs::write(dir.join("state.toml"), "invalid").unwrap();
        assert!(IdentityStore::open(dir.clone()).is_err());
        // A store from a build that recorded each match is refused rather
        // than quietly rewritten without those records.
        fs::write(
            dir.join("state.toml"),
            format!(
                "version = 1\nnext_generation = 1000016\n\n[outcomes.{}]\n\
winner = 1\nloser = 2\n",
                "ab".repeat(32)
            ),
        )
        .unwrap();
        assert!(IdentityStore::open(dir.clone()).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn concurrent_results_each_count_exactly_once() {
        // Every call is a distinct match here, so none may be lost to another
        // thread's read-modify-write and none may be applied twice.
        let dir = directory();
        let store = std::sync::Arc::new(IdentityStore::open(dir.clone()).unwrap());
        let a = store.profile_for_ticket(&ticket(b"Alpha", 1)).unwrap();
        let b = store.profile_for_ticket(&ticket(b"Bravo", 1)).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                std::thread::spawn(move || store.apply_outcome(a, b, None).unwrap())
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(store.player(a).unwrap().unwrap().wins, 8);
        assert_eq!(store.player(b).unwrap().unwrap().losses, 8);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}
