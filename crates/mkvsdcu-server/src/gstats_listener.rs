//! Authenticated result ingestion. Raw reports are never persisted.
//!
//! A console reports the match it just played. The report is accepted only if
//! the title authenticates, the reporting player proves ownership of a verified
//! login session, and the match it names is one the server watched two players
//! enter from a room. An accepted result updates both records once, in a single
//! transaction keyed to that pairing.
use crate::matches::{Matches, Outcome, Verdict};
use mkvsdcu_proto::gstats;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_CONNECTIONS: usize = 32;

fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("MKVSDCU_CHAT_TRACE").is_some_and(|value| value == "1"))
}

pub fn spawn(
    bind: SocketAddr,
    sessions: Arc<crate::session::AuthSessions>,
    matches: Arc<Matches>,
    title_secret: String,
) -> Result<JoinHandle<()>, String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("bind GStats {bind}: {e}"))?;
    println!(
        "[gstats] listening on {} (TCP, result ingestion)",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let count = Arc::new(AtomicUsize::new(0));
    let secret = Arc::new(title_secret);
    Ok(thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else {
                continue;
            };
            if count.fetch_add(1, AtomicOrdering::SeqCst) >= MAX_CONNECTIONS {
                count.fetch_sub(1, AtomicOrdering::SeqCst);
                continue;
            }
            let count = Arc::clone(&count);
            let secret = Arc::clone(&secret);
            let sessions = Arc::clone(&sessions);
            let matches = Arc::clone(&matches);
            thread::spawn(move || {
                if let Err(error) = serve(socket, &secret, &sessions, &matches) {
                    eprintln!("[gstats] {error}");
                }
                count.fetch_sub(1, AtomicOrdering::SeqCst);
            });
        }
    }))
}

/// What a report means for the two records.
///
/// The title settles some of this and not all of it. Where it does not, the
/// rule below is this server's stated policy, not a recovered one.
fn outcome(report: &gstats::ResultSnapshot) -> Result<(u32, u32, Option<u32>), String> {
    let (first, second) = match report.participants.as_slice() {
        [first, second] => (first, second),
        _ => return Err("result does not name both participants".into()),
    };
    let other = |player: &gstats::Participant| {
        if player.profile_id == first.profile_id {
            second
        } else {
            first
        }
    };
    let find = |profile: u32| {
        [first, second]
            .into_iter()
            .find(|player| player.profile_id == profile)
    };

    // An abort names the profile that quit, so the opponent is credited. An
    // abort is not counted as a disconnect: the title reports those apart.
    if let Some(aborted) = report.profile_aborted {
        let loser = find(aborted).ok_or("aborting profile is not a participant")?;
        return Ok((other(loser).profile_id, loser.profile_id, None));
    }
    if report.game_aborted {
        return Err("aborted result does not name the aborting profile".into());
    }

    // Local rule: a dropped connection is reported by the side that stayed, so
    // the reporter is credited and the opponent takes the loss and the
    // disconnect. The title marks that a disconnect happened without naming
    // whose it was.
    if report.disconnect {
        let reporter = find(report.reporter).ok_or("reporter is not a participant")?;
        let dropped = other(reporter);
        return Ok((
            reporter.profile_id,
            dropped.profile_id,
            Some(dropped.profile_id),
        ));
    }

    match first.rounds_won.cmp(&second.rounds_won) {
        Ordering::Greater => Ok((first.profile_id, second.profile_id, None)),
        Ordering::Less => Ok((second.profile_id, first.profile_id, None)),
        // Nothing in the report decides this, so nothing is written.
        Ordering::Equal => Err("result does not decide a winner".into()),
    }
}

/// Turn a decided outcome into the counter changes it means for both players.
///
/// The match itself is not recorded anywhere, so this must be called once per
/// pairing; the queue is what guarantees that, by handing each result to one
/// writer and only re-offering it if this fails.
fn commit(
    store: &crate::identity::IdentityStore,
    generation: u64,
    outcome: Outcome,
) -> Result<(), String> {
    store.apply_outcome(outcome.winner, outcome.loser, outcome.disconnect)?;
    println!(
        "[gstats] generation={generation} committed=true winner={} loser={} disconnect={:?}",
        outcome.winner, outcome.loser, outcome.disconnect
    );
    Ok(())
}

/// Apply every result the queue has decided but not yet applied.
///
/// Driven by session events rather than a timer, so it is called wherever a
/// pairing is created, answered or reported on. The queue hands each result
/// out once; a transient store failure gives it back, so it is retried on the
/// next event instead of being lost or counted twice.
pub fn flush_due_results(matches: &Matches, sessions: &crate::session::AuthSessions) {
    let due = matches.take_due();
    if due.is_empty() {
        return;
    }
    let Some(store) = sessions.identity_store() else {
        // With nowhere to write, holding the results achieves nothing but
        // keeping the queue full.
        for (generation, _) in due {
            println!(
                "[gstats] generation={generation} decided but no identity store is configured"
            );
            matches.settle(generation);
        }
        return;
    };
    for (generation, outcome) in due {
        match commit(&store, generation, outcome) {
            Ok(()) => matches.settle(generation),
            // Handed back on purpose: the next event retries it.
            Err(error) => {
                matches.release(generation);
                eprintln!("[gstats] generation={generation} not recorded, will retry: {error}")
            }
        }
    }
}

fn record(
    report: &gstats::ResultSnapshot,
    sessions: &crate::session::AuthSessions,
    matches: &Matches,
) -> Result<(), String> {
    let Some(session) = matches.session_for(&report.match_id, report.reporter) else {
        // Without an observed pairing there is no evidence both players were
        // in this match, so the report changes nothing.
        return Err(format!(
            "no watched session for match {:?} reported by profile {}",
            report.match_id, report.reporter
        ));
    };
    let mut reported = report
        .participants
        .iter()
        .map(|player| player.profile_id)
        .collect::<Vec<_>>();
    reported.sort_unstable();
    if reported.as_slice() != session.players {
        return Err(format!(
            "reported participants {reported:?} are not the watched pair {:?}",
            session.players
        ));
    }
    let (winner, loser, disconnect) = outcome(report)?;
    let outcome = Outcome {
        winner,
        loser,
        disconnect,
    };
    let generation = session.generation;
    match matches.report(generation, report.reporter, outcome) {
        Verdict::Agreed(_) => println!("[gstats] generation={generation} both peers agree"),
        Verdict::Held => println!(
            "[gstats] generation={generation} held from profile {}, awaiting the other peer",
            report.reporter
        ),
        Verdict::Conflict => {
            println!("[gstats] generation={generation} peers disagree; nothing recorded")
        }
        Verdict::Expired => println!(
            "[gstats] generation={generation} report from profile {} is too late; \
the pairing expired without both peers, nothing recorded",
            report.reporter
        ),
        Verdict::Ignored => println!(
            "[gstats] generation={generation} report from profile {} ignored; not awaiting one",
            report.reporter
        ),
    }
    // A report is itself a session event, so it writes whatever is due,
    // including the result this call may just have decided.
    flush_due_results(matches, sessions);
    Ok(())
}

fn serve(
    mut socket: TcpStream,
    secret: &str,
    sessions: &crate::session::AuthSessions,
    matches: &Matches,
) -> Result<(), String> {
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut random = [0u8; 14];
    openssl::rand::rand_bytes(&mut random).map_err(|e| e.to_string())?;
    let challenge: String = random[..10]
        .iter()
        .map(|b| char::from(b'0' + b % 10))
        .collect();
    let connection_id =
        (u32::from_be_bytes(random[10..].try_into().unwrap()) & 0x7fff_ffff).max(1) as i32;
    socket
        .write_all(&gstats::challenge_packet(&challenge)?)
        .map_err(|e| e.to_string())?;
    let mut pending = Vec::new();
    let auth = read_frame(&mut socket, &mut pending)?.ok_or("closed before auth")?;
    let (command, fields) = parse_fields(&auth)?;
    if command != "auth"
        || fields.get("id").map(String::as_str) != Some("1")
        || fields.get("gamename").is_none_or(String::is_empty)
    {
        return Err("invalid GStats auth frame".into());
    }
    let expected = gstats::authentication_response(&challenge, secret)?;
    if !fields.get("response").is_some_and(|response| {
        response.len() == expected.len()
            && openssl::memcmp::eq(response.as_bytes(), expected.as_bytes())
    }) {
        return Err("GStats authentication rejected".into());
    }
    socket
        .write_all(&gstats::session_packet(connection_id)?)
        .map_err(|e| e.to_string())?;
    println!("[gstats] authentication accepted");
    let mut game_session: Option<i32> = None;
    while let Some(frame) = read_frame(&mut socket, &mut pending)? {
        if trace_enabled() {
            println!("[gstats] trace frame {frame:?}");
        }
        let (command, fields) = parse_fields(&frame)?;
        let connid = fields.get("connid").and_then(|s| s.parse::<i32>().ok());
        if connid != Some(connection_id) {
            return Err("GStats connection id mismatch".into());
        }
        let sesskey = fields
            .get("sesskey")
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or("invalid game session key")?;
        match command {
            "newgame" => {
                if game_session.is_some() {
                    return Err("GStats game already active".into());
                }
                game_session = Some(sesskey);
            }
            "updgame" => {
                if game_session != Some(sesskey) {
                    return Err("GStats game was not created".into());
                }
                let done = fields.get("done").ok_or("missing completion flag")?;
                if done != "0" && done != "1" {
                    return Err("invalid completion flag".into());
                }
                let data = fields.get("gamedata").ok_or("missing game snapshot")?;
                let report = gstats::result_snapshot(&gstats::snapshot_fields(data)?)?;
                if !sessions.verify_result(
                    socket.peer_addr().map_err(|e| e.to_string())?.ip(),
                    report.reporter,
                    connection_id,
                    &report.auth,
                ) {
                    return Err("GStats player proof rejected".into());
                }
                if done == "1" {
                    game_session = None;
                    // A report that cannot be attributed is logged and dropped;
                    // it must not end the connection or the records.
                    if let Err(error) = record(&report, sessions, matches) {
                        eprintln!("[gstats] result not recorded: {error}");
                    }
                } else {
                    println!(
                        "[gstats] interim report accepted for match {:?}",
                        report.match_id
                    );
                }
                // The client does not wait for an acknowledgement here.
            }
            _ => return Err("unsupported GStats command".into()),
        }
    }
    Ok(())
}

fn parse_fields(frame: &str) -> Result<(&str, BTreeMap<String, String>), String> {
    let parts: Vec<_> = frame
        .strip_prefix('\\')
        .ok_or("unframed GStats message")?
        .split('\\')
        .collect();
    if parts.len() < 2 || !parts.len().is_multiple_of(2) {
        return Err("malformed GStats fields".into());
    }
    let mut fields = BTreeMap::new();
    for pair in parts[2..].as_chunks::<2>().0 {
        if pair[0].is_empty()
            || fields
                .insert(pair[0].to_owned(), pair[1].to_owned())
                .is_some()
        {
            return Err("duplicate or empty GStats field".into());
        }
    }
    Ok((parts[0], fields))
}

fn read_frame(socket: &mut TcpStream, pending: &mut Vec<u8>) -> Result<Option<String>, String> {
    loop {
        if let Some(at) = pending
            .windows(gstats::END.len())
            .position(|w| w == gstats::END)
        {
            let frame: Vec<_> = pending.drain(..at + gstats::END.len()).collect();
            return Ok(Some(gstats::decode_frame(&frame)?.to_owned()));
        }
        // A maximum-sized payload may already have a partial terminator.
        if pending.len() > gstats::MAX_FRAME + gstats::END.len() - 1 {
            return Err("GStats frame limit exceeded".into());
        }
        let mut chunk = [0; 2048];
        let count = socket.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            return if pending.is_empty() {
                Ok(None)
            } else {
                Err("truncated GStats frame".into())
            };
        }
        pending.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MATCH_ID: &str = "M1";

    #[derive(Clone, Copy)]
    enum Case {
        Valid,
        WrongTitle,
        WrongPartner,
        WrongProfile,
        SessionKeyAsChallenge,
        UnverifiedGp,
        WrongPeer,
        WrongGameSession,
    }

    /// Two players that agreed to a match through the challenge exchange.
    /// The reporting side announces `MATCH_ID`; its opponent keeps its own.
    fn watched_pair(reporter: u32, opponent: u32) -> Arc<Matches> {
        let matches = Arc::new(Matches::new());
        let peer_message = |profile: u32, mid: &str, answer: Option<u32>| {
            let answer = answer.map(|a| format!(";answer={a}")).unwrap_or_default();
            crate::matches::parse_peer_message(&format!(
                "0 ;msg={}{answer};b_mid={mid};b_PID={profile}",
                if answer.is_empty() {
                    crate::matches::MSG_CHALLENGE
                } else {
                    crate::matches::MSG_ANSWER
                }
            ))
            .unwrap()
        };
        let (from, to) = (format!("player{opponent}"), format!("player{reporter}"));
        matches.challenge(&from, &to, &peer_message(opponent, "opponent-mid", None));
        matches.answer(&to, &from, &peer_message(reporter, MATCH_ID, Some(0)));
        matches
    }

    fn snapshot(reporter: u32, proof: &str, extra: &str) -> String {
        format!(
            "\x01unique_game_id\x01{MATCH_ID}\x01pid_0\x01{reporter}\x01auth_0\x01{proof}\
\x01player_count\x012\x01profile_id_0\x011\x01player_name_0\x01Alpha\
\x01profile_id_1\x012\x01player_name_1\x01Bravo{extra}"
        )
    }

    fn run(case: Case) -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sessions = crate::session::AuthSessions::new();
        sessions.insert("token".into(), "partner".into());
        if !matches!(case, Case::UnverifiedGp) {
            sessions.bind_gp_peer(
                "token",
                if matches!(case, Case::WrongPeer) {
                    "192.0.2.7"
                } else {
                    "127.0.0.1"
                }
                .parse()
                .unwrap(),
            );
        }
        let matches = watched_pair(1, 2);
        let server = thread::spawn(move || {
            serve(
                listener.accept().unwrap().0,
                "synthetic",
                &sessions,
                &matches,
            )
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut challenge = [0; 38];
        client.read_exact(&mut challenge).unwrap();
        gstats::xor_payload(&mut challenge);
        let text = String::from_utf8(challenge.to_vec()).unwrap();
        let challenge = text
            .split("\\challenge\\")
            .nth(1)
            .unwrap()
            .split('\\')
            .next()
            .unwrap();
        let response = gstats::authentication_response(
            challenge,
            if matches!(case, Case::WrongTitle) {
                "wrong"
            } else {
                "synthetic"
            },
        )
        .unwrap();
        client
            .write_all(
                &gstats::encode_frame(&format!(
                    "\\auth\\\\gamename\\test\\response\\{response}\\port\\0\\id\\1"
                ))
                .unwrap(),
            )
            .unwrap();
        if !matches!(case, Case::WrongTitle) {
            // TCP may split even the small server session response.
            let mut encrypted = Vec::new();
            let text = loop {
                let mut byte = [0];
                client.read_exact(&mut byte).unwrap();
                encrypted.push(byte[0]);
                assert!(encrypted.len() <= 128);
                let mut decoded = encrypted.clone();
                gstats::xor_payload(&mut decoded);
                if decoded.ends_with(gstats::END) {
                    break String::from_utf8(decoded).unwrap();
                }
            };
            let id: i32 = text
                .split("\\sesskey\\")
                .nth(1)
                .unwrap()
                .split('\\')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            // Deliberately different from connection ID: the proof must use connid.
            let game_key = if id == 17 { 18 } else { 17 };
            let proof = gstats::player_response(
                if matches!(case, Case::SessionKeyAsChallenge) {
                    game_key
                } else {
                    id
                },
                if matches!(case, Case::WrongPartner) {
                    "wrong"
                } else {
                    "partner"
                },
            )
            .unwrap();
            let reporter = if matches!(case, Case::WrongProfile) {
                2
            } else {
                1
            };
            let submitted_key = if matches!(case, Case::WrongGameSession) {
                game_key + 1
            } else {
                game_key
            };
            let mut frames =
                gstats::encode_frame(&format!("\\newgame\\\\connid\\{id}\\sesskey\\{game_key}"))
                    .unwrap();
            frames.extend(
                gstats::encode_frame(&format!(
                    "\\updgame\\\\sesskey\\{submitted_key}\\connid\\{id}\\done\\1\\gamedata\\{}",
                    snapshot(reporter, &proof, "\x01round_0_round_winner_0\x011")
                ))
                .unwrap(),
            );
            client.write_all(&frames).unwrap();
        }
        drop(client);
        server.join().unwrap()
    }

    #[test]
    fn authenticated_player_result_is_received_without_history() {
        assert!(run(Case::Valid).is_ok());
    }

    #[test]
    fn wrong_title_secret_rejected() {
        assert_eq!(
            run(Case::WrongTitle).unwrap_err(),
            "GStats authentication rejected"
        );
    }

    #[test]
    fn player_proof_requires_partner_profile_peer_and_gp_verification() {
        for case in [
            Case::WrongPartner,
            Case::WrongProfile,
            Case::SessionKeyAsChallenge,
            Case::UnverifiedGp,
            Case::WrongPeer,
        ] {
            assert_eq!(run(case).unwrap_err(), "GStats player proof rejected");
        }
    }

    #[test]
    fn update_must_match_created_game_session() {
        assert_eq!(
            run(Case::WrongGameSession).unwrap_err(),
            "GStats game was not created"
        );
    }

    fn report(extra: &str, reporter: u32) -> gstats::ResultSnapshot {
        gstats::result_snapshot(
            &gstats::snapshot_fields(&snapshot(reporter, "proof", extra)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn the_player_who_won_more_rounds_wins_the_match() {
        assert_eq!(
            outcome(&report(
                "\x01round_0_round_winner_0\x012\x01round_0_round_winner_1\x011",
                1
            ))
            .unwrap(),
            (1, 2, None)
        );
        assert_eq!(
            outcome(&report("\x01round_0_round_winner_1\x013", 1)).unwrap(),
            (2, 1, None)
        );
    }

    #[test]
    fn an_undecided_result_is_not_written() {
        // Equal counters decide nothing, so neither record is touched.
        let error = outcome(&report(
            "\x01round_0_round_winner_0\x011\x01round_0_round_winner_1\x011",
            1,
        ))
        .unwrap_err();
        assert_eq!(error, "result does not decide a winner");
        assert_eq!(
            outcome(&report("", 1)).unwrap_err(),
            "result does not decide a winner"
        );
    }

    #[test]
    fn an_abort_credits_the_opponent_of_the_profile_that_quit() {
        assert_eq!(
            outcome(&report("\x01game_aborted\x011\x01profile_aborted\x012", 1)).unwrap(),
            (1, 2, None)
        );
        // Even when the aborting player had won more rounds.
        assert_eq!(
            outcome(&report(
                "\x01game_aborted\x011\x01profile_aborted\x011\x01round_0_round_winner_0\x019",
                1
            ))
            .unwrap(),
            (2, 1, None)
        );
        // An abort with no profile named is not guessed at.
        assert!(outcome(&report("\x01game_aborted\x011", 1)).is_err());
        // Nor is an abort blamed on someone outside the match.
        assert!(outcome(&report("\x01profile_aborted\x0199", 1)).is_err());
    }

    #[test]
    fn a_disconnect_credits_the_reporter_and_records_the_drop() {
        assert_eq!(
            outcome(&report("\x01disconnect\x011\x01disconnect_type\x011", 1)).unwrap(),
            (1, 2, Some(2))
        );
        // The same match reported by the other side credits that side.
        assert_eq!(
            outcome(&report("\x01disconnect\x011\x01disconnect_type\x011", 2)).unwrap(),
            (2, 1, Some(1))
        );
    }

    #[test]
    fn a_report_for_an_unwatched_match_changes_nothing() {
        let sessions = crate::session::AuthSessions::new();
        let matches = Arc::new(Matches::new());
        let error = record(
            &report("\x01round_0_round_winner_0\x011", 1),
            &sessions,
            &matches,
        )
        .unwrap_err();
        assert!(error.contains("no watched session"), "{error}");
    }

    #[test]
    fn a_report_naming_someone_outside_the_watched_pair_is_refused() {
        let sessions = crate::session::AuthSessions::new();
        // The watched pairing is 1 against 3, but the report claims 1 and 2.
        let matches = watched_pair(1, 3);
        let error = record(
            &report("\x01round_0_round_winner_0\x011", 1),
            &sessions,
            &matches,
        )
        .unwrap_err();
        assert!(error.contains("not the watched pair"), "{error}");
    }

    #[test]
    fn an_accepted_result_is_committed_once_for_its_pairing() {
        let directory = std::env::temp_dir().join(format!(
            "mkvdc-gstats-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = crate::identity::IdentityStore::open(directory.clone()).unwrap();
        let alpha = store
            .profile_for_ticket(&crate::identity::tests_support::ticket(b"Alpha", 1))
            .unwrap();
        let bravo = store
            .profile_for_ticket(&crate::identity::tests_support::ticket(b"Bravo", 1))
            .unwrap();
        let sessions = crate::session::AuthSessions::with_identity(store);
        let matches = watched_pair(alpha, bravo);
        let snapshot = gstats::result_snapshot(
            &gstats::snapshot_fields(&format!(
                "\x01unique_game_id\x01{MATCH_ID}\x01pid_0\x01{alpha}\x01auth_0\x01proof\
\x01player_count\x012\x01profile_id_0\x01{alpha}\x01player_name_0\x01Alpha\
\x01profile_id_1\x01{bravo}\x01player_name_1\x01Bravo\x01round_0_round_winner_0\x012"
            ))
            .unwrap(),
        )
        .unwrap();
        // One account is not enough: nothing is written while the opponent
        // is still expected.
        record(&snapshot, &sessions, &matches).unwrap();
        let store = sessions.identity_store().unwrap();
        assert_eq!(store.player(alpha).unwrap().unwrap().wins, 0);
        assert_eq!(store.player(bravo).unwrap().unwrap().games, 0);
        // The opponent describes the same result, so it is written once.
        let agreeing = gstats::result_snapshot(
            &gstats::snapshot_fields(&format!(
                "\x01unique_game_id\x01{MATCH_ID}\x01pid_0\x01{bravo}\x01auth_0\x01proof\
\x01player_count\x012\x01profile_id_0\x01{bravo}\x01player_name_0\x01Bravo\
\x01profile_id_1\x01{alpha}\x01player_name_1\x01Alpha\x01round_0_round_winner_1\x012"
            ))
            .unwrap(),
        )
        .unwrap();
        record(&agreeing, &sessions, &matches).unwrap();
        assert_eq!(store.player(alpha).unwrap().unwrap().wins, 1);
        assert_eq!(store.player(bravo).unwrap().unwrap().losses, 1);
        // A replay of either account is ignored, so nothing counts twice.
        record(&snapshot, &sessions, &matches).unwrap();
        record(&agreeing, &sessions, &matches).unwrap();
        assert_eq!(store.player(alpha).unwrap().unwrap().wins, 1);
        assert_eq!(store.player(alpha).unwrap().unwrap().games, 1);
        drop(sessions);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn maximum_payload_accepts_fragmented_terminator() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let payload = "a".repeat(gstats::MAX_FRAME);
        let mut pending = gstats::encode_frame(&payload).unwrap();
        let last = pending.pop().unwrap();
        client.write_all(&[last]).unwrap();
        assert_eq!(
            read_frame(&mut socket, &mut pending).unwrap(),
            Some(payload)
        );
    }
}
