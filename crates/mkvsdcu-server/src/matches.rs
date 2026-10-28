//! Game-session tracking: which two players agreed to play each other.
//!
//! A room is where players meet; a match is a separate one-versus-one session
//! between two of them. The title sets it up with a pair of player-targeted
//! peer messages carrying its own `;key=value` encoding: the challenger sends
//! `msg=10` and the player it challenged replies `msg=11` with an `answer`
//! field. Both messages carry the sender's profile and its match identity.
//!
//! Each player keeps its *own* match identity, so there is no shared value to
//! group them by. A session therefore records both identities and the server
//! gives every pairing its own generation, which is what a committed result is
//! keyed by. That stays correct whether or not the title ever reuses an
//! identity.
//!
//! What `answer` means is not established, so a session is recorded for every
//! answered challenge and the value is only logged. A declined challenge simply
//! produces a pairing that expires without a result, which costs nothing.
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Peer message types in the title's challenge exchange.
pub const MSG_CHALLENGE: u32 = 10;
pub const MSG_ANSWER: u32 = 11;

/// How long an unanswered challenge is remembered.
const CHALLENGE_TTL: Duration = Duration::from_secs(2 * 60);
/// How long a finished or abandoned session stays available for a late report.
const REPORT_GRACE: Duration = Duration::from_secs(10 * 60);
/// How long a session with no result at all is kept before it is dropped.
const SESSION_TTL: Duration = Duration::from_secs(60 * 60);
/// How long a pairing with one report waits for the other side. When it
/// closes, the single report is written on its own: a console that never
/// reports must not cost its opponent the result.
const AGREEMENT_WINDOW: Duration = Duration::from_secs(60);
/// Both participants, and no more: a third report cannot exist.
const MAX_REPORTS: usize = 2;
const MAX_SESSIONS: usize = 512;
const MAX_PENDING: usize = 512;
const MAX_VALUE_BYTES: usize = 64;

/// A decided result, as one peer reported it. Two peers must agree on this
/// exactly before it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub winner: u32,
    pub loser: u32,
    /// The profile whose connection dropped, when one did.
    pub disconnect: Option<u32>,
}

/// What a report means for the pairing it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Both peers reported the same outcome. Write it once.
    Agreed(Outcome),
    /// Held while the other peer is still expected.
    Held,
    /// The peers described different results. The pairing is abandoned
    /// and nothing is written, because there is no basis to prefer one.
    Conflict,
    /// Not a pairing awaiting a report: unknown, already decided, or
    /// from someone who did not play in it. The report is dropped.
    Ignored,
}

/// Why a pairing stopped being live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// A player left the room or lost its connection mid-match.
    Disconnected,
}

/// One player-targeted peer message, as far as this server reads it. Fields the
/// title includes but the server has no use for are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerMessage {
    pub msg: u32,
    pub answer: Option<u32>,
    pub profile_id: Option<u32>,
    pub match_id: Option<String>,
}

/// Decode the title's `;key=value;key=value` peer-message payload.
///
/// The payload follows the message's own leading parameter, so a caller passes
/// everything from the first `;`. Unknown keys are skipped rather than refused:
/// the title includes presentation and statistics fields here too.
pub fn parse_peer_message(payload: &str) -> Option<PeerMessage> {
    let body = payload.split_once(';')?.1;
    let mut parsed = PeerMessage::default();
    let mut seen_msg = false;
    for pair in body.split(';') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if value.len() > MAX_VALUE_BYTES {
            continue;
        }
        match key {
            "msg" => {
                parsed.msg = value.parse().ok()?;
                seen_msg = true;
            }
            "answer" => parsed.answer = value.parse().ok(),
            "b_PID" => {
                parsed.profile_id = value
                    .parse::<u32>()
                    .ok()
                    .filter(|id| *id > 0 && *id <= i32::MAX as u32);
            }
            "b_mid" => {
                parsed.match_id = (!value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_graphic()))
                .then(|| value.to_owned());
            }
            _ => {}
        }
    }
    seen_msg.then_some(parsed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Server-assigned identity, unique per pairing. A committed result is
    /// keyed by this, never by an identity the title chose.
    pub generation: u64,
    /// Each player's own match identity, in the same order as `players`.
    pub match_ids: [String; 2],
    /// Both participants' profile IDs, in ascending order.
    pub players: [u32; 2],
    pub ended: Option<Ended>,
}

impl Session {
    /// Whether either participant announced this identity.
    pub fn claims(&self, match_id: &str) -> bool {
        self.match_ids.iter().any(|known| known == match_id)
    }
}

struct Pending {
    challenger: String,
    profile_id: u32,
    match_id: String,
    at: Instant,
}

/// One peer's account of how the match ended.
struct Report {
    reporter: u32,
    outcome: Outcome,
    at: Instant,
}

struct Live {
    session: Session,
    started: Instant,
    ended_at: Option<Instant>,
    /// What each peer reported, at most one entry per participant.
    reports: Vec<Report>,
    /// The result once it is determined, by agreement or by the window
    /// closing. Set before it is written, and kept until the write is
    /// confirmed, so a failed write is retried rather than lost.
    decided: Option<Outcome>,
    /// Set once the result has been written, or once the pairing has been
    /// abandoned and never will be. The entry is kept for the report
    /// grace so replays resolve to it and are ignored, rather than
    /// looking like a fresh pairing.
    settled: bool,
    /// Nicknames of both participants, for departure handling.
    nicks: [String; 2],
}

#[derive(Default)]
struct Inner {
    /// Outstanding challenges, keyed by the nickname that was challenged.
    pending: BTreeMap<String, Pending>,
    sessions: BTreeMap<u64, Live>,
    next_generation: u64,
}

#[derive(Default)]
pub struct Matches {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Matches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Matches").finish_non_exhaustive()
    }
}

impl Matches {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start issuing generations at `base`.
    ///
    /// Committed results are deduplicated by generation in durable storage,
    /// so the counter must not restart at numbers a previous run already
    /// used; the identity store reserves the base.
    pub fn starting_at(base: u64) -> Self {
        let this = Self::default();
        this.lock().next_generation = base;
        this
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record a challenge from `from` to `to`.
    pub fn challenge(&self, from: &str, to: &str, message: &PeerMessage) {
        let (Some(profile_id), Some(match_id)) = (message.profile_id, message.match_id.clone())
        else {
            return;
        };
        if from == to {
            return;
        }
        let now = Instant::now();
        let mut inner = self.lock();
        inner.expire(now);
        if !inner.pending.contains_key(to) && inner.pending.len() >= MAX_PENDING {
            return;
        }
        inner.pending.insert(
            to.to_owned(),
            Pending {
                challenger: from.to_owned(),
                profile_id,
                match_id,
                at: now,
            },
        );
    }

    /// Record the reply to a challenge. Returns the session it formed.
    pub fn answer(&self, from: &str, to: &str, message: &PeerMessage) -> Option<Session> {
        let profile_id = message.profile_id?;
        let match_id = message.match_id.clone()?;
        let now = Instant::now();
        let mut inner = self.lock();
        inner.expire(now);
        // The answer travels back to the challenger, so the pending entry is
        // the one filed against the player that is now replying.
        let pending = inner.pending.remove(from)?;
        if pending.challenger != to || pending.profile_id == profile_id {
            return None;
        }
        if inner.sessions.len() >= MAX_SESSIONS {
            inner.drop_oldest_ended();
            if inner.sessions.len() >= MAX_SESSIONS {
                eprintln!("[match] session capacity reached; pairing not tracked");
                return None;
            }
        }
        inner.next_generation += 1;
        let generation = inner.next_generation;
        // Keep both arrays in one order so an identity stays with its player.
        let mut sides = [
            (pending.profile_id, pending.match_id, pending.challenger),
            (profile_id, match_id, from.to_owned()),
        ];
        sides.sort_by_key(|(id, _, _)| *id);
        let session = Session {
            generation,
            match_ids: [sides[0].1.clone(), sides[1].1.clone()],
            players: [sides[0].0, sides[1].0],
            ended: None,
        };
        inner.sessions.insert(
            generation,
            Live {
                session: session.clone(),
                started: now,
                ended_at: None,
                reports: Vec::new(),
                decided: None,
                settled: false,
                nicks: [sides[0].2.clone(), sides[1].2.clone()],
            },
        );
        println!(
            "[match] generation={generation} paired profiles={:?} answer={:?}",
            session.players, message.answer
        );
        Some(session)
    }

    /// A player left the room or dropped its connection.
    pub fn forget(&self, nick: &str) {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.pending.remove(nick);
        inner.pending.retain(|_, p| p.challenger != nick);
        for live in inner.sessions.values_mut() {
            if live.nicks.iter().any(|known| known == nick) && live.session.ended.is_none() {
                live.session.ended = Some(Ended::Disconnected);
                live.ended_at = Some(now);
                println!(
                    "[match] generation={} ended Disconnected",
                    live.session.generation
                );
            }
        }
        inner.expire(now);
    }

    /// Find the session a report belongs to. The reporter must be one of the
    /// two participants, and the identity must be one the pairing announced.
    pub fn session_for(&self, match_id: &str, reporter: u32) -> Option<Session> {
        let mut inner = self.lock();
        inner.expire(Instant::now());
        inner
            .sessions
            .values()
            .filter(|live| {
                live.session.claims(match_id) && live.session.players.contains(&reporter)
            })
            // Prefer the newest pairing if an identity is ever reused.
            .max_by_key(|live| live.session.generation)
            .map(|live| live.session.clone())
    }

    /// File one peer's account of how a pairing ended.
    ///
    /// A result is written only once both participants describe the same
    /// outcome. Until then it is held. Peers that disagree abandon the
    /// pairing and nothing is written, because nothing here can decide which
    /// of them is right. Anything that is not a pairing awaiting a report is
    /// ignored, including a replay of one already decided.
    pub fn report(&self, generation: u64, reporter: u32, outcome: Outcome) -> Verdict {
        let now = Instant::now();
        let mut inner = self.lock();
        let Some(live) = inner.sessions.get_mut(&generation) else {
            return Verdict::Ignored;
        };
        if live.settled || !live.session.players.contains(&reporter) {
            return Verdict::Ignored;
        }
        // Decided but not yet written: the writer retries it from the
        // queue, so a fresh account cannot reopen or change it.
        if live.decided.is_some() {
            return Verdict::Ignored;
        }
        // A peer repeating itself is idempotent; a peer contradicting itself
        // is as unusable as two peers contradicting each other.
        if let Some(seen) = live.reports.iter().find(|r| r.reporter == reporter) {
            if seen.outcome == outcome {
                return Verdict::Held;
            }
            live.settled = true;
            live.ended_at = Some(now);
            return Verdict::Conflict;
        }
        if live.reports.len() >= MAX_REPORTS {
            return Verdict::Ignored;
        }
        live.reports.push(Report {
            reporter,
            outcome,
            at: now,
        });
        let verdict = match live.reports.as_slice() {
            [_] => Verdict::Held,
            [first, second] if first.outcome == second.outcome => Verdict::Agreed(outcome),
            _ => Verdict::Conflict,
        };
        match verdict {
            // Determined, but not written yet: the caller writes it and
            // confirms with settle(). Until then the queue keeps it.
            Verdict::Agreed(agreed) => {
                live.decided = Some(agreed);
                live.ended_at = Some(now);
            }
            // Nothing will ever be written for a disputed pairing.
            Verdict::Conflict => {
                live.settled = true;
                live.ended_at = Some(now);
            }
            Verdict::Held | Verdict::Ignored => {}
        }
        verdict
    }

    /// Every result that is determined but not yet written: pairings both
    /// peers agreed on, and pairings whose agreement window has now closed
    /// with only one peer heard from.
    ///
    /// Nothing here runs on a timer. This is driven by session events, so a
    /// held report is carried forward until the next challenge, answer,
    /// departure or report moves it along. A player whose result looks stuck
    /// can start another session, and that alone drives the old one in.
    ///
    /// An entry stays here until `settle` confirms the write, so a write that
    /// fails is attempted again on the next event instead of being lost. The
    /// records key each result by generation, so a repeated write is a no-op.
    pub fn take_due(&self) -> Vec<(u64, Outcome)> {
        self.take_due_at(Instant::now())
    }

    /// `take_due` against a supplied clock, so the window is testable.
    pub fn take_due_at(&self, now: Instant) -> Vec<(u64, Outcome)> {
        let mut inner = self.lock();
        let mut due = Vec::new();
        for (generation, live) in inner.sessions.iter_mut() {
            if live.settled {
                continue;
            }
            // A single account whose window has closed decides the result.
            if live.decided.is_none()
                && let [only] = live.reports.as_slice()
                && now.duration_since(only.at) >= AGREEMENT_WINDOW
            {
                live.decided = Some(only.outcome);
                live.ended_at = Some(now);
            }
            if let Some(outcome) = live.decided {
                due.push((*generation, outcome));
            }
        }
        inner.expire(now);
        due
    }

    /// Confirm that a decided result has been written. Until this is called
    /// the result keeps coming back from `take_due`.
    pub fn settle(&self, generation: u64) {
        let mut inner = self.lock();
        if let Some(live) = inner.sessions.get_mut(&generation) {
            live.settled = true;
            live.ended_at.get_or_insert_with(Instant::now);
        }
    }

    /// Live pairings. Only the tests read this; nothing in the running server
    /// needs it, so it is not part of the public surface.
    #[cfg(test)]
    fn live(&self) -> Vec<Session> {
        let mut inner = self.lock();
        inner.expire(Instant::now());
        inner
            .sessions
            .values()
            .filter(|live| live.session.ended.is_none())
            .map(|live| live.session.clone())
            .collect()
    }
}

impl Inner {
    fn drop_oldest_ended(&mut self) {
        // Never discard an entry still holding an unwritten report: that is
        // the evidence a result rests on. Among the rest, prefer pairings
        // that have already finished, oldest first.
        if let Some(generation) = self
            .sessions
            .iter()
            .filter(|(_, live)| live.settled || live.reports.is_empty())
            .min_by_key(|(_, live)| {
                (
                    live.session.ended.is_none() && !live.settled,
                    live.ended_at.unwrap_or(live.started),
                )
            })
            .map(|(generation, _)| *generation)
        {
            self.sessions.remove(&generation);
        }
    }

    fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.at) < CHALLENGE_TTL);
        self.sessions.retain(|_, live| {
            // A report that has not been written is never dropped for age.
            // Nothing drives this on a timer, so the entry has to outlive
            // the quiet period until some later event claims it. Capacity
            // still bounds the queue.
            if !live.settled && (!live.reports.is_empty() || live.decided.is_some()) {
                return true;
            }
            match live.ended_at {
                // A finished session is kept long enough to accept its report.
                Some(ended) => now.duration_since(ended) < REPORT_GRACE,
                None => now.duration_since(live.started) < SESSION_TTL,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A challenge payload in the title's own encoding, as observed on the wire.
    fn payload(msg: u32, profile: u32, mid: &str, answer: Option<u32>) -> String {
        let answer = answer.map(|a| format!(";answer={a}")).unwrap_or_default();
        format!(
            "0 ;msg={msg}{answer};b_0_2=0;b_gv=0.085TU2-56;b_port=3074\
;b_addr=10.0.0.220:3074;b_gt=1;b_gm=0;b_mid={mid};b_PID={profile};b_ip=167772380"
        )
    }

    fn challenge(profile: u32, mid: &str) -> PeerMessage {
        parse_peer_message(&payload(MSG_CHALLENGE, profile, mid, None)).unwrap()
    }

    fn answer(profile: u32, mid: &str, value: u32) -> PeerMessage {
        parse_peer_message(&payload(MSG_ANSWER, profile, mid, Some(value))).unwrap()
    }

    #[test]
    fn reads_the_titles_peer_message_encoding() {
        let parsed = challenge(2, "435311728");
        assert_eq!(parsed.msg, MSG_CHALLENGE);
        assert_eq!(parsed.answer, None);
        assert_eq!(parsed.profile_id, Some(2));
        assert_eq!(parsed.match_id.as_deref(), Some("435311728"));

        let parsed = answer(1, "1750149478", 0);
        assert_eq!(parsed.msg, MSG_ANSWER);
        assert_eq!(parsed.answer, Some(0));
        assert_eq!(parsed.profile_id, Some(1));

        // A payload with no message type is not a peer message.
        assert_eq!(parse_peer_message("0 ;b_PID=1"), None);
        assert_eq!(parse_peer_message("no separator"), None);
        // A zero profile is refused rather than taken as a player.
        assert_eq!(
            parse_peer_message(&payload(MSG_CHALLENGE, 0, "1", None))
                .unwrap()
                .profile_id,
            None
        );
    }

    #[test]
    fn an_answered_challenge_pairs_the_two_players() {
        let matches = Matches::new();
        matches.challenge("p2", "p1", &challenge(2, "435311728"));
        // Nothing is paired until the challenge is answered.
        assert!(matches.live().is_empty());
        let session = matches
            .answer("p1", "p2", &answer(1, "1750149478", 0))
            .expect("pairing");
        assert_eq!(session.players, [1, 2]);
        // Each player keeps its own identity, held in player order.
        assert_eq!(
            session.match_ids,
            ["1750149478".to_owned(), "435311728".to_owned()]
        );
        assert_eq!(matches.live().len(), 1);
        // The challenge is consumed, so a replayed answer pairs nothing.
        assert!(
            matches
                .answer("p1", "p2", &answer(1, "1750149478", 0))
                .is_none()
        );
    }

    #[test]
    fn a_report_resolves_against_either_players_identity() {
        let matches = Matches::new();
        matches.challenge("p2", "p1", &challenge(2, "435311728"));
        let session = matches
            .answer("p1", "p2", &answer(1, "1750149478", 0))
            .unwrap();
        // Whichever identity a console reports, and whichever side reports it.
        for mid in ["435311728", "1750149478"] {
            for reporter in [1, 2] {
                assert_eq!(
                    matches.session_for(mid, reporter).map(|s| s.generation),
                    Some(session.generation)
                );
            }
        }
        // Not a participant, and an identity neither side announced.
        assert!(matches.session_for("435311728", 7).is_none());
        assert!(matches.session_for("999", 1).is_none());
        // A decided pairing stays resolvable for the report grace, which is
        // what lets a replay be recognised; report() is what refuses it.
        let agreed = Outcome {
            winner: 1,
            loser: 2,
            disconnect: None,
        };
        assert_eq!(matches.report(session.generation, 2, agreed), Verdict::Held);
        assert_eq!(
            matches.report(session.generation, 1, agreed),
            Verdict::Agreed(agreed)
        );
        assert_eq!(
            matches.report(session.generation, 1, agreed),
            Verdict::Ignored
        );
    }

    #[test]
    fn a_rematch_gets_its_own_generation() {
        let matches = Matches::new();
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        let first = matches.answer("p1", "p2", &answer(1, "M1", 0)).unwrap();
        // The same two players play again, reusing both identities.
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        let second = matches.answer("p1", "p2", &answer(1, "M1", 0)).unwrap();
        assert_ne!(first.generation, second.generation);
        // A report now resolves to the newer pairing.
        assert_eq!(
            matches.session_for("M1", 1).map(|s| s.generation),
            Some(second.generation)
        );
    }

    #[test]
    fn an_answer_without_a_matching_challenge_pairs_nothing() {
        let matches = Matches::new();
        // No challenge was ever filed.
        assert!(matches.answer("p1", "p2", &answer(1, "M1", 0)).is_none());
        // Answered by someone the challenge was not sent to.
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        assert!(matches.answer("p3", "p2", &answer(3, "M3", 0)).is_none());
        // Answer claiming the challenger's own profile.
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        assert!(matches.answer("p1", "p2", &answer(2, "M1", 0)).is_none());
        // A player cannot challenge itself.
        matches.challenge("p1", "p1", &challenge(1, "M1"));
        assert!(matches.answer("p1", "p1", &answer(1, "M1", 0)).is_none());
        assert!(matches.live().is_empty());
    }

    #[test]
    fn leaving_ends_the_session_but_keeps_it_reportable() {
        let matches = Matches::new();
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        let session = matches.answer("p1", "p2", &answer(1, "M1", 0)).unwrap();
        matches.forget("p2");
        assert!(matches.live().is_empty());
        let ended = matches.session_for("M1", 1).expect("still reportable");
        assert_eq!(ended.ended, Some(Ended::Disconnected));
        assert_eq!(ended.generation, session.generation);
    }

    #[test]
    fn an_unanswered_challenge_and_an_unreported_session_expire() {
        let matches = Matches::new();
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        {
            let mut inner = matches.lock();
            let at = inner.pending["p1"].at;
            inner.pending.get_mut("p1").unwrap().at = at - CHALLENGE_TTL;
        }
        assert!(matches.answer("p1", "p2", &answer(1, "M1", 0)).is_none());

        matches.challenge("p2", "p1", &challenge(2, "M2"));
        let session = matches.answer("p1", "p2", &answer(1, "M1", 0)).unwrap();
        {
            let mut inner = matches.lock();
            let started = inner.sessions[&session.generation].started;
            inner.sessions.get_mut(&session.generation).unwrap().started = started - SESSION_TTL;
        }
        assert!(matches.live().is_empty());
        assert!(matches.session_for("M1", 1).is_none());
    }

    fn paired(matches: &Matches) -> Session {
        matches.challenge("p2", "p1", &challenge(2, "M2"));
        matches.answer("p1", "p2", &answer(1, "M1", 0)).unwrap()
    }

    fn won_by(winner: u32, loser: u32) -> Outcome {
        Outcome {
            winner,
            loser,
            disconnect: None,
        }
    }

    #[test]
    fn a_result_is_written_only_once_both_peers_describe_it_the_same_way() {
        let matches = Matches::new();
        let session = paired(&matches);
        let outcome = won_by(1, 2);
        // The first account is held: one peer is not evidence enough.
        assert_eq!(
            matches.report(session.generation, 1, outcome),
            Verdict::Held
        );
        assert!(matches.take_due().is_empty(), "nothing is due yet");
        // The second account matches, so the result is decided.
        assert_eq!(
            matches.report(session.generation, 2, outcome),
            Verdict::Agreed(outcome)
        );
        // It stays due until the write is confirmed, so a store failure
        // is retried rather than dropped.
        assert_eq!(matches.take_due(), vec![(session.generation, outcome)]);
        assert_eq!(matches.take_due(), vec![(session.generation, outcome)]);
        matches.settle(session.generation);
        assert!(matches.take_due().is_empty(), "written once");
        // And a later account cannot reopen it.
        assert_eq!(
            matches.report(session.generation, 1, won_by(2, 1)),
            Verdict::Ignored
        );
    }

    #[test]
    fn peers_that_disagree_write_nothing() {
        let matches = Matches::new();
        let session = paired(&matches);
        assert_eq!(
            matches.report(session.generation, 1, won_by(1, 2)),
            Verdict::Held
        );
        // Each claims the win. Nothing here can decide which is right.
        assert_eq!(
            matches.report(session.generation, 2, won_by(2, 1)),
            Verdict::Conflict
        );
        // The pairing is abandoned: no late report revives it, and the
        // window must never hand the disputed result over for writing.
        assert_eq!(
            matches.report(session.generation, 1, won_by(1, 2)),
            Verdict::Ignored
        );
        assert!(
            matches
                .take_due_at(Instant::now() + AGREEMENT_WINDOW * 2)
                .is_empty()
        );
    }

    #[test]
    fn a_peer_contradicting_itself_is_a_conflict_too() {
        let matches = Matches::new();
        let session = paired(&matches);
        let outcome = won_by(1, 2);
        assert_eq!(
            matches.report(session.generation, 1, outcome),
            Verdict::Held
        );
        // A retransmission of the same account changes nothing.
        assert_eq!(
            matches.report(session.generation, 1, outcome),
            Verdict::Held
        );
        // The same peer now claiming the opposite is unusable evidence.
        assert_eq!(
            matches.report(session.generation, 1, won_by(2, 1)),
            Verdict::Conflict
        );
    }

    #[test]
    fn a_silent_opponent_does_not_cost_the_other_player_the_result() {
        let matches = Matches::new();
        let session = paired(&matches);
        let outcome = won_by(1, 2);
        matches.report(session.generation, 1, outcome);
        // Before the window closes the result is still held.
        assert!(matches.take_due().is_empty());
        // Once it closes, the one account there is becomes due.
        let due = matches.take_due_at(Instant::now() + AGREEMENT_WINDOW);
        assert_eq!(due, vec![(session.generation, outcome)]);
        // Confirming the write is what retires it; only then is it gone.
        matches.settle(session.generation);
        assert!(
            matches
                .take_due_at(Instant::now() + AGREEMENT_WINDOW * 3)
                .is_empty()
        );
        assert_eq!(
            matches.report(session.generation, 2, outcome),
            Verdict::Ignored
        );
    }

    #[test]
    fn a_report_outside_the_queue_is_ignored() {
        let matches = Matches::new();
        let session = paired(&matches);
        let outcome = won_by(1, 2);
        // A generation that was never paired here.
        assert_eq!(
            matches.report(session.generation + 99, 1, outcome),
            Verdict::Ignored
        );
        // Someone who did not play in this pairing.
        assert_eq!(
            matches.report(session.generation, 7, outcome),
            Verdict::Ignored
        );
    }

    #[test]
    fn a_held_report_survives_the_quiet_period_until_an_event_drives_it() {
        let matches = Matches::new();
        let session = paired(&matches);
        let outcome = won_by(1, 2);
        matches.report(session.generation, 1, outcome);
        // Both players leave, and far longer than the report grace passes with
        // nothing happening. An unwritten report must not be aged out, since
        // nothing drives the queue on a timer.
        matches.forget("p1");
        matches.forget("p2");
        let later = Instant::now() + REPORT_GRACE + SESSION_TTL;
        assert_eq!(
            matches.take_due_at(later),
            vec![(session.generation, outcome)]
        );
        // Still unwritten, so a second sweep after the same long silence
        // offers it again rather than discarding it.
        assert_eq!(
            matches.take_due_at(later),
            vec![(session.generation, outcome)]
        );
    }
}
