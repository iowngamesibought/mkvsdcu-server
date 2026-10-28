//! Independent codec for the SDK statistics transport (not HTTP stats reads).
//! Based on the pinned SDK gstats.c and update snapshot serializer 0x1056810.
//! No listener or persistent results acceptance is enabled by this module.

use std::collections::BTreeMap;

const MASK: &[u8] = b"GameSpy3D";
pub const END: &[u8] = b"\\final\\";
pub const MAX_FRAME: usize = 256 * 1024;

pub fn xor_payload(bytes: &mut [u8]) {
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte ^= MASK[i % MASK.len()];
    }
}

/// Client DoSend XORs the payload and then appends an unencoded terminator.
pub fn encode_frame(payload: &str) -> Result<Vec<u8>, &'static str> {
    if payload.len() > MAX_FRAME || payload.contains('\0') {
        return Err("invalid payload");
    }
    let mut frame = payload.as_bytes().to_vec();
    xor_payload(&mut frame);
    frame.extend_from_slice(END);
    Ok(frame)
}

pub fn decode_frame(frame: &[u8]) -> Result<String, &'static str> {
    let bytes = frame.strip_suffix(END).ok_or("missing terminator")?;
    if bytes.len() > MAX_FRAME {
        return Err("frame too large");
    }
    let mut plain = bytes.to_vec();
    xor_payload(&mut plain);
    if plain.contains(&0) {
        return Err("embedded null");
    }
    String::from_utf8(plain).map_err(|_| "non-UTF8 payload")
}

/// The SDK misleadingly calls this g_crc32; it is a wrapping polynomial hash,
/// not CRC-32. Restrict challenges to ASCII to avoid signed-char ambiguity.
pub fn authentication_response(
    challenge: &str,
    title_secret: &str,
) -> Result<String, &'static str> {
    if !challenge.is_ascii() || challenge.contains('\0') {
        return Err("invalid challenge");
    }
    let hash = challenge.bytes().fold(0i32, |h, b| {
        h.wrapping_mul(-1_664_117_991).wrapping_add(i32::from(b))
    });
    Ok(crate::gp::md5_hex(
        format!("{hash}{title_secret}").as_bytes(),
    ))
}

/// The client consumes at least 38 bytes and XOR-decodes the whole server
/// challenge. This response satisfies its challenge-field parser and minimum.
pub fn challenge_packet(challenge: &str) -> Result<Vec<u8>, &'static str> {
    if challenge.len() != 10 || !challenge.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("challenge must be ten ASCII alphanumerics");
    }
    let mut bytes = format!("\\lc\\1\\challenge\\{challenge}\\id\\1\\final\\").into_bytes();
    xor_payload(&mut bytes);
    Ok(bytes)
}

pub fn session_packet(connection_id: i32) -> Result<Vec<u8>, &'static str> {
    if connection_id <= 0 {
        return Err("invalid connection id");
    }
    let mut bytes = format!("\\lc\\2\\sesskey\\{connection_id}\\id\\1\\final\\").into_bytes();
    xor_payload(&mut bytes);
    Ok(bytes)
}

/// Player proof uses the SDK game challenge, distinct from title authentication.
pub fn player_response(
    connection_id: i32,
    partner_challenge: &str,
) -> Result<String, &'static str> {
    // SDK GenerateAuth has a 128-byte buffer and reserves 20 bytes beyond the
    // password and eight-byte game challenge. Reject inputs its client rejects.
    if connection_id <= 0
        || partner_challenge.is_empty()
        || !partner_challenge.is_ascii()
        || partner_challenge.contains('\0')
        || partner_challenge.len() + 8 + 20 >= 128
    {
        return Err("invalid player proof input");
    }
    let encoded = format!("{:08x}", (connection_id as u32) ^ 0x38f3_71e6);
    let challenge: String = encoded
        .bytes()
        .enumerate()
        .map(|(index, byte)| char::from(byte + 17 + index as u8))
        .collect();
    Ok(crate::gp::md5_hex(
        format!("{partner_challenge}{challenge}").as_bytes(),
    ))
}

/// Decode the nested key/value snapshot after the SDK escaped backslashes.
/// Duplicate fields are rejected, preserving a single meaning for each field.
pub fn snapshot_fields(data: &str) -> Result<Vec<(String, String)>, &'static str> {
    if data.len() > MAX_FRAME || data.contains(['\0', '\\']) {
        return Err("invalid snapshot");
    }
    let plain = data.replace('\x01', "\\");
    let parts: Vec<_> = plain
        .strip_prefix('\\')
        .ok_or("missing initial separator")?
        .split('\\')
        .collect();
    if !parts.len().is_multiple_of(2) {
        return Err("unpaired snapshot field");
    }
    let mut result: Vec<(String, String)> = Vec::new();
    let mut keys = std::collections::BTreeSet::new();
    for pair in parts.as_chunks::<2>().0 {
        if pair[0].is_empty() || !keys.insert(pair[0]) {
            return Err("duplicate or empty key");
        }
        result.push((pair[0].into(), pair[1].into()));
    }
    Ok(result)
}

/// Field names in the title's result snapshot. The core bucket set and the
/// indexed player buckets are taken from the update's own bucket tables.
pub mod field {
    pub const SNAPSHOT_TYPE: &str = "snapshot_type";
    /// The reporting profile, and its proof. Both are indexed: a console
    /// writes itself into slot 0 of the report it sends, so these carry the
    /// `_0` suffix while the flat names never appear on the wire.
    pub const REPORTER: &str = "pid_0";
    pub const AUTH: &str = "auth_0";
    pub const MATCH_ID: &str = "unique_game_id";
    pub const GAME_TYPE: &str = "game_type";
    pub const RANK_MODE: &str = "rank_mode";
    pub const ROUND: &str = "game_round";
    pub const ROUND_MAX: &str = "game_round_max";
    pub const PLAYER_COUNT: &str = "player_count";
    pub const GAME_ABORTED: &str = "game_aborted";
    pub const PROFILE_ABORTED: &str = "profile_aborted";
    pub const DISCONNECT: &str = "disconnect";
    pub const DISCONNECT_TYPE: &str = "disconnect_type";
    pub const PROFILE_ID: &str = "profile_id";
    pub const PLAYER_NAME: &str = "player_name";
}

/// One participant as the snapshot describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub index: u8,
    pub profile_id: u32,
    pub name: String,
    /// Rounds this participant won, from the indexed round bucket. The title
    /// emits the same counter under both the winner and score names.
    pub rounds_won: u32,
}

/// A decoded result snapshot. This is what the title sent, not a verdict:
/// deciding what it means for a player's record is the server's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultSnapshot {
    pub match_id: String,
    pub reporter: u32,
    pub auth: String,
    pub game_type: u32,
    pub rank_mode: u32,
    pub round: u32,
    pub round_max: u32,
    pub game_aborted: bool,
    /// The profile the title blames for an abort, when it named one.
    pub profile_aborted: Option<u32>,
    pub disconnect: bool,
    pub disconnect_type: u32,
    pub participants: Vec<Participant>,
}

/// Participants the title reports for one match. Two is the only count its
/// result producer emits.
pub const MAX_PARTICIPANTS: u8 = 2;

fn number(values: &BTreeMap<&str, &str>, key: &str) -> Result<u32, &'static str> {
    let Some(raw) = values.get(key) else {
        return Ok(0);
    };
    if raw.is_empty() || raw.len() > 10 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("non-numeric snapshot field");
    }
    raw.parse().map_err(|_| "snapshot field out of range")
}

fn flag(values: &BTreeMap<&str, &str>, key: &str) -> Result<bool, &'static str> {
    match number(values, key)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("snapshot flag is not zero or one"),
    }
}

/// Decode the nested snapshot of a completed match.
///
/// Unknown fields are ignored: the title emits presentation buckets such as
/// the chosen character and a score bank that carry no record meaning. Fields
/// this decoder does read must be well formed.
pub fn result_snapshot(fields: &[(String, String)]) -> Result<ResultSnapshot, &'static str> {
    let values: BTreeMap<&str, &str> = fields
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let reporter = number(&values, field::REPORTER)?;
    if reporter == 0 {
        return Err("missing reporting profile");
    }
    let match_id = *values
        .get(field::MATCH_ID)
        .ok_or("missing match identity")?;
    if match_id.is_empty() || match_id.len() > 64 || !match_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("invalid match identity");
    }
    let count = number(&values, field::PLAYER_COUNT)?;
    if count > u32::from(MAX_PARTICIPANTS) {
        return Err("unsupported participant count");
    }
    let mut participants = Vec::new();
    for index in 0..MAX_PARTICIPANTS {
        let profile = format!("{}_{index}", field::PROFILE_ID);
        if !values.contains_key(profile.as_str()) {
            continue;
        }
        let profile_id = number(&values, &profile)?;
        if profile_id == 0 || profile_id > i32::MAX as u32 {
            return Err("invalid participant profile");
        }
        let name = (*values
            .get(format!("{}_{index}", field::PLAYER_NAME).as_str())
            .ok_or("missing participant name")?)
        .to_owned();
        if name.is_empty() || name.len() > 64 {
            return Err("invalid participant name");
        }
        // The round buckets are indexed by participant slot. The winner and
        // score buckets carry the same counter, so either may supply it; a
        // malformed value is still an error.
        let winner = format!("round_0_round_winner_{index}");
        let score = format!("round_0_score_{index}");
        let rounds_won = if values.contains_key(winner.as_str()) {
            number(&values, &winner)?
        } else {
            number(&values, &score)?
        };
        if participants
            .iter()
            .any(|other: &Participant| other.profile_id == profile_id || other.name == name)
        {
            return Err("duplicate participant");
        }
        participants.push(Participant {
            index,
            profile_id,
            name,
            rounds_won,
        });
    }
    if count != 0 && participants.len() != count as usize {
        return Err("participant count does not match the entries");
    }
    let aborted = number(&values, field::PROFILE_ABORTED)?;
    Ok(ResultSnapshot {
        match_id: match_id.to_owned(),
        reporter,
        auth: (*values.get(field::AUTH).ok_or("missing player proof")?).to_owned(),
        game_type: number(&values, field::GAME_TYPE)?,
        rank_mode: number(&values, field::RANK_MODE)?,
        round: number(&values, field::ROUND)?,
        round_max: number(&values, field::ROUND_MAX)?,
        game_aborted: flag(&values, field::GAME_ABORTED)?,
        profile_aborted: (aborted != 0).then_some(aborted),
        disconnect: flag(&values, field::DISCONNECT)?,
        disconnect_type: number(&values, field::DISCONNECT_TYPE)?,
        participants,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(extra: &str) -> Vec<(String, String)> {
        let base = "snapshot_type1pid_07auth_0abcunique_game_idM1game_type0rank_mode1game_round1game_round_max1player_count2profile_id_07player_name_0Alphaprofile_id_19player_name_1Bravo";
        snapshot_fields(&format!("{base}{extra}")).unwrap()
    }

    #[test]
    fn result_snapshot_reads_participants_and_their_round_counters() {
        let decoded = result_snapshot(&snapshot(
            "round_0_round_winner_02round_0_round_winner_11character_05",
        ))
        .unwrap();
        assert_eq!(decoded.match_id, "M1");
        assert_eq!(decoded.reporter, 7);
        assert_eq!(decoded.auth, "abc");
        assert_eq!((decoded.round, decoded.round_max), (1, 1));
        assert_eq!(decoded.rank_mode, 1);
        assert!(!decoded.game_aborted && !decoded.disconnect);
        assert_eq!(decoded.profile_aborted, None);
        assert_eq!(
            decoded.participants,
            vec![
                Participant {
                    index: 0,
                    profile_id: 7,
                    name: "Alpha".into(),
                    rounds_won: 2
                },
                Participant {
                    index: 1,
                    profile_id: 9,
                    name: "Bravo".into(),
                    rounds_won: 1
                }
            ]
        );
    }

    #[test]
    fn score_bucket_stands_in_for_the_winner_bucket() {
        // The title reads one counter for both names, so either may arrive.
        let decoded = result_snapshot(&snapshot("round_0_score_01")).unwrap();
        assert_eq!(decoded.participants[0].rounds_won, 1);
        assert_eq!(decoded.participants[1].rounds_won, 0);
    }

    #[test]
    fn abort_and_disconnect_markers_are_decoded() {
        let decoded = result_snapshot(&snapshot("game_aborted1profile_aborted9")).unwrap();
        assert!(decoded.game_aborted);
        assert_eq!(decoded.profile_aborted, Some(9));

        let decoded = result_snapshot(&snapshot("disconnect1disconnect_type1")).unwrap();
        assert!(decoded.disconnect);
        assert_eq!(decoded.disconnect_type, 1);
    }

    #[test]
    fn malformed_snapshots_are_refused_rather_than_guessed() {
        // A participant count that disagrees with the entries present.
        assert!(
            snapshot_fields("pid_07auth_0aunique_game_idMplayer_count2")
                .map(|f| result_snapshot(&f))
                .unwrap()
                .is_err()
        );
        for extra in [
            // A non-numeric counter, a zero profile and a repeated player.
            "round_0_round_winner_0one",
            "game_aborted2",
        ] {
            assert!(
                result_snapshot(&snapshot(extra)).is_err(),
                "accepted {extra:?}"
            );
        }
        let duplicate = snapshot_fields(
            "pid_07auth_0aunique_game_idMprofile_id_07player_name_0Alphaprofile_id_17player_name_1Bravo",
        )
        .unwrap();
        assert!(result_snapshot(&duplicate).is_err());
        // Missing identity or reporter.
        assert!(result_snapshot(&snapshot_fields("pid_07auth_0a").unwrap()).is_err());
    }

    #[test]
    fn player_proof_uses_connection_game_challenge() {
        // Independently evaluated positional transform of 0x38f371e7.
        assert_eq!(
            player_response(1, "synthetic").unwrap(),
            crate::gp::md5_hex(b"syntheticDJyGLG|O")
        );
        assert_ne!(
            player_response(1, "synthetic"),
            player_response(2, "synthetic")
        );
        assert!(player_response(0, "synthetic").is_err());
    }
    #[test]
    fn framing_and_nested_snapshot_are_separate() {
        let p = "\\updgame\\\\sesskey\\17\\connid\\4\\done\\1\\gamedata\\\x01wins_0\x011\x01losses_1\x011";
        let encoded = encode_frame(p).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap(), p);
        assert_eq!(
            snapshot_fields("\x01wins_0\x011\x01losses_1\x011").unwrap(),
            vec![
                ("wins_0".into(), "1".into()),
                ("losses_1".into(), "1".into())
            ]
        );
        assert!(snapshot_fields("\x01wins\x011\x01wins\x012").is_err());
    }
    #[test]
    fn initial_challenge_satisfies_sdk_fixed_read() {
        let mut bytes = challenge_packet("0123456789").unwrap();
        assert_eq!(bytes.len(), 38);
        xor_payload(&mut bytes);
        assert_eq!(bytes, b"\\lc\\1\\challenge\\0123456789\\id\\1\\final\\");
    }
    #[test]
    fn auth_uses_signed_wrapping_polynomial_not_crc32() {
        // Independently calculated with Python's hashlib and explicit i32 wrap.
        assert_eq!(
            authentication_response("0123456789", "synthetic").unwrap(),
            "c7335187b0a78f76172dfbfd34bd25c4"
        );
        // For one ASCII byte the SDK hash is simply its numeric value.
        assert_eq!(
            authentication_response("A", "synthetic").unwrap(),
            crate::gp::md5_hex(b"65synthetic")
        );
        assert!(authentication_response("非ASCII", "synthetic").is_err());
    }

    /// The report console 10.0.0.220 sent after the first completed match,
    /// captured verbatim from the wire. Field order is the title's own.
    fn observed_report() -> String {
        let pairs = [
            ("auth_0", "4f5fa2712b8f7e2daf881fa56559390c"),
            ("profile_aborted", "0"),
            ("game_round", "1"),
            ("disconnect", "0"),
            ("disconnect_type", "0"),
            ("bank_0", "0"),
            ("player_0", "fakesha0w"),
            ("profile_id_0", "1"),
            ("character_0", "0"),
            ("mode_0", "0"),
            ("bank_1", "0"),
            ("player_1", "TESTUSE2333"),
            ("profile_id_1", "2"),
            ("character_1", "0"),
            ("mode_1", "0"),
            ("game_round_max", "1"),
            ("round_0_round_winner_0", "2"),
            ("round_0_round_winner_1", "0"),
            ("ctime_0", "0"),
            ("snapshot_type", "1"),
            ("ctime_1", "0"),
            ("unique_game_id", "434867459"),
            ("player_name_0", "fakesha0w"),
            ("player_name_1", "TESTUSE2333"),
            ("rank_mode", "1"),
            ("round_0_score_0", "2"),
            ("game_aborted", "0"),
            ("round_0_score_1", "0"),
            ("game_type", "0"),
            ("pid_0", "1"),
        ];
        let separator = char::from(1u8);
        let mut out = String::new();
        for (key, value) in pairs {
            out.push(separator);
            out.push_str(key);
            out.push(separator);
            out.push_str(value);
        }
        out
    }

    #[test]
    fn decodes_the_report_a_console_actually_sent() {
        let raw = observed_report();
        let report = result_snapshot(&snapshot_fields(&raw).expect("fields")).expect("snapshot");
        // The reporter and its proof come from the reporter's own slot 0.
        assert_eq!(report.reporter, 1);
        assert_eq!(report.auth, "4f5fa2712b8f7e2daf881fa56559390c");
        assert_eq!(report.match_id, "434867459");
        // No player_count field is sent at all; it must not be required.
        assert_eq!(report.participants.len(), 2);
        // Round counters are indexed by slot: the reporter won 2 rounds to 0.
        let winner = &report.participants[0];
        let loser = &report.participants[1];
        assert_eq!((winner.profile_id, winner.rounds_won), (1, 2));
        assert_eq!((loser.profile_id, loser.rounds_won), (2, 0));
        assert_eq!(winner.name, "fakesha0w");
        assert_eq!(loser.name, "TESTUSE2333");
    }
}
