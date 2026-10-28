//! XML views of local player aggregates. Ranking is a local policy, not an official rating.

// These two paths are the URLs the console requests, so the literals are
// the client's own and must not be renamed.
pub const PLAYER_PATH: &str = "/mkvsdcps3/GetPlayerStats.asp";
pub const LEADERBOARD_PATH: &str = "/mkvsdcps3/CreateOnlineStats.asp";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerStats {
    pub profile_id: u32,
    pub name: String,
    pub position: usize,
    pub wins: u32,
    pub losses: u32,
    pub disconnects: u32,
    pub games: u32,
    pub streak: u32,
    pub best_streak: u32,
}

pub fn profile_id(target: &str) -> Result<u32, &'static str> {
    let (path, query) = target.split_once('?').ok_or("missing query")?;
    if path != PLAYER_PATH {
        return Err("unknown path");
    }
    let value = query
        .strip_prefix("profile_id=")
        .ok_or("missing profile_id")?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid profile_id");
    }
    let id: u32 = value.parse().map_err(|_| "invalid profile_id")?;
    if id == 0 || id > i32::MAX as u32 {
        return Err("invalid profile_id");
    }
    Ok(id)
}

pub fn empty_player(id: u32) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><PLAYER profile_id=\"{id}\"></PLAYER>")
}

/// Only game type zero is established for the observed reporting path.
/// Untracked scoring/bank fields are omitted. Local skill is the win count.
pub fn player(row: &PlayerStats) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><PLAYER profile_id=\"{}\"><GAME_STATS game_type=\"0\" never_rank=\"{}\" never_position=\"{}\" never_wins=\"{}\" never_losses=\"{}\" never_disconnects=\"{}\" never_total_games=\"{}\" never_streak=\"{}\" never_best_streak=\"{}\"></GAME_STATS></PLAYER>",
        row.profile_id,
        row.wins,
        row.position,
        row.wins,
        row.losses,
        row.disconnects,
        row.games,
        row.streak,
        row.best_streak
    )
}

/// The client deliberately skips STATS child zero before reading ENTRY rows.
/// HEADER is a local placeholder; its name and contents are not inspected.
pub fn leaderboard(rows: &[PlayerStats]) -> String {
    use std::fmt::Write;
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ONLINE_STATS group=\"1\"><STATS reset_type=\"0\"><HEADER></HEADER>",
    );
    for row in rows {
        write!(xml,"<ENTRY column_1=\"{}\" column_2=\"{}\" column_3=\"{}\" column_4=\"{}\" column_5=\"{}\" column_6=\"{}\" column_7=\"{}\"></ENTRY>",row.position,escape(&row.name),row.wins,row.wins,row.losses,row.games,row.best_streak).unwrap();
    }
    xml.push_str("</STATS></ONLINE_STATS>");
    xml
}

fn escape(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if matches!(c, '\t' | '\n' | '\r')
                || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}') =>
            {
                out.push(c)
            }
            _ => out.push('\u{fffd}'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row() -> PlayerStats {
        PlayerStats {
            profile_id: 42,
            name: "A<&\"'".into(),
            position: 1,
            wins: 8,
            losses: 2,
            disconnects: 1,
            games: 10,
            streak: 3,
            best_streak: 5,
        }
    }
    #[test]
    fn accepts_profile_query_and_rejects_ambiguous_or_injected_values() {
        assert_eq!(profile_id(&format!("{PLAYER_PATH}?profile_id=42")), Ok(42));
        for suffix in ["0", "-1", "2147483648", "1&profile_id=2", "1%22", ""] {
            assert!(profile_id(&format!("{PLAYER_PATH}?profile_id={suffix}")).is_err());
        }
    }
    #[test]
    fn first_player_follows_ignored_header_and_names_are_escaped() {
        let xml = leaderboard(&[row()]);
        assert!(xml.contains("<STATS reset_type=\"0\"><HEADER></HEADER><ENTRY column_1=\"1\""));
        assert!(xml.contains("column_2=\"A&lt;&amp;&quot;&apos;\""));
        assert_eq!(xml.matches("<ENTRY ").count(), 1);
        assert!(xml.contains("column_4=\"8\" column_5=\"2\" column_6=\"10\" column_7=\"5\""));
    }
    #[test]
    fn player_history_maps_aggregates_without_untracked_scores() {
        let xml = player(&row());
        assert!(xml.contains(
            "never_wins=\"8\" never_losses=\"2\" never_disconnects=\"1\" never_total_games=\"10\""
        ));
        assert!(!xml.contains("never_scored"));
        assert!(empty_player(7).contains("<PLAYER profile_id=\"7\"></PLAYER>"));
    }
}
