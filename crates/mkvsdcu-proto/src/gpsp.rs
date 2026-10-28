//! GameSpy Presence search protocol (GPSP, TCP 29901).
//!
//! The title resolves a player's unique nickname to a profile here. It opens
//! one connection per lookup, sends a backslash-delimited `searchunique`
//! request, and waits for a reply terminated by `final`. Observed on the
//! operator's console during a challenge: each side looks up its opponent's
//! nickname, and the match cannot proceed until that search completes.
//!
//! Reply contract, taken from `gpiSearch.c` (`gpiProcessSearch`) in the
//! pinned SDK snapshot:
//!
//! - `bsr` carries a profile ID and starts one result record.
//! - `nick`, `uniquenick`, `namespaceid`, `firstname`, `lastname` and `email`
//!   are the record's fields, readable in any order; unknown keys are ignored.
//! - A following `bsr` or `bsrdone` ends the record.
//! - `bsrdone` ends the search. An optional `more` key follows it.
//! - Any other key at the top level is a fatal `GP_PARSE` error, so no
//!   leading status key may be added.
//! - No match is not an error: a reply of just `bsrdone` is a zero-result
//!   search and the client's callback still reports success.

/// The request and reply key/value separator.
const SEP: char = '\\';
/// Longest request accepted; the SDK's own buffer is far smaller than this.
pub const MAX_REQUEST_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchUnique {
    /// The session key the client was given at GPCM login, as sent.
    pub sesskey: String,
    /// The profile making the request.
    pub profile_id: u32,
    /// The nickname being resolved.
    pub uniquenick: String,
    /// The namespace list from the request, echoed back as `namespaceid`.
    pub namespace_id: u32,
    pub game_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpspError {
    NotSearchUnique,
    MissingField,
    InvalidField,
    TooLong,
}

/// Position just past the first `final` key, or `None` while incomplete. The
/// client sends one request per connection, but framing on `final` keeps a
/// second request on the same socket readable.
pub fn request_end(text: &str) -> Option<usize> {
    let marker = "\\final\\";
    text.find(marker).map(|at| at + marker.len())
}

fn pairs(request: &str) -> Vec<(&str, &str)> {
    let mut fields = request.split(SEP).skip_while(|field| field.is_empty());
    let mut out = Vec::new();
    while let Some(key) = fields.next() {
        if key.is_empty() {
            continue;
        }
        out.push((key, fields.next().unwrap_or("")));
    }
    out
}

/// Parse one `searchunique` request. The `searchunique` key carries an empty
/// value, so the first pair is the command itself.
pub fn parse_search_unique(request: &str) -> Result<SearchUnique, GpspError> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(GpspError::TooLong);
    }
    let fields = pairs(request);
    if !fields.iter().any(|(key, _)| *key == "searchunique") {
        return Err(GpspError::NotSearchUnique);
    }
    let value = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    };
    let uniquenick = value("uniquenick").ok_or(GpspError::MissingField)?;
    if uniquenick.is_empty() || uniquenick.len() > 64 {
        return Err(GpspError::InvalidField);
    }
    Ok(SearchUnique {
        sesskey: value("sesskey").unwrap_or_default().to_owned(),
        profile_id: value("profileid")
            .ok_or(GpspError::MissingField)?
            .parse()
            .map_err(|_| GpspError::InvalidField)?,
        uniquenick: uniquenick.to_owned(),
        namespace_id: value("namespaces")
            .unwrap_or("0")
            .parse()
            .map_err(|_| GpspError::InvalidField)?,
        game_name: value("gamename").unwrap_or_default().to_owned(),
    })
}

/// A value may not contain the separator, or it would reframe the reply.
fn safe(value: &str) -> bool {
    !value.contains(SEP) && !value.is_empty()
}

/// One matching profile, then the end of the search.
pub fn search_result(
    profile_id: u32,
    nick: &str,
    uniquenick: &str,
    namespace_id: u32,
) -> Option<String> {
    if !safe(nick) || !safe(uniquenick) {
        return None;
    }
    Some(format!(
        "\\bsr\\{profile_id}\\nick\\{nick}\\uniquenick\\{uniquenick}\\namespaceid\\{namespace_id}\\bsrdone\\\\final\\"
    ))
}

/// A completed search with no matches. Not an error for the client.
pub fn no_results() -> String {
    "\\bsrdone\\\\final\\".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED: &str = "\\searchunique\\\\sesskey\\690895341\\profileid\\2\\uniquenick\\fakesha0w\\namespaces\\0\\gamename\\mkvsdcu\\final\\";

    #[test]
    fn parses_the_request_observed_on_the_console() {
        assert_eq!(
            parse_search_unique(OBSERVED),
            Ok(SearchUnique {
                sesskey: "690895341".into(),
                profile_id: 2,
                uniquenick: "fakesha0w".into(),
                namespace_id: 0,
                game_name: "mkvsdcu".into(),
            })
        );
        assert_eq!(request_end(OBSERVED), Some(OBSERVED.len()));
    }

    #[test]
    fn framing_waits_for_final_and_allows_a_trailing_request() {
        let partial = &OBSERVED[..OBSERVED.len() - 4];
        assert_eq!(request_end(partial), None);
        let two = format!("{OBSERVED}{OBSERVED}");
        let end = request_end(&two).expect("first request framed");
        assert_eq!(end, OBSERVED.len());
        assert_eq!(request_end(&two[end..]), Some(OBSERVED.len()));
    }

    #[test]
    fn rejects_other_commands_and_bad_fields() {
        assert_eq!(
            parse_search_unique("\\login\\\\final\\"),
            Err(GpspError::NotSearchUnique)
        );
        assert_eq!(
            parse_search_unique("\\searchunique\\\\profileid\\2\\final\\"),
            Err(GpspError::MissingField)
        );
        assert_eq!(
            parse_search_unique("\\searchunique\\\\profileid\\x\\uniquenick\\a\\final\\"),
            Err(GpspError::InvalidField)
        );
        assert_eq!(
            parse_search_unique(&"x".repeat(MAX_REQUEST_BYTES + 1)),
            Err(GpspError::TooLong)
        );
    }

    #[test]
    fn result_and_empty_replies_match_the_client_grammar() {
        assert_eq!(
            search_result(2, "TESTUSE2333", "TESTUSE2333", 0).unwrap(),
            "\\bsr\\2\\nick\\TESTUSE2333\\uniquenick\\TESTUSE2333\\namespaceid\\0\\bsrdone\\\\final\\"
        );
        assert_eq!(no_results(), "\\bsrdone\\\\final\\");
        // Both replies must terminate so the client stops waiting.
        assert!(request_end(&search_result(1, "a", "a", 0).unwrap()).is_some());
        assert!(request_end(&no_results()).is_some());
        // A separator in a name would reframe the reply.
        assert_eq!(search_result(1, "a\\b", "a", 0), None);
        assert_eq!(search_result(1, "a", "", 0), None);
    }
}
