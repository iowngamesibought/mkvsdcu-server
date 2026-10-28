//! GameSpy GPCM connection-manager codec.
//!
//! Evidence for the client side: the pinned GameSpy SDK snapshot
//! `openmoh/openmohaa@a2f3401`, files `GP/gpiConnect.c` and `GP/gpi.c`.
//! The client opens TCP 29900 and expects the server to speak first:
//!
//! ```text
//! server: \lc\1\challenge\<server challenge>\id\1\final\
//! client: \login\\challenge\<user challenge>\authtoken\<token>\partnerid\<id>\
//!         response\<md5>\port\<port>\productid\<id>\gamename\<name>\
//!         namespaceid\<id>\sdkrevision\<n>\quiet\<n>\id\1\final\
//! server: \lc\2\sesskey\<n>\userid\<n>\profileid\<n>\uniquenick\<name>\
//!         proof\<md5>\id\1\final\
//! ```
//!
//! `gpiProcessConnectionManager` only dispatches an answer to the connect
//! operation when `\id\` is present; `gpiAddOperation` fixes the connect
//! operation to ID 1, so both server messages carry `\id\1`.
//!
//! For the console pre-authenticated path the client sets `user` to the AuthService
//! `authToken` and uses the AuthService `partnerChallenge` as the password
//! (`gpiSendLogin`, `gpiProcessConnect`). The server therefore needs the token
//! and partner challenge from its own AuthService response to compute `proof`.

use md5::compute as md5_digest;

pub const CONNECTION_MANAGER_PORT: u16 = 29900;
pub const MESSAGE_END: &[u8] = b"\\final\\";
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_AUTH_TOKEN_BYTES: usize = 255;
pub const MAX_SERVER_CHALLENGE_BYTES: usize = 127;
pub const MAX_USER_CHALLENGE_BYTES: usize = 255;
pub const MAX_UNIQUE_NICK_BYTES: usize = 30;

/// The client hashes the partner challenge, the token and both challenges with
/// MD5 and compares the server's `proof` as 32 lowercase hex characters.
pub fn md5_hex(input: &[u8]) -> String {
    format!("{:x}", md5_digest(input))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpError {
    MessageTooLong,
    NotDelimited,
    OddFieldCount,
    UnexpectedCommand,
    MissingField(&'static str),
    FieldTooLong(&'static str),
    InvalidField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub user_challenge: String,
    pub auth_token: String,
    pub partner_id: Option<i32>,
    pub product_id: Option<i32>,
    pub namespace_id: Option<i32>,
    pub sdk_revision: Option<i32>,
    pub quiet: Option<i32>,
    pub port: Option<u16>,
    pub game_name: Option<String>,
    pub user: Option<String>,
    pub unique_nick: Option<String>,
}

/// Parse the pre-authenticated `\login\...\final\` message. Unknown fields are
/// ignored because the shipped client may send platform-specific additions;
/// known fields are still length- and syntax-checked.
pub fn parse_login(message: &str) -> Result<LoginRequest, GpError> {
    let message = parse_fields(message)?;
    if message.command != "login" {
        return Err(GpError::UnexpectedCommand);
    }

    let user_challenge = required(&message, "challenge", MAX_USER_CHALLENGE_BYTES)?;
    if !is_safe_value(user_challenge) {
        return Err(GpError::InvalidField("challenge"));
    }
    let auth_token = required(&message, "authtoken", MAX_AUTH_TOKEN_BYTES)?;
    if !is_safe_value(auth_token) {
        return Err(GpError::InvalidField("authtoken"));
    }

    Ok(LoginRequest {
        user_challenge: user_challenge.to_owned(),
        auth_token: auth_token.to_owned(),
        partner_id: optional_i32(&message, "partnerid")?,
        product_id: optional_i32(&message, "productid")?,
        namespace_id: optional_i32(&message, "namespaceid")?,
        sdk_revision: optional_i32(&message, "sdkrevision")?,
        quiet: optional_i32(&message, "quiet")?,
        port: optional_u16(&message, "port")?,
        game_name: optional_owned(&message, "gamename"),
        user: optional_owned(&message, "user"),
        unique_nick: optional_owned(&message, "uniquenick"),
    })
}

/// Server challenge message. The connect operation is always ID 1 in the SDK.
pub fn challenge_message(server_challenge: &str) -> Result<String, GpError> {
    if server_challenge.is_empty() {
        return Err(GpError::MissingField("challenge"));
    }
    if server_challenge.len() > MAX_SERVER_CHALLENGE_BYTES {
        return Err(GpError::FieldTooLong("challenge"));
    }
    if !is_safe_value(server_challenge) {
        return Err(GpError::InvalidField("challenge"));
    }
    Ok(format!(
        "\\lc\\1\\challenge\\{server_challenge}\\id\\1\\final\\"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSuccess<'a> {
    pub sess_key: u32,
    pub user_id: u32,
    pub profile_id: u32,
    pub unique_nick: &'a str,
    pub proof: &'a str,
}

/// `\lc\2` success message accepted by `gpiProcessConnect` in `GPI_LOGIN`.
pub fn login_response(success: &LoginSuccess<'_>) -> Result<String, GpError> {
    if success.sess_key == 0 || success.sess_key > i32::MAX as u32 {
        return Err(GpError::InvalidField("sesskey"));
    }
    if success.user_id == 0 {
        return Err(GpError::InvalidField("userid"));
    }
    if success.profile_id == 0 {
        return Err(GpError::InvalidField("profileid"));
    }
    if success.unique_nick.is_empty() {
        return Err(GpError::MissingField("uniquenick"));
    }
    if success.unique_nick.len() > MAX_UNIQUE_NICK_BYTES {
        return Err(GpError::FieldTooLong("uniquenick"));
    }
    if !is_safe_value(success.unique_nick) {
        return Err(GpError::InvalidField("uniquenick"));
    }
    if success.proof.len() != 32 || !success.proof.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GpError::InvalidField("proof"));
    }

    Ok(format!(
        "\\lc\\2\\sesskey\\{}\\userid\\{}\\profileid\\{}\\uniquenick\\{}\\proof\\{}\\id\\1\\final\\",
        success.sess_key, success.user_id, success.profile_id, success.unique_nick, success.proof
    ))
}

/// Error message shape read by `gpiCheckForError`: `\error\\err\...\errmsg\...`.
pub fn error_message(code: u16, message: &str) -> String {
    let message: String = message
        .chars()
        .map(|character| match character {
            '\\' | '\r' | '\n' => ' ',
            other => other,
        })
        .take(128)
        .collect();
    format!("\\error\\\\err\\{code}\\errmsg\\{message}\\final\\")
}

/// Compute the `proof` the client expects. Its check is:
/// `MD5(passwordHash + 48 spaces + user + serverChallenge + userChallenge +
/// passwordHash)`, where `passwordHash = MD5(partnerChallenge)` and `user` is
/// the auth token on the pre-authenticated path.
pub fn proof(
    partner_challenge: &str,
    auth_token: &str,
    server_challenge: &str,
    user_challenge: &str,
) -> String {
    let password_hash = md5_hex(partner_challenge.as_bytes());
    let mut input = String::with_capacity(
        password_hash.len() * 2
            + 48
            + auth_token.len()
            + server_challenge.len()
            + user_challenge.len(),
    );
    input.push_str(&password_hash);
    input.push_str(&" ".repeat(48));
    input.push_str(auth_token);
    input.push_str(server_challenge);
    input.push_str(user_challenge);
    input.push_str(&password_hash);
    md5_hex(input.as_bytes())
}

/// Offset one past the first `\final\` terminator, if the buffer contains one.
pub fn find_message_end(data: &[u8]) -> Option<usize> {
    data.windows(MESSAGE_END.len())
        .position(|window| window == MESSAGE_END)
        .map(|position| position + MESSAGE_END.len())
}

#[derive(Debug)]
struct Fields<'a> {
    command: &'a str,
    values: Vec<(&'a str, &'a str)>,
}

fn parse_fields(message: &str) -> Result<Fields<'_>, GpError> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(GpError::MessageTooLong);
    }
    if !message.starts_with('\\') {
        return Err(GpError::NotDelimited);
    }

    let message = message
        .strip_suffix("\\final\\")
        .unwrap_or(message)
        .strip_prefix('\\')
        .ok_or(GpError::NotDelimited)?;
    let tokens: Vec<&str> = message.split('\\').collect();
    if tokens.len() < 2 || !tokens.len().is_multiple_of(2) {
        return Err(GpError::OddFieldCount);
    }
    let command = *tokens.first().ok_or(GpError::OddFieldCount)?;
    if command.is_empty() {
        return Err(GpError::OddFieldCount);
    }
    if tokens
        .iter()
        .any(|token| token.contains(['\r', '\n', '\0']))
    {
        return Err(GpError::NotDelimited);
    }

    // The wire form is `\command\command-value\key\value...`; the first token
    // is the command, the second is its (usually empty) value.
    let mut values = Vec::with_capacity(tokens.len() / 2);
    let (pairs, _) = tokens[2..].as_chunks::<2>();
    for pair in pairs {
        values.push((pair[0], pair[1]));
    }
    Ok(Fields { command, values })
}

fn value<'a>(message: &'a Fields<'a>, key: &str) -> Option<&'a str> {
    message
        .values
        .iter()
        .find(|(field, _)| *field == key)
        .map(|(_, value)| *value)
}

fn required<'a>(
    message: &'a Fields<'a>,
    key: &'static str,
    max: usize,
) -> Result<&'a str, GpError> {
    let value = value(message, key).ok_or(GpError::MissingField(key))?;
    if value.is_empty() {
        return Err(GpError::MissingField(key));
    }
    if value.len() > max {
        return Err(GpError::FieldTooLong(key));
    }
    Ok(value)
}

fn optional_i32(message: &Fields<'_>, key: &'static str) -> Result<Option<i32>, GpError> {
    match value(message, key) {
        Some(value) => value
            .parse()
            .map(Some)
            .map_err(|_| GpError::InvalidField(key)),
        None => Ok(None),
    }
}

fn optional_u16(message: &Fields<'_>, key: &'static str) -> Result<Option<u16>, GpError> {
    match value(message, key) {
        Some(value) => value
            .parse()
            .map(Some)
            .map_err(|_| GpError::InvalidField(key)),
        None => Ok(None),
    }
}

fn optional_owned(message: &Fields<'_>, key: &str) -> Option<String> {
    value(message, key).map(str::to_owned)
}

/// GP values are delimited by backslashes and travel as ASCII. Refusing control
/// characters keeps a parsed value from becoming a second message.
fn is_safe_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGIN: &str = "\\login\\\\challenge\\USERCHAL\\authtoken\\TOKEN\\partnerid\\33\\response\\0123456789abcdef0123456789abcdef\\port\\6500\\productid\\11507\\gamename\\mkvsdcu\\namespaceid\\40\\sdkrevision\\7\\quiet\\0\\id\\1\\final\\";

    #[test]
    fn parses_preauthenticated_login() {
        let parsed = parse_login(LOGIN).unwrap();
        assert_eq!(parsed.user_challenge, "USERCHAL");
        assert_eq!(parsed.auth_token, "TOKEN");
        assert_eq!(parsed.partner_id, Some(33));
        assert_eq!(parsed.product_id, Some(11507));
        assert_eq!(parsed.namespace_id, Some(40));
        assert_eq!(parsed.port, Some(6500));
        assert_eq!(parsed.game_name.as_deref(), Some("mkvsdcu"));
    }

    #[test]
    fn rejects_other_commands_and_missing_token() {
        assert_eq!(
            parse_login("\\status\\\\sesskey\\1\\final\\"),
            Err(GpError::UnexpectedCommand)
        );
        assert_eq!(
            parse_login("\\login\\\\challenge\\x\\final\\"),
            Err(GpError::MissingField("authtoken"))
        );
    }

    #[test]
    fn rejects_control_characters_in_values() {
        assert_eq!(
            parse_login("\\login\\\\challenge\\x\\authtoken\\bad\nvalue\\final\\"),
            Err(GpError::NotDelimited)
        );
    }

    #[test]
    fn builds_challenge_with_connect_id() {
        assert_eq!(
            challenge_message("1234567890").unwrap(),
            "\\lc\\1\\challenge\\1234567890\\id\\1\\final\\"
        );
        assert!(challenge_message("bad\\value").is_err());
    }

    #[test]
    fn md5_matches_standard_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn proof_uses_the_client_field_order() {
        let partner_challenge = "PARTNER";
        let auth_token = "TOKEN";
        let server_challenge = "SERVER";
        let user_challenge = "USER";
        let password_hash = md5_hex(partner_challenge.as_bytes());
        let expected = md5_hex(
            format!(
                "{password_hash}{}{auth_token}{server_challenge}{user_challenge}{password_hash}",
                " ".repeat(48)
            )
            .as_bytes(),
        );
        assert_eq!(
            proof(
                partner_challenge,
                auth_token,
                server_challenge,
                user_challenge
            ),
            expected
        );
    }

    #[test]
    fn builds_success_response_with_fields_the_client_requires() {
        let response = login_response(&LoginSuccess {
            sess_key: 7,
            user_id: 8,
            profile_id: 9,
            unique_nick: "player9",
            proof: "0123456789abcdef0123456789abcdef",
        })
        .unwrap();
        assert_eq!(
            response,
            "\\lc\\2\\sesskey\\7\\userid\\8\\profileid\\9\\uniquenick\\player9\\proof\\0123456789abcdef0123456789abcdef\\id\\1\\final\\"
        );
    }

    #[test]
    fn session_key_fits_sdk_signed_integer() {
        let mut success = LoginSuccess {
            sess_key: i32::MAX as u32,
            user_id: 1,
            profile_id: 1,
            unique_nick: "player1",
            proof: "0123456789abcdef0123456789abcdef",
        };
        assert!(login_response(&success).is_ok());
        success.sess_key += 1;
        assert_eq!(
            login_response(&success),
            Err(GpError::InvalidField("sesskey"))
        );
        success.sess_key = 0;
        assert_eq!(
            login_response(&success),
            Err(GpError::InvalidField("sesskey"))
        );
    }

    #[test]
    fn finds_framed_messages() {
        assert_eq!(
            find_message_end(b"\\lc\\1\\challenge\\x\\final\\\\ka\\\\final\\"),
            Some(24)
        );
        assert_eq!(find_message_end(b"\\lc\\1"), None);
    }

    #[test]
    fn error_message_is_single_line() {
        let message = error_message(266, "bad\\token\nnext");
        assert_eq!(
            message,
            "\\error\\\\err\\266\\errmsg\\bad token next\\final\\"
        );
    }
}
