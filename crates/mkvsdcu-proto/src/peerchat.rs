//! PeerChat wire format used by the Peer SDK.
//!
//! The Peer SDK connects to `peerchat.<domain>:6667` and uses a small IRC-like
//! line protocol. For a pre-authenticated Peer connection the client first
//! asks for the title's stream cipher, then sends `LOGINPREAUTH`, then supplies
//! `USER`/`NICK` before the server sends numeric `001`.
//!
//! Evidence: `Chat/chatMain.c`, `chatSocket.c`, `chatHandlers.c`,
//! `Chat/chatCrypt.c` and `Peer/peerOperations.c` at the pinned OpenMOHAA SDK
//! commit. Only the messages this server currently needs are modeled.

use std::fmt;

pub const PORT: u16 = 6667;
pub const MAX_LINE_BYTES: usize = 4096;
pub const MAX_PARAMS: usize = 32;
pub const MAX_AUTH_TOKEN_BYTES: usize = 255;
pub const MAX_PARTNER_CHALLENGE_BYTES: usize = 255;
pub const MAX_NICK_BYTES: usize = 30;
pub const MAX_USER_BYTES: usize = 128;
pub const MAX_REAL_NAME_BYTES: usize = 128;
pub const MAX_CDKEY_BYTES: usize = 255;
pub const MAX_GAME_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    EmptyLine,
    LineTooLong,
    InvalidCharacter,
    MissingCommand,
    TooManyParams,
    Syntax(&'static str),
    FieldTooLong(&'static str),
    EmptySecret,
}

impl fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLine => formatter.write_str("empty PeerChat line"),
            Self::LineTooLong => formatter.write_str("PeerChat line exceeds the limit"),
            Self::InvalidCharacter => {
                formatter.write_str("PeerChat line contains a non-printable byte")
            }
            Self::MissingCommand => formatter.write_str("PeerChat line has no command"),
            Self::TooManyParams => formatter.write_str("PeerChat line has too many parameters"),
            Self::Syntax(what) => write!(formatter, "invalid PeerChat {what}"),
            Self::FieldTooLong(field) => write!(formatter, "PeerChat {field} is too long"),
            Self::EmptySecret => formatter.write_str("PeerChat title secret is empty"),
        }
    }
}

/// One parsed IRC-like line. `params` keeps the client's order; a trailing
/// `:` parameter is returned as a single value without its colon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub prefix: Option<&'a str>,
    pub command: &'a str,
    pub params: Vec<&'a str>,
}

pub fn parse_line(line: &str) -> Result<Message<'_>, PeerError> {
    let line = line.strip_suffix("\r\n").unwrap_or(line);
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err(PeerError::EmptyLine);
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(PeerError::LineTooLong);
    }
    if !line
        .bytes()
        .all(|byte| byte == 1 || (0x20..=0x7e).contains(&byte))
    {
        return Err(PeerError::InvalidCharacter);
    }

    let mut rest = line;
    let prefix = if let Some(after) = rest.strip_prefix(':') {
        let end = after.find(' ').ok_or(PeerError::MissingCommand)?;
        let prefix = &after[..end];
        if prefix.contains('\x01') {
            return Err(PeerError::InvalidCharacter);
        }
        rest = trim_spaces(&after[end..]);
        if prefix.is_empty() {
            return Err(PeerError::MissingCommand);
        }
        Some(prefix)
    } else {
        None
    };

    if rest.is_empty() {
        return Err(PeerError::MissingCommand);
    }
    let command_end = rest.find(' ').unwrap_or(rest.len());
    let command = &rest[..command_end];
    if command.contains('\x01') {
        return Err(PeerError::InvalidCharacter);
    }
    rest = trim_spaces(&rest[command_end..]);

    let mut params = Vec::new();
    while !rest.is_empty() {
        if params.len() == MAX_PARAMS {
            return Err(PeerError::TooManyParams);
        }
        if let Some(trailing) = rest.strip_prefix(':') {
            // SDK ACTION/CTCP envelopes use SOH only inside message bodies.
            if trailing.contains('\x01')
                && (params.len() != 1 || !matches!(command, "PRIVMSG" | "NOTICE" | "UTM" | "ATM"))
            {
                return Err(PeerError::InvalidCharacter);
            }
            params.push(trailing);
            break;
        }
        let end = rest.find(' ').unwrap_or(rest.len());
        if rest[..end].contains('\x01') {
            return Err(PeerError::InvalidCharacter);
        }
        params.push(&rest[..end]);
        rest = trim_spaces(&rest[end..]);
    }

    Ok(Message {
        prefix,
        command,
        params,
    })
}

fn trim_spaces(text: &str) -> &str {
    text.trim_start_matches(' ')
}

/// The client commands modeled by M1. Anything else is preserved by name so
/// the listener can log it and keep the connection open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCommand<'a> {
    Crypt {
        version: &'a str,
        game_name: &'a str,
    },
    LoginPreAuth {
        auth_token: &'a str,
        partner_challenge: &'a str,
    },
    UserIp,
    Nick {
        nick: &'a str,
    },
    User {
        user: &'a str,
        real_name: Option<&'a str>,
    },
    CdKey {
        cdkey: &'a str,
    },
    Ping,
    Quit,
    Other(&'a str),
}

impl<'a> ClientCommand<'a> {
    pub fn parse(line: &'a str) -> Result<Self, PeerError> {
        let message = parse_line(line)?;
        let params = &message.params;

        match message.command {
            "CRYPT" => {
                if params.len() != 3 {
                    return Err(PeerError::Syntax("CRYPT"));
                }
                if !params[0].eq_ignore_ascii_case("des") {
                    return Err(PeerError::Syntax("CRYPT cipher"));
                }
                if params[1].is_empty() || !params[1].bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(PeerError::Syntax("CRYPT version"));
                }
                check_len("game name", params[2], MAX_GAME_NAME_BYTES, true)?;
                Ok(Self::Crypt {
                    version: params[1],
                    game_name: params[2],
                })
            }
            "LOGINPREAUTH" => {
                if params.len() != 2 {
                    return Err(PeerError::Syntax("LOGINPREAUTH"));
                }
                check_len("auth token", params[0], MAX_AUTH_TOKEN_BYTES, false)?;
                check_len(
                    "partner challenge",
                    params[1],
                    MAX_PARTNER_CHALLENGE_BYTES,
                    false,
                )?;
                Ok(Self::LoginPreAuth {
                    auth_token: params[0],
                    partner_challenge: params[1],
                })
            }
            "USRIP" => Ok(Self::UserIp),
            "NICK" => {
                if params.len() != 1 {
                    return Err(PeerError::Syntax("NICK"));
                }
                check_len("nick", params[0], MAX_NICK_BYTES, true)?;
                Ok(Self::Nick { nick: params[0] })
            }
            "USER" => {
                if params.len() < 4 {
                    return Err(PeerError::Syntax("USER"));
                }
                check_len("user", params[0], MAX_USER_BYTES, false)?;
                check_len("real name", params[3], MAX_REAL_NAME_BYTES, true)?;
                Ok(Self::User {
                    user: params[0],
                    real_name: Some(params[3]),
                })
            }
            "CDKEY" => {
                if params.len() != 1 {
                    return Err(PeerError::Syntax("CDKEY"));
                }
                check_len("CD key", params[0], MAX_CDKEY_BYTES, false)?;
                Ok(Self::CdKey { cdkey: params[0] })
            }
            "PING" => Ok(Self::Ping),
            "QUIT" => Ok(Self::Quit),
            other => Ok(Self::Other(other)),
        }
    }
}

fn check_len(
    field: &'static str,
    value: &str,
    max: usize,
    nonempty: bool,
) -> Result<(), PeerError> {
    if value.len() > max || (nonempty && value.is_empty()) {
        return Err(PeerError::FieldTooLong(field));
    }
    Ok(())
}

/// `:s 705 <nick> <client-out-key> <client-in-key>`. This line is the last
/// plaintext server line; everything after it is encrypted in both directions.
pub fn secure_key_message(nick: &str, out_key: &str, in_key: &str) -> String {
    format!(":s 705 {nick} {out_key} {in_key}\r\n")
}

/// `:s 707 <nick> <userid> <profileid>`; the client replies with `USRIP`.
pub fn login_message(nick: &str, user_id: u32, profile_id: u32) -> String {
    format!(":s 707 {nick} {user_id} {profile_id}\r\n")
}

/// `:s 302 <nick> :<user>@<ip>`; the SDK only consumes the address after `@`.
pub fn user_ip_message(nick: &str, user: &str, ip: &str) -> String {
    format!(":s 302 {nick} :{user}@{ip}\r\n")
}

/// `:s 001 <nick> :<text>`; this completes the chat connect operation.
pub fn welcome_message(nick: &str, text: &str) -> String {
    format!(":s 001 {nick} :{text}\r\n")
}

/// `:s 706 <nick> <result> :<text>`; result 0 is success.
pub fn cdkey_message(nick: &str, result: i32, text: &str) -> String {
    format!(":s 706 {nick} {result} :{text}\r\n")
}

/// `:s 708 <nick> :<text>`; login failure numeric.
pub fn login_failed_message(nick: &str, text: &str) -> String {
    format!(":s 708 {nick} :{text}\r\n")
}

/// The GameSpy stream cipher from `Chat/chatCrypt.c`: an RC4 variant whose
/// initial state is filled in reverse order. The state persists across writes,
/// so a connection must keep one cipher per direction.
#[derive(Debug, Clone)]
pub struct ChatCipher {
    state: [u8; 256],
    x: u8,
    y: u8,
}

impl ChatCipher {
    pub fn new(key: &[u8]) -> Result<Self, PeerError> {
        if key.is_empty() {
            return Err(PeerError::EmptySecret);
        }
        let mut state = [0u8; 256];
        for counter in 0..256 {
            state[255 - counter] = counter as u8;
        }
        let mut index1 = 0usize;
        let mut index2 = 0u8;
        for counter in 0..256 {
            index2 = key[index1]
                .wrapping_add(state[counter])
                .wrapping_add(index2);
            state.swap(counter, index2 as usize);
            index1 = (index1 + 1) % key.len();
        }
        Ok(Self { state, x: 0, y: 0 })
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.x = self.x.wrapping_add(1);
            self.y = self.state[self.x as usize].wrapping_add(self.y);
            self.state.swap(self.x as usize, self.y as usize);
            let index = self.state[self.x as usize].wrapping_add(self.state[self.y as usize]);
            *byte ^= self.state[index as usize];
        }
    }
}

/// The client XORs the server's random key string with the title secret and
/// uses exactly `strlen(random)` bytes as the cipher key. The length is taken
/// before the XOR, so a zero byte stays in the key: `chatHandlers.c` calls
/// `gs_xcode_buf` and then `gs_prepare_key` with the saved length, and
/// `gs_prepare_key` copies `key_data_len` bytes.
pub fn key_material(random: &str, secret: &str) -> Result<Vec<u8>, PeerError> {
    if secret.is_empty() {
        return Err(PeerError::EmptySecret);
    }
    Ok(random
        .bytes()
        .enumerate()
        .map(|(index, byte)| byte ^ secret.as_bytes()[index % secret.len()])
        .collect())
}

pub fn derive_cipher(random: &str, secret: &str) -> Result<ChatCipher, PeerError> {
    ChatCipher::new(&key_material(random, secret)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_crypt_and_preauth() {
        assert_eq!(
            ClientCommand::parse("CRYPT des 1 mkvsdcu\r\n").unwrap(),
            ClientCommand::Crypt {
                version: "1",
                game_name: "mkvsdcu"
            }
        );
        assert_eq!(
            ClientCommand::parse("LOGINPREAUTH token-1 challenge-1\r\n").unwrap(),
            ClientCommand::LoginPreAuth {
                auth_token: "token-1",
                partner_challenge: "challenge-1"
            }
        );
    }

    #[test]
    fn parses_user_with_trailing_real_name() {
        let command =
            ClientCommand::parse("USER abc127 127.0.0.1 peerchat.example :MKVSDCU\r\n").unwrap();
        assert_eq!(
            command,
            ClientCommand::User {
                user: "abc127",
                real_name: Some("MKVSDCU")
            }
        );
    }

    #[test]
    fn rejects_malformed_commands() {
        assert_eq!(
            ClientCommand::parse("CRYPT plain 1 x").unwrap_err(),
            PeerError::Syntax("CRYPT cipher")
        );
        assert_eq!(
            ClientCommand::parse("LOGINPREAUTH only-one").unwrap_err(),
            PeerError::Syntax("LOGINPREAUTH")
        );
        assert_eq!(
            ClientCommand::parse("NICK").unwrap_err(),
            PeerError::Syntax("NICK")
        );
        assert!(matches!(
            ClientCommand::parse("USER a b c").unwrap_err(),
            PeerError::Syntax("USER")
        ));
    }

    #[test]
    fn rejects_non_printable_and_oversized_lines() {
        assert_eq!(
            ClientCommand::parse("PING\0").unwrap_err(),
            PeerError::InvalidCharacter
        );
        let long = format!("NICK {}", "a".repeat(MAX_LINE_BYTES));
        assert_eq!(
            ClientCommand::parse(&long).unwrap_err(),
            PeerError::LineTooLong
        );
    }

    #[test]
    fn builds_the_server_lines() {
        assert_eq!(secure_key_message("*", "OUT", "IN"), ":s 705 * OUT IN\r\n");
        assert_eq!(login_message("player7", 7, 7), ":s 707 player7 7 7\r\n");
        assert_eq!(
            user_ip_message("*", "*", "192.0.2.10"),
            ":s 302 * :*@192.0.2.10\r\n"
        );
        assert_eq!(
            welcome_message("player7", "Welcome"),
            ":s 001 player7 :Welcome\r\n"
        );
        assert_eq!(
            cdkey_message("player7", 0, "Accepted"),
            ":s 706 player7 0 :Accepted\r\n"
        );
        assert_eq!(
            login_failed_message("*", "Login failed"),
            ":s 708 * :Login failed\r\n"
        );
    }

    #[test]
    fn cipher_round_trips_and_is_streaming() {
        let mut encipher = derive_cipher("abcdefghijklmnopqrstuvwx", "0123456789").unwrap();
        let mut decipher = derive_cipher("abcdefghijklmnopqrstuvwx", "0123456789").unwrap();
        let plain = b"LOGINPREAUTH token challenge\r\nNICK *\r\n";
        let mut wire = plain.to_vec();
        encipher.apply(&mut wire);
        assert_ne!(&wire[..], &plain[..]);
        decipher.apply(&mut wire);
        assert_eq!(&wire[..], &plain[..]);
    }

    #[test]
    fn cipher_matches_a_cross_language_vector() {
        // Generated by an independent Python transliteration of chatCrypt.c.
        // The plaintext is the exact input that expected value was produced
        // from, so it is evidence and must not be reworded.
        let mut cipher = derive_cipher("abcdefghijklmnopqrstuvwx", "0123456789").unwrap();
        let mut data = b"CRYPT des 1 mkvsdcps3".to_vec();
        cipher.apply(&mut data);
        assert_eq!(
            data,
            vec![
                0xf9, 0x1d, 0x7f, 0xf9, 0x4d, 0xcd, 0xf0, 0xa5, 0xdd, 0xbb, 0xde, 0xc0, 0x62, 0x97,
                0x6f, 0x04, 0xda, 0x1f, 0xea, 0xf8, 0x5a
            ]
        );
    }

    #[test]
    fn zero_xor_byte_stays_in_the_key() {
        assert_eq!(key_material("zbc", "axc").unwrap(), vec![0x1b, 0x1a, 0x00]);
        assert_eq!(key_material("abc", "axc").unwrap(), vec![0x00, 0x1a, 0x00]);
    }

    #[test]
    fn cipher_matches_a_cross_language_vector_with_zero_bytes() {
        // Generated by an independent Python transliteration of chatCrypt.c.
        // The plaintext is the exact input that expected value was produced
        // from, so it is evidence and must not be reworded.
        // The key contains zero bytes; the SDK keeps them because the length
        // was measured before gs_xcode_buf.
        let mut cipher = derive_cipher("abc", "axc").unwrap();
        let mut data = b"CRYPT des 1 mkvsdcps3".to_vec();
        cipher.apply(&mut data);
        assert_eq!(
            data,
            vec![
                0x49, 0x1a, 0x15, 0x11, 0xaf, 0xa6, 0xc8, 0xf1, 0x78, 0x28, 0xdd, 0xa3, 0x98, 0x58,
                0x6b, 0x77, 0xb9, 0x90, 0xb7, 0xaa, 0x33
            ]
        );
    }

    #[test]
    fn rejects_empty_secret() {
        assert_eq!(
            derive_cipher("abcd", "").unwrap_err(),
            PeerError::EmptySecret
        );
    }

    #[test]
    fn ctcp_envelopes_are_only_valid_in_trailing_message_bodies() {
        for command in ["PRIVMSG", "NOTICE", "UTM", "ATM"] {
            let line = format!("{command} #synthetic :\x01ACTION waves\x01\r\n");
            assert_eq!(parse_line(&line).unwrap().params[1], "\x01ACTION waves\x01");
        }
        for line in [
            "PRIVMSG #x :bad\0body",
            "PRIVMSG #x :bad\rbody",
            "PRIVMSG #x :bad\nbody",
            "PRIVMSG #x :bad\x02body",
            "PRIVMSG #\x01x :body",
            "PRIVMSG #x \x01body",
            "TOPIC #x :\x01bad",
            ":bad\x01!prefix PRIVMSG #x :body",
            "PRIV\x01MSG #x :body",
        ] {
            assert_eq!(parse_line(line).unwrap_err(), PeerError::InvalidCharacter);
        }
    }
}
