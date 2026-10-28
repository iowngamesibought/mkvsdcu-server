//! GameSpy availability probe.
//!
//! Client behavior is taken from `gsAvailable.c` in the fixed SDK snapshot:
//! one byte `0x09`, four reserved bytes (the reference leaves them
//! uninitialized), then the ASCII game name followed by NUL. The server
//! replies with `FE FD 09` plus a big-endian 32-bit service-disable bitfield:
//! bit 0 marks the service unavailable, bit 1 temporarily unavailable.
//!
//! The SDK treats a missing answer as available after its retry window, but
//! answering deterministically keeps the client state machine out of its
//! timeout path.

pub const PROBE_TYPE: u8 = 0x09;
pub const PROBE_PORT: u16 = 27900;
pub const RESPONSE_MAGIC: [u8; 3] = [0xFE, 0xFD, 0x09];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityError {
    TooShort,
    WrongType,
    MissingTerminator,
    InvalidName,
}

/// Parse the probe and return the NUL-terminated game name.
pub fn parse_probe(packet: &[u8]) -> Result<&str, AvailabilityError> {
    if packet.len() < 6 {
        return Err(AvailabilityError::TooShort);
    }
    if packet[0] != PROBE_TYPE {
        return Err(AvailabilityError::WrongType);
    }
    let name = &packet[5..];
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(AvailabilityError::MissingTerminator)?;
    std::str::from_utf8(&name[..end]).map_err(|_| AvailabilityError::InvalidName)
}

/// Build the seven-byte availability response.
pub fn response(disabled_services: u32) -> [u8; 7] {
    let mut packet = [0u8; 7];
    packet[..3].copy_from_slice(&RESPONSE_MAGIC);
    packet[3..].copy_from_slice(&disabled_services.to_be_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(name: &str) -> Vec<u8> {
        let mut packet = vec![0u8; name.len() + 6];
        packet[0] = PROBE_TYPE;
        packet[1..5].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        packet[5..5 + name.len()].copy_from_slice(name.as_bytes());
        packet
    }

    #[test]
    fn parses_sdk_shaped_probe_with_reserved_bytes() {
        assert_eq!(parse_probe(&probe("mkvsdcu")), Ok("mkvsdcu"));
    }

    #[test]
    fn rejects_wrong_type_and_short_packets() {
        let mut packet = probe("mkvsdcu");
        packet[0] = 0x08;
        assert_eq!(parse_probe(&packet), Err(AvailabilityError::WrongType));
        assert_eq!(parse_probe(&[0x09, 0, 0]), Err(AvailabilityError::TooShort));
    }

    #[test]
    fn rejects_missing_terminator() {
        let mut packet = probe("abc");
        let last = packet.len() - 1;
        packet[last] = b'c';
        assert_eq!(
            parse_probe(&packet),
            Err(AvailabilityError::MissingTerminator)
        );
    }

    #[test]
    fn available_response_is_big_endian_zero() {
        assert_eq!(response(0), [0xFE, 0xFD, 0x09, 0, 0, 0, 0]);
    }

    #[test]
    fn unavailable_bits_are_big_endian() {
        assert_eq!(response(3), [0xFE, 0xFD, 0x09, 0, 0, 0, 3]);
    }
}
