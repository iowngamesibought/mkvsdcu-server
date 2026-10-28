//! Bounded HTTP/1 request parsing for the AuthService listener.
//!
//! The GameSpy GHTTP client sends a single POST with `Content-Length`; this
//! parser deliberately does not implement chunked transfer or keep-alive.
//! Anything outside that shape is rejected instead of guessed.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    Incomplete,
    Malformed,
    UnsupportedTransferEncoding,
    MissingContentLength,
    InvalidContentLength,
    BodyTooLarge,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

impl Request<'_> {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }
}

/// Parse one complete HTTP/1.x request. `data` may contain trailing bytes;
/// only the request indicated by `Content-Length` is consumed.
pub fn parse_request<'a>(data: &'a [u8], max_body: usize) -> Result<Request<'a>, HttpError> {
    let header_end = find_header_end(data).ok_or(HttpError::Incomplete)?;
    let head_bytes = &data[..header_end];
    let head = std::str::from_utf8(head_bytes).map_err(|_| HttpError::Malformed)?;

    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HttpError::Malformed)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpError::Malformed)?;
    let target = parts.next().ok_or(HttpError::Malformed)?;
    let version = parts.next().ok_or(HttpError::Malformed)?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(HttpError::Malformed);
    }

    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(HttpError::Malformed);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::UnsupportedTransferEncoding);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .parse::<usize>()
                .map_err(|_| HttpError::InvalidContentLength)?;
            if content_length.replace(length).is_some() {
                return Err(HttpError::Malformed);
            }
        }
        headers.push((name, value));
    }

    let length = content_length.ok_or(HttpError::MissingContentLength)?;
    if length > max_body {
        return Err(HttpError::BodyTooLarge);
    }
    let body_start = header_end + 4;
    let body_end = body_start
        .checked_add(length)
        .ok_or(HttpError::InvalidContentLength)?;
    if data.len() < body_end {
        return Err(HttpError::Incomplete);
    }

    Ok(Request {
        method,
        target,
        version,
        headers,
        body: &data[body_start..body_end],
    })
}

/// Serialize a fixed-length HTTP/1.1 response that closes the connection.
pub fn response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"POST /AuthService HTTP/1.1\r\nHost: mkvsdc.local\r\nContent-Length: 5\r\nSOAPAction: \"x\"\r\n\r\nhello";

    #[test]
    fn parses_complete_post() {
        let request = parse_request(SAMPLE, 1024).unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/AuthService");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(request.body, b"hello");
        assert_eq!(request.header("soapaction"), Some("\"x\""));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let request = parse_request(SAMPLE, 1024).unwrap();
        assert_eq!(request.header("CONTENT-LENGTH"), Some("5"));
        assert_eq!(request.header("missing"), None);
    }

    #[test]
    fn reports_incomplete_body() {
        assert_eq!(
            parse_request(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel", 1024),
            Err(HttpError::Incomplete)
        );
    }

    #[test]
    fn rejects_chunked_and_missing_length() {
        assert_eq!(
            parse_request(
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                1024
            ),
            Err(HttpError::UnsupportedTransferEncoding)
        );
        assert_eq!(
            parse_request(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n", 1024),
            Err(HttpError::MissingContentLength)
        );
    }

    #[test]
    fn rejects_oversized_body() {
        let request = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse_request(request, 4), Err(HttpError::BodyTooLarge));
    }

    #[test]
    fn response_declares_exact_length() {
        let response = response("200 OK", "text/xml", b"abc");
        let text = std::str::from_utf8(&response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 3\r\n"));
        assert!(text.ends_with("\r\n\r\nabc"));
    }
}
