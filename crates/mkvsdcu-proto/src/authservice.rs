//! AuthService certificate-login SOAP codec.
//!
//! The client request fields are built in `AuthService.c:657-719`: `version`,
//! `gameid`, `partnercode`, `namespaceid`, and a ticket wrapper whose
//! `Value` child carries the base64 account ticket. The client parses the reply in
//! `AuthService.c:574-651`: it looks for the method's result element,
//! requires `responseCode == 0`, and reads `authToken` and
//! `partnerChallenge` as strings shorter than 256 bytes. It does not
//! verify a response signature on this path.
//!
//! The method name, the SOAP action, the request and result element names
//! and the ticket element name are the client's own and appear here only
//! as the literals it sends and expects. They are not this project's
//! naming and must not be renamed: the server matches on them, so
//! changing a character stops login working.
//!
//! The server response below is intentionally prefix-free: the SDK's small XML
//! reader matches local element names, and no namespace-prefix handling is
//! relied upon in this codec.

pub const CERT_LOGIN_METHOD: &str = "LoginPs3Cert";
pub const SOAP_ACTION_CERT_LOGIN: &str = "http://gamespy.net/AuthService/LoginPs3Cert";
pub const AUTH_TOKEN_MAX: usize = 255;
pub const PARTNER_CHALLENGE_MAX: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertLoginRequest {
    pub version: Option<i64>,
    pub game_id: Option<i64>,
    pub partner_code: Option<i64>,
    pub namespace_id: Option<i64>,
    pub account_ticket_base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertLoginResponse {
    pub auth_token: String,
    pub partner_challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    NotCertLogin,
    InvalidInteger(&'static str),
}

/// Parse the subset of the SOAP request that the service needs. The account ticket
/// is retained as base64 text; the private service does not validate it.
pub fn parse_cert_login(xml: &str) -> Result<CertLoginRequest, AuthError> {
    if find_element(xml, CERT_LOGIN_METHOD).is_none() {
        return Err(AuthError::NotCertLogin);
    }

    Ok(CertLoginRequest {
        version: int_element(xml, "version")?,
        game_id: int_element(xml, "gameid")?,
        partner_code: int_element(xml, "partnercode")?,
        namespace_id: int_element(xml, "namespaceid")?,
        account_ticket_base64: find_element(xml, "Value").map(|value| value.trim().to_owned()),
    })
}

/// Build the minimal SOAP success reply accepted by the SDK parser.
pub fn build_cert_login_response(response: &CertLoginResponse) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n\
         <Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\">\
         <Body>\
         <LoginPs3CertResult xmlns=\"http://gamespy.net/AuthService/\">\
         <responseCode>0</responseCode>\
         <authToken>{}</authToken>\
         <partnerChallenge>{}</partnerChallenge>\
         </LoginPs3CertResult>\
         </Body>\
         </Envelope>",
        escape_xml(&response.auth_token),
        escape_xml(&response.partner_challenge)
    )
}

fn int_element(xml: &str, name: &'static str) -> Result<Option<i64>, AuthError> {
    match find_element(xml, name) {
        Some(value) => value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| AuthError::InvalidInteger(name)),
        None => Ok(None),
    }
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Find the first element with the requested local name and return its inner
/// text. Prefixes are ignored (`ns1:gameid` matches `gameid`). This handles the
/// simple, non-nested field shapes used by AuthService only.
fn find_element<'a>(xml: &'a str, local: &str) -> Option<&'a str> {
    let mut cursor = 0;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        let end = start + xml[start..].find('>')?;
        let tag = &xml[start + 1..end];
        if tag.starts_with('/') || tag.starts_with('?') || tag.starts_with('!') {
            cursor = end + 1;
            continue;
        }
        if tag.ends_with('/') {
            let name = tag.trim_end_matches('/').trim();
            if local_name(name) == local {
                return Some("");
            }
            cursor = end + 1;
            continue;
        }
        let name_end = tag
            .find(|character: char| character.is_whitespace())
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        if local_name(name) == local {
            let inner_start = end + 1;
            let close = find_close(xml, inner_start, local)?;
            return Some(&xml[inner_start..close]);
        }
        cursor = end + 1;
    }
    None
}

fn find_close(xml: &str, from: usize, local: &str) -> Option<usize> {
    let mut cursor = from;
    while let Some(relative) = xml[cursor..].find("</") {
        let start = cursor + relative;
        let end = start + xml[start..].find('>')?;
        let name = xml[start + 2..end].trim();
        if local_name(name) == local {
            return Some(start);
        }
        cursor = end + 1;
    }
    None
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
<ns1:LoginPs3Cert xmlns:ns1="http://gamespy.net/AuthService/">
<ns1:version>1</ns1:version>
<ns1:gameid>2248</ns1:gameid>
<ns1:partnercode>33</ns1:partnercode>
<ns1:namespaceid>40</ns1:namespaceid>
<ns1:npticket><ns1:Value>AAECAwQ=</ns1:Value></ns1:npticket>
</ns1:LoginPs3Cert>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

    #[test]
    fn parses_prefixed_sdk_request() {
        let parsed = parse_cert_login(REQUEST).unwrap();
        assert_eq!(parsed.version, Some(1));
        assert_eq!(parsed.game_id, Some(2248));
        assert_eq!(parsed.partner_code, Some(33));
        assert_eq!(parsed.namespace_id, Some(40));
        assert_eq!(parsed.account_ticket_base64.as_deref(), Some("AAECAwQ="));
    }

    #[test]
    fn rejects_other_authservice_methods() {
        assert_eq!(
            parse_cert_login("<LoginRemoteAuth><version>1</version></LoginRemoteAuth>"),
            Err(AuthError::NotCertLogin)
        );
    }

    #[test]
    fn rejects_malformed_integer() {
        let request = "<LoginPs3Cert><gameid>abc</gameid></LoginPs3Cert>";
        assert_eq!(
            parse_cert_login(request),
            Err(AuthError::InvalidInteger("gameid"))
        );
    }

    #[test]
    fn builds_prefix_free_success_response() {
        let xml = build_cert_login_response(&CertLoginResponse {
            auth_token: "aabb".into(),
            partner_challenge: "ccdd".into(),
        });
        assert!(xml.contains("<LoginPs3CertResult"));
        assert!(xml.contains("<responseCode>0</responseCode>"));
        assert!(xml.contains("<authToken>aabb</authToken>"));
        assert!(xml.contains("<partnerChallenge>ccdd</partnerChallenge>"));
    }

    #[test]
    fn escapes_xml_metacharacters() {
        let xml = build_cert_login_response(&CertLoginResponse {
            auth_token: "a&b<c>".into(),
            partner_challenge: "\"x\"".into(),
        });
        assert!(xml.contains("a&amp;b&lt;c&gt;"));
        assert!(xml.contains("&quot;x&quot;"));
    }
}
