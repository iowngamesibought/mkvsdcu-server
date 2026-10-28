//! Loopback proof of the M1 transport path: SSL3 + RC4-MD5 + HTTP + SOAP.
//! This does not involve a real console and does not prove client acceptance.
//!
//! The SOAP element names in the request below are the ones the client
//! sends. They are the client's own naming and must not be renamed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use openssl::provider::Provider;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};

use mkvsdcu_server::auth_listener;
use mkvsdcu_server::cert;
use mkvsdcu_server::config::Config;
use mkvsdcu_server::session::AuthSessions;
use mkvsdcu_server::tls::LegacyTls;

#[test]
fn ssl3_authservice_returns_login_response() {
    let _providers = [
        Provider::load(None, "default").expect("default provider"),
        Provider::load(None, "legacy").expect("legacy provider"),
    ];

    let generated = cert::generate_self_signed().expect("generate certificate");
    let tls = Arc::new(LegacyTls::new(&generated.certificate, &generated.key).expect("TLS setup"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let address = listener.local_addr().expect("local address");
    let config = Config::parse(&format!(
        "[availability]\nbind = \"127.0.0.1:27900\"\n\
         [auth]\nbind = \"{}\"\nmax_request_bytes = 65536\n\
         [gp]\nbind = \"127.0.0.1:29900\"\n\
         [peerchat]\nbind = \"127.0.0.1:16667\"\ntitle_secret = \"0123456789\"\n",
        address
    ))
    .expect("test config");
    let sessions = Arc::new(AuthSessions::new());
    let server_sessions = Arc::clone(&sessions);

    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept");
        auth_listener::handle_connection(socket, &tls, &config, &server_sessions)
            .expect("serve one request");
    });

    let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("connector");
    builder.clear_options(SslOptions::NO_SSLV3);
    builder.set_security_level(0);
    builder
        .set_min_proto_version(Some(SslVersion::SSL3))
        .expect("client SSL3 minimum");
    builder
        .set_max_proto_version(Some(SslVersion::SSL3))
        .expect("client SSL3 maximum");
    builder
        .set_cipher_list("RC4-MD5:@SECLEVEL=0")
        .expect("client RC4-MD5");
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5)).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    let mut stream = connector
        .connect("mkvsdc.local", socket)
        .expect("SSL3 handshake");
    assert_eq!(stream.ssl().version_str(), "SSLv3");
    assert_eq!(
        stream.ssl().current_cipher().expect("cipher").name(),
        "RC4-MD5"
    );

    let body = sample_request();
    let request = format!(
        "POST /AuthService HTTP/1.1\r\n\
         Host: mkvsdc.local\r\n\
         Content-Type: text/xml; charset=utf-8\r\n\
         SOAPAction: \"{}\"\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        mkvsdcu_proto::authservice::SOAP_ACTION_CERT_LOGIN,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush request");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8(response).expect("UTF-8 response");
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.contains("<responseCode>0</responseCode>"), "{text}");
    assert!(text.contains("<authToken>"), "{text}");
    assert!(text.contains("<partnerChallenge>"), "{text}");

    let token = between(&text, "<authToken>", "</authToken>");
    let challenge = between(&text, "<partnerChallenge>", "</partnerChallenge>");
    let session = sessions
        .begin_gp_login(token)
        .expect("token stored for GPCM");
    assert_eq!(session.partner_challenge, challenge);

    server.join().expect("server thread");
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start = text.find(start).expect("start marker") + start.len();
    let end = text[start..].find(end).expect("end marker") + start;
    &text[start..end]
}

fn sample_request() -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://gamespy.net/AuthService/"><SOAP-ENV:Body><ns1:LoginPs3Cert><ns1:version>1</ns1:version><ns1:gameid>2248</ns1:gameid><ns1:partnercode>33</ns1:partnercode><ns1:namespaceid>40</ns1:namespaceid><ns1:npticket><ns1:Value>{}</ns1:Value></ns1:npticket></ns1:LoginPs3Cert></SOAP-ENV:Body></SOAP-ENV:Envelope>"#,
        "AAECAwQFBgcICQ=="
    )
}
