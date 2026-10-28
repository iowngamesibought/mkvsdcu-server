//! Legacy transport restricted to the game listener.
//!
//! The shipped client offers SSL 3.0 with `TLS_RSA_WITH_RC4_128_MD5` only.
//! OpenSSL here is the verified 3.5.8 static build with SSL3 and the built-in
//! legacy provider. This module never changes global system TLS settings.

use openssl::pkey::{PKey, Private};
use openssl::provider::Provider;
use openssl::ssl::{SslAcceptor, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use openssl::x509::X509;

pub struct LegacyTls {
    pub acceptor: SslAcceptor,
    _providers: Vec<Provider>,
}

impl LegacyTls {
    pub fn new(certificate: &X509, key: &PKey<Private>) -> Result<Self, String> {
        let providers = vec![
            Provider::load(None, "default")
                .map_err(|error| format!("load default provider: {error}"))?,
            Provider::load(None, "legacy")
                .map_err(|error| format!("load legacy provider: {error}"))?,
        ];

        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .map_err(|error| format!("create SSL acceptor: {error}"))?;
        builder.clear_options(
            SslOptions::NO_SSLV3
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
                | SslOptions::NO_TLSV1_2
                | SslOptions::NO_TLSV1_3,
        );
        builder.set_security_level(0);
        builder
            .set_min_proto_version(Some(SslVersion::SSL3))
            .map_err(|error| format!("SSL3 unavailable: {error}"))?;
        builder
            .set_max_proto_version(Some(SslVersion::SSL3))
            .map_err(|error| format!("SSL3 unavailable: {error}"))?;
        builder
            .set_cipher_list("RC4-MD5:@SECLEVEL=0")
            .map_err(|error| format!("RC4-MD5 unavailable: {error}"))?;
        builder
            .set_certificate(certificate)
            .map_err(|error| format!("set certificate: {error}"))?;
        builder
            .set_private_key(key)
            .map_err(|error| format!("set private key: {error}"))?;
        builder
            .check_private_key()
            .map_err(|error| format!("certificate/key mismatch: {error}"))?;
        // GameSpy certificate trust is not validated by the client; the
        // application layer still has to authenticate the account ticket.
        builder.set_verify(SslVerifyMode::NONE);

        Ok(Self {
            acceptor: builder.build(),
            _providers: providers,
        })
    }
}
