//! Ephemeral self-signed certificate for the gsSSL listener.
//!
//! The SDK's certificate parser is the reason this is deliberately minimal:
//! X.509 v3 (no extensions), 1024-bit RSA, SHA-1 signature. The client never
//! validates the chain (see the gsSSL handshake analysis), so the private key
//! is generated in memory for each process and never written to disk.

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};

pub struct GeneratedCertificate {
    pub certificate: X509,
    pub key: PKey<Private>,
}

pub fn generate_self_signed() -> Result<GeneratedCertificate, String> {
    let rsa = Rsa::generate(1024).map_err(|error| format!("generate RSA key: {error}"))?;
    let key = PKey::from_rsa(rsa).map_err(|error| format!("wrap RSA key: {error}"))?;

    let mut name_builder =
        X509NameBuilder::new().map_err(|error| format!("create certificate name: {error}"))?;
    name_builder
        .append_entry_by_text("CN", "mkvsdc.local")
        .map_err(|error| format!("set certificate CN: {error}"))?;
    let name = name_builder.build();

    let mut builder = X509::builder().map_err(|error| format!("create certificate: {error}"))?;
    builder
        .set_version(2)
        .map_err(|error| format!("set X.509 v3: {error}"))?;
    let serial_number = BigNum::from_u32(1).map_err(|error| format!("create serial: {error}"))?;
    let serial =
        Asn1Integer::from_bn(&serial_number).map_err(|error| format!("encode serial: {error}"))?;
    builder
        .set_serial_number(&serial)
        .map_err(|error| format!("set serial: {error}"))?;
    builder
        .set_subject_name(&name)
        .map_err(|error| format!("set subject: {error}"))?;
    builder
        .set_issuer_name(&name)
        .map_err(|error| format!("set issuer: {error}"))?;
    builder
        .set_pubkey(&key)
        .map_err(|error| format!("set public key: {error}"))?;
    let not_before = Asn1Time::days_from_now(0).map_err(|error| error.to_string())?;
    builder
        .set_not_before(&not_before)
        .map_err(|error| format!("set notBefore: {error}"))?;
    let not_after = Asn1Time::days_from_now(3650).map_err(|error| error.to_string())?;
    builder
        .set_not_after(&not_after)
        .map_err(|error| format!("set notAfter: {error}"))?;
    builder
        .sign(&key, MessageDigest::sha1())
        .map_err(|error| format!("sign certificate: {error}"))?;

    Ok(GeneratedCertificate {
        certificate: builder.build(),
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_has_explicit_version_required_by_sdk() {
        let generated = generate_self_signed().unwrap();
        let der = generated.certificate.to_der().unwrap();
        let mut pos = 0;
        // Enter Certificate, then TBSCertificate, using their DER lengths.
        for _ in 0..2 {
            assert_eq!(der[pos], 0x30);
            pos += 1;
            let length = der[pos];
            pos += 1;
            if length & 0x80 != 0 {
                pos += usize::from(length & 0x7f);
            }
        }
        // The SDK rejects a serial number here: it requires EXPLICIT Version.
        assert_eq!(&der[pos..pos + 5], &[0xa0, 3, 2, 1, 2]);
        assert_eq!(generated.certificate.public_key().unwrap().bits(), 1024);
        assert!(generated.certificate.verify(&generated.key).unwrap());
    }
}
