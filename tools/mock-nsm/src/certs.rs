//! Deterministic X.509 certificate generation for mock NSM attestation.
//!
//! Produces a proper certificate chain (root CA -> leaf) that can pass
//! Sui's on-chain attestation verification when the localnet validator
//! is patched to trust our mock root CA.

use der::{asn1::GeneralizedTime, DateTime, Decode, Encode, EncodePem};
use p384::ecdsa::SigningKey;
use p384::pkcs8::DecodePrivateKey;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
};

/// Fixed P-384 PKCS#8 DER private key for the mock root CA.
/// Generated once via:
///   openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -outform DER
/// This is deterministic: same key every build so the root CA PEM is stable.
#[rustfmt::skip]
const ROOT_CA_KEY_PKCS8_DER: &[u8] = &[
    // PKCS#8 PrivateKeyInfo wrapping an EC private key on P-384
    // Generated via: openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 |
    //                openssl pkcs8 -topk8 -nocrypt -outform DER
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01, 0x01, 0x04, 0x30, 0x45,
    0x4c, 0xec, 0x5e, 0xa4, 0xa1, 0xc9, 0x8f, 0x1f, 0x5e, 0x72, 0xac, 0x3d,
    0x02, 0xc5, 0xbf, 0x8f, 0x8d, 0x97, 0x9a, 0x48, 0x93, 0xb4, 0xe0, 0xcd,
    0x08, 0x6b, 0xf4, 0x91, 0x09, 0x4f, 0xa1, 0xb0, 0x77, 0x58, 0x6b, 0x46,
    0xdb, 0xd8, 0x40, 0x6e, 0xfa, 0x6d, 0xd2, 0x03, 0x61, 0xef, 0x1b, 0xa1,
    0x64, 0x03, 0x62, 0x00, 0x04, 0x78, 0x9c, 0xf5, 0xd9, 0x75, 0x64, 0x3c,
    0x8b, 0x6e, 0xb9, 0x59, 0x78, 0x8b, 0x36, 0x12, 0xa4, 0x38, 0x12, 0x10,
    0x85, 0xb0, 0xbb, 0x1f, 0x17, 0xa1, 0x07, 0x76, 0x71, 0xc4, 0xe0, 0x86,
    0x94, 0x56, 0x19, 0x35, 0xb4, 0x05, 0x3f, 0x1a, 0x62, 0xd8, 0x70, 0x1e,
    0x9f, 0xb6, 0x45, 0x54, 0x46, 0x73, 0xb6, 0xe0, 0x2a, 0x2a, 0x24, 0xa9,
    0x9a, 0xda, 0x2f, 0x35, 0xdc, 0x7f, 0x17, 0x43, 0x69, 0xfd, 0xd2, 0x6c,
    0x15, 0xf4, 0x5d, 0xd0, 0x04, 0x3c, 0x98, 0x13, 0x5d, 0x1b, 0xe0, 0x20,
    0x54, 0x56, 0xa1, 0x62, 0xbb, 0x89, 0xa0, 0xbe, 0xe6, 0xc1, 0xf6, 0x1d,
    0x99, 0xbe, 0xc6, 0x3e, 0x03,
];

/// Load the deterministic root CA signing key from the embedded PKCS#8 DER bytes.
pub fn root_ca_signing_key() -> SigningKey {
    SigningKey::from_pkcs8_der(ROOT_CA_KEY_PKCS8_DER)
        .expect("invalid embedded root CA PKCS#8 DER key")
}

/// Construct the fixed validity period: 2020-01-01 to 2099-01-01.
fn mock_validity() -> Validity {
    let not_before = Time::GeneralTime(GeneralizedTime::from_date_time(
        DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
    ));
    let not_after = Time::GeneralTime(GeneralizedTime::from_date_time(
        DateTime::new(2099, 1, 1, 0, 0, 0).unwrap(),
    ));
    Validity {
        not_before,
        not_after,
    }
}

/// Build a self-signed root CA certificate (DER-encoded).
///
/// Properties:
/// - Subject/Issuer: `CN=mock.nsm.local`
/// - BasicConstraints: critical, CA=true
/// - KeyUsage: critical, keyCertSign | cRLSign
/// - Validity: 2020-01-01 to 2099-01-01
/// - Signed with ECDSA P-384 / SHA-384
/// - Under 1024 bytes DER
pub fn build_root_ca_cert(signing_key: &SigningKey) -> Vec<u8> {
    let serial = SerialNumber::from(1u32);
    let validity = mock_validity();
    let subject: Name = "CN=mock.nsm.local".parse().expect("valid CN");

    let spki_owned =
        spki::SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key()).unwrap();

    let builder =
        CertificateBuilder::new(Profile::Root, serial, validity, subject, spki_owned, signing_key)
            .expect("CertificateBuilder::new for root CA");

    let cert = builder
        .build::<p384::ecdsa::DerSignature>()
        .expect("build root CA cert");

    let der_bytes = cert.to_der().expect("encode root CA cert to DER");
    assert!(
        der_bytes.len() <= 1024,
        "root CA cert exceeds 1024 bytes: {} bytes",
        der_bytes.len()
    );
    der_bytes
}

/// Build a leaf certificate signed by the root CA (DER-encoded).
///
/// Properties:
/// - Subject: `CN=mock.nsm.leaf`
/// - Issuer: `CN=mock.nsm.local` (matches root cert's subject)
/// - BasicConstraints: critical, CA=false
/// - KeyUsage: critical, digitalSignature | nonRepudiation
/// - Validity: 2020-01-01 to 2099-01-01
/// - Signed by root_key (ECDSA P-384 / SHA-384)
/// - Contains leaf_key as SubjectPublicKeyInfo
/// - Under 1024 bytes DER
pub fn build_leaf_cert(
    root_key: &SigningKey,
    _root_cert_der: &[u8],
    leaf_key: &p384::ecdsa::VerifyingKey,
) -> Vec<u8> {
    let serial = SerialNumber::from(2u32);
    let validity = mock_validity();
    let subject: Name = "CN=mock.nsm.leaf".parse().expect("valid CN");
    let issuer: Name = "CN=mock.nsm.local".parse().expect("valid CN");

    let spki_owned = spki::SubjectPublicKeyInfoOwned::from_key(*leaf_key).unwrap();

    let profile = Profile::Leaf {
        issuer,
        enable_key_agreement: false,
        enable_key_encipherment: false,
    };

    let builder =
        CertificateBuilder::new(profile, serial, validity, subject, spki_owned, root_key)
            .expect("CertificateBuilder::new for leaf cert");

    let cert = builder
        .build::<p384::ecdsa::DerSignature>()
        .expect("build leaf cert");

    let der_bytes = cert.to_der().expect("encode leaf cert to DER");
    assert!(
        der_bytes.len() <= 1024,
        "leaf cert exceeds 1024 bytes: {} bytes",
        der_bytes.len()
    );
    der_bytes
}

/// Return the root CA certificate in PEM format.
///
/// This is the certificate that must be installed as the trusted root
/// in a patched Sui localnet validator (replacing the AWS Nitro root).
pub fn root_ca_pem() -> String {
    let key = root_ca_signing_key();
    let der = build_root_ca_cert(&key);

    // Re-parse the DER to get a Certificate, then encode to PEM
    let cert = x509_cert::Certificate::from_der(&der).expect("re-parse root CA cert");
    cert.to_pem(der::pem::LineEnding::LF)
        .expect("encode root CA cert to PEM")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_root_ca_pem() {
        let pem = root_ca_pem();
        println!("{}", pem);
    }

    #[test]
    fn root_ca_cert_size() {
        let key = root_ca_signing_key();
        let der = build_root_ca_cert(&key);
        println!("Root CA cert DER size: {} bytes", der.len());
        assert!(der.len() <= 1024);
    }

    #[test]
    fn leaf_cert_size() {
        let root_key = root_ca_signing_key();
        let root_der = build_root_ca_cert(&root_key);

        // Generate a leaf key for testing
        let leaf_key = SigningKey::random(&mut rand::rngs::OsRng);
        let leaf_vk = leaf_key.verifying_key();

        let leaf_der = build_leaf_cert(&root_key, &root_der, leaf_vk);
        println!("Leaf cert DER size: {} bytes", leaf_der.len());
        assert!(leaf_der.len() <= 1024);
    }

    #[test]
    fn cert_chain_deterministic() {
        // Root CA cert should be identical across calls (deterministic key)
        let key = root_ca_signing_key();
        let der1 = build_root_ca_cert(&key);
        let der2 = build_root_ca_cert(&key);
        assert_eq!(der1, der2, "root CA cert should be deterministic");
    }
}
