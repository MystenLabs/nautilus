use anyhow::{Context, Result};
use der::Encode;
use p384::ecdsa::SigningKey;
use rand::rngs::OsRng;
use spki::EncodePublicKey;
use spki::SubjectPublicKeyInfoOwned;
use std::time::Duration;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

/// A test CA chain that mimics the AWS Nitro Enclave PKI hierarchy:
///   Root CA  ->  Intermediate  ->  Enclave cert
/// All keys are P-384 ECDSA, matching the real Nitro attestation structure.
pub struct TestCa {
    pub root_cert_der: Vec<u8>,
    pub intermediate_cert_der: Vec<u8>,
    pub enclave_cert_der: Vec<u8>,
    pub enclave_signing_key: SigningKey,
}

fn spki_owned(sk: &SigningKey) -> Result<SubjectPublicKeyInfoOwned> {
    let vk = sk.verifying_key();
    let doc = vk
        .to_public_key_der()
        .context("encode verifying key to DER")?;
    let spki = SubjectPublicKeyInfoOwned::try_from(doc.as_bytes())
        .context("parse SubjectPublicKeyInfoOwned")?;
    Ok(spki)
}

impl TestCa {
    pub fn new() -> Result<Self> {
        // ── Root CA (self-signed) ──────────────────────────────────────
        let root_sk = SigningKey::random(&mut OsRng);
        let root_spki = spki_owned(&root_sk)?;
        let root_serial = SerialNumber::from(1u32);
        let root_validity = Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60 * 30))
            .context("build root validity")?;
        let root_subject: Name =
            "CN=aws.nitro-enclaves".parse().context("parse root subject")?;

        let root_cert = CertificateBuilder::new(
            Profile::Root,
            root_serial,
            root_validity,
            root_subject,
            root_spki,
            &root_sk,
        )
        .context("build root cert builder")?
        .build::<p384::ecdsa::DerSignature>()
        .context("sign root cert")?;

        let root_cert_der = root_cert.to_der().context("encode root cert DER")?;

        // ── Intermediate CA ────────────────────────────────────────────
        let inter_sk = SigningKey::random(&mut OsRng);
        let inter_spki = spki_owned(&inter_sk)?;
        let inter_serial = SerialNumber::from(2u32);
        let inter_validity = Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60 * 20))
            .context("build intermediate validity")?;
        let inter_subject: Name = "CN=mock.intermediate"
            .parse()
            .context("parse intermediate subject")?;

        let inter_cert = CertificateBuilder::new(
            Profile::SubCA {
                issuer: root_cert.tbs_certificate.subject.clone(),
                path_len_constraint: Some(0),
            },
            inter_serial,
            inter_validity,
            inter_subject,
            inter_spki,
            &root_sk,
        )
        .context("build intermediate cert builder")?
        .build::<p384::ecdsa::DerSignature>()
        .context("sign intermediate cert")?;

        let intermediate_cert_der = inter_cert.to_der().context("encode intermediate cert DER")?;

        // ── Enclave (leaf) cert ────────────────────────────────────────
        let enclave_sk = SigningKey::random(&mut OsRng);
        let enclave_spki = spki_owned(&enclave_sk)?;
        let enclave_serial = SerialNumber::from(3u32);
        let enclave_validity = Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60 * 10))
            .context("build enclave validity")?;
        let enclave_subject: Name =
            "CN=mock.enclave".parse().context("parse enclave subject")?;

        let enclave_cert = CertificateBuilder::new(
            Profile::Leaf {
                issuer: inter_cert.tbs_certificate.subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            enclave_serial,
            enclave_validity,
            enclave_subject,
            enclave_spki,
            &inter_sk,
        )
        .context("build enclave cert builder")?
        .build::<p384::ecdsa::DerSignature>()
        .context("sign enclave cert")?;

        let enclave_cert_der = enclave_cert.to_der().context("encode enclave cert DER")?;

        Ok(Self {
            root_cert_der,
            intermediate_cert_der,
            enclave_cert_der,
            enclave_signing_key: enclave_sk,
        })
    }

    /// Returns the CA bundle as AWS Nitro formats it: root cert first, then intermediate.
    pub fn cabundle(&self) -> Vec<Vec<u8>> {
        vec![
            self.root_cert_der.clone(),
            self.intermediate_cert_der.clone(),
        ]
    }
}
