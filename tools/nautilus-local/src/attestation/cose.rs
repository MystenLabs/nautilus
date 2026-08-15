use anyhow::{Context, Result};
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use p384::ecdsa::{signature::Signer, Signature};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::ca::TestCa;
use super::cbor::build_attestation_payload;

/// Build a complete COSE_Sign1 attestation document that structurally matches
/// what the AWS Nitro Secure Module (NSM) would return in
/// `NsmResponse::Attestation { document }`.
///
/// Returns the raw CBOR-serialised COSE_Sign1 bytes.
pub fn build_attestation_document(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    pcrs: &BTreeMap<usize, Vec<u8>>,
    ca: &TestCa,
) -> Result<Vec<u8>> {
    // Fill in default (all-zero) PCRs for indices 0..16 where not provided
    let mut full_pcrs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for i in 0..16 {
        let value = pcrs.get(&i).cloned().unwrap_or_else(|| vec![0u8; 48]);
        full_pcrs.insert(i, value);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_millis() as u64;

    // Build the inner attestation payload (CBOR)
    let payload_bytes = build_attestation_payload(
        "mock-enclave-local",
        "SHA384",
        timestamp,
        &full_pcrs,
        &ca.enclave_cert_der,
        &ca.cabundle(),
        public_key,
        user_data,
        nonce,
    )?;

    // Build protected header: algorithm = ES384
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();

    // Build COSE_Sign1 and sign with the enclave P-384 key
    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(b"", |data| {
            let sig: Signature = ca.enclave_signing_key.sign(data);
            sig.to_bytes().to_vec()
        })
        .build();

    let bytes = cose_sign1
        .to_vec()
        .map_err(|e| anyhow::anyhow!("serialize COSE_Sign1 to CBOR: {e:?}"))?;

    Ok(bytes)
}
