use anyhow::{Context, Result};
use ciborium::Value;
use std::collections::BTreeMap;

/// Build the CBOR-encoded attestation document payload that mirrors the
/// AWS Nitro Enclave attestation document schema.
///
/// See: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
pub fn build_attestation_payload(
    module_id: &str,
    digest: &str,
    timestamp: u64,
    pcrs: &BTreeMap<usize, Vec<u8>>,
    certificate: &[u8],
    cabundle: &[Vec<u8>],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Build the PCR map: integer key -> byte string value
    let pcr_entries: Vec<(Value, Value)> = pcrs
        .iter()
        .map(|(&idx, val)| {
            (
                Value::Integer((idx as i64).into()),
                Value::Bytes(val.clone()),
            )
        })
        .collect();

    // Build the cabundle as an array of byte strings
    let cabundle_array: Vec<Value> = cabundle.iter().map(|c| Value::Bytes(c.clone())).collect();

    // Helper to convert Option<&[u8]> to Value (bytes or null)
    let opt_bytes = |v: Option<&[u8]>| -> Value {
        match v {
            Some(b) => Value::Bytes(b.to_vec()),
            None => Value::Null,
        }
    };

    // The attestation document is a CBOR map with text-string keys
    let doc = Value::Map(vec![
        (
            Value::Text("module_id".into()),
            Value::Text(module_id.into()),
        ),
        (Value::Text("digest".into()), Value::Text(digest.into())),
        (
            Value::Text("timestamp".into()),
            Value::Integer((timestamp as i64).into()),
        ),
        (Value::Text("pcrs".into()), Value::Map(pcr_entries)),
        (
            Value::Text("certificate".into()),
            Value::Bytes(certificate.to_vec()),
        ),
        (
            Value::Text("cabundle".into()),
            Value::Array(cabundle_array),
        ),
        (
            Value::Text("public_key".into()),
            opt_bytes(public_key),
        ),
        (
            Value::Text("user_data".into()),
            opt_bytes(user_data),
        ),
        (Value::Text("nonce".into()), opt_bytes(nonce)),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&doc, &mut buf).context("serialize attestation payload to CBOR")?;
    Ok(buf)
}
