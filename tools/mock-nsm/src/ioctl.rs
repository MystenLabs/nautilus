use std::collections::BTreeMap;
use serde_bytes::ByteBuf;

/// NSM request types (mirrors aws-nitro-enclaves-nsm-api)
#[derive(Debug, serde::Deserialize)]
pub enum NsmRequest {
    DescribePCR { index: u16 },
    ExtendPCR { index: u16, #[serde(with = "serde_bytes")] data: Vec<u8> },
    LockPCR { index: u16 },
    LockPCRs { range: u16 },
    DescribeNSM,
    Attestation {
        user_data: Option<ByteBuf>,
        nonce: Option<ByteBuf>,
        public_key: Option<ByteBuf>,
    },
    GetRandom,
}

/// NSM response types
#[derive(Debug, serde::Serialize)]
pub enum NsmResponse {
    DescribePCR { lock: bool, #[serde(with = "serde_bytes")] data: Vec<u8> },
    ExtendPCR { #[serde(with = "serde_bytes")] data: Vec<u8> },
    LockPCR,
    LockPCRs,
    DescribeNSM {
        version_major: u16,
        version_minor: u16,
        version_patch: u16,
        module_id: String,
        max_pcrs: u16,
        locked_pcrs: std::collections::BTreeSet<u16>,
        digest: String,
    },
    Attestation { #[serde(with = "serde_bytes")] document: Vec<u8> },
    GetRandom { #[serde(with = "serde_bytes")] random: Vec<u8> },
    Error(String),
}

/// Decode a CBOR-encoded NSM request.
/// Uses serde_cbor for compatibility with nsm_api.
pub fn decode_request(data: &[u8]) -> Result<NsmRequest, String> {
    serde_cbor::from_slice(data).map_err(|e| format!("CBOR decode error: {}", e))
}

/// Encode an NSM response to CBOR.
/// Uses serde_cbor for compatibility with nsm_api.
pub fn encode_response(response: &NsmResponse) -> Vec<u8> {
    serde_cbor::to_vec(response).expect("CBOR encode failed")
}

/// PCR state
pub struct PcrBank {
    pub pcrs: BTreeMap<usize, Vec<u8>>,
    pub locked: std::collections::BTreeSet<u16>,
}

impl PcrBank {
    pub fn new() -> Self {
        let mut pcrs = BTreeMap::new();
        // Initialize PCRs 0-15 with 48 bytes of zeros (SHA384)
        for i in 0..16 {
            pcrs.insert(i, vec![0u8; 48]);
        }
        Self {
            pcrs,
            locked: std::collections::BTreeSet::new(),
        }
    }
}

/// Handle an NSM request and produce a response
pub fn handle_request(
    request: NsmRequest,
    pcr_bank: &mut PcrBank,
    attestation_handler: &dyn Fn(Option<&[u8]>, Option<&[u8]>, Option<&[u8]>, &BTreeMap<usize, Vec<u8>>) -> Vec<u8>,
) -> NsmResponse {
    match request {
        NsmRequest::DescribePCR { index } => {
            let idx = index as usize;
            match pcr_bank.pcrs.get(&idx) {
                Some(data) => NsmResponse::DescribePCR {
                    lock: pcr_bank.locked.contains(&index),
                    data: data.clone(),
                },
                None => NsmResponse::Error("InvalidIndex".to_string()),
            }
        }
        NsmRequest::ExtendPCR { index, data } => {
            let idx = index as usize;
            if pcr_bank.locked.contains(&index) {
                return NsmResponse::Error("ReadOnlyIndex".to_string());
            }
            if let Some(pcr) = pcr_bank.pcrs.get_mut(&idx) {
                // PCR extend: SHA384(current_value || new_data)
                use sha2::{Sha384, Digest};
                let mut hasher = Sha384::new();
                hasher.update(&*pcr);
                hasher.update(&data);
                let result = hasher.finalize().to_vec();
                *pcr = result.clone();
                NsmResponse::ExtendPCR { data: result }
            } else {
                NsmResponse::Error("InvalidIndex".to_string())
            }
        }
        NsmRequest::LockPCR { index } => {
            pcr_bank.locked.insert(index);
            NsmResponse::LockPCR
        }
        NsmRequest::LockPCRs { range } => {
            for i in 0..range {
                pcr_bank.locked.insert(i);
            }
            NsmResponse::LockPCRs
        }
        NsmRequest::DescribeNSM => NsmResponse::DescribeNSM {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            module_id: "mock-nsm".to_string(),
            max_pcrs: 16,
            locked_pcrs: pcr_bank.locked.clone(),
            digest: "SHA384".to_string(),
        },
        NsmRequest::Attestation { user_data, nonce, public_key } => {
            let doc = attestation_handler(
                public_key.as_ref().map(|b| b.as_ref()),
                user_data.as_ref().map(|b| b.as_ref()),
                nonce.as_ref().map(|b| b.as_ref()),
                &pcr_bank.pcrs,
            );
            NsmResponse::Attestation { document: doc }
        }
        NsmRequest::GetRandom => {
            use rand::RngCore;
            let mut buf = vec![0u8; 256];
            rand::thread_rng().fill_bytes(&mut buf);
            NsmResponse::GetRandom { random: buf }
        }
    }
}
