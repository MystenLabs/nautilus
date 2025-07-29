// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};

// Storage for Seal-specific data
lazy_static::lazy_static! {
    // Seal-specific wallet (only for this module)
    pub static ref SEAL_WALLET: RwLock<Option<Ed25519KeyPair>> = RwLock::new(None);
    
    // Ephemeral storage for pending Seal requests
    pub static ref EPHEMERAL_STORAGE: RwLock<HashMap<String, EphemeralSession>> = RwLock::new(HashMap::new());
}

/// Encrypted object structure from Seal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedObject {
    pub version: u8,
    pub package_id: [u8; 32],
    pub id: Vec<u8>,
    pub services: Vec<([u8; 32], u8)>,
    pub threshold: u8,
    pub encrypted_shares: IBEEncryptions,
    pub ciphertext: Ciphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEEncryptions {
    BonehFranklinBLS12381 {
        nonce: Vec<u8>,
        encrypted_shares: Vec<Vec<u8>>,
        encrypted_randomness: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    Aes256Gcm { blob: Vec<u8>, aad: Option<Vec<u8>> },
    Hmac256Ctr { blob: Vec<u8>, aad: Option<Vec<u8>>, mac: [u8; 32] },
    Plain,
}

/// Ephemeral session data for Seal parameter loading
#[derive(Debug, Clone)]
pub struct EphemeralSession {
    pub session_id: String,
    pub ephemeral_sk: Vec<u8>, // ElGamal secret key
    pub session_key: SessionKey,
    pub created_at: u64,
    pub ttl_ms: u64,
    pub package_id: String,
    pub enclave_object_id: String,
}

/// Session key structure matching TypeScript SDK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    pub address: String,
    pub package_id: String,
    pub session_vk: Vec<u8>, // Session verification key
    pub creation_time: u64,
    pub ttl_min: u64,
}

/// Request structure for init_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadRequest {
    pub session_id: String, // Unique ID for this session
    pub package_id: String, // Package ID for the seal policy
    pub enclave_object_id: String, // The enclave object ID on chain
}

/// Response structure for init_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadResponse {
    pub request_body: SealRequestBody,
}

/// Request body structure for Seal key servers
#[derive(Debug, Serialize, Deserialize)]
pub struct SealRequestBody {
    pub ptb: String, // Base64 encoded PTB
    pub enc_key: Vec<u8>,
    pub enc_verification_key: Vec<u8>,
    pub request_signature: Vec<u8>,
    pub certificate: SessionCertificate,
}

/// Session certificate structure
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionCertificate {
    pub address: String,
    pub session_vk: Vec<u8>,
    pub creation_time: u64,
    pub ttl_min: u64,
    pub signature: Vec<u8>, // Wallet's personal message signature
}

/// Request structure for complete_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteParameterLoadRequest {
    pub session_id: String,
    pub encrypted_object: EncryptedObject, // The encrypted secret to decrypt
    pub seal_responses: Vec<SealServerResponse>,
}

/// Response from Seal key server
#[derive(Debug, Serialize, Deserialize)]
pub struct SealServerResponse {
    pub server_id: String,
    pub decryption_keys: Vec<DecryptionKey>,
    pub signature: Vec<u8>,
}

/// Decryption key from Seal server
#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionKey {
    pub id: Vec<u8>,
    pub encrypted_key: (String, String), // ElGamal encrypted key
}

/// Response structure for complete_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteParameterLoadResponse {
    pub decrypted_data: serde_json::Value, // The decrypted parameter data
}

/// Generate ElGamal ephemeral keypair (simplified - using Ed25519 for now)
pub fn generate_ephemeral_keypair() -> (Vec<u8>, Vec<u8>) {
    let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
    let pk = keypair.public().as_bytes().to_vec();
    let sk = keypair.private().as_bytes().to_vec();
    (sk, pk)
}

/// Create a PTB for seal_approve call using proper PTB builder
pub fn create_seal_approve_ptb(
    package_id: &[u8; 32],
    object_id: &[u8],
    enclave_object_id: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, crate::EnclaveError> {
    // Create PTB structure matching the Sui SDK format
    // This is a simplified version - in production would use actual Sui SDK types
    let ptb = serde_json::json!({
        "inputs": [
            {
                "type": "pure",
                "value": object_id
            },
            {
                "type": "object",
                "objectId": hex::encode(enclave_object_id),
                "version": null,
                "digest": null
            },
            {
                "type": "pure", 
                "value": signature
            }
        ],
        "commands": [
            {
                "MoveCall": {
                    "package": hex::encode(package_id),
                    "module": "seal_policy",
                    "function": "seal_approve",
                    "type_arguments": [],
                    "arguments": [
                        {"Input": 0},
                        {"Input": 1},
                        {"Input": 2}
                    ]
                }
            }
        ]
    });
    
    // Serialize to BCS format (simplified - would use proper BCS encoding)
    bcs::to_bytes(&ptb).map_err(|e| {
        crate::EnclaveError::GenericError(format!("Failed to serialize PTB: {}", e))
    })
}