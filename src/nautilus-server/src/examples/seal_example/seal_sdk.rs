// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::ObjectID;
use sui_json_rpc_types::SuiParsedData;
use rand::{thread_rng, RngCore};

const KEY_SIZE: usize = 32;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEPublicKeys {
    BonehFranklinBLS12381(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionInput {
    Aes256Gcm { data: Vec<u8>, aad: Option<Vec<u8>> },
    Hmac256Ctr { data: Vec<u8>, aad: Option<Vec<u8>> },
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

/// Response structure for init_parameter_load - CLI-ready parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadResponse {
    pub ptb: String,                    // Base64 encoded PTB
    pub enc_key: String,                // Base64 encoded ephemeral public key
    pub enc_verification_key: String,   // Base64 encoded ephemeral verification key
    pub request_signature: String,      // Base64 encoded request signature
    pub certificate: String,            // JSON string of certificate
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

/// Request format for signing (matches TypeScript SDK)
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestFormat {
    pub ptb: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub enc_verification_key: Vec<u8>,
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

// Key server info fetched from chain
#[derive(Debug, Deserialize)]
pub struct KeyServerInfo {
    #[allow(dead_code)]
    pub object_id: String,
    pub name: String,
    pub url: String,
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

/// Fetch key server URLs from Sui chain using proper SDK
pub async fn fetch_key_server_urls(
    key_server_ids: &[String],
    sui_rpc: &str,
) -> Result<Vec<KeyServerInfo>, Box<dyn std::error::Error>> {
    let sui_client = SuiClientBuilder::default()
        .build(sui_rpc)
        .await?;
    
    let mut servers = Vec::new();
    
    for object_id_str in key_server_ids {
        let object_id: ObjectID = object_id_str.parse()
            .map_err(|e| format!("Invalid object ID {}: {}", object_id_str, e))?;
        
        // Get the dynamic field object for version 1
        let dynamic_field_name = sui_types::dynamic_field::DynamicFieldName {
            type_: sui_types::TypeTag::U64,
            value: serde_json::Value::String("1".to_string()),
        };
        
        match sui_client.read_api()
            .get_dynamic_field_object(object_id, dynamic_field_name)
            .await
        {
            Ok(response) => {
                if let Some(object_data) = response.data {
                    if let Some(content) = object_data.content {
                        if let SuiParsedData::MoveObject(parsed_data) = content {
                            let fields = &parsed_data.fields;
                            
                            // Convert fields to JSON value for access
                            let fields_json = serde_json::to_value(fields)
                                .map_err(|e| format!("Failed to serialize fields: {}", e))?;
                            
                            // Extract URL and name from the nested 'value' field
                            let value_struct = fields_json.get("value")
                                .ok_or_else(|| format!("Missing 'value' field for object {}", object_id_str))?;
                            
                            // The value is a Struct, we need to access its fields
                            let value_fields = value_struct.get("fields")
                                .ok_or_else(|| format!("Missing 'fields' in value struct for object {}", object_id_str))?;
                            
                            let url = value_fields.get("url")
                                .and_then(|v| match v {
                                    serde_json::Value::String(s) => Some(s.clone()),
                                    _ => None,
                                })
                                .ok_or_else(|| format!("Missing or invalid 'url' field in value fields for object {}", object_id_str))?;
                            
                            let name = value_fields.get("name")
                                .and_then(|v| match v {
                                    serde_json::Value::String(s) => Some(s.clone()),
                                    _ => Some("Unknown".to_string()),
                                })
                                .unwrap_or_else(|| "Unknown".to_string());
                            
                            servers.push(KeyServerInfo {
                                object_id: object_id_str.clone(),
                                name,
                                url,
                            });
                        } else {
                            return Err(format!("Unexpected content type for object {}", object_id_str).into());
                        }
                    } else {
                        return Err(format!("No content found for object {}", object_id_str).into());
                    }
                } else {
                    return Err(format!("Object {} not found", object_id_str).into());
                }
            }
            Err(e) => {
                return Err(format!("Failed to fetch dynamic field for object {}: {}", object_id_str, e).into());
            }
        }
    }
    
    Ok(servers)
}

/// Simple seal_encrypt implementation for the CLI
pub fn seal_encrypt(
    package_id: [u8; 32],
    id: Vec<u8>,
    key_servers: Vec<[u8; 32]>,
    _public_keys: &IBEPublicKeys,
    threshold: u8,
    encryption_input: EncryptionInput,
) -> Result<EncryptedObject, Box<dyn std::error::Error>> {
    // Generate a random key
    let mut dem_key = [0u8; KEY_SIZE];
    thread_rng().fill_bytes(&mut dem_key);
    
    // Encrypt the data
    let ciphertext = match encryption_input {
        EncryptionInput::Aes256Gcm { data, aad } => {
            // For this example, we'll use a simple XOR encryption
            // In production, this would use proper AES-GCM encryption
            let mut blob = data.clone();
            for (i, byte) in blob.iter_mut().enumerate() {
                *byte ^= dem_key[i % KEY_SIZE];
            }
            Ciphertext::Aes256Gcm { blob, aad }
        }
        _ => return Err("Only Aes256Gcm encryption is supported in this example".into()),
    };
    
    // Create mock encrypted shares (in production, these would be real IBE encrypted shares)
    let services: Vec<([u8; 32], u8)> = key_servers
        .iter()
        .enumerate()
        .map(|(i, ks)| (*ks, i as u8))
        .collect();
    
    let encrypted_object = EncryptedObject {
        version: 0,
        package_id,
        id,
        services,
        threshold,
        encrypted_shares: IBEEncryptions::BonehFranklinBLS12381 {
            nonce: vec![0u8; 32],
            encrypted_shares: key_servers.iter().map(|_| vec![0u8; 48]).collect(),
            encrypted_randomness: vec![0u8; 32],
        },
        ciphertext,
    };
    
    Ok(encrypted_object)
}