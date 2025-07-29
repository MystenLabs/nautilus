// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes, Signer};
use fastcrypto::encoding::Encoding;

use super::seal_sdk::*;

/// Initialize the Seal wallet if not already initialized
async fn ensure_seal_wallet() -> Result<(), EnclaveError> {
    let mut wallet_guard = SEAL_WALLET.write().map_err(|e| {
        EnclaveError::GenericError(format!("Failed to acquire wallet lock: {}", e))
    })?;
    
    if wallet_guard.is_none() {
        info!("Initializing Seal wallet");
        let wallet = Ed25519KeyPair::generate(&mut rand::thread_rng());
        *wallet_guard = Some(wallet);
    }
    Ok(())
}

/// Init parameter load endpoint - Step 1 of Seal key retrieval
/// This endpoint is called by the host to get the request body for fetching keys
pub async fn init_parameter_load(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitParameterLoadRequest>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    info!("Initializing parameter load for session: {}", request.session_id);
    
    // Ensure wallet exists
    ensure_seal_wallet().await?;
    
    let wallet_guard = SEAL_WALLET.read().map_err(|e| {
        EnclaveError::GenericError(format!("Failed to acquire wallet lock: {}", e))
    })?;
    let wallet = wallet_guard.as_ref().ok_or_else(|| {
        EnclaveError::GenericError("Wallet not initialized".to_string())
    })?;
    let wallet_address_bytes = wallet.public().as_bytes();
    let wallet_address = hex::encode(wallet_address_bytes);
    
    // Parse package ID
    let package_id_bytes = hex::decode(&request.package_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid package ID: {}", e)))?;
    if package_id_bytes.len() != 32 {
        return Err(EnclaveError::GenericError("Package ID must be 32 bytes".to_string()));
    }
    let mut package_id = [0u8; 32];
    package_id.copy_from_slice(&package_id_bytes);
    
    // Generate object ID for the encrypted object (this would normally come from the encrypted object)
    let object_id = vec![1, 2, 3, 4]; // Placeholder
    
    // Parse enclave object ID
    let enclave_object_id = hex::decode(&request.enclave_object_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid enclave object ID: {}", e)))?;
    
    // Generate ephemeral keypair for ElGamal
    let (eph_sk, eph_pk) = generate_ephemeral_keypair();
    
    // Create session key
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {}", e)))?
        .as_millis() as u64;
    
    let session_vk = state.eph_kp.public().as_bytes().to_vec();
    let ttl_min = 60; // 60 minutes TTL
    
    let session_key = SessionKey {
        address: wallet_address.clone(),
        package_id: request.package_id.clone(),
        session_vk: session_vk.clone(),
        creation_time: current_time,
        ttl_min,
    };
    
    // Sign the sender address for seal_approve
    let sender_signature: fastcrypto::ed25519::Ed25519Signature = state.eph_kp.sign(wallet_address_bytes);
    let sender_signature = sender_signature.as_bytes().to_vec();
    
    // Create PTB using proper builder
    let ptb_bytes = create_seal_approve_ptb(
        &package_id,
        &object_id,
        &enclave_object_id,
        &sender_signature,
    )?;
    let ptb_base64 = fastcrypto::encoding::Base64::encode(&ptb_bytes);
    
    // Create certificate signature - wallet signs session key info
    let cert_msg = format!(
        "{}|{}|{}|{}",
        hex::encode(&session_vk),
        request.package_id,
        ttl_min,
        current_time
    );
    let cert_signature: fastcrypto::ed25519::Ed25519Signature = wallet.sign(cert_msg.as_bytes());
    let cert_signature = cert_signature.as_bytes().to_vec();
    
    // Create request signature - session key signs the request
    let request_msg = format!(
        "{}|{}|{}",
        ptb_base64,
        hex::encode(&eph_pk),
        hex::encode(&eph_pk), // enc_verification_key
    );
    let request_signature: fastcrypto::ed25519::Ed25519Signature = state.eph_kp.sign(request_msg.as_bytes());
    let request_signature = request_signature.as_bytes().to_vec();
    
    // Store ephemeral session
    let ephemeral_session = EphemeralSession {
        session_id: request.session_id.clone(),
        ephemeral_sk: eph_sk,
        session_key: session_key.clone(),
        created_at: current_time,
        ttl_ms: ttl_min * 60 * 1000,
        package_id: request.package_id.clone(),
        enclave_object_id: request.enclave_object_id.clone(),
    };
    
    {
        let mut storage = EPHEMERAL_STORAGE.write().map_err(|e| {
            EnclaveError::GenericError(format!("Failed to acquire storage lock: {}", e))
        })?;
        storage.insert(request.session_id.clone(), ephemeral_session);
    }
    
    // Build response
    let response = InitParameterLoadResponse {
        request_body: SealRequestBody {
            ptb: ptb_base64,
            enc_key: eph_pk.clone(),
            enc_verification_key: eph_pk,
            request_signature,
            certificate: SessionCertificate {
                address: wallet_address,
                session_vk,
                creation_time: current_time,
                ttl_min,
                signature: cert_signature,
            },
        },
    };
    
    Ok(Json(response))
}

/// Complete parameter load endpoint - Step 2 of Seal key retrieval
/// This endpoint is called by the host with the encrypted object and seal responses
pub async fn complete_parameter_load(
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    info!("Completing parameter load for session: {}", request.session_id);
    
    // Retrieve ephemeral session
    let ephemeral_session = {
        let mut storage = EPHEMERAL_STORAGE.write().map_err(|e| {
            EnclaveError::GenericError(format!("Failed to acquire storage lock: {}", e))
        })?;
        storage.remove(&request.session_id).ok_or_else(|| {
            EnclaveError::GenericError(format!("Session {} not found", request.session_id))
        })?
    };
    
    // Verify session hasn't expired
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {}", e)))?
        .as_millis() as u64;
    
    if current_time > ephemeral_session.created_at + ephemeral_session.ttl_ms {
        return Err(EnclaveError::GenericError("Session expired".to_string()));
    }
    
    // Verify the encrypted object's package ID matches
    let encrypted_pkg_id = hex::encode(&request.encrypted_object.package_id);
    if encrypted_pkg_id != ephemeral_session.package_id {
        return Err(EnclaveError::GenericError(
            format!("Package ID mismatch: {} != {}", encrypted_pkg_id, ephemeral_session.package_id)
        ));
    }
    
    // TODO: Verify Seal server responses against server public keys
    // TODO: Check threshold is met
    
    // Decrypt the keys using ephemeral SK
    // This is a simplified version - real implementation would use ElGamal decryption
    let mut decrypted_keys = Vec::new();
    for response in &request.seal_responses {
        for dk in &response.decryption_keys {
            // In real implementation, decrypt using ElGamal with ephemeral_session.ephemeral_sk
            // For now, just collect the key IDs
            decrypted_keys.push(dk.id.clone());
        }
    }
    
    // Check if we have enough keys based on threshold
    if decrypted_keys.len() < request.encrypted_object.threshold as usize {
        return Err(EnclaveError::GenericError(
            format!("Not enough keys received: {} < {}", 
                decrypted_keys.len(), 
                request.encrypted_object.threshold)
        ));
    }
    
    // Decrypt the actual data based on the ciphertext type
    let decrypted_data = match &request.encrypted_object.ciphertext {
        Ciphertext::Plain => {
            serde_json::json!({
                "message": "Plain text data - no decryption needed",
                "object_id": hex::encode(&request.encrypted_object.id)
            })
        },
        Ciphertext::Aes256Gcm { blob, aad } => {
            // TODO: Implement AES-256-GCM decryption using the decrypted keys
            // This would involve:
            // 1. Combining the decrypted key shares
            // 2. Using the combined key to decrypt the blob
            serde_json::json!({
                "message": "AES-256-GCM encrypted data (decryption not yet implemented)",
                "blob_size": blob.len(),
                "has_aad": aad.is_some()
            })
        },
        Ciphertext::Hmac256Ctr { blob, aad, mac } => {
            // TODO: Implement HMAC-256-CTR decryption
            serde_json::json!({
                "message": "HMAC-256-CTR encrypted data (decryption not yet implemented)",
                "blob_size": blob.len(),
                "has_aad": aad.is_some(),
                "mac": hex::encode(mac)
            })
        }
    };
    
    Ok(Json(CompleteParameterLoadResponse {
        decrypted_data,
    }))
}