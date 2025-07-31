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
use fastcrypto::traits::{KeyPair, Signer};
use fastcrypto::encoding::{Encoding, Base64};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::Signature;
use sui_types::signature::GenericSignature;
use seal_crypto::elgamal::genkey;
use seal_key_server::{signed_message, signed_request};
use rand::thread_rng;
use shared_crypto::intent::{Intent, IntentMessage};
use seal_key_server::types::Certificate;
use seal_key_server::types::FetchKeyRequest;
use fastcrypto::encoding::Hex;
use sui_types::crypto::SuiKeyPair;
use super::types::*;

/// Initialize the Seal wallet if not already initialized
async fn ensure_seal_wallet() -> Result<(), EnclaveError> {
    let mut wallet_guard = SEAL_WALLET.write().map_err(|e| {
        EnclaveError::GenericError(format!("Failed to acquire wallet lock: {}", e))
    })?;
    
    if wallet_guard.is_none() {
        info!("Initializing Seal wallet");
        let ed25519_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
        *wallet_guard = Some(SuiKeyPair::Ed25519(ed25519_kp));
    }
    Ok(())
}

/// Init parameter load endpoint - Step 1 of Seal key retrieval
/// This endpoint is called by the host to get the request body for fetching keys
pub async fn init_parameter_load(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    // Generate a unique session ID
    let session_id = uuid::Uuid::new_v4().to_string();
    info!("Initializing parameter load for session: {}", session_id);
    
    // Load config from default location
    let config_path = "./seal_config.yaml";
    let config_str = std::fs::read_to_string(config_path)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to read config file: {}", e)))?;
    let config: SealConfig = serde_yaml::from_str(&config_str)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to parse config file: {}", e)))?;
    
    // Ensure wallet exists
    ensure_seal_wallet().await?;
    
    let wallet_guard = SEAL_WALLET.read().map_err(|e| {
        EnclaveError::GenericError(format!("Failed to acquire wallet lock: {}", e))
    })?;
    let wallet = wallet_guard.as_ref().ok_or_else(|| {
        EnclaveError::GenericError("Wallet not initialized".to_string())
    })?;
    let public_key = wallet.public();
    let wallet_address: SuiAddress = (&public_key).into();
    
    // Parse package ID from config
    let package_id = ObjectID::from_hex_literal(&config.package_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid package ID in config: {}", e)))?;
    
    // Parse enclave object ID from config
    let enclave_id = ObjectID::from_hex_literal(&config.enclave_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid enclave object ID in config: {}", e)))?;
    
    let (_enc_secret, enc_key, enc_verification_key) = genkey(&mut thread_rng());
    let session = Ed25519KeyPair::generate(&mut thread_rng());

    // Create certificate
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {}", e)))?
        .as_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(
        package_id.to_hex_uncompressed(),
        session.public(),
        creation_time,
        ttl_min,
    );

    let msg_with_intent = IntentMessage::new(Intent::personal_message(), message.clone());
    let signature = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, wallet));
    let certificate = Certificate {
        user: wallet_address,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    let ptb = create_ptb(package_id, enclave_id);
    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);
    
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).unwrap()),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    Ok(Json(InitParameterLoadResponse {
        encoded_request: Hex::encode(bcs::to_bytes(&request).unwrap()),
    }))
}

/// Complete parameter load endpoint - Step 2 of Seal key retrieval
/// This endpoint is called by the host with the encrypted object and seal responses
pub async fn complete_parameter_load(
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    info!("Completing parameter load for session: {}", request.session_id);

    Ok(Json(CompleteParameterLoadResponse {
        response: "ok".to_string(),
    }))
}