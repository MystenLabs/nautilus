// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::apps::seal_example::{ENCRYPTION_KEYS, SEAL_API_KEY, SEAL_CONFIG};
use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::Hex;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::{KeyPair, Signer};
use rand::thread_rng;
use seal_sdk::types::{FetchKeyRequest, KeyId};
use seal_sdk::Certificate;
use seal_sdk::IBEPublicKey;
use seal_sdk::{seal_decrypt_all_objects, signed_message, signed_request};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sui_sdk_types::Argument;
use sui_sdk_types::Command;
use sui_sdk_types::Identifier;
use sui_sdk_types::Input;
use sui_sdk_types::MoveCall;
use sui_sdk_types::ObjectId as ObjectID;
use sui_sdk_types::PersonalMessage;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::TypeTag;

/// Step 1: This endpoint takes enclave obj id with initial shared version,
/// a list of key IDs and package id where seal_approve is defined.
/// Returns a FetchKeyRequest that contains the certificate and desired ptb.
pub async fn init_parameter_load(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitParameterLoadRequest>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    if SEAL_API_KEY.read().await.is_some() {
        return Err(EnclaveError::GenericError(
            "API key already set".to_string(),
        ));
    }
    // Generate session and create certificate.
    let session = Ed25519KeyPair::generate(&mut thread_rng());
    let session_vk = session.public();
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {}", e)))?
        .as_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(
        SEAL_CONFIG.package_id.to_string(),
        session_vk,
        creation_time,
        ttl_min,
    );

    // Convert fastcrypto keypair to sui-crypto for signing
    let sui_private_key = {
        let priv_key_bytes = state.eph_kp.as_ref();
        let key_bytes: [u8; 32] = priv_key_bytes
            .try_into()
            .map_err(|_| EnclaveError::GenericError("Invalid private key length".to_string()))?;
        sui_crypto::ed25519::Ed25519PrivateKey::new(key_bytes)
    };

    // Sign personal message
    let signature = {
        use sui_crypto::SuiSigner;
        sui_private_key
            .sign_personal_message(&PersonalMessage(message.as_bytes().into()))
            .map_err(|e| {
                EnclaveError::GenericError(format!("Failed to sign personal message: {}", e))
            })?
    };

    // Create certificate with enclave ephemeral key wallet and session vk.
    let certificate = Certificate {
        user: sui_private_key.public_key().to_address(),
        session_vk: session_vk.clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    // Create PTB for seal_approve of package with multiple IDs
    let ptb = create_ptb(
        SEAL_CONFIG.package_id,
        request.enclave_object_id,
        request.initial_shared_version,
        request.ids,
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("Failed to create PTB: {}", e)))?;
    // Use the lazily initialized encryption keys.
    let (_enc_secret, enc_key, enc_verification_key) = &*ENCRYPTION_KEYS;
    // Create FetchKeyRequest.
    let request_message = signed_request(&ptb, enc_key, enc_verification_key);
    let request_signature = session.sign(&request_message);
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).expect("should not fail")),
        enc_key: enc_key.clone(),
        enc_verification_key: enc_verification_key.clone(),
        request_signature,
        certificate,
    };

    Ok(Json(InitParameterLoadResponse {
        encoded_request: Hex::encode(bcs::to_bytes(&request).expect("should not fail")),
    }))
}

/// Step 3: Complete parameter load. This endpoint accepts the encrypted
/// object and encoded seal responses, which are fetched by the host
/// using cli. It fetches keys from each server for all ids included in PTB,
/// then decrypts all encrypted objects. Initialize SEAL_API (the first secret)
/// if decryption is successful and returns OK.
pub async fn complete_parameter_load(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    if SEAL_API_KEY.read().await.is_some() {
        return Err(EnclaveError::GenericError(
            "API key already set".to_string(),
        ));
    }

    // BUild a map for service obj id -> pk
    let mut server_pk_map: HashMap<ObjectID, IBEPublicKey> = HashMap::new();
    for (server_id, pk) in SEAL_CONFIG
        .key_servers
        .iter()
        .zip(SEAL_CONFIG.public_keys.iter())
    {
        server_pk_map.insert(*server_id, *pk);
    }

    // Load the encryption secret key from lazy static
    let (enc_secret, _enc_key, _enc_verification_key) = &*ENCRYPTION_KEYS;

    let decrypted_results = seal_decrypt_all_objects(
        enc_secret,
        &request.seal_responses,
        &request.encrypted_objects,
        &server_pk_map,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt objects: {}", e)))?;

    // The first secret is the weather API key, store it
    if let Some(api_key_bytes) = decrypted_results.first() {
        let api_key_str = String::from_utf8(api_key_bytes.clone())
            .map_err(|e| EnclaveError::GenericError(format!("Invalid UTF-8 in secret: {}", e)))?;

        let mut api_key_guard = (*SEAL_API_KEY).write().await;
        *api_key_guard = Some(api_key_str.clone());
    } else {
        return Err(EnclaveError::GenericError(
            "No secrets were decrypted".to_string(),
        ));
    }

    // Return the rest of dummy secrets as demo, remove as needed.
    Ok(Json(CompleteParameterLoadResponse {
        dummy_secrets: decrypted_results[1..].to_vec(),
    }))
}

/// Create a PTB with multiple commands for the given IDs and the enclave shared object.
async fn create_ptb(
    package_id: ObjectID,
    enclave_object_id: ObjectID,
    initial_shared_version: u64,
    ids: Vec<KeyId>,
) -> Result<ProgrammableTransaction, Box<dyn std::error::Error>> {
    let mut inputs = vec![];
    let mut commands = vec![];

    // Create inputs for all IDs
    for id in ids.iter() {
        inputs.push(Input::Pure {
            value: bcs::to_bytes(id)?,
        });
    }

    // Add the shared enclave object as the last input
    let enclave_input_idx = inputs.len();
    inputs.push(Input::Shared {
        object_id: enclave_object_id,
        initial_shared_version,
        mutable: false,
    });

    // Create MoveCall commands for each ID
    // Each call to seal_approve with a different ID
    for (idx, _id) in ids.iter().enumerate() {
        let move_call = MoveCall {
            package: package_id,
            module: Identifier::new("seal_policy")?,
            function: Identifier::new("seal_approve")?,
            type_arguments: vec![TypeTag::from_str(&format!(
                "{}::weather::WEATHER",
                package_id
            ))?],
            arguments: vec![
                Argument::Input(idx as u16),               // ID input
                Argument::Input(enclave_input_idx as u16), // Enclave object
            ],
        };
        commands.push(Command::MoveCall(move_call));
    }

    let ptb = ProgrammableTransaction { inputs, commands };

    Ok(ptb)
}
