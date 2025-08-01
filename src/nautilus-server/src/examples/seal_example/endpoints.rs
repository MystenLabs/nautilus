// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::examples::seal_example::{ENC_SECRET, SEAL_API_KEY, SEAL_CONFIG, SEAL_WALLET};
use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::Hex;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{KeyPair, Signer};
use rand::thread_rng;
use seal_crypto::elgamal::{decrypt as elgamal_decrypt, genkey};
use seal_crypto::ibe::PublicKey as IBEPublicKey;
use seal_crypto::IBEUserSecretKeys;
use seal_crypto::{seal_decrypt, EncryptedObject, IBEPublicKeys};
use seal_key_server::types::Certificate;
use seal_key_server::types::FetchKeyRequest;
use seal_key_server::types::FetchKeyResponse;
use seal_key_server::{signed_message, signed_request};
use shared_crypto::intent::{Intent, IntentMessage};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::Signature;
use sui_types::signature::GenericSignature;
use tracing::info;

/// Init parameter load endpoint - Step 1 of Seal key retrieval
/// This endpoint is called by the host to get the request body for fetching keys
pub async fn init_parameter_load(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    // Generate a unique session ID
    let session_id = uuid::Uuid::new_v4().to_string();
    info!("Initializing parameter load for session: {}", session_id);

    // Use cached config
    let config = &*SEAL_CONFIG;

    let wallet_guard = SEAL_WALLET.read().await;
    let public_key = wallet_guard.public();
    let wallet_address: SuiAddress = (&public_key).into();

    // Parse package ID from config
    let package_id = ObjectID::from_hex_literal(&config.package_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid package ID in config: {}", e)))?;

    // Parse enclave object ID from config
    let enclave_id = ObjectID::from_hex_literal(&config.enclave_id).map_err(|e| {
        EnclaveError::GenericError(format!("Invalid enclave object ID in config: {}", e))
    })?;

    let (enc_secret, enc_key, enc_verification_key) = genkey(&mut thread_rng());

    // Store encryption secret key in lazy static cache
    {
        let mut enc_secret_guard = (*ENC_SECRET).write().await;
        *enc_secret_guard = Some(enc_secret);
    }
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
    let signature =
        GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &*wallet_guard));
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
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    let encrypted_object: EncryptedObject = bcs::from_bytes(
        &Hex::decode(&request.encrypted_object)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid hex encoding: {}", e)))?,
    )
    .unwrap();
    let seal_responses: Vec<FetchKeyResponse> = bcs::from_bytes(
        &Hex::decode(&request.seal_responses)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid hex encoding: {}", e)))?,
    )
    .unwrap();

    let enc_secret_guard = (*ENC_SECRET).read().await;
    let enc_secret = enc_secret_guard.as_ref().ok_or_else(|| {
        EnclaveError::GenericError("Encryption secret key not found in cache".to_string())
    })?;

    let mut all_keys = HashMap::new();
    seal_responses.iter().for_each(|response| {
        let object_id = ObjectID::from_bytes(&response.decryption_keys[0].id).unwrap();
        // todo: handle array
        let user_secret_key =
            elgamal_decrypt(&enc_secret, &response.decryption_keys[0].encrypted_key);
        // todo: verify secret key
        all_keys.insert(object_id, user_secret_key);
    });

    let user_secret_keys = IBEUserSecretKeys::BonehFranklinBLS12381(all_keys);

    let config = &*SEAL_CONFIG;
    let pks: Vec<IBEPublicKey> = config
        .public_keys
        .iter()
        .map(
            |pk_hex| -> Result<IBEPublicKey, Box<dyn std::error::Error>> {
                let bytes =
                    Hex::decode(pk_hex).map_err(|e| format!("Invalid public key hex: {}", e))?;
                let pk = seal_crypto::ibe::PublicKey::from_byte_array(
                    &bytes.try_into().map_err(|_| "Invalid public key length")?,
                )?;
                Ok(pk)
            },
        )
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| EnclaveError::GenericError(format!("Failed to parse public keys: {}", e)))?;

    let public_keys = IBEPublicKeys::BonehFranklinBLS12381(pks);

    let secret = seal_decrypt(&encrypted_object, &user_secret_keys, Some(&public_keys))
        .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt: {}", e)))?;
    let secret_str = String::from_utf8(secret.clone()).unwrap();
    println!("secret: {}", secret_str);
    let mut api_key_guard = (*SEAL_API_KEY).write().await;
    *api_key_guard = Some(secret_str);
    Ok(Json(CompleteParameterLoadResponse {
        response: Hex::encode(&secret),
    }))
}
