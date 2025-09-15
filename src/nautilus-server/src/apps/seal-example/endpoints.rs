// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::apps::seal_example::{ENCLAVE_WALLET, ENCRYPTION_SECRET_KEY, SEAL_API_KEY, SEAL_CONFIG};
use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::encoding::Hex;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto::traits::{KeyPair, Signer};
use rand::thread_rng;
use seal_sdk::elgamal_decrypt;
use seal_sdk::genkey;
use seal_sdk::types::FetchKeyRequest;
use seal_sdk::types::FetchKeyResponse;
use seal_sdk::Certificate;
use seal_sdk::IBEPublicKey;
use seal_sdk::IBEUserSecretKeys;
use seal_sdk::{ibe_verify_user_secret_key, signed_message, signed_request};
use seal_sdk::{seal_decrypt, EncryptedObject, IBEPublicKeys};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sui_crypto::SuiSigner;
use sui_sdk_types::Address;
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
/// key name and package id where seal_approve is defined.
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

    // Parse enclave object id and package id.
    let enclave_object_id = ObjectID::from_str(&request.enclave_object_id).map_err(|e| {
        EnclaveError::GenericError(format!("Invalid enclave object ID in request: {}", e))
    })?;
    let package_id = state.package_id;
    // Generate session and create certificate.
    let session = Ed25519KeyPair::generate(&mut thread_rng());
    let session_vk = session.public();
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {}", e)))?
        .as_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(package_id.to_string(), session_vk, creation_time, ttl_min);

    // Sign personal message from enclave wallet.
    let wallet_guard = ENCLAVE_WALLET.read().await;
    let wallet_address = wallet_guard.public_key().to_address();
    let signature = wallet_guard
        .sign_personal_message(&PersonalMessage(message.as_bytes().into()))
        .map_err(|e| {
            EnclaveError::GenericError(format!("Failed to sign personal message: {}", e))
        })?;

    // Create certificate with enclave wallet and session vk.
    let certificate = Certificate {
        user: wallet_address,
        session_vk: session_vk.clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    // Create PTB for seal_approve of package.
    let ptb = create_ptb(
        package_id,
        enclave_object_id,
        request.initial_shared_version,
        wallet_address,
        request.key_name,
        &state.eph_kp,
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("Failed to create PTB: {}", e)))?;

    // Generate ephemeral encryption key and store temporarily.
    let (enc_secret, enc_key, enc_verification_key) = genkey(&mut thread_rng());
    {
        let mut enc_secret_guard = (*ENCRYPTION_SECRET_KEY).write().await;
        *enc_secret_guard = Some(enc_secret);
    }

    // Create FetchKeyRequest.
    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).expect("should not fail")),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    Ok(Json(InitParameterLoadResponse {
        encoded_request: Hex::encode(bcs::to_bytes(&request).expect("should not fail")),
    }))
}

/// Step 3: Complete parameter load. This endpoint accepts the encrypted
/// object and encoded seal responses, which is from after the seal response
/// are fetched by the host using cli. Initialize SEAL_API if decryption is
/// successful and returns OK
pub async fn complete_parameter_load(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<()>, EnclaveError> {
    if SEAL_API_KEY.read().await.is_some() {
        return Err(EnclaveError::GenericError(
            "API key already set".to_string(),
        ));
    }

    // Parse encrypted object.
    let encrypted_object: EncryptedObject = bcs::from_bytes(
        &Hex::decode(&request.encrypted_object)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid hex encoding: {}", e)))?,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to parse encrypted object: {}", e)))?;

    // Parse seal responses.
    let seal_responses: Vec<FetchKeyResponse> = bcs::from_bytes(
        &Hex::decode(&request.seal_responses)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid hex encoding: {}", e)))?,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to parse seal responses: {}", e)))?;

    // Parse public keys from config.
    let pks: Vec<IBEPublicKey> = SEAL_CONFIG
        .public_keys
        .iter()
        .map(
            |pk_hex| -> Result<IBEPublicKey, Box<dyn std::error::Error>> {
                let bytes =
                    Hex::decode(pk_hex).map_err(|e| format!("Invalid public key hex: {}", e))?;
                let pk = IBEPublicKey::from_byte_array(
                    &bytes.try_into().map_err(|_| "Invalid public key length")?,
                )?;
                Ok(pk)
            },
        )
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| EnclaveError::GenericError(format!("Failed to parse public keys: {}", e)))?;

    // Load encryption secret key from temp storage.
    let enc_secret_guard = (*ENCRYPTION_SECRET_KEY).read().await;
    let enc_secret = enc_secret_guard.as_ref().ok_or_else(|| {
        EnclaveError::GenericError("Encryption secret key not found in cache".to_string())
    })?;

    // Decrypt each key using encryption secret key and verify them using id.
    // todo: handle multiple keys.
    let mut all_keys = HashMap::new();
    for (i, seal_response) in seal_responses.iter().enumerate() {
        let service_id = encrypted_object.services[i].0;
        let public_key = pks[i];
        let user_secret_key =
            elgamal_decrypt(enc_secret, &seal_response.decryption_keys[0].encrypted_key);
        ibe_verify_user_secret_key(
            &user_secret_key,
            &seal_response.decryption_keys[0].id,
            &public_key,
        )
        .map_err(|e| {
            EnclaveError::GenericError(format!("Failed to verify user secret key: {}", e))
        })?;
        all_keys.insert(service_id, user_secret_key);
    }

    // Decrypt the encrypted object using the user secret keys.
    let secret = seal_decrypt(
        &encrypted_object,
        &IBEUserSecretKeys::BonehFranklinBLS12381(all_keys),
        Some(&IBEPublicKeys::BonehFranklinBLS12381(pks)),
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt: {}", e)))?;
    // todo: un-assume its a string
    let secret_str = String::from_utf8(secret.clone()).expect("should not fail");

    // Initialize SEAL_API_KEY.
    let mut api_key_guard = (*SEAL_API_KEY).write().await;
    *api_key_guard = Some(secret_str);

    Ok(Json(()))
}

/// Create a PTB with key id, the enclave shared object and the signature.
async fn create_ptb(
    package_id: ObjectID,
    enclave_object_id: ObjectID,
    initial_shared_version: u64,
    wallet_address: Address,
    key_name: String,
    eph_kp: &Ed25519KeyPair,
) -> Result<ProgrammableTransaction, Box<dyn std::error::Error>> {
    // eph_kp signs over ENCLAVE_WALLET address.
    let sig: Ed25519Signature = eph_kp.sign(wallet_address.as_bytes());

    let inputs = vec![
        // Input 0: id arg
        Input::Pure {
            value: bcs::to_bytes(key_name.as_bytes())?,
        },
        // Input 1: enclave arg (shared object)
        Input::Shared {
            object_id: enclave_object_id,
            initial_shared_version,
            mutable: false,
        },
        // Input 2: signature arg
        Input::Pure {
            value: bcs::to_bytes(&sig.as_bytes())?,
        },
    ];

    // Create the MoveCall command
    let move_call = MoveCall {
        package: package_id,
        module: Identifier::new("seal_policy")?,
        function: Identifier::new("seal_approve")?,
        type_arguments: vec![TypeTag::from_str(&format!(
            "{}::weather::WEATHER",
            package_id
        ))?],
        arguments: vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)],
    };

    let ptb = ProgrammableTransaction {
        inputs,
        commands: vec![Command::MoveCall(move_call)],
    };

    Ok(ptb)
}
