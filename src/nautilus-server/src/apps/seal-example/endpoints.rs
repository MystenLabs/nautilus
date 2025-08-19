// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::apps::seal_example::{ENC_SECRET, SEAL_API_KEY, SEAL_CONFIG, SEAL_WALLET};
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
use seal_sdk::IBEPublicKey;
use seal_sdk::IBEUserSecretKeys;
use seal_sdk::{seal_decrypt, EncryptedObject, IBEPublicKeys};
use seal_sdk::{signed_message, signed_request};
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
use tracing::info;
use seal_sdk::Certificate;
/// Init parameter load endpoint - Step 1 of Seal key retrieval
/// This endpoint is called by the host to get the request body for fetching keys
pub async fn init_parameter_load(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitParameterLoadRequest>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    // Generate a unique session ID
    let session_id = uuid::Uuid::new_v4().to_string();
    info!("Initializing parameter load for session: {}", session_id);

    let wallet_guard = SEAL_WALLET.read().await;
    let wallet_address = wallet_guard.public_key().to_address();

    // Parse package ID from config
    let package_id = ObjectID::from_str(&request.package_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid package ID in config: {}", e)))?;

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
        package_id.to_string(),
        session.public(),
        creation_time,
        ttl_min,
    );

    let signature = wallet_guard
        .sign_personal_message(&PersonalMessage(message.as_bytes().into()))
        .unwrap();

    let certificate = Certificate {
        user: wallet_address,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    let enclave_object_id = ObjectID::from_str(&request.enclave_object_id).map_err(|e| {
        EnclaveError::GenericError(format!("Invalid enclave object ID in request: {}", e))
    })?;

    let package_id = ObjectID::from_str(&request.package_id).map_err(|e| {
        EnclaveError::GenericError(format!("Invalid package ID in request: {}", e))
    })?;
    println!("certificate.user: {:?}", certificate.user);
    let ptb = create_ptb(
        package_id,
        enclave_object_id,
        request.initial_shared_version,
        wallet_address,
        &state.eph_kp,
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("Failed to create PTB: {}", e)))?;
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
        let object_id = ObjectID::new(response.decryption_keys[0].id.clone().try_into().unwrap());
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
                let pk = IBEPublicKey::from_byte_array(
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

async fn create_ptb(
    package_id: ObjectID,
    enclave_object_id: ObjectID,
    initial_shared_version: u64,
    wallet_address: Address,
    eph_kp: &Ed25519KeyPair,
) -> Result<ProgrammableTransaction, Box<dyn std::error::Error>> {
    println!("package_id: {:?}", package_id);
    println!("enclave_object_id: {:?}", enclave_object_id);

    let old_signing_payload = bcs::to_bytes(&wallet_address).expect("should not fail");
    let signing_payload = wallet_address.to_bytes();
    let sig: Ed25519Signature = eph_kp.sign(&signing_payload);

    println!("sig: {:?}", Hex::encode(sig.as_bytes()));
    println!("eph pk: {:?}", Hex::encode(eph_kp.public().as_bytes()));
    println!("wallet address: {:?}", Hex::encode(wallet_address.as_bytes()));
    println!("signing_payload: {:?}", Hex::encode(signing_payload));
    println!("old_signing_payload: {:?}", Hex::encode(old_signing_payload));
    // Create inputs
    let inputs = vec![
        // Input 0: id arg
        Input::Pure {
            value: bcs::to_bytes("weather_api_key".as_bytes())?,
        },
        // Input 1: enclave arg (shared object)
        Input::Shared {
            object_id: enclave_object_id, // ObjectID is an alias for Address
            initial_shared_version,
            mutable: false,
        },
        // Input 2: signature arg
        Input::Pure {
            value: sig.as_bytes().to_vec(),
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
        arguments: vec![
            Argument::Input(0), // id arg
            Argument::Input(1), // enclave arg
            Argument::Input(2), // signature arg
        ],
    };

    // Create the ProgrammableTransaction
    let ptb = ProgrammableTransaction {
        inputs,
        commands: vec![Command::MoveCall(move_call)],
    };

    Ok(ptb)
}
