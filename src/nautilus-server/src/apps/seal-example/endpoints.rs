// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::apps::seal_example::{ENCRYPTION_SECRET_KEY, SEAL_API_KEY, SEAL_CONFIG};
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
    let package_id = ObjectID::from_str(&SEAL_CONFIG.package_id)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid package ID in config: {}", e)))?;
    // Generate session and create certificate.
    let session = Ed25519KeyPair::generate(&mut thread_rng());
    let session_vk = session.public();
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {}", e)))?
        .as_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(package_id.to_string(), session_vk, creation_time, ttl_min);

    // Convert fastcrypto keypair to sui-crypto for signing
    let sui_private_key = {
        let priv_key_bytes = state.eph_kp.as_ref();
        let key_bytes: [u8; 32] = priv_key_bytes
            .try_into()
            .map_err(|_| EnclaveError::GenericError("Invalid private key length".to_string()))?;
        sui_crypto::ed25519::Ed25519PrivateKey::new(key_bytes)
    };

    // Get wallet address from the sui private key
    let wallet_address = sui_private_key.public_key().to_address();

    let pk = state.eph_kp.public();
    println!("enclave_pk: {}", Hex::encode(pk.as_ref()));
    println!("wallet_address: {}", wallet_address);

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
        user: wallet_address,
        session_vk: session_vk.clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    // Parse all IDs
    let ids: Vec<Vec<u8>> = request
        .ids
        .iter()
        .map(|id_str| {
            Hex::decode(id_str).map_err(|e| {
                EnclaveError::GenericError(format!("Invalid hex encoding for ID: {}", e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Create PTB for seal_approve of package with multiple IDs
    let ptb = create_ptb(
        package_id,
        enclave_object_id,
        request.initial_shared_version,
        ids,
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
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    if SEAL_API_KEY.read().await.is_some() {
        return Err(EnclaveError::GenericError(
            "API key already set".to_string(),
        ));
    }

    // Parse encrypted objects.
    let encrypted_objects: Vec<EncryptedObject> = request
        .encrypted_objects
        .iter()
        .map(|obj_str| {
            let bytes = Hex::decode(obj_str)
                .map_err(|e| EnclaveError::GenericError(format!("Invalid hex encoding: {}", e)))?;
            bcs::from_bytes::<EncryptedObject>(&bytes).map_err(|e| {
                EnclaveError::GenericError(format!("Failed to parse encrypted object: {}", e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Parse seal responses as Vec<(server obj id, FetchKeyResponse)>.
    let seal_responses: Vec<(ObjectID, FetchKeyResponse)> = bcs::from_bytes(
        &Hex::decode(&request.seal_responses)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid hex encoding: {}", e)))?,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to parse seal responses: {}", e)))?;

    // service obj id -> pk
    let mut server_pk_map: HashMap<ObjectID, IBEPublicKey> = HashMap::new();
    for (server_id_str, pk_hex) in SEAL_CONFIG.key_servers.iter().zip(SEAL_CONFIG.public_keys.iter()) {
        let server_id = ObjectID::from_str(server_id_str)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid server object ID {}: {}", server_id_str, e)))?;

        let pk_bytes = Hex::decode(pk_hex)
            .map_err(|e| EnclaveError::GenericError(format!("Invalid public key hex: {}", e)))?;
        let pk = IBEPublicKey::from_byte_array(
            &pk_bytes.try_into().map_err(|_| EnclaveError::GenericError("Invalid public key length".to_string()))?
        ).map_err(|e| EnclaveError::GenericError(format!("Failed to parse public key: {}", e)))?;

        server_pk_map.insert(server_id, pk);
    }

    // Load encryption secret key from temporary storage.
    let enc_secret_guard = (*ENCRYPTION_SECRET_KEY).read().await;
    let enc_secret = enc_secret_guard.as_ref().ok_or_else(|| {
        EnclaveError::GenericError("Encryption secret key not found in cache".to_string())
    })?;

    // Build a hashmap of all decrypted and verified keys
    // Map from decryption_key.id to a map of server_id -> user_secret_key
    // The user_secret_key is the result of elgamal_decrypt which we'll store directly
    type UserSecretKey = fastcrypto::groups::bls12381::G1Element;
    let mut cached_keys: HashMap<Vec<u8>, HashMap<ObjectID, UserSecretKey>> = HashMap::new();

    // Process all seal responses and build the key map
    for (server_id, seal_response) in seal_responses.iter() {
        // Get server's pk
        let public_key = server_pk_map.get(&server_id).ok_or_else(|| {
            EnclaveError::GenericError(format!("No public key configured for server {}", server_id))
        })?;

        for decryption_key in seal_response.decryption_keys.iter() {
            // Decrypt and verify the user secret key
            let user_secret_key = elgamal_decrypt(enc_secret, &decryption_key.encrypted_key);
            ibe_verify_user_secret_key(&user_secret_key, &decryption_key.id, public_key)
                .map_err(|e| {
                    EnclaveError::GenericError(format!("Failed to verify user secret key for server {}: {}", server_id, e))
                })?;

            // build the map from id -> map (server_obj_id -> usk)
            cached_keys.entry(decryption_key.id.clone()).or_insert_with(HashMap::new).insert(server_id.clone(), user_secret_key);
        }
    }

    // decrypt each encrypted object
    let mut decrypted_results = Vec::new();
    for encrypted_object in encrypted_objects.iter() {
        // look up keys for the given id of the encrypted object
        let keys_for_id = cached_keys.get(&encrypted_object.id).ok_or_else(|| {
            EnclaveError::GenericError(format!("No keys cached for object {:?}", encrypted_object.id))
        })?;
        // build the hash map of usks (server_id -> usk)
        // build the list of pks in the order of server_ids.
        let mut pks = Vec::new();
        let mut usks = HashMap::new();
        for (server_id, user_secret_key) in keys_for_id.iter() {
            usks.insert(server_id.clone(), user_secret_key.clone());
            let pk = server_pk_map.get(server_id).ok_or_else(|| {
                EnclaveError::GenericError(format!("No public key configured for server {}", server_id))
            })?;
            pks.push(pk.clone());
        }
        let secret = seal_decrypt(
            encrypted_object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(usks),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(pks.clone())),
        )
        .map_err(|e| {
            EnclaveError::GenericError(format!("Failed to decrypt object: {}", e))
        })?;

        decrypted_results.push(secret);
    }

    println!("decrypted_results: {:?}", decrypted_results.len());

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

    // Return all secrets in response as dummy secrets. remove if need for your app.
    let dummy_secrets = decrypted_results.iter()
        .map(|secret| String::from_utf8_lossy(secret).to_string())
        .collect::<Vec<_>>();

    Ok(Json(CompleteParameterLoadResponse { dummy_secrets }))
}

/// Create a PTB with multiple key IDs and the enclave shared object.
async fn create_ptb(
    package_id: ObjectID,
    enclave_object_id: ObjectID,
    initial_shared_version: u64,
    ids: Vec<Vec<u8>>,
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
