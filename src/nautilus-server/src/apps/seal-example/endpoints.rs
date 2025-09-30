// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::traits::{KeyPair, Signer};
use rand::thread_rng;
use seal_sdk::types::{FetchKeyRequest, KeyId};
use seal_sdk::{
    genkey, seal_decrypt_all_objects, signed_message, signed_request, Certificate, ElGamalSecretKey,
};
use sui_sdk_types::{
    Argument, Command, Identifier, Input, MoveCall, ObjectId as ObjectID, PersonalMessage,
    ProgrammableTransaction, TypeTag,
};
use tokio::sync::RwLock;

use super::types::*;
use crate::{AppState, EnclaveError};

lazy_static::lazy_static! {
    /// Configuration for Seal key servers, containing package
    /// IDs, key server object IDs and public keys are hardcoded
    /// here so they can be used to verify fetch key responses.
    pub static ref SEAL_CONFIG: SealConfig = {
        let config_str = include_str!("seal_config.yaml");
        serde_yaml::from_str(config_str)
            .expect("Failed to parse seal_config.yaml")
    };
    /// Encryption secret key generated initialized on startup.
    pub static ref ENCRYPTION_KEYS: (ElGamalSecretKey, seal_sdk::types::ElGamalPublicKey, seal_sdk::types::ElgamalVerificationKey) = {
        genkey(&mut thread_rng())
    };

    /// Secret plaintext decrypted and set in enclave here when
    /// /complete_parameter_load finishes. This is the weather
    /// API key in this example, change it for your application.
    pub static ref SEAL_API_KEY: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
}

/// This endpoint takes an enclave obj id with initial shared version
/// and a list of key identities. It initializes the session key and
/// uses state's ephemeral key to sign the personal message. Returns
/// a Hex encoded BCS serialized FetchKeyRequest containing the certificate
/// and the desired ptb for seal_approve. This is the first step for
/// the bootstrap phase.
pub async fn init_parameter_load(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitParameterLoadRequest>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    if SEAL_API_KEY.read().await.is_some() {
        return Err(EnclaveError::GenericError(
            "API key already set".to_string(),
        ));
    }
    // Generate the session and create certificate.
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

    // Convert fastcrypto keypair to sui-crypto for signing.
    let sui_private_key = {
        let priv_key_bytes = state.eph_kp.as_ref();
        let key_bytes: [u8; 32] = priv_key_bytes
            .try_into()
            .expect("Invalid private key length");
        sui_crypto::ed25519::Ed25519PrivateKey::new(key_bytes)
    };

    // Sign personal message.
    let signature = {
        use sui_crypto::SuiSigner;
        sui_private_key
            .sign_personal_message(&PersonalMessage(message.as_bytes().into()))
            .map_err(|e| {
                EnclaveError::GenericError(format!("Failed to sign personal message: {}", e))
            })?
    };

    // Create certificate with enclave's ephemeral key's address and session vk.
    let certificate = Certificate {
        user: sui_private_key.public_key().to_address(),
        session_vk: session_vk.clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    // Create PTB for seal_approve of package with all key IDs.
    let ptb = create_ptb(
        SEAL_CONFIG.package_id,
        request.enclave_object_id,
        request.initial_shared_version,
        request.ids,
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("Failed to create PTB: {}", e)))?;

    // Load the encryption public key and verification key.
    let (_enc_secret, enc_key, enc_verification_key) = &*ENCRYPTION_KEYS;

    // Create the FetchKeyRequest.
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

/// This endpoint accepts a list of encrypted objects and encoded seal responses,
/// It parses the seal responses for all IDs and decrypt all encrypted objects
/// with the encryption secret key. If all encrypted objects are decrypted, initialize
/// the SEAL_API_KEY with the first secret and return the dummy secrets in the response.
/// Remove dummy secrets for your app. This is done after the Seal responses are fetched
/// and to complete the bootstrap phase.
pub async fn complete_parameter_load(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    if SEAL_API_KEY.read().await.is_some() {
        return Err(EnclaveError::GenericError(
            "API key already set".to_string(),
        ));
    }

    // Load the encryption secret key and try decrypting all encrypted objects.
    let (enc_secret, _enc_key, _enc_verification_key) = &*ENCRYPTION_KEYS;
    let decrypted_results = seal_decrypt_all_objects(
        enc_secret,
        &request.seal_responses,
        &request.encrypted_objects,
        &SEAL_CONFIG.server_pk_map,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt objects: {}", e)))?;

    // The first secret is the weather API key, store it.
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

    // Return the rest of decrypted secrets as an example,
    // remove for your app as needed.
    Ok(Json(CompleteParameterLoadResponse {
        dummy_secrets: decrypted_results[1..].to_vec(),
    }))
}

/// Helper function that creates a PTB with multiple commands for
/// the given IDs and the enclave shared object.
async fn create_ptb(
    package_id: ObjectID,
    enclave_object_id: ObjectID,
    initial_shared_version: u64,
    ids: Vec<KeyId>,
) -> Result<ProgrammableTransaction, Box<dyn std::error::Error>> {
    let mut inputs = vec![];
    let mut commands = vec![];

    // Create inputs for all IDs.
    for id in ids.iter() {
        inputs.push(Input::Pure {
            value: bcs::to_bytes(id)?,
        });
    }

    // Add the shared enclave object as the last input.
    let enclave_input_idx = inputs.len();
    inputs.push(Input::Shared {
        object_id: enclave_object_id,
        initial_shared_version,
        mutable: false,
    });

    // Create multiple commands with each one calling seal_approve
    // with a different ID and the shared enclave object.
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
    Ok(ProgrammableTransaction { inputs, commands })
}
