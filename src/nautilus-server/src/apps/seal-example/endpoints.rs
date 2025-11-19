// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
use rand::thread_rng;
use seal_sdk::types::{ElGamalPublicKey, ElgamalVerificationKey, FetchKeyRequest, KeyId};
use seal_sdk::{
    decrypt_seal_responses, genkey, seal_decrypt_object, signed_message, signed_request,
    Certificate, ElGamalSecretKey,
};
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, PersonalMessage,
    ProgrammableTransaction,
};
use sui_crypto::ed25519::Ed25519PrivateKey;
use tokio::sync::RwLock;

use super::types::*;
use crate::{AppState, EnclaveError};

lazy_static::lazy_static! {
    /// Configuration for Seal key servers, containing package IDs, key server object IDs and
    /// public keys are hardcoded here so they can be used to verify fetch key responses.
    pub static ref SEAL_CONFIG: SealConfig = {
        let config_str = include_str!("seal_config.yaml");
        serde_yaml::from_str(config_str)
            .expect("Failed to parse seal_config.yaml")
    };

    /// Encryption secret key generated initialized on startup.
    pub static ref ENCRYPTION_KEYS: (ElGamalSecretKey, ElGamalPublicKey, ElgamalVerificationKey) = {
        genkey(&mut thread_rng())
    };

    /// Enclave wallet private key bytes, used to create signature for seal_approve PTB.
    pub static ref ENCLAVE_WALLET_BYTES: [u8; 32] = {
        let keypair = Ed25519KeyPair::generate(&mut thread_rng());
        let private_key = keypair.private();
        let bytes = private_key.as_ref();
        bytes.try_into().expect("Invalid private key length")
    };

    /// Cached Seal keys for decrypting encrypted objects.
    pub static ref CACHED_KEYS: RwLock<HashMap<Vec<u8>, HashMap<Address, G1Element>>> = RwLock::new(HashMap::new());

    /// Secret plaintext decrypted and set in enclave here when /provision_weather_api_key is
    /// called. This is the weather API key in this example, change it for your application.
    pub static ref SEAL_API_KEY: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
}

/// This endpoint takes an enclave object id with initial shared version and a key identity. It
/// initializes the session key and uses the enclave wallet to sign the personal message. Returns a
/// Hex encoded BCS serialized FetchKeyRequest containing the certificate and the desired PTB for
/// seal_approve. This is the first step for the key load phase.
pub async fn init_seal_key_load(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitKeyLoadRequest>,
) -> Result<Json<InitKeyLoadResponse>, EnclaveError> {
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
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {e}")))?
        .as_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(
        SEAL_CONFIG.package_id.to_string(),
        session_vk,
        creation_time,
        ttl_min,
    );

    // Load enclave wallet and convert to sui-crypto for signing.
    let sui_wallet = Ed25519PrivateKey::new(*ENCLAVE_WALLET_BYTES);

    // Sign personal message.
    let signature = {
        use sui_crypto::SuiSigner;
        sui_wallet
            .sign_personal_message(&PersonalMessage(message.as_bytes().into()))
            .map_err(|e| {
                EnclaveError::GenericError(format!("Failed to sign personal message: {e}"))
            })?
    };

    // Create certificate with wallet's address and session vk.
    let certificate = Certificate {
        user: sui_wallet.public_key().derive_address(),
        session_vk: session_vk.clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    // Create PTB for seal_approve of package with key ID and enclave public key.
    let enclave_pk = state.eph_kp.public().as_bytes().to_vec();
    let ptb = create_ptb(
        SEAL_CONFIG.package_id,
        request.enclave_object_id,
        request.initial_shared_version,
        request.id,
        enclave_pk,
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("Failed to create PTB: {e}")))?;

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

    Ok(Json(InitKeyLoadResponse {
        encoded_request: Hex::encode(bcs::to_bytes(&request).expect("should not fail")),
    }))
}

/// This endpoint accepts encoded seal responses and decrypts the keys from all servers. The
/// decrypted keys are cached in CACHED_KEYS for later use when decrypting objects on demand. This
/// is done after the Seal responses are fetched to complete the key load phase.
pub async fn complete_seal_key_load(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CompleteKeyLoadRequest>,
) -> Result<Json<()>, EnclaveError> {
    // Decrypt ALL keys from ALL servers and cache them
    let (enc_secret, _enc_key, _enc_verification_key) = &*ENCRYPTION_KEYS;
    let seal_keys = decrypt_seal_responses(
        enc_secret,
        &request.seal_responses,
        &SEAL_CONFIG.server_pk_map,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt seal responses: {e}")))?;

    // Cache the keys for later use.
    CACHED_KEYS.write().await.extend(seal_keys);

    Ok(Json(()))
}

/// This endpoint decrypts a weather API key using cached keys from the complete_key_load phase.
/// It demonstrates the on-demand decryption pattern where objects can be decrypted as they arrive
/// without needing to fetch keys again. Replace this with your own application specific endpoint.
pub async fn provision_weather_api_key(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<ProvisionWeatherApiRequest>,
) -> Result<Json<()>, EnclaveError> {
    // Decrypt the encrypted object using cached keys.
    let cached_keys_read = CACHED_KEYS.read().await;
    let api_key_bytes = seal_decrypt_object(
        &request.encrypted_object,
        &cached_keys_read,
        &SEAL_CONFIG.server_pk_map,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt weather API key: {e}")))?;

    // Convert decrypted bytes to UTF-8 string.
    let api_key_str = String::from_utf8(api_key_bytes)
        .map_err(|e| EnclaveError::GenericError(format!("Invalid UTF-8 in API key: {e}")))?;

    // Store the API key so it can be used to server request for /process_data.
    let mut api_key_guard = (*SEAL_API_KEY).write().await;
    *api_key_guard = Some(api_key_str);

    Ok(Json(()))
}

/// Helper function that creates a PTB with a single seal_approve command for the given ID and the
/// enclave shared object. Creates a signature using the enclave wallet signing the enclave's public
/// key.
async fn create_ptb(
    package_id: Address,
    enclave_object_id: Address,
    initial_shared_version: u64,
    id: KeyId,
    enclave_pk: Vec<u8>,
) -> Result<ProgrammableTransaction, Box<dyn std::error::Error>> {
    let mut inputs = vec![];
    let mut commands = vec![];

    // Get the enclave wallet and sign over the enclave public key.
    let wallet = Ed25519KeyPair::from_bytes(&*ENCLAVE_WALLET_BYTES)
        .expect("Failed to reconstruct keypair from bytes");
    let signature = wallet.sign(&enclave_pk).as_bytes().to_vec();
    let wallet_pk = wallet.public().as_bytes().to_vec();

    println!("Enclave PK: {}", Hex::encode(&enclave_pk));
    println!("Signature: {}", Hex::encode(&signature));
    println!("Wallet PK: {}", Hex::encode(&wallet_pk));
    // Input 0: ID.
    inputs.push(Input::Pure {
        value: bcs::to_bytes(&id)?,
    });

    // Input 1: signature.
    inputs.push(Input::Pure {
        value: bcs::to_bytes(&signature)?,
    });

    // Input 2: wallet_pk.
    inputs.push(Input::Pure {
        value: bcs::to_bytes(&wallet_pk)?,
    });

    // Input 3: shared enclave object.
    inputs.push(Input::Shared {
        object_id: enclave_object_id,
        initial_shared_version,
        mutable: false,
    });

    // Create seal_approve Move call.
    let move_call = MoveCall {
        package: package_id,
        module: Identifier::new("seal_policy")?,
        function: Identifier::new("seal_approve")?,
        type_arguments: vec![],
        arguments: vec![
            Argument::Input(0), // id
            Argument::Input(1), // signature
            Argument::Input(2), // wallet_pk
            Argument::Input(3), // enclave object
        ],
    };
    commands.push(Command::MoveCall(move_call));

    Ok(ProgrammableTransaction { inputs, commands })
}
