// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::common::IntentMessage;
use crate::common::{to_signed_response, IntentScope, ProcessDataRequest, ProcessedDataResponse};
use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tracing::info;
use std::sync::RwLock;

// Storage for encrypted secrets
use std::collections::HashMap;
lazy_static::lazy_static! {
    static ref ENCRYPTED_SECRETS: RwLock<HashMap<String, EncryptedObject>> = RwLock::new(HashMap::new());
}

/// Structure to hold the encrypted API key and related data
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedApiKey {
    pub encrypted_object: EncryptedObject,
}

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

/// Inner type T for IntentMessage<T>
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WeatherResponse {
    pub location: String,
    pub temperature: u64,
}

/// Inner type T for ProcessDataRequest<T>
#[derive(Debug, Serialize, Deserialize)]
pub struct WeatherRequest {
    pub location: String,
}

/// Request to set an encrypted secret
#[derive(Debug, Serialize, Deserialize)]
pub struct SetEncryptedSecretRequest {
    pub key: String,  // The name/key for this secret (e.g., "API_KEY")
    pub encrypted_object: EncryptedObject,
}

/// Response from setting encrypted secret
#[derive(Debug, Serialize, Deserialize)]
pub struct SetEncryptedSecretResponse {
    pub success: bool,
    pub message: String,
}

pub async fn process_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<WeatherRequest>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<WeatherResponse>>>, EnclaveError> {
    // Check if we have an encrypted API key stored
    let api_key = {
        let secrets = ENCRYPTED_SECRETS.read().map_err(|e| {
            EnclaveError::GenericError(format!("Failed to read encrypted secrets: {}", e))
        })?;
        
        if let Some(_encrypted_obj) = secrets.get("API_KEY") {
            // TODO: Decrypt the API key here once you provide the decryption method
            // For now, fall back to the state's api_key
            info!("Using encrypted API key (decryption not yet implemented)");
            state.api_key.clone()
        } else {
            info!("No encrypted API key found, using default from environment");
            state.api_key.clone()
        }
    };
    
    let url = format!(
        "https://api.weatherapi.com/v1/current.json?key={}&q={}",
        api_key, request.payload.location
    );
    let response = reqwest::get(url.clone()).await.map_err(|e| {
        EnclaveError::GenericError(format!("Failed to get weather response: {}", e))
    })?;
    let json = response.json::<Value>().await.map_err(|e| {
        EnclaveError::GenericError(format!("Failed to parse weather response: {}", e))
    })?;
    let location = json["location"]["name"].as_str().unwrap_or("Unknown");
    let temperature = json["current"]["temp_c"].as_f64().unwrap_or(0.0) as u64;
    let last_updated_epoch = json["current"]["last_updated_epoch"].as_u64().unwrap_or(0);
    let last_updated_timestamp_ms = last_updated_epoch * 1000_u64;
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get current timestamp: {}", e)))?
        .as_millis() as u64;

    // 1 hour in milliseconds = 60 * 60 * 1000 = 3_600_000
    if last_updated_timestamp_ms + 3_600_000 < current_timestamp {
        return Err(EnclaveError::GenericError(
            "Weather API timestamp is too old".to_string(),
        ));
    }

    Ok(Json(to_signed_response(
        &state.eph_kp,
        WeatherResponse {
            location: location.to_string(),
            temperature,
        },
        last_updated_timestamp_ms,
        IntentScope::ProcessData,
    )))
}

/// Host-only init functionality
use axum::{routing::{get, post}, Router};
use tokio::net::TcpListener;

/// Response for the ping endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {
    pub message: String,
}

/// Simple ping handler for host-only access
pub async fn ping() -> Json<PingResponse> {
    info!("Host init ping received");
    Json(PingResponse {
        message: "pong".to_string(),
    })
}

/// Set an encrypted secret
pub async fn set_encrypted_secret(
    Json(request): Json<SetEncryptedSecretRequest>,
) -> Result<Json<SetEncryptedSecretResponse>, EnclaveError> {
    info!("Setting encrypted secret with key: {}", request.key);
    
    // Store the encrypted secret
    let mut storage = ENCRYPTED_SECRETS.write().map_err(|e| {
        EnclaveError::GenericError(format!("Failed to write encrypted secrets: {}", e))
    })?;
    
    storage.insert(request.key.clone(), request.encrypted_object);
    
    Ok(Json(SetEncryptedSecretResponse {
        success: true,
        message: format!("Encrypted secret '{}' stored successfully", request.key),
    }))
}

/// Spawn a separate server on localhost:3001 for host-only init access
pub async fn spawn_host_init_server() -> Result<(), EnclaveError> {
    let host_app = Router::new()
        .route("/init/ping", get(ping))
        .route("/set_encrypted_secret", post(set_encrypted_secret));

    let host_listener = TcpListener::bind("127.0.0.1:3001")
        .await
        .map_err(|e| EnclaveError::GenericError(format!("Failed to bind host init server: {}", e)))?;
    
    info!("Host-only init server listening on {}", host_listener.local_addr().unwrap());
    
    tokio::spawn(async move {
        axum::serve(host_listener, host_app.into_make_service())
            .await
            .expect("Host init server failed");
    });

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::IntentMessage;
    use axum::{extract::State, Json};
    use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};

    #[tokio::test]
    async fn test_process_data() {
        let state = Arc::new(AppState {
            eph_kp: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            api_key: "045a27812dbe456392913223221306".to_string(),
        });
        let signed_weather_response = process_data(
            State(state),
            Json(ProcessDataRequest {
                payload: WeatherRequest {
                    location: "San Francisco".to_string(),
                },
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            signed_weather_response.response.data.location,
            "San Francisco"
        );
    }

    #[test]
    fn test_serde() {
        // test result should be consistent with test_serde in `move/enclave/sources/enclave.move`.
        use fastcrypto::encoding::{Encoding, Hex};
        let payload = WeatherResponse {
            location: "San Francisco".to_string(),
            temperature: 13,
        };
        let timestamp = 1744038900000;
        let intent_msg = IntentMessage::new(payload, timestamp, IntentScope::ProcessData);
        let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
        assert!(
            signing_payload
                == Hex::decode("0020b1d110960100000d53616e204672616e636973636f0d00000000000000")
                    .unwrap()
        );
    }
}