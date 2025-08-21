// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::AppState;
use crate::EnclaveError;
use axum::{extract::State, Json};
use fastcrypto::traits::Signer;
use fastcrypto::{encoding::Encoding, traits::ToFromBytes};
use fastcrypto::{encoding::Hex, traits::KeyPair as FcKeyPair};
use nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use nsm_api::driver;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use fastcrypto::ed25519::Ed25519KeyPair;

#[derive(Debug, Serialize, Deserialize)]
pub struct IntentMessage<T: Serialize> {
    pub intent: IntentScope,
    pub timestamp_ms: u64,
    pub data: T,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum IntentScope {
    JwtVerification = 0,
}

impl<T: Serialize + Debug> IntentMessage<T> {
    pub fn new(data: T, timestamp_ms: u64, intent: IntentScope) -> Self {
        Self {
            data,
            timestamp_ms,
            intent,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProcessedDataResponse<T> {
    pub response: T,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessDataRequest<T> {
    pub payload: T,
}

pub fn to_signed_response<T: Serialize + Clone>(
    kp: &Ed25519KeyPair,
    payload: T,
    timestamp_ms: u64,
    intent: IntentScope,
) -> ProcessedDataResponse<IntentMessage<T>> {
    let intent_msg = IntentMessage {
        intent,
        timestamp_ms,
        data: payload.clone(),
    };

    let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
    let sig = kp.sign(&signing_payload);
    ProcessedDataResponse {
        response: intent_msg,
        signature: Hex::encode(sig),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAttestationResponse {
    pub attestation: String,
}

pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GetAttestationResponse>, EnclaveError> {
    info!("get attestation called");

    let pk = state.eph_kp.public();
    let fd = driver::nsm_init();

    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(ByteBuf::from(pk.as_bytes().to_vec())),
    };

    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            Ok(Json(GetAttestationResponse {
                attestation: Hex::encode(document),
            }))
        }
        _ => {
            driver::nsm_exit(fd);
            Err(EnclaveError::GenericError(
                "unexpected response".to_string(),
            ))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub pk: String,
    pub endpoints_status: HashMap<String, bool>,
}

pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthCheckResponse>, EnclaveError> {
    let pk = state.eph_kp.public();

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| EnclaveError::GenericError(format!("Failed to create HTTP client: {}", e)))?;

    let endpoints_status = match std::fs::read_to_string("allowed_endpoints.yaml") {
        Ok(yaml_content) => {
            match serde_yaml::from_str::<serde_yaml::Value>(&yaml_content) {
                Ok(yaml_value) => {
                    let mut status_map = HashMap::new();

                    if let Some(endpoints) =
                        yaml_value.get("endpoints").and_then(|e| e.as_sequence())
                    {
                        for endpoint in endpoints {
                            if let Some(endpoint_str) = endpoint.as_str() {
                                let url = if endpoint_str.contains(".amazonaws.com") {
                                    format!("https://{}/ping", endpoint_str)
                                } else {
                                    format!("https://{}", endpoint_str)
                                };

                                let is_reachable = match client.get(&url).send().await {
                                    Ok(response) => {
                                        if endpoint_str.contains(".amazonaws.com") {
                                            // For AWS endpoints, check if response body contains "healthy"
                                            match response.text().await {
                                                Ok(body) => body.to_lowercase().contains("healthy"),
                                                Err(e) => {
                                                    info!(
                                                        "Failed to read response body from {}: {}",
                                                        endpoint_str, e
                                                    );
                                                    false
                                                }
                                            }
                                        } else {
                                            response.status().is_success()
                                        }
                                    }
                                    Err(e) => {
                                        info!("Failed to connect to {}: {}", endpoint_str, e);
                                        false
                                    }
                                };

                                status_map.insert(endpoint_str.to_string(), is_reachable);
                                info!(
                                    "Checked endpoint {}: reachable = {}",
                                    endpoint_str, is_reachable
                                );
                            }
                        }
                    }

                    status_map
                }
                Err(e) => {
                    info!("Failed to parse YAML: {}", e);
                    HashMap::new()
                }
            }
        }
        Err(e) => {
            info!("Failed to read allowed_endpoints.yaml: {}", e);
            HashMap::new()
        }
    };

    Ok(Json(HealthCheckResponse {
        pk: Hex::encode(pk.as_bytes()),
        endpoints_status,
    }))
}
