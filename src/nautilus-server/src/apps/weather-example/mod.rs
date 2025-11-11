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
/// ====
/// Core Nautilus server logic, replace it with your own
/// relavant structs and process_data endpoint.
/// ====
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

pub async fn process_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<WeatherRequest>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<WeatherResponse>>>, EnclaveError> {
    let url = format!(
        "https://api.weatherapi.com/v1/current.json?key={}&q={}",
        state.api_key, request.payload.location
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
