// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod endpoints;
pub mod types;

pub use endpoints::{complete_seal_key_load, init_seal_key_load, provision_weather_api_key};
pub use types::*;

use crate::app::endpoints::SEAL_API_KEY;
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
    // API key loaded from what was set during bootstrap.
    let api_key_guard = SEAL_API_KEY.read().await;
    let api_key = api_key_guard.as_ref().ok_or_else(|| {
        EnclaveError::GenericError(
            "API key not initialized. Please complete parameter load first.".to_string(),
        )
    })?;

    let url = format!(
        "https://api.weatherapi.com/v1/current.json?key={}&q={}",
        api_key, request.payload.location
    );
    let response = reqwest::get(url.clone())
        .await
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get weather response: {e}")))?;
    let json = response.json::<Value>().await.map_err(|e| {
        EnclaveError::GenericError(format!("Failed to parse weather response: {e}"))
    })?;
    let location = json["location"]["name"].as_str().unwrap_or("Unknown");
    let temperature = json["current"]["temp_c"].as_f64().unwrap_or(0.0) as u64;
    let last_updated_epoch = json["current"]["last_updated_epoch"].as_u64().unwrap_or(0);
    let last_updated_timestamp_ms = last_updated_epoch * 1000_u64;
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get current timestamp: {e}")))?
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
use axum::{
    routing::{get, post},
    Router,
};
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

/// Spawn a separate server on localhost:3001 for host-only bootstrap access.
pub async fn spawn_host_init_server(state: Arc<AppState>) -> Result<(), EnclaveError> {
    let host_app = Router::new()
        .route("/ping", get(ping))
        .route("/admin/init_seal_key_load", post(init_seal_key_load))
        .route(
            "/admin/complete_seal_key_load",
            post(complete_seal_key_load),
        )
        .route(
            "/admin/provision_weather_api_key",
            post(provision_weather_api_key),
        )
        .with_state(state);

    let host_listener = TcpListener::bind("0.0.0.0:3001")
        .await
        .map_err(|e| EnclaveError::GenericError(format!("Failed to bind host init server: {e}")))?;

    info!(
        "Host-only init server listening on {}",
        host_listener.local_addr().unwrap()
    );

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
