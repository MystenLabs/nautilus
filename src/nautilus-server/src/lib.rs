// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use serde_json::json;

#[cfg(feature = "gcp-verify-example")]
use std::collections::HashMap;
#[cfg(feature = "gcp-verify-example")]
use std::sync::Arc;
#[cfg(feature = "gcp-verify-example")]
use tokio::sync::RwLock;

mod apps {
    #[cfg(feature = "twitter-example")]
    #[path = "twitter-example/mod.rs"]
    pub mod twitter_example;

    #[cfg(feature = "weather-example")]
    #[path = "weather-example/mod.rs"]
    pub mod weather_example;

    #[cfg(feature = "gcp-verify-example")]
    #[path = "gcp-verify-example/mod.rs"]
    pub mod gcp_verify_example;
}

pub mod app {
    #[cfg(feature = "twitter-example")]
    pub use crate::apps::twitter_example::*;

    #[cfg(feature = "weather-example")]
    pub use crate::apps::weather_example::*;

    #[cfg(feature = "gcp-verify-example")]
    pub use crate::apps::gcp_verify_example::*;
}

pub mod common;

/// JWKS key structure for JWT verification
#[cfg(feature = "gcp-verify-example")]
#[derive(Debug, Clone)]
pub struct JwksKey {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    pub use_: Option<String>,
    pub n: String,
    pub e: String,
}

/// App state, at minimum needs to maintain the ephemeral keypair.  
pub struct AppState {
    /// Ephemeral keypair on boot
    pub eph_kp: Ed25519KeyPair,
    /// API key when querying api.weatherapi.com
    pub api_key: String,
    /// JWKS cache for JWT verification (only for gcp-verify-example)
    #[cfg(feature = "gcp-verify-example")]
    #[allow(clippy::type_complexity)]
    pub jwks_cache: Option<Arc<RwLock<(HashMap<String, JwksKey>, u64)>>>,
}

/// Implement IntoResponse for EnclaveError.
impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            EnclaveError::GenericError(e) => (StatusCode::BAD_REQUEST, e),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

/// Enclave errors enum.
#[derive(Debug)]
pub enum EnclaveError {
    GenericError(String),
}
