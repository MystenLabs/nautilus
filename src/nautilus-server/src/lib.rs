// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use serde_json::json;
use std::fmt;

pub mod examples {
    #[cfg(feature = "twitter")]
    pub mod twitter;

    #[cfg(feature = "weather")]
    pub mod weather;

    #[cfg(feature = "seal-example")]
    pub mod seal_example;
}

pub mod app {
    #[cfg(feature = "twitter")]
    pub use crate::examples::twitter::*;

    #[cfg(feature = "weather")]
    pub use crate::examples::weather::{WeatherResponse, WeatherRequest, process_data};

    #[cfg(feature = "seal-example")]
    pub use crate::examples::seal_example::{
        init_parameter_load, complete_parameter_load, ping, spawn_host_init_server,
        PingResponse, seal_sdk, process_data
    };
}

pub mod common;

/// App state, at minimum needs to maintain the ephemeral keypair.  
pub struct AppState {
    /// Ephemeral keypair on boot
    pub eph_kp: Ed25519KeyPair,
    /// API key when querying api.weatherapi.com
    pub api_key: String,
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

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnclaveError::GenericError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for EnclaveError {}
