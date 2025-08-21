// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use serde_json::json;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod app;
pub mod common;

#[derive(Debug, Clone)]
pub struct JwksKey {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    pub use_: Option<String>,
    pub n: String,
    pub e: String,
}

pub struct AppState {
    pub eph_kp: Ed25519KeyPair,
    pub jwks_cache: Arc<RwLock<(HashMap<String, JwksKey>, u64)>>,
}

#[derive(Debug)]
pub enum EnclaveError {
    GenericError(String),
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnclaveError::GenericError(msg) => write!(f, "Enclave error: {}", msg),
        }
    }
}

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
