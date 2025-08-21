// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use nautilus_server::app::{start_jwks_refresh_task, update_jwks_cache, verify_google_jwt};
use nautilus_server::common::{get_attestation, health_check};
use nautilus_server::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());

    let state = Arc::new(AppState {
        eph_kp,
        jwks_cache: Arc::new(RwLock::new((HashMap::new(), 0))),
    });

    if let Err(e) = update_jwks_cache(state.clone()).await {
        eprintln!("Warning: Failed to fetch initial JWKS: {:?}", e);
    }

    start_jwks_refresh_task(state.clone());

    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(ping))
        .route("/get_attestation", get(get_attestation))
        .route("/verify_google_jwt", post(verify_google_jwt))
        .route("/health_check", get(health_check))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

async fn ping() -> &'static str {
    "Pong!"
}
