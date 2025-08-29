// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use nautilus_server::common::{get_attestation, health_check};
use nautilus_server::AppState;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[cfg(any(feature = "weather-example", feature = "twitter-example"))]
use nautilus_server::app::process_data;

#[cfg(feature = "gcp-verify-example")]
use nautilus_server::app::{process_data, start_jwks_refresh_task, update_jwks_cache};

#[cfg(feature = "gcp-verify-example")]
use std::collections::HashMap;

#[cfg(feature = "gcp-verify-example")]
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<()> {
    let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());

    let state = {
        #[cfg(any(feature = "weather-example", feature = "twitter-example"))]
        {
            // This value can be stored with secret-manager. To do that, follow the prompt `sh configure_enclave.sh`
            // Answer `y` to `Do you want to use a secret?` and finish.
            // Then uncomment this code instead to fetch from env var API_KEY, which is fetched from secret manager.
            let api_key = std::env::var("API_KEY").expect("API_KEY must be set");
            // let api_key = "045a27812dbe456392913223221306".to_string();

            Arc::new(AppState {
                eph_kp,
                api_key,
                #[cfg(feature = "gcp-verify-example")]
                jwks_cache: None,
            })
        }

        #[cfg(feature = "gcp-verify-example")]
        {
            let state = Arc::new(AppState {
                eph_kp,
                api_key: String::new(), // Not needed for GCP example
                jwks_cache: Some(Arc::new(RwLock::new((HashMap::new(), 0)))),
            });

            // Initialize JWKS cache
            if let Err(e) = update_jwks_cache(state.clone()).await {
                eprintln!("Warning: Failed to fetch initial JWKS: {:?}", e);
            }

            // Start background JWKS refresh task
            start_jwks_refresh_task(state.clone());

            state
        }
    };

    // Define your own restricted CORS policy here if needed.
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(ping))
        .route("/get_attestation", get(get_attestation))
        .route("/process_data", post(process_data))
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
