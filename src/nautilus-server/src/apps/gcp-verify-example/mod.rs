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
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

#[cfg(feature = "gcp-verify-example")]
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

/// Inner type for ProcessDataRequest<T>
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyJwtRequest {
    pub jwt: String,
}

/// Inner type for IntentMessage<T>
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtVerificationData {
    pub jwt: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(feature = "gcp-verify-example")]
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwksKeyResponse>,
}

#[cfg(feature = "gcp-verify-example")]
#[derive(Debug, Deserialize)]
struct JwksKeyResponse {
    kid: String,
    alg: String,
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    n: String,
    e: String,
}

#[cfg(feature = "gcp-verify-example")]
pub async fn update_jwks_cache(state: Arc<AppState>) -> Result<(), EnclaveError> {
    let url = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
    
    info!("Fetching JWKS from Google...");
    
    let response = reqwest::get(url).await.map_err(|e| {
        error!("Failed to fetch JWKS: {}", e);
        EnclaveError::GenericError(format!("Failed to fetch JWKS: {}", e))
    })?;

    if !response.status().is_success() {
        error!("JWKS fetch failed with status: {}", response.status());
        return Err(EnclaveError::GenericError(format!(
            "JWKS fetch failed with status: {}",
            response.status()
        )));
    }

    let jwks: JwksResponse = response.json().await.map_err(|e| {
        error!("Failed to parse JWKS response: {}", e);
        EnclaveError::GenericError(format!("Failed to parse JWKS response: {}", e))
    })?;

    let mut keys_map = HashMap::new();
    for key in jwks.keys {
        keys_map.insert(
            key.kid.clone(),
            crate::JwksKey {
                kid: key.kid,
                alg: key.alg,
                kty: key.kty,
                use_: key.use_,
                n: key.n,
                e: key.e,
            },
        );
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get timestamp: {}", e)))?
        .as_secs();

    if let Some(jwks_cache) = &state.jwks_cache {
        let mut cache = jwks_cache.write().await;
        *cache = (keys_map, timestamp);
        
        info!("JWKS cache updated successfully with {} keys", cache.0.len());
    }
    Ok(())
}

#[cfg(feature = "gcp-verify-example")]
pub fn start_jwks_refresh_task(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
        
        loop {
            interval.tick().await;
            if let Err(e) = update_jwks_cache(state.clone()).await {
                error!("Failed to update JWKS cache: {:?}", e);
            }
        }
    });
}

#[cfg(feature = "gcp-verify-example")]
async fn should_refresh_cache(state: &Arc<AppState>) -> bool {
    if let Some(jwks_cache) = &state.jwks_cache {
        let cache = jwks_cache.read().await;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        current_time - cache.1 > 300 // 5 minutes
    } else {
        false
    }
}

pub async fn process_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<VerifyJwtRequest>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<JwtVerificationData>>>, EnclaveError> {
    info!("JWT verification requested");

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get current timestamp: {}", e)))?
        .as_millis() as u64;

    #[cfg(feature = "gcp-verify-example")]
    {
        if should_refresh_cache(&state).await {
            info!("JWKS cache is stale, refreshing...");
            if let Err(e) = update_jwks_cache(state.clone()).await {
                error!("Failed to refresh JWKS cache: {:?}", e);
            }
        }

        let header = match jsonwebtoken::decode_header(&request.payload.jwt) {
            Ok(header) => header,
            Err(e) => {
                let verification_data = JwtVerificationData {
                    jwt: request.payload.jwt,
                    verified: false,
                    claims: None,
                    error: Some(format!("Failed to decode JWT header: {}", e)),
                };
                
                return Ok(Json(to_signed_response(
                    &state.eph_kp,
                    verification_data,
                    current_timestamp,
                    IntentScope::JwtVerification,
                )));
            }
        };

        let kid = match header.kid {
            Some(kid) => kid,
            None => {
                let verification_data = JwtVerificationData {
                    jwt: request.payload.jwt,
                    verified: false,
                    claims: None,
                    error: Some("JWT header missing 'kid' field".to_string()),
                };
                
                return Ok(Json(to_signed_response(
                    &state.eph_kp,
                    verification_data,
                    current_timestamp,
                    IntentScope::JwtVerification,
                )));
            }
        };

        if let Some(jwks_cache) = &state.jwks_cache {
            let cache = jwks_cache.read().await;
            let jwks_key = match cache.0.get(&kid) {
                Some(key) => key.clone(),
                None => {
                    let verification_data = JwtVerificationData {
                        jwt: request.payload.jwt,
                        verified: false,
                        claims: None,
                        error: Some(format!("Key with kid '{}' not found in JWKS", kid)),
                    };
                    
                    return Ok(Json(to_signed_response(
                        &state.eph_kp,
                        verification_data,
                        current_timestamp,
                        IntentScope::JwtVerification,
                    )));
                }
            };

            let decoding_key = match create_decoding_key(&jwks_key) {
                Ok(key) => key,
                Err(e) => {
                    let verification_data = JwtVerificationData {
                        jwt: request.payload.jwt,
                        verified: false,
                        claims: None,
                        error: Some(format!("Failed to create decoding key: {:?}", e)),
                    };
                    
                    return Ok(Json(to_signed_response(
                        &state.eph_kp,
                        verification_data,
                        current_timestamp,
                        IntentScope::JwtVerification,
                    )));
                }
            };

            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_exp = true;
            validation.validate_aud = false; // Google JWT might not have audience

            match decode::<Value>(&request.payload.jwt, &decoding_key, &validation) {
                Ok(token_data) => {
                    info!("JWT verification successful");
                    let verification_data = JwtVerificationData {
                        jwt: request.payload.jwt,
                        verified: true,
                        claims: Some(token_data.claims),
                        error: None,
                    };
                    
                    Ok(Json(to_signed_response(
                        &state.eph_kp,
                        verification_data,
                        current_timestamp,
                        IntentScope::JwtVerification,
                    )))
                }
                Err(e) => {
                    info!("JWT verification failed: {}", e);
                    let verification_data = JwtVerificationData {
                        jwt: request.payload.jwt,
                        verified: false,
                        claims: None,
                        error: Some(format!("JWT verification failed: {}", e)),
                    };
                    
                    Ok(Json(to_signed_response(
                        &state.eph_kp,
                        verification_data,
                        current_timestamp,
                        IntentScope::JwtVerification,
                    )))
                }
            }
        } else {
            let verification_data = JwtVerificationData {
                jwt: request.payload.jwt,
                verified: false,
                claims: None,
                error: Some("JWKS cache not available".to_string()),
            };
            
            Ok(Json(to_signed_response(
                &state.eph_kp,
                verification_data,
                current_timestamp,
                IntentScope::JwtVerification,
            )))
        }
    }
    #[cfg(not(feature = "gcp-verify-example"))]
    {
        let verification_data = JwtVerificationData {
            jwt: request.payload.jwt,
            verified: false,
            claims: None,
            error: Some("GCP verify example not enabled".to_string()),
        };
        
        Ok(Json(to_signed_response(
            &state.eph_kp,
            verification_data,
            current_timestamp,
            IntentScope::JwtVerification,
        )))
    }
}

#[cfg(feature = "gcp-verify-example")]
fn create_decoding_key(jwks_key: &crate::JwksKey) -> Result<DecodingKey, EnclaveError> {
    use base64::{engine::general_purpose, Engine as _};
    
    if jwks_key.kty != "RSA" {
        return Err(EnclaveError::GenericError(
            "Only RSA keys are supported".to_string(),
        ));
    }

    // Validate that we can decode the base64url components
    let _n_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(&jwks_key.n)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to decode n: {}", e)))?;
    
    let _e_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(&jwks_key.e)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to decode e: {}", e)))?;

    // Use the base64url strings directly as jsonwebtoken expects this format
    let key = DecodingKey::from_rsa_components(&jwks_key.n, &jwks_key.e)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to create RSA key: {}", e)))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    #[cfg(feature = "gcp-verify-example")]
    #[tokio::test]
    async fn test_jwks_cache_refresh() {
        let state = Arc::new(AppState {
            eph_kp: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            api_key: String::new(),
            jwks_cache: Some(Arc::new(RwLock::new((HashMap::new(), 0)))),
        });

        let should_refresh = should_refresh_cache(&state).await;
        assert!(should_refresh);
    }

    #[cfg(feature = "gcp-verify-example")]
    #[tokio::test]
    async fn test_create_decoding_key() {
        let mock_jwks_key = crate::JwksKey {
            kid: "16d7abba381e3c1d24ff0072176a4d6883d53ef0".to_string(),
            alg: "RS256".to_string(),
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            n: "2g24x8Fr-7APEzsGEFE-Z1Y1oXXDvQJ2SYqHwuNVieMBoUiDQvUQl1Hvo1ZIcBUn625uUVCksK0txxVEQ6n-aha4wKx3N1re7k_kzLGxnYJ_tBGAHF4mAgMFUdXvyYaVB4X_tth5DCzi2cTqRiuIoVvD0-mGkceoJNNOzfrzsMTqAft-yByOtb-ABtlbqG3mbN0TWB_EwFwWDMAJyVwxLhC-cGCUrnwqLM0FJGvxeVXdFdbmUdm7uVX1icy7u1y-6AQ9GPQOJExNdNOc8zO57TLz2EjH_rP4r13m1kAl0oitDNic5UUPcN-2Xx2rVjtnbgxjh3vRNvEbI26MQdMNIQ".to_string(),
            e: "AQAB".to_string(),
        };

        let result = create_decoding_key(&mock_jwks_key);
        assert!(result.is_ok(), "Failed to create decoding key: {:?}", result.err());
    }
}
