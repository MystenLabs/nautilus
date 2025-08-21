// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{AppState, EnclaveError, JwksKey};
use crate::common::{to_signed_response, IntentScope, ProcessedDataResponse, IntentMessage};
use axum::extract::State;
use axum::Json;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyJwtRequest {
    pub jwt: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtVerificationData {
    pub jwt: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwksKeyResponse>,
}

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
            JwksKey {
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

    let mut cache = state.jwks_cache.write().await;
    *cache = (keys_map, timestamp);
    
    info!("JWKS cache updated successfully with {} keys", cache.0.len());
    Ok(())
}

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

async fn should_refresh_cache(state: &Arc<AppState>) -> bool {
    let cache = state.jwks_cache.read().await;
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    current_time - cache.1 > 300 // 5 minutes
}

pub async fn verify_google_jwt(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyJwtRequest>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<JwtVerificationData>>>, EnclaveError> {
    info!("JWT verification requested");

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get current timestamp: {}", e)))?
        .as_millis() as u64;

    if should_refresh_cache(&state).await {
        info!("JWKS cache is stale, refreshing...");
        if let Err(e) = update_jwks_cache(state.clone()).await {
            error!("Failed to refresh JWKS cache: {:?}", e);
        }
    }

    let header = match jsonwebtoken::decode_header(&request.jwt) {
        Ok(header) => header,
        Err(e) => {
            let verification_data = JwtVerificationData {
                jwt: request.jwt,
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
                jwt: request.jwt,
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

    let cache = state.jwks_cache.read().await;
    let jwks_key = match cache.0.get(&kid) {
        Some(key) => key.clone(),
        None => {
            let verification_data = JwtVerificationData {
                jwt: request.jwt,
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
                jwt: request.jwt,
                verified: false,
                claims: None,
                error: Some(format!("Failed to create decoding key: {}", e)),
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

    match decode::<Value>(&request.jwt, &decoding_key, &validation) {
        Ok(token_data) => {
            info!("JWT verification successful");
            let verification_data = JwtVerificationData {
                jwt: request.jwt,
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
                jwt: request.jwt,
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
}

fn create_decoding_key(jwks_key: &JwksKey) -> Result<DecodingKey, EnclaveError> {
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

    #[tokio::test]
    async fn test_jwks_cache_refresh() {
        let state = Arc::new(AppState {
            eph_kp: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            jwks_cache: Arc::new(RwLock::new((HashMap::new(), 0))),
        });

        let should_refresh = should_refresh_cache(&state).await;
        assert!(should_refresh);
    }

    #[tokio::test]
    async fn test_create_decoding_key() {
        let mock_jwks_key = JwksKey {
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

    #[test]
    fn test_base64_decoding() {
        use base64::{engine::general_purpose, Engine as _};
        
        let test_e = "AQAB";
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(test_e);
        assert!(decoded.is_ok(), "Failed to decode base64url: {:?}", decoded.err());
        
        let bytes = decoded.unwrap();
        assert_eq!(bytes, vec![1, 0, 1]);
        
        let reencoded = general_purpose::STANDARD.encode(&bytes);
        assert_eq!(reencoded, "AQAB");
    }

    #[tokio::test]
    async fn test_jwt_endpoint_with_invalid_jwt() {
        let state = Arc::new(AppState {
            eph_kp: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            jwks_cache: Arc::new(RwLock::new((HashMap::new(), 0))),
        });

        let request = VerifyJwtRequest {
            jwt: "invalid.jwt.token".to_string(),
        };

        let response = verify_google_jwt(State(state), Json(request)).await;
        assert!(response.is_ok());
        
        let json_response = response.unwrap().0;
        assert!(!json_response.response.data.verified);
        assert!(json_response.response.data.error.is_some());
        assert!(json_response.response.data.claims.is_none());
        assert!(!json_response.signature.is_empty());
    }

    #[tokio::test]
    async fn test_jwt_endpoint_missing_kid() {
        let state = Arc::new(AppState {
            eph_kp: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            jwks_cache: Arc::new(RwLock::new((HashMap::new(), 0))),
        });

        let request = VerifyJwtRequest {
            jwt: "eyJhbGciOiJSUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature".to_string(),
        };

        let response = verify_google_jwt(State(state), Json(request)).await;
        assert!(response.is_ok());
        
        let json_response = response.unwrap().0;
        assert!(!json_response.response.data.verified);
        assert!(json_response.response.data.error.as_ref().unwrap().contains("missing 'kid' field"));
        assert!(!json_response.signature.is_empty());
    }

    #[test]
    fn test_google_jwks_base64_decoding() {
        use base64::{engine::general_purpose, Engine as _};
        
        let google_n = "2g24x8Fr-7APEzsGEFE-Z1Y1oXXDvQJ2SYqHwuNVieMBoUiDQvUQl1Hvo1ZIcBUn625uUVCksK0txxVEQ6n-aha4wKx3N1re7k_kzLGxnYJ_tBGAHF4mAgMFUdXvyYaVB4X_tth5DCzi2cTqRiuIoVvD0-mGkceoJNNOzfrzsMTqAft-yByOtb-ABtlbqG3mbN0TWB_EwFwWDMAJyVwxLhC-cGCUrnwqLM0FJGvxeVXdFdbmUdm7uVX1icy7u1y-6AQ9GPQOJExNdNOc8zO57TLz2EjH_rP4r13m1kAl0oitDNic5UUPcN-2Xx2rVjtnbgxjh3vRNvEbI26MQdMNIQ";
        let google_e = "AQAB";
        
        let n_decoded = general_purpose::URL_SAFE_NO_PAD.decode(google_n);
        assert!(n_decoded.is_ok(), "Failed to decode Google n: {:?}", n_decoded.err());
        
        let e_decoded = general_purpose::URL_SAFE_NO_PAD.decode(google_e);
        assert!(e_decoded.is_ok(), "Failed to decode Google e: {:?}", e_decoded.err());
        
        let n_bytes = n_decoded.unwrap();
        let e_bytes = e_decoded.unwrap();
        
        assert!(!n_bytes.is_empty());
        assert_eq!(e_bytes, vec![1, 0, 1]);
    }

    #[test]
    fn test_create_decoding_key_with_google_data() {
        let google_key = JwksKey {
            kid: "16d7abba381e3c1d24ff0072176a4d6883d53ef0".to_string(),
            alg: "RS256".to_string(),
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            n: "2g24x8Fr-7APEzsGEFE-Z1Y1oXXDvQJ2SYqHwuNVieMBoUiDQvUQl1Hvo1ZIcBUn625uUVCksK0txxVEQ6n-aha4wKx3N1re7k_kzLGxnYJ_tBGAHF4mAgMFUdXvyYaVB4X_tth5DCzi2cTqRiuIoVvD0-mGkceoJNNOzfrzsMTqAft-yByOtb-ABtlbqG3mbN0TWB_EwFwWDMAJyVwxLhC-cGCUrnwqLM0FJGvxeVXdFdbmUdm7uVX1icy7u1y-6AQ9GPQOJExNdNOc8zO57TLz2EjH_rP4r13m1kAl0oitDNic5UUPcN-2Xx2rVjtnbgxjh3vRNvEbI26MQdMNIQ".to_string(),
            e: "AQAB".to_string(),
        };

        let result = create_decoding_key(&google_key);
        assert!(result.is_ok(), "Failed to create decoding key with Google data: {:?}", result.err());
    }

    #[test]
    fn test_jwt_verification_data_serialization() {
        use serde_json;

        let success_data = JwtVerificationData {
            jwt: "test.jwt.token".to_string(),
            verified: true,
            claims: Some(serde_json::json!({"test": "value"})),
            error: None,
        };

        let json = serde_json::to_string(&success_data).unwrap();
        assert!(!json.contains("\"error\""));
        assert!(json.contains("\"verified\":true"));
        assert!(json.contains("\"jwt\":\"test.jwt.token\""));
        assert!(json.contains("\"claims\""));

        let error_data = JwtVerificationData {
            jwt: "test.jwt.token".to_string(),
            verified: false,
            claims: None,
            error: Some("Test error".to_string()),
        };

        let json = serde_json::to_string(&error_data).unwrap();
        assert!(json.contains("\"error\":\"Test error\""));
        assert!(json.contains("\"verified\":false"));
        assert!(json.contains("\"jwt\":\"test.jwt.token\""));
        assert!(!json.contains("\"claims\""));
    }
}
