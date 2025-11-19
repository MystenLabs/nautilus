// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::common::IntentMessage;
use crate::common::{to_signed_response, IntentScope, ProcessDataRequest, ProcessedDataResponse};
use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use fastcrypto::encoding::{Encoding, Hex};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
/// ====
/// Core Nautilus server logic, replace it with your own
/// relavant structs and process_data endpoint.
/// ====
/// Inner type for IntentMessage<T>
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserData {
    pub twitter_name: Vec<u8>,
    pub sui_address: Vec<u8>,
}

/// Inner type for ProcessDataRequest<T>
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRequest {
    pub user_url: String,
}

pub async fn process_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<UserRequest>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<UserData>>>, EnclaveError> {
    let user_url = request.payload.user_url.clone();
    info!("Processing data for user URL: {}", user_url);

    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get current timestamp: {e}")))?
        .as_millis() as u64;
    // Fetch tweet content
    let (twitter_name, sui_address) = fetch_tweet_content(&state.api_key, &user_url).await?;
    Ok(Json(to_signed_response(
        &state.eph_kp,
        UserData {
            twitter_name: twitter_name.as_bytes().to_vec(),
            sui_address: sui_address.clone(),
        },
        current_timestamp,
        IntentScope::ProcessData,
    )))
}

async fn fetch_tweet_content(
    api_key: &str,
    user_url: &str,
) -> Result<(String, Vec<u8>), EnclaveError> {
    let client = reqwest::Client::new();
    if user_url.contains("/status/") {
        // Extract tweet ID from URL using regex
        let re = Regex::new(r"x\.com/\w+/status/(\d+)")
            .map_err(|_| EnclaveError::GenericError("Invalid tweet URL".to_string()))?;
        let tweet_id = re
            .captures(user_url)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| EnclaveError::GenericError("Invalid tweet URL".to_string()))?;

        // Construct the Twitter API URL
        let url = format!(
            "https://api.twitter.com/2/tweets/{tweet_id}?expansions=author_id&user.fields=username"
        );

        // Make the request to Twitter API
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .await
            .map_err(|_| {
                EnclaveError::GenericError("Failed to send request to Twitter API".to_string())
            })?
            .json::<serde_json::Value>()
            .await
            .map_err(|_| {
                EnclaveError::GenericError("Failed to parse response from Twitter API".to_string())
            })?;

        // Extract tweet text and author username
        let tweet_text = response["data"]["text"].as_str().ok_or_else(|| {
            EnclaveError::GenericError(format!("Failed to extract tweet text {response}"))
        })?;

        let twitter_name = response["includes"]["users"]
            .as_array()
            .and_then(|users| users.first())
            .and_then(|user| user["username"].as_str())
            .ok_or_else(|| EnclaveError::GenericError("Failed to extract username".to_string()))?;

        // Find the position of "#SUI" and extract address before it
        let sui_tag_pos = tweet_text
            .find("#SUI")
            .ok_or_else(|| EnclaveError::GenericError("No #SUI tag found in tweet".to_string()))?;

        let text_before_tag = &tweet_text[..sui_tag_pos];
        let sui_address_re = Regex::new(r"0x[0-9a-fA-F]{64}")
            .map_err(|_| EnclaveError::GenericError("Invalid Sui address regex".to_string()))?;

        let sui_address = sui_address_re
            .find(text_before_tag)
            .map(|m| m.as_str())
            .ok_or_else(|| {
                EnclaveError::GenericError(
                    "No valid Sui address found before #SUI in profile description".to_string(),
                )
            })?;

        Ok((
            twitter_name.to_string(),
            Hex::decode(sui_address)
                .map_err(|_| EnclaveError::GenericError("Invalid Sui address".to_string()))?,
        ))
    } else {
        // Handle profile URL
        let re = Regex::new(r"x\.com/(\w+)(?:/)?$")
            .map_err(|_| EnclaveError::GenericError("Invalid profile URL".to_string()))?;
        let username = re
            .captures(user_url)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| EnclaveError::GenericError("Invalid profile URL".to_string()))?;

        // Fetch user profile
        let url = format!(
            "https://api.twitter.com/2/users/by/username/{username}?user.fields=description"
        );

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .await
            .map_err(|_| {
                EnclaveError::GenericError("Failed to send request to Twitter API".to_string())
            })?
            .json::<serde_json::Value>()
            .await
            .map_err(|_| {
                EnclaveError::GenericError("Failed to parse response from Twitter API".to_string())
            })?;

        // Extract user description
        let description = response["data"]["description"].as_str().ok_or_else(|| {
            EnclaveError::GenericError("Failed to extract user description".to_string())
        })?;

        let sui_tag_pos = description.find("#SUI").ok_or_else(|| {
            EnclaveError::GenericError("No #SUI tag found in profile description".to_string())
        })?;

        let text_before_tag = &description[..sui_tag_pos];
        let sui_address_re = Regex::new(r"0x[0-9a-fA-F]{64}")
            .map_err(|_| EnclaveError::GenericError("Invalid Sui address regex".to_string()))?;

        let sui_address = sui_address_re
            .find(text_before_tag)
            .map(|m| m.as_str())
            .ok_or_else(|| {
                EnclaveError::GenericError(
                    "No valid Sui address found before #SUI in profile description".to_string(),
                )
            })?;

        Ok((
            username.to_string(),
            Hex::decode(&sui_address[2..])
                .map_err(|_| EnclaveError::GenericError("Invalid Sui address".to_string()))?,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_serde() {
        // serialization should be consistent with move test see `fun test_serde` in `enclave.move`.
        use crate::common::IntentMessage;
        let intent_msg = IntentMessage::new(
            UserData {
                twitter_name: "mystenintern".as_bytes().to_vec(),
                sui_address: Hex::decode(
                    "0x101ce8865558e08408b83f60ee9e78843d03d547c850cbe12cb599e17833dd3e",
                )
                .unwrap(),
            },
            1743989326143,
            IntentScope::ProcessData,
        );
        let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
        assert!(signing_payload == Hex::decode("003f41dd0d960100000c6d797374656e696e7465726e20101ce8865558e08408b83f60ee9e78843d03d547c850cbe12cb599e17833dd3e").unwrap());
    }
}
