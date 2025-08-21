// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    pub key_servers: Vec<String>,
    pub public_keys: Vec<String>
}

pub struct ParsedResponse {
    pub full_id: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadRequest {
    pub enclave_object_id: String,
    pub initial_shared_version: u64,
    pub package_id: String,
    pub key_name: String, // e.g. "weather-api-key"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadResponse {
    pub encoded_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteParameterLoadRequest {
    pub encrypted_object: String,
    pub seal_responses: String,
}
