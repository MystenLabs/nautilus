// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Configuration for Seal key servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    pub key_servers: Vec<String>,
    pub public_keys: Vec<String>,
}

/// Request for /init_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadRequest {
    pub enclave_object_id: String,
    pub initial_shared_version: u64,
    pub key_name: String, // e.g. "weather-api-key"
    pub package_id: String,
}

/// Response for /init_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadResponse {
    pub encoded_request: String,
}

/// Request for /complete_parameter_load
#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteParameterLoadRequest {
    pub encrypted_object: String,
    pub seal_responses: String,
}
