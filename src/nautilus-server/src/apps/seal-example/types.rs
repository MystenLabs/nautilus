// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use sui_json_rpc_types::SuiParsedData;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::ObjectID;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    pub package_id: String,
    pub key_servers: Vec<String>,
    pub public_keys: Vec<String>,
    pub threshold: u8,
    pub rpc_url: String,
}

pub struct ParsedResponse {
    pub full_id: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitParameterLoadRequest {
    pub enclave_object_id: String,
    pub initial_shared_version: u64,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteParameterLoadResponse {
    pub response: String,
}

/// Fetch key server URLs from Sui chain using proper SDK
pub async fn fetch_key_server_urls(
    key_server_ids: &[String],
    sui_rpc: &str,
) -> Result<Vec<KeyServerInfo>, Box<dyn std::error::Error>> {
    let sui_client = SuiClientBuilder::default().build(sui_rpc).await?;

    let mut servers = Vec::new();

    for object_id_str in key_server_ids {
        let object_id: ObjectID = object_id_str
            .parse()
            .map_err(|e| format!("Invalid object ID {}: {}", object_id_str, e))?;

        // Get the dynamic field object for version 1
        let dynamic_field_name = sui_types::dynamic_field::DynamicFieldName {
            type_: sui_types::TypeTag::U64,
            value: serde_json::Value::String("1".to_string()),
        };

        match sui_client
            .read_api()
            .get_dynamic_field_object(object_id, dynamic_field_name)
            .await
        {
            Ok(response) => {
                if let Some(object_data) = response.data {
                    if let Some(content) = object_data.content {
                        if let SuiParsedData::MoveObject(parsed_data) = content {
                            let fields = &parsed_data.fields;

                            // Convert fields to JSON value for access
                            let fields_json = serde_json::to_value(fields)
                                .map_err(|e| format!("Failed to serialize fields: {}", e))?;

                            // Extract URL and name from the nested 'value' field
                            let value_struct = fields_json.get("value").ok_or_else(|| {
                                format!("Missing 'value' field for object {}", object_id_str)
                            })?;

                            // The value is a Struct, we need to access its fields
                            let value_fields = value_struct.get("fields").ok_or_else(|| {
                                format!(
                                    "Missing 'fields' in value struct for object {}",
                                    object_id_str
                                )
                            })?;

                            let url = value_fields.get("url")
                                .and_then(|v| match v {
                                    serde_json::Value::String(s) => Some(s.clone()),
                                    _ => None,
                                })
                                .ok_or_else(|| format!("Missing or invalid 'url' field in value fields for object {}", object_id_str))?;

                            let name = value_fields
                                .get("name")
                                .and_then(|v| match v {
                                    serde_json::Value::String(s) => Some(s.clone()),
                                    _ => Some("Unknown".to_string()),
                                })
                                .unwrap_or_else(|| "Unknown".to_string());

                            servers.push(KeyServerInfo {
                                object_id: object_id_str.clone(),
                                name,
                                url,
                            });
                        } else {
                            return Err(format!(
                                "Unexpected content type for object {}",
                                object_id_str
                            )
                            .into());
                        }
                    } else {
                        return Err(format!("No content found for object {}", object_id_str).into());
                    }
                } else {
                    return Err(format!("Object {} not found", object_id_str).into());
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to fetch dynamic field for object {}: {}",
                    object_id_str, e
                )
                .into());
            }
        }
    }

    Ok(servers)
}