// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use fastcrypto::serde_helpers::ToFromByteArray;
use reqwest::Body;
use seal_sdk::types::{FetchKeyRequest, FetchKeyResponse};
use seal_sdk::IBEPublicKey;
use seal_sdk::{seal_encrypt, EncryptionInput, IBEPublicKeys};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use sui_json_rpc_types::SuiParsedData;
use sui_sdk::SuiClientBuilder;
use sui_sdk_types::ObjectId as NewObjectID;
use sui_types::base_types::ObjectID;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

/// Seal config containing key server object ids and pks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    pub key_servers: Vec<String>,
    pub public_keys: Vec<String>,
}

/// Key server object layout containing object id, name, and url.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: String,
    pub name: String,
    pub url: String,
}

/// Fetch and parse key server object from fullnode.
pub async fn fetch_key_server_urls(
    key_server_ids: &[String],
    sui_rpc: &str,
) -> Result<Vec<KeyServerInfo>, Box<dyn std::error::Error>> {
    // todo: use sui-rust-sdk grpc suite.
    let sui_client = SuiClientBuilder::default().build(sui_rpc).await?;
    let mut key_servers = Vec::new();

    for object_id_str in key_server_ids {
        let object_id: ObjectID = object_id_str
            .parse()
            .map_err(|e| format!("Invalid object ID {}: {}", object_id_str, e))?;

        // Get the dynamic field object for version 1
        // todo: handle other versions
        let dynamic_field_name = DynamicFieldName {
            type_: TypeTag::U64,
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
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    _ => "Unknown".to_string(),
                                })
                                .unwrap_or_else(|| "Unknown".to_string());

                            key_servers.push(KeyServerInfo {
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

    Ok(key_servers)
}

#[derive(Parser)]
#[command(name = "seal-cli")]
#[command(about = "Seal encryption and key management CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a secret using Seal.
    Encrypt {
        /// The secret to encrypt.
        secret: String,

        /// Unique per package identifier of the secret, e.g. weather-api-key.
        #[arg(short = 'n', long)]
        key_name: String,

        /// Package ID that defines seal policy.
        #[arg(short = 'p', long)]
        package_id: String,

        /// Threshold
        #[arg(short = 't', long)]
        threshold: u8,

        /// Path to seal_config.yaml file
        #[arg(short = 'c', long)]
        config_path: String,
    },

    /// Fetch keys from Seal servers using assembled fetch keys request.
    FetchKeys {
        /// Encoded fetch keys request. Returned as response from /init_parameter_load.
        fetch_keys_request: String,

        /// Fullnode rpc, used to get url.
        #[arg(short = 'r', long)]
        sui_rpc: String,

        /// Path to seal_config.yaml file
        #[arg(short = 'c', long)]
        config_path: String,

        /// Threshold
        #[arg(short = 't', long)]
        threshold: u8,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            secret,
            key_name,
            package_id,
            threshold,
            config_path,
        } => {
            // Read config from file.
            // todo: abstract a method for this and do parsing in serde.
            let config: SealConfig = if Path::new(&config_path).exists() {
                let config_str = fs::read_to_string(&config_path)
                    .map_err(|e| format!("Failed to read config file: {}", e))?;
                serde_yaml::from_str(&config_str)
                    .map_err(|e| format!("Failed to parse config file: {}", e))?
            } else {
                return Err(format!("Config file not found: {}", config_path).into());
            };

            // Parse key server ids from config.
            let key_server_ids = config
                .key_servers
                .iter()
                .map(|s| NewObjectID::from_str(s).unwrap())
                .collect::<Vec<_>>();

            // Parse pks from config.
            let pks: Vec<IBEPublicKey> = config
                .public_keys
                .iter()
                .map(
                    |pk_hex| -> Result<IBEPublicKey, Box<dyn std::error::Error>> {
                        let bytes = Hex::decode(pk_hex)
                            .map_err(|e| format!("Invalid public key hex: {}", e))?;
                        // todo: add this to seal-sdk for parsing
                        let pk = IBEPublicKey::from_byte_array(
                            &bytes.try_into().map_err(|_| "Invalid public key length")?,
                        )?;
                        Ok(pk)
                    },
                )
                .collect::<Result<Vec<_>, _>>()?;

            // Encrypt the secret.
            let package_id = NewObjectID::from_str(&package_id)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let (encrypted_object, _) = seal_encrypt(
                package_id,
                key_name.as_bytes().to_vec(),
                key_server_ids,
                &IBEPublicKeys::BonehFranklinBLS12381(pks),
                threshold,
                EncryptionInput::Aes256Gcm {
                    data: secret.as_bytes().to_vec(), // secret data to encrypt.
                    aad: None,
                },
            )
            .map_err(|e| format!("Encryption failed: {}", e))?;

            let bcs_bytes = bcs::to_bytes(&encrypted_object)?;
            println!("\nEncrypted object:");
            println!("{}", Hex::encode(&bcs_bytes));
        }

        Commands::FetchKeys {
            fetch_keys_request,
            sui_rpc,
            threshold,
            config_path,
        } => {
            // Parse fetch keys request.
            let request: FetchKeyRequest = bcs::from_bytes(
                &Hex::decode(&fetch_keys_request)
                    .map_err(|e| format!("Invalid hex encoding: {}", e))?,
            )
            .map_err(|e| format!("Failed to parse FetchKeyRequest from BCS: {}", e))?;

            // Read config from file.
            let config: SealConfig = if Path::new(&config_path).exists() {
                let config_str = fs::read_to_string(&config_path)
                    .map_err(|e| format!("Failed to read config file: {}", e))?;
                serde_yaml::from_str(&config_str)
                    .map_err(|e| format!("Failed to parse config file: {}", e))?
            } else {
                return Err(format!("Config file not found: {}", config_path).into());
            };

            // Fetch keys from key server urls and collect seal responses.
            let mut seal_responses = Vec::new();
            let client = reqwest::Client::new();
            for server in &fetch_key_server_urls(&config.key_servers, &sui_rpc).await? {
                println!(
                    "Fetching from {} ({}/v1/fetch_key)",
                    server.name, server.url
                );
                match client
                    .post(format!("{}/v1/fetch_key", server.url))
                    .header("Client-Sdk-Type", "rust")
                    .header("Client-Sdk-Version", "1.0.0")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        request.to_json_string().expect("should not fail"),
                    ))
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            let response_bytes = response.bytes().await.expect("should not fail");
                            let response: FetchKeyResponse =
                                serde_json::from_slice(&response_bytes)
                                    .expect("Failed to deserialize response");
                            seal_responses.push(response);
                            println!("\n Success {}", server.name);
                        } else {
                            let error_text = response
                                .text()
                                .await
                                .unwrap_or_else(|_| "Unknown error".to_string());
                            eprintln!("Server returned error: {}", error_text);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed: {}", e);
                    }
                }

                if seal_responses.len() >= threshold as usize {
                    println!("Reached threshold of {} responses", threshold);
                    break;
                }
            }

            if seal_responses.len() < threshold as usize {
                return Err(format!(
                    "Failed to get enough responses: {} < {}",
                    seal_responses.len(),
                    threshold
                )
                .into());
            }

            println!(
                "\n {:?} Seal responses: {:?}",
                seal_responses.len(),
                Hex::encode(bcs::to_bytes(&seal_responses).expect("should not fail"))
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_key_server_urls() {
        let key_server_ids =
            vec!["0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75".to_string()];
        let sui_rpc = "https://fullnode.testnet.sui.io:443";
        let key_servers = fetch_key_server_urls(&key_server_ids, sui_rpc)
            .await
            .unwrap();
        assert_eq!(key_servers.len(), 1);
        assert_eq!(
            key_servers[0].url,
            "https://seal-key-server-testnet-1.mystenlabs.com"
        );
    }
}
