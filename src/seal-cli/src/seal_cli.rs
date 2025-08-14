// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use fastcrypto::serde_helpers::ToFromByteArray;
use seal_sdk::types::{FetchKeyRequest, FetchKeyResponse};
use seal_sdk::IBEPublicKey;
use seal_sdk::{seal_encrypt, EncryptionInput, IBEPublicKeys};
use std::str::FromStr;
use sui_json_rpc_types::SuiParsedData;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::ObjectID;
use sui_sdk_types::ObjectId as NewObjectID;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    pub package_id: String,
    pub key_servers: Vec<String>,
    pub public_keys: Vec<String>,
    pub threshold: u8,
    pub rpc_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: String,
    pub name: String,
    pub url: String,
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

#[derive(Parser)]
#[command(name = "seal-cli")]
#[command(about = "Seal encryption and key management CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a secret using Seal
    Encrypt {
        /// The secret to encrypt
        secret: String,

        /// Name for the secret (default: API_KEY)
        #[arg(short = 'n', long, default_value = "API_KEY")]
        key_name: String,

        /// Path to seal_config.yaml file
        #[arg(short = 'c', long)]
        config: String,
    },

    /// Fetch keys from Seal servers using hex blob from init response
    FetchKeys {
        /// Hex-encoded BCS blob containing all parameters (from init response)
        #[arg(value_name = "fetch_keys_request")]
        fetch_keys_request: String,

        /// Path to seal_config.yaml file
        #[arg(short = 'c', long)]
        config: String,
    },
}

async fn handle_encrypt(
    secret: String,
    key_name: String,
    config_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load config file
    let config: SealConfig = if Path::new(&config_path).exists() {
        let config_str = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        serde_yaml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config file: {}", e))?
    } else {
        return Err(format!("Config file not found: {}", config_path).into());
    };

    let package_id =
    NewObjectID::from_str(&config.package_id).map_err(|e| format!("Invalid package ID: {}", e))?;

    let key_servers: Vec<[u8; 32]> = config
        .key_servers
        .iter()
        .map(|s| {
            NewObjectID::from_str(s.trim())
                .map(|id| *id.inner())
                .map_err(|e| format!("Invalid key server ID: {}", e))
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!("Encrypting secret with Seal parameters:");
    println!("  Secret name: {}", key_name);
    println!("  Package ID: {}", package_id);
    println!("  Key servers: {}", key_servers.len());
    println!("  Threshold: {}", config.threshold);

    let pks: Vec<IBEPublicKey> = config
        .public_keys
        .iter()
        .map(
            |pk_hex| -> Result<IBEPublicKey, Box<dyn std::error::Error>> {
                let bytes =
                    Hex::decode(pk_hex).map_err(|e| format!("Invalid public key hex: {}", e))?;
                let pk = IBEPublicKey::from_byte_array(
                    &bytes.try_into().map_err(|_| "Invalid public key length")?,
                )?;
                Ok(pk)
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    let public_keys = IBEPublicKeys::BonehFranklinBLS12381(pks);

    // Encrypt the secret
    let encryption_input = EncryptionInput::Aes256Gcm {
        data: secret.as_bytes().to_vec(),
        aad: None,
    };

    let encrypted_object = seal_encrypt(
        package_id.into(),
        key_name.as_bytes().to_vec(),
        key_servers
            .into_iter()
            .map(|bytes| NewObjectID::new(bytes).into())
            .collect(),
        &public_keys,
        config.threshold,
        encryption_input,
    )
    .map_err(|e| format!("Encryption failed: {}", e))?;

    println!("\n✓ Successfully encrypted secret '{}'", key_name);

    // Serialize to BCS bytes
    let bcs_bytes = bcs::to_bytes(&encrypted_object)?;
    println!("\nEncrypted object (BCS hex):");
    println!("{}", Hex::encode(&bcs_bytes));

    Ok(())
}

async fn handle_fetch_keys(
    fetch_keys_request: String,
    config_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes =
        Hex::decode(&fetch_keys_request).map_err(|e| format!("Invalid hex encoding: {}", e))?;
    let request: FetchKeyRequest = bcs::from_bytes(&bytes)
        .map_err(|e| format!("Failed to parse FetchKeyRequest from BCS: {}", e))?;

    println!(
        "fetch_keys_request: {:?}",
        serde_json::to_string(&request).unwrap()
    );
    let config: SealConfig = if Path::new(&config_path).exists() {
        let config_str = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        serde_yaml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config file: {}", e))?
    } else {
        return Err(format!("Config file not found: {}", config_path).into());
    };

    println!("Fetching Seal keys...");

    let client = reqwest::Client::new();

    let sui_rpc_url = config.rpc_url;
    println!("Using Sui RPC: {}", sui_rpc_url);

    // Get key server IDs from config
    let key_server_ids = config.key_servers.clone();

    let key_servers = fetch_key_server_urls(&key_server_ids, &sui_rpc_url).await?;
    println!("  Found {} key servers", key_servers.len());

    // Step 2: Fetch keys from Seal servers
    println!("\nStep 2: Fetching keys from Seal servers...");

    let mut seal_responses = Vec::new();
    for server in &key_servers {
        println!(
            "  Fetching from {} ({}/v1/fetch_key)",
            server.name, server.url
        );
        match client
            .post(format!("{}/v1/fetch_key", server.url))
            .header("Client-Sdk-Type", "rust")
            .header("Client-Sdk-Version", "1.0.0")
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    let response_bytes = response.bytes().await.unwrap();
                    let response: FetchKeyResponse = serde_json::from_slice(&response_bytes)
                        .expect("Failed to deserialize response");
                    println!("response: {:?}", serde_json::to_string(&response).unwrap());
                    seal_responses.push(response);
                    println!("    ✓ Success");
                } else {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    eprintln!("    ✗ Server returned error: {}", error_text);
                }
            }
            Err(e) => {
                eprintln!("    ✗ Failed: {}", e);
            }
        }

        if seal_responses.len() >= config.threshold as usize {
            println!("  Reached threshold of {} responses", config.threshold);
            break;
        }
    }

    if seal_responses.len() < config.threshold as usize {
        return Err(format!(
            "Failed to get enough responses: {} < {}",
            seal_responses.len(),
            config.threshold
        )
        .into());
    }

    println!(
        "\n✓ Successfully fetched {} seal responses",
        seal_responses.len()
    );

    println!(
        "Seal responses: {:?}",
        Hex::encode(bcs::to_bytes(&seal_responses).unwrap())
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            secret,
            key_name,
            config,
        } => {
            handle_encrypt(secret, key_name, config).await?;
        }

        Commands::FetchKeys {
            fetch_keys_request,
            config,
        } => {
            handle_fetch_keys(fetch_keys_request, config).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_key_server_urls() {
        let key_server_ids = vec!["0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75".to_string()];
        let sui_rpc = "https://fullnode.testnet.sui.io:443";
        let key_servers = fetch_key_server_urls(&key_server_ids, sui_rpc).await.unwrap();
        assert_eq!(key_servers.len(), 1);
        assert_eq!(key_servers[0].url, "https://test-key-server.com");
    }
}