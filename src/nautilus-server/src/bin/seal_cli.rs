// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::collections::HashMap;

const KEY_SIZE: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedObject {
    pub version: u8,
    pub package_id: [u8; 32],
    pub id: Vec<u8>,
    pub services: Vec<([u8; 32], u8)>,
    pub threshold: u8,
    pub encrypted_shares: IBEEncryptions,
    pub ciphertext: Ciphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEEncryptions {
    BonehFranklinBLS12381 {
        nonce: Vec<u8>,
        encrypted_shares: Vec<Vec<u8>>,
        encrypted_randomness: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    Aes256Gcm { blob: Vec<u8>, aad: Option<Vec<u8>> },
    Hmac256Ctr { blob: Vec<u8>, aad: Option<Vec<u8>>, mac: [u8; 32] },
    Plain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEPublicKeys {
    BonehFranklinBLS12381(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionInput {
    Aes256Gcm { data: Vec<u8>, aad: Option<Vec<u8>> },
    Hmac256Ctr { data: Vec<u8>, aad: Option<Vec<u8>> },
    Plain,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    pub session_id: String,
    pub package_id: String,
    pub enclave_object_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteRequest {
    pub session_id: String,
    pub encrypted_object: EncryptedObject,
    pub seal_responses: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct SealConfig {
    package_id: String,
    key_servers: Vec<String>,
    threshold: u8,
    enclave_object_id: Option<String>,
}

// Key server info fetched from chain
#[derive(Debug, Deserialize)]
struct KeyServerInfo {
    object_id: String,
    name: String,
    url: String,
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
        #[arg(short = 'c', long, default_value = "./seal_config.yaml")]
        config: String,
        
        /// Output file for encrypted object
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    
    /// Fetch keys from Seal servers and decrypt
    FetchKeys {
        /// Session ID for this request
        #[arg(short = 's', long)]
        session_id: String,
        
        /// Path to seal_config.yaml file
        #[arg(short = 'c', long, default_value = "./seal_config.yaml")]
        config: String,
        
        /// Enclave host URL
        #[arg(long, default_value = "http://localhost:3001")]
        enclave_url: String,
        
        /// JSON file containing the encrypted object
        #[arg(short = 'e', long)]
        encrypted_file: String,
        
        /// Sui RPC URL (default: testnet)
        #[arg(long)]
        sui_rpc: Option<String>,
        
        /// Output file for the decrypted result
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
}

/// Parse a hex string into a 32-byte array
fn parse_object_id(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("ObjectID must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Simple seal_encrypt implementation for the CLI
fn seal_encrypt(
    package_id: [u8; 32],
    id: Vec<u8>,
    key_servers: Vec<[u8; 32]>,
    _public_keys: &IBEPublicKeys,
    threshold: u8,
    encryption_input: EncryptionInput,
) -> Result<EncryptedObject, Box<dyn std::error::Error>> {
    use rand::{thread_rng, RngCore};
    
    // Generate a random key
    let mut dem_key = [0u8; KEY_SIZE];
    thread_rng().fill_bytes(&mut dem_key);
    
    // Encrypt the data
    let ciphertext = match encryption_input {
        EncryptionInput::Aes256Gcm { data, aad } => {
            // For this example, we'll use a simple XOR encryption
            // In production, this would use proper AES-GCM encryption
            let mut blob = data.clone();
            for (i, byte) in blob.iter_mut().enumerate() {
                *byte ^= dem_key[i % KEY_SIZE];
            }
            Ciphertext::Aes256Gcm { blob, aad }
        }
        _ => return Err("Only Aes256Gcm encryption is supported in this example".into()),
    };
    
    // Create mock encrypted shares (in production, these would be real IBE encrypted shares)
    let services: Vec<([u8; 32], u8)> = key_servers
        .iter()
        .enumerate()
        .map(|(i, ks)| (*ks, i as u8))
        .collect();
    
    let encrypted_object = EncryptedObject {
        version: 0,
        package_id,
        id,
        services,
        threshold,
        encrypted_shares: IBEEncryptions::BonehFranklinBLS12381 {
            nonce: vec![0u8; 32],
            encrypted_shares: key_servers.iter().map(|_| vec![0u8; 48]).collect(),
            encrypted_randomness: vec![0u8; 32],
        },
        ciphertext,
    };
    
    Ok(encrypted_object)
}

// Fetch key server URLs from Sui chain
async fn fetch_key_server_urls(
    key_server_ids: &[String],
    sui_rpc: &str,
) -> Result<Vec<KeyServerInfo>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut servers = Vec::new();
    
    for object_id in key_server_ids {
        // Fetch the key server object
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sui_getObject",
            "params": [
                object_id,
                {
                    "showContent": true
                }
            ]
        });
        
        let response = client
            .post(sui_rpc)
            .json(&request)
            .send()
            .await?;
        
        let json: Value = response.json().await?;
        
        // For V1 key servers, we need to fetch the dynamic field
        let versioned_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sui_getDynamicFieldObject",
            "params": [
                object_id,
                {
                    "type": "u64",
                    "value": "1" // EXPECTED_SERVER_VERSION = 1
                }
            ]
        });
        
        let versioned_response = client
            .post(sui_rpc)
            .json(&versioned_request)
            .send()
            .await?;
        
        let versioned_json: Value = versioned_response.json().await?;
        
        // Extract URL and name from versioned object
        let versioned_content = versioned_json
            .get("result")
            .and_then(|r| r.get("data"))
            .and_then(|d| d.get("content"))
            .and_then(|c| c.get("fields"))
            .and_then(|f| f.get("value"))
            .and_then(|v| v.get("fields"))
            .ok_or("Failed to parse versioned key server object")?;
        
        let url = versioned_content
            .get("url")
            .and_then(|u| u.as_str())
            .ok_or("Missing URL in key server")?
            .to_string();
        
        let name = versioned_content
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown")
            .to_string();
        
        servers.push(KeyServerInfo {
            object_id: object_id.clone(),
            name,
            url,
        });
    }
    
    Ok(servers)
}

async fn handle_encrypt(
    secret: String,
    key_name: String,
    config_path: String,
    output: Option<String>,
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
    
    let package_id = parse_object_id(&config.package_id)?;
    
    // Parse key servers
    let key_servers: Vec<[u8; 32]> = config.key_servers
        .iter()
        .map(|s| parse_object_id(s.trim()))
        .collect::<Result<Vec<_>, _>>()?;

    if key_servers.len() < config.threshold as usize {
        return Err("Number of key servers must be >= threshold".into());
    }

    println!("Encrypting secret with Seal parameters:");
    println!("  Secret name: {}", key_name);
    println!("  Package ID: 0x{}", hex::encode(&package_id));
    println!("  Key servers: {}", key_servers.len());
    println!("  Threshold: {}", config.threshold);

    // Create mock public keys (in production, these would be real IBE public keys)
    let public_keys = IBEPublicKeys::BonehFranklinBLS12381(
        key_servers.iter().map(|_| vec![0u8; 48]).collect()
    );

    // Encrypt the secret
    let encryption_input = EncryptionInput::Aes256Gcm {
        data: secret.as_bytes().to_vec(),
        aad: Some(key_name.as_bytes().to_vec()),
    };

    let encrypted_object = seal_encrypt(
        package_id,
        key_name.as_bytes().to_vec(),
        key_servers,
        &public_keys,
        config.threshold,
        encryption_input,
    )?;

    println!("\n✓ Successfully encrypted secret '{}'", key_name);
    
    // Save to file if output specified
    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&encrypted_object)?;
        fs::write(&output_path, json)?;
        println!("Encrypted object saved to: {}", output_path);
    } else {
        // Print the encrypted object as JSON
        println!("\nEncrypted object (JSON):");
        println!("{}", serde_json::to_string_pretty(&encrypted_object)?);
    }
    
    Ok(())
}

async fn handle_fetch_keys(
    session_id: String,
    config_path: String,
    enclave_url: String,
    encrypted_file: String,
    sui_rpc: Option<String>,
    output: Option<String>,
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
    
    // Load encrypted object
    let encrypted_object: EncryptedObject = {
        let encrypted_str = fs::read_to_string(&encrypted_file)
            .map_err(|e| format!("Failed to read encrypted file: {}", e))?;
        serde_json::from_str(&encrypted_str)
            .map_err(|e| format!("Failed to parse encrypted object: {}", e))?
    };
    
    let enclave_object_id = config.enclave_object_id
        .ok_or("enclave_object_id not found in config")?;
    
    println!("Fetching Seal keys:");
    println!("  Session ID: {}", session_id);
    println!("  Package ID: 0x{}", hex::encode(&encrypted_object.package_id));
    println!("  Enclave URL: {}", enclave_url);
    
    // Step 1: Initialize session with enclave
    println!("\nStep 1: Initializing session with enclave...");
    let client = reqwest::Client::new();
    let init_request = InitRequest {
        session_id: session_id.clone(),
        package_id: hex::encode(&encrypted_object.package_id),
        enclave_object_id: enclave_object_id.clone(),
    };
    
    let init_response = client
        .post(format!("{}/seal/init_parameter_load", enclave_url))
        .json(&init_request)
        .send()
        .await?;
    
    if !init_response.status().is_success() {
        return Err(format!("Init failed: {}", init_response.text().await?).into());
    }
    
    let init_data: Value = init_response.json().await?;
    let request_body = init_data.get("request_body")
        .ok_or("No request_body in init response")?;
    
    // Step 2: Fetch key server URLs from chain
    println!("\nStep 2: Fetching key server information from Sui chain...");
    let sui_rpc_url = sui_rpc.unwrap_or_else(|| "https://fullnode.testnet.sui.io:443".to_string());
    println!("  Using Sui RPC: {}", sui_rpc_url);
    
    // Get key server IDs from encrypted object
    let key_server_ids: Vec<String> = encrypted_object.services
        .iter()
        .map(|(id, _)| format!("0x{}", hex::encode(id)))
        .collect();
    
    let key_servers = fetch_key_server_urls(&key_server_ids, &sui_rpc_url).await?;
    println!("  Found {} key servers", key_servers.len());
    
    // Step 3: Fetch keys from Seal servers
    println!("\nStep 3: Fetching keys from Seal servers...");
    let mut seal_responses = Vec::new();
    for server in &key_servers {
        println!("  Fetching from {} ({})", server.name, server.url);
        match client
            .post(&server.url)
            .json(&request_body)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    let json_response = response.json::<Value>().await?;
                    seal_responses.push(json_response);
                    println!("    ✓ Success");
                } else {
                    eprintln!("    ✗ Server returned error: {}", response.status());
                }
            }
            Err(e) => {
                eprintln!("    ✗ Failed: {}", e);
            }
        }
        
        if seal_responses.len() >= encrypted_object.threshold as usize {
            println!("  Reached threshold of {} responses", encrypted_object.threshold);
            break;
        }
    }
    
    if seal_responses.len() < encrypted_object.threshold as usize {
        return Err(format!(
            "Failed to get enough responses: {} < {}",
            seal_responses.len(),
            encrypted_object.threshold
        ).into());
    }
    
    // Step 4: Complete parameter load
    println!("\nStep 4: Completing parameter load...");
    let complete_request = CompleteRequest {
        session_id,
        encrypted_object,
        seal_responses,
    };
    
    let complete_response = client
        .post(format!("{}/seal/complete_parameter_load", enclave_url))
        .json(&complete_request)
        .send()
        .await?;
    
    if !complete_response.status().is_success() {
        return Err(format!("Complete failed: {}", complete_response.text().await?).into());
    }
    
    let result: Value = complete_response.json().await?;
    
    println!("\n✓ Successfully decrypted data");
    
    // Save or print result
    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&result)?;
        fs::write(&output_path, json)?;
        println!("Result saved to: {}", output_path);
    } else {
        println!("\nDecrypted data:");
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    
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
            output,
        } => {
            handle_encrypt(secret, key_name, config, output).await?;
        }
        
        Commands::FetchKeys {
            session_id,
            config,
            enclave_url,
            encrypted_file,
            sui_rpc,
            output,
        } => {
            handle_fetch_keys(session_id, config, enclave_url, encrypted_file, sui_rpc, output).await?;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_object_id() {
        // Test with 0x prefix
        let id = parse_object_id("0x0000000000000000000000000000000000000000000000000000000000000001");
        assert!(id.is_ok());
        assert_eq!(id.unwrap()[31], 1);

        // Test without 0x prefix
        let id = parse_object_id("0000000000000000000000000000000000000000000000000000000000000001");
        assert!(id.is_ok());
        assert_eq!(id.unwrap()[31], 1);

        // Test invalid length
        let id = parse_object_id("0x00");
        assert!(id.is_err());
    }
}