// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

// Import from the parent crate
use nautilus_server::examples::seal_example::seal_sdk::{fetch_key_server_urls, seal_encrypt, IBEPublicKeys, EncryptionInput};


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
        
        /// BCS hex string of the encrypted object (from encrypt command output)
        #[arg(short = 'e', long)]
        encrypted_object: String,
        
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
    
    // Serialize to BCS bytes
    let bcs_bytes = bcs::to_bytes(&encrypted_object)?;
    println!("\nEncrypted object (BCS hex):");
    println!("{}", hex::encode(&bcs_bytes));
    
    // Save to file if output specified
    if let Some(output_path) = output {
        // Save as BCS bytes (hex format)
        fs::write(&output_path, hex::encode(&bcs_bytes))?;
        println!("\nBCS hex saved to: {}", output_path);
    }
    
    Ok(())
}

async fn handle_fetch_keys(
    session_id: String,
    config_path: String,
    enclave_url: String,
    encrypted_object_hex: String,
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
    
    // Parse the encrypted object from BCS hex
    let bcs_bytes = hex::decode(encrypted_object_hex.trim())
        .map_err(|e| format!("Invalid encrypted object hex: {}", e))?;
    let encrypted_object: EncryptedObject = bcs::from_bytes(&bcs_bytes)
        .map_err(|e| format!("Failed to parse encrypted object BCS: {}", e))?;
    
    let enclave_object_id = config.enclave_object_id
        .ok_or("enclave_object_id not found in config")?;
    
    println!("Fetching Seal keys:");
    println!("  Session ID: {}", session_id);
    println!("  Package ID: {}", hex::encode(&encrypted_object.package_id));
    println!("  Object ID: {}", String::from_utf8_lossy(&encrypted_object.id));
    println!("  Enclave URL: {}", enclave_url);
    
    let client = reqwest::Client::new();
    
    // Step 1: Fetch key server URLs from chain
    println!("\nStep 1: Fetching key server information from Sui chain...");
    let sui_rpc_url = sui_rpc.unwrap_or_else(|| "https://fullnode.testnet.sui.io:443".to_string());
    println!("  Using Sui RPC: {}", sui_rpc_url);
    
    // Get key server IDs from config
    let key_server_ids = config.key_servers.clone();
    
    let key_servers = fetch_key_server_urls(&key_server_ids, &sui_rpc_url).await?;
    println!("  Found {} key servers", key_servers.len());
    
    // Step 2: Fetch keys from Seal servers
    println!("\nStep 2: Fetching keys from Seal servers...");
    
    // Create request body for key servers
    let request_body = serde_json::json!({
        "session_id": session_id,
        "package_id": config.package_id,
        "enclave_object_id": enclave_object_id,
        "encrypted_object": encrypted_object
    });
    
    let mut seal_responses = Vec::new();
    for server in &key_servers {
        println!("  Fetching from {} ({}/v1/fetch_key)", server.name, server.url);
        match client
            .post(format!("{}/v1/fetch_key", server.url))
            .header("Client-Sdk-Type", "rust")
            .header("Client-Sdk-Version", "1.0.0")
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
                    let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
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
        ).into());
    }
    
    // Step 3: Send responses to enclave /complete endpoint
    println!("\nStep 3: Completing parameter load with enclave...");
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
    
    println!("\n✓ Successfully completed key fetch process");
    
    // Save or print result
    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&result)?;
        fs::write(&output_path, json)?;
        println!("Result saved to: {}", output_path);
    } else {
        println!("\nResult:");
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
            encrypted_object,
            sui_rpc,
            output,
        } => {
            handle_fetch_keys(session_id, config, enclave_url, encrypted_object, sui_rpc, output).await?;
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