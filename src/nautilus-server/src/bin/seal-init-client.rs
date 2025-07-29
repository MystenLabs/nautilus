// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
    pub encrypted_api_key: EncryptedApiKey,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedApiKey {
    pub encrypted_object: EncryptedObject,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("seal-init-client")
        .version("1.0")
        .about("Initialize Nautilus enclave with Seal-encrypted API key")
        .arg(
            Arg::new("api-key")
                .short('k')
                .long("api-key")
                .value_name("KEY")
                .help("The Weather API key to encrypt")
                .required(true),
        )
        .arg(
            Arg::new("package-id")
                .short('p')
                .long("package-id")
                .value_name("HEX")
                .help("Package ID (32-byte hex string)")
                .required(true),
        )
        .arg(
            Arg::new("key-servers")
                .short('s')
                .long("key-servers")
                .value_name("HEX")
                .help("Comma-separated list of key server IDs (32-byte hex strings)")
                .required(true),
        )
        .arg(
            Arg::new("threshold")
                .short('t')
                .long("threshold")
                .value_name("NUM")
                .help("Threshold for decryption")
                .default_value("2"),
        )
        .arg(
            Arg::new("enclave-host")
                .short('e')
                .long("enclave-host")
                .value_name("HOST")
                .help("Enclave host address")
                .default_value("localhost"),
        )
        .arg(
            Arg::new("enclave-port")
                .long("enclave-port")
                .value_name("PORT")
                .help("Enclave init port")
                .default_value("3001"),
        )
        .get_matches();

    // Parse arguments
    let api_key = matches.get_one::<String>("api-key").unwrap();
    let package_id = parse_object_id(matches.get_one::<String>("package-id").unwrap())?;
    let key_servers_str = matches.get_one::<String>("key-servers").unwrap();
    let threshold = u8::from_str(matches.get_one::<String>("threshold").unwrap())?;
    let enclave_host = matches.get_one::<String>("enclave-host").unwrap();
    let enclave_port = matches.get_one::<String>("enclave-port").unwrap();

    // Parse key servers
    let key_servers: Vec<[u8; 32]> = key_servers_str
        .split(',')
        .map(|s| parse_object_id(s.trim()))
        .collect::<Result<Vec<_>, _>>()?;

    if key_servers.len() < threshold as usize {
        return Err("Number of key servers must be >= threshold".into());
    }

    println!("Encrypting API key with Seal parameters:");
    println!("  Package ID: 0x{}", hex::encode(&package_id));
    println!("  Key servers: {}", key_servers.len());
    println!("  Threshold: {}", threshold);

    // Create mock public keys (in production, these would be real IBE public keys)
    let public_keys = IBEPublicKeys::BonehFranklinBLS12381(
        key_servers.iter().map(|_| vec![0u8; 48]).collect()
    );

    // Encrypt the API key
    let encryption_input = EncryptionInput::Aes256Gcm {
        data: api_key.as_bytes().to_vec(),
        aad: Some(b"weather-api-key".to_vec()),
    };

    let encrypted_object = seal_encrypt(
        package_id,
        b"api-key".to_vec(),
        key_servers,
        &public_keys,
        threshold,
        encryption_input,
    )?;

    let init_request = InitRequest {
        encrypted_api_key: EncryptedApiKey { encrypted_object },
    };

    // Send to enclave
    let url = format!("http://{}:{}/init", enclave_host, enclave_port);
    println!("\nSending encrypted API key to: {}", url);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&init_request)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;

    if status.is_success() {
        println!("✓ Successfully initialized enclave with encrypted API key");
        println!("Response: {}", body);
    } else {
        println!("✗ Failed to initialize enclave");
        println!("Status: {}", status);
        println!("Response: {}", body);
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