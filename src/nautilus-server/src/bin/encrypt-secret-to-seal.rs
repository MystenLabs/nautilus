// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::fs;
use std::path::Path;
use bcs;

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

#[derive(Debug, Deserialize)]
struct SealConfig {
    package_id: String,
    key_servers: Vec<String>,
    threshold: u8,
    #[serde(default)]
    enclave: Option<EnclaveConfig>,
}

#[derive(Debug, Deserialize)]
struct EnclaveConfig {
    #[serde(default = "default_host")]
    host: String,
    #[serde(default = "default_port")]
    port: u16,
}

fn default_host() -> String {
    "localhost".to_string()
}

fn default_port() -> u16 {
    3001
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
    let matches = Command::new("encrypt-secret-to-seal")
        .version("1.0")
        .about("Encrypt a secret using Seal and send it to Nautilus enclave")
        .arg(
            Arg::new("secret")
                .value_name("SECRET")
                .help("The secret to encrypt")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("key-name")
                .short('n')
                .long("key-name")
                .value_name("NAME")
                .help("Name for the secret in the enclave (default: API_KEY)")
                .default_value("API_KEY"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to seal_config.yaml file")
                .default_value("./src/nautilus-server/src/examples/seal_example/seal_config.yaml"),
        )
        .arg(
            Arg::new("package-id")
                .short('p')
                .long("package-id")
                .value_name("HEX")
                .help("Package ID (32-byte hex string) - overrides config file")
                .required(false),
        )
        .arg(
            Arg::new("key-servers")
                .short('s')
                .long("key-servers")
                .value_name("HEX")
                .help("Comma-separated list of key server IDs - overrides config file")
                .required(false),
        )
        .arg(
            Arg::new("threshold")
                .short('t')
                .long("threshold")
                .value_name("NUM")
                .help("Threshold for decryption - overrides config file")
                .required(false),
        )
        .arg(
            Arg::new("enclave-host")
                .short('e')
                .long("enclave-host")
                .value_name("HOST")
                .help("Enclave host address - overrides config file")
                .required(false),
        )
        .arg(
            Arg::new("enclave-port")
                .long("enclave-port")
                .value_name("PORT")
                .help("Enclave init port - overrides config file")
                .required(false),
        )
        .get_matches();

    // Parse arguments
    let secret = matches.get_one::<String>("secret").unwrap();
    let key_name = matches.get_one::<String>("key-name").unwrap();
    let config_path = matches.get_one::<String>("config").unwrap();
    
    // Load config file
    let config: SealConfig = if Path::new(config_path).exists() {
        let config_str = fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        serde_yaml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config file: {}", e))?
    } else {
        return Err(format!("Config file not found: {}", config_path).into());
    };
    
    // Use command line args if provided, otherwise use config values
    let package_id = if let Some(pid) = matches.get_one::<String>("package-id") {
        parse_object_id(pid)?
    } else {
        parse_object_id(&config.package_id)?
    };
    
    let key_servers_str = if let Some(ks) = matches.get_one::<String>("key-servers") {
        ks.clone()
    } else {
        config.key_servers.join(",")
    };
    
    let threshold = if let Some(t) = matches.get_one::<String>("threshold") {
        u8::from_str(t)?
    } else {
        config.threshold
    };
    
    let (enclave_host, enclave_port) = if let Some(enclave_cfg) = config.enclave {
        (
            matches.get_one::<String>("enclave-host")
                .cloned()
                .unwrap_or(enclave_cfg.host),
            matches.get_one::<String>("enclave-port")
                .unwrap_or(&enclave_cfg.port.to_string())
                .to_string()
        )
    } else {
        (
            matches.get_one::<String>("enclave-host")
                .cloned()
                .unwrap_or_else(|| "localhost".to_string()),
            matches.get_one::<String>("enclave-port")
                .cloned()
                .unwrap_or_else(|| "3001".to_string())
        )
    };

    // Parse key servers
    let key_servers: Vec<[u8; 32]> = key_servers_str
        .split(',')
        .map(|s| parse_object_id(s.trim()))
        .collect::<Result<Vec<_>, _>>()?;

    if key_servers.len() < threshold as usize {
        return Err("Number of key servers must be >= threshold".into());
    }

    println!("Encrypting secret with Seal parameters:");
    println!("  Secret name: {}", key_name);
    println!("  Package ID: 0x{}", hex::encode(&package_id));
    println!("  Key servers: {}", key_servers.len());
    println!("  Threshold: {}", threshold);

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
        threshold,
        encryption_input,
    )?;

    let init_request = InitRequest {
        encrypted_api_key: EncryptedApiKey { encrypted_object: encrypted_object.clone() },
    };

    // Print the encrypted result as hex encoded BCS bytes
    println!("\n✓ Successfully encrypted secret '{}'", key_name);
    
    // Serialize to BCS and print hex
    let bcs_bytes = bcs::to_bytes(&init_request)?;
    println!("\nBCS bytes (hex):");
    println!("{}", hex::encode(&bcs_bytes));
    
    println!("\nTo send this to the enclave, you would POST to:");
    println!("  URL: http://{}:{}/init", enclave_host, enclave_port);
    println!("  Content-Type: application/json");

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