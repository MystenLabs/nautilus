// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::serde_helpers::ToFromByteArray;
use seal_sdk::types::FetchKeyResponse;
use seal_sdk::{EncryptedObject, IBEPublicKey};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use sui_sdk_types::Address;

/// Custom deserializer for hex string to Address (for object IDs)
fn deserialize_object_id<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    Address::from_str(&s).map_err(serde::de::Error::custom)
}

/// Custom deserializer for Vec of hex strings to Vec<Address> (for object IDs)
fn deserialize_object_ids<'de, D>(deserializer: D) -> Result<Vec<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| Address::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Custom deserializer for Vec of hex strings to Vec<IBEPublicKey>
fn deserialize_ibe_public_keys<'de, D>(deserializer: D) -> Result<Vec<IBEPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let pk_hexs: Vec<String> = Vec::deserialize(deserializer)?;
    pk_hexs
        .into_iter()
        .map(|pk_hex| {
            let pk_bytes = Hex::decode(&pk_hex).map_err(serde::de::Error::custom)?;
            let pk = IBEPublicKey::from_byte_array(
                &pk_bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("Invalid public key length"))?,
            )
            .map_err(serde::de::Error::custom)?;
            Ok(pk)
        })
        .collect()
}

/// Custom deserializer for hex string to Vec<(Address, FetchKeyResponse)>
/// seal_responses uses Address for server IDs
fn deserialize_seal_responses<'de, D>(
    deserializer: D,
) -> Result<Vec<(Address, FetchKeyResponse)>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = String::deserialize(deserializer)?;
    let bytes = Hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
    let responses: Vec<(Address, FetchKeyResponse)> =
        bcs::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
    Ok(responses)
}

/// Custom deserializer for hex string to EncryptedObject
fn deserialize_encrypted_object<'de, D>(deserializer: D) -> Result<EncryptedObject, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = String::deserialize(deserializer)?;
    let bytes = Hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
    let responses: EncryptedObject = bcs::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
    Ok(responses)
}

/// Configuration for Seal key servers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "SealConfigRaw")]
pub struct SealConfig {
    pub key_servers: Vec<Address>,
    pub public_keys: Vec<IBEPublicKey>,
    pub package_id: Address,
    pub server_pk_map: HashMap<Address, IBEPublicKey>,
}

#[derive(Debug, Deserialize)]
struct SealConfigRaw {
    #[serde(deserialize_with = "deserialize_object_ids")]
    key_servers: Vec<Address>,
    #[serde(deserialize_with = "deserialize_ibe_public_keys")]
    public_keys: Vec<IBEPublicKey>,
    #[serde(deserialize_with = "deserialize_object_id")]
    package_id: Address,
}

impl TryFrom<SealConfigRaw> for SealConfig {
    type Error = String;

    fn try_from(raw: SealConfigRaw) -> Result<Self, Self::Error> {
        if raw.key_servers.len() != raw.public_keys.len() {
            return Err(format!(
                "key_servers and public_keys length mismatch: {} vs {}",
                raw.key_servers.len(),
                raw.public_keys.len()
            ));
        }

        let server_pk_map: HashMap<Address, IBEPublicKey> = raw
            .key_servers
            .iter()
            .zip(raw.public_keys.iter())
            .map(|(id, pk)| (*id, *pk))
            .collect();

        Ok(SealConfig {
            key_servers: raw.key_servers,
            public_keys: raw.public_keys,
            package_id: raw.package_id,
            server_pk_map,
        })
    }
}

/// Request for /init_seal_key_load
#[derive(Serialize, Deserialize)]
pub struct InitKeyLoadRequest {
    pub enclave_object_id: Address,
    pub initial_shared_version: u64,
}

/// Response for /init_seal_key_load
#[derive(Serialize, Deserialize)]
pub struct InitKeyLoadResponse {
    pub encoded_request: String,
}

/// Request for /complete_seal_key_load
#[derive(Serialize, Deserialize)]
pub struct CompleteKeyLoadRequest {
    #[serde(deserialize_with = "deserialize_seal_responses")]
    pub seal_responses: Vec<(Address, FetchKeyResponse)>,
}

/// Response for /complete_seal_key_load
#[derive(Serialize, Deserialize)]
pub struct CompleteKeyLoadResponse {
    pub status: String,
}

/// Request for /provision_weather_api_key
#[derive(Serialize, Deserialize)]
pub struct ProvisionWeatherApiRequest {
    #[serde(deserialize_with = "deserialize_encrypted_object")]
    pub encrypted_object: EncryptedObject,
}

/// Response for /provision_weather_api_key
#[derive(Serialize, Deserialize)]
pub struct ProvisionWeatherApiResponse {
    pub status: String,
}
