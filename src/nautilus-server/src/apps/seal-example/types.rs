// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::serde_helpers::ToFromByteArray;
use seal_sdk::types::{FetchKeyResponse, KeyId};
use seal_sdk::{EncryptedObject, IBEPublicKey};
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;
use sui_sdk_types::ObjectId as ObjectID;

/// Custom deserializer for hex strings to Vec<u8>
fn deserialize_hex_vec<'de, D>(deserializer: D) -> Result<Vec<KeyId>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: Vec<String> = Vec::deserialize(deserializer)?;
    hex_strings
        .into_iter()
        .map(|s| Hex::decode(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Custom deserializer for hex string to ObjectID
fn deserialize_object_id<'de, D>(deserializer: D) -> Result<ObjectID, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    ObjectID::from_str(&s).map_err(serde::de::Error::custom)
}

/// Custom deserializer for Vec of hex strings to Vec<ObjectID>
fn deserialize_object_ids<'de, D>(deserializer: D) -> Result<Vec<ObjectID>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| ObjectID::from_str(&s).map_err(serde::de::Error::custom))
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

/// Custom deserializer for hex string to Vec<(ObjectID, FetchKeyResponse)>
fn deserialize_seal_responses<'de, D>(
    deserializer: D,
) -> Result<Vec<(ObjectID, FetchKeyResponse)>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = String::deserialize(deserializer)?;
    let bytes = Hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
    let responses: Vec<(ObjectID, FetchKeyResponse)> =
        bcs::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
    Ok(responses)
}

/// Custom deserializer for hex string to Vec<EncryptedObject>
fn deserialize_encrypted_objects<'de, D>(deserializer: D) -> Result<Vec<EncryptedObject>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let hex_string: String = String::deserialize(deserializer)?;
    let bytes = Hex::decode(&hex_string).map_err(D::Error::custom)?;
    let objects: Vec<EncryptedObject> = bcs::from_bytes(&bytes).map_err(D::Error::custom)?;
    Ok(objects)
}

/// Configuration for Seal key servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    #[serde(deserialize_with = "deserialize_object_ids")]
    pub key_servers: Vec<ObjectID>,
    #[serde(deserialize_with = "deserialize_ibe_public_keys")]
    pub public_keys: Vec<IBEPublicKey>,
    #[serde(deserialize_with = "deserialize_object_id")]
    pub package_id: ObjectID,
}

/// Request for /init_parameter_load
#[derive(Serialize, Deserialize)]
pub struct InitParameterLoadRequest {
    pub enclave_object_id: ObjectID,
    pub initial_shared_version: u64,
    #[serde(deserialize_with = "deserialize_hex_vec")]
    pub ids: Vec<KeyId>, // all ids for all encrypted objects (hex strings -> Vec<u8>)
}

/// Response for /init_parameter_load
#[derive(Serialize, Deserialize)]
pub struct InitParameterLoadResponse {
    pub encoded_request: String,
}

/// Request for /complete_parameter_load
#[derive(Serialize, Deserialize)]
pub struct CompleteParameterLoadRequest {
    #[serde(deserialize_with = "deserialize_encrypted_objects")]
    pub encrypted_objects: Vec<EncryptedObject>,
    #[serde(deserialize_with = "deserialize_seal_responses")]
    pub seal_responses: Vec<(ObjectID, FetchKeyResponse)>,
}

/// Response for /complete_parameter_load, for demo on decrypting many secrets.
/// Can be removed for your own app.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteParameterLoadResponse {
    pub dummy_secrets: Vec<Vec<u8>>,
}
