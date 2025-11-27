#!/bin/bash

# Check if both arguments are provided
if [ "$#" -lt 6 ] || [ "$#" -gt 7 ]; then
    echo "Usage: $0 <enclave_package_id> <app_package_id> <enclave_config_id> <enclave_url> <module_name> <otw_name> [key_type]"
    echo "  key_type (optional): Ed25519, or Secp256k1. If omitted, defaults to Ed25519."
    echo "Example: $0 0x872852f77545c86a8bd9bdb8adc9e686b8573fc2a0dab0af44864bc1aecdaea9 0x2b70e34684d696a0a2847c793ee1e5b88a23289a7c04dd46249b95a9823367d9 0x86775ced1fdceae31d090cf48a11b4d8e4a613a2d49f657610c0bc287c8f0589 http://100.26.111.45:3000 weather WEATHER"
    exit 1
fi

ENCLAVE_PACKAGE_ID=$1
APP_PACKAGE_ID=$2
ENCLAVE_CONFIG_OBJECT_ID=$3
ENCLAVE_URL=$4
MODULE_NAME=$5
OTW_NAME=$6
KEY_TYPE=${7:-}  # Optional key type

echo 'fetching attestation'
# Fetch attestation and store the hex
ATTESTATION_HEX=$(curl -s $ENCLAVE_URL/get_attestation | jq -r '.attestation')

echo "got attestation, length=${#ATTESTATION_HEX}"

if [ ${#ATTESTATION_HEX} -eq 0 ]; then
    echo "Error: Attestation is empty. Please check status of $ENCLAVE_URL and its get_attestation endpoint."
    exit 1
fi

# Convert hex to array using Python
ATTESTATION_ARRAY=$(python3 - <<EOF
import sys

def hex_to_vector(hex_string):
    byte_values = [str(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)]
    rust_array = [f"{byte}u8" for byte in byte_values]
    return f"[{', '.join(rust_array)}]"

print(hex_to_vector("$ATTESTATION_HEX"))
EOF
)

echo 'converted attestation'
# Execute sui client command with the converted array and provided arguments
# If key_type is specified, use register_enclave_with_key_type; otherwise use register_enclave (defaults to Ed25519)
if [ -z "$KEY_TYPE" ]; then
    sui client ptb --assign v "vector$ATTESTATION_ARRAY" \
        --move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6 \
        --assign result \
        --move-call "${ENCLAVE_PACKAGE_ID}::enclave::register_enclave<${APP_PACKAGE_ID}::${MODULE_NAME}::${OTW_NAME}>" @${ENCLAVE_CONFIG_OBJECT_ID} result \
        --gas-budget 100000000
else
    sui client ptb --assign v "vector$ATTESTATION_ARRAY" \
        --move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6 \
        --assign result \
        --move-call "${ENCLAVE_PACKAGE_ID}::enclave::register_enclave_with_key_type<${APP_PACKAGE_ID}::${MODULE_NAME}::${OTW_NAME}>" @${ENCLAVE_CONFIG_OBJECT_ID} result "${ENCLAVE_PACKAGE_ID}::enclave::KeyType::${KEY_TYPE}" \
        --gas-budget 100000000
fi