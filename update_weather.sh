#!/bin/bash

# Check if all args are provided
if [ "$#" -ne 8 ]; then
    echo "Usage: $0 <app_package_id> <module_name> <otw_name> <enclave_object_id> <signature_hex> <timestamp_ms> <location> <temperature>"
    echo "Example: $0 0x2b70e34684d696a0a2847c793ee1e5b88a23289a7c04dd46249b95a9823367d9 weather WEATHER 0x5fc237c75757e47c5819b3f25bab6acc6c45c39db320a109e12c8c4468103438 bb0d315f8904f298288249c5d4498cb4904dad07f1ab149e59c7d0d1d39f5865fabc40f1cc927248fe6e381417fedbdb0d9df76eee86493977d347fdfe998e00 1743982200000 'San Francisco' 0"
    exit 1
fi

APP_PACKAGE_ID=$1
MODULE_NAME=$2
OTW_NAME=$3
ENCLAVE_OBJECT_ID=$4
SIG_HEX=$5
TIMESTAMP_MS=$6
LOCATION=$7
TEMPERATURE=$8

# Convert hex to vector array using Python
SIG_ARRAY=$(python3 - <<EOF
import sys

def hex_to_vector(hex_string):
    byte_values = [str(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)]
    rust_array = [f"{byte}u8" for byte in byte_values]
    return f"[{', '.join(rust_array)}]"

print(hex_to_vector("$SIG_HEX"))
EOF
)

echo "converted sig, length=${#SIG_ARRAY}"

sui client ptb \
    --move-call "${APP_PACKAGE_ID}::weather::update_weather<${APP_PACKAGE_ID}::${MODULE_NAME}::${OTW_NAME}>" \
        "\"$LOCATION\"" \
        $TEMPERATURE \
        $TIMESTAMP_MS \
        "vector$SIG_ARRAY" \
        @$ENCLAVE_OBJECT_ID \
    --assign nft_result \
    --transfer-objects "[nft_result]" @$(sui client active-address) \
    --gas-budget 100000000
