# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#!/bin/bash

# Gets the enclave id and CID
# expects there to be only one enclave running
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

sleep 5
# Secrets-block
# Seal example: create empty secrets.json (required by run.sh)
echo 'Creating empty secrets.json for seal example...'
echo '{}' > secrets.json

# This section will be populated by configure_enclave.sh based on secret configuration

cat secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

# Seal example: Expose port 3001 for localhost-only access to init endpoint
echo "Exposing seal init endpoint on localhost:3001..."
socat TCP4-LISTEN:3001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3001 &


# Additional port configurations will be added here by configure_enclave.sh if needed
