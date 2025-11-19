# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#!/bin/bash

# Gets the enclave id and CID
# expects there to be only one enclave running
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

sleep 5
# Secrets-block
SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:094557288217:secret:weather-mMoHen --region us-east-1 | jq -r .SecretString)
echo "$SECRET_VALUE" | jq -R '{"API_KEY": .}' > secrets.json

# This section will be populated by configure_enclave.sh based on secret configuration

cat secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

# Additional port configurations will be added here by configure_enclave.sh if needed
