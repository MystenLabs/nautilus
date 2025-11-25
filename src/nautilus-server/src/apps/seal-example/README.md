# Seal-Nautilus Pattern

This example is currently WIP. Use it as a reference only. 

The Seal-Nautilus pattern provides secure secret management for enclave applications, where user can encrypt any secrets to the enclave binary. 

One can define a Seal policy bounded to an enclave identity configured with specified PCRs. Users can use the enclave identity to encrypt any data using Seal, and only the enclave of the given PCRs can decrypt it. 

Here we reuse the weather example: Instead of storing the `weather-api-key` with AWS Secret Manager, we encrypt it using Seal, and show that only the enclave with the expected PCRs is able to decrypt and use it. 

## Components

1. Nautilus server running inside AWS Nitro Enclave (`src/nautilus-server/src/apps/seal-example`): This is the only place that the Seal secret can be decrypted according to the policy. It exposes the endpoints at port 3000 to the Internet with the `/get_attestation` and `/process_data` endpoints. It also exposes port 3001 to the `localhost` with 3 `/admin` endpoints, which can only be used to initialize and complete the key load steps on the host instance that the enclave runs.

2. Seal [CLI](https://github.com/MystenLabs/seal/tree/main/crates/seal-cli): In particular, `encrypt` and `fetch-keys` are used for this example. The latest doc for the CLI can be found [here](https://seal-docs.wal.app/SealCLI/#7-encrypt-and-fetch-keys-using-service-providers).

3. Move contract `move/seal-policy/seal_policy.move`: This defines the `seal_approve` policy using the enclave object. 

## Overview

> [!NOTE]
> Admin is someone that has access to the EC2 instance. He can build and run the enclave binary on it. He can also call the admin only enclave endpoints via localhost on the EC2 instance.

Phase 1: Start and Register the Server

1. Admin specifies the `seal_config.yaml` with the published Seal policy package ID and Seal configurations. Then the admin builds and runs the enclave with exposed `/get_attestation` endpoint. 

2. Admin uses the attestation response to register PCRs and the enclave public key. The `/process_data` endpoint currently returns an error because the `SEAL_API_KEY` is not yet initialized.

3. Admin registers the enclave on-chain and get enclave object ID and initial shared version. 

Phase 2: Initialize and Complete Key Load

4. Admin calls `/admin/init_seal_key_load` with the enclave object and key ID. Enclave returns an encoded `FetchKeyRequest`.

5. Admin uses FetchKeyRequest to call CLI to get Seal responses, encrypted under the enclave's encryption public key.

6. Admin calls `/admin/complete_seal_key_load` with seal responses. Enclave decrypts and caches all Seal keys in memory for later use.

Phase 3: Provision Application Secrets

7. Now that Seal keys are cached, encrypted objects can be decrypted on-demand using the cached keys. Specifically for our example, Admin calls `/admin/provision_weather_api_key` with the encrypted weather API key object. The enclave decrypts it using the cached keys and stores it as `SEAL_API_KEY`. 

8. Enclave can now serve `/process_data` requests. 

## Security Guarantees

The enclave generates 3 keypairs on startup, all kept only in enclave memory:

1. Enclave ephemeral keypair: Registered on-chain in the Enclave object, used to sign `/process_data` responses.
2. Enclave Seal wallet keypair: Used for Seal certificate and PTB signing.
3. ElGamal encryption keypair: Used to decrypt Seal responses.

During `/init_seal_key_load`, the wallet signs a PersonalMessage for the certificate and also signs the enclave public key as a commitment. This signature is included in the PTB passed to `seal_approve`. When Seal servers dry-run the transaction, `seal_approve` verifies:

1. The wallet signature is valid over the enclave's public key. 
2. The key ID matches the enclave's object ID. 
3. The transaction sender matches the wallet public key. 

This proves that only the enclave (which has access to both keys) could have created a valid signed PTB. 

During `/init_seal_key_load`, the enclave also generates an encryption key and return the encryption public key as part of `FetchKeyRequest`. The host uses the CLI to fetch keys from Seal servers, but the host cannot decrypt the `FetchKeyResponse` since it does not have the encryption secret key. Then the `FetchKeyResponse` is passed to the enclave at `/complete_seal_key_load`, and only the enclave can verify the consistency and decrypt the secret in memory.

### Why Two Step Key Load is Needed for Phase 2?

This is because an enclave operates without direct internet access so it cannot fetch secrets from Seal key servers' HTTP endpoints directly. Here we use the host acts as an intermediary to fetch encrypted secrets from Seal servers. 

This delegation is secure because the Seal responses are encrypted under the enclave's encryption key, so only the enclave can later decrypt the fetched Seal responses. The enclave is also initialized with the public keys of the Seal servers in `seal_config.yaml`, which can be used to verify the decrypted secrets are not tampered with.

## Steps

### Step 0: Build, Run and Register Enclave

This is the same as the Nautilus template. Refer to the main guide for more detailed instructions. 

```shell
# publish the enclave package
cd move/enclave
sui move build && sui client publish

# find this in output and set env var
ENCLAVE_PACKAGE_ID=0xc664c812bfce5b8ade4243da3d91fc529ac488f79f7f7bf2e0e7c4fd887a2433

# publish the app package
cd move/seal-example
sui move build && sui client publish

# find these in output and set env var
CAP_OBJECT_ID=0xa4a0ea418c1107a9d9ae2ff03dfaea5826cf6a419ee92f93988ec3c02d03c098
ENCLAVE_CONFIG_OBJECT_ID=0xcd4a3253cbe065c776ab5b9ef781f0b9ba9bb6f150c39e5caa8c90464539e0e7
APP_PACKAGE_ID=0x2080f9c370ddb22c48d6377f8aa64883c3a1c61d3febbcc18b6bf70553ae45a0
# update seal_config.yaml with APP_PACKAGE_ID inside the enclave

# in the enclave: build, run and expose
make build ENCLAVE_APP=seal-example && make run && sh expose_enclave.sh

# record the pcrs 
cat out/nitro.pcrs

PCR0=974fc964c1602b8346971fd8e3a92ea0d94c1993f2e349f1d2d046d5a6e4b1dc5cba8c08fc3448a05ef87f6ab8447d60
PCR1=974fc964c1602b8346971fd8e3a92ea0d94c1993f2e349f1d2d046d5a6e4b1dc5cba8c08fc3448a05ef87f6ab8447d60
PCR2=21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a

# populate name and url
MODULE_NAME=weather
OTW_NAME=WEATHER
ENCLAVE_URL=http://<PUBLIC_IP>:3000

# update pcrs
sui client call --function update_pcrs --module enclave --package $ENCLAVE_PACKAGE_ID --type-args "$APP_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID 0x$PCR0 0x$PCR1 0x$PCR2

# optional, update name
sui client call --function update_name --module enclave --package $ENCLAVE_PACKAGE_ID --type-args "$APP_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID "some name here"

# register the enclave onchain 
sh register_enclave.sh $ENCLAVE_PACKAGE_ID $APP_PACKAGE_ID $ENCLAVE_CONFIG_OBJECT_ID $ENCLAVE_URL $MODULE_NAME $OTW_NAME

# read from output the created enclave obj id and finds its initial shared version. 
ENCLAVE_OBJECT_ID=0x926b69b1c193ceb8ce4df0938c9d9f16fc9f4812abb7e8a9fac386d773ff91e1
ENCLAVE_OBJ_VERSION=658809575
```

Currently, the enclave is running but has no `SEAL_API_KEY` and cannot process requests. 

```bash
curl -H 'Content-Type: application/json' -d '{"payload": { "location": "San Francisco"}}' -X POST http://<PUBLIC_IP>:3000/process_data

{"error":"API key not initialized. Please complete key load first."}%
```

### Step 1: Encrypt Secret

The Seal CLI command can be ran in the root directory of [Seal repo](https://github.com/MystenLabs/seal). This step can be done anywhere where the secret value is secure. The output is later used for step 4.

This command looks up the public keys of the specified key servers ID using public fullnode on the given network. Then it uses the identity `id`, threshold `t`, the specified key servers `-k` and the policy package `-p` to encrypt the secret. 

```bash
# in seal repo
APP_PACKAGE_ID=0x2080f9c370ddb22c48d6377f8aa64883c3a1c61d3febbcc18b6bf70553ae45a0
ENCLAVE_OBJECT_ID=0x926b69b1c193ceb8ce4df0938c9d9f16fc9f4812abb7e8a9fac386d773ff91e1
cargo run --bin seal-cli encrypt --secret 303435613237383132646265343536333932393133323233323231333036 \
    --id $ENCLAVE_OBJECT_ID \
    -p $APP_PACKAGE_ID \
    -t 2 \
    -k 0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75,0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8 \
    -n testnet

Encrypted object:
<ENCRYPTED_OBJECT>
```

`--secret`: The secret value you are encrypting in Hex format. Only the enclave has access to decrypt it. The `weather-api-key` converted from UTF-8 to hex in python:

```python
>>> '045a27812dbe456392913223221306'.encode('utf-8').hex()
'303435613237383132646265343536333932393133323233323231333036'
```

`--id`: The enclave object ID. This is the idenity used to encrypt any data to the enclave. 
`-p`: The package ID containing the Seal policy (the APP_PACKAGE_ID from Step 0).
`-k`: A list of key server object ids. Here we use the two Mysten open testnet servers.
`-t`: Threshold used for encryption.
`-n`: The network of the key servers you are using.

### Step 2: Initialize Key Load

This step is done in the host that the enclave runs in, that can communicate to the enclave via port 3001.

In this call, the enclave creates a certificate and constructs a PTB calling `seal_approve` with the enclave object ID. The enclave wallet signs the enclave's public key to commit to it. A session key signs the request and returns the encoded FetchKeyRequest.

```bash
curl -X POST http://localhost:3001/admin/init_seal_key_load \
  -H 'Content-Type: application/json' \
  -d '{"enclave_object_id": "'$ENCLAVE_OBJECT_ID'", "initial_shared_version": '$ENCLAVE_OBJ_VERSION'}'

# Expected response:
{"encoded_request":"<FETCH_KEY_REQUEST>"}
```

### Step 3: Fetch Keys from Seal Servers

The Seal CLI command can be run in the root of [Seal repo](https://github.com/MystenLabs/seal). This can be done anywhere with any Internet connection. Replace `<FETCH_KEY_REQUEST>` with the output from Step 2.


This command parses the Hex encoded BCS serialized `FetchKeyRequest` and fetches keys from the specified key server objects for the given network. Each key server verifies the PTB and signature, then returns encrypted key shares (encrypted to enclave's ephemeral ElGamal key) if the Seal policy is satisfied. The CLI gathers all responses and return a Hex encoded value containing a list of Seal object IDs and its server responses.

```bash
# in seal repo
cargo run --bin seal-cli fetch-keys --request <FETCH_KEY_REQUEST> \
    -k 0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75,0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8 \
    -t 2 \
    -n testnet

Encoded seal responses:
<ENCODED_SEAL_RESPONSES>
```

`--request`: Output of step 2. 
`-k`: A list of key server object ids, here we use the two Mysten open testnet servers. 
`-t`: Threshold used for encryption. 
`-n`: The network of the key servers you are using.

### Step 4: Complete Key Load

This step is done in the host that the enclave runs in, that can communicate to the enclave via 3001. If it returns OK, the enclave decrypts and caches the Seal keys in memory. Replace `<ENCODED_SEAL_RESPONSES>` with the output from Step 3.


```bash
curl -X POST http://localhost:3001/admin/complete_seal_key_load \
  -H "Content-Type: application/json" \
  -d '{
    "seal_responses": "<ENCODED_SEAL_RESPONSES>"
  }'

# Expected response:
{"status":"OK"}
```

### Step 5: Provision Weather API Key

This step is done in the host that the enclave runs in, that can communicate to the enclave via port 3001. Replace `<ENCRYPTED_OBJECT>` with the output from Step 1.

In this call, the enclave uses the cached keys from Step 4 to decrypt the encrypted weather API key. This endpoint is application specific and replace or add more if needed. Repeat step 1 to encrypt other data to the enclave object ID and provision them to the enclave with an endpoint. 

```bash
curl -X POST http://localhost:3001/admin/provision_weather_api_key \
  -H "Content-Type: application/json" \
  -d '{
    "encrypted_object": "<ENCRYPTED_OBJECT>"
  }'

# Expected response:
{"status":"OK"}
```

### Step 6: Use the Service

Now the enclave server is fully functional to process data. 

```bash
curl -H 'Content-Type: application/json' -d '{"payload": { "location": "San Francisco"}}' -X POST http://<PUBLIC_IP>:3000/process_data

# Example response: 
{"response":{"intent":0,"timestamp_ms":1755805500000,"data":{"location":"San Francisco","temperature":18}},"signature":"4587c11eafe8e78c766c745c9f89b3bb7fd1a914d6381921e8d7d9822ddc9556966932df1c037e23bedc21f369f6edc66c1b8af019778eb6b1ec1ee7f324e801"}
```

## Handle Multiple Secrets

Since Seal uses public key encryption, one can encrypt many secrets to the enclave ID. Repeat step 1 with any data, using the same package ID and the same enclave object ID. 

Run steps 2-4 once to cache the Seal keys for the enclave ID.

Once keys are cached, decrypt any encrypted object by implementing one or more provision endpoints similar to step 5. 

## Multiple Enclaves

Multiple enclaves can access the same Seal encrypted secret. An alternative it to use one enclave to provision to other attested enclaves directly, without needing to fetch keys from Seal.

## Troubleshooting

1. Certificate expired error in Step 3: The certificate in the `FetchKeyRequest` expires after 30 minutes (TTL). Re-run Step 2 or update default to generate a fresh request with a new certificate, then retry Step 3.

2. Enclave Restarts: If the enclave restarts, all ephemeral keys (including cached Seal keys) are lost. You must re-run Steps 2-5 to reinitialize the enclave with secrets.