# Seal-Nautilus Pattern

This example is currently WIP. Use it as a reference only. 

The Seal-Nautilus pattern provides secure secret management for enclave applications, where user can encrypt any secrets to an enclave binary.

One can define a Seal policy configured with specified PCRs of the enclave. Users can encrypt any data using Seal with a fixed ID, and only the enclave of the given PCRs can decrypt them. 

Here we reuse the weather example: Instead of storing the `weather-api-key` with AWS Secret Manager, we encrypt it using Seal, and show that only the enclave with the expected PCRs is able to decrypt and use it. 

## Components

1. Nautilus server running inside AWS Nitro Enclave (`src/nautilus-server/src/apps/seal-example`): This is the only place that the Seal secret can be decrypted according to the policy. It exposes the endpoints at port 3000 to the Internet with the `/get_attestation` and `/process_data` endpoints. It also exposes port 3001 to the `localhost` with 3 `/admin` endpoints, which can only be used to initialize and complete the key load steps on the host instance that the enclave runs.

2. Seal [CLI](https://github.com/MystenLabs/seal/tree/main/crates/seal-cli): In particular, `encrypt` and `fetch-keys` are used for this example. The latest doc for the CLI can be found [here](https://seal-docs.wal.app/SealCLI/#7-encrypt-and-fetch-keys-using-service-providers).

3. Move contract `move/seal-policy/seal_policy.move`: This defines the `seal_approve` policy that verifies the signature committed to the wallet public key using the enclave ephermal key. 

## Overview

> [!NOTE]
> Admin is someone that has access to the EC2 instance. He can build and run the enclave binary on it. He can also call the admin only enclave endpoints via localhost on the EC2 instance.

Phase 1: Start and Register the Server

1. Admin specifies the `seal_config.yaml` with the published Seal policy package ID and Seal configurations. Then the admin builds and runs the enclave with exposed `/get_attestation` endpoint. 

2. Admin uses the attestation response to register PCRs and the enclave public key. The `/process_data` endpoint currently returns an error because the `SEAL_API_KEY` is not yet initialized.

3. Admin registers the enclave on-chain and get enclave object ID and initial shared version. 

Phase 2: Initialize and Complete Key Load

4. Admin calls `/admin/init_seal_key_load` with the enclave object. Enclave returns an encoded `FetchKeyRequest`.

5. Admin uses FetchKeyRequest to call CLI to get Seal responses that are encrypted under the enclave's encryption public key.

6. Admin calls `/admin/complete_seal_key_load` with Seal responses. Enclave decrypts and caches all Seal keys in memory for later use.

Phase 3: Provision Application Secrets

7. Now that Seal keys are cached, encrypted objects can be decrypted on-demand using the cached keys. Specifically for our example, Admin calls `/admin/provision_weather_api_key` with the encrypted weather API key object. The enclave decrypts it using the cached keys and stores it as `SEAL_API_KEY`. 

8. Enclave can now serve `/process_data` requests. 

## Security Guarantees

The enclave generates 3 keys on startup, all kept only in enclave memory:

1. Enclave ephemeral keypair (`state.eph_kp`): Ed25519 keypair. Used to sign `/process_data` responses and to create the signature argument in `seal_approve` PTB. Its public key is registered on-chain in the Enclave object.
2. Seal wallet (`WALLET_BYTES`): Ed25519 keypair. Used for Seal certificate signing and as the transaction sender for `seal_approve`.
3. ElGamal encryption keypair (`ENCRYPTION_KEYS`): BLS group elements. Used to decrypt Seal responses.

During `/init_seal_key_load`, the wallet signs a PersonalMessage for the certificate. The enclave also creates a PTB for `seal_approve` where the signature argument is created by the enclave ephemeral keypair signing an intent message containing the wallet's public key and timestamp. When Seal servers dry-run the transaction, `seal_approve` verifies:

1. The signature is verified using the enclave's ephemeral public key (from `enclave.pk()`) and the intent message with scope `WalletPK` over the wallet public key and timestamp.
2. The key ID is a fixed value of `vector[0]`.
3. The transaction sender matches the wallet public key.

This proves that only the enclave (which has access to wallet and the ephemeral keypair) could have created a valid signed PTB, as the ephemeral keypair commits to the wallet public key. 

During `/init_seal_key_load`, the enclave also generates an encryption keypair and return the encryption public key as part of `FetchKeyRequest`. The fetch key CLI is called outside the enclave, but no one except the enclave can decrypt the `FetchKeyResponse` since only enclave has the encryption secret key. Then the `FetchKeyResponse` is passed to the enclave at `/complete_seal_key_load`, and only the enclave can verify and decrypt the Seal key in memory.

### Why Two Step Key Load is Needed for Phase 2?

This is because an enclave operates without direct internet access so it cannot fetch secrets from Seal key servers' HTTP endpoints directly. Here we use the host acts as an intermediary to fetch encrypted secrets from Seal servers. 

This delegation is secure because the Seal responses are encrypted under the enclave's encryption key, so only the enclave can later decrypt the fetched Seal responses. The public keys of the Seal servers in `seal_config.yaml` are defined by the admin in the enclave, so the enclave can verify the decrypted Seal key is not tampered with.

## Steps

### Step 0: Build, Run and Register Enclave

This is largely the as the main Nautilus template (Refer to the main guide `UsingNautilus.md` for 
more detailed instructions) with two additions:

1. Update `seal_config.yaml` used by the enclave. 
2. Record `ENCLAVE_OBJ_VERSION` in addition to `ENCLAVE_OBJECT_ID`.

```shell
# publish the enclave package
cd move/enclave
sui move build && sui client publish

# find this in output and set env var
ENCLAVE_PACKAGE_ID=0x8ecf22e78c90c3e32833d76d82415d7e4227ea370bec4efdad4c4830cbda9e49

# publish the seal-policy app package
cd ../seal-policy
sui move build && sui client publish

# find these in output and set env vars
CAP_OBJECT_ID=0xbd6ad872040eddc08f20ff11e20a3dc030c3e30f4ab2303a0c42447006724262
ENCLAVE_CONFIG_OBJECT_ID=0x3ee612ffc17f29280b8479c36a1096a339e38c353a7662baa559ba4d879dd4de
APP_PACKAGE_ID=0x7f0171b76f82cd61ebb4ac3fd502deac6552e9becd38be28d5692b69b5fdb54e

# update seal_config.yaml with APP_PACKAGE_ID inside the enclave

# configure ec2 instance for enclave, see main guide for more details: UsingNautilus.md

# ssh in the ec2 instance containing the repo on configured diff: docker build, run and expose
make ENCLAVE_APP=seal-example && make run && sh expose_enclave.sh

# find the pcrs and set env vars
cat out/nitro.pcrs

PCR0=84db3309c8a06c31c1c0a44701fb6c47766244925d7c1d32d5e6589cbdea23aa1f619cddc62c7368ffe648a07df2feb8
PCR1=84db3309c8a06c31c1c0a44701fb6c47766244925d7c1d32d5e6589cbdea23aa1f619cddc62c7368ffe648a07df2feb8
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

# read from output the created enclave obj id and finds its initial shared version 
ENCLAVE_OBJECT_ID=0x9b8bc44069abc9843bbd2f54b4e7732136cc7c615c34959f98ab2f7c74f002bd
ENCLAVE_OBJ_VERSION=722158400
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
# set package id from step 0
APP_PACKAGE_ID=0x2080f9c370ddb22c48d6377f8aa64883c3a1c61d3febbcc18b6bf70553ae45a0
cargo run --bin seal-cli encrypt --secret 303435613237383132646265343536333932393133323233323231333036 \
    --id 0x00 \
    -p $APP_PACKAGE_ID \
    -t 2 \
    -k 0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75,0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8 \
    -n testnet

Encrypted object:
<ENCRYPTED_OBJECT>
```

`--secret`: The secret value you are encrypting in Hex format. Only the enclave has access to decrypt it. Here we use an example value for  `weather-api-key` converted from UTF-8 to Hex:

```python
>>> '045a27812dbe456392913223221306'.encode('utf-8').hex()
'303435613237383132646265343536333932393133323233323231333036'
```

`--id`: A fixed value of 0x00. This is the identity used to encrypt any data to the enclave. 
`-p`: The package ID containing the Seal policy (the APP_PACKAGE_ID from Step 0).
`-k`: A list of key server object ids. Here we use the two Mysten open testnet servers.
`-t`: Threshold used for encryption.
`-n`: The network of the key servers you are using.

### Step 2: Initialize Key Load

This step is done in the host that the enclave runs in, that can communicate to the enclave via port 3001.

In this call, the enclave creates a certificate (signed by the wallet) and constructs a PTB calling `seal_approve`. The enclave ephemeral keypair signs an intent message of the wallet public key. A session key signs the request and returns the encoded FetchKeyRequest.

```bash
# use ENCLAVE_OBJECT_ID and ENCLAVE_OBJ_VERSION from step 0
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

In this call, the enclave uses the cached keys from Step 4 to decrypt the encrypted weather API key. This endpoint is application specific and replace or add more if needed. Repeat step 1 to encrypt other data using ID value 0 and provision them to the enclave with an endpoint. 

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

Since Seal uses public key encryption, one can encrypt many secrets using the same fixed ID value of 0. Repeat step 1 with any data, using the same package ID and the same ID value of 0.

Run steps 2-4 once to cache the Seal keys for the enclave.

Once keys are cached, decrypt any encrypted object by implementing one or more provision endpoints similar to step 5. 

## Multiple Enclaves

Multiple enclaves can access the same Seal encrypted secret. An alternative it to use one enclave to provision to other attested enclaves directly, without needing to fetch keys from Seal.

## Troubleshooting

1. Certificate expired error in Step 3: The certificate in the `FetchKeyRequest` expires after 30 minutes (TTL). Re-run Step 2 or update default to generate a fresh request with a new certificate, then retry Step 3.

2. Enclave Restarts: If the enclave restarts, all ephemeral keys (including cached Seal keys) are lost. You must re-run Steps 2-5 to reinitialize the enclave with secrets.