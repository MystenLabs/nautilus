# Seal-Nautilus Pattern

This example is currently WIP. Use it as a reference only. 

The Seal-Nautilus pattern provides secure secret management for enclave applications, ensuring the Seal secret is only accessible within the attested enclaves. Here we reuse the weather example: Instead of storing the `weather-api-key` with AWS Secret Manager, we store it with Seal, and show that only the enclave with the expected PCRs has access to it. 

## Components

1. Nautilus server running inside AWS Nitro Enclave (`src/nautilus-server/src/apps/seal-example`): This is the only place that the Seal secret can be decrypted according to the policy. It exposes the endpoints at port 3000 to the Internet with the `/get_attestation` and `/process_data` endpoints. It also exposes port 3001 to the local host, which can only be used to initialize and complete the bootstrap steps inside the instance that the enclave runs.

2. Seal [CLI](https://github.com/MystenLabs/seal/tree/main/crates/seal-cli): In particular, `encrypt` and `fetch-keys` are used for this example. The latest doc for the CLI can be found [here](https://seal-docs.wal.app/SealCLI/#7-encrypt-and-fetch-keys-using-service-providers). 

3. Move contract `move/seal-policy/seal_policy.move`: This defines the `seal_approve` policy using the enclave object. 

## Overview

Phase 1: Start and register the server

1. The admin specifies the `seal_config.yaml` with the published Seal policy package ID and Seal configurations. Then the admin builds and runs the enclave with exposed `/get_attestation` endpoint. 
2. Admin uses the attestation response to register PCRs and the enclave public key. The `/process_data` endpoint currently returns an error because the `SEAL_API_KEY` is not yet initialized.
3. Admin registers the enclave on-chain and get enclave object ID and initial shared version. 

Phase 2: Bootstrap the secret in two steps

1. Admin encrypts the secret with a specified key ID. This can be done for multiple secrets with different IDs. 
2. Host calls `/init_parameter_load` with the enclave object and a list of key IDs used for encryption. Enclave returns the encoded `FetchKeyRequest`.
3. Admin uses CLI to fetch encrypted keys from Seal servers to get Seal responses. 
4. Host calls `/complete_parameter_load` with all encrypted objects from step 1 and the Seal responses from step 3. Enclave decrypts the secret(s) and initializes `SEAL_API_KEY`. 
5. Enclave can now serve `/process_data` requests. 

### Why bootstrap requires two steps?

This is because an enclave operates without direct internet access so it cannot fetch secrets from Seal key servers' http endpoints themselves. Here we use the host acts as an intermediary to fetch encrypted secrets from Seal servers. 

This delegation is secure because the Seal responses are encrypted under the enclave's encryption key, so only the enclave can later decrypt the fetched Seal responses. The enclave is also initialized with the public keys of the Seal servers in `seal_config.yaml`, which can be used to verify the decrypted secrets are not tampered with.

## Security Guarantees

The enclave generates an encryption secret key during initialization and this key never leaves the enclave memory. Seal servers encrypt the secret to the encryption public key, part of the `FetchKeyRequest` returned from `/init_parameter_load`. The host uses the CLI to fetch keys from Seal servers, but the host cannot decrypt the `FetchKeyResponse`. The `FetchKeyResponse` is passed to the enclave at `/complete_parameter_load`, and only the enclave can verify the consistency and decrypt the secret. 

Recall that the enclave also generates an ephemeral secret key on startup, that is only accessible in the enclave memory. The on-chain `seal_approve` function verifies the transaction sender is consistent with the enclave's registered ephemeral public key. During `/init_parameter_load`, a signature is created using the ephemeral secret key, committed over the PTB containing the Seal policy. As part of the `FetchKeyRequest`, this signature is later verified when Seal servers dry run the transaction. This ensures only the enclave can produce such signatures that can result in successful Seal responses.

```move
entry fun seal_approve<T: drop>(_id: vector<u8>, enclave: &Enclave<T>, ctx: &TxContext) {
    assert!(ctx.sender().to_bytes() == pk_to_address(enclave.pk()), ENoAccess);
}

fun pk_to_address(pk: &vector<u8>): vector<u8> {
    let mut arr = vector[0u8];
    arr.append(*pk);
    let hash = blake2b256(&arr);
    hash
}
```

Here we assume the enclave's ephemeral key scheme is Ed25519 so flag is `0x00`. A Sui address is derived as the `blake2b_hash(flag || pk)`. The `id` can be anything that uniquely identifies the key. 

## Steps

### Step 0: Build, Run and Register Enclave

This is the same as the Nautilus template. Refer to the main guide for more detailed instructions. 

```shell
# publish the enclave package
cd move/enclave
sui move build && sui client publish

ENCLAVE_PACKAGE_ID=0xe796d3cccaeaa5fd615bd1ac2cc02c37077471b201722f66bb131712a86f4ab6

# publish the app package
cd move/seal-example
sui move build && sui client publish

CAP_OBJECT_ID=0x55bb39cf70fb646ef4b008fd8e4195a4753e6af1817df830f26215178c4a6cf3
ENCLAVE_CONFIG_OBJECT_ID=0x57af8a8bde16bc99966d257765d1097a74ad36fb4c4cb632669e34224345b317
APP_PACKAGE_ID=0x82dc1ccc20ec94e7966299aa4398d9fe0333ab5c138dee5f81924b7b59ec48d8
# update seal_config.yaml with APP_PACKAGE_ID inside the enclave

# in the enclave: build, run and expose
make build ENCLAVE_APP=seal-example && make run && sh expose_enclave.sh

# record the pcrs 
cat out/nitro.pcrs

PCR0=396572221bd41001a0cc69467e7eb51ed486d364ceea37846970db1e9c32d6ba9e305fd22becbb4fa7addd8d3e9f95d6
PCR1=396572221bd41001a0cc69467e7eb51ed486d364ceea37846970db1e9c32d6ba9e305fd22becbb4fa7addd8d3e9f95d6
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
ENCLAVE_OBJECT_ID=0xac877b48ea0b2a03c9e5c7143661897ae925ae66f5acfe88ff80285cd17874e5
ENCLAVE_OBJ_VERSION=597601675
```

Currently, the enclave is running but has no `SEAL_API_KEY` and cannot process requests. 

```bash
curl -H 'Content-Type: application/json' -d '{"payload": { "location": "San Francisco"}}' -X POST http://<PUBLIC_IP>:3000/process_data

{"error":"API key not initialized. Please complete parameter load first."}%
```

### Step 1: Encrypt Secret

The Seal CLI command can be ran in the root directory of [Seal repo](https://github.com/MystenLabs/seal). This step can be done anywhere where the secret value is secure. The output is later used for step 4.

This command looks up the public keys of the specified key servers ID using public fullnode on the given network. Then it uses the identity `id`, threshold `t`, the specified key servers `-k` and the policy package `-p` to encrypt the secret. 

```bash
# in seal repo
APP_PACKAGE_ID=0x82dc1ccc20ec94e7966299aa4398d9fe0333ab5c138dee5f81924b7b59ec48d8
cargo run --bin seal-cli encrypt --secrets 303435613237383132646265343536333932393133323233323231333036,0101 \
    --ids 0000,0001 \
    -p $APP_PACKAGE_ID \
    -t 2 \
    -k 0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75,0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8 \
    -n testnet

# Output: <ENCRYPTED_OBJECT>
```

`--secrets`: A list of secret values that you are encrypting, that later only the enclave has access to. Here we use the weather api key and a dummy secret `0101` as example. The `weather-api-key` converted from UTF-8 to hex in python: 

```python
>>> '045a27812dbe456392913223221306'.encode('utf-8').hex()'303435613237383132646265343536333932393133323233323231333036'
```

`--ids`: A list of identifiers that uniquely map to the list of secrets. They need to be consistent with the ones used in the `/init_parameter_load` request. Here we use `0000`, `0001` as an example. 
`-p`: The package ID is the package containing the Seal policy. Here we use <APP_PACKAGE_ID> from the earlier step. 
`-k`: A list of key server object ids, here we use the two Mysten open testnet servers. 
`-t`: Threshold used for encryption. 
`-n`: The network of the key servers you are using.

### Step 2: Load the encrypted secret to enclave

This step is done in the host that the enclave runs in, that can communicate to the enclave via port 3001. 

In this call, the enclave creates the certificate containing the constructed PTB calling `seal_approve` with enclave object ID. The enclave ephemeral key signs request with session key and returns encoded fetch key request. The `ids` is a list of IDs used in step 1.  

```bash
curl -X POST http://localhost:3001/seal/init_parameter_load -H 'Content-Type: application/json' -d '{"enclave_object_id": "<ENCLAVE_OBJECT_ID>", "initial_shared_version": <ENCLAVE_OBJ_VERSION>, "ids": ["0000", "0001"] }'

# Output: {"encoded_request": "<FETCH_KEY_REQUEST>"}
```

### Step 3: Fetch Keys from Seal Servers

The Seal CLI command can be run in the root of [Seal repo](https://github.com/MystenLabs/seal). This can be done with any Internet connection. 

This command parses the Hex encoded BCS serialized `FetchKeyRequest` and fetches keys from the specified key server objects for the given network. The key server verifies the PTB and signature, then returns encrypted key shares (encrypted to enclave's ephemeral ElGamal key) if the seal policy is satisfied. The response is an Hex encoded BCS serialized a list of Seal object IDs and its server responses. Note that the `<FETCH_KEY_REQUEST>` has a certificate expiry (defaults to 10 minutes), restart with step 2 if you receive errors that the certificate is expired. 

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

### Step 4: Complete Secret Loading

This step is done in the host that the enclave runs in, that can communicate to the enclave via 3001. The server decrypts the first secret and initializes it as the `SEAL_API_KEY`. It also returns the rest as dummy secrets as an example, remove as needed. 

```bash
curl -X POST http://localhost:3001/seal/complete_parameter_load \
  -H "Content-Type: application/json" \
  -d '{
    "encrypted_objects": "<ENCRYPTED_OBJECT>",
    "seal_responses": "<ENCODED_SEAL_RESPONSES>"
  }'

{"dummy_secrets":[[1,1]]}
```

In this call, the enclave uses its ephemeral secret key to decrypt key shares and performs threshold decryption to recover the secrets. Then the enclave finishes the bootstrap phase by storing the decrypted secret `SEAL_API_KEY` in memory.

### Step 5: Use the Service

Now the enclave server is fully functional to process data. 

```bash
curl -H 'Content-Type: application/json' -d '{"payload": { "location": "San Francisco"}}' -X POST http://<PUBLIC_IP>:3000/process_data

{"response":{"intent":0,"timestamp_ms":1755805500000,"data":{"location":"San Francisco","temperature":18}},"signature":"4587c11eafe8e78c766c745c9f89b3bb7fd1a914d6381921e8d7d9822ddc9556966932df1c037e23bedc21f369f6edc66c1b8af019778eb6b1ec1ee7f324e801"}
```

## Handle Multiple Secrets

In step 1, pass in a list of secrets and a list of IDs to get an encoded list of encrypted objects. At step 2, pass in all IDs from step 1 to `ids` in an array so the returned `FetchKeyRequest` is constructed over all IDs. Step 3 and step 4 are unchanged. 

In this example, we show that if multiple encrypted secrets are passed, it decrypts the first one as the weather api key and the rest are treated as dummy strings that are decrypted and returned in the response. Modify or remove the dummy logic with your own application if needed. 

## Multiple Enclaves

If you want to define multiple enclaves to have access to the same Seal encrypted secret, define the `seal_approve` with the `EnclaveConfig` object. Alternatively, an enclave can provision the secret to other attested enclaves directly, without needing to fetch keys from Seal. 