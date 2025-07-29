# Nautilus: Verifiable offchain computation on Sui

Nautilus is a framework for **secure and verifiable off-chain computation on Sui**. For full product details, see the [Nautilus documentation](https://docs.sui.io/concepts/cryptography/nautilus).

This repository includes a reproducible build template for AWS Nitro Enclaves, along with patterns and examples for hybrid application development. For a complete end-to-end example, see the [Nautilus Twitter repository](https://github.com/MystenLabs/nautilus-twitter).

> [!IMPORTANT]
> The reproducible build template is intended as a starting point for building your own enclave. It is not feature complete, has not undergone a security audit, and is offered as a modification-friendly reference licensed under the Apache 2.0 license. THE TEMPLATE AND ITS RELATED DOCUMENTATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND FOR EVALUATION PURPOSES ONLY. You can adapt and extend it to fit your specific use case.

## Contact Us
For questions about Nautilus, use case discussions, or integration support, contact the Nautilus team on [Sui Discord](https://discord.com/channels/916379725201563759/1361500579603546223).

## Seal Example - Encrypted Secret Storage

This example demonstrates how to pass encrypted secrets to the enclave using Seal encryption instead of AWS Secret Manager. It maintains full compatibility with the existing weather and twitter examples while adding Seal encryption capabilities.

### 1. Configure and Run the Enclave

```bash
# Configure the EC2 instance with seal example
./configure_enclave.sh seal

# SSH into the instance and build
make EXAMPLE=seal-example
make run
```

### 2. Initialize with Encrypted Secret

From the host machine, use the `seal_cli` to encrypt your secret and fetch decryption keys:

```bash
# First, encrypt your secret (creates encrypted_secret.json)
./src/nautilus-server/target/debug/seal_cli encrypt "your-weather-api-key" \
  --config ./seal_config.yaml \
  --output encrypted_secret.json

# Then fetch keys from Seal servers
./src/nautilus-server/target/debug/seal_cli fetch-keys \
  --session-id "unique-session-id" \
  --config ./seal_config.yaml \
  --enclave-url http://localhost:3001 \
  --encrypted-file encrypted_secret.json \
  --sui-rpc https://fullnode.mainnet.sui.io:443
```

### 3. API Endpoints

#### `/init` - Initialize Parameter Load (Step 1)

Request body:
```json
{
  "session_id": "unique-session-id",
  "package_id": "0x1234...5678",  // 64-char hex string (32 bytes)
  "enclave_object_id": "0xabcd...ef01"  // Enclave object ID on chain
}
```

Response:
```json
{
  "request_body": {
    "ptb": "base64-encoded-PTB",
    "enc_key": [/* ElGamal public key bytes */],
    "enc_verification_key": [/* verification key bytes */],
    "request_signature": [/* signature bytes */],
    "certificate": {
      "address": "0x...",
      "session_vk": [/* session verification key */],
      "creation_time": 1234567890,
      "ttl_min": 60,
      "signature": [/* wallet signature bytes */]
    }
  }
}
```

#### `/complete` - Complete Parameter Load (Step 2)

Request body:
```json
{
  "session_id": "unique-session-id",
  "encrypted_object": {
    "version": 1,
    "package_id": [/* 32 bytes */],
    "id": [/* object ID bytes */],
    "services": [[/* service ID bytes */, /* index */]],
    "threshold": 2,
    "encrypted_shares": {
      "BonehFranklinBLS12381": {
        "nonce": [/* nonce bytes */],
        "encrypted_shares": [[/* share bytes */]],
        "encrypted_randomness": [/* randomness bytes */]
      }
    },
    "ciphertext": {
      "Aes256Gcm": {
        "blob": [/* encrypted data bytes */],
        "aad": null
      }
    }
  },
  "seal_responses": [
    {
      "server_id": "0x...",
      "decryption_keys": [
        {
          "id": "key-id",
          "encrypted_key": [/* encrypted key bytes */]
        }
      ]
    }
  ]
}
```

Response:
```json
{
  "decrypted_data": {
    "message": "Decrypted content or status",
    "object_id": "0x..."
  }
}
```
