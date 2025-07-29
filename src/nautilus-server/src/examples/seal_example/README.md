# Seal Example - Encrypted Secret Storage

This example demonstrates how to pass encrypted secrets to the enclave using Seal encryption instead of AWS Secret Manager. It maintains full compatibility with the existing weather and twitter examples while adding Seal encryption capabilities.

1. Configure and Run the Enclave

```bash
# Configure the EC2 instance with seal example
./configure_enclave.sh seal

# SSH into the instance and build
make EXAMPLE=seal-example
make run

```

2. Initialize with Encrypted Secret

From the host machine, use the `encrypt-secret-to-seal` command to encrypt and send your secret:

```bash
./src/nautilus-server/target/debug/encrypt-secret-to-seal "your-weather-api-key"
```

## Seal Parameter Load API

The enclave provides two endpoints for retrieving encrypted parameters from Seal:

### `/seal/init_parameter_load` (POST)

Initializes a parameter retrieval session. This endpoint generates the necessary request body for fetching encrypted keys from Seal servers.

**Request:**
```json
{
  "session_id": "unique-session-id",
  "package_id": "hex-encoded-32-byte-package-id",
  "enclave_object_id": "hex-encoded-enclave-object-id"
}
```

**Response:**
```json
{
  "request_body": {
    "ptb": "base64-encoded-programmable-transaction-block",
    "enc_key": [/* ephemeral public key bytes */],
    "enc_verification_key": [/* ephemeral public key bytes */],
    "request_signature": [/* signature bytes */],
    "certificate": {
      "address": "hex-encoded-wallet-address",
      "session_vk": [/* session verification key bytes */],
      "creation_time": 1234567890,
      "ttl_min": 60,
      "signature": [/* certificate signature bytes */]
    }
  }
}
```

### `/seal/complete_parameter_load` (POST)

Completes the parameter retrieval by processing Seal server responses and decrypting the data.

**Request:**
```json
{
  "session_id": "unique-session-id",
  "encrypted_object": {
    "id": [/* object ID bytes */],
    "package_id": [/* 32-byte package ID */],
    "threshold": 2,
    "ciphertext": {
      "Plain": null
      // or "Aes256Gcm": { "blob": [...], "aad": [...] }
      // or "Hmac256Ctr": { "blob": [...], "aad": [...], "mac": [...] }
    }
  },
  "seal_responses": [
    {
      "server_id": 1,
      "decryption_keys": [
        {
          "id": [/* key ID bytes */],
          "dec_share": [/* decryption share bytes */]
        }
      ],
      "signature": [/* server signature bytes */]
    }
  ]
}
```

**Response:**
```json
{
  "decrypted_data": {
    // Decrypted content based on ciphertext type
  }
}
```

**Usage Example:**

1. Call `/seal/init_parameter_load` to get the request body
2. Use the request body to fetch encrypted keys from Seal servers
3. Call `/seal/complete_parameter_load` with the Seal responses to decrypt the data

Note: These endpoints are available on the host-only init server (port 3001) and require proper authentication.
