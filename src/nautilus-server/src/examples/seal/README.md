# Seal Example - Encrypted Secret Storage

This example demonstrates how to pass encrypted secrets to the enclave using Seal encryption instead of AWS Secret Manager. It maintains full compatibility with the existing weather and twitter examples while adding Seal encryption capabilities.

## Quick Start

### 1. Build the Enclave and Client

```bash
cd src/nautilus-server
cargo build --features seal-example
```

### 2. Run the Enclave

```bash
# Start the enclave with seal-example feature
cargo run --features seal-example
```

### 3. Configure and Run the Enclave

```bash
# Configure the EC2 instance with seal example
./configure_enclave.sh seal

# SSH into the instance and build
make EXAMPLE=seal
make run

# In another terminal on the instance, expose the enclave
./expose_enclave.sh
```

### 4. Initialize with Encrypted API Key

From the host machine, use the `seal-init-client` to encrypt and send your API key:

```bash
# The client will encrypt your API key and send it to the enclave
./src/nautilus-server/target/debug/seal-init-client \
    --api-key "your-weather-api-key" \
    --package-id "0x0000000000000000000000000000000000000000000000000000000000000001" \
    --key-servers "0x1111111111111111111111111111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333333333333333333333333333" \
    --threshold 2 \
    --enclave-host localhost \
    --enclave-port 3001
```

The client will:
1. Encrypt your API key using Seal encryption with the specified parameters
2. Send the encrypted data to the enclave via the `/set_encrypted_secret` endpoint
3. Store it with the key name "API_KEY"

### 5. Test the Weather API

Once initialized, test the weather endpoint:

```bash
curl -X POST http://localhost:3000/process_data \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "location": "San Francisco"
    }
  }'
```

## CLI Options

The `seal-init-client` supports the following options:

```
USAGE:
    seal-init-client [OPTIONS] --api-key <KEY> --package-id <HEX> --key-servers <HEX>

OPTIONS:
    -k, --api-key <KEY>           The Weather API key to encrypt
    -p, --package-id <HEX>        Package ID (32-byte hex string)
    -s, --key-servers <HEX>       Comma-separated list of key server IDs (32-byte hex strings)
    -t, --threshold <NUM>         Threshold for decryption [default: 2]
    -e, --enclave-host <HOST>     Enclave host address [default: localhost]
        --enclave-port <PORT>     Enclave init port [default: 3001]
    -h, --help                    Print help information
    -V, --version                 Print version information
```

## Example with Real Object IDs

If you have actual Seal infrastructure deployed:

```bash
# Replace with your actual object IDs
PACKAGE_ID="0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
KEY_SERVER_1="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
KEY_SERVER_2="0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
KEY_SERVER_3="0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"

./target/debug/seal-init-client \
    --api-key "your-actual-api-key" \
    --package-id "$PACKAGE_ID" \
    --key-servers "$KEY_SERVER_1,$KEY_SERVER_2,$KEY_SERVER_3" \
    --threshold 2
```

## How It Works

1. **Encryption**: The CLI tool encrypts your API key using Seal's encryption scheme with the provided package ID and key server information.

2. **Transmission**: The encrypted data is sent to the enclave's `/set_encrypted_secret` endpoint on port 3001 (localhost only).

3. **Storage**: The enclave stores the encrypted secret with the key name "API_KEY" in memory.

4. **Usage**: When processing weather requests, the enclave will decrypt the API key (decryption implementation to be added).

## Using the /set_encrypted_secret Endpoint

The seal example exposes a generic endpoint that accepts encrypted secrets:

```bash
POST http://localhost:3001/set_encrypted_secret
Content-Type: application/json

{
  "key": "API_KEY",  // The name for this secret
  "encrypted_object": {
    "version": 0,
    "package_id": [...],
    "id": [...],
    "services": [...],
    "threshold": 2,
    "encrypted_shares": {...},
    "ciphertext": {...}
  }
}
```

### Adding Multiple Secrets

You can store multiple encrypted secrets by calling the endpoint multiple times:

```bash
# Each call to seal-init-client encrypts and sends one secret
# The endpoint can be called multiple times with different keys
# Example: DB_PASSWORD, ANOTHER_API_KEY, etc.
```

## Security Notes

- The init endpoint (port 3001) only binds to localhost, making it inaccessible from outside the enclave
- The API key is never transmitted in plaintext
- The encryption uses threshold cryptography, requiring cooperation from multiple key servers for decryption
- In production, use real IBE public keys and properly generated object IDs

## Testing Without Real Seal Infrastructure

For testing purposes, the current implementation uses a simplified encryption. In production:
1. Replace the mock encryption with actual Seal SDK calls
2. Use real IBE public keys from your key servers
3. Implement proper decryption in the enclave