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

### 4. Initialize with Encrypted Secret

From the host machine, use the `encrypt-secret-to-seal` command to encrypt and send your secret:

```bash
# Basic usage - encrypts a secret with default key name "API_KEY"
./src/nautilus-server/target/debug/encrypt-secret-to-seal "your-weather-api-key"

# Specify a custom key name for the secret
./src/nautilus-server/target/debug/encrypt-secret-to-seal "your-secret-value" --key-name "MY_SECRET"

# Use a custom config file
./src/nautilus-server/target/debug/encrypt-secret-to-seal "your-secret" \
    --config /path/to/your/seal_config.yaml

# Override specific parameters from the config file
./src/nautilus-server/target/debug/encrypt-secret-to-seal "your-secret" \
    --threshold 3 \
    --enclave-host 192.168.1.10
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

The `encrypt-secret-to-seal` command supports the following options:

```
USAGE:
    encrypt-secret-to-seal <SECRET> [OPTIONS]

ARGUMENTS:
    <SECRET>                      The secret to encrypt (required)

OPTIONS:
    -n, --key-name <NAME>         Name for the secret in the enclave [default: API_KEY]
    -c, --config <FILE>           Path to seal_config.yaml file 
                                  [default: ./src/nautilus-server/src/examples/seal/seal_config.yaml]
    -p, --package-id <HEX>        Package ID (32-byte hex string) - overrides config file
    -s, --key-servers <HEX>       Comma-separated list of key server IDs - overrides config file
    -t, --threshold <NUM>         Threshold for decryption - overrides config file
    -e, --enclave-host <HOST>     Enclave host address - overrides config file
        --enclave-port <PORT>     Enclave init port - overrides config file
    -h, --help                    Print help information
    -V, --version                 Print version information
```

## Configuration File Format

The `seal_config.yaml` file should contain:

```yaml
package_id: "0xba06ef0fd022b4831e49de32d032b185cf7ea0b9ac1ea168f9ba952f37775936"

key_servers:
  - "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75"
  - "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"

threshold: 2

# Optional: enclave connection settings
enclave:
  host: "localhost"
  port: 3001
```

## Example with Real Object IDs

If you have actual Seal infrastructure deployed:

1. Update your `seal_config.yaml` with real object IDs:

```yaml
package_id: "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
key_servers:
  - "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  - "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
  - "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
threshold: 2
```

2. Run the command:

```bash
./target/debug/encrypt-secret-to-seal "your-actual-api-key"
```

## How It Works

1. **Configuration**: The command reads parameters from `seal_config.yaml` (or command-line overrides).

2. **Encryption**: Your secret is encrypted using Seal's encryption scheme with the configured package ID and key server information.

3. **Transmission**: The encrypted data is sent to the enclave's `/init` endpoint on port 3001 (localhost only).

4. **Storage**: The enclave stores the encrypted secret with the specified key name (default: "API_KEY") in memory.

5. **Usage**: When the enclave needs the secret, it will decrypt it using Seal (decryption implementation to be added).

## Examples of Secrets You Can Encrypt

- **API Keys**: Weather API, Twitter API, or any external service API key
- **Database Credentials**: Database passwords or connection strings
- **Encryption Keys**: Master keys for data encryption
- **Authentication Tokens**: OAuth tokens, JWT secrets, etc.

```bash
# Weather API key
./target/debug/encrypt-secret-to-seal "your-weather-api-key"

# Database password
./target/debug/encrypt-secret-to-seal "db-password-123" --key-name "DB_PASSWORD"

# JWT secret
./target/debug/encrypt-secret-to-seal "my-jwt-secret-key" --key-name "JWT_SECRET"
```

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

You can store multiple encrypted secrets by running the command multiple times with different key names:

```bash
# Encrypt and store weather API key
./target/debug/encrypt-secret-to-seal "weather-api-key-123"

# Encrypt and store database password
./target/debug/encrypt-secret-to-seal "my-db-password" --key-name "DB_PASSWORD"

# Encrypt and store another API key
./target/debug/encrypt-secret-to-seal "twitter-api-key" --key-name "TWITTER_API_KEY"
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