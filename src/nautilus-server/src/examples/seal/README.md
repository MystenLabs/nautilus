# Seal Example - Encrypted Secret Storage

This example demonstrates how to pass encrypted secrets to the enclave using Seal encryption instead of AWS Secret Manager. It maintains full compatibility with the existing weather and twitter examples while adding Seal encryption capabilities.

1. Configure and Run the Enclave

```bash
# Configure the EC2 instance with seal example
./configure_enclave.sh seal

# SSH into the instance and build
make EXAMPLE=seal
make run

```

2. Initialize with Encrypted Secret

From the host machine, use the `encrypt-secret-to-seal` command to encrypt and send your secret:

```bash
./src/nautilus-server/target/debug/encrypt-secret-to-seal "your-weather-api-key"
```
