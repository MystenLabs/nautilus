# nautilus-local

Run Nautilus enclave applications locally without AWS Nitro. Boots the EIF in QEMU with a mock NSM device that provides attestation documents with a proper certificate chain.

## Quick Start

```bash
# Build
cd tools/nautilus-local && cargo build --release

# Run (boots EIF in QEMU, ~2.5 min on Apple Silicon)
./target/release/nautilus-local run ../../out/nitro.eif \
  --secrets '{"API_KEY":"your_key"}' \
  --memory 1G

# Test endpoints
curl http://localhost:3000/health_check
curl http://localhost:3000/get_attestation
```

## Prerequisites

- **QEMU** with x86_64 system emulation (`brew install qemu`)
- **Docker** (only for rebuilding mock-nsm binary)

## Commands

### `run` — Boot an EIF locally

```
nautilus-local run <eif-path> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--secrets <json>` | — | Inline JSON secrets |
| `--secrets-file <path>` | — | Path to secrets JSON file |
| `--port <n>` | 3000 | Host port mapping to enclave:3000 |
| `--secrets-port <n>` | 7777 | Host port for enclave:7777 |
| `--memory <size>` | 512M | VM memory (use `1G` for production EIFs) |
| `--cpus <n>` | 2 | VM CPU count |
| `--verbose` | false | Show full VM console output |
| `--qemu <path>` | auto-detect | Path to qemu-system-x86_64 |

### `attest` — Generate a standalone mock attestation

```
nautilus-local attest --public-key <hex>
```

Produces a hex-encoded COSE_Sign1 attestation document for offline testing.

## How It Works

```
┌─────────────────────────────────────┐
│  QEMU (x86_64, TCG emulation)      │
│                                     │
│  Alpine linux-virt kernel           │
│  ├── fuse.ko + cuse.ko (modules)   │
│  ├── mock-nsm (/dev/nsm via CUSE)  │
│  └── nautilus-server (from EIF)     │
│       ├── /health_check             │
│       ├── /get_attestation ──┐      │
│       └── /process_data      │      │
│                              │      │
│       ioctl(/dev/nsm) ◄──────┘      │
│       │                             │
│       ▼                             │
│  mock-nsm: CBOR decode request,    │
│  build cert chain, sign COSE_Sign1 │
│  with mock PCRs + ephemeral leaf   │
└─────────────────────────────────────┘
```

1. **EIF parsing** — Extracts kernel, ramdisk, and cmdline from the Nitro EIF format
2. **Kernel swap** — Replaces the Nitro kernel (which lacks PCI/NIC drivers) with Alpine linux-virt
3. **Overlay initrd** — Injects mock-nsm binary, kernel modules (e1000, fuse, cuse), and secrets
4. **QEMU boot** — Boots with TCG emulation, e1000 NIC, port-forwarded networking
5. **Mock NSM** — Creates `/dev/nsm` via CUSE, handles ioctl with the same protocol as real NSM

## Mock Attestation

The mock attestation is structurally identical to a real AWS Nitro attestation:
- Valid COSE_Sign1 envelope signed with ephemeral P-384 leaf key
- Proper X.509 certificate chain: fixed root CA → ephemeral leaf cert
- CBOR payload with module_id, timestamp, PCRs, certificate, cabundle
- Enclave's Ed25519 public key in the `public_key` field

**Differences from real Nitro:**
- PCRs are all zeros (not derived from actual enclave measurements)
- Certificate chain is rooted at a mock CA (not the AWS Nitro root CA)

## Testing with Sui Localnet (Full On-Chain E2E)

Mock attestations pass `load_nitro_attestation` on a patched Sui localnet.
This lets you test the complete flow locally — deploy contracts, register
enclaves, verify signatures — all without AWS.

### Automated (one command)

```bash
# Does everything: patch Sui, build, start localnet, boot enclave, register, verify
./scripts/test-localnet-e2e.sh

# Options
./scripts/test-localnet-e2e.sh --sui-dir ~/sui    # custom Sui repo path
./scripts/test-localnet-e2e.sh --skip-build        # skip Sui rebuild if already patched
./scripts/test-localnet-e2e.sh --port 3333         # custom port for nautilus-local
```

### Manual step-by-step

**1. Patch your Sui build** to trust the mock root CA:

```bash
./scripts/patch-sui-localnet.sh ~/sui
cd ~/sui && cargo build -p sui    # ~5 min first build
```

**2. Start localnet:**

```bash
cd ~/sui && RUST_LOG=off ./target/debug/sui start --with-faucet --force-regenesis
```

**3. Switch to localnet and get gas:**

```bash
# Use the locally built sui binary (version must match the localnet)
SUI=~/sui/target/debug/sui
$SUI client switch --env localnet
ADDR=$($SUI client active-address)
curl -s -X POST http://127.0.0.1:9123/gas \
  -H 'Content-Type: application/json' \
  -d "{\"FixedAmountRequest\":{\"recipient\":\"$ADDR\"}}"
```

**4. Start enclave:**

```bash
nautilus-local run out/nitro.eif --secrets '{"API_KEY":"..."}' --memory 1G --port 3333
```

**5. Publish Move packages:**

```bash
# test-publish works without needing Published.toml/environments config
$SUI client test-publish move/weather-example \
  --skip-dependency-verification \
  --build-env localnet \
  --with-unpublished-dependencies
```

Note the `PackageID` and `EnclaveConfig` object ID from the output.

**6. Register enclave on-chain:**

```bash
# Get attestation from nautilus-local
ATT_HEX=$(curl -s http://localhost:3333/get_attestation | python3 -c "import json,sys; print(json.load(sys.stdin)['attestation'])")

# Convert to Sui vector format
ATT_ARRAY=$(echo "$ATT_HEX" | python3 -c "
import sys
h = sys.stdin.read().strip()
vals = [str(int(h[i:i+2], 16)) + 'u8' for i in range(0, len(h), 2)]
print(f'[{\", \".join(vals)}]')
")

# Register
$SUI client ptb \
  --assign v "vector$ATT_ARRAY" \
  --move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6 \
  --assign result \
  --move-call "<PKG>::enclave::register_enclave<<PKG>::weather::WEATHER>" @<CONFIG_ID> result \
  --gas-budget 100000000
```

**7. Verify:** Check the output for a created `Enclave` shared object.

### How it works

The mock-nsm daemon generates attestations signed with a cert chain rooted at a
fixed mock CA (`tools/mock-nsm/mock-root-ca.pem`). The patch script replaces the
AWS Nitro root CA in Sui's source with this mock CA. The Sui validator then
accepts mock attestations as if they came from a real Nitro enclave.

> **Warning:** Never use the patched Sui binary for anything other than local
> development. The mock root CA is public and provides no security guarantees.

### Restoring the original Sui build

```bash
cp ~/sui/crates/sui-types/src/nitro_root_certificate.pem.bak \
   ~/sui/crates/sui-types/src/nitro_root_certificate.pem
```

## Rebuilding Pre-built Binaries

The repo includes pre-built binaries for convenience. To rebuild:

```bash
# Rebuild mock-nsm (requires Docker)
cd tools/mock-nsm
docker build --platform linux/amd64 -t mock-nsm-builder -f Dockerfile.build .
CID=$(docker create --platform linux/amd64 mock-nsm-builder /mock-nsm)
docker cp "$CID:/mock-nsm" ../nautilus-local/mock-nsm-x86_64
docker rm "$CID"

# Rebuild kernel modules (requires Docker)
cd tools/nautilus-local
docker build --platform linux/amd64 -t kernel-modules -f Dockerfile.kernel .
CID=$(docker create --platform linux/amd64 kernel-modules /bin/true)
docker cp "$CID:/out/fuse.ko" . && docker cp "$CID:/out/cuse.ko" .
docker rm "$CID"
```
