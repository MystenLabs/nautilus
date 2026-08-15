#!/bin/bash
set -euo pipefail

# Full E2E test: patch Sui, start localnet, boot nautilus-local, register enclave on-chain.
#
# This script automates the entire flow that was manually verified:
#   1. Patch Sui with mock root CA
#   2. Build patched Sui
#   3. Start localnet with faucet
#   4. Boot nautilus-local (QEMU + EIF)
#   5. Publish Move packages
#   6. Register enclave using mock attestation
#   7. Verify on-chain registration
#
# Prerequisites:
#   - Sui repo checkout (default: ~/sui)
#   - Docker (for rebuilding mock-nsm if needed)
#   - QEMU (brew install qemu)
#   - nautilus-local built: cd tools/nautilus-local && cargo build --release
#   - EIF file at out/nitro.eif
#
# Usage:
#   ./scripts/test-localnet-e2e.sh [--sui-dir <path>] [--skip-build] [--port <port>]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SUI_DIR="${HOME}/sui"
SKIP_BUILD=false
PORT=3333
NAUTILUS_PID=""
SUI_PID=""

usage() {
    echo "Usage: $0 [--sui-dir <path>] [--skip-build] [--port <port>]"
    echo ""
    echo "  --sui-dir <path>   Path to Sui repo checkout (default: ~/sui)"
    echo "  --skip-build       Skip Sui rebuild (use if already patched+built)"
    echo "  --port <port>      Port for nautilus-local (default: 3333)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --sui-dir) SUI_DIR="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --port) PORT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

SUI="$SUI_DIR/target/debug/sui"

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    [ -n "$NAUTILUS_PID" ] && kill "$NAUTILUS_PID" 2>/dev/null && echo "Stopped nautilus-local"
    [ -n "$SUI_PID" ] && kill "$SUI_PID" 2>/dev/null && echo "Stopped Sui localnet"
    # Remove ephemeral publish files
    rm -f "$REPO_DIR/move/enclave/Pub.localnet.toml" "$REPO_DIR/move/weather-example/Pub.localnet.toml"
    rm -f "$REPO_DIR/Pub.localnet.toml"
}
trap cleanup EXIT

# ── Step 1: Patch Sui ──────────────────────────────────────────────────────
echo "=== Step 1: Patch Sui with mock root CA ==="
TARGET="crates/sui-types/src/nitro_root_certificate.pem"
MOCK_CA="$REPO_DIR/tools/mock-nsm/mock-root-ca.pem"

if [ ! -f "$SUI_DIR/$TARGET" ]; then
    echo "Error: $SUI_DIR/$TARGET not found. Pass --sui-dir <path>"
    exit 1
fi
if [ ! -f "$MOCK_CA" ]; then
    echo "Error: $MOCK_CA not found. Build mock-nsm first."
    exit 1
fi

# Backup and patch
if [ ! -f "$SUI_DIR/$TARGET.bak" ]; then
    cp "$SUI_DIR/$TARGET" "$SUI_DIR/$TARGET.bak"
fi
cp "$MOCK_CA" "$SUI_DIR/$TARGET"
echo "Patched $TARGET with mock CA"

# ── Step 2: Build Sui ──────────────────────────────────────────────────────
if [ "$SKIP_BUILD" = false ]; then
    echo ""
    echo "=== Step 2: Building patched Sui (this takes ~5 min) ==="
    (cd "$SUI_DIR" && cargo build -p sui 2>&1 | tail -3)
else
    echo ""
    echo "=== Step 2: Skipping Sui build (--skip-build) ==="
fi

if [ ! -f "$SUI" ]; then
    echo "Error: $SUI not found"
    exit 1
fi

# ── Step 3: Start localnet ─────────────────────────────────────────────────
echo ""
echo "=== Step 3: Start Sui localnet ==="
RUST_LOG=off "$SUI" start --with-faucet --force-regenesis &>/dev/null &
SUI_PID=$!

# Wait for RPC
echo "Waiting for RPC..."
for i in $(seq 1 60); do
    if curl -s --connect-timeout 1 http://127.0.0.1:9000 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"sui_getLatestCheckpointSequenceNumber","params":[]}' \
        2>/dev/null | grep -q result; then
        echo "RPC ready"
        break
    fi
    sleep 2
done

# Wait for faucet
echo "Waiting for faucet..."
for i in $(seq 1 30); do
    if curl -s --connect-timeout 1 http://127.0.0.1:9123/gas -X POST \
        -H 'Content-Type: application/json' -d '{"FixedAmountRequest":{"recipient":"0x0000000000000000000000000000000000000000000000000000000000000000"}}' \
        2>/dev/null | grep -q "Success\|error"; then
        echo "Faucet ready"
        break
    fi
    sleep 2
done

# Switch to localnet env
"$SUI" client switch --env localnet 2>/dev/null || \
    "$SUI" client new-env --alias localnet --rpc http://127.0.0.1:9000 2>/dev/null
"$SUI" client switch --env localnet 2>/dev/null

# Get gas from faucet
ADDR=$("$SUI" client active-address 2>/dev/null)
FAUCET_RESULT=$(curl -s -X POST http://127.0.0.1:9123/gas \
    -H 'Content-Type: application/json' \
    -d "{\"FixedAmountRequest\":{\"recipient\":\"$ADDR\"}}")
if echo "$FAUCET_RESULT" | grep -q "Success"; then
    echo "Localnet running, got gas for $ADDR"
else
    echo "Error: faucet request failed: $FAUCET_RESULT"
    exit 1
fi

# ── Step 4: Boot nautilus-local ────────────────────────────────────────────
echo ""
echo "=== Step 4: Boot nautilus-local (QEMU, ~2.5 min) ==="
NAUTILUS="$REPO_DIR/tools/nautilus-local/target/release/nautilus-local"
EIF="$REPO_DIR/out/nitro.eif"

if [ ! -f "$NAUTILUS" ]; then
    echo "Error: $NAUTILUS not found. Run: cd tools/nautilus-local && cargo build --release"
    exit 1
fi
if [ ! -f "$EIF" ]; then
    echo "Error: $EIF not found."
    exit 1
fi

"$NAUTILUS" run "$EIF" --secrets '{"API_KEY":"test"}' --memory 1G --port "$PORT" &>/dev/null &
NAUTILUS_PID=$!

echo "Waiting for enclave server on port $PORT..."
for i in $(seq 1 60); do
    if curl -s --connect-timeout 2 "http://localhost:$PORT/health_check" > /dev/null 2>&1; then
        echo "Ready after ~$((i * 5))s"
        break
    fi
    sleep 5
done

PK=$(curl -s "http://localhost:$PORT/health_check" | uv run python -c "import json,sys; print(json.load(sys.stdin)['pk'])" 2>/dev/null)
if [ -z "$PK" ]; then
    echo "Error: nautilus-local didn't start"
    exit 1
fi
echo "Enclave public key: $PK"

# ── Step 5: Publish Move packages ──────────────────────────────────────────
echo ""
echo "=== Step 5: Publish Move packages ==="

# Use test-publish (works with Sui 1.68+ without needing Published.toml)
CHAIN_ID=$("$SUI" client chain-identifier 2>/dev/null)

WEATHER_JSON=$("$SUI" client test-publish "$REPO_DIR/move/weather-example" \
    --skip-dependency-verification \
    --build-env localnet \
    --with-unpublished-dependencies \
    --json 2>/dev/null)

eval "$(echo "$WEATHER_JSON" | uv run python -c "
import json, sys
data = json.load(sys.stdin)
for obj in data.get('objectChanges', []):
    if obj.get('type') == 'published':
        print(f'PKG={obj[\"packageId\"]}')
    otype = obj.get('objectType', '')
    if 'EnclaveConfig' in otype:
        print(f'CONFIG={obj[\"objectId\"]}')
")"

echo "Package:       $PKG"
echo "EnclaveConfig: $CONFIG"

# ── Step 6: Register enclave ───────────────────────────────────────────────
echo ""
echo "=== Step 6: Register enclave on-chain ==="

ATT_HEX=$(curl -s "http://localhost:$PORT/get_attestation" | \
    uv run python -c "import json,sys; print(json.load(sys.stdin)['attestation'])")
echo "Attestation: $((${#ATT_HEX} / 2)) bytes"

ATT_ARRAY=$(echo "$ATT_HEX" | uv run python -c "
import sys
h = sys.stdin.read().strip()
vals = [str(int(h[i:i+2], 16)) + 'u8' for i in range(0, len(h), 2)]
print(f'[{\", \".join(vals)}]')
")

REGISTER_OUTPUT=$("$SUI" client ptb \
    --assign v "vector$ATT_ARRAY" \
    --move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6 \
    --assign result \
    --move-call "${PKG}::enclave::register_enclave<${PKG}::weather::WEATHER>" @${CONFIG} result \
    --gas-budget 100000000 2>&1)

echo "$REGISTER_OUTPUT" | tail -5

# ── Step 7: Verify ─────────────────────────────────────────────────────────
echo ""
echo "=== Step 7: Verify ==="

if echo "$REGISTER_OUTPUT" | grep -q "Enclave<"; then
    ENCLAVE_ID=$(echo "$REGISTER_OUTPUT" | grep -o '0x[0-9a-f]*' | head -1)
    echo ""
    echo "======================================"
    echo "  SUCCESS: Enclave registered on-chain"
    echo "  Enclave ID: $ENCLAVE_ID"
    echo "  Package:    $PKG"
    echo "  Public Key: $PK"
    echo "======================================"
else
    echo "FAILED: Enclave registration did not succeed"
    echo "$REGISTER_OUTPUT"
    exit 1
fi
