#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MOCK_CA="$REPO_DIR/tools/mock-nsm/mock-root-ca.pem"
TARGET="crates/sui-types/src/nitro_root_certificate.pem"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path-to-sui-repo>"
    echo ""
    echo "Patches a local Sui checkout to accept mock Nautilus attestations."
    echo "This replaces the AWS Nitro root CA with the mock-nsm root CA."
    echo ""
    echo "After patching, rebuild Sui:"
    echo "  cd <sui-repo> && cargo build -p sui"
    exit 1
fi

SUI_DIR="$1"

if [ ! -f "$SUI_DIR/$TARGET" ]; then
    echo "Error: $SUI_DIR/$TARGET not found"
    echo "Make sure the path points to a valid Sui repo checkout."
    exit 1
fi

# Backup original
cp "$SUI_DIR/$TARGET" "$SUI_DIR/$TARGET.bak"
echo "Backed up original to $TARGET.bak"

# Copy mock CA
cp "$MOCK_CA" "$SUI_DIR/$TARGET"
echo "Replaced $TARGET with mock CA"

echo ""
echo "Now rebuild Sui (this takes a few minutes):"
echo "  cd $SUI_DIR && cargo build -p sui"
echo ""
echo "Then start localnet:"
echo "  cd $SUI_DIR && RUST_LOG=off ./target/debug/sui start --with-faucet --force-regenesis"
echo ""
echo "To restore the original AWS root CA:"
echo "  cp $SUI_DIR/$TARGET.bak $SUI_DIR/$TARGET"
