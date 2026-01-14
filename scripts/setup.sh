#!/bin/bash

set -e  # Exit on any error

echo "🚀 Setting up DA Builder Sample Integration"
echo "==========================================="

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust first:"
    echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Check if Foundry is installed
if ! command -v forge &> /dev/null; then
    echo "❌ Foundry is not installed. Please install Foundry first:"
    echo "   curl -L https://foundry.paradigm.xyz | bash"
    echo "   foundryup"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Install dependencies and build
echo "📦 Installing dependencies and building..."
forge install
echo "🔨 Building Solidity contracts and generating Rust bindings..."
cargo build --release

echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Generate a test wallet:"
echo "   cast wallet new"
echo ""
echo "2. Get Hoodi testnet ETH:"
echo "   https://hoodi-faucet.pk910.de/"
echo ""
echo "3. Set environment variables:"
echo ""
echo "   For Hoodi testnet (default):"
echo "   export PRIVATE_KEY=\"your_private_key_here\""
echo ""
echo "   For Mainnet:"
echo "   export PRIVATE_KEY=\"your_private_key_here\""
echo "   export TARGET_CHAIN=\"mainnet\""
echo "   export RPC_URL=\"your_non-da-builder_mainnet_rpc_endpoint\" # REQUIRED for mainnet"
echo ""
echo "4. Run the integration:"
echo "   cargo run --release" 