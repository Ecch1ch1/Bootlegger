#!/usr/bin/env bash
set -e

echo "🥾 Bootlegger Installer"
echo "========================"

TARGET_DIR="${HOME}/.local/bin"

if [ "$EUID" -eq 0 ]; then
    TARGET_DIR="/usr/local/bin"
fi

echo "Building release binary via cargo..."
cargo build --release -p bootlegger-cli

mkdir -p "${TARGET_DIR}"
install -m 755 target/release/bootlegger "${TARGET_DIR}/bootlegger"

echo ""
echo "✓ Successfully installed bootlegger to: ${TARGET_DIR}/bootlegger"

# Check if TARGET_DIR is in PATH
if [[ ":$PATH:" != *":${TARGET_DIR}:"* ]]; then
    echo ""
    echo "⚠️  ${TARGET_DIR} is not in your current PATH."
    echo "To run 'bootlegger' from anywhere, add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
else
    echo "🎉 You can now run 'bootlegger --help' from anywhere in your terminal!"
fi
