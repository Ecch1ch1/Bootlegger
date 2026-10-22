#!/usr/bin/env bash
set -e

VERSION="0.1.0"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) DEB_ARCH="amd64" ;;
    aarch64) DEB_ARCH="arm64" ;;
    *) DEB_ARCH="$ARCH" ;;
esac

PKG_NAME="bootlegger"
BUILD_DIR="target/debian/${PKG_NAME}_${VERSION}_${DEB_ARCH}"

echo "Building Debian/Ubuntu package for ${PKG_NAME} (${DEB_ARCH})..."

# 1. Compile release binary
cargo build --release -p bootlegger-cli

# 2. Setup Debian package tree
rm -rf "target/debian"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/bin"
mkdir -p "${BUILD_DIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "${BUILD_DIR}/usr/share/licenses/${PKG_NAME}"

# 3. Copy binaries and assets
install -m 755 target/release/bootlegger "${BUILD_DIR}/usr/bin/bootlegger"
install -m 644 README.md "${BUILD_DIR}/usr/share/doc/${PKG_NAME}/README.md"
install -m 644 LICENSE "${BUILD_DIR}/usr/share/licenses/${PKG_NAME}/copyright"

# 4. Generate control file
cat << CONTROL_EOF > "${BUILD_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Ecch1ch1 <bootlegger.omnivore184@passfwd.com>
Description: Plausible Deniability & Dilution Steganography for Covert Data Storage
 Bootlegger conceals secret payloads inside standard, valid archives (e.g. TAR)
 using micro-dispersion into block slack space, strict dilution budgets, and
 optional Tripwire anti-tamper pinning.
Homepage: https://github.com/Ecch1ch1/Bootlegger
CONTROL_EOF

# 5. Build .deb with dpkg-deb if available, or instruct user
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "${BUILD_DIR}"
    echo ""
    echo "✓ Generated Debian package: target/debian/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
    echo "Install via: sudo dpkg -i target/debian/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
else
    echo "⚠️  'dpkg-deb' not found on this system. Prepared package files in ${BUILD_DIR}."
    echo "On Debian/Ubuntu, run: dpkg-deb --build ${BUILD_DIR}"
fi
