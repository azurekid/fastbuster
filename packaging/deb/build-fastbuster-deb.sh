#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found. Install it with: sudo apt install -y dpkg-dev"
  exit 1
fi

mkdir -p "${OUT_DIR}"
BUILD_ROOT="$(mktemp -d)"
trap 'rm -rf "${BUILD_ROOT}"' EXIT

PKG_NAME="fastbuster_${VERSION}_all"
PKG_ROOT="${BUILD_ROOT}/${PKG_NAME}"

mkdir -p "${PKG_ROOT}/DEBIAN"
mkdir -p "${PKG_ROOT}/usr/lib/fastbuster"
mkdir -p "${PKG_ROOT}/usr/lib/fastbuster/fastbusterlib"
mkdir -p "${PKG_ROOT}/usr/bin"
mkdir -p "${PKG_ROOT}/usr/share/doc/fastbuster/examples"

cp "${ROOT_DIR}/fastbuster.py" "${PKG_ROOT}/usr/lib/fastbuster/fastbuster.py"
cp -R "${ROOT_DIR}/fastbusterlib/." "${PKG_ROOT}/usr/lib/fastbuster/fastbusterlib/"
cp "${ROOT_DIR}/example-wordlist.txt" "${PKG_ROOT}/usr/share/doc/fastbuster/examples/example-wordlist.txt"
cp "${ROOT_DIR}/README.md" "${PKG_ROOT}/usr/share/doc/fastbuster/README.md"
cp "${ROOT_DIR}/LICENSE" "${PKG_ROOT}/usr/share/doc/fastbuster/LICENSE"

cat > "${PKG_ROOT}/usr/bin/fastbuster" <<'EOF'
#!/usr/bin/env bash
# PYTHON_ARGCOMPLETE_OK
exec /usr/bin/python3 /usr/lib/fastbuster/fastbuster.py "$@"
EOF
chmod 0755 "${PKG_ROOT}/usr/bin/fastbuster"

mkdir -p "${PKG_ROOT}/usr/share/bash-completion/completions"
cat > "${PKG_ROOT}/usr/share/bash-completion/completions/fastbuster" <<'EOF'
# Enable tab-completion for fastbuster via argcomplete.
if command -v register-python-argcomplete >/dev/null 2>&1; then
  eval "$(register-python-argcomplete fastbuster)"
fi
EOF
chmod 0755 "${PKG_ROOT}/usr/lib/fastbuster/fastbuster.py"

cat > "${PKG_ROOT}/DEBIAN/control" <<EOF
Package: fastbuster
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: fastbuster maintainers
Depends: python3, python3-aiohttp, python3-uvloop, python3-argcomplete
Description: High-speed wordlist-driven web path scanner
 FastBuster is an async, high-concurrency web path scanner for authorized security testing.
 It supports large wordlists, response filters, output formats, resume checkpoints,
 wildcard detection, and adaptive auto-tuning.
EOF

OUTPUT_DEB="${OUT_DIR}/${PKG_NAME}.deb"
dpkg-deb --root-owner-group --build "${PKG_ROOT}" "${OUTPUT_DEB}"

echo "Built package: ${OUTPUT_DEB}"
