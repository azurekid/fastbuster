#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_DIR="${ROOT_DIR}/dist/apt-repo"

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
  echo "dpkg-scanpackages not found. Install it with: sudo apt install -y dpkg-dev"
  exit 1
fi

"${SCRIPT_DIR}/build-fastbuster-deb.sh" "${VERSION}"

mkdir -p "${REPO_DIR}"
cp -f "${ROOT_DIR}/dist/fastbuster_${VERSION}_all.deb" "${REPO_DIR}/"

pushd "${REPO_DIR}" >/dev/null
dpkg-scanpackages --multiversion . > Packages
gzip -9f Packages
popd >/dev/null

LIST_FILE="/etc/apt/sources.list.d/fastbuster-local.list"

echo "Adding local APT source: ${LIST_FILE}"
echo "deb [trusted=yes] file:${REPO_DIR} ./" | sudo tee "${LIST_FILE}" >/dev/null

sudo apt update

echo "Installing fastbuster from local APT repo"
sudo apt install -y fastbuster

echo "Done. Try: fastbuster --help"
