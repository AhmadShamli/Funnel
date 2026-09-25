#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-${VERSION:-0.4.5}}"
DIST_DIR="dist"
LDFLAGS="-s -w -X github.com/AhmadShamli/Funnel/internal/version.Version=${VERSION}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm/7"
)

for PLATFORM in "${PLATFORMS[@]}"; do
  IFS="/" read -r OS ARCH EXTRA <<< "${PLATFORM}"
  
  TARGET_NAME="funnel-v${VERSION}-${OS}-${ARCH}"
  if [ -n "${EXTRA:-}" ]; then
    TARGET_NAME="funnel-v${VERSION}-${OS}-${ARCH}v${EXTRA}"
  fi
  
  echo "==> Building ${TARGET_NAME}..."
  BUILD_DIR="dist/${TARGET_NAME}"
  mkdir -p "${BUILD_DIR}"
  
  BINARY_NAME="funnel"
  if [ "${OS}" = "windows" ]; then
    BINARY_NAME="funnel.exe"
  fi
  
  export CGO_ENABLED=0
  export GOOS="${OS}"
  export GOARCH="${ARCH}"
  if [ -n "${EXTRA:-}" ]; then
    export GOARM="${EXTRA}"
  else
    unset GOARM || true
  fi
  
  go build -trimpath -ldflags="${LDFLAGS}" -o "${BUILD_DIR}/${BINARY_NAME}" ./cmd/funnel
  cp LICENSE "${BUILD_DIR}/"
  cp README.md "${BUILD_DIR}/"
  cp .env.example "${BUILD_DIR}/"
  
  cd "${DIST_DIR}"
  if [ "${OS}" = "windows" ]; then
    zip -q -r "${TARGET_NAME}.zip" "${TARGET_NAME}"
  else
    tar -czf "${TARGET_NAME}.tar.gz" "${TARGET_NAME}"
  fi
  rm -rf "${TARGET_NAME}"
  cd ..
done

cd "${DIST_DIR}"
sha256sum funnel-*.tar.gz > checksums.txt
cd ..

echo "==> Build completed successfully! Generated artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
