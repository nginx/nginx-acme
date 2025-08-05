#!/bin/sh

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

set -e

VERSION="${1:-2.8.0}"
SHA256SUM="$2"
TARGET=${3:-$PWD/bin/pebble}

SHA256SUM_darwin_amd64=9b9625651f8ce47706235179503fec149f8f38bce2b2554efe8c0f2a021f877c
SHA256SUM_darwin_arm64=39e07d63dc776521f2ffe0584e5f4f081c984ac02742c882b430891d89f0c866
SHA256SUM_linux_amd64=34595d915bbc2fc827affb3f58593034824df57e95353b031c8d5185724485ce
SHA256SUM_linux_arm64=0e70f2537353f61cbf06aa54740bf7f7bb5f963ba00e909f23af5f85bc13fd1a

if "$TARGET" -version | grep "$VERSION"; then
    exit 0
fi

SYSTEM=$(uname -s | tr "[:upper:]" "[:lower:]")
MACHINE=$(uname -m)
case "$MACHINE" in
    aarch64)
        MACHINE=arm64;;
    x86_64)
        MACHINE=amd64;;
esac

if [ -z "$SHA256SUM" ]; then
    eval "SHA256SUM=\$SHA256SUM_${SYSTEM}_${MACHINE}"
fi

if echo "$SHA256SUM  $TARGET" | shasum -a 256 -c; then
    exit 0;
fi

PREFIX="pebble-${SYSTEM}-${MACHINE}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR"

curl -L -o "$PREFIX.tar.gz" \
    "https://github.com/letsencrypt/pebble/releases/download/v${VERSION}/${PREFIX}.tar.gz"

if ! echo "$SHA256SUM  $PREFIX.tar.gz" | shasum -a 256 -c; then
    echo "checksum mismatch"
    exit 1;
fi

tar -xzf "$PREFIX.tar.gz"

mkdir -p "$(dirname "$TARGET")"
mv "$PREFIX/$SYSTEM/$MACHINE/pebble" "$TARGET"
chmod +x "$TARGET"
