#!/bin/bash
# Install under a new directory. Checksums are pinned, not fetched alongside the archives.
set -eu -o pipefail
dest=$(realpath -m "${1:?toolchain directory required}")
case $(uname -m) in
  x86_64) goarch=amd64; bunarch=x64
    gohash=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
    bunhash=bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c;;
  aarch64) goarch=arm64; bunarch=aarch64
    gohash=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
    bunhash=baa6bb36f51d6e58561e02bbea825038a9df454f673d6d776e8bbf86f8c7850e;;
  *) exit 2;;
esac
mkdir "$dest" && cd "$dest" || exit 1
curl -fsSL --retry 3 "https://go.dev/dl/go1.27.4.linux-$goarch.tar.gz" -o go.tgz
curl -fsSL --retry 3 "https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-$bunarch.zip" -o bun.zip
printf '%s  go.tgz\n%s  bun.zip\n' "$gohash" "$bunhash" | sha256sum -c -
tar xzf go.tgz && unzip -q bun.zip
mkdir bin && mv "bun-linux-$bunarch/bun" bin/
rm go.tgz bun.zip
