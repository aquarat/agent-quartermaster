#!/usr/bin/env bash
# Wrangler through `aqmas cf env`: installs wrangler with bun into a temp dir and runs
# TestWranglerThroughShim (test/wrangler/wrangler_test.go): whoami, deploy (script + assets +
# cron), versions upload, secret put, d1 execute --remote, d1 migrations apply --remote,
# pages deploy, d1 execute with a name-only binding, and deploy with single-asset uploads, against a stand-in for aqmasd's proxy and the in-memory fake Cloudflare API.
# No real Cloudflare call, no OAuth config, nothing outside 127.0.0.1.
#
#   test/wrangler/run.sh                      # latest wrangler
#   WRANGLER_VERSION=4.165.0 test/wrangler/run.sh
#   KEEP=1 test/wrangler/run.sh               # keep the install dir and wrangler logs
#
# Writes test/wrangler/observed-paths.txt (override with OBSERVED_PATHS=...).
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH=$HOME/.local/toolchains/go/bin:$PATH
for b in bun node go; do command -v $b >/dev/null || { echo "wrangler test: $b not found" >&2; exit 1; }; done

T=$(mktemp -d "${TMPDIR:-/tmp}/aqmas-wrangler.XXXXXX")
cleanup() { if [[ ${KEEP:-0} == 1 ]]; then echo "wrangler test: kept $T"; else rm -rf "$T"; fi; }
trap cleanup EXIT
mkdir -p "$T/install" "$T/logs"
echo '{"name":"aqmas-wrangler-test","private":true}' >"$T/install/package.json"
(cd "$T/install" && bun add "wrangler@${WRANGLER_VERSION:-latest}" >/dev/null)
export WRANGLER_BIN=$T/install/node_modules/wrangler/bin/wrangler.js
[[ -f $WRANGLER_BIN ]] || { echo "wrangler test: $WRANGLER_BIN missing" >&2; exit 1; }
echo "wrangler test: wrangler $(node "$WRANGLER_BIN" --version 2>/dev/null | tail -1)"
export WRANGLER_LOG_DIR=$T/logs
cd "$ROOT"
go test -count=1 -v -timeout 20m -run '^TestWranglerThroughShim$' ./test/wrangler/
