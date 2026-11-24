#!/usr/bin/env bash
# Interop test with the real binaries: aqmasd + aqmas + a throwaway unprivileged sshd, with the
# owner played by test/interop/owner.ts (the web UI's own flow code + a software passkey).
# Everything runs on 127.0.0.1 in a temp dir; no real fleet host, key or config is touched.
#
#   test/interop/run.sh            # builds with `make build` first (needs Go + Bun)
#   AQMASD=... AQMAS=... test/interop/run.sh   # use prebuilt binaries for this machine
#   KEEP=1 test/interop/run.sh     # keep the temp dir (logs, config) for inspection
#
# Checks: passkey registration + login; a second passkey added, renamed, used, the first removed,
# removing the last refused; enrollment with --ca-pin from `aqmasd tls-fingerprint`;
# `aqmas ssh testhost -- echo ok` after a passkey approval; the certificate's principal,
# source-address, key id and validity; reuse of a cached certificate without a new request;
# `aqmas list` / `list --json` / `status` / `status ID`; Ctrl-C cancels a pending request
# (exit 130, status cancelled); a denied request exits 3; GET /v1/ssh-ca agrees with
# `aqmasd print-ssh-ca`; enrollment status needs the poll token; a revoked grant is not reused.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH=$HOME/.local/toolchains/go/bin:$PATH

fail() { echo "interop: FAIL: $*" >&2; exit 1; }
ok() { echo "interop: ok: $*"; }

for b in bun ssh ssh-keygen curl; do command -v $b >/dev/null || fail "$b not found"; done
SSHD=$(command -v sshd || true)
[[ -n $SSHD ]] || for p in /usr/sbin/sshd /usr/local/sbin/sshd; do [[ -x $p ]] && SSHD=$p; done
[[ -n $SSHD ]] || fail "sshd not found"

case $(uname -m) in
aarch64 | arm64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=amd64 ;;
*) fail "unsupported arch $(uname -m)" ;;
esac
VERSION=$(cat "$ROOT/VERSION") COMMIT=$(git -C "$ROOT" rev-parse HEAD)
if [[ -z ${AQMASD:-} || -z ${AQMAS:-} ]]; then
	# The suite's release sources are plain http on 127.0.0.1, which only a binary built with
	# the "interop" tag accepts (release builds are https only): build both for this machine.
	make -C "$ROOT" --no-print-directory web build >/dev/null
	AQMASD=${AQMASD:-$ROOT/bin/aqmasd-interop} AQMAS=${AQMAS:-$ROOT/bin/aqmas-interop}
	(cd "$ROOT" && CGO_ENABLED=0 go build -tags interop -trimpath -buildvcs=false -ldflags "-X main.version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/client.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$COMMIT" -o "$ROOT/bin/aqmasd-interop" ./cmd/aqmasd &&
		CGO_ENABLED=0 go build -tags interop -trimpath -buildvcs=false -ldflags "-X main.version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/client.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$COMMIT" -o "$ROOT/bin/aqmas-interop" ./cmd/aqmas)
fi
"$AQMASD" version | grep -q 'web ui: embedded' || fail "aqmasd has no embedded web UI"

T=$(mktemp -d "${TMPDIR:-/tmp}/aqmas-interop.XXXXXX")
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	[[ -d $T/wt-old ]] && { git -C "$ROOT" worktree remove --force "$T/wt-old" 2>/dev/null || true; }
	if [[ ${KEEP:-0} == 1 ]]; then echo "interop: kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap 'echo "interop: failed at line $LINENO; logs in $T (KEEP=1 keeps them)" >&2; KEEP=1' ERR

free_port() { bun -e 'const s = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } }); console.log(s.port); s.stop(true);'; }
PA=$(free_port) PW=$(free_port) PS=$(free_port)
PF=$(free_port) PG=$(free_port)
ME=$(id -un)
ORIGIN=https://aqmas.interop.test
mkdir -p "$T"/{data,sshd/principals,client/config,client/cache}
chmod 700 "$T"/data "$T"/client/config "$T"/client/cache

# --- test sshd: host key, principals file (CA key is added once aqmasd made it) ---
ssh-keygen -q -t ed25519 -N '' -C interop-host -f "$T/sshd/hostkey"
echo "$ME@testhost" >"$T/sshd/principals/$ME"

cat >"$T/config.toml" <<EOF
listen_agent    = "127.0.0.1:$PA"
listen_web      = "127.0.0.1:$PW"
data_dir        = "$T/data"
public_base_url = "$ORIGIN"
owner_name      = "interop-owner"
tls_sans        = ["127.0.0.1"]
client_cert_days = 2

[updates]
cache_dir = "$T/releases"
[updates.second]
api = "http://127.0.0.1:$PF/api/v1/repos/example/aqmas"
[updates.github]
api = "http://127.0.0.1:$PG"

[ttl]
pending_expiry_seconds = 120

[[targets]]
name     = "testhost"
address  = "127.0.0.1"
port     = $PS
users    = ["$ME"]
host_key = "$(cut -d' ' -f1-2 "$T/sshd/hostkey.pub")"
EOF

# --- aqmasd ---
"$AQMASD" -config "$T/config.toml" serve >"$T/aqmasd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$PW/api/ui/session" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS "http://127.0.0.1:$PW/api/ui/session" >/dev/null || { cat "$T/aqmasd.log"; fail "aqmasd did not start"; }
curl -fsS "http://127.0.0.1:$PW/" | grep -q '<script' || fail "web UI index not served"
ok "aqmasd up (agent :$PA, web :$PW)"

"$AQMASD" -config "$T/config.toml" print-ssh-ca >"$T/sshd/ca.pub"
PIN=$("$AQMASD" -config "$T/config.toml" tls-fingerprint)
[[ $PIN =~ ^sha256:[0-9a-f]{64}$ ]] || fail "tls-fingerprint printed '$PIN'"

cat >"$T/sshd/sshd_config" <<EOF
Port $PS
ListenAddress 127.0.0.1
HostKey $T/sshd/hostkey
PidFile $T/sshd/sshd.pid
TrustedUserCAKeys $T/sshd/ca.pub
AuthorizedPrincipalsFile $T/sshd/principals/%u
AuthorizedKeysFile none
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
EOF
"$SSHD" -D -e -f "$T/sshd/sshd_config" >"$T/sshd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PS") 2>/dev/null && break; sleep 0.1; done
ok "test sshd up on :$PS trusting the aqmas SSH CA"

# --- owner: first passkey via enroll code, sign in ---
export AQMAS_WEB_DIR=$ROOT/web AQMAS_BASE=http://127.0.0.1:$PW AQMAS_ORIGIN=$ORIGIN OWNER_STATE=$T/owner.json
owner() { bun "$ROOT/test/interop/owner.ts" "$@"; }
CODE=$("$AQMASD" -config "$T/config.toml" passkey-enroll-code | head -1)
owner register "$CODE" >/dev/null
owner session | grep -q '"authenticated":true' || fail "not signed in after registration"
owner login >/dev/null
owner session | grep -q '"authenticated":true' || fail "login with the saved passkey failed"
ok "passkey registered; login works"

# --- passkey management: add a second, rename it, sign in with it, remove the first ---
FIRST=$(owner passkeys | bun -e 'const p = await Bun.stdin.json(); if (p.length !== 1 || !p[0].current) process.exit(1); console.log(p[0].nickname)') ||
	fail "passkey list after registration"
[[ $FIRST == "Passkey 1" ]] || fail "first passkey is named '$FIRST', want 'Passkey 1'"
SECOND=$(owner add-passkey "interop second" 2>"$T/owner-add.err")
[[ $SECOND == "interop second" ]] || { cat "$T/owner-add.err"; fail "add-passkey printed '$SECOND'"; }
grep -q '"action":"add".*"new_nickname":"interop second","nickname":"".*"object":"passkey"' "$T/owner-add.err" || fail "passkey add (with its nickname) was not signed"
owner rename-passkey "interop second" "interop backup" >/dev/null 2>"$T/owner-rename.err" || { cat "$T/owner-rename.err"; fail "rename-passkey"; }
grep -q '"action":"rename".*"new_nickname":"interop backup","nickname":"interop second"' "$T/owner-rename.err" ||
	{ cat "$T/owner-rename.err"; fail "rename canonical lacks the nicknames"; }
owner use-passkey "interop backup" >/dev/null
owner login >/dev/null
owner passkeys | bun -e 'const p = await Bun.stdin.json(); const b = p.find((x) => x.nickname === "interop backup");
	if (p.length !== 2 || !b?.current || p.find((x) => x.nickname === "Passkey 1")?.current) process.exit(1)' ||
	fail "after rename + login: $(owner passkeys)"
owner remove-passkey "Passkey 1" >"$T/owner-remove.out" 2>"$T/owner-remove.err" || { cat "$T/owner-remove.err"; fail "remove-passkey"; }
grep -q '"signed_out":false' "$T/owner-remove.out" || fail "removing another passkey signed this session out"
if owner remove-passkey "interop backup" >/dev/null 2>"$T/owner-remove-last.err"; then fail "removed the last passkey"; fi
grep -q "409 conflict.*last passkey" "$T/owner-remove-last.err" || { cat "$T/owner-remove-last.err"; fail "last-passkey refusal"; }
owner state | grep -q '"action":"passkey_rename"' && owner state | grep -q '"action":"passkey_remove"' || fail "passkey changes not audited"
ok "passkeys: added 'interop second', renamed to 'interop backup', signed in with it, removed 'Passkey 1'; last one refused"

# --- client: enroll with the pinned CA ---
export AQMAS_CONFIG_DIR=$T/client/config AQMAS_CACHE_DIR=$T/client/cache
unset CLAUDECODE CLAUDE_SESSION_ID CLAUDE_CODE_SESSION_ID AQMAS_SESSION_ID SSH_AUTH_SOCK || true
"$AQMAS" enroll --owner-device --name interop-host --server "https://127.0.0.1:$PA" --ca-pin "$PIN" --note "interop test" \
	</dev/null >"$T/enroll.out" 2>"$T/enroll.err" &
EPID=$!
EID=$(owner wait enrollment interop-host 20)
CSRFP=$(owner item enrollment "$EID" | bun -e 'console.log((await Bun.stdin.json()).enrollment.csr_fingerprint)')
grep -q "client key: $CSRFP" "$T/enroll.err" || { cat "$T/enroll.err"; fail "enroll did not print the card's client key $CSRFP"; }
curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PA/v1/enroll/$EID" | grep -qx 404 || fail "enrollment status readable without the poll token"
owner approve "$EID" >/dev/null 2>"$T/owner-enroll.err"
wait $EPID || { cat "$T/enroll.err"; fail "aqmas enroll exited $?"; }
grep -q "Ref ${EID: -6}" "$T/enroll.err" || fail "enroll did not print the card's Ref"
ok "enrolled interop-host (Ref ${EID: -6})"

# An older, locally built CLI updates itself using the enrolled mTLS identity. Seed
# the server's release cache as the owner's bootstrap does, in both forms: one published
# source (GitHub only) and two (GitHub and a second source that agrees).
v=$(cat "$ROOT/VERSION")
make -C "$ROOT" release >/dev/null
mkdir -p "$T/releases/$v" "$T/upgrade"
cp "$ROOT/dist/"aqmas-* "$ROOT/dist/SHA256SUMS" "$ROOT/dist/SHA256SUMS.extra" "$T/releases/$v/"
for port in "$PF" "$PG"; do
  bun "$ROOT/test/interop/release-source.ts" "$port" "$v" "$T/releases/$v/SHA256SUMS" & PIDS+=($!)
  for _ in {1..50}; do curl -fsS "http://127.0.0.1:$port/releases/tags/v$v" >/dev/null 2>&1 && break; sleep 0.1; done
done
# Both sources must serve the same manifest before it becomes the cached release identity.
bun -e 'const [v,commit,...ports]=process.argv.slice(1);const get=async(p,n)=>{const r=await (await fetch(`http://127.0.0.1:${p}/releases/tags/v${v}`)).json();const a=r.assets.find(a=>a.name===n);return await (await fetch(`http://127.0.0.1:${p}/releases/assets/${a.id}`)).text()};
const parse=t=>Object.fromEntries(t.trim().split("\n").map(l=>l.split("  ").reverse()));const sums=[],extra=[];for(const p of ports){sums.push(await get(p,"SHA256SUMS"));extra.push(await get(p,"SHA256SUMS.extra"))}
if(sums[0]!==sums[1]||extra[0]!==extra[1])process.exit(1);const m=parse(sums[0]);console.log(JSON.stringify({version:v,commit,github:m,second:m,extra:parse(extra[0]),sources:2}))' "$v" "$(git -C "$ROOT" rev-parse HEAD)" "$PF" "$PG" > "$T/releases/latest-two.json"
# Brokers and CLIs of 0.9.2 read this release's SHA256SUMS and the bastion's record of it
# (with its new "extra" member) with their own, strict parser: the one from the 0.9.2 commit.
# v0.9.2, by commit: the test must not depend on a tag existing. Missing history is a failure.
OLD_TAG=0ba281b29076898ba5f117ae7b0b5f4754724d10
git -C "$ROOT" cat-file -e "$OLD_TAG^{commit}" 2>/dev/null || fail "0.9.2 ($OLD_TAG) is not in this clone; fetch the full history (git fetch --unshallow)"
[[ $(git -C "$ROOT" show "$OLD_TAG:VERSION") == 0.9.2 ]] || fail "$OLD_TAG is not 0.9.2"
{
  mkdir "$T/old-release"
  git -C "$ROOT" show "$OLD_TAG:internal/release/release.go" > "$T/old-release/release.go"
  printf 'module oldrelease\n\ngo 1.24\n' > "$T/old-release/go.mod"
  cat > "$T/old-release/compat_test.go" <<'GO'
package release

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNewReleaseReadsAsOld(t *testing.T) {
	b, err := os.ReadFile(os.Getenv("SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("0.9.2 parser refuses the new SHA256SUMS: %v", err)
	}
	if b, err = os.ReadFile(os.Getenv("LATEST")); err != nil {
		t.Fatal(err)
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil || !m.Valid() {
		t.Fatalf("0.9.2 refuses the new release record: %v", err)
	}
}
GO
  (cd "$T/old-release" && SUMS="$T/releases/$v/SHA256SUMS" LATEST="$T/releases/latest-two.json" GOFLAGS=-mod=mod GOTOOLCHAIN=local go test -count=1 . >"$T/old-release/out" 2>&1) || fail "0.9.2 parser: $(cat "$T/old-release/out")"
  ok "0.9.2's parser accepts this release's SHA256SUMS and the record with SHA256SUMS.extra"
}
bun -e 'const m=await Bun.file(process.argv[1]).json();delete m.second;m.sources=1;console.log(JSON.stringify(m))' "$T/releases/latest-two.json" > "$T/releases/latest.json"
(cd "$ROOT" && CGO_ENABLED=0 go build -tags interop -trimpath -buildvcs=false -ldflags '-X github.com/aquarat/agent-quartermaster/internal/client.Version=0.0.0' -o "$T/upgrade/aqmas" ./cmd/aqmas)
printf '\n[github]\napi = "http://127.0.0.1:%s"\n' "$PG" >> "$AQMAS_CONFIG_DIR/config.toml"
want=$(awk -v n="aqmas-linux-$ARCH" '$2==n {print $1}' "$T/releases/$v/SHA256SUMS")
# GitHub only: the bastion compared one published source; the CLI asks GitHub itself.
"$T/upgrade/aqmas" update --check >"$T/upgrade/check-one.out" 2>&1 || { cat "$T/upgrade/check-one.out"; fail "CLI check against a GitHub-only bastion"; }
grep -F "$want" "$T/upgrade/check-one.out" >/dev/null && grep -F 'against GitHub and its own rebuild' "$T/upgrade/check-one.out" >/dev/null || fail "GitHub-only check: $(cat "$T/upgrade/check-one.out")"
# With a second source: the same, and the CLI says the bastion compared two.
cp "$T/releases/latest-two.json" "$T/releases/latest.json"
"$T/upgrade/aqmas" update --check 2>&1 | grep -F 'against GitHub and a second source and its own rebuild' >/dev/null || fail "two-source check"
"$T/upgrade/aqmas" update --check 2>&1 | grep -F "$want" >/dev/null
# A system-wide install: the directory is not writable, so the upgrade stops before it
# downloads anything and names the one way forward.
mkdir "$T/upgrade-system" && cp "$T/upgrade/aqmas" "$T/upgrade-system/aqmas" && chmod 555 "$T/upgrade-system"
if [[ $(id -u) != 0 ]]; then
  if "$T/upgrade-system/aqmas" upgrade --yes --expect-sha256 "$want" </dev/null 2>"$T/upgrade/system.err"; then fail "upgrade in a read-only directory succeeded"; fi
  grep -F "sudo $T/upgrade-system/aqmas upgrade" "$T/upgrade/system.err" >/dev/null && grep -F 'nothing was downloaded' "$T/upgrade/system.err" >/dev/null || fail "system-install hint: $(cat "$T/upgrade/system.err")"
  "$T/upgrade-system/aqmas" version | grep -F 'aqmas 0.0.0 ' >/dev/null || fail "refused upgrade changed the executable"
fi
chmod 755 "$T/upgrade-system"
# Opt-in (AQMAS_INTEROP_SUDO=1, needs password-less sudo): the same install in a root-owned
# directory is upgraded with sudo, using this user's enrolment, and root leaves nothing of
# its own in the user's configuration or cache.
if [[ ${AQMAS_INTEROP_SUDO:-} == 1 ]] && sudo -n true 2>/dev/null; then
  SD=$(sudo -n mktemp -d /tmp/aqmas-interop-root.XXXXXX)
  sudo -n chmod 755 "$SD" && sudo -n install -o 0 -g 0 -m 755 "$T/upgrade/aqmas" "$SD/aqmas"
  sudo -n AQMAS_CONFIG_DIR="$AQMAS_CONFIG_DIR" AQMAS_CACHE_DIR="$AQMAS_CACHE_DIR" "$SD/aqmas" upgrade --yes --expect-sha256 "$want" </dev/null 2>"$T/upgrade/sudo.err" || { sudo -n rm -rf "$SD"; fail "sudo upgrade: $(cat "$T/upgrade/sudo.err")"; }
  grep -F 'only replacing the executable runs as root' "$T/upgrade/sudo.err" >/dev/null || fail "sudo upgrade did not say whose enrolment it used"
  "$SD/aqmas" version | grep -F "aqmas $v " >/dev/null && [[ $(stat -c %u "$SD/aqmas") == 0 ]] || fail "sudo upgrade did not install the release as root"
  [[ -z $(find "$AQMAS_CONFIG_DIR" "$AQMAS_CACHE_DIR" ! -user "$(id -u)" 2>/dev/null) ]] || fail "sudo upgrade left files that are not the user's in the configuration or cache"
  sudo -n rm -rf "$SD"
  ok 'sudo upgrade of a root-owned install used the invoking user'"'"'s enrolment and left its files alone'
fi
"$T/upgrade/aqmas" upgrade --yes --expect-sha256 "$want" </dev/null
"$T/upgrade/aqmas" version | grep -F "aqmas $v " >/dev/null
"$T/upgrade/aqmas.prev" version | grep -F 'aqmas 0.0.0 ' >/dev/null
ok 'old CLI verified the release (bastion with one source, then two) against GitHub, replaced itself and retained runnable previous version'
# A real 0.9.2 CLI (built from its commit) upgrades from this bastion: the record now has an
# "extra" member and the release a SHA256SUMS.extra, neither of which it knows.
{
  git -C "$ROOT" worktree add --detach "$T/wt-old" "$OLD_TAG" >/dev/null 2>&1 || fail "git worktree add $OLD_TAG"
  mkdir "$T/upgrade-old"
  (cd "$T/wt-old" && CGO_ENABLED=0 go build -tags interop -trimpath -buildvcs=false -ldflags '-X github.com/aquarat/agent-quartermaster/internal/client.Version=0.0.0' -o "$T/upgrade-old/aqmas" ./cmd/aqmas) || fail "build 0.9.2 CLI"
  "$T/upgrade-old/aqmas" upgrade --yes --expect-sha256 "$want" </dev/null 2>"$T/upgrade-old/err" || fail "0.9.2 CLI upgrade: $(cat "$T/upgrade-old/err")"
  "$T/upgrade-old/aqmas" version | grep -F "aqmas $v " >/dev/null || fail "0.9.2 CLI did not install $v"
  git -C "$ROOT" worktree remove --force "$T/wt-old"
  ok "0.9.2 CLI upgraded itself to $v from a bastion whose record has SHA256SUMS.extra"
}

# --- ssh: first request, approved for 10 min ---
"$AQMAS" ssh 127.0.0.1 --ttl 15m --why "interop first login" -- echo ok </dev/null >"$T/ssh1.out" 2>"$T/ssh1.err" &
SPID=$!
RID=$(owner wait ssh interop-host 20)
owner approve "$RID" 600 >/dev/null 2>"$T/owner-ssh1.err"
grep -q '"ttl_seconds":600' "$T/owner-ssh1.err" || fail "signed canonical lacks the chosen TTL"
wait $SPID || { cat "$T/ssh1.err" "$T/sshd.log"; fail "aqmas ssh exited $?"; }
[[ $(cat "$T/ssh1.out") == ok ]] || fail "remote command printed '$(cat "$T/ssh1.out")'"
grep -q "Accepted certificate ID \"aqmas:" "$T/sshd.log" || fail "sshd did not log a certificate login"
ok "aqmas ssh testhost -- echo ok printed ok (request $RID)"

CERT=$(readlink -f "$T/client/cache/$ME@testhost/current")/id_ed25519-cert.pub
[[ -f $CERT ]] || fail "no cached certificate at $CERT"
ssh-keygen -L -f "$CERT" >"$T/cert.txt"
grep -A1 'Principals:' "$T/cert.txt" | grep -qx "                $ME@testhost" || { cat "$T/cert.txt"; fail "principal is not $ME@testhost"; }
grep -q 'source-address 127.0.0.1/32' "$T/cert.txt" || { cat "$T/cert.txt"; fail "source-address is not 127.0.0.1/32"; }
grep -q 'Key ID: "aqmas:.*:interop-host:testhost"' "$T/cert.txt" || { cat "$T/cert.txt"; fail "unexpected key id"; }
grep -q 'permit-agent-forwarding' "$T/cert.txt" && fail "certificate permits agent forwarding"
read -r FROM TO < <(sed -n 's/^ *Valid: from \(.*\) to \(.*\)$/\1 \2/p' "$T/cert.txt")
SPAN=$(($(date -d "$TO" +%s) - $(date -d "$FROM" +%s)))
((SPAN >= 600 && SPAN <= 600 + 120)) || fail "certificate validity is ${SPAN}s, want 600 s (+ back-dating)"
CA_FP=$(ssh-keygen -lf "$T/sshd/ca.pub" | cut -d' ' -f2)
grep -q "Signing CA: ED25519 $CA_FP\|Signing CA: .* $CA_FP" "$T/cert.txt" || { cat "$T/cert.txt"; fail "not signed by the aqmasd SSH CA"; }
ok "certificate: principal $ME@testhost, source-address 127.0.0.1/32, valid ${SPAN}s, signed by $CA_FP"

# --- second ssh within the TTL reuses the certificate ---
N1=$(owner state | grep -o '"action":"request"' | wc -l || true)
"$AQMAS" ssh testhost --why "interop reuse" -- echo ok2 </dev/null >"$T/ssh2.out" 2>"$T/ssh2.err"
[[ $(cat "$T/ssh2.out") == ok2 ]] || fail "second ssh printed '$(cat "$T/ssh2.out")'"
grep -q 'reusing grant' "$T/ssh2.err" || fail "second ssh did not reuse the cached grant"
grep -q 'request ' "$T/ssh2.err" && fail "second ssh sent a new request"
N2=$(owner state | grep -o '"action":"request"' | wc -l || true)
[[ $N1 == "$N2" ]] || fail "server saw a new request ($N1 -> $N2)"
ok "second aqmas ssh reused the cached certificate (no new request)"

# --- list / status ---
"$AQMAS" list >"$T/list.out" 2>&1 || fail "aqmas list failed: $(cat "$T/list.out")"
grep -q testhost "$T/list.out" || fail "aqmas list does not show the grant"
"$AQMAS" list --json | bun -e 'const j = await Bun.stdin.json(); if (!j.grants?.some((g) => g.target_host === "testhost" && g.status === "approved")) process.exit(1)' ||
	fail "aqmas list --json lacks the active grant"
"$AQMAS" status >"$T/status.out" 2>&1 || fail "aqmas status failed"
grep -q 'host name *interop-host' "$T/status.out" && grep -q "$ME@testhost.*valid" "$T/status.out" || { cat "$T/status.out"; fail "aqmas status output"; }
"$AQMAS" status "$RID" >"$T/status-id.out" || fail "aqmas status ID failed"
grep -q 'status *approved' "$T/status-id.out" || { cat "$T/status-id.out"; fail "aqmas status ID"; }
ok "aqmas list, list --json, status, status ID"

# --- GET /v1/ssh-ca (mTLS) agrees with print-ssh-ca ---
KEY=$(sed -n 's/^client_key *= *"\(.*\)"/\1/p' "$T/client/config/config.toml")
CRT=$(sed -n 's/^client_cert *= *"\(.*\)"/\1/p' "$T/client/config/config.toml")
SCA=$(sed -n 's/^server_ca *= *"\(.*\)"/\1/p' "$T/client/config/config.toml")
curl -fsS --cacert "$SCA" --cert "$CRT" --key "$KEY" "https://127.0.0.1:$PA/v1/ssh-ca" >"$T/ssh-ca.json"
grep -qF "$(cut -d' ' -f2 "$T/sshd/ca.pub")" "$T/ssh-ca.json" || fail "/v1/ssh-ca differs from print-ssh-ca"
curl -sS -o /dev/null -w '%{http_code}' --cacert "$SCA" "https://127.0.0.1:$PA/v1/ssh-ca" 2>/dev/null | grep -qv '^200$' || fail "/v1/ssh-ca answered without a client certificate"
ok "GET /v1/ssh-ca matches aqmasd print-ssh-ca and needs a client certificate"

# --- Ctrl-C cancels a pending request ---
"$AQMAS" ssh testhost --fresh --why "interop cancel" -- true </dev/null >/dev/null 2>"$T/cancel.err" &
CPID=$!
CID=$(owner wait ssh interop-host 20)
kill -INT $CPID
RC=0
wait $CPID || RC=$?
((RC == 130)) || { cat "$T/cancel.err"; fail "cancelled aqmas exited $RC, want 130"; }
grep -q "cancelled request $CID" "$T/cancel.err" || { cat "$T/cancel.err"; fail "cancel message"; }
"$AQMAS" status "$CID" | grep 'status *cancelled' >/dev/null || fail "server status is not cancelled"
owner state | grep -q "\"id\":\"$CID\"" && fail "cancelled request still pending in the UI"
ok "Ctrl-C cancelled request $CID (exit 130, status cancelled, gone from the owner's queue)"

# --- a denied request exits 3 ---
"$AQMAS" ssh testhost --fresh --why "interop deny" -- true </dev/null >/dev/null 2>"$T/deny.err" &
DPID=$!
DID=$(owner wait ssh interop-host 20)
owner deny "$DID" >/dev/null 2>&1
RC=0
wait $DPID || RC=$?
((RC == 3)) || { cat "$T/deny.err"; fail "denied aqmas exited $RC, want 3"; }
ok "denied request $DID exits 3"

# --- revoking the grant in the UI shows on the agent side ---
GID=$(owner state | bun -e 'const s = await Bun.stdin.json(); console.log(s.grants.find((g) => g.target_host === "testhost").id)')
owner revoke-grant "$GID" >/dev/null 2>&1
"$AQMAS" list --json | bun -e 'const j = await Bun.stdin.json(); if (j.grants?.some((g) => g.id === process.argv[1])) process.exit(1)' "$GID" ||
	fail "revoked grant still listed as active"
ok "revoked grant $GID is no longer active"

# --- after the revoke, aqmas does not reuse the cached certificate ---
"$AQMAS" ssh testhost --why "interop after revoke" -- true </dev/null >/dev/null 2>"$T/after-revoke.err" &
APID=$!
AID=$(owner wait ssh interop-host 20)
grep -q "is revoked on the server; requesting a new one" "$T/after-revoke.err" || { cat "$T/after-revoke.err"; fail "no revoked-grant message"; }
owner deny "$AID" >/dev/null 2>&1
RC=0
wait $APID || RC=$?
((RC == 3)) || fail "after-revoke request exited $RC, want 3"
ok "after the revoke, aqmas asked again instead of reusing the cached certificate"

# Exercise the read-only v0.1.1 inventory on a consistent copy while the real
# broker is still serving. A revoked SSH grant still means a valid issued cert.
bun -e 'import {Database} from "bun:sqlite"; const db=new Database(process.argv[1],{readonly:true}); db.query("VACUUM INTO ?").run(process.argv[2]); db.close()' "$T/data/aqmas.db" "$T/pre-cutover.db"
"$AQMASD" -config "$T/config.toml" organisations-plan "$T/pre-cutover.db" >"$T/plan.json"
bun -e 'const p=await Bun.file(process.argv[1]).json(); const a=p.admit_to_personal_only;
if(p.source_schema!==5 || p.organisation.slug!=="personal" || a.length!==1 || a[0].name!=="interop-host" || !a[0].certificate_sha256 || p.services[0].sets[0].slug!=="testhost" || !p.retire.outstanding_certificates_and_unverified_children.some(g=>g.grant_id===process.argv[2]))process.exit(1)' "$T/plan.json" "$GID" || fail "personal cutover inventory"
"$AQMAS" list --json >/dev/null || fail "inventory interrupted legacy service"
ok "personal dry run identified live enrollment, target and outstanding SSH certificate"

source "$ROOT/test/interop/cutover.sh"
personal_cutover "${PIDS[0]}"
"$AQMAS" ssh testhost --fresh --why "post-cutover" -- echo ok </dev/null >"$T/scoped.out" 2>"$T/scoped.err" &
RPID=$!; RID=$(owner wait ssh interop-host 20); owner approve "$RID" 300 >/dev/null 2>"$T/scoped-owner.err"
wait "$RPID"; grep -qx ok "$T/scoped.out" && grep -q '"org_slug":"personal"' "$T/scoped-owner.err" || fail 'scoped SSH approval'
ok 'signed activation and personal SSH approval from the legacy CLI'

owner catalogue create
owner catalogue remove
if "$AQMAS" list >"$T/foreign.out" 2>&1; then fail 'client-a admission conferred personal access'; fi
# Admitted elsewhere: what it cannot see is a plain "not found", never a hint about its state.
grep -q 'not_found' "$T/foreign.out" && ! grep -q 'not admitted' "$T/foreign.out" || fail "a host admitted elsewhere was told more than not_found: $(cat "$T/foreign.out")"
owner catalogue readmit
"$AQMAS" list --json | bun -e 'if((await Bun.stdin.json()).grants.length)process.exit(1)' || fail 're-admission revived grants'
ok 'signed catalogue creation, identical sibling paths and remove/re-admit isolation'

# A host enrolled after the cutover is admitted nowhere: it is told so (not a bare
# "not found"), and the admission the page proposes right after the enrolment approval
# is what lets it in.
(
  export AQMAS_CONFIG_DIR=$T/late/config AQMAS_CACHE_DIR=$T/late/cache
  "$AQMAS" enroll --name late-host --server "https://127.0.0.1:$PA" --ca-pin "$PIN" --note "interop late host" </dev/null >"$T/late-enroll.out" 2>"$T/late-enroll.err" &
  LPID=$!
  LID=$(owner wait enrollment late-host 20)
  owner approve "$LID" >/dev/null 2>"$T/late-owner.err" || fail "approving the late enrolment: $(cat "$T/late-owner.err")"
  wait $LPID || { cat "$T/late-enroll.err"; fail "late enroll exited $?"; }
  if "$AQMAS" ssh testhost --why "not admitted yet" -- echo ok </dev/null >"$T/late.out" 2>"$T/late.err"; then fail 'an unadmitted host got access'; fi
  grep -q 'enrolled but not admitted to an organisation' "$T/late.err" && ! grep -q 'not_found' "$T/late.err" || fail "unadmitted host message: $(cat "$T/late.err")"
  owner catalogue admit-host:personal:late-host || fail 'admitting the late host'
  "$AQMAS" list >"$T/late-list.out" 2>&1 || fail "admitted late host still refused: $(cat "$T/late-list.out")"
) || exit 1
ok 'a host enrolled after the cutover hears "not admitted"; the admission proposed after its enrolment approval lets it in'

source "$ROOT/test/interop/seal.sh"
seal_cutover
# After a restart nothing is open: the approval tap itself opens the SSH CA (batch and single card).
"$AQMAS" ssh testhost --fresh --why "after restart" -- echo ok </dev/null >"$T/closed.out" 2>"$T/closed.err" &
RPID=$!; RID=$(owner wait ssh interop-host 20); owner batch "$RID" >/dev/null 2>"$T/batch.err" || { cat "$T/batch.err"; fail 'batch approval that opens the SSH CA'; }
wait "$RPID"; grep -qx ok "$T/closed.out" || fail 'sealed SSH signer with exact-action batch'
nothing_open 'batch approval (instant hold)'
"$AQMAS" ssh testhost --fresh --why "single card" -- echo ok </dev/null >"$T/closed2.out" 2>"$T/closed2.err" &
RPID=$!; RID=$(owner wait ssh interop-host 20); owner approve "$RID" 300 >/dev/null 2>"$T/single.err" || { cat "$T/single.err"; fail 'single approval that opens the SSH CA'; }
wait "$RPID"; grep -qx ok "$T/closed2.out" || fail 'single-card SSH approval'
nothing_open 'single approval (instant hold)'
ok 'approvals open the SSH CA for the instant only (batch and single card)'
source "$ROOT/test/interop/browserkey.sh"
browser_key_scenario
source "$ROOT/test/interop/vault.sh"
source "$ROOT/test/interop/envsets.sh"
env_scenario
echo "interop: ALL OK"
