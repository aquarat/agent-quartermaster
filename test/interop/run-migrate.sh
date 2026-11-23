#!/usr/bin/env bash
# Migration interop (docs/BUCKETS.md §8): a store sealed by the REAL v0.4.1 code (format 1) is
# moved to per-credential buckets (format 2) by this tree's binary through the Setup task
# "buckets", then used.
#
#   1. v0.4.1, built from its tag in a temporary git worktree and driven by its own owner helper
#      and web modules: organisations cutover, catalogue (client-a, club), env values written in
#      the form, an imported signer key, a Cloudflare proxy parent (fake Cloudflare), "Seal the
#      store" through the v0.4.1 runner, a second unlock passkey.
#   2. This tree: the broker serves "migration required" (queue and deny only); the runner task
#      "buckets"; open-legacy, create and test taps; a wrong and the right recovery drill;
#      activation; the runner pins and restarts.
#   3. Use: SSH grant, `aqmas run`, Reveal, `aqmas sign`, a Cloudflare proxy grant, an approval
#      window (fake Cloudflare Access), restart (nothing open, paused grant, Reopen), Close all,
#      a new organisation's scope key, the browser recovery drill and the offline seal-drill of a
#      backup copy; after each single-bucket action status.buckets shows only that bucket open;
#      finally a sentinel scan of the database, WAL, logs and outputs.
#
#   test/interop/run-migrate.sh        # builds this tree and v0.4.1 first (needs Go + Bun + git)
#   KEEP=1 test/interop/run-migrate.sh # keep the temp dir (the worktree is always removed)
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH=$HOME/.local/toolchains/go/bin:$PATH
fail() { echo "migrate-interop: FAIL: $*" >&2; exit 1; }
ok() { echo "migrate-interop: ok: $*"; }
for b in bun ssh ssh-keygen curl git openssl; do command -v $b >/dev/null || fail "$b not found"; done
SSHD=$(command -v sshd || true)
[[ -n $SSHD ]] || for p in /usr/sbin/sshd /usr/local/sbin/sshd; do [[ -x $p ]] && SSHD=$p; done
[[ -n $SSHD ]] || fail "sshd not found"
case $(uname -m) in aarch64 | arm64) ARCH=arm64 ;; x86_64 | amd64) ARCH=amd64 ;; *) fail "unsupported arch" ;; esac
OLD_TAG=v0.4.1

T=$(mktemp -d "${TMPDIR:-/tmp}/aqmas-migrate.XXXXXX")
L=$T/lab OLD=$T/v041
PIDS=()
cleanup() {
	[[ -f $T/aqmasd.pid ]] && kill "$(cat "$T/aqmasd.pid")" 2>/dev/null || true
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	[[ -d $OLD ]] && { git -C "$ROOT" worktree remove --force "$OLD" 2>/dev/null || true; }
	rm -f "$T/marker"
	if [[ ${KEEP:-0} == 1 ]]; then echo "migrate-interop: kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap 'echo "migrate-interop: failed at line $LINENO; logs in $T (KEEP=1 keeps them)" >&2; KEEP=1; for f in "$T"/maint.log "$T"/aqmasd-*.log; do [ -f "$f" ] && { echo "--- tail $f" >&2; tail -25 "$f" >&2; }; done' ERR

# --- binaries: this tree, and v0.4.1 from its tag (its own Makefile, web UI and helper) ---
VERSION=$(cat "$ROOT/VERSION") COMMIT=$(git -C "$ROOT" rev-parse HEAD)
if [[ -z ${AQMASD:-} || -z ${AQMAS:-} ]]; then
	make -C "$ROOT" --no-print-directory web build >/dev/null
	AQMASD=${AQMASD:-$ROOT/bin/aqmasd-linux-$ARCH} AQMAS=${AQMAS:-$ROOT/bin/aqmas-linux-$ARCH}
	if [[ ! -x $AQMASD ]]; then
		AQMASD=$ROOT/bin/aqmasd-interop
		(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-X main.version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$COMMIT" -o "$AQMASD" ./cmd/aqmasd)
	fi
fi
git -C "$ROOT" worktree add --detach "$OLD" "$OLD_TAG" >/dev/null 2>&1 || fail "git worktree add $OLD_TAG"
(cd "$OLD/web" && bun install --frozen-lockfile >/dev/null 2>&1) || fail "bun install for $OLD_TAG"
make -C "$OLD" --no-print-directory build >/dev/null 2>&1 || fail "make build of $OLD_TAG"
OLD_AQMASD=$OLD/bin/aqmasd-linux-$ARCH OLD_AQMAS=$OLD/bin/aqmas-linux-$ARCH
if [[ ! -x $OLD_AQMASD ]]; then
	OC=$(git -C "$OLD" rev-parse HEAD)
	(cd "$OLD" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-X main.version=0.4.1 -X github.com/aquarat/agent-quartermaster/internal/release.Version=0.4.1 -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$OC" -o "$OLD_AQMASD" ./cmd/aqmasd)
fi
"$OLD_AQMASD" version | grep -q 'aqmasd 0.4.1 (web ui: embedded)' || fail "the $OLD_TAG build is not 0.4.1 with its web UI"
"$AQMASD" version | grep -q 'web ui: embedded' || fail "aqmasd has no embedded web UI"
mkdir -p "$T/bin"
(cd "$ROOT" && go build -o "$T/bin/fakecf" ./test/interop/fakecf && go build -o "$T/bin/fakeaccess" ./test/interop/fakeaccess)
# The machine's aqmasd and aqmas are links, switched from v0.4.1 to this tree like an upgrade.
ln -sfn "$OLD_AQMASD" "$T/bin/aqmasd"; ln -sfn "$OLD_AQMAS" "$T/bin/aqmas"
D=$T/bin/aqmasd A=$T/bin/aqmas
ok "built this tree and $OLD_TAG ($(git -C "$OLD" rev-parse --short HEAD)) from a temporary worktree"

free_port() { bun -e 'const s = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } }); console.log(s.port); s.stop(true);'; }
PA=$(free_port) PW=$(free_port) PS=$(free_port) PF=$(free_port) PX=$(free_port)
ME=$(id -un) ORIGIN=https://aqmas.migrate.test
mkdir -p "$L"/{etc/tok,data,systemd} "$T"/{sshd/principals,client/config,client/cache,work}
chmod 700 "$L/data" "$L/etc/tok" "$T"/client/config "$T"/client/cache "$T/work"
ssh-keygen -q -t ed25519 -N '' -C interop-host -f "$T/sshd/hostkey"
echo "$ME@testhost" >"$T/sshd/principals/$ME"

# --- fake Cloudflare (the proxy parent token) and fake Cloudflare Access (windows) ---
ACCT=0123456789abcdef0123456789abcdef ZID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
PROXY_TOK=fake-proxy-parent-$(openssl rand -hex 18) MINTER_TOK=fake-minter-parent-$(openssl rand -hex 18)
(umask 077 && printf '%s\n' "$PROXY_TOK" >"$L/etc/tok/proxy" && printf '%s\n' "$MINTER_TOK" >"$L/etc/tok/minter" && printf '%s\n%s\n' "$PROXY_TOK" "$MINTER_TOK" >"$T/fakecf.tokens")
"$T/bin/fakecf" -listen "127.0.0.1:$PF" -token-file "$T/fakecf.tokens" -account $ACCT -zone example.com=$ZID >"$T/fakecf.log" 2>&1 &
PIDS+=($!)
TEAM=team.example.com AUD=interop-migrate-aud
"$T/bin/fakeaccess" -listen "127.0.0.1:$PX" -team $TEAM -aud $AUD -ca-out "$T/access-ca.pem" -token-out "$T/access.jwt" >"$T/fakeaccess.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do [[ -s $T/access.jwt ]] && curl -fsS "http://127.0.0.1:$PF/__fake/state" >/dev/null 2>&1 && break; sleep 0.1; done
[[ -s $T/access.jwt ]] || fail "fakeaccess did not start"
export AQMAS_ACCESS_JWT; AQMAS_ACCESS_JWT=$(cat "$T/access.jwt")

APPROVALS_TOPIC=http://127.0.0.1:1/SENTINELmigrateTOPIC
cat >"$L/etc/config.toml" <<EOF
# migration interop
listen_agent    = "127.0.0.1:$PA"
listen_web      = "127.0.0.1:$PW"
data_dir        = "$L/data"
public_base_url = "$ORIGIN"
owner_name      = "interop-owner"
tls_sans        = ["127.0.0.1"]
client_cert_days = 2

[ntfy]
topic_url = "$APPROVALS_TOPIC"

[access]
team_domain = "$TEAM"
aud = "$AUD"

[updates]
cache_dir = "$L/releases"
spool_dir = "$L/spool"

[ttl]
pending_expiry_seconds = 120

[cloudflare]
enabled = true
api_base = "http://127.0.0.1:$PF/client/v4"
allow_insecure_api_base = true
account_id = "$ACCT"
proxy_token_file = "$L/etc/tok/proxy"
minter_token_file = "$L/etc/tok/minter"
token_ip_condition = ["127.0.0.1/32"]
protected_access_hostnames = ["id.example.com"]
traefik_origin = "https://192.0.2.50:9443"
traefik_plain_origins = ["http://192.0.2.50"]

[[cloudflare.zones]]
name = "example.com"
id = "$ZID"

[[targets]]
name     = "testhost"
address  = "127.0.0.1"
port     = $PS
users    = ["$ME"]
host_key = "$(cut -d' ' -f1-2 "$T/sshd/hostkey.pub")"
EOF
echo '[Service]' >"$L/systemd/aqmasd.service"

# The hook is the test's systemd: one broker process (whatever $T/bin/aqmasd points at), which
# reaches the Access certs through fakeaccess and trusts its CA. "running" is one read of /proc.
cat >"$T/hook" <<EOF
#!/usr/bin/env bash
set -u
pidfile=$T/aqmasd.pid
running() { local s; [[ -f \$pidfile ]] && s=\$(cat "/proc/\$(cat \$pidfile)/status" 2>/dev/null) && [[ -n \$s ]] && ! grep -q '^State:[[:space:]]*[ZX]' <<<"\$s"; }
case \$1 in
stop) if running; then kill "\$(cat \$pidfile)"; for _ in \$(seq 600); do running || break; sleep 0.05; done; fi; ! running ;;
start) running && exit 1
  HTTPS_PROXY=http://127.0.0.1:$PX SSL_CERT_FILE=$T/access-ca.pem NO_PROXY=127.0.0.1,localhost setsid "$D" -config "$L/etc/config.toml" "\$2" >>"$T/aqmasd-\$2.log" 2>&1 </dev/null &
  echo \$! >\$pidfile ;;
active) running ;;
*) exit 2 ;;
esac
EOF
chmod +x "$T/hook"
maint() { "$D" "$1" "${@:2}" --test-layout "$L" "$T/hook" >>"$T/maint.log" 2>&1; }
wait_health() { for _ in $(seq 100); do curl -fsS "http://127.0.0.1:$PW/healthz" >/dev/null 2>&1 && return; sleep 0.1; done; fail "broker not healthy: $(tail -5 "$T"/aqmasd-*.log)"; }
restart() { "$T/hook" stop && "$T/hook" start serve && wait_health; }
schema() { "$D" -config "$L/etc/config.toml" setup-facts | bun -e 'console.log((await Bun.stdin.json()).schema)'; }

"$T/hook" start serve && wait_health
"$D" -config "$L/etc/config.toml" print-ssh-ca >"$T/sshd/ca.pub"
PIN=$("$D" -config "$L/etc/config.toml" tls-fingerprint)
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
EOF
"$SSHD" -D -e -f "$T/sshd/sshd_config" >"$T/sshd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PS") 2>/dev/null && break; sleep 0.1; done

# The owner: the helper and web modules of whichever version is installed (Access token preloaded).
export AQMAS_BASE=http://127.0.0.1:$PW AQMAS_ORIGIN=$ORIGIN OWNER_STATE=$T/owner.json
HELPER=$OLD/test/interop/owner.ts AQMAS_WEB_DIR=$OLD/web
export AQMAS_WEB_DIR
owner() { bun --preload "$ROOT/test/interop/access-preload.ts" "$HELPER" "$@"; }
owner register "$("$D" -config "$L/etc/config.toml" passkey-enroll-code | head -1)" >/dev/null
export AQMAS_CONFIG_DIR=$T/client/config AQMAS_CACHE_DIR=$T/client/cache
unset CLAUDECODE CLAUDE_SESSION_ID CLAUDE_CODE_SESSION_ID AQMAS_SESSION_ID SSH_AUTH_SOCK CLOUDFLARE_API_TOKEN CF_API_TOKEN || true
"$A" enroll --owner-device --name interop-host --server "https://127.0.0.1:$PA" --ca-pin "$PIN" --note "migrate interop" </dev/null >"$T/enroll.out" 2>"$T/enroll.err" &
EPID=$!
owner approve "$(owner wait enrollment interop-host 20)" >/dev/null 2>&1
wait $EPID || fail "enroll failed: $(cat "$T/enroll.err")"
grant() { # WHAT: a fresh SSH certificate, approved by the owner's own card, used for real
	"$A" ssh testhost --fresh --why "migrate interop: $1" -- echo granted </dev/null >"$T/ssh.out" 2>"$T/ssh.err" &
	local pid=$!
	owner approve "$(owner wait ssh interop-host 20)" 600 >/dev/null 2>"$T/ssh-owner.err" || { cat "$T/ssh-owner.err" "$T/ssh.err"; fail "approve after $1"; }
	wait $pid || { cat "$T/ssh.err"; fail "aqmas ssh after $1"; }
	[[ $(cat "$T/ssh.out") == granted ]] || fail "ssh after $1 printed '$(cat "$T/ssh.out")'"
}
grant "legacy start"
[[ $(schema) == 5 ]] || fail "expected a legacy database"

# --- 1. v0.4.1: runner, cutover, catalogue, seal (format 1), values, signer, second passkey ---
maint maint-init || { cat "$T/maint.log"; fail "maint-init"; }
(while :; do if [[ -e $L/spool/approved || -e $L/maint/journal.json ]]; then maint maint-run || true; fi; sleep 0.2; done) &
PIDS+=($!)
owner setup-run cutover 2>/dev/null
owner setup-wait cutover waiting 30 >/dev/null
owner activate-personal || fail "v0.4.1 cutover activation"
owner setup-wait cutover done 30 >/dev/null
owner catalogue create >/dev/null 2>&1 || fail "v0.4.1 catalogue"
RECIPIENT=$(owner age-keygen "$T/recovery.identity")
owner age-keygen "$T/other.identity" >/dev/null
owner setup-run seal "{\"recipient\":\"$RECIPIENT\",\"purge_backups\":true,\"lock_alert\":false}" 2>/dev/null
owner setup-wait seal waiting 30 >/dev/null
owner seal-eval; owner seal-eval
owner seal-drill "$T/recovery.identity"
owner seal-activate
owner setup-wait seal done 60 >/dev/null
[[ $(schema) == 8 && $(owner seal-status) == locked ]] || fail "v0.4.1 did not seal in format 1"
[[ ! -e $L/etc/tok/proxy && ! -e $L/data/ca/ssh_user_ca ]] || fail "v0.4.1 left plaintext sources"
owner login >/dev/null; owner seal-eval
[[ $(owner seal-status) == unlocked ]] || fail "v0.4.1 unlock"
SENTINEL=migrate-$(openssl rand -hex 16) SEED=$(openssl rand -hex 32)
printf 'APP_SECRET=%s\nAPP_TOKEN=second-%s\n' "$SENTINEL" "$SENTINEL" >"$T/work/form.env"
owner vault-commit client-a/paas/staging import "$T/work/form.env" >/dev/null 2>&1 || fail "v0.4.1 form commit"
printf '%s\n' "$SEED" >"$T/work/seed.hex"
owner vault-signer client-a/paas/release-key ed25519 import "$T/work/seed.hex" >"$T/work/signer.json" 2>/dev/null || fail "v0.4.1 signer import"
"$A" signer client-a/paas/release-key --pem >"$T/work/signer.pem"
"$A" cf api GET /zones --why "v0.4.1 proxy (cf.read is auto-approved)" </dev/null >"$T/cf-old-zones.out" 2>"$T/cf-old.err" || { cat "$T/cf-old.err"; fail "v0.4.1 proxied call"; }
owner capability register 'Old spare' unlock >/dev/null 2>&1 || fail "v0.4.1 second unlock passkey"
grant "v0.4.1 sealing"
ok "v0.4.1: cutover, catalogue, sealed in format 1 (schema 8), form values, imported signer, proxy parent, second unlock passkey"

# --- 2. this tree: migration required, then the runner task "buckets" ---
ln -sfn "$AQMASD" "$T/bin/aqmasd"; ln -sfn "$AQMAS" "$T/bin/aqmas"
HELPER=$ROOT/test/interop/owner.ts AQMAS_WEB_DIR=$ROOT/web
restart
source "$ROOT/test/interop/seal.sh" # nothing_open, open_kinds
owner login >/dev/null
[[ $(owner seal-status) == migration-required ]] || fail "new binary on a format-1 store: $(owner seal-status)"
"$A" ssh testhost --fresh --why "while migration is required" -- true </dev/null >/dev/null 2>"$T/mreq.err" &
RPID=$!; RID=$(owner wait ssh interop-host 20)
if owner approve "$RID" 300 >/dev/null 2>&1; then fail "approved while migration is required"; fi
owner deny "$RID" >/dev/null 2>&1 || fail "deny while migration is required"
RC=0; wait $RPID || RC=$?; ((RC == 3)) || fail "denied request exited $RC"
[[ $(owner setup-state buckets) == available ]] || fail "buckets task: $(owner setup-state buckets)"
ok "this tree on the v0.4.1 store: migration required (queue and deny only); the buckets task is offered"

owner setup-run buckets '{"purge_backups":false}' 2>/dev/null
owner setup-wait buckets waiting 60 >/dev/null
[[ $(owner seal-status) == setup ]] || fail "bucket-migrate mode not staged"
owner buckets --json | bun -e 'const s=(await Bun.stdin.json()).stage; if(s.source!=="format-1"||s.legacy_unlocked||s.choices.length!==2||s.choices.some(c=>!c.legacy))process.exit(1)' || fail "migration stage: $(owner buckets --json)"
if owner seal-activate 2>/dev/null; then fail "activated before staging"; fi
TAPS=$(owner stage 2>"$T/stage.err") || { cat "$T/stage.err"; fail "staging taps"; }
grep -q 'staging open-legacy installation' "$T/stage.err" || fail "no open-legacy tap"
owner buckets --json | bun -e 'const s=(await Bun.stdin.json()).stage; if(!s.legacy_unlocked||s.scopes.length!==3||s.scopes.some(x=>!x.wrapped||!x.tested))process.exit(1)' || fail "stage after the taps: $(owner buckets --json)"
if owner seal-activate 2>/dev/null; then fail "activated without the recovery drill"; fi
if owner seal-drill "$T/other.identity" 2>/dev/null; then fail "drill accepted another key"; fi
owner seal-drill "$T/recovery.identity" || fail "migration recovery drill"
owner seal-activate || fail "migration activation"
owner setup-wait buckets done 90 >"$T/buckets-result.json"
grep -q 'format1_backups' "$T/buckets-result.json" || fail "kept format-1 backups not reported: $(cat "$T/buckets-result.json")"
[[ $(schema) == 9 ]] || fail "not schema 9 after migration"
NEWPIN=$(sed -n 's/^manifest_sha256 = "\(.*\)"$/\1/p' "$L/etc/config.toml")
[[ $NEWPIN =~ ^[0-9a-f]{64}$ && -s $L/backups/sealed-${NEWPIN:0:16}/manifest.json ]] || fail "new activation not pinned"
owner login >/dev/null
[[ $(owner seal-status) == buckets ]] || fail "not serving buckets after migration"
nothing_open "migration"
owner buckets --json | bun -e 'const v=await Bun.stdin.json(); const k=v.buckets.map(b=>b.kind).sort().join();
  const spare=v.passkeys.find(p=>p.name==="Old spare"), me=v.passkeys.find(p=>p.current);
  if(k!=="cf-proxy,env-set,internal-ca,signer,ssh-ca"||v.scopes.filter(s=>s.has_key).length!==3||!spare||spare.scopes.length||!me||me.opens!==me.of)process.exit(1)' || fail "migrated buckets: $(owner buckets --json)"
ok "migrated in $TAPS staging taps (open-legacy, create, test), drill (wrong key refused), activation; schema 9; nothing open; the other unlock passkey is approve-only"

# --- 3. use, with only the needed bucket open each time ---
grant "migration"; nothing_open "SSH approval"
"$A" run client-a/paas/staging --why 'migrated values' -- sh -c '[ "$APP_SECRET" = "$1" ]' sh "$SENTINEL" </dev/null >"$T/run.out" 2>"$T/run.err" & RPID=$!
owner env-decide approve process; wait $RPID || { cat "$T/run.err"; fail "aqmas run did not deliver the migrated value"; }
nothing_open "aqmas run (collected)"
owner vault-reveal client-a/paas/staging APP_SECRET APP_TOKEN >"$T/work/revealed.json"
SENTINEL=$SENTINEL bun -e 'const e=await Bun.file(process.argv[1]).json(); if(JSON.stringify(e.map(x=>[x.name,x.value]))!==JSON.stringify([["APP_SECRET",process.env.SENTINEL],["APP_TOKEN","second-"+process.env.SENTINEL]]))process.exit(1)' "$T/work/revealed.json" || fail "reveal of migrated values"
rm "$T/work/revealed.json"; nothing_open "reveal"
head -c 140 /dev/urandom >"$T/work/manifest.bin"
"$A" sign client-a/paas/release-key --why 'migrated signer' - <"$T/work/manifest.bin" >"$T/work/sig.hex" 2>"$T/sign.err" & RPID=$!
owner vault-sign approve; wait $RPID || { cat "$T/sign.err"; fail "aqmas sign with the migrated key"; }
bun -e 'await Bun.write(process.argv[2], Buffer.from((await Bun.file(process.argv[1]).text()).trim(), "hex"))' "$T/work/sig.hex" "$T/work/sig.bin"
openssl pkeyutl -verify -pubin -inkey "$T/work/signer.pem" -rawin -in "$T/work/manifest.bin" -sigfile "$T/work/sig.bin" >/dev/null || fail "openssl rejected the migrated signer's signature"
nothing_open "single-use signature"
"$A" cf request cf.read --ttl 5m --why "migrated proxy" --json </dev/null >"$T/cf-new.out" 2>"$T/cf-new.err" & RPID=$!
owner approve "$(owner wait cloudflare interop-host 20)" 300 >/dev/null 2>&1; wait $RPID || fail "proxy request after migration"
[[ $(open_kinds) == cf-proxy ]] || fail "the proxy grant opened more: $(owner open-buckets)"
"$A" cf api GET /zones --why "migrated proxy" </dev/null >"$T/cf-new-zones.out" 2>&1 || fail "proxied call with the migrated parent"
owner buckets | bun -e 'const b=(await Bun.stdin.json()).find(b=>b.kind==="cf-proxy"); if(!b.holds.includes("grant"))process.exit(1)' || fail "proxy grant hold: $(owner buckets)"
owner close-all; nothing_open "close all after the proxy grant"
if timeout 60 "$A" cf api GET /zones --why "after close all" </dev/null >/dev/null 2>"$T/cf-closed.err"; then fail "proxied with the parent bucket closed"; fi
ok "after migration: SSH, aqmas run and Reveal of v0.4.1 values, aqmas sign with the v0.4.1 key, proxy with the v0.4.1 parent; each opened only its bucket"

# An approval window (personal, SSH): only the SSH CA is open while it is; two requests approved under it.
rm -f "$T/marker"
owner window 600 2 "$T/marker" >"$T/window.out" 2>"$T/window.err" & WPID=$!
for _ in $(seq 100); do [[ -s $T/marker ]] && break; sleep 0.2; done
[[ -s $T/marker ]] || { cat "$T/window.err"; fail "window did not open"; }
[[ $(open_kinds) == ssh-ca ]] || fail "the window opened more than the SSH CA: $(owner open-buckets)"
for n in 1 2; do
	"$A" ssh testhost --fresh --why "under window $n" -- echo windowed </dev/null >"$T/win.out" 2>"$T/win.err" || { cat "$T/win.err" "$T/window.err"; fail "ssh under the window"; }
	[[ $(cat "$T/win.out") == windowed ]] || fail "windowed ssh output"
done
grep -qx 'approved 2' "$T/marker" || fail "window approvals: $(cat "$T/marker")"
rm "$T/marker"; wait $WPID || { cat "$T/window.err"; fail "window helper"; }
nothing_open "window ended"
ok "approval window (Access-verified): only the SSH CA open while it lasts, two requests approved under it, closed after"

# Restart: nothing open; a signing grant is paused until one Reopen tap.
for f in a b c; do echo "artifact $f" >"$T/work/$f.bin"; done
"$A" sign client-a/paas/release-key --why 'grant over restart' --ttl 10m --count 5 "$T/work/a.bin" </dev/null >"$T/sg.out" 2>"$T/sg.err" & RPID=$!
owner vault-sign approve 600 5; wait $RPID || { cat "$T/sg.err"; fail "signing grant"; }
[[ $(open_kinds) == signer ]] || fail "signing grant opened more: $(owner open-buckets)"
restart; owner login >/dev/null; nothing_open "restart"
# Paused: the signing grant, and the proxy grant and cf.read auto-approval from before.
owner buckets | bun -e 'const b=(await Bun.stdin.json()).filter(b=>b.paused).map(b=>b.kind).sort().join(); if(b!=="cf-proxy,signer")process.exit(1)' || fail "paused after restart: $(owner buckets)"
if "$A" sign client-a/paas/release-key "$T/work/b.bin" </dev/null >/dev/null 2>"$T/sg-closed.err"; then fail "signed while the signer is closed"; fi
[[ $(owner reopen) == 1 ]] || fail "reopen after restart (two scopes, one tap)"
[[ $(open_kinds) == "cf-proxy signer" ]] || fail "reopen opened other than the paused buckets: $(owner open-buckets)"
"$A" sign client-a/paas/release-key "$T/work/b.bin" </dev/null >/dev/null 2>"$T/sg2.err" || { cat "$T/sg2.err"; fail "signing grant after reopen"; }
owner close-all; nothing_open "close all"
if "$A" sign client-a/paas/release-key "$T/work/c.bin" </dev/null >/dev/null 2>"$T/sg-closed2.err"; then fail "signed after close all"; fi
[[ $(owner reopen) == 1 ]] && "$A" sign client-a/paas/release-key "$T/work/c.bin" </dev/null >/dev/null 2>"$T/sg3.err" || fail "signing grant after close all + reopen"
"$A" sign client-a/paas/release-key --end >/dev/null 2>&1
[[ $(open_kinds) == cf-proxy ]] || fail "the ended signing grant left its bucket open: $(owner open-buckets)" # the proxy grant still holds its own
owner close-all; nothing_open "close all"
ok "restart opens nothing and pauses the signing grant; Reopen resumes it; Close all closes it again"

# A new organisation's first value needs its scope key ("club" had no buckets in v0.4.1).
printf 'CLUB_SECRET=%s\n' "$SENTINEL" >"$T/work/club.env"
if owner vault-commit club/paas/staging import "$T/work/club.env" >/dev/null 2>"$T/club.err"; then fail "wrote into an organisation without a scope key"; fi
grep -q 'create the scope first' "$T/club.err" || { cat "$T/club.err"; fail "no-scope refusal"; }
owner create-scope club 2>/dev/null || fail "create the club scope key"
owner vault-commit club/paas/staging import "$T/work/club.env" >/dev/null 2>&1 || fail "commit after creating the scope"
nothing_open "scope creation and commit"
ok "a new organisation's value is refused until its scope key is created; then written with nothing opened"

# Recovery: the browser drill, and the offline drill of a stopped broker's copy.
owner recovery-drill "$T/recovery.identity" >"$T/drill.json" || fail "browser recovery drill"
bun -e 'const r=await Bun.file(process.argv[1]).json(); if(!r.ok||r.scopes!==4||r.buckets!==6)process.exit(1)' "$T/drill.json" || fail "browser drill counts: $(cat "$T/drill.json")"
if owner recovery-drill "$T/other.identity" >/dev/null 2>&1; then fail "browser drill accepted another key"; fi
nothing_open "recovery drill"
"$T/hook" stop
[[ ! -e $L/data/aqmas.db-wal ]] || fail "the stopped broker left a WAL"
cp "$L/data/aqmas.db" "$T/backup.db"
"$T/hook" start serve && wait_health
"$D" -config "$L/etc/config.toml" seal-drill "$T/backup.db" "$RECIPIENT" <"$T/recovery.identity" >"$T/offline-drill.out" || fail "offline seal-drill"
if "$D" -config "$L/etc/config.toml" seal-drill "$T/backup.db" "$RECIPIENT" <"$T/other.identity" >/dev/null 2>&1; then fail "offline drill accepted another key"; fi
rm "$T/backup.db"
ok "browser drill ($(cat "$T/drill.json")) and offline drill: $(head -1 "$T/offline-drill.out")"

# Sentinels: values, the signer seed, the proxy parent and the recovery identity appear nowhere
# but where the test keeps its own inputs (work/, the identity files, the fake Cloudflare tokens).
RID_TEXT=$(cat "$T/recovery.identity")
SEED="$SEED" SENTINEL="$SENTINEL" PROXY="$PROXY_TOK" MINTER="$MINTER_TOK" IDENT="$RID_TEXT" bun -e '
  const {readdirSync,statSync,readFileSync}=require("node:fs"),path=require("node:path");
  const seed=Buffer.from(process.env.SEED,"hex");
  const forms=[seed,Buffer.from(process.env.SEED),Buffer.from(seed.toString("base64")),Buffer.from(seed.toString("base64url")),Buffer.from(process.env.SENTINEL),Buffer.from(process.env.PROXY),Buffer.from(process.env.MINTER),Buffer.from(process.env.IDENT.trim())];
  const skip=new Set(["work","v041","bin","fakecf.tokens","recovery.identity","other.identity","access.jwt","owner.json"]);
  let bad=[];const walk=d=>{for(const n of readdirSync(d)){const p=path.join(d,n);if(d===process.argv[1]&&skip.has(n))continue;if(p.endsWith("/etc/tok"))continue;
    const s=statSync(p);if(s.isDirectory())walk(p);else if(s.isFile()){const b=readFileSync(p);for(const f of forms)if(b.includes(f)){bad.push(p);break}}}};
  walk(process.argv[1]);if(bad.length){console.error(bad.join("\n"));process.exit(1)}' "$T" || fail "a secret leaked into the files above"
ok "sentinel scan: no value, signer seed, Cloudflare parent or recovery identity in the database, WAL, backups, logs or outputs"
echo "migrate-interop: all checks passed"
