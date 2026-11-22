#!/usr/bin/env bash
# Setup-queue interop (docs/SETUP.md): the real aqmasd, the real maintenance runner in its
# unprivileged test layout, the web UI's own setup code with a software passkey, and a
# throwaway sshd. A legacy (schema 5) broker with an enrolled host is taken through every
# Setup task from the web API alone:
#
#   cutover (cancel, then activate) → seal (wrong recovery key and cancel, then browser-made
#   key, on-box drill, activation, cold unlock) → enable self-update (mismatching release
#   refused, then seeded) → sync maintenance passkeys
#
# with an SSH grant issued and used after each step. A loop stands in for aqmas-maint.path;
# a hook script stands in for systemd. Nothing outside the temp dir is touched.
#
#   test/interop/run-setup.sh        # builds with `make build` first
#   KEEP=1 test/interop/run-setup.sh # keep the temp dir
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH=$HOME/.local/toolchains/go/bin:$PATH
fail() { echo "setup-interop: FAIL: $*" >&2; exit 1; }
ok() { echo "setup-interop: ok: $*"; }
for b in bun ssh ssh-keygen ssh-keyscan curl; do command -v $b >/dev/null || fail "$b not found"; done
SSHD=$(command -v sshd || true)
[[ -n $SSHD ]] || for p in /usr/sbin/sshd /usr/local/sbin/sshd; do [[ -x $p ]] && SSHD=$p; done
[[ -n $SSHD ]] || fail "sshd not found"
case $(uname -m) in aarch64 | arm64) ARCH=arm64 ;; x86_64 | amd64) ARCH=amd64 ;; *) fail "unsupported arch" ;; esac

VERSION=$(cat "$ROOT/VERSION") COMMIT=$(git -C "$ROOT" rev-parse HEAD)
if [[ -z ${AQMASD:-} || -z ${AQMAS:-} ]]; then
	make -C "$ROOT" --no-print-directory web build >/dev/null
	AQMASD=${AQMASD:-$ROOT/bin/aqmasd-linux-$ARCH} AQMAS=${AQMAS:-$ROOT/bin/aqmas-linux-$ARCH}
	if [[ ! -x $AQMASD ]]; then # make builds aqmasd for arm64 only; the runner needs a release identity
		AQMASD=$ROOT/bin/aqmasd-interop
		(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-X main.version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$COMMIT" -o "$AQMASD" ./cmd/aqmasd)
	fi
fi
"$AQMASD" version | grep -q 'web ui: embedded' || fail "aqmasd has no embedded web UI"

T=$(mktemp -d "${TMPDIR:-/tmp}/aqmas-setup.XXXXXX")
L=$T/lab # the runner's test layout: etc/, data/, spool/, releases/, maint/, backups/, alert/
PIDS=()
cleanup() {
	[[ -f $T/aqmasd.pid ]] && kill "$(cat "$T/aqmasd.pid")" 2>/dev/null || true
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [[ ${KEEP:-0} == 1 ]]; then echo "setup-interop: kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap 'echo "setup-interop: failed at line $LINENO; logs in $T (KEEP=1 keeps them)" >&2; KEEP=1; for f in "$T"/maint.log "$T"/aqmasd-*.log; do [ -f "$f" ] && { echo "--- tail $f" >&2; tail -25 "$f" >&2; }; done' ERR  # test logs hold no real secrets

free_port() { bun -e 'const s = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } }); console.log(s.port); s.stop(true);'; }
PA=$(free_port) PW=$(free_port) PS=$(free_port) PF=$(free_port) PG=$(free_port)
ME=$(id -un) ORIGIN=https://aqmas.setup.test
mkdir -p "$L"/{etc,data,systemd} "$T"/{sshd/principals,client/config,client/cache,rel-good,rel-bad}
chmod 700 "$L/data" "$T"/client/config "$T"/client/cache
ssh-keygen -q -t ed25519 -N '' -C interop-host -f "$T/sshd/hostkey"
echo "$ME@testhost" >"$T/sshd/principals/$ME"

# Secrets pasted in the UI. They may exist only where the runner stores them.
NTFY_TOPIC=https://ntfy.example.com/SENTINELlockalertTOPIC NTFY_TOKEN=tk_SENTINELlockalertTOKEN0123
FJ_TOKEN=fj_SENTINELforgejoREADtoken0123 GH_TOKEN=ghp_SENTINELgithubREADtoken0123

cat >"$L/etc/config.toml" <<EOF
# setup-queue interop; comments must survive the runner's edits
listen_agent    = "127.0.0.1:$PA"
listen_web      = "127.0.0.1:$PW"
data_dir        = "$L/data"
public_base_url = "$ORIGIN"
owner_name      = "interop-owner"
tls_sans        = ["127.0.0.1"]
client_cert_days = 2

[ntfy]
topic_url = "http://127.0.0.1:1/SENTINELapprovalsTOPIC"

[updates]
cache_dir = "$L/releases"
spool_dir = "$L/spool"

[ttl]
pending_expiry_seconds = 120

[[targets]]
name     = "testhost"
address  = "127.0.0.1"
port     = $PS
users    = ["$ME"]
host_key = "$(cut -d' ' -f1-2 "$T/sshd/hostkey.pub")"
EOF
echo '[Service]' >"$L/systemd/aqmasd.service"

# The hook is the test's systemd: one broker process, in the mode the runner asks for.
cat >"$T/hook" <<EOF
#!/usr/bin/env bash
set -u
pidfile=$T/aqmasd.pid
running() { [[ -f \$pidfile ]] && kill -0 "\$(cat \$pidfile)" 2>/dev/null; }
case \$1 in
stop) if running; then kill "\$(cat \$pidfile)"; for _ in \$(seq 600); do running || break; sleep 0.05; done; fi; ! running ;;  # up to 30 s: CI is slow
start) running && exit 1
  setsid "$AQMASD" -config "$L/etc/config.toml" "\$2" >>"$T/aqmasd-\$2.log" 2>&1 </dev/null &
  echo \$! >\$pidfile ;;
active) running ;;
*) exit 2 ;;
esac
EOF
chmod +x "$T/hook"
maint() { "$AQMASD" "$1" "${@:2}" --test-layout "$L" "$T/hook" >>"$T/maint.log" 2>&1; }
wait_health() { for _ in $(seq 100); do curl -fsS "http://127.0.0.1:$PW/healthz" >/dev/null 2>&1 && return; sleep 0.1; done; fail "broker not healthy: $(tail -5 "$T"/aqmasd-*.log)"; }

"$T/hook" start serve && wait_health
"$AQMASD" -config "$L/etc/config.toml" print-ssh-ca >"$T/sshd/ca.pub"
PIN=$("$AQMASD" -config "$L/etc/config.toml" tls-fingerprint)
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

export AQMAS_WEB_DIR=$ROOT/web AQMAS_BASE=http://127.0.0.1:$PW AQMAS_ORIGIN=$ORIGIN OWNER_STATE=$T/owner.json
owner() { bun "$ROOT/test/interop/owner.ts" "$@"; }
owner register "$("$AQMASD" -config "$L/etc/config.toml" passkey-enroll-code | head -1)" >/dev/null
export AQMAS_CONFIG_DIR=$T/client/config AQMAS_CACHE_DIR=$T/client/cache
unset CLAUDECODE CLAUDE_SESSION_ID CLAUDE_CODE_SESSION_ID AQMAS_SESSION_ID SSH_AUTH_SOCK || true
"$AQMAS" enroll --name interop-host --server "https://127.0.0.1:$PA" --ca-pin "$PIN" --note "setup interop" </dev/null >"$T/enroll.out" 2>"$T/enroll.err" &
EPID=$!
owner approve "$(owner wait enrollment interop-host 20)" >/dev/null 2>&1
wait $EPID || fail "enroll failed: $(cat "$T/enroll.err")"

# grant WHAT: a fresh certificate is requested, approved by the owner and used for real.
grant() {
	"$AQMAS" ssh testhost --fresh --why "setup interop: $1" -- echo granted </dev/null >"$T/ssh.out" 2>"$T/ssh.err" &
	local pid=$!
	owner approve "$(owner wait ssh interop-host 20)" 600 >/dev/null 2>&1 || { cat "$T/ssh.err"; fail "approve after $1"; }
	wait $pid || { cat "$T/ssh.err"; fail "aqmas ssh after $1"; }
	[[ $(cat "$T/ssh.out") == granted ]] || fail "ssh after $1 printed '$(cat "$T/ssh.out")'"
	ok "SSH grant issued and used after $1"
}
schema() { "$AQMASD" -config "$L/etc/config.toml" setup-facts | bun -e 'console.log((await Bun.stdin.json()).schema)'; }
grant "legacy start"
[[ $(schema) == 5 ]] || fail "expected a legacy database"

# --- the runner is not installed yet: every task says so ---
[[ $(owner setup-state cutover) == blocked:*"not installed"* ]] || fail "queue without a runner: $(owner setup-state cutover)"
maint maint-init || { cat "$T/maint.log"; fail "maint-init"; }
[[ $(stat -c %a "$L/etc/update-passkeys.json" "$L/etc/maint-secrets.key" | tr '\n' ' ') == "600 600 " ]] || fail "pins or secrets key are not private"
[[ $(owner setup-state cutover) == available && $(owner setup-state seal) == blocked:*organisations* && $(owner setup-state upgrade) == blocked:*self-update* ]] || fail "initial queue: $(owner setup)"
# Stand-in for aqmas-maint.path: start the runner whenever a request or a journal exists.
(while :; do if [[ -e $L/spool/approved || -e $L/maint/journal.json ]]; then maint maint-run || true; fi; sleep 0.2; done) &
PIDS+=($!)
ok "runner installed; queue shows cutover available, seal and upgrade blocked by their prerequisites"

# --- 1. organisations cutover: cancel leaves the legacy broker untouched, then the real one ---
owner setup-preview | grep -q '\\"slug\\":\\"personal\\"' || fail "no cutover plan preview"
owner setup-run cutover 2>"$T/sign-cutover.err" || { cat "$T/sign-cutover.err"; fail "sign cutover"; }
owner setup-wait cutover waiting 30 >/dev/null
if "$AQMAS" list >/dev/null 2>&1; then fail "agents were not fenced during the review"; fi
owner setup-cancel
owner setup-wait cutover failed 30 | grep -q 'cancelled' || fail "cancel not reported"
[[ $(schema) == 5 ]] || fail "cancelled cutover changed the schema"
grant "a cancelled cutover (rollback)"
owner setup-run cutover
owner setup-wait cutover waiting 30 >/dev/null
owner activate-personal || fail "signed activation"
owner setup-wait cutover done 30 >/dev/null
[[ $(schema) -ge 6 ]] || fail "cutover did not activate"
ls -d "$L"/backups/*-cutover/state/ca >/dev/null || fail "no cutover backup"
grant "the organisations cutover"

# --- 2. seal: a wrong recovery key and a cancel change nothing; then the real thing ---
RECIPIENT=$(owner age-keygen "$T/recovery.identity")
[[ $RECIPIENT =~ ^age1[a-z0-9]{58}$ ]] && grep -q '^AGE-SECRET-KEY-1' "$T/recovery.identity" || fail "browser-made age key: $RECIPIENT"
owner age-keygen "$T/other.identity" >/dev/null
cp "$L/etc/config.toml" "$T/config.before-seal"
SEAL_PARAMS="{\"recipient\":\"$RECIPIENT\",\"purge_backups\":true,\"lock_alert\":true}"
SEAL_SECRETS="{\"ntfy_topic_url\":\"$NTFY_TOPIC\",\"ntfy_token\":\"$NTFY_TOKEN\"}"
owner setup-run seal "$SEAL_PARAMS" "$SEAL_SECRETS" 2>"$T/sign-seal.err" || { cat "$T/sign-seal.err"; fail "sign seal"; }
owner setup-wait seal waiting 30 >/dev/null
[[ $(owner seal-status) == setup ]] || fail "import mode not offered"
owner seal-eval; owner seal-eval
if owner seal-activate 2>/dev/null; then fail "activated without a recovery drill"; fi
if owner seal-drill "$T/other.identity" 2>"$T/drill.err"; then fail "drill accepted another key"; fi
grep -q 'not the recovery key' "$T/drill.err" || { cat "$T/drill.err"; fail "wrong-key refusal"; }
if owner seal-activate 2>/dev/null; then fail "activated after a failed drill"; fi
owner setup-cancel
owner setup-wait seal failed 30 | grep -q 'unchanged and unsealed' || fail "seal cancel not reported"
cmp -s "$L/etc/config.toml" "$T/config.before-seal" || fail "cancelled seal left the configuration changed"
[[ -s $L/data/ca/ssh_user_ca && ! -e $L/alert/publish-token && -z $(ls -d "$L"/data/seal-stage-* 2>/dev/null) ]] || fail "cancelled seal left traces"
owner login >/dev/null
grant "a cancelled seal (rollback)"

owner setup-run seal "$SEAL_PARAMS" "$SEAL_SECRETS"
owner setup-wait seal waiting 30 >/dev/null
owner seal-eval; owner seal-eval
owner seal-drill "$T/recovery.identity" || fail "on-box recovery drill"
owner seal-activate || fail "seal activation"
owner setup-wait seal done 60 >"$T/seal-result.json"
grep -q 'manifest_sha256' "$T/seal-result.json" || fail "no manifest in the result"
[[ $(owner seal-status) == locked ]] || fail "sealed broker did not start locked"
[[ $(schema) == 8 ]] || fail "not sealed"
grep -q '^manifest_sha256 = "[0-9a-f]\{64\}"' "$L/etc/config.toml" && grep -q '^topic_url = ""' "$L/etc/config.toml" && grep -q 'comments must survive' "$L/etc/config.toml" || fail "configuration not pinned: $(cat "$L/etc/config.toml")"
[[ ! -e $L/data/ca/ssh_user_ca && ! -e $L/data/ca/client_ca.key && -s $L/data/ca/ssh_user_ca.pub ]] || fail "plaintext CA keys survive"
[[ $(ls "$L/backups") == sealed-* && -s $(echo "$L"/backups/sealed-*/inventory.json) ]] || fail "old backups not purged: $(ls "$L/backups")"
[[ $(cat "$L/alert/topic-url") == "$NTFY_TOPIC" && $(stat -c %a "$L/alert/publish-token") == 600 ]] || fail "lock-alert credential not stored"
owner login >/dev/null
owner seal-eval
[[ $(owner seal-status) == unlocked ]] || fail "cold unlock"
[[ $(owner setup-state seal) == done ]] || fail "seal not shown as done"
grant "sealing and a cold unlock"

# --- 3. enable self-update: a release that is not the installed binary is refused ---
mkdir -p "$T/rel-good" "$T/rel-bad"
for n in aqmas-darwin-arm64 aqmas-linux-amd64 aqmas-linux-arm64; do echo "cli $n" >"$T/rel-good/$n"; done
cp "$AQMASD" "$T/rel-good/aqmasd-linux-arm64"
(cd "$T/rel-good" && sha256sum aqmas-darwin-arm64 aqmas-linux-amd64 aqmas-linux-arm64 aqmasd-linux-arm64 >SHA256SUMS)
sed "s/^[0-9a-f]\{64\}  aqmasd-linux-arm64/$(printf 'f%.0s' {1..64})  aqmasd-linux-arm64/" "$T/rel-good/SHA256SUMS" >"$T/rel-bad/SHA256SUMS"
serve_release() { # DIR: both sources serve DIR
	for p in "${REL_PIDS[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done
	REL_PIDS=()
	for port in "$PF" "$PG"; do
		for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || break; sleep 0.1; done
		bun "$ROOT/test/interop/release-source.ts" "$port" "$VERSION" "$1/SHA256SUMS" & REL_PIDS+=($!); PIDS+=($!)
		for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$port/releases/tags/v$VERSION" >/dev/null 2>&1 && break; sleep 0.1; done
	done
}
REPO="ssh://git@127.0.0.1:$PS/example/agent-quartermaster.git"
HOSTKEY=$(owner setup-host-key "$REPO" | bun -e 'const r=await Bun.stdin.json();if(!r.keys[0].fingerprint.startsWith("SHA256:"))process.exit(1);console.log(r.keys.map(k=>k.line).filter(l=>l.includes("ssh-ed25519"))[0])')
[[ $HOSTKEY == "[127.0.0.1]:$PS ssh-ed25519 $(cut -d' ' -f2 "$T/sshd/hostkey.pub")" ]] || fail "host key lookup returned '$HOSTKEY'"
UP_PARAMS="{\"repo\":\"$REPO\",\"forgejo_api\":\"http://127.0.0.1:$PF/api/v1/repos/example/agent-quartermaster\",\"github_api\":\"http://127.0.0.1:$PG/repos/example/agent-quartermaster\",\"known_hosts\":[\"$HOSTKEY\"],\"forgejo_token\":true,\"github_token\":true}"
UP_SECRETS="{\"forgejo_token\":\"$FJ_TOKEN\",\"github_token\":\"$GH_TOKEN\"}"
cp "$L/etc/config.toml" "$T/config.before-updates"
serve_release "$T/rel-bad"
# Where releases come from is decided at the machine (`maint-init --repo …`), never by a
# request: until the sources are pinned the task is blocked.
[[ $(owner setup-state enable-updates) == blocked:*"Pin the release sources"* ]] || fail "enable-updates without pinned sources: $(owner setup-state enable-updates)"
if owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS" 2>"$T/sign-updates.err"; then fail "a request chose the release sources"; fi
maint maint-init --repo "$REPO" --forgejo-api "http://127.0.0.1:$PF/api/v1/repos/example/agent-quartermaster" --github-api "http://127.0.0.1:$PG/repos/example/agent-quartermaster" || fail "pinning the release sources"
if owner setup-run enable-updates "${UP_PARAMS/agent-quartermaster.git/elsewhere.git}" "$UP_SECRETS" 2>"$T/moved.err"; then fail "a request moved the pinned sources"; fi
grep -q 'fixed on this machine' "$T/moved.err" || { cat "$T/moved.err"; fail "pinned-source refusal"; }
owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS"
owner setup-wait enable-updates failed 60 | grep -q 'not the published' || fail "mismatching release not refused"
cmp -s "$L/etc/config.toml" "$T/config.before-updates" || fail "refused enable-updates changed the configuration"
[[ $(owner seal-status) == unlocked ]] || fail "a refused task restarted the broker"
grant "a refused enable-updates (rollback)"
serve_release "$T/rel-good"
owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS"
owner setup-wait enable-updates done 60 >"$T/updates-result.json"
grep -q '"deploy_key":"ssh-ed25519 ' "$T/updates-result.json" || fail "deploy key not shown"
grep -q "^repo = \"$REPO\"" "$L/etc/config.toml" && grep -q '^cache_dir' "$L/etc/config.toml" || fail "[updates] not written"
[[ $(cat "$L/etc/github-read-token") == "$GH_TOKEN" && $(cat "$L/etc/forgejo-read-token") == "$FJ_TOKEN" ]] || fail "tokens not stored"
grep -qF "$HOSTKEY" "$L/etc/known_hosts" || fail "forge host key not trusted"
[[ $(cat "$L/releases/$VERSION/aqmas-linux-amd64") == "cli aqmas-linux-amd64" ]] && grep -q "\"commit\":\"$COMMIT\"" "$L/releases/latest.json" || fail "release cache not seeded"
[[ $(owner seal-status) == locked ]] || fail "restart after enable-updates did not relock"
owner login >/dev/null; owner seal-eval
[[ $(owner setup-state enable-updates) == done && $(owner setup-state upgrade) == idle ]] || fail "queue after enable-updates: $(owner setup-state upgrade)"
grant "enabling self-update"

# --- 4. a new unlock passkey is not pinned until the owner signs the new list ---
owner capability register 'Setup spare' unlock
PINS() { owner setup | bun -e 'const v=await Bun.stdin.json();console.log(v.passkeys.filter(k=>k.pinned).length+"/"+v.passkeys.length)'; }
[[ $(PINS) == 1/2 && $(owner setup-state sync-passkeys) == available ]] || fail "new passkey pinned without a signature: $(PINS)"
owner setup-run sync-passkeys
owner setup-wait sync-passkeys done 30 >/dev/null
[[ $(PINS) == 2/2 ]] || fail "pins after sync: $(PINS)"
ok "maintenance passkeys synced by a signed list"

# --- nothing pasted in the UI may be anywhere but where the runner stores it ---
leaks=$(grep -rlE 'SENTINEL(lockalert|forgejoREAD|githubREAD)' "$T" --exclude-dir=alert --exclude=forgejo-read-token --exclude=github-read-token --exclude='config.before-*' --exclude='sign-*.err' 2>/dev/null || true)
[[ -z $leaks ]] || fail "pasted secrets leaked into: $leaks"
if grep -rl 'SENTINELapprovalsTOPIC\|AGE-SECRET-KEY-1' "$L" 2>/dev/null | grep -q .; then fail "retired notification URL or the recovery key is on the broker's disk"; fi
ok "pasted secrets exist only in their root-owned files; the recovery key was never stored"
echo "setup-interop: all checks passed"
