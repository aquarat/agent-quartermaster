#!/usr/bin/env bash
# Setup-queue interop (docs/SETUP.md): the real aqmasd, the real maintenance runner in its
# unprivileged test layout, the web UI's own setup code with a software passkey, and a
# throwaway sshd. A legacy (schema 5) broker with an enrolled host is taken through every
# Setup task from the web API alone:
#
#   cutover (cancel, then activate) → seal into per-credential buckets (wrong recovery key and
#   cancel, then browser-made key, staging taps, on-box drill, activation, nothing open after) → enable self-update, first with
#   GitHub alone (no key, no token), then with a second source that must agree (mismatching and disagreeing releases
#   refused, then seeded) → sync maintenance passkeys → access to the bastion itself (bastion.sh)
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
	# The suite's release sources are plain http on 127.0.0.1, which only a binary built with
	# the "interop" tag accepts (release builds are https only): build both for this machine.
	make -C "$ROOT" --no-print-directory web build >/dev/null
	AQMASD=${AQMASD:-$ROOT/bin/aqmasd-interop} AQMAS=${AQMAS:-$ROOT/bin/aqmas-interop}
	(cd "$ROOT" && CGO_ENABLED=0 go build -tags interop -trimpath -buildvcs=false -ldflags "-X main.version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/client.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$COMMIT" -o "$ROOT/bin/aqmasd-interop" ./cmd/aqmasd &&
		CGO_ENABLED=0 go build -tags interop -trimpath -buildvcs=false -ldflags "-X main.version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/client.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Version=$VERSION -X github.com/aquarat/agent-quartermaster/internal/release.Commit=$COMMIT" -o "$ROOT/bin/aqmas-interop" ./cmd/aqmas)
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
PA=$(free_port) PW=$(free_port) PS=$(free_port) PF=$(free_port) PG=$(free_port) PR=$(free_port)
ME=$(id -un) ORIGIN=https://aqmas.setup.test
mkdir -p "$L"/{etc,data,systemd} "$T"/{sshd/principals,client/config,client/cache,rel-good,rel-bad}
chmod 700 "$L/data" "$T"/client/config "$T"/client/cache
ssh-keygen -q -t ed25519 -N '' -C interop-host -f "$T/sshd/hostkey"
echo "$ME@testhost" >"$T/sshd/principals/$ME"

# Secrets pasted in the UI. They may exist only where the runner stores them.
NTFY_TOPIC=https://ntfy.example.com/SENTINELlockalertTOPIC NTFY_TOKEN=tk_SENTINELlockalertTOKEN0123
SECOND_TOKEN=fj_SENTINELsecondREADtoken0123 GH_TOKEN=ghp_SENTINELgithubREADtoken0123

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
# A killed broker stays a zombie where PID 1 does not reap (CI containers), so "the PID exists"
# is not "running". One read of /proc decides: asking twice (kill -0, then the state) called a
# broker that was reaped between the two questions "running", and stop or start then failed.
running() { local s; [[ -f \$pidfile ]] && s=\$(cat "/proc/\$(cat \$pidfile)/status" 2>/dev/null) && [[ -n \$s ]] && ! grep -q '^State:[[:space:]]*[ZX]' <<<"\$s"; }
case \$1 in
stop) if running; then kill "\$(cat \$pidfile)"; for _ in \$(seq 600); do running || break; sleep 0.05; done; fi; ! running ;;  # up to 30 s: CI is slow
start) running && exit 1
  setsid "$AQMASD" -config "$L/etc/config.toml" "\$2" >>"$T/aqmasd-\$2.log" 2>&1 </dev/null &
  echo \$! >\$pidfile ;;
active) running ;;
sys) shift; [[ -x $T/sys ]] && exec "$T/sys" "\$@"; exit 0 ;;  # the bastion tasks' system tools (bastion.sh)
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
[[ $(owner setup-state buckets) == blocked:*"Not needed"* ]] || fail "buckets task on an unsealed store: $(owner setup-state buckets)"
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
owner stage >/dev/null 2>"$T/stage.err" || { cat "$T/stage.err"; fail "staging taps"; }
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
owner stage >/dev/null 2>"$T/stage.err" || { cat "$T/stage.err"; fail "staging taps"; }
owner seal-drill "$T/recovery.identity" || fail "on-box recovery drill"
owner seal-activate || fail "seal activation"
owner setup-wait seal done 60 >"$T/seal-result.json"
grep -q 'manifest_sha256' "$T/seal-result.json" || fail "no manifest in the result"
[[ $(owner seal-status) == buckets ]] || fail "sealed broker does not serve buckets: $(owner seal-status)"
[[ $(schema) == 9 ]] || fail "not sealed in format 2"
grep -q '^manifest_sha256 = "[0-9a-f]\{64\}"' "$L/etc/config.toml" && grep -q '^topic_url = ""' "$L/etc/config.toml" && grep -q 'comments must survive' "$L/etc/config.toml" || fail "configuration not pinned: $(cat "$L/etc/config.toml")"
[[ ! -e $L/data/ca/ssh_user_ca && ! -e $L/data/ca/client_ca.key && -s $L/data/ca/ssh_user_ca.pub ]] || fail "plaintext CA keys survive"
[[ $(ls "$L/backups") == sealed-* && -s $(echo "$L"/backups/sealed-*/manifest.json) ]] || fail "old backups not purged: $(ls "$L/backups")"
[[ $(cat "$L/alert/topic-url") == "$NTFY_TOPIC" && $(stat -c %a "$L/alert/publish-token") == 600 ]] || fail "lock-alert credential not stored"
owner login >/dev/null
[[ -z $(owner open-buckets) ]] || fail "a bucket is open after the sealed restart: $(owner open-buckets)"
[[ $(owner setup-state seal) == done && $(owner setup-state buckets) == done ]] || fail "seal not shown as done: $(owner setup-state buckets)"
grant "sealing (the approval opens the SSH CA)"
[[ -z $(owner open-buckets) ]] || fail "the SSH approval left a bucket open: $(owner open-buckets)"

# --- 3. enable self-update: a release that is not the installed binary is refused ---
mkdir -p "$T/rel-good" "$T/rel-bad"
for n in aqmas-darwin-arm64 aqmas-linux-amd64 aqmas-linux-arm64; do echo "cli $n" >"$T/rel-good/$n"; done
cp "$AQMASD" "$T/rel-good/aqmasd-linux-arm64"
(cd "$T/rel-good" && sha256sum aqmas-darwin-arm64 aqmas-linux-amd64 aqmas-linux-arm64 aqmasd-linux-arm64 >SHA256SUMS)
# A build listed in SHA256SUMS.extra (0.9.3 on) is seeded the same way.
echo "cli aqmas-darwin-amd64" >"$T/rel-good/aqmas-darwin-amd64"
(cd "$T/rel-good" && sha256sum aqmas-darwin-amd64 >SHA256SUMS.extra)
cp "$T/rel-good/SHA256SUMS.extra" "$T/rel-bad/SHA256SUMS.extra"
sed "s/^[0-9a-f]\{64\}  aqmasd-linux-arm64/$(printf 'f%.0s' {1..64})  aqmasd-linux-arm64/" "$T/rel-good/SHA256SUMS" >"$T/rel-bad/SHA256SUMS"
serve_release() { # GITHUB_DIR [SECOND_DIR]: what GitHub ($PG) and the second source ($PF) publish
	for p in "${REL_PIDS[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done
	REL_PIDS=()
	local dir
	for port in "$PG" "$PF"; do
		dir=$1; [[ $port == "$PF" ]] && dir=${2:-$1}
		for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || break; sleep 0.1; done
		bun "$ROOT/test/interop/release-source.ts" "$port" "$VERSION" "$dir/SHA256SUMS" & REL_PIDS+=($!); PIDS+=($!)
		for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$port/releases/tags/v$VERSION" >/dev/null 2>&1 && break; sleep 0.1; done
	done
}
epoch() { owner buckets --json | bun -e 'console.log((await Bun.stdin.json()).epoch)'; }
sources() { owner setup | bun -e 'const s=(await Bun.stdin.json()).update_sources;console.log([s.origin,(s.compared??[]).length,(s.active??[]).length,s.second_api?"second":"github-only"].join(" "))'; }
GH_API="http://127.0.0.1:$PG/repos/example/agent-quartermaster"
SECOND_API="http://127.0.0.1:$PF/api/v1/repos/example/agent-quartermaster"

# --- 3a. GitHub only: one published source and this machine's rebuild; no key, no token ---
# Nothing is configured: the task is available (not blocked) and its sources are the built-in
# GitHub defaults. A request cannot choose others, the test's own stand-in included.
HTTP_REPO="http://127.0.0.1:$PR/example/agent-quartermaster.git" # stands in for https://github.com/…; nothing listens: discovery just fails
ONE_PARAMS="{\"repo\":\"$HTTP_REPO\",\"github_api\":\"$GH_API\",\"second_api\":\"\",\"known_hosts\":[],\"github_token\":false,\"second_token\":false}"
[[ $(owner setup-state enable-updates) == available && $(sources) == "default 1 0 github-only" ]] || fail "enable-updates with nothing configured: $(owner setup-state enable-updates) / $(sources)"
[[ ! -e $L/etc/repo-key ]] || fail "a deploy key was made although no SSH repository is configured"
if owner setup-run enable-updates "$ONE_PARAMS" 2>"$T/sign-updates.err"; then fail "a request chose the release sources"; fi
grep -q 'fixed on this machine' "$T/sign-updates.err" || { cat "$T/sign-updates.err"; fail "refusal of chosen sources"; }
# The owner, at the machine, points it at the stand-in GitHub (a fork would do the same).
maint maint-init --repo "$HTTP_REPO" --github-api "$GH_API" || fail "pinning GitHub-only sources"
[[ $(sources) == "pinned 1 0 github-only" ]] || fail "sources after pinning GitHub only: $(sources)"
if owner setup-run enable-updates "${ONE_PARAMS/\"second_api\":\"\"/\"second_api\":\"$SECOND_API\"}" 2>"$T/sign-added.err"; then fail "a request added a second source"; fi
cp "$L/etc/config.toml" "$T/config.before-updates"
EPOCH=$(epoch)
serve_release "$T/rel-bad" "$T/rel-good"
owner setup-run enable-updates "$ONE_PARAMS"
owner setup-wait enable-updates failed 60 | grep -q 'not the published' || fail "GitHub only: mismatching release not refused"
cmp -s "$L/etc/config.toml" "$T/config.before-updates" || fail "refused enable-updates changed the configuration"
[[ $(epoch) == "$EPOCH" ]] || fail "a refused task restarted the broker"
# The second source publishes something else and is simply not asked: it is not configured.
serve_release "$T/rel-good" "$T/rel-bad"
owner setup-run enable-updates "$ONE_PARAMS"
owner setup-wait enable-updates done 60 >"$T/updates-one.json"
grep -q '"sources":"GitHub"' "$T/updates-one.json" && ! grep -q deploy_key "$T/updates-one.json" || fail "GitHub-only result: $(cat "$T/updates-one.json")"
grep -q "^repo = \"$HTTP_REPO\"" "$L/etc/config.toml" && grep -q '^cache_dir' "$L/etc/config.toml" || fail "[updates] not written"
! grep -qE '^deploy_key|^\[updates\.(second|forgejo)\]|^token_file' "$L/etc/config.toml" || fail "GitHub-only configuration has a key, a second source or a token"
[[ ! -e $L/etc/repo-key && ! -e $L/etc/github-read-token && ! -e $L/etc/second-read-token && ! -s $L/etc/known_hosts ]] || fail "GitHub-only setup left a key, a token or a host key"
grep -q '"sources":1' "$L/releases/latest.json" && ! grep -q '"second"' "$L/releases/latest.json" && grep -q "\"commit\":\"$COMMIT\"" "$L/releases/latest.json" || fail "GitHub-only release identity: $(cat "$L/releases/latest.json")"
[[ $(cat "$L/releases/$VERSION/aqmas-linux-amd64") == "cli aqmas-linux-amd64" && $(cat "$L/releases/$VERSION/aqmas-darwin-amd64") == "cli aqmas-darwin-amd64" ]] || fail "release cache not seeded"
cmp -s "$T/rel-good/SHA256SUMS.extra" "$L/releases/$VERSION/SHA256SUMS.extra" && grep -q '"extra":{"aqmas-darwin-amd64"' "$L/releases/latest.json" || fail "SHA256SUMS.extra not recorded: $(cat "$L/releases/latest.json")"
owner login >/dev/null
# Nothing serves the repository, so the check for a new release cannot succeed: the upgrade
# task says so (first check pending, or failed) and never reads "idle" (shown as "Up to date").
[[ $(owner setup-state enable-updates) == done && $(owner setup-state upgrade) == blocked:*"check for a new release"* && $(sources) == "pinned 1 1 github-only" ]] || fail "queue after GitHub-only enable: $(owner setup-state upgrade) / $(sources)"
owner setup | grep -q 'No second release source is configured' || fail "the Setup page does not say that only GitHub is compared"
owner updates | grep -q '"sources":\["GitHub"\]' || fail "the update view does not name its one source: $(owner updates)"
grant "enabling self-update with GitHub only"
ok "self-update enabled with GitHub alone: no deploy key, no host key, no token; one published source"

# --- 3b. a second source, named at the machine: from now on it must agree ---
REPO="ssh://git@127.0.0.1:$PS/example/agent-quartermaster.git"
HOSTKEY=$(owner setup-host-key "$REPO" | bun -e 'const r=await Bun.stdin.json();if(!r.keys[0].fingerprint.startsWith("SHA256:"))process.exit(1);console.log(r.keys.map(k=>k.line).filter(l=>l.includes("ssh-ed25519"))[0])')
[[ $HOSTKEY == "[127.0.0.1]:$PS ssh-ed25519 $(cut -d' ' -f2 "$T/sshd/hostkey.pub")" ]] || fail "host key lookup returned '$HOSTKEY'"
UP_PARAMS="{\"repo\":\"$REPO\",\"github_api\":\"$GH_API\",\"second_api\":\"$SECOND_API\",\"known_hosts\":[\"$HOSTKEY\"],\"github_token\":true,\"second_token\":true}"
UP_SECRETS="{\"github_token\":\"$GH_TOKEN\",\"second_token\":\"$SECOND_TOKEN\"}"
# Still GitHub only on this machine: a request cannot add the second source by itself.
if owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS" 2>"$T/sign-second.err"; then fail "a request added a second source"; fi
maint maint-init --repo "$REPO" --second-api "$SECOND_API" --github-api "$GH_API" || fail "pinning the release sources"
[[ $(sources) == "pinned 2 1 second" ]] || fail "sources after pinning a second one: $(sources)"
[[ -s $L/etc/repo-key.pub ]] || fail "no deploy key for the SSH repository"
if owner setup-run enable-updates "${UP_PARAMS/agent-quartermaster.git/elsewhere.git}" "$UP_SECRETS" 2>"$T/moved.err"; then fail "a request moved the pinned sources"; fi
grep -q 'fixed on this machine' "$T/moved.err" || { cat "$T/moved.err"; fail "pinned-source refusal"; }
if owner setup-run enable-updates "$ONE_PARAMS" 2>"$T/sign-dropped.err"; then fail "a request dropped the configured second source"; fi
cp "$L/etc/config.toml" "$T/config.before-updates"
EPOCH=$(epoch)
serve_release "$T/rel-bad"
owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS"
owner setup-wait enable-updates failed 60 | grep -q 'not the published' || fail "mismatching release not refused"
# GitHub is right and the second source disagrees: refused, GitHub alone is not enough any more.
serve_release "$T/rel-good" "$T/rel-bad"
owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS"
owner setup-wait enable-updates failed 60 | grep -q 'disagree between GitHub and the second source' || fail "disagreeing second source not refused"
# ... and so is a second source that does not answer.
kill "${REL_PIDS[1]}" 2>/dev/null || true
for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PF") 2>/dev/null || break; sleep 0.1; done
owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS"
owner setup-wait enable-updates failed 60 | grep -q 'second source (' || fail "unreachable second source not refused"
cmp -s "$L/etc/config.toml" "$T/config.before-updates" || fail "refused enable-updates changed the configuration"
[[ $(epoch) == "$EPOCH" ]] || fail "a refused task restarted the broker"
grep -q '"sources":1' "$L/releases/latest.json" || fail "a refused task changed the release identity"
grant "a refused enable-updates (rollback)"
serve_release "$T/rel-good"
owner setup-run enable-updates "$UP_PARAMS" "$UP_SECRETS"
owner setup-wait enable-updates done 60 >"$T/updates-result.json"
grep -q '"deploy_key":"ssh-ed25519 ' "$T/updates-result.json" || fail "deploy key not shown"
grep -q "\"sources\":\"GitHub and second source (127.0.0.1:$PF)\"" "$T/updates-result.json" || fail "two-source result: $(cat "$T/updates-result.json")"
grep -q "^repo = \"$REPO\"" "$L/etc/config.toml" && grep -q '^cache_dir' "$L/etc/config.toml" && grep -q '^\[updates\.second\]' "$L/etc/config.toml" && grep -q "^api = \"$SECOND_API\"" "$L/etc/config.toml" || fail "[updates] not written"
[[ $(cat "$L/etc/github-read-token") == "$GH_TOKEN" && $(cat "$L/etc/second-read-token") == "$SECOND_TOKEN" ]] || fail "tokens not stored"
grep -qF "$HOSTKEY" "$L/etc/known_hosts" || fail "forge host key not trusted"
[[ $(cat "$L/releases/$VERSION/aqmas-linux-amd64") == "cli aqmas-linux-amd64" ]] && grep -q "\"commit\":\"$COMMIT\"" "$L/releases/latest.json" && grep -q '"sources":2' "$L/releases/latest.json" || fail "release cache not seeded"
owner login >/dev/null
[[ $(owner seal-status) == buckets && -z $(owner open-buckets) ]] || fail "restart after enable-updates left something open"
[[ $(owner setup-state enable-updates) == done && $(owner setup-state upgrade) == @(idle|blocked:*"check for a new release"*) && $(sources) == "pinned 2 2 second" ]] || fail "queue after enable-updates: $(owner setup-state upgrade) / $(sources)"
owner updates | grep -q "\"sources\":\[\"GitHub\",\"second source (127.0.0.1:$PF)\"\]" || fail "the update view does not name its two sources: $(owner updates)"
# From here on the second source cannot be dropped by leaving it out: not by a new pin ...
if maint maint-init --repo "$HTTP_REPO" --github-api "$GH_API"; then fail "a pin without --second-api dropped the second source"; fi
grep -q -- '--github-only' "$T/maint.log" || fail "the refusal does not name --github-only"
[[ $(sources) == "pinned 2 2 second" ]] || fail "sources after a refused re-pin: $(sources)"
ok "self-update enabled with a second source: it must agree and must answer"
grant "enabling self-update"

# --- 4. a new passkey that opens buckets is not pinned until the owner signs the new list ---
owner capability register 'Setup spare' unlock
PINS() { owner setup | bun -e 'const v=await Bun.stdin.json();console.log(v.passkeys.filter(k=>k.pinned).length+"/"+v.passkeys.length)'; }
[[ $(PINS) == 1/2 && $(owner setup-state sync-passkeys) == available ]] || fail "new passkey pinned without a signature: $(PINS)"
owner setup-run sync-passkeys
owner setup-wait sync-passkeys done 30 >/dev/null
[[ $(PINS) == 2/2 ]] || fail "pins after sync: $(PINS)"
ok "maintenance passkeys synced by a signed list"

# --- 5. access to the bastion itself: inspect, root, routine tasks (docs/BASTION-ACCESS.md) ---
source "$ROOT/test/interop/bastion.sh"
bastion_scenario

# --- nothing pasted in the UI may be anywhere but where the runner stores it ---
leaks=$(grep -rlE 'SENTINEL(lockalert|secondREAD|githubREAD)' "$T" --exclude-dir=alert --exclude=second-read-token --exclude=github-read-token --exclude='config.before-*' --exclude='sign-*.err' 2>/dev/null || true)
[[ -z $leaks ]] || fail "pasted secrets leaked into: $leaks"
# Format 2 keeps the approval-notice topic readable in the database (notice_channel, docs/BUCKETS.md §9):
# notices go out while everything is closed. It must have left the configuration, and the recovery key is nowhere.
leaks=$( (grep -rl 'AGE-SECRET-KEY-1' "$L"; grep -rl 'SENTINELapprovalsTOPIC' "$L" --exclude='aqmas.db' --exclude='aqmas.db-wal') 2>/dev/null || true)
[[ -z $leaks ]] || fail "retired notification URL or the recovery key is on the broker's disk: $leaks"
grep -q 'SENTINELapprovalsTOPIC' "$L/data/aqmas.db" "$L/data/aqmas.db-wal" 2>/dev/null || fail "the approval-notice topic did not move into the database"
ok "pasted secrets exist only in their root-owned files; the recovery key was never stored"
echo "setup-interop: all checks passed"
