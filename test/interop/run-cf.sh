#!/usr/bin/env bash
# Milestone 2 interop: the real aqmasd + aqmas binaries against the in-memory fake Cloudflare
# API (test/interop/fakecf), with the owner played by test/interop/owner.ts (the web UI's own
# flow code + a software passkey). Everything runs on 127.0.0.1 in a temp dir with fake tokens;
# no real Cloudflare API, account, key or fleet host is touched.
#
#   test/interop/run-cf.sh                 # builds aqmasd/aqmas/fakecf first
#   WRANGLER=1 test/interop/run-cf.sh      # also installs wrangler (bun add) and deploys through the shim
#   WRANGLER_BIN=.../wrangler.js test/interop/run-cf.sh   # use an installed wrangler
#   KEEP=1 test/interop/run-cf.sh          # keep the temp dir
#
# Proves: auto-approval of cf.read (no card); the deny-list (also against path tricks sent
# straight to the proxy with curl); scope enforcement + the needs-scope hint; tunnel config
# snapshot-before-PUT (and after), snapshot list/get; the tunnel guard rails (originServerName,
# plain :80 origin, catch-all) and the stale-version 409; the id.example.com Access guard
# (exact, wildcard, destinations; not overridable even with cf.admin) and the PATCH refusal;
# a cf.admin override of an overridable guard; child-token mint with name/expiry/IP condition,
# use, and deletion by the sweeper after expiry; revoke of a proxy grant takes effect at once;
# audit rows; no fake parent token value in any log or output; optionally wrangler deploy +
# d1 execute through `aqmas cf env` and the real proxy.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH=$HOME/.local/toolchains/go/bin:$PATH

fail() { echo "interop-cf: FAIL: $*" >&2; exit 1; }
ok() { echo "interop-cf: ok: cf: $*"; }

for b in bun curl go; do command -v $b >/dev/null || fail "$b not found"; done

T=$(mktemp -d "${TMPDIR:-/tmp}/aqmas-interop-cf.XXXXXX")
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [[ ${KEEP:-0} == 1 ]]; then echo "interop-cf: kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap 'echo "interop-cf: failed at line $LINENO; logs in $T (KEEP=1 keeps them)" >&2; KEEP=1' ERR

mkdir -p "$T"/{bin,data,tok,client/config,client/cache,work}
chmod 700 "$T"/data "$T"/tok "$T"/client/config "$T"/client/cache
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$T/bin/aqmasd" ./cmd/aqmasd &&
	CGO_ENABLED=0 go build -trimpath -o "$T/bin/aqmas" ./cmd/aqmas &&
	go build -o "$T/bin/fakecf" ./test/interop/fakecf)
if ! "$T/bin/aqmasd" version | grep -q 'web ui: embedded'; then
	make -C "$ROOT" --no-print-directory webui >/dev/null
	(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$T/bin/aqmasd" ./cmd/aqmasd)
fi
AQMASD=$T/bin/aqmasd AQMAS=$T/bin/aqmas

free_port() { bun -e 'const s = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } }); console.log(s.port); s.stop(true);'; }
PA=$(free_port) PW=$(free_port) PF=$(free_port)
ORIGIN=https://aqmas.interop.test
ACCT=0123456789abcdef0123456789abcdef
ZID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
TUN=7e570b05-0000-4000-8000-000000000000
DB=11111111-2222-4333-8444-555555555555
FAKE=http://127.0.0.1:$PF
# Fake parent tokens: random, never printed; the leak check at the end greps for them.
PROXY_TOK=fake-proxy-parent-$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
MINTER_TOK=fake-minter-parent-$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
(umask 077 && printf '%s\n' "$PROXY_TOK" >"$T/tok/proxy" && printf '%s\n' "$MINTER_TOK" >"$T/tok/minter" &&
	printf '%s\n%s\n' "$PROXY_TOK" "$MINTER_TOK" >"$T/tok/fakecf")

# --- fake Cloudflare ---
"$T/bin/fakecf" -listen "127.0.0.1:$PF" -token-file "$T/tok/fakecf" -account $ACCT \
	-zone example.com=$ZID -tunnel home=$TUN -d1 times=$DB >"$T/fakecf.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do curl -fsS "$FAKE/__fake/state" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS "$FAKE/__fake/state" >/dev/null || fail "fakecf did not start"
fakereq() { curl -fsS "$FAKE/__fake/requests" | sed "s/^null$/[]/"; }
fakeclear() { curl -fsS -X DELETE "$FAKE/__fake/requests" >/dev/null; }

cat >"$T/config.toml" <<EOF
listen_agent    = "127.0.0.1:$PA"
listen_web      = "127.0.0.1:$PW"
data_dir        = "$T/data"
public_base_url = "$ORIGIN"
owner_name      = "interop-owner"
tls_sans        = ["127.0.0.1"]
client_cert_days = 2

[ttl]
pending_expiry_seconds = 120
min_seconds = 60

[cloudflare]
enabled = true
api_base = "$FAKE/client/v4"
allow_insecure_api_base = true
account_id = "$ACCT"
proxy_token_file = "$T/tok/proxy"
minter_token_file = "$T/tok/minter"
token_ip_condition = ["127.0.0.1/32"]
# Guard-rail facts the checks below rely on (no built-in defaults; keep in step with the
# hostnames and origins used in this script).
protected_access_hostnames = ["id.example.com"]
traefik_origin = "https://192.0.2.50:9443"
traefik_plain_origins = ["http://192.0.2.50", "http://192.0.2.50:80"]

[[cloudflare.zones]]
name = "example.com"
id = "$ZID"
[[cloudflare.tunnels]]
name = "home"
id = "$TUN"
[[cloudflare.d1_databases]]
name = "times"
id = "$DB"
[[cloudflare.worker_bindings]]
script = "interop-worker"
allow = ["d1:times"]
EOF

"$AQMASD" -config "$T/config.toml" serve >"$T/aqmasd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$PW/api/ui/session" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS "http://127.0.0.1:$PW/api/ui/session" >/dev/null || { cat "$T/aqmasd.log"; fail "aqmasd did not start"; }
PIN=$("$AQMASD" -config "$T/config.toml" tls-fingerprint)
ok "aqmasd up with [cloudflare] -> fakecf on :$PF"

export AQMAS_WEB_DIR=$ROOT/web AQMAS_BASE=http://127.0.0.1:$PW AQMAS_ORIGIN=$ORIGIN OWNER_STATE=$T/owner.json
owner() { bun "$ROOT/test/interop/owner.ts" "$@"; }
owner register "$("$AQMASD" -config "$T/config.toml" passkey-enroll-code | head -1)" >/dev/null

export AQMAS_CONFIG_DIR=$T/client/config AQMAS_CACHE_DIR=$T/client/cache
unset CLAUDECODE CLAUDE_SESSION_ID CLAUDE_CODE_SESSION_ID AQMAS_SESSION_ID SSH_AUTH_SOCK || true
unset CLOUDFLARE_API_TOKEN CF_API_TOKEN CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL || true
"$AQMAS" enroll --name interop-host --server "https://127.0.0.1:$PA" --ca-pin "$PIN" --note "interop cf" \
	</dev/null >"$T/enroll.out" 2>"$T/enroll.err" &
EPID=$!
owner approve "$(owner wait enrollment interop-host 20)" >/dev/null 2>&1
wait $EPID || fail "enroll failed: $(cat "$T/enroll.err")"
ok "owner passkey + host enrolled"

# approve_next SCOPE TTL: wait for the pending Cloudflare card of SCOPE and approve it.
approve_next() {
	local id
	id=$(owner state | bun -e 'const s = await Bun.stdin.json(); const it = (s.pending ?? []).find((p) => p.kind === "cloudflare" && p.cloudflare.scope === process.argv[1]); console.log(it ? it.id : "")' "$1")
	for _ in $(seq 100); do
		[[ -n $id ]] && break
		sleep 0.2
		id=$(owner state | bun -e 'const s = await Bun.stdin.json(); const it = (s.pending ?? []).find((p) => p.kind === "cloudflare" && p.cloudflare.scope === process.argv[1]); console.log(it ? it.id : "")' "$1")
	done
	[[ -n $id ]] || fail "no pending card for $1"
	owner approve "$id" "$2" >/dev/null 2>"$T/owner-$1.err" || { cat "$T/owner-$1.err"; fail "owner approve $1"; }
	echo "$id"
}
cfapi() { "$AQMAS" cf api "$@" </dev/null; }
jget() { bun -e "const j = JSON.parse(await Bun.stdin.text()); const v = ($1); console.log(typeof v === 'string' ? v : JSON.stringify(v))"; }

# --- catalogue ---
"$AQMAS" cf scopes --json | bun -e 'const c = await Bun.stdin.json(); if (c.scopes.length !== 17 || c.account_id !== process.argv[1] || c.tunnels[0].name !== "home") process.exit(1)' $ACCT ||
	fail "catalogue"
ok "aqmas cf scopes: 17 scopes, account, zone/tunnel/D1 names"

# --- cf.read: auto-approved, no card ---
cfapi GET /zones --why "interop read" >"$T/zones.json" 2>"$T/zones.err" || { cat "$T/zones.err"; fail "GET /zones"; }
grep -q example.com "$T/zones.json" || fail "zones list"
owner state | bun -e 'const s = await Bun.stdin.json(); if ((s.pending ?? []).length) process.exit(1); if (!s.recent.some((a) => a.action === "cf_auto_approve")) process.exit(2)' ||
	fail "cf.read was not auto-approved without a card"
fakereq | bun -e 'const r = await Bun.stdin.json(); const z = r.filter((x) => x.path === "/client/v4/zones"); if (!z.length || z.some((x) => x.credential !== "parent")) process.exit(1)' ||
	fail "fakecf did not see /zones with the injected parent token"
READ_GID=$("$AQMAS" list --json | bun -e 'const j = await Bun.stdin.json(); console.log(j.grants.find((g) => g.scope === "cf.read").id)')
ok "GET /zones auto-approved cf.read (grant $READ_GID), upstream saw the parent token"

# --- deny-list and path tricks (straight to the proxy, mTLS) ---
RC=0
cfapi GET /user/tokens >/dev/null 2>"$T/deny.err" || RC=$?
((RC == 3)) && grep -q denied "$T/deny.err" || { cat "$T/deny.err"; fail "GET /user/tokens: exit $RC"; }
KEY=$(sed -n 's/^client_key *= *"\(.*\)"/\1/p' "$T/client/config/config.toml")
CRT=$(sed -n 's/^client_cert *= *"\(.*\)"/\1/p' "$T/client/config/config.toml")
SCA=$(sed -n 's/^server_ca *= *"\(.*\)"/\1/p' "$T/client/config/config.toml")
mtls() { curl -sS --path-as-is -o "$T/mtls.body" -D "$T/mtls.hdr" -w '%{http_code}' --cacert "$SCA" --cert "$CRT" --key "$KEY" -H "X-Aqmas-Grant: $READ_GID" "$@"; }
P=https://127.0.0.1:$PA/cf/client/v4
fakeclear
for path in "/accounts/$ACCT/cfd_tunnel/$TUN/token" "/accounts/$ACCT/cfd_tunnel/$TUN/configurations/../token" \
	"/accounts/$ACCT/cfd_tunnel/$TUN/configurations/%2e%2e/token" "/accounts/$ACCT/cfd_tunnel/$TUN%2Ftoken" \
	"/accounts/$ACCT/cfd_tunnel/$TUN/configurations;/../token" "/accounts/$ACCT//cfd_tunnel/$TUN/token" \
	"/accounts/$ACCT/cfd_tunnel/$TUN/configurations%252F..%252Ftoken" "/accounts/$ACCT/cfd_tunnel/$TUN/configurations/" \
	"/accounts/ffffffffffffffffffffffffffffffff/cfd_tunnel" "/user/tokens/../tokens" "/memberships/x"; do
	code=$(mtls "$P$path")
	[[ $code == 400 || $code == 403 || $code == 404 ]] || fail "$path answered $code"
done
code=$(mtls -X GET -H "X-HTTP-Method-Override: PUT" "$P/accounts/$ACCT/cfd_tunnel/$TUN/configurations")
[[ $code == 400 ]] || fail "method override answered $code"
code=$(mtls -X OPTIONS "$P/zones")
[[ $code == 405 ]] || fail "OPTIONS answered $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$SCA" "$P/zones")
[[ $code == 401 || $code == 000 ]] || fail "proxy without a client certificate answered $code"
n=$(fakereq | bun -e 'const r = await Bun.stdin.json(); console.log(r.length)')
[[ $n == 0 ]] || fail "$n refused calls reached fakecf"
ok "deny-list + 11 path tricks, method override, OPTIONS, no client cert: refused, nothing reached upstream"

# --- scope enforcement + needs-scope hint ---
cfapi GET "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" >"$T/cfg0.json" 2>/dev/null || fail "GET tunnel config with cf.read"
RC=0
cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --data @"$T/cfg0.json" >/dev/null 2>"$T/hint.err" || RC=$?
((RC == 3)) && grep -q 'aqmas cf request cf.tunnel.config tunnel=home' "$T/hint.err" || { cat "$T/hint.err"; fail "needs-scope hint (exit $RC)"; }
ok "PUT tunnel config with only cf.read: exit 3 with hint 'aqmas cf request cf.tunnel.config tunnel=home'"

# --- cf.tunnel.config: owner approves; snapshot before/after; guard rails; stale version ---
"$AQMAS" cf request cf.tunnel.config tunnel=home --ttl 30m --why "interop tunnel" --json </dev/null >"$T/tun-req.json" 2>"$T/tun-req.err" &
RPID=$!
approve_next cf.tunnel.config 1800 >/dev/null
wait $RPID || { cat "$T/tun-req.err"; fail "cf request cf.tunnel.config"; }
TUN_GID=$(jget 'j.grant.id' <"$T/tun-req.json")
grep -q '"scope_params":"tunnel=home"' "$T/owner-cf.tunnel.config.err" || fail "signed canonical lacks scope_params"
cfapi GET "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" >"$T/cfg1.json" 2>/dev/null
bun -e '
const j = JSON.parse(await Bun.file(process.argv[1]).text()); const c = j.result ?? j;
const ing = c.config.ingress.filter((r) => r.hostname);
const mk = (extra) => JSON.stringify({ config: { ...c.config, ingress: [...ing, ...extra, { service: "http_status:404" }] } });
const good = { hostname: "foo.example.com", service: "https://192.0.2.50:9443", originRequest: { originServerName: "foo.example.com", matchSNItoHost: true, http2Origin: true } };
await Bun.write(process.argv[2] + "/good.json", mk([good]));
await Bun.write(process.argv[2] + "/nosni.json", mk([good, { hostname: "bar.example.com", service: "https://192.0.2.50:9443" }]));
await Bun.write(process.argv[2] + "/plain.json", mk([good, { hostname: "baz.example.com", service: "http://192.0.2.50" }]));
await Bun.write(process.argv[2] + "/nocatch.json", JSON.stringify({ config: { ...c.config, ingress: [...ing, good] } }));
' "$T/cfg1.json" "$T/work"
fakeclear
cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --data @"$T/work/good.json" >"$T/put.out" 2>"$T/put.err" || { cat "$T/put.err"; fail "good tunnel PUT"; }
BEFORE=$(sed -n 's/.*snapshot before[: ]*\([0-9A-Z]\{26\}\).*/\1/p' "$T/put.err" | head -1)
AFTER=$(sed -n 's/.* after:* *\([0-9A-Z]\{26\}\).*/\1/p' "$T/put.err" | head -1)
[[ -n $BEFORE && -n $AFTER ]] || { cat "$T/put.err"; fail "PUT did not report snapshot ids"; }
fakereq | bun -e 'const r = (await Bun.stdin.json()).map((x) => x.method + " " + x.path.replace(/.*\/cfd_tunnel\/[^/]+/, "T"));
const i = r.indexOf("GET T/configurations"), p = r.indexOf("PUT T/configurations");
if (i < 0 || p < 0 || i > p) { console.error(r); process.exit(1) }' || fail "upstream did not see the snapshot GET before the PUT"
"$AQMAS" cf snapshot get "$BEFORE" -o "$T/snap-before.json" 2>/dev/null || fail "snapshot get"
grep -q foo.example.com "$T/snap-before.json" && fail "before-snapshot already has the new hostname"
"$AQMAS" cf snapshot get "$AFTER" 2>/dev/null | grep foo.example.com >/dev/null || fail "after-snapshot lacks the new hostname"
"$AQMAS" cf snapshot list --object "tunnel-config:$TUN" --json | bun -e 'const j = await Bun.stdin.json(); const s = j.snapshots ?? j; if (s.length < 2 || !s.every((x) => x.object_type === "tunnel-config")) process.exit(1)' ||
	fail "snapshot list"
ls "$T"/data/cf-snapshots/*/"$BEFORE".json >/dev/null || fail "snapshot file not in data_dir/cf-snapshots"
[[ $(stat -c %a "$T"/data/cf-snapshots/*/"$BEFORE".json) == 600 ]] || fail "snapshot file mode"
ok "tunnel PUT: snapshot GET before the PUT, before $BEFORE / after $AFTER, list + get, files 0600"

for f in nosni:tunnel-traefik-sni plain:tunnel-plain-origin nocatch:tunnel-catch-all; do
	fakeclear
	RC=0
	cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --data @"$T/work/${f%%:*}.json" >/dev/null 2>"$T/g.err" || RC=$?
	((RC == 3)) && grep -q "${f#*:}" "$T/g.err" || { cat "$T/g.err"; fail "${f%%:*} PUT not refused by ${f#*:} (exit $RC)"; }
	fakereq | bun -e 'const r = await Bun.stdin.json(); if (r.some((x) => x.method === "PUT")) process.exit(1)' || fail "refused PUT reached upstream"
done
ok "guard rails refused: no originServerName, http://192.0.2.50, no catch-all (nothing written upstream)"

# Someone else changes the config (straight at fakecf with the parent token): our PUT is stale.
curl -fsS -X PUT -H "Authorization: Bearer $(cat "$T/tok/proxy")" -H 'Content-Type: application/json' \
	--data @"$T/work/good.json" "$FAKE/client/v4/accounts/$ACCT/cfd_tunnel/$TUN/configurations" >/dev/null
RC=0
cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --data @"$T/work/good.json" >/dev/null 2>"$T/stale.err" || RC=$?
((RC == 3)) && grep -q 'tunnel-version' "$T/stale.err" || { cat "$T/stale.err"; fail "stale PUT not refused (exit $RC)"; }
cfapi GET "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" >/dev/null 2>&1
cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --data @"$T/work/good.json" >/dev/null 2>"$T/fresh.err" || { cat "$T/fresh.err"; fail "PUT after a fresh GET"; }
ok "stale tunnel PUT refused (tunnel-version, 409); accepted after a fresh GET"

# --- Access apps: the id.example.com guard ---
"$AQMAS" cf request cf.access.apps --ttl 30m --why "interop access" </dev/null >/dev/null 2>"$T/acc-req.err" &
RPID=$!
approve_next cf.access.apps 1800 >/dev/null
wait $RPID || { cat "$T/acc-req.err"; fail "cf request cf.access.apps"; }
APPS=/accounts/$ACCT/access/apps
fakeclear
for body in '{"name":"x","type":"self_hosted","domain":"id.example.com"}' \
	'{"name":"x","type":"self_hosted","domain":"ID.Example.com:443/login"}' \
	'{"name":"x","type":"self_hosted","domain":"*.example.com"}' \
	'{"name":"x","type":"self_hosted","domain":"ok.example.com","self_hosted_domains":["ok.example.com","id.example.com"]}' \
	'{"name":"x","type":"self_hosted","domain":"ok.example.com","destinations":[{"type":"public","uri":"*.com/x"}]}'; do
	RC=0
	cfapi POST "$APPS" --data "$body" >/dev/null 2>"$T/acc.err" || RC=$?
	((RC == 3)) && grep -q access-protected-hostname "$T/acc.err" || { cat "$T/acc.err"; fail "Access app not refused: $body"; }
done
fakereq | bun -e 'const r = await Bun.stdin.json(); if (r.some((x) => x.method === "POST")) process.exit(1)' || fail "refused Access POST reached upstream"
cfapi POST "$APPS" --data '{"name":"foo","type":"self_hosted","domain":"foo.example.com","session_duration":"730h"}' >"$T/app.json" 2>"$T/app.err" ||
	{ cat "$T/app.err"; fail "normal Access app"; }
APP=$(jget '(j.result ?? j).id' <"$T/app.json")
grep -Eq 'after:? *[0-9A-Z]{26}' "$T/app.err" || fail "Access app create has no after-snapshot"
RC=0
cfapi PATCH "$APPS/$APP" --data '{"session_duration":"24h"}' >/dev/null 2>"$T/patch.err" || RC=$?
((RC == 3)) && grep -q access-patch "$T/patch.err" || { cat "$T/patch.err"; fail "PATCH on an Access app (exit $RC)"; }
ok "Access: id.example.com refused (exact, case/port/path, *.example.com, self_hosted_domains, *.co.uk destination); normal app created; PATCH refused"

# --- cf.admin: overridable guard yes, never-guard no ---
"$AQMAS" cf request cf.admin --ttl 1h --why "interop break-glass" </dev/null >/dev/null 2>"$T/adm-req.err" &
RPID=$!
ADM_REQ=$(approve_next cf.admin 1800)
wait $RPID || { cat "$T/adm-req.err"; fail "cf request cf.admin"; }
grep -q '"ttl_seconds":1800' "$T/owner-cf.admin.err" || fail "cf.admin canonical"
ADM_GID=$("$AQMAS" list --json | bun -e 'const j = await Bun.stdin.json(); console.log(j.grants.find((g) => g.scope === "cf.admin").id)')
cfapi GET "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --grant "$ADM_GID" >/dev/null 2>&1
cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --grant "$ADM_GID" --override tunnel-traefik-sni --data @"$T/work/nosni.json" >/dev/null 2>"$T/ovr.err" ||
	{ cat "$T/ovr.err"; fail "cf.admin override of tunnel-traefik-sni"; }
RC=0
cfapi PUT "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --grant "$TUN_GID" --override tunnel-traefik-sni --data @"$T/work/nosni.json" >/dev/null 2>"$T/ovr2.err" || RC=$?
((RC != 0)) || fail "override accepted with a non-admin grant"
RC=0
cfapi POST "$APPS" --grant "$ADM_GID" --override access-protected-hostname --data '{"name":"x","type":"self_hosted","domain":"id.example.com"}' >/dev/null 2>"$T/ovr3.err" || RC=$?
((RC != 0)) && grep -q 'access-protected-hostname can never be overridden' "$T/ovr3.err" || { cat "$T/ovr3.err"; fail "never-guard overridden by cf.admin"; }
RC=0
cfapi POST "$APPS" --grant "$ADM_GID" --data '{"name":"x","type":"self_hosted","domain":"id.example.com"}' >/dev/null 2>"$T/ovr4.err" || RC=$?
((RC == 3)) && grep -q access-protected-hostname "$T/ovr4.err" || { cat "$T/ovr4.err"; fail "cf.admin created an Access app on id."; }
RC=0
cfapi GET /user/tokens --grant "$ADM_GID" >/dev/null 2>&1 || RC=$?
((RC == 3)) || fail "cf.admin reached /user/tokens"
ok "cf.admin (card approved 30 min): overrides tunnel-traefik-sni; cannot override the id. guard or reach /user/tokens; override refused for other grants"

# --- child token: mint once, name/expiry/IP condition, use, deletion after expiry ---
"$AQMAS" cf token cf.workers.deploy script=interop-worker --ttl 1m --why "interop token" -- \
	sh -c 'curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "$0/client/v4/user/tokens/verify"' "$FAKE" \
	</dev/null >"$T/tok-use.out" 2>"$T/tok-use.err" &
RPID=$!
TOK_REQ=$(approve_next cf.workers.deploy 60)
wait $RPID || { cat "$T/tok-use.err"; fail "aqmas cf token -- curl"; }
grep -q '"status":"active"' "$T/tok-use.out" || fail "child token not active upstream"
grep -q '"ip_condition":"127.0.0.1/32"' "$T/owner-cf.workers.deploy.err" && grep -q '"mode":"token"' "$T/owner-cf.workers.deploy.err" ||
	fail "token canonical lacks mode/ip_condition"
curl -fsS "$FAKE/__fake/tokens" >"$T/tokens.json"
bun -e 'const t = await Bun.file(process.argv[1]).json(); const a = (t.tokens ?? t).filter((x) => x.name.startsWith("aqmas:") && x.name.endsWith(":interop-host"));
if (a.length !== 1) process.exit(1); const x = a[0];
const life = (Date.parse(x.expires_on) - Date.parse(x.not_before)) / 1000;
if (life < 55 || life > 125 || !JSON.stringify(x.condition).includes("127.0.0.1/32") || x.policies.length !== 1 || x.policies[0].permission_groups.length !== 2 || Object.keys(x.policies[0].resources).join() !== "com.cloudflare.api.account." + process.argv[2]) { console.error(x); process.exit(2) }' "$T/tokens.json" $ACCT ||
	fail "minted token shape: $(cat "$T/tokens.json")"
ok "child token minted (aqmas:<grant>:interop-host, ~60 s, IP 127.0.0.1/32, 2 permission groups on the account), used via -- CMD"

# --- revoke a proxy grant: next call refused at once ---
owner revoke-grant "$TUN_GID" >/dev/null 2>&1 || fail "owner revoke-grant"
RC=0
cfapi GET "/accounts/$ACCT/cfd_tunnel/$TUN/configurations" --grant "$TUN_GID" >/dev/null 2>"$T/rev.err" || RC=$?
((RC == 3)) || { cat "$T/rev.err"; fail "revoked grant still works (exit $RC)"; }
ok "revoked cf.tunnel.config grant refused on the next call"

# --- wrangler through the local shim and the real proxy (optional) ---
if [[ -z ${WRANGLER_BIN:-} && ${WRANGLER:-0} == 1 ]]; then
	mkdir -p "$T/wr"
	echo '{"name":"w","private":true}' >"$T/wr/package.json"
	(cd "$T/wr" && bun add "wrangler@${WRANGLER_VERSION:-latest}" >/dev/null)
	WRANGLER_BIN=$T/wr/node_modules/wrangler/bin/wrangler.js
fi
if [[ -n ${WRANGLER_BIN:-} ]]; then
	command -v node >/dev/null || fail "node not found"
	W=$T/work/worker
	mkdir -p "$W/src" "$W/public" "$T/whome/xdg"
	printf 'name = "interop-worker"\nmain = "src/index.js"\ncompatibility_date = "2025-01-01"\nworkers_dev = true\n\n[assets]\ndirectory = "./public"\n\n[triggers]\ncrons = ["*/30 * * * *"]\n\n[[d1_databases]]\nbinding = "DB"\ndatabase_name = "times"\ndatabase_id = "%s"\n' "$DB" >"$W/wrangler.toml"
	echo "export default { async fetch() { return new Response('hi'); }, async scheduled() {} };" >"$W/src/index.js"
	echo '<!doctype html><p>hi</p>' >"$W/public/index.html"
	wr() { (cd "$W" && env HOME="$T/whome" XDG_CONFIG_HOME="$T/whome/xdg" WRANGLER_SEND_METRICS=false DO_NOT_TRACK=1 CI=1 FORCE_COLOR=0 \
		HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 \
		NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost "$AQMAS" cf env "$@" </dev/null); }
	fakeclear
	wr --request cf.workers.deploy script=interop-worker --ttl 30m --why "interop wrangler" -- node "$WRANGLER_BIN" deploy >"$T/wr-deploy.out" 2>&1 &
	RPID=$!
	approve_next cf.workers.deploy 1800 >/dev/null
	wait $RPID || { tail -40 "$T/wr-deploy.out"; fail "wrangler deploy through the shim"; }
	grep -q 'Uploaded interop-worker' "$T/wr-deploy.out" || { tail -20 "$T/wr-deploy.out"; fail "wrangler deploy output"; }
	fakereq | bun -e 'const r = await Bun.stdin.json();
const put = r.find((x) => x.method === "PUT" && /\/workers\/scripts\/interop-worker$/.test(x.path));
const up = r.filter((x) => /\/workers\/assets\/upload/.test(x.path));
if (!put || put.credential !== "parent" || !up.length || up.some((x) => x.credential !== "upload-jwt")) { console.error(r.map((x) => x.method + " " + x.path + " " + x.credential)); process.exit(1) }' ||
		fail "wrangler deploy did not reach fakecf as expected (parent token on the API, upload JWT on assets)"
	ok "wrangler deploy (script + assets + cron) through aqmas cf env and the real proxy (owner-approved cf.workers.deploy)"
	wr --request cf.d1 db=times access=read --ttl 30m --why "interop d1" -- node "$WRANGLER_BIN" d1 execute times --remote --command "SELECT 1 AS one" >"$T/wr-d1.out" 2>&1 &
	RPID=$!
	approve_next cf.d1 1800 >/dev/null
	wait $RPID || { tail -30 "$T/wr-d1.out"; fail "wrangler d1 execute (read)"; }
	grep -q '"one": 1' "$T/wr-d1.out" || { tail -20 "$T/wr-d1.out"; fail "d1 SELECT output"; }
	RC=0
	wr -- node "$WRANGLER_BIN" d1 execute times --remote --command "DROP TABLE x" >"$T/wr-d1w.out" 2>&1 || RC=$?
	((RC != 0)) && grep -q 'aqmas' "$T/wr-d1w.out" || { tail -20 "$T/wr-d1w.out"; fail "write SQL with access=read was not refused"; }
	ok "wrangler d1 execute --remote: SELECT allowed, DROP refused with access=read"
else
	echo "interop-cf: skip: wrangler (set WRANGLER=1 or WRANGLER_BIN)"
fi

# --- audit ---
owner state | bun -e 'const s = await Bun.stdin.json(); const a = new Set(s.recent.map((x) => x.action));
for (const w of ["cf_write", "cf_refused", "cf_token_mint"]) if (!a.has(w)) { console.error("missing " + w, [...a]); process.exit(1) }' || fail "audit rows"
ok "audit has cf_write, cf_refused, cf_token_mint"

# --- the child token is deleted upstream after expiry (sweeper, every minute) ---
for _ in $(seq 180); do
	curl -fsS "$FAKE/__fake/tokens" | bun -e 'const t = await Bun.stdin.json(); const a = (t.tokens ?? t).filter((x) => x.name.endsWith(":interop-host")); process.exit(a.length && a.every((x) => x.deleted) ? 0 : 1)' && break
	sleep 1
done
curl -fsS "$FAKE/__fake/tokens" | bun -e 'const t = await Bun.stdin.json(); const a = (t.tokens ?? t).filter((x) => x.name.endsWith(":interop-host")); process.exit(a.length && a.every((x) => x.deleted) ? 0 : 1)' ||
	fail "child token not deleted after expiry"
owner state | bun -e 'const s = await Bun.stdin.json(); if (!s.recent.some((x) => x.action === "cf_token_delete")) process.exit(1)' || fail "no cf_token_delete audit"
ok "child token deleted upstream by the sweeper after expiry (cf_token_delete audited)"

# --- no parent token value anywhere but the token files ---
if grep -rlF -e "$PROXY_TOK" -e "$MINTER_TOK" "$T" --exclude-dir=tok --exclude-dir=wr 2>/dev/null | grep -q .; then
	grep -rlF -e "$PROXY_TOK" -e "$MINTER_TOK" "$T" --exclude-dir=tok --exclude-dir=wr
	fail "a parent token value leaked into the files above"
fi
ok "no fake parent token value in logs, outputs, snapshots, the database or the client cache"

source "$ROOT/test/interop/cutover.sh"
personal_cutover "${PIDS[1]}"
"$AQMAS" cf scopes --json | bun -e 'if ((await Bun.stdin.json()).scopes.some(s=>s.modes.includes("token"))) process.exit(1)' || fail 'unrestricted child template after activation'
cfapi GET /zones --why 'post-cutover read' >/dev/null || fail 'post-cutover personal proxy'
"$AQMAS" cf snapshot list --json | bun -e 'if ((await Bun.stdin.json()).snapshots.length) process.exit(1)' || fail 'legacy snapshots visible'
ok 'signed activation, scoped proxy, archived legacy snapshots and provider template gate'

owner catalogue relax
"$AQMAS" cf scopes --json | bun -e 'const {scopes:s}=await Bun.stdin.json();const f=n=>s.find(x=>x.name===n);if(!f("cf.read").indefinite_available||f("cf.admin").max_ttl_seconds>3600||f("cf.read.private").max_ttl_seconds>7200)process.exit(1)' || fail 'effective scope duration bounds'
"$AQMAS" cf request cf.read --ttl indefinite --why 'explicit indefinite test' --json >"$T/indefinite.out" 2>"$T/indefinite.err" &
RPID=$!; RID=$(owner wait cloudflare interop-host 20); owner approve "$RID" indefinite > /dev/null 2>"$T/indefinite-owner.err"; wait "$RPID"
grep -q '"beyond_soft_cap":true' "$T/indefinite-owner.err" && grep -q '"indefinite":true' "$T/indefinite-owner.err" || fail 'unsigned indefinite duration'
GID=$(owner state | bun -e 'const s=await Bun.stdin.json();let g=s.grants.find(x=>x.indefinite);if(!g)process.exit(1);console.log(g.id)')
owner revoke-grant "$GID" >/dev/null
if cfapi GET /zones --grant "$GID" > /dev/null 2>&1; then fail 'revoked indefinite grant allowed'; fi
if "$AQMAS" cf request cf.admin --ttl indefinite --why 'must refuse' </dev/null >"$T/admin-denied.out" 2>&1; then fail 'indefinite sensitive scope'; fi
"$AQMAS" cf request cf.dns.edit zone=example.com --ttl 15m --why 'explicit standing window' --json >"$T/standing.out" 2>"$T/standing.err" &
RPID=$!; RID=$(owner wait cloudflare interop-host 20); owner approve "$RID" 900 indefinite >/dev/null 2>"$T/standing-owner.err"; wait "$RPID"
grep -q '"standing_indefinite":true' "$T/standing-owner.err" && grep -q '"standing_beyond_soft_cap":true' "$T/standing-owner.err" || fail 'standing exception missing from signed decision'
owner state | bun -e 'if(!(await Bun.stdin.json()).standing.some(x=>x.indefinite)) process.exit(1)' || fail 'standing duration missing from active list'
ok 'stale policy refused, explicit indefinite scope approval, sensitive cap and immediate revoke'

source "$ROOT/test/interop/seal.sh"
seal_cutover
"$AQMAS" cf scopes --json >/dev/null || fail 'locked public catalogue'
"$AQMAS" cf request cf.read --ttl 5m --why 'queue while closed' --json >"$T/locked-cf.out" 2>"$T/locked-cf.err" &
RPID=$!; RID=$(owner wait cloudflare interop-host 20); owner approve "$RID" 300 >/dev/null; wait "$RPID"
[[ $(open_kinds) == cf-proxy ]] || fail "the proxy approval opened other buckets: $(owner open-buckets)"
cfapi GET /zones --why 'sealed proxy parent' >/dev/null || fail 'sealed proxy forward'
owner close-all; nothing_open 'close all'
if timeout 60 "$AQMAS" cf api GET /zones --why 'after close all' </dev/null >/dev/null 2>"$T/closed-cf.err"; then fail 'proxied with the parent bucket closed'; fi
[[ $(owner reopen) == 1 ]] || fail 'reopen the proxy parent'
cfapi GET /zones --why 'after reopen' >/dev/null || fail 'proxy after reopen'
ok 'sealed proxy parent: the approval opens only its bucket (grant hold); close all pauses the grant; reopen resumes it'
for token in "$PROXY_TOK" "$MINTER_TOK"; do
  if grep -aFl "$token" "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$T"/seal-*.log "$T"/locked-cf.* "$T/data"/seal-stage-*/manifest.json "$T"/closed-cf.err 2>/dev/null | grep -q .; then fail 'sealed parent leaked'; fi
done
echo "interop-cf: ALL OK"
