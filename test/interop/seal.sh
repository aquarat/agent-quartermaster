# Sourced after personal_cutover; all paths and processes belong to this test.
# Seal format 2 (docs/BUCKETS.md): a seal import straight into per-credential buckets.
seal_start() {
  "$AQMASD" -config "$T/config.toml" "$1" >"$T/seal-$1.log" 2>&1 &
  SEAL_PID=$!; PIDS+=("$SEAL_PID")
  for _ in $(seq 100); do curl -fsS "$AQMAS_BASE/healthz" >/dev/null 2>&1 && return; sleep 0.1; done
  cat "$T/seal-$1.log"; fail "seal $1 did not start"
}
seal_restart() { kill "$SEAL_PID"; wait "$SEAL_PID" || true; seal_start serve; }
# nothing_open WHAT: no bucket is open (read from status.buckets).
nothing_open() { local o; o=$(owner open-buckets); [[ -z $o ]] || fail "$1: open buckets: $o"; }
seal_cutover() {
  local recipient stage pin
  kill "${PIDS[-1]}"; wait "${PIDS[-1]}" || true
  recipient=$(go run "$ROOT/test/interop/agefixture" "$T/offline.identity")
  go run "$ROOT/test/interop/agefixture" "$T/other.identity" >/dev/null
  cat >>"$T/config.toml" <<EOF
[seal]
required=true
recipient="$recipient"
EOF
  seal_start seal-import
  [[ $(owner seal-status) == setup ]] || fail 'seal import not staged'
  if owner seal-activate 2>/dev/null; then fail 'activated before any scope key was made'; fi
  owner stage >/dev/null 2>"$T/stage.err" || { cat "$T/stage.err"; fail 'staging taps'; }
  if owner seal-activate 2>/dev/null; then fail 'activated without recovery'; fi
  if owner seal-drill "$T/other.identity" 2>"$T/drill-other.err"; then fail 'drill accepted another identity'; fi
  owner seal-drill "$T/offline.identity" || fail 'on-box recovery drill'
  owner seal-activate; wait "$SEAL_PID" || true
  stage=$(find "$T/data" -maxdepth 1 -type d -name 'seal-stage-*')
  pin=$(sha256sum "$stage/manifest.json" | cut -d' ' -f1); echo "manifest_sha256=\"$pin\"" >>"$T/config.toml"
  bun -e 'const m=await Bun.file(process.argv[1]).json(); if(m.seal_format!==2||!m.scopes.length||!m.buckets.some(b=>b.kind==="ssh-ca"))process.exit(1)' "$stage/manifest.json" || fail 'format-2 manifest'
  rm -f "$T/data/ca/ssh_user_ca" "$T/data/ca/client_ca.key"
  rm -f "$T/tok/proxy" "$T/tok/minter"
  [[ $("$AQMASD" -config "$T/config.toml" setup-facts | bun -e 'console.log((await Bun.stdin.json()).schema)') == 9 ]] || fail 'not schema 9'
  seal_start serve; [[ $(owner seal-status) == buckets ]] || fail 'cold restart not serving buckets'; owner login >/dev/null
  nothing_open 'cold restart'
  "$AQMASD" -config "$T/config.toml" print-ssh-ca >/dev/null; "$AQMAS" list --json >/dev/null
  local original; original=$(owner passkeys | bun -e 'console.log((await Bun.stdin.json()).find(k=>k.current).nickname)')
  if owner capability disable "$original" 2>/dev/null; then fail 'disabled the only passkey that opens the scopes'; fi
  owner capability register 'Seal spare' unlock 2>"$T/cap-register.err" || { cat "$T/cap-register.err"; fail 'enable a new passkey from the signed-in one'; }
  nothing_open 'passkey enable'
  owner capability test 'Seal spare' 2>/dev/null || fail 'test the new passkey'
  seal_restart
  owner use-passkey 'Seal spare' >/dev/null; owner login >/dev/null
  owner buckets --json | bun -e 'const v=await Bun.stdin.json(),k=v.passkeys.find(p=>p.current),keyed=v.scopes.filter(s=>s.has_key).map(s=>s.scope); if(!k||k.missing.some(s=>keyed.includes(s))||k.opens!==k.of||k.scopes.some(s=>!s.tested))process.exit(1)' || fail "spare passkey does not open every bucket: $(owner buckets --json)"
  owner capability disable "$original" 2>/dev/null || fail 'disable the original passkey'
  owner buckets --json | bun -e 'const v=await Bun.stdin.json(),k=v.passkeys.find(p=>!p.current); if(!k||k.scopes.length||k.opens||!k.missing.includes("installation"))process.exit(1)' || fail 'disabled passkey still opens'
  # Enable covers every scope the passkey lacks, creating the organisations' scope keys (none existed yet).
  owner capability enable "$original" 2>/dev/null || fail 'enable the original passkey from the spare'
  owner buckets --json | bun -e 'const v=await Bun.stdin.json(); if(v.scopes.some(s=>!s.has_key)||v.passkeys.find(p=>!p.current).missing.length)process.exit(1)' || fail "scope keys after enable: $(owner buckets --json)"
  owner use-passkey "$original" >/dev/null; owner login >/dev/null
  # Its wraps are untested until it opens them: until then the spare stays the last tested passkey.
  if owner remove-passkey 'Seal spare' 2>/dev/null; then fail 'removed the last passkey with tested wraps'; fi
  owner capability test "$original" 2>/dev/null || fail 'test the re-enabled original passkey'
  owner remove-passkey 'Seal spare' >/dev/null
  owner close-all; nothing_open 'close all'
  [[ $(owner seal-status) == buckets ]] || fail 'close all stopped serving'
  seal_restart; [[ $(owner seal-status) == buckets ]] || fail 'restart'; nothing_open 'restart'
  ok 'sealed into buckets: staging taps, recovery drill (wrong key refused), activation, schema 9; passkey enabled from another, tested, disabled and re-enabled; close all; restart opens nothing'
}
# open_kinds: the kinds of the open buckets, sorted and unique, space-separated.
open_kinds() { owner open-kinds; }
