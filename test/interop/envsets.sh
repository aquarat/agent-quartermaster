# Local real CLI / broker and software passkey, with a disposable RAM mount
# directory (no use of the runner's aqmas checkout namespace).
env_scenario() {
  local path=client-a/paas/staging sentinel=interop-$(openssl rand -hex 16) pid
  local ram; ram=$(mktemp -d /dev/shm/aqmas-env-test.XXXXXXXX); chmod 700 "$ram"; export XDG_RUNTIME_DIR="$ram"
  mkdir -m 700 "$T/envwork"; printf 'APP_SECRET=%s\n' "$sentinel" >"$T/envwork/import.env"
  owner env-ticket import >"$T/envwork/ticket"
  "$AQMAS" set import "$path" --from "$T/envwork/import.env" --ticket-fd 3 3<"$T/envwork/ticket" >"$T/env-import.out" 2>"$T/env-import.err"
  owner env-decide commit
  "$AQMAS" run "$path" --why 'test child' -- sh -c 'test -n "$APP_SECRET"' </dev/null >"$T/env-run.out" 2>"$T/env-run.err" & pid=$!
  owner env-decide approve process; wait "$pid"
  (cd "$T/envwork"; "$AQMAS" co "$path" --why 'file delivery') >"$T/env-co.out" 2>"$T/env-co.err" & pid=$!
  owner env-decide approve file; wait "$pid"; [[ -L "$T/envwork/.env" ]] && cmp "$T/envwork/.env" "$T/envwork/import.env" || fail 'RAM file mismatch'
  "$AQMAS" ci "$path"; [[ ! -L "$T/envwork/.env" ]] || fail 'checkin left link'
  (cd "$T/envwork"; "$AQMAS" co "$path" --why 'file revoke') >"$T/env-co2.out" 2>"$T/env-co2.err" & pid=$!
  owner env-decide approve file; wait "$pid"; owner env-decide revoke file
  for _ in $(seq 50); do [[ ! -L "$T/envwork/.env" ]] && break; sleep .1; done; [[ ! -L "$T/envwork/.env" ]] || fail 'revoked checkout still visible'
  (eval "$("$AQMAS" cos "$path" --why 'shell delivery')"; [[ $APP_SECRET == "$sentinel" ]]; eval "$("$AQMAS" cis "$path")"; [[ ! -v APP_SECRET ]]) >"$T/env-shell.out" 2>"$T/env-shell.err" & pid=$!
  owner env-decide approve shell; wait "$pid"
  # A release whose values are not collected yet: its approval opened only the set's bucket
  # (env hold). Close all pauses it (423 on collection); Reopen resumes it; a restart too.
  local -a mtls=(curl --silent --show-error --cacert "$AQMAS_CONFIG_DIR/server-ca.pem" --key "$AQMAS_CONFIG_DIR/client.key" --cert "$AQMAS_CONFIG_DIR/client.crt")
  local base="https://127.0.0.1:$PA" rid gid
  env_release() {
    rid=$("${mtls[@]}" --fail "$base/v2/env/set?path=$path" | bun -e 'console.log(JSON.stringify({binding:await Bun.stdin.json(),mode:"process",reason:"paused collection test",ttl_seconds:300}))' | "${mtls[@]}" --fail -H 'Content-Type: application/json' --data-binary @- "$base/v2/env/requests" | bun -e 'console.log((await Bun.stdin.json()).id)')
    owner env-decide approve process; gid=$("${mtls[@]}" --fail "$base/v2/env/requests/$rid" | bun -e 'console.log((await Bun.stdin.json()).grant_id)')
  }
  env_release
  [[ $(open_kinds) == env-set ]] || fail "an env approval opened more than its set: $(owner open-buckets)"
  owner close-all; nothing_open 'close all with an uncollected release'
  [[ $("${mtls[@]}" -X POST -o /dev/null -w '%{http_code}' "$base/v2/grants/$gid/collect") == 423 ]] || fail 'collection after close all'
  owner buckets | bun -e 'const b=(await Bun.stdin.json()).filter(b=>b.paused); if(b.length!==1||b[0].kind!=="env-set")process.exit(1)' || fail 'the release is not listed as paused'
  [[ $(owner reopen) == 1 ]] || fail 'reopen took more than one tap'
  [[ $(open_kinds) == env-set ]] || fail "reopen opened more than the paused set: $(owner open-buckets)"
  "${mtls[@]}" --fail -X POST -o /dev/null "$base/v2/grants/$gid/collect"
  [[ $("${mtls[@]}" -X POST -o /dev/null -w '%{http_code}' "$base/v2/grants/$gid/collect") == 409 ]] || fail 'collection replay'
  nothing_open 'a collected release'
  env_release; seal_restart; nothing_open 'restart with an uncollected release'
  [[ $("${mtls[@]}" -X POST -o /dev/null -w '%{http_code}' "$base/v2/grants/$gid/collect") == 423 ]] || fail 'collection after restart'
  [[ $(owner reopen) == 1 ]] || fail 'reopen after restart'
  "${mtls[@]}" --fail -X POST -o /dev/null "$base/v2/grants/$gid/collect"; nothing_open 'collected after reopen'
  ok 'env release: only its bucket opens; close all and restart pause it (423); one Reopen tap resumes it'
  vault_scenario
  agent_iface_scenario
  # No diagnostic, audit or SQLite WAL (including free pages) contains the value.
  if grep -aFl "$sentinel" "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$T"/env-*.out "$T"/env-*.err "$T"/seal-*.log; then fail 'env value leaked'; fi
  rmdir "$ram/aqmas-env" "$ram"; ok 'env import, signed revision, child env, RAM checkout/checkin, revoke, shell export/unset, sentinel scan'
  kill "$SEAL_PID"; wait "$SEAL_PID" || true; rm "$T/data/ca/server.crt"; seal_start serve; owner repair-leaf; wait "$SEAL_PID" || true; seal_start serve; "$AQMAS" list --json >/dev/null; nothing_open 'leaf repair'
  owner recovery-drill "$T/offline.identity" >"$T/recovery-drill.json" || fail 'browser recovery drill'
  bun -e 'const r=await Bun.file(process.argv[1]).json(); if(!r.ok||r.scopes<2||r.buckets<5)process.exit(1)' "$T/recovery-drill.json" || fail "recovery drill counts: $(cat "$T/recovery-drill.json")"
  if owner recovery-drill "$T/other.identity" 2>/dev/null; then fail 'recovery drill accepted another identity'; fi
  nothing_open 'recovery drill'
  kill "$SEAL_PID"; wait "$SEAL_PID" || true
  local pin recovery; pin=$(sed -n 's/^manifest_sha256="\(.*\)"$/\1/p' "$T/config.toml")
  # Offline drill of a standalone backup: counts only.
  [[ ! -e $T/data/aqmas.db-wal ]] || fail 'the stopped broker left a WAL'; cp "$T/data/aqmas.db" "$T/backup.db" # stopped: a plain copy is a standalone backup
  "$AQMASD" -config "$T/config.toml" seal-drill "$T/backup.db" "$(sed -n 's/^recipient="\(.*\)"$/\1/p' "$T/config.toml")" <"$T/offline.identity" >"$T/offline-drill.out" || fail 'offline seal-drill'
  grep -q 'scope' "$T/offline-drill.out" || fail "offline drill output: $(cat "$T/offline-drill.out")"
  if "$AQMASD" -config "$T/config.toml" seal-drill "$T/backup.db" "$(sed -n 's/^recipient="\(.*\)"$/\1/p' "$T/config.toml")" <"$T/other.identity" >/dev/null 2>&1; then fail 'offline drill accepted another identity'; fi
  # Private UDS path fits sockaddr_un regardless of TMPDIR length.
  recovery=$(mktemp -d /dev/shm/aqmas-recovery.XXXXXXXX)
  cp "$T/data/aqmas.db" "$T/before-recovery.sqlite"; local backup; backup=$(sha256sum "$T/before-recovery.sqlite"|cut -d' ' -f1)
  printf 'recovery_backup_sha256="%s"\nrecovery_serial_high_water=1000000\n' "$backup" >>"$T/config.toml"
  "$AQMASD" -config "$T/config.toml" seal-recover "$recovery/session" <"$T/offline.identity" & pid=$!
  for _ in $(seq 50); do [[ -f "$recovery/session/ticket" ]] && break; sleep .1; done
  curl -fsS --unix-socket "$recovery/session/broker.sock" http://localhost/ | grep -qi 'isolated aqmas recovery' || fail 'private recovery UI not served'
  rm "$OWNER_STATE"; owner recover "$recovery/session" "$pin"; wait "$pid"; local newpin; newpin=$(sha256sum "$recovery/session/replacement-manifest.json"|cut -d' ' -f1); sed -i -e '/^recovery_backup_sha256=/d' -e '/^recovery_serial_high_water=/d' -e "s/^manifest_sha256=.*/manifest_sha256=\"$newpin\"/" "$T/config.toml"
  mv "$T/data/aqmas.db" "$T/recovered.sqlite"; cp "$T/before-recovery.sqlite" "$T/data/aqmas.db"; if timeout 5 "$AQMASD" -config "$T/config.toml" serve >"$T/rollback-refusal" 2>&1; then fail 'accepted rolled-back owner database'; fi; grep -q 'activation pin mismatch' "$T/rollback-refusal" || fail 'did not check recovery transition pin'; mv "$T/recovered.sqlite" "$T/data/aqmas.db"
  rm "$recovery/session/replacement-manifest.json"; rmdir "$recovery/session" "$recovery"; seal_start serve; owner login >/dev/null; nothing_open 'after recovery'
  owner buckets --json | bun -e 'const v=await Bun.stdin.json(),k=v.passkeys.find(p=>p.current),keyed=v.scopes.filter(s=>s.has_key).map(s=>s.scope); if(v.mode!=="buckets"||!k||k.missing.some(s=>keyed.includes(s))||k.opens!==k.of||k.scopes.some(s=>!s.tested))process.exit(1)' || fail 'replacement passkey does not open every bucket'
  owner rekey installation 2>/dev/null || fail 'rekey the installation scope with the replacement'
  owner capability test Replacement 2>/dev/null || fail 'replacement passkey after rekey'; nothing_open 'rekey'
  if "$AQMAS" list --json >/dev/null 2>&1; then fail 'old host remained admitted after recovery'; fi
  rm -f "$T/backup.db"
  ok 'leaf repair; browser and offline recovery drills; zero surviving owner passkeys to a replacement that opens every bucket; rekey'
}
