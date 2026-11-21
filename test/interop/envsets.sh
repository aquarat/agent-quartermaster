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
  # Create a second grant without an auto-collecting CLI. Lock between apply
  # and collection, then ensure the refused poll did not spend the grant.
  local -a mtls=(curl --silent --show-error --cacert "$AQMAS_CONFIG_DIR/server-ca.pem" --key "$AQMAS_CONFIG_DIR/client.key" --cert "$AQMAS_CONFIG_DIR/client.crt")
  local base="https://127.0.0.1:$PA" rid gid
  rid=$("${mtls[@]}" --fail "$base/v2/env/set?path=$path" | bun -e 'console.log(JSON.stringify({binding:await Bun.stdin.json(),mode:"process",reason:"locked collection test",ttl_seconds:300}))' | "${mtls[@]}" --fail -H 'Content-Type: application/json' --data-binary @- "$base/v2/env/requests" | bun -e 'console.log((await Bun.stdin.json()).id)')
  owner env-decide approve process; gid=$("${mtls[@]}" --fail "$base/v2/env/requests/$rid" | bun -e 'console.log((await Bun.stdin.json()).grant_id)')
  owner seal-lock; wait "$SEAL_PID" || true; seal_start serve
  [[ $("${mtls[@]}" -X POST -o /dev/null -w '%{http_code}' "$base/v2/grants/$gid/collect") == 423 ]] || fail 'collection while locked'
  owner seal-eval; "${mtls[@]}" --fail -X POST -o /dev/null "$base/v2/grants/$gid/collect"
  [[ $("${mtls[@]}" -X POST -o /dev/null -w '%{http_code}' "$base/v2/grants/$gid/collect") == 409 ]] || fail 'collection replay'
  # No diagnostic, audit or SQLite WAL (including free pages) contains the value.
  if grep -aFl "$sentinel" "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$T"/env-*.out "$T"/env-*.err "$T"/seal-*.log; then fail 'env value leaked'; fi
  rmdir "$ram/aqmas-env" "$ram"; ok 'env import, signed revision, child env, RAM checkout/checkin, revoke, shell export/unset, sentinel scan'
}
