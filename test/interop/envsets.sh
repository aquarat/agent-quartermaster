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
  kill "$SEAL_PID"; wait "$SEAL_PID" || true; rm "$T/data/ca/server.crt"; seal_start serve; owner seal-eval; owner repair-leaf; wait "$SEAL_PID" || true; seal_start serve; "$AQMAS" list --json >/dev/null
  kill "$SEAL_PID"; wait "$SEAL_PID" || true
  local stage digest recipient pin recovery; stage=$(find "$T/data" -type d -name 'seal-stage-*'); digest=$(sha256sum "$stage/inventory.json"|cut -d' ' -f1); pin=$(sha256sum "$stage/manifest.json"|cut -d' ' -f1); recipient=$(sed -n 's/^recipient="\(.*\)"$/\1/p' "$T/config.toml")
  # Private UDS path fits sockaddr_un regardless of TMPDIR length.
  recovery=$(mktemp -d /dev/shm/aqmas-recovery.XXXXXXXX)
  cp "$T/data/aqmas.db" "$T/before-recovery.sqlite"; local backup; backup=$(sha256sum "$T/before-recovery.sqlite"|cut -d' ' -f1)
  printf 'recovery_backup_sha256="%s"\nrecovery_serial_high_water=1000000\n' "$backup" >>"$T/config.toml"
  "$AQMASD" seal-transfer "$stage/inventory.json" "$digest" "$recipient" <"$T/offline.identity" | "$AQMASD" -config "$T/config.toml" seal-recover "$recovery/session" & pid=$!
  for _ in $(seq 50); do [[ -f "$recovery/session/ticket" ]] && break; sleep .1; done
  curl -fsS --unix-socket "$recovery/session/broker.sock" http://localhost/ | grep -qi 'isolated aqmas recovery' || fail 'private recovery UI not served'
  rm "$OWNER_STATE"; owner recover "$recovery/session" "$pin"; wait "$pid"; local newpin; newpin=$(sha256sum "$recovery/session/replacement-manifest.json"|cut -d' ' -f1); sed -i -e '/^recovery_backup_sha256=/d' -e '/^recovery_serial_high_water=/d' -e "s/^manifest_sha256=.*/manifest_sha256=\"$newpin\"/" "$T/config.toml"
  mv "$T/data/aqmas.db" "$T/recovered.sqlite"; cp "$T/before-recovery.sqlite" "$T/data/aqmas.db"; if timeout 5 "$AQMASD" -config "$T/config.toml" serve >"$T/rollback-refusal" 2>&1; then fail 'accepted rolled-back owner database'; fi; grep -q 'activation pin mismatch' "$T/rollback-refusal" || fail 'did not check recovery transition pin'; mv "$T/recovered.sqlite" "$T/data/aqmas.db"
  rm "$recovery/session/replacement-manifest.json"; rmdir "$recovery/session" "$recovery"; seal_start serve; owner login; owner seal-eval; [[ $(owner seal-status) == unlocked ]] || fail 'disaster replacement did not unlock'
  if "$AQMAS" list --json >/dev/null 2>&1; then fail 'old host remained admitted after recovery'; fi
  ok 'leaf repair and zero surviving owner passkeys to cold unlock with replacement'
}
