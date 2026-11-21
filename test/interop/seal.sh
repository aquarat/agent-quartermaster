# Sourced after personal_cutover; all paths and processes belong to this test.
seal_start() {
  "$AQMASD" -config "$T/config.toml" "$1" >"$T/seal-$1.log" 2>&1 &
  SEAL_PID=$!; PIDS+=("$SEAL_PID")
  for _ in $(seq 100); do curl -fsS "$AQMAS_BASE/healthz" >/dev/null 2>&1 && return; sleep 0.1; done
  cat "$T/seal-$1.log"; fail "seal $1 did not start"
}
seal_cutover() {
  local recipient stage digest pin
  kill "${PIDS[-1]}"; wait "${PIDS[-1]}" || true
  recipient=$(go run "$ROOT/test/interop/agefixture" "$T/offline.identity")
  cat >>"$T/config.toml" <<EOF
[seal]
required=true
recipient="$recipient"
EOF
  seal_start seal-import
  owner seal-eval; owner seal-eval
  stage=$(find "$T/data" -maxdepth 1 -type d -name 'seal-stage-*'); digest=$(sha256sum "$stage/inventory.json" | cut -d' ' -f1)
  if owner seal-activate 2>"$T/no-proof.err"; then fail 'activated without recovery'; fi
  "$AQMASD" seal-drill "$stage/inventory.json" "$digest" "$recipient" <"$T/offline.identity" >"$stage/recovery.proof"
  chmod 600 "$stage/recovery.proof"; owner seal-activate; wait "$SEAL_PID" || true
  pin=$(sha256sum "$stage/manifest.json" | cut -d' ' -f1); echo "manifest_sha256=\"$pin\"" >>"$T/config.toml"
  rm -f "$T/data/ca/ssh_user_ca" "$T/data/ca/client_ca.key"
  rm -f "$T/tok/proxy" "$T/tok/minter"
  seal_start serve; [[ $(owner seal-status) == locked ]] || fail 'cold restart not locked'; owner login >/dev/null
  "$AQMASD" -config "$T/config.toml" print-ssh-ca >/dev/null; "$AQMAS" list --json >/dev/null
  owner seal-eval; [[ $(owner seal-status) == unlocked ]] || fail 'no unlock'
  local original; original=$(owner passkeys | bun -e 'console.log((await Bun.stdin.json()).find(k=>k.current).nickname)')
  if owner capability disable "$original" approve-only 2>/dev/null; then fail 'downgraded only unlock credential'; fi
  owner capability register 'Seal spare' unlock
  owner seal-lock; wait "$SEAL_PID" || true; seal_start serve
  owner use-passkey 'Seal spare' >/dev/null; owner login >/dev/null; owner seal-eval
  owner capability disable "$original" approve-only; owner capability enable "$original" unlock
  owner use-passkey "$original" >/dev/null; owner login >/dev/null; owner remove-passkey 'Seal spare' >/dev/null
  owner seal-lock; wait "$SEAL_PID" || true; seal_start serve
  [[ $(owner seal-status) == locked ]] || fail 'lock now did not relock'; ok 'sealed migration, two PRF evaluations, recovery drill, unlock and explicit relock'
}
