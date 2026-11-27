# Sourced by run.sh; called from env_scenario on the sealed (format 2) broker. 0.11.0: a
# host proposes values with the real CLI (`aqmas set import|put ... --why`), the owner
# commits or discards the proposal with a software passkey, and `aqmas run` then gets
# what was proposed. The set does not exist before: `--create` proposes it, and a
# discarded proposal leaves nothing behind.
proposal_scenario() {
  local w="$T/proposals" path=client-a/paas/proposed pid rc psent
  mkdir -m 700 "$w"
  psent="interop-proposed-$(openssl rand -hex 16)"
  printf '# proposed by the interop host\nAPP_TOKEN=%s\nAPP_URL="https://example.com/a b"\n' "$psent" >"$w/proposed.env"

  # The file is checked here, by name and line number, before anything is sent.
  "$AQMAS" set check --from "$w/proposed.env" "$path" >"$w/env-prop-check.out" 2>"$w/env-prop-check.err" || fail "set check: $(cat "$w/env-prop-check.err")"
  [[ $(cat "$w/env-prop-check.out") == $'APP_TOKEN\nAPP_URL\nadd APP_TOKEN\nadd APP_URL' ]] || fail "set check output: $(cat "$w/env-prop-check.out")"
  printf 'APP_TOKEN=%s\nnot an assignment %s\n' "$psent" "$psent" >"$w/bad.env"
  rc=0; "$AQMAS" set import "$path" --from "$w/bad.env" --why 'interop: a file that does not import' --create >"$w/env-prop-bad.out" 2>"$w/env-prop-bad.err" || rc=$?
  [[ $rc == 1 ]] && grep -q 'line 2: ' "$w/env-prop-bad.err" && grep -q 'nothing was sent' "$w/env-prop-bad.err" || fail "import of a bad file: exit $rc: $(cat "$w/env-prop-bad.err")"
  "$AQMAS" set --help | grep -q 'aqmas set check --from FILE' || fail 'aqmas set --help'

  # A missing set is not created by a typo: --create is needed.
  rc=0; "$AQMAS" set import "$path" --from "$w/proposed.env" --why 'interop: no create' >"$w/env-prop-nocreate.out" 2>"$w/env-prop-nocreate.err" || rc=$?
  [[ $rc == 1 ]] && grep -q -- '--create' "$w/env-prop-nocreate.err" || fail "import into a missing set without --create: exit $rc: $(cat "$w/env-prop-nocreate.err")"

  # Discarded: exit 3, and no set, bucket or sealed record stays.
  # (Earlier scenarios may have left a bucket open under a grant: a proposal changes nothing about that.)
  local opened; opened=$(owner open-buckets)
  local buckets; buckets=$(owner buckets | bun -e 'console.log((await Bun.stdin.json()).length)')
  "$AQMAS" set import "$path" --from "$w/proposed.env" --why 'interop: propose a new set' --create --title 'Proposed env' >"$w/env-prop-discard.out" 2>"$w/env-prop-discard.err" & pid=$!
  owner env-proposal discard "$path" >/dev/null; rc=0; wait "$pid" || rc=$?
  [[ $rc == 3 ]] || fail "a discarded proposal: exit $rc: $(cat "$w/env-prop-discard.err")"
  [[ $("${mtls[@]}" -o /dev/null -w '%{http_code}' "$base/v2/env/set?path=$path") == 404 ]] || fail 'a discarded proposal created the set'
  [[ $(owner buckets | bun -e 'console.log((await Bun.stdin.json()).length)') == "$buckets" ]] || fail 'a discarded proposal left a bucket'
  [[ $(owner open-buckets) == "$opened" ]] || fail "a discarded proposal changed what is open: $(owner open-buckets)"

  # Committed: one tap creates the set with its first revision; nothing is opened.
  "$AQMAS" set import "$path" --from "$w/proposed.env" --why 'interop: propose a new set' --create --title 'Proposed env' >"$w/env-prop-commit.out" 2>"$w/env-prop-commit.err" & pid=$!
  owner env-proposal commit "$path" >"$w/card.json"; wait "$pid" || fail "a committed proposal: $(cat "$w/env-prop-commit.err")"
  grep -q "committed: $path is at revision 1" "$w/env-prop-commit.err" || fail "the CLI did not report the commit: $(cat "$w/env-prop-commit.err")"
  # The card and the terminal show the same Ref and commitment.
  bun -e 'const p=await Bun.file(process.argv[1]).json(), err=await Bun.file(process.argv[2]).text();
    if(!p.new_set||p.new_service||p.revision!==0||p.names.length||p.changes!=="APP_TOKEN:add,APP_URL:add"||!p.title.endsWith(" / Proposed env")||!err.includes("Ref "+p.ref)||!err.includes("commitment "+p.commitment)||p.ref.length!==6)process.exit(1)' "$w/card.json" "$w/env-prop-commit.err" || fail "proposal card: $(cat "$w/card.json")"
  [[ $(owner open-buckets) == "$opened" ]] || fail "committing a proposal opened a bucket: $(owner open-buckets)"
  "$AQMAS" run "$path" --why 'interop: use the proposed values' -- sh -c 'test "$APP_TOKEN" = "$(sed -n "s/^APP_TOKEN=//p" "$1")" && test "$APP_URL" = "https://example.com/a b"' sh "$w/proposed.env" </dev/null >"$w/env-prop-run.out" 2>"$w/env-prop-run.err" & pid=$!
  owner env-decide approve process; wait "$pid" || fail "aqmas run after a committed proposal: $(cat "$w/env-prop-run.err")"

  # One key of the set that now exists; the value comes on stdin.
  printf %s "$psent-2" | "$AQMAS" set put "$path" APP_ID --why 'interop: add one key' >"$w/env-prop-put.out" 2>"$w/env-prop-put.err" & pid=$!
  owner env-proposal commit "$path" >/dev/null; wait "$pid" || fail "set put: $(cat "$w/env-prop-put.err")"
  grep -q 'add APP_ID' "$w/env-prop-put.err" && grep -q 'revision 2' "$w/env-prop-put.err" || fail "set put output: $(cat "$w/env-prop-put.err")"
  [[ $("${mtls[@]}" --fail "$base/v2/env/set?path=$path" | bun -e 'const b=await Bun.stdin.json(); console.log(b.revision+" "+b.names.join())') == '2 APP_ID,APP_TOKEN,APP_URL' ]] || fail 'the set after put'

  # The proposed values are in no database page, log or output.
  if grep -aFl "$psent" "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$w"/env-prop-*.out "$w"/env-prop-*.err "$w/card.json" "$T"/seal-*.log 2>/dev/null; then fail 'a proposed value leaked'; fi
  ok 'env proposals: set check; --create needed; discard leaves nothing; commit creates the set; aqmas run gets the proposed values; put; sentinel scan'
}
