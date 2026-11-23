# Sourced by run.sh once the store is sealed. Remembered browsers (docs/BUCKETS.md §13): a passkey without PRF is
# enabled through a browser key, opens a bucket for an approval, survives a Rekey, then is
# forgotten and refused. The owner helper runs the page's own code (web/src/buckets.ts,
# capabilities.ts, browserKey.ts) against the real aqmasd; its software authenticator returns
# no PRF result for a passkey registered as approve-only.

# ssh_pending WHY: queue an SSH request that needs the SSH CA; sets RPID and RID.
ssh_pending() {
  "$AQMAS" ssh testhost --fresh --why "$1" -- echo ok </dev/null >"$T/bk.out" 2>"$T/bk.err" &
  RPID=$!; RID=$(owner wait ssh interop-host 20)
}
# mode_of NAME: how the passkey opens buckets ("prf", "browser" or "").
mode_of() { owner buckets --json | bun -e 'const v=await Bun.stdin.json(),s=JSON.parse(process.argv[2]);const k=v.passkeys.find(p=>p.id===s.find(x=>x.nickname===process.argv[1]).id);console.log(k.mode)' "$1" "$(owner passkeys)"; }

browser_key_scenario() {
  local original fp
  original=$(owner passkeys | bun -e 'console.log((await Bun.stdin.json()).find(k=>k.current).nickname)')
  owner close-all; nothing_open 'before the remembered browser'
  OWNER_NO_PRF=1 owner capability register 'No PRF' approve-only 2>"$T/bk-register.err" || { cat "$T/bk-register.err"; fail 'register a passkey without PRF'; }
  # No silent downgrade: a passkey that returns PRF results is refused the browser path.
  owner capability register 'Has PRF' approve-only 2>/dev/null || fail 'register an approve-only passkey with PRF'
  if owner remember 'Has PRF' 'Interop browser' 2>"$T/bk-downgrade.err"; then fail 'a passkey with PRF was moved to the browser path'; fi
  grep -q 'returned a PRF result' "$T/bk-downgrade.err" || { cat "$T/bk-downgrade.err"; fail 'refusal of the browser path for a PRF passkey'; }
  [[ $(mode_of 'Has PRF') == "" ]] || fail 'a refused remember changed the passkey'
  owner remove-passkey 'Has PRF' >/dev/null
  [[ $(mode_of 'No PRF') == "" && $(mode_of "$original") == prf ]] || fail 'modes before remember'

  # Not remembered: it cannot open the SSH CA. The challenge for a closed bucket does not even
  # list it (a browser would not offer the passkey), so the authenticator refuses to answer.
  owner use-passkey 'No PRF' >/dev/null; owner login >/dev/null
  ssh_pending 'no PRF, not remembered'
  if owner approve "$RID" 300 >/dev/null 2>"$T/bk-refused.err"; then fail 'a passkey without PRF opened a closed bucket'; fi
  grep -Eq '423 locked|credential not allowed' "$T/bk-refused.err" || { cat "$T/bk-refused.err"; fail 'refusal of a passkey without PRF'; }
  nothing_open 'refused approval'

  # Remember this browser: the PRF passkey approves (a signed action naming the passkey and
  # the browser key), the passkey without PRF enrols and tests.
  owner use-passkey "$original" >/dev/null; owner login >/dev/null
  owner remember 'No PRF' 'Interop browser' 2>"$T/bk-remember.err" || { cat "$T/bk-remember.err"; fail 'remember this browser'; }
  fp=$(owner browser-key); [[ $fp =~ ^[0-9a-f]{32}$ ]] || fail "browser key fingerprint '$fp'"
  grep -q "\"action\":\"remember\".*\"browser_key_id\":\"$fp\".*\"browser_label\":\"Interop browser\"" "$T/bk-remember.err" || { cat "$T/bk-remember.err"; fail 'the signed remember does not name the browser key'; }
  owner state | grep -q '"action":"passkey_remember_browser"' || fail 'remember not audited'
  owner buckets --json | bun -e 'const v=await Bun.stdin.json(),k=v.passkeys.find(p=>p.mode==="browser"),keyed=v.scopes.filter(s=>s.has_key).map(s=>s.scope),b=k?.browsers?.[0];
    if(!k||k.prf||k.browsers.length!==1||b.id!==process.argv[1]||b.label!=="Interop browser"||!b.last_used_at||keyed.some(s=>!b.scopes.some(x=>x.scope===s&&x.tested))||k.opens!==k.of||v.passkeys.filter(p=>p.mode==="prf").length!==1)process.exit(1)' "$fp" || fail "status after remember: $(owner buckets --json)"
  nothing_open 'remember'

  # It opens the SSH CA for the pending approval, from the remembered browser.
  owner use-passkey 'No PRF' >/dev/null; owner login >/dev/null
  owner approve "$RID" 300 >/dev/null 2>"$T/bk-approve.err" || { cat "$T/bk-approve.err"; fail 'approval from the remembered browser'; }
  wait "$RPID"; grep -qx ok "$T/bk.out" || fail 'SSH after an approval from the remembered browser'
  nothing_open 'approval from the remembered browser (instant hold)'

  # Rekey by the remembered browser, the test tap, and it still opens. The PRF passkey lost
  # its wrap of the scope (as after any rekey) and is enabled again from the remembered browser.
  owner rekey installation 2>"$T/bk-rekey.err" || { cat "$T/bk-rekey.err"; fail 'rekey from the remembered browser'; }
  owner buckets --json | bun -e 'const v=await Bun.stdin.json(),k=v.passkeys.find(p=>p.mode==="browser"),o=v.passkeys.find(p=>p.mode!=="browser"&&p.scopes.length);
    if(k.browsers[0].scopes.find(s=>s.scope==="installation").tested||o.scopes.some(s=>s.scope==="installation"))process.exit(1)' || fail "status after rekey: $(owner buckets --json)"
  owner capability test 'No PRF' 2>"$T/bk-test.err" || { cat "$T/bk-test.err"; fail 'test after rekey'; }
  ssh_pending 'after a rekey by the remembered browser'
  owner approve "$RID" 300 >/dev/null 2>"$T/bk-approve2.err" || { cat "$T/bk-approve2.err"; fail 'approval after rekey'; }
  wait "$RPID"; grep -qx ok "$T/bk.out" || fail 'SSH after the rekey'
  owner capability enable "$original" 2>"$T/bk-enable.err" || { cat "$T/bk-enable.err"; fail 'enable the PRF passkey from the remembered browser'; }
  owner capability test "$original" 2>/dev/null || fail 'test the re-enabled PRF passkey'
  [[ $(mode_of "$original") == prf ]] || fail 'the PRF passkey changed mode'

  # Forget (signed by the PRF passkey): the wraps are gone and the browser is refused.
  owner use-passkey "$original" >/dev/null; owner login >/dev/null
  owner forget 'No PRF' 2>"$T/bk-forget.err" || { cat "$T/bk-forget.err"; fail 'forget the browser'; }
  grep -q "\"action\":\"forget\".*\"browser_key_id\":\"$fp\"" "$T/bk-forget.err" || fail 'the signed forget does not name the browser key'
  [[ $(mode_of 'No PRF') == "" && -z $(owner browser-key) ]] || fail 'forget left the browser remembered'
  owner use-passkey 'No PRF' >/dev/null; owner login >/dev/null
  ssh_pending 'forgotten browser'
  if owner approve "$RID" 300 >/dev/null 2>"$T/bk-forgotten.err"; then fail 'a forgotten browser opened a bucket'; fi
  grep -Eq '423 locked|credential not allowed' "$T/bk-forgotten.err" || { cat "$T/bk-forgotten.err"; fail 'refusal after forget'; }
  nothing_open 'forgotten browser'
  owner deny "$RID" >/dev/null 2>&1; wait "$RPID" 2>/dev/null || true
  owner use-passkey "$original" >/dev/null; owner login >/dev/null
  owner remove-passkey 'No PRF' >/dev/null
  ok 'remembered browser: a passkey without PRF enabled through a browser key, approval opened the SSH CA, rekey and test, PRF passkey re-enabled from it, forgotten and refused'
}
