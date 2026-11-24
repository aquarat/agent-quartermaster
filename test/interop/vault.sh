# Sourced by run.sh; called from env_scenario on the sealed (format 2) broker: each
# approval opens only its own bucket. The owner is the web UI's own vault code (web/src/vault.ts) with a
# software passkey; the agent is the real CLI; signatures are checked by openssl.
vault_scenario() {
  local path=client-a/paas/web-form w="$T/vault" pid sentinel=vault-$(openssl rand -hex 16)
  local key=$'-----BEGIN TEST KEY-----\nline two '"$sentinel"$'\n\'single\' "double" $HOME `id` \\ end\n-----END TEST KEY-----\n'
  mkdir -m 700 "$w"
  openssl pkeyutl -help 2>&1 | grep -q -- -rawin || fail 'openssl 3 (pkeyutl -rawin) is needed to verify Ed25519 signatures'

  # A set made in the web API, filled by the form path: an import (one value multi-line), then a merge.
  owner catalogue "add-set:$path"
  printf 'APP_SECRET=%s\nOLD_TOKEN=gone\nAPP_KEY="-----BEGIN TEST KEY-----\\nline two %s\n'"'"'single'"'"' \\"double\\" $HOME `id` \\\\ end\n-----END TEST KEY-----\n"\n' "$sentinel" "$sentinel" >"$w/form.env"
  [[ $(owner vault-commit "$path" import "$w/form.env") == 'APP_KEY:add,APP_SECRET:add,OLD_TOKEN:add' ]] || fail 'form import changes'
  printf "APP_TOKEN='second %s'\n" "$sentinel" >"$w/merge.env"
  [[ $(owner vault-commit "$path" merge "$w/merge.env" OLD_TOKEN) == 'APP_TOKEN:add,OLD_TOKEN:remove' ]] || fail 'form merge changes'
  owner vault-state | bun -e 'const s=(await Bun.stdin.json()).sets.find(s=>s.set_slug==="web-form"); if(s.revision!==2||s.names.join()!=="APP_KEY,APP_SECRET,APP_TOKEN"||JSON.stringify(s).includes("vault-"))process.exit(1)' || fail 'state after form commits'

  # Reveal: decrypted by the asking process only; multi-line value intact.
  owner vault-reveal "$path" APP_KEY APP_SECRET APP_TOKEN >"$w/revealed.json"
  KEY="$key" SENTINEL="$sentinel" bun -e 'const e=await Bun.file(process.argv[1]).json(); const want=[["APP_KEY",process.env.KEY],["APP_SECRET",process.env.SENTINEL],["APP_TOKEN","second "+process.env.SENTINEL]]; if(JSON.stringify(e.map(x=>[x.name,x.value]))!==JSON.stringify(want))process.exit(1)' "$w/revealed.json" || fail 'reveal did not return what the form stored'
  nothing_open 'reveal (instant hold)'
  owner vault-policy client-a off
  if owner vault-reveal "$path" APP_SECRET >/dev/null 2>"$T/vault-noreveal.err"; then fail 'reveal with the organisation policy off'; fi
  owner vault-policy client-a on

  # Delivery of the form's values, multi-line included: child environment, shell export; a literal .env refuses.
  local keysum; keysum=$(printf %s "$key" | sha256sum | cut -d' ' -f1) # the child gets a minimal environment: pass the expectation as an argument
  "$AQMAS" run "$path" --why 'form values' -- sh -c '[ "$(printf %s "$APP_KEY" | sha256sum | cut -d" " -f1)" = "$1" ] && [ -n "$APP_SECRET" ]' sh "$keysum" </dev/null >"$T/vault-run.out" 2>"$T/vault-run.err" & pid=$!
  owner env-decide approve process; wait "$pid" || fail 'aqmas run did not deliver the multi-line value intact'
  (eval "$("$AQMAS" cos "$path" --why 'shell delivery of a multi-line value')"; [[ $APP_KEY == "$key" && $APP_TOKEN == "second $sentinel" ]]; eval "$("$AQMAS" cis "$path")"; [[ ! -v APP_KEY ]]) >"$T/vault-shell.out" 2>"$T/vault-shell.err" & pid=$!
  owner env-decide approve shell; wait "$pid" || fail 'shell export of a multi-line value'
  (cd "$T/envwork"; "$AQMAS" co "$path" --why 'file delivery must refuse') >"$T/vault-co.out" 2>"$T/vault-co.err" & pid=$!
  owner env-decide approve file; if wait "$pid"; then fail 'a multi-line value was written to a literal .env'; fi
  grep -q 'multi-line value' "$T/vault-co.err" && [[ ! -e "$T/envwork/.env" ]] || fail 'file mode did not explain the refusal'

  # A signer generated inside aqmas (Ed25519 over the SHA-256 digest): single-use grant for two files.
  local s1=client-a/paas/release-key fp
  owner vault-signer "$s1" ed25519-sha256 generate >"$w/signer1.json"
  "$AQMAS" signer "$s1" --pem >"$w/pub1.pem"
  fp=$(bun -e 'console.log((await Bun.file(process.argv[1]).json()).fingerprint)' "$w/signer1.json")
  "$AQMAS" signer "$s1" | grep "sha256:$fp" >/dev/null || fail 'CLI and page disagree about the signer public key'
  head -c 300000 /dev/urandom >"$w/image.bin"; echo 'release notes' >"$w/notes.txt"
  "$AQMAS" sign "$s1" --why 'interop release' "$w/image.bin" "$w/notes.txt" >"$T/vault-sign1.out" 2>"$T/vault-sign1.err" & pid=$!
  owner vault-sign approve; wait "$pid" || { cat "$T/vault-sign1.err"; fail 'aqmas sign (single use)'; }
  grep -q "$(sha256sum "$w/image.bin" | cut -d' ' -f1)" "$T/vault-sign1.err" || fail 'CLI did not print the digest to compare with the card'
  nothing_open 'single-use signing grant spent'
  for f in image.bin notes.txt; do
    openssl dgst -sha256 -binary "$w/$f" >"$w/$f.digest"
    openssl pkeyutl -verify -pubin -inkey "$w/pub1.pem" -rawin -in "$w/$f.digest" -sigfile "$w/$f.sig" >/dev/null || fail "openssl rejected the Ed25519 signature of $f"
  done
  if "$AQMAS" sign "$s1" --why 'again' "$w/image.bin" 2>/dev/null; then fail 'overwrote an existing signature file'; fi

  # An imported ECDSA P-256 key: a time-boxed grant, reused by a second call without a new approval.
  local s2=client-a/paas/ecdsa-key
  openssl ecparam -name prime256v1 -genkey -noout -out "$w/ec.pem" 2>/dev/null
  owner vault-signer "$s2" ecdsa-p256-sha256 import "$w/ec.pem" >"$w/signer2.json"
  "$AQMAS" signer "$s2" --pem >"$w/pub2.pem"
  cmp <(openssl ec -in "$w/ec.pem" -pubout 2>/dev/null) "$w/pub2.pem" || fail 'imported signer has another public key'
  for f in a b c; do echo "artifact $f" >"$w/$f.bin"; done
  "$AQMAS" sign "$s2" --why 'interop grant' --ttl 10m --count 5 "$w/a.bin" >"$T/vault-sign2.out" 2>"$T/vault-sign2.err" & pid=$!
  owner vault-sign approve 300 3; wait "$pid" || { cat "$T/vault-sign2.err"; fail 'aqmas sign (grant)'; }
  owner vault-state | bun -e 'const r=(await Bun.stdin.json()).requests; if(r.length!==1||r[0].used!==1||r[0].max_signatures!==3||r[0].ttl_seconds!==300||r[0].status!=="approved")process.exit(1)' || fail 'grant accounting'
  [[ $(open_kinds) == signer ]] || fail "a signing grant opened more than its signer: $(owner open-buckets)"
  "$AQMAS" sign "$s2" "$w/b.bin" "$w/c.bin" </dev/null >"$T/vault-sign3.out" 2>"$T/vault-sign3.err" || { cat "$T/vault-sign3.err"; fail 'second call under the signing grant'; }
  for f in a b c; do openssl dgst -sha256 -verify "$w/pub2.pem" -signature "$w/$f.bin.sig" "$w/$f.bin" >/dev/null || fail "openssl rejected the ECDSA signature of $f.bin"; done
  owner vault-state | bun -e 'if((await Bun.stdin.json()).requests.length)process.exit(1)' || fail 'a spent grant is still listed'
  "$AQMAS" sign "$s2" --why 'new grant to end' --ttl 10m "$w/a.bin" --force >"$T/vault-sign7.out" 2>"$T/vault-sign7.err" & pid=$!
  owner vault-sign approve 600 20; wait "$pid" || fail 'second signing grant'
  "$AQMAS" sign "$s2" --end || fail 'ending the signing grant'
  owner vault-state | bun -e 'if((await Bun.stdin.json()).requests.length)process.exit(1)' || fail 'an ended grant is still listed'
  nothing_open 'ended signing grant'

  # An imported Ed25519 seed signing a small manifest itself (pure Ed25519), from stdin, hex on stdout.
  local s3=client-a/paas/manifest-key seed; seed=$(openssl rand -hex 32)
  printf '%s\n' "$seed" >"$w/seed.hex"
  owner vault-signer "$s3" ed25519 import "$w/seed.hex" >"$w/signer3.json"
  "$AQMAS" signer "$s3" --pem >"$w/pub3.pem"
  head -c 140 /dev/urandom >"$w/manifest.bin"
  "$AQMAS" sign "$s3" --why 'interop manifest' - <"$w/manifest.bin" >"$w/manifest.sig.hex" 2>"$T/vault-sign4.err" & pid=$!
  owner vault-sign approve; wait "$pid" || { cat "$T/vault-sign4.err"; fail 'aqmas sign (stdin)'; }
  bun -e 'await Bun.write(process.argv[2], Buffer.from((await Bun.file(process.argv[1]).text()).trim(), "hex"))' "$w/manifest.sig.hex" "$w/manifest.sig"
  openssl pkeyutl -verify -pubin -inkey "$w/pub3.pem" -rawin -in "$w/manifest.bin" -sigfile "$w/manifest.sig" >/dev/null || fail 'openssl rejected the pure Ed25519 signature'
  if "$AQMAS" sign "$s3" --why 'too big' "$w/image.bin" 2>"$T/vault-sign5.err"; then fail 'pure Ed25519 accepted a large artifact'; fi
  "$AQMAS" sign "$s1" --why 'to be denied' --digest "$(sha256sum "$w/a.bin" | cut -d' ' -f1 | sed 's/^/sha256:/')" >"$T/vault-sign6.out" 2>"$T/vault-sign6.err" & pid=$!
  owner vault-sign deny; if wait "$pid"; then fail 'denied signing request produced a signature'; fi

  # Neither the imported seed nor a form value is anywhere outside the sealed records, in any encoding.
  SEED="$seed" SENTINEL="$sentinel" bun -e 'const seed=Buffer.from(process.env.SEED,"hex"), forms=[seed, Buffer.from(process.env.SEED), Buffer.from(seed.toString("base64")), Buffer.from(seed.toString("base64url")), Buffer.from(process.env.SENTINEL)];
    for (const f of process.argv.slice(1)) { const b=Buffer.from(await Bun.file(f).arrayBuffer()); for (const x of forms) if (b.includes(x)) { console.error("found in "+f); process.exit(1) } }' \
    "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$T"/vault-*.out "$T"/vault-*.err "$T"/seal-*.log "$w"/signer*.json || fail 'a signer key or form value leaked'
  owner vault-state | bun -e 'const t=await Bun.stdin.text(); if(t.includes(process.argv[1])||t.includes("private"))process.exit(1)' "$seed" || fail 'state exposes signer key material'
  ok 'web form (import, merge, multi-line), reveal and policy, run/shell delivery, signers: generate, import, single-use, grant reuse, stdin; openssl verification; sentinel scan'
}
