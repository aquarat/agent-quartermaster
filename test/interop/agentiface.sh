# Sourced by run.sh; called from env_scenario on the sealed (format 2) broker, after the
# vault scenario. 0.10.0: the agent guide, discovery as an owner switch, a single-value
# secret with `aqmas run` and `aqmas get`, "don't ask again" and the MCP server on stdio.
# The owner is the web UI's own code with a software passkey; the agent is the real CLI.
agent_iface_scenario() {
  local w="$T/iface" path=client-a/paas/tailnet-api-key pid value sum
  mkdir -m 700 "$w"
  value="tskey-interop-$(openssl rand -hex 16)"; printf %s "$value" >"$w/value"; sum=$(sha256sum "$w/value" | cut -d' ' -f1)

  # The guide is in the CLI itself, for people and for programs.
  "$AQMAS" guide >"$w/guide.md"
  grep -q 'aqmas run' "$w/guide.md" && grep -q 'claude mcp add aqmas -- aqmas mcp' "$w/guide.md" && grep -q 'not_admitted' "$w/guide.md" || fail 'aqmas guide lacks the essentials'
  "$AQMAS" guide --json | bun -e 'const g=await Bun.stdin.json(); if(!g.commands.some(c=>c.name==="get")||!g.exit_codes["3"]||g.mcp.tools.length!==8||!g.commands.some(c=>c.name==="ssh-agent"))process.exit(1)' || fail 'aqmas guide --json'
  "$AQMAS" help | grep -q 'aqmas guide' || fail 'aqmas help does not point to the guide'

  # Discovery is off until the owner turns it on, per organisation.
  "$AQMAS" ls >"$w/ls-off.out" 2>&1 || fail "aqmas ls with listing off: $(cat "$w/ls-off.out")"
  grep -q 'discovery is disabled by the owner' "$w/ls-off.out" && ! grep -q 'client-a' "$w/ls-off.out" || fail "listing off: $(cat "$w/ls-off.out")"
  "$AQMAS" ls --json | bun -e 'const c=await Bun.stdin.json(); if(c.discovery||c.credentials.length)process.exit(1)' || fail 'ls --json with listing off'
  owner catalogue policy:client-a:discovery=on || fail 'turning listing on for client-a'
  "$AQMAS" ls --json >"$w/ls.json"
  bun -e 'const c=await Bun.file(process.argv[1]).json(), by=Object.fromEntries(c.credentials.map(x=>[x.path,x]));
    const env=by["client-a/paas/web-form"], signer=by["client-a/paas/release-key"];
    if(!c.discovery||!env||env.kind!=="env-set"||env.names.join()!=="APP_KEY,APP_SECRET,APP_TOKEN"||!signer||signer.kind!=="signer"||signer.scheme!=="ed25519-sha256"||c.credentials.some(x=>x.path.startsWith("personal/")))process.exit(1)' "$w/ls.json" || fail "listing for client-a: $(cat "$w/ls.json")"
  if grep -q 'vault-\|interop-' "$w/ls.json"; then fail 'the listing carries a value'; fi
  "$AQMAS" targets >"$w/targets-off.out"; grep -q 'no SSH targets are listed' "$w/targets-off.out" || fail "personal has listing off, yet: $(cat "$w/targets-off.out")"
  owner catalogue policy:personal:discovery=on || fail 'turning listing on for personal'
  "$AQMAS" targets --json | bun -e 'const t=(await Bun.stdin.json()).targets.find(t=>t.name==="testhost"); if(!t||t.address!=="127.0.0.1"||!t.users.length||!t.path.startsWith("personal/fleet/"))process.exit(1)' || fail 'aqmas targets'
  "$AQMAS" targets | grep -q testhost || fail 'aqmas targets (table)'
  ok 'aqmas guide; discovery off by default; the owner turns listing on per organisation; ls and targets list names only'

  # A secret: one value, created with one tap, listed by name.
  owner vault-secret "$path" TAILNET_API_KEY "$w/value" 'interop key' 'https://example.com/admin/keys' >"$w/secret.json" || fail 'creating the secret'
  owner vault-state | bun -e 'const s=(await Bun.stdin.json()).sets.find(s=>s.set_slug==="tailnet-api-key"); if(!s||s.kind!=="secret"||s.revision!==1||s.names.join()!=="TAILNET_API_KEY"||s.standing_cap_seconds!==3600)process.exit(1)' || fail 'state of the new secret'
  "$AQMAS" ls --json | bun -e 'const s=(await Bun.stdin.json()).credentials.find(x=>x.path===process.argv[1]); if(!s||s.kind!=="secret"||s.env!=="TAILNET_API_KEY"||s.names||s.note!=="interop key")process.exit(1)' "$path" || fail 'the secret in aqmas ls'
  "$AQMAS" ls | grep -q "$path  *secret  *\$TAILNET_API_KEY" || fail "aqmas ls (table): $("$AQMAS" ls)"

  # aqmas run injects it under its own name, or another with --env.
  "$AQMAS" run "$path" --why 'interop: use the key' -- sh -c '[ "$(printf %s "$TAILNET_API_KEY" | sha256sum | cut -d" " -f1)" = "$1" ]' sh "$sum" </dev/null >"$T/iface-run.out" 2>"$T/iface-run.err" & pid=$!
  owner env-decide approve process; wait "$pid" || { cat "$T/iface-run.err"; fail 'aqmas run with a secret'; }
  "$AQMAS" run "$path" --env TS_API_KEY --why 'interop: another name' -- sh -c '[ -z "${TAILNET_API_KEY+x}" ] && [ "$(printf %s "$TS_API_KEY" | sha256sum | cut -d" " -f1)" = "$1" ]' sh "$sum" </dev/null >"$T/iface-run2.out" 2>"$T/iface-run2.err" & pid=$!
  owner env-decide approve process; wait "$pid" || { cat "$T/iface-run2.err"; fail 'aqmas run --env'; }
  # aqmas get prints the value; the card for it is the get delivery, signed as such.
  "$AQMAS" get "$path" --why 'interop: the value itself' </dev/null >"$w/got" 2>"$T/iface-get.err" & pid=$!
  owner env-decide approve get; wait "$pid" || { cat "$T/iface-get.err"; fail 'aqmas get'; }
  [[ $(cat "$w/got") == "$value" && $(wc -l <"$w/got") == 1 ]] || fail 'aqmas get printed something else'
  if "$AQMAS" get client-a/paas/web-form --why 'not a secret' </dev/null >/dev/null 2>"$T/iface-get2.err"; then fail 'aqmas get on an env set'; fi
  grep -q 'aqmas get prints one secret' "$T/iface-get2.err" || fail "get on an env set: $(cat "$T/iface-get2.err")"
  nothing_open 'collected secret releases'
  ok 'secret: one tap to create; aqmas run (and --env) and aqmas get deliver it with a virtual-authenticator approval'

  # "Don't ask again": approve one run for an hour; the next run needs no tap. The card
  # offers only what the item's limit allows (one hour until the owner raises it).
  "$AQMAS" run "$path" --why 'interop: first of several' -- true </dev/null >"$T/iface-st0.out" 2>"$T/iface-st0.err" & pid=$!
  if owner env-decide approve process 21600 2>"$T/iface-st0-owner.err"; then fail 'a six-hour rule under a one-hour limit'; fi
  owner env-decide approve process 3600; wait "$pid" || { cat "$T/iface-st0.err"; fail 'run approved with a standing rule'; }
  [[ $(open_kinds) == env-set ]] || fail "a don't-ask-again rule does not hold its bucket: $(owner open-buckets)"
  timeout 30 "$AQMAS" run "$path" --why 'interop: no tap this time' -- sh -c '[ "$(printf %s "$TAILNET_API_KEY" | sha256sum | cut -d" " -f1)" = "$1" ]' sh "$sum" </dev/null >"$T/iface-st1.out" 2>"$T/iface-st1.err" || { cat "$T/iface-st1.err"; fail 'the second aqmas run needed a tap'; }
  owner env-state | bun -e 'const s=await Bun.stdin.json(); if(s.standing.length!==1||s.standing[0].uses!==1||s.standing[0].mode!=="process"||s.releases.some(r=>r.status==="pending"))process.exit(1)' || fail 'rule accounting'
  # Another delivery mode is another question: get still asks.
  "$AQMAS" get "$path" --why 'interop: get is not run' </dev/null >"$w/got2" 2>"$T/iface-st2.err" & pid=$!
  owner env-decide approve get; wait "$pid" || fail 'aqmas get beside a run rule'

  # The MCP server over stdio: the protocol, the tools, a listing, and a run under the rule
  # (no tap; the output is the command's, never the value).
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"interop","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"aqmas_list_credentials","arguments":{}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"aqmas_list_targets","arguments":{}}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"aqmas_run\",\"arguments\":{\"path\":\"$path\",\"why\":\"interop: MCP run under the rule\",\"command\":[\"sh\",\"-c\",\"printf %s \\\"\$TAILNET_API_KEY\\\" | sha256sum | cut -d' ' -f1\"]}}}" \
    | "$AQMAS" mcp >"$T/iface-mcp.out" 2>"$T/iface-mcp.err" || { cat "$T/iface-mcp.err"; fail 'aqmas mcp'; }
  SUM="$sum" SECRET_PATH="$path" bun -e 'const by={}; for (const l of (await Bun.file(process.argv[1]).text()).trim().split("\n")) { const m=JSON.parse(l); if(m.jsonrpc!=="2.0")process.exit(2); if(m.id!==undefined)by[m.id]=m }
    const text=(id)=>{ if(by[id].error||by[id].result.isError)throw Error(JSON.stringify(by[id])); return by[id].result.content[0].text };
    const names=by[2].result.tools.map(t=>t.name).sort().join();
    if(by[1].result.protocolVersion!=="2025-06-18"||by[1].result.serverInfo.name!=="aqmas"||names!=="aqmas_guide,aqmas_list_credentials,aqmas_list_targets,aqmas_run,aqmas_sign,aqmas_ssh_exec,aqmas_status,aqmas_with_ssh_key")process.exit(3);
    const creds=JSON.parse(text(3)).credentials; if(!creds.some(c=>c.path===process.env.SECRET_PATH&&c.kind==="secret"&&c.env==="TAILNET_API_KEY"))process.exit(4);
    if(!JSON.parse(text(4)).targets.some(t=>t.name==="testhost"))process.exit(5);
    const run=JSON.parse(text(5)); if(run.exit_code!==0||run.stdout.trim()!==process.env.SUM)process.exit(6);' "$T/iface-mcp.out" || fail "MCP session: $(cat "$T/iface-mcp.out")"
  owner env-state | bun -e 'if((await Bun.stdin.json()).standing[0].uses!==2)process.exit(1)' || fail 'the MCP run did not go through the rule'

  # Revoke the rule: the next run asks again. Raise the limit: a longer rule is offered.
  owner env-standing-revoke
  "$AQMAS" run "$path" --why 'interop: after revoke' -- true </dev/null >"$T/iface-st3.out" 2>"$T/iface-st3.err" & pid=$!
  owner vault-standing-cap "$path" 21600
  owner env-decide approve process 21600; wait "$pid" || fail 'run after revoke, six-hour rule'
  owner env-state | bun -e 'const s=(await Bun.stdin.json()).standing; if(s.length!==1||s[0].expires_at-s[0].created_at!==21600000)process.exit(1)' || fail 'six-hour rule'
  # The owner turns aqmas get off for the organisation: get is refused, run still works (a
  # policy replacement also ends the rules, so this run asks).
  owner catalogue policy:client-a:get=off || fail 'turning aqmas get off'
  owner env-state | bun -e 'if((await Bun.stdin.json()).standing.length)process.exit(1)' || fail 'a rule survived a policy replacement'
  if "$AQMAS" get "$path" --why 'interop: get is off' </dev/null >/dev/null 2>"$T/iface-get3.err"; then fail 'aqmas get while turned off'; fi
  grep -q 'turned off aqmas get' "$T/iface-get3.err" || fail "get while off: $(cat "$T/iface-get3.err")"
  "$AQMAS" run "$path" --why 'interop: run while get is off' -- true </dev/null >"$T/iface-run3.out" 2>"$T/iface-run3.err" & pid=$!
  # This approval leaves a rule behind on purpose: recovery (later in run.sh) must end it.
  owner env-decide approve process 3600; wait "$pid" || fail 'aqmas run while get is off'
  owner env-state | bun -e 'if((await Bun.stdin.json()).standing.length!==1)process.exit(1)' || fail 'no rule left for the recovery check'

  # The value is in no log, output or database page outside its sealed record.
  if grep -aFl "$value" "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$T"/iface-*.out "$T"/iface-*.err "$T"/seal-*.log "$w/ls.json" "$w/secret.json" 2>/dev/null; then fail 'the secret value leaked'; fi
  ok "don't ask again: one approval covers the next run (CLI and MCP), not another mode; revoke, per-item limit, policy change end it; MCP stdio: tools/list, listings, run; sentinel scan"
}
