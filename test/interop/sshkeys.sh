# Sourced by run.sh; called from env_scenario on the sealed (format 2) broker, after the
# agent interface scenario (which turned listing on for client-a). 0.11.0: SSH key pairs as
# Vault items and deleting items with a bin. The owner is the web UI's own vault code with a
# software passkey; the agent is the real CLI; the SSH server is the suite's own sshd, whose
# authorized_keys file gets the public line the Vault shows; the SSH client is the real ssh.
ssh_key_scenario() {
  local w="$T/sshkey" k=client-a/paas/deploy-key pid line fp sock spid
  mkdir -m 700 "$w"
  local -a sshbase=(-F none -p "$PS" -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$w/known_hosts" -o PreferredAuthentications=publickey -o ConnectTimeout=10)
  local -a sshopts=("${sshbase[@]}" -o IdentityFile=none) # no key file of this account: the agent socket or nothing
  echo "[127.0.0.1]:$PS $(cut -d' ' -f1-2 "$T/sshd/hostkey.pub")" >"$w/known_hosts"
  local dest="$ME@127.0.0.1"
  # The previous scenario left a don't-ask-again rule (and so its env set's bucket) open on
  # purpose; what must hold here is about the key buckets.
  no_key_open() { local o; o=$(owner open-buckets); [[ $o != *signer:* ]] || fail "$1: open buckets: $o"; }

  # An SSH key generated on the broker: the page, the CLI and ssh-keygen agree on its public half.
  owner vault-ssh-key "$k" ssh-ed25519 generate >"$w/key.json" || fail 'creating the SSH key'
  line=$(bun -e 'const k=await Bun.file(process.argv[1]).json(); if(k.handout||k.scheme!=="ssh-ed25519"||!k.authorized_key.startsWith("ssh-ed25519 AAAA")||!k.authorized_key.endsWith(" aqmas:client-a/paas/deploy-key"))process.exit(1); console.log(k.authorized_key)' "$w/key.json") || fail "created key: $(cat "$w/key.json")"
  fp=$(bun -e 'console.log((await Bun.file(process.argv[1]).json()).fingerprint)' "$w/key.json")
  printf '%s\n' "$line" >"$w/key.pub"
  [[ $(ssh-keygen -lf "$w/key.pub" | cut -d' ' -f2) == "$fp" ]] || fail 'the fingerprint is not what ssh-keygen -lf prints'
  [[ $("$AQMAS" ssh-key "$k" --public) == "$line" ]] || fail 'aqmas ssh-key --public and the page disagree'
  "$AQMAS" ls --json | LINE="$line" bun -e 'const s=(await Bun.stdin.json()).credentials.find(x=>x.path===process.argv[1]); if(!s||s.kind!=="ssh-key"||s.public_key!==process.env.LINE||s.handout||!s.use.startsWith("aqmas ssh-agent "))process.exit(1)' "$k" || fail 'the SSH key in aqmas ls'
  "$AQMAS" ls | grep -F "$line" >/dev/null || fail 'aqmas ls (table) does not show the public line'
  owner vault-state | LINE="$line" FP="$fp" bun -e 'const st=await Bun.stdin.json(), s=st.sets.find(s=>s.set_slug==="deploy-key"); if(!s||s.kind!=="ssh-key"||s.authorized_key!==process.env.LINE||s.fingerprint!==process.env.FP||s.handout||st.schemes.some(x=>x.id.startsWith("ssh-")))process.exit(1)' || fail 'state of the new SSH key'
  if "$AQMAS" sign "$k" --why 'not a signer' "$w/key.pub" >/dev/null 2>"$T/sshkey-sign.err"; then fail 'aqmas sign with an SSH key'; fi
  grep -q 'aqmas ssh-agent' "$T/sshkey-sign.err" || fail "aqmas sign with an SSH key: $(cat "$T/sshkey-sign.err")"
  ok 'SSH key generated in aqmas: the page, aqmas ls, aqmas ssh-key --public and ssh-keygen -lf agree on the public line and fingerprint'

  # The server trusts that line. Without aqmas there is no way in; with the agent there is.
  printf '%s\n' "$line" >>"$T/sshd/authorized_keys"
  if SSH_AUTH_SOCK= ssh "${sshopts[@]}" "$dest" true 2>/dev/null; then fail 'ssh without any key was let in'; fi
  "$AQMAS" ssh-agent "$k" --why 'interop: ssh with the deploy key' --ttl 10m --count 6 -- ssh "${sshopts[@]}" "$dest" echo agent-ok </dev/null >"$T/sshkey-1.out" 2>"$T/sshkey-1.err" & pid=$!
  owner vault-sign approve 300 5; wait "$pid" || { cat "$T/sshkey-1.err"; fail 'aqmas ssh-agent -- ssh'; }
  grep -q agent-ok "$T/sshkey-1.out" || fail 'the remote command did not run'
  grep -q "$fp" "$T/sshkey-1.err" && grep -q 'Ref ' "$T/sshkey-1.err" || fail "the CLI did not print the fingerprint and Ref: $(cat "$T/sshkey-1.err")"
  grep -q "Accepted publickey for $ME .* ED25519 $fp" "$T/sshd.log" || fail 'sshd did not log a login with the Vault key'
  [[ $(owner open-buckets) == *"signer:$k"* && $(owner open-buckets | tr ' ' '\n' | grep -c '^signer:') == 1 ]] || fail "an SSH login grant did not open exactly its key: $(owner open-buckets)"
  # Within the grant: no tap, no --why.
  timeout 30 "$AQMAS" ssh-agent "$k" -- ssh "${sshopts[@]}" "$dest" echo again </dev/null >"$T/sshkey-2.out" 2>"$T/sshkey-2.err" || { cat "$T/sshkey-2.err"; fail 'the second aqmas ssh-agent needed a tap'; }
  grep -q again "$T/sshkey-2.out" && grep -q 'using the open SSH login grant' "$T/sshkey-2.err" || fail 'the open grant was not reused'
  owner vault-state | bun -e 'const r=(await Bun.stdin.json()).requests; if(r.length!==1||r[0].use!=="ssh-agent"||r[0].used!==2||r[0].max_signatures!==5||r[0].ttl_seconds!==300||r[0].items.length)process.exit(1)' || fail 'login grant accounting'
  # The command's exit status is the command's.
  local rc=0; timeout 30 "$AQMAS" ssh-agent "$k" -- ssh "${sshopts[@]}" "$dest" 'exit 7' </dev/null 2>/dev/null || rc=$?
  [[ $rc == 7 ]] || fail "exit status through aqmas ssh-agent: $rc"
  ok 'aqmas ssh-agent -- ssh: one passkey approval, then logins within the grant need no tap; sshd logs the Vault key'

  # git over SSH and scp, where they are installed: nothing but SSH_AUTH_SOCK carries the key
  # (GIT_SSH_COMMAND here only points ssh at this sandbox's known_hosts and port options).
  if command -v git >/dev/null; then
    git init -q --bare "$w/origin.git"
    GIT_SSH_COMMAND="ssh ${sshopts[*]}" timeout 60 "$AQMAS" ssh-agent "$k" -- git clone -q "ssh://$dest:$PS$w/origin.git" "$w/clone" </dev/null 2>"$T/sshkey-git.err" || { cat "$T/sshkey-git.err"; fail 'git clone over SSH through aqmas ssh-agent'; }
    (cd "$w/clone" && echo interop >file && git add file && git -c user.name=interop -c user.email=interop@example.com commit -qm one) || fail 'commit in the clone'
    (cd "$w/clone" && GIT_SSH_COMMAND="ssh ${sshopts[*]}" timeout 60 "$AQMAS" ssh-agent "$k" -- git push -q origin HEAD:refs/heads/main </dev/null 2>"$T/sshkey-push.err") || { cat "$T/sshkey-push.err"; fail 'git push over SSH through aqmas ssh-agent'; }
    git --git-dir="$w/origin.git" log --oneline main | grep one >/dev/null || fail 'the push did not arrive'
    ok 'git clone and git push over SSH through aqmas ssh-agent'
  else
    # Spend the same two logins so the accounting below holds.
    for _ in 1 2; do timeout 30 "$AQMAS" ssh-agent "$k" -- ssh "${sshopts[@]}" "$dest" true </dev/null 2>/dev/null || fail 'login under the grant'; done
  fi
  # The fifth login spends the grant; the bucket closes with it.
  owner vault-state | bun -e 'if((await Bun.stdin.json()).requests.length)process.exit(1)' || fail 'a spent login grant is still listed'
  no_key_open 'spent SSH login grant'

  # --socket: a long-running agent for a script. It lists exactly the one key, refuses every
  # other agent operation, and signs logins only (never ssh-keygen -Y sign).
  "$AQMAS" ssh-agent "$k" --why 'interop: a script with several connections' --ttl 10m --socket </dev/null >"$w/socket.out" 2>"$T/sshkey-sock.err" & spid=$!
  PIDS+=("$spid")
  owner vault-sign approve 600 20
  for _ in $(seq 100); do grep -q '^SSH_AUTH_SOCK=/' "$w/socket.out" 2>/dev/null && break; sleep 0.1; done
  sock=$(sed -n 's/^SSH_AUTH_SOCK=//p' "$w/socket.out"); [[ -S $sock ]] || fail "no agent socket: $(cat "$w/socket.out" "$T/sshkey-sock.err")"
  [[ $(stat -c %a "$sock") == 600 && $(stat -c %a "$(dirname "$sock")") == 700 ]] || fail 'the agent socket is not private'
  [[ $(SSH_AUTH_SOCK=$sock ssh-add -L) == "$line" ]] || fail "the agent offers something else: $(SSH_AUTH_SOCK=$sock ssh-add -L 2>&1)"
  SSH_AUTH_SOCK=$sock ssh "${sshopts[@]}" "$dest" echo socket-ok </dev/null >"$T/sshkey-3.out" 2>"$T/sshkey-3.err" || { cat "$T/sshkey-3.err"; fail 'ssh through the served socket'; }
  grep -q socket-ok "$T/sshkey-3.out" || fail 'ssh through the served socket ran nothing'
  ssh-keygen -q -t ed25519 -N '' -f "$w/other" >/dev/null
  if SSH_AUTH_SOCK=$sock ssh-add "$w/other" 2>/dev/null; then fail 'a key was added to the aqmas agent'; fi
  if SSH_AUTH_SOCK=$sock ssh-add -D 2>/dev/null; then fail 'the aqmas agent let its keys be removed'; fi
  echo 'not a login' >"$w/doc"
  if SSH_AUTH_SOCK=$sock ssh-keygen -Y sign -f "$w/key.pub" -n file "$w/doc" 2>"$T/sshkey-ysign.err"; then fail 'the SSH key signed a document (ssh-keygen -Y sign)'; fi
  [[ ! -e $w/doc.sig ]] || fail 'ssh-keygen -Y sign produced a signature'
  owner vault-state | bun -e 'const r=(await Bun.stdin.json()).requests; if(r.length!==1||r[0].used!==1)process.exit(1)' || fail 'a refused agent request reached the broker'
  ok 'aqmas ssh-agent --socket: exactly one key, logins only; add, remove and ssh-keygen -Y sign are refused'

  # The MCP tool runs a command with the key under the open grant.
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"interop","version":"0"}}}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"aqmas_list_credentials","arguments":{}}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"aqmas_with_ssh_key\",\"arguments\":{\"path\":\"$k\",\"why\":\"interop: MCP with the deploy key\",\"command\":$(bun -e 'console.log(JSON.stringify(process.argv.slice(1)))' ssh "${sshopts[@]}" "$dest" echo mcp-ok)}}}" \
    | "$AQMAS" mcp >"$T/sshkey-mcp.out" 2>"$T/sshkey-mcp.err" || { cat "$T/sshkey-mcp.err"; fail 'aqmas mcp with an SSH key'; }
  LINE="$line" K="$k" bun -e 'const by={}; for (const l of (await Bun.file(process.argv[1]).text()).trim().split("\n")) { const m=JSON.parse(l); if(m.id!==undefined)by[m.id]=m }
    const text=(id)=>{ if(by[id].error||by[id].result.isError)throw Error(JSON.stringify(by[id])); return by[id].result.content[0].text };
    if(!JSON.parse(text(2)).credentials.some(c=>c.path===process.env.K&&c.kind==="ssh-key"&&c.public_key===process.env.LINE))process.exit(2);
    const run=JSON.parse(text(3)); if(run.exit_code!==0||run.stdout.trim()!=="mcp-ok")process.exit(3);' "$T/sshkey-mcp.out" || fail "MCP with an SSH key: $(cat "$T/sshkey-mcp.out")"
  ok 'MCP: aqmas_list_credentials shows the public line; aqmas_with_ssh_key runs ssh with the key'

  # An ECDSA P-256 key generated in aqmas logs in the same way.
  local ec=client-a/paas/ec-key ecline ecfp
  owner vault-ssh-key "$ec" ssh-ecdsa-p256 generate >"$w/ec.json" || fail 'creating the ECDSA SSH key'
  ecline=$(bun -e 'const k=await Bun.file(process.argv[1]).json(); if(!k.authorized_key.startsWith("ecdsa-sha2-nistp256 "))process.exit(1); console.log(k.authorized_key)' "$w/ec.json") || fail "ECDSA key: $(cat "$w/ec.json")"
  ecfp=$(bun -e 'console.log((await Bun.file(process.argv[1]).json()).fingerprint)' "$w/ec.json")
  printf '%s\n' "$ecline" >"$w/ec.pub"; [[ $(ssh-keygen -lf "$w/ec.pub" | cut -d' ' -f2) == "$ecfp" ]] || fail 'ECDSA fingerprint is not what ssh-keygen -lf prints'
  printf '%s\n' "$ecline" >>"$T/sshd/authorized_keys"
  "$AQMAS" ssh-agent "$ec" --why 'interop: ssh with an ECDSA key' --ttl 5m --count 1 -- ssh "${sshopts[@]}" "$dest" echo ec-ok </dev/null >"$T/sshkey-ec.out" 2>"$T/sshkey-ec.err" & pid=$!
  owner vault-sign approve 300 1; wait "$pid" || { cat "$T/sshkey-ec.err"; fail 'aqmas ssh-agent -- ssh with an ECDSA key'; }
  grep -q ec-ok "$T/sshkey-ec.out" && grep -q "Accepted publickey for $ME .* ECDSA $ecfp" "$T/sshd.log" || fail 'sshd did not log a login with the ECDSA Vault key'
  ok 'an ECDSA P-256 SSH key generated in aqmas logs in to the real sshd through aqmas ssh-agent'

  # Hand-out is off unless the owner allows it for this key.
  if "$AQMAS" ssh-key "$k" --why 'interop: wants the key file' --out "$w/handed" </dev/null >/dev/null 2>"$T/sshkey-ho0.err"; then fail 'a key that may not be handed out was handed out'; fi
  grep -q "aqmas ssh-agent $k" "$T/sshkey-ho0.err" && [[ ! -e $w/handed ]] || fail "hand-out refusal: $(cat "$T/sshkey-ho0.err")"

  # Delete: one tap; from then on the key does not exist for the host, and the open socket's
  # next login is refused. The bin lists it; restore brings the key back, not the grant.
  owner vault-delete "$k" >"$w/deleted.json" || fail 'deleting the SSH key'
  bun -e 'const d=await Bun.file(process.argv[1]).json(); if(!d.ok||d.ended.grants!==1||d.purge_at-Date.now()<6.9*86400e3||d.purge_at-Date.now()>7.1*86400e3)process.exit(1)' "$w/deleted.json" || fail "delete result: $(cat "$w/deleted.json")"
  no_key_open 'deleted SSH key'
  if "$AQMAS" ssh-agent "$k" --why 'interop: deleted' -- true </dev/null >/dev/null 2>"$T/sshkey-del.err"; then fail 'aqmas ssh-agent with a deleted key'; fi
  grep -q 'not_found' "$T/sshkey-del.err" || fail "a deleted key: $(cat "$T/sshkey-del.err")"
  if "$AQMAS" ssh-key "$k" --public >/dev/null 2>&1; then fail 'the public line of a deleted key'; fi
  if "$AQMAS" ssh-agent client-a/paas/never-existed --why x -- true </dev/null >/dev/null 2>"$T/sshkey-never.err"; then fail 'a key that never existed'; fi
  [[ $(sed "s#$k#PATH#g" "$T/sshkey-del.err") == "$(sed 's#client-a/paas/never-existed#PATH#g' "$T/sshkey-never.err")" ]] || fail 'a deleted key answers differently from one that never existed'
  if SSH_AUTH_SOCK=$sock ssh "${sshopts[@]}" "$dest" true </dev/null 2>/dev/null; then fail 'the agent socket signed a login after the key was deleted'; fi
  grep -q 'the SSH login grant for .* is over' "$T/sshkey-sock.err" || fail "the agent did not say why: $(cat "$T/sshkey-sock.err")"
  "$AQMAS" ls --json | bun -e 'if((await Bun.stdin.json()).credentials.some(x=>x.path===process.argv[1]))process.exit(1)' "$k" || fail 'aqmas ls lists a deleted key'
  owner vault-state | FP="$fp" bun -e 'const st=await Bun.stdin.json(), d=st.deleted; if(st.sets.some(s=>s.set_slug==="deploy-key")||st.requests.length||d.length!==1||d[0].kind!=="ssh-key"||d[0].set_slug!=="deploy-key"||d[0].fingerprint!==process.env.FP||!d[0].deleted_by||d[0].purge_at-d[0].deleted_at!==604800000||!/^[0-9a-f]{64}$/.test(d[0].digest)||d[0].path_taken)process.exit(1)' || fail 'the bin after the delete'
  ok 'delete: the key is not_found for the host like one that never existed, its grant is gone, the open socket signs nothing; the bin lists it'

  owner vault-restore "$k" || fail 'restoring the SSH key'
  [[ $("$AQMAS" ssh-key "$k" --public) == "$line" ]] || fail 'the restored key has another public line'
  if SSH_AUTH_SOCK=$sock ssh "${sshopts[@]}" "$dest" true </dev/null 2>/dev/null; then fail 'the old grant came back with the restore'; fi
  kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null || true
  [[ ! -e $sock ]] || fail 'the agent socket was left behind'
  "$AQMAS" ssh-agent "$k" --why 'interop: after restore' --ttl 5m --count 1 -- ssh "${sshopts[@]}" "$dest" echo restored-ok </dev/null >"$T/sshkey-4.out" 2>"$T/sshkey-4.err" & pid=$!
  owner vault-sign approve 300 1; wait "$pid" || { cat "$T/sshkey-4.err"; fail 'aqmas ssh-agent after restore'; }
  grep -q restored-ok "$T/sshkey-4.out" || fail 'login with the restored key'
  owner vault-state | bun -e 'const st=await Bun.stdin.json(); if(st.deleted.length||st.requests.length)process.exit(1)' || fail 'state after restore'
  ok 'restore: the same key, usable again after a new approval; nothing that was live came back'

  # Hand-out, once the owner allows it: a red card, one delivery, a 0600 file that is the key.
  owner vault-ssh-handout "$k" on || fail 'allowing hand-out'
  "$AQMAS" ls --json | bun -e 'if(!(await Bun.stdin.json()).credentials.find(x=>x.path===process.argv[1]).handout)process.exit(1)' "$k" || fail 'aqmas ls does not say the key may be handed out'
  (umask 022; "$AQMAS" ssh-key "$k" --why 'interop: a tool that reads a key file' --out "$w/handed" </dev/null >"$T/sshkey-ho.out" 2>"$T/sshkey-ho.err") & pid=$!
  owner vault-sign approve; wait "$pid" || { cat "$T/sshkey-ho.err"; fail 'aqmas ssh-key (hand-out)'; }
  [[ $(stat -c %a "$w/handed") == 600 && $(cat "$w/handed.pub") == "$line" && $(ssh-keygen -y -f "$w/handed") == "$line" ]] || fail 'the handed-out file is not the key, or not private'
  grep -q "ssh -i $w/handed" "$T/sshkey-ho.out" && grep -q GIT_SSH_COMMAND "$T/sshkey-ho.out" && grep -q 'cannot recall it' "$T/sshkey-ho.err" || fail "hand-out output: $(cat "$T/sshkey-ho.out" "$T/sshkey-ho.err")"
  if grep -q 'PRIVATE KEY' "$T/sshkey-ho.out" "$T/sshkey-ho.err"; then fail 'the private key was printed'; fi
  SSH_AUTH_SOCK= ssh "${sshbase[@]}" -o IdentityFile="$w/handed" -o IdentitiesOnly=yes "$dest" echo file-ok </dev/null >"$T/sshkey-5.out" 2>"$T/sshkey-5.err" || { cat "$T/sshkey-5.err"; fail 'ssh -i with the handed-out key'; }
  if "$AQMAS" ssh-key "$k" --why 'again' --out "$w/handed" </dev/null >/dev/null 2>"$T/sshkey-ho2.err"; then fail 'overwrote the key file without --force'; fi
  no_key_open 'collected hand-out'
  ok 'hand-out: refused while off; once the owner allows it, one approval writes the key 0600 with its .pub, and ssh -i works'

  # Purge now: gone for good, bucket included; the path is free, here for the same key pasted back.
  owner vault-delete "$k" >/dev/null || fail 'deleting the SSH key again'
  owner vault-purge "$k" || fail 'purging the SSH key'
  owner vault-state | bun -e 'const st=await Bun.stdin.json(); if(st.deleted.length||st.sets.some(s=>s.set_slug==="deploy-key"))process.exit(1)' || fail 'state after purge'
  if owner vault-restore "$k" 2>/dev/null; then fail 'restore after purge'; fi
  owner vault-ssh-key "$k" ssh-ed25519 import "$w/handed" >"$w/key2.json" || fail 'pasting an OpenSSH private key'
  [[ $(bun -e 'console.log((await Bun.file(process.argv[1]).json()).authorized_key)' "$w/key2.json") == "$line" ]] || fail 'the pasted key has another public line'
  "$AQMAS" ssh-agent "$k" --why 'interop: the pasted key' --ttl 5m --count 1 -- ssh "${sshopts[@]}" "$dest" echo pasted-ok </dev/null >"$T/sshkey-6.out" 2>"$T/sshkey-6.err" & pid=$!
  owner vault-sign approve 300 1; wait "$pid" || { cat "$T/sshkey-6.err"; fail 'aqmas ssh-agent with a pasted key'; }
  grep -q pasted-ok "$T/sshkey-6.out" || fail 'login with the pasted key'
  ok 'purge now: nothing left to restore, the path is free; a pasted OpenSSH key gives the same public line and logs in'

  # A deleted secret: not_found, its don't-ask-again rule over. It stays in the bin: the
  # recovery and backup checks later in this run meet a store with a binned item.
  local s=client-a/paas/old-token; printf 'binned-%s' "$(openssl rand -hex 12)" >"$w/old"
  owner vault-secret "$s" OLD_TOKEN "$w/old" >/dev/null || fail 'creating a secret to delete'
  "$AQMAS" run "$s" --why 'interop: before the delete' -- true </dev/null >/dev/null 2>"$T/sshkey-old.err" & pid=$!
  owner env-decide approve process 3600; wait "$pid" || fail 'run before the delete'
  owner vault-delete "$s" | bun -e 'const d=await Bun.stdin.json(); if(d.ended.standing!==1)process.exit(1)' || fail 'the delete did not end the rule'
  if "$AQMAS" run "$s" --why 'interop: deleted' -- true </dev/null >/dev/null 2>"$T/sshkey-old2.err"; then fail 'aqmas run with a deleted secret'; fi
  grep -q 'not_found' "$T/sshkey-old2.err" || fail "a deleted secret: $(cat "$T/sshkey-old2.err")"
  owner env-state | bun -e 'if((await Bun.stdin.json()).standing.some(s=>s.path===process.argv[1]))process.exit(1)' "$s" || fail 'a rule survived the delete'
  owner vault-state | bun -e 'const d=(await Bun.stdin.json()).deleted; if(d.length!==1||d[0].kind!=="secret"||d[0].names.join()!=="OLD_TOKEN")process.exit(1)' || fail 'the bin after deleting a secret'

  # No private key and no value outside the sealed store and the one file the owner allowed.
  local body; body=$(sed -n 4p "$w/handed")
  if grep -aFl -e "$body" -e "$(cat "$w/old")" "$T/data/aqmas.db" "$T/data/aqmas.db-wal" "$T"/sshkey-*.out "$T"/sshkey-*.err "$T"/seal-*.log "$w/key.json" "$w/key2.json" 2>/dev/null; then fail 'an SSH private key or a deleted value leaked'; fi
  ok 'a deleted secret is not_found and its rule is over; it stays in the bin for the recovery checks; sentinel scan'
}
