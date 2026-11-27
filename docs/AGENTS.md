# aqmas for agents

This is the guide for an AI agent (or a script) working on a host that is enrolled with
agent-quartermaster. `aqmas guide` prints this text for the installed version;
`aqmas help` is the short command reference; `aqmas guide --json` is a machine-readable
summary of the commands.

## What aqmas is

aqmas is a credential broker. A server (`aqmasd`) on a separate bastion holds the
credentials: an SSH certificate authority, SSH keys, API tokens, signing keys, environment
values. This host holds none of them. When you need access you ask with the `aqmas` CLI (or
its MCP server), the owner approves on their phone or laptop with a passkey, and you get
something short-lived: an SSH certificate, a command run with a secret in its environment,
a signature, SSH logins with a key that stays in aqmas, a time-boxed API grant.

**The rule: do not look for long-lived credentials on this host, do not ask the owner to
paste one, and do not store one you were handed.** Ask aqmas each time. If aqmas does not
hold what you need, say so to the owner; they can add it in the Vault tab of the approval
page.

## How an approval works

1. You run a command with `--why "..."`.
2. aqmas prints a line with a **Ref** (six characters) and waits. The owner gets a
   notification and sees a card with the same Ref, what is asked for, which host asks, and
   your `--why` text marked as unverified.
3. The owner taps their passkey to approve or deny. The command continues, or fails with
   exit code 3 (denied) or 4 (nobody decided in time, usually ten minutes).

So:

- **Requests block.** Run them in the foreground and wait. Do not retry in a loop: every
  retry is another card on the owner's phone. A host may have five requests pending.
- **`--why` is for a person.** Say what you are about to do and for which task, in one
  honest, specific sentence: `--why "restart the nightly export job that failed at 02:10"`,
  not `--why "access"`. It is required whenever stdin is not a terminal. Never put a
  secret in it; it is logged.
- **Ask for what the task needs.** The shortest `--ttl` that covers the work; the one
  target; the one set.
- Ctrl-C (or a cancelled tool call) withdraws a pending request.
- Some things need no tap: a cached SSH certificate that is still valid, an SSH target the
  owner gave an auto-approval for, the Cloudflare scopes the owner marked automatic.
  Environment values, secrets and signatures always need a tap (or, for signing and for SSH
  logins with a key, a time-boxed grant the owner approved once).

## Is this host set up?

```sh
aqmas status          # enrolment, server, cached certificates
aqmas ls              # what this host may ask for (if the owner allows listing)
aqmas targets         # SSH targets this host may use (same condition)
aqmas list            # this host's active grants on the server
```

- "not enrolled": the owner has to run the install-and-enroll command from the approval
  page's Help tab on this machine. You cannot enroll by yourself; enrolment is approved
  with a passkey.
- `not_admitted` ("enrolled but not admitted to an organisation"): the host is known but
  the owner has not let it ask for anything. Ask the owner to admit it (Hosts tab), then
  run the command again.

## Finding what exists

Credentials are named `organisation/service/set`, for example `acme/billing/staging-env`.
SSH targets have plain names such as `web-1`.

```sh
aqmas ls              # PATH, KIND, what it holds (key names, never values), how to use it
aqmas ls --json
aqmas targets         # NAME, ADDRESS, PORT, USERS
aqmas targets --json
```

Listing is an owner setting per organisation ("Hosts may list what they can ask for"),
off by default. When it is off, `aqmas ls` says so and lists nothing: that does not mean
nothing exists. Ask the owner for the path, or to turn listing on. A path you cannot see,
a path that does not exist and an item the owner deleted give the same `not_found`; aqmas
never tells them apart.

Kinds:

| Kind | What it is | Use it with |
|---|---|---|
| `secret` | one value with an environment variable name, e.g. an API key | `aqmas run`, `aqmas get` |
| `env-set` | several named values | `aqmas run`, `aqmas checkout` |
| `signer` | a private key that never leaves aqmas | `aqmas sign` |
| `ssh-key` | an SSH key pair; `aqmas ls` shows its public `authorized_keys` line | `aqmas ssh-agent` (the key stays in aqmas); `aqmas ssh-key` only where the owner allows hand-out |
| `cloudflare-proxy`, `cloudflare-mint` | Cloudflare API access by scope | `aqmas cf ...` |
| SSH target | a machine this host may log in to | `aqmas ssh`, `aqmas mosh`, `aqmas cert` |

## Commands

### SSH to another machine

```sh
aqmas ssh alice@web-1 --why "check why nginx fails to reload" -- systemctl status nginx
aqmas ssh web-1 --ttl 30m --why "deploy release 1.4.2"         # interactive shell
aqmas mosh alice@web-1 --why "long maintenance session"
aqmas cert alice@web-1 --why "rsync the build output"          # only fetch the certificate
```

The certificate is cached and reused while it has two minutes left, so the second command
within the TTL needs no approval. `aqmas cert` prints the key, certificate and known_hosts
paths for tools such as `rsync -e` or `scp`; `aqmas ssh-config HOST` prints an opt-in
`~/.ssh/config` snippet. Use the target's name from `aqmas targets`, not an IP address of
your own choosing. Put the remote command after `--`.

### Run a command with a secret or an env set

```sh
aqmas run acme/infra/tailnet-api-key --why "list devices for the inventory report" -- ./inventory.sh
aqmas run acme/billing/staging-env --why "run the pending migration" -- bin/migrate
aqmas run acme/infra/tailnet-api-key --env TS_API_KEY --why "..." -- tool    # another variable name
```

This is the normal way to use a credential. The command is started directly (no shell)
with the values in its environment and a small inherited environment (`HOME`, `PATH`,
`USER`, `LANG`, `TMPDIR`, `TERM`). For shell syntax, run a shell: `-- sh -c 'curl -H
"Authorization: Bearer $TAILNET_API_KEY" https://api.example.com/devices'` (single quotes,
so your own shell does not expand the variable first). The exit status is the command's.
`--env NAME` renames the variable of a secret or a one-key set. aqmas refuses to replace a
variable that is already set in your environment.

Each `run` is one approval and one delivery. If you need the value for several commands,
put them in one script and run that. The owner can also choose "don't ask again" when
approving: for a while (an hour, up to a day for a low-risk key) the same request from this
host is approved without a tap. You cannot ask for that and you do not need to know whether
it is in force: run the command the same way each time, with an honest `--why`; it either
returns at once or waits for the owner. A rule covers one kind of use, so `aqmas get` after
an approved `aqmas run` asks again.

### Get a secret's value

```sh
TOKEN=$(aqmas get acme/infra/tailnet-api-key --why "configure the exporter's token file")
```

`aqmas get` prints one secret's value to stdout. Prefer `aqmas run`: with `get` the value
is in your process and has left aqmas, and the approval card tells the owner exactly that.
Use it only when a tool cannot take the value from its environment. Do not echo it, do not
write it to a file that outlives the task, do not put it in a command line (other users can
read those), and never paste it into a message, a commit, a log or a knowledge base. The
owner can turn `get` off for an organisation; then the request is refused and `run` is the
way.

### Files and shells that need the values

```sh
aqmas checkout acme/billing/staging-env --why "start the dev server" --file .env   # RAM-backed .env
aqmas checkin acme/billing/staging-env                                               # remove it
eval "$(aqmas checkout-shell acme/billing/staging-env --why "...")"                 # exports, Bash only
eval "$(aqmas checkin-shell acme/billing/staging-env)"
```

`checkout` links a `.env` file that lives on a RAM-backed filesystem and disappears at
check-in or expiry; a secret is written as `NAME=value`. Check in when you are done.

### Sign something

```sh
aqmas sign acme/releases/firmware-key --why "sign release 1.4.2" firmware.bin     # writes firmware.bin.sig
aqmas sign acme/releases/firmware-key --why "..." --digest sha256:HEX              # prints the signature
aqmas signer acme/releases/firmware-key --pem                                      # the public key
```

**Prefer `sign` over fetching keys.** A signing key in a `signer` set cannot be delivered
at all: files are hashed on this host, the owner approves the names and digests, aqmas
signs. If a signing key sits in an env set instead, tell the owner it could be a signer.
`--ttl 30m --count 20` asks for a grant that later `sign` calls reuse; `aqmas sign PATH
--end` ends it.

### Use an SSH key with a forge

For a host you reach with a plain SSH key instead of an aqmas certificate: a Git forge
(a user key or a deploy key), or a server that is not an aqmas target. The owner creates
the key in the Vault and puts its public line on the forge or in the server's
`~/.ssh/authorized_keys`. You never need the private half:

```sh
aqmas ssh-agent acme/forge/deploy-key --why "clone the app repository for the build" -- git clone ssh://git@forge.example.com/acme/app.git
aqmas ssh-agent acme/forge/deploy-key --why "push the release branch" --ttl 30m -- git push origin release
aqmas ssh-agent acme/forge/deploy-key --why "..." -- ssh -o BatchMode=yes deploy@build.example.com uptime
aqmas ssh-agent acme/forge/deploy-key --why "..." -- rsync -e ssh -a out/ deploy@build.example.com:/srv/out/
aqmas ssh-key acme/forge/deploy-key --public       # the authorized_keys line (no approval)
aqmas ssh-agent acme/forge/deploy-key --end        # give the grant back early
```

`aqmas ssh-agent PATH --why "..." -- COMMAND` runs COMMAND with `SSH_AUTH_SOCK` pointing at
a private agent socket that offers exactly that one key. Whatever speaks SSH underneath
(`git`, `ssh`, `scp`, `sftp`, `rsync -e ssh`) uses it without further options;
`GIT_SSH_COMMAND` and `-i` are not needed. Each login's signature is made by aqmas. The
exit status is the command's.

- One approval is a grant: `--ttl` (default 10 minutes, at most 24 hours) and `--count`
  logins (default 20). Later `aqmas ssh-agent` calls for the same key on this host reuse it
  without a tap and without `--why`, until it runs out, expires or the owner revokes it.
  For several commands, either run them one after the other like this or put them in one
  script and run that.
- It signs SSH logins with that key and nothing else. It is not a general SSH agent: no
  keys can be added, and `ssh-keygen -Y sign`, Git commit signing with the key or agent
  forwarding tricks are refused.
- Use the forge's host name, and the host key you already trust: aqmas does not manage
  `known_hosts` for these hosts. If the host key is unknown, tell the owner rather than
  turning host key checking off.
- For a script that makes many SSH connections, `aqmas ssh-agent PATH --why "..." --socket`
  serves the agent in the foreground and prints `SSH_AUTH_SOCK=/path`; start it in the
  background, read that line, export the variable, and stop the process when done.
- If a login fails with "the SSH login grant ... is over", run the command again: it asks
  anew. If the path answers `not_found`, the key was deleted or this host may not see it.

**Hand-out, only when the agent cannot be used.** Some tools insist on a key file. If the
owner marked the key "may be handed out" (`aqmas ls` says so), then

```sh
aqmas ssh-key acme/forge/deploy-key --why "the backup tool only reads a key file" --out ~/.ssh/backup_key
```

asks with a red card and, once approved, writes the private key (mode 0600) and
`FILE.pub`, and prints the `ssh -i` and `GIT_SSH_COMMAND` forms to use. From then on the
key is a file on this host and aqmas cannot recall it: delete it when the task is done and
never copy it elsewhere. Every hand-out is its own approval. For a key without that setting
the command is refused before the owner is asked; use `aqmas ssh-agent`.

### Cloudflare

```sh
aqmas cf scopes                                    # what can be asked for, and the names to use
aqmas cf api GET /zones                            # one call; a GET with no grant asks for cf.read
aqmas cf request cf.dns.edit zone=example.com --ttl 1h --why "add the TXT record for the new mail host"
aqmas cf env --request cf.workers.deploy script=api --why "deploy the api worker" -- wrangler deploy
```

The Cloudflare token stays in aqmas; calls go through its proxy under a scope and guard
rails. `aqmas cf help` has the rest.

### The bastion itself

```sh
aqmas bastion                                        # what this host may ask for there
aqmas ssh BASTION --why "why did the broker restart?" -- logs aqmasd since=2h
aqmas bastion task disk-usage --why "the disk alert fired"
```

Agents do not work on the bastion. The read-only inspect commands and the routine
maintenance tasks above exist so that you never need a shell there.

## Exit codes and what to do

| Code | Meaning | What to do |
|---|---|---|
| 0 | ok (or the exit status of the command you ran) | |
| 1 | error | read the message |
| 2 | usage | fix the command; `aqmas help` |
| 3 | denied, or refused by a guard rail | **stop.** Do not rephrase and retry. Tell the owner what you wanted and why |
| 4 | expired: nobody decided in time | the owner is probably away. Ask once more only if the task is worth another notification; otherwise report and continue with something else |
| 5 | server unreachable or TLS failure | the bastion or the network is down. Do not look for another way in; report it. Cached SSH certificates keep working until they expire |
| 130 | cancelled | |

Messages you may see:

- `not_admitted`: this host has no admission. Ask the owner to admit it.
- `not_found`: no such path or target *for this host*. Check the spelling with `aqmas ls`
  or `aqmas targets`, or ask the owner for the path. An item the owner deleted answers the
  same way from that moment, and everything that was open for it (grants, releases waiting
  to be collected, "don't ask again") has ended: do not retry, ask the owner.
- "waiting for the owner to reopen ...": the credential's bucket is closed (for example
  after the bastion restarted). The request is fine; the owner needs one more tap.
- "refusing to replace inherited NAME": that variable is already set in your environment;
  unset it or use `--env`.
- `rate_limited`: too many pending requests. Wait for the owner; do not add more.
- "revision changed": the owner edited the set while you were asking. Run the command again.

## Using aqmas from an MCP client

`aqmas mcp` is an MCP server on stdin/stdout. Register it once:

```sh
claude mcp add aqmas -- aqmas mcp
```

or, for any client that reads an `mcpServers` map:

```json
{ "mcpServers": { "aqmas": { "command": "aqmas", "args": ["mcp"] } } }
```

Tools: `aqmas_guide` (this text), `aqmas_status`, `aqmas_list_credentials`,
`aqmas_list_targets`, `aqmas_run`, `aqmas_sign`, `aqmas_with_ssh_key`, `aqmas_ssh_exec`,
`aqmas_store_env`.
The tools that need the owner (`aqmas_run`, `aqmas_sign`, `aqmas_with_ssh_key`,
`aqmas_ssh_exec`) **block until the owner decides** or
the tool's `approval_timeout_seconds` passes; they take a required `why`. There is no tool
that returns a secret's value: `aqmas_run` runs your command with the value in its
environment and returns the exit code and output. If your command prints the secret, the
output contains it, so do not print it. `aqmas_with_ssh_key` runs your command with an SSH
key through the agent socket described above (`aqmas_list_credentials` shows the key's
public line); no tool hands out a private key.

The CLI and the MCP server do the same things with the same approvals; use whichever your
harness makes easier.

## What aqmas does not protect against

The owner's approval is for this host, not for one process on it: anything running as your
user can use the same enrolment. The delivery modes are about accidents, not about a hostile
process: a command started by `aqmas run` can print its environment, so turning `aqmas get`
off, or approving `run` rather than `get`, does not keep the value from a host that wants
it. What limits a host is which organisations admit it and what the owner approves. A value delivered by `run`, `get` or `checkout` is in a
process on this host from then on, a handed-out SSH key is a file on it, and a certificate
works until it expires even if the grant is revoked. An SSH login grant lets anything
running as your user log in with that key until it runs out; the key itself stays in aqmas. That is why requests should be narrow, short and honestly described.
