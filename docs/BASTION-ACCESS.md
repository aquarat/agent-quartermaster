# Access to the bastion itself

**Design note · 2026-11-23 · for independent review before implementation.** The bastion that
runs `aqmasd` accepts only the owner's emergency key ([DESIGN.md](DESIGN.md)); agents cannot
log in. In practice the bastion needs maintenance: logs to read, packages to update, a service
to restart. This adds three controlled ways in, all approved with a passkey:

| Way in | Who lands where | Card | Approval |
|---|---|---|---|
| **Inspect** | `aqmas-inspect`, a locked-down account that can only run a fixed set of read-only commands | amber (normal) | one tap, default 1 h |
| **Root** | the owner's admin account, which has sudo | **red** | always a fresh tap, at most 1 h, allowlisted hosts only |
| **Routine task** | nobody logs in: the root maintenance runner runs a compiled-in task | normal Setup card | one tap by a pinned passkey |

Owner's stance: convenience is a legitimate trade-off, or the thing will not be used. The root
rules below are deliberate and are not relaxed for convenience.

## 1. Threat model and what changes

Today a compromised agent host cannot reach the bastion at all. After "Allow aqmas access to
the bastion" has run, the bastion's sshd trusts the aqmas SSH user CA for two principals. That
is new attack surface, bounded as follows.

* **The SSH CA can now mint a bastion login.** Whoever can sign with the CA can become the
  admin account. In a sealed store the CA key is in a bucket that only a passkey tap opens, and
  only for the instant of signing unless a standing rule or window holds it. While the CA
  bucket is open, a *broker bug* that signs the wrong principal is a bastion compromise. A
  broker compromise was already total for everything except what is sealed and closed; with
  this feature it can also wait for the next tap that opens the CA and mint itself a root
  login, which then reads whatever is opened later. This is the cost of the feature, and why it
  is off until the owner runs the Setup task, and removable.
* **A root session is equivalent to approving everything for its duration.** Root on the
  bastion can read every open bucket from the broker's memory, wait for others to be opened,
  replace `aqmasd`, replace the runner's pinned passkeys and mint certificates for the fleet.
  No rule in the broker constrains a root shell. The design therefore concentrates on making
  the approval unmistakable, rare, short, attributable and loud, not on constraining the shell.
* **Inspect must not be a stepping stone.** The inspect account gets no shell: sshd forces
  every session into `aqmasd inspect`, which runs a compiled-in allowlist of commands with
  fixed arguments. It cannot read `/var/lib/aqmas`, `/etc/aqmas`, the spool or CA material
  (ordinary file permissions: it is in no group that can), cannot forward ports (so it cannot
  reach the web listener on `127.0.0.1` or the agent API from inside), has no password, no
  `authorized_keys` and no sudo.
* **Emergency keys are untouched.** Everything here is additive (`AuthorizedPrincipalsFile`
  only affects certificate logins). When aqmas is down, the emergency key remains the way in.
* **Not addressed:** an issued SSH certificate cannot be recalled (no KRL yet), and sshd cannot
  enforce "one login per certificate". "Single-use" below means the broker hands the
  certificate out once and the CLI never caches it; a hostile requester that received it can
  log in more than once from the same source address until it expires. Hence the 1 h cap and
  the allowlist.

## 2. Configuration

Bastion access exists only while the root-owned configuration has a `[bastion]` table. The
Setup task writes it; nothing in a request can.

```toml
[bastion]
name       = "bastion"                 # what agents type: aqmas ssh bastion; principals <user>@<name>
address    = "192.0.2.10"              # where fleet hosts reach this machine's sshd
port       = 22
admin_user = "alice"                   # the owner's account here (has sudo)
host_key   = "ssh-ed25519 AAAA…"       # this machine's own host key, read by the runner
```

The inspect account's name is the constant `aqmas-inspect`. Validation: `name` may not be a
`[[targets]]` name or alias, no target may issue the principals `<admin_user>@<name>` or
`aqmas-inspect@<name>`, `admin_user` may not be `root`, the broker's account, the build
account or the inspect account. The table is **not** part of the personal catalogue's
configuration fingerprint: the bastion is deliberately not a catalogue set (see §4, last
paragraph), so adding or removing it does not need a new cutover review.

## 3. Host trust on the bastion (Setup tasks)

`deploy/hosts/install-host-trust.sh` refuses hosts the site policy lists (the example policy
lists the bastion) and stays that way for every manual use. It gains `--bastion-self`, used
only by the maintenance runner: the refuse rules are skipped for this one run, and it must be
combined with `--inspect-user`, which also installs the forced-command block. The public
repository names no real host: the policy file remains the place where a site names its own.

**"Allow aqmas access to the bastion"** (`bastion-access`; runner, root, fixed). Signed
parameters: `{"name","address","port","admin_user","ssh_ca"}` where `ssh_ca` is the SHA-256
fingerprint of the SSH user CA, shown on the card. The runner:

1. checks `admin_user` is an existing non-system account (uid ≥ 1000) and none of the reserved
   names;
2. reads `<data_dir>/ca/ssh_user_ca.pub` (a directory the broker owns, so read without
   following links) and continues only if it is one Ed25519 key with the **signed**
   fingerprint: a broker that swapped the file cannot get another CA trusted;
3. creates the system account `aqmas-inspect` if missing (`useradd --system`, home
   `/var/lib/aqmas-inspect`, shell `/bin/sh` because sshd runs a forced command through the
   shell, password locked, supplementary group `systemd-journal` only) and refuses to continue
   if an existing account of that name has any other group, a uid ≥ 1000, or uid 0;
4. runs the embedded host-trust installer for the two accounts. It writes
   `/etc/ssh/aqmas_user_ca.pub`, `/etc/ssh/aqmas_principals/<admin_user>` (`<admin_user>@<name>`),
   `/etc/ssh/aqmas_principals/aqmas-inspect` (`aqmas-inspect@<name>`),
   `/etc/ssh/sshd_config.d/10-aqmas.conf` (as on fleet hosts) and
   `/etc/ssh/sshd_config.d/90-aqmas-inspect.conf`:

   ```
   Match User aqmas-inspect
       ForceCommand /usr/local/bin/aqmasd inspect
       AuthorizedKeysFile none
       PasswordAuthentication no
       KbdInteractiveAuthentication no
       PermitTTY no
       AllowTcpForwarding no
       AllowStreamLocalForwarding no
       AllowAgentForwarding no
       X11Forwarding no
       PermitTunnel no
       PermitUserRC no
   ```

   backs up what it replaces, validates with `sshd -t`, checks with `sshd -T -C user=…` that
   both accounts see the CA and principals file, that the inspect account sees the forced
   command and no forwarding, and that the admin account does **not** see a forced command;
   restores the backup on any failed check; reloads sshd and waits for its port;
5. backs up the configuration, adds `[bastion]` (the edit is proved by re-parsing: old
   configuration plus exactly this table), restarts the broker and checks health. On failure
   the configuration is restored, the broker restarted and the trust files removed again.

A broker restart closes every bucket and window; the card says so. Reversible: yes, by the
next task. Other accounts on the bastion gain nothing: without a principals file a certificate
login is refused, and root has none.

**"Remove aqmas access to the bastion"** (`bastion-access-remove`, no parameters): removes the
`[bastion]` table, restarts the broker, uninstalls the trust files (only files the installer
wrote), ends the inspect account's sessions and deletes the account. A root session that is
already open is an ordinary login of the admin account and is not killed; the card says so.

## 4. Requests and approvals

A bastion session is its own request **kind** (`bastion`), not an SSH target. Reasons: after
the cutover to organisations the configuration fingerprint pins `[[targets]]`, so a new
target cannot be added without a fresh cutover; and a separate kind is invisible to every
silent-approval path by construction (standing rules, policy auto, batches and windows only
ever match kinds `ssh` and `cloudflare` and require an organisation binding, which a bastion
request does not have).

Agent API (mTLS, enrolled host admitted to the personal organisation):

* `GET /v1/bastion` → `{name, address, port, inspect_user, admin_user, root_allowed, inspect_max_seconds, root_max_seconds}`
  (404 while there is no `[bastion]` table).
* `POST /v1/bastion/requests {level, public_key, reason, ttl_seconds, requester}` → the usual
  `RequestCreated`. `level` is `inspect` or `root`. The login user is derived from the level,
  never taken from the request. `reason` is required. Level `root` from a host that is not on
  the allowlist is refused here (403), before anything is queued or notified.
* `GET /v1/bastion/requests/{id}` (long-poll) and `POST …/cancel`, as for other requests.

Stored in `requests` with `kind='bastion'`, `target_host=<name>`, `login_user`, `principal`,
address and port from the configuration. The shared per-host pending limit applies.

### Inspect

Normal card. TTL: default 1 h, at most the SSH maximum of the host's class. One tap; no
standing rule (the canonical key set has no standing field, so none can be signed). The
certificate is delivered like any SSH grant and the CLI caches and reuses it until it expires,
so an agent that reads logs repeatedly within the hour costs one tap. The certificate carries
`source-address` and **no** extensions (no pty, no forwarding); the principal is
`aqmas-inspect@<name>`.

Deviation from the approved outline, for the owner to decide: inspect requests are **not**
covered by approval windows or batches in this version. Both mechanisms are built on the
organisation catalogue, and the bastion is not in it (see above). Certificate reuse gives most
of the convenience; covering inspect by windows would mean adding the bastion to the catalogue
through a second signed cutover.

### Root

Rules, each enforced in the server and tested:

1. **Allowlist.** Only enrollments on the bastion allowlist may ask. The list is per
   installation, empty by default, and changes only with a passkey-signed action
   (`bastion_host` `allow` / `remove`, bound to the immutable enrollment ID, host name, class
   and enrollment address). A re-enrolled host has a new enrollment ID and is not on the list.
   Checked at create, at challenge and inside the apply transaction.
2. **Always a fresh tap.** No standing rule, policy auto, batch or window can decide a
   `bastion` request: those paths cannot build or apply its canonical text (tests cover each).
3. **One hour at most.** `ttl_seconds` ≤ 3600 at create (clamped), challenge (refused) and
   apply (refused). No indefinite, no soft-cap extension.
4. **The card is red and says what it means** (§6), lists the buckets open right now, and
   offers "Close all open buckets first" (on by default). All of that is signed (§5).
5. **Buckets.** With "close first" signed: after the certificate is signed and before the
   transaction commits, the broker closes every bucket, hold, window and pending tap
   (`closeAll`), and does so again at the moment the certificate is handed to the requester.
   Without it: the apply transaction recomputes the open list and refuses (409, review again)
   if any bucket is open that the signed list does not name. "Open" means held by something
   other than a tap that is being applied right now.
6. **Audit and alert before the certificate.** The grant, the `bastion_root` audit row (who
   signed, requester, enrollment, source address, key fingerprint, TTL, the open list and the
   close choice) and the grant's bastion record commit in one transaction: if the audit row
   cannot be written nothing is issued. After the commit the broker sends the ntfy alert
   synchronously (10 s limit) and records the outcome on the bastion record. The agent API
   returns the certificate only once that outcome is recorded. If ntfy failed the session
   proceeds and the card result and the Bastion access page say "alert not delivered".
   A crash between commit and alert leaves a grant whose certificate is never delivered.
7. **Single delivery.** The certificate is returned by exactly one poll (atomic mark, audited
   `bastion_cert_delivered`), and only within 5 minutes of approval. The CLI keeps it in a
   private temporary directory for the one `ssh` it runs, never in the certificate cache, and
   deletes key and certificate when ssh exits. Certificate: `source-address` plus `permit-pty`,
   no forwarding; principal `<admin_user>@<name>`.
8. **Visibility afterwards.** While a root certificate is unexpired the UI shows a red banner
   on every page ("root session on the bastion possible until HH:MM; anything you open now is
   readable by it") and the Bastion access section lists it. Revoking the grant is possible and
   marks it, but cannot recall the certificate; the card says so.

In an unsealed store there are no buckets: the card says that every credential is readable by
root outright, the open list is empty and "close first" is not offered.

## 5. Canonical text

Version 1 key sets (no organisation binding), in both legacy and organisations mode.

`request` with `kind:"bastion"`, actions `approve` / `deny`:

```
v, action, object, id, nonce, issued_at,
kind, level, requesting_host, host_id, address,
target, target_address, target_port, login_user, principal, key_fingerprint,
ssh_ca, host_key, cert_profile, ttl_seconds,
sealed, open_buckets, close_buckets
```

* `level`: `inspect` | `root`. `host_id`: the requester's enrollment ID. `address`: the
  requester's source address (becomes the certificate's `source-address`).
* `ssh_ca`, `host_key`: SHA-256 fingerprints of the signing CA and of the pinned bastion host
  key. `cert_profile`: `source-address` (inspect) or `source-address;permit-pty` (root).
* `sealed`: whether the store is sealed. `open_buckets`: a JSON array, as a string, of the
  sorted labels of the buckets open when the challenge was built (`"[]"` when none; always
  `"[]"` for inspect and for deny). `close_buckets`: the owner's choice (always `false` for
  inspect, deny, and an unsealed store).

The UI renders the red card from these signed fields only and refuses to sign when the card it
showed (level, open list, checkbox) differs from the parsed canonical text.

`grant` with `kind:"bastion"`, action `revoke`: the existing grant key set.

`bastion_host`, actions `allow` / `remove`: `id` = enrollment ID, plus `requesting_host`,
`class`, `address` (the key set of `host` revoke).

Routine tasks use the existing `setup` / `run` object: `id` names the task, `params` is its
canonical parameter text (§7).

## 6. The red card

Wording (fixed in the UI, selected by the signed `level`):

> **ROOT ON THE BASTION** · Ref ABC123
> **dev-1** asks to log in to **bastion** as **alice** (sudo) for 30 min.
> This is not an ordinary grant. Root on the bastion can read every bucket that is open while
> the session lasts, mint certificates for the whole fleet and replace aqmasd itself.
> Approving this ≈ approving everything until it ends.
> **Open right now:** SSH user CA · personal/paas/staging-env — or "No bucket is open."
> ☑ Close all open buckets before the certificate is issued (also ends approval windows)
> Requester's explanation (unverified): "…"

Red background band and border across the whole card, a warning icon and the words (never
colour alone), full width on a phone, the same card in the wide layout; the approve button is
red and reads "Approve root session". Root cards are never selectable for a batch and are
never shown inside a window's quick-approve list.

## 7. Routine maintenance as Setup tasks

Compiled into the runner's allowlist ([SETUP.md](SETUP.md)); each needs a tap by a pinned
passkey; none takes free text. Output shown on the page is fixed step text plus package names,
versions and sizes: nothing secret.

| Task | Parameters | What runs (fixed argv, clean environment) | Reversible |
|---|---|---|---|
| `os-update` | `{"kernel":bool}` | `dnf -y --refresh upgrade`, with `--exclude=kernel*` unless `kernel` is true | No (`dnf history undo` by hand) |
| `reboot` | `{}` | `systemctl reboot`, after the status is written | No. Comes back with nothing open |
| `restart-cloudflared` | `{}` | `systemctl restart` of the tunnel unit (`cloudflared-aqmas.service`, else `cloudflared.service`), then `is-active` | n/a (the page is unreachable for a few seconds) |
| `restart-broker` | `{}` | stop, start, health check | n/a. Comes back with nothing open |
| `disk-usage` | `{}` | `df -P -h` for `/`, the data directory and `/var/log`; `journalctl --disk-usage` | read-only |
| `journal-vacuum` | `{"keep_days":1…365}` | `journalctl --rotate`, `journalctl --vacuum-time=<n>d` | No |

**Kernel safety, generically.** Some hosts run a kernel the distribution did not ship. With
`kernel:false` (the default the UI and CLI send) the runner passes `--exclude=kernel*`, and
verifies the outcome instead of trusting the flag: it records every installed package before
and after (`rpm -qa`), and the default boot entry where `grubby` exists. If any package whose
name starts with `kernel` changed, or the default boot entry changed, the task **fails** with
that statement (the summary still lists what changed) so the owner looks before any reboot.
With `kernel:true` the same facts are reported as results. The summary is the before/after
difference: count, and up to 60 `name old → new` lines in the task log.

The only request-derived values that reach a command line are the boolean (as the presence of
one fixed argument) and `keep_days` (an integer re-formatted by the runner). No parameter is
ever passed as a string.

**Queueing by an agent.** `POST /v1/setup-requests {task, params, reason, requester}` from an
enrolled, admitted host; only the six routine tasks above are accepted (never the access
tasks, sealing, pins, updates). `reason` is required. The broker validates and canonicalises
the parameters with the task's own schema and stores a pending request (10 min expiry, shared
pending limit). It appears as a normal pending card: task title, fixed description,
parameters, requester and reason. Approving it is exactly the Setup page's flow (the owner's
tap signs `setup`/`run` for that task and those parameters; the broker spools it; the runner
verifies the signature against its own pins). The signature binds the task and parameters,
not the requester: host and reason are context, as everywhere else. Dismissing a request is
an unsigned session action (it can only return to "nothing queued"). `GET
/v1/setup-requests/{id}` (long-poll) reports `pending | approved | denied | expired |
cancelled` and, once approved, the runner's public status of that run (state, step, message,
results), matched by the digest of the signed text. Nothing runs without the tap.

## 8. `aqmasd inspect` (the forced command)

Runs as `aqmas-inspect`, reads `SSH_ORIGINAL_COMMAND`, never a shell. The request must be at
most 200 bytes of `[A-Za-z0-9 ._=-]`; anything else prints the help and exits 2. Commands:

```
help
logs <unit> [since=<n><m|h|d>] [lines=<n>]     default since=1h lines=500; at most 30d, 5000
status [<unit>]
failed
disk
version
```

`<unit>` is a key in a compiled-in table (`aqmasd`, `maint`, `cloudflared`, `firewall`,
`lock-alert`, `sshd`, `kernel`), never a unit name from the request. Each command is a fixed
argv of `/usr/bin/journalctl`, `/usr/bin/systemctl`, `/usr/bin/df`, `/usr/bin/uname` with
`--no-pager`, a clean environment and a 30 s limit. It does not read the broker's
configuration. Membership of `systemd-journal` lets the account read the system journal; the
forced command is what narrows that to the listed units.

## 9. CLI

```
aqmas ssh bastion --why "…" [--level inspect|root] [--ttl 30m] [-- <inspect command>]
aqmas bastion                      # what this host may ask for
aqmas bastion task os-update --why "…" [--kernel]
aqmas bastion task journal-vacuum --keep-days 14 --why "…"
aqmas bastion task reboot|restart-cloudflared|restart-broker|disk-usage --why "…"
```

`--level` defaults to `inspect`. The CLI uses the bastion flow when `--level` is given or the
name equals the one `GET /v1/bastion` reports. For `root` it prints, before waiting: "This
asks for ROOT on the bastion; the owner will see a red card." `aqmas bastion task` waits for
the decision and then for the runner, prints the result and exits non-zero if the task failed.

## 10. Web UI

* The red card (§6) in the pending list; amber inspect card.
* **Admin → Bastion access**: whether access is installed (and the two Setup tasks), the
  allowlist with one signed toggle per enrolled host, active and recent bastion sessions
  (level, host, until, buckets closed, alert delivered or not, revoke), and the routine
  tasks with their last result.
* The global red banner while a root certificate is unexpired.
* Help page section.

## 11. Storage

No change to the numbered schema ladder. Created idempotently at start, like the env and
window tables:

```
bastion_hosts(enrollment_id PK, host_name, added_at)
bastion_grants(grant_id PK, level, close_buckets, closed_count, alert, alert_at, delivered_at)
setup_requests(id PK, host_id, host_name, peer_address, task, params, reason, requester_json,
               status, created_at, expires_at, decided_at, decision_note, digest)
```

## 12. Tests

Canonical binding of every new action (Go and TypeScript, including the open list and the
close choice); root never decided by a standing rule, policy auto, batch or window; TTL cap at
create, challenge and apply; allowlist at create, challenge and apply, and after re-enrolment;
audit-before-issue with a failing audit write; close-before-issue really closes (pool empty,
windows ended) and the stale-open-list refusal; single delivery and the 5-minute limit; alert
failure surfaces; the forced command's parser (injection attempts) and its unit table; the
sshd files the runner test layout produces; every task's parameter schema (unknown keys,
non-canonical text, out-of-range values) and argv; agent-queued tasks do nothing before the
tap. `test/interop`: allow access in the runner test layout, an inspect session through a
real sshd with the produced configuration, a root grant with a bucket open that is closed
before delivery, a routine task queued by an agent and approved.
