# Access to the bastion itself

**Design and operation · 2026-11-23 · revised after independent design review (§13).** The
bastion that runs `aqmasd` accepts only the owner's emergency key ([DESIGN.md](DESIGN.md));
agents cannot log in. In practice the bastion needs maintenance: logs to read, packages to
update, a service to restart. This adds three controlled ways in, all approved with a passkey:

| Way in | Who lands where | Card | Approval |
|---|---|---|---|
| **Inspect** | `aqmas-inspect`, an account that can only run a fixed set of read-only commands | amber (normal) | one tap, default 1 h |
| **Root** | the owner's admin account, which has sudo | **red** | always a fresh tap, at most 1 h, only hosts on root's own allowlist |
| **Routine task** | nobody logs in: the root maintenance runner runs a compiled-in task | normal Setup card | one tap by a pinned passkey |

Owner's stance: convenience is a legitimate trade-off, or the thing will not be used. The root
rules below are deliberate and are not relaxed for convenience.

## For the owner: what you do

1. **Once:** Admin → Bastion access → **Allow aqmas access to the bastion**. Fill in the name
   agents will use, the address fleet hosts reach this machine on and your account's name;
   check the SSH CA fingerprint; tap with a pinned passkey. The broker restarts (everything
   open closes).
2. **Once per host that may ask for root:** tick it under *Who may ask for root* and tap
   (**Set who may ask for root on the bastion**). Empty by default.
3. **An agent wants to read logs:** it runs `aqmas ssh bastion --why "…" -- logs aqmasd`; you
   get an amber card; tap.
4. **An agent (or you) needs root:** `aqmas ssh bastion --level root --why "…"`; you get the
   red card; read which buckets are open, leave "Close all open buckets first" ticked, tap.
5. **Routine work:** the agent runs `aqmas bastion task os-update --why "…"` (or you press the
   task's button on the page); you get a normal card; tap with a pinned passkey; the result
   appears on the page and in the agent's terminal.

Your emergency key is never touched by any of this and stays the way in when aqmas is down.
Before installing an aqmas older than this feature, run **Remove aqmas access to the
bastion**: an older broker refuses a configuration with a `[bastion]` table.

## 1. Threat model and what changes

Today a compromised agent host cannot reach the bastion at all. After "Allow aqmas access to
the bastion" has run, the bastion's sshd trusts the aqmas SSH user CA for two principals. That
is new attack surface, bounded as follows.

* **The SSH CA can now mint a bastion login.** Whoever can sign with the CA can produce a
  certificate for the admin account. In a sealed store the CA key is in a bucket that only a
  passkey tap opens, for the instant of signing unless a standing rule or window holds it.
  Two things on the bastion do not depend on the broker behaving: sshd accepts an admin
  certificate **only from the addresses on root's own allowlist** (`from=` on the principals
  line, written by a signed Setup task), and the inspect certificate **carries its forced
  command inside itself**. So a broker bug or compromise that signs the wrong thing while the
  CA is open still needs control of an allowlisted host to become root here. With that, it is
  root; this is the cost of the feature, and why it is off until the owner installs it, and
  removable.
* **A root session is equivalent to approving everything for its duration.** Root on the
  bastion can read every open bucket from the broker's memory, wait for others to be opened,
  replace `aqmasd`, replace the runner's pinned passkeys, add its own key and mint certificates
  for the fleet. No rule in the broker constrains a root shell, and what root changed outlasts
  the certificate. The design therefore makes the approval unmistakable, rare, short,
  attributable and loud; it does not pretend to constrain the shell. "Root" means the admin
  account: with password-less sudo it is root at once, and without it the account can still
  change its own `authorized_keys` and wait, so it is treated as root either way.
* **Inspect must not be a stepping stone.** The inspect account gets no shell: sshd forces
  every session into `aqmasd inspect` (and so does the certificate), which runs a compiled-in
  allowlist of commands with fixed arguments. It cannot read `/var/lib/aqmas`, `/etc/aqmas`,
  the spool or CA material (ordinary file permissions: it is in no group that can), cannot
  forward anything (so it cannot reach the web listener on `127.0.0.1` or the agent API from
  inside), has no password, no `authorized_keys`, no writable home and no sudo.
* **What inspect can read.** The journal of the listed units, and their state. The broker and
  the runner log no secrets by design (the runner sends the output of the commands it runs,
  such as `dnf`, to its journal). Service state is read with `systemctl show` for a fixed list
  of properties, never `systemctl status`: a tunnel started as `cloudflared … --token …` has
  its token on its command line, and that token would let an agent serve the approval origin.
* **Emergency keys are untouched.** Everything here is additive (`AuthorizedPrincipalsFile`
  only affects certificate logins).
* **Not addressed.** An issued SSH certificate cannot be recalled (no KRL yet), and sshd
  cannot enforce "one login per certificate": "single-use" means the broker hands the
  certificate out once and the CLI never caches it. The alert that announces a root session is
  sent by the broker; a root-owned alert on every certificate login to the bastion (in the
  manner of the lock alert) would not depend on the broker and is the recommended next step.

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

The inspect account's name is the constant `aqmas-inspect`. Validation: `address` is a literal
IP address; `name` may not be a `[[targets]]` name or alias; no target may issue the principals
`<admin_user>@<name>` or `aqmas-inspect@<name>`; `admin_user` may not be `root`, the broker's
account, the build account or the inspect account. The table is **not** part of the personal
catalogue's configuration fingerprint: the bastion is deliberately not a catalogue set (§4),
so adding or removing it needs no new cutover review.

Root's allowlist is `/etc/aqmas/bastion-allow.json` (root:aqmas 0640): the broker reads it and
cannot write it.

## 3. Host trust on the bastion (Setup tasks)

`deploy/hosts/install-host-trust.sh` refuses hosts the site policy lists (the example policy
lists the bastion) and stays that way for every manual use. It gains `--bastion-self`, used
only by the maintenance runner: the refuse rules are skipped for that run, and it must be
combined with `--inspect-user` and `--inspect-command`, which install the forced-command
block. The public repository names no real host: the policy file remains the place where a
site names its own.

**"Allow aqmas access to the bastion"** (`bastion-access`; runner, root, fixed). Signed
parameters `{"name","address","port","admin_user","ssh_ca"}`; `ssh_ca` is the SHA-256
fingerprint of the SSH user CA, shown on the card. The runner:

1. checks `admin_user` is an existing non-system account (uid ≥ 1000) and none of the
   reserved names;
2. reads this machine's own Ed25519 host key and **builds the new configuration first**
   (the old one plus exactly the `[bastion]` table, proved by re-parsing, which also applies
   the collision rules of §2): nothing is touched if that fails;
3. reads `<data_dir>/ca/ssh_user_ca.pub` (a directory the broker owns, so read without
   following links) and continues only if it is one Ed25519 key with the **signed**
   fingerprint. In a sealed store it further requires that fingerprint to be the `ssh_ca` of
   the activation manifest whose digest is pinned in the root-owned configuration, so a
   broker cannot get another CA trusted by showing its own fingerprint on the card. (In an
   unsealed store the broker holds the real CA key anyway.)
4. creates the system account `aqmas-inspect` if missing (`useradd --system
   --no-create-home`, home `/`, shell `/bin/sh` because sshd runs a forced command through
   the shell, password locked, supplementary group `systemd-journal` only) and refuses to
   continue if an existing account of that name has uid 0, a uid ≥ 1000 or any other group;
5. runs the embedded host-trust installer for the inspect account. It writes
   `/etc/ssh/aqmas_user_ca.pub`, `/etc/ssh/aqmas_principals/aqmas-inspect`
   (`aqmas-inspect@<name>`), `/etc/ssh/sshd_config.d/10-aqmas.conf` (as on fleet hosts) and
   `/etc/ssh/sshd_config.d/90-aqmas-inspect.conf`:

   ```
   Match User aqmas-inspect
       ForceCommand /usr/local/bin/aqmasd inspect
       AuthenticationMethods publickey
       AuthorizedKeysFile none
       AuthorizedKeysCommand none
       PasswordAuthentication no
       KbdInteractiveAuthentication no
       DisableForwarding yes
       PermitTTY no
       PermitUserRC no
   ```

   backs up what it replaces, validates with `sshd -t`, checks with `sshd -T -C user=…` that
   the inspect account sees the CA, the principals file, the forced command and no
   forwarding, and that the admin account sees the CA and **no** forced command; restores
   the backup on any failed check; reloads sshd and waits for its port;
6. writes the admin account's principals file from root's allowlist (below; absent while the
   list is empty, so no root certificate is accepted yet);
7. backs up and replaces the configuration, restarts the broker and checks health. On
   failure the configuration is restored, the broker restarted and the trust files removed.

A broker restart closes every bucket and window; the card says so. Other accounts on the
bastion gain nothing: without a principals file a certificate login is refused.

**"Set who may ask for root on the bastion"** (`bastion-allow`). Signed parameters
`{"hosts":[{"id","name","address"}]}`: the complete new list, sorted by enrollment ID, at
most 32, empty to allow nobody. The runner writes `/etc/aqmas/bastion-allow.json` and the
admin principals file `/etc/ssh/aqmas_principals/<admin_user>`:

```
from="192.0.2.21,192.0.2.22" alice@bastion
```

(removed when the list is empty). No restart: sshd and the broker read both files on use. The
list binds the immutable enrollment ID *and* one address: a re-enrolled host has a new ID and
is not on the list, and a listed host asking from another address is refused.

**"Remove aqmas access to the bastion"** (`bastion-access-remove`, no parameters): removes the
`[bastion]` table, restarts the broker, removes the admin principals file and the allowlist,
uninstalls the trust files (only files the installer wrote), ends the inspect account's
sessions and deletes the account. A root session that is already open is an ordinary login of
the admin account and is not ended; the card says so.

## 4. Requests and approvals

A bastion session is its own request **kind** (`bastion`), not an SSH target. After the
cutover to organisations the configuration fingerprint pins `[[targets]]`, so a target cannot
be added without a fresh cutover; and a kind of its own can be kept out of every silent path
explicitly. The generic request paths name the kinds they serve (`ssh`, `cloudflare`) and
refuse every other: the request-creation path with its standing rules and policy auto, the
generic status and cancel endpoints, batches, windows and the standing-rule bookkeeping.
Batches and windows additionally require an organisation binding, which a bastion request
does not have, and the bastion's canonical text has no standing field. Tests drive a bastion
request through each of those paths and expect a refusal.

Agent API (mTLS, enrolled host admitted to the personal organisation):

* `GET /v1/bastion` → `{name, address, port, inspect_user, admin_user, root_allowed,
  inspect_max_seconds, inspect_default_seconds, root_max_seconds, tasks[]}` (404 while there
  is no `[bastion]` table).
* `POST /v1/bastion/requests {level, public_key, reason, ttl_seconds, requester}` → the usual
  `RequestCreated`. `level` is `inspect` or `root`; the login user is derived from it, never
  taken from the request. `reason` is required. Level `root` from an enrollment or address
  that is not on root's allowlist is refused here (403), before anything is queued or pushed.
* `GET /v1/bastion/requests/{id}` (long-poll) and `POST …/cancel`.

Stored in `requests` with `kind='bastion'`, `target_host=<name>`, `login_user`, `principal`,
address and port from the configuration, and no catalogue binding. The shared per-host
pending limit applies. In organisations mode the decision additionally requires the global
owner (the session's and the signing passkey's person).

### Inspect

Normal card. TTL: default 1 h, at most the SSH maximum of the host's class. One tap; no
standing rule (none can be signed). The certificate is delivered like any SSH grant and the
CLI caches and reuses it until it expires, so an agent that reads logs repeatedly within the
hour costs one tap. The certificate carries `source-address` and
`force-command="/usr/local/bin/aqmasd inspect"` as critical options and **no** extensions (no
pty, no forwarding); the principal is `aqmas-inspect@<name>`.

Deviation from the approved outline, for the owner to decide: inspect requests are **not**
covered by approval windows or batches in this version. Both are built on the organisation
catalogue, and the bastion is not in it (see above). Certificate reuse gives most of the
convenience; covering inspect by windows would mean adding the bastion to the catalogue
through a second signed cutover.

### Root

Rules, each enforced in the server and tested:

1. **Allowlist.** Only an enrollment on root's allowlist, asking from its listed address. The
   list is per installation, empty by default, kept in a root-owned file and changed only by
   the signed `bastion-allow` Setup task; sshd enforces the same addresses. Checked at
   create, at challenge and inside the apply transaction.
2. **Always a fresh tap.** No standing rule, policy auto, batch or window can decide a
   bastion request (above).
3. **One hour at most.** `ttl_seconds` ≤ 3600 at create (clamped), at challenge (refused), in
   the canonical text (cannot be built) and at apply (refused). No indefinite, no soft cap.
4. **The card is red and says what it means** (§6), lists the buckets open right now, says
   whether an alert channel exists, and offers "Close all open buckets first" (on by
   default). All of that is signed (§5).
5. **Buckets.** With "close first" signed: after the certificate is signed and before the
   transaction commits, the broker closes every bucket, hold, window and pending tap
   (`closeAll`), and does so again at the moment the certificate is handed to the requester.
   Without it: the apply transaction recomputes the open list and refuses (409, review again)
   if any bucket is open that the signed list does not name. "Open" means held by something
   other than an approval that is being applied at that instant. Closing does not delete
   standing rules: the next ordinary approval can open a bucket again while the root
   certificate is valid, which is what the banner (rule 8) is for.
6. **Audit and alert before the certificate.** The grant, the `bastion_root` audit row (who
   signed, requester, enrollment, source address, key fingerprint, TTL, the open list, the
   close choice) and the grant's bastion record commit in one transaction: if the audit row
   cannot be written nothing is issued. After the commit the broker sends the ntfy alert
   synchronously (10 s limit) and records the outcome (`sent`, `failed`, or `off` when no
   channel is configured). The agent API reports the request as approved, and returns the
   certificate, only once that outcome is recorded. If the alert failed the session proceeds
   and the card result and the Bastion access page say so. A crash between commit and alert
   leaves a grant whose certificate is never delivered. When no channel is configured the
   red card says "nobody will be alerted", and that fact is signed.
7. **Single delivery.** The certificate is returned by exactly one poll (atomic mark, audited
   `bastion_cert_delivered`), to the address it is bound to, within 5 minutes of approval;
   otherwise the grant is revoked. The CLI keeps key and certificate in a private temporary
   directory for the one `ssh` it runs, never in the certificate cache, and deletes them when
   ssh exits. Certificate: `source-address` plus `permit-pty`, no forwarding; principal
   `<admin_user>@<name>`.
8. **Visibility afterwards.** While a root certificate is unexpired and unrevoked the UI
   shows a red banner on every page ("a root certificate for the bastion is valid until
   HH:MM; whatever you open now is readable by that session, and a session can outlast its
   certificate") and the Bastion access section lists it. Revoking the grant marks it and
   stops delivery, but cannot recall a delivered certificate; the card says so.

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
sealed, open_buckets, close_buckets, alert_channel
```

* `level`: `inspect` | `root`. `host_id`: the requester's enrollment ID. `address`: the
  requester's source address (becomes the certificate's `source-address`).
* `ssh_ca`, `host_key`: SHA-256 fingerprints of the signing CA and of the pinned bastion host
  key. `cert_profile`: `source-address;force-command` (inspect) or `source-address;permit-pty`
  (root). `principal` is always `login_user@target`.
* `sealed`: whether the store is sealed. `open_buckets`: a JSON array, as a string, of the
  sorted, distinct labels of the buckets open when the challenge was built (`"[]"` when none;
  always `"[]"` except for a root approval of a sealed store). `close_buckets`: the owner's
  choice (false except there). `alert_channel`: a push channel exists (false except for a root
  approval). `ttl_seconds`: 0 for deny; for root at most 3600.

Text that contradicts itself (a level with the other level's profile, an open list on an
inspect card, a root TTL above the cap) cannot be built or parsed. The UI renders the red card
from these signed fields only and refuses to sign when the card it showed (level, open list,
checkbox) differs from the parsed canonical text.

`grant` with `kind:"bastion"`, action `revoke`: the existing grant key set. There is no
`standing` object of this kind.

Tasks use the existing `setup` / `run` object: `id` names the task, `params` is its canonical
parameter text.

| Task | `params` (keys in this order) |
|---|---|
| `bastion-access` | `{"name","address","port","admin_user","ssh_ca"}` |
| `bastion-access-remove` | `{}` |
| `bastion-allow` | `{"hosts":[{"id","name","address"}]}` sorted by `id` |
| `os-update` | `{"kernel":bool}` |
| `reboot`, `restart-cloudflared`, `restart-broker`, `disk-usage` | `{}` |
| `journal-vacuum` | `{"keep_days":1…365}` |

## 6. The red card

Wording (fixed in the UI, selected by the signed `level`):

> **ROOT ON THE BASTION** · Ref ABC123
> **dev-1** asks to log in to **bastion** as **alice** (your admin account) for 30 min.
> This is not an ordinary grant. Root on the bastion can read every bucket that is open while
> the session lasts, mint certificates for the whole fleet and replace aqmasd itself.
> Approving this ≈ approving everything until the session ends.
> **Open right now:** SSH user CA · personal/paas/staging-env — or "No bucket is open."
> ☑ Close all open buckets before the certificate is issued (also ends approval windows)
> You will be alerted when it is issued. — or — **No alert channel is configured: nobody will be alerted.**
> Requester's explanation (unverified): "…"

Red band and border across the whole card, a warning icon and the words (never colour alone),
full width on a phone, the same card in the wide layout; the approve button is red and reads
"Approve root session". Root cards are never selectable for a batch and never appear in a
window's quick-approve list.

## 7. Routine maintenance as Setup tasks

Compiled into the runner's allowlist ([SETUP.md](SETUP.md)); each needs a tap by a pinned
passkey; none takes free text. Output shown on the page is fixed step text plus package names,
versions and sizes: nothing secret. None of these tasks keeps a journal for crash recovery: an
interrupted one is simply run again.

| Task | Parameters | What runs (fixed argv, clean environment) | Reversible |
|---|---|---|---|
| `os-update` | `{"kernel":bool}` | `dnf -y --refresh upgrade` with the exclusions below unless `kernel` is true, in a transient unit outside the runner's sandbox | No (`dnf history undo` by hand) |
| `reboot` | `{}` | `systemctl reboot`, after the status is written | No. Comes back with nothing open |
| `restart-cloudflared` | `{}` | `systemctl restart` of the tunnel unit (`cloudflared-aqmas.service`, else `cloudflared.service`), then `is-active` | n/a (the page is unreachable for a few seconds) |
| `restart-broker` | `{}` | stop, start, health check | n/a. Comes back with nothing open |
| `disk-usage` | `{}` | `df -P -h` for `/`, the data directory and `/var/log`; `journalctl --disk-usage` | read-only |
| `journal-vacuum` | `{"keep_days":1…365}` | `journalctl --rotate`, `journalctl --vacuum-time=<n>d` | No |

**Kernel and boot-chain safety, generically.** Some hosts run a kernel the distribution did
not ship. With `kernel:false` (what the UI and CLI send unless told otherwise):

* dnf gets one `--exclude=<glob>` per entry of a compiled-in list (`kernel*`, `kmod-*`,
  `akmod-*`, `grub2*`, `shim*`, `dracut*`, `systemd-boot*`, `sdubby*`, `linux-firmware*`,
  `m1n1*`, `uboot*`, `asahi-*`) plus any glob in the optional root-owned
  `/etc/aqmas/os-update-exclude` (one per line, `[A-Za-z0-9._*+-]` only), for whatever else a
  site pins;
* the outcome is verified rather than trusted: the runner records every installed package
  before and after (`rpm -qa`) and a fingerprint of the boot files (names, sizes and times of
  everything under `/boot`, contents of the loader entries, `grub.cfg` and `grubenv`). If a
  package matching an exclusion changed, or the boot files changed, the task **fails** with
  that statement (the summary still lists what changed) and leaves a root-owned marker. While
  the marker exists the `reboot` task refuses, so a routine-looking reboot card cannot follow
  an update that touched the boot path unnoticed. An `os-update` with `kernel:true` (the
  owner accepting boot changes) or removing the marker on the machine clears it.

With `kernel:true` nothing is excluded and the same facts are reported as results. The summary
is the before/after difference: counts, and up to 60 `name old → new` lines in the task log.
When bastion access is installed, the task ends by re-running the host-trust check (a package
update could have changed sshd's configuration): if sshd no longer confines the inspect
account, the task fails and says so.

The only request-derived values that reach a command line are the boolean (as the presence of
fixed arguments) and `keep_days` (an integer re-formatted by the runner).

**Queueing by an agent.** `POST /v1/setup-requests {task, params, reason, requester}` from an
enrolled, admitted host. Accepted: the six routine tasks only (never the access tasks,
sealing, pins, updates of aqmas itself), never `kernel:true`, and `keep_days` of at least 7.
`reason` is required. Limits: one undecided request per host, three in total, three per host
in five minutes, and the shared per-host pending limit. The broker validates and
canonicalises the parameters with the task's own schema and stores a pending request (the
usual expiry). It appears as a normal pending card: task title, fixed description and warning,
the parameters, requester and reason. Approving it is exactly the Setup page's flow: the
owner's tap signs `setup`/`run` for that task and those parameters, the broker spools it, the
runner verifies the signature against its own pins. The signature binds the task and
parameters, not the requester: host and reason are context, as everywhere else. In the same
transaction that spools the request the broker marks the queued request approved, and only if
it is still pending and asks for exactly the signed task and parameters. Dismissing a request
is an unsigned session action (it can only return to "nothing queued"). `GET
/v1/setup-requests/{id}` (long-poll; `?after=<state>` waits for the run to leave that state)
reports `pending | approved | denied | expired | cancelled` and, once approved, the runner's
public status of that run (`queued | running | done | failed | refused`, step, message,
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
argv of `/usr/bin/journalctl`, `/usr/bin/systemctl`, `/usr/bin/df`, `/usr/bin/uname`,
`/usr/bin/uptime` with `--no-pager`, a clean environment and a 30 s limit. `status` is
`systemctl show` for `Id, LoadState, ActiveState, SubState, Result, ExecMainStatus,
ActiveEnterTimestamp, NRestarts`: no command lines. It does not read the broker's
configuration. Membership of `systemd-journal` lets the account read the system journal; the
forced command (in sshd's configuration and in the certificate) is what narrows that to the
listed units.

## 9. CLI

```
aqmas ssh bastion --why "…" [--level inspect|root] [--ttl 30m] [-- <inspect command>]
aqmas bastion                      # what this host may ask for
aqmas bastion task os-update --why "…"
aqmas bastion task journal-vacuum --keep-days 14 --why "…"
aqmas bastion task reboot|restart-cloudflared|restart-broker|disk-usage --why "…"
```

`--level` defaults to `inspect`. The CLI uses the bastion flow when `--level` is given or the
name equals the one `GET /v1/bastion` reports. For `root` it prints, before waiting: "This
asks for ROOT on the bastion; the owner will see a red card." `aqmas bastion task` waits for
the decision and then for the runner, prints the result and exits non-zero if the task failed
or was refused.

## 10. Web UI

* The red card (§6) in the pending list; amber inspect card; a normal card for a queued task.
* **Admin → Bastion access**: whether access is installed (and the two access tasks), who may
  ask for root (a checklist of enrolled hosts with their addresses, applied with one tap),
  active and recent bastion sessions (level, host, until, buckets closed, alert delivered or
  not, collected or not, revoke), and the routine tasks with their last result.
* The global red banner while a root certificate is unexpired.
* Help page section.

`GET /api/ui/bastion` → `{enabled, name, address, port, admin_user, inspect_user, ssh_ca,
sealed, alert_channel, hosts[{id,name,class,address,allowed,allowed_address,gone}],
sessions[{grant_id,level,requesting_host,login_user,not_before,not_after,status,
close_buckets,closed_count,alert,delivered_at}], root_until, tasks[]}`.
`GET /api/ui/state` gains `bastion_root_until` and pending items of kind `bastion` (with
`bastion{…}`) and `setup` (with `setup{task,title,summary,steps,reversible,warning,params,
blocked}`). A request's challenge takes `close_buckets` (required for a root approval of a
sealed store, refused elsewhere); its decide answers `{id, kind, status, level, closed_count,
alert}`. `POST /api/ui/setup/{task}/run` takes `request` (the queued request it answers);
`POST /api/ui/setup-requests/{id}/dismiss` drops one.

## 11. Storage

No change to the numbered schema ladder. Created idempotently at start in normal serving,
like the env and window tables:

```
bastion_grants(grant_id PK, level, close_buckets, closed_count, alert, alert_at, approved_at, delivered_at)
setup_requests(id PK, host_id, host_name, peer_address, task, params, reason, requester_json,
               status, created_at, expires_at, decided_at, decision_note, digest)
```

## 12. Tests

Canonical binding of every new action (Go and TypeScript, including the open list, the close
choice and the alert flag); root never decided by a standing rule, policy auto, batch or
window, and a bastion request refused on every generic path; TTL cap at create, challenge,
canonical text and apply; allowlist at create, challenge and apply, by enrollment and by
address; audit-before-issue with a failing audit write; close-before-issue really closes (pool
empty, windows ended) and the stale-open-list refusal; single delivery, the address check and
the 5-minute limit; alert failure and absence surface; the forced command's parser (injection
attempts), its unit table and that `status` prints no command line; the sshd files the runner
test layout produces; every task's parameter schema (unknown keys, non-canonical text,
out-of-range values) and argv; the kernel exclusions and the boot-change marker; agent-queued
tasks do nothing before the tap and are bound to the signed task and parameters.
`test/interop`: allow access in the runner test layout, an inspect session through a real sshd
with the produced configuration, a root grant with a bucket open that is closed before
delivery, a routine task queued by an agent and approved.

## 13. What the design review changed

An independent review of the first draft led to these changes: explicit kind dispatch with
refusal on every generic request path (instead of relying on the bastion not being a target);
the organisations-mode status page no longer depends on a catalogue binding for bastion rows,
and bastion decisions require the global owner there; `systemctl status` replaced by
`systemctl show` (command lines can hold the tunnel token); the forced command also in the
inspect certificate; a tighter `Match` block and no home directory; the allowlist moved from
the broker's database to a root-owned file with `from=` enforcement in sshd; the SSH CA
anchored in the root-pinned activation manifest; the card says when no alert channel exists;
wider kernel/boot-chain exclusions verified against the boot files, dnf outside the runner's
sandbox, the boot-change marker that blocks `reboot`, and the sshd re-check after updates;
agents cannot queue kernel updates or short journal trims and are rate-limited. Recommended
and not built: a root-owned alert on every certificate login to the bastion.
