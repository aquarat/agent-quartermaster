# Sealed-store operations (per-credential buckets)

> **Admin → Setup** ([SETUP.md](SETUP.md)) runs the import and the move from format 1 from
> the approval page: the runner does the root-owned parts, and the recovery drill runs on the
> bastion with a key you may generate in the browser. That is the convenient path the owner
> chose. The manual procedures here are the stricter ones (recovery key never on the bastion,
> drill on an isolated machine) and the reference for recovery. Design:
> [BUCKETS.md](BUCKETS.md); wire contract: [API.md](API.md#buckets).

Every procedure here is a **supervised format transition** or a rare recovery path, not an
automatic update. Rehearse on an isolated installation first. A successful WebAuthn *login*
proves nothing about a passkey's PRF; only a tested scope wrap does.

## Seal an unsealed store

The input is an activated personal catalogue (schema 6 or 7), at least one registered
passkey whose provider returns PRF results, and the matching CA files. Schema 9 is committed
only by a signed activation.

1. Keep independent emergency access. Stop updater activation, stop and drain the daemon.
   Keep the current binary, an independently encrypted SQLite online backup, protected config
   and keys. Record the SSH CA fingerprint, internal CA pin, SSH serial high-water mark,
   config version and backup digest off-host.
2. On a trusted owner system generate a **dedicated native age X25519** identity
   (`umask 077; age-keygen -o identity.txt`). Keep it and an independently protected spare
   offline. Only the `age1…` recipient goes on the bastion. Do not use an SSH key, a
   passphrase recipient or `-pq`. This identity plus a sealed backup decrypts every secret.
3. In the **root-owned** config add `[seal]`, `required = true`,
   `recipient = "age1…"`, without `manifest_sha256`. Old binaries reject this config. Run
   `aqmasd -require-root-config -config CONFIG seal-import` as the service user at its
   existing RP origin. No agent API, issuer worker or update poller runs in this mode. The
   process reads the CA private keys and the Cloudflare proxy parent once, seals each into its
   own bucket **in memory** and creates a scope key per scope with its recovery wrap. The
   Cloudflare minter parent is not imported (token mode is off under organisations): revoke it
   at Cloudflare. The ntfy topic URL is carried into the unsealed `notice_channel`.
4. Sign in. In the seal panel pick the passkey that will hold the keys and tap **create**
   (one tap per two scopes: fresh PRF salts, the broker wraps each scope key under the
   passkey's KEK), then **test** (one tap per two scopes: the broker opens each new wrap).
   The first tap fixes the passkey and session; another one is refused. A passkey without PRF
   results cannot be used: register one that has them and start again. Nothing is written yet;
   stopping the process discards the stage.
5. **Recovery drill.** Paste the identity once on this page: it is HPKE-sealed to the
   process's `drill_key`, opens every staged scope key from its recovery wrap, every bucket
   and every record, and is wiped. Activation requires this drill. It puts the identity on
   the bastion for a moment; for the strict check also run the offline drill (below) on a
   backup taken right after activation.
6. The page shows the activation manifest once every scope is wrapped and tested and the
   drill passed. Compare its SHA-256 and the recipient with your local view and independent
   pins (scopes, bucket kinds, CA pins, approve-only passkeys, dropped records). Sign
   **Activate**: a plain signature, without PRF. One transaction writes scopes, wraps,
   buckets, records, `notice_channel`, the signed manifest and audit, and sets schema 9;
   then `VACUUM` and a WAL checkpoint. The process exits and leaves `manifest.json` in
   `seal-stage-*/` under the data directory.
7. Atomically install and sync `manifest_sha256 = "<SHA-256 of manifest.json>"` in the root
   `[seal]` config. **Before restart**, remove `ntfy.topic_url` from the config, unlink both
   retired private CA files (`ca/ssh_user_ca`, `ca/client_ca.key`), remove both Cloudflare
   parent source files and their `LoadCredential=` entries. `serve` refuses to start while any
   of them remains. Retain the public SSH CA, the internal CA certificate, `server.crt` and the
   0600 `server.key`.
8. Cold start: every bucket is closed. Approve one SSH request (its tap opens the SSH CA for
   an instant), one enrollment and the configured proxy. Restart and confirm grants that need
   a bucket show as paused with **Reopen**. Take an encrypted post-activation online backup.

Unlinking files does **not** erase SSD blocks, WAL, snapshots, copied configs or backups.
Restrict, expire or cryptographically erase pre-import backups: they hold plaintext keys.
Rotate the ntfy capability and the Cloudflare parents upstream. For CA replacement distribute
both public SSH keys, move issuance, test and retire old trust on every target. Replacing
the internal CA requires independent pin distribution and new leaf and client identities.

### Post-import checks

Record the original **effective** systemd credential name → absolute source path mappings in
a root-owned JSON object before maintenance (`{}` for none). After retirement and unit reload
run `seal-preflight.py CONFIG SOURCES.json` as root, before starting the unit. The system
unit requires root-protected config ancestors; use `-require-root-config` for maintenance
commands too.

In Admin → Passkeys, **Enable** a second, independently held passkey for every scope (one
tap by a passkey that already opens them, then one by the new passkey per two scopes) and
**Test** it. Watch the agent TLS leaf expiry on the broker card and sign **Renew leaf**
(it opens the internal CA for an instant, then the broker restarts) well before expiry.
Never remove a CA or disable TLS verification to repair a leaf.

## Move a format-1 store to buckets (one-way)

For a store sealed by v0.4.1 (schema 8, one master key). The new binary in `serve` mode on
such a store reports `migration-required`: sign-in, request queueing, deny/revoke and the
Setup page work, nothing secret does, and upgrades are refused.

The move is **one-way**: after activation there is no rollback and v0.4.1 cannot read the
store. Run it from **Admin → Setup → Move to per-credential buckets** (task `buckets`):

1. **Run** (tap). The runner checks schema 8 and the format-1 pin, stops the broker, backs up
   database, keys and configuration, and starts it in `bucket-migrate` mode (no agent
   listener).
2. **Open the old store** (one tap by a format-1 unlock passkey; only those are offered). PRF
   `first` is its format-1 salt, `second` a fresh salt for the installation scope. The broker
   opens the master key, stages every record, signer key and current env revision in buckets
   in memory, creates the installation wrap for this passkey and wipes the master key.
3. **Create** the passkey's wraps for the other scopes in use, two per tap, then **test**
   every wrap, two per tap.
4. **Recovery drill**: paste the recovery key (as in step 5 above).
5. **Activate** (plain signature). The manifest names every other format-1 unlock passkey,
   which becomes approve-only until enabled again. One transaction writes everything, drops
   the format-1 wraps and sets schema 9. The runner verifies the signature against its pins,
   pins the new manifest digest, restarts `serve` with everything closed and, if
   `purge_backups` was set, deletes the pre-migration and older backups.

Before activation an interruption commits nothing: the runner restores the configuration and
restarts the format-1 broker, and the task can be run again. After activation it only
finishes forward. Pre-migration backups and offsite copies keep format-1 strength: anyone
with such a copy and one tap from a malicious page asking for an old salt gets the master
key. Delete or crypto-erase them once the new store is checked. After the move, enable your
other passkeys (Admin → Passkeys → **Enable**).

## Recovery drill

Prove the recovery identity opens a real backup. Do both from time to time.

* **Browser** (Admin → Recovery drill): paste the identity; the page seals it to a one-time
  broker key, one ordinary tap signs `recovery drill` with the packet's SHA-256, and the
  broker opens every scope key from its recovery wrap, every bucket and every record, then
  wipes everything. It reports counts only. This puts the identity into the approval page:
  prefer the offline drill.
* **Offline**, on an isolated trusted machine, against a standalone online backup (no WAL or
  journal beside it):

  ```sh
  umask 077
  aqmasd seal-drill BACKUP.db RECIPIENT <identity.txt
  ```

  It opens the backup read-only, checks schema 9 and that the signed manifest names
  `RECIPIENT`, opens every scope key, bucket and record and prints one line:
  `recovery drill passed: scopes=N buckets=M manifest_sha256=…`. The Cloudflare parent's
  record is bound to the configured issuer and account; without the configuration it is
  reported unchecked. Compare the digest with the off-host record. Never pass the identity in
  argv, a file on the bastion or shell history.

## Lost one passkey

1. **Remove** it (Admin → Passkeys, signed tap). The broker refuses if it is the only passkey
   that opens some scope: first enable another passkey for that scope, or enrol one with the
   recovery key (Admin → Recovery, the rare path). Removal deletes its wraps and ends the
   web sessions that signed in with it.
2. **Rekey** each scope it opened (Admin → Buckets → **Rekey**, one tap by a passkey that
   opens the scope). The scope and every bucket in it get new key pairs, every record is
   re-encrypted, drafts are dropped and the scope's open buckets close (their users pause until
   **Reopen**). Only the tapping passkey keeps a wrap. Copies of the old wraps in backups then
   expose only values as they were at the copy.
3. **Enable** your other passkeys again from the one that rekeyed (Admin → Passkeys), and test
   them.

## Lost every passkey

Rehearse **on an isolated restore**. Stop the broker, connector, updater and issuer traffic.
Verify the backup digest, host integrity, inventory, audit and serial high-water mark against
independent owner records. Never restore a stale serial allocator to service; rotate the CA if
continuity cannot be proven. Do not use this flow on a suspect host.

1. Restore a **standalone** online backup (no WAL, SHM or journal sidecars) as the database.
   In `[seal]` add `recovery_backup_sha256` (its full-file SHA-256 from the authenticated
   off-host inventory) and `recovery_serial_high_water` (the independently established highest
   SSH serial ever allocated under this CA, an integer). Normal `serve` is fenced while either
   setting is present. If the high-water mark is unknown, rotate the CA instead.
2. Over an independently verified, host-key-pinned private channel with session recording
   off, pipe the identity into the recovery process as the service user:

   ```sh
   aqmasd -require-root-config -config CONFIG seal-recover NEW_PRIVATE_DIRECTORY <identity.txt
   ```

   It checks the database against `recovery_backup_sha256`, opens every scope key from its
   recovery wrap and every bucket and record, and refuses on any failure. There is no master
   key to transfer: the identity itself is the input, read from stdin and wiped.
3. It then creates `NEW_PRIVATE_DIRECTORY` (0700, must not exist) with a private Unix socket
   `broker.sock` and a one-use `ticket` file. No production listener opens. Expose the socket
   **only to the owner's isolated browser** at the configured HTTPS RP origin through a trusted
   local TLS bridge or private forwarding, without redirecting production traffic. Open `/`
   there; only the recovery page is served.
4. Enter the ticket, a nickname for the replacement passkey and the independently recorded
   manifest SHA-256 (the current `manifest_sha256`). Register the replacement (PRF required),
   then tap once per two scopes to **create** its wraps and once per two scopes to **test**
   them. Finally sign the replacement plan: backup digest, serial high-water mark, scopes and
   the credentials it retires. Allow ten minutes; an expired or interrupted attempt needs a
   fresh local session.
5. One transaction stores the new passkey and its wraps, deletes every old passkey (their
   wraps go with them), ends every session, pending request, grant, standing rule, env release,
   signing grant and host admission, and records the transition. The process writes
   `replacement-manifest.json` in the directory and exits.
6. Save `replacement-manifest.json` off-host, confirm the transition committed, set
   `manifest_sha256` to the SHA-256 of that exact file and remove both recovery settings
   atomically. Old DB copies now fail the pin. Restore the listener configuration, start,
   sign in with the replacement and approve as usual (every bucket starts closed).

Hosts must enrol again and receive new admissions. Review policies and admissions before
restoring network access, reconcile outstanding children at their original issuers, and
retire lost root updater pins separately (`aqmasd maint-init --repin`). Recovery does not
change the offline recipient or undo disclosure from earlier backups. Rekey or rotate
upstream secrets if a key, recipient or running daemon may have been exposed.

## Restart alert and memory

Every start closes every bucket. The broker then writes `locked <epoch>` to
`/run/aqmas-lock/seal-status`, so the owner hears that grants needing a bucket are paused.
Install `aqmas-lock-alert.py` root-owned under `/usr/local/libexec/` and the separate
`aqmas-lock-alert.service`. Provision its two root-only files under `/etc/aqmas-alert/`: a
dedicated HTTPS topic URL and an ntfy **publish-only** token scoped to that topic. Neither
belongs to the broker uid. The helper sends only fixed text, never follows redirects,
coalesces by epoch and retries at most five times with backoff; it also reports the service
being down. Test a cold start with the helper starting later and a service-down alert. A
stolen notifier credential permits nuisance alerts, not opening buckets.

Use the shipped `deploy/bastion/aqmasd.service` limits. Key allocations need `mlock`ed,
`MADV_DONTDUMP` pages and fail closed if unavailable; test under the real service uid and
syscall filter. Disable kernel crash dumps, hibernation, VM RAM snapshots and body tracing,
avoid same-uid debugging, and disable swap or encrypt it with nonpersistent boot keys. The Go
heap, HTTP, signer and WebCrypto libraries can make copies outside locked pages. Do not
approve on a suspect host.
