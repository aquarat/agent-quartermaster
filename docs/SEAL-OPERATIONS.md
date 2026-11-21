# Sealed-store import and recovery drill (phase 1)

This is a **supervised format transition**, not an automatic update or a
fresh-install wizard. Use a compatible binary with the embedded UI. Rehearse
on an isolated installation first. The input is an existing, activated
personal catalogue (schema 6 or 7), at least one registered passkey, and the
matching CA files. Schema 8 is committed only by a signed activation. Do not
enable this on the strength of a successful WebAuthn *login*.

1. Keep independent emergency access. Stop updater activation, stop and drain
   the daemon and reconcile any outstanding upstream children with their
   original issuer. Keep the current binary, an independently encrypted SQLite
   online backup, protected config and keys. Record the SSH CA fingerprint,
   internal CA pin, serial high-water mark, config version and backup digest
   off-host. Do not let a service manager restart legacy issuance during setup.
2. On a trusted owner system generate a **dedicated native age X25519**
   identity (`umask 077; age-keygen -o identity.txt`). Keep that file and an
   independently protected spare offline. Only the `age1…` public recipient
   goes in the bastion config. Do not use an SSH key, passphrase recipient or
   `-pq`. This identity plus a matching sealed backup can decrypt every imported
   secret. Never paste it in the web page or send it to the daemon.
3. In the existing **root-owned** config in a non-service-writable directory,
   add `[seal]`, `required = true`, `recipient = "age1…"` (the complete
   recipient), initially without `manifest_sha256`. This fences `serve` even
   against a restored pre-seal DB. Old binaries reject this config. Supply the
   reviewed old credentials to **maintenance only**. Run `aqmasd -config CONFIG
   seal-import` as the service user at its existing RP origin. No agent API,
   issuer worker or update poller runs in this mode. Keep all source paths and
   directories operator-controlled for the entire maintenance interval.
4. Sign in and select the passkey to wrap the installation MK. Review the RP,
   installation, full credential ID and purpose. Complete **both** independent
   UV evaluations (create wrap, test wrap). An older credential might need a
   replacement registered with PRF enabled: if either evaluation fails, stop
   setup and retry before retiring anything. No automatic downgrade or switch
   to plaintext. The stage MK exists only in this process; restarting a failed
   *uncommitted* import starts a new stage. Discard artifacts from the old one.
5. Copy `seal-stage-*/inventory.json` from this particular setup over a
   separately authenticated operator channel to an isolated trusted Linux
   machine. Compare the SHA-256 and recipient with the **local operator view**.
   Using the compatible binary and the digest and recipient from that record:

   ```sh
   umask 077
   aqmasd seal-drill inventory.json "$EXPECTED_SHA256" "$RECIPIENT" \
       <identity.txt >recovery.proof
   ```

   The drill decrypts the age packet, checks installation/generation, opens
   the MK key-check and authenticates every staged payload. Its one-line output
   is an acknowledgement bound to this exact inventory; it cannot unlock the
   web service. Return only `recovery.proof`, as a service-owned 0600 file in
   the matching stage directory. No recovery material in browser, argv, logs
   or shell history. Repeat periodically against an independently inventoried
   backup; do not infer backup provenance from matching database rows.
6. Compare the entire activation manifest and its SHA-256 in the browser with
   the local `manifest.json` and independent pins. Check all roles, CF service,
   account and issuer, TLS leaf exception, recovery recipient and tested wrap.
   Sign **Activate sealed installation**. The version, records, credential
   wrap, signed transition and audit commit atomically. The process exits.
   A crash with `user_version=8` is **after** activation: finish only the
   matching pinned transition. Never lower the schema number or remove the
   root gate to bypass recovery.
7. Save the manifest digest, installation, generation and recipient off-host.
   Atomically install and sync `manifest_sha256 = "…"` in the root `[seal]`
   config. **Before restart**, remove `ntfy.topic_url` from the config, unlink
   both retired private CA files (`ssh_user_ca`, `client_ca.key`), remove both
   CF parent source files and their `LoadCredential=` entries. Leave the
   *names of the references* in the signed public CF profile: they are not
   loaded by sealed `serve`. Root-owned sources and config are deliberately
   retired by the operator, not deleted by a web request. Retain the public
   SSH CA and internal CA cert plus `server.crt` and private 0600 `server.key`
   in the service's 0700 CA directory. Removing or invalidating the leaf
   disables the agent listener; there is no fallback to plaintext HTTP.
8. Cold start: verify health and **Locked** in the approval UI. Test one
   passkey unlock, enrollment/SSH issuance and the configured proxy. Use
   **Lock now** and verify the supervisor restarts locked. Take an encrypted
   post-activation online backup, including the leaf, matching root pin and
   offline inventory. On updates or compatible rollback, `/healthz` may
   succeed while locked; unlock in a **separate** ceremony after reconnecting.
   Leave unattended updates disabled until the restore and restart drill works.

Unlinking files does **not** erase SSD blocks, WAL, snapshots, copied configs
or backups. Restrict/expire or cryptographically erase retired backups. Rotate
the ntfy capability and both parents upstream (first resolve children issued
by the old minter). For CA replacement distribute both public SSH keys, move
issuance, test and retire old trust on every target. Replacing the internal CA
requires independent pin distribution and new leaf/client identities. Changing
a wrap alone does not revoke material in a stolen backup. Never run a stale
pre-revocation database as a rollback. On suspected compromise rebuild and
reconcile independent host, grant, passkey, audit and issuer records before
allowing fleet access. See [SEALED.md](SEALED.md#operations-and-recovery).

### Lock alerts and memory

Use the provided `deploy/bastion/aqmasd.service` limits. Key allocations need
dedicated `mlock`/`MADV_DONTDUMP` pages and fail closed if unavailable; test
under the real service uid and syscall filter. Disable kernel crash dumps,
hibernation, VM RAM snapshots and body tracing, avoid same-uid debugging,
disable swap or encrypt it with nonpersistent boot keys. The Go heap, HTTP,
signer and WebCrypto libraries can make copies outside locked pages. Do not
unlock a suspect host.

Install `aqmas-lock-alert.py` root-owned under `/usr/local/libexec/` and the
separate `aqmas-lock-alert.service`. Provision its two root-only credential
files under `/etc/aqmas-alert/`: a dedicated HTTPS topic URL and an ntfy
**publish-only** token scoped only to that topic. Neither file belongs to the
broker uid. The helper reads bounded public metadata in `/run/aqmas-lock`,
sends only fixed text, never follows redirects, coalesces by boot generation,
and retries at most five times with backoff. Test both a cold start with the
helper starting later and a service-down alert. Check the helper's journal
for delivery failures. A stolen notifier credential permits nuisance alerts,
not unlocks or normal approval notifications. A crash can lose coalesced
ordinary notices; the durable decision queue/audit remains authoritative.
