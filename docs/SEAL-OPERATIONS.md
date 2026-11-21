# Sealed-store import and recovery

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

### Post-import operational checks

Record the original **effective** systemd credential name → absolute source
path mappings in a root-owned JSON object before maintenance (`{}` for none).
After retirement and unit reload run `seal-preflight.py CONFIG SOURCES.json`
as root, before starting the unit. Verify old copies and disabled credentials
against that inventory too. The daemon cannot discover previously removed
root-only mappings. The system unit requires root-protected config ancestors;
use `-require-root-config` for production maintenance commands as well.

In Admin, add a second independently held unlock-capable key. Sign its
nickname and capability, register, evaluate the new ID twice, then cold-test
it. Approve-only credentials never unlock. Inspect the agent TLS leaf expiry
on the broker card and sign renewal well before expiry. A failed or missing
leaf leaves the web surface reachable: unlock, review the CA pin and SANs,
sign **Renew leaf and restart locked**, then unlock again. If the old key is
inaccessible, repair its ownership/mode or remove the retired leaf key in
maintenance. Never remove a CA or disable TLS verification to repair a leaf.

### Loss of all working owner credentials

Rehearse **on an isolated restore**. Stop the broker, connector, updater and
issuer traffic; verify the backup digest, host integrity, inventory, audit and
serial high-water mark against independent owner records. Never restore a
stale serial allocator to service; rotate the CA if continuity cannot be
proven. Keep the complete backup untouched. Verify all expected env sets are
present, not just that the database opens. Do not use this flow on a suspect
host. The identity stays on a trusted Linux owner system. Over an independently
verified, host-key-pinned private channel, with session recording disabled,
pipe `aqmasd seal-transfer BUNDLE EXPECTED_SHA256 EXPECTED_RECIPIENT
<identity.txt` directly into `aqmasd -require-root-config -config CONFIG
seal-recover NEW_PRIVATE_DIRECTORY` as the service user. Never redirect the
transfer output to a file. It is the MK. Prefer running both sides on one
isolated trusted recovery system for the drill. Restore a **standalone** backup
with no WAL/SHM/journal sidecars. Before invoking recovery, pin its full-file
SHA-256 from the authenticated off-host inventory in `[seal]` as
`recovery_backup_sha256`, and the independently established highest SSH serial
ever allocated under this CA as `recovery_serial_high_water` (integer). Normal
serve is fenced while either recovery setting is present. Do not derive the
high-water mark from a potentially stale backup. If it is unknown, rotate
the CA rather than reusing the allocator.

Recovery verifies the MK/key-check, import inventory and each current env
revision before accepting a replacement. Only a private Unix `broker.sock`
is opened, with a one-use `ticket` file in the new 0700 directory. Expose the
socket **only to the owner's isolated browser** at the configured HTTPS RP
origin via a trusted local TLS bridge / private forwarding, without redirecting
production traffic. Open `/` on this privately mapped origin; only the recovery
listener serves the ticket-entry page. Enter the operator ticket, new nickname
and the independently recorded manifest SHA-256. No ordinary owner login,
public enroll code, Access JWKS fetch or recovery secret is needed in this
browser. Complete registration, both fresh PRF evaluations and the separate UV
signature on the replacement and retirement plan. Allow ten minutes; expired
or interrupted uncommitted attempts require a fresh local session.

Compare the signed backup digest and serial with the independent records. After
commit the recovery process exits. Save `replacement-manifest.json` off-host,
confirm the DB transition committed, replace the root `manifest_sha256` with
the SHA-256 of that exact file and remove both recovery settings atomically.
On interruption, compare the staged transition against the DB; a staged file
alone is not proof of commit. Old sealed DB copies now fail the root pin. Restore the original listener
configuration, cold start, sign in and unlock using the replacement key.
All old login keys, wraps and sessions are retired; hosts must enroll again
and receive new signed admissions. Review policies/admissions before restoring
network access, reconcile outstanding children at their original issuers,
and retire lost root updater pins separately. Recovery does not change the
offline recipient or undo disclosure from earlier backups. A stolen key,
recipient or running daemon requires rotation of underlying secrets as well.

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
