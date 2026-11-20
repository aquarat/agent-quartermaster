# Contract notes from the client workstream (ws/client)

Proposals and clarifications for `docs/API.md`, `docs/HOSTS.md` and `internal/api`. The client
on `ws/client` does **not** depend on any of the proposals below; it implements the contract
as written, and the "assumptions" are what it does where the contract is silent.

## What the client assumes (server workstream: please match or say otherwise)

1. **Server TLS certificate.** The CLI verifies the chain against one pinned anchor (the
   server CA, or a self-signed server leaf), **checks the server name** (an IP SAN for
   `192.0.2.60`; a DNS SAN if a name is used) and **requires the `serverAuth` EKU**. Client
   certificates issued at enrollment should carry `clientAuth` only: if server and client
   certificates came from the same CA, the EKU check is what stops an enrolled host from
   impersonating aqmasd to other hosts. Separate server and client CAs are better still.
2. **The server must send its CA in the TLS chain** (leaf + CA). **Mismatch today:** the
   review found that `ws/server` (`internal/server/pki`, `loadServer`/`TLSConfig`) sends only
   the leaf. Then `--ca-pin <CA fingerprint>` always fails ("chain does not contain the pinned
   CA"), TOFU can only pin the leaf, and every automatic leaf renewal on the server would make
   all enrolled hosts exit 5 until they re-enroll. Fix on the server: append the CA DER to the
   served certificate chain. `--ca-pin sha256:<hex>` is matched
   against the presented chain, and enroll then saves that CA as `server-ca.pem`; later runs
   verify against the saved file. A server that only sends its leaf can only be pinned by the
   leaf's own fingerprint.
3. **Pin format:** `sha256:<hex of SHA-256 over the certificate DER>` (what
   `openssl x509 -noout -fingerprint -sha256` prints, colons allowed).
4. **Long-poll:** the CLI sends `?wait=25s` (Go duration syntax) with a 60 s client timeout and
   honours `poll_after_ms` (clamped to 1..10 s) when an answer comes back early. Transient
   network errors while waiting are retried 5 times with backoff, then exit 5.
5. **Exit codes:** `denied` and `revoked` → 3, `expired` → 4, transport/TLS errors and HTTP
   502/503/504 → 5, Ctrl-C → 130, other `api.Error` codes (including `forbidden`) → 1.
6. **Grant checks the CLI enforces** before anything reaches ssh: `ssh.target_host` and
   `ssh.login_user` equal what was requested; `target_address` is an IP literal (no zone) or a
   DNS name; `1 <= target_port <= 65535`; `certificate` is a single OpenSSH **user**
   certificate for the ephemeral key, currently valid, with a finite `valid before`. Anything
   else is refused and nothing is saved.
7. **`known_hosts_line`:** exactly one entry, optional `@cert-authority` marker, `@revoked`
   refused. The CLI keeps only the key and **writes its own host patterns**
   (`address` or `[address]:port`, plus `aqmas.<target>` for the ssh-config snippet), so the
   server's pattern text is ignored. If the line is absent the CLI falls back to ssh's normal
   known_hosts files (still `StrictHostKeyChecking=yes`) and the ssh-config snippet will not
   work for that target. **Please always send it.**
8. **Enrollment:** the CLI refuses an issued certificate whose public key is not the CSR's key
   or whose CN is not the requested name, and checks it against `ca_cert_pem` when that is
   sent. `ssh_host_key_fingerprints` carries `SHA256:...` fingerprints of
   `/etc/ssh/ssh_host_*_key.pub` (best effort) so the approval page can show them.
9. **Requester:** `pid` is the aqmas process's own pid; `session_id` comes from
   `CLAUDE_SESSION_ID`, else `CLAUDE_CODE_SESSION_ID` (what Claude Code actually exports), else
   `AQMAS_SESSION_ID`. OpenCode is detected by any `OPENCODE*` variable.
10. **TTL:** the CLI refuses `--ttl` outside 1 min .. 8 h before asking.
11. **Cache sharing:** a cached grant for (user, host) is reused by any aqmas process of the
    same Unix user on that host while >= 2 min remain, whatever its `--why`; the owner approved
    access for the host, not for one agent session. Each grant lives in its own directory
    `<cache>/<user>@<host>/g-<request id>/` and `current` is swapped atomically.
12. **ssh is run with `-F none`** plus the options in API.md section 3, `PreferredAuthentications=publickey`,
    so nothing from `~/.ssh/config` (other identities, ControlMaster, ProxyCommand) applies.
13. **Ref:** the CLI prints `Ref <last 6 chars of the id, upper-cased>` with each request and
    enrollment, matching the web UI's `refCode` (ws/web `web/src/app.ts`).
14. **`RequestCreated.status == "approved"`** (standing approval): the CLI fetches the grant at
    once with `GET /v1/requests/{id}` (no `wait`).

## Proposed contract changes

1. **Cancel a request:** `POST /v1/requests/{id}/cancel` (requesting host only) →
   `RequestStatus` with a new status `cancelled`, so Ctrl-C removes the request from the owner's
   queue instead of leaving it pending until it expires. The CLI currently prints that the
   request stays pending.
2. **Show the server CA fingerprint on the bastion:** `aqmasd tls-fingerprint` (and on the
   approval page) printing the `sha256:<hex>` pin, so the owner can check a TOFU prompt or copy
   the value for `aqmas enroll --ca-pin`.
3. **Publish the SSH user CA public key:** `GET /v1/ssh-ca` → `{public_key, fingerprint}`
   (mTLS). Lets the CLI verify grant certificate signatures (today it can only check type, key
   binding and validity) and lets `deploy/hosts/install-host-trust.sh` be fed the right key.
4. **`Requester.ppid`** (optional): the parent pid identifies the agent process better than
   aqmas's own pid.
5. **CLI surface additions** to API.md section 3, already implemented: `aqmas cert [USER@]HOST`
   (make sure a certificate is cached, print paths; used by the ssh-config snippet), `--fresh`
   (ignore the cache), `aqmas list --json`, exit code 130 for Ctrl-C, and the env overrides
   `AQMAS_CONFIG_DIR` / `AQMAS_CACHE_DIR`.
6. **git helper (later):** `aqmas git-ssh` usable as `GIT_SSH_COMMAND`, mapping
   `git@build-box:2222` to the `forgejo` target, so agents can push with a Forgejo grant
   without hand-building ssh options.

## HOSTS.md corrections (from reading Forgejo 17.0.2's source; details in deploy/hosts/forgejo-ca.md)

- `SSH_AUTHORIZED_PRINCIPALS_ALLOW` does **not** map principals to users. Forgejo's built-in
  server looks up each certificate principal as a *principal key registered on a user account*
  (exact string match); `ALLOW` only limits what a user may register. The owner must register
  `alice` once in Forgejo's settings ("Manage SSH Certificate Principals").
- The built-in server appears **not to enforce `source-address`** (inferred, untested). The
  Forgejo grant is therefore usable from any host that obtains the key + certificate until it
  expires; keep Forgejo TTLs short or test before relying on it.
- An unparsable `SSH_TRUSTED_USER_CA_KEYS` value is fatal at Forgejo startup.
