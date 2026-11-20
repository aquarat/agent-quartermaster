# aqmas API contract (milestone 1)

All bodies are JSON (`Content-Type: application/json`), timestamps RFC 3339 UTC, IDs are
opaque strings (ULID). Go types live in `internal/api` and are the source of truth; this file
describes them. Errors: non-2xx with `{"error": "<code>", "message": "<human text>"}`;
codes: `bad_request`, `unauthenticated`, `forbidden`, `not_found`, `conflict`, `expired`,
`denied`, `internal`.

## 1. Agent API (`https://<bastion>:8443`, TLS 1.3, client certificate REQUIRED)

The client certificate (issued by aqmasd's internal client CA at enrollment) identifies the
**host**; its CommonName is the enrolled host name (e.g. `build-box`). Requests are attributed
to that host. The only unauthenticated endpoints are `/v1/enroll` and `/v1/enroll/{id}` (TLS
without client cert, server cert pinned by the CLI on first use / via `--ca-pin`).

### POST /v1/enroll  (no client cert)
`EnrollRequest {hostname, csr_pem, ssh_host_key_fingerprints[]?, note}` ->
`201 EnrollResponse {id, status:"pending", approve_url, poll_after_ms}`.
Owner approves in the web UI (passkey). The proposed hostname must be unique; re-enrolling an
existing name needs the owner to approve a replacement (old cert revoked).

### GET /v1/enroll/{id}  (no client cert; long-poll `?wait=25s`)
-> `EnrollStatus {id, status: pending|approved|denied|expired, client_cert_pem?, ca_cert_pem?}`.
The certificate is returned once; afterwards `status` stays `approved` without the cert.

### POST /v1/requests
`AccessRequest {kind, ssh?: SSHRequest, reason, ttl_seconds, requester: Requester}`

- `kind`: `"ssh"` in M1 (later: `"github"`, `"forgejo"`, `"cloudflare"`, `"http"`).
- `SSHRequest {target_host, login_user, public_key}`: `target_host` is a fleet host name known to
  aqmasd's config (`[[targets]]`), `public_key` is the ephemeral Ed25519 key in authorized_keys
  format.
- `Requester {tool, session_id?, cwd?, pid?, user}`: self-reported context (tool =
  `claude-code` / `opencode` / `owner-cli` / `other`); **untrusted, display only**.
- `reason`: free text, max 500 chars, **untrusted, display only**.
- `ttl_seconds`: requested; server clamps to policy (M1 default 1800, max 28800).

-> `201 RequestCreated {id, status, approve_url, poll_after_ms, expires_at}`
(`status` may already be `approved` if a standing approval matched).

### GET /v1/requests/{id}  (long-poll `?wait=25s`)
Only the requesting host may read its own requests.
-> `RequestStatus {id, kind, status: pending|approved|denied|expired|revoked, decided_at?,
   decision_note?, grant?: Grant}`
`Grant {id, kind, not_before, not_after, ssh?: SSHGrant}`;
`SSHGrant {certificate (OpenSSH cert, authorized_keys format), principals[], target_host,
target_address, target_port, login_user, known_hosts_line?}`.

### GET /v1/grants?active=1
-> `{grants: [GrantSummary]}` for the calling host (no certificates).

## 2. Web API for the approval UI (`http://127.0.0.1:8080`, behind cloudflared + Access)

Session: after Cloudflare Access, the UI authenticates the **owner** with a passkey
(WebAuthn) and gets an HttpOnly, Secure, SameSite=Strict session cookie (8 h). Every
state-changing call additionally requires a **per-action WebAuthn assertion** (below).
Validate the `Cf-Access-Jwt-Assertion` header against the Access app's AUD and team certs when
configured (defence in depth; config `access.team_domain`, `access.aud`).

- `GET  /api/ui/state` -> `{owner: {name, passkeys: n}, pending: [PendingItem], standing: [StandingApproval], recent: [AuditEntry]}`
- `GET  /api/ui/requests/{id}` -> `PendingItem` (full detail)
- `POST /api/ui/requests/{id}/challenge` `{action: "approve"|"deny", ttl_seconds?, standing_hours?}`
  -> `{challenge_id, canonical, public_key: PublicKeyCredentialRequestOptions}` (the UI shows `canonical`)
- `POST /api/ui/requests/{id}/decide` `{challenge_id, assertion: <WebAuthn assertion JSON>}`
  -> `RequestStatus`
- same challenge/decide pair for enrollments: `/api/ui/enrollments/{id}/challenge|decide`,
  standing approvals: `/api/ui/standing/{id}/challenge|revoke`, grants: `/api/ui/grants/{id}/challenge|revoke`.
- Passkeys: `POST /api/ui/passkeys/register/begin {enroll_code?}` -> creation options;
  `POST /api/ui/passkeys/register/finish` -> `{ok}`. The first passkey needs the one-time
  `enroll_code` from `aqmasd passkey-enroll-code`; later ones need a session plus an assertion.
- Login: `POST /api/ui/login/begin` / `POST /api/ui/login/finish` (discoverable credentials).
- `PendingItem {id, kind, created_at, expires_at, requesting_host, requesting_address,
  requester, reason, ssh?: {target_host, login_user, key_fingerprint}, ttl_requested,
  ttl_max, risk: "normal"|"high", similar_recent: n}`

### Approval challenge (the security boundary)
The WebAuthn challenge for an action is `SHA-256(canonical)` where `canonical` is the
UTF-8 JSON (keys sorted, no whitespace) of
`{"v":1,"action":..., "object":"request"|"enrollment"|..., "id":..., "requesting_host":...,
"kind":..., "target":..., "login_user":..., "key_fingerprint":..., "ttl_seconds":...,
"standing_hours":..., "nonce": <32 random bytes b64url>, "issued_at": ...}`.
The server stores `canonical` with the challenge id (valid 2 min, single use), shows the same
fields in the UI, and on `decide` verifies the assertion (user verification required) against
exactly that stored challenge before applying exactly that action. A page served by anyone else
cannot obtain a valid assertion for a different action.

## 3. CLI (`aqmas`) behaviour

- Config `~/.config/aqmas/config.toml` (`server = "https://192.0.2.60:8443"`, pinned server
  CA), client key/cert in `~/.config/aqmas/` (mode 600). `aqmas enroll --name <host>` creates
  them (prints the approve URL, waits).
- `aqmas ssh [user@]host [--ttl 30m] [--why "..."] [-- command...]`: reuse a still-valid
  certificate for (user, host) from `$XDG_RUNTIME_DIR/aqmas/` (or `~/.cache/aqmas/`, 0700);
  otherwise generate an Ed25519 key, `POST /v1/requests`, print the approve URL and a one-line
  summary to stderr, long-poll until decided (Ctrl-C cancels), save key + cert (0600), then
  `exec ssh -o IdentitiesOnly=yes -o IdentityAgent=none -i KEY -o CertificateFile=CERT
  -o UserKnownHostsFile=... user@address command...`. Exit codes: 0/ssh's own, 3 denied,
  4 expired, 5 server unreachable.
- `aqmas ssh-config` prints a `Match exec` snippet so plain `ssh host` can use aqmas (opt-in).
- `aqmas status [id]`, `aqmas list` (active grants), `aqmas version`.
- Requester context: tool auto-detected from env (`CLAUDECODE`, `OPENCODE*`), session id from
  `CLAUDE_SESSION_ID`/`AQMAS_SESSION_ID` if present, else empty; `--why` is required for non-tty use.
