# aqmas API contract (milestone 1, as built)

All bodies are JSON (`Content-Type: application/json`), timestamps RFC 3339 UTC, IDs are
opaque ASCII strings (ULID). Go types live in `internal/api` and are the source of truth; the
web UI mirrors them in `web/src/types.ts`. This file describes them.

Errors: non-2xx with `api.Error` `{"error": "<code>", "message": "<human text>"}`. Codes
(`api.Err*`): `bad_request` (400), `unauthenticated` (401), `forbidden` (403), `not_found`
(404), `conflict` (409: already decided, challenge already used, state changed),
`expired` (410), `rate_limited` (429), `denied`, `internal` (500).

Statuses (`api.Status*`): `pending`, `approved`, `denied`, `expired`, `revoked`, `cancelled`.

The short **Ref** of an item is the last 6 characters of its id, upper-cased. The UI shows it
on every card and the CLI prints it with every request and enrollment, so the owner can match
a card to the terminal that asked (an agent relays `approve_url`, so a highlighted card alone
proves nothing).

## 1. Agent API (`https://<bastion>:8443`)

TLS 1.3. The server presents **leaf + internal CA**; the leaf has the `serverAuth` EKU only
(SANs from `tls_sans`). Host client certificates are issued by the same CA with `clientAuth`
only, and aqmasd refuses its own server certificate as a client identity. The CLI pins the
CA: pin = `sha256:<hex of SHA-256 over the CA certificate DER>`, printed on the bastion by
`aqmasd tls-fingerprint` (the same as `openssl x509 -noout -fingerprint -sha256`, colons
allowed). It verifies the chain to the pin, the server name (IP SAN `192.0.2.60`) and the
`serverAuth` EKU. Because the CA (not the leaf) is pinned, renewing the leaf does not break
enrolled hosts.

The client certificate identifies the **host**: its CommonName is the enrolled host name.
Requests are attributed to that host. Only `/v1/enroll` and `/v1/enroll/{id}` work without a
client certificate; every other endpoint returns 401 without one.

Long-polls: `?wait=25s` (or `?wait=25`), capped at 25 s. `poll_after_ms` says how long to wait
before the next poll when an answer comes back early.

### POST /v1/enroll  (no client cert)
`EnrollRequest {hostname, csr_pem, ssh_host_key_fingerprints[]?, note?, poll_token}` ->
`201 EnrollResponse {id, status:"pending", approve_url, poll_after_ms}`.

- `hostname`: `[a-z0-9][a-z0-9-]{0,62}`; the CSR's CommonName must equal it. CSR key: ECDSA
  P-256 or Ed25519.
- `ssh_host_key_fingerprints`: `SHA256:...` of the host's `/etc/ssh/ssh_host_*_key.pub`
  (best effort; self-reported, anyone can copy them with `ssh-keyscan`: display only).
- `poll_token`: 32-128 random characters the enrolling host keeps. Only polls presenting it
  see the enrollment (below), so someone who learns the id from the approve link or the push
  notification cannot collect the once-only certificate first. The CLI also prints the CSR
  key fingerprint (`client key: SHA256:<hex>`), which the card shows as "Client key".
- `note`: at most 500 bytes.
- If a host of that name is enrolled, approving the enrollment **replaces** it (old client
  certificate revoked at once, its pending requests expired); the card shows risk `high`.
- Limits: 20 pending enrollments in total, 3 per source address (429 `rate_limited`).
  Undecided enrollments expire after `ttl.enrollment_expiry_seconds` (1 h).

### GET /v1/enroll/{id}  (no client cert; long-poll; header `X-Aqmas-Enroll-Token: <poll_token>`)
404 without the right token. ->
`EnrollStatus {id, status: pending|approved|denied|expired, client_cert_pem?, ca_cert_pem?}`.
The certificate is returned once; afterwards `status` stays `approved` without it. The CLI
refuses a certificate whose key is not the CSR's or whose CN is not the requested name, and
checks it against `ca_cert_pem`.

### POST /v1/requests
`AccessRequest {kind, ssh?: SSHRequest, reason, ttl_seconds, requester: Requester}` ->
`201 RequestCreated {id, status, approve_url, poll_after_ms, expires_at}`.

- `kind`: `"ssh"` in M1.
- `SSHRequest {target_host, login_user, public_key}`: `target_host` is a `[[targets]]` name
  in aqmasd's config, `login_user` one of that target's `users`, `public_key` an Ed25519 key in
  authorized_keys format (ephemeral, generated per request by the CLI).
- `Requester {tool, session_id?, cwd?, pid?, user}`: self-reported (`tool` = `claude-code` /
  `opencode` / `owner-cli` / `other`); **untrusted, display only**. `session_id` at most 128
  bytes, `cwd` 1024 (`api.Max*Bytes`; the CLI truncates on a UTF-8 boundary).
- `reason`: at most 500 **bytes** of UTF-8, no control characters; **untrusted, display only**.
- `ttl_seconds`: clamped to `[ttl.min_seconds, min(ttl.max_seconds, target max_ttl_seconds)]`
  (defaults 60 s .. 8 h; 0 means `ttl.default_seconds`, 30 min). The clamped value is the
  card's `ttl_max`: the owner may shorten, never lengthen.
- `status` is already `approved` when a standing approval matched (same host **connecting from
  the same address** as the request the owner approved, same target and login user, TTL within
  the rule's maximum); the CLI then fetches the grant at once.
- At most 5 pending requests per host (429 `rate_limited`). Undecided requests expire after
  `ttl.pending_expiry_seconds` (10 min). Requests from a revoked or replaced host cannot be
  approved and are expired on revoke.
- `approve_url` = `<public_base_url>/#r=<id>` (the UI scrolls to and highlights that card).

### GET /v1/requests/{id}  (long-poll)
Only the requesting host may read its own requests (others get 404).
-> `RequestStatus {id, kind, status, decided_at?, decision_note?, grant?: Grant}`;
`Grant {id, kind, not_before, not_after, ssh?: SSHGrant}`;
`SSHGrant {certificate, principals[], target_host, target_address, target_port, login_user,
known_hosts_line?}`. `known_hosts_line` is sent whenever the target has `host_key` in the
config (aqmasd warns at start for targets without one: pin them all).

### POST /v1/requests/{id}/cancel
Requesting host only (others 404). Withdraws a pending request -> `RequestStatus` with status
`cancelled`; 409 if already decided, 410 if expired. `aqmas` calls it on Ctrl-C.

### GET /v1/grants?active=1
-> `GrantList {grants: [GrantSummary]}` for the calling host (no certificates, no
`requesting_host`).

### GET /v1/ssh-ca
-> `SSHCA {public_key, fingerprint}`: the SSH user CA (authorized_keys format, `SHA256:...`).
The CLI checks every new grant's certificate signature against it.

### The SSH certificate

| field | value |
|---|---|
| type | user certificate for the request's ephemeral Ed25519 key |
| principals | `["<login_user>@<target>"]`, or the target's `principal` (Forgejo) |
| validity | `approved_at - 1 min` .. `approved_at + ttl` |
| critical options | `source-address` = the requesting host's address as seen on the mTLS connection, as a single-host CIDR (`192.0.2.50/32`) |
| extensions | `permit-pty`, `permit-port-forwarding` (no agent or X11 forwarding, no user rc) |
| key id | `aqmas:<grant id>:<requesting host>:<target>` |
| serial | the grant's row id |

## 2. Web API for the approval UI (`http://127.0.0.1:8080`, behind cloudflared + Access)

Static UI: `web/dist` embedded in aqmasd and served at `/` (`index.html` `no-store`, hashed
assets immutable; extension-less paths get `index.html`). CSP: `default-src 'self';
script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self';
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` (no inline
script or style).

**Guards on `/api/`:** every POST needs `X-Aqmas: 1` and `Content-Type: application/json`; a
present `Origin` must equal `public_base_url`; a present `Sec-Fetch-Site` must be
`same-origin` or `none`. When `access.team_domain` and `access.aud` are set, every request
needs a valid `Cf-Access-Jwt-Assertion` for that app (and `access.owner_email`, if set, must
match); sessions are bound to the Access `sub`. With Access off aqmasd logs a loud warning.

**Session:** cookie `__Host-aqmas_session` (HttpOnly, Secure, SameSite=Strict, Path=/, 8 h);
only its SHA-256 is stored. WebAuthn: RP ID = host of `public_base_url`, origin =
`public_base_url`, user verification required, discoverable credentials; WebAuthn session state
lives on the server, keyed by `challenge_id` (no state in cookies).

| endpoint | body | response |
|---|---|---|
| `GET /api/ui/session` (no session needed) | | `UISession {authenticated, owner: {name, passkeys}}` |
| `POST /api/ui/login/begin` | `{}` | `CeremonyBegin {challenge_id, public_key}`; 409 `conflict` when no passkey exists yet (UI shows the enroll-code form) |
| `POST /api/ui/login/finish` | `LoginFinish {challenge_id, assertion}` | `OK {ok}` + session cookie |
| `POST /api/ui/logout` | `{}` | `OK` |
| `POST /api/ui/passkeys/register/begin` | `RegisterBegin`: first passkey `{enroll_code}`; later ones (session) `{challenge_id, assertion}` for a signed `passkey add` | `CeremonyBegin` (creation options; `residentKey` and UV required, `credProps` requested) |
| `POST /api/ui/passkeys/register/finish` | `RegisterFinish {challenge_id, credential, name?}` (`name` = nickname) | `RegisterResult {ok, passkey: PasskeyInfo}` |
| `POST /api/ui/passkeys/challenge` | `{action: "add"}` | `ChallengeResponse` (object `passkey`, id `new`) |
| `POST /api/ui/passkeys/{id}/challenge` | `{action: "rename", nickname}` or `{action: "remove"}` | `ChallengeResponse` (object `passkey`, id `{id}`) |
| `POST /api/ui/passkeys/{id}/rename`, `.../remove` | `DecideRequest` | `PasskeyChange {ok, id, action, nickname, signed_out}` |
| `GET /api/ui/state` | | `UIState {owner, pending: [PendingItem], standing: [StandingApproval], grants: [GrantSummary], recent: [AuditEntry], passkeys: [PasskeyInfo]}` |
| `GET /api/ui/requests/{id}`, `GET /api/ui/enrollments/{id}` | | `PendingItem` plus `status` |
| `POST /api/ui/requests/{id}/challenge` | `ChallengeRequest {action: approve\|deny, ttl_seconds?, standing_hours?}` | `ChallengeResponse {challenge_id, canonical, public_key}` |
| `POST /api/ui/requests/{id}/decide` | `DecideRequest {challenge_id, assertion}` | `RequestStatus` **without** `grant` (browsers never get certificates) |
| `POST /api/ui/enrollments/{id}/challenge` / `decide` | `{action: approve\|deny}` / `DecideRequest` | `ChallengeResponse` / `EnrollStatus` without the certificate |
| `POST /api/ui/standing/{id}/challenge` / `revoke` | `{action: "revoke"}` / `DecideRequest` | `ChallengeResponse` / `RevokeResult {ok, id, status}` |
| `POST /api/ui/grants/{id}/challenge` / `revoke` | `{action: "revoke"}` / `DecideRequest` | `ChallengeResponse` / `RevokeResult` |

`public_key` is always the **bare** WebAuthn options object (the UI also accepts
`{publicKey: ...}`). `assertion` / `credential` are the browser's PublicKeyCredential JSON
(binary fields unpadded base64url; `userHandle` omitted when absent).

- `PendingItem {id, kind: ssh|enrollment, created_at, expires_at, requesting_host,
  requesting_address, requester, reason, ssh?: {target_host, login_user, key_fingerprint},
  enrollment?: {csr_fingerprint, ssh_host_key_fingerprints[], replaces_existing}, ttl_requested,
  ttl_max, risk: normal|high, similar_recent, status?}`. For enrollments `requesting_host` is
  the proposed name, `reason` the enroll note, the TTL fields 0, and `risk` `high` when it
  replaces a host. `similar_recent` counts the host's requests for the same target and user in
  the last 7 days.
- `GrantSummary` in `UIState.grants` carries `requesting_host` (active grants, newest first).
- `PasskeyInfo {id, nickname, authenticator, icon, aaguid, transports[], backup_eligible,
  backup_state, sign_count, created_at, last_used_at?, current}`: `id` is the hex of the first
  16 bytes of SHA-256(credential ID); `authenticator`/`icon` come from the AAGUID via an
  embedded copy of the community passkey-authenticator-aaguids list (`internal/server/aaguid`;
  "Unknown authenticator" for all-zero or unlisted AAGUIDs: with `none` attestation the AAGUID
  is the authenticator's unverified claim, display only); `backup_eligible` = a synced passkey,
  otherwise device-bound; `current` = the passkey this session signed in with. `last_used_at`
  and `sign_count` update on every assertion (sign-in and signed actions).
- **Nicknames:** trimmed, 1-64 UTF-8 bytes, no control/format/private-use/separator characters,
  unique ignoring case (409 `conflict` on a rename to a taken name; at registration a taken or
  empty name is made unique with " 2", " 3"...). An empty `name` at registration means the
  authenticator's name ("Bitwarden"), or "Passkey N" when unknown. Migration 3 names existing
  unnamed passkeys "Passkey 1", "Passkey 2", ... in registration order.
- **Passkey rename/remove** are signed actions like approvals. The endpoint's verb must equal
  the signed `action` (400 otherwise), the challenge is bound to the passkey's id, and on apply
  the passkey must still have the signed `nickname` (409 otherwise). Removing the **last**
  passkey is refused (409) both when the challenge is asked for and inside the apply
  transaction. Removing a passkey ends every web session that signed in with it; when that is
  the calling session, `signed_out` is true and the cookie is cleared. Each change is audited
  (`passkey_register`, `passkey_rename`, `passkey_remove`, object `passkey:<id>`) and pushed
  to ntfy, as is every new passkey.
- **TTL choice:** `ttl_seconds` above the card's `ttl_max` or below `ttl.min_seconds` is
  **rejected with 400**, never clamped (a clamped value in `canonical` would differ from the
  owner's choice). `standing_hours` above `ttl.max_standing_hours` (24) -> 400; the UI offers
  1, 4 or 8. A standing approval auto-approves later requests from the same host for the same
  target and login user, from the same address, up to its TTL, until it expires or is
  revoked; revoking a grant also revokes the standing approval created with it and the one
  that auto-approved it. Standing approvals are refused (400) for high-risk requests: a
  `high_risk` target, login user `root`, or a TTL above 4 h (the UI does not offer them there).
- After every decision aqmasd pushes what it **applied** to ntfy
  (`aqmas: approve ssh alice@db-1 for hosta, ttl 300s, standing 1h [ref ABC123]`), so a
  page that showed something else is noticed on the phone.

### Approval challenge (the security boundary)

The WebAuthn challenge for an action is `SHA-256(canonical)` (go-webauthn `WithChallenge`),
where `canonical` is UTF-8 JSON with keys sorted (bytewise; all keys ASCII), no whitespace, no
HTML escaping, values only strings, integers and booleans, and **exactly** this key set per
object (a missing or extra key cannot be built by the server and is refused by the UI):

| object | actions | keys besides `v` (1), `action`, `object`, `id`, `nonce` (32 random bytes, base64url), `issued_at` |
|---|---|---|
| `request` | `approve`, `deny` | `requesting_host, kind, target, login_user, key_fingerprint, ttl_seconds, standing_hours` |
| `enrollment` | `approve`, `deny` | `requesting_host, kind` (`"enrollment"`), `key_fingerprint` (CSR key), `replaces`, `ttl_seconds` (0), `standing_hours` (0) |
| `standing` | `revoke` | `requesting_host, kind, target, login_user, ttl_seconds` (the rule's max TTL), `standing_hours` |
| `grant` | `revoke` | `requesting_host, kind, target, login_user, ttl_seconds` (0), `standing_hours` |
| `passkey` | `add`, `rename`, `remove` | `nickname` (the passkey's current nickname; `""` for add), `new_nickname` (rename: the new one; otherwise `""`). For add `id` is `"new"`, otherwise the passkey's id |

Fingerprints: SSH keys `SHA256:<base64>` (OpenSSH style), CSR keys `SHA256:<hex>` of the PKIX
public key. Deny and revoke carry `standing_hours` 0.

The server stores `canonical` with the challenge (valid 2 min, single use, bound to the
session), and on `decide` verifies the assertion (user verification required, origin, RP ID,
sign count) against exactly that challenge, re-parses the stored text and applies exactly it.
For enrollments it refuses (409) if `replaces` no longer matches whether a host of that name
exists.

Before calling `navigator.credentials.get` the UI (`web/src/canonical.ts`, `flows.ts`) checks
that `canonical` re-serialises byte for byte, has only the known keys for its object, that
`SHA-256(canonical)` equals the options' challenge, and that every field equals what the owner
chose and the card showed (action, object, id, host, kind, target, login user, key/CSR
fingerprint, `replaces`, TTL, standing hours, passkey nickname and new nickname). The text
shown at confirmation is rendered from the canonical fields only (each value isolated in
`<bdi>`, invisible/bidi characters shown as `⟨U+XXXX⟩`, names outside `[A-Za-z0-9._-]`
flagged).

## 3. CLI (`aqmas`)

- Config `~/.config/aqmas/config.toml` (`server`, `server_ca` + `server_ca_sha256` pin,
  `host_name`, `client_cert`, `client_key`, `client_ca`, `default_ttl`); key and certificate
  in the same directory (0600, directory 0700). Overrides: `AQMAS_CONFIG_DIR`,
  `AQMAS_CACHE_DIR`.
- `aqmas enroll --name HOST [--server URL] [--ca-pin sha256:HEX] [--note TEXT] [--force]`:
  creates the client key + CSR, prints the approve URL and Ref, waits. Without `--ca-pin`, the
  CA is trusted only after the user confirms its fingerprint at a terminal.
- `aqmas ssh [USER@]HOST [--ttl 30m] [--why "..."] [--fresh] [-- COMMAND...]`: reuses a cached
  certificate for (user, host) from `$XDG_RUNTIME_DIR/aqmas/` (or `~/.cache/aqmas/`) while at
  least 2 min remain, whichever aqmas process of the same Unix user requested it (the owner
  approved access for the host, not for one agent session), after asking the server that its
  request is still `approved` (a revoked grant is not reused; if the server is unreachable the
  cached certificate is used with a warning); otherwise generates an Ed25519 key,
  `POST /v1/requests`, prints the approve URL and a one-line summary with the Ref, long-polls
  (Ctrl-C cancels the request), checks the grant (target, user, address, port, certificate
  key, validity, signer = `GET /v1/ssh-ca`), saves it (0600, one directory per grant, `current`
  swapped atomically) and execs
  `ssh -F none -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey
  -i KEY -o CertificateFile=CERT -o UserKnownHostsFile=<grant's known_hosts>
  -o StrictHostKeyChecking=yes -p PORT -- user@address command...`. The CLI writes its own
  known_hosts patterns from `known_hosts_line`'s key (`address` / `[address]:port` and
  `aqmas.<target>`); without the line it falls back to ssh's normal known_hosts files.
  `--ttl` outside 1 min .. 8 h is refused locally. `--why` is required when stdin is not a
  terminal.
- `aqmas cert [USER@]HOST [...] [--quiet]`: like `ssh` but only makes sure a certificate is
  cached and prints its paths (used by the `ssh-config` snippet).
- `aqmas ssh-config [USER@]HOST...` prints an opt-in `Match exec` snippet.
- `aqmas status [ID]`, `aqmas list [--json]`, `aqmas version`.
- Exit codes: 0 / ssh's own, 1 error, 2 usage, 3 denied or revoked, 4 expired, 5 server
  unreachable / TLS failure / HTTP 502-504, 130 cancelled (Ctrl-C, or the request was cancelled).
  Transient network errors while waiting are retried 5 times with backoff, then exit 5.
- Requester context: tool from env (`CLAUDECODE` -> `claude-code`, any `OPENCODE*` ->
  `opencode`, a terminal -> `owner-cli`, else `other`); `session_id` from `CLAUDE_SESSION_ID`,
  `CLAUDE_CODE_SESSION_ID` or `AQMAS_SESSION_ID`; `pid` is aqmas's own pid.

## 4. aqmasd commands (on the bastion, as user `aqmas`)

`serve`, `passkey-enroll-code` (one-time code, 15 min, single use, for the first passkey),
`print-ssh-ca` (for `TrustedUserCAKeys`), `print-client-ca` (internal CA PEM),
`tls-fingerprint` (the `--ca-pin` value), `revoke-host NAME` (revoke a host's client
certificate at once; there is no web action for this in M1), `version`.
