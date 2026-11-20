# Contract notes from the server workstream (`ws/server`)

What aqmasd implements where docs/API.md or `internal/api` is silent, how it matches
`docs/CONTRACT-NOTES-web.md` (ws/web) and `docs/CONTRACT-NOTES-client.md` (ws/client), and the
changes proposed to the shared contract. Nothing in `internal/api` or `docs/API.md` was changed on
this branch; types the UI/CLI need beyond `internal/api` are local wrappers in
`internal/server/web.go` / `agent.go`.

## Web API (matches ws/web's notes unless stated)

1. **Approve URLs** are `https://<base>/#r=<id>` for requests and enrollments (the UI highlights
   the item; no server routing). Extension-less paths still get `index.html` (no-store).
2. **Ceremonies** (web notes section 1): `login/begin {}` -> `{challenge_id, public_key}`,
   `login/finish {challenge_id, assertion}` -> `{ok}` + cookie `__Host-aqmas_session` (HttpOnly,
   Secure, SameSite=Strict, Path=/, 8 h; only its SHA-256 is stored).
   `passkeys/register/begin {enroll_code}` (first passkey only) or `{challenge_id, assertion}`
   (later ones, session required) -> `{challenge_id, public_key}`;
   `passkeys/register/finish {challenge_id, credential}` -> `{ok}`. `public_key` is the **bare**
   options object (the UI accepts bare or `{publicKey}`). `login/begin` -> 409 `conflict` when no
   passkey exists. A `finish` without `challenge_id` is refused: the server keeps no WebAuthn
   state in cookies.
3. **Later passkeys:** `POST /api/ui/passkeys/challenge {action:"add"}` -> canonical
   `{"action":"add","id":"new","issued_at":..,"nonce":..,"object":"passkey","v":1}`.
4. Registration requests the `credProps` extension itself, because the UI always asks for it and
   go-webauthn rejects unsolicited extension outputs.
5. `GET /api/ui/session` (no session) -> `{authenticated, owner:{name, passkeys}}`;
   `POST /api/ui/logout {}`.
6. **`UIState`** adds `grants: [GrantSummary + requesting_host]` (active, newest first).
   Pending enrollments carry `enrollment: {csr_fingerprint, ssh_host_key_fingerprints[],
   replaces_existing}` and `risk:"high"` when replacing. `GET /api/ui/requests/{id}` and
   `GET /api/ui/enrollments/{id}` return the item plus `status`.
7. **Canonical text** (web notes section 5): sorted keys (built from a map, keys ASCII), no
   whitespace, no HTML escaping, exactly the per-object key set below (missing or extra keys are
   impossible to build or parse; setting a field on an object that doesn't carry it is an error):
   - common: `v, action, object, id, nonce, issued_at`
   - request: `requesting_host, kind, target, login_user, key_fingerprint, ttl_seconds, standing_hours`
   - enrollment: `requesting_host, kind ("enrollment"), key_fingerprint, replaces, ttl_seconds (0), standing_hours (0)`
   - standing / grant: `requesting_host, kind, target, login_user, ttl_seconds, standing_hours`
     (standing: `ttl_seconds` = the rule's max TTL; grant: 0)
   - passkey: common only.
   Challenge = SHA-256(canonical), passed to go-webauthn with `WithChallenge`. On decide the
   server re-parses the stored text and applies exactly it; for enrollments it refuses (409) if
   `replaces` no longer matches whether a host of that name exists.
   Fingerprints: SSH keys `SHA256:<base64>` (OpenSSH), CSR keys `SHA256:<hex>` of the PKIX key.
8. **TTL choice:** a `ttl_seconds` above the request's (clamped) TTL, or below `min_seconds`, is
   **rejected with 400**, never clamped. `standing_hours` above `max_standing_hours` (24) -> 400.
   `ttl_max` in `PendingItem` = the request's clamped TTL.
9. **Decide responses:** request -> `RequestStatus` without `grant` (browsers never get
   certificates); enrollment -> `EnrollStatus` without the cert; revoke -> `{ok, id, status}`.
10. POSTs need `X-Aqmas: 1` and `Content-Type: application/json`; a present `Origin` must equal
    `public_base_url` and a present `Sec-Fetch-Site` must be `same-origin`/`none`.
11. **CSP:** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; ...;
    frame-ancestors 'none'` (no inline script/style). Hashed assets (`name-<hash>.ext`) are
    `immutable`, `index.html` is `no-store`. Checked with ws/web's real `web/dist`.
12. **Errors:** 401 `unauthenticated`, 403 `forbidden` (bad assertion, CSRF), 404 `not_found`,
    409 `conflict` (already decided/used challenge), 410 `expired`, 429 (code `conflict`) for
    more than 20 pending enrollments.

Verified by `TestUIFlows`: it runs ws/web's own `web/src/flows.ts` + `api.ts` under Bun with a
real signing software authenticator against this server (register, login, enrollment approve,
SSH approve with standing approval, revoke standing, revoke grant, add a second passkey), while
the Go test plays the fleet host. `AQMAS_WEB_DIR=<web checkout> go test ./internal/server -run TestUIFlows`.

## Agent API (matches ws/client's notes)

1. The TLS handshake serves **leaf + internal CA**. Pin: `aqmasd tls-fingerprint` ->
   `sha256:<hex of SHA-256 over the CA DER>`. The leaf has `serverAuth` only (SANs from
   `tls_sans`), host client certs `clientAuth` only; aqmasd also refuses its own server cert as a
   client identity. One CA signs both (separate CAs would be cleaner; the EKU split is what the
   CLI checks, so M1 keeps one).
2. `POST /v1/requests/{id}/cancel` (requesting host only; others get 404) -> `RequestStatus`
   with status **`cancelled`** (pending only; otherwise 409/410). Proposed: `api.StatusCancelled`.
3. `GET /v1/ssh-ca` (mTLS) -> `{public_key, fingerprint}`.
4. `known_hosts_line` is sent whenever the target has `host_key` in the config; aqmasd logs a
   warning at start for targets without one. Pin every target's host key.
5. `?wait=` accepts `25s` or `25`, capped at 25 s. Another host's request -> 404.
6. `source-address` is a single-host CIDR (`192.0.2.50/32`).

## Forgejo

`[[targets]]` takes `principal = "alice@forgejo"` (overrides `<login_user>@<target>`; the
Forgejo user must register that exact string under "Manage SSH Certificate Principals");
`forgejo_user` from HOSTS.md is an alias. **The principal must contain `@`**: a bare `alice`
would also log in as `alice` on any host that trusts the CA without an
`AuthorizedPrincipalsFile` (security review finding). HOSTS.md's `forgejo_user = "alice"`
is therefore refused by config validation. `max_ttl_seconds` caps a target's TTL (example config: 1 h for
Forgejo, whose built-in server probably ignores `source-address`).

## Security review (independent sub-agent) and what changed

- Accepted residual, wider than DESIGN.md says: whoever can change the Cloudflare zone (Workers,
  Snippets, DNS, the tunnel) controls the approval page's code and can show one action while
  having another signed. A Cloudflare token on another host is readable by the agents' user, not only
  by root. Mitigation added: after every decision aqmasd pushes what was **applied**
  (`aqmas: approve ssh alice@db-1 for hosta, ttl 300s, standing 1h [ref ABC123]`) to ntfy,
  so a mismatch shows on the phone. Real fix: narrow that token or host the UI on a zone it
  can't edit (owner's decision).
- Fixed: bare Forgejo principal (above); requests of a revoked/replaced host can no longer be
  approved and are expired on revoke; at most 5 pending requests per host and 3 pending
  enrollments per address (429); revoking a grant also revokes the standing approval created
  with it; `aqmasd revoke-host NAME` (bastion CLI; a web action needs a new canonical object the
  UI doesn't know yet); Access: optional `owner_email` check, sessions bound to the Access `sub`,
  loud warning when Access is off; long-polls no longer write to the DB; Access key fetch
  failures back off; rejected enroll codes are logged, not audited.
- Not changed: one CA for server and client certificates (EKU split; the CLI checks
  `serverAuth`); cloudflared runs as root (packaged default); no outbound IP filter on aqmasd
  (it needs ntfy and the Access certs).

## Proposed changes to `internal/api` / `docs/API.md` / `docs/DESIGN.md`

- `api.StatusCancelled = "cancelled"`; `POST /v1/requests/{id}/cancel`; `GET /v1/ssh-ca`.
- `ChallengeRequest.Action`: `approve | deny | revoke | add`.
- `PendingItem.Enrollment *PendingEnrollment {csr_fingerprint, ssh_host_key_fingerprints, replaces_existing}`;
  `GrantSummary.RequestingHost`; `UIState.Grants []GrantSummary`.
- Ceremony types: `CeremonyBegin {challenge_id, public_key}`, `LoginFinish {challenge_id, assertion}`,
  `RegisterBegin {enroll_code?, challenge_id?, assertion?}`, `RegisterFinish {challenge_id, credential}`,
  `UISession {authenticated, owner}`.
- API.md: document the per-object canonical key sets above (they replace the single key list),
  the `replaces` field, approve URL `/#r=<id>`, error code `rate_limited` (429).
- DESIGN.md / HOSTS.md: Forgejo principal via `principal`; host names `[a-z0-9-]`.

## Disagreements / not adopted

- **Bare begin responses without `challenge_id`** (web notes section 1, fallback): not
  implemented; WebAuthn session state lives server-side keyed by `challenge_id`.
- **`Requester.ppid`** (client proposal 4): not added to the server (needs `internal/api`).
- Separate server and client CAs: deferred (see agent API item 1).
