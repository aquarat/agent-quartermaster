# Contract notes from the server workstream (`ws/server`)

What aqmasd implements where docs/API.md or `internal/api` is silent or ambiguous, plus the changes
proposed to them. Nothing in `internal/api` or `docs/API.md` was changed on this branch.

## Implemented beyond the written contract (web UI needs these)

1. **Approve URLs** are `https://<base>/requests/<id>` and `https://<base>/enrollments/<id>`.
   aqmasd serves `index.html` (no-store) for any extension-less path, so these are SPA routes.
2. **Login / passkey ceremonies** (shapes were unspecified):
   - `POST /api/ui/login/begin {}` -> `{challenge_id, public_key}`; `public_key` is the inner
     `PublicKeyCredentialRequestOptions` JSON (base64url fields, empty `allowCredentials`,
     `userVerification: "required"`).
   - `POST /api/ui/login/finish {challenge_id, assertion}` -> `{ok:true}` + session cookie
     `__Host-aqmas_session` (HttpOnly, Secure, SameSite=Strict, Path=/, 8 h).
   - `POST /api/ui/passkeys/register/begin {enroll_code}` (first passkey) or
     `{challenge_id, assertion}` (later passkeys, session required) -> `{challenge_id, public_key}`
     where `public_key` is `PublicKeyCredentialCreationOptions` (resident key + UV required,
     attestation none, existing credentials excluded).
   - `POST /api/ui/passkeys/register/finish {challenge_id, credential, name?}` -> `{ok:true}`
     (`attestation` / `assertion` accepted as aliases of `credential`).
   - Later passkeys: `POST /api/ui/passkeys/challenge {action:"register"}` -> `ChallengeResponse`
     (canonical `object:"passkey"`, `id:"new"`, `kind:"passkey"`); its assertion goes into
     `register/begin`.
3. `GET /api/ui/session` (no session needed) -> `{authenticated: bool, owner: {name, passkeys}}`,
   so the UI can choose between "register with enroll code", "log in" and the dashboard.
4. `POST /api/ui/logout {}` -> `{ok:true}`.
5. `GET /api/ui/enrollments/{id}` -> `PendingItem` (`kind:"enrollment"`, `requesting_host` = the
   proposed hostname, `reason` = note, `risk:"high"` when it replaces an existing host) plus
   `status`, `key_fingerprint`, `ssh_host_key_fingerprints`. `GET /api/ui/requests/{id}` adds
   `status`. Both work for decided objects too.
6. **Decide responses:** requests -> `RequestStatus` **without** `grant` (the browser never gets a
   certificate); enrollments -> `EnrollStatus` without the cert; standing/grant revoke ->
   `{ok:true, id, status:"revoked"}`.
7. **Every web POST** needs `X-Aqmas: 1` and `Content-Type: application/json`; a present `Origin`
   must equal `public_base_url`, a present `Sec-Fetch-Site` must be `same-origin`/`none`.
8. **CSP** is `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; ...;
   frame-ancestors 'none'`: no inline `<script>`, no inline `<style>` and no `style="..."`
   attributes. Tell the server workstream if the UI needs a hash-based exception.
9. **Canonical text:** all 13 keys are always present (`v, action, object, id, requesting_host,
   kind, target, login_user, key_fingerprint, ttl_seconds, standing_hours, nonce, issued_at`);
   unused ones are `""` / `0`. `issued_at` is RFC 3339 UTC with seconds. Per object:
   - request: SSH key fingerprint `SHA256:<base64>` (OpenSSH style); `ttl_seconds` = the TTL that
     will be issued (requested, or the approver's shorter choice); deny has ttl/standing 0.
   - enrollment: `kind:"enrollment"`, `requesting_host` = proposed hostname, `key_fingerprint` =
     `SHA256:<hex>` of the CSR's PKIX public key.
   - standing revoke: host/kind/target/login_user of the rule, `ttl_seconds` = its max TTL.
   - grant revoke: host/kind/target/login_user of the grant.
   The server re-parses the stored canonical text on decide and applies exactly that.
10. **Status codes:** `expired` -> 410; `conflict` -> 409 (already decided, unknown or used
    challenge); too many pending enrollments (20) -> 429 with code `conflict`; missing/invalid
    session -> 401 `unauthenticated`; failed assertion -> 403 `forbidden`; another host's request
    -> 404 `not_found` (indistinguishable from missing).
11. `?wait=` accepts `25s` or `25`; capped at 25 s.
12. `PendingItem.ttl_max` = the (clamped) requested TTL, since the approver can only shorten.
    `risk:"high"` for `login_user = root`, `high_risk = true` targets, or TTL > 4 h.
13. `GrantSummary.status` is `approved`, `expired` or `revoked`. Revoking a grant also turns its
    request's status into `revoked`.
14. `source-address` is written as a single-host CIDR (`192.0.2.50/32`, `.../128`).
15. **Forgejo principal:** for targets with `forgejo_user` the certificate principal is that user
    name (HOSTS.md), not `<login_user>@<target>` (DESIGN.md's general rule).

## Proposed changes to `internal/api` / `docs/API.md`

- `ChallengeRequest.Action` comment: add `register` (passkeys).
- `PendingItem`: add `Status string` and
  `Enrollment *PendingEnrollment {key_fingerprint, ssh_host_key_fingerprints[], replaces_existing}`
  instead of the ad-hoc extra fields in item 5.
- Add types for the ceremonies in item 2 (`CeremonyBegin {challenge_id, public_key}`,
  `LoginFinish {challenge_id, assertion}`, `RegisterBegin {enroll_code?, challenge_id?, assertion?}`,
  `RegisterFinish {challenge_id, credential, name?}`) and `UISession {authenticated, owner}`.
- Add error code `rate_limited` (HTTP 429) to the list.
- DESIGN.md: say explicitly that Forgejo grants use `forgejo_user` as the principal.
- API.md: say that the enrollment id is the only thing protecting the one-time client
  certificate download (the certificate is public, the key never leaves the host, so this is fine,
  but a lost response means re-enrolling).
