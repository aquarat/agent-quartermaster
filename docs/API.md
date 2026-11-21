# aqmas API contract (milestone 1 as built; milestone 2 Cloudflare contract in section 5)

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
allowed). It verifies the chain to the pin, the server name (e.g. IP SAN `192.0.2.10`) and the
`serverAuth` EKU. Because the CA (not the leaf) is pinned, renewing the leaf does not break
enrolled hosts.

The client certificate identifies the **host**: its CommonName is the enrolled host name.
Requests are attributed to that host. Only `/v1/enroll` and `/v1/enroll/{id}` work without a
client certificate; every other endpoint returns 401 without one.

Long-polls: `?wait=25s` (or `?wait=25`), capped at 25 s. `poll_after_ms` says how long to wait
before the next poll when an answer comes back early.

### POST /v1/enroll  (no client cert)
`EnrollRequest {hostname, class?, csr_pem, ssh_host_key_fingerprints[]?, note?, poll_token}` ->
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
- `class`: `agent` (default) or `owner-device` (CLI `--owner-device`). The server stores
  the passkey-approved class with the enrollment, never trusting a class on an access request.
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

- `kind`: `"ssh"` (M1) or `"cloudflare"` (M2, section 5).
- `SSHRequest {target_host, login_user, public_key}`: `target_host` is a configured name, alias
  or address, optionally `host:port` (`[IPv6]:port`). The server filters by port and login user;
  an ambiguous selector is a 400 listing the candidates. The request records the original
  selector and snapshots the resolved endpoint and principal. `public_key` is an Ed25519 key in
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

### GET /v1/ssh-target

The mTLS `GET /v1/ssh-target?target=SELECTOR&user=USER` returns
`{name,address,port,max_seconds}` for cache lookup; `max_seconds` is the host-class SSH maximum.

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
| `POST /api/ui/passkeys/challenge` | `{action: "add", nickname?}` | `ChallengeResponse` (object `passkey`, id `new`, `new_nickname` = the nickname) |
| `POST /api/ui/passkeys/{id}/challenge` | `{action: "rename", nickname}` or `{action: "remove"}` | `ChallengeResponse` (object `passkey`, id `{id}`) |
| `POST /api/ui/passkeys/{id}/rename`, `.../remove` | `DecideRequest` | `PasskeyChange {ok, id, action, nickname, signed_out}` |
| `GET /api/ui/state` | | `UIState {owner, pending: [PendingItem], standing: [StandingApproval], grants: [GrantSummary], recent: [AuditEntry], passkeys: [PasskeyInfo]}` |
| `GET /api/ui/hosts` | session | Array of `{id,name,class,address,enrolled_at,not_before,not_after,last_request_at,revoked_at}`; `id` is the enrollment ID; absent times are null |
| `GET /api/ui/help` | session | `{agent_api_url,cli_download_base_url,ca_pin,owner_max_seconds}`; no secrets, no inferred URLs from request headers |
| `POST /api/ui/hosts/{id}/challenge` / `revoke` | `{action:"revoke"}` / `DecideRequest` | `ChallengeResponse` / `RevokeResult`; expires pending requests, revokes the host and standing/CF access, audits `host_revoke` |
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
- **Nicknames** (`internal/server/nickname`): runs of any Unicode space become one space,
  trimmed; 1-64 UTF-8 bytes; control, format (bidi, zero-width), private-use, separator and
  combining characters refused; unique ignoring case (409 `conflict` for a taken name). A
  nickname chosen when adding a passkey is **signed** with the add action (`new_nickname`) and
  register/finish uses exactly it (a different `name` there is 400); `name` at register/finish
  only names the first, enroll-code passkey. Without a chosen nickname the server uses the
  authenticator's name ("Bitwarden"), or "Passkey N" when unknown, made unique with " 2",
  " 3"... Look-alike letters from other scripts are not detected: the UI warns about non-ASCII
  nicknames and shows the passkey's short id (last 6 hex digits, upper case) on its tile and
  in every rename/remove confirmation. Migration 3 (Go, `fixPasskeyNames`) gives existing
  passkeys valid unique names: valid names are kept, the rest become "Passkey N" (N = the
  position in registration order, or the next free number).
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
  owner's choice). `standing_hours` above the host-class policy -> 400. For owner devices
  `ttl.owner_max_seconds` (86400) replaces the general SSH max, and `ttl.owner_max_standing_hours`
  (720) replaces `ttl.max_standing_hours`. CF scope TTLs and standing prohibitions are unchanged.
  A standing approval auto-approves later requests from the same host for the same
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
| `request` | `approve`, `deny` | `requesting_host, address` (source IP), `kind, target, target_address, target_port, principal, login_user, key_fingerprint, ttl_seconds, standing_hours` |
| `enrollment` | `approve`, `deny` | `requesting_host, address, class, kind` (`"enrollment"`), `key_fingerprint` (CSR key), `replaces, replaces_id` (incumbent enrollment ID or empty), `ttl_seconds` (0), `standing_hours` (0) |
| `host` | `revoke` | `requesting_host` (host name), `address` (enrollment address), `class`; `id` identifies the particular enrollment, not just its reusable name |
| `standing` | `revoke` | `requesting_host, kind, target, login_user, ttl_seconds` (the rule's max TTL), `standing_hours` |
| `grant` | `revoke` | `requesting_host, kind, target, login_user, ttl_seconds` (0), `standing_hours` |
| `passkey` | `add`, `rename`, `remove` | `nickname` (the passkey's current nickname; `""` for add), `new_nickname` (rename: the new one; add: the chosen nickname or `""`; remove: `""`). For add `id` is `"new"`, otherwise the passkey's id |
| `update` | `approve` | `from_version, from_commit, to_version, to_commit, daemon_sha256, darwin_arm64_sha256, linux_amd64_sha256, linux_arm64_sha256`. `id` equals `to_commit`. Versions are stable numeric semver, Git IDs are full lowercase hex, hashes are SHA-256 in lowercase hex. |

Updates: session-authenticated `GET /api/ui/updates` returns running `current`/`commit`, `candidate`, local `stat` and `diff`, `error` and updater `status`. `POST /api/ui/updates/{to_commit}/challenge` (`{"action":"approve"}`) and `.../decide` (standard assertion) use the ceremony below. A successful decision queues the proof (`{"ok":true}`); it does not mean installation succeeded.

On the agent listener, enrolled hosts may `GET /v1/releases/latest` for the latest installed and verified `{version,commit,forgejo,github}`. Each source map keys the four fixed asset names to their hex digests. `GET /v1/releases/{version}/{asset}` serves only the three CLI binaries or `SHA256SUMS` from root-managed cache. Missing releases return 404. See [UPDATES.md](UPDATES.md) for trust and setup.

The `passkey` object gained `nickname`/`new_nickname` (for `add` too) without a version bump:
a page from before this change refuses the new add text (unknown keys), which fails safe.

The key sets above are for `kind` `ssh`. For `kind` `cloudflare` (M2) the `request`,
`standing` and `grant` objects carry a different set (section 5.4); the parser picks the set
from (`object`, `kind`).

Migration 5 defaults existing enrollments to `agent`. SSH requests pending at upgrade
expire; old SSH standing rules without a signed destination cannot auto-approve new requests.
Request again to create a rule bound to the resolved address, port and principal.

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

### Organisation cutover and canonical v2

`GET /api/ui/migration` (owner session) returns `null` in ordinary operation and
`{id,plan,recovery_sha256}` in supervised maintenance. `POST /api/ui/migrations/{id}/challenge`
takes `{"action":"activate"}`. `.../activate` takes only the usual challenge ID and assertion.
The v2 `migration:activate` canonical adds exactly `plan` and `recovery_sha256` to the common
keys; `id` is the allocated personal org ID. `plan` is compact Go JSON in the fixed declaration
order of `organisations.Plan` (with the typed nested records in `web/src/migration.ts`, nil
lists/map encoded as null unless omitted by `omitempty`). The UI parses, checks key sets, order
and scalar types, reserializes and renders the signed records. The SHA-256 is over the actual
closed recovery DB bytes. No authority or plan is accepted from the decision body.

After activation, legacy request approvals/denials and standing/grant revocations use **v2**
even for a v1 CLI. They retain the kind's v1 key set, plus `org_id,org_slug,org_title,service_id,
service_slug,service_title,set_id,set_slug,set_title,set_revision,service_revision,policy_revision,
admission_generation,host_id,class,address,profile_revision,max_standing_hours`. `host_id` is
the immutable enrollment ID; `profile_revision` the SHA-256 of the reviewed public catalogue.
SSH also always signs `ssh_ca,host_key,cert_profile,principal,target_address,target_port,key_fingerprint`
(no pin: `host_key="unpinned"`). CF also signs `account_id,resource_ids,ip_condition` (`resource_ids`
uses sorted `db|tunnel|zone=id` pairs joined by `;`, empty for no named resources; mode proxy only).
Duplicate keys where sets overlap appear exactly once. All v2 nonces are 32 bytes encoded as
unpadded base64url. Source and destination are separate; a scoped page must refuse v1 and a v1
page refuses the extra fields. Enrollment, login, passkeys, release distribution and updates stay global.

Positive interop vectors: the signed `migration:activate` followed by `request:approve` for
`personal/fleet/testhost` in `test/interop/run.sh`; the CF cutover in `run-cf.sh`. Negative
cases include rewriting `v` alone, stripping any signed binding, adding an unknown plan field,
or changing an enrollment generation between review and apply. None is a v2 approval.

### Organisation Admin and duration choices

After activation, `GET /api/ui/catalogue` returns the owner's organisations, services,
sets, effective policy rules, eligible enrollments (including current generation), and
the exact auto-approved accesses. It requires an owner session. Create operations only
add public metadata: application services and empty revision-zero sets have no issuer.

`POST /api/ui/catalogue/{object}/{id}/challenge` takes `{action,plan}`; `.../decide`
takes `{challenge_id,assertion}`. `plan` is one scalar JSON string, encoded in the
declaration order of `api.CatalogueChange` and its typed records, using compact Go JSON
escaping. The browser constructs its expectation from the form and current catalogue,
validates the exact nested schema and displays decoded rows. All actions are canonical
v2: the common keys plus exactly `plan` (no unsigned replacements at decide).

| Object : action | Plan fields in order (besides the leading `owner_id`) |
|---|---|
| `organisation:create` | `organisation,new_policy,result_revision` |
| `service:create` | `organisation,service,kind,result_revision` |
| `credential_set:create` | `organisation,service,set,kind,result_revision` |
| `org_policy:replace` | `organisation,old_policy,new_policy,old_rules,new_rules,result_revision` |
| `org_host:admit` / `remove` | `organisation,host,result_revision,auto_access,admitted_services` |

A node contains `id,slug,title,revision`. For create, the new node has expected revision
zero and an allocated random ID. The owner becomes the initial approver in the creation
transaction. Host row ID, enrollment, name, fingerprint, class, prior membership and
generation are signed. `result_revision` on host actions means the next admission
generation. `auto_access:[]` means **none**. Policy rules are sorted by `(set_id,scope)`;
they bind policy-auto, standing eligibility, and explicit proxy-duration relaxation.
A policy replacement expires pending work and ends active grants/standing in that org.
Removal does so for that enrollment only. Re-admission never resurrects old bindings.
See `test/interop/catalogue.ts` for cross-language vectors including a stale signed replace.

Scoped access canonicals also carry `soft_cap,hard_cap,standing_soft_cap,standing_default`
(seconds), `offers_indefinite,offers_standing,offers_standing_indefinite`, and the signed
choices/consequences `indefinite,standing_indefinite,beyond_soft_cap,standing_beyond_soft_cap`.
`standing_seconds` is an exact sub-hour-capable alternative to `standing_hours`; at most
one can be nonzero, neither for indefinite standing. Both are checked against the host class.
Indefinite is a boolean, not a user-entered TTL of zero. An agent can explicitly ask for
it with `aqmas cf request SCOPE ... --ttl indefinite` (`POST /v2/personal/requests`,
`indefinite:true`, zero/absent `ttl_seconds`). The approval card defaults to a finite
duration. Only an explicitly signed indefinite choice uses the reserved UTC deadline
`9999-12-31T23:59:59Z`; active summaries also carry `indefinite:true`. All uses still
check admission, policy revision, peer and revocation. No indefinite auto-grant, no
indefinite minted token, and no indefinite SSH certificate. Every affected standing
exception ends on revocation or policy change regardless of duration.

The migrated proxy ceilings remain binding unless that exact ordinary scope has signed
`relax_proxy_duration:true`. Even then a configured `max_ttl_seconds` remains a hard
ceiling and prevents indefinite. `cf.admin` is capped at 3600 seconds and `cf.read.private`
at 7200 seconds, or less if configured. Neither admits relaxation or standing. Finite
duration inputs are bounded to ten years; SSH always intersects class, target and org
soft caps. Policy-auto never approves beyond the soft cap; standing matches only within
the original signed finite grant TTL. An indefinite standing rule is a separate explicit
proxy choice and does not make the grants it issues indefinite.

- Config `~/.config/aqmas/config.toml` (`server`, `server_ca` + `server_ca_sha256` pin,
  `host_name`, `client_cert`, `client_key`, `client_ca`, `default_ttl`); key and certificate
  in the same directory (0600, directory 0700). Overrides: `AQMAS_CONFIG_DIR`,
  `AQMAS_CACHE_DIR`.
- `aqmas enroll --name HOST --server URL [--ca-pin sha256:HEX] [--note TEXT] [--force] [--owner-device]`:
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
  `--ttl` outside 1 min .. the class maximum is refused locally. `--why` is required when stdin is not a
  terminal.
- `aqmas cert [USER@]HOST [...] [--quiet]`: like `ssh` but only makes sure a certificate is
  cached and prints its paths (used by the `ssh-config` snippet).
- `aqmas mosh [USER@]HOST [--ttl D] [--why TEXT] [-- MOSH-OPTIONS...]` uses the same cache
  and strict SSH bootstrap. Supports `-4`, `-6`, `--no-init`, `--predict=MODE`, `--port=N[:N]`
  (also `-p N[:N]`); executable overrides, local mode and alternate destinations are refused.
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
certificate at once; also available on Admin), `version`.


## 5. Cloudflare (milestone 2 contract)

Design, scope catalogue, deny-list, guard rails, snapshots and config: `docs/CLOUDFLARE.md`.
Types: `internal/api/cloudflare.go`. Everything in sections 1-4 still applies; this section only
adds.

### 5.1 Requesting: POST /v1/requests with kind "cloudflare"

`AccessRequest {kind: "cloudflare", cloudflare: CloudflareRequest {scope, params?, mode?},
reason, ttl_seconds, requester}`.

- `scope`: a catalogue name (`cf.read`, `cf.dns.edit`, ... `cf.admin`); unknown or disabled
  -> 400. `params`: exactly the scope's keys (`zone`, `tunnel`, `script`, `project`, `db`,
  `bucket`, `access`, `phase`, `name`), required ones present; zone/tunnel/db are **names**
  configured in aqmasd. `mode`: `proxy` (default) or `token` (only scopes with a token
  template, and only when aqmasd has a minter token and `token_ip_condition`).
- `ttl_seconds`: 0 = the scope's default; clamped into `[ttl.min_seconds, min(scope max, ttl.max_seconds)]`
  (`cf.admin` max 3600). The clamped value is the card's `ttl_max`.
- **Auto-approval**: `cf.read` and `cf.cache.purge` in proxy mode are approved at once
  (status `approved` in the 201), audited `cf_auto_approve`, no push; at most 4 such active
  grants per host and scope+params (then 429 `rate_limited`: reuse one). Otherwise a matching
  standing approval (same host connecting from the same address, kind, scope, **identical**
  `scope_params`, mode `proxy`, TTL within the rule's max) approves it. Otherwise `pending`,
  pushed as `aqmas: <host> wants <scope> <scope_params> (<ttl>)` (token mode: `aqmas: <host>
  wants a Cloudflare token <scope> <scope_params> (<ttl>)`; `cf.admin`:
  `aqmas: BREAK-GLASS cf.admin for <host>`).
- The same pending limits as SSH (5 per host) apply. `similar_recent` counts the host's
  requests for the same scope in 7 days.

### 5.2 Grants

`GET /v1/requests/{id}` -> `RequestStatus.grant` with `kind: "cloudflare"`,
`cloudflare: CloudflareGrant {scope, params, scope_params, mode, account_id, proxy_path,
token?, token_id?, token_delivered?, ip_condition?, permissions?}`.

- Proxy mode: no secret. Use the proxy (5.5) with `X-Aqmas-Grant: <grant id>`.
- Token mode: the **first** poll after approval mints the child token and returns `token`
  (never stored by aqmasd); later polls return `token_id` and `token_delivered: true` only. A
  failed mint answers 502 (`upstream`) and can be retried by polling again. The token expires at
  `not_after` and works only from `ip_condition`; aqmasd deletes it upstream at expiry or
  revoke.
- `GET /v1/grants?active=1`: `GrantSummary` gains `scope`, `scope_params`, `mode` for
  Cloudflare grants (`target_host`/`login_user` empty).
- Revoking a proxy grant (web UI) stops it at the next call; revoking a token grant deletes the
  child token upstream at once. Revoking or replacing a host (`aqmasd revoke-host`, re-enrollment)
  revokes its Cloudflare grants too (their child tokens are then deleted by the sweeper).
- Before the proxy sees a call, a missing/invalid client certificate gets a Cloudflare-shaped
  401/403 body (no `X-Aqmas-Error`).

### 5.3 Catalogue and snapshots (agent API, client certificate required)

- `GET /v1/cf/catalogue` -> `CFCatalogue {account_id, zones[], tunnels[], d1_databases[],
  scopes: [CFScopeInfo {name, title, description, params[{key, required, values?}], risk,
  auto_approve, standing_allowed, modes[], default_ttl_seconds, max_ttl_seconds}]}`. Any
  enrolled host. 404 when Cloudflare is not enabled.
- `GET /v1/cf/snapshots?object=<object key>&type=<type>&grant=<id>&limit=<n>` ->
  `CFSnapshotList {snapshots: [CFSnapshot]}` newest first, without `content` (limit default
  50, max 500).
- `GET /v1/cf/snapshots/{id}` -> `CFSnapshot` with `content` (the object as Cloudflare
  returned it, redacted as proxied reads are).
- Both need the calling host to hold an active Cloudflare grant (any scope or mode), else 403.

### 5.4 Canonical approval text for kind "cloudflare"

Same scheme as section 2 (sorted keys, no whitespace, strings/integers/booleans only,
`SHA-256(canonical)` is the WebAuthn challenge, exactly this key set):

| object | actions | keys besides `v`, `action`, `object`, `id`, `nonce`, `issued_at` |
|---|---|---|
| `request` (kind `cloudflare`) | `approve`, `deny` | `requesting_host, kind, scope, scope_params, mode, ip_condition, ttl_seconds, standing_hours` |
| `standing` (kind `cloudflare`) | `revoke` | `requesting_host, kind, scope, scope_params, mode, ttl_seconds` (the rule's max TTL), `standing_hours` |
| `grant` (kind `cloudflare`) | `revoke` | `requesting_host, kind, scope, scope_params, mode, ttl_seconds` (0), `standing_hours` (0) |

- `scope_params`: the canonical parameter string, `k=v` pairs with keys sorted bytewise,
  joined by `;` (`name=*.example.com;zone=example.com`), `""` when none. Values never
  contain `;` or `=` (validated). Zone/tunnel/db values are the configured **names**.
- `mode`: `proxy` or `token`. `ip_condition`: `""` in proxy mode; in token mode the token's
  CIDRs sorted and joined by `,`.
- `standing_hours` must be 0 when the scope does not allow standing approvals, in token mode,
  and for deny/revoke; the server refuses (400) otherwise. `ttl_seconds` follows the M1 rules
  (shorten only; refused, not clamped).
- On `decide` the server re-checks that the stored request still has this scope, scope_params
  and mode, and that `Reparse` of them still succeeds against the current config (a zone
  removed from the config since → 409).
- The UI checks every one of these fields against the card before signing (as in section 2)
  and describes the scope in its **own** words (`web/src/cfscopes.ts`): it refuses to sign a
  scope it has no description for, shows `cf.admin` as break-glass, and shows each
  `scope_params` pair separately.

### 5.5 The proxy: ANY /cf/client/v4/{cloudflare path}

On the agent API listener (`:8443`, mTLS client certificate required).

- Request header `X-Aqmas-Grant: <id>[,<id>...]` (at most 8): the grants the caller offers.
  aqmasd uses the first one that is the caller's, kind `cloudflare`, mode `proxy`, active,
  requested **from the same address as this connection**, and whose scope allows the call.
- Path, query, method and header rules: `docs/CLOUDFLARE.md` 3.1. Forwarded to the fixed
  `api_base` with the proxy parent token; the caller's `Authorization` is dropped (except on
  JWT-passthrough upload routes).
- Responses are Cloudflare's (status, body after redaction, whitelisted headers) plus
  `X-Aqmas-Grant-Used`, and for writes `X-Aqmas-Snapshot-Before`/`-After` and repeated
  `X-Aqmas-Warning`.
- aqmasd's own refusals are Cloudflare-shaped so tools print them:
  `{"success":false,"errors":[{"code":10403,"message":"aqmas <code>: <text>"}],"messages":[],"result":null}`
  with `X-Aqmas-Error: <code>`: `no_grant` (403; with `X-Aqmas-Needs-Scope: <scope>
  <scope_params>` when a scope would allow the call), `denied` (403, deny-list), `guard_rail`
  (403, or 409 for a stale tunnel config), `bad_path`/`bad_request` (400), 405, 413,
  `rate_limited` (429, `Retry-After`), `upstream` (502).
- Synthetic: `GET /user/tokens/verify`, `GET /user`, `GET /memberships`, `GET /accounts`
  (CLOUDFLARE.md 3.2).
- Overrides: `X-Aqmas-Override: <guard>[,...]` with a `cf.admin` grant only; with any other
  grant the header is refused (400).

### 5.6 CLI (`aqmas cf ...`)

- `aqmas cf scopes [--json]`: the catalogue.
- `aqmas cf request SCOPE [key=value...] [--mode proxy|token] [--ttl 2h] [--why TEXT] [--json]`:
  request, print approve URL + Ref, wait; prints the grant id and validity. `--why` is
  required when stdin is not a terminal (as for `ssh`).
- `aqmas cf api METHOD PATH [--data @FILE|@-|TEXT] [-H 'Name: value'] [--grant ID]...
  [--override GUARD] [--raw] [--why TEXT]`: one call through the proxy. PATH is relative to
  `/client/v4` (a full `https://api.cloudflare.com/client/v4/...` URL is accepted). Without
  `--grant` it offers all of the host's active proxy grants. A GET with no grant at all
  auto-requests `cf.read`. On `no_grant` it prints the `X-Aqmas-Needs-Scope` hint as a ready
  `aqmas cf request ...` command line. Body to stdout (pretty JSON unless `--raw`), aqmas
  headers (grant used, snapshots, warnings) to stderr. Exit 0 on 2xx, 1 on an upstream non-2xx,
  3 on an aqmas refusal (`no_grant`, `denied`, `guard_rail`), 5 unreachable.
- `aqmas cf env [--grant ID]... [--request SCOPE [k=v...]]... [--ttl D] [--why T] -- CMD...`:
  starts the local shim on `127.0.0.1:<random>` and runs CMD with
  `CLOUDFLARE_API_BASE_URL=http://127.0.0.1:<port>/client/v4`, `CLOUDFLARE_API_TOKEN` and
  `CF_API_TOKEN` = a random per-run bearer, `CLOUDFLARE_ACCOUNT_ID`/`CF_ACCOUNT_ID`, `CF_API_BASE`
  = the base URL; unsets `CLOUDFLARE_API_KEY`, `CLOUDFLARE_EMAIL`, `CF_API_KEY`, `CF_API_EMAIL`.
  The shim accepts only requests with that bearer and `Host: 127.0.0.1:<port>` (JWT-passthrough
  upload paths excepted, where the upload JWT is forwarded), forwards them to the proxy with
  mTLS and the grant list, and exits with CMD. Exit status = CMD's.
- `aqmas cf curl [aqmas flags] [--] [curl args...]`: `aqmas cf env -- curl` with every
  `https://api.cloudflare.com/client/v4` URL argument rewritten to the shim and the shim bearer
  added from a 0600 header file (`-H @file`, never on the command line).
- The shim also refuses requests carrying a browser `Origin` header, and adds `127.0.0.1` to
  CMD's `NO_PROXY`.
- `aqmas cf token SCOPE [key=value...] [--ttl D] [--why T] [-- CMD...]`: a token-mode grant.
  With CMD: runs it with `CLOUDFLARE_API_TOKEN`/`CF_API_TOKEN` = the child token and the
  account id (never printed). Without CMD: prints the token to stdout only when stdout is not a
  terminal or with `--print`. The token is cached 0600 under the cache dir for reuse by the same
  Unix user until 2 min before expiry, then deleted.
- `aqmas cf snapshot list [--object KEY] [--type T] [--grant ID] [--json]`,
  `aqmas cf snapshot get ID [-o FILE]` (content as pretty JSON).
- `aqmas list` shows Cloudflare grants (scope, params, mode, validity).

### 5.7 Web API additions

- `PendingItem` of kind `cloudflare` carries `cloudflare: PendingCloudflare {scope, params,
  scope_params, mode, ip_condition, title, description, risk (low|medium|high|admin),
  standing_allowed, permissions?, notes?}`; `ssh` is absent; `risk` is `normal` for low/medium,
  `high` for high/admin. `ttl_requested`/`ttl_max` as for SSH.
- `StandingApproval` and `GrantSummary` carry `scope`, `scope_params`, `mode` for Cloudflare.
- Challenges/decisions use the same endpoints (`/api/ui/requests/{id}/challenge|decide`,
  `/api/ui/standing/{id}/...`, `/api/ui/grants/{id}/...`) with the 5.4 canonical text.
- After every Cloudflare decision aqmasd pushes what it applied:
  `aqmas: approve cloudflare cf.dns.edit zone=example.com (proxy) for hosta, ttl 7200s, standing 0h [ref ABC123]`.
- Audit entries for Cloudflare: `cf_auto_approve`, `cf_write`, `cf_refused`, `cf_token_mint`,
  `cf_token_delete`, `cf_token_orphan` (object `grant:<id>` or `request:<id>`).
