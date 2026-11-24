# aqmas API contract (milestone 1 as built; milestone 2 Cloudflare contract in section 5)

All bodies are JSON (`Content-Type: application/json`), timestamps RFC 3339 UTC, IDs are
opaque ASCII strings (ULID). Go types live in `internal/api` and are the source of truth; the
web UI mirrors them in `web/src/types.ts`. This file describes them.

Errors: non-2xx with `api.Error` `{"error": "<code>", "message": "<human text>"}`. Codes
(`api.Err*`): `bad_request` (400), `unauthenticated` (401), `forbidden` (403), `not_found`
(404), `conflict` (409: already decided, challenge already used, state changed),
`expired` (410), `locked` (423: a sealed bucket is closed, [Buckets](#buckets)),
`rate_limited` (429), `denied`, `internal` (500).

`not_admitted` (404) replaces `not_found` on the agent API for one case only: the calling
host is enrolled but has no active admission to any organisation (the owner admits it under
the organisation's Hosts, or together with the enrolment approval). It describes the
caller's own state and is sent for every "not found" answer to that host alike, so it does
not reveal whether the thing asked for exists. A host that is admitted somewhere and asks
for something it cannot see still gets `not_found`, indistinguishable from a missing object.
The status is 404 so that clients older than the code behave as before and print it.

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
| `POST /api/ui/requests/{id}/challenge` | `ChallengeRequest {action: approve\|deny, ttl_seconds?, standing_hours?}` | `ChallengeResponse {challenge_id, canonical, public_key, open?}` (`open`: [Buckets](#buckets)) |
| `POST /api/ui/requests/{id}/decide` | `DecideRequest {challenge_id, assertion, open?}` | `RequestStatus` **without** `grant` (browsers never get certificates) |
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

The WebAuthn challenge for an action is `SHA-256(canonical)` (go-webauthn `WithChallenge`;
on a sealed installation an action that opens buckets binds an open descriptor too, see
[Buckets](#buckets)),
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

Updates: session-authenticated `GET /api/ui/updates` returns running `current`/`commit`, `candidate` (`{version,commit,github,second?,sources}`), `sources` (the published sources compared, by name: `"GitHub"`, and `"second source (HOST)"` when one is configured), local `stat` and `diff`, `error` and updater `status`. `POST /api/ui/updates/{to_commit}/challenge` (`{"action":"approve"}`) and `.../decide` (standard assertion) use the ceremony below. A successful decision queues the proof (`{"ok":true}`); it does not mean installation succeeded.

On the agent listener, enrolled hosts may `GET /v1/releases/latest` for the latest installed and verified `{version,commit,github,second?,sources,forgejo}`. `github` maps the four fixed asset names to their hex digests; `second` is the identical map from the configured second source and is absent without one; `sources` is 1 or 2 accordingly. `forgejo` repeats `github` for CLIs of 0.8.1 and earlier, which read the verified digests there (they predate the optional second source); current readers ignore it because `sources` is present, and a record without `sources` is read as the 0.8.1 form `{version,commit,forgejo,github}`. `GET /v1/releases/{version}/{asset}` serves only the three CLI binaries or `SHA256SUMS` from root-managed cache. Missing releases return 404. See [UPDATES.md](UPDATES.md) for trust and setup.

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

### Organisations (Vault, Hosts, Settings) and duration choices

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

**Admitting with the enrolment approval (web UI).** Approving an enrolment and admitting the
new host stay two signed actions with unchanged canonical texts: `enrollment:approve`, then
`org_host:admit`. The page joins them into one flow. "Let it join…" offers "Also admit to
ORGANISATION": preselected when the catalogue holds exactly one organisation, a choice (or
"Not now") when it holds several. After the enrolment approval is applied, the page reads the
catalogue again, proposes the `org_host:admit` plan for the new host row and shows its own
confirmation (host, class, certificate fingerprint, organisation, the services it may then
ask for and what is granted without asking, all read from the text to be signed). Both need
an individual passkey confirmation: neither enrolment nor admission is eligible for an
approval window. If the admission fails or is cancelled, the enrolment stays approved; the
sheet says "Joined, but not admitted" with the reason and "Try the admission again", and
Hosts marks the host "Not admitted" with Admit next to each organisation. Until it is
admitted the host's CLI is told `not_admitted` (above).
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
  CA is trusted only after the user confirms its fingerprint at a terminal. `--server` is the
  agent API (`https://HOST:8443`), not the web UI's address; the web UI's Help page shows the
  exact command with the pin. An address that is not the agent API is said to be so: before
  any prompt when its certificate chain is one the public web trusts (the agent API uses the
  bastion's private CA; an explicit `--ca-pin` is still honoured), and after the pinned
  handshake when the answer is a redirect or a web page.
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
certificate at once; also available on the Hosts tab), `version`.


`setup-facts` prints the schema version and the public passkey records as JSON for the
maintenance runner. As **root**: `aqmasd maint-init [--repin]` installs the runner and
`aqmasd maint-run` (started by `aqmas-maint.path`) runs one owner-approved request. The
Setup web API and the canonical `setup` object are in [SETUP.md](SETUP.md).

`inspect` is the forced command of the bastion's read-only account
([BASTION-ACCESS.md](BASTION-ACCESS.md) §8): sshd runs it for every session of
`aqmas-inspect`; it reads `SSH_ORIGINAL_COMMAND`, never the configuration.

Sealed stores ([Buckets](#buckets), [SEAL-OPERATIONS.md](SEAL-OPERATIONS.md)):
`seal-import` and `bucket-migrate` are the staging modes the runner starts;
`seal-drill BACKUP.db RECIPIENT <identity` opens every scope key, bucket and record of a
standalone backup offline and prints only counts and the manifest digest;
`seal-recover DIRECTORY <identity` is isolated recovery when every passkey is lost.

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
  On a sealed store (format 2) both also need the Cloudflare proxy parent's bucket open, else
  423 `locked` ("… is closed: waiting for the owner to reopen it"), as v0.4.1 required unlock.

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

# Buckets

Seal format 2, schema 9 ([BUCKETS.md](BUCKETS.md); procedures in
[SEAL-OPERATIONS.md](SEAL-OPERATIONS.md)). Session, CSRF and Access requirements are
unchanged. There is no unlock: format 1's `/api/ui/seal/unlock/*`, the `lock` control action
and the combined `unlock-window` ceremony are gone. Binary values are unpadded base64url;
`raw` below means the decoded bytes. Context strings:

    T2(role, f1, …, fn) = F("aqmas-seal") ‖ F(u64be(2)) ‖ F(role) ‖ F(f1) ‖ … ‖ F(fn)
    F(x) = u32be(len(x)) ‖ x

Routes under `/api/ui/seal/` answer 404 on an unsealed installation, 423 `locked` on a
format-1 store awaiting migration, and 409 while a stage is in progress (except status,
drill, stage and the `activate` control action). An operation that needs a closed bucket
answers **423 with error code `locked`**: agents get "*label* is closed: waiting for the owner
to reopen it" and keep their deadline; an approval that must open a bucket but carries no
`open` gets "this approval must open *labels*" (for a passkey that opens only from remembered
browsers: "… this browser is no longer remembered for this passkey …"). At most 60 open
attempts a minute and 64 pending (429 `rate_limited`).

## Open descriptor and bound challenge

A challenge whose action needs buckets returns `ChallengeResponse {challenge_id, canonical,
public_key, open: {descriptor, browsers?}}`; its finish takes `open` next to `challenge_id`
and `assertion` (`browsers`: [Remembered browsers](#remembered-browsers)):

| Challenge | Actions that carry `open` | Finish |
|---|---|---|
| `POST /api/ui/requests/{id}/challenge` | `approve` (SSH; Cloudflare proxy mode) | `POST /api/ui/requests/{id}/decide` |
| `POST /api/ui/enrollments/{id}/challenge` | `approve` | `POST /api/ui/enrollments/{id}/decide` |
| `POST /api/ui/seal/batch/challenge` | a batch with an approval | `POST /api/ui/seal/batch/finish` |
| `POST /api/ui/seal/windows/open/challenge` | sets with SSH or Cloudflare proxy | `POST /api/ui/seal/windows/open/finish` |
| `POST /api/ui/seal/env/challenge` | `approve` | `POST /api/ui/seal/env/finish` |
| `POST /api/ui/seal/vault/challenge` | `reveal`, `sign-approve` | `POST /api/ui/seal/vault/finish` |
| `POST /api/ui/seal/control/challenge` | `renew-leaf`, `reopen`, `rekey` | `POST /api/ui/seal/control/finish` |
| `POST /api/ui/seal/passkeys/challenge` | `register`, `enable`, `remember` (scopes that already have a key) | `POST /api/ui/seal/passkeys/authorize` |

Every other challenge keeps `challenge = SHA-256(canonical)`. The descriptor is canonical JSON
(sorted keys, no whitespace, no HTML escaping) with exactly these keys:

    {"attempt_id","buckets":[{"hold","id","kind","label","scope","until"}…],"epoch",
     "installation","object":"bucket-open","purpose":"approve","recipient","scopes","v":1}

* `attempt_id`, `epoch` (this boot), `installation`, each bucket `id`: 32 bytes.
* `recipient`: a fresh 65-byte P-256 point (uncompressed SEC1) for this ceremony only: single
  use, bound to the session and purpose, two minutes.
* `scopes`: one or two, `installation` first, then organisation IDs sorted. An action needing
  buckets of three scopes is refused (400): split it.
* `buckets`: sorted by raw ID. `kind` is `ssh-ca`, `internal-ca`, `cf-proxy`, `env-set` or
  `signer`; `label` the display path; `hold` the card text of what keeps it open afterwards
  (`; `-joined); `until` the latest RFC 3339 end, or `""` for an event (revoke, collect,
  restart). Every bucket's `scope` is in `scopes`. `buckets` is `[]` when the tap opens only
  scope keys (passkey enable, rekey of an empty scope).
* `rekey_salt` (seal-control `rekey` only, and then always): a fresh 32-byte salt. The
  descriptor then names exactly one scope; every `evalByCredential` entry is
  `{"first": salt(scope), "second": rekey_salt}`, and the packet carries
  `F(KEK_1) ‖ F(KEK_rekey)` where `KEK_rekey` is derived as below with the same scope and
  `rekey_salt` as the salt. The broker opens the old scope key with `KEK_1` and wraps the new
  one under `KEK_rekey` (BUCKETS.md §7). The page accepts `rekey_salt` only on a rekey card
  and refuses a rekey descriptor without it or a `second` input that differs.

The WebAuthn challenge is

    SHA-256(T2("open-challenge", SHA-256(canonical), SHA-256(descriptor)))

`public_key.extensions.prf.evalByCredential` maps each owner passkey that has wraps for
**all** the descriptor's scopes to `{"first": salt(s1), "second": salt(s2)}` (32-byte salts,
descriptor order; `second` only for two scopes), even when the buckets are open.
`allowCredentials` lists those passkeys, plus every other owner passkey when every needed
bucket is open at challenge time (a window open lists only its chosen credential). With no
passkey able to open them the challenge is refused (423).

The page parses the descriptor (exact key set, `v` 1, 32-byte IDs, 65-byte recipient starting
`0x04`, one or two scopes), checks its re-serialisation equals the string, recomputes the
bound challenge and compares it with the options, checks every `evalByCredential` entry has
exactly one 32-byte salt per scope, and shows the buckets (label, hold, until) on the card.
After the tap, with `getClientExtensionResults().prf.results.first` (and `.second` for two
scopes), for each scope *i*:

    KEK_i = HKDF-SHA256(ikm = PRF result_i, salt = raw installation,
                        info = T2("scope-kek", raw installation, utf8(rpId),
                                  raw credential ID, utf8(scope_i), raw salt_i), 32)

and sends `open: {attempt_id, enc, ciphertext}`: RFC 9180 base mode,
DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, to `recipient`, with

    info      = T2("hpke-open", raw installation, utf8(purpose))
    aad       = T2("open-aad", raw attempt ID, raw epoch, bound challenge (32 bytes), raw credential ID)
    plaintext = F(KEK_1) ‖ F(KEK_2 or "")

`enc` is 65 bytes. The page wipes PRF results and KEKs and never puts PRF results in the
assertion's `clientExtensionResults` (the broker refuses extension output it does not
expect). If the passkey returned no PRF results the page sends no `open`; the broker then
succeeds only when every needed bucket is already open. An `open` on a challenge without a
descriptor is refused (400); a packet sent while everything was open is consumed and
discarded only when it names this challenge's own `attempt_id` (another pending tap's attempt
is left alone).

The broker verifies the assertion over the bound challenge, consumes the attempt, opens the
packet, unwraps the signing passkey's scope wraps (marking them tested), re-reads each closed
bucket and refuses (409, "changed since the review") one whose key pair changed since the
challenge (a rekey in between), unwraps exactly the descriptor's closed buckets, wipes scope
keys and KEKs, holds the buckets for the apply, then keeps the descriptor's holds (or releases
them on failure). A failure anywhere opens and applies nothing.

**Scope-enrol descriptors** (passkey enable and test, recovery enrolment, staging) have the
same keys plus `credential_id` (the only allowed credential) and `salts` (one 32-byte salt per
scope, aligned), with `object` `"scope-enrol"`, `buckets` `[]` and `purpose` `enrol`, `test`,
`stage` or `migrate`. Their options carry `extensions.prf.eval {first, second?}` (not
`evalByCredential`) and `allowCredentials` = that credential. The bound challenge, KEK and
packet are as above with the descriptor's `purpose` in `info`. `migrate` adds
`legacy {installation, mk_version, prf_salt}` and exactly one scope (`installation`): PRF
`first` is `legacy.prf_salt`, `second` is `salts[0]`, and the packet's first slot carries the
format-1 KEK (HKDF over the first PRF output, salt = raw legacy installation, info = the
suite-1 tuple `mk-kek`, legacy installation, rpId, credential ID, `mk_version`, `prf_salt`),
the second the scope KEK.

## Seal status

`GET /api/ui/seal/status` (session):

    {"mode", "installation", "epoch",
     "scopes":   [{"scope","title","buckets","has_key","tested"}],
     "buckets":  [{"id","kind","label","scope","scope_title","open","opened_at"?,
                   "holds":[{"kind","ref","reason","until"?,"since"}],
                   "paused":[{"kind","ref","reason"}]}],
     "passkeys": [{"id","name","current","prf","had_prf","mode","scopes":[{"scope","tested"}],"opens","of","missing",
                   "browsers":[{"id","key","label","created_at","last_used_at"?,"scopes":[{"scope","tested"}]}]}],
     "active_windows"?, "profiles"?, "verified_access"?, "leaf_expires"?, "leaf_repair"?,
     "stage"?}

* `mode`: `unsealed` (only the empty lists), `buckets` (format 2 serving),
  `migration-required` (a schema-8 format-1 store under this binary: sign-in, queueing,
  deny/revoke and Setup only), `setup` (seal import or bucket migration staging) or
  `activated` (staging committed, the process is about to exit). Scopes, buckets and passkeys
  are filled in mode `buckets` for an owner session.
* `scopes`: the installation and every organisation, with or without a scope key.
* Hold `kind`: `instant`, `grant` (Cloudflare proxy grant), `env` (release until collected,
  at most 10 minutes), `sign` (signing grant), `standing`, `auto` (Cloudflare auto-approval:
  added only by a tap whose card said "re-arms Cloudflare auto-approval"; ends at restart,
  Close all, or when the set's policy no longer auto-approves any scope) or `window`. `paused` lists live users of the bucket (grants, env releases,
  signing grants, standing rules) without a hold on it: they wait for a **Reopen**.
* Per passkey: `id` as in `PasskeyInfo`; `prf` true when it holds any PRF scope wrap; `opens` the
  number of buckets in its scopes, `of` all buckets; `missing` the scopes it has no wrap for.
  `had_prf`: it has, or once had, a PRF wrap (sticky until the passkey is removed; such a
  passkey is refused the remembered-browser path).
  `mode` says how it opens buckets: `prf` (its own secret), `browser` (only from the
  remembered browsers in `browsers`; `scopes` is then the union over them, `tested` when some
  browser's wrap is) or `""` (nothing). `browsers[]`: `id` the key's fingerprint
  (`hex(SHA-256(public key)[0:16])`), `key` its public half (65 bytes, base64url), `label`,
  `created_at`, `last_used_at` (the last tap that opened from it), and the scopes it has a
  wrap of.
* `stage` (mode `setup`, owner session): `{source: "unsealed"|"format-1", scopes:[{scope,
  title, buckets, wrapped, tested}], drilled, drill_key, manifest?, legacy_unlocked,
  dropped?, choices:[{id, name, credential_id, legacy?: {mk_version, prf_salt,
  installation}}]}`. `manifest` appears once every scope is wrapped and tested and the drill
  passed; `choices` are the passkeys that may take the next step (for `format-1`, before the
  old store is open, only format-1 unlock passkeys).

## Seal control

`POST /api/ui/seal/control/challenge {action, buckets?, scope?}` → `ChallengeResponse`;
`POST /api/ui/seal/control/finish {challenge_id, assertion, open?}` → `{ok}`.

| `action` | Input | Signed fields | Opens | Effect |
|---|---|---|---|---|
| `close-all` | nothing | `open_buckets` (count) | nothing | Wipes every open bucket and hold, ends every window, drops pending attempts and capability stages |
| `renew-leaf` | nothing | `repair` (JSON string: `ca_pin`, `configured_sans`, `effect`) | `internal-ca`, instant | Renews the agent TLS leaf; the broker then restarts (everything closes) |
| `reopen` | `buckets`: 1–16 sorted, unique bucket IDs | `buckets` `[{id, label}]` | those buckets | Keeps each open with the holds of its live users |
| `rekey` | `scope` (with a key) | `scope`, `scope_title`, `bucket_count` | every bucket of the scope (an empty scope: its key alone) | New scope key and bucket keys, records re-encrypted, drafts dropped, the scope's buckets closed, only the tapping passkey keeps a wrap (a remembered browser: only that passkey with that browser key): of the new key, at the descriptor's `rekey_salt`, **untested** until it next opens (test it: `test` below). Requires `open` with both KEKs; returns `{ok, buckets}` |
| `activate` | nothing (mode `setup`, stage ready) | `manifest` (the format-2 manifest JSON string) | nothing | Commits the stage; the process exits. A plain signature: challenge `SHA-256(canonical)`, `open` refused, a passkey not pinned by the runner refused |

## Passkey capabilities

Session routes under `/api/ui/seal/passkeys/` (BUCKETS.md §7):

1. `challenge {action, nickname, capability, credential_id, scopes}`: `action` `register`,
   `enable`, `disable` or `test`; `capability` `unlock` (one or two `scopes`, installation
   first) or `approve-only` (none); `credential_id` the target's raw ID, `""` for register;
   `nickname` the target's current nickname or the new one. Register/enable: the canonical
   carries an open descriptor (purpose `approve`, `buckets` `[]`, the listed scopes that
   already have a key), so the approving passkey must already open them; with none, a plain
   challenge. Test: a scope-enrol descriptor (purpose `test`) at the target's own salts.
   Disable: plain. `enable` of a scope the target already opens with a **tested** wrap is
   refused (409): a tested wrap is never replaced.
2. `authorize {challenge_id, assertion, open?}` → register: `{registration_id, public_key}`
   (creation options, PRF requested); enable: `{registration_id}`; disable: `{ok}` (deletes
   the target's wraps for the listed scopes, or all; refused when no other passkey has a
   **tested** wrap of such a scope); test: `{ok, scopes}` (marks the wraps tested).
3. `create {registration_id, credential}` → `{ok}` (register only; an approve-only
   registration is committed here).
4. `evaluate {registration_id}` → `ChallengeResponse` with canonical object `passkey-enrol`
   and a scope-enrol descriptor (purpose `enrol`, the target credential, fresh salts). A
   listed scope without a key gets one now (fresh key pair and recovery wrap).
5. `finish {registration_id, challenge_id, assertion, open}` → `{ok, scopes}`: the broker
   wraps each open scope key under the target's KEKs and wipes it.

Repeat from step 1 for further scopes, two per round. A stage is bound to the session,
expires after five minutes (its opened scope keys are wiped then, by its own timer and by the
15 s reconcile pass) and is lost on restart (at most 16 pending). **Create** (Security → Buckets, or Vault → Add item)
for a new organisation's scope is `enable` of the signed-in passkey for that scope (two
taps). Until some passkey's wrap of a new scope has opened once (`test`, three taps in all),
creating its first bucket is refused (409 "test the new scope first").

## Remembered browsers

A passkey without PRF opens buckets from a browser profile that holds a key of its own
(BUCKETS.md §13). The browser key is a P-256 key pair whose private half never leaves the
browser; `browser_key` below is its public half (65 bytes, uncompressed SEC1, base64url) and
`browser_key_id` its fingerprint, lowercase hex of the first 16 bytes of its SHA-256.

**Passkey-capability actions** (the routes of [Passkey capabilities](#passkey-capabilities);
`challenge` takes two more fields, `browser_key` and `browser_label`):

| `action` | Input | Canonical adds | Tap | Effect |
|---|---|---|---|---|
| `remember` | `capability: "unlock"`, one or two `scopes`, `browser_key`, `browser_label` (1–64 printable characters, single spaces; it replaces the label of a browser already remembered for that passkey) | `browser_key`, `browser_key_id`, `browser_label` | as `enable`: open descriptor for the scopes that have a key, signed by a passkey that opens them | `authorize` → `{registration_id}`; then `evaluate` and `finish` as for `enable` |
| `test` with `browser_key` | the scopes that browser has a wrap of | `browser_key`, `browser_key_id` | scope-enrol descriptor, purpose `test`, with `browser_key`; `salts` are the wrap IDs | `authorize` → `{ok, scopes}` after a [release](#release) by the same tap |
| `forget` | `capability: "unlock"`, `scopes: []`, `browser_key` | `browser_key`, `browser_key_id` | plain (`SHA-256(canonical)`), any passkey | `authorize` → `{ok}`: deletes the browser key record and its wraps |

The canonical of the three, in full (sorted keys; `browser_label` only for `remember`):

    {"action","browser_key","browser_key_id","browser_label","capability":"unlock",
     "credential_id","epoch","id","installation","issued_at","nickname","nonce",
     "object":"passkey-capability","scopes":[…],"v":3}

`evaluate` for a `remember` returns canonical object `passkey-enrol` with `browser_key` and
`browser_key_id` added, and a scope-enrol descriptor (purpose `enrol`) that carries
`"browser_key"`; its `salts` are the new wrap IDs. The PRF inputs are still sent: a passkey
that answers them has PRF and the page stops (BUCKETS.md §13.4). `finish` takes `open` with
one fresh random 32-byte KEK per scope in the usual packet; the broker stores the scope key
wrapped under it and the KEK sealed to `browser_key`.

Refusals: `remember` for a passkey that has, or ever had, a PRF wrap (409; the mark is
sticky, status `had_prf`), with a label another browser of that passkey has (409), or naming
a scope that browser already opens with a tested wrap (409); `enable` for a passkey that has remembered browsers
(409); `forget` of the only tested wrap of a scope (409); a malformed key or label, a
`browser_key` on another action, a label on anything but `remember` (400).

**Offer.** `open.browsers` on a bucket-open challenge: `[{credential_id, key_id, label}]`, the
passkeys (raw credential ID) and browser keys (fingerprint) that have a wrap of every scope
of the descriptor. Not signed: a hint for the card. Such passkeys are in `allowCredentials`.

### Release

`POST /api/ui/seal/browser/release {challenge_id, assertion, browser_key}` →
`{wraps: [{scope, id, sealed_kek}]}`, in the descriptor's scope order.

* `challenge_id`: a pending challenge of this session that carries an open (bucket-open, or
  a scope-enrol of purpose `test` naming this `browser_key`). It stays pending.
* `assertion`: the tap's assertion, as the finish will send it. It is verified against the
  tap's bound challenge like a finish (signature, origin, user verification, owner session),
  but nothing is consumed and no sign count or last use is recorded.
* The wraps returned are those of the **asserting passkey** and `browser_key`: `id` the wrap
  ID (32 bytes), `sealed_kek` (113 bytes) = HPKE base mode to the browser key,
  `info = T2("browser-kek", raw installation, rpId, raw credential ID, scope, raw wrap ID,
  raw browser key)`, empty AAD, plaintext the 32-byte KEK.
* Errors: 409 for an unknown, expired, finished or already released tap, for a tap of
  another session, for a tap whose challenge is no longer pending, and for a step that
  releases nothing (an `enrol` tap, a PRF `test` tap); 403 for an
  assertion that does not verify; 423 `locked` when this browser is not remembered for the
  asserting passkey or for one of the scopes; 429 after three attempts on one tap.

The finish that follows takes the usual `open` packet: `F(KEK1) ‖ F(KEK2 or "")` with the
KEKs opened from `sealed_kek` (a rekey: the old KEK, then a fresh random one). A browser-key
passkey's packet without a release on the same tap is refused (423), as is a finish signed
by another passkey than the release was for (403).

## Recovery (Security tab, rare path)

1. `POST /api/ui/seal/recovery/key {}` → `{attempt_id, recipient}`: a fresh broker key (two
   minutes, single use). The page seals the pasted identity text to it: HPKE base mode,
   `info = T2("hpke-open", raw installation, "recovery")`,
   `aad = T2("open-aad", raw attempt ID, raw epoch, "", "")`; `packet` =
   base64url(`enc ‖ ciphertext`).
2. `POST /api/ui/seal/recovery/challenge {mode, attempt_id, packet_sha256, credential_id?,
   scopes?, browser_key?, browser_label?}`: `mode` `drill` (plain challenge) or `enrol` (target `credential_id`, one or two
   `scopes` with a key; scope-enrol descriptor, purpose `enrol`, fresh salts, the target
   taps). `packet_sha256` is the lowercase hex SHA-256 of the raw packet. With `browser_key`
   and `browser_label` the enrol is for a passkey without PRF from that browser
   ([Remembered browsers](#remembered-browsers)): the canonical adds `browser_key`,
   `browser_key_id` and `browser_label`, the descriptor carries `browser_key`, and the wraps
   written are browser wraps. Refused (409) for a passkey that has or ever had a PRF wrap, and for a label another browser of that passkey has; an enrol
   without `browser_key` is refused (409) for a passkey that has remembered browsers.
3. `POST /api/ui/seal/recovery/finish {challenge_id, assertion, packet, open?}` →
   `{ok, scopes, buckets}`: drill opens every scope key from its recovery wrap and every bucket
   and record, then wipes them; enrol wraps the recovered scope keys for the target.

`aqmasd seal-recover` serves its own steps on a private socket only (`POST /recovery/{step}`,
header `X-Aqmas-Recovery`: the ticket for `begin`, then the session it returns): `begin
{name}` → `{public_key, session, registration_id, installation, epoch, scopes}`; `create
{credential}` → `{credential_id, scopes}`; `evaluate {}` → `{canonical, public_key, open}`
(scope-enrol, purpose `enrol` until every scope is wrapped, then `test`); `finish {assertion,
open}` → `{next: "evaluate"}` or `{next: "replace", canonical, public_key}`; `replace
{assertion}` → `{ok}`. The scope keys the replacement passkey is wrapped for are **new**:
`replace` rekeys every scope and bucket and re-encrypts every record in the same transaction
that retires the old passkeys (its `effects` text says so).

## Stage

Seal import and bucket migration (status `mode` `setup`):

* `POST /api/ui/seal/stage/challenge {step, credential, scopes}`: `step` `open-legacy`
  (format-1 source, first step: exactly `["installation"]`, a format-1 unlock passkey),
  `create` (scopes without a wrap; fresh salts) or `test` (wrapped, untested scopes; their
  salts); `credential` the passkey's `id`; one or two scopes, installation first. The first
  step fixes the passkey and session. → `ChallengeResponse` with a scope-enrol descriptor of
  purpose `migrate`, `stage` or `test`.
* `POST /api/ui/seal/stage/finish {challenge_id, assertion, open}` → `{ok}`. A passkey
  without PRF results cannot be used.
* `POST /api/ui/seal/drill {packet}` → `{ok, scopes, buckets}`: the recovery identity sealed
  to `stage.drill_key` (HPKE base mode, empty AAD, info `aqmas-seal-drill-v1\0` followed by
  the 32 raw installation bytes; see [SETUP.md](SETUP.md)). It opens every staged scope key,
  bucket and record.
* Then the `activate` control action.

## Canonical key sets (v3)

Common keys: `v` (3), `object`, `action`, `id`, `nonce`, `issued_at`; most objects also carry
`installation` and `epoch` (this boot). Values may be strings, integers, booleans, arrays and
nested objects as listed.

| `object` | `action` | `id` | Further keys |
|---|---|---|---|
| `seal-control` | `close-all`, `renew-leaf`, `reopen`, `rekey`, `activate` | installation | `epoch` and the action's signed fields above (no `installation` key) |
| `passkey-capability` | `register`, `enable`, `disable`, `test` | fresh registration ID | `installation, epoch, credential_id, nickname, capability, scopes` |
| `passkey-enrol` | `enrol` | registration ID | `installation, epoch, credential_id, scopes` |
| `recovery` | `drill`, `enrol` | attempt ID | `installation, epoch, packet_sha256`; enrol adds `credential_id, nickname, scopes` |
| `recovery-enrol` (seal-recover) | `enrol`, `test` | registration ID | `installation, epoch, credential_id, nickname, scopes` |
| `recovery` (seal-recover) | `replace` | registration ID | `installation, epoch, credential_id, nickname, scopes, effects, manifest_sha256, backup_sha256, serial_high_water` (decimal string), `retire_credentials` (comma-joined IDs); challenge `SHA-256(canonical)` |
| `seal-stage` | `open-legacy`, `create`, `test` | installation | `epoch, credential, scopes` (no `installation` key) |

The batch, window, env and vault objects below keep their key sets; their challenges are
bound to a descriptor when they open buckets.

# Batch and window profiles

On a sealed installation, `/api/ui/seal/batch/{challenge,finish}` commits to
1–10 complete scoped canonicals, max 32 KiB, same org, sorted by request ID.
The flat v3 `batch/decide` profile adds `installation,epoch,org_id,org_title,
count,items` to the common keys. `items` is a canonical JSON array of strings.
The tap opens the union of the members' buckets (at most two scopes). Finish
accepts only the challenge ID, the UV assertion and `open`. Any stale member rolls
back all changes (including serials/signatures); the outer assertion and each
member and outcome are linked in audit. Only ordinary finite SSH and low-risk
proxy requests qualify. Individual taps remain available.

`/api/ui/seal/windows/policy/{challenge,finish}` signs a `window-policy/replace`
profile with the org as id, `installation,epoch,old,new`; old is the complete
reviewed profile and new the settings JSON. Limits: 5–60 minutes absolute,
15 seconds to the absolute duration idle. Defaults: personal enabled for known
ordinary sets, 10 minutes / 2 minutes idle, other orgs disabled. An open
window signs the explicit eligible set/scope list, path and per-action ceiling
(at most 30 minutes). No standing, root, high-risk, indefinite, token, env or
beyond-soft-cap decision. See [SEALED.md](SEALED.md#window-delegate-clicks-not-signatures).

Windows require verified Access. `windows/open/{challenge,finish}` uses
`window/open`, `installation,epoch,terms` with a new public window ID. Only
the chosen credential is offered. The tap opens the buckets the window's sets
need (SSH CA, the org's Cloudflare proxy parent) with a window hold. An open
returns `{id,token,expires_at}`. The tab retains a non-extractable
P-256 key and token only in memory. `windows/prepare` re-resolves an ordinary
decision and returns a one-use proposal; `windows/confirm` requires a raw
P1363 ECDSA-SHA256 proof over the suite-1 tuple `window-confirm`, installation,
window ID and proposal ID (UTF-8 base64url), canonical digest (raw bytes).
`presence` every 10s renews only the 30s presence lease; only applied decisions
advance idle. Close/reload drops secrets, logout ends that session's windows,
and a signed authority change fences old windows in SQLite. Security → Buckets can close
from another live owner session. A forwarded HTTP request or issued grant is
not recalled by closing a window. A window click is not a passkey signature.
# Env sets: immutable revisions and collection

The sealed runtime resolves `GET /v2/env/set?path=org/service/set` only for
the authenticated host's current admission. Vault (an env set's “More”)
issues a one-use, five-minute upload ticket bound to session, enrolled
owner-device, operation, immutable path IDs and base revision. Enter the
ticket at the CLI prompt (`--ticket-fd N` for a protected input stream).
`aqmas set import PATH --from FILE` replaces the **entire** set. `set put PATH
KEY` reads a hidden prompt or exact stdin bytes; `set unset PATH KEY` removes
one key. Imports accept UTF-8 literal assignments, whole-line comments and
blank lines, and quoted values that may span lines ("Dotenv import" below);
no interpolation, duplicate names or NUL. Compare the CLI's Ref and
commitment to the card before signing. The web form and reveal are described
under "Vault" below.

Upload (`POST /v2/env/upload`) stores only metadata and a per-draft encrypted
blob. SHA-256 commitment input is u32be-length-prefixed components: UTF-8
`aqmas-env-edit-v1`, secret random 32-byte salt, org/service/set IDs, base
revision as u64be, operation, then sorted triples of operation/name/exact
value bytes. Commit recomputes the commitment and key changes before atomically
publishing a fresh revision: one record per entry, sealed to the set's bucket
public key (nothing needs to be open). The store runs `secure_delete`; earlier
WAL frames, snapshots and backups can still retain old ciphertext.

Session-only `/api/ui/seal/env/{state,ticket,challenge,finish}`. V3 `env`
signs `action,id,installation,epoch,issued_at,nonce,metadata,ttl_seconds` and
the common `v,object`. Metadata is the complete reviewed draft or release
record (immutable IDs, path/title, revisions, admission, identity, manifest,
mode, address and policy limits); the untrusted free-form reason is blank
in the signed release. Approving a release opens the set's bucket until the
values are collected (10 minutes at most). Releases need a fresh individual tap, including
denials. No window, batch, standing or automatic env approval. Rotation
means replacing the value at its provider as well as importing the new set.

`POST /v2/env/requests`, `GET /v2/env/requests/{id}`, `POST .../{id}/cancel`,
`GET /v2/env/grants/{id}`, `POST .../{id}/checkin` return metadata only.
`POST /v2/grants/{id}/collect` returns values **once**, after commit, only to
the live issuing enrollment and peer with matching mode, revision, admission
and policy. A 423 `locked` (bucket closed) does not consume the grant. A response lost after
commit requires a new release. TTL bounds collection, not upstream validity.

* `aqmas run PATH --why REASON -- COMMAND ...` resolves COMMAND first and
  replaces aqmas with a process inheriting a small baseline environment and
  the approved entries. Collisions and process-control names are refused.
* `aqmas checkout PATH --why REASON [--file .env]` (`co`) uses a private
  0700 Linux tmpfs `XDG_RUNTIME_DIR` and an exclusive link in the trusted
  current directory. `checkin PATH` (`ci`) removes it and ends the grant.
  File values must be portable literal tokens; a set with a multi-line value
  is refused in file mode (after collection: use `run` or `cos` for it). A detached holder polls for
  revocation, expires locally and cleans up on loss of contact. A killed
  holder leaves its target until a subsequent checkout reaps it or the mount
  disappears. Exclude that mount from backups; disable persistent swap,
  hibernation and core dumps. macOS file mode refuses and points to `run`.
* `eval "$(aqmas cos PATH --why REASON)"` exports shell-quoted values;
  `eval "$(aqmas cis PATH)"` unsets them. Both refuse terminal stdout. Never
  tee, log, trace or redirect these exports to disk. Every subsequent child
  inherits them until checkin; same-uid processes may inspect them. Expiry
  and revocation cannot remove environment variables from another process.

Shell delivery is for Bash: the generated guard checks for **all** existing
destination variables (including unset-but-declared integer, nameref and
readonly attributes) before the first export. Disable command tracing. Use
`aqmas reap-checkouts` on login to remove RAM-file remnants from a killed
holder; checkout runs the same reaper and waits for holder readiness before
reporting success. Window-open audit stores the exact opening canonical
and the public WebAuthn verification fields when signed authenticator data
has no extensions. When it carries extensions, audit records that the opener
was verified live; the assertion cannot later be independently reverified
from the audit alone. No PRF/KEK or decrypted finish packet is persisted.

# Vault: web form, reveal and signer sets

Sealed, organisation-scoped installations only. The owner's **Vault** tab
talks to five session-only routes under `/api/ui/seal/vault/`; agents ask
for signatures under `/v2/sign/`. [SIGNING.md](SIGNING.md) is the guide; this
section is the wire contract.

`GET /api/ui/seal/vault/history?set=SET_ID` (owner session, read-only) returns
`{entries, last_changed_at, last_used_at}` for one application set: its newest
20 audit rows (`{at, actor, action, object, detail}`, as in `/api/ui/state`
`recent`) and, in Unix milliseconds, when it last changed (`vault_commit`,
`vault_signer_create`, `env_commit`) and was last used (`env_collect_*`,
`sign`); 0 when no such row is among the newest 200 about the set. The rows are
the owner's actions on the set (`object` `set:ID`), what admitted hosts asked
for and collected (their `detail` begins with the set's path) and the owner's
decisions on those. It carries no value, changes nothing and nothing is decided
from it; an unknown or archived set is 404.

## Transport encryption

Values and private keys cross the edge as one RFC 9180 HPKE base-mode message
per fresh key pair: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, the
suite of the bucket-open packet ([Buckets](#buckets)). Public keys are uncompressed SEC1 points (65
bytes); binary fields are unpadded base64url. `T(role, f...)` is the sealed
store's framed tuple (`aqmas-seal`, uint64 1, role, then each field, every
component prefixed with its uint32 big-endian length).

| Direction | Recipient key | `info` | AAD |
|---|---|---|---|
| Browser → broker (form edit, signer import) | Broker's, from `POST attempt`: in memory, one packet, five minutes, bound to the session | `T("hpke-vault", installation, purpose)` with purpose `edit` or `signer-import` | `T("hpke-vault-aad", attempt ID (32 bytes), epoch, set ID as UTF-8)` |
| Broker → browser (reveal) | Browser's, generated for this reveal and named in the signed canonical | `T("hpke-vault", installation, "reveal")` | `T("hpke-vault-aad", SHA-256 of the canonical, epoch, set ID as UTF-8)` |

The edge and any HTTP body logger see ciphertext only. The broker's upload
key is named in the signed metadata (`recipient`), as an open recipient is:
the page signs for the key it sealed to, so a packet opened and re-sealed on
the way is refused by the page before the tap. As with opening buckets
([SEALED.md](SEALED.md)), none of this defends against an edge that serves a
different page: such a page can read what is typed into it. An upload attempt
and a generated key awaiting its tap are dropped after five minutes, at
logout, and when their challenge is refused or finished.
A packet for one set, attempt, boot epoch or purpose does not open as another.
The reveal AAD contains the canonical's digest, and so its nonce: a recorded
response cannot be replayed into a later ceremony. Vectors:
`test/vectors/vault.json` (Go and TypeScript each open what the other sealed).

## Routes

* `GET state` → `{schemes, organisations:[{id,slug,title,allow_reveal}], sets, requests}`.
  A set carries `org_id, org_slug, org_title, service_id, service_slug,
  service_title, set_id, set_slug, set_title, kind ("env-set" | "signer"),
  revision, names, allow_reveal` and, for a signer, `scheme, origin, created_at,
  signatures, public_key, public_hex, public_pem, fingerprint` (SHA-256 of the
  raw public key). `requests` are pending signing requests and live signing
  grants (below). Metadata only; needs no open bucket.
* `POST attempt` `{}` → `{attempt_id, recipient, expires_at}`.
* `POST challenge` with a choice (below) → `{canonical, challenge_id, public_key, facts, open?}`.
* `POST finish` `{challenge_id, assertion, open?}` → the action's result.

Every action is a v3 review canonical: sorted keys `action, epoch, id,
installation, issued_at, metadata, nonce, object ("vault"), v (3)`.
`metadata` is a string holding a JSON object with sorted keys, no
insignificant space, `/`, `<`, `>` and `&` unescaped, U+2028/U+2029 as
` `/` `. The page builds the expected metadata from what the owner
chose and what `state` showed, and refuses a canonical that differs by one
byte. `finish` consumes the stored challenge, verifies a fresh user-verified
assertion over its SHA-256 (bound to the descriptor for `reveal` and
`sign-approve`, which open the set's bucket), rebuilds the metadata from current rows and
applies only if it is byte-identical. No vault action can be confirmed under
an approval window or in a batch. *Target fields* below are `org_id, org_slug,
org_title, service_id, service_slug, service_title, set_id, set_slug,
set_title, kind, revision`.

| `action`, `id` | Choice fields | Signed metadata | Result |
|---|---|---|---|
| `commit`, set ID | `attempt_id, enc, ciphertext, commitment` | target fields, `attempt_id, recipient, operation, changes, commitment, result_revision` | `{ok}`; a new immutable revision |
| `reveal`, set ID | `names` (sorted, unique, non-empty), `recipient` | target fields, `names, recipient` | `{enc, ciphertext}` |
| `policy`, org ID | `allow_reveal` | `org_id, org_slug, org_title, old_allow_reveal, allow_reveal` | `{ok}` |
| `signer-create`, new set ID (32 lower-case hex) | `service_id, set_slug, set_title, scheme, source` (`generate` or `import`); for import also `attempt_id, enc, ciphertext` | target fields of the new set (`kind` `signer`, `revision` 0), `scheme, source, attempt_id, recipient` (empty for a generated key), `public_key, fingerprint, result_revision` (0: a signer set stays at revision 0, its key is immutable) | `{set_id, path, scheme, public_key, public_hex, public_pem, fingerprint}` |
| `sign-approve`, `sign-deny`, `sign-revoke`; request ID | approve: `ttl_seconds, max_signatures` | target fields, `request_id, host, enrollment, address, scheme, fingerprint, items` (each `name, size, sha256` and, for a SHA-512 scheme, `sha512`), `requested_ttl_seconds, requested_max_signatures, ttl_seconds, max_signatures, admission_generation, policy_revision, service_revision, soft_cap_seconds, beyond_soft_cap` | `{ok}` |

`facts` are unsigned conveniences: `attempt_id` (the broker allocates one for
a generated key) and, for `signer-create`, `public_key, public_hex, public_pem,
fingerprint`. The page copies `attempt_id`, `public_key` and `fingerprint`
into its expected metadata, shows the public key from the canonical, and for
an import the owner compares it with the public half they already know.

**Form edit.** The plaintext is `{"operation","salt","entries":[{"name","value"}],"remove":[names]}`
(`salt`: 32 random bytes, standard base64 with padding). `operation` is
`merge` (add or replace `entries`, delete `remove`, keep the rest) or `import`
(the set becomes exactly `entries`; no `remove`). `commitment` is the env edit
commitment below with, for `merge`, one more group per removed name (sorted):
`"remove"`, the name, an empty value. `changes` is the sorted, comma-joined
list of `NAME:add`, `NAME:replace`, `NAME:remove`. The page never receives old
values: it computes `changes` from the key names in `state`. Limits are those
of an env set (64 keys, 8192 bytes a value, 24 KiB in all); a value may hold
any UTF-8 text except NUL, including newlines. The page stores line breaks
as LF and refuses an imported value that contains a carriage return (a text
box cannot keep one); `aqmas set import` stores such a value exactly.

**Reveal.** Refused for a signer (always), when the organisation's
`allow_reveal` is off. The tap opens the set's bucket for an instant. The plaintext is
`{"entries":[{"name","value"}]}` for exactly the signed names. The audit row
names the set, revision and key names. A new organisation allows reveal;
`policy` turns it off or on.

**Signer.** The private key is generated by the broker, or parsed from the
sealed import packet `{"private_key": text}` (hex seed or scalar; PKCS#8, SEC1
or OpenSSH PEM, unencrypted). It is sealed to the signer's own bucket under
role `signer-key`; `sign-approve` opens that bucket until the grant is used up,
expires or is revoked. No route returns it; there is no export.

**Dotenv import** (browser and `aqmas set import`): `NAME=value` lines, blank
lines and `#` comment lines. A value is bare (no quote, backslash, `$`,
backtick, `#` or surrounding space), single-quoted (literal, may span lines)
or double-quoted (may span lines; exactly the escapes `\n \r \t \\ \"`).
Nothing is expanded; only space or tab may follow a closing quote; CRLF is
read as LF. Errors name the line, never its content. Vectors:
`test/vectors/dotenv.json`.

## Signing (agent API, client certificate required)

* `GET /v2/sign/key?path=org/service/set` → the binding: `path, title, org,
  service, set, revision, service_revision, policy_revision,
  admission_generation, enrollment, host, class, scheme, public_key (standard
  base64), default_seconds, soft_cap_seconds`. Admitted hosts only; 404 otherwise.
* `POST /v2/sign/requests` `{binding, reason, ttl_seconds, max_signatures, items}` →
  the pending request. `ttl_seconds` 0 asks for a single-use grant (exactly
  `items`, once, collected within ten minutes of approval); above 0 asks for a
  time-boxed grant of up to `max_signatures` (default 20, at most 1000) for
  one minute to 24 hours. An item is `{name, size, sha256}` plus `sha512` or `message`
  (standard base64) when the scheme signs that; `size` is -1 when only a digest
  was given. At most 16 items a call and, for a scheme that signs the artifact
  itself, 40 KiB of artifacts. At most 30 requests an hour from one host
  (429), whatever became of them; ended requests are forgotten after 30 days
  (the audit log keeps them).
* `GET /v2/sign/requests/{id}`, `POST .../{id}/cancel`, `GET /v2/sign/grants/{id}`,
  `POST /v2/sign/grants/{id}/end`: metadata, cancel, end early.
* `POST /v2/sign/grants/{id}/sign` `{items}` → `{request, signatures:[{name, sha256, signature}]}`.
  423 `locked` while the signer's bucket is closed (after a restart:
  **Reopen**). Same host and address as the request. Each signature is
  verified against the public key and audited (path, scheme, digests, size,
  name, enrollment, address) in the transaction that spends the grant.

| Scheme | Key | Broker receives | Signature |
|---|---|---|---|
| `ed25519` | Ed25519 | the artifact (at most 4096 bytes) | pure Ed25519 over it; 64 raw bytes |
| `ed25519-sha256` | Ed25519 | SHA-256 | pure Ed25519 over the 32 raw digest bytes; 64 raw bytes |
| `ed25519ph` | Ed25519 | SHA-256 and SHA-512 | RFC 8032 Ed25519ph, empty context; 64 raw bytes |
| `ecdsa-p256-sha256` | P-256 | SHA-256 | ECDSA over the digest; ASN.1 DER |

A key has one scheme for life, fixed in the signed `signer-create` and inside
its sealed record.

# Bastion access

Design, rules and the owner's steps: [BASTION-ACCESS.md](BASTION-ACCESS.md). This is the wire
summary. A bastion session is request kind `bastion`: it has endpoints of its own, and the
generic request endpoints (`/v1/requests…`, batches, windows) answer 404 or refuse for it.

## Agent API (client certificate required)

* `GET /v1/bastion` → `{name, address, port, inspect_user, admin_user, root_allowed,
  inspect_max_seconds, inspect_default_seconds, root_max_seconds, tasks[]}`; 404 while access
  to the bastion is not installed.
* `POST /v1/bastion/requests {level, public_key, reason, ttl_seconds, requester}` → 201
  `RequestCreated`. `level`: `inspect` | `root`. `reason` is required. `ttl_seconds` 0 means
  the default (inspect 3600, root 1800); it is clamped to the level's maximum (root 3600).
  `root` from a host or address that is not on root's allowlist → 403, nothing queued.
* `GET /v1/bastion/requests/{id}?wait=` → `RequestStatus`. The grant is `{id, kind:"bastion",
  not_before, not_after, ssh{certificate, principals, target_host, target_address,
  target_port, login_user, known_hosts_line}}`. Inspect: the certificate on every poll. Root:
  the request reads `pending` until the alert attempt is recorded; the certificate is returned
  by one poll only, from the requesting address, within 5 minutes of approval (later:
  `revoked`); afterwards `certificate` is `""` and `decision_note` says why.
* `POST /v1/bastion/requests/{id}/cancel`.
* `POST /v1/setup-requests {task, params, reason, requester}` → 201 `RequestCreated`. Tasks:
  `os-update` (`{"kernel":false}` only), `reboot`, `restart-cloudflared`, `restart-broker`,
  `disk-usage`, `journal-vacuum` (`{"keep_days":7…365}`). 403 for any other task or
  parameters only the owner may choose; 429 when one is already pending for the host, three
  are pending in all, or the host asked three times in five minutes.
* `GET /v1/setup-requests/{id}?wait=&after=` → `{id, task, status, decision_note, run?}` with
  `status` `pending | approved | denied | expired | cancelled` and, once approved,
  `run{state, step, message, log[], result{}, finished_at}`, `state` `queued | running |
  waiting | done | failed | refused`. `after=<state>` makes the long poll wait until the run
  leaves that state.
* `POST /v1/setup-requests/{id}/cancel`.

## Certificates

| Level | Principal | Critical options | Extensions |
|---|---|---|---|
| inspect | `aqmas-inspect@<name>` | `source-address`, `force-command="/usr/local/bin/aqmasd inspect"` | none |
| root | `<admin_user>@<name>` | `source-address` | `permit-pty` |

Key id `aqmas:<grant-id>:<requesting-host>:bastion-<level>`; serial = grant row id.

## Web API

* `GET /api/ui/state`: pending items of kind `bastion` carry `bastion{level, target,
  target_address, target_port, login_user, principal, key_fingerprint, host_id, ssh_ca,
  host_key, cert_profile, sealed, open_buckets[], alert_channel}`; items of kind `setup` carry
  `setup{task, title, summary, steps[], reversible, warning, params, blocked}`.
  `bastion_root_until` is set while a root certificate is unexpired and unrevoked.
* `POST /api/ui/requests/{id}/challenge {action, ttl_seconds, close_buckets}` and
  `…/decide`, as for every request. `close_buckets` is required for a root approval of a
  sealed store and refused everywhere else; standing and indefinite choices are refused.
  Decide answers `{id, kind, status, level, closed_count, alert}` with `alert` `sent | failed
  | off` (root) and stays open until the alert attempt is over (at most 10 s).
* `GET /api/ui/bastion` → the Bastion access section (fields in BASTION-ACCESS.md §10).
* Revoking a bastion grant: `POST /api/ui/grants/{id}/challenge|revoke`, as for every grant.
* Queued maintenance: approve with the Setup flow ([SETUP.md](SETUP.md)) passing `request`;
  drop with `POST /api/ui/setup-requests/{id}/dismiss`.

## Canonical text

`request` with `kind:"bastion"` (version 1 in every mode), besides the common keys:
`kind, level, requesting_host, host_id, address, target, target_address, target_port,
login_user, principal, key_fingerprint, ssh_ca, host_key, cert_profile, ttl_seconds, sealed,
open_buckets, close_buckets, alert_channel`. Example (root, sealed store, one bucket open,
"close first" chosen):

```json
{"action":"approve","address":"192.0.2.21","alert_channel":true,"cert_profile":"source-address;permit-pty","close_buckets":true,"host_id":"01JD…","host_key":"SHA256:…","id":"01JE…","issued_at":"2026-11-23T10:00:00Z","key_fingerprint":"SHA256:…","kind":"bastion","level":"root","login_user":"alice","nonce":"…","object":"request","open_buckets":"[\"SSH user CA\"]","principal":"alice@bastion","requesting_host":"dev-1","sealed":true,"ssh_ca":"SHA256:…","target":"bastion","target_address":"192.0.2.10","target_port":22,"ttl_seconds":1800,"v":1}
```

Rules both sides enforce when building and parsing: `level` is `inspect` or `root`;
`cert_profile` is `source-address;force-command` for inspect and `source-address;permit-pty`
for root; `principal` equals `login_user@target`; `open_buckets` is the JSON encoding
(no whitespace, no HTML escaping) of a sorted array of distinct strings; a non-empty list,
`close_buckets:true` and `alert_channel:true` occur only on a root `approve` (the first two
only when `sealed`); `ttl_seconds` is 0 for `deny`, positive for `approve`, and at most 3600
for root. There is no `standing_hours` key, and no `standing` object of this kind.

## CLI

```
aqmas ssh bastion --why "…" [--level inspect|root] [--ttl D] [-- <inspect command>]
aqmas cert bastion --why "…"                      # inspect only
aqmas bastion                                     # what this host may ask for
aqmas bastion task <task> --why "…" [--keep-days N]
```

Inspect reuses its cached certificate like any SSH grant. Root never touches the cache: key
and certificate live in a private temporary directory for the one `ssh`, which runs as a
child, and are deleted when it exits. `aqmas bastion task` exits 0 when the task is done, 1
when it failed or the runner refused it, 3 when the owner dismissed it, 4 when it expired.
