# Contract notes from the web workstream (`ws/web`)

Proposals and assumptions the web UI makes where `docs/API.md` section 2 or
`internal/api/types.go` leave a gap. The UI's API calls all live in `web/src/api.ts` and
`web/src/flows.ts`, so any of these is a one-place change if the server decides otherwise.
`web/mock/server.ts` implements exactly what is written here.

## 1. Begin/finish bodies for login and registration (gap)

API.md names the endpoints but not the bodies. The UI uses the same pattern as the action
challenge/decide pair:

| Endpoint | Request body | Response |
|---|---|---|
| `POST /api/ui/login/begin` | `{}` | `{challenge_id, public_key}`; `public_key` is go-webauthn's `CredentialAssertion` (`{"publicKey": {...}}`), discoverable (empty `allowCredentials`), `userVerification: "required"` |
| `POST /api/ui/login/finish` | `{challenge_id, assertion}` | `{ok: true}` + `Set-Cookie` session |
| `POST /api/ui/passkeys/register/begin` | first passkey: `{enroll_code}`; later: `{challenge_id, assertion}` (see 2) | `{challenge_id, public_key}`; `public_key` is go-webauthn's `CredentialCreation`, `residentKey: "required"`, `userVerification: "required"` |
| `POST /api/ui/passkeys/register/finish` | `{challenge_id, credential}` | `{ok: true}` |

`assertion`/`credential` are the browser's PublicKeyCredential as JSON in the shape go-webauthn
parses (`id`, `rawId`, `type`, `authenticatorAttachment`, `clientExtensionResults`,
`response.{clientDataJSON, authenticatorData, signature, userHandle}` or
`response.{clientDataJSON, attestationObject, transports}`), binary fields unpadded base64url.
`userHandle` is omitted (not `null`) when the authenticator returns none. The server can feed
the inner object to `protocol.ParseCredentialRequestResponseBytes` /
`ParseCredentialCreationResponseBytes` after re-marshalling it.

The UI also accepts a bare `CredentialAssertion` / options object without the
`{challenge_id, public_key}` wrapper; it then sends no `challenge_id` (server keeps WebAuthn
session data some other way, e.g. a short-lived cookie).

`login/begin` returning **409 `conflict`** means "no passkey registered yet": the UI then opens
the enroll-code form. (Any other way to tell first run is fine too; say which.)

## 2. Adding a later passkey (gap)

"Later ones need a session plus an assertion": proposed

1. `POST /api/ui/passkeys/challenge {action: "add"}` -> `ChallengeResponse` with canonical
   `{"action":"add","id":"new","issued_at":...,"nonce":...,"object":"passkey","v":1}`.
2. Assertion over that, sent as `POST /api/ui/passkeys/register/begin {challenge_id, assertion}`
   -> creation options (as in 1). Then `register/finish` as usual.

## 3. `UIState.grants` (missing; needed for "Active grants")

`UIState` has no grants. Proposed: `grants: [GrantSummary]` (active ones, newest first), and
`GrantSummary.requesting_host` (`json:"requesting_host,omitempty"`) so the owner sees who holds
the access. The UI shows "This server doesn't list active grants yet" if the field is absent.

## 4. Enrollments in `PendingItem`

The UI expects enrollments in `UIState.pending` with `kind: "enrollment"`,
`requesting_host` = proposed host name, `requesting_address` = connecting address,
`reason` = the enroll `note`, and proposes an optional
`enrollment: {csr_fingerprint, ssh_host_key_fingerprints[], replaces_existing}`
(`PendingEnrollment`). `ttl_requested`/`ttl_max` are ignored for enrollments.

## 5. Canonical action (what the UI checks before it calls `navigator.credentials.get`)

The UI refuses to sign unless **all** hold:

- `canonical` re-serialises byte-for-byte as sorted-key, whitespace-free JSON (Go's default
  `\u003c` / `\u003e` / `\u0026` escaping and the unescaped form are both accepted). This
  rules out duplicate keys, i.e. text that two parsers could read differently.
- `v == 1`; `action`, `object`, `id` are non-empty strings; `ttl_seconds` and
  `standing_hours`, when present, are non-negative integers.
- **base64url-decoded `public_key.publicKey.challenge` == SHA-256(UTF-8 bytes of
  `canonical`)**. With go-webauthn this means `BeginLogin(user, webauthn.WithChallenge(sum))`
  (or equivalent): the default random challenge would fail this check.
- Fields match what the owner chose and what the card showed: `action`; `object`
  (`request`, `enrollment`, `standing`, `grant`, `passkey`); `id`; for requests
  `requesting_host`, `kind`, `target` (= `ssh.target_host`), `login_user`, `key_fingerprint`
  (= `ssh.key_fingerprint`); for standing/grant revokes `requesting_host` (if the item had
  one), `kind`, `target`, `login_user`; approve: `ttl_seconds` == chosen TTL (absent counts
  as 0), `standing_hours` == chosen (absent = 0); deny/revoke: `standing_hours` absent or 0.

- **Only known keys**, per object, else the UI refuses to sign (an unknown field such as a
  forced command must not be signed blind):
  common `v, action, object, id, nonce, issued_at`; `request` + `requesting_host, kind, target,
  login_user, key_fingerprint, ttl_seconds, standing_hours`; `enrollment` + `requesting_host,
  kind, key_fingerprint, replaces, ttl_seconds, standing_hours`; `standing` and `grant` +
  `requesting_host, kind, target, login_user, ttl_seconds, standing_hours`; `passkey`: common
  only. Actions: request/enrollment `approve|deny`, standing/grant `revoke`, passkey `add`.
  Adding a field later means updating `web/src/canonical.ts` in the same change.
- Enrollments: `kind` is `"enrollment"`, `key_fingerprint` is the CSR public key fingerprint
  (compared with `enrollment.csr_fingerprint` when the card has it), and **`replaces: true`**
  must be present when approving revokes an existing host's certificate (compared with
  `enrollment.replaces_existing`; absent counts as false).
- Server note: Go's `json.Marshal` of a struct emits keys in declaration order, not sorted.
  Marshal a `map[string]any` (sorted by Go) or declare the struct fields alphabetically. Keep
  keys ASCII (Go sorts by bytes, JavaScript by UTF-16 units). Values are strings, integers and
  booleans only.

The text shown to the owner is generated from the canonical fields only; each value is rendered
in its own `<bdi>`, invisible/bidi control characters are shown as `⟨U+XXXX⟩`, and a host or
user name outside `[A-Za-z0-9._-]` gets a warning. The server should restrict host names to
`[a-z0-9-]` anyway.

## 6. Challenge request bodies

- Approve request: `{action: "approve", ttl_seconds, standing_hours?}`; `standing_hours` is
  sent only when non-zero (1, 4 or 8). The UI caps `ttl_seconds` at `ttl_max`; the server
  should **reject** (400) a larger value rather than silently clamp it, because a clamped value
  in `canonical` would differ from the owner's choice and the UI would refuse it anyway.
- Deny request / enrollment: `{action: "deny"}`. Approve enrollment: `{action: "approve"}`.
- Revoke standing/grant: `{action: "revoke"}` to `.../challenge`, then
  `{challenge_id, assertion}` to `.../revoke`. The UI ignores the revoke response body.
- Action challenges: `timeout` in the options is used if <= 120 s; otherwise the UI assumes the
  2-minute lifetime from API.md and disables "Confirm" after it.

## 7. Errors the UI interprets

`401 unauthenticated` -> back to sign-in. `409 conflict` on decide -> "already acted on".
`404 not_found` -> "decided, revoked or expired elsewhere". `410`/`expired` -> start again.
A 3xx (Cloudflare Access session expired) -> "reload the page". POSTs always send
`X-Aqmas: 1` and `Content-Type: application/json`, credentials `same-origin`.

## 8. Static serving

`web/dist` is `index.html` + hashed `index-*.js`, `index-*.css`, `icon-*.svg`, referenced
with absolute paths (`/index-abc.js`), so serve dist at `/`. No inline scripts or styles; CSP
`default-src 'self'; frame-ancestors 'none'` is enough (the mock also sends `base-uri 'none';
form-action 'none'; object-src 'none'`). Suggested caching: `index.html` `no-cache`, hashed
assets immutable.

Cards show **Ref** = the last 6 characters of the item id, upper-cased. Proposal for the CLI:
print the same ref in its one-line summary, so the owner can match a card to the terminal
(the agent relays `approve_url`, so the highlighted card alone proves nothing).

The UI forces `userVerification: "required"`, `residentKey: "required"` on creation and
`userVerification: "required"` on assertions, drops server-sent extensions (creation sends
only `credProps`), and caps an action challenge's `timeout` at 120 s.

`approve_url` in `RequestCreated`/`EnrollResponse`: the UI scrolls to and highlights an item
when opened as `https://approvals.example.com/#r=<id>` (fragment, so no server routing).
