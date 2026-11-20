# agent-quartermaster (`aqmas`): design, milestones 1 and 2

Status (2026-11-20): milestone 2 (Cloudflare API access through aqmasd: proxy with scoped,
time-boxed grants, guard rails, snapshots, child tokens) is built and tested, not deployed:
design and operator setup `docs/CLOUDFLARE.md`, wire contract `docs/API.md` section 5.
Milestone 1 is built and tested (unit tests, `TestUIFlows`, and `test/interop/run.sh` with the
real binaries). Wire contract: `docs/API.md`; host and Forgejo trust: `docs/HOSTS.md`. A
site's own deployment plan, real target list and progress notes belong in its private ops
documentation, not in this repository.

A credential broker for a single owner's home lab or small fleet. Agents (Claude Code,
OpenCode) and the owner ask it for short-lived, approved access to other machines and services
instead of holding long-lived keys.

## Threat model

- Contain **one compromised agent or service on one host** to that host.
- Agents keep passwordless sudo on the host they were started on. Reaching **any other host**
  needs a grant the owner approves. The owner's own routine SSH also goes through aqmas.
- Convenience matters: grants must be quick to request and approve, and things must keep
  working when aqmas is down (a separate owner emergency key covers that; not aqmas's job).
- A dedicated **bastion** host runs aqmasd and nothing agents use. It must
  only accept an owner key that agents never hold (prerequisite, done by the owner/operator,
  not by this code): otherwise an agent could SSH in, become root and approve itself.

## Milestone 1 scope

1. **aqmasd** (Go, one binary) on the bastion: request/grant store, SSH user CA, agent API (mTLS),
   approval web UI with a **passkey (WebAuthn) assertion per approval**, push notification.
2. **aqmas** CLI (Go, same module) on fleet hosts: request SSH access, wait for approval, run
   `ssh` with the short-lived certificate. Also `enroll` (host identity), `status`, `list`.
3. **Fleet hosts** trust the aqmas SSH user CA (`TrustedUserCAKeys`) with per-host principals.
4. **Forgejo SSH (:2222)** trusts the same CA (built-in server, `SSH_TRUSTED_USER_CA_KEYS`).

Later milestones (design here only so M1 doesn't paint us into a corner): GitHub App
installation tokens; Forgejo API via Forgejo *authorized integrations* (aqmasd as JWT issuer);
Cloudflare policy proxy + minted expiring child tokens; generic header-injecting HTTP proxy;
SSH `ProxyJump` through aqmasd to cut sessions at expiry; KRL-based revocation.
See [Organisations, services and credential sets](ORGANISATIONS.md) for organisation-scoped approvals and CLI delivery of application secrets.

## Key decisions

- **Approval channel:** web UI served by aqmasd on 127.0.0.1 on the bastion, published through
  **its own Cloudflare tunnel connector on the bastion** (not a tunnel shared with other hosts)
  at e.g. `approvals.example.com`, behind a Cloudflare Access app (owner only). Access is convenience only; the security boundary
  is the **WebAuthn assertion per approval**, whose challenge commits to the exact request
  (see API.md "approval challenge"). No LAN DNS override for that name.
  **Accepted residual (wider than first thought):** whoever can change the Cloudflare zone
  (Workers, Snippets, DNS, the tunnel) controls the approval page's code and can show one action
  while having the owner sign another. In the reference deployment a Cloudflare token on
  another host is readable by the agents' user there, not only by root. Mitigations in M1: the UI renders the
  confirmation from the signed canonical text only, the CLI prints the same **Ref** as the card,
  and after every decision aqmasd pushes what it **applied** to ntfy (a mismatch shows on the
  phone). Real fix: narrow that token, or serve the UI from a zone it cannot
  edit; a later milestone moves the Cloudflare token into aqmas.
- **Owner passkey bootstrap:** the first passkey is registered with a one-time code that
  `aqmasd passkey-enroll-code` prints on the bastion (root/aqmas user only). Later passkeys need an
  existing passkey to approve them.
- **Several passkeys:** the owner keeps more than one (passkeys in password
  managers and platform keychains, and hardware security keys). The UI lists them (nickname,
  authenticator from the AAGUID, synced vs device-bound, created, last used, "this device")
  and can add, rename and remove them; rename and remove are passkey-signed actions with their
  own canonical text (API.md), every change is audited and pushed to ntfy, and the **last
  passkey can never be removed** (server-enforced): losing them all means a new enroll code on
  the bastion. Removing a passkey ends its web sessions.
- **Host identity:** each fleet host enrolls once (`aqmas enroll`): it generates an ECDSA P-256
  client key, aqmasd issues a client certificate (`clientAuth` EKU, `client_cert_days`, default
  730) from its internal CA after the owner approves the enrollment in the web UI (the card shows
  the CSR key fingerprint, the host's SSH host key fingerprints and the CLI's Ref). Agents on
  that host use it (it lives in the agent user's config dir: an agent already has root on its
  own host by design). A request is attributed to the host whose certificate authenticated it.
  Re-enrolling an existing name is a high-risk card; approving it revokes the old certificate.
  Revoke a host from Admin with a signed confirmation bound to its immutable enrollment ID,
  or with `aqmasd revoke-host NAME` on the bastion. Owner-device enrollment signs the class;
  existing and ordinary hosts remain agent-class. The owner defaults are a 24-hour maximum
  SSH TTL and 30-day standing window. Existing high-risk and per-target limits still apply.
  Owner-device sessions are never subject to any future “cut sessions at grant expiry” policy.
- **Agent API trust:** one internal CA signs both the agent-API server certificate
  (`serverAuth` only, SANs from `tls_sans`) and host client certificates (`clientAuth` only);
  the TLS handshake carries leaf + CA. Hosts pin the **CA** (`aqmas enroll --ca-pin` with the
  value of `aqmasd tls-fingerprint`), check the server name and require `serverAuth`, so an
  enrolled host cannot impersonate aqmasd and the server leaf can be renewed freely. aqmasd
  refuses its own server certificate as a client identity. Separate CAs would be cleaner and
  are deferred.
- **SSH certificates:** aqmasd signs the requester's **ephemeral** Ed25519 public key (generated
  per request by the CLI, private key never leaves the requesting host) with:
  principals `["<login-user>@<target-hostname>"]`; validity `now-1m .. now+ttl`;
  critical option `source-address` = the requesting host's address as seen on the mTLS
  connection, as a `/32`; extensions `permit-pty`, `permit-port-forwarding` only; key id
  `aqmas:<grant-id>:<requesting-host>:<target>`; serial = grant row id. Target hosts map that
  principal via `AuthorizedPrincipalsFile` (see HOSTS.md). Forgejo targets carry an explicit
  `principal` that must contain `@` (a bare name would double as a Unix login on a host that
  trusts the CA without a principals file), and a short `max_ttl_seconds`, because Forgejo's
  built-in server probably ignores `source-address`. The CLI checks each certificate against
  the CA published at `GET /v1/ssh-ca`.
- **TTLs:** default 30 min, min 1 min, max 8 h for SSH, optionally capped per target. The
  approver can shorten, never lengthen (a longer choice is refused, not clamped, so the signed
  text always equals the choice), and can choose "approve similar requests for 1/4/8 hours"
  (same requesting host + same target + same login user; server cap 24 h), which auto-approves
  matching requests until it expires (shown in the UI, revocable; revoking a grant also
  revokes the standing approval created with it and the one that issued it). A standing
  approval only matches requests from the address the approved request came from (a host's
  stolen client key used elsewhere gets no silent grants), and none is allowed for high-risk
  requests (`high_risk` targets, root, TTL above 4 h). No other auto-approval in M1. Undecided
  requests expire after 10 min, enrollments after 1 h. A host may have 5 pending requests;
  enrollments are limited to 20 pending, 3 per address. Ctrl-C in `aqmas` cancels the pending
  request (`cancelled`).
- **Certificate reuse:** a cached certificate for (user, host) is reused by any aqmas process
  of the same Unix user on the requesting host while >= 2 min remain: the owner approves access
  for a host, not for one agent session (agents on one host are one trust domain anyway).
- **Revocation in M1:** short TTLs only; revoking a grant in the UI marks it revoked (shown,
  audited) but cannot kill an issued certificate. KRL distribution is a later milestone.
- **Notifications:** ntfy (publish to a configured topic URL with a random topic name): "aqmas:
  <host> wants ssh <user>@<target>" plus the link for new requests and enrollments, and after
  every decision what was applied, with the Ref. Configurable; failure to notify never blocks a
  request.
- **Storage:** SQLite (pure Go driver `modernc.org/sqlite`), WAL, at `/var/lib/aqmas/aqmas.db`;
  CA keys under `/var/lib/aqmas/ca/` (mode 600, user `aqmas`). Audit log table, append-only.
- **Runtime on the bastion:** system user `aqmas`, systemd unit with hardening
  (`deploy/bastion/aqmasd.service`); agent API on `:8443` (TLS 1.3, client certs required except
  for enrollment; firewall it to the LAN), web UI on `127.0.0.1:8080` (its own cloudflared
  connector → it). Web API guards: `X-Aqmas` header, `Origin`/`Sec-Fetch-Site` checks, strict
  CSP, optional Cloudflare Access JWT validation bound to the owner's identity.
- **Toolchain:** Go 1.27 (user-local install at `~/.local/toolchains/go`), web UI in TypeScript built with Bun 1.4.4 into
  static files embedded in the aqmasd binary (`go:embed`). aqmasd is built for linux/arm64;
  the CLI for linux/arm64, linux/amd64 and darwin/arm64.

## Repository layout (contract between parallel workstreams)

```
go.mod                         module github.com/aquarat/agent-quartermaster
internal/api/                  SHARED wire types (owned by the lead; change only by agreement)
cmd/aqmasd/                    server main            (workstream: server)
internal/server/...            server packages         (workstream: server)
cmd/aqmas/                     CLI main               (workstream: client)
internal/client/...            client packages         (workstream: client)
web/                           TS sources, Bun build -> web/dist (workstream: web)
internal/webui/                go:embed of web/dist (`make build` copies it in)
internal/server/cfscope/       M2: Cloudflare scope catalogue, routes, deny-list (workstream: cf-proxy)
internal/server/cfproxy/       M2: Cloudflare proxy, guard rails, snapshots, minter (cf-proxy)
internal/testutil/fakecf/      M2: fake Cloudflare API for tests and interop (client)
deploy/bastion/                aqmasd.service, install.sh, cloudflared unit + config template
deploy/hosts/                  10-aqmas.conf, install-host-trust.sh, forgejo-ca.md
test/interop/                  run.sh (real binaries end to end), owner.ts, softauthn.ts
docs/                          DESIGN.md, API.md, HOSTS.md, CLOUDFLARE.md, UPDATES.md
```

Build and test: `make vet test build` (aqmasd linux/arm64; aqmas linux/arm64 and amd64, with
`web/dist` embedded), `cd web && bun test`, `AQMAS_WEB_DIR=$PWD/web go test ./internal/server
-run TestUIFlows` (the UI's own flow code against a real server), `make interop`.

## Open questions

- **Port forwarding:** every certificate carries `permit-port-forwarding` (design decision; it
  is not in the canonical text). A grant can be used as a SOCKS pivot into the target's
  networks; making it a per-target opt-in would need a config key and possibly a canonical
  field.
- **Cached certificates after revoke:** the CLI stops reusing a revoked grant, but the files
  stay on the requesting host until expiry and a compromised agent there can still use them
  (KRL distribution is a later milestone). An unreachable server does not block reuse.
- **Re-enrolling an expired host** still shows "replaces an existing host" (the old row is only
  expired, not revoked), which is accurate but makes the warning routine every 730 days.
- **Forgejo TTL:** `max_ttl_seconds = 3600` is the only control while `source-address` is
  unenforced; consider 900.
- **Cloudflare zone control** (residual above): milestone 2 moves the token into aqmasd; after
  the M2 cut-over agents can change the zone only through scoped grants the owner approves
  (Workers/DNS/tunnel writes are not auto-approved), which narrows this residual to "an
  approved grant for the zone serving the UI".
- **Forgejo, untested:** whether the built-in server enforces `source-address` (believed not),
  and whether the principals UI accepts `alice@forgejo` with
  `SSH_AUTHORIZED_PRINCIPALS_ALLOW = anything` (alternative: `email` with an address on the
  owner's account as the principal; it also contains `@`). Test before relying on Forgejo
  grants.
- **One CA for server and client certificates** (EKU split today); separate CAs later.
- **`Requester.ppid`** (client proposal): the parent pid identifies the agent process better
  than aqmas's own pid. Not added; display only either way.
- **`aqmas git-ssh`**: a `GIT_SSH_COMMAND` helper mapping `git@<forgejo host>:2222` to the
  `forgejo` target.
- **cloudflared runs as root** (packaged default) with systemd hardening; a dedicated user is
  possible later. aqmasd has no outbound IP filter (it needs ntfy and the Access certs).
