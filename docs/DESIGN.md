# agent-quartermaster (`aqmas`): design, milestone 1

Owner's home-lab credential broker. Agents (Claude Code, OpenCode) and the owner ask it for
short-lived, approved access to other machines and services instead of holding long-lived keys.

## Threat model

- Contain **one compromised agent or service on one host** to that host.
- Agents keep passwordless sudo on the host they were started on. Reaching **any other host**
  needs a grant the owner approves. The owner's own routine SSH also goes through aqmas.
- Convenience matters: grants must be quick to request and approve, and things must keep
  working when aqmas is down (a separate owner emergency key covers that; not aqmas's job).
- The bastion host **bastion (192.0.2.60)** runs aqmasd and nothing agents use. It must
  only accept an owner key that agents never hold (prerequisite, done by the owner/operator,
  not by this code): otherwise an agent could SSH in, become root and approve itself.

## Milestone 1 scope

1. **aqmasd** (Go, one binary) on .60: request/grant store, SSH user CA, agent API (mTLS),
   approval web UI with a **passkey (WebAuthn) assertion per approval**, push notification.
2. **aqmas** CLI (Go, same module) on fleet hosts: request SSH access, wait for approval, run
   `ssh` with the short-lived certificate. Also `enroll` (host identity), `status`, `list`.
3. **Fleet hosts** trust the aqmas SSH user CA (`TrustedUserCAKeys`) with per-host principals.
4. **Forgejo SSH (:2222)** trusts the same CA (built-in server, `SSH_TRUSTED_USER_CA_KEYS`).

Later milestones (design here only so M1 doesn't paint us into a corner): GitHub App
installation tokens; Forgejo API via Forgejo *authorized integrations* (aqmasd as JWT issuer);
Cloudflare policy proxy + minted expiring child tokens; generic header-injecting HTTP proxy;
SSH `ProxyJump` through aqmasd to cut sessions at expiry; KRL-based revocation.

## Key decisions

- **Approval channel:** web UI served by aqmasd on 127.0.0.1 on .60, published through **its
  own Cloudflare tunnel connector on .60** (not .50's tunnel) at `approvals.example.com`, behind
  a Cloudflare Access app (owner, OIDC IdP). Access is convenience only; the security boundary
  is the **WebAuthn assertion per approval**, whose challenge commits to the exact request
  (see API.md "approval challenge"). No LAN DNS override for that name.
  Known residual until the Cloudflare account token leaves the agents' hosts (a later milestone
  moves it into aqmas): root on the token's host could mint a certificate and phish the page. Documented, accepted for M1.
- **Owner passkey bootstrap:** the first passkey is registered with a one-time code that
  `aqmasd passkey-enroll-code` prints on .60 (root/aqmas user only). Later passkeys need an
  existing passkey to approve them.
- **Host identity:** each fleet host enrolls once (`aqmas enroll`): it generates an ECDSA P-256
  or Ed25519 client key, aqmasd issues a client certificate from its own internal client CA
  after the owner approves the enrollment in the web UI. Agents on that host use it (it lives in
  the agent user's config dir: an agent already has root on its own host by design). A request
  is attributed to the host whose certificate authenticated it.
- **SSH certificates:** aqmasd signs the requester's **ephemeral** Ed25519 public key (generated
  per request by the CLI, private key never leaves the requesting host) with:
  principals `["<login-user>@<target-hostname>"]`; validity `now-1m .. now+ttl`;
  critical option `source-address` = the requesting host's LAN address(es) as seen in the mTLS
  connection; extensions `permit-pty`, `permit-port-forwarding` (and `permit-agent-forwarding`
  off); key id `aqmas:<grant-id>:<requesting-host>:<target>`; serial = grant row id.
  Target hosts map that principal via `AuthorizedPrincipalsFile` (see HOSTS.md).
- **TTLs:** default 30 min, max 8 h for SSH. The approver can shorten, never lengthen, and can
  choose "approve similar requests for N hours" (same requesting host + same target + same
  login user), which auto-approves matching requests until it expires (re-shown in the UI,
  revocable). No other auto-approval in M1.
- **Revocation in M1:** short TTLs only; revoking a grant in the UI marks it revoked (shown,
  audited) but cannot kill an issued certificate. KRL distribution is a later milestone.
- **Notifications:** ntfy (publish to a configured topic URL with a random topic name; message
  carries only "aqmas: <host> wants ssh <user>@<target>" and the link). Configurable; failure to
  notify never blocks a request.
- **Storage:** SQLite (pure Go driver `modernc.org/sqlite`), WAL, at `/var/lib/aqmas/aqmas.db`;
  CA keys under `/var/lib/aqmas/ca/` (mode 600, user `aqmas`). Audit log table, append-only.
- **Runtime on .60:** system user `aqmas`, systemd unit with hardening; agent API on
  `:8443` (TLS, client certs required), web UI on `127.0.0.1:8080` (cloudflared → it).
- **Toolchain:** Go 1.27 (user-local install at `~/.local/toolchains/go`), web UI in TypeScript built with Bun 1.4.4 into
  static files embedded in the aqmasd binary (`go:embed`). Target linux/arm64 (all fleet Linux
  hosts are arm64 except db-1, amd64; build both CLI arches).

## Repository layout (contract between parallel workstreams)

```
go.mod                         module github.com/aquarat/agent-quartermaster
internal/api/                  SHARED wire types (owned by the lead; change only by agreement)
cmd/aqmasd/                    server main            (workstream: server)
internal/server/...            server packages         (workstream: server)
cmd/aqmas/                     CLI main               (workstream: client)
internal/client/...            client packages         (workstream: client)
web/                           TS sources, Bun build -> web/dist (workstream: web)
internal/webui/                go:embed of web/dist     (workstream: server; reads web/dist)
deploy/                        systemd units, install scripts, sshd snippets (workstream: client
                               for hosts/, server for bastion/)
docs/                          DESIGN.md, API.md, HOSTS.md
```
