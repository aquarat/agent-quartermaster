# agent-quartermaster (`aqmas`)

Credential broker for the owner's fleet: AI agents and the owner request short-lived,
passkey-approved access (SSH certificates first; GitHub, Forgejo, Cloudflare and HTTP APIs
later) instead of holding long-lived keys. Runs on the bastion (192.0.2.60).

- Design and milestone 1 scope: [docs/DESIGN.md](docs/DESIGN.md)
- API contract: [docs/API.md](docs/API.md), shared types in `internal/api`
- Fleet host trust: [docs/HOSTS.md](docs/HOSTS.md)

Toolchain: Go 1.27 (`~/.local/toolchains/go/bin`), Bun 1.4.4 for `web/`.
