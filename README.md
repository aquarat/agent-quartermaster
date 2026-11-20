# agent-quartermaster (`aqmas`)

Credential broker for a single owner's fleet: AI agents and the owner request short-lived,
passkey-approved access (SSH certificates, Cloudflare API grants; GitHub, Forgejo and HTTP
APIs later) instead of holding long-lived keys. The server (`aqmasd`) runs on a dedicated
bastion host; hosts enroll with the `aqmas` CLI.

Use the approval queue for daily work, the gear icon for passkeys and enrolled hosts,
and **Help** for enrollment and command examples using the running server’s URL and CA pin.

- Design and milestone 1 scope: [docs/DESIGN.md](docs/DESIGN.md)
- API contract: [docs/API.md](docs/API.md), shared types in `internal/api`
- Host and Forgejo trust: [docs/HOSTS.md](docs/HOSTS.md)
- Cloudflare (milestone 2): [docs/CLOUDFLARE.md](docs/CLOUDFLARE.md)
- Releases and self-update (planned): [docs/UPDATES.md](docs/UPDATES.md)

Toolchain: Go 1.27, Bun 1.4.4 for `web/`. `make vet test build`, `cd web && bun test`,
`make interop`, `make interop-cf`.

## Example deployment

Every site-specific value lives in configuration, never in the code:

- the bastion's `/etc/aqmas/config.toml` (`deploy/bastion/config.example.toml`): public URL
  (e.g. `https://approvals.example.com`), TLS SANs, targets with pinned host keys, ntfy topic,
  Cloudflare Access and Cloudflare account settings;
- each enrolled host's `~/.config/aqmas/config.toml`, written by
  `aqmas enroll --name web-1 --server https://192.0.2.10:8443 --ca-pin sha256:...`;
- each target host's `/etc/aqmas/host-trust.conf` for `deploy/hosts/install-host-trust.sh`
  (`deploy/hosts/host-trust.conf.example`).

Examples in this repository use placeholders: `example.com`, RFC 5737 addresses
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and hosts such as `bastion`,
`build-box`, `web-1` and `db-1`, with login user `alice`. Keep your own deployment notes,
target lists and host keys in private ops documentation.

## Licence

agent-quartermaster is free software: you can redistribute it and/or modify it under the terms of
the GNU Affero General Public License, version 3 (AGPL-3.0-only), as published by the Free
Software Foundation. See [LICENSE](LICENSE). If you run a modified version as a network service,
the AGPL requires you to offer its source to the service's users.

