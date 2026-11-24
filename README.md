# agent-quartermaster (`aqmas`)

Credential broker for a single owner's fleet: AI agents and the owner request short-lived,
passkey-approved access (SSH certificates, Cloudflare API grants, env credential sets,
signatures from keys that never leave the broker; GitHub, Forgejo and HTTP APIs later) instead of holding long-lived keys. The server (`aqmasd`) runs on a dedicated
bastion host; hosts enroll with the `aqmas` CLI.

## Status: alpha, use at your own risk

- This is **alpha software**. It works for its author's one installation; expect rough edges.
- It has **not had an independent security review**.
- It **brokers credentials**: SSH certificates, API tokens, signing keys. A mistake in it, or
  in how you deploy it, can expose them.
- **Use it at your own risk** (caveat emptor). There is no warranty; see the licence.
- **APIs, configuration and storage formats may change without a migration path** between
  versions.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

The approval page has seven tabs: **Approvals** for daily work, **Vault** for the credentials
(a searchable list of env sets, signing keys and what the broker holds; Add item; Reveal after a
tap), **Hosts**, **Activity**, **Security** (passkeys, open buckets, recovery key), **Settings**
(Setup, upgrades, policies) and **Help** for enrollment and command examples using the running
server’s URL and CA pin. The review behind this layout is [docs/UI-REVIEW.md](docs/UI-REVIEW.md).

## Install the CLI on a machine

Open **Help** on your broker's approval page. "Install the aqmas CLI" has one copy-paste block
each for Linux arm64, Linux x86-64 and macOS on Apple Silicon (`uname -sm` on the machine tells
you which). A block downloads the CLI of the release the broker runs from this repository's
GitHub release, checks it against the SHA-256 the broker itself verified for that release
(the hash is in the command, so it does not come from the download's origin), stops on a
mismatch, installs `~/.local/bin/aqmas` and prints its version. It works in bash and zsh and
needs no configuration on the broker. A broker without a verified record of its release yet
(before self-update is set up) shows the same blocks checking against GitHub's published
`SHA256SUMS`, and says that this is a check against GitHub only.

"Enroll a machine" on the same page then gives the `aqmas enroll` command with the agent API
address and CA pin. Later, `aqmas upgrade` upgrades the CLI from the broker
([docs/UPDATES.md](docs/UPDATES.md)); installed in `~/.local/bin` it needs no sudo.

- Design and milestone 1 scope: [docs/DESIGN.md](docs/DESIGN.md)
- API contract: [docs/API.md](docs/API.md), shared types in `internal/api`
- Credential sets from the Vault tab (write-only form, reveal) and signing inside aqmas:
  [docs/SIGNING.md](docs/SIGNING.md). Signing keys should not leave aqmas where a signer
  scheme exists: agents call `aqmas sign ORG/SERVICE/KEY --why "..." FILE`; `aqmas run`
  remains for the cases where that is not possible.
- Host and Forgejo trust: [docs/HOSTS.md](docs/HOSTS.md)
- Cloudflare (milestone 2): [docs/CLOUDFLARE.md](docs/CLOUDFLARE.md)
- Setup from the approval page (organisations cutover, sealing, self-update, upgrades) and the root maintenance runner: [docs/SETUP.md](docs/SETUP.md)
- Reproducible releases, `aqmas upgrade` and passkey-approved bastion updates: [docs/UPDATES.md](docs/UPDATES.md)
  Releases come from this GitHub repository alone by default (one published source, plus the
  bastion's own rebuild from source); a second, independent release source is optional and is
  named only in the bastion's configuration.

Toolchain: Go 1.27, Bun 1.4.4 for `web/`. `make vet test build`, `cd web && bun test`,
`make interop`, `make interop-cf`.

## Example deployment

Every site-specific value lives in configuration, never in the code:

- the bastion's `/etc/aqmas/config.toml` (`deploy/bastion/config.example.toml`): public URL
  (e.g. `https://approvals.example.com`), TLS SANs, targets with pinned host keys, ntfy topic,
  Cloudflare Access and Cloudflare account settings, and where releases come from (`[updates]`:
  GitHub by default, an optional second source);
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
