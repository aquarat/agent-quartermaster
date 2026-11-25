# agent-quartermaster (`aqmas`)

Credential broker for a single owner's fleet: AI agents and the owner request short-lived,
passkey-approved access (SSH certificates, Cloudflare API grants, env credential sets and
single-value secrets, signatures from keys that never leave the broker; GitHub, Forgejo and
HTTP APIs later) instead of holding long-lived keys. The server (`aqmasd`) runs on a dedicated
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
(a searchable list of secrets, env sets, signing keys and what the broker holds; Add item;
Reveal after a tap), **Hosts**, **Activity**, **Security** (passkeys, open buckets, recovery key), **Settings**
(Setup, upgrades, policies) and **Help** for enrollment and command examples using the running
server’s URL and CA pin. The review behind this layout is [docs/UI-REVIEW.md](docs/UI-REVIEW.md).

## Install the CLI on a machine

Open **Help** on your broker's approval page. "Install aqmas and enroll a machine" has one
copy-paste command for every supported machine: Linux arm64 and x86-64, macOS on Apple Silicon
and on Intel, in bash or zsh. It picks the build from `uname -sm` (an Apple Silicon Mac whose
shell runs under Rosetta still gets the arm64 build), says what it is about to do, downloads the
CLI of the release the broker runs from this repository's GitHub release, checks it against the
SHA-256 the broker recorded when it verified that release (the hashes are in the command; on a
broker that compares GitHub alone they are GitHub's published hashes as they stood then, with a
second source they are what both agreed on), stops on a mismatch, installs `~/.local/bin/aqmas`
and prints its version. It then asks on the terminal whether to enroll the machine and under
which name (the hostname, up to the first dot and lowercased, unless you type another) and runs
`aqmas enroll` with the broker's agent API address and CA pin. It needs no configuration on the
broker; without `agent_api_url` it installs only and says so. A broker without a verified record
of its release yet (before self-update is set up) checks against GitHub's published `SHA256SUMS`
instead, and says that this is a check against GitHub only. The macOS Intel build
(`aqmas-darwin-amd64`) is listed in its own `SHA256SUMS.extra`; a broker whose record predates
it checks that one build against the published file and says so. Per-platform install blocks
and the enroll-only command are on the same card for doing it by hand.

Later, `aqmas upgrade` upgrades the CLI from the broker
([docs/UPDATES.md](docs/UPDATES.md)); installed in `~/.local/bin` it needs no sudo.

## For agents

An agent on an enrolled machine learns aqmas from aqmas: `aqmas guide` prints the agent guide
of the installed version ([docs/AGENTS.md](docs/AGENTS.md): how approvals work, every command
with examples, what to do on each error), and `aqmas guide --json` is a command summary for
programs. Point an agent's notes or knowledge base at that command instead of copying it.

- **Discovery.** `aqmas ls` and `aqmas targets` list what the machine may ask for (paths,
  kinds, key names, SSH targets; never values). It is an owner switch per organisation,
  "Hosts may list what they can ask for" under Settings, off by default; while it is off a
  host has to be told each path.
- **MCP.** `aqmas mcp` is an MCP server on stdin/stdout with the same abilities as tools
  (guide, status, the two lists, run a command with a secret, sign, run a command over SSH).
  Register it with `claude mcp add aqmas -- aqmas mcp`, or
  `{"mcpServers": {"aqmas": {"command": "aqmas", "args": ["mcp"]}}}`. Tools that need the
  owner block until the owner decides; no tool returns a secret's value.
- **Secrets.** Vault → Add item → Secret holds one value (an API key, say) with the
  environment variable it is delivered as: `aqmas run ORG/SERVICE/SECRET --why "..." --
  COMMAND`, or `aqmas get` for the value itself.
- **Don't ask again.** When approving an env set or secret release the owner may choose
  "don't ask again" for 1, 6 or 24 hours, up to a limit set per item (one hour by default):
  the same machine then gets the same value again without another tap. Every delivery is
  still logged, and the rule ends when the value, the policy or the admission changes, or
  when the owner revokes it.

## Documentation

- Design and milestone 1 scope: [docs/DESIGN.md](docs/DESIGN.md)
- The guide for agents (`aqmas guide`): [docs/AGENTS.md](docs/AGENTS.md)
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
  `aqmas enroll --server https://192.0.2.10:8443 --ca-pin sha256:...` (the host name defaults
  to the machine's hostname; `--name web-1` sets another);
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
