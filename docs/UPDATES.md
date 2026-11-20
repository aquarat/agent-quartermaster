# Releases and self-update (planned)

Not built yet. Scheduled after milestone 2 (Cloudflare) and the UI round have landed.

## Requirements

1. **aqmasd** (bastion) updates arrive as **pull requests** that bump a version in the
   repository. aqmasd notices the new version, and **self-updates only after the owner agrees**
   (passkey-signed approval).
2. **The `aqmas` CLI self-upgrades** too: it checks for updates occasionally, offers to update,
   and **shows the SHA-256 of the new binary** as part of the process.
3. **Releases in the repository carry those hashes** (`SHA256SUMS` per release), so the trust
   sits with the repository host (Forgejo).
4. **CI mirrors the repository to GitHub** as part of the release flow.
5. Install location: `~/.local/bin/aqmas` on a workstation, `/usr/local/bin/aqmas` on Linux hosts.

## Decisions

- **Second hash source: GitHub.** The CLI (and aqmasd's updater) accept a release only if the
  `SHA256SUMS` from the Forgejo release and from the GitHub mirror's release agree. GitHub also
  makes the code history independently visible.
- **Distribution:** aqmasd serves CLI releases (binaries + `SHA256SUMS`) over the mTLS agent API;
  a **public GitHub repository** may also be used as a download/verification source.
- Consequence of a public mirror: the repository must not contain site-specific details (LAN
  addresses, tunnel/Access IDs, host keys, deploy progress notes). Those live in the
  operator's private ops documentation; the repository keeps generic examples with
  placeholders (RFC 5737 addresses, `example.com`).

## Proposed design (decisions above take precedence)

### Versioning and releases
- `VERSION` file (semver). A PR that changes it is a release PR; after merge, a Forgejo Actions
  workflow tags `vX.Y.Z`, builds `aqmasd` linux/arm64 and `aqmas` linux/arm64, linux/amd64,
  darwin/arm64 with `-trimpath` and stamped versions (reproducible: same commit -> same bytes),
  and creates a Forgejo release with the binaries and `SHA256SUMS`.
- The same workflow pushes `main` and tags to the GitHub mirror (Forgejo push mirror or a
  deploy-key push), and attaches the same `SHA256SUMS` to a GitHub release if wanted.

### CLI self-update (`aqmas update`, plus an occasional background check)
- At most once a day, when run interactively, the CLI checks the latest release; if newer it
  prints a one-line notice (never auto-installs, never prompts in non-TTY/agent use).
- `aqmas update` downloads the binary for its OS/arch, verifies it against the release's
  `SHA256SUMS`, **shows the hash and version and asks for confirmation**, then replaces itself
  atomically (keeping `aqmas.prev` for rollback). Root-owned installs (`/usr/local/bin`) need
  `sudo aqmas update`.
- **Cheap extra assurance (recommended):** also fetch `SHA256SUMS` from a second source and
  refuse on mismatch: the GitHub mirror's release, and/or aqmasd, which can build the same
  commit reproducibly on the bastion (see below) and publish its own hashes over the agent API.
  Two hosts agreeing is much stronger than one.
- Where the CLI fetches from: the private Forgejo repo needs credentials and Access off-LAN.
  Options: serve releases (binaries + `SHA256SUMS`) from aqmasd over the existing mTLS agent API
  (no new credential on hosts), or make the repository public.

### aqmasd self-update (bastion)
- aqmasd polls the repository (read-only deploy key) for a new `VERSION` on `main`.
- The UI shows "update available vX.Y.Z", the commit, and **the diff from the running commit,
  computed on the bastion from git objects it fetched and verified** (not the Forgejo web view,
  which a compromised Forgejo host could fake).
- The owner approves with a passkey; the canonical action commits to the exact commit hash and
  the expected binary hashes.
- A separate root-only `aqmas-update.service` (triggered by a path unit) builds that exact commit
  on the bastion (Go toolchain + vendored modules; the web bundle via Bun with no network installs),
  compares the hashes with the release's `SHA256SUMS`, runs the tests, installs with the previous
  binary kept, restarts aqmasd, health-checks, and rolls back automatically on failure. aqmasd
  itself never gets write access to its binary.
- The same build produces the CLI binaries that aqmasd can then serve and vouch for.
