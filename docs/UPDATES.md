# Releases and self-update

A release PR changes the single line in `VERSION` to a higher stable `MAJOR.MINOR.PATCH` (first release: `0.1.0`). Review the **source**, including CI, dependency locks, migrations and build scripts. Publishing a release does not install it. The release authorities are the Forgejo release and an independent GitHub build of the mirrored tag. Every supported binary must have the same SHA-256 in both manifests.

## Rebuild a release

Use a clean checkout of the exact tag, a clean environment, Go 1.27.4 and Bun 1.4.4. `bash ci/toolchains.sh /path/to/new-directory` installs the pinned Linux distributions after checking their archive SHA-256. Add its `go/bin` and `bin` to `PATH`. The version comes from `VERSION`; the separate commit stamp identifies the source for diffs. Go targets are explicit (`CGO_ENABLED=0`, baseline ISA, `-trimpath -buildvcs=false`, stripped symbols). The release web build has no runtime npm dependencies and uses the frozen lockfile in production/offline mode. Development/web tests need `cd web && bun install --frozen-lockfile`.

```sh
make release
make verify-release VERSION=0.1.0 SUMS=/path/to/downloaded/SHA256SUMS
```

`dist/` contains `aqmasd-linux-arm64`, `aqmas-linux-{amd64,arm64}`, `aqmas-darwin-arm64` and the sorted `SHA256SUMS`. To check reproducibility, build two fresh checkouts in different directories; compare `web/dist` recursively and compare the manifests. Forgejo builds natively on ARM64; GitHub builds on AMD64. A mismatch, including web bundler or toolchain drift, makes the release unusable. Do not repair a mismatch by copying the good manifest to the other host.

## CI and mirror setup

Enable Actions on both repositories. Protect `main`, restrict who can push release tags and require review of workflow changes. Forgejo's `linux-arm64` Docker job runs tests on a `VERSION` change on main, skips an existing tag, then creates the tag/release for the event commit and uploads the assets. Use the repository job token with `contents: write`. If release creation is denied, use the `RELEASE_TOKEN` Actions secret restricted to **this repository** with `write:repository`, and expire/rotate it. A failed upload leaves a draft; inspect it, verify the tag and assets, then complete it manually. Do not move a published tag.

Configure a Forgejo SSH **push** mirror to `ssh://git@github.com/aquarat/agent-quartermaster.git`, branch filter `main` (Forgejo also mirrors tags), sync-on-commit plus an interval for catch-up. Select *use SSH* so Forgejo generates and retains the private key. Add **only the generated public key** on GitHub:

```sh
gh repo deploy-key add mirror.pub -R aquarat/agent-quartermaster --allow-write --title aqmas-forgejo-push-mirror
```

Verify GitHub's SSH host key at the forge. Check mirror status after syncing. This key can write code and tags in one repository. It is not a cross-account PAT and must never enter a job, the broker, or the bastion. On tag push, GitHub independently builds and publishes all five files. Its comparison job may not reach the first forge through Access/private-repo authentication. The actual install checks still apply.

## Bastion: one-time setup by the owner

Start on a known-good bastion with an enrolled owner passkey, a merged-`/usr` Linux/arm64
host and the maintenance runner installed (`sudo aqmasd maint-init`, [SETUP.md](SETUP.md)).
`maint-init --repo … --forgejo-api … --github-api …` pins the release sources at the machine;
requests from the page can then never choose or change them.
Then use **Admin → Setup → Enable self-update**. One approval does all of this as root, with
nothing taken from the request but the typed values you see and sign:

1. Installs the build tools (bubblewrap, git, jq, make, a C compiler for the Go tests, unzip,
   curl, OpenSSH client; `dnf` on Fedora) and the pinned toolchains under `/opt/aqmas-tools`
   with the digest-checking `ci/toolchains.sh` that ships inside the release. Creates the
   locked `aqmas-build` account. Allow several GiB of temporary space for a rebuild.
2. Creates the dedicated SSH key `/etc/aqmas/repo-key` (root:aqmas 0440) if `maint-init` has
   not already. Its public half is shown on the page: register it as a **read-only** deploy
   key of the repository on the forge. Appends the forge host key lines you signed to
   `/etc/aqmas/known_hosts` (consulted only by the broker's and the builder's `git fetch`);
   the page can fetch them and shows fingerprints it computed itself for you to compare.
3. Stores the release-reading tokens you pasted as `/etc/aqmas/forgejo-read-token` and
   `/etc/aqmas/github-read-token` (root:aqmas 0440: the broker reads them to discover
   releases). They travel sealed to the runner. While GitHub is private use a fine-grained
   token with **Contents: read** for this repository only; remove it once public. The bastion
   needs an HTTPS route to the forge API that satisfies any Access policy in front of it.
4. **Seeds the installed identity.** Downloads both `SHA256SUMS` of the running version,
   requires them to agree and to match the SHA-256 of the installed `/usr/local/bin/aqmasd`,
   downloads the three CLI binaries, checks each against both manifests, and fills
   `/var/lib/aqmas-releases/VERSION/` and `latest.json`. A broker that is not the published
   binary is refused: self-update never starts from a PR build or a single source.
5. Writes `[updates]` into `/etc/aqmas/config.toml` and restarts the broker (a sealed broker
   comes back locked). If the broker does not come back, the previous configuration is
   restored.

   ```toml
   [updates]
   repo = "ssh://git@forge.example.com/example/agent-quartermaster.git"
   deploy_key = "/etc/aqmas/repo-key"
   [updates.forgejo]
   api = "https://forge.example.com/api/v1/repos/example/agent-quartermaster"
   token_file = "/etc/aqmas/forgejo-read-token"
   [updates.github]
   api = "https://api.github.com/repos/aquarat/agent-quartermaster"
   token_file = "/etc/aqmas/github-read-token" # omit for public releases
   ```

The passkeys that may approve updates are the maintenance pins
(`/etc/aqmas/update-passkeys.json`, root 0600). `maint-init` takes the first set from the
passkeys registered at that moment; afterwards they change only by the signed **Sync
maintenance passkeys** task or `maint-init --repin` on the machine. **Rotation/removal is
two operations:** update the broker's passkeys, then sync the pins.
On a store sealed in per-credential buckets (format 2) there is no lock: a pinned passkey
that is approve-only (no PRF wraps) can approve an update whenever it is signed in, where
format 1 refused update approval until an unlock ([BUCKETS.md](BUCKETS.md) §4.4). A compromised broker
can ignore its own credential revocation; it cannot change the pins.

Only root may modify `/usr/local/bin/aqmasd`, `/usr/local/bin/aqmasd.prev`, the release
cache or the pins. Give `/var/lib/aqmas/update.git` its own size-limited filesystem or
project quota so remote git objects cannot fill the credential database volume. Rehearse an
update and rollback on a disposable bastion before relying on it. A failed build or check
needs a fresh approval; `journalctl -u aqmas-maint.service` has the detail. A pinned
toolchain bump or a changed unit file is still a manual change on the machine.

## Approval, install and recovery

Every 15 minutes the daemon fetches main and tag refs using strict SSH host checking, verifies fetched object integrity, resolves the latest version tag to a full commit, checks `VERSION` at both refs, and checks ancestry from the running commit through the tag to main. These are **content/ancestry checks, not a maintainer signature**. It computes stat and patch from local objects; binary files are listed, not inlined; a text patch over 4 MiB blocks approval. The signed `update` binds both versions, both commits and four digests ([API.md](API.md)). Only a matching verified release is offered. The audit records the signed description; the spool carries that description and the original assertion.

The maintenance runner (`aqmasd maint-run` as root, [SETUP.md](SETUP.md)) independently verifies the WebAuthn signature against its pins, UV, RP/origin, signed issuance time, replay record and installed identity, then re-fetches **both** manifests and hands them to the installer embedded in the release. The installer checks the running binary against the root-owned installed record. Git fetch is sandboxed with only the read-only deploy key; it independently checks the latest stable tag, main VERSION, both ancestry relationships and exact target commit. Module fetch uses the Go proxy/checksum database, `-mod=readonly`, no `GONOSUMDB`, and checks that dependency files did not change. Build and tests have **no external network**, broker sockets, keys or writable host paths beyond their private workspace. Only bounded copies of four fixed outputs are extracted, unprivileged, for hashing in root-owned staging.

Verified executables install by rename, preserving the old inode. A synced root-owned rollback journal precedes activation. An unhealthy restart restores `aqmasd.prev`; the path unit also recovers an interrupted activation after boot. Cache publication follows process-identity and database health checks. Binary rollback does not reverse database migrations: require backwards-compatible migrations for self-update. For a breaking migration, take a consistent SQLite backup and perform a supervised manual upgrade. If recovery fails, stop the path unit, inspect the journal and hashes, and restore the compatible database backup if necessary before re-enabling.

### Trust limits

**Organisation inventory and rollback:** The read-only `organisations-plan` preview
([procedure](ORGANISATIONS.md#inventory-preview-in-this-branch)) leaves the live `user_version`
at 5. v0.1.1 rejects versions above 5, so do not install catalogue DDL on binary startup,
lower `user_version` by hand, or treat installing `.prev` as undoing a signed cutover. After
a future activation, fix forward unless the matching pre-activation recovery point can be
restored without losing an intervening revocation, enrollment, passkey or grant change.

Opening an already activated (schema 6) store stages an additive, empty relaxation table.
The first signed catalogue change sets `user_version=7` in the same transaction: an
older daemon that does not enforce signed duration policies must refuse to serve that DB.
Ordinary installation/restart alone does not advance the version.

* The runner and its installer are part of `aqmasd`: an approved release replaces the code that will verify later approvals (before v0.3.0 the verifier was installed once and never updated). The pins, units and toolchains are not touched by an update.
* A compromised **aqmasd** controls its DB/audit, spool, discovery and what its web UI displays. It can cause denial of service or deceive an owner into signing a real update. It cannot synthesize a valid assertion for a root-pinned key or choose unverified installer bytes. A passkey is not a trusted display. For high-risk changes, independently inspect the source and compare hashes outside the UI.
* A compromised **Forgejo** can publish and mirror malicious **source/workflows**; GitHub can honestly rebuild it, so agreement is not an independent source review. Likewise, compromise of a runner with repository-write permission may extend from one forged artifact to changing future source releases. Restrict/protect main, tags, workflow edits and job tokens. The bastion rebuild plus exact owner approval protect against substitution by a single artifact producer.
* A compromised **GitHub** alone, or a build-only runner alone, can withhold releases or supply mismatched bytes and block installation. Neither supplies the root WebAuthn key. Common compromised dependencies, a compromised toolchain or kernel, collusion, and the owner's approval of malicious source are outside this guarantee. Isolate the mirror key; it permits repository writes even though it cannot operate on other repositories.

## Upgrade a fleet CLI

Install `aqmas` at `~/.local/bin/aqmas` on Apple Silicon or `/usr/local/bin/aqmas` on Linux. Use `aqmas upgrade --check`; `aqmas upgrade` (alias `update`) displays the version and digest, downloads and verifies the executable over mTLS, then prompts. For a deliberate non-interactive install supply **both** `--yes` and `--expect-sha256 HEX`. For root-owned installs use `sudo aqmas upgrade` with root's own enrolled, protected CLI configuration. Do not point a privileged installer at an agent-writable config, token, executable directory or trust store. GitHub uses a separate system-CA HTTPS client, never the mTLS client identity. The CLI's `[github]` table accepts the same `api` and optional `token_file` settings as above. No Forgejo credential goes on fleet hosts.

The only degraded mode is an explicit `--allow-single-source` when GitHub is unreachable; it warns loudly and trusts the previously verified cache on the broker. It never overrides a malformed manifest or a mismatch. Without that exception, failure to verify is fatal. Interactive runs check the enrolled API for a one-line notice at most daily; no implicit install or prompt. Roll back with a rename of `aqmas.prev` over `aqmas` in the install directory. On macOS Go's arm64 linker already ad-hoc signs release binaries. The installer clears quarantine on its staged file if present and checks the signature. Invalid signatures require a corrected release; re-signing bytes locally after verification would invalidate the approved digest.
**Vault tables (web form, reveal policy, signers):** additive tables and triggers created on a
sealed start (`signer_keys`, `org_vault`, `sign_requests`), with no schema-version change. A
previous binary ignores them. A signer set is stored as an application set at revision 0 with no
env revision, so a previous binary sees an empty env set: nothing to request, deliver or check
in its recovery inventory. Its key record uses a seal role the previous binary does not open. Reveal-policy rows and
signing grants are simply not consulted by a previous binary, which has no reveal or signing
route.

**Sealed format:** activating schema 8 is a supervised import, never an
on-start migration. The root seal-required config and active manifest must
agree; pre-seal binaries are not valid rollback candidates. A compatible
update or rollback starts locked. Health is process/database readiness, not
permission to issue. Use a distinct owner unlock after reconnecting. See
[the operator procedure](SEAL-OPERATIONS.md).
