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

Start on a known-good bastion with an enrolled owner passkey. Keep a tested database backup (SQLite online backup) and a manual recovery path. The first release-enabled daemon is installed manually. Do not run the candidate Makefile, tests, Bun or git checkout as root.

1. Install systemd, bubblewrap (unprivileged user namespaces), util-linux, coreutils, git, OpenSSH, curl, unzip, make, jq, SQLite, a C compiler for Go tests, and distro CA roots. Use a merged-`/usr` Linux/arm64 host. Install the pinned toolchains under `/opt/aqmas-tools` using the verified bootstrap script above. Toolchains, installer, units and all their parent directories must be root-owned and not writable by `aqmas` or the builder. Create the dedicated locked `aqmas-build` account (no login, no other services). The scratch tree and module cache are fresh for every update; allow several GiB of temporary space, preferably with a filesystem quota.

2. Generate a dedicated SSH key and register its public half as a **read-only** Forgejo deploy key for this repository. Install its private half as `/etc/aqmas/repo-key`, readable by `aqmas`, not writable by it (root:aqmas 0440). Pin the independently verified host key in `/etc/ssh/ssh_known_hosts` (use `[host]:port` for nonstandard ports). For a private release API install repository-read-only tokens in files as root:aqmas 0440; the SSH key cannot read HTTP release attachments. Arrange an HTTPS route from the bastion to Forgejo that satisfies Access (e.g. trusted private routing with normal TLS hostname verification). While GitHub is private, use a fine-grained token with **Contents: read** for this repository only; remove it once public.

   Add to `/etc/aqmas/config.toml` (root-owned, parent not service-writable):

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

3. Install the root verifier built **from the trusted setup revision** (`go build -trimpath -o aqmas-update-verify ./cmd/aqmas-update-verify`) and `deploy/bastion/aqmas-updater.sh` in `/usr/local/libexec/` as root:root 0755. Install the `.service` and `.path` therefrom in `/etc/systemd/system/` as root:root 0644. Set `/etc/aqmas/updater.env` (root:root 0600) with `REPO=...` and `DEPLOY_KEY=/etc/aqmas/repo-key` as above; optional `HEALTH_URL=http://127.0.0.1:8080/healthz`. These helpers and pins are **never self-updated**. Apply reviewed changes to them manually.

   Pin only owner credentials explicitly trusted for **bastion updates**. On a known-good initial enrollment, export the public credential records, selecting the intended row(s); compare the credential IDs with your trusted enrollment records. Never refresh pins automatically from the running broker. As root, for example:

   ```sh
   umask 077
   sudo -u aqmas sqlite3 -readonly /var/lib/aqmas/aqmas.db \
     'SELECT credential_json FROM passkeys ORDER BY id' | jq -s 'map({id,publicKey})' > /etc/aqmas/update-passkeys.json
   ```

   Inspect and remove unwanted entries before enabling the unit. Keep this file root-owned 0600. **Rotation/removal is two operations:** update the broker's passkeys and remove/add the root pins out of band. A compromised broker can ignore its own credential revocation.

4. Prepare separate writable domains (do not put the cache, pins or helpers under the broker's state directory):

   ```sh
   install -d -o root -g root -m 0755 /var/lib/aqmas-releases
   install -d -o root -g aqmas -m 0730 /var/spool/aqmas-update
   ```

   Alternatively install `aqmas-update.tmpfiles.conf` in `/etc/tmpfiles.d/` and use `systemd-tmpfiles --create`. Install the updated `aqmasd.service`, which grants the narrow spool write exception. Leave the existing broker hardening, database and CA permissions in place. Only root may modify `/usr/local/bin/aqmasd`, `/usr/local/bin/aqmasd.prev` or the release cache. Use the shipped fixed spool/cache paths with the root units (alternate paths are for test servers). Give `/var/lib/aqmas/update.git` its own size-limited filesystem or project quota so remote git objects cannot fill the credential database volume.

5. **Seed the installed identity and cache.** In a reviewed clean checkout on the bastion, resolve `refs/tags/v$version^{commit}`, confirm its `VERSION` and expected history, build all four binaries as an ordinary owner user. Run the trusted helper `aqmas-update-verify bootstrap VERSION COMMIT` (root, absolute helper path) to a private temporary JSON file. It independently downloads both manifests but does **not** approve/install anything. Compare its complete digest map to the local build, e.g. `jq -r '.forgejo|to_entries[]|"\(.value)  \(.key)"' /path/to/verified.json | sort -k2 | cmp - dist/SHA256SUMS`. Only after a match, install the verified server and copy the three verified CLI binaries + `SHA256SUMS` into `/var/lib/aqmas-releases/VERSION/`. Install the verified JSON as `/var/lib/aqmas-releases/latest.json`. Use trusted owner staging, root ownership, 0755 directories, 0644 cache files. Confirm `aqmasd version`, restart and check `/healthz`. Do not bootstrap from a PR binary, from aqmasd's writable git cache or from a single release.

6. `systemctl daemon-reload && systemctl restart aqmasd && systemctl enable --now aqmas-updater.path`. Check **Admin → Updates** and `journalctl -u aqmas-updater.service`. A failed build/check needs fresh approval. For repeated invalid requests systemd rate-limits the trigger: investigate the spool and reset the failed unit before re-enabling the path. Rehearse an update and rollback on a disposable bastion before enabling unattended triggering on the production machine.

## Approval, install and recovery

Every 15 minutes the daemon fetches main and tag refs using strict SSH host checking, verifies fetched object integrity, resolves the latest version tag to a full commit, checks `VERSION` at both refs, and checks ancestry from the running commit through the tag to main. These are **content/ancestry checks, not a maintainer signature**. It computes stat and patch from local objects; a patch too large to show completely blocks approval. The signed `update` binds both versions, both commits and four digests ([API.md](API.md)). Only a matching verified release is offered. The audit records the signed description; the spool carries that description and the original assertion.

The root helper independently verifies the WebAuthn signature against its pins, UV, RP/origin, signed issuance time, replay record and installed identity, then re-fetches **both** manifests. The installer checks the running binary against the root-owned installed record. Git fetch is sandboxed with only the read-only deploy key; it independently checks the latest stable tag, main VERSION, both ancestry relationships and exact target commit. Module fetch uses the Go proxy/checksum database, `-mod=readonly`, no `GONOSUMDB`, and checks that dependency files did not change. Build and tests have **no external network**, broker sockets, keys or writable host paths beyond their private workspace. Only bounded copies of four fixed outputs are extracted, unprivileged, for hashing in root-owned staging.

Verified executables install by rename, preserving the old inode. A synced root-owned rollback journal precedes activation. An unhealthy restart restores `aqmasd.prev`; the path unit also recovers an interrupted activation after boot. Cache publication follows process-identity and database health checks. Binary rollback does not reverse database migrations: require backwards-compatible migrations for self-update. For a breaking migration, take a consistent SQLite backup and perform a supervised manual upgrade. If recovery fails, stop the path unit, inspect the journal and hashes, and restore the compatible database backup if necessary before re-enabling.

### Trust limits

**Organisation inventory and rollback:** The read-only `organisations-plan` preview
([procedure](ORGANISATIONS.md#inventory-preview-in-this-branch)) leaves the live `user_version`
at 5. v0.1.1 rejects versions above 5, so do not install catalogue DDL on binary startup,
lower `user_version` by hand, or treat installing `.prev` as undoing a signed cutover. After
a future activation, fix forward unless the matching pre-activation recovery point can be
restored without losing an intervening revocation, enrollment, passkey or grant change.

* A compromised **aqmasd** controls its DB/audit, spool, discovery and what its web UI displays. It can cause denial of service or deceive an owner into signing a real update. It cannot synthesize a valid assertion for a root-pinned key or choose unverified installer bytes. A passkey is not a trusted display. For high-risk changes, independently inspect the source and compare hashes outside the UI.
* A compromised **Forgejo** can publish and mirror malicious **source/workflows**; GitHub can honestly rebuild it, so agreement is not an independent source review. Likewise, compromise of a runner with repository-write permission may extend from one forged artifact to changing future source releases. Restrict/protect main, tags, workflow edits and job tokens. The bastion rebuild plus exact owner approval protect against substitution by a single artifact producer.
* A compromised **GitHub** alone, or a build-only runner alone, can withhold releases or supply mismatched bytes and block installation. Neither supplies the root WebAuthn key. Common compromised dependencies, a compromised toolchain or kernel, collusion, and the owner's approval of malicious source are outside this guarantee. Isolate the mirror key; it permits repository writes even though it cannot operate on other repositories.

## Upgrade a fleet CLI

Install `aqmas` at `~/.local/bin/aqmas` on Apple Silicon or `/usr/local/bin/aqmas` on Linux. Use `aqmas upgrade --check`; `aqmas upgrade` (alias `update`) displays the version and digest, downloads and verifies the executable over mTLS, then prompts. For a deliberate non-interactive install supply **both** `--yes` and `--expect-sha256 HEX`. For root-owned installs use `sudo aqmas upgrade` with root's own enrolled, protected CLI configuration. Do not point a privileged installer at an agent-writable config, token, executable directory or trust store. GitHub uses a separate system-CA HTTPS client, never the mTLS client identity. The CLI's `[github]` table accepts the same `api` and optional `token_file` settings as above. No Forgejo credential goes on fleet hosts.

The only degraded mode is an explicit `--allow-single-source` when GitHub is unreachable; it warns loudly and trusts the previously verified cache on the broker. It never overrides a malformed manifest or a mismatch. Without that exception, failure to verify is fatal. Interactive runs check the enrolled API for a one-line notice at most daily; no implicit install or prompt. Roll back with a rename of `aqmas.prev` over `aqmas` in the install directory. On macOS Go's arm64 linker already ad-hoc signs release binaries. The installer clears quarantine on its staged file if present and checks the signature. Invalid signatures require a corrected release; re-signing bytes locally after verification would invalidate the approved digest.
