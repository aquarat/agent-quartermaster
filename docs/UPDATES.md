# Releases and self-update

A release PR changes the single line in `VERSION` to a higher stable `MAJOR.MINOR.PATCH` (first release: `0.1.0`). Review the **source**, including CI, dependency locks, migrations and build scripts. Publishing a release does not install it.

## Release sources: GitHub, and optionally a second one

| | Published sources compared | What installs a release |
|---|---|---|
| **Default (nothing configured)** | **1**: the public GitHub repository's release (`SHA256SUMS`) | The bastion rebuilds the tag from source in a sandbox; all four binaries must have exactly the published hashes. |
| **With a second source configured** | **2**: GitHub and a second, independent builder (a Forgejo/Gitea-compatible forge) | Both manifests must be identical, and the bastion's own rebuild must match them. |

GitHub is the only source every installation has, and it needs no token, deploy key or host key while the repository is public: discovery is an anonymous `git fetch` over HTTPS, the diff on the approval card comes from those fetched objects, and the hashes come from the GitHub release API. One published source plus the local rebuild is the minimum, never less.

A second source is optional and exists **only in configuration**: no host name of one is in the code, the tests, the examples or the workflows. Once it is configured it is part of every check for good. If it disagrees, or cannot be reached, updates and "Enable self-update" stop with an error naming it. There is **no fallback to fewer sources**: otherwise whoever can make the second source unreachable could downgrade the check. To stop using it, remove it from the configuration.

The approval card and the Setup page say how many published sources were compared and name them: `GitHub`, and `second source (HOST)` with the host taken from the configuration.

### Configuration (`/etc/aqmas/config.toml`, root-owned)

```toml
[updates]
# The git remote releases are fetched and rebuilt from. Setting it turns discovery on;
# "Enable self-update" writes it. https:// is anonymous (a public repository). An ssh://
# remote needs deploy_key and the forge's host keys in /etc/aqmas/known_hosts.
repo = "https://github.com/aquarat/agent-quartermaster.git"
# deploy_key = "/etc/aqmas/repo-key"      # only for an ssh:// repo
# check_minutes = 5                        # 1–1440

[updates.github]
# Compiled default: https://api.github.com/repos/aquarat/agent-quartermaster. Override both
# this and repo for a fork.
api = "https://api.github.com/repos/aquarat/agent-quartermaster"
# token_file = "/etc/aqmas/github-read-token"   # only while the repository is private

# Optional second source. Leave the whole table out for GitHub only.
[updates.second]
api = "https://forge.example.com/api/v1/repos/example/agent-quartermaster"
# token_file = "/etc/aqmas/second-read-token"   # only if that repository is private
```

| Key | Meaning |
|---|---|
| `updates.repo` | Git remote: `https://HOST/OWNER/NAME.git` or `ssh://git@HOST[:PORT]/OWNER/NAME.git`. No password in the URL; plain `http` is refused. With a second source this may be that forge's SSH remote (as up to 0.8.1) or stay GitHub's. |
| `updates.deploy_key` | Read-only SSH key, required for an `ssh://` remote only. |
| `updates.github.api` | GitHub release API of the repository. Optional; the compiled default is `github.com/aquarat/agent-quartermaster`. |
| `updates.github.token_file` | Optional read token, needed only while the GitHub repository is private. |
| `updates.second.api` | Release API base of the second source, repository path included: `https://HOST/api/v1/repos/OWNER/NAME`. Setting it is what configures a second source. |
| `updates.second.token_file` | Optional read token for the second source. |

Addresses must be `https`, without credentials, query or fragment, at most 512 characters; the broker refuses to start otherwise. `[updates.forgejo]` is accepted as the old name of `[updates.second]` (see [Upgrading from 0.8.1](#upgrading-from-081)). A token file under `[updates.second]` (or `[updates.forgejo]`) without `api` is refused at start, with the two lines to add in the error: it looks like a second source and would configure none. Plain `http` is refused everywhere, loopback included; only test builds accept it.

### A second source cannot disappear by itself

Dropping a second source is a decision for the owner at the machine, never a side effect of an edit, a lost line or an upgrade:

- If the sources pinned at the machine (`maint-init`, `/etc/aqmas/maint-sources.json`) name a second source, the configuration must name exactly the same one. Otherwise the broker fetches and offers nothing, and the root runner refuses to install.
- If the installed release (`latest.json`) was verified against two sources and the configuration names one, the same applies ("no fewer sources than before"), and "Enable self-update" refuses too.
- The Setup page shows this as a blocking problem under "Enable self-update" and on "Upgrade aqmas", with the fix: add the two lines back (`[updates.second]` and its `api`), or decide at the machine to compare GitHub alone: `sudo aqmasd maint-init --repo URL --github-only`.
- `maint-init --repo URL` without `--second-api` is refused on a machine whose pin, configuration or installed release has a second source; `--github-only` says it is intended.

## Rebuild a release

Use a clean checkout of the exact tag, a clean environment, Go 1.27.4 and Bun 1.4.4. `bash ci/toolchains.sh /path/to/new-directory` installs the pinned Linux distributions after checking their archive SHA-256. Add its `go/bin` and `bin` to `PATH`. The version comes from `VERSION`; the separate commit stamp identifies the source for diffs. Go targets are explicit (`CGO_ENABLED=0`, baseline ISA, `-trimpath -buildvcs=false`, stripped symbols). The release web build has no runtime npm dependencies and uses the frozen lockfile in production/offline mode. Development/web tests need `cd web && bun install --frozen-lockfile`.

```sh
make release
make verify-release VERSION=0.1.0 SUMS=/path/to/downloaded/SHA256SUMS
```

`dist/` contains `aqmasd-linux-arm64`, `aqmas-linux-{amd64,arm64}`, `aqmas-darwin-arm64` and the sorted `SHA256SUMS`. To check reproducibility, build two fresh checkouts in different directories; compare `web/dist` recursively and compare the manifests. GitHub builds on AMD64; a second builder may build on another architecture (the Forgejo workflow builds natively on ARM64) and must produce the same bytes. A mismatch, including web bundler or toolchain drift, makes the release unusable. Do not repair a mismatch by copying the good manifest to the other host.

## CI

**GitHub** (`.github/workflows/release.yml`): on a `v*` tag it tests, builds and publishes the four binaries and `SHA256SUMS` as a GitHub release. Protect `main`, restrict who can push release tags and require review of workflow changes.

Its last job, `compare`, checks the published manifest against a second source **when one is configured for the repository**, and passes with a notice when none is:

| Actions secret | Value |
|---|---|
| `SECOND_SOURCE_RELEASES_URL` | The second source's release-download base, e.g. `https://forge.example.com/OWNER/NAME/releases/download`. The job fetches `<base>/<tag>/SHA256SUMS`, following the forge's redirect to the attachment (https only). |

It is read from a **secret only**: GitHub prints repository *variables* in the job log, which is public for a public repository, while secrets are masked. The job prints nothing but the final HTTP status. A second source the runner cannot reach (private network, an access policy) is a notice, not a failure: the checks at install time are what count. A manifest that was served and differs fails the job.

**A second builder** (`.forgejo/workflows/release.yml`, optional): the generic workflow for a Forgejo/Gitea instance that hosts a copy of the repository. It names no host (it uses the instance it runs on). Its `linux-arm64` Docker job runs tests on a `VERSION` change on main, skips an existing tag, then creates the tag/release for the event commit and uploads the assets. Use the repository job token with `contents: write`. If release creation is denied, use the `RELEASE_TOKEN` Actions secret restricted to **this repository** with `write:repository`, and expire/rotate it. A failed upload leaves a draft; inspect it, verify the tag and assets, then complete it manually. Do not move a published tag.

If that forge is where development happens, mirror it to GitHub with an SSH **push** mirror to `ssh://git@github.com/aquarat/agent-quartermaster.git`, branch filter `main` (tags are mirrored too), sync-on-commit plus an interval for catch-up. Select *use SSH* so the forge generates and retains the private key. Add **only the generated public key** on GitHub:

```sh
gh repo deploy-key add mirror.pub -R aquarat/agent-quartermaster --allow-write --title aqmas-push-mirror
```

Verify GitHub's SSH host key at the forge. Check mirror status after syncing. This key can write code and tags in one repository. It is not a cross-account PAT and must never enter a job, the broker, or the bastion. On tag push, GitHub independently builds and publishes all five files.

## Bastion: one-time setup by the owner

Start on a known-good bastion with an enrolled owner passkey, a merged-`/usr` Linux/arm64
host and the maintenance runner installed (`sudo aqmasd maint-init`, [SETUP.md](SETUP.md)).

**Where releases come from is decided at the machine, never by a request.** "Enable
self-update" signs and uses exactly one set of sources, in this order of precedence:

1. sources pinned from a terminal: `sudo aqmasd maint-init --repo URL [--github-api URL] [--second-api URL | --github-only]`
   (`/etc/aqmas/maint-sources.json`);
2. else the `[updates]` table of the root-owned configuration, as it stands;
3. else, with nothing configured, the public GitHub repository alone.

The page shows them and where they come from; it cannot choose, add or drop one.

Then use **Settings → Setup → Enable self-update**. One approval does all of this as root, with
nothing taken from the request but the values you see and sign:

1. Installs the build tools (bubblewrap, git, jq, make, a C compiler for the Go tests, unzip,
   curl, OpenSSH client; `dnf` on Fedora) and the pinned toolchains under `/opt/aqmas-tools`
   with the digest-checking `ci/toolchains.sh` that ships inside the release. Creates the
   locked `aqmas-build` account. Allow several GiB of temporary space for a rebuild.
2. **Only for an `ssh://` repository:** creates the dedicated SSH key `/etc/aqmas/repo-key`
   (root:aqmas 0440) if it does not exist. Its public half is shown on the page: register it
   as a **read-only** deploy key of the repository on the forge. Appends the forge host key
   lines you signed to `/etc/aqmas/known_hosts` (consulted only by the broker's and the
   builder's `git fetch`); the page can fetch them and shows fingerprints it computed itself
   for you to compare. With the default HTTPS repository there is no key and no host key:
   the system's certificate authorities apply.
3. Stores the release-reading tokens you pasted, if any, as `/etc/aqmas/github-read-token`
   and `/etc/aqmas/second-read-token` (root:aqmas 0440: the broker reads them to discover
   releases). They travel sealed to the runner. **No token is needed for public
   repositories.** While GitHub is private use a fine-grained token with **Contents: read**
   for this repository only, and an `ssh://` repo with a deploy key (an anonymous HTTPS
   fetch of a private repository fails); remove both once public.
4. **Seeds the installed identity.** Downloads `SHA256SUMS` of the running version from
   every configured source (GitHub; the second source too when there is one), requires
   them to agree and to match the SHA-256 of the installed `/usr/local/bin/aqmasd`,
   downloads the three CLI binaries, checks each against the manifest, and fills
   `/var/lib/aqmas-releases/VERSION/` and `latest.json`. A broker that is not the published
   binary is refused: self-update never starts from a PR build.
5. Writes `[updates]` into `/etc/aqmas/config.toml` (the tables above; `[updates.second]`
   only when a second source is configured) and restarts the broker (a sealed broker comes
   back locked). If the broker does not come back, the previous configuration is restored.

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

### Upgrading from 0.8.1

Up to 0.8.1 a second source was mandatory and its address had a compiled default. From
this version it is optional and comes only from configuration. What an existing
installation has on disk keeps its meaning:

| On the bastion | Written by 0.8.1 as | Read now as |
|---|---|---|
| `/etc/aqmas/config.toml` | `[updates.forgejo]` (`api`, `token_file`) | `[updates.second]` (old name still accepted) |
| `/etc/aqmas/maint-sources.json` | `"forgejo_api"` | `"second_api"` (old key still read) |
| `/etc/aqmas/forgejo-read-token` | second-source token | used as long as `token_file` points at it; the next "Enable self-update" stores `second-read-token` and removes it |
| `/var/lib/aqmas-releases/latest.json`, the rollback journal | `{"forgejo":…,"github":…}` | a record of two agreeing sources; the installer reads the digests from `"github"`, present in both forms |
| the spool, the updater's environment | no source address | unchanged |

Nothing on disk refers to the removed compiled address. Where the installed runner can
follow the published history to the new release, it installs the upgrade itself, with its
two-source check. An installation whose published history was rewritten in between cannot be
upgraded that way (the runner refuses a release its running commit is not an ancestor of):
it is reinstalled from a release as described in [SETUP.md](SETUP.md).

**Before upgrading, check `[updates.forgejo]` in `/etc/aqmas/config.toml`.** "Enable
self-update" of 0.8.1 wrote the second source's `api` line explicitly; then nothing needs to
change and both sources stay in use (renaming the table to `[updates.second]` is optional).

If the table has a `token_file` but **no `api` line** (0.8.1 then used its compiled address),
add the line first. 0.8.1 accepts it too, so this is safe to do before the upgrade
(placeholders: your forge's host, the repository's owner and name):

```toml
[updates.forgejo]            # or [updates.second] once the new version runs
api = "https://<FORGE_HOST>/api/v1/repos/<OWNER>/<NAME>"
token_file = "/etc/aqmas/forgejo-read-token"   # the existing line; omit if that repository is public
```

Without it the new broker **refuses to start** (its error names these lines) and the 0.8.1
installer restores 0.8.1. It does not start as a GitHub-only broker.

If there is **no second-source table at all** while `maint-sources.json` or `latest.json`
records a second source, the new broker starts and serves credentials, but updates are
blocked and the Setup page says why and shows the two lines to add
(see [A second source cannot disappear by itself](#a-second-source-cannot-disappear-by-itself)).

`[updates] repo`, `deploy_key` and `[updates.github]` stay as they are. Settings → Setup →
Enable self-update then shows "Two published sources are compared: GitHub and second source
(<FORGE_HOST>)".

To drop the second source instead: `sudo aqmasd maint-init --repo https://github.com/aquarat/agent-quartermaster.git --github-only`,
remove its table from the configuration, restart, and run "Enable self-update" again.

## Approval, install and recovery

Every 5 minutes (`[updates] check_minutes`, 1–1440) the daemon fetches main and tag refs (anonymous HTTPS with the system's certificate authorities, no redirects and no credential helper; or SSH with strict host checking and the read-only key), verifies fetched object integrity, resolves the latest version tag to a full commit, checks `VERSION` at both refs, and checks ancestry from the running commit through the tag to main. These are **content/ancestry checks, not a maintainer signature**. It computes stat and patch from local objects; binary files are listed, not inlined; a text patch over 4 MiB blocks approval. The signed `update` binds both versions, both commits and four digests ([API.md](API.md)). Only a release whose hashes every configured source publishes identically is offered; the card says how many sources were compared and names them. The audit records the signed description; the spool carries that description and the original assertion.

The maintenance runner (`aqmasd maint-run` as root, [SETUP.md](SETUP.md)) independently verifies the WebAuthn signature against its pins, UV, RP/origin, signed issuance time, replay record and installed identity, then re-fetches the manifest from **every configured source** (GitHub, and the second source when one is configured; an unreachable or disagreeing configured source refuses the install) and hands them to the installer embedded in the release. The installer checks the running binary against the root-owned installed record. Git fetch is sandboxed, with only the read-only deploy key for an SSH remote and nothing at all for an HTTPS one; it independently checks the latest stable tag, main VERSION, both ancestry relationships and exact target commit. Module fetch uses the Go proxy/checksum database, `-mod=readonly`, no `GONOSUMDB`, and checks that dependency files did not change. Build and tests have **no external network**, broker sockets, keys or writable host paths beyond their private workspace. Only bounded copies of four fixed outputs are extracted, unprivileged, for hashing in root-owned staging.

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
* **One published source or two:** with GitHub alone, the protection against a substituted artifact is the bastion's rebuild from the reviewed source plus your exact approval; a second source adds an independent builder that must have produced the same bytes. Neither is a source review.
* A compromised **forge where the source is written** (GitHub, or a second forge that mirrors to it) can publish malicious **source/workflows**; the other builder can honestly rebuild it, so agreement is not an independent source review. Likewise, compromise of a runner with repository-write permission may extend from one forged artifact to changing future source releases. Restrict/protect main, tags, workflow edits and job tokens. The bastion rebuild plus exact owner approval protect against substitution by a single artifact producer.
* A compromised release host alone (GitHub's, or the second source's), or a build-only runner alone, can withhold releases or supply mismatched bytes and block installation. Neither supplies the root WebAuthn key. Common compromised dependencies, a compromised toolchain or kernel, collusion, and the owner's approval of malicious source are outside this guarantee. Isolate the mirror key; it permits repository writes even though it cannot operate on other repositories.

## Upgrade a fleet CLI

Install `aqmas` at `~/.local/bin/aqmas` on Apple Silicon or `/usr/local/bin/aqmas` on Linux. Use `aqmas upgrade --check`; `aqmas upgrade` (alias `update`) displays the version and digest, downloads and verifies the executable over mTLS, then prompts. For a deliberate non-interactive install supply **both** `--yes` and `--expect-sha256 HEX`. For a system-wide install (the executable in a root-owned directory such as `/usr/local/bin`) run `sudo aqmas upgrade`: plain `aqmas upgrade` says so before it downloads anything. Under sudo the CLI takes the identity of the user who ran sudo (from `SUDO_UID`/`SUDO_GID`, with none of root's groups) for everything except the last step: it reads that user's enrolment in `~/.config/aqmas` with the usual ownership and permission checks, talks to the bastion and to GitHub, and reads a configured token file as that user. It takes root back only to replace the executable, which still requires the install directory and all its parents to be root-controlled: owned by root and writable by nobody else. A group-writable directory such as a `root:staff` mode-2775 `/usr/local/bin` is refused with that reason; install `aqmas` in `~/.local/bin` there and upgrade it without sudo. Root therefore never reads a file on the configuration's say-so, and never writes or re-owns anything in the user's directories. If the user's configuration lives elsewhere, name it: `sudo AQMAS_CONFIG_DIR=/path/to/aqmas aqmas upgrade` (sudo passes a variable given on its command line only where the sudoers rule allows it, `SETENV` or a full `ALL` rule; where it does not, keep the configuration in `~/.config/aqmas`). If that user has no enrolment at all, root's own enrolled configuration is used as before, found from root's account entry and not from `HOME` (which sudo may have kept); an enrolment directory owned by anyone other than the invoking user is refused. What this accepts: whoever may run sudo decides, through their own enrolment, what root installs, as they could with sudo anyway. Do not give a narrowly scoped sudo rule for `aqmas upgrade` to an account you would not give root. GitHub uses a separate system-CA HTTPS client, never the mTLS client identity. The CLI's `[github]` table (in the host's `~/.config/aqmas/config.toml`) accepts the same optional `api` and `token_file` settings as `[updates.github]` above; without it the CLI asks the public repository. The CLI never talks to a second source and no credential for one goes on fleet hosts: the bastion has already compared it (the CLI prints whether the bastion compared one published source or two), and the CLI then checks the bastion's digests against GitHub itself.

The only degraded mode is an explicit `--allow-single-source` when GitHub is unreachable from that host; it warns loudly and trusts the previously verified cache on the broker alone. It never overrides a malformed manifest or a mismatch. Without that exception, failure to verify is fatal. Interactive runs check the enrolled API for a one-line notice at most daily; no implicit install or prompt. **CLI and bastion of different versions** keep working in both directions: a bastion of this version repeats its verified digests under the key a 0.8.1 CLI reads (`forgejo`), and a CLI of this version reads a 0.8.1 bastion's two-source record. That repeat is GitHub's digests even when the bastion compared GitHub alone, so a 0.8.1 CLI believes two sources agreed where there was one plus the bastion's rebuild; it still fetches GitHub's manifest itself and refuses a mismatch. Roll back with a rename of `aqmas.prev` over `aqmas` in the install directory. On macOS Go's arm64 linker already ad-hoc signs release binaries. The installer clears quarantine on its staged file if present and checks the signature. Invalid signatures require a corrected release; re-signing bytes locally after verification would invalidate the approved digest.
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
