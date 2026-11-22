# Setup queue and the maintenance runner

**Admin → Setup** runs the remaining setup steps and every later upgrade from the approval
page. Each task is one passkey approval over a canonical description ([API.md](API.md)); a
small root program on the bastion, the *maintenance runner*, verifies that approval itself and
carries the task out. After the runner is installed there is nothing left to do in a terminal.

| Task | What it does | Your part | Reversible |
|---|---|---|---|
| **Switch to organisations** | Backup, fenced review mode, the signed cutover, restart ([ORGANISATIONS.md](ORGANISATIONS.md)) | Tap **Run**; review the plan; tap **Activate** | Cancel any time before activating. An unhealthy broker afterwards restores the backup. |
| **Seal the store** | Backup, seal import, recovery drill, activation pin, deletion of plaintext keys and old backups, lock alert, restart locked ([SEALED.md](SEALED.md)) | Save the recovery key; tap **Run**; create and test the wrap (two taps); paste the recovery key; tap **Activate**; tap **Unlock** | Cancel any time before activating. Not after. |
| **Enable self-update** | Build tools, pinned toolchains, build user, deploy key, forge host key, release tokens, release cache, `[updates]` | Register the deploy key on the forge; paste the token(s); tap **Run** | Configuration is restored if the release check or restart fails. |
| **Sync maintenance passkeys** | Replaces the runner's pinned passkeys with the listed ones | Tap **Run** with an already pinned passkey | Run again. |
| **Upgrade aqmas** | Rebuild in a sandbox, compare with both releases, install, restart ([UPDATES.md](UPDATES.md)) | Review the diff; tap **Approve** | The previous binary is restored if the new one is unhealthy. |

A task refuses to start when its prerequisite is missing (sealing needs organisations; an
upgrade needs self-update), when another task is running, or when the broker is locked. Every
task can be run again after a failure.

## Install the runner (once, as root)

```sh
sudo aqmasd maint-init
```

This creates the spool (`/var/spool/aqmas-update`, root:aqmas 0730), the release cache and
status directory (`/var/lib/aqmas-releases`), root-only state (`/var/lib/aqmas-maint`) and
backups (`/var/lib/aqmas-backups`); a key that pasted secrets are sealed to
(`/etc/aqmas/maint-secrets.key`, root 0600); the read-only deploy key
(`/etc/aqmas/repo-key`, public half shown on the Setup page); the units `aqmas-maint.path`
and `aqmas-maint.service`; and, **only if there are none yet**, the maintenance pins
(`/etc/aqmas/update-passkeys.json`, root 0600) from the passkeys registered at that moment.
That first pinning is trust on first use, which is why it happens in your terminal session
and not through a request. `--repin` repeats it (the way back in if every pinned passkey is
lost). `aqmasd.service` must allow the spool (`ReadWritePaths=-/var/spool/aqmas-update`, as
shipped).

## What the runner trusts

The spool is writable by the broker, so the runner treats every byte in it as hostile.

* **Tasks are compiled in.** The request names a task; it never carries a command, a path or
  a script. Unknown tasks, unknown parameter keys, non-canonical parameter text and values
  outside each task's patterns are refused before anything runs (`internal/maint/spec.go`).
* **The owner's signature is checked by root.** The request is the canonical text plus the
  WebAuthn assertion. The runner checks the assertion against its own pinned public keys, user
  verification, the RP origin from the root-owned configuration, an issuance time at most two
  minutes old, and a replay record. A compromised broker cannot forge any of that.
* **Pasted secrets are sealed to the runner.** The browser encrypts them (HPKE, P-256 /
  HKDF-SHA256 / AES-128-GCM) to the runner's public key; the signed text binds the SHA-256 of
  that packet. The broker, its log, its audit trail and the tunnel only ever see ciphertext.
  A compromised broker could show the browser a different key: don't paste on a host you
  suspect.
* **Status is public and contains no secrets:** fixed step text, digests, public keys.
* **Pins change only by a signed task** (or `maint-init --repin` on the machine). The new list
  is spelled out in what you sign, as credential ID and public-key digest, and the runner
  takes a key from the broker's record only when it matches.
* **The runner ships inside `aqmasd`** (`aqmasd maint-run`), so an approved upgrade also
  upgrades the runner. This is a deliberate convenience: an approved release now determines
  the code that will verify later approvals. Units, pins and the secrets key are not touched
  by an upgrade.

Things the runner does as root, all with fixed arguments: stop/start `aqmasd` (maintenance
modes are selected by a drop-in under `/run`, gone after a reboot), copy and restore the state
and configuration directories, edit `config.toml` (each edit is proved by re-parsing: the
result must equal the old configuration with exactly the intended fields changed), delete the
retired plaintext key files, install packages and toolchains, write token files, and run the
embedded release installer.

An interrupted task (crash, power loss) leaves a journal; the path unit starts the runner
again and it either finishes (after a signed activation) or restores the previous state.

## Sealing from the browser

The page offers to **generate the recovery key in the browser** (a native age X25519
identity, made with WebCrypto, never sent anywhere) or to take a public key you made with
`age-keygen`. Save the secret half (`AGE-SECRET-KEY-1…`) in your password manager before you
continue: with a backup of the database it decrypts everything, and it is the only way back if
every unlock passkey is lost.

The recovery drill runs **on the bastion** (an owner decision trading the isolated-machine
drill of [SEAL-OPERATIONS.md](SEAL-OPERATIONS.md) for one you will actually do): you paste
the secret half once; the browser seals it to the import process, which decrypts the staged
recovery packet with it, authenticates every staged secret and keeps only the
acknowledgement. The key is not written or logged, and the process exits at activation. This
proves the key you saved works. It does not prove the bastion never saw it, so treat a
bastion compromise during that window as exposure of the recovery key.

After activation the runner pins the manifest digest in the root configuration, blanks
`ntfy.topic_url`, deletes `ca/ssh_user_ca`, `ca/client_ca.key`, the Cloudflare parent token
files and their `LoadCredential=` lines, keeps `inventory.json` and `manifest.json` (the
encrypted recovery bundle) under `/var/lib/aqmas-backups/sealed-…/`, and, unless you untick
it, deletes every older backup in `/var/lib/aqmas-backups` because those still hold the
private keys. Deleting files does not erase old disk blocks or off-box copies; rotate what
matters ([SEAL-OPERATIONS.md](SEAL-OPERATIONS.md)).

The optional lock alert takes a dedicated ntfy topic URL and a publish-only token. They are
stored root-only in `/etc/aqmas-alert/` for the separate `aqmas-lock-alert.service`.

## Web API

All under a signed-in session. `GET` works while locked and in the maintenance modes.

* `GET /api/ui/setup` →
  `{mode, runner_installed, runner_version, secrets_key, deploy_key, passkeys[], current?, refused?, tasks[], update_sources}`.
  `mode` is `serve`, `cutover` or `seal-setup`. Each task is its fixed description (`id`,
  `title`, `summary`, `steps[]`, `reversible`, `secrets[]`) plus `state` (`available`,
  `blocked`, `idle`, `running`, `waiting`, `done`, `failed`), `blocked_by`, `rerunnable` and
  `last` (the last run: `state`, `step`, `waiting_for`, `deadline`, `started_at`,
  `finished_at`, `message`, `log[]`, `result{}`). `passkeys[]` are
  `{id, credential, key_sha256, name, pinned, current}`.
* `GET /api/ui/setup/cutover/preview` → `{id, plan}`: the plan the cutover would propose now.
* `POST /api/ui/setup/host-key {repo}` → `{host, keys:[{line, fingerprint}]}`: the forge's SSH
  host keys as the broker sees them, for you to compare. They only count once signed.
* `POST /api/ui/setup/{task}/challenge {params, secrets_sha256}` → the usual
  `{challenge_id, canonical, public_key}`.
* `POST /api/ui/setup/{task}/run {challenge_id, assertion, secrets}` → `{ok}`; the request is
  now in the spool. A passkey that is not pinned is refused here with an explanation.
* `POST /api/ui/setup/cancel {}`: ask a waiting task to give up. Unsigned on purpose: it can
  only return to the state before the task.
* `POST /api/ui/seal/drill {packet}` (import mode): the sealed recovery identity. The seal
  status gains `drill_key` and `drilled`.

Canonical text of a setup approval (keys sorted, as for every object):

```json
{"action":"run","id":"seal","issued_at":"2026-11-22T10:00:00Z","nonce":"…","object":"setup","params":"{\"recipient\":\"age1…\",\"purge_backups\":true,\"lock_alert\":false}","secrets_sha256":"","v":1}
```

`params` is the task's parameters as one JSON string with **keys in this fixed order** and no
extra whitespace; `secrets_sha256` is the SHA-256 of the raw secrets packet, or `""`:

| Task | `params` | Secrets (JSON object sealed to `secrets_key`, HPKE info `aqmas-setup-secrets-v1\0<task>`) |
|---|---|---|
| `cutover` | `{}` | none |
| `seal` | `{"recipient","purge_backups","lock_alert"}` | `ntfy_token`, `ntfy_topic_url` when `lock_alert` |
| `enable-updates` | `{"repo","forgejo_api","github_api","known_hosts":[sorted lines],"forgejo_token":bool,"github_token":bool}` | `forgejo_token` and/or `github_token` as flagged |
| `sync-passkeys` | `{"pins":[{"id","key_sha256"}]}` | none |

A packet is `base64url(enc ‖ ciphertext)` of HPKE base mode with an empty AAD. The drill
packet uses the same construction with the import process's `drill_key` and info
`aqmas-seal-drill-v1\0` followed by the 32 raw bytes of the staged installation ID.

## Trust limits

A compromised broker can refuse to queue a task, lie about progress, or show a misleading
page, and it already holds every credential until the store is sealed. It cannot make the
runner execute anything but a compiled-in task that a pinned passkey signed within the last
two minutes, and it cannot read pasted secrets it did not already have access to. The
release-reading tokens are stored root:aqmas 0440 because the broker reads them to discover
releases. The first pins come from the broker's database at `maint-init` time. Self-update
cannot change the pinned toolchains or the unit files; those remain manual changes.
