# Forgejo (built-in SSH server on :2222) trusting the aqmas SSH user CA

How to make a Forgejo instance that uses its built-in SSH server accept aqmas certificates.
The example below assumes Forgejo runs in a container configured through environment
variables (e.g. a compose or swarm stack); keep a way to roll the change back ready, since an
unparsable CA key stops Forgejo from starting.

## Settings

In the `environment:` list of the Forgejo service (same style as the existing
`GITEA__server__START_SSH_SERVER=true` lines):

```yaml
      # aqmas: accept SSH user certificates signed by the aqmas CA (built-in SSH server)
      - GITEA__server__SSH_TRUSTED_USER_CA_KEYS=ssh-ed25519 AAAA...the CA public key... aqmas-user-ca
      - GITEA__server__SSH_AUTHORIZED_PRINCIPALS_ALLOW=anything
```

`anything` is needed because the principal aqmasd issues for Forgejo contains `@` (see below):
`username` would only allow registering `alice`, `email` only one of the account's email
addresses. It only governs what a Forgejo user may *register*; logins still need a
certificate from the CA carrying a registered principal.

| ini (`[server]`) | env var | meaning in Forgejo 17 |
|---|---|---|
| `SSH_TRUSTED_USER_CA_KEYS` | `GITEA__server__SSH_TRUSTED_USER_CA_KEYS` (or `FORGEJO__server__...`) | Comma-separated list of CA public keys in authorized_keys format. Each is parsed at startup with `ssh.ParseAuthorizedKey`; **a key that fails to parse is `log.Fatal`: Forgejo does not start.** No commas in the key comment (the value is split on commas). |
| `SSH_AUTHORIZED_PRINCIPALS_ALLOW` | `GITEA__server__SSH_AUTHORIZED_PRINCIPALS_ALLOW` | Which principal strings a user may *register* on their account: `username`, `email`, `anything`, or `off`. Defaults to `username,email` when CA keys are set, `off` otherwise. It is checked only when a principal is added, not at login. |
| `SSH_TRUSTED_USER_CA_KEYS_FILENAME` | (leave unset) | Only used when Forgejo writes a CA file for an *external* OpenSSH; irrelevant with `START_SSH_SERVER=true`. |

`environment-to-ini` also supports a `__FILE` suffix
(`GITEA__server__SSH_TRUSTED_USER_CA_KEYS__FILE=/run/secrets/aqmas_user_ca`), which would let
the CA key come from a swarm config instead of the stack file. The public key is not a secret,
so the plain variable is fine.

## One manual step: register the principal

Forgejo does **not** map a certificate principal to a user by name. After the settings above,
the owner adds the principal `alice@forgejo` (exactly the `principal` of the `forgejo`
target in aqmasd's config) under *Settings → SSH / GPG keys → "Manage SSH Certificate Principals" →
"Add principal"* (the section only appears when principals are enabled). Forgejo's own text:
"These SSH certificate principals are associated with your account and allow full access to
your repositories." Principals are unique across all users.

aqmasd then issues Forgejo grants with principal `alice@forgejo`, login user `git`, the
`forgejo` target's address (e.g. `192.0.2.50`) and port `2222`, and a `known_hosts_line` with
the Forgejo built-in server's host key (`ssh-keyscan -p 2222 192.0.2.50`). Client side: `aqmas ssh git@forgejo` or, for git,
`aqmas cert git@forgejo` and a `GIT_SSH_COMMAND` using the printed paths (a `git-ssh` helper
is an open question in docs/DESIGN.md).

**Why the principal contains `@`:** a bare principal such as `alice` would also be accepted
as Unix user `alice` by any sshd that trusts the CA without an `AuthorizedPrincipalsFile`
(sshd then accepts a certificate whose principals include the login name). aqmasd's config
validation therefore refuses a Forgejo `principal` (or `forgejo_user`) without `@`.

Because fleet hosts only accept `alice@<host>` (their `AuthorizedPrincipalsFile`) and Forgejo
only accepts registered principals (`alice@forgejo`), a host certificate does not open Forgejo and a
Forgejo certificate does not open a host.

## What was verified, and how

Read in the Forgejo 17.0.2 source (2026-11-20):

- `modules/setting/ssh.go` (`loadSSHFrom`, `parseAuthorizedPrincipalsAllow`): the settings,
  their defaults, comma splitting and the `log.Fatal` on an unparsable CA key, as in the table.
- `modules/ssh/ssh.go` (`publicKeyHandler`), the built-in server's certificate login:
  1. the SSH user must be the built-in server user (`git`);
  2. no CA keys configured → every certificate is rejected; the certificate must be a user
     certificate;
  3. for each principal in the certificate, it looks up a stored key whose content equals the
     principal exactly (`SearchPublicKeyByContentExact`); unknown principals are skipped;
  4. the signing key must be one of the configured CA keys;
  5. `CertChecker.CheckCert(principal, cert)` checks the principal and the validity window
     (expired or not-yet-valid certificates fail);
  6. the login is authorised as that principal key's owner (`forgejo-key-id`).
- `models/asymkey/ssh_key_principals.go`: principals are stored as keys of type principal,
  unique across users, validated against `SSH_AUTHORIZED_PRINCIPALS_ALLOW` only when added;
  `routers/web/user/setting/keys.go` shows the principals UI only when principals are enabled.
- `modules/setting/config_env.go`: `GITEA__SECTION__KEY` / `FORGEJO__...` env vars and the
  `__FILE` suffix; `docker/root/etc/s6/gitea/setup` runs `environment-to-ini` on the container's
  `app.ini` at start.
- `options/locale/locale_en-US.ini`: the principals UI strings quoted above.
- The setup assumed here uses the built-in server (`GITEA__server__START_SSH_SERVER=true`,
  port 2222).

**Inferred from the source, not tested:** the `source-address` critical option is probably
**not enforced** by Forgejo's built-in server. `x/crypto/ssh`'s `CheckCert` deliberately skips
`source-address` and leaves it to the server, which enforces it from the `Permissions` returned
by the auth callback; Forgejo's handler never copies the certificate's critical options into
those permissions. So a Forgejo certificate copied to another LAN host would work there until
it expires. Keep Forgejo grants short, or test this (a cert with `source-address` set to an
address you are not connecting from) before relying on it.

**Not verified here:** nothing in this document was run against a live Forgejo: the end-to-end
certificate login, the principals UI and the `source-address` behaviour are untested.
