# Trusting aqmas on fleet hosts (milestone 1)

## sshd on each fleet host

`deploy/hosts/install-host-trust.sh` installs (dry run by default, `--apply` to change, backs
up what it replaces to `/var/backups/aqmas-host-trust/<UTC time>/`, validates with `sshd -t`
and `sshd -T` before reloading sshd, restores the backup on a failed check, then waits up to
10 s (`SSHD_WAIT_SECONDS`) for sshd's port(s) to listen again, since Fedora's reload briefly
closes the socket; `--uninstall` reverses it):

- `/etc/ssh/aqmas_user_ca.pub` (root:root 0644): the SSH user CA, from `aqmasd print-ssh-ca`
  on the bastion (the same key `GET /v1/ssh-ca` publishes). Only an `ssh-ed25519` line is
  accepted; `--ca-fingerprint` refuses any other key than the one the owner read.
- `/etc/ssh/aqmas_principals/alice` (root:root 0644, directory 0755): exactly one line,
  `alice@<name>`, where `<name>` is the host's name in aqmasd's `[[targets]]` (not
  necessarily `hostname -s`), for the login user from `--user` (repeatable) or `$SUDO_USER`;
  `root` is refused (meant for fleets with `PermitRootLogin no`).
- `/etc/ssh/sshd_config.d/10-aqmas.conf` (`deploy/hosts/10-aqmas.conf`):

```
TrustedUserCAKeys /etc/ssh/aqmas_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/aqmas_principals/%u
```

sshd uses the first value it reads for these keywords, so no earlier file may set them (the
script checks `sshd -T`).

```
sudo ./install-host-trust.sh --name dev-1 --ca-key aqmas_user_ca.pub            # plan
sudo ./install-host-trust.sh --name dev-1 --ca-key aqmas_user_ca.pub --apply \
     --ca-fingerprint SHA256:<as read on the bastion>                              # do it
```

Site policy comes from `/etc/aqmas/host-trust.conf` (or `--policy FILE`; format in
`deploy/hosts/host-trust.conf.example`) plus `--refuse NAME|ADDRESS` and
`--needs-approval NAME`: refused hosts (always list the bastion, by name and address) are never
configured, needs-approval hosts only with `--i-have-owner-approval`. The login user defaults to
`$SUDO_USER`; pass `--user` otherwise.

### The bastion itself

Run by hand, the installer never configures the bastion: the site policy refuses it, and that
stays so. The bastion's own sshd is configured only by the maintenance runner, through the
Setup task **Allow aqmas access to the bastion** ([BASTION-ACCESS.md](BASTION-ACCESS.md) §3).
The runner calls the same script with `--bastion-self`, which skips the refuse rules for that
run and is accepted only together with `--inspect-user` and `--inspect-command`: it installs
the CA and the principals file of the read-only `aqmas-inspect` account, plus
`/etc/ssh/sshd_config.d/90-aqmas-inspect.conf`, a `Match User` block that forces that account
into `aqmasd inspect` and disables forwarding, and it checks with `sshd -T -C user=…` that the
forced command applies to the inspect account and not to the owner's (`--admin-user`). The
owner's principals file on the bastion is written by the runner from root's allowlist, with a
`from="…"` restriction. Nothing here touches `authorized_keys`: the emergency key remains the
way in when aqmas is down.

`AuthorizedPrincipalsFile` only affects **certificate** logins; existing `authorized_keys`
logins keep working, so rollout is additive. Removing long-lived keys from agent sockets and
`authorized_keys` is a later, separate step.

The certificate carries `source-address <requesting host>/32`, which OpenSSH's sshd enforces,
so a certificate copied off the requesting host is useless elsewhere.

Rollout order: one canary host, verify cert login + plain key login + `sshd -t`, then the rest.
Keep a second root session open while changing sshd on a host.

## Forgejo (built-in SSH server on :2222)

Details and the source reading behind them: `deploy/hosts/forgejo-ca.md`. In short:

- Forgejo checks certificates against `[server] SSH_TRUSTED_USER_CA_KEYS`
  (`GITEA__server__SSH_TRUSTED_USER_CA_KEYS` in the container environment).
  An unparsable value is fatal at Forgejo startup, and the value is split on commas.
- Forgejo does **not** map a principal to a user by name. It looks each certificate principal
  up as a *principal registered on a user account* (exact string match).
  `SSH_AUTHORIZED_PRINCIPALS_ALLOW` only limits what a user may register. The owner registers
  the principal once under *Settings -> SSH / GPG keys -> Manage SSH Certificate Principals*.
- **The principal must contain `@`**: aqmasd's config validation refuses a bare Forgejo
  principal such as `alice`, because a bare name would also log in as Unix user `alice` on
  any host that trusts the CA without an `AuthorizedPrincipalsFile`. M1 uses
  `principal = "alice@forgejo"`, so Forgejo needs
  `SSH_AUTHORIZED_PRINCIPALS_ALLOW = anything` (neither `username` nor `email` would accept
  that string; `anything` only affects what can be registered, not who can log in).
- The built-in server **probably does not enforce `source-address`** (inferred from the source,
  untested): a Forgejo certificate copied to another host works there until it expires. The
  Forgejo target therefore has `max_ttl_seconds = 3600`; test the behaviour before relying on
  anything else.
- Fleet hosts accept only `alice@<host>` and Forgejo only the registered `alice@forgejo`,
  so a host certificate does not open Forgejo and a Forgejo certificate does not open a host.
  aqmasd's config validation refuses two targets that would issue the same principal.
- With `ALLOW = anything`, any *other* Forgejo account could register a principal such as
  `alice@db-1`, and a db-1 grant would then open Forgejo as that account. Only matters if
  other accounts exist; register the owner's principal first.

## aqmasd targets config (excerpt)

```toml
[[targets]]
name = "db-1"            # [a-z0-9-]; used in principals and in `aqmas ssh db-1`
address = "192.0.2.61"
aliases = ["db.example.com"]  # optional; may not shadow another selector
port = 22
users = ["alice"]
host_key = "ssh-ed25519 AAAA..."   # pinned, sent as known_hosts_line in grants

[[targets]]
name = "forgejo"
address = "192.0.2.50"
port = 2222
users = ["git"]
principal = "alice@forgejo"        # registered on the Forgejo account; must contain "@"
max_ttl_seconds = 3600             # source-address probably not enforced by Forgejo
host_key = "ssh-ed25519 AAAA..."   # the built-in server's key (ssh-keyscan -p 2222)
```

Other per-target keys: `high_risk = true` marks the card `high`. `forgejo_user` is a
deprecated alias of `principal` and is subject to the same `@` rule.

`aqmas ssh alice@192.0.2.61` and `aqmas mosh alice@db.example.com` share the
`alice@db-1` cache. For services sharing an address, use `user@address:port` or the
canonical target name. Names and aliases are matched case-insensitively without DNS lookups.
Use canonical names for `ssh-config`. Mosh needs the client locally, mosh-server on the
destination, and a reachable UDP port. The SSH certificate authenticates its bootstrap.

Using a Forgejo grant from git: `aqmas cert git@forgejo --why "..."` prints the key,
certificate and known_hosts paths; use them in `GIT_SSH_COMMAND` with the same options
`aqmas ssh` passes (`-F none -o IdentitiesOnly=yes -o IdentityAgent=none -i KEY
-o CertificateFile=CERT -o UserKnownHostsFile=KNOWN -o StrictHostKeyChecking=yes`). A
`git-ssh` helper is an open question (DESIGN.md).
