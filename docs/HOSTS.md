# Trusting aqmas on fleet hosts (milestone 1)

## sshd on each fleet host

`/etc/ssh/sshd_config.d/10-aqmas.conf`:

```
TrustedUserCAKeys /etc/ssh/aqmas_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/aqmas_principals/%u
```

`/etc/ssh/aqmas_principals/alice` (root:root 0644) contains exactly one line:
`alice@<this-hostname>` (the hostname as configured in aqmasd's `[[targets]]`, not
necessarily `hostname -s`). Add `root@<hostname>` to `/etc/ssh/aqmas_principals/root` only if
root logins are ever wanted (they are not: `PermitRootLogin no` fleet-wide).

`AuthorizedPrincipalsFile` only affects **certificate** logins; existing `authorized_keys`
logins keep working, so rollout is additive. Removing the owner's `id_rsa` from agent sockets
and authorized_keys is a later, separate step the owner decides.

Rollout order: one canary host, verify cert login + plain key login + sshd -t,
then the rest. Keep a second root session open while changing sshd on a host.

## Forgejo (built-in SSH server on :2222)

Forgejo checks user certificates against `[server] SSH_TRUSTED_USER_CA_KEYS` and maps
certificate principals to users via `SSH_AUTHORIZED_PRINCIPALS_ALLOW` (`username` / `email` /
`anything`). M1 design: issue Forgejo grants with principal `<forgejo-username>` and set
`SSH_AUTHORIZED_PRINCIPALS_ALLOW = username`; verify against the running Forgejo 17 build
before relying on it (owner's patched image `17.0.2-patched.1`). Config via
`GITEA__server__SSH_TRUSTED_USER_CA_KEYS` in the Forgejo stack file.

## aqmasd targets config (excerpt)

```toml
[[targets]]
name = "db-1"          # used in principals and in `aqmas ssh db-1`
address = "192.0.2.61"
port = 22
users = ["alice"]
host_key = "ssh-ed25519 AAAA..."   # pinned, emitted as known_hosts line in grants

[[targets]]
name = "forgejo"
address = "192.0.2.50"
port = 2222
users = ["git"]                    # principal for Forgejo is the Forgejo username, see above
forgejo_user = "alice"
```
