# SSH keys in the Vault, and deleting Vault items

Two things arrived together in 0.11.0: SSH key pairs as Vault items, and a **Delete** with a
seven-day bin for env sets, secrets, signing keys and SSH keys. The wire contract is in
[API.md](API.md#vault-web-form-reveal-signer-sets-ssh-keys-and-the-bin).

## SSH keys

An aqmas **SSH target** is a machine that trusts aqmas's certificate authority: `aqmas ssh`
gets a short-lived certificate for it and no key is ever installed there. That needs a
server you configure. An **SSH key** is for everything else that speaks SSH and only
accepts a plain public key: a Git forge (a user key or a deploy key on Forgejo, GitHub,
GitLab), or a server you do not control. aqmas holds the private half, sealed in its own
bucket like a signing key, and shows the public half as the one line those places ask for.

### For the owner

**Vault → Add item → SSH key.** Choose the organisation and service (a new one is created
on the way), a name, the key type (`Ed25519`, the default, or `ECDSA P-256` for a host
that needs it) and a comment (proposed: `aqmas:ORG/SERVICE/NAME`; plain ASCII, it is the
last field of the public line). Then either

* **Generate in aqmas**: the key pair is made on the bastion and the private half never
  exists anywhere else; or
* **Paste an existing OpenSSH private key**: the unencrypted contents of a key file
  (`ssh-keygen -p -N '' -f copy-of-key` removes a passphrase from a copy). The page
  encrypts it to a one-time key of the broker before it leaves the browser.

The passkey prompt shows the public line and its fingerprint; for a pasted key, compare
them with the `.pub` file you already have. The item page then shows

* the **authorized_keys line** (`ssh-ed25519 AAAA... comment`) with a Copy button,
* the **fingerprint** exactly as `ssh-keygen -lf key.pub` and a forge's key list show it
  (`SHA256:...`),
* where it goes: a forge's *SSH keys* (your account) or *Deploy keys* (one repository)
  form, or a line in `~/.ssh/authorized_keys` of the account on a server,
* the hosts that may ask for it, pending requests, live grants and recent history.

There is no reveal and no export. **Rotation** is not a feature of its own: make a new
key, put its line where the old one was, then delete the old item.

**"May be handed out"** is a setting of each key, off unless you turn it on (at creation,
or later on the item page with a passkey tap). Off, the private key cannot leave aqmas by
any route. On, a host may ask for the key file itself, each time with its own red card.

### Two ways for an agent to use it

**The key stays in aqmas (preferred):**

```sh
aqmas ssh-agent acme/forge/deploy-key --why "clone the app repository" -- git clone ssh://git@forge.example.com/acme/app.git
```

The approval card says: SSH logins with this key (its fingerprint), from this host and
address, up to N logins for M minutes. Both can be lowered; there is no single-use and no
indefinite form, and no "don't ask again" beyond the grant itself. Once approved, `aqmas`
runs the command with `SSH_AUTH_SOCK` pointing at a socket only that user can reach, which
offers this one key. For each login the SSH client asks the socket for a signature; the
CLI checks that the data is an SSH login request for this key and sends it to the broker,
which checks the same, signs, and records the login: the key, the host that asked, the
account name on the remote side, a digest of the SSH session and, with a current OpenSSH,
the remote server's host key fingerprint. Further `aqmas ssh-agent` calls for that key from
that host need no tap until the grant is used up, expires or is revoked (Vault → the key →
Revoke). The CLI's default is 10 minutes and 20 logins; the most is 24 hours and 1000.

A grant trusts the host for its duration: anything running as that user on it can log in
with the key until the count or time runs out, wherever the key is accepted. Each login is
in the activity log. The key cannot be copied and stops being usable the moment the grant
ends, the key is deleted or the host's admission ends.

**The key is handed out (only for a key that "may be handed out"):**

```sh
aqmas ssh-key acme/forge/deploy-key --why "the backup tool only reads a key file" --out ~/.ssh/backup_key
```

The card is red and says that the private key leaves aqmas and cannot be recalled. One
approval is one delivery, collected within ten minutes; there is nothing to lower and
nothing to reuse. The CLI writes the OpenSSH private key with mode 0600 (it refuses to
replace a file without `--force`) and the public line beside it as `FILE.pub`. From then
on the key is as safe as that host. Turning the setting off later stops further hand-outs;
it does not un-copy a key. If a handed-out key may have been copied, replace it: new key,
new public line on the server or forge, delete the old item.

For a key without the setting, `aqmas ssh-key` is refused before any card appears and
names `aqmas ssh-agent`. `aqmas ssh-key PATH --public` prints the public line for anyone
admitted, as `aqmas ls` does: it is public.

### What this does and does not protect

* The private key is sealed at rest and opened only inside a signing call (or the one
  hand-out), under the bucket's hold. It is in no log, audit row, listing or other response.
  Root on a bastion with the key's bucket open can use or read it.
* An SSH key in aqmas signs SSH logins and nothing else: not `ssh-keygen -Y sign`, not
  Git commit signatures, not certificates, not arbitrary bytes. Its agent socket cannot be
  given other keys, emptied or locked, and implements no extensions (so it cannot be used
  to forward the agent with destination constraints either).
* aqmas does not decide where the key is accepted: that is the forge's or server's
  `authorized_keys`. Give a deploy key the narrowest access the forge offers (one
  repository, read-only where that is enough).
* Host keys of these servers are not managed by aqmas. The SSH client's own `known_hosts`
  applies; the audit row records the host key the client bound the login to.
* An approval page served by a hostile origin can misdescribe a request. The CLI's Ref,
  the fingerprint it prints and the activity log are the independent checks.

## Deleting Vault items

The item page of an env set, a secret, a signing key and an SSH key has **Delete**. (SSH
targets and Cloudflare access are configuration, not Vault contents; they are removed
where they are configured. A service left without items stays; an empty service holds
nothing.)

1. **Delete** is one passkey tap over the item's path, kind and current revision. If the
   item changed since the page was loaded, the tap is refused and the page reloads.
2. From that tap the item does not exist for hosts: its path answers `not_found` exactly
   like a path that never existed and it is in no listing. Everything that could still use
   it has ended: grants, signing and SSH login grants, "don't ask again" rules, approved
   releases nobody collected, and requests waiting for a decision (their cards disappear;
   the activity entry of the delete says how many of each ended). Its bucket closes. The
   path is free for a new item.
3. **Vault → Deleted** lists what is in the bin: path, kind, who deleted it and when, and
   the time left. **Restore** (a passkey tap) puts the item back as it was, with the same
   contents, revision and key, and with nothing live: the next request asks you again, and
   a "don't ask again" has to be chosen again. Restore is refused while another item has
   the path (delete or rename that one first).
4. Seven days after the delete the broker destroys the item by itself: no tap, no open
   bucket. **Purge now** (red, a passkey tap) does the same at once. Destroyed means the
   sealed records (every revision, the private key record) and the item's bucket with its
   wrapped key are deleted from the store, the freed pages are overwritten and the
   write-ahead log is truncated. There is nothing left to open.

Delete, restore and purge are in Activity with the path, kind, who, when and a digest of
the sealed record, never a value. Deleting an item does not revoke what a host already
holds: a value delivered by `aqmas run`, a handed-out SSH key, an API key that is still
valid at its provider. Rotate those where they are issued.

**Backups.** A copy of the broker's store taken before a purge (a file backup, a
filesystem snapshot) still contains the item's sealed records and its bucket's wrapped
key. They are ciphertext: reading them takes a passkey that can open the item's scope or
the recovery key, as for everything else in a backup. If an item must be gone everywhere,
let the backups that contain it age out, or delete them. Restoring a whole store from a
backup taken while an item was in the bin brings back the bin entry with its original
deadline; the broker purges it on its first sweep if the seven days have passed.
