# Per-credential buckets (seal format 2)

**Design · 2026-11-23 · revised after independent review.** Replaces the single installation
master key (MK) of [SEALED.md](SEALED.md) format 1 (v0.4.1). The owner asked: *store
individual credentials in encrypted buckets; when the browser approves, decrypt only that
bucket; hold as few decrypted credentials as possible at any one time.*

In one paragraph: every secret lives in a **bucket** with its own P-256 key pair; the public
half is in the clear, so writing a value needs nothing open. Each bucket's private key is
wrapped to its **scope key** (one per scope: the installation, or one organisation). Each
scope key is wrapped once per passkey under a key derived from that passkey's WebAuthn PRF,
and once to the offline age recovery key. The approval tap that signs a decision also
evaluates PRF for at most two scopes; the browser sends the derived key-encryption keys to
the broker sealed with HPKE; the broker opens the scope key, unwraps exactly the buckets
the signed card lists, wipes the scope key at once and keeps each bucket only as long as
the card says (an instant, a grant, a window). There is no global unlock: after a restart
nothing is open, and nothing needs to be until it is used.

A passkey without PRF holds no such secret. It can be given one opt-in substitute: a key kept by
one browser profile (**Remember this browser**, §13). That is weaker than PRF, and §13 says by
how much: in short, that browser profile plus the passkey opens the remembered scopes, and so
does that browser profile plus a copy of the broker's database, with no passkey at all.

## 1. Threat model

| Event | Format 1 (v0.4.1) | Format 2 |
|---|---|---|
| Stolen disk, DB copy or backup | Nothing without a PRF tap or the recovery key | Same |
| Memory dump / brief root while running | Everything while unlocked | The buckets open at that instant (§5), plus Go heap copies the broker cannot wipe until the garbage collector reuses them: a parsed CA key, the Cloudflare token string during a proxied call, env values as Go strings while a release is collected or a reveal is sealed, the recovery identity text and parsed age identity during a drill, a recovery enrol or `seal-recover`, format-1 entries decrypted during migration staging, and the staging drill key. Scope keys live only for the length of a tap (an abandoned passkey-enable stage: at most five minutes, §7) |
| Malicious approval page (edge or browser) during one tap | KEK; with a DB copy, everything | KEKs of **at most two scopes**; with a DB copy, those scopes' buckets. It can also redirect the tap itself, e.g. turn it into a Reveal to a key it chose, as in format 1. Two "please retry" taps can cover four scopes |
| Persistent root | Everything once unlocked | Every bucket as it is used, every scope a tap yields. **Buckets do not defend against persistent root.** |
| DB writer (tampering) | Payload AEAD under the MK caught forged records | Records and bucket wraps are public-key encrypted: a DB writer can substitute ciphertexts, or a bucket or scope public key so later writes go to its key. A substituted key is refused the next time that bucket or scope is opened (the opened scalar must match), but values written in between were exposed. DB integrity was never a goal ([SEALED.md](SEALED.md)); this is stated, not fixed |
| A removed or stolen passkey plus an old backup | MK | That passkey's scopes, as of the backup **and afterwards** until the scope is **rekeyed** (§7). Rekey after losing a passkey; `seal-recover` rekeys every scope itself (§10) |
| A copy of a **remembered browser's profile** (§13) | Not applicable | Nothing by itself. With an assertion by the passkey that browser is remembered for (the passkey itself, or its password manager's vault): every scope that browser has a wrap of. With a DB copy as well, no broker is needed. Forget the browser and rekey its scopes when a profile may have been copied |
| Rollback to an older format-2 copy of the DB | Not detected | **Not detected either.** The root pin names only fixed fields (installation, recipient, CA pins, config digest), so any older format-2 copy of this installation boots. It brings back the wraps, records and grants of its time: passkeys removed since, wraps a rekey has replaced since (an old scope key, openable with a passkey lost since), revoked grants and rules. Restore only a copy you mean to; afterwards rekey every scope whose passkey was lost after the copy was taken (§11) |

Buckets protect **snapshots** (a disk, a backup, a memory dump, a brief root), not against an
attacker who stays. A window keeps the SSH CA open for its duration; what it may approve is
limited by policy, not by cryptography. A Cloudflare set with auto-approval or indefinite
grants keeps its proxy parent open from the first approval after a restart until the next
restart (§5): that is the convenience the owner chose, and it is shown under Security.

## 2. What is sealed, and what is not

Enumerated from v0.4.1 (`seal.Object` roles, `env_revisions`, `env_drafts`, `signer_keys`):

| Secret | v0.4.1 | Format 2 | Scope |
|---|---|---|---|
| SSH user CA private key | MK record `ssh-ca` | bucket `ssh-ca` | installation |
| Internal (client TLS) CA private key | MK record `internal-ca` | bucket `internal-ca` | installation |
| Cloudflare proxy parent token | MK record `cf-proxy` | bucket `cf-proxy` | its organisation |
| Cloudflare minter parent token | MK record `cf-minter` | **dropped**: token mode is off under organisations, so it was never used; revoke it at Cloudflare | — |
| Env set values (current revision) | MK-DEK record | bucket per env set, one record per entry | the set's organisation |
| Env drafts (CLI upload) | MK-DEK record | entries sealed to the set's bucket at upload | the set's organisation |
| Signer private key | MK-DEK record | bucket per signer set | the set's organisation |
| Approval-notice ntfy topic URL | MK record `ntfy-topic` | **not sealed**, §9 | — |

Older env revisions were already erased by v0.4.1 (`ReplaceEnv` nulls them) and open drafts
expire in five minutes; migration drops both.

## 3. Construction

Primitives (the existing suite): P-256; HPKE base mode RFC 9180, DHKEM(P-256, HKDF-SHA256) /
HKDF-SHA256 / AES-128-GCM (Go `crypto/hpke`, browser `@hpke/core`), single-shot with empty
AAD unless stated; XChaCha20-Poly1305 with a fresh random 24-byte nonce; HKDF-SHA256; age v1
X25519. Every context string is

    T2(role, f1, …, fn) = F("aqmas-seal") ‖ F(u64be(2)) ‖ F(role) ‖ F(f1) ‖ … ‖ F(fn)
    F(x) = u32be(len(x)) ‖ x

`inst` is the random 32-byte installation ID, `rp` the WebAuthn RP ID, `cred` the raw
credential ID, `scope` the UTF-8 string `installation` or an organisation ID, `B` a bucket
ID (32 random bytes), `pk*` an uncompressed SEC1 point (65 bytes). Version 2 in every label
separates format 2 from format 1. Every unwrap checks that the recovered scalar's public
point equals the stored public key.

### 3.1 Scope keys

Per scope: a random P-256 key pair `(skS, pkS)`, stored as `pkS` plus

* **recovery wrap:** one age file to the root-pinned recipient with plaintext
  `T2("scope-recovery", inst, scope, pkS, recipient) ‖ F(skS)`;
* **passkey wraps:** for each passkey enabled for the scope, `(salt, wrapP)` with
  `salt` 32 random bytes (the PRF input, fixed for the wrap's life),
  `KEK = HKDF-SHA256(ikm = PRF(salt), salt = inst, info = T2("scope-kek", inst, rp, cred, scope, salt), 32)`
  derived **in the browser** (the raw PRF output never leaves the page), and
  `wrapP = 0x01 ‖ nonce24 ‖ XChaCha20-Poly1305(KEK, nonce, skS, aad = T2("scope-wrap", inst, rp, cred, scope, salt, pkS))`.

A passkey wrap can only be made by a process holding `skS` **and** a KEK from that passkey's
live tap, so a DB writer cannot plant a passkey that later receives anything.

### 3.2 Buckets and records

Per bucket: `(B, scope, kind, ref, pkB, wrapB)`; `skB` is generated by the broker when the
bucket is created, wrapped and wiped: `wrapB = HPKE(pkS, info = T2("bucket-wrap", inst, B, scope, kind, pkB, pkS), skB)`
(113 bytes). Creating a bucket needs only `pkS`.

Every secret value is HPKE-encrypted to `pkB`, stored `enc ‖ ct`, with
`info = T2("bucket-record", inst, B, role, …)`:

| Role | further `info` fields | plaintext |
|---|---|---|
| `ssh-ca`, `internal-ca` | — | PEM private key |
| `cf-proxy` | org, service, set, issuer, account | token |
| `env-entry` | set, entry ID (32 random), entry name | value |
| `signer-key` | set, scheme, public key | `{"scheme","private"}` JSON |

A record cannot move between buckets, sets, names or roles. A `cf-proxy` record also binds the
configured Cloudflare `api_base` (issuer) and `account_id`: change either on a sealed store and
the record no longer opens (proxied calls fail closed, the drill reports it). A rekey opens
and re-seals with the values configured when it runs, so a rekey before the change keeps the
old binding and one after it cannot open the record: neither carries it across. There is no
in-place re-binding in format 2: treat `api_base` and `account_id` as fixed for the life of a
sealed store; another account means a new parent token, which needs a new seal import. An env revision is a list of
entry references; an unchanged entry keeps its ciphertext, so merges and unsets need no open
bucket. A value's length is the record length minus 81, which is how size limits are checked
without decrypting.

### 3.3 Why per-scope keys

* A PRF salt per **bucket** would bound a tap to two buckets, but every passkey would have to
  tap for every new bucket.
* One key per **passkey** makes one malicious-page tap (plus a DB copy) open everything, as
  format 1 does.
* One key per **scope**, wrapped per passkey: creating buckets is tapless, a tap yields at most
  two scopes (WebAuthn evaluates at most two PRF inputs per assertion; every action needs at
  most the installation and one organisation, since batches and windows are
  single-organisation), and storage is buckets + scopes × passkeys. Enabling a passkey needs
  one tap from it per two scopes plus one tap from a passkey that already opens them.

## 4. The approval tap

### 4.1 Which buckets an action needs

Derived from the stored request and the signed choice, never from the page:

| Action | Bucket | Hold (§5) |
|---|---|---|
| Approve SSH request | `ssh-ca` | instant (signed in the decision transaction) |
| … with a new or matching standing rule | `ssh-ca` | + standing hold until the rule ends |
| Approve Cloudflare proxy request | `cf-proxy` | grant hold until the grant ends |
| … auto-approvable, or with a new or matching standing rule | `cf-proxy` | + auto hold (until restart or policy change) / standing hold |
| Approve enrollment (client certificate) | `internal-ca` | instant |
| Renew agent TLS leaf | `internal-ca` | instant |
| Approve env or secret release (`aqmas run`, `get`, checkout) | the set | env hold until collected, revoked or 10 minutes |
| … with "don't ask again" | the set | + standing hold until the rule ends; a tap for the same set also re-arms its live rules |
| Reveal (vault) | the set | instant |
| Approve signing (`aqmas sign`) | the signer | signing hold until used up, expired or revoked |
| Open approval window | `ssh-ca` if its sets include SSH, the org's `cf-proxy` if they include Cloudflare | window hold until it ends |
| Batch | union of its items | per item |
| Reopen (Security, after a restart or Close all) | the named buckets | the holds of their live users |
| Rekey scope | every bucket of the scope | instant |
| Deny, revoke, policy, form commit, env commit, secret create/convert, don't-ask-again limit, signer create/import, catalogue, passkey add/rename/remove, updates, setup, Close all | none | — |

Challenge paths that carry an open: `POST /api/ui/{requests,enrollments}/{id}/challenge`
(web.go), `/api/ui/seal/batch/challenge`, `/api/ui/seal/windows/open/challenge`,
`/api/ui/seal/env/challenge` (approve), `/api/ui/seal/vault/challenge` (reveal,
sign-approve), `/api/ui/seal/control/challenge` (renew-leaf, reopen, rekey). All others keep
`challenge = SHA-256(canonical)`.

### 4.2 The descriptor and the bound challenge

The challenge response gains `open: {descriptor}`, canonical JSON with sorted keys:

    {"attempt_id","buckets":[{"hold","id","kind","label","scope","until"}…],"epoch",
     "installation","object":"bucket-open","purpose":"approve","recipient","scopes":[s1(,s2)],"v":1}

and the WebAuthn challenge becomes
`SHA-256(T2("open-challenge", SHA-256(canonical), SHA-256(descriptor)))`. The page recomputes
it, refuses options whose challenge differs, and shows the buckets and holds on the card
("Opens SSH user CA: instant"). `recipient` is a fresh HPKE key for this ceremony (single
use, session-bound, two minutes), so a substituted recipient fails at the honest broker.

Options carry `extensions.prf.evalByCredential`: for each passkey with wraps for **all**
the descriptor's scopes, `{first: salt(s1), second: salt(s2)}` in descriptor order, even when
the buckets are open (a hold may end before the tap). A **rekey** names one scope and adds
`"rekey_salt"` (a fresh 32-byte salt) to the descriptor; `second` is then that salt for every
passkey and the packet carries a second KEK derived at it for the same scope (§7). `allowCredentials` is those passkeys,
plus every other owner passkey when every needed bucket is open at challenge time.

### 4.3 Finish

Next to the assertion the page sends `open: {attempt_id, enc, ciphertext}`: HPKE to
`recipient`, `info = T2("hpke-open", inst, "approve")`,
`aad = T2("open-aad", attempt_id, epoch, challenge, cred)`, plaintext `F(KEK1) ‖ F(KEK2 or "")`.
The broker verifies the assertion over the bound challenge, consumes the attempt, opens the
packet, unwraps each scope key with the signing passkey's wrap, unwraps exactly the
descriptor's closed buckets, wipes scope keys and KEKs, holds the buckets with an instant
hold, applies the decision, then replaces the instant hold by the descriptor's holds (or
releases on failure). A failure anywhere opens and applies nothing. PRF results never reach
the broker in `clientExtensionResults`.

### 4.4 Passkeys without PRF

A passkey without PRF ("sign and approve only") signs in, denies, revokes, commits values and
approves anything whose buckets are already open (inside a window, for example). By itself it
cannot open a closed bucket; the card says which passkey can. This matches format 1, where
such a passkey could not unlock.

The owner may let such a passkey open buckets **from a browser it chooses to remember** (§13):
the missing secret then lives in that browser profile instead of in the passkey. It is opt-in
per passkey and per browser, signed, shown under Security, and never applied to a passkey
that has PRF. From a browser that is not remembered the passkey is what this section
describes, and the card names the browser that can open.

It also signs every action that opens no bucket, at any time. One difference from format 1
follows: format 1 refused update approval (and Setup tasks) while locked, so in practice an
update was signed after an unlock tap; format 2 has no lock, so an approve-only passkey that
is a maintenance pin (`/etc/aqmas/update-passkeys.json`, [UPDATES.md](UPDATES.md)) can approve
an update or a Setup task whenever it is signed in. The root runner checks only its pins,
never PRF. Keep only passkeys you would trust with that in the pins.

## 5. Holds

The broker keeps open buckets in one in-memory table: `B → (skB in a locked page, holds)`; the
key is wiped when the last hold is gone and no operation is using it. A hold is
`(kind, ref, until)`; kinds: **instant** (one operation), **grant** (Cloudflare proxy grant),
**env** (env release; at most 10 minutes, then the release is paused), **sign** (signing
grant), **standing**, **auto** (Cloudflare auto-approval, until restart, Close all, or the
set's policy no longer auto-approving any scope; added only by a tap whose card said
"re-arms Cloudflare auto-approval", never by an auto-approval itself, which adds only its
grant's hold), **window**. Holds end on their event (revoke, collect, last signature, window end)
and in a reconcile pass every 15 s that drops holds whose grant, rule or window is no longer
live. Approvals under a window add their own holds.

**Standing rules and auto-approval (the renewal decision).** SSH certificates are signed for
the full approved TTL, so a grant never needs a renewal; repeat access comes from standing
rules. A standing rule or auto policy issues without a tap only while its bucket is open.
Approving a request that creates or matches one keeps the bucket open for the rule's life
(auto: until restart). After a restart the first matching request waits for one tap, whose
card says "re-arms standing rule … until …": one tap per restart per rule, none in between.
Turning the rule off closes the bucket when idle.

**"Don't ask again" for env sets and secrets (0.10.0)** follows the same decision. A rule
made on an env approval puts a standing hold (`envstanding:<rule>`) on the set's own bucket
until the rule expires or is revoked, so later matching releases are issued and collected
without a tap. That is the cost the owner accepts with the choice: for that long, the value
is decryptable by the running broker, and the card and Security → Buckets say so. A closed
bucket (restart, Close all) never issues: the rule stays, the next request becomes an
ordinary card, and the tap that approves it re-arms every live rule of that set (the card's
open line lists them). Reopen (Security → Buckets) re-arms them too. A rule that ended by
itself (new revision, policy replacement, admission ended, limit changed) loses its hold at
once where the broker made the change, and in the reconcile pass otherwise.

Cloudflare **snapshots** (`/v1/cf/snapshots`) are served only while the proxy parent's
bucket is open (423 otherwise), as v0.4.1 served them only while unlocked.

**Restart.** Everything is closed; nothing is restored. Grants that need a bucket (proxy
grants, uncollected env releases, signing grants, standing rules, auto policies) are
**paused**; Security → Buckets lists them per bucket with **Reopen** (one tap per two scopes). The agent
sees `423 locked` "… is closed: waiting for the owner to reopen it" and keeps its deadline.

**Close all** (Security → Buckets or the header's tray, one signed tap) wipes every key and hold and ends every window. It
replaces format 1's **Lock now** and needs no restart. Format 1's lock state, unlock
ceremony, combined unlock+window and lock-protected route allowlist are gone; sign-in never
opened anything and still does not.

**Lock alert.** The separate alert service is unchanged: the broker writes `locked <epoch>`
at every start, so the owner hears that a restart paused grants.

**Hook for the planned bastion-SSH feature.** `bucketPool.snapshot()` lists open buckets and
holds; `closeAll()` wipes them. A future "SSH to the bastion" approval calls both before the
session starts and shows the list on its red card.

## 6. Security tab

**The header**, on every page, has a pill with the number of open buckets. It opens a tray: the
open buckets and their holds, what is waiting, and **Close all**.

**Security opens with one sentence**: "2 of 4 passkeys can open your credentials", each passkey's
state, and **Enable the other N…**, which runs the enable-then-test sequence of §7 for one passkey
after the other (the signed-in passkey approves, the passkey being enabled taps to create its keys
and to test them; a passkey that is not at hand can be skipped). The status's `prf` field only
says that a passkey has a wrap already, so every passkey that opens too little is offered; an
authenticator without PRF says so at its own tap and offers **Remember this browser** (§13)
or to skip it. A passkey that opens only from remembered browsers is marked **Browser key**
in the list, with the browsers' labels, and a scope that only remembered browsers open is
called out (if those browsers lose their storage, only the recovery key is left).

**Security → Buckets** lists every bucket (kind, path, scope), whether it is open, each hold (why,
ref, until), paused users with **Reopen**, per-scope **Rekey**, and **Close all**. Per passkey:
**Opens N of M buckets**, how it opens them (**PRF**: "with its own secret", or **Browser
key**: "only from remembered browsers", each with its label, when it was added and last used,
**this browser** where that applies, and **Forget**; §13.5), scopes enabled and tested,
**Not enabled for …**. A keyed scope no
passkey has opened since it was created or rekeyed carries `tested: false` and the badge
**Not tested yet** (empty) or **Untested after rekey** (with buckets).
`GET /api/ui/seal/status` returns `{mode, installation, epoch, scopes[], buckets[],
passkeys[], active_windows[]}` ([API.md](API.md#buckets)).

## 7. Passkeys and scopes

* **Enable a passkey** (new, or approve-only): an existing passkey signs the capability (format
  1's flow) and, in the same tap, opens the scope keys (PRF, ≤ two scopes); the new passkey
  then taps once with fresh salts for those scopes; the broker wraps each open scope key under
  the new KEKs and wipes it. Repeat per two scopes. The new wraps are marked tested the first
  time they open something; **Enable** (Security → Passkeys, or the guided sequence above) ends with that test round (so "enable B,
  then remove A" needs no separate step) and **Test** does it on demand. A **tested** wrap is
  never replaced (the KEKs come from the page): the page skips scopes the passkey already
  opens tested, the broker refuses an enable naming one, and the store refuses the write. An
  untested wrap may be replaced by an enable or a recovery enrol. A stage holds the opened scope keys between the
  two taps; it is wiped when it finishes, at its five-minute deadline (its own timer and the
  15 s reconcile pass) and by Close all.
* **Enrol with the recovery key** (when no passkey can open a scope any more): Security → Recovery key, paste
  the identity; the page seals it to a fresh broker key; one tap by the target passkey signs
  `recovery enrol` with the packet digest and evaluates PRF for up to two scopes. The broker
  opens those scope keys from their recovery wraps, wraps them for the passkey, wipes them.
  The same without writing is the **recovery drill**. This puts the recovery key into the
  approval page: the routine path is enabling from another passkey; the strict path is the
  offline drill and `seal-recover` (§10).
* **New organisation:** it has no scope key until a passkey creates it: the first value
  written in it is refused with "create the scope first" and Security → Buckets offers **Create** (Vault → Add item runs the same step for a new organisation) (an
  enable of the signed-in passkey for that scope: one signing tap, then one enrol tap; fresh
  `skS`, wrapped for that passkey and to the recovery key). That wrap is untested, so until a
  passkey has opened the new scope once (**Test**: a third tap) no bucket is created in it: the
  first write answers "test the new scope first".
* **Remove a passkey:** its wraps go with it (cascade), and so do its remembered browsers and
  their wraps (§13). The broker refuses to remove (or
  disable for a scope) a passkey with a wrap of a scope for which no **other** passkey has a
  **tested** wrap (of either kind); an untested wrap does not count (the refusal then says which passkey to
  test). The same rule, per scope, is the trigger
  `keep_one_scope_passkey`, recreated at every boot. Removal does not revoke copies of its wraps in old backups:
  for a lost or stolen passkey, **Rekey** its scopes.
* **Rekey a scope** (one tap by a passkey that opens it): new `skS'`; every bucket of the
  scope gets a new key pair and every record is re-encrypted; drafts are dropped; open
  buckets of the scope are closed (their users pause). Only the tapping passkey keeps a wrap
  (a remembered browser that rekeys: only that passkey with that browser, §13.3);
  others are enabled again from it. Old copies then expose only values as of the copy. The
  tap evaluates PRF twice: `first` at the passkey's salt opens the old `skS`; `second` at the
  descriptor's fresh `rekey_salt` gives the KEK that `skS'` is wrapped under, with that salt.
  So a KEK of the old salt (one malicious-page tap before the rekey) plus a later DB copy does
  not open `skS'`. The broker cannot check the fresh KEK before it is used, so the new wrap is
  **untested** until it next opens: the page chains a **Test** tap of the same passkey right
  after the rekey, and Security → Buckets shows the scope as **Untested after rekey** until a test passes.
  If it fails, the way back in is the recovery key: recovery enrol may replace an untested
  wrap (never a tested one), so it can re-wrap the rekeying passkey itself.
* The store runs with `PRAGMA secure_delete=ON` and checkpoints the WAL after removals,
  migrations and rekeys, so freed pages do not keep old wraps.

## 8. Migration and sealing (one-way)

**From v0.4.1 sealed (schema 8): Settings → Setup → "Move to per-credential buckets"** (task
`buckets`, params `{"purge_backups":bool}`). One way: no rollback and no v0.4.1 readability
afterwards.

1. **Run** (tap): the runner checks schema 8 and the format-1 pin, stops the broker, backs
   up DB, config and keys, starts it in `bucket-migrate` mode (no agent listener).
2. **Tap 1** by a format-1 unlock passkey: PRF `first` = its format-1 salt (opens the MK),
   `second` = a fresh salt for the installation scope. The broker opens the MK, decrypts every
   format-1 record, signer key and current env revision, and builds in memory every scope
   key, bucket, record and recovery wrap; then wipes the MK.
3. **Further taps** create the passkey's wraps for the remaining scopes in use (two per tap),
   then **test taps** reopen every wrap (two per tap). Activation requires every wrap tested.
4. **Recovery drill:** paste the recovery key; the broker opens every staged scope key from its
   recovery wrap.
5. **Activate** (a plain signature, as format 1's activation, so the runner can verify it with
   its pins): the format-2 manifest names the installation, recipient, every scope and bucket
   public key, the migrating passkey's wraps, and **every other format-1 unlock passkey, which
   becomes approve-only until enabled**. One transaction writes everything, drops the format-1
   tables, sets schema 9; then `VACUUM` and a WAL checkpoint. The runner verifies the signature,
   pins the new manifest digest, restarts serve and, unless untold, deletes the format-1
   backups of this store: the pre-migration backup and any other backup whose configuration
   pins the same format-1 manifest (they hold format-1 data, openable with the old salts).
   Other backups (unsealed copies, other tasks' rollback points) and state a restore set aside
   beside the data directory are kept and reported ([SETUP.md](SETUP.md)).

An interruption before step 5 commits nothing (staging is in memory): the runner restores the
config and restarts; the task can be run again from the backup state. After step 5 it only
finishes forward. Offsite copies made before migration keep format-1 strength: anyone with
such a copy and one tap from a malicious page asking for the old salt gets the MK.

The new binary in plain serve mode on a schema-8 DB serves sign-in, queueing and the Setup
page only ("migration required"). After migration the root pin names a format-2 manifest, so
a restored schema-8 DB fails the pin and is refused instead of being offered for migration
again.

**From an unsealed store (schema 6/7): "Seal the store"** produces format 2 directly with the
same stage: sources are the plaintext CA files, the Cloudflare proxy parent and the ntfy
config; then scope wraps (create, test), drill and activation as above.

## 9. What stays readable without a tap, and why

| Item | Why it cannot be in a bucket |
|---|---|
| Approval-notice ntfy topic URL (`notice_channel`) | Notices tell the owner a request is waiting, which is exactly when everything is closed. Theft lets someone read or send notices |
| Agent TLS leaf `server.key` (0600) | Agents connect while everything is closed (format-1 exception) |
| Lock-alert credential, updater read tokens, tunnel connector, OS keys | Unchanged, separate operational trust |
| Public material: public keys, salts, wraps, records, env value **names** | Ciphertext or public by design |

## 10. Recovery

* **Drill (browser):** Security → Recovery key drill (§7).
* **Drill (offline):** `aqmasd seal-drill BACKUP.db RECIPIENT <identity.txt` opens every scope
  key and bucket of a standalone backup and prints only counts and the manifest digest.
* **Lost one passkey:** remove it, rekey its scopes, enable a new passkey from another.
* **Lost every passkey:** `aqmasd seal-recover DIRECTORY <identity.txt` in isolated
  maintenance ([SEAL-OPERATIONS.md](SEAL-OPERATIONS.md)): it opens every scope key from its
  recovery wrap, generates a **new** key for every scope, registers a replacement passkey,
  wraps every new scope key for it (create and test taps), and in one transaction rekeys every
  scope (new bucket keys, every record re-encrypted, new recovery wraps), writes the
  replacement's wraps and retires the old passkeys. Copies of the old passkeys' wraps (old
  backups, a lost device) then open only the old scope keys. There is no MK to transfer, so `seal-transfer` is gone
  and the identity itself is piped to the recovery process.

## 11. Formats (schema 9)

    bucket_scopes(scope PK, public_key BLOB65, recovery BLOB, created)
    scope_wraps(id PK, passkey → passkeys ON DELETE CASCADE, scope → bucket_scopes, salt BLOB32 UNIQUE, wrap BLOB73, created, tested_at, UNIQUE(passkey, scope))
    browser_keys(id PK, passkey → passkeys ON DELETE CASCADE, public_key BLOB65, label, created, last_used, UNIQUE(passkey, public_key))          -- §13
    browser_wraps(id BLOB32 PK, browser_key → browser_keys ON DELETE CASCADE, scope → bucket_scopes, wrap BLOB73, sealed_kek BLOB113, created, tested_at, UNIQUE(browser_key, scope))
    scope_openers = VIEW(passkey, scope, tested_at) over scope_wraps and browser_wraps   -- what "another passkey opens this scope" is asked of
    passkey_prf(passkey PK → passkeys ON DELETE CASCADE, since)   -- sticky: has had a PRF wrap (§13.4); set by trigger mark_passkey_prf and at boot
    UNIQUE(passkey, label) on browser_keys
    buckets(id BLOB32 PK, scope → bucket_scopes, kind, ref, public_key BLOB65, wrap BLOB113, payload BLOB NULL, created, UNIQUE(kind, ref))
    env_revisions.payload / env_drafts.payload = JSON [{"n":name,"i":entry-id,"c":record}…] (unset drafts: names only); .wrap = bucket ID
    signer_keys.payload = record, .wrap = bucket ID
    secret_sets(set_id PK → credential_sets, note, url, created)             -- 0.10.0: marks a one-key env set as a secret; no ciphertext
    env_standing(id PK, host, set_id, binding, mode, peer, max_ttl, created, expires, revoked_at, uses)   -- 0.10.0: "don't ask again" rules; no ciphertext
    set_standing(set_id PK, cap_seconds 0..86400)                             -- 0.10.0: a set's longest "don't ask again" (no row: 3600)
    env_releases.delivery ('get' | NULL), env_releases.standing (rule ID | NULL)   -- 0.10.0, added columns
    seal_active(manifest = format-2 manifest, inventory = '{}', canonical, assertion)   -- root-pinned activation
    notice_channel(singleton, topic_url)

`browser_keys`, `browser_wraps`, `scope_openers` and `passkey_prf` came after schema 9 shipped. They are
created empty at every boot (`CREATE … IF NOT EXISTS`, as the guard trigger is), so an
existing store starts unchanged with nothing enabled and the schema version stays 9; an
older build of schema 9 ignores them. The 0.10.0 tables and columns are added the same
way. A secret needs no new format: its value is an ordinary env entry record in its set's
bucket, so recovery, rekey and the drills cover it without change. An older build sees a
secret as a one-key env set, ignores the rules (it asks for a tap every time) and writes
`process` releases only.

**Downgrade fence:** v0.4.1 refuses schema 9 (it requires schema 8 and its tables); the new
binary refuses schema 8 except for the pinned migration. The only way back is the
pre-migration backup with the v0.4.1 binary.

**No rollback fence within format 2.** The pinned manifest describes the store at activation
and boot checks only its fixed fields, because scopes, buckets and wraps change in normal use.
Nothing records a monotonic state outside the DB, so an older format-2 copy of the same
installation boots without complaint (§1). `seal-recover` writes a new pin (its
`recovery_transition`), which a copy from before the recovery fails.

## 12. Tests

Go/TS vectors for `T2`, KEK derivation, the bound challenge and the open packet; Go
round-trips and tamper cases for scope wraps, recovery wraps, bucket wraps and every record
role; each action opens only its buckets (other buckets absent from the open table, their
operations refused without a tap); windows open only their scope and close on expiry;
restart leaves nothing open; migration round trip and re-run after a simulated failure;
recovery open of every bucket; passkey enable, remove and rekey; sentinel scans of logs, DB,
WAL and output; canonical binding of every new action. Interop: migrate a store made by the
v0.4.1 binary, then SSH grant, `aqmas run`, Reveal, `aqmas sign`, a window, restart, recovery
drill.

Remembered browsers (§13): Go round-trips and every binding of the two ciphertexts; the
sealed KEKs are released only inside a valid tap by their own passkey, once, never for
another passkey or browser key, never after the tap; a KEK without the release opens
nothing; canonical binding of `remember` and `forget`; rekey by a remembered browser and by
a PRF passkey; removal and Forget; recovery enrol; a store from before the feature boots
unchanged; the sticky PRF mark (after Disable, after a rekey by another passkey, set at boot
for an existing store); unique labels; every refusal of a release (attempt cap, enrol and
PRF test taps, another session, expired, consumed, concurrent, Forget or removal before the
finish); no KEK and no browser private key in the DB, WAL, logs, audit or responses. Web:
the browser key against the broker's vector, generation (non-extractable), unusable storage,
the enable flow, an approval, rekey, a lost key, Forget, and the PRF path unchanged, against
a mock that seals for real. Interop: a software authenticator without PRF through the page's
own code and the real broker.

## 13. Remembered browsers (passkeys without PRF)

Some passkeys return no PRF result (a password manager that does not implement the
extension, for example). Such a passkey can sign, but it has no secret to derive a KEK from
(§4.4). **Remember this browser** gives it one, kept by a browser profile instead of by the
authenticator. It is opt-in, per passkey and per browser.

### 13.1 Construction

* **The browser key.** A P-256 key pair `(skK, pkK)` made in the browser with WebCrypto as a
  **non-extractable** ECDH key and kept in IndexedDB as a `CryptoKey`. The private half
  cannot be exported by any script and is never sent; the public half (65 bytes) is
  registered with the broker. Its **fingerprint** is `hex(SHA-256(pkK)[0:16])`. One profile
  has one key (per origin); it may be remembered for several passkeys, each with its own
  records.
* **The KEK.** 32 random bytes made by that browser when it is remembered (and again at a
  rekey). It takes the place of the PRF-derived KEK and reaches the broker the same way: in
  the tap's HPKE packet (§4.3).
* **What the broker stores**, per passkey, browser key and scope, with a random 32-byte
  **wrap ID** `W` (the role a PRF salt has):

      wrap       = 0x01 ‖ nonce24 ‖ XChaCha20-Poly1305(KEK, nonce, skS,
                     aad = T2("scope-wrap-browser", inst, rp, cred, scope, W, pkK, pkS))
      sealed_kek = HPKE(pkK, info = T2("browser-kek", inst, rp, cred, scope, W, pkK), KEK)

  `wrap` is the passkey wrap of §3.1 with its own label (a browser wrap is never read as a
  PRF wrap, or the other way round). `sealed_kek` is single-shot HPKE with an empty AAD, 113
  bytes. Both bind the installation, the RP, the passkey, the scope, the wrap ID and the
  browser key. The broker holds `pkK`, `wrap` and `sealed_kek` and **nothing that opens
  them**: it adds no key of its own. It sees the KEK (as it sees a PRF-derived one) only
  inside a tap, in a locked page, and wipes it when the tap ends.

So the browser key is one more recipient of the scope key, by the same two-step design:
the scope key is under a KEK; where a PRF passkey re-derives the KEK from its authenticator,
a remembered browser re-opens it with `skK`.

### 13.2 A tap from a remembered browser

Still one passkey prompt.

1. The challenge is the usual one (§4.2). The offer carries, next to the descriptor,
   `browsers: [{credential_id, key_id, label}]`: the passkey and browser pairs that have a
   wrap of every scope. It is a hint (not signed): the page compares it with the key its own
   profile holds, so the card can say "from this browser" or name the browser that can.
   Such a passkey is in `allowCredentials`. No `sealed_kek` is in the challenge.
2. The passkey signs the bound challenge. If it returned no PRF result and this browser is
   remembered for it, the page sends that assertion and its browser key to
   `POST /api/ui/seal/browser/release`. The broker checks the assertion exactly as a finish
   would (signature over this pending tap's bound challenge, origin, user verification, the
   session's owner) **without consuming or recording anything**, finds the wraps of **that
   passkey and that browser key**, and returns their wrap IDs and `sealed_kek`s. One release
   per tap, at most three attempts; a finished, expired or unknown tap releases nothing: the
   release is recorded under the lock the finish takes the tap with, and only while the
   tap's challenge is still unused, so a release that races the finish loses.
3. The page opens each `sealed_kek` with `skK` and sends the KEKs in the usual packet
   (HPKE to the ceremony's recipient, bound to the attempt, epoch, challenge and credential).
4. The finish verifies the assertion again, consumes the challenge and the attempt, unwraps
   the scope keys with the released browser's wraps and proceeds as in §4.3. It refuses a
   packet from a browser-key passkey whose tap released nothing, and a signer other than the
   one the release was for.

Opening therefore needs **both** the browser profile's key **and** a fresh assertion by that
passkey over this challenge. A wrap belongs to exactly one passkey and one browser key:
another passkey's assertion finds no row for that browser key, and the ciphertexts bind the
credential, so they would not open for it either.

### 13.3 Enable, Test, Rekey, Forget

* **Enable.** Security → Passkeys → Enable (or the guided sequence) runs as in §7. When the
  passkey being enabled returns no PRF result, the page offers **Remember this browser for
  *name***, with the trade-off in plain words and a label (default from the user agent,
  editable). Nothing is created until the owner accepts. Then: the browser makes its key
  (if it has none), asks `navigator.storage.persist()` (a refusal is said, not fatal), and a
  passkey that already opens the scopes approves the signed action `passkey-capability` /
  `remember`, which names the passkey (`credential_id`, `nickname`), the browser key
  (`browser_key`, `browser_key_id` = its fingerprint), `browser_label` and the scopes (one
  passkey's browsers have different labels: a taken label is refused; the cards and the
  Security row also show the start of the key's fingerprint, computed by the page); the
  same tap opens the scope keys, as for a PRF enable. The passkey being enabled then taps
  the `passkey-enrol` action (which names the browser key too); the page sends fresh random
  KEKs; the broker wraps each open scope key and seals each KEK to `pkK`. The audit entry
  `passkey_remember_browser` holds the signed text and the approving passkey. The notice
  sent afterwards names the passkey's nickname and the start of the key's fingerprint, never
  the label the owner typed.
* **Test** proves the wraps open: the same release and packet, for exactly the wraps the
  test names. Enable ends with it. As in §7 a tested wrap is never replaced.
* **Everything a PRF passkey does** works from a remembered browser: approvals, batches,
  windows, reveal, signing approvals, reopen, rekey, creating an organisation's scope key,
  and approving and opening for the enable of **another** passkey (PRF or browser). The
  recovery drill is a plain signature and needs nothing; recovery **enrol** takes
  `browser_key` and `browser_label` and writes browser wraps.
* **Rekey.** A remembered browser that rekeys sends the old KEK and a fresh random one; its
  new wrap gets the descriptor's `rekey_salt` as wrap ID and the fresh KEK sealed to the
  same `pkK`, untested until the chained test tap. Exactly as for a PRF rekey (§7) **nothing
  else keeps a wrap**: other passkeys, and the same passkey's other browsers, are enabled
  again. A rekey by another passkey likewise drops every browser wrap of the scope. The
  broker could seal a new KEK to a stored `pkK` without that browser being present; it does
  not, for the reason §3.1 gives for PRF: a wrap is only ever made in a tap by its own
  passkey with its own key material, so a DB writer who plants a public key receives
  nothing at the next rekey.
* **Forget** (Security → Passkeys, per browser; signed action `passkey-capability` /
  `forget` naming the passkey and the browser key, by any passkey, opening nothing): the
  broker deletes the browser key record and its wraps (and checkpoints the WAL); the page
  deletes the key from IndexedDB when it is this browser's and no other passkey is
  remembered for it. Refused when that browser holds the only tested wrap of a scope (enable
  something else first, or enrol with the recovery key). Removing the passkey removes its
  browsers.

### 13.4 Only for passkeys without PRF

A passkey opens buckets **one way**: with its own secret, or from remembered browsers.

* **A passkey that has, or ever had, a PRF wrap** carries a sticky mark (`passkey_prf`, §11).
  A trigger sets it in the transaction that writes the passkey's first PRF wrap (enable,
  recovery enrol, activation, `seal-recover`), and every boot marks the passkeys that have a
  PRF wrap at that moment, so an installation from before the mark existed is covered.
  Nothing clears it except removing the passkey. While it is set the broker refuses
  `remember` and recovery enrol for a browser, also after a Disable or a rekey by another
  passkey took the wraps away. Status reports it as `had_prf` and the page does not offer
  the browser path for such a passkey.
* **A passkey with remembered browsers** is refused a PRF `enable` (forget them first).
* **A passkey that was never enabled** has no mark, and the broker cannot tell whether its
  authenticator has PRF: PRF results never reach the broker (§4.3). Here the only check is
  the page's: it still sends the PRF inputs at the enrol tap, and when the passkey answers
  them it refuses to finish `remember` and says to use Enable. **This one rule is enforced
  by the page only.** A modified page, or a tap in a browser that hides PRF from an
  authenticator that has it, can put a PRF-capable passkey that has never been enabled on
  the browser path. The owner sees the result (the **Browser key** mark, the signed
  `remember` in the audit log) and undoes it with Forget.

It is not allowed at all for a PRF passkey, even on request, because it could only weaken
it: the browser path would be a second way in that needs less than the authenticator's own
secret, and a passkey with two ways in is as strong as the weaker one. There is no switch
that turns a PRF passkey into a browser-key passkey, and nothing does it silently.

### 13.5 Threat model

**The short version.** A remembered browser's secret is not in the passkey. Two things open
the remembered scopes: (1) that browser profile **and** that passkey, through the broker;
(2) that browser profile **and** a copy of the broker's database or of any backup of it,
**with no passkey and no tap**, because the wrap and the sealed KEK are in the database and
the browser key opens the sealed KEK. The offer says both before anything is signed.

What an attacker needs to open a scope's buckets (beyond what §1 already says):

| | Passkey with PRF | Passkey without PRF, remembered browser |
|---|---|---|
| Through the broker | one tap by the passkey on a page the attacker controls (§1) | the same tap **and** that browser profile's key |
| With a copy of the DB | the passkey's PRF output at the wrap's salt (one malicious-page tap, or the authenticator) | `skK`: code running in that origin in that profile at any time, or a copy of the profile on a browser that does not bind the key to hardware. **No passkey needed** |
| Without the DB | the passkey | the profile's key **and** an assertion by the passkey |

Stated plainly:

* **Before** (no PRF, not remembered): the passkey opens nothing. An attacker with the
  passkey and a session can approve only what is already open.
* **After**: anyone who has **this browser profile and this passkey** can open the
  credentials of the scopes that browser is remembered for. With PRF the authenticator alone
  holds the secret and releases it only on a tap; here the secret half lives in browser
  storage, where malware on that machine, a cloned profile directory, or script injected
  into the origin can use it. Non-extractable means script cannot **read** the scalar; it
  can still **use** the key while it runs there, and a browser that stores the key unbound
  to hardware protects it only as well as the profile directory on disk.
* **What the broker holds:** `pkK`, `wrap`, `sealed_kek`. Nothing that unwraps. A stolen DB
  or backup is as before: ciphertext. The broker gains no way to open a bucket on its own;
  a KEK is in its memory only during a tap, as a PRF-derived one is.
* **What a stolen browser profile gives:** nothing by itself and nothing with the broker
  alone: the release needs the passkey's assertion over a fresh challenge. With the passkey
  (for a password-manager passkey: the unlocked vault, or its sync account) it gives the
  remembered scopes. With a DB copy it gives them without the passkey. This is why the
  owner should not run agents, or anything else untrusted, in a profile that is remembered.
* **Malicious page during one tap** (§1): unchanged in kind. The page gets the KEKs of at
  most two scopes; they are useless without the DB. It can also *use* `skK` for that tap,
  as it can use PRF outputs.
* **Rollback and old backups** (§1): a forgotten browser's wraps survive in copies of the DB
  taken before the Forget; rekey the scopes if the profile may be in other hands.

A possible later hardening, **not built**: wrap `sealed_kek` once more at rest under a key
the broker host keeps outside the database (a file or a TPM), so that a database copy or
backup alone is not enough together with the profile and the attacker would also need the
host's key. It would not change case (1), and it would make the host key one more thing a
restore needs.

A scope that **only** remembered browsers can open is one storage eviction away from needing
the recovery key; Security says so and recommends a PRF passkey for it too.

### 13.6 Storage loss

A browser may drop the key: a private window (some refuse storage, some discard it at
close), "clear site data", a new profile, or storage eviction (Safari removes script-written
storage of sites not visited for a while; other browsers evict under disk pressure unless
`persist()` was granted). **A lost key is harmless.** Nothing fails obscurely:

* the page reads its key before every tap and at every refresh; with none, it says "this
  browser is no longer remembered; enable it again" on the passkey's row and offers
  **Remember this browser** (a new key, a new entry; forget the old entry);
* the approval card says which passkey opens from which remembered browser, and "not from
  this browser";
* a tap by that passkey sends no packet; if a needed bucket is closed the broker answers
  423 "this browser is no longer remembered for this passkey …"; if everything needed is
  open the approval goes through, as for any approve-only passkey;
* a browser that cannot keep a key at all is told so when it tries to remember, before
  anything is signed.

The broker cannot tell that a browser lost its key: the entry stays listed, with its "last
used" date, until it is forgotten.
