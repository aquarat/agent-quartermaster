# Sealed mode and fewer approval taps

> **Format 1 is superseded.** The installation master key (MK), the **Unlock broker**
> ceremony, **Lock now**, the combined unlock + window tap and the locked-route allowlist of
> v0.4.1 are replaced by per-credential buckets (seal format 2): [BUCKETS.md](BUCKETS.md) is
> the design, [API.md](API.md#buckets) the wire contract and
> [SEAL-OPERATIONS.md](SEAL-OPERATIONS.md) the procedures. This page keeps what still holds:
> batches, approval windows, transport encryption and the threat notes.

**Design · 2026-11-21, revised for format 2 on 2026-11-23.** A stolen disk or backup should
not be enough to become the SSH CA or obtain a Cloudflare parent token. After a restart the
bastion **receives requests but cannot satisfy those that need a closed bucket** until an
approval opens it. There is no global unlock: the tap that approves a decision also opens
exactly the buckets that decision needs. The price is availability: a restart, including a
successful update, pauses grants that need a bucket until the owner reopens them. Keep the
owner's independent emergency SSH access.

Two decisions that look similar in the UI have different meanings:

| Button | What one passkey assertion authorises |
|---|---|
| **Approve selected (3)** | Decide precisely the three requests shown with the choices shown, and open the buckets those decisions need. A fourth request arriving before the tap is not included. Recommended for a backlog. |
| **Open approval window: personal, 10 min** | Delegate a bounded class of *future* decisions to this tab, and keep the buckets they need open for the window's life. Each still has a confirmation, but the server no longer has passkey evidence of the owner's intent for that decision. |

Sign-in opens nothing. A signed-in owner can inspect the queue, deny and revoke with every
bucket closed. A window is never installation-wide. Signing out closes the window. Security →
Buckets offers a separate, freshly signed **Close all** (BUCKETS.md §5).

This is a design record, not an operator command reference. [API.md](API.md) describes
today's interface. It and [the organisation design](ORGANISATIONS.md) remain the authority on
grants, admissions and durations.

## What is sealed

[BUCKETS.md](BUCKETS.md) §2 lists every sealed secret and §9 what stays readable without a
tap, and why. Two deliberate exceptions carry over from format 1:

* **Agent TLS `server.key`** stays a service-readable 0600 leaf key in a 0700 directory, so
  agents can connect while every bucket is closed. TLS 1.3, the pinned internal CA, SANs,
  server-only EKU and live host-certificate checks still apply. Theft enables server
  impersonation; the leaf cannot issue host identities. If it is missing, expired, mismatched
  or invalid for the configured names, the agent listener is disabled and the web surface stays
  reachable for **Renew leaf**. Never fall back to HTTP, a new CA or unchecked clients.
* **The restart alert** (below) holds its own write-only ntfy credential.

Metadata is not confidential: host inventory, policy, key and env value names, grants,
audit, public passkey records, salts, scope and bucket public keys and wraps can be read in
a DB copy. Redacted CF snapshots are still sensitive; protect the DB, snapshot directory and
backups. Encryption does not authenticate policy rows or detect rollback of the whole DB.

**Restart alert without a circular dependency.** A separate service under its own uid
(`aqmas-lock-alert.service`) watches a local, read-only status file the broker writes at
every start (`locked <epoch>`). It alone holds a different, write-only ntfy credential for a
dedicated alert topic and publishes fixed text once per epoch, with bounded retries: no
inbound commands, request content or links from the daemon. It also reports the service
being down. Its credential is a disclosed disk-theft exception: it can send nuisance alerts,
not open buckets or publish approval notices. Ordinary approval notices use the unsealed
`notice_channel` topic (BUCKETS.md §9).

## Opening buckets

Every approval that needs a bucket carries an **open descriptor**; the WebAuthn challenge is
bound to it; the browser derives one key-encryption key (KEK) per scope from the passkey's
PRF output and sends the KEKs HPKE-sealed to a fresh, single-use broker key
([BUCKETS.md](BUCKETS.md) §4, [API.md](API.md#buckets)). The raw PRF output never leaves
the page and never appears in `clientExtensionResults`. A passkey without PRF signs in and
approves anything whose buckets are already open; it cannot open a closed one. Enabling,
testing, removing passkeys and rekeying scopes are in BUCKETS.md §7.

**What the extra encryption buys.** HTTPS ends at Cloudflare; the tunnel is a second
connection. Sending the KEKs in ordinary HTTPS JSON would give an edge observer reusable
offline unwrapping keys. With honest code and an unmodified challenge response, a passive edge
or HTTP body logger gets only a one-attempt ciphertext; deleting the attempt key also protects
a recorded exchange against later disk theft. An active edge controls the origin: it can
replace the page, substitute its own recipient *before* the tap, or ask for the same PRF salts
on a misleading ceremony. Binding the recipient into the signed challenge stops substitution
from succeeding **at the honest server**; it cannot stop a false page learning the KEKs. With
a DB copy those KEKs open their scopes' buckets offline, at most two scopes per tap. CSP,
Access, a pin shipped by that same page and a passkey prompt are not independent trusted
displays. Keep the zone, tunnel and owner browser trusted; for protection from an active edge
require independently installed client code and a separately authenticated channel, or move
the approval origin off that edge. Prefer the offline recovery path over pasting the recovery
key into the tunnel UI.

For the off-edge option the passkeys that hold scope keys need a **distinct RP ID outside the
edge-controlled origin's WebAuthn scope**, including parent-domain and related-origin
arrangements, bound there from enrolment through recovery. A pinned client for normal
approvals does not prevent a second, deceptive PRF ceremony at a still-authorised origin.

## Two ways to approve several requests

### Batch: fewer taps, same signed boundary

Select known pending requests within one org, set approve/deny and each duration
individually. Freeze the selection. Show **all** canonical descriptions, org/path, host and
destination, Ref, scopes, TTL and standing consequences before the tap. Example: “Approve Ref
A for 15 min; deny Ref B; approve Ref C for 5 min”. No “and 17 more”, blanket “approve
queue”, expandable-only critical fields or signature over bare IDs. Reason is marked
untrusted. Limit batches to ten entries and 32 KiB of canonical UTF-8; split larger
selections explicitly. Start with ordinary scoped requests only; send anything requiring
special confirmation (including the exclusions below) to its individual tap. The tap opens
the union of the members' buckets, so a batch may need at most two scopes.

Use one server-stored outer canonical committing to an ordered list of **complete** inner
action canonicals (Appendix A). The browser compares membership and every field with its
frozen cards, renders those bytes, then requests one UV assertion over the bound challenge.
Apply all or none: reparse every member, re-resolve identity, admission, policy, revisions,
cap, grantability and deadline in one immediate transaction. A concurrent cancel, deny,
policy edit or stale item returns conflict with **none applied** (and nothing stays open);
refresh and review a new selection. No network side effects in the transaction. Stage SSH
signatures privately; publish only on commit. Mint/collect later under normal delivery
checks; queue notifications after commit. Audit one signed list plus each exact member,
outcome and batch ID. The owner still signed every action's contents; a crowded screen makes
omissions easier for a human, hence the limit.

### Window: delegate clicks, not signatures

In **Security → Buckets → approval windows** (per organisation), a fresh signed policy change sets off or an absolute
maximum of 5–60 minutes and an idle limit (never longer than the absolute limit). Enabling
it does not open one. The owner chooses a duration up to that maximum and reviews **which
org, sets and actions, for how long, with what exclusions**. A fresh UV assertion signs
`window open` (Appendix A) and opens the buckets the window's sets need (the SSH CA, the
organisation's Cloudflare proxy parent) with a window hold until it ends; show a persistent
countdown, org and **End now**. Opening one never extends a grant or sets a standing rule.
Only an applied decision counts as activity; reads, polling and heartbeats do not. Neither
activity nor a new tab renews the absolute deadline.

Use a positive server-side allowlist. Start with finite, normal-risk non-root SSH to
explicitly eligible sets and low-risk CF proxy `cf.read`/`cf.cache.purge` where a decision is
needed. Admit only `request approve` and `request deny`, standing duration zero. Do not infer
eligibility from an org name, a client risk flag, or permission to auto-approve. Exclude
enrollments/replacements, admissions, policy, passkey, organisation and catalogue changes,
seal control (reopen, rekey, close all), recovery, updates, `cf.admin`, `cf.read.private`,
high-risk targets, token mode, env releases, vault actions, standing rules, indefinite and
beyond-soft-cap durations (requested or selected). These always use a fresh individual tap,
including denials where applicable. Client and club grants are excluded unless that org
explicitly opts particular eligible sets into windows in its signed policy; no org can waive
the hard exclusions. Unknown kinds and unmapped legacy routes fail closed.

**Confirming a click.** Use a distinct prepare/confirm route. The server builds the same
complete canonical action as for a tap, stores it one-use for at most two minutes and never
beyond the window deadline, binds it to session/window/tab. The UI compares against the
selected card and renders it before confirm. The server accepts only its stored proposal ID
and a proof from that tab over window ID and proposal hash (Appendix A), never mutable fields
from the click. Under the same decision fence/transaction, recheck session, opener
credential, window generation, deadline, membership, admission, policy, eligibility and exact
target fields before apply. A stale proposal needs new review; no automatic fallback to a
click on a passkey route. Attribute each action as e.g. **Approved under window opened by
passkey X at T**, with exact canonical, opener assertion reference, org, Ref, time and
result. Applied-action pushes distinguish window, batch and direct tap. Never describe a
window click as a WebAuthn signature.

**What the owner gives up.** Malicious page code can confirm eligible requests (or deny them)
with no click and no further tap. A hostile edge can serve such code. The tab key prevents
simple bearer replay from a copied HTTP transcript; it cannot tell a human click from a script
using the live tab. The server can attest to scope, expiry and what it applied, not that the
owner saw the card. Multiple ordinary grants can accumulate, SSH access can expose other
credentials on the host, and grants may survive the window, logout and **Close all** (a
Cloudflare grant then pauses until reopened; an issued SSH certificate stays valid). Closing
the window prevents *new* approvals, not use of existing grants. Choose batch if per-action
intent matters.

For example, distinguish **“You may approve for the next 10 minutes”** from **“Each SSH grant
can last up to 30 minutes.”** Sign and display the maximum resulting TTL per eligible
set/scope. The server can verify control of the opening key, not attest that the browser
generated it as non-exportable: hostile code present at opening can nominate a remote key and
copy the capability and session material. In that case automated confirmations and
heartbeats can continue after tab close, until server revocation or expiry. Absolute time and
the server allowlist, not the close event, bound that exposure.

A plain sign-in assertion is never exchangeable for a window, and a window open is never
exchangeable for anything else.

## Operations and recovery

Sealing, the one-way move from format 1, drills, lost passkeys and lost-everything recovery
are in [SEAL-OPERATIONS.md](SEAL-OPERATIONS.md) and BUCKETS.md §8 and §10.

**Recovery key: a dedicated native age X25519 identity.** Generate it on a trusted owner
device; keep the private identity offline and independently accessible even if the passkey
manager or account is lost. Only the public recipient goes on the bastion. Do not repurpose
the emergency SSH signing key or depend on a memorable password. The owner can keep an
independently protected second copy. Every scope key has a wrap to this recipient, so the
identity plus a sealed backup reads **all** its secrets without a passkey. See the
[age v1 specification](https://age-encryption.org/v1).

**Updates.** A fresh individual update assertion and root-pinned public keys remain exactly
as in [UPDATES.md](UPDATES.md). No PRF, window or bucket in the proof. Warn before approval:
“Restart closes every bucket; paused grants wait for a Reopen.” `/healthz` tests process/DB
health and seal readiness; a healthy restart with everything closed is success, not cause to
roll back. Rollback also restarts closed. Only compatible sealed binaries may be
auto-updated or rolled back; format changes are supervised (the move to buckets is a Setup
task).

**Memory on the bastion.** Scope keys, bucket keys and KEKs live in dedicated locked pages
(`mlock`, `MADV_DONTDUMP`); preflight the service uid's memlock limit and fail secret
operations closed if locking fails. Scope keys and KEKs are wiped at the end of the tap; a
bucket key is wiped when its last hold ends and no operation uses it. Preserve the
unprivileged service, `NoNewPrivileges`, empty capability set, private temp/devices and
narrow writable paths; set a bounded `LimitMEMLOCK`, `LimitCORE=0`, a non-dumpable process,
and disable crash dumps, hibernation, memory snapshots and body tracing. Disable swap or
encrypt it with nonpersistent boot keys; restrict ptrace and `/proc`. Go stacks, immutable
strings, library signers, TLS/HTTP buffers, JS/WebCrypto and GC copies defeat perfect
wiping. None of this protects against live root.

## Threats: what changes

BUCKETS.md §1 compares format 1 and format 2 event by event. These notes still apply:

| Event | Result and response |
|---|---|
| DB or backup copied | Buckets need a PRF-derived KEK or the recovery identity; metadata and any separately backed-up leaf or snapshots remain sensitive. Pre-import backups may contain plaintext. No rollback detection. |
| Powered-off disk stolen, no TPM | No usable scope or bucket key after a correct import. Leaf, connector, restart-alert and update-read keys may be usable; rotate them. Assumes no plaintext swap, dumps, earlier files or VM RAM snapshot. |
| Root on the bastion with everything closed | Can steal those exceptions, alter DB, policy, code, audit and page, disrupt service and trap the **next** tap. Cannot decrypt today's buckets from the clean cold disk. Never approve on a suspect host; rebuild from trusted media. |
| Root/daemon compromise while buckets are open | Can use every open bucket and every scope a later tap yields, release values and forge broker activity. **Close all** afterwards cannot unsteal anything. Replace broker trust and upstream keys. |
| Compromised Access/edge | Access bypass alone is not a WebAuthn signature. The edge sees session traffic; active origin control can mislead the owner, harvest KEKs on a tap or drive an open window. Tunnel TLS does not make the page independent of Cloudflare. |
| Compromised approval page/browser | Can request or misdescribe genuine ceremonies, exfiltrate KEKs for up to two scopes per tap and click repeatedly within an open window. Even a direct passkey tap is not a trusted display. Check CLI Refs and applied pushes; suspend the origin and rotate on exposure. |
| Lost/stolen passkey | Remove it, **rekey** its scopes and enable a replacement from another passkey (BUCKETS.md §7); old backups hold its wraps until the rekey. |
| Lost/stolen recovery identity | Format 2 offers no recipient change yet: if it is destroyed, keep two independently held passkeys enabled for every scope. If theft is possible, assume every backup it covers is exposed and rotate the protected credentials at their issuers (a rekey keeps wrapping to the same recipient). Losing every passkey and the identity cannot be fixed by root. |
| Close all or restart while grants exist | The proxy, env releases and signing pause locally; issued SSH certificates, provider-valid children and copied env values are not recalled. Revoke at the issuer or target where necessary. |

## Appendix A · Formats and checks at the boundaries

Format-2 constructions (context strings `T2`, scope and bucket wraps, records, KEK
derivation, descriptor, packet) are in BUCKETS.md §3–4 and API.md#buckets. Format 1's
suite-1 at-rest records, `mk-*` tuples and `hpke-finish` packet are kept only for the
one-way migration.

**In transit.** RFC 9180 HPKE base mode on both ends: DHKEM(P-256, HKDF-SHA256),
HKDF-SHA256, AES-128-GCM, one encapsulation and one message per fresh attempt key. No
caller-chosen HPKE nonce. Validate encoded public keys; domain-separate `info` by protocol,
installation and purpose; bind attempt ID, boot epoch, the bound challenge and the signing
credential in the AAD. The server keeps the ephemeral private key only in a bounded,
expiring attempt map bound to session and purpose; it is evicted on use, failure, timeout
and **Close all**. Strip PRF extension results from WebAuthn serialization on **both**
create and get; send only allowlisted public extension outputs. Do not modify signed
authenticator data. No telemetry, exception dumps, caches or intermediary body capture.
Treat client extension output as key material, **not signed proof**: proof is a valid bound
assertion plus a successful unwrap whose scalar matches the stored public key. Uncompressed
SEC1 P-256 public keys (65 bytes), unpadded base64url. Do not put decrypted packets,
transient extension data or ciphertext that might carry a secret into passkey records or
audit.

**Canonical profiles.** Preserve [API.md's rules](API.md#approval-challenge-the-security-boundary):
sorted ASCII keys, exact scalar types, UTF-8 JSON, byte-identical reserialization, 32-byte
random nonce, issuance time, SHA-256 over exact bytes, strict endpoint/object/verb/session
binding. Dispatch new object/version explicitly; unknown fields fail, no fallback. The UI
compares each option, signed field and digest with the selected action; display from
canonical only, with escaping/bidi isolation and full scope descriptions. The server
consumes its own stored challenge once and checks RP ID, origin, type, UP, UV, actual signer
and counter policy, owner authority, expiry and current state on apply.

| Profile | Fields committed beyond the common action/object/id/time/nonce/version |
|---|---|
| Batch decide | Installation, org ID/label, epoch, count and a scalar `items` string: canonical JSON array of strings, each string one complete independently parseable scoped request canonical, in bytewise request-ID order. Same JSON string escaping as the outer canonical; exact round trip in both languages. No duplicate IDs, nested batches, mixed orgs, unknown item versions or reusable inner challenge records. Only the outer hash is a challenge. |
| Window open | Installation, epoch and the terms: org ID/label, policy version, explicit eligible set IDs, allowed kinds/scopes/verbs, per-grant TTL ceilings and exclusions, absolute duration, idle limit, public window ID, the opener credential ID (sole allowed credential) and tab public key. Show the delegation, not just “verify identity”. Server times start at successful apply, capped by session expiry. |

**Window capability.** On open the tab generates an ephemeral non-exportable WebCrypto P-256
signing key; the server returns a random 32-byte opaque token once. Keep private key and
token in this document's memory only (no cookies for the window, storage, service workers,
URL or “restore tab”); the server stores only the token hash plus a revocable in-memory
record with signed terms, opener key/person, live login session hash and Access subject, tab
public key, deadlines, policy revision and epoch. Use the strict `__Host-aqmas_session`
cookie/POST guards too; require a verified Access subject for windows. Confirm requires token
plus an ECDSA-SHA256 tab signature over framed `window-confirm`, installation, window ID,
one-use proposal ID and canonical hash. A tab signature is a software capability, not user
verification; it is never accepted at an assertion endpoint. Revoke immediately on
end/logout, key or session loss, admission/policy/membership changes, **Close all**, restart
and expiry; invalidate pending proposals too. One active window per session; opening another
closes the old one. Security → Buckets shows active windows and can close them from another authenticated
owner session.

On pagehide/close/reload discard tab secrets and best-effort notify the server to close;
never resume from back-forward cache. The server cannot *observe tab close reliably*: a
presence lease (heartbeat every 10 s, expiry after 30 s, never extending idle or absolute
deadlines) and loss of the tab key prevent new confirms even if the close message was lost.
A hostile or still-running page can keep the lease alive within the signed limits. Use
monotonic server deadlines and serialize close against commit; revoke wins for any
not-yet-authorised decision.

## Appendix B · Which passkeys can hold scope keys?

Evidence reviewed **21 November 2026**; these are published results, not tests of the owner's
devices. “PRF works” means a *provider* returns a stable PRF result on UV `get()` for the
same credential and salt. Browser API support, successful sign-in, a vendor using PRF to
unlock its **own** vault, and a credential created on another device are four different
claims. A synced credential may also share a single recovery/failure domain. Security → Passkeys →
**Test** proves a passkey's wraps on the device in hand.

| Provider / authenticator | Evidence and deployment expectation |
|---|---|
| iCloud Keychain / Apple Passwords | **Yes on current platform paths.** [WebKit, Safari 18](https://webkit.org/blog/15865/webkit-features-in-safari-18-0/) introduced passkey PRF; [provider measurements](https://www.corbado.com/blog/passkeys-prf-webauthn) distinguish macOS 15+/iOS 18+ platform use from early iOS hybrid/QR inconsistencies. Test same-device and synced-device use separately on patched OS versions. |
| Bitwarden-stored passkey | **Uncertain/mixed; provision as approve-only until tested.** [Bitwarden's vault unlock documentation](https://bitwarden.com/help/login-with-passkeys/) describes Bitwarden as RP. Its [provider feature request](https://community.bitwarden.com/t/support-for-storing-prf-capable-passkeys-in-bitwarden-vault/82239) and [2026 cross-platform tests](https://www.corbado.com/blog/passkeys-prf-webauthn) do not establish general provider support: no output on tested macOS/Chrome; some community successes elsewhere. |
| 1Password | **Yes on supported browser-extension paths.** [Vendor support and extension fix](https://www.1password.community/1password-at-home-31/passkeys-don-t-work-on-filekey-app-21994) identifies 8.10.82+ for a specific interop fix. [Provider guidance](https://www.1password.community/developers-69/1password-prf-support-in-macos-applications-25946) says request PRF at creation. Don't extrapolate to old entries, every mobile provider or hybrid transport. |
| Google Password Manager | **Yes reported on Android/Chrome and desktop Chrome using GPM** ([PRF tests](https://www.corbado.com/blog/passkeys-prf-webauthn)). [Google's environment guide](https://developers.google.com/identity/passkeys/supported-environments) distinguishes GPM from a local Chrome profile or another OS provider. Choosing Chrome alone proves nothing. Test sync and QR separately. |
| Windows Hello | **Conditional yes**, not the old blanket “no”. [Patched Windows 11 reports](https://community.bitwarden.com/t/encryption-prf-via-windows-hello-passkey/94236) and [Bitwarden's November Hello support note](https://bitwarden.com/blog/use-windows-hello-or-apple-touch-id-to-log-into-bitwarden/) support recent Hello with Chromium. Reports for 24H2/25H2 with Feb 2026 update or later vary for `create()` vs `get()`; do not rely on older Windows or mistake an external key/Edge password manager for Hello. |
| YubiKey 5 series | **Yes with supported FIDO2 credential, firmware, UV/PIN and browser transport.** [Yubico's PRF guide](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html) describes assertion-time `hmac-secret`; [firmware guide](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Pseudo-Random_Function_PRF_Support.html) distinguishes newer 5.8 creation-time support. Use `get()` regardless. U2F-only mode is insufficient. |
| Security Key NFC series | **Yes on documented FIDO2 units; NFC end-to-end is conditional.** [Device info from a 5.4.3 Security Key NFC](https://github.com/Yubico/yubikey-manager/issues/594) lists `hmac-secret`. Test actual model/firmware over USB and separately on phone/NFC. [Safari 26.4](https://webkit.org/blog/17862/webkit-features-for-safari-26-4/) added roaming-key PRF; [interop issue 311099](https://bugs.webkit.org/show_bug.cgi?id=311099) documents mismatching results and a preview fix. Platform-key success is no proof for roaming keys. |

## Owner decisions (2026-11-21, as they stand under format 2)

1. **Any single enabled passkey opens what it holds** — Apple, a password-manager passkey or a
   hardware authenticator; no two-person or two-device rule. A passkey holds scope keys only if
   its provider returns a stable PRF result (tested when enabled, shown under Security); a passkey
   without PRF still signs in and approves. Recovery: a dedicated offline recovery key held by
   the owner, proven by a drill before activation.
2. **Approving through the Cloudflare-served page is acceptable**, with the per-attempt
   encryption above. An off-edge origin is optional later work.
3. **Accepted exceptions:** the agent-API TLS leaf key stays a protected service-readable file,
   the restart-alert publisher keeps its own ntfy credential, and the approval-notice topic
   stays unsealed (BUCKETS.md §9).
4. **Batches and approval windows** are both built. Windows are on by default for the owner's
   own organisation with conservative defaults (configurable under Security); client and club
   organisations default to off.
5. *Superseded:* the combined unlock + window tap. A window-open tap opens what the window
   needs; there is nothing else to unlock.
