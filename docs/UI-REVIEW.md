# UI review: credentials and navigation (2026-11-23)

Reviewed at v0.5.0 by walking every page as the owner would, against a local broker with mock
data and a virtual authenticator, at 375 px and 1280 px. This records what was found and what
was built on `feat/ui-vault-nav`. No protocol changed: every state change is the same canonical
text, checked the same way, signed by the same passkey tap.

## What was wrong

**Two pages held everything.** The queue page was 12,300 px tall on a phone (8,200 px wide):
signature requests, access requests, join requests, active access, auto-approvals and the
whole audit log. Admin was 11,700 px: Setup, Buckets, Organisations, Credential sets, Passkeys,
Recovery and Hosts in one scroll, behind a gear icon with no label. An "Env credential sets"
panel of ticket buttons sat above *every* page.

**Managing a credential:**

1. Finding one meant three dependent drop-downs (organisation → service → set). No list, no
   search, nothing that showed all sets at once; the first set of the first service was
   selected whether wanted or not.
2. Creating one was spread over three places: "Missing something?" disclosures under the
   drop-downs, a second set of create forms under Organisations (unlabelled slug and name
   boxes, no validation message), and "New signing key" at the bottom. A new organisation
   also needed its key created under Buckets → Create, which nothing pointed to.
3. Slug and name were typed separately, with no hint that the slug becomes the path agents use.
4. The same set appeared four times on Admin (Buckets, Organisations, Credential sets, the env
   ticket panel) with a different subset of facts each time. Nothing said who may ask for it
   or when it was last used.
5. What the broker holds itself (the SSH CA, the Cloudflare parent credential) was visible only
   as rows in Buckets.

**Passkeys.** After the move to buckets only the migrating passkey opens anything. The fix was
there (Passkeys → Enable, per passkey, below the tiles) but nothing said "one of your four
passkeys can open your credentials"; the tile badge read "Approve only". (0.5.1 fixed the
hidden Enable button and the badge; the missing summary is fixed here.)

**Common things were far away.** "N buckets open" in the header linked to the top of Admin, not
to Buckets, and Close all was at the bottom of that panel. On Admin, Help and Setup nothing
said a request was waiting. Policy fields were raw JSON key names.

## What was built

Seven tabs (a row in the header on a wide screen, a bar along the bottom on a phone):

| Tab | Holds | Why its own tab |
|---|---|---|
| **Approvals** | what waits (signatures, env releases, access, join requests), active access, auto-approvals | the daily page; nothing else competes with it |
| **Vault** | every credential as a list; the selected item; Add item | the owner's request, and where most of Admin's length was |
| **Hosts** | enrolled hosts, the organisations each may ask for (Admit/Remove), Revoke | "who can ask" is one question; it was split between Organisations and Hosts |
| **Activity** | the audit log with its filters | long, and read on purpose rather than in passing |
| **Security** | passkey readiness, passkeys, buckets open now, windows, recovery key | everything about who can open what |
| **Settings** | Setup and upgrades (Setup stays its own page under it), organisation policies | rare, deliberate changes. A "Bastion access" section belongs here |
| **Help** | where things are, commands | |

`#/admin` still works (it opens Settings), as does `#r=REF` from the CLI.

**On every page:** the Approvals tab carries the number waiting (so does the window title); the
header pill "N buckets open" opens a tray with what is open, what waits and **Close all**; a
search (`/` or Ctrl+K) finds vault items by name, path or key name, hosts, passkeys, waiting
requests by Ref, pages and actions.

**Vault**, in the manner of a password manager:

* left, filters: All items, by type (env sets, signing keys, Cloudflare, CAs, access rules), by
  organisation → service; on a phone these are a row of chips;
* middle, the items with a type icon, where they live, key count and revision, and Open/Paused
  when their bucket is; a search box over names, paths and key names;
* right, the item: the existing write-only editor (per key: Reveal, Replace, Remove; .env
  import; Review and save) or the signer card, then *Use it on a host*, *Who may ask for it*
  (the organisation's admitted hosts), *Activity* (last changed, last delivered or signed, the
  recent rows), and under *More* the reveal policy and CLI tickets. On a phone the item
  replaces the list, with a way back; the address (`#/vault/ID`) keeps the selection across
  reload and Back;
* **Add item**: a type (env set or signing key), a place and a name. The slug is suggested from
  the name and the resulting path is shown. A missing organisation, its encryption key and a
  missing service are created in order, one approval each, and the form moves on by itself.

Reveal is unchanged: a value appears only after a passkey tap for exactly those keys, for 60
seconds, and is dropped on Hide, on leaving the item or the tab, and on pagehide. Nothing in
the list, the search or the history fetches a value.

**Security** opens with "2 of 4 passkeys can open your credentials", each passkey's state, and
**Enable the other N…**: one passkey after the other, each the existing enable-then-test steps
with their signed text shown, with Skip for one that is not at hand. A mark on the Security
tab, a line in the tray and in the Vault say the same while it is true.

**Server addition (read-only):** `GET /api/ui/seal/vault/history?set=ID`, the item's recent
audit rows with last change and last use ([API.md](API.md#vault-web-form-reveal-and-signer-sets)).

## Not built, for the owner to decide

* **Rename, move and delete of an item.** The catalogue has only `create`. Deleting a set means
  archiving it, ending its releases and grants and deciding what happens to its bucket and to
  a reused slug; renaming a slug changes the path agents use. These are protocol additions
  with their own canonical cards, not layout. Until then: remove a set's keys (it then
  delivers nothing).
* **Copy without showing.** A "copy this value" that never renders it needs the clipboard write
  to happen after the passkey prompt, which Safari may refuse. Copy sits next to each
  revealed value instead.
* **Last used in the list** (it is in the item) would need the history for every set per poll.
* **History is read from the audit log** by scanning it for the set (every 30 s while an item is
  open). Fine at today's size; a set column on audit rows, or an index, when the log grows.
* The seven-tab bottom bar is tight at 375 px; five tabs with Hosts and Settings under "More"
  is the alternative.
* `web/screenshots/*.png` in the repository still show the old layout (`capture.ts` is updated;
  the pictures were left alone to keep this change free of binaries).
