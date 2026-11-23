// Routes, tabs, the vault's item model, the search index and the passkey readiness summary:
// the pure parts of the navigation.
import { describe, expect, test } from "bun:test";
import { PAGES, TABS, pageTitle, parseRoute, vaultHash } from "../src/nav";
import { buildItems, bucketItemId, filterItems, folders, matchesQuery, requesters, typeCounts, NO_FILTER, INSTALLATION } from "../src/vaultItems";
import { buildIndex, searchHits } from "../src/search";
import { readiness, readinessHeadline } from "../src/readiness";
import type { Catalogue } from "../src/catalogue";
import type { SealView } from "../src/sealPanel";
import type { VaultSet, VaultState } from "../src/vault";

describe("routes", () => {
  test("every tab has a page and parses back to it", () => {
    for (const t of TABS) {
      expect(parseRoute(t.hash).page).toBe(t.id);
      expect(PAGES[t.id].tab).toBe(t.id);
    }
    expect(PAGES.setup.tab).toBe("settings");
  });
  test("old and odd addresses", () => {
    expect(parseRoute("")).toEqual({ page: "approvals" });
    expect(parseRoute("#/")).toEqual({ page: "approvals" });
    expect(parseRoute("#/admin")).toEqual({ page: "settings" }); // the pre-tabs address
    expect(parseRoute("#/nope")).toEqual({ page: "approvals" });
    expect(parseRoute("#r=01ABC")).toEqual({ page: "approvals", focus: "01ABC" });
    expect(parseRoute("#r=<img>")).toEqual({ page: "approvals" });
    expect(parseRoute("#/setup")).toEqual({ page: "setup" });
  });
  test("vault items are addressed by id; anything else is the list", () => {
    expect(parseRoute("#/vault")).toEqual({ page: "vault" });
    expect(parseRoute("#/vault/new")).toEqual({ page: "vault", item: "new" });
    expect(parseRoute("#/vault/0123abcd")).toEqual({ page: "vault", item: "0123abcd" });
    expect(parseRoute('#/vault/"><img src=x>')).toEqual({ page: "vault" });
    expect(parseRoute("#/vault/a/b")).toEqual({ page: "vault" });
    expect(vaultHash("abc")).toBe("#/vault/abc");
    expect(vaultHash("a b")).toBe("#/vault");
    expect(vaultHash()).toBe("#/vault");
  });
  test("the title carries what is waiting on every page", () => {
    expect(pageTitle("approvals", 0)).toBe("aqmas");
    expect(pageTitle("approvals", 3)).toBe("(3) aqmas");
    expect(pageTitle("vault", 2)).toBe("(2) Vault · aqmas");
    expect(pageTitle("security", 0)).toBe("Passkeys & security · aqmas");
  });
});

const set = (org: string, svc: string, slug: string, extra: Partial<VaultSet> = {}): VaultSet => ({
  org_id: "o-" + org, org_slug: org, org_title: org.toUpperCase(), service_id: `v-${org}-${svc}`, service_slug: svc, service_title: svc, set_id: `s-${org}-${svc}-${slug}`, set_slug: slug, set_title: slug,
  kind: "env-set", revision: 3, names: ["API_TOKEN", "DB_URL"], allow_reveal: true, signatures: 0, ...extra,
});
const vault: VaultState = {
  schemes: [{ id: "ed25519", title: "Ed25519", key: "ed25519", input: "message", signed: "", output: "", check: "" }],
  organisations: [{ id: "o-personal", slug: "personal", title: "PERSONAL", allow_reveal: true }],
  sets: [set("client-a", "paas", "staging"), set("personal", "fw", "release", { kind: "signer", scheme: "ed25519", names: [], signatures: 2 })],
  requests: [],
};
const cat: Catalogue = {
  owner_id: "owner",
  organisations: [
    {
      id: "o-personal", slug: "personal", title: "PERSONAL", revision: 1, rules: [], auto_access: [], policy: {} as never,
      hosts: [{ row_id: 1, enrollment: "e1", name: "web-1", fingerprint: "", class: "agent", active: true, generation: 1 }, { row_id: 2, enrollment: "e2", name: "old", fingerprint: "", class: "agent", active: false, generation: 2 }],
      services: [
        { id: "v-personal-fw", slug: "fw", title: "fw", revision: 1, provider: "application", sets: [{ id: "s-personal-fw-release", slug: "release", title: "release", revision: 0, kind: "signer", archived: false }] },
        { id: "v-fleet", slug: "fleet", title: "Fleet", revision: 1, provider: "fleet", sets: [{ id: "s-ssh", slug: "db-1", title: "db-1", revision: 1, kind: "ssh-target", archived: false }, { id: "s-gone", slug: "gone", title: "gone", revision: 1, kind: "ssh-target", archived: true }] },
        { id: "v-cf", slug: "dns-cdn", title: "DNS", revision: 1, provider: "cloudflare", sets: [{ id: "s-cf", slug: "proxy", title: "Proxy", revision: 1, kind: "cloudflare-proxy", archived: false }] },
        { id: "v-empty", slug: "empty", title: "Empty", revision: 1, provider: "application", sets: [] },
      ],
    },
  ],
};
const bucket = (id: string, kind: string, label: string, scope: string, open = false) => ({ id, kind, label, scope, scope_title: scope === INSTALLATION ? "Installation" : scope, open, holds: [], paused: [] });
const seal: SealView = {
  mode: "buckets", installation: "i", epoch: "e",
  scopes: [{ scope: INSTALLATION, title: "Installation", buckets: 2, has_key: true }, { scope: "o-personal", title: "PERSONAL", buckets: 2, has_key: true }, { scope: "o-club", title: "Club", buckets: 0, has_key: false }],
  buckets: [bucket("AAAA", "ssh-ca", "SSH user CA", INSTALLATION, true), bucket("BBBB", "internal-ca", "Internal agent CA", INSTALLATION), bucket("CCCC", "cf-proxy", "personal/dns-cdn/proxy", "o-personal"), bucket("DDDD", "env-set", "client-a/paas/staging", "o-client-a")],
  passkeys: [
    { id: "p1", name: "Phone", current: true, prf: true, scopes: [{ scope: INSTALLATION, tested: true }, { scope: "o-personal", tested: true }], opens: 4, of: 4, missing: [] },
    { id: "p2", name: "Key", current: false, prf: false, scopes: [], opens: 0, of: 4, missing: [INSTALLATION, "o-personal"] },
    { id: "p3", name: "Manager", current: false, prf: true, scopes: [{ scope: INSTALLATION, tested: true }, { scope: "o-personal", tested: false }], opens: 4, of: 4, missing: [] },
  ],
};

describe("vault items", () => {
  const items = buildItems(vault, cat, seal);
  const by = (id: string) => items.find((i) => i.id === id)!;
  test("one item per set and per broker key, each bucket attached once", () => {
    expect(items.map((i) => i.id).sort()).toEqual(["s-cf", "s-client-a-paas-staging", "s-personal-fw-release", "s-ssh", bucketItemId("AAAA"), bucketItemId("BBBB")].sort());
    expect(by("s-client-a-paas-staging")).toMatchObject({ type: "env-set", path: "client-a/paas/staging", sub: "2 keys · revision 3" });
    expect(by("s-client-a-paas-staging").bucket!.id).toBe("DDDD");
    expect(by("s-personal-fw-release")).toMatchObject({ type: "signer", sub: "Ed25519 · 2 signatures", names: [] });
    expect(by("s-cf")).toMatchObject({ type: "cloudflare", path: "personal/dns-cdn/proxy" });
    expect(by("s-cf").bucket!.id).toBe("CCCC");
    expect(by("s-ssh")).toMatchObject({ type: "access", kind: "ssh-target" });
    expect(by(bucketItemId("AAAA"))).toMatchObject({ type: "ssh-ca", orgId: INSTALLATION });
    expect(items.some((i) => i.id === "s-gone")).toBe(false); // archived
  });
  test("without a catalogue or a seal the application sets are still listed", () => {
    expect(buildItems(vault, null, undefined).map((i) => i.id)).toEqual(["s-client-a-paas-staging", "s-personal-fw-release"]);
    expect(buildItems(undefined, undefined, undefined)).toEqual([]);
  });
  test("search matches names, paths, organisations, types and key names, every word", () => {
    const it = by("s-client-a-paas-staging");
    for (const q of ["staging", "CLIENT-A", "db_url", "env set", "paas api_token", ""]) expect(matchesQuery(it, q)).toBe(true);
    for (const q of ["release", "paas nope"]) expect(matchesQuery(it, q)).toBe(false);
  });
  test("filters and the tree", () => {
    expect(filterItems(items, { ...NO_FILTER, type: "signer" }).map((i) => i.id)).toEqual(["s-personal-fw-release"]);
    expect(filterItems(items, { ...NO_FILTER, org: INSTALLATION }).length).toBe(2);
    expect(filterItems(items, { ...NO_FILTER, org: "o-personal", service: "v-fleet" }).map((i) => i.id)).toEqual(["s-ssh"]);
    expect(filterItems(items, { ...NO_FILTER, q: "db" }).map((i) => i.id).sort()).toEqual(["s-client-a-paas-staging", "s-ssh"]);
    const tree = folders(items, cat);
    expect(tree.at(-1)!.id).toBe(INSTALLATION); // the broker's own keys come last
    const personal = tree.find((f) => f.id === "o-personal")!;
    expect(personal.count).toBe(3);
    expect(personal.services.find((s) => s.id === "v-empty")).toEqual({ id: "v-empty", title: "Empty", count: 0 }); // an empty service can still be picked
    expect(typeCounts(items).find((t) => t.type === "env-set")!.count).toBe(1);
  });
  test("who may ask: the organisation's admitted hosts", () => {
    expect(requesters(by("s-personal-fw-release"), cat)).toEqual([{ name: "web-1", class: "agent" }]);
    expect(requesters(by("s-client-a-paas-staging"), cat)).toBeUndefined(); // not in this catalogue
  });
});

describe("search", () => {
  const index = buildIndex({
    items: buildItems(vault, cat, seal),
    hosts: [{ id: "e1", name: "web-1", address: "192.0.2.21", class: "agent", enrolled_at: "", not_before: "", not_after: "", last_request_at: null, revoked_at: null }],
    passkeys: [{ id: "p1", nickname: "Phone", authenticator: "Apple Passwords" } as never],
    pending: [{ id: "01ABCDEFGH", kind: "ssh", requesting_host: "web-1", ssh: { target_host: "db-1", login_user: "alice" } } as never],
    signing: [{ id: "01SIGNREQ9", path: "personal/fw/release", host: "build-1" }],
    releases: [{ id: "01ENVREL77", path: "client-a/paas/staging", host: "build-1" }],
    canAdd: true,
    toEnable: 2,
  });
  test("no query: what waits, what to do, where to go", () => {
    const hits = searchHits(index, "");
    expect(hits[0]).toMatchObject({ group: "Waiting", href: "#r=01ABCDEFGH" });
    expect(hits.filter((x) => x.group === "Waiting").map((x) => x.href)).toEqual(["#r=01ABCDEFGH", "#r=01SIGNREQ9", "#/"]);
    expect(hits.some((x) => x.title === "Add a credential" && x.href === "#/vault/new")).toBe(true);
    expect(hits.some((x) => x.group === "Vault")).toBe(false);
    expect(hits.filter((x) => x.group === "Go to").map((x) => x.href)).toEqual(TABS.map((t) => t.hash));
  });
  test("finds items by key name, hosts, passkeys and actions", () => {
    expect(searchHits(index, "api_token")[0]).toMatchObject({ group: "Vault", href: "#/vault/s-client-a-paas-staging" });
    expect(searchHits(index, "web-1").map((x) => x.group)).toEqual(expect.arrayContaining(["Waiting", "Hosts"]));
    expect(searchHits(index, "phone")[0]).toMatchObject({ group: "Passkeys", href: "#/security" });
    expect(searchHits(index, "enable passkey")[0]).toMatchObject({ group: "Do", href: "#/security" });
    expect(searchHits(index, "zzz")).toEqual([]);
  });
  test("the enable action is offered only while a passkey opens too little", () => {
    const none = buildIndex({ items: [], hosts: [], passkeys: [], pending: [], signing: [], releases: [], canAdd: false, toEnable: 0 });
    expect(searchHits(none, "enable passkey").some((x) => x.title.startsWith("Enable passkeys"))).toBe(false);
    expect(searchHits(none, "credential").some((x) => x.title === "Add a credential")).toBe(false);
  });
});

describe("passkey readiness", () => {
  test("counts tested wraps of every keyed scope; `prf` false is still offered Enable", () => {
    const r = readiness(seal)!;
    expect(r.keyed).toEqual([INSTALLATION, "o-personal"]); // a scope without a key is not counted
    expect(r.ready.map((p) => p.id)).toEqual(["p1"]);
    expect(r.fixable).toEqual([
      { passkey: seal.passkeys![1]!, todo: [INSTALLATION, "o-personal"] }, // no wrap yet (the status says prf: false)
      { passkey: seal.passkeys![2]!, todo: ["o-personal"] }, // an untested wrap does not count
    ]);
    expect(r.opener!.id).toBe("p1");
    expect(readinessHeadline(r)).toBe("1 of 3 passkeys can open your credentials.");
  });
  test("all ready, one passkey, and stores that are not serving", () => {
    const all: SealView = { ...seal, passkeys: [seal.passkeys![0]!, { ...seal.passkeys![0]!, id: "p9", current: false }] };
    expect(readinessHeadline(readiness(all)!)).toBe("All 2 passkeys can open your credentials.");
    expect(readinessHeadline(readiness({ ...seal, passkeys: [seal.passkeys![0]!] })!)).toBe("Your passkey can open your credentials.");
    expect(readiness({ ...seal, mode: "migration-required" })).toBeUndefined();
    expect(readiness(undefined)).toBeUndefined();
    expect(readiness({ ...seal, passkeys: [{ ...seal.passkeys![0]!, current: false }, seal.passkeys![1]!] })!.opener).toBeUndefined();
  });
});
