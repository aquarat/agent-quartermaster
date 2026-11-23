// Seal format 2 flows end to end against the sealed mock: an approval tap opens exactly the
// buckets its card lists, the KEK packet is sent only when the passkey returned PRF results,
// and seal control (close all, reopen, rekey) binds what it names.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createApi, type Api } from "../src/api";
import { canonicalJSON } from "../src/buckets";
import { completeAction, completeLogin, prepareAction, prepareLogin, targetForPending } from "../src/flows";
import { envReview, type EnvState } from "../src/envsets";
import { beginControl, prepareControl, type SealView } from "../src/sealPanel";
import { startMock } from "../mock/server";
import { MockBuckets } from "../mock/buckets";
import { fakeAuth, jarFetch, prfAuth, rnd, type Sent } from "./helpers";
import { encode } from "../src/b64url";

describe("approvals open their buckets (sealed mock)", () => {
  const m = startMock({ port: 0, distDir: null, vault: true });
  const log: Sent[] = [];
  const api = createApi({ base: m.url, fetch: jarFetch(log) });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  const rp = new URL(m.url).hostname;
  const last = (suffix: string) => log.filter((x) => x.url.endsWith(suffix)).at(-1)!.body as Record<string, unknown>;
  const statusOf = async (kind: string) => (await api.sealStatus!()).buckets!.find((b) => b.kind === kind)!;
  beforeAll(async () => {
    await completeLogin(api, auth, await prepareLogin(api));
  });
  afterAll(() => m.stop());

  test("the status lists buckets, holds, paused users and per-passkey coverage", async () => {
    const v = await api.sealStatus!();
    expect(v.mode).toBe("buckets");
    expect(v.scopes!.map((s) => s.title)).toEqual(["Installation", "Personal", "Client A", "Club"]);
    expect(v.scopes!.find((s) => s.title === "Club")!.has_key).toBe(false);
    expect((await statusOf("ssh-ca")).holds[0]!.kind).toBe("standing");
    expect((await statusOf("cf-proxy")).paused.length).toBe(1);
    const me = v.passkeys!.find((p) => p.current)!;
    expect(me).toMatchObject({ prf: true, missing: [], of: v.buckets!.length });
    expect(v.passkeys!.some((p) => p.missing.length > 0)).toBe(true); // the seeded approve-only one
  });

  test("approve SSH: the card names the bucket and hold; the KEK packet rides next to the assertion", async () => {
    await fetch(m.url + "/mock/vault?closed=1");
    const item = (await api.state()).pending!.find((p) => p.id === "01JDEMO0SSH0DB1XXX0000001")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 900, standing_hours: 4 });
    expect(prep.open!.lines).toEqual([expect.stringMatching(/^Opens SSH user CA: while the standing rule lasts, until \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC$/)]);
    expect(prep.open!.canOpen).toContain(auth.id);
    const packets = m.store.buckets.packets.length;
    await completeAction(api, auth, prep);
    const body = last(`/requests/${item.id}/decide`);
    expect(Object.keys(body).sort()).toEqual(["assertion", "challenge_id", "open"]);
    expect(Object.keys(body.open as object).sort()).toEqual(["attempt_id", "ciphertext", "enc"]);
    expect(JSON.stringify(body.assertion)).not.toContain("prf");
    expect(m.store.buckets.packets.length).toBe(packets + 1);
    const ssh = await statusOf("ssh-ca");
    expect(ssh.open).toBe(true);
    expect(ssh.holds.map((h) => h.kind)).toEqual(["standing"]);
  });

  test("a passkey without PRF sends no open: refused while closed, fine while open", async () => {
    const other = fakeAuth(m.url);
    await fetch(m.url + "/mock/vault?closed=1");
    const enroll = (await api.state()).pending!.find((p) => p.kind === "enrollment")!;
    const prep = await prepareAction(api, targetForPending(enroll), { action: "approve" });
    expect(prep.open!.lines).toEqual(["Opens Internal CA: for this action only"]);
    await expect(completeAction(api, other, prep)).rejects.toThrow(/closed/);
    expect(Object.keys(last(`/enrollments/${enroll.id}/decide`)).sort()).toEqual(["assertion", "challenge_id"]);
    expect(m.store.applied.some((a) => a.canonical.id === enroll.id)).toBe(false);
    // Instant hold: approved with the PRF passkey, the CA is not kept open afterwards.
    await completeAction(api, auth, await prepareAction(api, targetForPending(enroll), { action: "approve" }));
    expect((await statusOf("internal-ca")).open).toBe(false);
  });

  test("deny opens nothing: no descriptor, no packet", async () => {
    const item = (await api.state()).pending!.find((p) => p.kind === "ssh")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "deny" });
    expect(prep.open).toBeUndefined();
    await completeAction(api, auth, prep);
    expect(Object.keys(last(`/requests/${item.id}/decide`)).sort()).toEqual(["assertion", "challenge_id"]);
  });

  test("a deny that comes back with a descriptor is refused before signing", async () => {
    const item = (await api.state()).pending!.find((p) => p.kind === "cloudflare")!;
    const lying: Api = {
      ...api,
      challenge: async (o, id, b) => api.challenge(o, id, { ...b, action: "approve", ttl_seconds: 900 }).then((r) => ({ ...r, canonical: r.canonical })),
    };
    await expect(prepareAction(lying, targetForPending(item), { action: "deny" })).rejects.toThrow(/Not signing/);
  });

  test("seal control: close all is a plain signature; reopen opens only the chosen buckets", async () => {
    let v = await api.sealStatus!();
    const close = await beginControl(api, v, "close-all", {}, rp);
    expect(close.lines).toEqual([]);
    await close.finish(auth);
    v = await api.sealStatus!();
    expect(v.buckets!.every((b) => !b.open)).toBe(true);
    const paused = v.buckets!.filter((b) => b.paused.length).map((b) => b.id).sort();
    expect(paused.length).toBeGreaterThan(0);
    // A broker that would open more than chosen is refused.
    const extra = v.buckets!.find((b) => !paused.includes(b.id))!.id;
    const sneaky: Api = { ...api, sealPost: async <T,>(p: Parameters<NonNullable<Api["sealPost"]>>[0], b: unknown) => api.sealPost!<T>(p, p === "control/challenge" ? { ...(b as object), buckets: [...paused, extra] } : b) };
    await expect(beginControl(sneaky, v, "reopen", { buckets: paused }, rp)).rejects.toThrow(/did not choose/);
    const reopen = await beginControl(api, v, "reopen", { buckets: paused }, rp);
    expect(reopen.lines.length).toBe(paused.length);
    await reopen.finish(auth);
    expect(last("/control/finish").open).toBeDefined();
    v = await api.sealStatus!();
    for (const id of paused) expect(v.buckets!.find((b) => b.id === id)!).toMatchObject({ open: true, paused: [] });
  });

  test("rekey names its scope; renew-leaf and activate refuse when not offered", async () => {
    const v = await api.sealStatus!();
    const scope = v.scopes!.find((s) => s.title === "Client A")!.scope;
    await expect(beginControl(api, v, "rekey", {}, rp)).rejects.toThrow(/Choose a scope/);
    const r = await beginControl(api, v, "rekey", { scope }, rp);
    expect(r.facts.some(([k, x]) => k === "scope" && x === scope)).toBe(true);
    await r.finish(auth);
    const after = await api.sealStatus!();
    expect(after.passkeys!.filter((p) => !p.missing.includes(scope)).length).toBe(1); // only the tapping passkey keeps a wrap
    await expect(beginControl(api, v, "renew-leaf", {}, rp)).rejects.toThrow(/repair/i);
    await expect(beginControl(api, v, "activate", {}, rp)).rejects.toThrow(/manifest/);
  });
});

// ---- env approve against a standalone MockBuckets ----

function harness() {
  const issued = new Map<string, { text: string; canonical: Record<string, unknown>; challenge: string }>();
  const deps = {
    passkeys: () => [] as { id: string; hex: string; name: string }[],
    sessionPasskey: () => undefined,
    issue: (text: string, canonical: Record<string, unknown>, _s: string | undefined, challenge: Buffer) => {
      const id = encode(rnd(8));
      issued.set(id, { text, canonical, challenge: challenge.toString("base64url") });
      return { id, challenge: challenge.toString("base64url") };
    },
    redeem: (id: unknown) => issued.get(id as string)!.canonical,
    requestOptions: (_r: Request, challenge: string) => ({ publicKey: { challenge, rpId: "aqmas.example.com", userVerification: "required", allowCredentials: [] as unknown[] } as Record<string, unknown> }),
    fail: (s: number, c: string, msg: string): never => {
      throw Object.assign(new Error(msg), { status: s, code: c });
    },
    audit: () => {},
  };
  const b = new MockBuckets(deps, encode(rnd(32)), encode(rnd(32)));
  return { b, deps };
}

describe("env release approve opens the set's bucket", () => {
  test("approve carries the descriptor and the packet; commit refuses one", async () => {
    const auth = prfAuth("https://aqmas.example.com");
    const { b, deps } = harness();
    deps.passkeys = () => [{ id: auth.id, hex: "00", name: "k" }];
    b.scopes = [{ scope: "org-1", title: "Org 1", has_key: true }];
    b.buckets = [{ id: encode(rnd(32)), kind: "env", label: "client-a/paas/staging", scope: "org-1", open: false, holds: [], paused: [] }];
    b.enableAll(auth.id);
    deps.requestOptions = (_r, challenge) => ({ publicKey: { challenge, rpId: "aqmas.example.com", userVerification: "required", allowCredentials: [{ type: "public-key", id: auth.id }] } });
    const v = { mode: "buckets", installation: b.installation, epoch: b.epoch } as SealView;
    const binding = { path: "client-a/paas/staging", title: "Staging", org: "o", service: "s", set: "x", revision: 3, service_revision: 1, policy_revision: 1, admission_generation: 1, enrollment: "e", host: "web-1", class: "fleet", names: ["A"], default_seconds: 600, soft_cap_seconds: 3600, offers_indefinite: false };
    const release = { ...binding, id: "01REL", grant_id: "", mode: "process", address: "192.0.2.10", reason: "deploy", ttl_seconds: 600, deadline: 1, not_after: 0, status: "pending", consumed: false };
    const sent: { path: string; body: Record<string, unknown> }[] = [];
    const api = {
      envPost: async (path: string, body: Record<string, unknown>) => {
        sent.push({ path, body });
        if (path === "finish") return (await b.finish(body, undefined)).canonical;
        const metadata = JSON.stringify({ ...release, reason: "" }, Object.keys(release));
        const canonical = { action: body.action, epoch: v.epoch, id: release.id, installation: v.installation, issued_at: "2026-11-23T10:00:00Z", metadata, nonce: encode(rnd(32)), object: "env", ttl_seconds: body.ttl_seconds, v: 3 };
        const text = canonicalJSON(canonical);
        if (body.action === "approve") return b.bucketOffer(new Request("https://aqmas.example.com/"), text, canonical, undefined, { buckets: [{ id: b.buckets[0]!.id, hold: "env", until: "2026-11-23T10:10:00Z" }] });
        // A broker that adds a descriptor to anything else is refused.
        return b.bucketOffer(new Request("https://aqmas.example.com/"), text, canonical, undefined, { buckets: [{ id: b.buckets[0]!.id, hold: "instant", until: "" }] });
      },
    } as unknown as Api;
    const p = await envReview(api, v, release, "approve", 600, "aqmas.example.com");
    expect(p.opens).toEqual(["Opens client-a/paas/staging: until the values are collected (10 minutes at most), until 2026-11-23 10:10:00 UTC"]);
    await p.tap(auth);
    expect(Object.keys(sent.at(-1)!.body).sort()).toEqual(["assertion", "challenge_id", "open"]);
    expect(b.packets.at(-1)!.purpose).toBe("approve");
    expect(b.buckets[0]!.holds.map((h) => h.kind)).toEqual(["env"]);
    await expect(envReview(api, v, release, "deny", 0, "aqmas.example.com")).rejects.toThrow(/Unexpected open/);
  });

  test("prepareControl refuses a canonical that is not in canonical form or names another installation", async () => {
    const { b } = harness();
    const v = { mode: "buckets", installation: b.installation, epoch: b.epoch } as SealView;
    const c = { action: "close-all", epoch: v.epoch, id: v.installation, issued_at: "2026-11-23T10:00:00Z", nonce: encode(rnd(32)), object: "seal-control", open_buckets: 0, v: 3 };
    const res = b.plainOffer(new Request("https://aqmas.example.com/"), canonicalJSON(c), c, undefined);
    (res.public_key.publicKey as Record<string, unknown>).allowCredentials = [{ type: "public-key", id: encode(rnd(8)) }];
    expect((await prepareControl(v, "close-all", res, "aqmas.example.com")).facts).toEqual([["open_buckets", "0"]]);
    await expect(prepareControl(v, "close-all", { ...res, canonical: JSON.stringify(c, null, 1) }, "aqmas.example.com")).rejects.toThrow(/canonical form/);
    await expect(prepareControl({ ...v, installation: encode(rnd(32)) }, "close-all", res, "aqmas.example.com")).rejects.toThrow(/differs/);
  });
});

export type { EnvState };
