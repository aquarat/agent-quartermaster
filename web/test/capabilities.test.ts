// Passkey enable/test/disable/register and the Admin recovery drill/enrol (docs/BUCKETS.md §7)
// against the mock: the loop's rounds and taps, `open` only with PRF, the last-passkey guard,
// and the recovery identity leaving the page only sealed.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi, type Api } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { prfAuth, jarFetch, type PrfAuth, type Sent } from "./helpers";
import { startCapability, type Intent, type Step } from "../src/capabilities";
import { beginRecovery } from "../src/recoveryPanel";
import { generateAgeIdentity } from "../src/setup";
import type { SealView } from "../src/sealPanel";
import type { PasskeyInfo } from "../src/types";

type Mock = ReturnType<typeof startMock>;
const rawOf = (b64: string) => new Uint8Array(Buffer.from(b64, "base64url"));

async function as(m: Mock, auth: PrfAuth) {
  const log: Sent[] = [];
  const api = createApi({ base: m.url, fetch: jarFetch(log) });
  await completeLogin(api, auth, await prepareLogin(api));
  return { api, log };
}

/** Run a step chain, choosing the authenticator per step; returns the taps made. */
async function run(first: Step, pick: (s: Step) => PrfAuth): Promise<Step[]> {
  const seen: Step[] = [];
  let s: Step | void = first;
  while (s) {
    seen.push(s);
    s = await s.tap(pick(s));
  }
  return seen;
}

describe("passkeys and scopes", () => {
  let m: Mock;
  let rp: string;
  let me: PrfAuth, bw: PrfAuth, yk: PrfAuth;
  let api: Api, log: Sent[];
  const status = () => api.sealStatus!();
  const pk = async (cred: string) => {
    const v = await status();
    const hex = m.store.passkeys.find((p) => p.id === cred)!.info.id;
    return v.passkeys!.find((p) => p.id === hex)!;
  };
  const intent = (i: Partial<Intent> & Pick<Intent, "action" | "credential_id" | "scopes">): Intent => ({ capability: "unlock", nickname: m.store.passkeys.find((p) => p.id === i.credential_id)?.info.nickname ?? "", ...i });
  const target = (s: Step) => (s.progress?.includes("signed-in") ? me : s.title.startsWith("Create the new") ? fresh : yk);
  let fresh: PrfAuth;

  beforeAll(async () => {
    m = startMock({ port: 0, distDir: null, vault: true });
    rp = new URL(m.url).hostname;
    me = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[0]!.id) });
    bw = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[1]!.id), prf: false });
    yk = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[2]!.id) });
    ({ api, log } = await as(m, me));
  });
  afterAll(() => m.stop());

  test("the seed: the last passkey opens nothing; club has no key", async () => {
    const v = await status();
    expect(v.scopes!.filter((s) => s.has_key).length).toBe(3);
    expect(v.scopes!.find((s) => s.title === "Club")!.has_key).toBe(false);
    const y = await pk(yk.id);
    expect(y.opens).toBe(0);
    expect(y.missing.length).toBe(3);
  });

  test("an authorising passkey without PRF sends no open; the enrolment is then refused", async () => {
    const other = await as(m, bw);
    const v = await other.api.sealStatus!();
    const first = await startCapability(other.api, v, intent({ action: "enable", credential_id: yk.id, scopes: ["installation"] }), rp);
    await expect(first.tap(bw)).rejects.toThrow(/no passkey opened/);
    const auth = other.log.find((x) => x.url.endsWith("/passkeys/authorize"))!.body as Record<string, unknown>;
    expect(auth.assertion).toBeDefined();
    expect("open" in auth).toBe(false);
  });

  test("enable three scopes: two rounds of two taps, open sent with PRF, results untested", async () => {
    const v = await status();
    const y = await pk(yk.id);
    log.length = 0;
    const steps = await run(await startCapability(api, v, intent({ action: "enable", credential_id: yk.id, scopes: y.missing }), rp), target);
    expect(steps.map((s) => s.progress)).toEqual([
      "Round 1 of 2 · tap 1 of 2: your signed-in passkey approves and opens the scope keys",
      "Round 1 of 2 · tap 2 of 2: the passkey being enabled taps",
      "Round 2 of 2 · tap 1 of 2: your signed-in passkey approves and opens the scope keys",
      "Round 2 of 2 · tap 2 of 2: the passkey being enabled taps",
    ]);
    expect(steps[0]!.lines.join(" ")).toMatch(/Opens the scope key/);
    const posts = log.filter((x) => /passkeys\/(authorize|finish)$/.test(x.url));
    expect(posts.length).toBe(4);
    for (const p of posts) expect(Object.keys((p.body as { open: object }).open).sort()).toEqual(["attempt_id", "ciphertext", "enc"]);
    // Nothing PRF-shaped in the assertion; every PRF output was wiped.
    expect(JSON.stringify(posts.map((p) => (p.body as { assertion: unknown }).assertion))).not.toContain("prf");
    for (const b of [...me.handed, ...yk.handed]) expect(b.every((x) => x === 0)).toBe(true);
    const after = await pk(yk.id);
    expect(after.missing).toEqual([]);
    expect(after.opens).toBe(after.of);
    expect(after.scopes.every((s) => !s.tested)).toBe(true);
  });

  test("test marks the wraps tested, one tap per two scopes by the target", async () => {
    const y = await pk(yk.id);
    const steps = await run(await startCapability(api, await status(), intent({ action: "test", credential_id: yk.id, scopes: y.scopes.map((s) => s.scope) }), rp), () => yk);
    expect(steps.length).toBe(2);
    expect(steps[0]!.progress).toBe("Round 1 of 2 · tap 1 of 1: " + m.store.passkeys[2]!.info.nickname + " taps");
    expect((await pk(yk.id)).scopes.every((s) => s.tested)).toBe(true);
  });

  test("create the club scope key with the signed-in passkey; disabling the last holder is refused", async () => {
    const v = await status();
    const club = v.scopes!.find((s) => s.title === "Club")!.scope;
    const steps = await run(await startCapability(api, v, intent({ action: "enable", credential_id: me.id, scopes: [club] }), rp), () => me);
    expect(steps.length).toBe(2);
    expect(steps[0]!.lines.some((l) => l.startsWith("Opens"))).toBe(false); // no key yet: nothing to open
    const after = await status();
    expect(after.scopes!.find((s) => s.scope === club)!.has_key).toBe(true);
    expect((await pk(me.id)).scopes.some((s) => s.scope === club)).toBe(true);
    const d = await startCapability(api, after, intent({ action: "disable", capability: "approve-only", credential_id: me.id, scopes: [club] }), rp);
    await expect(d.tap(me)).rejects.toThrow(/last passkey/);
  });

  test("register a new passkey for every keyed scope: create, then enrol, then a second round", async () => {
    const v = await status();
    fresh = prfAuth(m.url);
    const keyed = v.scopes!.filter((s) => s.has_key).map((s) => s.scope);
    const steps = await run(await startCapability(api, v, { action: "register", capability: "unlock", nickname: "Spare key", credential_id: "", scopes: keyed }, rp), (s) =>
      s.progress?.includes("signed-in") ? me : fresh,
    );
    expect(steps.map((s) => s.progress)).toEqual([
      "Round 1 of 2 · tap 1 of 3: your signed-in passkey approves and opens the scope keys",
      "Round 1 of 2 · tap 2 of 3: create the new passkey",
      "Round 1 of 2 · tap 3 of 3: the passkey being enabled taps",
      "Round 2 of 2 · tap 1 of 2: your signed-in passkey approves and opens the scope keys",
      "Round 2 of 2 · tap 2 of 2: the passkey being enabled taps",
    ]);
    expect(fresh.creates[0]!.extensions).toMatchObject({ prf: {} });
    const p = m.store.passkeys.find((x) => x.id === fresh.id)!;
    expect(p.info.nickname).toBe("Spare key");
    expect((await pk(fresh.id)).missing).toEqual([]);
  });

  test("an approve-only passkey: two taps, no enrolment", async () => {
    const extra = prfAuth(m.url, { prf: false });
    const steps = await run(await startCapability(api, await status(), { action: "register", capability: "approve-only", nickname: "Hardware", credential_id: "", scopes: [] }, rp), (s) => (s.progress?.includes("signed-in") ? me : extra));
    expect(steps.length).toBe(2);
    expect((await pk(extra.id)).opens).toBe(0);
  });

  test("disable removes the wraps when another passkey still opens the scopes", async () => {
    const y = await pk(yk.id);
    await run(await startCapability(api, await status(), intent({ action: "disable", capability: "approve-only", credential_id: yk.id, scopes: y.scopes.map((s) => s.scope) }), rp), () => me);
    expect((await pk(yk.id)).opens).toBe(0);
  });

  test("a server that changes the scopes or the target is refused before any tap", async () => {
    const v = await status();
    for (const edit of [(c: Record<string, unknown>) => (c.scopes = ["installation"]), (c: Record<string, unknown>) => (c.credential_id = me.id), (c: Record<string, unknown>) => (c.capability = "approve-only")]) {
      const lying: Api = {
        ...api,
        sealPost: async <T>(path: Parameters<NonNullable<Api["sealPost"]>>[0], body: unknown) => {
          const r = await api.sealPost!<{ canonical: string }>(path, body);
          if (path === "passkeys/challenge") {
            const c = JSON.parse(r.canonical);
            edit(c);
            r.canonical = JSON.stringify(c, Object.keys(c).sort());
          }
          return r as T;
        },
      };
      const gets = yk.gets.length + me.gets.length;
      await expect(startCapability(lying, v, intent({ action: "enable", credential_id: yk.id, scopes: v.scopes!.filter((s) => s.has_key).slice(1, 3).map((s) => s.scope) }), rp)).rejects.toThrow();
      expect(yk.gets.length + me.gets.length).toBe(gets);
    }
  });

  test("recovery drill and enrol: the identity travels sealed; only the key's own shape passes", async () => {
    const v = await status();
    const k = await generateAgeIdentity();
    await expect(beginRecovery(api, v, { mode: "drill" }, "not a key", rp)).rejects.toThrow(/not a recovery key/);
    log.length = 0;
    const drill = await beginRecovery(api, v, { mode: "drill" }, k.identity, rp);
    expect(drill.lines).toEqual([]);
    const res = await drill.finish(me);
    expect(res).toMatchObject({ ok: true, scopes: 4 });
    expect(JSON.stringify(log.map((x) => x.body))).not.toContain(k.identity);
    const ch = log.find((x) => x.url.endsWith("/recovery/challenge"))!.body as { packet_sha256: string };
    expect(drill.canonical).toContain(ch.packet_sha256);
    const enrol = await beginRecovery(api, v, { mode: "enrol", credential_id: yk.id, scopes: ["installation"] }, k.identity, rp);
    expect(enrol.lines.join(" ")).toMatch(/installation/);
    expect(await enrol.finish(yk)).toMatchObject({ ok: true, scopes: 1 });
    expect((await pk(yk.id)).scopes.map((s) => s.scope)).toEqual(["installation"]);
    // A passkey without PRF cannot be enrolled.
    const no = await beginRecovery(api, v, { mode: "enrol", credential_id: bw.id, scopes: ["installation"] }, k.identity, rp);
    await expect(no.finish(bw)).rejects.toThrow(/PRF/);
  });
});

describe("recovery panel in a DOM", () => {
  const m = startMock({ port: 0, distDir: null, vault: true });
  const win = new Window({ url: m.url + "/" });
  const G = globalThis as Record<string, unknown>;
  const saved: Record<string, unknown> = {};
  const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "Event", "navigator"];
  let api: Api, me: PrfAuth, v: SealView, pks: PasskeyInfo[];
  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    me = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[0]!.id) });
    api = createApi({ base: m.url, fetch: jarFetch() });
    await completeLogin(api, me, await prepareLogin(api));
    v = await api.sealStatus!();
    pks = (await api.state()).passkeys!;
  });
  afterAll(() => {
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });
  async function until(cond: () => boolean, ms = 3000) {
    const t0 = Date.now();
    while (!cond()) {
      if (Date.now() - t0 > ms) throw new Error("timed out");
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  test("the key is cleared at once, the drill runs from the tap, and the panel warns", async () => {
    const { recoveryPanel } = await import("../src/recoveryPanel");
    const el = recoveryPanel(api, me, v, pks, () => {});
    (win.document.body as unknown as HTMLElement).append(el);
    expect(el.textContent).toContain("routine way");
    const ta = el.querySelector("textarea") as HTMLTextAreaElement;
    ta.value = (await generateAgeIdentity()).identity;
    [...el.querySelectorAll("button")].find((b) => b.textContent === "Review…")!.click();
    expect(ta.value).toBe("");
    await until(() => [...el.querySelectorAll("button")].some((b) => b.textContent === "Run the drill with passkey"));
    [...el.querySelectorAll("button")].find((b) => b.textContent === "Run the drill with passkey")!.click();
    await until(() => (el.textContent ?? "").includes("Drill passed"));
    expect(el.textContent).toContain("Drill passed: 3 scopes");
  });

  test("Passkeys panel: what each passkey opens and the actions it offers", async () => {
    const { capabilityForm } = await import("../src/capabilities");
    const el = capabilityForm(api, me, v, pks, () => {});
    const rows = [...el.querySelectorAll("[data-passkey]")];
    expect(rows.length).toBe(3);
    expect(rows[0]!.textContent).toContain(`Opens ${v.passkeys![0]!.of} of ${v.passkeys![0]!.of} buckets`);
    expect(rows[2]!.textContent).toContain(`Opens 0 of ${v.passkeys![0]!.of} buckets`);
    expect(rows[2]!.textContent).toContain("Not enabled for Installation");
    expect([...rows[2]!.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Enable…"]);
    expect([...rows[0]!.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Test…", "Disable…"]);
    expect(el.textContent).not.toMatch(/unlock/i);
  });
});
