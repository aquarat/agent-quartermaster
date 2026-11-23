// Remembered browsers (docs/BUCKETS.md §13) against the mock: a passkey without PRF is
// enabled from the existing Enable flow, opens a bucket from the remembered browser, rekeys,
// loses its key (cleared storage) and is forgotten. The PRF path stays as it was. The browser
// key itself is checked against the broker's vectors (test/vectors/browserkey.json).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi, type Api } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { prfAuth, jarFetch, type PrfAuth, type Sent } from "./helpers";
import { capabilityForm, checkCapability, howItOpens, rememberOffer, startCapability, type BrowserContext, type Intent, type Step } from "../src/capabilities";
import { BrowserKeys, BrowserKeyError, browserKeyId, defaultLabel, memoryStore, normalizeLabel, NOT_REMEMBERED, NO_STORAGE, TRADE_OFF, type BrowserKeyStore, type LocalBrowserKey } from "../src/browserKey";
import { browserKekInfo, browserPath, canonicalJSON, parseDescriptor, prepareTap } from "../src/buckets";
import { beginControl } from "../src/sealPanel";
import { readiness, readinessPanel } from "../src/readiness";
import { encode } from "../src/b64url";
import { encodeAssertion } from "../src/webauthn";
import vector from "../../test/vectors/browserkey.json";

type Mock = ReturnType<typeof startMock>;
const rawOf = (b64: string) => new Uint8Array(Buffer.from(b64, "base64url"));
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

describe("the browser key", () => {
  test("opens a KEK the broker sealed; info and fingerprint match the broker's", async () => {
    const pub = unhex(vector.BrowserPub);
    const jwk = { kty: "EC", crv: "P-256", x: encode(pub.subarray(1, 33)), y: encode(pub.subarray(33)), d: encode(unhex(vector.BrowserPriv)) };
    const { d: _d, ...pubJwk } = jwk;
    const pair = {
      privateKey: await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
      publicKey: await crypto.subtle.importKey("jwk", pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []),
    } as CryptoKeyPair;
    const key: LocalBrowserKey = { pair, publicKey: pub, public: encode(pub), id: await browserKeyId(pub) };
    expect(key.id).toBe(vector.KeyID);
    const info = browserKekInfo(unhex(vector.Installation), vector.RPID, unhex(vector.Cred), vector.Scope, unhex(vector.WrapID), pub);
    expect(Buffer.from(info).toString("hex")).toBe(vector.KEKInfo);
    const keys = new BrowserKeys(memoryStore());
    expect(Buffer.from(await keys.openKEK(key, info, unhex(vector.SealedKEK))).toString("hex")).toBe(vector.KEK);
    // Another binding (here: another scope) opens nothing, in plain words.
    const other = browserKekInfo(unhex(vector.Installation), vector.RPID, unhex(vector.Cred), "org-1", unhex(vector.WrapID), pub);
    await expect(keys.openKEK(key, other, unhex(vector.SealedKEK))).rejects.toThrow(/did not open/);
  });

  test("is generated non-extractable, kept in the store, and never exportable", async () => {
    const store = memoryStore();
    const keys = new BrowserKeys(store, async () => true);
    expect(await keys.current()).toBeUndefined();
    const made = await keys.ensure();
    expect(made).toMatchObject({ created: true, persisted: true });
    expect(made.key.pair.privateKey.extractable).toBe(false);
    expect(made.key.pair.privateKey.usages).toEqual(["deriveBits"]);
    for (const f of ["pkcs8", "jwk", "raw"] as const) await expect(crypto.subtle.exportKey(f, made.key.pair.privateKey)).rejects.toThrow();
    expect(made.key.publicKey.length).toBe(65);
    expect(made.key.public).toBe(encode(made.key.publicKey));
    expect(made.key.id).toMatch(/^[0-9a-f]{32}$/);
    // The same profile keeps its key: ensure() makes no second one.
    const again = await keys.ensure();
    expect(again.created).toBe(false);
    expect(again.key.public).toBe(made.key.public);
    await keys.forget();
    expect(await keys.current()).toBeUndefined();
  });

  test("storage that refuses, drops or throws is said in plain words; a refused persist() is not an error", async () => {
    const throwing: BrowserKeyStore = { load: async () => { throw new Error("SecurityError"); }, save: async () => { throw new Error("QuotaExceededError"); }, clear: async () => { throw new Error("x"); } };
    const t = new BrowserKeys(throwing);
    expect(await t.current()).toBeUndefined(); // never throws
    await expect(t.ensure()).rejects.toThrow(NO_STORAGE);
    await t.forget(); // never throws
    // A private window that accepts the write and keeps nothing.
    const dropping: BrowserKeyStore = { load: async () => undefined, save: async () => {}, clear: async () => {} };
    await expect(new BrowserKeys(dropping).ensure()).rejects.toBeInstanceOf(BrowserKeyError);
    // navigator.storage.persist() said no, or is not there: the key is still made.
    expect((await new BrowserKeys(memoryStore(), async () => false).ensure()).persisted).toBe(false);
    expect((await new BrowserKeys(memoryStore(), async () => undefined).ensure()).persisted).toBeUndefined();
    // An extractable key planted in storage is not used.
    const planted = memoryStore();
    planted.pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    expect(await new BrowserKeys(planted).current()).toBeUndefined();
  });

  test("labels: a default from the user agent, normalised as the broker does", () => {
    expect(defaultLabel("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")).toBe("Firefox on Linux");
    expect(defaultLabel("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15")).toBe("Safari on macOS");
    expect(defaultLabel("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")).toBe("Chrome on Windows");
    expect(defaultLabel("")).toBe("Browser");
    expect(normalizeLabel("  Work   laptop ")).toBe("Work laptop");
    for (const bad of ["", "   ", "x".repeat(65), "a\u0007b"]) expect(() => normalizeLabel(bad)).toThrow(BrowserKeyError);
  });

  test("a descriptor names a browser key only where one is expected, and then exactly that one", () => {
    const b64 = (n: number, fill: number) => encode(new Uint8Array(n).fill(fill));
    const point = (fill: number) => {
      const p = new Uint8Array(65).fill(fill);
      p[0] = 4;
      return encode(p);
    };
    const d = { attempt_id: b64(32, 1), buckets: [], credential_id: b64(16, 2), epoch: b64(32, 3), installation: b64(32, 4), object: "scope-enrol", purpose: "enrol", recipient: point(5), salts: [b64(32, 6)], scopes: ["installation"], v: 1 };
    const withKey = canonicalJSON({ ...d, browser_key: point(7) });
    expect(parseDescriptor(withKey, { object: "scope-enrol", browserKey: point(7) }).browser_key).toBe(point(7));
    expect(() => parseDescriptor(withKey, { object: "scope-enrol" })).toThrow(/unexpected fields/);
    expect(() => parseDescriptor(withKey, { object: "scope-enrol", browserKey: point(8) })).toThrow(/another browser/);
    expect(() => parseDescriptor(canonicalJSON(d), { object: "scope-enrol", browserKey: point(7) })).toThrow(/unexpected fields/);
    expect(() => parseDescriptor(canonicalJSON({ ...d, purpose: "stage", browser_key: point(7) }), { object: "scope-enrol", browserKey: point(7) })).toThrow(/remembered or tested/);
  });
});

async function as(m: Mock, auth: PrfAuth) {
  const log: Sent[] = [];
  const api = createApi({ base: m.url, fetch: jarFetch(log) });
  await completeLogin(api, auth, await prepareLogin(api));
  return { api, log };
}

/** Run a step chain; an offer step is accepted with `label`. Returns the steps seen. */
async function run(first: Step, pick: (s: Step) => PrfAuth, label = "Work laptop"): Promise<Step[]> {
  const seen: Step[] = [];
  let s: Step | void = first;
  while (s) {
    seen.push(s);
    s = s.offer ? await s.offer.accept(label) : await s.tap(pick(s));
  }
  return seen;
}

describe("remember this browser", () => {
  let m: Mock;
  let rp: string;
  let me: PrfAuth, bw: PrfAuth, yk: PrfAuth;
  let api: Api, log: Sent[];
  const store = memoryStore();
  const keys = new BrowserKeys(store, async () => false);
  const browser: BrowserContext = { keys };
  const status = () => api.sealStatus!();
  const hexOf = (cred: string) => m.store.passkeys.find((p) => p.id === cred)!.info.id;
  const pk = async (cred: string) => (await status()).passkeys!.find((p) => p.id === hexOf(cred))!;
  const nick = (cred: string) => m.store.passkeys.find((p) => p.id === cred)!.info.nickname;
  const intent = (i: Partial<Intent> & Pick<Intent, "action" | "credential_id" | "scopes">): Intent => ({ capability: "unlock", nickname: nick(i.credential_id), ...i });
  // The signed-in PRF passkey approves; the passkey without PRF taps for itself.
  const pick = (s: Step) => (s.progress?.includes("signed-in") ? me : bw);
  const posts = (re: RegExp) => log.filter((x) => re.test(x.url));
  let keyed: string[];
  let win: Window;
  const G = globalThis as Record<string, unknown>;
  const saved: Record<string, unknown> = {};
  const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "navigator"];

  beforeAll(async () => {
    m = startMock({ port: 0, distDir: null, vault: true });
    rp = new URL(m.url).hostname;
    win = new Window({ url: m.url + "/" });
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    me = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[0]!.id) });
    bw = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[1]!.id), prf: false });
    yk = prfAuth(m.url, { rawId: rawOf(m.store.passkeys[2]!.id) });
    // The password-manager passkey starts as it does for the owner: sign and approve only.
    m.store.buckets.wraps.delete(bw.id);
    m.store.buckets.closeAll();
    ({ api, log } = await as(m, me));
    browserPath.keys = keys;
    browserPath.release = (body) => api.sealPost!("browser/release", body);
    keyed = (await status()).scopes!.filter((s) => s.has_key).map((s) => s.scope);
  });
  afterAll(async () => {
    delete browserPath.keys;
    delete browserPath.release;
    m.stop();
    await win.happyDOM.abort();
    win.close();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("the PRF path is unchanged: a PRF tap sends its packet and asks for no release", async () => {
    const v = await status();
    const ssh = v.buckets!.find((b) => b.kind === "ssh-ca")!;
    log.length = 0;
    const c = await beginControl(api, v, "reopen", { buckets: [ssh.id] }, rp);
    await c.finish(me);
    expect(posts(/browser\/release$/).length).toBe(0);
    expect(Object.keys((posts(/control\/finish$/)[0]!.body as { open: object }).open).sort()).toEqual(["attempt_id", "ciphertext", "enc"]);
    expect((await status()).buckets!.find((b) => b.id === ssh.id)!.open).toBe(true);
    expect((await pk(me.id)).mode).toBe("prf");
    expect(await keys.current()).toBeUndefined(); // nothing was created in this browser
    m.store.buckets.closeAll();
  });

  test("before: the passkey without PRF opens nothing and the card says who can", async () => {
    const p = await pk(bw.id);
    expect(p).toMatchObject({ mode: "", prf: false, opens: 0, browsers: [] });
    expect(howItOpens(p)).toBeUndefined();
    const v = await status();
    const ssh = v.buckets!.find((b) => b.kind === "ssh-ca")!;
    const b = await api.sealPost!<{ canonical: string; challenge_id: string; public_key: unknown; open?: unknown }>("control/challenge", { action: "reopen", buckets: [ssh.id] });
    const tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch });
    expect(tap.open!.canOpen).not.toContain(bw.id);
    expect(tap.open!.browsers).toEqual([]);
    const signed = await tap.sign(bw);
    expect(signed.open).toBeUndefined();
    await expect(api.sealPost!("control/finish", { challenge_id: b.challenge_id, ...signed })).rejects.toThrow(/closed/);
  });

  test("Enable: no PRF result → the offer with the trade-off → approve → enrol → test", async () => {
    const v = await status();
    log.length = 0;
    const first = await startCapability(api, v, intent({ action: "enable", credential_id: bw.id, scopes: keyed }), rp, 0, { thenTest: true, browser });
    const seen = await run(first, pick);
    const offer = seen.find((s) => s.offer)!;
    expect(seen.indexOf(offer)).toBe(2); // the approver tapped, the passkey tapped, then the offer
    expect(offer.title).toBe(`Remember this browser for ${nick(bw.id)}?`);
    expect(offer.offer!.why).toMatch(/no PRF result/);
    // Nothing existed before the owner accepted.
    const local = (await keys.current())!;
    expect(local).toBeDefined();
    const remember = seen[3]!;
    expect(remember.title).toContain(`Remember this browser (Work laptop) for ${nick(bw.id)}`);
    expect(remember.lines).toContain(TRADE_OFF);
    expect(remember.lines.join(" ")).toMatch(/did not promise to keep/); // persist() refused: said, not fatal
    const signed = JSON.parse(remember.detail) as Record<string, unknown>;
    expect(signed).toMatchObject({ object: "passkey-capability", action: "remember", credential_id: bw.id, browser_key: local.public, browser_key_id: local.id, browser_label: "Work laptop" });
    expect(seen.some((s) => s.title.startsWith("Create this browser's keys"))).toBe(true);
    expect(seen[seen.length - 1]!.title).toMatch(/^Test /);
    // What left this page: the public half, and ciphertext. Never the key pair.
    const sent = JSON.stringify(log.map((x) => x.body));
    expect(sent).toContain(local.public);
    for (const r of posts(/browser\/release$/)) expect(Object.keys(r.body as object).sort()).toEqual(["assertion", "browser_key", "challenge_id"]);
    expect(posts(/browser\/release$/).length).toBeGreaterThan(0); // the test taps
    expect(sent).not.toContain('"d":');
    // Every KEK the mock received for the remember was random bytes of this page, sealed.
    const p = await pk(bw.id);
    expect(p).toMatchObject({ mode: "browser", prf: false, opens: p.of, missing: [] });
    expect(p.browsers!.length).toBe(1);
    expect(p.browsers![0]!).toMatchObject({ id: local.id, key: local.public, label: "Work laptop" });
    expect(p.browsers![0]!.last_used_at).toBeDefined();
    expect(p.browsers![0]!.scopes.map((s) => s.scope).sort()).toEqual([...keyed].sort());
    expect(p.browsers![0]!.scopes.every((s) => s.tested)).toBe(true);
    expect(howItOpens(p)).toEqual({ mark: "Browser key", cls: "how-mark browser", text: "Opens buckets only from remembered browsers" });
    expect((await pk(me.id)).mode).toBe("prf");
    expect(m.store.recent.some((a) => a.action === "passkey_remember_browser" && (a.detail ?? "").includes(local.id))).toBe(true);
  });

  test("the remembered browser opens a bucket: one tap, the release, then the packet", async () => {
    const other = await as(m, bw);
    browserPath.release = (body) => other.api.sealPost!("browser/release", body);
    const v = await other.api.sealStatus!();
    const ssh = v.buckets!.find((b) => b.kind === "ssh-ca")!;
    const b = await other.api.sealPost!<{ canonical: string; challenge_id: string; public_key: unknown; open?: unknown }>("control/challenge", { action: "reopen", buckets: [ssh.id] });
    const tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch });
    const local = (await keys.current())!;
    expect(tap.open!.canOpen).toContain(bw.id);
    expect(tap.open!.browsers).toEqual([{ credential_id: bw.id, key_id: local.id, label: "Work laptop", here: true }]);
    bw.gets.length = 0;
    const signed = await tap.sign(bw);
    expect(bw.gets.length).toBe(1); // one passkey prompt
    expect(signed.open).toBeDefined();
    const rel = other.log.filter((x) => x.url.endsWith("/browser/release"));
    expect(rel.length).toBe(1);
    expect((rel[0]!.body as { assertion: unknown }).assertion).toEqual(signed.assertion);
    // The release is single use, and useless without this browser's key.
    await expect(other.api.sealPost!("browser/release", { challenge_id: b.challenge_id, assertion: signed.assertion, browser_key: local.public })).rejects.toThrow(/already released/);
    await other.api.sealPost!("control/finish", { challenge_id: b.challenge_id, ...signed });
    expect((await other.api.sealStatus!()).buckets!.find((x) => x.id === ssh.id)!.open).toBe(true);
    await expect(other.api.sealPost!("browser/release", { challenge_id: b.challenge_id, assertion: signed.assertion, browser_key: local.public })).rejects.toThrow(/stale/);
    m.store.buckets.closeAll();
    browserPath.release = (body) => api.sealPost!("browser/release", body);
  });

  test("another passkey's tap, or another browser's key, is released nothing", async () => {
    const v = await status();
    const ssh = v.buckets!.find((b) => b.kind === "ssh-ca")!;
    const local = (await keys.current())!;
    const challenge = () => api.sealPost!<{ canonical: string; challenge_id: string; public_key: unknown; open?: unknown }>("control/challenge", { action: "reopen", buckets: [ssh.id] });
    let b = await challenge();
    let tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch });
    // The PRF passkey signs: asking for the other passkey's sealed keys with it finds none.
    const byMe = await tap.sign(me);
    await expect(api.sealPost!("browser/release", { challenge_id: b.challenge_id, assertion: byMe.assertion, browser_key: local.public })).rejects.toThrow(/not remembered for this passkey/);
    // The right passkey, a key of some other browser.
    const stranger = (await new BrowserKeys(memoryStore()).ensure()).key;
    b = await challenge();
    tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch });
    // (Signed outside the page's own tap path, which would ask for the release itself.)
    const byBw = { assertion: encodeAssertion(await bw.get(tap.options)) };
    await expect(api.sealPost!("browser/release", { challenge_id: b.challenge_id, assertion: byBw.assertion, browser_key: stranger.public })).rejects.toThrow(/not remembered/);
    // An assertion over another challenge.
    b = await challenge();
    await expect(api.sealPost!("browser/release", { challenge_id: b.challenge_id, assertion: byBw.assertion, browser_key: local.public })).rejects.toThrow(/rejected/);
  });

  test("no silent downgrade: a PRF passkey is refused the browser path, by the broker and by the page", async () => {
    const v = await status();
    const local = (await keys.current())!;
    // A passkey that has PRF wraps.
    await expect(startCapability(api, v, intent({ action: "remember", credential_id: me.id, scopes: ["installation"], browser_key: local.public, browser_label: "Work laptop" }), rp)).rejects.toThrow(/only for passkeys without PRF/);
    // A passkey with PRF and no wraps yet: its enrol tap returns a PRF result, so the page stops.
    const steps = run(rememberOffer(api, v, { nickname: nick(yk.id), credential_id: yk.id, scopes: ["installation"] }, rp, browser, "test"), (s) => (s.progress?.includes("signed-in") ? me : yk));
    await expect(steps).rejects.toThrow(/returned a PRF result/);
    expect((await pk(yk.id)).mode).toBe("");
    // And the other way round: a passkey that opens from remembered browsers is not PRF-enabled.
    await expect(startCapability(api, v, intent({ action: "enable", credential_id: bw.id, scopes: ["installation"] }), rp)).rejects.toThrow(/only from remembered browsers/);
    // The canonical is checked against the browser key the owner chose.
    const c = { v: 3, object: "passkey-capability", action: "remember", capability: "unlock", credential_id: bw.id, nickname: "x", installation: v.installation, epoch: v.epoch, nonce: v.epoch, issued_at: "2026-01-01T00:00:00Z", id: v.epoch, scopes: ["installation"], browser_key: local.public, browser_key_id: local.id, browser_label: "Work laptop" };
    const i: Intent = { action: "remember", capability: "unlock", credential_id: bw.id, nickname: "x", scopes: ["installation"], browser_key: local.public, browser_label: "Work laptop" };
    expect(() => checkCapability(canonicalJSON(c), v, i, ["installation"])).not.toThrow();
    expect(() => checkCapability(canonicalJSON({ ...c, browser_key: yk.id }), v, i, ["installation"])).toThrow(/another browser key/);
    expect(() => checkCapability(canonicalJSON({ ...c, browser_label: "Other" }), v, i, ["installation"])).toThrow(/another browser label/);
    expect(() => checkCapability(canonicalJSON(c), v, { ...i, action: "enable", browser_key: undefined, browser_label: undefined }, ["installation"])).toThrow();
  });

  test("Rekey from the remembered browser: a fresh key, untested until its test tap", async () => {
    const other = await as(m, bw);
    browserPath.release = (body) => other.api.sealPost!("browser/release", body);
    let v = await other.api.sealStatus!();
    const scope = v.scopes!.find((s) => s.title === "Client A")!.scope;
    const before = m.store.buckets.browsers.get(bw.id)![0]!.wraps.get(scope)!;
    const sealedBefore = before.sealed, kekBefore = before.kek;
    const c = await beginControl(other.api, v, "rekey", { scope }, rp);
    await c.finish(bw);
    const after = m.store.buckets.browsers.get(bw.id)![0]!.wraps.get(scope)!;
    expect(after.tested).toBe(false);
    expect(after.sealed).not.toBe(sealedBefore);
    expect(after.kek).not.toBe(kekBefore);
    // As for a PRF rekey: nothing else keeps a wrap of the scope.
    expect(m.store.buckets.wraps.get(me.id)!.has(scope)).toBe(false);
    v = await other.api.sealStatus!();
    const local = (await keys.current())!;
    await run(await startCapability(other.api, v, intent({ action: "test", credential_id: bw.id, scopes: [scope], browser_key: local.public }), rp), () => bw);
    expect(m.store.buckets.browsers.get(bw.id)![0]!.wraps.get(scope)!.tested).toBe(true);
    // A browser-key passkey approves and opens for enabling another passkey (the PRF one, again).
    const back = await run(await startCapability(other.api, await other.api.sealStatus!(), intent({ action: "enable", credential_id: me.id, scopes: [scope] }), rp, 0, { thenTest: true }), (s) => (s.progress?.includes("signed-in") ? bw : me));
    expect(back.length).toBe(3);
    expect(m.store.buckets.wraps.get(me.id)!.get(scope)!.tested).toBe(true);
    browserPath.release = (body) => api.sealPost!("browser/release", body);
  });

  test("Security shows how each passkey opens, the remembered browser, and Forget", async () => {
    const v = await status();
    const pks = (await api.state()).passkeys!;
    browser.local = await keys.current();
    const el = capabilityForm(api, me, v, pks, () => {}, browser);
    const row = el.querySelector(`[data-passkey="${hexOf(bw.id)}"]`)!;
    expect(row.getAttribute("data-mode")).toBe("browser");
    expect(row.querySelector(".how-mark.browser")!.textContent).toBe("Browser key");
    expect(row.textContent).toContain("Opens buckets only from remembered browsers:");
    expect(row.textContent).toMatch(/Work laptop, added \d+ \w+ \d{4}, last used /);
    expect(row.querySelector(".badge.this")!.textContent).toBe("this browser");
    expect([...row.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Forget…", "Test this browser…"]);
    expect(row.textContent).not.toContain("no longer remembered");
    const mine = el.querySelector(`[data-passkey="${hexOf(me.id)}"]`)!;
    expect(mine.querySelector(".how-mark.prf")!.textContent).toBe("PRF");
    expect(mine.textContent).toContain("Opens buckets with its own secret (PRF).");
    expect(mine.textContent).not.toContain("Remember this browser");
    // The opening sentence marks it too, in words.
    const r = readiness(v)!;
    const panel = readinessPanel({ api, auth: me, passkeys: () => pks, refresh: () => {}, browser }, v, r);
    const li = [...panel.querySelectorAll("li")].find((x) => x.getAttribute("data-mode") === "browser")!;
    expect(li.textContent).toContain("Browser key");
    expect(li.textContent).toContain("only from remembered browsers: Work laptop (this browser)");
  });

  test("a lost key (cleared site data, eviction): not remembered, said plainly, enabled again", async () => {
    const kept = store.pair!;
    const local = (await keys.current())!;
    await store.clear(); // what clearing site data or storage eviction does
    expect(await keys.current()).toBeUndefined();
    const v = await status();
    const pks = (await api.state()).passkeys!;
    browser.local = undefined;
    // Security says so and offers to enable it again.
    const el = capabilityForm(api, me, v, pks, () => {}, browser);
    const row = el.querySelector(`[data-passkey="${hexOf(bw.id)}"]`)!;
    expect(row.querySelector(".not-remembered")!.textContent).toContain("this browser is no longer remembered; enable it again");
    expect(row.querySelector(".badge.this")).toBeNull();
    expect([...row.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Forget…", "Remember this browser…"]);
    // The approval card: this passkey opens only from the browser it names, not from here.
    const ssh = v.buckets!.find((b) => b.kind === "ssh-ca")!;
    const b = await api.sealPost!<{ canonical: string; challenge_id: string; public_key: unknown; open?: unknown }>("control/challenge", { action: "reopen", buckets: [ssh.id] });
    const tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch });
    expect(tap.open!.canOpen).not.toContain(bw.id);
    expect(tap.open!.browsers).toEqual([{ credential_id: bw.id, key_id: local.id, label: "Work laptop", here: false }]);
    log.length = 0;
    const signed = await tap.sign(bw);
    expect(signed.open).toBeUndefined();
    expect(posts(/browser\/release$/).length).toBe(0);
    await expect(api.sealPost!("control/finish", { challenge_id: b.challenge_id, ...signed })).rejects.toThrow(/no longer remembered for this passkey/);
    // A test of the lost browser stops before any tap, with the same words.
    await expect(startCapability(api, v, intent({ action: "test", credential_id: bw.id, scopes: ["installation"], browser_key: local.public }), rp).then((s) => s.tap(bw))).rejects.toThrow(NOT_REMEMBERED);
    // Enable again: a new key, a second remembered browser entry; the old one can be forgotten.
    const seen = await run(rememberOffer(api, v, { nickname: nick(bw.id), credential_id: bw.id, scopes: ["installation"] }, rp, browser, "again"), pick, "Work laptop (again)");
    expect(seen[seen.length - 1]!.title).toMatch(/^Test /);
    const p = await pk(bw.id);
    expect(p.browsers!.map((x) => x.label)).toEqual(["Work laptop", "Work laptop (again)"]);
    expect((await keys.current())!.id).not.toBe(local.id);
    // Put the first key back for the Forget test below.
    await store.clear();
    await store.save(kept);
    browser.local = await keys.current();
  });

  test("Forget: a signed action; the broker drops the wraps and this browser drops its key", async () => {
    const v = await status();
    const local = (await keys.current())!;
    const second = (await pk(bw.id)).browsers!.find((b) => b.id !== local.id)!;
    // Forget the other entry first (not this browser): the local key stays.
    let step = await startCapability(api, v, intent({ action: "forget", credential_id: bw.id, scopes: [], browser_key: second.key }), rp);
    expect(step.title).toBe(`Forget a remembered browser of ${nick(bw.id)}`);
    expect(JSON.parse(step.detail)).toMatchObject({ action: "forget", credential_id: bw.id, browser_key: second.key, browser_key_id: second.id, scopes: [] });
    await step.tap(me);
    expect((await pk(bw.id)).browsers!.map((b) => b.id)).toEqual([local.id]);
    expect(await keys.current()).toBeDefined();
    // Forget this browser from the panel: the Forget button, then the passkey button.
    const pks = (await api.state()).passkeys!;
    let refreshed = 0;
    const el = capabilityForm(api, me, await status(), pks, () => refreshed++, browser);
    (win.document.body as unknown as HTMLElement).append(el);
    const until = async (cond: () => boolean) => {
      const t0 = Date.now();
      while (!cond()) {
        if (Date.now() - t0 > 3000) throw new Error("timed out: " + el.textContent);
        await new Promise((r) => setTimeout(r, 10));
      }
    };
    el.querySelector<HTMLButtonElement>(`[data-passkey="${hexOf(bw.id)}"] li[data-browser="${local.id}"] button`)!.click();
    await until(() => !!el.querySelector("button.confirm"));
    expect(el.textContent).toContain("The broker deletes what it holds for that browser");
    el.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => refreshed > 0);
    const p = await pk(bw.id);
    expect(p).toMatchObject({ mode: "", opens: 0, browsers: [] });
    expect(await keys.current()).toBeUndefined(); // the key is gone from this browser too
    expect(m.store.recent.some((a) => a.action === "passkey_forget_browser")).toBe(true);
    // And it is refused from then on.
    const ssh = v.buckets!.find((b) => b.kind === "ssh-ca")!;
    m.store.buckets.closeAll();
    const b = await api.sealPost!<{ canonical: string; challenge_id: string; public_key: unknown; open?: unknown }>("control/challenge", { action: "reopen", buckets: [ssh.id] });
    const tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch });
    expect(tap.open!.browsers).toEqual([]);
    await expect(api.sealPost!("control/finish", { challenge_id: b.challenge_id, ...(await tap.sign(bw)) })).rejects.toThrow(/closed/);
  });
  test("recovery enrol for a passkey without PRF writes this browser's wraps", async () => {
    const { beginRecovery } = await import("../src/recoveryPanel");
    const { generateAgeIdentity } = await import("../src/setup");
    const v = await status();
    const identity = (await generateAgeIdentity()).identity;
    // Without the choice, the passkey's enrol tap has no PRF result: the page says what to tick.
    const plain = await beginRecovery(api, v, { mode: "enrol", credential_id: bw.id, scopes: ["installation"] }, identity, rp);
    await expect(plain.finish(bw)).rejects.toThrow(/Remember this browser/);
    const made = await keys.ensure();
    const r = await beginRecovery(api, v, { mode: "enrol", credential_id: bw.id, scopes: ["installation"], browser: { key: made.key.public, label: "Recovered laptop" } }, identity, rp);
    expect(JSON.parse(r.canonical)).toMatchObject({ object: "recovery", action: "enrol", browser_key: made.key.public, browser_key_id: made.key.id, browser_label: "Recovered laptop" });
    expect(r.lines.join(" ")).toMatch(/Creates this browser's keys/);
    await r.finish(bw);
    const p = await pk(bw.id);
    expect(p.mode).toBe("browser");
    expect(p.browsers![0]!).toMatchObject({ id: made.key.id, label: "Recovered laptop" });
    // A PRF passkey is not offered this path by the broker.
    await expect(beginRecovery(api, v, { mode: "enrol", credential_id: me.id, scopes: ["installation"], browser: { key: made.key.public, label: "x" } }, identity, rp)).rejects.toThrow(/only for passkeys without PRF/);
  });
});
