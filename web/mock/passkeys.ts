// Mock of passkey enable/test/disable/register (/api/ui/seal/passkeys/*) and the Admin
// recovery drill/enrol (/api/ui/seal/recovery/*) for seal format 2 (docs/BUCKETS.md §7).
// Wraps are mocked as in mock/buckets.ts: the salt plus the SHA-256 of the KEK.
import { createECDH, createHash, randomBytes } from "node:crypto";
import { browserKeyId, type MockBuckets } from "./buckets";
import { canonicalJSON, openAAD, openInfo } from "../src/buckets";
import { suite } from "../src/seal";

export interface PasskeyFlowDeps {
  buckets: MockBuckets;
  /** The mock store (mock/server.ts MockStore): passkeys, addPasskey, sessionPasskey, audit. */
  store: {
    passkeys: { id: string; info: { id: string; nickname: string } }[];
    sessionPasskey: Map<string, string>;
    addPasskey(kind: "apple" | "bitwarden" | "yubikey" | "unknown", nickname: string, createdAt: number, lastUsed?: number, credId?: string, transports?: string[]): { id: string; info: { id: string; nickname: string } };
    audit(actor: string, action: string, object: string, detail?: string): void;
  };
  fail(status: number, code: string, message: string): never;
}

const b64url = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const raw = (s: unknown) => Buffer.from(typeof s === "string" ? s : "", "base64url");
const ab = (b: Uint8Array) => new Uint8Array(b).buffer as ArrayBuffer;
const kekHash = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const nowISO = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
const text = (c: Record<string, unknown>) => canonicalJSON(c);

interface Registration {
  session: string | undefined;
  action: string;
  capability: string;
  nickname: string;
  scopes: string[];
  target: string;
  opened: Set<string>;
  createChallenge?: string;
  /** Remembered browsers (§13): the browser key (public half) and, for remember, its label. */
  browser?: string;
  label?: string;
}

export class MockPasskeyFlows {
  private regs = new Map<string, Registration>();
  private recovery = new Map<string, { priv: Buffer; session: string | undefined }>();

  constructor(private deps: PasskeyFlowDeps) {}

  private base(object: string, action: string, id: string) {
    const b = this.deps.buckets;
    return { v: 3, object, action, id, installation: b.installation, epoch: b.epoch, nonce: b64url(randomBytes(32)), issued_at: nowISO() };
  }

  private scopesIn(x: unknown, max = 2): string[] {
    const b = this.deps.buckets;
    if (!Array.isArray(x) || x.length > max || x.some((s) => typeof s !== "string" || !b.scopes.some((y) => y.scope === s))) return this.deps.fail(400, "bad_request", "unknown or too many scopes");
    return x as string[];
  }

  /** Record wraps for `cred` from an enrol packet (creating scope keys that had none). */
  private wrap(cred: string, scopes: string[], salts: string[], keks: Buffer[]): void {
    const b = this.deps.buckets;
    const m = b.wraps.get(cred) ?? new Map();
    scopes.forEach((s, i) => {
      const sc = b.scopes.find((x) => x.scope === s)!;
      sc.has_key = true;
      m.set(s, { salt: salts[i]!, tested: false, kek: kekHash(keks[i]!) });
    });
    b.wraps.set(cred, m);
  }

  /** As the broker's BrowserOrphanedScopes: refuse to forget the only thing that opens a scope. */
  private keepOpener(cred: string, key: string, scopes: string[]): void {
    const b = this.deps.buckets;
    for (const s of scopes) {
      const prf = [...b.wraps.values()].some((m) => m.get(s)?.tested);
      const other = [...b.browsers.entries()].some(([c, list]) => list.some((x) => !(c === cred && x.key === key) && x.wraps.get(s)?.tested));
      if (!prf && !other) this.deps.fail(409, "conflict", `this remembered browser is the only thing that can open ${s}: remember another browser or enable another passkey for it first, or enrol with the recovery key (Security → Recovery key)`);
    }
  }

  /** undefined for paths that are not passkeys/* or recovery/*. */
  async handle(req: Request, url: URL, body: Record<string, unknown>, session: string | undefined): Promise<unknown> {
    const b = this.deps.buckets, fail = this.deps.fail;
    if (!b.enabled || b.mode !== "buckets" || req.method !== "POST") return undefined;
    const verb = url.pathname.replace(/^\/api\/ui\/seal\//, "");
    switch (verb) {
      case "passkeys/challenge": {
        const action = String(body.action);
        if (!["register", "enable", "disable", "test", "remember", "forget"].includes(action)) fail(400, "bad_request", "unknown action");
        const scopes = this.scopesIn(body.scopes);
        const target = String(body.credential_id ?? "");
        if (action === "register" ? target !== "" : !this.deps.store.passkeys.some((p) => p.id === target)) fail(400, "bad_request", "unknown passkey");
        const id = b64url(randomBytes(32));
        const canonical: Record<string, unknown> = { ...this.base("passkey-capability", action, id), capability: String(body.capability), nickname: String(body.nickname ?? ""), credential_id: target, scopes };
        // Remembered browsers, with the broker's rules (internal/server/browserkey.go intentBrowser
        // and capability.go checkIntent): one way of opening per passkey, never a silent switch.
        const browser = typeof body.browser_key === "string" && body.browser_key ? body.browser_key : undefined;
        const label = typeof body.browser_label === "string" && body.browser_label ? body.browser_label : undefined;
        const named = action === "remember" || action === "forget";
        if (named && !browser) fail(400, "bad_request", "name the browser key");
        if (browser && !named && action !== "test") fail(400, "bad_request", "this passkey change takes no browser key");
        if (label && action !== "remember") fail(400, "bad_request", "only remembering a browser takes a label");
        if (named && body.capability !== "unlock") fail(400, "bad_request", "a remembered browser is an unlock capability");
        if (action === "forget" && scopes.length) fail(400, "bad_request", "forgetting a browser names no scope");
        if (browser && (raw(browser).length !== 65 || raw(browser)[0] !== 4)) fail(400, "bad_request", "invalid browser key");
        if (action === "remember" && (!label || label !== label.split(/\s+/).filter(Boolean).join(" ") || [...label].length > 64)) fail(400, "bad_request", "a browser label has 1 to 64 printable characters, single spaces");
        const mine = b.browsers.get(target) ?? [];
        const known = browser ? mine.find((x) => x.key === browser) : undefined;
        if (action === "remember") {
          if (b.wraps.get(target)?.size) fail(409, "conflict", "this passkey opens buckets with its own secret (PRF): a remembered browser is only for passkeys without PRF");
          for (const s of scopes) if (known?.wraps.get(s)?.tested) fail(409, "conflict", `this browser is already remembered for ${s} (tested): nothing to do`);
        }
        if (action === "enable" && mine.length) fail(409, "conflict", "this passkey opens buckets only from remembered browsers: use Remember this browser, or forget its browsers first to enable it with PRF");
        if (action === "forget") {
          if (!known) fail(409, "conflict", "this browser is not remembered for that passkey");
          this.keepOpener(target, known!.key, [...known!.wraps.keys()]);
        }
        if (browser) {
          canonical.browser_key = browser;
          canonical.browser_key_id = browserKeyId(raw(browser));
          if (action === "remember") canonical.browser_label = label;
        }
        const text = canonicalJSON(canonical);
        this.regs.set(id, { session, action, capability: String(body.capability), nickname: String(body.nickname ?? ""), scopes, target, opened: new Set(), browser, label });
        if (action === "test" && browser) {
          if (!known || !scopes.every((s) => known.wraps.has(s))) fail(409, "conflict", "this browser is not remembered for those scopes");
          return b.enrolOffer(req, text, canonical, session, { purpose: "test", credential: target, scopes, salts: scopes.map((s) => known!.wraps.get(s)!.id), browser });
        }
        if (action === "forget") return b.plainOffer(req, text, canonical, session);
        if (action === "test") {
          const w = b.wraps.get(target);
          if (!w || !scopes.every((s) => w.has(s))) fail(409, "conflict", "this passkey is not enabled for those scopes");
          return b.enrolOffer(req, text, canonical, session, { purpose: "test", credential: target, scopes, salts: scopes.map((s) => w!.get(s)!.salt) });
        }
        if (action === "disable") return b.plainOffer(req, text, canonical, session);
        const keyed = scopes.filter((s) => b.scopes.find((x) => x.scope === s)?.has_key);
        return b.bucketOffer(req, text, canonical, session, { buckets: [], scopes: keyed });
      }
      case "passkeys/authorize": {
        const f = await b.finish(body, session);
        const c = f.canonical;
        const reg = this.regs.get(String(c.id));
        if (c.object !== "passkey-capability" || !reg || reg.session !== session) return fail(409, "conflict", "wrong ceremony");
        if (reg.action === "test" && reg.browser) {
          const rel = f.attempt!.released;
          const known = (b.browsers.get(reg.target) ?? []).find((x) => x.key === reg.browser);
          if (!known || !rel || rel.cred !== reg.target || rel.key !== reg.browser) return fail(409, "conflict", "this browser's wraps changed; start again");
          reg.scopes.forEach((s, i) => {
            const x = known.wraps.get(s)!;
            if (x.kek !== kekHash(f.keks![i]!)) fail(403, "forbidden", "this browser's key did not open the scope key");
            x.tested = true;
          });
          known.last_used_at = nowISO();
          this.regs.delete(String(c.id));
          return { ok: true, scopes: reg.scopes };
        }
        if (reg.action === "forget") {
          const list = b.browsers.get(reg.target) ?? [];
          const known = list.find((x) => x.key === reg.browser);
          if (!known) return fail(409, "conflict", "this browser is not remembered for that passkey");
          this.keepOpener(reg.target, known.key, [...known.wraps.keys()]);
          b.browsers.set(reg.target, list.filter((x) => x !== known));
          this.regs.delete(String(c.id));
          this.deps.store.audit("owner", "passkey_forget_browser", "passkey:" + reg.target, text(c));
          return { ok: true };
        }
        if (reg.action === "test") {
          const w = b.wraps.get(reg.target)!;
          reg.scopes.forEach((s, i) => {
            const x = w.get(s)!;
            const hsh = kekHash(f.keks![i]!);
            if (x.kek && x.kek !== hsh) fail(403, "forbidden", "the KEK does not open the scope key");
            x.kek = hsh;
            x.tested = true;
          });
          this.regs.delete(String(c.id));
          return { ok: true, scopes: reg.scopes };
        }
        if (reg.action === "disable") {
          for (const s of reg.scopes) {
            const others = [...b.wraps.entries()].some(([cred, m]) => cred !== reg.target && m.has(s)) || [...b.browsers.entries()].some(([cred, list]) => cred !== reg.target && list.some((x) => x.wraps.get(s)?.tested));
            if (!others) fail(409, "conflict", "refusing: this is the last passkey that can open " + s);
          }
          for (const s of reg.scopes) b.wraps.get(reg.target)?.delete(s);
          this.regs.delete(String(c.id));
          this.deps.store.audit("owner", "passkey_disable", "passkey:" + reg.target, reg.scopes.join(","));
          return { ok: true };
        }
        if (f.keks) for (const s of f.attempt!.descriptor.scopes as string[]) reg.opened.add(s);
        if (reg.action === "enable" || reg.action === "remember") return { registration_id: c.id };
        reg.createChallenge = b64url(randomBytes(32));
        const host = new URL(req.url).hostname;
        return {
          registration_id: c.id,
          public_key: {
            publicKey: {
              rp: { name: "aqmas", id: host },
              user: { id: b64url(randomBytes(16)), name: "owner", displayName: "owner" },
              challenge: reg.createChallenge,
              pubKeyCredParams: [{ type: "public-key", alg: -7 }],
              timeout: 300000,
              authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
              attestation: "none",
              ...(reg.capability === "unlock" ? { extensions: { prf: {} } } : {}),
            },
          },
        };
      }
      case "passkeys/create": {
        const reg = this.regs.get(String(body.registration_id));
        if (!reg || reg.session !== session || reg.action !== "register" || !reg.createChallenge || reg.target) return fail(409, "conflict", "no registration waiting for a passkey");
        const cred = body.credential as { id?: string; response?: { clientDataJSON?: string } };
        let cd: { type?: string; challenge?: string } = {};
        try {
          cd = JSON.parse(raw(cred?.response?.clientDataJSON).toString("utf8"));
        } catch {
          fail(400, "bad_request", "invalid credential");
        }
        if (cd.type !== "webauthn.create" || cd.challenge !== reg.createChallenge || typeof cred.id !== "string") fail(403, "forbidden", "credential is for another challenge");
        const pk = this.deps.store.addPasskey("bitwarden", reg.nickname, Date.now(), undefined, cred.id);
        reg.target = pk.id;
        this.deps.store.audit("owner", "passkey_register", "passkey:" + pk.info.id, reg.capability);
        return { ok: true };
      }
      case "passkeys/evaluate": {
        const id = String(body.registration_id);
        const reg = this.regs.get(id);
        if (!reg || reg.session !== session || !reg.target || !reg.scopes.length) return fail(409, "conflict", "nothing to evaluate");
        for (const s of reg.scopes) if (b.scopes.find((x) => x.scope === s)?.has_key && !reg.opened.has(s)) fail(409, "conflict", "no passkey opened the key of " + s);
        const canonical: Record<string, unknown> = { ...this.base("passkey-enrol", "enrol", id), credential_id: reg.target, scopes: reg.scopes };
        if (reg.browser) Object.assign(canonical, { browser_key: reg.browser, browser_key_id: browserKeyId(raw(reg.browser)) });
        return b.enrolOffer(req, canonicalJSON(canonical), canonical, session, { purpose: "enrol", credential: reg.target, scopes: reg.scopes, browser: reg.browser });
      }
      case "passkeys/finish": {
        const id = String(body.registration_id);
        const reg = this.regs.get(id);
        if (!reg || reg.session !== session) return fail(409, "conflict", "no such registration");
        const f = await b.finish(body, session);
        if (f.canonical.id !== id || f.cred !== reg.target) fail(409, "conflict", "wrong ceremony");
        if (reg.browser) {
          // A remembered browser: the KEKs are its own random bytes; the "salts" are wrap IDs.
          if (f.attempt!.descriptor.browser_key !== reg.browser) fail(409, "conflict", "stale passkey enrolment; start again");
          await b.rememberBrowser(new URL(req.url).hostname, reg.target, reg.browser, reg.label!, reg.scopes, f.attempt!.salts.get(reg.target)!, f.keks!);
          this.regs.delete(id);
          this.deps.store.audit("owner", "passkey_remember_browser", "passkey:" + reg.target, text(f.canonical) + ` browser_key_id=${browserKeyId(raw(reg.browser))} label=${reg.label}`);
          return { ok: true, scopes: reg.scopes };
        }
        this.wrap(reg.target, reg.scopes, f.attempt!.salts.get(reg.target)!, f.keks!);
        this.regs.delete(id);
        this.deps.store.audit("owner", "passkey_enable", "passkey:" + reg.target, reg.scopes.join(","));
        return { ok: true, scopes: reg.scopes };
      }
      case "recovery/key": {
        const e = createECDH("prime256v1");
        e.generateKeys();
        const priv = Buffer.alloc(32);
        const k = e.getPrivateKey();
        k.copy(priv, 32 - k.length);
        const id = b64url(randomBytes(32));
        this.recovery.set(id, { priv, session });
        return { attempt_id: id, recipient: b64url(e.getPublicKey()) };
      }
      case "recovery/challenge": {
        const mode = body.mode;
        const a = this.recovery.get(String(body.attempt_id));
        if (!a || a.session !== session) return fail(409, "conflict", "recovery key expired; start again");
        if (typeof body.packet_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(body.packet_sha256)) fail(400, "bad_request", "packet_sha256");
        const canonical: Record<string, unknown> = { ...this.base("recovery", String(mode), String(body.attempt_id)), packet_sha256: body.packet_sha256 };
        if (mode === "drill") return b.plainOffer(req, canonicalJSON(canonical), canonical, session);
        if (mode !== "enrol") return fail(400, "bad_request", "mode");
        const scopes = this.scopesIn(body.scopes);
        const target = String(body.credential_id ?? "");
        if (!scopes.length || !this.deps.store.passkeys.some((p) => p.id === target)) fail(400, "bad_request", "choose a passkey and scopes");
        Object.assign(canonical, { credential_id: target, scopes });
        const browser = typeof body.browser_key === "string" && body.browser_key ? body.browser_key : undefined;
        if (!browser && b.browsers.get(target)?.length) fail(409, "conflict", "this passkey opens buckets only from remembered browsers: enrol it for this browser, or forget its browsers first");
        if (browser) {
          if (b.wraps.get(target)?.size) fail(409, "conflict", "this passkey opens buckets with its own secret (PRF): a remembered browser is only for passkeys without PRF");
          if (typeof body.browser_label !== "string" || !body.browser_label) fail(400, "bad_request", "a browser label has 1 to 64 printable characters, single spaces");
          Object.assign(canonical, { browser_key: browser, browser_key_id: browserKeyId(raw(browser)), browser_label: body.browser_label });
        }
        return b.enrolOffer(req, canonicalJSON(canonical), canonical, session, { purpose: "enrol", credential: target, scopes, browser });
      }
      case "recovery/finish": {
        const f = await b.finish(body, session);
        const c = f.canonical;
        const a = this.recovery.get(String(c.id));
        if (c.object !== "recovery" || !a) return fail(409, "conflict", "wrong ceremony");
        this.recovery.delete(String(c.id));
        const packet = raw(body.packet);
        if (createHash("sha256").update(packet).digest("hex") !== c.packet_sha256) fail(400, "bad_request", "the packet differs from the one signed");
        let identity = "";
        try {
          const recipientKey = await suite.kem.importKey("raw", ab(a.priv), false);
          const ctx = await suite.createRecipientContext({ recipientKey, enc: ab(packet.subarray(0, 65)), info: ab(openInfo(raw(b.installation), "recovery")) });
          const empty = new Uint8Array(0);
          identity = Buffer.from(await ctx.open(ab(packet.subarray(65)), ab(openAAD(raw(c.id), raw(b.epoch), empty, empty)))).toString("utf8");
        } catch {
          fail(400, "bad_request", "the recovery packet did not open");
        }
        if (!/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(identity.trim())) fail(403, "forbidden", "that is not the recovery key");
        const keyed = b.scopes.filter((s) => s.has_key).map((s) => s.scope);
        if (c.action === "drill") return { ok: true, scopes: keyed.length, buckets: b.buckets.filter((x) => keyed.includes(x.scope)).length };
        const scopes = c.scopes as string[];
        if (typeof c.browser_key === "string") await b.rememberBrowser(new URL(req.url).hostname, f.cred, c.browser_key, String(c.browser_label), scopes, f.attempt!.salts.get(f.cred)!, f.keks!);
        else this.wrap(f.cred, scopes, f.attempt!.salts.get(f.cred)!, f.keks!);
        return { ok: true, scopes: scopes.length, buckets: b.buckets.filter((x) => scopes.includes(x.scope)).length };
      }
    }
    return undefined;
  }
}
