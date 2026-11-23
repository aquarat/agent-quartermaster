// Mock of seal format 2 (docs/BUCKETS.md) for `bun run mock` and the tests: the status Admin →
// Buckets shows, seal control (close all, reopen, rekey, renew leaf) and the open descriptor
// every bucket-opening challenge carries. The KEK packet is opened for real (HPKE with the
// contract's Info/AAD), so the page's construction is exercised; KEKs are checked against
// the first one seen per passkey and scope (a stand-in for the real scope wrap). Passkey
// signatures are not verified, as in the rest of the mock.

import { createECDH, createHash, randomBytes } from "node:crypto";
import { canonicalJSON, openAAD, openChallenge, openInfo, type OpenBucket } from "../src/buckets";
import { suite } from "../src/seal";

const b64url = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const raw = (s: unknown) => Buffer.from(typeof s === "string" ? s : "", "base64url");
const ab = (b: Uint8Array) => new Uint8Array(b).buffer as ArrayBuffer;
const hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const nowISO = (t = Date.now()) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");

export interface MockBucket {
  id: string;
  kind: string;
  label: string;
  scope: string;
  open: boolean;
  opened_at?: string;
  holds: { kind: string; ref: string; reason: string; until?: string; since: string }[];
  paused: { kind: string; ref: string; reason: string }[];
}
export interface MockScope {
  scope: string;
  title: string;
  has_key: boolean;
}
export interface MockWrap {
  salt: string;
  tested: boolean;
  /** SHA-256 of the KEK first seen (mock stand-in for the XChaCha wrap). */
  kek?: string;
}
export interface OpenAttempt {
  id: string;
  session: string | undefined;
  priv: Buffer;
  pub: Buffer;
  descriptor: Record<string, unknown>;
  text: string;
  challenge: Buffer;
  /** Per credential (raw, base64url): the salts, aligned with scopes. */
  salts: Map<string, string[]>;
  expires: number;
}
export interface Finished {
  canonical: Record<string, unknown>;
  /** The raw credential ID that signed. */
  cred: string;
  attempt?: OpenAttempt;
  /** The KEKs from the packet (scope-enrol: [legacy?, …scopes]); undefined without a packet. */
  keks?: Buffer[];
}
export interface BucketDeps {
  passkeys(): { id: string; hex: string; name: string }[];
  sessionPasskey(session: string | undefined): string | undefined;
  issue(text: string, canonical: Record<string, unknown>, session: string | undefined, challenge: Buffer): { id: string; challenge: string };
  redeem(challengeId: unknown, assertion: unknown, session: string | undefined): Record<string, unknown>;
  requestOptions(req: Request, challenge: string): { publicKey: Record<string, unknown> };
  fail(status: number, code: string, message: string): never;
  audit(action: string, object: string, detail: string): void;
}

export class MockBuckets {
  enabled = false;
  mode: "buckets" | "migration-required" = "buckets";
  scopes: MockScope[] = [];
  buckets: MockBucket[] = [];
  /** credential (raw base64url) -> scope -> wrap */
  wraps = new Map<string, Map<string, MockWrap>>();
  /** Passkeys (raw base64url) that return no PRF result. */
  noPrf = new Set<string>();
  attempts = new Map<string, OpenAttempt>();
  /** challenge id -> attempt id */
  private byChallenge = new Map<string, string>();
  /** Every open packet received, decrypted (tests read this). */
  packets: { purpose: string; keks: Buffer[] }[] = [];
  leafRepair = "";

  constructor(
    private deps: BucketDeps,
    readonly installation: string,
    readonly epoch: string,
  ) {}

  /** Neutral seed: the installation and three organisations, a few buckets, one paused grant. */
  seed(orgs: { id: string; slug: string; title: string }[], sets: { set_id: string; org_id: string; org_slug: string; service_slug: string; set_slug: string; kind: string }[]): void {
    this.scopes = [{ scope: "installation", title: "Installation", has_key: true }, ...orgs.map((o) => ({ scope: o.id, title: o.title, has_key: o.slug !== "club" }))];
    const id = (s: string) => b64url(createHash("sha256").update("mock-bucket:" + s).digest());
    const add = (kind: string, label: string, scope: string): MockBucket => {
      const b: MockBucket = { id: id(kind + label), kind, label, scope, open: false, holds: [], paused: [] };
      this.buckets.push(b);
      return b;
    };
    const ssh = add("ssh-ca", "SSH user CA", "installation");
    add("internal-ca", "Internal CA", "installation");
    const personal = orgs.find((o) => o.slug === "personal");
    if (personal) {
      const cf = add("cf-proxy", "personal Cloudflare proxy token", personal.id);
      cf.paused.push({ kind: "grant", ref: "01MOCKGRANTCF0001", reason: "Cloudflare proxy grant for web-1 (cf.read)" });
    }
    for (const s of sets) {
      const scope = this.scopes.find((x) => x.scope === s.org_id);
      if (scope?.has_key) add(s.kind === "signer" ? "signer" : "env", `${s.org_slug}/${s.service_slug}/${s.set_slug}`, s.org_id);
    }
    ssh.open = true;
    ssh.opened_at = nowISO(Date.now() - 600_000);
    ssh.holds.push({ kind: "standing", ref: "01MOCKSTANDING0001", reason: "standing rule web-1 → alice@db-1", until: nowISO(Date.now() + 3 * 3600_000), since: ssh.opened_at });
    // Every seeded passkey but the last opens every keyed scope.
    const pks = this.deps.passkeys();
    pks.forEach((p, i) => {
      if (i < pks.length - 1 || pks.length === 1) this.enableAll(p.id);
    });
  }

  /** Give a passkey wraps for every keyed scope (tested). */
  enableAll(cred: string): void {
    const m = this.wraps.get(cred) ?? new Map<string, MockWrap>();
    for (const s of this.scopes) if (s.has_key && !m.has(s.scope)) m.set(s.scope, { salt: b64url(randomBytes(32)), tested: true });
    this.wraps.set(cred, m);
  }

  bucket(id: string): MockBucket {
    return this.buckets.find((b) => b.id === id) ?? this.deps.fail(404, "not_found", "no such bucket");
  }
  /** Buckets of a kind (and optional label prefix): what an action needs. */
  find(kind: string, scope?: string): MockBucket | undefined {
    return this.buckets.find((b) => b.kind === kind && (scope === undefined || b.scope === scope));
  }

  status(session: string | undefined, extra: Record<string, unknown> = {}) {
    const keyed = this.scopes.filter((s) => s.has_key).map((s) => s.scope);
    const cur = this.deps.sessionPasskey(session);
    return {
      mode: this.mode,
      installation: this.installation,
      epoch: this.epoch,
      scopes: this.scopes.map((s) => ({ ...s, buckets: this.buckets.filter((b) => b.scope === s.scope).length })),
      buckets: this.buckets.map((b) => ({ ...b, scope_title: this.scopes.find((s) => s.scope === b.scope)?.title ?? b.scope })),
      passkeys: this.deps.passkeys().map((p) => {
        const w = this.wraps.get(p.id) ?? new Map<string, MockWrap>();
        const scopes = [...w.entries()].map(([scope, x]) => ({ scope, tested: x.tested }));
        return {
          id: p.hex,
          name: p.name,
          current: p.hex === cur,
          prf: scopes.length > 0, // as the server: "has a wrap", not authenticator capability
          scopes,
          opens: this.buckets.filter((b) => w.has(b.scope)).length,
          of: this.buckets.length,
          missing: keyed.filter((s) => !w.has(s)),
        };
      }),
      active_windows: [],
      profiles: [],
      verified_access: false,
      leaf_expires: nowISO(Date.now() + 20 * 86_400_000),
      ...(this.leafRepair ? { leaf_repair: this.leafRepair } : {}),
      ...extra,
    };
  }

  private newAttempt(session: string | undefined, descriptor: Record<string, unknown>): { attempt: OpenAttempt; text: string } {
    const e = createECDH("prime256v1");
    e.generateKeys();
    const priv = Buffer.alloc(32);
    const k = e.getPrivateKey();
    k.copy(priv, 32 - k.length);
    const id = b64url(randomBytes(32));
    const d = { ...descriptor, attempt_id: id, epoch: this.epoch, installation: this.installation, recipient: b64url(e.getPublicKey()), v: 1 };
    const text = canonicalJSON(d);
    const attempt: OpenAttempt = { id, session, priv, pub: e.getPublicKey(), descriptor: d, text, challenge: Buffer.alloc(0), salts: new Map(), expires: Date.now() + 120_000 };
    this.attempts.set(id, attempt);
    return { attempt, text };
  }

  /** A plain v3 challenge (SHA-256 of the canonical, no open). */
  plainOffer(req: Request, text: string, canonical: Record<string, unknown>, session: string | undefined) {
    const ch = this.deps.issue(text, canonical, session, createHash("sha256").update(text, "utf8").digest());
    return { challenge_id: ch.id, canonical: text, public_key: this.deps.requestOptions(req, ch.challenge) };
  }

  /** A challenge whose tap opens `need` (bucket ids with their holds) or, with no buckets,
   * the keys of `scopes` for the tap (passkey enable). Every needed bucket open and no
   * passkey able to open them → still offered, so a no-PRF passkey can approve. */
  async bucketOffer(req: Request, text: string, canonical: Record<string, unknown>, session: string | undefined, need: { buckets: { id: string; hold: string; until: string }[]; scopes?: string[]; rekey?: boolean }) {
    const list: OpenBucket[] = need.buckets.map((n) => {
      const b = this.bucket(n.id);
      return { hold: n.hold, id: b.id, kind: b.kind, label: b.label, scope: b.scope, until: n.until };
    });
    const scopes = need.scopes ?? [...new Set(list.map((b) => b.scope))].sort((a, b) => (a === "installation" ? -1 : b === "installation" ? 1 : a < b ? -1 : 1));
    if (!scopes.length) return this.plainOffer(req, text, canonical, session);
    if (scopes.length > 2) this.deps.fail(409, "conflict", "one tap opens at most two scopes");
    // A rekey: the second PRF evaluation is at a fresh salt, for the new scope key's wrap.
    const rekeySalt = need.rekey ? b64url(randomBytes(32)) : undefined;
    const { attempt, text: d } = this.newAttempt(session, { buckets: list, object: "bucket-open", purpose: "approve", scopes, ...(rekeySalt ? { rekey_salt: rekeySalt } : {}) });
    const challenge = Buffer.from(await openChallenge(text, d));
    attempt.challenge = challenge;
    const ch = this.deps.issue(text, canonical, session, challenge);
    this.byChallenge.set(ch.id, attempt.id);
    const opts = this.deps.requestOptions(req, ch.challenge);
    const by: Record<string, Record<string, string>> = {};
    for (const p of this.deps.passkeys()) {
      const w = this.wraps.get(p.id);
      if (!w || !scopes.every((s) => w.has(s))) continue;
      const salts = scopes.map((s) => w.get(s)!.salt);
      if (rekeySalt) salts.push(rekeySalt);
      attempt.salts.set(p.id, salts);
      by[p.id] = salts.length === 2 ? { first: salts[0]!, second: salts[1]! } : { first: salts[0]! };
    }
    if (Object.keys(by).length) opts.publicKey.extensions = { prf: { evalByCredential: by } };
    return { challenge_id: ch.id, canonical: text, public_key: opts, open: { descriptor: d } };
  }

  /** A scope-enrol challenge for one named passkey with explicit salts (enable, test, stage). */
  async enrolOffer(req: Request, text: string, canonical: Record<string, unknown>, session: string | undefined, e: { purpose: "enrol" | "test" | "stage" | "migrate"; credential: string; scopes: string[]; salts?: string[]; legacy?: { mk_version: number; prf_salt: string; installation: string } }) {
    const salts = e.salts ?? e.scopes.map(() => b64url(randomBytes(32)));
    const desc: Record<string, unknown> = { buckets: [], object: "scope-enrol", purpose: e.purpose, scopes: e.scopes, credential_id: e.credential, salts };
    if (e.legacy) desc.legacy = e.legacy;
    const { attempt, text: d } = this.newAttempt(session, desc);
    const challenge = Buffer.from(await openChallenge(text, d));
    attempt.challenge = challenge;
    attempt.salts.set(e.credential, e.legacy ? [e.legacy.prf_salt, ...salts] : salts);
    const ch = this.deps.issue(text, canonical, session, challenge);
    this.byChallenge.set(ch.id, attempt.id);
    const opts = this.deps.requestOptions(req, ch.challenge);
    opts.publicKey.allowCredentials = [{ type: "public-key", id: e.credential }];
    const inputs = attempt.salts.get(e.credential)!;
    opts.publicKey.extensions = { prf: { eval: inputs.length === 2 ? { first: inputs[0], second: inputs[1] } : { first: inputs[0] } } };
    return { challenge_id: ch.id, canonical: text, public_key: opts, open: { descriptor: d } };
  }

  /** Redeem a challenge; open its packet if it carried one. For a bucket-open, check the KEKs,
   * refuse (423) when a needed bucket is closed and no packet came, and apply the holds. */
  async finish(body: Record<string, unknown>, session: string | undefined): Promise<Finished> {
    const cid = body.challenge_id;
    const canonical = this.deps.redeem(cid, body.assertion, session);
    const cred = String((body.assertion as { rawId?: unknown } | undefined)?.rawId ?? "");
    const aid = typeof cid === "string" ? this.byChallenge.get(cid) : undefined;
    if (!aid) {
      if (body.open !== undefined) this.deps.fail(400, "bad_request", "this action opens nothing");
      return { canonical, cred };
    }
    this.byChallenge.delete(cid as string);
    const attempt = this.attempts.get(aid)!;
    this.attempts.delete(aid);
    const d = attempt.descriptor;
    const scopes = d.scopes as string[];
    let keks: Buffer[] | undefined;
    if (body.open !== undefined) {
      const o = body.open as Record<string, unknown>;
      if (o?.attempt_id !== attempt.id) this.deps.fail(400, "bad_request", "open packet is for another attempt");
      keks = await this.openPacket(attempt, raw(cred), raw(o.enc), raw(o.ciphertext));
      this.packets.push({ purpose: d.purpose as string, keks });
    }
    if (d.object === "scope-enrol") {
      if (!keks) this.deps.fail(400, "bad_request", "this step needs the passkey's PRF");
      if (cred !== d.credential_id) this.deps.fail(403, "forbidden", "another passkey answered");
      return { canonical, cred, attempt, keks };
    }
    const list = d.buckets as OpenBucket[];
    if (keks) {
      const w = this.wraps.get(cred);
      if (!w || keks.length !== scopes.length + (d.rekey_salt ? 1 : 0)) this.deps.fail(403, "forbidden", "this passkey cannot open these scopes");
      scopes.forEach((s, i) => {
        const wrap = w!.get(s) ?? this.deps.fail(403, "forbidden", "this passkey cannot open " + s);
        const h = hex(keks![i]!);
        if (wrap.kek && wrap.kek !== h) this.deps.fail(403, "forbidden", "the KEK does not open the scope key");
        wrap.kek = h;
        wrap.tested = true;
      });
    } else {
      const closed = list.filter((b) => !this.bucket(b.id).open);
      if (closed.length) this.deps.fail(423, "locked", `${closed.map((b) => b.label).join(", ")} is closed: approve with a passkey that can open it`);
    }
    const since = nowISO();
    for (const x of list) {
      if (x.hold === "instant") continue;
      const b = this.bucket(x.id);
      if (!b.open) b.opened_at = since;
      b.open = true;
      b.holds.push({ kind: x.hold, ref: String(canonical.id ?? ""), reason: `${x.hold} ${String(canonical.object ?? "")} ${String(canonical.id ?? "").slice(-6)}`, ...(x.until ? { until: x.until } : {}), since });
    }
    return { canonical, cred, attempt, keks };
  }

  private async openPacket(a: OpenAttempt, cred: Buffer, enc: Buffer, ct: Buffer): Promise<Buffer[]> {
    const d = a.descriptor;
    let plain: Buffer;
    try {
      const recipientKey = await suite.kem.importKey("raw", ab(a.priv), false);
      const ctx = await suite.createRecipientContext({ recipientKey, enc: ab(enc), info: ab(openInfo(raw(d.installation), d.purpose as string)) });
      plain = Buffer.from(await ctx.open(ab(ct), ab(openAAD(raw(a.id), raw(d.epoch), a.challenge, cred))));
    } catch {
      return this.deps.fail(400, "bad_request", "the open packet did not open; start again");
    }
    const out: Buffer[] = [];
    let at = 0;
    for (let i = 0; i < 2; i++) {
      const n = plain.readUInt32BE(at);
      at += 4;
      if (n === 0 && i === 1) continue;
      if (n !== 32) this.deps.fail(400, "bad_request", "invalid open packet");
      out.push(plain.subarray(at, at + 32));
      at += 32;
    }
    if (at !== plain.length) this.deps.fail(400, "bad_request", "invalid open packet");
    return out;
  }

  closeAll(): void {
    for (const b of this.buckets) {
      for (const x of b.holds) if (x.kind !== "instant") b.paused.push({ kind: x.kind, ref: x.ref, reason: x.reason });
      b.open = false;
      b.holds = [];
      delete b.opened_at;
    }
  }

  /** /api/ui/seal/status and /api/ui/seal/control/*; undefined for other paths. */
  async handle(req: Request, url: URL, body: Record<string, unknown>, session: string | undefined, extra: () => Record<string, unknown> = () => ({})): Promise<unknown> {
    if (!this.enabled) return undefined;
    const p = url.pathname, post = req.method === "POST", fail = this.deps.fail;
    if (p === "/api/ui/seal/status" && !post) return this.status(session, extra());
    if (this.mode !== "buckets") return undefined;
    if (p === "/api/ui/seal/control/challenge" && post) {
      const action = body.action;
      const canonical: Record<string, unknown> = { v: 3, object: "seal-control", action, id: this.installation, epoch: this.epoch, nonce: b64url(randomBytes(32)), issued_at: nowISO() };
      let need: { id: string; hold: string; until: string }[] = [];
      switch (action) {
        case "close-all":
          canonical.open_buckets = this.buckets.filter((b) => b.open).length;
          break;
        case "renew-leaf":
          if (!this.leafRepair) fail(409, "conflict", "no repair pending");
          canonical.repair = this.leafRepair;
          need = this.buckets.filter((b) => b.kind === "internal-ca").map((b) => ({ id: b.id, hold: "instant", until: "" }));
          break;
        case "reopen": {
          const ids = body.buckets;
          if (!Array.isArray(ids) || !ids.length) fail(400, "bad_request", "name the buckets");
          const list = (ids as string[]).map((id) => this.bucket(id));
          canonical.buckets = list.map((b) => ({ id: b.id, label: b.label }));
          need = list.map((b) => ({ id: b.id, hold: "instant", until: "" }));
          break;
        }
        case "rekey": {
          const s = this.scopes.find((x) => x.scope === body.scope && x.has_key) ?? fail(404, "not_found", "no such scope");
          canonical.scope = s.scope;
          canonical.scope_title = s.title;
          canonical.bucket_count = this.buckets.filter((b) => b.scope === s.scope).length;
          need = this.buckets.filter((b) => b.scope === s.scope).map((b) => ({ id: b.id, hold: "instant", until: "" }));
          return this.bucketOffer(req, canonicalJSON(canonical), canonical, session, { buckets: need, scopes: [s.scope], rekey: true });
        }
        default:
          fail(400, "bad_request", "unknown control action");
      }
      const text = canonicalJSON(canonical);
      return need.length ? this.bucketOffer(req, text, canonical, session, { buckets: need }) : this.plainOffer(req, text, canonical, session);
    }
    if (p === "/api/ui/seal/control/finish" && post) {
      const f = await this.finish(body, session);
      const c = f.canonical;
      if (c.object !== "seal-control") fail(409, "conflict", "wrong ceremony");
      switch (c.action) {
        case "close-all":
          this.closeAll();
          this.deps.audit("seal_close_all", "seal", "");
          break;
        case "renew-leaf":
          this.leafRepair = "";
          break;
        case "reopen":
          for (const x of c.buckets as { id: string }[]) {
            const b = this.bucket(x.id);
            const since = nowISO();
            if (!b.open) b.opened_at = since;
            b.open = true;
            for (const u of b.paused) b.holds.push({ kind: u.kind, ref: u.ref, reason: u.reason, since });
            b.paused = [];
          }
          this.deps.audit("seal_reopen", "seal", (c.buckets as { label: string }[]).map((x) => x.label).join(","));
          break;
        case "rekey":
          for (const b of this.buckets.filter((x) => x.scope === c.scope)) {
            for (const x of b.holds) b.paused.push({ kind: x.kind, ref: x.ref, reason: x.reason });
            b.open = false;
            b.holds = [];
          }
          for (const [cred, m] of this.wraps) if (cred !== f.cred) m.delete(c.scope as string);
          // The tapping passkey's new wrap is at the descriptor's fresh salt, untested.
          this.wraps.get(f.cred)?.forEach((w, s) => {
            if (s !== c.scope) return;
            delete w.kek;
            w.salt = f.attempt!.descriptor.rekey_salt as string;
            w.tested = false;
          });
          this.deps.audit("seal_rekey", "scope:" + String(c.scope), "");
          break;
      }
      return { ok: true };
    }
    return undefined;
  }
}
