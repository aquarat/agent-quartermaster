// Mock of the Credential sets page's server side (docs/API.md "Vault") for `bun run mock`,
// the tests and the screenshots: neutral made-up organisations, real HPKE both ways and real
// signer keys, so the page's own crypto and canonical checks are exercised. Like the rest of
// the mock, passkey signatures are not verified.
//
//   GET /mock/vault?locked=0|1   turns the sealed, organisation-scoped view on (mock only)

import { createECDH, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { suite, tuple } from "../src/seal";
import { canonicalJSON, editChanges, editCommitment, type Edit, type SignItem, type SignRequest, type VaultOrg, type VaultSet } from "../src/vault";

const b64url = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const hex = (b: Uint8Array | Buffer) => Buffer.from(b).toString("hex");
const sha256 = (b: string | Uint8Array) => createHash("sha256").update(b).digest();
const utf8 = (s: string) => new TextEncoder().encode(s);
const ab = (b: Uint8Array) => new Uint8Array(b).buffer as ArrayBuffer;
const nowISO = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
const id32 = (seed: string) => sha256("mock-id:" + seed).subarray(0, 16).toString("hex");

export interface VaultDeps {
  issue(text: string, canonical: Record<string, unknown>, session: string | undefined): { id: string; challenge: string };
  redeem(challengeId: unknown, assertion: unknown, session: string | undefined): Record<string, unknown>;
  requestOptions(req: Request, challenge: string): unknown;
  fail(status: number, code: string, message: string): never;
  audit(action: string, object: string, detail: string): void;
}

const SCHEMES = [
  { id: "ed25519", title: "Ed25519 (pure, RFC 8032)", key: "ed25519", input: "message", signed: "the artifact's own bytes", output: "64 raw bytes (R || S)", check: "openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in FILE -sigfile FILE.sig" },
  { id: "ed25519-sha256", title: "Ed25519 over the SHA-256 digest", key: "ed25519", input: "sha256", signed: "the 32 raw bytes of the artifact's SHA-256 (pure Ed25519 over that digest)", output: "64 raw bytes (R || S)", check: "openssl dgst -sha256 -binary FILE > d && openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in d -sigfile FILE.sig" },
  { id: "ed25519ph", title: "Ed25519ph (RFC 8032 prehash, SHA-512)", key: "ed25519", input: "sha512", signed: "the artifact's SHA-512, as Ed25519ph with an empty context", output: "64 raw bytes (R || S)", check: "an RFC 8032 Ed25519ph verifier (empty context) over FILE" },
  { id: "ecdsa-p256-sha256", title: "ECDSA P-256 over SHA-256", key: "ecdsa-p256", input: "sha256", signed: "the artifact's SHA-256 (ECDSA, NIST P-256)", output: "ASN.1 DER (r, s)", check: "openssl dgst -sha256 -verify pub.pem -signature FILE.sig FILE" },
];

function spki(raw: Uint8Array): string {
  const prefix = raw.length === 32 ? "302a300506032b6570032100" : "3059301306072a8648ce3d020106082a8648ce3d030107034200";
  const der = Buffer.concat([Buffer.from(prefix, "hex"), raw]);
  return "-----BEGIN PUBLIC KEY-----\n" + der.toString("base64").replace(/(.{64})(?=.)/g, "$1\n") + "\n-----END PUBLIC KEY-----\n";
}
function rawPublic(key: ReturnType<typeof createPublicKey>): Buffer {
  const j = key.export({ format: "jwk" });
  return j.kty === "OKP" ? Buffer.from(j.x!, "base64url") : Buffer.concat([Buffer.from([4]), Buffer.from(j.x!, "base64url"), Buffer.from(j.y!, "base64url")]);
}
/** A new or pasted key's raw public half (the mock keeps no private key at all). */
function keyFor(scheme: string, pasted?: string): Buffer {
  const ed = SCHEMES.find((s) => s.id === scheme)!.key === "ed25519";
  if (pasted === undefined) {
    return rawPublic(ed ? generateKeyPairSync("ed25519").publicKey : generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey);
  }
  const t = pasted.trim();
  if (/^[0-9a-fA-F]+$/.test(t)) {
    const b = Buffer.from(t, "hex");
    if (ed && (b.length === 32 || b.length === 64)) return rawPublic(createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), b.subarray(0, 32)]), format: "der", type: "pkcs8" })));
    if (!ed && b.length === 32) {
      const e = createECDH("prime256v1");
      e.setPrivateKey(b);
      return e.getPublicKey();
    }
    throw new Error("not an unencrypted private key");
  }
  const k = createPrivateKey(t);
  if ((k.asymmetricKeyType === "ed25519") !== ed) throw new Error("not an unencrypted private key");
  return rawPublic(createPublicKey(k));
}

interface Attempt {
  session: string | undefined;
  priv: Buffer;
  expires: number;
  purpose?: "edit" | "signer-import" | "signer-generate";
  target?: string;
  enc?: Buffer;
  ct?: Buffer;
  commitment?: string;
  scheme?: string;
  pub?: Buffer;
  /** The upload recipient handed out for this attempt (base64url), signed in the canonical. */
  recipient?: string;
}

export class MockVault {
  enabled = false;
  locked = false;
  readonly installation = b64url(sha256("mock installation"));
  readonly epoch = b64url(randomBytes(32));
  orgs: VaultOrg[] = [];
  sets: VaultSet[] = [];
  requests: SignRequest[] = [];
  private values = new Map<string, Map<string, string>>();
  private attempts = new Map<string, Attempt>();

  constructor(private deps: VaultDeps) {
    this.seed();
  }

  private seed(): void {
    const org = (slug: string, title: string, reveal = true) => {
      const o = { id: id32("org:" + slug), slug, title, allow_reveal: reveal };
      this.orgs.push(o);
      return o;
    };
    const personal = org("personal", "Personal"), client = org("client-a", "Client A"), club = org("club", "Club", false);
    const set = (o: VaultOrg, svc: string, svcTitle: string, slug: string, title: string, revision: number, values: Record<string, string>): VaultSet => {
      const s: VaultSet = { org_id: o.id, org_slug: o.slug, org_title: o.title, service_id: id32(o.slug + "/" + svc), service_slug: svc, service_title: svcTitle, set_id: id32(o.slug + "/" + svc + "/" + slug), set_slug: slug, set_title: title, kind: "env-set", revision, names: Object.keys(values).sort(), allow_reveal: o.allow_reveal, signatures: 0 };
      this.sets.push(s);
      this.values.set(s.set_id, new Map(Object.entries(values)));
      return s;
    };
    const signer = (o: VaultOrg, svc: string, svcTitle: string, slug: string, title: string, scheme: string, signatures: number): VaultSet => {
      const s = set(o, svc, svcTitle, slug, title, 0, {}); // a signer set stays at revision 0
      const pub = keyFor(scheme);
      Object.assign(s, { kind: "signer", scheme, origin: "generated", created_at: Date.now() - 9 * 86_400_000, signatures, public_key: b64url(pub), public_hex: hex(pub), public_pem: spki(pub), fingerprint: hex(sha256(pub)) });
      this.values.delete(s.set_id);
      return s;
    };
    set(client, "paas", "PaaS", "staging", "Staging env", 7, {
      APP_SECRET: "mock-app-secret-2f9c1e",
      DATABASE_URL: "postgres://app:mock-password@db.example.com:5432/staging",
      SMTP_PASSWORD: "mock smtp pass with spaces",
      TLS_KEY: "-----BEGIN PRIVATE KEY-----\nTU9DSyBLRVkgTUFURVJJQUwsIE5PVCBBIFJFQUwgS0VZ\nbW9jayBsaW5lIHR3bw==\n-----END PRIVATE KEY-----\n",
    });
    set(client, "paas", "PaaS", "production", "Production env", 0, {});
    set(club, "website", "Website", "deploy", "Deploy secrets", 2, { DEPLOY_TOKEN: "mock-deploy-token", APP_ID: "club-site" });
    const manifestKey = signer(personal, "firmware", "Firmware", "release-key", "Release key", "ed25519", 12);
    const imageKey = signer(personal, "firmware", "Firmware", "image-key", "Image key", "ed25519-sha256", 3);
    const request = (s: VaultSet, id: string, host: string, address: string, reason: string, items: SignItem[], ttl: number, max: number, status = "pending", used = 0): void => {
      this.requests.push({
        path: `${s.org_slug}/${s.service_slug}/${s.set_slug}`, title: `${s.org_title} / ${s.service_title} / ${s.set_title}`, org: s.org_id, service: s.service_id, set: s.set_id, revision: 0, service_revision: 1, policy_revision: 1, admission_generation: 1,
        enrollment: id32("enrollment:" + host), host, class: "fleet", scheme: s.scheme!, public_key: Buffer.from(s.public_key!, "base64url").toString("base64"), default_seconds: 3600, soft_cap_seconds: 86400,
        id, grant_id: status === "approved" ? "01MOCKGRANT" + id.slice(-6) : "", address, reason, items, ttl_seconds: ttl, max_signatures: max, deadline: Date.now() + 540_000, not_after: status === "approved" ? Date.now() + 1_260_000 : 0, status, used,
      });
    };
    const manifest = Buffer.concat([Buffer.from("S1M1"), Buffer.alloc(12, 1), sha256("mock image"), Buffer.alloc(92, 7)]);
    request(manifestKey, "01MOCKSIGNREQUEST0000A7K2QD", "build-1", "192.0.2.14", "sign the 2026.11 release manifest", [{ name: "manifest.bin", size: manifest.length, sha256: hex(sha256(manifest)), message: manifest.toString("base64") }], 0, 1);
    request(imageKey, "01MOCKSIGNREQUEST0000B3X9TM", "build-1", "192.0.2.14", "nightly image builds", [
      { name: "image-a.bin", size: 342852, sha256: hex(sha256("mock image a")) },
      { name: "image-b.bin", size: 339104, sha256: hex(sha256("mock image b")) },
    ], 1800, 20);
    request(imageKey, "01MOCKSIGNREQUEST0000C5R1WZ", "laptop", "198.51.100.7", "bench images", [{ name: "bench.bin", size: 120044, sha256: hex(sha256("mock bench")) }], 3600, 10, "approved", 4);
  }

  sealStatus() {
    return { mode: this.locked ? "locked" : "unlocked", epoch: this.epoch, installation: this.installation, choices: [] };
  }
  catalogue() {
    return {
      owner_id: id32("owner"),
      organisations: this.orgs.map((o) => ({
        id: o.id, slug: o.slug, title: o.title, revision: 1, hosts: [], auto_access: [], rules: [],
        policy: { default_seconds: 3600, soft_cap_seconds: 86400, indefinite: true, standing_default_seconds: 3600, standing_soft_cap_seconds: 86400, standing_indefinite: true },
        services: [...new Map(this.sets.filter((s) => s.org_id === o.id).map((s) => [s.service_id, s])).values()].map((v) => ({
          id: v.service_id, slug: v.service_slug, title: v.service_title, revision: 1, provider: "application",
          sets: this.sets.filter((s) => s.service_id === v.service_id).map((s) => ({ id: s.set_id, slug: s.set_slug, title: s.set_title, revision: s.revision, kind: s.kind, archived: false })),
        })),
      })),
    };
  }
  private state() {
    return { unlocked: !this.locked, schemes: SCHEMES, organisations: this.orgs, sets: this.sets.map((s) => ({ ...s, allow_reveal: this.orgs.find((o) => o.id === s.org_id)!.allow_reveal })), requests: this.requests.filter((r) => r.status === "pending" || r.status === "approved") };
  }
  private target(s: VaultSet) {
    return { org_id: s.org_id, org_slug: s.org_slug, org_title: s.org_title, service_id: s.service_id, service_slug: s.service_slug, service_title: s.service_title, set_id: s.set_id, set_slug: s.set_slug, set_title: s.set_title, kind: s.kind, revision: s.revision };
  }
  private async open(a: Attempt, purpose: string, attempt: string, set: string): Promise<Buffer> {
    try {
      const recipientKey = await suite.kem.importKey("raw", ab(a.priv), false);
      const ctx = await suite.createRecipientContext({ recipientKey, enc: ab(a.enc!), info: ab(tuple("hpke-vault", Buffer.from(this.installation, "base64url"), utf8(purpose))) });
      return Buffer.from(await ctx.open(ab(a.ct!), ab(tuple("hpke-vault-aad", Buffer.from(attempt, "base64url"), Buffer.from(this.epoch, "base64url"), utf8(set)))));
    } catch {
      return this.deps.fail(400, "bad_request", "the sealed packet could not be opened; start again");
    }
  }
  private live(session: string | undefined, id: unknown): Attempt {
    const a = typeof id === "string" ? this.attempts.get(id) : undefined;
    if (!a || a.session !== session || a.expires < Date.now()) return this.deps.fail(409, "conflict", "upload attempt expired or already used; start again");
    return a;
  }
  private submit(session: string | undefined, c: Record<string, unknown>, purpose: "edit" | "signer-import", target: string): Attempt {
    const a = this.live(session, c.attempt_id);
    if (a.purpose) this.deps.fail(409, "conflict", "upload attempt already used; start again");
    if (typeof c.enc !== "string" || typeof c.ciphertext !== "string") this.deps.fail(400, "bad_request", "invalid sealed packet");
    Object.assign(a, { purpose, target, enc: Buffer.from(c.enc as string, "base64url"), ct: Buffer.from(c.ciphertext as string, "base64url"), commitment: c.commitment, scheme: c.scheme });
    return a;
  }

  /** Validates a choice against current data and returns the metadata that gets signed. */
  private async review(session: string | undefined, c: Record<string, unknown>, begin: boolean): Promise<{ meta: Record<string, unknown>; facts: Record<string, unknown> }> {
    const fail = this.deps.fail;
    const facts: Record<string, unknown> = {};
    const setOf = (id: unknown) => this.sets.find((s) => s.set_id === id) ?? fail(404, "not_found", "not found");
    const needUnlocked = () => {
      if (this.locked) fail(423, "locked", "waiting for owner unlock; retry within the original deadline");
    };
    switch (c.action) {
      case "policy": {
        const o = this.orgs.find((x) => x.id === c.id) ?? fail(404, "not_found", "not found");
        if (typeof c.allow_reveal !== "boolean" || c.allow_reveal === o.allow_reveal) fail(409, "conflict", "policy already has that value; reload");
        if (c.allow_reveal) needUnlocked();
        return { meta: { org_id: o.id, org_slug: o.slug, org_title: o.title, old_allow_reveal: o.allow_reveal, allow_reveal: c.allow_reveal }, facts };
      }
      case "commit": {
        const s = setOf(c.id);
        if (s.kind !== "env-set") fail(400, "bad_request", "not an env set");
        needUnlocked();
        const a = begin ? this.submit(session, c, "edit", s.set_id) : this.live(session, c.attempt_id);
        if (a.purpose !== "edit" || a.target !== s.set_id) fail(409, "conflict", "upload attempt expired; start again");
        const edit = JSON.parse((await this.open(a, "edit", c.attempt_id as string, s.set_id)).toString("utf8")) as Edit & { salt: string };
        if (edit.operation !== "merge" && edit.operation !== "import") fail(400, "bad_request", "invalid form edit");
        const e = { operation: edit.operation, entries: edit.entries ?? [], remove: edit.remove ?? [], salt: new Uint8Array(Buffer.from(edit.salt, "base64")) };
        let commitment = "", changes = "";
        try {
          commitment = await editCommitment(e, { org: s.org_id, service: s.service_id, set: s.set_id, revision: s.revision });
          changes = editChanges(e, s.names);
        } catch (err) {
          fail(400, "bad_request", (err as Error).message);
        }
        if (commitment !== a.commitment) fail(400, "bad_request", "invalid edit commitment");
        facts.attempt_id = c.attempt_id;
        facts.edit = e; // mock-internal, removed before the response
        return { meta: { ...this.target(s), attempt_id: c.attempt_id, operation: e.operation, changes, commitment, result_revision: s.revision + 1, recipient: a.recipient ?? "" }, facts };
      }
      case "reveal": {
        const s = setOf(c.id);
        const o = this.orgs.find((x) => x.id === s.org_id)!;
        if (s.kind !== "env-set") fail(403, "forbidden", "a signer key is never revealed");
        if (!o.allow_reveal) fail(403, "forbidden", "this organisation does not allow reveal");
        needUnlocked();
        const names = c.names as string[];
        if (!Array.isArray(names) || !names.length || names.some((n, i) => !s.names.includes(n) || (i > 0 && names[i - 1]! >= n))) fail(400, "bad_request", "name the keys to reveal, sorted, each once");
        const pub = typeof c.recipient === "string" ? Buffer.from(c.recipient, "base64url") : Buffer.alloc(0);
        if (pub.length !== 65 || pub[0] !== 4) fail(400, "bad_request", "invalid reveal recipient");
        return { meta: { ...this.target(s), names, recipient: c.recipient }, facts };
      }
      case "signer-create": {
        const parent = this.sets.find((s) => s.service_id === c.service_id) ?? fail(404, "not_found", "not found");
        const scheme = SCHEMES.find((x) => x.id === c.scheme);
        if (!scheme || typeof c.id !== "string" || !/^[0-9a-f]{32}$/.test(c.id) || typeof c.set_slug !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(c.set_slug) || typeof c.set_title !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$/.test(c.set_title)) return fail(400, "bad_request", "invalid signer set");
        if (this.sets.some((s) => s.set_id === c.id || (s.service_id === parent.service_id && s.set_slug === c.set_slug))) fail(409, "conflict", "a set with that name or ID exists; reload");
        needUnlocked();
        let attempt = c.attempt_id as string | undefined;
        let pub: Buffer;
        let recipient = "";
        if (c.source === "generate" && begin) {
          attempt = b64url(randomBytes(32));
          pub = keyFor(scheme.id);
          this.attempts.set(attempt, { session, priv: Buffer.alloc(0), expires: Date.now() + 300_000, purpose: "signer-generate", target: c.id, scheme: scheme.id, pub });
        } else if (c.source === "generate") {
          const a = this.live(session, attempt);
          if (a.purpose !== "signer-generate" || a.target !== c.id || a.scheme !== scheme.id) fail(409, "conflict", "generated key expired; start again");
          pub = a.pub!;
        } else if (c.source === "import") {
          const a = begin ? this.submit(session, c, "signer-import", c.id) : this.live(session, attempt);
          if (a.purpose !== "signer-import" || a.target !== c.id || a.scheme !== scheme.id) fail(409, "conflict", "upload attempt expired; start again");
          recipient = a.recipient ?? "";
          const packet = JSON.parse((await this.open(a, "signer-import", attempt!, c.id)).toString("utf8")) as { private_key?: string };
          try {
            pub = keyFor(scheme.id, String(packet.private_key ?? ""));
          } catch {
            return fail(400, "bad_request", `not an unencrypted ${scheme.key} private key (hex seed, PKCS#8, SEC1 or OpenSSH PEM)`);
          }
        } else return fail(400, "bad_request", "choose generate or import");
        Object.assign(facts, { attempt_id: attempt, public_key: b64url(pub), fingerprint: hex(sha256(pub)), public_hex: hex(pub), public_pem: spki(pub) });
        return {
          meta: { org_id: parent.org_id, org_slug: parent.org_slug, org_title: parent.org_title, service_id: parent.service_id, service_slug: parent.service_slug, service_title: parent.service_title, set_id: c.id, set_slug: c.set_slug, set_title: c.set_title, kind: "signer", revision: 0, scheme: scheme.id, source: c.source, attempt_id: attempt, public_key: b64url(pub), fingerprint: hex(sha256(pub)), result_revision: 0, recipient },
          facts,
        };
      }
      case "sign-approve":
      case "sign-deny":
      case "sign-revoke": {
        const r = this.requests.find((x) => x.id === c.id) ?? fail(404, "not_found", "not found");
        if ((c.action === "sign-revoke") !== (r.status === "approved") || (c.action !== "sign-revoke" && r.status !== "pending")) fail(409, "conflict", "decision no longer available");
        const s = setOf(r.set);
        const ttl = Number(c.ttl_seconds ?? 0), max = Number(c.max_signatures ?? 0);
        if (c.action === "sign-approve") {
          needUnlocked();
          const single = ttl === 0 && max === r.items.length;
          const timed = r.ttl_seconds > 0 && ttl > 0 && ttl <= r.ttl_seconds && max >= 1 && max <= r.max_signatures;
          if (!single && !timed) fail(400, "bad_request", "duration or count exceeds the request");
        } else if (ttl !== 0 || max !== 0) fail(400, "bad_request", "unexpected duration");
        return {
          meta: {
            ...this.target(s), request_id: r.id, host: r.host, enrollment: r.enrollment, address: r.address, scheme: r.scheme, fingerprint: hex(sha256(Buffer.from(r.public_key, "base64"))),
            items: r.items.map((it) => (it.sha512 ? { name: it.name, size: it.size, sha256: it.sha256, sha512: it.sha512 } : { name: it.name, size: it.size, sha256: it.sha256 })),
            requested_ttl_seconds: r.ttl_seconds, requested_max_signatures: r.max_signatures, ttl_seconds: ttl, max_signatures: max,
            admission_generation: r.admission_generation, policy_revision: r.policy_revision, service_revision: r.service_revision, soft_cap_seconds: r.soft_cap_seconds, beyond_soft_cap: ttl > r.soft_cap_seconds,
          },
          facts,
        };
      }
    }
    return fail(400, "bad_request", "unknown vault action");
  }

  /** Returns undefined for a path that is not the vault's (or when the view is off). */
  async handle(req: Request, url: URL, body: Record<string, unknown>, session: string | undefined): Promise<unknown> {
    if (!this.enabled) return undefined;
    const p = url.pathname, post = req.method === "POST", fail = this.deps.fail;
    if (p === "/api/ui/seal/status" && !post) return this.sealStatus();
    if (p === "/api/ui/seal/env/state" && !post) return { drafts: [], releases: [] };
    if (p === "/api/ui/catalogue" && !post) return this.catalogue();
    if (!p.startsWith("/api/ui/seal/vault/")) return undefined;
    const verb = p.slice("/api/ui/seal/vault/".length);
    if (verb === "state" && !post) return this.state();
    if (verb === "attempt" && post) {
      if (this.locked) fail(423, "locked", "waiting for owner unlock; retry within the original deadline");
      const e = createECDH("prime256v1");
      e.generateKeys();
      const priv = Buffer.alloc(32);
      e.getPrivateKey().copy(priv, 32 - e.getPrivateKey().length);
      const id = b64url(randomBytes(32));
      this.attempts.set(id, { session, priv, expires: Date.now() + 300_000, recipient: b64url(e.getPublicKey()) });
      return { attempt_id: id, recipient: b64url(e.getPublicKey()), expires_at: Date.now() + 300_000 };
    }
    if (verb === "challenge" && post) {
      const { meta, facts } = await this.review(session, body, true);
      delete facts.edit;
      const canonical = { v: 3, object: "vault", action: body.action, id: body.id, installation: this.installation, epoch: this.epoch, issued_at: nowISO(), nonce: b64url(randomBytes(32)), metadata: canonicalJSON(meta) };
      const text = canonicalJSON(canonical);
      const ch = this.deps.issue(text, { ...canonical, text }, session);
      return { canonical: text, challenge_id: ch.id, public_key: this.deps.requestOptions(req, ch.challenge), facts };
    }
    if (verb === "finish" && post) {
      const c = this.deps.redeem(body.challenge_id, body.assertion, session);
      if (c.object !== "vault") fail(409, "conflict", "wrong ceremony");
      const signed = JSON.parse(c.metadata as string) as Record<string, unknown>;
      const choice: Record<string, unknown> = { action: c.action, id: c.id, attempt_id: signed.attempt_id, names: signed.names, recipient: signed.recipient, allow_reveal: signed.allow_reveal, service_id: signed.service_id, set_slug: signed.set_slug, set_title: signed.set_title, scheme: signed.scheme, source: signed.source, ttl_seconds: signed.ttl_seconds, max_signatures: signed.max_signatures };
      let reviewed: Awaited<ReturnType<MockVault["review"]>>;
      try {
        reviewed = await this.review(session, choice, false);
      } finally {
        if (typeof signed.attempt_id === "string") queueMicrotask(() => this.attempts.delete(signed.attempt_id as string));
      }
      if (canonicalJSON(reviewed.meta) !== c.metadata) fail(409, "conflict", "the proposal changed; review again");
      switch (c.action) {
        case "policy": {
          const o = this.orgs.find((x) => x.id === c.id)!;
          o.allow_reveal = signed.allow_reveal as boolean;
          this.deps.audit("vault_policy", "org:" + o.id, `org=${o.slug} allow_reveal=${o.allow_reveal}`);
          return { ok: true };
        }
        case "commit": {
          const s = this.sets.find((x) => x.set_id === c.id)!;
          const edit = reviewed.facts.edit as Edit;
          const values = edit.operation === "import" ? new Map<string, string>() : this.values.get(s.set_id)!;
          for (const e of edit.entries) values.set(e.name, e.value);
          for (const n of edit.remove) values.delete(n);
          this.values.set(s.set_id, values);
          s.revision++;
          s.names = [...values.keys()].sort();
          this.deps.audit("vault_commit", "set:" + s.set_id, `${s.org_slug}/${s.service_slug}/${s.set_slug} revision=${s.revision} changes=${signed.changes}`);
          return { ok: true };
        }
        case "reveal": {
          const s = this.sets.find((x) => x.set_id === c.id)!;
          const names = signed.names as string[];
          const plain = utf8(JSON.stringify({ entries: names.map((n) => ({ name: n, value: this.values.get(s.set_id)!.get(n)! })) }));
          const recipientPublicKey = await suite.kem.deserializePublicKey(ab(Buffer.from(signed.recipient as string, "base64url")));
          const sender = await suite.createSenderContext({ recipientPublicKey, info: ab(tuple("hpke-vault", Buffer.from(this.installation, "base64url"), utf8("reveal"))) });
          const ct = await sender.seal(ab(plain), ab(tuple("hpke-vault-aad", sha256(c.text as string), Buffer.from(this.epoch, "base64url"), utf8(s.set_id))));
          this.deps.audit("vault_reveal", "set:" + s.set_id, `${s.org_slug}/${s.service_slug}/${s.set_slug} revision=${s.revision} names=${names.join(",")}`);
          return { enc: b64url(new Uint8Array(sender.enc)), ciphertext: b64url(new Uint8Array(ct)) };
        }
        case "signer-create": {
          const m = reviewed.meta as Record<string, string>;
          const pub = Buffer.from(m.public_key!, "base64url");
          const s: VaultSet = { org_id: m.org_id!, org_slug: m.org_slug!, org_title: m.org_title!, service_id: m.service_id!, service_slug: m.service_slug!, service_title: m.service_title!, set_id: m.set_id!, set_slug: m.set_slug!, set_title: m.set_title!, kind: "signer", revision: 0, names: [], allow_reveal: true, scheme: m.scheme, origin: m.source === "import" ? "imported" : "generated", created_at: Date.now(), signatures: 0, public_key: m.public_key, public_hex: hex(pub), public_pem: spki(pub), fingerprint: m.fingerprint };
          this.sets.push(s);
          this.deps.audit("vault_signer_create", "set:" + s.set_id, `${s.org_slug}/${s.service_slug}/${s.set_slug} scheme=${s.scheme} origin=${s.origin} fingerprint=${s.fingerprint}`);
          return { set_id: s.set_id, path: `${s.org_slug}/${s.service_slug}/${s.set_slug}`, scheme: s.scheme, public_key: s.public_key, public_hex: s.public_hex, public_pem: s.public_pem, fingerprint: s.fingerprint };
        }
        default: {
          const r = this.requests.find((x) => x.id === c.id)!;
          if (c.action === "sign-approve") {
            const ttl = signed.ttl_seconds as number;
            Object.assign(r, { status: "approved", grant_id: "01MOCKGRANT" + r.id.slice(-6), ttl_seconds: ttl, max_signatures: signed.max_signatures, not_after: Date.now() + (ttl > 0 ? ttl : 600) * 1000 });
          } else r.status = c.action === "sign-deny" ? "denied" : "revoked";
          this.deps.audit("vault_" + String(c.action).replace("-", "_"), "request:" + r.id, `${r.path} host=${r.host}`);
          return { ok: true };
        }
      }
    }
    return fail(404, "not_found", "not found");
  }
}
