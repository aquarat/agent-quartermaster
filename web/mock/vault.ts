// Mock of the Credential sets page's server side (docs/API.md "Vault") for `bun run mock`,
// the tests and the screenshots: neutral made-up organisations, real HPKE both ways and real
// signer keys, so the page's own crypto and canonical checks are exercised. Like the rest of
// the mock, passkey signatures are not verified.
//
//   GET /mock/vault?mode=buckets|migration-required&closed=1   turns the sealed, organisation-scoped view on (mock only)

import { createECDH, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { suite, tuple } from "../src/seal";
import type { MockBuckets } from "./buckets";
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
  /** Seal format 2: reveal and sign-approve open the set's bucket (mock/buckets.ts). */
  buckets?: MockBuckets;
  readonly installation = b64url(sha256("mock installation"));
  readonly epoch = b64url(randomBytes(32));
  orgs: VaultOrg[] = [];
  sets: VaultSet[] = [];
  requests: SignRequest[] = [];
  /** Application services (also ones that have no set yet). */
  services: { id: string; org_id: string; slug: string; title: string }[] = [];
  /** Enrolled hosts and the organisations each is admitted to (catalogue + /api/ui/hosts). */
  hosts: { row_id: number; enrollment: string; name: string; fingerprint: string; class: string; address: string; revoked_at: string | null; orgs: Map<string, { active: boolean; generation: number }> }[] = [];
  /** Per set: audit rows for the item view (newest first). */
  private history = new Map<string, { at: string; actor: string; action: string; object: string; detail: string }[]>();
  private values = new Map<string, Map<string, string>>();
  private attempts = new Map<string, Attempt>();
  /** Per organisation: the policy and its revision, once a replacement was applied. */
  private policies = new Map<string, { policy: Record<string, unknown>; revision: number }>();
  /** Per set: an explicit "longest don't-ask-again" (the default is one hour). */
  private caps = new Map<string, number>();
  /** Env and secret releases hosts asked for, and the "don't ask again" rules. */
  releases: Record<string, unknown>[] = [];
  standing: Record<string, unknown>[] = [];

  /** A host asks for a set (as `aqmas run` or `aqmas get` would): a pending release. */
  addRelease(path: string, mode: string, host = "build-1", reason = "list devices for the inventory report"): string {
    const s = this.sets.find((x) => `${x.org_slug}/${x.service_slug}/${x.set_slug}` === path);
    if (!s) throw new Error("no set " + path);
    const hst = this.hosts.find((x) => x.name === host)!;
    const id = "01MOCKENVREQ" + String(this.releases.length + 2).padStart(4, "0") + b64url(randomBytes(6)).replace(/[^A-Za-z0-9]/g, "X").toUpperCase();
    // Key order is the broker's (envset.Release): it is what the page signs over.
    this.releases.push({
      path, title: `${s.org_title} / ${s.service_title} / ${s.set_title}`, org: s.org_id, service: s.service_id, set: s.set_id, revision: s.revision, service_revision: 1, policy_revision: this.policies.get(s.org_id)?.revision ?? 1, admission_generation: 1,
      enrollment: hst.enrollment, host, class: hst.class, names: [...s.names], default_seconds: 3600, soft_cap_seconds: 86400, offers_indefinite: true,
      id, grant_id: "", mode, address: hst.address, reason, ttl_seconds: 600, deadline: Date.now() + 540_000, not_after: 0, status: "pending", consumed: false,
    });
    return id;
  }
  private cap(set: string): number {
    return this.caps.get(set) ?? 3600;
  }
  private envMeta(c: Record<string, unknown>): string {
    const fail = this.deps.fail;
    const ttl = Number(c.ttl_seconds ?? 0), standing = Number(c.standing_seconds ?? 0);
    if (c.action === "standing-revoke") {
      const st = this.standing.find((x) => x.id === c.id) ?? fail(409, "conflict", "that rule has ended; reload");
      return JSON.stringify({ ...st, uses: 0 });
    }
    const r = this.releases.find((x) => x.id === c.id) ?? fail(404, "not_found", "not found");
    if (standing !== 0 && c.action !== "approve") fail(400, "bad_request", "unexpected standing duration");
    if ((c.action === "revoke") !== (r.status === "approved") || (c.action !== "revoke" && r.status !== "pending")) fail(409, "conflict", "decision no longer available");
    if (c.action === "approve") {
      if (ttl <= 0 || ttl > (r.ttl_seconds as number)) fail(400, "bad_request", "duration exceeds request");
      if (standing !== 0 && (standing < 60 || standing > this.cap(r.set as string))) fail(400, "bad_request", "don't-ask-again is off for this set, or longer than its limit");
    } else if (ttl !== 0) fail(400, "bad_request", "unexpected duration");
    return JSON.stringify({ ...r, reason: "" });
  }
  private async env(req: Request, verb: string, body: Record<string, unknown>, session: string | undefined): Promise<unknown> {
    const fail = this.deps.fail;
    if (verb === "challenge") {
      const standing = Number(body.standing_seconds ?? 0);
      const canonical: Record<string, unknown> = { v: 3, object: "env", action: body.action, id: body.id, installation: this.installation, epoch: this.epoch, issued_at: nowISO(), nonce: b64url(randomBytes(32)), metadata: this.envMeta(body), ttl_seconds: Number(body.ttl_seconds ?? 0) };
      if (standing > 0) canonical.standing_seconds = standing;
      const text = canonicalJSON(canonical);
      const ch = this.deps.issue(text, { ...canonical, text }, session);
      return { canonical: text, challenge_id: ch.id, public_key: this.deps.requestOptions(req, ch.challenge) };
    }
    if (verb !== "finish") return fail(404, "not_found", "not found");
    const c = this.buckets?.enabled ? (await this.buckets.finish(body, session)).canonical : this.deps.redeem(body.challenge_id, body.assertion, session);
    if (c.object !== "env") fail(409, "conflict", "wrong ceremony");
    if (this.envMeta(c) !== c.metadata) fail(409, "conflict", "env proposal changed; review again");
    if (c.action === "standing-revoke") this.standing = this.standing.filter((x) => x.id !== c.id);
    else {
      const r = this.releases.find((x) => x.id === c.id)!;
      if (c.action === "approve") {
        Object.assign(r, { status: "approved", grant_id: "01MOCKGRANT" + String(r.id).slice(-6), ttl_seconds: c.ttl_seconds, not_after: Date.now() + Number(c.ttl_seconds) * 1000 });
        if (Number(c.standing_seconds ?? 0) > 0) {
          const { grant_id: _g, reason: _r, ttl_seconds: _t, deadline: _d, not_after: _n, status: _s, consumed: _c, id, mode, address, ...binding } = r;
          this.standing.push({ ...binding, id, mode, address, max_ttl_seconds: c.ttl_seconds, created_at: Date.now(), expires_at: Date.now() + Number(c.standing_seconds) * 1000, uses: 0 });
        }
      } else {
        r.status = c.action === "deny" ? "denied" : "revoked";
        this.standing = this.standing.filter((x) => x.id !== c.id);
      }
    }
    this.deps.audit("env_" + String(c.action).replace("-", "_"), "env:" + c.id, c.standing_seconds ? `standing=${c.standing_seconds}` : "");
    return { ok: true };
  }

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
    for (const x of this.sets) if (!this.services.some((v) => v.id === x.service_id)) this.services.push({ id: x.service_id, org_id: x.org_id, slug: x.service_slug, title: x.service_title });
    const host = (name: string, cls: string, address: string, orgs: VaultOrg[]) =>
      this.hosts.push({ row_id: this.hosts.length + 1, enrollment: id32("enrollment:" + name), name, fingerprint: "SHA256:" + b64url(sha256("mock host " + name)), class: cls, address, revoked_at: null, orgs: new Map(orgs.map((o) => [o.id, { active: true, generation: 1 }])) });
    host("build-1", "agent", "192.0.2.14", [personal, client]);
    host("web-1", "agent", "192.0.2.21", [personal]);
    host("laptop", "owner-device", "198.51.100.7", [personal, client, club]);
    const staging = this.sets[0]!, sp = "client-a/paas/staging";
    const past = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
    this.history.set(staging.set_id, [
      { at: past(42), actor: "host:build-1", action: "env_collect_run", object: "grant:01MOCKGRANTENV0001", detail: `${sp} revision=7 enrollment=${id32("enrollment:build-1")}` },
      { at: past(43), actor: "owner", action: "env_approve", object: "env:01MOCKENVREQ0001", detail: `passkey=1 ${sp}` },
      { at: past(44), actor: "host:build-1", action: "env_request", object: "request:01MOCKENVREQ0001", detail: `${sp} mode=run` },
      { at: past(3 * 1440), actor: "owner", action: "vault_reveal", object: "set:" + staging.set_id, detail: `passkey=1 nonce=mock ${sp} revision=7 names=DATABASE_URL` },
      { at: past(5 * 1440), actor: "owner", action: "vault_commit", object: "set:" + staging.set_id, detail: `passkey=1 nonce=mock ${sp} revision=7 operation=merge changes=SMTP_PASSWORD:replace` },
    ]);
    const manifest = Buffer.concat([Buffer.from("S1M1"), Buffer.alloc(12, 1), sha256("mock image"), Buffer.alloc(92, 7)]);
    request(manifestKey, "01MOCKSIGNREQUEST0000A7K2QD", "build-1", "192.0.2.14", "sign the 2026.11 release manifest", [{ name: "manifest.bin", size: manifest.length, sha256: hex(sha256(manifest)), message: manifest.toString("base64") }], 0, 1);
    request(imageKey, "01MOCKSIGNREQUEST0000B3X9TM", "build-1", "192.0.2.14", "nightly image builds", [
      { name: "image-a.bin", size: 342852, sha256: hex(sha256("mock image a")) },
      { name: "image-b.bin", size: 339104, sha256: hex(sha256("mock image b")) },
    ], 1800, 20);
    request(imageKey, "01MOCKSIGNREQUEST0000C5R1WZ", "laptop", "198.51.100.7", "bench images", [{ name: "bench.bin", size: 120044, sha256: hex(sha256("mock bench")) }], 3600, 10, "approved", 4);
  }

  catalogue() {
    return {
      owner_id: id32("owner"),
      organisations: this.orgs.map((o) => ({
        id: o.id, slug: o.slug, title: o.title, revision: this.policies.get(o.id)?.revision ?? 1,
        policy: this.policies.get(o.id)?.policy ?? { default_seconds: 3600, soft_cap_seconds: 86400, indefinite: true, standing_default_seconds: 3600, standing_soft_cap_seconds: 86400, standing_indefinite: true },
        rules: [],
        services: this.services.filter((v) => v.org_id === o.id).map((v) => ({
          id: v.id, slug: v.slug, title: v.title, revision: 1, provider: "application",
          sets: this.sets.filter((s) => s.service_id === v.id).map((s) => ({ id: s.set_id, slug: s.set_slug, title: s.set_title, revision: s.revision, kind: s.kind, archived: false })),
        })),
        hosts: this.hosts.filter((x) => !x.revoked_at).map((x) => ({ row_id: x.row_id, enrollment: x.enrollment, name: x.name, fingerprint: x.fingerprint, class: x.class, active: x.orgs.get(o.id)?.active ?? false, generation: x.orgs.get(o.id)?.generation ?? 0 })),
        auto_access: [],
      })),
    };
  }
  /** An approved enrolment becomes a host that no organisation has admitted. */
  enrolled(enrollment: string, name: string, cls: string, address: string): void {
    this.hosts.push({ row_id: this.hosts.length + 1, enrollment, name, fingerprint: "SHA256:" + b64url(sha256("mock host " + name)), class: cls, address, revoked_at: null, orgs: new Map() });
  }
  hostList() {
    const day = 86_400_000;
    return this.hosts.map((x, i) => ({ id: x.enrollment, name: x.name, address: x.address, class: x.class, enrolled_at: new Date(Date.now() - (20 + i) * day).toISOString(), not_before: new Date(Date.now() - (20 + i) * day).toISOString(), not_after: new Date(Date.now() + 70 * day).toISOString(), last_request_at: i < 2 ? new Date(Date.now() - (i + 1) * 2_520_000).toISOString() : null, revoked_at: x.revoked_at }));
  }
  private note(set: string, action: string, detail: string): void {
    const rows = this.history.get(set) ?? [];
    rows.unshift({ at: new Date().toISOString(), actor: "owner", action, object: "set:" + set, detail: "passkey=1 nonce=mock " + detail });
    this.history.set(set, rows);
    this.deps.audit(action, "set:" + set, detail);
  }

  /** One catalogue change (create an organisation, service or empty set; admit or remove a
   * host): the plan the page proposed must be exactly what the current rows give. */
  private change(object: string, action: string, id: string, planText: unknown, apply: boolean): void {
    const fail = this.deps.fail, bad = () => fail(409, "conflict", "catalogue or admission changed; reload and review again");
    if (typeof planText !== "string") return fail(400, "bad_request", "invalid catalogue proposal");
    const c = JSON.parse(planText) as { old_policy?: Record<string, unknown>; new_policy?: Record<string, unknown>; result_revision?: number; organisation: { id: string; slug: string; title: string; revision: number }; service?: { id: string; slug: string; title: string; revision: number }; set?: { id: string; slug: string; title: string; revision: number }; host?: { enrollment: string } };
    const fresh = (n: { id: string; slug: string; title: string; revision: number } | undefined, taken: { id: string; slug: string }[]) => !!n && n.id === id && /^[0-9a-f]{32}$/.test(n.id) && /^[a-z0-9][a-z0-9-]{0,62}$/.test(n.slug) && /^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$/.test(n.title) && !taken.some((t) => t.id === n.id || t.slug === n.slug);
    const cat = this.catalogue();
    const org = cat.organisations.find((o) => o.id === c.organisation?.id);
    if (object === "organisation" && action === "create") {
      if (!fresh(c.organisation, this.orgs)) bad();
      if (apply) {
        this.orgs.push({ id: c.organisation.id, slug: c.organisation.slug, title: c.organisation.title, allow_reveal: true });
        this.buckets?.scopes.push({ scope: c.organisation.id, title: c.organisation.title, has_key: false });
      }
      return;
    }
    if (!org) return bad();
    const service = org.services.find((v) => v.id === c.service?.id);
    if (object === "service" && action === "create") {
      if (!fresh(c.service, org.services)) bad();
      if (apply) this.services.push({ id: c.service!.id, org_id: org.id, slug: c.service!.slug, title: c.service!.title });
    } else if (object === "credential_set" && action === "create") {
      if (!service || !fresh(c.set, service.sets.map((x) => ({ id: x.id, slug: x.slug })))) bad();
      if (apply) {
        this.sets.push({ org_id: org.id, org_slug: org.slug, org_title: org.title, service_id: service!.id, service_slug: service!.slug, service_title: service!.title, set_id: c.set!.id, set_slug: c.set!.slug, set_title: c.set!.title, kind: "env-set", revision: 0, names: [], allow_reveal: true, signatures: 0 });
        this.values.set(c.set!.id, new Map());
      }
    } else if (object === "org_host" && (action === "admit" || action === "remove")) {
      const hst = this.hosts.find((x) => x.enrollment === id && x.enrollment === c.host?.enrollment);
      const cur = hst?.orgs.get(org.id) ?? { active: false, generation: 0 };
      if (!hst || cur.active !== (action === "remove")) return bad();
      if (apply) hst.orgs.set(org.id, { active: action === "admit", generation: cur.generation + 1 });
    } else if (object === "org_policy" && action === "replace") {
      // The whole policy is replaced; the plan names the old one exactly.
      if (id !== org.id || !c.new_policy || JSON.stringify(c.old_policy) !== JSON.stringify(org.policy) || c.organisation.revision !== org.revision || c.result_revision !== org.revision + 1) return bad();
      for (const k of ["discovery", "deny_get"]) if (Object.hasOwn(c.new_policy, k) && c.new_policy[k] !== true) return bad(); // omitted while off
      if (apply) {
        this.policies.set(org.id, { policy: c.new_policy, revision: org.revision + 1 });
        // As on the broker: a policy replacement ends the organisation's pending work and rules.
        this.standing = this.standing.filter((x) => x.org !== org.id);
        for (const r of this.releases) if (r.org === org.id && (r.status === "pending" || r.status === "approved")) r.status = r.status === "pending" ? "expired" : "revoked";
      }
    } else return fail(400, "bad_request", "unsupported catalogue change in the mock");
    if (apply) this.deps.audit(`${object}_${action}`, `${object}:${id}`, "change=" + planText);
  }

  private state() {
    return { schemes: SCHEMES, organisations: this.orgs, sets: this.sets.map((s) => ({ ...s, allow_reveal: this.orgs.find((o) => o.id === s.org_id)!.allow_reveal, standing_cap_seconds: s.kind === "signer" ? 0 : this.cap(s.set_id) })), requests: this.requests.filter((r) => r.status === "pending" || r.status === "approved") };
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
    switch (c.action) {
      case "policy": {
        const o = this.orgs.find((x) => x.id === c.id) ?? fail(404, "not_found", "not found");
        if (typeof c.allow_reveal !== "boolean" || c.allow_reveal === o.allow_reveal) fail(409, "conflict", "policy already has that value; reload");
        return { meta: { org_id: o.id, org_slug: o.slug, org_title: o.title, old_allow_reveal: o.allow_reveal, allow_reveal: c.allow_reveal }, facts };
      }
      case "commit": {
        const s = setOf(c.id);
        if (s.kind !== "env-set" && s.kind !== "secret") fail(400, "bad_request", "not an env set");
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
        if (s.kind === "secret") {
          const after = new Set(e.operation === "import" ? [] : s.names);
          for (const x of e.entries) after.add(x.name);
          for (const n of e.remove) after.delete(n);
          if (after.size !== 1) fail(400, "bad_request", "a secret holds exactly one value: replace it, or keep several values in an env set");
        }
        facts.attempt_id = c.attempt_id;
        facts.edit = e; // mock-internal, removed before the response
        return { meta: { ...this.target(s), attempt_id: c.attempt_id, operation: e.operation, changes, commitment, result_revision: s.revision + 1, recipient: a.recipient ?? "" }, facts };
      }
      case "reveal": {
        const s = setOf(c.id);
        const o = this.orgs.find((x) => x.id === s.org_id)!;
        if (s.kind !== "env-set" && s.kind !== "secret") fail(403, "forbidden", "a signer key is never revealed");
        if (!o.allow_reveal) fail(403, "forbidden", "this organisation does not allow reveal");
        const names = c.names as string[];
        if (!Array.isArray(names) || !names.length || names.some((n, i) => !s.names.includes(n) || (i > 0 && names[i - 1]! >= n))) fail(400, "bad_request", "name the keys to reveal, sorted, each once");
        const pub = typeof c.recipient === "string" ? Buffer.from(c.recipient, "base64url") : Buffer.alloc(0);
        if (pub.length !== 65 || pub[0] !== 4) fail(400, "bad_request", "invalid reveal recipient");
        return { meta: { ...this.target(s), names, recipient: c.recipient }, facts };
      }
      case "signer-create": {
        const svc = this.services.find((v) => v.id === c.service_id) ?? fail(404, "not_found", "not found");
        const po = this.orgs.find((o) => o.id === svc.org_id)!;
        const parent = { org_id: po.id, org_slug: po.slug, org_title: po.title, service_id: svc.id, service_slug: svc.slug, service_title: svc.title };
        const scheme = SCHEMES.find((x) => x.id === c.scheme);
        if (!scheme || typeof c.id !== "string" || !/^[0-9a-f]{32}$/.test(c.id) || typeof c.set_slug !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(c.set_slug) || typeof c.set_title !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$/.test(c.set_title)) return fail(400, "bad_request", "invalid signer set");
        if (this.sets.some((s) => s.set_id === c.id || (s.service_id === parent.service_id && s.set_slug === c.set_slug))) fail(409, "conflict", "a set with that name or ID exists; reload");
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
      case "secret-create": {
        const svc = this.services.find((v) => v.id === c.service_id) ?? fail(404, "not_found", "not found");
        const po = this.orgs.find((o) => o.id === svc.org_id)!;
        if (typeof c.id !== "string" || !/^[0-9a-f]{32}$/.test(c.id) || typeof c.set_slug !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(c.set_slug) || typeof c.set_title !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$/.test(c.set_title) || typeof c.note !== "string" || typeof c.url !== "string" || (c.url !== "" && !/^https?:\/\/[^\s"<>`\\]+$/.test(c.url))) return fail(400, "bad_request", "invalid secret");
        if (this.sets.some((s) => s.set_id === c.id || (s.service_id === svc.id && s.set_slug === c.set_slug))) fail(409, "conflict", "a set with that name or ID exists; reload");
        const a = begin ? this.submit(session, c, "edit", c.id) : this.live(session, c.attempt_id);
        if (a.purpose !== "edit" || a.target !== c.id) fail(409, "conflict", "upload attempt expired; start again");
        const edit = JSON.parse((await this.open(a, "edit", c.attempt_id as string, c.id)).toString("utf8")) as Edit & { salt: string };
        const e = { operation: edit.operation, entries: edit.entries ?? [], remove: edit.remove ?? [], salt: new Uint8Array(Buffer.from(edit.salt, "base64")) };
        if (e.operation !== "import" || e.entries.length !== 1 || e.remove.length) fail(400, "bad_request", "a secret is one name and one value");
        let commitment = "";
        try {
          commitment = await editCommitment(e, { org: po.id, service: svc.id, set: c.id, revision: 0 });
        } catch (err) {
          fail(400, "bad_request", (err as Error).message);
        }
        if (commitment !== a.commitment) fail(400, "bad_request", "invalid edit commitment");
        facts.attempt_id = c.attempt_id;
        facts.edit = e; // mock-internal, removed before the response
        return { meta: { org_id: po.id, org_slug: po.slug, org_title: po.title, service_id: svc.id, service_slug: svc.slug, service_title: svc.title, set_id: c.id, set_slug: c.set_slug, set_title: c.set_title, kind: "secret", revision: 0, attempt_id: c.attempt_id, env_name: e.entries[0]!.name, note: c.note, url: c.url, commitment, result_revision: 1, recipient: a.recipient ?? "" }, facts };
      }
      case "secret-convert": {
        const s = setOf(c.id);
        if (s.kind !== "env-set" || s.names.length !== 1) fail(409, "conflict", "only an env set with exactly one key becomes a secret; reload");
        if (typeof c.note !== "string" || typeof c.url !== "string") fail(400, "bad_request", "invalid secret");
        return { meta: { ...this.target(s), env_name: s.names[0], note: c.note, url: c.url }, facts };
      }
      case "standing-cap": {
        const s = setOf(c.id);
        const n = c.standing_cap_seconds;
        if (s.kind === "signer") fail(400, "bad_request", "only env sets and secrets have a don't-ask-again limit");
        if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0 || n > 86400 || n % 60 !== 0) return fail(400, "bad_request", "the limit is between 0 (off) and 24 hours, in whole minutes");
        if (n === this.cap(s.set_id)) fail(409, "conflict", "the limit already has that value; reload");
        return { meta: { ...this.target(s), old_standing_cap_seconds: this.cap(s.set_id), standing_cap_seconds: n }, facts };
      }
      case "sign-approve":
      case "sign-deny":
      case "sign-revoke": {
        const r = this.requests.find((x) => x.id === c.id) ?? fail(404, "not_found", "not found");
        if ((c.action === "sign-revoke") !== (r.status === "approved") || (c.action !== "sign-revoke" && r.status !== "pending")) fail(409, "conflict", "decision no longer available");
        const s = setOf(r.set);
        const ttl = Number(c.ttl_seconds ?? 0), max = Number(c.max_signatures ?? 0);
        if (c.action === "sign-approve") {
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

  /** The bucket a reveal or a signing approval opens (format 2). */
  private bucketFor(c: Record<string, unknown>): string | undefined {
    const set = c.action === "reveal" ? this.sets.find((s) => s.set_id === c.id) : c.action === "sign-approve" ? this.sets.find((s) => s.set_id === this.requests.find((r) => r.id === c.id)?.set) : undefined;
    if (!set) return undefined;
    return this.buckets?.buckets.find((b) => b.label === `${set.org_slug}/${set.service_slug}/${set.set_slug}`)?.id;
  }

  /** Returns undefined for a path that is not the vault's (or when the view is off). */
  async handle(req: Request, url: URL, body: Record<string, unknown>, session: string | undefined): Promise<unknown> {
    if (!this.enabled) return undefined;
    const p = url.pathname, post = req.method === "POST", fail = this.deps.fail;
    if (p === "/api/ui/seal/env/state" && !post) {
      const live = this.releases.filter((r) => r.status === "pending" || r.status === "approved");
      this.standing = this.standing.filter((x) => (x.expires_at as number) > Date.now());
      return { drafts: [], releases: live, standing: this.standing, standing_caps: Object.fromEntries(live.map((r) => [r.set, this.cap(r.set as string)])) };
    }
    if ((p === "/api/ui/seal/env/challenge" || p === "/api/ui/seal/env/finish") && post) return this.env(req, p.slice("/api/ui/seal/env/".length), body, session);
    if (p === "/api/ui/catalogue" && !post) return this.catalogue();
    const cm = p.match(/^\/api\/ui\/catalogue\/([a-z_]+)\/([^/]+)\/(challenge|decide)$/);
    if (cm && post) {
      const [, object, id, verb] = cm as unknown as [string, string, string, string];
      if (verb === "challenge") {
        this.change(object, String(body.action), id, body.plan, false);
        const canonical = { v: 2, action: body.action, object, id, plan: body.plan, nonce: b64url(randomBytes(32)), issued_at: nowISO() };
        const text = JSON.stringify(canonical, Object.keys(canonical).sort());
        const ch = this.deps.issue(text, canonical, session);
        return { challenge_id: ch.id, canonical: text, public_key: this.deps.requestOptions(req, ch.challenge) };
      }
      const c = this.deps.redeem(body.challenge_id, body.assertion, session);
      if (c.object !== object || c.id !== id) fail(403, "forbidden", "challenge is for a different object");
      this.change(object, String(c.action), id, c.plan, true);
      return { ok: true };
    }
    if (p === "/api/ui/seal/vault/history" && !post) {
      const set = this.sets.find((x) => x.set_id === url.searchParams.get("set")) ?? fail(404, "not_found", "not found");
      const entries = this.history.get(set.set_id) ?? [];
      const at = (re: RegExp) => Date.parse(entries.find((e) => re.test(e.action))?.at ?? "") || 0;
      return { entries: entries.slice(0, 20), last_changed_at: at(/^(vault_commit|vault_signer_create|vault_secret_create|env_commit)$/), last_used_at: at(/^(sign|env_collect_.*)$/) };
    }
    if (!p.startsWith("/api/ui/seal/vault/")) return undefined;
    const verb = p.slice("/api/ui/seal/vault/".length);
    if (verb === "state" && !post) return this.state();
    if (verb === "attempt" && post) {
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
      const bucket = this.bucketFor(body);
      if (bucket && this.buckets?.enabled) {
        const ttl = Number(body.ttl_seconds ?? 0);
        const hold = body.action === "sign-approve" ? { hold: "sign", until: new Date(Date.now() + (ttl > 0 ? ttl : 600) * 1000).toISOString().replace(/\.\d+Z$/, "Z") } : { hold: "instant", until: "" };
        return { ...(await this.buckets.bucketOffer(req, text, { ...canonical, text }, session, { buckets: [{ id: bucket, ...hold }] })), facts };
      }
      const ch = this.deps.issue(text, { ...canonical, text }, session);
      return { canonical: text, challenge_id: ch.id, public_key: this.deps.requestOptions(req, ch.challenge), facts };
    }
    if (verb === "finish" && post) {
      const c = this.buckets?.enabled ? (await this.buckets.finish(body, session)).canonical : this.deps.redeem(body.challenge_id, body.assertion, session);
      if (c.object !== "vault") fail(409, "conflict", "wrong ceremony");
      const signed = JSON.parse(c.metadata as string) as Record<string, unknown>;
      const choice: Record<string, unknown> = { action: c.action, id: c.id, attempt_id: signed.attempt_id, names: signed.names, recipient: signed.recipient, allow_reveal: signed.allow_reveal, service_id: signed.service_id, set_slug: signed.set_slug, set_title: signed.set_title, scheme: signed.scheme, source: signed.source, ttl_seconds: signed.ttl_seconds, max_signatures: signed.max_signatures, note: signed.note, url: signed.url, standing_cap_seconds: signed.standing_cap_seconds };
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
          this.note(s.set_id, "vault_commit", `${s.org_slug}/${s.service_slug}/${s.set_slug} revision=${s.revision} changes=${signed.changes}`);
          return { ok: true };
        }
        case "reveal": {
          const s = this.sets.find((x) => x.set_id === c.id)!;
          const names = signed.names as string[];
          const plain = utf8(JSON.stringify({ entries: names.map((n) => ({ name: n, value: this.values.get(s.set_id)!.get(n)! })) }));
          const recipientPublicKey = await suite.kem.deserializePublicKey(ab(Buffer.from(signed.recipient as string, "base64url")));
          const sender = await suite.createSenderContext({ recipientPublicKey, info: ab(tuple("hpke-vault", Buffer.from(this.installation, "base64url"), utf8("reveal"))) });
          const ct = await sender.seal(ab(plain), ab(tuple("hpke-vault-aad", sha256(c.text as string), Buffer.from(this.epoch, "base64url"), utf8(s.set_id))));
          this.note(s.set_id, "vault_reveal", `${s.org_slug}/${s.service_slug}/${s.set_slug} revision=${s.revision} names=${names.join(",")}`);
          return { enc: b64url(new Uint8Array(sender.enc)), ciphertext: b64url(new Uint8Array(ct)) };
        }
        case "secret-create": {
          const m = reviewed.meta as Record<string, string>;
          const edit = reviewed.facts.edit as Edit;
          const s: VaultSet = { org_id: m.org_id!, org_slug: m.org_slug!, org_title: m.org_title!, service_id: m.service_id!, service_slug: m.service_slug!, service_title: m.service_title!, set_id: m.set_id!, set_slug: m.set_slug!, set_title: m.set_title!, kind: "secret", revision: 1, names: [edit.entries[0]!.name], allow_reveal: true, signatures: 0, ...(m.note ? { note: m.note } : {}), ...(m.url ? { url: m.url } : {}) };
          this.sets.push(s);
          this.values.set(s.set_id, new Map([[edit.entries[0]!.name, edit.entries[0]!.value]]));
          this.note(s.set_id, "vault_secret_create", `${s.org_slug}/${s.service_slug}/${s.set_slug} revision=1 env=${s.names[0]}`);
          return { set_id: s.set_id, path: `${s.org_slug}/${s.service_slug}/${s.set_slug}`, env_name: s.names[0] };
        }
        case "secret-convert": {
          const s = this.sets.find((x) => x.set_id === c.id)!;
          Object.assign(s, { kind: "secret", ...(signed.note ? { note: signed.note } : {}), ...(signed.url ? { url: signed.url } : {}) });
          this.note(s.set_id, "vault_secret_convert", `${s.org_slug}/${s.service_slug}/${s.set_slug} revision=${s.revision} env=${s.names[0]}`);
          return { ok: true };
        }
        case "standing-cap": {
          const s = this.sets.find((x) => x.set_id === c.id)!;
          this.caps.set(s.set_id, signed.standing_cap_seconds as number);
          this.standing = this.standing.filter((x) => x.set !== s.set_id);
          this.note(s.set_id, "vault_standing_cap", `${s.org_slug}/${s.service_slug}/${s.set_slug} standing_cap=${signed.standing_cap_seconds}`);
          return { ok: true };
        }
        case "signer-create": {
          const m = reviewed.meta as Record<string, string>;
          const pub = Buffer.from(m.public_key!, "base64url");
          const s: VaultSet = { org_id: m.org_id!, org_slug: m.org_slug!, org_title: m.org_title!, service_id: m.service_id!, service_slug: m.service_slug!, service_title: m.service_title!, set_id: m.set_id!, set_slug: m.set_slug!, set_title: m.set_title!, kind: "signer", revision: 0, names: [], allow_reveal: true, scheme: m.scheme, origin: m.source === "import" ? "imported" : "generated", created_at: Date.now(), signatures: 0, public_key: m.public_key, public_hex: hex(pub), public_pem: spki(pub), fingerprint: m.fingerprint };
          this.sets.push(s);
          this.note(s.set_id, "vault_signer_create", `${s.org_slug}/${s.service_slug}/${s.set_slug} scheme=${s.scheme} origin=${s.origin} fingerprint=${s.fingerprint}`);
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
