// Seal format 2 in the browser: byte-for-byte vectors shared with Go
// (test/vectors/buckets.json, internal/server/seal/bucket_test.go TestBucketVectors),
// descriptor validation, and the tap: PRF only for listed passkeys, KEKs only inside the
// HPKE packet, nothing sent without a PRF result.
import { describe, expect, test } from "bun:test";
import { createECDH } from "node:crypto";
import vector from "../../test/vectors/buckets.json";
import { canonicalJSON, deriveKEK, holdWords, kekInfo, openAAD, openChallenge, openInfo, parseDescriptor, prepareTap, t2, type ChallengeLike } from "../src/buckets";
import { decode, encode } from "../src/b64url";
import { suite, wrapKeyBytes } from "../src/seal";
import { fakeAuth, prfAuth, rnd } from "./helpers";

const x = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const hex = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("hex");
const b64 = (b: Uint8Array) => encode(b);
const te = new TextEncoder();

describe("vectors shared with Go", () => {
  const inst = x(vector.Installation), cred = x(vector.Cred), salt = x(vector.Salt);
  test("T2 framing and KEKInfo", () => {
    expect(hex(kekInfo(inst, vector.RPID, cred, vector.Scope, salt))).toBe(vector.KEKInfo);
    expect(hex(t2("x"))).toBe("0000000a61716d61732d7365616c00000008000000000000000200000001" + "78");
  });
  test("KEK derivation", async () => {
    expect(hex(await deriveKEK(x(vector.PRF), inst, vector.RPID, cred, vector.Scope, salt))).toBe(vector.KEK);
    expect(hex(await deriveKEK(x(vector.PRF), inst, vector.RPID, cred, "other", salt))).not.toBe(vector.KEK);
  });
  test("bound challenge, HPKE info and AAD", async () => {
    const ch = await openChallenge(vector.Canonical, vector.Descriptor);
    expect(hex(ch)).toBe(vector.Challenge);
    expect(hex(openInfo(inst, "approve"))).toBe(vector.Info);
    expect(hex(openAAD(x(vector.AttemptID), x(vector.Epoch), ch, cred))).toBe(vector.AAD);
  });
  test("the browser packet (make-open-packet.ts) opens with the vector's recipient", async () => {
    const bp = (vector as unknown as { browser_packet?: { Enc: string; Ciphertext: string; KEK2: string } }).browser_packet;
    expect(bp).toBeDefined();
    const key = await suite.kem.importKey("raw", x(vector.RecipientPriv).buffer as ArrayBuffer, false);
    const ctx = await suite.createRecipientContext({ recipientKey: key, enc: x(bp!.Enc).buffer as ArrayBuffer, info: x(vector.Info).buffer as ArrayBuffer });
    const plain = new Uint8Array(await ctx.open(x(bp!.Ciphertext).buffer as ArrayBuffer, x(vector.AAD).buffer as ArrayBuffer));
    expect(hex(plain)).toBe("00000020" + vector.KEK + "00000020" + bp!.KEK2);
  });
});

// ---- a tiny broker: descriptor + options as the contract says ----

const RP = "aqmas.example.com";
function recipient() {
  const e = createECDH("prime256v1");
  e.generateKeys();
  const priv = Buffer.alloc(32);
  e.getPrivateKey().copy(priv, 32 - e.getPrivateKey().length);
  return { priv, pub: new Uint8Array(e.getPublicKey()) };
}
const canonical = canonicalJSON({ action: "approve", id: "r1", object: "request", v: 2 });

async function offer(o: { scopes: string[]; buckets?: Record<string, unknown>[]; creds: { id: string; salts: Uint8Array[] }[]; allow?: string[]; descriptor?: (d: Record<string, unknown>) => Record<string, unknown>; text?: (t: string) => string }) {
  const r = recipient();
  const inst = rnd(32), epoch = rnd(32), attempt = rnd(32);
  let d: Record<string, unknown> = {
    attempt_id: b64(attempt),
    buckets: o.buckets ?? [{ hold: "instant", id: b64(rnd(32)), kind: "ssh-ca", label: "SSH user CA", scope: o.scopes[0], until: "" }],
    epoch: b64(epoch),
    installation: b64(inst),
    object: "bucket-open",
    purpose: "approve",
    recipient: b64(r.pub),
    scopes: o.scopes,
    v: 1,
  };
  if (o.descriptor) d = o.descriptor(d);
  let text = canonicalJSON(d);
  if (o.text) text = o.text(text);
  const ch = await openChallenge(canonical, text);
  const by: Record<string, Record<string, string>> = {};
  for (const c of o.creds) by[c.id] = c.salts.length === 2 ? { first: b64(c.salts[0]!), second: b64(c.salts[1]!) } : { first: b64(c.salts[0]!) };
  const res: ChallengeLike = {
    canonical,
    public_key: { publicKey: { challenge: encode(ch), rpId: RP, userVerification: "required", allowCredentials: (o.allow ?? (o.creds.length ? o.creds.map((c) => c.id) : [b64(rnd(16))])).map((id) => ({ type: "public-key", id })), ...(o.creds.length ? { extensions: { prf: { evalByCredential: by } } } : {}) } },
    open: { descriptor: text },
  };
  return { res, r, inst, epoch, attempt, ch, d };
}
async function openPacket(priv: Buffer, inst: Uint8Array, purpose: string, aad: Uint8Array, packet: { enc: string; ciphertext: string }) {
  const key = await suite.kem.importKey("raw", new Uint8Array(priv).buffer as ArrayBuffer, false);
  const ctx = await suite.createRecipientContext({ recipientKey: key, enc: decode(packet.enc), info: openInfo(inst, purpose).buffer });
  return new Uint8Array(await ctx.open(decode(packet.ciphertext), aad.buffer as ArrayBuffer));
}

describe("descriptor validation", () => {
  const good = { scopes: ["installation"], creds: [] as { id: string; salts: Uint8Array[] }[] };
  test("a well-formed descriptor parses; the card lists bucket, hold and end", async () => {
    const { res } = await offer({ ...good, buckets: [{ hold: "grant", id: b64(rnd(32)), kind: "cf-proxy", label: "personal Cloudflare proxy token", scope: "installation", until: "2026-11-23T12:00:00Z" }] });
    const tap = await prepareTap(res, RP);
    expect(tap.lines).toEqual(["Opens personal Cloudflare proxy token: while the grant lasts, until 2026-11-23 12:00:00 UTC"]);
  });
  const cases: [string, Parameters<typeof offer>[0]["descriptor"], RegExp][] = [
    ["extra key", (d) => ({ ...d, extra: 1 }), /unexpected fields/],
    ["missing key", (d) => { const { epoch: _e, ...rest } = d; return rest; }, /unexpected fields/],
    ["wrong purpose", (d) => ({ ...d, purpose: "enrol" }), /purpose/],
    ["wrong object", (d) => ({ ...d, object: "scope-enrol" }), /not a bucket-open/],
    ["wrong version", (d) => ({ ...d, v: 2 }), /version/],
    ["bad recipient (not uncompressed)", (d) => ({ ...d, recipient: b64(new Uint8Array(65).fill(2)) }), /recipient/],
    ["bad recipient (length)", (d) => ({ ...d, recipient: b64(rnd(33)) }), /binary/],
    ["three scopes", (d) => ({ ...d, scopes: ["installation", "a", "b"] }), /one or two scopes/],
    ["no scopes", (d) => ({ ...d, scopes: [] }), /one or two scopes/],
    ["bucket outside the scopes", (d) => ({ ...d, buckets: [{ hold: "instant", id: b64(rnd(32)), kind: "ssh-ca", label: "x", scope: "other", until: "" }] }), /scope is not in/],
    ["bucket with extra field", (d) => ({ ...d, buckets: [{ hold: "instant", id: b64(rnd(32)), kind: "ssh-ca", label: "x", scope: "installation", until: "", more: 1 }] }), /unexpected fields/],
    ["bad until", (d) => ({ ...d, buckets: [{ hold: "grant", id: b64(rnd(32)), kind: "ssh-ca", label: "x", scope: "installation", until: "tomorrow" }] }), /hold end/],
    ["short installation", (d) => ({ ...d, installation: b64(rnd(31)) }), /binary/],
  ];
  for (const [name, mod, re] of cases)
    test(`refused: ${name}`, async () => {
      const { res } = await offer({ ...good, descriptor: mod });
      await expect(prepareTap(res, RP)).rejects.toThrow(re);
    });
  test("refused: non-canonical text (whitespace)", async () => {
    const { res } = await offer({ ...good, text: (t) => t.replace(",", ", ") });
    await expect(prepareTap(res, RP)).rejects.toThrow(/canonical/);
  });
  test("refused: a challenge that does not bind this descriptor (or this canonical)", async () => {
    const a = await offer(good), b = await offer(good);
    await expect(prepareTap({ ...a.res, open: b.res.open }, RP)).rejects.toThrow(/does not bind/);
    await expect(prepareTap({ ...a.res, canonical: canonicalJSON({ action: "approve", id: "r2", object: "request", v: 2 }) }, RP)).rejects.toThrow(/does not bind/);
    // An open-less response must commit to SHA-256(canonical) alone.
    await expect(prepareTap({ ...a.res, open: undefined }, RP)).rejects.toThrow();
  });
  test("refused: salt count, salt length, PRF inputs for a passkey not allowed, other extensions", async () => {
    const id = b64(rnd(16));
    await expect(prepareTap((await offer({ scopes: ["installation", "org"], creds: [{ id, salts: [rnd(32)] }] })).res, RP)).rejects.toThrow(/unexpected fields/);
    await expect(prepareTap((await offer({ scopes: ["installation"], creds: [{ id, salts: [rnd(32), rnd(32)] }] })).res, RP)).rejects.toThrow(/unexpected fields/);
    await expect(prepareTap((await offer({ scopes: ["installation"], creds: [{ id, salts: [rnd(31)] }] })).res, RP)).rejects.toThrow(/binary/);
    await expect(prepareTap((await offer({ scopes: ["installation"], creds: [{ id, salts: [rnd(32)] }], allow: [b64(rnd(16))] })).res, RP)).rejects.toThrow(/may not answer/);
    const o = await offer({ scopes: ["installation"], creds: [{ id, salts: [rnd(32)] }] });
    (o.res.public_key as { publicKey: Record<string, unknown> }).publicKey.extensions = { prf: { evalByCredential: {} }, credProps: true };
    await expect(prepareTap(o.res, RP)).rejects.toThrow(/unexpected fields/);
  });
  test("refused: another installation or broker start than the status names", async () => {
    const o = await offer(good);
    await expect(prepareTap(o.res, RP, { installation: b64(rnd(32)) })).rejects.toThrow(/another installation/);
    await expect(prepareTap(o.res, RP, { epoch: b64(rnd(32)) })).rejects.toThrow(/another broker start/);
    expect((await prepareTap(o.res, RP, { installation: b64(o.inst), epoch: b64(o.epoch) })).open).toBeDefined();
  });
  test("refused: a descriptor where none may be", async () => {
    const o = await offer(good);
    await expect(prepareTap(o.res, RP, { allowOpen: false })).rejects.toThrow(/Unexpected open/);
  });
  test("parseDescriptor: scope-enrol needs aligned salts and, for migrate, the legacy binding", () => {
    const base = { attempt_id: b64(rnd(32)), buckets: [], credential_id: b64(rnd(16)), epoch: b64(rnd(32)), installation: b64(rnd(32)), object: "scope-enrol", purpose: "stage", recipient: b64(recipient().pub), salts: [b64(rnd(32))], scopes: ["installation"], v: 1 };
    expect(parseDescriptor(canonicalJSON(base), { object: "scope-enrol" }).purpose).toBe("stage");
    expect(() => parseDescriptor(canonicalJSON({ ...base, salts: [] }), { object: "scope-enrol" })).toThrow(/Salts/);
    expect(() => parseDescriptor(canonicalJSON({ ...base, purpose: "approve" }), { object: "scope-enrol" })).toThrow(/purpose/);
    expect(() => parseDescriptor(canonicalJSON({ ...base, purpose: "migrate" }), { object: "scope-enrol" })).toThrow(/unexpected fields/);
    const legacy = { installation: b64(rnd(32)), mk_version: 1, prf_salt: b64(rnd(32)) };
    expect(parseDescriptor(canonicalJSON({ ...base, purpose: "migrate", legacy }), { object: "scope-enrol" }).legacy).toEqual(legacy);
    expect(() => parseDescriptor(canonicalJSON({ ...base, purpose: "migrate", legacy, scopes: ["installation", "o"], salts: [b64(rnd(32)), b64(rnd(32))] }), { object: "scope-enrol" })).toThrow(/exactly one scope/);
    expect(() => parseDescriptor(canonicalJSON({ ...base, purpose: "test" }), { object: "scope-enrol", purposes: ["stage"] })).toThrow(/purpose/);
  });
});

describe("hold wording", () => {
  test("the broker's reason strings: instant dropped next to a lasting hold, kinds spelled out", () => {
    expect(holdWords("instant (this approval only)", "")).toBe("for this action only");
    expect(holdWords("instant", "")).toBe("for this action only");
    expect(holdWords("instant (this approval only); Cloudflare grant", "2026-11-23T12:00:00Z")).toBe("Cloudflare grant, until 2026-11-23 12:00:00 UTC");
    expect(holdWords("instant (this approval only); re-arms Cloudflare auto-approval until restart", "")).toBe("re-arms Cloudflare auto-approval until restart");
    expect(holdWords("grant", "2026-11-23T12:00:00Z")).toBe("while the grant lasts, until 2026-11-23 12:00:00 UTC");
  });
});

describe("rekey", () => {
  const withSalt = (salt: Uint8Array) => (d: Record<string, unknown>) => ({ ...d, rekey_salt: b64(salt) });
  test("the second PRF evaluation is at the descriptor's fresh salt; the packet carries both KEKs", async () => {
    const auth = prfAuth(`https://${RP}`);
    const old = rnd(32), fresh = rnd(32);
    const o = await offer({ scopes: ["org-1"], creds: [{ id: auth.id, salts: [old, fresh] }], descriptor: withSalt(fresh), buckets: [] });
    const tap = await prepareTap(o.res, RP, { rekey: true, requireOpen: true });
    expect(tap.lines.some((l) => l.startsWith("Rekeys org-1"))).toBe(true);
    const signed = await tap.sign(auth);
    const plain = await openPacket(o.r.priv, o.inst, "approve", openAAD(o.attempt, o.epoch, o.ch, auth.rawId), signed.open!);
    const k1 = await deriveKEK(await auth.evaluate(old), o.inst, RP, auth.rawId, "org-1", old);
    const k2 = await deriveKEK(await auth.evaluate(fresh), o.inst, RP, auth.rawId, "org-1", fresh);
    expect(hex(plain)).toBe("00000020" + hex(k1) + "00000020" + hex(k2));
  });
  test("refused: a rekey salt where no rekey was asked, none where one was, a second input that differs, two scopes", async () => {
    const id = b64(rnd(16));
    const fresh = rnd(32);
    const o = await offer({ scopes: ["org-1"], creds: [{ id, salts: [rnd(32), fresh] }], descriptor: withSalt(fresh) });
    await expect(prepareTap(o.res, RP)).rejects.toThrow(/unexpected fields/);
    const plain = await offer({ scopes: ["org-1"], creds: [{ id, salts: [rnd(32)] }] });
    await expect(prepareTap(plain.res, RP, { rekey: true })).rejects.toThrow(/unexpected fields/);
    const other = await offer({ scopes: ["org-1"], creds: [{ id, salts: [rnd(32), rnd(32)] }], descriptor: withSalt(fresh) });
    await expect(prepareTap(other.res, RP, { rekey: true })).rejects.toThrow(/fresh salt/);
    const two = await offer({ scopes: ["installation", "org-1"], creds: [{ id, salts: [rnd(32), fresh] }], descriptor: withSalt(fresh) });
    await expect(prepareTap(two.res, RP, { rekey: true })).rejects.toThrow(/exactly one scope/);
  });
});

describe("the tap", () => {
  test("two scopes: one tap, PRF results become KEKs inside the packet only, and are wiped", async () => {
    const auth = prfAuth(`https://${RP}`);
    const s1 = rnd(32), s2 = rnd(32);
    const other = b64(rnd(16));
    const o = await offer({ scopes: ["installation", "org-1"], creds: [{ id: auth.id, salts: [s1, s2] }], allow: [auth.id, other], buckets: [
      { hold: "instant", id: b64(rnd(32)), kind: "ssh-ca", label: "SSH user CA", scope: "installation", until: "" },
      { hold: "window", id: b64(rnd(32)), kind: "cf-proxy", label: "org-1 Cloudflare proxy token", scope: "org-1", until: "2026-11-23T13:00:00Z" },
    ] });
    const tap = await prepareTap(o.res, RP);
    expect(tap.open!.canOpen).toEqual([auth.id]);
    expect(tap.lines.length).toBe(2);
    const signed = await tap.sign(auth);
    // The WebAuthn call carried evalByCredential with binary salts for this passkey only.
    const ext = auth.gets[0]!.extensions as { prf: { evalByCredential: Record<string, { first: Uint8Array; second: Uint8Array }> } };
    expect(Object.keys(ext.prf.evalByCredential)).toEqual([auth.id]);
    expect(hex(ext.prf.evalByCredential[auth.id]!.first)).toBe(hex(s1));
    // Nothing of the PRF in the assertion.
    expect(signed.assertion.clientExtensionResults).toEqual({});
    // Checked on the parsed fields: the binary fields are random base64url, which can spell
    // any three letters by chance.
    expect(Object.keys(signed.assertion).filter((k) => /prf|extension/i.test(k))).toEqual(["clientExtensionResults"]);
    expect(Object.keys(signed.assertion.response).some((k) => /prf|extension/i.test(k))).toBe(false);
    const plain = await openPacket(o.r.priv, o.inst, "approve", openAAD(o.attempt, o.epoch, o.ch, auth.rawId), signed.open!);
    const k1 = await deriveKEK(await auth.evaluate(s1), o.inst, RP, auth.rawId, "installation", s1);
    const k2 = await deriveKEK(await auth.evaluate(s2), o.inst, RP, auth.rawId, "org-1", s2);
    expect(hex(plain)).toBe("00000020" + hex(k1) + "00000020" + hex(k2));
    for (const out of auth.handed) expect(out.every((b) => b === 0)).toBe(true);
    await expect(tap.open!.finish({} as never)).rejects.toThrow(/already used/);
  });
  test("a passkey without PRF (or not listed) signs, and no open is sent", async () => {
    const auth = fakeAuth(`https://${RP}`);
    const listed = b64(rnd(16));
    const o = await offer({ scopes: ["installation"], creds: [{ id: listed, salts: [rnd(32)] }], allow: [listed, encode(new Uint8Array(0))] });
    const tap = await prepareTap(o.res, RP);
    const signed = await tap.sign(auth);
    expect(signed.open).toBeUndefined();
    const noPrf = prfAuth(`https://${RP}`, { prf: false });
    const o2 = await offer({ scopes: ["installation"], creds: [{ id: noPrf.id, salts: [rnd(32)] }] });
    expect((await (await prepareTap(o2.res, RP)).sign(noPrf)).open).toBeUndefined();
  });
  test("scope-enrol migrate: slot 1 is the format-1 KEK, slot 2 the scope KEK; only the named passkey", async () => {
    const auth = prfAuth(`https://${RP}`);
    const r = recipient();
    const inst = rnd(32), epoch = rnd(32), attempt = rnd(32), legacyInst = rnd(32), legacySalt = rnd(32), salt = rnd(32);
    const d = { attempt_id: b64(attempt), buckets: [], credential_id: auth.id, epoch: b64(epoch), installation: b64(inst), legacy: { installation: b64(legacyInst), mk_version: 3, prf_salt: b64(legacySalt) }, object: "scope-enrol", purpose: "migrate", recipient: b64(r.pub), salts: [b64(salt)], scopes: ["installation"], v: 1 };
    const text = canonicalJSON(d);
    const ch = await openChallenge(canonical, text);
    const res: ChallengeLike = { canonical, public_key: { challenge: encode(ch), rpId: RP, userVerification: "required", allowCredentials: [{ type: "public-key", id: auth.id }], extensions: { prf: { eval: { first: b64(legacySalt), second: b64(salt) } } } }, open: { descriptor: text } };
    await expect(prepareTap(res, RP, { object: "scope-enrol", purposes: ["stage"] })).rejects.toThrow(/purpose/);
    await expect(prepareTap({ ...res, public_key: { ...(res.public_key as object), extensions: { prf: { eval: { first: b64(salt), second: b64(legacySalt) } } } } }, RP, { object: "scope-enrol" })).rejects.toThrow(/PRF inputs differ/);
    await expect(prepareTap({ ...res, public_key: { ...(res.public_key as object), allowCredentials: [{ type: "public-key", id: b64(rnd(8)) }] } }, RP, { object: "scope-enrol" })).rejects.toThrow(/one named passkey/);
    const tap = await prepareTap(res, RP, { object: "scope-enrol", purposes: ["migrate"], requireOpen: true });
    const signed = await tap.sign(auth);
    const plain = await openPacket(r.priv, inst, "migrate", openAAD(attempt, epoch, ch, auth.rawId), signed.open!);
    const legacyKEK = await wrapKeyBytes((await auth.evaluate(legacySalt)) as Uint8Array<ArrayBuffer>, legacyInst, RP, auth.rawId, 3, legacySalt);
    const scopeKEK = await deriveKEK(await auth.evaluate(salt), inst, RP, auth.rawId, "installation", salt);
    expect(hex(plain)).toBe("00000020" + hex(legacyKEK) + "00000020" + hex(scopeKEK));
    // Without PRF an enrolment step cannot finish.
    const tap2 = await prepareTap(res, RP, { object: "scope-enrol" });
    await expect(tap2.sign(prfAuth(`https://${RP}`, { prf: false, rawId: auth.rawId }))).rejects.toThrow(/PRF/);
  });
  test("requireOpen refuses a plain challenge; a plain one commits to SHA-256(canonical) with no extensions", async () => {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(canonical)));
    const plain: ChallengeLike = { canonical, public_key: { challenge: encode(digest), rpId: RP, userVerification: "required", allowCredentials: [{ type: "public-key", id: b64(rnd(8)) }] } };
    await expect(prepareTap(plain, RP, { requireOpen: true })).rejects.toThrow(/no open descriptor/);
    const tap = await prepareTap(plain, RP);
    expect(tap.open).toBeUndefined();
    expect((await tap.sign(fakeAuth())).open).toBeUndefined();
    await expect(prepareTap({ ...plain, public_key: { ...(plain.public_key as object), extensions: { prf: {} } } }, RP)).rejects.toThrow(/Invalid review options/);
  });
});
