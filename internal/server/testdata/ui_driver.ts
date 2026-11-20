// Owner side of TestUIFlows (ui_flows_test.go): drives a real aqmasd through the web UI's own
// flow code (web/src/flows.ts + api.ts from the ws/web workstream) with a software WebAuthn
// authenticator that really signs (ECDSA P-256, "none" attestation).
//
//   AQMAS_WEB_DIR=<checkout>/web AQMAS_BASE=http://127.0.0.1:port AQMAS_ORIGIN=https://aqmas.example.com \
//   AQMAS_CODE=<enroll code> bun internal/server/testdata/ui_driver.ts
//
// Steps: register first passkey (enroll code), sign in, approve the pending enrollment, approve
// the pending SSH request for 10 min with a 1 h standing approval, wait for the second (auto-
// approved) grant, revoke the standing approval, revoke the first grant, add a second passkey,
// sign in with it. Prints "UI-DRIVER OK" at the end.

const web = process.env.AQMAS_WEB_DIR!;
const base = process.env.AQMAS_BASE!;
const origin = process.env.AQMAS_ORIGIN!;
const code = process.env.AQMAS_CODE!;

const { createApi } = await import(`${web}/src/api.ts`);
const flows = await import(`${web}/src/flows.ts`);
const { encode, decode } = await import(`${web}/src/b64url.ts`);

const te = new TextEncoder();
const u8 = (b: ArrayBuffer | Uint8Array) => (b instanceof Uint8Array ? b : new Uint8Array(b));
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const ab = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const be32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

// Minimal CBOR (definite lengths only).
function head(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  return new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
}
const cInt = (n: number) => (n >= 0 ? head(0, n) : head(1, -1 - n));
const cBytes = (b: Uint8Array) => cat(head(2, b.length), b);
const cText = (s: string) => cat(head(3, te.encode(s).length), te.encode(s));
const cMap = (pairs: Uint8Array[][]) => cat(head(5, pairs.length), ...pairs.flat());

// P1363 (r||s) -> DER ECDSA-Sig-Value.
function der(sig: Uint8Array): Uint8Array {
  const int = (x: Uint8Array) => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++;
    let v = x.slice(i);
    if (v[0]! & 0x80) v = cat(new Uint8Array([0]), v);
    return cat(new Uint8Array([2, v.length]), v);
  };
  const body = cat(int(sig.slice(0, 32)), int(sig.slice(32)));
  return cat(new Uint8Array([0x30, body.length]), body);
}

function softAuthenticator() {
  let key: CryptoKeyPair;
  let credId: Uint8Array;
  let userHandle: Uint8Array;
  let rpId = "";
  let counter = 0;
  return {
    async create(o: PublicKeyCredentialCreationOptions) {
      if (o.authenticatorSelection?.userVerification !== "required" || o.authenticatorSelection?.residentKey !== "required") throw new Error("UI did not force UV/resident key");
      key = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
      credId = crypto.getRandomValues(new Uint8Array(32));
      userHandle = u8(o.user.id as ArrayBuffer);
      rpId = o.rp.id!;
      const cose = cMap([[cInt(1), cInt(2)], [cInt(3), cInt(-7)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(raw.slice(1, 33))], [cInt(-3), cBytes(raw.slice(33))]]);
      const authData = cat(await sha256(te.encode(rpId)), new Uint8Array([0x45]), be32(counter), new Uint8Array(16), new Uint8Array([0, credId.length]), credId, cose);
      const att = cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cMap([])], [cText("authData"), cBytes(authData)]]);
      const cd = te.encode(JSON.stringify({ type: "webauthn.create", challenge: encode(o.challenge as ArrayBuffer), origin, crossOrigin: false }));
      return {
        id: encode(credId),
        rawId: ab(credId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => (o.extensions && (o.extensions as Record<string, unknown>).credProps ? { credProps: { rk: true } } : {}),
        response: { clientDataJSON: ab(cd), attestationObject: ab(att), getTransports: () => ["internal", "hybrid"] },
      };
    },
    async get(o: PublicKeyCredentialRequestOptions) {
      if (o.userVerification !== "required") throw new Error("UI did not require UV");
      counter++;
      const authData = cat(await sha256(te.encode(o.rpId ?? rpId)), new Uint8Array([0x05]), be32(counter));
      const cd = te.encode(JSON.stringify({ type: "webauthn.get", challenge: encode(o.challenge as ArrayBuffer), origin, crossOrigin: false }));
      const p1363 = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, cat(authData, await sha256(cd))));
      return {
        id: encode(credId),
        rawId: ab(credId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({}),
        response: { clientDataJSON: ab(cd), authenticatorData: ab(authData), signature: ab(der(p1363)), userHandle: ab(userHandle) },
      };
    },
  };
}

// fetch with a cookie jar (the session cookie is Secure; this test talks plain HTTP to 127.0.0.1
// exactly like cloudflared does, so keep it by hand).
let cookie = "";
const jar = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const h = new Headers(init?.headers);
  if (cookie) h.set("cookie", cookie);
  const res = await fetch(input, { ...init, headers: h });
  const sc = res.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0]!;
  return res;
}) as typeof fetch;

const api = createApi({ base, fetch: jar });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor<T>(what: string, f: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 300; i++) {
    const v = await f();
    if (v !== undefined) return v;
    await sleep(100);
  }
  throw new Error("timed out waiting for " + what);
}
const step = (s: string) => console.log("ui-driver: " + s);

const owner = softAuthenticator();
await flows.completeRegistration(api, owner, await flows.prepareRegistrationWithCode(api, code));
step("registered first passkey");
await flows.completeLogin(api, owner, await flows.prepareLogin(api));
step("signed in");

const enr = await waitFor("enrollment", async () => (await api.state()).pending?.find((p: any) => p.kind === "enrollment"));
if (!enr.enrollment?.csr_fingerprint) throw new Error("enrollment card lacks csr_fingerprint");
let p = await flows.prepareAction(api, flows.targetForPending(enr), { action: "approve" });
step("enrollment canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);
step("approved enrollment");

const req = await waitFor("ssh request", async () => (await api.state()).pending?.find((p: any) => p.kind === "ssh"));
// The owner may not lengthen: the server must refuse, not clamp.
try {
  await flows.prepareAction(api, flows.targetForPending(req), { action: "approve", ttl_seconds: req.ttl_max + 60 });
  throw new Error("server accepted a TTL above ttl_max");
} catch (e) {
  if (!(e instanceof Error) || (e as any).status !== 400) throw e;
}
p = await flows.prepareAction(api, flows.targetForPending(req), { action: "approve", ttl_seconds: 600, standing_hours: 1 });
step("request canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);
step("approved ssh request with 1 h standing approval");

const st = await api.state();
if (!st.standing?.length) throw new Error("no standing approval in state");
const grants = await waitFor("two grants", async () => {
  const g = (await api.state()).grants;
  return g && g.length >= 2 ? g : undefined;
});
if (!grants.every((g: any) => g.requesting_host === "uihost")) throw new Error("grants lack requesting_host");

p = await flows.prepareAction(api, flows.targetForStanding(st.standing[0]), { action: "revoke" });
await flows.completeAction(api, owner, p);
step("revoked standing approval");
const first = grants[grants.length - 1];
p = await flows.prepareAction(api, flows.targetForGrant(first), { action: "revoke" });
await flows.completeAction(api, owner, p);
step("revoked grant " + first.id);
console.log("REVOKED-GRANT " + first.id);

// Second passkey: sign "passkey add", register, then sign in with it.
const second = softAuthenticator();
p = await flows.prepareAction(api, flows.PASSKEY_TARGET, { action: "add" });
step("passkey canonical: " + p.canonicalText);
const reg = await flows.authorizeAddPasskey(api, owner, p);
await flows.completeRegistration(api, second, reg);
cookie = "";
await flows.completeLogin(api, second, await flows.prepareLogin(api));
if ((await api.state()).owner.passkeys !== 2) throw new Error("second passkey not registered");
step("added and used a second passkey");
console.log("UI-DRIVER OK");
