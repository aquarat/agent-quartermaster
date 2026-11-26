// Test helpers: a fake authenticator and a cookie-keeping fetch.
import { encode } from "../src/b64url";
import type { AssertionCredentialLike, AttestationCredentialLike, Authenticator } from "../src/webauthn";

const te = new TextEncoder();
export const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const buf = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

export interface FakeAuth extends Authenticator {
  gets: PublicKeyCredentialRequestOptions[];
  creates: PublicKeyCredentialCreationOptions[];
  /** Override the challenge the fake "signs" (to simulate a phished/other challenge). */
  forceChallenge?: ArrayBuffer;
}

export function fakeAuth(origin = "http://localhost"): FakeAuth {
  const rawId = rnd(32);
  const userHandle = rnd(16);
  const a: FakeAuth = {
    gets: [],
    creates: [],
    async get(o) {
      a.gets.push(o);
      const ch = a.forceChallenge ?? (o.challenge as ArrayBuffer);
      const cd = JSON.stringify({ type: "webauthn.get", challenge: encode(ch), origin, crossOrigin: false });
      const cred: AssertionCredentialLike = {
        id: encode(rawId),
        rawId: buf(rawId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({}),
        response: { clientDataJSON: buf(te.encode(cd)), authenticatorData: buf(rnd(37)), signature: buf(rnd(71)), userHandle: buf(userHandle) },
      };
      return cred;
    },
    async create(o) {
      a.creates.push(o);
      const cd = JSON.stringify({ type: "webauthn.create", challenge: encode(o.challenge as ArrayBuffer), origin });
      const id = rnd(32);
      const cred: AttestationCredentialLike = {
        id: encode(id),
        rawId: buf(id),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({ credProps: { rk: true } }),
        response: { clientDataJSON: buf(te.encode(cd)), attestationObject: buf(rnd(120)), getTransports: () => ["internal", "hybrid"] },
      };
      return cred;
    },
  };
  return a;
}

export interface Sent {
  url: string;
  method: string;
  headers: Headers;
  credentials?: RequestCredentials;
  body?: unknown;
}

/** fetch that keeps the session cookie (Bun's fetch has no jar) and records requests. */
export function jarFetch(log: Sent[] = []): typeof fetch & { log: Sent[]; cookie: () => string } {
  let cookie = "";
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    log.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(headers),
      credentials: init?.credentials,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    });
    if (cookie) headers.set("cookie", cookie);
    const res = await fetch(input, { ...init, headers });
    const sc = res.headers.get("set-cookie");
    if (sc) cookie = sc.split(";")[0]!;
    return res;
  }) as typeof fetch & { log: Sent[]; cookie: () => string };
  f.log = log;
  f.cookie = () => cookie;
  return f;
}

/** A fake passkey with WebAuthn PRF (HMAC-SHA-256 over "WebAuthn PRF\0" ‖ input, like a
 * real authenticator's hmac-secret). `prf: false` = a passkey without PRF. */
export interface PrfAuth extends FakeAuth {
  rawId: Uint8Array;
  id: string;
  /** What the authenticator would return for `salt` (test oracle). */
  evaluate(salt: Uint8Array): Promise<Uint8Array>;
  /** Every PRF output handed out, to check they were wiped. */
  handed: Uint8Array[];
}
export function prfAuth(origin = "http://localhost", opts: { prf?: boolean; rawId?: Uint8Array } = {}): PrfAuth {
  const rawId = opts.rawId ?? rnd(32);
  const secret = rnd(32);
  const userHandle = rnd(16);
  const evaluate = async (salt: Uint8Array) => {
    const k = await crypto.subtle.importKey("raw", buf(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const input = new Uint8Array(13 + salt.length);
    input.set(te.encode("WebAuthn PRF\0"));
    input.set(salt, 13);
    const inner = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    return new Uint8Array(await crypto.subtle.sign("HMAC", k, inner));
  };
  const asBytes = (x: BufferSource) => (x instanceof ArrayBuffer ? new Uint8Array(x) : new Uint8Array(x.buffer, x.byteOffset, x.byteLength));
  const a: PrfAuth = {
    rawId,
    id: encode(rawId),
    handed: [],
    evaluate,
    gets: [],
    creates: [],
    async get(o) {
      a.gets.push(o);
      const ch = a.forceChallenge ?? (o.challenge as ArrayBuffer);
      const cd = JSON.stringify({ type: "webauthn.get", challenge: encode(ch), origin, crossOrigin: false });
      const prf = (o.extensions as { prf?: { eval?: AuthenticationExtensionsPRFValues; evalByCredential?: Record<string, AuthenticationExtensionsPRFValues> } } | undefined)?.prf;
      const values = prf?.evalByCredential?.[encode(rawId)] ?? prf?.eval;
      let results: { first: ArrayBuffer; second?: ArrayBuffer } | undefined;
      if (opts.prf !== false && values) {
        const first = await evaluate(asBytes(values.first));
        const second = values.second ? await evaluate(asBytes(values.second)) : undefined;
        a.handed.push(first, ...(second ? [second] : []));
        results = second ? { first: first.buffer as ArrayBuffer, second: second.buffer as ArrayBuffer } : { first: first.buffer as ArrayBuffer };
      }
      return {
        id: encode(rawId),
        rawId: buf(rawId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => (results ? { prf: { results } } : {}),
        response: { clientDataJSON: buf(te.encode(cd)), authenticatorData: buf(rnd(37)), signature: buf(rnd(71)), userHandle: buf(userHandle) },
      };
    },
    async create(o) {
      a.creates.push(o);
      const cd = JSON.stringify({ type: "webauthn.create", challenge: encode(o.challenge as ArrayBuffer), origin });
      return {
        id: encode(rawId),
        rawId: buf(rawId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({ credProps: { rk: true }, ...(opts.prf !== false ? { prf: { enabled: true } } : {}) }),
        response: { clientDataJSON: buf(te.encode(cd)), attestationObject: buf(rnd(120)), getTransports: () => ["internal"] },
      };
    },
  };
  return a;
}

// ---- a throwaway OpenSSH private key (0.11.0 SSH key import tests) ----
import { generateKeyPairSync } from "node:crypto";

const sshString = (b: Uint8Array | string) => {
  const body = Buffer.from(b);
  const n = Buffer.alloc(4);
  n.writeUInt32BE(body.length);
  return Buffer.concat([n, body]);
};
/** A throwaway Ed25519 key as an unencrypted OpenSSH private key file (made here, used nowhere). */
export function testOpenSSHKey(comment = "test-only"): { pem: string; pub: Buffer } {
  const k = generateKeyPairSync("ed25519");
  const pub = Buffer.from(k.publicKey.export({ format: "jwk" }).x!, "base64url");
  const seed = k.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const blob = Buffer.concat([sshString("ssh-ed25519"), sshString(pub)]);
  const check = Buffer.from([1, 2, 3, 4]);
  let priv = Buffer.concat([check, check, sshString("ssh-ed25519"), sshString(pub), sshString(Buffer.concat([seed, pub])), sshString(comment)]);
  for (let i = 1; priv.length % 8 !== 0; i++) priv = Buffer.concat([priv, Buffer.from([i])]);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(1);
  const file = Buffer.concat([Buffer.from("openssh-key-v1\0"), sshString("none"), sshString("none"), sshString(""), count, sshString(blob), sshString(priv)]);
  return { pem: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + file.toString("base64").replace(/(.{70})(?=.)/g, "$1\n") + "\n-----END OPENSSH PRIVATE KEY-----\n", pub };
}

