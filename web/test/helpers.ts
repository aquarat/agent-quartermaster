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
