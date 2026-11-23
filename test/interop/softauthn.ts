// Software WebAuthn authenticator (ES256, "none" attestation, discoverable, UV) that really
// signs. It stands in for the owner's passkey in TestUIFlows (internal/server/testdata/
// ui_driver.ts) and in the interop test's owner helper (test/interop/owner.ts). It implements
// the subset of navigator.credentials.create/get that the web UI's flows (web/src/flows.ts)
// call, and checks the UI forced user verification / resident keys as it must.
//
// State can be saved and restored (save()/softAuthenticator(origin, saved)) so a CLI helper can
// keep one passkey across invocations. Test-only: the private key is written in clear.

const te = new TextEncoder();
const u8 = (b: ArrayBuffer | ArrayBufferView) =>
  b instanceof Uint8Array ? b : ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(b);
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
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", ab(b)));
const be32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

export function b64url(b: ArrayBuffer | ArrayBufferView): string {
  return Buffer.from(u8(b)).toString("base64url");
}
export function unb64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

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

export interface SavedAuthenticator {
  prfSecret?: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
  credId: string;
  userHandle: string;
  rpId: string;
  counter: number;
}

export interface SoftAuthenticator {
  create(o: PublicKeyCredentialCreationOptions): Promise<unknown>;
  get(o: PublicKeyCredentialRequestOptions): Promise<unknown>;
  save(): Promise<SavedAuthenticator>;
}

/** `opts.prf: false` makes a passkey without PRF (as some password managers have): it ignores
 * the PRF extension at registration and returns no PRF result (docs/BUCKETS.md §4.4, §13). */
export async function softAuthenticator(origin: string, saved?: SavedAuthenticator, opts: { prf?: boolean } = {}): Promise<SoftAuthenticator> {
  let key: CryptoKeyPair | undefined;
  let credId: Uint8Array = new Uint8Array();
  let userHandle: Uint8Array = new Uint8Array();
  let rpId = "";
  let counter = 0;
  let prfSecret: Uint8Array | undefined;
  if (saved) {
    key = {
      privateKey: await crypto.subtle.importKey("jwk", saved.privateJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]),
      publicKey: await crypto.subtle.importKey("jwk", saved.publicJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
    };
    credId = unb64url(saved.credId);
    userHandle = unb64url(saved.userHandle);
    rpId = saved.rpId;
    counter = saved.counter;
    prfSecret = saved.prfSecret ? unb64url(saved.prfSecret) : undefined;
  }
  return {
    async create(o) {
      if (o.authenticatorSelection?.userVerification !== "required" || o.authenticatorSelection?.residentKey !== "required")
        throw new Error("UI did not force UV/resident key");
      key = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
      credId = crypto.getRandomValues(new Uint8Array(32));
      prfSecret = o.extensions?.prf && opts.prf !== false ? crypto.getRandomValues(new Uint8Array(32)) : undefined;
      userHandle = u8(o.user.id as ArrayBuffer);
      rpId = o.rp.id!;
      const cose = cMap([[cInt(1), cInt(2)], [cInt(3), cInt(-7)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(raw.slice(1, 33))], [cInt(-3), cBytes(raw.slice(33))]]);
      const authData = cat(await sha256(te.encode(rpId)), new Uint8Array([0x45]), be32(counter), new Uint8Array(16), new Uint8Array([0, credId.length]), credId, cose);
      const att = cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cMap([])], [cText("authData"), cBytes(authData)]]);
      const cd = te.encode(JSON.stringify({ type: "webauthn.create", challenge: b64url(o.challenge as ArrayBuffer), origin, crossOrigin: false }));
      return {
        id: b64url(credId),
        rawId: ab(credId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({ ...(o.extensions?.credProps ? { credProps: { rk: true } } : {}), ...(prfSecret ? {prf:{enabled:true}} : {}) }),
        response: { clientDataJSON: ab(cd), attestationObject: ab(att), getTransports: () => ["internal", "hybrid"] },
      };
    },
    async get(o) {
      if (!key) throw new Error("no credential");
      if (o.rpId && o.rpId !== rpId) throw new Error("credential belongs to another RP");
      if (o.allowCredentials?.length && !o.allowCredentials.some(d => b64url(d.id as ArrayBuffer) === b64url(credId))) throw new Error("credential not allowed");
      // PRF: `eval`, or `evalByCredential` (only the entry of the answering credential counts,
      // as in WebAuthn L3). Model the authenticator's credential-specific UV hmac-secret: the
      // PRF extension hashes its domain prefix and input before evaluation.
      const prfIn = o.extensions?.prf as { eval?: { first?: BufferSource; second?: BufferSource }; evalByCredential?: Record<string, { first?: BufferSource; second?: BufferSource }> } | undefined;
      const inputs = prfIn?.evalByCredential?.[b64url(credId)] ?? prfIn?.eval;
      const evalPRF = async (salt: BufferSource) => {
        const secret = await crypto.subtle.importKey("raw", ab(prfSecret!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        return crypto.subtle.sign("HMAC", secret, ab(await sha256(cat(te.encode("WebAuthn PRF\0"), u8(salt as ArrayBuffer)))));
      };
      let first: ArrayBuffer | undefined, second: ArrayBuffer | undefined;
      if (inputs?.first && prfSecret) {
        first = await evalPRF(inputs.first);
        if (inputs.second) second = await evalPRF(inputs.second);
      }
      if (o.userVerification !== "required") throw new Error("UI did not require UV");
      counter++;
      const authData = cat(await sha256(te.encode(o.rpId ?? rpId)), new Uint8Array([0x05]), be32(counter));
      const cd = te.encode(JSON.stringify({ type: "webauthn.get", challenge: b64url(o.challenge as ArrayBuffer), origin, crossOrigin: false }));
      const p1363 = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, cat(authData, await sha256(cd))));
      return {
        id: b64url(credId),
        rawId: ab(credId),
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => (first ? { prf: { results: second ? { first, second } : { first } } } : {}),
        response: { clientDataJSON: ab(cd), authenticatorData: ab(authData), signature: ab(der(p1363)), userHandle: ab(userHandle) },
      };
    },
    async save() {
      if (!key) throw new Error("no credential to save");
      return {
        privateJwk: await crypto.subtle.exportKey("jwk", key.privateKey),
        publicJwk: await crypto.subtle.exportKey("jwk", key.publicKey),
        credId: b64url(credId),
        userHandle: b64url(userHandle),
        rpId,
        counter,
        ...(prfSecret ? {prfSecret:b64url(prfSecret)} : {}),
      };
    },
  };
}
