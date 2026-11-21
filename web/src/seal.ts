// The only assertion path which evaluates PRF. Callers supply the frozen
// credential selection from authenticated status, never from the challenge.
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { decode, encode } from "./b64url";
import { decodeRequestOptions, encodeAssertion, unwrapPublicKey, type Authenticator } from "./webauthn";

const utf8 = new TextEncoder();
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
function number(n: number) {
  if (!Number.isSafeInteger(n) || n < 1) throw Error("Invalid seal generation");
  const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(n)); return out;
}
function frames(parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const v = new DataView(out.buffer); let i = 0;
  for (const p of parts) { v.setUint32(i, p.length); out.set(p, i + 4); i += 4 + p.length; }
  return out;
}
function tuple(role: string, ...parts: Uint8Array[]) {
  return frames([utf8.encode("aqmas-seal"), number(1), utf8.encode(role), ...parts]);
}

export async function wrapKeyBytes(prf: Uint8Array<ArrayBuffer>, install: Uint8Array<ArrayBuffer>, rpID: string, cred:Uint8Array, generation:number, salt:Uint8Array) {
  if (prf.length!==32 || install.length!==32 || salt.length!==32 || !cred.length || cred.length>1023) throw Error('Invalid wrap binding');
  const key=await crypto.subtle.importKey('raw',prf,'HKDF',false,['deriveBits']);
  const info=tuple('mk-kek',install,utf8.encode(rpID),cred,number(generation),salt);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:install,info},key,256));
}
function raw(s: unknown, min: number, max = min) {
  if (typeof s !== "string" || s.length > 2 * max) throw Error("Invalid seal binding");
  const b = new Uint8Array(decode(s));
  if (encode(b) !== s || b.length < min || b.length > max) throw Error("Invalid seal binding");
  return b;
}
export interface Selection {
  action: "unlock" | "wrap-enroll"; installation: string; mk_version: number; epoch: string;
  credential_id: string; prf_salt: string; rp_id: string; registration_id?: string;
}
export interface SealBegin { canonical: string; attempt_id: string; publicKey: unknown }

export async function prepareSeal(selection: Selection, begin: SealBegin, rpID: string) {
  const c = JSON.parse(begin.canonical);
  const keys = ["action", "credential_id", "epoch", "id", "installation", "issued_at", "mk_version", "nonce", "object", "prf_salt", "recipient", "rp_id", "suite", "v"];
  if (selection.action === "wrap-enroll") keys.push("registration_id");
  if (c?.v !== 3 || c.object !== "seal" || c.suite !== 1 || !["unlock", "wrap-enroll"].includes(c.action) ||
      c.action !== selection.action || c.id !== begin.attempt_id || c.rp_id !== rpID ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(c.issued_at) || JSON.stringify(c, keys.sort()) !== begin.canonical) throw Error("Invalid seal canonical");
  for (const k of ["installation", "mk_version", "epoch", "credential_id", "prf_salt", "rp_id", "registration_id"] as const) {
    if (selection[k] !== c[k]) throw Error("Seal ceremony differs from selection");
  }
  if (c.action === "wrap-enroll" && !c.registration_id) throw Error("Missing registration binding");
  const install = raw(c.installation, 32), epoch = raw(c.epoch, 32), salt = raw(c.prf_salt, 32), credID = raw(c.credential_id, 1, 1023);
  const id = raw(c.id, 32), pk = raw(c.recipient, 65); raw(c.nonce, 32);
  number(c.mk_version); // reject non-integer or unsafe generations before the tap
  if (pk[0] !== 4) throw Error("Invalid seal recipient");
  const key = await suite.kem.deserializePublicKey(pk.buffer);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(begin.canonical)));
  const o = unwrapPublicKey(begin.publicKey);
  if (o.rpId !== rpID || o.userVerification !== "required" || o.challenge !== encode(digest) ||
      !Array.isArray(o.allowCredentials) || o.allowCredentials.length !== 1 || o.allowCredentials[0]?.id !== c.credential_id ||
      o.allowCredentials[0]?.type !== "public-key" || JSON.stringify(o.extensions) !== JSON.stringify({prf:{eval:{first:c.prf_salt}}})) throw Error("Invalid seal assertion options");
  const options = decodeRequestOptions(o);
  options.extensions = { prf: { eval: { first: salt } } };
  const info = tuple("hpke-finish", install, utf8.encode(c.action));
  const aad = tuple("hpke-aad", id, epoch, digest);
  let used = false;
  return {
    canonical: begin.canonical,
    async finish(auth: Authenticator) {
      if (used) throw Error("Ceremony already used"); used = true;
      const response = await auth.get(options);
      if (encode(response.rawId) !== c.credential_id || response.id !== c.credential_id) throw Error("Unexpected credential");
      const first = (response.getClientExtensionResults?.() as AuthenticationExtensionsClientOutputs)?.prf?.results?.first;
      if (!(first instanceof ArrayBuffer) || first.byteLength !== 32) throw Error("This passkey did not return a PRF result");
      const prf = new Uint8Array(first);
      try {
        const kek = await wrapKeyBytes(prf, install, rpID, credID, c.mk_version, salt);
        try {
          const assertion = utf8.encode(JSON.stringify(encodeAssertion(response)));
          if (assertion.length > 16384) throw Error("Seal assertion too large");
          const plain = frames([kek, assertion]);
          try {
            const sender = await suite.createSenderContext({recipientPublicKey:key,info});
            const ct = await sender.seal(plain, aad);
            return { attempt_id: c.id as string, enc: encode(sender.enc), ciphertext: encode(ct) };
          } finally { plain.fill(0); }
        } finally { kek.fill(0); }
      } finally { prf.fill(0); }
    },
  };
}
