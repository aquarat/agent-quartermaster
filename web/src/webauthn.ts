// Conversion between go-webauthn's JSON (base64url strings) and the browser's WebAuthn
// objects (ArrayBuffers), in both directions. Kept DOM-free apart from the types so it can be
// unit-tested under Bun.
//
// go-webauthn shapes (github.com/go-webauthn/webauthn/protocol):
//   BeginLogin/BeginDiscoverableLogin -> CredentialAssertion {"publicKey": {challenge, timeout,
//     rpId, allowCredentials: [{type, id, transports}], userVerification, hints, extensions}}
//   BeginRegistration -> CredentialCreation {"publicKey": {rp, user: {id, name, displayName},
//     challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection,
//     hints, attestation, attestationFormats, extensions}}
//   ParseCredentialRequestResponse expects {id, rawId, type, authenticatorAttachment,
//     clientExtensionResults, response: {clientDataJSON, authenticatorData, signature, userHandle}}
//   ParseCredentialCreationResponse expects {id, rawId, type, authenticatorAttachment,
//     clientExtensionResults, response: {clientDataJSON, attestationObject, transports}}
// All binary fields are URLEncodedBase64 (unpadded base64url).

import { decode, encode } from "./b64url";

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class WebAuthnFormatError extends Error {
  override name = "WebAuthnFormatError";
}

function req<T>(v: T | undefined | null, what: string): T {
  if (v === undefined || v === null) throw new WebAuthnFormatError(`missing ${what}`);
  return v;
}

function str(v: unknown, what: string): string {
  if (typeof v !== "string") throw new WebAuthnFormatError(`${what} must be a string`);
  return v;
}

function bin(v: unknown, what: string): ArrayBuffer {
  try {
    return decode(str(v, what));
  } catch (e) {
    throw new WebAuthnFormatError(`${what}: ${(e as Error).message}`);
  }
}

/** Accept go-webauthn's wrapper `{publicKey: {...}}` or bare options. */
export function unwrapPublicKey(json: unknown): Json {
  if (!isObject(json)) throw new WebAuthnFormatError("WebAuthn options must be an object");
  const inner = json["publicKey"];
  if (inner !== undefined) {
    if (!isObject(inner)) throw new WebAuthnFormatError("publicKey must be an object");
    return inner;
  }
  return json;
}

function descriptors(v: unknown, what: string): PublicKeyCredentialDescriptor[] | undefined {
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v)) throw new WebAuthnFormatError(`${what} must be an array`);
  return v.map((d, i) => {
    if (!isObject(d)) throw new WebAuthnFormatError(`${what}[${i}] must be an object`);
    const out: PublicKeyCredentialDescriptor = {
      type: (d["type"] as PublicKeyCredentialType | undefined) ?? "public-key",
      id: bin(d["id"], `${what}[${i}].id`),
    };
    if (Array.isArray(d["transports"])) out.transports = d["transports"] as AuthenticatorTransport[];
    return out;
  });
}

function copyIf(src: Json, dst: Json, keys: string[]): void {
  for (const k of keys) if (src[k] !== undefined && src[k] !== null) dst[k] = src[k];
}

/** go-webauthn assertion options JSON -> PublicKeyCredentialRequestOptions. User verification
 * is always forced to "required" (the server requires the UV flag anyway); extensions are
 * dropped (M1 uses none, and binary-valued ones would need their own decoding). */
export function decodeRequestOptions(json: unknown): PublicKeyCredentialRequestOptions {
  const pk = unwrapPublicKey(json);
  const out: Json = {
    challenge: bin(req(pk["challenge"], "publicKey.challenge"), "publicKey.challenge"),
    userVerification: "required",
  };
  copyIf(pk, out, ["timeout", "rpId", "hints"]);
  const allow = descriptors(pk["allowCredentials"], "publicKey.allowCredentials");
  if (allow && allow.length > 0) out["allowCredentials"] = allow;
  return out as unknown as PublicKeyCredentialRequestOptions;
}

/** go-webauthn creation options JSON -> PublicKeyCredentialCreationOptions. */
export function decodeCreationOptions(json: unknown): PublicKeyCredentialCreationOptions {
  const pk = unwrapPublicKey(json);
  const user = pk["user"];
  if (!isObject(user)) throw new WebAuthnFormatError("missing publicKey.user");
  const rp = pk["rp"];
  if (!isObject(rp)) throw new WebAuthnFormatError("missing publicKey.rp");
  const params = pk["pubKeyCredParams"];
  if (!Array.isArray(params)) throw new WebAuthnFormatError("missing publicKey.pubKeyCredParams");
  const out: Json = {
    rp: { ...rp },
    user: {
      id: bin(user["id"], "publicKey.user.id"),
      name: str(user["name"], "publicKey.user.name"),
      displayName: str(user["displayName"] ?? user["name"], "publicKey.user.displayName"),
    },
    challenge: bin(req(pk["challenge"], "publicKey.challenge"), "publicKey.challenge"),
    pubKeyCredParams: params,
  };
  copyIf(pk, out, ["timeout", "attestation", "attestationFormats", "hints"]);
  // Login is discoverable and every approval needs user verification: insist on both.
  const sel = isObject(pk["authenticatorSelection"]) ? pk["authenticatorSelection"] : {};
  out["authenticatorSelection"] = { ...sel, residentKey: "required", requireResidentKey: true, userVerification: "required" };
  const requested = pk["extensions"];
  const probe = isObject(requested) && isObject(requested.prf) && Object.keys(requested.prf).length === 0;
  out["extensions"] = { credProps: true, ...(probe ? {prf:{}} : {}) };
  const exclude = descriptors(pk["excludeCredentials"], "publicKey.excludeCredentials");
  if (exclude && exclude.length > 0) out["excludeCredentials"] = exclude;
  return out as unknown as PublicKeyCredentialCreationOptions;
}

// ---- browser -> JSON ----

/** The parts of a PublicKeyCredential we read (structural, so tests can fake it). */
export interface AssertionCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  authenticatorAttachment?: string | null;
  getClientExtensionResults?: () => unknown;
  response: {
    clientDataJSON: ArrayBuffer;
    authenticatorData: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle?: ArrayBuffer | null;
  };
}

export interface AttestationCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  authenticatorAttachment?: string | null;
  getClientExtensionResults?: () => unknown;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject: ArrayBuffer;
    getTransports?: () => string[];
  };
}

export interface AssertionJSON {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  clientExtensionResults: unknown;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
}

export interface AttestationJSON {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  clientExtensionResults: unknown;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
}

function registrationProperties(c: { getClientExtensionResults?: () => unknown }): unknown {
  try {
    const r = c.getClientExtensionResults?.();
    // Copy only the boolean. Never spread an extension object: PRF results
    // (including unknown future fields) are reusable key material.
    if (isObject(r) && isObject(r.credProps) && typeof r.credProps.rk === "boolean") {
      return { credProps: { rk: r.credProps.rk } };
    }
    return {};
  } catch {
    return {};
  }
}

export function encodeAssertion(c: AssertionCredentialLike): AssertionJSON {
  const r = c.response;
  const out: AssertionJSON = {
    id: c.id,
    rawId: encode(c.rawId),
    type: c.type,
    clientExtensionResults: {},
    response: {
      clientDataJSON: encode(r.clientDataJSON),
      authenticatorData: encode(r.authenticatorData),
      signature: encode(r.signature),
    },
  };
  if (r.userHandle && r.userHandle.byteLength > 0) out.response.userHandle = encode(r.userHandle);
  if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
  return out;
}

export function encodeAttestation(c: AttestationCredentialLike): AttestationJSON {
  const r = c.response;
  let transports: string[] = [];
  try {
    transports = r.getTransports?.() ?? [];
  } catch {
    transports = [];
  }
  const out: AttestationJSON = {
    id: c.id,
    rawId: encode(c.rawId),
    type: c.type,
    clientExtensionResults: registrationProperties(c),
    response: {
      clientDataJSON: encode(r.clientDataJSON),
      attestationObject: encode(r.attestationObject),
      transports,
    },
  };
  if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
  return out;
}

// ---- the authenticator boundary ----

/** What the flows need from the browser; tests supply a fake. */
export interface Authenticator {
  get(options: PublicKeyCredentialRequestOptions): Promise<AssertionCredentialLike>;
  create(options: PublicKeyCredentialCreationOptions): Promise<AttestationCredentialLike>;
}

export function browserAuthenticator(): Authenticator {
  return {
    async get(options) {
      if (!globalThis.navigator?.credentials || !globalThis.PublicKeyCredential) {
        throw new WebAuthnFormatError("This browser does not support passkeys.");
      }
      const cred = await navigator.credentials.get({ publicKey: options });
      if (!cred) throw new WebAuthnFormatError("No passkey was returned.");
      return cred as unknown as AssertionCredentialLike;
    },
    async create(options) {
      if (!globalThis.navigator?.credentials || !globalThis.PublicKeyCredential) {
        throw new WebAuthnFormatError("This browser does not support passkeys.");
      }
      const cred = await navigator.credentials.create({ publicKey: options });
      if (!cred) throw new WebAuthnFormatError("No passkey was created.");
      return cred as unknown as AttestationCredentialLike;
    },
  };
}
