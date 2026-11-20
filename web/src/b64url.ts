// base64url (RFC 4648 section 5) without padding, as go-webauthn's URLEncodedBase64 emits.
// Decoding tolerates trailing "=" padding (go-webauthn accepts both) but rejects the standard
// alphabet's "+" and "/" so a contract mismatch fails loudly instead of decoding garbage.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

export type BytesLike = ArrayBuffer | ArrayBufferView;

function toBytes(data: BytesLike): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data);
}

export function encode(data: BytesLike): string {
  const b = toBytes(data);
  let out = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = b.length - i;
  if (rest === 1) {
    const n = b[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

export class Base64UrlError extends Error {
  override name = "Base64UrlError";
}

/** Decode base64url to a fresh ArrayBuffer (what WebAuthn's BufferSource fields want). */
export function decode(s: string): ArrayBuffer {
  if (typeof s !== "string") throw new Base64UrlError("base64url value is not a string");
  const str = s.replace(/=+$/, "");
  if (str.length % 4 === 1) throw new Base64UrlError("invalid base64url length");
  const out = new Uint8Array(Math.floor((str.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    const v = c < 128 ? LOOKUP[c]! : -1;
    if (v < 0) throw new Base64UrlError(`invalid base64url character at ${i}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // Leftover bits must be zero (canonical encoding).
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Base64UrlError("non-canonical base64url");
  return out.buffer.slice(0, o);
}

export function bytesEqual(a: BytesLike, b: BytesLike): boolean {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}
