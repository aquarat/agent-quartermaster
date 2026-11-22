// Reading side of age's X25519 key encoding, for the mock and the tests (the page itself only
// ever writes these keys: web/src/setup.ts). Written separately from that code on purpose.

const ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** Decode a bech32 (BIP-173) string: checks case, characters and checksum. */
export function bech32Decode(text: string): { hrp: string; data: Uint8Array } {
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) throw new Error("bech32: mixed case");
  const s = text.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (sep < 1 || s.length - sep - 1 < 6) throw new Error("bech32: no separator or checksum");
  const hrp = s.slice(0, sep);
  const values: number[] = [];
  for (const ch of s.slice(sep + 1)) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error("bech32: bad character");
    values.push(v);
  }
  let c = 1n;
  const feed = (v: number) => {
    const b = c >> 25n;
    c = ((c & 0x1ffffffn) << 5n) ^ BigInt(v);
    [0x3b6a57b2n, 0x26508e6dn, 0x1ea119fan, 0x3d4233ddn, 0x2a1462b3n].forEach((g, i) => {
      if ((b >> BigInt(i)) & 1n) c ^= g;
    });
  };
  for (const ch of hrp) feed(ch.charCodeAt(0) >> 5);
  feed(0);
  for (const ch of hrp) feed(ch.charCodeAt(0) & 31);
  for (const v of values) feed(v);
  if (c !== 1n) throw new Error("bech32: bad checksum");
  const out: number[] = [];
  let acc = 0n;
  let bits = 0n;
  for (const v of values.slice(0, -6)) {
    acc = (acc << 5n) | BigInt(v);
    bits += 5n;
    if (bits >= 8n) {
      bits -= 8n;
      out.push(Number((acc >> bits) & 0xffn));
      acc &= (1n << bits) - 1n;
    }
  }
  if (bits >= 5n || acc !== 0n) throw new Error("bech32: bad padding");
  return { hrp, data: Uint8Array.from(out) };
}

/** The age recipient (age1…) of an AGE-SECRET-KEY-1… identity: X25519(scalar, base point). */
export async function recipientOf(identity: string): Promise<{ scalar: Uint8Array; publicKey: Uint8Array }> {
  if (identity !== identity.toUpperCase()) throw new Error("age identities are upper case");
  const { hrp, data } = bech32Decode(identity);
  if (hrp !== "age-secret-key-" || data.length !== 32) throw new Error("not an age X25519 identity");
  // RFC 8410 PKCS#8 wrapper for a raw X25519 private key.
  const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20, ...data]);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]);
  const base = new Uint8Array(32);
  base[0] = 9;
  const point = await crypto.subtle.importKey("raw", base, { name: "X25519" }, false, []);
  const publicKey = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: point }, priv, 256));
  return { scalar: data, publicKey };
}
