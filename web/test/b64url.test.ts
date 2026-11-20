import { describe, expect, test } from "bun:test";
import { Base64UrlError, bytesEqual, decode, encode } from "../src/b64url";

describe("base64url", () => {
  test("round-trips every length 0..64 and random data", () => {
    for (let n = 0; n <= 64; n++) {
      const b = crypto.getRandomValues(new Uint8Array(n));
      const s = encode(b);
      expect(s).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(s).toBe(Buffer.from(b).toString("base64url"));
      expect(bytesEqual(decode(s), b)).toBe(true);
    }
  });

  test("RFC 4648 vectors, unpadded", () => {
    const vec: Array<[string, string]> = [["", ""], ["f", "Zg"], ["fo", "Zm8"], ["foo", "Zm9v"], ["foob", "Zm9vYg"], ["fooba", "Zm9vYmE"], ["foobar", "Zm9vYmFy"]];
    for (const [plain, enc] of vec) {
      expect(encode(new TextEncoder().encode(plain))).toBe(enc);
      expect(new TextDecoder().decode(decode(enc))).toBe(plain);
    }
  });

  test("uses - and _ (url alphabet)", () => {
    expect(encode(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe("-_-_");
  });

  test("tolerates padding like go-webauthn", () => {
    expect(new TextDecoder().decode(decode("Zm8="))).toBe("fo");
    expect(new TextDecoder().decode(decode("Zg=="))).toBe("f");
  });

  test("rejects the standard alphabet, junk and bad lengths", () => {
    expect(() => decode("+/+/")).toThrow(Base64UrlError);
    expect(() => decode("ab c")).toThrow(Base64UrlError);
    expect(() => decode("abcde")).toThrow(Base64UrlError);
    expect(() => decode("Zh")).toThrow(Base64UrlError); // non-zero trailing bits
  });

  test("decode returns an ArrayBuffer of the exact length", () => {
    const ab = decode("AAECAwQ");
    expect(ab).toBeInstanceOf(ArrayBuffer);
    expect(ab.byteLength).toBe(5);
  });

  test("encode accepts views at an offset", () => {
    const big = new Uint8Array([9, 9, 1, 2, 3, 9]);
    expect(encode(big.subarray(2, 5))).toBe(encode(new Uint8Array([1, 2, 3])));
    expect(encode(new DataView(big.buffer, 2, 3))).toBe("AQID");
  });
});
