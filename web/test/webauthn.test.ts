import { describe, expect, test } from "bun:test";
import { bytesEqual, decode, encode } from "../src/b64url";
import { WebAuthnFormatError, decodeCreationOptions, decodeRequestOptions, encodeAssertion, encodeAttestation } from "../src/webauthn";
import { fakeAuth, rnd } from "./helpers";

const ch = rnd(32);
const credId = rnd(48);
const userId = rnd(64);

// Exactly what go-webauthn's BeginLogin marshals (protocol.CredentialAssertion).
const goAssertion = JSON.parse(
  JSON.stringify({
    publicKey: {
      challenge: encode(ch),
      timeout: 120000,
      rpId: "approvals.example.com",
      allowCredentials: [{ type: "public-key", id: encode(credId), transports: ["internal", "hybrid"] }],
      userVerification: "required",
    },
  }),
);

// What go-webauthn's BeginRegistration marshals (protocol.CredentialCreation).
const goCreation = JSON.parse(
  JSON.stringify({
    publicKey: {
      rp: { name: "aqmas", id: "approvals.example.com" },
      user: { name: "alice", displayName: "alice", id: encode(userId) },
      challenge: encode(ch),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -8 },
      ],
      timeout: 300000,
      excludeCredentials: [{ type: "public-key", id: encode(credId) }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
    },
  }),
);

describe("request options (go-webauthn -> browser)", () => {
  test("decodes publicKey.challenge and allowCredentials[].id to ArrayBuffers", () => {
    const o = decodeRequestOptions(goAssertion);
    expect(o.challenge).toBeInstanceOf(ArrayBuffer);
    expect(bytesEqual(o.challenge as ArrayBuffer, ch)).toBe(true);
    expect(o.rpId).toBe("approvals.example.com");
    expect(o.timeout).toBe(120000);
    expect(o.userVerification).toBe("required");
    expect(o.allowCredentials).toHaveLength(1);
    expect(o.allowCredentials![0]!.type).toBe("public-key");
    expect(bytesEqual(o.allowCredentials![0]!.id as ArrayBuffer, credId)).toBe(true);
    expect(o.allowCredentials![0]!.transports).toEqual(["internal", "hybrid"]);
  });

  test("accepts bare options without the publicKey wrapper", () => {
    const o = decodeRequestOptions(goAssertion.publicKey);
    expect(bytesEqual(o.challenge as ArrayBuffer, ch)).toBe(true);
  });

  test("forces user verification even if the server says otherwise", () => {
    const o = decodeRequestOptions({ publicKey: { ...goAssertion.publicKey, userVerification: "discouraged" } });
    expect(o.userVerification).toBe("required");
  });

  test("drops server-sent extensions", () => {
    const o = decodeRequestOptions({ publicKey: { ...goAssertion.publicKey, extensions: { appid: "https://evil" } } });
    expect(o.extensions).toBeUndefined();
  });

  test("discoverable login: empty/absent allowCredentials is left out", () => {
    const o = decodeRequestOptions({ publicKey: { challenge: encode(ch), allowCredentials: [] } });
    expect(o.allowCredentials).toBeUndefined();
  });

  test("rejects missing or malformed challenge", () => {
    expect(() => decodeRequestOptions({ publicKey: {} })).toThrow(WebAuthnFormatError);
    expect(() => decodeRequestOptions({ publicKey: { challenge: "a+b/" } })).toThrow(WebAuthnFormatError);
    expect(() => decodeRequestOptions(null)).toThrow(WebAuthnFormatError);
  });
});

describe("creation options (go-webauthn -> browser)", () => {
  test("decodes user.id, challenge and excludeCredentials[].id", () => {
    const o = decodeCreationOptions(goCreation);
    expect(bytesEqual(o.user.id as ArrayBuffer, userId)).toBe(true);
    expect(o.user.name).toBe("alice");
    expect(o.user.displayName).toBe("alice");
    expect(bytesEqual(o.challenge as ArrayBuffer, ch)).toBe(true);
    expect(o.rp).toEqual({ name: "aqmas", id: "approvals.example.com" });
    expect(o.pubKeyCredParams).toHaveLength(2);
    expect(bytesEqual(o.excludeCredentials![0]!.id as ArrayBuffer, credId)).toBe(true);
    expect(o.authenticatorSelection?.residentKey).toBe("required");
    expect(o.attestation).toBe("none");
  });

  test("forces discoverable credentials and user verification; only credProps extension", () => {
    const o = decodeCreationOptions({ publicKey: { ...goCreation.publicKey, authenticatorSelection: { userVerification: "discouraged", residentKey: "discouraged", authenticatorAttachment: "platform" }, extensions: { evil: true } } });
    expect(o.authenticatorSelection).toEqual({ authenticatorAttachment: "platform", residentKey: "required", requireResidentKey: true, userVerification: "required" });
    expect(o.extensions).toEqual({ credProps: true });
  });

  test("requires rp, user and pubKeyCredParams", () => {
    expect(() => decodeCreationOptions({ publicKey: { ...goCreation.publicKey, user: undefined } })).toThrow(WebAuthnFormatError);
    expect(() => decodeCreationOptions({ publicKey: { ...goCreation.publicKey, rp: undefined } })).toThrow(WebAuthnFormatError);
  });
});

describe("credentials (browser -> go-webauthn)", () => {
  test("assertion JSON has exactly go-webauthn's fields, unpadded base64url", async () => {
    const auth = fakeAuth();
    const cred = await auth.get(decodeRequestOptions(goAssertion));
    const j = encodeAssertion(cred);
    expect(Object.keys(j).sort()).toEqual(["authenticatorAttachment", "clientExtensionResults", "id", "rawId", "response", "type"]);
    expect(Object.keys(j.response).sort()).toEqual(["authenticatorData", "clientDataJSON", "signature", "userHandle"]);
    expect(j.type).toBe("public-key");
    expect(j.rawId).toBe(j.id);
    for (const v of [j.rawId, j.response.clientDataJSON, j.response.authenticatorData, j.response.signature, j.response.userHandle!]) {
      expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
    }
    // clientDataJSON round-trips and carries the challenge as base64url.
    const cd = JSON.parse(new TextDecoder().decode(decode(j.response.clientDataJSON)));
    expect(cd.type).toBe("webauthn.get");
    expect(cd.challenge).toBe(encode(ch));
    expect(bytesEqual(decode(j.response.signature), cred.response.signature)).toBe(true);
    expect(bytesEqual(decode(j.response.authenticatorData), cred.response.authenticatorData)).toBe(true);
    // Survives JSON serialisation unchanged.
    expect(JSON.parse(JSON.stringify(j))).toEqual(j);
  });

  test("assertion without userHandle omits the field (not null)", async () => {
    const cred = await fakeAuth().get(decodeRequestOptions(goAssertion));
    const j = encodeAssertion({ ...cred, authenticatorAttachment: null, response: { ...cred.response, userHandle: null } });
    expect("userHandle" in j.response).toBe(false);
    expect("authenticatorAttachment" in j).toBe(false);
  });

  test("attestation JSON has clientDataJSON, attestationObject and transports", async () => {
    const cred = await fakeAuth().create(decodeCreationOptions(goCreation));
    const j = encodeAttestation(cred);
    expect(Object.keys(j.response).sort()).toEqual(["attestationObject", "clientDataJSON", "transports"]);
    expect(j.response.transports).toEqual(["internal", "hybrid"]);
    expect(j.clientExtensionResults).toEqual({ credProps: { rk: true } });
    expect(bytesEqual(decode(j.response.attestationObject), cred.response.attestationObject)).toBe(true);
  });
});
