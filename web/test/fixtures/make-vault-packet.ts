// Writes "browser_sealed" into test/vectors/vault.json: a form edit sealed by the page's own
// code (web/src/vault.ts vaultCommit) to a fresh recipient, for the Go side to open
// (internal/server/seal/vault_vectors_test.go). Run: bun web/test/fixtures/make-vault-packet.ts
import { createECDH } from "node:crypto";
import { tuple } from "../../src/seal";
import { vaultCommit, type VaultSet } from "../../src/vault";
import type { Api } from "../../src/api";
import type { SealView } from "../../src/sealPanel";

const path = new URL("../../../test/vectors/vault.json", import.meta.url);
const v = await Bun.file(path).json();
const unhex = (s: string) => Buffer.from(s, "hex");
const utf8 = (s: string) => new TextEncoder().encode(s);
const e = createECDH("prime256v1");
e.generateKeys();
const priv = Buffer.alloc(32);
e.getPrivateKey().copy(priv, 32 - e.getPrivateKey().length);

let sent: { enc: string; ciphertext: string } | undefined;
const stop = new Error("captured");
const api = {
  vaultPost: async (p: string, body: { enc: string; ciphertext: string }) => {
    if (p === "attempt") return { attempt_id: unhex(v.attempt_id).toString("base64url"), recipient: e.getPublicKey().toString("base64url") };
    sent = body;
    throw stop;
  },
} as unknown as Api;
const seal = { installation: unhex(v.installation).toString("base64url"), epoch: unhex(v.epoch).toString("base64url") } as SealView;
const set = { set_id: v.set_id, org_id: "1".repeat(32), service_id: "2".repeat(32), kind: "env-set", revision: 7, names: ["OLD_SECRET"] } as VaultSet;
// The plaintext is captured where the page hands it to HPKE (it is zeroed afterwards).
let plaintext = "";
const encode = TextEncoder.prototype.encode;
TextEncoder.prototype.encode = function (s?: string) {
  if (s?.startsWith('{"operation"')) plaintext = s;
  return encode.call(this, s);
};
await vaultCommit(api, seal, set, { operation: "merge", entries: [{ name: "APP_KEY", value: "-----BEGIN KEY-----\nline two\n-----END KEY-----\n" }, { name: "APP_TOKEN", value: 'tok "q" \\ $HOME' }], remove: ["OLD_SECRET"] }, "localhost").catch((err) => {
  if (err !== stop) throw err;
});
TextEncoder.prototype.encode = encode;
if (!sent || !plaintext) throw new Error("nothing was sealed");
v.browser_sealed = {
  purpose: "edit",
  recipient_priv: priv.toString("hex"),
  recipient_pub: e.getPublicKey().toString("hex"),
  info: Buffer.from(tuple("hpke-vault", unhex(v.installation), utf8("edit"))).toString("hex"),
  aad: Buffer.from(tuple("hpke-vault-aad", unhex(v.attempt_id), unhex(v.epoch), utf8(v.set_id))).toString("hex"),
  enc: Buffer.from(sent.enc, "base64url").toString("hex"),
  ciphertext: Buffer.from(sent.ciphertext, "base64url").toString("hex"),
  plaintext,
};
await Bun.write(path, JSON.stringify(v, null, 2) + "\n");
console.log("wrote browser_sealed to test/vectors/vault.json");
