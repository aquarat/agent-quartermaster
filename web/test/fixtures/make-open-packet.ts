// Writes "browser_packet" into test/vectors/buckets.json: the KEK packet exactly as the
// page builds it (src/buckets.ts), F(KEK) ‖ F(KEK2) sealed to the vector's RecipientPub with
// its Info and AAD. Go's TestBucketVectors opens it. Synthetic keys only.
//
//   cd web && bun test/fixtures/make-open-packet.ts
import { deriveKEK, openAAD, openInfo, sealKEKs } from "../../src/buckets";
import { decode } from "../../src/b64url";

const path = new URL("../../../test/vectors/buckets.json", import.meta.url);
const v = JSON.parse(await Bun.file(path).text());
const x = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const hex = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("hex");

const inst = x(v.Installation), cred = x(v.Cred), challenge = x(v.Challenge);
const kek = await deriveKEK(x(v.PRF), inst, v.RPID, cred, v.Scope, x(v.Salt));
if (hex(kek) !== v.KEK) throw Error("KEK differs from the Go vector");
if (hex(openInfo(inst, "approve")) !== v.Info || hex(openAAD(x(v.AttemptID), x(v.Epoch), challenge, cred)) !== v.AAD) throw Error("Info/AAD differ from the Go vector");
const kek2 = new Uint8Array(32).fill(7);
const kek2Hex = hex(kek2);
const sealed = await sealKEKs(x(v.RecipientPub), openInfo(inst, "approve"), openAAD(x(v.AttemptID), x(v.Epoch), challenge, cred), [kek, kek2]);
v.browser_packet = { Enc: hex(decode(sealed.enc)), Ciphertext: hex(decode(sealed.ciphertext)), KEK2: kek2Hex };
await Bun.write(path, JSON.stringify(v, null, 2) + "\n");
console.log("wrote browser_packet");
