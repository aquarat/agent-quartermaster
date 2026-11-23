// Seal format 2 in the browser (docs/BUCKETS.md §3–4): the open descriptor a challenge
// carries, the bound WebAuthn challenge, the PRF inputs, the per-scope KEK derivation and the
// HPKE packet that takes the KEKs to the broker. DOM-free so it is unit-tested against the Go
// vectors (test/vectors/buckets.json).
//
// One rule above all: a raw PRF output never leaves this module. It is turned into a KEK at
// once, the KEKs are sealed to the ceremony's recipient, and every buffer is zeroed. The
// assertion that is sent next to the packet is built by encodeAssertion, which never copies
// extension results.

import { decode, encode } from "./b64url";
import { frames, suite, wrapKeyBytes } from "./seal";
import { decodeRequestOptions, encodeAssertion, unwrapPublicKey, type AssertionCredentialLike, type AssertionJSON, type Authenticator } from "./webauthn";
import { NOT_REMEMBERED, type BrowserKeys, type LocalBrowserKey } from "./browserKey";

const utf8 = new TextEncoder();
type Bytes = Uint8Array<ArrayBuffer>;

export class OpenError extends Error {
  override name = "OpenError";
}
/** The passkey that was to hold a scope key returned no PRF result. The enable flow offers
 * "Remember this browser" instead (§13); everywhere else it is an error like any other. */
export class NoPrfError extends OpenError {}
const fail = (why: string): never => {
  throw new OpenError(why);
};

/** A fresh copy whose buffer is exactly its bytes (what WebCrypto and @hpke/core want). */
function own(b: Uint8Array): Bytes {
  const out = new Uint8Array(b.length);
  out.set(b);
  return out;
}

function u64(n: number): Bytes {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

/** T2(role, f…) = F("aqmas-seal") ‖ F(u64be(2)) ‖ F(role) ‖ F(f)… */
export function t2(role: string, ...fields: Uint8Array[]): Bytes {
  return own(frames([utf8.encode("aqmas-seal"), u64(2), utf8.encode(role), ...fields]));
}

export async function sha256(b: Uint8Array | string): Promise<Bytes> {
  const data = typeof b === "string" ? utf8.encode(b) : own(b);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

/** SHA-256(T2("open-challenge", SHA-256(canonical), SHA-256(descriptor))). */
export async function openChallenge(canonical: string, descriptor: string): Promise<Bytes> {
  return sha256(t2("open-challenge", await sha256(canonical), await sha256(descriptor)));
}

export const kekInfo = (inst: Uint8Array, rpId: string, cred: Uint8Array, scope: string, salt: Uint8Array) =>
  t2("scope-kek", inst, utf8.encode(rpId), cred, utf8.encode(scope), salt);
/** HPKE info of a remembered browser's sealed KEK (§13): T2("browser-kek", inst, rp, cred, scope, wrap id, browser key). */
export const browserKekInfo = (inst: Uint8Array, rpId: string, cred: Uint8Array, scope: string, wrapId: Uint8Array, browserKey: Uint8Array) =>
  t2("browser-kek", inst, utf8.encode(rpId), cred, utf8.encode(scope), wrapId, browserKey);
export const openInfo = (inst: Uint8Array, purpose: string) => t2("hpke-open", inst, utf8.encode(purpose));
export const openAAD = (attempt: Uint8Array, epoch: Uint8Array, challenge: Uint8Array, cred: Uint8Array) => t2("open-aad", attempt, epoch, challenge, cred);

/** KEK = HKDF-SHA256(ikm = PRF output, salt = installation, info = T2("scope-kek", …), 32). */
export async function deriveKEK(prf: Uint8Array, inst: Uint8Array, rpId: string, cred: Uint8Array, scope: string, salt: Uint8Array): Promise<Bytes> {
  if (prf.length !== 32 || inst.length !== 32 || salt.length !== 32 || !cred.length || cred.length > 1023 || !validScope(scope) || !rpId) fail("Invalid KEK binding");
  const ikm = own(prf);
  try {
    const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: own(inst), info: kekInfo(inst, rpId, cred, scope, salt) }, key, 256));
  } finally {
    ikm.fill(0);
  }
}

/** HPKE base mode to `recipient` (65-byte point) of F(KEK1) ‖ F(KEK2 or ""). Zeroes the plaintext. */
export async function sealKEKs(recipient: Uint8Array, info: Uint8Array, aad: Uint8Array, keks: Uint8Array[]): Promise<{ enc: string; ciphertext: string }> {
  if (keks.length < 1 || keks.length > 2 || keks.some((k) => k.length !== 32)) fail("Invalid KEKs");
  return sealTo(recipient, info, aad, frames([keks[0]!, keks[1] ?? new Uint8Array(0)]));
}

/** HPKE base mode, single shot; zeroes `plain`. Used for KEK packets and the recovery identity. */
export async function sealTo(recipient: Uint8Array, info: Uint8Array, aad: Uint8Array, plain: Uint8Array): Promise<{ enc: string; ciphertext: string }> {
  try {
    if (recipient.length !== 65 || recipient[0] !== 4) fail("Invalid recipient");
    const recipientPublicKey = await suite.kem.deserializePublicKey(own(recipient).buffer);
    const sender = await suite.createSenderContext({ recipientPublicKey, info: own(info).buffer });
    const ct = await sender.seal(own(plain).buffer, own(aad).buffer);
    return { enc: encode(sender.enc), ciphertext: encode(ct) };
  } finally {
    plain.fill(0);
  }
}

// ---- descriptors ----

export interface OpenBucket {
  hold: string;
  id: string;
  kind: string;
  label: string;
  scope: string;
  /** RFC 3339, or "" when the hold has no fixed end (restart, revoke, policy change). */
  until: string;
}
export interface Legacy {
  mk_version: number;
  prf_salt: string;
  installation: string;
}
export interface Descriptor {
  attempt_id: string;
  buckets: OpenBucket[];
  epoch: string;
  installation: string;
  object: "bucket-open" | "scope-enrol";
  purpose: string;
  recipient: string;
  scopes: string[];
  v: 1;
  /** scope-enrol only: the one passkey that may answer, and the PRF inputs aligned with scopes. */
  credential_id?: string;
  salts?: string[];
  /** scope-enrol, purpose "migrate": the format-1 unlock wrap the first PRF input opens. */
  legacy?: Legacy;
  /** scope-enrol for a remembered browser (§13): that browser key's public half. The salts are
   * then wrap IDs and the KEKs come from the browser, not from PRF. */
  browser_key?: string;
  /** bucket-open of a rekey (one scope): the fresh salt of the second PRF evaluation; the new
   * scope key is wrapped under the KEK derived from it, not under the passkey's old salt. */
  rekey_salt?: string;
}

export const ENROL_PURPOSES = ["enrol", "test", "stage", "migrate"] as const;
const OPEN_KEYS = ["attempt_id", "buckets", "epoch", "installation", "object", "purpose", "recipient", "scopes", "v"];
const BUCKET_KEYS = ["hold", "id", "kind", "label", "scope", "until"];
const RFC3339 = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?(Z|[+-]\d\d:\d\d)$/;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
function exactKeys(o: Record<string, unknown>, keys: string[], what: string) {
  const got = Object.keys(o).sort();
  const want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) fail(`${what} has unexpected fields`);
}
/** Unpadded base64url of exactly `min`..`max` bytes, in its one canonical spelling. */
export function rawB64(v: unknown, min: number, max = min): Bytes {
  if (typeof v !== "string" || v.length > Math.ceil((max * 4) / 3) + 1) fail("Invalid binary field");
  let b: Bytes;
  try {
    b = new Uint8Array(decode(v as string));
  } catch {
    return fail("Invalid binary field");
  }
  if (encode(b) !== v || b.length < min || b.length > max) fail("Invalid binary field");
  return b;
}
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const wellFormed = (s: string) => !LONE.test(s);
function validScope(s: unknown): s is string {
  return typeof s === "string" && s.length > 0 && utf8.encode(s).length <= 256 && wellFormed(s);
}
const text = (s: unknown, max: number) => typeof s === "string" && utf8.encode(s).length <= max && wellFormed(s);

/** Sorted-key, whitespace-free JSON as Go's encoding/json writes it with HTML escaping off. */
export function canonicalJSON(v: unknown): string {
  const enc = (x: unknown): string => {
    if (Array.isArray(x)) return `[${x.map(enc).join(",")}]`;
    if (isObject(x)) return `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${enc(x[k])}`).join(",")}}`;
    return JSON.stringify(x);
  };
  return enc(v).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

export interface DescriptorExpectation {
  /** Which shape is acceptable here (default: bucket-open only). */
  object?: Descriptor["object"];
  /** Acceptable purposes (default: "approve" for bucket-open, any enrol purpose for scope-enrol). */
  purposes?: readonly string[];
  installation?: string;
  epoch?: string;
  /** A rekey: the descriptor must carry `rekey_salt` (and only then may it). */
  rekey?: boolean;
  /** scope-enrol for a remembered browser: the descriptor must name exactly this browser key
   * (base64url public half), and only then may it name one. */
  browserKey?: string;
}

/** Parse and validate a descriptor exactly per the wire contract; refuses anything else. */
export function parseDescriptor(textIn: string, want: DescriptorExpectation = {}): Descriptor {
  if (typeof textIn !== "string" || textIn.length > 65536) fail("Invalid open descriptor");
  let d: unknown;
  try {
    d = JSON.parse(textIn);
  } catch {
    return fail("Open descriptor is not JSON");
  }
  if (!isObject(d)) return fail("Open descriptor is not an object");
  const object = want.object ?? "bucket-open";
  if (d.object !== object) fail(`Open descriptor is not a ${object}`);
  if (d.v !== 1) fail("Unknown open descriptor version");
  const purposes = want.purposes ?? (object === "bucket-open" ? ["approve"] : ENROL_PURPOSES);
  if (typeof d.purpose !== "string" || !purposes.includes(d.purpose)) fail("Unexpected open purpose");
  if (object === "bucket-open" && d.purpose !== "approve") fail("Unexpected open purpose");
  if (object === "scope-enrol" && !(ENROL_PURPOSES as readonly string[]).includes(d.purpose as string)) fail("Unexpected open purpose");
  const keys = [...OPEN_KEYS];
  if (object === "scope-enrol") keys.push("credential_id", "salts");
  if (d.purpose === "migrate") keys.push("legacy");
  if (object === "bucket-open" && want.rekey) keys.push("rekey_salt");
  if (want.browserKey !== undefined) {
    if (object !== "scope-enrol" || (d.purpose !== "enrol" && d.purpose !== "test")) fail("A browser key is named only when a browser is remembered or tested");
    keys.push("browser_key");
  }
  exactKeys(d, keys, "Open descriptor");
  rawB64(d.attempt_id, 32);
  rawB64(d.installation, 32);
  rawB64(d.epoch, 32);
  const r = rawB64(d.recipient, 65);
  if (r[0] !== 4) fail("Invalid open recipient");
  if (want.installation !== undefined && d.installation !== want.installation) fail("Open descriptor names another installation");
  if (want.epoch !== undefined && d.epoch !== want.epoch) fail("Open descriptor is from another broker start");
  const scopes = d.scopes;
  if (!Array.isArray(scopes) || scopes.length < 1 || scopes.length > 2 || !scopes.every(validScope) || new Set(scopes).size !== scopes.length) fail("Open descriptor must name one or two scopes");
  if (want.rekey) {
    if ((scopes as string[]).length !== 1) fail("A rekey opens exactly one scope");
    rawB64(d.rekey_salt, 32);
  }
  if (!Array.isArray(d.buckets) || d.buckets.length > 512) fail("Invalid bucket list");
  const ids = new Set<string>();
  for (const b of d.buckets as unknown[]) {
    if (!isObject(b)) fail("Invalid bucket entry");
    const e = b as Record<string, unknown>;
    exactKeys(e, BUCKET_KEYS, "Bucket entry");
    rawB64(e.id, 32);
    if (ids.has(e.id as string)) fail("Bucket listed twice");
    ids.add(e.id as string);
    if (!(scopes as string[]).includes(e.scope as string)) fail("A bucket's scope is not in the descriptor");
    if (!validScope(e.kind) || !text(e.label, 1024) || !text(e.hold, 256) || !(e.hold as string)) fail("Invalid bucket entry");
    if (typeof e.until !== "string" || (e.until !== "" && !RFC3339.test(e.until))) fail("Invalid bucket hold end");
  }
  if (object === "scope-enrol") {
    if ((d.buckets as unknown[]).length) fail("An enrolment opens no bucket");
    rawB64(d.credential_id, 1, 1023);
    if (!Array.isArray(d.salts) || d.salts.length !== (scopes as string[]).length) fail("Salts do not match the scopes");
    for (const s of d.salts as unknown[]) rawB64(s, 32);
    if (want.browserKey !== undefined) {
      const k = rawB64(d.browser_key, 65);
      if (k[0] !== 4 || d.browser_key !== want.browserKey) fail("This step is for another browser's key");
    }
    if (d.purpose === "migrate") {
      if ((scopes as string[]).length !== 1) fail("Migration stages exactly one scope per tap");
      const l = d.legacy;
      if (!isObject(l)) return fail("Missing legacy binding");
      exactKeys(l, ["installation", "mk_version", "prf_salt"], "Legacy binding");
      if (!Number.isSafeInteger(l.mk_version) || (l.mk_version as number) < 1) fail("Invalid legacy generation");
      rawB64(l.prf_salt, 32);
      rawB64(l.installation, 32);
    }
  }
  if (canonicalJSON(d) !== textIn) fail("Open descriptor is not in canonical form");
  return d as unknown as Descriptor;
}

// ---- what the card says ----

const HOLDS: Record<string, string> = {
  instant: "for this action only",
  grant: "while the grant lasts",
  env: "until the values are collected (10 minutes at most)",
  sign: "while the signing grant lasts",
  standing: "while the standing rule lasts",
  auto: "while auto-approval is on (until restart)",
  window: "while the approval window is open",
};
/** The broker's instant hold: its reason text ("instant (this approval only)") or its kind. */
const isInstant = (part: string) => part === "instant" || part.startsWith("instant (");
/** The card's words for a descriptor's `hold`: the broker joins the reasons of a bucket's holds
 * with "; " (e.g. "instant (this approval only); Cloudflare grant"). A hold kind is spelled out;
 * any other reason is shown as the broker wrote it; the instant part is dropped next to others. */
export function holdWords(hold: string, until: string): string {
  const all = hold.split("; ").filter((p) => p !== "");
  const lasting = all.filter((p) => !isInstant(p));
  if (!lasting.length) return HOLDS.instant!;
  const base = lasting.map((p) => HOLDS[p] ?? p).join("; ");
  if (!until) return base;
  return `${base}, until ${until.replace("T", " ").replace(/(\.\d+)?Z$/, " UTC")}`;
}

/** One line per bucket, for the card before the tap. */
export function describeOpen(d: Descriptor): string[] {
  if (d.object === "scope-enrol" && d.browser_key) {
    return [
      d.purpose === "test"
        ? `Tests that this browser can open: ${d.scopes.join(", ")}. Opens no credential.`
        : `Creates this browser's keys for: ${d.scopes.join(", ")}. From then on this passkey opens them only together with this browser. Opens no credential.`,
    ];
  }
  if (d.object === "scope-enrol") {
    const verb = d.purpose === "test" ? "Tests" : d.purpose === "migrate" ? "Opens the format-1 key and creates" : "Creates";
    return [`${verb} this passkey's key for: ${d.scopes.join(", ")}. Opens no credential.`];
  }
  if (d.rekey_salt) {
    // A rekey opens the old keys only to re-encrypt: every bucket of the scope ends closed.
    const re = d.buckets.length ? [`Re-keys ${d.buckets.map((b) => b.label).join(", ")} (closes them; users pause until you Reopen them).`] : [];
    return [...re, `Rekeys ${d.scopes[0]}: your passkey's new key uses a fresh PRF input (a remembered browser: a fresh key). It taps once more right afterwards to test it.`];
  }
  if (!d.buckets.length) return [`Opens the scope key of ${d.scopes.join(" and ")} for the length of this tap (no credential stays open).`];
  return d.buckets.map((b) => `Opens ${b.label}: ${holdWords(b.hold, b.until)}`);
}

// ---- the tap ----

export interface OpenPacket {
  attempt_id: string;
  enc: string;
  ciphertext: string;
}
export interface PreparedOpen {
  descriptor: Descriptor;
  text: string;
  /** The bound challenge (raw). */
  challenge: Bytes;
  /** Raw credential IDs (base64url) that can open the descriptor's scopes from here: those
   * whose PRF can, and those remembered for this browser (§13). */
  canOpen: string[];
  /** Passkeys without PRF that open these scopes from a remembered browser; `here` when that
   * is this browser. */
  browsers: BrowserOpener[];
  lines: string[];
  /** After the tap: the KEK packet, or undefined when this passkey returned no PRF result and
   * this browser is not remembered for it. `assertion` is what the tap signed: a remembered
   * browser shows it to the broker to be handed its sealed KEKs. */
  finish(cred: AssertionCredentialLike, assertion?: AssertionJSON): Promise<OpenPacket | undefined>;
}
export interface BrowserOpener {
  credential_id: string;
  key_id: string;
  label: string;
  here: boolean;
}
export interface ReleasedWrap {
  scope: string;
  id: string;
  sealed_kek: string;
}
/** How a tap reaches this profile's browser key and the broker's release endpoint. The app
 * sets it once at start (main.ts); with nothing set, the remembered-browser path is off and
 * everything behaves as before. */
export const browserPath: {
  keys?: BrowserKeys;
  release?: (body: { challenge_id: string; assertion: AssertionJSON; browser_key: string }) => Promise<{ wraps?: unknown }>;
} = {};

/** What every approval card needs: options to pass to navigator.credentials.get, the open
 * (if any) and a signer that sends PRF-derived keys only inside the HPKE packet. */
export interface Tap {
  options: PublicKeyCredentialRequestOptions;
  open?: PreparedOpen;
  lines: string[];
  /** Call straight from the tap: auth.get starts before the first await. */
  sign(auth: Authenticator): Promise<{ assertion: AssertionJSON; open?: OpenPacket }>;
}

export interface ChallengeLike {
  /** Needed for the remembered-browser path: the release names the pending challenge. */
  challenge_id?: string;
  canonical: string;
  public_key: unknown;
  open?: unknown;
}

export interface TapExpectation extends DescriptorExpectation {
  /** The one credential that may answer (raw ID, base64url). */
  selected?: string;
  /** A bound open is acceptable here (default true when the response carries one). */
  allowOpen?: boolean;
  /** An open is required (stage/enrol steps). */
  requireOpen?: boolean;
}

function prfOf(cred: AssertionCredentialLike): { first?: Uint8Array; second?: Uint8Array } {
  let r: unknown;
  try {
    r = cred.getClientExtensionResults?.();
  } catch {
    return {};
  }
  const res = isObject(r) && isObject(r.prf) && isObject(r.prf.results) ? r.prf.results : undefined;
  const view = (x: unknown) => (x instanceof ArrayBuffer ? new Uint8Array(x) : ArrayBuffer.isView(x) ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength) : undefined);
  return { first: view(res?.first), second: view(res?.second) };
}

/** Check a challenge response's WebAuthn options and, when it carries one, its open descriptor. */
export async function prepareTap(r: ChallengeLike, rpId: string, want: TapExpectation = {}): Promise<Tap> {
  const o = unwrapPublicKey(r.public_key);
  const allow = o.allowCredentials;
  if (
    o.rpId !== rpId ||
    o.userVerification !== "required" ||
    !Array.isArray(allow) ||
    !allow.length ||
    allow.some((x) => !isObject(x) || x.type !== "public-key" || typeof x.id !== "string") ||
    (want.selected !== undefined && (allow.length !== 1 || (allow[0] as { id: string }).id !== want.selected))
  )
    fail("Invalid review options");
  const options = decodeRequestOptions(o);
  const sent = r.open;
  if (sent === undefined || sent === null) {
    if (want.requireOpen) fail("The broker sent no open descriptor for this step");
    if (o.extensions !== undefined) fail("Invalid review options");
    if (o.challenge !== encode(await sha256(r.canonical))) fail("The passkey challenge does not match the action shown");
    return { options, lines: [], sign: async (auth) => ({ assertion: encodeAssertion(await auth.get(options)) }) };
  }
  if (want.allowOpen === false) fail("Unexpected open descriptor");
  if (!isObject(sent)) return fail("Invalid open descriptor");
  exactKeys(sent, sent.browsers === undefined ? ["descriptor"] : ["browsers", "descriptor"], "Open");
  const textIn = sent.descriptor as string;
  // This profile's browser key, read before the tap: the passkey prompt must start inside the
  // click, with no storage round trip in between.
  const local: LocalBrowserKey | undefined = await browserPath.keys?.current();
  const d = parseDescriptor(textIn, want);
  const challenge = await openChallenge(r.canonical, textIn);
  if (o.challenge !== encode(challenge)) fail("The passkey challenge does not bind the action and the buckets shown");
  const inst = rawB64(d.installation, 32), epoch = rawB64(d.epoch, 32), attempt = rawB64(d.attempt_id, 32), recipient = rawB64(d.recipient, 65);
  const allowed = new Set((allow as { id: string }[]).map((x) => x.id));
  const browsers: BrowserOpener[] = [];
  if (sent.browsers !== undefined) {
    if (d.object !== "bucket-open" || !Array.isArray(sent.browsers) || sent.browsers.length > 256) fail("Invalid remembered-browser list");
    for (const x of sent.browsers as unknown[]) {
      if (!isObject(x)) return fail("Invalid remembered-browser list");
      exactKeys(x, ["credential_id", "key_id", "label"], "Remembered browser");
      rawB64(x.credential_id, 1, 1023);
      if (typeof x.key_id !== "string" || !/^[0-9a-f]{32}$/.test(x.key_id) || !text(x.label, 256)) fail("Invalid remembered-browser list");
      if (!allowed.has(x.credential_id as string)) fail("A remembered browser for a passkey that may not answer");
      browsers.push({ credential_id: x.credential_id as string, key_id: x.key_id as string, label: x.label as string, here: !!local && local.id === x.key_id });
    }
  }
  const ext = o.extensions;
  // Per credential: the PRF inputs, aligned with the descriptor's scopes.
  const salts = new Map<string, Bytes[]>();
  let migrate: Legacy | undefined;
  if (d.object === "bucket-open") {
    if (ext === undefined) {
      // No passkey can open these scopes: only a tap whose buckets are already open can succeed.
    } else {
      if (!isObject(ext)) return fail("Invalid PRF options");
      exactKeys(ext, ["prf"], "Extensions");
      const prf = ext.prf;
      if (!isObject(prf)) return fail("Invalid PRF options");
      exactKeys(prf, ["evalByCredential"], "PRF options");
      const by = prf.evalByCredential;
      if (!isObject(by)) return fail("Invalid PRF options");
      for (const [id, v] of Object.entries(by)) {
        rawB64(id, 1, 1023);
        if (!allowed.has(id)) fail("PRF inputs for a passkey that may not answer");
        if (!isObject(v)) fail("Invalid PRF inputs");
        const e = v as Record<string, unknown>;
        if (d.rekey_salt) {
          // Rekey: first = the passkey's salt for the scope, second = the descriptor's fresh salt.
          exactKeys(e, ["first", "second"], "PRF inputs");
          if (e.second !== d.rekey_salt) fail("The rekey's second PRF input is not the descriptor's fresh salt");
          salts.set(id, [rawB64(e.first, 32), rawB64(e.second, 32)]);
          continue;
        }
        exactKeys(e, d.scopes.length === 2 ? ["first", "second"] : ["first"], "PRF inputs");
        salts.set(id, d.scopes.map((_, i) => rawB64(i ? e.second : e.first, 32)));
      }
    }
  } else {
    const only = d.credential_id!;
    const list = allow as { id: string }[];
    if (list.length !== 1 || list[0]!.id !== only) fail("This step is for one named passkey");
    if (want.selected !== undefined && want.selected !== only) fail("This step is for another passkey");
    const inputs = d.purpose === "migrate" ? [d.legacy!.prf_salt, d.salts![0]!] : d.salts!;
    const expected = canonicalJSON({ prf: { eval: inputs.length === 2 ? { first: inputs[0], second: inputs[1] } : { first: inputs[0] } } });
    if (!isObject(ext) || canonicalJSON(ext) !== expected) fail("The PRF inputs differ from the descriptor's");
    salts.set(only, inputs.map((s) => rawB64(s, 32)));
    migrate = d.legacy;
  }
  // WebAuthn wants binary PRF inputs; decodeRequestOptions drops extensions.
  if (salts.size) {
    if (d.object === "bucket-open") {
      const by: Record<string, AuthenticationExtensionsPRFValues> = {};
      for (const [id, s] of salts) by[id] = s.length === 2 ? { first: own(s[0]!), second: own(s[1]!) } : { first: own(s[0]!) };
      options.extensions = { prf: { evalByCredential: by } };
    } else {
      const s = [...salts.values()][0]!;
      options.extensions = { prf: { eval: s.length === 2 ? { first: own(s[0]!), second: own(s[1]!) } : { first: own(s[0]!) } } };
    }
  }
  const info = openInfo(inst, d.purpose);
  /** The remembered-browser path (§13): show the broker this tap's assertion, be handed the
   * sealed KEKs of this passkey and this browser key, open them with the browser key. */
  const released = async (rawCred: Bytes, assertion: AssertionJSON | undefined, key: LocalBrowserKey): Promise<Bytes[]> => {
    if (!browserPath.keys || !browserPath.release || !assertion || typeof r.challenge_id !== "string") return fail("This page cannot ask for a remembered browser's keys here");
    const res = await browserPath.release({ challenge_id: r.challenge_id, assertion, browser_key: key.public });
    const wraps = res?.wraps;
    if (!Array.isArray(wraps) || wraps.length !== d.scopes.length) return fail("The broker did not release this browser's keys for every scope");
    const out: Bytes[] = [];
    try {
      for (let i = 0; i < wraps.length; i++) {
        const w = wraps[i] as unknown;
        if (!isObject(w)) return fail("Invalid released key");
        exactKeys(w, ["id", "scope", "sealed_kek"], "Released key");
        if (w.scope !== d.scopes[i]) fail("The released keys are for other scopes");
        if (d.object === "scope-enrol" && w.id !== d.salts![i]) fail("The released key is not the one this test names");
        const id = rawB64(w.id, 32), sealed = rawB64(w.sealed_kek, 113);
        out.push(await browserPath.keys.openKEK(key, browserKekInfo(inst, rpId, rawCred, d.scopes[i]!, id, key.publicKey), sealed));
      }
    } catch (e) {
      for (const k of out) k.fill(0);
      throw e;
    }
    return out;
  };
  let used = false;
  const open: PreparedOpen = {
    descriptor: d,
    text: textIn,
    challenge,
    canOpen: d.object === "bucket-open" ? [...new Set([...salts.keys(), ...browsers.filter((b) => b.here).map((b) => b.credential_id)])] : [...salts.keys()],
    browsers,
    lines: describeOpen(d),
    async finish(cred, assertion) {
      if (used) fail("Ceremony already used");
      used = true;
      const id = encode(cred.rawId);
      const { first, second } = prfOf(cred);
      const wipe = () => {
        first?.fill(0);
        second?.fill(0);
      };
      try {
        if (id !== cred.id) fail("Unexpected credential");
        const mine = salts.get(id);
        const need = migrate || d.rekey_salt ? 2 : d.scopes.length;
        const ok = !!mine && first?.length === 32 && (need === 1 || second?.length === 32);
        const rawCred = new Uint8Array(cred.rawId);
        const fresh = () => crypto.getRandomValues(new Uint8Array(32)) as Bytes;
        const send = async (keks: Bytes[]) => {
          try {
            return { attempt_id: d.attempt_id, ...(await sealKEKs(recipient, info, openAAD(attempt, epoch, challenge, rawCred), keks)) };
          } finally {
            for (const k of keks) k.fill(0);
          }
        };
        if (d.object === "scope-enrol" && d.browser_key) {
          // Remember or test this browser (§13). Its key must be the one the step names.
          if (!local || local.public !== d.browser_key) fail(NOT_REMEMBERED);
          if (d.purpose === "enrol") {
            // No silent downgrade: a passkey that returns a PRF result holds its own secret.
            if (first?.length === 32) fail("This passkey returned a PRF result: it can hold the secret itself, which is stronger. Use Enable instead of remembering this browser.");
            return await send(d.scopes.map(fresh));
          }
          return await send(await released(rawCred, assertion, local!));
        }
        if (!ok) {
          if (d.object === "scope-enrol") throw new NoPrfError("This passkey did not return a PRF result, so it cannot hold a scope key");
          // A passkey without PRF opens from this browser when it is remembered for it. A
          // rekey adds a fresh KEK made here, as PRF's second evaluation does.
          const here = browsers.some((b) => b.credential_id === id && b.here);
          if (!here || !local) return undefined;
          const keks = await released(rawCred, assertion, local);
          if (d.rekey_salt) keks.push(fresh());
          return await send(keks);
        }
        const keks: Bytes[] = [];
        try {
          if (migrate) {
            const p1 = own(first!);
            try {
              keks.push(own(await wrapKeyBytes(p1, rawB64(migrate.installation, 32), rpId, rawCred, migrate.mk_version, mine![0]!)));
            } finally {
              p1.fill(0);
            }
            keks.push(await deriveKEK(second!, inst, rpId, rawCred, d.scopes[0]!, mine![1]!));
          } else {
            const outs = [first!, second!];
            // A rekey derives its second KEK for the same scope, at the fresh salt.
            const scopes = d.rekey_salt ? [d.scopes[0]!, d.scopes[0]!] : d.scopes;
            for (let i = 0; i < scopes.length; i++) keks.push(await deriveKEK(outs[i]!, inst, rpId, rawCred, scopes[i]!, mine![i]!));
          }
          const sealed = await sealKEKs(recipient, info, openAAD(attempt, epoch, challenge, rawCred), keks);
          return { attempt_id: d.attempt_id, ...sealed };
        } finally {
          for (const k of keks) k.fill(0);
        }
      } finally {
        wipe();
      }
    },
  };
  return {
    options,
    open,
    lines: open.lines,
    async sign(auth) {
      const cred = await auth.get(options);
      const assertion = encodeAssertion(cred);
      const packet = await open.finish(cred, assertion);
      return packet ? { assertion, open: packet } : { assertion };
    },
  };
}
