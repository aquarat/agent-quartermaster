// Credential sets ("vault"): the browser half of docs/API.md "Vault: web form, reveal and
// signer sets". No DOM here. Every action builds the complete canonical it expects from what
// the owner chose and refuses a server canonical that differs by one byte. Values and private
// keys leave this module only as HPKE ciphertext; revealed values arrive only as HPKE
// ciphertext for a key generated here for that one reveal.
import { type Api } from "./api";
import { decode, encode } from "./b64url";
import { checkReview, type Review } from "./review";
import { suite, tuple } from "./seal";
import { type SealView } from "./sealPanel";
import { type Authenticator, encodeAssertion } from "./webauthn";

const utf8 = new TextEncoder();

export interface Scheme {
  id: string;
  title: string;
  key: string;
  input: "message" | "sha256" | "sha512";
  signed: string;
  output: string;
  check: string;
}
export interface VaultOrg {
  id: string;
  slug: string;
  title: string;
  allow_reveal: boolean;
}
export interface VaultSet {
  org_id: string;
  org_slug: string;
  org_title: string;
  service_id: string;
  service_slug: string;
  service_title: string;
  set_id: string;
  set_slug: string;
  set_title: string;
  kind: "env-set" | "signer";
  revision: number;
  names: string[];
  allow_reveal: boolean;
  scheme?: string;
  origin?: string;
  created_at?: number;
  signatures: number;
  public_key?: string;
  public_hex?: string;
  public_pem?: string;
  fingerprint?: string;
}
export interface SignItem {
  name: string;
  size: number;
  sha256: string;
  sha512?: string;
  /** Standard base64: only for a scheme that signs the artifact itself. */
  message?: string;
}
export interface SignRequest {
  path: string;
  title: string;
  org: string;
  service: string;
  set: string;
  revision: number;
  service_revision: number;
  policy_revision: number;
  admission_generation: number;
  enrollment: string;
  host: string;
  class: string;
  scheme: string;
  /** Standard base64 of the raw public key. */
  public_key: string;
  default_seconds: number;
  soft_cap_seconds: number;
  id: string;
  grant_id: string;
  address: string;
  reason: string;
  items: SignItem[];
  ttl_seconds: number;
  max_signatures: number;
  deadline: number;
  not_after: number;
  status: string;
  used: number;
}
export interface VaultState {
  unlocked: boolean;
  schemes: Scheme[];
  organisations: VaultOrg[];
  sets: VaultSet[];
  requests: SignRequest[];
}
export interface Entry {
  name: string;
  value: string;
}
export interface Edit {
  operation: "merge" | "import";
  entries: Entry[];
  remove: string[];
}
export interface SignerResult {
  set_id: string;
  path: string;
  scheme: string;
  public_key: string;
  public_hex: string;
  public_pem: string;
  fingerprint: string;
}
interface VaultReview extends Review {
  facts?: Record<string, unknown>;
}

// ---- encodings shared with the broker ----

/** Go's reviewJSON of a map: keys sorted at every level, no insignificant space, nothing
 * HTML-escaped, U+2028/U+2029 escaped. Numbers must be safe integers. */
export function canonicalJSON(v: unknown): string {
  if (v === null || typeof v === "boolean") return String(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw Error("Non-integer in a signed description");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) => canonicalJSON(k) + ":" + canonicalJSON(o[k])).join(",") + "}";
  }
  throw Error("Unsupported value in a signed description");
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b as Uint8Array<ArrayBuffer>));
}
function raw(s: unknown, min: number, max = min): Uint8Array {
  if (typeof s !== "string" || s.length > 2 * max + 4) throw Error("Invalid binary field from the server");
  const b = new Uint8Array(decode(s));
  if (encode(b) !== s || b.length < min || b.length > max) throw Error("Invalid binary field from the server");
  return b;
}
function stdB64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
function fromStdB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** No lone surrogates: the string has exactly one UTF-8 encoding. */
function wellFormed(s: string): boolean {
  try {
    encodeURIComponent(s);
    return true;
  } catch {
    return false;
  }
}

const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const DENIED_PREFIX = ["AQMAS_", "LD_", "DYLD_", "BASH", "ZSH", "SHEL", "PROMPT", "PS4", "GIT_", "SSH_", "GCONV_", "PYTHON", "PERL", "RUBY", "NODE_", "BUN_", "NPM_", "GO", "CARGO_", "RUST", "HIST", "XDG_", "LC_", "SSLKEYLOG", "ENV_", "JAVA_", "JDK_", "KRB5", "BUNDLE_", "VIM", "EDITOR", "TERM", "AWS_CONFIG", "AWS_SHARED"];
const ALLOWED_SUFFIX = ["_TOKEN", "_KEY", "_PASSWORD", "_SECRET", "_URL", "_DSN", "_USER", "_USERNAME", "_ID"];
export const MAX_KEYS = 64;
export const MAX_VALUE_BYTES = 8192;
export const MAX_SET_BYTES = 24 << 10;

/** envset.SafeName: APP_* or a credential-like suffix, never loader, shell or tool settings. */
export function safeName(s: string): boolean {
  if (!NAME_RE.test(s) || DENIED_PREFIX.some((p) => s.startsWith(p))) return false;
  return s.startsWith("APP_") || ALLOWED_SUFFIX.some((x) => s.endsWith(x));
}
/** Why a key name is refused, in the owner's words (null = fine). */
export function nameProblem(s: string): string | null {
  if (safeName(s)) return null;
  if (!NAME_RE.test(s)) return "Use capital letters, digits and underscores, starting with a letter (at most 64).";
  if (DENIED_PREFIX.some((p) => s.startsWith(p))) return "That name would change how a shell, loader or tool behaves; aqmas never delivers it.";
  return "Names start with APP_ or end in _TOKEN, _KEY, _PASSWORD, _SECRET, _URL, _DSN, _USER, _USERNAME or _ID.";
}
/** envset.Validate. Messages name keys, never values. */
export function validateEntries(entries: Entry[]): void {
  if (entries.length > MAX_KEYS) throw Error("too many keys");
  const seen = new Set<string>();
  let size = 0;
  for (const e of entries) {
    if (!safeName(e.name) || seen.has(e.name)) throw Error("unsupported or duplicate environment name");
    const n = utf8.encode(e.value).length;
    if (n > MAX_VALUE_BYTES || e.value.includes("\0") || !wellFormed(e.value)) throw Error(`unsupported value for ${e.name}`);
    size += e.name.length + n;
    seen.add(e.name);
  }
  if (size > MAX_SET_BYTES) throw Error("environment too large");
}

const GO_SPACE = /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/;
const BARE_REFUSED = /[\r\0"'`$\\#]/;

/** envset.ParseFile, rule for rule (docs/API.md "Dotenv import"). Errors name the line. */
export function parseDotenv(text: string): Entry[] {
  if (utf8.encode(text).length > MAX_SET_BYTES + 4096 || !wellFormed(text)) throw Error("invalid dotenv size or encoding");
  let s = text.replaceAll("\r\n", "\n");
  const out: Entry[] = [];
  let line = 1;
  const bad = (n = line) => Error(`unsupported literal assignment on line ${n}`);
  while (s.length > 0) {
    if (s[0] === "\n") {
      s = s.slice(1);
      line++;
      continue;
    }
    let end = s.indexOf("\n");
    if (end < 0) end = s.length;
    if (s[0] === "#") {
      s = s.slice(end);
      continue;
    }
    const first = s.slice(0, end);
    const eq = first.indexOf("=");
    if (eq < 0 || !safeName(first.slice(0, eq))) throw bad();
    const k = first.slice(0, eq);
    const rest = first.slice(eq + 1);
    let v: string;
    if (rest !== "" && (rest[0] === "'" || rest[0] === '"')) {
      const quote = rest[0];
      const body = s.slice(k.length + 2);
      const start = line;
      let i = 0;
      v = "";
      for (;;) {
        if (i >= body.length) throw bad(start);
        let c = body[i]!;
        i++;
        if (c === quote) break;
        if (c === "\n") line++;
        if (c === "\\" && quote === '"') {
          if (i >= body.length) throw bad(start);
          const e = 'nrt\\"'.indexOf(body[i]!);
          if (e < 0) throw bad();
          c = '\n\r\t\\"'[e]!;
          i++;
        }
        v += c;
      }
      const tail = body.slice(i);
      end = tail.indexOf("\n");
      if (end < 0) end = tail.length;
      if (tail.slice(0, end).replace(/^[ \t]+|[ \t]+$/g, "") !== "") throw bad();
      s = tail.slice(end);
    } else {
      if (BARE_REFUSED.test(rest) || GO_SPACE.test(rest)) throw bad();
      v = rest;
      s = s.slice(end);
    }
    out.push({ name: k, value: v });
  }
  validateEntries(out);
  return out;
}

function checkEdit(e: Edit): string[] {
  validateEntries(e.entries);
  const removed = [...e.remove].sort();
  if (e.operation === "import" ? removed.length > 0 : e.operation !== "merge" || e.entries.length + removed.length === 0 || removed.length > MAX_KEYS) throw Error("invalid edit");
  removed.forEach((n, i) => {
    if (!NAME_RE.test(n) || (i > 0 && removed[i - 1] === n) || e.entries.some((x) => x.name === n)) throw Error("invalid edit");
  });
  return removed;
}

/** envset.Edit.Commit: SHA-256 over uint32-length-prefixed parts. Binds the salt, the set's
 * immutable IDs, the base revision and every (operation, name, exact value) group. */
export async function editCommitment(edit: Edit & { salt: Uint8Array }, b: { org: string; service: string; set: string; revision: number }): Promise<string> {
  const removed = checkEdit(edit);
  if (edit.salt.length !== 32 || !Number.isSafeInteger(b.revision) || b.revision < 0) throw Error("invalid edit");
  const parts: Uint8Array[] = [];
  const owned: Uint8Array[] = []; // encoded copies (they include the values): zeroed below
  const add = (p: Uint8Array | string) => {
    if (typeof p === "string") owned.push((p = utf8.encode(p)));
    parts.push(p);
  };
  add("aqmas-env-edit-v1");
  add(edit.salt);
  add(b.org);
  add(b.service);
  add(b.set);
  const rev = new Uint8Array(8);
  new DataView(rev.buffer).setBigUint64(0, BigInt(b.revision));
  add(rev);
  add(edit.operation);
  for (const x of [...edit.entries].sort((p, q) => (p.name < q.name ? -1 : p.name > q.name ? 1 : 0))) {
    add(edit.operation);
    add(x.name);
    add(x.value);
  }
  for (const n of removed) {
    add("remove");
    add(n);
    add(new Uint8Array(0));
  }
  const buf = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(buf.buffer);
  let i = 0;
  for (const p of parts) {
    view.setUint32(i, p.length);
    buf.set(p, i + 4);
    i += 4 + p.length;
  }
  try {
    return hex(await sha256(buf));
  } finally {
    buf.fill(0);
    for (const p of owned) p.fill(0);
  }
}

/** envset.Edit.Changes: "NAME:add|replace|remove", sorted, comma-joined, from key names only. */
export function editChanges(edit: Edit, oldNames: string[]): string {
  const present = new Set<string>();
  const ops: string[] = [];
  for (const x of edit.entries) {
    present.add(x.name);
    ops.push(x.name + (oldNames.includes(x.name) ? ":replace" : ":add"));
  }
  for (const n of edit.remove) {
    if (edit.operation !== "merge" || !oldNames.includes(n) || present.has(n)) throw Error("cannot remove missing key");
    present.add(n);
    ops.push(n + ":remove");
  }
  if (edit.operation === "import") for (const n of oldNames) if (!present.has(n)) ops.push(n + ":remove");
  return ops.sort().join(",");
}

export function newSetId(): string {
  return hex(crypto.getRandomValues(new Uint8Array(16)));
}

/** SubjectPublicKeyInfo PEM for a raw Ed25519 (32 bytes) or P-256 (65 bytes) public key. */
export function publicPem(rawKey: Uint8Array): string {
  const prefix = rawKey.length === 32 ? "302a300506032b6570032100" : rawKey.length === 65 && rawKey[0] === 4 ? "3059301306072a8648ce3d020106082a8648ce3d030107034200" : "";
  if (!prefix) throw Error("Invalid public key");
  const der = new Uint8Array(prefix.length / 2 + rawKey.length);
  for (let i = 0; i < prefix.length / 2; i++) der[i] = parseInt(prefix.slice(2 * i, 2 * i + 2), 16);
  der.set(rawKey, prefix.length / 2);
  return "-----BEGIN PUBLIC KEY-----\n" + stdB64(der).replace(/(.{64})(?=.)/g, "$1\n") + "\n-----END PUBLIC KEY-----\n";
}

// ---- ceremonies ----

function targetFields(s: VaultSet) {
  return { org_id: s.org_id, org_slug: s.org_slug, org_title: s.org_title, service_id: s.service_id, service_slug: s.service_slug, service_title: s.service_title, set_id: s.set_id, set_slug: s.set_slug, set_title: s.set_title, kind: s.kind, revision: s.revision };
}
const pathOf = (s: { org_slug: string; service_slug: string; set_slug: string }) => `${s.org_slug}/${s.service_slug}/${s.set_slug}`;

function sealBinding(v: SealView) {
  return { install: raw(v.installation, 32), epoch: raw(v.epoch, 32) };
}
async function review(api: Api, v: SealView, action: string, id: string, body: Record<string, unknown>, metadata: (facts: Record<string, unknown>) => Record<string, unknown> | Promise<Record<string, unknown>>, rp: string) {
  const b = await api.vaultPost!<VaultReview>("challenge", { action, id, ...body });
  const facts = b.facts && typeof b.facts === "object" ? b.facts : {};
  const meta = canonicalJSON(await metadata(facts));
  const opts = await checkReview(b, { v: 3, object: "vault", action, id, installation: v.installation, epoch: v.epoch, metadata: meta }, rp);
  let used = false;
  return {
    canonical: b.canonical,
    async finish<T>(auth: Authenticator): Promise<T> {
      if (used) throw Error("Ceremony already used");
      used = true;
      return api.vaultPost!<T>("finish", { challenge_id: b.challenge_id, assertion: encodeAssertion(await auth.get(opts)) });
    },
  };
}

/** Seal one upload to a fresh broker recipient. The plaintext buffer is zeroed. */
async function upload(api: Api, v: SealView, purpose: "edit" | "signer-import", setId: string, plain: Uint8Array) {
  try {
    const { install, epoch } = sealBinding(v);
    const a = await api.vaultPost!<{ attempt_id: string; recipient: string }>("attempt", {});
    const attempt = raw(a.attempt_id, 32);
    const pk = raw(a.recipient, 65);
    if (pk[0] !== 4) throw Error("Invalid upload recipient");
    const recipientPublicKey = await suite.kem.deserializePublicKey(pk.buffer as ArrayBuffer);
    const sender = await suite.createSenderContext({ recipientPublicKey, info: tuple("hpke-vault", install, utf8.encode(purpose)).buffer as ArrayBuffer });
    const ct = await sender.seal(plain.buffer as ArrayBuffer, tuple("hpke-vault-aad", attempt, epoch, utf8.encode(setId)).buffer as ArrayBuffer);
    return { attempt_id: a.attempt_id, enc: encode(sender.enc), ciphertext: encode(ct) };
  } finally {
    plain.fill(0);
  }
}

/** The write-only form: seal the edit, then one tap over its commitment and key changes. */
export async function vaultCommit(api: Api, v: SealView, set: VaultSet, edit: Edit, rp: string) {
  if (set.kind !== "env-set") throw Error("Not an env set");
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const changes = editChanges(edit, set.names);
  const commitment = await editCommitment({ ...edit, salt }, { org: set.org_id, service: set.service_id, set: set.set_id, revision: set.revision });
  const body: Record<string, unknown> = { operation: edit.operation, salt: stdB64(salt), entries: edit.entries.map((e) => ({ name: e.name, value: e.value })) };
  if (edit.remove.length) body.remove = edit.remove;
  const sent = await upload(api, v, "edit", set.set_id, utf8.encode(JSON.stringify(body)));
  const r = await review(api, v, "commit", set.set_id, { ...sent, commitment }, () => ({ ...targetFields(set), attempt_id: sent.attempt_id, operation: edit.operation, changes, commitment, result_revision: set.revision + 1 }), rp);
  return {
    detail: `Save ${pathOf(set)}: revision ${set.revision} → ${set.revision + 1} (${edit.operation}). Changes: ${changes}`,
    changes,
    commitment,
    tap: (auth: Authenticator) => r.finish<unknown>(auth),
  };
}

/** Reveal: a key pair made here for this one reveal; the broker re-encrypts to it after a
 * fresh tap; only this page can open the answer. */
export async function vaultReveal(api: Api, v: SealView, set: VaultSet, names: string[], rp: string) {
  if (set.kind !== "env-set") throw Error("A signer key is never revealed");
  const sorted = [...new Set(names)].sort();
  if (!sorted.length || sorted.length !== names.length || sorted.some((n) => !set.names.includes(n))) throw Error("Choose keys of this set, each once");
  const { install, epoch } = sealBinding(v);
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
  const recipient = encode(await crypto.subtle.exportKey("raw", pair.publicKey));
  const r = await review(api, v, "reveal", set.set_id, { names: sorted, recipient }, () => ({ ...targetFields(set), names: sorted, recipient }), rp);
  return {
    detail: `Reveal ${sorted.join(", ")} of ${pathOf(set)} revision ${set.revision} to this page`,
    async tap(auth: Authenticator): Promise<Entry[]> {
      const out = await r.finish<{ enc: string; ciphertext: string }>(auth);
      return openReveal(pair, install, epoch, r.canonical, set.set_id, raw(out.enc, 65), raw(out.ciphertext, 17, 64 << 10), sorted);
    },
  };
}

/** Opens a reveal packet and checks it holds exactly the names asked for. */
export async function openReveal(recipientKey: CryptoKey | CryptoKeyPair, install: Uint8Array, epoch: Uint8Array, canonical: string, setId: string, enc: Uint8Array, ciphertext: Uint8Array, names: string[]): Promise<Entry[]> {
  const digest = await sha256(utf8.encode(canonical));
  const ctx = await suite.createRecipientContext({ recipientKey, enc: enc.buffer as ArrayBuffer, info: tuple("hpke-vault", install, utf8.encode("reveal")).buffer as ArrayBuffer });
  const plain = new Uint8Array(await ctx.open(ciphertext.buffer as ArrayBuffer, tuple("hpke-vault-aad", digest, epoch, utf8.encode(setId)).buffer as ArrayBuffer));
  try {
    const p = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain)) as { entries?: unknown };
    const entries = Array.isArray(p?.entries) ? (p.entries as Entry[]) : [];
    if (entries.length !== names.length || entries.some((e, i) => typeof e?.name !== "string" || typeof e.value !== "string" || e.name !== names[i])) throw Error("The revealed keys differ from the ones you asked for");
    return entries.map((e) => ({ name: e.name, value: e.value }));
  } finally {
    plain.fill(0);
  }
}

export async function vaultPolicy(api: Api, v: SealView, org: VaultOrg, allowReveal: boolean, rp: string) {
  if (org.allow_reveal === allowReveal) throw Error("The policy already has that value");
  const r = await review(api, v, "policy", org.id, { allow_reveal: allowReveal }, () => ({ org_id: org.id, org_slug: org.slug, org_title: org.title, old_allow_reveal: org.allow_reveal, allow_reveal: allowReveal }), rp);
  return { detail: `${allowReveal ? "Allow" : "Stop allowing"} value reveal for ${org.slug}`, tap: (auth: Authenticator) => r.finish<unknown>(auth) };
}

export interface SignerParent {
  org_id: string;
  org_slug: string;
  org_title: string;
  service_id: string;
  service_slug: string;
  service_title: string;
}

/** A signer set: generated inside aqmas, or an existing private key sealed here once. The
 * public key comes from the broker; the canonical must carry exactly it. */
export async function vaultSignerCreate(api: Api, v: SealView, parent: SignerParent, set: { id: string; slug: string; title: string }, scheme: string, source: "generate" | "import", privateKey: string | undefined, rp: string) {
  if (!/^[0-9a-f]{32}$/.test(set.id)) throw Error("Invalid set ID");
  const body: Record<string, unknown> = { service_id: parent.service_id, set_slug: set.slug, set_title: set.title, scheme, source };
  let attempt: string | undefined;
  if (source === "import") {
    if (!privateKey?.trim()) throw Error("Paste the private key to import");
    const sent = await upload(api, v, "signer-import", set.id, utf8.encode(JSON.stringify({ private_key: privateKey })));
    attempt = sent.attempt_id;
    Object.assign(body, sent);
  } else if (privateKey !== undefined) throw Error("A generated key takes no input");
  let key: Uint8Array = new Uint8Array(0);
  let fingerprint = "";
  const r = await review(api, v, "signer-create", set.id, body, async (facts) => {
    if (attempt !== undefined && facts.attempt_id !== attempt) throw Error("The broker answered for another upload");
    raw(facts.attempt_id, 32);
    key = raw(facts.public_key, 32, 65);
    if (key.length !== 32 && !(key.length === 65 && key[0] === 4)) throw Error("Invalid public key from the server");
    fingerprint = hex(await sha256(key));
    if (facts.fingerprint !== fingerprint) throw Error("The fingerprint does not match the public key");
    return { org_id: parent.org_id, org_slug: parent.org_slug, org_title: parent.org_title, service_id: parent.service_id, service_slug: parent.service_slug, service_title: parent.service_title, set_id: set.id, set_slug: set.slug, set_title: set.title, kind: "signer", revision: 0, scheme, source, attempt_id: facts.attempt_id, public_key: facts.public_key, fingerprint, result_revision: 0 };
  }, rp);
  const publicKey = encode(key);
  return {
    detail: `Create signer ${parent.org_slug}/${parent.service_slug}/${set.slug} (${scheme}, ${source === "generate" ? "generated in aqmas" : "imported"}). Public key ${hex(key)}`,
    publicKey,
    publicHex: hex(key),
    publicPem: publicPem(key),
    fingerprint,
    async tap(auth: Authenticator): Promise<SignerResult> {
      const out = await r.finish<SignerResult>(auth);
      if (out.set_id !== set.id || out.public_key !== publicKey || out.fingerprint !== fingerprint || out.scheme !== scheme) throw Error("The created signer differs from the one you approved");
      return { ...out, public_hex: hex(key), public_pem: publicPem(key) };
    },
  };
}

/** Bytes of a pure-scheme artifact, after checking they are what the card's SHA-256 names. */
export async function itemMessage(it: SignItem): Promise<Uint8Array | null> {
  if (it.message === undefined) return null;
  const m = fromStdB64(it.message);
  if (hex(await sha256(m)) !== it.sha256 || it.size !== m.length) throw Error("An artifact does not match its SHA-256");
  return m;
}
export function hexPreview(m: Uint8Array, max = 256): string {
  const rows: string[] = [];
  for (let i = 0; i < Math.min(m.length, max); i += 16) rows.push(hex(m.subarray(i, Math.min(i + 16, m.length, max))).replace(/(..)(?=.)/g, "$1 "));
  return rows.join("\n") + (m.length > max ? `\n… ${m.length - max} more bytes` : "");
}

/** Approve, deny or revoke a signing request. The expected canonical lists every artifact
 * (name, size, SHA-256, and SHA-512 where that is what gets signed) and the granted limits. */
export async function vaultSignDecision(api: Api, v: SealView, set: VaultSet, req: SignRequest, action: "sign-approve" | "sign-deny" | "sign-revoke", ttl: number, max: number, rp: string) {
  if (set.kind !== "signer" || set.set_id !== req.set || set.scheme !== req.scheme) throw Error("This request is for another signer");
  const fingerprint = hex(await sha256(fromStdB64(req.public_key)));
  if (set.fingerprint !== fingerprint) throw Error("The request names another public key");
  if (action !== "sign-approve" && (ttl !== 0 || max !== 0)) throw Error("Only an approval has a duration");
  for (const it of req.items) await itemMessage(it);
  const items = req.items.map((it) => (it.sha512 ? { name: it.name, size: it.size, sha256: it.sha256, sha512: it.sha512 } : { name: it.name, size: it.size, sha256: it.sha256 }));
  const body = action === "sign-approve" ? { ttl_seconds: ttl, max_signatures: max } : {};
  const r = await review(api, v, action, req.id, body, () => ({
    ...targetFields(set), request_id: req.id, host: req.host, enrollment: req.enrollment, address: req.address, scheme: req.scheme, fingerprint, items,
    requested_ttl_seconds: req.ttl_seconds, requested_max_signatures: req.max_signatures, ttl_seconds: ttl, max_signatures: max,
    admission_generation: req.admission_generation, policy_revision: req.policy_revision, service_revision: req.service_revision, soft_cap_seconds: req.soft_cap_seconds, beyond_soft_cap: ttl > req.soft_cap_seconds,
  }), rp);
  const what = action === "sign-approve" ? (ttl === 0 ? `sign exactly ${items.length} artifact(s), once` : `up to ${max} signatures over anything ${req.host} submits for ${ttl} seconds${ttl > req.soft_cap_seconds ? " — BEYOND SOFT CAP" : ""}`) : action === "sign-deny" ? "deny" : "revoke";
  return {
    detail: `${pathOf(set)} (${req.scheme}) for ${req.host}, ${req.address}: ${what}\n` + items.map((it) => `${it.name} · ${it.size < 0 ? "size not given" : it.size + " bytes"} · sha256 ${it.sha256}`).join("\n"),
    tap: (auth: Authenticator) => r.finish<unknown>(auth),
  };
}
