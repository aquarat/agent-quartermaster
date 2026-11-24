// Settings → Setup (docs/SETUP.md), DOM-free: the wire types of GET /api/ui/setup, the task
// parameter encoding the runner accepts, sealing of pasted secrets, the recovery key made in
// the browser, and the signed "run this task" flow.
//
// A setup approval is one passkey assertion over
//   {"action":"run","id":<task>,"issued_at":…,"nonce":…,"object":"setup","params":<text>,"secrets_sha256":<hex or "">,"v":1}
// The page derives <text> and the packet hash itself and refuses to sign anything else.
// Secrets only ever leave this module as HPKE ciphertext for the root runner.

import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import type { Api } from "./api";
import { decode, encode } from "./b64url";
import { challengeCommitsTo, mismatches, parseCanonical } from "./canonical";
import { CHALLENGE_LIFETIME_MS, FlowError } from "./flows";
import { decodeRequestOptions, encodeAssertion, unwrapPublicKey, type Authenticator } from "./webauthn";
import { canonicalJSON, prepareTap } from "./buckets";
import type { SealView, StageChoice, StageView } from "./sealPanel";

// ---- wire types (internal/server/setup.go, internal/maint/status.go) ----

export type SetupState = "available" | "blocked" | "idle" | "running" | "waiting" | "done" | "failed";

/** One run of a task (maint.TaskStatus). */
export interface SetupRun {
  task?: string;
  state: string; // running | waiting | done | failed
  step: string;
  waiting_for?: string;
  deadline?: string;
  started_at: string;
  finished_at?: string;
  message?: string;
  log: string[] | null;
  result?: Record<string, string> | null;
}

export interface SetupTask {
  id: string;
  title: string;
  summary: string;
  steps: string[] | null;
  reversible: string;
  secrets?: string[];
  state: SetupState | string;
  blocked_by?: string;
  rerunnable?: boolean;
  last?: SetupRun | null;
  /** Where the page shows the task: "" / absent = the Setup queue; "bastion" and "routine"
   * = Settings → Bastion access (maint.Spec.Group). */
  group?: string;
  /** Shown in red above the approve button (a restart closes every bucket…). */
  warning?: string;
}

export interface SetupPasskey {
  /** Passkey id as elsewhere in the UI. */
  id: string;
  /** Credential ID, base64url: what a pin names. */
  credential: string;
  key_sha256: string;
  name: string;
  pinned: boolean;
  current: boolean;
}

/** GET /api/ui/setup. */
export interface SetupView {
  /** "seal-setup": a seal import or a bucket migration is staged ("bucket-migrate" accepted too). */
  mode: "serve" | "cutover" | "seal-setup" | "bucket-migrate";
  runner_installed: boolean;
  runner_version?: string;
  /** HPKE public key (base64url, P-256 uncompressed) pasted secrets are sealed to. */
  secrets_key?: string;
  /** Public half of the read-only deploy key (only an SSH repository uses it). */
  deploy_key?: string;
  passkeys: SetupPasskey[] | null;
  current?: SetupRun | null;
  refused?: { at: string; reason: string } | null;
  tasks: SetupTask[] | null;
  update_sources: UpdateSources | null;
}

/** Where releases come from. The three addresses are fixed at the machine (its configuration
 * or `maint-init`); "Enable self-update" signs exactly these and the runner accepts no others. */
export interface UpdateSources {
  /** Git remote: https://… (anonymous, a public repository) or ssh://… (deploy key + host keys). */
  repo: string;
  github_api: string;
  /** "" = no second source: GitHub and the machine's own rebuild are compared. */
  second_api: string;
  origin: "pinned" | "config" | "default";
  /** The published sources by name: "GitHub", "second source (HOST)". */
  compared: string[] | null;
  /** The same for the configuration the broker runs with now; empty while self-update is off. */
  active: string[] | null;
  note?: string;
}

export interface HostKeys {
  host: string;
  keys: { line: string; fingerprint: string }[];
}

const utf8 = new TextEncoder();

// ---- bech32 (BIP-173) and the age X25519 key pair ----

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i]!;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const codes = [...hrp].map((c) => c.charCodeAt(0));
  return [...codes.map((c) => c >>> 5), 0, ...codes.map((c) => c & 31)];
}

/** Lower-case bech32 of `data` under `hrp` (no length limit, as age uses it). */
function bech32(hrp: string, data: Uint8Array): string {
  const words: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const b of data) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >>> bits) & 31);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);
  const mod = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  for (let i = 0; i < 6; i++) words.push((mod >>> (5 * (5 - i))) & 31);
  return hrp + "1" + words.map((w) => CHARSET[w]).join("");
}

/** The pattern the runner accepts for a recipient (internal/maint/spec.go). */
const RECIPIENT_RE = /^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$/;

/** Why `s` is not a native age X25519 public key, or null when it is one (checksum included). */
export function ageRecipientProblem(s: string): string | null {
  if (/^AGE-SECRET-KEY-1/i.test(s)) return "That is the secret half. Only the public key (age1…) goes here.";
  if (!RECIPIENT_RE.test(s)) return "A recovery public key looks like age1… (62 characters, lower case).";
  const words = [...s.slice(4)].map((c) => CHARSET.indexOf(c));
  if (polymod([...hrpExpand("age"), ...words]) !== 1) return "That public key has a typing error (its checksum does not match).";
  return null;
}

/** A native age X25519 identity made with WebCrypto. Nothing is stored or sent. */
export async function generateAgeIdentity(): Promise<{ identity: string; recipient: string }> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("This page needs HTTPS (no Web Crypto) to make a key.");
  let pair: CryptoKeyPair;
  try {
    pair = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  } catch {
    throw new Error("This browser cannot make X25519 keys. Make one with age-keygen and paste its public key instead.");
  }
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  const pub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  // RFC 8410: the PKCS#8 of an X25519 key ends with the 32-byte private scalar.
  if (pkcs8.length !== 48 || pub.length !== 32) throw new Error("Unexpected X25519 key encoding.");
  const scalar = pkcs8.slice(16);
  try {
    return { identity: bech32("age-secret-key-", scalar).toUpperCase(), recipient: bech32("age", pub) };
  } finally {
    scalar.fill(0);
    pkcs8.fill(0);
  }
}

// ---- sealed packets (internal/maint/secrets.go) ----

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

/** HPKE info for a task's secrets packet. */
export function secretsInfo(task: string): Uint8Array {
  return utf8.encode("aqmas-setup-secrets-v1\0" + task);
}

/** HPKE info for the recovery-drill packet of one staged installation. */
export function drillInfo(installation: string): Uint8Array {
  const id = new Uint8Array(decode(installation));
  if (id.length !== 32 || encode(id) !== installation) throw new Error("Invalid installation ID");
  const prefix = utf8.encode("aqmas-seal-drill-v1\0");
  const out = new Uint8Array(prefix.length + id.length);
  out.set(prefix);
  out.set(id, prefix.length);
  return out;
}

const buf = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

/** base64url(enc || ciphertext): HPKE base mode, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
 * AES-128-GCM, empty AAD, one message. */
export async function sealPacket(publicKeyB64url: string, info: Uint8Array, plaintext: Uint8Array): Promise<string> {
  const pk = new Uint8Array(decode(publicKeyB64url));
  if (pk.length !== 65 || pk[0] !== 4) throw new Error("Invalid sealing key");
  const recipientPublicKey = await suite.kem.deserializePublicKey(buf(pk));
  const sender = await suite.createSenderContext({ recipientPublicKey, info: buf(info) });
  const ct = new Uint8Array(await sender.seal(buf(plaintext)));
  const enc = new Uint8Array(sender.enc);
  const out = new Uint8Array(enc.length + ct.length);
  out.set(enc);
  out.set(ct, enc.length);
  return encode(out);
}

/** What the canonical binds for a packet: lower-case hex SHA-256 of its raw bytes. */
export async function packetHash(packet: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", decode(packet)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * The OpenSSH fingerprint ("SHA256:…") of a known_hosts line, computed here from the key
 * itself. The page never shows a fingerprint somebody else calculated for the line it signs.
 */
export async function hostKeyFingerprint(line: string): Promise<string> {
  const blob = line.trim().split(" ")[2] ?? "";
  if (!/^[A-Za-z0-9+/]{40,1000}={0,2}$/.test(blob)) throw new Error("not a host key line");
  const raw = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  return "SHA256:" + btoa(String.fromCharCode(...digest)).replace(/=+$/, "");
}

// ---- task parameters (internal/maint/spec.go) ----

/** A JSON string as Go's encoder writes it with SetEscapeHTML(false). */
function goString(s: string): string {
  return JSON.stringify(s).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

class Fields {
  private seen = new Set<string>();
  constructor(
    private task: string,
    private o: Record<string, unknown>,
  ) {
    if (o === null || typeof o !== "object" || Array.isArray(o)) throw new Error(`${task}: parameters must be an object`);
  }
  private get(k: string): unknown {
    this.seen.add(k);
    return this.o[k];
  }
  str(k: string, o: Record<string, unknown> = this.o): string {
    const v = o === this.o ? this.get(k) : o[k];
    if (typeof v !== "string") throw new Error(`${this.task}: ${k} must be a string`);
    return goString(v);
  }
  bool(k: string): string {
    const v = this.get(k);
    if (typeof v !== "boolean") throw new Error(`${this.task}: ${k} must be true or false`);
    return String(v);
  }
  int(k: string, min: number, max: number): string {
    const v = this.get(k);
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) throw new Error(`${this.task}: ${k} must be a whole number from ${min} to ${max}`);
    return String(v);
  }
  list(k: string): unknown[] {
    const v = this.get(k);
    if (!Array.isArray(v)) throw new Error(`${this.task}: ${k} must be a list`);
    return v;
  }
  done(): void {
    const extra = Object.keys(this.o).filter((k) => !this.seen.has(k));
    if (extra.length) throw new Error(`${this.task}: unknown parameter ${extra.join(", ")}`);
  }
}

/** The one accepted encoding of a task's parameters: exactly Go's json.Marshal of the typed
 * struct (fixed key order, no whitespace, no HTML escaping). Throws on anything outside the
 * task's schema. */
export function canonicalParams(task: string, params: Record<string, unknown>): string {
  const f = new Fields(task, params);
  let out: string;
  switch (task) {
    case "cutover":
      out = "{}";
      break;
    case "seal":
      out = `{"recipient":${f.str("recipient")},"purge_backups":${f.bool("purge_backups")},"lock_alert":${f.bool("lock_alert")}}`;
      break;
    case "buckets":
      out = `{"purge_backups":${f.bool("purge_backups")}}`;
      break;
    case "enable-updates": {
      const hosts = f.list("known_hosts").map((line) => {
        if (typeof line !== "string") throw new Error("enable-updates: known_hosts must be strings");
        return line;
      });
      // The broker sorts the lines before signing (bytewise; they are ASCII).
      const sorted = [...hosts].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      out =
        `{"repo":${f.str("repo")},"github_api":${f.str("github_api")},"second_api":${f.str("second_api")},` +
        `"known_hosts":[${sorted.map(goString).join(",")}],"github_token":${f.bool("github_token")},"second_token":${f.bool("second_token")}}`;
      break;
    }
    case "sync-passkeys": {
      const pins = f.list("pins").map((p) => {
        if (p === null || typeof p !== "object" || Array.isArray(p)) throw new Error("sync-passkeys: a pin must be an object");
        const pin = p as Record<string, unknown>;
        const extra = Object.keys(pin).filter((k) => k !== "id" && k !== "key_sha256");
        if (extra.length) throw new Error(`sync-passkeys: unknown pin field ${extra.join(", ")}`);
        return `{"id":${f.str("id", pin)},"key_sha256":${f.str("key_sha256", pin)}}`;
      });
      out = `{"pins":[${pins.join(",")}]}`;
      break;
    }
    // Access to the bastion itself and routine maintenance (docs/BASTION-ACCESS.md §5).
    case "bastion-access":
      out = `{"name":${f.str("name")},"address":${f.str("address")},"port":${f.int("port", 1, 65535)},"admin_user":${f.str("admin_user")},"ssh_ca":${f.str("ssh_ca")}}`;
      break;
    case "bastion-allow": {
      const hosts = f.list("hosts").map((x) => {
        if (x === null || typeof x !== "object" || Array.isArray(x)) throw new Error("bastion-allow: a host must be an object");
        const host = x as Record<string, unknown>;
        const extra = Object.keys(host).filter((k) => k !== "id" && k !== "name" && k !== "address");
        if (extra.length) throw new Error(`bastion-allow: unknown host field ${extra.join(", ")}`);
        for (const k of ["id", "name", "address"]) if (typeof host[k] !== "string") throw new Error(`bastion-allow: ${k} must be a string`);
        return host as { id: string; name: string; address: string };
      });
      // The complete list, sorted by enrollment id (ASCII), without duplicates.
      hosts.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      if (hosts.some((x, i) => i > 0 && hosts[i - 1]!.id === x.id)) throw new Error("bastion-allow: a host is listed twice");
      out = `{"hosts":[${hosts.map((x) => `{"id":${goString(x.id)},"name":${goString(x.name)},"address":${goString(x.address)}}`).join(",")}]}`;
      break;
    }
    case "os-update":
      out = `{"kernel":${f.bool("kernel")}}`;
      break;
    case "journal-vacuum":
      out = `{"keep_days":${f.int("keep_days", 1, 365)}}`;
      break;
    case "bastion-access-remove":
    case "reboot":
    case "restart-cloudflared":
    case "restart-broker":
    case "disk-usage":
      out = "{}";
      break;
    default:
      throw new Error(`unknown setup task ${JSON.stringify(task)}`);
  }
  f.done();
  return out;
}

/** The parameters of a queued maintenance request, from its canonical text: accepted only
 * when it is exactly this page's own encoding of the task's schema (so what the card says is
 * what an approval signs). Throws otherwise. */
export function queuedParams(task: string, text: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    v = null;
  }
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("the task parameters are not a JSON object");
  if (canonicalParams(task, v as Record<string, unknown>) !== text) throw new Error("the task parameters are not in their canonical form");
  return v as Record<string, unknown>;
}

/** Plain words for the parameters of a bastion or routine task (one line each). */
export function paramLines(task: string, p: Record<string, unknown>): string[] {
  switch (task) {
    case "bastion-access":
      return [`Name agents use: ${String(p["name"])}`, `Address and port: ${String(p["address"])}, ${String(p["port"])}`, `Admin account (root level): ${String(p["admin_user"])}`, `SSH user CA: ${String(p["ssh_ca"])}`];
    case "bastion-allow": {
      const hosts = (p["hosts"] as Array<{ id: string; name: string; address: string }>) ?? [];
      return hosts.length ? hosts.map((x) => `${x.name} from ${x.address} (enrollment ${x.id})`) : ["Nobody: no host may ask for root."];
    }
    case "os-update":
      return [p["kernel"] === true ? "Including the kernel and boot chain." : "The kernel and boot chain are left alone."];
    case "journal-vacuum":
      return [`Keep the last ${String(p["keep_days"])} day${p["keep_days"] === 1 ? "" : "s"} of the journal; older entries are deleted.`];
    default:
      return [];
  }
}

/** The secrets a task with these parameters must carry, sorted (maint.SecretNames). */
export function secretNames(task: string, params: Record<string, unknown>): string[] {
  if (task === "seal") return params["lock_alert"] === true ? ["ntfy_token", "ntfy_topic_url"] : [];
  if (task === "enable-updates") return [...(params["github_token"] === true ? ["github_token"] : []), ...(params["second_token"] === true ? ["second_token"] : [])];
  return [];
}

// ---- the signed run ----

export interface PreparedSetup {
  task: string;
  challengeId: string;
  /** Exactly what the passkey signs. */
  canonicalText: string;
  /** The task parameters inside it, as this page derived them. */
  params: string;
  secretsHash: string;
  /** Sealed secrets ("" when the task takes none). Ciphertext only. */
  packet: string;
  options: PublicKeyCredentialRequestOptions;
  validUntil: number;
}

const ISSUED_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;

/** Seal the secrets, ask for a challenge and verify that it commits to exactly this task,
 * these parameters and this packet. Nothing is signed here. `rpId` defaults to the page's host. */
export async function prepareSetupTask(
  api: Api,
  view: Pick<SetupView, "secrets_key">,
  task: string,
  params: Record<string, unknown>,
  secrets?: Record<string, string>,
  rpId: string | undefined = (globalThis as { location?: { hostname?: string } }).location?.hostname,
  now = Date.now(),
): Promise<PreparedSetup> {
  let want: string;
  try {
    want = canonicalParams(task, params);
  } catch (e) {
    throw new FlowError((e as Error).message);
  }
  const names = Object.keys(secrets ?? {}).sort();
  if (JSON.stringify(names) !== JSON.stringify(secretNames(task, params))) {
    throw new FlowError("The secrets entered do not match the chosen options.");
  }
  let packet = "";
  let hash = "";
  if (names.length > 0) {
    if (!view.secrets_key) throw new FlowError("The maintenance runner has published no key to seal secrets to. Is it installed?");
    const sorted: Record<string, string> = {};
    for (const k of names) {
      const v = secrets![k];
      if (typeof v !== "string" || v === "") throw new FlowError(`The secret ${k} is empty.`);
      sorted[k] = v;
    }
    const plaintext = utf8.encode(JSON.stringify(sorted));
    try {
      packet = await sealPacket(view.secrets_key, secretsInfo(task), plaintext);
    } catch (e) {
      throw new FlowError(`Could not seal the secrets: ${(e as Error).message}.`);
    } finally {
      plaintext.fill(0);
    }
    hash = await packetHash(packet);
  }

  const r = await api.setupPost!<{ challenge_id?: unknown; canonical?: unknown; public_key?: unknown }>(`/${encodeURIComponent(task)}/challenge`, {
    params: JSON.parse(want),
    secrets_sha256: hash,
  });
  if (!r || typeof r.challenge_id !== "string" || !r.challenge_id) throw new FlowError("The server sent no challenge id.");
  if (typeof r.canonical !== "string") throw new FlowError("The server sent no action text to confirm.");

  let c;
  try {
    c = parseCanonical(r.canonical);
  } catch (e) {
    throw new FlowError(`Not signing: ${(e as Error).message}.`);
  }
  const problems = mismatches(c, { action: "run", object: "setup", id: task, params: want, secrets_sha256: hash });
  if (c.v !== 1) problems.push(`v: expected 1, server sent ${JSON.stringify(c.v)}`);
  let nonceOk = false;
  try {
    nonceOk = typeof c.nonce === "string" && decode(c.nonce).byteLength === 32 && encode(decode(c.nonce)) === c.nonce;
  } catch {
    nonceOk = false;
  }
  if (!nonceOk) problems.push("nonce is not 32 random bytes");
  if (typeof c.issued_at !== "string" || !ISSUED_RE.test(c.issued_at)) problems.push("issued_at is not a UTC time");
  if (problems.length > 0) throw new FlowError(`Not signing: the server's action differs from what you chose (${problems.join("; ")}).`);

  let pk: Record<string, unknown>;
  try {
    pk = unwrapPublicKey(r.public_key);
  } catch (e) {
    throw new FlowError(`Not signing: ${(e as Error).message}.`);
  }
  const challenge = pk["challenge"];
  if (typeof challenge !== "string") throw new FlowError("Not signing: the server sent no WebAuthn challenge.");
  let commits = false;
  try {
    commits = await challengeCommitsTo(r.canonical, challenge);
  } catch (e) {
    throw new FlowError(`Not signing: ${(e as Error).message}.`);
  }
  if (!commits) throw new FlowError("Not signing: the passkey challenge does not match the action shown.");
  if (pk["userVerification"] !== "required") throw new FlowError("Not signing: the request does not require user verification.");
  if (rpId !== undefined && pk["rpId"] !== rpId) throw new FlowError("Not signing: the request is for a different site.");
  if (pk["extensions"] !== undefined && pk["extensions"] !== null) throw new FlowError("Not signing: the request carries unexpected extensions.");

  const options = decodeRequestOptions(r.public_key);
  const timeout = typeof options.timeout === "number" && options.timeout > 0 ? Math.min(options.timeout, CHALLENGE_LIFETIME_MS) : CHALLENGE_LIFETIME_MS;
  options.timeout = timeout;
  return { task, challengeId: r.challenge_id, canonicalText: r.canonical, params: want, secretsHash: hash, packet, options, validUntil: now + timeout };
}

/** Passkey prompt + hand-over to the runner's spool. Call straight from the owner's tap: the
 * prompt starts before any other await. */
export async function completeSetupTask(api: Api, auth: Authenticator, p: PreparedSetup, request?: string): Promise<void> {
  const cred = await auth.get(p.options);
  // `request`: the agent's queued maintenance request this run answers (the broker marks it
  // approved only if it asked for exactly the signed task and parameters).
  await api.setupPost!(`/${encodeURIComponent(p.task)}/run`, { challenge_id: p.challengeId, assertion: encodeAssertion(cred), secrets: p.packet, ...(request ? { request } : {}) });
}

/** Prepare and sign in one go (tools and tests; the page shows the canonical in between). */
export async function runSetupTask(
  api: Api,
  auth: Authenticator,
  view: SetupView,
  task: string,
  params: Record<string, unknown>,
  secrets?: Record<string, string>,
  rpId?: string,
  request?: string,
): Promise<void> {
  const has = secrets && Object.keys(secrets).length > 0 ? secrets : undefined;
  const p = rpId === undefined ? await prepareSetupTask(api, view, task, params, has) : await prepareSetupTask(api, view, task, params, has, rpId);
  await completeSetupTask(api, auth, p, request);
}

/** Seal the pasted recovery identity to the import process and have it run the drill. */
export async function sendDrill(api: Api, seal: { drill_key?: string; installation: string }, identity: string): Promise<void> {
  if (!seal.drill_key) throw new FlowError("The import has published no key for the recovery check. Reload the page.");
  const plaintext = utf8.encode(identity.trim() + "\n");
  let packet: string;
  try {
    packet = await sealPacket(seal.drill_key, drillInfo(seal.installation), plaintext);
  } finally {
    plaintext.fill(0);
  }
  await api.sealPost!("drill", { packet });
}

/** True while the broker stages a seal import or a bucket migration. */
export const staging = (mode: string | undefined) => mode === "seal-setup" || mode === "bucket-migrate";

// ---- the staged store (seal import and bucket migration; docs/BUCKETS.md §8) ----

export type StageStep = "open-legacy" | "create" | "test";
const PURPOSE: Record<StageStep, string> = { "open-legacy": "migrate", create: "stage", test: "test" };

/** What the next tap does, and how many taps the whole staging takes. */
export interface StagePlan {
  migrate: boolean;
  /** The next passkey step, or null when every scope is wrapped and tested. */
  next: { step: StageStep; scopes: string[] } | null;
  /** 1-based number of the next tap, and the total. */
  tap: number;
  taps: number;
  legacyDone: boolean;
  created: boolean;
  tested: boolean;
}

export function stagePlan(st: StageView): StagePlan {
  const migrate = st.source === "format-1";
  const all = st.scopes;
  const n = all.length;
  const legacyDone = !migrate || !!st.legacy_unlocked;
  const unwrapped = all.filter((x) => !x.wrapped).map((x) => x.scope);
  const untested = all.filter((x) => x.wrapped && !x.tested).map((x) => x.scope);
  const wrapped = n - unwrapped.length;
  const testedN = all.filter((x) => x.tested).length;
  // Open-legacy carries exactly one scope (the installation first); then two per tap.
  const taps = migrate ? 1 + Math.ceil(Math.max(0, n - 1) / 2) + Math.ceil(n / 2) : Math.ceil(n / 2) * 2;
  const doneTaps = migrate ? (legacyDone ? 1 : 0) + Math.ceil(Math.max(0, wrapped - (legacyDone ? 1 : 0)) / 2) + Math.ceil(testedN / 2) : Math.ceil(wrapped / 2) + Math.ceil(testedN / 2);
  let next: StagePlan["next"] = null;
  if (!legacyDone) {
    const first = unwrapped.includes("installation") ? "installation" : unwrapped[0];
    next = first ? { step: "open-legacy", scopes: [first] } : null;
  } else if (unwrapped.length) next = { step: "create", scopes: unwrapped.slice(0, 2) };
  else if (untested.length) next = { step: "test", scopes: untested.slice(0, 2) };
  return { migrate, next, tap: Math.min(doneTaps + 1, taps), taps, legacyDone, created: legacyDone && unwrapped.length === 0, tested: unwrapped.length === 0 && untested.length === 0 };
}

const STAGE_KEYS = ["action", "credential", "epoch", "id", "issued_at", "nonce", "object", "scopes", "v"];

/** One staging tap: challenge, checks of the canonical ("seal-stage") and the scope-enrol
 * descriptor, then `finish` (call from the tap: the prompt starts before any other await). */
export async function stageStep(api: Api, v: SealView, step: StageStep, choice: StageChoice, scopes: string[], rpId: string) {
  if (!v.stage || v.mode !== "setup") throw new FlowError("Nothing is staged.");
  if (step === "open-legacy" && (!choice.legacy || scopes.length !== 1)) throw new FlowError("This passkey cannot open the format-1 store.");
  if (!scopes.length || scopes.length > 2) throw new FlowError("One tap covers one or two scopes.");
  const b = await api.sealPost!<{ challenge_id: string; canonical: string; public_key: unknown; open?: { descriptor: string } }>("stage/challenge", { step, credential: choice.id, scopes });
  if (!b || typeof b.challenge_id !== "string" || typeof b.canonical !== "string") throw new FlowError("The server sent no challenge.");
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(b.canonical);
  } catch {
    throw new FlowError("Not signing: the staging text is not JSON.");
  }
  const keys = Object.keys(c).sort();
  let nonceOk = false;
  try {
    nonceOk = typeof c.nonce === "string" && decode(c.nonce).byteLength === 32 && encode(decode(c.nonce)) === c.nonce;
  } catch {
    nonceOk = false;
  }
  if (
    c.v !== 3 ||
    c.object !== "seal-stage" ||
    c.action !== step ||
    c.id !== v.installation ||
    c.epoch !== v.epoch ||
    c.credential !== choice.id ||
    JSON.stringify(c.scopes) !== JSON.stringify(scopes) ||
    !nonceOk ||
    typeof c.issued_at !== "string" ||
    !ISSUED_RE.test(c.issued_at) ||
    keys.join() !== STAGE_KEYS.join() ||
    canonicalJSON(c) !== b.canonical
  )
    throw new FlowError("Not signing: the staging step differs from the one you chose.");
  let tap;
  try {
    tap = await prepareTap(b, rpId, { object: "scope-enrol", purposes: [PURPOSE[step]], installation: v.installation, epoch: v.epoch, requireOpen: true, selected: choice.credential_id });
  } catch (e) {
    throw new FlowError(`Not signing: ${(e as Error).message}.`);
  }
  const d = tap.open!.descriptor;
  if (d.credential_id !== choice.credential_id || JSON.stringify(d.scopes) !== JSON.stringify(scopes)) throw new FlowError("Not signing: the tap is for other scopes or another passkey.");
  if (step === "open-legacy" && canonicalJSON(d.legacy) !== canonicalJSON(choice.legacy)) throw new FlowError("Not signing: the format-1 binding differs from the staged one.");
  let used = false;
  return {
    canonical: b.canonical,
    lines: tap.lines,
    async finish(auth: Authenticator): Promise<void> {
      if (used) throw new FlowError("Already used: start the step again.");
      used = true;
      const signed = await tap.sign(auth);
      if (!signed.open) throw new FlowError("This passkey returned no PRF result, so it cannot hold the store's keys. Use a passkey that supports PRF.");
      await api.sealPost!("stage/finish", { challenge_id: b.challenge_id, assertion: signed.assertion, open: signed.open });
    },
  };
}
