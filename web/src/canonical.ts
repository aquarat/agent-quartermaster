// The canonical action text (docs/API.md "Approval challenge"). The UI describes the action
// to the owner FROM THE CANONICAL STRING the server returned, never from the card it was
// started from, and refuses to sign unless
//   1. canonical is well-formed canonical JSON (sorted keys, no whitespace, no duplicates),
//   2. SHA-256(canonical) equals the WebAuthn challenge the passkey will sign, and
//   3. its fields match what the owner chose (action, object, id, TTL, standing hours) and the
//      facts on the card (host, target, user, key).
// So what is shown is exactly what is signed, and what is signed is what was asked for.

import { bytesEqual, decode, encode } from "./b64url";
import { planRows,catalogueRows } from './migration';
import {
  ScopeParamsError,
  cfScope,
  paramPairs,
  paramProblems,
  parseIPCondition,
  parseScopeParams,
  unusualParams,
  wideCIDRs,
  type CFRisk,
} from "./cfscopes";
import { duration, hours, isPlainName, kindLabel } from "./format";

export interface Canonical {
  principal?: string; replaces_id?: string;
  class?: string; address?: string; target_address?: string; target_port?: number;
  v: number;
  action: string;
  object: string;
  id: string;
  requesting_host?: string;
  kind?: string;
  target?: string;
  login_user?: string;
  key_fingerprint?: string;
  ttl_seconds?: number;
  standing_hours?: number;
  replaces?: boolean;
  // kind "cloudflare" (API.md 5.4)
  scope?: string;
  scope_params?: string;
  mode?: string;
  ip_condition?: string;
  nickname?: string;
  new_nickname?: string;
  nonce?: string;
  issued_at?: string;
  [k: string]: unknown;
}

// Keys allowed per object. Anything else is refused: the owner can only judge what the UI
// knows how to describe, so an unknown field (say, a forced command) must not be signed blind.
const COMMON_KEYS = ["v", "action", "object", "id", "nonce", "issued_at"];
const UPDATE_KEYS = ['from_commit','to_commit','from_version','to_version','daemon_sha256','linux_arm64_sha256','linux_amd64_sha256','darwin_arm64_sha256'] as const;
type UpdateFields = Partial<Record<typeof UPDATE_KEYS[number], string>>;
const ALLOWED_KEYS: Record<string, string[]> = {
  migration:[...COMMON_KEYS,'plan','recovery_sha256'],
  update: [...COMMON_KEYS,...UPDATE_KEYS],
  host: [...COMMON_KEYS, 'address','class','requesting_host'],
  request: [...COMMON_KEYS,'address','principal', 'target_address','target_port',"requesting_host", "kind", "target", "login_user", "key_fingerprint", "ttl_seconds", "standing_hours"],
  enrollment: [...COMMON_KEYS,'replaces_id','address','class', "requesting_host", "kind", "key_fingerprint", "replaces", "ttl_seconds", "standing_hours"],
  standing: [...COMMON_KEYS, "requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"],
  grant: [...COMMON_KEYS, "requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"],
  passkey: [...COMMON_KEYS, "nickname", "new_nickname"],
  // A maintenance task for the root runner (docs/SETUP.md): id names the task.
  setup: [...COMMON_KEYS, "params", "secrets_sha256"],
};
// kind "cloudflare" (API.md 5.4): a different, exact key set for request/standing/grant.
const CF_KEYS: Record<string, string[]> = {
  request: [...COMMON_KEYS, "requesting_host", "kind", "scope", "scope_params", "mode", "ip_condition", "ttl_seconds", "standing_hours"],
  standing: [...COMMON_KEYS, "requesting_host", "kind", "scope", "scope_params", "mode", "ttl_seconds", "standing_hours"],
  grant: [...COMMON_KEYS, "requesting_host", "kind", "scope", "scope_params", "mode", "ttl_seconds", "standing_hours"],
};
const STRING_KEYS = ["requesting_host", "kind", "target", "login_user", "key_fingerprint", "nickname", "new_nickname", "scope", "scope_params", "mode", "ip_condition", "nonce", "issued_at"] as const;
const ALLOWED_ACTIONS: Record<string, string[]> = {
  migration:['activate'],
  update:['approve'],
  host:['revoke'],
  request: ["approve", "deny"],
  enrollment: ["approve", "deny"],
  standing: ["revoke"],
  grant: ["revoke"],
  passkey: ["add", "rename", "remove"],
  setup: ["run"],
};
export const catalogueVerbs={organisation:['create'],service:['create'],credential_set:['create'],org_policy:['replace'],org_host:['admit','remove']};
for(const [k,v] of Object.entries(catalogueVerbs)){ALLOWED_KEYS[k]=[...COMMON_KEYS,'plan'];ALLOWED_ACTIONS[k]=v;}
const durationFlags=['indefinite','standing_indefinite','beyond_soft_cap','standing_beyond_soft_cap'];

export class CanonicalError extends Error {
  override name = "CanonicalError";
}

function sortedJSON(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(sortedJSON).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${sortedJSON(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

/** Go's encoding/json escapes <, >, &, U+2028 and U+2029 by default. */
function goEscape(s: string): string {
  return s
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/** Parse and validate canonical text. Throws CanonicalError. */
export function parseCanonical(text: string): Canonical {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new CanonicalError("canonical action is not valid JSON");
  }
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new CanonicalError("canonical action is not an object");
  // Re-serialise with sorted keys: a mismatch means whitespace, unsorted or duplicate keys,
  // i.e. text whose meaning could be read two ways.
  const again = sortedJSON(v);
  if ((v as Canonical).v!==2 && text !== again && text !== goEscape(again)) throw new CanonicalError("canonical action is not in canonical form");
  const c = v as Canonical;
  if (c.v !== 1 && c.v!==2) throw new CanonicalError(`unsupported canonical version ${String(c.v)}`);
  if(c.object==='migration' && c.v!==2) throw new CanonicalError('migration requires canonical v2');
  if(c.v===2){if(text!==again.replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029') || typeof c.nonce!=='string' || decode(c.nonce).byteLength!==32 || encode(decode(c.nonce))!==c.nonce || typeof c.issued_at!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(c.issued_at))throw new CanonicalError('invalid v2 encoding');}
  for (const k of ["action", "object", "id"] as const) {
    if (typeof c[k] !== "string" || c[k] === "") throw new CanonicalError(`canonical action has no ${k}`);
  }
  if (!Object.hasOwn(ALLOWED_KEYS,c.object)) throw new CanonicalError(`unknown object ${JSON.stringify(c.object)}`);
  // The key set depends on (object, kind): a Cloudflare request carries scope/params/mode
  // instead of target/user/key.
  const cf = c.kind === "cloudflare" && CF_KEYS[c.object] !== undefined;
  let allowed = cf ? CF_KEYS[c.object]! : ALLOWED_KEYS[c.object]!;
  if(c.object==='migration'){if(typeof c.recovery_sha256!=='string' || !/^[0-9a-f]{64}$/.test(c.recovery_sha256) || typeof c.plan!=='string')throw new CanonicalError('invalid migration');planRows(c.plan,c.id);}
  else if(Object.hasOwn(catalogueVerbs,c.object)){if(c.v!==2||typeof c.plan!=='string')throw new CanonicalError('invalid catalogue change');catalogueRows(c.plan,c.object);}
  else if(c.v===2){if(!['request','standing','grant'].includes(c.object)|| !['ssh','cloudflare'].includes(c.kind??''))throw new CanonicalError('unsupported scoped action');allowed=[...new Set([...allowed,...bindingKeys(c.kind),...durationFlags,'standing_seconds'])];validateBinding(c);}
  if (!ALLOWED_ACTIONS[c.object]!.includes(c.action)) throw new CanonicalError(`unknown action ${JSON.stringify(c.action)} for ${c.object}`);
  const extra = Object.keys(c).filter((k) => !allowed.includes(k));
  if (extra.length) throw new CanonicalError(`canonical action has fields this page can't show (${extra.join(", ")})`);
  const missing = allowed.filter(k => !Object.hasOwn(c,k));
  if (missing.length) throw new CanonicalError(`canonical action lacks ${missing.join(', ')}`);
  if (c.object==='update') {
    for (const k of UPDATE_KEYS) {
      const re=k.endsWith('_commit')?/^[0-9a-f]{40}$/:k.endsWith('_version')?/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/:/^[0-9a-f]{64}$/;
      const v=c[k]; if(typeof v!=='string'||!re.test(v)||v.trim()!==v) throw new CanonicalError(`invalid ${k}`);
    }
    if(c.to_commit!==c.id) throw new CanonicalError('update id differs from commit');
  }
  if (c.object === "setup") checkSetup(c);
  if (c.object==='request' && !cf && (typeof c.principal!=='string'||!c.principal||typeof c.address!=='string'||!c.address)) throw new CanonicalError('invalid SSH source or principal');
  if (c.object==='enrollment' && (typeof c.replaces_id!=='string'||Boolean(c.replaces_id)!==c.replaces||c.ttl_seconds!==0||c.standing_hours!==0)) throw new CanonicalError('inconsistent enrollment');
  if ((c.object==='host'||c.object==='enrollment') && (typeof c.address!=='string'||!c.address||!['owner-device','agent'].includes(c.class ?? ''))) throw new CanonicalError('invalid host address or class');
  if(c.object==='request' && !cf && (!c.target_address || typeof c.target_address!=='string'|| !Number.isInteger(c.target_port)||c.target_port!<1||c.target_port!>65535)) throw new CanonicalError('invalid SSH destination');
  for (const k of STRING_KEYS) {
    if (c[k] !== undefined && typeof c[k] !== "string") throw new CanonicalError(`canonical ${k} is not a string`);
  }
  if (c.replaces !== undefined && typeof c.replaces !== "boolean") throw new CanonicalError("canonical replaces is not a boolean");
  for (const k of ["ttl_seconds", "standing_hours"] as const) {
    if (c[k] !== undefined && (typeof c[k] !== "number" || !Number.isSafeInteger(c[k]) || c[k]! < 0)) {
      throw new CanonicalError(`canonical ${k} is not a whole number`);
    }
  }
  if (cf) checkCloudflare(c, allowed);
  return c;
}

/** Object "setup": v1, the task's parameters as one JSON object text, and the digest of the
 * sealed secrets packet (or ""). The caller compares both with what it derived itself. */
function checkSetup(c: Canonical): void {
  if (c.v !== 1) throw new CanonicalError("setup requires canonical v1");
  if (typeof c.params !== "string" || typeof c.secrets_sha256 !== "string" || !/^([0-9a-f]{64})?$/.test(c.secrets_sha256)) throw new CanonicalError("invalid setup fields");
  let p: unknown;
  try {
    p = JSON.parse(c.params);
  } catch {
    p = null;
  }
  if (p === null || typeof p !== "object" || Array.isArray(p)) throw new CanonicalError("setup parameters are not a JSON object");
}

/** Kind "cloudflare": every key present, a scope this page can describe, well-formed
 * parameters for it, a consistent mode/ip_condition, and no standing approval where none can
 * exist. Throws CanonicalError. */
function checkCloudflare(c: Canonical, keys: string[]): void {
  const missing = keys.filter((k) => !(k in c));
  if (missing.length) throw new CanonicalError(`canonical action lacks ${missing.join(", ")}`);
  const scope = cfScope(c.scope);
  if (!scope) throw new CanonicalError(`this page has no description of Cloudflare scope ${JSON.stringify(c.scope)}, so it won't sign it`);
  let params: Record<string, string>;
  try {
    params = parseScopeParams(c.scope_params!);
  } catch (e) {
    throw new CanonicalError((e as Error).message);
  }
  const problems = paramProblems(scope, params);
  if (problems.length) throw new CanonicalError(`scope_params: ${problems.join("; ")}`);
  if (c.mode !== "proxy" && c.mode !== "token") throw new CanonicalError(`unknown Cloudflare mode ${JSON.stringify(c.mode)}`);
  if (c.mode === "token" && !scope.token) throw new CanonicalError(`${scope.name} has no token mode`);
  if (c.object === "request") {
    let cidrs: string[];
    try {
      cidrs = parseIPCondition(c.ip_condition!);
    } catch (e) {
      throw new CanonicalError((e as Error).message);
    }
    if (c.mode === "proxy" && cidrs.length) throw new CanonicalError("ip_condition must be empty in proxy mode");
    if (c.mode === "token" && !cidrs.length) throw new CanonicalError("a token must carry an ip_condition");
  }
  if ((c.standing_hours ?? 0) > 0) {
    if (c.object !== "request" || c.action !== "approve") throw new CanonicalError("only an approval can carry standing_hours");
    if (!scope.standing) throw new CanonicalError(`${scope.name} never allows auto-approval (standing_hours must be 0)`);
    if (c.mode !== "proxy") throw new CanonicalError("token grants are never auto-approved (standing_hours must be 0)");
  }
  if (c.object === "request" && c.action === "approve" && (c.ttl_seconds ?? 0) > ((c.v===1||c.scope==='cf.admin'||c.scope==='cf.read.private')?scope.maxTTL:Number(c.hard_cap))) {
    throw new CanonicalError(`${scope.name} lasts at most ${duration(scope.maxTTL)}`);
  }
}

/** Parsed Cloudflare parameters of a (validated) canonical action; {} if absent or bad. */
export function canonicalParams(c: Canonical): Record<string, string> {
  try {
    return parseScopeParams(c.scope_params ?? "");
  } catch (e) {
    if (e instanceof ScopeParamsError) return {};
    throw e;
  }
}

export async function sha256(text: string): Promise<ArrayBuffer> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new CanonicalError("this page needs HTTPS (no Web Crypto) to check the challenge");
  return subtle.digest("SHA-256", new TextEncoder().encode(text));
}

/** True when the WebAuthn challenge (base64url) is SHA-256 of the canonical UTF-8 bytes. */
export async function challengeCommitsTo(canonical: string, challengeB64url: string): Promise<boolean> {
  return bytesEqual(await sha256(canonical), decode(challengeB64url));
}

/** What the owner chose plus the facts on the card. Unset fields are not checked. */
export interface Expectation extends UpdateFields {
  standing_seconds?:number;
  scoped_facts?: Record<string,string|number|boolean>;
  indefinite?:boolean;standing_indefinite?:boolean;
  plan?: string; recovery_sha256?:string;
  principal?: string; replaces_id?: string;
  class?: string; address?: string; target_address?: string; target_port?: number;
  action: string;
  object: string;
  id: string;
  ttl_seconds?: number;
  standing_hours?: number;
  requesting_host?: string;
  kind?: string;
  target?: string;
  login_user?: string;
  key_fingerprint?: string;
  replaces?: boolean;
  scope?: string;
  scope_params?: string;
  mode?: string;
  ip_condition?: string;
  /** Setup: the task's canonical parameters and the sealed packet's digest ("" for none). */
  params?: string;
  secrets_sha256?: string;
  /** Passkey actions: the passkey's current nickname ("" for add). */
  nickname?: string;
  /** Passkey rename: the new nickname ("" for add and remove). */
  new_nickname?: string;
}

/** List of human-readable mismatches between canonical and the expectation (empty = ok). */
export function mismatches(c: Canonical, e: Expectation): string[] {
  const out: string[] = [];
  const cmp = (field: string, got: unknown, want: unknown) => {
    if (want === undefined) return;
    if (got !== want) out.push(`${field}: expected ${JSON.stringify(want)}, server sent ${JSON.stringify(got ?? null)}`);
  };
  cmp("action", c.action, e.action);
  cmp("object", c.object, e.object);
  cmp("id", c.id, e.id);
  if(e.scoped_facts)cmp('standing_seconds',c.standing_seconds,e.standing_seconds??0);
  if(c.object==='migration'){cmp('plan',c.plan,e.plan??'');cmp('recovery_sha256',c.recovery_sha256,e.recovery_sha256??'');}
  else if(Object.hasOwn(catalogueVerbs,c.object))cmp('plan',c.plan,e.plan??'');
  else if(e.scoped_facts || c.v===2){cmp('v',c.v,2);cmp('indefinite',c.indefinite,e.indefinite??false);cmp('standing_indefinite',c.standing_indefinite,e.standing_indefinite??false);for(const k of bindingKeys(c.kind)){if(!e.scoped_facts || !Object.hasOwn(e.scoped_facts,k))out.push(`card lacks ${k}`);else cmp(k,c[k],e.scoped_facts[k]);}}
  if (e.object==='update') for (const k of UPDATE_KEYS) cmp(k,c[k],e[k]??'');
  if (e.object === "setup" || c.object === "setup") {
    cmp("params", c.params, e.params ?? "");
    cmp("secrets_sha256", c.secrets_sha256, e.secrets_sha256 ?? "");
  }
  cmp("requesting_host", c.requesting_host, e.requesting_host);
  cmp("kind", c.kind, e.kind);
  cmp("target", c.target, e.target);
  for(const k of ['replaces_id','principal','address','class','target_address','target_port'] as const) cmp(k,c[k],e[k]);
  cmp("login_user", c.login_user, e.login_user);
  cmp("key_fingerprint", c.key_fingerprint, e.key_fingerprint);
  cmp("scope", c.scope, e.scope);
  cmp("scope_params", c.scope_params, e.scope_params);
  cmp("mode", c.mode, e.mode);
  cmp("ip_condition", c.ip_condition, e.ip_condition);
  if (e.object === "enrollment") cmp("replaces", c.replaces ?? false, e.replaces ?? false);
  if (e.object === "passkey") {
    // Every passkey action carries both nicknames; add and remove must not rename anything.
    cmp("nickname", c.nickname, e.nickname ?? "");
    cmp("new_nickname", c.new_nickname, e.action === "rename" || e.action === "add" ? (e.new_nickname ?? "") : "");
  }
  if (e.action === "approve") {
    cmp("ttl_seconds", c.ttl_seconds ?? 0, e.ttl_seconds);
    cmp("standing_hours", c.standing_hours ?? 0, e.standing_hours ?? 0);
  } else {
    // Revoking a Cloudflare standing approval names the rule's max TTL; a grant revoke 0.
    cmp("ttl_seconds", c.ttl_seconds ?? 0, e.ttl_seconds);
    // Deny/revoke must not carry a standing approval.
    cmp("standing_hours", c.standing_hours ?? 0, 0);
  }
  return out;
}

/** A headline piece: our own words (string) or a value from canonical, rendered isolated
 * (<bdi>) so right-to-left text in one value can't reorder the rest of the sentence. */
export type Part = string | { value: string };

export interface Description {
  /** One sentence, e.g. "Approve SSH as alice@db-1 for 30 min, requested by web-1." */
  headline: string;
  headlineParts: Part[];
  /** Extra sentence for a standing approval, shown as a warning. */
  standing?: string;
  standingParts?: Part[];
  /** Things the owner must notice (replacing a host, unusual characters in names). */
  warnings: string[];
  /** Every canonical field, in the order the owner should read them. */
  fields: Array<[string, string]>;
  /** Kind "cloudflare": one line per parameter, then the mode, each from canonical. */
  details?: Part[][];
  /** Kind "cloudflare": the scope's risk (this page's own table). */
  risk?: CFRisk;
  /** cf.admin: show the confirmation as break-glass. */
  breakGlass?: boolean;
}

const FIELD_LABELS: Record<string, string> = {
  address:'Source address',class:'Host class',target_address:'Target address',target_port:'Target port',principal:'Certificate principal',replaces_id:'Enrollment replaced',
  action: "Action",
  object: "Applies to",
  kind: "Kind",
  scope: "Cloudflare scope",
  scope_params: "Parameters",
  mode: "Mode",
  ip_condition: "Token usable from",
  login_user: "Log in as",
  target: "On host",
  requesting_host: "Requested by",
  ttl_seconds: "Access lasts",
  standing_hours: "Auto-approve similar",
  replaces: "Replaces existing host",
  nickname: "Passkey",
  new_nickname: "New name",
  key_fingerprint: "Key",
  params: "Task parameters",
  secrets_sha256: "Sealed secrets (SHA-256)",
  id: "ID",
  issued_at: "Issued",
  nonce: "Nonce",
  v: "Format",
};
const FIELD_ORDER = Object.keys(FIELD_LABELS);

function fieldValue(k: string, v: unknown): string {
  if (k === "ttl_seconds" && typeof v === "number") return v > 0 ? duration(v) : "n/a";
  if (k === "standing_hours" && typeof v === "number") return v > 0 ? `for ${hours(v)}` : "no";
  if (k === "replaces" && typeof v === "boolean") return v ? "yes" : "no";
  if (k === "scope_params" && v === "") return "none";
  if (k === "ip_condition" && v === "") return "n/a (proxy)";
  if ((k === "nickname" || k === "new_nickname") && v === "") return "(none)";
  if (k === "secrets_sha256" && v === "") return "none";
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

function t(strings: TemplateStringsArray, ...vals: Array<string | Part[]>): Part[] {
  const out: Part[] = [];
  strings.forEach((str, i) => {
    if (str) out.push(str);
    if (i < vals.length) {
      const v = vals[i]!;
      if (Array.isArray(v)) out.push(...v);
      else out.push({ value: v });
    }
  });
  return out;
}

export function partsText(parts: Part[]): string {
  return parts.map((p) => (typeof p === "string" ? p : p.value)).join("");
}

/** Short id of a passkey as the UI shows it on the tile: the last 6 hex digits, upper case. */
export function shortId(id: string): string {
  return id.slice(-6).toUpperCase();
}

function who(c: Canonical): Part[] {
  return [{ value: c.login_user ?? "?" }, "@", { value: c.target ?? "?" }];
}

/** Describe the canonical action in plain words. Built only from canonical's own fields. */
export function describe(c: Canonical): Description {
  if(Object.hasOwn(catalogueVerbs,c.object)){const p=JSON.parse(String(c.plan));const headline=`${p.organisation.title}: ${c.action} ${c.object.replace('_',' ')}.`;return {headline,headlineParts:[{value:p.organisation.title},`: ${c.action} ${c.object.replace('_',' ')}.`],warnings:c.object==='org_policy'||c.action==='remove'?['Affected pending work expires; broker grants and standing approvals end. Issued SSH certificates can still work until expiry, and sessions can continue.']:[],fields:catalogueRows(String(c.plan),c.object)};}
  if(c.object==='migration'){const headline='personal: activate organisation admissions and retire previous authority.';return {headline,headlineParts:[headline],warnings:['Pending requests expire; standing approvals and broker grants end. Issued SSH certificates and unverified children can still work until their original expiry.'],fields:[['Recovery SHA-256',String(c.recovery_sha256)],...planRows(String(c.plan),c.id)]};}
  if(c.v===2){const d=describe({...c,v:1});const path=[c.org_title,c.service_title,c.set_title].map(String).join(' › ');d.headline=`${path}: ${d.headline}`;d.headlineParts=[{value:path},': ',...d.headlineParts];if(c.indefinite||c.standing_indefinite)d.warnings.push(`INDEFINITE ${c.indefinite?'grant':'standing approval'} — active until revoked.`);if(Number(c.standing_seconds)>0)d.warnings.push(`Also auto-approve matching requests for ${duration(Number(c.standing_seconds))}.`);if(c.beyond_soft_cap||c.standing_beyond_soft_cap)d.warnings.push('Beyond soft cap: check the duration before approving.');d.fields=fieldList(c);return d;}
  if (c.kind === "cloudflare" && CF_KEYS[c.object]) return describeCloudflare(c);
  const kind = kindLabel(c.kind ?? "ssh");
  const host = c.requesting_host ?? "?";
  let headline: Part[];
  let standing: Part[] | undefined;
  const warnings: string[] = [];
  switch (`${c.object}:${c.action}`) {
    case 'update:approve':
      headline=t`Install aqmasd ${String(c.to_version)} on the bastion, replacing ${String(c.from_version)}.`;
      warnings.push('The updater will rebuild this commit, verify all four binaries, and restart the credential broker.');
      break;
    case "setup:run":
      headline = t`Run the setup task ${c.id} on the bastion.`;
      warnings.push("The root maintenance runner checks this signature itself and carries the task out.");
      break;
    case "request:approve":
      headline = t`Approve ${kind} as ${who(c)} for ${duration(c.ttl_seconds ?? 0)}, requested by ${host}.`;
      if ((c.standing_hours ?? 0) > 0) {
        standing = t`Also auto-approve the same request (${host} to ${who(c)}) for the next ${hours(c.standing_hours!)}.`;
      }
      break;
    case "request:deny":
      headline = t`Deny ${kind} as ${who(c)}, requested by ${host}.`;
      break;
    case "enrollment:approve":
      headline = c.replaces ? t`Let ${host} join the fleet, replacing the existing host of that name.` : t`Let ${host} join the fleet as a trusted host.`;
      if (c.replaces) warnings.push(`The current ${host} loses its client certificate. Only approve if you re-installed or re-keyed that host yourself.`);
      break;
    case 'host:revoke':
      headline=t`Revoke host ${host} (${c.class!}, enrolled from ${c.address!}, enrollment ${c.id}).`;
      warnings.push('Pending requests expire; standing approvals and proxy grants stop. Child tokens may work until deleted upstream. Issued SSH certificates remain valid until expiry. Existing SSH and mosh sessions are not disconnected.');
      break;
    case "enrollment:deny":
      headline = t`Refuse ${host} joining the fleet.`;
      break;
    case "standing:revoke":
      headline = t`Stop auto-approving ${kind} as ${who(c)} for ${host}.`;
      break;
    case "grant:revoke":
      headline = t`Revoke ${host}'s ${kind} access as ${who(c)}.`;
      break;
    case "passkey:add":
      headline = c.new_nickname ? t`Allow adding a new passkey named ${c.new_nickname} to aqmas.` : ["Allow adding a new passkey to aqmas (named after its authenticator)."];
      break;
    case "passkey:rename":
      headline = t`Rename the passkey ${c.nickname ?? "?"} (id ${shortId(c.id)}) to ${c.new_nickname ?? "?"}.`;
      break;
    case "passkey:remove":
      headline = t`Remove the passkey ${c.nickname ?? "?"} (id ${shortId(c.id)}). It can no longer sign in or approve anything.`;
      break;
    default:
      headline = t`${c.action} ${c.object} ${c.id}.`;
  }
  for (const k of ["nickname", "new_nickname"] as const) {
    const v = c[k];
    if (typeof v === "string" && v !== "" && !/^[\x20-\x7e]+$/.test(v)) {
      warnings.push(`The passkey name ${JSON.stringify(v)} has characters outside plain ASCII, which can look like other letters: go by the id.`);
    }
  }
  for (const [k, label] of [
    ["requesting_host", "requesting host"],
    ["target", "target host"],
    ["login_user", "login user"],
  ] as const) {
    if (c[k] !== undefined && !isPlainName(c[k])) warnings.push(`The ${label} name contains unusual characters: check it letter by letter.`);
  }
  return {
    headline: partsText(headline),
    headlineParts: headline,
    standing: standing ? partsText(standing) : undefined,
    standingParts: standing,
    warnings,
    details: c.object==='enrollment' ? [t`Class: ${c.class!}. Enrolling from ${c.address!}.`, ...(c.replaces ? [t`Replaces enrollment ${c.replaces_id!}.`] : [])] : c.object==='request' ? [t`Resolved address: ${c.target_address!}, port ${String(c.target_port)}.`,t`Certificate principal ${c.principal!}, usable from ${c.address!}.`] : undefined,
    fields: fieldList(c),
  };
}

const revisions=['set_revision','service_revision','policy_revision','admission_generation'];
const offerFlags=['offers_indefinite','offers_standing','offers_standing_indefinite'];const policyNumbers=['soft_cap','hard_cap','standing_soft_cap','standing_default','max_standing_hours'];
function bindingKeys(kind:unknown):string[]{return ['org_id','org_slug','org_title','service_id','service_slug','service_title','set_id','set_slug','set_title',...revisions,'host_id','class','address','profile_revision',...policyNumbers,...offerFlags,...(kind==='ssh'?['ssh_ca','host_key','cert_profile','principal','target_address','target_port','key_fingerprint']:['account_id','resource_ids','ip_condition'])];}
function validateBinding(c:Canonical){for(const k of [...bindingKeys(c.kind),...durationFlags]){const x=c[k];if(offerFlags.includes(k)||durationFlags.includes(k)){if(typeof x!=='boolean')throw new CanonicalError(`invalid ${k}`);}else if(revisions.includes(k)||policyNumbers.includes(k)||k==='target_port'){if(typeof x!=='number'||!Number.isSafeInteger(x)||x<(policyNumbers.includes(k)?0:1))throw new CanonicalError(`invalid ${k}`);}else if(typeof x!=='string'||(!x && k!=='resource_ids'&&k!=='ip_condition'))throw new CanonicalError(`invalid ${k}`);}
 const seconds=c.standing_seconds;if(typeof seconds!=='number'||!Number.isSafeInteger(seconds)||seconds<0||seconds>0&&(c.standing_hours!==0||!c.offers_standing||c.standing_indefinite||c.indefinite||c.object!=='request'||c.action!=='approve'||seconds>Number(c.max_standing_hours)*3600))throw new CanonicalError('invalid standing seconds');
 if(c.indefinite && (!c.offers_indefinite||c.kind==='ssh'||c.scope==='cf.admin'||c.scope==='cf.read.private'||c.ttl_seconds!==0) || c.standing_indefinite && (!c.offers_standing_indefinite||!c.offers_standing||c.standing_hours!==0) || c.beyond_soft_cap!==(c.indefinite||Number(c.ttl_seconds)>Number(c.soft_cap)) || c.standing_beyond_soft_cap!==(c.standing_indefinite||Math.max(seconds,Number(c.standing_hours)*3600)>Number(c.standing_soft_cap)))throw new CanonicalError('inconsistent duration policy');
 if(c.kind==='cloudflare' && (c.mode!=='proxy'|| c.ip_condition!=='' || !/^[0-9a-f]{32}$/.test(String(c.account_id))))throw new CanonicalError('unverified Cloudflare template');if(!['agent','owner-device'].includes(c.class??''))throw new CanonicalError('unknown host class');if(c.kind==='ssh'&&c.cert_profile!=='source-address;permit-pty;permit-port-forwarding')throw new CanonicalError('unknown certificate profile');}

function fieldList(c: Canonical): Array<[string, string]> {
  const keys = Object.keys(c).sort((a, b) => {
    const ia = FIELD_ORDER.indexOf(a);
    const ib = FIELD_ORDER.indexOf(b);
    return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib) || a.localeCompare(b);
  });
  return keys.map((k) => [FIELD_LABELS[k] ?? k, fieldValue(k, c[k])]);
}

/** Plain words for a Cloudflare action, from canonical and this page's scope table only.
 * parseCanonical has already refused unknown scopes and malformed parameters. */
function describeCloudflare(c: Canonical): Description {
  const scope = cfScope(c.scope);
  const params = canonicalParams(c);
  const host = c.requesting_host ?? "?";
  const what: Part[] = scope ? scope.phrase(params) : [{ value: c.scope ?? "?" }];
  const token = c.mode === "token";
  const cidrs = token ? (c.ip_condition ?? "").split(",").filter(Boolean) : [];
  const modeWords: Part[] = token
    ? ["as a real API token that leaves aqmas, limited to ", { value: cidrs.join(", ") || "?" }]
    : ["through the aqmas proxy (no secret leaves aqmas)"];
  let headline: Part[];
  let standing: Part[] | undefined;
  const warnings: string[] = [];
  const breakGlass = c.scope === "cf.admin";
  switch (`${c.object}:${c.action}`) {
    case "request:approve":
      headline = t`Approve Cloudflare for ${host}: ${what} for ${duration(c.ttl_seconds ?? 0)}, ${modeWords}.`;
      if ((c.standing_hours ?? 0) > 0) {
        standing = t`Also auto-approve the same Cloudflare request from ${host} (${c.scope ?? "?"} ${c.scope_params || "without parameters"}, proxy) for the next ${hours(c.standing_hours!)}.`;
      }
      break;
    case "request:deny":
      headline = t`Deny Cloudflare for ${host}: ${what}.`;
      break;
    case "standing:revoke":
      headline =
        (c.ttl_seconds ?? 0) > 0
          ? t`Stop auto-approving Cloudflare for ${host}: ${what} (each grant up to ${duration(c.ttl_seconds!)}).`
          : t`Stop auto-approving Cloudflare for ${host}: ${what}.`;
      break;
    case "grant:revoke":
      headline = token ? t`Revoke ${host}'s Cloudflare token (deleted at Cloudflare at once): ${what}.` : t`Revoke ${host}'s Cloudflare access: ${what}.`;
      break;
    default:
      headline = t`${c.action} ${c.object} ${c.id}.`;
  }
  if (breakGlass && c.action === "approve") {
    warnings.push(
      "BREAK-GLASS: full Cloudflare access for up to 1 hour. Every API call on every zone, tunnel and app except the deny-list (API tokens, members, tunnel run tokens), and guard rails can be overridden per call. Approve only if you asked for this yourself.",
    );
  }
  if (token && c.action === "approve") {
    warnings.push(
      "A real Cloudflare API token leaves aqmas. aqmas's guard rails and snapshots do not apply to calls made with it; it expires with the grant and revoking deletes it.",
    );
    const note = scope?.tokenNote?.(params);
    if (note) warnings.push(note);
    const wide = wideCIDRs(cidrs);
    if (wide.length) warnings.push(`The token works from whole networks, not one address: ${wide.join(", ")}.`);
  }
  if (!isPlainName(host)) warnings.push("The requesting host name contains unusual characters: check it letter by letter.");
  if (scope) {
    for (const label of unusualParams(scope, params)) warnings.push(`The ${label} value contains unusual characters: check it letter by letter.`);
  }
  for (const cidr of cidrs) {
    if (!/^[0-9a-f.:/]+$/.test(cidr)) warnings.push("The token's IP condition contains unusual characters: check it letter by letter.");
  }
  const details: Part[][] = paramPairs(scope, params).map(([label, val]) => [`${label}: `, { value: val }]);
  details.push(token ? ["Mode: real API token, usable only from ", { value: cidrs.join(", ") || "?" }] : ["Mode: through the aqmas proxy"]);
  return {
    headline: partsText(headline),
    headlineParts: headline,
    standing: standing ? partsText(standing) : undefined,
    standingParts: standing,
    warnings,
    fields: fieldList(c),
    details,
    risk: scope?.risk,
    breakGlass,
  };
}
