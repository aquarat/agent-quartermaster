// The canonical action text (docs/API.md "Approval challenge"). The UI describes the action
// to the owner FROM THE CANONICAL STRING the server returned, never from the card it was
// started from, and refuses to sign unless
//   1. canonical is well-formed canonical JSON (sorted keys, no whitespace, no duplicates),
//   2. SHA-256(canonical) equals the WebAuthn challenge the passkey will sign, and
//   3. its fields match what the owner chose (action, object, id, TTL, standing hours) and the
//      facts on the card (host, target, user, key).
// So what is shown is exactly what is signed, and what is signed is what was asked for.

import { bytesEqual, decode } from "./b64url";
import { duration, hours, isPlainName, kindLabel } from "./format";

export interface Canonical {
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
  nonce?: string;
  issued_at?: string;
  [k: string]: unknown;
}

// Keys allowed per object. Anything else is refused: the owner can only judge what the UI
// knows how to describe, so an unknown field (say, a forced command) must not be signed blind.
const COMMON_KEYS = ["v", "action", "object", "id", "nonce", "issued_at"];
const ALLOWED_KEYS: Record<string, string[]> = {
  request: [...COMMON_KEYS, "requesting_host", "kind", "target", "login_user", "key_fingerprint", "ttl_seconds", "standing_hours"],
  enrollment: [...COMMON_KEYS, "requesting_host", "kind", "key_fingerprint", "replaces", "ttl_seconds", "standing_hours"],
  standing: [...COMMON_KEYS, "requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"],
  grant: [...COMMON_KEYS, "requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"],
  passkey: COMMON_KEYS,
};
const ALLOWED_ACTIONS: Record<string, string[]> = {
  request: ["approve", "deny"],
  enrollment: ["approve", "deny"],
  standing: ["revoke"],
  grant: ["revoke"],
  passkey: ["add"],
};

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
  if (text !== again && text !== goEscape(again)) throw new CanonicalError("canonical action is not in canonical form");
  const c = v as Canonical;
  if (c.v !== 1) throw new CanonicalError(`unsupported canonical version ${String(c.v)}`);
  for (const k of ["action", "object", "id"] as const) {
    if (typeof c[k] !== "string" || c[k] === "") throw new CanonicalError(`canonical action has no ${k}`);
  }
  const allowed = ALLOWED_KEYS[c.object];
  if (!allowed) throw new CanonicalError(`unknown object ${JSON.stringify(c.object)}`);
  if (!ALLOWED_ACTIONS[c.object]!.includes(c.action)) throw new CanonicalError(`unknown action ${JSON.stringify(c.action)} for ${c.object}`);
  const extra = Object.keys(c).filter((k) => !allowed.includes(k));
  if (extra.length) throw new CanonicalError(`canonical action has fields this page can't show (${extra.join(", ")})`);
  for (const k of ["requesting_host", "kind", "target", "login_user", "key_fingerprint", "nonce", "issued_at"] as const) {
    if (c[k] !== undefined && typeof c[k] !== "string") throw new CanonicalError(`canonical ${k} is not a string`);
  }
  if (c.replaces !== undefined && typeof c.replaces !== "boolean") throw new CanonicalError("canonical replaces is not a boolean");
  for (const k of ["ttl_seconds", "standing_hours"] as const) {
    if (c[k] !== undefined && c[k] !== null && (typeof c[k] !== "number" || !Number.isInteger(c[k]) || c[k]! < 0)) {
      throw new CanonicalError(`canonical ${k} is not a whole number`);
    }
  }
  return c;
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
export interface Expectation {
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
  cmp("requesting_host", c.requesting_host, e.requesting_host);
  cmp("kind", c.kind, e.kind);
  cmp("target", c.target, e.target);
  cmp("login_user", c.login_user, e.login_user);
  cmp("key_fingerprint", c.key_fingerprint, e.key_fingerprint);
  if (e.object === "enrollment") cmp("replaces", c.replaces ?? false, e.replaces ?? false);
  if (e.action === "approve") {
    cmp("ttl_seconds", c.ttl_seconds ?? 0, e.ttl_seconds);
    cmp("standing_hours", c.standing_hours ?? 0, e.standing_hours ?? 0);
  } else {
    // Deny/revoke must not carry a standing approval.
    cmp("standing_hours", c.standing_hours ?? 0, 0);
  }
  return out;
}

/** A headline piece: our own words (string) or a value from canonical, rendered isolated
 * (<bdi>) so right-to-left text in one value can't reorder the rest of the sentence. */
export type Part = string | { value: string };

export interface Description {
  /** One sentence, e.g. "Approve SSH as alice@db-1 for 30 min, requested by build-box." */
  headline: string;
  headlineParts: Part[];
  /** Extra sentence for a standing approval, shown as a warning. */
  standing?: string;
  standingParts?: Part[];
  /** Things the owner must notice (replacing a host, unusual characters in names). */
  warnings: string[];
  /** Every canonical field, in the order the owner should read them. */
  fields: Array<[string, string]>;
}

const FIELD_LABELS: Record<string, string> = {
  action: "Action",
  object: "Applies to",
  kind: "Kind",
  login_user: "Log in as",
  target: "On host",
  requesting_host: "Requested by",
  ttl_seconds: "Access lasts",
  standing_hours: "Auto-approve similar",
  replaces: "Replaces existing host",
  key_fingerprint: "Key",
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

function who(c: Canonical): Part[] {
  return [{ value: c.login_user ?? "?" }, "@", { value: c.target ?? "?" }];
}

/** Describe the canonical action in plain words. Built only from canonical's own fields. */
export function describe(c: Canonical): Description {
  const kind = kindLabel(c.kind ?? "ssh");
  const host = c.requesting_host ?? "?";
  let headline: Part[];
  let standing: Part[] | undefined;
  const warnings: string[] = [];
  switch (`${c.object}:${c.action}`) {
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
      headline = ["Allow adding a new passkey to aqmas."];
      break;
    default:
      headline = t`${c.action} ${c.object} ${c.id}.`;
  }
  for (const [k, label] of [
    ["requesting_host", "requesting host"],
    ["target", "target host"],
    ["login_user", "login user"],
  ] as const) {
    if (c[k] !== undefined && !isPlainName(c[k])) warnings.push(`The ${label} name contains unusual characters: check it letter by letter.`);
  }
  const keys = Object.keys(c).sort((a, b) => {
    const ia = FIELD_ORDER.indexOf(a);
    const ib = FIELD_ORDER.indexOf(b);
    return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib) || a.localeCompare(b);
  });
  const fields: Array<[string, string]> = keys.map((k) => [FIELD_LABELS[k] ?? k, fieldValue(k, c[k])]);
  return {
    headline: partsText(headline),
    headlineParts: headline,
    standing: standing ? partsText(standing) : undefined,
    standingParts: standing,
    warnings,
    fields,
  };
}
