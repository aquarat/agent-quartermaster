// Activity log classification (pure, tested). Maps aqmasd's audit rows (actor, action,
// object, detail) to a kind of event (colour + glyph + words), the filter groups it belongs to,
// and the card it refers to. Every field of an audit row is shown as text only; nothing here
// builds DOM.

import type { AuditEntry } from "./types";
import { own } from "./dom";
import { dayKey } from "./format";

/** Event kinds: each has a colour, a glyph and a text label in the UI (colour is never alone). */
export type EventKind = "approve" | "deny" | "revoke" | "request" | "auto" | "passkey" | "system" | "warning" | "cfwrite" | "token";

export type FilterGroup = "decisions" | "requests" | "passkeys" | "hosts" | "cloudflare";
export type Filter = "all" | FilterGroup;

export const FILTERS: ReadonlyArray<{ id: Filter; label: string }> = [
  { id: "all", label: "All" },
  { id: "decisions", label: "Decisions" },
  { id: "requests", label: "Requests" },
  { id: "passkeys", label: "Passkeys" },
  { id: "hosts", label: "Hosts" },
  { id: "cloudflare", label: "Cloudflare" },
];

export interface EventInfo {
  kind: EventKind;
  /** Short words for the event, e.g. "Approved", "Passkey renamed". */
  label: string;
  groups: FilterGroup[];
  /** About Cloudflare: the row also carries a cloud mark (decisions keep their own colour). */
  cloudflare?: true;
}

const KNOWN: Record<string, EventInfo> = {
  approve: { kind: "approve", label: "Approved", groups: ["decisions"] },
  deny: { kind: "deny", label: "Denied", groups: ["decisions"] },
  enroll_approve: { kind: "approve", label: "Host let in", groups: ["decisions", "hosts"] },
  enroll_deny: { kind: "deny", label: "Host refused", groups: ["decisions", "hosts"] },
  standing_create: { kind: "auto", label: "Auto-approval on", groups: ["decisions"] },
  auto_approve: { kind: "auto", label: "Auto-approved", groups: ["decisions", "requests"] },
  standing_revoke: { kind: "revoke", label: "Auto-approval off", groups: ["decisions"] },
  grant_revoke: { kind: "revoke", label: "Access revoked", groups: ["decisions"] },
  host_revoke: { kind: "revoke", label: "Host revoked", groups: ["hosts", "decisions"] },
  request: { kind: "request", label: "Requested", groups: ["requests"] },
  request_cancel: { kind: "revoke", label: "Withdrawn", groups: ["requests"] },
  enroll_request: { kind: "request", label: "Join request", groups: ["requests", "hosts"] },
  expire: { kind: "revoke", label: "Expired", groups: ["requests"] },
  login: { kind: "passkey", label: "Signed in", groups: ["passkeys"] },
  logout: { kind: "passkey", label: "Signed out", groups: ["passkeys"] },
  passkey_register: { kind: "passkey", label: "Passkey added", groups: ["passkeys"] },
  passkey_rename: { kind: "passkey", label: "Passkey renamed", groups: ["passkeys"] },
  passkey_remove: { kind: "passkey", label: "Passkey removed", groups: ["passkeys"] },
  passkey_enroll_code: { kind: "passkey", label: "Enroll code made", groups: ["passkeys"] },
  passkey_clone_warning: { kind: "warning", label: "Clone warning", groups: ["passkeys"] },
  // Credential sets and signing keys (API.md "Vault").
  vault_commit: { kind: "system", label: "Values saved", groups: ["decisions"] },
  vault_reveal: { kind: "warning", label: "Values revealed", groups: ["decisions"] },
  vault_policy: { kind: "system", label: "Reveal policy changed", groups: ["decisions"] },
  vault_signer_create: { kind: "passkey", label: "Signing key created", groups: ["decisions"] },
  vault_sign_approve: { kind: "approve", label: "Signing approved", groups: ["decisions"] },
  vault_sign_deny: { kind: "deny", label: "Signing denied", groups: ["decisions"] },
  vault_sign_revoke: { kind: "revoke", label: "Signing revoked", groups: ["decisions"] },
  sign_request: { kind: "request", label: "Signature requested", groups: ["requests"] },
  sign: { kind: "token", label: "Signed", groups: ["requests"] },
  env_request: { kind: "request", label: "Env values requested", groups: ["requests"] },
  env_approve: { kind: "approve", label: "Env release approved", groups: ["decisions"] },
  env_deny: { kind: "deny", label: "Env release denied", groups: ["decisions"] },
  env_revoke: { kind: "revoke", label: "Env release revoked", groups: ["decisions"] },
  env_commit: { kind: "system", label: "Values saved (CLI)", groups: ["decisions"] },
  env_collect_run: { kind: "token", label: "Values delivered", groups: ["requests"] },
  // Cloudflare (API.md 5.7): writes and token events have their own colours, refusals warn.
  cf_auto_approve: { kind: "auto", label: "Cloudflare auto-approved", groups: ["decisions", "requests", "cloudflare"], cloudflare: true },
  cf_write: { kind: "cfwrite", label: "Cloudflare write", groups: ["cloudflare"], cloudflare: true },
  cf_refused: { kind: "warning", label: "Cloudflare refused", groups: ["cloudflare"], cloudflare: true },
  cf_token_mint: { kind: "token", label: "Token minted", groups: ["cloudflare"], cloudflare: true },
  cf_token_delete: { kind: "token", label: "Token deleted", groups: ["cloudflare"], cloudflare: true },
  cf_token_orphan: { kind: "warning", label: "Stray token deleted", groups: ["cloudflare"], cloudflare: true },
};

// Decisions about Cloudflare objects: aqmasd's detail names "cloudflare <scope>" at a fixed
// place (anchored, so host-sent text later in a detail can't make an SSH row look like one).
const CF = "cloudflare cf\\.[a-z0-9.-]+(?: |$)";
const CF_DETAIL: Record<string, RegExp> = {
  approve: new RegExp(`^grant=\\S+ ${CF}`),
  auto_approve: new RegExp(`^standing=\\S+ grant=\\S+ host=\\S+ ${CF}`),
  standing_create: new RegExp(`^host=\\S+ ${CF}`),
  grant_revoke: new RegExp(`^${CF}`),
  request: new RegExp(`^${CF}`),
  deny: new RegExp(`^${CF}`),
  standing_revoke: new RegExp(`^host=\\S+ ${CF}`),
};
const CF_DECISION_LABELS: Record<string, string> = {
  approve: "Cloudflare approved",
  auto_approve: "Cloudflare auto-approved",
  standing_create: "Cloudflare auto-approval on",
  grant_revoke: "Cloudflare access revoked",
  request: "Cloudflare requested",
  deny: "Cloudflare denied",
  standing_revoke: "Cloudflare auto-approval off",
};

/** Is this row about Cloudflare? */
export function isCloudflare(e: AuditEntry): boolean {
  if (e.action.startsWith("cf_")) return true;
  const re = own(CF_DETAIL, e.action);
  return re !== undefined && re.test(e.detail ?? "");
}

export function classify(e: AuditEntry): EventInfo {
  const known = own(KNOWN, e.action);
  const info: EventInfo = known
    ? { ...known, groups: [...known.groups] }
    : { kind: /error|fail|warn|refused|orphan/i.test(e.action) ? "warning" : "system", label: humanize(e.action), groups: [] };
  if (isCloudflare(e)) {
    info.cloudflare = true;
    if (!known?.cloudflare) info.label = own(CF_DECISION_LABELS, e.action) ?? `Cloudflare: ${info.label}`;
    if (!info.groups.includes("cloudflare")) info.groups.push("cloudflare");
  }
  // Anything a host did, or that is about a host or enrollment, also counts as "hosts".
  if ((e.actor.startsWith("host:") || /^(host|enrollment):/.test(e.object)) && !info.groups.includes("hosts")) info.groups.push("hosts");
  return info;
}

function humanize(action: string): string {
  const s = action.replace(/_/g, " ").trim();
  return s ? s[0]!.toUpperCase() + s.slice(1) : "Event";
}

export function matches(e: AuditEntry, f: Filter): boolean {
  return f === "all" || classify(e).groups.includes(f);
}

export interface Actor {
  kind: "owner" | "host" | "system" | "other";
  /** Text for the chip: "owner", the host name, "system", or the raw actor. */
  name: string;
}

export function actor(a: string): Actor {
  if (a === "owner") return { kind: "owner", name: "owner" };
  if (a === "system") return { kind: "system", name: "system" };
  if (a.startsWith("host:") && a.length > 5) return { kind: "host", name: a.slice(5) };
  return { kind: "other", name: a };
}

export interface ObjectRef {
  /** "request", "grant", "standing", "enrollment", "passkey", "host", ... ("" when no colon). */
  type: string;
  id: string;
  /** Short words: "request ABC123", "host db-1", "passkey 3F2A1B". */
  short: string;
}

const TYPE_WORDS: Record<string, string> = {
  request: "request",
  grant: "access",
  standing: "auto-approval",
  enrollment: "enrollment",
  passkey: "passkey",
  host: "host",
  enroll_code: "enroll code",
};

export function objectRef(o: string): ObjectRef {
  const i = o.indexOf(":");
  if (i < 0) return { type: o, id: "", short: own(TYPE_WORDS, o) ?? o };
  const type = o.slice(0, i);
  const id = o.slice(i + 1);
  const words = own(TYPE_WORDS, type) ?? type;
  // Hosts are named; everything else gets the same short Ref the cards show.
  const short = type === "host" || id.length <= 8 ? `${words} ${id}` : `${words} ${id.slice(-6).toUpperCase()}`;
  return { type, id, short };
}

/** Does the detail text carry requester-influenced strings (host names, enroll notes...)? */
export function detailUntrusted(e: AuditEntry): boolean {
  if (!e.detail) return false;
  return e.actor.startsWith("host:") || /^(request|enrollment|host|grant|standing):/.test(e.object) || e.action === "enroll_request";
}

export interface DayGroup {
  key: string;
  /** Timestamp (ms) of the first row, for the label. */
  at: number;
  entries: AuditEntry[];
}

/** Group rows (newest first, as the server sends them) by local day, keeping their order. */
export function groupByDay(entries: AuditEntry[]): DayGroup[] {
  const out: DayGroup[] = [];
  for (const e of entries) {
    const t = new Date(e.at).getTime();
    const key = dayKey(t);
    const last = out.at(-1);
    if (last && last.key === key) last.entries.push(e);
    else out.push({ key, at: t, entries: [e] });
  }
  return out;
}

/** Stable identity for a row (expanded state survives re-renders). */
export function rowKey(e: AuditEntry): string {
  return `${e.at}|${e.actor}|${e.action}|${e.object}`;
}
