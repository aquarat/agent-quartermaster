// Activity log classification (pure, tested). Maps aqmasd's audit rows (actor, action,
// object, detail) to a kind of event (colour + glyph + words), the filter groups it belongs to,
// and the card it refers to. Every field of an audit row is shown as text only; nothing here
// builds DOM.

import type { AuditEntry } from "./types";
import { dayKey } from "./format";

/** Event kinds: each has a colour, a glyph and a text label in the UI (colour is never alone). */
export type EventKind = "approve" | "deny" | "revoke" | "request" | "auto" | "passkey" | "system" | "warning";

export type FilterGroup = "decisions" | "requests" | "passkeys" | "hosts";
export type Filter = "all" | FilterGroup;

export const FILTERS: ReadonlyArray<{ id: Filter; label: string }> = [
  { id: "all", label: "All" },
  { id: "decisions", label: "Decisions" },
  { id: "requests", label: "Requests" },
  { id: "passkeys", label: "Passkeys" },
  { id: "hosts", label: "Hosts" },
];

export interface EventInfo {
  kind: EventKind;
  /** Short words for the event, e.g. "Approved", "Passkey renamed". */
  label: string;
  groups: FilterGroup[];
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
};

/** Words for each kind, for screen readers and the legend. */
export const KIND_WORDS: Record<EventKind, string> = {
  approve: "approval",
  deny: "refusal",
  revoke: "revocation or expiry",
  request: "new request",
  auto: "auto-approval",
  passkey: "passkey",
  system: "system",
  warning: "warning",
};

export function classify(e: AuditEntry): EventInfo {
  const known = KNOWN[e.action];
  const info: EventInfo = known
    ? { ...known, groups: [...known.groups] }
    : { kind: /error|fail|warn/i.test(e.action) ? "warning" : "system", label: humanize(e.action), groups: [] };
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
  if (i < 0) return { type: o, id: "", short: TYPE_WORDS[o] ?? o };
  const type = o.slice(0, i);
  const id = o.slice(i + 1);
  const words = TYPE_WORDS[type] ?? type;
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
