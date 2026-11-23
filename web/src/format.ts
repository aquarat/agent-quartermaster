// Small formatting helpers (pure, tested).

/** 1800 -> "30 min", 3600 -> "1 hour", 5400 -> "1 h 30 min", 28800 -> "8 hours". */
export function duration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "?";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const totalMin = Math.round(seconds / 60);
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h === 0) return `${m} min`;
  if (m === 0) return h === 1 ? "1 hour" : `${h} hours`;
  return `${h} h ${m} min`;
}

export function hours(n: number): string {
  return n === 1 ? "1 hour" : `${n} hours`;
}

/** Countdown to `target`: "4:05", "1 h 12 min", or "expired". */
export function countdown(target: string | number | Date, now = Date.now()): string {
  const t = typeof target === "number" ? target : new Date(target).getTime();
  if (!Number.isFinite(t)) return "?";
  const s = Math.floor((t - now) / 1000);
  if (s <= 0) return "expired";
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m}:${String(r).padStart(2, "0")}`;
  }
  return duration(s);
}

/** "12 s ago", "5 min ago", "3 h ago", or a date. */
export function ago(at: string | number | Date, now = Date.now()): string {
  const t = typeof at === "number" ? at : new Date(at).getTime();
  if (!Number.isFinite(t)) return "?";
  const s = Math.max(0, Math.floor((now - t) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 7 * 86400) return Math.floor(s / 86400) === 1 ? "1 day ago" : `${Math.floor(s / 86400)} days ago`;
  return new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

export function kindLabel(kind: string): string {
  if (kind === "ssh") return "SSH";
  if (kind === "enrollment") return "New host";
  if (kind === "cloudflare") return "Cloudflare";
  if (kind === "bastion") return "Bastion";
  if (kind === "setup") return "Maintenance";
  return kind;
}

const AUDIT_LABELS: Record<string, string> = {
  cf_auto_approve: "auto-approved Cloudflare",
  cf_write: "Cloudflare write",
  cf_refused: "Cloudflare call refused",
  cf_token_mint: "Cloudflare token minted",
  cf_token_delete: "Cloudflare token deleted",
  cf_token_orphan: "stray Cloudflare token deleted",
  passkey_remember_browser: "browser remembered for a passkey",
  passkey_forget_browser: "remembered browser forgotten",
};

/** Plain words for an audit action (unknown ones are shown as they are). */
export function auditLabel(action: string): string {
  return AUDIT_LABELS[action] ?? action;
}

export const TTL_PRESETS = [900, 1800, 3600, 14400, 28800];
export const STANDING_PRESETS = [0, 1, 4, 8];

/** TTL choices for an item: presets up to ttl_max, plus the requested value (clamped) if it
 * isn't a preset. Returns the options and the default (requested, clamped). */
export function ttlChoices(requested: number, max: number): { options: number[]; def: number } {
  const cap = max > 0 ? max : Math.max(...TTL_PRESETS);
  const options = TTL_PRESETS.filter((t) => t <= cap);
  let def = requested > 0 ? Math.min(requested, cap) : Math.min(1800, cap);
  if (options.length === 0) options.push(cap);
  if (!options.includes(def)) {
    options.push(def);
    options.sort((a, b) => a - b);
  }
  return { options, def };
}

// Invisible and direction-changing characters (bidi overrides/isolates, zero-width, BOM, tag
// characters, variation selectors, private use, control characters other than tab/newline).
// Untrusted text could use them to make what is displayed differ from what it is, so they are
// shown as visible <U+XXXX> markers instead. Runs of combining marks (which can draw over
// neighbouring text) are cut to two.
const INVISIBLE = /(?![\n\t])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFE00-\uFE0F\uFFA0\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;
const MARK_RUN = /(\p{M}{2})\p{M}+/gu;

export function visibleText(s: unknown): string {
  const str = typeof s === "string" ? s : s === undefined || s === null ? "" : String(s);
  return str
    .replace(INVISIBLE, (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`)
    .replace(MARK_RUN, "$1⟨…⟩");
}

/** Host and user names as aqmas issues them: ASCII letters, digits, dot, dash, underscore.
 * Anything else (look-alike letters, RTL text) gets a visible warning. */
export function isPlainName(s: unknown): boolean {
  return typeof s === "string" && /^[A-Za-z0-9._-]{1,253}$/.test(s);
}

// ---- dates for the activity log ----

const DAY_MS = 86_400_000;

function localMidnight(t: number): number {
  const d = new Date(t);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** Local calendar day of `t` as "YYYY-MM-DD" (group key). */
export function dayKey(at: string | number | Date): string {
  const d = new Date(typeof at === "number" ? at : new Date(at).getTime());
  if (!Number.isFinite(d.getTime())) return "?";
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** "Today", "Yesterday", "Monday 18 November" (this year) or "18 November 2025". */
export function dayLabel(at: string | number | Date, now = Date.now()): string {
  const t = typeof at === "number" ? at : new Date(at).getTime();
  if (!Number.isFinite(t)) return "Unknown date";
  const days = Math.round((localMidnight(now) - localMidnight(t)) / DAY_MS);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  const d = new Date(t);
  const sameYear = d.getFullYear() === new Date(now).getFullYear();
  return d.toLocaleDateString("en-GB", sameYear && days > 0 && days < 7 ? { weekday: "long", day: "numeric", month: "long" } : sameYear ? { day: "numeric", month: "long" } : { day: "numeric", month: "long", year: "numeric" });
}

/** "14:05" in local time. */
export function clockTime(at: string | number | Date): string {
  const t = typeof at === "number" ? at : new Date(at).getTime();
  if (!Number.isFinite(t)) return "?";
  return new Date(t).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

/** Full local date and time, for hover titles: "Wed 20 Nov 2026, 14:05:09". */
export function absoluteTime(at: string | number | Date): string {
  const t = typeof at === "number" ? at : new Date(at).getTime();
  if (!Number.isFinite(t)) return "?";
  return new Date(t).toLocaleString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** Activity row time: relative within the last 12 hours, else the clock time (the day
 * header carries the date). */
export function eventTime(at: string | number | Date, now = Date.now()): string {
  const t = typeof at === "number" ? at : new Date(at).getTime();
  if (!Number.isFinite(t)) return "?";
  return now - t < 12 * 3600_000 ? ago(t, now) : clockTime(t);
}

/** "1 Nov 2026" style short date. */
export function shortDate(at: string | number | Date): string {
  const t = typeof at === "number" ? at : new Date(at).getTime();
  if (!Number.isFinite(t)) return "?";
  return new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}
