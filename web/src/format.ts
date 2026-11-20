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
  return new Date(t).toLocaleString();
}

export function kindLabel(kind: string): string {
  if (kind === "ssh") return "SSH";
  if (kind === "enrollment") return "New host";
  return kind;
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
