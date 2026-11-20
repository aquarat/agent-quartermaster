// The approval page's OWN description of every built-in Cloudflare scope (docs/CLOUDFLARE.md
// section 2, Go: internal/server/cfscope/catalogue.go). The page describes what it signs from
// this table and the canonical text only; the server's title/description/permissions/notes are
// shown on the card as a supplement, never instead. A scope missing here cannot be signed.
//
// Keep in step with the Go catalogue: names, parameter keys (and which are required), closed
// value sets, risk, built-in maximum TTL, whether standing approvals and token mode exist.

import type { Part } from "./canonical";

export type CFRisk = "low" | "medium" | "high" | "admin";
export const CF_RISKS: readonly CFRisk[] = ["low", "medium", "high", "admin"];

export type CFMode = "proxy" | "token";

const HOUR = 3600;

/** Ruleset phases cf.rulesets may write (Go: cfscope.AllowedPhases). */
export const CF_PHASES = [
  "http_ratelimit",
  "http_request_cache_settings",
  "http_request_dynamic_redirect",
  "http_request_firewall_custom",
  "http_request_late_transform",
  "http_request_transform",
] as const;

// Value shapes the Go side accepts (catalogue.go / config/cloudflare.go). A value outside its
// shape is shown with a warning (the server is the authority on what exists).
const CF_NAME_RE = /^[a-z0-9][a-z0-9.-]{0,252}$/; // configured zone/tunnel/db names
const SCRIPT_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const PROJECT_RE = /^[a-z0-9][a-z0-9-]{0,57}$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
const GLOB_RE = /^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))+$/;

export interface CFParamDesc {
  key: string;
  /** Label on cards and the confirmation, e.g. "Zone". */
  label: string;
  required: boolean;
  /** Closed set: any other value is refused. */
  values?: readonly string[];
  /** Expected shape: a value outside it gets an "unusual characters" warning. */
  shape?: RegExp;
}

export interface CFScopeDesc {
  name: string;
  risk: CFRisk;
  /** Built-in maximum grant length (config can only lower it). */
  maxTTL: number;
  /** "Approve similar for N hours" can exist (proxy mode only). */
  standing: boolean;
  /** A child-token template exists (mode "token" possible). */
  token: boolean;
  params: CFParamDesc[];
  /** What the grant lets the host do, as the rest of a sentence ("edit DNS records in zone …").
   * Values come in as parts so they are rendered isolated. */
  phrase(p: Record<string, string>): Part[];
  can: string[];
  cannot: string[];
  /** Token mode: what the child token can do beyond the scope (the page's own words). */
  tokenNote?: (p: Record<string, string>) => string;
}

const zone: CFParamDesc = { key: "zone", label: "Zone", required: true, shape: CF_NAME_RE };
const optZone: CFParamDesc = { ...zone, required: false };

const v = (s: string | undefined): Part => ({ value: s ?? "?" });

const SCOPES: CFScopeDesc[] = [
  {
    name: "cf.read",
    risk: "low",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [],
    phrase: () => ["read the Cloudflare configuration (allow-listed reads only)"],
    can: ["Read tunnels and their routes, Access apps, policies and groups, zones, DNS records, rulesets, zone settings, and Workers/Pages/R2/D1 metadata."],
    cannot: ["Change anything.", "Read secrets, tokens, personal data (Access logs, users) or object data."],
  },
  {
    name: "cf.read.private",
    risk: "high",
    maxTTL: 2 * HOUR,
    standing: false,
    token: false,
    params: [],
    phrase: () => ["read personal data in Cloudflare (Access logs and users, identity providers, email addresses, audit logs)"],
    can: ["Read Access request logs and users (household emails, IP addresses), identity provider settings, email routing addresses, full Pages project and Worker settings, the account audit log."],
    cannot: ["Change anything.", "Read API tokens or tunnel run tokens."],
  },
  {
    name: "cf.dns.edit",
    risk: "high",
    maxTTL: 8 * HOUR,
    standing: true,
    token: true,
    params: [zone, { key: "name", label: "Only DNS names", required: false, shape: GLOB_RE }],
    phrase: (p) => {
      const out: Part[] = ["edit DNS records in zone ", v(p["zone"])];
      const n = p["name"];
      if (n) out.push(n.startsWith("*.") ? " (only names matching " : " (only the name ", { value: n }, ")");
      return out;
    },
    can: ["Create, change and delete DNS records in this zone (only the matching names, when a name is given)."],
    cannot: ["Touch the zone apex, MX/NS/SOA/CAA records, SPF/DKIM/DMARC, ACME challenges or protected names (guard rail).", "Touch other zones."],
    tokenNote: (p) =>
      (p["name"] ? "Cloudflare cannot limit a token to a name pattern: this token can change EVERY record in the zone. " : "") +
      "A token bypasses aqmas's guard rails and snapshots.",
  },
  {
    name: "cf.tunnel.config",
    risk: "high",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [{ key: "tunnel", label: "Tunnel", required: true, shape: CF_NAME_RE }],
    phrase: (p) => ["replace the routes (ingress config) of tunnel ", v(p["tunnel"])],
    can: ["Read and replace the whole ingress config of this tunnel: which hostnames the internet reaches and where they go. aqmas snapshots it first."],
    cannot: ["Create, delete or re-key tunnels, or read a tunnel's run token.", "Write rules the guard rails refuse (missing catch-all, Traefik without SNI, removing an Access check)."],
  },
  {
    name: "cf.access.apps",
    risk: "high",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [],
    phrase: () => ["create, change and delete Cloudflare Access apps"],
    can: ["Create, change and delete Access applications (who may reach which hostname) and their app-level policies."],
    cannot: ["Put an app on aqmasd's protected hostnames.", "Change login methods or the Access organization."],
  },
  {
    name: "cf.access.policies",
    risk: "high",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [],
    phrase: () => ["create, change and delete Cloudflare Access policies and groups"],
    can: ["Create, change and delete reusable Access policies and groups."],
    cannot: ["Change a policy or group shared by several apps (guard rail).", "Change login methods."],
  },
  {
    name: "cf.access.idp-org",
    risk: "high",
    maxTTL: 2 * HOUR,
    standing: false,
    token: false,
    params: [],
    phrase: () => ["change Cloudflare Access login methods (identity providers and organization settings)"],
    can: ["Change identity providers (OIDC IdP, GitHub, PIN) and the Access organization settings. This affects every login."],
    cannot: ["Delete an identity provider (guard rail)."],
  },
  {
    name: "cf.rulesets",
    risk: "high",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [zone, { key: "phase", label: "Only phase", required: false, values: CF_PHASES }],
    phrase: (p) => {
      const out: Part[] = ["add and change rules (WAF, rate limits, redirects, cache, transforms) in zone ", v(p["zone"])];
      if (p["phase"]) out.push(" (only phase ", { value: p["phase"] }, ")");
      return out;
    },
    can: ["Add and change WAF custom rules, rate limits, redirects, cache and transform rules in this zone (only the given phase, when set)."],
    cannot: ["Replace a whole ruleset or drop existing rules (guard rail).", "Touch other zones or other phases."],
  },
  {
    name: "cf.zone-settings",
    risk: "medium",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [zone],
    phrase: (p) => ["change the settings of zone ", v(p["zone"])],
    can: ["Change zone settings such as TLS and HTTPS options in this zone."],
    cannot: ["Turn off Always Use HTTPS, lower TLS below 1.2, set SSL other than strict, or widen HSTS (guard rail)."],
  },
  {
    name: "cf.cache.purge",
    risk: "low",
    maxTTL: 8 * HOUR,
    standing: true,
    token: true,
    params: [zone],
    phrase: (p) => ["purge listed URLs from the cache of zone ", v(p["zone"])],
    can: ["Purge up to 30 listed URLs at a time from this zone's cache."],
    cannot: ["Purge everything.", "Change any setting."],
    tokenNote: () => "A token can also purge EVERYTHING in the zone's cache.",
  },
  {
    name: "cf.workers.deploy",
    risk: "medium",
    maxTTL: 8 * HOUR,
    standing: true,
    token: true,
    params: [{ key: "script", label: "Worker", required: true, shape: SCRIPT_RE }, optZone],
    phrase: (p) => {
      const out: Part[] = ["deploy the Worker ", v(p["script"])];
      if (p["zone"]) out.push(" (with routes and custom domains in zone ", { value: p["zone"] }, ")");
      else out.push(" (no routes or custom domains)");
      return out;
    },
    can: ["Upload and deploy this Worker with its assets, secrets and cron triggers; routes and custom domains only in the given zone."],
    cannot: ["Read the Worker's source or tail its logs.", "Deploy other Workers (through the proxy).", "Remove custom domains (guard rail)."],
    tokenNote: () => "Cloudflare cannot limit a token to one script: this token can deploy or delete ANY Worker on the account until it expires.",
  },
  {
    name: "cf.pages",
    risk: "medium",
    maxTTL: 8 * HOUR,
    standing: true,
    token: true,
    params: [{ key: "project", label: "Pages project", required: true, shape: PROJECT_RE }],
    phrase: (p) => ["deploy the Pages project ", v(p["project"])],
    can: ["Upload deployments, roll back, and manage custom domains of this Pages project."],
    cannot: ["Touch other Pages projects (through the proxy)."],
    tokenNote: () => "Cloudflare cannot limit a token to one project: this token works on ANY Pages project on the account.",
  },
  {
    name: "cf.d1",
    risk: "medium",
    maxTTL: 8 * HOUR,
    standing: true,
    token: true,
    params: [
      { key: "db", label: "D1 database", required: true, shape: CF_NAME_RE },
      { key: "access", label: "Access", required: true, values: ["read", "migrate"] },
    ],
    phrase: (p) =>
      p["access"] === "migrate"
        ? ["run ANY SQL, including schema changes and data edits, on D1 database ", v(p["db"])]
        : ["run read-only queries on D1 database ", v(p["db"])],
    can: ["access=read: SELECT, EXPLAIN and read-only PRAGMA. access=migrate: any SQL, including schema changes, inserts and deletes."],
    cannot: ["Export the database.", "Reach other D1 databases (through the proxy)."],
    tokenNote: () => "Cloudflare cannot limit a token to one database: this token reaches EVERY D1 database on the account, and its SQL is not checked.",
  },
  {
    name: "cf.r2.admin",
    risk: "medium",
    maxTTL: 8 * HOUR,
    standing: true,
    token: false,
    params: [],
    phrase: () => ["manage R2 buckets (create buckets, CORS, lifecycle, custom domains; no object data)"],
    can: ["List and create R2 buckets; change bucket CORS, lifecycle rules and custom domains."],
    cannot: ["Read or write objects.", "Create temporary S3 credentials."],
  },
  {
    name: "cf.r2.objects",
    risk: "medium",
    maxTTL: 8 * HOUR,
    standing: true,
    token: true,
    params: [
      { key: "bucket", label: "R2 bucket", required: true, shape: BUCKET_RE },
      { key: "access", label: "Access", required: true, values: ["read", "write"] },
    ],
    phrase: (p) =>
      p["access"] === "write"
        ? ["read, upload and delete objects in R2 bucket ", v(p["bucket"])]
        : ["list and download objects in R2 bucket ", v(p["bucket"])],
    can: ["access=read: list and download objects. access=write: also upload and delete them."],
    cannot: ["Change bucket settings.", "Reach other buckets (through the proxy)."],
    tokenNote: () => "Cloudflare cannot limit this token to one bucket: it reaches EVERY R2 bucket on the account.",
  },
  {
    name: "cf.email",
    risk: "high",
    maxTTL: 8 * HOUR,
    standing: false,
    token: false,
    params: [zone],
    phrase: (p) => ["change email routing and sending for zone ", v(p["zone"])],
    can: ["Change email routing rules and their DNS in this zone, destination addresses, and email sending subdomains."],
    cannot: ["Touch other zones' email routing.", "Forward mail to an address not in aqmasd's email_forward_allow."],
  },
  {
    name: "cf.admin",
    risk: "admin",
    maxTTL: 1 * HOUR,
    standing: false,
    token: false,
    params: [],
    phrase: () => ["use the WHOLE Cloudflare account (break-glass: everything except the deny-list)"],
    can: ["Any Cloudflare API call on any zone, tunnel, Worker or app, including ones aqmas does not know.", "Override guard rails per call (each override is audited and pushed)."],
    cannot: ["Anything on the deny-list: API tokens, account members, tunnel run tokens, billing, certificates, other accounts.", "Last longer than 1 hour, or be auto-approved."],
  },
];

const BY_NAME = new Map(SCOPES.map((s) => [s.name, s]));

/** The page's own description of a scope, or undefined (the page then refuses to sign). */
export function cfScope(name: string | undefined): CFScopeDesc | undefined {
  return name === undefined ? undefined : BY_NAME.get(name);
}

export function cfScopeNames(): string[] {
  return SCOPES.map((s) => s.name);
}

export class ScopeParamsError extends Error {
  override name = "ScopeParamsError";
}

/** Parse canonical scope_params ("k=v;k=v", keys sorted bytewise, no duplicates, no empty
 * key or value, values without ";" or "="; "" = none). Throws ScopeParamsError. */
export function parseScopeParams(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (s === "") return out;
  let prev: string | null = null;
  for (const part of s.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) throw new ScopeParamsError(`malformed scope_params ${JSON.stringify(s)}`);
    const k = part.slice(0, eq);
    const val = part.slice(eq + 1);
    if (val === "") throw new ScopeParamsError(`scope_params has an empty value for ${JSON.stringify(k)}`);
    if (val.includes("=")) throw new ScopeParamsError(`scope_params value for ${JSON.stringify(k)} contains "="`);
    if (!/^[a-z]{1,32}$/.test(k)) throw new ScopeParamsError(`scope_params has an unexpected key ${JSON.stringify(k)}`);
    if (prev !== null && !(prev < k)) throw new ScopeParamsError(`scope_params keys are not sorted or repeat (${JSON.stringify(s)})`);
    prev = k;
    out[k] = val;
  }
  return out;
}

/** The canonical form (inverse of parseScopeParams). */
export function formatScopeParams(p: Record<string, string>): string {
  return Object.keys(p)
    .filter((k) => p[k] !== "")
    .sort()
    .map((k) => `${k}=${p[k]}`)
    .join(";");
}

/** Problems that make the parameters unsignable for this scope (unknown or missing keys,
 * values outside a closed set, a DNS name outside the zone). Empty = fine. */
export function paramProblems(scope: CFScopeDesc, p: Record<string, string>): string[] {
  const out: string[] = [];
  const known = new Set(scope.params.map((x) => x.key));
  for (const k of Object.keys(p)) if (!known.has(k)) out.push(`${scope.name} takes no parameter ${JSON.stringify(k)}`);
  for (const d of scope.params) {
    const val = p[d.key];
    if (val === undefined) {
      if (d.required) out.push(`${scope.name} needs parameter ${d.key}`);
      continue;
    }
    if (d.values && !d.values.includes(val)) out.push(`${d.key} must be one of ${d.values.join(", ")}`);
  }
  const glob = p["name"];
  if (glob !== undefined && p["zone"] !== undefined) {
    const base = glob.startsWith("*.") ? glob.slice(2) : glob;
    const z = p["zone"];
    if (base !== z && !base.endsWith("." + z)) out.push(`name ${JSON.stringify(glob)} is not inside zone ${JSON.stringify(z)}`);
  }
  return out;
}

/** Labels of parameter values whose characters are outside their usual shape. */
export function unusualParams(scope: CFScopeDesc, p: Record<string, string>): string[] {
  const out: string[] = [];
  for (const d of scope.params) {
    const val = p[d.key];
    if (val !== undefined && d.shape && !d.shape.test(val)) out.push(d.label);
  }
  return out;
}

/** Parameters as labelled pairs, in the scope's own order. */
export function paramPairs(scope: CFScopeDesc | undefined, p: Record<string, string>): Array<[string, string]> {
  if (!scope) return Object.keys(p).sort().map((k) => [k, p[k]!]);
  return scope.params.filter((d) => p[d.key] !== undefined).map((d) => [d.label, p[d.key]!]);
}

export const CIDR_RE = /^(?:(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|[0-9a-f:]{2,39}\/\d{1,3})$/;

/** Parse an ip_condition ("cidr,cidr", sorted bytewise, no duplicates). Throws ScopeParamsError. */
export function parseIPCondition(s: string): string[] {
  if (s === "") return [];
  const parts = s.split(",");
  for (let i = 0; i < parts.length; i++) {
    if (!CIDR_RE.test(parts[i]!)) throw new ScopeParamsError(`ip_condition entry ${JSON.stringify(parts[i])} is not a CIDR`);
    if (i > 0 && !(parts[i - 1]! < parts[i]!)) throw new ScopeParamsError("ip_condition is not sorted or repeats an entry");
  }
  return parts;
}

/** CIDRs wider than a single address. */
export function wideCIDRs(cidrs: string[]): string[] {
  return cidrs.filter((c) => {
    const bits = Number(c.split("/")[1]);
    return c.includes(":") ? bits < 128 : bits < 32;
  });
}

export function riskLabel(r: string): string {
  switch (r) {
    case "low":
      return "Low risk";
    case "medium":
      return "Medium risk";
    case "high":
      return "High risk";
    case "admin":
      return "Break-glass";
    default:
      return `Risk: ${r}`;
  }
}

/** Capitalise the first word of a phrase (for card headings). */
export function sentenceCase(parts: Part[]): Part[] {
  const [first, ...rest] = parts;
  if (typeof first === "string" && first.length) return [first[0]!.toUpperCase() + first.slice(1), ...rest];
  return parts;
}
