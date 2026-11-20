// Kind "cloudflare" (API.md 5.4/5.7): canonical key sets, refusals, plain-words descriptions,
// mismatches, and the flows against the mock. Also a drift check against the Go catalogue.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ApiError, createApi, type Api } from "../src/api";
import { encode } from "../src/b64url";
import { CanonicalError, describe as describeAction, mismatches, parseCanonical, partsText } from "../src/canonical";
import { cfScope, cfScopeNames, formatScopeParams, parseScopeParams, ScopeParamsError } from "../src/cfscopes";
import { FlowError, completeAction, completeLogin, prepareAction, prepareLogin, targetForGrant, targetForPending, targetForStanding } from "../src/flows";
import { canonicalJSON, mockPendingCloudflare, startMock } from "../mock/server";
import type { ChallengeResponse } from "../src/types";
import { fakeAuth, jarFetch } from "./helpers";

const req = {
  v: 1,
  action: "approve",
  object: "request",
  id: "01JCF",
  requesting_host: "agenthost",
  kind: "cloudflare",
  scope: "cf.dns.edit",
  scope_params: "name=*.example.net;zone=example.net",
  mode: "proxy",
  ip_condition: "",
  ttl_seconds: 7200,
  standing_hours: 0,
  nonce: "bm9uY2U",
  issued_at: "2026-11-20T10:00:00Z",
};
const grant = {
  v: 1,
  action: "revoke",
  object: "grant",
  id: "g1",
  requesting_host: "agenthost",
  kind: "cloudflare",
  scope: "cf.read",
  scope_params: "",
  mode: "proxy",
  ttl_seconds: 0,
  standing_hours: 0,
  nonce: "n",
  issued_at: "t",
};
const standing = { ...grant, object: "standing", id: "s1", scope: "cf.dns.edit", scope_params: "zone=example.net", ttl_seconds: 7200 };
const token = { ...req, scope: "cf.workers.deploy", scope_params: "script=shopfront-api;zone=example.net", mode: "token", ip_condition: "203.0.113.7/32" };

const parse = (o: Record<string, unknown>) => parseCanonical(canonicalJSON(o));
const without = (o: Record<string, unknown>, k: string) => Object.fromEntries(Object.entries(o).filter(([x]) => x !== k));

describe("cloudflare canonical: key sets", () => {
  test("request, standing and grant round-trip", () => {
    for (const o of [req, standing, grant, token, { ...req, action: "deny", ttl_seconds: 0 }]) {
      const text = canonicalJSON(o);
      const c = parseCanonical(text);
      expect(canonicalJSON(c)).toBe(text);
      expect(c.scope).toBe(o.scope);
    }
  });

  test("every key is required, no extra key is allowed", () => {
    for (const k of Object.keys(req)) {
      if (["v", "action", "object", "id"].includes(k)) continue;
      expect(() => parse(without(req, k))).toThrow(CanonicalError);
    }
    expect(() => parse(without(req, "ip_condition"))).toThrow(/lacks ip_condition/);
    expect(() => parse(without(grant, "scope_params"))).toThrow(/lacks scope_params/);
    expect(() => parse({ ...req, extra: "x" })).toThrow(/extra/);
    expect(() => parse({ ...grant, ip_condition: "" })).toThrow(/ip_condition/); // request only
    expect(() => parse({ ...standing, ip_condition: "" })).toThrow(/ip_condition/);
  });

  test("the key set is picked by (object, kind): no mixing SSH and Cloudflare fields", () => {
    // Cloudflare kind with SSH fields.
    const sshShaped = { ...without(without(without(without(req, "scope"), "scope_params"), "mode"), "ip_condition"), target: "db-1", login_user: "root", key_fingerprint: "SHA256:x" };
    expect(() => parse(sshShaped)).toThrow(/target|login_user|key_fingerprint/);
    expect(() => parse({ ...req, target: "db-1" })).toThrow(/target/);
    // SSH kind with Cloudflare fields.
    expect(() => parse({ ...req, kind: "ssh" })).toThrow(/scope/);
    // Enrollment and passkey never take them.
    expect(() => parse({ v: 1, action: "approve", object: "enrollment", id: "e", kind: "cloudflare", scope: "cf.read" })).toThrow(/scope/);
    expect(() => parse({ v: 1, action: "add", object: "passkey", id: "new", kind: "cloudflare" })).toThrow(/kind/);
  });

  test("unknown scope is refused", () => {
    expect(() => parse({ ...req, scope: "cf.everything", scope_params: "" })).toThrow(/no description of Cloudflare scope "cf.everything"/);
    expect(() => parse({ ...grant, scope: "CF.READ" })).toThrow(/no description/);
  });

  test("malformed scope_params are refused", () => {
    for (const sp of [
      "zone=",
      "zone",
      "=example.net",
      "zone=example.net;",
      ";zone=example.net",
      "zone=example.net;name=*.example.net", // unsorted
      "zone=a.co.uk;zone=a.co.uk", // duplicate
      "zone=a=b",
      "Zone=example.net",
      " zone=example.net",
    ]) {
      expect(() => parse({ ...req, scope_params: sp })).toThrow(CanonicalError);
    }
    expect(() => parse({ ...req, scope_params: "" })).toThrow(/needs parameter zone/);
    expect(() => parse({ ...req, scope_params: "foo=bar;zone=example.net" })).toThrow(/takes no parameter "foo"/);
    expect(() => parse({ ...req, scope_params: "name=*.example.com;zone=example.net" })).toThrow(/not inside zone/);
    expect(() => parse({ ...req, scope_params: "name=evilexample.net;zone=example.net" })).toThrow(/not inside zone/);
    expect(() => parse({ ...req, scope: "cf.d1", scope_params: "access=write;db=billing" })).toThrow(/access must be one of read, migrate/);
    expect(() => parse({ ...req, scope: "cf.rulesets", scope_params: "phase=http_request_origin;zone=example.net" })).toThrow(/phase/);
    expect(() => parse({ ...grant, scope: "cf.read", scope_params: "zone=example.net" })).toThrow(/takes no parameter/);
  });

  test("parseScopeParams / formatScopeParams", () => {
    expect(parseScopeParams("")).toEqual({});
    expect(parseScopeParams("name=*.example.net;zone=example.net")).toEqual({ name: "*.example.net", zone: "example.net" });
    expect(formatScopeParams({ zone: "example.net", name: "*.example.net" })).toBe("name=*.example.net;zone=example.net");
    expect(() => parseScopeParams("b=1;a=2")).toThrow(ScopeParamsError);
  });

  test("standing_hours only on a proxy approval of a scope that allows it", () => {
    expect(parse({ ...req, standing_hours: 4 }).standing_hours).toBe(4);
    expect(() => parse({ ...req, scope: "cf.admin", scope_params: "", ttl_seconds: 3600, standing_hours: 1 })).toThrow(/never allows auto-approval/);
    expect(() => parse({ ...req, scope: "cf.read.private", scope_params: "", ttl_seconds: 3600, standing_hours: 1 })).toThrow(/never allows/);
    expect(() => parse({ ...token, standing_hours: 1 })).toThrow(/token grants are never auto-approved/);
    expect(() => parse({ ...req, action: "deny", standing_hours: 1 })).toThrow(/only an approval/);
    expect(() => parse({ ...grant, standing_hours: 1 })).toThrow(/only an approval/);
  });

  test("mode and ip_condition must agree", () => {
    expect(() => parse({ ...req, ip_condition: "203.0.113.7/32" })).toThrow(/empty in proxy mode/);
    expect(() => parse({ ...token, ip_condition: "" })).toThrow(/must carry an ip_condition/);
    expect(() => parse({ ...token, ip_condition: "203.0.113.9/32,203.0.113.7/32" })).toThrow(/not sorted/);
    expect(() => parse({ ...token, ip_condition: "203.0.113.7/32,203.0.113.7/32" })).toThrow(/not sorted or repeats/);
    expect(() => parse({ ...token, ip_condition: "anywhere" })).toThrow(/not a CIDR/);
    expect(() => parse({ ...token, ip_condition: "203.0.113.7/32, 198.51.100.0/24" })).toThrow(/not a CIDR/);
    expect(parse({ ...token, ip_condition: "198.51.100.0/24,203.0.113.7/32" }).ip_condition).toBe("198.51.100.0/24,203.0.113.7/32");
    expect(() => parse({ ...req, mode: "direct" })).toThrow(/unknown Cloudflare mode/);
    expect(() => parse({ ...req, scope: "cf.tunnel.config", scope_params: "tunnel=home", mode: "token", ip_condition: "203.0.113.7/32" })).toThrow(/no token mode/);
  });

  test("TTL above the scope's built-in maximum is refused (cf.admin: 1 hour)", () => {
    expect(() => parse({ ...req, scope: "cf.admin", scope_params: "", ttl_seconds: 7200 })).toThrow(/at most 1 hour/);
    expect(() => parse({ ...req, ttl_seconds: 8 * 3600 + 1 })).toThrow(/at most 8 hours/);
    expect(parse({ ...req, scope: "cf.admin", scope_params: "", ttl_seconds: 3600 }).ttl_seconds).toBe(3600);
  });

  test("Go's HTML escaping in values parses, and the value is flagged", () => {
    const text = canonicalJSON({ ...req, scope: "cf.tunnel.config", scope_params: "tunnel=a<b>&c" });
    expect(text).toContain("tunnel=a\\u003cb\\u003e\\u0026c");
    const c = parseCanonical(text);
    expect(c.scope_params).toBe("tunnel=a<b>&c");
    expect(describeAction(c).warnings.join(" ")).toMatch(/Tunnel value contains unusual characters/);
  });
});

describe("cloudflare describe()", () => {
  const head = (scope: string, scope_params = "", extra: Record<string, unknown> = {}) =>
    describeAction(parse({ ...req, scope, scope_params, ttl_seconds: 3600, ...extra })).headline;

  test("the spec's example", () => {
    const d = describeAction(parse(req));
    expect(d.headline).toBe(
      "Approve Cloudflare for agenthost: edit DNS records in zone example.net (only names matching *.example.net) for 2 hours, through the aqmas proxy (no secret leaves aqmas).",
    );
    expect(d.risk).toBe("high");
    expect(d.breakGlass).toBe(false);
    expect(d.warnings).toEqual([]);
    // Each parameter is its own line, values isolated; then the mode.
    expect(d.details!.map(partsText)).toEqual(["Zone: example.net", "Only DNS names: *.example.net", "Mode: through the aqmas proxy"]);
    expect(d.details![0]!.filter((p) => typeof p !== "string")).toEqual([{ value: "example.net" }]);
    // Values in the headline are separate parts.
    expect(d.headlineParts.filter((p) => typeof p !== "string").map((p) => (p as { value: string }).value)).toEqual(["agenthost", "example.net", "*.example.net", "2 hours"]);
    // Every canonical field is listed.
    expect(d.fields.length).toBe(Object.keys(req).length);
    expect(d.fields.find(([k]) => k === "Parameters")![1]).toBe("name=*.example.net;zone=example.net");
    expect(d.fields.find(([k]) => k === "Token usable from")![1]).toBe("n/a (proxy)");
  });

  test("one wording per scope family", () => {
    expect(head("cf.read")).toBe("Approve Cloudflare for agenthost: read the Cloudflare configuration (allow-listed reads only) for 1 hour, through the aqmas proxy (no secret leaves aqmas).");
    expect(head("cf.read.private")).toContain("read personal data in Cloudflare");
    expect(head("cf.dns.edit", "name=www.example.net;zone=example.net")).toContain("edit DNS records in zone example.net (only the name www.example.net) for 1 hour");
    expect(head("cf.dns.edit", "zone=example.net")).toContain("edit DNS records in zone example.net for 1 hour");
    expect(head("cf.tunnel.config", "tunnel=home")).toContain("replace the routes (ingress config) of tunnel home");
    expect(head("cf.access.apps")).toContain("create, change and delete Cloudflare Access apps");
    expect(head("cf.access.policies")).toContain("Access policies and groups");
    expect(head("cf.access.idp-org")).toContain("change Cloudflare Access login methods");
    expect(head("cf.rulesets", "zone=example.net")).toContain("in zone example.net for 1 hour");
    expect(head("cf.rulesets", "phase=http_request_dynamic_redirect;zone=example.net")).toContain("in zone example.net (only phase http_request_dynamic_redirect)");
    expect(head("cf.zone-settings", "zone=example.net")).toContain("change the settings of zone example.net");
    expect(head("cf.cache.purge", "zone=example.net")).toContain("purge listed URLs from the cache of zone example.net");
    expect(head("cf.workers.deploy", "script=shopfront-api")).toContain("deploy the Worker shopfront-api (no routes or custom domains)");
    expect(head("cf.workers.deploy", "script=shopfront-api;zone=example.net")).toContain("deploy the Worker shopfront-api (with routes and custom domains in zone example.net)");
    expect(head("cf.pages", "project=shopfront")).toContain("deploy the Pages project shopfront");
    expect(head("cf.d1", "access=read;db=billing")).toContain("run read-only queries on D1 database billing");
    expect(head("cf.d1", "access=migrate;db=billing")).toContain("run ANY SQL, including schema changes and data edits, on D1 database billing");
    expect(head("cf.r2.admin")).toContain("manage R2 buckets");
    expect(head("cf.r2.objects", "access=read;bucket=photos-bucket")).toContain("list and download objects in R2 bucket photos-bucket");
    expect(head("cf.r2.objects", "access=write;bucket=photos-bucket")).toContain("read, upload and delete objects in R2 bucket photos-bucket");
    expect(head("cf.email", "zone=example.net")).toContain("change email routing and sending for zone example.net");
  });

  test("cf.admin is loud", () => {
    const d = describeAction(parse({ ...req, scope: "cf.admin", scope_params: "", ttl_seconds: 3600 }));
    expect(d.headline).toBe(
      "Approve Cloudflare for agenthost: use the WHOLE Cloudflare account (break-glass: everything except the deny-list) for 1 hour, through the aqmas proxy (no secret leaves aqmas).",
    );
    expect(d.breakGlass).toBe(true);
    expect(d.risk).toBe("admin");
    expect(d.warnings[0]).toMatch(/^BREAK-GLASS: full Cloudflare access for up to 1 hour/);
    expect(d.warnings[0]).toMatch(/except the deny-list/);
    // A deny of it is not loud.
    expect(describeAction(parse({ ...req, action: "deny", scope: "cf.admin", scope_params: "", ttl_seconds: 0 })).warnings).toEqual([]);
  });

  test("token mode says a real token leaves aqmas, limited to the IP condition", () => {
    const d = describeAction(parse(token));
    expect(d.headline).toBe(
      "Approve Cloudflare for agenthost: deploy the Worker shopfront-api (with routes and custom domains in zone example.net) for 2 hours, as a real API token that leaves aqmas, limited to 203.0.113.7/32.",
    );
    expect(d.warnings.join(" ")).toMatch(/real Cloudflare API token leaves aqmas/);
    expect(d.warnings.join(" ")).toMatch(/ANY Worker on the account/);
    expect(d.details!.map(partsText).at(-1)).toBe("Mode: real API token, usable only from 203.0.113.7/32");
    const wide = describeAction(parse({ ...token, ip_condition: "198.51.100.0/24" }));
    expect(wide.warnings.join(" ")).toMatch(/whole networks.*198\.51\.100\.0\/24/);
  });

  test("standing, deny and revoke wording", () => {
    expect(describeAction(parse({ ...req, standing_hours: 4 })).standing).toBe(
      "Also auto-approve the same Cloudflare request from agenthost (cf.dns.edit name=*.example.net;zone=example.net, proxy) for the next 4 hours.",
    );
    expect(describeAction(parse({ ...req, action: "deny", ttl_seconds: 0 })).headline).toBe(
      "Deny Cloudflare for agenthost: edit DNS records in zone example.net (only names matching *.example.net).",
    );
    expect(describeAction(parse(grant)).headline).toBe("Revoke agenthost's Cloudflare access: read the Cloudflare configuration (allow-listed reads only).");
    expect(describeAction(parse({ ...grant, scope: "cf.pages", scope_params: "project=shopfront", mode: "token" })).headline).toBe(
      "Revoke agenthost's Cloudflare token (deleted at Cloudflare at once): deploy the Pages project shopfront.",
    );
    expect(describeAction(parse(standing)).headline).toBe("Stop auto-approving Cloudflare for agenthost: edit DNS records in zone example.net (each grant up to 2 hours).");
  });

  test("unusual characters in any value are flagged", () => {
    const cyrillicA = String.fromCharCode(0x430);
    const d = describeAction(parse({ ...req, scope_params: `name=*.ex${cyrillicA}mple.com;zone=ex${cyrillicA}mple.com` }));
    expect(d.warnings.join(" ")).toMatch(/Zone value contains unusual characters/);
    expect(d.warnings.join(" ")).toMatch(/Only DNS names value contains unusual characters/);
    expect(describeAction(parse({ ...req, requesting_host: "agent‮host" })).warnings.join(" ")).toMatch(/requesting host name contains unusual/);
    expect(describeAction(parse({ ...req, scope: "cf.pages", scope_params: "project=My Site" })).warnings.join(" ")).toMatch(/Pages project value/);
  });

  test("mismatches cover scope, scope_params, mode and ip_condition", () => {
    const c = parse(token);
    const want = {
      action: "approve",
      object: "request",
      id: "01JCF",
      ttl_seconds: 7200,
      standing_hours: 0,
      requesting_host: "agenthost",
      kind: "cloudflare",
      scope: token.scope,
      scope_params: token.scope_params,
      mode: "token",
      ip_condition: "203.0.113.7/32",
    };
    expect(mismatches(c, want)).toEqual([]);
    for (const [k, v] of Object.entries({ scope: "cf.pages", scope_params: "script=shopfront-api", mode: "proxy", ip_condition: "", kind: "ssh", requesting_host: "hosta", ttl_seconds: 3600 })) {
      const m = mismatches(c, { ...want, [k]: v });
      expect(m.length).toBe(1);
      expect(m[0]).toStartWith(`${k}:`);
    }
    // A revoke of a standing approval must name the rule's TTL the card showed.
    const s = parse(standing);
    expect(mismatches(s, { action: "revoke", object: "standing", id: "s1", ttl_seconds: 7200 })).toEqual([]);
    expect(mismatches(s, { action: "revoke", object: "standing", id: "s1", ttl_seconds: 3600 })).toHaveLength(1);
  });
});

describe("cfscopes.ts matches the Go catalogue", () => {
  test("same 17 scope names, risk, standing, max TTL, token mode and parameter keys", async () => {
    const root = join(import.meta.dir, "..", "..");
    const apiGo = await readFile(join(root, "internal/api/cloudflare.go"), "utf8");
    const catGo = await readFile(join(root, "internal/server/cfscope/catalogue.go"), "utf8");
    const consts = new Map<string, string>();
    for (const m of apiGo.matchAll(/^\s*(CF(?:Scope|Param|Risk)\w+)\s*=\s*"([^"]+)"/gm)) consts.set(m[1]!, m[2]!);
    const goNames = [...consts].filter(([k]) => k.startsWith("CFScope")).map(([, v]) => v);
    expect(goNames.length).toBe(17);
    expect(cfScopeNames().sort()).toEqual([...goNames].sort());

    const blocks = catGo.split("{scope: Scope{Name: api.").slice(1);
    expect(blocks.length).toBe(17);
    const ttl = (e: string) => {
      const t = e.trim();
      if (t === "AdminMaxTTL" || t === "hour") return 3600;
      const m = /^(\d+) \* hour$/.exec(t);
      if (!m) throw new Error(`unparsed TTL ${t}`);
      return Number(m[1]) * 3600;
    };
    for (const b of blocks) {
      const body = b.split(/\n\t\{scope: |\n\}/)[0]!;
      const name = consts.get(/^(\w+)/.exec(body)![1]!)!;
      const ui = cfScope(name)!;
      expect({ name, ok: !!ui }).toEqual({ name, ok: true });
      const risk = consts.get(/Risk:\s+api\.(\w+)/.exec(body)![1]!)!;
      const params = [...body.matchAll(/\{api\.(CFParam\w+), p\w+, (true|false)\}/g)].map((m) => ({ key: consts.get(m[1]!)!, required: m[2] === "true" }));
      expect({
        name,
        risk,
        standing: /StandingAllowed: true/.test(body),
        maxTTL: ttl(/MaxTTL: ([^}]+?)\}/.exec(body)![1]!),
        token: /tokenFor:/.test(body),
        params,
      }).toEqual({
        name,
        risk: ui.risk,
        standing: ui.standing,
        maxTTL: ui.maxTTL,
        token: ui.token,
        params: ui.params.map((p) => ({ key: p.key, required: p.required })),
      });
    }
  });
});

// ---- flows against the mock ----

type Mock = ReturnType<typeof startMock>;

async function signedIn(m: Mock) {
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  await completeLogin(api, auth, await prepareLogin(api));
  return { api, auth, f };
}

describe("cloudflare flows (mock)", () => {
  let m: Mock;
  beforeAll(() => {
    m = startMock({ port: 0, distDir: null });
  });
  afterAll(() => m.stop());

  test("the mock's state carries Cloudflare items as aqmasd will", async () => {
    const { api } = await signedIn(m);
    const s = await api.state();
    const dns = s.pending!.find((p) => p.id === "01JDEMO0CF0DNS0EDIT000009")!;
    expect(dns.kind).toBe("cloudflare");
    expect(dns.ssh).toBeUndefined();
    expect(dns.risk).toBe("high");
    expect(dns.cloudflare).toMatchObject({ scope: "cf.dns.edit", scope_params: "name=*.example.net;zone=example.net", mode: "proxy", ip_condition: "", risk: "high", standing_allowed: true });
    const tok = s.pending!.find((p) => p.id === "01JDEMO0CF0WORKER0TOKEN11")!;
    expect(tok.cloudflare).toMatchObject({ mode: "token", ip_condition: "203.0.113.7/32", standing_allowed: false });
    expect(tok.cloudflare!.permissions).toContain("Workers Scripts Write (account)");
    expect(s.grants!.find((g) => g.id === "01JDEMO0CFGRANT0READ00008")).toMatchObject({ kind: "cloudflare", scope: "cf.read", mode: "proxy" });
    expect("scope_params" in s.grants!.find((g) => g.id === "01JDEMO0CFGRANT0READ00008")!).toBe(false); // omitempty
  });

  test("approve cf.dns.edit for 1 h with a 4 h standing approval", async () => {
    const { api, auth } = await signedIn(m);
    const item = (await api.state()).pending!.find((p) => p.id === "01JDEMO0CF0DNS0EDIT000009")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 3600, standing_hours: 4 });
    expect(prep.canonicalText).toBe(canonicalJSON(prep.canonical));
    expect(Object.keys(prep.canonical).sort()).toEqual(Object.keys(req).sort());
    expect(prep.description.headline).toContain("edit DNS records in zone example.net (only names matching *.example.net) for 1 hour");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(prep.canonicalText)));
    expect(encode(prep.options.challenge as ArrayBuffer)).toBe(encode(digest));
    const res = (await completeAction(api, auth, prep)) as { status: string };
    expect(res.status).toBe("approved");
    expect(m.store.applied.at(-1)!.canonical).toMatchObject({ kind: "cloudflare", scope: "cf.dns.edit", ttl_seconds: 3600, standing_hours: 4, mode: "proxy", ip_condition: "" });
    const s = await api.state();
    expect(s.grants!.some((g) => g.scope === "cf.dns.edit" && g.scope_params === "name=*.example.net;zone=example.net")).toBe(true);
    expect(s.standing!.some((x) => x.scope === "cf.dns.edit" && x.scope_params === "name=*.example.net;zone=example.net" && x.max_ttl_seconds === 3600)).toBe(true);
  });

  test("approve a token-mode request; a standing approval for it is refused by the server", async () => {
    const { api, auth } = await signedIn(m);
    const item = m.store.spawnCloudflare(mockPendingCloudflare("cf.workers.deploy", { script: "frames" }, "token"));
    const e = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 1800, standing_hours: 1 }).catch((x) => x);
    expect((e as ApiError).status).toBe(400);
    const prep = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 1800 });
    expect(prep.canonical).toMatchObject({ mode: "token", ip_condition: "203.0.113.7/32", scope_params: "script=frames" });
    expect((await completeAction(api, auth, prep)) as object).toMatchObject({ status: "approved" });
  });

  test("deny cf.admin", async () => {
    const { api, auth } = await signedIn(m);
    const item = (await api.state()).pending!.find((p) => p.id === "01JDEMO0CF0ADMIN000000012")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "deny" });
    expect(prep.description.headline).toBe("Deny Cloudflare for agenthost: use the WHOLE Cloudflare account (break-glass: everything except the deny-list).");
    expect((await completeAction(api, auth, prep)) as object).toMatchObject({ status: "denied" });
  });

  test("revoke a Cloudflare standing approval and a Cloudflare grant", async () => {
    const { api, auth } = await signedIn(m);
    let s = await api.state();
    const st = s.standing!.find((x) => x.id === "01JDEMO0CFSTANDING0000013")!;
    let prep = await prepareAction(api, targetForStanding(st), { action: "revoke" });
    expect(prep.canonical).toMatchObject({ object: "standing", kind: "cloudflare", ttl_seconds: 7200, standing_hours: 0 });
    expect(prep.description.headline).toBe("Stop auto-approving Cloudflare for agenthost: edit DNS records in zone example.net (each grant up to 2 hours).");
    await completeAction(api, auth, prep);
    const g = s.grants!.find((x) => x.id === "01JDEMO0CFGRANT0READ00008")!;
    prep = await prepareAction(api, targetForGrant(g), { action: "revoke" });
    expect(prep.canonical).toMatchObject({ object: "grant", kind: "cloudflare", scope: "cf.read", scope_params: "", mode: "proxy", ttl_seconds: 0 });
    expect(prep.description.headline).toBe("Revoke agenthost's Cloudflare access: read the Cloudflare configuration (allow-listed reads only).");
    await completeAction(api, auth, prep);
    s = await api.state();
    expect(s.standing!.some((x) => x.id === st.id)).toBe(false);
    expect(s.grants!.some((x) => x.id === g.id)).toBe(false);
  });

  test("a card without its Cloudflare detail is never signed", async () => {
    const { api } = await signedIn(m);
    const item = m.store.spawnCloudflare(mockPendingCloudflare("cf.read"));
    const e = await prepareAction(api, targetForPending({ ...item, cloudflare: undefined }), { action: "deny" }).catch((x) => x);
    expect(e).toBeInstanceOf(FlowError);
    expect((e as FlowError).message).toMatch(/scope/);
  });
});

describe("a lying server is caught before a Cloudflare action is signed", () => {
  let m: Mock;
  beforeAll(() => {
    m = startMock({ port: 0, distDir: null });
  });
  afterAll(() => m.stop());

  const sha = async (t: string) => encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t))));
  const rewrite = async (r: ChallengeResponse, change: Record<string, unknown>) => {
    const text = canonicalJSON({ ...JSON.parse(r.canonical), ...change });
    const pk = (r.public_key as { publicKey: Record<string, unknown> }).publicKey;
    return { ...r, canonical: text, public_key: { publicKey: { ...pk, challenge: await sha(text) } } };
  };

  async function tampered(change: Record<string, unknown>, mode: "proxy" | "token" = "proxy") {
    const { api, auth } = await signedIn(m);
    const evil: Api = { ...api, challenge: async (o, id, b) => rewrite(await api.challenge(o, id, b), change) };
    const item =
      mode === "token"
        ? m.store.spawnCloudflare(mockPendingCloudflare("cf.dns.edit", { zone: "example.net" }, "token"))
        : m.store.spawnCloudflare(mockPendingCloudflare("cf.dns.edit", { zone: "example.net", name: "*.example.net" }));
    const e = await prepareAction(evil, targetForPending(item), { action: "approve", ttl_seconds: 3600 }).catch((x) => x);
    expect(e).toBeInstanceOf(FlowError);
    expect(auth.gets.length).toBe(1); // only the login
    return (e as FlowError).message;
  }

  test("a wider scope", async () => {
    expect(await tampered({ scope: "cf.admin", scope_params: "" })).toMatch(/scope/);
  });
  test("dropped name restriction", async () => {
    expect(await tampered({ scope_params: "zone=example.net" })).toMatch(/scope_params/);
  });
  test("switched to token mode", async () => {
    expect(await tampered({ mode: "token", ip_condition: "0.0.0.0/0" })).toMatch(/mode/);
  });
  test("a different IP condition on a token", async () => {
    expect(await tampered({ ip_condition: "0.0.0.0/0" }, "token")).toMatch(/ip_condition/);
  });
  test("a sneaked-in standing approval", async () => {
    expect(await tampered({ standing_hours: 8 })).toMatch(/standing_hours/);
  });
  test("SSH fields smuggled into a Cloudflare action", async () => {
    expect(await tampered({ target: "db-1", login_user: "root" })).toMatch(/target|login_user/);
  });
  test("a revoke that names a different standing rule TTL", async () => {
    const { api } = await signedIn(m);
    const evil: Api = { ...api, challenge: async (o, id, b) => rewrite(await api.challenge(o, id, b), { ttl_seconds: 28800 }) };
    const st = (await api.state()).standing!.find((x) => x.kind === "cloudflare")!;
    const e = await prepareAction(evil, targetForStanding(st), { action: "revoke" }).catch((x) => x);
    expect((e as FlowError).message).toMatch(/ttl_seconds/);
  });
});
