// Activity log classification and day grouping (pure).
import { describe, expect, test } from "bun:test";
import { FILTERS, actor, classify, detailUntrusted, groupByDay, isCloudflare, matches, objectRef, rowKey } from "../src/audit";
import { dayKey, dayLabel, eventTime } from "../src/format";
import type { AuditEntry } from "../src/types";

const e = (action: string, actorS = "owner", object = "request:01JDEMO00000000000000ABC123", at = "2026-11-20T10:00:00Z", detail?: string): AuditEntry => ({
  at,
  actor: actorS,
  action,
  object,
  detail,
});

describe("classify", () => {
  test("every server action has a kind, a label and filter groups", () => {
    const want: Record<string, [string, string[]]> = {
      approve: ["approve", ["decisions"]],
      deny: ["deny", ["decisions"]],
      enroll_approve: ["approve", ["decisions", "hosts"]],
      enroll_deny: ["deny", ["decisions", "hosts"]],
      standing_create: ["auto", ["decisions"]],
      auto_approve: ["auto", ["decisions", "requests"]],
      standing_revoke: ["revoke", ["decisions"]],
      grant_revoke: ["revoke", ["decisions"]],
      host_revoke: ["revoke", ["hosts", "decisions"]],
      request_cancel: ["revoke", ["requests"]],
      enroll_request: ["request", ["requests", "hosts"]],
      login: ["passkey", ["passkeys"]],
      passkey_register: ["passkey", ["passkeys"]],
      passkey_rename: ["passkey", ["passkeys"]],
      passkey_remove: ["passkey", ["passkeys"]],
      passkey_enroll_code: ["passkey", ["passkeys"]],
      passkey_clone_warning: ["warning", ["passkeys"]],
    };
    for (const [action, [kind, groups]] of Object.entries(want)) {
      const c = classify(e(action, "owner", "x"));
      expect({ action, kind: c.kind as string, groups: c.groups as string[] }).toEqual({ action, kind, groups });
      expect(c.label.length).toBeGreaterThan(0);
    }
  });

  test("host actors and host/enrollment objects also count as hosts", () => {
    expect(classify(e("request", "host:web-1")).groups).toEqual(["requests", "hosts"]);
    expect(classify(e("host_revoke", "system", "host:web-1")).groups).toContain("hosts");
    expect(matches(e("request", "host:web-1"), "hosts")).toBe(true);
    expect(matches(e("login", "owner", "passkey:ab"), "hosts")).toBe(false);
    expect(matches(e("login"), "all")).toBe(true);
  });

  test("unknown actions fall back to grey system rows, errors to warnings", () => {
    expect(classify(e("frobnicate"))).toEqual({ kind: "system", label: "Frobnicate", groups: [] });
    expect(classify(e("ntfy_error")).kind).toBe("warning");
  });
});

describe("classify: Cloudflare", () => {
  test("cf_* events: refusals warn, writes and token events have their own kinds", () => {
    const want: Record<string, [string, string, string[]]> = {
      cf_auto_approve: ["auto", "Cloudflare auto-approved", ["decisions", "requests", "cloudflare"]],
      cf_write: ["cfwrite", "Cloudflare write", ["cloudflare"]],
      cf_refused: ["warning", "Cloudflare refused", ["cloudflare"]],
      cf_token_mint: ["token", "Token minted", ["cloudflare"]],
      cf_token_delete: ["token", "Token deleted", ["cloudflare"]],
      cf_token_orphan: ["warning", "Stray token deleted", ["cloudflare"]],
    };
    for (const [action, [kind, label, groups]] of Object.entries(want)) {
      const c = classify(e(action, "system", "grant:01JDEMO0CFGRANT00000000014"));
      expect({ action, kind: c.kind as string, label: c.label, groups: c.groups as string[], cf: c.cloudflare }).toEqual({ action, kind, label, groups, cf: true });
    }
    // A host's write or refusal also counts as a host event.
    expect(classify(e("cf_write", "host:agenthost", "grant:x")).groups).toEqual(["cloudflare", "hosts"]);
    // An unknown future cf_ event still lands in the Cloudflare filter, refusal-like ones warn.
    expect(classify(e("cf_snapshot_prune", "system", "x"))).toEqual({ kind: "system", label: "Cloudflare: Cf snapshot prune", groups: ["cloudflare"], cloudflare: true });
    expect(classify(e("cf_mint_failed", "system", "x")).kind).toBe("warning");
  });

  test("decisions about Cloudflare objects keep their colour, gain the mark and the filter", () => {
    const cases: Array<[string, string, string, string]> = [
      ["approve", "grant=01JG cloudflare cf.dns.edit zone=example.net mode=proxy for agenthost ttl=7200 ip= src=192.0.2.50 signed by passkey 1 nonce=Ab", "approve", "Cloudflare approved"],
      ["standing_create", "host=agenthost cloudflare cf.dns.edit zone=example.net mode=proxy max_ttl=7200 hours=4", "auto", "Cloudflare auto-approval on"],
      ["auto_approve", "standing=01JS grant=01JG host=agenthost cloudflare cf.read mode=proxy ttl=3600 from=192.0.2.50", "auto", "Cloudflare auto-approved"],
      ["grant_revoke", "cloudflare cf.pages project=shopfront — child token deleted upstream passkey=1 nonce=Ab", "revoke", "Cloudflare access revoked"],
      ["grant_revoke", "cloudflare cf.read — proxy access ends now passkey=1 nonce=Ab", "revoke", "Cloudflare access revoked"],
      ["deny", "cloudflare cf.admin mode=proxy for agenthost passkey=1 nonce=Ab", "deny", "Cloudflare denied"],
      ["standing_revoke", "host=agenthost cloudflare cf.dns.edit zone=example.net mode=proxy passkey=1 nonce=Ab", "revoke", "Cloudflare auto-approval off"],
      ["request", "cloudflare cf.admin mode=proxy ttl=3600 from=192.0.2.50", "request", "Cloudflare requested"],
    ];
    for (const [action, detail, kind, label] of cases) {
      const c = classify(e(action, action === "request" ? "host:agenthost" : "owner", "request:x", undefined, detail));
      expect({ action, kind: c.kind as string, label: c.label, cf: c.cloudflare }).toEqual({ action, kind, label, cf: true });
      expect(c.groups).toContain("cloudflare");
    }
    // SSH rows are not Cloudflare, even when a reason mentions it.
    const ssh = e("request", "host:web-1", "request:x", undefined, 'ssh alice@db-1 reason="fix cloudflare dns"');
    expect(isCloudflare(ssh)).toBe(false);
    expect(classify(ssh).cloudflare).toBeUndefined();
    expect(matches(ssh, "cloudflare")).toBe(false);
    // Nor when host-sent text later in the detail imitates aqmasd's wording.
    expect(isCloudflare(e("request", "host:web-1", "request:x", undefined, 'ssh alice@db-1 reason="x" cloudflare cf.admin'))).toBe(false);
    expect(isCloudflare(e("approve", "owner", "request:x", undefined, "grant=01JG alice@db-1 for cloudflare cf.admin"))).toBe(false);
    expect(classify(e("approve", "owner", "request:x", undefined, "grant=01JG alice@db-1 for web-1 ttl=1800")).label).toBe("Approved");
    expect(FILTERS.map((f) => f.id)).toContain("cloudflare");
  });
});

describe("actor, object, detail", () => {
  test("actor chips", () => {
    expect(actor("owner")).toEqual({ kind: "owner", name: "owner" });
    expect(actor("system")).toEqual({ kind: "system", name: "system" });
    expect(actor("host:web-1")).toEqual({ kind: "host", name: "web-1" });
    expect(actor("host:")).toEqual({ kind: "other", name: "host:" });
  });

  test("objects get the cards' short Ref; hosts keep their name", () => {
    expect(objectRef("request:01JDEMO00000000000000ABC123")).toEqual({ type: "request", id: "01JDEMO00000000000000ABC123", short: "request ABC123" });
    expect(objectRef("grant:01jdemo0grant000000000xyz9").short).toBe("access 00XYZ9");
    expect(objectRef("host:db-1")).toEqual({ type: "host", id: "db-1", short: "host db-1" });
    expect(objectRef("passkey:3")).toEqual({ type: "passkey", id: "3", short: "passkey 3" });
    expect(objectRef("passkey")).toEqual({ type: "passkey", id: "", short: "passkey" });
    expect(objectRef("enroll_code").short).toBe("enroll code");
  });

  test("detail that can carry host-sent text is flagged", () => {
    expect(detailUntrusted(e("request", "host:web-1", "request:x", undefined, "ssh alice@db-1"))).toBe(true);
    expect(detailUntrusted(e("enroll_request", "system", "enrollment:x", undefined, "hostname=<b>x</b>"))).toBe(true);
    expect(detailUntrusted(e("login", "owner", "passkey:ab", undefined, 'nickname="x"'))).toBe(false);
    expect(detailUntrusted(e("approve"))).toBe(false); // no detail at all
  });
});

describe("days", () => {
  test("groupByDay keeps order and splits on local days", () => {
    const d1 = new Date(2026, 10, 20, 9, 0).toISOString();
    const d1b = new Date(2026, 10, 20, 0, 5).toISOString();
    const d0 = new Date(2026, 10, 19, 23, 55).toISOString();
    const g = groupByDay([e("approve", "owner", "a", d1), e("deny", "owner", "b", d1b), e("login", "owner", "c", d0)]);
    expect(g.map((x) => [x.key, x.entries.map((y) => y.object)])).toEqual([
      ["2026-11-20", ["a", "b"]],
      ["2026-11-19", ["c"]],
    ]);
    expect(rowKey(g[0]!.entries[0]!)).not.toBe(rowKey(g[0]!.entries[1]!));
  });

  test("day labels and row times", () => {
    const now = new Date(2026, 10, 20, 15, 0).getTime();
    expect(dayLabel(new Date(2026, 10, 20, 1, 0).getTime(), now)).toBe("Today");
    expect(dayLabel(new Date(2026, 10, 19, 23, 0).getTime(), now)).toBe("Yesterday");
    expect(dayLabel(new Date(2026, 10, 17, 12, 0).getTime(), now)).toBe("Tuesday 17 November");
    expect(dayLabel(new Date(2026, 9, 1, 12, 0).getTime(), now)).toBe("1 October");
    expect(dayLabel(new Date(2025, 9, 1, 12, 0).getTime(), now)).toBe("1 October 2025");
    expect(dayKey(new Date(2026, 0, 5, 12).getTime())).toBe("2026-01-05");
    expect(eventTime(now - 5 * 60_000, now)).toBe("5 min ago");
    expect(eventTime(new Date(2026, 10, 19, 9, 7).getTime(), now)).toBe("09:07");
  });
});
