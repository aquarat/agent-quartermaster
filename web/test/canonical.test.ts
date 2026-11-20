import { describe, expect, test } from "bun:test";
import { encode } from "../src/b64url";
import { CanonicalError, challengeCommitsTo, describe as describeAction, mismatches, parseCanonical } from "../src/canonical";
import { canonicalJSON } from "../mock/server";

const base = {
  v: 1,
  action: "approve",
  object: "request",
  id: "01JX",
  requesting_host: "build-box",
  kind: "ssh",
  target: "db-1",
  login_user: "alice",
  key_fingerprint: "SHA256:abc",
  ttl_seconds: 1800,
  standing_hours: 0,
  nonce: "bm9uY2U",
  issued_at: "2026-11-20T10:00:00Z",
};

describe("canonical", () => {
  test("parses sorted, compact JSON", () => {
    const c = parseCanonical(canonicalJSON(base));
    expect(c.action).toBe("approve");
  });

  test("accepts Go's HTML escaping and plain form", () => {
    const withLt = { ...base, key_fingerprint: "a<b>&c" };
    const goForm = canonicalJSON(withLt);
    expect(goForm).toContain("a\\u003cb\\u003e\\u0026c");
    expect(parseCanonical(goForm).key_fingerprint).toBe("a<b>&c");
    const plain = goForm.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&");
    expect(parseCanonical(plain).key_fingerprint).toBe("a<b>&c");
  });

  test("rejects whitespace, unsorted and duplicate keys", () => {
    expect(() => parseCanonical(JSON.stringify(base, null, 1))).toThrow(CanonicalError);
    expect(() => parseCanonical(JSON.stringify(base))).toThrow(CanonicalError); // insertion order, not sorted
    const dup = canonicalJSON(base).replace('"action":"approve"', '"action":"deny","action":"approve"');
    expect(() => parseCanonical(dup)).toThrow(CanonicalError);
  });

  test("rejects wrong version, missing fields, bad numbers", () => {
    expect(() => parseCanonical(canonicalJSON({ ...base, v: 2 }))).toThrow(/version/);
    expect(() => parseCanonical(canonicalJSON({ ...base, id: "" }))).toThrow(/id/);
    expect(() => parseCanonical(canonicalJSON({ ...base, ttl_seconds: -5 }))).toThrow(/ttl_seconds/);
    expect(() => parseCanonical(canonicalJSON({ ...base, ttl_seconds: "1800" }))).toThrow(/ttl_seconds/);
    expect(() => parseCanonical("[1]")).toThrow(CanonicalError);
    expect(() => parseCanonical("nope")).toThrow(CanonicalError);
  });

  test("challenge must be SHA-256 of the exact canonical bytes", async () => {
    const text = canonicalJSON(base);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    expect(await challengeCommitsTo(text, encode(digest))).toBe(true);
    expect(await challengeCommitsTo(canonicalJSON({ ...base, ttl_seconds: 28800 }), encode(digest))).toBe(false);
  });

  test("mismatches catch every field the owner relies on", () => {
    const c = parseCanonical(canonicalJSON(base));
    const want = { action: "approve", object: "request", id: "01JX", ttl_seconds: 1800, standing_hours: 0, requesting_host: "build-box", kind: "ssh", target: "db-1", login_user: "alice", key_fingerprint: "SHA256:abc" };
    expect(mismatches(c, want)).toEqual([]);
    for (const [k, v] of Object.entries({ action: "deny", id: "other", ttl_seconds: 3600, standing_hours: 4, requesting_host: "x", target: "y", login_user: "root", key_fingerprint: "SHA256:zzz" })) {
      expect(mismatches(c, { ...want, [k]: v }).length).toBeGreaterThan(0);
    }
    // A deny must not smuggle in a standing approval.
    const deny = parseCanonical(canonicalJSON({ ...base, action: "deny", standing_hours: 8 }));
    expect(mismatches(deny, { action: "deny", object: "request", id: "01JX" })).toHaveLength(1);
  });

  test("describe reads only canonical fields", () => {
    const d = describeAction(parseCanonical(canonicalJSON(base)));
    expect(d.headline).toBe("Approve SSH as alice@db-1 for 30 min, requested by build-box.");
    expect(d.standing).toBeUndefined();
    const s = describeAction(parseCanonical(canonicalJSON({ ...base, standing_hours: 4 })));
    expect(s.standing).toBe("Also auto-approve the same request (build-box to alice@db-1) for the next 4 hours.");
    expect(describeAction(parseCanonical(canonicalJSON({ ...base, action: "deny", ttl_seconds: 0 }))).headline).toBe("Deny SSH as alice@db-1, requested by build-box.");
    expect(describeAction(parseCanonical(canonicalJSON({ v: 1, action: "revoke", object: "grant", id: "g", requesting_host: "ci-1", kind: "ssh", target: "db-1", login_user: "alice" }))).headline).toBe(
      "Revoke ci-1's SSH access as alice@db-1.",
    );
    // Every field is listed, including the nonce.
    expect(d.fields.map(([k]) => k)).toContain("Nonce");
    expect(d.fields.length).toBe(Object.keys(base).length);
  });
});
