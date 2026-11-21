import { describe, expect, test } from "bun:test";
import { encode } from "../src/b64url";
import { CanonicalError, challengeCommitsTo, describe as describeAction, mismatches, parseCanonical } from "../src/canonical";
import { canonicalJSON } from "../mock/server";

const base = {
  v: 1,
  action: "approve",
  object: "request",
  id: "01JX",
  requesting_host: "web-1",
  kind: "ssh",
  target: "db-1",
  target_address:'192.0.2.10',target_port:22,
  address:'192.0.2.8',principal:'alice@db-1',
  login_user: "alice",
  key_fingerprint: "SHA256:abc",
  ttl_seconds: 1800,
  standing_hours: 0,
  nonce: "bm9uY2U",
  issued_at: "2026-11-20T10:00:00Z",
};

describe("canonical", () => {
  test('bastion updates bind every displayed digest and both identities',()=>{
    const fields={from_version:'0.1.0',from_commit:'a'.repeat(40),to_version:'0.1.1',to_commit:'b'.repeat(40),daemon_sha256:'1'.repeat(64),linux_arm64_sha256:'2'.repeat(64),linux_amd64_sha256:'3'.repeat(64),darwin_arm64_sha256:'4'.repeat(64)};
    const choice={...fields,id:fields.to_commit,action:'approve',object:'update'};
    const text=canonicalJSON({...choice,nonce:base.nonce,issued_at:base.issued_at,v:1});
    const c=parseCanonical(text);
    expect(mismatches(c,choice)).toEqual([]);
    for(const k of Object.keys(fields)) expect(mismatches(c,{...choice,[k]:'different'})).not.toEqual([]);
    expect(()=>parseCanonical(text.replace(/"daemon_sha256":"[^"]+",/,''))).toThrow();
  });
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
    expect(() => parseCanonical(canonicalJSON({ ...base, v: 3 }))).toThrow(/version/);
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
    const want = { action: "approve", object: "request", id: "01JX", ttl_seconds: 1800, standing_hours: 0, requesting_host: "web-1", kind: "ssh", target: "db-1", login_user: "alice", key_fingerprint: "SHA256:abc" };
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
    expect(d.headline).toBe("Approve SSH as alice@db-1 for 30 min, requested by web-1.");
    expect(d.standing).toBeUndefined();
    const s = describeAction(parseCanonical(canonicalJSON({ ...base, standing_hours: 4 })));
    expect(s.standing).toBe("Also auto-approve the same request (web-1 to alice@db-1) for the next 4 hours.");
    expect(describeAction(parseCanonical(canonicalJSON({ ...base, action: "deny", ttl_seconds: 0 }))).headline).toBe("Deny SSH as alice@db-1, requested by web-1.");
    expect(describeAction(parseCanonical(canonicalJSON({ v: 1, action: "revoke", object: "grant", id: "g", requesting_host: "laptop-2", kind: "ssh", target: "db-1", login_user: "alice",nonce:'n',issued_at:'t',ttl_seconds:0,standing_hours:0 }))).headline).toBe(
      "Revoke laptop-2's SSH access as alice@db-1.",
    );
    // Every field is listed, including the nonce.
    expect(d.fields.map(([k]) => k)).toContain("Nonce");
    expect(d.fields.length).toBe(Object.keys(base).length);
  });

  test("refuses fields and actions the page can't describe", () => {
    expect(() => parseCanonical(canonicalJSON({ ...base, force_command: "rm -rf /" }))).toThrow(/force_command/);
    expect(() => parseCanonical(canonicalJSON({ ...base, principals: ["root@x"] }))).toThrow(/principals/);
    expect(() => parseCanonical(canonicalJSON({ ...base, action: "revoke" }))).toThrow(/unknown action/);
    expect(() => parseCanonical(canonicalJSON({ ...base, object: "user" }))).toThrow(/unknown object/);
    expect(() => parseCanonical(canonicalJSON({ v: 1, action: "add", object: "passkey", id: "new", target: "x" }))).toThrow(/target/);
    expect(() => parseCanonical(canonicalJSON({ ...base, target: 5 }))).toThrow(/target/);
  });

  test("enrollment that replaces a host says so and must match the card", () => {
    const enr = { v: 1, action: "approve", object: "enrollment", id: "e1", requesting_host: "db-1", kind: "enrollment", key_fingerprint: "SHA256:k", replaces: true, nonce: "n", issued_at: "t",address:'192.0.2.10',class:'agent',ttl_seconds:0,standing_hours:0 };
    const c = parseCanonical(canonicalJSON({...enr,replaces_id:'old'}));
    expect(mismatches(c,{action:'approve',object:'enrollment',id:'e1',replaces:true,class:'owner-device'})).toHaveLength(1);
    const d = describeAction(c);
    expect(d.headline).toBe("Let db-1 join the fleet, replacing the existing host of that name.");
    expect(d.warnings.join(" ")).toMatch(/loses its client certificate/);
    expect(mismatches(c, { action: "approve", object: "enrollment", id: "e1", replaces: false })).toHaveLength(1);
    expect(mismatches(c, { action: "approve", object: "enrollment", id: "e1", replaces: true, key_fingerprint: "SHA256:other" })).toHaveLength(1);
  });

  test("values are separate parts (rendered isolated) and odd names are flagged", () => {
    const cyrillicA = String.fromCharCode(0x430);
    const d = describeAction(parseCanonical(canonicalJSON({ ...base, target: "b" + cyrillicA + "ckup" })));
    expect(d.headlineParts.filter((p) => typeof p !== "string").map((p) => (p as { value: string }).value)).toEqual(["SSH", "alice", "b" + cyrillicA + "ckup", "30 min", "web-1"]);
    expect(d.warnings.join(" ")).toMatch(/target host name contains unusual characters/);
    expect(describeAction(parseCanonical(canonicalJSON(base))).warnings).toEqual([]);
  });

  test("Go escapes U+2028/2029; both forms parse", () => {
    const ls = String.fromCharCode(0x2028);
    const text = canonicalJSON({ ...base, key_fingerprint: "a" + ls + "b" });
    expect(text).not.toContain(ls);
    expect(parseCanonical(text).key_fingerprint).toBe("a" + ls + "b");
  });
});
