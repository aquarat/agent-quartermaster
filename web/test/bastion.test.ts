// Access to the bastion itself (docs/BASTION-ACCESS.md §5): the canonical text of a bastion
// decision, what the page refuses to sign, and the parameters of the bastion and routine tasks.
import { afterAll, describe, expect, test } from "bun:test";
import { createApi } from "../src/api";
import { CanonicalError, describe as describeCanonical, mismatches, openList, parseCanonical, parseOpenList, ROOT_CONSEQUENCES, ROOT_NO_ALERT, ROOT_TITLE } from "../src/canonical";
import { completeLogin, decideBastion, FlowError, prepareAction, prepareLogin, targetForPending } from "../src/flows";
import { canonicalParams, completeSetupTask, paramLines, prepareSetupTask, queuedParams, runSetupTask, secretNames, type SetupView } from "../src/setup";
import { allowParams, queuedSummary } from "../src/bastion";
import { startMock } from "../mock/server";
import { fakeAuth, jarFetch } from "./helpers";
import vectors from "./fixtures/bastion-vectors.json";

const NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
type Fields = Record<string, unknown>;

/** Canonical text as the broker builds it: sorted keys, no whitespace. */
function text(over: Fields = {}, drop: string[] = []): string {
  const c: Fields = {
    v: 1, action: "approve", object: "request", id: "01REQ", nonce: NONCE, issued_at: "2026-11-23T10:00:00Z",
    kind: "bastion", level: "root", requesting_host: "dev-1", host_id: "01ENROLLMENT", address: "192.0.2.21",
    target: "bastion", target_address: "192.0.2.10", target_port: 22, login_user: "alice", principal: "alice@bastion",
    key_fingerprint: "SHA256:key", ssh_ca: "SHA256:ca", host_key: "SHA256:host", cert_profile: "source-address;permit-pty",
    ttl_seconds: 1800, sealed: true, open_buckets: '["SSH user CA","personal/paas/staging-env"]', close_buckets: true, alert_channel: true,
    ...over,
  };
  for (const k of drop) delete c[k];
  return JSON.stringify(Object.fromEntries(Object.keys(c).sort().map((k) => [k, c[k]])));
}
const inspect: Fields = { level: "inspect", login_user: "aqmas-inspect", principal: "aqmas-inspect@bastion", cert_profile: "source-address;force-command", ttl_seconds: 3600, open_buckets: "[]", close_buckets: false, alert_channel: false };

describe("canonical text of a bastion decision", () => {
  test("a root approval parses and is described from its own fields", () => {
    const c = parseCanonical(text());
    const d = describeCanonical(c);
    expect(d.headline).toContain(ROOT_TITLE);
    expect(d.headline).toContain("dev-1");
    expect(d.headline).toContain("30 min");
    expect(d.bastion).toEqual({ level: "root", action: "approve", host: "dev-1", target: "bastion", user: "alice", address: "192.0.2.21", ttl: 1800, sealed: true, open: ["SSH user CA", "personal/paas/staging-env"], close: true, alert: true });
    expect(d.warnings).toContain(ROOT_CONSEQUENCES);
    expect(d.warnings.join("\n")).toContain("Open right now: SSH user CA · personal/paas/staging-env");
    expect(d.fields.some(([k, v]) => k === "Buckets open" && v.includes("staging-env"))).toBe(true);
  });

  test("left open and no alert channel are said in words", () => {
    const d = describeCanonical(parseCanonical(text({ close_buckets: false, alert_channel: false })));
    expect(d.warnings.join("\n")).toContain("STAY OPEN");
    expect(d.warnings).toContain(ROOT_NO_ALERT);
    expect(d.bastion!.close).toBe(false);
  });

  test("inspect approve, both denies, an unsealed root approval and a grant revoke parse", () => {
    expect(describeCanonical(parseCanonical(text(inspect))).headline).toContain("read-only inspect access");
    parseCanonical(text({ action: "deny", ttl_seconds: 0, open_buckets: "[]", close_buckets: false, alert_channel: false }));
    parseCanonical(text({ ...inspect, action: "deny", ttl_seconds: 0 }));
    const d = describeCanonical(parseCanonical(text({ sealed: false, open_buckets: "[]", close_buckets: false })));
    expect(d.warnings.join("\n")).toContain("not sealed");
    const g = parseCanonical('{"action":"revoke","id":"01G","issued_at":"2026-11-23T10:00:00Z","kind":"bastion","login_user":"alice","nonce":"' + NONCE + '","object":"grant","requesting_host":"dev-1","standing_hours":0,"target":"bastion","ttl_seconds":0,"v":1}');
    expect(describeCanonical(g).warnings.join(" ")).toContain("cannot be recalled");
  });

  const bad: Array<[string, string]> = [
    ["unknown level", text({ level: "admin" })],
    ["root with the inspect profile", text({ cert_profile: "source-address;force-command" })],
    ["inspect with the root profile", text({ ...inspect, cert_profile: "source-address;permit-pty" })],
    ["a profile with port forwarding", text({ cert_profile: "source-address;permit-pty;permit-port-forwarding" })],
    ["principal that is not user@target", text({ principal: "root@bastion" })],
    ["root longer than an hour", text({ ttl_seconds: 3601 })],
    ["approve without a duration", text({ ttl_seconds: 0 })],
    ["deny with a duration", text({ action: "deny", open_buckets: "[]", close_buckets: false, alert_channel: false })],
    ["inspect with an open list", text({ ...inspect, open_buckets: '["SSH user CA"]' })],
    ["inspect with the close choice", text({ ...inspect, close_buckets: true })],
    ["inspect with the alert flag", text({ ...inspect, alert_channel: true })],
    ["deny with an open list", text({ action: "deny", ttl_seconds: 0, close_buckets: false, alert_channel: false })],
    ["unsealed with an open list", text({ sealed: false, close_buckets: false })],
    ["unsealed with the close choice", text({ sealed: false, open_buckets: "[]" })],
    ["open list not sorted", text({ open_buckets: '["b","a"]' })],
    ["open list with a duplicate", text({ open_buckets: '["a","a"]' })],
    ["open list with whitespace", text({ open_buckets: '["a", "b"]' })],
    ["open list that is not a list", text({ open_buckets: '{"a":1}' })],
    ["open list as a real array", text({ open_buckets: ["a"] })],
    ["open list with a non-string", text({ open_buckets: "[1]" })],
    ["missing open_buckets", text({}, ["open_buckets"])],
    ["missing close_buckets", text({}, ["close_buckets"])],
    ["missing alert_channel", text({}, ["alert_channel"])],
    ["missing level", text({}, ["level"])],
    ["missing host_id", text({}, ["host_id"])],
    ["a standing field", text({ standing_hours: 1 })],
    ["standing_hours even when 0", text({ standing_hours: 0 })],
    ["an extra field", text({ force_command: "/bin/sh" })],
    ["empty host key", text({ host_key: "" })],
    ["port 0", text({ target_port: 0 })],
    ["close_buckets as a string", text({ close_buckets: "true" })],
    ["sealed as a number", text({ sealed: 1 })],
    ["canonical v2", text({ v: 2 })],
    ["a standing object of this kind", '{"action":"revoke","id":"01S","issued_at":"2026-11-23T10:00:00Z","kind":"bastion","login_user":"alice","nonce":"' + NONCE + '","object":"standing","requesting_host":"dev-1","standing_hours":0,"target":"bastion","ttl_seconds":0,"v":1}'],
    ["an ssh request carrying a level", '{"action":"approve","address":"192.0.2.21","id":"01R","issued_at":"2026-11-23T10:00:00Z","key_fingerprint":"k","kind":"ssh","level":"root","login_user":"alice","nonce":"' + NONCE + '","object":"request","principal":"alice@db-1","requesting_host":"dev-1","standing_hours":0,"target":"db-1","target_address":"192.0.2.61","target_port":22,"ttl_seconds":600,"v":1}'],
  ];
  for (const [name, t] of bad) {
    test(`refused: ${name}`, () => {
      expect(() => parseCanonical(t)).toThrow(CanonicalError);
    });
  }

  test("shared vectors (web/test/fixtures/bastion-vectors.json; the Go tests can read the same file)", () => {
    for (const v of vectors.valid) expect(parseCanonical(v.text).level).toBe(v.level);
    for (const v of vectors.invalid) expect(() => parseCanonical(v.text), v.why).toThrow(CanonicalError);
  });

  test("the open list encoding is sorted, distinct and exact", () => {
    expect(openList([])).toBe("[]");
    expect(openList(["b", "a", "b"])).toBe('["a","b"]');
    expect(openList(["personal/x", "SSH user CA", 'q"uote'])).toBe('["SSH user CA","personal/x","q\\"uote"]');
    expect(parseOpenList('["a","b"]')).toEqual(["a", "b"]);
    for (const t of ['["b","a"]', "[ ]", "null", '"a"', '["a",1]']) expect(() => parseOpenList(t)).toThrow(CanonicalError);
  });
});

describe("what the card showed must be what is signed", () => {
  const card = {
    action: "approve", object: "request", id: "01REQ", ttl_seconds: 1800, kind: "bastion", level: "root", requesting_host: "dev-1", host_id: "01ENROLLMENT", address: "192.0.2.21",
    target: "bastion", target_address: "192.0.2.10", target_port: 22, login_user: "alice", principal: "alice@bastion", key_fingerprint: "SHA256:key", ssh_ca: "SHA256:ca", host_key: "SHA256:host",
    cert_profile: "source-address;permit-pty", sealed: true, open_buckets: ["personal/paas/staging-env", "SSH user CA"], close_buckets: true, alert_channel: true,
  };
  const diff = (over: Fields, e: Fields = {}) => mismatches(parseCanonical(text(over)), { ...card, ...e } as never).map((m) => m.split(":")[0]);

  test("the matching text has no mismatch", () => {
    expect(diff({})).toEqual([]);
  });
  test("each signed fact is compared", () => {
    expect(diff({ open_buckets: '["SSH user CA"]' })).toEqual(["open_buckets"]);
    expect(diff({ open_buckets: '["SSH user CA","personal/paas/production-env","personal/paas/staging-env"]' })).toEqual(["open_buckets"]);
    expect(diff({ close_buckets: false })).toEqual(["close_buckets"]);
    expect(diff({ alert_channel: false })).toEqual(["alert_channel"]);
    expect(diff({ ttl_seconds: 3600 })).toEqual(["ttl_seconds"]);
    expect(diff({ host_id: "01OTHER" })).toEqual(["host_id"]);
    expect(diff({ ssh_ca: "SHA256:other" })).toEqual(["ssh_ca"]);
    expect(diff({ host_key: "SHA256:other" })).toEqual(["host_key"]);
    expect(diff({ address: "192.0.2.99" })).toEqual(["address"]);
    expect(diff({ target_address: "192.0.2.99" })).toEqual(["target_address"]);
    expect(diff({ key_fingerprint: "SHA256:other" })).toEqual(["key_fingerprint"]);
    expect(diff({ requesting_host: "web-1" })).toEqual(["requesting_host"]);
  });
  test("a root text for an inspect card, and the reverse", () => {
    const inspectCard = { level: "inspect", login_user: "aqmas-inspect", principal: "aqmas-inspect@bastion", cert_profile: "source-address;force-command", ttl_seconds: 1800, open_buckets: [], close_buckets: false, alert_channel: false };
    expect(diff({}, inspectCard)).toContain("level");
    expect(diff({ ...inspect, ttl_seconds: 1800 })).toContain("level");
  });
  test("an ssh text for a bastion card, and a bastion text for an ssh card", () => {
    const ssh = parseCanonical('{"action":"approve","address":"192.0.2.21","id":"01REQ","issued_at":"2026-11-23T10:00:00Z","key_fingerprint":"SHA256:key","kind":"ssh","login_user":"alice","nonce":"' + NONCE + '","object":"request","principal":"alice@bastion","requesting_host":"dev-1","standing_hours":0,"target":"bastion","target_address":"192.0.2.10","target_port":22,"ttl_seconds":1800,"v":1}');
    expect(mismatches(ssh, card as never).length).toBeGreaterThan(3);
    const sshCard = { action: "approve", object: "request", id: "01REQ", ttl_seconds: 1800, kind: "ssh", requesting_host: "dev-1", target: "bastion", login_user: "alice" };
    expect(mismatches(parseCanonical(text()), sshCard as never).map((m) => m.split(":")[0])).toContain("kind");
  });
  test("a deny must carry nothing", () => {
    const deny = parseCanonical(text({ action: "deny", ttl_seconds: 0, open_buckets: "[]", close_buckets: false, alert_channel: false }));
    expect(mismatches(deny, { ...card, action: "deny", ttl_seconds: undefined } as never)).toEqual([]);
  });
});

describe("bastion flows against the mock", () => {
  const m = startMock({ port: 0, distDir: null, seed: false });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  afterAll(() => void m.stop());
  const bodyOf = (suffix: string) => f.log.filter((x) => x.url.endsWith(suffix)).at(-1)!.body as Fields;

  test("sign in", async () => {
    await completeLogin(api, auth, await prepareLogin(api));
  });

  test("root approval: close_buckets is sent, signed, and the decision reports what was closed", async () => {
    const item = m.store.bastion.spawn("root");
    const p = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 900, closeBuckets: true });
    expect(bodyOf(`/requests/${item.id}/challenge`)).toEqual({ action: "approve", ttl_seconds: 900, close_buckets: true });
    expect(p.canonical.close_buckets).toBe(true);
    expect(p.description.bastion!.open).toEqual(["SSH user CA", "personal/paas/staging-env"]);
    const d = await decideBastion(api, auth, m.store.bastion.spawn("root"), { action: "approve", ttl_seconds: 600, closeBuckets: true });
    expect(d).toMatchObject({ kind: "bastion", status: "approved", level: "root", closed_count: 2, alert: "sent" });
    expect(m.store.bastion.open).toEqual([]);
    expect((await api.state()).bastion_root_until).toBeTruthy();
  });

  test("root approval without the choice, or the choice anywhere else, is refused before any request", async () => {
    const root = m.store.bastion.spawn("root");
    const n = f.log.length;
    await expect(prepareAction(api, targetForPending(root), { action: "approve", ttl_seconds: 600 })).rejects.toThrow(FlowError);
    const insp = m.store.bastion.spawn("inspect");
    await expect(prepareAction(api, targetForPending(insp), { action: "approve", ttl_seconds: 600, closeBuckets: true })).rejects.toThrow(/close-buckets/);
    await expect(prepareAction(api, targetForPending(root), { action: "deny", closeBuckets: false })).rejects.toThrow(FlowError);
    await expect(prepareAction(api, targetForPending(root), { action: "approve", ttl_seconds: 600, closeBuckets: true, standing_hours: 1 })).rejects.toThrow(/standing/);
    await expect(prepareAction(api, targetForPending(insp), { action: "approve" })).rejects.toThrow(/how long/);
    const ssh = m.store.spawnRequest();
    await expect(prepareAction(api, targetForPending(ssh), { action: "approve", ttl_seconds: 600, closeBuckets: true })).rejects.toThrow(/close-buckets/);
    expect(f.log.length).toBe(n);
  });

  test("inspect: no close_buckets on the wire; deny sends only the action", async () => {
    const insp = m.store.bastion.spawn("inspect");
    const d = await decideBastion(api, auth, insp, { action: "approve", ttl_seconds: 1800 });
    expect(bodyOf(`/requests/${insp.id}/challenge`)).toEqual({ action: "approve", ttl_seconds: 1800 });
    expect(d).toMatchObject({ status: "approved", level: "inspect", closed_count: 0 });
    const root = m.store.bastion.spawn("root");
    expect(await decideBastion(api, auth, root, { action: "deny" })).toMatchObject({ status: "denied" });
    expect(bodyOf(`/requests/${root.id}/challenge`)).toEqual({ action: "deny" });
  });

  test("a bucket opened since the card was drawn: the signed list differs, nothing is signed", async () => {
    m.store.bastion.open = ["SSH user CA"];
    const item = m.store.bastion.spawn("root");
    const target = targetForPending(item);
    m.store.bastion.open = ["SSH user CA", "personal/paas/production-env"];
    const gets = auth.gets.length;
    await expect(prepareAction(api, target, { action: "approve", ttl_seconds: 600, closeBuckets: false })).rejects.toThrow(/open_buckets/);
    expect(auth.gets.length).toBe(gets);
    // Read again (as the page does before the challenge) and it goes through.
    const p = await prepareAction(api, targetForPending(await api.request(item.id)), { action: "approve", ttl_seconds: 600, closeBuckets: false });
    expect(p.description.bastion).toMatchObject({ close: false, open: ["SSH user CA", "personal/paas/production-env"] });
  });

  test("the card said an alert channel exists, the signed text says none: refused", async () => {
    const item = m.store.bastion.spawn("root");
    const target = targetForPending(item);
    m.store.bastion.alertChannel = false;
    await expect(prepareAction(api, target, { action: "approve", ttl_seconds: 600, closeBuckets: true })).rejects.toThrow(/alert_channel/);
    m.store.bastion.alertChannel = true;
  });

  test("root TTL above the cap is refused by the server and never signed", async () => {
    const item = m.store.bastion.spawn("root", { ttl_requested: 3600, ttl_max: 3600 });
    await expect(prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 7200, closeBuckets: true })).rejects.toThrow();
  });

  test("a queued task is not a canonical request", () => {
    expect(() => targetForPending(m.store.bastion.spawnQueued())).toThrow(FlowError);
  });

  test("approving a queued task signs setup/run for its parameters and names the request", async () => {
    const item = m.store.bastion.spawnQueued("journal-vacuum", '{"keep_days":14}');
    const read = queuedSummary(item)!;
    expect(read.params).toEqual({ keep_days: 14 });
    const p = await prepareSetupTask(api, {}, "journal-vacuum", read.params, undefined, new URL(m.url).hostname);
    expect(p.params).toBe('{"keep_days":14}');
    expect(parseCanonical(p.canonicalText)).toMatchObject({ object: "setup", action: "run", id: "journal-vacuum", params: '{"keep_days":14}' });
    await completeSetupTask(api, auth, p, item.id);
    expect(bodyOf("/setup/journal-vacuum/run")["request"]).toBe(item.id);
    expect(m.store.bastion.answered.at(-1)).toEqual({ request: item.id, task: "journal-vacuum", params: '{"keep_days":14}' });
    expect(m.store.pending.some((x) => x.id === item.id)).toBe(false);
    const v = await api.setupGet!<SetupView>("");
    await new Promise((r) => setTimeout(r, 0));
    expect(v.tasks!.find((t) => t.id === "journal-vacuum")!.group).toBe("routine");
  });

  test("runSetupTask keeps its old signature and takes an optional request id", async () => {
    m.store.setup.current = null;
    const v = await api.setupGet!<SetupView>("");
    await runSetupTask(api, auth, v, "disk-usage", {}, undefined, new URL(m.url).hostname);
    expect("request" in bodyOf("/setup/disk-usage/run")).toBe(false);
  });

  test("dismiss", async () => {
    const item = m.store.bastion.spawnQueued();
    await api.dismissSetupRequest!(item.id);
    expect(m.store.bastion.dismissed).toContain(item.id);
  });
});

describe("parameters of the bastion and routine tasks (maint.Canonical's encoding)", () => {
  test("each task's exact text", () => {
    expect(canonicalParams("bastion-access", { ssh_ca: "SHA256:" + "A".repeat(43), admin_user: "alice", port: 22, address: "192.0.2.10", name: "bastion" })).toBe(
      '{"name":"bastion","address":"192.0.2.10","port":22,"admin_user":"alice","ssh_ca":"SHA256:' + "A".repeat(43) + '"}',
    );
    expect(canonicalParams("bastion-access-remove", {})).toBe("{}");
    expect(canonicalParams("bastion-allow", { hosts: [] })).toBe('{"hosts":[]}');
    expect(canonicalParams("bastion-allow", { hosts: [{ address: "192.0.2.22", name: "web-1", id: "01B" }, { id: "01A", name: "dev-1", address: "192.0.2.21" }] })).toBe(
      '{"hosts":[{"id":"01A","name":"dev-1","address":"192.0.2.21"},{"id":"01B","name":"web-1","address":"192.0.2.22"}]}',
    );
    expect(canonicalParams("os-update", { kernel: false })).toBe('{"kernel":false}');
    expect(canonicalParams("os-update", { kernel: true })).toBe('{"kernel":true}');
    expect(canonicalParams("journal-vacuum", { keep_days: 14 })).toBe('{"keep_days":14}');
    for (const t of ["reboot", "restart-cloudflared", "restart-broker", "disk-usage"]) expect(canonicalParams(t, {})).toBe("{}");
    for (const t of ["bastion-access", "bastion-allow", "os-update", "reboot", "journal-vacuum"]) expect(secretNames(t, { lock_alert: true })).toEqual([]);
  });

  test("outside the schema", () => {
    const bad: Array<[string, Record<string, unknown>]> = [
      ["os-update", {}],
      ["os-update", { kernel: "yes" }],
      ["os-update", { kernel: false, exclude: "kernel*" }],
      ["reboot", { force: true }],
      ["journal-vacuum", { keep_days: 0 }],
      ["journal-vacuum", { keep_days: 366 }],
      ["journal-vacuum", { keep_days: 1.5 }],
      ["journal-vacuum", { keep_days: "14" }],
      ["bastion-access", { name: "bastion", address: "192.0.2.10", port: "22", admin_user: "alice", ssh_ca: "x" }],
      ["bastion-access", { name: "bastion", address: "192.0.2.10", port: 22, admin_user: "alice" }],
      ["bastion-allow", {}],
      ["bastion-allow", { hosts: [{ id: "01A", name: "dev-1", address: "192.0.2.21", from: "*" }] }],
      ["bastion-allow", { hosts: [{ id: "01A", name: "dev-1", address: "192.0.2.21" }, { id: "01A", name: "dev-1", address: "192.0.2.22" }] }],
      ["bastion-allow", { hosts: ["01A"] }],
      ["shell", {}],
    ];
    for (const [task, p] of bad) expect(() => canonicalParams(task, p), `${task} ${JSON.stringify(p)}`).toThrow();
  });

  test("a queued request's text is accepted only in its canonical form", () => {
    expect(queuedParams("os-update", '{"kernel":false}')).toEqual({ kernel: false });
    for (const t of ['{"kernel": false}', '{"kernel":false,"x":1}', "[]", "nope", '{"keep_days":14}']) expect(() => queuedParams("os-update", t)).toThrow();
    expect(paramLines("os-update", { kernel: false })[0]).toContain("left alone");
    expect(paramLines("os-update", { kernel: true })[0]).toContain("Including the kernel");
    expect(paramLines("journal-vacuum", { keep_days: 14 })[0]).toContain("14 days");
  });

  test("the allowlist the page signs is the complete ticked list, sorted by enrollment", () => {
    const hosts = [
      { id: "01C", name: "laptop", address: "192.0.2.30", allowed: false },
      { id: "01A", name: "dev-1", address: "192.0.2.99", allowed: true, allowed_address: "192.0.2.21" },
      { id: "01B", name: "web-1", address: "192.0.2.22", allowed: false },
    ];
    expect(allowParams(hosts, new Set(["01C", "01A"]))).toEqual({ hosts: [{ id: "01A", name: "dev-1", address: "192.0.2.21" }, { id: "01C", name: "laptop", address: "192.0.2.30" }] });
    expect(allowParams(hosts, new Set())).toEqual({ hosts: [] });
  });
});
