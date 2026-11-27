// 0.11.0 logic against the mock: SSH keys (public line, create, hand-out, requests) and the
// bin (delete, restore, purge), with the canonical binding of every new action.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createApi, type Api } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth, testOpenSSHKey } from "./helpers";
import { BIN_SECONDS, canonicalJSON, newSetId, sshCommentProblem, sshDefaultComment, sshPublic, vaultCommit, vaultDelete, vaultPurge, vaultRestore, vaultSignDecision, vaultSignerCreate, vaultSshHandout, vaultSshKeyCreate, vaultStandingCap, type VaultState } from "../src/vault";
import type { SealView } from "../src/sealPanel";

type Json = Record<string, unknown>;
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
/** An Api whose challenge answers pass through `tamper` (a hostile or stale server). */
function tampering(api: Api, tamper: (canonical: Json, meta: Json, res: Json) => void): Api {
  return {
    ...api,
    vaultPost: async <T>(path: "attempt" | "challenge" | "finish", body: unknown) => {
      const res = (await api.vaultPost!<Json>(path, body)) as Json;
      if (path === "challenge") {
        const c = JSON.parse(res.canonical as string) as Json;
        const meta = JSON.parse(c.metadata as string) as Json;
        tamper(c, meta, res);
        c.metadata = canonicalJSON(meta);
        res.canonical = canonicalJSON(c);
      }
      return res as T;
    },
  };
}

describe("SSH public line and fingerprint", () => {
  // Public halves of two keys made with ssh-keygen for this test; the lines and fingerprints
  // are what `cat k.pub` and `ssh-keygen -lf k.pub` printed.
  const ED_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFM8SSRh9u01p5F4Tac41ZhBABr1Ow21M9Wcw0T3qIaJ aqmas:client-a/forge/deploy-key";
  const ED_FP = "SHA256:B25TaTh0rVrSMTParZ0CzGfj/XxPEw4pKPHY1SX+s/A";
  const EC_LINE = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJtr+nuJu1HyUBQbACSJTy8GM+nixhPF4ggBsAz4u0My2zve6GTHlMKUNXSQDkWHUUY6fgLuoguVr4h8H8ga45Q= test key";
  const EC_FP = "SHA256:+fh+EW9RY8fGReYtuTHQmBONWbYqUpaw3QjQMj9d5AQ";

  test("matches ssh-keygen for Ed25519 and ECDSA P-256", async () => {
    const ed = unb64(ED_LINE.split(" ")[1]!).subarray(-32);
    expect(await sshPublic("ssh-ed25519", ed, "aqmas:client-a/forge/deploy-key")).toEqual({ authorizedKey: ED_LINE, fingerprint: ED_FP });
    const ec = unb64(EC_LINE.split(" ")[1]!).subarray(-65);
    expect(await sshPublic("ssh-ecdsa-p256", ec, "test key")).toEqual({ authorizedKey: EC_LINE, fingerprint: EC_FP });
  });
  test("refuses a wrong length, an unknown type and a bad comment", async () => {
    await expect(sshPublic("ssh-ed25519", new Uint8Array(33), "c")).rejects.toThrow();
    await expect(sshPublic("ssh-ecdsa-p256", new Uint8Array(65), "c")).rejects.toThrow(); // no 0x04 prefix
    await expect(sshPublic("ssh-rsa", new Uint8Array(32), "c")).rejects.toThrow();
    await expect(sshPublic("ssh-ed25519", new Uint8Array(32), "two\nlines")).rejects.toThrow();
  });
  test("comment rule and default", () => {
    expect(sshDefaultComment("client-a", "forge", "deploy-key")).toBe("aqmas:client-a/forge/deploy-key");
    for (const ok of ["a", "aqmas:client-a/forge/deploy-key", "deploy key for the forge", "x".repeat(100)]) expect(sshCommentProblem(ok)).toBeNull();
    for (const bad of ["", " lead", "trail ", "tab\there", "new\nline", "café", "x".repeat(101)]) expect(sshCommentProblem(bad)).not.toBeNull();
  });
});

describe("SSH keys and the bin against the mock", () => {
  const m = startMock({ port: 0, distDir: null, vault: true });
  const api = createApi({ base: m.url, fetch: jarFetch() });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  const rp = new URL(m.url).hostname;
  let seal: SealView;
  let state: VaultState;
  const refresh = async () => {
    state = await api.vaultState!();
  };
  const pathOf = (s: { org_slug: string; service_slug: string; set_slug: string }) => `${s.org_slug}/${s.service_slug}/${s.set_slug}`;
  const set = (path: string) => state.sets.find((s) => pathOf(s) === path)!;
  const parent = () => {
    const s = set("client-a/paas/staging");
    return { org_id: s.org_id, org_slug: s.org_slug, org_title: s.org_title, service_id: s.service_id, service_slug: s.service_slug, service_title: s.service_title };
  };
  beforeAll(async () => {
    await completeLogin(api, auth, await prepareLogin(api));
    seal = await api.sealStatus!();
    await refresh();
  });
  afterAll(() => m.stop());

  test("the state names the key types and the bin's length", () => {
    expect(state.ssh_key_types!.map((t) => t.id)).toEqual(["ssh-ed25519", "ssh-ecdsa-p256"]);
    expect(state.bin_seconds).toBe(BIN_SECONDS);
    expect(state.deleted).toEqual([]);
  });

  test("create: generated in aqmas; the canonical carries the public line, comment and hand-out", async () => {
    const id = newSetId();
    const opts = { scheme: "ssh-ed25519", source: "generate" as const, comment: "aqmas:client-a/paas/deploy-key", handout: false };
    const node = { id, slug: "deploy-key", title: "Deploy key" };
    const tampers: ((c: Json, meta: Json, res: Json) => unknown)[] = [
      (_c, meta) => (meta.handout = true),
      (_c, meta) => (meta.comment = "other"),
      (_c, meta) => (meta.authorized_key = String(meta.authorized_key).replace("deploy-key", "other-key")),
      (_c, meta) => (meta.fingerprint = "SHA256:" + "A".repeat(43)),
      (_c, meta) => (meta.scheme = "ssh-ecdsa-p256"),
      (_c, meta) => (meta.source = "import"),
      (_c, meta) => (meta.set_slug = "other"),
      (_c, meta) => (meta.kind = "signer"),
      (_c, meta) => (meta.recipient = "x"),
      (_c, meta) => (meta.extra = 1),
      (_c, _meta, res) => ((res.facts as Json).authorized_key = "ssh-ed25519 AAAA other"),
      (c) => (c.action = "signer-create"),
    ];
    for (const t of tampers) await expect(vaultSshKeyCreate(tampering(api, t as never), seal, parent(), { ...node, id: newSetId() }, opts, rp)).rejects.toThrow();
    await expect(vaultSshKeyCreate(api, seal, parent(), node, { ...opts, comment: " bad" }, rp)).rejects.toThrow("Comment");
    await expect(vaultSshKeyCreate(api, seal, parent(), node, { ...opts, scheme: "ssh-rsa" }, rp)).rejects.toThrow("Unknown SSH key type");
    await expect(vaultSshKeyCreate(api, seal, parent(), node, { ...opts, privateKey: "x" }, rp)).rejects.toThrow("no input");
    const p = await vaultSshKeyCreate(api, seal, parent(), node, opts, rp);
    expect(p.authorizedKey).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43} aqmas:client-a\/paas\/deploy-key$/);
    expect(p.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    expect(p.detail).toContain(p.authorizedKey);
    const out = await p.tap(auth);
    expect(out).toMatchObject({ set_id: id, path: "client-a/paas/deploy-key", authorized_key: p.authorizedKey, fingerprint: p.fingerprint, handout: false });
    await refresh();
    const s = set("client-a/paas/deploy-key");
    expect(s).toMatchObject({ kind: "ssh-key", revision: 0, names: [], scheme: "ssh-ed25519", origin: "generated", authorized_key: p.authorizedKey, fingerprint: p.fingerprint, comment: opts.comment, handout: false, standing_cap_seconds: 0 });
    // The page's own derivation agrees with what the broker lists.
    expect(await sshPublic(s.scheme!, new Uint8Array(Buffer.from(s.public_key!, "base64url")), s.comment!)).toEqual({ authorizedKey: s.authorized_key!, fingerprint: s.fingerprint! });
  });

  test("create: a pasted OpenSSH private key is sealed here; ECDSA can be generated; a wrong key is refused", async () => {
    const k = testOpenSSHKey();
    const sent: Json[] = [];
    const spy: Api = { ...api, vaultPost: async <T>(path: "attempt" | "challenge" | "finish", body: unknown) => (sent.push(body as Json), api.vaultPost!<T>(path, body)) };
    const p = await vaultSshKeyCreate(spy, seal, parent(), { id: newSetId(), slug: "pasted-key", title: "Pasted key" }, { scheme: "ssh-ed25519", source: "import", privateKey: k.pem, comment: "pasted", handout: true }, rp);
    expect(JSON.stringify(sent)).not.toContain("OPENSSH");
    expect(JSON.stringify(sent)).not.toContain(k.pem.split("\n")[1]!);
    expect(p.authorizedKey).toBe((await sshPublic("ssh-ed25519", new Uint8Array(k.pub), "pasted")).authorizedKey);
    expect(p.detail).toContain("MAY BE HANDED OUT");
    expect((await p.tap(auth)).handout).toBe(true);
    await expect(vaultSshKeyCreate(api, seal, parent(), { id: newSetId(), slug: "wrong-type", title: "Wrong type" }, { scheme: "ssh-ecdsa-p256", source: "import", privateKey: k.pem, comment: "c", handout: false }, rp)).rejects.toThrow("private key (hex seed");
    await expect(vaultSshKeyCreate(api, seal, parent(), { id: newSetId(), slug: "no-key", title: "No key" }, { scheme: "ssh-ed25519", source: "import", privateKey: " ", comment: "c", handout: false }, rp)).rejects.toThrow("Paste");
    const ec = await vaultSshKeyCreate(api, seal, parent(), { id: newSetId(), slug: "ec-key", title: "EC key" }, { scheme: "ssh-ecdsa-p256", source: "generate", comment: "ec", handout: false }, rp);
    expect(ec.authorizedKey.startsWith("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY")).toBe(true);
    await ec.tap(auth);
    await refresh();
    expect(set("client-a/paas/pasted-key")).toMatchObject({ origin: "imported", handout: true });
    expect(set("client-a/paas/ec-key").scheme).toBe("ssh-ecdsa-p256");
  });

  test("an SSH key has no values, no limit and no reveal", async () => {
    const s = set("client-a/paas/deploy-key");
    await expect(vaultCommit(api, seal, s, { operation: "merge", entries: [{ name: "APP_KEY", value: "v" }], remove: [] }, rp)).rejects.toThrow();
    await expect(vaultStandingCap(api, seal, s, 0, rp)).rejects.toThrow();
  });

  test("hand-out setting: its own signed action, bound to the key and both values", async () => {
    const s = set("client-a/paas/deploy-key");
    await expect(vaultSshHandout(api, seal, s, false, rp)).rejects.toThrow("already");
    await expect(vaultSshHandout(api, seal, set("client-a/paas/staging"), true, rp)).rejects.toThrow("Not an SSH key");
    for (const t of [(_c: Json, meta: Json) => (meta.handout = false), (_c: Json, meta: Json) => (meta.old_handout = true), (_c: Json, meta: Json) => (meta.fingerprint = "SHA256:x"), (_c: Json, meta: Json) => (meta.set_id = set("client-a/paas/ec-key").set_id), (c: Json) => (c.action = "delete")])
      await expect(vaultSshHandout(tampering(api, t as never), seal, s, true, rp)).rejects.toThrow();
    const p = await vaultSshHandout(api, seal, s, true, rp);
    expect(p.detail).toContain("MAY be handed out");
    await p.tap(auth);
    await refresh();
    expect(set("client-a/paas/deploy-key").handout).toBe(true);
    await (await vaultSshHandout(api, seal, set("client-a/paas/deploy-key"), false, rp)).tap(auth);
    await refresh();
    expect(set("client-a/paas/deploy-key").handout).toBe(false);
  });

  test("ssh-agent and hand-out requests: the decision carries `use`, the SSH fingerprint and no artifacts", async () => {
    m.store.vault.addSshRequest("client-a/paas/deploy-key", "ssh-agent", "build-1", 3600, 20);
    m.store.vault.addSshRequest("client-a/paas/pasted-key", "ssh-handout");
    expect(() => m.store.vault.addSshRequest("client-a/paas/deploy-key", "ssh-handout")).toThrow("hand-out is off");
    await refresh();
    const agent = state.requests.find((r) => r.use === "ssh-agent")!;
    const handout = state.requests.find((r) => r.use === "ssh-handout")!;
    const setOf = (r: typeof agent) => state.sets.find((s) => s.set_id === r.set)!;
    expect(agent.items).toEqual([]);
    const tampers: ((c: Json, meta: Json) => unknown)[] = [
      (_c, meta) => delete meta.use,
      (_c, meta) => (meta.use = "ssh-handout"),
      (_c, meta) => (meta.ttl_seconds = 3600),
      (_c, meta) => (meta.max_signatures = 20),
      (_c, meta) => (meta.fingerprint = "0".repeat(64)),
      (_c, meta) => (meta.host = "other-host"),
      (_c, meta) => (meta.kind = "signer"),
      (_c, meta) => (meta.items as unknown[]).push({ name: "x", size: 1, sha256: "1".repeat(64) }),
      (c) => (c.id = handout.id),
    ];
    for (const t of tampers) await expect(vaultSignDecision(tampering(api, t as never), seal, setOf(agent), agent, "sign-approve", 600, 5, rp)).rejects.toThrow();
    // Limits: an agent grant is 1 minute up to what was asked; a hand-out is exactly once.
    for (const [ttl, max] of [[0, 20], [59, 5], [3601, 5], [600, 21], [600, 0]] as const) await expect(vaultSignDecision(api, seal, setOf(agent), agent, "sign-approve", ttl, max, rp)).rejects.toThrow("limits");
    for (const [ttl, max] of [[600, 1], [0, 2], [0, 0]] as const) await expect(vaultSignDecision(api, seal, setOf(handout), handout, "sign-approve", ttl, max, rp)).rejects.toThrow("limits");
    await expect(vaultSignDecision(api, seal, setOf(handout), agent, "sign-approve", 600, 5, rp)).rejects.toThrow("another SSH key");
    await expect(vaultSignDecision(api, seal, { ...setOf(agent), fingerprint: "SHA256:other" }, agent, "sign-approve", 600, 5, rp)).rejects.toThrow("another public key");
    // A signer's request cannot be decided as an SSH key's, nor the reverse.
    const signing = state.requests.find((r) => r.use === undefined)!;
    await expect(vaultSignDecision(api, seal, setOf(agent), signing, "sign-deny", 0, 0, rp)).rejects.toThrow();
    await expect(vaultSignDecision(api, seal, state.sets.find((s) => s.set_id === signing.set)!, agent, "sign-deny", 0, 0, rp)).rejects.toThrow();

    const a = await vaultSignDecision(api, seal, setOf(agent), agent, "sign-approve", 600, 5, rp);
    expect(a.detail).toContain("up to 5 SSH logins for 600 seconds");
    expect(a.detail).toContain(setOf(agent).fingerprint!);
    await a.tap(auth);
    const h = await vaultSignDecision(api, seal, setOf(handout), handout, "sign-approve", 0, 1, rp);
    expect(h.detail).toContain("HAND OUT THE PRIVATE KEY");
    expect(h.detail).toContain("cannot be recalled");
    await h.tap(auth);
    await refresh();
    expect(state.requests.find((r) => r.id === agent.id)).toMatchObject({ status: "approved", ttl_seconds: 600, max_signatures: 5 });
    expect(state.requests.find((r) => r.id === handout.id)).toMatchObject({ status: "approved", ttl_seconds: 0, max_signatures: 1 });
    await (await vaultSignDecision(api, seal, setOf(handout), state.requests.find((r) => r.id === handout.id)!, "sign-revoke", 0, 0, rp)).tap(auth);
    await refresh();
    expect(state.requests.some((r) => r.id === handout.id)).toBe(false);
  });

  test("delete: bound to path, kind and revision; ends the item's grants; the path is free", async () => {
    const s = set("client-a/paas/deploy-key");
    const tampers: ((c: Json, meta: Json) => unknown)[] = [
      (_c, meta) => (meta.path = "client-a/paas/other"),
      (_c, meta) => (meta.kind = "signer"),
      (_c, meta) => (meta.revision = 1),
      (_c, meta) => (meta.bin_seconds = 60),
      (_c, meta) => (meta.fingerprint = ""),
      (_c, meta) => (meta.set_id = set("client-a/paas/ec-key").set_id),
      (c) => (c.action = "purge"),
      (c) => (c.id = set("client-a/paas/ec-key").set_id),
    ];
    for (const t of tampers) await expect(vaultDelete(tampering(api, t as never), seal, s, rp)).rejects.toThrow();
    // A stale revision is refused by the broker before anything is signed.
    const env = set("client-a/paas/staging");
    await expect(vaultDelete(api, seal, { ...env, revision: env.revision - 1 }, rp)).rejects.toThrow("changed");
    const p = await vaultDelete(api, seal, s, rp);
    expect(p.detail).toContain("client-a/paas/deploy-key");
    expect(p.detail).toContain("7 days");
    const before = Date.now();
    const out = await p.tap(auth);
    expect(out.ok).toBe(true);
    expect(out.ended).toEqual({ grants: 1, standing: 0, releases: 0, pending: 0 }); // the ssh-agent grant approved above
    expect(out.purge_at).toBeGreaterThanOrEqual(before + BIN_SECONDS * 1000);
    await refresh();
    expect(set("client-a/paas/deploy-key")).toBeUndefined();
    expect(state.requests.some((r) => r.set === s.set_id)).toBe(false);
    expect(state.deleted!.length).toBe(1);
    expect(state.deleted![0]).toMatchObject({ set_id: s.set_id, set_slug: "deploy-key", kind: "ssh-key", revision: 0, fingerprint: s.fingerprint, authorized_key: s.authorized_key, path_taken: false, deleted_by: "Mock passkey" });
    expect(state.deleted![0]!.digest).toMatch(/^[0-9a-f]{64}$/);
    // Gone for the item routes, as if it never existed.
    await expect(api.vaultHistory!(s.set_id)).rejects.toThrow();
    await expect(vaultDelete(api, seal, s, rp)).rejects.toThrow();
  });

  test("restore: refused while a live item has the path, then puts the item back as it was", async () => {
    const d = state.deleted![0]!;
    // The path is free: a new key takes it.
    const again = newSetId();
    await (await vaultSshKeyCreate(api, seal, parent(), { id: again, slug: "deploy-key", title: "Deploy key 2" }, { scheme: "ssh-ed25519", source: "generate", comment: "second", handout: false }, rp)).tap(auth);
    await refresh();
    expect(state.deleted![0]!.path_taken).toBe(true);
    await expect(vaultRestore(api, seal, state.deleted![0]!, rp)).rejects.toThrow("Another item has that path");
    // The broker refuses too, whatever the page believed.
    await expect(vaultRestore(api, seal, { ...state.deleted![0]!, path_taken: false }, rp)).rejects.toThrow("live item");
    // Delete the newcomer (two items of the same path are in the bin), then restore the first.
    await (await vaultDelete(api, seal, set("client-a/paas/deploy-key"), rp)).tap(auth);
    await refresh();
    expect(state.deleted!.map((x) => x.set_id).sort()).toEqual([d.set_id, again].sort());
    const first = state.deleted!.find((x) => x.set_id === d.set_id)!;
    for (const t of [(_c: Json, meta: Json) => (meta.deleted_at = 1), (_c: Json, meta: Json) => (meta.path = "client-a/paas/x"), (_c: Json, meta: Json) => (meta.set_id = again), (_c: Json, meta: Json) => (meta.digest = first.digest), (c: Json) => (c.action = "purge")])
      await expect(vaultRestore(tampering(api, t as never), seal, first, rp)).rejects.toThrow();
    await (await vaultRestore(api, seal, first, rp)).tap(auth);
    await refresh();
    expect(set("client-a/paas/deploy-key")).toMatchObject({ set_id: d.set_id, kind: "ssh-key", fingerprint: d.fingerprint, handout: false });
    expect(state.requests.some((r) => r.set === d.set_id)).toBe(false); // the grant did not come back
    expect(state.deleted!.find((x) => x.set_id === again)!.path_taken).toBe(true);
  });

  test("purge: bound to the digest; destroys the binned item; seven days do it without a tap", async () => {
    const d = state.deleted![0]!;
    for (const t of [(_c: Json, meta: Json) => (meta.digest = "0".repeat(64)), (_c: Json, meta: Json) => delete meta.digest, (_c: Json, meta: Json) => (meta.deleted_at = 1), (_c: Json, meta: Json) => (meta.kind = "secret"), (c: Json) => (c.action = "restore")])
      await expect(vaultPurge(tampering(api, t as never), seal, d, rp)).rejects.toThrow();
    await expect(vaultPurge(api, seal, { ...d, digest: "short" }, rp)).rejects.toThrow("digest");
    const p = await vaultPurge(api, seal, d, rp);
    expect(p.detail).toContain("PURGE");
    await p.tap(auth);
    await refresh();
    expect(state.deleted).toEqual([]);
    await expect(vaultRestore(api, seal, d, rp)).rejects.toThrow();
    // An env set with values: delete it, let the seven days pass, and it is gone for good.
    const env = set("club/website/deploy");
    await (await vaultDelete(api, seal, env, rp)).tap(auth);
    await refresh();
    expect(state.deleted![0]).toMatchObject({ kind: "env-set", names: ["APP_ID", "DEPLOY_TOKEN"], revision: 2 });
    expect(state.deleted![0]!.fingerprint).toBeUndefined();
    m.store.vault.deleted[0]!.purge_at = Date.now() - 1;
    await refresh();
    expect(state.deleted).toEqual([]);
    expect(set("club/website/deploy")).toBeUndefined();
  });

  test("the mock answers like the broker: one key one family, hand-out re-checked at approval, a late restore is a conflict", async () => {
    // The same private key as a signing key and as an SSH key is refused, both ways.
    const seed = "42".repeat(32);
    await (await vaultSignerCreate(api, seal, parent(), { id: newSetId(), slug: "plain-key", title: "Plain key" }, "ed25519", "import", seed, rp)).tap(auth);
    await expect(vaultSshKeyCreate(api, seal, parent(), { id: newSetId(), slug: "same-key", title: "Same key" }, { scheme: "ssh-ed25519", source: "import", privateKey: seed, comment: "c", handout: false }, rp)).rejects.toThrow("already holds this key as a signing key");
    const other = "17".repeat(32);
    await (await vaultSshKeyCreate(api, seal, parent(), { id: newSetId(), slug: "seed-key", title: "Seed key" }, { scheme: "ssh-ed25519", source: "import", privateKey: other, comment: "c", handout: true }, rp)).tap(auth);
    await expect(vaultSignerCreate(api, seal, parent(), { id: newSetId(), slug: "same-signer", title: "Same signer" }, "ed25519", "import", other, rp)).rejects.toThrow("already holds this key as an SSH key");
    // A hand-out request whose key lost the setting cannot be approved.
    m.store.vault.addSshRequest("client-a/paas/seed-key", "ssh-handout");
    m.store.vault.sets.find((x) => x.set_slug === "seed-key")!.handout = false;
    await refresh();
    const req = state.requests.find((r) => r.use === "ssh-handout" && r.status === "pending" && r.set === set("client-a/paas/seed-key").set_id)!;
    await expect(vaultSignDecision(api, seal, set("client-a/paas/seed-key"), req, "sign-approve", 0, 1, rp)).rejects.toThrow("no longer be handed out");
    await (await vaultSignDecision(api, seal, set("client-a/paas/seed-key"), req, "sign-deny", 0, 0, rp)).tap(auth);
    // Past its deadline but not swept yet: restore is a conflict, as on the broker.
    await (await vaultDelete(api, seal, set("client-a/paas/seed-key"), rp)).tap(auth);
    const late = { ...(await api.vaultState!()).deleted!.find((d) => d.set_slug === "seed-key")! };
    m.store.vault.deleted.find((d) => d.set_slug === "seed-key")!.purge_at = Date.now() - 1;
    await expect(vaultRestore(api, seal, late, rp)).rejects.toThrow("seven days are over");
    await refresh();
    expect(state.deleted!.some((d) => d.set_slug === "seed-key")).toBe(false);
  });
});

describe("wording", () => {
  test("time left in the bin", async () => {
    const { timeLeft } = await import("../src/vaultPage");
    const h = 3_600_000;
    expect(timeLeft(7 * 24 * h)).toBe("7 days");
    expect(timeLeft(7 * 24 * h - 60_000)).toBe("7 days");
    expect(timeLeft(6 * 24 * h + 2 * h)).toBe("6 days 2 hours");
    expect(timeLeft(25 * h)).toBe("1 day 1 hour");
    expect(timeLeft(5 * h)).toBe("5 hours");
    expect(timeLeft(30 * 60_000)).toBe("30 min");
    expect(timeLeft(0)).toBe("a moment");
  });
  test("activity rows for the new actions", async () => {
    const { classify } = await import("../src/audit");
    const row = (actor: string, action: string) => classify({ at: "2026-11-26T10:00:00Z", actor, action, object: "set:x", detail: "" }).label;
    expect(row("owner", "vault_ssh_key_create")).toBe("SSH key created");
    expect(row("owner", "vault_ssh_key_handout")).toBe("SSH key hand-out setting changed");
    expect(row("owner", "vault_delete")).toBe("Item deleted (in the bin)");
    expect(row("owner", "vault_restore")).toBe("Item restored");
    expect(row("system", "vault_purge")).toBe("Item purged for good");
    expect(row("host:build-1", "ssh_request")).toBe("SSH key use requested");
    expect(classify({ at: "2026-11-26T10:00:00Z", actor: "host:build-1", action: "ssh_key_collect", object: "grant:x", detail: "" })).toMatchObject({ kind: "warning", label: "SSH private key handed out" });
  });
});
