// Settings → Setup, DOM-free: the parameter encoding the runner accepts, sealed packets, the
// recovery key made in the browser, and the pre-signing checks of a setup run.
import { afterAll, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { createApi, type Api } from "../src/api";
import { decode, encode } from "../src/b64url";
import { parseCanonical } from "../src/canonical";
import { completeLogin, prepareLogin } from "../src/flows";
import {
  ageRecipientProblem,
  canonicalParams,
  drillInfo,
  generateAgeIdentity,
  packetHash,
  prepareSetupTask,
  runSetupTask,
  sealPacket,
  secretsInfo,
  sendDrill,
  type SetupView,
} from "../src/setup";
import { bech32Decode, recipientOf } from "../mock/age";
import { startMock } from "../mock/server";
import { fakeAuth, jarFetch, prfAuth } from "./helpers";
import { stagePlan, stageStep } from "../src/setup";
import { prepareControl } from "../src/sealPanel";
import { deriveKEK } from "../src/buckets";
import { wrapKeyBytes } from "../src/seal";
import type { StageView } from "../src/sealPanel";

const te = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) => Buffer.from(b as ArrayBuffer).toString("hex");
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const HOST_A = "forge.example.com ecdsa-sha2-nistp256 " + "A".repeat(60);
const HOST_B = "forge.example.com ssh-ed25519 " + "B".repeat(44);
const UPDATES = { repo: "ssh://git@forge.example.com/owner/agent-quartermaster.git", github_api: "https://api.github.com/repos/owner/agent-quartermaster", second_api: "https://forge.example.com/api/v1/repos/owner/agent-quartermaster" };

describe("canonicalParams: exactly Go's json.Marshal of the typed parameters", () => {
  test("cutover", () => {
    expect(canonicalParams("cutover", {})).toBe("{}");
    expect(() => canonicalParams("cutover", { force: true })).toThrow();
  });

  test("seal: fixed key order whatever order the caller used", () => {
    const recipient = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj";
    expect(canonicalParams("seal", { lock_alert: false, recipient, purge_backups: true })).toBe(`{"recipient":"${recipient}","purge_backups":true,"lock_alert":false}`);
    expect(() => canonicalParams("seal", { recipient, purge_backups: "yes", lock_alert: false })).toThrow();
    expect(() => canonicalParams("seal", { recipient, purge_backups: true })).toThrow();
    expect(() => canonicalParams("seal", { recipient, purge_backups: true, lock_alert: false, identity: "x" })).toThrow();
  });

  test("buckets: exactly {\"purge_backups\":bool}", () => {
    expect(canonicalParams("buckets", { purge_backups: true })).toBe('{"purge_backups":true}');
    expect(canonicalParams("buckets", { purge_backups: false })).toBe('{"purge_backups":false}');
    expect(() => canonicalParams("buckets", {})).toThrow();
    expect(() => canonicalParams("buckets", { purge_backups: "yes" })).toThrow();
    expect(() => canonicalParams("buckets", { purge_backups: true, rollback: true })).toThrow();
  });

  test("enable-updates: known_hosts sorted, flags last, no HTML escaping", () => {
    expect(canonicalParams("enable-updates", { ...UPDATES, github_token: true, second_token: false, known_hosts: [HOST_B, HOST_A] })).toBe(
      `{"repo":"${UPDATES.repo}","github_api":"${UPDATES.github_api}","second_api":"${UPDATES.second_api}","known_hosts":["${HOST_A}","${HOST_B}"],"github_token":true,"second_token":false}`,
    );
    // GitHub only: an HTTPS repository, no second source, no host keys, no tokens.
    expect(canonicalParams("enable-updates", { repo: "https://github.com/owner/agent-quartermaster.git", github_api: UPDATES.github_api, second_api: "", known_hosts: [], github_token: false, second_token: false })).toBe(
      `{"repo":"https://github.com/owner/agent-quartermaster.git","github_api":"${UPDATES.github_api}","second_api":"","known_hosts":[],"github_token":false,"second_token":false}`,
    );
    expect(canonicalParams("enable-updates", { repo: "a&b<c>", github_api: 'q"\\', second_api: " ", known_hosts: [], github_token: false, second_token: false })).toBe(
      '{"repo":"a&b<c>","github_api":"q\\"\\\\","second_api":"\\u2028","known_hosts":[],"github_token":false,"second_token":false}',
    );
    expect(() => canonicalParams("enable-updates", { ...UPDATES, known_hosts: [1], github_token: false, second_token: false })).toThrow();
  });

  test("sync-passkeys: pins in the order given", () => {
    const pins = [
      { key_sha256: "b".repeat(64), id: "cred-two-xxxxxxxxxxxx" },
      { id: "cred-one-xxxxxxxxxxxx", key_sha256: "a".repeat(64) },
    ];
    expect(canonicalParams("sync-passkeys", { pins })).toBe(`{"pins":[{"id":"cred-two-xxxxxxxxxxxx","key_sha256":"${"b".repeat(64)}"},{"id":"cred-one-xxxxxxxxxxxx","key_sha256":"${"a".repeat(64)}"}]}`);
    expect(canonicalParams("sync-passkeys", { pins: [] })).toBe('{"pins":[]}');
    expect(() => canonicalParams("sync-passkeys", { pins: [{ id: "x", key_sha256: "y", name: "z" }] })).toThrow();
  });

  test("unknown tasks (and the upgrade, which is signed as an update) have no parameters", () => {
    expect(() => canonicalParams("upgrade", {})).toThrow();
    expect(() => canonicalParams("rm -rf", {})).toThrow();
  });
});

describe("sealed packets", () => {
  test("info strings", () => {
    expect(hex(secretsInfo("seal"))).toBe(hex(te.encode("aqmas-setup-secrets-v1\0seal")));
    const id = crypto.getRandomValues(new Uint8Array(32));
    const info = drillInfo(encode(id));
    expect(hex(info.slice(0, 20))).toBe(hex(te.encode("aqmas-seal-drill-v1\0")));
    expect(hex(info.slice(20))).toBe(hex(id));
    expect(info.length).toBe(52);
    expect(() => drillInfo(encode(new Uint8Array(31)))).toThrow();
  });

  test("round trip: enc || ciphertext opens with the recipient key and the same info; the hash is over the raw packet", async () => {
    const pair = await suite.kem.generateKeyPair();
    const pub = encode(await suite.kem.serializePublicKey(pair.publicKey));
    const plaintext = te.encode('{"ntfy_token":"tk_secret","ntfy_topic_url":"https://ntfy.example.com/t"}');
    const packet = await sealPacket(pub, secretsInfo("seal"), plaintext);
    expect(packet).toMatch(/^[A-Za-z0-9_-]+$/);
    const raw = new Uint8Array(decode(packet));
    expect(raw.length).toBe(65 + plaintext.length + 16);
    const open = async (info: Uint8Array) => {
      const ctx = await suite.createRecipientContext({ recipientKey: pair.privateKey, enc: raw.slice(0, 65).buffer, info: info.slice().buffer });
      return new Uint8Array(await ctx.open(raw.slice(65).buffer));
    };
    expect(hex(await open(secretsInfo("seal")))).toBe(hex(plaintext));
    await expect(open(secretsInfo("enable-updates"))).rejects.toThrow();
    expect(await packetHash(packet)).toBe(hex(await crypto.subtle.digest("SHA-256", raw)));
    expect(await packetHash(packet)).toMatch(/^[0-9a-f]{64}$/);
    // A fresh ephemeral key every time.
    expect(await sealPacket(pub, secretsInfo("seal"), plaintext)).not.toBe(packet);
    await expect(sealPacket(encode(new Uint8Array(65)), secretsInfo("seal"), plaintext)).rejects.toThrow();
  });
});

describe("the recovery key made in the browser", () => {
  test("is a native age X25519 identity: HRPs, case, lengths, checksums, and the recipient is its public key", async () => {
    for (let i = 0; i < 8; i++) {
      const { identity, recipient } = await generateAgeIdentity();
      expect(identity).toMatch(/^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}$/);
      expect(recipient).toMatch(/^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$/);
      expect(identity.length).toBe(74);
      expect(recipient.length).toBe(62);
      const id = bech32Decode(identity); // throws on a bad checksum
      const rc = bech32Decode(recipient);
      expect(id.hrp).toBe("age-secret-key-");
      expect(rc.hrp).toBe("age");
      expect(id.data.length).toBe(32);
      expect(rc.data.length).toBe(32);
      // Derived independently: X25519(scalar, base point).
      expect(hex((await recipientOf(identity)).publicKey)).toBe(hex(rc.data));
      expect(ageRecipientProblem(recipient)).toBeNull();
    }
    const a = await generateAgeIdentity();
    const b = await generateAgeIdentity();
    expect(a.identity).not.toBe(b.identity);
  });

  test("agrees with age's own test key, and catches typing errors in a pasted public key", async () => {
    // filippo.io/age's well-known pair (the scalar is 32 bytes of 0x42).
    const recipient = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj";
    const { publicKey, scalar } = await recipientOf("AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX");
    expect(hex(scalar)).toBe("42".repeat(32));
    expect(hex(publicKey)).toBe(hex(bech32Decode(recipient).data));
    expect(ageRecipientProblem(recipient)).toBeNull();
    expect(ageRecipientProblem(recipient.replace("zvky", "zvkz"))).toContain("checksum");
    expect(ageRecipientProblem("AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX")).toContain("secret half");
    expect(ageRecipientProblem("age1short")).not.toBeNull();
  });

  test("nothing in the setup code stores anything in the browser", async () => {
    for (const f of ["setup.ts", "setupPage.ts"]) {
      const text = await readFile(join(import.meta.dir, "..", "src", f), "utf8");
      for (const sink of ["localStorage", "sessionStorage", "indexedDB", "document.cookie"]) expect({ f, sink, found: text.includes(sink) }).toEqual({ f, sink, found: false });
    }
  });
});

describe("signing a setup task", () => {
  const m = startMock({ port: 0, distDir: null, setupStepMs: 20 });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  const view = () => api.setupGet!<SetupView>("");
  afterAll(() => m.stop());

  /** An Api whose challenge answer is the mock's, altered. */
  async function tampered(task: string, params: Record<string, unknown>, alter: (r: { challenge_id: string; canonical: string; public_key: { publicKey: Record<string, unknown> } }) => Promise<void> | void) {
    const posts: string[] = [];
    const fake = {
      setupPost: async (path: string, body: unknown) => {
        posts.push(path);
        if (!path.endsWith("/challenge")) throw new Error("must not be reached");
        const r = await api.setupPost!<{ challenge_id: string; canonical: string; public_key: { publicKey: Record<string, unknown> } }>(path, body);
        await alter(r);
        return r;
      },
    } as unknown as Api;
    const a = fakeAuth(m.url);
    await expect(runSetupTask(fake, a, await view(), task, params, undefined, "127.0.0.1")).rejects.toThrow(/Not signing/);
    expect(a.gets.length).toBe(0); // the passkey was never asked
    expect(posts).toEqual([`/${task}/challenge`]);
  }
  const recommit = async (r: { canonical: string; public_key: { publicKey: Record<string, unknown> } }, c: Record<string, unknown>) => {
    r.canonical = JSON.stringify(c, Object.keys(c).sort());
    r.public_key.publicKey["challenge"] = encode(await crypto.subtle.digest("SHA-256", te.encode(r.canonical)));
  };

  test("sign in", async () => {
    await completeLogin(api, auth, await prepareLogin(api));
    expect((await view()).tasks!.filter((t) => !t.group).map((t) => t.id)).toEqual(["cutover", "seal", "buckets", "enable-updates", "sync-passkeys", "upgrade"]);
  });

  test("refuses to sign when the server's text differs: params, task, secrets hash, an extra key, the challenge, the options", async () => {
    const pins = (await view()).passkeys!.slice(0, 2).map((k) => ({ id: k.credential, key_sha256: k.key_sha256 }));
    // Other parameters than the ones chosen (one pin dropped), properly re-committed.
    await tampered("sync-passkeys", { pins }, async (r) => {
      const c = JSON.parse(r.canonical);
      c.params = canonicalParams("sync-passkeys", { pins: pins.slice(0, 1) });
      await recommit(r, c);
    });
    // The same parameters in another key order are not the canonical encoding either.
    await tampered("sync-passkeys", { pins }, async (r) => {
      const c = JSON.parse(r.canonical);
      c.params = JSON.stringify({ pins: pins.map((p) => ({ key_sha256: p.key_sha256, id: p.id })) });
      await recommit(r, c);
    });
    // Another task.
    await tampered("cutover", {}, async (r) => {
      const c = JSON.parse(r.canonical);
      c.id = "seal";
      await recommit(r, c);
    });
    // A secrets packet nobody chose.
    await tampered("cutover", {}, async (r) => {
      const c = JSON.parse(r.canonical);
      c.secrets_sha256 = "a".repeat(64);
      await recommit(r, c);
    });
    // A field this page cannot describe.
    await tampered("cutover", {}, async (r) => {
      const c = JSON.parse(r.canonical);
      c.command = "curl example.com | sh";
      await recommit(r, c);
    });
    // Another object or action, another version.
    await tampered("cutover", {}, async (r) => recommit(r, { ...JSON.parse(r.canonical), object: "update" }));
    await tampered("cutover", {}, async (r) => recommit(r, { ...JSON.parse(r.canonical), action: "approve" }));
    await tampered("cutover", {}, async (r) => recommit(r, { ...JSON.parse(r.canonical), v: 2 }));
    // Not byte-canonical (keys unsorted), although the challenge commits to it.
    await tampered("cutover", {}, async (r) => {
      const c = JSON.parse(r.canonical);
      r.canonical = JSON.stringify(c, Object.keys(c).sort().reverse());
      r.public_key.publicKey["challenge"] = encode(await crypto.subtle.digest("SHA-256", te.encode(r.canonical)));
    });
    // A challenge that does not commit to the text shown.
    await tampered("cutover", {}, (r) => void (r.public_key.publicKey["challenge"] = encode(crypto.getRandomValues(new Uint8Array(32)))));
    // Weakened or foreign request options.
    await tampered("cutover", {}, (r) => void (r.public_key.publicKey["userVerification"] = "preferred"));
    await tampered("cutover", {}, (r) => void (r.public_key.publicKey["rpId"] = "evil.example.com"));
    await tampered("cutover", {}, (r) => void (r.public_key.publicKey["extensions"] = { prf: {} }));
    expect(m.store.setup.received.length).toBe(0);
    expect(m.store.setup.current).toBeNull();
  });

  test("refuses secrets that the chosen options do not call for, before any request", async () => {
    const recipient = (await generateAgeIdentity()).recipient;
    const v = await view();
    const n = f.log.length;
    await expect(runSetupTask(api, auth, v, "seal", { recipient, purge_backups: true, lock_alert: false }, { ntfy_token: "tk_12345678" })).rejects.toThrow(/do not match/);
    await expect(runSetupTask(api, auth, v, "seal", { recipient, purge_backups: true, lock_alert: true }, {})).rejects.toThrow(/do not match/);
    await expect(runSetupTask(api, auth, { ...v, secrets_key: undefined }, "seal", { recipient, purge_backups: true, lock_alert: true }, { ntfy_token: "tk_12345678", ntfy_topic_url: "https://ntfy.example.com/t" })).rejects.toThrow(/key to seal/);
    expect(f.log.length).toBe(n);
  });

  test("a run without secrets: what is signed is exactly the derived text, and the runner gets it", async () => {
    const before = auth.gets.length;
    await runSetupTask(api, auth, await view(), "cutover", {}, undefined, "127.0.0.1");
    expect(auth.gets.length).toBe(before + 1);
    const challenge = [...f.log].reverse().find((x) => x.url.endsWith("/api/ui/setup/cutover/challenge"))!;
    expect(challenge.body).toEqual({ params: {}, secrets_sha256: "" });
    const run = f.log.at(-1)!;
    expect(run.url.endsWith("/api/ui/setup/cutover/run")).toBe(true);
    expect((run.body as { secrets: string }).secrets).toBe("");
    expect(m.store.setup.received.at(-1)).toEqual({ task: "cutover", params: "{}", secrets: {} });
    expect((await view()).tasks![0]!.state).toMatch(/running|waiting/);
    // Let the fake runner reach the fenced review, then put everything back.
    for (let i = 0; i < 100 && (await view().catch(() => null))?.current?.state !== "waiting"; i++) await new Promise((r) => setTimeout(r, 10));
    await api.setupPost!("/cancel", {});
    for (let i = 0; i < 100 && (await view().catch(() => null))?.mode !== "serve"; i++) await new Promise((r) => setTimeout(r, 10));
    expect((await view()).tasks![0]!.state).toBe("failed");
  });

  test("secrets leave the page only inside the sealed packet", async () => {
    m.store.setup.scoped = true;
    const secrets = { ntfy_topic_url: "https://ntfy.example.com/aqmas-LOCK-topic-9f3", ntfy_token: "tk_SUPERSECRET_publish_only_77" };
    const { recipient } = await generateAgeIdentity();
    const start = f.log.length;
    await runSetupTask(api, auth, await view(), "seal", { lock_alert: true, purge_backups: false, recipient }, { ...secrets }, "127.0.0.1");
    const sent = f.log.slice(start);
    const wire = JSON.stringify(sent.map((x) => [x.url, x.body, [...x.headers.entries()]]));
    for (const s of Object.values(secrets)) expect(wire.includes(s)).toBe(false);
    expect(wire.includes("SUPERSECRET")).toBe(false);
    const challenge = sent.find((x) => x.url.endsWith("/seal/challenge"))!.body as { params: unknown; secrets_sha256: string };
    const run = sent.find((x) => x.url.endsWith("/seal/run"))!.body as { secrets: string; challenge_id: string; assertion: unknown };
    expect(Object.keys(run).sort()).toEqual(["assertion", "challenge_id", "secrets"]);
    expect(challenge.params).toEqual({ recipient, purge_backups: false, lock_alert: true });
    expect(challenge.secrets_sha256).toBe(await packetHash(run.secrets));
    // The runner, holding the private key, reads exactly what was typed; the signed text binds the packet.
    const got = m.store.setup.received.at(-1)!;
    expect(got.secrets).toEqual(secrets);
    expect(got.params).toBe(`{"recipient":"${recipient}","purge_backups":false,"lock_alert":true}`);
    const signed = m.store.challenges.get(run.challenge_id)!.canonicalText!;
    const c = parseCanonical(signed);
    expect(c).toMatchObject({ v: 1, object: "setup", action: "run", id: "seal", params: got.params, secrets_sha256: challenge.secrets_sha256 });
    expect(Object.keys(c).sort()).toEqual(["action", "id", "issued_at", "nonce", "object", "params", "secrets_sha256", "v"]);
    expect(encode(auth.gets.at(-1)!.challenge as ArrayBuffer)).toBe(encode(await crypto.subtle.digest("SHA-256", te.encode(signed))));
  });

  test("the recovery drill: the identity travels sealed to the import, and only the right one passes", async () => {
    const s = m.store.setup;
    const mine = await generateAgeIdentity();
    const other = await generateAgeIdentity();
    s.stop();
    s.downUntil = 0;
    s.jump(new URLSearchParams("scoped=1&mode=seal-setup&wrap=tested"));
    s.recipient = mine.recipient;
    const seal = await api.sealStatus!();
    expect(seal.mode).toBe("setup");
    expect(seal.stage!.drilled).toBe(false);
    const key = { drill_key: seal.stage!.drill_key, installation: seal.installation };
    await expect(sendDrill(api, key, other.identity)).rejects.toThrow(/not the recovery key/);
    expect(s.drilled).toBe(false);
    const start = f.log.length;
    await sendDrill(api, key, `  ${mine.identity}\n`);
    const sent = f.log.slice(start);
    expect(s.drilled).toBe(true);
    expect((await api.sealStatus!()).stage!.drilled).toBe(true);
    expect(sent.length).toBe(1);
    expect(sent[0]!.url.endsWith("/api/ui/seal/drill")).toBe(true);
    expect(Object.keys(sent[0]!.body as object)).toEqual(["packet"]);
    expect(JSON.stringify(sent[0]!.body).includes("AGE-SECRET-KEY")).toBe(false);
    await expect(sendDrill(api, { installation: seal.installation }, mine.identity)).rejects.toThrow();
  });

  test("prepareSetupTask leaves the passkey alone and reports what will be signed", async () => {
    const s = m.store.setup;
    s.jump(new URLSearchParams("mode=serve&scoped=1"));
    s.mode = "serve";
    s.activated = false;
    const v = await view();
    const pins = v.passkeys!.map((k) => ({ id: k.credential, key_sha256: k.key_sha256 }));
    const before = auth.gets.length;
    const p = await prepareSetupTask(api, v, "sync-passkeys", { pins }, undefined, "127.0.0.1");
    expect(auth.gets.length).toBe(before);
    expect(p.params).toBe(canonicalParams("sync-passkeys", { pins }));
    expect(JSON.parse(p.canonicalText).params).toBe(p.params);
    expect(p.packet).toBe("");
    expect(p.secretsHash).toBe("");
    expect(p.validUntil).toBeGreaterThan(Date.now());
  });
});

describe("host key fingerprint", () => {
  test("is computed from the key itself, as OpenSSH prints it", async () => {
    const { hostKeyFingerprint } = await import("../src/setup");
    // ssh-keygen -lf on this line prints SHA256:fwpJzbd7GzTJbyNj4tyVpuWqcp+HsH4o+j2CCD+eLZM
    const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGilJAtWZP1K8q90h5+KBdPRC0+wBFVVtHkOZQLmI9jB";
    const raw = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    const want = "SHA256:" + Buffer.from(new Uint8Array(await crypto.subtle.digest("SHA-256", raw))).toString("base64").replace(/=+$/, "");
    expect(await hostKeyFingerprint(`forge.example.com ssh-ed25519 ${blob}`)).toBe(want);
    expect(want).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    await expect(hostKeyFingerprint("forge.example.com ssh-ed25519 not-base64!")).rejects.toThrow();
  });
});

describe("the stage plan", () => {
  const sc = (scope: string, wrapped = false, tested = false) => ({ scope, title: scope, buckets: 1, wrapped, tested });
  const st = (over: Partial<StageView>): StageView => ({ source: "unsealed", scopes: [], drilled: false, drill_key: "", choices: [], ...over });
  test("seal import: two scopes per create tap, then two per test tap", () => {
    let p = stagePlan(st({ scopes: [sc("installation"), sc("a"), sc("b")] }));
    expect(p).toMatchObject({ migrate: false, next: { step: "create", scopes: ["installation", "a"] }, tap: 1, taps: 4 });
    p = stagePlan(st({ scopes: [sc("installation", true), sc("a", true), sc("b")] }));
    expect(p).toMatchObject({ next: { step: "create", scopes: ["b"] }, tap: 2 });
    p = stagePlan(st({ scopes: [sc("installation", true), sc("a", true), sc("b", true)] }));
    expect(p).toMatchObject({ next: { step: "test", scopes: ["installation", "a"] }, tap: 3, created: true, tested: false });
    p = stagePlan(st({ scopes: [sc("installation", true, true), sc("a", true, true), sc("b", true, true)] }));
    expect(p).toMatchObject({ next: null, tested: true });
  });
  test("migration: the open-legacy tap carries exactly the installation scope first", () => {
    let p = stagePlan(st({ source: "format-1", legacy_unlocked: false, scopes: [sc("a"), sc("installation"), sc("b")] }));
    expect(p).toMatchObject({ migrate: true, next: { step: "open-legacy", scopes: ["installation"] }, tap: 1, taps: 4 });
    p = stagePlan(st({ source: "format-1", legacy_unlocked: true, scopes: [sc("a"), sc("installation", true), sc("b")] }));
    expect(p).toMatchObject({ next: { step: "create", scopes: ["a", "b"] }, tap: 2 });
  });
});

describe("the staged store against the mock", () => {
  const m = startMock({ port: 0, distDir: null, setupStepMs: 20 });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const rp = "127.0.0.1";
  // The seeded "iPhone" passkey (mock/server.ts seedCred(1)), with a PRF.
  const pk = prfAuth(m.url, { rawId: new Uint8Array(createHash("sha256").update("seed-1").digest()) });
  afterAll(() => m.stop());
  const s = () => m.store.setup;
  const status = () => api.sealStatus!();
  const fromB64 = (x: string) => new Uint8Array(decode(x));

  async function tapAll(before = 0): Promise<number> {
    let taps = 0;
    for (;;) {
      const v = await status();
      const plan = stagePlan(v.stage!);
      if (!plan.next) return taps;
      expect(plan.tap).toBe(before + taps + 1);
      const choice = v.stage!.choices.find((c) => c.credential_id === pk.id)!;
      const step = await stageStep(api, v, plan.next.step, choice, plan.next.scopes, rp);
      expect(step.lines.length).toBe(1);
      const gets = pk.gets.length;
      const done = step.finish(pk);
      expect(pk.gets.length).toBe(gets + 1); // the prompt started inside the call
      await done;
      taps++;
    }
  }

  test("sign in", async () => {
    await completeLogin(api, pk, await prepareLogin(api));
  });

  test("seal import: create and test taps, the drill, then Activate (a plain signature)", async () => {
    const mine = await generateAgeIdentity();
    s().jump(new URLSearchParams("scoped=1&mode=seal-setup&wrap=none&drilled=0"));
    s().recipient = mine.recipient;
    const v = await status();
    expect(v.stage!.source).toBe("unsealed");
    expect(stagePlan(v.stage!).taps).toBe(4);
    const start = s().stageKeks.length;
    expect(await tapAll()).toBe(4);
    const got = s().stageKeks.slice(start);
    expect(got.map((x) => x.step)).toEqual(["create", "create", "test", "test"]);
    // A test tap reproduces exactly the KEKs the create taps made.
    expect([...got[2]!.keks, ...got[3]!.keks]).toEqual([...got[0]!.keks, ...got[1]!.keks]);
    expect(JSON.stringify(f.log.map((x) => x.body)).includes(Buffer.from(pk.handed[0]!).toString("base64url"))).toBe(false);
    for (const h of pk.handed) expect(h.every((b) => b === 0)).toBe(true); // PRF outputs wiped
    // No manifest until the recovery key is proven.
    expect((await status()).stage!.manifest).toBeUndefined();
    await sendDrill(api, { drill_key: (await status()).stage!.drill_key, installation: v.installation }, mine.identity);
    const ready = await status();
    expect(ready.stage!.manifest).toContain("recovery_recipient");
    const b = await api.sealPost!<{ challenge_id: string; canonical: string; public_key: unknown }>("control/challenge", { action: "activate" });
    const { tap } = await prepareControl(ready, "activate", b, rp);
    expect(tap.open).toBeUndefined();
    await api.sealPost!("control/finish", { challenge_id: b.challenge_id, ...(await tap.sign(pk)) });
    expect((await status()).mode).toBe("activated");
    for (let i = 0; i < 200 && !s().sealed; i++) await new Promise((r) => setTimeout(r, 10));
    expect(s().sealed).toBe(true);
  });

  test("migration: the open-legacy tap sends the format-1 KEK in slot 1 and the installation KEK in slot 2", async () => {
    const mine = await generateAgeIdentity();
    for (let i = 0; i < 200 && s().current; i++) await new Promise((r) => setTimeout(r, 10));
    s().activated = false;
    s().jump(new URLSearchParams("mode=bucket-migrate&wrap=none&drilled=0"));
    s().recipient = mine.recipient;
    const v = await status();
    expect(v.stage!.source).toBe("format-1");
    expect(v.stage!.legacy_unlocked).toBe(false);
    const plan = stagePlan(v.stage!);
    expect(plan.next).toEqual({ step: "open-legacy", scopes: ["installation"] });
    const choice = v.stage!.choices.find((c) => c.credential_id === pk.id)!;
    expect(choice.legacy).toBeTruthy();
    const step = await stageStep(api, v, "open-legacy", choice, ["installation"], rp);
    await step.finish(pk);
    const got = s().stageKeks.at(-1)!;
    expect(got.step).toBe("open-legacy");
    expect(got.keks.length).toBe(2);
    const L = choice.legacy!;
    const cred = pk.rawId;
    const legacyKEK = await wrapKeyBytes(new Uint8Array(await pk.evaluate(fromB64(L.prf_salt))), fromB64(L.installation), rp, cred, L.mk_version, fromB64(L.prf_salt));
    expect(got.keks[0]).toBe(hex(legacyKEK));
    const salt = fromB64(s().stageScopes.find((x) => x.scope === "installation")!.salt!);
    const instKEK = await deriveKEK(await pk.evaluate(salt), fromB64(v.installation), rp, cred, "installation", salt);
    expect(got.keks[1]).toBe(hex(instKEK));
    expect((await status()).stage!.legacy_unlocked).toBe(true);
    expect(await tapAll(1)).toBe(3);
  });

  test("refused before the tap: another step, other scopes, another descriptor; a passkey without PRF sends nothing", async () => {
    s().activated = false;
    s().jump(new URLSearchParams("scoped=1&mode=seal-setup&wrap=none"));
    const v = await status();
    const choice = v.stage!.choices.find((c) => c.credential_id === pk.id)!;
    const alter = (edit: (r: { canonical: string; open: { descriptor: string } }) => void) =>
      ({
        sealPost: async (path: string, body: unknown) => {
          const r = await api.sealPost!<{ canonical: string; open: { descriptor: string } }>(path as "stage/challenge", body);
          edit(r);
          return r;
        },
      }) as unknown as typeof api;
    const plan = stagePlan(v.stage!);
    const gets = pk.gets.length;
    // The text names another step.
    await expect(stageStep(alter((r) => (r.canonical = r.canonical.replace('"action":"create"', '"action":"test"'))), v, "create", choice, plan.next!.scopes, rp)).rejects.toThrow(/Not signing/);
    // The descriptor names other scopes (and so the challenge no longer binds it either).
    await expect(stageStep(alter((r) => (r.open.descriptor = r.open.descriptor.replace("org-personal", "org-client-a"))), v, "create", choice, plan.next!.scopes, rp)).rejects.toThrow(/Not signing/);
    // Asking for the wrong step is refused by the broker.
    await expect(stageStep(api, v, "test", choice, plan.next!.scopes, rp)).rejects.toThrow();
    expect(pk.gets.length).toBe(gets);
    // A passkey without PRF: nothing reaches stage/finish.
    const plain = prfAuth(m.url, { prf: false, rawId: pk.rawId });
    const step = await stageStep(api, v, "create", choice, plan.next!.scopes, rp);
    const n = f.log.length;
    await expect(step.finish(plain)).rejects.toThrow(/PRF/);
    expect(f.log.slice(n).some((x) => x.url.endsWith("/stage/finish"))).toBe(false);
  });

  test("Move to per-credential buckets: the run signs exactly {purge_backups} and stages a format-1 store", async () => {
    for (let i = 0; i < 200 && s().current; i++) await new Promise((r) => setTimeout(r, 10));
    s().stop();
    s().current = null;
    s().jump(new URLSearchParams("mode=serve&scoped=1&sealed=1&format1=1"));
    s().activated = false;
    const v = await api.setupGet!<SetupView>("");
    expect(v.tasks!.find((t) => t.id === "buckets")!.state).toBe("available");
    await runSetupTask(api, pk, v, "buckets", { purge_backups: false }, undefined, rp);
    expect(s().received.at(-1)).toEqual({ task: "buckets", params: '{"purge_backups":false}', secrets: {} });
    for (let i = 0; i < 200 && s().mode !== "seal-setup"; i++) await new Promise((r) => setTimeout(r, 10));
    expect((await status()).stage!.source).toBe("format-1");
  });
});
