// Vault logic: vectors shared with Go, and the canonical binding of every action.
import { describe, expect, test } from "bun:test";
import vectors from "../../test/vectors/vault.json";
import dotenv from "../../test/vectors/dotenv.json";
import { canonicalJSON, editChanges, editCommitment, openReveal, parseDotenv, publicPem, safeName } from "../src/vault";
import { suite } from "../src/seal";
import { createECDH, createPublicKey } from "node:crypto";

const unhex = (s: string) => new Uint8Array(s.match(/../g)!.map((x) => parseInt(x, 16)));

describe("vectors shared with Go", () => {
  test("dotenv reader", () => {
    for (const c of dotenv as { name: string; input: string; entries?: unknown; error_line?: number }[]) {
      if (c.error_line) {
        let msg = "";
        try {
          parseDotenv(c.input);
        } catch (e) {
          msg = (e as Error).message;
        }
        expect({ name: c.name, refused: msg !== "" }).toEqual({ name: c.name, refused: true });
        const m = /^unsupported literal assignment on line (\d+)$/.exec(msg);
        expect({ name: c.name, line: m ? Number(m[1]) : -1 }).toEqual({ name: c.name, line: c.error_line });
      } else {
        expect({ name: c.name, entries: parseDotenv(c.input) }).toEqual({ name: c.name, entries: c.entries } as never);
      }
    }
  });
  test("dotenv errors never echo the content", () => {
    for (const s of ["APP_TOKEN=$(sentinel)", "APP_TOKEN='sentinel", 'APP_TOKEN="sentinel\\x"', "APP_TOKEN=sentinel\nAPP_TOKEN=sentinel", "sentinel"]) {
      expect(() => parseDotenv(s)).toThrow();
      try {
        parseDotenv(s);
      } catch (e) {
        expect((e as Error).message).not.toContain("sentinel");
      }
    }
    expect(safeName("LD_PRELOAD")).toBe(false);
    expect(safeName("APP_ANYTHING")).toBe(true);
  });
  test("edit commitment and changes", async () => {
    const c = vectors.commitment;
    const edit = { operation: c.edit.operation as "merge", entries: c.edit.entries, remove: c.edit.remove, salt: Uint8Array.from(atob(c.edit.salt), (x) => x.charCodeAt(0)) };
    expect(await editCommitment(edit, c)).toBe(c.commitment);
    expect(editChanges(edit, c.old_names)).toBe(c.changes);
    expect(await editCommitment({ ...edit, remove: [] }, c)).not.toBe(c.commitment);
    expect(await editCommitment(edit, { ...c, revision: c.revision + 1 })).not.toBe(c.commitment);
    expect(() => editChanges({ ...edit, remove: ["MISSING_KEY"] }, c.old_names)).toThrow();
    await expect(editCommitment({ ...edit, remove: ["APP_TOKEN"] }, c)).rejects.toThrow();
  });
  test("a packet sealed by Go opens with the reveal path, and only in its context", async () => {
    const g = vectors.go_sealed;
    const key = await suite.kem.importKey("raw", unhex(g.recipient_priv).buffer as ArrayBuffer, false);
    const names = ["APP_KEY", "APP_TOKEN"];
    const open = (canonical: string, set: string, epoch = vectors.epoch) => openReveal(key, unhex(vectors.installation), unhex(epoch), canonical, set, unhex(g.enc), unhex(g.ciphertext), names);
    const entries = await open(vectors.canonical, vectors.set_id);
    expect(JSON.stringify({ entries })).toBe(g.plaintext);
    await expect(open(vectors.canonical.replace("2026", "2027"), vectors.set_id)).rejects.toThrow();
    await expect(open(vectors.canonical, vectors.set_id.replace("0", "1"))).rejects.toThrow();
    await expect(open(vectors.canonical, vectors.set_id, vectors.installation)).rejects.toThrow();
    await expect(openReveal(key, unhex(vectors.installation), unhex(vectors.epoch), vectors.canonical, vectors.set_id, unhex(g.enc), unhex(g.ciphertext), ["APP_KEY"])).rejects.toThrow("differ");
  });
  test("canonical JSON matches Go's map encoding", () => {
    expect(canonicalJSON({ b: [1, { z: true, a: "<&>/" }], a: "x\u2028y\"\\\n", c: null })).toBe('{"a":"x\\u2028y\\"\\\\\\n","b":[1,{"a":"<&>/","z":true}],"c":null}');
    expect(() => canonicalJSON({ a: 1.5 })).toThrow();
  });
  test("public key PEM", () => {
    const ed = crypto.getRandomValues(new Uint8Array(32));
    expect(createPublicKey(publicPem(ed)).export({ format: "jwk" }).x).toBe(Buffer.from(ed).toString("base64url"));
    const p256 = createECDH("prime256v1");
    p256.generateKeys();
    const jwk = createPublicKey(publicPem(new Uint8Array(p256.getPublicKey()))).export({ format: "jwk" });
    expect(jwk.crv).toBe("P-256");
    expect(Buffer.from(jwk.x!, "base64url").equals(p256.getPublicKey().subarray(1, 33))).toBe(true);
    expect(() => publicPem(new Uint8Array(33))).toThrow();
  });
});

// ---- every action, end to end against the mock, and its canonical binding ----
import { afterAll, beforeAll } from "bun:test";
import { createApi, type Api } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { fakeAuth, jarFetch, prfAuth } from "./helpers";
import { hexPreview, itemMessage, newSetId, vaultCommit, vaultPolicy, vaultReveal, vaultSignDecision, vaultSignerCreate, type VaultState } from "../src/vault";
import type { SealView } from "../src/sealPanel";

type Json = Record<string, unknown>;
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

describe("vault actions against the mock", () => {
  const m = startMock({ port: 0, distDir: null, vault: true });
  const api = createApi({ base: m.url, fetch: jarFetch() });
  // A passkey with PRF that is enabled for every scope: its taps open the buckets they need.
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  const rp = new URL(m.url).hostname;
  let seal: SealView;
  let state: VaultState;
  const refresh = async () => {
    state = await api.vaultState!();
  };
  const set = (path: string) => state.sets.find((s) => `${s.org_slug}/${s.service_slug}/${s.set_slug}` === path)!;
  beforeAll(async () => {
    await completeLogin(api, auth, await prepareLogin(api));
    seal = await api.sealStatus!();
    await refresh();
  });
  afterAll(() => m.stop());

  test("form commit, then reveal in the browser, multi-line value intact", async () => {
    const s = set("client-a/paas/staging");
    const pem = "-----BEGIN PRIVATE KEY-----\nline two\n-----END PRIVATE KEY-----\n";
    const edit = { operation: "merge" as const, entries: [{ name: "TLS_KEY", value: pem }, { name: "APP_TOKEN", value: 'new "token" $HOME' }], remove: ["SMTP_PASSWORD"] };
    const c = await vaultCommit(api, seal, s, edit, rp);
    expect(c.changes).toBe("APP_TOKEN:add,SMTP_PASSWORD:remove,TLS_KEY:replace");
    expect(c.detail).not.toContain("line two");
    await c.tap(auth);
    await refresh();
    const after = set("client-a/paas/staging");
    expect(after.revision).toBe(s.revision + 1);
    expect(after.names).toEqual(["APP_SECRET", "APP_TOKEN", "DATABASE_URL", "TLS_KEY"]);
    const r = await vaultReveal(api, seal, after, ["APP_TOKEN", "TLS_KEY"], rp);
    expect(await r.tap(auth)).toEqual([{ name: "APP_TOKEN", value: 'new "token" $HOME' }, { name: "TLS_KEY", value: pem }]);
    await expect(r.tap(auth)).rejects.toThrow("already used");
    // The stale set (old revision) no longer matches what the server would sign.
    await expect(vaultReveal(api, seal, s, ["TLS_KEY"], rp)).rejects.toThrow("Canonical differs");
  });

  test("no value or private key crosses in the clear", async () => {
    const sent: string[] = [];
    const spy: Api = { ...api, vaultPost: (path, body) => (sent.push(JSON.stringify(body)), api.vaultPost!(path, body)) };
    const c = await vaultCommit(spy, seal, set("client-a/paas/production"), { operation: "import", entries: [{ name: "APP_SECRET", value: "sentinel-value-1" }], remove: [] }, rp);
    await c.tap(auth);
    const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const p = await vaultSignerCreate(spy, seal, set("personal/firmware/release-key"), { id: newSetId(), slug: "imported-key", title: "Imported key" }, "ed25519", "import", seed, rp);
    expect(p.publicHex).toBe("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const made = await p.tap(auth);
    expect(made.public_hex).toBe(p.publicHex);
    expect(sent.length).toBeGreaterThan(4);
    for (const body of sent) {
      expect(body).not.toContain("sentinel-value-1");
      expect(body).not.toContain(seed);
    }
    await refresh();
    expect(set("personal/firmware/imported-key").kind).toBe("signer");
    await expect(vaultReveal(api, seal, set("personal/firmware/imported-key"), ["X"], rp)).rejects.toThrow("never revealed");
    const direct = await api.vaultPost!("challenge", { action: "reveal", id: set("personal/firmware/imported-key").set_id, names: ["APP_KEY"], recipient: "x" }).catch((e) => e);
    expect((direct as Error).message).toContain("never revealed");
  });

  test("generated signer: the canonical carries the public key shown", async () => {
    const parent = set("personal/firmware/release-key");
    const p = await vaultSignerCreate(api, seal, parent, { id: newSetId(), slug: "p256-key", title: "P-256 key" }, "ecdsa-p256-sha256", "generate", undefined, rp);
    expect(p.publicHex).toMatch(/^04[0-9a-f]{128}$/);
    expect(p.publicPem).toContain("BEGIN PUBLIC KEY");
    const made = await p.tap(auth);
    expect(made.fingerprint).toBe(p.fingerprint);
    for (const tamper of [
      (_c: Json, meta: Json) => (meta.scheme = "ed25519ph"),
      (_c: Json, meta: Json) => (meta.set_slug = "other"),
      (_c: Json, meta: Json) => (meta.fingerprint = "0".repeat(64)),
      (_c: Json, _m: Json, res: Json) => ((res.facts as Json).fingerprint = "0".repeat(64)),
      (_c: Json, meta: Json) => (meta.service_id = "f".repeat(32)),
      (_c: Json, meta: Json) => (meta.source = "import"),
    ]) {
      await expect(vaultSignerCreate(tampering(api, tamper as never), seal, parent, { id: newSetId(), slug: "x-" + newSetId().slice(0, 6), title: "X" }, "ed25519", "generate", undefined, rp)).rejects.toThrow();
    }
    // The broker substituting its own key: metadata and facts agree with each other, so the
    // page shows that key; what it must refuse is an answer for another upload attempt.
    await expect(vaultSignerCreate(tampering(api, ((_c: Json, meta: Json, res: Json) => (meta.attempt_id = (res.facts as Json).attempt_id = "A".repeat(43))) as never), seal, parent, { id: newSetId(), slug: "y", title: "Y" }, "ed25519", "import", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", rp)).rejects.toThrow("another upload");
  });

  test("a canonical that differs from the choice is refused before the tap", async () => {
    await refresh();
    const s = set("client-a/paas/staging");
    const edit = { operation: "merge" as const, entries: [{ name: "APP_ID", value: "1" }], remove: [] };
    const gets = auth.gets.length;
    const commitTampers: ((c: Json, meta: Json) => unknown)[] = [
      (_c, meta) => (meta.changes = "APP_ID:add,APP_SECRET:remove"),
      (_c, meta) => (meta.commitment = "0".repeat(64)),
      (_c, meta) => (meta.set_id = set("client-a/paas/production").set_id),
      (c) => (c.id = set("client-a/paas/production").set_id),
      (_c, meta) => (meta.operation = "import"),
      (_c, meta) => (meta.attempt_id = "A".repeat(43)),
      // The key the page sealed to is part of what is signed: a packet re-sealed on the way
      // to another recipient shows up as another key here.
      (_c, meta) => (meta.recipient = (meta.recipient as string).replace(/.$/, (x) => (x === "A" ? "B" : "A"))),
      (_c, meta) => delete meta.recipient,
      (_c, meta) => (meta.result_revision = 99),
      (_c, meta) => (meta.extra = true),
      (c) => (c.action = "reveal"),
      (c) => (c.object = "env"),
      (c) => (c.epoch = "A".repeat(43)),
      (c) => (c.extra = 1),
    ];
    for (const t of commitTampers) await expect(vaultCommit(tampering(api, t as never), seal, s, edit, rp)).rejects.toThrow();
    const revealTampers: ((c: Json, meta: Json) => unknown)[] = [
      (_c, meta) => (meta.names = ["APP_SECRET", "DATABASE_URL"]),
      (_c, meta) => (meta.names = ["DATABASE_URL"]),
      (_c, meta) => (meta.recipient = (meta.recipient as string).replace(/.$/, (x) => (x === "A" ? "B" : "A"))),
      (_c, meta) => (meta.set_id = set("club/website/deploy").set_id),
      (_c, meta) => (meta.org_slug = "personal"),
      (_c, meta) => (meta.revision = 1),
      (c) => (c.installation = "A".repeat(43)),
    ];
    for (const t of revealTampers) await expect(vaultReveal(tampering(api, t as never), seal, s, ["APP_SECRET"], rp)).rejects.toThrow();
    await expect(vaultPolicy(tampering(api, ((_c: Json, meta: Json) => (meta.allow_reveal = true)) as never), seal, state.organisations.find((o) => o.slug === "client-a")!, false, rp)).rejects.toThrow();
    await expect(vaultPolicy(tampering(api, ((_c: Json, meta: Json) => (meta.org_id = "0".repeat(32))) as never), seal, state.organisations.find((o) => o.slug === "client-a")!, false, rp)).rejects.toThrow();
    expect(auth.gets.length).toBe(gets); // no passkey prompt was ever shown
  });

  test("a reveal answer with other keys, or for another ceremony, is refused", async () => {
    const s = set("client-a/paas/staging");
    const other = await vaultReveal(api, seal, s, ["DATABASE_URL"], rp);
    let stolen: unknown;
    const capture: Api = { ...api, vaultPost: async <T>(p: "attempt" | "challenge" | "finish", b: unknown) => { const r = await api.vaultPost!<T>(p, b); if (p === "finish") stolen = r; return r; } };
    const first = await vaultReveal(capture, seal, s, ["APP_SECRET"], rp);
    expect((await first.tap(auth))[0]!.name).toBe("APP_SECRET");
    // Replaying the recorded ciphertext into a later ceremony fails to open.
    const replay: Api = { ...api, vaultPost: async <T>(p: "attempt" | "challenge" | "finish", b: unknown) => (p === "finish" ? (stolen as T) : api.vaultPost!<T>(p, b)) };
    const second = await vaultReveal(replay, seal, s, ["APP_SECRET"], rp);
    await expect(second.tap(auth)).rejects.toThrow();
    expect((await other.tap(auth))[0]!.name).toBe("DATABASE_URL");
  });

  test("reveal policy switch, and reveal refused while it is off", async () => {
    const club = state.organisations.find((o) => o.slug === "club")!;
    expect(club.allow_reveal).toBe(false);
    const direct = await api.vaultPost!("challenge", { action: "reveal", id: set("club/website/deploy").set_id, names: ["APP_ID"], recipient: "x" }).catch((e) => e);
    expect((direct as Error).message).toContain("does not allow reveal");
    await (await vaultPolicy(api, seal, club, true, rp)).tap(auth);
    await refresh();
    expect(state.organisations.find((o) => o.slug === "club")!.allow_reveal).toBe(true);
    expect((await (await vaultReveal(api, seal, set("club/website/deploy"), ["APP_ID"], rp)).tap(auth))[0]!.value).toBe("club-site");
    await expect(vaultPolicy(api, seal, club, false, rp)).rejects.toThrow(); // stale view: the canonical says old=true
  });

  test("signing decisions bind every artifact and limit", async () => {
    await refresh();
    const single = state.requests.find((r) => r.ttl_seconds === 0 && r.status === "pending")!;
    const timed = state.requests.find((r) => r.ttl_seconds > 0 && r.status === "pending")!;
    const live = state.requests.find((r) => r.status === "approved")!;
    const setOf = (r: typeof single) => state.sets.find((s) => s.set_id === r.set)!;
    const msg = (await itemMessage(single.items[0]!))!;
    expect(msg.length).toBe(140);
    expect(hexPreview(msg).split("\n").length).toBe(9);
    await expect(itemMessage({ ...single.items[0]!, sha256: "0".repeat(64) })).rejects.toThrow();
    const tampers: ((c: Json, meta: Json) => unknown)[] = [
      (_c, meta) => ((meta.items as Json[])[0]!.sha256 = "0".repeat(64)),
      (_c, meta) => ((meta.items as Json[])[0]!.name = "other.bin"),
      (_c, meta) => ((meta.items as Json[])[0]!.size = 1),
      (_c, meta) => (meta.items as Json[]).push({ name: "extra.bin", size: 1, sha256: "1".repeat(64) }),
      (_c, meta) => (meta.ttl_seconds = 1800),
      (_c, meta) => (meta.max_signatures = 500),
      (_c, meta) => (meta.fingerprint = "0".repeat(64)),
      (_c, meta) => (meta.scheme = "ed25519-sha256"),
      (_c, meta) => (meta.host = "other-host"),
      (_c, meta) => (meta.address = "203.0.113.9"),
      (_c, meta) => (meta.set_id = setOf(timed).set_id),
      (_c, meta) => (meta.beyond_soft_cap = true),
      (c) => (c.action = "sign-deny"),
      (c) => (c.id = timed.id),
    ];
    for (const t of tampers) await expect(vaultSignDecision(tampering(api, t as never), seal, setOf(single), single, "sign-approve", 0, 1, rp)).rejects.toThrow();
    // Wrong signer, a key that is not the set's, or limits above the request.
    await expect(vaultSignDecision(api, seal, setOf(timed), single, "sign-approve", 0, 1, rp)).rejects.toThrow("another signer");
    await expect(vaultSignDecision(api, seal, { ...setOf(single), fingerprint: "0".repeat(64) }, single, "sign-approve", 0, 1, rp)).rejects.toThrow("another public key");
    await expect(vaultSignDecision(api, seal, setOf(timed), timed, "sign-approve", timed.ttl_seconds + 1, 5, rp)).rejects.toThrow();
    await expect(vaultSignDecision(api, seal, setOf(timed), timed, "sign-approve", 600, timed.max_signatures + 1, rp)).rejects.toThrow();
    await expect(vaultSignDecision(api, seal, setOf(single), single, "sign-deny", 60, 1, rp)).rejects.toThrow();
    const a = await vaultSignDecision(api, seal, setOf(single), single, "sign-approve", 0, 1, rp);
    expect(a.detail).toContain(single.items[0]!.sha256);
    await a.tap(auth);
    const t = await vaultSignDecision(api, seal, setOf(timed), timed, "sign-approve", 600, 5, rp);
    expect(t.detail).toContain("up to 5 signatures over anything build-1 submits for 600 seconds");
    await (await vaultSignDecision(api, seal, setOf(live), live, "sign-revoke", 0, 0, rp)).tap(auth);
    await t.tap(auth);
    await refresh();
    expect(state.requests.find((r) => r.id === timed.id)).toMatchObject({ status: "approved", ttl_seconds: 600, max_signatures: 5 });
    expect(state.requests.find((r) => r.id === live.id)).toBeUndefined();
    await (await vaultSignDecision(api, seal, setOf(timed), state.requests.find((r) => r.id === timed.id)!, "sign-revoke", 0, 0, rp)).tap(auth);
  });

  test("closed buckets: saving needs nothing open; a reveal opens the set's bucket only with PRF", async () => {
    await fetch(m.url + "/mock/vault?closed=1");
    seal = await api.sealStatus!();
    await refresh();
    const s = set("client-a/paas/staging");
    expect(seal.buckets!.find((b) => b.label === "client-a/paas/staging")!.open).toBe(false);
    // A write is encrypted to the bucket's public key: no open, no PRF.
    const commit = await vaultCommit(api, seal, s, { operation: "merge", entries: [{ name: "APP_ID", value: "1" }], remove: [] }, rp);
    await commit.tap(fakeAuth(m.url));
    await refresh();
    // A passkey without PRF cannot open the closed bucket: the broker refuses, nothing leaves.
    const noPrf = await vaultReveal(api, seal, set("client-a/paas/staging"), ["APP_ID"], rp);
    expect(noPrf.opens).toEqual(["Opens client-a/paas/staging: for this action only"]);
    await expect(noPrf.tap(fakeAuth(m.url))).rejects.toThrow("closed");
    // The enabled passkey's tap carries the KEK packet; the bucket opens for this reveal only.
    const before = m.store.buckets.packets.length;
    expect((await (await vaultReveal(api, seal, set("client-a/paas/staging"), ["APP_ID"], rp)).tap(auth))[0]!.value).toBe("1");
    expect(m.store.buckets.packets.length).toBe(before + 1);
    expect((await api.sealStatus!()).buckets!.find((b) => b.label === "client-a/paas/staging")!.open).toBe(false);
    // Policy changes open nothing.
    await (await vaultPolicy(api, seal, state.organisations.find((o) => o.slug === "client-a")!, false, rp)).tap(fakeAuth(m.url));
  });
});
