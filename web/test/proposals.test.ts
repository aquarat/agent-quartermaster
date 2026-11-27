// Env proposals (docs/API.md "Env proposals") against the mock: a host asks to store values,
// the owner commits or discards with one tap, and no window or batch ever decides one.
import { beforeAll, describe, expect, test } from "bun:test";
import { createApi, type Api } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth } from "./helpers";
import { batchReview } from "../src/approvals";
import { envProposalReview, proposalChanges, proposalWords, type EnvProposal, type ProposalAction } from "../src/envsets";
import { canonicalJSON } from "../src/vault";
import type { SealView } from "../src/sealPanel";
import type { PendingItem } from "../src/types";

type Json = Record<string, unknown>;
const STAGING = "client-a/paas/staging";

describe("proposal wording", () => {
  test("changes are grouped by what happens to each key; nothing is dropped", () => {
    expect(proposalChanges("A:replace,B:add,C:remove,D:add")).toEqual({ added: ["B", "D"], replaced: ["A"], removed: ["C"], other: [] });
    expect(proposalChanges("")).toEqual({ added: [], replaced: [], removed: [], other: [] });
    expect(proposalChanges("A:frobnicate,:add,plain")).toEqual({ added: [], replaced: [], removed: [], other: ["A:frobnicate", ":add", "plain"] });
  });
  test("import is stated as replacing the whole set; a new service and set are named", () => {
    const base = { path: "client-a/billing/live", title: "Client A / billing / Live", host: "build-1", class: "agent", address: "192.0.2.14", revision: 0, ref: "ABC123", reason: "why", operation: "import", changes: "A:add,B:add", new_service: true, new_set: true } as EnvProposal;
    const w = proposalWords(base);
    expect(w.who).toBe("build-1 (agent), from 192.0.2.14, wants to store values in client-a/billing/live (Client A / billing / Live).");
    expect(w.creates).toBe("Committing creates the service billing and creates the set live: neither exists yet.");
    expect(w.operation).toBe("Import: REPLACES the whole set. Afterwards client-a/billing/live holds exactly the 2 keys build-1 sent.");
    expect(w.values).toContain("The values were chosen by build-1");
    expect(w.values).toContain("what every later request for client-a/billing/live receives");
    expect(w.reason).toBe("Requester explanation (unverified): why");
    expect(proposalWords({ ...base, new_service: false }).creates).toBe("Committing creates the set live: it does not exist yet.");
    expect(proposalWords({ ...base, new_service: false, new_set: false, changes: "A:replace,B:remove" }).operation).toContain("holds exactly the 1 key build-1 sent; 1 key in it now is removed.");
    expect(proposalWords({ ...base, new_service: false, new_set: false }).creates).toBe("");
    expect(proposalWords({ ...base, operation: "put", changes: "A:replace" }).operation).toBe("Put: sets one key, A. The other keys stay as they are.");
    expect(proposalWords({ ...base, operation: "unset", changes: "A:remove" }).operation).toBe("Unset: removes one key, A. The other keys stay as they are.");
  });
});

describe("env proposals against the mock", () => {
  const m = startMock({ port: 0, distDir: null, vault: true });
  const vault = m.store.vault;
  const api = createApi({ base: m.url, fetch: jarFetch() });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  const rp = new URL(m.url).hostname;
  let seal: SealView;
  const setOf = (path: string) => vault.sets.find((s) => `${s.org_slug}/${s.service_slug}/${s.set_slug}` === path);
  const pending = async () => (await api.envState!()).proposals ?? [];
  const listed = async (id: string) => (await pending()).find((p) => p.id === id)!;
  const decide = async (id: string, action: ProposalAction) => (await envProposalReview(api, seal, await listed(id), action, rp)).tap(auth);

  beforeAll(async () => {
    await completeLogin(api, auth, await prepareLogin(api));
    seal = await api.sealStatus!();
    // The dev fixture's example is not part of these tests.
    for (const p of await pending()) vault.cancelProposal(p.id);
  });

  test("state lists a pending proposal in the contract's shape, metadata only", async () => {
    expect(await pending()).toEqual([]);
    const id = vault.addProposal(STAGING, "import", { APP_SECRET: "sentinel-value-1", NEW_KEY: "sentinel-value-2" }, { reason: "rotate" });
    const p = await listed(id);
    expect(Object.keys(p)).toEqual(["path", "title", "org", "service", "set", "revision", "service_revision", "policy_revision", "admission_generation", "enrollment", "host", "class", "names", "default_seconds", "soft_cap_seconds", "offers_indefinite", "id", "ref", "operation", "commitment", "changes", "reason", "address", "new_service", "new_set", "status", "created_at", "expires_at", "result_revision"]);
    expect(p).toMatchObject({ path: STAGING, title: "Client A / PaaS / Staging env", host: "build-1", address: "192.0.2.14", revision: 7, operation: "import", changes: "APP_SECRET:replace,DATABASE_URL:remove,NEW_KEY:add,SMTP_PASSWORD:remove,TLS_KEY:remove", reason: "rotate", new_service: false, new_set: false, status: "pending", result_revision: 0 });
    expect(p.ref).toBe(id.slice(-6));
    expect(p.expires_at - p.created_at).toBe(600_000);
    expect(JSON.stringify(await api.envState!())).not.toContain("sentinel-value");
    vault.cancelProposal(id);
    expect(await pending()).toEqual([]);
  });

  test("commit is one fresh tap, signs the proposal with the reason blank, and writes the next revision", async () => {
    const id = vault.addProposal(STAGING, "put", { SENTRY_DSN: "https://mock@sentry.example.com/2" }, { reason: "add error reporting" });
    const p = await listed(id);
    const taps = auth.gets.length;
    const r = await envProposalReview(api, seal, p, "proposal-commit", rp);
    expect(auth.gets.length).toBe(taps); // review alone never taps
    expect(r.detail).toContain(`Commit · Client A / PaaS / Staging env · Ref ${p.ref}`);
    expect(r.detail).toContain("Put: sets one key, SENTRY_DSN.");
    expect(r.detail).toContain("Requester explanation (unverified): add error reporting");
    expect(r.detail).toContain('"reason": ""'); // the signed text does not carry the host's words
    await r.tap(auth);
    expect(auth.gets.length).toBe(taps + 1);
    expect(setOf(STAGING)).toMatchObject({ revision: 8, names: ["APP_SECRET", "DATABASE_URL", "SENTRY_DSN", "SMTP_PASSWORD", "TLS_KEY"] });
    expect(vault.proposals.find((x) => x.id === id)).toMatchObject({ status: "committed", result_revision: 8 });
    expect(await pending()).toEqual([]);
    expect(m.store.recent.some((a) => a.action === "env_proposal_commit" && a.object === "env:" + id)).toBe(true);
    // Decided once: the same proposal cannot be decided again.
    await expect(envProposalReview(api, seal, p, "proposal-discard", rp)).rejects.toThrow(/no longer available/);
  });

  test("import replaces the whole set; unset removes one key", async () => {
    await decide(vault.addProposal(STAGING, "unset", { TLS_KEY: "" }), "proposal-commit");
    expect(setOf(STAGING)).toMatchObject({ revision: 9, names: ["APP_SECRET", "DATABASE_URL", "SENTRY_DSN", "SMTP_PASSWORD"] });
    await decide(vault.addProposal(STAGING, "import", { APP_SECRET: "a", ONLY_OTHER: "b" }), "proposal-commit");
    expect(setOf(STAGING)).toMatchObject({ revision: 10, names: ["APP_SECRET", "ONLY_OTHER"] });
  });

  test("discard leaves nothing: no revision, no values, not listed", async () => {
    const before = structuredClone(setOf(STAGING));
    const id = vault.addProposal(STAGING, "import", { WIPED: "x" });
    await decide(id, "proposal-discard");
    expect(setOf(STAGING)).toEqual(before!);
    expect(vault.proposals.find((x) => x.id === id)).toMatchObject({ status: "discarded", result_revision: 0 });
    expect((vault as unknown as { proposed: Map<string, unknown> }).proposed.has(id)).toBe(false);
    expect(await pending()).toEqual([]);
    expect(m.store.recent.some((a) => a.action === "env_proposal_discard" && a.object === "env:" + id)).toBe(true);
  });

  test("a proposal for a new set creates it on commit; a discarded one creates nothing", async () => {
    const sets = vault.sets.length, services = vault.services.length;
    const gone = vault.addProposal("client-a/paas/preview", "import", { A: "1" }, { create: true });
    expect(await listed(gone)).toMatchObject({ new_service: false, new_set: true, revision: 0, names: [], changes: "A:add" });
    expect(vault.sets.length).toBe(sets); // nothing exists until the owner commits
    await decide(gone, "proposal-discard");
    expect(setOf("client-a/paas/preview")).toBeUndefined();

    const id = vault.addProposal("client-a/paas/preview", "import", { A: "1", B: "2" }, { create: true, title: "Preview env" });
    const p = await listed(id);
    expect(p.title).toBe("Client A / PaaS / Preview env");
    await decide(id, "proposal-commit");
    expect(setOf("client-a/paas/preview")).toMatchObject({ set_id: p.set, service_id: p.service, set_title: "Preview env", kind: "env-set", revision: 1, names: ["A", "B"] });
    expect(vault.services.length).toBe(services);
    expect((await api.vaultState!()).sets.some((s) => s.set_id === p.set)).toBe(true);
  });

  test("a proposal for a new service creates the service and the set", async () => {
    const id = vault.addProposal("client-a/billing/live", "put", { STRIPE_KEY: "mock" }, { create: true });
    const p = await listed(id);
    expect(p).toMatchObject({ new_service: true, new_set: true, revision: 0, title: "Client A / billing / live" });
    expect(vault.services.some((s) => s.id === p.service)).toBe(false);
    await decide(id, "proposal-commit");
    expect(vault.services.find((s) => s.id === p.service)).toMatchObject({ slug: "billing", org_id: p.org });
    expect(setOf("client-a/billing/live")).toMatchObject({ set_id: p.set, revision: 1, names: ["STRIPE_KEY"] });
    // Without --create a missing set is never proposed, and an existing path is not created.
    expect(() => vault.addProposal("client-a/billing/typo", "put", { A: "1" })).toThrow();
    expect(() => vault.addProposal("client-a/billing/live", "put", { A: "1" }, { create: true })).toThrow();
    // A host proposes only inside an organisation it is admitted to.
    expect(() => vault.addProposal("club/website/deploy", "put", { A: "1" })).toThrow(/not admitted/);
  });

  test("a stale proposal is a conflict: at review, and between review and tap", async () => {
    const s = setOf(STAGING)!;
    // The set moves on after the review was shown: the tap is refused and nothing is written.
    const id = vault.addProposal(STAGING, "put", { LATE: "1" });
    const r = await envProposalReview(api, seal, await listed(id), "proposal-commit", rp);
    s.revision++;
    await expect(r.tap(auth)).rejects.toMatchObject({ status: 409 });
    expect(s.names).not.toContain("LATE");
    expect(vault.proposals.find((x) => x.id === id)!.status).toBe("superseded");
    expect(await pending()).toEqual([]);

    // Two proposals on one revision: committing the first supersedes the second.
    const a = vault.addProposal(STAGING, "put", { FIRST: "1" }), b = vault.addProposal(STAGING, "put", { SECOND: "2" });
    const second = await listed(b);
    await decide(a, "proposal-commit");
    await expect(envProposalReview(api, seal, second, "proposal-commit", rp)).rejects.toMatchObject({ status: 409 });
    await expect(envProposalReview(api, seal, second, "proposal-discard", rp)).rejects.toMatchObject({ status: 409 });
    expect(s.names).toContain("FIRST");
    expect(s.names).not.toContain("SECOND");

    // For a new set: the path is taken before the owner decides.
    const c = vault.addProposal("client-a/paas/race", "put", { A: "1" }, { create: true }), d = vault.addProposal("client-a/paas/race", "put", { B: "2" }, { create: true });
    const loser = await listed(d);
    await decide(c, "proposal-commit");
    await expect(envProposalReview(api, seal, loser, "proposal-commit", rp)).rejects.toMatchObject({ status: 409 });
    expect(setOf("client-a/paas/race")!.names).toEqual(["A"]);

    // The host's admission changes: its pending proposal is gone.
    const e = vault.addProposal(STAGING, "put", { X: "1" });
    const adm = vault.hosts.find((h) => h.name === "build-1")!.orgs.get(s.org_id)!;
    adm.generation++;
    expect(await pending()).toEqual([]);
    expect(vault.proposals.find((x) => x.id === e)!.status).toBe("superseded");
    adm.generation--;
  });

  test("an expired proposal is no longer listed or decidable", async () => {
    const id = vault.addProposal(STAGING, "put", { SLOW: "1" });
    const p = await listed(id);
    vault.proposals.find((x) => x.id === id)!.expires_at = Date.now() - 1;
    await expect(envProposalReview(api, seal, p, "proposal-commit", rp)).rejects.toMatchObject({ status: 409 });
    expect(vault.proposals.find((x) => x.id === id)!.status).toBe("expired");
    expect(await pending()).toEqual([]);
  });

  test("the page refuses a broker text that differs from the card, and a proposal that is not whole", async () => {
    const id = vault.addProposal(STAGING, "put", { HONEST: "1" });
    const p = await listed(id);
    const tampering = (change: (meta: Json, c: Json) => void): Api => ({
      ...api,
      envPost: async <T>(path: "ticket" | "challenge" | "finish", body: unknown) => {
        const res = (await api.envPost!<Json>(path, body)) as Json;
        if (path === "challenge") {
          const c = JSON.parse(res.canonical as string) as Json, meta = JSON.parse(c.metadata as string) as Json;
          change(meta, c);
          c.metadata = JSON.stringify(meta);
          res.canonical = canonicalJSON(c);
        }
        return res as T;
      },
    });
    await envProposalReview(tampering(() => {}), seal, p, "proposal-commit", rp); // the wrapper alone changes nothing
    for (const change of [(x: Json) => (x.changes = "HONEST:add,OTHER:remove"), (x: Json) => (x.commitment = "0".repeat(64)), (x: Json) => (x.path = "client-a/paas/production"), (x: Json) => (x.operation = "import"), (x: Json) => (x.new_set = true), (x: Json) => (x.reason = "smuggled"), (_: Json, c: Json) => (c.action = "proposal-discard"), (_: Json, c: Json) => (c.ttl_seconds = 600)])
      await expect(envProposalReview(tampering(change), seal, p, "proposal-commit", rp)).rejects.toThrow();
    const { ref: _ref, ...noRef } = p;
    for (const bad of [noRef, { ...p, extra: 1 }, { ...p, commitment: "short" }, { ...p, operation: "merge" }, { ...p, status: "committed" }, { ...p, new_service: true }, { ...p, new_set: true }])
      await expect(envProposalReview(api, seal, bad as EnvProposal, "proposal-commit", rp)).rejects.toThrow("Unknown or incomplete env proposal");
    await expect(envProposalReview(api, seal, p, "approve" as ProposalAction, rp)).rejects.toThrow("committed or discarded");
    await decide(id, "proposal-discard");
  });

  test("no approval window or batch decides a proposal: it is never among the selectable requests, and takes no duration", async () => {
    const id = vault.addProposal(STAGING, "put", { ALONE: "1" });
    const p = await listed(id);
    // Windows and the batch panel select from `pending` only (app.ts: multiPanel).
    const waiting = (await api.state()).pending ?? [];
    expect(waiting.length).toBeGreaterThan(0);
    expect(JSON.stringify(waiting)).not.toContain(id);
    // Forced into a batch anyway: the broker has no such request, and the page refuses a
    // batch whose text is the proposal's.
    const forged = [{ item: { ...waiting[0]!, id } as PendingItem, action: "approve" as const, ttl_seconds: 600 }];
    await expect(batchReview(api, seal, forged, rp)).rejects.toThrow();
    const real = await api.envPost!<{ canonical: string }>("challenge", { id, action: "proposal-commit", ttl_seconds: 0 });
    const echo: Api = { ...api, sealPost: async <T>() => ({ canonical: JSON.stringify({ id: "A".repeat(43), org_id: p.org, org_title: "Client A", items: JSON.stringify([real.canonical]) }), challenge_id: "x", public_key: {} }) as T };
    await expect(batchReview(echo, seal, forged, rp)).rejects.toThrow("unsupported canonical version 3");
    // A proposal is not a release: release verbs do not reach it, and it takes no duration
    // and no "don't ask again".
    await expect(api.envPost!("challenge", { id, action: "approve", ttl_seconds: 600 })).rejects.toMatchObject({ status: 404 });
    await expect(api.envPost!("challenge", { id, action: "proposal-commit", ttl_seconds: 600 })).rejects.toMatchObject({ status: 400 });
    await expect(api.envPost!("challenge", { id, action: "proposal-commit", ttl_seconds: 0, standing_seconds: 3600 })).rejects.toMatchObject({ status: 400 });
    expect(vault.proposals.find((x) => x.id === id)!.status).toBe("pending");
    expect(vault.standing).toEqual([]);
    vault.cancelProposal(id);
  });
});
