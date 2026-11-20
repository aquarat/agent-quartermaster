// Owner side of TestUIFlows (ui_flows_test.go): drives a real aqmasd through the web UI's own
// flow code (web/src/flows.ts + api.ts) with the software WebAuthn authenticator in
// test/interop/softauthn.ts, which really signs (ECDSA P-256, "none" attestation).
//
//   AQMAS_WEB_DIR=<checkout>/web AQMAS_BASE=http://127.0.0.1:port AQMAS_ORIGIN=https://aqmas.example.com \
//   AQMAS_CODE=<enroll code> bun internal/server/testdata/ui_driver.ts
//
// Steps: register first passkey (enroll code), sign in, approve the pending enrollment, approve
// the pending SSH request for 10 min with a 1 h standing approval, wait for the second (auto-
// approved) grant, revoke the standing approval, revoke the first grant, add a second passkey,
// sign in with it, rename the first passkey, remove it, check the last one can't be removed.
// Prints "UI-DRIVER OK" at the end.

const web = process.env.AQMAS_WEB_DIR!;
const base = process.env.AQMAS_BASE!;
const origin = process.env.AQMAS_ORIGIN!;
const code = process.env.AQMAS_CODE!;

const { createApi } = await import(`${web}/src/api.ts`);
const flows = await import(`${web}/src/flows.ts`);

const { softAuthenticator: newAuthenticator } = await import("../../../test/interop/softauthn.ts");
const softAuthenticator = () => newAuthenticator(origin);

// fetch with a cookie jar (the session cookie is Secure; this test talks plain HTTP to 127.0.0.1
// exactly like cloudflared does, so keep it by hand).
let cookie = "";
const jar = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const h = new Headers(init?.headers);
  if (cookie) h.set("cookie", cookie);
  const res = await fetch(input, { ...init, headers: h });
  const sc = res.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0]!;
  return res;
}) as typeof fetch;

const api = createApi({ base, fetch: jar });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor<T>(what: string, f: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 300; i++) {
    const v = await f();
    if (v !== undefined) return v;
    await sleep(100);
  }
  throw new Error("timed out waiting for " + what);
}
const step = (s: string) => console.log("ui-driver: " + s);

const owner = await softAuthenticator();
await flows.completeRegistration(api, owner, await flows.prepareRegistrationWithCode(api, code));
step("registered first passkey");
await flows.completeLogin(api, owner, await flows.prepareLogin(api));
step("signed in");

const enr = await waitFor("enrollment", async () => (await api.state()).pending?.find((p: any) => p.kind === "enrollment"));
if (!enr.enrollment?.csr_fingerprint) throw new Error("enrollment card lacks csr_fingerprint");
let p = await flows.prepareAction(api, flows.targetForPending(enr), { action: "approve" });
step("enrollment canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);
step("approved enrollment");

const req = await waitFor("ssh request", async () => (await api.state()).pending?.find((p: any) => p.kind === "ssh"));
// The owner may not lengthen: the server must refuse, not clamp.
try {
  await flows.prepareAction(api, flows.targetForPending(req), { action: "approve", ttl_seconds: req.ttl_max + 60 });
  throw new Error("server accepted a TTL above ttl_max");
} catch (e) {
  if (!(e instanceof Error) || (e as any).status !== 400) throw e;
}
p = await flows.prepareAction(api, flows.targetForPending(req), { action: "approve", ttl_seconds: 600, standing_hours: 1 });
step("request canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);
step("approved ssh request with 1 h standing approval");

const st = await api.state();
if (!st.standing?.length) throw new Error("no standing approval in state");
const grants = await waitFor("two grants", async () => {
  const g = (await api.state()).grants;
  return g && g.length >= 2 ? g : undefined;
});
if (!grants.every((g: any) => g.requesting_host === "uihost")) throw new Error("grants lack requesting_host");

p = await flows.prepareAction(api, flows.targetForStanding(st.standing[0]), { action: "revoke" });
await flows.completeAction(api, owner, p);
step("revoked standing approval");
const first = grants[grants.length - 1];
p = await flows.prepareAction(api, flows.targetForGrant(first), { action: "revoke" });
await flows.completeAction(api, owner, p);
step("revoked grant " + first.id);
console.log("REVOKED-GRANT " + first.id);

// Second passkey: sign "passkey add", register, then sign in with it.
const second = await softAuthenticator();
p = await flows.prepareAction(api, flows.PASSKEY_TARGET, { action: "add" });
step("passkey canonical: " + p.canonicalText);
const reg = await flows.authorizeAddPasskey(api, owner, p);
await flows.completeRegistration(api, second, reg);
cookie = "";
await flows.completeLogin(api, second, await flows.prepareLogin(api));
if ((await api.state()).owner.passkeys !== 2) throw new Error("second passkey not registered");
step("added and used a second passkey");

// Passkey management: rename the first, then remove it (signed with the second, which this
// session uses); the last one can't be removed.
let pks = (await api.state()).passkeys;
const firstPk = pks.find((x: any) => !x.current);
const secondPk = pks.find((x: any) => x.current);
if (pks.length !== 2 || !firstPk || !secondPk || firstPk.nickname !== "Passkey 1") throw new Error("passkey list " + JSON.stringify(pks));
p = await flows.prepareAction(api, flows.targetForPasskey(firstPk), { action: "rename", nickname: "Old laptop" });
step("rename canonical: " + p.canonicalText);
if (p.description.headline !== "Rename the passkey Passkey 1 to Old laptop.") throw new Error("rename headline " + p.description.headline);
await flows.completeAction(api, second, p);
pks = (await api.state()).passkeys;
const renamed = pks.find((x: any) => x.id === firstPk.id);
if (renamed?.nickname !== "Old laptop") throw new Error("rename not applied " + JSON.stringify(pks));
p = await flows.prepareAction(api, flows.targetForPasskey(renamed), { action: "remove" });
const removed = (await flows.completeAction(api, second, p)) as any;
if (!removed.ok || removed.signed_out) throw new Error("remove result " + JSON.stringify(removed));
pks = (await api.state()).passkeys;
if (pks.length !== 1 || pks[0].id !== secondPk.id) throw new Error("after remove " + JSON.stringify(pks));
try {
  await flows.prepareAction(api, flows.targetForPasskey(pks[0]), { action: "remove" });
  throw new Error("server offered to remove the last passkey");
} catch (e) {
  if ((e as any).status !== 409) throw e;
}
step("renamed and removed the first passkey; the last one is protected");
console.log("UI-DRIVER OK");
