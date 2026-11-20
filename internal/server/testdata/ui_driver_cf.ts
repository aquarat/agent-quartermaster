// Owner side of TestUIFlowsCloudflare (ui_flows_cf_test.go): the web UI's own flow code
// (web/src/flows.ts, canonical.ts checks) approving and revoking Cloudflare requests against a
// real aqmasd, with the software passkey. Prints "UI-DRIVER-CF OK" at the end.

const web = process.env.AQMAS_WEB_DIR!;
const base = process.env.AQMAS_BASE!;
const origin = process.env.AQMAS_ORIGIN!;
const code = process.env.AQMAS_CODE!;

const { createApi } = await import(`${web}/src/api.ts`);
const flows = await import(`${web}/src/flows.ts`);
const { softAuthenticator } = await import("../../../test/interop/softauthn.ts");

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
const step = (s: string) => console.log("ui-driver-cf: " + s);
const pendingScope = (scope: string) =>
  waitFor(scope, async () => (await api.state()).pending?.find((p: any) => p.kind === "cloudflare" && p.cloudflare?.scope === scope));
async function refused(what: string, f: () => Promise<unknown>) {
  try {
    await f();
  } catch (e) {
    if ((e as any).status === 400 || (e as any).name === "CanonicalError") return;
    throw e;
  }
  throw new Error("accepted: " + what);
}

const owner = await softAuthenticator(origin);
await flows.completeRegistration(api, owner, await flows.prepareRegistrationWithCode(api, code));
await flows.completeLogin(api, owner, await flows.prepareLogin(api));
const enr = await waitFor("enrollment", async () => (await api.state()).pending?.find((p: any) => p.kind === "enrollment"));
await flows.completeAction(api, owner, await flows.prepareAction(api, flows.targetForPending(enr), { action: "approve" }));
step("approved enrollment");

// 1. DNS edit, proxy mode: approve shorter TTL with a 1 h standing approval.
const dns = await pendingScope("cf.dns.edit");
if (dns.cloudflare.scope_params !== "name=*.example.com;zone=example.com") throw new Error("scope_params " + dns.cloudflare.scope_params);
let p = await flows.prepareAction(api, flows.targetForPending(dns), { action: "approve", ttl_seconds: 3600, standing_hours: 1 });
step("dns canonical: " + p.canonicalText);
const c = JSON.parse(p.canonicalText);
if (c.scope !== "cf.dns.edit" || c.mode !== "proxy" || c.ip_condition !== "" || c.standing_hours !== 1) throw new Error("dns canonical fields");
await flows.completeAction(api, owner, p);

// 2. Token mode: no standing approvals; the canonical text carries the IP condition.
const tok = await pendingScope("cf.workers.deploy");
await refused("standing in token mode", () =>
  flows.prepareAction(api, flows.targetForPending(tok), { action: "approve", ttl_seconds: tok.ttl_max, standing_hours: 1 }));
p = await flows.prepareAction(api, flows.targetForPending(tok), { action: "approve", ttl_seconds: tok.ttl_max });
step("token canonical: " + p.canonicalText);
if (JSON.parse(p.canonicalText).ip_condition !== "198.51.100.0/24,203.0.113.7/32") throw new Error("ip_condition");
await flows.completeAction(api, owner, p);

// 3. Break-glass: no standing, at most 1 h.
const adm = await pendingScope("cf.admin");
if (adm.cloudflare.risk !== "admin" || adm.risk !== "high" || adm.ttl_max > 3600) throw new Error("admin card " + JSON.stringify(adm));
await refused("standing on cf.admin", () =>
  flows.prepareAction(api, flows.targetForPending(adm), { action: "approve", ttl_seconds: 1800, standing_hours: 1 }));
await refused("ttl above ttl_max", () => flows.prepareAction(api, flows.targetForPending(adm), { action: "approve", ttl_seconds: 7200 }));
p = await flows.prepareAction(api, flows.targetForPending(adm), { action: "approve", ttl_seconds: 1800 });
step("admin canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);

// 4. Revoke the token grant (deletes the child token) and the DNS standing approval.
const st = await waitFor("cf grants", async () => {
  const s = await api.state();
  return s.grants?.some((g: any) => g.scope === "cf.workers.deploy" && g.mode === "token") && s.standing?.length ? s : undefined;
});
const tg = st.grants.find((g: any) => g.scope === "cf.workers.deploy");
p = await flows.prepareAction(api, flows.targetForGrant(tg), { action: "revoke" });
step("grant revoke canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);
console.log("REVOKED-GRANT " + tg.id);
const sa = st.standing.find((s: any) => s.scope === "cf.dns.edit");
p = await flows.prepareAction(api, flows.targetForStanding(sa), { action: "revoke" });
step("standing revoke canonical: " + p.canonicalText);
await flows.completeAction(api, owner, p);
console.log("REVOKED-STANDING " + sa.id);
console.log("UI-DRIVER-CF OK");
