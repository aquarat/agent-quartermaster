// 0.10.0 in happy-dom against the mock: the listing switch in an organisation's policy, the
// Add item → Secret flow, a secret's own view, "don't ask again" on an approval card and its
// per-item limit, and the Help card for agents.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { completeAction, completeLogin, prepareAction, prepareLogin, type ActionChoice, type ActionTarget } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth } from "./helpers";
import type { VaultHost } from "../src/vaultPage";
import type { VaultView as Page } from "../src/vaultView";
import type { Catalogue } from "../src/catalogue";
import type { VaultState } from "../src/vault";
import type { SealView } from "../src/sealPanel";
import type { EnvState } from "../src/envsets";

const m = startMock({ port: 0, distDir: null, vault: true });
const win = new Window({ url: m.url + "/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "Event", "navigator"];
const VALUE = "tskey-api-mock-sentinel-41c7";
const PATH = "client-a/paas/tailnet-api-key";

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + [...(win.document as unknown as Document).querySelectorAll(".error, [role=status]")].map((e) => e.textContent).join(" | "));
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("agent interface, secrets and don't-ask-again in a DOM", () => {
  const api = createApi({ base: m.url, fetch: jarFetch() });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  let page: Page;
  let state: VaultState;
  let seal: SealView;
  let host: VaultHost;
  let catalogue: Catalogue | null = null;
  let sel: string | undefined;
  let loads = 0;
  let asked = 0;
  /** Every reload the page asked for has been drawn (nothing is still on its way). */
  const settled = () => until(() => loads === asked);
  /** A reload this test starts itself, counted like the ones the page asks for. */
  const refresh = () => (asked++, reload());
  const body = () => win.document.body as unknown as HTMLElement;
  const click = (root: ParentNode, text: string) => {
    const b = [...root.querySelectorAll("button")].find((x) => x.textContent === text);
    if (!b) throw new Error("no button " + text + " among " + [...root.querySelectorAll("button")].map((x) => x.textContent).join(" | "));
    b.click();
  };
  const fire = (el: Element, ev: string) => el.dispatchEvent(new win.Event(ev) as unknown as Event);
  const reload = async () => {
    state = await api.vaultState!();
    seal = await api.sealStatus!();
    catalogue = (await api.catalogue!()) ?? null;
    page.update(state, seal, catalogue, sel);
    loads++;
  };
  const select = (path: string | undefined) => {
    sel = path === undefined || path === "new" ? path : state.sets.find((s) => `${s.org_slug}/${s.service_slug}/${s.set_slug}` === path)!.set_id;
    page.update(state, seal, catalogue, sel);
  };
  const setOf = (path: string) => state.sets.find((s) => `${s.org_slug}/${s.service_slug}/${s.set_slug}` === path);

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    await completeLogin(api, auth, await prepareLogin(api));
    host = { api, auth, changed: () => void refresh(), propose: () => {} };
    page = new (await import("../src/vaultView")).VaultView(host);
    body().append(page.el);
    seal = await api.sealStatus!();
    await refresh();
  });
  afterAll(async () => {
    await settled();
    page.clearSecrets();
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("Settings: “Hosts may list what they can ask for” is off, explained, and part of the signed policy", async () => {
    const { policyForm } = await import("../src/catalogue");
    const org = () => catalogue!.organisations.find((o) => o.slug === "client-a")!;
    const asked: { t: ActionTarget; c: ActionChoice }[] = [];
    const draw = () => {
      const f = policyForm(catalogue!, org(), (t, c) => asked.push({ t, c }));
      body().append(f);
      return f;
    };
    let form = draw();
    const list = form.querySelector<HTMLInputElement>(`#pol-discovery-${org().id}`)!;
    const get = form.querySelector<HTMLInputElement>(`#pol-get-${org().id}`)!;
    expect(list.checked).toBe(false);
    expect(get.checked).toBe(true);
    expect(form.textContent).toContain("Hosts may list what they can ask for");
    expect(form.textContent).toContain("Values are never listed");
    expect(form.textContent).toContain("it cannot tell an item it was not told about from one that does not exist");
    // Untouched, the proposal has the shape every earlier release signed.
    click(form, "Review policy replacement…");
    const base = ["default_seconds", "soft_cap_seconds", "indefinite", "standing_default_seconds", "standing_soft_cap_seconds", "standing_indefinite"];
    let plan = JSON.parse(String(asked.at(-1)!.t.facts["plan"]));
    expect(Object.keys(plan.new_policy)).toEqual(base);
    expect(Object.keys(plan.old_policy)).toEqual(base);
    // Turned on: one more field, last, and the confirmation says what it means.
    list.checked = true;
    fire(list, "change");
    click(form, "Review policy replacement…");
    plan = JSON.parse(String(asked.at(-1)!.t.facts["plan"]));
    expect(Object.keys(plan.new_policy)).toEqual([...base, "discovery"]);
    expect(Object.keys(plan.old_policy)).toEqual(base);
    const p = await prepareAction(api, asked.at(-1)!.t, asked.at(-1)!.c);
    expect(p.description.warnings.join(" ")).toContain("Listing ON: every host admitted to this organisation can list the names of its items");
    expect(p.description.warnings.join(" ")).toContain("Affected pending work expires");
    expect(p.description.fields.some(([k, v]) => k === "new_policy › discovery" && v === "true")).toBe(true);
    await completeAction(api, auth, p);
    form.remove();
    await refresh();
    expect(org().policy.discovery).toBe(true);
    expect(org().revision).toBe(2);
    // Drawn again from the new catalogue: on; turning aqmas get off rides the same flow.
    form = draw();
    expect(form.querySelector<HTMLInputElement>(`#pol-discovery-${org().id}`)!.checked).toBe(true);
    const get2 = form.querySelector<HTMLInputElement>(`#pol-get-${org().id}`)!;
    get2.checked = false;
    fire(get2, "change");
    click(form, "Review policy replacement…");
    plan = JSON.parse(String(asked.at(-1)!.t.facts["plan"]));
    expect(Object.keys(plan.new_policy)).toEqual([...base, "discovery", "deny_get"]);
    expect(Object.keys(plan.old_policy)).toEqual([...base, "discovery"]);
    const p2 = await prepareAction(api, asked.at(-1)!.t, asked.at(-1)!.c);
    expect(p2.description.warnings.join(" ")).toContain("aqmas get OFF");
    expect(p2.description.warnings.join(" ")).not.toContain("Listing");
    form.remove();
  });

  test("Add item → Secret: one form, one tap; the value is never shown", async () => {
    select("new");
    const form = page.el.querySelector<HTMLElement>(".vault-add-form")!;
    const set = (id: string, value: string, ev = "input") => {
      const el = form.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(id)!;
      el.value = value;
      fire(el, ev);
    };
    expect([...form.querySelectorAll(".type-card strong")].map((e) => e.textContent)).toEqual(["Secret (single value)", "Env set", "Signing key"]);
    set("#add-org", state.organisations.find((o) => o.slug === "client-a")!.id, "change");
    const radio = form.querySelector<HTMLInputElement>("#add-type-secret")!;
    radio.checked = true;
    fire(radio, "change");
    const secret = form.querySelector<HTMLElement>(".vault-new-secret")!;
    expect(secret.textContent).toContain("New secret in Client A › PaaS");
    expect(form.querySelector(".add-steps")!.hasAttribute("hidden")).toBe(true); // one step
    click(secret, "Review…");
    expect(secret.querySelector(".error")!.textContent).toContain("Slug:");
    set("#sec-title", "Tailnet API key");
    expect(form.querySelector<HTMLInputElement>("#sec-slug")!.value).toBe("tailnet-api-key");
    expect(form.querySelector<HTMLInputElement>("#sec-env")!.value).toBe("TAILNET_API_KEY");
    click(secret, "Review…");
    expect(secret.querySelector(".error")!.textContent).toContain("Type or paste the value");
    set("#sec-value", VALUE);
    set("#sec-env", "LD_PRELOAD");
    click(secret, "Review…");
    expect(secret.querySelector(".error")!.textContent).toContain("Variable name: That name would change how a shell, loader or tool behaves");
    set("#sec-env", "TAILNET_API_KEY");
    set("#sec-url", "javascript:alert(1)");
    click(secret, "Review…");
    expect(secret.querySelector(".error")!.textContent).toContain("Link:");
    set("#sec-url", "https://example.com/admin/keys");
    set("#sec-note", "admin console key");
    const taps = auth.gets.length;
    click(secret, "Review…");
    await until(() => !!secret.querySelector(".vault-confirm .confirm"));
    const confirm = secret.querySelector(".vault-confirm")!.textContent!;
    expect(confirm).toContain("delivered to a command as TAILNET_API_KEY");
    expect(confirm).not.toContain(VALUE);
    expect(form.querySelector<HTMLTextAreaElement>("#sec-value")!.disabled).toBe(true); // frozen until the tap
    expect(auth.gets.length).toBe(taps);
    click(secret, "Create with passkey");
    await until(() => setOf(PATH)?.kind === "secret");
    await settled();
    expect(auth.gets.length).toBe(taps + 1);
    expect(setOf(PATH)).toMatchObject({ revision: 1, names: ["TAILNET_API_KEY"], note: "admin console key", url: "https://example.com/admin/keys" });
    expect(catalogue!.organisations.find((o) => o.slug === "client-a")!.services[0]!.sets.find((s) => s.slug === "tailnet-api-key")!.kind).toBe("secret");
    expect(body().textContent).not.toContain(VALUE);
  });

  test("a secret's page: one name, hidden value, reveal with a tap, replace write-only, run and get", async () => {
    select(PATH);
    const main = page.el.querySelector<HTMLElement>(".vault-secret")!;
    expect(page.el.querySelector(".vault-title")!.textContent).toContain("Secret · " + PATH);
    expect(main.textContent).toContain("Delivered as");
    expect(main.textContent).toContain("TAILNET_API_KEY");
    expect(main.textContent).toContain("admin console key");
    expect(main.querySelector<HTMLAnchorElement>("a")!.href).toBe("https://example.com/admin/keys");
    expect(main.querySelector(".kv-row")).toBeNull(); // not an env set's key editor
    expect(main.textContent).not.toContain(VALUE);
    const use = page.el.querySelector(".vault-use")!.textContent!;
    expect(use).toContain(`aqmas run ${PATH}`);
    expect(use).toContain(`aqmas get ${PATH}`);
    expect(use).toContain("the value leaves aqmas");
    click(main, "Reveal");
    await until(() => !!main.querySelector(".vault-confirm .confirm"));
    click(main, "Reveal with passkey");
    await until(() => !!main.querySelector(".revealed-value"));
    expect(main.querySelector(".revealed-value")!.textContent).toBe(VALUE);
    click(main, "Hide now");
    expect(main.textContent).not.toContain(VALUE);
    // Replace: one field; the old value is not loaded into it.
    const next = main.querySelector<HTMLTextAreaElement>("textarea")!;
    expect(next.value).toBe("");
    const replaceButton = [...main.querySelectorAll("button")].find((b) => b.textContent === "Review and replace…")!;
    expect(replaceButton.disabled).toBe(true);
    next.value = VALUE + "-2";
    fire(next, "input");
    click(main, "Review and replace…");
    await until(() => !!main.querySelector(".vault-confirm .confirm"));
    expect(main.querySelector(".vault-confirm")!.textContent).toContain("revision 1 → 2");
    expect(main.querySelector(".vault-confirm")!.textContent).not.toContain(VALUE);
    click(main, "Replace with passkey");
    await until(() => setOf(PATH)?.revision === 2);
    expect(setOf(PATH)!.names).toEqual(["TAILNET_API_KEY"]);
    await settled();
    expect(page.el.querySelector(".vault-secret")!.textContent).toContain("revision 2");
  });

  test("the item's “longest don't ask again” is one hour until the owner changes it with a tap", async () => {
    await settled();
    select(PATH);
    const line = page.el.querySelector<HTMLElement>(".vault-standing")!;
    const pick = line.querySelector<HTMLSelectElement>("select")!;
    expect([...pick.options].map((o) => o.textContent)).toEqual(["Off", "1 hour", "6 hours", "24 hours"]);
    expect(pick.value).toBe("3600");
    expect([...line.querySelectorAll("button")].find((b) => b.textContent === "Change…")!.disabled).toBe(true);
    pick.value = "21600";
    fire(pick, "change");
    click(line, "Change…");
    await until(() => !!line.querySelector(".vault-confirm .confirm"));
    expect(line.querySelector(".vault-confirm")!.textContent).toContain("up to 6 hours");
    click(line, "Change with passkey");
    await until(() => setOf(PATH)?.standing_cap_seconds === 21600);
    await settled();
    // The line is drawn again from the new limit (a stale one would sign the old value).
    expect(page.el.querySelector<HTMLSelectElement>(".vault-standing select")!.value).toBe("21600");
    // A signing key has signing grants instead: no such line.
    select("personal/firmware/release-key");
    expect(page.el.querySelector(".vault-standing")).toBeNull();
  });

  test("an env set with exactly one key offers Convert to secret", async () => {
    await settled();
    const prod = m.store.vault.sets.find((s) => s.set_slug === "production")!;
    Object.assign(prod, { names: ["DEPLOY_TOKEN"], revision: 1 });
    await refresh();
    select("client-a/paas/staging");
    expect(page.el.querySelector(".vault-convert")).toBeNull(); // several keys
    select("client-a/paas/production");
    const line = page.el.querySelector<HTMLElement>(".vault-convert")!;
    click(line, "Convert to secret…");
    await until(() => !!line.querySelector(".vault-confirm .confirm"));
    expect(line.querySelector(".vault-confirm")!.textContent).toContain("DEPLOY_TOKEN");
    click(line, "Convert with passkey");
    await until(() => setOf("client-a/paas/production")?.kind === "secret");
    await settled();
    expect(page.el.querySelector(".vault-secret")).not.toBeNull();
    expect(page.el.querySelector(".vault-convert")).toBeNull();
  });

  test("approval card for aqmas get: says the value leaves aqmas; “don't ask again” only up to the item's limit", async () => {
    const { envPanel, standingChoices } = await import("../src/envsets");
    expect(standingChoices(0)).toEqual([]);
    expect(standingChoices(3600)).toEqual([3600]);
    expect(standingChoices(86400)).toEqual([3600, 21600, 86400]);
    const id = m.store.vault.addRelease(PATH, "get");
    let env: EnvState = await api.envState!();
    let refreshed = 0;
    const draw = () => {
      const el = envPanel(api, auth, seal, env, null, () => void (async () => ((env = await api.envState!()), refreshed++))());
      body().append(el);
      return el;
    };
    let panel = draw();
    const card = panel.querySelector<HTMLElement>(`[data-release="${id}"]`)!;
    const mode = card.querySelector(".env-mode")!;
    expect(mode.textContent).toContain("GET: the value of TAILNET_API_KEY is handed to the requesting process on build-1");
    expect(mode.textContent).toContain("has left aqmas");
    expect(mode.classList.contains("warn")).toBe(true);
    const again = card.querySelector<HTMLSelectElement>("select.env-standing")!;
    // The item's limit is six hours (set above): 24 hours is not offered; nothing is preselected.
    expect([...again.options].map((o) => o.textContent)).toEqual(["Just this once", "Don't ask again for 1 hour", "Don't ask again for 6 hours"]);
    expect(again.value).toBe("0");
    expect(card.querySelector(".env-standing-words")!.textContent).toBe("");
    again.value = "21600";
    fire(again, "change");
    expect(card.querySelector(".env-standing-words")!.textContent).toContain(`For the next 6 hours, build-1 gets ${PATH} whenever it asks with aqmas get, without asking you.`);
    const taps = auth.gets.length;
    click(card, "Review approve");
    await until(() => !!panel.querySelector("[role=status] pre"));
    const detail = panel.querySelector("[role=status] pre")!.textContent!;
    expect(detail).toContain("has left aqmas");
    expect(detail).toContain("DON'T ASK AGAIN: For the next 6 hours");
    expect(detail).toContain("Requester explanation (unverified): list devices for the inventory report");
    expect(auth.gets.length).toBe(taps);
    click(panel, "Confirm approve with passkey");
    await until(() => m.store.vault.standing.length === 1 && refreshed === 1);
    expect(m.store.vault.standing[0]).toMatchObject({ id, mode: "get", max_ttl_seconds: 600, host: "build-1" });
    panel.remove();
    // The rule is listed where it can be revoked, with a tap.
    panel = draw();
    const rule = panel.querySelector<HTMLElement>(`[data-rule="${id}"]`)!;
    expect(rule.textContent).toContain(`${PATH} · build-1 · don't ask again`);
    expect(rule.textContent).toContain("used 0 times so far");
    click(rule, "Review revoke");
    await until(() => !!panel.querySelector("[role=status] pre"));
    expect(panel.querySelector("[role=status] pre")!.textContent).toContain("its next request asks you again");
    click(panel, "Confirm revoke with passkey");
    await until(() => m.store.vault.standing.length === 0 && refreshed === 2);
    panel.remove();

    // An item whose limit is off offers no choice, and says where to change that.
    const other = m.store.vault.addRelease(PATH, "process");
    env = await api.envState!();
    env = { ...env, standing_caps: { ...env.standing_caps, [setOf(PATH)!.set_id]: 0 } };
    panel = draw();
    const plain = panel.querySelector<HTMLElement>(`[data-release="${other}"]`)!;
    expect(plain.querySelector("select.env-standing")).toBeNull();
    expect(plain.querySelector(".env-standing-off")!.textContent).toContain("off for this item");
    expect(plain.querySelector(".env-mode")!.textContent).toContain("Run: TAILNET_API_KEY goes into the environment of one command on build-1");
    expect(plain.querySelector(".env-mode")!.classList.contains("warn")).toBe(false);
    // The broker refuses a rule beyond the limit even if a page asks for one.
    const { envReview } = await import("../src/envsets");
    const item = env.releases.find((r) => r.id === other)!;
    await expect(envReview(api, seal, item, "approve", 600, new URL(m.url).hostname, 86400)).rejects.toThrow(/longer than its limit/);
    panel.remove();
  });

  test("Help has a card for agents: the guide, the lists and the MCP registration", async () => {
    const { helpPage } = await import("../src/help");
    const el = helpPage({ agent_api_url: "https://192.0.2.10:8443", cli_download_base_url: "", ca_pin: "sha256:" + "a".repeat(64), owner_max_seconds: 86400 });
    const card = [...el.querySelectorAll("section.card")].find((s) => s.querySelector("h2")!.textContent === "For agents")!;
    const commands = [...card.querySelectorAll("pre code")].map((c) => c.textContent);
    expect(commands).toContain("aqmas guide");
    expect(commands).toContain("aqmas ls");
    expect(commands).toContain("aqmas targets");
    expect(commands).toContain("claude mcp add aqmas -- aqmas mcp");
    expect(JSON.parse(commands.find((c) => c!.includes("mcpServers"))!)).toEqual({ mcpServers: { aqmas: { command: "aqmas", args: ["mcp"] } } });
    expect(card.textContent).toContain("No tool returns a secret's value");
    expect(card.textContent).toContain("don't ask again");
  });
});
