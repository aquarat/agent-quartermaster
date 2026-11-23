// The Vault tab in happy-dom against the mock: hostile strings stay text, the
// form never shows stored values, revealed values are dropped on hide.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth } from "./helpers";
import type { VaultHost } from "../src/vaultPage";
import type { VaultView as Page } from "../src/vaultView";
import type { Catalogue } from "../src/catalogue";
import type { VaultState } from "../src/vault";
import type { SealView } from "../src/sealPanel";

const m = startMock({ port: 0, distDir: null, vault: true });
const win = new Window({ url: m.url + "/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "Event", "navigator"];
const EVIL = '<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>';

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + [...(win.document as unknown as Document).querySelectorAll(".error, [role=status]")].map((e) => e.textContent).join(" | "));
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("Vault tab in a DOM", () => {
  const api = createApi({ base: m.url, fetch: jarFetch() });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  let page: Page;
  let state: VaultState;
  let seal: SealView;
  let host: VaultHost;
  let cards: typeof import("../src/vaultPage").signCards;
  const click = (root: ParentNode, text: string) => {
    const b = [...root.querySelectorAll("button")].find((x) => x.textContent === text);
    if (!b) throw new Error("no button " + text);
    b.click();
  };
  let catalogue: Catalogue | null = null;
  let sel: string | undefined;
  const reload = async () => {
    state = await api.vaultState!();
    seal = await api.sealStatus!();
    catalogue = (await api.catalogue!()) ?? null;
    page.update(state, seal, catalogue, sel);
  };
  /** Open an item the way the address does (#/vault/ID). */
  const select = (path: string | undefined) => {
    sel = path === undefined || path === "new" ? path : state.sets.find((s) => `${s.org_slug}/${s.service_slug}/${s.set_slug}` === path)!.set_id;
    page.update(state, seal, catalogue, sel);
  };

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    await completeLogin(api, auth, await prepareLogin(api));
    const mod = await import("../src/vaultPage");
    cards = mod.signCards;
    host = { api, auth, changed: () => void reload() };
    page = new (await import("../src/vaultView")).VaultView(host);
    (win.document.body as unknown as HTMLElement).append(page.el);
    seal = await api.sealStatus!();
    await reload();
  });
  afterAll(() => {
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("stored values are never in the form; names are", () => {
    select("client-a/paas/staging");
    const text = page.el.textContent!;
    expect(text).toContain("DATABASE_URL");
    expect(text).not.toContain("mock-app-secret");
    expect(text).not.toContain("mock-password");
    expect(page.el.querySelectorAll(".kv-row textarea").length).toBe(0);
  });

  test("reveal shows text only after a tap and drops it on hide", async () => {
    const before = auth.gets.length;
    click(page.el.querySelector(".vault-keys li")!, "Reveal");
    await until(() => !!page.el.querySelector(".vault-confirm .confirm"));
    expect(page.el.textContent).not.toContain("mock-app-secret");
    expect(auth.gets.length).toBe(before);
    click(page.el, "Reveal with passkey");
    await until(() => !!page.el.querySelector(".revealed-value"));
    expect(auth.gets.length).toBe(before + 1);
    expect(page.el.querySelector(".revealed-value")!.textContent).toBe("mock-app-secret-2f9c1e");
    const shown = page.el.querySelector(".revealed-value")!;
    page.clearSecrets(); // what leaving the tab does
    expect(shown.textContent).toBe("");
    expect(page.el.querySelector(".revealed-value")).toBeNull();
    expect(page.el.querySelector(".vault-editor")).toBeNull(); // the form goes too
    expect(page.el.textContent).not.toContain("mock-app-secret");
    page.update(state, seal, catalogue, sel); // coming back builds a fresh one
    expect(page.el.querySelector(".vault-editor")).not.toBeNull();
    expect(page.el.textContent).not.toContain("mock-app-secret");
  });

  test("hostile names, reasons and revealed values render as inert text", async () => {
    const evil: VaultState = JSON.parse(JSON.stringify(state));
    const req = evil.requests.find((r) => r.status === "pending")!;
    req.reason = EVIL;
    req.host = EVIL;
    req.address = EVIL;
    req.items[0]!.name = EVIL + "\u202egnp.bin";
    const set = evil.sets.find((s) => s.set_id === req.set)!;
    set.org_title = set.service_title = set.set_title = EVIL;
    const box = win.document.createElement("div") as unknown as HTMLElement;
    box.append(...cards(host, seal, evil));
    expect(box.querySelector("img")).toBeNull();
    expect(box.querySelector("script")).toBeNull();
    expect(box.textContent).toContain('<img src=x onerror="window.pwned=1">');
    expect(box.textContent).toContain("⟨U+202E⟩");
    // A value with markup, saved through the form and revealed again.
    click(page.el, "Add a key");
    const row = page.el.querySelector(".kv-row")!;
    const name = row.querySelector("input")!, value = row.querySelector("textarea")!;
    name.value = "APP_HTML";
    value.value = EVIL;
    value.dispatchEvent(new win.Event("input") as unknown as Event);
    expect(page.el.querySelector(".vault-changes")!.textContent).toContain("APP_HTML added");
    click(page.el, "Review and save…");
    await until(() => !!page.el.querySelector(".vault-confirm .confirm"));
    expect(page.el.querySelector(".vault-confirm")!.textContent).not.toContain("onerror");
    click(page.el, "Save with passkey");
    await until(() => state.sets.some((s) => s.names.includes("APP_HTML")));
    await until(() => !!page.el.querySelector('.vault-keys li[data-name="APP_HTML"]'));
    expect(page.el.querySelectorAll(".kv-row textarea").length).toBe(0); // the form was cleared
    click(page.el.querySelector('.vault-keys li[data-name="APP_HTML"]')!, "Reveal");
    await until(() => !!page.el.querySelector(".vault-confirm .confirm"));
    click(page.el, "Reveal with passkey");
    await until(() => !!page.el.querySelector(".revealed-value"));
    expect(page.el.querySelector(".revealed-value")!.textContent).toBe(EVIL);
    expect(page.el.querySelector("img")).toBeNull();
    expect(page.el.querySelector("script")).toBeNull();
    expect((win as unknown as { pwned?: number }).pwned).toBeUndefined();
    page.clearSecrets();
    page.update(state, seal, catalogue, sel);
  });

  test("signer sets offer no reveal and no value form; reveal-off organisations offer none", () => {
    select("personal/firmware/release-key");
    expect(page.el.querySelector(".vault-signer")).not.toBeNull();
    expect(page.el.querySelector(".vault-editor")).toBeNull();
    expect([...page.el.querySelectorAll(".vault-main button")].some((b) => /Reveal|Export/.test(b.textContent!))).toBe(false);
    expect(page.el.querySelector(".vault-signer")!.textContent).toContain("aqmas sign personal/firmware/");
    select("club/website/deploy");
    expect(page.el.querySelector(".vault-editor")!.textContent).toContain("Reveal is off");
    expect([...page.el.querySelectorAll(".vault-editor button")].some((b) => b.textContent!.startsWith("Reveal"))).toBe(false);
  });

  test("a time-boxed request says what it really allows; ed25519ph leads with the SHA-512", () => {
    const timed = state.requests.find((r) => r.status === "pending" && r.ttl_seconds > 0)!;
    const box = win.document.createElement("div") as unknown as HTMLElement;
    box.append(...cards(host, seal, { ...state, requests: [timed] }));
    expect(box.textContent).toContain("ANYTHING this host submits");
    expect(box.textContent!.replaceAll(" ", "")).toContain(timed.items[0]!.sha256);
    const ph: VaultState = JSON.parse(JSON.stringify(state));
    const r = ph.requests.find((x) => x.id === timed.id)!;
    r.scheme = ph.sets.find((s) => s.set_id === r.set)!.scheme = "ed25519ph";
    r.items = [{ name: "a.bin", size: 3, sha256: "a".repeat(64), sha512: "b".repeat(128) }];
    const b2 = win.document.createElement("div") as unknown as HTMLElement;
    b2.append(...cards(host, seal, { ...ph, requests: [r] }));
    const labels = [...b2.querySelectorAll(".sign-label")].map((x) => x.textContent);
    expect(labels[0]).toContain("SHA-512 · this is what gets signed");
    expect(labels[1]).toContain("NOT covered by the signature");
  });

  test("the confirmation describes the choice captured at the click, and the form cannot move under it", async () => {
    const timed = state.requests.find((r) => r.status === "pending" && r.ttl_seconds > 0)!;
    const box = win.document.createElement("div") as unknown as HTMLElement;
    (win.document.body as unknown as HTMLElement).append(box);
    box.append(...cards(host, seal, { ...state, requests: [timed] }));
    const once = box.querySelector<HTMLInputElement>("input[type=checkbox]")!;
    const minutes = box.querySelector<HTMLInputElement>("input[type=number]")!;
    click(box, "Approve…");
    // While aqmas is asked and while the panel is open, the limits are frozen.
    expect(once.disabled).toBe(true);
    expect(minutes.disabled).toBe(true);
    await until(() => !!box.querySelector(".vault-confirm"));
    once.checked = true; // a script or a stray event changing the box changes nothing that is shown or signed
    once.dispatchEvent(new win.Event("input") as unknown as Event);
    const panel = box.querySelector(".vault-confirm")!.textContent!;
    expect(panel).toContain(`up to ${timed.max_signatures} signatures over ANYTHING this host submits`);
    expect(panel).not.toContain("Single use");
    click(box.querySelector(".vault-confirm")!, "Cancel");
    expect(once.disabled).toBe(false);
    box.remove();

    // The save panel: the changes listed are the ones taken with the edit.
    select("client-a/paas/staging");
    const editor = page.el.querySelector<HTMLElement>(".vault-editor")!;
    const remove = [...editor.querySelectorAll("button")].filter((b) => b.textContent === "Remove");
    remove[0]!.click();
    click(editor, "Review and save…");
    expect(remove.every((b) => b.disabled)).toBe(true);
    await until(() => !!editor.querySelector(".vault-confirm"));
    const text = editor.querySelector(".vault-confirm")!.textContent!;
    expect(text).toContain("removed");
    expect(text).toContain(":remove"); // the signed changes string itself
    click(editor.querySelector(".vault-confirm")!, "Cancel");
    expect(remove[1]!.disabled).toBe(false);
  });
  test("the list: every item once, key names searchable, never a value; filters narrow it", () => {
    select(undefined);
    expect(page.el.dataset["pane"]).toBe("list");
    const titles = () => [...page.el.querySelectorAll(".vault-item .item-title")].map((x) => x.textContent);
    expect(titles()).toEqual(expect.arrayContaining(["Staging env", "Production env", "Deploy secrets", "Release key", "Image key", "SSH user CA", "Internal CA"]));
    expect(page.el.querySelectorAll(".vault-item").length).toBe(new Set([...page.el.querySelectorAll<HTMLElement>(".vault-item")].map((a) => a.dataset["item"])).size);
    expect(page.el.textContent).not.toContain("mock-app-secret");
    const search = page.el.querySelector<HTMLInputElement>(".vault-search")!;
    search.value = "database_url";
    search.dispatchEvent(new win.Event("input") as unknown as Event);
    expect(titles()).toEqual(["Staging env"]);
    expect(page.el.querySelector(".vault-count")!.textContent).toMatch(/^1 of \d+ items$/);
    search.value = "mock-app-secret"; // a value is not something the page knows
    search.dispatchEvent(new win.Event("input") as unknown as Event);
    expect(titles()).toEqual([]);
    search.value = "";
    search.dispatchEvent(new win.Event("input") as unknown as Event);
    const chip = (re: RegExp) => [...page.el.querySelectorAll<HTMLButtonElement>(".vault-side .side-item")].find((b) => re.test(b.textContent!))!;
    chip(/^Signing keys/).click();
    expect(titles().sort()).toEqual(["Image key", "Release key"]);
    expect(chip(/^Signing keys/).getAttribute("aria-pressed")).toBe("true");
    chip(/^All items/).click();
    chip(/^Club/).click();
    expect(titles()).toEqual(["Deploy secrets"]);
    chip(/^All items/).click();
    // Items link to their address; the selected one is marked.
    const a = page.el.querySelector<HTMLAnchorElement>(".vault-item")!;
    expect(a.getAttribute("href")).toBe("#/vault/" + a.dataset["item"]);
  });

  test("an item shows who may ask for it and its history; hostile titles stay text", async () => {
    select("client-a/paas/staging");
    expect(page.el.dataset["pane"]).toBe("detail");
    expect(page.el.querySelector(".vault-item[aria-current=true] .item-title")!.textContent).toBe("Staging env");
    await until(() => !!page.el.querySelector(".vault-history"));
    const who = page.el.querySelector(".vault-who")!.textContent!;
    expect(who).toContain("build-1");
    expect(who).not.toContain("web-1"); // admitted to personal only
    const hist = page.el.querySelector(".vault-history")!.textContent!;
    expect(hist).toContain("Values delivered");
    expect(hist).toContain("Last changed");
    expect(page.el.querySelector(".vault-use")!.textContent).toContain("aqmas run client-a/paas/staging");
    // Typing in the editor survives a poll that changes something else (a bucket opening).
    click(page.el, "Add a key");
    page.el.querySelector<HTMLInputElement>(".kv-row input")!.value = "KEEP_ME";
    const opened: SealView = JSON.parse(JSON.stringify(seal));
    opened.buckets!.find((b) => b.label === "client-a/paas/staging")!.open = true;
    page.update(state, opened, catalogue, sel);
    expect(page.el.querySelector<HTMLInputElement>(".kv-row input")!.value).toBe("KEEP_ME");
    expect(page.el.querySelector(".vault-bar .badge")!.textContent).toBe("Open now");
    // Another item: nothing of this one stays, not even a confirmation left open in it.
    page.el.querySelector<HTMLDetailsElement>("details.vault-more")!.open = true;
    click(page.el.querySelector(".vault-more")!, "Turn reveal off…");
    await until(() => !!page.el.querySelector(".vault-more .vault-confirm"));
    page.update(state, opened, catalogue, sel); // a poll leaves the open confirmation alone
    expect(page.el.querySelector(".vault-more .vault-confirm")).not.toBeNull();
    select("club/website/deploy");
    expect(page.el.querySelector(".vault-confirm")).toBeNull();
    expect(page.el.querySelector(".vault-extra")!.textContent).not.toContain("client-a/paas/staging");
    expect(page.el.querySelector(".vault-use")!.textContent).toContain("aqmas run club/website/deploy");
    expect(page.el.querySelector<HTMLInputElement>(".kv-row input")).toBeNull();
    select("client-a/paas/staging");
    const evil: VaultState = JSON.parse(JSON.stringify(state));
    for (const x of evil.sets) x.set_title = x.org_title = x.service_title = EVIL;
    page.update(evil, seal, null, sel);
    expect(page.el.querySelector("img")).toBeNull();
    expect(page.el.querySelector("script")).toBeNull();
    expect(page.el.textContent).toContain("onerror");
    page.update(state, seal, catalogue, sel);
  });

  test("what the broker holds itself is listed and explained, with nothing to reveal", () => {
    const ca = [...page.el.querySelectorAll<HTMLAnchorElement>(".vault-item")].find((a) => a.textContent!.includes("SSH user CA"))!;
    sel = ca.dataset["item"];
    page.update(state, seal, catalogue, sel);
    const info = page.el.querySelector(".vault-info")!;
    expect(info.textContent).toContain("never leaves");
    expect(page.el.querySelector(".vault-editor")).toBeNull();
    expect([...page.el.querySelectorAll(".vault-detail button")].some((b) => /Reveal|Export/.test(b.textContent!))).toBe(false);
  });

  test("Add item: a type, a place and a name; what is missing is created in order", async () => {
    const proposed: { object: string; plan: Record<string, { slug: string; title: string; id: string }> }[] = [];
    host.propose = (t) => proposed.push({ object: t.object, plan: JSON.parse(String(t.facts!["plan"])) });
    const fresh = new (await import("../src/vaultView")).VaultView(host);
    (win.document.body as unknown as HTMLElement).append(fresh.el);
    fresh.update(state, seal, catalogue, "new");
    const form = fresh.el.querySelector<HTMLElement>(".vault-add-form")!;
    const set = (id: string, value: string, ev = "input") => {
      const el = form.querySelector<HTMLInputElement | HTMLSelectElement>(id)!;
      el.value = value;
      el.dispatchEvent(new win.Event(ev) as unknown as Event);
    };
    // An existing organisation and service: one step, the empty set.
    set("#add-org", state.organisations.find((o) => o.slug === "client-a")!.id, "change");
    expect(form.querySelector(".add-steps")!.hasAttribute("hidden")).toBe(true);
    click(form, "Create env set…");
    expect(form.querySelector(".error")!.textContent).toContain("Item:");
    set("#add-set-title", "Preview env");
    expect(form.querySelector<HTMLInputElement>("#add-set-slug")!.value).toBe("preview-env");
    expect(form.querySelector(".add-path")!.textContent).toContain("client-a/paas/preview-env");
    click(form, "Create env set…");
    expect(proposed.at(-1)!.object).toBe("credential_set");
    expect(proposed.at(-1)!.plan["set"]).toMatchObject({ slug: "preview-env", title: "Preview env" });
    expect(proposed.at(-1)!.plan["organisation"]!.slug).toBe("client-a");
    set("#add-set-slug", "staging"); // taken in that service
    click(form, "Create env set…");
    expect(form.querySelector(".error")!.textContent).toContain("already used");
    // A new organisation: its creation comes first, then its key, service and the set.
    set("#add-org", "new", "change");
    set("#add-org-new-title", "Side project");
    expect([...form.querySelectorAll(".add-steps li")].length).toBe(4);
    expect(form.querySelector(".add-steps li.now")!.textContent).toContain("Create the organisation Side project");
    click(form, "Create organisation…");
    expect(proposed.at(-1)!.object).toBe("organisation");
    expect(proposed.at(-1)!.plan["organisation"]).toMatchObject({ slug: "side-project", title: "Side project" });
    // A signing key in an existing service: the signer form, with the service named.
    set("#add-org", state.organisations.find((o) => o.slug === "personal")!.id, "change");
    form.querySelector<HTMLInputElement>("#add-type-signer")!.checked = true;
    form.querySelector<HTMLInputElement>("#add-type-signer")!.dispatchEvent(new win.Event("change") as unknown as Event);
    expect(form.querySelector(".vault-new-signer")!.textContent).toContain("New signing key in Personal › Firmware");
    fresh.el.remove();
    delete host.propose;
  });
});
