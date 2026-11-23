// The Credential sets page in happy-dom against the mock: hostile strings stay text, the
// form never shows stored values, revealed values are dropped on hide.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth } from "./helpers";
import type { VaultPage as Page, VaultHost } from "../src/vaultPage";
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

describe("Credential sets page in a DOM", () => {
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
  const reload = async () => {
    state = await api.vaultState!();
    page.update(state, seal, null);
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
    page = new mod.VaultPage(host);
    (win.document.body as unknown as HTMLElement).append(page.el);
    seal = await api.sealStatus!();
    await reload();
  });
  afterAll(() => {
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("stored values are never in the form; names are", () => {
    const pick = page.el.querySelector<HTMLSelectElement>("#vault-org")!;
    pick.value = state.organisations.find((o) => o.slug === "client-a")!.id;
    pick.dispatchEvent(new win.Event("change") as unknown as Event);
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
    page.clearSecrets();
    expect(page.el.querySelector(".revealed-value")).toBeNull();
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
  });

  test("signer sets offer no reveal and no value form; reveal-off organisations offer none", () => {
    const pick = page.el.querySelector<HTMLSelectElement>("#vault-org")!;
    pick.value = state.organisations.find((o) => o.slug === "personal")!.id;
    pick.dispatchEvent(new win.Event("change") as unknown as Event);
    expect(page.el.querySelector(".vault-signer")).not.toBeNull();
    expect(page.el.querySelector(".vault-editor")).toBeNull();
    expect([...page.el.querySelectorAll(".vault-body button")].some((b) => /Reveal|Export/.test(b.textContent!))).toBe(false);
    expect(page.el.querySelector(".vault-signer")!.textContent).toContain("aqmas sign personal/firmware/");
    pick.value = state.organisations.find((o) => o.slug === "club")!.id;
    pick.dispatchEvent(new win.Event("change") as unknown as Event);
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
    const pick = page.el.querySelector<HTMLSelectElement>("#vault-org")!;
    pick.value = state.organisations.find((o) => o.slug === "client-a")!.id;
    pick.dispatchEvent(new win.Event("change") as unknown as Event);
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
});
