// Admin → Buckets, the header indicator and the approval card in happy-dom against the sealed
// mock: what is open is shown, the card lists what a tap opens before the tap, Close all and
// Rekey say what they do, and no unlock wording is left.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { startMock } from "../mock/server";
import { CLOSE_ALL_TEXT, REKEY_WARNING } from "../src/sealPanel";
import { jarFetch, prfAuth } from "./helpers";

const m = startMock({ port: 0, distDir: null, vault: true });
const win = new Window({ url: m.url + "/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "CSS", "HTMLElement", "HTMLDialogElement", "Node", "navigator"];

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + [...(win.document as unknown as Document).querySelectorAll(".error")].map((e) => e.textContent).join(" | "));
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("buckets in the UI", () => {
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  let root: HTMLElement;
  const go = (hash: string) => {
    win.location.hash = hash;
    win.dispatchEvent(new win.Event("hashchange"));
  };
  const button = (el: ParentNode, re: RegExp) => [...el.querySelectorAll<HTMLButtonElement>("button")].find((b) => re.test(b.textContent ?? ""));

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    if (!(G["CSS"] as { escape?: unknown } | undefined)?.escape) G["CSS"] = { escape: (s: string) => s.replace(/[^A-Za-z0-9_-]/g, (c) => "\\" + c) };
    const doc = win.document as unknown as Document;
    doc.body.innerHTML = '<div id="app"></div>'; // test fixture only
    root = doc.getElementById("app")!;
    const { App } = await import("../src/app");
    new App(root, api, auth).start();
    await until(() => !!root.querySelector("button.primary"));
    await until(() => f.log.some((x) => x.url.endsWith("/api/ui/login/begin")));
    await new Promise((r) => setTimeout(r, 50));
    root.querySelector<HTMLButtonElement>("button.primary")!.click();
    await until(() => !!root.querySelector("#sec-pending article"));
  });
  afterAll(async () => {
    await win.happyDOM.abort();
    win.close();
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("the header says how much is open", async () => {
    await until(() => !!root.querySelector("#buckets-indicator .badge"));
    expect(root.querySelector("#buckets-indicator")!.textContent).toBe("1 bucket open");
  });

  test("the approval card lists what the tap opens, before the tap", async () => {
    const doc = win.document as unknown as Document;
    root.querySelector<HTMLElement>('[data-id="01JDEMO0SSH0DB1XXX0000001"]')!.querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!button(dlg, /^Continue$/));
    button(dlg, /^Continue$/)!.click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect([...dlg.querySelectorAll(".open-lines li")].map((li) => li.textContent)).toEqual(["Opens SSH user CA: for this action only"]);
    expect(dlg.textContent).toContain("PRF test passkey");
    const before = auth.gets.length;
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    expect(auth.gets.length).toBe(before + 1); // inside the tap
    await until(() => !!dlg.querySelector("h2.ok"));
    expect(f.log.filter((x) => x.url.endsWith("/decide")).at(-1)!.body).toHaveProperty("open");
    button(dlg, /^Done$|^Close$/)?.click();
  });

  test("Admin → Buckets: scopes, holds, paused users with Reopen, Create, Rekey and Close all", async () => {
    go("#/admin");
    await until(() => !!root.querySelector("#sec-buckets .buckets"));
    const sec = root.querySelector<HTMLElement>("#sec-buckets")!;
    expect([...sec.querySelectorAll(".scope h3")].map((x) => x.textContent)).toEqual(["Installation", "Personal", "Client A", "Club"]);
    const club = sec.querySelector<HTMLElement>(".scope:last-child")!;
    expect(club.textContent).toContain("No key yet");
    expect(button(club, /^Create…$/)).toBeTruthy();
    const ssh = [...sec.querySelectorAll<HTMLElement>(".bucket")].find((b) => b.textContent!.includes("SSH user CA"))!;
    expect(ssh.querySelector(".badge")!.textContent).toBe("Open");
    expect(ssh.querySelector(".holds")!.textContent).toContain("standing rule");
    const cf = [...sec.querySelectorAll<HTMLElement>(".bucket")].find((b) => b.textContent!.includes("Cloudflare proxy token"))!;
    expect(cf.textContent).toContain("waiting for a Reopen");
    const reopen = button(sec, /^Reopen selected/)!;
    expect(reopen.disabled).toBe(true);
    const tick = cf.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    tick.checked = true;
    tick.dispatchEvent(new win.Event("change") as unknown as Event);
    expect(reopen.disabled).toBe(false);
    // Rekey warns before anything is signed.
    button(sec.querySelector<HTMLElement>(".scope")!, /^Rekey…$/)!.click();
    await until(() => sec.querySelector(".buckets-review")!.textContent!.includes(REKEY_WARNING));
    // A rekey closes its buckets: they are re-keyed, not listed as opened.
    expect(sec.querySelector(".buckets-review .open-lines")!.textContent).toContain("Re-keys SSH user CA");
    expect(sec.querySelector(".buckets-review .open-lines")!.textContent).not.toContain("Opens SSH user CA");
    expect(REKEY_WARNING).toContain("Admin → Recovery");
    // Close all: one signed tap, opens nothing, closes everything.
    button(sec, /^Close all…$/)!.click();
    await until(() => sec.querySelector(".buckets-review")!.textContent!.includes(CLOSE_ALL_TEXT));
    expect(sec.querySelector(".buckets-review")!.textContent).toContain("This tap opens no bucket.");
    const sign = button(sec, /^Close all with passkey$/)!;
    const before = auth.gets.length;
    sign.click();
    expect(auth.gets.length).toBe(before + 1);
    await until(() => root.querySelector("#buckets-indicator")!.textContent === "nothing open", 4000);
    expect(m.store.buckets.buckets.every((b) => !b.open)).toBe(true);
  });

  test("the passkeys panel says what each passkey opens", async () => {
    await until(() => !!root.querySelector("#sec-passkeys .pk"));
    const tiles = [...root.querySelectorAll<HTMLElement>("#sec-passkeys .pk")];
    expect(tiles.some((t) => /Opens \d+ of \d+ buckets/.test(t.textContent!))).toBe(true);
    expect(tiles.some((t) => t.textContent!.includes("Approve only"))).toBe(true);
  });

  test("no unlock wording anywhere on the page", () => {
    const text = (win.document as unknown as Document).body.textContent!;
    expect(text).not.toMatch(/\bunlock|Lock now|\blocked\b/i);
  });

  test("migration required: a banner points to Admin → Setup", async () => {
    await fetch(m.url + "/mock/vault?mode=migration-required");
    go("#/");
    await until(() => !!root.querySelector("#sec-seal .card"), 4000);
    const banner = root.querySelector<HTMLElement>("#sec-seal")!;
    expect(banner.textContent).toContain("Move to per-credential buckets");
    expect(banner.querySelector<HTMLAnchorElement>("a.btn")!.getAttribute("href")).toBe("#/setup");
    await fetch(m.url + "/mock/vault?mode=buckets");
  });
});
