// The UI itself, in happy-dom against the mock: untrusted text stays text, and the passkey
// prompt starts synchronously inside the tap (Safari's user-gesture rule).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { startMock } from "../mock/server";
import { fakeAuth, jarFetch } from "./helpers";

const win = new Window({ url: "http://localhost/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "CSS", "HTMLElement", "HTMLDialogElement", "Node"];

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("App in a DOM", () => {
  const m = startMock({ port: 0, distDir: null });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  let root: HTMLElement;

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
  });

  afterAll(async () => {
    await win.happyDOM.abort();
    win.close();
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("sign-in: the tap calls navigator.credentials.get before any other await", async () => {
    await until(() => !!root.querySelector("button.primary"));
    // Wait for the prefetched login options.
    await until(() => f.log.some((x) => x.url.endsWith("/api/ui/login/begin")));
    await new Promise((r) => setTimeout(r, 50));
    const btn = root.querySelector<HTMLButtonElement>("button.primary")!;
    const before = auth.gets.length;
    const fetches = f.log.length;
    btn.click();
    expect(auth.gets.length).toBe(before + 1); // synchronous, inside the click
    expect(f.log.length).toBe(fetches); // and no request before it
    await until(() => !!root.querySelector("#sec-pending article"));
  });

  test("untrusted fields render as text, inside the fenced box", async () => {
    const card = root.querySelector<HTMLElement>('[data-id="01JDEMO0SSH0ROOT00000002"]')!;
    expect(card).toBeTruthy();
    expect(card.querySelectorAll("img, script, b, iframe, a").length).toBe(0);
    const agent = card.querySelector(".agent")!;
    expect(agent.textContent).toContain('<img src=x onerror="alert(1)">');
    expect(agent.textContent).toContain("<b>not-bold</b>");
    expect(agent.textContent).toContain("⟨U+202E⟩"); // bidi override made visible
    // The trusted facts are outside it.
    expect(card.querySelector(".target")!.textContent).toBe("root@laptop-2");
    expect(agent.contains(card.querySelector(".target"))).toBe(false);
  });

  test("approve: canonical shown, then the passkey prompt starts inside the tap, no Cancel while signing", async () => {
    const doc = win.document as unknown as Document;
    const card = root.querySelector<HTMLElement>('[data-id="01JDEMO0SSH0DB1XXX0000001"]')!;
    card.querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector("button.approve"));
    const ttl15 = [...dlg.querySelectorAll<HTMLInputElement>('input[name="ttl"]')].find((i) => i.value === "900")!;
    ttl15.checked = true;
    [...dlg.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === "Continue")!.click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toBe("Approve SSH as alice@db-1 for 15 min, requested by web-1.");
    expect(dlg.querySelectorAll(".headline bdi").length).toBe(5); // kind, user, target, duration, host: each isolated

    const before = auth.gets.length;
    const fetches = f.log.length;
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    expect(auth.gets.length).toBe(before + 1);
    expect(f.log.length).toBe(fetches);
    expect([...dlg.querySelectorAll("button")].some((b) => b.textContent === "Cancel")).toBe(false);

    await until(() => !!dlg.querySelector("h2.ok"));
    expect(dlg.querySelector("h2.ok")!.textContent).toBe("Approved");
    expect(m.store.applied.at(-1)!.canonical).toMatchObject({ ttl_seconds: 900, target: "db-1" });
  });

  test("no auto-approval choice for a high-risk request", async () => {
    const doc = win.document as unknown as Document;
    doc.querySelector("dialog")?.close();
    const card = root.querySelector<HTMLElement>('[data-id="01JDEMO0SSH0ROOT00000002"]')!;
    card.querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector('input[name="ttl"]'));
    expect(dlg.querySelectorAll('input[name="standing"]').length).toBe(0);
  });

  test("passkeys: listed with authenticator, sync state and this-device; hostile nicknames stay text", async () => {
    expect(root.querySelector('#sec-passkeys')).toBeNull();win.location.hash='#/admin';win.dispatchEvent(new win.Event('hashchange'));
    const evil = '<img src=x onerror="alert(3)">\u202Ekey';
    m.store.passkeys[1]!.info.nickname = evil;
    m.store.audit("owner", "passkey_rename", "passkey:" + m.store.passkeys[1]!.info.id, `to=${JSON.stringify(evil)}`);
    await until(() => !!root.querySelector("#sec-passkeys article") && [...root.querySelectorAll("#sec-passkeys .pk-name")].some((n) => n.textContent!.includes("onerror")), 8000);
    const tiles = [...root.querySelectorAll<HTMLElement>("#sec-passkeys article.pk")];
    expect(tiles.length).toBe(3);
    expect(root.querySelectorAll("img, script, iframe").length).toBe(0);
    expect(tiles[1]!.querySelector(".pk-name")!.textContent).toBe('<img src=x onerror="alert(3)">⟨U+202E⟩key');
    expect(tiles[0]!.textContent).toContain("This device");
    expect(tiles[0]!.textContent).toContain("Synced");
    expect(tiles[2]!.textContent).toContain("Device-bound");
    expect(tiles[2]!.textContent).toContain("Security Key NFC by Yubico");
  });

  test("rename sheet: confirmation text comes from the canonical", async () => {
    const doc = win.document as unknown as Document;
    doc.querySelector("dialog")?.close();
    const tile = [...root.querySelectorAll<HTMLElement>("#sec-passkeys article.pk")][2]!;
    [...tile.querySelectorAll("button")].find((b) => b.textContent === "Rename…")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector("input#pk-rename"));
    const input = dlg.querySelector<HTMLInputElement>("input#pk-rename")!;
    expect(input.value).toBe("YubiKey on keyring");
    input.value = "Desk key";
    [...dlg.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === "Continue")!.click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toMatch(/^Rename the passkey YubiKey on keyring \(id [0-9A-F]{6}\) to Desk key\.$/);
    dlg.close();
  });

  test("activity: day groups, kinds as text + icon, filters, untrusted detail as text", async () => {
    win.location.hash='#/';win.dispatchEvent(new win.Event('hashchange'));await until(()=>!!root.querySelector('#sec-recent'));
    const sec = root.querySelector<HTMLElement>("#sec-recent")!;
    await until(() => !!sec.querySelector(".ev-day"));
    const days = [...sec.querySelectorAll(".ev-day-h")].map((x) => x.textContent);
    expect(days[0]).toBe("Today");
    expect(days).toContain("Yesterday");
    // Every row has a glyph (aria-hidden) and words; colour is never alone.
    for (const row of sec.querySelectorAll(".ev")) {
      expect(row.querySelector(".ev-glyph svg")!.getAttribute("aria-hidden")).toBe("true");
      expect(row.querySelector(".ev-label")!.textContent!.length).toBeGreaterThan(0);
    }
    // The hostile detail in the seed is text inside the unverified fence, once expanded.
    const hostile = [...sec.querySelectorAll<HTMLElement>(".ev")].find((r) => r.classList.contains("ev-request") && r.querySelector(".ev-more")!.textContent!.includes("onerror"))!;
    expect(hostile).toBeTruthy();
    const toggle = hostile.querySelector<HTMLButtonElement>(".ev-toggle")!;
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    toggle.click();
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(hostile.querySelector<HTMLElement>(".ev-more")!.hidden).toBe(false);
    expect(hostile.querySelector(".ev-detail .agent-label")!.textContent).toContain("unverified");
    expect(sec.querySelectorAll("img, script, b").length).toBe(0);
    // The owner's own rename row (nickname with markup) is plain text too, not fenced.
    const own = [...sec.querySelectorAll<HTMLElement>(".ev-passkey")].find((r) => r.querySelector(".ev-more")!.textContent!.includes("onerror"))!;
    expect(own.querySelector(".ev-detail-plain")!.textContent).toContain('<img src=x onerror=\\"alert(3)\\">');

    // Filters: pressed state and rows.
    const btn = (id: string) => root.querySelector<HTMLButtonElement>(`.filters [data-filter="${id}"]`)!;
    btn("passkeys").click();
    expect(btn("passkeys").getAttribute("aria-pressed")).toBe("true");
    expect(btn("all").getAttribute("aria-pressed")).toBe("false");
    const labels = [...sec.querySelectorAll(".ev-label")].map((x) => x.textContent);
    expect(labels.length).toBeGreaterThan(0);
    for (const l of labels) expect(["Signed in", "Signed out", "Passkey added", "Passkey renamed", "Passkey removed", "Enroll code made", "Clone warning"]).toContain(l!);
    btn("hosts").click();
    expect([...sec.querySelectorAll(".actor")].some((a) => a.classList.contains("actor-host"))).toBe(true);
    btn("all").click();
  });

  test("activity rows link to cards that are on the page", async () => {
    const sec = root.querySelector<HTMLElement>("#sec-recent")!;
    const jump = sec.querySelector<HTMLButtonElement>(".ev-jump");
    expect(jump).toBeTruthy();
    expect(jump!.getAttribute("aria-label")).toMatch(/^Show the .+ card$/);
    jump!.click();
    expect(root.querySelectorAll(".focus").length).toBe(1);
  });

  test('Help uses live values and every displayed command has a copy button', async () => {
    win.location.hash='#/help';win.dispatchEvent(new win.Event('hashchange'));
    await until(()=>!!root.querySelector('.command'));
    expect(root.querySelector('#sec-passkeys')).toBeNull();
    expect(root.textContent).toContain('https://agent.example.com:8443');
    expect(root.textContent).toContain('sha256:'+'0'.repeat(64));
    expect(root.querySelectorAll('pre').length).toBe(root.querySelectorAll('.command button').length);
  });
});
