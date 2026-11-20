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
    expect(root.querySelectorAll("img, script, b, iframe, a").length).toBe(0);
    const agent = card.querySelector(".agent")!;
    expect(agent.textContent).toContain('<img src=x onerror="alert(1)">');
    expect(agent.textContent).toContain("<b>not-bold</b>");
    expect(agent.textContent).toContain("⟨U+202E⟩"); // bidi override made visible
    // The trusted facts are outside it.
    expect(card.querySelector(".target")!.textContent).toBe("root@ci-1");
    expect(agent.contains(card.querySelector(".target"))).toBe(false);
  });

  test("approve: canonical shown, then the passkey prompt starts inside the tap, no Cancel while signing", async () => {
    const doc = win.document as unknown as Document;
    const card = root.querySelector<HTMLElement>('[data-id="01JDEMO0SSH0DBHOST0000001"]')!;
    card.querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector("button.approve"));
    const ttl15 = [...dlg.querySelectorAll<HTMLInputElement>('input[name="ttl"]')].find((i) => i.value === "900")!;
    ttl15.checked = true;
    [...dlg.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === "Continue")!.click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toBe("Approve SSH as alice@db-1 for 15 min, requested by build-box.");
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
});
