// Cloudflare cards in a DOM (happy-dom) against the mock: plain words from the page's own
// scope table, cf.admin loud, the standing offer only where allowed, revoke of a Cloudflare grant.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { mockPendingCloudflare, startMock } from "../mock/server";
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

describe("Cloudflare cards", () => {
  const m = startMock({ port: 0, distDir: null });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  let root: HTMLElement;
  let doc: Document;
  // Extra items the tests need, added before the first render.
  const tokenStanding = m.store.spawnCloudflare({ ...mockPendingCloudflare("cf.pages", { project: "shopfront" }, "token"), standing_allowed: true });
  const unknown = m.store.spawnCloudflare({ ...mockPendingCloudflare("cf.read"), scope: "cf.mystery", title: "Mystery" });

  const card = (id: string) => root.querySelector<HTMLElement>(`[data-id="${id}"]`)!;
  const dialog = () => doc.querySelector("dialog")!;
  async function openApprove(id: string) {
    dialog()?.close();
    card(id).querySelector<HTMLButtonElement>("button.approve")!.click();
    await until(() => !!dialog().querySelector('input[name="ttl"]'));
    return dialog();
  }

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    if (!(G["CSS"] as { escape?: unknown } | undefined)?.escape) G["CSS"] = { escape: (s: string) => s.replace(/[^A-Za-z0-9_-]/g, (c) => "\\" + c) };
    doc = win.document as unknown as Document;
    doc.body.innerHTML = '<div id="app"></div>'; // test fixture only
    root = doc.getElementById("app")!;
    await completeLogin(api, auth, await prepareLogin(api));
    const { App } = await import("../src/app");
    new App(root, api, auth).start();
    await until(() => !!root.querySelector('[data-id="01JDEMO0CF0ADMIN000000012"]'));
  });

  afterAll(async () => {
    await win.happyDOM.abort();
    win.close();
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("a DNS card reads in plain words, each parameter on its own", () => {
    const c = card("01JDEMO0CF0DNS0EDIT000009");
    expect(c.querySelector("h3.target")!.textContent).toBe("Edit DNS records in zone example.net (only names matching *.example.net)");
    expect(c.querySelectorAll("h3.target bdi").length).toBe(2);
    expect(c.querySelector(".badge")!.textContent).toBe("High risk");
    expect(c.querySelector(".badge")!.classList.contains("risk-high")).toBe(true);
    const facts = [...c.querySelectorAll(".facts dt")].map((d) => [d.textContent, d.nextElementSibling!.textContent]);
    expect(facts).toContainEqual(["Zone", "example.net"]);
    expect(facts).toContainEqual(["Only DNS names", "*.example.net"]);
    expect(facts).toContainEqual(["Mode", "Through the aqmas proxy (no secret leaves aqmas)"]);
    expect(facts).toContainEqual(["Scope", "cf.dns.edit"]);
    expect(facts.find(([k]) => k === "Ref")![1]).toBe("000009");
    expect(c.querySelector(".agent")!.textContent).toContain("Add a CNAME");
    expect(c.classList.contains("cf-admin")).toBe(false);
    expect(c.querySelector(".scope-details")!.textContent).toContain("Cannot:");
  });

  test("cf.admin is loud", () => {
    const c = card("01JDEMO0CF0ADMIN000000012");
    expect(c.classList.contains("cf-admin")).toBe(true);
    expect(c.querySelector(".badge.risk-admin")!.textContent).toBe("Break-glass");
    expect(c.querySelector(".breakglass")!.textContent).toMatch(/BREAK-GLASS: full Cloudflare access for 1 hour, everything except the deny-list/);
    expect(c.getAttribute("aria-label")).toMatch(/^Break-glass Cloudflare request/);
    expect(c.querySelector("button.approve")!.textContent).toBe("Approve break-glass…");
  });

  test("a token card shows the server's permissions and notes, and the page's own warning", () => {
    const c = card("01JDEMO0CF0WORKER0TOKEN11");
    const box = c.querySelector(".token-box")!;
    expect(box.textContent).toContain("A real API token leaves aqmas");
    expect([...box.querySelectorAll(".perms li")].map((l) => l.textContent)).toContain("Workers Routes Write (zone example.net)");
    expect(box.querySelector(".notes")!.textContent).toMatch(/ANY Worker/);
    expect(box.querySelector(".warn")!.textContent).toMatch(/ANY Worker on the account/);
    const mode = [...c.querySelectorAll(".facts dt")].find((d) => d.textContent === "Mode")!.nextElementSibling!.textContent;
    expect(mode).toBe("Real API token, usable only from 203.0.113.7/32");
  });

  test("approve sheet: standing offered for a proxy scope that allows it, TTLs within ttl_max", async () => {
    const dlg = await openApprove("01JDEMO0CF0DNS0EDIT000009");
    expect(dlg.querySelectorAll('input[name="standing"]').length).toBe(4);
    for (const i of dlg.querySelectorAll<HTMLInputElement>('input[name="ttl"]')) expect(Number(i.value)).toBeLessThanOrEqual(28800);
  });

  test("no standing offer for token mode (even if the server says allowed) or cf.admin; cf.admin TTLs never above 1 h", async () => {
    let dlg = await openApprove("01JDEMO0CF0WORKER0TOKEN11");
    expect(dlg.querySelectorAll('input[name="standing"]').length).toBe(0);
    dlg = await openApprove(tokenStanding.id);
    expect(dlg.querySelectorAll('input[name="standing"]').length).toBe(0);
    dlg = await openApprove("01JDEMO0CF0ADMIN000000012");
    expect(dlg.querySelectorAll('input[name="standing"]').length).toBe(0);
    const ttls = [...dlg.querySelectorAll<HTMLInputElement>('input[name="ttl"]')].map((i) => Number(i.value));
    expect(Math.max(...ttls)).toBe(3600);
    expect(dlg.querySelector("#sheet-title")!.textContent).toBe("Approve break-glass access");
  });

  test("cf.admin confirmation is loud, then the passkey prompt starts inside the tap", async () => {
    const dlg = await openApprove("01JDEMO0CF0ADMIN000000012");
    [...dlg.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === "Continue")!.click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector("#sheet-title")!.textContent).toBe("Break-glass: check, then confirm");
    expect(dlg.querySelector(".headline")!.classList.contains("loud")).toBe(true);
    expect(dlg.querySelector(".headline")!.textContent).toBe(
      "Approve Cloudflare for agenthost: use the WHOLE Cloudflare account (break-glass: everything except the deny-list) for 1 hour, through the aqmas proxy (no secret leaves aqmas).",
    );
    expect(dlg.querySelector("p.breakglass")!.textContent).toMatch(/^BREAK-GLASS/);
    expect(dlg.querySelector(".badge.risk-admin")).toBeTruthy();
    const before = auth.gets.length;
    const fetches = f.log.length;
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    expect(auth.gets.length).toBe(before + 1);
    expect(f.log.length).toBe(fetches);
    await until(() => !!dlg.querySelector("h2.ok"));
    expect(m.store.applied.at(-1)!.canonical).toMatchObject({ scope: "cf.admin", ttl_seconds: 3600, standing_hours: 0 });
  });

  test("confirmation lists each parameter separately", async () => {
    const dlg = await openApprove("01JDEMO0CF0TUNNEL00000010");
    [...dlg.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === "Continue")!.click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect([...dlg.querySelectorAll(".cf-details li")].map((l) => l.textContent)).toEqual(["Tunnel: main", "Mode: through the aqmas proxy"]);
    dialog().close();
  });

  test("an unknown scope: Approve is disabled and the card says why", () => {
    const c = card(unknown.id);
    expect(c.querySelector("h3.target")!.textContent).toBe("Unknown Cloudflare scope cf.mystery");
    expect(c.querySelector(".warn")!.textContent).toMatch(/no description of the Cloudflare scope "cf.mystery"/);
    expect(c.querySelector<HTMLButtonElement>("button.approve")!.disabled).toBe(true);
  });

  test("Cloudflare grants and standing approvals are listed; a grant revokes with its own wording", async () => {
    // Wait for the poll after the admin approval to list the new grant.
    await new Promise((r) => setTimeout(r, 50));
    const g = card("01JDEMO0CFGRANT0READ00008");
    expect(g.querySelector("h3")!.textContent).toBe("Read the Cloudflare configuration (allow-listed reads only)");
    const st = card("01JDEMO0CFSTANDING0000013");
    expect(st.querySelector("h3")!.textContent).toBe("Edit DNS records in zone example.net");
    const facts = [...st.querySelectorAll(".facts dt")].map((d) => [d.textContent, d.nextElementSibling!.textContent]);
    expect(facts).toContainEqual(["Zone", "example.net"]);
    expect(facts).toContainEqual(["Mode", "Through the aqmas proxy"]);

    dialog()?.close();
    g.querySelector<HTMLButtonElement>("button.deny")!.click();
    const dlg = dialog();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toBe("Revoke agenthost's Cloudflare access: read the Cloudflare configuration (allow-listed reads only).");
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => !!dlg.querySelector("h2.neg") && dlg.querySelector("h2")!.textContent === "Revoked");
    expect(dlg.textContent).toContain("The aqmas proxy refuses it from the next call.");
    expect(m.store.applied.at(-1)!.canonical).toMatchObject({ object: "grant", kind: "cloudflare", scope: "cf.read" });
  });

  test("Cloudflare activity rows: own glyphs and colours, a cloud mark, their own filter", async () => {
    win.location.hash = "#/activity";
    win.dispatchEvent(new win.Event("hashchange"));
    await until(() => !!root.querySelector("#sec-recent"));
    const sec = root.querySelector<HTMLElement>("#sec-recent")!;
    await until(() => !!sec.querySelector(".ev-cf"));
    const rows = [...sec.querySelectorAll<HTMLElement>(".ev")];
    const row = (label: string) => rows.find((r) => r.querySelector(".ev-label")!.textContent === label)!;
    expect(row("Cloudflare auto-approved").classList.contains("ev-auto")).toBe(true);
    expect(row("Cloudflare write").classList.contains("ev-cfwrite")).toBe(true);
    expect(row("Cloudflare refused").classList.contains("ev-warning")).toBe(true);
    expect(row("Token minted").classList.contains("ev-token")).toBe(true);
    // The owner's approval of cf.admin earlier in this file, and the revoke of the cf.read grant.
    expect(row("Cloudflare approved").classList.contains("ev-approve")).toBe(true);
    for (const r of rows.filter((x) => x.classList.contains("ev-cf"))) {
      expect(r.querySelector(".ev-glyph .cf-mark")!.getAttribute("aria-hidden")).toBe("true");
      expect(r.querySelector(".ev-label")!.textContent).toMatch(/Cloudflare|Token/);
    }
    // SSH rows carry no cloud mark.
    expect(rows.filter((x) => !x.classList.contains("ev-cf")).every((r) => !r.querySelector(".cf-mark"))).toBe(true);
    const btn = (id: string) => root.querySelector<HTMLButtonElement>(`.filters [data-filter="${id}"]`)!;
    btn("cloudflare").click();
    const shown = [...sec.querySelectorAll<HTMLElement>(".ev")];
    expect(shown.length).toBeGreaterThan(3);
    expect(shown.every((r) => r.classList.contains("ev-cf"))).toBe(true);
    btn("all").click();
  });
});
