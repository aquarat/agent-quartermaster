// The whole page in happy-dom against the mock: the tabs, what each page holds, the vault
// through the address, the header's tray and search, and the guided "enable my other
// passkeys" sequence end to end.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { ApiError, createApi } from "../src/api";
import { decode, encode } from "../src/b64url";
import { startMock } from "../mock/server";
import { TABS } from "../src/nav";
import type { Authenticator } from "../src/webauthn";
import { jarFetch, prfAuth } from "./helpers";

const m = startMock({ port: 0, distDir: null, vault: true });
const win = new Window({ url: m.url + "/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "Event", "navigator", "CSS"];

async function until(cond: () => boolean, ms = 4000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + [...(win.document as unknown as Document).querySelectorAll(".error, [role=alert]")].map((e) => e.textContent).join(" | "));
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("navigation", () => {
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const me = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, me.id);
  m.store.buckets.enableAll(me.id);
  // The seeded hardware key (enabled for nothing yet), as an authenticator of its own.
  const seededKey = m.store.passkeys[2]!;
  const yk = prfAuth(m.url, { rawId: new Uint8Array(decode(seededKey.id)) });
  const taps: string[] = [];
  const auth: Authenticator = {
    get(o) {
      const allow = (o.allowCredentials ?? []).map((c) => encode(c.id as ArrayBuffer));
      const who = allow.length === 1 && allow[0] === yk.id ? yk : me;
      taps.push(who === yk ? "key" : "me");
      return who.get(o);
    },
    create: (o) => me.create(o),
  };
  let root: HTMLElement;
  let doc: Document;
  const go = (hash: string) => {
    win.location.hash = hash;
    win.dispatchEvent(new win.Event("hashchange"));
  };
  const button = (el: ParentNode, re: RegExp) => [...el.querySelectorAll<HTMLButtonElement>("button")].find((b) => re.test(b.textContent ?? ""));
  const sections = () => [...root.querySelectorAll<HTMLElement>("main section.section")].map((s) => s.id.replace(/^sec-/, ""));
  const current = () => [...root.querySelectorAll('.tab[aria-current="page"]')].map((a) => a.textContent!.replace(/[\d!]+$/, ""));

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    if (!(G["CSS"] as { escape?: unknown } | undefined)?.escape) G["CSS"] = { escape: (s: string) => s.replace(/[^A-Za-z0-9_-]/g, (c) => "\\" + c) };
    doc = win.document as unknown as Document;
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

  test("seven tabs, the current one marked, what waits counted on Approvals", () => {
    const tabs = [...root.querySelectorAll<HTMLAnchorElement>("nav.tabs a.tab")];
    expect(tabs.map((a) => a.getAttribute("href"))).toEqual(TABS.map((t) => t.hash));
    expect(tabs.map((a) => a.querySelector(".tab-label")!.textContent)).toEqual(["Approvals", "Vault", "Hosts", "Activity", "Security", "Settings", "Help"]);
    expect(current()).toEqual(["Approvals"]);
    // Requests, enrollments and signature requests all wait for the owner.
    const waiting = m.store.pending.length + m.store.vault.requests.filter((r) => r.status === "pending").length;
    expect(root.querySelector('.tab[data-tab="approvals"] .tab-count')!.textContent).toBe(String(waiting));
    expect(doc.title).toBe(`(${waiting}) aqmas`);
    // One passkey opens nothing yet: Security carries a mark with words for a screen reader.
    const mark = root.querySelector('.tab[data-tab="security"] .tab-count')!;
    expect(mark.textContent).toBe("!");
    expect(mark.getAttribute("aria-label")).toContain("cannot open your credentials yet");
  });

  test("each page holds its own sections and nothing else", async () => {
    expect(sections()).toEqual(["signing", "env", "pending", "enroll", "grants", "standing"]);
    const pages: [string, string, string[]][] = [
      ["#/vault", "Vault", ["vault"]],
      ["#/hosts", "Hosts", ["hosts"]],
      ["#/activity", "Activity", ["recent"]],
      ["#/security", "Security", ["readiness", "passkeys", "buckets", "recovery"]],
      ["#/settings", "Settings", ["setup", "bastion", "orgs"]],
      ["#/help", "Help", ["help"]],
      ["#/admin", "Settings", ["setup", "bastion", "orgs"]], // an old bookmark
      ["#/setup", "Settings", []], // Setup is a page of Settings
      ["#/", "Approvals", ["signing", "env", "pending", "enroll", "grants", "standing"]],
    ];
    for (const [hash, tab, want] of pages) {
      go(hash);
      await until(() => current()[0] === tab && JSON.stringify(sections()) === JSON.stringify(want));
      // The tray and what is waiting stay in the header on every page.
      expect(root.querySelector(".topbar .tray-button")!.textContent).toMatch(/open$/);
      expect(root.querySelector('.tab[data-tab="approvals"] .tab-count')!.textContent).not.toBe("");
      expect(doc.title).toMatch(/^\(\d+\) /);
    }
    expect(root.querySelector(".crumb a")).toBeNull();
    // Following a tab with the keyboard leaves the focus on the tabs (the header is redrawn).
    root.querySelector<HTMLElement>('.tab[data-tab="hosts"]')!.focus();
    go("#/hosts");
    await until(() => current()[0] === "Hosts");
    expect((doc.activeElement as HTMLElement).dataset["tab"]).toBe("hosts");
    go("#/");
    await until(() => current()[0] === "Approvals" && sections().length === 6);
  });

  test("Vault: the address selects the item; no value without its own tap", async () => {
    const staging = m.store.vault.sets.find((s) => s.set_slug === "staging")!;
    go("#/vault");
    await until(() => root.querySelectorAll(".vault-item").length > 5);
    expect(root.querySelector(".vault3")!.getAttribute("data-pane")).toBe("list");
    expect(root.querySelector(".vault-placeholder")!.textContent).toContain("passkeys can open your credentials");
    const link = root.querySelector<HTMLAnchorElement>(`.vault-item[data-item="${staging.set_id}"]`)!;
    go(link.getAttribute("href")!);
    await until(() => !!root.querySelector(".vault-editor .vault-keys li"));
    expect(root.querySelector(".vault3")!.getAttribute("data-pane")).toBe("detail");
    expect(root.textContent).not.toContain("mock-app-secret");
    const gets = me.gets.length;
    button(root.querySelector(".vault-keys li")!, /^Reveal$/)!.click();
    await until(() => !!root.querySelector(".vault-confirm .confirm"));
    expect(me.gets.length).toBe(gets);
    expect(root.textContent).not.toContain("mock-app-secret");
    button(root, /^Reveal with passkey$/)!.click();
    await until(() => !!root.querySelector(".revealed-value"));
    expect(me.gets.length).toBe(gets + 1);
    // Leaving the item, or the tab, drops what was shown.
    go("#/vault");
    await until(() => root.querySelector(".vault3")!.getAttribute("data-pane") === "list");
    expect(root.querySelector(".revealed-value")).toBeNull();
    go(link.getAttribute("href")!);
    await until(() => !!root.querySelector(".vault-editor"));
    expect(root.querySelector(".revealed-value")).toBeNull();
    expect(root.textContent).not.toContain("mock-app-secret");
    // An address that names no item: a moment's grace (an item created a second ago), no item shown.
    go("#/vault/nope");
    await until(() => /Looking for that item|not in the vault/.test(root.querySelector(".vault-main")!.textContent!));
    expect(root.querySelector(".vault-editor")).toBeNull();
    // Typed values go with the tab, every time (the forms are rebuilt on the way back).
    for (const round of [1, 2]) {
      go(link.getAttribute("href")!);
      await until(() => !!root.querySelector(".vault-editor"));
      button(root.querySelector(".vault-editor")!, /^Add a key$/)!.click();
      const typed = root.querySelector<HTMLTextAreaElement>(".kv-row textarea")!;
      typed.value = "typed-secret-" + round;
      go("#/hosts");
      await until(() => current()[0] === "Hosts");
      expect(typed.value).toBe("");
      expect(typed.isConnected).toBe(false);
    }
  });

  test("Hosts: each host with its admissions; admitting is a signed catalogue change", async () => {
    go("#/hosts");
    await until(() => root.querySelectorAll("#sec-hosts article.card").length === 3);
    const web = [...root.querySelectorAll<HTMLElement>("#sec-hosts article.card")].find((c) => c.querySelector("h3")!.textContent === "web-1")!;
    const rows = [...web.querySelectorAll<HTMLElement>(".admission-list li")];
    expect(rows.map((r) => r.querySelector("bdi")!.textContent + ":" + r.querySelector(".badge")!.textContent)).toEqual(["Personal:admitted", "Client A:not admitted", "Club:not admitted"]);
    button(rows[1]!, /^Admit…$/)!.click();
    const dlg = doc.querySelector<HTMLDialogElement>("dialog.sheet")!;
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toBe("Client A: admit org host.");
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => m.store.vault.catalogue().organisations.find((o) => o.slug === "client-a")!.hosts.find((x) => x.name === "web-1")!.active);
    button(dlg, /^Done$|^Close$/)?.click();
    expect(web.querySelector("button.deny")).toBeTruthy(); // Revoke host is still here
  });

  // Generous: these wait for the page to follow the mock through several round trips.
  const soon = (cond: () => boolean) => until(cond, 30_000);
  const sheet = () => doc.querySelector<HTMLDialogElement>("dialog.sheet")!;
  const catHost = (org: string, name: string) => m.store.vault.catalogue().organisations.find((o) => o.slug === org)!.hosts.find((x) => x.name === name);
  const joinCard = async (name: string) => {
    go("#/");
    await soon(() => [...root.querySelectorAll("article.card.enroll")].some((c) => c.querySelector("h3")!.textContent === name));
    return [...root.querySelectorAll<HTMLElement>("article.card.enroll")].find((c) => c.querySelector("h3")!.textContent === name)!;
  };

  test("letting a host join offers to admit it: two confirmations, a failed admission is shown and can be retried", async () => {
    const card = await joinCard("kiosk-3");
    expect(card.querySelector(".admit-hint")!.textContent).toContain("also offers to admit it to an organisation");
    button(card, /^Let it join…$/)!.click();
    const dlg = sheet();
    await soon(() => !!dlg.querySelector("fieldset.admit-choice"));
    // Several organisations: a choice, nothing preselected, and "Not now" is one of the answers.
    const radios = [...dlg.querySelectorAll<HTMLInputElement>('fieldset.admit-choice input[type="radio"]')];
    expect(radios.map((r) => r.closest("label")!.textContent!.trim())).toEqual(["Personal personal", "Client A client-a", "Club club", "Not now"]);
    expect(radios.some((r) => r.checked)).toBe(false);
    const before = me.gets.length;
    button(dlg, /^Continue$/)!.click();
    expect(dlg.querySelector('[role="alert"]')!.textContent).toContain("Choose an organisation");
    expect(me.gets.length).toBe(before);
    radios[1]!.checked = true;
    radios[1]!.dispatchEvent(new win.Event("change", { bubbles: true }) as unknown as Event);
    button(dlg, /^Continue$/)!.click();

    // First confirmation: the enrolment, unchanged, saying what follows.
    await soon(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toContain("kiosk-3");
    expect(dlg.querySelector(".chain-note")!.textContent).toBe("Step 1 of 2: let it join. Step 2 follows as its own confirmation: admit kiosk-3 to Client A.");
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();

    // Second confirmation: the ordinary org_host admit, with exactly what is admitted to what.
    await soon(() => dlg.querySelector(".headline")?.textContent === "Client A: admit org host." && !!dlg.querySelector("button.confirm"));
    expect(m.store.pending.some((p) => p.id === "01JDEMO0ENROLL0KIOSK00003")).toBe(false);
    expect(catHost("client-a", "kiosk-3")!.active).toBe(false);
    expect(dlg.querySelector(".chain-note")!.textContent).toContain("kiosk-3 has joined. Step 2 of 2: admit it to Client A");
    const summary = dlg.querySelector(".admission-summary")!.textContent!;
    for (const part of ["kiosk-3", "agent", "01JDEMO0ENROLL0KIOSK00003", "Client A", "client-a", "PaaS (2)"]) expect(summary).toContain(part);

    // The admission fails (the organisation changed under it): the sheet says the host joined,
    // that the admission did not happen, and offers it again.
    const apply = api.apply;
    api.apply = async () => {
      api.apply = apply;
      throw new ApiError(409, "conflict", "catalogue or admission changed; reload and review again");
    };
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await soon(() => dlg.querySelector("#sheet-title")?.textContent === "Joined, but not admitted");
    expect(dlg.querySelector(".chain-note")!.textContent).toContain("kiosk-3 has joined: that approval went through. Admitting it to Client A did not");
    expect(dlg.querySelector('[role="alert"]')!.textContent).not.toBe("");
    expect(dlg.textContent).toContain("The admission was not made");
    expect(catHost("client-a", "kiosk-3")!.active).toBe(false);
    button(dlg, /^Try the admission again$/)!.click();
    await soon(() => dlg.querySelector(".headline")?.textContent === "Client A: admit org host." && !!dlg.querySelector("button.confirm"));
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await soon(() => dlg.querySelector("#sheet-title")?.textContent === "Admitted");
    expect(catHost("client-a", "kiosk-3")!.active).toBe(true);
    expect(catHost("personal", "kiosk-3")!.active).toBe(false);
    expect(dlg.textContent).toContain("kiosk-3 has joined and is admitted to Client A");
    // The enrolment was signed as the existing action, once; the admission is the catalogue's own.
    expect(m.store.applied.filter((a) => a.canonical["id"] === "01JDEMO0ENROLL0KIOSK00003").map((a) => a.object + ":" + a.action)).toEqual(["enrollment:approve"]);
    button(dlg, /^Done$/)!.click();
  });

  test("one organisation: admitting is preselected and can be switched off; an unadmitted host is marked on Hosts", async () => {
    m.store.pending.unshift({
      id: "01JDEMO0ENROLL0KIOSK00004",
      kind: "enrollment",
      created_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 25 * 60_000).toISOString(),
      requesting_host: "kiosk-4",
      requesting_address: "192.0.2.41",
      requester: { tool: "owner-cli", user: "pi" },
      reason: "Second lobby kiosk.",
      enrollment: { replaces_id: "", max_ssh_seconds: 28800, max_standing_hours: 24, class: "agent", csr_fingerprint: "SHA256:" + "k".repeat(43), ssh_host_key_fingerprints: [] },
      ttl_requested: 0,
      ttl_max: 0,
      risk: "normal",
    } as unknown as (typeof m.store.pending)[number]);
    const card = await joinCard("kiosk-4");
    // As if the catalogue held one organisation only.
    const real = api.catalogue!;
    api.catalogue = async () => {
      const cat = (await real())!;
      return { ...cat, organisations: cat.organisations.filter((o) => o.slug === "personal") };
    };
    try {
      button(card, /^Let it join…$/)!.click();
      const dlg = sheet();
      await soon(() => !!dlg.querySelector("fieldset.admit-choice"));
      const box = dlg.querySelector<HTMLInputElement>('fieldset.admit-choice input[type="checkbox"]')!;
      expect(box.checked).toBe(true);
      expect(box.closest("label")!.textContent!.trim()).toBe("Also admit kiosk-4 to Personal");
      expect(dlg.querySelectorAll('fieldset.admit-choice input[type="radio"]').length).toBe(0);
      // Off is possible: then it is one confirmation, and the result says what is missing.
      box.checked = false;
      button(dlg, /^Continue$/)!.click();
      await soon(() => !!dlg.querySelector("button.confirm"));
      expect(dlg.querySelector(".chain-note")).toBeNull();
      dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
      await soon(() => dlg.querySelector("#sheet-title")?.textContent === "Approved");
      expect(dlg.querySelector(".not-admitted-note")!.textContent).toContain("kiosk-4 has joined but is not admitted to an organisation, so it can ask for nothing yet");
      const open = [...dlg.querySelectorAll<HTMLAnchorElement>("a")].find((a) => a.textContent === "Open Hosts")!;
      expect(open.getAttribute("href")).toBe("#/hosts");
      button(dlg, /^Done$/)!.click();
    } finally {
      api.catalogue = real;
    }
    go("#/hosts");
    const cards = () => [...root.querySelectorAll<HTMLElement>("#sec-hosts article.card")];
    await soon(() => cards().some((c) => c.querySelector("h3 bdi")?.textContent === "kiosk-4"));
    const k4 = cards().find((c) => c.querySelector("h3 bdi")!.textContent === "kiosk-4")!;
    expect(k4.classList.contains("unadmitted")).toBe(true);
    expect(k4.querySelector("h3 .badge.not-admitted")!.textContent).toBe("Not admitted");
    expect(k4.querySelector(".not-admitted-note")!.textContent).toContain("enrolled but not admitted to any organisation");
    expect([...k4.querySelectorAll(".admission-list button")].map((b) => b.textContent)).toEqual(["Admit…", "Admit…", "Admit…"]);
    // A host admitted somewhere carries no such mark.
    const k3 = cards().find((c) => c.querySelector("h3 bdi")!.textContent === "kiosk-3")!;
    expect(k3.querySelector(".badge.not-admitted")).toBeNull();
    expect(k3.classList.contains("unadmitted")).toBe(false);
    // Admitting from there is the same signed change, and the mark goes.
    button(k4.querySelector(".admission-list li")!, /^Admit…$/)!.click();
    const dlg = sheet();
    await soon(() => dlg.querySelector(".headline")?.textContent === "Personal: admit org host." && !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".chain-note")).toBeNull();
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await soon(() => catHost("personal", "kiosk-4")!.active);
    button(dlg, /^Done$|^Close$/)?.click();
    await soon(() => !cards().find((c) => c.querySelector("h3 bdi")?.textContent === "kiosk-4")?.querySelector(".badge.not-admitted"));
  });

  test("Hosts: an expired certificate is said to be that, not “Not admitted”", async () => {
    // As aqmasd: the host list still has the host, the catalogue no longer lists it.
    const hosts = api.hosts, catalogue = api.catalogue!;
    api.hosts = async () => (await hosts()).map((x) => (x.name === "web-1" ? { ...x, not_after: new Date(Date.now() - 86_400_000).toISOString() } : x));
    api.catalogue = async () => {
      const cat = (await catalogue())!;
      return { ...cat, organisations: cat.organisations.map((o) => ({ ...o, hosts: o.hosts.filter((x) => x.name !== "web-1") })) };
    };
    try {
      go("#/");
      await soon(() => current()[0] === "Approvals");
      go("#/hosts");
      const web = () => [...root.querySelectorAll<HTMLElement>("#sec-hosts article.card")].find((c) => c.querySelector("h3 bdi")?.textContent === "web-1");
      await soon(() => !!web()?.querySelector(".badge.cert-expired"));
      const card = web()!;
      expect(card.querySelector(".badge.cert-expired")!.textContent).toBe("Certificate expired");
      expect(card.querySelector(".badge.not-admitted")).toBeNull();
      expect(card.classList.contains("unadmitted")).toBe(false);
      expect(card.textContent).toContain("client certificate has expired");
      expect(card.textContent).not.toContain("Create an organisation first");
      expect(card.querySelectorAll(".admission-list button").length).toBe(0);
    } finally {
      api.hosts = hosts;
      api.catalogue = catalogue;
    }
    go("#/");
    await soon(() => current()[0] === "Approvals");
    go("#/hosts");
    await soon(() => [...root.querySelectorAll<HTMLElement>("#sec-hosts article.card")].some((c) => c.querySelector("h3 bdi")?.textContent === "web-1" && !c.querySelector(".badge.cert-expired")));
  });

  test("the tray: what is open and Close all, reviewed before its tap", async () => {
    const trayButton = root.querySelector<HTMLButtonElement>(".tray-button")!;
    expect(trayButton.getAttribute("aria-expanded")).toBe("false");
    trayButton.click();
    const panel = root.querySelector<HTMLElement>(".tray-panel")!;
    expect(panel.hidden).toBe(false);
    expect(panel.textContent).toContain("waiting for you");
    const gets = me.gets.length;
    button(panel, /^Close all…$/)!.click();
    await until(() => !!panel.querySelector("button.confirm"));
    expect(me.gets.length).toBe(gets); // nothing signed before the confirmation
    expect(panel.textContent).toContain("Close all wipes every open bucket key");
    button(panel, /^Cancel$/)!.click();
    trayButton.click();
    expect(panel.hidden).toBe(true);
  });

  test("search: opens from the header, finds an item by a key name, goes there", async () => {
    root.querySelector<HTMLButtonElement>(".search-open")!.click();
    const dlg = doc.querySelector<HTMLDialogElement>("dialog.search-dialog")!;
    expect(dlg.open).toBe(true);
    const input = dlg.querySelector<HTMLInputElement>(".search-input")!;
    expect([...dlg.querySelectorAll(".search-group")].map((x) => x.textContent)).toEqual(expect.arrayContaining(["Waiting", "Do", "Go to"]));
    input.value = "smtp_password";
    input.dispatchEvent(new win.Event("input") as unknown as Event);
    const hits = [...dlg.querySelectorAll<HTMLElement>("[role=option]")];
    expect(hits.length).toBe(1);
    expect(hits[0]!.textContent).toContain("Staging env");
    expect(hits[0]!.getAttribute("aria-selected")).toBe("true");
    expect(dlg.textContent).not.toContain("mock smtp pass");
    input.dispatchEvent(new win.KeyboardEvent("keydown", { key: "Enter" }) as unknown as Event);
    expect(dlg.open).toBe(false);
    expect(win.location.hash).toBe("#/vault/" + m.store.vault.sets.find((s) => s.set_slug === "staging")!.set_id);
  });

  test("Security: the banner says how many passkeys open the credentials and enables the rest in one sequence", async () => {
    go("#/security");
    await until(() => !!root.querySelector("#sec-readiness .readiness"));
    const panel = () => root.querySelector<HTMLElement>("#sec-readiness .readiness")!;
    expect(panel().querySelector(".readiness-head")!.textContent).toBe("3 of 4 passkeys can open your credentials.");
    expect(panel().classList.contains("attention")).toBe(true);
    expect(panel().querySelector(".readiness-list li.todo")!.textContent).toContain("YubiKey on keyring");
    taps.length = 0;
    button(panel(), /^Enable YubiKey on keyring…$/)!.click();
    await until(() => !!panel().querySelector(".wizard button.confirm"));
    expect(panel().querySelector(".wizard-progress")!.textContent).toContain("Passkey 1 of 1: YubiKey on keyring");
    expect(taps).toEqual([]); // the first step is shown before anything is signed
    // Every step shows what it signs and waits for its own tap, as Passkeys → Enable does.
    const seen: string[] = [];
    for (let i = 0; i < 12 && !root.querySelector("#sec-readiness .readiness.ok"); i++) {
      await until(() => !!root.querySelector("#sec-readiness .wizard button.confirm:not([disabled])") || !!root.querySelector("#sec-readiness .readiness.ok"));
      const go2 = root.querySelector<HTMLButtonElement>("#sec-readiness .wizard button.confirm:not([disabled])");
      if (!go2) break;
      expect(root.querySelector("#sec-readiness .wizard details.signed pre")!.textContent!.length).toBeGreaterThan(10);
      seen.push(root.querySelector("#sec-readiness .wizard h3")!.textContent!);
      const before = taps.length;
      go2.click();
      await until(() => taps.length > before);
      await until(() => root.querySelector("#sec-readiness .wizard h3")?.textContent !== seen.at(-1) || !!root.querySelector("#sec-readiness .readiness.ok"));
    }
    await until(() => !!root.querySelector("#sec-readiness .readiness.ok"));
    expect(panel().querySelector(".readiness-head")!.textContent).toBe("All 4 passkeys can open your credentials.");
    // Enable (the signed-in passkey approves, the key enrols) for each round, then the key's tests.
    expect(seen.some((s) => s.startsWith("Enable YubiKey on keyring for"))).toBe(true);
    expect(seen.some((s) => s.startsWith("Test YubiKey on keyring for"))).toBe(true);
    expect(taps.slice(0, 2)).toEqual(["me", "key"]);
    expect(taps.length).toBe(seen.length);
    const k = (await api.sealStatus!()).passkeys!.find((p) => p.id === seededKey.info.id)!;
    expect(k.missing).toEqual([]);
    expect(k.scopes.every((s) => s.tested)).toBe(true);
    await until(() => root.querySelector('.tab[data-tab="security"] .tab-count')!.textContent === "");
  });

  // Last: it ends the session the other tests use.
  test("Sign out ends the session on the server and shows the sign-in page", async () => {
    go("#/");
    await until(() => !!root.querySelector("header button.signout"));
    const b = root.querySelector<HTMLButtonElement>("header button.signout")!;
    expect(b.getAttribute("aria-label")).toBe("Sign out");
    b.click();
    await until(() => !!root.querySelector("button.primary") && !root.querySelector("header.topbar"));
    expect(f.log.some((x) => x.url.endsWith("/api/ui/logout") && x.method === "POST")).toBe(true);
    expect(root.querySelector(".signin-note")!.textContent).toContain("Signed out.");
    expect(m.store.sessions.size).toBe(0);
    // The old cookie no longer works.
    await expect(api.state()).rejects.toMatchObject({ code: "unauthenticated" });
  });
});
