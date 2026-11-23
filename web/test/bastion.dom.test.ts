// Access to the bastion itself, in happy-dom against the mock: the red root card and its
// confirmation come from the signed text, the close choice is signed, bastion cards are never
// batch-selectable, a queued task is approved through the setup flow, the banner, and
// Admin → Bastion access.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { ROOT_CLOSE_LABEL, ROOT_CONSEQUENCES, ROOT_TITLE } from "../src/canonical";
import { startMock } from "../mock/server";
import { fakeAuth, jarFetch } from "./helpers";

const win = new Window({ url: "http://localhost/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "CSS", "HTMLElement", "HTMLDialogElement", "Node"];

async function until(cond: () => boolean, ms = 5000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("bastion access in a DOM", () => {
  const m = startMock({ port: 0, distDir: null, seed: false, setupStepMs: 20 });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  let root: HTMLElement;
  let doc: Document;
  const rootItem = m.store.bastion.spawn("root");
  const inspectItem = m.store.bastion.spawn("inspect");
  const queued = m.store.bastion.spawnQueued();
  const dismissable = m.store.bastion.spawnQueued("journal-vacuum", '{"keep_days":14}');
  const bodies = (suffix: string) => f.log.filter((x) => x.url.endsWith(suffix)).map((x) => x.body as Record<string, unknown>);
  const button = (el: ParentNode, label: string) => [...el.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === label)!;
  const card = (id: string) => root.querySelector<HTMLElement>(`[data-id="${id}"]`)!;
  /** Ask the app to poll now (it does when the tab becomes visible). */
  const poke = () => void doc.dispatchEvent(new win.Event("visibilitychange") as unknown as Event);

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    if (!(G["CSS"] as { escape?: unknown } | undefined)?.escape) G["CSS"] = { escape: (s: string) => s.replace(/[^A-Za-z0-9_-]/g, (c) => "\\" + c) };
    doc = win.document as unknown as Document;
    win.happyDOM.setURL(m.url + "/"); // the setup flow checks the request's rpId against the page's host
    doc.body.innerHTML = '<div id="app"></div>'; // test fixture only
    root = doc.getElementById("app")!;
    const { App } = await import("../src/app");
    new App(root, api, auth).start();
    await until(() => !!root.querySelector("button.primary") && f.log.some((x) => x.url.endsWith("/api/ui/login/begin")));
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

  test("the root card is red, says what it means in words and lists the open buckets", () => {
    const c = card(rootItem.id);
    expect(c.classList.contains("bastion-root")).toBe(true);
    expect(c.querySelector(".root-band")!.textContent).toBe(ROOT_TITLE);
    expect(c.querySelector(".root-band svg")).toBeTruthy(); // icon and words, never colour alone
    expect(c.textContent).toContain(ROOT_CONSEQUENCES);
    expect([...c.querySelectorAll(".root-open-list li")].map((li) => li.textContent)).toEqual(["SSH user CA", "personal/paas/staging-env"]);
    expect(c.textContent).toContain("You will be alerted when it is issued.");
    expect(c.querySelector("button.approve")!.textContent).toBe("Approve root session…");
    expect(c.querySelector("button.approve")!.classList.contains("root")).toBe(true);
    expect(c.querySelector(".agent")!.textContent).toContain("replace the tunnel credentials file");
    expect(c.querySelectorAll('input[type="checkbox"]').length).toBe(0); // not selectable for anything
  });

  test("the inspect card is an ordinary card that says what the account can do", () => {
    const c = card(inspectItem.id);
    expect(c.classList.contains("bastion-inspect")).toBe(true);
    expect(c.querySelector(".root-band")).toBeNull();
    expect(c.textContent).toContain("fixed set of log and status commands");
    expect(c.querySelector(".target")!.textContent).toBe("aqmas-inspect@bastion");
    expect(c.querySelector("button.approve")!.textContent).toBe("Approve…");
  });

  test("bastion and queued-task cards are never offered to the batch panel", async () => {
    const { multiPanel } = await import("../src/approvals");
    const facts = { offers_standing: 0 } as unknown as Record<string, string | number>;
    const panel = multiPanel(api, auth, {} as never, { id: () => "" } as never, [{ ...rootItem, scoped_facts: facts }, { ...inspectItem, scoped_facts: facts }, { ...queued, scoped_facts: facts }], () => {});
    expect(panel.querySelectorAll("input").length).toBe(0);
  });

  test("root approval: default close, confirmation drawn from the signed text, toggling re-prepares", async () => {
    card(rootItem.id).querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector("#root-close"));
    expect(dlg.querySelector<HTMLInputElement>("#root-close")!.checked).toBe(true);
    expect(dlg.textContent).toContain(ROOT_CLOSE_LABEL);
    expect(dlg.querySelectorAll('input[name="standing"]').length).toBe(0);
    expect([...dlg.querySelectorAll<HTMLInputElement>('input[name="ttl"]')].every((i) => Number(i.value) <= 1800)).toBe(true);
    // A bucket opens between the card and the tap: the confirmation shows the signed list.
    m.store.bastion.open = ["SSH user CA", "personal/paas/production-env", "personal/paas/staging-env"];
    button(dlg, "Continue").click();
    await until(() => !!dlg.querySelector("button.confirm"));
    const path = `/requests/${rootItem.id}/challenge`;
    expect(bodies(path).at(-1)).toEqual({ action: "approve", ttl_seconds: 1800, close_buckets: true });
    const block = dlg.querySelector(".root-block")!;
    expect(block.querySelector(".root-band")!.textContent).toBe(ROOT_TITLE);
    expect([...block.querySelectorAll(".root-open-list li")].map((li) => li.textContent)).toEqual(["SSH user CA", "personal/paas/production-env", "personal/paas/staging-env"]);
    expect(dlg.querySelector<HTMLInputElement>("#root-close-signed")!.checked).toBe(true);
    expect(dlg.querySelector("#sheet-title")!.textContent).toBe("Root on the bastion: check, then confirm");
    expect(dlg.querySelector("button.confirm")!.textContent).toBe("Approve root session with passkey");
    expect(dlg.querySelector("button.confirm")!.classList.contains("root")).toBe(true);
    expect(dlg.querySelector(".signed")!.textContent).toContain("Close them first");

    // Unticking is a different signed text: a fresh challenge, and the block says so.
    const n = bodies(path).length;
    const box = dlg.querySelector<HTMLInputElement>("#root-close-signed")!;
    box.checked = false;
    box.dispatchEvent(new win.Event("change") as unknown as Event);
    await until(() => bodies(path).length === n + 1 && !!dlg.querySelector("button.confirm"));
    expect(bodies(path).at(-1)).toEqual({ action: "approve", ttl_seconds: 1800, close_buckets: false });
    expect(dlg.querySelector<HTMLInputElement>("#root-close-signed")!.checked).toBe(false);
    expect(dlg.querySelector(".root-block")!.textContent).toContain("STAY OPEN");

    const gets = auth.gets.length;
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    expect(auth.gets.length).toBe(gets + 1); // the prompt starts inside the tap
    await until(() => !!dlg.querySelector("h2.ok"));
    expect(m.store.applied.at(-1)!.canonical).toMatchObject({ kind: "bastion", level: "root", close_buckets: false, ttl_seconds: 1800 });
    expect(dlg.textContent).toContain("left open");
    expect(dlg.textContent).toContain("Alert sent.");
    expect(dlg.textContent).toContain("cannot be recalled");
    dlg.close();
  });

  test("while the root certificate is valid a red banner shows on every page", async () => {
    await until(() => !!root.querySelector("#root-banner"));
    const b = root.querySelector("#root-banner")!;
    expect(b.textContent).toMatch(/^A root certificate for the bastion is valid until \d\d:\d\d( [AP]M)?\. Whatever you open now is readable by that session; a session can outlast its certificate\.$/);
    expect(b.getAttribute("role")).toBe("alert");
    expect(b.querySelector("svg")).toBeTruthy();
  });

  test("an alert that was not delivered is said loudly on the result", async () => {
    m.store.bastion.alertOutcome = "failed";
    m.store.bastion.open = ["SSH user CA"];
    const item = m.store.bastion.spawn("root");
    poke();
    await until(() => !!card(item.id));
    card(item.id).querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector("#root-close"));
    button(dlg, "Continue").click();
    await until(() => !!dlg.querySelector("button.confirm"));
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => !!dlg.querySelector("h2.ok"));
    expect(dlg.textContent).toContain("1 bucket closed");
    expect(dlg.querySelector(".breakglass")!.textContent).toContain("ALERT NOT DELIVERED");
    dlg.close();
    m.store.bastion.alertOutcome = "sent";
  });

  test("inspect approval: no close choice anywhere, nothing about buckets on the wire", async () => {
    card(inspectItem.id).querySelector<HTMLButtonElement>("button.approve")!.click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector('input[name="ttl"]'));
    expect(dlg.querySelector("#root-close")).toBeNull();
    expect(dlg.querySelector(".root-band")).toBeNull();
    button(dlg, "Continue").click();
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".root-block")).toBeNull();
    expect(dlg.querySelector(".headline")!.textContent).toContain("read-only inspect access");
    expect(bodies(`/requests/${inspectItem.id}/challenge`).at(-1)).toEqual({ action: "approve", ttl_seconds: 3600 });
    dlg.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => !!dlg.querySelector("h2.ok"));
    expect(m.store.applied.at(-1)!.canonical).toMatchObject({ level: "inspect", open_buckets: "[]", close_buckets: false });
    dlg.close();
  });

  test("a queued task: its card, approval through the setup flow naming the request, and dismiss", async () => {
    const c = card(queued.id);
    expect(c.classList.contains("queued-task")).toBe(true);
    expect(c.querySelector(".target")!.textContent).toBe("Update system packages");
    expect(c.querySelector(".queued-params")!.textContent).toContain("kernel and boot chain are left alone");
    expect(c.querySelector(".agent")!.textContent).toContain("monthly updates");
    button(c, "Approve…").click();
    await until(() => !!c.querySelector("button.confirm"));
    expect(c.querySelector(".signed")!.textContent).toContain('"params":"{\\"kernel\\":false}"');
    const gets = auth.gets.length;
    c.querySelector<HTMLButtonElement>("button.confirm")!.click();
    expect(auth.gets.length).toBe(gets + 1);
    await until(() => m.store.bastion.answered.length === 1);
    expect(bodies("/setup/os-update/run").at(-1)!["request"]).toBe(queued.id);
    expect(m.store.bastion.answered[0]).toEqual({ request: queued.id, task: "os-update", params: '{"kernel":false}' });

    poke();
    await until(() => !card(queued.id) && !!card(dismissable.id));
    const d = card(dismissable.id);
    expect(d.querySelector(".setup-warning")).toBeNull();
    button(d, "Dismiss").click();
    await until(() => m.store.bastion.dismissed.includes(dismissable.id));
  });

  test("a queued task the runner cannot take now says why and cannot be approved", async () => {
    const item = m.store.bastion.spawnQueued("reboot", "{}", { setup: { ...m.store.bastion.spawnQueued("reboot", "{}").setup!, blocked: "Another task is in progress." } });
    poke();
    await until(() => !!card(item.id));
    const c = card(item.id);
    expect(c.textContent).toContain("Another task is in progress.");
    expect(button(c, "Approve…").disabled).toBe(true);
    expect(c.querySelector(".setup-warning")!.textContent).toContain("nothing open");
  });

  test("Admin → Bastion access: status, sessions, and the allowlist signs the complete sorted list", async () => {
    await until(() => m.store.setup.current === null, 8000);
    win.location.hash = "#/admin";
    win.dispatchEvent(new win.Event("hashchange"));
    await until(() => !!root.querySelector('#sec-bastion [data-task="bastion-allow"] .bastion-hosts'), 8000);
    const sec = root.querySelector<HTMLElement>("#sec-bastion")!;
    expect(sec.querySelector(".bastion-status")!.textContent).toContain("Installed");
    expect(sec.textContent).toContain("emergency key is never touched");
    const rows = [...sec.querySelectorAll<HTMLElement>(".bastion-session")];
    expect(rows.length).toBe(3);
    expect(rows.some((r) => r.classList.contains("root") && r.textContent!.includes("NOT DELIVERED"))).toBe(true);
    expect(rows.some((r) => r.textContent!.includes("left open"))).toBe(true);
    // The grouped tasks live here, not in the Setup summary line.
    expect([...sec.querySelectorAll<HTMLElement>("[data-task]")].map((x) => x.dataset["task"])).toEqual(["bastion-access", "bastion-access-remove", "bastion-allow", "os-update", "reboot", "restart-cloudflared", "restart-broker", "disk-usage", "journal-vacuum"]);
    expect(root.querySelector("#sec-setup")!.textContent).not.toContain("bastion");
    expect(sec.querySelector<HTMLInputElement>('[data-task="os-update"] input[type="checkbox"]')!.checked).toBe(false);
    expect(sec.querySelector<HTMLInputElement>('[data-task="journal-vacuum"] input.text')!.value).toBe("14");

    const allow = sec.querySelector<HTMLElement>('[data-task="bastion-allow"]')!;
    const boxes = [...allow.querySelectorAll<HTMLInputElement>(".bastion-hosts input")];
    expect(boxes.map((b) => b.checked)).toEqual([true, false, false]);
    boxes[2]!.checked = true; // laptop
    button(allow, "Apply…").click();
    await until(() => !!allow.querySelector("button.confirm"));
    expect(allow.querySelector(".root-band")!.textContent).toContain("WHO MAY ASK FOR ROOT");
    expect(allow.textContent).toContain("Adding: laptop");
    allow.querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => m.store.setup.received.some((r) => r.task === "bastion-allow"));
    expect(m.store.setup.received.find((r) => r.task === "bastion-allow")!.params).toBe(
      '{"hosts":[{"id":"01HZX0DEV1ENROLLMENT000001","name":"dev-1","address":"192.0.2.21"},{"id":"01HZX0LAPTOPENROLLMENT0003","name":"laptop","address":"192.0.2.30"}]}',
    );
  });

  test("revoking an active session goes through the ordinary grant revoke", async () => {
    const sec = root.querySelector<HTMLElement>("#sec-bastion")!;
    const row = [...sec.querySelectorAll<HTMLElement>(".bastion-session.active")][0]!;
    button(row, "Revoke…").click();
    const dlg = doc.querySelector("dialog")!;
    await until(() => !!dlg.querySelector("button.confirm"));
    expect(dlg.querySelector(".headline")!.textContent).toContain("Bastion access");
    expect(dlg.textContent).toContain("cannot be recalled");
    dlg.close();
  });
});
