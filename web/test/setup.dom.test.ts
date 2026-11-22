// Admin → Setup in happy-dom: the queue's cards against a scripted server, then the whole
// thing (cutover, seal with the recovery key, self-update, upgrade) through the App and the mock.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { ApiError, createApi, type Api } from "../src/api";
import type { SetupTask, SetupView } from "../src/setup";
import { startMock } from "../mock/server";
import { fakeAuth, jarFetch } from "./helpers";

const win = new Window({ url: "http://localhost/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "CSS", "HTMLElement", "HTMLDialogElement", "Node"];
const doc = win.document as unknown as Document;

async function until(cond: () => boolean, ms = 4000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

beforeAll(() => {
  for (const k of GLOBALS) {
    saved[k] = G[k];
    G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
  }
  if (!(G["CSS"] as { escape?: unknown } | undefined)?.escape) G["CSS"] = { escape: (s: string) => s.replace(/[^A-Za-z0-9_-]/g, (c) => "\\" + c) };
});
afterAll(async () => {
  await win.happyDOM.abort();
  win.close();
  for (const k of GLOBALS) G[k] = saved[k];
});

const task = (id: string, state: string, over: Partial<SetupTask> = {}): SetupTask => ({ id, title: `Task ${id}`, summary: `Summary of ${id}.`, steps: ["First step", "Second step"], reversible: "Yes, until you activate.", state, ...over });
const KEYS = [
  { id: "aa", credential: "cred-phone-xxxxxxxxxxxx", key_sha256: "a".repeat(64), name: "Phone", pinned: true, current: true },
  { id: "bb", credential: "cred-key-xxxxxxxxxxxxxx", key_sha256: "b".repeat(64), name: "Desk <b>key</b>", pinned: true, current: false },
];
function baseView(over: Partial<SetupView> = {}): SetupView {
  return {
    mode: "serve",
    runner_installed: true,
    runner_version: "1.4.0",
    secrets_key: "",
    deploy_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeployKeyForTheTest aqmas-update@bastion",
    passkeys: KEYS,
    tasks: [
      task("cutover", "done", { last: { state: "done", step: "Finished", started_at: "2026-11-22T10:00:00Z", finished_at: "2026-11-22T10:01:00Z", message: "Switched to organisations.", log: ["Stop the broker", "Back up", "<img src=x onerror=alert(1)>"], result: { backup: "/var/lib/aqmas-backups/cutover-1", manifest_sha256: "c".repeat(64) } } }),
      task("seal", "available", { secrets: ["ntfy_topic_url", "ntfy_token"] }),
      task("enable-updates", "failed", { rerunnable: true, last: { state: "failed", step: "Check the installed broker", started_at: "2026-11-22T10:00:00Z", finished_at: "2026-11-22T10:01:00Z", message: "the release check failed", log: [] } }),
      task("sync-passkeys", "done", { rerunnable: true }),
      task("upgrade", "blocked", { blocked_by: "Enable self-update first." }),
    ],
    update_sources: {},
    ...over,
  };
}

describe("the Setup queue against a scripted server", () => {
  let script: () => SetupView = () => baseView();
  let calls = 0;
  let signedOut = 0;
  const api = {
    setupGet: async (path: string) => {
      if (path !== "") throw new ApiError(409, "conflict", "no cutover to preview");
      calls++;
      return script();
    },
    setupPost: async () => {
      throw new ApiError(409, "conflict", "not in this test");
    },
    updates: async () => ({ current: "1.4.0", commit: "a".repeat(40), status: "", error: "", candidate: {}, stat: "", diff: "" }),
  } as unknown as Api;
  let root: HTMLElement;
  let page: import("../src/setupPage").SetupPage;
  const card = (id: string) => root.querySelector<HTMLElement>(`[data-task="${id}"]`)!;
  const badge = (id: string) => card(id).querySelector(".setup-state")!.textContent;

  beforeAll(async () => {
    doc.body.innerHTML = '<div id="queue"></div>'; // test fixture only
    root = doc.getElementById("queue")!;
    const { SetupPage } = await import("../src/setupPage");
    page = new SetupPage(root, api, fakeAuth(), { openMigration: () => {}, openUpdate: () => {}, signedOut: () => void signedOut++, pollMs: 15, idleMs: 15 });
    page.start();
    await until(() => !!root.querySelector("[data-task]"));
  });
  afterAll(() => page.stop());

  test("cards in server order, each with title, summary, steps, the reversible note and a state badge", () => {
    expect([...root.querySelectorAll<HTMLElement>("[data-task]")].map((c) => c.dataset["task"])).toEqual(["cutover", "seal", "enable-updates", "sync-passkeys", "upgrade"]);
    const c = card("seal");
    expect(c.querySelector("h3")!.textContent).toBe("Task seal");
    expect(c.textContent).toContain("Summary of seal.");
    expect([...c.querySelectorAll(".setup-steps li")].map((l) => l.textContent)).toEqual(["First step", "Second step"]);
    expect(c.textContent).toContain("Yes, until you activate.");
    expect(Object.fromEntries(["cutover", "seal", "enable-updates", "sync-passkeys", "upgrade"].map((id) => [id, [card(id).dataset["state"], badge(id)]]))).toEqual({
      cutover: ["done", "Done"],
      seal: ["available", "Ready"],
      "enable-updates": ["failed", "Failed"],
      "sync-passkeys": ["done", "Done"],
      upgrade: ["blocked", "Blocked"],
    });
  });

  test("blocked says why; Run is offered when available or failed, Run again when done and rerunnable", () => {
    expect(card("upgrade").querySelector(".setup-blocked")!.textContent).toBe("Blocked: Enable self-update first.");
    expect(card("upgrade").querySelector(".setup-go")).toBeNull();
    expect(card("seal").querySelector(".setup-go")!.textContent).toBe("Run…");
    expect(card("enable-updates").querySelector(".setup-go")!.textContent).toBe("Run again…");
    expect(card("sync-passkeys").querySelector(".setup-go")!.textContent).toBe("Run again…");
    expect(card("cutover").querySelector(".setup-go")).toBeNull(); // done, not rerunnable
  });

  test("the last run: message, results and log, with server text kept as text", () => {
    const c = card("cutover");
    expect(c.querySelector(".setup-message")!.textContent).toContain("Switched to organisations.");
    expect(c.textContent).toContain("/var/lib/aqmas-backups/cutover-1");
    expect(c.textContent).toContain("manifest sha256");
    const log = c.querySelector(".setup-log")!;
    expect(log.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(root.querySelectorAll("img, script, b").length).toBe(0);
    expect(log.closest("details")!.hasAttribute("open")).toBe(false);
    expect(card("enable-updates").querySelector(".setup-last .error")!.textContent).toContain("Last run failed: the release check failed");
    expect(card("sync-passkeys").textContent).toContain("Desk <b>key</b>");
  });

  test("the deploy key is shown for copying with the read-only instruction", () => {
    const c = card("enable-updates");
    expect(c.querySelector("[data-deploy-key]")!.textContent).toBe(baseView().deploy_key!);
    expect(c.textContent).toContain("read-only deploy key");
    expect([...c.querySelectorAll("input")].some((i) => (i as HTMLInputElement).placeholder === "ssh://git@forge.example.com/owner/agent-quartermaster.git")).toBe(true);
    expect(c.querySelectorAll('input[type="password"]').length).toBe(2);
  });

  test("no notices when the runner is installed and this passkey is pinned", () => {
    expect(root.querySelectorAll("[data-notice]").length).toBe(0);
  });

  test("runner not installed: says so, with the one command to run on the bastion", async () => {
    script = () => baseView({ runner_installed: false, tasks: baseView().tasks!.map((t) => (t.state === "done" && !t.rerunnable ? t : { ...t, state: "blocked", blocked_by: "The maintenance runner is not installed on this machine yet." })) });
    await until(() => !!root.querySelector('[data-notice="runner"]'));
    const n = root.querySelector('[data-notice="runner"]')!;
    expect(n.textContent).toContain("not installed");
    expect(n.querySelector("pre")!.textContent).toBe("sudo aqmasd maint-init");
    expect(root.querySelector(".setup-go")).toBeNull();
    expect(card("seal").querySelector(".setup-blocked")!.textContent).toContain("not installed");
    script = () => baseView();
    await until(() => !root.querySelector('[data-notice="runner"]'));
  });

  test("signed in with a passkey that is not pinned: said up front, pointing at Sync maintenance passkeys", async () => {
    script = () => baseView({ passkeys: [{ ...KEYS[0]!, pinned: false }, KEYS[1]!] });
    await until(() => !!root.querySelector('[data-notice="unpinned"]'));
    const n = root.querySelector('[data-notice="unpinned"]')!;
    expect(n.textContent).toContain("Phone");
    expect(n.textContent).toContain("is not pinned for maintenance");
    expect(n.textContent).toContain("would be refused");
    expect(n.textContent).toContain("Desk <b>key</b>");
    expect(n.textContent).toContain("Sync maintenance passkeys");
    const rows = [...card("sync-passkeys").querySelectorAll(".setup-passkeys li")].map((l) => l.textContent);
    expect(rows[0]).toContain("Not pinned");
    expect(rows[0]).toContain("This session");
    expect(rows[1]).toContain("Pinned");
    script = () => baseView();
    await until(() => !root.querySelector('[data-notice="unpinned"]'));
  });

  test("a refused request is shown with the runner's reason", async () => {
    script = () => baseView({ refused: { at: new Date().toISOString(), reason: "the approval is older than two minutes" } });
    await until(() => !!root.querySelector('[data-notice="refused"]'));
    expect(root.querySelector('[data-notice="refused"]')!.textContent).toContain("refused the last request");
    expect(root.querySelector('[data-notice="refused"]')!.textContent).toContain("the approval is older than two minutes");
    script = () => baseView();
    await until(() => !root.querySelector('[data-notice="refused"]'));
  });

  test("running and waiting show live progress; polling goes on across a broker restart", async () => {
    const running = (step: string): SetupView => {
      const cur = { task: "seal", state: "running", step, started_at: new Date().toISOString(), log: ["Stop the broker and back up", step] };
      return baseView({ current: cur, tasks: baseView().tasks!.map((t) => (t.id === "seal" ? { ...t, state: "running", last: cur } : t.state === "done" ? t : { ...t, state: "blocked", blocked_by: "Another task is in progress." })) });
    };
    script = () => running("Stop the broker and back up");
    await until(() => card("seal").dataset["state"] === "running");
    expect(badge("seal")).toBe("Running");
    const progress = card("seal").querySelector(".setup-progress")!;
    expect(progress.getAttribute("role")).toBe("status");
    expect(progress.textContent).toContain("Running: Stop the broker and back up");
    expect(card("seal").querySelector(".setup-go")).toBeNull();
    expect(card("enable-updates").querySelector(".setup-blocked")!.textContent).toContain("Another task is in progress.");

    // The broker goes away: no dead page, a plain notice, and the page keeps asking.
    script = () => {
      throw new ApiError(0, "network", "Could not reach aqmas (connection refused).");
    };
    const banner = root.querySelector(".setup-banner")!;
    await until(() => banner.textContent!.includes("Broker restarting…"));
    expect(banner.getAttribute("role")).toBe("status");
    expect(card("seal").dataset["state"]).toBe("running"); // the last known state stays
    const during = calls;
    await until(() => calls >= during + 3);
    expect(signedOut).toBe(0);

    // It comes back fenced and waiting, with a deadline.
    const deadline = new Date(Date.now() + 10 * 60_000).toISOString();
    script = () => {
      const cur = { task: "seal", state: "waiting", step: "Start the broker in import mode", waiting_for: "the passkey wrap and your activation", deadline, started_at: new Date().toISOString(), log: [] };
      return baseView({ current: cur, tasks: baseView().tasks!.map((t) => (t.id === "seal" ? { ...t, state: "waiting", last: cur } : t)) });
    };
    await until(() => card("seal").dataset["state"] === "waiting");
    expect((banner as HTMLElement).hidden).toBe(true);
    expect(badge("seal")).toBe("Waiting for you");
    expect(card("seal").querySelector(".setup-progress")!.textContent).toContain("Waiting for you: the passkey wrap and your activation");
    expect(card("seal").querySelector("[data-setup-until]")!.textContent).toMatch(/^9:\d\d$|^10:00$/);

    script = () => baseView({ tasks: baseView().tasks!.map((t) => (t.id === "seal" ? { ...t, state: "done" } : t)) });
    await until(() => card("seal").dataset["state"] === "done");
    expect(badge("seal")).toBe("Done");
  });

  test("an idle upgrade reads as up to date", async () => {
    script = () => baseView({ tasks: baseView().tasks!.map((t) => (t.id === "upgrade" ? { ...t, state: "idle", blocked_by: undefined } : t)) });
    await until(() => card("upgrade").dataset["state"] === "idle");
    expect(badge("upgrade")).toBe("Up to date");
    expect(card("upgrade").textContent).toContain("Running 1.4.0");
    script = () => baseView();
  });

  test("typing survives polls; a 401 sends the owner to sign-in and stops polling", async () => {
    await until(() => !!card("seal").querySelector('input[placeholder="age1…"]'));
    const field = card("seal").querySelector<HTMLInputElement>('input[placeholder="age1…"]')!;
    field.value = "age1half-typed";
    const n = calls;
    await until(() => calls >= n + 3);
    expect(card("seal").querySelector<HTMLInputElement>('input[placeholder="age1…"]')).toBe(field);
    expect(field.value).toBe("age1half-typed");

    script = () => {
      throw new ApiError(401, "unauthenticated", "sign in with your passkey");
    };
    await until(() => signedOut === 1);
    const after = calls;
    await new Promise((r) => setTimeout(r, 80));
    expect(calls).toBe(after);
  });
});

describe("Setup through the App and the mock", () => {
  const m = startMock({ port: 0, distDir: null, setupStepMs: 40 });
  const f = jarFetch();
  const api = createApi({ base: m.url, fetch: f });
  const auth = fakeAuth(m.url);
  let root: HTMLElement;
  const card = (id: string) => root.querySelector<HTMLElement>(`[data-task="${id}"]`)!;
  const state = (id: string) => card(id)?.dataset["state"];
  const button = (scope: ParentNode, text: string | RegExp) => [...scope.querySelectorAll<HTMLButtonElement>("button")].find((b) => (typeof text === "string" ? b.textContent === text : text.test(b.textContent ?? "")))!;
  const dlg = () => doc.querySelector("dialog")!;
  let identity = "";
  const token = "tk_LOCKALERT_publish_only_4242";

  /** Run… → check → Confirm with passkey; the prompt must start inside the second tap. */
  async function run(id: string) {
    card(id).querySelector<HTMLButtonElement>(".setup-go")!.click();
    await until(() => !!card(id).querySelector("button.confirm") || !!card(id).querySelector(".setup-run .error")?.textContent);
    expect(card(id).querySelector(".setup-run .error")?.textContent ?? "").toBe("");
    const signed = card(id).querySelector(".signed pre")!.textContent!;
    const gets = auth.gets.length;
    const fetches = f.log.length;
    card(id).querySelector<HTMLButtonElement>("button.confirm")!.click();
    expect(auth.gets.length).toBe(gets + 1);
    expect(f.log.length).toBe(fetches);
    return JSON.parse(signed) as Record<string, unknown>;
  }

  beforeAll(async () => {
    const { SETUP_POLL } = await import("../src/setupPage");
    SETUP_POLL.active = SETUP_POLL.idle = 20;
    doc.body.innerHTML = '<div id="app"></div>'; // test fixture only
    root = doc.getElementById("app")!;
    // The page checks that it is asked to sign for its own site.
    win.happyDOM.setURL(m.url + "/");
    const { App } = await import("../src/app");
    new App(root, api, auth).start();
    await until(() => !!root.querySelector("button.primary"));
    await until(() => f.log.some((x) => x.url.endsWith("/api/ui/login/begin")));
    await new Promise((r) => setTimeout(r, 30));
    root.querySelector<HTMLButtonElement>("button.primary")!.click();
    await until(() => !!root.querySelector("#sec-pending"));
  });
  afterAll(() => m.stop());

  test("Admin has one Setup entry (no separate Updates section), which opens the queue", async () => {
    win.location.hash = "#/admin";
    win.dispatchEvent(new win.Event("hashchange"));
    await until(() => !!root.querySelector("#sec-setup a"));
    expect(root.querySelector("#sec-updates")).toBeNull();
    expect(root.querySelector("#sec-setup")!.textContent).toContain("Next: Switch to organisations.");
    const link = root.querySelector<HTMLAnchorElement>("#sec-setup a")!;
    expect(link.getAttribute("href")).toBe("#/setup");
    win.location.hash = "#/setup";
    win.dispatchEvent(new win.Event("hashchange"));
    await until(() => !!card("upgrade"));
    expect([...root.querySelectorAll<HTMLElement>("[data-task]")].map((c) => [c.dataset["task"], c.dataset["state"]])).toEqual([
      ["cutover", "available"],
      ["seal", "blocked"],
      ["enable-updates", "available"],
      ["sync-passkeys", "done"],
      ["upgrade", "blocked"],
    ]);
    expect(card("seal").querySelector(".setup-blocked")!.textContent).toContain("Switch to organisations first.");
  });

  test("cutover: plan preview, Run, the fenced review with Activate and Cancel, then done", async () => {
    await until(() => !!card("cutover").querySelector("details.setup-more dl"));
    const preview = [...card("cutover").querySelectorAll("details")].find((d) => d.querySelector("summary")!.textContent!.startsWith("Preview of the plan"))!;
    expect(preview.querySelector("summary")!.textContent).toBe("Preview of the plan: 3 hosts, 2 SSH targets, 3 credential sets");
    expect(preview.hasAttribute("open")).toBe(false);
    expect(preview.textContent).toContain("web-1");

    const signed = await run("cutover");
    expect(signed).toMatchObject({ action: "run", object: "setup", id: "cutover", params: "{}", secrets_sha256: "", v: 1 });
    // The broker restarts on the way; the page rides it out and lands in the review.
    await until(() => state("cutover") === "waiting", 8000);
    expect(m.store.setup.mode).toBe("cutover");
    await until(() => !!button(card("cutover"), "Review and activate…"));
    expect(card("cutover").textContent).toContain("Recovery SHA-256");
    expect(button(card("cutover"), "Cancel this task…")).toBeTruthy();
    expect(state("seal")).toBe("blocked");

    // Activation is the existing signed migration review.
    button(card("cutover"), "Review and activate…").click();
    await until(() => !!dlg().querySelector("button.confirm"));
    expect(dlg().querySelector(".headline")!.textContent).toContain("activate organisation admissions");
    dlg().querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => m.store.setup.scoped, 8000);
    await until(() => state("cutover") === "done", 8000);
    dlg().close();
    expect(card("cutover").querySelector(".setup-go")).toBeNull();
    expect(card("cutover").textContent).toContain("Switched to organisations.");
    await until(() => state("seal") === "available");
  }, 30000);

  test("cancel puts a waiting task back, in two taps and without a passkey", async () => {
    m.store.setup.scoped = false;
    delete m.store.setup.last["cutover"];
    await until(() => state("cutover") === "available");
    await run("cutover");
    await until(() => !!card("cutover") && !!button(card("cutover"), "Cancel this task…"), 8000);
    const gets = auth.gets.length;
    button(card("cutover"), "Cancel this task…").click();
    button(card("cutover"), "Yes, cancel and put everything back").click();
    await until(() => state("cutover") === "failed", 8000);
    expect(auth.gets.length).toBe(gets);
    expect(card("cutover").textContent).toContain("Cancelled. Everything was put back as it was.");
    expect(card("cutover").querySelector(".setup-go")!.textContent).toBe("Run again…");
    m.store.setup.scoped = true;
    await until(() => state("seal") === "available");
  }, 30000);

  test("seal: the recovery key is made here, shown once, and only its public half is signed", async () => {
    const c = card("seal");
    button(c, "Generate a recovery key in this browser").click();
    await until(() => !!c.querySelector(".setup-secret"));
    identity = c.querySelector(".setup-secret")!.textContent!;
    expect(identity).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/);
    expect(c.textContent).toContain("Save this in your password manager now. It is the only way back if you lose every passkey. It is not sent anywhere.");
    expect(button(c, "Copy")).toBeTruthy();
    expect(button(c, "Download")).toBeTruthy();

    // Not without "I have saved it".
    c.querySelector<HTMLButtonElement>(".setup-go")!.click();
    await until(() => !!c.querySelector(".setup-run .error")!.textContent);
    expect(c.querySelector(".setup-run .error")!.textContent).toContain("I have saved it");
    expect(c.querySelector("button.confirm")).toBeNull();

    const boxes = [...c.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
    const savedBox = boxes.find((b) => b.closest("label")!.textContent!.includes("I have saved it"))!;
    const purge = boxes.find((b) => b.closest("label")!.textContent!.includes("Delete older on-box backups"))!;
    expect(purge.checked).toBe(true);
    savedBox.checked = true;
    // The optional lock alert.
    const alert = [...c.querySelectorAll("details")].find((d) => d.querySelector("summary")!.textContent!.includes("Lock alert"))!;
    expect(alert.hasAttribute("open")).toBe(false);
    const [topic, tok] = [...alert.querySelectorAll<HTMLInputElement>("input")];
    expect(tok!.type).toBe("password");
    topic!.value = "https://ntfy.example.com/aqmas-lock-7f3a";
    tok!.value = token;

    const start = f.log.length;
    const signed = await run("seal");
    // Once the owner continued, the secret half is gone from the page.
    expect(root.textContent!.includes("AGE-SECRET-KEY-1")).toBe(false);
    expect(doc.body.textContent!.includes(identity)).toBe(false);
    const params = JSON.parse(signed["params"] as string);
    expect(Object.keys(params)).toEqual(["recipient", "purge_backups", "lock_alert"]);
    expect(params).toMatchObject({ purge_backups: true, lock_alert: true });
    expect(params.recipient).toMatch(/^age1[a-z0-9]{58}$/);
    expect(signed["secrets_sha256"]).toMatch(/^[0-9a-f]{64}$/);

    await until(() => state("seal") === "waiting", 8000);
    // Nothing typed or generated left the page in the clear; the runner got the sealed secrets.
    const wire = JSON.stringify(f.log.slice(start).map((x) => [x.url, x.body]));
    expect(wire.includes(token)).toBe(false);
    expect(wire.includes("aqmas-lock-7f3a")).toBe(false);
    expect(wire.includes("AGE-SECRET-KEY")).toBe(false);
    expect(m.store.setup.received.at(-1)!.secrets).toEqual({ ntfy_topic_url: "https://ntfy.example.com/aqmas-lock-7f3a", ntfy_token: token });
    expect(m.store.setup.recipient).toBe(params.recipient);
  }, 30000);

  test("seal-setup: a four-step checklist; Activate needs the tested wrap and the proven recovery key", async () => {
    await until(() => card("seal").querySelectorAll(".setup-checklist > li").length === 4, 8000);
    const steps = () => [...card("seal").querySelectorAll<HTMLElement>(".setup-checklist > li")];
    expect(steps().map((s) => s.querySelector("strong")!.textContent)).toEqual(["Create the unlock wrap", "Test the wrap", "Prove the recovery key", "Activate"]);
    expect(steps().map((s) => s.dataset["done"])).toEqual(["false", "false", "false", "false"]);
    // The generic import panel is not shown twice on this page.
    expect(root.querySelector("#sec-seal")).toBeNull();
    expect(button(steps()[0]!, /^Create with iPhone/)).toBeTruthy();
    expect(button(card("seal"), "Activate…").disabled).toBe(true);
    expect(button(card("seal"), "Cancel this task…")).toBeTruthy();

    // The wrap ceremony is the existing one: its canonical is checked before any tap.
    button(steps()[0]!, /^Create with iPhone/).click();
    await until(() => !!button(card("seal"), "Create unlock wrap with passkey"));
    expect(card("seal").querySelector(".signed pre")!.textContent).toContain('"action":"wrap-enroll"');

    // (The fake authenticator has no PRF, so the test moves the import on itself.)
    m.store.setup.wrap = "tested";
    m.store.setup.wrapCredential = m.store.passkeys[0]!.id;
    await until(() => steps()[1]?.dataset["done"] === "true");
    expect(steps().map((s) => s.dataset["done"])).toEqual(["true", "true", "false", "false"]);
    expect(button(card("seal"), "Activate…").disabled).toBe(true);

    // Prove the recovery key: wrong text, another key, then the right one. The field is cleared each time.
    const drill = () => steps()[2]!.querySelector<HTMLInputElement>('input[type="password"]')!;
    const other = (await (await import("../src/setup")).generateAgeIdentity()).identity;
    const start = f.log.length;
    drill().value = "not a key";
    button(steps()[2]!, "Check the recovery key").click();
    expect(drill().value).toBe("");
    expect(steps()[2]!.querySelector(".error")!.textContent).toContain("AGE-SECRET-KEY-1");
    expect(f.log.slice(start).some((x) => x.url.endsWith("/seal/drill"))).toBe(false);
    drill().value = other;
    button(steps()[2]!, "Check the recovery key").click();
    expect(drill().value).toBe("");
    await until(() => !!steps()[2]!.querySelector(".error")!.textContent);
    expect(steps()[2]!.querySelector(".error")!.textContent).toContain("not the recovery key");
    drill().value = identity;
    button(steps()[2]!, "Check the recovery key").click();
    expect(drill().value).toBe("");
    await until(() => steps()[2]?.dataset["done"] === "true");
    const drills = f.log.slice(start).filter((x) => x.url.endsWith("/seal/drill"));
    expect(drills.length).toBe(2);
    expect(JSON.stringify(f.log.slice(start).map((x) => x.body)).includes("AGE-SECRET-KEY")).toBe(false);

    // Activate: the manifest stays visible; the passkey prompt starts inside the tap.
    await until(() => !button(card("seal"), "Activate…").disabled);
    button(card("seal"), "Activate…").click();
    await until(() => !!button(card("seal"), "Activate sealed installation with passkey"));
    expect(card("seal").querySelector(".signed")!.hasAttribute("open")).toBe(true);
    expect(card("seal").querySelector(".signed pre")!.textContent).toContain("recovery_recipient");
    const gets = auth.gets.length;
    button(card("seal"), "Activate sealed installation with passkey").click();
    expect(auth.gets.length).toBe(gets + 1);
    await until(() => m.store.setup.sealed, 8000);
    await until(() => state("seal") === "done", 8000);
    expect(card("seal").textContent).toContain("The store is sealed.");
    expect(card("seal").querySelector(".setup-checklist")).toBeNull();
  }, 30000);

  test("enable self-update: API addresses follow the repository, host keys are fetched to compare, tokens go sealed", async () => {
    const c = card("enable-updates");
    const inputs = [...c.querySelectorAll<HTMLInputElement>("input")];
    const [repo, forgejo, github, forgejoToken, githubToken] = inputs;
    c.querySelector<HTMLButtonElement>(".setup-go")!.click();
    expect(c.querySelector(".setup-run .error")!.textContent).toContain("repository address");
    repo!.value = "ssh://git@forge.example.com/owner/agent-quartermaster.git";
    repo!.dispatchEvent(new win.Event("input") as unknown as Event);
    expect(forgejo!.value).toBe("https://forge.example.com/api/v1/repos/owner/agent-quartermaster");
    expect(github!.value).toBe("https://api.github.com/repos/owner/agent-quartermaster");
    c.querySelector<HTMLButtonElement>(".setup-go")!.click();
    expect(c.querySelector(".setup-run .error")!.textContent).toContain("host key first");
    button(c, "Fetch host key").click();
    await until(() => c.querySelectorAll(".setup-fingerprints li").length === 2);
    expect(c.querySelector(".setup-fingerprints")!.textContent).toMatch(/ssh-ed25519 SHA256:[A-Za-z0-9+/]{43}/);
    githubToken!.value = "ghp_READONLYTOKEN_0123456789";
    expect(forgejoToken!.value).toBe("");

    const start = f.log.length;
    const signed = await run("enable-updates");
    const params = JSON.parse(signed["params"] as string);
    expect(Object.keys(params)).toEqual(["repo", "forgejo_api", "github_api", "known_hosts", "forgejo_token", "github_token"]);
    expect(params.known_hosts.length).toBe(2);
    expect([...params.known_hosts].sort()).toEqual(params.known_hosts);
    expect(params).toMatchObject({ forgejo_token: false, github_token: true });
    await until(() => m.store.setup.updatesReady, 8000);
    await until(() => state("enable-updates") === "done", 8000);
    expect(JSON.stringify(f.log.slice(start).map((x) => x.body)).includes("READONLYTOKEN")).toBe(false);
    expect(m.store.setup.received.at(-1)!.secrets).toEqual({ github_token: "ghp_READONLYTOKEN_0123456789" });
    // The form is back for another run, prefilled from the configuration, with empty token fields.
    await until(() => card("enable-updates").querySelector<HTMLInputElement>("input")?.value === params.repo);
    expect([...card("enable-updates").querySelectorAll<HTMLInputElement>('input[type="password"]')].map((i) => i.value)).toEqual(["", ""]);
  }, 30000);

  test("upgrade: the release review lives in the queue and is approved through the update flow", async () => {
    await until(() => state("upgrade") === "available");
    const c = card("upgrade");
    await until(() => !!button(c, "Approve update…"));
    expect(c.textContent).toContain("Available: 1.5.0");
    expect(c.textContent).toContain("Release hashes agree");
    button(c, "Approve update…").click();
    await until(() => !!dlg().querySelector("button.confirm"));
    expect(dlg().querySelector(".headline")!.textContent).toBe("Install aqmasd 1.5.0 on the bastion, replacing 1.4.0.");
    dlg().querySelector<HTMLButtonElement>("button.confirm")!.click();
    await until(() => m.store.setup.version === "1.5.0", 8000);
    dlg().close();
    await until(() => state("upgrade") === "idle", 8000);
    expect(card("upgrade").querySelector(".setup-state")!.textContent).toBe("Up to date");
    expect(card("upgrade").textContent).toContain("Installed 1.5.0 and the broker is healthy.");
    expect(card("upgrade").textContent).toContain("Running 1.5.0");
  }, 30000);

  test("sync passkeys: untick one, and exactly the ticked ones are signed as pins", async () => {
    m.store.setup.pins = [m.store.passkeys[0]!.id, m.store.passkeys[1]!.id];
    await until(() => state("sync-passkeys") === "available");
    const c = card("sync-passkeys");
    expect(c.textContent).toContain("already pinned");
    const boxes = [...c.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
    expect(boxes.map((b) => b.checked)).toEqual([true, true, true]);
    boxes[1]!.checked = false;
    const signed = await run("sync-passkeys");
    const params = JSON.parse(signed["params"] as string) as { pins: { id: string; key_sha256: string }[] };
    expect(params.pins.map((p) => p.id)).toEqual([m.store.passkeys[0]!.id, m.store.passkeys[2]!.id]);
    for (const p of params.pins) expect(Object.keys(p)).toEqual(["id", "key_sha256"]);
    await until(() => JSON.stringify(m.store.setup.pins) === JSON.stringify(params.pins.map((p) => p.id)), 8000);
    await until(() => !!card("sync-passkeys").textContent!.includes("2 passkey(s) pinned"), 8000);
  }, 30000);

  test("a Run with a passkey that is not pinned is refused with the broker's explanation", async () => {
    m.store.setup.pins = [m.store.passkeys[2]!.id];
    await until(() => !!root.querySelector('[data-notice="unpinned"]'));
    await run("sync-passkeys");
    await until(() => !!card("sync-passkeys").querySelector(".setup-run .error")?.textContent, 8000);
    expect(card("sync-passkeys").querySelector(".setup-run .error")!.textContent).toContain("not pinned for maintenance");
    expect(card("sync-passkeys").textContent).toContain("Nothing was changed.");
  }, 30000);
});
