// Screenshots of the UI against the mock server (seeded data, signed in via the mock-only
// /mock/login), at phone, tablet and desktop widths. Not part of the build or the tests.
//
//   cd web && bun run build && bun screenshots/capture.ts [path/to/headless_shell]
//
// Uses Chromium's DevTools protocol directly (no extra dependencies). Default browser: the
// Playwright headless shell under ~/.cache/ms-playwright.

import { readdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { startMock } from "../mock/server";

const outDir = import.meta.dir;
const dist = join(import.meta.dir, "..", "dist");

function findBrowser(): string {
  if (process.argv[2]) return process.argv[2];
  const base = join(homedir(), ".cache", "ms-playwright");
  for (const d of readdirSync(base).filter((x) => x.startsWith("chromium_headless_shell-")).sort().reverse()) {
    for (const sub of readdirSync(join(base, d))) {
      if (sub.startsWith("chrome-headless-shell")) return join(base, d, sub, "chrome-headless-shell");
    }
  }
  throw new Error("no headless shell found; pass its path");
}

const mock = startMock({ port: 0, distDir: dist });
const origin = `http://localhost:${mock.server.port}`;
const profile = mkdtempSync(join(tmpdir(), "aqmas-shots-"));
const browser = Bun.spawn(
  [findBrowser(), "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"],
  { stderr: "pipe", stdout: "ignore" },
);

async function devtoolsPort(): Promise<number> {
  const reader = browser.stderr.getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) throw new Error("browser exited: " + buf);
    buf += new TextDecoder().decode(value);
    const m = /DevTools listening on ws:\/\/[^:]+:(\d+)\//.exec(buf);
    if (m) return Number(m[1]);
  }
}

const port = await devtoolsPort();
const pages = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()) as Array<{ type: string; webSocketDebuggerUrl: string }>;
const ws = new WebSocket(pages.find((p) => p.type === "page")!.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const waiting = new Map<number, (v: { result?: unknown; error?: unknown }) => void>();
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(String(ev.data));
  if (msg.id && waiting.has(msg.id)) {
    waiting.get(msg.id)!(msg);
    waiting.delete(msg.id);
  }
});
async function cdp<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const id = ++seq;
  ws.send(JSON.stringify({ id, method, params }));
  const r = await new Promise<{ result?: unknown; error?: unknown }>((res) => waiting.set(id, res));
  if (r.error) throw new Error(`${method}: ${JSON.stringify(r.error)}`);
  return r.result as T;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function evaluate(expr: string): Promise<unknown> {
  const r = await cdp<{ result: { value?: unknown } }>("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  return r.result.value;
}
async function until(expr: string, ms = 5000) {
  const t0 = Date.now();
  while (!(await evaluate(expr))) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + expr);
    await sleep(50);
  }
}

async function open(width: number, dark: boolean) {
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
  await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }] });
  await cdp("Page.navigate", { url: `${origin}/mock/login` });
  await until(`!!document.querySelector("#sec-pending article")`);
  await sleep(400);
}

async function shoot(name: string, width: number, full: boolean) {
  let height = 900;
  if (full) {
    const m = await cdp<{ cssContentSize: { height: number } }>("Page.getLayoutMetrics");
    height = Math.ceil(m.cssContentSize.height);
    await cdp("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 });
    await sleep(300);
    const m2 = await cdp<{ cssContentSize: { height: number } }>("Page.getLayoutMetrics");
    height = Math.ceil(m2.cssContentSize.height);
  }
  const shot = await cdp<{ data: string }>("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: full,
    clip: { x: 0, y: 0, width, height, scale: 1 },
  });
  writeFileSync(join(outDir, name), Buffer.from(shot.data, "base64"));
  console.log(`${name} ${width}x${height}`);
}

try {
  await cdp("Page.enable");
  await cdp("Runtime.enable");
  for (const w of [375, 768, 1280, 1920, 2560]) {
    await open(w, false);
    await shoot(`main-${w}.png`, w, true);
  }
  await open(1280, true);
  await shoot("main-1280-dark.png", 1280, true);
  await open(375, true);
  await shoot("main-375-dark.png", 375, true);

  // Rename sheet on a phone: type a name, continue to the canonical confirmation.
  await open(375, false);
  await evaluate(`[...document.querySelectorAll("#sec-passkeys article")][2].querySelector("button").click()`);
  await until(`!!document.querySelector("dialog input#pk-rename")`);
  await evaluate(`(() => { const i = document.querySelector("dialog input#pk-rename"); i.value = "YubiKey C (desk)"; [...document.querySelectorAll("dialog button")].find(b => b.textContent === "Continue").click(); })()`);
  await until(`!!document.querySelector("dialog button.confirm")`);
  await evaluate(`document.querySelector("dialog details.signed").open = true`);
  await sleep(300);
  await shoot("sheet-rename-375.png", 375, false);

  // Removing the passkey this session signed in with: warning first, then confirmation.
  await open(375, false);
  await evaluate(`document.querySelector("#sec-passkeys article.current button.deny").click()`);
  await until(`[...document.querySelectorAll("dialog button")].some(b => b.textContent === "Continue")`);
  await sleep(200);
  await shoot("sheet-remove-current-375.png", 375, false);
  await evaluate(`[...document.querySelectorAll("dialog button")].find(b => b.textContent === "Continue").click()`);
  await until(`!!document.querySelector("dialog button.confirm")`);
  await sleep(200);
  await shoot("sheet-remove-confirm-375.png", 375, false);

  // Activity with a row expanded and the Passkeys filter, desktop.
  await open(1280, false);
  await evaluate(`document.querySelector('.filters [data-filter="passkeys"]').click()`);
  await sleep(200);
  await evaluate(`document.querySelector("#sec-recent .ev-toggle").click()`);
  await sleep(200);
  await shoot("activity-passkeys-filter-1280.png", 1280, false);
} finally {
  ws.close();
  browser.kill();
  mock.stop();
  rmSync(profile, { recursive: true, force: true });
}
