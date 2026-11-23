// Screenshots of the UI against the mock server (seeded data, signed in via the mock-only
// /mock/login), at phone, tablet and desktop widths. Not part of the build or the tests.
//
//   cd web && bun run build && bun screenshots/capture.ts [path/to/headless_shell]
//   SHOTS=vault bun screenshots/capture.ts     only the Credential sets pictures (vault-*.png)
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
const defaultOrigin = `http://localhost:${mock.server.port}`;
const only = process.env.SHOTS ?? "";
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
  const r = await cdp<{ result: { value?: unknown }; exceptionDetails?: { text: string; exception?: { description?: string } } }>("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`page: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
  return r.result.value;
}
async function until(expr: string, ms = 5000) {
  const t0 = Date.now();
  while (!(await evaluate(expr))) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + expr);
    await sleep(50);
  }
}

async function open(width: number, dark: boolean, origin = defaultOrigin) {
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

/** One element, whole, wherever it is on the page. */
async function shootEl(name: string, selector: string, width: number) {
  const m = await cdp<{ cssContentSize: { height: number } }>("Page.getLayoutMetrics");
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: Math.ceil(m.cssContentSize.height), deviceScaleFactor: 1, mobile: width < 600 });
  await sleep(250);
  const r = (await evaluate(`(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return { x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height }; })()`)) as { x: number; y: number; w: number; h: number };
  const pad = 12;
  const clip = { x: 0, y: Math.max(0, r.y - pad), width, height: Math.ceil(r.h + 2 * pad), scale: 1 };
  const shot = await cdp<{ data: string }>("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip });
  writeFileSync(join(outDir, name), Buffer.from(shot.data, "base64"));
  console.log(`${name} ${width}x${clip.height}`);
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
}
const click = (selector: string, text?: string) =>
  evaluate(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((b) => ${text === undefined ? "true" : `b.textContent.trim() === ${JSON.stringify(text)}`}); if (!el) throw new Error("no " + ${JSON.stringify(selector + " " + (text ?? ""))}); el.click(); })()`);
const pick = (selector: string, label: string) =>
  evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el.value = [...el.options].find((o) => o.textContent.includes(${JSON.stringify(label)})).value; el.dispatchEvent(new Event("change")); })()`);
const type = (selector: string, value: string) =>
  evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true })); })()`);
// The headless shell has no authenticator. The mock checks an assertion's shape and
// challenge, not its signature, so the pictures use a stand-in (screenshots only).
const FAKE_PASSKEY = `navigator.credentials.get = async (o) => {
  const b64 = (u) => btoa(String.fromCharCode(...new Uint8Array(u))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const cd = JSON.stringify({ type: "webauthn.get", challenge: b64(o.publicKey.challenge), origin: location.origin, crossOrigin: false });
  return { id: b64(raw), rawId: raw.buffer, type: "public-key", authenticatorAttachment: "platform", getClientExtensionResults: () => ({}),
    response: { clientDataJSON: new TextEncoder().encode(cd).buffer, authenticatorData: crypto.getRandomValues(new Uint8Array(37)).buffer, signature: crypto.getRandomValues(new Uint8Array(71)).buffer, userHandle: new Uint8Array(16).buffer } };
}; true`;

const ENV_FILE = "# staging\nAPP_SECRET=mock-rotated-secret\nAPP_TOKEN=mock-new-token\nTLS_KEY=\"-----BEGIN PRIVATE KEY-----\nTU9DSyBLRVkgTUFURVJJQUwgUk9UQVRFRA==\n-----END PRIVATE KEY-----\n\"\n";

/** Vault and the signing cards, against the mock's made-up organisations. */
async function vaultShots(w: number) {
  const m = startMock({ port: 0, distDir: dist, vault: true });
  const origin = `http://localhost:${m.server.port}`;
  try {
    await open(w, false, origin);
    await until(`document.querySelectorAll("#sec-signing .sign-card").length >= 2`);
    await sleep(300);
    await shootEl(`vault-sign-single-${w}.png`, "#sec-signing .sign-card:nth-of-type(1)", w);
    await shootEl(`vault-sign-timed-${w}.png`, "#sec-signing .sign-card:nth-of-type(2)", w);
    await evaluate(FAKE_PASSKEY);
    await evaluate(`location.hash = "#/admin"`);
    await until(`!!document.querySelector("#sec-vault .vault-pick select")`);
    // The write-only form with a .env import waiting to be saved.
    await pick("#vault-org", "client-a");
    await until(`!!document.querySelector("#sec-vault .vault-editor .vault-keys li")`);
    await evaluate(`(() => { const dt = new DataTransfer(); dt.items.add(new File([${JSON.stringify(ENV_FILE)}], "staging.env")); const i = document.querySelector("#vault-file"); i.files = dt.files; i.dispatchEvent(new Event("change")); })()`);
    await until(`document.querySelectorAll("#sec-vault .vault-changes li").length === 3`);
    await click("#sec-vault .vault-keys li:nth-child(3) .btn", "Remove");
    await sleep(200);
    await shootEl(`vault-form-${w}.png`, "#sec-vault .vault-editor", w);
    // Reveal: values on the page, with the countdown.
    await evaluate(`[...document.querySelectorAll("#sec-vault .kv-row .btn")].forEach((b) => b.click())`);
    await click("#sec-vault .vault-editor .btn", "Reveal all…");
    await until(`!!document.querySelector("#sec-vault .vault-confirm .confirm")`);
    await click("#sec-vault .vault-confirm .confirm");
    await until(`document.querySelectorAll("#sec-vault .revealed-item").length === 4`);
    await sleep(200);
    await shootEl(`vault-reveal-${w}.png`, "#sec-vault .vault-editor", w);
    await click("#sec-vault .revealed-head .btn", "Hide now");
    // A new signing key: the public key before the tap, then what verifiers need.
    await pick("#vault-org", "personal");
    await until(`!!document.querySelector("#sec-vault .vault-signer")`);
    await evaluate(`document.querySelector("#sec-vault .vault-new-signer").open = true`);
    await type("#ns-slug", "ota-key");
    await type("#ns-title", "OTA key");
    await click("#sec-vault .vault-new-signer .btn", "Review…");
    await until(`!!document.querySelector("#sec-vault .vault-new-signer .vault-confirm .vault-key")`);
    await sleep(200);
    await shootEl(`vault-signer-${w}.png`, "#sec-vault .vault-new-signer", w);
    await click("#sec-vault .vault-new-signer .vault-confirm .confirm");
    await until(`!!document.querySelector("#sec-vault .vault-signer .vault-done")`);
    await sleep(600);
    await shootEl(`vault-signer-created-${w}.png`, "#sec-vault .vault-signer", w);
  } finally {
    m.stop();
  }
}

try {
  await cdp("Page.enable");
  await cdp("Runtime.enable");
  if (only === "" || only === "vault") for (const w of [375, 1280]) await vaultShots(w);
  if (only !== "") throw "done";
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
} catch (e) {
  if (e !== "done") throw e;
} finally {
  ws.close();
  browser.kill();
  mock.stop();
  rmSync(profile, { recursive: true, force: true });
}
