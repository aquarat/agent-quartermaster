// Seal format 2 (docs/BUCKETS.md §5–6): the status the broker reports, its control actions
// (close all, reopen, rekey, renew the agent TLS leaf, activate a staged store) and
// Admin → Buckets. There is no unlock: a bucket opens only for the tap that needs it and
// stays open only as long as its holds say.

import { type Api } from "./api";
import { h, replace, type Child } from "./dom";
import { canonicalJSON, prepareTap, type OpenPacket, type Tap } from "./buckets";
import { binary32, type Review } from "./review";
import { type Authenticator } from "./webauthn";
import { countdown, visibleText as vt } from "./format";
import type { Profile, TabWindow } from "./approvals";
import type { PasskeyInfo } from "./types";

export interface BucketHold {
  kind: string;
  ref: string;
  reason: string;
  until?: string;
  since: string;
}
export interface PausedUser {
  kind: string;
  ref: string;
  reason: string;
}
export interface BucketInfo {
  id: string;
  kind: string;
  label: string;
  scope: string;
  scope_title: string;
  open: boolean;
  opened_at?: string;
  holds: BucketHold[];
  paused: PausedUser[];
}
export interface ScopeInfo {
  scope: string;
  title: string;
  buckets: number;
  has_key: boolean;
}
export interface PasskeyScopes {
  /** The passkey's id as in UIState.passkeys (hex). */
  id: string;
  name: string;
  current: boolean;
  prf: boolean;
  scopes: { scope: string; tested: boolean }[];
  opens: number;
  of: number;
  missing: string[];
}
export interface StageScope {
  scope: string;
  title: string;
  buckets: number;
  wrapped: boolean;
  tested: boolean;
}
export interface StageChoice {
  id: string;
  name: string;
  credential_id: string;
  legacy?: { mk_version: number; prf_salt: string; installation: string };
}
/** status.stage while a seal import or a bucket migration is staged (mode "setup"). */
export interface StageView {
  source: "unsealed" | "format-1";
  scopes: StageScope[];
  drilled: boolean;
  drill_key: string;
  manifest?: string;
  legacy_unlocked?: boolean;
  choices: StageChoice[];
}
export interface SealView {
  mode: "unsealed" | "buckets" | "migration-required" | "setup" | "activated";
  installation: string;
  epoch: string;
  scopes?: ScopeInfo[];
  buckets?: BucketInfo[];
  passkeys?: PasskeyScopes[];
  stage?: StageView;
  leaf_expires?: string;
  leaf_repair?: string;
  verified_access?: boolean;
  profiles?: Profile[];
  active_windows?: {
    id: string;
    org: string;
    opener: string;
    expires_at: string;
  }[];
}

/** The format-2 serving mode: approvals may open buckets. */
export const serving = (v: SealView | undefined) => v?.mode === "buckets";

export function openCount(v: SealView): number {
  return (v.buckets ?? []).filter((b) => b.open).length;
}
/** "2 buckets open" / "1 bucket open" / "nothing open". */
export function openSummary(v: SealView): string {
  const n = openCount(v);
  return n === 0 ? "nothing open" : n === 1 ? "1 bucket open" : `${n} buckets open`;
}

/** The header's indicator: how much is decrypted right now. Links to Admin → Buckets. */
export function bucketIndicator(v: SealView): HTMLElement {
  const n = openCount(v);
  const a = h("a", { class: `badge buckets-open${n ? " open" : ""}`, title: "Admin → Buckets" }, openSummary(v));
  a.href = "#/admin";
  a.dataset["open"] = String(n);
  return a;
}

export const REKEY_WARNING =
  "Rekey replaces this scope's key and every bucket key in it, and re-encrypts every value. Do it after losing a passkey or a backup: removing a passkey does not revoke copies of its wraps in old backups. Your passkey's new key uses a fresh PRF input: test it right afterwards (Admin → Passkeys → Test). Afterwards only this passkey can open the scope: enable your other passkeys again from it. Open buckets of the scope close and their users pause until you Reopen them. Old copies then expose only values as they were at the copy.";

export const CLOSE_ALL_TEXT = "Close all wipes every open bucket key and hold and ends every approval window, without a restart. Grants that need a bucket pause until you Reopen them.";

export type ControlAction = "close-all" | "renew-leaf" | "reopen" | "rekey" | "activate";
export interface ControlParams {
  /** reopen: the buckets to open. */
  buckets?: string[];
  /** rekey: the scope. */
  scope?: string;
}

const CORE = ["action", "epoch", "id", "issued_at", "nonce", "object", "v"];

/** Check a seal-control challenge: the canonical's fixed fields, the plain fields that say
 * what the tap does, and (reopen, rekey, renew-leaf) the bound open. */
export async function prepareControl(v: SealView, action: ControlAction, b: Review, rp: string, params: ControlParams = {}): Promise<{ tap: Tap; facts: [string, string][] }> {
  const c = JSON.parse(b.canonical) as Record<string, unknown>;
  if (c.v !== 3 || c.object !== "seal-control" || c.action !== action || c.id !== v.installation || c.epoch !== v.epoch) throw Error("Seal control canonical differs from review");
  if (!binary32(c.nonce) || typeof c.issued_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(c.issued_at)) throw Error("Invalid ceremony metadata");
  if (canonicalJSON(c) !== b.canonical) throw Error("Seal control canonical is not in canonical form");
  const extra = Object.keys(c).filter((k) => !CORE.includes(k));
  const facts: [string, string][] = extra.map((k) => [k, typeof c[k] === "string" ? (c[k] as string) : JSON.stringify(c[k])]);
  let open: "none" | "optional" = "none";
  switch (action) {
    case "activate":
      if (v.mode !== "setup" || !v.stage?.manifest) throw Error("No reviewed manifest");
      if (extra.length !== 1 || c.manifest !== v.stage.manifest) throw Error("Seal control canonical differs from review");
      break;
    case "renew-leaf":
      if (!serving(v) || !v.leaf_repair) throw Error("Repair unavailable");
      if (c.repair !== v.leaf_repair) throw Error("Seal control canonical differs from review");
      open = "optional";
      break;
    case "close-all":
      if (!serving(v)) throw Error("Nothing to close");
      break;
    case "reopen": {
      const ids = params.buckets ?? [];
      if (!serving(v) || !ids.length || new Set(ids).size !== ids.length) throw Error("Choose the buckets to reopen");
      if (ids.some((id) => !b.canonical.includes(id))) throw Error("The signed text does not name every bucket you chose");
      open = "optional";
      break;
    }
    case "rekey":
      if (!serving(v) || !params.scope) throw Error("Choose a scope");
      if (!extra.some((k) => c[k] === params.scope)) throw Error("The signed text names another scope");
      open = "optional";
      break;
  }
  const tap = await prepareTap(b, rp, { installation: v.installation, epoch: v.epoch, allowOpen: open !== "none", rekey: action === "rekey", requireOpen: action === "rekey" });
  if (tap.open && action === "reopen") {
    const ids = new Set(params.buckets);
    if (tap.open.descriptor.buckets.some((x) => !ids.has(x.id))) throw Error("The tap would open a bucket you did not choose");
  }
  if (tap.open && action === "rekey" && !tap.open.descriptor.scopes.includes(params.scope!)) throw Error("The tap opens another scope");
  return { tap, facts };
}

/** Challenge + pre-signing checks for a seal control action; `finish` signs and applies it.
 * For "activate", `detail` is the complete bound manifest plus its digest. */
export async function beginControl(api: Api, v: SealView, action: ControlAction, params: ControlParams = {}, rp: string = globalThis.location?.hostname ?? "") {
  if (action === "activate" && (v.mode !== "setup" || !v.stage?.manifest)) throw Error("No reviewed manifest");
  if (action === "rekey" && !params.scope) throw Error("Choose a scope");
  if (action === "reopen" && !params.buckets?.length) throw Error("Choose the buckets to reopen");
  const body: Record<string, unknown> = { action };
  if (params.buckets) body.buckets = params.buckets;
  if (params.scope) body.scope = params.scope;
  const b = await api.sealPost!<Review>("control/challenge", body);
  const { tap, facts } = await prepareControl(v, action, b, rp, params);
  let detail = b.canonical;
  if (action === "activate") {
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v.stage!.manifest!))), (x) => x.toString(16).padStart(2, "0")).join("");
    let manifest = v.stage!.manifest!;
    try {
      manifest = JSON.stringify(JSON.parse(manifest), null, 2);
    } catch {
      /* shown as sent */
    }
    detail = manifest + "\nCompare SHA-256 with the local operator view: " + digest;
  }
  return {
    detail,
    facts,
    lines: tap.lines,
    /** Call from the tap: the passkey prompt starts before any other await. */
    async finish(auth: Authenticator): Promise<void> {
      const signed: { assertion: unknown; open?: OpenPacket } = await tap.sign(auth);
      await api.sealPost!("control/finish", { challenge_id: b.challenge_id, ...signed });
    },
  };
}

// ---- Admin → Buckets ----

const KINDS: Record<string, string> = {
  "ssh-ca": "SSH user CA",
  "internal-ca": "Internal CA",
  "cf-proxy": "Cloudflare proxy token",
  env: "Env set",
  "env-set": "Env set",
  signer: "Signer key",
};
export const kindWords = (k: string) => KINDS[k] ?? k;

function untilEl(iso: string | undefined): Child {
  if (!iso) return "until restart or revoke";
  const t = Date.parse(iso);
  return Number.isFinite(t) ? h("span", null, "until ", h("time", { datetime: iso, "data-until": String(t) }, countdown(t))) : vt(iso);
}

export interface BucketsHooks {
  /** Start the passkey flow that creates an organisation's scope key (capabilities.ts). */
  createScope?(scope: string, review: HTMLElement): Promise<void>;
}

/** Admin → Buckets: every bucket, what holds it open, what waits for a Reopen, per-scope
 * Rekey and Create, Close all. Each action is one signed tap shown before it is taken. */
export function bucketsPanel(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], refresh: () => void, tab?: TabWindow, hooks: BucketsHooks = {}): HTMLElement {
  const root = h("article", { class: "card buckets" });
  const review = h("div", { role: "status", class: "buckets-review" });
  const err = (e: unknown) => replace(review, h("p", { class: "error", role: "alert" }, vt((e as Error).message)));
  const button = (label: string, f: () => Promise<void>, cls = "btn") =>
    h(
      "button",
      {
        type: "button",
        class: cls,
        on: {
          click: async (ev) => {
            const btn = ev.currentTarget as HTMLButtonElement;
            btn.disabled = true;
            try {
              await f();
            } catch (e) {
              err(e);
            } finally {
              btn.disabled = false;
            }
          },
        },
      },
      label,
    );
  /** Review → one tap. The tap button calls the passkey prompt before any other await. */
  const confirm = (title: string, warning: string | null, c: Awaited<ReturnType<typeof beginControl>>) => {
    const sign = h("button", { type: "button", class: "btn approve confirm" }, title + " with passkey");
    sign.addEventListener("click", () => {
      sign.disabled = true;
      c.finish(auth).then(
        () => {
          replace(review, h("p", null, "Done."));
          refresh();
        },
        (e) => err(e),
      );
    });
    replace(
      review,
      h("h3", null, title),
      warning ? h("p", { class: "warn" }, warning) : null,
      c.lines.length ? h("ul", { class: "open-lines" }, c.lines.map((l) => h("li", null, vt(l)))) : h("p", { class: "muted" }, "This tap opens no bucket."),
      c.facts.length ? h("dl", { class: "facts" }, c.facts.map(([k, x]) => [h("dt", null, vt(k)), h("dd", null, h("span", { class: "mono" }, vt(x)))])) : null,
      h("details", { class: "signed" }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(c.detail))),
      h("div", { class: "actions" }, sign),
    );
    sign.focus();
  };

  const buckets = v.buckets ?? [];
  const scopes = v.scopes ?? [];
  const n = openCount(v);
  const picked = new Map<string, string>(); // bucket id -> scope, for Reopen
  const reopen = button("Reopen selected…", async () => {
    const ids = [...picked.keys()].sort();
    if (!ids.length) throw Error("Tick the paused buckets to reopen.");
    if (new Set(picked.values()).size > 2) throw Error("One tap opens at most two scopes: choose buckets of one or two scopes.");
    confirm("Reopen", null, await beginControl(api, v, "reopen", { buckets: ids }));
  }, "btn approve");
  reopen.disabled = true;
  const sync = () => {
    reopen.disabled = picked.size === 0;
    reopen.textContent = `Reopen selected (${picked.size})…`;
  };

  const rows: Child[] = [];
  const titleOf = (s: string) => scopes.find((x) => x.scope === s)?.title || s;
  const scopeNames = [...new Set([...scopes.map((s) => s.scope), ...buckets.map((b) => b.scope)])];
  for (const s of scopeNames) {
    const info = scopes.find((x) => x.scope === s);
    const mine = buckets.filter((b) => b.scope === s);
    const head = h("div", { class: "scope-head" }, h("h3", null, vt(info?.title || s)), h("span", { class: "muted" }, ` · ${mine.length} bucket${mine.length === 1 ? "" : "s"}`));
    if (info && !info.has_key) {
      head.append(h("span", { class: "badge" }, "No key yet"));
      if (hooks.createScope)
        head.append(
          button("Create…", async () => {
            await hooks.createScope!(s, review);
          }),
        );
    } else if (info) {
      head.append(
        button("Rekey…", async () => {
          confirm(`Rekey ${info.title || s}`, REKEY_WARNING, await beginControl(api, v, "rekey", { scope: s }));
        }, "btn deny small"),
      );
    }
    const list = h("ul", { class: "bucket-list" });
    for (const b of mine) {
      const li = h(
        "li",
        { class: `bucket${b.open ? " open" : ""}`, "data-bucket": b.id },
        h("p", null, h("strong", null, vt(b.label)), " ", h("span", { class: "muted" }, vt(kindWords(b.kind))), " ", h("span", { class: `badge${b.open ? " open" : ""}` }, b.open ? "Open" : "Closed")),
      );
      if (b.holds.length)
        li.append(h("ul", { class: "holds" }, b.holds.map((x) => h("li", null, vt(x.reason || x.kind), x.ref ? h("span", { class: "muted mono" }, " ", vt(x.ref)) : null, " · ", untilEl(x.until)))));
      if (b.paused.length) {
        const tick = h("input", { type: "checkbox", "aria-label": `Reopen ${vt(b.label)}` });
        tick.addEventListener("change", () => {
          if (tick.checked) picked.set(b.id, b.scope);
          else picked.delete(b.id);
          sync();
        });
        li.append(
          h("p", { class: "warn" }, `${b.paused.length} waiting for a Reopen:`),
          h("ul", { class: "paused" }, b.paused.map((p) => h("li", null, vt(p.reason || p.kind), p.ref ? h("span", { class: "muted mono" }, " ", vt(p.ref)) : null))),
          h("label", null, tick, " Reopen this bucket"),
        );
      }
      list.append(li);
    }
    rows.push(h("section", { class: "scope", "data-scope": s }, head, list));
  }
  const paused = buckets.some((b) => b.paused.length);
  const controls = h("div", { class: "actions" });
  if (paused) controls.append(reopen);
  controls.append(
    button("Close all…", async () => {
      confirm("Close all", CLOSE_ALL_TEXT, await beginControl(api, v, "close-all"));
    }, "btn deny"),
  );
  const extra: Child[] = [];
  if (serving(v)) {
    extra.push(h("p", { class: "muted" }, v.leaf_expires ? "Agent TLS expires " + vt(v.leaf_expires) : "Agent listener disabled: TLS leaf invalid"));
    if (v.leaf_repair)
      extra.push(
        button("Review TLS leaf renewal…", async () => {
          confirm("Renew the agent TLS leaf", null, await beginControl(api, v, "renew-leaf"));
        }),
      );
  }
  for (const w of v.active_windows ?? [])
    extra.push(
      h(
        "div",
        { class: "window" },
        "Approval window: " + vt(w.org) + " · ",
        untilEl(w.expires_at),
        button("End now", async () => {
          await api.sealPost!("windows/close", { window_id: w.id });
          if (tab?.id() === w.id) tab.forget();
          refresh();
        }),
      ),
    );
  void pks; // the current passkey is resolved by hooks.createScope
  void titleOf;
  root.append(
    h("p", { class: "headline" }, n === 0 ? "Nothing is open." : `${n} of ${buckets.length} bucket${buckets.length === 1 ? "" : "s"} open.`),
    h("p", { class: "muted" }, "Each credential is in its own encrypted bucket. A bucket opens only with the approval that needs it and stays open only while something below holds it. After a restart nothing is open; grants that need a bucket wait for a Reopen."),
    rows.length ? h("div", { class: "scopes" }, rows) : h("p", { class: "empty" }, "No buckets yet."),
    controls,
    h("div", null, extra),
    review,
  );
  return root;
}

function link(text: string, href: string): HTMLAnchorElement {
  const a = h("a", { class: "btn approve" }, text);
  a.href = href;
  return a;
}

/** Shown above every page when the broker needs the owner's attention. */
export function sealBanner(v: SealView): HTMLElement | null {
  if (v.mode === "migration-required")
    return h(
      "article",
      { class: "card warn-card" },
      h("h2", null, "Move to per-credential buckets"),
      h("p", null, "This broker runs a newer version that keeps every credential in its own bucket. Until the store is moved, it signs in, queues requests and lets you deny and revoke, but issues nothing."),
      h("div", { class: "actions" }, link("Open Admin → Setup", "#/setup")),
    );
  if (v.mode === "activated") return h("article", { class: "card" }, h("p", { class: "spinner", role: "status" }, "Activated. The broker restarts in a moment; nothing is open until an approval needs it."));
  return null;
}
