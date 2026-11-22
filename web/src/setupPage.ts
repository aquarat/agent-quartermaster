// Admin → Setup (docs/SETUP.md): the task queue. Each task is a card with its fixed
// description, its state, the last run, and whatever the owner has to enter or tap. The
// broker restarts during tasks, so this page polls by itself and treats an unreachable broker
// as "restarting", never as an error page.
//
// Cards are redrawn piecewise (state, form, last run) and only when their inputs change, so a
// poll never clears a field the owner is typing in. Secrets typed here are read once, sealed
// by setup.ts and never stored.

import { ApiError, type Api } from "./api";
import { updateCard, type UpdateView } from "./admin";
import { h, replace, type Child } from "./dom";
import { explainError, nothingChanged, type ActionTarget } from "./flows";
import { ago, countdown, visibleText as vt } from "./format";
import { planRows } from "./migration";
import { beginChoice, beginControl, type SealView } from "./sealPanel";
import {
  ageRecipientProblem,
  completeSetupTask,
  generateAgeIdentity,
  hostKeyFingerprint,
  prepareSetupTask,
  sendDrill,
  type HostKeys,
  type PreparedSetup,
  type SetupRun,
  type SetupTask,
  type SetupView,
} from "./setup";
import type { Authenticator } from "./webauthn";

export interface SetupHooks {
  /** Open the existing cutover activation review (canonical checks live there). */
  openMigration(target: ActionTarget): void;
  /** Open the existing upgrade approval review. */
  openUpdate(target: ActionTarget): void;
  /** The session ended (401): send the owner to sign-in. */
  signedOut(): void;
  /** The broker's mode or a task's state changed: the rest of the app should refresh. */
  changed?(): void;
  /** Poll interval while a task is in progress (default 2 s) and otherwise (default 5 s). */
  pollMs?: number;
  idleMs?: number;
}

/** How often the page asks for the setup state: while a task is in progress, and otherwise. */
export const SETUP_POLL = { active: 2000, idle: 5000 };

interface Migration {
  id: string;
  plan: string;
  recovery_sha256: string;
}

interface Collected {
  params: Record<string, unknown>;
  secrets?: Record<string, string>;
  /** Plain words for what is about to be signed. */
  summary: Child[];
  /** The challenge was verified: drop what must not outlive this step. */
  onPrepared?: () => void;
  /** The signed request reached the spool: clear the fields. */
  onSent?: () => void;
}

/** A problem with what the owner entered (shown next to the Run button). */
class Invalid extends Error {}

const BADGES: Record<string, string> = {
  available: "Ready",
  blocked: "Blocked",
  idle: "Nothing to do",
  running: "Running",
  waiting: "Waiting for you",
  done: "Done",
  failed: "Failed",
};

// The runner's patterns (internal/maint/spec.go), for a friendly message before the tap.
const REPO_RE = /^ssh:\/\/[a-z_][a-z0-9_-]{0,31}@([a-z0-9][a-z0-9.-]{0,252})(:[0-9]{1,5})?\/([A-Za-z0-9][A-Za-z0-9._/-]{0,200})\.git$/;
const API_RE = /^https?:\/\/[A-Za-z0-9.:-]{1,255}\/[A-Za-z0-9._/-]{1,200}$/;
const TOKEN_RE = /^[A-Za-z0-9_.~+/=:-]{8,512}$/;
const TOPIC_RE = /^https:\/\/[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?\/[A-Za-z0-9_-]{1,128}$/;
const IDENTITY_RE = /^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}$/;

const REPO_HINT = "ssh://git@forge.example.com/owner/agent-quartermaster.git";
const FORGEJO_HINT = "https://forge.example.com/api/v1/repos/owner/agent-quartermaster";
const GITHUB_HINT = "https://api.github.com/repos/owner/agent-quartermaster";

/** aqmas's own words for a refusal (a 4xx carries the reason); otherwise the usual wording. */
function explain(e: unknown): string {
  if (e instanceof ApiError && (e.code === "conflict" || e.code === "bad_request") && e.message) return e.message;
  return explainError(e);
}

function runnable(v: SetupView, t: SetupTask): boolean {
  return t.state === "available" || t.state === "failed" || (t.state === "done" && !!t.rerunnable && !v.current && v.mode === "serve" && v.runner_installed);
}

let fieldSeq = 0;
function input(type: "text" | "password" | "checkbox", placeholder = ""): HTMLInputElement {
  const el = h("input", { type, id: `setup-f${++fieldSeq}`, autocomplete: "off", spellcheck: "false" });
  if (type !== "checkbox") el.className = "text";
  if (placeholder) el.placeholder = placeholder;
  return el;
}
function field(label: string, el: HTMLInputElement, hint?: Child): HTMLElement {
  return h("div", { class: "field" }, h("label", { for: el.id }, label), el, hint ? h("p", { class: "hint muted" }, hint) : null);
}
function check(el: HTMLInputElement, ...label: Child[]): HTMLElement {
  return h("label", { class: "setup-check", for: el.id }, el, h("span", null, label));
}

function copyButton(text: () => string, label = "Copy"): HTMLButtonElement {
  const b = h("button", { type: "button", class: "btn small" }, label);
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text());
      b.textContent = "Copied";
    } catch {
      b.textContent = "Select the text and copy it";
    }
  });
  return b;
}

function download(name: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function count(n: number, one: string): string {
  return `${n} ${one}${n === 1 ? "" : "s"}`;
}

/** "3 hosts, 2 SSH targets, 4 credential sets" from a cutover plan. */
function planSummary(text: string): string {
  const p = JSON.parse(text) as { admit_to_personal_only?: unknown[] | null; services?: { sets?: { ssh_target?: unknown }[] | null }[] | null };
  const sets = (p.services ?? []).flatMap((s) => s.sets ?? []);
  return [count((p.admit_to_personal_only ?? []).length, "host"), count(sets.filter((s) => s.ssh_target).length, "SSH target"), count(sets.length, "credential set")].join(", ");
}

function planDetails(text: string, id: string, title: string): HTMLElement {
  try {
    const rows = planRows(text, id);
    return h(
      "details",
      { class: "setup-more" },
      h("summary", null, `${title}: ${planSummary(text)}`),
      h("dl", { class: "facts" }, rows.map(([k, v]) => [h("dt", null, vt(k)), h("dd", null, h("bdi", null, vt(v)))])),
    );
  } catch (e) {
    return h("p", { class: "error", role: "alert" }, `The plan could not be checked, so it is not shown: ${vt((e as Error).message)}.`);
  }
}

interface Card {
  root: HTMLElement;
  badge: HTMLElement;
  status: HTMLElement;
  form: HTMLElement;
  last: HTMLElement;
  keys: Record<"status" | "form" | "last", string | undefined>;
}

export class SetupPage {
  private view: SetupView | null = null;
  private migration: Migration | null = null;
  private seal: SealView | null = null;
  private updates: UpdateView | null = null;
  private preview: { id: string; plan: string } | { error: string } | null = null;
  private cards = new Map<string, Card>();
  private queued: { task: string; at: number } | null = null;
  private signature = "";
  private failing = false;
  private busy = false;
  private again = false;
  private stopped = true;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private ticker: ReturnType<typeof setInterval> | undefined;
  private banner = h("p", { class: "setup-banner", role: "status", "aria-live": "polite" }, "Loading…");
  private notices = h("div", { class: "setup-notices" });
  private list = h("div", { class: "setup-list" });

  constructor(
    private root: HTMLElement,
    private api: Api,
    private auth: Authenticator,
    private hooks: SetupHooks,
  ) {
    replace(root, this.banner, this.notices, this.list);
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.ticker = setInterval(() => this.tick(), 1000);
    void this.refresh();
  }

  stop(): void {
    this.stopped = true;
    clearTimeout(this.timer);
    clearInterval(this.ticker);
  }

  // ---- data ----

  private active(): boolean {
    const v = this.view;
    return this.failing || !!this.queued || !!v?.current || (!!v && v.mode !== "serve");
  }

  async refresh(): Promise<void> {
    if (this.stopped) return;
    if (this.busy) {
      this.again = true;
      return;
    }
    this.busy = true;
    clearTimeout(this.timer);
    try {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") await this.load();
    } finally {
      this.busy = false;
      if (this.again) {
        this.again = false;
        void this.refresh();
      } else if (!this.stopped) {
        this.timer = setTimeout(() => void this.refresh(), this.active() ? (this.hooks.pollMs ?? SETUP_POLL.active) : (this.hooks.idleMs ?? SETUP_POLL.idle));
      }
    }
  }

  private async load(): Promise<void> {
    let v: SetupView;
    try {
      v = await this.api.setupGet!<SetupView>("");
    } catch (e) {
      if (e instanceof ApiError && e.code === "unauthenticated") {
        this.stop();
        this.hooks.signedOut();
        return;
      }
      this.failed(e);
      return;
    }
    if (this.stopped) return;
    const tasks = v.tasks ?? [];
    const quiet = <T>(p: Promise<T> | undefined): Promise<T | undefined> => (p ? p.catch(() => undefined) : Promise.resolve(undefined));
    const cutover = tasks.find((t) => t.id === "cutover");
    const wantPreview = v.mode === "serve" && !!cutover && (cutover.state === "available" || cutover.state === "failed");
    if (!wantPreview) this.preview = null;
    const upgrade = tasks.find((t) => t.id === "upgrade");
    const [migration, seal, updates, preview] = await Promise.all([
      v.mode === "cutover" ? quiet(this.api.migration?.()) : undefined,
      v.mode === "seal-setup" ? quiet(this.api.sealStatus?.()) : undefined,
      upgrade && upgrade.state !== "blocked" ? quiet(this.api.updates()) : undefined,
      wantPreview && !this.preview
        ? this.api.setupGet!<{ id: string; plan: string }>("/cutover/preview").catch((e) => (e instanceof ApiError && e.status >= 400 && e.status < 500 ? { error: explain(e) } : undefined))
        : undefined,
    ]);
    if (this.stopped) return;
    // A helper call that failed (the broker went away mid-poll) keeps what was shown before.
    if (v.mode !== "cutover") this.migration = null;
    else if (migration) this.migration = migration;
    if (v.mode !== "seal-setup") this.seal = null;
    else if (seal) this.seal = seal;
    if (updates) this.updates = updates;
    if (preview) this.preview = preview;

    const q = this.queued;
    if (q) {
      const t = tasks.find((x) => x.id === q.task);
      const after = (iso: string | undefined) => !!iso && Date.parse(iso) >= q.at - 5000;
      if (v.current?.task === q.task || after(t?.last?.started_at) || after(v.refused?.at) || Date.now() - q.at > 60_000) this.queued = null;
    }
    this.view = { ...v, tasks, passkeys: v.passkeys ?? [] };
    this.failing = false;
    this.banner.textContent = "";
    this.banner.hidden = true;
    this.render();
    const signature = JSON.stringify([v.mode, tasks.map((t) => t.state)]);
    if (this.signature && this.signature !== signature) this.hooks.changed?.();
    this.signature = signature;
  }

  private failed(e: unknown): void {
    const restarting = !!this.queued || !!this.view?.current || (!!this.view && this.view.mode !== "serve");
    this.failing = true;
    this.banner.hidden = false;
    this.banner.textContent = restarting
      ? "Broker restarting… This page keeps checking and carries on by itself."
      : e instanceof ApiError && e.code === "access"
        ? vt(e.message)
        : `Can't reach the broker (${vt(explainError(e))}). It may be restarting; this page keeps checking.`;
  }

  private tick(): void {
    const now = Date.now();
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-setup-until]")) t.textContent = countdown(Number(t.dataset["setupUntil"]), now);
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-setup-since]")) t.textContent = ago(Number(t.dataset["setupSince"]), now);
  }

  // ---- rendering ----

  private render(): void {
    const v = this.view!;
    this.renderNotices(v);
    const ids = new Set(v.tasks!.map((t) => t.id));
    for (const [id, c] of this.cards) {
      if (!ids.has(id)) {
        c.root.remove();
        this.cards.delete(id);
      }
    }
    for (const t of v.tasks!) {
      let c = this.cards.get(t.id);
      if (!c) {
        c = this.newCard(t);
        this.cards.set(t.id, c);
        this.list.appendChild(c.root);
      }
      this.renderCard(c, t, v);
    }
  }

  private noticeKey = "";
  private renderNotices(v: SetupView): void {
    const keys = v.passkeys!;
    const key = JSON.stringify([v.runner_installed, v.refused, keys]);
    if (key === this.noticeKey) return;
    this.noticeKey = key;
    const out: Child[] = [];
    if (!v.runner_installed) {
      const cmd = "sudo aqmasd maint-init";
      out.push(
        h(
          "div",
          { class: "warn setup-notice", "data-notice": "runner" },
          h("p", null, "The maintenance runner is not installed on this machine yet. Run this once in a terminal on the bastion; after that everything happens on this page:"),
          h("div", { class: "setup-copy" }, h("pre", { class: "cmd" }, cmd), copyButton(() => cmd)),
        ),
      );
    } else {
      const mine = keys.find((k) => k.current);
      const pinned = keys.filter((k) => k.pinned);
      if (mine && !mine.pinned) {
        out.push(
          h(
            "div",
            { class: "warn setup-notice", "data-notice": "unpinned" },
            h("p", null, "The passkey you signed in with (", h("bdi", null, vt(mine.name)), ") is not pinned for maintenance, so a Run signed with it would be refused."),
            pinned.length
              ? h(
                  "p",
                  null,
                  "Sign and approve with a pinned passkey (",
                  pinned.map((k, i) => [i ? ", " : "", h("bdi", null, vt(k.name))]),
                  "), then run “Sync maintenance passkeys” below to pin this one too.",
                )
              : h("p", null, "No registered passkey is pinned. Re-pin from a terminal on the bastion: ", h("span", { class: "mono" }, "sudo aqmasd maint-init --repin")),
          ),
        );
      }
    }
    if (v.refused) {
      const at = Date.parse(v.refused.at);
      out.push(
        h(
          "div",
          { class: "warn setup-notice", "data-notice": "refused", role: "alert" },
          h("p", null, "The runner refused the last request", Number.isFinite(at) ? [" (", h("time", { "data-setup-since": String(at), datetime: v.refused.at }, ago(at)), ")"] : null, ": ", h("bdi", null, vt(v.refused.reason))),
          h("p", null, "Nothing was changed."),
        ),
      );
    }
    replace(this.notices, out);
  }

  private newCard(t: SetupTask): Card {
    const badge = h("span", { class: "badge setup-state" });
    const status = h("div", { class: "setup-status" });
    const form = h("div", { class: "setup-form" });
    const last = h("div", { class: "setup-last" });
    const steps = t.steps ?? [];
    const root = h(
      "article",
      { class: "card setup-task", "data-task": t.id, "aria-labelledby": `setup-${t.id}-h` },
      h("div", { class: "setup-head" }, h("h3", { id: `setup-${t.id}-h` }, vt(t.title)), badge),
      h("p", null, vt(t.summary)),
      h(
        "details",
        { class: "setup-more" },
        h("summary", null, `What happens (${count(steps.length, "step")})`),
        h("ol", { class: "setup-steps" }, steps.map((s) => h("li", null, vt(s)))),
        h("p", { class: "muted" }, h("strong", null, "Can it be undone? "), vt(t.reversible)),
      ),
      status,
      form,
      last,
    );
    return { root, badge, status, form, last, keys: { status: undefined, form: undefined, last: undefined } };
  }

  private part(c: Card, name: "status" | "form" | "last", data: unknown, build: () => Child[]): void {
    const key = JSON.stringify(data) ?? "";
    if (c.keys[name] === key) return;
    c.keys[name] = key;
    // Keep collapsible parts as the owner left them.
    const open = [...c[name].querySelectorAll<HTMLDetailsElement>("details[data-keep]")].filter((d) => d.open).map((d) => d.dataset["keep"]);
    replace(c[name], build());
    for (const d of c[name].querySelectorAll<HTMLDetailsElement>("details[data-keep]")) if (open.includes(d.dataset["keep"])) d.open = true;
    this.tick();
  }

  private renderCard(c: Card, t: SetupTask, v: SetupView): void {
    const queued = this.queued?.task === t.id && t.state !== "running" && t.state !== "waiting";
    const state = queued ? "running" : t.state;
    c.root.dataset["state"] = state;
    c.badge.className = `badge setup-state state-${/^[a-z]+$/.test(state) ? state : "other"}`;
    c.badge.textContent = queued ? "Starting" : state === "idle" && t.id === "upgrade" ? "Up to date" : state === "done" && t.rerunnable ? "Done" : (BADGES[state] ?? vt(state));

    const run = t.last ?? undefined;
    this.part(c, "status", [state, queued, t.blocked_by, run?.step, run?.waiting_for, run?.deadline, run?.started_at], () => this.statusPart(t, queued, run));
    this.part(c, "form", this.formKey(t, v), () => this.formPart(t, v));
    this.part(c, "last", [t.state, run], () => this.lastPart(t, run));
  }

  private statusPart(t: SetupTask, queued: boolean, run: SetupRun | undefined): Child[] {
    if (queued) return [h("p", { class: "spinner", role: "status" }, "Approved. Waiting for the runner to start…")];
    switch (t.state) {
      case "blocked":
        return [h("p", { class: "setup-blocked" }, h("strong", null, "Blocked: "), vt(t.blocked_by || "not possible right now."))];
      case "running": {
        const at = Date.parse(run?.started_at ?? "");
        return [
          h(
            "p",
            { class: "setup-progress", role: "status", "aria-live": "polite" },
            h("strong", null, "Running: "),
            vt(run?.step || "starting…"),
            Number.isFinite(at) ? [" ", h("span", { class: "muted" }, "(started ", h("time", { "data-setup-since": String(at), datetime: run!.started_at }, ago(at)), ")")] : null,
          ),
          h("p", { class: "muted" }, "The broker may restart while this runs. This page keeps checking."),
        ];
      }
      case "waiting": {
        const until = Date.parse(run?.deadline ?? "");
        return [
          h(
            "p",
            { class: "setup-progress", role: "status", "aria-live": "polite" },
            h("strong", null, "Waiting for you: "),
            vt(run?.waiting_for || run?.step || "your next step below."),
          ),
          Number.isFinite(until) ? h("p", { class: "muted" }, "If nothing happens it gives up and puts everything back in ", h("time", { "data-setup-until": String(until), datetime: run!.deadline }, countdown(until)), ".") : null,
        ];
      }
      case "idle":
        return [h("p", { class: "muted" }, t.id === "upgrade" ? "No new release is waiting. New releases show up here by themselves." : "Nothing to do right now.")];
      default:
        return [];
    }
  }

  private lastPart(t: SetupTask, run: SetupRun | undefined): Child[] {
    if (!run) return [];
    const live = run.state === "running" || run.state === "waiting";
    const log = run.log ?? [];
    const result = Object.entries(run.result ?? {});
    const at = Date.parse(run.finished_at ?? "");
    const out: Child[] = [];
    if (!live && (run.message || run.state === "failed")) {
      out.push(
        h(
          "p",
          { class: run.state === "failed" ? "error" : "setup-message" },
          h("strong", null, run.state === "failed" ? "Last run failed: " : "Last run: "),
          vt(run.message || run.step || run.state),
          Number.isFinite(at) ? [" ", h("span", { class: "muted" }, "(", h("time", { "data-setup-since": String(at), datetime: run.finished_at }, ago(at)), ")")] : null,
        ),
      );
      if (run.state === "failed" && t.state === "failed") out.push(h("p", { class: "muted" }, "It is safe to run it again."));
    }
    if (result.length) {
      out.push(
        h(
          "details",
          { class: "setup-more", "data-keep": "result", open: !live && run.state === "done" && t.state !== "done" },
          h("summary", null, "Results"),
          h("dl", { class: "facts" }, result.map(([k, v]) => [h("dt", null, vt(k.replaceAll("_", " "))), h("dd", null, h("span", { class: "mono" }, vt(v)))])),
        ),
      );
    }
    if (log.length) {
      out.push(h("details", { class: "setup-more", "data-keep": "log" }, h("summary", null, live ? `Progress log (${log.length})` : `Log of the last run (${log.length})`), h("pre", { class: "cmd setup-log" }, log.map((l) => vt(l)).join("\n"))));
    }
    return out;
  }

  // ---- per-task forms ----

  private formKey(t: SetupTask, v: SetupView): unknown {
    const can = runnable(v, t);
    switch (t.id) {
      case "cutover":
        return [can, t.state, v.mode, v.mode === "cutover" ? this.migration : null, can ? this.preview : null, v.current?.state];
      case "seal":
        return [can, t.state, v.mode, v.mode === "seal-setup" ? this.seal : null, v.current?.state];
      case "enable-updates":
        return [can, t.state, v.deploy_key, v.update_sources];
      case "sync-passkeys":
        return [can, t.state, v.passkeys];
      case "upgrade":
        return [t.state, this.updates];
      default:
        return [can, t.state];
    }
  }

  private formPart(t: SetupTask, v: SetupView): Child[] {
    const can = runnable(v, t);
    const label = t.state === "available" ? "Run…" : "Run again…";
    // A finished task keeps its form out of the way, so the next thing to do stands out.
    const again = (form: Child[]): Child[] => (t.state === "done" && can && form.length ? [h("details", { class: "setup-more", "data-keep": "again" }, h("summary", null, "Change it or run it again"), form)] : form);
    switch (t.id) {
      case "cutover":
        return v.mode === "cutover" ? this.cutoverReview(t, v) : can ? this.cutoverForm(t, label) : [];
      case "seal":
        return v.mode === "seal-setup" ? this.sealChecklist(v) : can ? this.sealForm(t, label) : [];
      case "enable-updates":
        return again(this.updatesForm(t, v, can, label));
      case "sync-passkeys":
        return again(this.pinsForm(t, v, can, label));
      case "upgrade":
        return this.updates && ["available", "idle", "failed", "done"].includes(t.state) ? [updateCard(this.updates, (target) => this.hooks.openUpdate(target))] : [];
      default:
        // A task this page has no form for: it can still say so instead of guessing parameters.
        return can ? [h("p", { class: "muted" }, "This page is older than the broker and cannot start this task. Reload it.")] : [];
    }
  }

  /** Run… → what will be signed → Confirm with passkey. The passkey prompt starts inside the
   * second tap (Safari only allows it in a user gesture). */
  private runPanel(t: SetupTask, label: string, collect: () => Collected): HTMLElement {
    const box = h("div", { class: "setup-run" });
    const idle = (message = "") => {
      const err = h("p", { class: "error", role: "alert" }, message);
      const go = h("button", { type: "button", class: "btn approve setup-go" }, label);
      go.addEventListener("click", async () => {
        err.textContent = "";
        let c: Collected;
        try {
          c = collect();
        } catch (e) {
          if (!(e instanceof Invalid)) throw e;
          err.textContent = e.message;
          return;
        }
        go.disabled = true;
        go.textContent = "Preparing…";
        try {
          const p = await prepareSetupTask(this.api, this.view!, t.id, c.params, c.secrets);
          c.onPrepared?.();
          confirm(p, c);
        } catch (e) {
          err.textContent = vt(explain(e));
          go.disabled = false;
          go.textContent = label;
        }
      });
      replace(box, err, h("div", { class: "actions" }, go));
    };
    const confirm = (p: PreparedSetup, c: Collected) => {
      const back = h("button", { type: "button", class: "btn" }, "Back");
      const sign = h("button", { type: "button", class: "btn approve confirm" }, "Confirm with passkey");
      back.addEventListener("click", () => idle());
      sign.addEventListener("click", () => {
        if (Date.now() > p.validUntil) {
          idle("That took too long and the request expired. Start again.");
          return;
        }
        // completeSetupTask calls the passkey prompt synchronously from here.
        const done = completeSetupTask(this.api, this.auth, p);
        replace(box, h("p", { class: "spinner", role: "status" }, "Confirm on your device…"));
        done.then(
          () => {
            c.onSent?.();
            this.queued = { task: t.id, at: Date.now() };
            replace(box, h("p", { class: "spinner", role: "status" }, "Approved. Waiting for the runner to start…"));
            void this.refresh();
          },
          (e) => {
            const again = h("button", { type: "button", class: "btn" }, "Start again");
            again.addEventListener("click", () => idle());
            replace(
              box,
              h("p", { class: "error", role: "alert" }, vt(explain(e))),
              h("p", { class: "muted" }, nothingChanged(e) ? "Nothing was changed." : "It may or may not have gone through. The state above updates by itself."),
              h("div", { class: "actions" }, again),
            );
            void this.refresh();
          },
        );
      });
      replace(
        box,
        h("h4", null, "Check, then confirm"),
        c.summary,
        h("details", { class: "signed" }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(p.canonicalText))),
        h("p", { class: "muted" }, "Valid for ", h("time", { "data-setup-until": String(p.validUntil) }, countdown(p.validUntil))),
        h("div", { class: "actions" }, back, sign),
      );
      sign.focus();
    };
    idle();
    return box;
  }

  /** Cancel a waiting task: unsigned, it only ever returns to the state before the task. */
  private cancelControl(): HTMLElement {
    const box = h("div", { class: "setup-cancel" });
    const out = h("p", { class: "error", role: "alert" });
    const ask = () => {
      const b = h("button", { type: "button", class: "btn deny" }, "Cancel this task…");
      b.addEventListener("click", sure);
      replace(box, b, out);
    };
    const sure = () => {
      const yes = h("button", { type: "button", class: "btn deny confirm" }, "Yes, cancel and put everything back");
      const no = h("button", { type: "button", class: "btn" }, "Keep going");
      no.addEventListener("click", ask);
      yes.addEventListener("click", async () => {
        yes.disabled = true;
        try {
          await this.api.setupPost!("/cancel", {});
          replace(box, h("p", { class: "spinner", role: "status" }, "Cancelling… the runner is putting everything back."));
        } catch (e) {
          out.textContent = vt(explain(e));
          ask();
        }
        void this.refresh();
      });
      replace(box, h("p", null, "Cancel? Nothing has been changed for good yet; the broker goes back to how it was."), h("div", { class: "actions" }, no, yes), out);
    };
    ask();
    return box;
  }

  private cutoverForm(t: SetupTask, label: string): Child[] {
    const pv = this.preview;
    return [
      !pv
        ? h("p", { class: "muted", role: "status" }, "Building a preview of the plan…")
        : "error" in pv
          ? h("p", { class: "muted" }, "No preview of the plan is available (", vt(pv.error), "). You review the real plan before anything is activated.")
          : planDetails(pv.plan, pv.id, "Preview of the plan"),
      h("p", { class: "muted" }, "Run backs everything up and brings the broker back fenced, with agents refused. You then review the final plan here and activate it."),
      this.runPanel(t, label, () => ({
        params: {},
        summary: [h("p", { class: "headline pos" }, "Start the switch to organisations: stop the broker, back it up and bring it back fenced for your review."), h("p", null, "Nothing is changed for good until you activate the plan.")],
      })),
    ];
  }

  private cutoverReview(_t: SetupTask, v: SetupView): Child[] {
    const m = this.migration;
    if (!m) return [h("p", { class: "muted", role: "status" }, "Loading the plan for review…"), v.current?.state === "waiting" ? this.cancelControl() : null];
    const activate = h("button", { type: "button", class: "btn approve setup-go" }, "Review and activate…");
    activate.addEventListener("click", () => this.hooks.openMigration({ object: "migration", id: m.id, facts: { plan: m.plan, recovery_sha256: m.recovery_sha256 } }));
    return [
      h("p", null, "Fleet access is paused. Compare the recovery digest and review each admission, credential set and authority retirement before signing."),
      h("dl", { class: "facts" }, h("dt", null, "Recovery SHA-256"), h("dd", null, h("span", { class: "mono" }, vt(m.recovery_sha256)))),
      planDetails(m.plan, m.id, "The plan"),
      h("div", { class: "actions" }, activate),
      h("p", { class: "muted" }, "After you activate, the runner restarts the broker and this card turns to Done."),
      v.current?.state === "waiting" ? this.cancelControl() : null,
    ];
  }

  private sealForm(t: SetupTask, label: string): Child[] {
    // The secret half lives only in these variables and one <pre>, until the owner continues.
    let identity = "";
    let recipient = "";
    let mode: "choose" | "generated" | "kept" = "choose";
    const keyBox = h("div", { class: "setup-key" });
    const keyErr = h("p", { class: "error", role: "alert" });
    const paste = input("text", "age1…");
    const saved = input("checkbox");
    const purge = input("checkbox");
    purge.checked = true;
    const topic = input("text", "https://ntfy.example.com/aqmas-lock");
    const token = input("password");

    const choose = () => {
      identity = recipient = "";
      mode = "choose";
      saved.checked = false;
      const gen = h("button", { type: "button", class: "btn" }, "Generate a recovery key in this browser");
      gen.addEventListener("click", async () => {
        keyErr.textContent = "";
        gen.disabled = true;
        try {
          const k = await generateAgeIdentity();
          identity = k.identity;
          recipient = k.recipient;
          generated();
        } catch (e) {
          keyErr.textContent = vt((e as Error).message);
          gen.disabled = false;
        }
      });
      replace(keyBox, gen, field("Or paste the public key of one you made yourself", paste, ["Made with ", h("span", { class: "mono" }, "age-keygen"), ". Only the public half (age1…) goes here."]), keyErr);
    };
    const generated = () => {
      mode = "generated";
      const other = h("button", { type: "button", class: "btn small" }, "Use a key I made myself instead");
      other.addEventListener("click", choose);
      const dl = h("button", { type: "button", class: "btn small" }, "Download");
      dl.addEventListener("click", () => download("aqmas-recovery-key.txt", `# aqmas recovery key. Keep it secret and offline.\n# public key: ${recipient}\n${identity}\n`));
      replace(
        keyBox,
        h("p", { class: "warn" }, "Save this in your password manager now. It is the only way back if you lose every passkey. It is not sent anywhere."),
        h("pre", { class: "cmd setup-secret", "aria-label": "Recovery key (secret)" }, identity),
        h("div", { class: "actions" }, copyButton(() => identity), dl),
        check(saved, "I have saved it"),
        h("p", { class: "hint muted" }, "It is shown once: when you continue it is gone from this page. Public half, which is all the broker gets: ", h("span", { class: "mono" }, recipient)),
        other,
        keyErr,
      );
    };
    const kept = () => {
      identity = "";
      mode = "kept";
      const other = h("button", { type: "button", class: "btn small" }, "Use another key");
      other.addEventListener("click", choose);
      replace(keyBox, h("p", null, "Recovery key: saved by you. Public half: ", h("span", { class: "mono" }, recipient)), other, keyErr);
    };
    choose();

    const collect = (): Collected => {
      if (mode === "generated" && !saved.checked) throw new Invalid("Save the recovery key first, then tick “I have saved it”.");
      if (mode === "choose") {
        recipient = paste.value.trim();
        if (!recipient) throw new Invalid("Generate a recovery key, or paste the public key of your own.");
      }
      const problem = ageRecipientProblem(recipient);
      if (problem) throw new Invalid(problem);
      const url = topic.value.trim();
      const tok = token.value.trim();
      let secrets: Record<string, string> | undefined;
      if (url || tok) {
        if (!TOPIC_RE.test(url)) throw new Invalid("The lock alert needs the ntfy topic address, like https://ntfy.example.com/topic (lower-case host, no user name or query).");
        if (!TOKEN_RE.test(tok)) throw new Invalid("The lock alert needs the publish-only token for that topic.");
        secrets = { ntfy_topic_url: url, ntfy_token: tok };
      }
      const params = { recipient, purge_backups: purge.checked, lock_alert: !!secrets };
      return {
        params,
        secrets,
        summary: [
          h("p", { class: "headline pos" }, "Seal the store: back up, record the recovery key and start the supervised import."),
          h(
            "dl",
            { class: "facts" },
            h("dt", null, "Recovery public key"),
            h("dd", null, h("span", { class: "mono" }, recipient)),
            h("dt", null, "Older backups"),
            h("dd", null, params.purge_backups ? "deleted after activation (they hold the plaintext keys)" : "kept (they still hold the plaintext keys)"),
            h("dt", null, "Lock alert"),
            h("dd", null, secrets ? "set up; its address and token travel encrypted to the runner" : "not set up"),
          ),
          h("p", null, "Nothing is sealed for good until you activate in the next steps."),
        ],
        onPrepared: () => {
          if (mode === "generated") kept();
        },
        onSent: () => {
          topic.value = token.value = "";
        },
      };
    };

    return [
      h("h4", null, "1. Recovery key"),
      h("p", { class: "muted" }, "If every unlock passkey is ever lost, this key is the only way to get the sealed store back."),
      keyBox,
      h("h4", null, "2. Old backups"),
      check(purge, "Delete older on-box backups that still contain the plaintext keys (recommended)"),
      h(
        "details",
        { class: "setup-more" },
        h("summary", null, "3. Lock alert (optional, can be skipped)"),
        h("p", { class: "muted" }, "Sends you a notification whenever the broker is waiting locked, for example after a reboot. Use a dedicated ntfy topic."),
        field("ntfy topic address", topic),
        field("Publish-only token", token, "Sealed in this browser for the runner; the broker never sees it."),
      ),
      this.runPanel(t, label, collect),
    ];
  }

  /** seal-setup mode: wrap, test, prove the recovery key, activate. */
  private sealChecklist(v: SetupView): Child[] {
    const s = this.seal;
    const cancel = v.current?.state === "waiting" ? this.cancelControl() : null;
    if (!s) return [h("p", { class: "muted", role: "status" }, "Loading the import…"), cancel];
    if (s.mode === "activated") return [h("p", { class: "spinner", role: "status" }, "Activated. The broker restarts locked in a moment; unlock it with your passkey when it is back.")];
    if (s.mode !== "setup") return [];
    const choices = s.choices ?? [];
    const creating = choices.filter((c) => c.selection.registration_id?.endsWith("-create"));
    const testing = choices.filter((c) => c.selection.registration_id?.endsWith("-test"));
    const tested = !!s.manifest;
    const created = tested || testing.length > 0;
    const elsewhere = !tested && choices.length === 0;
    const drilled = !!s.drilled;
    const review = h("div", { class: "setup-run", role: "status" });

    const ceremony = (label: string, title: string, begin: () => Promise<{ detail: string; finish: (auth: Authenticator) => Promise<void> }>, open = false) => {
      const b = h("button", { type: "button", class: "btn approve" }, label);
      b.addEventListener("click", async () => {
        b.disabled = true;
        try {
          const c = await begin();
          const sign = h("button", { type: "button", class: "btn approve confirm" }, `${title} with passkey`);
          sign.addEventListener("click", () => {
            sign.disabled = true;
            // finish() starts the passkey prompt synchronously, inside this tap.
            c.finish(this.auth).then(
              () => replace(review, h("p", { class: "spinner" }, "Done. Checking…")),
              (e) => replace(review, h("p", { class: "error" }, vt(explain(e)))),
            ).finally(() => void this.refresh());
          });
          replace(review, h("h4", null, title), h("details", { class: "signed", open }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(c.detail))), h("div", { class: "actions" }, sign));
          sign.focus();
        } catch (e) {
          replace(review, h("p", { class: "error" }, vt(explain(e))));
        } finally {
          b.disabled = false;
        }
      });
      return b;
    };
    const wrap = (key: SealView["choices"][number], verb: string, title: string) =>
      ceremony(`${verb} with ${vt(key.name)}…`, title, async () => {
        const { p } = await beginChoice(this.api, key);
        return { detail: p.canonical, finish: async (auth) => void (await this.api.sealPost!("unlock/finish", await p.finish(auth))) };
      });
    const step = (done: boolean, now: boolean, title: string, ...body: Child[]) =>
      h("li", { class: `setup-step${done ? " done" : now ? " now" : ""}`, "data-done": String(done) }, h("p", null, h("strong", null, title), " ", h("span", { class: `badge setup-state state-${done ? "done" : now ? "waiting" : "blocked"}` }, done ? "Done" : now ? "Your turn" : "Later")), done ? null : body);

    const drillKey = input("password", "AGE-SECRET-KEY-1…");
    const drillOut = h("p", { class: "error", role: "alert" });
    const drillGo = h("button", { type: "button", class: "btn approve" }, "Check the recovery key");
    drillGo.addEventListener("click", async () => {
      // Read once and clear the field at once: the key leaves this page only as ciphertext.
      const identity = drillKey.value.trim();
      drillKey.value = "";
      drillOut.textContent = "";
      if (!IDENTITY_RE.test(identity)) {
        drillOut.textContent = "That is not a recovery key. Paste the secret half you saved: it starts with AGE-SECRET-KEY-1.";
        return;
      }
      drillGo.disabled = true;
      try {
        await sendDrill(this.api, s, identity);
      } catch (e) {
        drillOut.textContent = vt(explain(e));
      } finally {
        drillGo.disabled = false;
      }
      void this.refresh();
    });

    const activate = ceremony("Activate…", "Activate sealed installation", () => beginControl(this.api, s, "activate"), true);
    activate.disabled = !(tested && drilled);

    return [
      h("p", null, "Fleet access is paused while you finish these four steps. Nothing is sealed for good until the last one."),
      elsewhere ? h("p", { class: "warn" }, "The unlock wrap was started in another browser session. Continue there, or cancel and run the task again from here.") : null,
      h(
        "ol",
        { class: "setup-checklist" },
        step(created, creating.length > 0, "Create the unlock wrap", h("p", { class: "muted" }, "One tap: your passkey makes the key that unlocks the store."), h("div", { class: "actions" }, creating.map((k) => wrap(k, "Create", "Create unlock wrap")))),
        step(tested, testing.length > 0, "Test the wrap", h("p", { class: "muted" }, "One more tap proves the same passkey can open it again."), h("div", { class: "actions" }, testing.map((k) => wrap(k, "Test", "Test wrap independently")))),
        step(
          drilled,
          !drilled,
          "Prove the recovery key",
          field("Paste the recovery key you saved", drillKey, "It is encrypted in this browser for the import, used once to open the staged copy, and not kept."),
          h("div", { class: "actions" }, drillGo),
          drillOut,
        ),
        step(false, tested && drilled, "Activate", h("p", { class: "muted" }, tested && drilled ? "Review the manifest and sign. After this the plaintext key files are deleted and the broker restarts locked." : "Available once the wrap is tested and the recovery key is proven."), h("div", { class: "actions" }, activate)),
      ),
      review,
      cancel,
    ];
  }

  private updatesForm(t: SetupTask, v: SetupView, can: boolean, label: string): Child[] {
    const key = v.deploy_key ?? "";
    const deploy: Child[] = key
      ? [
          h("h4", null, "1. Let this machine read the repository"),
          h("p", null, "Add this as a ", h("strong", null, "read-only deploy key"), " on the forge repository (repository settings → deploy keys, without write access):"),
          h("div", { class: "setup-copy" }, h("pre", { class: "cmd", "data-deploy-key": "" }, vt(key)), copyButton(() => key)),
        ]
      : [];
    if (!can) return t.state === "blocked" || !key ? [] : [h("details", { class: "setup-more", "data-keep": "deploy" }, h("summary", null, "Deploy key"), deploy.slice(1))];

    const src = v.update_sources ?? {};
    const repo = input("text", REPO_HINT);
    const forgejo = input("text", FORGEJO_HINT);
    const github = input("text", GITHUB_HINT);
    repo.value = src["repo"] ?? "";
    forgejo.value = src["forgejo_api"] ?? "";
    github.value = src["github_api"] ?? "";
    const forgejoToken = input("password");
    const githubToken = input("password");
    let keys: HostKeys["keys"] = [];
    let keysFor = "";
    const hostBox = h("div", { class: "setup-hostkeys", role: "status" });
    const fetchBtn = h("button", { type: "button", class: "btn" }, "Fetch host key");
    const showKeys = () =>
      replace(
        hostBox,
        keys.length
          ? [
              h("p", null, "The forge answered with these host keys. Compare the fingerprints with the ones your forge publishes; they count only once you sign them."),
              h("ul", { class: "setup-fingerprints" }, keys.map((k) => h("li", null, h("span", { class: "muted" }, vt(k.line.split(" ")[1] ?? "")), " ", h("span", { class: "mono" }, vt(k.fingerprint))))),
            ]
          : [],
      );
    // The API addresses usually follow from the repository address: fill them in until the
    // owner types their own.
    let guessed = { forgejo: forgejo.value === "", github: github.value === "" };
    forgejo.addEventListener("input", () => (guessed.forgejo = false));
    github.addEventListener("input", () => (guessed.github = false));
    repo.addEventListener("input", () => {
      const m = REPO_RE.exec(repo.value.trim());
      if (m && guessed.forgejo) forgejo.value = `https://${m[1]}/api/v1/repos/${m[3]}`;
      if (m && guessed.github) github.value = `https://api.github.com/repos/${m[3]}`;
      if (repo.value.trim() !== keysFor && keys.length) {
        keys = [];
        showKeys();
      }
    });
    fetchBtn.addEventListener("click", async () => {
      const url = repo.value.trim();
      if (!REPO_RE.test(url)) {
        replace(hostBox, h("p", { class: "error" }, `Enter the repository address first, like ${REPO_HINT}`));
        return;
      }
      fetchBtn.disabled = true;
      replace(hostBox, h("p", { class: "spinner" }, "Asking the forge…"));
      try {
        const r = await this.api.setupPost!<HostKeys>("/host-key", { repo: url });
        // Fingerprints are computed here from the lines that will be signed, not taken from the reply.
        keys = await Promise.all(
          (r.keys ?? []).filter((k) => typeof k?.line === "string").map(async (k) => ({ line: k.line, fingerprint: await hostKeyFingerprint(k.line) })),
        );
        keysFor = url;
        if (!keys.length) throw new Error("The forge returned no usable host key.");
        showKeys();
      } catch (e) {
        keys = [];
        replace(hostBox, h("p", { class: "error" }, vt(explain(e))));
      } finally {
        fetchBtn.disabled = false;
      }
    });

    const collect = (): Collected => {
      const p = { repo: repo.value.trim(), forgejo_api: forgejo.value.trim(), github_api: github.value.trim() };
      if (!REPO_RE.test(p.repo)) throw new Invalid(`The repository address must look like ${REPO_HINT}`);
      if (!API_RE.test(p.forgejo_api) || !p.forgejo_api.includes("/api/v1/repos/")) throw new Invalid(`The Forgejo API address must look like ${FORGEJO_HINT}`);
      if (!API_RE.test(p.github_api)) throw new Invalid(`The GitHub API address must look like ${GITHUB_HINT}`);
      if (!keys.length || keysFor !== p.repo) throw new Invalid("Fetch the forge's host key first and compare its fingerprint.");
      const secrets: Record<string, string> = {};
      for (const [name, el, what] of [["forgejo_token", forgejoToken, "Forgejo"], ["github_token", githubToken, "GitHub"]] as const) {
        const val = el.value.trim();
        if (!val) continue;
        if (!TOKEN_RE.test(val)) throw new Invalid(`The ${what} token contains characters a token cannot have. Paste it again.`);
        secrets[name] = val;
      }
      const fingerprints = keys.map((k) => k.fingerprint);
      return {
        params: { ...p, known_hosts: keys.map((k) => k.line).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)), forgejo_token: "forgejo_token" in secrets, github_token: "github_token" in secrets },
        secrets: Object.keys(secrets).length ? secrets : undefined,
        summary: [
          h("p", { class: "headline pos" }, "Enable self-update: install the build tools, trust the forge and store the release tokens."),
          h(
            "dl",
            { class: "facts" },
            h("dt", null, "Repository"),
            h("dd", null, h("span", { class: "mono" }, vt(p.repo))),
            h("dt", null, "Forgejo releases"),
            h("dd", null, h("span", { class: "mono" }, vt(p.forgejo_api))),
            h("dt", null, "GitHub releases"),
            h("dd", null, h("span", { class: "mono" }, vt(p.github_api))),
            h("dt", null, "Forge host keys"),
            h("dd", null, fingerprints.map((f) => h("span", { class: "mono block" }, vt(f)))),
            h("dt", null, "Tokens"),
            h("dd", null, Object.keys(secrets).length ? `${Object.keys(secrets).map((k) => (k === "forgejo_token" ? "Forgejo" : "GitHub")).join(" and ")}, encrypted to the runner` : "none"),
          ),
        ],
        onSent: () => {
          forgejoToken.value = githubToken.value = "";
        },
      };
    };

    return [
      deploy,
      h("h4", null, key ? "2. Where releases come from" : "Where releases come from"),
      field("Repository (SSH address)", repo, "The forge repository this machine rebuilds releases from."),
      field("Forgejo API address", forgejo),
      field("GitHub API address", github, "The mirror: a release is only offered when both publish the same hashes."),
      h("div", { class: "actions" }, fetchBtn),
      hostBox,
      h("h4", null, key ? "3. Release tokens (only for private repositories)" : "Release tokens (only for private repositories)"),
      field("Forgejo read token (optional)", forgejoToken),
      field("GitHub read-only token (optional)", githubToken, "Tokens are sealed in this browser for the runner. The broker and the tunnel only see ciphertext."),
      this.runPanel(t, label, collect),
    ];
  }

  private pinsForm(t: SetupTask, v: SetupView, can: boolean, label: string): Child[] {
    const keys = v.passkeys ?? [];
    if (!keys.length) return [];
    const boxes = keys.map((k) => {
      const el = input("checkbox");
      el.checked = true;
      el.disabled = !can;
      el.dataset["credential"] = k.credential;
      return el;
    });
    const list = h(
      "ul",
      { class: "setup-passkeys" },
      keys.map((k, i) =>
        h(
          "li",
          null,
          can ? check(boxes[i]!, h("bdi", null, vt(k.name))) : h("bdi", null, vt(k.name)),
          " ",
          h("span", { class: `badge setup-state state-${k.pinned ? "done" : "blocked"}` }, k.pinned ? "Pinned" : "Not pinned"),
          k.current ? [" ", h("span", { class: "badge this" }, "This session")] : null,
        ),
      ),
    );
    if (!can) return [list];
    const collect = (): Collected => {
      const chosen = keys.filter((_, i) => boxes[i]!.checked);
      if (!chosen.length) throw new Invalid("Tick at least one passkey: with none pinned, nothing on this page could be approved.");
      return {
        params: { pins: chosen.map((k) => ({ id: k.credential, key_sha256: k.key_sha256 })) },
        summary: [
          h("p", { class: "headline pos" }, "Replace the pinned maintenance passkeys with: ", chosen.map((k, i) => [i ? ", " : "", h("bdi", { class: "val" }, vt(k.name))]), "."),
          // Spell out every change, by identifier and key digest: a name alone can be imitated.
          ...chosen
            .filter((k) => !k.pinned)
            .map((k) => h("p", { class: "warn" }, "Adding: ", h("bdi", { class: "val" }, vt(k.name)), " (credential ", h("span", { class: "mono" }, vt(k.credential.slice(0, 16)) + "…"), ", key ", h("span", { class: "mono" }, vt(k.key_sha256.slice(0, 16)) + "…"), "). Only add a passkey you registered yourself.")),
          ...keys
            .filter((k, i) => k.pinned && !boxes[i]!.checked)
            .map((k) => h("p", { class: "warn" }, "Removing: ", h("bdi", { class: "val" }, vt(k.name)), ". It can no longer approve setup tasks or upgrades.")),
        ],
      };
    };
    return [
      h("p", { class: "muted" }, "Ticked passkeys may approve the tasks on this page. This must be signed with a passkey that is already pinned."),
      list,
      this.runPanel(t, label, collect),
    ];
  }
}

/** One line for the Admin page: what Setup wants next. */
export function setupSummary(v: SetupView | null | undefined): string {
  if (!v) return "Setup steps and upgrades.";
  const tasks = v.tasks ?? [];
  const busy = tasks.find((t) => t.state === "waiting") ?? tasks.find((t) => t.state === "running");
  if (busy) return busy.state === "waiting" ? `“${vt(busy.title)}” is waiting for you.` : `“${vt(busy.title)}” is running.`;
  if (!v.runner_installed) return "The maintenance runner is not installed yet.";
  const next = tasks.find((t) => t.state === "failed") ?? tasks.find((t) => t.state === "available");
  if (next) return next.state === "failed" ? `“${vt(next.title)}” failed and can be run again.` : next.id === "upgrade" ? "An upgrade is ready to review." : `Next: ${vt(next.title)}.`;
  return "Everything is set up. Upgrades show up here.";
}
