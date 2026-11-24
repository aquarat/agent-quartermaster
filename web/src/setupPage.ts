// Settings → Setup (docs/SETUP.md): the task queue. Each task is a card with its fixed
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
import { beginControl, type SealView, type StageChoice } from "./sealPanel";
import {
  ageRecipientProblem,
  completeSetupTask,
  generateAgeIdentity,
  hostKeyFingerprint,
  prepareSetupTask,
  sendDrill,
  stagePlan,
  stageStep,
  staging,
  type HostKeys,
  type StageStep,
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
  /** Which task groups this page shows (maint.Spec.Group). Default [""]: the Setup queue;
   * Settings → Bastion access shows ["bastion", "routine"]. */
  groups?: string[];
  /** false: a second task list on a page whose Setup queue already shows the runner's
   * notices (not installed, unpinned passkey, refused request). */
  notices?: boolean;
  /** Forms for tasks this class has none for (the bastion and routine tasks). `run` builds
   * the usual Run… → check → Confirm with passkey panel. Return undefined for "no form". */
  form?(t: SetupTask, v: SetupView, can: boolean, label: string, run: (label: string, collect: () => Collected) => HTMLElement): Child[] | undefined;
  /** What that form depends on besides the task's state (re-rendered when it changes). */
  formKey?(t: SetupTask, v: SetupView): unknown;
  /** Called (and awaited) after every successful load of the setup view, before rendering. */
  loaded?(v: SetupView): void | Promise<void>;
}

/** How often the page asks for the setup state: while a task is in progress, and otherwise. */
export const SETUP_POLL = { active: 2000, idle: 5000 };

interface Migration {
  id: string;
  plan: string;
  recovery_sha256: string;
}

export interface Collected {
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
export class Invalid extends Error {}

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
const REPO_RE = /^(ssh:\/\/[a-z_][a-z0-9_-]{0,31}@|https:\/\/|http:\/\/(?=127\.0\.0\.1:))([a-z0-9][a-z0-9.-]{0,252})(:[0-9]{1,5})?\/([A-Za-z0-9][A-Za-z0-9._/-]{0,200})\.git$/;
const API_RE = /^https?:\/\/[A-Za-z0-9.:-]{1,255}\/[A-Za-z0-9._/-]{1,200}$/;
const TOKEN_RE = /^[A-Za-z0-9_.~+/=:-]{8,512}$/;
const TOPIC_RE = /^https:\/\/[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?\/[A-Za-z0-9_-]{1,128}$/;
const IDENTITY_RE = /^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}$/;

const REPO_HINT = "https://github.com/owner/agent-quartermaster.git";
const SSH_REPO_HINT = "ssh://git@forge.example.com/owner/agent-quartermaster.git";
const SECOND_HINT = "https://forge.example.com/api/v1/repos/owner/agent-quartermaster";
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
    const groups = this.hooks.groups ?? [""];
    const tasks = (v.tasks ?? []).filter((t) => groups.includes(t.group ?? ""));
    const quiet = <T>(p: Promise<T> | undefined): Promise<T | undefined> => (p ? p.catch(() => undefined) : Promise.resolve(undefined));
    const cutover = tasks.find((t) => t.id === "cutover");
    const wantPreview = v.mode === "serve" && !!cutover && (cutover.state === "available" || cutover.state === "failed");
    if (!wantPreview) this.preview = null;
    const upgrade = tasks.find((t) => t.id === "upgrade");
    const [migration, seal, updates, preview] = await Promise.all([
      v.mode === "cutover" ? quiet(this.api.migration?.()) : undefined,
      staging(v.mode) ? quiet(this.api.sealStatus?.()) : undefined,
      upgrade && upgrade.state !== "blocked" ? quiet(this.api.updates()) : undefined,
      wantPreview && !this.preview
        ? this.api.setupGet!<{ id: string; plan: string }>("/cutover/preview").catch((e) => (e instanceof ApiError && e.status >= 400 && e.status < 500 ? { error: explain(e) } : undefined))
        : undefined,
    ]);
    if (this.stopped) return;
    // A helper call that failed (the broker went away mid-poll) keeps what was shown before.
    if (v.mode !== "cutover") this.migration = null;
    else if (migration) this.migration = migration;
    if (!staging(v.mode)) this.seal = null;
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
    await this.hooks.loaded?.(this.view);
    if (this.stopped) return;
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
    if (this.hooks.notices === false) return;
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
      t.warning ? h("p", { class: "warn setup-warning" }, vt(t.warning)) : null,
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
      case "buckets":
        return [can, t.state, v.mode, this.stagedHere(t, v) ? this.seal : null, v.current?.state];
      case "enable-updates":
        return [can, t.state, v.deploy_key, v.update_sources];
      case "sync-passkeys":
        return [can, t.state, v.passkeys];
      case "upgrade":
        return [t.state, this.updates];
      default:
        return [can, t.state, this.hooks.formKey?.(t, v)];
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
        return this.stagedHere(t, v) ? this.stageChecklist(v) : can ? this.sealForm(t, label) : [];
      case "buckets":
        return this.stagedHere(t, v) ? this.stageChecklist(v) : can ? this.bucketsForm(t, label) : [];
      case "enable-updates":
        return again(this.updatesForm(t, v, can, label));
      case "sync-passkeys":
        return again(this.pinsForm(t, v, can, label));
      case "upgrade":
        return this.updates && ["available", "idle", "failed", "done"].includes(t.state) ? [updateCard(this.updates, (target) => this.hooks.openUpdate(target))] : [];
      default: {
        const custom = this.hooks.form?.(t, v, can, label, (l, collect) => this.runPanel(t, l, collect));
        if (custom) return custom;
      }
      // A task this page has no form for: it can still say so instead of guessing parameters.
      // eslint-disable-next-line no-fallthrough
      case "":
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
        if (!TOPIC_RE.test(url)) throw new Invalid("The restart alert needs the ntfy topic address, like https://ntfy.example.com/topic (lower-case host, no user name or query).");
        if (!TOKEN_RE.test(tok)) throw new Invalid("The restart alert needs the publish-only token for that topic.");
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
            h("dt", null, "Restart alert"),
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
      h("p", { class: "muted" }, "If every passkey that can open the store is ever lost, this key is the only way to get the sealed store back."),
      keyBox,
      h("h4", null, "2. Old backups"),
      check(purge, "Delete older on-box backups that still contain the plaintext keys (recommended)"),
      h(
        "details",
        { class: "setup-more" },
        h("summary", null, "3. Restart alert (optional, can be skipped)"),
        h("p", { class: "muted" }, "Sends you a notification whenever the broker restarts (for example after a reboot) and grants wait for you to reopen them. Use a dedicated ntfy topic."),
        field("ntfy topic address", topic),
        field("Publish-only token", token, "Sealed in this browser for the runner; the broker never sees it."),
      ),
      this.runPanel(t, label, collect),
    ];
  }

  /** Whether this card shows the staged store: the staging belongs to the task that runs. */
  private stagedHere(t: SetupTask, v: SetupView): boolean {
    if (!staging(v.mode)) return false;
    const owner = v.current?.task ?? (v.mode === "bucket-migrate" ? "buckets" : "seal");
    return owner === t.id;
  }

  /** "Move to per-credential buckets": one-way, so the card says so before Run. */
  private bucketsForm(t: SetupTask, label: string): Child[] {
    const purge = input("checkbox");
    purge.checked = true;
    const oneWay = [
      h("p", { class: "warn" }, h("strong", null, "One-way. "), "There is no rollback: after you activate, this version of aqmas cannot go back to the single store key, and the backup taken before the move is the only way back (with the previous version)."),
      h("p", { class: "muted" }, "Your other passkeys that could open the old store become approve-only until you enable them for buckets in Security → Passkeys."),
    ];
    return [
      ...oneWay,
      check(purge, "Delete the pre-migration and older on-box backups after activation (recommended)"),
      h("p", { class: "hint muted" }, "They still hold the old single-key store, which anyone with a copy and one tap from your old passkey salts could open."),
      this.runPanel(t, label, () => ({
        params: { purge_backups: purge.checked },
        summary: [
          h("p", { class: "headline pos" }, "Move to per-credential buckets: back up, stop the broker and stage every credential in its own bucket for your taps."),
          ...oneWay,
          h("dl", { class: "facts" }, h("dt", null, "Older backups"), h("dd", null, purge.checked ? "deleted after activation (they hold the old store)" : "kept (they still hold the old store)")),
          h("p", null, "Nothing changes for good until you activate in the next steps; cancelling before then restores everything."),
        ],
      })),
    ];
  }

  /** Mode setup (seal import or bucket migration): open the old store (migration), create
   * and test this passkey's scope keys, prove the recovery key, activate. */
  private stageChecklist(v: SetupView): Child[] {
    const s = this.seal;
    const cancel = v.current?.state === "waiting" ? this.cancelControl() : null;
    if (!s) return [h("p", { class: "muted", role: "status" }, "Loading the staged store…"), cancel];
    if (s.mode === "activated") return [h("p", { class: "spinner", role: "status" }, "Activated. The broker restarts in a moment with nothing open: each credential opens with the approval that needs it.")];
    if (s.mode !== "setup" || !s.stage) return [];
    const st = s.stage;
    const plan = stagePlan(st);
    const drilled = !!st.drilled;
    const ready = !!st.manifest;
    const review = h("div", { class: "setup-run", role: "status" });
    const titleOf = (scope: string) => st.scopes.find((x) => x.scope === scope)?.title || scope;

    const ceremony = (label: string, title: string, begin: () => Promise<{ detail: string; lines?: string[]; finish: (auth: Authenticator) => Promise<void> }>, open = false) => {
      const b = h("button", { type: "button", class: "btn approve" }, label);
      b.addEventListener("click", async () => {
        b.disabled = true;
        try {
          const c = await begin();
          const sign = h("button", { type: "button", class: "btn approve confirm" }, `${title} with passkey`);
          sign.addEventListener("click", () => {
            sign.disabled = true;
            // finish() starts the passkey prompt synchronously, inside this tap.
            c.finish(this.auth)
              .then(
                () => replace(review, h("p", { class: "spinner" }, "Done. Checking…")),
                (e) => replace(review, h("p", { class: "error" }, vt(explain(e)))),
              )
              .finally(() => void this.refresh());
          });
          replace(
            review,
            h("h4", null, title),
            c.lines?.length ? h("ul", { class: "open-lines" }, c.lines.map((l) => h("li", null, vt(l)))) : null,
            h("details", { class: "signed", open }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(c.detail))),
            h("div", { class: "actions" }, sign),
          );
          sign.focus();
        } catch (e) {
          replace(review, h("p", { class: "error" }, vt(explain(e))));
        } finally {
          b.disabled = false;
        }
      });
      return b;
    };
    const tapFor = (step: StageStep, scopes: string[], verb: string, title: string) => (choice: StageChoice) =>
      ceremony(`${verb} with ${vt(choice.name)}…`, title, async () => {
        const p = await stageStep(this.api, s, step, choice, scopes, location.hostname);
        return { detail: p.canonical, lines: p.lines, finish: (auth) => p.finish(auth) };
      });
    const step = (done: boolean, now: boolean, title: string, ...body: Child[]) =>
      h("li", { class: `setup-step${done ? " done" : now ? " now" : ""}`, "data-done": String(done) }, h("p", null, h("strong", null, title), " ", h("span", { class: `badge setup-state state-${done ? "done" : now ? "waiting" : "blocked"}` }, done ? "Done" : now ? "Your turn" : "Later")), done ? null : body);
    const guide = (step: StageStep) => {
      const n = plan.next;
      if (!n || n.step !== step) return null;
      return h("p", { class: "setup-tap" }, `Tap ${plan.tap} of ${plan.taps}: `, n.scopes.map(titleOf).join(" and "));
    };
    const choices = (step: StageStep) => {
      const n = plan.next;
      if (!n || n.step !== step) return null;
      const list = step === "open-legacy" ? st.choices.filter((c) => !!c.legacy) : st.choices;
      if (!list.length) return h("p", { class: "warn" }, "No passkey here can do this step. It may have been started in another browser session: continue there, or cancel and run the task again.");
      const verb = step === "open-legacy" ? "Open" : step === "create" ? "Create" : "Test";
      const title = step === "open-legacy" ? "Open the old store and create the first key" : step === "create" ? "Create this passkey's keys" : "Test this passkey's keys";
      return h("div", { class: "actions" }, list.map(tapFor(step, n.scopes, verb, title)));
    };

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
        await sendDrill(this.api, { drill_key: st.drill_key, installation: s.installation }, identity);
      } catch (e) {
        drillOut.textContent = vt(explain(e));
      } finally {
        drillGo.disabled = false;
      }
      void this.refresh();
    });

    const activate = ceremony("Activate…", "Activate the bucket store", () => beginControl(this.api, s, "activate"), true);
    activate.disabled = !ready;
    const scopeList = h(
      "ul",
      { class: "setup-scopes" },
      st.scopes.map((x) => h("li", { "data-scope": x.scope }, vt(x.title || x.scope), ` · ${x.buckets} bucket${x.buckets === 1 ? "" : "s"} · `, x.tested ? "tested" : x.wrapped ? "created, not tested" : "not created")),
    );
    const items: HTMLElement[] = [];
    if (plan.migrate)
      items.push(
        step(plan.legacyDone, plan.next?.step === "open-legacy", "Open the old store", h("p", { class: "muted" }, "One tap with a passkey that opened the old store: it opens the old key once, moves every credential into its bucket in memory and creates your first scope key."), guide("open-legacy"), choices("open-legacy")),
      );
    items.push(
      step(plan.created, plan.next?.step === "create", "Create your passkey's keys", h("p", { class: "muted" }, "Each tap creates this passkey's key for up to two scopes."), scopeList, guide("create"), choices("create")),
      step(plan.tested, plan.next?.step === "test", "Test them", h("p", { class: "muted" }, "Each tap proves the same passkey opens up to two scope keys again."), guide("test"), choices("test")),
      step(drilled, !drilled, "Prove the recovery key", field("Paste the recovery key you saved", drillKey, "It is encrypted in this browser for the broker, used once to open every staged scope key, and not kept."), h("div", { class: "actions" }, drillGo), drillOut),
      step(false, ready, "Activate", h("p", { class: "muted" }, ready ? "Review the manifest and sign. After this the broker restarts with nothing open; each approval opens only the bucket it needs." : "Available once every scope key is created and tested and the recovery key is proven."), h("div", { class: "actions" }, activate)),
    );
    return [
      h("p", null, "Fleet access is paused while you finish these steps. Nothing changes for good until you activate."),
      plan.migrate ? h("p", { class: "warn" }, "One-way: after you activate there is no rollback; the pre-migration backup is the only way back. Your other old passkeys become approve-only until enabled.") : null,
      h("ol", { class: "setup-checklist" }, items),
      review,
      cancel,
    ];
  }

  private updatesForm(t: SetupTask, v: SetupView, can: boolean, label: string): Child[] {
    // Where releases come from is fixed at the machine; this page shows it and signs it.
    const src = v.update_sources;
    const repoUrl = src?.repo ?? "";
    const ssh = repoUrl.startsWith("ssh://");
    const second = src?.second_api ?? "";
    const compared = src?.compared?.length ? src.compared : ["GitHub"];
    // The deploy key matters only for an SSH repository.
    const key = ssh ? (v.deploy_key ?? "") : "";
    const deploy: Child[] = key
      ? [
          h("h4", null, "Let this machine read the repository"),
          h("p", null, "Add this as a ", h("strong", null, "read-only deploy key"), " on the forge repository (repository settings → deploy keys, without write access):"),
          h("div", { class: "setup-copy" }, h("pre", { class: "cmd", "data-deploy-key": "" }, vt(key)), copyButton(() => key)),
        ]
      : [];
    const sources: Child[] = src
      ? [
          h("h4", null, "Where releases come from"),
          h(
            "p",
            { "data-sources": String(compared.length) },
            second
              ? `Two published sources are compared: ${compared.join(" and ")}. A release is offered only when both publish the same hashes, and installed only when this machine's own rebuild matches them. If the second source cannot be reached, the update waits.`
              : "One published source is compared: GitHub. A release is installed only when this machine's own rebuild from source matches the hashes GitHub publishes. No second source is configured.",
          ),
          h(
            "dl",
            { class: "facts" },
            h("dt", null, "Repository"),
            h("dd", null, h("span", { class: "mono" }, vt(repoUrl))),
            h("dt", null, "GitHub releases"),
            h("dd", null, h("span", { class: "mono" }, vt(src.github_api))),
            h("dt", null, "Second source"),
            h("dd", null, second ? h("span", { class: "mono" }, vt(second)) : "none"),
          ),
          src.note ? h("p", { class: "muted", "data-sources-note": "" }, vt(src.note)) : null,
          h(
            "p",
            { class: "muted" },
            src.origin === "pinned"
              ? "Fixed on the machine with “aqmasd maint-init --repo …”. This page cannot change them."
              : src.origin === "config"
                ? "Taken from the [updates] table of the machine's configuration. This page cannot change them."
                : "Nothing is configured, so these are the built-in defaults. A second source or another repository is set in the [updates] table of the machine's configuration, never from this page.",
          ),
        ]
      : [];
    if (!can) return t.state === "blocked" || !sources.length ? [] : [h("details", { class: "setup-more", "data-keep": "sources" }, h("summary", null, "Release sources"), sources.slice(1), deploy.slice(1))];

    const githubToken = input("password");
    const secondToken = input("password");
    let keys: HostKeys["keys"] = [];
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
    fetchBtn.addEventListener("click", async () => {
      fetchBtn.disabled = true;
      replace(hostBox, h("p", { class: "spinner" }, "Asking the forge…"));
      try {
        const r = await this.api.setupPost!<HostKeys>("/host-key", { repo: repoUrl });
        // Fingerprints are computed here from the lines that will be signed, not taken from the reply.
        keys = await Promise.all(
          (r.keys ?? []).filter((k) => typeof k?.line === "string").map(async (k) => ({ line: k.line, fingerprint: await hostKeyFingerprint(k.line) })),
        );
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
      if (!src) throw new Invalid("The release sources are not known yet. Reload the page.");
      const p = { repo: repoUrl, github_api: src.github_api, second_api: second };
      if (!REPO_RE.test(p.repo)) throw new Invalid(`The repository address must look like ${REPO_HINT} or ${SSH_REPO_HINT}. It is set on the machine.`);
      if (!API_RE.test(p.github_api)) throw new Invalid(`The GitHub API address must look like ${GITHUB_HINT}. It is set on the machine.`);
      if (second && (!API_RE.test(second) || !second.includes("/api/v1/repos/"))) throw new Invalid(`The second source's API address must look like ${SECOND_HINT}. It is set on the machine.`);
      if (ssh && !keys.length) throw new Invalid("Fetch the forge's host key first and compare its fingerprint.");
      const secrets: Record<string, string> = {};
      for (const [name, el, what] of [["github_token", githubToken, "GitHub"], ["second_token", secondToken, "second-source"]] as const) {
        const val = el.value.trim();
        if (!val || (name === "second_token" && !second)) continue;
        if (!TOKEN_RE.test(val)) throw new Invalid(`The ${what} token contains characters a token cannot have. Paste it again.`);
        secrets[name] = val;
      }
      const fingerprints = keys.map((k) => k.fingerprint);
      const named = Object.keys(secrets).map((k) => (k === "github_token" ? "GitHub" : "second source"));
      return {
        params: {
          ...p,
          known_hosts: ssh ? keys.map((k) => k.line).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)) : [],
          github_token: "github_token" in secrets,
          second_token: "second_token" in secrets,
        },
        secrets: Object.keys(secrets).length ? secrets : undefined,
        summary: [
          h("p", { class: "headline pos" }, second ? `Enable self-update from 2 sources: ${compared.join(" and ")}.` : "Enable self-update from 1 source: GitHub."),
          h(
            "dl",
            { class: "facts" },
            h("dt", null, "Repository"),
            h("dd", null, h("span", { class: "mono" }, vt(p.repo))),
            h("dt", null, "GitHub releases"),
            h("dd", null, h("span", { class: "mono" }, vt(p.github_api))),
            h("dt", null, "Second source"),
            h("dd", null, second ? h("span", { class: "mono" }, vt(second)) : "none: GitHub and this machine's own rebuild"),
            ssh ? [h("dt", null, "Forge host keys"), h("dd", null, fingerprints.map((f) => h("span", { class: "mono block" }, vt(f))))] : null,
            h("dt", null, "Tokens"),
            h("dd", null, named.length ? `${named.join(" and ")}, encrypted to the runner` : "none"),
          ),
        ],
        onSent: () => {
          githubToken.value = secondToken.value = "";
        },
      };
    };

    return [
      sources,
      deploy,
      ssh ? [h("h4", null, "The forge's host key"), h("div", { class: "actions" }, fetchBtn), hostBox] : null,
      h("h4", null, "Release tokens (only for private repositories)"),
      field("GitHub read-only token (optional)", githubToken, second ? undefined : "Leave empty for a public repository. A token is sealed in this browser for the runner; the broker and the tunnel only see ciphertext."),
      second ? field("Second-source read token (optional)", secondToken, "Tokens are sealed in this browser for the runner. The broker and the tunnel only see ciphertext.") : null,
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
  // Bastion access and routine maintenance have their own section.
  const tasks = (v.tasks ?? []).filter((t) => !t.group);
  const busy = tasks.find((t) => t.state === "waiting") ?? tasks.find((t) => t.state === "running");
  if (busy) return busy.state === "waiting" ? `“${vt(busy.title)}” is waiting for you.` : `“${vt(busy.title)}” is running.`;
  if (!v.runner_installed) return "The maintenance runner is not installed yet.";
  const next = tasks.find((t) => t.state === "failed") ?? tasks.find((t) => t.state === "available");
  if (next) return next.state === "failed" ? `“${vt(next.title)}” failed and can be run again.` : next.id === "upgrade" ? "An upgrade is ready to review." : `Next: ${vt(next.title)}.`;
  return "Everything is set up. Upgrades show up here.";
}
