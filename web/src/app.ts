// The approval UI. Rendering only; the security-relevant logic lives in flows.ts,
// canonical.ts and webauthn.ts.
//
// Untrusted text (reason, requester fields, and for safety every server string) is shown
// through text nodes only, with invisible/bidi characters made visible (visibleText).

import { ApiError, createApi, type Api } from "./api";
import { $, h, replace, type Child } from "./dom";
import {
  FlowError,
  LOGIN_OPTIONS_MAX_AGE_MS,
  PASSKEY_TARGET,
  authorizeAddPasskey,
  completeAction,
  completeLogin,
  completeRegistration,
  explainError,
  prepareAction,
  prepareLogin,
  prepareRegistrationWithCode,
  targetForGrant,
  targetForPending,
  targetForStanding,
  type ActionChoice,
  type ActionTarget,
  type PreparedAction,
  type PreparedLogin,
  type PreparedRegistration,
} from "./flows";
import { STANDING_PRESETS, ago, countdown, duration, hours, kindLabel, ttlChoices, visibleText as vt } from "./format";
import type { AuditEntry, GrantSummary, PendingItem, StandingApproval, UIState } from "./types";
import { browserAuthenticator, type Authenticator } from "./webauthn";

const POLL_MS = 5000;

export class App {
  readonly api: Api;
  readonly auth: Authenticator;
  private root: HTMLElement;
  private state: UIState | null = null;
  private lastOk = 0;
  private offline = false;
  private view: "loading" | "signin" | "main" = "loading";
  private pollTimer: number | undefined;
  private tickTimer: number | undefined;
  private refreshing = false;
  private rendered = new Map<string, string>();
  private login: PreparedLogin | null = null;
  private sheet: Sheet;
  private focusId: string | null = null;

  constructor(root: HTMLElement, api: Api = createApi(), auth: Authenticator = browserAuthenticator()) {
    this.root = root;
    this.api = api;
    this.auth = auth;
    this.sheet = new Sheet(this);
    const m = /^#r=([A-Za-z0-9_-]{1,64})$/.exec(location.hash);
    this.focusId = m ? m[1]! : null;
  }

  start(): void {
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible" && this.view === "main") void this.refresh();
    });
    this.tickTimer = window.setInterval(() => this.tick(), 1000);
    void this.refresh();
  }

  // ---- data ----

  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    try {
      const s = await this.api.state();
      this.state = normalise(s);
      this.lastOk = Date.now();
      this.offline = false;
      if (this.view !== "main") this.showMain();
      else this.renderSections();
    } catch (e) {
      if (e instanceof ApiError && e.code === "unauthenticated") {
        this.sheet.close();
        this.showSignin();
      } else if (this.view === "main") {
        this.offline = true;
        this.updateStatus(e);
      } else {
        this.showFatal(e);
      }
    } finally {
      this.refreshing = false;
    }
  }

  private schedulePoll(): void {
    if (this.pollTimer !== undefined) return;
    this.pollTimer = window.setInterval(() => {
      if (document.visibilityState === "visible" && this.view === "main") void this.refresh();
    }, POLL_MS);
  }

  /** Called by the sheet after an action is applied. */
  changed(): void {
    void this.refresh();
  }

  pendingIds(): Set<string> {
    return new Set((this.state?.pending ?? []).map((p) => p.id));
  }

  // ---- views ----

  private showFatal(e: unknown): void {
    this.view = "loading";
    replace(
      this.root,
      h(
        "main",
        { class: "signin" },
        h("h1", { class: "brand" }, "aqmas"),
        h("p", { class: "error", role: "alert" }, vt(explainError(e))),
        h("button", { class: "btn primary big", type: "button", on: { click: () => void this.refresh() } }, "Try again"),
      ),
    );
  }

  private showSignin(message?: string): void {
    this.view = "signin";
    this.state = null;
    this.rendered.clear();
    document.title = "aqmas";
    const status = h("p", { class: "error", role: "alert", "aria-live": "assertive" }, message ? vt(message) : "");
    const signBtn = h("button", { class: "btn primary big", type: "button" }, "Sign in with passkey");
    const regDetails = h("details", { class: "first-run" });
    const regBody = h("div", { class: "first-run-body" });
    replace(
      this.root,
      h(
        "main",
        { class: "signin" },
        h("h1", { class: "brand" }, "aqmas"),
        h("p", { class: "lede" }, "Approve and refuse access requests from your fleet."),
        signBtn,
        status,
        regDetails,
      ),
    );
    append(regDetails, h("summary", null, "First time on this device?"), regBody);
    this.renderRegisterStart(regBody, status);

    const prefetch = () => {
      prepareLogin(this.api)
        .then((p) => (this.login = p))
        .catch((e) => {
          this.login = null;
          if (e instanceof ApiError && e.code === "conflict") {
            regDetails.open = true;
            status.textContent = "No passkey is registered yet. Register this device with the enroll code.";
          }
        });
    };
    prefetch();

    signBtn.addEventListener("click", async () => {
      status.textContent = "";
      signBtn.disabled = true;
      let p = this.login;
      this.login = null;
      try {
        if (!p || Date.now() - p.fetchedAt > LOGIN_OPTIONS_MAX_AGE_MS) p = await prepareLogin(this.api);
        await completeLogin(this.api, this.auth, p);
        await this.refresh();
      } catch (e) {
        status.textContent = vt(explainError(e));
        prefetch();
      } finally {
        signBtn.disabled = false;
      }
    });
  }

  private renderRegisterStart(body: HTMLElement, status: HTMLElement): void {
    const input = h("input", {
      id: "enroll-code",
      type: "text",
      autocomplete: "one-time-code",
      inputmode: "text",
      spellcheck: "false",
      enterkeyhint: "go",
    });
    const go = h("button", { class: "btn", type: "button" }, "Continue");
    replace(
      body,
      h("p", null, "Register this device's passkey with a one-time code. On the bastion (bastion), as root or the aqmas user, run:"),
      h("pre", { class: "cmd" }, "aqmasd passkey-enroll-code"),
      h("label", { for: "enroll-code" }, "Enroll code"),
      input,
      go,
    );
    const submit = async () => {
      status.textContent = "";
      go.disabled = true;
      try {
        const reg = await prepareRegistrationWithCode(this.api, input.value);
        this.renderRegisterCreate(body, status, reg);
      } catch (e) {
        status.textContent = vt(explainError(e));
      } finally {
        go.disabled = false;
      }
    };
    go.addEventListener("click", () => void submit());
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void submit();
    });
  }

  private renderRegisterCreate(body: HTMLElement, status: HTMLElement, reg: PreparedRegistration): void {
    const create = h("button", { class: "btn primary big", type: "button" }, "Create passkey");
    replace(body, h("p", null, "Code accepted. Create the passkey on this device (Face ID, fingerprint or security key)."), create);
    create.addEventListener("click", async () => {
      status.textContent = "";
      create.disabled = true;
      try {
        await completeRegistration(this.api, this.auth, reg);
        this.showSignin("Passkey registered. Sign in with it now.");
      } catch (e) {
        status.textContent = vt(explainError(e));
        this.renderRegisterStart(body, status);
      }
    });
  }

  private showMain(): void {
    this.view = "main";
    this.rendered.clear();
    replace(
      this.root,
      h(
        "header",
        { class: "topbar" },
        h("h1", { class: "brand" }, "aqmas"),
        h("p", { class: "status", id: "status", "aria-live": "polite" }),
      ),
      h(
        "main",
        { class: "sections" },
        section("pending", "Waiting for you"),
        section("enroll", "Hosts asking to join"),
        section("grants", "Active access"),
        section("standing", "Auto-approvals"),
        section("recent", "Recent activity"),
        section("passkeys", "Passkeys"),
      ),
    );
    this.renderSections();
    this.schedulePoll();
  }

  private renderSections(): void {
    const s = this.state;
    if (!s || this.view !== "main") return;
    const requests = s.pending!.filter((p) => p.kind !== "enrollment");
    const enrolls = s.pending!.filter((p) => p.kind === "enrollment");
    document.title = requests.length + enrolls.length > 0 ? `(${requests.length + enrolls.length}) aqmas` : "aqmas";

    this.section("pending", requests, () =>
      requests.length
        ? requests.map((p) => this.requestCard(p))
        : [h("p", { class: "empty" }, "Nothing is waiting. New requests show up here within a few seconds.")],
    );
    this.section("enroll", enrolls, () => enrolls.map((p) => this.enrollCard(p)), enrolls.length === 0);
    this.section("grants", s.grants, () => {
      if (s.grants === undefined) return [h("p", { class: "empty" }, "This server doesn't list active grants yet.")];
      const active = s.grants!.filter((g) => g.status === "approved");
      return active.length ? active.map((g) => this.grantRow(g)) : [h("p", { class: "empty" }, "No host holds access right now.")];
    });
    this.section("standing", s.standing, () =>
      s.standing!.length ? s.standing!.map((a) => this.standingRow(a)) : [h("p", { class: "empty" }, "No auto-approvals are active.")],
    );
    this.section("recent", s.recent, () =>
      s.recent!.length ? [h("ol", { class: "audit" }, s.recent!.map((e) => auditRow(e)))] : [h("p", { class: "empty" }, "No activity yet.")],
    );
    this.section("passkeys", s.owner, () => [
      h(
        "p",
        null,
        `Signed in as ${vt(s.owner.name)}. `,
        s.owner.passkeys === 1 ? "1 passkey is registered." : `${s.owner.passkeys} passkeys are registered.`,
      ),
      h("button", { class: "btn", type: "button", on: { click: () => this.sheet.openAddPasskey() } }, "Add a passkey"),
    ]);
    this.updateStatus();
    this.tick();
    if (this.focusId) {
      const el = this.root.querySelector(`[data-id="${CSS.escape(this.focusId)}"]`);
      if (el) {
        el.classList.add("focus");
        el.scrollIntoView({ block: "center" });
      }
      this.focusId = null;
    }
  }

  /** Re-render a section only when its data changed (keeps scroll/focus stable while polling). */
  private section(name: string, data: unknown, build: () => Child[], hidden = false): void {
    const key = JSON.stringify(data) ?? "undefined";
    const sec = $(`#sec-${name}`, this.root);
    sec.hidden = hidden;
    if (this.rendered.get(name) === key) return;
    this.rendered.set(name, key);
    const list = $(".list", sec);
    replace(list, build());
    const count = sec.querySelector(".count");
    if (count) count.textContent = Array.isArray(data) && data.length > 0 ? String(data.length) : "";
  }

  private updateStatus(err?: unknown): void {
    const el = this.root.querySelector("#status");
    if (!el) return;
    if (this.offline) {
      el.textContent = `Can't reach aqmas${err ? ` (${vt(explainError(err))})` : ""}. Retrying.`;
      el.classList.add("bad");
    } else {
      el.textContent = this.lastOk ? `Updated ${ago(this.lastOk)}` : "";
      el.classList.remove("bad");
    }
  }

  private tick(): void {
    const now = Date.now();
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-until]")) updateCountdown(t, now);
    for (const t of document.querySelectorAll<HTMLElement>("dialog [data-until]")) updateCountdown(t, now);
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-since]")) t.textContent = ago(Number(t.dataset["since"]), now);
    if (this.view === "main" && !this.offline) this.updateStatus();
    this.sheet.tick(now);
  }

  // ---- cards ----

  private requestCard(p: PendingItem): HTMLElement {
    const ssh = p.ssh;
    const high = p.risk === "high";
    return h(
      "article",
      { class: `card request${high ? " high" : ""}`, "data-id": p.id, "aria-label": `${kindLabel(p.kind)} request from ${vt(p.requesting_host)}` },
      h(
        "div",
        { class: "card-top" },
        h("span", { class: "kind" }, vt(kindLabel(p.kind))),
        high ? h("span", { class: "risk" }, "High risk") : null,
        h("span", { class: "expires" }, "Expires in ", until(p.expires_at)),
      ),
      ssh
        ? h("h3", { class: "target" }, h("span", { class: "user" }, vt(ssh.login_user)), h("span", { class: "at" }, "@"), h("span", { class: "host" }, vt(ssh.target_host)))
        : h("h3", { class: "target" }, vt(p.kind)),
      h(
        "dl",
        { class: "facts" },
        fact("From", h("span", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
        fact("Asks for", duration(p.ttl_requested), p.ttl_max > 0 ? h("span", { class: "muted" }, ` (up to ${duration(p.ttl_max)} allowed)`) : null),
        ssh ? fact("Key", h("span", { class: "mono" }, vt(ssh.key_fingerprint))) : null,
        p.similar_recent > 0 ? fact("Similar", p.similar_recent === 1 ? "1 similar request recently" : `${p.similar_recent} similar requests recently`) : null,
        fact("Asked", since(p.created_at)),
      ),
      agentSays(p),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openDeny(p) } }, "Deny…"),
        h("button", { class: "btn approve", type: "button", on: { click: () => this.sheet.openApprove(p) } }, "Approve…"),
      ),
    );
  }

  private enrollCard(p: PendingItem): HTMLElement {
    const e = p.enrollment;
    return h(
      "article",
      { class: "card enroll", "data-id": p.id, "aria-label": `${vt(p.requesting_host)} asks to join` },
      h("div", { class: "card-top" }, h("span", { class: "kind" }, "New host"), e?.replaces_existing ? h("span", { class: "risk" }, "Replaces an existing host") : null, h("span", { class: "expires" }, "Expires in ", until(p.expires_at))),
      h("h3", { class: "target" }, h("span", { class: "host" }, vt(p.requesting_host))),
      h(
        "dl",
        { class: "facts" },
        fact("Connecting from", h("span", { class: "addr" }, vt(p.requesting_address))),
        e?.csr_fingerprint ? fact("Client key", h("span", { class: "mono" }, vt(e.csr_fingerprint))) : null,
        e?.ssh_host_key_fingerprints?.length ? fact("SSH host keys", e.ssh_host_key_fingerprints.map((f) => h("span", { class: "mono block" }, vt(f)))) : null,
        fact("Asked", since(p.created_at)),
      ),
      agentSays(p),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openDeny(p) } }, "Refuse…"),
        h("button", { class: "btn approve", type: "button", on: { click: () => this.sheet.openApprove(p) } }, "Let it join…"),
      ),
    );
  }

  private standingRow(a: StandingApproval): HTMLElement {
    return h(
      "article",
      { class: "row", "data-id": a.id },
      h("h3", { class: "target small" }, h("span", { class: "user" }, vt(a.login_user)), h("span", { class: "at" }, "@"), h("span", { class: "host" }, vt(a.target_host))),
      h(
        "dl",
        { class: "facts" },
        fact("For host", h("span", { class: "host-name" }, vt(a.requesting_host))),
        fact("Each grant", `up to ${duration(a.max_ttl_seconds)}`),
        fact("Ends in", until(a.expires_at)),
        fact("Used", a.uses === 1 ? "once" : `${a.uses} times`),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForStanding(a)) } }, "Revoke…"),
      ),
    );
  }

  private grantRow(g: GrantSummary): HTMLElement {
    return h(
      "article",
      { class: "row", "data-id": g.id },
      h("h3", { class: "target small" }, h("span", { class: "user" }, vt(g.login_user ?? "?")), h("span", { class: "at" }, "@"), h("span", { class: "host" }, vt(g.target_host ?? "?"))),
      h(
        "dl",
        { class: "facts" },
        g.requesting_host ? fact("Held by", h("span", { class: "host-name" }, vt(g.requesting_host))) : null,
        fact("Kind", vt(kindLabel(g.kind))),
        fact("Ends in", until(g.not_after)),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForGrant(g)) } }, "Revoke…"),
      ),
    );
  }
}

// ---- helpers ----

function append(parent: Node, ...children: Child[]): void {
  for (const c of children) if (c instanceof Node) parent.appendChild(c);
}

function normalise(s: UIState): UIState {
  const pending = [...(s.pending ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at));
  return { ...s, pending, standing: s.standing ?? [], recent: s.recent ?? [], grants: s.grants === undefined ? undefined : (s.grants ?? []) };
}

function section(name: string, title: string): HTMLElement {
  return h(
    "section",
    { id: `sec-${name}`, class: "section", "aria-labelledby": `sec-${name}-h` },
    h("h2", { id: `sec-${name}-h` }, title, " ", h("span", { class: "count" })),
    h("div", { class: "list" }),
  );
}

function fact(label: string, ...value: Child[]): Child[] {
  return [h("dt", null, label), h("dd", null, ...value)];
}

function until(iso: string | number): HTMLElement {
  const ms = typeof iso === "number" ? iso : new Date(iso).getTime();
  const t = h("time", { class: "countdown", "data-until": String(ms), datetime: new Date(ms).toISOString() });
  updateCountdown(t, Date.now());
  return t;
}

function since(iso: string): HTMLElement {
  const t = h("time", { "data-since": String(new Date(iso).getTime()), datetime: iso });
  t.textContent = ago(iso);
  return t;
}

function updateCountdown(t: HTMLElement, now: number): void {
  const ms = Number(t.dataset["until"]);
  const left = ms - now;
  t.textContent = countdown(ms, now);
  t.classList.toggle("soon", left > 0 && left < 60_000);
  t.classList.toggle("over", left <= 0);
}

/** The untrusted, agent-written part of a request, visibly fenced off. */
function agentSays(p: PendingItem): HTMLElement {
  const r = p.requester ?? { tool: "", user: "" };
  const meta: Child[] = [];
  const add = (label: string, v: unknown) => {
    if (v === undefined || v === null || v === "" || v === 0) return;
    meta.push(h("dt", null, label), h("dd", { dir: "ltr" }, vt(v)));
  };
  add("Tool", r.tool);
  add("User", r.user);
  add("Directory", r.cwd);
  add("Session", r.session_id);
  add("PID", r.pid);
  return h(
    "div",
    { class: "agent", role: "group", "aria-label": "Agent says (unverified, written by the requester)" },
    h("p", { class: "agent-label" }, "Agent says", h("span", { class: "muted" }, ", unverified")),
    p.reason ? h("p", { class: "reason", dir: "auto" }, vt(p.reason)) : h("p", { class: "reason muted" }, "(no reason given)"),
    meta.length ? h("dl", { class: "agent-meta" }, meta) : null,
  );
}

function auditRow(e: AuditEntry): HTMLElement {
  return h(
    "li",
    null,
    h("time", { datetime: e.at }, ago(e.at)),
    " ",
    h("span", { class: "actor" }, vt(e.actor)),
    " ",
    h("strong", null, vt(e.action)),
    " ",
    h("span", { class: "mono" }, vt(e.object)),
    e.detail ? h("span", { class: "detail" }, vt(e.detail)) : null,
  );
}

// ---- the decision sheet ----

type Step = "choose" | "working" | "confirm" | "create" | "done" | "error";

class Sheet {
  private dlg: HTMLDialogElement;
  private body: HTMLElement;
  private step: Step | null = null;
  private target: ActionTarget | null = null;
  private prepared: PreparedAction | null = null;
  private goneNote: HTMLElement | null = null;
  private retry: (() => void) | null = null;

  constructor(private app: App) {
    this.body = h("div", { class: "sheet-body" });
    this.dlg = h("dialog", { class: "sheet", "aria-labelledby": "sheet-title" }, this.body) as HTMLDialogElement;
    this.dlg.addEventListener("cancel", (e) => {
      if (this.step === "working") e.preventDefault();
    });
    this.dlg.addEventListener("close", () => {
      this.step = null;
      this.prepared = null;
      this.target = null;
    });
    document.body.appendChild(this.dlg);
  }

  close(): void {
    if (this.dlg.open) this.dlg.close();
  }

  private open(target: ActionTarget, ...content: Child[]): void {
    this.target = target;
    this.prepared = null;
    this.render(...content);
    if (!this.dlg.open) this.dlg.showModal();
  }

  private render(...content: Child[]): void {
    this.goneNote = h("p", { class: "warn", role: "status", hidden: true }, "This is no longer waiting: it was decided elsewhere, withdrawn or expired.");
    replace(this.body, this.goneNote, ...content);
    const first = this.body.querySelector<HTMLElement>("[data-autofocus]") ?? this.body.querySelector<HTMLElement>("button");
    first?.focus();
  }

  tick(now: number): void {
    if (!this.dlg.open || !this.target) return;
    const t = this.target;
    if (this.goneNote && (t.object === "request" || t.object === "enrollment") && this.step !== "done") {
      this.goneNote.hidden = this.app.pendingIds().has(t.id);
    }
    if (this.step === "confirm" && this.prepared && now > this.prepared.validUntil) {
      const btn = this.body.querySelector<HTMLButtonElement>("button.confirm");
      if (btn && !btn.disabled) {
        btn.disabled = true;
        const note = this.body.querySelector(".validity");
        if (note) note.textContent = "This confirmation has expired. Start again to get a fresh one.";
      }
    }
  }

  private summary(p: PendingItem): HTMLElement {
    if (p.kind === "enrollment") {
      return h("div", { class: "summary" }, h("p", { class: "target" }, h("span", { class: "host" }, vt(p.requesting_host))), h("p", null, "New host connecting from ", h("span", { class: "addr" }, vt(p.requesting_address))));
    }
    return h(
      "div",
      { class: "summary" },
      h("p", { class: "target" }, h("span", { class: "user" }, vt(p.ssh?.login_user ?? "?")), h("span", { class: "at" }, "@"), h("span", { class: "host" }, vt(p.ssh?.target_host ?? "?"))),
      h("p", null, `${kindLabel(p.kind)} requested by `, h("span", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
    );
  }

  openApprove(p: PendingItem): void {
    const target = targetForPending(p);
    const cancel = h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Cancel");
    if (p.kind === "enrollment") {
      this.step = "choose";
      const go = h("button", { class: "btn approve", type: "button", "data-autofocus": "" }, "Continue");
      go.addEventListener("click", () => void this.prepare(target, { action: "approve" }, () => this.openApprove(p)));
      this.open(target, h("h2", { id: "sheet-title" }, "Let this host join?"), this.summary(p), h("p", null, "It gets a client certificate and can then ask for access. Each request still needs your approval."), h("div", { class: "actions" }, cancel, go));
      return;
    }
    const { options, def } = ttlChoices(p.ttl_requested, p.ttl_max);
    const ttlSet = h(
      "fieldset",
      { class: "chips" },
      h("legend", null, "How long"),
      options.map((t) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "ttl", value: String(t), checked: t === def }), h("span", null, duration(t), t === p.ttl_requested ? h("small", null, " requested") : null)),
      ),
    );
    const standSet = h(
      "fieldset",
      { class: "chips" },
      h("legend", null, `Also auto-approve the same request (${vt(p.requesting_host)} to ${vt(p.ssh?.login_user ?? "?")}@${vt(p.ssh?.target_host ?? "?")})`),
      STANDING_PRESETS.map((n) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "standing", value: String(n), checked: n === 0 }), h("span", null, n === 0 ? "No" : `for ${hours(n)}`)),
      ),
    );
    const go = h("button", { class: "btn approve", type: "button", "data-autofocus": "" }, "Continue");
    go.addEventListener("click", () => {
      const ttl = Number(ttlSet.querySelector<HTMLInputElement>("input:checked")?.value ?? def);
      const standing = Number(standSet.querySelector<HTMLInputElement>("input:checked")?.value ?? 0);
      void this.prepare(target, { action: "approve", ttl_seconds: ttl, standing_hours: standing }, () => this.openApprove(p));
    });
    this.step = "choose";
    this.open(target, h("h2", { id: "sheet-title" }, "Approve access"), this.summary(p), ttlSet, standSet, h("div", { class: "actions" }, cancel, go));
  }

  openDeny(p: PendingItem): void {
    const target = targetForPending(p);
    this.target = target;
    if (!this.dlg.open) {
      this.render();
      this.dlg.showModal();
    }
    void this.prepare(target, { action: "deny" });
  }

  openRevoke(target: ActionTarget): void {
    this.target = target;
    if (!this.dlg.open) {
      this.render();
      this.dlg.showModal();
    }
    void this.prepare(target, { action: "revoke" });
  }

  openAddPasskey(): void {
    this.target = PASSKEY_TARGET;
    if (!this.dlg.open) {
      this.render();
      this.dlg.showModal();
    }
    void this.prepare(PASSKEY_TARGET, { action: "add" });
  }

  private working(text: string): void {
    this.step = "working";
    this.render(h("h2", { id: "sheet-title" }, text), h("p", { class: "spinner", role: "status" }, "Working…"));
  }

  private async prepare(target: ActionTarget, choice: ActionChoice, retry?: () => void): Promise<void> {
    this.target = target;
    this.retry = retry ?? (() => void this.prepare(target, choice));
    this.working("Preparing confirmation");
    try {
      const p = await prepareAction(this.app.api, target, choice);
      if (this.target !== target || !this.dlg.open) return;
      this.prepared = p;
      this.showConfirm(p);
    } catch (e) {
      if (this.target !== target || !this.dlg.open) return;
      this.showError(e);
    }
  }

  private showConfirm(p: PreparedAction): void {
    this.step = "confirm";
    const d = p.description;
    const negative = p.choice.action !== "approve" && p.choice.action !== "add";
    const confirm = h("button", { class: `btn confirm big ${negative ? "deny" : "approve"}`, type: "button", "data-autofocus": "" }, "Confirm with passkey");
    const cancel = h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Cancel");
    confirm.addEventListener("click", () => this.confirm(p, confirm));
    this.render(
      h("h2", { id: "sheet-title" }, "Check, then confirm"),
      h("p", { class: `headline ${negative ? "neg" : "pos"}` }, vt(d.headline)),
      d.standing ? h("p", { class: "warn" }, vt(d.standing)) : null,
      h(
        "details",
        { class: "signed" },
        h("summary", null, "Exactly what your passkey signs"),
        h("dl", { class: "facts" }, d.fields.map(([k, v]) => fact(k, h("span", { class: "mono" }, vt(v))))),
      ),
      h("p", { class: "validity muted" }, "Valid for ", until(p.validUntil)),
      h("div", { class: "actions" }, cancel, confirm),
    );
  }

  /** Runs inside the tap: the passkey prompt starts before any other await. */
  private confirm(p: PreparedAction, btn: HTMLButtonElement): void {
    if (Date.now() > p.validUntil) return;
    btn.disabled = true;
    const isPasskey = p.target.object === "passkey";
    const run = isPasskey ? authorizeAddPasskey(this.app.api, this.app.auth, p) : completeAction(this.app.api, this.app.auth, p);
    this.step = "working";
    const note = this.body.querySelector(".validity");
    if (note) note.textContent = "Waiting for your passkey…";
    run.then(
      (res) => {
        if (!this.dlg.open) return;
        if (isPasskey) this.showCreatePasskey(res as PreparedRegistration);
        else this.showDone(p);
        this.app.changed();
      },
      (e) => {
        if (!this.dlg.open) return;
        this.showError(e);
        this.app.changed();
      },
    );
  }

  private showCreatePasskey(reg: PreparedRegistration): void {
    this.step = "create";
    const create = h("button", { class: "btn approve big", type: "button", "data-autofocus": "" }, "Create the new passkey");
    create.addEventListener("click", () => {
      create.disabled = true;
      completeRegistration(this.app.api, this.app.auth, reg).then(
        () => {
          this.step = "done";
          this.render(h("h2", { id: "sheet-title" }, "Passkey added"), h("p", null, "You can now sign in and approve with it."), h("div", { class: "actions" }, h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Done")));
          this.app.changed();
        },
        (e) => this.showError(e),
      );
    });
    this.render(h("h2", { id: "sheet-title" }, "Create the new passkey"), h("p", null, "Approved. Now create the passkey, on this device or another one via the browser's options (QR code, security key)."), h("div", { class: "actions" }, h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Cancel"), create));
  }

  private showDone(p: PreparedAction): void {
    this.step = "done";
    const c = p.canonical;
    const words: Record<string, string> = { approve: "Approved", deny: "Denied", revoke: "Revoked" };
    let detail = "";
    if (c.object === "grant") detail = "Marked revoked. The certificate itself stays valid until it expires (no revocation list yet).";
    else if (c.object === "request" && c.action === "approve") detail = `${c.requesting_host ?? "The host"} can now use ${c.login_user ?? "?"}@${c.target ?? "?"} for ${duration(c.ttl_seconds ?? 0)}.`;
    else if (c.object === "enrollment" && c.action === "approve") detail = `${c.requesting_host ?? "The host"} can now ask for access.`;
    else if (c.object === "standing") detail = "Matching requests need your approval again.";
    const done = h("button", { class: "btn big", type: "button", "data-autofocus": "", on: { click: () => this.close() } }, "Done");
    this.render(h("h2", { id: "sheet-title", class: c.action === "approve" ? "ok" : "neg" }, words[c.action] ?? "Done"), h("p", { class: "headline" }, vt(p.description.headline)), detail ? h("p", null, vt(detail)) : null, h("div", { class: "actions" }, done));
  }

  private showError(e: unknown): void {
    this.step = "error";
    const msg = explainError(e);
    const isFlow = e instanceof FlowError;
    const nothingChanged =
      isFlow ||
      (e instanceof ApiError && e.status >= 400) ||
      (e instanceof Error && ["NotAllowedError", "AbortError", "InvalidStateError", "SecurityError"].includes(e.name));
    const again = this.retry;
    this.render(
      h("h2", { id: "sheet-title", class: "neg" }, isFlow ? "Not signed" : "That didn't work"),
      h("p", { class: "error", role: "alert" }, vt(msg)),
      h("p", { class: "muted" }, nothingChanged ? "Nothing was changed." : "The connection failed, so it may or may not have gone through: check the list, it updates by itself."),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Close"),
        again ? h("button", { class: "btn approve", type: "button", on: { click: () => again() } }, "Start again") : null,
      ),
    );
  }
}
