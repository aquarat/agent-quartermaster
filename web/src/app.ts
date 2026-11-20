// The approval UI. Rendering only; the security-relevant logic lives in flows.ts,
// canonical.ts and webauthn.ts.
//
// Untrusted text (reason, requester fields, and for safety every server string) is shown
// through text nodes only, with invisible/bidi characters made visible (visibleText).

import { ApiError, createApi, type Api } from "./api";
import type { Part } from "./canonical";
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
  nothingChanged,
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
import { CF_RISKS, cfScope, paramPairs, parseScopeParams, riskLabel, sentenceCase, unusualParams, type CFScopeDesc } from "./cfscopes";
import { STANDING_PRESETS, ago, auditLabel, countdown, duration, hours, isPlainName, kindLabel, ttlChoices, visibleText as vt } from "./format";
import type { AuditEntry, GrantSummary, PendingCloudflare, PendingItem, StandingApproval, UIState } from "./types";
import { browserAuthenticator, type Authenticator } from "./webauthn";

const POLL_MS = 5000;
/** Login options are refreshed this often while the sign-in page is open, so a tap can call
 * navigator.credentials.get at once (Safari needs the call inside the tap, before any await). */
const LOGIN_REFRESH_MS = 45_000;
/** Lists don't re-render for this long after a touch, so cards don't move under a finger. */
const TOUCH_SETTLE_MS = 1500;

/** Short reference shown on cards; the CLI prints the same so the owner can match them. */
export function refCode(id: string): string {
  return id.slice(-6).toUpperCase();
}

export class App {
  readonly api: Api;
  readonly auth: Authenticator;
  private root: HTMLElement;
  private state: UIState | null = null;
  private lastOk = 0;
  private offline = false;
  private view: "loading" | "signin" | "main" = "loading";
  private pollTimer: number | undefined;
  private refreshing = false;
  private rendered = new Map<string, string>();
  private login: PreparedLogin | null = null;
  private loginTimer: number | undefined;
  private sheet: Sheet;
  private focusId: string | null = null;
  private pointerDown = false;
  private lastTouch = 0;

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
      if (document.visibilityState !== "visible") return;
      if (this.view === "main") void this.refresh();
      if (this.view === "signin") this.prefetchLogin();
    });
    const down = () => {
      this.pointerDown = true;
      this.lastTouch = Date.now();
    };
    const up = () => {
      this.pointerDown = false;
      this.lastTouch = Date.now();
    };
    this.root.addEventListener("pointerdown", down, { passive: true });
    this.root.addEventListener("touchstart", down, { passive: true });
    for (const ev of ["pointerup", "pointercancel", "touchend", "touchcancel"]) window.addEventListener(ev, up, { passive: true });
    window.setInterval(() => this.tick(), 1000);
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
        this.sheet.close(true);
        if (this.view !== "signin") this.showSignin();
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

  /** Called by the sheet after an action was attempted. */
  changed(): void {
    void this.refresh();
  }

  /** Is this object still live on the server, as of the last poll? undefined = can't tell. */
  stillLive(t: ActionTarget): boolean | undefined {
    const s = this.state;
    if (!s) return undefined;
    switch (t.object) {
      case "request":
      case "enrollment":
        return (s.pending ?? []).some((p) => p.id === t.id);
      case "standing":
        return (s.standing ?? []).some((a) => a.id === t.id);
      case "grant":
        return s.grants === undefined ? undefined : (s.grants ?? []).some((g) => g.id === t.id && g.status === "approved");
      default:
        return undefined;
    }
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

  private loginStatus: HTMLElement | null = null;
  private loginDetails: HTMLDetailsElement | null = null;
  private signBtn: HTMLButtonElement | null = null;

  /** Fetch login options ahead of the tap (and keep them fresh). */
  private prefetchLogin(): void {
    if (this.view !== "signin") return;
    prepareLogin(this.api).then(
      (p) => {
        this.login = p;
        if (this.signBtn) this.signBtn.disabled = false;
      },
      (e) => {
        this.login = null;
        if (!this.loginStatus) return;
        if (e instanceof ApiError && e.code === "conflict") {
          if (this.loginDetails) this.loginDetails.open = true;
          this.loginStatus.textContent = "No passkey is registered yet. Register this device with the enroll code.";
        } else {
          this.loginStatus.textContent = vt(explainError(e));
        }
      },
    );
  }

  private showSignin(message?: string): void {
    this.view = "signin";
    this.state = null;
    this.login = null;
    this.rendered.clear();
    document.title = "aqmas";
    const status = h("p", { class: "error", role: "alert", "aria-live": "assertive" }, message ? vt(message) : "");
    const signBtn = h("button", { class: "btn primary big", type: "button" }, "Sign in with passkey");
    const regDetails = h("details", { class: "first-run" });
    const regBody = h("div", { class: "first-run-body" });
    this.loginStatus = status;
    this.loginDetails = regDetails;
    this.signBtn = signBtn;
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
    regDetails.append(h("summary", null, "First time on this device?"), regBody);
    this.renderRegisterStart(regBody, status);

    this.prefetchLogin();
    if (this.loginTimer === undefined) {
      this.loginTimer = window.setInterval(() => {
        if (this.view === "signin" && document.visibilityState === "visible") this.prefetchLogin();
      }, LOGIN_REFRESH_MS);
    }

    signBtn.addEventListener("click", () => {
      status.textContent = "";
      const p = this.login;
      this.login = null;
      if (!p || Date.now() - p.fetchedAt > LOGIN_OPTIONS_MAX_AGE_MS) {
        // Never await a fetch inside the tap: get fresh options and ask for another tap.
        signBtn.disabled = true;
        status.textContent = "Getting ready… tap again in a moment.";
        this.prefetchLogin();
        return;
      }
      signBtn.disabled = true;
      // completeLogin calls navigator.credentials.get synchronously from here.
      completeLogin(this.api, this.auth, p)
        .then(() => this.refresh())
        .catch((e) => {
          status.textContent = vt(explainError(e));
          this.prefetchLogin();
        });
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
      if (go.disabled) return;
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
    create.addEventListener("click", () => {
      status.textContent = "";
      create.disabled = true;
      completeRegistration(this.api, this.auth, reg).then(
        () => this.showSignin("Passkey registered. Sign in with it now."),
        (e) => {
          status.textContent = vt(explainError(e));
          this.renderRegisterStart(body, status);
        },
      );
    });
  }

  private showMain(): void {
    this.view = "main";
    this.rendered.clear();
    this.loginStatus = this.signBtn = this.loginDetails = null;
    replace(
      this.root,
      h("header", { class: "topbar" }, h("h1", { class: "brand" }, "aqmas"), h("p", { class: "status", id: "status" })),
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
    // While a finger is on the screen, leave the lists alone (the next poll catches up).
    const touching = this.pointerDown || Date.now() - this.lastTouch < TOUCH_SETTLE_MS;

    this.section(
      "pending",
      requests,
      () =>
        requests.length
          ? requests.map((p) => this.requestCard(p))
          : [h("p", { class: "empty" }, "Nothing is waiting. New requests show up here within a few seconds.")],
      false,
      touching,
    );
    this.section("enroll", enrolls, () => enrolls.map((p) => this.enrollCard(p)), enrolls.length === 0, touching);
    this.section(
      "grants",
      s.grants,
      () => {
        if (s.grants === undefined) return [h("p", { class: "empty" }, "This server doesn't list active grants yet.")];
        const active = s.grants!.filter((g) => g.status === "approved");
        return active.length ? active.map((g) => this.grantRow(g)) : [h("p", { class: "empty" }, "No host holds access right now.")];
      },
      false,
      touching,
    );
    this.section(
      "standing",
      s.standing,
      () => (s.standing!.length ? s.standing!.map((a) => this.standingRow(a)) : [h("p", { class: "empty" }, "No auto-approvals are active.")]),
      false,
      touching,
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
  private section(name: string, data: unknown, build: () => Child[], hidden = false, defer = false): void {
    const key = JSON.stringify(data) ?? "undefined";
    const sec = $(`#sec-${name}`, this.root);
    if (this.rendered.get(name) === key) return;
    if (defer && this.rendered.has(name)) return;
    sec.hidden = hidden;
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
      el.setAttribute("role", "alert");
    } else {
      el.textContent = this.lastOk ? `Updated ${ago(this.lastOk)}` : "";
      el.classList.remove("bad");
      el.removeAttribute("role");
    }
  }

  private tick(): void {
    const now = Date.now();
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-until]")) updateCountdown(t, now);
    for (const t of document.querySelectorAll<HTMLElement>("dialog [data-until]")) updateCountdown(t, now);
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-since]")) t.textContent = ago(Number(t.dataset["since"]), now);
    if (this.view === "main" && !this.offline) this.updateStatus();
    if (this.view === "main" && this.rendered.size > 0 && !this.pointerDown && now - this.lastTouch >= TOUCH_SETTLE_MS) {
      // Catch up on a render that was deferred during a touch.
      this.renderSectionsIfDeferred();
    }
    this.sheet.tick(now);
  }

  private renderSectionsIfDeferred(): void {
    const s = this.state;
    if (!s) return;
    const req = s.pending!.filter((p) => p.kind !== "enrollment");
    const enr = s.pending!.filter((p) => p.kind === "enrollment");
    const stale =
      this.rendered.get("pending") !== JSON.stringify(req) ||
      this.rendered.get("enroll") !== JSON.stringify(enr) ||
      this.rendered.get("standing") !== JSON.stringify(s.standing) ||
      this.rendered.get("grants") !== (JSON.stringify(s.grants) ?? "undefined");
    if (stale) this.renderSections();
  }

  // ---- cards ----

  private requestCard(p: PendingItem): HTMLElement {
    if (p.kind === "cloudflare") return this.cfRequestCard(p);
    const ssh = p.ssh;
    const high = p.risk === "high";
    const odd = !isPlainName(p.requesting_host) || (ssh && (!isPlainName(ssh.login_user) || !isPlainName(ssh.target_host)));
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
      ssh ? targetLine(ssh.login_user, ssh.target_host) : h("h3", { class: "target" }, vt(p.kind)),
      odd ? h("p", { class: "warn" }, "A name here contains unusual characters. Check it letter by letter.") : null,
      h(
        "dl",
        { class: "facts" },
        fact("From", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
        fact("Asks for", duration(p.ttl_requested), p.ttl_max > 0 ? h("span", { class: "muted" }, ` (up to ${duration(p.ttl_max)} allowed)`) : null),
        ssh ? fact("Key", h("span", { class: "mono" }, vt(ssh.key_fingerprint))) : null,
        p.similar_recent > 0 ? fact("Similar", p.similar_recent === 1 ? "1 similar request recently" : `${p.similar_recent} similar requests recently`) : null,
        fact("Asked", since(p.created_at)),
        fact("Ref", h("span", { class: "mono" }, vt(refCode(p.id)))),
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

  /** A Cloudflare request: scope in this page's own words, each parameter, mode, TTL, risk. */
  private cfRequestCard(p: PendingItem): HTMLElement {
    const cf = p.cloudflare;
    const v = cfView(cf?.scope, cf?.scope_params, cf?.mode);
    const risk = v.scope?.risk ?? cfRisk(cf?.risk);
    const admin = cf?.scope === "cf.admin";
    const token = cf?.mode === "token";
    const odd = !isPlainName(p.requesting_host) || v.unusual.length > 0;
    return h(
      "article",
      {
        class: `card request cloudflare${risk === "high" || risk === "admin" ? " high" : ""}${admin ? " cf-admin" : ""}`,
        "data-id": p.id,
        "aria-label": `${admin ? "Break-glass " : ""}Cloudflare request from ${vt(p.requesting_host)}`,
      },
      h(
        "div",
        { class: "card-top" },
        h("span", { class: "kind" }, "Cloudflare"),
        riskBadge(risk),
        h("span", { class: "expires" }, "Expires in ", until(p.expires_at)),
      ),
      admin ? h("p", { class: "breakglass", role: "note" }, "BREAK-GLASS: full Cloudflare access for 1 hour, everything except the deny-list. Approve only if you asked for it yourself.") : null,
      v.heading,
      v.problem ? h("p", { class: "warn" }, vt(v.problem)) : null,
      odd ? h("p", { class: "warn" }, "A name here contains unusual characters. Check it letter by letter.") : null,
      h(
        "dl",
        { class: "facts" },
        fact("Scope", h("span", { class: "mono" }, vt(cf?.scope ?? "?"))),
        v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))),
        fact("Mode", token ? ["Real API token, usable only from ", h("span", { class: "mono" }, vt(cf?.ip_condition || "?"))] : "Through the aqmas proxy (no secret leaves aqmas)"),
        fact("From", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
        fact("Asks for", duration(p.ttl_requested), p.ttl_max > 0 ? h("span", { class: "muted" }, ` (up to ${duration(p.ttl_max)} allowed)`) : null),
        p.similar_recent > 0 ? fact("Similar", p.similar_recent === 1 ? "1 similar request recently" : `${p.similar_recent} similar requests recently`) : null,
        fact("Asked", since(p.created_at)),
        fact("Ref", h("span", { class: "mono" }, vt(refCode(p.id)))),
      ),
      token ? tokenBox(cf!, v.scope) : null,
      scopeDetails(v.scope, cf),
      agentSays(p),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openDeny(p) } }, "Deny…"),
        h(
          "button",
          { class: "btn approve", type: "button", disabled: !!v.problem, title: v.problem ? "This page can't describe this scope, so it won't sign an approval" : undefined, on: { click: () => this.sheet.openApprove(p) } },
          admin ? "Approve break-glass…" : "Approve…",
        ),
      ),
    );
  }

  private enrollCard(p: PendingItem): HTMLElement {
    const e = p.enrollment;
    return h(
      "article",
      { class: "card enroll", "data-id": p.id, "aria-label": `${vt(p.requesting_host)} asks to join` },
      h("div", { class: "card-top" }, h("span", { class: "kind" }, "New host"), e?.replaces_existing ? h("span", { class: "risk" }, "Replaces an existing host") : null, h("span", { class: "expires" }, "Expires in ", until(p.expires_at))),
      h("h3", { class: "target" }, h("bdi", { class: "host" }, vt(p.requesting_host))),
      !isPlainName(p.requesting_host) ? h("p", { class: "warn" }, "This host name contains unusual characters. Check it letter by letter.") : null,
      e?.replaces_existing ? h("p", { class: "warn" }, "A host with this name is already enrolled. Approving revokes its certificate.") : null,
      enrollFacts(p),
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
    if (a.kind === "cloudflare") {
      const v = cfView(a.scope, a.scope_params, a.mode, true);
      return h(
        "article",
        { class: "row cloudflare", "data-id": a.id },
        v.heading,
        v.problem ? h("p", { class: "warn" }, vt(v.problem)) : null,
        h(
          "dl",
          { class: "facts" },
          fact("Scope", h("span", { class: "mono" }, vt(a.scope ?? "?"))),
          v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))),
          fact("Mode", vt(modeWords(a.mode))),
          fact("For host", h("bdi", { class: "host-name" }, vt(a.requesting_host))),
          fact("Each grant", `up to ${duration(a.max_ttl_seconds)}`),
          fact("Ends in", until(a.expires_at)),
          fact("Used", a.uses === 1 ? "once" : `${a.uses} times`),
        ),
        h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForStanding(a)) } }, "Revoke…")),
      );
    }
    return h(
      "article",
      { class: "row", "data-id": a.id },
      targetLine(a.login_user, a.target_host, true),
      h(
        "dl",
        { class: "facts" },
        fact("For host", h("bdi", { class: "host-name" }, vt(a.requesting_host))),
        fact("Each grant", `up to ${duration(a.max_ttl_seconds)}`),
        fact("Ends in", until(a.expires_at)),
        fact("Used", a.uses === 1 ? "once" : `${a.uses} times`),
      ),
      h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForStanding(a)) } }, "Revoke…")),
    );
  }

  private grantRow(g: GrantSummary): HTMLElement {
    if (g.kind === "cloudflare") {
      const v = cfView(g.scope, g.scope_params, g.mode, true);
      const admin = g.scope === "cf.admin";
      return h(
        "article",
        { class: `row cloudflare${admin ? " cf-admin" : ""}`, "data-id": g.id },
        admin ? h("p", { class: "breakglass", role: "note" }, "BREAK-GLASS access is active.") : null,
        v.heading,
        v.problem ? h("p", { class: "warn" }, vt(v.problem)) : null,
        h(
          "dl",
          { class: "facts" },
          g.requesting_host ? fact("Held by", h("bdi", { class: "host-name" }, vt(g.requesting_host))) : null,
          fact("Kind", "Cloudflare ", h("span", { class: "mono" }, vt(g.scope ?? "?"))),
          v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))),
          fact("Mode", vt(modeWords(g.mode))),
          fact("Ends in", until(g.not_after)),
        ),
        h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForGrant(g)) } }, "Revoke…")),
      );
    }
    return h(
      "article",
      { class: "row", "data-id": g.id },
      targetLine(g.login_user ?? "?", g.target_host ?? "?", true),
      h(
        "dl",
        { class: "facts" },
        g.requesting_host ? fact("Held by", h("bdi", { class: "host-name" }, vt(g.requesting_host))) : null,
        fact("Kind", vt(kindLabel(g.kind))),
        fact("Ends in", until(g.not_after)),
      ),
      h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForGrant(g)) } }, "Revoke…")),
    );
  }
}

// ---- helpers ----

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

function targetLine(user: string, host: string, small = false): HTMLElement {
  return h(
    "h3",
    { class: small ? "target small" : "target" },
    h("bdi", { class: "user" }, vt(user)),
    h("span", { class: "at" }, "@"),
    h("bdi", { class: "host" }, vt(host)),
  );
}

interface CFView {
  scope: CFScopeDesc | undefined;
  pairs: Array<[string, string]>;
  unusual: string[];
  heading: HTMLElement;
  /** Why this page won't sign an approval for it (unknown scope, bad parameters). */
  problem?: string;
}

/** A Cloudflare scope + canonical parameters as a heading in this page's own words. */
function cfView(scopeName: string | undefined, scopeParams: string | undefined, mode: string | undefined, small = false): CFView {
  const scope = cfScope(scopeName);
  let params: Record<string, string> = {};
  let problem: string | undefined;
  try {
    params = parseScopeParams(scopeParams ?? "");
  } catch (e) {
    problem = `${(e as Error).message}: this page won't sign it.`;
  }
  if (!scope) problem = `This page has no description of the Cloudflare scope "${scopeName ?? ""}", so it won't sign it.`;
  const cls = small ? "target cf small" : "target cf";
  const heading = scope
    ? h("h3", { class: cls }, renderParts(sentenceCase(scope.phrase(params))), mode === "token" ? h("span", { class: "muted mode-tag" }, " (API token)") : null)
    : h("h3", { class: cls }, "Unknown Cloudflare scope ", h("bdi", { class: "val" }, vt(scopeName ?? "?")));
  return { scope, pairs: paramPairs(scope, params), unusual: scope ? unusualParams(scope, params) : [], heading, problem };
}

function cfRisk(r: string | undefined): string {
  return r && (CF_RISKS as readonly string[]).includes(r) ? r : "high";
}

function riskBadge(risk: string): HTMLElement {
  return h("span", { class: `badge risk-${cfRisk(risk)}` }, riskLabel(cfRisk(risk)));
}

function modeWords(mode: string | undefined): string {
  if (mode === "token") return "Real API token";
  if (mode === "proxy") return "Through the aqmas proxy";
  return mode ?? "?";
}

/** Token mode: what the minted token can do (server's words) and this page's own warning. */
function tokenBox(cf: PendingCloudflare, scope: CFScopeDesc | undefined): HTMLElement {
  const own = scope?.tokenNote?.(cf.params ?? {});
  return h(
    "div",
    { class: "token-box", role: "group", "aria-label": "API token details" },
    h("p", { class: "token-label" }, "A real API token leaves aqmas"),
    h("p", null, "Guard rails and snapshots don't apply to it. It expires with the grant and is deleted at Cloudflare on revoke."),
    own ? h("p", { class: "warn" }, own) : null,
    cf.permissions?.length ? [h("p", { class: "muted" }, "Token permissions (from aqmas):"), h("ul", { class: "perms" }, cf.permissions.map((x) => h("li", null, vt(x))))] : null,
    cf.notes?.length ? h("ul", { class: "notes" }, cf.notes.map((x) => h("li", null, vt(x)))) : null,
  );
}

/** What the scope allows and doesn't (this page's words), plus the server's own description. */
function scopeDetails(scope: CFScopeDesc | undefined, cf: PendingCloudflare | undefined): HTMLElement | null {
  if (!scope && !cf?.description) return null;
  return h(
    "details",
    { class: "scope-details" },
    h("summary", null, "What this allows"),
    scope ? [h("p", { class: "muted" }, "Can:"), h("ul", null, scope.can.map((x) => h("li", null, x))), h("p", { class: "muted" }, "Cannot:"), h("ul", null, scope.cannot.map((x) => h("li", null, x)))] : null,
    cf?.title || cf?.description ? h("p", { class: "server-says" }, h("span", { class: "muted" }, "aqmas catalogue: "), vt(cf.title), cf.title && cf.description ? ". " : "", vt(cf.description)) : null,
  );
}

function enrollFacts(p: PendingItem): HTMLElement {
  const e = p.enrollment;
  return h(
    "dl",
    { class: "facts" },
    fact("Connecting from", h("span", { class: "addr" }, vt(p.requesting_address))),
    e?.csr_fingerprint ? fact("Client key", h("span", { class: "mono" }, vt(e.csr_fingerprint))) : null,
    e?.ssh_host_key_fingerprints?.length ? fact("SSH host keys (self-reported)", e.ssh_host_key_fingerprints.map((f) => h("span", { class: "mono block" }, vt(f)))) : null,
    fact("Asked", since(p.created_at)),
    fact("Ref", h("span", { class: "mono" }, vt(refCode(p.id)))),
  );
}

function until(iso: string | number): HTMLElement {
  const ms = typeof iso === "number" ? iso : new Date(iso).getTime();
  const t = h("time", { class: "countdown", "data-until": String(ms), datetime: Number.isFinite(ms) ? new Date(ms).toISOString() : "" });
  updateCountdown(t, Date.now());
  return t;
}

function since(iso: string): HTMLElement {
  const ms = new Date(iso).getTime();
  const t = h("time", { "data-since": String(ms), datetime: iso });
  t.textContent = ago(ms);
  return t;
}

function updateCountdown(t: HTMLElement, now: number): void {
  const ms = Number(t.dataset["until"]);
  const left = ms - now;
  t.textContent = countdown(ms, now);
  t.classList.toggle("soon", left > 0 && left < 60_000);
  t.classList.toggle("over", left <= 0);
}

/** Render description parts: canonical values isolated in <bdi>, our words as plain text. */
function renderParts(parts: Part[]): Child[] {
  return parts.map((p) => (typeof p === "string" ? p : h("bdi", { class: "val" }, vt(p.value))));
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
    h("bdi", { class: "actor" }, vt(e.actor)),
    " ",
    h("strong", { title: e.action }, vt(auditLabel(e.action))),
    " ",
    h("span", { class: "mono" }, vt(e.object)),
    e.detail ? h("span", { class: "detail" }, vt(e.detail)) : null,
  );
}

// ---- the decision sheet ----

type Step = "choose" | "working" | "confirm" | "signing" | "create" | "done" | "error";

class Sheet {
  private dlg: HTMLDialogElement;
  private body: HTMLElement;
  private step: Step | null = null;
  private target: ActionTarget | null = null;
  private prepared: PreparedAction | null = null;
  private goneNote: HTMLElement | null = null;
  private retry: (() => void) | null = null;
  /** Bumped whenever a flow starts or the sheet closes; async results for an older flow are
   * dropped so they can never draw over (or act in) a different flow. */
  private seq = 0;

  constructor(private app: App) {
    this.body = h("div", { class: "sheet-body" });
    this.dlg = h("dialog", { class: "sheet", "aria-labelledby": "sheet-title" }, this.body) as HTMLDialogElement;
    this.dlg.addEventListener("cancel", (e) => {
      // Escape / Android back: not while a signed action is in flight.
      if (this.busy()) e.preventDefault();
    });
    this.dlg.addEventListener("close", () => {
      this.seq++;
      this.step = null;
      this.prepared = null;
      this.target = null;
      this.retry = null;
    });
    document.body.appendChild(this.dlg);
  }

  private busy(): boolean {
    return this.step === "signing";
  }

  close(force = false): void {
    if (!this.dlg.open) return;
    if (this.busy() && !force) return;
    this.dlg.close();
  }

  /** Start a new flow: returns its sequence number. */
  private begin(target: ActionTarget): number {
    this.seq++;
    this.target = target;
    this.prepared = null;
    this.retry = null;
    if (!this.dlg.open) {
      this.render();
      this.dlg.showModal();
    }
    return this.seq;
  }

  private current(seq: number): boolean {
    return seq === this.seq && this.dlg.open;
  }

  private render(...content: Child[]): void {
    this.goneNote = h("p", { class: "warn", role: "status", hidden: true }, "This is no longer waiting: it was decided elsewhere, withdrawn, revoked or expired.");
    replace(this.body, this.goneNote, ...content);
    const first = this.body.querySelector<HTMLElement>("[data-autofocus]") ?? this.body.querySelector<HTMLElement>("button");
    first?.focus();
    this.tick(Date.now());
  }

  tick(now: number): void {
    if (!this.dlg.open || !this.target) return;
    const gone = this.step !== "done" && this.step !== "signing" && this.app.stillLive(this.target) === false;
    if (this.goneNote) this.goneNote.hidden = !gone;
    if (this.step === "confirm" && this.prepared) {
      const btn = this.body.querySelector<HTMLButtonElement>("button.confirm");
      const expired = now > this.prepared.validUntil;
      if (btn) btn.disabled = expired || gone;
      if (expired) {
        const note = this.body.querySelector(".validity");
        if (note) note.textContent = "This confirmation has expired. Start again to get a fresh one.";
      }
    }
  }

  private cancelButton(): HTMLButtonElement {
    return h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Cancel");
  }

  private summary(p: PendingItem): HTMLElement {
    if (p.kind === "enrollment") {
      return h(
        "div",
        { class: "summary" },
        h("p", { class: "target" }, h("bdi", { class: "host" }, vt(p.requesting_host))),
        p.enrollment?.replaces_existing ? h("p", { class: "warn" }, "A host with this name is already enrolled. Approving revokes its certificate.") : null,
        enrollFacts(p),
      );
    }
    if (p.kind === "cloudflare") {
      const cf = p.cloudflare;
      const v = cfView(cf?.scope, cf?.scope_params, cf?.mode);
      return h(
        "div",
        { class: "summary" },
        cf?.scope === "cf.admin" ? h("p", { class: "breakglass", role: "note" }, "BREAK-GLASS: full Cloudflare access, everything except the deny-list.") : null,
        v.heading,
        h("dl", { class: "facts" }, v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))), fact("Mode", vt(modeWords(cf?.mode)))),
        h("p", null, "Cloudflare requested by ", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
      );
    }
    return h(
      "div",
      { class: "summary" },
      targetLine(p.ssh?.login_user ?? "?", p.ssh?.target_host ?? "?"),
      h("p", null, `${kindLabel(p.kind)} requested by `, h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
    );
  }

  openApprove(p: PendingItem): void {
    const target = targetForPending(p);
    const seq = this.begin(target);
    const again = () => this.openApprove(p);
    this.step = "choose";
    if (p.kind === "enrollment") {
      const go = h("button", { class: "btn approve", type: "button", "data-autofocus": "" }, "Continue");
      go.addEventListener("click", () => void this.prepare(seq, target, { action: "approve" }, again));
      this.render(
        h("h2", { id: "sheet-title" }, "Let this host join?"),
        this.summary(p),
        h("p", null, "It gets a client certificate and can then ask for access. Each request still needs your approval."),
        h("div", { class: "actions" }, this.cancelButton(), go),
      );
      return;
    }
    const cf = p.kind === "cloudflare" ? p.cloudflare : undefined;
    const cfDesc = cf ? cfScope(cf.scope) : undefined;
    // Never offer more than the card's ttl_max, nor (Cloudflare) the scope's built-in maximum.
    const maxTTL = cfDesc ? Math.min(p.ttl_max > 0 ? p.ttl_max : cfDesc.maxTTL, cfDesc.maxTTL) : p.ttl_max;
    const { options, def } = ttlChoices(p.ttl_requested, maxTTL);
    const ttlSet = h(
      "fieldset",
      { class: "chips" },
      h("legend", null, "How long"),
      options.map((t) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "ttl", value: String(t), checked: t === def }), h("span", null, duration(t), t === p.ttl_requested ? h("small", null, " requested") : null)),
      ),
    );
    // SSH: aqmasd refuses standing approvals for high-risk requests (high_risk target, root,
    // > 4 h). Cloudflare: only when the server allows it for this scope AND this page's own
    // table does, and only in proxy mode (never cf.admin, never a token).
    const offerStanding = cf ? cf.standing_allowed === true && cf.mode === "proxy" && cfDesc?.standing === true : p.risk !== "high";
    const standLegend: Child[] = cf
      ? ["Also auto-approve the same Cloudflare request (", h("bdi", null, vt(p.requesting_host)), ", ", h("bdi", null, vt(cf.scope)), cf.scope_params ? [" ", h("bdi", null, vt(cf.scope_params))] : null, ")"]
      : ["Also auto-approve the same request (", h("bdi", null, vt(p.requesting_host)), " to ", h("bdi", null, vt(p.ssh?.login_user ?? "?")), "@", h("bdi", null, vt(p.ssh?.target_host ?? "?")), ")"];
    const standSet = !offerStanding ? null : h(
      "fieldset",
      { class: "chips" },
      h("legend", null, standLegend),
      STANDING_PRESETS.map((n) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "standing", value: String(n), checked: n === 0 }), h("span", null, n === 0 ? "No" : `for ${hours(n)}`)),
      ),
    );
    const go = h("button", { class: "btn approve", type: "button", "data-autofocus": "" }, "Continue");
    go.addEventListener("click", () => {
      const ttl = Number(ttlSet.querySelector<HTMLInputElement>("input:checked")?.value ?? def);
      const standing = Number(standSet?.querySelector<HTMLInputElement>("input:checked")?.value ?? 0);
      void this.prepare(seq, target, { action: "approve", ttl_seconds: ttl, standing_hours: standing }, again);
    });
    this.render(h("h2", { id: "sheet-title" }, cf?.scope === "cf.admin" ? "Approve break-glass access" : "Approve access"), this.summary(p), ttlSet, standSet, h("div", { class: "actions" }, this.cancelButton(), go));
  }

  openDeny(p: PendingItem): void {
    const target = targetForPending(p);
    void this.prepare(this.begin(target), target, { action: "deny" });
  }

  openRevoke(target: ActionTarget): void {
    void this.prepare(this.begin(target), target, { action: "revoke" });
  }

  openAddPasskey(): void {
    const target: ActionTarget = { ...PASSKEY_TARGET };
    void this.prepare(this.begin(target), target, { action: "add" });
  }

  private working(text: string): void {
    this.step = "working";
    this.render(h("h2", { id: "sheet-title" }, text), h("p", { class: "spinner", role: "status" }, "Working…"), h("div", { class: "actions" }, this.cancelButton()));
  }

  private async prepare(seq: number, target: ActionTarget, choice: ActionChoice, retry?: () => void): Promise<void> {
    if (!this.current(seq)) return;
    this.retry = retry ?? (() => void this.prepare(this.begin(target), target, choice));
    this.working("Preparing confirmation");
    try {
      const p = await prepareAction(this.app.api, target, choice);
      if (!this.current(seq)) return;
      this.prepared = p;
      this.showConfirm(seq, p);
    } catch (e) {
      if (!this.current(seq)) return;
      this.showError(e);
    }
  }

  private showConfirm(seq: number, p: PreparedAction): void {
    this.step = "confirm";
    const d = p.description;
    const negative = p.choice.action !== "approve" && p.choice.action !== "add";
    const confirm = h("button", { class: `btn confirm big ${negative ? "deny" : "approve"}`, type: "button", "data-autofocus": "" }, "Confirm with passkey");
    confirm.addEventListener("click", () => this.confirm(seq, p, confirm));
    const loud = d.breakGlass && !negative;
    this.render(
      h("h2", { id: "sheet-title" }, loud ? "Break-glass: check, then confirm" : "Check, then confirm"),
      d.risk ? h("p", { class: "card-top" }, h("span", { class: "kind" }, "Cloudflare"), riskBadge(d.risk)) : null,
      h("p", { class: `headline ${negative ? "neg" : "pos"}${loud ? " loud" : ""}` }, renderParts(d.headlineParts)),
      d.details?.length ? h("ul", { class: "cf-details" }, d.details.map((line) => h("li", null, renderParts(line)))) : null,
      d.standingParts ? h("p", { class: "warn" }, renderParts(d.standingParts)) : null,
      d.warnings.map((w, i) => h("p", { class: loud && i === 0 ? "breakglass" : "warn" }, vt(w))),
      h(
        "details",
        { class: "signed" },
        h("summary", null, "Exactly what your passkey signs"),
        h("dl", { class: "facts" }, d.fields.map(([k, v]) => fact(k, h("span", { class: "mono" }, vt(v))))),
      ),
      h("p", { class: "validity muted" }, "Valid for ", until(p.validUntil)),
      h("div", { class: "actions" }, this.cancelButton(), confirm),
    );
  }

  /** Runs inside the tap: the passkey prompt starts before any other await. */
  private confirm(seq: number, p: PreparedAction, btn: HTMLButtonElement): void {
    if (!this.current(seq) || this.step !== "confirm" || Date.now() > p.validUntil) return;
    btn.disabled = true;
    const isPasskey = p.target.object === "passkey";
    // Both start with auth.get(...) synchronously, i.e. still inside the user gesture.
    const run = isPasskey ? authorizeAddPasskey(this.app.api, this.app.auth, p) : completeAction(this.app.api, this.app.auth, p);
    // From here the signed action may reach the server: no Cancel, no Escape, until it settles.
    this.step = "signing";
    this.render(
      h("h2", { id: "sheet-title" }, "Waiting for your passkey"),
      h("p", { class: `headline ${p.choice.action === "approve" || p.choice.action === "add" ? "pos" : "neg"}` }, renderParts(p.description.headlineParts)),
      h("p", { class: "spinner", role: "status" }, "Confirm on your device. This closes by itself."),
    );
    run.then(
      (res) => {
        this.app.changed();
        if (this.step === "signing") this.step = "done";
        if (!this.current(seq)) return;
        if (isPasskey) this.showCreatePasskey(seq, res as PreparedRegistration);
        else this.showDone(p, res);
      },
      (e) => {
        this.app.changed();
        if (this.step === "signing") this.step = "error";
        if (!this.current(seq)) return;
        this.showError(e);
      },
    );
  }

  private showCreatePasskey(seq: number, reg: PreparedRegistration): void {
    this.step = "create";
    const create = h("button", { class: "btn approve big", type: "button", "data-autofocus": "" }, "Create the new passkey");
    create.addEventListener("click", () => {
      if (!this.current(seq)) return;
      create.disabled = true;
      completeRegistration(this.app.api, this.app.auth, reg).then(
        () => {
          this.app.changed();
          if (!this.current(seq)) return;
          this.step = "done";
          this.render(h("h2", { id: "sheet-title", class: "ok" }, "Passkey added"), h("p", null, "You can now sign in and approve with it."), h("div", { class: "actions" }, h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Done")));
        },
        (e) => {
          if (this.current(seq)) this.showError(e);
        },
      );
    });
    this.render(
      h("h2", { id: "sheet-title" }, "Create the new passkey"),
      h("p", null, "Approved. Now create the passkey, on this device or another one through the browser's options (QR code, security key)."),
      h("div", { class: "actions" }, this.cancelButton(), create),
    );
  }

  private showDone(p: PreparedAction, res: unknown): void {
    this.step = "done";
    const c = p.canonical;
    const r = (res && typeof res === "object" ? res : {}) as { status?: unknown; grant?: { not_after?: unknown } };
    const expected: Record<string, string> = { approve: "approved", deny: "denied" };
    const want = c.object === "request" || c.object === "enrollment" ? expected[c.action] : undefined;
    const status = typeof r.status === "string" ? r.status : undefined;
    const done = h("button", { class: "btn big", type: "button", "data-autofocus": "", on: { click: () => this.close() } }, "Done");

    if (want && status && status !== want) {
      this.render(
        h("h2", { id: "sheet-title", class: "neg" }, "Check this"),
        h("p", null, `aqmas accepted your passkey but reports the ${c.object} as "${vt(status)}", not "${want}".`),
        h("div", { class: "actions" }, done),
      );
      return;
    }
    const words: Record<string, string> = { approve: "Approved", deny: "Denied", revoke: "Revoked" };
    const lines: Child[] = [];
    if (c.object === "grant" && c.kind === "cloudflare")
      lines.push(
        c.mode === "token"
          ? "Revoked, with any auto-approval that issued it or came with it. aqmas deletes the API token at Cloudflare now."
          : "Revoked, with any auto-approval that issued it or came with it. The aqmas proxy refuses it from the next call.",
      );
    else if (c.object === "grant")
      lines.push("Marked revoked, with any auto-approval that issued it or came with it. aqmas on the host stops reusing it; the certificate itself stays valid until it expires (no revocation list yet).");
    else if (c.object === "request" && c.action === "approve" && c.kind === "cloudflare") {
      const notAfter = typeof r.grant?.not_after === "string" ? new Date(r.grant.not_after) : null;
      lines.push(
        h(
          "span",
          null,
          h("bdi", null, vt(c.requesting_host ?? "The host")),
          " has the Cloudflare grant ",
          h("span", { class: "mono" }, vt(c.scope ?? "?")),
          notAfter && Number.isFinite(notAfter.getTime()) ? ` until ${notAfter.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.` : ` for ${duration(c.ttl_seconds ?? 0)}.`,
        ),
      );
      if (c.mode === "token") lines.push("The API token is handed to the host once, on its next poll.");
    }
    else if (c.object === "standing") lines.push("Matching requests need your approval again.");
    else if (c.object === "enrollment" && c.action === "approve") lines.push(h("span", null, h("bdi", null, vt(c.requesting_host ?? "The host")), " can now ask for access."));
    else if (c.object === "request" && c.action === "approve") {
      const notAfter = typeof r.grant?.not_after === "string" ? new Date(r.grant.not_after) : null;
      lines.push(
        h(
          "span",
          null,
          h("bdi", null, vt(c.requesting_host ?? "The host")),
          " can now use ",
          h("bdi", null, vt(c.login_user ?? "?")),
          "@",
          h("bdi", null, vt(c.target ?? "?")),
          notAfter && Number.isFinite(notAfter.getTime()) ? ` until ${notAfter.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.` : ` for ${duration(c.ttl_seconds ?? 0)}.`,
        ),
      );
    }
    this.render(
      h("h2", { id: "sheet-title", class: c.action === "approve" ? "ok" : "neg" }, words[c.action] ?? "Done"),
      h("p", { class: "headline" }, renderParts(p.description.headlineParts)),
      lines.map((l) => h("p", null, l)),
      h("div", { class: "actions" }, done),
    );
  }

  private showError(e: unknown): void {
    this.step = "error";
    const msg = explainError(e);
    const again = this.retry;
    this.render(
      h("h2", { id: "sheet-title", class: "neg" }, e instanceof FlowError ? "Not signed" : "That didn't work"),
      h("p", { class: "error", role: "alert" }, vt(msg)),
      h(
        "p",
        { class: "muted" },
        nothingChanged(e) ? "Nothing was changed." : "It may or may not have gone through. Check the list, which updates by itself.",
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Close"),
        again ? h("button", { class: "btn approve", type: "button", on: { click: () => again() } }, "Start again") : null,
      ),
    );
  }
}
