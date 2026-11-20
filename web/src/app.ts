// The approval UI. Rendering only; the security-relevant logic lives in flows.ts,
// canonical.ts and webauthn.ts.
//
// Untrusted text (reason, requester fields, and for safety every server string) is shown
// through text nodes only, with invisible/bidi characters made visible (visibleText).

import { ApiError, createApi, type Api } from "./api";
import { FILTERS, actor, classify, detailUntrusted, groupByDay, matches, objectRef, rowKey, type Filter } from "./audit";
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
  nicknameProblem,
  nothingChanged,
  prepareAction,
  prepareLogin,
  prepareRegistrationWithCode,
  targetForGrant,
  targetForPasskey,
  targetForPending,
  targetForStanding,
  type ActionChoice,
  type ActionTarget,
  type PreparedAction,
  type PreparedLogin,
  type PreparedRegistration,
} from "./flows";
import {
  STANDING_PRESETS,
  absoluteTime,
  ago,
  countdown,
  dayLabel,
  duration,
  eventTime,
  hours,
  isPlainName,
  kindLabel,
  shortDate,
  ttlChoices,
  visibleText as vt,
} from "./format";
import { chevronIcon, eventIcon, passkeyIcon, syncIcon } from "./icons";
import type { AuditEntry, GrantSummary, PasskeyChange, PasskeyInfo, PendingItem, RegisterResult, StandingApproval, UIState } from "./types";
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
  /** Activity filter and which rows are expanded (kept across re-renders). */
  private filter: Filter = "all";
  private expanded = new Set<string>();
  private evSeq = 0;

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
      case "passkey":
        return t.id === "new" || s.passkeys === undefined ? undefined : (s.passkeys ?? []).some((p) => p.id === t.id);
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

  isCurrentPasskey(id: string): boolean {
    return (this.state?.passkeys ?? []).some((p) => p.id === id && p.current);
  }

  /** The session ended because its passkey was removed: back to sign-in with a message. */
  signedOut(message: string): void {
    this.sheet.close(true);
    this.showSignin(message);
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
      h("p", null, "Register this device's passkey with a one-time code. On the aqmasd host, as root or the aqmas user, run:"),
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
    const filters = h(
      "div",
      { class: "filters", role: "group", "aria-label": "Show activity" },
      FILTERS.map((f) =>
        h(
          "button",
          {
            class: "filter",
            type: "button",
            "data-filter": f.id,
            "aria-pressed": String(f.id === this.filter),
            on: { click: () => this.setFilter(f.id) },
          },
          f.label,
        ),
      ),
    );
    replace(
      this.root,
      h("header", { class: "topbar" }, h("h1", { class: "brand" }, "aqmas"), h("p", { class: "status", id: "status" })),
      h(
        "main",
        { class: "sections" },
        h("div", { class: "col col-queue" }, section("pending", "Waiting for you"), section("enroll", "Hosts asking to join")),
        h(
          "div",
          { class: "col col-access" },
          section("grants", "Active access", "tiles"),
          section("standing", "Auto-approvals", "tiles"),
          section("passkeys", "Passkeys"),
        ),
        h("aside", { class: "col col-activity", "aria-labelledby": "sec-recent-h" }, section("recent", "Recent activity", "", filters)),
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
    const shown = this.shownIds();
    this.section("recent", [s.recent, this.filter, [...shown].sort()], () => this.activity(s.recent!, shown), false, false, 0);
    this.section("passkeys", [s.owner, s.passkeys], () => this.passkeys(s), false, touching, 0);
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

  /** Ids of every card on the page (activity rows link to these). */
  private shownIds(): Set<string> {
    const s = this.state;
    const out = new Set<string>();
    if (!s) return out;
    for (const p of s.pending ?? []) out.add(p.id);
    for (const a of s.standing ?? []) out.add(a.id);
    for (const g of s.grants ?? []) if (g.status === "approved") out.add(g.id);
    for (const p of s.passkeys ?? []) out.add(p.id);
    return out;
  }

  private setFilter(f: Filter): void {
    this.filter = f;
    for (const b of this.root.querySelectorAll<HTMLElement>(".filters .filter")) b.setAttribute("aria-pressed", String(b.dataset["filter"] === f));
    this.renderSections();
  }

  /** Scroll to a card and highlight it for a moment. */
  private jumpTo(id: string): void {
    const el = this.root.querySelector<HTMLElement>(`[data-id="${CSS.escape(id)}"]`);
    if (!el) return;
    for (const f of this.root.querySelectorAll(".focus")) f.classList.remove("focus");
    el.classList.add("focus");
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    const btn = el.querySelector<HTMLElement>("button");
    btn?.focus({ preventScroll: true });
    window.setTimeout(() => el.classList.remove("focus"), 2500);
  }

  // ---- activity ----

  private activity(entries: AuditEntry[], shown: Set<string>): Child[] {
    if (!entries.length) return [h("p", { class: "empty" }, "No activity yet.")];
    const list = entries.filter((e) => matches(e, this.filter));
    if (!list.length) return [h("p", { class: "empty" }, "Nothing of this kind in the recent activity.")];
    const now = Date.now();
    return groupByDay(list).map((g) => {
      const label = dayLabel(g.at, now);
      return h(
        "section",
        { class: "ev-day", "aria-label": label },
        h("h3", { class: "ev-day-h" }, h("time", { datetime: g.key }, label)),
        h("ol", { class: "ev-list" }, g.entries.map((e) => this.eventRow(e, shown, now))),
      );
    });
  }

  private eventRow(e: AuditEntry, shown: Set<string>, now: number): HTMLElement {
    const info = classify(e);
    const who = actor(e.actor);
    const obj = objectRef(e.object);
    const key = rowKey(e);
    const open = this.expanded.has(key);
    const at = new Date(e.at).getTime();
    const moreId = `ev-${++this.evSeq}`;
    const linkable = obj.id !== "" && shown.has(obj.id);

    const untrusted = detailUntrusted(e);
    const more = h(
      "div",
      { class: "ev-more", id: moreId, hidden: !open },
      h(
        "dl",
        { class: "facts" },
        fact("When", absoluteTime(at)),
        fact("By", h("bdi", { class: "mono" }, vt(e.actor))),
        e.object ? fact("About", h("span", { class: "mono" }, vt(e.object))) : null,
      ),
      e.detail
        ? untrusted
          ? h(
              "div",
              { class: "agent ev-detail", role: "group", "aria-label": "Details, may include text a host sent (unverified)" },
              h("p", { class: "agent-label" }, "Details", h("span", { class: "muted" }, ", may include text a host sent (unverified)")),
              h("p", { class: "mono", dir: "ltr" }, vt(e.detail)),
            )
          : h("p", { class: "ev-detail-plain mono" }, vt(e.detail))
        : null,
      linkable ? h("button", { class: "btn small", type: "button", on: { click: () => this.jumpTo(obj.id) } }, `Show the ${vt(obj.short)} card`) : null,
    );
    const toggle = h(
      "button",
      { class: "ev-toggle", type: "button", "aria-expanded": String(open), "aria-controls": moreId },
      h("span", { class: "ev-glyph" }, eventIcon(info.kind)),
      h("span", { class: "ev-label" }, vt(info.label)),
      h("span", { class: `actor actor-${who.kind}` }, who.kind === "host" ? [h("span", { class: "sr" }, "host "), h("bdi", null, vt(who.name))] : vt(who.name)),
      obj.short ? h("span", { class: "ev-obj" }, vt(obj.short)) : null,
      h("time", { class: "ev-time", datetime: e.at, title: absoluteTime(at), "data-ev-at": String(at) }, eventTime(at, now)),
      chevronIcon(),
    );
    toggle.addEventListener("click", () => {
      const nowOpen = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(nowOpen));
      more.hidden = !nowOpen;
      if (nowOpen) this.expanded.add(key);
      else this.expanded.delete(key);
    });
    return h(
      "li",
      { class: `ev ev-${info.kind}` },
      h(
        "div",
        { class: "ev-line" },
        toggle,
        linkable
          ? h(
              "button",
              { class: "ev-jump", type: "button", "aria-label": `Show the ${vt(obj.short)} card`, on: { click: () => this.jumpTo(obj.id) } },
              "Show",
            )
          : null,
      ),
      more,
    );
  }

  // ---- passkeys ----

  private passkeys(s: UIState): Child[] {
    const list = s.passkeys;
    const add = h("button", { class: "btn", type: "button", on: { click: () => this.sheet.openAddPasskey() } }, "Add a passkey");
    const signedIn = h("p", { class: "muted" }, "Signed in as ", h("bdi", null, vt(s.owner.name)), ".");
    if (list === undefined || list === null) {
      // Older server: only the count.
      return [
        h("p", null, `Signed in as ${vt(s.owner.name)}. `, s.owner.passkeys === 1 ? "1 passkey is registered." : `${s.owner.passkeys} passkeys are registered.`),
        add,
      ];
    }
    const only = list.length <= 1;
    return [
      h("div", { class: "tiles" }, list.map((p) => this.passkeyTile(p, only))),
      only ? h("p", { class: "muted" }, "Add a second passkey (another password manager or a hardware key) so you can still get in if you lose this one.") : null,
      h("div", { class: "pk-foot" }, add, signedIn),
    ];
  }

  private passkeyTile(p: PasskeyInfo, only: boolean): HTMLElement {
    const synced = p.backup_eligible === true;
    const transports = (p.transports ?? []).map(transportLabel).filter((t) => t !== "");
    return h(
      "article",
      { class: `row pk${p.current ? " current" : ""}`, "data-id": p.id, "aria-label": `Passkey ${vt(p.nickname)}` },
      h(
        "div",
        { class: "pk-head" },
        h("span", { class: "pk-icon" }, passkeyIcon(p.icon)),
        h(
          "div",
          { class: "pk-names" },
          h("h3", { class: "pk-name" }, h("bdi", null, vt(p.nickname))),
          h("p", { class: "pk-auth" }, vt(p.authenticator || "Unknown authenticator")),
        ),
      ),
      h(
        "div",
        { class: "badges" },
        h(
          "span",
          {
            class: `badge ${synced ? "synced" : "bound"}`,
            title: synced ? "Synced: the password manager copies it to your other devices" : "Device-bound: it never leaves this authenticator",
          },
          syncIcon(synced),
          synced ? "Synced" : "Device-bound",
        ),
        p.current ? h("span", { class: "badge this", title: "You signed in with this passkey" }, "This device") : null,
      ),
      h(
        "dl",
        { class: "facts" },
        fact("Added", h("time", { datetime: p.created_at, title: absoluteTime(p.created_at) }, shortDate(p.created_at))),
        fact("Last used", p.last_used_at ? since(p.last_used_at) : h("span", { class: "muted" }, "never")),
        transports.length ? fact("Connects by", transports.join(", ")) : null,
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", type: "button", on: { click: () => this.sheet.openRename(p) } }, "Rename…"),
        h(
          "button",
          {
            class: "btn deny",
            type: "button",
            disabled: only,
            title: only ? "Your only passkey can't be removed" : undefined,
            on: { click: () => this.sheet.openRemove(p) },
          },
          "Remove…",
        ),
      ),
      only ? h("p", { class: "muted small" }, "Your only passkey can't be removed. Add another first.") : null,
    );
  }

  /** Re-render a section only when its data changed (keeps scroll/focus stable while polling). */
  private section(name: string, data: unknown, build: () => Child[], hidden = false, defer = false, count?: number): void {
    const key = JSON.stringify(data) ?? "undefined";
    const sec = $(`#sec-${name}`, this.root);
    if (this.rendered.get(name) === key) return;
    if (defer && this.rendered.has(name)) return;
    sec.hidden = hidden;
    this.rendered.set(name, key);
    const list = $(".list", sec);
    replace(list, build());
    const countEl = sec.querySelector(".count");
    const n = count ?? (Array.isArray(data) ? data.length : 0);
    if (countEl) countEl.textContent = n > 0 ? String(n) : "";
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
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-ev-at]")) t.textContent = eventTime(Number(t.dataset["evAt"]), now);
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
      this.rendered.get("grants") !== (JSON.stringify(s.grants) ?? "undefined") ||
      this.rendered.get("passkeys") !== JSON.stringify([s.owner, s.passkeys]);
    if (stale) this.renderSections();
  }

  // ---- cards ----

  private requestCard(p: PendingItem): HTMLElement {
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

function section(name: string, title: string, listClass = "", extra?: Child): HTMLElement {
  return h(
    "section",
    { id: `sec-${name}`, class: "section", "aria-labelledby": `sec-${name}-h` },
    h("div", { class: "section-head" }, h("h2", { id: `sec-${name}-h` }, title, " ", h("span", { class: "count" })), extra),
    h("div", { class: listClass ? `list ${listClass}` : "list" }),
  );
}

const TRANSPORTS: Record<string, string> = {
  usb: "USB",
  nfc: "NFC",
  ble: "Bluetooth",
  internal: "built in",
  hybrid: "phone (QR code)",
  "smart-card": "smart card",
};

function transportLabel(t: string): string {
  return TRANSPORTS[t] ?? vt(t);
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

function isNegative(action: string): boolean {
  return action === "deny" || action === "revoke" || action === "remove";
}

function passkeySummary(p: PasskeyInfo): HTMLElement {
  return h(
    "div",
    { class: "summary pk-head" },
    h("span", { class: "pk-icon" }, passkeyIcon(p.icon)),
    h("div", { class: "pk-names" }, h("p", { class: "pk-name" }, h("bdi", null, vt(p.nickname))), h("p", { class: "pk-auth" }, vt(p.authenticator))),
  );
}

/** A labelled nickname input with a hint and an error line. */
function nicknameField(id: string, value: string, placeholder: string) {
  const input = h("input", {
    id,
    type: "text",
    class: "text",
    value,
    autocomplete: "off",
    spellcheck: "false",
    maxlength: "64",
    enterkeyhint: "go",
    placeholder: placeholder || undefined,
    "data-autofocus": "",
    "aria-describedby": `${id}-hint ${id}-err`,
  });
  const error = h("p", { class: "error", id: `${id}-err`, role: "alert" });
  input.addEventListener("input", () => (error.textContent = ""));
  const field = (label: string, hint: string) =>
    h("div", { class: "field" }, h("label", { for: id }, label), input, h("p", { class: "hint muted", id: `${id}-hint` }, hint));
  return { input, error, field };
}

// ---- the decision sheet ----

type Step = "choose" | "working" | "confirm" | "signing" | "create" | "done" | "error";

class Sheet {
  private dlg: HTMLDialogElement;
  private body: HTMLElement;
  private step: Step | null = null;
  private target: ActionTarget | null = null;
  private prepared: PreparedAction | null = null;
  /** Nickname chosen for a passkey being added ("" = let the server name it). */
  private addNickname = "";
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
    const { options, def } = ttlChoices(p.ttl_requested, p.ttl_max);
    const ttlSet = h(
      "fieldset",
      { class: "chips" },
      h("legend", null, "How long"),
      options.map((t) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "ttl", value: String(t), checked: t === def }), h("span", null, duration(t), t === p.ttl_requested ? h("small", null, " requested") : null)),
      ),
    );
    // aqmasd refuses standing approvals for high-risk requests (high_risk target, root, > 4 h).
    const standSet = p.risk === "high" ? null : h(
      "fieldset",
      { class: "chips" },
      h("legend", null, "Also auto-approve the same request (", h("bdi", null, vt(p.requesting_host)), " to ", h("bdi", null, vt(p.ssh?.login_user ?? "?")), "@", h("bdi", null, vt(p.ssh?.target_host ?? "?")), ")"),
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
    this.render(h("h2", { id: "sheet-title" }, "Approve access"), this.summary(p), ttlSet, standSet, h("div", { class: "actions" }, this.cancelButton(), go));
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
    const seq = this.begin(target);
    this.step = "choose";
    this.addNickname = "";
    const { input, error, field } = nicknameField("pk-new-name", "", "e.g. YubiKey on keyring");
    const go = h("button", { class: "btn approve", type: "button" }, "Continue");
    const submit = () => {
      const name = input.value.trim();
      const problem = name ? nicknameProblem(name) : null;
      if (problem) {
        error.textContent = problem;
        input.focus();
        return;
      }
      this.addNickname = name;
      void this.prepare(seq, target, { action: "add" }, () => this.openAddPasskey());
    };
    go.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
    this.render(
      h("h2", { id: "sheet-title" }, "Add a passkey"),
      h("p", null, "First confirm with a passkey you already have. Then create the new one, on this device or another (the browser offers a QR code or a security key)."),
      field("Name (optional)", "Leave it empty to name it after its password manager or key, like “Bitwarden”."),
      error,
      h("div", { class: "actions" }, this.cancelButton(), go),
    );
  }

  openRename(p: PasskeyInfo): void {
    const target = targetForPasskey(p);
    const seq = this.begin(target);
    this.step = "choose";
    const { input, error, field } = nicknameField("pk-rename", p.nickname, "");
    const go = h("button", { class: "btn approve", type: "button" }, "Continue");
    const submit = () => {
      const name = input.value.trim();
      const problem = nicknameProblem(name) ?? (name === p.nickname ? "That is already its name." : null);
      if (problem) {
        error.textContent = problem;
        input.focus();
        return;
      }
      void this.prepare(seq, target, { action: "rename", nickname: name }, () => this.openRename(p));
    };
    go.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
    this.render(
      h("h2", { id: "sheet-title" }, "Rename passkey"),
      passkeySummary(p),
      field("New name", "Names are unique. Pick one that tells you where the passkey lives."),
      error,
      h("div", { class: "actions" }, this.cancelButton(), go),
    );
    input.select();
  }

  openRemove(p: PasskeyInfo): void {
    const target = targetForPasskey(p);
    const seq = this.begin(target);
    if (!p.current) {
      void this.prepare(seq, target, { action: "remove" }, () => this.openRemove(p));
      return;
    }
    this.step = "choose";
    const go = h("button", { class: "btn deny", type: "button" }, "Continue");
    go.addEventListener("click", () => void this.prepare(seq, target, { action: "remove" }, () => this.openRemove(p)));
    this.render(
      h("h2", { id: "sheet-title" }, "Remove the passkey you signed in with?"),
      passkeySummary(p),
      h("p", { class: "warn" }, "You signed in with this passkey. Removing it signs you out here; sign in again with another passkey."),
      h("div", { class: "actions" }, this.cancelButton(), go),
    );
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
    const negative = isNegative(p.choice.action);
    const removingCurrent = p.canonical.object === "passkey" && p.canonical.action === "remove" && this.app.isCurrentPasskey(p.target.id);
    const confirm = h("button", { class: `btn confirm big ${negative ? "deny" : "approve"}`, type: "button", "data-autofocus": "" }, "Confirm with passkey");
    confirm.addEventListener("click", () => this.confirm(seq, p, confirm));
    this.render(
      h("h2", { id: "sheet-title" }, "Check, then confirm"),
      h("p", { class: `headline ${negative ? "neg" : "pos"}` }, renderParts(d.headlineParts)),
      d.standingParts ? h("p", { class: "warn" }, renderParts(d.standingParts)) : null,
      d.warnings.map((w) => h("p", { class: "warn" }, vt(w))),
      removingCurrent ? h("p", { class: "warn" }, "This is the passkey you signed in with: you will be signed out here.") : null,
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
    const isAdd = p.target.object === "passkey" && p.canonical.action === "add";
    // Both start with auth.get(...) synchronously, i.e. still inside the user gesture.
    const run = isAdd ? authorizeAddPasskey(this.app.api, this.app.auth, p) : completeAction(this.app.api, this.app.auth, p);
    // From here the signed action may reach the server: no Cancel, no Escape, until it settles.
    this.step = "signing";
    this.render(
      h("h2", { id: "sheet-title" }, "Waiting for your passkey"),
      h("p", { class: `headline ${isNegative(p.choice.action) ? "neg" : "pos"}` }, renderParts(p.description.headlineParts)),
      h("p", { class: "spinner", role: "status" }, "Confirm on your device. This closes by itself."),
    );
    run.then(
      (res) => {
        if (this.step === "signing") this.step = "done";
        const change = res as Partial<PasskeyChange> | null;
        if (p.target.object === "passkey" && change && change.signed_out === true) {
          // The removed passkey was this session's: the server ended the session.
          this.app.signedOut(`Removed the passkey “${vt(p.canonical.nickname ?? "")}”. You signed in with it, so sign in again with another passkey.`);
          return;
        }
        this.app.changed();
        if (!this.current(seq)) return;
        if (isAdd) this.showCreatePasskey(seq, res as PreparedRegistration);
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
      completeRegistration(this.app.api, this.app.auth, reg, this.addNickname).then(
        (res) => {
          this.app.changed();
          if (!this.current(seq)) return;
          this.step = "done";
          const pk = (res && typeof res === "object" ? (res as RegisterResult).passkey : undefined) ?? undefined;
          this.render(
            h("h2", { id: "sheet-title", class: "ok" }, "Passkey added"),
            pk && typeof pk.nickname === "string"
              ? h("p", null, "It's called ", h("bdi", { class: "val" }, vt(pk.nickname)), " (", vt(pk.authenticator || "Unknown authenticator"), "). You can rename it in the Passkeys list.")
              : null,
            h("p", null, "You can now sign in and approve with it."),
            h("div", { class: "actions" }, h("button", { class: "btn", type: "button", "data-autofocus": "", on: { click: () => this.close() } }, "Done")),
          );
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
    const words: Record<string, string> = { approve: "Approved", deny: "Denied", revoke: "Revoked", rename: "Renamed", remove: "Removed" };
    const lines: Child[] = [];
    if (c.object === "grant")
      lines.push("Marked revoked, with any auto-approval that issued it or came with it. aqmas on the host stops reusing it; the certificate itself stays valid until it expires (no revocation list yet).");
    else if (c.object === "standing") lines.push("Matching requests need your approval again.");
    else if (c.object === "passkey" && c.action === "remove") lines.push("It can no longer sign in or approve anything here. Delete it from its password manager or key too if you no longer need it.");
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
      h("h2", { id: "sheet-title", class: c.action === "approve" || c.action === "rename" ? "ok" : "neg" }, words[c.action] ?? "Done"),
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
