// Access to the bastion itself (docs/BASTION-ACCESS.md §6, §7, §10): the red root card, the
// inspect card, the card of a maintenance task an agent queued, the banner while a root
// certificate is valid, and Admin → Bastion access. Rendering only: what is signed is checked
// in canonical.ts, flows.ts and setup.ts, and the confirmation is always drawn from the
// signed text.

import { ApiError, type Api } from "./api";
import { type BastionFacts, BASTION_ROOT_MAX_SECONDS, INSPECT_NOTE, ROOT_ALERT, ROOT_CLOSE_LABEL, ROOT_CONSEQUENCES, ROOT_NO_ALERT, ROOT_TITLE, ROOT_UNSEALED } from "./canonical";
import { h, replace, type Child } from "./dom";
import { explainError, nothingChanged, targetForGrant, type ActionTarget } from "./flows";
import { absoluteTime, ago, countdown, duration, isPlainName, ttlChoices, visibleText as vt } from "./format";
import { warningIcon } from "./icons";
import { completeSetupTask, paramLines, prepareSetupTask, queuedParams, type PreparedSetup, type SetupTask, type SetupView } from "./setup";
import { Invalid, SetupPage, type Collected } from "./setupPage";
import type { BastionDecision, BastionHost, BastionSession, BastionView, PendingItem } from "./types";
import type { Authenticator } from "./webauthn";

const clock = (iso: string | number) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/** The loud heading of everything about root on the bastion: icon and words, never colour alone. */
export function rootBand(text: string = ROOT_TITLE): HTMLElement {
  return h("p", { class: "root-band", role: "note" }, warningIcon(), h("strong", null, text));
}

/** "Open right now": the buckets a root session could read. `open` comes from the signed
 * text on the confirmation, and from the card (a preview, re-read before signing) elsewhere. */
export function openBucketsBlock(sealed: boolean, open: readonly string[]): HTMLElement {
  if (!sealed) return h("p", { class: "root-open" }, vt(ROOT_UNSEALED));
  if (open.length === 0) return h("p", { class: "root-open" }, h("strong", null, "Open right now: "), "No bucket is open.");
  return h("div", { class: "root-open" }, h("p", null, h("strong", null, `Open right now (${open.length}):`)), h("ul", { class: "root-open-list" }, open.map((l) => h("li", null, h("bdi", null, vt(l))))));
}

export function alertLine(alert: boolean): HTMLElement {
  return alert ? h("p", { class: "root-alert" }, ROOT_ALERT) : h("p", { class: "root-alert none" }, h("strong", null, ROOT_NO_ALERT));
}

export interface BastionCardHooks {
  approve(p: PendingItem): void;
  deny(p: PendingItem): void;
  /** Shared pieces of every request card. */
  agentSays(p: PendingItem): HTMLElement;
  until(iso: string): HTMLElement;
  since(iso: string): HTMLElement;
  ref(id: string): string;
}

/** A pending bastion request: the red root card or the ordinary inspect card. */
export function bastionCard(p: PendingItem, k: BastionCardHooks): HTMLElement {
  const b = p.bastion;
  const level = b?.level ?? "unknown";
  const root = level === "root";
  const known = root || level === "inspect";
  const odd = !isPlainName(p.requesting_host) || (b && (!isPlainName(b.login_user) || !isPlainName(b.target)));
  const facts = h(
    "dl",
    { class: "facts" },
    h("dt", null, "From"),
    h("dd", null, h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
    h("dt", null, "Asks for"),
    h("dd", null, duration(p.ttl_requested), root ? h("span", { class: "muted" }, ` (a root session lasts at most ${duration(BASTION_ROOT_MAX_SECONDS)})`) : null),
    b ? [h("dt", null, "Address"), h("dd", null, h("bdi", null, vt(b.target_address)), ` · port ${b.target_port}`)] : null,
    b ? [h("dt", null, "Principal"), h("dd", null, h("bdi", null, vt(b.principal)))] : null,
    b ? [h("dt", null, "Key"), h("dd", null, h("span", { class: "mono" }, vt(b.key_fingerprint)))] : null,
    p.similar_recent > 0 ? [h("dt", null, "Similar"), h("dd", null, p.similar_recent === 1 ? "1 similar request recently" : `${p.similar_recent} similar requests recently`)] : null,
    h("dt", null, "Asked"),
    h("dd", null, k.since(p.created_at)),
    h("dt", null, "Ref"),
    h("dd", null, h("span", { class: "mono" }, vt(k.ref(p.id)))),
  );
  const who = h("h3", { class: "target" }, h("bdi", { class: "user" }, vt(b?.login_user ?? "?")), h("span", { class: "at" }, "@"), h("bdi", { class: "host" }, vt(b?.target ?? "?")));
  const actions = h(
    "div",
    { class: "actions" },
    h("button", { class: "btn deny", type: "button", on: { click: () => k.deny(p) } }, "Deny…"),
    h(
      "button",
      { class: `btn approve${root ? " root" : ""}`, type: "button", disabled: !known, title: known ? undefined : "Access to the bastion is no longer installed: this can only be denied", on: { click: () => k.approve(p) } },
      root ? "Approve root session…" : "Approve…",
    ),
  );
  if (root) {
    return h(
      "article",
      { class: "card request bastion bastion-root", "data-id": p.id, "data-level": "root", "aria-label": `Root on the bastion requested by ${vt(p.requesting_host)}` },
      rootBand(),
      h("div", { class: "card-top" }, h("span", { class: "kind" }, "Bastion"), h("span", { class: "risk" }, "Root"), h("span", { class: "expires" }, "Expires in ", k.until(p.expires_at))),
      h("p", { class: "root-ask" }, h("bdi", { class: "host-name" }, vt(p.requesting_host)), " asks to log in to ", h("bdi", null, vt(b?.target ?? "?")), " as ", h("bdi", null, vt(b?.login_user ?? "?")), ` (your admin account, sudo) for ${duration(p.ttl_requested)}.`),
      h("p", { class: "root-consequences" }, ROOT_CONSEQUENCES),
      openBucketsBlock(b?.sealed === true, b?.open_buckets ?? []),
      b?.sealed ? h("p", { class: "muted" }, "You choose on the next step whether to close them first (the default).") : null,
      alertLine(b?.alert_channel === true),
      odd ? h("p", { class: "warn" }, "A name here contains unusual characters. Check it letter by letter.") : null,
      facts,
      k.agentSays(p),
      actions,
    );
  }
  return h(
    "article",
    { class: "card request bastion bastion-inspect", "data-id": p.id, "data-level": vt(level), "aria-label": `Bastion inspect request from ${vt(p.requesting_host)}` },
    h("div", { class: "card-top" }, h("span", { class: "kind" }, "Bastion"), h("span", { class: "badge" }, known ? "Inspect (read-only)" : "Unknown level"), h("span", { class: "expires" }, "Expires in ", k.until(p.expires_at))),
    who,
    known ? h("p", null, INSPECT_NOTE) : h("p", { class: "warn" }, "Access to the bastion is no longer installed, or this page does not know this level. It can only be denied."),
    odd ? h("p", { class: "warn" }, "A name here contains unusual characters. Check it letter by letter.") : null,
    facts,
    k.agentSays(p),
    actions,
  );
}

/** What happened to an approved bastion decision (the server's BastionDecision). */
export function decisionLines(c: Record<string, unknown>, r: Partial<BastionDecision>): HTMLElement[] {
  if (c.level !== "root") return [h("p", null, "The inspect certificate is on its way to the host. It can only run the fixed log and status commands.")];
  const out: HTMLElement[] = [];
  if (c.sealed === true) {
    out.push(
      c.close_buckets === true
        ? h("p", { class: "root-result" }, h("strong", null, typeof r.closed_count === "number" ? `${r.closed_count} bucket${r.closed_count === 1 ? "" : "s"} closed` : "Buckets closed"), " before the certificate was issued. Approval windows ended.")
        : h("p", { class: "warn" }, "Open buckets were left open: the root session can read them."),
    );
  }
  out.push(
    r.alert === "sent"
      ? h("p", { class: "root-result" }, "Alert sent.")
      : r.alert === "failed"
        ? h("p", { class: "breakglass", role: "alert" }, "ALERT NOT DELIVERED: the push service did not accept it. The session proceeds.")
        : h("p", { class: "breakglass", role: "alert" }, "No alert channel is configured: nobody was alerted."),
  );
  out.push(h("p", null, "The certificate is handed to the host once. It cannot be recalled; revoking only stops a certificate that was not collected yet."));
  return out;
}

/** The banner on every page while a root certificate for the bastion is valid. */
export function rootBanner(until: string | undefined, now = Date.now()): HTMLElement | null {
  const at = until ? Date.parse(until) : NaN;
  if (!Number.isFinite(at) || at <= now) return null;
  return h(
    "div",
    { class: "root-banner", role: "alert", id: "root-banner" },
    warningIcon(),
    h("p", null, h("strong", null, `A root certificate for the bastion is valid until ${clock(at)}.`), " Whatever you open now is readable by that session; a session can outlast its certificate."),
  );
}

/** Keep the banner under the top bar in step with the state (called on every render). */
export function syncRootBanner(root: HTMLElement, until: string | undefined): void {
  const old = root.querySelector<HTMLElement>(":scope > #root-banner");
  if ((old?.dataset["rootUntil"] ?? "") === (until ?? "")) return;
  old?.remove();
  const el = rootBanner(until);
  if (!el) return;
  el.dataset["rootUntil"] = until;
  root.insertBefore(el, root.querySelector(":scope > header.topbar")?.nextSibling ?? null);
}

/** The summary at the top of the approval sheet. */
export function bastionSummary(p: PendingItem): HTMLElement {
  const b = p.bastion;
  const root = b?.level === "root";
  return h(
    "div",
    { class: `summary${root ? " root-summary" : ""}` },
    root ? rootBand() : null,
    h("h3", { class: "target" }, h("bdi", { class: "user" }, vt(b?.login_user ?? "?")), h("span", { class: "at" }, "@"), h("bdi", { class: "host" }, vt(b?.target ?? "?"))),
    h("p", null, root ? "Root on the bastion requested by " : "Read-only inspect access to the bastion requested by ", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
    root ? h("p", { class: "root-consequences" }, ROOT_CONSEQUENCES) : h("p", null, INSPECT_NOTE),
  );
}

/** The first step of approving a bastion session: how long, and for root in a sealed store
 * whether to close every open bucket first (ticked by default). No standing or indefinite
 * choice exists. */
export function bastionChoice(p: PendingItem, onContinue: () => void): { title: HTMLElement; body: Child[]; go: HTMLButtonElement; read(): { ttl: number; close: boolean } } {
  const b = p.bastion;
  const root = b?.level === "root";
  const cap = root ? Math.min(p.ttl_requested, BASTION_ROOT_MAX_SECONDS) : p.ttl_requested;
  const { options, def } = ttlChoices(cap, cap);
  const ttlSet = h(
    "fieldset",
    { class: "chips" },
    h("legend", null, "How long"),
    options.map((t) => h("label", { class: "chip" }, h("input", { type: "radio", name: "ttl", value: String(t), checked: t === def }), h("span", null, duration(t), t === p.ttl_requested ? h("small", null, " requested") : null))),
  );
  const close = h("input", { type: "checkbox", id: "root-close", checked: true });
  const go = h("button", { class: `btn approve${root ? " root" : ""}`, type: "button", "data-autofocus": "" }, "Continue");
  go.addEventListener("click", onContinue);
  return {
    title: h("h2", { id: "sheet-title" }, root ? "Approve a root session on the bastion" : "Approve inspect access"),
    body: [
      bastionSummary(p),
      root ? openBucketsBlock(b?.sealed === true, b?.open_buckets ?? []) : null,
      root && b?.sealed ? h("label", { class: "setup-check root-close", for: "root-close" }, close, h("span", null, ROOT_CLOSE_LABEL)) : null,
      root ? alertLine(b?.alert_channel === true) : null,
      ttlSet,
      h("p", { class: "muted" }, "Every bastion session needs its own approval: there is no auto-approval for it."),
    ],
    go,
    read: () => ({ ttl: Number(ttlSet.querySelector<HTMLInputElement>("input:checked")?.value ?? def), close: close.checked }),
  };
}

/** The red block of the confirmation, drawn from the SIGNED text only. Toggling the close
 * choice calls onToggle, which must fetch a fresh challenge (the choice is signed). */
export function rootConfirmBlock(f: BastionFacts, onToggle: (close: boolean) => void): HTMLElement {
  const box = h("input", { type: "checkbox", id: "root-close-signed", checked: f.close });
  box.addEventListener("change", () => onToggle(box.checked));
  return h(
    "div",
    { class: "root-block", role: "group", "aria-label": "Root on the bastion" },
    rootBand(),
    h("p", { class: "root-consequences" }, ROOT_CONSEQUENCES),
    openBucketsBlock(f.sealed, f.open),
    f.sealed ? h("label", { class: "setup-check root-close", for: "root-close-signed" }, box, h("span", null, ROOT_CLOSE_LABEL)) : null,
    f.sealed && !f.close && f.open.length ? h("p", { class: "breakglass" }, "They STAY OPEN: the root session can read them.") : null,
    alertLine(f.alert),
  );
}

// ---- a maintenance task an agent queued (kind "setup") ----

/** Plain words for the task and parameters a queued request asks for; null when this page
 * cannot read them (then it will not approve them either). */
export function queuedSummary(p: PendingItem): { params: Record<string, unknown>; lines: string[] } | null {
  const s = p.setup;
  if (!s) return null;
  try {
    const params = queuedParams(s.task, s.params);
    return { params, lines: paramLines(s.task, params) };
  } catch {
    return null;
  }
}

export interface QueuedHooks {
  agentSays(p: PendingItem): HTMLElement;
  until(iso: string): HTMLElement;
  ref(id: string): string;
  changed(): void;
}

/** Card of a queued maintenance task. Approving it is the Setup page's own flow: the tap
 * signs setup/run for exactly this task and these parameters (a pinned passkey), and the run
 * call names the request so the broker marks it approved. Dismissing is unsigned. */
export function queuedTaskCard(api: Api, auth: Authenticator, p: PendingItem, k: QueuedHooks): HTMLElement {
  const s = p.setup;
  const read = queuedSummary(p);
  const box = h("div", { class: "setup-run queued-run" });
  const steps = s?.steps ?? [];
  // While a step is in flight the app leaves this card alone (it re-renders lists on a poll).
  const busy = (on: boolean) => box.classList.toggle("busy", on);
  const idle = (message = "") => {
    busy(false);
    const err = h("p", { class: "error", role: "alert" }, message);
    const blocked = s?.blocked || (!read ? "This page cannot read this task's parameters, so it will not approve it. Reload the page." : "");
    const go = h("button", { type: "button", class: "btn approve", disabled: !!blocked, title: blocked || undefined }, "Approve…");
    const no = h("button", { type: "button", class: "btn deny" }, "Dismiss");
    go.addEventListener("click", async () => {
      if (!s || !read) return;
      err.textContent = "";
      go.disabled = true;
      go.textContent = "Preparing…";
      busy(true);
      try {
        confirm(await prepareSetupTask(api, {}, s.task, read.params));
      } catch (e) {
        idle(vt(explainError(e)));
      }
    });
    no.addEventListener("click", async () => {
      no.disabled = true;
      busy(true);
      try {
        await api.dismissSetupRequest!(p.id);
        busy(false);
        replace(box, h("p", { class: "muted", role: "status" }, "Dismissed."));
      } catch (e) {
        idle(vt(explainError(e)));
      }
      k.changed();
    });
    replace(box, blocked ? h("p", { class: "warn" }, "Cannot be approved right now: ", vt(blocked)) : null, err, h("div", { class: "actions" }, no, go));
  };
  const confirm = (prep: PreparedSetup) => {
    // The page derived the parameters itself and the challenge was checked against them:
    // prep.params is what the passkey signs. It must be the text the card showed.
    if (prep.params !== s!.params) return idle("Not signing: the task parameters changed.");
    const back = h("button", { type: "button", class: "btn" }, "Back");
    const sign = h("button", { type: "button", class: "btn approve confirm" }, "Confirm with passkey");
    back.addEventListener("click", () => idle());
    sign.addEventListener("click", () => {
      if (Date.now() > prep.validUntil) return idle("That took too long and the request expired. Start again.");
      // The passkey prompt starts synchronously from this tap.
      const done = completeSetupTask(api, auth, prep, p.id);
      replace(box, h("p", { class: "spinner", role: "status" }, "Confirm on your device…"));
      done.then(
        () => {
          busy(false);
          replace(box, h("p", { class: "ok", role: "status" }, "Approved. The maintenance runner carries it out; progress is under Admin → Bastion access."));
          k.changed();
        },
        (e) => {
          const again = h("button", { type: "button", class: "btn" }, "Start again");
          again.addEventListener("click", () => idle());
          busy(false);
          replace(box, h("p", { class: "error", role: "alert" }, vt(e instanceof ApiError && e.message ? e.message : explainError(e))), h("p", { class: "muted" }, nothingChanged(e) ? "Nothing was changed." : "It may or may not have gone through."), h("div", { class: "actions" }, again));
          k.changed();
        },
      );
    });
    replace(
      box,
      h("h4", null, "Check, then confirm"),
      h("p", { class: "headline pos" }, "Run “", h("bdi", { class: "val" }, vt(s!.title)), "” on the bastion."),
      read!.lines.map((l) => h("p", null, vt(l))),
      s!.warning ? h("p", { class: "warn setup-warning" }, vt(s!.warning)) : null,
      h("p", { class: "muted" }, "This needs a passkey that is pinned for maintenance. The root runner checks the signature itself."),
      h("details", { class: "signed" }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(prep.canonicalText))),
      h("div", { class: "actions" }, back, sign),
    );
    sign.focus();
  };
  idle();
  return h(
    "article",
    { class: "card request queued-task", "data-id": p.id, "data-task": vt(s?.task ?? ""), "aria-label": `Maintenance task requested by ${vt(p.requesting_host)}` },
    h("div", { class: "card-top" }, h("span", { class: "kind" }, "Maintenance"), h("span", { class: "expires" }, "Expires in ", k.until(p.expires_at))),
    h("h3", { class: "target" }, vt(s?.title ?? "Unknown task")),
    h("p", null, vt(s?.summary ?? "")),
    read?.lines.length ? h("ul", { class: "queued-params" }, read.lines.map((l) => h("li", null, vt(l)))) : null,
    s?.warning ? h("p", { class: "warn setup-warning" }, vt(s.warning)) : null,
    h(
      "details",
      { class: "setup-more" },
      h("summary", null, `What happens (${steps.length} step${steps.length === 1 ? "" : "s"})`),
      h("ol", { class: "setup-steps" }, steps.map((x) => h("li", null, vt(x)))),
      h("p", { class: "muted" }, h("strong", null, "Can it be undone? "), vt(s?.reversible ?? "")),
    ),
    h("dl", { class: "facts" }, h("dt", null, "From"), h("dd", null, h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))), h("dt", null, "Ref"), h("dd", null, h("span", { class: "mono" }, vt(k.ref(p.id))))),
    k.agentSays(p),
    h("p", { class: "muted" }, "Nothing runs unless you approve. The host and its reason are context: your signature covers the task and its parameters."),
    box,
  );
}

// ---- Admin → Bastion access ----

/** The complete, sorted allowlist the bastion-allow task signs, from the ticked hosts. */
export function allowParams(hosts: readonly BastionHost[], ticked: ReadonlySet<string>): { hosts: Array<{ id: string; name: string; address: string }> } {
  return {
    hosts: hosts
      .filter((x) => ticked.has(x.id))
      .map((x) => ({ id: x.id, name: x.name, address: x.allowed && x.allowed_address ? x.allowed_address : x.address }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  };
}

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^[0-9a-f:]{2,39}$/;
const RESERVED = ["root", "aqmas", "aqmas-inspect", "aqmas-build"];

let seq = 0;
function text(placeholder: string, value = ""): HTMLInputElement {
  const el = h("input", { type: "text", id: `bastion-f${++seq}`, class: "text", autocomplete: "off", spellcheck: "false", placeholder });
  el.value = value;
  return el;
}
const field = (label: string, el: HTMLInputElement, hint?: string) => h("div", { class: "field" }, h("label", { for: el.id }, label), el, hint ? h("p", { class: "hint muted" }, hint) : null);
function tick(label: Child, checked = false): { el: HTMLInputElement; row: HTMLElement } {
  const el = h("input", { type: "checkbox", id: `bastion-f${++seq}` });
  el.checked = checked;
  return { el, row: h("label", { class: "setup-check", for: el.id }, el, h("span", null, label)) };
}

export interface BastionPanelHooks {
  openRevoke(target: ActionTarget): void;
  signedOut(): void;
  changed?(): void;
  pollMs?: number;
  idleMs?: number;
}

/** Admin → Bastion access: whether access is installed, who may ask for root, the sessions,
 * and the access and routine tasks (the Setup page's own cards, with their forms from here). */
export class BastionPanel {
  readonly el = h("div", { class: "bastion-panel" });
  private head = h("div", { class: "bastion-head" });
  private sessions = h("div", { class: "bastion-sessions" });
  private tasks = h("div", { class: "setup bastion-tasks" });
  private page: SetupPage;
  private view: BastionView | null = null;
  private keys = { head: "", sessions: "" };

  constructor(
    private api: Api,
    auth: Authenticator,
    private hooks: BastionPanelHooks,
  ) {
    replace(this.el, this.head, this.sessions, h("h3", { class: "bastion-h" }, "Access and routine tasks"), h("p", { class: "muted" }, "Each task is one approval by a passkey that is pinned for maintenance. A small root program on this machine checks the signature itself and does the work; none of them takes free text."), this.tasks);
    this.page = new SetupPage(this.tasks, api, auth, {
      openMigration: () => {},
      openUpdate: () => {},
      signedOut: () => hooks.signedOut(),
      changed: () => hooks.changed?.(),
      pollMs: hooks.pollMs,
      idleMs: hooks.idleMs,
      groups: ["bastion", "routine"],
      loaded: () => this.load(),
      formKey: (t) => this.formKey(t),
      form: (t, v, can, label, run) => this.form(t, v, can, label, run),
    });
  }

  start(): void {
    this.page.start();
  }
  stop(): void {
    this.page.stop();
  }

  private async load(): Promise<void> {
    if (!this.api.bastion) return;
    try {
      this.view = await this.api.bastion();
    } catch {
      return; // the setup poll shows the outage; keep what was shown
    }
    this.render();
  }

  private render(): void {
    const v = this.view;
    if (!v) return;
    const headKey = JSON.stringify([v.enabled, v.name, v.address, v.port, v.admin_user, v.inspect_user, v.root_until, v.alert_channel, v.sealed]);
    if (headKey !== this.keys.head) {
      this.keys.head = headKey;
      replace(
        this.head,
        rootBanner(v.root_until),
        v.enabled
          ? h(
              "div",
              { class: "bastion-status on" },
              h("p", null, h("span", { class: "badge setup-state state-done" }, "Installed"), " Agents reach this machine as ", h("bdi", { class: "mono" }, vt(v.name ?? "")), " (", h("bdi", null, vt(v.address ?? "")), `, port ${v.port ?? 22}).`),
              h("dl", { class: "facts" }, h("dt", null, "Inspect"), h("dd", null, h("bdi", { class: "mono" }, vt(v.inspect_user)), " — fixed log and status commands only, amber card"), h("dt", null, "Root"), h("dd", null, h("bdi", { class: "mono" }, vt(v.admin_user ?? "")), " — your admin account, red card, at most 1 hour, listed hosts only")),
            )
          : h("div", { class: "bastion-status off" }, h("p", null, h("span", { class: "badge setup-state state-blocked" }, "Not installed"), " This machine's sshd accepts only your emergency key. Run “Allow aqmas access to the bastion” below to let aqmas issue certificates for it.")),
        v.enabled && !v.alert_channel ? h("p", { class: "warn" }, ROOT_NO_ALERT, " A root session would be approved without a push notification.") : null,
        h("p", { class: "muted" }, "Your emergency key is never touched by any of this and stays the way in when aqmas is down."),
      );
    }
    const list = v.sessions ?? [];
    const sessKey = JSON.stringify(list);
    if (sessKey !== this.keys.sessions) {
      this.keys.sessions = sessKey;
      replace(this.sessions, h("h3", { class: "bastion-h" }, "Sessions"), list.length ? h("div", { class: "tiles" }, list.map((s) => this.sessionRow(s))) : h("p", { class: "empty" }, "No bastion session yet."));
    }
  }

  private sessionRow(s: BastionSession): HTMLElement {
    const root = s.level === "root";
    const active = s.status === "active";
    const alert =
      !root ? null : s.alert === "sent" ? "sent" : s.alert === "failed" ? h("strong", { class: "bad" }, "NOT DELIVERED") : s.alert === "off" ? h("strong", { class: "bad" }, "no alert channel") : h("span", { class: "muted" }, "pending");
    const at = Date.parse(s.not_after);
    return h(
      "article",
      { class: `row bastion-session${root ? " root" : ""}${active ? " active" : ""}`, "data-id": s.grant_id, "data-level": vt(s.level) },
      root ? rootBand(active ? "ROOT SESSION POSSIBLE" : "Root session") : h("p", null, h("span", { class: "badge" }, "Inspect")),
      h(
        "dl",
        { class: "facts" },
        h("dt", null, "Host"),
        h("dd", null, h("bdi", { class: "host-name" }, vt(s.requesting_host)), " as ", h("bdi", null, vt(s.login_user))),
        h("dt", null, active ? "Valid until" : "Ended"),
        h("dd", null, Number.isFinite(at) ? h("time", { datetime: s.not_after, title: absoluteTime(at) }, active ? `${clock(at)} (${countdown(at)})` : ago(at)) : "?"),
        h("dt", null, "Status"),
        h("dd", null, vt(s.status)),
        root ? [h("dt", null, "Buckets"), h("dd", null, s.close_buckets ? `${s.closed_count} closed first` : h("strong", { class: "bad" }, "left open"))] : null,
        root ? [h("dt", null, "Alert"), h("dd", null, alert)] : null,
        root ? [h("dt", null, "Certificate"), h("dd", null, s.delivered_at ? `collected ${clock(s.delivered_at)}` : "not collected")] : null,
      ),
      active
        ? h(
            "div",
            { class: "actions" },
            h("button", { class: "btn deny", type: "button", on: { click: () => this.hooks.openRevoke(targetForGrant({ id: s.grant_id, kind: "bastion", status: "approved", target_host: this.view?.name ?? "", login_user: s.login_user, requesting_host: s.requesting_host, not_before: s.not_before, not_after: s.not_after })) } }, "Revoke…"),
          )
        : null,
      active && root ? h("p", { class: "muted small" }, s.delivered_at ? "The certificate was collected: revoking marks the session but cannot recall it." : "Revoking now stops the certificate from being handed out.") : null,
    );
  }

  private formKey(t: SetupTask): unknown {
    const v = this.view;
    if (t.id === "bastion-access") return [v?.ssh_ca, v?.enabled, v?.name, v?.address, v?.port, v?.admin_user];
    if (t.id === "bastion-allow") return [v?.hosts, v?.admin_user, v?.name];
    return null;
  }

  private form(t: SetupTask, _v: SetupView, can: boolean, label: string, run: (label: string, collect: () => Collected) => HTMLElement): Child[] | undefined {
    const b = this.view;
    const again = (form: Child[]): Child[] => (t.state === "done" && can ? [h("details", { class: "setup-more", "data-keep": "again" }, h("summary", null, "Change it or run it again"), form)] : form);
    switch (t.id) {
      case "bastion-access": {
        if (!can) return [];
        if (!b) return [h("p", { class: "muted", role: "status" }, "Loading…")];
        const name = text("bastion", b.name ?? "bastion");
        const address = text("192.0.2.10", b.address ?? "");
        const port = text("22", String(b.port ?? 22));
        const admin = text("alice", b.admin_user ?? "");
        port.inputMode = "numeric";
        const collect = (): Collected => {
          const p = { name: name.value.trim(), address: address.value.trim(), port: Number(port.value.trim()), admin_user: admin.value.trim(), ssh_ca: b.ssh_ca };
          if (!NAME_RE.test(p.name)) throw new Invalid("The name is a plain lowercase host name, like “bastion”.");
          if (!IPV4_RE.test(p.address) && !(p.address.includes(":") && IPV6_RE.test(p.address))) throw new Invalid("The address is a literal IP address, the one fleet hosts reach this machine on.");
          if (!Number.isInteger(p.port) || p.port < 1 || p.port > 65535 || String(p.port) !== port.value.trim()) throw new Invalid("The port is a number from 1 to 65535.");
          if (!USER_RE.test(p.admin_user) || RESERVED.includes(p.admin_user)) throw new Invalid("The admin account is your own login on this machine: not root and not one of aqmas's accounts.");
          return {
            params: p,
            summary: [
              h("p", { class: "headline pos" }, "Let this machine's sshd accept aqmas certificates: read-only inspect as ", h("bdi", { class: "val" }, vt(b.inspect_user)), ", and root as ", h("bdi", { class: "val" }, vt(p.admin_user)), " behind the red card."),
              paramLines(t.id, p).map((l) => h("p", null, vt(l))),
              h("p", { class: "warn" }, "Check the SSH CA fingerprint against one you trust (for example a fleet host's /etc/ssh/aqmas_user_ca.pub). Nobody can ask for root until you also set who may."),
            ],
          };
        };
        return again([
          field("Name agents use", name, "As in “aqmas ssh bastion”. Not the name of an existing SSH target."),
          field("Address fleet hosts reach this machine on", address),
          field("SSH port", port),
          field("Your admin account on this machine", admin, "It has sudo. A root session logs in as this account."),
          h("p", null, "SSH user CA that will be trusted: ", h("span", { class: "mono" }, vt(b.ssh_ca))),
          run(label, collect),
        ]);
      }
      case "bastion-access-remove":
        return can
          ? [run(label, () => ({ params: {}, summary: [h("p", { class: "headline neg" }, "Stop this machine's sshd from accepting aqmas certificates and delete the inspect account."), h("p", null, "Afterwards only your emergency key gets in. A root session that is already open is not ended.")] }))]
          : [];
      case "bastion-allow": {
        if (!b) return can ? [h("p", { class: "muted", role: "status" }, "Loading…")] : [];
        const hosts = b.hosts ?? [];
        if (!hosts.length) return [h("p", { class: "empty" }, "No enrolled hosts.")];
        const boxes = hosts.map((x) => {
          const c = tick([h("bdi", { class: "host-name" }, vt(x.name)), " ", h("span", { class: "addr" }, vt(x.allowed && x.allowed_address ? x.allowed_address : x.address)), x.class ? h("span", { class: "muted" }, ` · ${vt(x.class)}`) : null, x.gone ? [" ", h("span", { class: "badge setup-state state-blocked" }, "No longer enrolled")] : null], x.allowed);
          c.el.disabled = !can;
          c.el.dataset["host"] = x.id;
          return c;
        });
        const list = h("ul", { class: "setup-passkeys bastion-hosts" }, boxes.map((c) => h("li", null, c.row)));
        if (!can) return [list];
        const collect = (): Collected => {
          const ticked = new Set(hosts.filter((_, i) => boxes[i]!.el.checked).map((x) => x.id));
          const params = allowParams(hosts, ticked);
          const added = hosts.filter((x) => ticked.has(x.id) && !x.allowed);
          const removed = hosts.filter((x) => !ticked.has(x.id) && x.allowed);
          return {
            params,
            summary: [
              rootBand("WHO MAY ASK FOR ROOT ON THE BASTION"),
              h("p", { class: "headline pos" }, params.hosts.length ? ["Replace the list with: ", params.hosts.map((x, i) => [i ? ", " : "", h("bdi", { class: "val" }, vt(x.name)), " from ", h("bdi", { class: "val" }, vt(x.address))]), "."] : "Clear the list: no host may ask for root."),
              added.map((x) => h("p", { class: "warn" }, "Adding: ", h("bdi", { class: "val" }, vt(x.name)), " (enrollment ", h("span", { class: "mono" }, vt(x.id)), "). It may then put the red card in front of you, and sshd accepts a root certificate from its address.")),
              removed.map((x) => h("p", null, "Removing: ", h("bdi", { class: "val" }, vt(x.name)), ".")),
              h("p", { class: "muted" }, "Every root session still needs its own red card and tap."),
            ],
          };
        };
        return [h("p", { class: "muted" }, "Ticked hosts may ask for a root session, from the address shown. The list is kept by root, not by the broker; this machine's sshd enforces the same addresses."), list, run("Apply…", collect)];
      }
      case "os-update": {
        if (!can) return [];
        const kernel = tick("Also update the kernel and boot chain");
        return [
          kernel.row,
          h("p", { class: "hint muted" }, "Leave unticked on a machine with a kernel the distribution did not ship. If boot files change anyway, the task fails and Reboot is refused until you looked."),
          run(label, () => ({ params: { kernel: kernel.el.checked }, summary: [h("p", { class: "headline pos" }, "Install the pending system package updates on the bastion."), paramLines(t.id, { kernel: kernel.el.checked }).map((l) => h("p", { class: kernel.el.checked ? "warn" : "" }, vt(l)))] })),
        ];
      }
      case "journal-vacuum": {
        if (!can) return [];
        const days = text("14", "14");
        days.inputMode = "numeric";
        return [
          field("Keep this many days", days, "Older journal entries are deleted for good."),
          run(label, () => {
            const n = Number(days.value.trim());
            if (!Number.isInteger(n) || n < 1 || n > 365 || String(n) !== days.value.trim()) throw new Invalid("Keep days is a whole number from 1 to 365.");
            return { params: { keep_days: n }, summary: [h("p", { class: "headline neg" }, "Rotate the journal and delete old entries."), paramLines(t.id, { keep_days: n }).map((l) => h("p", null, vt(l)))] };
          }),
        ];
      }
      case "reboot":
      case "restart-cloudflared":
      case "restart-broker":
      case "disk-usage":
        return can ? [run(label, () => ({ params: {}, summary: [h("p", { class: `headline ${t.id === "disk-usage" ? "pos" : "neg"}` }, vt(t.title), "."), t.warning ? h("p", { class: "warn setup-warning" }, vt(t.warning)) : null] }))] : [];
    }
    return undefined;
  }
}
