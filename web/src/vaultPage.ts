// Admin → Credential sets: the write-only form, reveal, signer keys and signing approvals
// (docs/API.md "Vault", docs/SIGNING.md). All logic and every canonical check is in vault.ts;
// this file only draws. Text from the server or a file goes in as text nodes through
// visibleText; values the owner types or reveals live in form controls and <pre> text nodes
// and are dropped on hide, save, navigation and pagehide.
import { type Api } from "./api";
import { type Catalogue, planString } from "./catalogue";
import { type Child, append, h, replace } from "./dom";
import type { ActionChoice, ActionTarget } from "./flows";
import { countdown, duration, visibleText as vt } from "./format";
import { type SealView } from "./sealPanel";
import {
  type Edit,
  type Entry,
  type Scheme,
  type SignRequest,
  type SignerResult,
  type VaultOrg,
  type VaultSet,
  type VaultState,
  editChanges,
  hexPreview,
  itemMessage,
  nameProblem,
  newSetId,
  parseDotenv,
  validateEntries,
  vaultCommit,
  vaultPolicy,
  vaultReveal,
  vaultSignDecision,
  vaultSignerCreate,
} from "./vault";
import type { Authenticator } from "./webauthn";

const REVEAL_SECONDS = 60;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const TITLE_RE = /^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$/;

export interface VaultHost {
  api: Api;
  auth: Authenticator;
  /** Reload state after something was applied. */
  changed(): void;
  /** Open the catalogue sheet (create organisation, service or empty set). */
  propose?(target: ActionTarget, choice: ActionChoice): void;
}

const pathOf = (s: { org_slug: string; service_slug: string; set_slug: string }) => `${s.org_slug}/${s.service_slug}/${s.set_slug}`;
const message = (e: unknown) => vt(e instanceof Error ? e.message : String(e));

function btn(label: string, cls: string, click: (ev: MouseEvent) => void): HTMLButtonElement {
  return h("button", { class: "btn " + cls, type: "button", on: { click } }, label);
}
function copyButton(text: () => string, label = "Copy"): HTMLButtonElement {
  const b = btn(label, "small", async () => {
    try {
      await navigator.clipboard.writeText(text());
      b.textContent = "Copied";
    } catch {
      b.textContent = "Copy failed: select the text";
    }
    window.setTimeout(() => (b.textContent = label), 2000);
  });
  return b;
}
/** A full digest in groups of eight, wrapping between groups; never truncated. */
function digest(hexText: string): HTMLElement {
  const el = h("span", { class: "mono digest" });
  for (let i = 0; i < hexText.length; i += 8) el.append(h("span", null, vt(hexText.slice(i, i + 8))), " ");
  return el;
}
function scopeHeading(orgTitle: string, serviceTitle: string, setTitle: string): HTMLElement {
  return h("h3", { class: "vault-scope" }, h("bdi", null, vt(orgTitle)), " › ", h("bdi", null, vt(serviceTitle)), " › ", h("bdi", null, vt(setTitle)));
}
function bytes(n: number): string {
  return n < 0 ? "size not given" : n === 1 ? "1 byte" : `${n.toLocaleString("en-GB")} bytes`;
}

/** Two steps, as everywhere in this app: the server's canonical is checked against the
 * choice first (prepare), then one button starts the passkey prompt inside its own tap. */
function ceremony<T>(slot: HTMLElement, auth: Authenticator, confirmLabel: string, cls: string, prepare: () => Promise<{ detail: string; tap(a: Authenticator): Promise<T> }>, before: (detail: string) => Child[], done: (out: T) => void, cancelled?: () => void): void {
  const error = h("p", { class: "error", role: "alert" });
  replace(slot, h("p", { class: "muted", role: "status" }, "Checking with aqmas…"));
  prepare().then(
    (p) => {
      const go = btn(confirmLabel, cls + " confirm", async () => {
        go.disabled = true;
        error.textContent = "";
        try {
          const out = await p.tap(auth);
          replace(slot);
          done(out);
        } catch (e) {
          replace(slot, h("p", { class: "error", role: "alert" }, "Not applied: ", message(e), ". Nothing changed; start again."));
          cancelled?.();
        }
      });
      replace(
        slot,
        h(
          "div",
          { class: "vault-confirm" },
          ...before(p.detail),
          h("p", { class: "hint muted" }, "Checked: the text your passkey signs describes exactly this."),
          h("div", { class: "actions" }, btn("Cancel", "", () => (replace(slot), cancelled?.())), go),
          error,
        ),
      );
      go.focus();
    },
    (e) => {
      replace(slot, h("p", { class: "error", role: "alert" }, message(e)));
      cancelled?.();
    },
  );
}

// ---- signing requests and grants (queue page and Admin) ----

function schemeOf(state: VaultState, id: string): Scheme | undefined {
  return state.schemes.find((s) => s.id === id);
}

function signCard(host: VaultHost, seal: SealView, state: VaultState, req: SignRequest): HTMLElement {
  const set = state.sets.find((s) => s.set_id === req.set);
  const scheme = schemeOf(state, req.scheme);
  const timed = req.ttl_seconds > 0;
  const live = req.status === "approved";
  const slot = h("div", { class: "vault-slot" });
  const card = h("article", { class: "card request sign-card" + (timed ? " high" : "") });
  card.setAttribute("data-id", req.id);
  const [orgTitle = "?", serviceTitle = "?", setTitle = "?"] = set ? [set.org_title, set.service_title, set.set_title] : req.title.split(" / ");
  card.append(
    h("div", { class: "card-top" }, h("span", { class: "badge" }, live ? "Signing grant" : "Signature request"), h("span", { class: "muted" }, "Ref ", h("span", { class: "mono" }, vt(req.id.slice(-6).toUpperCase())))),
    scopeHeading(orgTitle, serviceTitle, setTitle),
    h("p", { class: "mono" }, vt(req.path)),
  );
  if (!set || !scheme) {
    card.append(h("p", { class: "error" }, "This page does not know that signer or scheme. Reload; do not approve."));
    return card;
  }
  const items = h("ol", { class: "sign-items" });
  for (const it of req.items) {
    const li = h(
      "li",
      null,
      h("div", { class: "sign-file" }, h("bdi", { class: "mono" }, vt(it.name)), h("span", { class: "muted" }, " · ", bytes(it.size))),
    );
    if (scheme.input === "sha512") {
      // The signature covers the SHA-512 only. aqmas never sees the file, so the SHA-256 is
      // the requester's word and must not be what the owner compares.
      li.append(
        h("div", { class: "sign-digest" }, h("span", { class: "sign-label" }, "SHA-512 · this is what gets signed"), digest(it.sha512 ?? "")),
        h("div", { class: "sign-digest minor" }, h("span", { class: "sign-label" }, "SHA-256 · requester's claim, NOT covered by the signature"), digest(it.sha256)),
      );
    } else li.append(h("div", { class: "sign-digest" }, h("span", { class: "sign-label" }, "SHA-256"), digest(it.sha256)));
    if (it.message !== undefined) {
      const pre = h("pre", { class: "mono sign-bytes" }, "checking…");
      li.append(h("details", null, h("summary", null, "The bytes that get signed"), pre));
      itemMessage(it).then(
        (m) => (pre.textContent = m ? hexPreview(m) : ""),
        () => {
          pre.textContent = "These bytes do NOT match the SHA-256 above. Do not approve.";
          pre.classList.add("error");
        },
      );
    }
    items.append(li);
  }
  card.append(
    h(
      "dl",
      { class: "facts" },
      h("dt", null, "Scheme"),
      h("dd", null, vt(scheme.title), h("span", { class: "muted" }, " · signs ", vt(scheme.signed))),
      h("dt", null, "Key"),
      h("dd", null, digest(set.fingerprint ?? "")),
      h("dt", null, "From"),
      h("dd", null, h("bdi", null, vt(req.host)), h("span", { class: "muted" }, " at ", h("span", { class: "mono" }, vt(req.address)))),
    ),
    h("p", { class: "sign-count" }, live ? "Asked for with:" : req.items.length === 1 ? "One artifact:" : `${req.items.length} artifacts:`),
    items,
    h("p", { class: "agent-says" }, h("span", { class: "muted" }, "Requester's explanation (unverified): "), h("bdi", null, vt(req.reason))),
  );

  if (live) {
    const left = h("span", null, countdown(req.not_after));
    card.append(
      h(
        "p",
        { class: timed ? "warn" : "muted" },
        timed
          ? `${req.used} of ${req.max_signatures} signatures used. Until it ends, this host can have anything signed with this key. Ends in `
          : "Approved for exactly these artifacts, once. Waiting for the host to collect; ends in ",
        left,
        ".",
      ),
      h("div", { class: "actions" }, btn("Revoke…", "deny", () => ceremony(slot, host.auth, "Revoke with passkey", "deny", () => vaultSignDecision(host.api, seal, set, req, "sign-revoke", 0, 0, location.hostname), () => [h("p", null, "Ends this signing grant now. Signatures already made stay valid.")], () => host.changed()))),
      slot,
    );
    return card;
  }

  // Pending: what approving would allow, with limits that can only be lowered.
  const minutes = h("input", { type: "number", class: "text num", id: `sg-min-${req.id}`, inputmode: "numeric" });
  const count = h("input", { type: "number", class: "text num", id: `sg-max-${req.id}`, inputmode: "numeric" });
  const once = h("input", { type: "checkbox", id: `sg-once-${req.id}` });
  const blunt = h("p", { class: "warn" });
  const choice = () => {
    if (!timed || once.checked) return { ttl: 0, max: req.items.length };
    return { ttl: Math.round(Number(minutes.value) * 60), max: Math.round(Number(count.value)) };
  };
  const describe = () => {
    const c = choice();
    minutes.disabled = count.disabled = once.checked;
    blunt.className = c.ttl === 0 ? "muted" : "warn";
    blunt.textContent =
      c.ttl === 0
        ? `Single use: aqmas signs exactly ${req.items.length === 1 ? "this artifact" : "these artifacts"}, once, and nothing else.`
        : `Time-boxed: up to ${c.max} signatures over ANYTHING this host submits for ${duration(c.ttl)}, not only the artifacts above. Each one is logged.${c.ttl > req.soft_cap_seconds ? " BEYOND SOFT CAP." : ""}`;
  };
  if (timed) {
    const maxMin = Math.max(1, Math.floor(req.ttl_seconds / 60));
    minutes.value = String(maxMin);
    minutes.min = "1";
    minutes.max = String(maxMin);
    count.value = String(req.max_signatures);
    count.min = "1";
    count.max = String(req.max_signatures);
    for (const el of [minutes, count, once]) el.addEventListener("input", describe);
    card.append(
      h(
        "div",
        { class: "sign-limits" },
        h("label", { for: minutes.id }, "Minutes (at most ", String(maxMin), ") ", minutes),
        h("label", { for: count.id }, "Signatures (at most ", String(req.max_signatures), ") ", count),
        h("label", { class: "check", for: once.id }, once, " Only these artifacts, once"),
      ),
    );
  }
  describe();
  const actions = h("div", { class: "actions" });
  const decide = (action: "sign-approve" | "sign-deny") => {
    const c = action === "sign-approve" ? choice() : { ttl: 0, max: 0 };
    if (action === "sign-approve" && c.ttl !== 0 && !(c.ttl >= 60 && c.ttl <= req.ttl_seconds && c.max >= 1 && c.max <= req.max_signatures)) {
      replace(slot, h("p", { class: "error", role: "alert" }, "Choose limits within what was asked for."));
      return;
    }
    actions.hidden = true;
    ceremony(
      slot,
      host.auth,
      action === "sign-approve" ? "Approve with passkey" : "Deny with passkey",
      action === "sign-approve" ? "approve" : "deny",
      () => vaultSignDecision(host.api, seal, set, req, action, c.ttl, c.max, location.hostname),
      () => [h("p", null, action === "sign-approve" ? vt(blunt.textContent) : "Deny this request. Nothing is signed.")],
      () => host.changed(),
      () => (actions.hidden = false),
    );
  };
  actions.append(btn("Deny…", "deny", () => decide("sign-deny")), btn(state.unlocked ? "Approve…" : "Unlock to approve", "approve", () => decide("sign-approve")));
  (actions.lastChild as HTMLButtonElement).disabled = !state.unlocked;
  card.append(blunt, actions, slot);
  return card;
}

/** Pending signature requests, then live signing grants. */
export function signCards(host: VaultHost, seal: SealView, state: VaultState): HTMLElement[] {
  const order = (r: SignRequest) => (r.status === "pending" ? 0 : 1);
  return [...state.requests].sort((a, b) => order(a) - order(b) || (a.id < b.id ? -1 : 1)).map((r) => signCard(host, seal, state, r));
}

// ---- the Admin section ----

interface Tree {
  id: string;
  slug: string;
  title: string;
  revision?: number;
  services: { id: string; slug: string; title: string; revision?: number }[];
}

export class VaultPage {
  readonly el = h("div", { class: "vault" });
  private state?: VaultState;
  private seal?: SealView;
  private catalogue?: Catalogue | null;
  private sel = { org: "", service: "", set: "" };
  private keys = { requests: "", pick: "", body: "" };
  private requestsBox = h("div", { class: "list vault-requests" });
  private pickBox = h("article", { class: "card vault-pick" });
  private bodyBox = h("div", { class: "vault-body" });
  /** Drops revealed values, typed values and pasted keys (hide, save, leaving the page). */
  private forget: (() => void)[] = [];
  /** The signer made a moment ago in this tab (its card says so). */
  private created = "";

  constructor(private host: VaultHost) {
    this.el.append(this.requestsBox, this.pickBox, this.bodyBox);
  }

  clearSecrets(): void {
    for (const f of this.forget.splice(0)) f();
  }

  update(state: VaultState, seal: SealView, catalogue: Catalogue | null | undefined): void {
    this.state = state;
    this.seal = seal;
    this.catalogue = catalogue;
    const tree = this.tree();
    const org = tree.find((o) => o.id === this.sel.org) ?? tree[0];
    const service = org?.services.find((s) => s.id === this.sel.service) ?? org?.services[0];
    const sets = state.sets.filter((s) => s.service_id === service?.id);
    const set = sets.find((s) => s.set_id === this.sel.set) ?? sets[0];
    this.sel = { org: org?.id ?? "", service: service?.id ?? "", set: set?.set_id ?? "" };

    const rk = JSON.stringify([state.requests, state.unlocked, seal.epoch]);
    if (rk !== this.keys.requests && !this.requestsBox.querySelector(".vault-confirm")) {
      this.keys.requests = rk;
      replace(this.requestsBox, state.requests.length ? [h("h3", null, "Signing requests and grants"), signCards(this.host, seal, state)] : null);
    }
    const pk = JSON.stringify([tree, this.sel, sets.map((s) => [s.set_id, s.kind]), state.organisations, state.unlocked, !!catalogue]);
    if (pk !== this.keys.pick) {
      this.keys.pick = pk;
      this.drawPick(tree, sets);
    }
    const bk = JSON.stringify([set, service, state.unlocked, state.organisations.find((o) => o.id === org?.id), seal.epoch]);
    if (bk !== this.keys.body) {
      this.keys.body = bk;
      this.clearSecrets();
      replace(this.bodyBox, !service ? null : [set ? (set.kind === "signer" ? this.signerView(set) : this.editor(set)) : h("p", { class: "empty" }, "This service has no credential sets yet."), this.newSigner(org!, service)]);
    }
  }

  private redraw(): void {
    if (this.state && this.seal) this.update(this.state, this.seal, this.catalogue);
  }

  /** Organisations and application services: from the catalogue when Admin has it (it also
   * lists services that have no sets yet), else from the sets themselves. */
  private tree(): Tree[] {
    const state = this.state!;
    if (this.catalogue)
      return this.catalogue.organisations.map((o) => ({ id: o.id, slug: o.slug, title: o.title, revision: o.revision, services: o.services.filter((s) => s.provider === "application").map((s) => ({ id: s.id, slug: s.slug, title: s.title, revision: s.revision })) }));
    return state.organisations.map((o) => ({
      id: o.id,
      slug: o.slug,
      title: o.title,
      services: [...new Map(state.sets.filter((s) => s.org_id === o.id).map((s) => [s.service_id, { id: s.service_id, slug: s.service_slug, title: s.service_title }])).values()],
    }));
  }

  private drawPick(tree: Tree[], sets: VaultSet[]): void {
    const state = this.state!;
    const org = tree.find((o) => o.id === this.sel.org);
    const service = org?.services.find((s) => s.id === this.sel.service);
    const select = (id: string, label: string, options: { id: string; text: string }[], value: string, pick: (v: string) => void) => {
      const el = h("select", { id, class: "text" }, options.length ? options.map((o) => h("option", { value: o.id }, vt(o.text))) : h("option", { value: "" }, "none yet"));
      el.value = value;
      el.disabled = options.length === 0;
      el.addEventListener("change", () => pick(el.value));
      return h("div", { class: "field" }, h("label", { for: id }, label), el);
    };
    const slot = h("div", { class: "vault-slot" });
    const policyOrg = state.organisations.find((o) => o.id === org?.id);
    replace(
      this.pickBox,
      h(
        "div",
        { class: "vault-selects" },
        select("vault-org", "Organisation", tree.map((o) => ({ id: o.id, text: `${o.title} (${o.slug})` })), this.sel.org, (v) => ((this.sel = { org: v, service: "", set: "" }), this.redraw())),
        select("vault-service", "Service", (org?.services ?? []).map((s) => ({ id: s.id, text: `${s.title} (${s.slug})` })), this.sel.service, (v) => ((this.sel = { ...this.sel, service: v, set: "" }), this.redraw())),
        select("vault-set", "Credential set", sets.map((s) => ({ id: s.set_id, text: `${s.set_title} (${s.set_slug}) · ${s.kind === "signer" ? "signing key" : `${s.names.length} keys`}` })), this.sel.set, (v) => ((this.sel = { ...this.sel, set: v }), this.redraw())),
      ),
      policyOrg ? this.policyLine(policyOrg, slot) : null,
      slot,
      this.host.propose && this.catalogue ? this.createForms(org, service) : null,
    );
  }

  private policyLine(org: VaultOrg, slot: HTMLElement): HTMLElement {
    const next = !org.allow_reveal;
    const b = btn(next ? "Allow reveal…" : "Turn reveal off…", "small", () =>
      ceremony(
        slot,
        this.host.auth,
        next ? "Allow reveal with passkey" : "Turn reveal off with passkey",
        next ? "approve" : "deny",
        () => vaultPolicy(this.host.api, this.seal!, org, next, location.hostname),
        () => [h("p", null, next ? "Values of " : "Values of ", h("bdi", null, vt(org.title)), next ? " can be shown on this page again, each time after a passkey tap." : " can no longer be shown on this page. Delivery to hosts (aqmas run) is unchanged.")],
        () => this.host.changed(),
      ),
    );
    b.disabled = next && !this.state!.unlocked;
    return h("p", { class: "vault-policy" }, h("span", null, "Reveal on this page for ", h("bdi", null, vt(org.title)), ": ", h("strong", null, org.allow_reveal ? "allowed" : "off"), ". "), b);
  }

  /** Create what is missing without leaving the page (the existing catalogue approval). */
  private createForms(org: Tree | undefined, service: Tree["services"][number] | undefined): HTMLElement {
    const cat = this.catalogue!;
    const form = (label: string, kind: "organisation" | "service" | "credential_set") => {
      const slug = h("input", { type: "text", class: "text", maxlength: "63", placeholder: "slug", autocomplete: "off", spellcheck: "false" });
      const title = h("input", { type: "text", class: "text", maxlength: "64", placeholder: "Display name", autocomplete: "off" });
      const error = h("p", { class: "error", role: "alert" });
      return h(
        "details",
        { class: "vault-create" },
        h("summary", null, label),
        h("div", { class: "vault-create-row" }, slug, title, btn("Review…", "small", () => {
          if (!SLUG_RE.test(slug.value) || !TITLE_RE.test(title.value)) {
            error.textContent = "Slug: lower-case letters, digits and dashes. Name: letters, digits, spaces, dot, dash, underscore.";
            return;
          }
          error.textContent = "";
          const id = newSetId();
          const n = { id, slug: slug.value, title: title.value, revision: 0 };
          const node = (x: { id: string; slug: string; title: string; revision?: number }) => ({ id: x.id, slug: x.slug, title: x.title, revision: x.revision ?? 0 });
          const policy = { default_seconds: 3600, soft_cap_seconds: 86400, indefinite: true, standing_default_seconds: 3600, standing_soft_cap_seconds: 86400, standing_indefinite: true };
          const plan =
            kind === "organisation"
              ? { organisation: n, new_policy: policy, result_revision: 1 }
              : kind === "service"
                ? { organisation: node(org!), service: n, kind: "application", result_revision: 1 }
                : { organisation: node(org!), service: node(service!), set: n, kind: "env-set", result_revision: 0 };
          this.host.propose!({ object: kind, id, facts: { plan: planString({ owner_id: cat.owner_id, ...plan }) } }, { action: "create" });
        })),
        error,
      );
    };
    return h(
      "div",
      { class: "vault-creates" },
      h("span", { class: "muted" }, "Missing something? "),
      form("New organisation", "organisation"),
      org ? form(`New service in ${vt(org.title)}`, "service") : null,
      org && service ? form(`New empty set in ${vt(service.title)}`, "credential_set") : null,
    );
  }

  // ---- env set: write-only form and reveal ----

  private editor(set: VaultSet): HTMLElement {
    const state = this.state!;
    const card = h("article", { class: "card vault-editor" });
    const slot = h("div", { class: "vault-slot" });
    const revealBox = h("div", { class: "vault-revealed" });
    const rowsBox = h("div", { class: "vault-rows" });
    const summary = h("ul", { class: "vault-changes" });
    const error = h("p", { class: "error", role: "alert" });
    const removed = new Set<string>();
    let rows: { name: HTMLInputElement; value: HTMLTextAreaElement; el: HTMLElement }[] = [];
    let mode: "merge" | "import" = "merge";
    let imported = "";

    const edit = (): Edit => {
      const entries: Entry[] = rows.filter((r) => r.name.value !== "" || r.value.value !== "").map((r) => ({ name: r.name.value.trim(), value: r.value.value }));
      // A key being replaced in the same save is not also removed: the new value wins.
      return { operation: mode, entries, remove: mode === "merge" ? [...removed].filter((n) => !entries.some((x) => x.name === n)).sort() : [] };
    };
    const refresh = () => {
      const e = edit();
      error.textContent = "";
      let changes: string[] = [];
      try {
        for (const x of e.entries) {
          const p = nameProblem(x.name);
          if (p) throw Error(`${x.name || "A key without a name"}: ${p}`);
        }
        validateEntries(e.entries);
        changes = e.entries.length + e.remove.length || mode === "import" ? editChanges(e, set.names).split(",").filter(Boolean) : [];
      } catch (err) {
        error.textContent = (err as Error).message.replace(/^unsupported or duplicate environment name$/, "Each key can appear once.").replace(/^unsupported value for /, "Too long (8192 bytes at most) or not text: ").replace(/^environment too large$/, "Too much in one set (24 KiB at most).");
      }
      replace(
        summary,
        changes.map((c) => {
          const [name, kind] = c.split(":");
          return h("li", { class: "chg-" + kind }, h("span", { class: "mono" }, vt(name)), " ", h("span", { class: "badge" }, kind === "add" ? "added" : kind === "replace" ? "replaced" : "removed"));
        }),
      );
      save.disabled = !state.unlocked || changes.length === 0 || error.textContent !== "";
      for (const li of existing.children) {
        const n = li.getAttribute("data-name")!;
        li.classList.toggle("gone", mode === "import" ? !e.entries.some((x) => x.name === n) : removed.has(n));
      }
    };
    const addRow = (name = "", value = "") => {
      const n = h("input", { type: "text", class: "text mono kv-name", placeholder: "KEY_NAME", autocomplete: "off", spellcheck: "false", maxlength: "64", "aria-label": "Key name" });
      const v = h("textarea", { class: "mono kv-value", placeholder: "value (several lines are fine)", autocomplete: "off", spellcheck: "false", "aria-label": "Value" });
      v.rows = Math.min(8, Math.max(2, value.split("\n").length));
      n.value = name;
      v.value = value;
      const row = { name: n, value: v, el: h("div", { class: "kv-row" }) };
      row.el.append(n, v, btn("✕", "small", () => {
        v.value = "";
        rows = rows.filter((r) => r !== row);
        row.el.remove();
        if (!rows.length) {
          mode = "merge";
          imported = "";
          replace(importNote);
        }
        refresh();
      }));
      (row.el.lastChild as HTMLElement).setAttribute("aria-label", "Drop this row");
      n.addEventListener("input", refresh);
      v.addEventListener("input", refresh);
      rows.push(row);
      rowsBox.append(row.el);
      return row;
    };
    const clearRows = () => {
      for (const r of rows) r.value.value = r.name.value = "";
      rows = [];
      replace(rowsBox);
      removed.clear();
      mode = "merge";
      imported = "";
      replace(importNote);
    };

    // Existing keys: names only. Their values are never fetched to draw this list.
    const canReveal = set.allow_reveal && state.unlocked;
    const hide = () => {
      for (const pre of revealBox.querySelectorAll("pre")) pre.textContent = "";
      replace(revealBox);
      window.clearInterval(timer);
    };
    let timer = 0;
    const reveal = (names: string[]) =>
      ceremony<Entry[]>(
        slot,
        this.host.auth,
        "Reveal with passkey",
        "approve",
        () => vaultReveal(this.host.api, this.seal!, set, names, location.hostname),
        () => [h("p", null, "Show ", h("span", { class: "mono" }, vt(names.join(", "))), " on this page for ", String(REVEAL_SECONDS), " seconds. aqmas encrypts the answer to a key that exists only in this tab, and logs which keys were shown.")],
        (entries) => {
          hide();
          const until = Date.now() + REVEAL_SECONDS * 1000;
          const left = h("strong", null, String(REVEAL_SECONDS));
          let shown: Entry[] | null = entries;
          replace(
            revealBox,
            h("div", { class: "revealed-head" }, h("span", null, "Hidden again in ", left, " s"), btn("Hide now", "small", hide)),
            entries.map((e, i) => h("div", { class: "revealed-item" }, h("div", { class: "revealed-name" }, h("span", { class: "mono" }, vt(e.name)), copyButton(() => shown?.[i]?.value ?? "")), h("pre", { class: "mono revealed-value", tabindex: "0" }, e.value))),
          );
          timer = window.setInterval(() => {
            const s = Math.ceil((until - Date.now()) / 1000);
            left.textContent = String(Math.max(0, s));
            if (s <= 0 || !revealBox.isConnected) {
              shown = null;
              hide();
            }
          }, 500);
          this.forget.push(() => ((shown = null), hide()));
        },
      );
    const existing = h("ul", { class: "vault-keys" });
    for (const name of set.names) {
      const rm = btn("Remove", "small", () => {
        if (removed.has(name)) removed.delete(name);
        else removed.add(name);
        rm.textContent = removed.has(name) ? "Keep" : "Remove";
        refresh();
      });
      const li = h(
        "li",
        null,
        h("span", { class: "mono key-name" }, vt(name)),
        h("span", { class: "muted key-dots", "aria-label": "value hidden" }, "••••••"),
        h("span", { class: "key-actions" }, canReveal ? btn("Reveal", "small", () => reveal([name])) : null, btn("Replace", "small", () => addRow(name).value.focus()), rm),
      );
      li.setAttribute("data-name", name);
      existing.append(li);
    }

    // .env import: parsed here, shown as key names and what happens to each.
    const importNote = h("div", { class: "vault-import-note" });
    const load = async (file: File | undefined) => {
      if (!file) return;
      error.textContent = "";
      try {
        if (file.size > 64 << 10) throw Error("That file is too large for an env set.");
        const entries = parseDotenv(new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer()));
        if (!entries.length) throw Error("No assignments found in that file.");
        clearRows();
        for (const e of entries) addRow(e.name, e.value);
        imported = file.name;
        drawImport();
        refresh();
      } catch (e) {
        replace(importNote, h("p", { class: "error", role: "alert" }, "Not imported: ", e instanceof TypeError ? "the file is not UTF-8 text" : message(e), ". Nothing was read into the form."));
      }
    };
    const drawImport = () => {
      const radio = (value: "merge" | "import", label: string) => {
        const el = h("input", { type: "radio", name: "vault-import-mode", id: "vim-" + value });
        el.checked = mode === value;
        el.addEventListener("change", () => ((mode = value), refresh()));
        return h("label", { class: "check", for: el.id }, el, " ", label);
      };
      replace(
        importNote,
        h("p", null, "From ", h("bdi", { class: "mono" }, vt(imported)), ": ", String(rows.length), rows.length === 1 ? " key." : " keys."),
        radio("merge", "Add and replace these keys; keep the others"),
        radio("import", "Replace the whole set: keys not in the file are removed"),
      );
    };
    const file = h("input", { type: "file", id: "vault-file", class: "vault-file" });
    file.accept = ".env,.txt,text/plain";
    file.addEventListener("change", () => {
      void load(file.files?.[0]);
      file.value = "";
    });
    const drop = h("label", { class: "dropzone", for: "vault-file" }, h("strong", null, "Import a .env file"), h("span", { class: "muted" }, " Drop it here or choose it. It is read in this tab; only an encrypted copy of the values leaves it."), file);
    drop.addEventListener("dragover", (ev) => {
      ev.preventDefault();
      drop.classList.add("over");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (ev) => {
      ev.preventDefault();
      drop.classList.remove("over");
      void load(ev.dataTransfer?.files?.[0]);
    });

    const save = btn("Review and save…", "approve", () => {
      const e = edit();
      save.disabled = true;
      ceremony(
        slot,
        this.host.auth,
        "Save with passkey",
        "approve",
        () => vaultCommit(this.host.api, this.seal!, set, e, location.hostname),
        () => [h("p", null, "Revision ", String(set.revision), " → ", String(set.revision + 1), mode === "import" ? ", replacing the whole set" : "", ". Hosts holding a release of the old revision lose it."), summary.cloneNode(true)],
        () => {
          clearRows();
          for (const x of e.entries) x.value = "";
          this.host.changed();
        },
        refresh,
      );
    });
    this.forget.push(() => {
      for (const r of rows) r.value.value = "";
    });
    append(card, [
      scopeHeading(set.org_title, set.service_title, set.set_title),
      h("p", { class: "muted" }, h("span", { class: "mono" }, vt(pathOf(set))), " · revision ", String(set.revision), " · ", set.names.length === 1 ? "1 key" : `${set.names.length} keys`),
      !state.unlocked ? h("p", { class: "warn" }, "The broker is locked: unlock it to save or reveal values. Key names stay visible.") : null,
      set.names.length
        ? [
            existing,
            set.allow_reveal
              ? state.unlocked && set.names.length > 1
                ? h("div", { class: "actions start" }, btn("Reveal all…", "small", () => reveal([...set.names].sort())))
                : null
              : h("p", { class: "hint muted" }, "Reveal is off for this organisation: values can be replaced here, not shown."),
          ]
        : h("p", { class: "empty" }, "No values yet. Add keys below or import a .env file."),
      revealBox,
      h("h4", null, "Add or replace values"),
      h("p", { class: "hint muted" }, "Write-only: what you type is encrypted in this tab for aqmas's sealed store before it is sent, and old values are never loaded into this form."),
      rowsBox,
      h("div", { class: "actions start" }, btn("Add a key", "small", () => addRow().name.focus())),
      drop,
      importNote,
      h("h4", null, "What will change"),
      summary,
      error,
      h("div", { class: "actions" }, save),
      slot,
    ]);
    refresh();
    return card;
  }

  // ---- signer sets ----

  private keyFacts(scheme: Scheme | undefined, hexKey: string, pem: string, fingerprint: string): HTMLElement {
    return h(
      "dl",
      { class: "facts vault-key" },
      h("dt", null, "Scheme"),
      h("dd", null, vt(scheme?.title ?? "?"), scheme ? h("div", { class: "hint muted" }, "Signs ", vt(scheme.signed), ". Signature: ", vt(scheme.output), ".") : null),
      h("dt", null, "Public key"),
      h("dd", null, h("span", { class: "mono" }, vt(hexKey)), " ", copyButton(() => hexKey, "Copy hex"), " ", copyButton(() => pem, "Copy PEM")),
      h("dt", null, "Fingerprint"),
      h("dd", null, digest(fingerprint), h("div", { class: "hint muted" }, "SHA-256 of the raw public key")),
    );
  }

  private signerView(set: VaultSet): HTMLElement {
    const scheme = schemeOf(this.state!, set.scheme ?? "");
    const cmd = `aqmas sign ${pathOf(set)} --why "…" ${scheme?.input === "message" ? "manifest.bin" : "FILE..."}`;
    return h(
      "article",
      { class: "card vault-signer" },
      this.created === set.set_id ? h("p", { class: "vault-done", role: "status" }, "Created. Give verifiers the public key below; the private half is in the sealed store.") : null,
      scopeHeading(set.org_title, set.service_title, set.set_title),
      h("p", { class: "muted" }, h("span", { class: "mono" }, vt(pathOf(set))), " · signing key · ", set.origin === "imported" ? "imported" : "generated in aqmas", set.created_at ? ` · ${new Date(set.created_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}` : "", " · ", set.signatures === 1 ? "1 signature" : `${set.signatures} signatures`, " so far"),
      this.keyFacts(scheme, set.public_hex ?? "", set.public_pem ?? "", set.fingerprint ?? ""),
      h("p", { class: "hint muted" }, "The private key stays in the sealed store. It is never delivered to a host and cannot be revealed or exported; hosts ask aqmas to sign:"),
      h("div", { class: "command" }, h("pre", null, h("code", null, cmd)), copyButton(() => cmd)),
      scheme ? h("p", { class: "hint muted" }, "Check a signature independently: ", h("span", { class: "mono" }, vt(scheme.check))) : null,
    );
  }

  private newSigner(org: Tree, service: Tree["services"][number]): HTMLElement {
    const state = this.state!;
    const slug = h("input", { type: "text", class: "text", id: "ns-slug", maxlength: "63", placeholder: "release-key", autocomplete: "off", spellcheck: "false" });
    const title = h("input", { type: "text", class: "text", id: "ns-title", maxlength: "64", placeholder: "Release key", autocomplete: "off" });
    const scheme = h("select", { class: "text", id: "ns-scheme" }, state.schemes.map((s) => h("option", { value: s.id }, vt(s.title))));
    const about = h("p", { class: "hint muted" });
    const describe = () => {
      const s = schemeOf(state, scheme.value);
      about.textContent = s ? `Signs ${s.signed}. Signature: ${s.output}. A key keeps its scheme for life.` : "";
    };
    scheme.addEventListener("change", describe);
    describe();
    const gen = h("input", { type: "radio", name: "ns-source", id: "ns-generate" });
    const imp = h("input", { type: "radio", name: "ns-source", id: "ns-import" });
    gen.checked = true;
    const pasted = h("textarea", { class: "mono kv-value", id: "ns-key", placeholder: "hex seed, or an unencrypted PKCS#8 / SEC1 / OpenSSH private key", autocomplete: "off", spellcheck: "false", "aria-label": "Private key to import" });
    pasted.rows = 4;
    const pasteField = h("div", { class: "field", hidden: true }, h("label", { for: "ns-key" }, "Private key (pasted once)"), pasted, h("p", { class: "hint muted" }, "Encrypted in this tab for the sealed store, then cleared from this field. aqmas shows you the matching public key before you confirm."));
    for (const el of [gen, imp]) el.addEventListener("change", () => (pasteField.hidden = !imp.checked));
    const slot = h("div", { class: "vault-slot" });
    const error = h("p", { class: "error", role: "alert" });
    this.forget.push(() => (pasted.value = ""));
    const parent = { org_id: org.id, org_slug: org.slug, org_title: org.title, service_id: service.id, service_slug: service.slug, service_title: service.title };
    const go = btn(state.unlocked ? "Review…" : "Unlock to create a key", "approve", () => {
      if (!SLUG_RE.test(slug.value) || !TITLE_RE.test(title.value)) {
        error.textContent = "Slug: lower-case letters, digits and dashes. Name: letters, digits, spaces, dot, dash, underscore.";
        return;
      }
      error.textContent = "";
      const source = imp.checked ? "import" : "generate";
      const key = imp.checked ? pasted.value : undefined;
      const picked = schemeOf(state, scheme.value);
      const set = { id: newSetId(), slug: slug.value, title: title.value };
      let shown: { publicHex: string; publicPem: string; fingerprint: string } | undefined;
      ceremony<SignerResult>(
        slot,
        this.host.auth,
        "Create with passkey",
        "approve",
        async () => {
          const p = await vaultSignerCreate(this.host.api, this.seal!, parent, set, scheme.value, source, key, location.hostname);
          pasted.value = "";
          shown = p;
          return p;
        },
        () => [
          h("p", null, source === "import" ? "aqmas read your key. Compare this public key with the one you already use before confirming:" : "aqmas generated this key pair. The private half never leaves the sealed store:"),
          scopeHeading(org.title, service.title, set.title),
          this.keyFacts(picked, shown!.publicHex, shown!.publicPem, shown!.fingerprint),
        ],
        (out) => {
          slug.value = title.value = "";
          this.sel = { ...this.sel, set: out.set_id };
          // The new key becomes the selected set; its card carries the confirmation.
          this.created = out.set_id;
          this.host.changed();
        },
      );
    });
    go.disabled = !state.unlocked;
    return h(
      "details",
      { class: "card vault-new-signer" },
      h("summary", null, "New signing key in ", h("bdi", null, vt(service.title))),
      h("p", { class: "hint muted" }, "A signing key lives in the sealed store and is never delivered: hosts send digests and get signatures back, each one approved or covered by a time-boxed grant, each one logged."),
      h("div", { class: "vault-selects" }, h("div", { class: "field" }, h("label", { for: "ns-slug" }, "Slug"), slug), h("div", { class: "field" }, h("label", { for: "ns-title" }, "Display name"), title), h("div", { class: "field" }, h("label", { for: "ns-scheme" }, "Scheme"), scheme)),
      about,
      h("div", { class: "vault-source" }, h("label", { class: "check", for: "ns-generate" }, gen, " Generate inside aqmas"), h("label", { class: "check", for: "ns-import" }, imp, " Import an existing private key")),
      pasteField,
      error,
      h("div", { class: "actions" }, go),
      slot,
    );
  }
}
