// The Vault tab: every credential the broker holds as one searchable list, in the manner of a
// password manager. Left: filters (type, organisation → service). Middle: the items. Right:
// the selected item (its fields, who may ask for it, what happened to it) or the Add item form.
//
// This file is layout only. Saving, revealing, creating a signer and every other
// state-changing action is a form of vaultPage.ts or a catalogue proposal, with the same
// canonical checks and the same passkey tap as before. No value is fetched to draw anything
// here: the list shows key names, and a value appears only after its own Reveal tap.
import { classify, actor } from "./audit";
import { proposeCreate, type Catalogue } from "./catalogue";
import { type Child, append, h, replace } from "./dom";
import { envPanel } from "./envsets";
import { absoluteTime, ago, visibleText as vt } from "./format";
import { itemIcon } from "./icons";
import { vaultHash } from "./nav";
import { kindWords, type SealView } from "./sealPanel";
import { newSetId, type SetHistory, type VaultState } from "./vault";
import { INSTALLATION, NO_FILTER, TYPE_WORDS, buildItems, filterItems, folders, requesters, typeCounts, type Filter, type ItemType, type VaultItem } from "./vaultItems";
import { SLUG_RE, TITLE_RE, VaultForms, btn, copyButton, signCards, slugify, type VaultHost } from "./vaultPage";

export interface VaultViewHost extends VaultHost {
  /** Start the passkey flow that creates an organisation's scope key (capabilities.ts). */
  createScope?(scope: string, review: HTMLElement): Promise<void>;
  /** One line about passkeys that cannot open buckets yet (readiness.ts), or null. */
  readinessNote?(): Child;
}

const HISTORY_MAX_AGE_MS = 30_000;
const NEW = "new";
const DELETED = "deleted";
const DELETABLE = ["env-set", "secret", "signer", "ssh-key"];
const SLUG_HELP = "Name: letters, digits, spaces, dot, dash, underscore. Slug: lower-case letters, digits and dashes.";

interface NewNode {
  id: string;
  title: HTMLInputElement;
  slug: HTMLInputElement;
}

export class VaultView {
  readonly el = h("div", { class: "vault vault3" });
  readonly forms: VaultForms;
  private state?: VaultState;
  private seal?: SealView;
  private catalogue?: Catalogue | null;
  private items: VaultItem[] = [];
  private filter: Filter = { ...NO_FILTER };
  private selected = "";
  private keys = { side: "", list: "", bar: "", main: "", extra: "", add: "" };
  private side = h("nav", { class: "vault-side", "aria-label": "Filter the vault" });
  private search = h("input", { type: "search", class: "text vault-search", placeholder: "Search this vault", autocomplete: "off", spellcheck: "false", "aria-label": "Search this vault" });
  private list = h("ul", { class: "vault-items", role: "list" });
  private count = h("p", { class: "muted vault-count", role: "status" });
  private bar = h("div", { class: "vault-bar" });
  private main = h("div", { class: "vault-main" });
  private extra = h("div", { class: "vault-extra" });
  private detail = h("section", { class: "vault-detail", "aria-label": "Selected item" });
  private history?: { id: string; at: number; data?: SetHistory; rev: string };
  private selectedAt = 0;
  private add?: AddForm;

  constructor(private host: VaultViewHost) {
    this.forms = new VaultForms(host);
    const addLink = h("a", { class: "btn approve vault-add" }, "+ Add item");
    addLink.href = vaultHash(NEW);
    this.search.addEventListener("input", () => {
      this.filter = { ...this.filter, q: this.search.value };
      this.drawList();
    });
    // Up and down move through the list, as in any list of items.
    this.list.addEventListener("keydown", (ev) => {
      if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
      const links = [...this.list.querySelectorAll<HTMLElement>("a.vault-item")];
      const i = links.indexOf(document.activeElement as HTMLElement);
      const next = links[i + (ev.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        ev.preventDefault();
        next.focus();
      }
    });
    this.search.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        this.list.querySelector<HTMLElement>("a.vault-item")?.focus();
      }
    });
    this.detail.append(this.bar, this.main, this.extra);
    this.el.append(this.side, h("section", { class: "vault-list", "aria-label": "Items" }, h("div", { class: "vault-list-head" }, this.search, addLink), this.count, this.list), this.detail);
  }

  /** Leaving the Vault (another tab, pagehide): revealed, typed and pasted values go, and
   * the forms that held them are dropped, so coming back builds fresh ones. */
  clearSecrets(): void {
    this.forms.clearSecrets();
    this.dropPane();
  }

  private dropPane(): void {
    replace(this.bar);
    replace(this.main);
    replace(this.extra);
    this.keys.main = this.keys.extra = this.keys.bar = this.keys.add = "";
    this.add = undefined;
  }

  /** `item` comes from the address (#/vault/ID): the selection survives reload and Back. */
  update(state: VaultState, seal: SealView, catalogue: Catalogue | null | undefined, item: string | undefined): void {
    this.state = state;
    this.seal = seal;
    this.catalogue = catalogue;
    this.forms.bind(state, seal);
    this.items = buildItems(state, catalogue, seal);
    if ((item ?? "") !== this.selected) {
      // Another item: nothing of the previous one stays, whatever was open in it (a
      // confirmation, a revealed value, a half-typed form).
      this.selected = item ?? "";
      this.selectedAt = Date.now();
      this.clearSecrets();
    }
    this.el.dataset["pane"] = this.selected ? "detail" : "list";
    this.drawSide();
    this.drawList();
    this.drawDetail();
  }

  // ---- filters ----

  private setFilter(f: Partial<Filter>): void {
    this.filter = { ...this.filter, ...f };
    this.keys.side = "";
    this.drawSide();
    this.drawList();
  }

  private drawSide(): void {
    const f = this.filter;
    const tree = folders(this.items, this.catalogue);
    const types = typeCounts(this.items);
    const binned = this.state?.deleted?.length ?? 0;
    const key = JSON.stringify([tree, types, f.org, f.service, f.type, this.items.length, binned, this.selected === DELETED]);
    if (key === this.keys.side) return;
    this.keys.side = key;
    const chip = (label: Child, count: number, on: boolean, pick: () => void, cls = "") =>
      h("button", { class: `side-item${cls}`, type: "button", "aria-pressed": String(on), on: { click: pick } }, h("span", { class: "side-label" }, label), h("span", { class: "side-count" }, String(count)));
    const all = !f.org && !f.service && !f.type;
    replace(
      this.side,
      h(
        "div",
        { class: "side-group" },
        chip("All items", this.items.length, all, () => this.setFilter({ org: "", service: "", type: "" })),
        // The bin: shown while something is in it (or while it is the page on show).
        binned || this.selected === DELETED ? chip("Deleted", binned, this.selected === DELETED, () => (location.hash = vaultHash(this.selected === DELETED ? undefined : DELETED)), " side-deleted") : null,
      ),
      h(
        "div",
        { class: "side-group", role: "group", "aria-label": "Types" },
        h("h3", { class: "side-h" }, "Types"),
        types.map((t) => chip([itemIcon(t.type), TYPE_WORDS[t.type].many], t.count, f.type === t.type, () => this.setFilter({ type: f.type === t.type ? "" : t.type }))),
      ),
      h(
        "div",
        { class: "side-group", role: "group", "aria-label": "Organisations" },
        h("h3", { class: "side-h" }, "Organisations"),
        tree.map((o) => [
          chip(h("bdi", null, vt(o.title)), o.count, f.org === o.id && !f.service, () => this.setFilter(f.org === o.id && !f.service ? { org: "", service: "" } : { org: o.id, service: "" })),
          // Services of the organisation that is selected (all of them on a wide screen).
          o.services.map((s) => chip(h("bdi", null, vt(s.title)), s.count, f.service === s.id, () => this.setFilter(f.service === s.id ? { org: o.id, service: "" } : { org: o.id, service: s.id }), ` side-sub${f.org === o.id ? " in-org" : ""}`)),
        ]),
      ),
    );
  }

  // ---- the list ----

  private drawList(): void {
    const shown = filterItems(this.items, this.filter);
    const key = JSON.stringify([shown.map((i) => [i.id, i.title, i.sub, i.orgTitle, i.serviceTitle, i.bucket?.open, i.bucket?.paused.length]), this.selected]);
    if (key === this.keys.list) return;
    this.keys.list = key;
    const focused = (document.activeElement as HTMLElement | null)?.dataset?.["item"];
    this.count.textContent = shown.length === this.items.length ? `${shown.length} item${shown.length === 1 ? "" : "s"}` : `${shown.length} of ${this.items.length} items`;
    replace(
      this.list,
      shown.length
        ? shown.map((it) => {
            const a = h(
              "a",
              { class: "vault-item", "data-item": it.id, "data-type": it.type },
              h("span", { class: "item-icon" }, itemIcon(it.type)),
              h(
                "span",
                { class: "item-text" },
                h("span", { class: "item-title" }, h("bdi", null, vt(it.title))),
                h("span", { class: "item-where muted" }, h("bdi", null, vt(it.orgTitle)), it.serviceTitle ? [" › ", h("bdi", null, vt(it.serviceTitle))] : null),
                h("span", { class: "item-sub muted" }, TYPE_WORDS[it.type].one, " · ", vt(it.sub)),
              ),
              it.bucket?.open ? h("span", { class: "badge open" }, "Open") : null,
              it.bucket?.paused.length ? h("span", { class: "badge warn" }, "Paused") : null,
            );
            a.href = vaultHash(it.id);
            if (it.id === this.selected) a.setAttribute("aria-current", "true");
            return h("li", null, a);
          })
        : h("li", { class: "empty" }, this.items.length ? "Nothing matches. Clear the search or pick All items." : "Nothing here yet. Add your first item."),
    );
    if (focused) this.list.querySelector<HTMLElement>(`[data-item="${CSS.escape(focused)}"]`)?.focus();
  }

  // ---- the selected item ----

  private back(): HTMLElement {
    const a = h("a", { class: "vault-back" }, "‹ All items");
    a.href = vaultHash();
    return a;
  }

  private drawDetail(): void {
    if (this.selected === NEW) return this.drawAdd();
    if (this.selected === DELETED) return this.drawDeleted();
    const it = this.items.find((i) => i.id === this.selected);
    if (!it) {
      const settling = !!this.selected && Date.now() - this.selectedAt < 4000;
      const key = `none:${this.selected}:${settling}`;
      if (key === this.keys.main) return;
      this.keys.main = key;
      replace(this.bar, this.selected ? this.back() : null);
      replace(this.extra);
      replace(
        this.main,
        this.selected
          ? h("p", { class: "empty", role: "status" }, settling ? "Looking for that item…" : "That item is not in the vault (any more).")
          : h("div", { class: "vault-placeholder" }, h("p", { class: "empty" }, "Pick an item to see its fields, who may ask for it and what happened to it."), this.host.readinessNote?.()),
      );
      return;
    }
    const bk = JSON.stringify([it.id, it.title, it.path, it.type, it.bucket]);
    if (bk !== this.keys.bar) {
      this.keys.bar = bk;
      const b = it.bucket;
      replace(
        this.bar,
        this.back(),
        h(
          "div",
          { class: "vault-title", "data-type": it.type },
          h("span", { class: "item-icon big" }, itemIcon(it.type)),
          h("div", null, h("h3", null, h("bdi", null, vt(it.title))), h("p", { class: "muted" }, TYPE_WORDS[it.type].one, " · ", h("span", { class: "mono" }, vt(it.path)), " ", copyButton(() => it.path, "Copy path"))),
          b ? h("span", { class: `badge${b.open ? " open" : ""}`, title: b.open ? "Its bucket is decrypted in memory right now: Security → Buckets" : "Its bucket is closed: the next approval that needs it opens it" }, b.open ? "Open now" : "Closed") : null,
        ),
      );
    }
    const org = this.state!.organisations.find((o) => o.id === it.orgId);
    // The editor holds what the owner is typing: it is rebuilt only when the set itself, the
    // reveal policy or the broker's epoch changed, never because a bucket opened or a poll ran.
    const mk = JSON.stringify([it.id, it.set, org, this.seal!.epoch, it.set ? null : [it.bucket, it.kind]]);
    if (mk !== this.keys.main) {
      this.keys.main = mk;
      this.forms.clearSecrets();
      replace(this.main, it.set ? (it.set.kind === "ssh-key" ? this.forms.sshKeyView(it.set) : it.set.kind === "signer" ? this.forms.signerView(it.set) : it.set.kind === "secret" ? this.forms.secretView(it.set) : this.forms.editor(it.set)) : this.infoCard(it));
    }
    this.loadHistory(it);
    const mine = it.set ? this.state!.requests.filter((r) => r.set === it.id) : [];
    const who = requesters(it, this.catalogue);
    // The set itself is part of the key: "More" holds forms built from its revision and limit.
    const ek = JSON.stringify([it.id, it.set, who, mine, this.history?.id === it.id ? this.history.data : null, org, it.type, this.seal!.epoch, !!this.catalogue]);
    // A signing card waiting for its tap stays as it is.
    // (the selection has not changed here: a new selection emptied the pane above). A CLI
    // ticket on show stays too, and "More" stays open across a redraw.
    if (ek !== this.keys.extra && !this.extra.querySelector(".vault-confirm, button.confirm, .vault-more [role=status]:not(:empty)")) {
      this.keys.extra = ek;
      const more = !!this.extra.querySelector<HTMLDetailsElement>("details.vault-more")?.open;
      replace(this.extra, this.extras(it, who, mine));
      if (more) this.extra.querySelector<HTMLDetailsElement>("details.vault-more")!.open = true;
    }
  }

  private loadHistory(it: VaultItem): void {
    const api = this.host.api;
    if (!it.set || !api.vaultHistory) return;
    const rev = `${it.set.revision}/${it.set.signatures}`;
    const hst = this.history;
    if (hst?.id === it.id && hst.rev === rev && Date.now() - hst.at < HISTORY_MAX_AGE_MS) return;
    const mine = (this.history = { id: it.id, at: Date.now(), rev, data: hst?.id === it.id ? hst.data : undefined });
    api.vaultHistory(it.id).then(
      (data) => {
        if (this.history !== mine) return;
        mine.data = data;
        if (this.selected === it.id) this.drawDetail();
      },
      () => {
        // An older server has no history, or the broker is away: the card just is not shown.
      },
    );
  }

  private infoCard(it: VaultItem): HTMLElement {
    const b = it.bucket;
    const about: Record<ItemType, string> = {
      "ssh-ca": "The key that signs the short-lived SSH certificates hosts receive. It is generated inside the sealed store and never leaves it; an SSH approval opens its bucket for as long as the grant needs.",
      "internal-ca": "The broker's own certificate authority for the agent API. It stays in the sealed store.",
      cloudflare: b ? "The parent Cloudflare credential the broker proxies with and mints child tokens from. It is never delivered to a host; a Cloudflare approval opens its bucket." : "What admitted hosts may ask of Cloudflare through this broker. The scopes and their limits come from the bastion's configuration.",
      access: "An access rule: something admitted hosts may ask for (for example an SSH certificate for one target). Nothing secret is stored under it.",
      "env-set": "An env set this page cannot edit (this server does not list its keys).",
      secret: "A secret this page cannot edit (this server does not list it).",
      signer: "A signing key this page cannot describe (this server does not list it).",
      "ssh-key": "An SSH key this page cannot describe (this server does not list it).",
    };
    const link = (text: string, href: string) => {
      const a = h("a", null, text);
      a.href = href;
      return a;
    };
    return h(
      "article",
      { class: "card vault-info" },
      h("p", null, about[it.type]),
      h(
        "dl",
        { class: "facts" },
        h("dt", null, "Organisation"),
        h("dd", null, h("bdi", null, vt(it.orgTitle))),
        it.serviceTitle ? [h("dt", null, "Service"), h("dd", null, h("bdi", null, vt(it.serviceTitle)))] : null,
        h("dt", null, "Kind"),
        h("dd", null, vt(b ? kindWords(b.kind) : it.kind)),
        b ? [h("dt", null, "Bucket"), h("dd", null, b.open ? "Open" : "Closed", b.holds.length ? vt(` · held by ${b.holds.map((x) => x.reason || x.kind).join("; ")}`) : "", b.paused.length ? ` · ${b.paused.length} waiting for a Reopen` : "")] : null,
      ),
      h("p", { class: "hint muted" }, "This item is managed elsewhere: ", b ? [link("Security → Buckets", "#/security"), " (reopen, rekey, close), "] : null, link("Settings", "#/settings"), " (policies, setup)", it.orgId !== INSTALLATION ? [" and ", link("Hosts", "#/hosts"), " (who may ask)"] : null, "."),
    );
  }

  private extras(it: VaultItem, who: { name: string; class: string }[] | undefined, mine: VaultState["requests"]): Child[] {
    const out: Child[] = [];
    const hosts = h("a", null, "Hosts");
    hosts.href = "#/hosts";
    if (mine.length) out.push(h("div", { class: "vault-requests" }, h("h4", null, it.type === "ssh-key" ? "Requests and grants for this SSH key" : "Signing requests and grants for this key"), signCards(this.host, this.seal!, { ...this.state!, requests: mine })));
    if (it.set?.kind === "env-set" || it.set?.kind === "secret") {
      const cmd = `aqmas run ${it.path} --why "…" -- COMMAND`;
      const get = `aqmas get ${it.path} --why "…"`;
      const secret = it.set.kind === "secret";
      out.push(
        h(
          "article",
          { class: "card vault-use" },
          h("h4", null, "Use it on a host"),
          h("p", { class: "hint muted" }, secret ? ["An admitted host asks; you approve on the Approvals tab; the command gets the value as ", h("span", { class: "mono" }, vt(it.names[0] ?? "")), "."] : "An admitted host asks; you approve on the Approvals tab; the command gets the values as environment variables."),
          h("div", { class: "command" }, h("pre", null, h("code", null, cmd)), copyButton(() => cmd)),
          secret ? [h("p", { class: "hint muted" }, "Or the value itself on stdout, for a tool that cannot read its environment. The approval card says that the value leaves aqmas; you can turn this off per organisation in Settings."), h("div", { class: "command" }, h("pre", null, h("code", null, get)), copyButton(() => get))] : null,
        ),
      );
    }
    if (it.orgId !== INSTALLATION)
      out.push(
        h(
          "article",
          { class: "card vault-who" },
          h("h4", null, "Who may ask for it"),
          who === undefined
            ? h("p", { class: "muted" }, "Hosts admitted to ", h("bdi", null, vt(it.orgTitle)), ": see ", hosts, ".")
            : who.length
              ? [h("ul", { class: "who-list" }, who.map((x) => h("li", null, h("bdi", { class: "host-name" }, vt(x.name)), " ", h("span", { class: "badge" }, vt(x.class))))), h("p", { class: "hint muted" }, "Every host admitted to ", h("bdi", null, vt(it.orgTitle)), " may ask; each request still needs your approval. Change admissions under ", hosts, ".")]
              : h("p", { class: "muted" }, "No host is admitted to ", h("bdi", null, vt(it.orgTitle)), " yet, so nothing can ask for this. Admit one under ", hosts, "."),
        ),
      );
    const hist = this.history?.id === it.id ? this.history.data : undefined;
    if (hist) {
      const when = (ms: number) => (ms ? h("time", { datetime: new Date(ms).toISOString(), title: absoluteTime(ms) }, ago(ms)) : h("span", { class: "muted" }, "not in the recent log"));
      out.push(
        h(
          "article",
          { class: "card vault-history" },
          h("h4", null, "Activity"),
          h("dl", { class: "facts" }, h("dt", null, "Last changed"), h("dd", null, when(hist.last_changed_at)), h("dt", null, it.type === "signer" ? "Last signature" : it.type === "ssh-key" ? "Last used" : "Last delivered"), h("dd", null, when(hist.last_used_at))),
          hist.entries.length
            ? h(
                "ol",
                { class: "hist-list" },
                hist.entries.map((e) => {
                  const who2 = actor(e.actor);
                  return h("li", null, h("span", { class: "hist-label" }, vt(classify(e).label)), " ", h("span", { class: `actor actor-${who2.kind}` }, h("bdi", null, vt(who2.name))), " ", h("time", { class: "muted", datetime: e.at, title: absoluteTime(e.at) }, ago(e.at)));
                }),
              )
            : h("p", { class: "muted" }, "Nothing recorded yet."),
          (() => {
            const a = h("a", null, "All activity");
            a.href = "#/activity";
            return h("p", { class: "hint muted" }, "Full details, including which keys were revealed: ", a, ".");
          })(),
        ),
      );
    }
    const org = this.state!.organisations.find((o) => o.id === it.orgId);
    if (it.set && org) {
      const more: Child[] = [this.forms.policyLine(org)];
      const keyed = it.set.kind === "signer" || it.set.kind === "ssh-key";
      if (!keyed) more.push(this.forms.standingLine(it.set), this.forms.convertLine(it.set));
      // One-use tickets for `aqmas set import|put|unset` from an owner device (docs/API.md).
      const o = this.catalogue?.organisations.find((x) => x.id === it.orgId);
      const svc = o?.services.find((v) => v.id === it.serviceId);
      const set = svc?.sets.find((s) => s.id === it.id);
      if (it.set.kind === "env-set" && o && svc && set && o.hosts.some((x) => x.active && x.class === "owner-device"))
        more.push(h("h4", null, "Edit from your own machine instead"), h("p", { class: "hint muted" }, "A one-use ticket lets ", h("span", { class: "mono" }, "aqmas set import|put|unset"), " on an owner device stage the change; you then approve it on the Approvals tab."), envPanel(this.host.api, this.host.auth, this.seal!, { drafts: [], releases: [] }, { owner_id: this.catalogue!.owner_id, organisations: [{ ...o, services: [{ ...svc, sets: [set] }] }] }, () => this.host.changed()));
      out.push(h("details", { class: "card vault-more" }, h("summary", null, "More: reveal policy", !keyed ? ", don't ask again" : "", it.set.kind === "env-set" ? ", CLI tickets" : ""), more));
    }
    if (it.set && DELETABLE.includes(it.set.kind)) out.push(this.forms.deleteLine(it.set, () => (location.hash = vaultHash(DELETED))));
    return out;
  }

  // ---- the bin ----

  private drawDeleted(): void {
    const key = JSON.stringify(["deleted", this.state!.deleted ?? [], this.seal!.epoch]);
    // A Restore or Purge waiting for its tap stays as it is.
    if (key === this.keys.main || this.main.querySelector(".vault-confirm, button.confirm")) return;
    this.keys.main = key;
    this.keys.bar = this.keys.extra = "";
    replace(this.bar, this.back(), h("div", { class: "vault-title" }, h("div", null, h("h3", null, "Deleted"), h("p", { class: "muted" }, "Items in the bin: unusable, restorable until aqmas destroys them."))));
    replace(this.extra);
    replace(this.main, this.forms.deletedList());
  }

  // ---- Add item ----

  private drawAdd(): void {
    if (!this.add) {
      this.add = new AddForm(this);
      replace(this.bar, this.back(), h("div", { class: "vault-title" }, h("div", null, h("h3", null, "Add item"), h("p", { class: "muted" }, "Each step is one passkey approval; nothing is stored before its tap."))));
      replace(this.extra);
      replace(this.main, this.add.el);
      this.keys.main = "new";
    }
    this.add.sync();
  }

  /** What AddForm needs from the view. */
  ctx() {
    return { host: this.host, forms: this.forms, state: this.state!, seal: this.seal!, catalogue: this.catalogue, filter: this.filter };
  }
}

/** Add item: a type, a place (existing or new organisation and service) and a name. What is
 * missing is created in order, each with its own approval, and the form moves on by itself
 * when the broker reports the new row. */
class AddForm {
  readonly el = h("article", { class: "card vault-add-form" });
  private type: "env-set" | "secret" | "signer" | "ssh-key" = "env-set";
  private org = h("select", { class: "text", id: "add-org" });
  private service = h("select", { class: "text", id: "add-service" });
  private newOrg = this.node("add-org-new", "Client A");
  private newService = this.node("add-svc-new", "PaaS");
  private set = this.node("add-set", "Staging env");
  private orgNew = h("div", { class: "add-new", hidden: true });
  private serviceNew = h("div", { class: "add-new", hidden: true });
  private setBox = h("div", { class: "field-pair" });
  private steps = h("ol", { class: "add-steps" });
  private action = h("div", { class: "add-action" });
  private error = h("p", { class: "error", role: "alert" });
  private key = "";

  constructor(private view: VaultView) {
    const { catalogue, filter } = view.ctx();
    const radio = (value: "env-set" | "secret" | "signer" | "ssh-key", title: string, text: string) => {
      const el = h("input", { type: "radio", name: "add-type", id: "add-type-" + value });
      el.checked = this.type === value;
      el.addEventListener("change", () => {
        this.type = value;
        this.sync(true);
      });
      return h("label", { class: "type-card", for: el.id }, el, h("span", { class: "item-icon" }, itemIcon(value)), h("span", null, h("strong", null, title), h("span", { class: "muted" }, text)));
    };
    const pair = (n: NewNode, what: string) => [h("div", { class: "field" }, h("label", { for: n.title.id }, what + " name"), n.title), h("div", { class: "field" }, h("label", { for: n.slug.id }, "Slug"), n.slug)];
    replace(this.orgNew, pair(this.newOrg, "Organisation"));
    replace(this.serviceNew, pair(this.newService, "Service"));
    replace(this.setBox, pair(this.set, "Item"));
    this.org.addEventListener("change", () => {
      // Another organisation: start from its first service, not the previous choice.
      replace(this.service);
      this.sync(true);
    });
    this.service.addEventListener("change", () => this.sync(true));
    for (const n of [this.newOrg, this.newService, this.set]) for (const el of [n.title, n.slug]) el.addEventListener("input", () => this.sync(true));
    append(this.el, [
      h("h4", null, "1. What is it?"),
      h(
        "div",
        { class: "type-cards", role: "radiogroup", "aria-label": "Type" },
        radio("secret", "Secret (single value)", "One API key, token or password, delivered to a command as one environment variable."),
        radio("env-set", "Env set", "Several values a command gets as environment variables. Type them or import a .env file."),
        radio("signer", "Signing key", "A private key that never leaves the broker: hosts send digests and get signatures back."),
        radio("ssh-key", "SSH key", "A key pair for a forge or a server you add its public line to: hosts log in through aqmas, which keeps the private half."),
      ),
      h("p", { class: "hint muted" }, "SSH targets (machines reached with a short-lived certificate) and Cloudflare scopes are not added here: they come from the bastion's configuration (Settings → Setup)."),
      h("h4", null, "2. Where does it belong?"),
      catalogue ? null : h("p", { class: "warn" }, "The catalogue is not available, so a new item cannot be placed. Reload the page."),
      h("div", { class: "field" }, h("label", { for: "add-org" }, "Organisation"), this.org),
      this.orgNew,
      h("div", { class: "field" }, h("label", { for: "add-service" }, "Service"), this.service),
      this.serviceNew,
      h("h4", { class: "add-name-h" }, "3. What is it called?"),
      this.setBox,
      h("p", { class: "hint muted add-path" }),
      this.error,
      this.steps,
      this.action,
    ]);
    this.fill();
    // Start in the organisation and service the list is filtered to.
    if (filter.org && [...this.org.options].some((o) => o.value === filter.org)) this.org.value = filter.org;
    this.fill();
    if (filter.service && [...this.service.options].some((o) => o.value === filter.service)) this.service.value = filter.service;
  }

  private node(id: string, placeholder: string): NewNode {
    const title = h("input", { type: "text", class: "text", id: id + "-title", maxlength: "64", placeholder, autocomplete: "off" });
    const slug = h("input", { type: "text", class: "text mono", id: id + "-slug", maxlength: "63", placeholder: slugify(placeholder), autocomplete: "off", spellcheck: "false" });
    title.addEventListener("input", () => {
      if (!slug.dataset["typed"]) slug.value = slugify(title.value);
    });
    slug.addEventListener("input", () => (slug.dataset["typed"] = slug.value ? "1" : ""));
    return { id: newSetId(), title, slug };
  }

  /** (Re)fill the two selects from the catalogue, keeping the choice. */
  private fill(): void {
    const cat = this.view.ctx().catalogue;
    const options = (el: HTMLSelectElement, list: { id: string; title: string; slug: string }[], what: string) => {
      const was = el.value;
      replace(el, list.map((o) => h("option", { value: o.id }, vt(`${o.title} (${o.slug})`))), h("option", { value: NEW }, `New ${what}…`));
      // A choice that no longer exists is not replaced by its neighbour: the owner chooses again.
      el.value = [...el.options].some((o) => o.value === was) ? was : was ? NEW : (list[0]?.id ?? NEW);
    };
    options(this.org, cat?.organisations ?? [], "organisation");
    const org = cat?.organisations.find((o) => o.id === this.org.value);
    options(this.service, org?.services.filter((v) => v.provider === "application") ?? [], "service");
  }

  /** Called on every poll: adopt what was created meanwhile, then show the next step. */
  sync(_typed = false): void {
    const { host, forms, state, seal, catalogue: cat } = this.view.ctx();
    // An approved step shows up in the catalogue under the id this form chose for it.
    if (cat?.organisations.some((o) => o.id === this.newOrg.id)) {
      this.fill();
      this.org.value = this.newOrg.id;
      this.newOrg = { ...this.newOrg, id: newSetId() };
    }
    const orgNow = cat?.organisations.find((o) => o.id === this.org.value);
    if (orgNow?.services.some((v) => v.id === this.newService.id)) {
      this.fill();
      this.service.value = this.newService.id;
      this.newService = { ...this.newService, id: newSetId() };
    }
    if (state.sets.some((s) => s.set_id === this.set.id) || cat?.organisations.some((o) => o.services.some((v) => v.sets.some((s) => s.id === this.set.id)))) {
      location.hash = vaultHash(this.set.id);
      return;
    }
    const keep = [this.org.value, this.service.value];
    this.fill();
    if (keep[0] === NEW) this.org.value = NEW;
    this.fill();
    if (keep[1] === NEW || this.org.value === NEW) this.service.value = NEW;
    const org = cat?.organisations.find((o) => o.id === this.org.value);
    const service = org?.services.find((v) => v.id === this.service.value);
    this.orgNew.hidden = this.org.value !== NEW;
    this.serviceNew.hidden = this.service.value !== NEW;
    // A signing key and a secret bring their own form (name, slug and what is specific to them).
    const signer = this.type !== "env-set";
    this.setBox.hidden = signer;
    this.el.querySelector<HTMLElement>(".add-name-h")!.hidden = signer;
    const scope = org ? seal.scopes?.find((s) => s.scope === org.id) : undefined;
    const needKey = !org || (!!scope && !scope.has_key);
    const orgTitle = org?.title ?? this.newOrg.title.value;
    const serviceTitle = service?.title ?? this.newService.title.value;
    const path = `${org?.slug ?? (this.newOrg.slug.value || "…")}/${service?.slug ?? (this.newService.slug.value || "…")}/${signer ? "…" : this.set.slug.value || "…"}`;
    const pathEl = this.el.querySelector<HTMLElement>(".add-path")!;
    replace(pathEl, "Hosts will ask for it as ", h("span", { class: "mono" }, vt(path)), ". The slug cannot be changed later.");

    type Stage = "org" | "key" | "service" | "set";
    const stages: { id: Stage; label: Child; done: boolean }[] = [];
    if (!org) stages.push({ id: "org", label: ["Create the organisation ", h("bdi", null, vt(orgTitle || "…"))], done: false });
    if (needKey) stages.push({ id: "key", label: ["Create its encryption key (three taps: create, enrol this passkey, test)"], done: false });
    if (!service) stages.push({ id: "service", label: ["Create the service ", h("bdi", null, vt(serviceTitle || "…"))], done: false });
    stages.push({ id: "set", label: this.type === "signer" ? "Create the signing key" : this.type === "ssh-key" ? "Create the SSH key" : this.type === "secret" ? "Create the secret with its value" : ["Create the empty env set ", h("bdi", null, vt(this.set.title.value || "…")), ", then add its values"], done: false });
    const stage = stages[0]!.id;
    const key = JSON.stringify([stage, this.type, org?.id, service?.id, stages.length, seal.epoch]);
    replace(this.steps, stages.length > 1 ? stages.map((s, i) => h("li", { class: i === 0 ? "now" : "" }, s.label)) : null);
    this.steps.hidden = stages.length <= 1;
    // A step waiting for its tap is left alone; so is the signer form while it is being filled in.
    if (this.action.querySelector("button.confirm, .vault-confirm")) return;
    if (key === this.key) return;
    this.key = key;
    this.error.textContent = "";
    const valid = (n: NewNode, taken: { slug: string }[], what: string): { id: string; slug: string; title: string; revision: number } | undefined => {
      const title = n.title.value.trim(), slug = n.slug.value;
      if (!TITLE_RE.test(title) || !SLUG_RE.test(slug)) {
        this.error.textContent = `${what}: ${SLUG_HELP}`;
        return undefined;
      }
      if (taken.some((t) => t.slug === slug)) {
        this.error.textContent = `${what}: the slug ${slug} is already used there.`;
        return undefined;
      }
      this.error.textContent = "";
      return { id: n.id, slug, title, revision: 0 };
    };
    // The parents are read from the catalogue at the click, not from the poll that drew the
    // button: the proposal names the rows (and revisions) as they are now.
    const propose = host.propose && cat ? (kind: "organisation" | "service" | "credential_set", n: NewNode, what: string) => {
      const c = this.view.ctx().catalogue;
      const o = c?.organisations.find((x) => x.id === this.org.value);
      const v = o?.services.find((x) => x.id === this.service.value);
      if (!c || (kind !== "organisation" && !o) || (kind === "credential_set" && !v)) {
        this.error.textContent = "The catalogue changed. Choose the place again.";
        return;
      }
      const node = valid(n, kind === "organisation" ? c.organisations : kind === "service" ? o!.services : v!.sets, what);
      if (node) proposeCreate(c, host.propose!, kind, node, o, v);
    } : undefined;
    const review = h("div", { role: "status", class: "wizard-step" });
    if (!propose) return replace(this.action);
    switch (stage) {
      case "org":
        return replace(this.action, h("div", { class: "actions start" }, btn("Create organisation…", "approve", () => propose("organisation", this.newOrg, "Organisation"))));
      case "key":
        return replace(
          this.action,
          h("p", { class: "hint muted" }, h("bdi", null, vt(orgTitle)), " has no encryption key yet. Your signed-in passkey creates it and becomes the first that can open its items; enable your other passkeys afterwards under Security."),
          h(
            "div",
            { class: "actions start" },
            btn("Create its key…", "approve", (ev) => {
              const b = ev.currentTarget as HTMLButtonElement;
              b.disabled = true;
              (host.createScope?.(org!.id, review) ?? Promise.reject(Error("Create the key under Security → Buckets."))).catch((e: unknown) => {
                b.disabled = false;
                replace(review, h("p", { class: "error", role: "alert" }, vt((e as Error).message)));
              });
            }),
          ),
          review,
        );
      case "service":
        return replace(this.action, h("div", { class: "actions start" }, btn("Create service…", "approve", () => propose("service", this.newService, "Service"))));
      case "set":
        if (this.type === "signer") return replace(this.action, forms.newSigner({ org: org!, service: service! }, (id) => (location.hash = vaultHash(id)), this.el));
        if (this.type === "ssh-key") return replace(this.action, forms.newSshKey({ org: org!, service: service! }, (id) => (location.hash = vaultHash(id)), this.el));
        if (this.type === "secret") return replace(this.action, forms.newSecret({ org: org!, service: service! }, (id) => (location.hash = vaultHash(id)), this.el));
        return replace(this.action, h("div", { class: "actions start" }, btn("Create env set…", "approve", () => propose("credential_set", this.set, "Item"))));
    }
  }
}
