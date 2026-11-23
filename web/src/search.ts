// Global search (the header's field, "/" or Ctrl+K): vault items by name, path, organisation
// or key name, hosts, passkeys, waiting requests by Ref, and every page and common action.
// It only navigates: choosing a result changes the address, nothing else.
import type { HostInfo } from "./admin";
import { h, replace } from "./dom";
import { visibleText as vt } from "./format";
import { itemIcon, navIcon } from "./icons";
import { TABS, vaultHash } from "./nav";
import type { PasskeyInfo, PendingItem } from "./types";
import { TYPE_WORDS, type VaultItem } from "./vaultItems";

export interface Hit {
  group: "Vault" | "Waiting" | "Hosts" | "Passkeys" | "Go to" | "Do";
  title: string;
  sub: string;
  href: string;
  /** Lower-case text the query is matched against. */
  hay: string;
  /** An item type or a tab id, for the glyph. */
  icon: string;
}

export interface SearchSource {
  items: VaultItem[];
  hosts: HostInfo[];
  passkeys: PasskeyInfo[];
  pending: PendingItem[];
  /** Signature requests and env releases waiting for a decision. */
  signing: { id: string; path: string; host: string }[];
  releases: { id: string; path: string; host: string }[];
  /** Whether the vault can take a new item (organisations active, store sealed). */
  canAdd: boolean;
  /** Passkeys that cannot open every bucket yet. */
  toEnable: number;
}

const ACTIONS: { title: string; sub: string; href: string; icon: string; words: string }[] = [
  { title: "Enable passkeys to open buckets", sub: "Security", href: "#/security", icon: "security", words: "enable passkey prf bucket open unlock" },
  { title: "Add a passkey", sub: "Security → Passkeys", href: "#/security", icon: "security", words: "add register new passkey yubikey" },
  { title: "Close all buckets", sub: "Security → Buckets open now", href: "#/security", icon: "security", words: "close all lock buckets panic" },
  { title: "Recovery key and drill", sub: "Security → Recovery key", href: "#/security", icon: "security", words: "recovery key drill lost" },
  { title: "Admit a host to an organisation", sub: "Hosts", href: "#/hosts", icon: "hosts", words: "admit admission host organisation revoke" },
  { title: "Update aqmas, run a setup task", sub: "Settings → Setup", href: "#/setup", icon: "settings", words: "update upgrade setup seal migrate maintenance" },
  { title: "Grant and auto-approval policy", sub: "Settings → Organisations", href: "#/settings", icon: "settings", words: "policy duration ttl standing auto approval organisation" },
];

export function buildIndex(src: SearchSource): Hit[] {
  const out: Hit[] = [];
  const add = (group: Hit["group"], title: string, sub: string, href: string, icon: string, more = "") => out.push({ group, title, sub, href, icon, hay: `${title}\n${sub}\n${more}`.toLowerCase() });
  for (const it of src.items) add("Vault", it.title, `${TYPE_WORDS[it.type].one} · ${it.path}`, vaultHash(it.id), it.type, `${it.orgTitle}\n${it.serviceTitle}\n${it.names.join("\n")}`);
  for (const p of src.pending) {
    const ref = p.id.slice(-6).toUpperCase();
    add("Waiting", p.kind === "enrollment" ? `Host asking to join: ${p.requesting_host}` : `${p.kind} request from ${p.requesting_host}`, `Ref ${ref}`, `#r=${p.id}`, "approvals", `${p.ssh?.target_host ?? ""} ${p.ssh?.login_user ?? ""} ${p.cloudflare?.scope ?? ""}`);
  }
  for (const r of src.signing) add("Waiting", `Signature request from ${r.host}`, `Ref ${r.id.slice(-6).toUpperCase()} · ${r.path}`, `#r=${r.id}`, "approvals");
  for (const r of src.releases) add("Waiting", `Env release for ${r.host}`, `Ref ${r.id.slice(-6).toUpperCase()} · ${r.path}`, "#/", "approvals");
  for (const x of src.hosts) add("Hosts", x.name, `${x.class} · ${x.address}${x.revoked_at ? " · revoked" : ""}`, "#/hosts", "hosts");
  for (const p of src.passkeys) add("Passkeys", p.nickname, p.authenticator || "Passkey", "#/security", "security");
  if (src.canAdd) add("Do", "Add a credential", "Vault → Add item", vaultHash("new"), "vault", "new create env set signing key secret api key token");
  for (const a of ACTIONS) if (a.title !== ACTIONS[0]!.title || src.toEnable > 0) add("Do", a.title, a.sub, a.href, a.icon, a.words);
  for (const t of TABS) add("Go to", t.label, t.title, t.hash, t.id);
  return out;
}

const GROUP_ORDER: Hit["group"][] = ["Waiting", "Vault", "Do", "Hosts", "Passkeys", "Go to"];

/** Every word must appear. With no query: what is waiting, the actions and the pages. */
export function searchHits(index: Hit[], q: string, limit = 30): Hit[] {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  const pool = words.length ? index.filter((x) => words.every((w) => x.hay.includes(w))) : index.filter((x) => x.group === "Waiting" || x.group === "Do" || x.group === "Go to");
  const first = words[0] ?? "";
  // Title matches before matches elsewhere, within the group order.
  const rank = (x: Hit) => GROUP_ORDER.indexOf(x.group) * 2 + (first && x.title.toLowerCase().includes(first) ? 0 : 1);
  return pool
    .map((x, i) => ({ x, i }))
    .sort((a, b) => rank(a.x) - rank(b.x) || a.i - b.i)
    .slice(0, limit)
    .map((y) => y.x);
}

export class SearchBox {
  /** The header's control. */
  readonly button = h("button", { class: "search-open", type: "button", "aria-label": "Search (press /)", title: "Search vault items, hosts, pages and actions (press /)", "aria-haspopup": "dialog" }, navIcon("search"), h("span", { class: "search-open-label" }, "Search"), h("kbd", { class: "search-key", "aria-hidden": "true" }, "/"));
  private dialog = h("dialog", { class: "search-dialog", "aria-label": "Search" });
  private input = h("input", { type: "search", class: "text search-input", placeholder: "Search items, key names, hosts, pages…", autocomplete: "off", spellcheck: "false", role: "combobox", "aria-controls": "search-results", "aria-expanded": "true", "aria-autocomplete": "list" });
  private results = h("ul", { class: "search-results", id: "search-results", role: "listbox", "aria-label": "Results" });
  private hits: Hit[] = [];
  private active = 0;
  private index: Hit[] = [];

  constructor(private source: () => SearchSource, private prepare?: () => void) {
    this.dialog.append(h("div", { class: "search-head" }, this.input, h("button", { class: "btn small", type: "button", on: { click: () => this.close() } }, "Close")), this.results);
    this.button.addEventListener("click", () => this.open());
    this.input.addEventListener("input", () => this.draw());
    this.input.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
        ev.preventDefault();
        this.move(ev.key === "ArrowDown" ? 1 : -1);
      } else if (ev.key === "Enter") {
        ev.preventDefault();
        this.go(this.hits[this.active]);
      }
    });
    // A click on the backdrop closes, as Escape does.
    this.dialog.addEventListener("click", (ev) => {
      if (ev.target === this.dialog) this.close();
    });
  }

  /** "/" and Ctrl+K (or ⌘K) open the search from anywhere except a text field. */
  bindKeys(target: Document | HTMLElement = document): void {
    target.addEventListener("keydown", (e) => {
      const ev = e as KeyboardEvent;
      const el = ev.target as HTMLElement | null;
      const typing = !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
      const combo = (ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k";
      if (!(combo || (ev.key === "/" && !typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey))) return;
      if (document.querySelector("dialog[open]") && !this.dialog.open) return; // an approval sheet is open
      ev.preventDefault();
      this.open();
    });
  }

  open(): void {
    if (this.dialog.open) return;
    this.prepare?.();
    if (!this.dialog.isConnected) document.body.append(this.dialog);
    this.input.value = "";
    this.dialog.showModal();
    this.refresh();
    this.input.focus();
  }

  close(): void {
    if (this.dialog.open) this.dialog.close();
  }

  /** New data arrived (hosts and the catalogue are fetched when the search opens). */
  refresh(): void {
    if (!this.dialog.open) return;
    this.index = buildIndex(this.source());
    this.draw();
  }

  private go(hit: Hit | undefined): void {
    if (!hit) return;
    this.close();
    location.hash = hit.href;
  }

  private move(by: number): void {
    if (!this.hits.length) return;
    this.active = (this.active + by + this.hits.length) % this.hits.length;
    this.mark();
  }

  private mark(): void {
    const rows = [...this.results.querySelectorAll<HTMLElement>("[role=option]")];
    rows.forEach((li, i) => li.setAttribute("aria-selected", String(i === this.active)));
    const cur = rows[this.active];
    if (cur) {
      this.input.setAttribute("aria-activedescendant", cur.id);
      cur.scrollIntoView?.({ block: "nearest" });
    } else this.input.removeAttribute("aria-activedescendant");
  }

  private draw(): void {
    this.hits = searchHits(this.index, this.input.value);
    this.active = 0;
    let group = "";
    replace(
      this.results,
      this.hits.length
        ? this.hits.map((x, i) => {
            const head = x.group !== group ? h("li", { class: "search-group", role: "presentation" }, (group = x.group)) : null;
            const li = h(
              "li",
              { class: "search-hit", role: "option", id: `search-hit-${i}`, "aria-selected": "false" },
              h("span", { class: "item-icon" }, x.group === "Vault" ? itemIcon(x.icon) : navIcon(x.icon)),
              h("span", { class: "item-text" }, h("span", { class: "item-title" }, h("bdi", null, vt(x.title))), h("span", { class: "item-sub muted" }, vt(x.sub))),
            );
            li.addEventListener("click", () => this.go(x));
            return [head, li];
          })
        : h("li", { class: "empty", role: "presentation" }, "Nothing found."),
    );
    this.mark();
  }
}
