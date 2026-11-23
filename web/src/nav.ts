// Navigation: the routes, the tabs and which sections each page shows. Pure except navBar.
//
// A new section on a page is one entry in PAGES (and one this.section(...) call in app.ts);
// a new page is one entry in PAGES plus one in TABS.
import { h } from "./dom";
import { navIcon } from "./icons";

export type PageId = "approvals" | "vault" | "hosts" | "activity" | "security" | "settings" | "setup" | "help";

export interface Route {
  page: PageId;
  /** Vault: the selected item's id, or "new" for the Add item form. */
  item?: string;
  /** #r=ID: the card to scroll to on Approvals. */
  focus?: string;
}

export interface PageDef {
  title: string;
  /** The tab that is current while this page is open. */
  tab: PageId;
  /** [section id, heading]: drawn in this order as #sec-<id>. */
  sections: [id: string, heading: string][];
}

export const PAGES: Record<PageId, PageDef> = {
  approvals: { title: "Approvals", tab: "approvals", sections: [] }, // two columns, laid out in app.ts
  vault: { title: "Vault", tab: "vault", sections: [["vault", "Vault"]] },
  hosts: { title: "Hosts", tab: "hosts", sections: [["hosts", "Enrolled hosts"]] },
  activity: { title: "Activity", tab: "activity", sections: [] }, // one section with filters, in app.ts
  security: {
    title: "Passkeys & security",
    tab: "security",
    sections: [
      ["readiness", "Can your passkeys open your credentials?"],
      ["passkeys", "Passkeys"],
      ["buckets", "Buckets open now"],
      ["recovery", "Recovery key"],
    ],
  },
  settings: {
    title: "Settings",
    tab: "settings",
    sections: [
      ["setup", "Setup and upgrades"],
      ["orgs", "Organisations and policies"],
    ],
  },
  setup: { title: "Setup", tab: "settings", sections: [] },
  help: { title: "Help", tab: "help", sections: [["help", "Operator cheat sheet"]] },
};

export const TABS: { id: PageId; label: string; hash: string; title: string }[] = [
  { id: "approvals", label: "Approvals", hash: "#/", title: "Requests waiting for you, active access and auto-approvals" },
  { id: "vault", label: "Vault", hash: "#/vault", title: "Credentials: env sets, signing keys and what the broker holds" },
  { id: "hosts", label: "Hosts", hash: "#/hosts", title: "Enrolled hosts and which organisations they may ask for" },
  { id: "activity", label: "Activity", hash: "#/activity", title: "The audit log" },
  { id: "security", label: "Security", hash: "#/security", title: "Passkeys, open buckets and the recovery key" },
  { id: "settings", label: "Settings", hash: "#/settings", title: "Setup, upgrades and organisation policies" },
  { id: "help", label: "Help", hash: "#/help", title: "Enrollment and command examples" },
];

const ID = /^[A-Za-z0-9_-]{1,64}$/;

/** `#/admin` is the pre-tabs address of what is now Settings (old links and bookmarks). */
export function parseRoute(hash: string): Route {
  const r = /^#r=([A-Za-z0-9_-]{1,64})$/.exec(hash);
  if (r) return { page: "approvals", focus: r[1]! };
  const [, name = "", rest = ""] = /^#\/([a-z]*)(?:\/(.*))?$/.exec(hash) ?? [];
  switch (name) {
    case "vault":
      return ID.test(rest) ? { page: "vault", item: rest } : { page: "vault" };
    case "hosts":
    case "activity":
    case "security":
    case "settings":
    case "setup":
    case "help":
      return { page: name };
    case "admin":
      return { page: "settings" };
    default:
      return { page: "approvals" };
  }
}

export function vaultHash(item?: string): string {
  return item && ID.test(item) ? `#/vault/${item}` : "#/vault";
}

export function pageTitle(page: PageId, pending: number): string {
  const n = pending > 0 ? `(${pending}) ` : "";
  return page === "approvals" ? `${n}aqmas` : `${n}${PAGES[page].title} · aqmas`;
}

/** The tab bar: a row in the header on a wide screen, a bar along the bottom on a phone. */
export function navBar(): HTMLElement {
  return h(
    "nav",
    { class: "tabs", "aria-label": "Pages" },
    TABS.map((t) => {
      const a = h("a", { class: "tab", title: t.title, "data-tab": t.id }, navIcon(t.id), h("span", { class: "tab-label" }, t.label), h("span", { class: "tab-count", "data-count": t.id }));
      a.href = t.hash;
      return a;
    }),
  );
}

/** Mark the current tab and set the count badges (0 or absent: no badge). */
export function updateNav(nav: ParentNode, page: PageId, counts: Partial<Record<PageId, number>>, alerts: Partial<Record<PageId, string>> = {}): void {
  const tab = PAGES[page].tab;
  for (const a of nav.querySelectorAll<HTMLElement>(".tab")) {
    const id = a.dataset["tab"] as PageId;
    if (id === tab) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
    const n = counts[id] ?? 0;
    const badge = a.querySelector<HTMLElement>(".tab-count")!;
    const text = n > 0 ? String(n) : alerts[id] ? "!" : "";
    if (badge.textContent !== text) badge.textContent = text;
    const label = n > 0 ? `${n} waiting` : (alerts[id] ?? "");
    if (label) badge.setAttribute("aria-label", label);
    else badge.removeAttribute("aria-label");
  }
}
