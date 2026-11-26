// The Vault tab's model (no DOM): one list of items from the three things the broker reports
// (application sets with their key names, the catalogue of every organisation's services and
// sets, and the buckets of the sealed store), plus the filters and the search over it.
// Nothing here holds a secret: key names, titles, paths and public keys only.
import type { Catalogue } from "./catalogue";
import type { BucketInfo, SealView } from "./sealPanel";
import type { VaultSet, VaultState } from "./vault";

export type ItemType = "env-set" | "secret" | "signer" | "ssh-key" | "cloudflare" | "ssh-ca" | "internal-ca" | "access";

export const TYPE_WORDS: Record<ItemType, { one: string; many: string }> = {
  "env-set": { one: "Env set", many: "Env sets" },
  secret: { one: "Secret", many: "Secrets" },
  signer: { one: "Signing key", many: "Signing keys" },
  "ssh-key": { one: "SSH key", many: "SSH keys" },
  cloudflare: { one: "Cloudflare", many: "Cloudflare" },
  "ssh-ca": { one: "SSH CA", many: "SSH CAs" },
  "internal-ca": { one: "Internal CA", many: "Internal CAs" },
  access: { one: "Access rule", many: "Access rules" },
};
export const TYPE_ORDER: ItemType[] = ["secret", "env-set", "signer", "ssh-key", "cloudflare", "ssh-ca", "internal-ca", "access"];

export interface VaultItem {
  /** The set id, or "b-" + a short form of the bucket id for a bucket no set stands for. */
  id: string;
  type: ItemType;
  title: string;
  /** org/service/set for a set; the bucket's label otherwise. */
  path: string;
  orgId: string;
  orgTitle: string;
  serviceId: string;
  serviceTitle: string;
  /** One line for the list: "4 keys · revision 7", "Ed25519 · 12 signatures". */
  sub: string;
  /** Key names of an env set (never values). */
  names: string[];
  /** Application sets: what the editor and the signer card work from. */
  set?: VaultSet;
  bucket?: BucketInfo;
  /** The catalogue's kind for a set this page cannot edit (shown as a fact). */
  kind: string;
}

export interface Filter {
  /** "" = every organisation; INSTALLATION = the broker's own keys. */
  org: string;
  service: string;
  type: ItemType | "";
  q: string;
}
export const NO_FILTER: Filter = { org: "", service: "", type: "", q: "" };
export const INSTALLATION = "installation";

const plural = (n: number, one: string, many = one + "s") => (n === 1 ? `1 ${one}` : `${n} ${many}`);

/** A bucket id is base64url of 32 bytes: its first 22 characters identify it in a route. */
export const bucketItemId = (id: string) => "b-" + id.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 22);

function typeOfKind(kind: string, provider: string): ItemType {
  if (kind === "signer") return "signer";
  if (kind === "ssh-key") return "ssh-key";
  if (kind === "secret") return "secret";
  if (kind === "env-set") return "env-set";
  if (provider === "cloudflare" || kind.startsWith("cloudflare") || kind.startsWith("cf-")) return "cloudflare";
  return "access";
}

export function buildItems(vault: VaultState | undefined, cat: Catalogue | null | undefined, seal: SealView | undefined): VaultItem[] {
  const items: VaultItem[] = [];
  const buckets = [...(seal?.buckets ?? [])];
  const takeBucket = (path: string): BucketInfo | undefined => {
    const i = buckets.findIndex((b) => b.label === path && b.kind !== "ssh-ca" && b.kind !== "internal-ca");
    return i < 0 ? undefined : buckets.splice(i, 1)[0];
  };
  const seen = new Set<string>();
  for (const s of vault?.sets ?? []) {
    const path = `${s.org_slug}/${s.service_slug}/${s.set_slug}`;
    const scheme = vault?.schemes.find((x) => x.id === s.scheme)?.title ?? s.scheme ?? "";
    seen.add(s.set_id);
    items.push({
      id: s.set_id,
      type: s.kind === "signer" ? "signer" : s.kind === "ssh-key" ? "ssh-key" : s.kind === "secret" ? "secret" : "env-set",
      title: s.set_title,
      path,
      orgId: s.org_id,
      orgTitle: s.org_title,
      serviceId: s.service_id,
      serviceTitle: s.service_title,
      sub: s.kind === "ssh-key" ? `${vault?.ssh_key_types?.find((x) => x.id === s.scheme)?.title ?? s.scheme ?? ""} · ${plural(s.signatures, "login")}${s.handout ? " · may be handed out" : ""}` : s.kind === "signer" ? `${scheme} · ${plural(s.signatures, "signature")}` : s.kind === "secret" ? `$${s.names[0] ?? "?"} · revision ${s.revision}` : s.names.length ? `${plural(s.names.length, "key")} · revision ${s.revision}` : "empty",
      names: s.kind === "signer" || s.kind === "ssh-key" ? [] : s.names,
      set: s,
      bucket: takeBucket(path),
      kind: s.kind,
    });
  }
  for (const o of cat?.organisations ?? [])
    for (const v of o.services)
      for (const s of v.sets) {
        if (seen.has(s.id) || s.archived) continue;
        const path = `${o.slug}/${v.slug}/${s.slug}`;
        const type = typeOfKind(s.kind, v.provider);
        // An application set the vault did not list (an older server, or one being created).
        items.push({ id: s.id, type, title: s.title, path, orgId: o.id, orgTitle: o.title, serviceId: v.id, serviceTitle: v.title, sub: type === "env-set" || type === "secret" ? `revision ${s.revision}` : s.kind, names: [], bucket: takeBucket(path), kind: s.kind });
      }
  // What is left is the broker's own (the CAs), or a set no list above named.
  for (const b of buckets) {
    // The bucket of an item in the bin: Vault → Deleted lists that item, not this list.
    if (b.label.startsWith("(deleted) ")) continue;
    const type: ItemType = b.kind === "ssh-ca" ? "ssh-ca" : b.kind === "internal-ca" ? "internal-ca" : b.kind === "cf-proxy" ? "cloudflare" : b.kind === "signer" ? "signer" : "env-set";
    const own = b.scope === INSTALLATION;
    items.push({ id: bucketItemId(b.id), type, title: b.label, path: b.label, orgId: own ? INSTALLATION : b.scope, orgTitle: b.scope_title || (own ? "Installation" : b.scope), serviceId: "", serviceTitle: "", sub: own ? "held by the broker" : "Cloudflare parent token", names: [], bucket: b, kind: b.kind });
  }
  return items;
}

/** Every word of the query must appear in the title, path, organisation, service, type or a key name. */
export function matchesQuery(it: VaultItem, q: string): boolean {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [it.title, it.path, it.orgTitle, it.serviceTitle, TYPE_WORDS[it.type].one, ...it.names].join("\n").toLowerCase();
  return words.every((w) => hay.includes(w));
}

export function filterItems(items: VaultItem[], f: Filter): VaultItem[] {
  return items
    .filter((it) => (!f.org || it.orgId === f.org) && (!f.service || it.serviceId === f.service) && (!f.type || it.type === f.type) && matchesQuery(it, f.q))
    .sort((a, b) => a.orgTitle.localeCompare(b.orgTitle) || a.serviceTitle.localeCompare(b.serviceTitle) || a.title.localeCompare(b.title));
}

export interface Folder {
  id: string;
  title: string;
  count: number;
  services: { id: string; title: string; count: number }[];
}

/** The sidebar's tree: every organisation and service (also empty ones, from the catalogue),
 * then the broker's own keys. */
export function folders(items: VaultItem[], cat: Catalogue | null | undefined): Folder[] {
  const out = new Map<string, Folder>();
  const folder = (id: string, title: string) => out.get(id) ?? (out.set(id, { id, title, count: 0, services: [] }), out.get(id)!);
  for (const o of cat?.organisations ?? []) {
    const f = folder(o.id, o.title);
    for (const v of o.services) f.services.push({ id: v.id, title: v.title, count: 0 });
  }
  for (const it of items) {
    const f = folder(it.orgId, it.orgTitle);
    f.count++;
    if (!it.serviceId) continue;
    let s = f.services.find((x) => x.id === it.serviceId);
    if (!s) f.services.push((s = { id: it.serviceId, title: it.serviceTitle, count: 0 }));
    s.count++;
  }
  return [...out.values()].sort((a, b) => Number(a.id === INSTALLATION) - Number(b.id === INSTALLATION) || a.title.localeCompare(b.title));
}

export function typeCounts(items: VaultItem[]): { type: ItemType; count: number }[] {
  return TYPE_ORDER.map((type) => ({ type, count: items.filter((i) => i.type === type).length })).filter((x) => x.count > 0);
}

/** Admitted, unrevoked hosts of the item's organisation: the ones that may ask for it. */
export function requesters(it: VaultItem, cat: Catalogue | null | undefined): { name: string; class: string }[] | undefined {
  const o = cat?.organisations.find((x) => x.id === it.orgId);
  return o?.hosts.filter((x) => x.active).map((x) => ({ name: x.name, class: x.class }));
}
