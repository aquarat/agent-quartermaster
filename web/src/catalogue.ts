import { h } from "./dom";
import type { ActionChoice, ActionTarget } from "./flows";
import { visibleText } from "./format";
export type Node = { id: string; slug: string; title: string; revision: number };
export type Policy = {
  default_seconds: number;
  soft_cap_seconds: number;
  indefinite: boolean;
  standing_default_seconds: number;
  standing_soft_cap_seconds: number;
  standing_indefinite: boolean;
  /** "Hosts may list what they can ask for" (absent = off). */
  discovery?: boolean;
  /** `aqmas get` turned off for the organisation's secrets (absent = allowed). */
  deny_get?: boolean;
};
/** The policy as the broker serialises it: the six fields in order, then each switch only
 * while it is on. A policy that uses neither switch has the wire shape it always had. */
export function policyWire(p: Policy): Policy {
  const out: Policy = {
    default_seconds: p.default_seconds,
    soft_cap_seconds: p.soft_cap_seconds,
    indefinite: p.indefinite,
    standing_default_seconds: p.standing_default_seconds,
    standing_soft_cap_seconds: p.standing_soft_cap_seconds,
    standing_indefinite: p.standing_indefinite,
  };
  if (p.discovery) out.discovery = true;
  if (p.deny_get) out.deny_get = true;
  return out;
}
type Rule = { set_id: string; scope: string; auto: boolean; standing: boolean; relax_proxy_duration: boolean };
export type CatHost = {
  row_id: number;
  enrollment: string;
  name: string;
  fingerprint: string;
  class: string;
  active: boolean;
  generation: number;
};
export type Service = Node & { provider: string; sets: (Node & { kind: string; archived: boolean })[] };
export type Org = Node & { services: Service[]; hosts: CatHost[]; auto_access: unknown[]; policy: Policy; rules: Rule[] };
export type Catalogue = { owner_id: string; organisations: Org[] };
const node = (n: Node) => ({ id: n.id, slug: n.slug, title: n.title, revision: n.revision });
const defaults: Policy = {
  default_seconds: 3600,
  soft_cap_seconds: 86400,
  indefinite: true,
  standing_default_seconds: 3600,
  standing_soft_cap_seconds: 86400,
  standing_indefinite: true,
};
export function planString(value: unknown) {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}


export type Sign = (t: ActionTarget, c: ActionChoice) => void;
const btn = (text: string, click: () => void, cls = "btn") => h("button", { class: cls, type: "button", on: { click } }, text);
const propose = (cat: Catalogue, sign: Sign, object: ActionTarget["object"], action: ActionChoice["action"], id: string, proposal: object) =>
  sign({ object, id, facts: { plan: planString({ owner_id: cat.owner_id, ...proposal }) } }, { action });

/** The proposal that creates an organisation, an application service or an empty env set.
 * `n` is the new node (revision 0); the parents are the catalogue's own rows. */
export function proposeCreate(cat: Catalogue, sign: Sign, kind: "organisation" | "service" | "credential_set", n: Node, org?: Node, svc?: Node): void {
  propose(
    cat,
    sign,
    kind,
    "create",
    n.id,
    kind === "organisation"
      ? { organisation: n, new_policy: defaults, result_revision: 1 }
      : kind === "service"
        ? { organisation: node(org!), service: n, kind: "application", result_revision: 1 }
        : { organisation: node(org!), service: node(svc!), set: n, kind: "env-set", result_revision: 0 },
  );
}

type Duration = Exclude<keyof Policy, "discovery" | "deny_get">;
const POLICY_WORDS: Record<Duration, string> = {
  default_seconds: "Grant: default duration (seconds)",
  soft_cap_seconds: "Grant: longest duration (seconds)",
  indefinite: "Grant: offer “until revoked”",
  standing_default_seconds: "Auto-approval: default duration (seconds)",
  standing_soft_cap_seconds: "Auto-approval: longest duration (seconds)",
  standing_indefinite: "Auto-approval: offer “until revoked”",
};
const RULE_WORDS = { auto: "auto-approve", standing: "may have an auto-approval", relax_proxy_duration: "relax the proxy duration" } as const;

/** Settings: one organisation's grant and auto-approval policy, replaced as a whole. */
export function policyForm(cat: Catalogue, o: Org, sign: Sign): HTMLElement {
  const next = { ...o.policy };
  const rules = o.rules.map((r) => ({ ...r }));
  const setTitle = (id: string) => {
    for (const v of o.services) for (const s of v.sets) if (s.id === id) return `${v.slug}/${s.slug}`;
    return id;
  };
  return h(
    "details",
    { class: "policy-form" },
    h("summary", null, "Grant and auto-approval policy"),
    h("p", { class: "muted" }, "SSH certificates are capped at the longest duration and never indefinite until KRL distribution is available. Indefinite is never preselected."),
    h(
      "div",
      { class: "policy-fields" },
      (Object.keys(POLICY_WORDS) as Duration[]).map((key) => {
        const v = next[key];
        const field = h("input", { type: typeof v === "boolean" ? "checkbox" : "number", class: typeof v === "boolean" ? undefined : "text num" });
        if (typeof v === "boolean") {
          field.checked = v;
          field.onchange = () => Object.assign(next, { [key]: field.checked });
          return h("label", { class: "check" }, field, " ", POLICY_WORDS[key]);
        }
        field.value = String(v);
        field.oninput = () => Object.assign(next, { [key]: field.valueAsNumber });
        return h("label", { class: "policy-num" }, POLICY_WORDS[key], " ", field);
      }),
    ),
    (() => {
      // What admitted hosts may learn and do by themselves. Both are part of the same signed
      // policy replacement as the durations above.
      const list = h("input", { type: "checkbox", id: `pol-discovery-${o.id}` });
      list.checked = !!next.discovery;
      list.onchange = () => (next.discovery = list.checked);
      const get = h("input", { type: "checkbox", id: `pol-get-${o.id}` });
      get.checked = !next.deny_get;
      get.onchange = () => (next.deny_get = !get.checked);
      return h(
        "div",
        { class: "policy-switches" },
        h("label", { class: "check", for: list.id }, list, " Hosts may list what they can ask for"),
        h(
          "p",
          { class: "hint muted" },
          "On: every host admitted to this organisation can list the names of its items, the key names of env sets, the variable names of secrets and its SSH targets (aqmas ls, aqmas targets, the MCP tools). Values are never listed. Off (the default): a host has to be told each path; it cannot tell an item it was not told about from one that does not exist.",
        ),
        h("label", { class: "check", for: get.id }, get, " Hosts may ask for a secret's value itself (aqmas get)"),
        h("p", { class: "hint muted" }, "Off: secrets of this organisation are only delivered into a command's environment (aqmas run). Each request still needs your approval either way."),
      );
    })(),
    rules.length ? h("p", { class: "muted" }, "Relaxing applies only to the selected proxy scope. cf.admin: at most 1 h; cf.read.private: at most 2 h. Configured scope ceilings still apply.") : null,
    ...rules.map((r) =>
      h(
        "fieldset",
        null,
        h("legend", null, h("span", { class: "mono" }, visibleText(`${r.scope || "SSH"} · ${setTitle(r.set_id)}`))),
        ...(["auto", "standing", "relax_proxy_duration"] as const).map((k) => {
          const el = h("input", { type: "checkbox" });
          el.checked = r[k];
          el.disabled = (k === "auto" && !["cf.read", "cf.cache.purge"].includes(r.scope)) || (k === "relax_proxy_duration" && (!r.scope || ["cf.admin", "cf.read.private"].includes(r.scope)));
          el.onchange = () => {
            r[k] = el.checked;
          };
          return h("label", { class: "check" }, el, " ", RULE_WORDS[k]);
        }),
      ),
    ),
    h(
      "div",
      { class: "actions start" },
      btn("Review policy replacement…", () =>
        propose(cat, sign, "org_policy", "replace", o.id, { organisation: node(o), old_policy: policyWire(o.policy), new_policy: policyWire(next), old_rules: o.rules, new_rules: rules, result_revision: o.revision + 1 }),
      ),
    ),
  );
}

/** The signed catalogue change that admits a host to an organisation, or removes it: the
 * target and choice for the confirmation sheet. The plan is exactly the catalogue's rows. */
export function admissionProposal(cat: Catalogue, o: Org, host: CatHost): { target: ActionTarget; choice: ActionChoice } {
  const proposal = {
    organisation: node(o),
    host,
    result_revision: host.generation + 1,
    auto_access: host.active ? [] : o.auto_access,
    admitted_services: o.services,
  };
  return { target: { object: "org_host", id: host.enrollment, facts: { plan: planString({ owner_id: cat.owner_id, ...proposal }) } }, choice: { action: host.active ? "remove" : "admit" } };
}

/** Hosts: admit a host to an organisation, or remove it. */
export function admissionButton(cat: Catalogue, o: Org, host: CatHost, sign: Sign): HTMLButtonElement {
  return btn(
    host.active ? "Remove…" : "Admit…",
    () => {
      const p = admissionProposal(cat, o, host);
      sign(p.target, p.choice);
    },
    host.active ? "btn small deny" : "btn small approve",
  );
}

/** What the enrolment approval offers: no organisation (nothing to offer), exactly one
 * (admitting is preselected) or several (the owner chooses one, or "not now"). */
export function admitOffer(cat: Catalogue | null | undefined): { orgs: Org[]; preselected: string | null } {
  const orgs = cat?.organisations ?? [];
  return { orgs, preselected: orgs.length === 1 ? orgs[0]!.id : null };
}
