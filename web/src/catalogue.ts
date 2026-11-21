import { h } from "./dom";
import type { ActionChoice, ActionTarget } from "./flows";
import { visibleText } from "./format";
type Node = { id: string; slug: string; title: string; revision: number };
type Policy = {
  default_seconds: number;
  soft_cap_seconds: number;
  indefinite: boolean;
  standing_default_seconds: number;
  standing_soft_cap_seconds: number;
  standing_indefinite: boolean;
};
type Rule = { set_id: string; scope: string; auto: boolean; standing: boolean; relax_proxy_duration: boolean };
type Host = {
  row_id: number;
  enrollment: string;
  name: string;
  fingerprint: string;
  class: string;
  active: boolean;
  generation: number;
};
type Service = Node & { provider: string; sets: (Node & { kind: string; archived: boolean })[] };
type Org = Node & { services: Service[]; hosts: Host[]; auto_access: unknown[]; policy: Policy; rules: Rule[] };
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

export function cataloguePage(cat: Catalogue, sign: (t: ActionTarget, c: ActionChoice) => void) {
  const owner_id = cat.owner_id;
  const btn = (text: string, click: () => void) =>
    h("button", { class: "btn", type: "button", on: { click } }, text);
  const propose = (object: ActionTarget["object"], action: ActionChoice["action"], id: string, proposal: object) =>
    sign({ object, id, facts: { plan: planString({ owner_id, ...proposal }) } }, { action });
  function create(kind: "organisation" | "service" | "credential_set", org?: Org, svc?: Service) {
    const slug = h("input", { type: "text", maxlength: "63" }),
      title = h("input", { type: "text", maxlength: "64" });
    return h(
      "details",
      null,
      h("summary", null, `Create ${kind === "credential_set" ? "empty credential set" : kind}`),
      h("label", null, "Slug ", slug),
      h("label", null, "Display name ", title),
      btn("Review creation…", () => {
        const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
          b.toString(16).padStart(2, "0"),
        ).join("");
        const n = { id, slug: slug.value, title: title.value, revision: 0 };
        propose(
          kind,
          "create",
          id,
          kind === "organisation"
            ? { organisation: n, new_policy: defaults, result_revision: 1 }
            : kind === "service"
              ? { organisation: node(org!), service: n, kind: "application", result_revision: 1 }
              : { organisation: node(org!), service: node(svc!), set: n, kind: "env-set", result_revision: 0 },
        );
      }),
    );
  }
  function policies(o: Org) {
    const next = { ...o.policy };
    const rules = o.rules.map((r) => ({ ...r }));
    return h(
      "details",
      null,
      h("summary", null, "Grant and standing policy"),
      h(
        "p",
        null,
        "Durations in seconds. SSH certificates are capped at the soft cap and never indefinite until KRL distribution is available. Indefinite is never preselected.",
      ),
      ...Object.entries(next).map(([key, v]) => {
        const field = h("input", { type: typeof v === "boolean" ? "checkbox" : "number" });
        if (typeof v === "boolean") {
          field.checked = v;
          field.onchange = () => Object.assign(next, { [key]: field.checked });
        } else {
          field.value = String(v);
          field.oninput = () => Object.assign(next, { [key]: field.valueAsNumber });
        }
        return h("label", null, key.replaceAll("_", " ") + " ", field);
      }),
      h(
        "p",
        null,
        "Explicit relaxation applies only to the selected proxy scope. cf.admin: at most 1 h; cf.read.private: at most 2 h. Configured scope ceilings still apply.",
      ),
      ...rules.map((r) =>
        h(
          "fieldset",
          null,
          h("legend", null, `${r.scope || "SSH"} · ${r.set_id}`),
          ...(["auto", "standing", "relax_proxy_duration"] as const).map((k) => {
            const el = h("input", { type: "checkbox" });
            el.checked = r[k];
            el.disabled =
              (k === "auto" && !["cf.read", "cf.cache.purge"].includes(r.scope)) ||
              (k === "relax_proxy_duration" && (!r.scope || ["cf.admin", "cf.read.private"].includes(r.scope)));
            el.onchange = () => {
              r[k] = el.checked;
            };
            return h("label", null, el, k.replaceAll("_", " "));
          }),
        ),
      ),
      btn("Review policy replacement…", () =>
        propose("org_policy", "replace", o.id, {
          organisation: node(o),
          old_policy: o.policy,
          new_policy: next,
          old_rules: o.rules,
          new_rules: rules,
          result_revision: o.revision + 1,
        }),
      ),
    );
  }
  function admission(o: Org, host: Host) {
    return h(
      "p",
      null,
      `${host.name} · ${host.class} · ${host.active ? "admitted" : "not admitted"} `,
      btn(host.active ? "Review removal…" : "Review admission…", () =>
        propose("org_host", host.active ? "remove" : "admit", host.enrollment, {
          organisation: node(o),
          host,
          result_revision: host.generation + 1,
          auto_access: host.active ? [] : o.auto_access,
          admitted_services: o.services,
        }),
      ),
    );
  }
  return h(
    "div",
    null,
    create("organisation"),
    ...cat.organisations.map((o) =>
      h(
        "article",
        { class: "card" },
        h("h3", null, visibleText(o.title)),
        h("p", null, `${o.slug} · ${o.id}`),
        policies(o),
        h("h4", null, "Services and credential sets"),
        ...o.services.map((v) =>
          h(
            "div",
            null,
            h("strong", null, visibleText(v.title)),
            ...v.sets.map((s) =>
              h(
                "p",
                null,
                `${o.slug}/${v.slug}/${s.slug} · ${s.kind} · revision ${s.revision}${s.archived ? " · archived" : ""}`,
              ),
            ),
            v.provider === "application" ? create("credential_set", o, v) : null,
          ),
        ),
        create("service", o),
        h("h4", null, "Host admissions"),
        ...o.hosts.map((host) => admission(o, host)),
      ),
    ),
  );
}
