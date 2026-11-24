// Real owner-side catalogue ceremonies, using exactly the browser's verifier.
import { admissionProposal, planString, type Catalogue } from "../../web/src/catalogue";
import type { Api } from "../../web/src/api";
import type { Authenticator } from "../../web/src/webauthn";
import { completeAction, prepareAction, type ActionChoice, type ActionTarget } from "../../web/src/flows";

const node = (n: { id: string; slug: string; title: string; revision: number }) => ({
  id: n.id,
  slug: n.slug,
  title: n.title,
  revision: n.revision,
});
const fresh = (slug: string) => ({ id: crypto.randomUUID().replaceAll("-", ""), slug, title: slug, revision: 0 });

export async function exerciseCatalogue(api: Api, auth: Authenticator, mode: string) {
  const read = async (): Promise<Catalogue> => {
    const c = await api.catalogue!();
    if (!c) throw Error("missing activated catalogue");
    return c;
  };
  const cat = await read(),
    owner_id = cat.owner_id;
  const prepare = (object: ActionTarget["object"], action: ActionChoice["action"], id: string, p: object) =>
    prepareAction(api, { object, id, facts: { plan: planString({ owner_id, ...p }) } }, { action });
  const apply = async (object: ActionTarget["object"], action: ActionChoice["action"], id: string, p: object) =>
    completeAction(api, auth, await prepare(object, action, id, p));
  const org = async (slug: string) => (await read()).organisations.find((o) => o.slug === slug)!;
  const admit = async (slug: string, active: boolean) => {
    const o = await org(slug),
      host = o.hosts[0]!;
    if (host.active === active) throw Error("unexpected prior admission");
    await apply("org_host", active ? "admit" : "remove", host.enrollment, {
      organisation: node(o),
      host,
      result_revision: host.generation + 1,
      auto_access: active ? o.auto_access : [],
      admitted_services: o.services,
    });
  };
  if (mode.startsWith("add-set:")) {
    // add-set:ORG/SERVICE/SLUG: one more empty env set, created through the web API.
    const [o, sv, slug] = mode.slice(8).split("/");
    const parent = await org(o!),
      service = parent.services.find((s) => s.slug === sv)!,
      set = fresh(slug!);
    await apply("credential_set", "create", set.id, {
      organisation: node(parent),
      service: node(service),
      set,
      kind: "env-set",
      result_revision: 0,
    });
    return;
  }
  if (mode.startsWith("admit-host:")) {
    // admit-host:ORG:NAME: what the page proposes right after it approved NAME's enrolment
    // ("Also admit to ORG"), built by the page's own function.
    const [o, name] = mode.slice(11).split(":");
    const now = await read(),
      parent = now.organisations.find((x) => x.slug === o)!,
      host = parent.hosts.find((h) => h.name === name);
    if (!host || host.active) throw Error("host is not listed as unadmitted");
    const p = admissionProposal(now, parent, host);
    await completeAction(api, auth, await prepareAction(api, p.target, p.choice));
    return;
  }
  if (mode === "remove" || mode === "readmit") {
    await admit("personal", mode === "readmit");
    return;
  }
  if (mode === "relax") {
    const o = await org("personal");
    const next = {
      ...o.policy,
      default_seconds: 120,
      soft_cap_seconds: 300,
      indefinite: true,
      standing_indefinite: true,
    };
    const change = {
      organisation: node(o),
      old_policy: o.policy,
      new_policy: next,
      old_rules: o.rules,
      new_rules: o.rules.map((r) => ({
        ...r,
        relax_proxy_duration: r.scope === "cf.read" || r.scope === "cf.dns.edit",
      })),
      result_revision: o.revision + 1,
    };
    const stale = await prepare("org_policy", "replace", o.id, change);
    await apply("org_policy", "replace", o.id, change);
    try {
      await completeAction(api, auth, stale);
    } catch (e) {
      if ((e as { status: number }).status === 409) return;
      throw e;
    }
    throw Error("accepted stale signed policy");
  }
  for (const slug of ["client-a", "club"]) {
    const n = fresh(slug);
    await apply("organisation", "create", n.id, {
      organisation: n,
      new_policy: {
        default_seconds: 3600,
        soft_cap_seconds: 86400,
        indefinite: true,
        standing_default_seconds: 3600,
        standing_soft_cap_seconds: 86400,
        standing_indefinite: true,
      },
      result_revision: 1,
    });
    let o = await org(slug);
    if (o.hosts.some((h) => h.active) || o.rules.length || o.auto_access.length)
      throw Error("new org inherited authority");
    const service = fresh("paas");
    await apply("service", "create", service.id, {
      organisation: node(o),
      service,
      kind: "application",
      result_revision: 1,
    });
    o = await org(slug);
    const svc = node(o.services[0]!),
      set = fresh("staging");
    await apply("credential_set", "create", set.id, {
      organisation: node(o),
      service: svc,
      set,
      kind: "env-set",
      result_revision: 0,
    });
  }
  await admit("client-a", true);
}
