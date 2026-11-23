import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { type Catalogue } from "./catalogue";
import { type Authenticator } from "./webauthn";
import { checkTap, type Review } from "./review";
import { opensList } from "./approvals";
import { h, replace } from "./dom";
import { visibleText } from "./format";
interface Binding {
  path: string;
  title: string;
  org: string;
  service: string;
  set: string;
  revision: number;
  service_revision: number;
  policy_revision: number;
  admission_generation: number;
  enrollment: string;
  host: string;
  class: string;
  names: string[];
  default_seconds: number;
  soft_cap_seconds: number;
  offers_indefinite: boolean;
}
interface Draft extends Binding {
  id: string;
  operation: string;
  commitment: string;
  changes: string;
  expires_at: number;
}
interface Release extends Binding {
  id: string;
  grant_id: string;
  mode: string;
  address: string;
  reason: string;
  ttl_seconds: number;
  deadline: number;
  not_after: number;
  status: string;
  consumed: boolean;
}
export interface EnvState {
  drafts: Draft[];
  releases: Release[];
}
const bindingKeys = [
  "path",
  "title",
  "org",
  "service",
  "set",
  "revision",
  "service_revision",
  "policy_revision",
  "admission_generation",
  "enrollment",
  "host",
  "class",
  "names",
  "default_seconds",
  "soft_cap_seconds",
  "offers_indefinite",
];
export async function envReview(
  api: Api,
  v: SealView,
  item: Draft | Release,
  action: string,
  ttl: number,
  rp: string,
) {
  const draft = "commitment" in item;
  const keys = bindingKeys.concat(
    draft
      ? ["id", "operation", "commitment", "changes", "expires_at"]
      : [
          "id",
          "grant_id",
          "mode",
          "address",
          "reason",
          "ttl_seconds",
          "deadline",
          "not_after",
          "status",
          "consumed",
        ],
  );
  if (
    Object.keys(item).length !== keys.length ||
    !keys.every((k) => Object.hasOwn(item, k)) ||
    !item.path ||
    !item.enrollment ||
    !Number.isSafeInteger(item.revision) ||
    !Array.isArray(item.names) ||
    (draft &&
      (!/^[0-9a-f]{64}$/.test(item.commitment) ||
        item.class !== "owner-device" ||
        !["import", "put", "unset"].includes(item.operation))) ||
    (!draft && !["process", "file", "shell"].includes(item.mode))
  )
    throw Error("Unknown or incomplete env profile");
  const metadata = JSON.stringify(draft ? item : { ...item, reason: "" }, keys)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  const b = await api.envPost!<Review>("challenge", {
    id: item.id,
    action,
    ttl_seconds: ttl,
  });
  // Approving a release opens the set's bucket (format 2); the other actions open nothing.
  const tap = await checkTap(
    b,
    {
      v: 3,
      object: "env",
      action,
      id: item.id,
      installation: v.installation,
      epoch: v.epoch,
      metadata,
      ttl_seconds: ttl,
    },
    rp,
    { allowOpen: action === "approve" },
  );
  return {
    opens: tap.lines,
    detail:
      `${action} · ${item.title} · Ref ${item.id.slice(-6)}\n` +
      (draft
        ? `Revision ${item.revision} → ${item.revision + 1}. Changes: ${item.changes}. Compare the full commitment against the uploading CLI.`
        : `${item.mode} release to ${item.host}, ${item.address}. ${action === "approve" ? (ttl === -1 ? "INDEFINITE — until revoked" : `${ttl} seconds${ttl > item.soft_cap_seconds ? " — BEYOND SOFT CAP" : ""}`) : action}. Collection is once only. Copied values remain usable at the provider. Requester explanation (unverified): ${item.reason}`) +
      "\n" +
      JSON.stringify(JSON.parse(metadata), null, 2),
    tap: async (auth: Authenticator) =>
      api.envPost!("finish", {
        challenge_id: b.challenge_id,
        ...(await tap.sign(auth)),
      }),
  };
}
export function envPanel(
  api: Api,
  auth: Authenticator,
  v: SealView,
  state: EnvState,
  cat: Catalogue | null | undefined,
  refresh: () => void,
) {
  const box = h("article", { class: "card" }),
    review = h("div", { role: "status" });
  const button = (s: string, f: () => Promise<void>) =>
    h(
      "button",
      {
        class: "btn",
        type: "button",
        on: {
          click: async (ev) => {
            const el = ev.currentTarget as HTMLButtonElement;
            el.disabled = true;
            try {
              await f();
            } catch (e) {
              replace(review, visibleText((e as Error).message));
            } finally {
              el.disabled = false;
            }
          },
        },
      },
      s,
    );
  for (const org of cat?.organisations ?? [])
    for (const service of org.services)
      for (const set of service.sets.filter(
        (s) => s.kind === "env-set" && !s.archived,
      )) {
        const path = [org.slug, service.slug, set.slug].join("/");
        const g = h(
          "div",
          {},
          h("h3", null, visibleText(path + ` · revision ${set.revision}`)),
        );
        for (const host of org.hosts.filter(
          (h) => h.active && h.class === "owner-device",
        ))
          for (const op of ["import", "put", "unset"])
            g.append(
              button(`Ticket for ${op} from ${host.name}`, async () => {
                const res = await api.envPost!<{ ticket: string }>("ticket", {
                  path,
                  operation: op,
                  enrollment: host.enrollment,
                });
                replace(
                  review,
                  "Enter this one-use ticket at the trusted CLI prompt (expires in 5 minutes): ",
                  h("code", null, res.ticket),
                );
              }),
            );
        box.append(g);
      }
  for (const item of [...state.releases, ...state.drafts]) {
    const draft = "commitment" in item,
      g = h(
        "div",
        {},
        h(
          "h3",
          null,
          visibleText(
            item.path + " · " + item.host + " · Ref " + item.id.slice(-6),
          ),
        ),
      );
    const amount = h("input", {
        type: "number",
        value: String(
          draft
            ? 0
            : item.ttl_seconds > 0
              ? item.ttl_seconds
              : item.default_seconds,
        ),
      }),
      ind = h("input", { type: "checkbox" });
    if (!draft && item.status === "pending") {
      g.append(h("label", null, "TTL seconds ", amount));
      if (item.ttl_seconds === -1 && item.offers_indefinite)
        g.append(h("label", null, ind, " Indefinite (until revoked)"));
    }
    for (const action of draft
      ? ["commit", "discard"]
      : item.status === "pending"
        ? ["approve", "deny"]
        : ["revoke"])
      g.append(
        button("Review " + action, async () => {
          const p = await envReview(
            api,
            v,
            item,
            action,
            action === "approve"
              ? ind.checked
                ? -1
                : Number(amount.value)
              : 0,
            location.hostname,
          );
          replace(
            review,
            action === "approve" ? opensList(p.opens) : null,
            h("pre", null, visibleText(p.detail)),
            button("Confirm " + action + " with passkey", async () => {
              await p.tap(auth);
              replace(review, "Applied.");
              refresh();
            }),
          );
        }),
      );
    box.append(g);
  }
  box.append(review);
  return box;
}
