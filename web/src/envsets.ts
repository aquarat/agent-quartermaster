import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { type Catalogue } from "./catalogue";
import { type Authenticator } from "./webauthn";
import { checkTap, type Review } from "./review";
import { opensList } from "./approvals";
import { h, replace } from "./dom";
import { countdown, visibleText } from "./format";
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
/** A "don't ask again" rule: later matching releases are approved without a tap. */
export interface Standing extends Binding {
  id: string;
  mode: string;
  address: string;
  max_ttl_seconds: number;
  created_at: number;
  expires_at: number;
  uses: number;
}
/** A host asks to store values (docs/API.md "Env proposals"): the owner commits or discards
 * it with a tap of its own. Key order is the broker's (envset.Proposal): it is what is signed. */
export interface EnvProposal extends Binding {
  id: string;
  /** Six characters, the Ref the CLI printed. */
  ref: string;
  operation: string;
  commitment: string;
  /** As a draft: `NAME:add`, `NAME:replace`, `NAME:remove`, comma-separated. */
  changes: string;
  /** The host's `--why`: unverified, and signed as blank. */
  reason: string;
  address: string;
  new_service: boolean;
  new_set: boolean;
  status: string;
  created_at: number;
  expires_at: number;
  result_revision: number;
}
export interface EnvState {
  drafts: Draft[];
  releases: Release[];
  /** Pending proposals. Never part of an approval window or a batch. */
  proposals?: EnvProposal[];
  standing?: Standing[];
  /** Per set id: the longest "don't ask again" its cards may offer (seconds; 0 = off). */
  standing_caps?: Record<string, number>;
}
const MODES = ["process", "file", "shell", "get"];
/** What a delivery mode does, in the owner's words. */
export function modeWords(mode: string, host: string, names: string[]): string {
  const what = names.length === 1 ? names[0]! : `${names.length} values`;
  switch (mode) {
    case "get":
      return `GET: the value of ${what} is handed to the requesting process on ${host} (aqmas get prints it). From then on it is in that process and has left aqmas.`;
    case "process":
      return `Run: ${what} go${names.length === 1 ? "es" : ""} into the environment of one command on ${host} (aqmas run).`;
    case "file":
      return `File: ${what} written to a RAM-backed .env file on ${host} until check-in or expiry (aqmas checkout).`;
    default:
      return `Shell: ${what} exported into a shell on ${host} (aqmas checkout-shell).`;
  }
}
export const hoursWords = (seconds: number) => (seconds % 3600 === 0 ? `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}` : `${Math.round(seconds / 60)} minutes`);
/** The plain meaning of a "don't ask again" choice. */
export function standingWords(seconds: number, host: string, path: string, mode: string): string {
  const how = mode === "get" ? "aqmas get" : mode === "process" ? "aqmas run" : mode === "file" ? "aqmas checkout" : "aqmas checkout-shell";
  return `For the next ${hoursWords(seconds)}, ${host} gets ${path} whenever it asks with ${how}, without asking you. Each delivery is logged. It ends early if the value changes, the host or policy changes, or you revoke it here.`;
}
/** The "don't ask again" durations a card may offer: the usual steps up to the set's limit. */
export function standingChoices(cap: number): number[] {
  return [3600, 21600, 86400].filter((s) => s <= cap);
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
  standing = 0,
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
    (!draft && !MODES.includes(item.mode))
  )
    throw Error("Unknown or incomplete env profile");
  if (standing !== 0 && (action !== "approve" || draft || ttl <= 0 || !Number.isSafeInteger(standing) || standing < 60)) throw Error("Don't-ask-again goes with a timed approval only");
  const metadata = JSON.stringify(draft ? item : { ...item, reason: "" }, keys)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  // "Don't ask again" is in the request and in the signed text only when chosen.
  const choice = standing > 0 ? { standing_seconds: standing } : {};
  const b = await api.envPost!<Review>("challenge", {
    id: item.id,
    action,
    ttl_seconds: ttl,
    ...choice,
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
      ...choice,
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
        : `${modeWords(item.mode, item.host, item.names)} From ${item.address}. ${action === "approve" ? (ttl === -1 ? "INDEFINITE — until revoked" : `${ttl} seconds${ttl > item.soft_cap_seconds ? " — BEYOND SOFT CAP" : ""}`) : action}. Collection is once only. Copied values remain usable at the provider.${standing > 0 ? " DON'T ASK AGAIN: " + standingWords(standing, item.host, item.path, item.mode) : ""} Requester explanation (unverified): ${item.reason}`) +
      "\n" +
      JSON.stringify(JSON.parse(metadata), null, 2),
    tap: async (auth: Authenticator) =>
      api.envPost!("finish", {
        challenge_id: b.challenge_id,
        ...(await tap.sign(auth)),
      }),
  };
}
const proposalKeys = bindingKeys.concat(["id", "ref", "operation", "commitment", "changes", "reason", "address", "new_service", "new_set", "status", "created_at", "expires_at", "result_revision"]);
export type ProposalAction = "proposal-commit" | "proposal-discard";
/** A proposal's `changes`, by what happens to each key. Anything that is not
 * NAME:add|replace|remove is kept as it came, so the card never hides part of the signed text. */
export function proposalChanges(changes: string): { added: string[]; replaced: string[]; removed: string[]; other: string[] } {
  const out = { added: [] as string[], replaced: [] as string[], removed: [] as string[], other: [] as string[] };
  for (const part of changes === "" ? [] : changes.split(",")) {
    const i = part.lastIndexOf(":"),
      name = part.slice(0, i),
      op = part.slice(i + 1);
    if (i > 0 && op === "add") out.added.push(name);
    else if (i > 0 && op === "replace") out.replaced.push(name);
    else if (i > 0 && op === "remove") out.removed.push(name);
    else out.other.push(part);
  }
  return out;
}
const keysWords = (n: number) => `${n} key${n === 1 ? "" : "s"}`;
/** A proposal in the owner's words: the card and the review before the tap say the same. */
export function proposalWords(p: EnvProposal) {
  const c = proposalChanges(p.changes);
  const [, service = "", set = ""] = p.path.split("/");
  const sent = c.added.length + c.replaced.length;
  const one = c.added[0] ?? c.replaced[0] ?? c.removed[0] ?? "?";
  return {
    who: `${p.host} (${p.class}), from ${p.address}, wants to store values in ${p.path} (${p.title}).`,
    creates: p.new_service
      ? `Committing creates the service ${service} and creates the set ${set}: neither exists yet.`
      : p.new_set
        ? `Committing creates the set ${set}: it does not exist yet.`
        : "",
    operation:
      p.operation === "import"
        ? `Import: REPLACES the whole set. Afterwards ${p.path} holds exactly the ${keysWords(sent)} ${p.host} sent${c.removed.length ? `; ${keysWords(c.removed.length)} in it now ${c.removed.length === 1 ? "is" : "are"} removed` : ""}.`
        : p.operation === "put"
          ? `Put: sets one key, ${one}. The other keys stay as they are.`
          : `Unset: removes one key, ${one}. The other keys stay as they are.`,
    changes: c,
    revision: `${p.revision} → ${p.revision + 1}`,
    values: `The values were chosen by ${p.host}: you see their names here, never the values. Once committed they are what every later request for ${p.path} receives.`,
    compare: `Compare the commitment and Ref ${p.ref} with what the CLI printed on ${p.host}.`,
    reason: `Requester explanation (unverified): ${p.reason}`,
  };
}
/** Whether the broker's proposal is one this page can show and sign: exactly the contract's
 * keys, typed as the broker sends them, and a Ref that is the ID's own (the CLI prints it). */
export function proposalReadable(p: EnvProposal): boolean {
  return !(
    Object.keys(p).length !== proposalKeys.length ||
    !proposalKeys.every((k) => Object.hasOwn(p, k)) ||
    typeof p.path !== "string" ||
    typeof p.title !== "string" ||
    typeof p.host !== "string" ||
    typeof p.class !== "string" ||
    typeof p.address !== "string" ||
    typeof p.reason !== "string" ||
    typeof p.id !== "string" ||
    p.ref !== p.id.slice(-6).toUpperCase() ||
    !p.path ||
    !p.enrollment ||
    !p.id ||
    !Number.isSafeInteger(p.revision) ||
    p.revision < 0 ||
    !Array.isArray(p.names) ||
    typeof p.changes !== "string" ||
    typeof p.new_service !== "boolean" ||
    typeof p.new_set !== "boolean" ||
    (p.new_service && !p.new_set) ||
    (p.new_set && (p.revision !== 0 || p.names.length !== 0 || p.operation === "unset")) ||
    p.status !== "pending" ||
    !/^[0-9a-f]{64}$/.test(p.commitment) ||
    !["import", "put", "unset"].includes(p.operation)
  );
}
/** Commit or discard a proposal: always one fresh tap for this one proposal. The signed
 * metadata is the whole proposal with the reason blank (it is the host's, unverified). */
export async function envProposalReview(api: Api, v: SealView, p: EnvProposal, action: ProposalAction, rp: string) {
  if (!proposalReadable(p)) throw Error("Unknown or incomplete env proposal");
  if (action !== "proposal-commit" && action !== "proposal-discard") throw Error("A proposal is committed or discarded, nothing else");
  const metadata = JSON.stringify({ ...p, reason: "" }, proposalKeys)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  // No duration and no "don't ask again": neither is in the request or in the signed text.
  const b = await api.envPost!<Review>("challenge", { id: p.id, action, ttl_seconds: 0 });
  const tap = await checkTap(b, { v: 3, object: "env", action, id: p.id, installation: v.installation, epoch: v.epoch, metadata, ttl_seconds: 0 }, rp, { allowOpen: false });
  const w = proposalWords(p);
  return {
    detail:
      (action === "proposal-commit"
        ? [`Commit · ${p.title} · Ref ${p.ref}`, w.who, w.creates, w.operation, `Changes: ${p.changes}. Revision ${w.revision}.`, w.values, `Commitment ${p.commitment}`, w.reason]
        : [`Discard · ${p.title} · Ref ${p.ref}`, `Nothing is stored; ${p.host} is told the proposal was discarded.`, w.reason]
      )
        .filter(Boolean)
        .join("\n") +
      "\n" +
      JSON.stringify(JSON.parse(metadata), null, 2),
    tap: async (auth: Authenticator) => api.envPost!("finish", { challenge_id: b.challenge_id, ...(await tap.sign(auth)) }),
  };
}
const standingKeys = bindingKeys.concat(["id", "mode", "address", "max_ttl_seconds", "created_at", "expires_at", "uses"]);
/** Revoke a "don't ask again" rule: the signed text is the rule itself. */
export async function envStandingRevoke(api: Api, v: SealView, st: Standing, rp: string) {
  if (Object.keys(st).length !== standingKeys.length || !standingKeys.every((k) => Object.hasOwn(st, k)) || !MODES.includes(st.mode) || !Array.isArray(st.names)) throw Error("Unknown or incomplete rule");
  // The use counter may move between review and tap; the broker signs it as 0.
  const metadata = JSON.stringify({ ...st, uses: 0 }, standingKeys)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  const b = await api.envPost!<Review>("challenge", { id: st.id, action: "standing-revoke", ttl_seconds: 0 });
  const tap = await checkTap(b, { v: 3, object: "env", action: "standing-revoke", id: st.id, installation: v.installation, epoch: v.epoch, metadata, ttl_seconds: 0 }, rp, { allowOpen: false });
  return {
    detail: `Stop "don't ask again" for ${st.path} on ${st.host}: its next request asks you again.`,
    tap: async (auth: Authenticator) => api.envPost!("finish", { challenge_id: b.challenge_id, ...(await tap.sign(auth)) }),
  };
}
/** The approval card for one proposal. Everything from the host (reason, path, title, key
 * names) goes in as text through visibleText. It has no duration, no "don't ask again" and no
 * checkbox: a proposal is decided alone, by a tap of its own. */
export function proposalCard(api: Api, auth: Authenticator, v: SealView, p: EnvProposal, refresh: () => void): HTMLElement {
  // A proposal this page cannot read is not drawn as one (its words could mislead) and
  // offers no tap; the other cards still render.
  if (!proposalReadable(p)) return h("div", { class: "card env-proposal" }, h("p", { class: "error" }, "A proposal arrived that this page cannot read safely; it cannot be decided here. Reload, or update the page."));
  // Only the latest click's review may offer a tap: Commit then Discard (or the reverse)
  // must never leave the other action's confirm button under the owner's finger.
  let seq = 0;
  const w = proposalWords(p),
    status = h("div", { role: "status", class: "env-proposal-status" });
  const names = (label: string, list: string[], cls: string) => (list.length ? [h("dt", null, label), h("dd", { class: "mono " + cls }, visibleText(list.join(", ")))] : []);
  const left = h("time", { class: "countdown", "data-until": String(p.expires_at), datetime: Number.isFinite(p.expires_at) ? new Date(p.expires_at).toISOString() : "" }, countdown(p.expires_at));
  const act = (label: string, action: ProposalAction, cls: string) => {
    const verb = action === "proposal-commit" ? "Commit" : "Discard";
    const b = h(
      "button",
      {
        class: "btn " + cls,
        type: "button",
        on: {
          click: async () => {
            const mine = ++seq;
            b.disabled = true;
            replace(status, "Checking what the broker asks you to sign…");
            try {
              // The broker's text is checked against this card before anything is offered to tap.
              const r = await envProposalReview(api, v, p, action, location.hostname);
              if (mine !== seq) return;
              const confirm = h(
                "button",
                {
                  class: "btn confirm " + cls,
                  type: "button",
                  on: {
                    click: async () => {
                      confirm.disabled = true;
                      try {
                        await r.tap(auth);
                        replace(status, action === "proposal-commit" ? "Committed." : "Discarded.");
                        refresh();
                      } catch (e) {
                        replace(status, h("p", { class: "error" }, visibleText((e as Error).message)));
                      }
                    },
                  },
                },
                `${verb} with passkey`,
              );
              replace(
                status,
                h("details", { class: "signed" }, h("summary", null, "What you sign"), h("pre", null, visibleText(r.detail))),
                confirm,
                h("button", { class: "btn", type: "button", on: { click: () => (seq++, replace(status)) } }, "Cancel"),
              );
            } catch (e) {
              if (mine === seq) replace(status, h("p", { class: "error" }, visibleText((e as Error).message)));
            } finally {
              b.disabled = false;
            }
          },
        },
      },
      label,
    );
    return b;
  };
  const g = h(
    "div",
    { class: "env-proposal" },
    h("h3", null, visibleText(`${p.path} · ${p.host} · Ref ${p.ref}`)),
    h("p", { class: "env-proposal-who" }, h("span", { class: "kind" }, "Store values"), " ", visibleText(w.who)),
    w.creates ? h("p", { class: "warn env-proposal-creates" }, visibleText(w.creates)) : null,
    h("p", { class: p.operation === "import" ? "warn env-mode" : "env-mode" }, visibleText(w.operation)),
    h(
      "dl",
      { class: "facts env-proposal-changes" },
      names("Added", w.changes.added, "added"),
      names("Replaced", w.changes.replaced, "replaced"),
      names("Removed", w.changes.removed, "removed"),
      names("Other (as sent)", w.changes.other, "other"),
      p.changes === "" ? [h("dt", null, "Changes"), h("dd", null, "None: the set stays as it is, at a new revision.")] : [],
      h("dt", null, "Revision"),
      h("dd", null, w.revision),
      h("dt", null, "Commitment"),
      h("dd", { class: "mono commitment" }, p.commitment),
      h("dt", null, "Ref"),
      h("dd", { class: "mono ref" }, visibleText(p.ref)),
      h("dt", null, "Expires in"),
      h("dd", null, left),
    ),
    h("p", { class: "env-proposal-values" }, visibleText(w.values)),
    h("p", { class: "hint muted env-proposal-compare" }, visibleText(w.compare)),
    h("p", { class: "agent env-proposal-reason" }, visibleText(w.reason)),
    h("div", { class: "actions" }, act("Commit", "proposal-commit", "approve"), act("Discard", "proposal-discard", "deny")),
    status,
  );
  g.setAttribute("data-proposal", p.id);
  return g;
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
  for (const p of state.proposals ?? []) box.append(proposalCard(api, auth, v, p, refresh));
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
    const again = h("select", { class: "text env-standing" }, h("option", { value: "0" }, "Just this once"));
    const meaning = h("p", { class: "hint muted env-standing-words" });
    if (!draft && item.status === "pending") {
      g.setAttribute("data-release", item.id);
      g.append(h("p", { class: item.mode === "get" ? "warn env-mode" : "env-mode" }, visibleText(modeWords(item.mode, item.host, item.names))));
      g.append(h("label", null, "TTL seconds ", amount));
      if (item.ttl_seconds === -1 && item.offers_indefinite)
        g.append(h("label", null, ind, " Indefinite (until revoked)"));
      // "Don't ask again": only up to the set's limit; nothing is preselected.
      const steps = standingChoices(state.standing_caps?.[item.set] ?? 0);
      if (steps.length) {
        for (const s of steps) again.append(h("option", { value: String(s) }, `Don't ask again for ${hoursWords(s)}`));
        const say = () => {
          const s = Number(again.value);
          meaning.textContent = s > 0 ? standingWords(s, item.host, item.path, item.mode) : "";
          meaning.className = s > 0 ? "warn env-standing-words" : "hint muted env-standing-words";
        };
        again.addEventListener("change", say);
        g.append(h("label", null, "Similar requests ", again), meaning);
      } else g.append(h("p", { class: "hint muted env-standing-off" }, "“Don't ask again” is off for this item (Vault → the item → More)."));
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
            action === "approve" && !ind.checked ? Number(again.value) : 0,
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
  for (const st of state.standing ?? []) {
    const g = h(
      "div",
      { class: "env-rule" },
      h("h3", null, visibleText(`${st.path} · ${st.host} · don't ask again`)),
      h("p", { class: "muted" }, visibleText(`${modeWords(st.mode, st.host, st.names)} Approved without asking until ${new Date(st.expires_at).toLocaleString("en-GB")}; used ${st.uses} time${st.uses === 1 ? "" : "s"} so far.`)),
    );
    g.setAttribute("data-rule", st.id);
    g.append(
      button("Review revoke", async () => {
        const p = await envStandingRevoke(api, v, st, location.hostname);
        replace(
          review,
          h("pre", null, visibleText(p.detail)),
          button("Confirm revoke with passkey", async () => {
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
