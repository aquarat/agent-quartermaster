import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { type Authenticator, encodeAssertion } from "./webauthn";
import { binary32, checkReview, checkTap, type Review } from "./review";
import { encode, decode } from "./b64url";
import { type PendingItem, type PasskeyInfo } from "./types";
import { mismatches, parseCanonical, describe } from "./canonical";
import { targetForPending } from "./flows";
import { h, replace } from "./dom";
import { visibleText } from "./format";
export interface Settings {
  enabled: boolean;
  max_seconds: number;
  idle_seconds: number;
  sets: string[];
}
export interface Rule {
  set: string;
  path: string;
  kind: string;
  scope: string;
  grant_max_seconds: number;
}
export interface Profile {
  org: string;
  title: string;
  personal: boolean;
  window_revision: number;
  policy_revision: number;
  generation: number;
  settings: Settings;
  eligible: Rule[];
}
const exclusions =
  "Individual passkey required: root or high-risk SSH; administrative, private or token-mode Cloudflare; env releases; standing, indefinite and beyond-soft-cap grants; enrollment, admission, catalogue, policy, passkey, broker and update actions.";
interface Receipt {
  id: string;
  token: string;
  expires_at: string;
}
type Open = {
  org: string;
  duration_seconds: number;
  tab_key: string;
  credential_id: string;
};
export async function makeOpening(p: Profile, cred: string, duration: number) {
  p = structuredClone(p);
  if (
    p.settings.max_seconds > 3600 ||
    p.settings.idle_seconds < 15 ||
    p.settings.idle_seconds > p.settings.max_seconds ||
    p.eligible.some(
      (r) =>
        !Number.isSafeInteger(r.grant_max_seconds) ||
        r.grant_max_seconds < 1 ||
        r.grant_max_seconds > 1800 ||
        !(
          (r.kind === "ssh-ca" && r.scope === "") ||
          (r.kind === "cloudflare-proxy" &&
            ["cf.read", "cf.cache.purge"].includes(r.scope))
        ),
    ) ||
    !p.settings.enabled ||
    !Number.isInteger(duration) ||
    duration < 300 ||
    duration > p.settings.max_seconds
  )
    throw Error("Outside window policy");
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const input: Open = {
    org: p.org,
    duration_seconds: duration,
    tab_key: encode(await crypto.subtle.exportKey("raw", pair.publicKey)),
    credential_id: cred,
  };
  return {
    key: pair.privateKey,
    input,
    terms(id: string) {
      if (!binary32(id)) throw Error("Invalid window ID");
      return JSON.stringify({
        org: p.org,
        title: p.title,
        window_revision: p.window_revision,
        policy_revision: p.policy_revision,
        generation: p.generation,
        rules: p.eligible.filter((r) => p.settings.sets.includes(r.set)),
        verbs: "request approve; request deny",
        exclusions,
        duration_seconds: duration,
        idle_seconds: Math.min(duration, p.settings.idle_seconds),
        tab_key: input.tab_key,
        credential_id: cred,
        id,
      });
    },
  };
}
export type Opening = Awaited<ReturnType<typeof makeOpening>>;
type Selection = {
  item: PendingItem;
  action: "approve" | "deny";
  ttl_seconds: number;
};
const choice = (s: Selection) => ({
  id: s.item.id,
  action: s.action,
  ttl_seconds: s.action === "approve" ? s.ttl_seconds : 0,
});
function checkOrdinary(text: string, s: Selection) {
  const c = parseCanonical(text),
    t = targetForPending(s.item);
  if (
    c.v !== 2 ||
    c.object !== "request" ||
    c.action !== s.action ||
    c.ttl_seconds !== choice(s).ttl_seconds ||
    c.standing_hours ||
    c.standing_seconds ||
    c.indefinite ||
    c.standing_indefinite ||
    c.beyond_soft_cap ||
    c.standing_beyond_soft_cap ||
    (c.kind === "ssh" && (c.login_user === "root" || s.item.risk === "high")) ||
    (c.kind === "cloudflare" &&
      (c.mode !== "proxy" ||
        !["cf.read", "cf.cache.purge"].includes(c.scope ?? ""))) ||
    mismatches(c, {
      ...t.facts,
      action: s.action,
      object: "request",
      id: t.id,
      ttl_seconds: choice(s).ttl_seconds,
      standing_hours: 0,
      standing_seconds: 0,
    }).length
  )
    throw Error("Decision does not match the selected card");
  return c;
}
const facts = (text: string, s: Selection) => {
  const d = describe(checkOrdinary(text, s));
  return [
    `Ref ${s.item.id.slice(-6)} · ${d.headline}`,
    ...d.fields.map(([k, v]) => `${k}: ${v}`),
    ...d.warnings,
    `Requester explanation (unverified): ${s.item.reason}`,
    text,
  ].join("\n");
};
export async function batchReview(
  api: Api,
  v: SealView,
  selected: Selection[],
  rp: string,
) {
  const list = structuredClone(selected).sort((a, b) =>
    a.item.id < b.item.id ? -1 : 1,
  );
  if (
    list.length < 1 ||
    list.length > 10 ||
    new Set(list.map((x) => x.item.id)).size !== list.length
  )
    throw Error("Select one to ten distinct requests");
  const b = await api.sealPost!<Review>("batch/challenge", {
    items: list.map(choice),
  });
  if (new TextEncoder().encode(b.canonical).length > 32768)
    throw Error("Oversize batch");
  const c = JSON.parse(b.canonical);
  const texts = JSON.parse(c.items);
  if (
    !binary32(c.id) ||
    !Array.isArray(texts) ||
    texts.length !== list.length ||
    JSON.stringify(texts) !== c.items
  )
    throw Error("Malformed batch selection");
  const details = texts.map((t, i) => {
    const s = list[i]!;
    const a = checkOrdinary(t, s);
    if (a.org_id !== c.org_id || a.org_title !== c.org_title)
      throw Error("Mixed organisations");
    return facts(t, s);
  });
  const tap = await checkTap(
    b,
    {
      v: 3,
      object: "batch",
      action: "decide",
      id: c.id,
      installation: v.installation,
      epoch: v.epoch,
      org_id: c.org_id,
      org_title: c.org_title,
      count: list.length,
      items: c.items,
    },
    rp,
  );
  return {
    text: details.join("\n\n"),
    /** What the tap opens, for the card (format 2). */
    opens: tap.lines,
    tap: async (auth: Authenticator) =>
      api.sealPost!("batch/finish", {
        challenge_id: b.challenge_id,
        ...(await tap.sign(auth)),
      }),
  };
}
function msg(
  installation: string,
  id: string,
  proposal: string,
  digest: ArrayBuffer,
) {
  const te = new TextEncoder();
  const parts = [
    te.encode("aqmas-seal"),
    Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 1),
    te.encode("window-confirm"),
    new Uint8Array(decode(installation)),
    te.encode(id),
    te.encode(proposal),
    new Uint8Array(digest),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  let at = 0;
  for (const p of parts) {
    new DataView(out.buffer).setUint32(at, p.length);
    out.set(p, at + 4);
    at += 4 + p.length;
  }
  return out;
}
export class TabWindow {
  private current?: {
    api: Api;
    key: CryptoKey;
    r: Receipt;
    install: string;
    terms: { org: string; rules: Rule[] };
    timer: number;
  };
  id() {
    return this.current?.r.id;
  }
  forget() {
    if (this.current) window.clearInterval(this.current.timer);
    this.current = undefined;
  }
  end() {
    const c = this.current;
    this.forget();
    if (c)
      void c.api.sealPost!("windows/close", { window_id: c.r.id }).catch(
        () => {},
      );
  }
  start(api: Api, op: Opening, r: Receipt, id: string, install: string) {
    if (r.id !== id || !binary32(r.token))
      throw Error("Unexpected window response");
    this.forget();
    const timer = window.setInterval(() => {
      void api.sealPost!("windows/presence", {
        window_id: id,
        token: r.token,
      }).catch(() => {
        if (this.id() === id) this.forget();
      });
    }, 10000);
    this.current = {
      api,
      key: op.key,
      r,
      install,
      terms: JSON.parse(op.terms(id)),
      timer,
    };
  }
  async prepare(selection: Selection) {
    const c = this.current;
    if (!c) throw Error("Open a window in this tab");
    const s = structuredClone(selection),
      auth = { window_id: c.r.id, token: c.r.token };
    const p = await c.api.sealPost!<{ proposal_id: string; canonical: string }>(
      "windows/prepare",
      { ...auth, choice: choice(s) },
    );
    if (!binary32(p.proposal_id)) throw Error("Invalid proposal");
    const a = checkOrdinary(p.canonical, s);
    if (
      a.org_id !== c.terms.org ||
      !c.terms.rules.some(
        (r) =>
          r.set === a.set_id &&
          r.scope === (a.scope ?? "") &&
          r.kind === (a.kind === "ssh" ? "ssh-ca" : "cloudflare-proxy") &&
          Number(a.ttl_seconds) <= r.grant_max_seconds,
      )
    )
      throw Error("Proposal exceeds the signed window");
    const text = facts(p.canonical, s),
      bytes = msg(
        c.install,
        c.r.id,
        p.proposal_id,
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(p.canonical),
        ),
      );
    return {
      text,
      confirm: async () => {
        if (this.current !== c) throw Error("Window ended");
        const proof = encode(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            c.key,
            bytes,
          ),
        );
        return c.api.sealPost!("windows/confirm", {
          ...auth,
          proposal_id: p.proposal_id,
          proof,
        });
      },
    };
  }
}
export function eligible(v: SealView) {
  return v.verified_access
    ? v.profiles?.find(
        (p) =>
          p.personal &&
          p.settings.enabled &&
          p.eligible.some((r) => p.settings.sets.includes(r.set)),
      )
    : undefined;
}
/** What a tap opens and for how long (format 2), shown before the tap. */
export function opensList(lines: string[]): HTMLElement {
  return lines.length
    ? h("ul", { class: "open-lines" }, lines.map((l) => h("li", null, visibleText(l))))
    : h("p", { class: "muted open-lines" }, "This tap opens no bucket.");
}
const button = (label: string, run: () => Promise<void>, err: HTMLElement) =>
  h(
    "button",
    {
      type: "button",
      class: "btn",
      on: {
        click: async (ev) => {
          const b = ev.currentTarget as HTMLButtonElement;
          b.disabled = true;
          try {
            await run();
          } catch (e) {
            replace(err, visibleText((e as Error).message));
          } finally {
            b.disabled = false;
          }
        },
      },
    },
    label,
  );
export function multiPanel(
  api: Api,
  auth: Authenticator,
  v: SealView,
  tab: TabWindow,
  items: PendingItem[],
  refresh: () => void,
) {
  const box = h("article", { class: "card" }),
    review = h("div", { role: "status" }),
    list: (() => Selection | undefined)[] = [];
  const go = button(
    "Approve selected (0)",
    async () => {
      const selected = list.flatMap((f) => f() ?? []);
      const p = await batchReview(api, v, selected, location.hostname);
      replace(
        review,
        opensList(p.opens),
        h("pre", null, visibleText(p.text)),
        button(
          `Decide ${selected.length} with passkey`,
          async () => {
            await p.tap(auth);
            replace(review, "Applied.");
            refresh();
          },
          review,
        ),
      );
    },
    review,
  );
  for (const item of items) {
    if (
      !item.scoped_facts ||
      item.kind === "enrollment" ||
      item.kind === "bastion" || // a bastion session always needs its own tap
      item.kind === "setup" ||
      item.ssh?.login_user === "root" ||
      item.risk === "high" ||
      item.ttl_requested! <= 0
    )
      continue;
    const on = h("input", { type: "checkbox" }),
      deny = h("input", { type: "checkbox" }),
      ttl = h("input", { type: "number", value: String(item.ttl_requested) });
    const selection = (): Selection => ({
      item,
      action: deny.checked ? "deny" : "approve",
      ttl_seconds: Number(ttl.value),
    });
    list.push(() => (on.checked ? selection() : undefined));
    on.onchange = () => {
      go.textContent = `Approve selected (${list.filter((f) => f()).length})`;
    };
    box.append(
      h(
        "div",
        {},
        h(
          "label",
          null,
          on,
          ` Ref ${item.id.slice(-6)} · ${item.requesting_host} · ${item.ssh?.target_host ?? item.cloudflare?.scope}`,
        ),
        h("label", null, " seconds ", ttl),
        h("label", null, deny, " Deny"),
        tab.id() &&
          button(
            "Review under window",
            async () => {
              const p = await tab.prepare(selection());
              replace(
                review,
                h("pre", null, visibleText(p.text)),
                button(
                  "Confirm under window",
                  async () => {
                    await p.confirm();
                    replace(review, "Applied under window.");
                    refresh();
                  },
                  review,
                ),
              );
            },
            review,
          ),
      ),
    );
  }
  box.append(go, review);
  return box;
}
export function windowAdmin(
  api: Api,
  auth: Authenticator,
  v: SealView,
  tab: TabWindow,
  keys: PasskeyInfo[],
  refresh: () => void,
) {
  const box = h("article", { class: "card" }),
    review = h("div", { role: "status" });
  for (const p of v.profiles ?? []) {
    const enabled = h("input", {
        type: "checkbox",
        checked: p.settings.enabled,
      }),
      abs = h("input", {
        type: "number",
        value: String(p.settings.max_seconds),
      }),
      idle = h("input", {
        type: "number",
        value: String(p.settings.idle_seconds),
      });
    const group = h(
      "div",
      {},
      h("h3", null, visibleText(p.title)),
      h("label", null, enabled, " Allow windows"),
      h("label", null, " Maximum seconds ", abs),
      h("label", null, " Idle seconds ", idle),
    );
    const sets = new Map<string, HTMLInputElement>();
    for (const r of p.eligible) {
      if (!sets.has(r.set)) {
        const el = h("input", {
          type: "checkbox",
          checked: p.settings.sets.includes(r.set),
        });
        sets.set(r.set, el);
        group.append(h("label", null, el, visibleText(r.path)));
      }
    }
    group.append(
      button(
        "Review window policy",
        async () => {
          const settings = {
            enabled: enabled.checked,
            max_seconds: Number(abs.value),
            idle_seconds: Number(idle.value),
            sets: [...sets]
              .filter(([, el]) => el.checked)
              .map(([k]) => k)
              .sort(),
          };
          const b = await api.sealPost!<Review>("windows/policy/challenge", {
            org: p.org,
            settings,
          });
          const opts = await checkReview(
            b,
            {
              object: "window-policy",
              action: "replace",
              v: 3,
              id: p.org,
              installation: v.installation,
              epoch: v.epoch,
              old: JSON.stringify(p),
              new: JSON.stringify(settings),
            },
            location.hostname,
          );
          replace(
            review,
            h("pre", null, visibleText(b.canonical)),
            button(
              "Sign policy change",
              async () => {
                await api.sealPost!("windows/policy/finish", {
                  challenge_id: b.challenge_id,
                  assertion: encodeAssertion(await auth.get(opts)),
                });
                refresh();
              },
              review,
            ),
          );
        },
        review,
      ),
    );
    if (v.verified_access && p.settings.enabled && p.settings.sets.length) {
      const dur = h("input", {
        type: "number",
        value: String(p.settings.max_seconds),
      });
      group.append(h("label", null, " Open for seconds ", dur));
      for (const k of keys) {
        if (!k.raw_id) continue;
        group.append(
          button(
            "Open with " + k.nickname + "…",
            async () => {
              const op = await makeOpening(p, k.raw_id!, Number(dur.value));
              const b = await api.sealPost!<Review>(
                "windows/open/challenge",
                op.input,
              );
              const id = JSON.parse(b.canonical).id,
                terms = op.terms(id);
              const tap = await checkTap(
                b,
                {
                  object: "window",
                  action: "open",
                  v: 3,
                  id,
                  installation: v.installation,
                  epoch: v.epoch,
                  terms,
                },
                location.hostname,
                { selected: k.raw_id },
              );
              replace(
                review,
                opensList(tap.lines),
                h("pre", null, visibleText(terms)),
                button(
                  "Delegate these decisions with passkey",
                  async () => {
                    tab.start(
                      api,
                      op,
                      await api.sealPost!<Receipt>("windows/open/finish", {
                        challenge_id: b.challenge_id,
                        ...(await tap.sign(auth)),
                      }),
                      id,
                      v.installation,
                    );
                    refresh();
                  },
                  review,
                ),
              );
            },
            review,
          ),
        );
      }
    }
    box.append(group);
  }
  box.append(review);
  return box;
}
