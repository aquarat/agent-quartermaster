// "Can my passkeys open my credentials?" (docs/BUCKETS.md §7). A passkey opens a bucket only
// if it holds a tested wrap of the bucket's scope key, and a new or migrated store starts
// with one such passkey. This module says where things stand in one sentence and walks the
// owner through enabling the others, one after the other. It adds no ceremony of its own:
// every tap is a step of capabilities.ts (enable, then test), with the same signed text.
import { type Api } from "./api";
import { browserTested, howItOpens, noPrfSeen, rememberOffer, runSteps, startCapability, testedScopes, type BrowserContext } from "./capabilities";
import { h, replace } from "./dom";
import { shortKey } from "./browserKey";
import { visibleText as vt } from "./format";
import { serving, type PasskeyScopes, type SealView } from "./sealPanel";
import type { PasskeyInfo } from "./types";
import type { Authenticator } from "./webauthn";

export interface Readiness {
  /** Scopes that have a key (the installation and each organisation with one). */
  keyed: string[];
  /** Passkeys with a tested wrap of every keyed scope. */
  ready: PasskeyScopes[];
  /** Passkeys that lack a tested wrap of some scope, and those scopes. The status's `prf`
   * only says "has a wrap already": whether an authenticator supports PRF at all is learnt
   * when it is enabled, so every passkey that opens too little is offered. */
  fixable: { passkey: PasskeyScopes; todo: string[] }[];
  /** The signed-in passkey, when it is one of `ready` (it has to open the keys it shares). */
  opener?: PasskeyScopes;
  /** Keyed scopes that no PRF passkey opens (tested): only remembered browsers do (§13). If
   * those browsers lose their storage, only the recovery key is left. */
  browserOnly: string[];
}

/** undefined: not a format-2 store, or nothing to open yet. */
export function readiness(v: SealView | undefined): Readiness | undefined {
  if (!serving(v) || !v?.passkeys?.length) return undefined;
  const keyed = (v.scopes ?? []).filter((s) => s.has_key).map((s) => s.scope);
  if (!keyed.length) return undefined;
  const out: Readiness = { keyed, ready: [], fixable: [], browserOnly: [] };
  const opens = (mode: string, s: string) => v.passkeys!.some((p) => (mode === "browser" ? p.mode === "browser" : p.mode !== "browser") && p.scopes.some((x) => x.scope === s && x.tested));
  out.browserOnly = keyed.filter((s) => opens("browser", s) && !opens("prf", s));
  for (const p of v.passkeys) {
    const todo = keyed.filter((s) => !p.scopes.some((x) => x.scope === s && x.tested));
    if (todo.length) out.fixable.push({ passkey: p, todo });
    else out.ready.push(p);
  }
  out.opener = out.ready.find((p) => p.current);
  return out;
}

/** "2 of 4 passkeys can open your credentials." */
export function readinessHeadline(r: Readiness): string {
  const total = r.ready.length + r.fixable.length;
  if (r.ready.length === total) return total === 1 ? "Your passkey can open your credentials." : `All ${total} passkeys can open your credentials.`;
  return `${r.ready.length} of ${total} passkeys can open your credentials.`;
}

const names = (v: SealView, scopes: string[]) => scopes.map((s) => v.scopes?.find((x) => x.scope === s)?.title || s).join(", ");

export interface ReadinessHost {
  api: Api;
  auth: Authenticator;
  /** The current passkey list (nicknames and raw credential ids). */
  passkeys(): PasskeyInfo[];
  refresh(): void;
  /** This profile's browser key store and key: without it "Remember this browser" is not offered. */
  browser?: BrowserContext;
}

/** The status card: the sentence, each passkey's state, and "Enable the other N…". */
export function readinessPanel(host: ReadinessHost, v: SealView, r: Readiness): HTMLElement {
  const pks = host.passkeys();
  const nick = (p: PasskeyScopes) => pks.find((x) => x.id === p.id)?.nickname ?? p.name;
  const all = r.fixable.length === 0;
  const box = h("article", { class: `card readiness${all ? " ok" : " attention"}` });
  const flow = h("div", { class: "readiness-flow" });
  const local = host.browser?.local;
  const row = (p: PasskeyScopes, state: string, cls: string, note?: string) => {
    const how = howItOpens(p);
    // A passkey without PRF opens only from the browsers named here: say so in words.
    const from = p.mode === "browser" ? `${how!.text}: ${(p.browsers ?? []).map((b) => b.label + ` (key ${shortKey(b.id)})` + (local && b.id === local.id ? " (this browser)" : "")).join(", ")}${(p.browsers ?? []).some((b) => local && b.id === local.id) ? "" : ". Not this browser"}.` : undefined;
    return h(
      "li",
      { class: cls, "data-mode": p.mode ?? "" },
      h("strong", null, h("bdi", null, vt(nick(p)))),
      p.current ? h("span", { class: "badge this" }, "signed in") : null,
      h("span", { class: "badge state" }, state),
      p.mode === "browser" ? h("span", { class: how!.cls }, how!.mark) : null,
      note ? h("span", { class: "muted" }, " ", vt(note)) : null,
      from ? h("span", { class: "muted how-from" }, " ", vt(from)) : null,
    );
  };
  const start = h("button", { class: "btn approve", type: "button" }, r.fixable.length === 1 ? `Enable ${vt(nick(r.fixable[0]!.passkey))}…` : `Enable the other ${r.fixable.length}…`);
  start.addEventListener("click", () => {
    start.hidden = true;
    void enableAll(host, flow, () => (start.hidden = false));
  });
  box.append(
    h("p", { class: "readiness-head" }, readinessHeadline(r)),
    all
      ? h("p", { class: "muted" }, "Any of them can approve a request that needs a closed bucket. Test one after restoring a backup or changing a password manager: Passkeys → Test.")
      : h("p", null, "Only a passkey that has been enabled can approve a request that needs a closed bucket (reveal, release, sign, reopen). The others can still sign in, deny and revoke."),
    h(
      "ul",
      { class: "readiness-list" },
      r.ready.map((p) => row(p, "opens everything", "ok")),
      r.fixable.map((f) => row(f.passkey, f.passkey.scopes.some((x) => x.tested) ? "opens some" : "opens nothing yet", "todo", `not enabled for ${names(v, f.todo)}`)),
    ),
  );
  if (r.browserOnly.length)
    box.append(h("p", { class: "warn browser-only" }, `${names(v, r.browserOnly)}: only remembered browsers open ${r.browserOnly.length === 1 ? "it" : "them"}. If those browsers lose their storage, only the recovery key is left: enable a passkey with PRF for ${r.browserOnly.length === 1 ? "it" : "them"} too.`));
  if (!all) {
    if (r.opener) box.append(h("p", { class: "muted" }, "You need each passkey at hand: ", h("bdi", null, vt(nick(r.opener))), " approves (one tap per passkey), then the passkey being enabled taps to create its own keys and once more to prove they work. If an authenticator has no PRF support, its step says so and offers to remember this browser for it instead (weaker: the step says how), or skip it (it stays able to sign in and approve)."), h("div", { class: "actions start" }, start));
    else
      box.append(
        h(
          "p",
          { class: "warn" },
          r.ready.length ? ["Sign in with ", h("bdi", null, vt(r.ready.map(nick).join(" or "))), " to enable the others: the passkey that approves has to open the keys it shares."] : "No passkey opens every scope. Enable this one per scope under Passkeys below, or use the recovery key.",
        ),
      );
  }
  box.append(flow);
  return box;
}

/** One passkey after the other: enable for what it lacks, then test. A fresh status before
 * each, so a passkey enabled a moment ago is not asked again. */
async function enableAll(host: ReadinessHost, flow: HTMLElement, idle: () => void): Promise<void> {
  const skipped = new Set<string>();
  let done = 0;
  const next = async (): Promise<void> => {
    let v: SealView;
    try {
      v = await host.api.sealStatus!();
    } catch (e) {
      replace(flow, h("p", { class: "error", role: "alert" }, vt((e as Error).message)));
      return idle();
    }
    const r = readiness(v);
    const todo = (r?.fixable ?? []).filter((f) => !skipped.has(f.passkey.id));
    if (!r || !todo.length) {
      replace(flow, h("p", { class: "vault-done", role: "status" }, r ? readinessHeadline(r) : "Done.", skipped.size ? ` ${skipped.size} skipped: start again when you have ${skipped.size === 1 ? "it" : "them"} at hand.` : ""));
      host.refresh();
      return idle();
    }
    const { passkey: p, todo: scopes } = todo[0]!;
    const pks = host.passkeys();
    const info = pks.find((x) => x.id === p.id);
    const review = h("div", { role: "status", class: "wizard-step" });
    const skip = h("button", { class: "btn small", type: "button" }, "Skip this passkey");
    const stop = h("button", { class: "btn small", type: "button" }, "Stop here");
    skip.addEventListener("click", () => {
      skipped.add(p.id);
      void next();
    });
    stop.addEventListener("click", () => {
      replace(flow);
      host.refresh();
      idle();
    });
    replace(
      flow,
      h(
        "div",
        { class: "wizard" },
        h("p", { class: "wizard-progress" }, `Passkey ${done + skipped.size + 1} of ${done + skipped.size + todo.length}: `, h("strong", null, h("bdi", null, vt(info?.nickname ?? p.name))), ` for ${names(v, scopes)}`),
        review,
        h("div", { class: "actions start" }, skip, stop),
      ),
    );
    if (!info?.raw_id) {
      replace(review, h("p", { class: "error", role: "alert" }, "This server does not say which credential that is. Use Passkeys → Enable below."));
      return;
    }
    try {
      // A passkey that already opens only from remembered browsers is never sent down the
      // PRF path, and the other way round: the offer is explicit either way.
      const offerable = !p.prf && !p.had_prf ? host.browser : undefined;
      const step =
        p.mode === "browser" && host.browser
          ? rememberOffer(host.api, v, { nickname: info.nickname, credential_id: info.raw_id, scopes }, location.hostname, host.browser, `${info.nickname} has no PRF and opens only from remembered browsers.`, { skip: browserTested(p, host.browser.local) })
          : offerable && noPrfSeen.has(info.raw_id)
            ? rememberOffer(host.api, v, { nickname: info.nickname, credential_id: info.raw_id, scopes }, location.hostname, offerable, `${info.nickname} returned no PRF result earlier, so it cannot hold the secret itself.`)
            : await startCapability(host.api, v, { action: "enable", capability: "unlock", nickname: info.nickname, credential_id: info.raw_id, scopes }, location.hostname, 0, { thenTest: true, skip: testedScopes(v, pks, info.raw_id), browser: offerable });
      runSteps(review, host.auth, step, () => {
        done++;
        void next();
      });
    } catch (e) {
      replace(review, h("p", { class: "error", role: "alert" }, vt((e as Error).message)));
    }
  };
  await next();
}
