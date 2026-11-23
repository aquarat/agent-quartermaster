// Passkeys and scopes (docs/BUCKETS.md §7): enable a passkey for scopes, test its wraps,
// disable it, register a new one, create an organisation's scope key. Each round covers at
// most two scopes: the signed-in passkey signs the capability change and, in the same tap,
// opens the scope keys; then the passkey being enabled taps once with fresh salts.

import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { browserPath, canonicalJSON, NoPrfError, prepareTap, type OpenPacket } from "./buckets";
import { BrowserKeyError, browserKeyId, defaultLabel, normalizeLabel, NOT_REMEMBERED, shortKey, TRADE_OFF, type BrowserKeys, type LocalBrowserKey } from "./browserKey";
import { decode } from "./b64url";
import { type PasskeyScopes, type RememberedBrowser } from "./sealPanel";
import { type Authenticator, decodeCreationOptions, encodeAttestation, type AssertionJSON } from "./webauthn";
import { h, replace } from "./dom";
import { binary32, type Review } from "./review";
import { encode } from "./b64url";
import { ago, shortDate, visibleText as vt } from "./format";
import { type PasskeyInfo } from "./types";

export type Intent = {
  action: "register" | "enable" | "disable" | "test" | "remember" | "forget";
  capability: "unlock" | "approve-only";
  nickname: string;
  /** Target raw credential ID (base64url); "" for register. */
  credential_id: string;
  scopes: string[];
  /** Remembered browsers (§13): the browser key's public half for remember, forget and the
   * test of that browser's wraps; the label for remember. */
  browser_key?: string;
  browser_label?: string;
};

/** "Remember this browser for …": not a passkey tap but a choice, with the trade-off in plain
 * words and an editable label. accept() makes this browser's key and returns the first tap. */
export interface Offer {
  nickname: string;
  /** Why this is offered (e.g. the passkey returned no PRF result). */
  why: string;
  label: string;
  accept(label: string): Promise<Step>;
}

export interface Step {
  title: string;
  /** "Round 1 of 2 · tap 1 of 2: …" */
  progress?: string;
  /** What the tap opens or creates, from the descriptor. */
  lines: string[];
  /** Exactly what is signed (the canonical). */
  detail: string;
  tap(auth: Authenticator): Promise<Step | void>;
  /** Present on an offer step: runSteps shows the choice instead of a passkey button. */
  offer?: Offer;
}

/** This profile's browser key store and, when it has one, its key. */
export interface BrowserContext {
  keys: BrowserKeys;
  local?: LocalBrowserKey;
}

type Signed = { assertion: AssertionJSON; open?: OpenPacket };
interface Authorized {
  ok?: boolean;
  registration_id?: string;
  public_key?: unknown;
  scopes?: string[];
}
interface Evaluated extends Review {
  open?: { descriptor: string };
}

const ISSUED = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const CORE = ["action", "browser_key", "browser_key_id", "browser_label", "capability", "credential_id", "epoch", "id", "installation", "issued_at", "nickname", "nonce", "object", "scopes", "v"];
const usesBrowser = (i: Intent) => i.action === "remember" || i.action === "forget" || (i.action === "test" && !!i.browser_key);
const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);
function scopesOf(x: unknown): string[] | undefined {
  if (Array.isArray(x) && x.every((s) => typeof s === "string")) return x as string[];
  if (typeof x === "string") return x === "" ? [] : x.split(",");
  return undefined;
}

/** Checks the passkey-capability canonical against the intent; returns the extra plain fields. */
export function checkCapability(text: string, v: SealView, i: Intent, scopes: string[]): { id: string; facts: [string, string][] } {
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(text);
  } catch {
    throw Error("The server's text is not JSON");
  }
  if (canonicalJSON(c) !== text) throw Error("The server's text is not in canonical form");
  if (
    c.v !== 3 ||
    c.object !== "passkey-capability" ||
    c.action !== i.action ||
    c.capability !== i.capability ||
    c.credential_id !== i.credential_id ||
    c.nickname !== i.nickname ||
    c.installation !== v.installation ||
    c.epoch !== v.epoch ||
    !binary32(c.nonce) ||
    typeof c.issued_at !== "string" ||
    !ISSUED.test(c.issued_at)
  )
    throw Error("The server's passkey change differs from what you chose");
  const got = scopesOf(c.scopes);
  if (!got || !sameSet(got, scopes)) throw Error("The server's passkey change names other scopes");
  // The browser key is named exactly when the owner chose a remembered-browser action, and
  // then it is this one: its public half, its fingerprint and (remember) the label typed.
  if (usesBrowser(i)) {
    if (!i.browser_key || c.browser_key !== i.browser_key || typeof c.browser_key_id !== "string" || !/^[0-9a-f]{32}$/.test(c.browser_key_id)) throw Error("The server's passkey change names another browser key");
    if (i.action === "remember" ? c.browser_label !== i.browser_label : c.browser_label !== undefined) throw Error("The server's passkey change names another browser label");
  } else if (c.browser_key !== undefined || c.browser_key_id !== undefined || c.browser_label !== undefined) throw Error("The server's passkey change names a browser key you did not choose");
  if (i.action !== "disable" && i.action !== "test" && i.action !== "forget" && !binary32(c.id)) throw Error("Invalid registration");
  if (usesBrowser(i) && c.browser_key_id !== fingerprintOf.get(i.browser_key!)) throw Error("The server's fingerprint is not that of the browser key you chose");
  const facts = Object.keys(c)
    .filter((k) => !CORE.includes(k))
    .map((k): [string, string] => [k, typeof c[k] === "string" ? (c[k] as string) : JSON.stringify(c[k])]);
  return { id: typeof c.id === "string" ? c.id : "", facts };
}

/** Fingerprints this page computed itself (browser key, base64url → hex), so a card shows and
 * checks the page's own value, not the server's. */
const fingerprintOf = new Map<string, string>();
async function fingerprint(key: string): Promise<string> {
  const id = fingerprintOf.get(key) ?? (await browserKeyId(new Uint8Array(decode(key))));
  fingerprintOf.set(key, id);
  return id;
}

/** Passkeys that returned no PRF result at an enrol tap in this page session: Enable goes
 * straight to the offer for them instead of spending two taps to find out again. */
export const noPrfSeen = new Set<string>();

const titleOf = (v: SealView, s: string) => v.scopes?.find((x) => x.scope === s)?.title || s;

/** The scopes this passkey already opens with a tested wrap: an enable skips them (the broker
 * never replaces a tested wrap). */
export function testedScopes(v: SealView, pks: PasskeyInfo[], raw: string): string[] {
  const id = pks.find((p) => p.raw_id === raw)?.id;
  return (v.passkeys ?? []).find((p) => p.id === id)?.scopes.filter((s) => s.tested).map((s) => s.scope) ?? [];
}

/** The whole loop for one intent: rounds of at most two scopes. Nothing is signed until a
 * step's tap(auth). With `thenTest`, an enable ends with test rounds of the same scopes (a
 * new scope takes no value until a passkey has opened it once, and only a tested wrap lets
 * another passkey be removed). An enable skips `opts.skip` (scopes already tested). */
export async function startCapability(api: Api, v: SealView, i: Intent, rp: string, round = 0, opts: { thenTest?: boolean; skip?: string[]; browser?: BrowserContext } = {}): Promise<Step> {
  const enabling = i.action === "enable" || i.action === "remember";
  const skip = enabling ? (opts.skip ?? []) : [];
  const all = [...new Set(i.scopes)].filter((s) => !skip.includes(s));
  if (enabling && i.scopes.length && !all.length) throw Error(`${i.nickname} already opens ${i.scopes.map((s) => titleOf(v, s)).join(", ")} (tested): nothing to enable`);
  if (usesBrowser(i) && !i.browser_key) throw Error(NOT_REMEMBERED);
  const keyId = usesBrowser(i) ? await fingerprint(i.browser_key!) : "";
  const known = (v.passkeys ?? []).flatMap((p) => p.browsers ?? []).find((x) => x.id === keyId);
  const perRound = 2;
  const rounds = Math.max(1, Math.ceil(all.length / perRound));
  const mine = all.slice(round * perRound, round * perRound + perRound);
  const body = { ...i, scopes: mine };
  i = { ...i, scopes: all };
  const b = await api.sealPost!<Review>("passkeys/challenge", body);
  const { id, facts } = checkCapability(b.canonical, v, i, mine);
  const keyed = new Set((v.scopes ?? []).filter((s) => s.has_key).map((s) => s.scope));
  const bind = { installation: v.installation, epoch: v.epoch };
  const tap =
    i.action === "test"
      ? await prepareTap(b, rp, { ...bind, object: "scope-enrol", purposes: ["test"], selected: i.credential_id, requireOpen: true, ...(i.browser_key ? { browserKey: i.browser_key } : {}) })
      : await prepareTap(b, rp, { ...bind, object: "bucket-open", purposes: ["approve"], allowOpen: i.action !== "disable" && i.action !== "forget" });
  const d = tap.open?.descriptor;
  if (i.action === "test" && (d!.credential_id !== i.credential_id || !sameSet(d!.scopes, mine))) throw Error("The test is for another passkey or other scopes");
  if (d && d.object === "bucket-open" && (d.buckets.length || d.scopes.some((s) => !mine.includes(s)))) throw Error("The approving tap would open more than the scopes chosen");
  if (i.action !== "test" && i.action !== "disable" && i.action !== "forget") {
    // Every chosen scope that has a key must be opened by this tap, or the enrolment fails.
    const need = mine.filter((s) => keyed.has(s));
    if (need.length && (!d || !sameSet(d.scopes, need))) throw Error("The server did not offer to open the scope keys this needs");
  }
  const taps = i.action === "test" || i.action === "disable" || i.action === "forget" ? 1 : mine.length === 0 ? (i.action === "register" ? 2 : 1) : i.action === "register" ? 3 : 2;
  const prog = (n: number, what: string) => `${rounds > 1 ? `Round ${round + 1} of ${rounds} · ` : ""}tap ${n} of ${taps}: ${what}`;
  const names = mine.map((s) => titleOf(v, s)).join(", ");
  const next = async (target: string): Promise<Step | void> => {
    if (round + 1 >= rounds) {
      if (opts.thenTest && (enabling || i.action === "register") && all.length) {
        const { browser_label: _label, ...rest } = i;
        return startCapability(api, v, { ...rest, action: "test", capability: "unlock", credential_id: target, scopes: all }, rp, 0);
      }
      return;
    }
    return startCapability(api, v, { ...i, action: i.action === "register" ? "enable" : i.action, credential_id: target }, rp, round + 1, opts);
  };

  const enrol = async (registration: string, target: string, n: number): Promise<Step> => {
    const e = await api.sealPost!<Evaluated>("passkeys/evaluate", { registration_id: registration });
    const c = JSON.parse(e.canonical) as Record<string, unknown>;
    if (canonicalJSON(c) !== e.canonical || c.v !== 3 || c.installation !== v.installation || c.epoch !== v.epoch || (c.id !== registration && c.registration_id !== registration) || (c.credential_id !== undefined && c.credential_id !== target))
      throw Error("The enrolment text differs from this passkey change");
    const remembering = i.action === "remember";
    if (remembering ? c.browser_key !== i.browser_key : c.browser_key !== undefined) throw Error("The enrolment text names another browser key");
    const t = await prepareTap(e, rp, { ...bind, object: "scope-enrol", purposes: ["enrol"], selected: target, requireOpen: true, ...(remembering ? { browserKey: i.browser_key! } : {}) });
    const ed = t.open!.descriptor;
    if (ed.credential_id !== target || !sameSet(ed.scopes, mine)) throw Error("The enrolment is for another passkey or other scopes");
    return {
      title: remembering ? `Create this browser's keys for ${names}` : `Create this passkey's keys for ${names}`,
      progress: prog(n, "the passkey being enabled taps"),
      lines: t.lines,
      detail: e.canonical,
      async tap(auth) {
        let s: Signed;
        try {
          s = await t.sign(auth);
        } catch (err) {
          // No PRF: this passkey cannot hold the secret itself. Offer the remembered browser.
          if (err instanceof NoPrfError) noPrfSeen.add(target);
          if (err instanceof NoPrfError && i.action === "enable" && opts.browser) return rememberOffer(api, v, { nickname: i.nickname, credential_id: target, scopes: all }, rp, opts.browser, `${i.nickname} returned no PRF result, so it cannot hold the secret itself.`, { thenTest: opts.thenTest });
          if (err instanceof NoPrfError && i.action === "register") throw Error("This passkey returned no PRF result, so it cannot hold a scope key. Add it as an approve-only passkey instead, then use Remember this browser on it.");
          throw err;
        }
        if (!s.open) throw Error("This passkey returned no PRF result, so it cannot hold a scope key");
        const r = await api.sealPost!<Authorized>("passkeys/finish", { registration_id: registration, challenge_id: e.challenge_id, ...s });
        if (!r.ok || (r.scopes && !mine.every((x) => r.scopes!.includes(x)))) throw Error("The broker did not enable every scope");
        return next(target);
      },
    };
  };

  const what =
    i.action === "test"
      ? `Test ${i.nickname} for ${names}`
      : i.action === "disable"
        ? `Disable ${i.nickname} for ${names || "every scope"}`
        : i.action === "forget"
          ? `Forget a remembered browser of ${i.nickname}`
        : i.action === "remember"
          ? `Remember this browser (${i.browser_label}) for ${i.nickname}: ${names}`
        : i.action === "register"
          ? `Add passkey ${i.nickname || "(named after its authenticator)"}${mine.length ? ` for ${names}` : " (approve only)"}`
          : `Enable ${i.nickname} for ${names}`;
  return {
    title: what,
    progress: i.action === "test" ? prog(1, `${i.nickname} taps`) : i.action === "disable" || i.action === "forget" ? undefined : prog(1, "your signed-in passkey approves" + (d ? " and opens the scope keys" : "")),
    lines: [
      ...(i.action === "remember" ? [`This browser's key: ${shortKey(keyId)} (the start of its fingerprint; Security lists it next to the name).`, TRADE_OFF] : []),
      ...(i.action === "forget" ? [`Forgets ${known ? `“${known.label}”` : "a browser"}, key ${shortKey(keyId)}.`, "The broker deletes what it holds for that browser. This passkey then no longer opens anything from it."] : []),
      ...tap.lines,
      ...facts.map(([k, x]) => `${k}: ${x}`),
    ],
    detail: b.canonical,
    async tap(auth) {
      const s: Signed = await tap.sign(auth);
      const n = await api.sealPost!<Authorized>("passkeys/authorize", { challenge_id: b.challenge_id, ...s });
      if (i.action === "disable" || i.action === "test" || i.action === "forget") {
        if (!n.ok) throw Error(i.action === "test" ? "The test failed" : i.action === "forget" ? "Forgetting failed" : "Disabling failed");
        return next(i.credential_id);
      }
      if (n.registration_id !== id) throw Error("Wrong registration");
      if (enabling) {
        if (!mine.length) return next(i.credential_id);
        return enrol(id, i.credential_id, 2);
      }
      const create = decodeCreationOptions(n.public_key);
      if (create.rp.id !== rp || (i.capability === "unlock" && !create.extensions?.prf)) throw Error("Registration options mismatch");
      return {
        title: `Create the new passkey ${i.nickname}`,
        progress: prog(2, "create the new passkey"),
        lines: [mine.length ? "Then it taps once more to create its keys." : "It can sign and approve; it opens no bucket."],
        detail: `Register ${i.nickname}`,
        async tap(auth2) {
          const cr = await auth2.create(create);
          const target = encode(cr.rawId);
          const r = await api.sealPost!<Authorized>("passkeys/create", { registration_id: id, credential: encodeAttestation(cr) });
          if (r.ok === false) throw Error("Registration failed");
          if (!mine.length) return next(target);
          return enrol(id, target, 3);
        },
      };
    },
  };
}

/** The scopes this browser already opens for a passkey with a tested wrap. */
export function browserTested(p: PasskeyScopes | undefined, local: LocalBrowserKey | undefined): string[] {
  return (p?.browsers ?? []).find((b) => local && b.id === local.id)?.scopes.filter((s) => s.tested).map((s) => s.scope) ?? [];
}

/** The offer step: the trade-off, a label, and (on accept) this browser's key is made and the
 * signed remember flow starts. Nothing is created or signed before accept(). */
export function rememberOffer(api: Api, v: SealView, target: { nickname: string; credential_id: string; scopes: string[] }, rp: string, browser: BrowserContext, why: string, opts: { thenTest?: boolean; skip?: string[]; label?: string } = {}): Step {
  const offer: Offer = {
    nickname: target.nickname,
    why,
    label: opts.label ?? defaultLabel(),
    async accept(label) {
      const browser_label = normalizeLabel(label);
      const made = await browser.keys.ensure();
      browser.local = made.key;
      const step = await startCapability(api, v, { action: "remember", capability: "unlock", nickname: target.nickname, credential_id: target.credential_id, scopes: target.scopes, browser_key: made.key.public, browser_label }, rp, 0, { thenTest: opts.thenTest ?? true, skip: opts.skip, browser });
      // A refusal is not an error, but the owner should know the key may be evicted.
      return made.persisted === false ? { ...step, lines: [...step.lines, "This browser did not promise to keep this site's storage. If it evicts the key, this browser is no longer remembered and you enable it again."] } : step;
    },
  };
  return { title: `Remember this browser for ${target.nickname}?`, lines: [], detail: "", tap: async () => undefined, offer };
}

/** Render each step and its "Confirm with passkey" button; the click starts the prompt
 * synchronously (Safari only allows it inside the user gesture). */
export function runSteps(review: HTMLElement, auth: Authenticator, first: Step, done: () => void): void {
  const showOffer = (s: Step, o: Offer) => {
    const label = h("input", { type: "text", maxlength: "64", value: o.label, "aria-label": "Name for this browser" }) as HTMLInputElement;
    const go = h("button", { type: "button", class: "btn approve" }, "Remember this browser…");
    const no = h("button", { type: "button", class: "btn" }, "Not now");
    const out = h("p", { class: "error", role: "alert" });
    go.addEventListener("click", () => {
      go.disabled = true;
      out.textContent = "";
      o.accept(label.value).then(show, (e) => {
        out.textContent = vt((e as Error).message);
        go.disabled = false;
      });
    });
    no.addEventListener("click", () => {
      replace(review, h("p", null, vt(`${o.nickname} was not changed: it still signs in and approves, and opens nothing by itself.`)));
      done();
    });
    replace(
      review,
      h("div", { class: "remember-offer" },
        h("h3", null, vt(s.title)),
        h("p", null, vt(o.why), " It can still open your credentials from a browser you choose to remember."),
        h("p", { class: "warn tradeoff" }, h("strong", null, "The trade-off. "), TRADE_OFF),
        h("ul", { class: "open-lines" },
          h("li", null, "This browser makes a key that cannot be exported and keeps it in its own storage. It is never sent."),
          h("li", null, "The broker stores only ciphertext it cannot open by itself, and hands it to this browser only inside a tap by this passkey. That ciphertext is also in every copy and backup of the broker's database: with this browser's key it opens without the passkey."),
          h("li", null, "A passkey that already opens your credentials approves this, in a signed action that names the passkey and this browser's key."),
          h("li", null, "If this browser's storage is cleared, it is no longer remembered: you enable it again. Forget removes it at any time."),
        ),
        h("label", { class: "browser-label" }, "Name for this browser ", label),
        h("div", { class: "actions" }, go, no),
        out,
      ),
    );
    go.focus();
  };
  const show = (s: Step) => {
    if (s.offer) return showOffer(s, s.offer);
    const go = h("button", { type: "button", class: "btn approve confirm" }, "Confirm with passkey");
    const out = h("p", { class: "error", role: "alert" });
    go.addEventListener("click", () => {
      go.disabled = true;
      out.textContent = "";
      s.tap(auth).then(
        (n) => {
          if (n) show(n);
          else {
            replace(review, h("p", null, "Done."));
            done();
          }
        },
        (e) => {
          out.textContent = vt((e as Error).message);
          go.disabled = false;
        },
      );
    });
    replace(
      review,
      h("h3", null, vt(s.title)),
      s.progress ? h("p", { class: "muted progress" }, vt(s.progress)) : null,
      s.lines.length ? h("ul", { class: "open-lines" }, s.lines.map((l) => h("li", null, vt(l)))) : null,
      h("details", { class: "signed" }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(s.detail))),
      h("div", { class: "actions" }, go),
      out,
    );
    go.focus();
  };
  show(first);
}

/** A keyed scope no passkey has opened since it was made: with buckets in it, only a rekey
 * gets it there. `tested` is absent from an older server: then it reads as tested. */
export const untestedAfterRekey = (v: SealView, scope: string) => {
  const s = v.scopes?.find((x) => x.scope === scope);
  return !!s && s.has_key && s.tested === false && s.buckets > 0;
};
const untestedWords = (v: SealView, scope: string) => (untestedAfterRekey(v, scope) ? "untested after rekey: Test it now" : "not tested yet");

export const REKEY_TEST_FAILED = "The rekeyed scope did not open from this passkey. Try the test again; if it keeps failing, use the recovery key: Security → Recovery key.";

/** The signed-in passkey's own intent fields: a passkey that opens only from remembered
 * browsers acts with this browser's key (and the label this browser already has). */
async function mine(v: SealView, me: PasskeyInfo, browser: BrowserContext | undefined): Promise<{ status?: PasskeyScopes; key?: LocalBrowserKey; label?: string }> {
  const status = (v.passkeys ?? []).find((p) => p.id === me.id);
  if (status?.mode !== "browser") return { status };
  const key = browser?.local ?? (await (browser?.keys ?? browserPath.keys)?.current());
  const known = status.browsers?.find((b) => key && b.id === key.id);
  if (!key || !known) throw new BrowserKeyError(NOT_REMEMBERED);
  return { status, key, label: known.label };
}

/** Right after a rekey: the rekeying passkey tests its new wrap (one tap). Until it does, the
 * scope opens only from the recovery key. A failed test says so. */
export async function testAfterRekey(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], scope: string, review: HTMLElement, refresh: () => void, browser?: BrowserContext): Promise<void> {
  const me = pks.find((p) => p.current);
  if (!me?.raw_id) throw Error("Sign in with the passkey that rekeyed, then Security → Passkeys → Test. " + REKEY_TEST_FAILED);
  const { key } = await mine(v, me, browser);
  const step = await startCapability(api, v, { action: "test", capability: "unlock", nickname: me.nickname, credential_id: me.raw_id, scopes: [scope], ...(key ? { browser_key: key.public } : {}) }, location.hostname);
  runSteps(review, auth, { ...step, title: `Rekey done: test ${me.nickname}'s new key for ${titleOf(v, scope)}`, tap: (a) => step.tap(a).catch((e: unknown) => {
    throw Error(`${(e as Error).message}. ${REKEY_TEST_FAILED}`);
  }) }, refresh);
}

/** Security → Buckets "Create": the signed-in passkey creates an organisation's scope key, then
 * tests it (three taps): the broker writes nothing into a scope no passkey has opened yet. */
export async function createScope(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], scope: string, review: HTMLElement, refresh: () => void, browser?: BrowserContext): Promise<void> {
  const me = pks.find((p) => p.current);
  if (!me?.raw_id) throw Error("Sign in with a passkey that can hold scope keys first");
  const { key, label } = await mine(v, me, browser);
  const intent: Intent = key
    ? { action: "remember", capability: "unlock", nickname: me.nickname, credential_id: me.raw_id, scopes: [scope], browser_key: key.public, browser_label: label! }
    : { action: "enable", capability: "unlock", nickname: me.nickname, credential_id: me.raw_id, scopes: [scope] };
  const step = await startCapability(api, v, intent, location.hostname, 0, { thenTest: true, browser });
  runSteps(review, auth, step, refresh);
}

const HOW_PRF = "with its own secret (PRF)";
const HOW_BROWSER = "only from remembered browsers";

/** How a passkey opens buckets, in words and with a mark that is not colour alone. */
export function howItOpens(p: PasskeyScopes): { mark: string; cls: string; text: string } | undefined {
  if (p.mode === "browser") return { mark: "Browser key", cls: "how-mark browser", text: `Opens buckets ${HOW_BROWSER}` };
  if (p.mode === "prf" || (p.mode === undefined && p.prf)) return { mark: "PRF", cls: "how-mark prf", text: `Opens buckets ${HOW_PRF}` };
  return undefined;
}

/** "Firefox on Linux (key ab12 cd34 ef56), added 1 Nov 2026, last used 2 h ago". */
export function browserWords(b: RememberedBrowser): string {
  return `${b.label} (key ${shortKey(b.id)}), added ${shortDate(b.created_at)}, last used ${b.last_used_at ? ago(b.last_used_at) : "never"}`;
}

/** After Forget: this profile's key is deleted when it was the forgotten one and no other
 * passkey is remembered for it. */
async function dropLocalKey(api: Api, browser: BrowserContext | undefined, forgotten: string): Promise<void> {
  const local = browser?.local ?? (await browser?.keys.current());
  if (!browser || !local || local.id !== forgotten) return;
  try {
    const v = await api.sealStatus!();
    if ((v.passkeys ?? []).some((p) => (p.browsers ?? []).some((b) => b.id === local.id))) return;
  } catch {
    return; // cannot tell: keep the key, it is harmless
  }
  await browser.keys.forget();
  browser.local = undefined;
}

/** The Passkeys panel's bucket part: what each passkey opens and how, Enable/Test/Disable,
 * remembered browsers with Forget, Add. */
export function capabilityForm(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], refresh: () => void, browser?: BrowserContext): HTMLElement {
  const box = h("div", { class: "capabilities" });
  const review = h("div", { role: "status" });
  const name = h("input", { placeholder: "New passkey nickname" });
  const btn = (label: string, fn: () => Promise<void>, cls = "btn") =>
    h(
      "button",
      {
        class: cls,
        type: "button",
        on: {
          click: async (ev) => {
            const el = ev.currentTarget as HTMLButtonElement;
            el.disabled = true;
            try {
              await fn();
            } catch (e) {
              replace(review, h("p", { class: "error", role: "alert" }, vt((e as Error).message)));
            } finally {
              el.disabled = false;
            }
          },
        },
      },
      label,
    );
  const start = (i: Intent, after?: () => Promise<void>) => async () =>
    runSteps(review, auth, await startCapability(api, v, i, location.hostname, 0, { browser }), () => {
      void (after?.() ?? Promise.resolve()).then(refresh, refresh);
    });
  const keyed = (v.scopes ?? []).filter((s) => s.has_key).map((s) => s.scope);
  const local = browser?.local;
  for (const p of v.passkeys ?? []) {
    const info = pks.find((x) => x.id === p.id);
    const raw = info?.raw_id ?? "";
    const nick = info?.nickname ?? p.name;
    const how = howItOpens(p);
    const remembered = p.mode === "browser";
    const here = remembered ? p.browsers?.find((b) => local && b.id === local.id) : undefined;
    const row = h(
      "div",
      { class: "pk-buckets", "data-passkey": p.id, "data-mode": p.mode ?? (p.prf ? "prf" : "") },
      h("p", null, h("strong", null, vt(nick)), " · ", `Opens ${p.opens} of ${p.of} buckets`, p.current ? " · signed in" : ""),
      how ? h("p", { class: "how-line" }, h("span", { class: how.cls }, how.mark), " ", how.text, remembered ? ":" : ".") : null,
      !how ? h("p", { class: "warn" }, "Not enabled for any bucket yet: it can sign in and approve, but not open your credentials. Use Enable below (you tap with a passkey that already opens buckets, then with this one). If this authenticator has no PRF support, Enable says so and offers to remember this browser for it instead.") : null,
    );
    if (remembered) {
      row.append(
        h(
          "ul",
          { class: "browsers" },
          (p.browsers ?? []).map((b) =>
            h(
              "li",
              { "data-browser": b.id },
              h("span", { class: "browser-what" }, h("bdi", null, vt(browserWords(b))), local && b.id === local.id ? h("span", { class: "badge this" }, "this browser") : null),
              h("span", { class: "muted" }, b.scopes.length ? ` Opens: ${b.scopes.map((s) => `${titleOf(v, s.scope)} (${s.tested ? "tested" : untestedWords(v, s.scope)})`).join(", ")}.` : " Opens nothing now (the scope was rekeyed): remember it again."),
              raw ? btn("Forget…", start({ action: "forget", capability: "unlock", nickname: nick, credential_id: raw, scopes: [], browser_key: b.key }, () => dropLocalKey(api, browser, b.id)), "btn small") : null,
            ),
          ),
        ),
      );
      if (!here) row.append(h("p", { class: "warn not-remembered" }, `This browser is not remembered for ${vt(nick)}. If it was, its key is gone (a private window, cleared site data, or the browser evicted this site's storage): this browser is no longer remembered; enable it again.`));
    } else if (p.scopes.length) row.append(h("p", { class: "muted" }, "Enabled for: ", p.scopes.map((s) => `${titleOf(v, s.scope)} (${s.tested ? "tested" : untestedWords(v, s.scope)})`).join(", ")));
    if (p.missing.length && !remembered) row.append(h("p", { class: "warn" }, "Not enabled for ", p.missing.map((s) => titleOf(v, s)).join(", ")));
    const acts = h("div", { class: "actions" });
    if (remembered) {
      // What this browser lacks (or has untested) for this passkey.
      const todo = keyed.filter((s) => !here?.scopes.some((x) => x.scope === s && x.tested));
      if (raw && todo.length && browser)
        acts.append(btn(here ? "Remember this browser for the rest…" : "Remember this browser…", async () => runSteps(review, auth, rememberOffer(api, v, { nickname: nick, credential_id: raw, scopes: todo }, location.hostname, browser, here ? `This browser does not open ${todo.map((s) => titleOf(v, s)).join(", ")} for ${nick} yet.` : `${nick} has no PRF and opens only from remembered browsers.`, { skip: browserTested(p, local), label: here?.label }), refresh)));
      if (raw && here?.scopes.length && local) acts.append(btn("Test this browser…", start({ action: "test", capability: "unlock", nickname: nick, credential_id: raw, scopes: here.scopes.map((s) => s.scope), browser_key: local.public })));
    } else {
      // Enable covers scopes it lacks and scopes whose wrap is not tested yet (an untested wrap
      // may be replaced), then tests them in the same flow.
      const todo = keyed.filter((s) => !p.scopes.some((x) => x.scope === s && x.tested));
      // p.prf only means "has at least one wrap"; whether the authenticator supports PRF is learnt during Enable.
      // A passkey that has (or had) a PRF wrap is never offered the browser path.
      const offerable = !p.prf && !p.had_prf ? browser : undefined;
      if (raw && todo.length)
        acts.append(
          btn("Enable…", async () =>
            runSteps(
              review,
              auth,
              offerable && noPrfSeen.has(raw)
                ? rememberOffer(api, v, { nickname: nick, credential_id: raw, scopes: todo }, location.hostname, offerable, `${nick} returned no PRF result earlier, so it cannot hold the secret itself.`)
                : await startCapability(api, v, { action: "enable", capability: "unlock", nickname: nick, credential_id: raw, scopes: todo }, location.hostname, 0, { thenTest: true, skip: testedScopes(v, pks, raw), browser: offerable }),
              refresh,
            ),
          ),
        );
      if (raw && p.scopes.length) {
        acts.append(btn("Test…", start({ action: "test", capability: "unlock", nickname: nick, credential_id: raw, scopes: p.scopes.map((s) => s.scope) })));
        acts.append(btn("Disable…", start({ action: "disable", capability: "approve-only", nickname: nick, credential_id: raw, scopes: p.scopes.map((s) => s.scope) })));
      }
    }
    row.append(acts);
    box.append(row);
  }
  box.append(
    h("h4", null, "Add a passkey"),
    h("p", { class: "muted" }, "Your signed-in passkey approves; the new one then taps to create its own keys, two scopes per round."),
    name,
    btn("Add a passkey that opens buckets…", async () => start({ action: "register", capability: "unlock", nickname: name.value.trim(), credential_id: "", scopes: keyed })()),
    btn("Add an approve-only passkey…", async () => start({ action: "register", capability: "approve-only", nickname: name.value.trim(), credential_id: "", scopes: [] })()),
    review,
  );
  return box;
}
