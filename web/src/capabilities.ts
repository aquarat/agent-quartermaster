// Passkeys and scopes (docs/BUCKETS.md §7): enable a passkey for scopes, test its wraps,
// disable it, register a new one, create an organisation's scope key. Each round covers at
// most two scopes: the signed-in passkey signs the capability change and, in the same tap,
// opens the scope keys; then the passkey being enabled taps once with fresh salts.

import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { canonicalJSON, prepareTap, type OpenPacket } from "./buckets";
import { type Authenticator, decodeCreationOptions, encodeAttestation, type AssertionJSON } from "./webauthn";
import { h, replace } from "./dom";
import { binary32, type Review } from "./review";
import { encode } from "./b64url";
import { visibleText as vt } from "./format";
import { type PasskeyInfo } from "./types";

export type Intent = {
  action: "register" | "enable" | "disable" | "test";
  capability: "unlock" | "approve-only";
  nickname: string;
  /** Target raw credential ID (base64url); "" for register. */
  credential_id: string;
  scopes: string[];
};

export interface Step {
  title: string;
  /** "Round 1 of 2 · tap 1 of 2: …" */
  progress?: string;
  /** What the tap opens or creates, from the descriptor. */
  lines: string[];
  /** Exactly what is signed (the canonical). */
  detail: string;
  tap(auth: Authenticator): Promise<Step | void>;
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
const CORE = ["action", "capability", "credential_id", "epoch", "id", "installation", "issued_at", "nickname", "nonce", "object", "scopes", "v"];
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
  if (i.action !== "disable" && i.action !== "test" && !binary32(c.id)) throw Error("Invalid registration");
  const facts = Object.keys(c)
    .filter((k) => !CORE.includes(k))
    .map((k): [string, string] => [k, typeof c[k] === "string" ? (c[k] as string) : JSON.stringify(c[k])]);
  return { id: typeof c.id === "string" ? c.id : "", facts };
}

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
export async function startCapability(api: Api, v: SealView, i: Intent, rp: string, round = 0, opts: { thenTest?: boolean; skip?: string[] } = {}): Promise<Step> {
  const skip = i.action === "enable" ? (opts.skip ?? []) : [];
  const all = [...new Set(i.scopes)].filter((s) => !skip.includes(s));
  if (i.action === "enable" && i.scopes.length && !all.length) throw Error(`${i.nickname} already opens ${i.scopes.map((s) => titleOf(v, s)).join(", ")} (tested): nothing to enable`);
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
      ? await prepareTap(b, rp, { ...bind, object: "scope-enrol", purposes: ["test"], selected: i.credential_id, requireOpen: true })
      : await prepareTap(b, rp, { ...bind, object: "bucket-open", purposes: ["approve"], allowOpen: i.action !== "disable" });
  const d = tap.open?.descriptor;
  if (i.action === "test" && (d!.credential_id !== i.credential_id || !sameSet(d!.scopes, mine))) throw Error("The test is for another passkey or other scopes");
  if (d && d.object === "bucket-open" && (d.buckets.length || d.scopes.some((s) => !mine.includes(s)))) throw Error("The approving tap would open more than the scopes chosen");
  if (i.action !== "test" && i.action !== "disable") {
    // Every chosen scope that has a key must be opened by this tap, or the enrolment fails.
    const need = mine.filter((s) => keyed.has(s));
    if (need.length && (!d || !sameSet(d.scopes, need))) throw Error("The server did not offer to open the scope keys this needs");
  }
  const taps = i.action === "test" || i.action === "disable" ? 1 : mine.length === 0 ? (i.action === "register" ? 2 : 1) : i.action === "register" ? 3 : 2;
  const prog = (n: number, what: string) => `${rounds > 1 ? `Round ${round + 1} of ${rounds} · ` : ""}tap ${n} of ${taps}: ${what}`;
  const names = mine.map((s) => titleOf(v, s)).join(", ");
  const next = async (target: string): Promise<Step | void> => {
    if (round + 1 >= rounds) {
      if (opts.thenTest && (i.action === "enable" || i.action === "register") && all.length) return startCapability(api, v, { ...i, action: "test", capability: "unlock", credential_id: target, scopes: all }, rp, 0);
      return;
    }
    return startCapability(api, v, { ...i, action: i.action === "register" ? "enable" : i.action, credential_id: target }, rp, round + 1, opts);
  };

  const enrol = async (registration: string, target: string, n: number): Promise<Step> => {
    const e = await api.sealPost!<Evaluated>("passkeys/evaluate", { registration_id: registration });
    const c = JSON.parse(e.canonical) as Record<string, unknown>;
    if (canonicalJSON(c) !== e.canonical || c.v !== 3 || c.installation !== v.installation || c.epoch !== v.epoch || (c.id !== registration && c.registration_id !== registration) || (c.credential_id !== undefined && c.credential_id !== target))
      throw Error("The enrolment text differs from this passkey change");
    const t = await prepareTap(e, rp, { ...bind, object: "scope-enrol", purposes: ["enrol"], selected: target, requireOpen: true });
    const ed = t.open!.descriptor;
    if (ed.credential_id !== target || !sameSet(ed.scopes, mine)) throw Error("The enrolment is for another passkey or other scopes");
    return {
      title: `Create this passkey's keys for ${names}`,
      progress: prog(n, "the passkey being enabled taps"),
      lines: t.lines,
      detail: e.canonical,
      async tap(auth) {
        const s: Signed = await t.sign(auth);
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
        : i.action === "register"
          ? `Add passkey ${i.nickname || "(named after its authenticator)"}${mine.length ? ` for ${names}` : " (approve only)"}`
          : `Enable ${i.nickname} for ${names}`;
  return {
    title: what,
    progress: i.action === "test" ? prog(1, `${i.nickname} taps`) : i.action === "disable" ? undefined : prog(1, "your signed-in passkey approves" + (d ? " and opens the scope keys" : "")),
    lines: [...tap.lines, ...facts.map(([k, x]) => `${k}: ${x}`)],
    detail: b.canonical,
    async tap(auth) {
      const s: Signed = await tap.sign(auth);
      const n = await api.sealPost!<Authorized>("passkeys/authorize", { challenge_id: b.challenge_id, ...s });
      if (i.action === "disable" || i.action === "test") {
        if (!n.ok) throw Error(i.action === "test" ? "The test failed" : "Disabling failed");
        return next(i.credential_id);
      }
      if (n.registration_id !== id) throw Error("Wrong registration");
      if (i.action === "enable") {
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

/** Render each step and its "Confirm with passkey" button; the click starts the prompt
 * synchronously (Safari only allows it inside the user gesture). */
export function runSteps(review: HTMLElement, auth: Authenticator, first: Step, done: () => void): void {
  const show = (s: Step) => {
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

/** Right after a rekey: the rekeying passkey tests its new wrap (one tap). Until it does, the
 * scope opens only from the recovery key. A failed test says so. */
export async function testAfterRekey(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], scope: string, review: HTMLElement, refresh: () => void): Promise<void> {
  const me = pks.find((p) => p.current);
  if (!me?.raw_id) throw Error("Sign in with the passkey that rekeyed, then Security → Passkeys → Test. " + REKEY_TEST_FAILED);
  const step = await startCapability(api, v, { action: "test", capability: "unlock", nickname: me.nickname, credential_id: me.raw_id, scopes: [scope] }, location.hostname);
  runSteps(review, auth, { ...step, title: `Rekey done: test ${me.nickname}'s new key for ${titleOf(v, scope)}`, tap: (a) => step.tap(a).catch((e: unknown) => {
    throw Error(`${(e as Error).message}. ${REKEY_TEST_FAILED}`);
  }) }, refresh);
}

/** Security → Buckets "Create": the signed-in passkey creates an organisation's scope key, then
 * tests it (three taps): the broker writes nothing into a scope no passkey has opened yet. */
export async function createScope(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], scope: string, review: HTMLElement, refresh: () => void): Promise<void> {
  const me = pks.find((p) => p.current);
  if (!me?.raw_id) throw Error("Sign in with a passkey that can hold scope keys first");
  const step = await startCapability(api, v, { action: "enable", capability: "unlock", nickname: me.nickname, credential_id: me.raw_id, scopes: [scope] }, location.hostname, 0, { thenTest: true });
  runSteps(review, auth, step, refresh);
}

/** The Passkeys panel's bucket part: what each passkey opens, Enable/Test/Disable, Add. */
export function capabilityForm(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], refresh: () => void): HTMLElement {
  const box = h("div", { class: "capabilities" });
  const review = h("div", { role: "status" });
  const name = h("input", { placeholder: "New passkey nickname" });
  const btn = (label: string, fn: () => Promise<void>) =>
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
  const start = (i: Intent) => async () => runSteps(review, auth, await startCapability(api, v, i, location.hostname), refresh);
  const keyed = (v.scopes ?? []).filter((s) => s.has_key).map((s) => s.scope);
  for (const p of v.passkeys ?? []) {
    const info = pks.find((x) => x.id === p.id);
    const raw = info?.raw_id ?? "";
    const nick = info?.nickname ?? p.name;
    const row = h(
      "div",
      { class: "pk-buckets", "data-passkey": p.id },
      h("p", null, h("strong", null, vt(nick)), " · ", `Opens ${p.opens} of ${p.of} buckets`, p.current ? " · signed in" : ""),
      !p.prf ? h("p", { class: "warn" }, "Not enabled for any bucket yet: it can sign in and approve, but not open your credentials. Use Enable below (you tap with a passkey that already opens buckets, then with this one). If this authenticator has no PRF support, Enable will say so.") : null,
      p.scopes.length ? h("p", { class: "muted" }, "Enabled for: ", p.scopes.map((s) => `${titleOf(v, s.scope)} (${s.tested ? "tested" : untestedWords(v, s.scope)})`).join(", ")) : null,
      p.missing.length ? h("p", { class: "warn" }, "Not enabled for ", p.missing.map((s) => titleOf(v, s)).join(", ")) : null,
    );
    const acts = h("div", { class: "actions" });
    // Enable covers scopes it lacks and scopes whose wrap is not tested yet (an untested wrap
    // may be replaced), then tests them in the same flow.
    const todo = keyed.filter((s) => !p.scopes.some((x) => x.scope === s && x.tested));
    // p.prf only means "has at least one wrap"; whether the authenticator supports PRF is learnt during Enable.
    if (raw && todo.length)
      acts.append(btn("Enable…", async () => runSteps(review, auth, await startCapability(api, v, { action: "enable", capability: "unlock", nickname: nick, credential_id: raw, scopes: todo }, location.hostname, 0, { thenTest: true, skip: testedScopes(v, pks, raw) }), refresh)));
    if (raw && p.scopes.length) {
      acts.append(btn("Test…", start({ action: "test", capability: "unlock", nickname: nick, credential_id: raw, scopes: p.scopes.map((s) => s.scope) })));
      acts.append(btn("Disable…", start({ action: "disable", capability: "approve-only", nickname: nick, credential_id: raw, scopes: p.scopes.map((s) => s.scope) })));
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
