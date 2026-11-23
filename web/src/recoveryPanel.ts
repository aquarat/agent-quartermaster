// Admin → Recovery (docs/BUCKETS.md §7, §10): the recovery drill and enrolling a passkey with
// the recovery key, for when no passkey can open a scope any more. The identity is read once
// from the textarea, which is cleared at once, sealed to a fresh broker key and never stored.

import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { canonicalJSON, openAAD, openInfo, prepareTap, rawB64, sealTo, sha256 } from "./buckets";
import { decode, encode } from "./b64url";
import { binary32, type Review } from "./review";
import { h, replace } from "./dom";
import { visibleText as vt } from "./format";
import { type Authenticator } from "./webauthn";
import { type PasskeyInfo } from "./types";

const utf8 = new TextEncoder();
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const IDENTITY = /^AGE-SECRET-KEY-1[0-9A-Z]{58}$/;

export const RECOVERY_WARNING =
  "This is the rare path. The routine way to give a passkey a scope is to enable it from another passkey that opens the scope (Passkeys → Enable). Pasting the recovery key puts it into this web page: use it only when no passkey can open a scope any more, or for the drill. The key is sealed in this browser to a one-time broker key, used once and never stored.";

export interface RecoveryChoice {
  mode: "drill" | "enrol";
  /** enrol: the target passkey's raw credential ID and at most two scopes. */
  credential_id?: string;
  scopes?: string[];
}
export interface RecoveryResult {
  ok: boolean;
  scopes: number;
  buckets: number;
}

/** Seal the identity text to the broker's recovery key. packet = b64url(enc ‖ ct);
 * packet_sha256 = hex SHA-256 of those packet bytes. Zeroes the plaintext. */
export async function sealIdentity(v: SealView, key: { attempt_id: string; recipient: string }, identity: string): Promise<{ packet: string; packet_sha256: string }> {
  const inst = rawB64(v.installation, 32), epoch = rawB64(v.epoch, 32), attempt = rawB64(key.attempt_id, 32), pub = rawB64(key.recipient, 65);
  const empty = new Uint8Array(0);
  const s = await sealTo(pub, openInfo(inst, "recovery"), openAAD(attempt, epoch, empty, empty), utf8.encode(identity));
  const enc = new Uint8Array(decode(s.enc)), ct = new Uint8Array(decode(s.ciphertext));
  const bytes = new Uint8Array(enc.length + ct.length);
  bytes.set(enc);
  bytes.set(ct, enc.length);
  return { packet: encode(bytes), packet_sha256: hexOf(await sha256(bytes)) };
}

/** Seal, ask for the challenge and check it; returns the card text and the signer. */
export async function beginRecovery(api: Api, v: SealView, choice: RecoveryChoice, identity: string, rp: string) {
  const text = identity.trim();
  if (!IDENTITY.test(text)) throw Error("That is not a recovery key: paste the secret half, starting with AGE-SECRET-KEY-1.");
  if (choice.mode === "enrol" && (!choice.credential_id || !choice.scopes?.length || choice.scopes.length > 2)) throw Error("Choose a passkey and one or two scopes");
  const key = await api.sealPost!<{ attempt_id: string; recipient: string }>("recovery/key", {});
  if (!binary32(key.attempt_id)) throw Error("Invalid recovery key response");
  const { packet, packet_sha256 } = await sealIdentity(v, key, text + "\n");
  const body: Record<string, unknown> = { mode: choice.mode, attempt_id: key.attempt_id, packet_sha256 };
  if (choice.mode === "enrol") Object.assign(body, { credential_id: choice.credential_id, scopes: choice.scopes });
  const b = await api.sealPost!<Review>("recovery/challenge", body);
  const c = JSON.parse(b.canonical) as Record<string, unknown>;
  if (
    canonicalJSON(c) !== b.canonical ||
    c.v !== 3 ||
    c.object !== "recovery" ||
    (c.action !== choice.mode && c.mode !== choice.mode) ||
    c.installation !== v.installation ||
    c.epoch !== v.epoch ||
    c.packet_sha256 !== packet_sha256 ||
    (choice.mode === "enrol" && c.credential_id !== choice.credential_id)
  )
    throw Error("The recovery text differs from what you chose");
  const bind = { installation: v.installation, epoch: v.epoch };
  const tap =
    choice.mode === "enrol"
      ? await prepareTap(b, rp, { ...bind, object: "scope-enrol", purposes: ["enrol"], selected: choice.credential_id, requireOpen: true })
      : await prepareTap(b, rp, { ...bind, allowOpen: false });
  const d = tap.open?.descriptor;
  if (d && (d.credential_id !== choice.credential_id || [...d.scopes].sort().join() !== [...choice.scopes!].sort().join())) throw Error("The enrolment is for another passkey or other scopes");
  return {
    canonical: b.canonical,
    packet_sha256,
    lines: tap.lines,
    /** Call from the tap: the prompt starts before any other await. */
    async finish(auth: Authenticator): Promise<RecoveryResult> {
      const s = await tap.sign(auth);
      if (choice.mode === "enrol" && !s.open) throw Error("This passkey returned no PRF result, so it cannot hold a scope key");
      return api.sealPost!<RecoveryResult>("recovery/finish", { challenge_id: b.challenge_id, packet, ...s });
    },
  };
}

export function recoveryPanel(api: Api, auth: Authenticator, v: SealView, pks: PasskeyInfo[], refresh: () => void): HTMLElement {
  const review = h("div", { role: "status" });
  const identity = h("textarea", { placeholder: "AGE-SECRET-KEY-1…", autocomplete: "off", spellcheck: "false", "aria-label": "Recovery key (secret)" }) as HTMLTextAreaElement;
  const mode = h("select", { "aria-label": "What to do" }, h("option", { value: "drill" }, "Drill: prove the key opens every scope (writes nothing)"), h("option", { value: "enrol" }, "Enrol a passkey from the recovery key")) as HTMLSelectElement;
  const target = h("select", { "aria-label": "Passkey to enrol" }, pks.filter((p) => p.raw_id).map((p) => h("option", { value: p.raw_id! }, vt(p.nickname)))) as HTMLSelectElement;
  const boxes = (v.scopes ?? []).filter((s) => s.has_key).map((s) => {
    const el = h("input", { type: "checkbox", value: s.scope });
    return { el, label: h("label", null, el, " ", vt(s.title || s.scope)) };
  });
  const err = h("p", { class: "error", role: "alert" });
  const go = h("button", { type: "button", class: "btn" }, "Review…");
  go.addEventListener("click", async () => {
    // Read once and clear at once: the key leaves this page only as ciphertext.
    const text = identity.value;
    identity.value = "";
    err.textContent = "";
    go.disabled = true;
    try {
      const choice: RecoveryChoice = mode.value === "enrol" ? { mode: "enrol", credential_id: target.value, scopes: boxes.filter((b) => b.el.checked).map((b) => b.el.value) } : { mode: "drill" };
      const r = await beginRecovery(api, v, choice, text, location.hostname);
      const sign = h("button", { type: "button", class: "btn approve confirm" }, choice.mode === "drill" ? "Run the drill with passkey" : "Enrol with passkey");
      sign.addEventListener("click", () => {
        sign.disabled = true;
        r.finish(auth).then(
          (res) => {
            replace(review, h("p", null, `${choice.mode === "drill" ? "Drill passed" : "Enrolled"}: ${res.scopes} scope${res.scopes === 1 ? "" : "s"}, ${res.buckets} bucket${res.buckets === 1 ? "" : "s"}.`));
            refresh();
          },
          (e) => replace(review, h("p", { class: "error", role: "alert" }, vt((e as Error).message))),
        );
      });
      replace(
        review,
        h("h4", null, choice.mode === "drill" ? "Recovery drill" : "Enrol with the recovery key"),
        r.lines.length ? h("ul", { class: "open-lines" }, r.lines.map((l) => h("li", null, vt(l)))) : null,
        h("p", { class: "muted" }, "Sealed packet SHA-256: ", h("span", { class: "mono" }, r.packet_sha256)),
        h("details", { class: "signed" }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(r.canonical))),
        h("div", { class: "actions" }, sign),
      );
    } catch (e) {
      err.textContent = vt((e as Error).message);
    } finally {
      go.disabled = false;
    }
  });
  return h(
    "article",
    { class: "card recovery" },
    h("p", { class: "warn" }, RECOVERY_WARNING),
    h("label", null, "Action ", mode),
    h("div", { class: "recovery-enrol" }, h("label", null, "Passkey ", target), h("p", { class: "muted" }, "Scopes (one or two per tap):"), boxes.map((b) => b.label)),
    h("label", null, "Recovery key ", identity),
    h("div", { class: "actions" }, go),
    err,
    review,
  );
}
