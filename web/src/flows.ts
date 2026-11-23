// DOM-free flows: sign-in, registration, and the signed-action flow (challenge -> verify ->
// show -> passkey -> apply). The UI calls these; tests drive them against the mock server.
//
// Each passkey prompt is its own step so the UI can call it straight from a tap: Safari only
// allows navigator.credentials.* inside a user gesture, and an await on fetch in between can
// use that gesture up.

import { ApiError, type Api, type ObjectKind } from "./api";
import { challengeCommitsTo, describe, mismatches, parseCanonical, type Canonical, type Description, type Expectation } from "./canonical";
import type { BastionDecision, BeginResponse, GrantSummary, PasskeyInfo, PendingItem, StandingApproval } from "./types";
import { prepareTap, type PreparedOpen, type Tap } from "./buckets";
import {
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAssertion,
  encodeAttestation,
  unwrapPublicKey,
  type Authenticator,
} from "./webauthn";

export class FlowError extends Error {
  override name = "FlowError";
}

// ---- sign-in ----

export interface PreparedLogin {
  challengeId?: string;
  options: PublicKeyCredentialRequestOptions;
  fetchedAt: number;
}

function beginOptions(r: BeginResponse): unknown {
  // Proposed shape {challenge_id, public_key}; also accept a bare go-webauthn CredentialAssertion.
  return r.public_key !== undefined ? r.public_key : r;
}

export async function prepareLogin(api: Api, now = Date.now()): Promise<PreparedLogin> {
  const r = await api.loginBegin();
  return { challengeId: r.challenge_id, options: decodeRequestOptions(beginOptions(r)), fetchedAt: now };
}

/** Login options are fetched ahead of the tap; treat them as stale after this long. */
export const LOGIN_OPTIONS_MAX_AGE_MS = 60_000;

export async function completeLogin(api: Api, auth: Authenticator, p: PreparedLogin): Promise<void> {
  const cred = await auth.get(p.options);
  await api.loginFinish(p.challengeId, encodeAssertion(cred));
}

// ---- registration ----

export interface PreparedRegistration {
  challengeId?: string;
  options: PublicKeyCredentialCreationOptions;
}

function toRegistration(r: BeginResponse): PreparedRegistration {
  return { challengeId: r.challenge_id, options: decodeCreationOptions(beginOptions(r)) };
}

/** First passkey: one-time enroll code from `aqmasd passkey-enroll-code`. */
export async function prepareRegistrationWithCode(api: Api, enrollCode: string): Promise<PreparedRegistration> {
  const code = enrollCode.trim();
  if (!code) throw new FlowError("Enter the enroll code first.");
  return toRegistration(await api.registerBegin({ enroll_code: code }));
}

/** Create the passkey and register it. `nickname`: only for the first passkey (enroll code);
 * later passkeys get the nickname signed with the add action, so leave it "". "" lets the
 * server name it after the authenticator. Resolves to the server's RegisterResult. */
export async function completeRegistration(api: Api, auth: Authenticator, p: PreparedRegistration, nickname = ""): Promise<unknown> {
  const cred = await auth.create(p.options);
  return api.registerFinish(p.challengeId, encodeAttestation(cred), nickname.trim() || undefined);
}

/** A nickname as the server stores it (internal/server/nickname.Normalize): runs of any
 * Unicode space become one plain space, trimmed. */
export function normalizeNickname(name: string): string {
  return name.replace(/\p{Zs}+/gu, " ").trim();
}

/** Client-side check of a nickname before asking for a challenge (the server checks again):
 * returns an error message or null. Mirrors api.MaxNicknameBytes and the server's character rules. */
export function nicknameProblem(name: string): string | null {
  const n = normalizeNickname(name);
  if (!n) return "Enter a name.";
  if (new TextEncoder().encode(n).length > 64) return "That name is too long (64 bytes at most).";
  if (/[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}\p{Mn}\p{Me}]/u.test(n)) return "That name contains invisible, control or combining characters.";
  return null;
}

// ---- signed actions ----

/** What the owner is acting on: an object plus the facts the card showed. */
export interface ActionTarget {
  object: ObjectKind;
  id: string;
  facts: Omit<Expectation, "action" | "object" | "id" | "ttl_seconds" | "standing_hours">;
  /** For a revoke: the ttl_seconds its canonical must carry (Cloudflare standing: the rule's
   * max TTL; Cloudflare grant: 0). Unset = not checked (M1 SSH). */
  revokeTTL?: number;
}

/** Cloudflare facts from a card. Missing fields become "" so they are still compared: the
 * page never signs a Cloudflare action whose scope it did not show. */
function cfFacts(scope: string | undefined, scopeParams: string | undefined, mode: string | undefined) {
  return { scope: scope ?? "", scope_params: scopeParams ?? "", mode: mode ?? "" };
}

export function targetForPending(item: PendingItem): ActionTarget {
  if (item.kind === "setup") {
    // Not a canonical request: a queued task is approved through the setup task flow
    // (prepareSetupTask + completeSetupTask with the request id) or dismissed.
    throw new FlowError("A queued maintenance task is approved from its own card.");
  }
  if (item.kind === "bastion") {
    const b = item.bastion;
    // Missing facts become "" / false so they are still compared: the page never signs a
    // bastion session whose level or authority it did not show.
    return {
      object: "request",
      id: item.id,
      facts: {
        requesting_host: item.requesting_host,
        kind: "bastion",
        level: b?.level ?? "",
        host_id: b?.host_id ?? "",
        address: item.requesting_address ?? "",
        target: b?.target ?? "",
        target_address: b?.target_address ?? "",
        target_port: b?.target_port ?? 0,
        login_user: b?.login_user ?? "",
        principal: b?.principal ?? "",
        key_fingerprint: b?.key_fingerprint ?? "",
        ssh_ca: b?.ssh_ca ?? "",
        host_key: b?.host_key ?? "",
        cert_profile: b?.cert_profile ?? "",
        sealed: b?.sealed ?? false,
        open_buckets: b?.open_buckets ?? [],
        alert_channel: b?.alert_channel ?? false,
      },
    };
  }
  if (item.kind === "enrollment") {
    return {
      object: "enrollment",
      id: item.id,
      facts: {
        requesting_host: item.requesting_host,
        kind: "enrollment",
        class:item.enrollment?.class ?? '', address:item.requesting_address ?? '',
        replaces_id:item.enrollment?.replaces_id ?? '',
        key_fingerprint: item.enrollment?.csr_fingerprint ?? '',
        replaces: item.enrollment?.replaces_existing ?? false,
      },
    };
  }
  if (item.kind === "cloudflare") {
    const cf = item.cloudflare;
    return {
      object: "request",
      id: item.id,
      facts: {
        requesting_host: item.requesting_host,
        kind: "cloudflare",
        scoped_facts:item.scoped_facts,
        ...cfFacts(cf?.scope, cf?.scope_params, cf?.mode),
        ip_condition: cf?.ip_condition ?? "",
      },
    };
  }
  return {
    object: "request",
    id: item.id,
    facts: {
      requesting_host: item.requesting_host,
      kind: item.kind,
      scoped_facts:item.scoped_facts,
      target: item.ssh?.target_host ?? '', target_address:item.ssh?.target_address ?? '', target_port:item.ssh?.target_port ?? 0,
      principal:item.ssh?.principal ?? '',address:item.requesting_address ?? '',
      login_user: item.ssh?.login_user ?? '',
      key_fingerprint: item.ssh?.key_fingerprint ?? '',
    },
  };
}

export function targetForStanding(s: StandingApproval): ActionTarget {
  if (s.kind === "cloudflare") {
    return {
      object: "standing",
      id: s.id,
      facts: { standing_indefinite:s.indefinite,scoped_facts:s.scoped_facts, requesting_host: s.requesting_host, kind: "cloudflare", ...cfFacts(s.scope, s.scope_params, s.mode) },
      revokeTTL: s.max_ttl_seconds,
    };
  }
  return {
    object: "standing",
    id: s.id,
    facts: { scoped_facts:s.scoped_facts, requesting_host: s.requesting_host, kind: s.kind, target: s.target_host, login_user: s.login_user },revokeTTL:s.scoped_facts?s.max_ttl_seconds:undefined,
  };
}

export function targetForGrant(g: GrantSummary): ActionTarget {
  if (g.kind === "cloudflare") {
    return {
      object: "grant",
      id: g.id,
      facts: { indefinite:g.indefinite,scoped_facts:g.scoped_facts, requesting_host: g.requesting_host, kind: "cloudflare", ...cfFacts(g.scope, g.scope_params, g.mode) },
      revokeTTL: 0,
    };
  }
  return {
    object: "grant",
    id: g.id,
    facts: { scoped_facts:g.scoped_facts, requesting_host: g.requesting_host, kind: g.kind, target: g.target_host, login_user: g.login_user },revokeTTL:0,
  };
}

export const PASSKEY_TARGET: ActionTarget = { object: "passkey", id: "new", facts: { nickname: "" } };

/** Rename or remove an existing passkey: the canonical must name it by its current nickname. */
export function targetForPasskey(p: PasskeyInfo): ActionTarget {
  return { object: "passkey", id: p.id, facts: { nickname: p.nickname } };
}

export interface ActionChoice {
  standing_seconds?:number;
  action: import('./types').Action;indefinite?:boolean;standing_indefinite?:boolean;
  ttl_seconds?: number;
  standing_hours?: number;
  /** rename: the new nickname; add: an optional nickname for the new passkey. Sent
   * normalised (normalizeNickname); the canonical must carry exactly it as new_nickname. */
  nickname?: string;
  /** Root bastion approval of a sealed store: close every open bucket before the certificate
   * is issued. Required there (the owner's explicit choice is signed) and refused elsewhere. */
  closeBuckets?: boolean;
}

/** True for the one decision that carries the close choice. */
function needsCloseChoice(target: ActionTarget, choice: ActionChoice): boolean {
  return target.object === "request" && target.facts.kind === "bastion" && target.facts.level === "root" && target.facts.sealed === true && choice.action === "approve";
}

export interface PreparedAction {
  target: ActionTarget;
  choice: ActionChoice;
  challengeId: string;
  canonicalText: string;
  canonical: Canonical;
  description: Description;
  options: PublicKeyCredentialRequestOptions;
  /** Seal format 2: the buckets this tap opens and for how long (shown on the card). */
  open?: PreparedOpen;
  /** Signs, and seals the PRF-derived keys when the action opens buckets. */
  tap?: Tap;
  /** When the server stops accepting this challenge (2 min per API.md, or the WebAuthn timeout). */
  validUntil: number;
}

export const CHALLENGE_LIFETIME_MS = 120_000;

/** Ask the server for a challenge and verify it commits to exactly the chosen action. */
export async function prepareAction(api: Api, target: ActionTarget, choice: ActionChoice, now = Date.now()): Promise<PreparedAction> {
  const body: import('./types').ChallengeRequest = { action: choice.action };
  if(target.facts.plan && target.object!=='migration')body.plan=target.facts.plan;
  if(choice.indefinite)body.indefinite=true;if(choice.standing_indefinite)body.standing_indefinite=true;
  if(choice.standing_seconds)body.standing_seconds=choice.standing_seconds;
  if (choice.action === "approve") {
    if (choice.ttl_seconds !== undefined) body.ttl_seconds = choice.ttl_seconds;
    if (choice.standing_hours) body.standing_hours = choice.standing_hours;
  }
  const bastion = target.object === "request" && target.facts.kind === "bastion";
  if (needsCloseChoice(target, choice)) {
    if (typeof choice.closeBuckets !== "boolean") throw new FlowError("Choose whether to close all open buckets first.");
    body.close_buckets = choice.closeBuckets;
  } else if (choice.closeBuckets !== undefined) {
    throw new FlowError("Only a root session on the bastion (sealed store) takes the close-buckets choice.");
  }
  if (bastion) {
    if (target.facts.level !== "inspect" && target.facts.level !== "root") throw new FlowError("Not signing: this page does not know this bastion level.");
    if (choice.standing_hours || choice.standing_seconds || choice.indefinite || choice.standing_indefinite) throw new FlowError("A bastion session takes no standing or indefinite choice.");
    if (choice.action === "approve" && !(Number(choice.ttl_seconds) > 0)) throw new FlowError("Choose how long the session may last.");
  }
  let newNickname: string | undefined;
  if (choice.action === "rename" || choice.action === "add") {
    if (target.object !== "passkey") throw new FlowError("Only passkeys have nicknames.");
    newNickname = normalizeNickname(choice.nickname ?? "");
    if (choice.action === "rename" || newNickname !== "") {
      const problem = nicknameProblem(newNickname);
      if (problem) throw new FlowError(problem);
      body.nickname = newNickname;
    }
  }
  const r = await api.challenge(target.object, target.id, body);
  if (!r || typeof r.challenge_id !== "string" || !r.challenge_id) throw new FlowError("The server sent no challenge id.");
  if (typeof r.canonical !== "string") throw new FlowError("The server sent no action text to confirm.");

  let canonical: Canonical;
  try {
    canonical = parseCanonical(r.canonical);
  } catch (e) {
    throw new FlowError(`Not signing: ${(e as Error).message}.`);
  }
  const problems = mismatches(canonical, {
    action: choice.action,
    object: target.object,
    id: target.id,
    ttl_seconds: choice.action === "approve" ? (target.object === "request" ? choice.ttl_seconds : undefined) : target.revokeTTL,
    standing_hours: choice.action === "approve" ? (choice.standing_hours ?? 0) : 0,
    ...target.facts,
    standing_seconds:choice.standing_seconds,
    indefinite:choice.indefinite??target.facts.indefinite,standing_indefinite:choice.standing_indefinite??target.facts.standing_indefinite,
    new_nickname: newNickname,
    close_buckets: choice.closeBuckets ?? false,
  });
  // Belt and braces: a bastion card and a bastion text always go together.
  if ((canonical.kind === "bastion") !== bastion && target.object === "request") problems.push("kind: the server's action is not the kind of request the card showed");
  if (problems.length > 0) {
    throw new FlowError(`Not signing: the server's action differs from what you chose (${problems.join("; ")}).`);
  }

  const pk = unwrapPublicKey(r.public_key);
  const challenge = pk["challenge"];
  if (typeof challenge !== "string") throw new FlowError("Not signing: the server sent no WebAuthn challenge.");
  let tap: Tap | undefined;
  if (r.open !== undefined && r.open !== null) {
    // Format 2: the challenge binds the action AND the buckets the tap opens (docs/BUCKETS.md §4.2).
    if (choice.action !== "approve" || (target.object !== "request" && target.object !== "enrollment")) throw new FlowError("Not signing: only an approval can open a bucket.");
    const rp = typeof location !== "undefined" && location.hostname ? location.hostname : String(pk["rpId"] ?? "");
    try {
      tap = await prepareTap(r, rp);
    } catch (e) {
      throw new FlowError(`Not signing: ${(e as Error).message}.`);
    }
  } else {
    let commits = false;
    try {
      commits = await challengeCommitsTo(r.canonical, challenge);
    } catch (e) {
      throw new FlowError(`Not signing: ${(e as Error).message}.`);
    }
    if (!commits) throw new FlowError("Not signing: the passkey challenge does not match the action shown.");
    if (pk["extensions"] !== undefined && pk["extensions"] !== null) throw new FlowError("Not signing: the request carries unexpected extensions.");
  }

  const options = tap?.options ?? decodeRequestOptions(r.public_key);
  const timeout = typeof options.timeout === "number" && options.timeout > 0 ? Math.min(options.timeout, CHALLENGE_LIFETIME_MS) : CHALLENGE_LIFETIME_MS;
  options.timeout = timeout;
  return {
    target,
    choice,
    challengeId: r.challenge_id,
    canonicalText: r.canonical,
    canonical,
    description: describe(canonical),
    options,
    ...(tap ? { tap, open: tap.open } : {}),
    validUntil: now + timeout,
  };
}

/** Passkey prompt + apply. Call straight from the owner's tap on "Confirm with passkey". */
export async function completeAction(api: Api, auth: Authenticator, p: PreparedAction): Promise<unknown> {
  if (p.target.object === "passkey" && p.choice.action === "add") throw new FlowError("Use authorizeAddPasskey to add a passkey.");
  if (p.tap) {
    // tap.sign starts the passkey prompt before its first await (Safari's user gesture). The
    // KEK packet is sent only when this passkey returned PRF results.
    const signed = await p.tap.sign(auth);
    return api.apply(p.target.object, p.target.id, p.challengeId, signed.assertion, undefined, signed.open);
  }
  const cred = await auth.get(p.options);
  // Passkey rename/remove: the endpoint is named after the SIGNED action (canonical), so a
  // page bug can't send a rename assertion to the remove endpoint (the server refuses it anyway).
  const action = p.target.object === "passkey" ? p.canonical.action : undefined;
  return api.apply(p.target.object, p.target.id, p.challengeId, encodeAssertion(cred), action);
}

/** Adding a passkey: sign the "passkey:add" action, which opens register/begin. */
export async function authorizeAddPasskey(api: Api, auth: Authenticator, p: PreparedAction): Promise<PreparedRegistration> {
  if (p.target.object !== "passkey" || p.canonical.action !== "add") throw new FlowError("not a passkey add action");
  const cred = await auth.get(p.options);
  return toRegistration(await api.registerBegin({ challenge_id: p.challengeId, assertion: encodeAssertion(cred) }));
}

/** Approve or deny a pending bastion request in one go (tools and tests; the page shows the
 * canonical text in between). `closeBuckets` is required for a root approval of a sealed
 * store and must be left out otherwise. Resolves to the server's BastionDecision. */
export async function decideBastion(
  api: Api,
  auth: Authenticator,
  item: PendingItem,
  choice: { action: "approve" | "deny"; ttl_seconds?: number; closeBuckets?: boolean },
): Promise<BastionDecision> {
  if (item.kind !== "bastion") throw new FlowError("not a bastion request");
  const c: ActionChoice = { action: choice.action };
  if (choice.action === "approve") c.ttl_seconds = choice.ttl_seconds ?? item.ttl_requested;
  if (choice.closeBuckets !== undefined) c.closeBuckets = choice.closeBuckets;
  const p = await prepareAction(api, targetForPending(item), c);
  return (await completeAction(api, auth, p)) as BastionDecision;
}

// ---- errors in words ----

/** True when an error proves the action was NOT applied: refused before signing, passkey
 * prompt cancelled, or a 4xx from aqmas. 5xx and network errors may come after the server
 * applied it (a proxy timing out, a lost response), so they are "unknown". */
export function nothingChanged(e: unknown): boolean {
  if (e instanceof FlowError) return true;
  if (e instanceof ApiError) return e.status >= 400 && e.status < 500;
  if (e instanceof Error) return ["NotAllowedError", "AbortError", "InvalidStateError", "SecurityError", "WebAuthnFormatError", "Base64UrlError"].includes(e.name);
  return false;
}


export function explainError(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case "unauthenticated":
        return "You're signed out. Sign in with your passkey again.";
      case "expired":
        return `That has expired. ${e.message}`.trim();
      case "conflict":
        return `Someone or something already acted on this. ${e.message}`.trim();
      case "not_found":
        return "It's gone: it was decided, revoked or expired elsewhere.";
      case "forbidden":
        return `Refused by aqmas: ${e.message}`;
      default:
        return e.message || `Error ${e.status}`;
    }
  }
  if (e instanceof Error) {
    if (e.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out. Nothing was signed.";
    if (e.name === "InvalidStateError") return "This passkey is already registered here.";
    if (e.name === "SecurityError") return "The browser refused the passkey request for this address.";
    if (e.name === "AbortError") return "The passkey prompt was interrupted. Nothing was signed.";
    return e.message;
  }
  return String(e);
}
