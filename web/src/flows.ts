// DOM-free flows: sign-in, registration, and the signed-action flow (challenge -> verify ->
// show -> passkey -> apply). The UI calls these; tests drive them against the mock server.
//
// Each passkey prompt is its own step so the UI can call it straight from a tap: Safari only
// allows navigator.credentials.* inside a user gesture, and an await on fetch in between can
// use that gesture up.

import { ApiError, type Api, type ObjectKind } from "./api";
import { challengeCommitsTo, describe, mismatches, parseCanonical, type Canonical, type Description, type Expectation } from "./canonical";
import type { BeginResponse, PendingItem, StandingApproval, GrantSummary } from "./types";
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

export async function completeRegistration(api: Api, auth: Authenticator, p: PreparedRegistration): Promise<void> {
  const cred = await auth.create(p.options);
  await api.registerFinish(p.challengeId, encodeAttestation(cred));
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
  if (item.kind === "enrollment") {
    return {
      object: "enrollment",
      id: item.id,
      facts: {
        requesting_host: item.requesting_host,
        kind: "enrollment",
        key_fingerprint: item.enrollment?.csr_fingerprint,
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
      target: item.ssh?.target_host,
      login_user: item.ssh?.login_user,
      key_fingerprint: item.ssh?.key_fingerprint,
    },
  };
}

export function targetForStanding(s: StandingApproval): ActionTarget {
  if (s.kind === "cloudflare") {
    return {
      object: "standing",
      id: s.id,
      facts: { requesting_host: s.requesting_host, kind: "cloudflare", ...cfFacts(s.scope, s.scope_params, s.mode) },
      revokeTTL: s.max_ttl_seconds,
    };
  }
  return {
    object: "standing",
    id: s.id,
    facts: { requesting_host: s.requesting_host, kind: s.kind, target: s.target_host, login_user: s.login_user },
  };
}

export function targetForGrant(g: GrantSummary): ActionTarget {
  if (g.kind === "cloudflare") {
    return {
      object: "grant",
      id: g.id,
      facts: { requesting_host: g.requesting_host, kind: "cloudflare", ...cfFacts(g.scope, g.scope_params, g.mode) },
      revokeTTL: 0,
    };
  }
  return {
    object: "grant",
    id: g.id,
    facts: { requesting_host: g.requesting_host, kind: g.kind, target: g.target_host, login_user: g.login_user },
  };
}

export const PASSKEY_TARGET: ActionTarget = { object: "passkey", id: "new", facts: {} };

export interface ActionChoice {
  action: "approve" | "deny" | "revoke" | "add";
  ttl_seconds?: number;
  standing_hours?: number;
}

export interface PreparedAction {
  target: ActionTarget;
  choice: ActionChoice;
  challengeId: string;
  canonicalText: string;
  canonical: Canonical;
  description: Description;
  options: PublicKeyCredentialRequestOptions;
  /** When the server stops accepting this challenge (2 min per API.md, or the WebAuthn timeout). */
  validUntil: number;
}

export const CHALLENGE_LIFETIME_MS = 120_000;

/** Ask the server for a challenge and verify it commits to exactly the chosen action. */
export async function prepareAction(api: Api, target: ActionTarget, choice: ActionChoice, now = Date.now()): Promise<PreparedAction> {
  const body: { action: ActionChoice["action"]; ttl_seconds?: number; standing_hours?: number } = { action: choice.action };
  if (choice.action === "approve") {
    if (choice.ttl_seconds !== undefined) body.ttl_seconds = choice.ttl_seconds;
    if (choice.standing_hours) body.standing_hours = choice.standing_hours;
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
  });
  if (problems.length > 0) {
    throw new FlowError(`Not signing: the server's action differs from what you chose (${problems.join("; ")}).`);
  }

  const pk = unwrapPublicKey(r.public_key);
  const challenge = pk["challenge"];
  if (typeof challenge !== "string") throw new FlowError("Not signing: the server sent no WebAuthn challenge.");
  let commits = false;
  try {
    commits = await challengeCommitsTo(r.canonical, challenge);
  } catch (e) {
    throw new FlowError(`Not signing: ${(e as Error).message}.`);
  }
  if (!commits) throw new FlowError("Not signing: the passkey challenge does not match the action shown.");

  const options = decodeRequestOptions(r.public_key);
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
    validUntil: now + timeout,
  };
}

/** Passkey prompt + apply. Call straight from the owner's tap on "Confirm with passkey". */
export async function completeAction(api: Api, auth: Authenticator, p: PreparedAction): Promise<unknown> {
  if (p.target.object === "passkey") throw new FlowError("Use authorizeAddPasskey for passkey actions.");
  const cred = await auth.get(p.options);
  return api.apply(p.target.object, p.target.id, p.challengeId, encodeAssertion(cred));
}

/** Adding a passkey: sign the "passkey:add" action, which unlocks register/begin. */
export async function authorizeAddPasskey(api: Api, auth: Authenticator, p: PreparedAction): Promise<PreparedRegistration> {
  if (p.target.object !== "passkey") throw new FlowError("not a passkey action");
  const cred = await auth.get(p.options);
  return toRegistration(await api.registerBegin({ challenge_id: p.challengeId, assertion: encodeAssertion(cred) }));
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
