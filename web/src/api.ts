// Fetch wrapper for the web UI API (docs/API.md section 2).
// Every POST carries X-Aqmas: 1 and Content-Type: application/json (the server's CSRF check);
// every call uses credentials: "same-origin" so only the HttpOnly session cookie travels.

import type {
  BeginResponse,
  ChallengeRequest,
  ChallengeResponse,
  PendingItem,
  UIState,
} from "./types";
import type { HostInfo } from './admin';
import type { HelpConfig } from './help';

export class ApiError extends Error {
  override name = "ApiError";
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Objects with a challenge endpoint, and the verb that applies the signed action. */
export const OBJECT_PATHS = {
  organisation:{path:'catalogue/organisation',apply:'decide'},service:{path:'catalogue/service',apply:'decide'},credential_set:{path:'catalogue/credential_set',apply:'decide'},org_host:{path:'catalogue/org_host',apply:'decide'},org_policy:{path:'catalogue/org_policy',apply:'decide'},
  migration:{path:'migrations',apply:'activate'},
  host: {path:'hosts', apply:'revoke'},
  update: {path:'updates', apply:'decide'},
  request: { path: "requests", apply: "decide" },
  enrollment: { path: "enrollments", apply: "decide" },
  standing: { path: "standing", apply: "revoke" },
  grant: { path: "grants", apply: "revoke" },
} as const;
export type ObjectKind = keyof typeof OBJECT_PATHS | "passkey";

export interface ApiOptions {
  /** Base URL; "" (same origin) in the browser. */
  base?: string;
  fetch?: typeof fetch;
}

export interface Api {
  envState?():Promise<import('./envsets').EnvState>;
  /** Credential sets page (docs/API.md "Vault"). */
  vaultState?(): Promise<import('./vault').VaultState>;
  vaultPost?<T>(path: 'attempt' | 'challenge' | 'finish', body: unknown): Promise<T>;
  envPost?<T>(path:'ticket'|'challenge'|'finish',body:unknown):Promise<T>;
  sealStatus?(): Promise<import('./sealPanel').SealView>;
  sealPost?<T>(path: 'unlock/challenge'|'unlock/finish'|'control/challenge'|'control/finish'|`passkeys/${'challenge'|'authorize'|'create'|'evaluate'|'finish'}`|`batch/${'challenge'|'finish'}`|'drill'|`windows/${'policy/challenge'|'policy/finish'|'open/challenge'|'open/finish'|'prepare'|'confirm'|'presence'|'close'}`, body: unknown): Promise<T>;
  /** Admin → Setup (docs/SETUP.md); `path` is relative to /api/ui/setup. */
  setupGet?<T>(path: string): Promise<T>;
  setupPost?<T>(path: string, body: unknown): Promise<T>;
  catalogue?():Promise<import('./catalogue').Catalogue|null>;
  migration?():Promise<{id:string;plan:string;recovery_sha256:string}|null>;
  hosts(): Promise<HostInfo[]>;
  updates(): Promise<import('./admin').UpdateView>;
  help(): Promise<HelpConfig>;
  state(): Promise<UIState>;
  request(id: string): Promise<PendingItem>;
  challenge(object: ObjectKind, id: string, body: ChallengeRequest): Promise<ChallengeResponse>;
  /** Apply a signed action. Passkey rename/remove need `action` (it picks the endpoint; the
   * server also checks it against what was signed). */
  apply(object: ObjectKind, id: string, challengeId: string, assertion: unknown, action?: string): Promise<unknown>;
  loginBegin(): Promise<BeginResponse>;
  loginFinish(challengeId: string | undefined, assertion: unknown): Promise<unknown>;
  registerBegin(body: { enroll_code?: string; challenge_id?: string; assertion?: unknown }): Promise<BeginResponse>;
  /** `name`: the nickname (omitted = the server names it after the authenticator). */
  registerFinish(challengeId: string | undefined, credential: unknown, name?: string): Promise<unknown>;
}

const seg = encodeURIComponent;

export function createApi(opts: ApiOptions = {}): Api {
  const base = opts.base ?? "";
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);

  async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    const init: RequestInit = { method, headers, credentials: "same-origin", cache: "no-store", redirect: "manual" };
    if (method === "POST") {
      headers["X-Aqmas"] = "1";
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body ?? {});
    }
    let res: Response;
    try {
      res = await doFetch(base + path, init);
    } catch (e) {
      throw new ApiError(0, "network", `Could not reach aqmas (${(e as Error).message}).`);
    }
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      // Cloudflare Access redirects to its login page when its own session ends.
      throw new ApiError(res.status, "access", "Your Cloudflare Access session has ended. Reload the page to sign in again.");
    }
    const text = await res.text();
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
    }
    if (!res.ok) {
      const b = (json ?? {}) as { error?: unknown; message?: unknown };
      const code = typeof b.error === "string" ? b.error : res.status === 401 ? "unauthenticated" : "http_" + res.status;
      const msg = typeof b.message === "string" && b.message ? b.message : `${res.status} ${res.statusText}`.trim();
      throw new ApiError(res.status, code, msg);
    }
    if (json === undefined && text) throw new ApiError(res.status, "bad_response", "The server sent a response that isn't JSON.");
    return json as T;
  }

  function objectPath(object: ObjectKind): { path: string; apply: string } {
    if (object === "passkey") return { path: "passkeys", apply: "" };
    return OBJECT_PATHS[object];
  }

  return {
    vaultState: () => call('GET', '/api/ui/seal/vault/state'),
    vaultPost: (path, body) => call('POST', `/api/ui/seal/vault/${path}`, body),
    envState:()=>call('GET','/api/ui/seal/env/state'),envPost:(path,body)=>call('POST',`/api/ui/seal/env/${path}`,body),
    sealStatus: () => call('GET','/api/ui/seal/status'),
    sealPost: (path,body) => call('POST',`/api/ui/seal/${path}`,body),
    setupGet: (path) => call('GET',`/api/ui/setup${path}`),
    setupPost: (path,body) => call('POST',`/api/ui/setup${path}`,body),
    hosts: () => call('GET','/api/ui/hosts'),
    updates: () => call('GET','/api/ui/updates'),
    migration: () => call('GET','/api/ui/migration'),
    catalogue: () => call('GET','/api/ui/catalogue'),
    help: () => call('GET','/api/ui/help'),
    state: () => call<UIState>("GET", "/api/ui/state"),
    request: (id) => call<PendingItem>("GET", `/api/ui/requests/${seg(id)}`),
    challenge: (object, id, body) => {
      if (object === "passkey") {
        if (id === "new") return call<ChallengeResponse>("POST", "/api/ui/passkeys/challenge", body);
        return call<ChallengeResponse>("POST", `/api/ui/passkeys/${seg(id)}/challenge`, body);
      }
      return call<ChallengeResponse>("POST", `/api/ui/${objectPath(object).path}/${seg(id)}/challenge`, body);
    },
    apply: (object, id, challengeId, assertion, action) => {
      if (object === "passkey") {
        if (action !== "rename" && action !== "remove") throw new Error("adding a passkey is applied by registerBegin");
        return call<unknown>("POST", `/api/ui/passkeys/${seg(id)}/${action}`, { challenge_id: challengeId, assertion });
      }
      const p = objectPath(object);
      return call<unknown>("POST", `/api/ui/${p.path}/${seg(id)}/${p.apply}`, { challenge_id: challengeId, assertion });
    },
    loginBegin: () => call<BeginResponse>("POST", "/api/ui/login/begin", {}),
    loginFinish: (challengeId, assertion) =>
      call<unknown>("POST", "/api/ui/login/finish", challengeId ? { challenge_id: challengeId, assertion } : { assertion }),
    registerBegin: (body) => call<BeginResponse>("POST", "/api/ui/passkeys/register/begin", body),
    registerFinish: (challengeId, credential, name) => {
      const body: Record<string, unknown> = challengeId ? { challenge_id: challengeId, credential } : { credential };
      if (name) body["name"] = name;
      return call<unknown>("POST", "/api/ui/passkeys/register/finish", body);
    },
  };
}
