// Wire types for the web UI API (docs/API.md section 2). Mirrors internal/api/types.go,
// which is the source of truth. A few fields stay optional here so the UI degrades
// gracefully against an older server.

export interface Requester {
  tool: string; // self-reported, untrusted
  session_id?: string;
  cwd?: string;
  pid?: number;
  user: string;
}

export interface PendingSSH {
  principal: string;
  target_address: string;
  target_port: number;
  requested_target?: string;
  target_host: string;
  login_user: string;
  key_fingerprint: string;
}

/** Enrollment detail for kind "enrollment" (api.PendingEnrollment). */
export interface PendingEnrollment {
  replaces_id: string;
  max_ssh_seconds: number;
  max_standing_hours: number;
  class: "agent" | "owner-device";
  csr_fingerprint?: string;
  ssh_host_key_fingerprints?: string[];
  replaces_existing?: boolean;
}

/** Cloudflare detail for kind "cloudflare" (api.PendingCloudflare, API.md 5.7). */
export interface PendingCloudflare {
  scope: string;
  params: Record<string, string> | null;
  scope_params: string; // exactly as it will be signed
  mode: string; // "proxy" | "token"
  ip_condition: string; // "" in proxy mode; sorted CIDRs joined by ","
  title: string; // the server catalogue's words (supplement only)
  description: string;
  risk: string; // "low" | "medium" | "high" | "admin"
  standing_allowed: boolean;
  permissions?: string[]; // token mode: the child token's policy in plain words
  notes?: string[];
}

export interface PendingItem {
  scoped_facts?: Record<string,string|number>;
  max_standing_hours?: number;
  id: string;
  kind: string; // "ssh" | "enrollment" | "cloudflare"
  created_at: string;
  expires_at: string;
  requesting_host: string;
  requesting_address: string;
  requester: Requester;
  reason: string; // untrusted
  ssh?: PendingSSH;
  enrollment?: PendingEnrollment;
  cloudflare?: PendingCloudflare;
  ttl_requested: number;
  ttl_max: number;
  risk: string; // "normal" | "high" (Cloudflare: low/medium -> normal, high/admin -> high)
  similar_recent: number;
  status?: string; // only on GET /api/ui/requests/{id} and /api/ui/enrollments/{id}
}

export interface StandingApproval {
  indefinite?:boolean;
  scoped_facts?: Record<string,string|number>;
  id: string;
  requesting_host: string;
  kind: string;
  target_host: string;
  login_user: string;
  max_ttl_seconds: number;
  expires_at: string;
  uses: number;
  // kind "cloudflare" (target_host/login_user empty then)
  scope?: string;
  scope_params?: string;
  mode?: string;
}

export interface GrantSummary {
  indefinite?:boolean;
  scoped_facts?: Record<string,string|number>;
  id: string;
  kind: string;
  status: string;
  target_host?: string;
  login_user?: string;
  requesting_host?: string; // set in UIState.grants
  not_before: string;
  not_after: string;
  // kind "cloudflare"
  scope?: string;
  scope_params?: string;
  mode?: string;
}

export interface AuditEntry {
  at: string;
  actor: string;
  action: string;
  object: string;
  detail?: string;
}

export interface UIOwner {
  name: string;
  passkeys: number;
}

/** Icon keys the server sends in PasskeyInfo.icon (api.PasskeyIcon*). */
export type PasskeyIcon =
  | "apple"
  | "bitwarden"
  | "onepassword"
  | "google"
  | "chrome"
  | "windows"
  | "microsoft"
  | "samsung"
  | "yubikey"
  | "manager"
  | "unknown";

/** One registered owner passkey (api.PasskeyInfo). */
export interface PasskeyInfo {
  /** Hex of the first 16 bytes of SHA-256(credential ID); the canonical "passkey" id. */
  id: string;
  nickname: string;
  /** Friendly name from the AAGUID, or "Unknown authenticator". */
  authenticator: string;
  icon: PasskeyIcon | string;
  aaguid: string; // "" when the authenticator reported none
  transports: string[] | null;
  /** Synced (multi-device) passkey; false = device-bound (e.g. a hardware key). */
  backup_eligible: boolean;
  backup_state: boolean;
  sign_count: number;
  created_at: string;
  last_used_at?: string;
  /** The passkey this session signed in with. */
  current: boolean;
}

export interface UIState {
  catalogue_enabled?:boolean;
  migration?:{id:string;plan:string;recovery_sha256:string};
  owner: UIOwner;
  pending: PendingItem[] | null;
  standing: StandingApproval[] | null;
  recent: AuditEntry[] | null;
  grants?: GrantSummary[] | null; // active grants (api.UIState.grants)
  passkeys?: PasskeyInfo[] | null; // api.UIState.passkeys (absent on an older server)
}

export type Action = "approve" | "deny" | "revoke" | "add" | "rename" | "remove" | 'activate' | 'create' | 'replace' | 'admit';

export interface ChallengeRequest {
  standing_seconds?:number;
  plan?:string;indefinite?:boolean;standing_indefinite?:boolean;
  action: Action;
  ttl_seconds?: number;
  standing_hours?: number;
  /** Passkey rename: the new nickname. */
  nickname?: string;
}

/** Response of register/finish (api.RegisterResult). */
export interface RegisterResult {
  ok: boolean;
  passkey?: PasskeyInfo;
}

/** Response of /api/ui/passkeys/{id}/rename and /remove (api.PasskeyChange). */
export interface PasskeyChange {
  ok: boolean;
  id: string;
  action: "rename" | "remove";
  nickname: string;
  /** The removed passkey was this session's: signed out. */
  signed_out: boolean;
}

/** Response of every .../challenge endpoint. `public_key` is go-webauthn's
 * CredentialAssertion (`{publicKey: {...}}`) or the bare request options. */
export interface ChallengeResponse {
  challenge_id: string;
  canonical: string;
  public_key: unknown;
}

/** Response of login/begin and register/begin (api.CeremonyBegin). */
export interface BeginResponse {
  challenge_id?: string;
  public_key?: unknown;
}

export interface ApiErrorBody {
  error: string;
  message: string;
}
