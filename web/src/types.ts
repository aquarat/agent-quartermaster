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
  target_host: string;
  login_user: string;
  key_fingerprint: string;
}

/** Enrollment detail for kind "enrollment" (api.PendingEnrollment). */
export interface PendingEnrollment {
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

export interface UIState {
  owner: UIOwner;
  pending: PendingItem[] | null;
  standing: StandingApproval[] | null;
  recent: AuditEntry[] | null;
  grants?: GrantSummary[] | null; // active grants (api.UIState.grants)
}

export type Action = "approve" | "deny" | "revoke" | "add";

export interface ChallengeRequest {
  action: Action;
  ttl_seconds?: number;
  standing_hours?: number;
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
