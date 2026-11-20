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

export interface PendingItem {
  id: string;
  kind: string; // "ssh" | "enrollment"
  created_at: string;
  expires_at: string;
  requesting_host: string;
  requesting_address: string;
  requester: Requester;
  reason: string; // untrusted
  ssh?: PendingSSH;
  enrollment?: PendingEnrollment;
  ttl_requested: number;
  ttl_max: number;
  risk: string; // "normal" | "high"
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
