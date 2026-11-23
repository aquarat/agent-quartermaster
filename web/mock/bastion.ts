// Mock of access to the bastion itself (docs/BASTION-ACCESS.md): pending inspect and root
// requests, a maintenance task queued by an agent, GET /api/ui/bastion, the canonical text of
// a bastion decision and the specs and parameters of the bastion and routine Setup tasks.
// mock/server.ts and mock/setup.ts hook this in with a few lines each.

import { randomBytes } from "node:crypto";
import type { BastionHost, BastionSession, BastionView, GrantSummary, PendingItem } from "../src/types";

const now = () => Date.now();
const iso = (t = now()) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");
const ulidish = () => (Date.now().toString(36) + randomBytes(8).toString("hex")).toUpperCase().slice(0, 26);
const fp = (seed: string) => "SHA256:" + Buffer.from(seed.padEnd(32, "x").slice(0, 32)).toString("base64").replace(/=+$/, "");
const q = (s: string) => JSON.stringify(s);

/** The specs of maint.Specs with a group (internal/maint/spec.go). */
export const BASTION_SPECS = [
  { id: "bastion-access", group: "bastion", title: "Allow aqmas access to the bastion", summary: "Makes this machine's own sshd accept aqmas certificates for two accounts: a read-only inspect account that can only run fixed log and status commands, and your admin account (root, behind a red card, from hosts you allow). Your emergency keys are not touched and stay the way in when aqmas is down.", steps: ["Check the admin account and the SSH CA against what you signed", "Create the confined inspect account", "Install the CA, the two principals files and the forced-command block; validate and reload sshd", "Record this machine as a destination in the configuration", "Restart the broker and check it is healthy"], reversible: "Yes: “Remove aqmas access to the bastion”. If a check fails, the previous sshd files and configuration are restored.", warning: "Restarts the broker: every open bucket closes and every approval window ends." },
  { id: "bastion-access-remove", group: "bastion", title: "Remove aqmas access to the bastion", summary: "Stops this machine's sshd from accepting aqmas certificates and deletes the inspect account. Afterwards only your emergency key gets in.", steps: ["Remove this machine as a destination from the configuration and restart the broker", "Remove the CA, principals files and forced-command block; validate and reload sshd", "End the inspect account's sessions and delete the account"], reversible: "Yes: allow access again. A root session that is already open is an ordinary login of your admin account and is not ended.", warning: "Restarts the broker: every open bucket closes and every approval window ends." },
  { id: "bastion-allow", group: "bastion", title: "Set who may ask for root on the bastion", summary: "Replaces the list of enrolled hosts that may ask for a root session with the hosts listed here. The list is kept by root, not by the broker, and this machine's sshd accepts a root certificate only from the listed addresses.", steps: ["Write the root-owned list", "Rewrite the admin account's principals file with the listed addresses"], reversible: "Run it again with another list. An empty list means nobody can ask for root." },
  { id: "os-update", group: "routine", title: "Update system packages", summary: "Installs the distribution's pending package updates (dnf upgrade) and reports what changed. The kernel and the boot chain are left alone unless you allow them.", steps: ["Record the installed packages and the boot files", "Run dnf upgrade outside the runner's sandbox", "Compare before and after; fail if the kernel, boot chain or boot files changed without your permission", "Check sshd still confines the inspect account"], reversible: "No. Undo by hand on the machine (dnf history undo)." },
  { id: "reboot", group: "routine", title: "Reboot the bastion", summary: "Restarts the whole machine.", steps: ["Record the request", "Reboot"], reversible: "No.", warning: "The bastion comes back with nothing open: every bucket closed, every approval window ended, standing rules paused until the next approval. Approvals are unavailable for a minute or two." },
  { id: "restart-cloudflared", group: "routine", title: "Restart cloudflared", summary: "Restarts the tunnel connector that publishes this page.", steps: ["Restart the tunnel service", "Check it is running"], reversible: "Nothing to undo.", warning: "This page is unreachable for a few seconds." },
  { id: "restart-broker", group: "routine", title: "Restart aqmasd", summary: "Stops and starts the broker.", steps: ["Stop the broker and wait for it to exit", "Start it and check it is healthy"], reversible: "Nothing to undo.", warning: "The broker comes back with nothing open: every bucket closed, every approval window ended." },
  { id: "disk-usage", group: "routine", title: "Show disk and journal usage", summary: "Reports free space on the system and data file systems and the size of the journal. Changes nothing.", steps: ["Measure"], reversible: "Read-only." },
  { id: "journal-vacuum", group: "routine", title: "Rotate and trim the journal", summary: "Rotates the system journal and deletes entries older than the number of days you choose.", steps: ["Rotate the journal", "Delete entries older than the chosen age", "Report the space freed"], reversible: "No: deleted log entries are gone." },
];

const EMPTY = ["bastion-access-remove", "reboot", "restart-cloudflared", "restart-broker", "disk-usage"];

/** Strict parameters of a bastion or routine task as the broker canonicalises them, or
 * undefined for another task. `fail` throws a 400. */
export function bastionParams(task: string, raw: unknown, fail: (m: string) => never): { text: string; value: Record<string, unknown> } | undefined {
  if (!BASTION_SPECS.some((s) => s.id === task)) return undefined;
  const o = (raw ?? {}) as Record<string, unknown>;
  if (o === null || typeof o !== "object" || Array.isArray(o)) fail("invalid task parameters");
  const only = (keys: string[]) => {
    if (Object.keys(o).some((k) => !keys.includes(k))) fail("invalid task parameters");
  };
  if (EMPTY.includes(task)) {
    only([]);
    return { text: "{}", value: {} };
  }
  if (task === "os-update") {
    only(["kernel"]);
    const kernel = o.kernel === true;
    return { text: `{"kernel":${kernel}}`, value: { kernel } };
  }
  if (task === "journal-vacuum") {
    only(["keep_days"]);
    const n = o.keep_days;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 365) fail("keep_days must be between 1 and 365");
    return { text: `{"keep_days":${n}}`, value: { keep_days: n } };
  }
  if (task === "bastion-access") {
    only(["name", "address", "port", "admin_user", "ssh_ca"]);
    const v = { name: String(o.name ?? ""), address: String(o.address ?? ""), port: Number(o.port), admin_user: String(o.admin_user ?? ""), ssh_ca: String(o.ssh_ca ?? "") };
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(v.name) || !/^[0-9a-f.:]+$/.test(v.address) || !Number.isInteger(v.port) || v.port < 1 || v.port > 65535) fail("name must be a plain host name and address a literal IP address");
    if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(v.admin_user) || ["root", "aqmas", "aqmas-inspect", "aqmas-build"].includes(v.admin_user)) fail("admin_user must be your own account: not root and not one of aqmas's accounts");
    if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(v.ssh_ca)) fail("ssh_ca must be the SHA256 fingerprint of the SSH user CA");
    return { text: `{"name":${q(v.name)},"address":${q(v.address)},"port":${v.port},"admin_user":${q(v.admin_user)},"ssh_ca":${q(v.ssh_ca)}}`, value: v };
  }
  // bastion-allow
  only(["hosts"]);
  if (!Array.isArray(o.hosts) || o.hosts.length > 32) fail("hosts must be a list of at most 32 entries (empty to allow nobody)");
  const hosts = (o.hosts as Array<Record<string, unknown>>).map((x) => ({ id: String(x?.id ?? ""), name: String(x?.name ?? ""), address: String(x?.address ?? "") }));
  for (const [i, x] of hosts.entries()) {
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(x.id) || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(x.name) || !/^[0-9a-f.:]+$/.test(x.address)) fail("each host needs its enrollment id, name and a literal IP address");
    if (i > 0 && hosts[i - 1]!.id >= x.id) fail("hosts must be sorted by enrollment id, without duplicates");
  }
  return { text: `{"hosts":[${hosts.map((x) => `{"id":${q(x.id)},"name":${q(x.name)},"address":${q(x.address)}}`).join(",")}]}`, value: { hosts } };
}

/** What mock/server.ts keeps: pending items, grants and the audit log. */
export interface BastionStore {
  pending: PendingItem[];
  grants: GrantSummary[];
  audit(actor: string, action: string, object: string, detail?: string): void;
}

export class MockBastion {
  enabled = true;
  name = "bastion";
  address = "192.0.2.10";
  port = 22;
  adminUser = "alice";
  sealed = true;
  alertChannel = true;
  /** What the next root approval's alert attempt reports. */
  alertOutcome: "sent" | "failed" = "sent";
  sshCA = fp("mock-ssh-user-ca");
  hostKey = fp("mock-bastion-host-key");
  /** Labels of the buckets "open right now". */
  open: string[] = ["SSH user CA", "personal/paas/staging-env"];
  hosts: BastionHost[] = [
    { id: "01HZX0DEV1ENROLLMENT000001", name: "dev-1", class: "agent", address: "192.0.2.21", allowed: true, allowed_address: "192.0.2.21" },
    { id: "01HZX0WEB1ENROLLMENT000002", name: "web-1", class: "agent", address: "192.0.2.22", allowed: false },
    { id: "01HZX0LAPTOPENROLLMENT0003", name: "laptop", class: "owner-device", address: "192.0.2.30", allowed: false },
  ];
  sessions: BastionSession[] = [];
  /** Requests the owner dismissed, and run calls that named a request (tests look here). */
  dismissed: string[] = [];
  answered: Array<{ request: string; task: string; params: string }> = [];

  constructor(private store: BastionStore) {}

  private item(level: "inspect" | "root", over: Partial<PendingItem> = {}): PendingItem {
    const user = level === "root" ? this.adminUser : "aqmas-inspect";
    const host = this.hosts[0]!;
    return {
      id: ulidish(),
      kind: "bastion",
      created_at: iso(now() - 20_000),
      expires_at: iso(now() + 560_000),
      requesting_host: host.name,
      requesting_address: host.address,
      requester: { tool: "claude-code", user: "dev", cwd: "/home/dev/infra" },
      reason: level === "root" ? "replace the tunnel credentials file" : "approvals page is slow, reading aqmasd logs",
      ttl_requested: level === "root" ? 1800 : 3600,
      ttl_max: level === "root" ? 1800 : 3600,
      risk: level === "root" ? "high" : "normal",
      similar_recent: 0,
      bastion: {
        level, target: this.name, target_address: this.address, target_port: this.port, login_user: user, principal: `${user}@${this.name}`,
        key_fingerprint: fp("req-" + level + randomBytes(4).toString("hex")), host_id: host.id, ssh_ca: this.sshCA, host_key: this.hostKey,
        cert_profile: level === "root" ? "source-address;permit-pty" : "source-address;force-command", sealed: this.sealed,
        open_buckets: level === "root" && this.sealed ? [...this.open].sort() : [], alert_channel: level === "root" ? this.alertChannel : false,
      },
      ...over,
    };
  }

  spawn(level: "inspect" | "root", over: Partial<PendingItem> = {}): PendingItem {
    const it = this.item(level, over);
    this.store.pending.push(it);
    return it;
  }

  /** A routine task an agent queued. */
  spawnQueued(task = "os-update", params = '{"kernel":false}', over: Partial<PendingItem> = {}): PendingItem {
    const spec = BASTION_SPECS.find((s) => s.id === task)!;
    const it: PendingItem = {
      id: ulidish(), kind: "setup", created_at: iso(now() - 15_000), expires_at: iso(now() + 570_000), requesting_host: "dev-1", requesting_address: "192.0.2.21",
      requester: { tool: "claude-code", user: "dev" }, reason: "monthly updates", ttl_requested: 0, ttl_max: 0, risk: "normal", similar_recent: 0,
      setup: { task, title: spec.title, summary: spec.summary, steps: spec.steps, reversible: spec.reversible, warning: spec.warning, params },
      ...over,
    };
    this.store.pending.push(it);
    return it;
  }

  /** The current open list of a pending root item, as GET /api/ui/requests/{id} recomputes it. */
  refresh(p: PendingItem): PendingItem {
    if (p.kind === "bastion" && p.bastion?.level === "root") {
      p.bastion.open_buckets = this.sealed ? [...this.open].sort() : [];
      p.bastion.sealed = this.sealed;
      p.bastion.alert_channel = this.alertChannel;
    }
    return p;
  }

  /** Canonical text fields of a decision on a pending bastion request (canon.bastionKeys). */
  canonical(base: Record<string, unknown>, p: PendingItem, action: string, body: Record<string, unknown>, fail: (status: number, code: string, m: string) => never): Record<string, unknown> {
    const b = this.refresh(p).bastion!;
    if (body.standing_hours || body.standing_seconds || body.indefinite || body.standing_indefinite) fail(400, "bad_request", "a bastion session takes no standing or indefinite choice: every one needs its own approval");
    const root = b.level === "root";
    const c: Record<string, unknown> = {
      ...base, kind: "bastion", level: b.level, requesting_host: p.requesting_host, host_id: b.host_id, address: p.requesting_address, target: b.target,
      target_address: b.target_address, target_port: b.target_port, login_user: b.login_user, principal: b.principal, key_fingerprint: b.key_fingerprint,
      ssh_ca: b.ssh_ca, host_key: b.host_key, cert_profile: b.cert_profile, ttl_seconds: 0, sealed: b.sealed, open_buckets: "[]", close_buckets: false, alert_channel: false,
    };
    if (action === "deny") {
      if (body.ttl_seconds !== undefined || body.close_buckets !== undefined) fail(400, "bad_request", "deny takes no ttl_seconds or close_buckets");
      return c;
    }
    const ttl = typeof body.ttl_seconds === "number" ? body.ttl_seconds : p.ttl_requested;
    if (ttl < 60 || ttl > p.ttl_requested || (root && ttl > 3600)) fail(400, "bad_request", "ttl_seconds is outside what this bastion session allows");
    c.ttl_seconds = ttl;
    if (!root) {
      if (body.close_buckets !== undefined) fail(400, "bad_request", "close_buckets belongs to a root session");
      return c;
    }
    if (!this.hosts.some((x) => x.id === b.host_id && x.allowed)) fail(409, "conflict", "this host is not on the bastion allowlist");
    c.alert_channel = this.alertChannel;
    if (!b.sealed) {
      if (body.close_buckets === true) fail(400, "bad_request", "the store is not sealed: there are no buckets to close");
      return c;
    }
    if (typeof body.close_buckets !== "boolean") fail(400, "bad_request", "choose whether to close all open buckets first (close_buckets)");
    c.open_buckets = JSON.stringify([...this.open].sort());
    c.close_buckets = body.close_buckets;
    return c;
  }

  /** Apply a signed bastion decision; returns api.BastionDecision. */
  apply(c: Record<string, unknown>, p: PendingItem): unknown {
    const id = String(c.id);
    if (c.action === "deny") {
      this.store.audit("owner", "deny", `request:${id}`, `bastion ${c.level} for ${p.requesting_host}`);
      return { id, kind: "bastion", status: "denied", level: c.level, closed_count: 0, alert: "" };
    }
    const root = c.level === "root";
    const ttl = Number(c.ttl_seconds);
    const grant: GrantSummary = { id: ulidish(), kind: "bastion", status: "approved", target_host: String(c.target), login_user: String(c.login_user), requesting_host: p.requesting_host, not_before: iso(now() - 60_000), not_after: iso(now() + ttl * 1000) };
    this.store.grants.unshift(grant);
    let closed = 0;
    if (root && c.close_buckets === true) {
      closed = this.open.length;
      this.open = [];
    }
    const alert = !root ? "off" : !this.alertChannel ? "off" : this.alertOutcome;
    this.sessions.unshift({ grant_id: grant.id, level: String(c.level), requesting_host: p.requesting_host, login_user: String(c.login_user), not_before: grant.not_before, not_after: grant.not_after, status: "active", close_buckets: c.close_buckets === true, closed_count: closed, alert });
    this.store.audit("owner", root ? "bastion_root" : "approve", `request:${id}`, `grant=${grant.id} bastion ${c.level} ${c.principal} for ${p.requesting_host} ttl=${ttl} open=${c.open_buckets} close=${c.close_buckets} closed=${closed}`);
    return { id, kind: "bastion", status: "approved", level: c.level, closed_count: closed, alert };
  }

  rootUntil(): string | undefined {
    const live = this.sessions.filter((s) => s.level === "root" && s.status === "active" && Date.parse(s.not_after) > now() && this.store.grants.some((g) => g.id === s.grant_id && g.status === "approved"));
    return live.length ? live.map((s) => s.not_after).sort().at(-1) : undefined;
  }

  view(): BastionView {
    for (const s of this.sessions) {
      const g = this.store.grants.find((x) => x.id === s.grant_id);
      s.status = g?.status === "revoked" ? "revoked" : Date.parse(s.not_after) <= now() ? "expired" : "active";
    }
    const v: BastionView = { enabled: this.enabled, inspect_user: "aqmas-inspect", ssh_ca: this.sshCA, sealed: this.sealed, alert_channel: this.alertChannel, hosts: this.hosts, sessions: this.sessions, tasks: BASTION_SPECS.map((s) => s.id) };
    if (this.enabled) Object.assign(v, { name: this.name, address: this.address, port: this.port, admin_user: this.adminUser });
    const until = this.rootUntil();
    if (until) v.root_until = until;
    return v;
  }

  /** The fake runner finished one of the bastion tasks. */
  ran(task: string, params: Record<string, unknown>): { message: string; result?: Record<string, string> } {
    switch (task) {
      case "bastion-access":
        Object.assign(this, { enabled: true, name: params.name, address: params.address, port: params.port, adminUser: params.admin_user });
        return { message: "This machine's sshd now accepts aqmas certificates for the inspect and admin accounts." };
      case "bastion-access-remove":
        this.enabled = false;
        for (const h of this.hosts) Object.assign(h, { allowed: false, allowed_address: undefined });
        return { message: "Access removed. Only your emergency key gets in." };
      case "bastion-allow": {
        const list = params.hosts as Array<{ id: string; address: string }>;
        for (const h of this.hosts) {
          const a = list.find((x) => x.id === h.id);
          h.allowed = !!a;
          h.allowed_address = a?.address;
        }
        return { message: `${list.length} host(s) may ask for root.` };
      }
      case "os-update":
        return { message: "12 packages updated.", result: { packages_changed: "12", kernel_changed: "no", reboot_suggested: "no" } };
      case "disk-usage":
        return { message: "Measured.", result: { root: "41G used of 100G (41%)", journal: "812.0M" } };
      case "journal-vacuum":
        return { message: "Journal trimmed.", result: { freed: "512.0M" } };
      default:
        return { message: "Done." };
    }
  }

  /** GET /api/ui/bastion and POST /api/ui/setup-requests/{id}/dismiss; undefined otherwise. */
  handle(path: string, post: boolean, fail: (status: number, code: string, m: string) => never): unknown | undefined {
    if (path === "/api/ui/bastion" && !post) return this.view();
    const m = path.match(/^\/api\/ui\/setup-requests\/([^/]+)\/dismiss$/);
    if (m && post) {
      const id = decodeURIComponent(m[1]!);
      const i = this.store.pending.findIndex((x) => x.id === id && x.kind === "setup");
      if (i < 0) fail(404, "not_found", "no such request");
      this.store.pending.splice(i, 1);
      this.dismissed.push(id);
      this.store.audit("owner", "setup_request_dismiss", `setup-request:${id}`);
      return { ok: true };
    }
    return undefined;
  }

  /** A run call that names a queued request: it must ask for exactly the signed task and
   * parameters, and is then approved (removed from the pending list). */
  answer(request: unknown, task: string, params: string, fail: (status: number, code: string, m: string) => never): void {
    if (typeof request !== "string" || !request) return;
    const p = this.store.pending.find((x) => x.id === request && x.kind === "setup");
    if (!p) fail(404, "not_found", "no such request");
    if (p!.setup!.task !== task || p!.setup!.params !== params) fail(409, "conflict", "the signed task is not the one this request asked for");
    this.store.pending.splice(this.store.pending.indexOf(p!), 1);
    this.answered.push({ request, task, params });
  }
}
