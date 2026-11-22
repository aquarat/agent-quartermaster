// Mock of Admin → Setup (docs/SETUP.md) for `bun run mock` and the tests: the setup view, the
// signed run of each task with a fake runner (running → waiting → done, the broker "down" in
// between), cancel, the cutover review, the supervised seal import with the recovery drill,
// and an upgrade to approve.
//
//   GET /mock/setup?installed=0|1&pinned=0|1&scoped=0|1&sealed=0|1&updates=0|1
//                  &mode=serve|cutover|seal-setup&wrap=none|created|tested&drilled=0|1
//     jumps the mock to a state (development and screenshots only).
//
// Like the rest of the mock, signatures are not verified. Sealed packets are opened for
// real, so the page's HPKE code is exercised.

import { createECDH, createHash, randomBytes } from "node:crypto";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { bech32Decode, recipientOf } from "./age";

const b64url = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const sha256hex = (b: string | Uint8Array) => createHash("sha256").update(b).digest("hex");
const nowISO = (ms = Date.now()) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

/** Sorted keys, no whitespace, no HTML escaping: canon.Build's encoding. */
export function plainCanonical(v: Record<string, unknown>): string {
  return JSON.stringify(v, Object.keys(v).sort());
}

interface KeyPair {
  priv: Buffer;
  pub: string;
}
function newKey(): KeyPair {
  const e = createECDH("prime256v1");
  e.generateKeys();
  const priv = Buffer.alloc(32);
  const raw = e.getPrivateKey();
  raw.copy(priv, 32 - raw.length);
  return { priv, pub: b64url(e.getPublicKey()) };
}

/** Open base64url(enc || ciphertext) as the runner does (internal/maint/secrets.go). */
export async function openPacket(key: KeyPair, info: Uint8Array, packet: string): Promise<Uint8Array> {
  if (!/^[A-Za-z0-9_-]+$/.test(packet)) throw new Error("invalid secrets packet");
  const raw = Buffer.from(packet, "base64url");
  if (raw.length < 65 + 16 || raw.length > 8 << 10) throw new Error("invalid secrets packet");
  const recipientKey = await suite.kem.importKey("raw", new Uint8Array(key.priv).buffer, false);
  const ctx = await suite.createRecipientContext({ recipientKey, enc: new Uint8Array(raw.subarray(0, 65)).buffer, info: new Uint8Array(info).buffer });
  return new Uint8Array(await ctx.open(new Uint8Array(raw.subarray(65)).buffer));
}

export interface MockRun {
  task: string;
  state: "running" | "waiting" | "done" | "failed";
  step: string;
  waiting_for?: string;
  deadline?: string;
  started_at: string;
  finished_at?: string;
  message?: string;
  log: string[];
  result?: Record<string, string>;
}

const SPECS = [
  {
    id: "cutover",
    title: "Switch to organisations",
    summary: "Moves this broker from the legacy single list to the organisations catalogue: your hosts, SSH targets and Cloudflare scopes become the “personal” organisation.",
    steps: ["Stop the broker and wait for it to exit", "Back up the database, keys and configuration", "Start the broker fenced for review (agents are refused)", "You review the plan and activate it with your passkey", "Restart the broker and check it is healthy"],
    reversible: "Until you activate, cancelling changes nothing. If the broker is unhealthy afterwards the backup is restored automatically. Later it is fix-forward only.",
  },
  {
    id: "seal",
    title: "Seal the store",
    summary: "Encrypts the SSH CA, the internal CA key, the notification URL and the Cloudflare parent tokens under a key that only your passkey can unlock. After every restart the broker starts locked until you unlock it.",
    steps: ["Stop the broker and back up", "Record the recovery key (public half) in the root-owned configuration", "Start the broker in import mode (agents are refused)", "You create and test the passkey wrap, prove the recovery key works, and activate", "Pin the activation, delete the plaintext key files and old backups", "Set up the lock alert if you gave it a credential", "Restart locked"],
    reversible: "Until you activate, cancelling restores the configuration. After activation there is no way back to plaintext: recovery is your passkeys or the recovery key.",
    secrets: ["ntfy_topic_url", "ntfy_token"],
  },
  {
    id: "enable-updates",
    title: "Enable self-update",
    summary: "Prepares this machine to rebuild and install new releases itself, each one approved by you on this page.",
    steps: ["Install build tools, the pinned Go and Bun toolchains and a locked build user", "Create the read-only deploy key and trust the forge's host key", "Store the release-reading tokens", "Check the installed broker against both published releases and cache the matching CLIs", "Add the update sources to the configuration and restart the broker"],
    reversible: "The previous configuration is restored if the release check or the restart fails. Installed tools stay.",
    secrets: ["forgejo_token", "github_token"],
  },
  {
    id: "sync-passkeys",
    title: "Sync maintenance passkeys",
    summary: "Replaces the root-owned list of passkeys that may approve tasks on this page with the passkeys listed here.",
    steps: ["Compare each listed passkey with the broker's record", "Replace the pinned list"],
    reversible: "Run it again with another list. If no pinned passkey is left, re-pin from a terminal on the machine.",
  },
  {
    id: "upgrade",
    title: "Upgrade aqmas",
    summary: "Rebuilds the approved release from source in a sandbox, checks all four binaries against both published releases, installs the broker and restarts it.",
    steps: ["Verify the approval and both releases", "Fetch, build and test in a sandbox without network", "Install, restart and check health"],
    reversible: "The previous binary is restored automatically if the new one is unhealthy. Database migrations are not reversed.",
  },
] as const;

const RE = {
  recipient: /^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$/,
  repo: /^ssh:\/\/[a-z_][a-z0-9_-]{0,31}@([a-z0-9][a-z0-9.-]{0,252})(:[0-9]{1,5})?\/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\.git$/,
  api: /^https?:\/\/[A-Za-z0-9.:-]{1,255}\/[A-Za-z0-9._/-]{1,200}$/,
  hostKey: /^(\[[a-z0-9][a-z0-9.-]{0,252}\]:[0-9]{1,5}|[a-z0-9][a-z0-9.-]{0,252}) (ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) [A-Za-z0-9+/]{40,1024}={0,2}$/,
  cred: /^[A-Za-z0-9_-]{16,1366}$/,
  token: /^[A-Za-z0-9_.~+/=:-]{8,512}$/,
  topic: /^https:\/\/[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?\/[A-Za-z0-9_-]{1,128}$/,
  hash: /^[0-9a-f]{64}$/,
};

function knownHost(repo: string): string {
  const m = RE.repo.exec(repo);
  if (!m) return "";
  return !m[2] || m[2] === ":22" ? m[1]! : `[${m[1]}]${m[2]}`;
}

/** A cutover plan in organisations.Plan's wire order (web/src/migration.ts checks it). */
function mockPlan(passkeys: string[]): string {
  const named = (id: string, slug: string, title: string) => ({ id, slug, title });
  const target = (name: string, address: string, users: string[]) => ({ Aliases: [], Name: name, Address: address, Port: 22, Users: users, HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockHostKey" + name, PrincipalOverride: "", ForgejoUser: "", MaxTTLSeconds: 28800, HighRisk: false });
  const plan = {
    source_schema: 5,
    organisation: named("org-personal", "personal", "Personal"),
    owner_approver: named("approver-owner", "owner", "alice"),
    owner_webauthn_id_hex: "00".repeat(32),
    owner_passkeys: passkeys,
    ssh_ca_fingerprint: "SHA256:" + "A".repeat(43),
    tls_ca_pin: "sha256:" + "0".repeat(64),
    approval_origin: "https://aqmas.example.com",
    legacy_ttl_policy: { OwnerMaxSeconds: 86400, OwnerMaxStandingHours: 24, DefaultSeconds: 1800, MaxSeconds: 28800, MinSeconds: 60, PendingExpirySeconds: 600, EnrollmentExpirySeconds: 1800, MaxStandingHours: 8 },
    services: [
      {
        ...named("svc-ssh", "ssh", "SSH"),
        sets: [
          { ...named("set-db-1", "db-1", "db-1"), kind: "ssh", ssh_target: target("db-1", "192.0.2.10", ["alice"]) },
          { ...named("set-build-box", "build-box", "build-box"), kind: "ssh", ssh_target: target("build-box", "192.0.2.20", ["alice", "root"]) },
        ],
      },
      { ...named("svc-cloudflare", "cloudflare", "Cloudflare"), sets: [{ ...named("set-cf", "main", "Main account"), kind: "cloudflare" }] },
    ],
    public_config_sha256: "1".repeat(64),
    admit_to_personal_only: [
      { host_id: 1, enrollment_id: "01JDEMOENROLLWEB1000000001", certificate_sha256: "2".repeat(64), name: "web-1", class: "agent", not_after_ms: 1900000000000 },
      { host_id: 2, enrollment_id: "01JDEMOENROLLBUILD00000002", certificate_sha256: "3".repeat(64), name: "build-box", class: "agent", not_after_ms: 1900000000000 },
      { host_id: 3, enrollment_id: "01JDEMOENROLLLAPTOP0000003", certificate_sha256: "4".repeat(64), name: "laptop-2", class: "owner-device", not_after_ms: 1900000000000 },
    ],
    retire: {
      expire_requests: ["01JDEMO0SSH0DB1XXX0000001"],
      expire_enrollments: [],
      revoke_grants: ["01JDEMO0GRANT00000000005"],
      revoke_standing: ["01JDEMO0STANDING000000004"],
      outstanding_certificates_and_unverified_children: [],
      preserve_grant_high_water: 6,
      expire_challenges: "all",
      legacy_history: "kept read-only",
    },
  };
  return JSON.stringify(plan);
}

/** What the mock needs from mock/server.ts. */
export interface MockHost {
  passkeys(): { id: string; hex: string; name: string }[];
  sessionPasskey(session: string | undefined): string | undefined;
  issue(text: string, canonical: Record<string, unknown>, session: string | undefined): { id: string; challenge: string };
  /** Take an action challenge and check the assertion against it; returns its canonical. */
  redeem(challengeId: unknown, assertion: unknown, session: string | undefined): Record<string, unknown>;
  requestOptions(req: Request, challenge: string): unknown;
  fail(status: number, code: string, message: string): never;
  audit(action: string, object: string, detail?: string): void;
}

export class MockSetup {
  mode: "serve" | "cutover" | "seal-setup" = "serve";
  installed = true;
  scoped = false;
  sealed = false;
  updatesReady = false;
  candidate = true;
  version = "1.4.0";
  /** Pinned credential IDs; null = every passkey registered at "maint-init" time. */
  pins: string[] | null = null;
  current: MockRun | null = null;
  refused: { at: string; reason: string } | null = null;
  last: Record<string, MockRun> = {};
  updateSources: Record<string, string> = {};
  secretsKey = newKey();
  drillKey = newKey();
  deployKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockDeployKeyMockDeployKeyMockDeployKey0 aqmas-update@bastion";
  // The staged seal import.
  wrap: "none" | "created" | "tested" = "none";
  wrapCredential = "";
  drilled = false;
  activated = false;
  recipient = "";
  installation = b64url(randomBytes(32));
  epoch = b64url(randomBytes(32));
  attempts = new Map<string, string>();
  /** The API answers 502 until then: the broker is restarting. */
  downUntil = 0;
  /** Tests: what the runner received, opened. Secrets appear here and nowhere else. */
  received: Array<{ task: string; params: string; secrets: Record<string, string> }> = [];
  private timers = new Set<ReturnType<typeof setTimeout>>();

  constructor(
    private host: MockHost,
    public stepMs = 1500,
  ) {}

  stop(): void {
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
  }

  private later(steps: number, f: () => void): void {
    const t = setTimeout(() => {
      this.timers.delete(t);
      f();
    }, steps * this.stepMs);
    this.timers.add(t);
  }

  private pinned(): string[] {
    this.pins ??= this.host.passkeys().map((p) => p.id);
    return this.pins;
  }

  // ---- the fake runner ----

  private begin(task: string, step: string): MockRun {
    this.refused = null;
    this.current = { task, state: "running", step, started_at: nowISO(), log: [step] };
    return this.current;
  }
  private step(text: string, restart = false): void {
    if (!this.current) return;
    this.current.state = "running";
    this.current.step = text;
    delete this.current.waiting_for;
    delete this.current.deadline;
    this.current.log.push(text);
    if (restart) this.downUntil = Date.now() + this.stepMs * 0.8;
  }
  private wait(what: string, minutes: number): void {
    if (!this.current) return;
    this.current.state = "waiting";
    this.current.waiting_for = what;
    this.current.deadline = nowISO(Date.now() + minutes * 60_000);
    this.current.log.push("Waiting: " + what);
  }
  private finish(state: "done" | "failed", message: string, result?: Record<string, string>): void {
    const run = this.current;
    if (!run) return;
    this.current = null;
    this.mode = "serve";
    this.last[run.task] = { ...run, state, step: state === "done" ? "Finished" : run.step, finished_at: nowISO(), message, result, waiting_for: undefined, deadline: undefined, log: [...run.log, message] };
  }

  private start(task: string, params: Record<string, unknown>): void {
    const steps: readonly string[] = SPECS.find((s) => s.id === task)!.steps;
    const at = (i: number) => steps[i]!;
    const stamp = nowISO().replace(/[-:]/g, "");
    switch (task) {
      case "cutover":
        this.begin(task, at(0));
        this.later(1, () => this.step(at(1), true));
        this.later(2, () => {
          this.step(at(2));
          this.mode = "cutover";
          this.wait("your review and activation of the plan", 15);
        });
        break;
      case "seal":
        this.recipient = String(params["recipient"]);
        this.wrap = "none";
        this.wrapCredential = "";
        this.drilled = this.activated = false;
        this.begin(task, at(0));
        this.later(1, () => this.step(at(1), true));
        this.later(2, () => {
          this.step(at(2));
          this.mode = "seal-setup";
          this.wait("the passkey wrap, the recovery key check and your activation", 30);
        });
        break;
      case "enable-updates":
        this.begin(task, at(0));
        for (let i = 1; i < steps.length; i++) this.later(i, () => this.step(at(i), i === steps.length - 1));
        this.later(steps.length, () => {
          this.updatesReady = true;
          this.updateSources = { repo: String(params["repo"]), forgejo_api: String(params["forgejo_api"]), github_api: String(params["github_api"]) };
          this.finish("done", "Self-update is enabled. New releases will be offered here.", { release_cache: "/var/lib/aqmas-releases", known_hosts: String((params["known_hosts"] as string[]).length) + " host key(s) trusted" });
        });
        break;
      case "sync-passkeys": {
        this.begin(task, at(0));
        this.pins = (params["pins"] as { id: string }[]).map((p) => p.id);
        this.finish("done", `${this.pins.length} passkey(s) pinned for maintenance.`);
        break;
      }
      case "upgrade":
        this.begin(task, at(0));
        this.later(1, () => this.step(at(1)));
        this.later(2, () => this.step(at(2), true));
        this.later(3, () => {
          this.candidate = false;
          this.version = "1.5.0";
          this.finish("done", "Installed 1.5.0 and the broker is healthy.", { previous_binary: `/var/lib/aqmas-backups/aqmasd-${stamp}` });
        });
        break;
    }
  }

  private activatedCutover(): void {
    this.step("Restart the broker and check it is healthy", true);
    this.later(1, () => {
      this.scoped = true;
      this.finish("done", "Switched to organisations. The broker is healthy.", { backup: "/var/lib/aqmas-backups/cutover-" + nowISO().replace(/[-:]/g, "") });
    });
  }

  private activatedSeal(): void {
    this.activated = true;
    this.step("Pin the activation, delete the plaintext key files and old backups");
    this.later(1, () => this.step("Restart locked", true));
    this.later(2, () => {
      this.sealed = true;
      this.finish("done", "The store is sealed. Unlock the broker with your passkey after every restart.", { manifest_sha256: sha256hex(this.manifest()), sealed_bundle: "/var/lib/aqmas-backups/sealed-" + nowISO().replace(/[-:]/g, "") });
    });
  }

  private manifest(): string {
    return JSON.stringify({ installation: this.installation, recovery_recipient: this.recipient, roles: ["ssh-ca", "tls-ca", "ntfy", "cloudflare-parent"], wrapped_credentials: [this.wrapCredential] });
  }

  // ---- views ----

  view(session: string | undefined) {
    const pins = this.pinned();
    const cur = this.host.sessionPasskey(session);
    const keys = this.host.passkeys();
    const passkeys = keys.map((k) => ({ id: k.hex, credential: k.id, key_sha256: sha256hex("cose:" + k.id), name: k.name, pinned: pins.includes(k.id), current: k.hex === cur }));
    const unpinned = passkeys.filter((p) => !p.pinned).length;
    const tasks = SPECS.map((spec) => {
      const t: Record<string, unknown> & { state: string } = { ...spec, state: "available" };
      let last: MockRun | undefined = this.last[spec.id];
      let blocked = "";
      let rerunnable = false;
      switch (spec.id) {
        case "cutover":
          if (this.scoped) t.state = "done";
          break;
        case "seal":
          if (this.sealed) t.state = "done";
          else if (!this.scoped) [t.state, blocked] = ["blocked", "Switch to organisations first."];
          break;
        case "enable-updates":
          rerunnable = true;
          if (this.updatesReady) t.state = "done";
          break;
        case "sync-passkeys":
          rerunnable = true;
          if (unpinned === 0 && pins.length === keys.length) t.state = "done";
          break;
        case "upgrade":
          if (!this.updatesReady) [t.state, blocked] = ["blocked", "Enable self-update first."];
          else if (!this.candidate) t.state = "idle";
          break;
      }
      if (t.state === "available" && last?.state === "failed") t.state = "failed";
      if (t.state === "available" || t.state === "failed" || (t.state === "done" && rerunnable)) {
        if (!this.installed) [t.state, blocked] = ["blocked", "The maintenance runner is not installed on this machine yet."];
        else if ((this.mode !== "serve" || this.current) && t.state !== "done") [t.state, blocked] = ["blocked", "Another task is in progress."];
      }
      if (this.current?.task === spec.id) {
        t.state = this.current.state;
        blocked = "";
        last = this.current;
      }
      if (blocked) t.blocked_by = blocked;
      if (rerunnable) t.rerunnable = true;
      if (last) t.last = last;
      return t;
    });
    const v: Record<string, unknown> = { mode: this.mode, runner_installed: this.installed, passkeys, tasks, update_sources: this.updateSources };
    if (this.installed) Object.assign(v, { runner_version: this.version, secrets_key: this.secretsKey.pub, deploy_key: this.deployKey });
    if (this.current) v.current = this.current;
    if (this.refused) v.refused = this.refused;
    return v;
  }

  updatesView() {
    const commit = (c: string) => c.repeat(40);
    const sums = Object.fromEntries(["aqmasd-linux-arm64", "aqmas-linux-arm64", "aqmas-linux-amd64", "aqmas-darwin-arm64"].map((a) => [a, sha256hex("mock release " + a)]));
    const base = { current: this.version, commit: this.version === "1.4.0" ? commit("a") : commit("b"), status: "", stat: "", diff: "" };
    if (!this.updatesReady) return { ...base, error: "Update discovery is disabled", candidate: {} };
    if (!this.candidate) return { ...base, error: "", candidate: {} };
    return {
      ...base,
      error: "",
      candidate: { version: "1.5.0", commit: commit("b"), forgejo: sums, github: sums },
      stat: " internal/server/setup.go | 12 ++++++------\n 1 file changed, 6 insertions(+), 6 deletions(-)",
      diff: "diff --git a/internal/server/setup.go b/internal/server/setup.go\n--- a/internal/server/setup.go\n+++ b/internal/server/setup.go\n@@ -1,3 +1,3 @@\n-old line\n+new line\n",
    };
  }

  private sealView(req: Request) {
    const mode = this.activated ? "activated" : "setup";
    const rp = new URL(req.url).hostname;
    const keys = this.host.passkeys().filter((k) => this.wrap === "none" || k.id === this.wrapCredential);
    const choices =
      this.wrap === "tested" || this.activated
        ? []
        : keys.map((k) => ({
            id: k.hex,
            name: k.name,
            selection: { action: "wrap-enroll", credential_id: k.id, installation: this.installation, epoch: this.epoch, rp_id: rp, mk_version: 1, prf_salt: b64url(createHash("sha256").update("salt:" + k.id).digest()), registration_id: `reg-${k.hex.slice(0, 8)}-${this.wrap === "none" ? "create" : "test"}` },
          }));
    const v: Record<string, unknown> = { mode, epoch: this.epoch, installation: this.installation, choices, drill_key: this.drillKey.pub, drilled: this.drilled };
    if (this.wrap === "tested" && !this.activated) v.manifest = this.manifest();
    return v;
  }

  // ---- parameters as the broker canonicalises them ----

  private params(task: string, raw: unknown): { text: string; value: Record<string, unknown>; secrets: string[] } {
    const fail = (m: string): never => this.host.fail(400, "bad_request", m);
    const o = (raw ?? {}) as Record<string, unknown>;
    if (typeof o !== "object" || Array.isArray(o)) fail("invalid task parameters");
    const only = (obj: Record<string, unknown>, keys: string[]) => {
      if (Object.keys(obj).some((k) => !keys.includes(k))) fail("invalid task parameters");
    };
    const s = (v: unknown) => (typeof v === "string" ? v : v === undefined ? "" : fail("invalid task parameters"));
    const b = (v: unknown) => (typeof v === "boolean" ? v : v === undefined ? false : fail("invalid task parameters"));
    const q = JSON.stringify;
    switch (task) {
      case "cutover":
        only(o, []);
        return { text: "{}", value: {}, secrets: [] };
      case "seal": {
        only(o, ["recipient", "purge_backups", "lock_alert"]);
        const v = { recipient: s(o.recipient), purge_backups: b(o.purge_backups), lock_alert: b(o.lock_alert) };
        if (!RE.recipient.test(v.recipient)) fail("recipient must be a native age X25519 public key (age1…)");
        try {
          if (bech32Decode(v.recipient).hrp !== "age") throw new Error();
        } catch {
          fail("recipient must be a native age X25519 public key (age1…)");
        }
        return { text: `{"recipient":${q(v.recipient)},"purge_backups":${v.purge_backups},"lock_alert":${v.lock_alert}}`, value: v, secrets: v.lock_alert ? ["ntfy_token", "ntfy_topic_url"] : [] };
      }
      case "enable-updates": {
        only(o, ["repo", "forgejo_api", "github_api", "known_hosts", "forgejo_token", "github_token"]);
        const hosts = (Array.isArray(o.known_hosts) ? [...o.known_hosts] : o.known_hosts === undefined ? [] : fail("invalid task parameters")).map(s).sort();
        const v = { repo: s(o.repo), forgejo_api: s(o.forgejo_api), github_api: s(o.github_api), known_hosts: hosts, forgejo_token: b(o.forgejo_token), github_token: b(o.github_token) };
        const host = knownHost(v.repo);
        if (!host) fail("repo must look like ssh://git@forge.example.com/owner/name.git");
        if (!RE.api.test(v.forgejo_api) || !RE.api.test(v.github_api)) fail("release API must be a plain https URL");
        if (!v.forgejo_api.includes("/api/v1/repos/")) fail("Forgejo API must contain /api/v1/repos/");
        if (hosts.length < 1 || hosts.length > 4 || new Set(hosts).size !== hosts.length) fail("one to four sorted, distinct known_hosts lines required");
        for (const line of hosts) if (!RE.hostKey.test(line) || !line.startsWith(host + " ")) fail(`known_hosts lines must be “${host} <key type> <key>”`);
        return {
          text: `{"repo":${q(v.repo)},"forgejo_api":${q(v.forgejo_api)},"github_api":${q(v.github_api)},"known_hosts":[${hosts.map((h) => q(h)).join(",")}],"forgejo_token":${v.forgejo_token},"github_token":${v.github_token}}`,
          value: v,
          secrets: [...(v.forgejo_token ? ["forgejo_token"] : []), ...(v.github_token ? ["github_token"] : [])],
        };
      }
      case "sync-passkeys": {
        only(o, ["pins"]);
        const pins = (Array.isArray(o.pins) ? o.pins : fail("invalid task parameters")).map((p: unknown) => {
          const pin = (p ?? {}) as Record<string, unknown>;
          only(pin, ["id", "key_sha256"]);
          return { id: s(pin.id), key_sha256: s(pin.key_sha256) };
        });
        if (pins.length < 1 || pins.length > 32) fail("one to 32 pins required");
        if (pins.some((p) => !RE.cred.test(p.id) || !RE.hash.test(p.key_sha256)) || new Set(pins.map((p) => p.id)).size !== pins.length) fail("invalid or duplicate pin");
        const known = this.host.passkeys();
        if (pins.some((p) => !known.some((k) => k.id === p.id && sha256hex("cose:" + k.id) === p.key_sha256))) this.host.fail(409, "conflict", "a listed passkey is not registered");
        return { text: `{"pins":[${pins.map((p) => `{"id":${q(p.id)},"key_sha256":${q(p.key_sha256)}}`).join(",")}]}`, value: { pins }, secrets: [] };
      }
    }
    return this.host.fail(404, "not_found", "no such task");
  }

  private runnable(session: string | undefined, task: string): void {
    const t = (this.view(session).tasks as Array<{ id: string; state: string; blocked_by?: string; rerunnable?: boolean }>).find((x) => x.id === task);
    if (!t) this.host.fail(404, "not_found", "no such task");
    if (t!.state === "available" || t!.state === "failed" || (t!.state === "done" && t!.rerunnable && !this.current && this.mode === "serve" && this.installed)) return;
    this.host.fail(409, "conflict", t!.blocked_by || `this task cannot run now (${t!.state})`);
  }

  private needPinned(session: string | undefined): void {
    if (!this.installed) this.host.fail(409, "conflict", "the maintenance runner is not installed on this machine yet");
    const cur = this.host.sessionPasskey(session);
    const pk = this.host.passkeys().find((k) => k.hex === cur);
    if (!pk || !this.pinned().includes(pk.id)) this.host.fail(409, "conflict", "this passkey is not pinned for maintenance: sign with a pinned passkey, then run “Sync maintenance passkeys”");
  }

  // ---- HTTP ----

  /** Returns undefined when the path is not one of the mock's setup endpoints. */
  async handle(req: Request, url: URL, body: Record<string, unknown>, session: string | undefined): Promise<unknown | undefined> {
    const p = url.pathname;
    const post = req.method === "POST";
    const fail = this.host.fail;
    let m: RegExpMatchArray | null;

    if (p === "/api/ui/setup" && !post) return this.view(session);
    if (p === "/api/ui/updates" && !post) return this.updatesView();
    if (p === "/api/ui/setup/cutover/preview" && !post) {
      if (this.mode !== "serve" || this.scoped) fail(409, "conflict", "no cutover to preview");
      return { id: "org-personal", plan: mockPlan(this.host.passkeys().map((k) => k.hex)) };
    }
    if (p === "/api/ui/setup/cancel" && post) {
      if (this.current?.state !== "waiting") fail(409, "conflict", "no task is waiting");
      this.host.audit("setup_cancel", "setup:" + this.current!.task);
      this.step("Cancelled: putting everything back", true);
      this.later(1, () => this.finish("failed", "Cancelled. Everything was put back as it was."));
      return { ok: true };
    }
    if (p === "/api/ui/setup/host-key" && post) {
      const host = knownHost(String(body.repo ?? ""));
      if (!host) fail(400, "bad_request", "repo must look like ssh://git@forge.example.com/owner/name.git");
      const keys = [
        ["ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI" + b64url(createHash("sha256").update("ed:" + host).digest()).replace(/[-_]/g, "A")],
        ["ecdsa-sha2-nistp256", "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB" + b64url(createHash("sha512").update("ec:" + host).digest()).replace(/[-_]/g, "B")],
      ].map(([type, key]) => ({ line: `${host} ${type} ${key}`, fingerprint: "SHA256:" + createHash("sha256").update(Buffer.from(key!, "base64")).digest("base64").replace(/=+$/, "") }));
      return { host, keys: keys.sort((a, b) => (a.line < b.line ? -1 : 1)) };
    }
    if ((m = p.match(/^\/api\/ui\/setup\/([a-z-]+)\/(challenge|run)$/)) && post) {
      const task = m[1]!;
      if (m[2] === "challenge") {
        if (task === "upgrade") fail(400, "bad_request", "approve upgrades through /api/ui/updates");
        this.runnable(session, task);
        const { text, secrets } = this.params(task, body.params);
        const hash = typeof body.secrets_sha256 === "string" ? body.secrets_sha256 : "";
        if ((secrets.length !== 0) !== (hash !== "") || (hash !== "" && !RE.hash.test(hash))) fail(400, "bad_request", "secrets do not match the chosen options");
        const canonical = { v: 1, action: "run", object: "setup", id: task, params: text, secrets_sha256: hash, nonce: b64url(randomBytes(32)), issued_at: nowISO() };
        const canonicalText = plainCanonical(canonical);
        const c = this.host.issue(canonicalText, canonical, session);
        return { challenge_id: c.id, canonical: canonicalText, public_key: this.host.requestOptions(req, c.challenge) };
      }
      const c = this.host.redeem(body.challenge_id, body.assertion, session);
      if (c.object !== "setup" || c.id !== task) fail(403, "forbidden", "challenge is for a different object");
      this.runnable(session, task);
      const packet = typeof body.secrets === "string" ? body.secrets : "";
      const hash = packet ? sha256hex(Buffer.from(packet, "base64url")) : "";
      if (hash !== c.secrets_sha256) fail(400, "bad_request", "secrets do not match the signed request");
      this.needPinned(session);
      const { value, secrets: names } = this.params(task, JSON.parse(String(c.params)));
      // From here on this is the runner: it opens the packet with its own key.
      let secrets: Record<string, string> = {};
      if (names.length) {
        try {
          secrets = JSON.parse(new TextDecoder().decode(await openPacket(this.secretsKey, new TextEncoder().encode("aqmas-setup-secrets-v1\0" + task), packet)));
        } catch {
          this.refused = { at: nowISO(), reason: "secrets packet could not be opened" };
          return { ok: true };
        }
        const bad = Object.keys(secrets).sort().join() !== [...names].sort().join() || Object.entries(secrets).some(([k, v]) => !(k === "ntfy_topic_url" ? RE.topic : RE.token).test(v));
        if (bad) {
          this.refused = { at: nowISO(), reason: "unexpected or malformed secret" };
          return { ok: true };
        }
      }
      this.received.push({ task, params: String(c.params), secrets });
      this.host.audit("setup_run", "setup:" + task, String(c.params));
      this.start(task, value);
      return { ok: true };
    }

    // The fenced cutover review (the page's existing activation flow).
    if (p === "/api/ui/migration" && !post) return this.mode === "cutover" ? this.cutover() : null;
    if ((m = p.match(/^\/api\/ui\/migrations\/([^/]+)\/(challenge|activate)$/)) && post) {
      const review = this.cutover();
      if (this.mode !== "cutover" || m[1] !== review.id) fail(404, "not_found", "no such migration");
      if (m[2] === "challenge") {
        if (body.action !== "activate") fail(400, "bad_request", "expected activate");
        const canonical = { v: 2, action: "activate", object: "migration", id: review.id, plan: review.plan, recovery_sha256: review.recovery_sha256, nonce: b64url(randomBytes(32)), issued_at: nowISO() };
        const text = plainCanonical(canonical);
        const c = this.host.issue(text, canonical, session);
        return { challenge_id: c.id, canonical: text, public_key: this.host.requestOptions(req, c.challenge) };
      }
      const c = this.host.redeem(body.challenge_id, body.assertion, session);
      if (c.object !== "migration") fail(403, "forbidden", "challenge is for a different object");
      this.activatedCutover();
      return { ok: true };
    }

    // An upgrade to approve (the page's existing update flow).
    if ((m = p.match(/^\/api\/ui\/updates\/([0-9a-f]{40})\/(challenge|decide)$/)) && post) {
      const u = this.updatesView();
      const cand = u.candidate as { version?: string; commit?: string; forgejo?: Record<string, string> };
      if (!cand.commit || cand.commit !== m[1] || this.current || this.mode !== "serve") fail(409, "conflict", "no such update to approve now");
      if (m[2] === "challenge") {
        const f = cand.forgejo!;
        const canonical = {
          v: 1, action: "approve", object: "update", id: cand.commit, nonce: b64url(randomBytes(32)), issued_at: nowISO(),
          from_version: u.current, from_commit: u.commit, to_version: cand.version, to_commit: cand.commit,
          daemon_sha256: f["aqmasd-linux-arm64"], linux_arm64_sha256: f["aqmas-linux-arm64"], linux_amd64_sha256: f["aqmas-linux-amd64"], darwin_arm64_sha256: f["aqmas-darwin-arm64"],
        };
        const text = plainCanonical(canonical);
        const c = this.host.issue(text, canonical, session);
        return { challenge_id: c.id, canonical: text, public_key: this.host.requestOptions(req, c.challenge) };
      }
      const c = this.host.redeem(body.challenge_id, body.assertion, session);
      if (c.object !== "update") fail(403, "forbidden", "challenge is for a different object");
      this.needPinned(session);
      this.start("upgrade", {});
      return { ok: true };
    }

    // The supervised seal import.
    if (p.startsWith("/api/ui/seal/")) {
      if (this.mode !== "seal-setup") return undefined;
      const rest = p.slice("/api/ui/seal/".length);
      if (rest === "status" && !post) return this.sealView(req);
      if (!post) return undefined;
      if (this.activated) fail(409, "conflict", "already activated");
      if (rest === "unlock/challenge") {
        const key = this.host.passkeys().find((k) => k.hex === body.credential);
        const want = `reg-${key?.hex.slice(0, 8)}-${this.wrap === "none" ? "create" : "test"}`;
        if (!key || this.wrap === "tested" || body.registration_id !== want || (this.wrap === "created" && key.id !== this.wrapCredential)) fail(409, "conflict", "the import moved on; reload the page");
        const attempt = b64url(randomBytes(32));
        const salt = b64url(createHash("sha256").update("salt:" + key!.id).digest());
        const rp = new URL(req.url).hostname;
        const canonical = { v: 3, object: "seal", suite: 1, action: "wrap-enroll", id: attempt, credential_id: key!.id, epoch: this.epoch, installation: this.installation, mk_version: 1, prf_salt: salt, rp_id: rp, registration_id: want, recipient: this.drillKey.pub, nonce: b64url(randomBytes(32)), issued_at: nowISO() };
        const text = plainCanonical(canonical);
        this.attempts.set(attempt, key!.id);
        return {
          canonical: text,
          attempt_id: attempt,
          publicKey: { rpId: rp, userVerification: "required", timeout: 120000, challenge: b64url(createHash("sha256").update(text, "utf8").digest()), allowCredentials: [{ id: key!.id, type: "public-key" }], extensions: { prf: { eval: { first: salt } } } },
        };
      }
      if (rest === "unlock/finish") {
        const cred = this.attempts.get(String(body.attempt_id));
        if (!cred || typeof body.enc !== "string" || typeof body.ciphertext !== "string") fail(400, "bad_request", "unknown attempt");
        this.attempts.clear();
        this.wrapCredential = cred!;
        this.wrap = this.wrap === "none" ? "created" : "tested";
        return { ok: true };
      }
      if (rest === "control/challenge") {
        if (body.action !== "activate" || this.wrap !== "tested") fail(409, "conflict", "the wrap has not been tested yet");
        const canonical = { v: 3, object: "seal-control", action: "activate", id: this.installation, epoch: this.epoch, manifest: this.manifest(), nonce: b64url(randomBytes(32)), issued_at: nowISO() };
        const text = plainCanonical(canonical);
        const c = this.host.issue(text, canonical, session);
        return { challenge_id: c.id, canonical: text, public_key: this.host.requestOptions(req, c.challenge) };
      }
      if (rest === "control/finish") {
        const c = this.host.redeem(body.challenge_id, body.assertion, session);
        if (c.object !== "seal-control") fail(403, "forbidden", "challenge is for a different object");
        if (!this.drilled) fail(409, "conflict", "prove the recovery key first");
        this.activatedSeal();
        return { ok: true };
      }
      if (rest === "drill") {
        let identity: Uint8Array;
        try {
          const info = Buffer.concat([Buffer.from("aqmas-seal-drill-v1\0"), Buffer.from(this.installation, "base64url")]);
          identity = await openPacket(this.drillKey, info, String(body.packet ?? ""));
        } catch {
          return fail(400, "bad_request", "the recovery key packet could not be opened; reload the page and try again");
        }
        let ok = false;
        try {
          const text = new TextDecoder().decode(identity);
          const { publicKey } = await recipientOf(text.trim());
          ok = text.endsWith("\n") && Buffer.from(bech32Decode(this.recipient).data).equals(Buffer.from(publicKey));
        } catch {
          ok = false;
        }
        identity.fill(0);
        if (!ok) fail(409, "conflict", "this is not the recovery key for the public key you gave: nothing was changed");
        this.drilled = true;
        return { ok: true };
      }
      return undefined;
    }
    return undefined;
  }

  private cutover() {
    const plan = mockPlan(this.host.passkeys().map((k) => k.hex));
    return { id: "org-personal", plan, recovery_sha256: sha256hex("recovery:" + plan) };
  }

  /** GET /mock/setup?…: jump to a state (development only). */
  jump(q: URLSearchParams): Record<string, unknown> {
    const flag = (k: string) => (q.has(k) ? q.get(k) === "1" : undefined);
    this.stop();
    this.current = null;
    this.installed = flag("installed") ?? this.installed;
    this.scoped = flag("scoped") ?? this.scoped;
    this.sealed = flag("sealed") ?? this.sealed;
    this.updatesReady = flag("updates") ?? this.updatesReady;
    if (flag("pinned") === false) this.pins = [];
    if (flag("pinned") === true) this.pins = null;
    const mode = q.get("mode");
    if (mode === "serve" || mode === "cutover" || mode === "seal-setup") {
      this.mode = mode;
      if (mode !== "serve") {
        const task = mode === "cutover" ? "cutover" : "seal";
        this.begin(task, "Start the broker for your review (agents are refused)");
        this.wait(mode === "cutover" ? "your review and activation of the plan" : "the passkey wrap, the recovery key check and your activation", 15);
        if (mode === "seal-setup") this.scoped = true;
      }
    }
    const wrap = q.get("wrap");
    if (wrap === "none" || wrap === "created" || wrap === "tested") {
      this.wrap = wrap;
      this.wrapCredential = wrap === "none" ? "" : (this.host.passkeys()[0]?.id ?? "");
    }
    this.drilled = flag("drilled") ?? this.drilled;
    return { mode: this.mode, installed: this.installed, scoped: this.scoped, sealed: this.sealed, updates: this.updatesReady, wrap: this.wrap, drilled: this.drilled };
  }
}
