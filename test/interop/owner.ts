// Owner helper for the interop test (test/interop/run.sh): plays the owner in the approval UI
// against a running aqmasd, using the web UI's own API and flow code (web/src/api.ts,
// web/src/flows.ts: the same pre-signing canonical checks the browser runs) and the software
// passkey from softauthn.ts. Each invocation is one command; the passkey and the session cookie
// persist in a JSON state file between invocations.
//
//   AQMAS_WEB_DIR=<repo>/web AQMAS_BASE=http://127.0.0.1:<web port> \
//   AQMAS_ORIGIN=<public_base_url> OWNER_STATE=<file> bun test/interop/owner.ts <command>
//
// Commands:
//   register CODE                 register the first passkey with an enroll code, then sign in
//   login                         sign in again with the saved passkey
//   session                       print GET /api/ui/session
//   state                         print GET /api/ui/state
//   wait KIND [HOST] [SECONDS]    wait for a pending item (ssh|enrollment), print its id
//   item KIND ID                  print one item (GET /api/ui/requests|enrollments/{id})
//   approve ID [TTL [STANDING_H]] approve a pending request (TTL seconds) or enrollment
//   deny ID                       deny a pending request or enrollment
//   revoke-grant ID               revoke an active grant
//   canonical                     with approve/deny: also print the signed canonical text (stderr)

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { softAuthenticator, type SavedAuthenticator } from "./softauthn.ts";

const web = must("AQMAS_WEB_DIR");
const base = must("AQMAS_BASE");
const origin = must("AQMAS_ORIGIN");
const stateFile = must("OWNER_STATE");

function must(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`owner: ${name} is not set`);
    process.exit(2);
  }
  return v;
}

const { createApi } = await import(`${web}/src/api.ts`);
const flows = await import(`${web}/src/flows.ts`);

interface Saved {
  passkey?: SavedAuthenticator;
  cookie?: string;
}
const saved: Saved = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")) : {};
let cookie = saved.cookie ?? "";

// The session cookie is Secure; this helper talks plain HTTP to 127.0.0.1 exactly like
// cloudflared does, so the jar is kept by hand.
const jar = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const h = new Headers(init?.headers);
  if (cookie) h.set("cookie", cookie);
  // The server checks a present Origin against public_base_url, as a browser would send it.
  if ((init?.method ?? "GET") === "POST") h.set("origin", origin);
  const res = await fetch(input, { ...init, headers: h });
  const sc = res.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0]!;
  return res;
}) as typeof fetch;
const api = createApi({ base, fetch: jar });
const auth = await softAuthenticator(origin, saved.passkey);

async function persist() {
  const out: Saved = { cookie };
  try {
    out.passkey = await auth.save();
  } catch {
    out.passkey = saved.passkey;
  }
  writeFileSync(stateFile, JSON.stringify(out), { mode: 0o600 });
}

async function findPending(id: string) {
  const s = await api.state();
  const it = (s.pending ?? []).find((p: { id: string }) => p.id === id);
  if (!it) throw new Error(`no pending item ${id}`);
  return it;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const [cmd, ...args] = process.argv.slice(2);
try {
  switch (cmd) {
    case "register": {
      await flows.completeRegistration(api, auth, await flows.prepareRegistrationWithCode(api, args[0] ?? ""));
      await persist();
      cookie = "";
      await flows.completeLogin(api, auth, await flows.prepareLogin(api));
      console.log("registered and signed in");
      break;
    }
    case "login": {
      cookie = "";
      await flows.completeLogin(api, auth, await flows.prepareLogin(api));
      console.log("signed in");
      break;
    }
    case "session": {
      const r = await fetch(`${base}/api/ui/session`, { headers: cookie ? { cookie } : {} });
      console.log(JSON.stringify(await r.json()));
      break;
    }
    case "state":
      console.log(JSON.stringify(await api.state()));
      break;
    case "wait": {
      const [kind, host, secs] = args;
      const deadline = Date.now() + Number(secs ?? 30) * 1000;
      for (;;) {
        const s = await api.state();
        const it = (s.pending ?? []).find(
          (p: { kind: string; requesting_host: string }) => p.kind === kind && (!host || p.requesting_host === host),
        );
        if (it) {
          console.log(it.id);
          break;
        }
        if (Date.now() > deadline) throw new Error(`no pending ${kind} item within ${secs ?? 30}s`);
        await sleep(200);
      }
      break;
    }
    case "item": {
      const [kind, id] = args;
      const path = kind === "enrollment" ? "enrollments" : "requests";
      const r = await jar(`${base}/api/ui/${path}/${encodeURIComponent(id!)}`);
      console.log(JSON.stringify(await r.json()));
      break;
    }
    case "approve":
    case "deny": {
      const [id, ttl, standing] = args;
      const it = await findPending(id!);
      const choice: { action: "approve" | "deny"; ttl_seconds?: number; standing_hours?: number } = { action: cmd };
      if (cmd === "approve" && it.kind !== "enrollment") {
        choice.ttl_seconds = Number(ttl ?? it.ttl_max);
        if (standing) choice.standing_hours = Number(standing);
      }
      const p = await flows.prepareAction(api, flows.targetForPending(it), choice);
      console.error("owner: signing " + p.canonicalText);
      const out = await flows.completeAction(api, auth, p);
      console.log(JSON.stringify(out));
      break;
    }
    case "revoke-grant": {
      const s = await api.state();
      const g = (s.grants ?? []).find((x: { id: string }) => x.id === args[0]);
      if (!g) throw new Error(`no active grant ${args[0]}`);
      const p = await flows.prepareAction(api, flows.targetForGrant(g), { action: "revoke" });
      console.error("owner: signing " + p.canonicalText);
      console.log(JSON.stringify(await flows.completeAction(api, auth, p)));
      break;
    }
    default:
      console.error("owner: unknown command " + cmd);
      process.exit(2);
  }
  await persist();
} catch (e) {
  await persist();
  const err = e as { name?: string; message?: string; status?: number; code?: string };
  console.error(`owner: ${cmd}: ${err.name ?? "Error"} ${err.status ?? ""} ${err.code ?? ""} ${err.message ?? String(e)}`);
  process.exit(1);
}
