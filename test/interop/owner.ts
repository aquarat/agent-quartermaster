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
//   passkeys                      print the passkey list (state.passkeys) as JSON
//   add-passkey [NAME]            sign "passkey add" with the active passkey, create a new one
//                                 (named NAME, or by the server), print its nickname
//   rename-passkey NAME NEW       sign and apply a rename
//   remove-passkey NAME           sign and apply a remove; prints the PasskeyChange
//   use-passkey NAME              make NAME the active passkey (then `login`)
//
// Every signed action prints its canonical text on stderr ("owner: signing ...").

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
  /** Every passkey this helper holds, by nickname, and the one it signs with. */
  keys?: Record<string, SavedAuthenticator>;
  /** When the last setup task or upgrade was approved (setup-wait reads runs started after it). */
  ranAt?: number;
  active?: string;
  cookie?: string;
}
const saved: Saved = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")) : {};
const keys: Record<string, SavedAuthenticator> = saved.keys ?? {};
let active = saved.active ?? "";
let ranAt = saved.ranAt ?? 0;
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
let auth = await softAuthenticator(origin, active ? keys[active] : undefined);

async function persist() {
  try {
    if (active) keys[active] = await auth.save();
  } catch {
    // no credential yet
  }
  writeFileSync(stateFile, JSON.stringify({ keys, active, cookie, ranAt } satisfies Saved), { mode: 0o600 });
}

async function findPasskey(name: string) {
  const s = await api.state();
  const p = (s.passkeys ?? []).find((x: { nickname: string }) => x.nickname === name);
  if (!p) throw new Error(`no passkey named ${JSON.stringify(name)}`);
  return p;
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
    case 'recover':{const [dir,pin]=args;const post=async(path:string,token:string,body:unknown)=>{const res=await fetch('http://localhost/recovery/'+path,{unix:`${dir}/broker.sock`,method:'POST',headers:{'X-Aqmas-Recovery':token,'X-Aqmas':'1','Content-Type':'application/json',origin},body:JSON.stringify(body)});if(!res.ok)throw Error('recovery '+path+': '+res.status);return res.json()};const fresh=await softAuthenticator(origin);let step=await (await import(`${web}/src/recovery.ts`)).recoverSteps(post,readFileSync(dir+'/ticket','utf8'),'Replacement',pin,new URL(origin).hostname);while(step)step=await step.apply(fresh);auth=fresh;active='Replacement';cookie='';break;}
    case 'repair-leaf':{const v=await api.sealStatus();const b=await api.sealPost('control/challenge',{action:'renew-leaf'});const opts=await (await import(`${web}/src/sealPanel.ts`)).prepareControl(v,'renew-leaf',b,new URL(origin).hostname);const {encodeAssertion}=await import(`${web}/src/webauthn.ts`);await api.sealPost('control/finish',{challenge_id:b.challenge_id,assertion:encodeAssertion(await auth.get(opts))});break;}
    case 'env-ticket':{const cat=await api.catalogue();const host=cat.organisations.find((o:any)=>o.slug==='client-a').hosts.find((h:any)=>h.active&&h.class==='owner-device');console.log((await api.envPost('ticket',{path:'client-a/paas/staging',operation:args[0],enrollment:host.enrollment})).ticket);break}
    case 'env-decide':{const [action,mode]=args;for(let n=0;;n++){const state=await api.envState();const item=action==='commit'?state.drafts[0]:state.releases.find((r:any)=>r.mode===mode&&r.status===(action==='revoke'?'approved':'pending'));if(item){const review=await (await import(`${web}/src/envsets.ts`)).envReview(api,await api.sealStatus(),item,action,action==='approve'?300:0,new URL(origin).hostname);await review.tap(auth);break}if(n>=150)throw Error('no env decision queued');await Bun.sleep(100)}break}
    case 'batch': {const state=await api.state(),v=await api.sealStatus();const sel=args.map(id=>({item:state.pending.find((p:any)=>p.id===id),action:'approve',ttl_seconds:300}));const b=await (await import(`${web}/src/approvals.ts`)).batchReview(api,v,sel,new URL(origin).hostname);await b.tap(auth);break;}
    case 'seal-status': console.log((await api.sealStatus()).mode);break;
    // ---- Admin → Setup (docs/SETUP.md), through the web UI's own setup module ----
    case 'setup': console.log(JSON.stringify(await api.setupGet!('')));break;
    case 'setup-state': {const v:any=await api.setupGet!('');const t=v.tasks.find((t:any)=>t.id===args[0]);console.log(t.state+(t.blocked_by?': '+t.blocked_by:''));break;}
    case 'setup-wait': {
      // The broker restarts during tasks: connection errors and a dropped session are expected.
      // "done"/"failed" are read from the finished run itself: the card's own state can say
      // "blocked: unlock first" when a sealed broker has just restarted.
      const [task,want,seconds]=args;let last='';const since=Math.floor(ranAt/1000)*1000; // started_at has one-second resolution
      for(let n=0;n<Number(seconds??60)*5;n++){
        try{const v:any=await api.setupGet!('');const t=v.tasks.find((t:any)=>t.id===task);last=t.state+' '+(t.last?.step??'')+' '+(t.last?.message??'');
          const mine=Date.parse(t.last?.started_at??'')>=since;
          const finished=!v.current&&mine&&t.last?.state===want;
          const live=(want==='waiting'||want==='running')&&t.state===want;
          if(live||finished){console.log(JSON.stringify(t.last??{}));last='';break}}catch(e){last=String((e as Error).message)}
        await sleep(200);
      }
      if(last)throw Error(`setup task ${task} did not reach ${want}: ${last}`);break;
    }
    case 'setup-run': {
      const [task,params,secrets]=args;const setup=await import(`${web}/src/setup.ts`);const v:any=await api.setupGet!('');
      let p=JSON.parse(params??'{}');
      if(task==='sync-passkeys')p={pins:v.passkeys.map((k:any)=>({id:k.credential,key_sha256:k.key_sha256}))};
      const at=Date.now();await setup.runSetupTask(api,auth,v,task!,p,secrets?JSON.parse(secrets):undefined);ranAt=at;break;
    }
    case 'setup-cancel': await api.setupPost!('/cancel',{});break;
    case 'updates': console.log(JSON.stringify(await api.updates()));break;
    case 'approve-update': { // "Upgrade aqmas": the update approval, exactly as the card builds it
      const v=await api.updates(),c=v.candidate,f=c.forgejo??{};if(v.error||!c.version)throw Error('no verified update: '+v.error);
      const p=await flows.prepareAction(api,{object:'update',id:c.commit,facts:{from_version:v.current,from_commit:v.commit,to_version:c.version,to_commit:c.commit,daemon_sha256:f['aqmasd-linux-arm64']!,linux_arm64_sha256:f['aqmas-linux-arm64']!,linux_amd64_sha256:f['aqmas-linux-amd64']!,darwin_arm64_sha256:f['aqmas-darwin-arm64']!}},{action:'approve'});
      const at=Date.now();await flows.completeAction(api,auth,p);ranAt=at;console.log(c.version);break;
    }
    case 'setup-preview': console.log(JSON.stringify(await api.setupGet!('/cutover/preview')));break;
    case 'setup-host-key': console.log(JSON.stringify(await api.setupPost!('/host-key',{repo:args[0]})));break;
    case 'age-keygen': {const k=await (await import(`${web}/src/setup.ts`)).generateAgeIdentity();writeFileSync(args[0]!,k.identity+'\n',{mode:0o600});console.log(k.recipient);break;}
    case 'seal-drill': {const v=await api.sealStatus();await (await import(`${web}/src/setup.ts`)).sendDrill(api,v,readFileSync(args[0]!,'utf8'));break;}
    case 'capability': {
      const [action,name,capability]=args, v=await api.sealStatus(), key=action==='register'?null:await findPasskey(name!);
      const flow=await (await import(`${web}/src/capabilities.ts`)).startCapability(api,v,{action,nickname:name,credential_id:key?.raw_id??'',capability},new URL(origin).hostname);
      let step=await flow.approve(auth);const device=action==='register'?await softAuthenticator(origin):await softAuthenticator(origin,keys[name!]);
      while(step)step=await step.tap(device);if(action!=='disable')keys[name!]=await device.save();break;
    }
    case 'seal-eval': {
      const v=await api.sealStatus();const choice=v.choices.find((c:any)=>c.name===active);if(!choice)throw Error('no choice for active credential');
      const b=await api.sealPost('unlock/challenge',{credential:choice.id,registration_id:choice.selection.registration_id});
      const prepared=await (await import(`${web}/src/seal.ts`)).prepareSeal(choice.selection,b,new URL(origin).hostname);
      const packet=await prepared.finish(auth);await api.sealPost('unlock/finish',packet);
      let refused=false;try{await api.sealPost('unlock/finish',packet)}catch{refused=true}if(!refused)throw Error('replayed seal packet');break;
    }
    case 'seal-lock':case 'seal-activate': {
      const action=cmd==='seal-lock'?'lock':'activate',v=await api.sealStatus();const b=await api.sealPost('control/challenge',{action});
      const opts=await (await import(`${web}/src/sealPanel.ts`)).prepareControl(v,action,b,new URL(origin).hostname);
      const {encodeAssertion}=await import(`${web}/src/webauthn.ts`);
      await api.sealPost('control/finish',{challenge_id:b.challenge_id,assertion:encodeAssertion(await auth.get(opts))});break;
    }
    case 'catalogue':{const {exerciseCatalogue}=await import('./catalogue');await exerciseCatalogue(api,auth,args[0]??'create');break;}
    case 'activate-personal': {
      const m=await api.migration!(); if(!m)throw Error('no fenced cutover'); const p=await flows.prepareAction(api,{object:'migration',id:m.id,facts:{plan:m.plan,recovery_sha256:m.recovery_sha256}},{action:'activate'});
      await flows.completeAction(api,auth,p);await persist();break;
    }
    case "register": {
      const res = await flows.completeRegistration(api, auth, await flows.prepareRegistrationWithCode(api, args[0] ?? ""));
      active = (res as { passkey?: { nickname?: string } }).passkey?.nickname ?? "first";
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
      const choice: { action: "approve" | "deny"; ttl_seconds?: number; standing_hours?: number;indefinite?:boolean;standing_indefinite?:boolean } = { action: cmd };
      if (cmd === "approve" && it.kind !== "enrollment") {
        choice.ttl_seconds = ttl==='indefinite'?0:Number(ttl ?? it.ttl_max);choice.indefinite=ttl==='indefinite';
        if (standing==='indefinite')choice.standing_indefinite=true;else if(standing)choice.standing_hours=Number(standing);
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
    case "passkeys":
      console.log(JSON.stringify((await api.state()).passkeys ?? []));
      break;
    case "add-passkey": {
      // The nickname is part of the signed add action.
      const p = await flows.prepareAction(api, flows.PASSKEY_TARGET, { action: "add", nickname: args[0] ?? "" });
      console.error("owner: signing " + p.canonicalText);
      const reg = await flows.authorizeAddPasskey(api, auth, p);
      const fresh = await softAuthenticator(origin);
      const res = (await flows.completeRegistration(api, fresh, reg)) as { passkey?: { nickname?: string } };
      const name = res.passkey?.nickname;
      if (!name) throw new Error("register/finish returned no passkey nickname");
      keys[name] = await fresh.save();
      console.log(name);
      break;
    }
    case "rename-passkey": {
      const [from, to] = args;
      const pk = await findPasskey(from!);
      const p = await flows.prepareAction(api, flows.targetForPasskey(pk), { action: "rename", nickname: to });
      console.error("owner: signing " + p.canonicalText);
      const out = (await flows.completeAction(api, auth, p)) as { nickname: string };
      if (keys[from!]) {
        keys[out.nickname] = keys[from!]!;
        delete keys[from!];
        if (active === from) active = out.nickname;
      }
      console.log(JSON.stringify(out));
      break;
    }
    case "remove-passkey": {
      const pk = await findPasskey(args[0]!);
      const p = await flows.prepareAction(api, flows.targetForPasskey(pk), { action: "remove" });
      console.error("owner: signing " + p.canonicalText);
      const out = await flows.completeAction(api, auth, p);
      delete keys[args[0]!];
      if (active === args[0]) active = "";
      console.log(JSON.stringify(out));
      break;
    }
    case "use-passkey": {
      const name = args[0]!;
      if (!keys[name]) throw new Error(`this helper holds no passkey named ${JSON.stringify(name)}`);
      await persist(); // save the current one's counter first
      active = name;
      auth = await softAuthenticator(origin, keys[name]);
      console.log("using " + name);
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
