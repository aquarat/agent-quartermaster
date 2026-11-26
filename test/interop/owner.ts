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
// Seal format 2 (docs/BUCKETS.md), through web/src/{setup,sealPanel,capabilities,recoveryPanel}.ts:
//   stage                         every staging tap of the active passkey (open-legacy, create, test)
//   seal-drill FILE               the on-box recovery drill of a stage (identity sealed to the broker)
//   seal-activate | close-all | rekey SCOPE | repair-leaf   signed seal control actions
//   reopen                        reopen every bucket that has paused users (prints the taps)
//   buckets [--json] | open-buckets   bucket status; the open buckets as "kind:label ..."
//   recovery-drill FILE           Security → Recovery key drill with the identity in FILE
//   create-scope TITLE            create an organisation's scope key (signed-in passkey)
//   capability ACTION NAME [CAP]  register|enable|test|disable a passkey's scope keys
//                                 (OWNER_NO_PRF=1 register …: the new passkey has no PRF)
//   remember NAME [LABEL]         Remember this browser for NAME, a passkey without PRF (docs/BUCKETS.md
//                                 §13): the signed-in passkey approves, NAME enrols and tests
//   forget NAME                   Forget this browser for NAME (signed by the signed-in passkey)
//   browser-key                   print this "browser profile"'s key fingerprint ("" when it has none)
//   window SECONDS COUNT MARKER   open a personal approval window, approve COUNT SSH requests
//                                 under it, keep it open while MARKER exists, then close it
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
  /** The last setup task or upgrade this helper approved: SHA-256(canonical), first 16 hex. */
  ranId?: string;
  active?: string;
  cookie?: string;
  /** This helper's "browser profile" key (docs/BUCKETS.md §13). A browser keeps it in IndexedDB
   * as a non-extractable CryptoKey, which no file can hold: TEST ONLY, the state file keeps a
   * JWK and every run imports it non-extractable, so the page code sees what a browser gives it. */
  browser?: { privateJwk: JsonWebKey; publicJwk: JsonWebKey };
}
const saved: Saved = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")) : {};
const keys: Record<string, SavedAuthenticator> = saved.keys ?? {};
let active = saved.active ?? "";
let ranId = saved.ranId ?? "";
const requestId = async (canonical: string) => Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))).toString("hex").slice(0, 16);
let cookie = saved.cookie ?? "";
let profileKey = saved.browser;

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
  writeFileSync(stateFile, JSON.stringify({ keys, active, cookie, ranId, ...(profileKey ? { browser: profileKey } : {}) } satisfies Saved), { mode: 0o600 });
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

// Remembered browsers: every tap of this helper can take the page's own browser-key path
// (web/src/buckets.ts browserPath), exactly as the app wires it at start.
const browserKey = await import(`${web}/src/browserKey.ts`);
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const browserKeys = new browserKey.BrowserKeys(
  {
    async load() {
      if (!profileKey) return undefined;
      return { privateKey: await crypto.subtle.importKey("jwk", profileKey.privateJwk, ECDH, false, ["deriveBits"]), publicKey: await crypto.subtle.importKey("jwk", profileKey.publicJwk, ECDH, true, []) };
    },
    async save(): Promise<CryptoKeyPair> {
      throw new Error("the helper's profile key is made by newProfileKey()");
    },
    async clear() {
      profileKey = undefined;
    },
  },
  async () => true,
);
async function newProfileKey() {
  const pair = (await crypto.subtle.generateKey(ECDH, true, ["deriveBits"])) as CryptoKeyPair;
  profileKey = { privateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey), publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}
{
  const { browserPath } = await import(`${web}/src/buckets.ts`);
  browserPath.keys = browserKeys;
  browserPath.release = (body: unknown) => api.sealPost("browser/release", body);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const rp = new URL(origin).hostname;
/** A seal control action (Security → Buckets, Setup activation) exactly as the page signs it. */
async function control(action: string, params: Record<string, unknown> = {}) {
  const c = await (await import(`${web}/src/sealPanel.ts`)).beginControl(api, await api.sealStatus(), action as never, params, rp);
  console.error(`owner: signing seal ${action}${action === "activate" ? "" : " " + c.detail}${c.lines.length ? " · " + c.lines.join(" ") : ""}`);
  await c.finish(auth);
}
const [cmd, ...args] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'recover':{const [dir,pin]=args;const post=async(path:string,token:string,body:unknown)=>{const res=await fetch('http://localhost/recovery/'+path,{unix:`${dir}/broker.sock`,method:'POST',headers:{'X-Aqmas-Recovery':token,'X-Aqmas':'1','Content-Type':'application/json',origin},body:JSON.stringify(body)});if(!res.ok)throw Error('recovery '+path+': '+res.status);return res.json()};const fresh=await softAuthenticator(origin);let step=await (await import(`${web}/src/recovery.ts`)).recoverSteps(post,readFileSync(dir+'/ticket','utf8'),'Replacement',pin,new URL(origin).hostname);while(step)step=await step.apply(fresh);auth=fresh;active='Replacement';cookie='';break;}
    case 'repair-leaf': await control('renew-leaf');break;
    case 'env-ticket':{const cat=await api.catalogue();const host=cat.organisations.find((o:any)=>o.slug==='client-a').hosts.find((h:any)=>h.active&&h.class==='owner-device');console.log((await api.envPost('ticket',{path:'client-a/paas/staging',operation:args[0],enrollment:host.enrollment})).ticket);break}
    case 'env-decide':{const [action,mode,standing]=args; // approve|deny|revoke|commit MODE [STANDING-SECONDS]: "don't ask again" rides an approval
      for(let n=0;;n++){const state=await api.envState();const item=action==='commit'?state.drafts[0]:state.releases.find((r:any)=>r.mode===mode&&r.status===(action==='revoke'?'approved':'pending'));if(item){const env=await import(`${web}/src/envsets.ts`);if(standing&&!env.standingChoices(state.standing_caps?.[item.set]??0).includes(Number(standing)))throw Error('the card does not offer that duration');const review=await env.envReview(api,await api.sealStatus(),item,action,action==='approve'?300:0,new URL(origin).hostname,Number(standing??0));await review.tap(auth);break}if(n>=150)throw Error('no env decision queued');await Bun.sleep(100)}break}
    case 'env-state': console.log(JSON.stringify(await api.envState()));break;
    case 'env-standing-revoke':{const env=await import(`${web}/src/envsets.ts`);const st=(await api.envState()).standing?.[0];if(!st)throw Error('no rule to revoke');await (await env.envStandingRevoke(api,await api.sealStatus(),st,new URL(origin).hostname)).tap(auth);break}
    case 'vault-secret': { // ORG/SERVICE/SLUG ENVNAME VALUEFILE [NOTE] [URL]: Add item → Secret, the value sealed in this process
      const vault=await import(`${web}/src/vault.ts`);const [path,name,file,note,url]=args;const [o,sv,slug]=path!.split('/');
      const cat=await api.catalogue();const org=cat.organisations.find((x:any)=>x.slug===o),service=org.services.find((x:any)=>x.slug===sv);
      const parent={org_id:org.id,org_slug:org.slug,org_title:org.title,service_id:service.id,service_slug:service.slug,service_title:service.title};
      const p=await vault.vaultSecretCreate(api,await api.sealStatus(),parent,{id:vault.newSetId(),slug,title:slug},name,readFileSync(file!,'utf8'),note??'',url??'',new URL(origin).hostname);
      console.log(JSON.stringify(await p.tap(auth)));break;}
    case 'vault-standing-cap': { // PATH SECONDS: the item's "longest don't ask again"
      const vault=await import(`${web}/src/vault.ts`);const [path,seconds]=args;
      const set=(await api.vaultState()).sets.find((s:any)=>`${s.org_slug}/${s.service_slug}/${s.set_slug}`===path);if(!set)throw Error('no set '+path);
      await (await vault.vaultStandingCap(api,await api.sealStatus(),set,Number(seconds),new URL(origin).hostname)).tap(auth);break;}
    case 'vault-state': console.log(JSON.stringify(await api.vaultState()));break;
    case 'vault-commit': { // PATH merge|import ENVFILE [REMOVE...]: the write-only form, values sealed in this process
      const vault=await import(`${web}/src/vault.ts`);const [path,operation,file,...remove]=args;
      const set=(await api.vaultState()).sets.find((s:any)=>`${s.org_slug}/${s.service_slug}/${s.set_slug}`===path);if(!set)throw Error('no set '+path);
      const p=await vault.vaultCommit(api,await api.sealStatus(),set,{operation,entries:vault.parseDotenv(readFileSync(file!,'utf8')),remove},new URL(origin).hostname);await p.tap(auth);console.log(p.changes);break;}
    case 'vault-reveal': { // PATH NAME...: prints the decrypted entries as JSON (the caller keeps them out of scanned files)
      const vault=await import(`${web}/src/vault.ts`);const [path,...names]=args;
      const set=(await api.vaultState()).sets.find((s:any)=>`${s.org_slug}/${s.service_slug}/${s.set_slug}`===path);if(!set)throw Error('no set '+path);
      const p=await vault.vaultReveal(api,await api.sealStatus(),set,names.sort(),new URL(origin).hostname);console.log(JSON.stringify(await p.tap(auth)));break;}
    case 'vault-policy': { // ORG on|off
      const vault=await import(`${web}/src/vault.ts`);const org=(await api.vaultState()).organisations.find((o:any)=>o.slug===args[0]);
      const p=await vault.vaultPolicy(api,await api.sealStatus(),org,args[1]==='on',new URL(origin).hostname);await p.tap(auth);break;}
    case 'vault-signer': { // ORG/SERVICE/SLUG SCHEME generate|import [KEYFILE]: prints the created signer as JSON
      const vault=await import(`${web}/src/vault.ts`);const [path,scheme,source,file]=args;const [o,sv,slug]=path!.split('/');
      const cat=await api.catalogue();const org=cat.organisations.find((x:any)=>x.slug===o),service=org.services.find((x:any)=>x.slug===sv);
      const parent={org_id:org.id,org_slug:org.slug,org_title:org.title,service_id:service.id,service_slug:service.slug,service_title:service.title};
      const p=await vault.vaultSignerCreate(api,await api.sealStatus(),parent,{id:vault.newSetId(),slug,title:slug},scheme,source,file?readFileSync(file,'utf8'):undefined,new URL(origin).hostname);
      const made=await p.tap(auth);if(made.public_key!==p.publicKey)throw Error('created another key than the one reviewed');console.log(JSON.stringify(made));break;}
    case 'vault-sign': { // approve|deny|revoke [TTL MAX]: the oldest matching signing request, exactly as the card signs it
      const vault=await import(`${web}/src/vault.ts`);const [verb,ttl,max]=args;
      for(let n=0;;n++){const st=await api.vaultState();const req=st.requests.find((r:any)=>r.status===(verb==='revoke'?'approved':'pending'));
        if(req){const set=st.sets.find((s:any)=>s.set_id===req.set);const single=verb==='approve'&&ttl===undefined;
          // An SSH key hand-out is one delivery (0, 1); SSH logins are always a time-boxed grant.
          const one=req.use==='ssh-handout'?1:req.items.length;
          const p=await vault.vaultSignDecision(api,await api.sealStatus(),set,req,'sign-'+verb,verb==='approve'?(single?0:Number(ttl)):0,verb==='approve'?(single?one:Number(max)):0,new URL(origin).hostname);await p.tap(auth);break}
        if(n>=150)throw Error('no signing request queued');await Bun.sleep(100)}break;}
    case 'vault-ssh-key': { // ORG/SERVICE/SLUG TYPE generate|import [KEYFILE|-] [handout]: Add item → SSH key; prints the created key as JSON
      const vault=await import(`${web}/src/vault.ts`);const [path,scheme,source,file,handout]=args;const [o,sv,slug]=path!.split('/');
      const cat=await api.catalogue();const org=cat.organisations.find((x:any)=>x.slug===o),service=org.services.find((x:any)=>x.slug===sv);
      const parent={org_id:org.id,org_slug:org.slug,org_title:org.title,service_id:service.id,service_slug:service.slug,service_title:service.title};
      const p=await vault.vaultSshKeyCreate(api,await api.sealStatus(),parent,{id:vault.newSetId(),slug,title:slug},{scheme,source,privateKey:source==='import'?readFileSync(file!,'utf8'):undefined,comment:vault.sshDefaultComment(o,sv,slug),handout:handout==='handout'},new URL(origin).hostname);
      const made=await p.tap(auth);if(made.authorized_key!==p.authorizedKey||made.fingerprint!==p.fingerprint)throw Error('created another key than the one reviewed');console.log(JSON.stringify(made));break;}
    case 'vault-ssh-handout': { // PATH on|off: the key's "May be handed out" setting
      const vault=await import(`${web}/src/vault.ts`);const [path,to]=args;
      const set=(await api.vaultState()).sets.find((s:any)=>`${s.org_slug}/${s.service_slug}/${s.set_slug}`===path);if(!set)throw Error('no set '+path);
      await (await vault.vaultSshHandout(api,await api.sealStatus(),set,to==='on',new URL(origin).hostname)).tap(auth);break;}
    case 'vault-delete': { // PATH: Delete on the item page; prints what the delete ended
      const vault=await import(`${web}/src/vault.ts`);const [path]=args;
      const set=(await api.vaultState()).sets.find((s:any)=>`${s.org_slug}/${s.service_slug}/${s.set_slug}`===path);if(!set)throw Error('no set '+path);
      console.log(JSON.stringify(await (await vault.vaultDelete(api,await api.sealStatus(),set,new URL(origin).hostname)).tap(auth)));break;}
    case 'vault-restore': case 'vault-purge': { // PATH: Vault → Deleted → Restore / Purge now (the newest binned item with that path)
      const vault=await import(`${web}/src/vault.ts`);const [path]=args;
      const item=((await api.vaultState()).deleted??[]).filter((s:any)=>`${s.org_slug}/${s.service_slug}/${s.set_slug}`===path).sort((a:any,b:any)=>b.deleted_at-a.deleted_at)[0];if(!item)throw Error('nothing in the bin named '+path);
      await (await (cmd==='vault-restore'?vault.vaultRestore:vault.vaultPurge)(api,await api.sealStatus(),item,new URL(origin).hostname)).tap(auth);break;}
    case 'batch': {const state=await api.state(),v=await api.sealStatus();const sel=args.map(id=>({item:state.pending.find((p:any)=>p.id===id),action:'approve',ttl_seconds:300}));const b=await (await import(`${web}/src/approvals.ts`)).batchReview(api,v,sel,new URL(origin).hostname);await b.tap(auth);break;}
    case 'seal-status': console.log((await api.sealStatus()).mode);break;
    // ---- Settings → Setup (docs/SETUP.md), through the web UI's own setup module ----
    case 'setup': console.log(JSON.stringify(await api.setupGet!('')));break;
    case 'setup-state': {const v:any=await api.setupGet!('');const t=v.tasks.find((t:any)=>t.id===args[0]);console.log(t.state+(t.blocked_by?': '+t.blocked_by:''));break;}
    case 'setup-wait': {
      // The broker restarts during tasks: connection errors and a dropped session are expected.
      // "done"/"failed" are read from the finished run itself: the card's own state can say
      // "blocked: unlock first" when a sealed broker has just restarted.
      const [task,want,seconds]=args;let last='';
      for(let n=0;n<Number(seconds??60)*5;n++){
        try{const v:any=await api.setupGet!('');const t=v.tasks.find((t:any)=>t.id===task);last=t.state+' '+(t.last?.step??'')+' '+(t.last?.message??'');
          const mine=t.last?.request===ranId; // the run this helper's own approval started
          const finished=!v.current&&mine&&t.last?.state===want;
          if(want==='done'&&!v.current&&mine&&t.last?.state==='failed')throw Object.assign(Error(`setup task ${task} failed: ${t.last.message}`),{fatal:true});
          const live=(want==='waiting'||want==='running')&&t.state===want;
          if(live||finished){console.log(JSON.stringify(t.last??{}));last='';break}}catch(e){if((e as {fatal?:boolean}).fatal)throw e;last=String((e as Error).message)}
        await sleep(200);
      }
      if(last)throw Error(`setup task ${task} did not reach ${want}: ${last}`);break;
    }
    case 'setup-run': {
      const [task,params,secrets]=args;const setup=await import(`${web}/src/setup.ts`);const v:any=await api.setupGet!('');
      let p=JSON.parse(params??'{}');
      if(task==='sync-passkeys')p={pins:v.passkeys.map((k:any)=>({id:k.credential,key_sha256:k.key_sha256}))};
      const prepared=await setup.prepareSetupTask(api,v,task!,p,secrets?JSON.parse(secrets):undefined,new URL(origin).hostname);
      console.error('owner: signing '+prepared.canonicalText);
      await setup.completeSetupTask(api,auth,prepared);ranId=await requestId(prepared.canonicalText);break;
    }
    case 'setup-cancel': await api.setupPost!('/cancel',{});break;
    case 'updates': console.log(JSON.stringify(await api.updates()));break;
    case 'approve-update': { // "Upgrade aqmas": the update approval, exactly as the card builds it
      const v=await api.updates(),c=v.candidate,f=c.github??{};if(v.error||!c.version)throw Error('no verified update: '+v.error);
      const p=await flows.prepareAction(api,{object:'update',id:c.commit,facts:{from_version:v.current,from_commit:v.commit,to_version:c.version,to_commit:c.commit,daemon_sha256:f['aqmasd-linux-arm64']!,linux_arm64_sha256:f['aqmas-linux-arm64']!,linux_amd64_sha256:f['aqmas-linux-amd64']!,darwin_arm64_sha256:f['aqmas-darwin-arm64']!}},{action:'approve'});
      await flows.completeAction(api,auth,p);ranId=await requestId(p.canonicalText);console.log(c.version);break;
    }
    case 'setup-preview': console.log(JSON.stringify(await api.setupGet!('/cutover/preview')));break;
    case 'setup-host-key': console.log(JSON.stringify(await api.setupPost!('/host-key',{repo:args[0]})));break;
    case 'age-keygen': {const k=await (await import(`${web}/src/setup.ts`)).generateAgeIdentity();writeFileSync(args[0]!,k.identity+'\n',{mode:0o600});console.log(k.recipient);break;}
    case 'seal-drill': {const v=await api.sealStatus();await (await import(`${web}/src/setup.ts`)).sendDrill(api,{drill_key:v.stage?.drill_key,installation:v.installation},readFileSync(args[0]!,'utf8'));break;}
    // ---- seal format 2 (docs/BUCKETS.md): staging, control, passkeys, recovery ----
    case 'stage': { // every staging tap the active passkey can make: open-legacy, create, test (two scopes per tap)
      const setup=await import(`${web}/src/setup.ts`);let taps=0;
      for(;;){const v=await api.sealStatus();if(v.mode!=='setup'||!v.stage)throw Error('nothing is staged: '+v.mode);
        const plan=setup.stagePlan(v.stage);if(!plan.next)break;
        const choice=v.stage.choices.find((c:any)=>c.name===active);if(!choice)throw Error('no staging choice for '+active);
        const step=await setup.stageStep(api,v,plan.next.step,choice,plan.next.scopes,rp);console.error(`owner: staging ${plan.next.step} ${plan.next.scopes.join(',')}: ${step.lines.join(' ')}`);
        await step.finish(auth);if(++taps>12)throw Error('staging does not converge');}
      console.log(taps);break;
    }
    case 'seal-activate': await control('activate');break;
    case 'close-all': await control('close-all');break;
    case 'rekey': await control('rekey',{scope:args[0]});break;
    case 'reopen': { // every bucket with paused users, at most two scopes per tap; prints the number of taps
      let taps=0;for(;;){const v=await api.sealStatus();const paused=(v.buckets??[]).filter((b:any)=>b.paused.length&&!b.open);if(!paused.length)break;
        const scopes=[...new Set(paused.map((b:any)=>b.scope))].slice(0,2);const ids=paused.filter((b:any)=>scopes.includes(b.scope)).map((b:any)=>b.id).sort();
        await control('reopen',{buckets:ids});if(++taps>8)throw Error('reopen does not converge');}
      console.log(taps);break;
    }
    case 'buckets': { // [--json] which buckets are open, with their holds and paused users
      const v=await api.sealStatus();
      if(args[0]==='--json'){console.log(JSON.stringify(v));break;}
      console.log(JSON.stringify((v.buckets??[]).map((b:any)=>({kind:b.kind,label:b.label,scope:b.scope,open:b.open,holds:b.holds.map((h:any)=>h.kind).sort(),paused:b.paused.length}))));break;
    }
    case 'open-buckets': { // "kind:label kind:label" of the open buckets, sorted ("" when nothing is open)
      const v=await api.sealStatus();console.log((v.buckets??[]).filter((b:any)=>b.open).map((b:any)=>`${b.kind}:${b.label}`).sort().join(' '));break;
    }
    case 'open-kinds': { // the kinds of the open buckets, sorted, unique, space-separated
      const v=await api.sealStatus();console.log([...new Set((v.buckets??[]).filter((b:any)=>b.open).map((b:any)=>b.kind))].sort().join(' '));break;
    }
    case 'recovery-drill': { // IDENTITY-FILE: Security → Recovery key drill; prints {ok,scopes,buckets}
      const v=await api.sealStatus();const r=await (await import(`${web}/src/recoveryPanel.ts`)).beginRecovery(api,v,{mode:'drill'},readFileSync(args[0]!,'utf8'),rp);
      console.log(JSON.stringify(await r.finish(auth)));break;
    }
    case 'create-scope': { // TITLE: Security → Buckets "Create": the signed-in passkey creates an organisation's scope key
      const v=await api.sealStatus();const sc=(v.scopes??[]).find((x:any)=>x.title===args[0]||x.scope===args[0]);if(!sc)throw Error('no scope '+args[0]);
      const me=(await api.state()).passkeys.find((k:any)=>k.current);
      // Enable (two taps), then the test tap that lets the broker write into the new scope.
      let step=await (await import(`${web}/src/capabilities.ts`)).startCapability(api,v,{action:'enable',capability:'unlock',nickname:me.nickname,credential_id:me.raw_id,scopes:[sc.scope]},rp,0,{thenTest:true});
      for(let n=0;step;n++){if(n>4)throw Error('create does not converge');step=(await step.tap(auth)) as any;}
      break;
    }
    case 'capability': { // register|enable|test|disable NAME [unlock|approve-only]
      const [action,name,capability]=args;const v=await api.sealStatus();
      const key=action==='register'?null:await findPasskey(name!);const pk=key?(v.passkeys??[]).find((p:any)=>p.id===key.id):null;
      const keyed=(v.scopes??[]).filter((s:any)=>s.has_key).map((s:any)=>s.scope);
      // A passkey that opens only from remembered browsers is tested with this profile's key.
      const local=pk?.mode==='browser'&&action==='test'?await browserKeys.current():undefined;
      const here=local?(pk.browsers??[]).find((b:any)=>b.id===local.id):undefined;
      if(pk?.mode==='browser'&&action==='test'&&!here)throw Error('this helper\'s browser is not remembered for '+name);
      const scopes=action==='register'?(capability==='approve-only'?[]:keyed):action==='enable'?pk.missing:(here??pk).scopes.map((s:any)=>s.scope);
      const caps=await import(`${web}/src/capabilities.ts`);
      let step=await caps.startCapability(api,v,{action,nickname:name,credential_id:key?.raw_id??'',capability:capability??(action==='disable'?'approve-only':'unlock'),scopes,...(local?{browser_key:local.public}:{})},rp);
      // The signed-in passkey approves each round; the passkey being enabled (or tested) answers the rest.
      let device:any=action==='register'?await softAuthenticator(origin,undefined,{prf:process.env.OWNER_NO_PRF!=='1'}):name===active?auth:await softAuthenticator(origin,keys[name!]);
      for(let n=0;step;n++){if(n>12)throw Error('capability flow does not converge');const mine=/signed-in passkey/.test(step.progress??'')||(action==='disable');
        console.error(`owner: ${step.title} · ${step.progress??''}`);step=(await step.tap(mine?auth:device)) as any;}
      if(device!==auth&&action!=='disable')keys[name!]=await device.save();
      break;
    }
    case 'browser-key': console.log((await browserKeys.current())?.id??'');break;
    case 'remember': { // NAME [LABEL]: the offer the page makes when NAME returns no PRF result, accepted
      const [name,label]=args;const v=await api.sealStatus();const key=await findPasskey(name!);const pk=(v.passkeys??[]).find((p:any)=>p.id===key.id);
      const caps=await import(`${web}/src/capabilities.ts`);
      if(!profileKey)await newProfileKey();
      const ctx={keys:browserKeys,local:await browserKeys.current()};
      const keyed=(v.scopes??[]).filter((s:any)=>s.has_key).map((s:any)=>s.scope);const done=caps.browserTested(pk,ctx.local);
      const offer=caps.rememberOffer(api,v,{nickname:name!,credential_id:key.raw_id,scopes:keyed.filter((s:string)=>!done.includes(s))},rp,ctx,'interop',{skip:done});
      console.error(`owner: ${offer.title}`);
      let step:any=await offer.offer!.accept(label??'Interop browser');
      const device:any=name===active?auth:await softAuthenticator(origin,keys[name!]);
      for(let n=0;step;n++){if(n>12)throw Error('remember does not converge');const mine=/signed-in passkey/.test(step.progress??'');
        console.error(`owner: ${step.title} · ${step.progress??''} · signing ${step.detail}`);step=await step.tap(mine?auth:device);}
      if(device!==auth)keys[name!]=await device.save();
      break;
    }
    case 'forget': { // NAME: Forget this helper's browser for NAME
      const v=await api.sealStatus();const key=await findPasskey(args[0]!);const pk=(v.passkeys??[]).find((p:any)=>p.id===key.id);
      const local=await browserKeys.current();const here=local?(pk.browsers??[]).find((b:any)=>b.id===local.id):undefined;
      if(!here)throw Error('this helper\'s browser is not remembered for '+args[0]);
      const step=await (await import(`${web}/src/capabilities.ts`)).startCapability(api,v,{action:'forget',capability:'unlock',nickname:args[0],credential_id:key.raw_id,scopes:[],browser_key:here.key},rp);
      console.error(`owner: ${step.title} · signing ${step.detail}`);await step.tap(auth);
      // As the page: the profile's key goes when no other passkey is remembered for it.
      if(!((await api.sealStatus()).passkeys??[]).some((p:any)=>(p.browsers??[]).some((b:any)=>b.id===local!.id)))await browserKeys.forget();
      break;
    }
    case 'window': { // SECONDS COUNT MARKER: open a personal approval window, approve COUNT SSH requests under it, close it
      const [secs,count,marker]=args;(globalThis as any).window??=globalThis;
      const ap=await import(`${web}/src/approvals.ts`);const {checkReview,checkTap}=await import(`${web}/src/review.ts`);const {encodeAssertion}=await import(`${web}/src/webauthn.ts`);
      let v=await api.sealStatus();let p=(v.profiles??[]).find((x:any)=>x.personal);if(!p)throw Error('no personal window profile');
      const settings={enabled:true,max_seconds:Math.max(Number(secs),p.settings.max_seconds),idle_seconds:p.settings.idle_seconds,sets:[...new Set(p.eligible.filter((r:any)=>r.kind==='ssh-ca').map((r:any)=>r.set))].sort()};
      const pb=await api.sealPost!<any>('windows/policy/challenge',{org:p.org,settings});
      const popts=await checkReview(pb,{object:'window-policy',action:'replace',v:3,id:p.org,installation:v.installation,epoch:v.epoch,old:JSON.stringify(p),new:JSON.stringify(settings)},rp);
      await api.sealPost!('windows/policy/finish',{challenge_id:pb.challenge_id,assertion:encodeAssertion(await auth.get(popts))});
      v=await api.sealStatus();p=(v.profiles??[]).find((x:any)=>x.personal);if(!v.verified_access)throw Error('windows need a verified Access identity');
      const me=(await api.state()).passkeys.find((k:any)=>k.current);const op=await ap.makeOpening(p,me.raw_id,Number(secs));
      const b=await api.sealPost!<any>('windows/open/challenge',op.input);const id=JSON.parse(b.canonical).id;
      const tap=await checkTap(b,{object:'window',action:'open',v:3,id,installation:v.installation,epoch:v.epoch,terms:op.terms(id)},rp,{selected:me.raw_id});
      console.error('owner: window opens: '+tap.lines.join(' '));
      const tab=new ap.TabWindow();tab.start(api,op,await api.sealPost!<any>('windows/open/finish',{challenge_id:b.challenge_id,...(await tap.sign(auth))}),id,v.installation);
      await persist();writeFileSync(marker!,'open\n');
      try{for(let done=0;done<Number(count);){const st=await api.state();const it=(st.pending??[]).find((x:any)=>x.kind==='ssh');
          if(!it){await sleep(200);continue}
          const prep=await tab.prepare({item:it,action:'approve',ttl_seconds:Math.min(300,it.ttl_requested)});await prep.confirm();done++;writeFileSync(marker!,`approved ${done}\n`);}
        // Held open until the caller removes the marker (it checks the buckets meanwhile).
        for(let n=0;existsSync(marker!)&&n<600;n++)await sleep(200);
      }finally{tab.end();await sleep(500);}
      break;
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
      if (it.kind === "bastion") {
        // The page offers no standing choice for the bastion; asking the server anyway must fail.
        const c: Record<string, unknown> = { action: cmd };
        if (cmd === "approve") c.ttl_seconds = choice.ttl_seconds;
        if (standing) c.standing_hours = Number(standing);
        const p = await flows.prepareAction(api, flows.targetForPending(await api.request(id!)), c);
        console.error("owner: signing " + p.canonicalText);
        console.log(JSON.stringify(await flows.completeAction(api, auth, p)));
        break;
      }
      const p = await flows.prepareAction(api, flows.targetForPending(it), choice);
      console.error("owner: signing " + p.canonicalText);
      const out = await flows.completeAction(api, auth, p);
      console.log(JSON.stringify(out));
      break;
    }
    case "approve-root": { // ID TTL close|keep: the red card, with the signed choice about open buckets
      const [id, ttl, close] = args;
      const it = await api.request(id!);
      const p = await flows.prepareAction(api, flows.targetForPending(it), { action: "approve", ttl_seconds: Number(ttl), ...(it.bastion?.sealed ? { closeBuckets: close === "close" } : {}) });
      console.error("owner: signing " + p.canonicalText);
      console.log(JSON.stringify(await flows.completeAction(api, auth, p)));
      break;
    }
    case "approve-task": { // ID: a maintenance task an agent queued, approved through the Setup flow
      const it = await findPending(args[0]!);
      const setup = await import(`${web}/src/setup.ts`);
      await setup.runSetupTask(api, auth, await api.setupGet!(""), it.setup.task, setup.queuedParams(it.setup.task, it.setup.params), undefined, rp, it.id);
      break;
    }
    case "bastion":
      console.log(JSON.stringify(await api.bastion()));
      break;
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
