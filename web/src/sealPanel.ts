import { type Api } from './api';
import { h,replace } from './dom';
import { encode,decode } from './b64url';
import { prepareSeal,type Selection,type SealBegin } from './seal';
import { type Authenticator,decodeRequestOptions,encodeAssertion,unwrapPublicKey } from './webauthn';
import { visibleText } from './format';

export interface SealView { mode:'unsealed'|'setup'|'activated'|'locked'|'unlocked'; installation:string; epoch:string; choices:{id:string;name:string;selection:Selection}[]; manifest?:string }
type Control = {challenge_id:string;canonical:string;public_key:unknown};
export async function prepareControl(v:SealView,action:'activate'|'lock',b:Control,rp:string) {
  const c=JSON.parse(b.canonical);
  const expected:Record<string,unknown>={action,epoch:v.epoch,id:v.installation,issued_at:c.issued_at,nonce:c.nonce,object:'seal-control',v:3};
  if(action==='activate') {if(v.mode!=='setup'||!v.manifest)throw Error('No reviewed manifest');expected.manifest=v.manifest;}
  if(action==='lock'&&v.mode!=='unlocked')throw Error('Already locked');
  if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(c.issued_at)||decode(c.nonce).byteLength!==32||encode(decode(c.nonce))!==c.nonce||JSON.stringify(expected,Object.keys(expected).sort())!==b.canonical)throw Error('Seal control canonical differs from review');
  const o=unwrapPublicKey(b.public_key);
  if(o.rpId!==rp||o.userVerification!=='required'||o.extensions!==undefined||!Array.isArray(o.allowCredentials)||!o.allowCredentials.length||encode(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.canonical)))!==o.challenge)throw Error('Seal control options mismatch');
  return decodeRequestOptions(o);
}

export function sealPanel(api:Api,auth:Authenticator,v:SealView,refresh:()=>void) {
  const root=h('article',{class:'card'}), controls=h('div'), review=h('div',{role:'status'});
  const button=(s:string,f:()=>Promise<void>)=>h('button',{type:'button',class:'btn',on:{click:async ev=>{const btn=ev.currentTarget as HTMLButtonElement;btn.disabled=true;try{await f()}catch(e){replace(review,h('p',{class:'error'},visibleText((e as Error).message)))}finally{btn.disabled=false}}}},s);
  function confirm(title:string,detail:string,apply:()=>Promise<void>){replace(review,h('h3',null,title),h('pre',null,visibleText(detail)),button(title+' with passkey',async()=>{await apply();replace(review,'Applied.');refresh()}))}
  if(v.mode==='locked'||v.mode==='setup')for(const key of v.choices){controls.append(button(visibleText(key.name)+' — review',async()=>{
    const b=await api.sealPost!<SealBegin>('unlock/challenge',{credential:key.id,registration_id:key.selection.registration_id});
    const p=await prepareSeal(key.selection,b,location.hostname);
    const title=v.mode==='locked'?'Unlock broker':key.selection.registration_id?.endsWith('-test')?'Test wrap independently':'Create unlock wrap';
    confirm(title,p.canonical,async()=>{await api.sealPost!('unlock/finish',await p.finish(auth))});
  }))}
  if(v.mode==='unlocked'||v.mode==='setup'&&v.manifest){const action=v.mode==='unlocked'?'lock':'activate';const label=action==='lock'?'Lock now':'Activate sealed installation';controls.append(button(label+'…',async()=>{
    const b=await api.sealPost!<Control>('control/challenge',{action});const opts=await prepareControl(v,action,b,location.hostname);
    // The complete bound manifest (all roles, pins, credential and ciphertext digests) stays visible through signing.
    const detail=action==='lock'?b.canonical:JSON.stringify(JSON.parse(JSON.parse(b.canonical).manifest),null,2)+'\nCompare SHA-256 with the local operator view: '+Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v.manifest!))),x=>x.toString(16).padStart(2,'0')).join('');
    confirm(label,detail,async()=>{await api.sealPost!('control/finish',{challenge_id:b.challenge_id,assertion:encodeAssertion(await auth.get(opts))})});
  }))}
  root.append(h('h2',null,v.mode==='locked'?'Locked — unlock broker':v.mode==='setup'?'Supervised seal import':v.mode==='unlocked'?'Broker unlocked':'Sealed installation activated'),h('p',null,v.mode==='setup'?'Fleet access is paused. Test a passkey twice and verify the offline recovery copy before signing.':v.mode==='locked'?'You can inspect the queue, deny requests and revoke access. Unlocking resumes existing authority.':'Restart interrupts issuance. An unlock passkey is needed after every update.'),controls,review);return root;
}
