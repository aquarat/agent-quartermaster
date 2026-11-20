// Ordered wire schema of organisations.Plan. Objects have exactly these keys;
// '?' denotes Go omitempty; '[T]' is a list. Only declared lists/maps accept
// null (nil Go slices/maps). Render leaf values without interpreting markup.
type Shape = string | { [key:string]: Shape };
const named={id:'s',slug:'s',title:'s'};
const target={Aliases:'[s]',Name:'s',Address:'s',Port:'n',Users:'[s]',HostKey:'s',PrincipalOverride:'s',ForgejoUser:'s',MaxTTLSeconds:'n',HighRisk:'b'};
const ttl={OwnerMaxSeconds:'n',OwnerMaxStandingHours:'n',DefaultSeconds:'n',MaxSeconds:'n',MinSeconds:'n',PendingExpirySeconds:'n',EnrollmentExpirySeconds:'n',MaxStandingHours:'n'};
const cf={Enabled:'b',APIBase:'s',AllowInsecureAPIBase:'b',AccountID:'s',ProxyTokenCredential:'s',ProxyTokenFile:'s',MinterTokenCredential:'s',MinterTokenFile:'s',TokenIPCondition:'[s]',SnapshotDir:'s',SnapshotRetentionDays:'n',RatePerMinute:'n',WriteRatePerMinute:'n',MaxBodyBytes:'n',UploadMaxBodyBytes:'n',ProtectedAccessHostnames:'[s]',TraefikOrigin:'s',TraefikPlainOrigins:'[s]',ProtectedDNSNames:'[s]',EmailForwardAllow:'[s]',WorkerBindings:'[worker]',Zones:'[cfObj]',Tunnels:'[cfObj]',D1Databases:'[cfObj]',Scopes:'overrides'};
const defs: Record<string,Shape>={
 service:{...named,sets:'[set]'},set:{...named,kind:'s','ssh_target?':target},worker:{Script:'s',PagesProject:'s',Allow:'[s]'},cfObj:{Name:'s',ID:'s'},override:{Disabled:'b',MaxTTLSeconds:'n',DefaultTTL:'n',NoAutoApprove:'b',NoStanding:'b',NoTokenMode:'b',ExtraDeny:'[s]'},
 scope:{name:'s',title:'s',description:'s',params:'[param]',risk:'s',auto_approve:'b',standing_allowed:'b',modes:'[s]',default_ttl_seconds:'n',max_ttl_seconds:'n'},param:{key:'s',required:'b','values?':'[s]'},
 host:{host_id:'n',enrollment_id:'s',certificate_sha256:'s',name:'s',class:'s',not_after_ms:'n'},out:{grant_id:'s',host_id:'n',kind:'s',not_after_ms:'n','child_id?':'s'},
};
const plan={source_schema:'n',organisation:named,owner_approver:named,owner_webauthn_id_hex:'s',owner_passkeys:'[s]',ssh_ca_fingerprint:'s',tls_ca_pin:'s',approval_origin:'s',legacy_ttl_policy:ttl,services:'[service]','cloudflare_public_config?':cf,'effective_cf_scopes?':'[scope]','disabled_token_templates?':'[s]',public_config_sha256:'s',admit_to_personal_only:'[host]',retire:{expire_requests:'[s]',expire_enrollments:'[s]',revoke_grants:'[s]',revoke_standing:'[s]',outstanding_certificates_and_unverified_children:'[out]',preserve_grant_high_water:'n',expire_challenges:'s',legacy_history:'s'}};

export function planRows(text:string,id:string):Array<[string,string]>{
 if(new TextEncoder().encode(text).length>131072)throw Error('oversize cutover plan');const p=JSON.parse(text);if(p.source_schema!==5||p.organisation?.id!==id||p.organisation?.slug!=='personal')throw Error('unexpected cutover');
 const rows:Array<[string,string]>=[];function walk(v:unknown,shape:Shape,path:string){const bad=()=>{throw Error(`unrecognised migration field at ${path}`)};
  if(typeof shape==='string'){
    if(shape==='overrides'){if(v===null)return;if(!v||typeof v!=='object'||Array.isArray(v))return bad();const keys=Object.keys(v);if(keys.join()!==keys.slice().sort().join())return bad();for(const k of keys){if(!/^cf\.[a-z0-9.-]+$/.test(k))return bad();walk((v as Record<string,unknown>)[k],defs.override!,`${path}.${k}`)}return}
    if(shape.startsWith('[')){if(v===null||Array.isArray(v)&&v.length===0){rows.push([path,'none']);return};if(!Array.isArray(v))return bad();v.forEach((e,i)=>walk(e,shape.slice(1,-1),`${path} ${i+1}`));return}
    if(Object.hasOwn(defs,shape)){walk(v,defs[shape]!,path);return}
    if(!(shape==='s' && typeof v==='string'||shape==='n' && Number.isSafeInteger(v)||shape==='b' && typeof v==='boolean'))return bad();rows.push([path,String(v)]);return;
  }
  if(v===null||typeof v!=='object'||Array.isArray(v))return bad();const fields=Object.keys(shape).filter(k=>!k.endsWith('?')||Object.hasOwn(v,k.slice(0,-1)));if(JSON.stringify(fields.map(k=>k.replace(/\?$/,'')))!==JSON.stringify(Object.keys(v)))return bad();for(const key of fields){const k=key.replace(/\?$/,'');walk((v as Record<string,unknown>)[k],shape[key]!,path?`${path} › ${k}`:k)}
 }
 walk(p,plan,'');const encoded=JSON.stringify(p).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));if(text!==encoded)throw Error('noncanonical migration plan');return rows;
}
