import { test, expect } from "bun:test";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { encode } from "../src/b64url";
import { prepareSeal,wrapKeyBytes } from "../src/seal";
import vector from '../../test/vectors/suite1.json';
import { decodeCreationOptions, encodeAttestation, type Authenticator } from "../src/webauthn";
import { softAuthenticator } from "../../test/interop/softauthn";

test('browser KEK opens the libsodium mk-wrap vector in Go', async()=>{
  const id=(n:number)=>new Uint8Array(32).fill(n);
  const derive=async(salt:number)=>Buffer.from(await wrapKeyBytes(id(6),id(1),'example.test',new Uint8Array([255,1]),7,id(salt))).toString('hex');
  expect(await derive(2)).toBe(vector.kek);expect(await derive(3)).not.toBe(vector.kek);
});

test("PRF is used only for the selected credential; only HPKE ciphertext leaves the page", async () => {
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const recipient = await suite.kem.generateKeyPair();
  const rp = "example.test", auth = await softAuthenticator(`https://${rp}`);
  const random = () => encode(crypto.getRandomValues(new Uint8Array(32)));
  const create = decodeCreationOptions({rp:{name:"test",id:rp},user:{id:random(),name:"owner"},challenge:random(),pubKeyCredParams:[{type:"public-key",alg:-7}]});
  create.extensions = {prf:{},credProps:true};
  const key = await (auth as Authenticator).create(create);
  expect(encodeAttestation({...key,getClientExtensionResults:()=>({prf:{results:{first:"SENTINEL"}},credProps:{rk:true,extra:"SENTINEL"}})}).clientExtensionResults).toEqual({credProps:{rk:true}});
  const sel = {action:"unlock" as const,credential_id:key.id,epoch:random(),installation:random(),mk_version:1,prf_salt:random(),rp_id:rp};
  const canonical = {...sel,v:3,object:"seal",suite:1,issued_at:"2026-01-01T00:00:00Z",nonce:random(),id:random(),recipient:encode(await suite.kem.serializePublicKey(recipient.publicKey))};
  const text = JSON.stringify(canonical,Object.keys(canonical).sort());
  const opts = { rpId:rp,userVerification:"required",allowCredentials:[{id:key.id,type:"public-key"}], challenge:encode(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(text))),extensions:{prf:{eval:{first:sel.prf_salt}}} };
  const b = {canonical:text,attempt_id:canonical.id, publicKey:opts};
  for(const bad of [{...sel,epoch:random()},{...sel,prf_salt:random()},{...sel,action:"wrap-enroll" as const}]) await expect(prepareSeal(bad,b,rp)).rejects.toThrow();
  for(const mod of [{userVerification:"preferred"},{allowCredentials:[]},{challenge:random()},{extensions:{prf:{eval:{first:random()}}}}]) await expect(prepareSeal(sel,{...b,publicKey:{...opts,...mod}},rp)).rejects.toThrow();
  const prepared = await prepareSeal(sel,b,rp);
  const finish = await prepared.finish(auth as Authenticator);
  expect(Object.keys(finish).sort()).toEqual(["attempt_id","ciphertext","enc"]);
  await expect(prepared.finish(auth as Authenticator)).rejects.toThrow();
});
