// Regenerate public RFC 9180 wire fixtures using @hpke/core. These are
// synthetic recipient secrets, never keys from a broker or authenticator.
import {Aes128Gcm,CipherSuite,DhkemP256HkdfSha256,HkdfSha256} from '@hpke/core';
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
const buf=(n:number)=>Buffer.alloc(32,n), hex=(b:ArrayBuffer)=>Buffer.from(b).toString('hex');
const frame=(...parts:Buffer[])=>Buffer.concat(parts.flatMap(b=>{const n=Buffer.alloc(4);n.writeUInt32BE(b.length);return [n,b]}));
const ctx=(role:string,...fields:Buffer[])=>frame(Buffer.from('aqmas-seal'),Buffer.from('0000000000000001','hex'),Buffer.from(role),...fields);
const vectors=[];
for(const purpose of ['unlock','wrap-enroll']) {
  const pair=await suite.kem.generateKeyPair();
  const info=ctx('hpke-finish',buf(1),Buffer.from(purpose)),aad=ctx('hpke-aad',buf(2),buf(3),buf(4));
  const plain=frame(buf(5),Buffer.from('test assertion'));
  const sender=await suite.createSenderContext({recipientPublicKey:pair.publicKey,info});
  vectors.push({purpose,info:info.toString('hex'),aad:aad.toString('hex'),pub:hex(await suite.kem.serializePublicKey(pair.publicKey)),priv:hex(await suite.kem.serializePrivateKey(pair.privateKey)),enc:hex(sender.enc),ciphertext:hex(await sender.seal(plain,aad))});
}
await Bun.write(new URL('../../../test/vectors/hpke.json',import.meta.url),JSON.stringify(vectors,null,2)+'\n');
