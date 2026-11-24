// Loopback release API, including GitHub's authenticated asset API shape. Serves SHA256SUMS
// and, when they exist beside it, SHA256SUMS.extra and the binaries both list.
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
const [port,version,file]=process.argv.slice(2);
// SHA256SUMS.extra and the build it lists (macOS x86-64) are served only where they exist.
const names=['SHA256SUMS','aqmas-darwin-arm64','aqmas-linux-amd64','aqmas-linux-arm64','SHA256SUMS.extra','aqmas-darwin-amd64'];
const uuid=(i:number)=>`00000000-0000-0000-0000-00000000000${i+1}`;
const path=(n:string)=>n==='SHA256SUMS'?file!:join(dirname(file!),n);
Bun.serve({hostname:'127.0.0.1',port:Number(port), fetch(req){
  const u=new URL(req.url);
  if(u.pathname.endsWith(`/releases/tags/v${version}`))return Response.json({tag_name:`v${version}`,assets:names.filter(n=>existsSync(path(n))).map(n=>({name:n,id:names.indexOf(n)+1,uuid:uuid(names.indexOf(n))}))});
  for(const [i,n] of names.entries())if(u.pathname.endsWith(`/releases/assets/${i+1}`)||u.pathname===`/attachments/${uuid(i)}`)return new Response(Bun.file(path(n)));
  return new Response('',{status:404});
}});
