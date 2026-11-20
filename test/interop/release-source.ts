// Loopback release API, including GitHub's authenticated asset API shape.
const [port,version,file]=process.argv.slice(2);
Bun.serve({hostname:'127.0.0.1',port:Number(port), fetch(req){
  const u=new URL(req.url);
  const uuid='00000000-0000-0000-0000-000000000001';
  if(u.pathname.endsWith(`/releases/tags/v${version}`))return Response.json({tag_name:`v${version}`,assets:[{name:'SHA256SUMS',id:1,uuid}]});
  if(['/releases/assets/1',`/attachments/${uuid}`].includes(u.pathname))return new Response(Bun.file(file));
  return new Response('',{status:404});
}});
