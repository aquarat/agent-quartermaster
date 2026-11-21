// bun run build: web/index.html + src -> web/dist (hashed assets, no inline scripts/styles).
import { rm, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const root = import.meta.dir;
const outdir = join(root, "dist");
await rm(outdir, { recursive: true, force: true });

const result = await Bun.build({
  entrypoints: [join(root, "index.html")],
  outdir,
  minify: true,
  sourcemap: "none",
  target: "browser",
  publicPath: "/",
  naming: { entry: "[name].[ext]", chunk: "[name]-[hash].[ext]", asset: "[name]-[hash].[ext]" },
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
const recovery=await Bun.build({entrypoints:[join(root,'recovery/index.html')],outdir:join(outdir,'private'),minify:true,sourcemap:'none',target:'browser',publicPath:'/',naming:{entry:'[name].[ext]',chunk:'[name]-[hash].[ext]'}});if(!recovery.success)throw Error('Failed to build recovery-only entry');

// The server sends CSP default-src 'self': fail the build if anything inline slipped in.
const html = await readFile(join(outdir, "index.html"), "utf8");
const problems: string[] = [];
for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  if (!/\bsrc=/.test(m[1]!) || m[2]!.trim()) problems.push("inline <script>");
}
if (/<style\b/i.test(html)) problems.push("inline <style>");
if (/\son[a-z]+\s*=/i.test(html)) problems.push("inline event handler");
if (/\sstyle\s*=/i.test(html)) problems.push("style attribute");
if (/(src|href)=["']?(https?:)?\/\//i.test(html)) problems.push("external URL");
if (problems.length) {
  console.error(`dist/index.html violates CSP rules: ${problems.join(", ")}`);
  process.exit(1);
}
const files = await readdir(outdir);
console.log(`built ${files.length} files into web/dist: ${files.join(", ")}`);
