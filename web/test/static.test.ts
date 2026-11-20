// Guards: no HTML-parsing sinks in the UI source; built page obeys the CSP; mock sends it.
import { describe, expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { startMock } from "../mock/server";

const src = join(import.meta.dir, "..", "src");

describe("source guards", () => {
  test("no innerHTML/outerHTML/insertAdjacentHTML/document.write/eval in src", async () => {
    for (const f of await readdir(src)) {
      if (!f.endsWith(".ts")) continue;
      const text = await readFile(join(src, f), "utf8");
      const code = text.replace(/\/\/.*$/gm, "");
      for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "createContextualFragment", "DOMParser"]) {
        expect({ file: f, sink, found: code.includes(sink) }).toEqual({ file: f, sink, found: false });
      }
    }
  });
});

describe("built page", () => {
  test("bun run build output has no inline script/style and is served with the CSP", async () => {
    const proc = Bun.spawnSync(["bun", "build.ts"], { cwd: join(import.meta.dir, "..") });
    expect(proc.exitCode).toBe(0);
    const dist = join(import.meta.dir, "..", "dist");
    const html = await readFile(join(dist, "index.html"), "utf8");
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
    expect(html).not.toMatch(/<style/i);
    expect(html).not.toMatch(/\son[a-z]+=/i);
    const js = (await readdir(dist)).find((f) => /^index-[a-z0-9]+\.js$/.test(f));
    expect(js).toBeDefined();
    const m = startMock({ port: 0, distDir: dist });
    try {
      const r = await fetch(m.url + "/");
      expect(r.status).toBe(200);
      expect(r.headers.get("content-security-policy")).toContain("default-src 'self'");
      expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
      const a = await fetch(m.url + "/" + js);
      expect(a.status).toBe(200);
      expect((await fetch(m.url + "/../package.json")).status).toBe(404);
    } finally {
      m.stop();
    }
  });
});
