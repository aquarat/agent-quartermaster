// Preloaded into the owner helper (bun --preload) by test/interop/run-migrate.sh: sends the
// Cloudflare Access token from fakeaccess on every request, as cloudflared would forward it.
// It patches fetch so the v0.4.1 helper, which knows nothing of Access, works unchanged.
const token = process.env.AQMAS_ACCESS_JWT;
if (token) {
  const real = globalThis.fetch;
  globalThis.fetch = Object.assign(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const h = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      h.set("Cf-Access-Jwt-Assertion", token);
      return real(input, { ...init, headers: h });
    },
    { preconnect: real.preconnect },
  ) as typeof fetch;
}
