# aqmas milestone 2: Cloudflare access through aqmasd

Status (2026-11-20): contract. Wire types: `internal/api/cloudflare.go`; agent and web API:
`docs/API.md` section 5; catalogue metadata: `internal/server/cfscope/catalogue.go`. Evidence and
owner decisions: branch `research/cloudflare`, `the research notes`
(cited below as "research"; section 9 = design decisions 1-11).

Goal: the account-wide Cloudflare API token leaves the hosts where agents can read it,
and lives only on the bastion (.60) inside aqmasd. Agents get **time-boxed area grants** (the
research shows bursty project-day use: per-call approval would get in the way) and use them
through aqmasd's **proxy**, which checks every call against the grant's scope, injects the
parent token, enforces the owner's Cloudflare rules (guard rails) and snapshots objects before
writing them. Tools that cannot use the proxy get a **minted child token** (fallback).

Threat model (owner): almost every agent session is trustworthy; aqmas contains one compromised
session or service on one host. So: reads are cheap (auto-approved), writes are scoped and
time-boxed, nothing an agent holds is a long-lived Cloudflare secret, and every write leaves an
audit row, a push notification and a revertable snapshot.

## 1. Model

- A request of kind `cloudflare` names a **scope** from the built-in catalogue (section 2),
  its **parameters** (zone, tunnel, script, ...) and a **mode**:
  - `proxy` (default, design decision 1): no secret is returned. The host calls
    `https://<bastion>:8443/cf/client/v4/<cloudflare path>` with its mTLS client certificate and
    `X-Aqmas-Grant: <grant id>[,<id>...]`. Revoking the grant stops it at once.
  - `token` (fallback): aqmasd mints a child API token limited by a fixed per-scope template,
    the grant's expiry and the static egress IP condition, and returns its value **once**.
- Scope names and their parameter keys are **built into the code** (Go: `cfscope`; web:
  `web/src/cfscopes.ts`) so the approval page can always describe what it signs. aqmasd's config
  may only narrow scopes (section 6).
- Parameters naming zones, tunnels and D1 databases use **names configured in aqmasd**
  (`[[cloudflare.zones]]` etc.); aqmasd maps them to ids. An unconfigured zone/tunnel/database
  can only be reached with `cf.admin` (that is how a second tunnel is handled: it is simply not configured).
- **Approval** works as in M1 (passkey per decision; the canonical text now carries
  `scope`, `scope_params`, `mode`, `ip_condition`; API.md 5.4). `cf.read` and `cf.cache.purge`
  in proxy mode are **auto-approved** (design decision 2). "Approve similar for N hours" (standing
  approvals) exists per scope, proxy mode only, matching host + address + scope + exact
  scope_params. Never for `cf.admin` or `cf.read.private`, never for token mode.
- A proxy grant is usable only from the **address the request came from** (as M1 binds SSH
  certificates with `source-address`).

## 2. Scope catalogue

Risk L/M/H/A = low/medium/high/admin. TTLs: default / max. "Token": child-token template
(permission group names; `acct` = account resources, `zone` = the zone parameter's zone).
Every write scope also includes the GETs of the objects it writes, so one grant is enough.

| Scope | Params | Risk | Auto | Standing | TTL | Token |
|---|---|---|---|---|---|---|
| `cf.read` | – | L | yes | yes | 8h / 8h | – |
| `cf.read.private` | – | H | never | never | 1h / 2h | – |
| `cf.dns.edit` | `zone`, `name`? | H | no | yes | 2h / 8h | zone: DNS Write, Zone Read |
| `cf.tunnel.config` | `tunnel` | H | no | yes | 2h / 8h | – |
| `cf.access.apps` | – | H | no | yes | 2h / 8h | – |
| `cf.access.policies` | – | H | no | yes | 2h / 8h | – |
| `cf.access.idp-org` | – | H | no | no | 1h / 2h | – |
| `cf.rulesets` | `zone`, `phase`? | H | no | yes | 2h / 8h | – |
| `cf.zone-settings` | `zone` | M | no | yes | 1h / 8h | – |
| `cf.cache.purge` | `zone` | L | yes | yes | 1h / 8h | zone: Cache Purge, Zone Read |
| `cf.workers.deploy` | `script`, `zone`? | M | no | yes | 2h / 8h | acct: Workers Scripts Write, Account Settings Read; zone: Workers Routes Write, Zone Read |
| `cf.pages` | `project` | M | no | yes | 2h / 8h | acct: Pages Write, Account Settings Read |
| `cf.d1` | `db`, `access`=read\|migrate | M | no | yes | 1h / 8h | acct: D1 Read or D1 Write, Account Settings Read |
| `cf.r2.admin` | – | M | no | yes | 1h / 8h | – |
| `cf.r2.objects` | `bucket`, `access`=read\|write | M | no | yes | 1h / 8h | acct: Workers R2 Storage Read or Write |
| `cf.email` | `zone` | M | no | yes | 1h / 8h | – |
| `cf.admin` | – | A | never | never | 1h / 1h | – |

Deferred (not in M2): `cf.token.ci:{repo}` (design decision 5: CI deploy tokens stay in Forgejo
secrets for now); `cf.access.service-tokens` (the response carries `client_secret`; rare, done
by the owner in the dashboard; the proxy denies service-token creation, section 3).

### 2.1 Route tables

Paths are below `/client/v4`. Placeholders:

| Placeholder | Accepts | Bound to |
|---|---|---|
| `{acct}` | the configured `account_id` only | always |
| `{zone}` | 32 lowercase hex, a configured zone | the `zone` param's id when the scope has one |
| `{tunnel}` | UUID, a configured tunnel | the `tunnel` param's id when the scope has one |
| `{db}` | UUID, a configured D1 database | the `db` param's id |
| `{script}` | `[a-z0-9][a-z0-9_-]{0,62}` | the `script` param |
| `{project}` | `[a-z0-9][a-z0-9-]{0,57}` | the `project` param |
| `{bucket}` | R2 bucket name | the `bucket` param |
| `{phase}` | one of `cfscope.AllowedPhases` | the `phase` param when set |
| `{id}` | `[A-Za-z0-9_-]{1,64}` | – |
| `{name}` | `[A-Za-z0-9_.-]{1,128}` | – |
| `{key...}` | the rest of the path, ≥ 1 segment, percent-encoding allowed (R2 object keys) | – |

`cf.admin` accepts any well-formed id for `{zone}`/`{tunnel}`/`{db}` (configured or not) but
still only the configured `{acct}`.

Annotations: **S:type** = snapshot type (section 4.2), **G:name** = guard rails (section 4),
**U** = upload (streamed, `upload_max_body_bytes`), **J** = JWT passthrough (the client's
`Authorization: Bearer <upload JWT>` is forwarded and the parent token is NOT injected; the JWT
came from an upload-session call the same scope allowed).

**`cf.read`** (GET only):
```
/accounts/{acct}
/accounts/{acct}/cfd_tunnel                       /accounts/{acct}/cfd_tunnel/{tunnel}
/accounts/{acct}/cfd_tunnel/{tunnel}/configurations   /accounts/{acct}/cfd_tunnel/{tunnel}/connections
/accounts/{acct}/access/apps   /accounts/{acct}/access/apps/{id}   /accounts/{acct}/access/apps/{id}/policies
/accounts/{acct}/access/policies   /accounts/{acct}/access/policies/{id}
/accounts/{acct}/access/groups     /accounts/{acct}/access/groups/{id}
/accounts/{acct}/access/organizations   /accounts/{acct}/access/service_tokens
/zones   /zones/{zone}
/zones/{zone}/dns_records   /zones/{zone}/dns_records/{id}   /zones/{zone}/dns_records/export
/zones/{zone}/rulesets   /zones/{zone}/rulesets/{id}   /zones/{zone}/rulesets/phases/{phase*}/entrypoint
/zones/{zone}/settings   /zones/{zone}/settings/{name}
/zones/{zone}/workers/routes   /zones/{zone}/pagerules   /zones/{zone}/bot_management   /zones/{zone}/managed_headers
/zones/{zone}/email/routing   /zones/{zone}/email/routing/rules   /zones/{zone}/email/routing/rules/catch_all
/accounts/{acct}/workers/scripts   /accounts/{acct}/workers/domains   /accounts/{acct}/workers/subdomain
/accounts/{acct}/workers/account-settings   /accounts/{acct}/workers/scripts/{script*}/versions
/accounts/{acct}/workers/scripts/{script*}/deployments
/accounts/{acct}/pages/projects   /accounts/{acct}/pages/projects/{project*}/deployments
/accounts/{acct}/pages/projects/{project*}/deployments/{id}   …/deployments/{id}/history/logs
/accounts/{acct}/pages/projects/{project*}/domains
/accounts/{acct}/r2/buckets   /accounts/{acct}/r2/buckets/{bucket*}
/accounts/{acct}/d1/database   /accounts/{acct}/d1/database/{db}
/accounts/{acct}/challenges/widgets                     (list only)
```
(`{phase*}` here: any phase name `[a-z_]{1,64}`, read-only; `{script*}`/`{project*}`/`{bucket*}`:
any well-formed name, cf.read has no parameters.)

**`cf.read.private`** (GET): `/accounts/{acct}/access/logs/access_requests`,
`/accounts/{acct}/access/users[/{id}[/active_sessions|/last_seen_identity]]`,
`/accounts/{acct}/access/identity_providers[/{id}]`,
`/accounts/{acct}/email/routing/addresses[/{id}]`, `/accounts/{acct}/pages/projects/{project*}`,
`/accounts/{acct}/workers/scripts/{script*}/settings`, `/accounts/{acct}/audit_logs`.

**`cf.dns.edit`** (zone, name?): GET `/zones/{zone}`, `/zones/{zone}/dns_records[/{id}]`;
`POST /zones/{zone}/dns_records` (S:dns-name, G:dns); `PUT|PATCH|DELETE
/zones/{zone}/dns_records/{id}` (S:dns-record, G:dns). With `name`, every record written (body
for POST/PUT/PATCH, before-snapshot for PUT/PATCH/DELETE) must match the glob
(`*.example.com` matches one or more labels below `example.com`, not `example.com` itself).

**`cf.tunnel.config`** (tunnel): GET `/accounts/{acct}/cfd_tunnel/{tunnel}`,
`…/{tunnel}/configurations`; `PUT /accounts/{acct}/cfd_tunnel/{tunnel}/configurations`
(S:tunnel-config, G:tunnel).

**`cf.access.apps`**: GET apps, app, app policies, policies, groups (as cf.read);
`POST /accounts/{acct}/access/apps` (S:access-app, G:access-app); `PUT|DELETE
/accounts/{acct}/access/apps/{id}` (S:access-app, G:access-app); `PATCH …/apps/{id}` (G:access-patch,
always refused with a hint); `POST /accounts/{acct}/access/apps/{id}/policies`, `PUT|DELETE
…/apps/{id}/policies/{id}` (app-scoped legacy policies; S:access-app).

**`cf.access.policies`**: GET policies, policy, groups, group, apps; `POST
/accounts/{acct}/access/policies`, `PUT|DELETE …/policies/{id}` (S:access-policy, G:access-policy);
`POST /accounts/{acct}/access/groups`, `PUT|DELETE …/groups/{id}` (S:access-group, G:access-policy).

**`cf.access.idp-org`**: GET/POST `/accounts/{acct}/access/identity_providers`, GET/PUT/DELETE
`…/identity_providers/{id}` (S:access-idp, G:idp); GET/PUT `/accounts/{acct}/access/organizations`
(S:access-org).

**`cf.rulesets`** (zone, phase?): GET `/zones/{zone}/rulesets[/{id}]`,
`…/rulesets/phases/{phase}/entrypoint`; `PUT /zones/{zone}/rulesets/phases/{phase}/entrypoint`
(S:ruleset-entrypoint, G:ruleset); `POST /zones/{zone}/rulesets/{id}/rules`, `PATCH|DELETE
…/rulesets/{id}/rules/{id}` (S:ruleset, G:ruleset: the ruleset's `phase`, read from the
before-snapshot, must be allowed and equal the `phase` param when set).

**`cf.zone-settings`** (zone): GET settings; `PATCH /zones/{zone}/settings/{name}` and `PATCH
/zones/{zone}/settings` (bulk `{"items":[…]}`) (S:zone-setting, G:zone-settings).

**`cf.cache.purge`** (zone): `POST /zones/{zone}/purge_cache` (G:purge: body exactly
`{"files":[…]}`, 1-30 entries, each an `http(s)` URL (string, or `{"url":…}` object) whose host
is the zone or below it).

**`cf.workers.deploy`** (script, zone?): the calls `wrangler deploy` / `versions` / `secret` /
`triggers` make for one script (the proxy workstream verifies this list against the wrangler
bundle and the client's wrangler test, and documents the final table here):
```
GET          /accounts/{acct}/workers/services/{script}
GET|PUT      /accounts/{acct}/workers/scripts/{script}                     (PUT: U; GET is content: denied, section 3)
GET|PATCH    /accounts/{acct}/workers/scripts/{script}/settings|script-settings   (S:workers-script-settings on PATCH)
POST         /accounts/{acct}/workers/scripts/{script}/assets-upload-session
POST         /accounts/{acct}/workers/assets/upload                         (U, J)
GET|POST     /accounts/{acct}/workers/scripts/{script}/subdomain   GET /accounts/{acct}/workers/subdomain
GET|PUT      /accounts/{acct}/workers/scripts/{script}/schedules
GET|PUT      /accounts/{acct}/workers/scripts/{script}/secrets   GET|DELETE …/secrets/{name}
GET|POST     /accounts/{acct}/workers/scripts/{script}/versions  GET …/versions/{id}   (POST: U)
GET|POST     /accounts/{acct}/workers/scripts/{script}/deployments
GET          /accounts/{acct}/workers/domains   PUT /accounts/{acct}/workers/domains (G:workers-domain)
DELETE       /accounts/{acct}/workers/domains/{id}                          (G:workers-domain-remove, S:workers-domains)
GET|PUT      /accounts/{acct}/workers/scripts/{script}/domains/records      (G:workers-domain)
GET|POST     /zones/{zone}/workers/routes   PUT|DELETE /zones/{zone}/workers/routes/{id}  (G:workers-route, S:workers-routes)
GET          /zones?name=…   /accounts/{acct}/workers/account-settings   /accounts/{acct}/workers/durable_objects/namespaces
```
G:workers-domain: every hostname must be in the `zone` param's zone (refused without `zone`)
and `service`/`script` must equal the script. G:workers-route: `script` equals the script.

**`cf.pages`** (project): GET/PATCH `/accounts/{acct}/pages/projects/{project}` (S:pages-project);
GET/POST `…/{project}/deployments` (POST: U); GET/DELETE `…/deployments/{id}`, POST
`…/deployments/{id}/retry|rollback`, GET `…/deployments/{id}/history/logs`; GET
`…/{project}/upload-token`; `POST /pages/assets/check-missing|upload|upsert-hashes` (U, J);
GET/POST `…/{project}/domains`, GET/PATCH/DELETE `…/domains/{name}`.

**`cf.d1`** (db, access): GET `/accounts/{acct}/d1/database` (wrangler looks databases up by
name), GET `…/database/{db}`; `POST …/database/{db}/query|raw` (G:d1: with `access=read` the
`sql` must be only `SELECT`, `EXPLAIN`, `WITH … SELECT` or read-only `PRAGMA` (`table_list`,
`table_info`, `table_xinfo`, `index_list`, `index_info`, `foreign_key_list`) statements; with
`migrate` anything). Export is denied (section 3).

**`cf.r2.admin`**: GET/POST `/accounts/{acct}/r2/buckets`, GET `…/buckets/{bucket*}`,
GET/PUT/DELETE `…/buckets/{bucket*}/cors|lifecycle`, GET/POST `…/buckets/{bucket*}/domains/custom`,
GET/PUT/DELETE `…/domains/custom/{name}`, GET/PUT `…/domains/managed`.

**`cf.r2.objects`** (bucket, access): GET `/accounts/{acct}/r2/buckets/{bucket}/objects`,
GET `…/objects/{key...}`; with `access=write` also PUT (U) / DELETE `…/objects/{key...}`.

**`cf.email`** (zone): GET/POST `/zones/{zone}/email/routing/rules`, GET/PUT/DELETE
`…/rules/{id}`, GET/PUT `…/rules/catch_all` (S:email-rules); GET/POST/PATCH/DELETE
`/zones/{zone}/email/routing/dns`; POST `/zones/{zone}/email/routing/enable|disable`;
GET/POST `/accounts/{acct}/email/routing/addresses`, GET/DELETE `…/addresses/{id}`;
GET/POST/DELETE `/zones/{zone}/email/sending/{key...}`.

**`cf.admin`**: any method on any path that passes normalisation (3.1) and is not denied
(section 3). When the call also matches a route of another scope (ignoring parameter binding),
that route's snapshot type and guard rails apply; guard rails can be overridden per call with
`X-Aqmas-Override: <guard>[,<guard>]` (section 4), except the never-overridable ones.

## 3. Deny-list (always wins, also for `cf.admin`)

Refused with 403 `denied` (and an audit row, and a push for the first four groups):

- `/user/tokens` and below (except `GET /user/tokens/verify`, answered by aqmasd, 3.2);
  `/accounts/*/tokens` and below. (Token values, account takeover.)
- `/memberships` and below, `/accounts/*/members` and below, any non-GET on `/user`, anything
  else under `/user/` (`GET /user` and `GET /memberships` are synthetic, 3.2).
- Tunnel secrets: `/accounts/*/cfd_tunnel/*/token`, `…/cfd_tunnel/*/management` and below,
  `/accounts/*/warp_connector/*/token`, `/accounts/*/tunnels/*/token` (legacy).
- Tunnel lifecycle: `POST /accounts/*/cfd_tunnel`, `PUT|PATCH|DELETE /accounts/*/cfd_tunnel/*`,
  `DELETE …/cfd_tunnel/*/connections` (rogue connectors / kicking the connector).
- `POST /accounts/*/access/service_tokens`, `…/service_tokens/*/rotate|refresh`.
- `GET /accounts/*/challenges/widgets/*` (single widget = Turnstile secret), `…/rotate_secret`.
- `/accounts/*/workers/scripts/*/tails` and below; `GET /accounts/*/workers/scripts/*` and
  `…/content` and below (script source).
- `POST /accounts/*/r2/temp-access-credentials`; `/accounts/*/d1/database/*/export`.
- `/accounts/*/logpush` and `/zones/*/logpush` and below.
- `/certificates` and below; `/zones/*/origin_tls_client_auth`, `/zones/*/custom_certificates`
  and below; `/zones/*/ssl/certificate_packs` writes.
- Writes under `/accounts/*/secrets_store`, `/accounts/*/hyperdrive`, `/accounts/*/teamnet`,
  `/accounts/*/devices`, `/accounts/*/gateway`; anything under `/accounts/*/registrar`,
  `/accounts/*/subscriptions`, `/zones/*/subscription`, `/user/billing`.
- `POST /zones`, `DELETE /zones/*`; `/graphql`.
- `/accounts/{other}` for any account id but the configured one.
- Anything in `[cloudflare.scopes."<scope>"].extra_deny` (`"METHOD /path/template"`, `*` for
  any method or segment) for that scope.

### 3.1 Path, query, method and header normalisation

- Only `GET POST PUT PATCH DELETE` (others 405). `X-HTTP-Method-Override`, `X-HTTP-Method`,
  `X-Method-Override` present → 400 `bad_request`.
- The **escaped** path after `/cf/client/v4` is checked and forwarded byte for byte (no
  re-encoding): it must start with `/`, contain only `A-Za-z0-9 . _ ~ - ! $ & ' ( ) * + , = : @ / %`,
  no empty segment (`//`), no trailing `/`, no `.` or `..` segment, no `;`, no `\`. A `%` must
  start a valid `%XX`; percent-encoded segments match only `{key...}`, and their decoded form
  must not be `.`/`..`/empty or contain `/`, `\` or NUL. Otherwise 400 `bad_path`.
- Query: at most 2048 bytes of `A-Za-z0-9 . _ ~ - % = & + , : *`, valid `%XX`; forwarded as is.
- Upstream URL = `api_base` + escaped path + `?query`; the host is fixed (no SSRF), redirects
  are never followed (a 3xx becomes 502).
- Request headers forwarded: `Content-Type`, `Accept`, `If-Match`, `If-None-Match` (and the
  body). `Authorization` only on J routes. Everything else (cookies, `X-Auth-*`, `Cf-*`, the
  local shim's bearer) is dropped. aqmasd sets `Authorization: Bearer <proxy parent>` and its
  own `User-Agent`.
- Response headers passed back: `Content-Type`, `Content-Disposition`, `Cf-Ray`, `Retry-After`,
  `ETag`, `Last-Modified`; plus the `X-Aqmas-*` headers (`internal/api`).
- Bodies: routes whose guard rails parse the body read at most `max_body_bytes` (2 MiB); U routes
  stream up to `upload_max_body_bytes` (100 MiB); other routes 2 MiB. Over → 413.

### 3.2 Synthetic endpoints (answered by aqmasd; any active proxy grant suffices)

- `GET /user/tokens/verify` → `{"success":true,…,"result":{"id":"aqmas:<grant id>","status":"active","expires_on":"<grant not_after>"}}`.
- `GET /user` → `{"result":{"id":"aqmas","email":"aqmas-proxy@<host>.invalid"}}`.
- `GET /memberships`, `GET /accounts` → the configured account only
  (`{"id":"<acct>","name":"aqmas proxy"}`; memberships wrap it as `{"account":{…},"status":"accepted"}`).

### 3.3 Response redaction (all scopes, also cf.admin)

JSON responses (`application/json`, up to 32 MiB) are rewritten when they contain, at any
depth: keys `secret`, `client_secret`, `tunnel_secret`, `token`, `private_key`, `password`,
`credentials_file` (case-insensitive) with a non-empty string value; and `value` inside any
object under an `env_vars` key whose `type` is not `plain_text` (Pages secrets) — every such
value becomes `"[redacted by aqmas]"`. Redaction adds `X-Aqmas-Warning: redacted N fields`.
Non-JSON (R2 objects, logs) passes through unchanged. **Any write whose body contains the string
`[redacted by aqmas]` is refused** (never overridable): writing a redacted object back would
destroy the secret.

## 4. Guard rails

Refusals answer 403 `guard_rail` (409 for `tunnel-version`) with a Cloudflare-shaped error body
naming the guard; warnings answer normally with `X-Aqmas-Warning`. Each guard has a name;
**overridable** ones can be overridden only by a `cf.admin` grant with `X-Aqmas-Override: <name>`
(the override is audited and pushed). **Never** = not even then.

| Guard | Applies to | Refuses | Override |
|---|---|---|---|
| `tunnel-whole-config` | tunnel PUT | body other than `{"config":{"ingress":[…], …}}` | yes |
| `tunnel-catch-all` | tunnel PUT | last ingress rule not a catch-all (`service: http_status:404`, no hostname/path) | yes |
| `tunnel-traefik-sni` | tunnel PUT | a rule with `service == traefik_origin` whose `originRequest.originServerName != hostname` (warns when `matchSNItoHost`/`http2Origin` are not true) | yes |
| `tunnel-plain-origin` | tunnel PUT | a rule whose service is in `traefik_plain_origins` (redirect loop) | yes |
| `tunnel-no-tls-verify` | tunnel PUT | `noTLSVerify: true` on a rule that did not have it before | yes |
| `tunnel-access-aud` | tunnel PUT | removing or changing `originRequest.access` of a hostname that had it (the `fj` rule carries Forgejo's Access aud) | yes |
| `tunnel-version` | tunnel PUT | live config `version` differs from the version this host last read through the proxy (or the host never read it): 409, "GET the config again and re-apply your change" | yes |
| `access-protected-hostname` | Access app POST/PUT | `domain`, any `self_hosted_domains[]`, or any `destinations[].uri` covering a `protected_access_hostnames` entry: exact host, a wildcard covering it (`*.example.com`, `*.co.uk` …), with or without path | **never** |
| `access-patch` | Access app PATCH | always: "PATCH on Access apps fails with 10405: GET it, change it, PUT the whole object" | **never** |
| `access-policy-shared` | policy/group PUT/DELETE | a `reusable` policy (or a group) referenced by more than one app (aqmasd counts via GET apps): "change which policy the app references instead" | yes |
| `idp-delete` | IdP DELETE | always | yes |
| `dns-protected` | DNS writes | records named the zone apex, `MX`/`NS`/`SOA`/`CAA` types, `TXT` at the apex or `_dmarc.*`/`*._domainkey.*` or starting `v=spf1`, names starting `_acme-challenge.`, names in `protected_dns_names` (checked on the body and on the before-snapshot) | yes |
| `ruleset-keep-rules` | entrypoint PUT | a PUT that drops any rule id present in the before-snapshot ("add rules, never replace a ruleset") | yes |
| `ruleset-phase` | ruleset writes | phase not allowed / not the grant's phase | (scope) |
| `zone-settings-policy` | settings PATCH | `always_use_https` off, `min_tls_version` < 1.2, `ssl` other than `strict`, HSTS (`security_header`) `include_subdomains` or `preload` true | yes |
| `workers-domain-remove` | Workers custom-domain DELETE | always (dropping a custom domain deletes its DNS record) | yes |
| `redacted-write` | any write | body contains `[redacted by aqmas]` | **never** |

Warnings (never refuse): tunnel PUT adds a hostname with no proxied DNS record in a configured
zone or no Access app (best effort, from GETs aqmasd makes after the PUT); DNS write of a
`CNAME` to `*.cfargotunnel.com` with `proxied:false`; an `A` record to an RFC 1918 address;
Access app with `session_duration` above `730h`; a policy with `decision: bypass` or an
`everyone` include; DELETE of an Access app whose domain is a hostname in a tunnel config;
ruleset rule DELETE.

Scope enforcement (the DNS name glob, the Workers script/zone binding, D1 read-only SQL, cache
purge `files` only, ruleset phases) is not a guard rail: it cannot be overridden, `cf.admin`
simply is not limited by it.

### 4.1 Writes: order of operations

1. Normalise (3.1), deny-list (3), pick the grant (first offered grant whose scope matches),
   rate limit (per host: `rate_per_minute`, writes `write_rate_per_minute`; 429 + `Retry-After`).
2. Read the body (bounded), parse it if the route has guard rails.
3. **Before-snapshot**: GET the object with the parent token; failure → 502, nothing written.
4. Guard rails (they see body + before-snapshot).
5. Forward the write. On 2xx: **after-snapshot** (failure → warning only).
6. Audit row `cf_write` (actor `host:<name>`, object `grant:<id>`, detail: method, path,
   status, `before=<id> after=<id>`, warnings count, overrides, for tunnel PUTs a hostname diff
   `+a ~b -c`), and an ntfy push `aqmas: <host> <METHOD> <object> [ref <grant ref>]`.
   Refusals: audit `cf_refused` with code and guard. Reads: not in the audit table; one
   structured log line each (method, path, status, grant, host, duration).
7. Response with `X-Aqmas-Grant-Used`, `X-Aqmas-Snapshot-Before/After`, `X-Aqmas-Warning`.

Never logged anywhere: the parent token, child-token values, request or response bodies.

### 4.2 Snapshots

| Type | GET used | Object key |
|---|---|---|
| `tunnel-config` | `/accounts/{acct}/cfd_tunnel/{t}/configurations` | `tunnel-config:<tunnel id>` |
| `access-app` | `/accounts/{acct}/access/apps/{id}` (POST: before = missing; after from `result.id`) | `access-app:<id>` |
| `access-policy` / `access-group` | `…/access/policies/{id}` / `…/access/groups/{id}` | `access-policy:<id>` / `access-group:<id>` |
| `access-idp` / `access-org` | `…/identity_providers/{id}` / `…/access/organizations` | `access-idp:<id>` / `access-org` |
| `dns-record` | `/zones/{z}/dns_records/{id}` | `dns-record:<zone id>:<id>` |
| `dns-name` (POST) | `/zones/{z}/dns_records?name=<name>` (before), the new record (after) | `dns-name:<zone id>:<name>` |
| `ruleset-entrypoint` | `/zones/{z}/rulesets/phases/{phase}/entrypoint` | `ruleset-entrypoint:<zone id>:<phase>` |
| `ruleset` | `/zones/{z}/rulesets/{id}` | `ruleset:<zone id>:<id>` |
| `zone-setting` | `/zones/{z}/settings/{name}` or `/zones/{z}/settings` | `zone-setting:<zone id>:<name>` or `…:all` |
| `email-rules` | `/zones/{z}/email/routing/rules` | `email-rules:<zone id>` |
| `pages-project` | `/accounts/{acct}/pages/projects/{p}` | `pages-project:<p>` |
| `workers-script-settings` | `…/workers/scripts/{s}/settings` | `workers-script-settings:<s>` |
| `workers-routes` / `workers-domains` | `/zones/{z}/workers/routes` / `…/workers/domains` | `workers-routes:<zone id>` / `workers-domains` |

Stored by aqmasd on .60 (design decision 3) under `snapshot_dir` (default
`/var/lib/aqmas/cf-snapshots`): `<YYYY-MM-DD>/<id>.json` = the GET's `result` after redaction
(3.3), `<id>.meta.json` = `api.CFSnapshot` without content; files 0600, directories 0700.
Retention: hourly prune deletes snapshots older than `snapshot_retention_days` (default and
maximum 7) **except the newest snapshot of each object key**. Include it in the bastion's backups.

Agents read snapshots with `aqmas cf snapshot list|get` (API.md 5.3); a host needs any active
Cloudflare grant (cf.read is auto-approved, so this is cheap). Reverting = PUT the snapshot's
content back through the proxy with the matching write scope (it is snapshotted again).

## 5. Child tokens (token mode)

- Only for scopes with a template (section 2), never auto-approved, never standing; needs
  `minter_token_*` and `token_ip_condition` in the config.
- The canonical text signs `mode: "token"` and `ip_condition`; the card shows the template's
  permissions in plain words and its notes (e.g. "can deploy ANY Worker on the account").
- **Minted on delivery**: on the first `GET /v1/requests/{id}` after approval aqmasd marks the
  grant delivered (in one transaction), calls `POST /user/tokens` with the minter parent:
  name `aqmas:<grant id>:<host>`, `not_before` = now, `expires_on` = grant `not_after`,
  `condition.request_ip.in` = `token_ip_condition`, policies from the template (permission
  group names resolved through `GET /user/tokens/permission_groups`, cached), resources
  `com.cloudflare.api.account.<acct>` and/or `com.cloudflare.api.account.zone.<zone id>`.
  It returns the value in that response only and stores just the token id. If minting fails the
  mark is undone and the poll returns 502 (the CLI retries).
- **Deletion**: on grant revoke (at once, best effort) and by the sweeper (every minute) for
  every token-mode grant past `not_after` whose token is not yet deleted (retries until 2xx or
  404). Every 15 minutes the sweeper also lists upstream tokens named `aqmas:*`: one past its
  expiry, or one aqmasd has no record of, is deleted, audited `cf_token_orphan` and pushed.
- Audit: `cf_token_mint` (grant, token id, permissions), `cf_token_delete`.

## 6. Configuration (`[cloudflare]` in `/etc/aqmas/config.toml`)

```toml
[cloudflare]
enabled = true
account_id = "<32 hex>"
# api_base = "https://api.cloudflare.com/client/v4"
proxy_token_credential  = "cf-proxy-token"    # systemd LoadCredential= name (preferred)
minter_token_credential = "cf-minter-token"   # optional: token mode off without it
token_ip_condition = ["<static home IPv4>/32"] # design decision 4; configurable
# snapshot_dir = "/var/lib/aqmas/cf-snapshots"; snapshot_retention_days = 7
# rate_per_minute = 600; write_rate_per_minute = 60
# protected_access_hostnames = ["id.example.com"]
# traefik_origin = "https://192.0.2.50:9443"
# traefik_plain_origins = ["http://192.0.2.50", "http://192.0.2.50:80"]
# protected_dns_names = ["id.example.com"]

[[cloudflare.zones]]
name = "example.com"
id   = "<zone id>"
[[cloudflare.tunnels]]
name = "home"
id   = "aa11bb22-…"
[[cloudflare.d1_databases]]
name = "app-db"
id   = "<uuid>"

[cloudflare.scopes."cf.read"]
# no_auto_approve = true
[cloudflare.scopes."cf.email"]
# disabled = true
```

Overrides can only narrow: `disabled`, a lower `max_ttl_seconds`, `default_ttl_seconds`,
`no_auto_approve`, `no_standing`, `no_token_mode`, `extra_deny`. Unknown scope names and a
`max_ttl_seconds` above the built-in maximum are start-up errors. `cf.admin` (1 h, never auto,
never standing) and `cf.read.private` (never auto, never standing) are fixed.

Parent tokens: two new tokens (design decision 9: without Memberships Write / User Details
Write), both IP-conditioned to the static egress address (design decision 4): the **proxy parent**
(everything the scopes need, no API Tokens permission) and the **minter parent** (API Tokens
Write only). Each is a root-owned file in `/etc/aqmas/` handed to aqmasd by systemd
`LoadCredential=` (read once at start from `$CREDENTIALS_DIRECTORY/<name>`; `*_token_file` is
the alternative: a file owned by user `aqmas`, mode 0600/0400, refused otherwise). Never logged,
never in the database. Plan: `docs/DEPLOY-M2.md`.

## 7. Agent-side tools (API.md 5.6)

`aqmas cf request|api|curl|env|token|snapshot|scopes`. `aqmas cf env -- <cmd>` runs a command
with `CLOUDFLARE_API_BASE_URL` pointing at a **local shim** on `127.0.0.1` (random port, random
per-run bearer as `CLOUDFLARE_API_TOKEN`), which forwards to the proxy with mTLS and the grant
list. Unmodified wrangler, curl and scripts work through it.
