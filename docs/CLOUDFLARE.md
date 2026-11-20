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
| `cf.email` | `zone` | H | no | no | 1h / 8h | – |
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
| `{dbname}` | the NAME of a configured D1 database (wrangler looks databases up by name) | the `db` param |

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

**`cf.workers.deploy`** (script, zone?): the calls wrangler 4.165's `deploy`, `versions
upload|deploy`, `secret put|list|delete|bulk` and `triggers deploy` make for one script, read
from its bundle (`S` = `/accounts/{acct}/workers/scripts/{script}`, `W` = `/accounts/{acct}/workers`):
```
GET          W/services/{script}   W/services/{script}/environments/{name}[/bindings|routes|subdomain]
GET          W/workers/{script}                                   (new Workers API: metadata, subdomain)
PUT          S                                                    (U, G:workers-bindings; first deploy, DO migrations, `secret put` stub; GET S is source: denied)
GET|POST     S/versions   GET S/versions/{id}                     (POST: U, G:workers-bindings, ?bindings_inherit=strict)
GET|POST     S/deployments
GET          S/settings|script-settings   PATCH S/settings|script-settings   (S:workers-script-settings, G:workers-bindings)
POST         S/assets-upload-session                              (parent token; answers the upload JWT)
POST         W/assets/upload   W/assets/upload/{id}               (U, J: Bearer = the session JWT)
GET|POST     S/subdomain   GET W/subdomain                        (wrangler POSTs S/subdomain on every deploy)
GET|PUT      S/schedules
GET|PUT      S/secrets   PATCH S/secrets-bulk   GET|DELETE S/secrets/{name}
GET          S/routes   PUT S/routes                              (G:workers-route, S:workers-script-routes)
GET|POST     /zones/{zone}/workers/routes   PUT|DELETE …/routes/{id}  (fallback; G:workers-route, S:workers-routes)
GET          /zones                                               (wrangler: ?name=<host>&account.id=<acct>)
GET          W/domains   W/domains/records   W/domains/records/{id}   S/domains/records
PUT          W/domains   S/domains/records   POST S/domains/changeset (G:workers-domain; PUT: S:workers-domains)
DELETE       W/domains/{id}   W/domains/records/{id}              (G:workers-domain-remove, S:workers-domains)
GET          W/account-settings   W/durable_objects/namespaces
```
G:workers-domain (scope check): every `hostname` in the body must be in the `zone` param's zone
(refused without `zone`), every `service`/`script` must equal the script, `zone_id`/`zone_name`
the zone. G:workers-route: on the zone routes `script` equals the script; on `PUT S/routes`
(a JSON array) every pattern's host is in the `zone` param's zone (refused without `zone`
unless the array is empty) and `zone_id`/`zone_name`/`script` match. Not covered (cf.admin):
queues, workflows (`PUT /accounts/{acct}/workflows/{name}`), containers, dispatch namespaces,
`PUT /accounts/{acct}/workers/subdomain` (registering the account's workers.dev subdomain),
`PUT /accounts/{acct}/workers/triggers/{script}` (event subscriptions). With
`CLOUDFLARE_API_TOKEN` and an account id set, wrangler makes no `/user/tokens/verify` or
`/memberships` call; it does call them (all synthetic, 3.2) after an API error 10000/9106.

**`cf.pages`** (project): GET/PATCH `/accounts/{acct}/pages/projects/{project}` (S:pages-project; PATCH: G:pages-bindings);
GET/POST `…/{project}/deployments` (POST: U, multipart incl. `_worker.bundle`); GET/DELETE
`…/deployments/{id}`, POST `…/deployments/{id}/retry|rollback`, GET
`…/deployments/{id}/history/logs`; GET `…/{project}/upload-token`; `POST
/pages/assets/check-missing|upload|upsert-hashes` (U, J: Bearer = the upload-token JWT);
GET/POST `…/{project}/domains`, GET/PATCH/DELETE `…/domains/{name}` (writes: G:pages-domain,
protected hostnames). That is all `wrangler pages
deploy` calls for an existing project (project creation, `POST …/pages/projects`, is cf.admin;
note wrangler turns `pages deploy` of a missing project into `wrangler deploy` when it detects
an AI agent).

**`cf.d1`** (db, access): GET `/accounts/{acct}/d1/database`, GET `…/database/{db}`, GET
`…/database/{dbname}` (wrangler's lookup by name, `?fields=uuid,name`, when the binding has no
`database_id`); `POST …/database/{db}/query|raw` (G:d1: with `access=read` every statement of
the `sql` (also in a batch) must be `SELECT`, `EXPLAIN`, `WITH … SELECT` or a read-only
`PRAGMA` (`table_list`, `table_info`, `table_xinfo`, `index_list`, `index_info`,
`foreign_key_list`, never `= value`), and no write keyword may appear outside literals and
comments; with `migrate` anything). `POST …/database/{db}/import` only with `access=migrate`
(`d1 execute --file`: init/ingest/poll; the file itself goes to a presigned R2 URL that does
not pass the proxy and is never checked). `migrations apply --remote` is only `/query` calls.
Export is denied (section 3).

**`cf.r2.admin`**: GET/POST `/accounts/{acct}/r2/buckets`, GET `…/buckets/{bucket*}`,
GET/PUT/DELETE `…/buckets/{bucket*}/cors|lifecycle`, GET/POST `…/buckets/{bucket*}/domains/custom`,
GET/PUT/DELETE `…/domains/custom/{name}`, GET/PUT `…/domains/managed`. Custom-domain writes
(G:r2-domain): the domain must lie in a configured zone (and `zoneId`, when given, be its id;
scope check) and never touch a protected hostname.

**`cf.r2.objects`** (bucket, access): GET `/accounts/{acct}/r2/buckets/{bucket}/objects`,
GET `…/objects/{key...}`; with `access=write` also PUT (U) / DELETE `…/objects/{key...}`.

**`cf.email`** (zone): GET/POST `/zones/{zone}/email/routing/rules`, GET/PUT/DELETE
`…/rules/{id}`, GET/PUT `…/rules/catch_all` (S:email-rules, G:email-forward); GET/POST/PATCH/DELETE
`/zones/{zone}/email/routing/dns`; POST `/zones/{zone}/email/routing/enable|disable`;
GET/POST `/accounts/{acct}/email/routing/addresses` (POST: G:email-forward), GET/DELETE `…/addresses/{id}`;
GET/POST/DELETE `/zones/{zone}/email/sending/{key...}`.

**`cf.admin`**: any method on any path that passes normalisation (3.1) and is not denied
(section 3). When the call also matches a route of another scope (ignoring parameter binding,
literals and ids compared case-insensitively, unconfigured objects allowed), that route's
snapshot type and guard rails apply; guard rails can be overridden per call with
`X-Aqmas-Override: <guard>[,<guard>]` (section 4), except the never-overridable ones. A path
with a percent-encoded segment is accepted only when it matches such a route with `{key...}`
at that position.

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
- `/accounts/*/workers/scripts/*/tails` and below, `/accounts/*/workers/tails` and below;
  `GET /accounts/*/workers/scripts/*` and `…/content` and below,
  `/accounts/*/workers/services/*/environments/*/content` and below, `GET
  /accounts/*/workers/dispatch/namespaces/*/scripts/*` and its `…/content` (script source).
- `POST /accounts/*/r2/temp-access-credentials`; `/accounts/*/d1/database/*/export`.
- `/accounts/*/logpush` and `/zones/*/logpush` and below.
- `/certificates` and below; `/zones/*/origin_tls_client_auth`, `/zones/*/custom_certificates`
  and below; `/zones/*/ssl/certificate_packs` writes.
- Writes under `/accounts/*/secrets_store`, `/accounts/*/hyperdrive`, `/accounts/*/teamnet`,
  `/accounts/*/devices`, `/accounts/*/gateway`; anything under `/accounts/*/registrar`,
  `/accounts/*/subscriptions`, `/zones/*/subscription`, `/user/billing`.
- `POST /zones`, `DELETE /zones/*`; `/graphql`; any non-GET on `/accounts`.
- `/accounts/{other}` for any account id but the configured one.
- Other shapes of objects a guarded route owns, and hostname-bearing objects nobody manages
  through aqmas (they would bypass guard rails and snapshots, also for cf.admin): non-GET
  `/zones/*/access` and below; `/zones/*/dns_records/batch|import` and below; `PUT|PATCH|DELETE
  /zones/*/dns_records`; non-GET `/accounts/*/access/apps/*/settings`; non-GET
  `/accounts/*/tunnels` and `/accounts/*/warp_connector` and below (pushed); `PUT|PATCH
  /zones/*`; non-GET under `/zones/*/hostnames/settings`, `/zones/*/pagerules`,
  `/zones/*/snippets`, `/zones/*/workers/filters`, `/zones/*/load_balancers`,
  `/zones/*/spectrum`, `/zones/*/custom_hostnames`, `/accounts/*/workers/services`,
  `/accounts/*/workers/workers`; `POST /zones/*/rulesets` (PUT the phase entrypoint instead),
  `DELETE /zones/*/rulesets/*`; `PUT|PATCH|POST /accounts/*/workers/domains/*` and below.
  (`PUT /zones/{zone}/rulesets/{id}` is a cf.rulesets route with S:ruleset and
  `ruleset-keep-rules`.)
- Anything in `[cloudflare.scopes."<scope>"].extra_deny` (`"METHOD /path/template"`, `*` or
  `{x}` for any method or segment; an entry covers its path and everything below it; invalid
  entries are a start-up error) for that scope.

Deny matching compares percent-decoded, lower-cased segments (`/User/%74okens` is denied),
except that `/accounts/{acct}` must be the configured id byte for byte. The synthetic GETs
(3.2) are never denied.

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
- Request headers forwarded: `Content-Type`, `Accept`, `If-Match`, `If-None-Match`,
  `Cloudflare-Workers-Script-Api-Date` (wrangler sets it on `POST …/subdomain`; it selects the
  API behaviour) (and the body). `Authorization` only on J routes. Everything else (cookies, `X-Auth-*`, `Cf-*`, the
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
Non-JSON (logs) and R2 object bodies (whatever their content type: they are the caller's data)
pass through unchanged. A JSON answer that does not parse, or is larger than 32 MiB, answers
502 rather than going out unchecked. Snapshots store the redacted form. **Any write whose body contains the string
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
| `tunnel-access-aud` | tunnel PUT | removing or changing `originRequest.access` of a hostname that had it (e.g. a rule whose origin checks the Access aud) | yes |
| `tunnel-version` | tunnel PUT | live config `version` differs from the version this host last read through the proxy (or the host never read it): 409, "GET the config again and re-apply your change" | yes |
| `access-protected-hostname` | Access app POST/PUT | `domain`, any `self_hosted_domains[]`, or any `destinations[].uri`/`hostname` touching a protected hostname (below) | **never** |
| `protected-hostname` | Workers custom domains (`PUT W/domains`, `S/domains/records`, `POST S/domains/changeset`; DELETE of one by id), Workers routes (`pattern`, also of the existing route on PUT/DELETE by id), Pages domains, R2 custom domains, DNS records (body, merged PATCH, before-snapshot), tunnel PUT | a hostname touching a protected hostname. Tunnel: the ingress rules for protected hostnames must stay byte-identical and in the same order (none added, removed or changed, no wildcard rule covering one added), and the config-wide `originRequest` must not change while such a rule exists | **never** |
| `access-patch` | Access app PATCH | always: "PATCH on Access apps fails with 10405: GET it, change it, PUT the whole object" | **never** |
| `access-policy-shared` | policy/group PUT/DELETE | a `reusable` policy (or a group) referenced by more than one app (aqmasd counts via GET apps): "change which policy the app references instead" | yes |
| `idp-delete` | IdP DELETE | always | yes |
| `dns-protected` | DNS writes | records named the zone apex, `MX`/`NS`/`SOA`/`CAA` types, `TXT` at the apex or `_dmarc.*`/`*._domainkey.*` or starting `v=spf1`, names starting `_acme-challenge.`, names in `protected_dns_names` (checked on the body and on the before-snapshot) | yes |
| `ruleset-keep-rules` | entrypoint PUT | a PUT that drops any rule id present in the before-snapshot ("add rules, never replace a ruleset") | yes |
| `ruleset-phase` | ruleset writes | phase not allowed / not the grant's phase | (scope) |
| `zone-settings-policy` | settings PATCH | `always_use_https` off, `min_tls_version` < 1.2, `ssl` other than `strict`, HSTS (`security_header`) `include_subdomains` or `preload` true | yes |
| `workers-domain-remove` | Workers custom-domain DELETE | always (dropping a custom domain deletes its DNS record) | yes |
| `redacted-write` | any write | body contains `[redacted by aqmas]` | **never** |
| `email-forward` | email routing rule POST/PUT, catch-all PUT, destination address POST | a `forward` action to an address not in `email_forward_allow`, a `worker` (or any other non-`drop`) action, a destination address not in the list | yes |

**Protected hostnames** = `protected_access_hostnames` ∪ `protected_dns_names` (both empty by
default: then nothing is protected, and aqmasd warns at start). A candidate (hostname, URL,
route pattern) touches one when, lower-cased and without scheme, port, path and trailing dot,
it equals it, or a `*` wildcard in either covers the other (`*.example.com`, `*example.com`,
`*`). Candidates that cannot be judged (non-ASCII, `%`, user info) count as touching.

**Strict JSON** on every route with a guard rail or scope check (and Pages project PATCH): the
body must be `application/json` (aqmasd forwards it as exactly that), valid UTF-8, and no
object may have two keys that are equal ignoring case (Unicode simple folding, exact
duplicates included) or a key that folds to a field aqmasd reads without being spelled exactly
so (`Domain`, `OriginRequest`, `ſql`, …): 400 `bad_request`. Workers uploads (`PUT S`, `POST
S/versions`, multipart `PATCH S/settings`) must be `multipart/form-data` with exactly one
`metadata` (`settings`) part, spelled exactly, without a transfer encoding, holding such JSON.

Warnings (never refuse): tunnel PUT adds a hostname with no proxied DNS record in a configured
zone or no Access app (best effort, from GETs aqmasd makes after the PUT); DNS write of a
`CNAME` to `*.cfargotunnel.com` with `proxied:false`; an `A` record to an RFC 1918 address;
Access app with `session_duration` above `730h`; a policy with `decision: bypass` or an
`everyone` include; DELETE of an Access app whose domain is a hostname in a tunnel config;
ruleset rule DELETE.

Scope enforcement (the DNS name glob, the Workers script/zone binding and route ownership, data
bindings, D1 body shape and read-only SQL, cache purge `files` only, ruleset phases, R2 custom
domains in configured zones) is not a guard rail: it cannot be overridden, `cf.admin`
simply is not limited by it. A violation answers 403 `no_grant` (audited `cf_refused`) with
`X-Aqmas-Needs-Scope` where one helps (`cf.dns.edit zone=…` without `name`, `cf.d1
access=migrate;db=…`, `cf.admin` for purge-everything).

`X-Aqmas-Override` with a non-admin grant, naming an unknown guard, or naming a
never-overridable one answers 400 `bad_request` before anything is read or written.
**Data bindings** (cf.workers.deploy, cf.pages): the `bindings[]` of a Workers upload's
`metadata` part or settings PATCH, its `tail_consumers[]` (a tail consumer receives the
script's logs), and the `deployment_configs.{production,preview}` bindings of a Pages project
PATCH may only name data listed for that script / project in `[[cloudflare.worker_bindings]]`
(`d1:<configured db name>`, `r2:<bucket>`, `kv:<namespace-id>`, `service:<script>`,
`queue:<name>`, `durable_object:<script or namespace id>`, `hyperdrive:<id>`,
`vectorize:<index>`, `analytics_engine:<dataset>`, `secrets_store:<store>/<secret>`,
`dispatch_namespace:<ns>`, `mtls:<certificate id>`, `workflow:<name>`, `pipeline:<name>`,
`send_email:<binding name>`). Free: `plain_text`, `secret_text`, `json`, `assets`,
`version_metadata`, `ai`, `browser`, `inherit`, `wasm_module`, `text_blob`, `data_blob`,
`images`, `ratelimit`, `media`, `secret_key`, a service binding to itself, Durable Objects and
workflows of the script itself. Unknown binding types and unknown Pages config keys are
refused. No entry = no data bindings. (Pages deployments carry no bindings: `wrangler pages
deploy` uploads only `_worker.bundle`, `_routes.json` and the manifest.) Child tokens cannot
enforce any of this (noted on the card).

**D1 bodies**: exactly `{"sql", "params"?}`, `{"batch": [{"sql", "params"?}…]}` or
`[{"sql", "params"?}…]`; any other key is refused (both access levels) and every `sql` is
checked with `access=read`.

**Workers routes by id** (PUT/DELETE `/zones/{zone}/workers/routes/{id}`): the route in the
before-snapshot must exist and belong to the grant's script.

`tunnel-traefik-sni` and `tunnel-plain-origin` compare services as URLs: scheme, port
(default by scheme, leading zeros dropped) and host, IPs canonicalised (IPv4-mapped IPv6, and
dotted quads with leading zeros read both as decimal and as octal).

`tunnel-version`: a GET of `…/configurations` through any scope (cf.read included, also
cf.admin) records the version for (host, tunnel) in memory; the version in the after-snapshot
of the host's own successful PUT counts as read too. After an aqmasd restart every host reads
again.

### 4.1 Writes: order of operations

1. Normalise (3.1), deny-list (3), pick the grant (first offered grant whose scope matches),
   rate limit (per host: `rate_per_minute`, writes `write_rate_per_minute`; 429 + `Retry-After`;
   JWT asset uploads count only towards `rate_per_minute`).
2. Read the body (bounded), parse it if the route has guard rails.
3. **Before-snapshot**: GET the object with the parent token; failure → 502, nothing written
   (a 404 counts as "missing" only for ruleset entrypoints; creates have no before GET). It is
   stored only once the guard rails pass (a refused write leaves no snapshot).
4. Guard rails (they see body + before-snapshot).
5. Forward the write. On 2xx: **after-snapshot** (failure → warning only).
6. Audit row `cf_write` (actor `host:<name>`, object `grant:<id>`, detail: method, path,
   status, `before=<id> after=<id>`, warnings count, overrides, for tunnel PUTs a hostname diff
   `+a ~b -c`), and an ntfy push `aqmas: <host> <METHOD> <object> [ref <grant ref>]`.
   Refusals: audit `cf_refused` with code and guard (deny-list, guard rails, override misuse,
   scope enforcement, and `no_grant` on writes; `no_grant` on reads, `bad_path`, 405 and 429
   are only logged). Writes are audited whatever Cloudflare answered; the push goes out on 2xx
   only, and not for JWT asset uploads or `access=read` D1 queries (audited, not pushed) unless
   an override was used. Reads: not in the audit table; one structured log line each (method,
   path, status, grant, host, duration).
7. Response with `X-Aqmas-Grant-Used`, `X-Aqmas-Snapshot-Before/After`, `X-Aqmas-Warning`.

Never logged anywhere: the parent token, child-token values, request or response bodies.

### 4.2 Snapshots

| Type | GET used | Object key |
|---|---|---|
| `tunnel-config` | `/accounts/{acct}/cfd_tunnel/{t}/configurations` | `tunnel-config:<tunnel id>` |
| `access-app` | `/accounts/{acct}/access/apps/{id}` (POST: before = missing; after from `result.id`; also for app-scoped policy writes) | `access-app:<id>` |
| `access-policy` / `access-group` | `…/access/policies/{id}` / `…/access/groups/{id}` | `access-policy:<id>` / `access-group:<id>` |
| `access-idp` / `access-org` | `…/identity_providers/{id}` / `…/access/organizations` | `access-idp:<id>` / `access-org` |
| `dns-record` | `/zones/{z}/dns_records/{id}` | `dns-record:<zone id>:<id>` |
| `dns-name` (POST) | `/zones/{z}/dns_records?name=<name>` (before), the new record (after) | `dns-name:<zone id>:<name>` |
| `ruleset-entrypoint` | `/zones/{z}/rulesets/phases/{phase}/entrypoint` | `ruleset-entrypoint:<zone id>:<phase>` |
| `ruleset` | `/zones/{z}/rulesets/{id}` | `ruleset:<zone id>:<id>` |
| `zone-setting` | `/zones/{z}/settings/{name}` or `/zones/{z}/settings` | `zone-setting:<zone id>:<name>` or `…:all` |
| `email-rules` | `/zones/{z}/email/routing/rules` | `email-rules:<zone id>` |
| `pages-project` | `/accounts/{acct}/pages/projects/{p}` | `pages-project:<p>` |
| `workers-script-settings` | the path written (`…/workers/scripts/{s}/settings` or `…/script-settings`) | `workers-script-settings:<s>` |
| `workers-script-routes` | `…/workers/scripts/{s}/routes` | `workers-script-routes:<s>` |
| `workers-routes` / `workers-domains` | `/zones/{z}/workers/routes` / `…/workers/domains` | `workers-routes:<zone id>` / `workers-domains` |

Creates of policies, groups and IdPs work as `access-app` (before = missing, after from
`result.id`). An after GET answering 404 (a DELETE) stores an after-snapshot with
`missing: true`.

Stored by aqmasd on .60 (design decision 3) under `snapshot_dir` (default
`/var/lib/aqmas/cf-snapshots`): `<YYYY-MM-DD>/<id>.json` = the GET's `result` after redaction
(3.3), `<id>.meta.json` = `api.CFSnapshot` without content; files 0600, directories 0700.
Retention: hourly prune deletes snapshots older than `snapshot_retention_days` (default and
maximum 7) **except the newest snapshot of each object key**. Include it in the bastion's backups.

Agents read snapshots with `aqmas cf snapshot list|get` (API.md 5.3); a host needs any active
Cloudflare grant (cf.read is auto-approved, so this is cheap), and sees only snapshots of its
own writes (`host` = its name; another host's id answers 404). `access-idp`, `pages-project`
and `workers-script-settings` snapshots additionally need an active grant of
`cf.read.private`, of the scope that writes them (`cf.access.idp-org`, `cf.pages`,
`cf.workers.deploy`) or `cf.admin` (core reports the host's active scopes through the optional
`cfproxy.ScopeLister`; without it these types are never served). Reverting = PUT the snapshot's
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
# All of the following default to empty (the guards that need them then do not apply):
protected_access_hostnames = ["id.example.com"]   # e.g. the identity provider; aqmasd warns when empty
# protected_dns_names = ["id.example.com"]
# traefik_origin = "https://192.0.2.10:443"
# traefik_plain_origins = ["http://192.0.2.10", "http://192.0.2.10:80"]
# email_forward_allow = ["owner@example.net"]

[[cloudflare.zones]]
name = "example.com"
id   = "<zone id>"
[[cloudflare.tunnels]]
name = "home"
id   = "<tunnel uuid>"
[[cloudflare.d1_databases]]
name = "app-db"
id   = "<uuid>"

# Data bindings a Worker / Pages project may have when deployed through aqmas (default: none).
[[cloudflare.worker_bindings]]
script = "hello"
allow  = ["d1:app-db", "r2:assets", "kv:<namespace-id>", "service:auth"]
[[cloudflare.worker_bindings]]
pages_project = "site"
allow  = ["d1:app-db"]

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
