package cfscope

// workersRoutes: cf.workers.deploy (script, zone?). The calls wrangler 4.165's `deploy`,
// `versions upload|deploy`, `secret put|list|delete|bulk` and `triggers deploy` make for one
// script, read from its bundle (docs/CLOUDFLARE.md 2.1). Calls only made for queues,
// workflows, containers, dispatch namespaces or to register the account's workers.dev
// subdomain are not here (cf.admin).
func workersRoutes() []rdef {
	const a = "/accounts/{acct}/workers"
	const s = a + "/scripts/{script}"
	return []rdef{
		// Existence and metadata (legacy services API, the new workers API).
		rt("GET", a+"/services/{script}"),
		rt("GET", a+"/services/{script}/environments/{name}"),
		rt("GET", a+"/services/{script}/environments/{name}/bindings|routes|subdomain"),
		rt("GET", a+"/workers/{script}"),
		// Upload: first deploy / migrations (PUT), otherwise versions + deployments.
		rt("PUT", s, optU, optG(GuardWorkersBindings)),
		rt("GET", s+"/versions"),
		rt("POST", s+"/versions", optU, optG(GuardWorkersBindings)),
		rt("GET", s+"/versions/{id}"),
		rt("GET|POST", s+"/deployments"),
		rt("GET", s+"/settings|script-settings"),
		rt("PATCH", s+"/settings|script-settings", optSG(SnapWorkersScriptSettings, GuardWorkersBindings)),
		// Static assets: the session uses the parent token, the uploads the session's JWT.
		rt("POST", s+"/assets-upload-session"),
		rt("POST", a+"/assets/upload", optU, optJ),
		rt("POST", a+"/assets/upload/{id}", optU, optJ),
		// workers.dev.
		rt("GET|POST", s+"/subdomain"),
		rt("GET", a+"/subdomain"),
		// Cron triggers and secrets.
		rt("GET|PUT", s+"/schedules"),
		rt("GET|PUT", s+"/secrets"),
		rt("PATCH", s+"/secrets-bulk"),
		rt("GET|DELETE", s+"/secrets/{name}"),
		// Routes: the script's own route list (needs the zone param for its patterns), or
		// the per-zone fallback.
		rt("GET", s+"/routes"),
		rt("PUT", s+"/routes", optSG(SnapWorkersScriptRoutes, GuardWorkersRoute)),
		rt("GET", "/zones/{zone}/workers/routes"),
		rt("POST", "/zones/{zone}/workers/routes", optSG(SnapWorkersRoutes, GuardWorkersRoute)),
		rt("PUT|DELETE", "/zones/{zone}/workers/routes/{id}", optSG(SnapWorkersRoutes, GuardWorkersRoute)),
		rt("GET", "/zones"), // wrangler looks zones up by name (?name=...&account.id=...)
		// Custom domains.
		rt("GET", a+"/domains"),
		rt("GET", a+"/domains/records"),
		rt("GET", a+"/domains/records/{id}"),
		rt("PUT", a+"/domains", optSG(SnapWorkersDomains, GuardWorkersDomain)),
		rt("DELETE", a+"/domains/{id}", optSG(SnapWorkersDomains, GuardWorkersDomRm)),
		rt("DELETE", a+"/domains/records/{id}", optSG(SnapWorkersDomains, GuardWorkersDomRm)),
		rt("GET", s+"/domains/records"),
		rt("POST", s+"/domains/changeset", optG(GuardWorkersDomain)),
		rt("PUT", s+"/domains/records", optSG(SnapWorkersDomains, GuardWorkersDomain)),
		// Account facts wrangler reads.
		rt("GET", a+"/account-settings"),
		rt("GET", a+"/durable_objects/namespaces"),
	}
}

// pagesRoutes: cf.pages (project). The calls `wrangler pages deploy` makes (project GET,
// upload token, JWT-authenticated asset calls, the multipart deployment, deployment polling
// and logs), plus rollback, retry and custom domains.
func pagesRoutes() []rdef {
	const p = "/accounts/{acct}/pages/projects/{project}"
	return []rdef{
		rt("GET", p),
		rt("PATCH", p, optSG(SnapPagesProject, GuardPagesBindings)),
		rt("GET", p+"/upload-token"),
		rt("POST", "/pages/assets/check-missing|upload|upsert-hashes", optU, optJ),
		rt("GET", p+"/deployments"),
		rt("POST", p+"/deployments", optU),
		rt("GET|DELETE", p+"/deployments/{id}"),
		rt("POST", p+"/deployments/{id}/retry|rollback"),
		rt("GET", p+"/deployments/{id}/history/logs"),
		rt("GET", p+"/domains"),
		rt("POST", p+"/domains", optG(GuardPagesDomain)),
		rt("GET", p+"/domains/{name}"),
		rt("PATCH|DELETE", p+"/domains/{name}", optG(GuardPagesDomain)),
	}
}
