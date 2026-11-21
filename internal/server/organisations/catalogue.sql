-- Schema 6. Install only in the signed cutover transaction, never on startup:
-- a rollback to a schema-5 binary must fail closed after activation.
CREATE TABLE people (
 id TEXT PRIMARY KEY, webauthn_handle BLOB NOT NULL UNIQUE, title TEXT NOT NULL,
 owner INTEGER NOT NULL CHECK(owner IN (0,1))
) STRICT;
CREATE UNIQUE INDEX single_owner ON people(owner) WHERE owner=1;
CREATE TABLE passkey_people (
 passkey_id INTEGER PRIMARY KEY REFERENCES passkeys(id) ON DELETE CASCADE,
 person_id TEXT NOT NULL REFERENCES people(id)
) STRICT;
CREATE TABLE organisations (
 id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE CHECK(length(slug) BETWEEN 1 AND 63 AND slug GLOB '[a-z0-9]*' AND slug NOT GLOB '*[^a-z0-9-]*'),
 title TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1))
) STRICT;
CREATE TABLE org_approvers (
 org_id TEXT NOT NULL REFERENCES organisations(id), person_id TEXT NOT NULL REFERENCES people(id),
 role TEXT NOT NULL CHECK(role='approver'), revision INTEGER NOT NULL CHECK(revision>0), PRIMARY KEY(org_id,person_id)
) STRICT;
CREATE TABLE services (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organisations(id),
 slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 63 AND slug GLOB '[a-z0-9]*' AND slug NOT GLOB '*[^a-z0-9-]*'),
 title TEXT NOT NULL, provider TEXT NOT NULL CHECK(provider IN ('fleet','cloudflare','application')),
 revision INTEGER NOT NULL CHECK(revision>0), archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
 UNIQUE(org_id,slug), UNIQUE(id,provider)
) STRICT;
CREATE TRIGGER service_parent_immutable BEFORE UPDATE OF id,org_id,provider ON services
BEGIN SELECT RAISE(ABORT,'immutable service binding'); END;
CREATE TABLE credential_sets (
 id TEXT PRIMARY KEY, service_id TEXT NOT NULL, provider TEXT NOT NULL,
 slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 63 AND slug GLOB '[a-z0-9]*' AND slug NOT GLOB '*[^a-z0-9-]*'),
 title TEXT NOT NULL, kind TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=0),
 archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
 CHECK((provider='fleet' AND kind='ssh-ca') OR (provider='cloudflare' AND kind IN ('cloudflare-proxy','cloudflare-mint')) OR (provider='application' AND kind='env-set')),
 UNIQUE(service_id,slug), FOREIGN KEY(service_id,provider) REFERENCES services(id,provider)
) STRICT;
CREATE TRIGGER set_parent_immutable BEFORE UPDATE OF id,service_id,provider,kind ON credential_sets
BEGIN SELECT RAISE(ABORT,'immutable credential set binding'); END;
CREATE TABLE org_hosts (
 org_id TEXT NOT NULL REFERENCES organisations(id), host_id INTEGER NOT NULL REFERENCES hosts(id),
 active INTEGER NOT NULL CHECK(active IN (0,1)), generation INTEGER NOT NULL CHECK(generation>0), PRIMARY KEY(org_id,host_id)
) STRICT;
CREATE TRIGGER admission_next_generation BEFORE UPDATE ON org_hosts WHEN
 NEW.generation!=OLD.generation+1 OR NEW.active=OLD.active OR NEW.org_id!=OLD.org_id OR NEW.host_id!=OLD.host_id
BEGIN SELECT RAISE(ABORT,'invalid admission generation'); END;
CREATE TRIGGER admission_keep_generation BEFORE DELETE ON org_hosts BEGIN SELECT RAISE(ABORT,'retain admission history'); END;
CREATE TABLE org_policies (
 org_id TEXT NOT NULL REFERENCES organisations(id), revision INTEGER NOT NULL CHECK(revision>0),
 default_seconds INTEGER NOT NULL CHECK(default_seconds>0), soft_cap INTEGER NOT NULL CHECK(soft_cap>=default_seconds),
 indefinite INTEGER NOT NULL CHECK(indefinite IN (0,1)), standing_default INTEGER NOT NULL CHECK(standing_default>=0),
 standing_soft_cap INTEGER NOT NULL CHECK(standing_soft_cap>=standing_default), standing_indefinite INTEGER NOT NULL CHECK(standing_indefinite IN (0,1)),
 PRIMARY KEY(org_id,revision)
) STRICT;
CREATE TABLE set_policies (
 set_id TEXT NOT NULL REFERENCES credential_sets(id), revision INTEGER NOT NULL CHECK(revision>0),
 scope TEXT NOT NULL, default_seconds INTEGER NOT NULL CHECK(default_seconds>0), soft_cap INTEGER NOT NULL CHECK(soft_cap>=default_seconds),
 indefinite INTEGER NOT NULL CHECK(indefinite IN (0,1)), auto INTEGER NOT NULL CHECK(auto IN (0,1)), standing INTEGER NOT NULL CHECK(standing IN (0,1)),
 PRIMARY KEY(set_id,revision,scope), CHECK(auto=0 OR scope IN ('cf.read','cf.cache.purge'))
) STRICT;
CREATE TABLE personal_aliases (
 kind TEXT NOT NULL, alias TEXT NOT NULL, set_id TEXT NOT NULL UNIQUE REFERENCES credential_sets(id), PRIMARY KEY(kind,alias)
) STRICT;
CREATE TRIGGER alias_no_update BEFORE UPDATE ON personal_aliases BEGIN SELECT RAISE(ABORT,'immutable personal alias'); END;
CREATE TRIGGER alias_no_delete BEFORE DELETE ON personal_aliases BEGIN SELECT RAISE(ABORT,'immutable personal alias'); END;
-- Grants and standing rules inherit their source request's immutable binding.
-- No binding for ambiguous legacy objects. No second, writable org ID.
CREATE TABLE request_bindings (
 request_id TEXT PRIMARY KEY REFERENCES requests(id), set_id TEXT NOT NULL REFERENCES credential_sets(id),
 set_revision INTEGER NOT NULL CHECK(set_revision>=0), service_revision INTEGER NOT NULL CHECK(service_revision>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0), generation INTEGER NOT NULL CHECK(generation>0)
) STRICT;
CREATE INDEX requests_by_set ON request_bindings(set_id,request_id);
CREATE TABLE personal_cutover (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), org_id TEXT NOT NULL REFERENCES organisations(id),
 config_sha256 TEXT NOT NULL, plan TEXT NOT NULL
) STRICT;
CREATE VIEW personal_resources AS
 SELECT s.id AS set_id,s.revision AS set_revision,v.id AS service_id,v.revision AS service_revision,
 o.id AS org_id,o.revision AS policy_revision,h.host_id,h.generation,a.kind,a.alias,
 e.class,hst.enrollment_id,hst.not_after AS host_not_after,
 o.slug AS org_slug,o.title AS org_title,v.slug AS service_slug,v.title AS service_title,s.slug AS set_slug,s.title AS set_title
 FROM personal_cutover c JOIN organisations o ON o.id=c.org_id JOIN services v ON v.org_id=o.id
 JOIN credential_sets s ON s.service_id=v.id JOIN personal_aliases a ON a.set_id=s.id AND a.kind=s.kind
 JOIN org_hosts h ON h.org_id=o.id JOIN hosts hst ON hst.id=h.host_id JOIN enrollments e ON e.id=hst.enrollment_id
 WHERE h.active=1 AND hst.revoked_at IS NULL AND o.archived=0 AND v.archived=0 AND s.archived=0;
CREATE VIEW personal_requests AS
 SELECT r.id AS request_id,p.* FROM requests r JOIN request_bindings b ON b.request_id=r.id
 JOIN personal_resources p ON p.host_id=r.host_id AND p.set_id=b.set_id AND p.set_revision=b.set_revision
 AND p.policy_revision=b.policy_revision AND p.service_revision=b.service_revision AND p.generation=b.generation
 WHERE (p.kind='ssh-ca' AND r.kind='ssh' AND p.alias=r.target_host)
 OR (r.kind='cloudflare' AND ((p.kind='cloudflare-proxy' AND r.mode='proxy') OR (p.kind='cloudflare-mint' AND r.mode='token')));
CREATE TRIGGER host_remove_admissions AFTER UPDATE OF revoked_at ON hosts WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
 UPDATE org_hosts SET active=0,generation=generation+1 WHERE host_id=NEW.id AND active=1;
END;
CREATE TRIGGER org_host_retire AFTER UPDATE OF active ON org_hosts WHEN NEW.active=0
BEGIN
 UPDATE requests SET status=CASE status WHEN 'approved' THEN 'revoked' ELSE 'expired' END,decision_note='organisation admission ended'
 WHERE status IN ('pending','approved') AND host_id=NEW.host_id AND id IN (SELECT b.request_id FROM request_bindings b JOIN credential_sets s ON s.id=b.set_id JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id);
 UPDATE grants SET revoked_at=CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE host_id=NEW.host_id AND revoked_at IS NULL AND request_id IN (SELECT b.request_id FROM request_bindings b JOIN credential_sets s ON s.id=b.set_id JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id);
 UPDATE standing SET revoked_at=CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE host_id=NEW.host_id AND revoked_at IS NULL AND source_request_id IN (SELECT b.request_id FROM request_bindings b JOIN credential_sets s ON s.id=b.set_id JOIN services v ON v.id=s.service_id WHERE v.org_id=NEW.org_id);
END;
CREATE TRIGGER new_owner_passkey AFTER INSERT ON passkeys BEGIN
 INSERT INTO passkey_people(passkey_id,person_id) SELECT NEW.id,id FROM people WHERE owner=1;
END;
