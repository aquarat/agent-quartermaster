package store

// migrations are applied in order; PRAGMA user_version records how many have run. Never edit a
// migration that has shipped: append a new one.
var migrations = []string{
	// 1: initial schema. Times are unix milliseconds (UTC).
	`
CREATE TABLE meta (
	key   TEXT PRIMARY KEY,
	value BLOB NOT NULL
) STRICT;

CREATE TABLE enrollments (
	id               TEXT PRIMARY KEY,
	hostname         TEXT NOT NULL,
	csr_pem          TEXT NOT NULL,
	key_fingerprint  TEXT NOT NULL,
	ssh_host_key_fps TEXT NOT NULL DEFAULT '[]',
	note             TEXT NOT NULL DEFAULT '',
	peer_address     TEXT NOT NULL,
	status           TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired')),
	created_at       INTEGER NOT NULL,
	expires_at       INTEGER NOT NULL,
	decided_at       INTEGER,
	decision_note    TEXT NOT NULL DEFAULT '',
	cert_pem         TEXT NOT NULL DEFAULT '',
	cert_delivered   INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX enrollments_status ON enrollments(status);

CREATE TABLE hosts (
	id            INTEGER PRIMARY KEY,
	name          TEXT NOT NULL,
	cert_sha256   TEXT NOT NULL UNIQUE,
	enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
	created_at    INTEGER NOT NULL,
	not_after     INTEGER NOT NULL,
	revoked_at    INTEGER
) STRICT;
CREATE UNIQUE INDEX hosts_active_name ON hosts(name) WHERE revoked_at IS NULL;

CREATE TABLE standing (
	id                TEXT PRIMARY KEY,
	host_id           INTEGER NOT NULL REFERENCES hosts(id),
	host_name         TEXT NOT NULL,
	kind              TEXT NOT NULL,
	target_host       TEXT NOT NULL,
	login_user        TEXT NOT NULL,
	max_ttl           INTEGER NOT NULL,
	created_at        INTEGER NOT NULL,
	expires_at        INTEGER NOT NULL,
	revoked_at        INTEGER,
	uses              INTEGER NOT NULL DEFAULT 0,
	source_request_id TEXT NOT NULL
) STRICT;
CREATE INDEX standing_host ON standing(host_id);

CREATE TABLE requests (
	id              TEXT PRIMARY KEY,
	host_id         INTEGER NOT NULL REFERENCES hosts(id),
	host_name       TEXT NOT NULL,
	peer_address    TEXT NOT NULL,
	kind            TEXT NOT NULL,
	target_host     TEXT NOT NULL,
	login_user      TEXT NOT NULL,
	public_key      TEXT NOT NULL,
	key_fingerprint TEXT NOT NULL,
	reason          TEXT NOT NULL,
	requester_json  TEXT NOT NULL,
	ttl_requested   INTEGER NOT NULL,
	status          TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','revoked')),
	created_at      INTEGER NOT NULL,
	expires_at      INTEGER NOT NULL,
	decided_at      INTEGER,
	decision_note   TEXT NOT NULL DEFAULT '',
	standing_id     TEXT REFERENCES standing(id)
) STRICT;
CREATE INDEX requests_status ON requests(status);
CREATE INDEX requests_similar ON requests(host_id, target_host, login_user, created_at);

CREATE TABLE grants (
	serial       INTEGER PRIMARY KEY AUTOINCREMENT,
	id           TEXT NOT NULL UNIQUE,
	request_id   TEXT NOT NULL UNIQUE REFERENCES requests(id),
	host_id      INTEGER NOT NULL REFERENCES hosts(id),
	host_name    TEXT NOT NULL,
	kind         TEXT NOT NULL,
	target_host  TEXT NOT NULL,
	login_user   TEXT NOT NULL,
	principals   TEXT NOT NULL,
	certificate  TEXT NOT NULL,
	not_before   INTEGER NOT NULL,
	not_after    INTEGER NOT NULL,
	revoked_at   INTEGER
) STRICT;
CREATE INDEX grants_host ON grants(host_id, not_after);

CREATE TABLE passkeys (
	id              INTEGER PRIMARY KEY,
	credential_id   BLOB NOT NULL UNIQUE,
	credential_json TEXT NOT NULL,
	name            TEXT NOT NULL DEFAULT '',
	created_at      INTEGER NOT NULL,
	last_used_at    INTEGER
) STRICT;

CREATE TABLE challenges (
	id           TEXT PRIMARY KEY,
	purpose      TEXT NOT NULL CHECK (purpose IN ('action','login','register')),
	object_type  TEXT NOT NULL DEFAULT '',
	object_id    TEXT NOT NULL DEFAULT '',
	canonical    TEXT NOT NULL DEFAULT '',
	session_data TEXT NOT NULL DEFAULT '',
	session_hash TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	used         INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE enroll_codes (
	hash       TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER
) STRICT;

CREATE TABLE web_sessions (
	hash         TEXT PRIMARY KEY,
	passkey_id   INTEGER NOT NULL REFERENCES passkeys(id),
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	at     INTEGER NOT NULL,
	actor  TEXT NOT NULL,
	action TEXT NOT NULL,
	object TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`,
}
