// Package canon builds the canonical action text that a per-action WebAuthn challenge commits
// to (docs/API.md, "Approval challenge"). The challenge is SHA-256(canonical); on decide the
// server re-parses the stored canonical text and applies exactly the action it describes.
//
// Each object has a fixed key set (the web UI refuses to sign text with any other key):
//
//	common:     v, action, object, id, nonce, issued_at
//	request:    + requesting_host, address, kind, target, target_address, target_port, principal, login_user, key_fingerprint, ttl_seconds, standing_hours
//	enrollment: + requesting_host, address, class, kind, key_fingerprint, replaces, replaces_id, ttl_seconds, standing_hours
//	host:       + requesting_host, address, class (id identifies the enrolled identity)
//	standing:   + requesting_host, kind, target, login_user, ttl_seconds, standing_hours
//	grant:      + requesting_host, kind, target, login_user, ttl_seconds, standing_hours
//	passkey:    + nickname, new_nickname
//
// For passkey "add" the id is "new" and both nicknames are ""; for "rename" and "remove" the
// id is the passkey's id (hex of the first 16 bytes of SHA-256 of the credential ID),
// nickname its current nickname and new_nickname the new one (rename) or "" (remove).
//
// For kind "cloudflare" (milestone 2) the request, standing and grant objects carry a different
// set instead (docs/API.md 5.4); the set is chosen by (object, kind):
//
//	request:    + requesting_host, kind, scope, scope_params, mode, ip_condition, ttl_seconds, standing_hours
//	standing:   + requesting_host, kind, scope, scope_params, mode, ttl_seconds, standing_hours
//	grant:      + requesting_host, kind, scope, scope_params, mode, ttl_seconds, standing_hours
package canon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/release"
	"slices"
	"time"
)

// Version is the canonical format version ("v").
const Version = 1

// Actions.
const (
	ActionApprove = "approve"
	ActionDeny    = "deny"
	ActionRevoke  = "revoke"
	ActionAdd     = "add"    // add another passkey
	ActionRename  = "rename" // rename a passkey
	ActionRemove  = "remove" // remove a passkey
)

// Objects.
const (
	ObjectRequest    = "request"
	ObjectHost       = "host"
	ObjectEnrollment = "enrollment"
	ObjectStanding   = "standing"
	ObjectGrant      = "grant"
	ObjectPasskey    = "passkey"
	// ObjectSetup is a maintenance task for the root runner (docs/SETUP.md). id names the
	// task; params is that task's canonical typed parameters; secrets_sha256 commits to an
	// HPKE packet only the runner can open ("" when the task takes no secrets).
	ObjectSetup = "setup"
	ActionRun   = "run"
)

var commonKeys = []string{"v", "action", "object", "id", "nonce", "issued_at"}

// objectKeys are the keys each object carries besides the common ones.
var objectKeys = map[string][]string{
	ObjectSetup:      {"params", "secrets_sha256"},
	"update":         {"from_version", "from_commit", "to_version", "to_commit", "daemon_sha256", "linux_arm64_sha256", "linux_amd64_sha256", "darwin_arm64_sha256"},
	ObjectRequest:    {"address", "principal", "requesting_host", "kind", "target", "target_address", "target_port", "login_user", "key_fingerprint", "ttl_seconds", "standing_hours"},
	ObjectEnrollment: {"replaces_id", "class", "address", "requesting_host", "kind", "key_fingerprint", "replaces", "ttl_seconds", "standing_hours"},
	ObjectHost:       {"class", "address", "requesting_host"},
	ObjectStanding:   {"requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"},
	ObjectGrant:      {"requesting_host", "kind", "target", "login_user", "ttl_seconds", "standing_hours"},
	ObjectPasskey:    {"nickname", "new_nickname"},
}

// KindCloudflare is the request kind whose objects carry the Cloudflare key sets.
const KindCloudflare = "cloudflare"

// KindBastion is a session on the bastion itself (docs/BASTION-ACCESS.md §5). Its request
// carries the level, the open-bucket list the owner was shown and the close choice, and has no
// standing field: a standing approval for the bastion cannot be expressed, let alone signed.
const KindBastion = "bastion"

var bastionKeys = map[string][]string{
	ObjectRequest: {"kind", "level", "requesting_host", "host_id", "address", "target", "target_address", "target_port", "login_user", "principal",
		"key_fingerprint", "ssh_ca", "host_key", "cert_profile", "ttl_seconds", "sealed", "open_buckets", "close_buckets", "alert_channel"},
}

// cloudflareKeys replace objectKeys for kind "cloudflare".
var cloudflareKeys = map[string][]string{
	ObjectRequest:  {"requesting_host", "kind", "scope", "scope_params", "mode", "ip_condition", "ttl_seconds", "standing_hours"},
	ObjectStanding: {"requesting_host", "kind", "scope", "scope_params", "mode", "ttl_seconds", "standing_hours"},
	ObjectGrant:    {"requesting_host", "kind", "scope", "scope_params", "mode", "ttl_seconds", "standing_hours"},
}

// keysFor returns the key set (besides the common keys) for an object of a kind.
func keysFor(object, kind string) ([]string, bool) {
	if kind == KindCloudflare {
		if k, ok := cloudflareKeys[object]; ok {
			return k, true
		}
	}
	if kind == KindBastion {
		if k, ok := bastionKeys[object]; ok {
			return k, true
		}
		if object != ObjectGrant {
			return nil, false
		}
	}
	k, ok := objectKeys[object]
	return k, ok
}

var objectActions = map[string][]string{
	"update":         {ActionApprove},
	ObjectSetup:      {ActionRun},
	ObjectHost:       {ActionRevoke},
	ObjectRequest:    {ActionApprove, ActionDeny},
	ObjectEnrollment: {ActionApprove, ActionDeny},
	ObjectStanding:   {ActionRevoke},
	ObjectGrant:      {ActionRevoke},
	ObjectPasskey:    {ActionAdd, ActionRename, ActionRemove},
}

// Action is everything the owner approves with one passkey assertion.
type Action struct {
	StandingSeconds    int  `json:"standing_seconds"`
	Indefinite         bool `json:"indefinite"`
	StandingIndefinite bool `json:"standing_indefinite"`
	BeyondSoft         bool `json:"beyond_soft_cap"`
	StandingBeyondSoft bool `json:"standing_beyond_soft_cap"`
	api.ScopeBinding
	Update
	Params         string `json:"params"`         // setup: canonical task parameters (JSON)
	SecretsHash    string `json:"secrets_sha256"` // setup: SHA-256 of the sealed secrets packet
	Plan           string `json:"plan"`
	RecoveryHash   string `json:"recovery_sha256"`
	Principal      string `json:"principal"`
	ReplacesID     string `json:"replaces_id"`
	Class          string `json:"class"`
	Address        string `json:"address"`
	TargetAddress  string `json:"target_address"`
	TargetPort     int    `json:"target_port"`
	Action         string `json:"action"`
	Object         string `json:"object"`
	ID             string `json:"id"`
	RequestingHost string `json:"requesting_host"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	LoginUser      string `json:"login_user"`
	KeyFingerprint string `json:"key_fingerprint"`
	Replaces       bool   `json:"replaces"` // enrollment: approving revokes an existing host
	TTLSeconds     int    `json:"ttl_seconds"`
	StandingHours  int    `json:"standing_hours"`
	// Kind "cloudflare": scope name, canonical scope_params ("k=v;k=v"), mode (proxy|token)
	// and, on request objects, ip_condition (token mode: sorted CIDRs joined by ",").
	Scope       string `json:"scope"`
	ScopeParams string `json:"scope_params"`
	Mode        string `json:"mode"`
	IPCondition string `json:"ip_condition"`
	Nickname    string `json:"nickname"`     // passkey: its current nickname
	NewNickname string `json:"new_nickname"` // passkey rename: the new nickname
	// Kind "bastion": the level (inspect|root), whether the store is sealed, the labels of the
	// buckets open when the card was built (a JSON array as a string) and the owner's choice
	// to close every bucket before the certificate is issued.
	Level        string `json:"level"`
	Sealed       bool   `json:"sealed"`
	OpenBuckets  string `json:"open_buckets"`
	CloseBuckets bool   `json:"close_buckets"`
	// AlertChannel: a push channel exists, so approving a root session alerts the owner.
	AlertChannel bool `json:"alert_channel"`
}

// Signed is a parsed canonical text: the action plus the challenge metadata.
type Signed struct {
	Action
	V        int       `json:"v"`
	Nonce    string    `json:"nonce"`
	IssuedAt time.Time `json:"issued_at"`
}

// NewNonce returns 32 random bytes, base64url without padding.
func NewNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a Action) values() map[string]any {
	m := map[string]any{
		"plan": a.Plan, "recovery_sha256": a.RecoveryHash, "params": a.Params, "secrets_sha256": a.SecretsHash,
		"from_version": a.FromVersion, "to_version": a.ToVersion, "from_commit": a.FromCommit, "to_commit": a.ToCommit, "daemon_sha256": a.DaemonHash, "linux_arm64_sha256": a.LinuxARM, "linux_amd64_sha256": a.LinuxAMD, "darwin_arm64_sha256": a.DarwinARM,
		"principal": a.Principal, "replaces_id": a.ReplacesID,
		"class": a.Class, "address": a.Address, "target_address": a.TargetAddress, "target_port": a.TargetPort,
		"requesting_host": a.RequestingHost,
		"kind":            a.Kind,
		"target":          a.Target,
		"login_user":      a.LoginUser,
		"key_fingerprint": a.KeyFingerprint,
		"replaces":        a.Replaces,
		"ttl_seconds":     a.TTLSeconds,
		"standing_hours":  a.StandingHours,
		"scope":           a.Scope,
		"scope_params":    a.ScopeParams,
		"mode":            a.Mode,
		"ip_condition":    a.IPCondition,
		"nickname":        a.Nickname,
		"new_nickname":    a.NewNickname,
		"level":           a.Level,
		"sealed":          a.Sealed,
		"open_buckets":    a.OpenBuckets,
		"close_buckets":   a.CloseBuckets,
		"alert_channel":   a.AlertChannel,
	}
	bindingValues(a.ScopeBinding, m)
	m["standing_seconds"] = a.StandingSeconds
	m["indefinite"] = a.Indefinite
	m["standing_indefinite"] = a.StandingIndefinite
	m["beyond_soft_cap"] = a.BeyondSoft
	m["standing_beyond_soft_cap"] = a.StandingBeyondSoft
	return m
}

func isZero(v any) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case int:
		return x == 0
	case bool:
		return !x
	}
	return false
}

// Build returns the canonical UTF-8 JSON text for a: the object's fixed key set, keys sorted
// (encoding/json sorts map keys bytewise; all keys are ASCII), no insignificant whitespace, no
// HTML escaping. A field set on an object that does not carry it is an error, so nothing the
// server acts on can be left out of what the owner signs.
func Build(a Action, nonce string, issuedAt time.Time) (string, error) {
	if a.Object == "update" && (!release.Newer(a.ToVersion, a.FromVersion) || !release.ValidCommit(a.FromCommit) || !release.ValidCommit(a.ToCommit) || a.ID != a.ToCommit || a.ToCommit == a.FromCommit || !a.Sums().Valid()) {
		return "", errors.New("invalid update fields")
	}
	if a.Object == ObjectSetup && (len(a.Params) > 16<<10 || !json.Valid([]byte(a.Params)) || a.SecretsHash != "" && !release.ValidHash(a.SecretsHash)) {
		return "", errors.New("invalid setup fields")
	}
	if a.Action == "" || a.ID == "" {
		return "", errors.New("canon: action and id are required")
	}
	if a.Kind == KindBastion && a.Object == ObjectRequest {
		if err := validateBastion(a); err != nil {
			return "", err
		}
	}
	v := a.version()
	keys, ok := actionKeys(v, a.Object, a.Kind)
	if !ok {
		return "", fmt.Errorf("canon: unknown object %q", a.Object)
	}
	if !slices.Contains(objectActions[a.Object], a.Action) {
		return "", fmt.Errorf("canon: action %q not valid for %s", a.Action, a.Object)
	}
	if nonce == "" {
		return "", errors.New("canon: nonce required")
	}
	if v == 2 {
		if err := validateV2(a, nonce); err != nil {
			return "", err
		}
	}
	if a.TTLSeconds < 0 || a.StandingHours < 0 {
		return "", errors.New("canon: negative ttl or standing hours")
	}
	m := map[string]any{
		"v":         v,
		"action":    a.Action,
		"object":    a.Object,
		"id":        a.ID,
		"nonce":     nonce,
		"issued_at": issuedAt.UTC().Format(time.RFC3339),
	}
	for k, v := range a.values() {
		if slices.Contains(keys, k) {
			m[k] = v
		} else if !isZero(v) {
			return "", fmt.Errorf("canon: %s does not carry %s", a.Object, k)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

// Challenge returns SHA-256(canonical), the WebAuthn challenge bytes.
func Challenge(canonical string) []byte {
	h := sha256.Sum256([]byte(canonical))
	return h[:]
}

// Parse decodes canonical text produced by Build: it must have exactly the object's key set and
// round-trip byte for byte, so the parsed action is exactly what the challenge committed to.
func Parse(canonical string) (Signed, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(canonical), &raw); err != nil {
		return Signed{}, fmt.Errorf("canon: %w", err)
	}
	var obj string
	if err := json.Unmarshal(raw["object"], &obj); err != nil {
		return Signed{}, errors.New("canon: no object")
	}
	// The key set depends on (object, kind); kind is absent on passkey objects. A kind that
	// is not a string is caught by the strict decode below.
	var kind string
	if k, ok := raw["kind"]; ok {
		_ = json.Unmarshal(k, &kind)
	}
	var version int
	if err := json.Unmarshal(raw["v"], &version); err != nil {
		return Signed{}, errors.New("canon: invalid version")
	}
	keys, ok := actionKeys(version, obj, kind)
	if !ok {
		return Signed{}, fmt.Errorf("canon: unknown object %q", obj)
	}
	want := append(slices.Clone(commonKeys), keys...)
	if len(raw) != len(want) {
		return Signed{}, errors.New("canon: wrong key set")
	}
	for _, k := range want {
		if _, ok := raw[k]; !ok {
			return Signed{}, fmt.Errorf("canon: missing %s", k)
		}
	}
	var s Signed
	if err := json.Unmarshal([]byte(canonical), &s); err != nil {
		return Signed{}, fmt.Errorf("canon: %w", err)
	}
	if s.V != s.Action.version() {
		return Signed{}, fmt.Errorf("canon: unsupported version %d", s.V)
	}
	again, err := Build(s.Action, s.Nonce, s.IssuedAt)
	if err != nil {
		return Signed{}, err
	}
	if again != canonical {
		return Signed{}, errors.New("canon: text is not canonical")
	}
	return s, nil
}

// BastionRootMaxSeconds caps a root session; canonical text beyond it cannot be built.
const BastionRootMaxSeconds = 3600

// OpenList encodes bucket labels for open_buckets: sorted, distinct, as a JSON array.
func OpenList(labels []string) string {
	l := slices.Clone(labels)
	slices.Sort(l)
	l = slices.Compact(l)
	if l == nil {
		l = []string{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(l)
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// ParseOpenList decodes open_buckets; only the exact encoding of OpenList is accepted.
func ParseOpenList(text string) ([]string, error) {
	var l []string
	if len(text) > 8<<10 || json.Unmarshal([]byte(text), &l) != nil || l == nil || OpenList(l) != text {
		return nil, errors.New("canon: invalid open_buckets")
	}
	return l, nil
}

// validateBastion rejects any bastion request text whose fields contradict each other, so a
// card cannot be signed that says one thing and applies another.
func validateBastion(a Action) error {
	if a.Level != "inspect" && a.Level != "root" {
		return errors.New("canon: unknown bastion level")
	}
	if a.HostID == "" || a.Address == "" || a.Target == "" || a.TargetAddress == "" || a.TargetPort <= 0 || a.LoginUser == "" || a.Principal != a.LoginUser+"@"+a.Target ||
		a.KeyFingerprint == "" || a.SSHCA == "" || a.HostKey == "" || a.RequestingHost == "" {
		return errors.New("canon: incomplete bastion request")
	}
	want := "source-address;force-command"
	if a.Level == "root" {
		want = "source-address;permit-pty"
	}
	if a.CertProfile != want {
		return errors.New("canon: wrong certificate profile for this level")
	}
	open, err := ParseOpenList(a.OpenBuckets)
	if err != nil {
		return err
	}
	approveRoot := a.Level == "root" && a.Action == ActionApprove
	if !approveRoot && (len(open) != 0 || a.CloseBuckets || a.AlertChannel) || !a.Sealed && (len(open) != 0 || a.CloseBuckets) {
		return errors.New("canon: open_buckets, close_buckets and alert_channel belong to a root approval")
	}
	if a.Action != ActionApprove && a.TTLSeconds != 0 || a.Action == ActionApprove && a.TTLSeconds <= 0 || a.Level == "root" && a.TTLSeconds > BastionRootMaxSeconds {
		return errors.New("canon: invalid bastion duration")
	}
	return nil
}
