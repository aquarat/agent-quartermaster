package canon

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/organisations"
)

const Migration = "migration"

func init() { objectActions[Migration] = []string{"activate"} }

func (a Action) version() int {
	if a.Object == Migration || a.OrgID != "" {
		return 2
	}
	return Version
}
func actionKeys(v int, object, kind string) ([]string, bool) {
	if v == Version {
		return keysFor(object, kind)
	}
	if v != 2 {
		return nil, false
	}
	if object == Migration {
		return []string{"plan", "recovery_sha256"}, true
	}
	if !slices.Contains([]string{ObjectRequest, ObjectGrant, ObjectStanding}, object) {
		return nil, false
	}
	keys, ok := keysFor(object, kind)
	if !ok {
		return nil, false
	}
	keys = slices.Clone(keys)
	for _, k := range scopeKeys(kind) {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys, kind == "ssh" || kind == KindCloudflare
}

func scopeKeys(kind string) []string {
	keys := []string{"org_id", "org_slug", "org_title", "service_id", "service_slug", "service_title", "set_id", "set_slug", "set_title", "set_revision", "service_revision", "policy_revision", "admission_generation", "host_id", "class", "address", "profile_revision", "max_standing_hours"}
	if kind == "ssh" {
		return append(keys, "ssh_ca", "host_key", "cert_profile", "principal", "target_address", "target_port", "key_fingerprint")
	}
	return append(keys, "account_id", "resource_ids", "ip_condition")
}

func validateV2(a Action, nonce string) error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(b) != 32 {
		return errors.New("invalid v2 nonce")
	}
	if a.Object == Migration {
		var p organisations.Plan
		if len(a.Plan) > organisations.MaxPlanBytes || json.Unmarshal([]byte(a.Plan), &p) != nil {
			return errors.New("invalid migration plan")
		}
		text, err := json.Marshal(p)
		if err != nil || string(text) != a.Plan || p.Organisation.ID != a.ID || p.Organisation.Slug != "personal" || p.Source != organisations.SourceSchema || !lowerHex(a.RecoveryHash, 64) {
			return errors.New("invalid migration binding")
		}
		return nil
	}
	if !lowerHex(a.OrgID, 32) || !lowerHex(a.ServiceID, 32) || !lowerHex(a.SetID, 32) || a.SetRevision <= 0 || a.ServiceRevision <= 0 || a.PolicyRevision <= 0 || a.AdmissionGeneration <= 0 || a.HostID == "" || a.Address == "" || (a.Class != "agent" && a.Class != "owner-device") || a.MaxStandingHours < 0 || !lowerHex(a.ProfileRevision, 64) {
		return errors.New("incomplete scoped binding")
	}
	if a.Kind == "ssh" && (a.SSHCA == "" || a.HostKey == "" || a.CertProfile == "" || a.KeyFingerprint == "" || a.Principal == "" || a.TargetAddress == "" || a.TargetPort <= 0) {
		return errors.New("incomplete SSH authority")
	}
	if a.Kind == KindCloudflare && (!lowerHex(a.AccountID, 32) || a.Mode != "proxy") {
		return errors.New("invalid Cloudflare authority")
	}
	return nil
}

func lowerHex(s string, n int) bool {
	_, err := hex.DecodeString(s)
	return len(s) == n && strings.ToLower(s) == s && err == nil
}

func (a Action) CardFacts() map[string]any {
	if a.OrgID == "" {
		return nil
	}
	fields := a.values()
	out := map[string]any{}
	for _, k := range scopeKeys(a.Kind) {
		out[k] = fields[k]
	}
	return out
}

// All public binding fields are scalars. Use their wire names in the canonical
// rather than serialising a second, independently writable description.
func bindingValues(b api.ScopeBinding, m map[string]any) {
	v := reflect.ValueOf(b)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		m[t.Field(i).Tag.Get("json")] = v.Field(i).Interface()
	}
}
