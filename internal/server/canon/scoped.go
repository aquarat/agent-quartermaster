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

var CatalogueActions = map[string][]string{"organisation": {"create"}, "service": {"create"}, "credential_set": {"create"}, "org_host": {"admit", "remove"}, "org_policy": {"replace"}}

func init() {
	objectActions[Migration] = []string{"activate"}
	for k, v := range CatalogueActions {
		objectActions[k] = v
	}
}

func (a Action) version() int {
	if a.Object == Migration || a.OrgID != "" || CatalogueActions[a.Object] != nil {
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
	if CatalogueActions[object] != nil {
		return []string{"plan"}, kind == ""
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
	keys = append(keys, "indefinite", "standing_indefinite", "beyond_soft_cap", "standing_beyond_soft_cap", "standing_seconds")
	for _, k := range scopeKeys(kind) {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys, kind == "ssh" || kind == KindCloudflare
}

func scopeKeys(kind string) []string {
	keys := []string{"org_id", "org_slug", "org_title", "service_id", "service_slug", "service_title", "set_id", "set_slug", "set_title", "set_revision", "service_revision", "policy_revision", "admission_generation", "host_id", "class", "address", "profile_revision", "max_standing_hours"}
	keys = append(keys, "soft_cap", "hard_cap", "standing_soft_cap", "standing_default", "offers_indefinite", "offers_standing", "offers_standing_indefinite")
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
	if CatalogueActions[a.Object] != nil {
		var c api.CatalogueChange
		if len(a.Plan) > 60<<10 || json.Unmarshal([]byte(a.Plan), &c) != nil {
			return errors.New("invalid catalogue change")
		}
		b, err := json.Marshal(c)
		if err != nil || string(b) != a.Plan || !lowerHex(c.Org.ID, 32) || !lowerHex(c.Owner, 32) || !validChangeShape(a, c) {
			return errors.New("noncanonical catalogue change")
		}
		return nil
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
	if a.StandingSeconds < 0 || a.StandingSeconds != 0 && (a.StandingHours != 0 || a.StandingIndefinite || a.Indefinite || !a.OffersStanding || a.Action != ActionApprove || a.Object != ObjectRequest) {
		return errors.New("invalid standing duration")
	}
	if a.SoftCap <= 0 || a.HardCap <= 0 || a.StandingDefault < 0 || a.StandingDefault > a.StandingSoftCap || a.BeyondSoft != (a.Indefinite || a.TTLSeconds > a.SoftCap) || a.StandingBeyondSoft != (a.StandingIndefinite || a.StandingHours > a.StandingSoftCap/3600 || a.StandingSeconds > a.StandingSoftCap) {
		return errors.New("invalid duration risk binding")
	}
	if a.Indefinite && (a.Kind != KindCloudflare || a.Scope == api.CFScopeAdmin || a.Scope == api.CFScopeReadPrivate || !a.OffersIndefinite || a.TTLSeconds != 0) || a.StandingIndefinite && (!a.OffersStanding || !a.OffersStandingIndefinite || a.StandingHours != 0) {
		return errors.New("ineligible indefinite choice")
	}
	return nil
}

// A canonical must not silently accept fields that are irrelevant for the
// verb. Database-dependent checks (e.g. auto-access and the old policy) are
// performed separately at challenge and inside the apply transaction.
func validChangeShape(a Action, c api.CatalogueChange) bool {
	var fields api.CatalogueChange
	fields.Owner, fields.Org, fields.ResultRevision = c.Owner, c.Org, c.ResultRevision
	switch a.Object {
	case "organisation":
		if c.Org.ID != a.ID || c.Org.Revision != 0 || c.Policy == nil || c.ResultRevision != 1 {
			return false
		}
		fields.Policy = c.Policy
	case "service":
		if c.Service == nil || c.Service.ID != a.ID || c.Service.Revision != 0 || c.Kind != "application" || c.ResultRevision != 1 {
			return false
		}
		fields.Service, fields.Kind = c.Service, c.Kind
	case "credential_set":
		if c.Service == nil || c.Set == nil || c.Set.ID != a.ID || c.Set.Revision != 0 || c.Kind != "env-set" || c.ResultRevision != 0 {
			return false
		}
		fields.Service, fields.Set, fields.Kind = c.Service, c.Set, c.Kind
	case "org_policy":
		if c.Org.ID != a.ID || c.Policy == nil || c.OldPolicy == nil || c.Rules == nil || c.OldRules == nil || c.ResultRevision != c.Org.Revision+1 {
			return false
		}
		fields.Policy, fields.OldPolicy, fields.Rules, fields.OldRules = c.Policy, c.OldPolicy, c.Rules, c.OldRules
	case "org_host":
		if c.Host == nil || c.Host.Enrollment != a.ID || c.Host.Active != (a.Action == "remove") || c.Auto == nil || c.Resources == nil || c.ResultRevision != c.Host.Generation+1 {
			return false
		}
		fields.Host, fields.Auto, fields.Resources = c.Host, c.Auto, c.Resources
	default:
		return false
	}
	return fields == c
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
