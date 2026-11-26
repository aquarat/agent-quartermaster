package api

// DurationPolicy is the public, complete policy for an org. Scope exceptions
// are explicit set IDs; the organisation switches alone never relax a built-in
// Cloudflare ceiling. Standing defaults are durations, not opt-in to standing.
type DurationPolicy struct {
	Default            int  `json:"default_seconds"`
	Soft               int  `json:"soft_cap_seconds"`
	Indefinite         bool `json:"indefinite"`
	StandingDefault    int  `json:"standing_default_seconds"`
	StandingSoft       int  `json:"standing_soft_cap_seconds"`
	StandingIndefinite bool `json:"standing_indefinite"`
	// Discovery ("Hosts may list what they can ask for") lets an admitted host
	// list this organisation's sets and targets (GET /v2/catalogue): names and
	// key names, never values. DenyGet turns `aqmas get` off for the
	// organisation's secrets (`aqmas run` is unchanged). Both are omitted while
	// false, so a policy that uses neither has the wire shape it always had.
	Discovery bool `json:"discovery,omitempty"`
	DenyGet   bool `json:"deny_get,omitempty"`
}

type CatalogueRule struct {
	Set      string `json:"set_id"`
	Scope    string `json:"scope"`
	Auto     bool   `json:"auto"`
	Standing bool   `json:"standing"`
	Relax    bool   `json:"relax_proxy_duration"`
}

type CatalogueNode struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Title    string `json:"title"`
	Revision int    `json:"revision"`
}

type CatalogueSet struct {
	CatalogueNode
	Kind     string `json:"kind"`
	Archived bool   `json:"archived"`
}
type CatalogueService struct {
	CatalogueNode
	Provider string         `json:"provider"`
	Sets     []CatalogueSet `json:"sets"`
}
type CatalogueHost struct {
	ID          int64  `json:"row_id"`
	Enrollment  string `json:"enrollment"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Class       string `json:"class"`
	Active      bool   `json:"active"`
	Generation  int    `json:"generation"`
}
type CatalogueOrg struct {
	CatalogueNode
	Policy   DurationPolicy     `json:"policy"`
	Rules    []CatalogueRule    `json:"rules"`
	Services []CatalogueService `json:"services"`
	Hosts    []CatalogueHost    `json:"hosts"`
	Auto     []AutoAccess       `json:"auto_access"`
}
type AutoAccess struct {
	Set          string `json:"set_id"`
	Scope        string `json:"scope"`
	Mode         string `json:"mode"`
	Restrictions string `json:"restrictions"`
	MaxSeconds   int    `json:"max_seconds"`
}

type Catalogue struct {
	OwnerID string         `json:"owner_id"`
	Orgs    []CatalogueOrg `json:"organisations"`
}

// CatalogueChange describes one typed proposal. Optional fields are selected
// by (object,action); decide re-derives it byte for byte from current rows.
type CatalogueChange struct {
	Owner          string              `json:"owner_id"`
	Org            CatalogueNode       `json:"organisation"`
	Service        *CatalogueNode      `json:"service,omitempty"`
	Set            *CatalogueNode      `json:"set,omitempty"`
	Kind           string              `json:"kind,omitempty"`
	OldPolicy      *DurationPolicy     `json:"old_policy,omitempty"`
	Policy         *DurationPolicy     `json:"new_policy,omitempty"`
	OldRules       *[]CatalogueRule    `json:"old_rules,omitempty"`
	Rules          *[]CatalogueRule    `json:"new_rules,omitempty"`
	Host           *CatalogueHost      `json:"host,omitempty"`
	ResultRevision int                 `json:"result_revision"`
	Auto           *[]AutoAccess       `json:"auto_access,omitempty"`
	Resources      *[]CatalogueService `json:"admitted_services,omitempty"`
}

// HostCatalogue is GET /v2/catalogue: what the calling host may ask for, in
// the organisations that admitted it and let hosts list. Names only.
type HostCatalogue struct {
	// Discovery is false when no organisation that admits the host allows
	// listing; both lists are then empty.
	Discovery   bool             `json:"discovery"`
	Credentials []HostCredential `json:"credentials"`
	Targets     []HostTarget     `json:"targets"`
}

// HostCredential is one credential set the host may request.
type HostCredential struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"` // env-set | secret | signer | ssh-key | cloudflare-proxy | cloudflare-mint
	Title string `json:"title"`
	// Names are an env set's key names; Env is a secret's variable name.
	Names  []string `json:"names,omitempty"`
	Env    string   `json:"env,omitempty"`
	Note   string   `json:"note,omitempty"`
	URL    string   `json:"url,omitempty"`
	Scheme string   `json:"scheme,omitempty"`
	// PublicKey is an SSH key's public line ("ssh-ed25519 AAAA... comment"), to
	// put in authorized_keys or a forge's key form. Handout: the owner allows
	// `aqmas ssh-key` to deliver the private key.
	PublicKey string `json:"public_key,omitempty"`
	Handout   bool   `json:"handout,omitempty"`
	// Approval: "owner" (a passkey tap for every request) or "per-scope"
	// (Cloudflare: some scopes are approved by policy, see `aqmas cf scopes`).
	Approval string `json:"approval"`
	Use      string `json:"use"`
}

// HostTarget is one SSH target the host may ask a certificate for.
type HostTarget struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Aliases    []string `json:"aliases,omitempty"`
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	Users      []string `json:"users"`
	HighRisk   bool     `json:"high_risk,omitempty"`
	MaxSeconds int      `json:"max_seconds,omitempty"`
	// Approval: "owner" (every request), or "owner-or-standing" (a tap unless
	// an auto-approval the owner made earlier covers this host, target and user).
	Approval string `json:"approval"`
	Use      string `json:"use"`
}
