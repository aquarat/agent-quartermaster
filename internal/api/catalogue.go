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
