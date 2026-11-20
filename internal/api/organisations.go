package api

// ScopeBinding is the card's authority and enrollment identity. The signed
// canonical is flat; legacy wire views omit this entire nested object.
type ScopeBinding struct {
	OrgID               string `json:"org_id"`
	OrgSlug             string `json:"org_slug"`
	OrgTitle            string `json:"org_title"`
	ServiceID           string `json:"service_id"`
	ServiceSlug         string `json:"service_slug"`
	ServiceTitle        string `json:"service_title"`
	SetID               string `json:"set_id"`
	SetSlug             string `json:"set_slug"`
	SetTitle            string `json:"set_title"`
	SetRevision         int    `json:"set_revision"`
	ServiceRevision     int    `json:"service_revision"`
	PolicyRevision      int    `json:"policy_revision"`
	AdmissionGeneration int    `json:"admission_generation"`
	HostID              string `json:"host_id"`
	ProfileRevision     string `json:"profile_revision"`
	MaxStandingHours    int    `json:"max_standing_hours"`
	SSHCA               string `json:"ssh_ca"`
	HostKey             string `json:"host_key"`
	CertProfile         string `json:"cert_profile"`
	AccountID           string `json:"account_id"`
	ResourceIDs         string `json:"resource_ids"`
}
