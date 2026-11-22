package signer

// Binding is what an admitted host learns about a signer set: where it lives,
// which scheme its key signs with and the public key to verify against. The
// private key has no wire form anywhere in aqmas.
type Binding struct {
	Path            string `json:"path"`
	Title           string `json:"title"`
	Org             string `json:"org"`
	Service         string `json:"service"`
	Set             string `json:"set"`
	Revision        int    `json:"revision"`
	ServiceRevision int    `json:"service_revision"`
	PolicyRevision  int    `json:"policy_revision"`
	Generation      int    `json:"admission_generation"`
	Enrollment      string `json:"enrollment"`
	Host            string `json:"host"`
	Class           string `json:"class"`
	Scheme          string `json:"scheme"`
	PublicKey       []byte `json:"public_key"`
	Default         int    `json:"default_seconds"`
	Soft            int    `json:"soft_cap_seconds"`
}

// MaxGrantSeconds and MaxGrantSignatures bound a time-boxed signing grant
// whatever the organisation's duration policy says.
const (
	MaxGrantSeconds    = 24 * 3600
	MaxGrantSignatures = 1000
	DefaultSignatures  = 20
	// CollectSeconds is how long an approved single-use grant waits for the
	// requester to fetch its signatures.
	CollectSeconds = 600
)

// Request is a signing request and, once approved, its grant. TTL 0 is a
// single-use grant: exactly Items, once. TTL > 0 is a time-boxed grant: up to
// Max signatures over anything the host submits until Until.
type Request struct {
	Binding
	ID       string `json:"id"`
	Grant    string `json:"grant_id"`
	Peer     string `json:"address"`
	Reason   string `json:"reason"`
	Items    []Item `json:"items"`
	TTL      int    `json:"ttl_seconds"`
	Max      int    `json:"max_signatures"`
	Deadline int64  `json:"deadline"`
	Until    int64  `json:"not_after"`
	Status   string `json:"status"`
	Used     int    `json:"used"`
}
type Signature struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Signature []byte `json:"signature"`
}
type Signed struct {
	Request    Request     `json:"request"`
	Signatures []Signature `json:"signatures"`
}
