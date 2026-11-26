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
	MinGrantSeconds    = 60
	DefaultSignatures  = 20
	// MaxMessageBytes bounds the artifacts of one call for a scheme that signs
	// the artifact itself (they travel in one bounded JSON body).
	MaxMessageBytes = 40 << 10
	// MaxRequestsPerHour bounds one host's signing requests, whatever became of them.
	MaxRequestsPerHour = 30
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
	// Use is empty for ordinary signing. For an SSH key it is UseSSHAgent
	// (login signatures) or UseSSHHandout (the private key is delivered once).
	Use string `json:"use,omitempty"`
}

// SSHKey is what an admitted host learns about an SSH key (GET /v2/ssh/key):
// the binding and the public half. Handout says whether the owner allows the
// private key to be delivered (`aqmas ssh-key`).
type SSHKey struct {
	Binding       Binding `json:"binding"`
	AuthorizedKey string  `json:"authorized_key"`
	Fingerprint   string  `json:"fingerprint"`
	Comment       string  `json:"comment"`
	Handout       bool    `json:"handout"`
}

// SSHHandout is the one answer that carries an SSH private key: an OpenSSH
// private key file, delivered once under an approved hand-out grant.
type SSHHandout struct {
	Request       Request `json:"request"`
	PrivateKey    string  `json:"private_key"`
	AuthorizedKey string  `json:"authorized_key"`
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
