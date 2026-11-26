package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// SSH keys (docs/SSH-KEYS.md) are signer keys whose scheme signs exactly one
// thing: the data of an SSH public-key user authentication request (RFC 4252
// section 7). Anything else is refused by Valid, so such a key cannot be used
// as a general signing oracle, and a key made for `aqmas sign` can never
// answer an SSH login.
const (
	SSHEd25519   = "ssh-ed25519"
	SSHECDSAP256 = "ssh-ecdsa-p256"

	// UseSSHAgent and UseSSHHandout are the two things a host may ask of an SSH
	// key: signatures for logins while the key stays in aqmas, or the private
	// key itself (only when the owner allowed hand-out for that key).
	UseSSHAgent   = "ssh-agent"
	UseSSHHandout = "ssh-handout"

	// SSHUserAuthName is the item name of a login signature (a label only).
	SSHUserAuthName = "ssh-userauth"

	methodPublicKey = "publickey"
	methodHostBound = "publickey-hostbound-v00@openssh.com"
	msgUserAuth     = 50
)

// SSHKeyType is one key type the Vault offers for a new SSH key.
type SSHKeyType struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Algorithm string `json:"algorithm"`
}

func SSHKeyTypes() []SSHKeyType {
	return []SSHKeyType{{SSHEd25519, "Ed25519", ssh.KeyAlgoED25519}, {SSHECDSAP256, "ECDSA P-256", ssh.KeyAlgoECDSA256}}
}

// IsSSH reports whether a scheme belongs to an SSH key.
func IsSSH(scheme string) bool { return scheme == SSHEd25519 || scheme == SSHECDSAP256 }

func sshAlgorithm(scheme string) string {
	if scheme == SSHECDSAP256 {
		return ssh.KeyAlgoECDSA256
	}
	return ssh.KeyAlgoED25519
}

var sshSchemes = []Scheme{
	{ID: SSHEd25519, Title: "SSH key (Ed25519)", Key: "ed25519", Input: "message", SSH: true,
		Signed: "an SSH login request (public-key user authentication) for this key, and nothing else", Output: "64 raw bytes (R || S)",
		Check: "ssh -i is not needed: the SSH server checks it against the authorized key",
		sign: func(priv []byte, it Item) ([]byte, error) {
			return ed25519.Sign(ed25519.NewKeyFromSeed(priv), it.Message), nil
		},
		verify: func(pub []byte, it Item, sig []byte) bool { return ed25519.Verify(pub, it.Message, sig) }},
	{ID: SSHECDSAP256, Title: "SSH key (ECDSA P-256)", Key: "ecdsa-p256", Input: "message", SSH: true,
		Signed: "an SSH login request (public-key user authentication) for this key, and nothing else", Output: "ASN.1 DER (r, s)",
		Check: "ssh -i is not needed: the SSH server checks it against the authorized key",
		sign: func(priv []byte, it Item) ([]byte, error) {
			k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), priv)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(it.Message)
			return ecdsa.SignASN1(rand.Reader, k, sum[:])
		},
		verify: func(pub []byte, it Item, sig []byte) bool {
			k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
			sum := sha256.Sum256(it.Message)
			return err == nil && ecdsa.VerifyASN1(k, sum[:], sig)
		}},
}

// SSHPublicKey is the key in the form golang.org/x/crypto/ssh works with.
func SSHPublicKey(scheme string, pub []byte) (ssh.PublicKey, error) {
	switch {
	case scheme == SSHEd25519 && len(pub) == ed25519.PublicKeySize:
		return ssh.NewPublicKey(ed25519.PublicKey(pub))
	case scheme == SSHECDSAP256:
		k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
		if err != nil {
			return nil, errors.New("invalid public key")
		}
		return ssh.NewPublicKey(k)
	}
	return nil, errors.New("not an SSH key")
}

// ValidSSHComment accepts 1 to 100 printable ASCII characters without a
// leading or trailing space: what an authorized_keys line carries unchanged.
func ValidSSHComment(s string) bool {
	if len(s) == 0 || len(s) > 100 || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// AuthorizedKey is the public line for authorized_keys or a forge's key form:
// "ssh-ed25519 AAAA... comment", without a newline.
func AuthorizedKey(scheme string, pub []byte, comment string) (string, error) {
	k, err := SSHPublicKey(scheme, pub)
	if err != nil {
		return "", err
	}
	if !ValidSSHComment(comment) {
		return "", errors.New("invalid SSH key comment")
	}
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k)), "\n") + " " + comment, nil
}

// SSHFingerprint is the fingerprint as `ssh-keygen -lf` prints it: "SHA256:...".
func SSHFingerprint(scheme string, pub []byte) (string, error) {
	k, err := SSHPublicKey(scheme, pub)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(k), nil
}

// OpenSSHPrivate is the unencrypted OpenSSH private key file for a hand-out.
// The caller clears the result.
func OpenSSHPrivate(scheme string, priv []byte, comment string) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("invalid signer key")
	}
	var key any
	switch scheme {
	case SSHEd25519:
		key = ed25519.NewKeyFromSeed(priv)
	case SSHECDSAP256:
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), priv)
		if err != nil {
			return nil, errors.New("invalid signer key")
		}
		key = k
	default:
		return nil, errors.New("not an SSH key")
	}
	blk, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(blk), nil
}

// UserAuth is a parsed SSH public-key user authentication request: the only
// data an SSH key in aqmas signs.
type UserAuth struct {
	SessionID []byte
	User      string
	Service   string
	Method    string
	Algorithm string
	// PublicKey is the SSH wire form of the key the login is for.
	PublicKey []byte
	// HostKey is the server's host key (wire form) when the client bound the
	// request to it (OpenSSH 8.9 and later); nil otherwise.
	HostKey []byte
}

// SessionDigest names the SSH session in the audit log without storing it.
func (u UserAuth) SessionDigest() string {
	sum := sha256.Sum256(u.SessionID)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HostKeyFingerprint is the server host key's fingerprint, or "" when the
// request was not bound to one.
func (u UserAuth) HostKeyFingerprint() string {
	if len(u.HostKey) == 0 {
		return ""
	}
	sum := sha256.Sum256(u.HostKey)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

var errNotUserAuth = errors.New("an SSH key signs SSH login requests only (public-key user authentication)")

func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// ParseUserAuth accepts exactly the data a client signs for "publickey"
// authentication (RFC 4252 section 7) and OpenSSH's host-bound variant:
// session identifier, SSH_MSG_USERAUTH_REQUEST, user, "ssh-connection", the
// method, TRUE, the algorithm and the public key, with nothing after it.
// SSHSIG blobs (ssh-keygen -Y sign), certificates to sign, host-based
// authentication and arbitrary bytes all fail.
func ParseUserAuth(msg []byte) (UserAuth, error) {
	var u UserAuth
	var user, service, method, algo []byte
	var ok bool
	rest := msg
	if u.SessionID, rest, ok = sshString(rest); !ok || len(u.SessionID) < 16 || len(u.SessionID) > 64 {
		return u, errNotUserAuth
	}
	if len(rest) < 1 || rest[0] != msgUserAuth {
		return u, errNotUserAuth
	}
	rest = rest[1:]
	if user, rest, ok = sshString(rest); !ok || len(user) == 0 || len(user) > 255 || !utf8.Valid(user) || bytes.IndexByte(user, 0) >= 0 {
		return u, errNotUserAuth
	}
	if service, rest, ok = sshString(rest); !ok || string(service) != "ssh-connection" {
		return u, errNotUserAuth
	}
	if method, rest, ok = sshString(rest); !ok || string(method) != methodPublicKey && string(method) != methodHostBound {
		return u, errNotUserAuth
	}
	if len(rest) < 1 || rest[0] != 1 {
		return u, errNotUserAuth
	}
	rest = rest[1:]
	if algo, rest, ok = sshString(rest); !ok || string(algo) != ssh.KeyAlgoED25519 && string(algo) != ssh.KeyAlgoECDSA256 {
		return u, errNotUserAuth
	}
	if u.PublicKey, rest, ok = sshString(rest); !ok || len(u.PublicKey) == 0 {
		return u, errNotUserAuth
	}
	if string(method) == methodHostBound {
		if u.HostKey, rest, ok = sshString(rest); !ok || len(u.HostKey) == 0 {
			return u, errNotUserAuth
		}
		// A real host key, not a container for other bytes.
		if _, err := ssh.ParsePublicKey(u.HostKey); err != nil {
			return u, errNotUserAuth
		}
	}
	if len(rest) != 0 {
		return u, errNotUserAuth
	}
	// The embedded key must be a well-formed key of the named algorithm.
	if k, err := ssh.ParsePublicKey(u.PublicKey); err != nil || k.Type() != string(algo) {
		return u, errNotUserAuth
	}
	u.User, u.Service, u.Method, u.Algorithm = string(user), string(service), string(method), string(algo)
	return u, nil
}

// SSHLogin checks that an item is a login request for exactly this key and
// returns what it says. Sign and Verify of an SSH scheme both go through it.
func (s Scheme) SSHLogin(pub []byte, it Item) (UserAuth, error) {
	if !s.SSH {
		return UserAuth{}, errors.New("not an SSH key")
	}
	u, err := ParseUserAuth(it.Message)
	if err != nil {
		return u, err
	}
	k, err := SSHPublicKey(s.ID, pub)
	if err != nil || u.Algorithm != sshAlgorithm(s.ID) || !bytes.Equal(u.PublicKey, k.Marshal()) {
		return u, errors.New("this login request is for another SSH key")
	}
	return u, nil
}

// SSHSignature turns the scheme's raw signature into the SSH wire signature
// an agent returns.
func (s Scheme) SSHSignature(sig []byte) (*ssh.Signature, error) {
	switch s.ID {
	case SSHEd25519:
		if len(sig) != ed25519.SignatureSize {
			return nil, errors.New("invalid signature")
		}
		return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: sig}, nil
	case SSHECDSAP256:
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil {
			return nil, errors.New("invalid signature")
		}
		return &ssh.Signature{Format: ssh.KeyAlgoECDSA256, Blob: ssh.Marshal(rs)}, nil
	}
	return nil, errors.New("not an SSH key")
}

// SSHItem wraps the data an SSH client asks an agent to sign.
func SSHItem(data []byte) Item {
	sum := sha256.Sum256(data)
	return Item{Name: SSHUserAuthName, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Message: bytes.Clone(data)}
}
