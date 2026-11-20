// Package ids generates opaque identifiers and random secrets.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a ULID (48-bit millisecond timestamp, 80 random bits, Crockford base32).
func New() string { return newAt(time.Now()) }

func newAt(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	// 128 bits -> 26 base32 characters: prepend 2 zero bits so the total is 130 = 26*5.
	out := make([]byte, 0, 26)
	var buf uint64
	bits := 2
	for _, x := range b {
		buf = buf<<8 | uint64(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, crockford[(buf>>uint(bits))&31])
		}
	}
	return string(out)
}

// Secret returns n random bytes base64url-encoded without padding.
func Secret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash returns the hex SHA-256 of s, used to store bearer secrets (cookies, codes) at rest.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
