// Package nickname normalises and checks passkey nicknames. A nickname appears in signed
// canonical text ("remove the passkey X"), so two passkeys must not have names that read the
// same: every space character becomes one plain space, invisible, control and combining
// characters are refused, and uniqueness ignores case. (Look-alike letters from other
// scripts are still possible; the UI flags non-ASCII names and shows the passkey's short id
// next to its name wherever it asks for a signature.)
package nickname

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxBytes is the longest nickname in UTF-8 bytes (api.MaxNicknameBytes).
const MaxBytes = 64

// Normalize returns the nickname as stored: runs of any Unicode space character collapsed to
// one U+0020, trimmed. It refuses empty or over-long names and control, format (bidi,
// zero-width), private-use, surrogate, line/paragraph separator and combining characters.
func Normalize(n string) (string, error) {
	if !utf8.ValidString(n) {
		return "", errors.New("nickname is not valid UTF-8")
	}
	var b strings.Builder
	space := false
	for _, r := range n {
		if unicode.Is(unicode.Zs, r) {
			space = true
			continue
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs, unicode.Zl, unicode.Zp, unicode.Mn, unicode.Me) {
			return "", errors.New("nickname contains control, invisible or combining characters")
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" {
		return "", errors.New("nickname is empty")
	}
	if len(out) > MaxBytes {
		return "", fmt.Errorf("nickname is longer than %d bytes", MaxBytes)
	}
	return out, nil
}

// Same reports whether two normalised nicknames count as the same name (case ignored).
func Same(a, b string) bool { return strings.EqualFold(a, b) }

// Unique returns name, or name plus " 2", " 3", ... (shortened to fit MaxBytes) when taken(c)
// reports a candidate as used.
func Unique(name string, taken func(string) bool) string {
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf(" %d", i)
		base := name
		for len(base)+len(suffix) > MaxBytes {
			_, size := utf8.DecodeLastRuneInString(base)
			base = base[:len(base)-size]
		}
		if c := strings.TrimRight(base, " ") + suffix; !taken(c) {
			return c
		}
	}
}
