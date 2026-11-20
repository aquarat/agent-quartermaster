// Package release defines the small, closed vocabulary shared by both update paths.
package release

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var Version = "dev"
var Commit = "unknown"

const Daemon = "aqmasd-linux-arm64"

var Assets = [...]string{"aqmas-darwin-arm64", "aqmas-linux-amd64", "aqmas-linux-arm64", Daemon}
var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidVersion(s string) bool { return len(s) <= 64 && versionRE.MatchString(s) }
func ValidCommit(s string) bool  { return commitRE.MatchString(s) }
func ValidHash(s string) bool    { return digestRE.MatchString(s) }
func Newer(a, b string) bool {
	if !ValidVersion(a) || !ValidVersion(b) {
		return false
	}
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i, s := range aa {
		if len(s) != len(bb[i]) {
			return len(s) > len(bb[i])
		}
		if s != bb[i] {
			return s > bb[i]
		}
	}
	return false
}

type Sums map[string]string

func (s Sums) Valid() bool {
	if len(s) != len(Assets) {
		return false
	}
	for _, a := range Assets {
		if !ValidHash(s[a]) {
			return false
		}
	}
	return true
}
func (s Sums) Agrees(t Sums) bool { return s.Valid() && maps.Equal(s, t) }
func Parse(b []byte) (Sums, error) {
	s := Sums{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		hash, name, ok := strings.Cut(line, "  ")
		if !ok || !slices.Contains(Assets[:], name) || s[name] != "" || !ValidHash(hash) {
			return nil, errors.New("invalid or duplicate SHA256SUMS entry")
		}
		s[name] = hash
	}
	if !s.Valid() {
		return nil, errors.New("incomplete SHA256SUMS")
	}
	return s, nil
}
func (s Sums) Text() string {
	var b strings.Builder
	for _, name := range Assets {
		fmt.Fprintf(&b, "%s  %s\n", s[name], name)
	}
	return b.String()
}

type Metadata struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Forgejo Sums   `json:"forgejo"`
	GitHub  Sums   `json:"github"`
}

func (m Metadata) Valid() bool {
	return ValidVersion(m.Version) && ValidCommit(m.Commit) && m.Forgejo.Agrees(m.GitHub)
}
