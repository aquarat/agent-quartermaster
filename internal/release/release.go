// Package release defines the small, closed vocabulary shared by both update paths.
package release

import (
	"encoding/json"
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

// Metadata is a verified release identity: what the bastion caches as latest.json, hands to
// its installer and serves to fleet CLIs. GitHub is the manifest every installation checks.
// Second is the manifest of the configured second source and is absent without one; when
// present it must be identical.
type Metadata struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	GitHub  Sums   `json:"github"`
	Second  Sums   `json:"second,omitempty"`
}

// record is Metadata on disk and on the wire. Sources (1 or 2) marks a record written by
// this format. Records of 0.8.1 and earlier have no such field: they named the second
// source "forgejo" and always had one.
type record struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	GitHub  Sums   `json:"github"`
	Second  Sums   `json:"second,omitempty"`
	Sources int    `json:"sources,omitempty"`
	Legacy  Sums   `json:"forgejo,omitempty"`
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(record{Version: m.Version, Commit: m.Commit, GitHub: m.GitHub, Second: m.Second, Sources: m.Compared()})
}

// LegacyJSON is the record with the verified digests repeated under "forgejo", where a CLI
// of 0.8.1 or earlier looks for them (and refuses a reply without them). Current readers
// ignore that key because the record says how many sources it holds.
func (m Metadata) LegacyJSON() ([]byte, error) {
	return json.Marshal(record{Version: m.Version, Commit: m.Commit, GitHub: m.GitHub, Second: m.Second, Sources: m.Compared(), Legacy: m.GitHub})
}

func (m *Metadata) UnmarshalJSON(b []byte) error {
	var v record
	if e := json.Unmarshal(b, &v); e != nil {
		return e
	}
	switch {
	case v.Sources == 0 && v.Second == nil:
		v.Second = v.Legacy
	case v.Sources == 1 && v.Second == nil, v.Sources == 2 && v.Second != nil:
	default:
		return errors.New("release metadata does not hold the sources it counts")
	}
	*m = Metadata{Version: v.Version, Commit: v.Commit, GitHub: v.GitHub, Second: v.Second}
	return nil
}

func (m Metadata) Valid() bool {
	return ValidVersion(m.Version) && ValidCommit(m.Commit) && m.GitHub.Valid() && (m.Second == nil || m.Second.Agrees(m.GitHub))
}

// Compared is how many published sources the record holds agreeing manifests of.
func (m Metadata) Compared() int {
	if m.Second != nil {
		return 2
	}
	return 1
}
