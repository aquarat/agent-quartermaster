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

// Assets are the files SHA256SUMS lists, exactly. Brokers of 0.9.0 to 0.9.2 parse that file
// strictly (these four names, nothing else), so it never gains a line: a build added later
// is listed in ExtraSums instead, which those brokers never fetch.
var Assets = [...]string{"aqmas-darwin-arm64", "aqmas-linux-amd64", "aqmas-linux-arm64", Daemon}

// DarwinAMD is the macOS x86-64 CLI, published from 0.9.3 on.
const DarwinAMD = "aqmas-darwin-amd64"

// ExtraAssets are the builds listed in ExtraSums (SHA256SUMS.extra) rather than SHA256SUMS.
var ExtraAssets = [...]string{DarwinAMD}

// ExtraSums is the name of the second checksum file. A release before 0.9.3 has none.
const ExtraSums = "SHA256SUMS.extra"

// ExtraSince is the first release that publishes ExtraSums. From it on the file is
// required: a source that leaves it out is refused, so it cannot be stripped to push the
// builds it lists back onto an unrecorded check.
const ExtraSince = "0.9.3"

// NeedsExtra reports whether a release of version v must publish ExtraSums.
func NeedsExtra(v string) bool { return ValidVersion(v) && !Newer(ExtraSince, v) }

// CLIAssets are every CLI build a release may carry.
var CLIAssets = [...]string{"aqmas-darwin-arm64", DarwinAMD, "aqmas-linux-amd64", "aqmas-linux-arm64"}
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

// ValidExtra reports whether s is a complete ExtraSums manifest.
func (s Sums) ValidExtra() bool {
	if len(s) != len(ExtraAssets) {
		return false
	}
	for _, a := range ExtraAssets {
		if !ValidHash(s[a]) {
			return false
		}
	}
	return true
}

// ParseExtra parses ExtraSums as strictly as Parse parses SHA256SUMS.
func ParseExtra(b []byte) (Sums, error) {
	s := Sums{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		hash, name, ok := strings.Cut(line, "  ")
		if !ok || !slices.Contains(ExtraAssets[:], name) || s[name] != "" || !ValidHash(hash) {
			return nil, errors.New("invalid or duplicate " + ExtraSums + " entry")
		}
		s[name] = hash
	}
	if !s.ValidExtra() {
		return nil, errors.New("incomplete " + ExtraSums)
	}
	return s, nil
}

// ExtraText is ExtraSums as published.
func (s Sums) ExtraText() string {
	var b strings.Builder
	for _, name := range ExtraAssets {
		fmt.Fprintf(&b, "%s  %s\n", s[name], name)
	}
	return b.String()
}

// Metadata is a verified release identity: what the bastion caches as latest.json, hands to
// its installer and serves to fleet CLIs. GitHub is the manifest every installation checks.
// Second is the manifest of the configured second source and is absent without one; when
// present it must be identical.
//
// Extra holds the ExtraSums digests (absent for a release without that file). Every
// configured source must publish the same ExtraSums, or none: Fill refuses anything else, so
// a record with Second and Extra means both sources agreed on Extra too. It is a member of
// its own because CLIs and brokers of 0.9.2 and earlier require GitHub to hold exactly the
// four SHA256SUMS names, and ignore a member they do not know.
type Metadata struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	GitHub  Sums   `json:"github"`
	Second  Sums   `json:"second,omitempty"`
	Extra   Sums   `json:"extra,omitempty"`
}

// Hash is the verified digest of any asset of the release ("" when it has none).
func (m Metadata) Hash(asset string) string {
	if slices.Contains(ExtraAssets[:], asset) {
		return m.Extra[asset]
	}
	return m.GitHub[asset]
}

// record is Metadata on disk and on the wire. Sources (1 or 2) marks a record written by
// this format. Records of 0.8.1 and earlier have no such field: they named the second
// source "forgejo" and always had one.
type record struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	GitHub  Sums   `json:"github"`
	Second  Sums   `json:"second,omitempty"`
	Extra   Sums   `json:"extra,omitempty"`
	Sources int    `json:"sources,omitempty"`
	Legacy  Sums   `json:"forgejo,omitempty"`
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(record{Version: m.Version, Commit: m.Commit, GitHub: m.GitHub, Second: m.Second, Extra: m.Extra, Sources: m.Compared()})
}

// LegacyJSON is the record with the verified digests repeated under "forgejo", where a CLI
// of 0.8.1 or earlier looks for them (and refuses a reply without them). Current readers
// ignore that key because the record says how many sources it holds.
//
// Know what this tells an old CLI: it copies GitHub's digests under "forgejo" even when the
// bastion compared GitHub alone, so a 0.8.1 CLI believes two sources agreed where there was
// one (plus the bastion's rebuild). That is accepted for compatibility, so that old CLIs can
// still upgrade themselves. It does not weaken their own check: the old CLI still fetches
// GitHub's manifest itself and refuses a mismatch.
func (m Metadata) LegacyJSON() ([]byte, error) {
	return json.Marshal(record{Version: m.Version, Commit: m.Commit, GitHub: m.GitHub, Second: m.Second, Extra: m.Extra, Sources: m.Compared(), Legacy: m.GitHub})
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
	*m = Metadata{Version: v.Version, Commit: v.Commit, GitHub: v.GitHub, Second: v.Second, Extra: v.Extra}
	return nil
}

func (m Metadata) Valid() bool {
	return ValidVersion(m.Version) && ValidCommit(m.Commit) && m.GitHub.Valid() && (m.Second == nil || m.Second.Agrees(m.GitHub)) && (m.Extra == nil || m.Extra.ValidExtra())
}

// Compared is how many published sources the record holds agreeing manifests of.
func (m Metadata) Compared() int {
	if m.Second != nil {
		return 2
	}
	return 1
}
