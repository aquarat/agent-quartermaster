// Package envset contains the shared public release contract and the local
// literal-value codec. Values are carried only by upload and collect.
package envset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxBytes = 24 << 10

var nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func ValidPath(path string) bool {
	p := strings.Split(path, "/")
	return len(p) == 3 && slug.MatchString(p[0]) && slug.MatchString(p[1]) && slug.MatchString(p[2])
}

type Binding struct {
	Path            string   `json:"path"`
	Title           string   `json:"title"`
	Org             string   `json:"org"`
	Service         string   `json:"service"`
	Set             string   `json:"set"`
	Revision        int      `json:"revision"`
	ServiceRevision int      `json:"service_revision"`
	PolicyRevision  int      `json:"policy_revision"`
	Generation      int      `json:"admission_generation"`
	Enrollment      string   `json:"enrollment"`
	Host            string   `json:"host"`
	Class           string   `json:"class"`
	Names           []string `json:"names"`
	Default         int      `json:"default_seconds"`
	Soft            int      `json:"soft_cap_seconds"`
	Forever         bool     `json:"offers_indefinite"`
}
type Upload struct {
	Ticket     string `json:"ticket"`
	Edit       Edit   `json:"edit"`
	Commitment string `json:"commitment"`
}
type Entry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Edit struct {
	Op      string  `json:"operation"`
	Salt    []byte  `json:"salt"`
	Entries []Entry `json:"entries"`
	// Remove is used by "merge" only (the web form): names deleted in the same
	// revision as Entries are added or replaced.
	Remove []string `json:"remove,omitempty"`
}
type Draft struct {
	Binding
	ID         string `json:"id"`
	Operation  string `json:"operation"`
	Commitment string `json:"commitment"`
	Changes    string `json:"changes"`
	Expires    int64  `json:"expires_at"`
}
type Release struct {
	Binding
	ID       string `json:"id"`
	Grant    string `json:"grant_id"`
	Mode     string `json:"mode"`
	Peer     string `json:"address"`
	Reason   string `json:"reason"`
	TTL      int    `json:"ttl_seconds"`
	Deadline int64  `json:"deadline"`
	Until    int64  `json:"not_after"`
	Status   string `json:"status"`
	Consumed bool   `json:"consumed"`
}

// Standing is a "don't ask again" rule the owner made while approving one
// release: later releases of the same set revision to the same host, from the
// same address, in the same delivery mode and within MaxTTL are approved
// without a tap until it expires or is revoked. It carries no value.
type Standing struct {
	Binding
	ID      string `json:"id"` // the release whose approval created it
	Mode    string `json:"mode"`
	Peer    string `json:"address"`
	MaxTTL  int    `json:"max_ttl_seconds"`
	Created int64  `json:"created_at"`
	Expires int64  `json:"expires_at"`
	Uses    int    `json:"uses"`
}

// StandingCapDefault is a set's "longest don't-ask-again" until the owner
// changes it; StandingCapMax is the most the owner can allow.
const (
	StandingCapDefault = 3600
	StandingCapMax     = 86400
)

type Collection struct {
	Release Release `json:"release"`
	Entries []Entry `json:"entries"`
}

// Use a deliberately small namespace for delivery. App-specific names plus
// common credential suffixes, never loader, shell or tool configuration.
func SafeName(s string) bool {
	if !nameRE.MatchString(s) {
		return false
	}
	for _, p := range []string{"AQMAS_", "LD_", "DYLD_", "BASH", "ZSH", "SHEL", "PROMPT", "PS4", "GIT_", "SSH_", "GCONV_", "PYTHON", "PERL", "RUBY", "NODE_", "BUN_", "NPM_", "GO", "CARGO_", "RUST", "HIST", "XDG_", "LC_", "SSLKEYLOG", "ENV_", "JAVA_", "JDK_", "KRB5", "BUNDLE_", "VIM", "EDITOR", "TERM", "AWS_CONFIG", "AWS_SHARED"} {
		if strings.HasPrefix(s, p) {
			return false
		}
	}
	if strings.HasPrefix(s, "APP_") {
		return true
	}
	for _, suffix := range []string{"_TOKEN", "_KEY", "_PASSWORD", "_SECRET", "_URL", "_DSN", "_USER", "_USERNAME", "_ID"} {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
func Validate(entries []Entry) error {
	if len(entries) > 64 {
		return errors.New("too many keys")
	}
	seen := map[string]bool{}
	size := 0
	for _, e := range entries {
		if !SafeName(e.Name) || seen[e.Name] {
			return errors.New("unsupported or duplicate environment name")
		}
		if len(e.Value) > 8192 || !utf8.ValidString(e.Value) || strings.ContainsRune(e.Value, 0) {
			return fmt.Errorf("unsupported value for %s", e.Name)
		}
		size += len(e.Name) + len(e.Value)
		seen[e.Name] = true
	}
	if size > MaxBytes {
		return errors.New("environment too large")
	}
	return nil
}
func Names(entries []Entry) []string {
	n := make([]string, len(entries))
	for i, e := range entries {
		n[i] = e.Name
	}
	slices.Sort(n)
	return n
}
func (e Edit) Commit(b Binding) (string, error) {
	if len(e.Salt) != 32 || Validate(e.Entries) != nil || b.Revision < 0 || !(e.Op == "import" || e.Op == "merge" && len(e.Entries)+len(e.Remove) > 0 || e.Op == "put" && len(e.Entries) == 1 || e.Op == "unset" && len(e.Entries) == 1 && e.Entries[0].Value == "") {
		return "", errors.New("invalid edit")
	}
	if len(e.Remove) > 0 && (e.Op != "merge" || len(e.Remove) > 64) {
		return "", errors.New("invalid edit")
	}
	removed := slices.Clone(e.Remove)
	slices.Sort(removed)
	for i, n := range removed {
		if !nameRE.MatchString(n) || i > 0 && removed[i-1] == n || slices.ContainsFunc(e.Entries, func(x Entry) bool { return x.Name == n }) {
			return "", errors.New("invalid edit")
		}
	}
	h := sha256.New()
	add := func(p []byte) { h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p)))); h.Write(p) }
	add([]byte("aqmas-env-edit-v1"))
	add(e.Salt)
	for _, s := range []string{b.Org, b.Service, b.Set} {
		add([]byte(s))
	}
	add(binary.BigEndian.AppendUint64(nil, uint64(b.Revision)))
	add([]byte(e.Op))
	entries := slices.Clone(e.Entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, x := range entries {
		add([]byte(e.Op))
		add([]byte(x.Name))
		add([]byte(x.Value))
	}
	for _, n := range removed {
		add([]byte("remove"))
		add([]byte(n))
		add(nil)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (e Edit) Changes(old []string) (string, error) {
	present := map[string]bool{}
	var ops []string
	for _, x := range e.Entries {
		kind := "add"
		if slices.Contains(old, x.Name) {
			kind = "replace"
		}
		if e.Op == "unset" {
			if kind != "replace" {
				return "", errors.New("cannot unset missing key")
			}
			kind = "remove"
		}
		present[x.Name] = true
		ops = append(ops, x.Name+":"+kind)
	}
	for _, n := range e.Remove {
		if e.Op != "merge" || !slices.Contains(old, n) || present[n] {
			return "", errors.New("cannot remove missing key")
		}
		present[n] = true
		ops = append(ops, n+":remove")
	}
	if e.Op == "import" {
		for _, n := range old {
			if !present[n] {
				ops = append(ops, n+":remove")
			}
		}
	}
	slices.Sort(ops)
	return strings.Join(ops, ","), nil
}
func (e Edit) Apply(old []Entry) ([]Entry, error) {
	m := map[string]string{}
	if e.Op != "import" {
		for _, x := range old {
			m[x.Name] = x.Value
		}
	}
	for _, x := range e.Entries {
		if e.Op == "unset" {
			delete(m, x.Name)
		} else {
			m[x.Name] = x.Value
		}
	}
	for _, n := range e.Remove {
		delete(m, n)
	}
	out := make([]Entry, 0, len(m))
	for k, v := range m {
		out = append(out, Entry{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, Validate(out)
}

// ParseFile reads the literal dotenv subset documented in docs/API.md
// ("Dotenv import"): NAME=value lines, blank lines and # comment lines.
// A value is bare (no quotes, backslash, $, backtick, # or surrounding
// space), single-quoted (literal; may span lines) or double-quoted (may span
// lines; only the escapes \n \r \t \\ \" are accepted). Nothing is ever
// expanded. Errors name the line, never its content.
func ParseFile(b []byte) ([]Entry, error) {
	if len(b) > MaxBytes+4096 || !utf8.Valid(b) {
		return nil, errors.New("invalid dotenv size or encoding")
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	var out []Entry
	line := 1
	bad := func() ([]Entry, error) { return nil, fmt.Errorf("unsupported literal assignment on line %d", line) }
	for len(s) > 0 {
		if s[0] == '\n' {
			s = s[1:]
			line++
			continue
		}
		end := strings.IndexByte(s, '\n')
		if end < 0 {
			end = len(s)
		}
		if s[0] == '#' {
			s = s[end:]
			continue
		}
		k, rest, ok := strings.Cut(s[:end], "=")
		if !ok || !SafeName(k) {
			return bad()
		}
		var v string
		if rest != "" && (rest[0] == '\'' || rest[0] == '"') {
			quote := rest[0]
			body := s[len(k)+2:]
			var sb strings.Builder
			i, start := 0, line
			for {
				if i >= len(body) {
					line = start
					return bad()
				}
				c := body[i]
				i++
				if c == quote {
					break
				}
				if c == '\n' {
					line++
				}
				if c == '\\' && quote == '"' {
					if i >= len(body) {
						line = start
						return bad()
					}
					e := strings.IndexByte(`nrt\"`, body[i])
					if e < 0 {
						return bad()
					}
					c = "\n\r\t\\\""[e]
					i++
				}
				sb.WriteByte(c)
			}
			v = sb.String()
			tail := body[i:]
			end = strings.IndexByte(tail, '\n')
			if end < 0 {
				end = len(tail)
			}
			if strings.Trim(tail[:end], " \t") != "" {
				return bad()
			}
			s = tail[end:]
		} else {
			if strings.ContainsAny(rest, "\r\x00\"'`$\\#") || strings.TrimSpace(rest) != rest {
				return bad()
			}
			v = rest
			s = s[end:]
		}
		out = append(out, Entry{k, v})
	}
	return out, Validate(out)
}

// FileBytes renders the portable literal subset only: `checkout` refuses a
// value that file readers disagree about (spaces, quotes, newlines, ...).
func FileBytes(e []Entry) ([]byte, error) {
	if err := Validate(e); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, x := range e {
		if strings.ContainsAny(x.Value, "\r\n") {
			return nil, fmt.Errorf("%s is a multi-line value: a literal .env file cannot carry it; use `aqmas run` or `aqmas checkout-shell`", x.Name)
		}
		for _, c := range x.Value {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_./:@%+,=-", c)) {
				return nil, fmt.Errorf("%s needs process delivery: not a portable literal dotenv value", x.Name)
			}
		}
		fmt.Fprintf(&b, "%s=%s\n", x.Name, x.Value)
	}
	return b.Bytes(), nil
}
