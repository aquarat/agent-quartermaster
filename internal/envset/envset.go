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
	if len(e.Salt) != 32 || Validate(e.Entries) != nil || b.Revision < 0 || !(e.Op == "import" || e.Op == "put" && len(e.Entries) == 1 || e.Op == "unset" && len(e.Entries) == 1 && e.Entries[0].Value == "") {
		return "", errors.New("invalid edit")
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
	out := make([]Entry, 0, len(m))
	for k, v := range m {
		out = append(out, Entry{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, Validate(out)
}
func ParseFile(b []byte) ([]Entry, error) {
	if len(b) > MaxBytes || !utf8.Valid(b) {
		return nil, errors.New("invalid dotenv size or encoding")
	}
	var out []Entry
	for n, line := range bytes.Split(b, []byte{'\n'}) {
		s := strings.TrimSuffix(string(line), "\r")
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok || !SafeName(k) || strings.ContainsAny(v, "\r\n\x00\"'`$\\#") || strings.TrimSpace(v) != v {
			return nil, fmt.Errorf("unsupported literal assignment on line %d", n+1)
		}
		out = append(out, Entry{k, v})
	}
	return out, Validate(out)
}
func FileBytes(e []Entry) ([]byte, error) {
	if err := Validate(e); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, x := range e {
		for _, c := range x.Value {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_./:@%+,=-", c)) {
				return nil, fmt.Errorf("%s needs process delivery: not a portable literal dotenv value", x.Name)
			}
		}
		fmt.Fprintf(&b, "%s=%s\n", x.Name, x.Value)
	}
	return b.Bytes(), nil
}
