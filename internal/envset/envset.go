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

// Proposal is a host's request to store values (docs/API.md "Env proposals"):
// the binding the edit applies to (for a new set the proposed IDs, revision 0
// and no names), what it changes by name, and its state. It carries no value.
// The field order is the signed order: the page rebuilds the reviewed text
// from it.
type Proposal struct {
	Binding
	ID         string `json:"id"`
	Ref        string `json:"ref"`
	Operation  string `json:"operation"`
	Commitment string `json:"commitment"`
	Changes    string `json:"changes"`
	Reason     string `json:"reason"`
	Peer       string `json:"address"`
	NewService bool   `json:"new_service"`
	NewSet     bool   `json:"new_set"`
	Status     string `json:"status"`
	Created    int64  `json:"created_at"`
	Expires    int64  `json:"expires_at"`
	Result     int    `json:"result_revision"`
}

// ProposalCreate asks for a set (and, with ServiceID, a service) that does
// not exist yet; the host chooses the IDs so that its commitment covers them.
type ProposalCreate struct {
	ServiceID string `json:"service_id"`
	SetID     string `json:"set_id"`
	Title     string `json:"title"`
}

// ProposalRequest is the body of POST /v2/env/proposals.
type ProposalRequest struct {
	Path       string          `json:"path"`
	Reason     string          `json:"reason"`
	Edit       Edit            `json:"edit"`
	Commitment string          `json:"commitment"`
	Create     *ProposalCreate `json:"create"`
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
	for len(s) > 0 {
		a := nextAssignment(s, line)
		if a.why != "" {
			return nil, fmt.Errorf("unsupported literal assignment on line %d", a.at)
		}
		if a.ok {
			out = append(out, Entry{a.name, a.value})
		}
		s, line = a.rest, a.next
	}
	return out, Validate(out)
}

// assignment is one step of the dotenv scanner: a blank line, a comment, an
// entry (ok) or a refusal (why, noticed on line at). After a refusal inside a
// quoted value the rest of the file cannot be read (fatal).
type assignment struct {
	ok          bool
	name, value string
	rest        string
	next        int // the line rest starts on (a comment leaves its newline in rest)
	at          int
	why         string
	fatal       bool
}

func nextAssignment(s string, line int) assignment {
	skip := func(at int, why string) assignment {
		// The refused line is dropped whole, so a checker can go on with the next.
		rest := ""
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			rest = s[i:]
		}
		return assignment{rest: rest, next: line, at: at, why: why}
	}
	if s[0] == '\n' {
		return assignment{rest: s[1:], next: line + 1}
	}
	end := strings.IndexByte(s, '\n')
	if end < 0 {
		end = len(s)
	}
	if s[0] == '#' {
		return assignment{rest: s[end:], next: line}
	}
	k, rest, ok := strings.Cut(s[:end], "=")
	if !ok {
		return skip(line, "not a NAME=value line")
	}
	if !SafeName(k) {
		return skip(line, "aqmas does not deliver under this name ("+NameRule+")")
	}
	if rest == "" || rest[0] != '\'' && rest[0] != '"' {
		if strings.ContainsAny(rest, "\r\x00\"'`$\\#") || strings.TrimSpace(rest) != rest {
			return skip(line, "a bare value cannot hold quotes, backslash, $, backtick, # or surrounding space: put it in single quotes")
		}
		return assignment{ok: true, name: k, value: rest, rest: s[end:], next: line}
	}
	quote := rest[0]
	body := s[len(k)+2:]
	var sb strings.Builder
	i, start := 0, line
	for {
		if i >= len(body) {
			return assignment{at: start, why: "the quoted value that starts here is never closed", fatal: true}
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
				return assignment{at: start, why: "the quoted value that starts here is never closed", fatal: true}
			}
			e := strings.IndexByte(`nrt\"`, body[i])
			if e < 0 {
				return assignment{at: line, why: `a double-quoted value accepts only the escapes \n \r \t \\ \": use single quotes for literal text`, fatal: true}
			}
			c = "\n\r\t\\\""[e]
			i++
		}
		sb.WriteByte(c)
	}
	tail := body[i:]
	end = strings.IndexByte(tail, '\n')
	if end < 0 {
		end = len(tail)
	}
	if strings.Trim(tail[:end], " \t") != "" {
		return assignment{rest: tail[end:], next: line, at: line, why: "text after the closing quote"}
	}
	return assignment{ok: true, name: k, value: sb.String(), rest: tail[end:], next: line}
}

// NameRule says which names aqmas delivers (SafeName), for messages.
const NameRule = "capital letters, digits and underscores, starting with APP_ or ending in _TOKEN, _KEY, _PASSWORD, _SECRET, _URL, _DSN, _USER, _USERNAME or _ID; never a name a shell, loader or tool reads as configuration"

// Problem is one reason a file would not import. Line is 0 for the file as a
// whole. Neither field ever holds a value or any other text from the file.
type Problem struct {
	Line int
	Why  string
}

func (p Problem) String() string {
	if p.Line == 0 {
		return p.Why
	}
	return fmt.Sprintf("line %d: %s", p.Line, p.Why)
}

// CheckFile validates a dotenv file against the import rules (ParseFile) and
// reports every problem it can find instead of the first. names are the keys
// of the lines that would import, in file order. The file imports exactly
// when there are no problems. Nothing returned contains a value: a refused
// line is named by its number only, because what looks like its name may be
// part of a value.
func CheckFile(b []byte) (names []string, problems []Problem) {
	if len(b) > MaxBytes+4096 {
		return nil, []Problem{{0, fmt.Sprintf("the file is larger than an env set may be (%d bytes of names and values)", MaxBytes)}}
	}
	if !utf8.Valid(b) {
		return nil, []Problem{{0, "the file is not UTF-8 text"}}
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	seen := map[string]bool{}
	line, size := 1, 0
	for len(s) > 0 {
		a := nextAssignment(s, line)
		switch {
		case a.why != "":
			problems = append(problems, Problem{a.at, a.why})
			if a.fatal {
				problems = append(problems, Problem{0, fmt.Sprintf("nothing after line %d was checked", a.at)})
				return names, problems
			}
		case a.ok && seen[a.name]:
			problems = append(problems, Problem{line, "this name is already set on an earlier line"})
		case a.ok && (len(a.value) > 8192 || strings.ContainsRune(a.value, 0)):
			problems = append(problems, Problem{line, "the value is longer than 8192 bytes or holds a NUL byte"})
		case a.ok:
			seen[a.name] = true
			names = append(names, a.name)
			size += len(a.name) + len(a.value)
		}
		s, line = a.rest, a.next
	}
	if len(names) > 64 {
		problems = append(problems, Problem{0, "more than 64 keys"})
	}
	if size > MaxBytes {
		problems = append(problems, Problem{0, fmt.Sprintf("names and values together are larger than %d bytes", MaxBytes)})
	}
	return names, problems
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
