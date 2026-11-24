package maint

import (
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

// The configuration is edited as text so comments and layout survive, and every edit is
// proved by parsing: the result must equal the old configuration with exactly the intended
// fields changed. Values written here were validated against strict patterns first, so
// quoting them cannot open a new key or table.

var errConfigShape = errors.New("the configuration file has a layout this task cannot edit safely; edit it by hand")

func checked(old *config.Config, raw []byte, change func(*config.Config)) ([]byte, error) {
	got, err := config.Parse(raw)
	if err != nil {
		return nil, errConfigShape
	}
	want := *old
	change(&want)
	if !reflect.DeepEqual(got, &want) {
		return nil, errConfigShape
	}
	return raw, nil
}

func ensureNewline(raw []byte) string {
	s := string(raw)
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// addSeal fences the installation for a seal import.
func addSeal(raw []byte, recipient string) ([]byte, error) {
	old, err := config.Parse(raw)
	if err != nil || old.Seal != (config.Seal{}) {
		return nil, errors.New("configuration already has a [seal] section")
	}
	out := ensureNewline(raw) + "\n[seal]\nrequired = true\nrecipient = " + strconv.Quote(recipient) + "\n"
	return checked(old, []byte(out), func(c *config.Config) { c.Seal = config.Seal{Required: true, Recipient: recipient} })
}

var recipientLine = regexp.MustCompile(`(?m)^[ \t]*recipient[ \t]*=[ \t]*"age1[a-z0-9]{58}"[ \t]*\n`)
var topicLine = regexp.MustCompile(`(?m)^[ \t]*(ntfy\.)?topic_url[ \t]*=[^\n]*\n`)

// pinSeal records the activation and retires the plaintext notification URL.
func pinSeal(raw []byte, manifest string) ([]byte, error) {
	old, err := config.Parse(raw)
	if err != nil || !old.Seal.Required || old.Seal.Manifest != "" {
		return nil, errors.New("configuration is not staged for sealing")
	}
	s := ensureNewline(raw)
	loc := recipientLine.FindAllStringIndex(s, -1)
	if len(loc) != 1 {
		return nil, errConfigShape
	}
	s = s[:loc[0][1]] + "manifest_sha256 = " + strconv.Quote(manifest) + "\n" + s[loc[0][1]:]
	if old.Ntfy.TopicURL != "" {
		loc = topicLine.FindAllStringIndex(s, -1)
		if len(loc) != 1 {
			return nil, errConfigShape
		}
		line := s[loc[0][0]:loc[0][1]]
		s = s[:loc[0][0]] + line[:strings.Index(line, "=")] + "= \"\"\n" + s[loc[0][1]:]
	}
	return checked(old, []byte(s), func(c *config.Config) { c.Seal.Manifest = manifest; c.Ntfy.TopicURL = "" })
}

var tableHeader = regexp.MustCompile(`(?m)^[ \t]*\[`)
var updatesHeader = regexp.MustCompile(`(?m)^[ \t]*\[updates(\.(forgejo|second|github))?\][ \t]*(#[^\n]*)?\n`)

// setUpdates replaces any [updates] tables with the given sources.
func setUpdates(raw []byte, u config.Updates) ([]byte, error) {
	old, err := config.Parse(raw)
	if err != nil {
		return nil, errConfigShape
	}
	s := ensureNewline(raw)
	for {
		loc := updatesHeader.FindStringIndex(s)
		if loc == nil {
			break
		}
		end := len(s)
		if next := tableHeader.FindStringIndex(s[loc[1]:]); next != nil {
			end = loc[1] + next[0]
		}
		s = s[:loc[0]] + s[end:]
	}
	q := strconv.Quote
	// A relocated cache or spool (test servers) is the operator's own setting: keep it.
	u.CacheDir, u.SpoolDir = old.Updates.CacheDir, old.Updates.SpoolDir
	// The operator's own check interval survives too.
	u.CheckMinutes = old.Updates.CheckMinutes
	s += "\n[updates]\nrepo = " + q(u.Repo) + "\n"
	if u.DeployKey != "" {
		s += "deploy_key = " + q(u.DeployKey) + "\n"
	}
	if u.CheckMinutes != 0 {
		s += "check_minutes = " + strconv.Itoa(u.CheckMinutes) + "\n"
	}
	if u.CacheDir != "" {
		s += "cache_dir = " + q(u.CacheDir) + "\n"
	}
	if u.SpoolDir != "" {
		s += "spool_dir = " + q(u.SpoolDir) + "\n"
	}
	s += "[updates.github]\napi = " + q(u.GitHub.API) + "\n"
	if u.GitHub.TokenFile != "" {
		s += "token_file = " + q(u.GitHub.TokenFile) + "\n"
	}
	// No second source, no table: nothing about one is written unless it is configured.
	if u.Second.API != "" {
		s += "[updates.second]\napi = " + q(u.Second.API) + "\n"
		if u.Second.TokenFile != "" {
			s += "token_file = " + q(u.Second.TokenFile) + "\n"
		}
	}
	return checked(old, []byte(s), func(c *config.Config) { c.Updates = u })
}

var manifestLine = regexp.MustCompile(`(?m)^[ \t]*manifest_sha256[ \t]*=[ \t]*"([0-9a-f]{64})"[ \t]*\n`)

// repinSeal replaces the activation pin (format 1 → format 2 after the move to buckets).
func repinSeal(raw []byte, old, manifest string) ([]byte, error) {
	cfg, err := config.Parse(raw)
	if err != nil || !cfg.Seal.Required || cfg.Seal.Manifest != old {
		return nil, errors.New("configuration does not pin the store being moved")
	}
	s := ensureNewline(raw)
	loc := manifestLine.FindAllStringSubmatchIndex(s, -1)
	if len(loc) != 1 || s[loc[0][2]:loc[0][3]] != old {
		return nil, errConfigShape
	}
	s = s[:loc[0][2]] + manifest + s[loc[0][3]:]
	return checked(cfg, []byte(s), func(c *config.Config) { c.Seal.Manifest = manifest })
}

var bastionHeader = regexp.MustCompile(`(?m)^[ \t]*\[bastion\][ \t]*(#[^\n]*)?\n`)

// removeBastion deletes the [bastion] table; the rest of the file is untouched.
func removeBastion(raw []byte) ([]byte, error) {
	old, err := config.Parse(raw)
	if err != nil {
		return nil, errConfigShape
	}
	if !old.Bastion.Enabled() {
		return raw, nil
	}
	s := ensureNewline(raw)
	loc := bastionHeader.FindAllStringIndex(s, -1)
	if len(loc) != 1 {
		return nil, errConfigShape
	}
	end := len(s)
	if next := tableHeader.FindStringIndex(s[loc[0][1]:]); next != nil {
		end = loc[0][1] + next[0]
	}
	s = s[:loc[0][0]] + s[end:]
	return checked(old, []byte(s), func(c *config.Config) { c.Bastion = config.Bastion{} })
}

// addBastion records this machine as a destination: the old configuration plus exactly the
// [bastion] table (replacing an earlier one). Parsing the result applies every rule of the
// configuration, name and principal collisions included, before anything else is touched.
func addBastion(raw []byte, b config.Bastion) ([]byte, error) {
	raw, err := removeBastion(raw)
	if err != nil {
		return nil, err
	}
	old, err := config.Parse(raw)
	if err != nil {
		return nil, errConfigShape
	}
	q := strconv.Quote
	out := ensureNewline(raw) + "\n[bastion]\nname = " + q(b.Name) + "\naddress = " + q(b.Address) + "\nport = " + strconv.Itoa(b.Port) +
		"\nadmin_user = " + q(b.AdminUser) + "\nhost_key = " + q(b.HostKey) + "\n"
	if _, err := config.Parse([]byte(out)); err != nil {
		// Say why: a name or principal that collides with a target is the owner's to fix.
		return nil, errors.New("the configuration would not be valid with this bastion entry: " + strings.TrimPrefix(err.Error(), "config: "))
	}
	return checked(old, []byte(out), func(c *config.Config) { c.Bastion = b })
}
