// Package maint is the maintenance runner behind Admin → Setup (docs/SETUP.md).
//
// aqmasd (unprivileged) writes one owner-signed request to a spool. The runner (root, started
// by a systemd path unit as `aqmasd maint-run`) treats the spool as hostile: it verifies the
// WebAuthn assertion against root-pinned passkeys, accepts only the tasks compiled in below
// with their small typed parameters, and never runs anything a request names.
package maint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/release"
)

// Task identifiers: the complete allowlist. "upgrade" is carried by the older "update"
// canonical object, which binds versions, commits and digests instead of parameters.
const (
	TaskCutover = "cutover"
	TaskSeal    = "seal"
	TaskBuckets = "buckets"
	TaskUpdates = "enable-updates"
	TaskPins    = "sync-passkeys"
	TaskUpgrade = "upgrade"
)

// Spec is the fixed, owner-facing description of a task. Nothing here comes from a request.
type Spec struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	Reversible string   `json:"reversible"`
	// Secrets are the only names a sealed packet for this task may carry.
	Secrets []string `json:"secrets,omitempty"`
}

// Specs lists the tasks in the order the Setup page shows them.
var Specs = []Spec{
	{ID: TaskCutover, Title: "Switch to organisations",
		Summary: "Moves this broker from the legacy single list to the organisations catalogue: your hosts, SSH targets and Cloudflare scopes become the “personal” organisation.",
		Steps: []string{"Stop the broker and wait for it to exit", "Back up the database, keys and configuration", "Start the broker fenced for review (agents are refused)",
			"You review the plan and activate it with your passkey", "Restart the broker and check it is healthy"},
		Reversible: "Until you activate, cancelling changes nothing. If the broker is unhealthy afterwards the backup is restored automatically. Later it is fix-forward only."},
	{ID: TaskSeal, Title: "Seal the store",
		Summary: "Encrypts the SSH CA, the internal CA key, the notification URL and the Cloudflare parent tokens under a key that only your passkey can unlock. After every restart the broker starts locked until you unlock it.",
		Steps: []string{"Stop the broker and back up", "Record the recovery key (public half) in the root-owned configuration", "Start the broker in import mode (agents are refused)",
			"You create and test the passkey wrap, prove the recovery key works, and activate", "Pin the activation, delete the plaintext key files and old backups", "Set up the lock alert if you gave it a credential", "Restart locked"},
		Reversible: "Until you activate, cancelling restores the configuration. After activation there is no way back to plaintext: recovery is your passkeys or the recovery key.",
		Secrets:    []string{"ntfy_topic_url", "ntfy_token"}},
	{ID: TaskBuckets, Title: "Move to per-credential buckets",
		Summary: "Moves a store sealed by aqmas 0.4.1 (one key for everything) to per-credential buckets: each approval then opens only the credentials it needs, and nothing is open after a restart.",
		Steps: []string{"Stop the broker and back up the database, keys and configuration", "Start the broker in migration mode (agents are refused)",
			"You open the old store once with a passkey, create and test its scope keys, prove the recovery key and activate", "Pin the new activation and restart the broker", "Delete the pre-migration and older backups unless you keep them"},
		Reversible: "No: one-way; the pre-migration backup is the way back if it fails before activation"},
	{ID: TaskUpdates, Title: "Enable self-update",
		Summary: "Prepares this machine to rebuild and install new releases itself, each one approved by you on this page.",
		Steps: []string{"Install build tools, the pinned Go and Bun toolchains and a locked build user", "Create the read-only deploy key and trust the forge's host key", "Store the release-reading tokens",
			"Check the installed broker against both published releases and cache the matching CLIs", "Add the update sources to the configuration and restart the broker"},
		Reversible: "The previous configuration is restored if the release check or the restart fails. Installed tools stay.",
		Secrets:    []string{"forgejo_token", "github_token"}},
	{ID: TaskPins, Title: "Sync maintenance passkeys",
		Summary:    "Replaces the root-owned list of passkeys that may approve tasks on this page with the passkeys listed here.",
		Steps:      []string{"Compare each listed passkey with the broker's record", "Replace the pinned list"},
		Reversible: "Run it again with another list. If no pinned passkey is left, re-pin from a terminal on the machine."},
	{ID: TaskUpgrade, Title: "Upgrade aqmas",
		Summary:    "Rebuilds the approved release from source in a sandbox, checks all four binaries against both published releases, installs the broker and restarts it.",
		Steps:      []string{"Verify the approval and both releases", "Fetch, build and test in a sandbox without network", "Install, restart and check health"},
		Reversible: "The previous binary is restored automatically if the new one is unhealthy. Database migrations are not reversed."},
}

// Lookup finds a compiled-in task.
func Lookup(id string) (Spec, bool) {
	for _, s := range Specs {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

// CutoverParams is empty: the plan is bound by the separate activation signature.
type CutoverParams struct{}

// SealParams. The age recipient is public; lock-alert credentials travel as sealed secrets.
type SealParams struct {
	Recipient    string `json:"recipient"`
	PurgeBackups bool   `json:"purge_backups"`
	LockAlert    bool   `json:"lock_alert"`
}

// BucketsParams: whether to delete the backups that still hold format-1 data afterwards.
type BucketsParams struct {
	PurgeBackups bool `json:"purge_backups"`
}

func (BucketsParams) validate() error { return nil }

// UpdatesParams names the release sources. The token flags say which sealed secrets follow.
type UpdatesParams struct {
	Repo         string   `json:"repo"`
	ForgejoAPI   string   `json:"forgejo_api"`
	GitHubAPI    string   `json:"github_api"`
	KnownHosts   []string `json:"known_hosts"`
	ForgejoToken bool     `json:"forgejo_token"`
	GitHubToken  bool     `json:"github_token"`
}

// Pin identifies one passkey by credential ID (base64url) and SHA-256 of its COSE public key.
type Pin struct {
	ID      string `json:"id"`
	KeyHash string `json:"key_sha256"`
}

// PinsParams is the complete new pin list.
type PinsParams struct {
	Pins []Pin `json:"pins"`
}

var (
	recipientRE = regexp.MustCompile(`^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$`)
	repoRE      = regexp.MustCompile(`^ssh://[a-z_][a-z0-9_-]{0,31}@([a-z0-9][a-z0-9.-]{0,252})(:[0-9]{1,5})?/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\.git$`)
	apiRE       = regexp.MustCompile(`^https?://[A-Za-z0-9.:-]{1,255}/[A-Za-z0-9._/-]{1,200}$`)
	hostKeyRE   = regexp.MustCompile(`^(\[[a-z0-9][a-z0-9.-]{0,252}\]:[0-9]{1,5}|[a-z0-9][a-z0-9.-]{0,252}) (ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) [A-Za-z0-9+/]{40,1000}={0,2}$`)
	credIDRE    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	tokenRE     = regexp.MustCompile(`^[A-Za-z0-9_.~+/=:-]{8,512}$`)
	topicRE     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?/[A-Za-z0-9_-]{1,128}$`)
)

// KnownHost returns the host name a known_hosts line must carry for an ssh:// repo URL.
func KnownHost(repo string) string {
	m := repoRE.FindStringSubmatch(repo)
	if m == nil {
		return ""
	}
	if m[2] == "" || m[2] == ":22" {
		return m[1]
	}
	return "[" + m[1] + "]" + m[2]
}

func (p SealParams) validate() error {
	if !recipientRE.MatchString(p.Recipient) {
		return errors.New("recipient must be a native age X25519 public key (age1…)")
	}
	return nil
}

func (p UpdatesParams) validate() error {
	host := KnownHost(p.Repo)
	if host == "" {
		return errors.New("repo must look like ssh://git@forge.example.com/owner/name.git")
	}
	for _, u := range []string{p.ForgejoAPI, p.GitHubAPI} {
		if !apiRE.MatchString(u) || !release.SafeURL(u) || strings.Contains(u, "..") {
			return errors.New("release API must be a plain https URL")
		}
	}
	if !strings.Contains(p.ForgejoAPI, "/api/v1/repos/") {
		return errors.New("Forgejo API must contain /api/v1/repos/")
	}
	if len(p.KnownHosts) == 0 || len(p.KnownHosts) > 4 || !slices.IsSorted(p.KnownHosts) || len(slices.Compact(slices.Clone(p.KnownHosts))) != len(p.KnownHosts) {
		return errors.New("one to four sorted, distinct known_hosts lines required")
	}
	for _, line := range p.KnownHosts {
		if !hostKeyRE.MatchString(line) || !strings.HasPrefix(line, host+" ") {
			return fmt.Errorf("known_hosts lines must be “%s <key type> <key>”", host)
		}
	}
	return nil
}

func (p PinsParams) validate() error {
	if len(p.Pins) == 0 || len(p.Pins) > 32 {
		return errors.New("one to 32 pins required")
	}
	seen := map[string]bool{}
	for _, k := range p.Pins {
		if len(k.ID) < 16 || len(k.ID) > 1366 || !credIDRE.MatchString(k.ID) || !release.ValidHash(k.KeyHash) || seen[k.ID] {
			return errors.New("invalid or duplicate pin")
		}
		seen[k.ID] = true
	}
	return nil
}

type validator interface{ validate() error }

func (CutoverParams) validate() error { return nil }

// Canonical returns the one accepted encoding of a task's parameters.
func Canonical(task string, v any) (string, error) {
	want, err := blank(task)
	if err != nil {
		return "", err
	}
	if fmt.Sprintf("%T", v) != fmt.Sprintf("%T", want) {
		return "", errors.New("parameters do not belong to this task")
	}
	if err := v.(validator).validate(); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func blank(task string) (any, error) {
	switch task {
	case TaskCutover:
		return CutoverParams{}, nil
	case TaskSeal:
		return SealParams{}, nil
	case TaskBuckets:
		return BucketsParams{}, nil
	case TaskUpdates:
		return UpdatesParams{}, nil
	case TaskPins:
		return PinsParams{}, nil
	}
	return nil, errors.New("unknown setup task")
}

// Parse accepts only the canonical encoding of the named task's parameters: unknown keys,
// another key order, extra whitespace or a value outside the task's schema are all refused.
func Parse(task, text string) (any, error) {
	var v any
	var err error
	strict := func(dst any) error {
		d := json.NewDecoder(strings.NewReader(text))
		d.DisallowUnknownFields()
		if e := d.Decode(dst); e != nil {
			return errors.New("invalid task parameters")
		}
		if d.More() {
			return errors.New("invalid task parameters")
		}
		return nil
	}
	switch task {
	case TaskCutover:
		var p CutoverParams
		err, v = strict(&p), p
	case TaskSeal:
		var p SealParams
		err, v = strict(&p), p
	case TaskBuckets:
		var p BucketsParams
		err, v = strict(&p), p
	case TaskUpdates:
		var p UpdatesParams
		err, v = strict(&p), p
		if err == nil && p.KnownHosts == nil {
			err = errors.New("invalid task parameters")
		}
	case TaskPins:
		var p PinsParams
		err, v = strict(&p), p
	default:
		return nil, errors.New("unknown setup task")
	}
	if err != nil {
		return nil, err
	}
	again, err := Canonical(task, v)
	if err != nil {
		return nil, err
	}
	if again != text {
		return nil, errors.New("task parameters are not canonical")
	}
	return v, nil
}

// SecretNames returns the secrets a task with these parameters must carry, sorted.
func SecretNames(task string, params any) []string {
	var out []string
	switch p := params.(type) {
	case SealParams:
		if p.LockAlert {
			out = []string{"ntfy_token", "ntfy_topic_url"}
		}
	case UpdatesParams:
		if p.ForgejoToken {
			out = append(out, "forgejo_token")
		}
		if p.GitHubToken {
			out = append(out, "github_token")
		}
	}
	return out
}

func validSecret(name, value string) bool {
	switch name {
	case "ntfy_topic_url":
		u, err := url.Parse(value)
		return topicRE.MatchString(value) && err == nil && u.User == nil
	case "ntfy_token", "forgejo_token", "github_token":
		return tokenRE.MatchString(value)
	}
	return false
}
