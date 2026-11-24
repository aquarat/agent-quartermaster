// Package maint is the maintenance runner behind Settings → Setup (docs/SETUP.md).
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
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/release"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
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
	// Access to the bastion itself and routine maintenance (docs/BASTION-ACCESS.md §3, §7).
	TaskBastionAccess = "bastion-access"
	TaskBastionRemove = "bastion-access-remove"
	TaskBastionAllow  = "bastion-allow"
	TaskOSUpdate      = "os-update"
	TaskReboot        = "reboot"
	TaskRestartTunnel = "restart-cloudflared"
	TaskRestartBroker = "restart-broker"
	TaskDiskUsage     = "disk-usage"
	TaskJournalVacuum = "journal-vacuum"
)

// Groups place a task on the page: "" is the Setup queue, the others Settings → Bastion access.
const (
	GroupBastion = "bastion"
	GroupRoutine = "routine"
)

// AgentTasks are the only tasks an enrolled host may queue for the owner's approval
// (POST /v1/setup-requests). Nothing here installs trust, changes who may approve, or
// changes what the bastion runs beyond the distribution's own package updates.
var AgentTasks = []string{TaskOSUpdate, TaskReboot, TaskRestartTunnel, TaskRestartBroker, TaskDiskUsage, TaskJournalVacuum}

// Spec is the fixed, owner-facing description of a task. Nothing here comes from a request.
type Spec struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	Reversible string   `json:"reversible"`
	// Secrets are the only names a sealed packet for this task may carry.
	Secrets []string `json:"secrets,omitempty"`
	// Group is where the page shows the task ("" = the Setup queue).
	Group string `json:"group,omitempty"`
	// Warning is shown in red above the approve button (a restart closes every bucket…).
	Warning string `json:"warning,omitempty"`
}

// Specs lists the tasks in the order the Setup page shows them.
var Specs = []Spec{
	{ID: TaskCutover, Title: "Switch to organisations",
		Summary: "Moves this broker from the legacy single list to the organisations catalogue: your hosts, SSH targets and Cloudflare scopes become the “personal” organisation.",
		Steps: []string{"Stop the broker and wait for it to exit", "Back up the database, keys and configuration", "Start the broker fenced for review (agents are refused)",
			"You review the plan and activate it with your passkey", "Restart the broker and check it is healthy"},
		Reversible: "Until you activate, cancelling changes nothing. If the broker is unhealthy afterwards the backup is restored automatically. Later it is fix-forward only."},
	{ID: TaskSeal, Title: "Seal the store",
		Summary: "Puts the SSH CA, the internal CA key and the Cloudflare proxy parent token each in its own encrypted bucket that only your passkey's approval opens, for as long as that approval needs it. After a restart nothing is open.",
		Steps: []string{"Stop the broker and back up", "Record the recovery key (public half) in the root-owned configuration", "Start the broker in import mode (agents are refused)",
			"You create and test your passkey's scope keys, prove the recovery key works, and activate", "Pin the activation, delete the plaintext key files and old backups", "Set up the lock alert if you gave it a credential", "Restart with nothing open"},
		Reversible: "Until you activate, cancelling restores the configuration. After activation there is no way back to plaintext: recovery is your passkeys or the recovery key.",
		Secrets:    []string{"ntfy_topic_url", "ntfy_token"}},
	{ID: TaskBuckets, Title: "Move to per-credential buckets",
		Summary: "Moves a store sealed by aqmas 0.4.1 (one key for everything) to per-credential buckets: each approval then opens only the credentials it needs, and nothing is open after a restart.",
		Steps: []string{"Stop the broker and back up the database, keys and configuration", "Start the broker in migration mode (agents are refused)",
			"You open the old store once with a passkey, create and test its scope keys, prove the recovery key and activate", "Pin the new activation and restart the broker", "Delete the pre-migration and older backups unless you keep them"},
		Reversible: "No — one-way; before activation the backup restores everything"},
	{ID: TaskUpdates, Title: "Enable self-update",
		Summary: "Prepares this machine to rebuild and install new releases itself, each one approved by you on this page.",
		Steps: []string{"Install build tools, the pinned Go and Bun toolchains and a locked build user", "For an SSH repository only: create the read-only deploy key and trust the forge's host key", "Store the release-reading tokens, if any",
			"Check the installed broker against the published release at GitHub (and at the second source when one is configured) and cache the matching CLIs", "Add the update sources to the configuration and restart the broker"},
		Reversible: "The previous configuration is restored if the release check or the restart fails. Installed tools stay.",
		Secrets:    []string{"github_token", "second_token"}},
	{ID: TaskPins, Title: "Sync maintenance passkeys",
		Summary:    "Replaces the root-owned list of passkeys that may approve tasks on this page with the passkeys listed here.",
		Steps:      []string{"Compare each listed passkey with the broker's record", "Replace the pinned list"},
		Reversible: "Run it again with another list. If no pinned passkey is left, re-pin from a terminal on the machine."},
	{ID: TaskUpgrade, Title: "Upgrade aqmas",
		Summary:    "Rebuilds the approved release from source in a sandbox, checks all four binaries against the published release (GitHub, and the second source when one is configured), installs the broker and restarts it.",
		Steps:      []string{"Verify the approval and the published release at every configured source", "Fetch, build and test in a sandbox without network", "Install, restart and check health"},
		Reversible: "The previous binary is restored automatically if the new one is unhealthy. Database migrations are not reversed."},
	{ID: TaskBastionAccess, Group: GroupBastion, Title: "Allow aqmas access to the bastion",
		Summary: "Makes this machine's own sshd accept aqmas certificates for two accounts: a read-only inspect account that can only run fixed log and status commands, and your admin account (root, behind a red card, from hosts you allow). Your emergency keys are not touched and stay the way in when aqmas is down.",
		Steps: []string{"Check the admin account and the SSH CA against what you signed", "Create the confined inspect account", "Install the CA, the two principals files and the forced-command block; validate and reload sshd",
			"Record this machine as a destination in the configuration", "Restart the broker and check it is healthy"},
		Reversible: "Yes: “Remove aqmas access to the bastion”. If a check fails, the previous sshd files and configuration are restored.",
		Warning:    "Restarts the broker: every open bucket closes and every approval window ends."},
	{ID: TaskBastionRemove, Group: GroupBastion, Title: "Remove aqmas access to the bastion",
		Summary: "Stops this machine's sshd from accepting aqmas certificates and deletes the inspect account. Afterwards only your emergency key gets in.",
		Steps: []string{"Remove this machine as a destination from the configuration and restart the broker", "Remove the CA, principals files and forced-command block; validate and reload sshd",
			"End the inspect account's sessions and delete the account"},
		Reversible: "Yes: allow access again. A root session that is already open is an ordinary login of your admin account and is not ended.",
		Warning:    "Restarts the broker: every open bucket closes and every approval window ends."},
	{ID: TaskBastionAllow, Group: GroupBastion, Title: "Set who may ask for root on the bastion",
		Summary:    "Replaces the list of enrolled hosts that may ask for a root session with the hosts listed here. The list is kept by root, not by the broker, and this machine's sshd accepts a root certificate only from the listed addresses.",
		Steps:      []string{"Write the root-owned list", "Rewrite the admin account's principals file with the listed addresses"},
		Reversible: "Run it again with another list. An empty list means nobody can ask for root."},
	{ID: TaskOSUpdate, Group: GroupRoutine, Title: "Update system packages",
		Summary:    "Installs the distribution's pending package updates (dnf upgrade) and reports what changed. The kernel and the boot chain are left alone unless you allow them.",
		Steps:      []string{"Record the installed packages and the boot files", "Run dnf upgrade outside the runner's sandbox", "Compare before and after; fail if the kernel, boot chain or boot files changed without your permission", "Check sshd still confines the inspect account"},
		Reversible: "No. Undo by hand on the machine (dnf history undo)."},
	{ID: TaskReboot, Group: GroupRoutine, Title: "Reboot the bastion",
		Summary:    "Restarts the whole machine.",
		Steps:      []string{"Record the request", "Reboot"},
		Reversible: "No.",
		Warning:    "The bastion comes back with nothing open: every bucket closed, every approval window ended, standing rules paused until the next approval. Approvals are unavailable for a minute or two."},
	{ID: TaskRestartTunnel, Group: GroupRoutine, Title: "Restart cloudflared",
		Summary:    "Restarts the tunnel connector that publishes this page.",
		Steps:      []string{"Restart the tunnel service", "Check it is running"},
		Reversible: "Nothing to undo.",
		Warning:    "This page is unreachable for a few seconds."},
	{ID: TaskRestartBroker, Group: GroupRoutine, Title: "Restart aqmasd",
		Summary:    "Stops and starts the broker.",
		Steps:      []string{"Stop the broker and wait for it to exit", "Start it and check it is healthy"},
		Reversible: "Nothing to undo.",
		Warning:    "The broker comes back with nothing open: every bucket closed, every approval window ended."},
	{ID: TaskDiskUsage, Group: GroupRoutine, Title: "Show disk and journal usage",
		Summary:    "Reports free space on the system and data file systems and the size of the journal. Changes nothing.",
		Steps:      []string{"Measure"},
		Reversible: "Read-only."},
	{ID: TaskJournalVacuum, Group: GroupRoutine, Title: "Rotate and trim the journal",
		Summary:    "Rotates the system journal and deletes entries older than the number of days you choose.",
		Steps:      []string{"Rotate the journal", "Delete entries older than the chosen age", "Report the space freed"},
		Reversible: "No: deleted log entries are gone."},
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

// UpdatesParams names the release sources. SecondAPI is "" without a second source;
// KnownHosts is empty unless Repo is an SSH remote. The token flags say which sealed secrets
// follow.
type UpdatesParams struct {
	Repo        string   `json:"repo"`
	GitHubAPI   string   `json:"github_api"`
	SecondAPI   string   `json:"second_api"`
	KnownHosts  []string `json:"known_hosts"`
	GitHubToken bool     `json:"github_token"`
	SecondToken bool     `json:"second_token"`
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

// BastionAccessParams describes this machine as a destination. SSHCA is the fingerprint of
// the SSH user CA the owner read on the card: the runner trusts no other key.
type BastionAccessParams struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	AdminUser string `json:"admin_user"`
	SSHCA     string `json:"ssh_ca"`
}

// AllowedHost is one enrolled host that may ask for root on the bastion: its enrollment ID,
// its name (for people) and the one address its requests and logins must come from.
type AllowedHost struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// BastionAllowParams is the complete new allowlist, sorted by enrollment ID.
type BastionAllowParams struct {
	Hosts []AllowedHost `json:"hosts"`
}

var enrollmentRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func (p BastionAllowParams) validate() error {
	if p.Hosts == nil || len(p.Hosts) > 32 {
		return errors.New("hosts must be a list of at most 32 entries (empty to allow nobody)")
	}
	for i, h := range p.Hosts {
		ip, err := netip.ParseAddr(h.Address)
		if !enrollmentRE.MatchString(h.ID) || !config.ValidName(h.Name) || err != nil || ip.String() != h.Address || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("each host needs its enrollment id, name and a literal IP address")
		}
		if i > 0 && p.Hosts[i-1].ID >= h.ID {
			return errors.New("hosts must be sorted by enrollment id, without duplicates")
		}
	}
	return nil
}

// AgentAllowed says whether an enrolled host may queue this task with these parameters.
// Beyond the task list: no kernel or boot-chain updates, and no journal trim that would
// delete the last week (the record of a recent session on the bastion).
func AgentAllowed(task string, params any) error {
	if !slices.Contains(AgentTasks, task) {
		return errors.New("this task can only be started by the owner on the approval page")
	}
	switch p := params.(type) {
	case OSUpdateParams:
		if p.Kernel {
			return errors.New("only the owner can start an update that includes the kernel and boot chain")
		}
	case JournalVacuumParams:
		if p.KeepDays < 7 {
			return errors.New("a queued journal trim keeps at least 7 days")
		}
	}
	return nil
}

// OSUpdateParams: Kernel allows kernel packages and the default boot entry to change.
type OSUpdateParams struct {
	Kernel bool `json:"kernel"`
}

// JournalVacuumParams: entries older than KeepDays days are deleted.
type JournalVacuumParams struct {
	KeepDays int `json:"keep_days"`
}

// Parameterless tasks. Distinct types, so the runner dispatches on the type alone.
type (
	BastionRemoveParams struct{}
	RebootParams        struct{}
	RestartTunnelParams struct{}
	RestartBrokerParams struct{}
	DiskUsageParams     struct{}
)

func (BastionRemoveParams) validate() error { return nil }
func (RebootParams) validate() error        { return nil }
func (RestartTunnelParams) validate() error { return nil }
func (RestartBrokerParams) validate() error { return nil }
func (DiskUsageParams) validate() error     { return nil }
func (OSUpdateParams) validate() error      { return nil }

func (p JournalVacuumParams) validate() error {
	if p.KeepDays < 1 || p.KeepDays > 365 {
		return errors.New("keep_days must be between 1 and 365")
	}
	return nil
}

var caFingerprintRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func (p BastionAccessParams) validate() error {
	// The same rules the configuration applies, so a signed request can never produce a
	// configuration the broker refuses to start with.
	ip, err := netip.ParseAddr(p.Address)
	if !config.ValidName(p.Name) || err != nil || ip.String() != p.Address || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("name must be a plain host name and address a literal IP address")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("port out of range")
	}
	if !config.ValidUser(p.AdminUser) || config.ReservedBastionUser(p.AdminUser) {
		return errors.New("admin_user must be your own account: not root and not one of aqmas's accounts")
	}
	if !caFingerprintRE.MatchString(p.SSHCA) {
		return errors.New("ssh_ca must be the SHA256 fingerprint of the SSH user CA")
	}
	return nil
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
	proto := release.GitProtocol(p.Repo)
	if proto == "" {
		return errors.New("repo must look like https://github.com/owner/name.git or ssh://git@forge.example.com/owner/name.git")
	}
	apis := []string{p.GitHubAPI}
	if p.SecondAPI != "" {
		apis = append(apis, p.SecondAPI)
		if !strings.Contains(p.SecondAPI, "/api/v1/repos/") {
			return errors.New("the second source's API must contain /api/v1/repos/")
		}
	} else if p.SecondToken {
		return errors.New("a second-source token needs a second source")
	}
	for _, u := range apis {
		if !apiRE.MatchString(u) || !release.ValidAPI(u) {
			return errors.New("release API must be a plain https URL")
		}
	}
	if proto != "ssh" {
		// An HTTPS remote is checked against the system's certificate authorities.
		if len(p.KnownHosts) != 0 {
			return errors.New("known_hosts lines are only for an SSH repository")
		}
		return nil
	}
	host := KnownHost(p.Repo)
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
	case TaskBastionAccess:
		return BastionAccessParams{}, nil
	case TaskBastionRemove:
		return BastionRemoveParams{}, nil
	case TaskBastionAllow:
		return BastionAllowParams{}, nil
	case TaskOSUpdate:
		return OSUpdateParams{}, nil
	case TaskReboot:
		return RebootParams{}, nil
	case TaskRestartTunnel:
		return RestartTunnelParams{}, nil
	case TaskRestartBroker:
		return RestartBrokerParams{}, nil
	case TaskDiskUsage:
		return DiskUsageParams{}, nil
	case TaskJournalVacuum:
		return JournalVacuumParams{}, nil
	}
	return nil, errors.New("unknown setup task")
}

// Decode reads a task's parameters from JSON in any key order (what a browser or the CLI
// sends) into the task's typed schema: unknown keys and trailing data are refused. Only the
// tasks added with bastion access use it; Canonical then validates the values.
func Decode(task string, raw []byte) (any, error) {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	strict := func(dst any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if e := d.Decode(dst); e != nil || d.More() {
			return errors.New("invalid task parameters")
		}
		return nil
	}
	var v any
	var err error
	switch task {
	case TaskBastionAccess:
		var p BastionAccessParams
		err, v = strict(&p), p
	case TaskBastionRemove:
		var p BastionRemoveParams
		err, v = strict(&p), p
	case TaskBastionAllow:
		var p BastionAllowParams
		err, v = strict(&p), p
	case TaskOSUpdate:
		var p OSUpdateParams
		err, v = strict(&p), p
	case TaskReboot:
		var p RebootParams
		err, v = strict(&p), p
	case TaskRestartTunnel:
		var p RestartTunnelParams
		err, v = strict(&p), p
	case TaskRestartBroker:
		var p RestartBrokerParams
		err, v = strict(&p), p
	case TaskDiskUsage:
		var p DiskUsageParams
		err, v = strict(&p), p
	case TaskJournalVacuum:
		var p JournalVacuumParams
		err, v = strict(&p), p
	default:
		return nil, errors.New("unknown setup task")
	}
	if err != nil {
		return nil, err
	}
	return v, nil
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
		// Decode knows the bastion and routine tasks; the canonical round trip below is
		// what refuses another key order, whitespace or an absent key.
		v, err = Decode(task, []byte(text))
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
		if p.GitHubToken {
			out = append(out, "github_token")
		}
		if p.SecondToken {
			out = append(out, "second_token")
		}
	}
	return out
}

func validSecret(name, value string) bool {
	switch name {
	case "ntfy_topic_url":
		u, err := url.Parse(value)
		return topicRE.MatchString(value) && err == nil && u.User == nil
	case "ntfy_token", "github_token", "second_token":
		return tokenRE.MatchString(value)
	}
	return false
}
