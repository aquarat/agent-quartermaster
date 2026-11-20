// Package organisations describes the personal catalogue proposed by a v0.1.1
// cutover. Planning has no access to the CF loader, notification or issuer APIs.
package organisations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/cfscope"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

const (
	SourceSchema = 5 // includes the signed enrollment class
	MaxPlanBytes = 128 << 10
	maxRows      = 512
)

type Object struct {
	ID    string `json:"id"`
	Slug  string `json:"slug"`
	Title string `json:"title"`
}

type Set struct {
	Object
	Kind   string         `json:"kind"`
	Target *config.Target `json:"ssh_target,omitempty"`
}

type Service struct {
	Object
	Sets []Set `json:"sets"`
}

type Admission struct {
	HostID      int64  `json:"host_id"`
	Enrollment  string `json:"enrollment_id"`
	Fingerprint string `json:"certificate_sha256"`
	Name        string `json:"name"`
	Class       string `json:"class"`
	NotAfter    int64  `json:"not_after_ms"`
}

// Outstanding includes revoked SSH grants as their certs cannot be recalled.
// Missing token_id after a mint claim is not evidence that no child exists.
type Outstanding struct {
	Grant    string `json:"grant_id"`
	Host     int64  `json:"host_id"`
	Kind     string `json:"kind"`
	NotAfter int64  `json:"not_after_ms"`
	TokenID  string `json:"child_id,omitempty"`
}

type Retirement struct {
	PendingRequests    []string      `json:"expire_requests"`
	PendingEnrollments []string      `json:"expire_enrollments"`
	ActiveGrants       []string      `json:"revoke_grants"`
	Standing           []string      `json:"revoke_standing"`
	Outstanding        []Outstanding `json:"outstanding_certificates_and_unverified_children"`
	GrantSerial        int64         `json:"preserve_grant_high_water"`
	ActionChallenges   string        `json:"expire_challenges"`
	History            string        `json:"legacy_history"`
}

type Plan struct {
	Source         int        `json:"source_schema"`
	Organisation   Object     `json:"organisation"`
	Owner          Object     `json:"owner_approver"`
	OwnerHandle    string     `json:"owner_webauthn_id_hex"`
	Passkeys       []string   `json:"owner_passkeys"`
	SSHCAPin       string     `json:"ssh_ca_fingerprint"`
	ClientCAPin    string     `json:"tls_ca_pin"`
	ApprovalOrigin string     `json:"approval_origin"`
	TTL            config.TTL `json:"legacy_ttl_policy"`
	Services       []Service  `json:"services"`
	// Cloudflare config contains credential references, never their contents.
	Cloudflare *config.Cloudflare `json:"cloudflare_public_config,omitempty"`
	Scopes     []api.CFScopeInfo  `json:"effective_cf_scopes,omitempty"`
	ConfigHash string             `json:"public_config_sha256"`
	Admissions []Admission        `json:"admit_to_personal_only"`
	Retire     Retirement         `json:"retire"`
}

// Namespaced by installation handle. Stable even when a repeat dry run is
// made against another backup. Never use the mutable slug to look up a grant.
func object(handle []byte, path, title string) Object {
	h := sha256.New()
	fmt.Fprintf(h, "aqmas.personal.v1\x00%x\x00%s", handle, path)
	i := strings.LastIndexByte(path, '/')
	return Object{hex.EncodeToString(h.Sum(nil)[:16]), path[i+1:], title}
}

func configPlan(cfg *config.Config, handle []byte, sshPin, clientPin string) (*Plan, error) {
	p := &Plan{Source: SourceSchema, Organisation: object(handle, "personal", "personal"), Owner: object(handle, "owner", cfg.OwnerName), OwnerHandle: hex.EncodeToString(handle),
		SSHCAPin: sshPin, ClientCAPin: clientPin, ApprovalOrigin: cfg.PublicBaseURL, TTL: cfg.TTL, Services: []Service{}}
	fleet := Service{Object: object(handle, "personal/fleet", "fleet"), Sets: []Set{}}
	for _, t := range cfg.Targets {
		fleet.Sets = append(fleet.Sets, Set{object(handle, "personal/fleet/"+t.Name, t.Name), "ssh-ca", &t})
	}
	slices.SortFunc(fleet.Sets, func(a, b Set) int { return strings.Compare(a.Slug, b.Slug) })
	p.Services = append(p.Services, fleet)
	cf := &cfg.Cloudflare
	if cf.Enabled {
		// Never print URLs containing embedded credentials or query tokens.
		u, err := url.Parse(cf.APIBase)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("cloudflare API base must not contain credentials, query or fragment")
		}
		cat, err := cfscope.NewCatalogue(cf)
		if err != nil {
			return nil, err
		}
		p.Cloudflare = cf
		p.Scopes = cat.API().Scopes
		dns := Service{Object: object(handle, "personal/dns-cdn", "dns-cdn"), Sets: []Set{{object(handle, "personal/dns-cdn/proxy", "proxy"), "cloudflare-proxy", nil}}}
		for i, sc := range p.Scopes {
			if cf.MinterTokenCredential == "" && cf.MinterTokenFile == "" {
				p.Scopes[i].Modes = []string{api.CFModeProxy}
				continue
			}
			if slices.Contains(sc.Modes, api.CFModeToken) {
				dns.Sets = append(dns.Sets, Set{object(handle, "personal/dns-cdn/mint", "mint"), "cloudflare-mint", nil})
				break
			}
		}
		p.Services = append(p.Services, dns)
	}
	// Fingerprint only the proposed public catalogue. Exclude the DB
	// inventory: at restart an enrollment or grant change is not config drift.
	b, err := json.Marshal(struct {
		SSH, TLS, Origin string
		TTL              config.TTL
		Services         []Service
		Cloudflare       *config.Cloudflare
		Scopes           []api.CFScopeInfo
	}{sshPin, clientPin, cfg.PublicBaseURL, cfg.TTL, p.Services, p.Cloudflare, p.Scopes})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	p.ConfigHash = hex.EncodeToString(h[:])
	return p, nil
}

var ErrTooLarge = errors.New("organisation migration plan too large for a single review")

// scan limits each inventory independently and never accepts a truncated plan.
func scan(ctx context.Context, tx *sql.Tx, query string, visit func(*sql.Rows) error, args ...any) error {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for n := 0; rows.Next(); n++ {
		if n >= maxRows {
			return ErrTooLarge
		}
		if err := visit(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Inventory reads every input in a single database snapshot. Call with a
// validated config and the public fingerprints from its matching CA backup.
func Inventory(ctx context.Context, tx *sql.Tx, cfg *config.Config, sshPin, clientPin string, now time.Time) (*Plan, error) {
	var schema int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schema); err != nil {
		return nil, err
	}
	if schema != SourceSchema {
		return nil, fmt.Errorf("personal inventory requires schema %d; found %d", SourceSchema, schema)
	}
	var handle []byte
	if err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='owner_webauthn_id'`).Scan(&handle); err != nil {
		return nil, err
	}
	if len(handle) != 32 {
		return nil, errors.New("invalid owner WebAuthn handle")
	}
	p, err := configPlan(cfg, handle, sshPin, clientPin)
	if err != nil {
		return nil, err
	}
	err = scan(ctx, tx, `SELECT credential_id FROM passkeys ORDER BY id`, func(rows *sql.Rows) error {
		var cred []byte
		if err := rows.Scan(&cred); err != nil {
			return err
		}
		h := sha256.Sum256(cred)
		p.Passkeys = append(p.Passkeys, hex.EncodeToString(h[:16]))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(p.Passkeys) == 0 {
		return nil, errors.New("register an owner passkey before planning activation")
	}
	p.Admissions = []Admission{}
	err = scan(ctx, tx, `SELECT h.id,e.id,h.cert_sha256,h.name,e.class,h.not_after FROM hosts h JOIN enrollments e ON e.id=h.enrollment_id WHERE h.revoked_at IS NULL AND h.created_at<=?1 AND h.not_after>?1 AND e.status='approved' ORDER BY h.id`, func(rows *sql.Rows) error {
		var a Admission
		if err := rows.Scan(&a.HostID, &a.Enrollment, &a.Fingerprint, &a.Name, &a.Class, &a.NotAfter); err != nil {
			return err
		}
		p.Admissions = append(p.Admissions, a)
		return nil
	}, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	r := &p.Retire
	r.ActionChallenges = "all v1 action challenges"
	r.History = "owner-only, unassigned; no automatic attribution by name, alias or Cloudflare account; preserve audit and deletion records"
	for _, q := range []struct {
		query string
		out   *[]string
	}{
		{`SELECT id FROM requests WHERE status='pending' ORDER BY id`, &r.PendingRequests},
		{`SELECT id FROM enrollments WHERE status='pending' ORDER BY id`, &r.PendingEnrollments},
		{`SELECT id FROM grants WHERE revoked_at IS NULL AND not_after>? ORDER BY id`, &r.ActiveGrants},
		{`SELECT id FROM standing WHERE revoked_at IS NULL AND expires_at>? ORDER BY id`, &r.Standing},
	} {
		var args []any
		if strings.Contains(q.query, "?") {
			args = []any{now.UnixMilli()}
		}
		*q.out = []string{}
		err = scan(ctx, tx, q.query, func(rows *sql.Rows) error {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			*q.out = append(*q.out, id)
			return nil
		}, args...)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name='grants'),0)`).Scan(&r.GrantSerial); err != nil {
		return nil, err
	}
	r.Outstanding = []Outstanding{}
	err = scan(ctx, tx, `SELECT id,host_id,kind,not_after,token_id FROM grants WHERE not_after>? AND (kind='ssh' OR (kind='cloudflare' AND mode='token' AND (token_id!='' OR token_delivered!=0) AND token_deleted_at IS NULL)) ORDER BY serial`, func(rows *sql.Rows) error {
		var o Outstanding
		if err := rows.Scan(&o.Grant, &o.Host, &o.Kind, &o.NotAfter, &o.TokenID); err != nil {
			return err
		}
		r.Outstanding = append(r.Outstanding, o)
		return nil
	}, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPlanBytes {
		return nil, ErrTooLarge
	}
	return p, nil
}
