package organisations

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
)

//go:embed catalogue.sql
var schema string

// Backfill materialises a previously reviewed plan. The caller owns the
// immediate transaction and must roll it back on any error. Compare bytes,
// not just host counts or names; never accept an inventory from decide.
func Backfill(ctx context.Context, tx *sql.Tx, cfg *config.Config, sshPin, clientPin string, now time.Time, reviewed string) error {
	p, err := Inventory(ctx, tx, cfg, sshPin, clientPin, now)
	if err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if string(b) != reviewed {
		return errors.New("migration inventory changed; review again")
	}
	exec := func(query string, args ...any) error { _, err := tx.ExecContext(ctx, query, args...); return err }
	if err := exec(schema); err != nil {
		return err
	}
	org := p.Organisation.ID
	if err := exec(`INSERT INTO people SELECT ?,value,?,1 FROM meta WHERE key='owner_webauthn_id'`, p.Owner.ID, p.Owner.Title); err != nil {
		return err
	}
	if err := exec(`INSERT INTO passkey_people SELECT id,? FROM passkeys`, p.Owner.ID); err != nil {
		return err
	}
	if err := exec(`INSERT INTO organisations(id,slug,title,revision) VALUES(?,?,?,1)`, org, p.Organisation.Slug, p.Organisation.Title); err != nil {
		return err
	}
	if err := exec(`INSERT INTO org_approvers VALUES(?,?,'approver',1)`, org, p.Owner.ID); err != nil {
		return err
	}
	if err := exec(`INSERT INTO org_policies VALUES(?,1,?,?,0,0,?,0)`, org, p.TTL.DefaultSeconds, max(p.TTL.MaxSeconds, p.TTL.OwnerMaxSeconds), max(p.TTL.MaxStandingHours, p.TTL.OwnerMaxStandingHours)*3600); err != nil {
		return err
	}
	for _, s := range p.Services {
		provider := "fleet"
		if s.Slug == "dns-cdn" {
			provider = "cloudflare"
		}
		if err := exec(`INSERT INTO services(id,org_id,slug,title,provider,revision) VALUES(?,?,?,?,?,1)`, s.ID, org, s.Slug, s.Title, provider); err != nil {
			return err
		}
		for _, set := range s.Sets {
			if err := exec(`INSERT INTO credential_sets(id,service_id,provider,slug,title,kind,revision) VALUES(?,?,?,?,?,?,1)`, set.ID, s.ID, provider, set.Slug, set.Title, set.Kind); err != nil {
				return err
			}
			if err := exec(`INSERT INTO personal_aliases VALUES(?,?,?)`, set.Kind, set.Slug, set.ID); err != nil {
				return err
			}
			if set.Kind == "cloudflare-mint" && len(p.BlockedMint) > 0 {
				if err := exec(`UPDATE credential_sets SET archived=1 WHERE id=?`, set.ID); err != nil {
					return err
				}
			}
			policy := func(scope string, def, cap int, auto, standing bool) error {
				return exec(`INSERT INTO set_policies VALUES(?,1,?,?,?,0,?,?)`, set.ID, scope, min(def, cap), cap, auto, standing)
			}
			if t := set.Target; t != nil {
				cap := max(p.TTL.MaxSeconds, p.TTL.OwnerMaxSeconds)
				if t.MaxTTLSeconds > 0 {
					cap = min(cap, t.MaxTTLSeconds)
				}
				if err := policy("", p.TTL.DefaultSeconds, cap, false, !t.HighRisk); err != nil {
					return err
				}
				continue
			}
			for _, scope := range p.Scopes {
				mode := api.CFModeProxy
				if set.Kind == "cloudflare-mint" {
					mode = api.CFModeToken
				}
				for _, m := range scope.Modes {
					if mode == m {
						if err := policy(scope.Name, scope.DefaultTTL, min(scope.MaxTTL, p.TTL.MaxSeconds), m == api.CFModeProxy && scope.AutoApprove, m == api.CFModeProxy && scope.StandingAllowed); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	for _, a := range p.Admissions {
		if err := exec(`INSERT INTO org_hosts VALUES(?,?,1,1)`, org, a.HostID); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`UPDATE enrollments SET status='expired',decided_at=? WHERE status='pending'`,
		`UPDATE requests SET status='expired',decided_at=? WHERE status='pending'`,
		`UPDATE requests SET status='revoked' WHERE status='approved' AND id IN (SELECT request_id FROM grants WHERE revoked_at IS NULL AND not_after>?)`,
		`UPDATE grants SET revoked_at=?1 WHERE revoked_at IS NULL AND not_after>?1`,
		`UPDATE standing SET revoked_at=?1 WHERE revoked_at IS NULL AND expires_at>?1`,
	} {
		if err := exec(q, now.UnixMilli()); err != nil {
			return err
		}
	}
	if err := exec(`UPDATE challenges SET used=1 WHERE purpose='action'`); err != nil {
		return err
	}
	if err := exec(`INSERT INTO personal_cutover VALUES(1,?,?,?)`, org, p.ConfigHash, string(b)); err != nil {
		return err
	}
	return exec(`PRAGMA user_version=6`)
}
