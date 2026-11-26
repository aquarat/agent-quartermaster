package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

var catalogueID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var catalogueTitle = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$`)
var initialPolicy = api.DurationPolicy{Default: 3600, Soft: 86400, Indefinite: true, StandingDefault: 3600, StandingSoft: 86400, StandingIndefinite: true}

func (s *Server) ownerCatalogue(ctx context.Context, q *store.Q, sess string, pk int64) (api.Catalogue, error) {
	var empty api.Catalogue
	if s.seal != nil {
		if err := s.sealOwner(ctx, q, sess, pk); err != nil {
			return empty, err
		}
	}
	if !q.Scoped() || s.maintenance {
		return empty, errNotFound()
	}
	owner, err := q.GlobalOwner(ctx, sess, pk, s.now())
	if err != nil {
		return empty, errForbidden("owner credential and session required")
	}
	c, err := q.Catalogue(ctx, owner, s.now())
	if err != nil {
		return c, err
	}
	if s.seal != nil && s.seal.stage == nil {
		// A signer set is stored as an application set with a signer_keys row.
		signers, err := q.SignerSets(ctx)
		if err != nil {
			return c, err
		}
		// A secret likewise: an application set with a secret_sets row.
		secrets, err := q.SecretSets(ctx)
		if err != nil {
			return c, err
		}
		// An SSH key: a signer row with an ssh_keys row.
		sshKeys, err := q.SSHKeySets(ctx)
		if err != nil {
			return c, err
		}
		for i := range c.Orgs {
			for j := range c.Orgs[i].Services {
				for k := range c.Orgs[i].Services[j].Sets {
					if set := &c.Orgs[i].Services[j].Sets[k]; sshKeys[set.ID] {
						set.Kind = "ssh-key"
					} else if signers[set.ID] {
						set.Kind = "signer"
					} else if secrets[set.ID] {
						set.Kind = "secret"
					}
				}
			}
		}
	}
	for i := range c.Orgs {
		o := &c.Orgs[i]
		for _, r := range o.Rules {
			if !r.Auto {
				continue
			}
			if s.cf.cat == nil {
				return c, errConflict("unavailable automatic scope")
			}
			sc, ok := s.cf.cat.Lookup(r.Scope)
			if !ok || !sc.AutoApprove {
				return c, errConflict("invalid automatic scope")
			}
			restriction := "allow-listed reads"
			if r.Scope == api.CFScopeCachePurge {
				zones := []string{}
				for _, z := range s.cfg.Cloudflare.Zones {
					zones = append(zones, z.Name+"="+z.ID)
				}
				restriction = "files only; zones: " + strings.Join(zones, ",")
			}
			cap := min(sc.MaxTTL, s.cfg.TTL.MaxSeconds)
			if r.Relax {
				cap = o.Policy.Soft
				if lim := s.cfg.Cloudflare.Scopes[r.Scope].MaxTTLSeconds; lim > 0 {
					cap = min(cap, lim)
				}
			}
			o.Auto = append(o.Auto, api.AutoAccess{Set: r.Set, Scope: r.Scope, Mode: "proxy", Restrictions: restriction, MaxSeconds: min(cap, o.Policy.Soft)})
		}
	}
	return c, nil
}

func (s *Server) catalogueHandler(w http.ResponseWriter, r *http.Request, sess string) {
	if !s.store.Q().Scoped() || s.maintenance {
		writeJSON(w, 200, nil)
		return
	}
	ctx := r.Context()
	var c api.Catalogue
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		c, err = s.ownerCatalogue(ctx, q, sess, pk)
		return err
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) validateChange(cat api.Catalogue, obj, action, id string, c api.CatalogueChange) error {
	bad := errConflict("catalogue or admission changed; reload and review again")
	if cat.OwnerID != c.Owner || !slices.Contains(canon.CatalogueActions[obj], action) {
		return bad
	}
	want := api.CatalogueChange{Owner: cat.OwnerID}
	var org *api.CatalogueOrg
	var service *api.CatalogueService
	unique := func(n api.CatalogueNode, existing []api.CatalogueNode) bool {
		if n.Revision != 0 || !catalogueID.MatchString(n.ID) || !config.ValidName(n.Slug) || !catalogueTitle.MatchString(n.Title) || strings.TrimSpace(n.Title) != n.Title {
			return false
		}
		for _, old := range existing {
			if n.ID == old.ID || n.Slug == old.Slug {
				return false
			}
		}
		return true
	}
	orgs := []api.CatalogueNode{}
	for i := range cat.Orgs {
		o := &cat.Orgs[i]
		orgs = append(orgs, o.CatalogueNode)
		if o.ID == c.Org.ID {
			org = o
		}
	}
	if obj == "organisation" {
		if id != c.Org.ID || !unique(c.Org, orgs) {
			return bad
		}
		want.Org = c.Org
		want.Policy = &initialPolicy
		want.ResultRevision = 1
	} else {
		if org == nil {
			return bad
		}
		want.Org = org.CatalogueNode
		services := []api.CatalogueNode{}
		for i := range org.Services {
			v := &org.Services[i]
			services = append(services, v.CatalogueNode)
			if c.Service != nil && v.ID == c.Service.ID {
				service = v
			}
		}
		switch obj {
		case "service":
			if c.Service == nil || id != c.Service.ID || !unique(*c.Service, services) {
				return bad
			}
			want.Service = c.Service
			want.Kind = "application"
			want.ResultRevision = 1
		case "credential_set":
			if service == nil || service.Provider != "application" || c.Set == nil || id != c.Set.ID {
				return bad
			}
			sets := []api.CatalogueNode{}
			for _, set := range service.Sets {
				sets = append(sets, set.CatalogueNode)
			}
			if !unique(*c.Set, sets) {
				return bad
			}
			want.Service = &service.CatalogueNode
			want.Set = c.Set
			want.Kind = "env-set"
			want.ResultRevision = 0
		case "org_host":
			if c.Host == nil || id != c.Host.Enrollment {
				return bad
			}
			for _, h := range org.Hosts {
				if h.Enrollment == id && h.Active != (action == "admit") {
					want.Host = &h
					want.ResultRevision = h.Generation + 1
					break
				}
			}
			if want.Host == nil {
				return bad
			}
			auto := []api.AutoAccess{}
			if action == "admit" {
				auto = org.Auto
			}
			want.Auto = &auto
			want.Resources = &org.Services
		case "org_policy":
			if id != org.ID || c.Policy == nil || c.Rules == nil {
				return bad
			}
			p := *c.Policy
			if p.Default < s.cfg.TTL.MinSeconds || p.Default > p.Soft || p.Soft > 315360000 || p.StandingDefault < 0 || p.StandingDefault > p.StandingSoft || p.StandingSoft > 315360000 {
				return errBad("invalid policy duration")
			}
			if len(*c.Rules) != len(org.Rules) {
				return bad
			}
			for i, r := range *c.Rules {
				old := org.Rules[i]
				if old.Set != r.Set || old.Scope != r.Scope {
					return bad
				}
				if r.Scope == "" {
					if r.Auto || r.Relax {
						return bad
					}
					continue
				}
				if s.cf.cat == nil {
					return bad
				}
				sc, ok := s.cf.cat.Lookup(r.Scope)
				if !ok || r.Auto && !sc.AutoApprove || r.Standing && !sc.StandingAllowed || r.Relax && (r.Scope == api.CFScopeAdmin || r.Scope == api.CFScopeReadPrivate) {
					return errBad("scope cannot offer the selected policy")
				}
			}
			want.OldPolicy = &org.Policy
			want.Policy = c.Policy
			want.OldRules = &org.Rules
			want.Rules = c.Rules
			want.ResultRevision = org.Revision + 1
		default:
			return bad
		}
	}
	if !reflect.DeepEqual(want, c) {
		return bad
	}
	return nil
}

func (s *Server) catalogueChallenge(ctx context.Context, sess, obj, id string, in api.ChallengeRequest) (canon.Action, error) {
	a := canon.Action{Object: obj, Action: in.Action, ID: id, Plan: in.Plan}
	var c api.CatalogueChange
	if in.TTLSeconds != 0 || in.StandingHours != 0 || in.Nickname != "" || in.Indefinite || in.StandingIndefinite || json.Unmarshal([]byte(in.Plan), &c) != nil {
		return a, errBad("invalid catalogue proposal")
	}
	err := s.store.Tx(ctx, func(q *store.Q) error {
		pk, err := q.SessionPasskeyID(ctx, sess)
		if err != nil {
			return err
		}
		cat, err := s.ownerCatalogue(ctx, q, sess, pk)
		if err != nil {
			return err
		}
		return s.validateChange(cat, obj, in.Action, id, c)
	})
	return a, err
}
func (s *Server) catalogueApply(ctx context.Context, sess string, pk int64, sg canon.Signed) error {
	var c api.CatalogueChange
	if sg.V != 2 || json.Unmarshal([]byte(sg.Plan), &c) != nil {
		return errBad("invalid catalogue signature")
	}
	return s.store.Tx(ctx, func(q *store.Q) error {
		cat, err := s.ownerCatalogue(ctx, q, sess, pk)
		if err != nil {
			return err
		}
		if err := s.validateChange(cat, sg.Object, sg.Action.Action, sg.ID, c); err != nil {
			return err
		}
		if err := q.WriteCatalogue(ctx, sg.Object, sg.Action.Action, c, s.now()); err != nil {
			return err
		}
		if err := q.MarkPolicySchema(ctx); err != nil {
			return err
		}
		return q.Audit(ctx, s.now(), "owner", sg.Object+"_"+sg.Action.Action, sg.Object+":"+sg.ID, fmt.Sprintf("signer=%d nonce=%s change=%s", pk, sg.Nonce, sg.Plan))
	})
}
