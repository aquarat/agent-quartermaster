package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Env proposals (docs/API.md "Env proposals"): any host admitted to an
// organisation may ask to store values in an env set, or in a new set (and
// service) of that organisation. Nothing a host sends here changes what a
// later release delivers until the owner has committed it with a fresh tap:
// the entries are sealed to the set's bucket on arrival and wait in
// env_proposals. For a set without a bucket the proposal row holds the bucket
// the set would get, so a proposal that is not committed leaves no bucket,
// service or set behind.

// ProposalTTL is how long a proposal waits for the owner.
const ProposalTTL = 10 * time.Minute

// proposalTarget is what committing a proposal would write to.
type proposalTarget struct {
	serviceSlug, setSlug   string
	serviceTitle, setTitle string // of what is created
	newService, newSet     bool
}

// pendingBucket is the bucket of a set that has none yet, kept in the
// proposal until commit: public material and the wrap of its private key to
// the scope key (ScopePublic says which one).
type pendingBucket struct {
	ID          []byte `json:"id"`
	Public      []byte `json:"public"`
	Wrap        []byte `json:"wrap"`
	ScopePublic []byte `json:"scope_public"`
}

// envBase answers GET /v2/env/set?path=P&create=1: the set's binding when it
// exists; otherwise what a new set at that path would start from (`set` and,
// for a missing service, `service` are empty).
func (s *Server) envBase(ctx context.Context, q *store.Q, host int64, path string) (envset.Binding, error) {
	b, err := q.EnvBinding(ctx, host, path, s.now())
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return b, err
	}
	if !envset.ValidPath(path) {
		return b, errNotFound()
	}
	p := strings.Split(path, "/")
	base, err := s.newSetBase(ctx, q, host, p[0], p[1], p[2])
	if err != nil {
		return b, err
	}
	b = base.Binding
	b.Path = path
	b.Title = base.OrgTitle + " / " + base.ServiceTitle
	return b, nil
}

// newSetBase resolves the organisation and service of a set to be created
// and refuses a path that cannot be created.
func (s *Server) newSetBase(ctx context.Context, q *store.Q, host int64, org, service, set string) (store.EnvBase, error) {
	base, err := q.EnvBase(ctx, host, org, service, s.now())
	if err != nil {
		return base, err
	}
	if base.ServiceBlocked {
		return base, errConflict("that service cannot take an env set")
	}
	if !config.ValidName(service) || !config.ValidName(set) {
		return base, errBad("a service or set name is 1 to 63 lowercase letters, digits and hyphens, starting with a letter or digit")
	}
	if base.Service == "" {
		base.ServiceTitle = service
		return base, nil
	}
	// Any set with the slug takes the path, also one EnvBinding does not show
	// (a signing key, an SSH key).
	if free, err := q.SetSlugFree(ctx, base.Service, "", set); err != nil {
		return base, err
	} else if !free {
		return base, errConflict("that path is taken")
	}
	return base, nil
}

// proposalBinding is the binding a proposal applies to, from the store as it
// is now: the set's own binding, or for `create` the binding the new set will
// have. Both the request and the owner's review use it, so a commit applies
// to exactly what was proposed.
func (s *Server) proposalBinding(ctx context.Context, q *store.Q, host int64, path string, c *envset.ProposalCreate) (envset.Binding, proposalTarget, error) {
	var t proposalTarget
	if !envset.ValidPath(path) {
		return envset.Binding{}, t, errBad("expected an exact org/service/set path")
	}
	p := strings.Split(path, "/")
	t.serviceSlug, t.setSlug = p[1], p[2]
	b, err := q.EnvBinding(ctx, host, path, s.now())
	if c == nil {
		if err != nil {
			return b, t, err
		}
		if secret, err := q.IsSecret(ctx, b.Set); err != nil {
			return b, t, err
		} else if secret {
			return b, t, errBad("a secret is replaced in the Vault, not from the CLI")
		}
		return b, t, nil
	}
	if err == nil {
		return b, t, errConflict("that path exists: propose without create")
	}
	if !errors.Is(err, store.ErrNotFound) {
		return b, t, err
	}
	base, err := s.newSetBase(ctx, q, host, p[0], p[1], p[2])
	if err != nil {
		return b, t, err
	}
	t.newSet, t.setTitle = true, c.Title
	if t.setTitle == "" {
		t.setTitle = t.setSlug
	}
	if !catalogueID.MatchString(c.SetID) || !catalogueTitle.MatchString(t.setTitle) || strings.TrimSpace(t.setTitle) != t.setTitle {
		return b, t, errBad("create needs a set_id of 32 lowercase hex characters and a title of 1 to 64 letters, digits, spaces, dots, underscores and hyphens")
	}
	if free, err := q.SetSlugFree(ctx, "", c.SetID, ""); err != nil {
		return b, t, err
	} else if !free {
		return b, t, errConflict("that set ID is taken")
	}
	if base.Service == "" {
		t.newService, t.serviceTitle = true, t.serviceSlug
		if !catalogueID.MatchString(c.ServiceID) || c.ServiceID == c.SetID {
			return b, t, errBad("the service does not exist: create needs a service_id of 32 lowercase hex characters")
		}
		if free, err := q.ServiceIDFree(ctx, c.ServiceID); err != nil {
			return b, t, err
		} else if !free {
			return b, t, errConflict("that service ID is taken")
		}
		base.Service = c.ServiceID
	} else if c.ServiceID != "" {
		return b, t, errConflict("the service exists: leave service_id empty")
	}
	// A set is created with its first revision, so the organisation must be
	// able to take a first write.
	if _, err := s.writableScope(ctx, q, base.Org); err != nil {
		return b, t, err
	}
	b = base.Binding
	b.Path, b.Title, b.Set = path, base.OrgTitle+" / "+base.ServiceTitle+" / "+t.setTitle, c.SetID
	return b, t, nil
}

// envPropose is POST /v2/env/proposals.
func (s *Server) envPropose(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	var in envset.ProposalRequest
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	defer wipeEntries(in.Edit.Entries)
	op := in.Edit.Op
	if op != "import" && op != "put" && op != "unset" || len(in.Edit.Remove) > 0 {
		return nil, errBad("a proposal is an import, a put or an unset")
	}
	if in.Create != nil && op == "unset" {
		return nil, errBad("a new set is created by an import or a put")
	}
	if len(in.Reason) > MaxReasonLen || strings.TrimSpace(in.Reason) == "" || !utf8.ValidString(in.Reason) || hasControl(in.Reason, false) {
		return nil, errBad("a reason is required: one line of 1 to 500 characters saying what the values are for")
	}
	peer := peerIP(r)
	if net.ParseIP(peer) == nil {
		return nil, errBad("missing source address")
	}
	b, t, err := s.proposalBinding(ctx, q, h.ID, in.Path, in.Create)
	if err != nil {
		return nil, err
	}
	commit, err := in.Edit.Commit(b)
	if err != nil || commit != in.Commitment {
		return nil, errBad("invalid edit commitment")
	}
	changes, err := in.Edit.Changes(b.Names)
	if err != nil {
		return nil, errBad(err.Error())
	}
	if changes == "" {
		return nil, errBad("the edit changes nothing")
	}
	now := s.now()
	if n, err := s.allPending(ctx, q, h.ID, now); err != nil {
		return nil, err
	} else if n >= MaxPendingPerHost {
		return nil, &apiErr{429, "rate_limited", "too many pending requests"}
	}
	// The plaintext is here and the commitment checked: seal each entry to the
	// set's bucket now (no bucket is opened); an unset carries its name only.
	// A set without a bucket gets one made here and kept in the proposal.
	x := store.StagedProposal{Host: h.ID, ServiceSlug: t.serviceSlug, SetSlug: t.setSlug, SetTitle: t.setTitle}
	row, err := q.BucketByRef(ctx, "env-set", b.Set)
	if errors.Is(err, store.ErrNotFound) {
		var sc store.ScopeRow
		if sc, err = s.writableScope(ctx, q, b.Org); err != nil {
			return nil, err
		}
		if row, err = s.newBucket(sc, "env-set", b.Set, nil); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(pendingBucket{ID: row.ID, Public: row.Public, Wrap: row.Wrap, ScopePublic: sc.Public})
		if err != nil {
			return nil, err
		}
		x.Bucket = string(raw)
	} else if err != nil {
		return nil, err
	}
	var recs []envRecord
	if op == "unset" {
		recs = []envRecord{{N: in.Edit.Entries[0].Name}}
	} else if recs, err = s.sealEntries(s.sealBucket(row), b.Set, in.Edit.Entries); err != nil {
		return nil, err
	}
	payload, err := recordsJSON(recs)
	if err != nil {
		return nil, err
	}
	id := ids.New()
	x.Record = store.CipherRecord{Payload: payload, Wrap: row.ID}
	x.P = envset.Proposal{Binding: b, ID: id, Ref: ref(id), Operation: op, Commitment: commit, Changes: changes, Reason: in.Reason, Peer: peer,
		NewService: t.newService, NewSet: t.newSet, Status: "pending", Created: now.UnixMilli(), Expires: now.Add(ProposalTTL).UnixMilli()}
	if err = q.NewEnvProposal(ctx, x); err != nil {
		return nil, err
	}
	if err = q.Audit(ctx, now, "host:"+h.Name, "env_proposal", "proposal:"+id, fmt.Sprintf("%s operation=%s set=%s new_service=%t new_set=%t commitment=%s changes=%s from=%s", b.Path, op, b.Set, t.newService, t.newSet, commit, changes, peer)); err != nil {
		return nil, err
	}
	// Only after commit: the page refreshes and the owner is told.
	if c, _ := ctx.Value(signCallKey{}).(*signCall); c != nil {
		what := "store values in"
		if t.newSet {
			what = "create"
		}
		c.after = func() {
			s.bcast.notify()
			s.notify.Send("aqmas: "+h.Name, fmt.Sprintf("aqmas: %s wants to %s %s [ref %s]", h.Name, what, b.Path, ref(id)), s.cfg.PublicBaseURL+"/")
		}
	}
	return x.P, nil
}

// visibleProposal is a proposal as its own host sees it, from the address it
// was made from; anything else is not found.
func (s *Server) visibleProposal(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (store.StagedProposal, error) {
	x, err := q.EnvProposal(ctx, r.PathValue("id"))
	if err != nil || x.Host != h.ID || x.P.Peer != peerIP(r) {
		return x, errNotFound()
	}
	return x, nil
}

// envProposalCancel is POST /v2/env/proposals/{id}/cancel.
func (s *Server) envProposalCancel(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	x, err := s.visibleProposal(ctx, q, r, h)
	if err != nil {
		return nil, err
	}
	if err = q.EndEnvProposal(ctx, x.P.ID, "cancelled", 0); err != nil {
		return nil, errConflict("proposal no longer pending")
	}
	x.P.Status = "cancelled"
	if c, _ := ctx.Value(signCallKey{}).(*signCall); c != nil {
		c.after = s.bcast.notify
	}
	return x.P, q.Audit(ctx, s.now(), "host:"+h.Name, "env_proposal_cancel", "proposal:"+x.P.ID, x.P.Path)
}

// envProposalPoll is GET /v2/env/proposals/{id}[?wait=SECONDS]: it returns as
// soon as the proposal is no longer pending, like GET /v1/requests/{id}.
func (s *Server) envProposalPoll(w http.ResponseWriter, r *http.Request, h *store.Host) {
	ctx := r.Context()
	if err := s.bucketsReady(); err != nil {
		s.writeErr(w, r, s.hostNotFound(ctx, h, err))
		return
	}
	var out envset.Proposal
	err := s.longPoll(ctx, parseWait(r.URL.Query().Get("wait")), func() (bool, error) {
		err := s.store.Tx(ctx, func(q *store.Q) error {
			if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
				return err
			}
			if err := q.SweepEnv(ctx, s.now()); err != nil {
				return err
			}
			x, err := s.visibleProposal(ctx, q, r, h)
			out = x.P
			return err
		})
		return out.Status != "pending", err
	})
	if err != nil {
		s.writeErr(w, r, s.hostNotFound(ctx, h, err))
		return
	}
	writeJSON(w, 200, out)
}

// reviewProposal returns the text the owner signs for a proposal decision:
// the complete proposal with the host's free-form reason blanked. A commit is
// offered only while the store is what the proposal was made against.
func (s *Server) reviewProposal(ctx context.Context, q *store.Q, sess string, pk int64, in envChoice) (string, error) {
	x, err := q.EnvProposal(ctx, in.ID)
	if err != nil {
		return "", err
	}
	if err = q.IsOrgOwner(ctx, x.P.Org, sess, pk, s.now()); err != nil {
		return "", errForbidden("organisation approval required")
	}
	if x.P.Status != "pending" {
		return "", errConflict("decision no longer available")
	}
	if in.TTL != 0 {
		return "", errBad("unexpected duration")
	}
	if in.Action == "proposal-commit" {
		if _, _, err = s.currentProposal(ctx, q, x); err != nil {
			return "", err
		}
	}
	x.P.Reason = ""
	return reviewJSON(x.P)
}

// currentProposal re-derives the binding and refuses when anything the
// proposal was made against has changed: the set's revision, the host's
// admission, the organisation's policy, or for a new set the path and IDs.
func (s *Server) currentProposal(ctx context.Context, q *store.Q, x store.StagedProposal) (envset.Binding, proposalTarget, error) {
	var c *envset.ProposalCreate
	if x.P.NewSet {
		c = &envset.ProposalCreate{SetID: x.P.Set, Title: x.SetTitle}
		if x.P.NewService {
			c.ServiceID = x.P.Service
		}
	}
	b, t, err := s.proposalBinding(ctx, q, x.Host, x.P.Path, c)
	if err != nil || !reflect.DeepEqual(b, x.P.Binding) || t.newService != x.P.NewService || t.newSet != x.P.NewSet {
		var ae *apiErr
		if errors.As(err, &ae) && ae.status == http.StatusBadRequest {
			return b, t, errConflict(ae.msg)
		}
		return b, t, errConflict("the set, the host's admission or the policy changed since this was proposed: discard it and have the host propose again")
	}
	return b, t, nil
}

// commitProposal publishes a proposal as the set's next revision, creating
// the service, the set and the set's bucket first when the proposal asked
// for them. No bucket is opened: the entries were sealed when they arrived.
func (s *Server) commitProposal(ctx context.Context, q *store.Q, id string) error {
	x, err := q.EnvProposal(ctx, id)
	if err != nil {
		return err
	}
	b, t, err := s.currentProposal(ctx, q, x)
	if err != nil {
		return err
	}
	unset := x.P.Operation == "unset"
	recs, err := parseRecords(x.Record.Payload, !unset)
	if err != nil {
		return err
	}
	if (x.P.Operation == "put" || unset) && len(recs) != 1 {
		return errConflict("edit commitment or manifest mismatch")
	}
	names := make([]envset.Entry, len(recs))
	for i, r := range recs {
		names[i] = envset.Entry{Name: r.N}
	}
	changes, err := envset.Edit{Op: x.P.Operation, Entries: names}.Changes(b.Names)
	if err != nil || changes != x.P.Changes {
		return errConflict("edit commitment or manifest mismatch")
	}
	var row store.BucketRow
	if x.Bucket != "" {
		var pb pendingBucket
		if json.Unmarshal([]byte(x.Bucket), &pb) != nil || !bytes.Equal(pb.ID, x.Record.Wrap) {
			return errConflict("damaged proposal")
		}
		if _, err := q.BucketByRef(ctx, "env-set", b.Set); err == nil {
			return errConflict("the set got its key since this was proposed: discard it and have the host propose again")
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		sc, err := s.writableScope(ctx, q, b.Org)
		if err != nil {
			return err
		}
		if !bytes.Equal(sc.Public, pb.ScopePublic) {
			return errConflict("the organisation's scope key changed since this was proposed: discard it and have the host propose again")
		}
		row = store.BucketRow{ID: pb.ID, Scope: sc.Scope, Kind: "env-set", Ref: b.Set, Public: pb.Public, Wrap: pb.Wrap, Created: s.now()}
	} else {
		if row, err = s.setRow(ctx, q, "env-set", b.Set); err != nil {
			return err
		}
		if !bytes.Equal(x.Record.Wrap, row.ID) {
			return errConflict("the proposal was sealed to another key: discard it and have the host propose again")
		}
	}
	// Committed first: writing the revision updates the set's row, and the
	// trigger on it supersedes every proposal of the set still pending.
	if err = q.EndEnvProposal(ctx, x.P.ID, "committed", b.Revision+1); err != nil {
		return errConflict("decision no longer available")
	}
	exists := errConflict("a service or set with that name or ID exists now: discard this and have the host propose again")
	if t.newService {
		if err = q.CreateEnvService(ctx, b.Service, b.Org, t.serviceSlug, t.serviceTitle); err != nil {
			return exists
		}
	}
	if t.newSet {
		if err = q.CreateEnvSet(ctx, b.Set, b.Service, t.setSlug, t.setTitle); err != nil {
			return exists
		}
	}
	if x.Bucket != "" {
		if err = q.InsertBucket(ctx, row); err != nil {
			return err
		}
	}
	old, _, err := s.revisionRecords(ctx, q, b)
	if err != nil {
		return err
	}
	return s.writeRevision(ctx, q, b, row, mergeRecords(old, x.P.Operation, recs, nil))
}
