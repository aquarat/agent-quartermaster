package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Routine maintenance queued by an agent (docs/BASTION-ACCESS.md §7). A queued request is
// only a card: approving it is the Setup page's own flow (the owner's tap signs setup/run
// for the task and parameters, the root runner verifies that signature against its pins).
// The broker never runs anything, and neither does a request.

const (
	// One undecided maintenance request per host, a few in total, and a pause between a
	// host's requests: these cards ask for restarts, and must stay rare.
	maxSetupPerHost  = 1
	maxSetupPending  = 3
	setupCooldown    = 5 * time.Minute
	setupCooldownMax = 3 // requests per host within the cooldown
)

func (s *Server) handleSetupRequestCreate(w http.ResponseWriter, r *http.Request, h *store.Host) {
	// Off until the owner has installed access to the bastion: before that no host can put
	// a maintenance card in front of the owner.
	if _, err := s.bastionCfg(); err != nil {
		s.writeErr(w, r, err)
		return
	}
	var in api.SetupRequest
	if err := decode(r, &in); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := validReason(in.Reason); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := validRequester(in.Requester); err != nil {
		s.writeErr(w, r, err)
		return
	}
	// The task's own schema, then the narrower rules for a request that is not the owner's.
	typed, err := maint.Decode(in.Task, in.Params)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	if err := maint.AgentAllowed(in.Task, typed); err != nil {
		s.writeErr(w, r, errForbidden(err.Error()))
		return
	}
	params, err := maint.Canonical(in.Task, typed)
	if err != nil {
		s.writeErr(w, r, errBad(err.Error()))
		return
	}
	spec, _ := maint.Lookup(in.Task)
	now := s.now()
	req := &store.SetupRequest{ID: ids.New(), HostID: h.ID, HostName: h.Name, PeerAddress: peerIP(r), Task: in.Task, Params: params, Reason: in.Reason,
		Requester: in.Requester, Status: api.StatusPending, CreatedAt: now, ExpiresAt: now.Add(secs(s.cfg.TTL.PendingExpirySeconds))}
	ctx := r.Context()
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
			return err
		}
		if err := q.ExpireSetupRequests(ctx, now); err != nil {
			return err
		}
		limited := &apiErr{http.StatusTooManyRequests, api.ErrRateLimited, "a maintenance request is already waiting for the owner, or this host asked too often; try again later"}
		if n, err := q.CountPendingSetup(ctx, h.ID, now); err != nil {
			return err
		} else if n >= maxSetupPerHost {
			return limited
		}
		if n, err := q.CountAllPendingSetup(ctx, now); err != nil {
			return err
		} else if n >= maxSetupPending {
			return limited
		}
		if n, err := q.CountRecentSetup(ctx, h.ID, now.Add(-setupCooldown)); err != nil {
			return err
		} else if n >= setupCooldownMax {
			return limited
		}
		if err := s.pendingRoom(ctx, q, h.ID, now); err != nil {
			return err
		}
		if err := q.InsertSetupRequest(ctx, req); err != nil {
			return err
		}
		return q.Audit(ctx, now, "host:"+h.Name, "setup_request", "setup-request:"+req.ID, fmt.Sprintf("task=%s params=%s from=%s", req.Task, req.Params, req.PeerAddress))
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	url := s.approveURL(req.ID)
	s.notify.Send("aqmas: "+h.Name, fmt.Sprintf("aqmas: %s asks to run “%s” on the bastion", h.Name, spec.Title), url)
	writeJSON(w, http.StatusCreated, api.RequestCreated{ID: req.ID, Status: req.Status, ApproveURL: url, PollAfterMS: PollAfterMS, ExpiresAt: req.ExpiresAt})
}

// setupRequestOf loads a maintenance request of this host; anything else is "not found".
func setupRequestOf(ctx context.Context, q *store.Q, id string, host int64) (*store.SetupRequest, error) {
	req, err := q.GetSetupRequest(ctx, id)
	if err != nil || req.HostID != host {
		return nil, errNotFound()
	}
	return req, nil
}

// setupRun reports the runner's public status of the run a request's approval started,
// matched by the digest of the signed text.
func (s *Server) setupRunOf(req *store.SetupRequest) *api.SetupRunStatus {
	if req.Status != api.StatusApproved || req.Digest == "" {
		return nil
	}
	st, _ := s.runnerStatus()
	from := func(t *maint.TaskStatus) *api.SetupRunStatus {
		return &api.SetupRunStatus{State: t.State, Step: t.Step, Message: t.Message, Log: t.Log, Result: t.Result, Finished: t.Finished}
	}
	if c := st.Current; c != nil && c.Request == req.Digest {
		return from(c)
	}
	if t := st.Tasks[req.Task]; t != nil && t.Request == req.Digest {
		return from(t)
	}
	// Not started (yet). Only the refusal of this very request is this requester's business.
	if rf := st.Refused; rf != nil && rf.Request == req.Digest {
		return &api.SetupRunStatus{State: "refused", Message: rf.Reason, Finished: rf.At}
	}
	if req.DecidedAt != nil && s.now().Sub(*req.DecidedAt) > 2*maint.MaxAge {
		return &api.SetupRunStatus{State: "failed", Message: "the maintenance runner did not pick this up"}
	}
	return &api.SetupRunStatus{State: "queued"}
}

func terminalRun(r *api.SetupRunStatus) bool {
	return r != nil && (r.State == "done" || r.State == "failed" || r.State == "refused")
}

func (s *Server) handleSetupRequestStatus(w http.ResponseWriter, r *http.Request, h *store.Host) {
	if !s.bastionOn {
		s.writeErr(w, r, errNotFound())
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	var req *store.SetupRequest
	var run *api.SetupRunStatus
	// ?after=<state> waits for the run to leave that state, so a client can follow
	// pending → queued → running → done with long polls.
	after := r.URL.Query().Get("after")
	err := s.longPoll(ctx, parseWait(r.URL.Query().Get("wait")), func() (bool, error) {
		var err error
		if req, err = setupRequestOf(ctx, s.store.Q(), id, h.ID); err != nil {
			return false, err
		}
		if req.Status == api.StatusPending && !s.now().Before(req.ExpiresAt) {
			req.Status = api.StatusExpired
		}
		run = s.setupRunOf(req)
		if req.Status == api.StatusPending {
			return false, nil
		}
		return req.Status != api.StatusApproved || terminalRun(run) || run != nil && run.State != after, nil
	})
	if err != nil {
		s.writeErr(w, r, mapNotFound(err))
		return
	}
	if ctx.Err() != nil {
		return
	}
	writeJSON(w, http.StatusOK, api.SetupRequestStatus{ID: req.ID, Task: req.Task, Status: req.Status, DecisionNote: req.DecisionNote, Run: run})
}

func (s *Server) handleSetupRequestCancel(w http.ResponseWriter, r *http.Request, h *store.Host) {
	if !s.bastionOn {
		s.writeErr(w, r, errNotFound())
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	now := s.now()
	var req *store.SetupRequest
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.ExpireSetupRequests(ctx, now); err != nil {
			return err
		}
		var err error
		if req, err = setupRequestOf(ctx, q, id, h.ID); err != nil {
			return err
		}
		if err := q.DecideSetupRequest(ctx, id, h.ID, api.StatusCancelled, "cancelled by requester", "", now); err != nil {
			return statusErr(req.Status)
		}
		req.Status = api.StatusCancelled
		return q.Audit(ctx, now, "host:"+h.Name, "setup_request_cancel", "setup-request:"+id, "")
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	writeJSON(w, http.StatusOK, api.SetupRequestStatus{ID: req.ID, Task: req.Task, Status: req.Status})
}

// handleSetupRequestDismiss removes a queued request from the owner's page. Unsigned on
// purpose, like cancelling a waiting task: it can only return to "nothing queued".
func (s *Server) handleSetupRequestDismiss(w http.ResponseWriter, r *http.Request, _ string) {
	if !s.bastionOn {
		s.writeErr(w, r, errNotFound())
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	now := s.now()
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if err := q.ExpireSetupRequests(ctx, now); err != nil {
			return err
		}
		req, err := q.GetSetupRequest(ctx, id)
		if err != nil {
			return mapNotFound(err)
		}
		if err := q.DecideSetupRequest(ctx, id, 0, api.StatusDenied, "dismissed by owner", "", now); err != nil {
			return statusErr(req.Status)
		}
		return q.Audit(ctx, now, "owner", "setup_request_dismiss", "setup-request:"+id, "task="+req.Task+" host="+req.HostName)
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.bcast.notify()
	writeJSON(w, http.StatusOK, api.OK{OK: true})
}

// setupItems are the queued maintenance requests as pending cards.
func (s *Server) setupItems(ctx context.Context, sess string) ([]api.PendingItem, error) {
	now := s.now()
	q := s.store.Q()
	if err := q.ExpireSetupRequests(ctx, now); err != nil {
		return nil, err
	}
	reqs, err := q.PendingSetupRequests(ctx, now)
	if err != nil || len(reqs) == 0 {
		return nil, err
	}
	out := []api.PendingItem{}
	for _, rq := range reqs {
		spec, ok := maint.Lookup(rq.Task)
		if !ok {
			continue
		}
		ps := &api.PendingSetup{Task: rq.Task, Title: spec.Title, Summary: spec.Summary, Steps: spec.Steps, Reversible: spec.Reversible, Warning: spec.Warning, Params: rq.Params}
		if err := s.setupRunnable(ctx, sess, rq.Task); err != nil {
			ps.Blocked = err.Error()
		}
		out = append(out, api.PendingItem{ID: rq.ID, Kind: api.KindSetup, CreatedAt: rq.CreatedAt, ExpiresAt: rq.ExpiresAt, RequestingHost: rq.HostName,
			RequestingAddress: rq.PeerAddress, Requester: rq.Requester, Reason: rq.Reason, Risk: "normal", Setup: ps})
	}
	return out, nil
}

// approveSetupRequest is called inside the spooling transaction when the owner's signed
// setup/run answers a queued request: the request must still be pending and must be for
// exactly the task and parameters that were signed.
func approveSetupRequest(ctx context.Context, q *store.Q, id, task, params, digest string, now time.Time) error {
	if err := q.ExpireSetupRequests(ctx, now); err != nil {
		return err
	}
	req, err := q.GetSetupRequest(ctx, id)
	if err != nil {
		return mapNotFound(err)
	}
	if req.Task != task || req.Params != params {
		return errConflict("the signed task is not the one this request asked for")
	}
	if err := q.DecideSetupRequest(ctx, id, 0, api.StatusApproved, "approved by owner", digest, now); err != nil {
		return statusErr(req.Status)
	}
	return q.Audit(ctx, now, "owner", "setup_request_approve", "setup-request:"+id, "task="+task+" host="+req.HostName+" run="+digest)
}
