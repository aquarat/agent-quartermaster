package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// Agent side of signer sets (docs/SIGNING.md). A host asks for signatures by
// digest; the owner approves the exact artifacts (or a bounded grant); the
// broker signs inside a lease on the sealed store and returns signatures. No
// route in this file, or anywhere else, returns a signer's private key.

func (s *Server) signAgentRoutes(m *http.ServeMux) {
	route := func(pattern string, f func(context.Context, *store.Q, *http.Request, *store.Host) (any, error)) {
		m.Handle(pattern, s.requireHost(func(w http.ResponseWriter, r *http.Request, h *store.Host) {
			if err := s.bucketsReady(); err != nil {
				s.writeErr(w, r, err)
				return
			}
			call := &signCall{}
			if r.Method == http.MethodPost { // no network read inside a lease or transaction
				var err error
				if call.body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody)); err != nil {
					s.writeErr(w, r, errBad("body too large or unreadable"))
					return
				}
			}
			ctx := r.Context()
			var out any
			err := s.store.Tx(ctx, func(q *store.Q) error {
				if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
					return err
				}
				if err := q.SweepSign(ctx, s.now()); err != nil {
					return err
				}
				var err error
				out, err = f(context.WithValue(ctx, signCallKey{}, call), q, r, h)
				return err
			})
			if err != nil {
				s.writeErr(w, r, mapNotFound(err))
				return
			}
			if call.after != nil {
				call.after()
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, out)
		}))
	}
	route("GET /v2/sign/key", func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		return q.SignBinding(ctx, h.ID, r.URL.Query().Get("path"), s.now())
	})
	route("POST /v2/sign/requests", s.signRequest)
	route("GET /v2/sign/requests/{id}", func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		return q.VisibleSignRequest(ctx, h.ID, peerIP(r), r.PathValue("id"), false, s.now())
	})
	route("POST /v2/sign/requests/{id}/cancel", s.signEnd)
	route("GET /v2/sign/grants/{id}", func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		return q.VisibleSignRequest(ctx, h.ID, peerIP(r), r.PathValue("id"), true, s.now())
	})
	route("POST /v2/sign/grants/{id}/end", s.signEnd)
	route("POST /v2/sign/grants/{id}/sign", s.signWith)
}

type signCallKey struct{}

// signCall carries the request body in and a post-commit notification out.
type signCall struct {
	body  []byte
	after func()
}

func signInput(ctx context.Context, v any) error {
	c, _ := ctx.Value(signCallKey{}).(*signCall)
	if c == nil || len(c.body) == 0 {
		return errBad("JSON body required")
	}
	if err := json.Unmarshal(c.body, v); err != nil {
		return errBad("invalid JSON body")
	}
	return nil
}

// checkItems validates a list for one scheme and refuses duplicates.
func checkItems(sc signer.Scheme, items []signer.Item) error {
	if len(items) == 0 || len(items) > signer.MaxItems {
		return errBad(fmt.Sprintf("send 1 to %d artifacts", signer.MaxItems))
	}
	seen := map[string]bool{}
	bytes := 0
	for _, it := range items {
		if bytes += len(it.Message); bytes > signer.MaxMessageBytes {
			return errBad(fmt.Sprintf("at most %d bytes of artifacts a call for a scheme that signs the artifact itself", signer.MaxMessageBytes))
		}
		if err := sc.Valid(it); err != nil {
			return errBad(err.Error())
		}
		key := it.Name + "\x00" + it.SHA256 + "\x00" + it.SHA512
		if seen[key] {
			return errBad("duplicate artifact")
		}
		seen[key] = true
	}
	return nil
}

func (s *Server) signRequest(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	var in struct {
		Binding signer.Binding `json:"binding"`
		Reason  string         `json:"reason"`
		TTL     int            `json:"ttl_seconds"`
		Max     int            `json:"max_signatures"`
		Items   []signer.Item  `json:"items"`
	}
	if err := signInput(ctx, &in); err != nil {
		return nil, err
	}
	b, err := q.SignBinding(ctx, h.ID, in.Binding.Path, s.now())
	if err != nil {
		return nil, err
	}
	if !signBindingEqual(b, in.Binding) {
		return nil, errConflict("signer or admission changed")
	}
	sc, ok := signer.Lookup(b.Scheme)
	if !ok {
		return nil, errConflict("this broker does not know the signer's scheme")
	}
	if err = checkItems(sc, in.Items); err != nil {
		return nil, err
	}
	if len(in.Reason) > MaxReasonLen || strings.TrimSpace(in.Reason) == "" || hasControl(in.Reason, false) {
		return nil, errBad("invalid reason")
	}
	switch {
	case in.TTL < 0 || in.TTL > 0 && in.TTL < signer.MinGrantSeconds || in.Max < 0 || in.Max > signer.MaxGrantSignatures:
		return nil, errBad("invalid duration or count")
	case in.TTL == 0:
		if in.Max != 0 && in.Max != len(in.Items) {
			return nil, errBad("a single-use request signs exactly its artifacts; add --ttl for a signing grant")
		}
		in.Max = len(in.Items)
	default:
		in.TTL = min(in.TTL, signer.MaxGrantSeconds)
		if in.Max == 0 {
			in.Max = max(signer.DefaultSignatures, len(in.Items))
		}
		if in.Max < len(in.Items) {
			return nil, errBad("count is below the number of artifacts")
		}
	}
	peer := peerIP(r)
	if net.ParseIP(peer) == nil {
		return nil, errBad("missing source address")
	}
	now := s.now()
	n, err := s.allPending(ctx, q, h.ID, now)
	if err != nil {
		return nil, err
	}
	if n >= MaxPendingPerHost {
		return nil, &apiErr{429, "rate_limited", "too many pending requests"}
	}
	// Cancelled and decided requests count too: each one notifies the owner.
	pending := secs(s.cfg.TTL.PendingExpirySeconds)
	if recent, err := q.SignRecent(ctx, h.ID, now.Add(pending-time.Hour)); err != nil {
		return nil, err
	} else if recent >= signer.MaxRequestsPerHour {
		return nil, &apiErr{429, "rate_limited", "too many signing requests this hour; use a time-boxed grant (--ttl) for a run of signatures"}
	}
	out := signer.Request{Binding: b, ID: ids.New(), Peer: peer, Reason: in.Reason, Items: in.Items, TTL: in.TTL, Max: in.Max, Deadline: now.Add(pending).UnixMilli(), Status: "pending"}
	if err = q.NewSignRequest(ctx, h.ID, out); err != nil {
		return nil, err
	}
	if err = q.Audit(ctx, now, "host:"+h.Name, "sign_request", "request:"+out.ID, fmt.Sprintf("%s scheme=%s ttl=%d max=%d items=%s", b.Path, b.Scheme, out.TTL, out.Max, itemDigests(out.Items))); err != nil {
		return nil, err
	}
	// Only after commit: the page refreshes and the owner is told.
	if c, _ := ctx.Value(signCallKey{}).(*signCall); c != nil {
		c.after = func() {
			s.bcast.notify()
			s.notify.Send("aqmas: "+h.Name, fmt.Sprintf("aqmas: %s wants %d signature(s) with %s [ref %s]", h.Name, len(out.Items), b.Path, ref(out.ID)), s.cfg.PublicBaseURL+"/")
		}
	}
	return out, nil
}
func (s *Server) signEnd(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	grant := strings.HasSuffix(r.URL.Path, "/end")
	v, err := q.VisibleSignRequest(ctx, h.ID, peerIP(r), r.PathValue("id"), grant, s.now())
	if err != nil {
		return nil, err
	}
	status := "cancelled"
	if grant {
		status = "revoked"
	}
	if err = q.DecideSign(ctx, v.ID, status, "", 0, 0, 0); err != nil {
		return nil, errConflict("request no longer active")
	}
	s.releaseAfter(ctx, "sign:"+v.ID)
	return api.OK{OK: true}, q.Audit(ctx, s.now(), "host:"+h.Name, "sign_"+status, "request:"+v.ID, v.Path)
}

// signWith is the one place a signer key is opened. A single-use grant signs
// exactly the artifacts the owner saw, once; a time-boxed grant signs what
// the host submits until its count or deadline runs out. Every signature is
// checked against the public key and audited before it is returned.
func (s *Server) signWith(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	var in struct {
		Items []signer.Item `json:"items"`
	}
	if err := signInput(ctx, &in); err != nil {
		return nil, err
	}
	now := s.now()
	v, err := q.VisibleSignRequest(ctx, h.ID, peerIP(r), r.PathValue("id"), true, now)
	if err != nil {
		return nil, err
	}
	if v.Status != "approved" || v.Until <= now.UnixMilli() {
		return nil, errConflict("grant expired, revoked or used up")
	}
	sc, ok := signer.Lookup(v.Scheme)
	if !ok {
		return nil, errConflict("unknown signing scheme")
	}
	if err = checkItems(sc, in.Items); err != nil {
		return nil, err
	}
	if v.TTL == 0 {
		a, _ := json.Marshal(in.Items)
		b, _ := json.Marshal(v.Items)
		if string(a) != string(b) || v.Used != 0 {
			return nil, errConflict("a single-use grant signs exactly the approved artifacts, once")
		}
	} else if v.Used+len(in.Items) > v.Max {
		return nil, errConflict("grant has too few signatures left")
	}
	t, err := q.VaultSet(ctx, v.Set)
	if err != nil || t.Kind != "signer" || t.Scheme != v.Scheme || string(t.PublicKey) != string(v.PublicKey) {
		return nil, errConflict("signer no longer available")
	}
	rec, err := q.SignerCipher(ctx, v.Set)
	if err != nil {
		return nil, err
	}
	row, err := s.setRow(ctx, q, "signer", v.Set)
	if err != nil || string(rec.Wrap) != string(row.ID) {
		return nil, errConflict("signer no longer available")
	}
	out := signer.Signed{}
	// The key is decrypted from the open signer bucket for this call only.
	err = s.withBucket(row, func(b seal.Bucket, k *seal.Key) error {
		p, err := b.Open(k, seal.RoleSignerKey, signerFields(t), rec.Payload)
		if err != nil {
			return errConflict("signer record failed authentication")
		}
		var key signerSecret
		err = json.Unmarshal(p, &key)
		clear(p)
		defer clear(key.Private)
		if err != nil || key.Scheme != t.Scheme || len(key.Private) != 32 {
			return errConflict("signer record failed authentication")
		}
		for _, it := range in.Items {
			sig, err := sc.Sign(key.Private, it)
			if err != nil || !sc.Verify(t.PublicKey, it, sig) {
				return errConflict("signing failed its own verification")
			}
			out.Signatures = append(out.Signatures, signer.Signature{Name: it.Name, SHA256: it.SHA256, Signature: sig})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, it := range in.Items {
		if err = q.Audit(ctx, now, "host:"+h.Name, "sign", "grant:"+v.Grant, fmt.Sprintf("%s scheme=%s sha256=%s sha512=%s size=%d name=%q enrollment=%s address=%s", v.Path, v.Scheme, it.SHA256, it.SHA512, it.Size, it.Name, v.Enrollment, v.Peer)); err != nil {
			return nil, err
		}
	}
	if err = q.UseSign(ctx, v.Grant, v.Set, len(in.Items), now); err != nil {
		return nil, errConflict("grant expired, revoked or used up")
	}
	if v.Used += len(in.Items); v.Used >= v.Max {
		v.Status = "used"
		s.releaseAfter(ctx, "sign:"+v.ID) // the last signature ends the hold
	}
	out.Request = v
	return out, nil
}
