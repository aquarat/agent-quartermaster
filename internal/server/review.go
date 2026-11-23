package server

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Additional ceremony profiles are not accepted by the legacy decide or root
// update parsers. Each finish rebuilds its own exact profile before apply.
func reviewJSON(v any) (string, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(b.Bytes(), []byte("\n"))), nil
}
func (s *Server) reviewFields(obj, action, id string) map[string]any {
	return map[string]any{"v": 3, "object": obj, "action": action, "id": id, "installation": s.seal.installation, "epoch": s.seal.opens.Epoch(), "issued_at": s.now().UTC().Format(time.RFC3339), "nonce": canon.NewNonce()}
}
func (s *Server) beginReview(ctx context.Context, sess, obj, action, text string, selected *storedPasskey) (api.ChallengeResponse, error) {
	return s.beginTap(ctx, sess, obj, action, text, nil, selected)
}

// beginTap stores a v3 challenge whose tap also opens the needed buckets.
func (s *Server) beginTap(ctx context.Context, sess, obj, action, text string, needs []bucketNeed, selected *storedPasskey) (api.ChallengeResponse, error) {
	var out api.ChallengeResponse
	opts, t, err := s.actionOptions(ctx, sess, text, needs, selected)
	if err != nil {
		return out, err
	}
	id, err := s.storeChallenge(ctx, sess, obj, action, text, t)
	if err != nil {
		return out, err
	}
	return api.ChallengeResponse{Canonical: text, ChallengeID: id, PublicKey: opts, Open: t.offer()}, nil
}

// storeChallenge records a single-use challenge and, with it, the server half
// of the open the tap carries.
func (s *Server) storeChallenge(ctx context.Context, sess, obj, objectID, text string, t *tapOpen) (string, error) {
	now := s.now()
	c := &store.Challenge{ID: ids.New(), Purpose: "action", ObjectType: obj, ObjectID: objectID, Canonical: text, SessionHash: sess, CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
	if err := s.store.Q().InsertChallenge(ctx, c); err != nil {
		return "", err
	}
	if t != nil {
		t.canonical = text
		s.seal.taps.put(c.ID, t, now)
	}
	return c.ID, nil
}

// takeReview consumes a v3 challenge, verifies the tap (opening buckets when
// it offered an open) and the owner. settle(true) keeps the descriptor's
// holds after a successful apply; settle(false) releases them. settle is
// never nil.
func (s *Server) takeReview(ctx context.Context, sess, obj string, in api.DecideRequest) (*store.Challenge, int64, func(bool), error) {
	noop := func(bool) {}
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil {
		return nil, 0, noop, err
	}
	if c.SessionHash != sess || c.ObjectType != obj {
		if s.seal != nil {
			s.seal.taps.take(c.ID)
		}
		return nil, 0, noop, errConflict("wrong ceremony")
	}
	row, settle, err := s.verifyTap(ctx, sess, c.ID, c.Canonical, in.Assertion, in.Open)
	if err == nil {
		if err = s.sealOwner(ctx, s.store.Q(), sess, row); err != nil {
			settle(false)
			settle = noop
		}
	}
	return c, row, settle, err
}
