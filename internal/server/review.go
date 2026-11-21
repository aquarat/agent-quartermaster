package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/canon"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/go-webauthn/webauthn/webauthn"
	"time"
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
	return map[string]any{"v": 3, "object": obj, "action": action, "id": id, "installation": s.seal.inv.Installation, "epoch": s.seal.attempts.Epoch(), "issued_at": s.now().UTC().Format(time.RFC3339), "nonce": canon.NewNonce()}
}
func (s *Server) beginReview(ctx context.Context, sess, obj, action, text string, selected *storedPasskey) (api.ChallengeResponse, error) {
	var out api.ChallengeResponse
	o, err := s.loadOwner(ctx)
	if err != nil {
		return out, err
	}
	if selected != nil {
		o.creds = []webauthn.Credential{selected.cred}
	}
	opts, err := s.requestOptions(o, canon.Challenge(text))
	if err != nil {
		return out, err
	}
	now := s.now()
	c := &store.Challenge{ID: ids.New(), Purpose: "action", ObjectType: obj, ObjectID: action, Canonical: text, SessionHash: sess, CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
	if err = s.store.Q().InsertChallenge(ctx, c); err != nil {
		return out, err
	}
	return api.ChallengeResponse{Canonical: text, ChallengeID: c.ID, PublicKey: opts}, nil
}
func (s *Server) takeReview(ctx context.Context, sess, obj string, in api.DecideRequest) (*store.Challenge, int64, error) {
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil {
		return nil, 0, err
	}
	if c.SessionHash != sess || c.ObjectType != obj {
		return nil, 0, errConflict("wrong ceremony")
	}
	row, err := s.verifyAssertion(ctx, canon.Challenge(c.Canonical), in.Assertion)
	if err == nil {
		err = s.sealOwner(ctx, s.store.Q(), sess, row)
	}
	return c, row, err
}
