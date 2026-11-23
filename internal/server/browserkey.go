package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Remembered browsers (docs/BUCKETS.md §13): a passkey without PRF opens
// buckets from a browser profile that holds a key of its own. The broker
// stores that key's public half and, per scope, two ciphertexts: the scope key
// under a KEK and the KEK sealed to the browser key. It never holds anything
// that unwraps either. The sealed KEKs leave the broker only here: inside a
// pending tap, after that tap's assertion by the wrap's own passkey verified.

func (s *Server) browserRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/browser/release", s.browserRelease)
}

// parseBrowserKey decodes a browser key's public half: an uncompressed P-256 point.
func parseBrowserKey(text string) ([]byte, error) {
	pub, err := strictB64(text, 65)
	if err != nil || !seal.ValidPublic(pub) {
		return nil, errBad("invalid browser key")
	}
	return pub, nil
}

// normalizeBrowserLabel trims a label and collapses its white space: 1 to 64
// printable characters.
func normalizeBrowserLabel(in string) (string, error) {
	out := strings.Join(strings.Fields(in), " ")
	if out == "" || utf8.RuneCountInString(out) > 64 || !utf8.ValidString(out) {
		return "", errBad("a browser label has 1 to 64 characters")
	}
	for _, r := range out {
		if !unicode.IsPrint(r) {
			return "", errBad("a browser label has printable characters only")
		}
	}
	return out, nil
}

// intentBrowser validates the browser fields of a capability intent and
// returns the browser key (nil when the intent names none).
func intentBrowser(in capIntent) ([]byte, error) {
	named := in.Action == "remember" || in.Action == "forget"
	switch {
	case named && in.Browser == "":
		return nil, errBad("name the browser key")
	case in.Browser != "" && !named && in.Action != "test":
		return nil, errBad("this passkey change takes no browser key")
	case in.Label != "" && in.Action != "remember":
		return nil, errBad("only remembering a browser takes a label")
	case named && in.Capability != "unlock":
		return nil, errBad("a remembered browser is an unlock capability")
	case in.Action == "forget" && len(in.Scopes) > 0:
		return nil, errBad("forgetting a browser names no scope")
	}
	if in.Browser == "" {
		return nil, nil
	}
	pub, err := parseBrowserKey(in.Browser)
	if err != nil {
		return nil, err
	}
	if in.Action == "remember" {
		if l, err := normalizeBrowserLabel(in.Label); err != nil || l != in.Label {
			return nil, errBad("a browser label has 1 to 64 printable characters, single spaces")
		}
	}
	return pub, nil
}

// capBrowserFields adds the browser key to a passkey-capability canonical:
// the public half, its fingerprint (what the audit log and the UI show) and,
// for remember, the label.
func capBrowserFields(m map[string]any, in capIntent) {
	if in.Browser == "" {
		return
	}
	m["browser_key"] = in.Browser
	if pub, err := parseBrowserKey(in.Browser); err == nil {
		m["browser_key_id"] = seal.BrowserKeyID(pub)
	}
	if in.Action == "remember" {
		m["browser_label"] = in.Label
	}
}

type releasedWrap struct {
	Scope     string `json:"scope"`
	ID        string `json:"id"`
	SealedKEK string `json:"sealed_kek"`
}

// browserRelease hands a remembered browser its sealed KEKs for one pending
// tap. The body carries the tap's assertion: it must verify over the tap's
// bound challenge and come from the passkey the wraps belong to. Nothing is
// consumed or recorded: the finish that follows verifies the same assertion
// again, consumes the challenge and applies the action. One release per tap.
func (s *Server) browserRelease(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		ChallengeID string          `json:"challenge_id"`
		Assertion   json.RawMessage `json:"assertion"`
		Browser     string          `json:"browser_key"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	pub, err := parseBrowserKey(in.Browser)
	if err != nil {
		return nil, err
	}
	t := s.seal.taps.peek(in.ChallengeID)
	if t == nil || t.session != sess || !s.now().Before(t.expires) || t.canonical == "" {
		return nil, errConflict("stale approval; review again")
	}
	if t.purpose != "" && (t.purpose != "test" || !bytes.Equal(t.browserPub, pub)) {
		return nil, errConflict("this step releases nothing to a browser")
	}
	if t.released.Load() != nil {
		return nil, errConflict("this approval's keys were already released; review again")
	}
	if t.tries.Add(1) > 3 {
		return nil, &apiErr{429, "rate_limited", "too many attempts for this approval; review again"}
	}
	var allowed [][]byte
	if t.cred != nil {
		allowed = [][]byte{t.cred}
	}
	challenge := seal.OpenChallenge([]byte(t.canonical), []byte(t.descriptor))
	row, err := s.verifyOnly(ctx, challenge, in.Assertion, allowed, t.ext)
	if err != nil {
		return nil, err
	}
	q := s.store.Q()
	if err = s.sealOwner(ctx, q, sess, row); err != nil {
		return nil, err
	}
	// The wraps of exactly this passkey and this browser key: another passkey's
	// assertion finds no row here, whatever key it names.
	key, err := q.BrowserKey(ctx, row, pub)
	if err != nil {
		return nil, &apiErr{423, "locked", "this browser is not remembered for this passkey: enable it again in Security → Passkeys"}
	}
	out := make([]releasedWrap, 0, len(t.scopes))
	for i, scope := range t.scopes {
		bw, err := q.BrowserWrap(ctx, key.ID, scope)
		if err != nil || bw.Passkey != row || t.purpose == "test" && !bytes.Equal(bw.ID, t.salts[i][:]) {
			return nil, &apiErr{423, "locked", "this browser is not remembered for " + scopeName(ctx, q, scope) + ": enable it again in Security → Passkeys"}
		}
		out = append(out, releasedWrap{Scope: scope, ID: encodeID(bw.ID), SealedKEK: encodeID(bw.SealedKEK)})
	}
	// Only while the tap is pending: under the registry lock a finish takes it
	// with, and with its challenge still unused. A release that lost the race
	// against the finish (or against a second release) hands out nothing.
	if !s.seal.taps.release(in.ChallengeID, t, &tapRelease{row: row, key: key.ID}) {
		return nil, errConflict("this approval was finished or its keys were already released; review again")
	}
	if ok, err := q.ChallengePending(ctx, in.ChallengeID, s.now()); err != nil || !ok {
		return nil, errConflict("stale approval; review again")
	}
	s.log.Info("sealed keys released to a remembered browser", "passkey", passkeyID(key.RawID), "browser", seal.BrowserKeyID(pub), "scopes", len(out))
	return map[string]any{"wraps": out}, nil
}

// browserView is one remembered browser in GET /api/ui/seal/status.
type browserView struct {
	ID       string          `json:"id"`  // fingerprint of the public half
	Key      string          `json:"key"` // the public half (base64url): what a Forget names
	Label    string          `json:"label"`
	Created  string          `json:"created_at"`
	LastUsed string          `json:"last_used_at,omitempty"`
	Scopes   []coverageScope `json:"scopes"`
}

// browserViews lists a passkey's remembered browsers with the scopes each opens.
func browserViews(keys []store.BrowserKeyRow, wraps []store.BrowserWrapRow, passkey int64) []browserView {
	out := []browserView{}
	for _, k := range keys {
		if k.Passkey != passkey {
			continue
		}
		v := browserView{ID: seal.BrowserKeyID(k.Public), Key: encodeID(k.Public), Label: k.Label, Created: k.Created.UTC().Format("2006-01-02T15:04:05Z"), Scopes: []coverageScope{}}
		if k.LastUsed != nil {
			v.LastUsed = k.LastUsed.UTC().Format("2006-01-02T15:04:05Z")
		}
		for _, w := range wraps {
			if w.Key == k.ID {
				v.Scopes = append(v.Scopes, coverageScope{w.Scope, w.Tested != nil})
			}
		}
		out = append(out, v)
	}
	return out
}
