package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Recovery drill and enrolment in Admin (docs/BUCKETS.md §7, §10; contract
// "Recovery"). The pasted age identity reaches the broker HPKE-sealed to a
// fresh single-use key; it opens scope keys from their recovery wraps, which
// are checked (drill) or wrapped for one passkey (enrol), then everything is
// wiped. Nothing stays open.

func (s *Server) recoveryRoutes(m *http.ServeMux) {
	s.sealedEndpoint(m, "POST /api/ui/seal/recovery/key", s.recoveryKey)
	s.sealedEndpoint(m, "POST /api/ui/seal/recovery/challenge", s.recoveryChallenge)
	s.sealedEndpoint(m, "POST /api/ui/seal/recovery/finish", s.recoveryFinish)
}

func (s *Server) recoveryKey(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct{}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if _, err := s.vaultOwner(ctx, s.store.Q(), sess); err != nil {
		return nil, err
	}
	id, pub, err := s.seal.opens.Begin(sess, "recovery", "")
	if err != nil {
		return nil, &apiErr{429, "rate_limited", err.Error()}
	}
	return map[string]any{"attempt_id": id, "recipient": encodeID(pub)}, nil
}

type recoveryChoice struct {
	Mode       string   `json:"mode"`
	Attempt    string   `json:"attempt_id"`
	PacketHash string   `json:"packet_sha256"`
	Credential string   `json:"credential_id,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	// Enrol a passkey without PRF for the browser holding this key (§13).
	Browser string `json:"browser_key,omitempty"`
	Label   string `json:"browser_label,omitempty"`
}

// recoveryPlan validates a choice and returns the canonical's own fields and
// the target passkey (enrol).
func (s *Server) recoveryPlan(ctx context.Context, q *store.Q, sess string, c recoveryChoice) (map[string]any, *storedPasskey, error) {
	if _, ok := s.seal.opens.Peek(sess, c.Attempt); !ok {
		return nil, nil, errConflict("the recovery key expired; paste it again")
	}
	if h, err := hex.DecodeString(c.PacketHash); err != nil || len(h) != 32 || hex.EncodeToString(h) != c.PacketHash {
		return nil, nil, errBad("invalid packet digest")
	}
	f := map[string]any{"packet_sha256": c.PacketHash}
	switch c.Mode {
	case "drill":
		if c.Credential != "" || len(c.Scopes) > 0 || c.Browser != "" || c.Label != "" {
			return nil, nil, errBad("a drill names no passkey or scope")
		}
		return f, nil, nil
	case "enrol":
		scopes, err := s.validScopes(ctx, q, c.Scopes)
		if err != nil || len(scopes) == 0 || !slices.Equal(scopes, c.Scopes) {
			return nil, nil, errBad("name one or two scopes, installation first")
		}
		for _, sc := range scopes {
			if _, err := q.Scope(ctx, sc); err != nil {
				return nil, nil, errConflict(scopeName(ctx, q, sc) + " has no scope key to recover")
			}
		}
		raw, err := strictB64(c.Credential, 1023)
		if err != nil {
			return nil, nil, err
		}
		pk, _, err := findPasskey(ctx, q, passkeyID(raw))
		if err != nil {
			return nil, nil, err
		}
		f["credential_id"], f["nickname"], f["scopes"] = c.Credential, pk.Name, scopes
		// A passkey opens buckets one way only: with its own secret, or from
		// remembered browsers (§13.4).
		wraps, err := q.ScopeWraps(ctx, pk.ID)
		if err != nil {
			return nil, nil, err
		}
		keys, err := q.BrowserKeys(ctx, pk.ID)
		if err != nil {
			return nil, nil, err
		}
		if c.Browser == "" {
			if c.Label != "" {
				return nil, nil, errBad("only remembering a browser takes a label")
			}
			if len(keys) > 0 {
				return nil, nil, errConflict("this passkey opens buckets only from remembered browsers: enrol it for this browser, or forget its browsers first")
			}
			return f, pk, nil
		}
		pub, err := parseBrowserKey(c.Browser)
		if err != nil {
			return nil, nil, err
		}
		if l, err := normalizeBrowserLabel(c.Label); err != nil || l != c.Label {
			return nil, nil, errBad("a browser label has 1 to 64 printable characters, single spaces")
		}
		if len(wraps) > 0 {
			return nil, nil, errConflict("this passkey opens buckets with its own secret (PRF): a remembered browser is only for passkeys without PRF")
		}
		f["browser_key"], f["browser_key_id"], f["browser_label"] = c.Browser, seal.BrowserKeyID(pub), c.Label
		return f, pk, nil
	}
	return nil, nil, errBad("mode must be drill or enrol")
}

func (s *Server) recoveryCanonical(fields map[string]any, mode, attempt, nonce, at string) (string, error) {
	m := s.reviewFields("recovery", mode, attempt)
	m["nonce"], m["issued_at"] = nonce, at
	for k, v := range fields {
		m[k] = v
	}
	return reviewJSON(m)
}

func (s *Server) recoveryChallenge(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in recoveryChoice
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	q := s.store.Q()
	if _, err := s.vaultOwner(ctx, q, sess); err != nil {
		return nil, err
	}
	fields, target, err := s.recoveryPlan(ctx, q, sess, in)
	if err != nil {
		return nil, err
	}
	base := s.reviewFields("recovery", in.Mode, in.Attempt)
	text, err := s.recoveryCanonical(fields, in.Mode, in.Attempt, base["nonce"].(string), base["issued_at"].(string))
	if err != nil {
		return nil, err
	}
	if in.Mode == "drill" {
		return s.beginReview(ctx, sess, "recovery", in.Mode, text, nil)
	}
	salts := make([]seal.ID, len(in.Scopes))
	for i := range salts {
		salts[i] = seal.RandomID()
	}
	var browser []byte
	if in.Browser != "" {
		if browser, err = parseBrowserKey(in.Browser); err != nil {
			return nil, err
		}
	}
	opts, t, err := s.enrolTap(sess, "enrol", text, target.cred, in.Scopes, salts, browser)
	if err != nil {
		return nil, err
	}
	id, err := s.storeChallenge(ctx, sess, "recovery", in.Mode, text, t)
	if err != nil {
		return nil, err
	}
	return api.ChallengeResponse{ChallengeID: id, Canonical: text, PublicKey: opts, Open: t.offer()}, nil
}

func (s *Server) recoveryFinish(ctx context.Context, r *http.Request, sess string) (any, error) {
	var in struct {
		ChallengeID string          `json:"challenge_id"`
		Assertion   json.RawMessage `json:"assertion"`
		Packet      string          `json:"packet"`
		Open        *api.OpenPacket `json:"open,omitempty"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	z := s.seal
	c, err := s.consume(ctx, in.ChallengeID, "action", s.now())
	if err != nil {
		return nil, err
	}
	t := z.taps.take(c.ID)
	if c.SessionHash != sess || c.ObjectType != "recovery" {
		return nil, errConflict("wrong ceremony")
	}
	var m struct {
		recoveryChoice
		Action   string
		ID       string
		Nonce    string
		IssuedAt string `json:"issued_at"`
	}
	if json.Unmarshal([]byte(c.Canonical), &m) != nil || m.Action != c.ObjectID {
		return nil, errBad("invalid recovery ceremony")
	}
	m.Mode, m.Attempt = m.Action, m.ID
	q := s.store.Q()
	fields, target, err := s.recoveryPlan(ctx, q, sess, m.recoveryChoice)
	if err != nil {
		return nil, err
	}
	if want, err := s.recoveryCanonical(fields, m.Mode, m.Attempt, m.Nonce, m.IssuedAt); err != nil || want != c.Canonical {
		return nil, errConflict("recovery state changed; start again")
	}
	var row int64
	if m.Mode == "enrol" {
		if t == nil || t.purpose != "enrol" || t.session != sess || !s.now().Before(t.expires) || !bytes.Equal(t.cred, target.CredentialID) {
			return nil, errConflict("stale recovery enrolment; start again")
		}
		row, err = s.verifySelected(ctx, seal.OpenChallenge([]byte(c.Canonical), []byte(t.descriptor)), in.Assertion, [][]byte{t.cred}, t.ext)
		if err == nil && row != target.ID {
			err = errForbidden("wrong passkey for this enrolment")
		}
	} else {
		if t != nil || in.Open != nil {
			return nil, errBad("a drill opens nothing")
		}
		row, err = s.verifyAssertion(ctx, sha256Bytes(c.Canonical), in.Assertion)
	}
	if err != nil {
		return nil, err
	}
	if err = s.sealOwner(ctx, q, sess, row); err != nil {
		return nil, err
	}
	packet, err := strictB64(in.Packet, 65+8192)
	if err != nil || len(packet) < 65+17 || sha256Hex(packet) != m.PacketHash {
		return nil, errBad("the recovery packet is not the one reviewed")
	}
	at, err := z.opens.Take(sess, "recovery", m.Attempt)
	if err != nil {
		return nil, errConflict("the recovery key expired; paste it again")
	}
	text, err := at.OpenBytes(z.installation, z.opens.Epoch(), nil, packet[:65], packet[65:])
	if err != nil {
		return nil, errBad("the recovery packet could not be opened; reload the page and try again")
	}
	identity, err := seal.ParseIdentity(text)
	clear(text)
	if err != nil {
		return nil, errBad("that is not an age identity")
	}
	scopes, err := q.Scopes(ctx)
	if err != nil {
		return nil, err
	}
	recoverScope := func(x store.ScopeRow) (*seal.Key, error) {
		k, err := seal.Scope{Installation: z.installation, Name: x.Scope, Public: x.Public}.Recover(identity, z.recipient, x.Recovery)
		if err != nil {
			return nil, errConflict("this is not the recovery key of this installation: nothing was changed")
		}
		return k, nil
	}
	nScopes, nBuckets := 0, 0
	if m.Mode == "drill" {
		for _, x := range scopes {
			k, err := recoverScope(x)
			if err != nil {
				return nil, err
			}
			n, err := s.drillScope(ctx, q, x, k)
			k.Destroy()
			if err != nil {
				return nil, err
			}
			nScopes++
			nBuckets += n
		}
		_ = q.Audit(ctx, s.now(), "owner", "recovery_drill", "seal", fmt.Sprintf("passkey=%d scopes=%d buckets=%d", row, nScopes, nBuckets))
		s.log.Info("recovery drill passed", "scopes", nScopes, "buckets", nBuckets)
		return map[string]any{"ok": true, "scopes": nScopes, "buckets": nBuckets}, nil
	}
	keks, err := s.enrolKEKs(t, sess, c.Canonical, in.Open)
	if err != nil {
		return nil, err
	}
	defer destroyKeys(keks)
	z.scopeMu.Lock()
	defer z.scopeMu.Unlock()
	var wraps []store.ScopeWrapRow
	var bwraps []store.BrowserWrapRow
	var browser []byte
	if m.Browser != "" {
		if browser, err = parseBrowserKey(m.Browser); err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(browser, t.browserPub) {
		return nil, errConflict("stale recovery enrolment; start again")
	}
	for i, sc := range t.scopes {
		j := slices.IndexFunc(scopes, func(x store.ScopeRow) bool { return x.Scope == sc })
		if j < 0 {
			return nil, errConflict("scope changed; start again")
		}
		k, err := recoverScope(scopes[j])
		if err != nil {
			return nil, err
		}
		if browser != nil {
			bs := seal.BrowserScope{Installation: z.installation, RPID: s.rpID, RawID: t.cred, Scope: sc, WrapID: t.salts[i], Browser: browser}
			w, err := bs.Wrap(keks[i], k, scopes[j].Public)
			k.Destroy()
			if err != nil {
				return nil, err
			}
			sealed, err := bs.SealKEK(keks[i])
			if err != nil {
				return nil, err
			}
			bwraps = append(bwraps, store.BrowserWrapRow{ID: bytes.Clone(t.salts[i][:]), Scope: sc, Wrap: w, SealedKEK: sealed, Created: s.now()})
			bs2, err := q.ScopeBuckets(ctx, sc)
			if err != nil {
				return nil, err
			}
			nScopes++
			nBuckets += len(bs2)
			continue
		}
		ps := seal.PasskeyScope{Installation: z.installation, RPID: s.rpID, RawID: t.cred, Scope: sc, Salt: t.salts[i]}
		w, err := ps.Wrap(keks[i], k, scopes[j].Public)
		k.Destroy()
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, store.ScopeWrapRow{Passkey: row, Scope: sc, Salt: bytes.Clone(t.salts[i][:]), Wrap: w, Created: s.now()})
		bs, err := q.ScopeBuckets(ctx, sc)
		if err != nil {
			return nil, err
		}
		nScopes++
		nBuckets += len(bs)
	}
	err = s.store.Tx(ctx, func(q *store.Q) error {
		if err := s.sealOwner(ctx, q, sess, row); err != nil {
			return err
		}
		for _, w := range wraps {
			if err := q.PutScopeWrap(ctx, w); errors.Is(err, store.ErrTestedWrap) {
				return errConflict("this passkey already opens " + scopeName(ctx, q, w.Scope) + " (tested): disable it for that scope first")
			} else if err != nil {
				return err
			}
		}
		if len(bwraps) > 0 {
			key, err := q.PutBrowserKey(ctx, store.BrowserKeyRow{Passkey: row, Public: browser, Label: m.Label, Created: s.now()})
			if err != nil {
				return err
			}
			for _, w := range bwraps {
				w.Key = key
				if err := q.PutBrowserWrap(ctx, w); errors.Is(err, store.ErrTestedWrap) {
					return errConflict("this browser is already remembered for " + scopeName(ctx, q, w.Scope) + " (tested): forget it first")
				} else if err != nil {
					return err
				}
			}
		}
		return q.Audit(ctx, s.now(), "owner", "recovery_enrol", "passkey:"+target.id, c.Canonical)
	})
	if err != nil {
		return nil, err
	}
	s.bcast.notify()
	s.notify.Send("aqmas: recovery", "The recovery key enabled a passkey for "+fmt.Sprint(t.scopes), s.cfg.PublicBaseURL+"/")
	return map[string]any{"ok": true, "scopes": nScopes, "buckets": nBuckets}, nil
}

// drillScope opens every bucket of a scope and authenticates its records,
// then wipes everything. It returns the number of buckets checked.
func (s *Server) drillScope(ctx context.Context, q *store.Q, sc store.ScopeRow, skS *seal.Key) (int, error) {
	rows, err := q.ScopeBuckets(ctx, sc.Scope)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		b := s.sealBucket(row)
		k, err := b.UnwrapWith(skS, sc.Public, row.Wrap)
		if err != nil {
			return 0, errConflict(row.Label + " did not open from the recovery key")
		}
		err = s.checkRecords(ctx, q, row, b, k)
		k.Destroy()
		if err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// checkRecords authenticates every record a bucket holds, discarding plaintext.
func (s *Server) checkRecords(ctx context.Context, q *store.Q, row store.BucketRow, b seal.Bucket, k *seal.Key) error {
	bad := errConflict(row.Label + ": a record failed authentication")
	open := func(role string, fields [][]byte, rec []byte) error {
		p, err := b.Open(k, role, fields, rec)
		clear(p)
		if err != nil {
			return bad
		}
		return nil
	}
	switch row.Kind {
	case seal.RoleSSHCA, seal.RoleInternalCA:
		return open(row.Kind, nil, row.Payload)
	case seal.RoleCFProxy:
		return open(row.Kind, s.cfRecordFields(row), row.Payload)
	case "env-set":
		rev, err := q.SetRevision(ctx, row.Ref)
		if err != nil || rev == 0 {
			return err
		}
		cur, err := q.EnvCipher(ctx, row.Ref, rev)
		if err != nil {
			return err
		}
		recs, err := parseRecords(cur.Payload, true)
		if err != nil {
			return err
		}
		entries, err := openEntries(b, k, row.Ref, recs)
		for i := range entries {
			entries[i].Value = ""
		}
		if err != nil {
			return bad
		}
	case "signer":
		scheme, public, rec, err := q.SignerKey(ctx, row.Ref)
		if err != nil {
			return err
		}
		return open(seal.RoleSignerKey, signerFields(store.VaultTarget{SetID: row.Ref, Scheme: scheme, PublicKey: public}), rec.Payload)
	}
	return nil
}
