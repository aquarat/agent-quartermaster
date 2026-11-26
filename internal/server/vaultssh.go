package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/seal"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// SSH keys (docs/SSH-KEYS.md). An SSH key is a signer whose scheme signs SSH
// login requests only, stored exactly like a signer: sealed to its own bucket,
// opened only inside a signing call. Hosts use it in one of two ways. The
// preferred one keeps the key here: the owner approves a time-boxed login
// grant and `aqmas ssh-agent` forwards each login's signature request. The
// other hands the private key out, once per approval, and only for a key the
// owner marked "may be handed out". That delivery is the single route in
// aqmasd that returns a private key.

// reviewSSHKeyCreate validates a new SSH key and returns its signed metadata.
// The key is generated (or the pasted one opened) at the challenge; finish
// re-derives the same public half from the pending entry.
func (s *Server) reviewSSHKeyCreate(ctx context.Context, q *store.Q, sess string, owner func(string) error, c *vaultChoice, facts map[string]any, begin bool) (map[string]any, error) {
	t, err := q.VaultService(ctx, c.Service)
	if err != nil {
		return nil, err
	}
	if err = owner(t.OrgID); err != nil {
		return nil, err
	}
	sc, ok := signer.Lookup(c.Scheme)
	if !ok || !sc.SSH || !catalogueID.MatchString(c.ID) || !config.ValidName(c.Slug) || !catalogueTitle.MatchString(c.Title) || strings.TrimSpace(c.Title) != c.Title {
		return nil, errBad("invalid SSH key")
	}
	if !signer.ValidSSHComment(c.Comment) {
		return nil, errBad("the comment is 1 to 100 plain ASCII characters, without a leading or trailing space")
	}
	if c.Handout == nil {
		return nil, errBad("say whether the key may be handed out")
	}
	if free, err := q.SetSlugFree(ctx, t.ServiceID, c.ID, c.Slug); err != nil || !free {
		return nil, errConflict("a set with that name or ID exists; reload")
	}
	if err = s.canWrite(ctx, q, "signer", c.ID, t.OrgID); err != nil {
		return nil, err
	}
	t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Revision = c.ID, c.Slug, c.Title, "ssh-key", 0
	var pub []byte
	recipient := "" // the upload recipient of a pasted key; empty for a generated one
	switch {
	case c.Source == "generate" && begin:
		if c.Attempt != "" || c.Enc != "" || c.Ciphertext != "" {
			return nil, errBad("unexpected upload")
		}
		priv, p, err := sc.Generate()
		if err != nil {
			return nil, err
		}
		if c.Attempt, err = s.seal.vault.add(s.now(), &vaultPending{session: sess, purpose: "signer-generate", target: t.SetID, scheme: sc.ID, priv: priv, pub: p}); err != nil {
			clear(priv)
			return nil, err
		}
		pub = p
	case c.Source == "generate":
		p := s.seal.vault.get(s.now(), sess, c.Attempt, false)
		if p == nil || p.purpose != "signer-generate" || p.target != t.SetID || p.scheme != sc.ID {
			return nil, errConflict("generated key expired; start again")
		}
		clear(p.priv)
		pub = p.pub
	case c.Source == "import":
		var p *vaultPending
		if begin {
			p, err = s.submit(sess, *c, "signer-import", t.SetID)
		} else if p = s.seal.vault.get(s.now(), sess, c.Attempt, false); p == nil || p.purpose != "signer-import" || p.target != t.SetID || p.scheme != sc.ID {
			err = errConflict("upload attempt expired; start again")
		}
		if err != nil {
			return nil, err
		}
		var priv []byte
		if priv, pub, err = s.openSignerKey(p, c.Attempt, t.SetID); err != nil {
			return nil, err
		}
		clear(priv)
		recipient = encodeID(p.recipient.Public())
	default:
		return nil, errBad("choose generate or import")
	}
	t.Scheme, t.PublicKey = sc.ID, pub
	line, err := signer.AuthorizedKey(sc.ID, pub, c.Comment)
	if err != nil {
		return nil, errBad("invalid SSH key")
	}
	m := targetFields(t)
	m["scheme"], m["source"], m["attempt_id"], m["recipient"], m["result_revision"] = sc.ID, c.Source, c.Attempt, recipient, 0
	m["public_key"], m["fingerprint"], m["authorized_key"], m["comment"], m["handout"] = encodeID(pub), setFingerprint(t), line, c.Comment, *c.Handout
	facts["public_key"], facts["fingerprint"], facts["authorized_key"] = m["public_key"], m["fingerprint"], line
	return m, nil
}

// applySSHKeyCreate seals the key the owner signed for into its own bucket.
func (s *Server) applySSHKeyCreate(ctx context.Context, q *store.Q, sess, id, service, slug, title, scheme, source, attempt, public, comment string, handout bool, now time.Time) (out any, object, detail, note string, err error) {
	sc, _ := signer.Lookup(scheme)
	p := s.seal.vault.get(now, sess, attempt, false)
	if p == nil {
		return nil, "", "", "", errConflict("key expired; start again")
	}
	var priv, pub []byte
	origin := "generated"
	if source == "import" {
		origin = "imported"
		if priv, pub, err = s.openSignerKey(p, attempt, id); err != nil {
			return nil, "", "", "", err
		}
	} else {
		priv, pub = p.priv, p.pub // p is this request's own snapshot
	}
	defer clear(priv)
	// Never seal a key that is not the private half of the public key signed for.
	if derived, err := sc.Public(priv); err != nil || !bytes.Equal(derived, pub) || encodeID(pub) != public {
		return nil, "", "", "", errConflict("key expired; start again")
	}
	t, err := q.VaultService(ctx, service)
	if err != nil {
		return nil, "", "", "", err
	}
	t.SetID, t.SetSlug, t.SetTitle, t.Kind, t.Scheme, t.PublicKey, t.Origin, t.Comment, t.Handout = id, slug, title, "ssh-key", sc.ID, pub, origin, comment, handout
	row, err := s.ensureSetBucket(ctx, q, "signer", t.SetID, t.OrgID)
	if err != nil {
		return nil, "", "", "", err
	}
	plain, err := json.Marshal(signerSecret{Scheme: sc.ID, Private: priv})
	if err != nil {
		return nil, "", "", "", err
	}
	rec, err := s.sealBucket(row).Seal(seal.RoleSignerKey, signerFields(t), plain)
	clear(plain)
	if err != nil {
		return nil, "", "", "", err
	}
	blob := seal.RandomID()
	if err = q.CreateSSHKey(ctx, t, store.CipherRecord{Blob: blob[:], Payload: rec, Wrap: row.ID}, now); err != nil {
		return nil, "", "", "", errConflict("a set with that name or ID exists; reload")
	}
	v := setView(t)
	out = map[string]any{"set_id": t.SetID, "path": t.Path(), "scheme": sc.ID, "public_key": v.PublicKey, "fingerprint": v.Fingerprint, "authorized_key": v.AuthorizedKey, "comment": comment, "handout": handout}
	return out, "set:" + t.SetID, fmt.Sprintf("%s scheme=%s origin=%s handout=%t fingerprint=%s", t.Path(), sc.ID, origin, handout, v.Fingerprint), fmt.Sprintf("Created SSH key %s (%s)", t.Path(), sc.ID), nil
}

// ---- agent side ----

func (s *Server) sshAgentRoutes(m *http.ServeMux) {
	s.signRoute(m, "GET /v2/ssh/key", func(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
		k, _, err := s.sshKey(ctx, q, h.ID, r.URL.Query().Get("path"))
		return k, err
	})
	s.signRoute(m, "POST /v2/ssh/requests", s.sshRequest)
	s.signRoute(m, "POST /v2/ssh/grants/{id}/key", s.sshHandout)
}

// sshKey resolves an SSH key for an admitted host. A path that is not an SSH
// key (a signer, an env set, nothing at all) is the same not_found.
func (s *Server) sshKey(ctx context.Context, q *store.Q, host int64, path string) (signer.SSHKey, signer.Scheme, error) {
	var k signer.SSHKey
	b, err := q.SignBinding(ctx, host, path, s.now())
	if err != nil {
		return k, signer.Scheme{}, err
	}
	sc, known := signer.Lookup(b.Scheme)
	comment, handout, ok, err := q.SSHKeyMeta(ctx, b.Set)
	if err != nil {
		return k, sc, err
	}
	if !ok || !known || !sc.SSH {
		return k, sc, errNotFound()
	}
	k = signer.SSHKey{Binding: b, Comment: comment, Handout: handout}
	if k.AuthorizedKey, err = signer.AuthorizedKey(b.Scheme, b.PublicKey, comment); err != nil {
		return k, sc, err
	}
	k.Fingerprint, err = signer.SSHFingerprint(b.Scheme, b.PublicKey)
	return k, sc, err
}

// sshRequest files a request to use an SSH key: a time-boxed grant of login
// signatures (the key stays here), or one delivery of the private key.
func (s *Server) sshRequest(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	var in struct {
		Binding signer.Binding `json:"binding"`
		Reason  string         `json:"reason"`
		Use     string         `json:"use"`
		TTL     int            `json:"ttl_seconds"`
		Max     int            `json:"max_signatures"`
	}
	if err := signInput(ctx, &in); err != nil {
		return nil, err
	}
	k, _, err := s.sshKey(ctx, q, h.ID, in.Binding.Path)
	if err != nil {
		return nil, err
	}
	b := k.Binding
	if !signBindingEqual(b, in.Binding) {
		return nil, errConflict("SSH key or admission changed")
	}
	if len(in.Reason) > MaxReasonLen || strings.TrimSpace(in.Reason) == "" || hasControl(in.Reason, false) {
		return nil, errBad("invalid reason")
	}
	switch in.Use {
	case signer.UseSSHAgent:
		if in.TTL < signer.MinGrantSeconds || in.Max < 0 || in.Max > signer.MaxGrantSignatures {
			return nil, errBad("an SSH login grant lasts from one minute to 24 hours and covers at most 1000 logins")
		}
		in.TTL = min(in.TTL, signer.MaxGrantSeconds)
		if in.Max == 0 {
			in.Max = signer.DefaultSignatures
		}
	case signer.UseSSHHandout:
		if !k.Handout {
			return nil, errForbidden("the owner does not allow this SSH key to be handed out: use `aqmas ssh-agent " + b.Path + " --why ... -- COMMAND` (the key stays in aqmas), or ask the owner to allow hand-out for it in the Vault")
		}
		if in.TTL != 0 || in.Max > 1 {
			return nil, errBad("a hand-out delivers the key once")
		}
		in.Max = 1
	default:
		return nil, errBad("use is ssh-agent or ssh-handout")
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
	pending := secs(s.cfg.TTL.PendingExpirySeconds)
	if recent, err := q.SignRecent(ctx, h.ID, now.Add(pending-time.Hour)); err != nil {
		return nil, err
	} else if recent >= signer.MaxRequestsPerHour {
		return nil, &apiErr{429, "rate_limited", "too many requests for keys this hour; one login grant (--ttl) covers a run of SSH commands"}
	}
	out := signer.Request{Binding: b, ID: ids.New(), Peer: peer, Reason: in.Reason, Items: []signer.Item{}, TTL: in.TTL, Max: in.Max, Deadline: now.Add(pending).UnixMilli(), Status: "pending", Use: in.Use}
	if err = q.NewSignRequest(ctx, h.ID, out); err != nil {
		return nil, err
	}
	if err = q.Audit(ctx, now, "host:"+h.Name, "ssh_request", "request:"+out.ID, fmt.Sprintf("%s scheme=%s use=%s ttl=%d max=%d", b.Path, b.Scheme, out.Use, out.TTL, out.Max)); err != nil {
		return nil, err
	}
	if c, _ := ctx.Value(signCallKey{}).(*signCall); c != nil {
		c.after = func() {
			s.bcast.notify()
			text := fmt.Sprintf("aqmas: %s wants SSH logins with %s [ref %s]", h.Name, b.Path, ref(out.ID))
			if out.Use == signer.UseSSHHandout {
				text = fmt.Sprintf("aqmas: %s wants the PRIVATE SSH key %s handed out [ref %s]", h.Name, b.Path, ref(out.ID))
			}
			s.notify.Send("aqmas: "+h.Name, text, s.cfg.PublicBaseURL+"/")
		}
	}
	return out, nil
}

// sshHandout delivers an SSH private key, once, under an approved hand-out
// grant: only for a key that may be handed out now, only to the host and
// address that asked. From then on the key is a file on that host; aqmas
// cannot recall it.
func (s *Server) sshHandout(ctx context.Context, q *store.Q, r *http.Request, h *store.Host) (any, error) {
	now := s.now()
	v, err := q.VisibleSignRequest(ctx, h.ID, peerIP(r), r.PathValue("id"), true, now)
	if err != nil {
		return nil, err
	}
	if v.Use != signer.UseSSHHandout {
		return nil, errConflict("this grant does not hand out a key")
	}
	if v.Status != "approved" || v.Until <= now.UnixMilli() || v.Used != 0 {
		return nil, errConflict("grant expired, revoked or already collected")
	}
	t, err := q.VaultSet(ctx, v.Set)
	if err != nil || t.Kind != "ssh-key" || t.Scheme != v.Scheme || string(t.PublicKey) != string(v.PublicKey) {
		return nil, errConflict("SSH key no longer available")
	}
	if !t.Handout {
		return nil, errForbidden("the owner no longer allows this SSH key to be handed out")
	}
	rec, err := q.SignerCipher(ctx, v.Set)
	if err != nil {
		return nil, err
	}
	row, err := s.setRow(ctx, q, "signer", v.Set)
	if err != nil || string(rec.Wrap) != string(row.ID) {
		return nil, errConflict("SSH key no longer available")
	}
	out := signer.SSHHandout{}
	if out.AuthorizedKey, err = signer.AuthorizedKey(t.Scheme, t.PublicKey, t.Comment); err != nil {
		return nil, err
	}
	err = s.withBucket(row, func(b seal.Bucket, k *seal.Key) error {
		p, err := b.Open(k, seal.RoleSignerKey, signerFields(t), rec.Payload)
		if err != nil {
			return errConflict("SSH key record failed authentication")
		}
		var key signerSecret
		err = json.Unmarshal(p, &key)
		clear(p)
		defer clear(key.Private)
		if err != nil || key.Scheme != t.Scheme || len(key.Private) != 32 {
			return errConflict("SSH key record failed authentication")
		}
		file, err := signer.OpenSSHPrivate(t.Scheme, key.Private, t.Comment)
		if err != nil {
			return errConflict("SSH key record failed authentication")
		}
		out.PrivateKey = string(file)
		clear(file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = q.UseHandout(ctx, v.Grant, now); err != nil {
		return nil, errConflict("grant expired, revoked or already collected")
	}
	if err = q.Audit(ctx, now, "host:"+h.Name, "ssh_key_collect", "grant:"+v.Grant, fmt.Sprintf("%s scheme=%s fingerprint=%s enrollment=%s address=%s", v.Path, v.Scheme, setFingerprint(t), v.Enrollment, v.Peer)); err != nil {
		return nil, err
	}
	s.releaseAfter(ctx, "sign:"+v.ID) // the one delivery ends the hold
	v.Used, v.Status = 1, "used"
	out.Request = v
	return out, nil
}
