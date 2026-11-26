package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/envset"
	"github.com/aquarat/agent-quartermaster/internal/signer"
)

// SignOptions are the flags of `aqmas sign`.
type SignOptions struct {
	Path   string
	Why    string
	TTL    int // seconds; 0 asks for a single-use grant
	Count  int // with TTL: signatures the grant may make (0: server default)
	Out    string
	Format string // raw, hex or base64; "" picks raw for files and hex for stdout
	Digest string // sha256:HEX instead of an artifact
	Force  bool
	Files  []string // "-" is stdin
}

func (e *Env) signBinding(ctx context.Context, c *APIClient, path string) (signer.Binding, signer.Scheme, error) {
	var b signer.Binding
	if !envset.ValidPath(path) {
		return b, signer.Scheme{}, &UsageError{Msg: "expected an exact org/service/key path"}
	}
	err := c.do(ctx, "GET", "/v2/sign/key?path="+url.QueryEscape(path), nil, &b)
	if err != nil {
		return b, signer.Scheme{}, err
	}
	sc, ok := signer.Lookup(b.Scheme)
	if b.Path != path || b.Org == "" || b.Service == "" || b.Set == "" || b.Enrollment == "" || len(b.PublicKey) == 0 {
		return b, sc, errors.New("unexpected signer binding")
	}
	if ok && sc.SSH {
		return b, sc, fmt.Errorf("%s is an SSH key, not a signing key: use `aqmas ssh-agent %s --why \"...\" -- COMMAND` (its public line: `aqmas ssh-key %s --public`)", path, path, path)
	}
	if !ok {
		return b, sc, fmt.Errorf("this aqmas does not know signing scheme %q; upgrade", sanitize(b.Scheme))
	}
	return b, sc, nil
}

// SignerInfo runs `aqmas signer PATH`: the scheme and public key, for verifiers.
func (e *Env) SignerInfo(ctx context.Context, path string, pemOnly bool) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	b, sc, err := e.signBinding(ctx, c, path)
	if err != nil {
		return err
	}
	p, err := sc.PublicPEM(b.PublicKey)
	if err != nil {
		return err
	}
	if pemOnly {
		_, err = io.WriteString(e.Stdout, p)
		return err
	}
	_, err = fmt.Fprintf(e.Stdout, "signer       %s\nscheme       %s (%s)\nsigns        %s\nsignature    %s\npublic key   %s\nfingerprint  sha256:%s\nverify       %s\n%s", b.Path, sc.ID, sc.Title, sc.Signed, sc.Output, hex.EncodeToString(b.PublicKey), signer.Fingerprint(b.PublicKey), sc.Check, p)
	return err
}

// signItem hashes one artifact locally. Only a scheme that signs the message
// itself sends the bytes, and then only up to signer.MaxMessage.
func signItem(sc signer.Scheme, name string, in io.Reader) (signer.Item, error) {
	h256, h512 := sha256.New(), sha512.New()
	var keep bytes.Buffer
	w := io.MultiWriter(h256, h512)
	var r io.Reader = in
	if sc.Input == "message" {
		r = io.TeeReader(io.LimitReader(in, signer.MaxMessage+1), &keep)
	}
	n, err := io.Copy(w, r)
	if err != nil {
		return signer.Item{}, fmt.Errorf("%s: %w", name, err)
	}
	it := signer.Item{Name: name, Size: n, SHA256: hex.EncodeToString(h256.Sum(nil))}
	switch sc.Input {
	case "message":
		if n > signer.MaxMessage {
			return it, fmt.Errorf("%s: scheme %s signs the artifact itself, at most %d bytes; sign a manifest or digest of it, or use a key with a digest scheme", name, sc.ID, signer.MaxMessage)
		}
		it.Message = append([]byte{}, keep.Bytes()...)
	case "sha512":
		it.SHA512 = hex.EncodeToString(h512.Sum(nil))
	}
	return it, sc.Valid(it)
}

type signTarget struct {
	item signer.Item
	out  string // "" is stdout
}

func (e *Env) signTargets(sc signer.Scheme, o SignOptions) ([]signTarget, error) {
	var out []signTarget
	if o.Digest != "" {
		alg, hx, _ := strings.Cut(o.Digest, ":")
		if len(o.Files) > 0 || alg != "sha256" || sc.Input != "sha256" {
			return nil, &UsageError{Msg: "--digest takes sha256:HEX, no files, and a key whose scheme signs a SHA-256 digest (this key: " + sc.ID + ")"}
		}
		it := signer.Item{Name: "digest", Size: -1, SHA256: strings.ToLower(hx)}
		if err := sc.Valid(it); err != nil {
			return nil, &UsageError{Msg: "--digest needs 64 hex characters"}
		}
		return []signTarget{{it, o.Out}}, nil
	}
	if len(o.Files) == 0 {
		return nil, &UsageError{Msg: "name the files to sign, - for stdin, or --digest sha256:HEX"}
	}
	if len(o.Files) > signer.MaxItems {
		return nil, &UsageError{Msg: fmt.Sprintf("at most %d files a call", signer.MaxItems)}
	}
	if o.Out != "" && len(o.Files) != 1 {
		return nil, &UsageError{Msg: "--out needs exactly one input; several files get FILE.sig each"}
	}
	seen := map[string]bool{}
	total := 0
	for _, f := range o.Files {
		t := signTarget{out: o.Out}
		var err error
		if f == "-" {
			t.item, err = signItem(sc, "stdin", e.Stdin)
		} else {
			name := filepath.Base(f)
			if !signer.ValidName(name) {
				return nil, fmt.Errorf("unsupported file name for the approval card: %q", name)
			}
			var fh *os.File
			if fh, err = os.Open(f); err != nil {
				return nil, err
			}
			if st, e2 := fh.Stat(); e2 != nil || !st.Mode().IsRegular() {
				fh.Close()
				return nil, fmt.Errorf("%s is not a regular file", f)
			}
			t.item, err = signItem(sc, name, fh)
			fh.Close()
			if t.out == "" {
				t.out = f + ".sig"
			}
		}
		if err != nil {
			return nil, err
		}
		if seen[t.item.Name+t.item.SHA256] {
			return nil, &UsageError{Msg: "the same artifact is named twice"}
		}
		seen[t.item.Name+t.item.SHA256] = true
		if total += len(t.item.Message); total > signer.MaxMessageBytes {
			return nil, fmt.Errorf("scheme %s signs the artifacts themselves: at most %d bytes of them a call", sc.ID, signer.MaxMessageBytes)
		}
		out = append(out, t)
	}
	return out, nil
}

func (e *Env) signSlot(cfg *Config, path string) (string, error) {
	cert, err := os.ReadFile(expandHome(cfg.ClientCert))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00sign\x00%s", cfg.Server, cfg.ServerCASHA256, path, cert)
	return "sign-" + hex.EncodeToString(h.Sum(nil)), nil
}

// Sign runs `aqmas sign`: hash locally, ask the owner, have aqmasd sign, check
// every signature against the signer's public key, then write it.
func (e *Env) Sign(ctx context.Context, o SignOptions) error {
	switch o.Format {
	case "", "raw", "hex", "base64":
	default:
		return &UsageError{Msg: "--format is raw, hex or base64"}
	}
	if o.TTL == 0 && o.Count != 0 {
		return &UsageError{Msg: "--count needs --ttl (a time-boxed signing grant)"}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	b, sc, err := e.signBinding(ctx, c, o.Path)
	if err != nil {
		return err
	}
	targets, err := e.signTargets(sc, o)
	if err != nil {
		return err
	}
	items := make([]signer.Item, len(targets))
	for i, t := range targets {
		items[i] = t.item
		if t.out != "" && !o.Force {
			if _, err := os.Lstat(t.out); err == nil {
				return fmt.Errorf("%s exists; remove it or pass --force", t.out)
			}
		}
	}
	slot, err := e.signSlot(cfg, o.Path)
	if err != nil {
		return err
	}
	dir, err := trustedDir(e.Paths.ConfigDir, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	var out signer.Signed
	done := false
	// A live time-boxed grant from an earlier call needs no new approval.
	if r, err := readRecord(dir, slot); err == nil && r.Mode == "sign" && r.Path == o.Path && r.Until > e.now().Add(5*time.Second).UnixMilli() {
		err = e.signCall(ctx, c, r.Grant, items, &out)
		var ae *APIError
		switch {
		case err == nil:
			done = true
			e.logf("signed under the open signing grant for %s (%d of %d used)", o.Path, out.Request.Used, out.Request.Max)
		case errors.As(err, &ae) && (ae.HTTPStatus == 404 || ae.HTTPStatus == 409):
			_ = unlinkAt(dir, slot)
		default:
			return err
		}
	} else if err == nil {
		_ = unlinkAt(dir, slot)
	}
	if !done {
		why, err := e.checkWhy(o.Why)
		if err != nil {
			return err
		}
		var v signer.Request
		if err = c.do(ctx, "POST", "/v2/sign/requests", map[string]any{"binding": b, "reason": why, "ttl_seconds": o.TTL, "max_signatures": o.Count, "items": items}, &v); err != nil {
			return err
		}
		if !sameJSON(v.Binding, b) || !sameJSON(v.Items, items) || v.Status != "pending" || !safeID(v.ID) {
			return errors.New("invalid signing request response")
		}
		id := v.ID
		kind := "once"
		if v.TTL > 0 {
			kind = fmt.Sprintf("plus a grant of up to %d signatures for %s", v.Max, time.Duration(v.TTL)*time.Second)
		}
		e.logf("awaiting approval to sign with %s (%s), %s; open the approval page · Ref %s", o.Path, sc.ID, kind, RefCode(id))
		for _, it := range items {
			e.logf("  sha256 %s  %s", it.SHA256, sanitize(it.Name))
			if it.SHA512 != "" {
				e.logf("  sha512 %s  (the digest this scheme signs)", it.SHA512)
			}
		}
		defer func() {
			if ctx.Err() != nil {
				bg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = c.do(bg, "POST", "/v2/sign/requests/"+id+"/cancel", nil, nil)
			}
		}()
		end := time.Now().Add(min(time.Until(time.UnixMilli(v.Deadline))+2*time.Minute, 24*time.Hour))
		notice := false
	wait:
		for {
			if err = sleepCtx(ctx, time.Second); err != nil {
				return err
			}
			v = signer.Request{}
			if err = c.do(ctx, "GET", "/v2/sign/requests/"+id, nil, &v); err != nil {
				return err
			}
			if !sameJSON(v.Binding, b) || v.ID != id || !sameJSON(v.Items, items) {
				return errors.New("signing request changed")
			}
			switch v.Status {
			case "pending":
				if time.Now().After(end) {
					return &DecisionError{Status: "expired", What: "signing request"}
				}
				continue
			case "approved":
				if !safeID(v.Grant) || v.Until <= e.now().UnixMilli() {
					return errors.New("invalid signing grant")
				}
			default:
				return &DecisionError{Status: v.Status, What: "signing request"}
			}
			err = e.signCall(ctx, c, v.Grant, items, &out)
			var ae *APIError
			if errors.As(err, &ae) && ae.HTTPStatus == 423 && ae.Code == "locked" {
				if !notice {
					e.logf("%s", lockedNotice(ae))
					notice = true
				}
				continue
			}
			if err != nil {
				return err
			}
			break wait
		}
		if out.Request.TTL > 0 && out.Request.Used < out.Request.Max {
			_ = unlinkAt(dir, slot)
			if err := writeNewAt(dir, slot, mustMetadata(checkoutRecord{Path: o.Path, Mode: "sign", Grant: out.Request.Grant, Until: out.Request.Until})); err != nil {
				e.logf("could not remember the signing grant: %s", sanitize(err.Error()))
			} else {
				e.logf("signing grant open until %s (%d of %d used); further `aqmas sign %s` calls need no approval; end it with `aqmas sign %s --end`", time.UnixMilli(out.Request.Until).Local().Format(time.RFC3339), out.Request.Used, out.Request.Max, o.Path, o.Path)
			}
		}
	}
	if len(out.Signatures) != len(items) {
		return errors.New("broker returned the wrong number of signatures")
	}
	for i, t := range targets {
		s := out.Signatures[i]
		if s.Name != t.item.Name || s.SHA256 != t.item.SHA256 || !sc.Verify(b.PublicKey, t.item, s.Signature) {
			return fmt.Errorf("signature for %s does not verify against the signer's public key; nothing written", sanitize(t.item.Name))
		}
	}
	for i, t := range targets {
		if err := e.writeSignature(t.out, o.Format, o.Force, out.Signatures[i].Signature); err != nil {
			return err
		}
		if t.out != "" {
			e.logf("wrote %s (%s, sha256 %s)", t.out, sc.ID, t.item.SHA256)
		}
	}
	return nil
}
func (e *Env) signCall(ctx context.Context, c *APIClient, grant string, items []signer.Item, out *signer.Signed) error {
	*out = signer.Signed{}
	return c.do(ctx, "POST", "/v2/sign/grants/"+grant+"/sign", map[string]any{"items": items}, out)
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func (e *Env) writeSignature(path, format string, force bool, sig []byte) error {
	if format == "" {
		format = "raw"
		if path == "" {
			format = "hex"
		}
	}
	var b []byte
	switch format {
	case "hex":
		b = []byte(hex.EncodeToString(sig) + "\n")
	case "base64":
		b = []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
	default:
		if path == "" && e.StdoutIsTTY {
			return errors.New("refusing raw signature bytes on a terminal; use --format hex or --out FILE")
		}
		b = sig
	}
	if path == "" {
		_, err := e.Stdout.Write(b)
		return err
	}
	flag := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if ce := f.Close(); err == nil {
		err = ce
	}
	return err
}

// SignEnd runs `aqmas sign PATH --end`: give back an open signing grant.
func (e *Env) SignEnd(ctx context.Context, path string) error {
	if !envset.ValidPath(path) {
		return &UsageError{Msg: "expected an exact org/service/key path"}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	slot, err := e.signSlot(cfg, path)
	if err != nil {
		return err
	}
	dir, err := trustedDir(e.Paths.ConfigDir, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	r, err := readRecord(dir, slot)
	if err != nil || r.Mode != "sign" || r.Path != path {
		return errors.New("no open signing grant recorded for " + path)
	}
	_ = unlinkAt(dir, slot)
	err = c.do(ctx, "POST", "/v2/sign/grants/"+r.Grant+"/end", nil, nil)
	var ae *APIError
	if errors.As(err, &ae) && (ae.HTTPStatus == 404 || ae.HTTPStatus == 409) {
		err = nil // already over
	}
	return err
}
