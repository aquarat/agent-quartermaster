package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"golang.org/x/term"
	"io"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"
)

func (e *Env) envBinding(ctx context.Context, c *APIClient, path string) (envset.Binding, error) {
	var b envset.Binding
	if !envset.ValidPath(path) {
		return b, &UsageError{Msg: "expected an exact org/service/set path"}
	}
	err := c.do(ctx, "GET", "/v2/env/set?path="+url.QueryEscape(path), nil, &b)
	if err == nil && (b.Path != path || b.Org == "" || b.Service == "" || b.Set == "" || b.Enrollment == "" || b.Revision < 0) {
		err = errors.New("unexpected env binding")
	}
	return b, err
}
func bounded(in io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(in, int64(max)+1))
	if err != nil || len(b) > max {
		clear(b)
		return nil, errors.New("input unreadable or too large")
	}
	return b, nil
}
func (e *Env) SetEdit(ctx context.Context, op, path, key, from string, ticketFD int) error {
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	b, err := e.envBinding(ctx, c, path)
	if err != nil {
		return err
	}
	if b.Class != "owner-device" {
		return errors.New("upload requires an admitted owner-device enrollment")
	}
	var ticket []byte
	if ticketFD >= 0 {
		f := os.NewFile(uintptr(ticketFD), "upload-ticket")
		if f == nil {
			return errors.New("invalid ticket descriptor")
		}
		ticket, err = bounded(f, 128)
	} else {
		f, e2 := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if e2 != nil {
			return errors.New("use a terminal or --ticket-fd for the Admin upload ticket")
		}
		defer f.Close()
		fmt.Fprint(e.Stderr, "Admin upload ticket (hidden): ")
		ticket, err = term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(e.Stderr)
	}
	defer clear(ticket)
	if err != nil {
		return errors.New("could not read ticket")
	}
	edit := envset.Edit{Op: op, Salt: make([]byte, 32)}
	rand.Read(edit.Salt)
	switch op {
	case "import":
		f, err := os.Open(from)
		if err != nil {
			return err
		}
		defer f.Close()
		raw, err := bounded(f, envset.MaxBytes)
		if err != nil {
			return err
		}
		defer clear(raw)
		edit.Entries, err = envset.ParseFile(raw)
		if err != nil {
			return err
		}
	case "put":
		var raw []byte
		if e.StdinIsTTY {
			fmt.Fprintf(e.Stderr, "Value for %s (hidden): ", key)
			raw, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(e.Stderr)
		} else {
			raw, err = bounded(e.Stdin, 8192)
		}
		defer clear(raw)
		if err != nil {
			return errors.New("could not read value")
		}
		edit.Entries = []envset.Entry{{Name: key, Value: string(raw)}}
	case "unset":
		edit.Entries = []envset.Entry{{Name: key}}
	default:
		return errors.New("unknown edit operation")
	}
	digest, err := edit.Commit(b)
	if err != nil {
		return err
	}
	changes, err := edit.Changes(b.Names)
	if err != nil {
		return err
	}
	var draft envset.Draft
	err = c.do(ctx, "POST", "/v2/env/upload", envset.Upload{Ticket: strings.TrimSpace(string(ticket)), Edit: edit, Commitment: digest}, &draft)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(b, draft.Binding) || digest != draft.Commitment || draft.Operation != op || draft.Changes != changes {
		return errors.New("draft differs from submitted edit")
	}
	e.logf("staged %s revision %d · Ref %s · %s · compare commitment %s before signing in Admin", path, b.Revision, RefCode(draft.ID), changes, digest)
	return nil
}
func (e *Env) envRelease(ctx context.Context, c *APIClient, b envset.Binding, mode, why string, ttl int) (envset.Collection, error) {
	var empty envset.Collection
	why, err := e.checkWhy(why)
	if err != nil {
		return empty, err
	}
	var v envset.Release
	if err = c.do(ctx, "POST", "/v2/env/requests", map[string]any{"binding": b, "mode": mode, "reason": why, "ttl_seconds": ttl}, &v); err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(v.Binding, b) || v.Mode != mode || v.Status != "pending" || !safeID(v.ID) {
		return empty, errors.New("invalid env request response")
	}
	id := v.ID
	end := time.Now().Add(min(time.Until(time.UnixMilli(v.Deadline))+2*time.Minute, 24*time.Hour))
	e.logf("awaiting %s release of %s revision %d; open the approval page · Ref %s", mode, b.Path, b.Revision, RefCode(id))
	defer func() {
		if ctx.Err() != nil {
			bg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = c.do(bg, "POST", "/v2/env/requests/"+id+"/cancel", nil, nil)
		}
	}()
	notice := false
	for {
		if err = sleepCtx(ctx, time.Second); err != nil {
			return empty, err
		}
		v = envset.Release{}
		if err = c.do(ctx, "GET", "/v2/env/requests/"+id, nil, &v); err != nil {
			return empty, err
		}
		if !reflect.DeepEqual(v.Binding, b) || v.ID != id || v.Mode != mode {
			return empty, errors.New("release binding changed")
		}
		switch v.Status {
		case "pending":
			if time.Now().After(end) {
				return empty, &DecisionError{Status: "expired", What: "env request"}
			}
			continue
		case "approved":
			if !safeID(v.Grant) || v.Consumed || v.Until <= e.now().UnixMilli() {
				return empty, errors.New("invalid or already collected grant")
			}
		default:
			return empty, &DecisionError{Status: v.Status, What: "env release"}
		}
		var out envset.Collection
		err = c.do(ctx, "POST", "/v2/grants/"+v.Grant+"/collect", nil, &out)
		var ae *APIError
		if errors.As(err, &ae) && ae.HTTPStatus == 423 && ae.Code == "locked" {
			if !notice {
				e.logf("waiting for owner unlock")
				notice = true
			}
			continue
		}
		if err != nil {
			return empty, err
		}
		v.Consumed = true
		if !reflect.DeepEqual(out.Release, v) || envset.Validate(out.Entries) != nil || !slices.Equal(envset.Names(out.Entries), b.Names) {
			return empty, errors.New("collected env release does not match the reviewed revision")
		}
		return out, nil
	}
}

type checkoutRecord struct {
	Path, Mode, Grant, Link, CWD, Base string
	Names                              []string
	Until                              int64
	Dev, Ino                           uint64
}

func (e *Env) envSlot(cfg *Config, path, mode string) (string, error) {
	cert, err := os.ReadFile(expandHome(cfg.ClientCert))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s", cfg.Server, cfg.ServerCASHA256, path, mode, cert)
	return "env-" + hex.EncodeToString(h.Sum(nil)), nil
}
func (e *Env) EnvUse(ctx context.Context, path, mode, why, file string, ttl int, command []string) error {
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	b, err := e.envBinding(ctx, c, path)
	if err != nil {
		return err
	}
	var exe string
	switch mode {
	case "process":
		if len(command) == 0 {
			return &UsageError{Msg: "run needs -- COMMAND"}
		}
		exe, err = exec.LookPath(command[0])
		if err != nil {
			return err
		}
	case "shell":
		if e.StdoutIsTTY {
			return errors.New("refusing shell exports to terminal; use eval with command substitution")
		}
	case "file":
		if err = filePreflight(file); err != nil {
			return err
		}
	default:
		return errors.New("unknown env mode")
	}
	for _, n := range b.Names {
		if !envset.SafeName(n) {
			return errors.New("unsafe env name")
		}
		if _, ok := os.LookupEnv(n); ok && mode != "file" {
			return fmt.Errorf("refusing to replace inherited %s", n)
		}
	}
	out, err := e.envRelease(ctx, c, b, mode, why, ttl)
	if err != nil {
		return err
	}
	if mode == "process" {
		env := []string{}
		for _, n := range []string{"HOME", "PATH", "USER", "LANG", "TMPDIR", "TERM"} {
			if v, ok := os.LookupEnv(n); ok {
				env = append(env, n+"="+v)
			}
		}
		for _, x := range out.Entries {
			env = append(env, x.Name+"="+x.Value)
		}
		return syscall.Exec(exe, command, env)
	}
	slot, err := e.envSlot(cfg, path, mode)
	if err != nil {
		return err
	}
	r := checkoutRecord{Path: path, Mode: mode, Grant: out.Release.Grant, Names: b.Names, Until: out.Release.Until}
	if mode == "file" {
		return e.fileCheckout(slot, file, r, out.Entries)
	}
	if err = e.saveShell(slot, r); err != nil {
		return err
	}
	var buf strings.Builder
	for _, x := range out.Entries {
		fmt.Fprintf(&buf, "export %s='%s'\n", x.Name, strings.ReplaceAll(x.Value, "'", "'\\''"))
	}
	e.logf("shell-mode release: children inherit these values until checkin-shell; other processes of this user may read them")
	_, err = io.WriteString(e.Stdout, buf.String())
	return err
}
func (e *Env) saveShell(slot string, r checkoutRecord) error {
	dir, err := trustedDir(e.Paths.ConfigDir, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	return writeNewAt(dir, slot, mustMetadata(r))
}
func mustMetadata(r checkoutRecord) []byte { b, _ := json.Marshal(r); return b }
func (e *Env) EnvCheckin(ctx context.Context, path, mode string) error {
	if !envset.ValidPath(path) {
		return errors.New("invalid set path")
	}
	if mode == "shell" && e.StdoutIsTTY {
		return errors.New("refusing shell output to terminal; use eval with command substitution")
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	slot, err := e.envSlot(cfg, path, mode)
	if err != nil {
		return err
	}
	var r checkoutRecord
	if mode == "file" {
		r, err = e.fileCheckin(slot, path)
	} else {
		var d *os.File
		d, err = trustedDir(e.Paths.ConfigDir, true)
		if err != nil {
			return err
		}
		defer d.Close()
		r, err = readRecord(d, slot)
		if err == nil {
			if r.Path != path || r.Mode != "shell" || !safeID(r.Grant) {
				return errors.New("wrong shell record")
			}
			for _, n := range r.Names {
				if !envset.SafeName(n) {
					return errors.New("unsafe shell record")
				}
			}
			for _, n := range r.Names {
				if _, err = fmt.Fprintln(e.Stdout, "unset "+n); err != nil {
					return err
				}
			}
			err = unlinkAt(d, slot)
		}
	}
	if err != nil {
		return err
	}
	return c.do(ctx, "POST", "/v2/env/grants/"+r.Grant+"/checkin", nil, nil)
}
