package client

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
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

// SetOptions is one `aqmas set import|put|unset`.
type SetOptions struct {
	Op, Path, Key, From string
	Why                 string
	// Create asks for a set (and service) that does not exist yet; Title is the
	// new set's title (default: its name).
	Create bool
	Title  string
}

// readEdit reads what the edit stores, before anything is sent: an import's
// file (checked as `aqmas set check` does; every problem is printed, by line
// number only), a put's value from the hidden prompt or stdin, an unset's name.
func (e *Env) readEdit(op, key, from string) (envset.Edit, error) {
	edit := envset.Edit{Op: op, Salt: make([]byte, 32)}
	if _, err := rand.Read(edit.Salt); err != nil {
		return edit, err
	}
	switch op {
	case "import":
		raw, err := readImport(from)
		if err != nil {
			return edit, err
		}
		defer clear(raw)
		if _, problems := envset.CheckFile(raw); len(problems) > 0 {
			for _, p := range problems {
				e.logf("%s: %s", from, p)
			}
			return edit, fmt.Errorf("%s would not import (%d problem(s) above); nothing was sent", from, len(problems))
		}
		if edit.Entries, err = envset.ParseFile(raw); err != nil {
			return edit, err
		}
	case "put", "unset":
		if !envset.SafeName(key) {
			return edit, &UsageError{Msg: "aqmas does not deliver under the name " + sanitize(key) + ": use " + envset.NameRule}
		}
		if op == "unset" {
			edit.Entries = []envset.Entry{{Name: key}}
			break
		}
		var raw []byte
		var err error
		if e.StdinIsTTY {
			fmt.Fprintf(e.Stderr, "Value for %s (hidden): ", key)
			raw, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(e.Stderr)
		} else {
			raw, err = bounded(e.Stdin, 8192)
		}
		defer clear(raw)
		if err != nil {
			return edit, errors.New("could not read value")
		}
		edit.Entries = []envset.Entry{{Name: key, Value: string(raw)}}
		if err = envset.Validate(edit.Entries); err != nil {
			return edit, errors.New("the value is not valid UTF-8 text without NUL bytes, or is longer than 8192 bytes")
		}
	default:
		return edit, errors.New("unknown edit operation")
	}
	return edit, nil
}

func readImport(from string) ([]byte, error) {
	f, err := openImport(from)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return bounded(f, envset.MaxBytes+4096)
}

// SetEdit is the owner-device ticket flow: the edit is uploaded against a
// one-use ticket from the Vault and committed there. ticketFD < 0 reads the
// ticket at a hidden prompt.
func (e *Env) SetEdit(ctx context.Context, op, path, key, from string, ticketFD int) error {
	if !envset.ValidPath(path) {
		return &UsageError{Msg: "expected an exact org/service/set path"}
	}
	edit, err := e.readEdit(op, key, from)
	defer wipe(edit.Entries)
	if err != nil {
		return err
	}
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	b, err := e.envBinding(ctx, c, path)
	if err != nil {
		return err
	}
	if b.Class != "owner-device" {
		return errors.New("an upload ticket needs an admitted owner-device enrollment; without --ticket the edit is proposed to the owner instead")
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

func wipe(entries []envset.Entry) {
	for i := range entries {
		entries[i].Value = ""
	}
}

// changeWords renders a proposal's changes ("A:add,B:replace") for a person:
// names only.
func changeWords(changes string) string {
	by := map[string][]string{}
	for _, c := range strings.Split(changes, ",") {
		if name, kind, ok := strings.Cut(c, ":"); ok {
			by[kind] = append(by[kind], name)
		}
	}
	var out []string
	for _, kind := range []string{"add", "replace", "remove"} {
		if len(by[kind]) > 0 {
			out = append(out, kind+" "+strings.Join(by[kind], ", "))
		}
	}
	return strings.Join(out, "; ")
}

func newHexID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

var setTitleRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$`)

// SetPropose asks the owner to store values (docs/API.md "Env proposals"):
// the edit is sealed by the broker on arrival and waits for the owner's tap.
// It prints the Ref, the commitment and the key changes, then blocks until
// the owner commits or discards, the proposal expires or is superseded, or
// ctx ends (the proposal is then withdrawn). It returns the final proposal.
func (e *Env) SetPropose(ctx context.Context, o SetOptions) (envset.Proposal, error) {
	var none envset.Proposal
	why := strings.TrimSpace(o.Why)
	if why == "" {
		return none, &UsageError{Msg: "--why \"...\" is required: say what the values are for (the owner sees it on the card)"}
	}
	why, err := e.checkWhy(why)
	if err != nil {
		return none, err
	}
	if !envset.ValidPath(o.Path) {
		return none, &UsageError{Msg: "expected an exact org/service/set path"}
	}
	if o.Title != "" && (!o.Create || !setTitleRE.MatchString(o.Title) || strings.TrimSpace(o.Title) != o.Title) {
		return none, &UsageError{Msg: "--title goes with --create and is 1 to 64 letters, digits, spaces, dots, underscores and hyphens"}
	}
	if o.Create && o.Op == "unset" {
		return none, &UsageError{Msg: "--create goes with set import or set put"}
	}
	// The file or value is read and checked before anything is sent.
	edit, err := e.readEdit(o.Op, o.Key, o.From)
	defer wipe(edit.Entries)
	if err != nil {
		return none, err
	}
	if o.Op == "put" && edit.Entries[0].Value == "" {
		return none, errors.New("the value is empty: was stdin empty? (nothing was sent; to remove a key use aqmas set unset)")
	}
	_, c, err := e.authedClient()
	if err != nil {
		return none, err
	}
	var b envset.Binding
	q := "/v2/env/set?path=" + url.QueryEscape(o.Path)
	if o.Create {
		q += "&create=1"
	}
	if err = c.do(ctx, "GET", q, nil, &b); err != nil {
		var ae *APIError
		if !o.Create && errors.As(err, &ae) && ae.Code == "not_found" {
			return none, fmt.Errorf("%w (no set %s for this host; to propose creating it add --create)", err, o.Path)
		}
		return none, err
	}
	if b.Path != o.Path || b.Org == "" || b.Enrollment == "" || b.Revision < 0 || b.Names == nil || (b.Set == "" || b.Service == "") && !o.Create {
		return none, errors.New("unexpected env binding")
	}
	req := envset.ProposalRequest{Path: o.Path, Reason: why, Edit: edit}
	if b.Set == "" {
		// A new set: this host chooses the IDs, so that the commitment the
		// owner compares covers them.
		req.Create = &envset.ProposalCreate{Title: o.Title}
		if req.Create.SetID, err = newHexID(); err != nil {
			return none, err
		}
		if b.Service == "" {
			if req.Create.ServiceID, err = newHexID(); err != nil {
				return none, err
			}
			b.Service = req.Create.ServiceID
		}
		b.Set = req.Create.SetID
	} else if o.Create {
		e.logf("%s exists: proposing the edit to it (nothing is created)", o.Path)
	}
	if req.Commitment, err = edit.Commit(b); err != nil {
		return none, err
	}
	changes, err := edit.Changes(b.Names)
	if err != nil {
		return none, fmt.Errorf("%s has no key %s to unset", o.Path, o.Key)
	}
	if changes == "" {
		return none, errors.New("the edit changes nothing")
	}
	var p envset.Proposal
	if err = c.do(ctx, "POST", "/v2/env/proposals", req, &p); err != nil {
		return none, err
	}
	// From here the broker holds a proposal the owner can commit: every way out
	// either withdraws it or says plainly that it may still be committed.
	id := p.ID
	if !safeID(id) {
		return none, errors.New("the broker answered without a usable proposal ID; if a card appears on the approval page for " + o.Path + ", discard it")
	}
	refCode := RefCode(id)
	e.logf("proposal Ref %s", refCode)
	until := time.UnixMilli(p.Expires)
	if p.Expires <= 0 || time.Until(until) > 15*time.Minute {
		until = time.Now().Add(10 * time.Minute)
	}
	maybe := fmt.Sprintf("proposal %s could not be withdrawn and may still be committed by the owner until %s: check the approval page (discard the card with Ref %s), or afterwards the set's keys with `aqmas set check --from FILE %s`", refCode, until.Local().Format("15:04"), refCode, o.Path)
	// giveUp ends a wait that failed: the proposal is withdrawn, or the error
	// says what became of it, or that it may still be committed.
	giveUp := func(cause error) error {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := c.do(bg, "POST", "/v2/env/proposals/"+id+"/cancel", struct{}{}, nil)
		if err == nil {
			if errors.Is(cause, ErrCancelled) {
				return cause
			}
			return fmt.Errorf("%w (proposal %s was withdrawn; nothing was stored)", cause, refCode)
		}
		outcome := maybe
		var ae *APIError
		if errors.As(err, &ae) && ae.HTTPStatus == 409 {
			// No longer pending: say what it became, if the broker will tell.
			var got envset.Proposal
			if c.do(bg, "GET", "/v2/env/proposals/"+id, nil, &got) == nil && got.ID == id && got.Status == "committed" {
				outcome = fmt.Sprintf("proposal %s was COMMITTED by the owner meanwhile: %s is at revision %d", refCode, o.Path, got.Result)
			} else if got.ID == id && got.Status != "" && got.Status != "pending" {
				outcome = fmt.Sprintf("proposal %s is %s; nothing was stored", refCode, got.Status)
			}
		}
		var ue *UnreachableError
		if errors.As(cause, &ue) || errors.Is(cause, ErrCancelled) {
			e.logf("%s", outcome)
			return cause
		}
		return fmt.Errorf("%w; %s", cause, outcome)
	}
	b.Title = p.Title // a new set's title is composed by the broker
	if !reflect.DeepEqual(b, p.Binding) || p.Commitment != req.Commitment || p.Operation != o.Op || p.Changes != changes || p.Status != "pending" || p.Ref != refCode ||
		p.NewSet != (req.Create != nil) || p.NewService != (req.Create != nil && req.Create.ServiceID != "") {
		return none, giveUp(errors.New("the broker's proposal differs from the submitted edit"))
	}
	what := o.Op + " into " + o.Path
	switch {
	case p.NewService:
		what = "create service and set " + o.Path + " (" + o.Op + ")"
	case p.NewSet:
		what = "create set " + o.Path + " (" + o.Op + ")"
	case o.Op == "import":
		what = "import into " + o.Path + ", replacing the whole set"
	}
	e.logf("proposed: %s, revision %d · Ref %s", what, p.Revision, p.Ref)
	e.logf("changes: %s", changeWords(p.Changes))
	e.logf("commitment %s", p.Commitment)
	e.logf("waiting for the owner to commit or discard on the approval page (compare Ref and commitment with the card; Ctrl-C withdraws)")
	first := time.Second
	if e.PollMin > 0 {
		first = e.PollMin
	}
	backoff, told := first, false
	for p.Status == "pending" {
		var got envset.Proposal
		err = c.do(ctx, "GET", "/v2/env/proposals/"+id+"?wait=25", nil, &got)
		if ctx.Err() != nil {
			return p, giveUp(ErrCancelled)
		}
		var ue *UnreachableError
		var ae *APIError
		if errors.As(err, &ue) || errors.As(err, &ae) && ae.HTTPStatus >= 500 {
			// A broker restart or a network blip: the proposal is still there.
			// Keep asking until it would have expired.
			if time.Now().After(until) {
				return p, giveUp(&UnreachableError{Err: fmt.Errorf("no answer about proposal %s since it was made: %w", refCode, err)})
			}
			if !told {
				e.logf("the broker is not answering (%s); still waiting for the decision on proposal %s", Sanitize(err.Error()), refCode)
				told = true
			}
			if sleepCtx(ctx, backoff) != nil {
				return p, giveUp(ErrCancelled)
			}
			backoff = min(backoff*2, 15*time.Second)
			continue
		}
		if err != nil {
			return p, giveUp(err)
		}
		if got.ID != id || got.Commitment != p.Commitment || got.Set != p.Set {
			return p, giveUp(errors.New("the broker answered with another proposal"))
		}
		backoff, told = first, false
		if p = got; p.Status == "pending" {
			if time.Now().After(until.Add(2 * time.Minute)) {
				return p, giveUp(&DecisionError{Status: "expired", What: "proposal " + p.Ref})
			}
			// A broker that answers at once must not be polled in a tight loop.
			if sleepCtx(ctx, max(e.PollMin, 0)) != nil {
				return p, giveUp(ErrCancelled)
			}
		}
	}
	switch p.Status {
	case "committed":
		e.logf("committed: %s is at revision %d", o.Path, p.Result)
		return p, nil
	case "discarded":
		return p, &DecisionError{Status: "denied", What: "proposal " + p.Ref, Note: "the owner discarded it; nothing was stored"}
	case "superseded":
		return p, &DecisionError{Status: "expired", What: "proposal " + p.Ref, Note: "superseded: the set, this host's admission or the organisation's policy changed before the owner decided; nothing was stored, propose again"}
	case "expired":
		return p, &DecisionError{Status: "expired", What: "proposal " + p.Ref, Note: "nobody decided within ten minutes; nothing was stored"}
	case "cancelled":
		return p, &DecisionError{Status: "cancelled", What: "proposal " + p.Ref}
	}
	return p, errors.New("unexpected proposal status")
}

// SetCheck is `aqmas set check --from FILE [PATH]`: the import rules applied
// here, nothing sent. Key names go to stdout, one per line; with a path, also
// what an import would add, replace and remove ("add NAME" ...). Problems go
// to stderr with their line number. Never a value.
func (e *Env) SetCheck(ctx context.Context, from, path string) error {
	if path != "" && !envset.ValidPath(path) {
		return &UsageError{Msg: "expected an exact org/service/set path"}
	}
	raw, err := readImport(from)
	if err != nil {
		return err
	}
	defer clear(raw)
	names, problems := envset.CheckFile(raw)
	for _, n := range names {
		fmt.Fprintln(e.Stdout, n)
	}
	for _, p := range problems {
		e.logf("%s: %s", from, p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s would not import: %d problem(s)", from, len(problems))
	}
	if path == "" {
		e.logf("%s would import: %d key(s)", from, len(names))
		return nil
	}
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	old := []string{}
	b, err := e.envBinding(ctx, c, path)
	var ae *APIError
	switch {
	case err == nil:
		old = b.Names
	case errors.As(err, &ae) && ae.Code == "not_found":
		e.logf("no set %s for this host: an import with --create would propose creating it", path)
	default:
		return err
	}
	entries := make([]envset.Entry, len(names))
	for i, n := range names {
		entries[i] = envset.Entry{Name: n}
	}
	changes, err := envset.Edit{Op: "import", Entries: entries}.Changes(old)
	if err != nil {
		return err
	}
	for _, c := range strings.Split(changes, ",") {
		if name, kind, ok := strings.Cut(c, ":"); ok {
			fmt.Fprintln(e.Stdout, kind, name)
		}
	}
	e.logf("%s would import into %s: %s", from, path, cmp.Or(changeWords(changes), "no keys"))
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
				e.logf("%s", lockedNotice(ae))
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

// EnvOptions is one delivery of an env set or a secret.
type EnvOptions struct {
	Path string
	// Mode: process (run), file (checkout), shell (checkout-shell) or get
	// (print one secret's value).
	Mode    string
	Why     string
	File    string // file mode: the link to create
	TTL     int    // seconds; 0: the organisation's default; -1: indefinite
	Command []string
	// EnvName renames the one variable of a secret or a one-key set (process mode).
	EnvName string
	// Run, when set, starts the command and returns instead of replacing this
	// process (the MCP server). env is the child's complete environment.
	Run func(exe string, argv, env []string) error
}

// EnvUse delivers with the classic argument list (run, checkout, checkout-shell).
func (e *Env) EnvUse(ctx context.Context, path, mode, why, file string, ttl int, command []string) error {
	return e.EnvDeliver(ctx, EnvOptions{Path: path, Mode: mode, Why: why, File: file, TTL: ttl, Command: command})
}

// EnvDeliver asks for one release of a set and hands it over in o.Mode.
func (e *Env) EnvDeliver(ctx context.Context, o EnvOptions) error {
	path, mode, why, file, ttl, command := o.Path, o.Mode, o.Why, o.File, o.TTL, o.Command
	if o.EnvName != "" && mode != "process" {
		return &UsageError{Msg: "--env renames the variable for aqmas run only"}
	}
	if o.EnvName != "" && !envset.SafeName(o.EnvName) {
		return &UsageError{Msg: "--env: aqmas does not deliver under that name (use capital letters, digits and underscores, starting with APP_ or ending in _TOKEN, _KEY, _PASSWORD, _SECRET, _URL, _DSN, _USER, _USERNAME or _ID; never a name a shell, loader or tool reads as configuration)"}
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return err
	}
	b, err := e.envBinding(ctx, c, path)
	if err != nil {
		return err
	}
	if (mode == "get" || o.EnvName != "") && len(b.Names) != 1 {
		if mode == "get" {
			return &UsageError{Msg: fmt.Sprintf("aqmas get prints one secret; %s holds %d values: use aqmas run %s --why \"...\" -- COMMAND", path, len(b.Names), path)}
		}
		return &UsageError{Msg: fmt.Sprintf("--env renames the variable of a secret; %s holds %d values", path, len(b.Names))}
	}
	var exe string
	switch mode {
	case "get":
		if len(command) > 0 {
			return &UsageError{Msg: "get takes no command; use aqmas run PATH --why \"...\" -- COMMAND"}
		}
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
		if o.EnvName != "" {
			n = o.EnvName
		}
		if _, ok := os.LookupEnv(n); ok && mode != "file" && mode != "get" {
			return fmt.Errorf("refusing to replace inherited %s (unset it, or for a secret choose another name with --env)", n)
		}
	}
	out, err := e.envRelease(ctx, c, b, mode, why, ttl)
	if err != nil {
		return err
	}
	if mode == "get" {
		// The one value and a newline, nothing else: `$(aqmas get ...)` drops the newline.
		_, err = io.WriteString(e.Stdout, out.Entries[0].Value+"\n")
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
			name := x.Name
			if o.EnvName != "" {
				name = o.EnvName
			}
			env = append(env, name+"="+x.Value)
		}
		if o.Run != nil {
			return o.Run(exe, command, env)
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
	_, err = io.WriteString(e.Stdout, shellExports(out.Entries))
	if err == nil {
		e.logf("shell-mode release: children inherit these values until checkin-shell; other processes of this user may read them")
	}
	return err
}
func shellExports(entries []envset.Entry) string {
	var buf strings.Builder
	buf.WriteString("if [ -z \"${BASH_VERSION-}\" ]; then printf '%s\\n' 'aqmas: shell checkout requires Bash' >&2; false\nelif ")
	for i, x := range entries {
		if i > 0 {
			buf.WriteString(" || ")
		}
		fmt.Fprintf(&buf, "builtin declare -p %s >/dev/null 2>&1", x.Name)
	}
	buf.WriteString("; then printf '%s\\n' 'aqmas: destination variable exists; no exports applied' >&2; false\nelse\n")
	for _, x := range entries {
		fmt.Fprintf(&buf, "export %s='%s'\n", x.Name, strings.ReplaceAll(x.Value, "'", "'\\''"))
	}
	buf.WriteString("fi\n")
	return buf.String()
}

func openImport(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := trustedDir(filepath.Dir(abs), false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(abs), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || st.Mode&0022 != 0 {
		unix.Close(fd)
		return nil, errors.New("import requires a trusted owned regular file")
	}
	return os.NewFile(uintptr(fd), "env import"), nil
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
			var b strings.Builder
			b.WriteString("if [ -n \"${BASH_VERSION-}\" ]")
			for _, n := range r.Names {
				fmt.Fprintf(&b, " && { ! builtin declare -p %s >/dev/null 2>&1 || [[ $(builtin declare -p %s) == 'declare -x %s='* ]]; }", n, n, n)
			}
			b.WriteString("; then\n")
			for _, n := range r.Names {
				fmt.Fprintf(&b, "builtin unset -v %s\n", n)
			}
			b.WriteString("else printf '%s\\n' 'aqmas: changed shell variable attributes; inspect manually' >&2; false; fi\n")
			if _, err = io.WriteString(e.Stdout, b.String()); err != nil {
				return err
			}
			err = unlinkAt(d, slot)
		}
	}
	if err != nil {
		return err
	}
	return c.do(ctx, "POST", "/v2/env/grants/"+r.Grant+"/checkin", nil, nil)
}
