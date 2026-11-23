package maint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// Status is the runner's public report (world-readable, so nothing secret: only fixed text,
// public identifiers and digests). aqmasd shows it on the Setup page.
type Status struct {
	Runner  RunnerInfo             `json:"runner"`
	Current *TaskStatus            `json:"current,omitempty"`
	Refused *Refusal               `json:"refused,omitempty"` // the last request that was not run
	Tasks   map[string]*TaskStatus `json:"tasks"`
}

// Refusal says why a spooled request was rejected before any task started.
type Refusal struct {
	At     string `json:"at"`
	Reason string `json:"reason"`
	// Request identifies the refused approval like TaskStatus.Request ("" when the spool
	// held nothing readable).
	Request string `json:"request,omitempty"`
}

// RunnerInfo describes the installed runner.
type RunnerInfo struct {
	Version    string   `json:"version"`
	SecretsKey string   `json:"secrets_key"` // HPKE public key for pasted secrets
	Pins       []string `json:"pins"`        // pinned credential IDs, base64url
	DeployKey  string   `json:"deploy_key,omitempty"`
	Sources    *Sources `json:"sources,omitempty"` // pinned on the machine; nil when not
}

// TaskStatus is one run of one task.
type TaskStatus struct {
	Task string `json:"task"`
	// Request identifies the approval that started this run: the first 16 hex characters of
	// SHA-256(canonical). Empty for a recovery the runner started itself.
	Request  string            `json:"request,omitempty"`
	State    string            `json:"state"` // running | waiting | done | failed
	Step     string            `json:"step"`
	Waiting  string            `json:"waiting_for,omitempty"`
	Deadline string            `json:"deadline,omitempty"`
	Started  string            `json:"started_at"`
	Finished string            `json:"finished_at,omitempty"`
	Message  string            `json:"message,omitempty"`
	Log      []string          `json:"log"`
	Result   map[string]string `json:"result,omitempty"`
}

const maxLog = 100

// clean keeps one printable line; status text is rendered by a browser.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ReadStatus loads a status file leniently: a missing or damaged file is an empty status.
func ReadStatus(path string) Status {
	var s Status
	if b, err := os.ReadFile(path); err == nil && len(b) <= 1<<20 {
		_ = json.Unmarshal(b, &s)
	}
	if s.Tasks == nil {
		s.Tasks = map[string]*TaskStatus{}
	}
	return s
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (r *Runner) save() {
	b, err := json.Marshal(r.st)
	if err == nil {
		err = writeAtomic(r.l.status(), b, 0644)
	}
	if err != nil {
		r.log.Error("could not write status", "error", err)
	}
}

// begin opens a task's status; step, wait, finish update it.
func (r *Runner) begin(task string) {
	r.st.Current = &TaskStatus{Task: task, State: "running", Started: stamp(r.now()), Log: []string{}}
	r.save()
}

func (r *Runner) step(text string) {
	text = clean(text)
	r.log.Info("step", "task", r.st.Current.Task, "step", text)
	c := r.st.Current
	c.State, c.Step, c.Waiting, c.Deadline = "running", text, "", ""
	c.Log = append(c.Log, stamp(r.now())+" "+text)
	if len(c.Log) > maxLog {
		c.Log = c.Log[len(c.Log)-maxLog:]
	}
	r.save()
}

func (r *Runner) wait(what, text string, deadline time.Time) {
	r.step(text)
	c := r.st.Current
	c.State, c.Waiting, c.Deadline = "waiting", what, stamp(deadline)
	r.save()
}

func (r *Runner) result(key, value string) {
	c := r.st.Current
	if c.Result == nil {
		c.Result = map[string]string{}
	}
	c.Result[key] = clean(value)
	r.save()
}

func (r *Runner) finish(err error, okMessage string) {
	c := r.st.Current
	if c == nil {
		return
	}
	c.Finished, c.Waiting, c.Deadline = stamp(r.now()), "", ""
	if err != nil {
		c.State, c.Message = "failed", clean(err.Error())
		r.log.Error("task failed", "task", c.Task, "error", err)
	} else {
		c.State, c.Message = "done", clean(okMessage)
	}
	if c.Message != "" && c.Message != c.Step {
		c.Log = append(c.Log, c.Finished+" "+c.Message)
	}
	r.st.Tasks[c.Task] = c
	r.st.Current = nil
	r.save()
}
