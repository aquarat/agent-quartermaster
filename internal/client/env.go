package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"time"
)

// Version is set at build time with -ldflags "-X .../internal/client.Version=...".
var Version = "dev"

// Env is everything the commands read from the outside world, so tests can replace it.
type Env struct {
	Paths      Paths
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	StdinIsTTY bool
	Getenv     func(string) string
	Environ    func() []string
	Now        func() time.Time
	Getwd      func() (string, error)
	PID        int
	User       string
	// PollMin is the minimum delay between polls when the server answers a long-poll at once.
	PollMin time.Duration
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) logf(format string, args ...any) {
	fmt.Fprintf(e.Stderr, "aqmas: "+format+"\n", args...)
}

// authedClient loads the config, trust and client certificate and returns an mTLS API client.
func (e *Env) authedClient() (*Config, *APIClient, error) {
	cfg, err := LoadConfig(e.Paths)
	if err != nil {
		return nil, nil, err
	}
	if cfg.ClientCert == "" || cfg.ClientKey == "" {
		return nil, nil, ErrNotEnrolled
	}
	trust, err := LoadTrust(cfg)
	if err != nil {
		return nil, nil, err
	}
	keyPath, certPath := expandHome(cfg.ClientKey), expandHome(cfg.ClientCert)
	if err := checkSecretFile(keyPath); err != nil {
		return nil, nil, fmt.Errorf("client key: %w", err)
	}
	if err := checkPrivatePath(certPath, false); err != nil {
		return nil, nil, fmt.Errorf("client certificate: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("client key/certificate: %w", err)
	}
	if pair.Leaf != nil && e.now().After(pair.Leaf.NotAfter) {
		return nil, nil, fmt.Errorf("client certificate expired at %s; re-enroll with `aqmas enroll --name %s --force`",
			pair.Leaf.NotAfter.UTC().Format(time.RFC3339), cfg.HostName)
	}
	c, err := NewAPIClient(cfg.Server, trust, &pair, e.now)
	if err != nil {
		return nil, nil, err
	}
	return cfg, c, nil
}

// sleepCtx sleeps d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ErrCancelled
	case <-t.C:
		return nil
	}
}

// pollDelay is how long to wait before the next poll after a pending answer that took took.
func (e *Env) pollDelay(pollAfterMS int, took time.Duration) time.Duration {
	min := e.PollMin
	if min == 0 {
		min = time.Second
	}
	d := time.Duration(pollAfterMS) * time.Millisecond
	if d < min {
		d = min
	}
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	// A real long-poll already waited; only throttle answers that came back quickly.
	if took >= d {
		return 0
	}
	return d - took
}

// DefaultEnv is the real process environment.
func DefaultEnv(stdinIsTTY bool) (*Env, error) {
	p, err := DefaultPaths(os.Getenv)
	if err != nil {
		return nil, err
	}
	return &Env{
		Paths:      p,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		StdinIsTTY: stdinIsTTY,
		Getenv:     os.Getenv,
		Environ:    os.Environ,
		Now:        time.Now,
		Getwd:      os.Getwd,
		PID:        os.Getpid(),
		User:       currentUser(),
	}, nil
}
