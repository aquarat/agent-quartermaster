package client

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

var (
	cfScopeRE      = regexp.MustCompile(`^cf(\.[a-z0-9-]+)+$`)
	cfParamKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	cfParamValueRE = regexp.MustCompile(`^[A-Za-z0-9*._:/@+-]{1,253}$`)
)

// CFRequestSpec is one Cloudflare grant to request.
type CFRequestSpec struct {
	Scope  string
	Params map[string]string
	Mode   string // "" (proxy) or token
}

func (s CFRequestSpec) String() string {
	out := s.Scope
	if p := canonicalScopeParams(s.Params); p != "" {
		out += " " + p
	}
	if s.Mode == api.CFModeToken {
		out += " (token)"
	}
	return out
}

// ParseCFSpec parses `SCOPE [key=value...]`.
func ParseCFSpec(scope string, kv []string) (CFRequestSpec, error) {
	s := CFRequestSpec{Scope: scope, Params: map[string]string{}}
	if !cfScopeRE.MatchString(scope) {
		return s, &UsageError{Msg: fmt.Sprintf("invalid scope %q (see `aqmas cf scopes`)", sanitize(scope))}
	}
	for _, a := range kv {
		k, v, ok := strings.Cut(a, "=")
		if !ok || !cfParamKeyRE.MatchString(k) {
			return s, &UsageError{Msg: fmt.Sprintf("scope parameter %q: want key=value (e.g. zone=example.com)", sanitize(a))}
		}
		if !cfParamValueRE.MatchString(v) {
			return s, &UsageError{Msg: fmt.Sprintf("scope parameter %s: invalid value %q", k, sanitize(v))}
		}
		if _, dup := s.Params[k]; dup {
			return s, &UsageError{Msg: fmt.Sprintf("scope parameter %s given twice", k)}
		}
		s.Params[k] = v
	}
	return s, nil
}

// checkWhy applies the M1 --why rules: required without a terminal, plain text, 500 bytes.
func (e *Env) checkWhy(why string) (string, error) {
	why = strings.TrimSpace(why)
	if why == "" && !e.StdinIsTTY {
		return "", &UsageError{Msg: "--why \"...\" is required when stdin is not a terminal (say what you need the access for)"}
	}
	if len(why) > MaxReasonLen {
		return "", &UsageError{Msg: fmt.Sprintf("--why is longer than %d bytes", MaxReasonLen)}
	}
	if !utf8.ValidString(why) || sanitize(why) != why {
		return "", &UsageError{Msg: "--why must be plain single-line text"}
	}
	return why, nil
}

func checkCFTTL(ttl time.Duration) error {
	if ttl != 0 && ttl != CFIndefinite && (ttl < time.Minute || ttl > 315360000*time.Second) {
		return &UsageError{Msg: "--ttl must be a positive supported duration or indefinite"}
	}
	return nil
}

const CFIndefinite time.Duration = -1

// pendingCF is a created Cloudflare request being waited for.
type pendingCF struct {
	spec    CFRequestSpec
	created *api.RequestCreated
}

// createCF posts one Cloudflare request and prints the approve URL.
func (e *Env) createCF(ctx context.Context, c *APIClient, cfg *Config, spec CFRequestSpec, ttl time.Duration, why string) (*pendingCF, error) {
	req := &api.AccessRequest{
		Kind:       api.KindCloudflare,
		Cloudflare: &api.CloudflareRequest{Scope: spec.Scope, Params: spec.Params, Mode: spec.Mode},
		Reason:     why,
		TTLSeconds: int(ttl / time.Second),
		Requester:  e.Requester(),
	}
	if len(req.Cloudflare.Params) == 0 {
		req.Cloudflare.Params = nil
	}
	if ttl == CFIndefinite {
		if spec.Mode == api.CFModeToken {
			return nil, &UsageError{Msg: "token mode never offers indefinite grants"}
		}
		req.Indefinite = true
		req.TTLSeconds = 0
	}
	created, err := c.CreateRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if !safeID(created.ID) {
		return nil, fmt.Errorf("server returned an invalid request id %q", sanitize(created.ID))
	}
	shownWhy, shownTTL := why, "scope default ttl"
	if ttl == CFIndefinite {
		shownTTL = "INDEFINITE (until revoked)"
	}
	if shownWhy == "" {
		shownWhy = "(no reason given)"
	}
	if ttl > 0 {
		shownTTL = ttl.String()
	}
	e.logf("request %s (Ref %s): cloudflare %s for %s by %s on %s: %s", created.ID, RefCode(created.ID), spec, shownTTL,
		req.Requester.Tool, sanitize(cfg.HostName), shownWhy)
	switch created.Status {
	case api.StatusPending:
		e.logf("approve at: %s  (waiting; Ctrl-C cancels)", sanitize(created.ApproveURL))
	case api.StatusApproved:
		e.logf("approved at once (auto-approved or a standing approval)")
	}
	return &pendingCF{spec: spec, created: created}, nil
}

// waitCF waits for a created Cloudflare request and checks the grant against what was asked.
func (e *Env) waitCF(ctx context.Context, c *APIClient, p *pendingCF) (*api.RequestStatus, error) {
	st, err := e.waitRequest(ctx, c, p.created)
	if err != nil {
		return nil, err
	}
	g := st.Grant
	if g == nil || g.Kind != api.KindCloudflare || g.Cloudflare == nil || !safeID(g.ID) {
		return nil, fmt.Errorf("request %s: the server approved it but sent no usable Cloudflare grant", p.created.ID)
	}
	mode := p.spec.Mode
	if mode == "" {
		mode = api.CFModeProxy
	}
	if g.Cloudflare.Scope != p.spec.Scope || (g.Cloudflare.Mode != "" && g.Cloudflare.Mode != mode) {
		return nil, fmt.Errorf("request %s: the grant is for %s (%s), not the requested %s (%s)", p.created.ID,
			sanitize(g.Cloudflare.Scope), sanitize(g.Cloudflare.Mode), p.spec.Scope, mode)
	}
	return st, nil
}

// RequestCF creates Cloudflare requests (all at once, so the owner sees every card) and waits
// for each. Ctrl-C withdraws the ones still pending. Token-mode values are cached, never
// returned in the printed output.
func (e *Env) RequestCF(ctx context.Context, c *APIClient, cfg *Config, specs []CFRequestSpec, ttl time.Duration, why string) ([]*api.RequestStatus, error) {
	if err := checkCFTTL(ttl); err != nil {
		return nil, err
	}
	why, err := e.checkWhy(why)
	if err != nil {
		return nil, err
	}
	// The legacy CLI ceiling can be exceeded only when the live catalogue
	// explicitly offers that duration for every requested proxy scope.
	if ttl > MaxTTL || ttl == CFIndefinite {
		cat, err := c.CFCatalogue(ctx)
		if err != nil {
			return nil, err
		}
		for _, spec := range specs {
			allowed := false
			for _, sc := range cat.Scopes {
				if sc.Name == spec.Scope && spec.Mode != api.CFModeToken && (ttl == CFIndefinite && sc.IndefiniteAvailable || ttl > 0 && ttl/time.Second <= time.Duration(sc.MaxTTL)) {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, &UsageError{Msg: "requested duration is not offered for " + sanitize(spec.Scope)}
			}
		}
	}
	var pend []*pendingCF
	cancelAll := func(from int) {
		for _, p := range pend[from:] {
			e.cancelRequestNote(c, p.created, "")
		}
	}
	for _, s := range specs {
		p, err := e.createCF(ctx, c, cfg, s, ttl, why)
		if err != nil {
			if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) {
				cancelAll(0)
			}
			return nil, err
		}
		pend = append(pend, p)
	}
	var out []*api.RequestStatus
	for i, p := range pend {
		st, err := e.waitCF(ctx, c, p)
		if err != nil {
			if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) {
				cancelAll(i)
			}
			return nil, err
		}
		if st.Grant.Cloudflare.Mode == api.CFModeToken {
			if err := e.storeCFToken(p.created.ID, st.Grant); err != nil {
				return nil, err
			}
		}
		st.Grant.Cloudflare.Token = "" // cached (token mode); never handed further up
		e.logf("approved: grant %s (%s) valid until %s", st.Grant.ID, describeCFGrant(st.Grant.Cloudflare.Scope,
			st.Grant.Cloudflare.ScopeParams, st.Grant.Cloudflare.Mode), st.Grant.NotAfter.Local().Format("15:04:05"))
		out = append(out, st)
	}
	return out, nil
}

func describeCFGrant(scope, params, mode string) string {
	s := sanitize(scope)
	if params != "" {
		s += " " + sanitize(params)
	}
	if mode != "" && mode != api.CFModeProxy {
		s += " (" + sanitize(mode) + ")"
	}
	return s
}

// NeedsScopeCommand renders the X-Aqmas-Needs-Scope hint ("cf.dns.edit name=x;zone=y") as a
// ready command line.
func NeedsScopeCommand(needs string) string {
	scope, params, _ := strings.Cut(strings.TrimSpace(needs), " ")
	if !cfScopeRE.MatchString(scope) {
		return ""
	}
	parts := []string{"aqmas", "cf", "request", scope}
	if params != "" {
		for _, kv := range strings.Split(params, ";") {
			if kv != "" {
				parts = append(parts, shellQuote(kv))
			}
		}
	}
	return strings.Join(parts, " ") + ` --why "..."`
}

var shellSafeRE = regexp.MustCompile(`^[A-Za-z0-9._:/@+=,-]+$`)

func shellQuote(s string) string {
	if shellSafeRE.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
