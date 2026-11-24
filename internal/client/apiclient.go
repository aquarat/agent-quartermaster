package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Exit codes (docs/API.md section 3).
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitDenied      = 3
	ExitExpired     = 4
	ExitUnreachable = 5
	ExitCancelled   = 130
)

// UnreachableError covers connection and TLS failures (exit 5).
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string {
	return "server unreachable or TLS failure: " + e.Err.Error()
}
func (e *UnreachableError) Unwrap() error { return e.Err }

// APIError is a non-2xx response carrying api.Error.
type APIError struct {
	HTTPStatus int
	Code       string
	Message    string
	// NotAPI names the address that answered when the answer cannot have come from the
	// agent API: a redirect or an HTML page (a web UI, or a sign-in proxy in front of one).
	NotAPI string
}

// notAgentAPI is the explanation for an answer that is not the agent API's.
func notAgentAPI(server, what string) string {
	return fmt.Sprintf("%s does not look like the aqmas agent API (%s). "+
		"The server address must be the bastion's agent API, https://HOST:8443, not the address of the web UI. "+
		"The Help page in the web UI shows the exact `aqmas enroll` command with --server and --ca-pin", sanitize(server), what)
}

// lockedNotice is what the CLI prints while a bucket it needs is closed (423
// "locked"): the broker's own words when it names the bucket, else a generic line.
func lockedNotice(e *APIError) string {
	if e != nil && strings.Contains(e.Message, "waiting for the owner") && len(e.Message) <= 200 && !strings.ContainsFunc(e.Message, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return e.Message
	}
	return "waiting for the owner to reopen the credential's bucket"
}

// NotAdmitted reports the server's "enrolled, but not admitted to an organisation" answer.
func NotAdmitted(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == api.ErrNotAdmitted
}

// plainNotFound is a 404 that means "nothing of that name here", not "this host is not
// admitted": the cue for the callers that turn a 404 into "feature not installed".
func plainNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.HTTPStatus == http.StatusNotFound && ae.Code != api.ErrNotAdmitted
}

func (e *APIError) Error() string {
	if e.NotAPI != "" {
		return notAgentAPI(e.NotAPI, sanitize(e.Message))
	}
	if e.Code == api.ErrNotAdmitted {
		return "this host is enrolled but not admitted to an organisation yet, so the broker shows it nothing. " +
			"Ask the owner to admit it in the web UI (the organisation's Hosts page: Admit), then run the command again"
	}
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.HTTPStatus)
	}
	return fmt.Sprintf("server: %s: %s", sanitize(e.Code), sanitize(msg))
}

// DecisionError is a request or enrollment that ended without approval.
type DecisionError struct {
	Status string // denied, expired, revoked, cancelled
	What   string // "request 01J..." or "enrollment 01J..."
	Note   string
}

func (e *DecisionError) Error() string {
	s := fmt.Sprintf("%s was %s", e.What, e.Status)
	if e.Note != "" {
		s += ": " + sanitize(e.Note)
	}
	return s
}

// ErrCancelled is returned when the user interrupted a wait.
var ErrCancelled = errors.New("cancelled")

// ExitCode maps an error to the CLI's exit code.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var de *DecisionError
	var ue *UnreachableError
	var ae *APIError
	var uerr *UsageError
	var cfr *CFRefusalError
	var cfs *CFStatusError
	switch {
	case errors.As(err, &cfr):
		return ExitDenied
	case errors.As(err, &cfs):
		if cfs.Status == http.StatusBadGateway || cfs.Status == http.StatusServiceUnavailable || cfs.Status == http.StatusGatewayTimeout {
			return ExitUnreachable
		}
		return ExitError
	case errors.Is(err, ErrCancelled), errors.Is(err, context.Canceled):
		return ExitCancelled
	case errors.As(err, &de):
		switch de.Status {
		case api.StatusExpired:
			return ExitExpired
		case api.StatusCancelled:
			return ExitCancelled
		}
		return ExitDenied
	case errors.As(err, &ue):
		return ExitUnreachable
	case errors.As(err, &ae):
		switch ae.Code {
		case "denied":
			return ExitDenied
		case "expired":
			return ExitExpired
		}
		if ae.HTTPStatus == http.StatusBadGateway || ae.HTTPStatus == http.StatusServiceUnavailable || ae.HTTPStatus == http.StatusGatewayTimeout {
			return ExitUnreachable
		}
		return ExitError
	case errors.As(err, &uerr):
		return ExitUsage
	}
	return ExitError
}

// UsageError is a command-line mistake (exit 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// APIClient talks to the agent API.
type APIClient struct {
	base string
	http *http.Client
	// proxyHTTP shares the transport but has no overall timeout: proxied uploads stream up
	// to 100 MiB and are bounded by the caller's context.
	proxyHTTP *http.Client
	maxRsp    int64
}

// NewAPIClient builds a client that verifies the server with trust and presents clientCert
// (nil for the unauthenticated enrollment endpoints).
func NewAPIClient(server string, trust *Trust, clientCert *tls.Certificate, now func() time.Time) (*APIClient, error) {
	host, _, err := serverHostPort(server)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:               nil, // never route the broker through an HTTP(S)_PROXY from the environment
		TLSClientConfig:     trust.TLSConfig(host, clientCert, now),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     60 * time.Second,
	}
	return &APIClient{
		base:      strings.TrimRight(server, "/"),
		http:      &http.Client{Transport: tr, Timeout: 60 * time.Second, CheckRedirect: noRedirects},
		proxyHTTP: &http.Client{Transport: tr, CheckRedirect: noRedirects},
		maxRsp:    1 << 20,
	}, nil
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c *APIClient) do(ctx context.Context, method, path string, in, out any) error {
	return c.doWith(ctx, method, path, nil, in, out)
}

func (c *APIClient) doWith(ctx context.Context, method, path string, hdr http.Header, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "aqmas/"+Version)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		return &UnreachableError{Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxRsp))
	if err != nil {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		return &UnreachableError{Err: err}
	}
	// The agent API never redirects and never answers with a page. Either means the
	// address is something else, typically the web UI or the sign-in proxy in front of it.
	html := strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))), "text/html")
	if redirect := resp.StatusCode >= 300 && resp.StatusCode <= 399; redirect || html {
		what := fmt.Sprintf("it answered HTTP %d with a web page", resp.StatusCode)
		if redirect {
			what = fmt.Sprintf("it answered HTTP %d, a redirect", resp.StatusCode)
			if u, err := url.Parse(resp.Header.Get("Location")); err == nil && u.Host != "" && len(u.Host) <= 255 {
				what += " to " + u.Host
			}
		}
		return &APIError{HTTPStatus: resp.StatusCode, Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: what, NotAPI: c.base}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{HTTPStatus: resp.StatusCode}
		var body api.Error
		if json.Unmarshal(data, &body) != nil || body.Code == "" {
			ae.Code = fmt.Sprintf("http_%d", resp.StatusCode)
			ae.Message = http.StatusText(resp.StatusCode)
		} else {
			ae.Code, ae.Message = body.Code, body.Message
		}
		return ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("server sent an unreadable %s %s response: %w", method, path, err)
	}
	return nil
}

// Enroll posts an enrollment.
func (c *APIClient) Enroll(ctx context.Context, req *api.EnrollRequest) (*api.EnrollResponse, error) {
	var out api.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/v1/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnrollStatus long-polls an enrollment (wait 0 = no long-poll) with the enrollment's poll token.
func (c *APIClient) EnrollStatus(ctx context.Context, id, pollToken string, wait time.Duration) (*api.EnrollStatus, error) {
	var out api.EnrollStatus
	hdr := http.Header{}
	hdr.Set(api.EnrollTokenHeader, pollToken)
	if err := c.doWith(ctx, http.MethodGet, "/v1/enroll/"+url.PathEscape(id)+waitQuery(wait), hdr, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateRequest posts an access request.
func (c *APIClient) CreateRequest(ctx context.Context, req *api.AccessRequest) (*api.RequestCreated, error) {
	var out api.RequestCreated
	path := "/v1/requests"
	if req.Indefinite {
		path = "/v2/personal/requests"
	} // never downgrade an explicit indefinite request
	if err := c.do(ctx, http.MethodPost, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RequestStatus long-polls a request (wait 0 = no long-poll).
func (c *APIClient) RequestStatus(ctx context.Context, id string, wait time.Duration) (*api.RequestStatus, error) {
	var out api.RequestStatus
	if err := c.do(ctx, http.MethodGet, "/v1/requests/"+url.PathEscape(id)+waitQuery(wait), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelRequest withdraws a pending request (POST /v1/requests/{id}/cancel).
func (c *APIClient) CancelRequest(ctx context.Context, id string) (*api.RequestStatus, error) {
	var out api.RequestStatus
	if err := c.do(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(id)+"/cancel", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SSHCA fetches the SSH user CA public key (GET /v1/ssh-ca).
func (c *APIClient) Resolve(ctx context.Context, t Target) (api.ResolvedTarget, error) {
	var out api.ResolvedTarget
	err := c.do(ctx, "GET", "/v1/ssh-target?"+url.Values{"target": {t.Host}, "user": {t.User}}.Encode(), nil, &out)
	return out, err
}

func (c *APIClient) SSHCA(ctx context.Context) (*api.SSHCA, error) {
	var out api.SSHCA
	if err := c.do(ctx, http.MethodGet, "/v1/ssh-ca", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActiveGrants lists this host's active grants.
func (c *APIClient) ActiveGrants(ctx context.Context) (*api.GrantList, error) {
	var out api.GrantList
	if err := c.do(ctx, http.MethodGet, "/v1/grants?active=1", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- the bastion itself (docs/BASTION-ACCESS.md) ----

// BastionInfo asks what this host may request on the bastion (GET /v1/bastion; 404 while
// access to the bastion is not installed).
func (c *APIClient) BastionInfo(ctx context.Context) (*api.BastionInfo, error) {
	var out api.BastionInfo
	if err := c.do(ctx, http.MethodGet, "/v1/bastion", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateBastionRequest asks for a session on the bastion.
func (c *APIClient) CreateBastionRequest(ctx context.Context, req *api.BastionRequest) (*api.RequestCreated, error) {
	var out api.RequestCreated
	if err := c.do(ctx, http.MethodPost, "/v1/bastion/requests", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BastionRequestStatus long-polls a bastion request (wait 0 = no long-poll).
func (c *APIClient) BastionRequestStatus(ctx context.Context, id string, wait time.Duration) (*api.RequestStatus, error) {
	var out api.RequestStatus
	if err := c.do(ctx, http.MethodGet, "/v1/bastion/requests/"+url.PathEscape(id)+waitQuery(wait), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelBastionRequest withdraws a pending bastion request.
func (c *APIClient) CancelBastionRequest(ctx context.Context, id string) (*api.RequestStatus, error) {
	var out api.RequestStatus
	if err := c.do(ctx, http.MethodPost, "/v1/bastion/requests/"+url.PathEscape(id)+"/cancel", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateSetupRequest queues a routine maintenance task for the owner's approval.
func (c *APIClient) CreateSetupRequest(ctx context.Context, req *api.SetupRequest) (*api.RequestCreated, error) {
	var out api.RequestCreated
	if err := c.do(ctx, http.MethodPost, "/v1/setup-requests", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetupRequestStatus long-polls a queued task. after names the run state the caller has
// already seen: once approved, the poll returns when the run has left it.
func (c *APIClient) SetupRequestStatus(ctx context.Context, id string, wait time.Duration, after string) (*api.SetupRequestStatus, error) {
	var out api.SetupRequestStatus
	q := url.Values{}
	if wait > 0 {
		q.Set("wait", wait.String())
	}
	if after != "" {
		q.Set("after", after)
	}
	path := "/v1/setup-requests/" + url.PathEscape(id)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelSetupRequest withdraws a queued task that is still undecided.
func (c *APIClient) CancelSetupRequest(ctx context.Context, id string) (*api.SetupRequestStatus, error) {
	var out api.SetupRequestStatus
	if err := c.do(ctx, http.MethodPost, "/v1/setup-requests/"+url.PathEscape(id)+"/cancel", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func waitQuery(wait time.Duration) string {
	if wait <= 0 {
		return ""
	}
	return "?wait=" + url.QueryEscape(wait.String())
}

// Sanitize is sanitize for callers outside the package (error messages may quote
// server-controlled text such as certificate names).
func Sanitize(s string) string { return sanitize(s) }

// sanitize strips control characters (terminal escape injection) from server- or
// user-supplied text before it is printed, and caps its length.
func sanitize(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= 2000 {
			b.WriteString("...")
			break
		}
		switch {
		case r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' || (r >= '‪' && r <= '‮') || (r >= '⁦' && r <= '⁩'):
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}
