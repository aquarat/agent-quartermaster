package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// cfTokenDirName is the per-user cache of token-mode grants, under the cache dir.
const cfTokenDirName = "cf-tokens"

var cfTokenRE = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{16,512}$`)

// cachedCFToken is <cache>/cf-tokens/<grant id>.json (0600).
type cachedCFToken struct {
	GrantID     string    `json:"grant_id"`
	RequestID   string    `json:"request_id"`
	Scope       string    `json:"scope"`
	ScopeParams string    `json:"scope_params"`
	AccountID   string    `json:"account_id"`
	NotAfter    time.Time `json:"not_after"`
	TokenID     string    `json:"token_id,omitempty"`
	Token       string    `json:"token"`
}

func (e *Env) cfTokenDir() (string, error) {
	if err := ensurePrivateDir(e.Paths.CacheDir); err != nil {
		return "", err
	}
	dir := filepath.Join(e.Paths.CacheDir, cfTokenDirName)
	if err := ensurePrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// storeCFToken caches a token-mode grant's value. The value comes only on the first poll after
// approval; if it is missing here, another process (or a crash before caching) consumed it.
func (e *Env) storeCFToken(requestID string, g *api.Grant) error {
	cf := g.Cloudflare
	if cf.Token == "" {
		if cf.TokenDelivered {
			return fmt.Errorf("grant %s: the child token was already delivered once and is not in this host's cache; request a new grant", g.ID)
		}
		return fmt.Errorf("grant %s: the server sent no child token", g.ID)
	}
	if !cfTokenRE.MatchString(cf.Token) {
		return fmt.Errorf("grant %s: the server sent a malformed child token", g.ID)
	}
	dir, err := e.cfTokenDir()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cachedCFToken{GrantID: g.ID, RequestID: requestID, Scope: cf.Scope, ScopeParams: cf.ScopeParams,
		AccountID: cf.AccountID, NotAfter: g.NotAfter, TokenID: cf.TokenID, Token: cf.Token}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, g.ID+".json"), data, 0o600)
}

// loadCFTokens returns the cached tokens, deleting expired ones (and unreadable files).
func (e *Env) loadCFTokens() ([]cachedCFToken, error) {
	dir := filepath.Join(e.Paths.CacheDir, cfTokenDirName)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := checkPrivatePath(dir, true); err != nil {
		return nil, err
	}
	now := e.now()
	var out []cachedCFToken
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".json") || !safeID(strings.TrimSuffix(name, ".json")) {
			continue
		}
		path := filepath.Join(dir, name)
		if checkSecretFile(path) != nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var t cachedCFToken
		if json.Unmarshal(data, &t) != nil || t.GrantID+".json" != name {
			os.Remove(path)
			continue
		}
		if !now.Before(t.NotAfter) {
			os.Remove(path) // expired: the token no longer works; never keep it around
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.After(out[j].NotAfter) })
	return out, nil
}

func (e *Env) dropCFToken(grantID string) {
	if safeID(grantID) {
		os.Remove(filepath.Join(e.Paths.CacheDir, cfTokenDirName, grantID+".json"))
	}
}

// CFTokenOptions are the flags of `aqmas cf token`.
type CFTokenOptions struct {
	Spec  CFRequestSpec
	TTL   time.Duration
	Why   string
	Print bool
	Fresh bool
}

// CFToken runs `aqmas cf token`: a cached or new token-mode grant; runs cmd with it, or prints
// it (only to a non-terminal or with --print). Returns cmd's exit status.
func (e *Env) CFToken(ctx context.Context, o CFTokenOptions, cmd []string) (int, error) {
	o.Spec.Mode = api.CFModeToken
	if err := checkCFTTL(o.TTL); err != nil {
		return 0, err
	}
	why, err := e.checkWhy(o.Why)
	if err != nil {
		return 0, err
	}
	cfg, c, err := e.authedClient()
	if err != nil {
		return 0, err
	}
	dir, err := e.cfTokenDir()
	if err != nil {
		return 0, err
	}
	unlock, err := e.lockDir(ctx.Done(), dir)
	if err != nil {
		return 0, err
	}
	tok, err := e.cachedOrNewCFToken(ctx, c, cfg, o, why)
	unlock()
	if err != nil {
		return 0, err
	}
	if len(cmd) > 0 {
		env := childEnv(e.environ(), map[string]string{
			"CLOUDFLARE_API_TOKEN":  tok.Token,
			"CF_API_TOKEN":          tok.Token,
			"CLOUDFLARE_ACCOUNT_ID": tok.AccountID,
			"CF_ACCOUNT_ID":         tok.AccountID,
		}, []string{"CLOUDFLARE_API_BASE_URL", "CF_API_BASE_URL", "CF_API_BASE"})
		return e.runChild(ctx, cmd, env)
	}
	if e.StdoutIsTTY && !o.Print {
		e.logf("child token for grant %s is cached until %s; not printed to a terminal (use --print, or run a command: aqmas cf token ... -- CMD)",
			tok.GrantID, tok.NotAfter.Local().Format("15:04:05"))
		return 0, nil
	}
	_, err = fmt.Fprintln(e.Stdout, tok.Token)
	return 0, err
}

func (e *Env) cachedOrNewCFToken(ctx context.Context, c *APIClient, cfg *Config, o CFTokenOptions, why string) (*cachedCFToken, error) {
	want := canonicalScopeParams(o.Spec.Params)
	if !o.Fresh {
		toks, err := e.loadCFTokens()
		if err != nil {
			return nil, err
		}
		for _, t := range toks {
			if t.Scope != o.Spec.Scope || t.ScopeParams != want || t.NotAfter.Sub(e.now()) < MinRemaining {
				continue
			}
			st, err := c.RequestStatus(ctx, t.RequestID, 0)
			var ue *UnreachableError
			switch {
			case err == nil && st.Status == api.StatusApproved:
			case errors.As(err, &ue):
				e.logf("warning: cannot check grant %s with the server (%v); using the cached token", t.GrantID, err)
			default:
				status := "unknown"
				if err == nil {
					status = sanitize(st.Status)
				}
				e.logf("cached grant %s is %s on the server; requesting a new one", t.GrantID, status)
				e.dropCFToken(t.GrantID)
				continue
			}
			e.logf("reusing token grant %s (%s), valid until %s", t.GrantID, describeCFGrant(t.Scope, t.ScopeParams, ""),
				t.NotAfter.Local().Format("15:04:05"))
			return &t, nil
		}
	}
	sts, err := e.RequestCF(ctx, c, cfg, []CFRequestSpec{o.Spec}, o.TTL, why)
	if err != nil {
		return nil, err
	}
	gid := sts[0].Grant.ID
	toks, err := e.loadCFTokens()
	if err != nil {
		return nil, err
	}
	for _, t := range toks {
		if t.GrantID == gid {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("grant %s: token not found in the cache after approval (expired already?)", gid)
}
