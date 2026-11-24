package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// GitHub is the only release source every installation has: these are the compiled defaults,
// overridable in configuration so that a fork works. A second source has no default at all;
// it exists only where the configuration names it.
const GitHubAPI = "https://api.github.com/repos/aquarat/agent-quartermaster"
const GitHubRepo = "https://github.com/aquarat/agent-quartermaster.git"

var ErrOffline = errors.New("release source unreachable")

// ErrNoAsset is a release that has no attachment of the name asked for.
var ErrNoAsset = errors.New("missing release checksum asset")
var attachmentID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Source struct {
	API       string `toml:"api"`
	TokenFile string `toml:"token_file"`
}

// Host is the host name of the source's API, for naming it to the owner ("" when unset).
func (s Source) Host() string {
	u, e := url.Parse(s.API)
	if e != nil {
		return ""
	}
	return u.Host
}

// loopbackHTTP lets plain http to a loopback address stand in for https. It is off in
// every production binary: only Go tests (EnableLoopbackHTTPForTests) and binaries built
// with the "interop" tag for the interop suite turn it on, because their fake release
// sources and git remotes listen on 127.0.0.1 without TLS.
var loopbackHTTP bool

// EnableLoopbackHTTPForTests is for tests only: it accepts http://127.0.0.1 where https is
// required. Nothing in a release build calls it.
func EnableLoopbackHTTPForTests() { loopbackHTTP = true }

// ValidAPI reports whether s is acceptable as a release API base: https only, no
// credentials, query or fragment, and a bounded length.
func ValidAPI(s string) bool {
	u, e := url.Parse(s)
	return e == nil && len(s) <= 512 && SafeURL(s) && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "..") && !strings.ContainsAny(s, "?#@ \t\r\n\"\\")
}

var sshRepoRE = regexp.MustCompile(`^ssh://[a-z_][a-z0-9_-]{0,31}@[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\.git$`)
var httpsRepoRE = regexp.MustCompile(`^https://[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\.git$`)
var loopbackRepoRE = regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]{1,5}/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\.git$`)

// GitProtocol classifies a git remote the update path may fetch from: "ssh" (with a deploy
// key and pinned host keys), "https" (anonymous, a public repository), or "" for anything
// else ("http" to loopback exists in test builds only). No form carries a password.
func GitProtocol(repo string) string {
	switch {
	case strings.Contains(repo, ".."):
	case sshRepoRE.MatchString(repo):
		return "ssh"
	case httpsRepoRE.MatchString(repo):
		return "https"
	case loopbackHTTP && loopbackRepoRE.MatchString(repo):
		return "http"
	}
	return ""
}

var githubAPIRE = regexp.MustCompile(`^https://api\.github\.com/repos/([A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99})$`)

// RepoFor is the git remote that goes with a GitHub release API: the public repository over
// HTTPS. An API that is not api.github.com (or unset) gives the compiled default.
func RepoFor(githubAPI string) string {
	if m := githubAPIRE.FindStringSubmatch(strings.TrimRight(githubAPI, "/")); m != nil {
		return "https://github.com/" + strings.TrimSuffix(m[1], ".git") + ".git"
	}
	return GitHubRepo
}

// DownloadBase is where GitHub publishes the assets of a release: the public download
// address that goes with a GitHub release API ("" for the compiled default) and a version.
// It is "" for an invalid version, and for an API that is not api.github.com: nothing is
// known about where such a source serves downloads.
func DownloadBase(githubAPI, version string) string {
	if githubAPI == "" {
		githubAPI = GitHubAPI
	}
	m := githubAPIRE.FindStringSubmatch(strings.TrimRight(githubAPI, "/"))
	if m == nil || !ValidVersion(version) {
		return ""
	}
	return "https://github.com/" + strings.TrimSuffix(m[1], ".git") + "/releases/download/v" + version
}

// Sources are the published release sources an installation compares: GitHub always, and a
// second, independent builder (a Forgejo/Gitea-compatible forge) only when configured.
type Sources struct {
	GitHub Source
	Second Source
}

// HasSecond reports whether a second source is configured.
func (s Sources) HasSecond() bool { return s.Second.API != "" }

// Names lists the sources in the words shown to the owner.
func (s Sources) Names() []string {
	names := []string{"GitHub"}
	if s.HasSecond() {
		names = append(names, "second source ("+s.Second.Host()+")")
	}
	return names
}

// Fill fetches the manifest of m.Version from every configured source and requires them to
// agree. A configured source that cannot be reached, or disagrees, is an error: there is no
// fallback to fewer sources, or making one unreachable would downgrade the check.
//
// ExtraSums is filled the same way, except that a release may have none (one from before
// 0.9.3): then Extra stays nil. Where one source has the file and another does not, or they
// differ, that is a disagreement like any other.
func (s Sources) Fill(ctx context.Context, m *Metadata) error {
	var e error
	m.Second, m.Extra = nil, nil
	if m.GitHub, e = s.GitHub.Hashes(ctx, m.Version, true); e != nil {
		return fmt.Errorf("GitHub: %w", e)
	}
	if m.Extra, e = s.GitHub.ExtraHashes(ctx, m.Version, true); e != nil {
		return fmt.Errorf("GitHub: %w", e)
	}
	if s.HasSecond() {
		if m.Second, e = s.Second.Hashes(ctx, m.Version, false); e != nil {
			return fmt.Errorf("second source (%s): %w", s.Second.Host(), e)
		}
		if !m.Second.Agrees(m.GitHub) {
			return errors.New("release hashes disagree between GitHub and the second source (" + s.Second.Host() + ")")
		}
		extra, e := s.Second.ExtraHashes(ctx, m.Version, false)
		if e != nil {
			return fmt.Errorf("second source (%s): %w", s.Second.Host(), e)
		}
		if (extra == nil) != (m.Extra == nil) || extra != nil && !maps.Equal(extra, m.Extra) {
			return errors.New("release hashes (" + ExtraSums + ") disagree between GitHub and the second source (" + s.Second.Host() + ")")
		}
	}
	return nil
}

func SafeURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Host != "" && u.User == nil && (u.Scheme == "https" || loopbackHTTP && u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())
}
func ReadLimit(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("release data too large")
	}
	return b, e
}

// Hashes uses the release API for private as well as public repositories. Never send
// bearer credentials to the storage origin of a redirected download. github selects the API
// shape: GitHub's, or the Forgejo/Gitea one a second source speaks.
func (s Source) Hashes(ctx context.Context, version string, github bool) (Sums, error) {
	b, e := s.Asset(ctx, version, "SHA256SUMS", github, 4096)
	if e != nil {
		return nil, e
	}
	return Parse(b)
}

// ExtraHashes is the release's ExtraSums manifest, or nil for a release that has none.
func (s Source) ExtraHashes(ctx context.Context, version string, github bool) (Sums, error) {
	b, e := s.Asset(ctx, version, ExtraSums, github, 4096)
	if errors.Is(e, ErrNoAsset) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return ParseExtra(b)
}

// Asset downloads one named release attachment (bounded). The caller verifies its digest.
func (s Source) Asset(ctx context.Context, version, name string, github bool, limit int64) ([]byte, error) {
	if !ValidVersion(version) {
		return nil, errors.New("invalid release version")
	}
	base := strings.TrimRight(s.API, "/")
	if base == "" {
		if !github {
			return nil, errors.New("no second release source is configured")
		}
		base = GitHubAPI
	}
	if !SafeURL(base) {
		return nil, errors.New("invalid release API URL")
	}
	origin, _ := url.Parse(base)
	var token string
	if s.TokenFile != "" {
		b, e := os.ReadFile(s.TokenFile)
		if e != nil {
			return nil, errors.New("cannot read release API token file")
		}
		token = strings.TrimSpace(string(b))
	}
	timeout := 30 * time.Second
	if limit > 1<<20 {
		timeout = 10 * time.Minute
	}
	client := http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || !SafeURL(req.URL.String()) || via[0].URL.Scheme != req.URL.Scheme {
			return errors.New("invalid release redirect")
		}
		req.Header.Del("Authorization")
		return nil
	}}
	get := func(target, accept string, limit int64) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		if e != nil {
			return nil, e
		}
		if req.URL.Host != origin.Host || req.URL.Scheme != origin.Scheme {
			return nil, errors.New("unexpected release asset origin")
		}
		req.Header.Set("Accept", accept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, e := client.Do(req)
		if e != nil {
			var ne *net.OpError
			if errors.As(e, &ne) {
				return nil, ErrOffline
			}
			return nil, errors.New("release HTTPS request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
				return nil, ErrOffline
			}
			return nil, fmt.Errorf("release API: HTTP %d", resp.StatusCode)
		}
		return ReadLimit(resp.Body, limit)
	}
	b, e := get(base+"/releases/tags/v"+version, "application/json", 1<<20)
	if e != nil {
		return nil, e
	}
	var r struct {
		Tag    string `json:"tag_name"`
		Draft  bool
		Assets []struct {
			Name string
			ID   int64
			UUID string `json:"uuid"`
			Type string `json:"type"`
		}
	}
	if json.Unmarshal(b, &r) != nil || r.Tag != "v"+version || r.Draft {
		return nil, errors.New("invalid release metadata")
	}
	var target string
	for _, a := range r.Assets {
		if a.Name != name {
			continue
		}
		if target != "" || a.ID <= 0 {
			return nil, errors.New("invalid release checksum asset")
		}
		if github {
			target = fmt.Sprintf("%s/releases/assets/%d", base, a.ID)
		} else {
			prefix, _, ok := strings.Cut(base, "/api/v1/repos/")
			if !ok || !attachmentID.MatchString(a.UUID) || a.Type == "external" {
				return nil, errors.New("invalid release attachment")
			}
			target = prefix + "/attachments/" + a.UUID
		}
	}
	if target == "" {
		return nil, ErrNoAsset
	}
	return get(target, "application/octet-stream", limit)
}
