package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const GitHubAPI = "https://api.github.com/repos/aquarat/agent-quartermaster"
const ForgejoAPI = "https://forge.example.com/api/v1/repos/aquarat/agent-quartermaster"

var ErrOffline = errors.New("release source unreachable")
var attachmentID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Source struct {
	API       string `toml:"api"`
	TokenFile string `toml:"token_file"`
}

func SafeURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Host != "" && u.User == nil && (u.Scheme == "https" || u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())
}
func ReadLimit(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("release data too large")
	}
	return b, e
}

// Hashes uses the release API for private as well as public repositories. Never send
// bearer credentials to the storage origin of a redirected download.
func (s Source) Hashes(ctx context.Context, version string, github bool) (Sums, error) {
	b, e := s.Asset(ctx, version, "SHA256SUMS", github, 4096)
	if e != nil {
		return nil, e
	}
	return Parse(b)
}

// Asset downloads one named release attachment (bounded). The caller verifies its digest.
func (s Source) Asset(ctx context.Context, version, name string, github bool, limit int64) ([]byte, error) {
	if !ValidVersion(version) {
		return nil, errors.New("invalid release version")
	}
	base := strings.TrimRight(s.API, "/")
	if base == "" {
		base = ForgejoAPI
		if github {
			base = GitHubAPI
		}
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
				return nil, errors.New("invalid Forgejo release attachment")
			}
			target = prefix + "/attachments/" + a.UUID
		}
	}
	if target == "" {
		return nil, errors.New("missing release checksum asset")
	}
	return get(target, "application/octet-stream", limit)
}
