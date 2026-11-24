package server

import (
	"net/http"
	"strings"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/maint"
	"github.com/aquarat/agent-quartermaster/internal/release"
)

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, _ string) {
	hs, err := s.store.Q().Hosts(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, hs)
}

// handleHelp gives the Help page what it prints into commands. The install commands carry
// the CLI hashes of the release this broker runs, from the record its last verified install
// left (the same one fleet CLIs upgrade from), so a new machine checks its download against
// what the broker recorded then and not against a file fetched now. Where the record was
// made from GitHub alone those hashes are GitHub's own, pinned at that time; the response
// says how many sources agreed. A record of any other release, or none, gives no hashes.
// A token_file means the repository is private: its downloads are not public, so no GitHub
// address is offered. Nothing here comes from the request.
func (s *Server) handleHelp(w http.ResponseWriter, _ *http.Request, _ string) {
	v := api.HelpConfig{AgentAPIURL: s.cfg.AgentAPIURL, CAPin: s.pki.CAPin(), OwnerMaxSeconds: s.cfg.TTL.OwnerMaxSeconds}
	if release.ValidVersion(release.Version) {
		v.ReleaseVersion = release.Version
		if m := maint.ReadInstalled(s.cfg.Updates.Cache()); m != nil && m.Version == release.Version && m.Commit == release.Commit {
			v.CLISHA256, v.CLISHA256Sources = map[string]string{}, m.Compared()
			for _, a := range release.Assets {
				if a != release.Daemon {
					v.CLISHA256[a] = m.GitHub[a]
				}
			}
		}
	}
	if base := strings.TrimRight(s.cfg.CLIDownloadBaseURL, "/"); base != "" {
		v.CLIDownloadBaseURL, v.CLIDownloadSource = base, "config"
	} else if base := release.DownloadBase(s.cfg.Updates.GitHub.API, v.ReleaseVersion); base != "" && s.cfg.Updates.GitHub.TokenFile == "" {
		v.CLIDownloadBaseURL, v.CLIDownloadSource = base, "github"
	}
	writeJSON(w, http.StatusOK, v)
}
