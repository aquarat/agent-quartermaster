package server

import (
	"net/http"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, _ string) {
	hs, err := s.store.Q().Hosts(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, hs)
}

func (s *Server) handleHelp(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, api.HelpConfig{AgentAPIURL: s.cfg.AgentAPIURL, CLIDownloadBaseURL: s.cfg.CLIDownloadBaseURL, CAPin: s.pki.CAPin(), OwnerMaxSeconds: s.cfg.TTL.OwnerMaxSeconds})
}
