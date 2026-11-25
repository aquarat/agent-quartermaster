package server

import (
	"net/http"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// handleHostCatalogue is GET /v2/catalogue (docs/API.md "Discovery"): what
// the calling host may ask for. It lists only organisations that admit this
// host AND have "Hosts may list what they can ask for" on; every other
// organisation contributes nothing, so an organisation with the switch off
// cannot be told from one that does not exist. Names, key names and public
// settings only: no value, no key, and nothing about other hosts.
func (s *Server) handleHostCatalogue(w http.ResponseWriter, r *http.Request, h *store.Host) {
	ctx := r.Context()
	out := api.HostCatalogue{Credentials: []api.HostCredential{}, Targets: []api.HostTarget{}}
	err := s.store.Tx(ctx, func(q *store.Q) error {
		if err := requireActiveIdentity(ctx, q, h.ID); err != nil {
			return err
		}
		if !q.Scoped() {
			return errNotFound()
		}
		if ok, err := q.Admitted(ctx, h.ID); err != nil {
			return err
		} else if !ok {
			return errNotAdmitted()
		}
		sets, err := q.HostSets(ctx, h.ID, s.now())
		if err != nil {
			return err
		}
		out.Discovery = len(sets) > 0
		vault := s.seal != nil && s.bucketsReady() == nil
		for _, x := range sets {
			path := x.OrgSlug + "/" + x.ServiceSlug + "/" + x.SetSlug
			switch x.Kind {
			case "ssh-ca":
				t, ok := s.cfg.Target(x.SetSlug)
				if !ok {
					continue
				}
				approval := "owner-or-standing"
				if t.HighRisk {
					approval = "owner"
				}
				user := "USER"
				if len(t.Users) == 1 {
					user = t.Users[0]
				}
				out.Targets = append(out.Targets, api.HostTarget{Name: t.Name, Path: path, Aliases: t.Aliases, Address: t.Address, Port: t.Port, Users: t.Users, HighRisk: t.HighRisk, MaxSeconds: t.MaxTTLSeconds, Approval: approval, Use: "aqmas ssh " + user + "@" + t.Name + " --why \"...\""})
			case "cloudflare-proxy", "cloudflare-mint":
				if !s.cfg.Cloudflare.Enabled {
					continue
				}
				out.Credentials = append(out.Credentials, api.HostCredential{Path: path, Kind: x.Kind, Title: x.SetTitle, Approval: "per-scope", Use: "aqmas cf scopes"})
			case "env-set":
				if !vault {
					continue
				}
				kind, names, scheme, note, link, ok, err := q.HostSetDetail(ctx, x.SetID)
				if err != nil {
					return err
				}
				if !ok { // nothing stored yet: nothing to ask for
					continue
				}
				c := api.HostCredential{Path: path, Kind: kind, Title: x.SetTitle, Approval: "owner"}
				switch kind {
				case "signer":
					c.Scheme, c.Use = scheme, "aqmas sign "+path+" --why \"...\" FILE"
				case "secret":
					c.Env, c.Note, c.URL, c.Use = names[0], note, link, "aqmas run "+path+" --why \"...\" -- COMMAND"
				default:
					c.Names, c.Use = names, "aqmas run "+path+" --why \"...\" -- COMMAND"
				}
				out.Credentials = append(out.Credentials, c)
			}
		}
		return nil
	})
	if err != nil {
		s.writeErr(w, r, s.hostNotFound(ctx, h, err))
		return
	}
	writeJSON(w, http.StatusOK, out)
}
