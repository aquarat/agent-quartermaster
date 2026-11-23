// Package server is aqmasd: the agent API (mTLS) and the approval web API (passkeys).
package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aquarat/agent-quartermaster/internal/server/cfaccess"
	"github.com/aquarat/agent-quartermaster/internal/server/cfproxy"
	"github.com/aquarat/agent-quartermaster/internal/server/config"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
	"github.com/aquarat/agent-quartermaster/internal/server/notify"
	"github.com/aquarat/agent-quartermaster/internal/server/pki"
	"github.com/aquarat/agent-quartermaster/internal/server/store"
)

// Tunables.
const (
	ChallengeTTL      = 2 * time.Minute
	RegisterTTL       = 5 * time.Minute
	SessionTTL        = 8 * time.Hour
	EnrollCodeTTL     = 15 * time.Minute
	MaxWait           = 25 * time.Second
	PollAfterMS       = 2000
	MaxPendingEnrolls = 20
	// MaxPendingEnrollsPerIP limits unauthenticated enrollments per peer address.
	MaxPendingEnrollsPerIP = 3
	// MaxPendingPerHost limits how many undecided requests one host may queue.
	MaxPendingPerHost = 5
	MaxReasonLen      = 500 // api.MaxReasonBytes
	sessionCookie     = "__Host-aqmas_session"
	csrfHeader        = "X-Aqmas"
)

// Options configures a Server.
type Options struct {
	Recovery    bool   // isolated Unix socket only, no agent or network workers
	ConfigPath  string // reread frozen source configuration before supervised import commits
	SealSetup   bool   // supervised seal import, never serve agents
	Maintenance bool   // supervised, login and personal cutover only
	Config      *config.Config
	Logger      *slog.Logger
	Now         func() time.Time // for tests; default time.Now
	// HTTPClient is used for ntfy and Cloudflare Access certs (tests inject one).
	HTTPClient *http.Client
	// AccessCertsURL overrides the Access JWKS URL (tests).
	AccessCertsURL string

	// newCFProxy replaces cfproxy.New (tests in this package inject a fake proxy).
	newCFProxy func(cfproxy.Options) (cfProxy, error)
}

// Server is a running aqmasd instance.
type Server struct {
	recovery        bool
	configPath      string
	seal            *sealRuntime
	sealSetup       bool
	maintenance     bool
	cutover         *cutoverReview // installed before opening the maintenance web listener
	profileRevision string
	updates         updateState
	cfg             *config.Config
	log             *slog.Logger
	now             func() time.Time
	store           *store.Store
	pki             *pki.PKI
	wa              *webauthn.WebAuthn
	rpID            string
	ownerID         []byte
	notify          *notify.Notifier
	access          *cfaccess.Verifier
	bcast           broadcaster
	cf              cfState // milestone 2; zero when cloudflare.enabled is false
}

// DBPath returns the database path for a data dir.
func DBPath(dataDir string) string { return filepath.Join(dataDir, "aqmas.db") }

// CADir returns the key material directory for a data dir.
func CADir(dataDir string) string { return filepath.Join(dataDir, "ca") }

// New opens the store, loads or generates key material and prepares the handlers.
func New(o Options) (*Server, error) {
	cfg := o.Config
	if !o.Recovery && (cfg.Seal.RecoverySerial != nil || cfg.Seal.RecoveryBackupSHA256 != "") {
		return nil, errors.New("broker fenced for recovery; install the replacement transition pin before serving")
	}
	if o.Recovery {
		if err := verifyRecoverySource(cfg); err != nil {
			return nil, err
		}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Stat(cfg.DataDir); err != nil {
		return nil, err
	} else if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("data_dir %s is group/other writable (mode %v)", cfg.DataDir, st.Mode().Perm())
	}
	if o.Maintenance || cfg.Seal.Required || o.SealSetup {
		if _, err := os.Stat(DBPath(cfg.DataDir)); err != nil {
			return nil, fmt.Errorf("cutover requires an existing database: %w", err)
		}
	}
	if o.Maintenance && cfg.Seal.Required {
		return nil, errors.New("personal cutover is unavailable on a seal-required installation")
	}
	// Check the format gate first. In particular a rejected (newer) DB must
	// not create replacement CAs before failing closed.
	st, err := store.Open(DBPath(cfg.DataDir))
	if err != nil {
		return nil, err
	}
	mode, err := sealBoot(cfg, st, o.SealSetup)
	if err != nil {
		st.Close()
		return nil, err
	}
	sealed := mode == modeBuckets || mode == modeMigration
	var p *pki.PKI
	if sealed || o.SealSetup {
		p, err = pki.LoadPublic(CADir(cfg.DataDir))
		if err == nil && !o.SealSetup {
			if leafErr := p.LoadLeaf(cfg.TLSSANs); leafErr != nil {
				o.Logger.Error("agent TLS leaf unavailable: agent listener disabled; the web page remains reachable")
			}
		}
	} else {
		p, err = pki.Load(CADir(cfg.DataDir), cfg.TLSSANs, !o.Maintenance)
	}
	if err != nil {
		st.Close()
		return nil, err
	}
	// The DB holds no secrets but is the authority for who may approve: keep it private.
	for _, f := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(DBPath(cfg.DataDir)+f, 0o600)
	}
	u, _ := url.Parse(cfg.PublicBaseURL)
	rpID := u.Hostname()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "aqmas",
		RPOrigins:     []string{cfg.PublicBaseURL},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
			Registration: webauthn.TimeoutConfig{Timeout: RegisterTTL, TimeoutUVD: RegisterTTL},
		},
	})
	if err != nil {
		st.Close()
		return nil, err
	}
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		st.Close()
		return nil, err
	}
	ownerID, err := st.Q().SetMetaIfAbsent(context.Background(), "owner_webauthn_id", rnd)
	if err != nil {
		st.Close()
		return nil, err
	}
	s := &Server{
		recovery:   o.Recovery,
		configPath: o.ConfigPath,
		sealSetup:  o.SealSetup,
		cfg:        cfg, log: o.Logger, now: o.Now, store: st, pki: p, wa: wa, rpID: rpID, ownerID: ownerID, maintenance: o.Maintenance,
		notify: &notify.Notifier{TopicURL: cfg.Ntfy.TopicURL, Client: o.HTTPClient, Log: o.Logger},
	}
	for _, t := range cfg.Targets {
		if t.HostKey == "" {
			o.Logger.Warn("target has no host_key: grants carry no known_hosts line", "target", t.Name)
		}
	}
	if !cfg.Access.Enabled() {
		o.Logger.Warn("Cloudflare Access validation is OFF (access.team_domain/aud unset): only passkeys protect the web UI")
	}
	if cfg.Access.Enabled() {
		s.access = cfaccess.New(cfg.Access.TeamDomain, cfg.Access.AUD)
		if o.AccessCertsURL != "" {
			s.access.CertsURL = o.AccessCertsURL
		}
		if o.HTTPClient != nil {
			s.access.Client = o.HTTPClient
		}
	}
	if err := s.verifyPersonalConfig(); err != nil {
		st.Close()
		return nil, err
	}
	if sealed {
		if err = s.loadSeal(mode); err == nil {
			err = s.setupSealedNotices()
		}
		if err != nil {
			st.Close()
			return nil, err
		}
	}
	if o.SealSetup {
		s.notify = &notify.Notifier{}
	}
	if cfg.Cloudflare.Enabled && !s.maintenance && !o.SealSetup && !o.Recovery {
		if err := s.setupCloudflare(o); err != nil {
			st.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close releases the store.
func (s *Server) Close() error {
	if z := s.seal; z != nil {
		z.opens.Close()
		z.taps.clear()
		z.capabilities.wipe()
		z.pool.closeAll()
	}
	return s.store.Close()
}

// PKI exposes the loaded key material (for tests and print commands).
func (s *Server) PKI() *pki.PKI { return s.pki }

// Store exposes the store (tests).
func (s *Server) Store() *store.Store { return s.store }

// Run serves the agent API and the web UI until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.recovery {
		return errors.New("recovery must not start public listeners")
	}
	lock, err := s.lockService()
	if err != nil {
		return err
	}
	defer lock.Close()
	if s.seal != nil {
		if _, err := s.store.DB().ExecContext(ctx, `DELETE FROM challenges`); err != nil {
			return err
		}
		s.publishLockStatus("locked")
	}
	agentLn, err := net.Listen("tcp", s.cfg.ListenAgent)
	if err != nil {
		return err
	}
	webLn, err := net.Listen("tcp", s.cfg.ListenWeb)
	if err != nil {
		agentLn.Close()
		return err
	}
	if s.maintenance {
		if err := s.prepareRecovery(ctx); err != nil {
			webLn.Close()
			agentLn.Close()
			return err
		}
	}
	if s.sealSetup {
		if err = s.newStage(); err != nil {
			agentLn.Close()
			webLn.Close()
			return err
		}
	}
	agentSrv := &http.Server{
		Handler:           s.AgentHandler(),
		TLSConfig:         s.pki.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      MaxWait + 15*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	webSrv := &http.Server{
		Handler:           s.WebHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 2)
	if s.sealSetup || s.pki.ServerLeaf == nil {
		agentLn.Close()
	} else {
		go func() { errc <- agentSrv.ServeTLS(agentLn, "", "") }()
	}
	go func() { errc <- webSrv.Serve(webLn) }()
	if !s.maintenance && !s.sealSetup {
		go s.sweeper(ctx)
	}
	if !s.maintenance && !s.sealSetup && s.cfg.Updates.Repo != "" {
		go s.pollUpdates(ctx)
	}
	s.log.Info("aqmasd listening", "agent", agentLn.Addr().String(), "web", webLn.Addr().String())
	var lockStop <-chan struct{}
	if s.seal != nil {
		lockStop = s.seal.stop
	}
	select {
	case <-lockStop:
		err = errors.New("broker restarting (agent TLS leaf renewed)")
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agentSrv.Shutdown(sctx)
	webSrv.Shutdown(sctx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func (s *Server) sweeper(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.sealServing() {
				if err := s.store.Q().SweepEnv(ctx, s.now()); err != nil {
					s.log.Warn("env expiry sweep failed")
				}
				s.reconcileHolds(ctx)
			}
			n, err := s.store.Q().ExpireStale(ctx, s.now())
			if err != nil {
				s.log.Warn("expiry sweep failed", "error", err)
			} else if n > 0 {
				s.bcast.notify()
			}
			s.cfSweep(ctx)
		}
	}
}

// broadcaster wakes long-polls whenever any state changes.
type broadcaster struct {
	mu sync.Mutex
	ch chan struct{}
}

func (b *broadcaster) wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ch == nil {
		b.ch = make(chan struct{})
	}
	return b.ch
}

func (b *broadcaster) notify() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ch != nil {
		close(b.ch)
	}
	b.ch = make(chan struct{})
}

// longPoll calls check until it reports done, the wait elapses or the client goes away.
func (s *Server) longPoll(ctx context.Context, wait time.Duration, check func() (bool, error)) error {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		ch := s.bcast.wait()
		done, err := check()
		if err != nil || done || wait <= 0 {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			_, err := check()
			return err
		case <-ch:
		case <-time.After(5 * time.Second): // also notices expiry without a broadcast
		}
	}
}

// parseWait reads ?wait= as a Go duration ("25s") or seconds ("25"), capped at MaxWait.
func parseWait(v string) time.Duration {
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return 0
		}
		d = time.Duration(n) * time.Second
	}
	if d < 0 {
		return 0
	}
	if d > MaxWait {
		return MaxWait
	}
	return d
}

// NewEnrollCode creates a one-time passkey enroll code (valid 15 minutes, single use) in the
// database at dataDir and returns it. Only its hash is stored.
func NewEnrollCode(dataDir string, now time.Time) (string, error) {
	st, err := store.Open(DBPath(dataDir))
	if err != nil {
		return "", err
	}
	defer st.Close()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b) // 32 chars
	var parts []string
	for i := 0; i < len(raw); i += 4 {
		parts = append(parts, raw[i:i+4])
	}
	code := strings.Join(parts, "-")
	ctx := context.Background()
	err = st.Tx(ctx, func(q *store.Q) error {
		if err := q.InsertEnrollCode(ctx, ids.Hash(normalizeCode(code)), now, now.Add(EnrollCodeTTL)); err != nil {
			return err
		}
		return q.Audit(ctx, now, "system", "passkey_enroll_code", "enroll_code", "one-time code created (valid 15 min)")
	})
	return code, err
}

// RevokeHost revokes the active identity of host name in the database at dataDir (its client
// certificate stops working at once; its standing approvals and pending requests end too).
// For the bastion operator: `aqmasd revoke-host <name>`.
func RevokeHost(dataDir, name string, now time.Time) error {
	st, err := store.Open(DBPath(dataDir))
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	return st.Tx(ctx, func(q *store.Q) error {
		h, err := q.ActiveHostByName(ctx, name)
		if err != nil {
			return fmt.Errorf("no active host %q: %w", name, err)
		}
		if err := q.RevokeHost(ctx, h.ID, now); err != nil {
			return err
		}
		return q.Audit(ctx, now, "system", "host_revoke", "host:"+name, fmt.Sprintf("host_id=%d via aqmasd revoke-host", h.ID))
	})
}

func normalizeCode(c string) string {
	c = strings.ToUpper(c)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, c)
}
