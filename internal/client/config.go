// Package client implements the aqmas CLI: host enrollment, SSH certificate requests against
// aqmasd's agent API (docs/API.md sections 1 and 3), the local certificate cache and the ssh
// argv builder.
package client

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultServer is the bastion's agent API.
const DefaultServer = "https://192.0.2.60:8443"

// DefaultTTL is used when neither --ttl nor default_ttl is given.
const DefaultTTL = 30 * time.Minute

// MaxTTL is the M1 policy maximum; the server clamps too, this only catches typos early.
const MaxTTL = 8 * time.Hour

// Config is ~/.config/aqmas/config.toml.
type Config struct {
	// Server is the agent API base URL.
	Server string `toml:"server"`
	// ServerCA is a PEM file holding the pinned server CA certificate (written by enroll).
	ServerCA string `toml:"server_ca,omitempty"`
	// ServerCASHA256 is "sha256:<hex>" of the pinned server CA certificate (DER). When both
	// are set, the PEM must match the fingerprint.
	ServerCASHA256 string `toml:"server_ca_sha256,omitempty"`
	// HostName is the name this host enrolled as (the client certificate's CommonName).
	HostName   string `toml:"host_name,omitempty"`
	ClientCert string `toml:"client_cert,omitempty"`
	ClientKey  string `toml:"client_key,omitempty"`
	ClientCA   string `toml:"client_ca,omitempty"`
	// DefaultTTL is a Go duration ("30m").
	DefaultTTL string `toml:"default_ttl,omitempty"`
}

// Paths locates the aqmas config and cache directories.
type Paths struct {
	ConfigDir string // ~/.config/aqmas
	CacheDir  string // $XDG_RUNTIME_DIR/aqmas or ~/.cache/aqmas
}

// DefaultPaths follows docs/API.md section 3. AQMAS_CONFIG_DIR and AQMAS_CACHE_DIR override.
func DefaultPaths(getenv func(string) string) (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	p := Paths{}
	switch {
	case getenv("AQMAS_CONFIG_DIR") != "":
		p.ConfigDir = getenv("AQMAS_CONFIG_DIR")
	case getenv("XDG_CONFIG_HOME") != "":
		p.ConfigDir = filepath.Join(getenv("XDG_CONFIG_HOME"), "aqmas")
	default:
		p.ConfigDir = filepath.Join(home, ".config", "aqmas")
	}
	switch {
	case getenv("AQMAS_CACHE_DIR") != "":
		p.CacheDir = getenv("AQMAS_CACHE_DIR")
	case getenv("XDG_RUNTIME_DIR") != "" && isPrivateDir(getenv("XDG_RUNTIME_DIR")):
		p.CacheDir = filepath.Join(getenv("XDG_RUNTIME_DIR"), "aqmas")
	default:
		p.CacheDir = filepath.Join(home, ".cache", "aqmas")
	}
	return p, nil
}

func isPrivateDir(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	return ownedByMe(fi) && fi.Mode().Perm()&0o077 == 0
}

// ConfigFile is the config path.
func (p Paths) ConfigFile() string { return filepath.Join(p.ConfigDir, "config.toml") }

// ErrNotEnrolled means there is no usable config yet.
var ErrNotEnrolled = errors.New("this host is not enrolled: run `aqmas enroll --name <host>` first")

// LoadConfig reads and checks the config. A missing file yields ErrNotEnrolled.
func LoadConfig(p Paths) (*Config, error) {
	if err := checkPrivatePath(p.ConfigDir, true); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}
	if err := checkPrivatePath(p.ConfigFile(), false); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}
	data, err := os.ReadFile(p.ConfigFile())
	if err != nil {
		return nil, err
	}
	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.ConfigFile(), err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", p.ConfigFile(), und)
	}
	if c.Server == "" {
		c.Server = DefaultServer
	}
	return &c, nil
}

// TTL returns the configured default TTL.
func (c *Config) TTL() (time.Duration, error) {
	if c == nil || c.DefaultTTL == "" {
		return DefaultTTL, nil
	}
	d, err := time.ParseDuration(c.DefaultTTL)
	if err != nil {
		return 0, fmt.Errorf("default_ttl: %w", err)
	}
	return d, nil
}

// SaveConfig writes the config atomically with mode 0600 in a 0700 directory.
func SaveConfig(p Paths, c *Config) error {
	if err := ensurePrivateDir(p.ConfigDir); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# aqmas client config, written by `aqmas enroll`. Mode 0600.\n")
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return writeFileAtomic(p.ConfigFile(), buf.Bytes(), 0o600)
}

// ensurePrivateDir creates dir (0700) or checks an existing one is ours and not group/world
// accessible; a too-open mode on our own directory is tightened.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if !ownedByMe(fi) {
		return fmt.Errorf("%s is not owned by the current user; refusing to use it", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// checkPrivatePath refuses paths that someone else owns or can write: the config decides which
// server and CA are trusted, so a writable config is as bad as no pinning at all.
func checkPrivatePath(path string, wantDir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it", path)
	}
	if wantDir != fi.IsDir() {
		return fmt.Errorf("%s: unexpected file type", path)
	}
	if !ownedByMe(fi) {
		return fmt.Errorf("%s is not owned by the current user; refusing to use it", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable (mode %04o); fix with chmod go-w", path, fi.Mode().Perm())
	}
	return nil
}

// checkSecretFile additionally refuses group/world-readable secrets (like ssh does for keys).
func checkSecretFile(path string) error {
	if err := checkPrivatePath(path, false); err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; private keys must be 0600 (chmod 600 %s)", path, fi.Mode().Perm(), path)
	}
	return nil
}

func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return int(st.Uid) == os.Getuid()
}

// writeFileAtomic writes data to a temp file in the same directory, fsyncs and renames it.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
