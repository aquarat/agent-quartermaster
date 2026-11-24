package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// Invoker is the user who ran `sudo aqmas upgrade`. A system-wide install (say
// /usr/local/bin/aqmas) can only be replaced by root, but the enrolment that proves who this
// host is belongs to that user. So the upgrade runs with the user's identity for everything
// (reading the enrolment with all its ownership checks, talking to the bastion and GitHub,
// reading a token file the configuration names) and takes root back only to replace the
// executable. Root therefore never trusts, reads on a user's say-so, writes or re-owns
// anything in the user's directories. Nothing but `upgrade` does this.
type Invoker struct {
	UID, GID  int
	Name      string // for messages; "uid N" when the account has no name here
	Home      string
	ConfigDir string
	CacheDir  string
}

// lookupHome finds a user's name and home directory by uid (a variable for tests).
var lookupHome = func(uid int) (name, home string, err error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", "", err
	}
	return u.Username, u.HomeDir, nil
}

func ownerUID(path string) (int, fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, nil, fmt.Errorf("%s: cannot read its owner", path)
	}
	return int(st.Uid), fi, nil
}

// RootPaths are root's own directories, from the account database and not from HOME: sudo
// keeps the invoking user's HOME on some systems (macOS, sudo -E, env_keep), and root's own
// enrolment is by definition not there.
func RootPaths() Paths {
	_, home, err := lookupHome(0)
	if err != nil || home == "" {
		home = "/root"
		if runtime.GOOS == "darwin" {
			home = "/var/root"
		}
	}
	return Paths{ConfigDir: filepath.Join(home, ".config", "aqmas"), CacheDir: filepath.Join(home, ".cache", "aqmas")}
}

// SudoInvoker resolves whose enrolment a root `aqmas upgrade` uses. inv is nil when the
// process is not root, was not started through sudo by another user, or that user has no
// enrolment. In that last case rootOwn is true: root's own configuration is used, as before,
// and the caller takes it from RootPaths. An enrolment directory that exists but is not
// owned by exactly the invoking user is an error, never a fallback.
func SudoInvoker(getenv func(string) string, euid int) (inv *Invoker, rootOwn bool, err error) {
	inv, err = sudoInvoker(getenv, euid)
	if errors.Is(err, errInvokerNotEnrolled) {
		return nil, true, nil
	}
	return inv, false, err
}

var errInvokerNotEnrolled = errors.New("the user who ran sudo has no enrolment")

func sudoInvoker(getenv func(string) string, euid int) (*Invoker, error) {
	if euid != 0 {
		return nil, nil
	}
	uid, err := strconv.Atoi(getenv("SUDO_UID"))
	if err != nil || uid <= 0 {
		return nil, nil // a root login, or sudo run by root itself
	}
	inv := &Invoker{UID: uid, Name: fmt.Sprintf("uid %d", uid)}
	if inv.GID, err = strconv.Atoi(getenv("SUDO_GID")); err != nil || inv.GID < 0 {
		return nil, errors.New("started through sudo (SUDO_UID is set) without a usable SUDO_GID; refusing to guess the invoking user's group")
	}
	name, home, err := lookupHome(uid)
	if err == nil && home != "" {
		inv.Name, inv.Home = name, home
	} else if h := getenv("HOME"); h != "" {
		// No account database entry to read (some systems keep users elsewhere): sudo's own
		// HOME is acceptable only when it is that user's directory.
		if owner, fi, e := ownerUID(h); e == nil && fi.IsDir() && owner == uid {
			inv.Home = h
		}
	}
	if u := getenv("SUDO_USER"); inv.Name == fmt.Sprintf("uid %d", uid) && u != "" {
		inv.Name = sanitize(u)
	}
	switch {
	case getenv("AQMAS_CONFIG_DIR") != "":
		inv.ConfigDir = getenv("AQMAS_CONFIG_DIR")
	case inv.Home == "":
		return nil, fmt.Errorf("cannot find the home directory of %s, who ran sudo; name the enrolment with: sudo AQMAS_CONFIG_DIR=/path/to/.config/aqmas aqmas upgrade", inv.Name)
	default:
		inv.ConfigDir = filepath.Join(inv.Home, ".config", "aqmas")
	}
	if inv.Home == "" {
		inv.Home = filepath.Dir(filepath.Dir(inv.ConfigDir))
	}
	if inv.CacheDir = getenv("AQMAS_CACHE_DIR"); inv.CacheDir == "" {
		inv.CacheDir = filepath.Join(inv.Home, ".cache", "aqmas")
	}
	owner, fi, err := ownerUID(inv.ConfigDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errInvokerNotEnrolled // root's own enrolment, if any
	case err != nil:
		return nil, err
	case fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir():
		return nil, fmt.Errorf("%s is not a directory; refusing to use it", inv.ConfigDir)
	case owner != uid:
		return nil, fmt.Errorf("%s is not owned by %s (uid %d), who ran sudo; refusing to use it", inv.ConfigDir, inv.Name, uid)
	}
	return inv, nil
}

// Paths are the invoking user's directories.
func (i *Invoker) Paths() Paths { return Paths{ConfigDir: i.ConfigDir, CacheDir: i.CacheDir} }

// Drop gives up root for the invoking user's identity (effective uid and gid, and no
// supplementary group of root's) and returns the function that takes root back. HOME follows,
// because paths in the configuration are written relative to it. From here every file check
// in this package ("owned by the current user", not writable by others) is made as that user.
func (i *Invoker) Drop() (elevate func() error, err error) {
	groups, err := syscall.Getgroups()
	if err != nil {
		return nil, err
	}
	egid, home := os.Getegid(), os.Getenv("HOME")
	if err = syscall.Setgroups([]int{i.GID}); err != nil {
		return nil, fmt.Errorf("dropping root's groups: %w", err)
	}
	if err = syscall.Setegid(i.GID); err != nil {
		return nil, fmt.Errorf("switching to group %d: %w", i.GID, err)
	}
	if err = syscall.Seteuid(i.UID); err != nil {
		return nil, fmt.Errorf("switching to %s: %w", i.Name, err)
	}
	if os.Geteuid() != i.UID || os.Getegid() != i.GID {
		return nil, errors.New("could not take the invoking user's identity")
	}
	_ = os.Setenv("HOME", i.Home)
	return func() error {
		if err := syscall.Seteuid(0); err != nil {
			return fmt.Errorf("taking root back for the installation: %w", err)
		}
		if err := syscall.Setegid(egid); err != nil {
			return err
		}
		if err := syscall.Setgroups(groups); err != nil {
			return err
		}
		if os.Geteuid() != 0 {
			return errors.New("could not take root back for the installation")
		}
		_ = os.Setenv("HOME", home)
		return nil
	}, nil
}
