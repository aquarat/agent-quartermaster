package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquarat/agent-quartermaster/internal/envset"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

var safeLeaf = regexp.MustCompile(`^[.A-Za-z0-9_-]{1,128}$`)

func validLeaf(n string) bool { return safeLeaf.MatchString(n) && n != "." && n != ".." }

// Walk the entire path on pinned descriptors. Shared sticky root-owned
// intermediate directories are permitted; the final directory is ours.
func trustedDir(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("use a clean absolute trusted directory")
	}
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(path[1:], "/")
	for i, p := range parts {
		n, err := unix.Openat(fd, p, dirFlags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = n
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return nil, err
		}
		final := i == len(parts)-1
		uid := int(st.Uid)
		if uid != os.Geteuid() && (uid != 0 || final) || st.Mode&0022 != 0 && (final || uid != 0 || st.Mode&unix.S_ISVTX == 0) || final && private && st.Mode&0077 != 0 {
			unix.Close(fd)
			return nil, errors.New("unsafe directory ownership or mode")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func unlinkAt(d *os.File, name string) error { return unix.Unlinkat(int(d.Fd()), name, 0) }
func writeNewAt(d *os.File, name string, b []byte) error {
	if !validLeaf(name) {
		return errors.New("invalid checkout file name")
	}
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	_, err = f.Write(b)
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = unlinkAt(d, name)
	}
	return err
}
func readRecord(d *os.File, name string) (r checkoutRecord, err error) {
	if !validLeaf(name) {
		return r, errors.New("invalid checkout index")
	}
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return r, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return r, errors.New("unsafe checkout index")
	}
	b, err := bounded(f, 16384)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil || !safeID(r.Grant) || !envset.ValidPath(r.Path) {
		return r, errors.New("invalid checkout index")
	}
	return r, nil
}
func ramRoot() (*os.File, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	dir, err := trustedDir(base, true)
	if err != nil {
		return nil, errors.New("checkout needs a verified private RAM-backed XDG_RUNTIME_DIR; use run")
	}
	defer dir.Close()
	if err = verifyRAM(dir); err != nil {
		return nil, err
	}
	fd := int(dir.Fd())
	if err = unix.Mkdirat(fd, "aqmas-env", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	root, err := trustedDir(filepath.Join(base, "aqmas-env"), true)
	if err != nil {
		return nil, err
	}
	if err = verifyRAM(root); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}
func filePreflight(name string) error {
	if !validLeaf(name) {
		return errors.New("--file must be a plain basename in the trusted working directory")
	}
	root, err := ramRoot()
	if err != nil {
		return err
	}
	root.Close()
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	dir, err := trustedDir(cwd, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("checkout path already exists or is inaccessible")
	}
	return nil
}
func lockedDir(d *os.File) error { return unix.Flock(int(d.Fd()), unix.LOCK_EX) }
func (e *Env) fileCheckout(slot, name string, r checkoutRecord, values []envset.Entry) error {
	b, err := envset.FileBytes(values)
	if err != nil {
		return err
	}
	defer clear(b)
	root, err := ramRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = lockedDir(root); err != nil {
		return err
	}
	r.CWD, err = os.Getwd()
	if err != nil {
		return err
	}
	wd, err := trustedDir(r.CWD, false)
	if err != nil {
		return err
	}
	defer wd.Close()
	var ws unix.Stat_t
	if err = unix.Fstat(int(wd.Fd()), &ws); err != nil {
		return err
	}
	r.Dev, r.Ino = uint64(ws.Dev), uint64(ws.Ino)
	r.Link = name
	var id [16]byte
	rand.Read(id[:])
	r.Base = "grant-" + hex.EncodeToString(id[:])
	if err = writeNewAt(root, slot, mustMetadata(r)); err != nil {
		return fmt.Errorf("checkout already present or index unavailable: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = cleanupFile(root, slot, r)
		}
	}()
	if err = unix.Mkdirat(int(root.Fd()), r.Base, 0700); err != nil {
		return err
	}
	gfd, err := unix.Openat(int(root.Fd()), r.Base, dirFlags, 0)
	if err != nil {
		return err
	}
	gd := os.NewFile(uintptr(gfd), r.Base)
	defer gd.Close()
	if err = verifyRAM(gd); err != nil {
		return err
	}
	if err = unix.Flock(gfd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	if err = writeNewAt(gd, "values", b); err != nil {
		return err
	}
	if err = unix.Symlinkat(filepath.Join(root.Name(), r.Base, "values"), int(wd.Fd()), name); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "_env-holder", slot, r.Grant)
	cmd.ExtraFiles = []*os.File{gd}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	ok = true
	e.logf("checked out %s to %s until %s", r.Path, name, time.UnixMilli(r.Until).UTC().Format(time.RFC3339))
	return nil
}
func validRecord(r checkoutRecord) bool {
	return r.Mode == "file" && validLeaf(r.Link) && len(r.Base) == 38 && strings.HasPrefix(r.Base, "grant-") && validLeaf(r.Base) && envset.ValidPath(r.Path) && safeID(r.Grant)
}

// Remove plaintext first. A replacement file/link is never followed. Move
// the directory entry aside without replacement to check the exact inode
// being removed, rather than checking and then unlinking a mutable name.
func cleanupFile(root *os.File, slot string, r checkoutRecord) error {
	if !validRecord(r) {
		return errors.New("invalid file checkout record")
	}
	fd, err := unix.Openat(int(root.Fd()), r.Base, dirFlags, 0)
	if err == nil {
		err = unix.Unlinkat(fd, "values", 0)
		unix.Close(fd)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		err = unix.Unlinkat(int(root.Fd()), r.Base, unix.AT_REMOVEDIR)
	}
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if wd, err := trustedDir(r.CWD, false); err == nil {
		defer wd.Close()
		var st unix.Stat_t
		if unix.Fstat(int(wd.Fd()), &st) == nil && uint64(st.Dev) == r.Dev && uint64(st.Ino) == r.Ino {
			if err = removeOurLink(wd, r.Link, filepath.Join(root.Name(), r.Base, "values")); err != nil {
				return err
			}
		}
	}
	return unlinkAt(root, slot)
}
func (e *Env) fileCheckin(slot, path string) (r checkoutRecord, err error) {
	root, err := ramRoot()
	if err != nil {
		return r, err
	}
	defer root.Close()
	if err = lockedDir(root); err != nil {
		return r, err
	}
	r, err = readRecord(root, slot)
	if err != nil || r.Path != path || r.Mode != "file" {
		return r, errors.New("no matching file checkout")
	}
	return r, cleanupFile(root, slot, r)
}
func (e *Env) HoldEnv(ctx context.Context, slot, grant string) error {
	if !validLeaf(slot) || !strings.HasPrefix(slot, "env-") || !safeID(grant) {
		return errors.New("invalid holder invocation")
	}
	held := os.NewFile(3, "grant-dir")
	if held == nil {
		return errors.New("missing holder descriptor")
	}
	defer held.Close()
	root, err := ramRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	r, err := readRecord(root, slot)
	if err != nil || r.Grant != grant || !validRecord(r) {
		return errors.New("missing matching checkout")
	}
	var actual, want unix.Stat_t
	if unix.Fstat(3, &actual) != nil || unix.Fstatat(int(root.Fd()), r.Base, &want, unix.AT_SYMLINK_NOFOLLOW) != nil || actual.Dev != want.Dev || actual.Ino != want.Ino {
		return errors.New("invalid holder directory")
	}
	defer func() {
		if lockedDir(root) == nil {
			if live, err := readRecord(root, slot); err == nil && live.Grant == grant {
				_ = cleanupFile(root, slot, live)
			}
		}
	}()
	_, c, err := e.authedClient()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Until(time.UnixMilli(r.Until)))
	for {
		if time.Until(deadline) <= 0 {
			break
		}
		poll, cancel := context.WithTimeout(ctx, min(time.Until(deadline), 3*time.Second))
		var status envset.Release
		err = c.do(poll, "GET", "/v2/env/grants/"+grant, nil, &status)
		cancel()
		if err != nil || status.Status != "approved" || status.Grant != grant || status.Mode != "file" || status.Path != r.Path {
			break
		}
		if err = sleepCtx(ctx, min(time.Second, time.Until(deadline))); err != nil {
			break
		}
	}
	end, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.do(end, "POST", "/v2/env/grants/"+grant+"/checkin", nil, nil)
	return nil
}

// Reap only indices on the verified private RAM mount whose holder has lost
// its directory lease. No process IDs or persisted bearer values are trusted.
func ReapEnv() error {
	root, err := ramRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = lockedDir(root); err != nil {
		return err
	}
	names, err := root.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, slot := range names {
		if !strings.HasPrefix(slot, "env-") {
			continue
		}
		r, err := readRecord(root, slot)
		if err != nil || !validRecord(r) {
			continue
		}
		fd, err := unix.Openat(int(root.Fd()), r.Base, dirFlags, 0)
		if err == nil {
			err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
			unix.Close(fd)
			if err != nil {
				continue
			}
		} else if !errors.Is(err, unix.ENOENT) {
			continue
		}
		if err = cleanupFile(root, slot, r); err != nil {
			return err
		}
	}
	return nil
}
