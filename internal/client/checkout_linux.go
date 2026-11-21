package client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func verifyRAM(d *os.File) error {
	var st unix.Statfs_t
	if unix.Fstatfs(int(d.Fd()), &st) != nil || st.Type != unix.TMPFS_MAGIC {
		return errors.New("checkout filesystem is not verified tmpfs; use run")
	}
	return nil
}
func removeOurLink(dir *os.File, name, target string) error {
	fd := int(dir.Fd())
	var b [4096]byte
	n, err := unix.Readlinkat(fd, name, b[:])
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
		return nil
	}
	if err != nil || string(b[:n]) != target {
		return err
	}
	var id [16]byte
	rand.Read(id[:])
	hold := ".aqmas-clean-" + hex.EncodeToString(id[:])
	if err = unix.Renameat2(fd, name, fd, hold, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	n, err = unix.Readlinkat(fd, hold, b[:])
	if err == nil && string(b[:n]) == target {
		return unix.Unlinkat(fd, hold, 0)
	}
	if unix.Renameat2(fd, hold, fd, name, unix.RENAME_NOREPLACE) != nil {
		return errors.New("checkout link changed concurrently; inspect preserved .aqmas-clean entry")
	}
	return nil
}
