// Package secretfile reads bounded service credentials through pinned path
// components. O_NONBLOCK prevents a substituted FIFO from hanging startup.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Read requires a single-link regular file owned by the service uid. A
// systemd credential may alternatively be root-owned. The file checked with
// fstat is the one read, even if its pathname is concurrently replaced.
func Read(path string, systemd bool, limit int64) ([]byte, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { unix.Close(fd) }()
	for _, dir := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, dir, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("credential directory: %w", err)
		}
		unix.Close(fd)
		fd = next
	}
	n, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("credential file: %w", err)
	}
	f := os.NewFile(uintptr(n), "credential")
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(n, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return nil, errors.New("credential must be a single-link regular file")
	}
	if int(st.Uid) != os.Geteuid() && !(systemd && st.Uid == 0) {
		return nil, errors.New("credential has wrong owner")
	}
	mode := st.Mode & 07777
	if mode != 0400 && mode != 0600 {
		return nil, fmt.Errorf("credential mode %04o: must be 0600 or 0400, not group/other accessible", mode)
	}
	if st.Size > limit {
		return nil, errors.New("credential too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("could not read bounded credential")
	}
	return b, nil
}
