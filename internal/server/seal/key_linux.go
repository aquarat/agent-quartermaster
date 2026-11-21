//go:build linux

package seal

import (
	"os"

	"golang.org/x/sys/unix"
)

// Dedicated pages: locking an ordinary Go slice could lock and later unlock
// unrelated heap objects. Never populate the page before both calls succeed.
func keyPage() ([]byte, error) {
	p, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	if err = unix.Madvise(p, unix.MADV_DONTDUMP); err == nil {
		err = unix.Mlock(p)
	}
	if err != nil {
		_ = unix.Munmap(p)
		return nil, err
	}
	return p, nil
}

func freePage(p []byte) {
	clear(p)
	if err := unix.Munmap(p); err != nil {
		panic("seal: munmap failed")
	}
}
