//go:build linux

package main

import "golang.org/x/sys/unix"

func restrictDumps() error {
	// Also applies outside systemd. RLIMIT_CORE alone doesn't stop a piped
	// core_pattern handler; PR_SET_DUMPABLE protects against that as well.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
