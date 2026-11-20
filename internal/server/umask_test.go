//go:build unix

package server

import (
	"os"
	"syscall"
	"testing"
)

// TestMain pins a strict umask. t.TempDir creates its directories with mode 0777 masked by the
// process umask, and aqmasd (correctly) refuses a group/other-writable data dir. CI containers
// may run with umask 000, which made every server test fail there (first release run).
func TestMain(m *testing.M) {
	syscall.Umask(0o077)
	os.Exit(m.Run())
}
