//go:build !linux

package client

import (
	"errors"
	"os"
)

func verifyRAM(*os.File) error {
	return errors.New("cannot verify a private RAM disk on this platform; use aqmas run")
}
func removeOurLink(*os.File, string, string) error {
	return errors.New("file checkout unsupported; use run")
}
