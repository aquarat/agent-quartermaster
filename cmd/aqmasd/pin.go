package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// The system unit supplies an immutable argument requiring this check. The
// entire path, not just the leaf config, must be controlled by root.
func rootPin(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("root config needs a clean absolute path")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || p == path && !st.Mode().IsRegular() || p != path && !st.IsDir() {
			return errors.New("config or ancestor not protected by root")
		}
		if p == "/" {
			return nil
		}
	}
}
