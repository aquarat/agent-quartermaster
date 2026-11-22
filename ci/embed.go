// Package ci exposes the pinned toolchain installer to the maintenance runner.
package ci

import _ "embed"

// Toolchains installs the pinned Go and Bun under a new directory, checking pinned digests.
//
//go:embed toolchains.sh
var Toolchains string

// GoVersion and BunVersion are what toolchains.sh installs (and `make pins` requires).
const (
	GoVersion  = "go1.27.4"
	BunVersion = "1.4.4"
)
