//go:build !linux

package main

import "errors"

func restrictDumps() error { return errors.New("aqmasd: protected service requires Linux") }
