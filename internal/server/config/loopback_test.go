package config

import "github.com/aquarat/agent-quartermaster/internal/release"

// The fake release sources and git remotes of these tests listen on 127.0.0.1 without TLS.
func init() { release.EnableLoopbackHTTPForTests() }
