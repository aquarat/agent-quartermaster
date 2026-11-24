//go:build interop

package release

// Binaries of the interop suite (test/interop, built with -tags interop) talk to fake
// release sources on 127.0.0.1 over plain http. Release builds never carry this tag.
func init() { loopbackHTTP = true }
