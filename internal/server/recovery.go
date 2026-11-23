package server

import (
	"context"
	"errors"
	"io"
)

// Recover is `aqmasd seal-recover DIRECTORY <identity.txt` (docs/BUCKETS.md
// §10): in isolated maintenance it opens every scope key from its recovery
// wrap, registers a replacement passkey, wraps every scope key for it and
// retires the old passkeys.
//
// STAGE-AGENT: the format-1 implementation (one MK received over a pipe) was
// removed with the MK; rebuild it on scope recovery wraps.
func (s *Server) Recover(ctx context.Context, dir string, input io.Reader) error {
	if !s.recovery || s.seal == nil {
		return errors.New("isolated sealed maintenance required")
	}
	return errStage("seal-recover")
}
