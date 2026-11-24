package client

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// "not_admitted" arrives with status 404 (so older CLIs take their usual path); this CLI says
// what it means and does not mistake it for "no such target" or "feature not installed".
func TestNotAdmittedIsSaidPlainly(t *testing.T) {
	err := fmt.Errorf("resolving: %w", &APIError{HTTPStatus: 404, Code: api.ErrNotAdmitted, Message: "this host is enrolled but not admitted to an organisation yet"})
	if !NotAdmitted(err) || NotATarget(err) || plainNotFound(err) {
		t.Fatalf("classification: admitted=%v target=%v plain=%v", NotAdmitted(err), NotATarget(err), plainNotFound(err))
	}
	if msg := err.Error(); !strings.Contains(msg, "enrolled but not admitted") || !strings.Contains(msg, "Hosts page") || strings.Contains(msg, "server: ") {
		t.Fatalf("message: %s", msg)
	}
	plain := &APIError{HTTPStatus: 404, Code: api.ErrNotFound, Message: "not found"}
	if NotAdmitted(plain) || !NotATarget(plain) || !plainNotFound(plain) || plain.Error() != "server: not_found: not found" {
		t.Fatalf("a plain 404 changed: %s", plain.Error())
	}
}
