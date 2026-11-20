// Package aaguid maps a passkey's AAGUID (the authenticator model id in the registration's
// authenticator data) to a friendly name and an icon key for the web UI.
//
// The table (table.go) is generated from the community list
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids: all of aaguid.json plus
// the Yubico entries of combined_aaguid.json. To regenerate, fetch both files and run:
//
//	{ jq -r 'to_entries[] | "\(.key)\t\(.value.name)"' aaguid.json
//	  jq -r 'to_entries[] | select(.value.name|test("yubi";"i")) | "\(.key)\t\(.value.name)"' combined_aaguid.json
//	} | sort -u -t$'\t' -k1,1
//
// and format the lines as table.go does (icon from the name: Apple/iCloud, Bitwarden,
// 1Password, Google, Chrome/Chromium, Windows Hello, Edge/Microsoft, Samsung, Yubi*, else
// "manager").
//
// The AAGUID is display only: with "none" attestation the authenticator's claim is not
// verified, and some clients report all zeros (shown as unknown).
package aaguid

import (
	"encoding/hex"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

// Authenticator is a friendly name plus an api.PasskeyIcon* key.
type Authenticator struct {
	Name string
	Icon string
}

// Unknown is returned for an absent, all-zero or unlisted AAGUID.
var Unknown = Authenticator{Name: "Unknown authenticator", Icon: api.PasskeyIconUnknown}

// Format returns the AAGUID as a lower-case UUID string, or "" when it is absent, not 16
// bytes, or all zeros.
func Format(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Lookup returns the UUID string (see Format) and the authenticator for an AAGUID.
func Lookup(b []byte) (string, Authenticator) {
	u := Format(b)
	if a, ok := table[u]; ok && u != "" {
		return u, a
	}
	return u, Unknown
}
