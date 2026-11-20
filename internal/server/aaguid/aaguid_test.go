package aaguid

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func mustUUID(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatalf("bad uuid %s", s)
	}
	return b
}

func TestLookup(t *testing.T) {
	for _, c := range []struct{ uuid, name, icon string }{
		{"fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "iCloud Keychain (Apple Passwords)", api.PasskeyIconApple},
		{"d548826e-79b4-db40-a3d8-11116f7e8349", "Bitwarden", api.PasskeyIconBitwarden},
		{"bada5566-a7aa-401f-bd96-45619a55120d", "1Password", api.PasskeyIconOnePassword},
		{"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", "Google Password Manager", api.PasskeyIconGoogle},
		{"adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac", api.PasskeyIconChrome},
		{"08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello", api.PasskeyIconWindows},
		{"53414d53-554e-4700-0000-000000000000", "Samsung Pass", api.PasskeyIconSamsung},
		{"cb69481e-8ff7-4039-93ec-0a2729a154a8", "YubiKey 5 Series", api.PasskeyIconYubiKey},
		{"a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa", "Security Key NFC by Yubico", api.PasskeyIconYubiKey},
		{"e77e3c64-05e3-428b-8824-0cbeb04b829d", "Security Key NFC by Yubico", api.PasskeyIconYubiKey},
		{"50726f74-6f6e-5061-7373-50726f746f6e", "Proton Pass", api.PasskeyIconManager},
	} {
		u, a := Lookup(mustUUID(t, c.uuid))
		if u != c.uuid || a.Name != c.name || a.Icon != c.icon {
			t.Errorf("%s: got %s %+v, want %s/%s", c.uuid, u, a, c.name, c.icon)
		}
	}
	for _, b := range [][]byte{nil, make([]byte, 16), {1, 2, 3}} {
		if u, a := Lookup(b); u != "" || a != Unknown {
			t.Errorf("%x: %q %+v", b, u, a)
		}
	}
	if u, a := Lookup(mustUUID(t, "00000000-0000-0000-0000-000000000001")); u != "00000000-0000-0000-0000-000000000001" || a != Unknown {
		t.Errorf("unlisted: %q %+v", u, a)
	}
	icons := map[string]bool{api.PasskeyIconApple: true, api.PasskeyIconBitwarden: true, api.PasskeyIconOnePassword: true,
		api.PasskeyIconGoogle: true, api.PasskeyIconChrome: true, api.PasskeyIconWindows: true, api.PasskeyIconMicrosoft: true,
		api.PasskeyIconSamsung: true, api.PasskeyIconYubiKey: true, api.PasskeyIconManager: true}
	for k, a := range table {
		if Format(mustUUID(t, k)) != k || a.Name == "" || !icons[a.Icon] {
			t.Errorf("table entry %s %+v", k, a)
		}
	}
}
