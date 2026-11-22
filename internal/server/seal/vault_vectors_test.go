package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aquarat/agent-quartermaster/internal/envset"
)

// test/vectors/vault.json: "go_sealed" is written here (AQMAS_UPDATE_VECTORS=1)
// and opened by web/test/vault.test.ts; "browser_sealed" is written by
// web/test/fixtures/make-vault-packet.ts and opened here. "commitment" and
// test/vectors/dotenv.json pin the form's edit commitment and dotenv reader
// in both languages.
type vaultPacket struct {
	Purpose   string `json:"purpose"`
	Priv      string `json:"recipient_priv"`
	Pub       string `json:"recipient_pub"`
	Info      string `json:"info"`
	AAD       string `json:"aad"`
	Enc       string `json:"enc"`
	Ct        string `json:"ciphertext"`
	Plaintext string `json:"plaintext"`
}
type vaultVectors struct {
	Installation string       `json:"installation"`
	Epoch        string       `json:"epoch"`
	SetID        string       `json:"set_id"`
	AttemptID    string       `json:"attempt_id"`
	Canonical    string       `json:"canonical"`
	GoSealed     vaultPacket  `json:"go_sealed"`
	Browser      *vaultPacket `json:"browser_sealed,omitempty"`
	Commitment   struct {
		Org        string      `json:"org"`
		Service    string      `json:"service"`
		Set        string      `json:"set"`
		Revision   int         `json:"revision"`
		OldNames   []string    `json:"old_names"`
		Edit       envset.Edit `json:"edit"`
		Commitment string      `json:"commitment"`
		Changes    string      `json:"changes"`
	} `json:"commitment"`
}

const vaultVectorPath = "../../../test/vectors/vault.json"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestVaultTransportVectors(t *testing.T) {
	var v vaultVectors
	raw, err := os.ReadFile(vaultVectorPath)
	if err == nil {
		err = json.Unmarshal(raw, &v)
	}
	install, epoch, attempt := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	set := "0123456789abcdef0123456789abcdef"
	canonical := `{"action":"reveal","epoch":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","id":"0123456789abcdef0123456789abcdef","installation":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","issued_at":"2026-11-22T10:00:00Z","metadata":"{}","nonce":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ","object":"vault","v":3}`
	digest := sha256.Sum256([]byte(canonical))
	revealInfo, revealAAD := Tuple("hpke-vault", install, []byte("reveal")), Tuple("hpke-vault-aad", digest[:], epoch, []byte(set))
	editInfo, editAAD := Tuple("hpke-vault", install, []byte("edit")), Tuple("hpke-vault-aad", attempt, epoch, []byte(set))
	if os.Getenv("AQMAS_UPDATE_VECTORS") != "" {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		plain := `{"entries":[{"name":"APP_KEY","value":"-----BEGIN PRIVATE KEY-----\nline two\n-----END PRIVATE KEY-----\n"},{"name":"APP_TOKEN","value":"tøken \"quoted\" \\ $HOME"}]}`
		enc, ct, err := SealTo(k.PublicKey().Bytes(), revealInfo, revealAAD, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		v.Installation, v.Epoch, v.SetID, v.AttemptID, v.Canonical = hex.EncodeToString(install), hex.EncodeToString(epoch), set, hex.EncodeToString(attempt), canonical
		v.GoSealed = vaultPacket{"reveal", hex.EncodeToString(k.Bytes()), hex.EncodeToString(k.PublicKey().Bytes()), hex.EncodeToString(revealInfo), hex.EncodeToString(revealAAD), hex.EncodeToString(enc), hex.EncodeToString(ct), plain}
		c := &v.Commitment
		c.Org, c.Service, c.Set, c.Revision, c.OldNames = "11111111111111111111111111111111", "22222222222222222222222222222222", set, 7, []string{"APP_TOKEN", "DB_URL", "OLD_SECRET"}
		c.Edit = envset.Edit{Op: "merge", Salt: bytes.Repeat([]byte{9}, 32), Entries: []envset.Entry{{Name: "APP_TOKEN", Value: "new"}, {Name: "APP_KEY", Value: "a\nb\n"}}, Remove: []string{"OLD_SECRET"}}
		c.Commitment, _ = c.Edit.Commit(envset.Binding{Org: c.Org, Service: c.Service, Set: c.Set, Revision: c.Revision})
		c.Changes, _ = c.Edit.Changes(c.OldNames)
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vaultVectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if v.Canonical != canonical || v.GoSealed.Info != hex.EncodeToString(revealInfo) || v.GoSealed.AAD != hex.EncodeToString(revealAAD) {
		t.Fatal("reveal context encoding changed")
	}
	r, err := RecipientFromScalar(unhex(t, v.GoSealed.Priv))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := r.Open(revealInfo, revealAAD, unhex(t, v.GoSealed.Enc), unhex(t, v.GoSealed.Ct)); err != nil || string(b) != v.GoSealed.Plaintext {
		t.Fatal("go-sealed packet does not open", err)
	}
	// Any other purpose, canonical, epoch or set fails.
	for _, x := range [][2][]byte{{editInfo, revealAAD}, {revealInfo, editAAD}, {revealInfo, Tuple("hpke-vault-aad", digest[:], install, []byte(set))}, {revealInfo, Tuple("hpke-vault-aad", digest[:], epoch, []byte(set+"0"))}} {
		if _, err := r.Open(x[0], x[1], unhex(t, v.GoSealed.Enc), unhex(t, v.GoSealed.Ct)); err == nil {
			t.Fatal("packet opened in another context")
		}
	}
	c := v.Commitment
	if got, err := c.Edit.Commit(envset.Binding{Org: c.Org, Service: c.Service, Set: c.Set, Revision: c.Revision}); err != nil || got != c.Commitment {
		t.Fatal("commitment vector", err)
	}
	if got, err := c.Edit.Changes(c.OldNames); err != nil || got != c.Changes {
		t.Fatal("changes vector", err)
	}
	if v.Browser == nil {
		t.Fatal("browser_sealed vector missing: run bun web/test/fixtures/make-vault-packet.ts")
	}
	b := v.Browser
	if b.Purpose != "edit" || b.Info != hex.EncodeToString(editInfo) || b.AAD != hex.EncodeToString(editAAD) {
		t.Fatal("browser context encoding differs")
	}
	r, err = RecipientFromScalar(unhex(t, b.Priv))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := r.Open(editInfo, editAAD, unhex(t, b.Enc), unhex(t, b.Ct))
	if err != nil || string(plain) != b.Plaintext {
		t.Fatal("browser-sealed packet does not open", err)
	}
	var e envset.Edit
	if json.Unmarshal(plain, &e) != nil || e.Op != "merge" || len(e.Salt) != 32 {
		t.Fatal("browser edit does not parse as an edit")
	}
}

type dotenvCase struct {
	Name    string         `json:"name"`
	Input   string         `json:"input"`
	Entries []envset.Entry `json:"entries,omitempty"`
	Error   int            `json:"error_line,omitempty"`
}

func TestDotenvVectors(t *testing.T) {
	const path = "../../../test/vectors/dotenv.json"
	inputs := [][2]string{
		{"bare", "APP_URL=https://example.com/a?b=c&d\nAPP_ID=\n"},
		{"comments and blanks", "# first\n\nAPP_TOKEN=abc\n# APP_SECRET=no\n"},
		{"crlf", "APP_TOKEN=abc\r\nAPP_SECRET=def\r\n"},
		{"single quoted literal", "APP_SECRET='a \"b\" $HOME \\n #x'\n"},
		{"single quoted multi-line", "APP_KEY='-----BEGIN KEY-----\nAAAA\n-----END KEY-----'\nAPP_ID=1\n"},
		{"double quoted escapes", "APP_SECRET=\"tab\\there \\\"q\\\" back\\\\slash\\r\\n\"\n"},
		{"double quoted multi-line", "APP_KEY=\"-----BEGIN KEY-----\nAAAA\\nBBBB\n-----END KEY-----\n\"  \nAPP_ID=1"},
		{"dollar is literal inside quotes", "APP_SECRET=\"${HOME} $(id) `id`\"\n"},
		{"unicode", "APP_SECRET='pässwörd ✓'\n"},
		{"no newline at end", "APP_TOKEN=abc"},
		{"bad: unsafe name", "PATH=/tmp\n"},
		{"bad: lower-case name", "APP_TOKEN=a\napp_secret=b\n"},
		{"bad: bare dollar", "APP_TOKEN=a\nAPP_SECRET=$HOME\n"},
		{"bad: bare inline comment", "APP_TOKEN=a #x\n"},
		{"bad: bare leading space", "APP_TOKEN= a\n"},
		{"bad: unknown escape", "APP_TOKEN=a\nAPP_ID=1\nAPP_SECRET=\"a\\x\"\n"},
		{"bad: escape on a later line", "APP_SECRET=\"a\nb\\q\"\n"},
		{"bad: text after quote", "APP_SECRET='a' b\n"},
		{"bad: unterminated", "APP_TOKEN=a\nAPP_SECRET='abc\nAPP_ID=1\n"},
		{"bad: duplicate", "APP_TOKEN=a\nAPP_TOKEN=b\n"},
		{"bad: export prefix", "export APP_TOKEN=a\n"},
		{"bad: no equals", "APP_TOKEN\n"},
	}
	var want []dotenvCase
	if os.Getenv("AQMAS_UPDATE_VECTORS") != "" {
		for _, in := range inputs {
			c := dotenvCase{Name: in[0], Input: in[1]}
			entries, err := envset.ParseFile([]byte(in[1]))
			if err != nil {
				var line int
				if _, e := sscanLine(err.Error(), &line); e != nil {
					line = -1 // rejected as a whole (duplicate, limits)
				}
				c.Error = line
			} else {
				c.Entries = entries
			}
			want = append(want, c)
		}
		out, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &want) != nil || len(want) != len(inputs) {
		t.Fatal("dotenv vectors missing or stale", err)
	}
	for i, c := range want {
		if c.Input != inputs[i][1] {
			t.Fatalf("%s: stale vector", c.Name)
		}
		entries, err := envset.ParseFile([]byte(c.Input))
		if (err != nil) != (c.Error != 0) || (c.Name[:3] == "bad") != (err != nil) {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if err != nil {
			var line int
			if _, e := sscanLine(err.Error(), &line); e == nil && line != c.Error {
				t.Fatalf("%s: line %d, want %d", c.Name, line, c.Error)
			}
			continue
		}
		a, _ := json.Marshal(entries)
		b, _ := json.Marshal(c.Entries)
		if string(a) != string(b) {
			t.Fatalf("%s: %s", c.Name, a)
		}
	}
}

func sscanLine(msg string, line *int) (int, error) {
	return fmt.Sscanf(msg, "unsupported literal assignment on line %d", line)
}
