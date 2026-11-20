package cfproxy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// RedactedMarker replaces secret values in responses (docs/CLOUDFLARE.md 3.3). A write whose
// body contains it is refused: writing a redacted object back would destroy the secret.
const RedactedMarker = "[redacted by aqmas]"

// maxRedactBytes caps JSON responses aqmasd rewrites (larger JSON answers 502).
const maxRedactBytes = 32 << 20

var secretKeys = map[string]bool{
	"secret": true, "client_secret": true, "tunnel_secret": true, "token": true,
	"private_key": true, "password": true, "credentials_file": true,
}

// decodeJSON parses JSON keeping numbers exact.
func decodeJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errTrailing
	}
	return v, nil
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errTrailing = constErr("trailing data after JSON value")

func encodeJSON(v any) []byte {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// redactValue rewrites secrets in place and returns how many values it replaced.
func redactValue(v any) int {
	n := 0
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(k)
			if secretKeys[lk] {
				if s, ok := val.(string); ok && s != "" && s != RedactedMarker {
					x[k] = RedactedMarker
					n++
					continue
				}
			}
			if lk == "env_vars" {
				n += redactEnvVars(val)
			}
			n += redactValue(x[k])
		}
	case []any:
		for _, e := range x {
			n += redactValue(e)
		}
	}
	return n
}

// redactEnvVars: Pages env_vars {"NAME": {"type": "secret_text", "value": "..."}} (an
// object or an array of such objects): every value whose type is not plain_text.
func redactEnvVars(v any) int {
	n := 0
	one := func(e any) {
		o, ok := e.(map[string]any)
		if !ok {
			return
		}
		if t, _ := o["type"].(string); t == "plain_text" {
			return
		}
		if val, ok := o["value"]; ok && val != nil && val != RedactedMarker {
			if s, isStr := val.(string); isStr && s == "" {
				return
			}
			o["value"] = RedactedMarker
			n++
		}
	}
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			one(e)
		}
	case []any:
		for _, e := range x {
			one(e)
		}
	}
	return n
}

// redactJSON redacts a JSON document; it returns the original bytes when nothing changed.
func redactJSON(b []byte) ([]byte, int, error) {
	v, err := decodeJSON(b)
	if err != nil {
		return nil, 0, err
	}
	n := redactValue(v)
	if n == 0 {
		return b, 0, nil
	}
	return encodeJSON(v), n, nil
}

// containsMarker reports whether a write body carries the redaction marker, also when it
// is hidden in a JSON string escape.
func containsMarker(body []byte, parsed any) bool {
	if bytes.Contains(body, []byte(RedactedMarker)) {
		return true
	}
	if parsed == nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case string:
			return strings.Contains(x, RedactedMarker)
		case map[string]any:
			for k, e := range x {
				if strings.Contains(k, RedactedMarker) || walk(e) {
					return true
				}
			}
		case []any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(parsed)
}

// markerScanner wraps a streamed upload body: it fails the read as soon as the marker
// appears (the upstream request is then aborted before it completes) and caps the size.
type markerScanner struct {
	r        interface{ Read([]byte) (int, error) }
	limit    int64
	n        int64
	tail     []byte
	found    bool
	tooLarge bool
}

const (
	errMarker   = constErr("upload contains the redaction marker")
	errTooLarge = constErr("upload too large")
)

func (m *markerScanner) Read(p []byte) (int, error) {
	if m.found {
		return 0, errMarker
	}
	if m.tooLarge {
		return 0, errTooLarge
	}
	n, err := m.r.Read(p)
	if n > 0 {
		m.n += int64(n)
		if m.n > m.limit {
			m.tooLarge = true
			return 0, errTooLarge
		}
		buf := append(m.tail, p[:n]...)
		if bytes.Contains(buf, []byte(RedactedMarker)) {
			m.found = true
			return 0, errMarker
		}
		keep := len(RedactedMarker) - 1
		if len(buf) > keep {
			buf = buf[len(buf)-keep:]
		}
		m.tail = append(m.tail[:0], buf...)
	}
	return n, err
}
