package cfproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquarat/agent-quartermaster/internal/api"
	"github.com/aquarat/agent-quartermaster/internal/server/ids"
)

func (h *harness) snapList(q string) (int, api.CFSnapshotList) {
	req := httptest.NewRequest("GET", "/v1/cf/snapshots"+q, nil)
	rec := httptest.NewRecorder()
	h.p.ServeSnapshotList(rec, req, h.caller)
	var l api.CFSnapshotList
	_ = json.Unmarshal(rec.Body.Bytes(), &l)
	return rec.Code, l
}

func (h *harness) snapGet(id string) (int, api.CFSnapshot) {
	req := httptest.NewRequest("GET", "/v1/cf/snapshots/"+id, nil)
	rec := httptest.NewRecorder()
	h.p.ServeSnapshotGet(rec, req, h.caller, id)
	var s api.CFSnapshot
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	return rec.Code, s
}

func TestSnapshotEndpointsAndPrune(t *testing.T) {
	h := newHarness(t)
	h.grant("D", api.CFScopeDNSEdit, map[string]string{"zone": "example.com"})
	recs := "/zones/" + zoneA + "/dns_records"
	h.cf.result("GET "+recs+"/a1", map[string]any{"id": "a1", "name": "www.example.com", "type": "A", "content": "203.0.113.1"})
	h.cf.result("GET "+recs+"/a2", map[string]any{"id": "a2", "name": "w2.example.com", "type": "A", "content": "203.0.113.2"})
	// Day 1: two writes of a1; day 9: one write of a2.
	h.now = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	r1 := h.call("PUT", recs+"/a1", map[string]any{"name": "www", "type": "A", "content": "203.0.113.3"}, g("D"))
	h.now = h.now.Add(time.Hour)
	r2 := h.call("PUT", recs+"/a1", map[string]any{"name": "www", "type": "A", "content": "203.0.113.4"}, g("D"))
	h.now = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	r3 := h.call("PUT", recs+"/a2", map[string]any{"name": "w2", "type": "A", "content": "203.0.113.5"}, g("D"))
	for _, r := range []res{r1, r2, r3} {
		expect(t, r, 200, "")
	}

	code, l := h.snapList("")
	if code != 200 || len(l.Snapshots) != 6 || l.Snapshots[0].ObjectKey != "dns-record:"+zoneA+":a2" || l.Snapshots[0].Content != nil {
		t.Fatalf("list %d %+v", code, l)
	}
	if _, l = h.snapList("?object=dns-record:" + zoneA + ":a1&limit=3"); len(l.Snapshots) != 3 {
		t.Fatalf("filter %d", len(l.Snapshots))
	}
	if _, l = h.snapList("?type=tunnel-config"); len(l.Snapshots) != 0 {
		t.Fatal("type filter")
	}
	if c, _ := h.snapList("?limit=x"); c != 400 {
		t.Fatal("bad limit")
	}
	code, s := h.snapGet(r1.Header().Get(api.CFSnapshotBeforeHeader))
	if code != 200 || !strings.Contains(string(s.Content), "203.0.113.1") || s.SHA256 == "" || s.Size != len(s.Content) {
		t.Fatalf("get %d %+v", code, s)
	}
	if c, _ := h.snapGet("../../etc/passwd"); c != 404 {
		t.Fatal("path id")
	}
	if c, _ := h.snapGet(ids.New()); c != 404 {
		t.Fatal("unknown id")
	}
	// No active grant: 403.
	h.grants.active = false
	if c, _ := h.snapList(""); c != 403 {
		t.Fatal("list without grant")
	}
	if c, _ := h.snapGet(r1.Header().Get(api.CFSnapshotBeforeHeader)); c != 403 {
		t.Fatal("get without grant")
	}
	h.grants.active = true

	// Prune on day 10 (7 days): day-1 snapshots go except the newest of a1 (r2's after).
	if err := h.p.Prune(context.Background(), time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	_, l = h.snapList("")
	var kept []string
	for _, s := range l.Snapshots {
		kept = append(kept, s.ID)
	}
	want := []string{r3.Header().Get(api.CFSnapshotAfterHeader), r3.Header().Get(api.CFSnapshotBeforeHeader), r2.Header().Get(api.CFSnapshotAfterHeader)}
	if strings.Join(kept, ",") != strings.Join(want, ",") {
		t.Fatalf("kept %v want %v", kept, want)
	}
}

func TestMarkerScannerBoundaries(t *testing.T) {
	data := []byte(strings.Repeat("a", 1000) + RedactedMarker + "zz")
	for _, chunk := range []int{1, 3, 7, 19, 1000, 5000} {
		m := &markerScanner{r: &chunkReader{b: data, n: chunk}, limit: 1 << 20}
		_, err := io.Copy(io.Discard, m)
		if err != errMarker || !m.found {
			t.Fatalf("chunk %d: %v", chunk, err)
		}
	}
	m := &markerScanner{r: bytes.NewReader(bytes.Repeat([]byte("b"), 100)), limit: 50}
	if _, err := io.Copy(io.Discard, m); err != errTooLarge {
		t.Fatalf("limit: %v", err)
	}
	m = &markerScanner{r: bytes.NewReader([]byte("[redacted by aqma")), limit: 50}
	if _, err := io.Copy(io.Discard, m); err != nil {
		t.Fatalf("partial marker: %v", err)
	}
}

type chunkReader struct {
	b []byte
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	n := min(c.n, len(p), len(c.b))
	copy(p, c.b[:n])
	c.b = c.b[n:]
	return n, nil
}

func TestHelpers(t *testing.T) {
	for _, c := range []struct {
		glob, name string
		ok         bool
	}{
		{"*.dev.example.com", "a.dev.example.com", true},
		{"*.dev.example.com", "a.b.dev.example.com", true},
		{"*.dev.example.com", "dev.example.com", false},
		{"*.dev.example.com", "xdev.example.com", false},
		{"www.example.com", "WWW.example.com", true},
		{"www.example.com", "a.www.example.com", false},
	} {
		if nameGlobMatch(c.glob, c.name) != c.ok {
			t.Errorf("glob %s %s", c.glob, c.name)
		}
	}
	for _, c := range []struct {
		pat, host string
		ok        bool
	}{
		{"*.example.com", "id.example.com", true},
		{"*.com", "id.example.com", true},
		{"*", "id.example.com", true},
		{"example.com", "id.example.com", false},
		{"*.example.org", "id.example.com", false},
		{"id.example.com.evil", "id.example.com", false},
	} {
		if coversHost(c.pat, c.host) != c.ok {
			t.Errorf("covers %s %s", c.pat, c.host)
		}
	}
	if _, ok := hostOf("id.example.com@evil"); ok {
		t.Error("user info")
	}
	if h, ok := hostOf("HTTPS://Id.Example.com.:8443/a?b"); !ok || h != "id.example.com" {
		t.Errorf("hostOf %q", h)
	}
	l := newLimiter()
	now := time.Now()
	for i := 0; i < 2; i++ {
		if ok, _ := l.take(1, false, 2, now); !ok {
			t.Fatal("limiter")
		}
	}
	if ok, wait := l.take(1, false, 2, now); ok || wait != 30 {
		t.Fatalf("limiter wait %d", wait)
	}
	if fqdn("@", "example.com") != "example.com" || fqdn("www", "example.com") != "www.example.com" || fqdn("WWW.example.com.", "example.com") != "www.example.com" {
		t.Error("fqdn")
	}
}

func TestUpstreamURLByteForByte(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/zones/x", "/a/b%252Fc/d", "/a/caf%C3%A9", "/a/(x)!*'$&+,=:@~"} {
		u, err := h.p.upstreamURL(p, "a=1")
		if err != nil || u.EscapedPath() != "/client/v4"+p || u.RawQuery != "a=1" {
			t.Errorf("%s: %v %v", p, u, err)
		}
	}
	_ = http.MethodGet
}
