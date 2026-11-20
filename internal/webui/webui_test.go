package webui

import (
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler()
	for path, want := range map[string]int{"/": 200, "/requests/01ABC": 200, "/missing.js": 404, "/../../etc/passwd": 200} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Errorf("%s: %d want %d", path, w.Code, want)
		}
		if w.Code == 200 && (w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store") {
			t.Errorf("%s: headers %v", path, w.Header())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != 405 {
		t.Fatalf("POST: %d", w.Code)
	}
}
