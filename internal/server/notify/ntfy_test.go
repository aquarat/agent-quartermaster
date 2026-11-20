package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	got := make(chan *http.Request, 1)
	bodies := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- string(b)
		got <- r
	}))
	defer srv.Close()
	n := &Notifier{TopicURL: srv.URL + "/topic"}
	n.Send("aqmas: host", "aqmas: host wants ssh a@b\r\nInjected: x", "https://aqmas.example.com/requests/1")
	select {
	case r := <-got:
		body := <-bodies
		if r.Header.Get("Click") != "https://aqmas.example.com/requests/1" || r.Header.Get("Title") != "aqmas: host" {
			t.Fatalf("headers %v", r.Header)
		}
		if strings.Contains(body, "\r") || !strings.Contains(body, "wants ssh a@b") {
			t.Fatalf("body %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no publish")
	}
	// A dead endpoint must not block the caller.
	start := time.Now()
	(&Notifier{TopicURL: "http://127.0.0.1:1/x"}).Send("t", "x", "u")
	(&Notifier{}).Send("t", "x", "u")
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Send blocked")
	}
}
