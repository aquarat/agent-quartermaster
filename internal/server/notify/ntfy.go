// Package notify publishes push notifications to an ntfy topic. Messages carry a title, a short
// text and the approve URL only; failures are logged and never block the caller.
package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Notifier sends notifications; the zero value (empty TopicURL) does nothing.
type Notifier struct {
	// Dispatch is used by the sealed broker. It takes responsibility for the
	// operation lease, including the HTTP response, or coalesces a cold notice.
	Dispatch func(title, text, clickURL string)
	TopicURL string
	Client   *http.Client
	Log      *slog.Logger
}

// Send publishes asynchronously.
func (n *Notifier) Send(title, text, clickURL string) {
	if n != nil && n.Dispatch != nil {
		n.Dispatch(title, text, clickURL)
		return
	}
	if n == nil || n.TopicURL == "" {
		return
	}
	go n.send(title, text, clickURL)
}

func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func (n *Notifier) send(title, text, clickURL string) {
	n.Publish(context.Background(), title, text, clickURL)
}

// ErrNoChannel is Deliver's answer when no topic is configured.
var ErrNoChannel = errors.New("no notification channel is configured")

// Configured reports whether a push channel exists.
func (n *Notifier) Configured() bool { return n != nil && (n.TopicURL != "" || n.Dispatch != nil) }

// Deliver publishes synchronously and reports whether the push service accepted the
// message. It is for the alerts that must be attempted before something is handed out.
func (n *Notifier) Deliver(parent context.Context, title, text, clickURL string) error {
	if n == nil || n.TopicURL == "" {
		return ErrNoChannel
	}
	return n.publish(parent, title, text, clickURL)
}

// Publish runs synchronously within the caller's lease.
func (n *Notifier) Publish(parent context.Context, title, text, clickURL string) {
	_ = n.publish(parent, title, text, clickURL)
}

func (n *Notifier) publish(parent context.Context, title, text, clickURL string) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.TopicURL, strings.NewReader(clean(text, 300)+"\n"+clickURL))
	if err != nil {
		n.logErr()
		return errors.New("ntfy publish failed")
	}
	req.Header.Set("Title", clean(title, 120))
	req.Header.Set("Click", clickURL)
	req.Header.Set("Tags", "key")
	req.Header.Set("Priority", "high")
	c := n.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	client := *c
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		n.logErr()
		return errors.New("ntfy publish failed")
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		if n.Log != nil {
			n.Log.Warn("ntfy publish failed", "status", resp.StatusCode)
		}
		return errors.New("ntfy publish refused")
	}
	return nil
}

func (n *Notifier) logErr() {
	if n.Log != nil {
		// The topic URL is a capability; don't log it (url.Error includes it).
		n.Log.Warn("ntfy publish failed")
	}
}
