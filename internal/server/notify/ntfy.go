// Package notify publishes push notifications to an ntfy topic. Messages carry a title, a short
// text and the approve URL only; failures are logged and never block the caller.
package notify

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Notifier sends notifications; the zero value (empty TopicURL) does nothing.
type Notifier struct {
	TopicURL string
	Client   *http.Client
	Log      *slog.Logger
}

// Send publishes asynchronously.
func (n *Notifier) Send(title, text, clickURL string) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.TopicURL, strings.NewReader(clean(text, 300)+"\n"+clickURL))
	if err != nil {
		n.logErr(err)
		return
	}
	req.Header.Set("Title", clean(title, 120))
	req.Header.Set("Click", clickURL)
	req.Header.Set("Tags", "key")
	req.Header.Set("Priority", "high")
	c := n.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		n.logErr(err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		if n.Log != nil {
			n.Log.Warn("ntfy publish failed", "status", resp.StatusCode)
		}
	}
}

func (n *Notifier) logErr(err error) {
	if n.Log != nil {
		// The topic URL is a capability; don't log it (url.Error includes it).
		n.Log.Warn("ntfy publish failed", "error", strings.ReplaceAll(err.Error(), n.TopicURL, "<topic>"))
	}
}
