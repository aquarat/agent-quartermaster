// Package webui serves the approval UI's static files. `make webui` copies web/dist into
// internal/webui/dist before `go build`; when that directory has no index.html the tiny
// placeholder in fallback/ is served instead, so the server builds without the web workstream.
package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

//go:embed fallback
var fallbackFS embed.FS

// FS returns the UI file system rooted at the directory holding index.html.
func FS() fs.FS {
	if sub, err := fs.Sub(distFS, "dist"); err == nil {
		// dist/ always holds its .gitignore; it counts as built only with an index.html.
		if _, err := fs.Stat(sub, "index.html"); err == nil {
			return sub
		}
	}
	sub, _ := fs.Sub(fallbackFS, "fallback")
	return sub
}

// IsFallback reports whether the placeholder UI is embedded.
func IsFallback() bool {
	_, err := fs.Stat(distFS, "dist/index.html")
	return err != nil
}

var types = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".txt":         "text/plain; charset=utf-8",
	".map":         "application/json",
}

func contentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := types[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

// Handler serves the SPA: existing files as-is (hashed assets under /assets/ cached immutably,
// everything else revalidated), index.html with no-store for any extension-less path (client
// routes such as /requests/<id>), 404 otherwise.
func Handler() http.Handler {
	root := FS()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		for _, seg := range strings.Split(p, "/") {
			if strings.HasPrefix(seg, ".") {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}
		if p == "" || p == "index.html" {
			serveIndex(w, r, root)
			return
		}
		if st, err := fs.Stat(root, p); err == nil && !st.IsDir() {
			b, err := fs.ReadFile(root, p)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", contentType(p))
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				w.Write(b)
			}
			return
		}
		if path.Ext(p) == "" {
			serveIndex(w, r, root)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS) {
	b, err := fs.ReadFile(root, "index.html")
	if err != nil {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(b)
	}
}
