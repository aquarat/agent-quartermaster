# agent-quartermaster build. Pure Go (CGO_ENABLED=0); the web UI is built with Bun into web/dist
# and embedded into aqmasd via internal/webui/dist (placeholder page when web/dist is absent).

GO      ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/toolchains/go/bin/go)
BUN     ?= bun
VERSION ?= $(shell git describe --always --dirty --tags 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build aqmasd aqmas web webui test vet clean

all: build

build: aqmasd aqmas

aqmasd: webui
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/aqmasd-linux-arm64 ./cmd/aqmasd

# The CLI lives on the client workstream's branch; skip quietly until it is merged.
aqmas:
	@if [ -d cmd/aqmas ]; then \
		set -e; \
		echo "GOOS=linux GOARCH=arm64 go build ./cmd/aqmas"; GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/aqmas-linux-arm64 ./cmd/aqmas; \
		echo "GOOS=linux GOARCH=amd64 go build ./cmd/aqmas"; GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/aqmas-linux-amd64 ./cmd/aqmas; \
	else echo "cmd/aqmas not present: skipping the CLI"; fi

# Build the TypeScript UI (web/ workstream) if present.
web:
	@if [ -f web/package.json ]; then cd web && $(BUN) run build; else echo "web/ not present: skipping"; fi

# Copy web/dist into the embed directory (or leave it empty, which selects the placeholder).
webui:
	@find internal/webui/dist -mindepth 1 ! -name .gitignore -exec rm -rf {} +
	@if [ -f web/dist/index.html ]; then cp -R web/dist/. internal/webui/dist/; echo "webui: embedding web/dist"; \
	else echo "webui: web/dist not built, embedding the placeholder page"; fi

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; echo "gofmt needed"; exit 1; }

test: vet
	$(GO) test ./...

clean:
	rm -rf bin
	@find internal/webui/dist -mindepth 1 ! -name .gitignore -exec rm -rf {} +
