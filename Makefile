# agent-quartermaster build. Pure Go (CGO_ENABLED=0); the web UI is built with Bun into web/dist
# and embedded into aqmasd via internal/webui/dist (placeholder page when web/dist is absent).

GO      ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/toolchains/go/bin/go)
BUN     ?= bun
VERSION ?= $(shell git describe --always --dirty --tags 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build aqmasd aqmas web webui test vet clean interop

all: build

build: aqmasd aqmas

aqmasd: webui
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/aqmasd-linux-arm64 ./cmd/aqmasd

aqmas:
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/aqmas-linux-arm64 ./cmd/aqmas
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/aqmas-linux-amd64 ./cmd/aqmas

# Build the TypeScript UI into web/dist (embedded into aqmasd by the webui target).
web:
	cd web && $(BUN) install --frozen-lockfile && $(BUN) run build

# Copy web/dist into the embed directory (or leave it empty, which selects the placeholder).
webui: web
	@find internal/webui/dist -mindepth 1 ! -name .gitignore -exec rm -rf {} +
	@if [ -f web/dist/index.html ]; then cp -R web/dist/. internal/webui/dist/; echo "webui: embedding web/dist"; \
	else echo "webui: web/dist not built, embedding the placeholder page"; fi

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd internal deploy test)" || { gofmt -l cmd internal deploy test; echo "gofmt needed"; exit 1; }

test: vet
	$(GO) test ./...

# Real binaries end to end: aqmasd + aqmas + a throwaway sshd on 127.0.0.1 (test/interop/run.sh).
interop:
	test/interop/run.sh

clean:
	rm -rf bin
	@find internal/webui/dist -mindepth 1 ! -name .gitignore -exec rm -rf {} +
