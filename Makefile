# agent-quartermaster build. Pure Go (CGO_ENABLED=0); the web UI is built with Bun into web/dist
# and embedded into aqmasd via internal/webui/dist (placeholder page when web/dist is absent).

GO      ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/toolchains/go/bin/go)
BUN     ?= bun
VERSION ?= $(shell cat VERSION)
COMMIT  := $(shell git rev-parse --verify HEAD)
SUMS    ?= SHA256SUMS
MODULE  := github.com/aquarat/agent-quartermaster
# aqmasd reads main.version; the aqmas CLI reads internal/client.Version (an -X for a symbol a
# binary doesn't link is ignored, so both binaries get both).
LDFLAGS := -s -w -X main.version=$(VERSION) -X $(MODULE)/internal/client.Version=$(VERSION) -X $(MODULE)/internal/release.Version=$(VERSION) -X $(MODULE)/internal/release.Commit=$(COMMIT)
GOBUILD := CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOTOOLCHAIN=local $(GO) build -mod=readonly -buildvcs=false -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build aqmasd aqmas web webui test vet clean interop interop-cf check-private

all: build

.PHONY: release verify-release pins
pins:
	@test "$$($(GO) env GOVERSION)" = go1.27.4 && test "$$($(BUN) --version)" = 1.4.4 || { echo 'need Go 1.27.4 and Bun 1.4.4'; exit 1; }
	@test '$(VERSION)' = "$$(cat VERSION)" && grep -Exq '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)' VERSION
	@test $$(wc -l < VERSION) -eq 1 && test $$(printf %s '$(COMMIT)' | wc -c) -eq 40

release: pins
	$(MAKE) build WEB_INSTALL='--production --offline --ignore-scripts'
	mkdir -p dist
	cp bin/aqmasd-linux-arm64 bin/aqmas-linux-arm64 bin/aqmas-linux-amd64 bin/aqmas-darwin-arm64 dist/
	cd dist && sha256sum aqmas-darwin-arm64 aqmas-linux-amd64 aqmas-linux-arm64 aqmasd-linux-arm64 > SHA256SUMS

verify-release:
	@set -e; expected=$$(mktemp); trap 'rm -f "$$expected"' EXIT; cp '$(SUMS)' "$$expected"; $(MAKE) release; cmp "$$expected" dist/SHA256SUMS

build: aqmasd aqmas

aqmasd: webui
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/aqmasd-linux-arm64 ./cmd/aqmasd

aqmas:
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/aqmas-linux-arm64 ./cmd/aqmas
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/aqmas-linux-amd64 ./cmd/aqmas
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o bin/aqmas-darwin-arm64 ./cmd/aqmas

# Build the TypeScript UI into web/dist (embedded into aqmasd by the webui target).
web:
	cd web && $(BUN) install --frozen-lockfile $(WEB_INSTALL) && $(BUN) run build

# Copy web/dist into the embed directory (or leave it empty, which selects the placeholder).
webui: web
	@find internal/webui/dist -mindepth 1 ! -name .gitignore -exec rm -rf {} +
	@if [ -f web/dist/index.html ]; then cp -R web/dist/. internal/webui/dist/; echo "webui: embedding web/dist"; \
	else echo "webui: web/dist not built, embedding the placeholder page"; fi

# The repository is public; the first installation's own hosts are not. Fails if a private
# host name, address or name is in any tracked file (internal/release has the same check as
# a test, which also sees untracked files). Written with one-character classes so that the
# pattern does not match itself.
PRIVATE_RE := example[.]invalid
check-private:
	@! git grep -nE '$(PRIVATE_RE)' || { echo 'site-specific names in the tree (see above)'; exit 1; }

vet: check-private
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd internal deploy test)" || { gofmt -l cmd internal deploy test; echo "gofmt needed"; exit 1; }

test: vet
	$(GO) test ./...

# Real binaries end to end: aqmasd + aqmas + a throwaway sshd on 127.0.0.1 (test/interop/run.sh),
# the Setup runner (run-setup.sh) and the move of a store sealed by the real v0.4.1 (built from its
# tag in a temporary git worktree) to per-credential buckets (run-migrate.sh).
interop:
	test/interop/run.sh
	test/interop/run-setup.sh
	test/interop/run-migrate.sh

# Milestone 2: real aqmasd + aqmas against the fake Cloudflare API (test/interop/run-cf.sh);
# WRANGLER=1 also deploys with wrangler through `aqmas cf env` (installs wrangler with bun).
interop-cf: webui
	test/interop/run-cf.sh

clean:
	rm -rf bin
	@find internal/webui/dist -mindepth 1 ! -name .gitignore -exec rm -rf {} +
