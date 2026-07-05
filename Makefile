# Convenience wrapper around the standard Go targets so contributors
# don't have to memorise the exact -ldflags incantation. CI uses these
# same targets, so behaviour is consistent between dev and release.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X sca-go/cli/internal/cli.Version=$(VERSION) \
  -X sca-go/cli/internal/cli.Commit=$(COMMIT) \
  -X sca-go/cli/internal/cli.Built=$(BUILT)

.PHONY: build test test-race vet lint fmt tidy clean docker install tools help

help:
	@echo "Targets:"
	@echo "  build       Build ./bin/wolfee for the current host"
	@echo "  install     Install wolfee into \$$GOBIN (or \$$GOPATH/bin)"
	@echo "  tools       Install runtime tools (trivy, govulncheck) into ./bin"
	@echo "  test        Run unit tests"
	@echo "  test-race   Run tests with the race detector"
	@echo "  vet         go vet"
	@echo "  fmt         gofmt -w on all .go files"
	@echo "  tidy        go mod tidy"
	@echo "  docker      Build the wolfee+trivy+cdxgen Docker image (TAG=wolfee:dev)"
	@echo "  clean       Remove ./bin"

# Runtime tools wolfee shells out to. trivy is load-bearing for the
# --image flag; govulncheck powers the Go side of --reachable. cdxgen
# / atom (Node) cover project-path + non-Go --reachable — install them
# separately with: npm i -g @cyclonedx/cdxgen @appthreat/atom @appthreat/atom-parsetools
# Requires curl + network. Binaries land in ./bin (add it to PATH, or
# pass --trivy-bin ./bin/trivy).
TRIVY_VERSION ?= v0.58.1
tools:
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
	  | sh -s -- -b ./bin $(TRIVY_VERSION)
	GOBIN=$(CURDIR)/bin go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Installed ./bin/trivy ($(TRIVY_VERSION)) and ./bin/govulncheck"

build:
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/wolfee ./cmd/wolfee
	@echo "Built ./bin/wolfee ($(VERSION))"

install:
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/wolfee

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

# Cross-compile matrix used by the release workflow. Skip CGO so the
# binary is statically linked and ships without a libc dependency.
.PHONY: build-all
build-all:
	@mkdir -p bin
	@for tgt in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	  GOOS=$${tgt%/*} GOARCH=$${tgt#*/} CGO_ENABLED=0 \
	    go build -trimpath -ldflags '$(LDFLAGS)' \
	    -o bin/wolfee-$$(echo $$tgt | tr / -)$$( [ "$${tgt%/*}" = "windows" ] && echo .exe ) \
	    ./cmd/wolfee || exit 1; \
	  echo "  built bin/wolfee-$$(echo $$tgt | tr / -)"; \
	done

TAG ?= wolfee:dev
docker:
	# Builds the runtime image (wolfee + trivy + cdxgen + atom +
	# govulncheck). Docker context is just `.`.
	docker build -f Dockerfile -t $(TAG) \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  .

clean:
	rm -rf bin
