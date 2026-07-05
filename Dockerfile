# Dockerfile for the wolfee CLI.
#
# Multi-stage:
#   1. Go builder  — compiles the static wolfee binary
#   2. Node builder — installs cdxgen + atom + atom-parsetools globally
#   3. Final       — Debian slim with wolfee + trivy + cdxgen + atom
#
# Runtime tools the final image must carry:
#   - trivy   : detection + severity for the --image flag (subprocess).
#               --image hard-fails without it, so it is load-bearing.
#   - cdxgen  : cataloguing for project-path / --bom / --reachable.
#   - atom / govulncheck : --reachable call-graph (degrade gracefully).

FROM golang:1.22-bookworm AS go-builder
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w \
        -X sca-go/cli/internal/cli.Version=${VERSION} \
        -X sca-go/cli/internal/cli.Commit=${COMMIT}" \
      -o /out/wolfee \
      ./cmd/wolfee

# govulncheck powers the Go side of `--reachable`. Built here so it
# ships in the final image. NOTE: at scan time govulncheck shells out
# to the Go toolchain to build the call graph, so `--reachable` on a
# Go project only works where `go` is on PATH (CI, a golang base
# image, the dev box). Without it the wrapper degrades gracefully —
# Go findings just stay "unknown", the scan still completes.
RUN GOBIN=/out go install golang.org/x/vuln/cmd/govulncheck@latest

# ── cdxgen + atom install stage ───────────────────────────────
# atom (@appthreat/atom) powers js/python/java/php reachability for
# `--reachable`, same way govulncheck powers Go. atom-parsetools
# ships atom's frontend parsers (astgen for JS/TS, phpastgen for
# PHP); atom cannot build a call graph for those languages without
# it. Like cdxgen they are Node-based; missing/failed atom degrades
# gracefully (findings stay unknown), so this is additive, not
# load-bearing.
FROM node:20-bookworm-slim AS node-builder
RUN npm install -g @cyclonedx/cdxgen@latest @appthreat/atom@latest @appthreat/atom-parsetools@latest && \
    npm cache clean --force

# ── trivy stage ───────────────────────────────────────────────
# trivy provides detection + severity for the --image flag. We copy
# the binary from the official image rather than curl|sh so the build
# is reproducible and offline-friendly. PIN: bump this tag to the
# latest stable trivy release — https://github.com/aquasecurity/trivy/releases
FROM ghcr.io/aquasecurity/trivy:0.58.1 AS trivy

# ── final image ───────────────────────────────────────────────
FROM debian:bookworm-slim
# atom builds a JVM code graph and needs JDK 21+ even for the
# JavaScript frontend; without it atom exits 0 but analyses nothing, so
# the JDK is load-bearing for js/python/java/php --reachable. bookworm
# only ships JDK 17, so pull 21 from backports.
RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' \
      > /etc/apt/sources.list.d/backports.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      nodejs \
      npm && \
    apt-get install -y --no-install-recommends -t bookworm-backports \
      openjdk-21-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# cdxgen lives under /usr/lib/node_modules in the node-builder image.
# Pulling the whole node_modules tree + the bin shim keeps cdxgen runnable.
COPY --from=node-builder /usr/local/lib/node_modules/@cyclonedx /usr/lib/node_modules/@cyclonedx
COPY --from=node-builder /usr/local/lib/node_modules/@appthreat /usr/lib/node_modules/@appthreat
RUN ln -s /usr/lib/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js /usr/local/bin/cdxgen && \
    ATOM_BIN="$(node -e "const b=require('/usr/lib/node_modules/@appthreat/atom/package.json').bin; process.stdout.write(typeof b==='string'?b:b[Object.keys(b)[0]])")" && \
    ln -s "/usr/lib/node_modules/@appthreat/atom/${ATOM_BIN}" /usr/local/bin/atom && \
    chmod +x /usr/local/bin/atom && \
    node -e "const b=require('/usr/lib/node_modules/@appthreat/atom-parsetools/package.json').bin||{}; const m=typeof b==='string'?{'atom-parsetools':b}:b; for (const [n,r] of Object.entries(m)) console.log(n+' '+r);" \
      | while read -r name rel; do \
          ln -s "/usr/lib/node_modules/@appthreat/atom-parsetools/${rel}" "/usr/local/bin/${name}" && \
          chmod +x "/usr/local/bin/${name}"; \
        done

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=go-builder /out/wolfee /usr/local/bin/wolfee
COPY --from=go-builder /out/govulncheck /usr/local/bin/govulncheck

ENTRYPOINT ["/usr/local/bin/wolfee"]
CMD ["--help"]
