# syntax=docker/dockerfile:1
#
# Multi-stage build for tiny-url. The runtime image is distroless/static —
# no shell, no package manager, no glibc — so the attack surface inside the
# container is the binary plus the embedded static assets and nothing else.
# This works because we use modernc.org/sqlite (pure Go, no CGO), which lets
# CGO_ENABLED=0 produce a fully static binary.
#
# Build:   docker build -t tiny-url .
# Run:     docker run -p 8080:8080 tiny-url                   # memory backend
# Persist: docker run -p 8080:8080 -e STORAGE_BACKEND=sqlite \
#              -e SQLITE_PATH=/data/tiny-url.db \
#              -v tinyurl-data:/data tiny-url

FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache go.mod / go.sum first so source-only changes don't bust the deps layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Strip debug + symbol tables to shrink the binary; CGO off for a static link.
# -trimpath rewrites file paths so build location doesn't leak into stack
# traces (small but free hygiene win).
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/tiny-url .

# ----------------------------------------------------------------------------

FROM gcr.io/distroless/static:nonroot

# /data is the conventional spot for the SQLite file when the operator
# mounts a volume. Setting it as the WORKDIR means relative-path defaults
# (e.g. SQLITE_PATH=tiny-url.db) write here without further configuration.
WORKDIR /data

COPY --from=builder /out/tiny-url /tiny-url

EXPOSE 8080

# distroless/static:nonroot already runs as uid 65532; declaring it here is
# documentation, not a privilege change.
USER nonroot:nonroot

ENTRYPOINT ["/tiny-url"]
