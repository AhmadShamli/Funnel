# Stage 1: Build static Go binary
FROM golang:1.24-bookworm AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and embedded assets
COPY . .

# Compile static binary without CGO
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /build/funnel ./cmd/funnel

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iptables \
    sudo \
    util-linux \
    tini \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user & group
RUN groupadd -g 10001 funnel && \
    useradd -u 10001 -g funnel -d /home/funnel -m -s /bin/bash funnel

# Install static Go binary from builder
COPY --from=builder /build/funnel /usr/local/bin/funnel

# Setup directories, entrypoint, and permissions
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN mkdir -p /data /run/funnel && \
    chown -R funnel:funnel /data /run/funnel && \
    chmod +x /app/docker-entrypoint.sh /usr/local/bin/funnel

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["/usr/local/bin/funnel", "serve"]
